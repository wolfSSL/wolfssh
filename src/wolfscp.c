/* wolfscp.c
 *
 * Copyright (C) 2014-2026 wolfSSL Inc.
 *
 * This file is part of wolfSSH.
 *
 * wolfSSH is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfSSH is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with wolfSSH.  If not, see <http://www.gnu.org/licenses/>.
 */


/*
 * The scp module provides SCP server functionality including a default
 * receive callback. The default callbacks assume a filesystem is
 * available, but users can write and register their own callbacks if
 * no filesystem is available.
 */


#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssh/wolfscp.h>

#ifdef WOLFSSH_SCP

#include <wolfssh/ssh.h>
#include <wolfssh/internal.h>
#include <wolfssh/log.h>

#include <errno.h>
#include <stdint.h>


#ifdef NO_INLINE
    #include <wolfssh/misc.h>
#else
    #define WOLFSSH_MISC_INCLUDED
    #include "src/misc.c"
#endif

#ifndef WOLFSSH_DEFAULT_EXTDATA_SZ
    #define WOLFSSH_DEFAULT_EXTDATA_SZ 128
#endif

#ifndef NO_FILESYSTEM
static int ScpFileIsDir(ScpSendCtx* ctx);
static int ScpPushDir(void *fs, ScpSendCtx* ctx, const char* path, void* heap);
static int ScpPopDir(void *fs, ScpSendCtx* ctx, void* heap);
#endif

#define WOLFSSH_MODE_MASK 0777

const char scpError[] = "scp error: %s, %d";
const char scpState[] = "scp state: %s";


/* Logs an SCP state error, except a non-blocking WS_WANT_READ/WS_WANT_WRITE,
 * which is normal back-pressure the caller retries (matching the quiet
 * SCP_SEND_FILE handling) rather than a transfer failure. */
static void LogScpStateError(const char* state, int ret)
{
    (void)state;
    if (ret != WS_WANT_READ && ret != WS_WANT_WRITE)
        WLOG(WS_LOG_ERROR, scpError, state, ret);
}


static int _DumpExtendedData(WOLFSSH* ssh)
{
    byte msg[WOLFSSH_DEFAULT_EXTDATA_SZ];
    int msgSz;

    msgSz = wolfSSH_extended_data_read(ssh, msg, WOLFSSH_DEFAULT_EXTDATA_SZ-1);
    if (msgSz > 0) {
        msg[msgSz] = 0;
        fprintf(stderr, "%s", msg);
        msgSz = WS_SUCCESS;
    }

    return msgSz;
}


/* Sends sz bytes from data, completing any rekey or full window that blocks
 * the send.
 *
 * Attempts the send; on a WS_WINDOW_FULL (peer window reached zero) or
 * WS_REKEYING result, drives wolfSSH_worker once to pick up the peer's window
 * adjust or to advance the rekey, then retries the send. The retry is what
 * clears the status: wolfSSH_worker does not reset ssh->error, so a loop that
 * keyed on ssh->error staying WS_WINDOW_FULL would keep driving the worker
 * after the window already reopened and stall the transfer. This mirrors the
 * original SCP_SEND_FILE handling, extended to the control-message senders so a
 * rekey or full window during a timestamp/header/confirmation send is no longer
 * reported as fatal. Termination needs no retry count: in blocking mode
 * wolfSSH_worker waits on the socket for the peer's packet; in non-blocking
 * mode it returns WS_WANT_READ/WS_WANT_WRITE, which is returned to the caller
 * so a stalled rekey cannot spin forever. Returns the byte count from
 * wolfSSH_stream_send (>= 0) or a negative error code, matching the wrapped
 * call so callers keep their existing return handling.
 */
static int ScpStreamSend(WOLFSSH* ssh, byte* data, word32 sz)
{
    int ret = WS_SUCCESS;
    int err;
    int done = 0;

    if (ssh == NULL || data == NULL)
        return WS_BAD_ARGUMENT;

    /* Flush queued output before sending. Otherwise a KEXINIT enqueued by a
     * rekey triggered on the prior send sits unsent while wolfSSH_worker runs
     * DoReceive before its own flush, blocking on the socket with the peer
     * waiting for our KEXINIT. */
    if (wolfSSH_OutputPending(ssh)) {
        ret = wolfSSH_SendPacket(ssh);
        if (ret < 0)
            return ret;
    }

    while (!done) {
        ret = wolfSSH_stream_send(ssh, data, sz);
        if (ret >= 0) {
            /* sent (full or partial byte count); exits via while (!done) */
            done = 1;
        }
        else {
            err = wolfSSH_get_error(ssh);
            if (err == WS_WINDOW_FULL || err == WS_REKEYING) {
                ret = wolfSSH_worker(ssh, NULL);
                err = wolfSSH_get_error(ssh);
                /* A non-blocking want surfaces as a generic worker error with
                 * the want recorded in ssh->error (see GetInputData). Return it
                 * so the caller retries instead of tearing down the send. */
                if (err == WS_WANT_READ || err == WS_WANT_WRITE)
                    return err;
                /* Only a rekey/window/channel-data status means "keep driving".
                 * Any other negative status is fatal and returned. */
                if (ret < 0 && ret != WS_REKEYING && ret != WS_WINDOW_FULL
                        && ret != WS_CHAN_RXD)
                    return ret;
                /* otherwise loop and retry the send, which clears the status */
            }
            else {
                /* Fatal or other final status; return it unchanged. */
                done = 1;
            }
        }
    }

    return ret;
}


/* Reads up to sz bytes into data, completing any rekey that fires mid-read.
 *
 * Flushes queued output before reading so a KEXINIT enqueued by a receive-side
 * highwater rekey is actually sent, otherwise the peer can wait for our KEXINIT
 * while we block on the read. On a read that fails with WS_REKEYING the worker
 * is driven to finish the rekey and the read is retried. The helper is
 * error-code transparent: every other status (WS_EOF, WS_EXTDATA,
 * WS_CHANNEL_CLOSED, WS_SOCKET_ERROR_E, WS_WANT_READ/WS_WANT_WRITE, byte count)
 * is returned unchanged so each caller keeps its existing branch handling.
 */
static int ScpStreamRead(WOLFSSH* ssh, byte* data, word32 sz)
{
    int ret = WS_SUCCESS;
    int done = 0;

    if (ssh == NULL || data == NULL)
        return WS_BAD_ARGUMENT;

    do {
        if (wolfSSH_OutputPending(ssh)) {
            ret = wolfSSH_SendPacket(ssh);
            if (ret < 0)
                return ret;
        }

        ret = wolfSSH_stream_read(ssh, data, sz);
        if (ret < 0 && wolfSSH_get_error(ssh) == WS_REKEYING) {
            /* Drive the rekey to completion, then retry the read. A worker
             * status that is not rekey or channel data means the rekey stalled
             * or a non-blocking want occurred, so return it rather than
             * spin. */
            ret = wolfSSH_worker(ssh, NULL);
            if (ret < 0 && ret != WS_CHAN_RXD
                    && wolfSSH_get_error(ssh) != WS_REKEYING)
                return ret;
        }
        else {
            done = 1;
        }
    } while (!done);

    return ret;
}


int DoScpSink(WOLFSSH* ssh)
{
    int ret = WS_SUCCESS;

    if (ssh == NULL)
        return WS_BAD_ARGUMENT;

    while (ret == WS_SUCCESS && ssh->scpState != SCP_DONE) {

        switch (ssh->scpState) {

            case SCP_SINK_BEGIN:
                WLOG(WS_LOG_DEBUG, scpState, "SCP_SINK_BEGIN");

                ssh->scpState = SCP_SEND_CONFIRMATION;
                ssh->scpNextState = SCP_RECEIVE_MESSAGE;

                ssh->scpConfirm = ssh->ctx->scpRecvCb(ssh,
                        WOLFSSH_SCP_NEW_REQUEST, ssh->scpBasePath,
                        NULL, 0, 0, 0, 0, NULL, 0, 0,
                        wolfSSH_GetScpRecvCtx(ssh));
                continue;

            case SCP_RECEIVE_MESSAGE:
                WLOG(WS_LOG_DEBUG, scpState, "SCP_RECEIVE_MESSAGE");

                if ( (ret = ReceiveScpMessage(ssh)) < WS_SUCCESS) {
                    if (ret == WS_EOF) {
                        ret = WS_SUCCESS; /* successfully received message */
                        ssh->scpState = SCP_DONE;
                        break;
                    }

                    LogScpStateError("RECEIVE_MESSAGE", ret);
                    break;
                }

                if (ssh->scpMsgType == WOLFSSH_SCP_MSG_DIR) {
                    ssh->scpState = SCP_SEND_CONFIRMATION;
                    ssh->scpNextState = SCP_RECEIVE_MESSAGE;
                    ssh->scpFileState = WOLFSSH_SCP_NEW_DIR;

                } else if (ssh->scpMsgType == WOLFSSH_SCP_MSG_END_DIR) {
                    ssh->scpState = SCP_SEND_CONFIRMATION;
                    ssh->scpNextState = SCP_RECEIVE_MESSAGE;

                } else if (ssh->scpMsgType == WOLFSSH_SCP_MSG_TIME) {
                    ssh->scpState = SCP_SEND_CONFIRMATION;
                    ssh->scpNextState = SCP_RECEIVE_MESSAGE;
                    continue;

                } else if (ssh->scpMsgType == WOLFSSH_SCP_MSG_FILE) {
                    ssh->scpState = SCP_SEND_CONFIRMATION;
                    ssh->scpNextState = SCP_RECEIVE_FILE;
                    ssh->scpFileState = WOLFSSH_SCP_NEW_FILE;

                } else {
                    ret = WS_SCP_BAD_MSG_E;
                    WLOG(WS_LOG_ERROR, scpError, "bad msg type", ret);
                    break;
                }

                /* scp receive callback */
                ssh->scpConfirm = ssh->ctx->scpRecvCb(ssh, ssh->scpFileState,
                        ssh->scpBasePath, ssh->scpFileName, ssh->scpFileMode,
                        ssh->scpMTime, ssh->scpATime, ssh->scpFileSz, NULL, 0,
                        0, wolfSSH_GetScpRecvCtx(ssh));

                continue;

            case SCP_SEND_CONFIRMATION:
                WLOG(WS_LOG_DEBUG, scpState, "SCP_SEND_CONFIRMATION");

                if ( (ret = SendScpConfirmation(ssh)) < WS_SUCCESS) {
                    LogScpStateError("SEND_CONFIRMATION", ret);
                    break;
                }

                ssh->scpState = ssh->scpNextState;
                continue;

            case SCP_RECEIVE_CONFIRMATION:
                WLOG(WS_LOG_DEBUG, scpState, "SCP_RECEIVE_CONFIRMATION");

                if ( (ret = ReceiveScpConfirmation(ssh)) < WS_SUCCESS) {
                    LogScpStateError("RECEIVE_CONFIRMATION", ret);
                    break;
                }

                ssh->scpState = SCP_RECEIVE_MESSAGE;
                continue;

            case SCP_RECEIVE_FILE:
                WLOG(WS_LOG_DEBUG, scpState, "SCP_RECEIVE_FILE");

                if ( (ret = ReceiveScpFile(ssh)) < WS_SUCCESS) {
                    LogScpStateError("RECEIVE_FILE", ret);
                    break;
                }

                /* reset success status */
                ret = WS_SUCCESS;

                /* scp receive callback, give user file data */
                ssh->scpConfirm = ssh->ctx->scpRecvCb(ssh,
                        WOLFSSH_SCP_FILE_PART, ssh->scpBasePath,
                        ssh->scpFileName, ssh->scpFileMode, ssh->scpMTime,
                        ssh->scpATime, ssh->scpFileSz, ssh->scpFileBuffer,
                        ssh->scpFileBufferSz, ssh->scpFileOffset,
                        wolfSSH_GetScpRecvCtx(ssh));
                ssh->scpFileOffset += ssh->scpFileBufferSz;

                /* reset recv buffer */
                ssh->scpFileBufferSz = 0;

                if (ssh->scpConfirm != WS_SCP_CONTINUE) {
                    /* user aborted, send failure confirmation */
                    ssh->scpState = SCP_SEND_CONFIRMATION;
                    ssh->scpNextState = SCP_DONE;

                } else if (ssh->scpFileOffset < ssh->scpFileSz) {
                    ssh->scpNextState = SCP_RECEIVE_FILE;

                } else {
                    /* scp receive callback, notify user file is done */
                    ssh->scpConfirm = ssh->ctx->scpRecvCb(ssh,
                        WOLFSSH_SCP_FILE_DONE, ssh->scpBasePath,
                        ssh->scpFileName, ssh->scpFileMode, ssh->scpMTime,
                        ssh->scpATime, ssh->scpFileSz, NULL, 0, 0,
                        wolfSSH_GetScpRecvCtx(ssh));

                    ssh->scpFileOffset = 0;
                    ssh->scpATime = 0;
                    ssh->scpMTime = 0;
                    ssh->scpState = SCP_SEND_CONFIRMATION;
                    ssh->scpNextState = SCP_RECEIVE_CONFIRMATION;
                }
                continue;

        } /* end switch */

    } /* end while */

    return ret;
}

static int ScpSourceInit(WOLFSSH* ssh)
{
    /* file name */
    if (ssh->scpFileName != NULL) {
        WFREE(ssh->scpFileName, ssh->ctx->heap, DYNTYPE_STRING);
        ssh->scpFileName = NULL;
        ssh->scpFileNameSz = 0;
    }

    ssh->scpFileName = (char*)WMALLOC(DEFAULT_SCP_FILE_NAME_SZ, ssh->ctx->heap,
                                      DYNTYPE_STRING);
    if (ssh->scpFileName == NULL)
        return WS_MEMORY_E;

    ssh->scpFileNameSz = DEFAULT_SCP_FILE_NAME_SZ;
    WMEMSET(ssh->scpFileName, 0, DEFAULT_SCP_FILE_NAME_SZ);

    /* file buffer */
    ssh->scpFileBuffer = (byte*)WMALLOC(DEFAULT_SCP_BUFFER_SZ, ssh->ctx->heap,
                                        DYNTYPE_BUFFER);
    if (ssh->scpFileBuffer == NULL) {
        WFREE(ssh->scpFileName, ssh->ctx->heap, DYNTYPE_STRING);
        ssh->scpFileName = NULL;
        return WS_MEMORY_E;
    }
    ssh->scpFileBufferSz = DEFAULT_SCP_BUFFER_SZ;
    WMEMSET(ssh->scpFileBuffer, 0, DEFAULT_SCP_BUFFER_SZ);

    /* reset per-file state so a reused connection starts a fresh transfer */
    ssh->scpFileOffset = 0;
    ssh->scpBufferedSz = 0;
    ssh->scpFileHeaderSent = 0;

    return WS_SUCCESS;
}


/* Sends timestamp information (access, modification) to peer.
 *
 * T<modification_secs> 0 <access_secs> 0
 *
 * returns WS_SUCCESS on success, negative upon error
 */
static int SendScpTimestamp(WOLFSSH* ssh)
{
    int ret = WS_SUCCESS, bufSz;
    char buf[DEFAULT_SCP_MSG_SZ];

    if (ssh == NULL)
        return WS_BAD_ARGUMENT;

    WMEMSET(buf, 0, sizeof(buf));
#ifdef WORD64_AVAILABLE
    WSNPRINTF(buf, sizeof(buf), "T%llu 0 %llu 0\n",
              (unsigned long long)ssh->scpMTime,
              (unsigned long long)ssh->scpATime);
#else
    WSNPRINTF(buf, sizeof(buf), "T%lu 0 %lu 0\n",
              (unsigned long)ssh->scpMTime,
              (unsigned long)ssh->scpATime);
#endif
    bufSz = (int)WSTRLEN(buf);

    ret = ScpStreamSend(ssh, (byte*)buf, bufSz);
    if (ret == bufSz) {
        WLOG(WS_LOG_DEBUG, "scp: sent timestamp: %s", buf);
        ret = WS_SUCCESS;
    }
    /* A non-blocking want is left as WS_WANT_READ/WS_WANT_WRITE for the caller
     * to retry (nothing is queued yet, so the resend is clean), consistent with
     * the SCP_SEND_FILE data path; only a real short send is fatal. */
    else if (ret != WS_WANT_READ && ret != WS_WANT_WRITE) {
        ret = WS_FATAL_ERROR;
    }

    return ret;
}




/* Sends file header (mode, file name) to peer.
 *
 * C<mode> <length> <filename>
 *
 * returns WS_SUCCESS on success, negative upon error
 */
static int SendScpFileHeader(WOLFSSH* ssh)
{
    int ret = WS_SUCCESS, bufSz;
    char buf[DEFAULT_SCP_MSG_SZ];
    char *filehdr;

    if (ssh == NULL)
        return WS_BAD_ARGUMENT;

#ifndef WSCPFILEHDR
    WMEMSET(buf, 0, sizeof(buf));
    WSNPRINTF(buf, sizeof(buf), "C%04o %u %s\n",
              ssh->scpFileMode & WOLFSSH_MODE_MASK,
              ssh->scpFileSz, ssh->scpFileName);
    filehdr = buf;
#else
    filehdr = WSCPFILEHDR(ssh);
    if (!filehdr)
        return WS_BAD_ARGUMENT;
#endif
    bufSz = (int)WSTRLEN(filehdr);
    ret = ScpStreamSend(ssh, (byte*)filehdr, bufSz);
    if (ret == bufSz) {
        WLOG(WS_LOG_DEBUG, "scp: sent file header: %s", filehdr);
        ret = WS_SUCCESS;
    }
    /* leave a non-blocking want for the caller to retry; only a real short
     * send is fatal (see SendScpTimestamp) */
    else if (ret != WS_WANT_READ && ret != WS_WANT_WRITE) {
        ret = WS_FATAL_ERROR;
    }
    return ret;
}

/* Sends directory message to peer, length is ignored but must
 * be present in message format (set to 0).
 *
 * D<mode> <length> <dirname>
 *
 * returns WS_SUCCESS on success, negative upon error
 */
static int SendScpEnterDirectory(WOLFSSH* ssh)
{
    int ret = WS_SUCCESS, bufSz;
    char buf[DEFAULT_SCP_MSG_SZ];

    if (ssh == NULL)
        return WS_BAD_ARGUMENT;

    WMEMSET(buf, 0, sizeof(buf));

    WSNPRINTF(buf, sizeof(buf), "D%04o 0 %s\n",
            ssh->scpFileMode & WOLFSSH_MODE_MASK,
            ssh->scpFileName);

    bufSz = (int)WSTRLEN(buf);

    ret = ScpStreamSend(ssh, (byte*)buf, bufSz);
    if (ret == bufSz) {
        WLOG(WS_LOG_DEBUG, "scp: sent directory msg: %s", buf);
        ret = WS_SUCCESS;
    }
    /* leave a non-blocking want for the caller to retry; only a real short
     * send is fatal (see SendScpTimestamp) */
    else if (ret != WS_WANT_READ && ret != WS_WANT_WRITE) {
        ret = WS_FATAL_ERROR;
    }

    return ret;
}

/* Sends end directory message to peer.
 *
 * returns WS_SUCCESS on success, negative upon error
 */
static int SendScpExitDirectory(WOLFSSH* ssh)
{
    int ret = WS_SUCCESS;
    char buf[2];

    if (ssh == NULL)
        return WS_BAD_ARGUMENT;

    buf[0] = 'E';
    buf[1] = '\n';

    ret = ScpStreamSend(ssh, (byte*)buf, sizeof(buf));
    if (ret == sizeof(buf)) {
        WLOG(WS_LOG_DEBUG, "scp: sent end directory msg: E");
        ret = WS_SUCCESS;
    }
    /* leave a non-blocking want for the caller to retry; only a real short
     * send is fatal (see SendScpTimestamp) */
    else if (ret != WS_WANT_READ && ret != WS_WANT_WRITE) {
        ret = WS_FATAL_ERROR;
    }

    return ret;
}

int DoScpSource(WOLFSSH* ssh)
{
    int ret = WS_SUCCESS;

    if (ssh == NULL)
        return WS_BAD_ARGUMENT;

    while (ret == WS_SUCCESS && ssh->scpState != SCP_DONE) {

        switch (ssh->scpState) {

            case SCP_SOURCE_BEGIN:
                WLOG(WS_LOG_DEBUG, scpState, "SCP_SOURCE_BEGIN");

                ssh->scpConfirm = ssh->ctx->scpSendCb(ssh,
                        WOLFSSH_SCP_NEW_REQUEST, NULL, NULL, 0, NULL, NULL,
                        NULL, 0, NULL, NULL, 0, wolfSSH_GetScpSendCtx(ssh));

                if (ssh->scpConfirm == WS_SCP_ABORT ||
                                                    ssh->scpConfirm == WS_EOF) {
                    ssh->scpState = SCP_RECEIVE_CONFIRMATION_WITH_RECEIPT;
                    ssh->scpNextState = SCP_DONE;
                } else {
                    ssh->scpState = SCP_SOURCE_INIT;
                }
                continue;

            case SCP_SOURCE_INIT:
                WLOG(WS_LOG_DEBUG, scpState, "SCP_SOURCE_INIT");

                if ( (ret = ScpSourceInit(ssh)) < WS_SUCCESS) {
                    break;
                }

                ssh->scpState = SCP_RECEIVE_CONFIRMATION;
                ssh->scpNextState = SCP_TRANSFER;
                continue;

            case SCP_SEND_CONFIRMATION:
                WLOG(WS_LOG_DEBUG, scpState, "SCP_SEND_CONFIRMATION");

                if ( (ret = SendScpConfirmation(ssh)) < WS_SUCCESS) {
                    LogScpStateError("SEND_CONFIRMATION", ret);
                    break;
                }

                ssh->scpState = ssh->scpNextState;
                continue;

            case SCP_CONFIRMATION_WITH_RECEIPT:
                WLOG(WS_LOG_DEBUG, scpState, "SCP_CONFIRMATION_WITH_RECEIPT");

                if ( (ret = SendScpConfirmation(ssh)) < WS_SUCCESS) {
                    LogScpStateError("SEND_CONFIRMATION", ret);
                    break;
                }

                ssh->scpState = SCP_RECEIVE_CONFIRMATION;
                continue;

            case SCP_RECEIVE_CONFIRMATION_WITH_RECEIPT:
                WLOG(WS_LOG_DEBUG, scpState,
                     "SCP_RECEIVE_CONFIRMATION_WITH_RECEIPT");

                if ( (ret = ReceiveScpConfirmation(ssh)) < WS_SUCCESS) {
                    LogScpStateError("RECEIVE_CONFIRMATION_WITH_RECEIPT", ret);
                    break;
                }

                ssh->scpState = SCP_SEND_CONFIRMATION;
                continue;

            case SCP_RECEIVE_CONFIRMATION:
                WLOG(WS_LOG_DEBUG, scpState, "SCP_RECEIVE_CONFIRMATION");

                if ( (ret = ReceiveScpConfirmation(ssh)) < WS_SUCCESS) {
                    LogScpStateError("RECEIVE_CONFIRMATION", ret);
                    break;
                }

                ssh->scpState = ssh->scpNextState;
                continue;

            case SCP_TRANSFER:
                WLOG(WS_LOG_DEBUG, scpState, "SCP_TRANSFER");

                ssh->scpConfirm = ssh->ctx->scpSendCb(ssh,
                        ssh->scpRequestType, ssh->scpBasePath,
                        ssh->scpFileName, ssh->scpFileNameSz, &(ssh->scpMTime),
                        &(ssh->scpATime), &(ssh->scpFileMode),
                        ssh->scpFileOffset, &(ssh->scpFileSz),
                        ssh->scpFileBuffer + ssh->scpBufferedSz,
                        ssh->scpFileBufferSz - ssh->scpBufferedSz,
                        wolfSSH_GetScpSendCtx(ssh));

                if (ssh->scpConfirm == WS_SCP_ENTER_DIR) {
                    ssh->scpState = SCP_SEND_ENTER_DIRECTORY;
                    continue;

                } else if (ssh->scpConfirm == WS_SCP_EXIT_DIR) {
                    ssh->scpState = SCP_SEND_EXIT_DIRECTORY;
                    continue;

                } else if (ssh->scpConfirm == WS_SCP_EXIT_DIR_FINAL) {
                    ssh->scpState = SCP_SEND_EXIT_DIRECTORY_FINAL;
                    continue;

                } else if (ssh->scpConfirm == WS_SCP_COMPLETE) {
                    ssh->scpState = SCP_DONE;
                    continue;

                } else if (ssh->scpConfirm == WS_SCP_ABORT) {
                #if !defined(NO_FILESYSTEM) && \
                        !defined(WOLFSSH_SCP_USER_CALLBACKS)
                    /* drain any partial recursive dir stack so a later exec on
                     * this connection starts from a fresh root, not a stale
                     * handle left by the aborted walk */
                    ScpSendCtx* sendCtx =
                        (ScpSendCtx*)wolfSSH_GetScpSendCtx(ssh);
                    if (sendCtx != NULL)
                        ScpSendCtxFreeDirs(ssh->fs, sendCtx, ssh->ctx->heap);
                #endif
                    ssh->scpState = SCP_SEND_CONFIRMATION;
                    ssh->scpNextState = SCP_DONE;
                    continue;

                } else if (ssh->scpConfirm >= 0) {

                    /* transfer buffered file data */
                    ssh->scpBufferedSz += ssh->scpConfirm;
                    ssh->scpConfirm = WS_SCP_CONTINUE;

                    /* send timestamp and file header once per file. A send
                     * callback may return 0 bytes on its first call (metadata
                     * now, data next), so key on the flag not scpFileOffset. */
                    if (!ssh->scpFileHeaderSent) {
                        if (ssh->scpTimestamp == 1) {
                            ssh->scpState = SCP_SEND_TIMESTAMP;
                        } else {
                            ssh->scpState = SCP_SEND_FILE_HEADER;
                        }
                    } else {
                        ssh->scpState = SCP_SEND_FILE;
                    }
                    continue;

                } else {

                    /* error */
                    ret = ssh->scpConfirm;
                    break;
                }

            case SCP_SEND_TIMESTAMP:
                WLOG(WS_LOG_DEBUG, scpState, "SCP_SEND_TIMESTAMP");

                if ( (ret = SendScpTimestamp(ssh)) < WS_SUCCESS) {
                    LogScpStateError("SEND_TIMESTAMP", ret);
                    break;
                }

                ssh->scpState = SCP_RECEIVE_CONFIRMATION;
                ssh->scpNextState = SCP_SEND_FILE_HEADER;
                continue;

            case SCP_SEND_ENTER_DIRECTORY:
                WLOG(WS_LOG_DEBUG, scpState, "SCP_SEND_ENTER_DIRECTORY");

                if ( (ret = SendScpEnterDirectory(ssh)) < WS_SUCCESS) {
                    LogScpStateError("SEND_ENTER_DIRECTORY", ret);
                    break;
                }

                ssh->scpState = SCP_RECEIVE_CONFIRMATION;
                ssh->scpNextState = SCP_TRANSFER;
                continue;

            case SCP_SEND_EXIT_DIRECTORY:
                WLOG(WS_LOG_DEBUG, scpState, "SCP_SEND_EXIT_DIRECTORY");

                if ( (ret = SendScpExitDirectory(ssh)) < WS_SUCCESS) {
                    LogScpStateError("SEND_EXIT_DIRECTORY", ret);
                    break;
                }

                ssh->scpState = SCP_RECEIVE_CONFIRMATION;
                ssh->scpNextState = SCP_TRANSFER;
                continue;

            case SCP_SEND_EXIT_DIRECTORY_FINAL:
                WLOG(WS_LOG_DEBUG, scpState, "SCP_SEND_EXIT_DIRECTORY_FINAL");

                if ( (ret = SendScpExitDirectory(ssh)) < WS_SUCCESS) {
                    LogScpStateError("SEND_EXIT_DIRECTORY", ret);
                    break;
                }

                ssh->scpState = SCP_RECEIVE_CONFIRMATION;
                ssh->scpNextState = SCP_DONE;
                continue;
            case SCP_SEND_FILE_HEADER:
                WLOG(WS_LOG_DEBUG, scpState, "SCP_SEND_FILE_HEADER");

                if ( (ret = SendScpFileHeader(ssh)) < WS_SUCCESS) {
                    LogScpStateError("SEND_FILE_HEADER", ret);
                    break;
                }

                ssh->scpFileHeaderSent = 1;
                ssh->scpState = SCP_RECEIVE_CONFIRMATION;
                ssh->scpNextState = SCP_SEND_FILE;
                continue;

            case SCP_SEND_FILE:
                WLOG(WS_LOG_DEBUG, scpState, "SCP_SEND_FILE");

                /* nothing buffered (send callback returned 0 bytes): skip the
                 * send so no zero-length CHANNEL_DATA goes on the wire; routing
                 * below handles the empty buffer */
                if (ssh->scpBufferedSz > 0) {
                    ret = ScpStreamSend(ssh, ssh->scpFileBuffer,
                                        ssh->scpBufferedSz);
                    if (ret == WS_WANT_READ || ret == WS_WANT_WRITE) {
                        /* ScpStreamSend already drove the worker through any
                         * rekey or full window; a non-blocking want means the
                         * socket is not ready. Surface it for the caller to
                         * retry without closing the file mid-transfer.
                         * scpBufferedSz and scpFileOffset are preserved for the
                         * next call. */
                        break;
                    }
                    if (ret == WS_EXTDATA) {
                        _DumpExtendedData(ssh);
                        continue;
                    }
                    if (ret < 0) {
                    #if !defined(NO_FILESYSTEM) && \
                            !defined(WOLFSSH_SCP_USER_CALLBACKS)
                        /* if the socket send had a fatal error, try to close any
                         * open file descriptor before exit */
                        ScpSendCtx* sendCtx = NULL;
                        sendCtx = (ScpSendCtx*)wolfSSH_GetScpSendCtx(ssh);
                        if (sendCtx != NULL) {
                            WFCLOSE(ssh->fs, sendCtx->fp);
                            sendCtx->fp = NULL;
                        }
                    #endif
                        WLOG(WS_LOG_ERROR, scpError, "failed to send file", ret);
                        break;
                    }

                    ssh->scpFileOffset += ret;
                    if (ret != (int)ssh->scpBufferedSz) {
                        /* case where not all of buffer was sent */
                        WMEMMOVE(ssh->scpFileBuffer, ssh->scpFileBuffer + ret,
                                 ssh->scpBufferedSz - ret);
                    }
                    ssh->scpBufferedSz -= ret;
                    ret = WS_SUCCESS;
                }

                if (ssh->scpBufferedSz > 0) {
                    /* There is still file data in the buffer to send,
                     * go ahead and try to send it by repeating this
                     * state. */
                    continue;
                }
                else if (ssh->scpFileOffset < ssh->scpFileSz) {
                    ssh->scpState = SCP_TRANSFER;
                    ssh->scpRequestType = WOLFSSH_SCP_CONTINUE_FILE_TRANSFER;

                } else {
                    ssh->scpState = SCP_CONFIRMATION_WITH_RECEIPT;
                    if (ssh->scpIsRecursive) {
                        ssh->scpFileOffset = 0;
                        ssh->scpBufferedSz = 0;
                        ssh->scpFileHeaderSent = 0;
                        ssh->scpATime = 0;
                        ssh->scpMTime = 0;
                        ssh->scpNextState = SCP_TRANSFER;
                        ssh->scpRequestType = WOLFSSH_SCP_RECURSIVE_REQUEST;
                    } else {
                        ssh->scpNextState = SCP_DONE;
                    }
                }

                continue;

            default:
                break;

        } /* end switch */

    } /* end while */

    if (ret == WS_SUCCESS && ssh->scpState == SCP_DONE) {
        /* Send SSH_MSG_CHANNEL_CLOSE */
        ret = wolfSSH_stream_exit(ssh, 0);
    }

    return ret;
}

int DoScpRequest(WOLFSSH* ssh)
{
    int ret = WS_SUCCESS;

    if (ssh == NULL)
        return WS_BAD_ARGUMENT;

    if (ssh->ctx->scpRecvCb == NULL) {
        WLOG(WS_LOG_DEBUG, "scp error: receive callback is null, please set");
        return WS_BAD_ARGUMENT;
    }

    while (ret == WS_SUCCESS && ssh->scpState != SCP_DONE) {

        switch (ssh->scpRequestState) {

            case SCP_PARSE_COMMAND:
                WLOG(WS_LOG_DEBUG, scpState, "SCP_PARSE_COMMAND");

                if ( (ret = ParseScpCommand(ssh)) < WS_SUCCESS) {
                    WLOG(WS_LOG_ERROR, scpError, "PARSE_COMMAND", ret);
                    break;
                }

                if (ssh->scpDirection == WOLFSSH_SCP_TO) {
                    ssh->scpRequestState = SCP_SINK;
                    ssh->scpState = SCP_SINK_BEGIN;
                    continue;

                } else if (ssh->scpDirection == WOLFSSH_SCP_FROM) {
                    ssh->scpRequestState = SCP_SOURCE;
                    ssh->scpState = SCP_SOURCE_BEGIN;
                    continue;

                } else {
                    ret = WS_SCP_CMD_E;
                    WLOG(WS_LOG_ERROR, scpError, "invalid command", ret);
                    break;
                }

            case SCP_SINK:
                WLOG(WS_LOG_DEBUG, scpState, "SCP_SINK");
                if ( (ret = DoScpSink(ssh)) < WS_SUCCESS) {
                    LogScpStateError("SCP_SINK", ret);
                }
                break;

            case SCP_SOURCE:
                WLOG(WS_LOG_DEBUG, scpState, "SCP_SOURCE");
                if ( (ret = DoScpSource(ssh)) < WS_SUCCESS) {
                    LogScpStateError("SCP_SOURCE", ret);
                }
                break;
        }
    }

    if (ret == WS_SUCCESS && ssh->scpState == SCP_DONE) {
        byte buf[1];

        /* Peer MUST send back a SSH_MSG_CHANNEL_CLOSE unless already
            sent*/
        ret = ScpStreamRead(ssh, buf, 1);
        if (ret == WS_SOCKET_ERROR_E || ret == WS_CHANNEL_CLOSED) {
            WLOG(WS_LOG_DEBUG, scpState, "Peer hung up, but SCP is done");
            ret = WS_SUCCESS;
        }
        else if (ret != WS_EOF) {
            WLOG(WS_LOG_DEBUG, scpState, "Did not receive EOF packet");
        }
        else {
            ret = WS_SUCCESS;
        }
    }

    return ret;
}

/* Sets the error message that is sent back to the peer when an error or fatal
 * confirmation message is sent. Expected to be used inside the scp
 * callbacks.
 *
 * ssh     - pointer to initialized WOLFSSH structure
 * message - error message to be sent to peer, dynamically allocated, freed
 *           internally when WOLFSSH session is freed.
 *
 * Returns WS_SUCCESS on success, negative upon error
 */
WOLFSSH_API int wolfSSH_SetScpErrorMsg(WOLFSSH* ssh, const char* message)
{
    char* value = NULL;
    word32 valueSz = 0;
    int ret = WS_SUCCESS;

    if (ssh == NULL)
        ret = WS_BAD_ARGUMENT;

    if (ret == WS_SUCCESS) {
        valueSz = (word32)WSTRLEN(message) + 1;
        if (valueSz > 0)
            value = (char*)WMALLOC(valueSz + SCP_MIN_CONFIRM_SZ,
                                   ssh->ctx->heap, DYNTYPE_STRING);
        if (value == NULL)
            ret = WS_MEMORY_E;
    }

    if (ret == WS_SUCCESS) {
        /* leave room for cmd at beginning, add \n\0 at end */
        WSTRNCPY(value + 1, message, valueSz);
        *(value + valueSz)     = '\n';
        *(value + valueSz + 1) = '\0';

        if (ssh->scpConfirmMsg != NULL) {
            WFREE(ssh->scpConfirmMsg, ssh->ctx->heap, DYNTYPE_STRING);
            ssh->scpConfirmMsg = NULL;
        }

        ssh->scpConfirmMsg = value;
        ssh->scpConfirmMsgSz = valueSz + SCP_MIN_CONFIRM_SZ;
    }

    return ret;
}

/* Determine if channel command sent in initial negotiation is scp.
 * Return 1 if yes, 0 if no */
int ChannelCommandIsScp(WOLFSSH* ssh)
{
    const char* cmd;
    int ret = 0;

    if (ssh == NULL)
        return WS_BAD_ARGUMENT;

    cmd = wolfSSH_GetSessionCommand(ssh);
    if (cmd != NULL && WSTRLEN(cmd) >= 3) {
        if (WSTRNCMP(cmd, "scp", 3) == 0)
            ret = 1;
    }

    return ret;
}

/* Reads file mode from SCP header string, mode is prefixed by "C", ex: "C0644",
 * places mode in ssh->scpFileMode.
 *
 * buf      - buffer containing mode string
 * bufSz    - size of buffer
 * inOutIdx - [IN/OUT] index into buffer, sets index after mode
 *
 * returns WS_SUCCESS on success, negative upon error
 */
static int GetScpFileMode(WOLFSSH* ssh, byte* buf, word32 bufSz,
                          word32* inOutIdx)
{
    int ret = WS_SUCCESS;
    word32 idx;
    byte modeOctet[SCP_MODE_OCTET_LEN + 1];
    int mode, i;

    if (ssh == NULL || buf == NULL || inOutIdx == NULL ||
        bufSz < (SCP_MODE_OCTET_LEN + 1))
        return WS_BAD_ARGUMENT;

    idx = *inOutIdx;

    /* skip leading "C" or "D" */
    if ((buf[idx] != 'C' && buf[idx] != 'D') || (idx + 1 > bufSz))
        return WS_BAD_ARGUMENT;
    idx++;

    WMEMCPY(modeOctet, buf + idx, SCP_MODE_OCTET_LEN);
    modeOctet[SCP_MODE_OCTET_LEN] = '\0';
    idx += SCP_MODE_OCTET_LEN;

    /* convert octal string to int without mp_read_radix() */
    mode = 0;

    for (i = 0; i < SCP_MODE_OCTET_LEN; i++)
    {
        if (modeOctet[i] < '0' || modeOctet[i] > '7') {
            ret = WS_BAD_ARGUMENT;
            break;
        }
        mode <<= 3;
        mode |= (modeOctet[i] - '0');
    }

    if (ret == WS_SUCCESS) {
        /* store file mode, masking off setuid/setgid/sticky bits from the
         * peer-supplied value to match the send path */
        ssh->scpFileMode = mode & WOLFSSH_MODE_MASK;
        /* eat trailing space */
        if (bufSz >= (word32)(idx +1))
            idx++;
        ret = WS_SUCCESS;
        *inOutIdx = idx;
    }

    return ret;
}


#ifdef WOLFSSH_TEST_INTERNAL
int wolfSSH_TestScpGetFileMode(WOLFSSH* ssh, byte* buf, word32 bufSz,
        word32* inOutIdx)
{
    return GetScpFileMode(ssh, buf, bufSz, inOutIdx);
}
#endif /* WOLFSSH_TEST_INTERNAL */


/* Locates first space present in given string (buf) and sets inOutIdx
 * to that offset.
 *
 * Returns WS_SUCCESS on success, or negative upon error */
static int FindSpaceInString(byte* buf, word32 bufSz, word32* inOutIdx)
{
    word32 idx;
    int spaceFound = 0;

    if (buf == NULL || inOutIdx == NULL)
        return WS_BAD_ARGUMENT;

    idx = *inOutIdx;

    while (idx < bufSz) {
        if (buf[idx] == ' ') {
            spaceFound = 1;
            break;
        }
        idx++;
    }

    if (!spaceFound)
        return WS_FATAL_ERROR;

    *inOutIdx = idx;

    return WS_SUCCESS;
}

/* Reads file size from beginning of string, expects space to be after,
 * places size in ssh->scpFileSz.
 *
 * buf      - buffer containing size string
 * bufSz    - size of buffer
 * inOutIdx - [IN/OUT] index into buffer, increments index upon return
 *
 * returns WS_SUCCESS on success, negative upon error
 */
static int GetScpFileSize(WOLFSSH* ssh, byte* buf, word32 bufSz,
                          word32* inOutIdx)
{
    int ret = WS_SUCCESS;
    word32 idx, spaceIdx;

    if (ssh == NULL || buf == NULL || inOutIdx == NULL)
        return WS_BAD_ARGUMENT;

    idx = *inOutIdx;
    spaceIdx = idx;

    if (FindSpaceInString(buf, bufSz, &spaceIdx) != WS_SUCCESS)
        ret = WS_SCP_BAD_MSG_E;

    if (ret == WS_SUCCESS) {
        /* replace space with newline to terminate the size field, then parse
         * with strtoull() which parses in 64-bit width, so a negative field
         * such as "-1" wraps above UINT32_MAX and is rejected by the bound
         * below instead of becoming a huge word32 size */
        char* endptr = NULL;
        word64 fileSz;

        buf[spaceIdx] = '\n';
        errno = 0;
        fileSz = (word64)strtoull((char*)(buf + idx), &endptr, 10);
        buf[spaceIdx] = ' ';

        /* reject any parse error (e.g. ERANGE overflow), a non-numeric field
         * (parse must consume every character up to the separator), and
         * sizes too large for the word32 scpFileSz */
        if (errno != 0 || endptr != (char*)(buf + spaceIdx) ||
            fileSz > UINT32_MAX) {
            ret = WS_SCP_BAD_MSG_E;
        }
        else {
            ssh->scpFileSz = (word32)fileSz;

            /* increment idx to space, then eat trailing space */
            idx = spaceIdx;
            if (bufSz >= (word32)(idx + 1))
                idx++;

            *inOutIdx = idx;
        }
    }

    return ret;
}

/* Reads file name from beginning of string, expects string to be
 * null terminated.
 *
 * Places null-terminated file name in ssh->scpFileName and file name
 * length (not including null terminator) in ssh->scpFileNameSz.
 *
 * buf      - buffer containing size string
 * bufSz    - size of buffer
 * inOutIdx - [IN/OUT] index into buffer, increments index upon return
 *
 * returns WS_SUCCESS on success, negative upon error
 */
static int GetScpFileName(WOLFSSH* ssh, byte* buf, word32 bufSz,
                          word32* inOutIdx)
{
    int ret = WS_SUCCESS;
    word32 idx, len;
    const char* fileName;

    if (ssh == NULL || buf == NULL || inOutIdx == NULL)
        return WS_BAD_ARGUMENT;

    idx = *inOutIdx;
    len = (word32)WSTRLEN((char*)(buf + idx));

    if ((idx + len) > bufSz)
        ret = WS_SCP_CMD_E;

    if (ret == WS_SUCCESS) {
        word32 i;

        fileName = (const char*)(buf + idx);

        if (len == 0 ||
                (len == 1 && fileName[0] == '.') ||
                (len == 2 && fileName[0] == '.' && fileName[1] == '.')) {
            WLOG(WS_LOG_ERROR, "scp: invalid file name component received");
            wolfSSH_SetScpErrorMsg(ssh, "invalid file name");
            return WS_SCP_BAD_MSG_E;
        }

        for (i = 0; i < len; i++) {
            char c = fileName[i];

            if (c == '/' || c == '\\'
#if defined(USE_WINDOWS_API) || defined(WOLFSSL_NUCLEUS)
                || c == ':'
#endif
            ) {
                WLOG(WS_LOG_ERROR, "scp: invalid file name component received");
                wolfSSH_SetScpErrorMsg(ssh, "invalid file name");
                return WS_SCP_BAD_MSG_E;
            }
        }

        if (ssh->scpFileName != NULL) {
            WFREE(ssh->scpFileName, ssh->ctx->heap, DYNTYPE_STRING);
            ssh->scpFileName = NULL;
            ssh->scpFileNameSz = 0;
        }

        ssh->scpFileName = (char*)WMALLOC(len + 1, ssh->ctx->heap,
                                          DYNTYPE_STRING);
        if (ssh->scpFileName == NULL)
            ret = WS_MEMORY_E;

        if (ret == WS_SUCCESS) {
            WMEMCPY(ssh->scpFileName, buf + idx, len);
            ssh->scpFileName[len] = '\0';
            ssh->scpFileNameSz = len;

            *inOutIdx = idx;
        }
    }

    return ret;
}

/* Reads timestamp information (access, modification) from beginning
 * of string, expects space to be after each time value:
 *
 * T<modification_secs> 0 <access_secs> 0
 *
 * Places modification time in ssh->scpMTime and access time in
 * ssh->scpATime variables.
 *
 * buf      - buffer containing size string
 * bufSz    - size of buffer
 * inOutIdx - [IN/OUT] index into buffer, increments index upon return
 *
 * returns WS_SUCCESS on success, negative upon error
 */
static int GetScpTimestamp(WOLFSSH* ssh, byte* buf, word32 bufSz,
                           word32* inOutIdx)
{
    int ret = WS_SUCCESS;
    word32 idx, spaceIdx;

    if (ssh == NULL || buf == NULL || inOutIdx == NULL)
        return WS_BAD_ARGUMENT;

    idx = *inOutIdx;
    spaceIdx = idx;

    /* skip leading "T" */
    if (buf[idx] != 'T' || (idx + 1) > bufSz)
        return WS_SCP_TIMESTAMP_E;
    idx++;

    if (FindSpaceInString(buf, bufSz, &spaceIdx) != WS_SUCCESS)
        ret = WS_SCP_TIMESTAMP_E;

    /* read modification time */
    if (ret == WS_SUCCESS) {
        char* endptr = NULL;

        /* replace space with newline to terminate the field */
        buf[spaceIdx] = '\n';
        errno = 0;
        ssh->scpMTime = (word64)strtoull((char*)(buf + idx), &endptr, 10);
        buf[spaceIdx] = ' ';

        /* reject any parse error (e.g. ERANGE overflow) and a non-numeric
         * field, then step past the separating space */
        if (errno != 0 || endptr != (char*)(buf + spaceIdx)) {
            ret = WS_SCP_TIMESTAMP_E;
        }
        else if (spaceIdx + 1 < bufSz) {
            idx = spaceIdx + 1;
        }
        else {
            ret = WS_SCP_TIMESTAMP_E;
        }
    }

    /* skip '0 ' */
    if (ret == WS_SUCCESS) {
        if (buf[idx] != '0') {
            ret = WS_SCP_TIMESTAMP_E;
        }
        else {
            idx++;
            if (idx >= bufSz || buf[idx] != ' ') {
                ret = WS_SCP_TIMESTAMP_E;
            }
            else {
                idx++;
                if (idx >= bufSz)
                    ret = WS_SCP_TIMESTAMP_E;
            }
        }
    }

    /* read access time */
    if (ret == WS_SUCCESS) {
        spaceIdx = idx;
        if (FindSpaceInString(buf, bufSz, &spaceIdx) != WS_SUCCESS)
            ret = WS_SCP_TIMESTAMP_E;
    }

    if (ret == WS_SUCCESS) {
        char* endptr = NULL;
        /* replace space with newline for strtoull */
        buf[spaceIdx] = '\n';
        errno = 0;
        ssh->scpATime = (word64)strtoull((char*)(buf + idx), &endptr, 10);
        /* restore space, increment idx past it */
        buf[spaceIdx] = ' ';

        if (errno != 0 || endptr != (char*)(buf + spaceIdx)) {
            ret = WS_SCP_TIMESTAMP_E;
        }
        else if (spaceIdx + 1 < bufSz) {
            idx = spaceIdx + 1;
        }
        else {
            ret = WS_SCP_TIMESTAMP_E;
        }
    }

    if (ret == WS_SUCCESS) {
        *inOutIdx = idx;
    }

    return ret;
}


#ifdef WOLFSSH_TEST_INTERNAL
int wolfSSH_TestScpGetFileSize(WOLFSSH* ssh, byte* buf, word32 bufSz,
        word32* inOutIdx)
{
    return GetScpFileSize(ssh, buf, bufSz, inOutIdx);
}

int wolfSSH_TestScpGetTimestamp(WOLFSSH* ssh, byte* buf, word32 bufSz,
        word32* inOutIdx)
{
    return GetScpTimestamp(ssh, buf, bufSz, inOutIdx);
}
#endif /* WOLFSSH_TEST_INTERNAL */


/* checks for if directory is being renamed in command
 *
 * returns WS_SUCCESS on success
 */
static int ScpCheckForRename(WOLFSSH* ssh)
{
    /* case of file, not directory */
    char buf[DEFAULT_SCP_MSG_SZ];
    int  sz = (int)WSTRLEN(ssh->scpBasePath);
    int  idx;

    /* buf holds scpBasePath plus the "/.." suffix and a terminator, so bound
     * by sz. The old checks bounded by cmdSz, the peer command/source length,
     * which is unrelated to scpBasePath. */
    if (sz + 4 > DEFAULT_SCP_MSG_SZ) {
        return WS_BUFFER_E;
    }

    /* Copy the full base path including its terminator; copying a partial
     * length would leave the tail of buf uninitialized and make the CleanPath
     * result below depend on stack garbage. */
    WMEMCPY(buf, ssh->scpBasePath, sz + 1);
    buf[sz] = '\0';
    WSTRNCAT(buf, "/..", DEFAULT_SCP_MSG_SZ);

    idx = wolfSSH_CleanPath(ssh, buf, DEFAULT_SCP_MSG_SZ);
    if (idx < 0) {
        return WS_FATAL_ERROR;
    }
    idx = idx + 1; /* +1 for delimiter */
#ifdef WOLFSSL_NUCLEUS
    /* no delimiter to skip in case of at base address */
    if (idx == 4) { /* case of 4 for drive letter plus ":\" + 1 */
        idx--;
    }
#else
    /* allow placing file at base address ':/' */
    if (WSTRLEN(buf) == 1 && buf[0] == WS_DELIM) {
        idx--; /* no delimiter at base */
    }
#endif
    /* idx is the offset of the filename component within scpBasePath, so it
     * cannot exceed the base path length. */
    if (idx > sz) {
        return WS_BUFFER_E;
    }

    sz = sz - idx; /* size of file name */
    if (ssh->scpFileNameSz < (word32)sz || ssh->scpFileName == NULL) {
        if (ssh->scpFileName != NULL) {
            WFREE(ssh->scpFileName, ssh->ctx->heap, DYNTYPE_STRING);
            ssh->scpFileNameSz = 0;
        }
        ssh->scpFileName = (char*)WMALLOC(sz + 1, ssh->ctx->heap,
            DYNTYPE_STRING);
        if (ssh->scpFileName == NULL) {
            WLOG(WS_LOG_DEBUG, scpError, "memory error creating file name",
                    WS_MEMORY_E);
            ssh->scpBasePath = NULL;
            return WS_MEMORY_E;
        }
        ssh->scpFileName[0] = '\0'; /* make sure null terminated for check */
    }

    /* are we not going down into a directory? i.e. last char is delimiter */
    if (ssh->scpBasePath[WSTRLEN(ssh->scpBasePath) - 1] != '/' &&
            ssh->scpBasePath[WSTRLEN(ssh->scpBasePath) - 1] != '\\') {

        /* is the last name in the path different then fileName found */
        if (WSTRNCMP(ssh->scpFileName, ssh->scpBasePath + idx, sz) != 0) {
            WLOG(WS_LOG_DEBUG, "scp: renaming from %s to %s",
                    ssh->scpFileName, ssh->scpBasePath + idx);
            ssh->scpFileReName = ssh->scpFileName;
            WSTRNCPY(ssh->scpFileName, ssh->scpBasePath + idx, sz + 1);
            ssh->scpFileName[sz]  = '\0';
            ssh->scpFileNameSz    = sz;
            *((char*)ssh->scpBasePath + idx) = '\0';
        }
    }

    return WS_SUCCESS;
}


/* helps with checking if the base path is a directory or file
 * returns WS_SUCCESS on success */
static int ParseBasePathHelper(WOLFSSH* ssh)
{
    int ret;
    ret = ScpCheckForRename(ssh);
#ifndef NO_FILESYSTEM
    if (ret == WS_SUCCESS) {
        ScpSendCtx ctx;

        WMEMSET(&ctx, 0, sizeof(ScpSendCtx));

        if (ScpPushDir(ssh->fs, &ctx, ssh->scpBasePath, ssh->ctx->heap) != WS_SUCCESS) {
            WLOG(WS_LOG_DEBUG, "scp : issue opening base dir");
            ssh->error = WS_INVALID_PATH_E;
            ret = WS_FATAL_ERROR;
        }
        else {
            ret = ScpPopDir(ssh->fs, &ctx, ssh->ctx->heap);
            if (ret == WS_SCP_DIR_STACK_EMPTY_E) {
                ret = WS_SUCCESS; /* is ok to empty the directory stack here */
            }
        }
    }
#endif /* NO_FILESYSTEM */

    /* default case of directory */
    return ret;
}


/*int GetScpBasePath(WOLFSSH* ssh, const char* in)
{
    int ret = WS_SUCCESS, len;

    if (ssh == NULL || in == NULL)
        return WS_BAD_ARGUMENT;

    if (ssh->scpBasePath != NULL) {
        WFREE(ssh->scpBasePath, ssh->ctx->heap, DYNTYPE_STRING);
        ssh->spBasePath = NULL;
    }

    len = (int)WSTRLEN(in);
    ssh->scpBasePath = (char*)WMALLOC(len, ssh->ctx->heap, DYNTYPE_STRING);

    if (ssh->scpBasePath == NULL) {
        ret = WS_MEMORY_E;
    } else {
        WMEMCPY(ssh->scpBasePath, in, len);
        ssh->scpBasePath[len] = '\0';
    }

    return ret;
}*/

/* Parse scp command received, currently only looks for and stores the
 * SCP base path being written to.
 *
 * return WS_SUCCESS on success, negative upon error
 */
int ParseScpCommand(WOLFSSH* ssh)
{
    int ret = WS_SUCCESS;
    const char* cmd;
    word32 cmdSz, idx = 0;

    if (ssh == NULL)
        return WS_BAD_ARGUMENT;

    cmd = wolfSSH_GetSessionCommand(ssh);
    if (cmd == NULL)
        ret = WS_SCP_CMD_E;

    if (ret == WS_SUCCESS) {
        cmdSz = (word32)WSTRLEN(cmd);

        while ((idx + 1 < cmdSz) && (ret == WS_SUCCESS)) {

            if (cmd[idx] == ' ' && cmd[idx + 1] == '-' && (idx + 2 < cmdSz)) {
                idx = idx + 2;

                switch (cmd[idx]) {
                    case 'r':
                        ssh->scpIsRecursive = 1;
                        ssh->scpRequestType = WOLFSSH_SCP_RECURSIVE_REQUEST;
                        break;

                    case 'p':
                        ssh->scpTimestamp = 1;
                        break;

                    case 't':
                        ssh->scpDirection = WOLFSSH_SCP_TO;
                        ssh->scpBasePathSz = cmdSz + WOLFSSH_MAX_FILENAME;
                        ssh->scpBasePathDynamic = (char*)WMALLOC(
                                ssh->scpBasePathSz,
                                ssh->ctx->heap, DYNTYPE_BUFFER);
                        if (ssh->scpBasePathDynamic == NULL) {
                            return WS_MEMORY_E;
                        }
                        WMEMSET(ssh->scpBasePathDynamic, 0, ssh->scpBasePathSz);
                        if (idx + 2 < cmdSz) {
                            /* skip space */
                            idx += 2;
                            ssh->scpBasePath = ssh->scpBasePathDynamic;
                            WMEMCPY(ssh->scpBasePathDynamic, cmd + idx,
                                cmdSz - idx);
                            if (wolfSSH_CleanPath(ssh,
                                    ssh->scpBasePathDynamic,
                                    ssh->scpBasePathSz) < 0) {
                                ret = WS_FATAL_ERROR;
                            }
                            else {
                                ret = ParseBasePathHelper(ssh);
                            }
                        }
                        break;

                    case 'f':
                        ssh->scpDirection = WOLFSSH_SCP_FROM;
                        ssh->scpBasePathSz = cmdSz + WOLFSSH_MAX_FILENAME;
                        ssh->scpBasePathDynamic = (char*)WMALLOC(
                                ssh->scpBasePathSz,
                                ssh->ctx->heap, DYNTYPE_BUFFER);
                        if (ssh->scpBasePathDynamic == NULL) {
                            return WS_MEMORY_E;
                        }
                        WMEMSET(ssh->scpBasePathDynamic, 0, ssh->scpBasePathSz);
                        if (idx + 2 < cmdSz) {
                            /* skip space */
                            idx += 2;
                            ssh->scpBasePath = ssh->scpBasePathDynamic;
                            WMEMCPY(ssh->scpBasePathDynamic, cmd + idx,
                                cmdSz - idx);
                            if (wolfSSH_CleanPath(ssh,
                                        ssh->scpBasePathDynamic,
                                        ssh->scpBasePathSz) < 0)
                                ret = WS_FATAL_ERROR;
                        }
                        break;
                } /* end switch */
            }
            idx++;
        } /* end while */

        if (ssh->scpDirection != WOLFSSH_SCP_TO &&
            ssh->scpDirection != WOLFSSH_SCP_FROM) {
            ret = WS_SCP_CMD_E;
        }
    }

    return ret;
}

/* Reads and parses SCP protocol control messages
 *
 * Reads up to DEFAULT_SCP_MSG_SZ characters and null-terminates the string.
 * If string is greater than DEFAULT_SCP_MSG_SZ, then only
 * DEFAULT_SCP_MSG_SZ-1 characters are read and string is NULL-terminated.
 *
 * returns WS_SUCCESS on success, negative upon error
 */
int ReceiveScpMessage(WOLFSSH* ssh)
{
    int sz = 0, ret = WS_SUCCESS;
    word32 idx = 0;
    byte* buf;

    if (ssh == NULL)
        return WS_BAD_ARGUMENT;

    /* create persistent msg buffer in case of nonblocking */
    if (ssh->scpRecvMsg == NULL) {
        ssh->scpRecvMsg = (char*)WMALLOC(DEFAULT_SCP_MSG_SZ, ssh->ctx->heap,
                DYNTYPE_STRING);
        if (ssh->scpRecvMsg == NULL) {
            return WS_MEMORY_E;
        }
        ssh->scpRecvMsgSz = 0;
    }
    buf = (byte*)ssh->scpRecvMsg;

    /* keep reading until newline found */
    do {
        int err;
        word32 lastChannel = 0;

        if (ssh->scpRecvMsgSz >= DEFAULT_SCP_MSG_SZ - 1) {
            WLOG(WS_LOG_ERROR, "scp: buffer not big enough to recv message");
            return WS_BUFFER_E;
        }

        /* Flush queued output before polling. A KEXINIT enqueued by a rekey
         * would otherwise sit unsent while wolfSSH_worker runs DoReceive before
         * its own flush, deadlocking against a peer that waits for our
         * KEXINIT. */
        if (wolfSSH_OutputPending(ssh)) {
            ret = wolfSSH_SendPacket(ssh);
            if (ret < 0)
                return ret;
        }

        /* If channel data is already buffered, read it directly rather than
         * polling the socket. A control message delivered into the channel
         * buffer while a rekey was completing leaves wolfSSH_worker returning
         * the rekey status (not WS_CHAN_RXD), so without this the buffered
         * message is never read and the next worker blocks on the socket. */
        if (wolfSSH_stream_peek(ssh, NULL, 1) > 0) {
            sz = wolfSSH_stream_read(ssh, buf + ssh->scpRecvMsgSz,
                    DEFAULT_SCP_MSG_SZ - ssh->scpRecvMsgSz);
            /* match the WS_CHAN_RXD branch below: return on a non-positive
             * read so a hypothetical zero cannot re-loop this peek path */
            if (sz <= 0)
                return sz;
            ssh->scpRecvMsgSz += sz;
            sz = ssh->scpRecvMsgSz;
            continue;
        }

        err = wolfSSH_worker(ssh, &lastChannel);
        if (err < 0) {
            int rc;

            rc = wolfSSH_get_error(ssh);
            switch (rc) {
                case WS_CHAN_RXD:
                    sz = wolfSSH_ChannelIdRead(ssh, lastChannel,
                        buf + ssh->scpRecvMsgSz,
                        DEFAULT_SCP_MSG_SZ - ssh->scpRecvMsgSz);
                    if (sz <= 0) {
                        return sz;
                    }
                    ssh->scpRecvMsgSz += sz;
                    sz = ssh->scpRecvMsgSz;
                    break;

                case WS_EXTDATA:
                    _DumpExtendedData(ssh);
                    break;

                case WS_WINDOW_FULL:
                case WS_REKEYING:
                    continue;
                case WS_CHANNEL_CLOSED:
                    return WS_EOF;
                default:
                    return err;
            }
        }

        /* check if wolfSSH_worker returns 0 from handling a channel eof */
        if (err == 0) {
            WOLFSSH_CHANNEL* channel;
            channel = wolfSSH_ChannelFind(ssh, lastChannel, WS_CHANNEL_ID_SELF);
            if (channel == NULL) {
                ret = WS_INVALID_CHANID;
            }
            else if (wolfSSH_ChannelGetEof(channel)) {
                return WS_EOF;
            }
        }
    } while (sz == 0 || buf[sz - 1] != 0x0a);

    /* null-terminate request, replace newline */
    if (sz > 0) {
        buf[sz - 1] = '\0';
    }

    switch (buf[0]) {
        case 'C':
            FALL_THROUGH;

        case 'D':
            if (buf[0] == 'C') {
                WLOG(WS_LOG_DEBUG, "scp: Receiving file: %s\n", buf);
                ssh->scpMsgType = WOLFSSH_SCP_MSG_FILE;
            } else {
                WLOG(WS_LOG_DEBUG, "scp: Receiving directory: %s\n", buf);
                ssh->scpMsgType = WOLFSSH_SCP_MSG_DIR;
            }

            if ((ret = GetScpFileMode(ssh, buf, sz, &idx)) != WS_SUCCESS)
                break;

            if ((ret = GetScpFileSize(ssh, buf, sz, &idx)) != WS_SUCCESS)
                break;

            if (ssh->scpFileReName == NULL) {
                ret = GetScpFileName(ssh, buf, sz, &idx);
            }
            else {
                ssh->scpFileReName = NULL;
            }
            break;

        case 'E':
            ssh->scpMsgType = WOLFSSH_SCP_MSG_END_DIR;
            ssh->scpFileState = WOLFSSH_SCP_END_DIR;
            break;

        case 'T':
            WLOG(WS_LOG_DEBUG, "scp: Receiving timestamp: %s\n", buf);
            ssh->scpMsgType = WOLFSSH_SCP_MSG_TIME;

            /* parse access and modification times */
            ret = GetScpTimestamp(ssh, buf, sz, &idx);
            break;

        default:
            ret = WS_SCP_BAD_MSG_E;
            WLOG(WS_LOG_DEBUG, "scp: Received invalid message\n");
            break;
    }

    ssh->scpRecvMsgSz = 0;

    return ret;
}

int ReceiveScpFile(WOLFSSH* ssh)
{
    int partSz, ret = WS_SUCCESS;

    if (ssh == NULL)
        return WS_BAD_ARGUMENT;

    /* We don't want to over-read the buffer. The file data is
     * terminated by the sender with a nul which is checked later. */
    partSz = min(ssh->scpFileSz - ssh->scpFileOffset, DEFAULT_SCP_BUFFER_SZ);

    /* don't even bother reading if read size is 0 */
    if (partSz == 0) return ret;

    if (ssh->scpFileBuffer == NULL) {
        ssh->scpFileBuffer = (byte*)WMALLOC(DEFAULT_SCP_BUFFER_SZ,
                ssh->ctx->heap, DYNTYPE_BUFFER);
        if (ssh->scpFileBuffer == NULL)
            ret = WS_MEMORY_E;
    }

    if (ret == WS_SUCCESS) {
        ret = ScpStreamRead(ssh, ssh->scpFileBuffer, partSz);
        if (ret > 0) {
            ssh->scpFileBufferSz = ret;
        }
    }

    return ret;
}

int SendScpConfirmation(WOLFSSH* ssh)
{
    char* msg;
    int msgSz, ret = WS_SUCCESS;
    char defaultMsg[2] = { 0x00, 0x00 };

    if (ssh == NULL)
        return WS_BAD_ARGUMENT;

    if (ssh->scpConfirmMsg != NULL &&
        ssh->scpConfirmMsgSz > SCP_MIN_CONFIRM_SZ &&
        ssh->scpConfirm == WS_SCP_ABORT) {
        msg = ssh->scpConfirmMsg;
    } else {
        msg = defaultMsg;
    }

    switch (ssh->scpConfirm) {
        case WS_SCP_ABORT:
            msg[0] = SCP_CONFIRM_ERR;
            break;

        case WS_SCP_CONTINUE:
            /* default to ok confirmation */
            FALL_THROUGH;

        default:
            msg[0] = SCP_CONFIRM_OK;
            break;
    }

    /* skip first byte for accurate strlen, may be 0 */
    msgSz = (int)XSTRLEN(msg + 1) + 1;
    ret = ScpStreamSend(ssh, (byte*)msg, msgSz);
    if (ret == msgSz && ssh->scpConfirm != WS_SCP_ABORT) {
        ret = WS_SUCCESS;
        WLOG(WS_LOG_DEBUG, "scp: sent confirmation (code: %d)", msg[0]);

        if (ssh->scpConfirmMsg != NULL) {
            WFREE(ssh->scpConfirmMsg, ssh->ctx->heap, DYNTYPE_STRING);
            ssh->scpConfirmMsg = NULL;
            ssh->scpConfirmMsgSz = 0;
        }
    }
    /* leave a non-blocking want for the caller to retry; a real short send or a
     * peer abort is fatal (see SendScpTimestamp) */
    else if (ret != WS_WANT_READ && ret != WS_WANT_WRITE) {
        ret = WS_FATAL_ERROR;
    }

    return ret;
}

int ReceiveScpConfirmation(WOLFSSH* ssh)
{
    int ret = WS_SUCCESS;
    int msgSz;
    byte msg[DEFAULT_SCP_MSG_SZ + 1];

    if (ssh == NULL)
        return WS_BAD_ARGUMENT;

    WMEMSET(msg, 0, sizeof(msg));
    msgSz = ScpStreamRead(ssh, msg, DEFAULT_SCP_MSG_SZ);

    if (msgSz < 0) {
        if (wolfSSH_get_error(ssh) == WS_EXTDATA)
            _DumpExtendedData(ssh);
        else
            ret = msgSz;
    } else if (msgSz > 1) {
        /* null terminate */
        msg[msgSz] = 0x00;
    }

    if (ret == WS_SUCCESS) {
        switch (msg[0]) {
            case SCP_CONFIRM_OK:
                break;
            case SCP_CONFIRM_ERR:
                FALL_THROUGH;
            case SCP_CONFIRM_FATAL:
                FALL_THROUGH;
            default:
                WLOG(WS_LOG_ERROR,
                     "scp error: peer sent error confirmation (code: %d)",
                     msg[0]);
                ret = WS_FATAL_ERROR;

                /* SCP peer signaled a failure, propagate the error back
                 * to the caller. If not set here WS_CHAN_RXD could be
                 * returned. */
                ssh->error = ret;
                break;
        }
    }

    return ret;
}


/* allow SCP callback handlers whether user or not */

/* install SCP recv callback */
void wolfSSH_SetScpRecv(WOLFSSH_CTX* ctx, WS_CallbackScpRecv cb)
{
    if (ctx)
        ctx->scpRecvCb = cb;
}


/* install SCP recv context */
void wolfSSH_SetScpRecvCtx(WOLFSSH* ssh, void *ctx)
{
    if (ssh)
        ssh->scpRecvCtx = ctx;
}


/* get SCP recv context */
void* wolfSSH_GetScpRecvCtx(WOLFSSH* ssh)
{
    if (ssh)
        return ssh->scpRecvCtx;

    return NULL;
}

/* install SCP send callback */
void wolfSSH_SetScpSend(WOLFSSH_CTX* ctx, WS_CallbackScpSend cb)
{
    if (ctx)
        ctx->scpSendCb = cb;
}


/* install SCP send context */
void wolfSSH_SetScpSendCtx(WOLFSSH* ssh, void *ctx)
{
    if (ssh)
        ssh->scpSendCtx = ctx;
}


/* get SCP send context */
void* wolfSSH_GetScpSendCtx(WOLFSSH* ssh)
{
    if (ssh)
        return ssh->scpSendCtx;

    return NULL;
}


#ifndef NO_WOLFSSH_CLIENT
int wolfSSH_SCP_connect(WOLFSSH* ssh, byte* cmd)
{
    int ret = WS_SUCCESS;

    if (ssh == NULL)
        return WS_BAD_ARGUMENT;

    if (ssh->error == WS_WANT_READ || ssh->error == WS_WANT_WRITE)
        ssh->error = WS_SUCCESS;

    if (ssh->connectState < CONNECT_SERVER_CHANNEL_REQUEST_DONE) {

        WLOG(WS_LOG_SCP, "Trying to do SSH connect first");
        WLOG(WS_LOG_SCP, "cmd = %s", (const char*)cmd);
        if ((ret = wolfSSH_SetChannelType(ssh, WOLFSSH_SESSION_EXEC, cmd,
                        (word32)WSTRLEN((const char*)cmd))) != WS_SUCCESS) {
            WLOG(WS_LOG_SCP, "Unable to set subsystem channel type");
            return ret;
        }

        if ((ret = wolfSSH_connect(ssh)) != WS_SUCCESS) {
            return ret;
        }
    }

    return ret;
}


/* Shared format so the size probe and the write cannot drift. */
#define SCP_CMD_FMT "scp -%c %s"

static char* MakeScpCmd(const char* name, char dir, void* heap)
{
    char* cmd;
    int sz;

#ifdef USE_WINDOWS_API
    sz = WSCPRINTF(SCP_CMD_FMT, dir, name) + 1;
#else
    sz = WSNPRINTF(NULL, 0, SCP_CMD_FMT, dir, name) + 1;
#endif
    if (sz <= 0) {
        return NULL;
    }
    cmd = (char*)WMALLOC(sz, heap, DYNTYPE_STRING);
    if (cmd == NULL) {
        return NULL;
    }
    sz = WSNPRINTF(cmd, sz, SCP_CMD_FMT, dir, name);
    if (sz <= 0) {
        WFREE(cmd, heap, DYNTYPE_STRING);
        return NULL;
    }

    return cmd;
}


int wolfSSH_SCP_to(WOLFSSH* ssh, const char* src, const char* dst)
{
    int ret = WS_SUCCESS;

    /* dst is passed to the server in the scp -t command */
    /* src is used locally to fopen and read for copy to */

    if (ssh == NULL || src == NULL || dst == NULL)
        return WS_BAD_ARGUMENT;

    if (ssh->scpState == SCP_SETUP) {
        char* cmd = MakeScpCmd(dst, 't', ssh->ctx->heap);
        if (cmd == NULL) {
            WLOG(WS_LOG_SCP, "Cannot allocate scp command");
            ssh->error = WS_MEMORY_E;
            return WS_ERROR;
        }

        ssh->scpBasePath = src;
        ret = wolfSSH_SCP_connect(ssh, (byte*)cmd);
        if (ret == WS_SUCCESS) {
            ssh->scpState = SCP_SOURCE_BEGIN;
            ssh->scpRequestState = SCP_SOURCE;
        }
        if (cmd) {
            WFREE(cmd, ssh->ctx->heap, DYNTYPE_STRING);
        }
    }
    if (ssh->scpState != SCP_SETUP) {
        if (ret == WS_SUCCESS) {
            ret = DoScpSource(ssh);
        }
    }

    return ret;
}


int wolfSSH_SCP_from(WOLFSSH* ssh, const char* src, const char* dst)
{
    int ret = WS_SUCCESS;

    /* src is passed to the server in the scp -f command */
    /* dst is used locally to fopen and write for copy from */

    if (ssh == NULL || src == NULL || dst == NULL)
        return WS_BAD_ARGUMENT;

    if (ssh->scpState == SCP_SETUP) {
        char* cmd = MakeScpCmd(src, 'f', ssh->ctx->heap);
        if (cmd == NULL) {
            WLOG(WS_LOG_SCP, "Cannot allocate scp command");
            ssh->error = WS_MEMORY_E;
            return WS_ERROR;
        }

        ssh->scpBasePath = dst;
        ret = wolfSSH_SCP_connect(ssh, (byte*)cmd);
        if (ret == WS_SUCCESS) {
            ret = ParseBasePathHelper(ssh);
        }
        if (ret == WS_SUCCESS) {
            ssh->scpState = SCP_SINK_BEGIN;
            ssh->scpRequestState = SCP_SINK;
        }
        if (cmd) {
            WFREE(cmd, ssh->ctx->heap, DYNTYPE_STRING);
        }
    }
    if (ssh->scpState != SCP_SETUP) {
        if (ret == WS_SUCCESS) {
            ret = DoScpSink(ssh);
        }
    }

    return ret;
}
#endif /* ! NO_WOLFSSH_CLIENT */


#if !defined(WOLFSSH_SCP_USER_CALLBACKS)

/* Extract file name from full path, store in fileName.
 * Return WS_SUCCESS on success, negative upon error */
static int ExtractFileName(const char* filePath, char* fileName,
                           word32 fileNameSz)
{
    int ret = WS_SUCCESS;
    word32 fileLen;
    int idx = 0, pathLen, separator = -1;

    if (filePath == NULL || fileName == NULL)
        return WS_BAD_ARGUMENT;

    pathLen = (int)WSTRLEN(filePath);

    /* find last separator */
    while (idx < pathLen) {
        if (filePath[idx] == '/' || filePath[idx] == '\\')
            separator = idx;
        idx++;
    }

    /* a path with no separator is a bare file or directory name; the whole
     * string is then the file name (separator == -1 is handled correctly by
     * the length math below) */
    if (pathLen == 0)
        return WS_BAD_ARGUMENT;

    fileLen = pathLen - separator - 1;
    if (fileLen + 1 > fileNameSz)
        return WS_SCP_PATH_LEN_E;

    WMEMCPY(fileName, filePath + separator + 1, fileLen);
    fileName[fileLen] = '\0';

    return ret;
}

#ifdef WOLFSSH_TEST_INTERNAL
int wolfSSH_TestScpExtractFileName(const char* filePath, char* fileName,
                                   word32 fileNameSz)
{
    return ExtractFileName(filePath, fileName, fileNameSz);
}
#endif

#if !defined(NO_FILESYSTEM)

/* for porting to systems without errno */
static INLINE int wolfSSH_LastError(void)
{
    return errno;
}


/* WOLFSSH_SCP_FD_UTIMES is defined for platforms that can set file timestamps
 * on the still-open descriptor, binding the update to the inode. On those the
 * timestamp is applied before the file is closed. Other platforms fall back to
 * applying the timestamp by path after the file is closed. */
#if defined(USE_WINDOWS_API) || defined(WFUTIMES)
    #define WOLFSSH_SCP_FD_UTIMES
#endif

/* set file access and modification times
 *
 * On descriptor-capable platforms (fp != NULL and WOLFSSH_SCP_FD_UTIMES) the
 * timestamps are applied to the open descriptor so the update is bound to the
 * inode. This avoids a race where the path could be replaced by a symlink
 * between closing the file and a path-based time update, which would let a
 * peer-supplied timestamp be applied to an arbitrary target. Buffered file
 * data is flushed first so the later close does not write and overwrite the
 * modification time. On the POSIX path-based fallback, fp is NULL because the
 * file has already been closed and the timestamp is applied by path; that path
 * update uses utimensat() with AT_SYMLINK_NOFOLLOW when available so a swapped
 * symlink is not followed, and only drops to plain utimes() otherwise. The
 * Windows branch always requires an open fp and rejects fp == NULL with
 * WS_BAD_ARGUMENT (there is no path-based fallback there).
 *
 * Returns WS_SUCCESS on success, or negative upon error */
static int SetTimestampInfo(WFILE* fp, const char* fileName,
        word64 mTime, word64 aTime)
{
    int ret = WS_SUCCESS;
#ifdef USE_WINDOWS_API
    struct _utimbuf tmp;
    int fd;
#else
    struct timeval tmp[2];
#endif

    if (fileName == NULL)
        ret= WS_BAD_ARGUMENT;

    if (ret == WS_SUCCESS) {
#ifdef USE_WINDOWS_API
        if (fp == NULL) {
            ret = WS_BAD_ARGUMENT;
        }
        else {
            fd = _fileno(fp);
            tmp.actime  = aTime;
            tmp.modtime = mTime;
            /* commit buffered data to disk before stamping so the close cannot
             * flush a write that bumps the modification time back */
            if (WFFLUSH(fp) != 0 || _commit(fd) != 0 || _futime(fd, &tmp) != 0)
                ret = WS_FATAL_ERROR;
        }
#else
        tmp[0].tv_sec = (time_t)aTime;
        tmp[0].tv_usec = 0;
        tmp[1].tv_sec = (time_t)mTime;
        tmp[1].tv_usec = 0;

    #ifdef WFUTIMES
        if (fp != NULL) {
            if (WFFLUSH(fp) != 0 || WFUTIMES(fileno(fp), tmp) != 0)
                ret = WS_FATAL_ERROR;
        }
        else
    #endif
        {
            (void)fp;
            /* no open descriptor to bind to; prefer the no-follow path update
             * so a swapped symlink is not followed, falling back to plain
             * utimes() only when utimensat() is unavailable */
    #ifdef WUTIMES_NOFOLLOW
            if (WUTIMES_NOFOLLOW(fileName, tmp) != 0)
    #else
            if (WUTIMES(fileName, tmp) != 0)
    #endif
                ret = WS_FATAL_ERROR;
        }
#endif
    }

    return ret;
}

/* Default SCP receive callback, called by wolfSSH when application has called
 * wolfSSH_accept() and a new SCP request has been received for an incoming
 * file or directory.
 *
 * Handles accepting recursive directories by having wolfSSH tell the callback
 * when to step into and out of a directory.
 *
 * When a new file copy "to" request is received, this callback is called in
 * the WOLFSSH_SCP_NEW_FILE state, where the base directory is placed in
 * 'basePath'. If the peer sends a recursive directory copy, wolfSSH calls
 * this callback in the WOLFSSH_SCP_NEW_DIR state, with a directory name in
 * 'fileName', when a directory should be created and entered.  Directory
 * mode is located in 'fileMode'. When a directory should be exited, the
 * callback is called in the WOLFSSH_SCP_END_DIR state.
 *
 * When an file transfer is incoming, the callback will first be called in
 * the WOLFSSH_SCP_NEW_FILE, with the file name in 'fileName', file mode
 * in 'fileMode', and optionally modification and access times in 'mTime'
 * and 'aTime', respectively.  These timestamps may or may not be present,
 * depenidng on the peer command that was executed.  If the peer did not send
 * these, they will be set to 0 when entering the callback.
 *
 * After each state is completed, the callback should return either
 * WS_SCP_CONTINUE to continue the copy operation, or WS_SCP_ABORT to abort
 * the copy. When WS_SCP_ABORT is returned, an optional error message can be
 * sent to the peer. This error message can be set by calling
 * wolfSSH_SetScpErrorMsg().
 *
 * ssh   - pointer to active WOLFSSH session
 * state - current state of operation, can be one of:
 *         WOLFSSH_SCP_NEW_FILE  - new incoming file, no data yet, but size
 *                                 and name
 *         WOLFSSH_SCP_FILE_PART - new file data, or continuation of
 *                                 existing file
 *         WOLFSSH_SCP_FILE_DONE - indicates named file transfer is done
 *         WOLFSSH_SCP_NEW_DIR   - indicates new directory, name in fileName
 *         WOLFSSH_SCP_END_DIR   - indicates leaving directory, up recursively
 * basePath    - base directory path peer is requesting that file be written to
 * fileName    - name of incoming file or directory
 * fileMode    - mode/permission of incoming file or directory
 * mTime       - file modification time, if sent by peer in seconds since
 *               Unix epoch (00:00:00 UTC, Jan. 1, 1970). mTime is 0 if
 *               peer did not send time value.
 * aTime       - file access time, if sent by peer in seconds since Unix
 *               epoch (00:00:00 UTC, Jan. 1, 1970). aTime is 0 if peer did
 *               not send time value.
 * totalFileSz - total size of incoming file (directory size may list zero)
 * buf         - file or file chunk
 * bufSz       - size of buf, bytes
 * fileOffset  - offset into total file size, where buf should be placed
 * ctx         - optional user context, stores file pointer in default case
 *
 * Return SCP status that is sent to client/sender. One of:
 *     WS_SCP_CONTINUE - continue SCP operation
 *     WS_SCP_ABORT    - abort SCP operation, send error to peer
 */
int wsScpRecvCallback(WOLFSSH* ssh, int state, const char* basePath,
        const char* fileName, int fileMode, word64 mTime, word64 aTime,
        word32 totalFileSz, byte* buf, word32 bufSz, word32 fileOffset,
        void* ctx)
{
    WFILE* fp = NULL;
    int ret = WS_SCP_CONTINUE;
    word32 bytes;
#ifdef WOLFSCP_FLUSH
    static word32 flush_bytes = 0;
    #ifndef WRITE_FLUSH_SIZE
    #define WRITE_FLUSH_SIZE (64*1024)
    #endif
#endif

#ifdef WOLFSSL_NUCLEUS
    char abslut[WOLFSSH_MAX_FILENAME];
    fp = (WFILE*)&ssh->scpFd; /* uses file descriptor for file operations */
    abslut[0] = '\0';
#endif

    if (ctx != NULL) {
        fp = (WFILE*)ctx;
    }

    switch (state) {

        case WOLFSSH_SCP_NEW_REQUEST:

            /* cd into requested root path */
     #ifdef WOLFSSL_NUCLEUS
            {
                DSTAT stat;

                wolfSSH_CleanPath(ssh, (char*)basePath, WOLFSSH_MAX_FILENAME);
                /* make sure is directory */
                if ((ret = NU_Get_First(&stat, basePath)) != NU_SUCCESS) {
                    /* if back to root directory i.e. A:/ then handle case
                     * where file system has nothing in it. */
                    if (basePath[1] == ':' && ret == NUF_NOFILE) {
                         ret = WS_SCP_CONTINUE;
                    }
                    else {
                        WLOG(WS_LOG_ERROR,
                            "scp: invalid destination directory, abort");
                        wolfSSH_SetScpErrorMsg(ssh,
                                "invalid destination directory");
                        ret = WS_SCP_ABORT;
                    }
                }
                else {
                    ret = WS_SCP_CONTINUE;

                    /* check to make sure that it is a directory */
                    if ((stat.fattribute & ADIRENT) == 0) {
                        WLOG(WS_LOG_ERROR,
                            "scp: invalid destination directory, abort");
                        wolfSSH_SetScpErrorMsg(ssh,
                                "invalid destination directory");
                        ret = WS_SCP_ABORT;
                    }
                    NU_Done(&stat);
                }
            }
            if (ret != WS_SCP_ABORT) {
                ssh->scpDirDepth = 0;
            }
    #else
            if (WCHDIR(ssh->fs, basePath) != 0) {
                WLOG(WS_LOG_ERROR,
                    "scp: invalid destination directory, abort");
                wolfSSH_SetScpErrorMsg(ssh, "invalid destination directory");
                ret = WS_SCP_ABORT;
            }
            else {
                ssh->scpDirDepth = 0;
            }
    #endif
            break;

        case WOLFSSH_SCP_NEW_FILE:

            /* open file */
        #ifdef WOLFSSL_NUCLEUS
            /* use absolute path */
            WSTRNCAT(abslut, (char*)basePath, WOLFSSH_MAX_FILENAME);
            WSTRNCAT(abslut, "/", WOLFSSH_MAX_FILENAME);
            WSTRNCAT(abslut, fileName, WOLFSSH_MAX_FILENAME);
            wolfSSH_CleanPath(ssh, abslut, WOLFSSH_MAX_FILENAME);
            if (WFOPEN(ssh->fs, &fp, abslut, "wb") != 0) {
        #else
        #ifdef WOLFSSH_HAVE_SYMLINK
            /* refuse to write through a pre-existing symlink, which would
             * escape the destination directory */
            if (wIsSymlink(fileName)) {
                WLOG(WS_LOG_ERROR,
                    "scp: refusing to write through symlink, abort");
                wolfSSH_SetScpErrorMsg(ssh, "symlink target rejected");
                ret = WS_SCP_ABORT;
                break;
            }
        #endif
            if (WFOPEN(ssh->fs, &fp, fileName, "wb") != 0) {
        #endif
                WLOG(WS_LOG_ERROR,
                    "scp: unable to open file for writing, abort");
                wolfSSH_SetScpErrorMsg(ssh, "unable to open file for writing");
                ret = WS_SCP_ABORT;
                break;
            }

#ifdef WOLFSCP_FLUSH
            flush_bytes = 0;
#endif
            /* store file pointer in user ctx */
            wolfSSH_SetScpRecvCtx(ssh, fp);
            break;

        case WOLFSSH_SCP_FILE_PART:

            if (fp == NULL) {
                WLOG(WS_LOG_ERROR, "scp: file pointer was null, abort");
                ret = WS_SCP_ABORT;
                break;
            }
            /* read file, or file part; an empty file gives a null buffer */
            if (buf != NULL && bufSz > 0) {
                bytes = (word32)WFWRITE(ssh->fs, buf, 1, bufSz, fp);
            }
            else {
                bytes = 0;
            }
            if (bytes != bufSz) {
                WLOG(WS_LOG_ERROR, scpError, "scp receive callback unable "
                     "to write requested size to file", bytes);
                WFCLOSE(ssh->fs, fp);
                fp = NULL;
                ret = WS_SCP_ABORT;
            } else {
#ifdef WOLFSCP_FLUSH
                flush_bytes += bytes;
                if (flush_bytes >= WRITE_FLUSH_SIZE) {
                    if (WFFLUSH(fp) != 0)
                       WLOG(WS_LOG_ERROR, scpError, "scp fflush failed", 0);
                    if (fsync(fileno(fp)) != 0)
                       WLOG(WS_LOG_ERROR, scpError, "scp fsync failed", 0);
                    flush_bytes = 0;
                    usleep(1000);
                }
#endif
            }
            break;

        case WOLFSSH_SCP_FILE_DONE:

            /* close file */
            if (fp != NULL) {
#ifdef WOLFSCP_FLUSH
                (void)WFFLUSH(fp);
                (void)fsync(fileno(fp));
                flush_bytes = 0;
#endif
#ifdef WOLFSSH_SCP_FD_UTIMES
                /* set timestamp info on the open file, before closing, so the
                 * update is bound to the inode and cannot be redirected to a
                 * symlink swapped in over the path */
                if (mTime != 0 || aTime != 0)
                    ret = SetTimestampInfo(fp, fileName, mTime, aTime);
#endif
                WFCLOSE(ssh->fs, fp);
                fp = NULL;
            }
#ifdef WOLFSSH_SCP_FD_UTIMES
            else if (mTime != 0 || aTime != 0) {
                /* descriptor-based update required but the file was never
                 * opened; do not fall back to a path update that could follow
                 * a swapped symlink, fail so the handling below aborts */
                ret = WS_FATAL_ERROR;
            }
#endif

            /* set timestamp info */
            if (mTime != 0 || aTime != 0) {
#ifndef WOLFSSH_SCP_FD_UTIMES
                /* no descriptor-based update available, set by path now that
                 * the file is closed so the close cannot overwrite the time */
                ret = SetTimestampInfo(NULL, fileName, mTime, aTime);
#endif
                if (ret == WS_SUCCESS) {
                    ret = WS_SCP_CONTINUE;
                } else {
                    WLOG(WS_LOG_ERROR,
                        "scp: unable to set timestamp info, abort");
                    ret = WS_SCP_ABORT;
                }
            }

            break;

        case WOLFSSH_SCP_NEW_DIR:

            if (WSTRLEN(fileName) > 0) {
                /* try to create new directory */
            #ifdef WOLFSSL_NUCLEUS
                /* get absolute path */
                WSTRNCAT(abslut, (char*)basePath, WOLFSSH_MAX_FILENAME);
                WSTRNCAT(abslut, "/", WOLFSSH_MAX_FILENAME);
                WSTRNCAT(abslut, fileName, WOLFSSH_MAX_FILENAME);
                wolfSSH_CleanPath(ssh, abslut, WOLFSSH_MAX_FILENAME);
                if (WMKDIR(ssh->fs, abslut, fileMode) != 0) {
                    /* check if directory already exists */
                    if (NU_Make_Dir(abslut) != NUF_EXIST) {
                        WLOG(WS_LOG_ERROR, scpState,
                            "error creating directory, abort");
                        wolfSSH_SetScpErrorMsg(ssh, "error creating directory");
                        ret = WS_SCP_ABORT;
                        break;

                    }
                }
            #else
                if (WMKDIR(ssh->fs, fileName, fileMode) != 0) {
                    if (wolfSSH_LastError() != EEXIST) {
                        WLOG(WS_LOG_ERROR,
                            "scp: error creating directory, abort");
                        wolfSSH_SetScpErrorMsg(ssh, "error creating directory");
                        ret = WS_SCP_ABORT;
                        break;
                    }
                }
            #endif

                /* cd into directory */
            #ifdef WOLFSSL_NUCLEUS
                WSTRNCAT((char*)basePath, "/", WOLFSSH_MAX_FILENAME);
                WSTRNCAT((char*)basePath, fileName, WOLFSSH_MAX_FILENAME);
                wolfSSH_CleanPath(ssh, (char*)basePath, WOLFSSH_MAX_FILENAME);
                ssh->scpDirDepth++;
            #else
            #ifdef WOLFSSH_HAVE_SYMLINK
                /* WMKDIR returning EEXIST above may have matched a pre-existing
                 * symlink; refuse to follow it out of the destination dir */
                if (wIsSymlink(fileName)) {
                    WLOG(WS_LOG_ERROR,
                        "scp: refusing to enter symlinked directory, abort");
                    wolfSSH_SetScpErrorMsg(ssh, "symlink in destination path");
                    ret = WS_SCP_ABORT;
                    break;
                }
            #endif
                if (WCHDIR(ssh->fs, fileName) != 0) {
                    WLOG(WS_LOG_ERROR,
                            "scp: unable to cd into directory, abort");
                    wolfSSH_SetScpErrorMsg(ssh, "unable to cd into directory");
                    ret = WS_SCP_ABORT;
                }
                else {
                    ssh->scpDirDepth++;
                }
            #endif
            }
            break;

        case WOLFSSH_SCP_END_DIR:

            /* abort if peer sent END_DIR without a matching NEW_DIR */
            if (ssh->scpDirDepth == 0) {
                WLOG(WS_LOG_ERROR,
                    "scp: end directory without matching start, abort");
                wolfSSH_SetScpErrorMsg(ssh,
                    "end directory without matching start");
                ret = WS_SCP_ABORT;
                break;
            }

            /* cd out of directory */
        #ifdef WOLFSSL_NUCLEUS
                WSTRNCAT((char*)basePath, "/..", WOLFSSH_MAX_FILENAME - 1);
                wolfSSH_CleanPath(ssh, (char*)basePath, WOLFSSH_MAX_FILENAME);
                ssh->scpDirDepth--;
        #else
            if (WCHDIR(ssh->fs, "..") != 0) {
                WLOG(WS_LOG_ERROR,
                            "scp: unable to cd out of directory, abort");
                wolfSSH_SetScpErrorMsg(ssh, "unable to cd out of directory");
                ret = WS_SCP_ABORT;
            }
            else {
                ssh->scpDirDepth--;
            }
        #endif
            break;

        default:
            WLOG(WS_LOG_ERROR,
                            "scp: invalid scp command request, abort");
            wolfSSH_SetScpErrorMsg(ssh, "invalid scp command request");
            ret = WS_SCP_ABORT;
    }

    WOLFSSH_UNUSED(totalFileSz);
    WOLFSSH_UNUSED(fileOffset);
    return ret;
}

static int _GetFileSize(void* fs, WFILE* fp, word32* fileSz)
{
    WOLFSSH_UNUSED(fs);

    if (fp == NULL || fileSz == NULL)
        return WS_BAD_ARGUMENT;

    /* get file size */
    WFSEEK(fs, fp, 0, WSEEK_END);
    *fileSz = (word32)WFTELL(fs, fp);
    WREWIND(fs, fp);

    return WS_SUCCESS;
}

static int GetFileStats(void *fs, ScpSendCtx* ctx, const char* fileName,
                        word64* mTime, word64* aTime, int* fileMode)
{
    int ret = WS_SUCCESS;

    WOLFSSH_UNUSED(fs);

    if (ctx == NULL || fileName == NULL || mTime == NULL ||
        aTime == NULL || fileMode == NULL) {
        return WS_BAD_ARGUMENT;
    }

    /* get file stats for times and mode */
#if defined(USE_WINDOWS_API)
    BOOL error;

    error = !WS_GetFileAttributesExA(fileName, &ctx->s, NULL);
    if (error)
        return WS_BAD_FILE_E;

    *aTime = ((word64)ctx->s.ftLastAccessTime.dwHighDateTime << 32) |
        (word64)ctx->s.ftLastAccessTime.dwLowDateTime;
    *mTime = ((word64)ctx->s.ftLastWriteTime.dwHighDateTime << 32) |
        (word64)ctx->s.ftLastWriteTime.dwLowDateTime;

    *fileMode = 0555 |
        (ctx->s.dwFileAttributes & FILE_ATTRIBUTE_READONLY ? 0 : 0200);
    *fileMode |= (ctx->s.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ? 040000 : 0;
#else
    /* WLSTAT (lstat on POSIX) leaves a symlink unfollowed, so it classifies as
     * neither dir nor file and is skipped; WOLFSSH_NO_SYMLINK_CHECK falls back
     * to WSTAT so links are followed by design. */
#ifdef WOLFSSH_HAVE_SYMLINK
    if (WLSTAT(fs, fileName, &ctx->s) < 0) {
#else
    if (WSTAT(fs, fileName, &ctx->s) < 0) {
#endif
        ret = WS_BAD_FILE_E;
        #ifdef WOLFSSL_NUCLEUS
        if (WSTRLEN(fileName) < 4 && WSTRLEN(fileName) > 2 &&
                fileName[1] == ':') {
            *fileMode = 0755;
            ret = WS_SUCCESS;
        }
        #endif
    }
    else {
    #ifdef WOLFSSL_NUCLEUS
        if (ctx->s.fattribute & ARDONLY) {
            *fileMode = 0444;
        }
        if (ctx->s.fattribute == ANORMAL) { /* ANORMAL = 0 */
            *fileMode = 0666;
        }
        if (ctx->s.fattribute == ADIRENT) {
            *fileMode = 0755;
        }
        *mTime = ctx->s.fupdate;
        *aTime = ctx->s.faccdate;
        NU_Done(&ctx->s);
    #elif defined(WOLFSSH_ZEPHYR)
        /* No time data in zephyr fs */
        *mTime = (word64)0;
        *aTime = (word64)0;
        /* Default perms */
        *fileMode = 0755;
        /* Mimic S_IFMT */
        if (ctx->s.type == FS_DIR_ENTRY_FILE)
            *fileMode |= 0100000;  /* S_IFREG */
        else if (ctx->s.type == FS_DIR_ENTRY_DIR)
            *fileMode |= 0040000;  /* S_IFDIR */
        else
            ret = WS_BAD_FILE_E;

    #else
        *mTime = (word64)ctx->s.st_mtime;
        *aTime = (word64)ctx->s.st_atime;
        *fileMode = ctx->s.st_mode & (S_IRWXU | S_IRWXG | S_IRWXO);
    #endif
    }
#endif

    return ret;
}

/* Create new ScpDir struct for pushing on directory stack.
 * Return valid pointer on success, NULL on failure */
static ScpDir* ScpNewDir(void *fs, const char* path, void* heap)
{
    WOLFSSH_UNUSED(fs);

    ScpDir* entry = NULL;

    if (path == NULL) {
        WLOG(WS_LOG_ERROR, scpError, "invalid directory path",
             WS_INVALID_PATH_E);
        return NULL;
    }

    entry = (ScpDir*)WMALLOC(sizeof(ScpDir), heap, DYNTYPE_SCPDIR);
    if (entry == NULL) {
        WLOG(WS_LOG_ERROR, scpError, "error allocating ScpDir" , WS_MEMORY_E);
        return NULL;
    }

    entry->next = NULL;
#ifdef USE_WINDOWS_API
    {
        char sPath[MAX_PATH];
        int isDir;

        /* add wildcard to get full directory */
        WSNPRINTF(sPath, MAX_PATH, "%s/*", path);

        entry->dir = (HANDLE)WS_FindFirstFileA(sPath,
            sPath, sizeof(sPath), &isDir, heap);
        if (entry->dir == INVALID_HANDLE_VALUE) {
            WFREE(entry, heap, DYNTYPE_SCPDIR);
            WLOG(WS_LOG_ERROR, scpError, "opendir failed on directory",
                WS_INVALID_PATH_E);
            return NULL;
        }
    }
#else
    #ifdef WOLFSSH_HAVE_SYMLINK
    /* refuse a symlinked directory leaf atomically (closes the descend race) */
    if (wOpendirNoFollow(fs, &entry->dir, path) != 0) {
    #else
    if (WOPENDIR(fs, heap, &entry->dir, path) != 0
        #if !defined(WOLFSSL_NUCLEUS) && !defined(WOLFSSH_ZEPHYR)
            || entry->dir == NULL
        #endif
            ) {
    #endif
        WFREE(entry, heap, DYNTYPE_SCPDIR);
        WLOG(WS_LOG_ERROR, scpError, "opendir failed on directory",
             WS_INVALID_PATH_E);
        return NULL;
    }
#endif
    return entry;
}

/* Create and push new ScpDir on stack, append directory to ctx->dirName */
int ScpPushDir(void *fs, ScpSendCtx* ctx, const char* path, void* heap)
{
    ScpDir* entry;
    word32  pathSz;

    if (ctx == NULL || path == NULL)
        return WS_BAD_ARGUMENT;

    pathSz = (word32)WSTRLEN(path);
    if (pathSz >= sizeof(ctx->dirName))
        return WS_BUFFER_E;

    entry = ScpNewDir(fs, path, heap);
    if (entry == NULL) {
        return WS_FATAL_ERROR;
    }

    if (ctx->currentDir == NULL) {
        entry->next = NULL;
        ctx->currentDir = entry;
    } else {
        entry->next = ctx->currentDir;
        ctx->currentDir = entry;
    }

    /* append directory name to ctx->dirName, terminator included; the guard
     * above bounds pathSz so the copy always fits */
    WMEMCPY(ctx->dirName, path, pathSz + 1);

    return WS_SUCCESS;
}

#ifdef WOLFSSH_TEST_INTERNAL
int wolfSSH_TestScpPushDir(const char* path)
{
    ScpSendCtx ctx;
    int ret;

    WMEMSET(&ctx, 0, sizeof(ctx));
    ret = ScpPushDir(NULL, &ctx, path, NULL);
    if (ret == WS_SUCCESS)
        ScpSendCtxFreeDirs(NULL, &ctx, NULL);

    return ret;
}
#endif /* WOLFSSH_TEST_INTERNAL */

/* Remove top ScpDir from directory stack, remove dir from ctx->dirName */
int ScpPopDir(void *fs, ScpSendCtx* ctx, void* heap)
{
    WOLFSSH_UNUSED(fs);

    ScpDir* entry = NULL;
    int idx = 0, separator = 0;

    if (ctx->currentDir != NULL) {
        entry = ctx->currentDir;
        ctx->currentDir = entry->next;
    }

    if (entry != NULL) {
    #ifdef USE_WINDOWS_API
        FindClose(entry->dir);
    #else
        WCLOSEDIR(fs, &entry->dir);
    #endif
        WFREE(entry, heap, DYNTYPE_SCPDIR);
    }

    /* remove directory from ctx->dirName path, find last separator */
    while (idx < (int)sizeof(ctx->dirName)) {
        if (ctx->dirName[idx] == '/' || ctx->dirName[idx] == '\\')
            separator = idx;
        idx++;
    }

    if (separator != 0) {
        WMEMSET(ctx->dirName + separator, 0,
                sizeof(ctx->dirName) - separator);
    }

    if (ctx->currentDir == NULL)
        return WS_SCP_DIR_STACK_EMPTY_E;

    WOLFSSH_UNUSED(heap);
    return WS_SUCCESS;
}

/* Drain dir-stack entries (and open dir handles) left on a send context after
 * a recursive transfer aborts mid-tree before popping.  Safe on an empty
 * stack. */
void ScpSendCtxFreeDirs(void* fs, ScpSendCtx* ctx, void* heap)
{
    if (ctx != NULL) {
        while (ctx->currentDir != NULL)
            (void)ScpPopDir(fs, ctx, heap);
    }
}

/* Get next entry in directory, either file or directory, skips self (.)
 * and parent (..) directories, stores in ctx->entry.
 * Return WS_SUCCESS on success or negative upon error */
static int FindNextDirEntry(void *fs, ScpSendCtx* ctx)
{
    WOLFSSH_UNUSED(fs);

    if (ctx == NULL)
        return WS_BAD_ARGUMENT;

    /* skip self (.) and parent (..) directories */
#ifdef WOLFSSL_NUCLEUS

    if (WSTRNCMP(ctx->currentDir->dir.lfname, "",  1) == 0) {
        WLOG(WS_LOG_DEBUG, scpError, "no file name found, no . or ..",
                WS_NEXT_ERROR);
        return WS_NEXT_ERROR;
    }

    /* There is a special case with Nucleus on root directory where the first
     * entry is not "." and should not be skipped over */
    if ((WSTRNCMP(ctx->currentDir->dir.lfname, ".",  1) == 0) ||
              (WSTRNCMP(ctx->currentDir->dir.lfname ,"..", 2) == 0)) {
        ctx->nextError = 1;
    }

    if (ctx->nextError == 1) {
        WDIR* dr;
        do {
            dr = WREADDIR(fs, &ctx->currentDir->dir);
        } while (dr != NULL &&
             (WSTRNCMP(ctx->currentDir->dir.lfname, ".",  1) == 0 ||
              WSTRNCMP(ctx->currentDir->dir.lfname ,"..", 2) == 0));
        if (dr == NULL) {
            return WS_NEXT_ERROR;
        }
    }
    ctx->nextError = 1;
#elif defined(USE_WINDOWS_API)
    do {
        char realFileName[MAX_PATH];
        int  sz;

        if (WS_FindNextFileA(ctx->currentDir->dir,
            realFileName, sizeof(realFileName)) == 0) {
            return WS_FATAL_ERROR;
        }

        sz = (int)WSTRLEN(realFileName);
        if (ctx->entry != NULL) {
            WFREE(ctx->entry, NULL, DYNTYPE_SCPDIR);
            ctx->entry = NULL;
        }

        ctx->entry = (char*)WMALLOC(sz + 1, NULL, DYNTYPE_SCPDIR);
        if (ctx->entry == NULL) {
            return WS_MEMORY_E;
        }
        WMEMCPY(ctx->entry, realFileName, sz);
        ctx->entry[sz] = '\0';
    } while ((ctx->entry != NULL) &&
        (((WSTRLEN(ctx->entry) == 1) && WSTRNCMP(ctx->entry, ".", 1) == 0) ||
         ((WSTRLEN(ctx->entry) == 2) && WSTRNCMP(ctx->entry, "..", 2) == 0)));
#elif defined(WOLFSSH_ZEPHYR)
    do {
        if (fs_readdir(&ctx->currentDir->dir, &ctx->entry) != 0)
            return WS_FATAL_ERROR;
        if (ctx->entry.name[0] == 0) /* Reached end-of-dir */
            return WS_NEXT_ERROR;
    } while (1);
#else
    do {
        ctx->entry = WREADDIR(fs, &ctx->currentDir->dir);
    } while ((ctx->entry != NULL) &&
             (
               ((WSTRLEN(ctx->entry->d_name) == 1) &&
                (WSTRNCMP(ctx->entry->d_name, ".",  1) == 0))
               ||
               ((WSTRLEN(ctx->entry->d_name) == 2) &&
                (WSTRNCMP(ctx->entry->d_name ,"..", 2) == 0))
             ));
#endif

    return WS_SUCCESS;
}

/* Test if directory stack is empty, return 1 if empty, otherwise 0 */
static int ScpDirStackIsEmpty(ScpSendCtx* ctx)
{
    if (ctx && ctx->currentDir == NULL)
        return 1;

    return 0;
}

/* returns 1 if is directory */
int ScpFileIsDir(ScpSendCtx* ctx)
{
#ifdef WOLFSSL_NUCLEUS
    return (ctx->s.fattribute & ADIRENT);
#elif defined(USE_WINDOWS_API)
    return (ctx->s.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY);
#elif defined(WOLFSSH_ZEPHYR)
    return ctx->s.type == FS_DIR_ENTRY_DIR;
#else
    return S_ISDIR(ctx->s.st_mode);
#endif
}

static int ScpFileIsFile(ScpSendCtx* ctx)
{
#ifdef WOLFSSL_NUCLEUS
    return (ctx->s.fattribute != ADIRENT);
#elif defined(USE_WINDOWS_API)
    return ((ctx->s.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0);
#elif defined(WOLFSSH_ZEPHYR)
    return ctx->s.type == FS_DIR_ENTRY_FILE;
#else
    return S_ISREG(ctx->s.st_mode);
#endif
}


/* Process a single entry, testing if is directory and opening files
 *
 * returns WS_SCP_ENTER_DIR when entering a new directory
 *         WS_SCP_ABORT on fail case
 *         WS_NEXT_ERROR when next call to the function will cause an error
 *         WS_SUCCESS when successfully opening a file
 */
static int ScpProcessEntry(WOLFSSH* ssh, char* fileName, word64* mTime,
        word64* aTime, int* fileMode, word32* totalFileSz, byte* buf,
        word32 bufSz, void* ctx, ScpSendCtx* sendCtx)
{
    int ret = WS_SUCCESS, dirNameLen, dNameLen;
    char filePath[DEFAULT_SCP_FILE_NAME_SZ];

#ifdef WOLFSSL_NUCLEUS
    if (WSTRNCMP(sendCtx->currentDir->dir.lfname, ".",  1) == 0 ||
              WSTRNCMP(sendCtx->currentDir->dir.lfname ,"..", 2) == 0) {
        ret = WS_NEXT_ERROR;
    }
#endif

    if (ret == WS_SUCCESS) {

        dirNameLen = (int)WSTRLEN(sendCtx->dirName);
    #if defined(WOLFSSL_NUCLEUS)
        dNameLen = (int)WSTRLEN(sendCtx->currentDir->dir.lfname);
    #elif defined(USE_WINDOWS_API)
        {
            char path[MAX_PATH];

            GetFullPathNameA(fileName, MAX_PATH, path, NULL);
            dNameLen = (int)WSTRLEN(path);
        }
    #elif defined(WOLFSSH_ZEPHYR)
        dNameLen   = (int)WSTRLEN(sendCtx->entry.name);
    #else
        dNameLen   = (int)WSTRLEN(sendCtx->entry->d_name);
    #endif
        if ((dirNameLen + 1 + dNameLen) > DEFAULT_SCP_FILE_NAME_SZ) {
            WLOG(WS_LOG_ERROR, "scp: dir name length too long, abort");
            ret = WS_SCP_ABORT;

        } else {
            WSTRNCPY(filePath, sendCtx->dirName,
                     DEFAULT_SCP_FILE_NAME_SZ);
            WSTRNCAT(filePath, "/", DEFAULT_SCP_FILE_NAME_SZ);

        #ifdef WOLFSSL_NUCLEUS
            WSTRNCAT(filePath, sendCtx->currentDir->dir.lfname,
                 DEFAULT_SCP_FILE_NAME_SZ);
            WSTRNCPY(fileName, sendCtx->currentDir->dir.lfname,
                 DEFAULT_SCP_FILE_NAME_SZ);
            if (wolfSSH_CleanPath(ssh, filePath, DEFAULT_SCP_FILE_NAME_SZ) < 0) {
                ret = WS_SCP_ABORT;
            }
        #elif defined(USE_WINDOWS_API)
            WSTRNCAT(filePath, sendCtx->entry,
                DEFAULT_SCP_FILE_NAME_SZ);
            WSTRNCPY(fileName, sendCtx->entry,
                DEFAULT_SCP_FILE_NAME_SZ);
        #elif defined(WOLFSSH_ZEPHYR)
            WSTRNCAT(filePath, sendCtx->entry.name,
                     DEFAULT_SCP_FILE_NAME_SZ);
            WSTRNCPY(fileName, sendCtx->entry.name,
                     DEFAULT_SCP_FILE_NAME_SZ);
        #else
            WSTRNCAT(filePath, sendCtx->entry->d_name,
                     DEFAULT_SCP_FILE_NAME_SZ);
            WSTRNCPY(fileName, sendCtx->entry->d_name,
                     DEFAULT_SCP_FILE_NAME_SZ);
        #endif
        #ifdef WOLFSSH_HAVE_SYMLINK
            /* filePath is fully built; reject a planted symlink before
             * GetFileStats or any descend/open follows it. */
            if (ret == WS_SUCCESS && wIsSymlink(filePath)) {
                WLOG(WS_LOG_ERROR,
                    "scp: symlink entry rejected, aborting transfer");
                ret = WS_SCP_ABORT;
            }
        #endif /* WOLFSSH_HAVE_SYMLINK */

            if (ret == WS_SUCCESS) {
                ret = GetFileStats(ssh->fs, sendCtx, filePath, mTime, aTime, fileMode);
            }
        }
    }

    if (ret == WS_SUCCESS) {

        if (ScpFileIsDir(sendCtx)) {

            ret = ScpPushDir(ssh->fs, sendCtx, filePath, ssh->ctx->heap);
            if (ret == WS_SUCCESS) {
                ret = WS_SCP_ENTER_DIR;
            } else {
                WLOG(WS_LOG_ERROR, "scp: Error with push dir, abort");
                ret = WS_SCP_ABORT;
            }

        } else if (ScpFileIsFile(sendCtx)) {
        #ifdef WOLFSSH_HAVE_SYMLINK
            if (wFopenNoFollow(ssh->fs, &(sendCtx->fp), filePath) != 0) {
        #else
            if (WFOPEN(ssh->fs, &(sendCtx->fp), filePath, "rb") != 0) {
        #endif
                WLOG(WS_LOG_ERROR, "scp: Error with opening file, abort");
                wolfSSH_SetScpErrorMsg(ssh, "unable to open file "
                                       "for reading");
                ret = WS_SCP_ABORT;
            }

            if (ret == WS_SUCCESS) {
                ret = _GetFileSize(ssh->fs, sendCtx->fp, totalFileSz);

                if (ret == WS_SUCCESS)
                    ret = (word32)WFREAD(ssh->fs, buf, 1, bufSz, sendCtx->fp);
            }

            /* keep fp open if no errors and transfer will continue */
            if ((sendCtx->fp != NULL) &&
                ((ret < 0) || (*totalFileSz == (word32)ret))) {
                WFCLOSE(ssh->fs, sendCtx->fp);
                sendCtx->fp = NULL;
            }
        }

    } else {
        /* WS_SCP_ABORT entries (e.g. a rejected symlink) were already logged at
         * their source, so only the generic, unexpected-error case is noted
         * here to avoid a misleading second log line. */
        if (ret != WS_NEXT_ERROR && ret != WS_SCP_ABORT) {
            WLOG(WS_LOG_ERROR, "scp: ret does not equal WS_NEXT_ERROR, abort");
            ret = WS_SCP_ABORT;
        }
    }

    WOLFSSH_UNUSED(ctx);
    return ret;
}


/* Default SCP send callback, called by wolfSSH when an application has called
 * wolfSSH_accept() and a new SCP request has been received requesting a file
 * be copied from the server to the peer.
 *
 * Depending on the peer request, this callback can be called in one of
 * several different states.  If the peer requested a single file, the
 * WOLFSSH_SCP_SINGLE_FILE_REQUEST state will be passed to the callback, where
 * the callback is responsible for populating file info and placing the single
 * file (or file part) into 'buf'.
 *
 * If the peer requests a directory of files be transferred, in a recursive
 * request, WOLFSSH_SCP_RECURSIVE_REQUEST will be passed to the callback. The
 * callback is then responsible for traversing through the requested directory
 * one directory or file at a time, returning WS_SCP_ENTER_DIR when a new
 * directory is entered, WS_SCP_EXIT_DIR when a directory is exited (not
 * including the final directory exit), and WS_SCP_EXIT_DIR_FINAL when the
 * final directory is done.
 *
 * At any time, the callback can abort the transfer by returning WS_SCP_ABORT.
 * This will send an error confirmation message to the peer.  When returning
 * WS_SCP_ABORT, the callback can call wolfSSH_SetScpErrorMsg() with an
 * optional error message to send back to the peer.
 *
 * When sending file data, the callback should copy up to 'bufSz' bytes
 * into 'buf', and return the number of bytes copied into 'buf'. Less than
 * 'bufSz' bytes can be copied into buf, which will cause only some file data
 * to be sent to the peer.  In this scenario, the callback will be called
 * again with the state set to WOLFSSH_SCP_CONTINUE_FILE_TRANSFER.  In this
 * state, the callback should again place up to 'bufSz' data in 'buf. The
 * 'fileOffset' variable holds the current offset into the file where file
 * bytes should be copied from.
 *
 * ssh   - [IN] pointer to active WOLFSSH session
 * state - [IN] current state of operation, can be one of:
 *         WOLFSSH_SCP_SINGLE_FILE_REQUEST    - peer requested a single file to
 *                                              be copied from the server
 *         WOLFSSH_SCP_RECURSIVE_REQUEST      - peer requested an entire
 *                                              directory be copied from the
 *                                              server, recursively
 *         WOLFSSH_SCP_CONTINUE_FILE_TRANSFER - file did not transfer completely
 *                                              in previous call, need more
 *                                              data to be sent from server
 *                                              to peer to complete file
 *                                              transfer.
 * peerRequest - [IN] name of file/directory the peer is requesting to be copied
 * fileName    - [OUT] name of file/directory callback is sending to peer,
 *               should be NULL terminated.
 * mTime       - [OUT] file modification time, in seconds since
 *               Unix epoch (00:00:00 UTC, Jan. 1, 1970). Optional, and set
 *               to 0 by default.
 * aTime       - [OUT] file access time, in seconds since Unix
 *               epoch (00:00:00 UTC, Jan. 1, 1970). Optional, and set to 0
 *               by default.
 * fileMode    - [OUT] mode/permission of outgoing file or directory, in
 *               decimal representation (ie: 0644 octal == 420 decimal)
 * fileOffset  - offset into total file size, from where file data should be
 *               read into 'buf'.
 * totalFileSz - total size of file being sent, bytes
 * buf         - [OUT] buffer to place file (or file part) in, of size bufSz
 * bufSz       - [IN] size of buf, bytes
 * ctx         - [IN] optional user context, stores file pointer in default
 *               case. Can be set by calling wolfSSH_SetScpSendCtx().
 *
 * Return number of bytes copied into buf, if doing a file transfer, otherwise
 * one of:
 *     WS_SCP_ENTER_DIR            - send directory name to peer - fileName,
 *                                   mode (optional), mTime (optional), and
 *                                   aTime (optional) should be set. Return
 *                                   when callback and "entered" a directory.
 *     WS_SCP_EXIT_DIR             - return when recursive directory traversal
 *                                   has "exited" a directory.
 *     WS_SCP_EXIT_DIR_FINAL       - return when recursive directory transfer
 *                                   is complete.
 *     WS_SCP_ABORT                - abort file transfer request
 *     WS_BAD_FILE_E               - local file open error hit
 *
 * Symlink handling: file-content opens go through wFopenNoFollow and directory
 * opens (both the recursive root and every descend) go through wOpendirNoFollow.
 * Both are atomic against a swapped link on POSIX (O_NOFOLLOW, plus O_DIRECTORY
 * for the directory open) and fall back to a wIsSymlink check-then-open on
 * Windows or where O_NOFOLLOW is absent.  The root also gets an explicit
 * wIsSymlink pre-check because a trailing separator (open("link/", O_NOFOLLOW))
 * can still follow the link; symlinks below the root are rejected as
 * ScpProcessEntry traverses them.  No "stays under a trusted base" containment
 * is attempted: SCP has no library-level base path (wolfsshd relies on OS
 * chroot) and wolfSSH_RealPath does not resolve links.  GetFileStats uses WLSTAT
 * so it does not follow a link for metadata or classification.  On the
 * Windows/fallback path the open is check-then-open, so a concurrent in-jail
 * writer racing it remains a best-effort gap.  For hostile multi-tenant use,
 * confine the session with an OS mechanism (chroot, dropped privileges) and
 * treat these checks as defense in depth.
 */
int wsScpSendCallback(WOLFSSH* ssh, int state, const char* peerRequest,
        char* fileName, word32 fileNameSz, word64* mTime, word64* aTime,
        int* fileMode, word32 fileOffset, word32* totalFileSz, byte* buf,
        word32 bufSz, void* ctx)
{
    ScpSendCtx* sendCtx = NULL;
    int ret = WS_SUCCESS;
    char filePath[DEFAULT_SCP_FILE_NAME_SZ];

    if (ctx != NULL) {
        sendCtx = (ScpSendCtx*)ctx;
    }

#ifdef WOLFSSL_NUCLEUS
    if (sendCtx != NULL) sendCtx->fp = &sendCtx->fd;
#endif

    WMEMSET(filePath, 0, DEFAULT_SCP_FILE_NAME_SZ);

    switch (state) {

        case WOLFSSH_SCP_NEW_REQUEST:

            /* new request, user may return WS_SCP_ABORT
             * to abort/reject transfer attempt, ie:
             *
             * wolfSSH_SetScpErrorMsg(ssh, "scp transfer rejected");
             * ret = WS_SCP_ABORT;
             */
            break;

        case WOLFSSH_SCP_SINGLE_FILE_REQUEST:
            /* open without following a symlink so its target is not streamed
             * to the peer; see this function's symlink-handling note. */
            if ((sendCtx == NULL) ||
        #ifdef WOLFSSH_HAVE_SYMLINK
                wFopenNoFollow(ssh->fs, &(sendCtx->fp), peerRequest) != 0) {
        #else
                WFOPEN(ssh->fs, &(sendCtx->fp), peerRequest, "rb") != 0) {
        #endif
                WLOG(WS_LOG_ERROR, "scp: unable to open file, abort");
                wolfSSH_SetScpErrorMsg(ssh, "unable to open file for reading");
                ret = WS_BAD_FILE_E;
            }

            if (ret == WS_SUCCESS) {
            #ifdef WOLFSSL_NUCLEUS
                if (sendCtx->fd < 0)
                    ret = WS_SCP_ABORT;
            #else
                if (sendCtx->fp == NULL)
                    ret = WS_SCP_ABORT;
            #endif
            }

            if (ret == WS_SUCCESS)
                ret = _GetFileSize(ssh->fs, sendCtx->fp, totalFileSz);

            if (ret == WS_SUCCESS)
                ret = GetFileStats(ssh->fs, sendCtx, peerRequest, mTime, aTime, fileMode);

            if (ret == WS_SUCCESS)
                ret = ExtractFileName(peerRequest, fileName, fileNameSz);

            if (ret == WS_SUCCESS) {
                if (sendCtx != NULL && sendCtx->fp != NULL) {
                    /* If it is an empty file, do not read. */
                    if (*totalFileSz != 0) {
                        ret = (word32)WFREAD(ssh->fs, buf, 1, bufSz,
                                             sendCtx->fp);
                        if (ret == 0) { /* handle unexpected case */
                            ret = WS_EOF;
                        }
                    }
                } else {
                    WLOG(WS_LOG_ERROR,
                                      "scp: error extracting file name, abort");
                    ret = WS_SCP_ABORT;
                }
            }

            /* keep fp open if no errors and transfer will continue */
            if ((sendCtx != NULL) && (sendCtx->fp != NULL) &&
                ((ret < 0) || (*totalFileSz == (word32)ret))) {
                WFCLOSE(ssh->fs, sendCtx->fp);
                sendCtx->fp = NULL;
            }

            break;

        case WOLFSSH_SCP_RECURSIVE_REQUEST:

            if (ScpDirStackIsEmpty(sendCtx)) {
            #ifdef WOLFSSH_HAVE_SYMLINK
                word32 rootLen;
            #endif

                /* first request, keep track of request directory.  Reject a
                 * symlink root here (a trailing separator can still follow);
                 * see the symlink-handling note in this function's header. */
                ret = WS_SUCCESS;
                if (peerRequest == NULL) {
                    WLOG(WS_LOG_ERROR,
                        "scp: missing recursive root path, abort");
                    ret = WS_SCP_ABORT;
                }
            #ifdef WOLFSSH_HAVE_SYMLINK
                /* lstat() follows the link when the path ends in a separator,
                 * so check the root with any trailing separators removed */
                else {
                    rootLen = (word32)WSTRLEN(peerRequest);
                    while (rootLen > 1 && (peerRequest[rootLen - 1] == '/' ||
                                           peerRequest[rootLen - 1] == '\\'))
                        rootLen--;
                    if (rootLen >= DEFAULT_SCP_FILE_NAME_SZ) {
                        WLOG(WS_LOG_ERROR,
                            "scp: recursive root path too long, abort");
                        wolfSSH_SetScpErrorMsg(ssh,
                            "unable to open file for reading");
                        ret = WS_SCP_ABORT;
                    }
                    else {
                        WMEMCPY(filePath, peerRequest, rootLen);
                        filePath[rootLen] = '\0';
                        if (wIsSymlink(filePath)) {
                            WLOG(WS_LOG_ERROR,
                                "scp: refusing recursive root symlink, abort");
                            wolfSSH_SetScpErrorMsg(ssh,
                                "unable to open file for reading");
                            ret = WS_SCP_ABORT;
                        }
                    }
                }
            #endif /* WOLFSSH_HAVE_SYMLINK */

                if (ret == WS_SUCCESS) {
                    ret = ScpPushDir(ssh->fs, sendCtx, peerRequest,
                                     ssh->ctx->heap);
                    if (ret != WS_SUCCESS) {
                        WLOG(WS_LOG_ERROR,
                             "scp: error opening base directory, abort");
                    }
                }

                if (ret == WS_SUCCESS) {
                    /* get file name from request */
                    ret = ExtractFileName(peerRequest, fileName, fileNameSz);
                    if (ret != WS_SUCCESS) {
                        WLOG(WS_LOG_ERROR,
                             "scp: error extracting directory name, abort");
                    }
                }

                if (ret == WS_SUCCESS) {
                    ret = GetFileStats(ssh->fs, sendCtx, peerRequest, mTime, aTime,
                                       fileMode);
                    if (ret != WS_SUCCESS) {
                        WLOG(WS_LOG_ERROR,
                             "scp: error getting file stats, abort");
                    }
                }

                if (ret == WS_SUCCESS) {
                    ret = WS_SCP_ENTER_DIR;
                } else {
                    ret = WS_SCP_ABORT;
                }


                /* send directory msg or abort */
                break;
            }
            ret = FindNextDirEntry(ssh->fs, sendCtx);

            /* help out static analysis tool */
            if (ret != WS_BAD_ARGUMENT && sendCtx == NULL)
                ret = WS_BAD_ARGUMENT;

            if (ret == WS_SUCCESS || ret == WS_NEXT_ERROR) {

            #if defined(WOLFSSL_NUCLEUS) || defined(WOLFSSH_ZEPHYR)
                if (ret == WS_NEXT_ERROR) {
            #else
                /* reached end of directory */
                if (sendCtx->entry == NULL) {
            #endif
                    ret = ScpPopDir(ssh->fs, sendCtx, ssh->ctx->heap);
                    if (ret == WS_SUCCESS) {
                        ret = WS_SCP_EXIT_DIR;

                    } else if (ret == WS_SCP_DIR_STACK_EMPTY_E) {
                        ret = WS_SCP_EXIT_DIR_FINAL;

                    } else {
                        WLOG(WS_LOG_ERROR,
                            "scp: error popping directory, abort");
                        ret = WS_SCP_ABORT;
                    }

                    /* send exit directory msg or abort */
                    break;
                }
            }

            if (ret != WS_BAD_ARGUMENT && sendCtx == NULL)
                ret = WS_BAD_ARGUMENT;

            if (ret == WS_SUCCESS) {
                ret = ScpProcessEntry(ssh, fileName,
                        mTime, aTime, fileMode, totalFileSz, buf,
                        bufSz, ctx, sendCtx);
            }
            break;

        case WOLFSSH_SCP_CONTINUE_FILE_TRANSFER:

            if (sendCtx == NULL) {
                WLOG(WS_LOG_ERROR, "scp: sendCtx was null, abort");
                ret = WS_SCP_ABORT;
                break;
            }

            if (sendCtx->fp == NULL) {
                WLOG(WS_LOG_ERROR, "scp: file has been closed, abort");
                ret = WS_SCP_ABORT;
                break;
            }

            ret = (word32)WFREAD(ssh->fs, buf, 1, bufSz, sendCtx->fp);
            if (ret == 0) { /* handle case of EOF */
                ret = WS_EOF;
            }

            if ((ret <= 0) || (fileOffset + ret == *totalFileSz)) {
                WFCLOSE(ssh->fs, sendCtx->fp);
                sendCtx->fp = NULL;
            }

            break;
    }

    return ret;
}

#else

/* single file transfer with no filesystem */
int wsScpRecvCallback(WOLFSSH* ssh, int state, const char* basePath,
        const char* fileName, int fileMode, word64 mTime, word64 aTime,
        word32 totalFileSz, byte* buf, word32 bufSz, word32 fileOffset,
        void* ctx)
{
    ScpBuffer* recvBuffer;
    int ret = WS_SCP_CONTINUE;
    int sz;

    if (ctx == NULL) {
        WLOG(WS_LOG_DEBUG, scpState, "SCP receive ctx not set");
        return WS_SCP_ABORT;
    }
    recvBuffer = (ScpBuffer*)ctx;

    switch (state) {

        case WOLFSSH_SCP_NEW_REQUEST:
            break;

        case WOLFSSH_SCP_NEW_FILE:
            /* create file */
            sz = (int)WSTRLEN(fileName);
            if (sz >= DEFAULT_SCP_FILE_NAME_SZ) {
                WLOG(WS_LOG_ERROR, "scp: file name is too large, abort");
                wolfSSH_SetScpErrorMsg(ssh, "file name is too large");
                ret = WS_SCP_ABORT;
                break;
            }
            WMEMCPY(recvBuffer->name, fileName, sz);
            recvBuffer->mTime = mTime;
            recvBuffer->mode = fileMode;
            if (recvBuffer->status) {
                if (recvBuffer->status(ssh, fileName, WOLFSSH_SCP_NEW_FILE,
                            recvBuffer) != WS_SUCCESS) {
                    WLOG(WS_LOG_ERROR, "scp: status of new file failed, abort");
                    ret = WS_SCP_ABORT;
                }
            }
            break;

        case WOLFSSH_SCP_FILE_PART:
            /* read file, or file part; an empty file gives a null buffer */
            sz = (bufSz < recvBuffer->bufferSz - recvBuffer->idx) ?
                bufSz : recvBuffer->bufferSz - recvBuffer->idx;

            if (recvBuffer->idx >= recvBuffer->bufferSz) {
                wolfSSH_SetScpErrorMsg(ssh,
                        "buffer is not large enough for file");
                WLOG(WS_LOG_ERROR, scpState, "SCP buffer too small for file");
                ret = WS_SCP_ABORT;
                break;
            }

            if (buf != NULL && sz > 0) {
                WMEMCPY(recvBuffer->buffer + recvBuffer->idx, buf, sz);
                recvBuffer->idx    += sz;
                recvBuffer->fileSz += sz;
            }
            if (recvBuffer->status) {
                if (recvBuffer->status(ssh, recvBuffer->name,
                            WOLFSSH_SCP_FILE_PART, recvBuffer) != WS_SUCCESS) {
                    WLOG(WS_LOG_ERROR, "scp: bad status, abort");
                    ret = WS_SCP_ABORT;
                }
            }
            break;

        case WOLFSSH_SCP_FILE_DONE:
            recvBuffer->idx   = 0; /* rewind when done */
            recvBuffer->mTime = 0; /* @TODO set time if wanted */
            if (recvBuffer->status) {
                if (recvBuffer->status(ssh, recvBuffer->name,
                            WOLFSSH_SCP_FILE_DONE, recvBuffer) != WS_SUCCESS) {
                    WLOG(WS_LOG_ERROR, "scp: bad status, abort");
                    ret = WS_SCP_ABORT;
                }
            }
            break;

        case WOLFSSH_SCP_NEW_DIR:
        case WOLFSSH_SCP_END_DIR:
            WLOG(WS_LOG_ERROR,
                    "scp: creating a new directory not supported");
            wolfSSH_SetScpErrorMsg(ssh,
                    "creating a new directory not supported");
            ret = WS_SCP_ABORT;
            break;

        default:
            WLOG(WS_LOG_ERROR, scpState,
                   "invalid scp command request");
            wolfSSH_SetScpErrorMsg(ssh, "invalid scp command request");
            ret = WS_SCP_ABORT;
    }

    WOLFSSH_UNUSED(totalFileSz);
    WOLFSSH_UNUSED(fileOffset);
    WOLFSSH_UNUSED(aTime);
    WOLFSSH_UNUSED(basePath);
    return ret;
}


/* callback for single file transfer with no file system */
int wsScpSendCallback(WOLFSSH* ssh, int state, const char* peerRequest,
        char* fileName, word32 fileNameSz, word64* mTime, word64* aTime,
        int* fileMode, word32 fileOffset, word32* totalFileSz, byte* buf,
        word32 bufSz, void* ctx)
{
    ScpBuffer* sendBuffer= NULL;
    int ret = WS_SUCCESS;

    if (ctx == NULL) {
        WLOG(WS_LOG_DEBUG, scpState, "no ctx sent to hold file info");
        return WS_SCP_ABORT;
    }
    sendBuffer = (ScpBuffer*)ctx;

    switch (state) {
        case WOLFSSH_SCP_NEW_REQUEST:
            break;

        case WOLFSSH_SCP_SINGLE_FILE_REQUEST:
            if (sendBuffer->buffer == NULL) {
                WLOG(WS_LOG_DEBUG, scpState, "no buffer to send");
                ret = WS_SCP_ABORT;
                break;
            }

            ret = ExtractFileName(peerRequest, fileName, fileNameSz);
            if (ret == WS_SUCCESS && sendBuffer->status) {
                if ( sendBuffer->status(ssh, fileName,
                            WOLFSSH_SCP_SINGLE_FILE_REQUEST, sendBuffer)
                            != WS_SUCCESS) {
                    WLOG(WS_LOG_ERROR, scpState, "bad status of file, abort");
                    ret = WS_SCP_ABORT;
                    break;
                }
            }

            if (WSTRLEN(fileName) != sendBuffer->nameSz ||
                WMEMCMP(sendBuffer->name, fileName, sendBuffer->nameSz) != 0) {
                WLOG(WS_LOG_ERROR, scpState, "file name did not match, abort");
                wolfSSH_SetScpErrorMsg(ssh, "file name did not match");
                ret = WS_SCP_ABORT;
                break;
            }
            *totalFileSz = sendBuffer->fileSz;
            *mTime = sendBuffer->mTime;
            *aTime = sendBuffer->mTime;
            *fileMode = sendBuffer->mode;

            /* copy over buffer info */
            ret = (bufSz < (sendBuffer->fileSz - sendBuffer->idx))?
                bufSz : sendBuffer->fileSz - sendBuffer->idx;
            if (sendBuffer->idx  + ret >= sendBuffer->bufferSz) {
                WLOG(WS_LOG_ERROR, scpState,
                    "potential buffer overflow caught, abort");
                ret = WS_SCP_ABORT;
                break;
            }
            WMEMCPY(buf, sendBuffer->buffer + sendBuffer->idx, ret);
            sendBuffer->idx += ret;

            break;

        case WOLFSSH_SCP_RECURSIVE_REQUEST:
            WLOG(WS_LOG_ERROR, scpState,
                   "recursive request without filesystem not supported, abort");
            wolfSSH_SetScpErrorMsg(ssh,
                    "recursive request without filesystem not supported");
            ret = WS_SCP_ABORT;
            break;

        case WOLFSSH_SCP_CONTINUE_FILE_TRANSFER:
            /* copy over buffer info */
            if (sendBuffer->idx >= sendBuffer->bufferSz) {
                WLOG(WS_LOG_ERROR, scpState,
                    "sendbuffer idx greater than buffer size, abort");
                ret = WS_SCP_ABORT;
                break;
            }
            ret = (bufSz < (sendBuffer->fileSz - sendBuffer->idx))?
                bufSz : sendBuffer->fileSz - sendBuffer->idx;
            if (ret > 0) {
                if (sendBuffer->idx  + ret >= sendBuffer->bufferSz) {
                    ret = WS_SCP_ABORT;
                    WLOG(WS_LOG_ERROR, scpState, "buffer size issue, abort");
                    break;
                }
                WMEMCPY(buf, sendBuffer->buffer + sendBuffer->idx, ret);
                sendBuffer->idx += ret;
            }
            if (ret == 0) { /* handle case of EOF */
                ret = WS_EOF;
            }

            if (sendBuffer->status(ssh, sendBuffer->name,
                        WOLFSSH_SCP_CONTINUE_FILE_TRANSFER, sendBuffer)
                        != WS_SUCCESS) {
                WLOG(WS_LOG_DEBUG, scpState, "continue status fail, abort");
                ret = WS_SCP_ABORT;
                break;
            }

            break;

        default:
            WLOG(WS_LOG_DEBUG, scpState, "bad state");
            ret = WS_SCP_ABORT;
    }
    WOLFSSH_UNUSED(fileOffset);

    return ret;
}
#endif /* NO_FILESYSTEM */
#endif /* WOLFSSH_SCP_USER_CALLBACKS */

#endif /* WOLFSSH_SCP */

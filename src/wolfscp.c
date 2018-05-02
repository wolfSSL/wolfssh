/* scp.c
 *
 * Copyright (C) 2014-2018 wolfSSL Inc.
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

#ifdef WOLFSSH_SCP

#include <wolfssh/ssh.h>
#include <wolfssh/internal.h>
#include <wolfssh/log.h>
#include <wolfssh/wolfscp.h>

#ifdef NO_INLINE
    #include <wolfssh/misc.h>
#else
    #define WOLFSSH_MISC_INCLUDED
    #include "src/misc.c"
#endif

#if defined(NO_FILESYSTEM) && !defined(WOLFSSH_SCP_USER_CALLBACKS)
    #error "scp with no filesystem requires user callbacks"
#endif

const char scpError[] = "scp error: %s, %d";
const char scpState[] = "scp state: %s";

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
                        NULL, 0, 0, 0, 0, NULL, 0, 0, ssh->scpRecvCtx);
                continue;

            case SCP_RECEIVE_MESSAGE:
                WLOG(WS_LOG_DEBUG, scpState, "SCP_RECEIVE_MESSAGE");

                if ( (ssh->error = ReceiveScpMessage(ssh)) < WS_SUCCESS) {
                    if (ssh->error == WS_EOF) {
                        ssh->scpState = SCP_DONE;
                        break;
                    }

                    WLOG(WS_LOG_ERROR, scpError, "RECEIVE_MESSAGE", ssh->error);
                    ret = WS_FATAL_ERROR;
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
                    ssh->error = WS_SCP_BAD_MSG_E;
                    WLOG(WS_LOG_ERROR, scpError, "bad msg type", ssh->error);
                    ret = WS_FATAL_ERROR;
                    break;
                }

                /* scp receive callback */
                ssh->scpConfirm = ssh->ctx->scpRecvCb(ssh, ssh->scpFileState,
                        ssh->scpBasePath, ssh->scpFileName, ssh->scpFileMode,
                        ssh->scpMTime, ssh->scpATime, ssh->scpFileSz, NULL, 0,
                        0, ssh->scpRecvCtx);

                continue;

            case SCP_SEND_CONFIRMATION:
                WLOG(WS_LOG_DEBUG, scpState, "SCP_SEND_CONFIRMATION");

                if ( (ssh->error = SendScpConfirmation(ssh)) < WS_SUCCESS) {
                    WLOG(WS_LOG_ERROR, scpError, "SEND_CONFIRMATION",
                         ssh->error);
                    ret = WS_FATAL_ERROR;
                    break;
                }

                ssh->scpState = ssh->scpNextState;
                continue;

            case SCP_RECEIVE_CONFIRMATION:
                WLOG(WS_LOG_DEBUG, scpState, "SCP_RECEIVE_CONFIRMATION");

                if ( (ssh->error = ReceiveScpConfirmation(ssh)) < WS_SUCCESS) {
                    WLOG(WS_LOG_ERROR, scpError, "RECEIVE_CONFIRMATION",
                         ssh->error);
                    ret = WS_FATAL_ERROR;
                    break;
                }

                ssh->scpState = SCP_RECEIVE_MESSAGE;
                continue;

            case SCP_RECEIVE_FILE:
                WLOG(WS_LOG_DEBUG, scpState, "SCP_RECEIVE_FILE");

                if ( (ssh->error = ReceiveScpFile(ssh)) < WS_SUCCESS) {
                    WLOG(WS_LOG_ERROR, scpError, "RECEIVE_FILE", ssh->error);
                    ret = WS_FATAL_ERROR;
                    break;
                }

                /* scp receive callback, give user file data */
                ssh->scpConfirm = ssh->ctx->scpRecvCb(ssh,
                        WOLFSSH_SCP_FILE_PART, ssh->scpBasePath,
                        ssh->scpFileName, ssh->scpFileMode, ssh->scpMTime,
                        ssh->scpATime, ssh->scpFileSz, ssh->scpFileBuffer,
                        ssh->scpFileBufferSz, ssh->scpFileOffset,
                        ssh->scpRecvCtx);

                ssh->scpFileOffset += ssh->scpFileBufferSz;

                /* shrink and reset recv buffer */
                WFREE(ssh->scpFileBuffer, ssh->ctx->heap, DYNTYPE_BUFFFER);
                ssh->scpFileBuffer = NULL;
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
                        ssh->scpRecvCtx);

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

    ret = wolfSSH_stream_send(ssh, (byte*)buf, bufSz);
    if (ret != bufSz) {
        ret = WS_FATAL_ERROR;
    } else {
        WLOG(WS_LOG_DEBUG, "scp: sent timestamp: %s", buf);
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

    if (ssh == NULL)
        return WS_BAD_ARGUMENT;

    WMEMSET(buf, 0, sizeof(buf));

    WSNPRINTF(buf, sizeof(buf), "C%04o %u %s\n",
              ssh->scpFileMode, ssh->scpFileSz, ssh->scpFileName);

    bufSz = (int)WSTRLEN(buf);

    ret = wolfSSH_stream_send(ssh, (byte*)buf, bufSz);
    if (ret != bufSz) {
        ret = WS_FATAL_ERROR;
    } else {
        WLOG(WS_LOG_DEBUG, "scp: sent file header: %s", buf);
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

    WSNPRINTF(buf, sizeof(buf), "D%04o 0 %s\n", ssh->scpFileMode,
              ssh->scpFileName);

    bufSz = (int)WSTRLEN(buf);

    ret = wolfSSH_stream_send(ssh, (byte*)buf, bufSz);
    if (ret != bufSz) {
        ret = WS_FATAL_ERROR;
    } else {
        WLOG(WS_LOG_DEBUG, "scp: sent directory msg: %s", buf);
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

    ret = wolfSSH_stream_send(ssh, (byte*)buf, sizeof(buf));
    if (ret != sizeof(buf)) {
        ret = WS_FATAL_ERROR;
    } else {
        WLOG(WS_LOG_DEBUG, "scp: sent end directory msg: E");
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

                if ( (ssh->error = ScpSourceInit(ssh)) < WS_SUCCESS) {
                    ret = WS_FATAL_ERROR;
                    break;
                }

                ssh->scpState = SCP_RECEIVE_CONFIRMATION;
                ssh->scpNextState = SCP_TRANSFER;
                continue;

            case SCP_SEND_CONFIRMATION:
                WLOG(WS_LOG_DEBUG, scpState, "SCP_SEND_CONFIRMATION");

                if ( (ssh->error = SendScpConfirmation(ssh)) < WS_SUCCESS) {
                    WLOG(WS_LOG_ERROR, scpError, "SEND_CONFIRMATION",
                         ssh->error);
                    ret = WS_FATAL_ERROR;
                    break;
                }

                ssh->scpState = ssh->scpNextState;
                continue;

            case SCP_CONFIRMATION_WITH_RECEIPT:
                WLOG(WS_LOG_DEBUG, scpState, "SCP_CONFIRMATION_WITH_RECEIPT");

                if ( (ssh->error = SendScpConfirmation(ssh)) < WS_SUCCESS) {
                    WLOG(WS_LOG_ERROR, scpError, "SEND_CONFIRMATION",
                         ssh->error);
                    ret = WS_FATAL_ERROR;
                    break;
                }

                ssh->scpState = SCP_RECEIVE_CONFIRMATION;
                continue;

            case SCP_RECEIVE_CONFIRMATION_WITH_RECEIPT:
                WLOG(WS_LOG_DEBUG, scpState,
                     "SCP_RECEIVE_CONFIRMATION_WITH_RECEIPT");

                if ( (ssh->error = ReceiveScpConfirmation(ssh)) < WS_SUCCESS) {
                    WLOG(WS_LOG_ERROR, scpError,
                         "RECEIVE_CONFIRMATION_WITH_RECEIPT", ssh->error);
                    ret = WS_FATAL_ERROR;
                    break;
                }

                ssh->scpState = SCP_SEND_CONFIRMATION;
                continue;

            case SCP_RECEIVE_CONFIRMATION:
                WLOG(WS_LOG_DEBUG, scpState, "SCP_RECEIVE_CONFIRMATION");

                if ( (ssh->error = ReceiveScpConfirmation(ssh)) < WS_SUCCESS) {
                    WLOG(WS_LOG_ERROR, scpError, "RECEIVE_CONFIRMATION",
                         ssh->error);
                    ret = WS_FATAL_ERROR;
                    break;
                }

                ssh->scpState = ssh->scpNextState;
                continue;

            case SCP_TRANSFER:
                WLOG(WS_LOG_DEBUG, scpState, "SCP_SINK_TRANSFER");

                ssh->scpConfirm = ssh->ctx->scpSendCb(ssh,
                        ssh->scpRequestType, ssh->scpBasePath,
                        ssh->scpFileName, ssh->scpFileNameSz, &(ssh->scpMTime),
                        &(ssh->scpATime), &(ssh->scpFileMode),
                        ssh->scpFileOffset, &(ssh->scpFileSz),
                        ssh->scpFileBuffer, ssh->scpFileBufferSz,
                        ssh->scpSendCtx);

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
                    ssh->scpState = SCP_SEND_CONFIRMATION;
                    ssh->scpNextState = SCP_DONE;
                    continue;

                } else if (ssh->scpConfirm > 0) {

                    /* transfer buffered file data */
                    ssh->scpBufferedSz = ssh->scpConfirm;
                    ssh->scpConfirm = WS_SCP_CONTINUE;

                    /* only send timestamp and file header first time */
                    if (ssh->scpFileOffset == 0) {
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
                    ssh->error = ssh->scpConfirm;
                    ret = WS_FATAL_ERROR;
                    break;
                }

                continue;

            case SCP_SEND_TIMESTAMP:
                WLOG(WS_LOG_DEBUG, scpState, "SCP_SEND_TIMESTAMP");

                if ( (ssh->error = SendScpTimestamp(ssh)) < WS_SUCCESS) {
                    WLOG(WS_LOG_ERROR, scpError, "SEND_TIMESTAMP",
                         ssh->error);
                    ret = WS_FATAL_ERROR;
                    break;
                }

                ssh->scpState = SCP_RECEIVE_CONFIRMATION;
                ssh->scpNextState = SCP_SEND_FILE_HEADER;
                continue;

            case SCP_SEND_ENTER_DIRECTORY:
                WLOG(WS_LOG_DEBUG, scpState, "SCP_SEND_ENTER_DIRECTORY");

                if ( (ssh->error = SendScpEnterDirectory(ssh)) < WS_SUCCESS) {
                    WLOG(WS_LOG_ERROR, scpError, "SEND_ENTER_DIRECTORY",
                         ssh->error);
                    ret = WS_FATAL_ERROR;
                    break;
                }

                ssh->scpState = SCP_RECEIVE_CONFIRMATION;
                ssh->scpNextState = SCP_TRANSFER;
                continue;

            case SCP_SEND_EXIT_DIRECTORY:
                WLOG(WS_LOG_DEBUG, scpState, "SCP_SEND_EXIT_DIRECTORY");

                if ( (ssh->error = SendScpExitDirectory(ssh)) < WS_SUCCESS) {
                    WLOG(WS_LOG_ERROR, scpError, "SEND_EXIT_DIRECTORY",
                         ssh->error);
                    ret = WS_FATAL_ERROR;
                    break;
                }

                ssh->scpState = SCP_RECEIVE_CONFIRMATION;
                ssh->scpNextState = SCP_TRANSFER;
                continue;

            case SCP_SEND_EXIT_DIRECTORY_FINAL:
                WLOG(WS_LOG_DEBUG, scpState, "SCP_SEND_EXIT_DIRECTORY_FINAL");

                if ( (ssh->error = SendScpExitDirectory(ssh)) < WS_SUCCESS) {
                    WLOG(WS_LOG_ERROR, scpError, "SEND_EXIT_DIRECTORY",
                         ssh->error);
                    ret = WS_FATAL_ERROR;
                    break;
                }

                ssh->scpState = SCP_RECEIVE_CONFIRMATION;
                ssh->scpNextState = SCP_DONE;
                continue;

            case SCP_SEND_FILE_HEADER:
                WLOG(WS_LOG_DEBUG, scpState, "SCP_SEND_FILE_HEADER");

                if ( (ssh->error = SendScpFileHeader(ssh)) < WS_SUCCESS) {
                    WLOG(WS_LOG_ERROR, scpError, "SEND_FILE_HEADER",
                         ssh->error);
                    ret = WS_FATAL_ERROR;
                    break;
                }

                ssh->scpState = SCP_RECEIVE_CONFIRMATION;
                ssh->scpNextState = SCP_SEND_FILE;
                continue;

            case SCP_SEND_FILE:
                WLOG(WS_LOG_DEBUG, scpState, "SCP_SEND_FILE");

                ret = wolfSSH_stream_send(ssh, ssh->scpFileBuffer,
                                          ssh->scpBufferedSz);
                if (ret < 0) {
                    WLOG(WS_LOG_ERROR, scpError, "failed to send file",
                         ssh->error);
                    ssh->error = ret;
                    ret = WS_FATAL_ERROR;
                    break;
                }

                ssh->scpFileOffset += ret;
                ssh->scpBufferedSz = 0;
                ret = WS_SUCCESS;

                if (ssh->scpFileOffset < ssh->scpFileSz) {
                    ssh->scpState = SCP_TRANSFER;
                    ssh->scpRequestType = WOLFSSH_SCP_CONTINUE_FILE_TRANSFER;

                } else {
                    ssh->scpState = SCP_CONFIRMATION_WITH_RECEIPT;
                    if (ssh->scpIsRecursive) {
                        ssh->scpFileOffset = 0;
                        ssh->scpBufferedSz = 0;
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

                if ( (ssh->error = ParseScpCommand(ssh)) < WS_SUCCESS) {
                    WLOG(WS_LOG_ERROR, scpError, "PARSE_COMMAND", ssh->error);
                    ret = WS_FATAL_ERROR;
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
                ret = DoScpSink(ssh);
                break;

            case SCP_SOURCE:
                WLOG(WS_LOG_DEBUG, scpState, "SCP_SOURCE");
                ret = DoScpSource(ssh);
                break;
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
        valueSz = (word32)WSTRLEN(message);
        if (valueSz > 0)
            value = (char*)WMALLOC(valueSz + SCP_MIN_CONFIRM_SZ + 1,
                                   ssh->ctx->heap, DYNTYPE_STRING);
        if (value == NULL)
            ret = WS_MEMORY_E;
    }

    if (ret == WS_SUCCESS) {
        /* leave room for cmd at beginning, add \n\0 at end */
        WSTRNCPY(value + 1, message, valueSz);
        *(value + valueSz + 1) = '\n';
        *(value + valueSz + 2) = '\0';

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
    int ret;
    mp_int tmp;
    word32 idx;
    byte modeOctet[SCP_MODE_OCTET_LEN];
    char decimalString[SCP_MODE_OCTET_LEN + 1];

    if (ssh == NULL || buf == NULL || inOutIdx == NULL ||
        bufSz < (SCP_MODE_OCTET_LEN + 1))
        return WS_BAD_ARGUMENT;

    idx = *inOutIdx;

    /* skip leading "C" or "D" */
    if ((buf[idx] != 'C' && buf[idx] != 'D') || (idx + 1 > bufSz))
        return WS_BAD_ARGUMENT;
    idx++;

    WMEMCPY(modeOctet, buf + idx, sizeof(modeOctet));
    idx += SCP_MODE_OCTET_LEN;

    ret = mp_init(&tmp);
    if (ret == MP_OKAY) {
        ret = mp_read_radix(&tmp, (const char*)modeOctet, 8);
    }

    if (ret == MP_OKAY) {
        /* convert octal to decimal */
        ret = mp_todecimal(&tmp, decimalString);

        if (ret == MP_OKAY) {
            /* convert string to int */
            ssh->scpFileMode = atoi(decimalString);
        }
    }

    if (ret == MP_OKAY) {
        /* eat trailing space */
        if (bufSz >= (word32)(idx + 1))
            idx++;

        ret = WS_SUCCESS;
        *inOutIdx = idx;
    }

    mp_clear(&tmp);

    return ret;
}

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
        ret = WS_SCP_TIMESTAMP_E;

    if (ret == WS_SUCCESS) {
        /* replace space with newline for atoi */
        buf[spaceIdx] = '\n';
        ssh->scpFileSz = atoi((char*)(buf + idx));

        /* restore space, increment idx to space */
        buf[spaceIdx] = ' ';
        idx = spaceIdx;

        /* eat trailing space */
        if (bufSz >= (word32)(idx + 1))
            idx++;

        *inOutIdx = idx;
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

    if (ssh == NULL || buf == NULL || inOutIdx == NULL)
        return WS_BAD_ARGUMENT;

    idx = *inOutIdx;
    len = (word32)WSTRLEN((char*)(buf + idx));

    if (len == 0 || (idx + len) > bufSz)
        ret = WS_SCP_CMD_E;

    if (ret == WS_SUCCESS) {

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
 * Places modifiation time in ssh->scpMTime and access time in
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
        /* replace space with newline for atoi */
        buf[spaceIdx] = '\n';
        ssh->scpMTime = atoi((char*)(buf + idx));

        /* restore space, increment idx past it */
        buf[spaceIdx] = ' ';
        if (spaceIdx + 1 < bufSz) {
            idx = spaceIdx + 1;
        } else {
            ret = WS_SCP_TIMESTAMP_E;
        }
    }

    /* skip '0 ' */
    if (ret == WS_SUCCESS) {
        if (buf[idx] != '0' || ++idx > bufSz)
            ret = WS_SCP_TIMESTAMP_E;

        if (ret == WS_SUCCESS) {
            if (buf[idx] != ' ' || ++idx > bufSz)
                ret = WS_SCP_TIMESTAMP_E;
        }
    }

    /* read access time */
    if (ret == WS_SUCCESS) {
        spaceIdx = idx;
        if (FindSpaceInString(buf, bufSz, &spaceIdx) != WS_SUCCESS)
            ret = WS_SCP_TIMESTAMP_E;
    }

    if (ret == WS_SUCCESS) {
        /* replace space with newline for atoi */
        buf[spaceIdx] = '\n';
        ssh->scpATime = atoi((char*)(buf + idx));

        /* restore space, increment idx past it */
        buf[spaceIdx] = ' ';
        if (spaceIdx + 1 < bufSz) {
            idx = spaceIdx + 1;
        } else {
            ret = WS_SCP_TIMESTAMP_E;
        }
    }

    if (ret == WS_SUCCESS) {
        *inOutIdx = idx;
    }

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

        while ((idx < cmdSz) && (ret == WS_SUCCESS)) {

            if (cmd[idx] == '-' && (idx + 1 < cmdSz)) {
                idx++;

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
                        if (idx + 2 < cmdSz) {
                            /* skip space */
                            idx += 2;
                            ssh->scpBasePath = cmd + idx;
                        }
                        break;

                    case 'f':
                        ssh->scpDirection = WOLFSSH_SCP_FROM;
                        if (idx + 2 < cmdSz) {
                            /* skip space */
                            idx += 2;
                            ssh->scpBasePath = cmd + idx;
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
    int sz, ret = WS_SUCCESS;
    word32 idx = 0;
    byte buf[DEFAULT_SCP_MSG_SZ];

    if (ssh == NULL)
        return WS_BAD_ARGUMENT;

    sz = wolfSSH_stream_read(ssh, buf, sizeof(buf));
    if (sz < 0)
        return sz;

    /* null-terminate request, replace newline */
    buf[sz-1] = '\0';

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

            ret = GetScpFileName(ssh, buf, sz, &idx);
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

    return ret;
}

int ReceiveScpFile(WOLFSSH* ssh)
{
    int partSz, ret = WS_SUCCESS;
    byte* part;

    if (ssh == NULL)
        return WS_BAD_ARGUMENT;

    partSz = min(ssh->scpFileSz - ssh->scpFileOffset, DEFAULT_SCP_BUFFER_SZ);

    part = (byte*)WMALLOC(partSz, ssh->ctx->heap, DYNTYPE_BUFFER);
    if (part == NULL)
        ret = WS_MEMORY_E;

    if (ret == WS_SUCCESS) {
        WMEMSET(part, 0, partSz);

        ret = wolfSSH_stream_read(ssh, part, partSz);
        if (ret > 0) {
            ssh->scpFileBuffer = part;
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
    ret = wolfSSH_stream_send(ssh, (byte*)msg, msgSz);

    if (ret != msgSz || ssh->scpConfirm == WS_SCP_ABORT) {
        ret = WS_FATAL_ERROR;

    } else {
        ret = WS_SUCCESS;
        WLOG(WS_LOG_DEBUG, "scp: sent confirmation (code: %d)", msg[0]);

        if (ssh->scpConfirmMsg != NULL) {
            WFREE(ssh->scpConfirmMsg, ssh->ctx->heap, DYNTYPE_STRING);
            ssh->scpConfirmMsg = NULL;
            ssh->scpConfirmMsgSz = 0;
        }
    }

    return ret;
}

int ReceiveScpConfirmation(WOLFSSH* ssh)
{
    int ret = WS_SUCCESS;
    int msgSz;
    byte msg[DEFAULT_SCP_MSG_SZ];

    if (ssh == NULL)
        return WS_BAD_ARGUMENT;

    WMEMSET(msg, 0, sizeof(msg));
    msgSz = wolfSSH_stream_read(ssh, msg, sizeof(msg));

    if (msgSz < 0) {
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


#if !defined(WOLFSSH_SCP_USER_CALLBACKS) && !defined(NO_FILESYSTEM)

/* for porting to systems without errno */
static INLINE int wolfSSH_LastError(void)
{
    return errno;
}

/* set file access and modification times
 * Returns WS_SUCCESS on success, or negative upon error */
static int SetTimestampInfo(const char* fileName, word64 mTime, word64 aTime)
{
    int ret = WS_SUCCESS;
    struct timeval tmp[2];

    if (fileName == NULL)
        ret= WS_BAD_ARGUMENT;

    if (ret == WS_SUCCESS) {
        tmp[0].tv_sec = aTime;
        tmp[0].tv_usec = 0;
        tmp[1].tv_sec = mTime;
        tmp[1].tv_usec = 0;

        ret = utimes(fileName, tmp);
    }

    return ret;
}


/* Default SCP receive callback, called by wolfSSH when application has called
 * wolfSSH_accept() and a new SCP request has been received for an incomming
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
 *         WOLFSSH_SCP_NEW_FILE  - new incomming file, no data yet, but size
 *                                 and name
 *         WOLFSSH_SCP_FILE_PART - new file data, or continuation of
 *                                 existing file
 *         WOLFSSH_SCP_FILE_DONE - indicates named file transfer is done
 *         WOLFSSH_SCP_NEW_DIR   - indicates new directory, name in fileName
 *         WOLFSSH_SCP_END_DIR   - indicates leaving directory, up recursively
 * basePath    - base directory path peer is requesting that file be written to
 * fileName    - name of incomming file or directory
 * fileMode    - mode/permission of incomming file or directory
 * mTime       - file modification time, if sent by peer in seconds since
 *               Unix epoch (00:00:00 UTC, Jan. 1, 1970). mTime is 0 if
 *               peer did not send time value.
 * aTime       - file access time, if sent by peer in seconds since Unix
 *               epoch (00:00:00 UTC, Jan. 1, 1970). aTime is 0 if peer did
 *               not send time value.
 * totalFileSz - total size of incomming file (directory size may list zero)
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

    if (ctx != NULL)
        fp = (WFILE*)ctx;

    switch (state) {

        case WOLFSSH_SCP_NEW_REQUEST:

            /* cd into requested root path */
            if (WCHDIR(basePath) != 0) {
                wolfSSH_SetScpErrorMsg(ssh, "invalid destination directory");
                ret = WS_SCP_ABORT;
            }
            break;

        case WOLFSSH_SCP_NEW_FILE:

            /* open file */
            if (WFOPEN(&fp, fileName, "wb") != 0) {
                wolfSSH_SetScpErrorMsg(ssh, "unable to open file for writing");
                ret = WS_SCP_ABORT;
                break;
            }

            /* store file pointer in user ctx */
            wolfSSH_SetScpRecvCtx(ssh, fp);
            break;

        case WOLFSSH_SCP_FILE_PART:

            if (fp == NULL) {
                ret = WS_SCP_ABORT;
                break;
            }

            /* read file, or file part */
            bytes = (word32)WFWRITE(buf, 1, bufSz, fp);
            if (bytes != bufSz) {
                WLOG(WS_LOG_ERROR, scpError, "scp receive callback unable "
                     "to write requested size to file", bytes);
                ret = WS_SCP_ABORT;
            }
            break;

        case WOLFSSH_SCP_FILE_DONE:

            /* close file */
            if (fp != NULL)
                WFCLOSE(fp);

            /* set timestamp info */
            if (mTime != 0 || aTime != 0)
                ret = SetTimestampInfo(fileName, mTime, aTime);

            if (ret == WS_SUCCESS) {
                ret = WS_SCP_CONTINUE;
            } else {
                ret = WS_SCP_ABORT;
            }

            break;

        case WOLFSSH_SCP_NEW_DIR:

            /* try to create new directory */
            if (WMKDIR(fileName, fileMode) != 0) {
                if (wolfSSH_LastError() != EEXIST) {
                    wolfSSH_SetScpErrorMsg(ssh, "error creating directory");
                    ret = WS_SCP_ABORT;
                    break;
                }
            }

            /* cd into directory */
            if (WCHDIR(fileName) != 0) {
                wolfSSH_SetScpErrorMsg(ssh, "unable to cd into directory");
                ret = WS_SCP_ABORT;
            }
            break;

        case WOLFSSH_SCP_END_DIR:

            /* cd out of directory */
            if (WCHDIR("../") != 0) {
                wolfSSH_SetScpErrorMsg(ssh, "unable to cd out of directory");
                ret = WS_SCP_ABORT;
            }
            break;

        default:
            wolfSSH_SetScpErrorMsg(ssh, "invalid scp command request");
            ret = WS_SCP_ABORT;
    }

    (void)totalFileSz;
    (void)fileOffset;
    return ret;
}

/* Extract file name from full path, store in fileName.
 * Return WS_SUCCESS on success, negative upon error */
static int ExtractFileName(const char* filePath, char* fileName,
                           word32 fileNameSz)
{
    int ret = WS_SUCCESS;
    word32 pathLen, fileLen;
    word32 idx = 0, separator = 0;

    if (filePath == NULL || fileName == NULL)
        return WS_BAD_ARGUMENT;

    pathLen = (int)WSTRLEN(filePath);

    /* find last separator */
    while (idx < pathLen) {
        if (filePath[idx] == '/' || filePath[idx] == '\\')
            separator = idx;
        idx++;
    }

    if (separator == 0)
        return WS_BAD_ARGUMENT;

    fileLen = pathLen - separator - 1;
    if (fileLen + 1 > fileNameSz)
        return WS_SCP_FILE_SZ_E;

    WMEMCPY(fileName, filePath + separator + 1, fileLen);
    fileName[fileLen] = '\0';

    return ret;
}

static int GetFileSize(WFILE* fp, word32* fileSz)
{
    if (fp == NULL || fileSz == NULL)
        return WS_BAD_ARGUMENT;

    /* get file size */
    WFSEEK(fp, 0, WSEEK_END);
    *fileSz = (word32)WFTELL(fp);
    WREWIND(fp);

    return WS_SUCCESS;
}

static int GetFileStats(ScpSendCtx* ctx, const char* fileName,
                        word64* mTime, word64* aTime, int* fileMode)
{
    int ret = WS_SUCCESS;

    if (ctx == NULL || fileName == NULL || mTime == NULL ||
        aTime == NULL || fileMode == NULL) {
        return WS_BAD_ARGUMENT;
    }

    /* get file stats for times and mode */
    if (stat(fileName, &ctx->s) < 0) {
        ret = WS_BAD_FILE_E;

    } else {
        *mTime = (word64)ctx->s.st_mtime;
        *aTime = (word64)ctx->s.st_atime;
        *fileMode = ctx->s.st_mode & (S_IRWXU | S_IRWXG | S_IRWXO);
    }

    return ret;
}

/* Create new ScpDir struct for pushing on directory stack.
 * Return valid pointer on success, NULL on failure */
static ScpDir* ScpNewDir(const char* path, void* heap)
{
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
    entry->dir = opendir(path);
    if (entry->dir == NULL) {
        WFREE(entry, heap, DYNTYPE_SCPDIR);
        WLOG(WS_LOG_ERROR, scpError, "opendir failed on directory",
             WS_INVALID_PATH_E);
        return NULL;
    }

    return entry;
}

/* Create and push new ScpDir on stack, append directory to ctx->dirName */
static int ScpPushDir(ScpSendCtx* ctx, const char* path, void* heap)
{
    ScpDir* entry;

    if (ctx == NULL)
        return WS_BAD_ARGUMENT;

    entry = ScpNewDir(path, heap);
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

    /* append directory name to ctx->dirName */
    WSTRNCPY(ctx->dirName, path, DEFAULT_SCP_FILE_NAME_SZ);

    return WS_SUCCESS;
}

/* Remove top ScpDir from directory stack, remove dir from ctx->dirName */
static int ScpPopDir(ScpSendCtx* ctx, void* heap)
{
    ScpDir* entry = NULL;
    int idx = 0, separator = 0;

    if (ctx->currentDir != NULL) {
        entry = ctx->currentDir;
        ctx->currentDir = entry->next;
    }

    if (entry != NULL) {
        closedir(entry->dir);
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
        return WS_SCP_STACK_EMPTY_E;

    (void)heap;
    return WS_SUCCESS;
}

/* Get next entry in directory, either file or directory, skips self (.)
 * and parent (..) directories, stores in ctx->entry.
 * Return WS_SUCCESS on success or negative upon error */
static int FindNextDirEntry(ScpSendCtx* ctx)
{
    if (ctx == NULL)
        return WS_BAD_ARGUMENT;

    /* skip self (.) and parent (..) directories */
    do {
        ctx->entry = readdir(ctx->currentDir->dir);
    } while ((ctx->entry != NULL) &&
             (WSTRNCMP(ctx->entry->d_name, ".",  1) == 0 ||
              WSTRNCMP(ctx->entry->d_name ,"..", 2) == 0));

    return WS_SUCCESS;
}

/* Test if directory stack is empty, return 1 if empty, otherwise 0 */
static int ScpDirStackIsEmpty(ScpSendCtx* ctx)
{
    if (ctx && ctx->currentDir == NULL)
        return 1;

    return 0;
}

static int ScpFileIsDir(ScpSendCtx* ctx)
{
    return S_ISDIR(ctx->s.st_mode);
}

static int ScpFileIsFile(ScpSendCtx* ctx)
{
    return S_ISREG(ctx->s.st_mode);
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
 * one directory or file at a time, returning WS_SCP_ENTER_DIRECTORY when
 * a new directory is entered, WS_SCP_EXIT_DIRECTORY when a directory is
 * exited (not including the final directory exit), and
 * WS_SCP_EXIT_DIRECTORY_FINAL when the final directory is done.
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
 *     WS_SCP_ENTER_DIRECTORY      - send directory name to peer - fileName,
 *                                   mode (optional), mTime (optional), and
 *                                   aTime (optional) should be set. Return
 *                                   when callback and "entered" a directory.
 *     WS_SCP_EXIT_DIRECTORY       - return when recursive directory traversal
 *                                   has "exited" a directory.
 *     WS_SCP_EXIT_DIRECTORY_FINAL - return when recursive directory transfer
 *                                   is complete.
 *     WS_SCP_ABORT                - abort file transfer request
 */
int wsScpSendCallback(WOLFSSH* ssh, int state, const char* peerRequest,
        char* fileName, word32 fileNameSz, word64* mTime, word64* aTime,
        int* fileMode, word32 fileOffset, word32* totalFileSz, byte* buf,
        word32 bufSz, void* ctx)
{
    ScpSendCtx* sendCtx = NULL;
    int ret = WS_SUCCESS, dirNameLen, dNameLen;
    char filePath[DEFAULT_SCP_FILE_NAME_SZ];

    if (ctx != NULL) {
        sendCtx = (ScpSendCtx*)ctx;
    }

    WMEMSET(filePath, 0, DEFAULT_SCP_FILE_NAME_SZ);

    switch (state) {

        case WOLFSSH_SCP_SINGLE_FILE_REQUEST:

            if ((sendCtx == NULL) || WFOPEN(&(sendCtx->fp), peerRequest,
                                            "rb") != 0) {
                wolfSSH_SetScpErrorMsg(ssh, "unable to open file for reading");
                ret = WS_SCP_ABORT;
            }

            if (ret == WS_SUCCESS) {
                if (sendCtx->fp == NULL)
                    ret = WS_SCP_ABORT;
            }

            if (ret == WS_SUCCESS)
                ret = GetFileSize(sendCtx->fp, totalFileSz);

            if (ret == WS_SUCCESS)
                ret = GetFileStats(sendCtx, peerRequest, mTime, aTime, fileMode);

            if (ret == WS_SUCCESS)
                ret = ExtractFileName(peerRequest, fileName, fileNameSz);

            if (ret == WS_SUCCESS && sendCtx != NULL && sendCtx->fp != NULL) {
                ret = (word32)WFREAD(buf, 1, bufSz, sendCtx->fp);
            } else {
                ret = WS_SCP_ABORT;
            }

            /* keep fp open if no errors and transfer will continue */
            if ((sendCtx != NULL) && (sendCtx->fp != NULL) &&
                ((ret < 0) || (*totalFileSz == (word32)ret))) {
                WFCLOSE(sendCtx->fp);
            }

            break;

        case WOLFSSH_SCP_RECURSIVE_REQUEST:

            if (ScpDirStackIsEmpty(sendCtx)) {

                /* first request, keep track of request directory */
                ret = ScpPushDir(sendCtx, peerRequest, ssh->ctx->heap);

                if (ret == WS_SUCCESS) {
                    /* get file name from request */
                    ret = ExtractFileName(peerRequest, fileName, fileNameSz);
                }

                if (ret == WS_SUCCESS) {
                    ret = GetFileStats(sendCtx, peerRequest, mTime, aTime,
                                       fileMode);
                }

                if (ret == WS_SUCCESS) {
                    ret = WS_SCP_ENTER_DIR;
                } else {
                    ret = WS_SCP_ABORT;
                }

                /* send directory msg or abort */
                break;
            }

            ret = FindNextDirEntry(sendCtx);
            if (ret == WS_SUCCESS) {

                /* reached end of directory */
                if (sendCtx->entry == NULL) {
                    ret = ScpPopDir(sendCtx, ssh->ctx->heap);
                    if (ret == WS_SUCCESS) {
                        ret = WS_SCP_EXIT_DIR;

                    } else if (ret == WS_SCP_STACK_EMPTY_E) {
                        ret = WS_SCP_EXIT_DIR_FINAL;

                    } else {
                        ret = WS_SCP_ABORT;
                    }

                    /* send exit directory msg or abort */
                    break;
                }
            }

            if (ret == WS_SUCCESS) {

                dirNameLen = (int)WSTRLEN(sendCtx->dirName);
                dNameLen   = (int)WSTRLEN(sendCtx->entry->d_name);

                if ((dirNameLen + 1 + dNameLen) > DEFAULT_SCP_FILE_NAME_SZ) {
                    ret = WS_SCP_ABORT;

                } else {
                    WSTRNCPY(filePath, sendCtx->dirName,
                             DEFAULT_SCP_FILE_NAME_SZ);
                    WSTRNCAT(filePath, "/", 1);
                    WSTRNCAT(filePath, sendCtx->entry->d_name,
                             DEFAULT_SCP_FILE_NAME_SZ - 1 - dirNameLen);
                    WSTRNCPY(fileName, sendCtx->entry->d_name,
                             DEFAULT_SCP_FILE_NAME_SZ);

                    ret = GetFileStats(sendCtx, filePath, mTime, aTime,
                                       fileMode);
                }
            }

            if (ret == WS_SUCCESS) {

                if (ScpFileIsDir(sendCtx)) {

                    ret = ScpPushDir(sendCtx, filePath, ssh->ctx->heap);
                    if (ret == WS_SUCCESS) {
                        ret = WS_SCP_ENTER_DIR;
                    } else {
                        ret = WS_SCP_ABORT;
                    }

                } else if (ScpFileIsFile(sendCtx)) {

                    if (WFOPEN(&(sendCtx->fp), filePath, "rb") != 0) {
                        wolfSSH_SetScpErrorMsg(ssh, "unable to open file "
                                               "for reading");
                        ret = WS_SCP_ABORT;
                    }

                    if (ret == WS_SUCCESS) {
                        ret = GetFileSize(sendCtx->fp, totalFileSz);

                        if (ret == WS_SUCCESS)
                            ret = (word32)WFREAD(buf, 1, bufSz, sendCtx->fp);
                    }

                    /* keep fp open if no errors and transfer will continue */
                    if ((sendCtx->fp != NULL) &&
                        ((ret < 0) || (*totalFileSz == (word32)ret))) {
                        WFCLOSE(sendCtx->fp);
                    }
                }

            } else {
                ret = WS_SCP_ABORT;
            }

            break;

        case WOLFSSH_SCP_CONTINUE_FILE_TRANSFER:

            if (sendCtx == NULL) {
                ret = WS_SCP_ABORT;
                break;
            }

            ret = (word32)WFREAD(buf, 1, bufSz, sendCtx->fp);
            if ((ret < 0) || (fileOffset + ret == *totalFileSz)) {
                WFCLOSE(sendCtx->fp);
            }

            break;
    }

    return ret;
}

#endif /* WOLFSSH_SCP_USER_CALLBACKS */

#endif /* WOLFSSH_SCP */


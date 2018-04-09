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

#ifdef NO_INLINE
    #include <wolfssh/misc.h>
#else
    #define WOLFSSH_MISC_INCLUDED
    #include "src/misc.c"
#endif

#ifndef NULL
    #include <stddef.h>
#endif

#ifndef SCP_USER_CALLBACKS
    /* for utimes() */
    #include <sys/time.h>
    #include <errno.h>
#endif

/* size of scp protocol message buffer, dependent mostly on
 * path and file name lengths, on the stack */
#ifndef DEFAULT_SCP_MSG_SZ
    #define DEFAULT_SCP_MSG_SZ 1024
#endif

/* size of scp file transfer buffer, allocated dynamically */
#ifndef DEFAULT_SCP_BUFFER_SZ
    #define DEFAULT_SCP_BUFFER_SZ DEFAULT_MAX_PACKET_SZ
#endif

const char scpError[] = "scp error: %s, %d";
const char scpState[] = "scp state: %s";

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

        switch (ssh->scpState) {

            case SCP_PARSE_COMMAND:
                WLOG(WS_LOG_DEBUG, scpState, "SCP_PARSE_COMMAND");

                if ( (ssh->error = ParseScpCommand(ssh)) < WS_SUCCESS) {
                    WLOG(WS_LOG_ERROR, scpError, "PARSE_COMMAND", ssh->error);
                    ret = WS_FATAL_ERROR;
                    break;
                }

                ssh->scpState = SCP_SEND_CONFIRMATION;

                if (ssh->scpDirection == WOLFSSH_SCP_TO) {
                    ssh->scpNextState = SCP_RECEIVE_MESSAGE;

                    ssh->scpConfirm = ssh->ctx->scpRecvCb(ssh,
                            WOLFSSH_SCP_NEW_REQUEST, ssh->scpBasePath,
                            NULL, 0, 0, 0, 0, NULL, 0, 0, ssh->scpRecvCtx);

                } else if (ssh->scpDirection == WOLFSSH_SCP_FROM) {
                    ret = WS_UNIMPLEMENTED_E;
                    WLOG(WS_LOG_ERROR, scpError, "retrieving files not "
                            "supported yet", ret);
                    break;

                } else {
                    ret = WS_SCP_CMD_E;
                    WLOG(WS_LOG_ERROR, scpError, "invalid command", ret);
                    break;
                }

                continue;

            case SCP_RECEIVE_MESSAGE:
                WLOG(WS_LOG_DEBUG, scpState, "SCP_RECEIVE_MESSAGE");

                if ( (ssh->error = ReceiveScpMessage(ssh)) < WS_SUCCESS) {
                    if (ssh->error == WS_EOF) {
                        ssh->scpState = SCP_DONE;
                        break;
                    }

                    WLOG(WS_LOG_ERROR, scpError, "RECEIVE_MESSAGE",
                         ssh->error);
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

        while (idx < cmdSz) {

            if (cmd[idx] == '-' && (idx + 1 < cmdSz)) {
                idx++;

                switch (cmd[idx]) {
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


#ifndef SCP_USER_CALLBACKS

/* for porting to systems without errno */
static INLINE int wolfSSH_LastError(void)
{
    return errno;
}

static int SetTimestampInfo(const char* fileName, int mTime, int aTime)
{
    int ret;
    struct timeval tmp[2];

    if (fileName == NULL)
        return WS_BAD_ARGUMENT;

    tmp[0].tv_sec = aTime;
    tmp[0].tv_usec = 0;
    tmp[1].tv_sec = mTime;
    tmp[1].tv_usec = 0;

    ret = utimes(fileName, tmp);

    return ret;
}


/* Default SCP receive callback, called by wolfSSH when application has called
 * wolfSSH_accept() and a new SCP request has been received for an incomming
 * file or directory.
 *
 * Handles accepting recursive directories by telling the user when to step
 * into (WOLFSSH_SCP_NEW_DIR) and out of (WOLFSSH_SCP_END_DIR) a directory.
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
 *
 *     When WS_SCP_ABORT is returned, an optional error message can be sent
 *     to the peer. This error message can be set by calling
 *     wolfSSH_SetScpErrorMsg().
 */
int wsScpRecvCallback(WOLFSSH* ssh, int state, const char* basePath,
        const char* fileName, word32 fileMode, word32 mTime, word32 aTime,
        word32 totalFileSz, byte* buf, word32 bufSz, word32 fileOffset,
        void* ctx)
{
    WFILE* fp;
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
            WFCLOSE(fp);

            /* set timestamp info */
            if (mTime != 0 || aTime != 0) {
                SetTimestampInfo(fileName, mTime, aTime);
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

#endif /* SCP_USER_CALLBACKS */

#endif /* WOLFSSH_SCP */


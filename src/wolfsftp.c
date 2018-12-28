/* wolfsftp.c
 *
 * Copyright (C) 2014-2016 wolfSSL Inc.
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


#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif
#define _CRT_SECURE_NO_WARNINGS
#include <wolfssh/wolfsftp.h>

#ifdef WOLFSSH_SFTP

#include <wolfssh/internal.h>
#include <wolfssh/log.h>

#ifdef NO_INLINE
    #include <wolfssh/misc.h>
#else
    #define WOLFSSH_MISC_INCLUDED
    #include "src/misc.c"
#endif


/* enum for bit field with an ID of each of the state structures */
enum WS_SFTP_STATE_ID {
    STATE_ID_ALL   = 0, /* default to select all */
    STATE_ID_LSTAT = 0x01,
    STATE_ID_OPEN  = 0x02,
    STATE_ID_GET   = 0x04,
};

enum WS_SFTP_LSTAT_STATE_ID {
    STATE_LSTAT_INIT,
    STATE_LSTAT_SEND_TYPE_REQ,
    STATE_LSTAT_GET_HEADER,
    STATE_LSTAT_CHECK_REQ_ID,
    STATE_LSTAT_PARSE_REPLY,
    STATE_LSTAT_CLEANUP
};

typedef struct WS_SFTP_LSTAT_STATE {
    enum WS_SFTP_LSTAT_STATE_ID state;
    word32 reqId;
    word32 dirSz;
} WS_SFTP_LSTAT_STATE;


enum WS_SFTP_OPEN_STATE_ID {
    STATE_OPEN_INIT,
    STATE_OPEN_SEND,
    STATE_OPEN_GETHANDLE,
    STATE_OPEN_CLEANUP
};

typedef struct WS_SFTP_OPEN_STATE {
    enum WS_SFTP_OPEN_STATE_ID state;
    byte* data;
    int sz;
    word32 idx;
} WS_SFTP_OPEN_STATE;


enum WS_SFTP_GET_STATE_ID {
    STATE_GET_INIT,
    STATE_GET_LSTAT,
    STATE_GET_OPEN_REMOTE,
    STATE_GET_LOOKUP_OFFSET,
    STATE_GET_OPEN_LOCAL,
    STATE_GET_READ,
    STATE_GET_CLOSE_LOCAL,
    STATE_GET_CLOSE_REMOTE,
    STATE_GET_CLEANUP
};

typedef struct WS_SFTP_GET_STATE {
    enum WS_SFTP_GET_STATE_ID state;
    WS_SFTP_FILEATRB attrib;
    byte handle[WOLFSSH_MAX_HANDLE];
    WFILE* fl;
    long gOfst;
    word32 handleSz;
    byte r[WOLFSSH_MAX_SFTP_RW];
} WS_SFTP_GET_STATE;


enum WS_SFTP_SEND_READ_STATE_ID {
    STATE_SEND_READ_INIT,
    STATE_SEND_READ_SEND_REQ,
    STATE_SEND_READ_GET_HEADER,
    STATE_SEND_READ_CHECK_REQ_ID,
    STATE_SEND_READ_FTP_DATA,
    STATE_SEND_READ_REMAINDER,
    STATE_SEND_READ_FTP_STATUS,
    STATE_SEND_READ_CLEANUP
};

typedef struct WS_SFTP_SEND_READ_STATE {
    enum WS_SFTP_SEND_READ_STATE_ID state;
    byte* data;
    word32 reqId;
    word32 idx;
    word32 sz;
    byte type;
} WS_SFTP_SEND_READ_STATE;


static int SendPacketType(WOLFSSH* ssh, byte type, byte* buf, word32 bufSz);
static int SFTP_ParseAtributes(WOLFSSH* ssh,  WS_SFTP_FILEATRB* atr);
static int SFTP_ParseAtributes_buffer(WOLFSSH* ssh,  WS_SFTP_FILEATRB* atr,
        byte* buf, word32 bufSz);
static int SFTP_GetAttributes(const char* fileName, WS_SFTP_FILEATRB* atr,
        byte link);
static int SFTP_GetAttributes_Handle(WOLFSSH* ssh, byte* handle, int handleSz,
        WS_SFTP_FILEATRB* atr);
static WS_SFTPNAME* wolfSSH_SFTPNAME_new(void* heap);


/* Used to clear and free all states. Should be when returning errors or success
 * Must be called when free'ing the SFTP. For now static since only used in
 * wolfsftp.c
 *
 * Note: Most cases an error will free all states and a success will free
 *       specific state ID.
 */
static void wolfSSH_SFTP_ClearState(WOLFSSH* ssh, enum WS_SFTP_STATE_ID state)
{
    if (ssh) {

        if (state == 0)
            state = ~state; /* set all bits hot */

        if (state & STATE_ID_GET) {
            XFREE(ssh->getState, ssh->ctx->heap, DYNTYPE_SFTP_STATE);
            ssh->getState   = NULL;
        }
        if (state & STATE_ID_LSTAT) {
            XFREE(ssh->lstatState, ssh->ctx->heap, DYNTYPE_SFTP_STATE);
            ssh->lstatState = NULL;
        }

        if (state & STATE_ID_OPEN) {
            XFREE(ssh->openState, ssh->ctx->heap, DYNTYPE_SFTP_STATE);
            ssh->openState  = NULL;
        }
    }
}


/* Gets packet header information
 * request Id, type, and size of type specific data
 * return value is length of type specific data still on the wire to be read
 */
static int SFTP_GetHeader(WOLFSSH* ssh, word32* reqId, byte* type)
{
    int    ret;
    word32 len;
    byte buf[WOLFSSH_SFTP_HEADER];

    if (type == NULL || reqId == NULL || ssh == NULL) {
        WLOG(WS_LOG_SFTP, "NULL argument error");
        wolfSSH_SFTP_ClearState(ssh, STATE_ID_ALL);
        return WS_BAD_ARGUMENT;
    }

    ret = wolfSSH_stream_read(ssh, buf, sizeof(buf));
    if (ret == WS_WANT_READ) {
        ssh->error = ret;
        return ret;
    }

    if (ret < WOLFSSH_SFTP_HEADER) {
        WLOG(WS_LOG_SFTP, "Unable to read SFTP header");
        wolfSSH_SFTP_ClearState(ssh, STATE_ID_ALL);
        return WS_FATAL_ERROR;
    }

    ato32(buf, &len);
    *type = buf[LENGTH_SZ];
    ato32(buf + UINT32_SZ + MSG_ID_SZ, reqId);

    return len - UINT32_SZ - MSG_ID_SZ;
}


/* Sets the packet header information to the front of buf. It is assumed that
 * buf is at least WOLFSSH_SFTP_HEADER (9).
 *
 * reqId  request ID to place in header of packet
 * type   type of SFTP packet i.e. WOLFSSH_FTP_OPEN
 * len    length of all data in packet
 * buf    buffer to place packet header at front of
 *
 * returns WS_SUCCESS on success
 */
static int SFTP_SetHeader(WOLFSSH* ssh, word32 reqId, byte type, word32 len,
        byte* buf) {
    c32toa(len + LENGTH_SZ + MSG_ID_SZ, buf);
    buf[LENGTH_SZ] = type;
    c32toa(reqId, buf + LENGTH_SZ + MSG_ID_SZ);

    (void)ssh;

    return WS_SUCCESS;
}


#ifndef NO_WOLFSSH_SERVER
/* unique from other packets because the request ID is not also sent.
 *
 * returns WS_SUCCESS on success
 */
static int SFTP_ServerRecvInit(WOLFSSH* ssh) {
    int  len;
    byte id;
    word32 sz = 0;
    word32 version = 0;
    byte buf[LENGTH_SZ + MSG_ID_SZ + UINT32_SZ];

    if ((len = wolfSSH_stream_read(ssh, buf, sizeof(buf))) != sizeof(buf)) {
        return len;
    }

    ato32(buf, &sz);
    if (sz < MSG_ID_SZ + UINT32_SZ) {
        wolfSSH_SFTP_ClearState(ssh, STATE_ID_ALL);
        return WS_BUFFER_E;
    }

    /* compare versions supported */
    id = buf[LENGTH_SZ];
    if (id != WOLFSSH_FTP_INIT) {
        WLOG(WS_LOG_SFTP, "Unexpected SFTP type received");
        wolfSSH_SFTP_ClearState(ssh, STATE_ID_ALL);
        return WS_BUFFER_E;
    }

    ato32(buf + LENGTH_SZ + MSG_ID_SZ, &version);
    if (version != WOLFSSH_SFTP_VERSION) {
        WLOG(WS_LOG_SFTP, "Unsupported SFTP version, sending version 3");
    }

    /* silently ignore extensions if not supported */
    sz = sz - MSG_ID_SZ - UINT32_SZ;
    if (sz > 0) {
        byte* data = (byte*)WMALLOC(sz, NULL, DYNTYPE_BUFFER);
        if (data ==  NULL) return WS_MEMORY_E;
        len = wolfSSH_stream_read(ssh, data, sz);
        WFREE(data, NULL, DYNTYPE_BUFFER);
        if (len != (int)sz)
            return len;
    }

    ssh->reqId++;
    return WS_SUCCESS;
}


/* unique from SendPacketType because the request ID is not also sent.
 *
 * returns WS_SUCCESS on success
 */
static int SFTP_ServerSendInit(WOLFSSH* ssh) {
    int  ret;
    byte buf[LENGTH_SZ + MSG_ID_SZ + UINT32_SZ];

    c32toa(MSG_ID_SZ + UINT32_SZ, buf);
    buf[LENGTH_SZ] = WOLFSSH_FTP_VERSION;

    /* version */
    c32toa((word32)WOLFSSH_SFTP_VERSION, buf + LENGTH_SZ + MSG_ID_SZ);
    if ((ret = wolfSSH_stream_send(ssh, buf, sizeof(buf))) != sizeof(buf)) {
        return ret;
    }

    return WS_SUCCESS;
}


/* @TODO
 * state machine for SFTP protocol
 * returns WS_SFTP_COMPLETE on success
 */
int wolfSSH_SFTP_accept(WOLFSSH* ssh)
{
    int ret = WS_SFTP_COMPLETE;

    if (ssh == NULL) {
        return WS_BAD_ARGUMENT;
    }

    /* check accept is done, if not call wolfSSH accept */
    if (ssh->acceptState < ACCEPT_CLIENT_SESSION_ESTABLISHED) {
        byte name[] = "sftp";

        WLOG(WS_LOG_SFTP, "Trying to do SSH accept first");
        if ((ret = wolfSSH_SetChannelType(ssh, WOLFSSH_SESSION_SUBSYSTEM,
                            name, sizeof(name) - 1)) != WS_SUCCESS) {
            WLOG(WS_LOG_SFTP, "Unable to set subsystem channel type");
            return ret;
        }

        if ((ret = wolfSSH_accept(ssh)) != WS_SUCCESS) {
            return ret;
        }
    }

    switch (ssh->sftpState) {
        case SFTP_BEGIN:
            if ((ssh->error = SFTP_ServerRecvInit(ssh)) != WS_SUCCESS) {
                return WS_FATAL_ERROR;
            }
            ssh->sftpState = SFTP_RECV;
            FALL_THROUGH;
            /* no break */

        case SFTP_RECV:
            if ((ssh->error = SFTP_ServerSendInit(ssh)) != WS_SUCCESS) {
                return WS_FATAL_ERROR;
            }
            ssh->sftpState = SFTP_DONE;
            WLOG(WS_LOG_SFTP, "SFTP connection established");
            break;

        default:
            ret = WS_FATAL_ERROR;
    }

    return ret;
}

/* returns the size of buffer needed to hold attributes */
static int SFTP_AtributesSz(WOLFSSH* ssh, WS_SFTP_FILEATRB* atr)
{
    word32 sz = 0;

    (void)ssh;

    sz += UINT32_SZ; /* flag */

    /* check if size attribute present */
    if (atr->flags & WOLFSSH_FILEATRB_SIZE) {
        sz += UINT32_SZ * 2;
    }

    /* check if uid and gid attribute present */
    if (atr->flags & WOLFSSH_FILEATRB_UIDGID) {
        sz += UINT32_SZ * 2;
    }

    /* check if permissions attribute present */
    if (atr->flags & WOLFSSH_FILEATRB_PERM) {
        sz += UINT32_SZ;
    }

    /* check if time attribute present */
    if (atr->flags & WOLFSSH_FILEATRB_TIME) {
        sz += UINT32_SZ * 2;
    }

    /* check if extended attributes are present */
    if (atr->flags & WOLFSSH_FILEATRB_EXT) {
        sz += UINT32_SZ;

        /* @TODO handle extended attributes */
    }

    return sz;
}


/* set attributes in buffer
 *
 * returns WS_SUCCESS on success
 */
static int SFTP_SetAttributes(WOLFSSH* ssh, byte* buf, word32 bufSz,
        WS_SFTP_FILEATRB* atr)
{
    word32 idx = 0;

    (void)ssh;
    (void)bufSz;

    /* get flags */
    c32toa(atr->flags, buf); idx += UINT32_SZ;

    /* check if size attribute present */
    if (atr->flags & WOLFSSH_FILEATRB_SIZE) {
        c32toa((word32)(atr->sz << 32), buf + idx);        idx += UINT32_SZ;
        c32toa((word32)(atr->sz & 0xFFFFFFFF), buf + idx); idx += UINT32_SZ;
    }

    /* check if uid and gid attribute present */
    if (atr->flags & WOLFSSH_FILEATRB_UIDGID) {
        c32toa(atr->uid, buf + idx); idx += UINT32_SZ;
        c32toa(atr->gid, buf + idx); idx += UINT32_SZ;
    }

    /* check if permissions attribute present */
    if (atr->flags & WOLFSSH_FILEATRB_PERM) {
        c32toa(atr->per, buf + idx); idx += UINT32_SZ;
    }


    /* check if time attribute present */
    if (atr->flags & WOLFSSH_FILEATRB_TIME) {
        c32toa(atr->atime, buf + idx); idx += UINT32_SZ;
        c32toa(atr->mtime, buf + idx); idx += UINT32_SZ;
    }

    /* check if extended attributes are present */
    if (atr->flags & WOLFSSH_FILEATRB_EXT) {
        /* @TODO handle attribute extensions */
        c32toa(atr->extCount, buf + idx);
    }

    return WS_SUCCESS;
}


/* returns WS_SUCCESS on success */
static int wolfSSH_SFTP_RecvRealPath(WOLFSSH* ssh, int reqId, int maxSz)
{
    WS_SFTP_FILEATRB atr;
    char* dir;
    char  r[WOLFSSH_MAX_FILENAME];
    word32 rSz;
    word32 idx = 0;
    word32 i;
    byte* out;

    WLOG(WS_LOG_SFTP, "Receiving WOLFSSH_FTP_REALPATH");

    if (ssh == NULL) {
        WLOG(WS_LOG_SFTP, "Bad argument passed in");
        return WS_BAD_ARGUMENT;
    }

    /* get directory from wire */
    dir = (char*)WMALLOC(maxSz, ssh->ctx->heap, DYNTYPE_BUFFER);
    if (dir == NULL) {
        return WS_MEMORY_E;
    }
    if (wolfSSH_stream_read(ssh, (byte*)dir, maxSz) < 0) {
        WFREE(dir, ssh->ctx->heap, DYNTYPE_BUFFER);
        return WS_FATAL_ERROR;
    }

    ato32((byte*)dir, &rSz);
    if (rSz > WOLFSSH_MAX_FILENAME || (int)(rSz + UINT32_SZ) > maxSz) {
        WFREE(dir, ssh->ctx->heap, DYNTYPE_BUFFER);
        return WS_BUFFER_E;
    }
    WMEMCPY(r, dir + UINT32_SZ, rSz);
    r[rSz] = '\0';
    WFREE(dir, ssh->ctx->heap, DYNTYPE_BUFFER);

    /* get working directory in the case of receiving non absolute path */
    if (r[0] != '/' && r[1] != ':') {
        char wd[WOLFSSH_MAX_FILENAME];

        if (WGETCWD(wd, WOLFSSH_MAX_FILENAME) == NULL) {
            WLOG(WS_LOG_SFTP, "Unable to get current working directory");
            wolfSSH_SFTP_SendStatus(ssh, WOLFSSH_FTP_FAILURE, reqId,
                    "Directory error", "English");
            return WS_BAD_FILE_E;
        }
        WSTRNCAT(wd, "/", WOLFSSH_MAX_FILENAME);
        WSTRNCAT(wd, r, WOLFSSH_MAX_FILENAME);
        WMEMCPY(r, wd, WOLFSSH_MAX_FILENAME);
    }

    clean_path(r);
    rSz = (int)WSTRLEN(r);

    /* for real path always send '/' chars */
    for (i = 0; i < rSz; i++) {
        if (r[i] == WS_DELIM) r[i] = '/';
    }
    WLOG(WS_LOG_SFTP, "Real Path Directory = %s", r);

    /* send response */
    maxSz = WOLFSSH_SFTP_HEADER + (UINT32_SZ * 3) + (rSz * 2);

    WMEMSET(&atr, 0, sizeof(WS_SFTP_FILEATRB));
    maxSz += SFTP_AtributesSz(ssh, &atr);

    out = (byte*)WMALLOC(maxSz, ssh->ctx->heap, DYNTYPE_BUFFER);
    if (out == NULL) {
        return WS_MEMORY_E;
    }

    SFTP_SetHeader(ssh, reqId, WOLFSSH_FTP_NAME,
            maxSz - WOLFSSH_SFTP_HEADER, out);
    idx += WOLFSSH_SFTP_HEADER;

    /* set number of files */
    c32toa(1, out + idx); idx += UINT32_SZ; /* only sending one file name */

    /* set file name size and string */
    c32toa(rSz, out + idx); idx += UINT32_SZ;
    WMEMCPY(out + idx, r, rSz); idx += rSz;

    /* set long name size and string */
    c32toa(rSz, out + idx); idx += UINT32_SZ;
    WMEMCPY(out + idx, r, rSz); idx += rSz;

    /* set attributes */
    SFTP_SetAttributes(ssh, out + idx, maxSz - idx, &atr);

    /* send out buffer */
    if (wolfSSH_stream_send(ssh, out, maxSz) < 0) {
        WFREE(out, ssh->ctx->heap, DYNTYPE_BUFFER);
        return WS_FATAL_ERROR;
    }
    WFREE(out, ssh->ctx->heap, DYNTYPE_BUFFER);

    return WS_SUCCESS;
}


/* Look for incoming packet and handle it
 *
 * returns WS_SUCCESS on success
 */
int wolfSSH_SFTP_read(WOLFSSH* ssh)
{
    int maxSz;
    word32 reqId;
    byte   type = 0;


    /* Wait for packet to come in then handle it, maxSz is the size of packet
     * expected to come. */
    maxSz = SFTP_GetHeader(ssh, &reqId, &type);
    if (maxSz <= 0) {
        return WS_FATAL_ERROR;
    }

    ssh->reqId = reqId;
    switch (type) {
        case WOLFSSH_FTP_REALPATH:
            return wolfSSH_SFTP_RecvRealPath(ssh, reqId, maxSz);

        case WOLFSSH_FTP_RMDIR:
            return wolfSSH_SFTP_RecvRMDIR(ssh, reqId, maxSz);

        case WOLFSSH_FTP_MKDIR:
            return wolfSSH_SFTP_RecvMKDIR(ssh, reqId, maxSz);

        case WOLFSSH_FTP_STAT:
            return wolfSSH_SFTP_RecvSTAT(ssh, reqId, maxSz);

        case WOLFSSH_FTP_LSTAT:
            return wolfSSH_SFTP_RecvLSTAT(ssh, reqId, maxSz);

        case WOLFSSH_FTP_FSTAT:
            return wolfSSH_SFTP_RecvFSTAT(ssh, reqId, maxSz);

        case WOLFSSH_FTP_OPEN:
            return wolfSSH_SFTP_RecvOpen(ssh, reqId, maxSz);

        case WOLFSSH_FTP_READ:
            return wolfSSH_SFTP_RecvRead(ssh, reqId, maxSz);

        case WOLFSSH_FTP_WRITE:
            return wolfSSH_SFTP_RecvWrite(ssh, reqId, maxSz);

        case WOLFSSH_FTP_CLOSE:
            return wolfSSH_SFTP_RecvClose(ssh, reqId, maxSz);

        case WOLFSSH_FTP_REMOVE:
            return wolfSSH_SFTP_RecvRemove(ssh, reqId, maxSz);

        case WOLFSSH_FTP_RENAME:
            return wolfSSH_SFTP_RecvRename(ssh, reqId, maxSz);

        case WOLFSSH_FTP_SETSTAT:
            return wolfSSH_SFTP_RecvSetSTAT(ssh, reqId, maxSz);

    #ifndef NO_WOLFSSH_DIR
        case WOLFSSH_FTP_OPENDIR:
            return wolfSSH_SFTP_RecvOpenDir(ssh, reqId, maxSz);

        case WOLFSSH_FTP_READDIR:
            return wolfSSH_SFTP_RecvReadDir(ssh, reqId, maxSz);
    #endif

        default:
            /* read rest of data off the wire and send error status to client */
            {
                byte* data;
                WLOG(WS_LOG_SFTP, "Unknown packet type [%d] received", type);
                data = (byte*)WMALLOC(maxSz, ssh->ctx->heap, DYNTYPE_BUFFER);
                if (data != NULL) {
                    if (wolfSSH_stream_read(ssh, data, maxSz) != maxSz){
                        WFREE(data, ssh->ctx->heap, DYNTYPE_BUFFER);
                        return WS_FATAL_ERROR;
                    }
                    WFREE(data, ssh->ctx->heap, DYNTYPE_BUFFER);
                }
                wolfSSH_SFTP_SendStatus(ssh, WOLFSSH_FTP_FAILURE, reqId,
                                  "Unknown/Unsupported packet type", "English");
            }
    }

    return WS_SUCCESS;
}


/* send a status packet
 *
 * structure of status packet is as follows
 * {
 *  uint32 error code
 *  string error msg
 *  string language
 * }
 *
 * returns WS_SUCCESS on success
 */
int wolfSSH_SFTP_SendStatus(WOLFSSH* ssh, word32 status, word32 reqId,
        const char* reason, const char* lang)
{
    byte*  buf;
    word32 sz;
    word32 maxSz;
    word32 idx = 0;

    if (ssh == NULL) {
        return WS_BAD_ARGUMENT;
    }

    maxSz = WOLFSSH_SFTP_HEADER + (UINT32_SZ * 3);
    if (reason != NULL) {
        maxSz += (word32)WSTRLEN(reason);
    }
    if (lang != NULL) {
        maxSz += (word32)WSTRLEN(lang);
    }

    buf = (byte*)WMALLOC(maxSz, ssh->ctx->heap, DYNTYPE_BUFFER);
    if (buf == NULL) {
        return WS_MEMORY_E;
    }
    idx += WOLFSSH_SFTP_HEADER;

    if (SFTP_SetHeader(ssh, reqId, WOLFSSH_FTP_STATUS, maxSz - idx, buf)
            != WS_SUCCESS) {
        WFREE(buf, ssh->heap, DYNTYPE_BUFFER);
        return WS_FATAL_ERROR;
    }

    c32toa(status, buf + idx); idx += UINT32_SZ;

    sz = (reason != NULL)? (int)WSTRLEN(reason): 0;
    if (sz + idx + UINT32_SZ > maxSz) {
        WFREE(buf, ssh->heap, DYNTYPE_BUFFER);
        return WS_BUFFER_E;
    }

    c32toa(sz, buf + idx); idx += UINT32_SZ;
    if (reason != NULL) {
        WMEMCPY(buf + idx, reason, sz); idx += sz;
    }


    sz = (lang != NULL)? (int)WSTRLEN(lang): 0;
    if (sz + idx + UINT32_SZ > maxSz) {
        WFREE(buf, ssh->heap, DYNTYPE_BUFFER);
        return WS_BUFFER_E;
    }

    c32toa(sz, buf + idx); idx += UINT32_SZ;
    if (lang != NULL) {
        WMEMCPY(buf + idx, lang, sz);
    }

    if (wolfSSH_stream_send(ssh, buf, maxSz) <= 0) {
        WFREE(buf, ssh->heap, DYNTYPE_BUFFER);
        return WS_FATAL_ERROR;
    }
    WFREE(buf, ssh->heap, DYNTYPE_BUFFER);

    return WS_SUCCESS;
}


/* Handles packet to remove a directory
 *
 * returns WS_SUCCESS on success
 */
int wolfSSH_SFTP_RecvRMDIR(WOLFSSH* ssh, int reqId, word32 maxSz)
{
    word32 sz;
    int    ret;
    byte*  data;
    char*  dir;
    word32 idx = 0;

    if (ssh == NULL) {
        return WS_BAD_ARGUMENT;
    }

    WLOG(WS_LOG_SFTP, "Receiving WOLFSSH_FTP_RMDIR");

    data = (byte*)WMALLOC(maxSz, ssh->ctx->heap, DYNTYPE_BUFFER);
    if (data == NULL) {
        return WS_MEMORY_E;
    }
    ret = wolfSSH_stream_read(ssh, data, maxSz);
    if (ret < 0 || ret != (int)maxSz) {
        WFREE(data, ssh->ctx->heap, DYNTYPE_BUFFER);
        return WS_FATAL_ERROR;
    }

    ato32(data + idx, &sz); idx += UINT32_SZ;
    if (sz + idx > maxSz) {
        WFREE(data, ssh->ctx->heap, DYNTYPE_BUFFER);
        return WS_BUFFER_E;
    }

    /* plus one to make sure is null terminated */
    dir = (char*)WMALLOC(sz + 1, ssh->ctx->heap, DYNTYPE_BUFFER);
    if (dir == NULL) {
        WFREE(data, ssh->ctx->heap, DYNTYPE_BUFFER);
        return WS_MEMORY_E;
    }
    WMEMCPY(dir, data + idx, sz);
    dir[sz] = '\0';

    clean_path(dir);
    ret = WRMDIR(dir);
    WFREE(data, ssh->ctx->heap, DYNTYPE_BUFFER);
    WFREE(dir, ssh->ctx->heap, DYNTYPE_BUFFER);

    if (ret != 0) {
        /* @TODO errno holds reason for rmdir failure. Status sent could be
         * better if using errno value to send reason i.e. permissions .. */
        WLOG(WS_LOG_SFTP, "Error removing directory %s", dir);
        wolfSSH_SFTP_SendStatus(ssh, WOLFSSH_FTP_FAILURE, reqId,
                "Remove Directory Error", "English");
        return WS_BAD_FILE_E;
    }
    else {
        wolfSSH_SFTP_SendStatus(ssh, WOLFSSH_FTP_OK, reqId,
                "Removed Directory", "English");
        return WS_SUCCESS;
    }
}


/* Handles packet to make a directory
 *
 * returns WS_SUCCESS on success
 */
int wolfSSH_SFTP_RecvMKDIR(WOLFSSH* ssh, int reqId, word32 maxSz)
{
    word32 sz;
    int    ret;
    byte*  data;
    char*  dir;
    word32 mode = 0;
    word32 idx = 0;

    if (ssh == NULL) {
        return WS_BAD_ARGUMENT;
    }

    WLOG(WS_LOG_SFTP, "Receiving WOLFSSH_FTP_MKDIR");

    data = (byte*)WMALLOC(maxSz, ssh->ctx->heap, DYNTYPE_BUFFER);
    if (data == NULL) {
        return WS_MEMORY_E;
    }
    wolfSSH_stream_read(ssh, data, maxSz);

    ato32(data + idx, &sz); idx += UINT32_SZ;
    if (sz + idx > maxSz) {
        WFREE(data, ssh->ctx->heap, DYNTYPE_BUFFER);
        return WS_BUFFER_E;
    }

    /* plus one to make sure is null terminated */
    dir = (char*)WMALLOC(sz + 1, ssh->ctx->heap, DYNTYPE_BUFFER);
    if (dir == NULL) {
        WFREE(data, ssh->ctx->heap, DYNTYPE_BUFFER);
        return WS_MEMORY_E;
    }
    WMEMCPY(dir, data + idx, sz);
    dir[sz] = '\0';
    idx += sz;

    ato32(data + idx, &sz); idx += UINT32_SZ;
    if (sz != UINT32_SZ) {
        WLOG(WS_LOG_SFTP, "Attribute size larger than 4 not yet supported");
        WLOG(WS_LOG_SFTP, "Skipping over attribute and using default");
        mode = 0x41ED;
    }
    else {
        ato32(data + idx, &mode);
    }
    clean_path(dir);
    ret = WMKDIR(dir, mode);
    WFREE(data, ssh->ctx->heap, DYNTYPE_BUFFER);
    WFREE(dir, ssh->ctx->heap, DYNTYPE_BUFFER);

    if (ret != 0) {
        WLOG(WS_LOG_SFTP, "Error creating directory %s", dir);
        wolfSSH_SFTP_SendStatus(ssh, WOLFSSH_FTP_FAILURE, reqId,
                "Create Directory Error", "English");
        return WS_BAD_FILE_E;
    }
    else {
        wolfSSH_SFTP_SendStatus(ssh, WOLFSSH_FTP_OK, reqId,
                "Created Directory", "English");
        return WS_SUCCESS;
    }
}


/* Handles packet to open a file
 *
 * returns WS_SUCCESS on success
 */
int wolfSSH_SFTP_RecvOpen(WOLFSSH* ssh, int reqId, word32 maxSz)
{
    WS_SFTP_FILEATRB atr;
    WFD    fd;
    word32 sz;
    byte*  data;
    char*  dir;
    word32 reason;
    word32 idx = 0;
    int m = 0;

    if (ssh == NULL) {
        return WS_BAD_ARGUMENT;
    }

    WLOG(WS_LOG_SFTP, "Receiving WOLFSSH_FTP_OPEN");

    if (sizeof(WFD) > WOLFSSH_MAX_HANDLE) {
        WLOG(WS_LOG_SFTP, "Handle size is too large");
        return WS_FATAL_ERROR;
    }

    data = (byte*)WMALLOC(maxSz, ssh->ctx->heap, DYNTYPE_BUFFER);
    if (data == NULL) {
        return WS_MEMORY_E;
    }
    wolfSSH_stream_read(ssh, data, maxSz);

    ato32(data + idx, &sz); idx += UINT32_SZ;
    if (sz + idx > maxSz) {
        WFREE(data, ssh->ctx->heap, DYNTYPE_BUFFER);
        return WS_BUFFER_E;
    }

    /* plus one to make sure is null terminated */
    dir = (char*)WMALLOC(sz + 1, ssh->ctx->heap, DYNTYPE_BUFFER);
    if (dir == NULL) {
        WFREE(data, ssh->ctx->heap, DYNTYPE_BUFFER);
        return WS_MEMORY_E;
    }
    WMEMCPY(dir, data + idx, sz);
    dir[sz] = '\0';
    idx += sz;

    /* get reason for opening file */
    ato32(data + idx, &reason); idx += UINT32_SZ;


    /* @TODO handle attributes */
    SFTP_ParseAtributes_buffer(ssh, &atr, data + idx, maxSz);

    WFREE(data, ssh->ctx->heap, DYNTYPE_BUFFER);

    if ((reason & WOLFSSH_FXF_READ) && (reason & WOLFSSH_FXF_WRITE)) {
        m |= WOLFSSH_O_RDWR;
    }
    else {
        if (reason & WOLFSSH_FXF_READ) {
            m |= WOLFSSH_O_RDONLY;
        }
        if (reason & WOLFSSH_FXF_WRITE) {
            m |= WOLFSSH_O_WRONLY;
        }
    }

    if (reason & WOLFSSH_FXF_APPEND) {
        m |= WOLFSSH_O_APPEND;
    }
    if (reason & WOLFSSH_FXF_CREAT) {
        m |= WOLFSSH_O_CREAT;
    }
    if (reason & WOLFSSH_FXF_TRUNC) {
        m |= WOLFSSH_O_TRUNC;
    }
    if (reason & WOLFSSH_FXF_EXCL) {
        m |= WOLFSSH_O_EXCL;
    }

    /* if file permissions not set then use default */
    if (!(atr.flags & WOLFSSH_FILEATRB_PERM)) {
        atr.per = 0644;
    }

    clean_path(dir);
    fd = WOPEN(dir, m, atr.per);
    if (fd < 0) {
        WLOG(WS_LOG_SFTP, "Error opening file %s", dir);
        WFREE(dir, ssh->ctx->heap, DYNTYPE_BUFFER);
        wolfSSH_SFTP_SendStatus(ssh, WOLFSSH_FTP_FAILURE, reqId,
                "Open File Error", "English");
        return WS_BAD_FILE_E;
    }

#ifdef WOLFSSH_STOREHANDLE
    if (SFTP_AddHandleNode(ssh, (byte*)&fd, sizeof(WFD), dir) != WS_SUCCESS) {
        WLOG(WS_LOG_SFTP, "Unable to store handle");
        WFREE(dir, ssh->ctx->heap, DYNTYPE_BUFFER);
        wolfSSH_SFTP_SendStatus(ssh, WOLFSSH_FTP_FAILURE, reqId,
                "Internal Failure", "English");
        return WS_FATAL_ERROR;
    }
#endif
    WFREE(dir, ssh->ctx->heap, DYNTYPE_BUFFER);

    SendPacketType(ssh, WOLFSSH_FTP_HANDLE, (byte*)&fd, sizeof(WFD));

    return WS_SUCCESS;
}


#ifndef NO_WOLFSSH_DIR

/* hold pointers to directory handles */
typedef struct DIR_HANDLE {
    WDIR dir;
    char* dirName; /* base name of directory */
    byte isEof;    /* flag for if read everything */
    word64 id;     /* handle ID */
    struct DIR_HANDLE* next;
} DIR_HANDLE;
static DIR_HANDLE* dirList = NULL;
static word64 idCount = 0;
/* @TODO add locking for thread safety */


#ifndef USE_WINDOWS_API

/* Handles packet to open a directory
 *
 * returns WS_SUCCESS on success
 */
int wolfSSH_SFTP_RecvOpenDir(WOLFSSH* ssh, int reqId, word32 maxSz)
{
    WDIR  ctx;
    word32 sz;
    byte*  data;
    char*  dir;
    word32 idx = 0;

    if (ssh == NULL) {
        return WS_BAD_ARGUMENT;
    }

    WLOG(WS_LOG_SFTP, "Receiving WOLFSSH_FTP_OPENDIR");

    if (sizeof(WFD) > WOLFSSH_MAX_HANDLE) {
        WLOG(WS_LOG_SFTP, "Handle size is too large");
        return WS_FATAL_ERROR;
    }

    data = (byte*)WMALLOC(maxSz, ssh->ctx->heap, DYNTYPE_BUFFER);
    if (data == NULL) {
        return WS_MEMORY_E;
    }
    wolfSSH_stream_read(ssh, data, maxSz);

    /* get directory name */
    ato32(data + idx, &sz); idx += UINT32_SZ;
    if (sz + idx > maxSz) {
        WFREE(data, ssh->ctx->heap, DYNTYPE_BUFFER);
        return WS_BUFFER_E;
    }

    /* plus one to make sure is null terminated */
    dir = (char*)WMALLOC(sz + 1, ssh->ctx->heap, DYNTYPE_BUFFER);
    if (dir == NULL) {
        WFREE(data, ssh->ctx->heap, DYNTYPE_BUFFER);
        return WS_MEMORY_E;
    }
    WMEMCPY(dir, data + idx, sz);
    dir[sz] = '\0';
    WFREE(data, ssh->ctx->heap, DYNTYPE_BUFFER);

    /* get directory handle */
    clean_path(dir);
    if (WOPENDIR(&ctx, dir) != 0) {
        WLOG(WS_LOG_SFTP, "Error with opening directory");
        WFREE(dir, ssh->ctx->heap, DYNTYPE_BUFFER);

        wolfSSH_SFTP_SendStatus(ssh, WOLFSSH_FTP_NOFILE, reqId,
                "Unable To Open Directory", "English");
        return WS_BAD_FILE_E;
    }

    (void)reqId;

    /* add to directory list @TODO locking for thread safety */
    if (dirList == NULL) {
        dirList = (DIR_HANDLE*)WMALLOC(sizeof(DIR_HANDLE), ssh->ctx->heap,
                DYNTYPE_SFTP);
        if (dirList == NULL) {
            WFREE(dir, ssh->ctx->heap, DYNTYPE_BUFFER);
            WCLOSEDIR(&ctx);
            return WS_MEMORY_E;
        }
#ifdef WOLFSSL_NUCLEUS
        WMEMCPY(&dirList->dir, &ctx, sizeof(WDIR));
#else
        dirList->dir  = ctx;
#endif
        dirList->id    = idCount++;
        dirList->isEof = 0;
        dirList->next  = NULL;
        dirList->dirName = dir; /* take over ownership of buffer */
        SendPacketType(ssh, WOLFSSH_FTP_HANDLE, (byte*)&dirList->id,
                sizeof(word64));
    }
    else {
        DIR_HANDLE* cur = (DIR_HANDLE*)WMALLOC(sizeof(DIR_HANDLE),
                ssh->ctx->heap, DYNTYPE_SFTP);
        if (cur == NULL) {
            WFREE(dir, ssh->ctx->heap, DYNTYPE_BUFFER);
			WCLOSEDIR(&ctx);
            return WS_MEMORY_E;
        }
#ifdef WOLFSSL_NUCLEUS
        WMEMCPY(&cur->dir, &ctx, sizeof(WDIR));
#else
        cur->dir  = ctx;
#endif
        cur->id    = idCount++;
        cur->isEof = 0;
        cur->next  = dirList;
        dirList    = cur;
        dirList->dirName = dir; /* take over ownership of buffer */
        SendPacketType(ssh, WOLFSSH_FTP_HANDLE, (byte*)&cur->id,
                sizeof(word64));
    }

    return WS_SUCCESS;
}

#else /* USE_WINDOWS_API */

/* Handles packet to open a directory
 *
 * returns WS_SUCCESS on success
 */
int wolfSSH_SFTP_RecvOpenDir(WOLFSSH* ssh, int reqId, word32 maxSz)
{
    word32 sz;
    byte* data;
    char* dirName;
    word32 idx = 0;
    HANDLE findHandle;
    WIN32_FIND_DATAA findData;

    if (ssh == NULL) {
        return WS_BAD_ARGUMENT;
    }

    WLOG(WS_LOG_SFTP, "Receiving WOLFSSH_FTP_OPENDIR");

    data = (byte*)WMALLOC(maxSz, ssh->ctx->heap, DYNTYPE_BUFFER);
    if (data == NULL) {
        return WS_MEMORY_E;
    }
    wolfSSH_stream_read(ssh, data, maxSz);

    /* get directory name */
    ato32(data + idx, &sz);
    idx += UINT32_SZ;
    if (sz + idx > maxSz) {
        WFREE(data, ssh->ctx->heap, DYNTYPE_BUFFER);
        return WS_BUFFER_E;
    }

    /* plus one to make sure is null terminated */
    dirName = (char*)WMALLOC(sz + 1, ssh->ctx->heap, DYNTYPE_BUFFER);
    if (dirName == NULL) {
        WFREE(data, ssh->ctx->heap, DYNTYPE_BUFFER);
        return WS_MEMORY_E;
    }
    WMEMCPY(dirName, data + idx, sz);
    dirName[sz] = '\0';
    WFREE(data, ssh->ctx->heap, DYNTYPE_BUFFER);

    clean_path(dirName);

    /* get directory handle */
    findHandle = FindFirstFileA(dirName, &findData);
    if (findHandle == INVALID_HANDLE_VALUE ||
        !(findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {

        WLOG(WS_LOG_SFTP, "Error with opening directory");
        WFREE(dirName, ssh->ctx->heap, DYNTYPE_BUFFER);

        wolfSSH_SFTP_SendStatus(ssh, WOLFSSH_FTP_NOFILE, reqId,
                "Unable To Open Directory", "English");
        if (findHandle != INVALID_HANDLE_VALUE)
            FindClose(findHandle);
        return WS_BAD_FILE_E;
    }
    FindClose(findHandle);

    /* add to directory list @TODO locking for thread safety */
    {
        DIR_HANDLE* cur = (DIR_HANDLE*)WMALLOC(sizeof(DIR_HANDLE),
                ssh->ctx->heap, DYNTYPE_SFTP);
        if (cur == NULL) {
            WFREE(dirName, ssh->ctx->heap, DYNTYPE_BUFFER);
            return WS_MEMORY_E;
        }
        cur->dir = INVALID_HANDLE_VALUE;
        cur->id = idCount++;
        cur->isEof = 0;
        cur->dirName = dirName; /* take over ownership of buffer */
        cur->next = dirList;
        dirList = cur;
        SendPacketType(ssh, WOLFSSH_FTP_HANDLE, (byte*)&cur->id,
                sizeof(word64));
    }

    return WS_SUCCESS;
}

#endif

#ifdef WOLFSSL_NUCLEUS
/* For Nucleus port
 * helper function that gets file information from reading directory
 * @TODO allow user to override
 *
 * returns WS_SUCCESS on success
 */
static int wolfSSH_SFTPNAME_readdir(WOLFSSH* ssh, WDIR* dir, WS_SFTPNAME* out,
        char* dirName)
{
    int sz;
    byte special = 0;
    int ret = WS_SUCCESS;

    if (dir == NULL || ssh == NULL || out == NULL) {
        return WS_BAD_ARGUMENT;
    }

    /* special case of getting drives at "/" */
    if (WSTRLEN(dirName) < 3 && dirName[0] == WS_DELIM) {
        unsigned int idx = dir->fsize; /* index of current drive */
        MNT_LIST_S* list = NU_NULL;

        if (NU_List_Mount(&list) != NU_SUCCESS) {
            return WS_FATAL_ERROR;
        }

        for (; idx > 0 && list != NU_NULL; idx--) list = list->next;
        if (list == NULL) {
            return WS_FATAL_ERROR;
        }

        if (list->next == NULL) {
            ret = WS_NEXT_ERROR;
        }

        dir->lfname[0] =  list->mnt_name[0];
        dir->lfname[1] =  ':';
        dir->lfname[2] =  '/';
        dir->lfname[3] =  '\0';
        dir->fsize++;
        special = 1;
    }

    /* use long name on Nucleus because sfname has only the file name and in all
     * caps */
    sz = (int)WSTRLEN(dir->lfname);
    out->fName = (char*)WMALLOC(sz + 1, out->heap, DYNTYPE_SFTP);
    if (out->fName == NULL) {
        return WS_MEMORY_E;
    }
    WMEMCPY(out->fName, dir->lfname, sz);
    out->fName[sz] = '\0';
    out->fSz = sz;

    sz = (int)WSTRLEN(dir->lfname);
    out->lName = (char*)WMALLOC(sz + 1, out->heap, DYNTYPE_SFTP);
    if (out ->lName == NULL) {
        return WS_MEMORY_E;
    }
    WMEMCPY(out->lName, dir->lfname, sz);
    out->lName[sz] = '\0';
    out->lSz = sz;

    {
        char* buf;
        int   bufSz;
        int   tmpSz;

        bufSz = out->fSz + WSTRLEN(dirName) + sizeof(WS_DELIM);
        buf = (char*)WMALLOC(bufSz + 1, out->heap, DYNTYPE_SFTP);
        if (buf == NULL) {
            return WS_MEMORY_E;
        }
        buf[0] = '\0';
        if (!special) { /* do not add dir name in special case */
            WSTRNCAT(buf, dirName, bufSz + 1);
            tmpSz = WSTRLEN(buf);

            /* add delimiter between path and file/dir name */
            if (tmpSz + 1 < bufSz) {
                buf[tmpSz] = WS_DELIM;
                buf[tmpSz+1] = '\0';
            }

        }
        WSTRNCAT(buf, out->fName, bufSz + 1);

        clean_path(buf);
        if (SFTP_GetAttributes(buf, &out->atrb, 0) != WS_SUCCESS) {
            WLOG(WS_LOG_SFTP, "Unable to get attribute values for %s", buf);
        }
        WFREE(buf, out->heap, DYNTYPE_SFTP);
    }

    if (!special && (WREADDIR(dir)) == NULL) {
        ret = WS_NEXT_ERROR;
    }

    return ret;
}
#elif defined(USE_WINDOWS_API)

/* helper function that gets file information from reading directory
* @TODO allow user to override
*
* returns WS_SUCCESS on success
*/
static int wolfSSH_SFTPNAME_readdir(WOLFSSH* ssh, WDIR* dir, WS_SFTPNAME* out,
        char* dirName)
{
    int sz;
    HANDLE findHandle;
    WIN32_FIND_DATAA findData;

    if (dir == NULL || ssh == NULL || out == NULL) {
        return WS_BAD_ARGUMENT;
    }

    if (*dir == INVALID_HANDLE_VALUE) {
        char name[MAX_PATH];
        word32 nameLen = (word32)WSTRLEN(dirName);

        if (nameLen > MAX_PATH - 3) {
            WLOG(WS_LOG_DEBUG, "Path name is too long.");
            return WS_FATAL_ERROR;
        }
        WSTRNCPY(name, dirName, MAX_PATH);
        WSTRNCAT(name, "\\*", MAX_PATH);

        findHandle = FindFirstFileA(name, &findData);

        if (findHandle == INVALID_HANDLE_VALUE)
            return WS_FATAL_ERROR;
        else
            *dir = findHandle;
    }
    else {
        findHandle = *dir;
        if (FindNextFileA(findHandle, &findData) != 0)
            return WS_FATAL_ERROR;
    }

    sz = (int)WSTRLEN(findData.cFileName);
    out->fName = (char*)WMALLOC(sz + 1, out->heap, DYNTYPE_SFTP);
    if (out->fName == NULL) {
        return WS_MEMORY_E;
    }
    out->lName = (char*)WMALLOC(sz + 1, out->heap, DYNTYPE_SFTP);
    if (out->lName == NULL) {
        WFREE(out->fName, out->heap, DYNTYPE_SFTP);
        return WS_MEMORY_E;
    }

    WMEMCPY(out->fName, findData.cFileName, sz);
    WMEMCPY(out->lName, findData.cFileName, sz);
    out->fName[sz] = '\0';
    out->lName[sz] = '\0';
    out->fSz = sz;
    out->lSz = sz;

    /* attempt to get file attributes. Could be directory or have none */
    {
        char* buf;
        int   bufSz;
        int   tmpSz;

        bufSz = out->fSz + (int)WSTRLEN(dirName) + sizeof(WS_DELIM);
        buf = (char*)WMALLOC(bufSz + 1, out->heap, DYNTYPE_SFTP);
        if (buf == NULL) {
            return WS_MEMORY_E;
        }
        buf[0] = '\0';
        WSTRNCAT(buf, dirName, bufSz + 1);
        tmpSz = (int)WSTRLEN(buf);

        /* add delimiter between path and file/dir name */
        if (tmpSz + 1 < bufSz) {
            buf[tmpSz] = WS_DELIM;
            buf[tmpSz + 1] = '\0';
        }
        WSTRNCAT(buf, out->fName, bufSz + 1);

        clean_path(buf);
        if (SFTP_GetAttributes(buf, &out->atrb, 0) != WS_SUCCESS) {
            WLOG(WS_LOG_SFTP, "Unable to get attribute values for %s",
                out->fName);
        }
        WFREE(buf, out->heap, DYNTYPE_SFTP);
    }

    return WS_SUCCESS;
}

#else
/* helper function that gets file information from reading directory
 * @TODO allow user to override
 *
 * returns WS_SUCCESS on success
 */
static int wolfSSH_SFTPNAME_readdir(WOLFSSH* ssh, WDIR* dir, WS_SFTPNAME* out,
        char* dirName)
{
    struct dirent* dp;
    int sz;

    if (dir == NULL || ssh == NULL || out == NULL) {
        return WS_BAD_ARGUMENT;
    }

    dp = WREADDIR(dir);
    if (dp == NULL) {
        return WS_FATAL_ERROR;
    }

    sz = (int)WSTRLEN(dp->d_name);
    out->fName = (char*)WMALLOC(sz + 1, out->heap, DYNTYPE_SFTP);
    if (out->fName == NULL) {
        return WS_MEMORY_E;
    }
    out->lName = (char*)WMALLOC(sz + 1, out->heap, DYNTYPE_SFTP);
    if (out ->lName == NULL) {
        WFREE(out->fName, out->heap, DYNTYPE_SFTP);
        return WS_MEMORY_E;
    }

    WMEMCPY(out->fName, dp->d_name, sz);
    WMEMCPY(out->lName, dp->d_name, sz);
    out->fName[sz] = '\0';
    out->lName[sz] = '\0';
    out->fSz = sz;
    out->lSz = sz;

    /* attempt to get file attributes. Could be directory or have none */
    {
        char* buf;
        int   bufSz;
        int   tmpSz;

        bufSz = out->fSz + (int)WSTRLEN(dirName) + sizeof(WS_DELIM);
        buf = (char*)WMALLOC(bufSz + 1, out->heap, DYNTYPE_SFTP);
        if (buf == NULL) {
            return WS_MEMORY_E;
        }
        buf[0] = '\0';
        WSTRNCAT(buf, dirName, bufSz + 1);
        tmpSz = (int)WSTRLEN(buf);

        /* add delimiter between path and file/dir name */
        if (tmpSz + 1 < bufSz) {
            buf[tmpSz] = WS_DELIM;
            buf[tmpSz+1] = '\0';
        }
        WSTRNCAT(buf, out->fName, bufSz + 1);

        clean_path(buf);
        if (SFTP_GetAttributes(buf, &out->atrb, 0) != WS_SUCCESS) {
            WLOG(WS_LOG_SFTP, "Unable to get attribute values for %s",
                    out->fName);
        }
        WFREE(buf, out->heap, DYNTYPE_SFTP);
    }

    return WS_SUCCESS;
}
#endif


/* helper function to create a name packet. out buffer will have the following
 * format on success
 *
 * [ SFTP header ] [ count ] [ file [ name | long name | attribs ] ].
 *
 * outSz gets set to the size of resulting buffer
 * returns WS_SUCCESS on success
 */
static int wolfSSH_SFTP_SendName(WOLFSSH* ssh, WS_SFTPNAME* list, word32 count,
        byte* out, word32* outSz, int reqId)
{
    WS_SFTPNAME* cur = list;
    word32 i, idx = 0;

    if (out == NULL || outSz == NULL || ssh == NULL || list == NULL) {
        return WS_BAD_ARGUMENT;
    }

    if (*outSz < WOLFSSH_SFTP_HEADER + UINT32_SZ) {
        return WS_BUFFER_E;
    }

    if (SFTP_SetHeader(ssh, reqId, WOLFSSH_FTP_NAME,
                *outSz - WOLFSSH_SFTP_HEADER, out) != WS_SUCCESS) {
        return WS_BUFFER_E;
    }
    idx += WOLFSSH_SFTP_HEADER;

    c32toa(count, out + idx); idx += UINT32_SZ;

    for (i = 0; i < count && cur != NULL; i++) {
        if (*outSz - idx < cur->fSz + cur->lSz + UINT32_SZ * 2) {
            /* not enough space for the buffer */
            return WS_FATAL_ERROR;
        }

        c32toa(cur->fSz, out + idx); idx += UINT32_SZ;
        WMEMCPY(out + idx, cur->fName, cur->fSz); idx += cur->fSz;
        c32toa(cur->lSz, out + idx); idx += UINT32_SZ;
        WMEMCPY(out + idx, cur->lName, cur->lSz); idx += cur->lSz;
        if (SFTP_SetAttributes(ssh, out + idx, *outSz - idx, &cur->atrb) !=
                WS_SUCCESS) {
            return WS_FATAL_ERROR;
        }
        idx += SFTP_AtributesSz(ssh, &cur->atrb);
        cur = cur->next;
    }

    *outSz = idx;

    return WS_SUCCESS;
}


/* Handles packet to read a directory
 *
 * returns WS_SUCCESS on success
 */
int wolfSSH_SFTP_RecvReadDir(WOLFSSH* ssh, int reqId, word32 maxSz)
{
    WDIR   dir;
    word64 handle = 0;
    word32 sz;
    byte*  data;
    word32 idx = 0;
    int count = 0;
    int ret;
    WS_SFTPNAME* name = NULL;
    WS_SFTPNAME* list = NULL;
    word32 outSz = 0;
    DIR_HANDLE* cur = dirList;
    char* dirName = NULL;

    if (ssh == NULL) {
        return WS_BAD_ARGUMENT;
    }

    WLOG(WS_LOG_SFTP, "Receiving WOLFSSH_FTP_READDIR");

    #ifdef USE_WINDOWS_API
        dir = INVALID_HANDLE_VALUE;
    #endif

    data = (byte*)WMALLOC(maxSz, ssh->ctx->heap, DYNTYPE_BUFFER);
    if (data == NULL) {
        return WS_MEMORY_E;
    }
    wolfSSH_stream_read(ssh, data, maxSz);

    /* get directory handle */
    ato32(data + idx, &sz); idx += UINT32_SZ;
    if (sz + idx > maxSz || sz > WOLFSSH_MAX_HANDLE) {
        WFREE(data, ssh->ctx->heap, DYNTYPE_BUFFER);
        return WS_BUFFER_E;
    }
    WMEMCPY((byte*)&handle, data + idx, sz);

    /* find DIR given handle */
    while (cur != NULL) {
        if (cur->id == handle) {
            dir = cur->dir;
            dirName = cur->dirName;
            break;
        }
        cur = cur->next;
    }
    if (cur == NULL) {
        /* unable to find handle */
        return WS_FATAL_ERROR;
    }

    /* this closes the directory before returning */
    //wc_ReadDirFirst(&ctx, dir, NULL);

    /* get directory information */
    outSz += UINT32_SZ + WOLFSSH_SFTP_HEADER; /* hold header+number of files */
    do {
        name = wolfSSH_SFTPNAME_new(ssh->ctx->heap);
        ret = wolfSSH_SFTPNAME_readdir(ssh, &dir, name, dirName);
        if (ret == WS_SUCCESS || ret == WS_NEXT_ERROR) {
            count++;
            outSz += name->fSz + name->lSz + (UINT32_SZ * 2);
            outSz += SFTP_AtributesSz(ssh, &name->atrb);
            name->next = list;
            list = name;
        }
        else {
            wolfSSH_SFTPNAME_free(name);
        }
    } while (ret == WS_SUCCESS);

    WFREE(data, ssh->ctx->heap, DYNTYPE_BUFFER);
    if (list == NULL || cur->isEof) {
        wolfSSH_SFTP_SendStatus(ssh, WOLFSSH_FTP_EOF, reqId,
                "No More Files In Directory", "English");
        return WS_SUCCESS;
    }

    /* if next state would cause an error then set EOF flag for when called
     * again */
    if (ret == WS_NEXT_ERROR) {
        cur->isEof = 1;
    }

    data = (byte*)WMALLOC(outSz, ssh->ctx->heap, DYNTYPE_BUFFER);
    if (data == NULL) {
        return WS_MEMORY_E;
    }

    if (wolfSSH_SFTP_SendName(ssh, list, count, data, &outSz, reqId)
            != WS_SUCCESS) {
        WFREE(data, ssh->ctx->heap, DYNTYPE_BUFFER);
        return WS_FATAL_ERROR;
    }
    wolfSSH_SFTPNAME_list_free(list);

    idx = 0;
    while (idx < outSz) {
        if ((ret = wolfSSH_stream_send(ssh, data + idx, outSz - idx)) < 0) {
            WFREE(data, ssh->ctx->heap, DYNTYPE_BUFFER);
            return ret;
        }
        idx += ret;
    }
    WFREE(data, ssh->ctx->heap, DYNTYPE_BUFFER);

    return WS_SUCCESS;
}


/* Handles packet to close a directory
 *
 * returns 0 on success
 */
int wolfSSH_SFTP_RecvCloseDir(WOLFSSH* ssh, byte* handle, word32 handleSz)
{
    DIR_HANDLE* cur = dirList;

    if (ssh == NULL || handle == NULL || handleSz != sizeof(word64)) {
        return WS_BAD_ARGUMENT;
    }

    WLOG(WS_LOG_SFTP, "Receiving WOLFSSH_FTP_CLOSE Directory");

    /* find DIR given handle */
    while (cur != NULL) {
        if (cur->id == *((word64*)handle)) {
            break;
        }
        cur = cur->next;
    }
    if (cur == NULL) {
        /* unable to find handle */
        return WS_FATAL_ERROR;
    }

#ifdef USE_WINDOWS_API
    FindClose(cur->dir);
#else
    WCLOSEDIR(&cur->dir);
#endif

    /* remove directory from list */
    if (cur != NULL) {
        DIR_HANDLE* pre = dirList;

        WLOG(WS_LOG_SFTP, "Free'ing and closing handle %ld pointer of [%p]",
                (long)cur->id, cur);
        /* case where node is at head of list */
        if (pre == cur) {
            dirList = cur->next;
            WFREE(cur->dirName, ssh->ctx->heap, DYNTYPE_SFTP);
            WFREE(cur, ssh->ctx->heap, DYNTYPE_SFTP);
        }
        else {
            while (pre->next != NULL && pre->next != cur) pre = pre->next;
            if (pre->next != cur) {
                /* error case where current handle is not in list? */
                return WS_FATAL_ERROR;
            }
            else {
                pre->next = cur->next;
                WFREE(cur->dirName, ssh->ctx->heap, DYNTYPE_SFTP);
                WFREE(cur, ssh->ctx->heap, DYNTYPE_SFTP);
            }
        }
    }

    return WS_SUCCESS;
}
#endif /* NO_WOLFSSH_DIR */

/* Handles packet to write a file
 *
 * returns WS_SUCCESS on success
 */
int wolfSSH_SFTP_RecvWrite(WOLFSSH* ssh, int reqId, word32 maxSz)
{
    WFD    fd;
    word32 sz;
    int    ret;
    byte*  data;
    word32 idx  = 0;
    word64 ofst = 0;

    if (ssh == NULL) {
        return WS_BAD_ARGUMENT;
    }

    WLOG(WS_LOG_SFTP, "Receiving WOLFSSH_FTP_WRITE");

    data = (byte*)WMALLOC(maxSz, ssh->ctx->heap, DYNTYPE_BUFFER);
    if (data == NULL) {
        return WS_MEMORY_E;
    }

    sz = 0;
    do {
        ret = wolfSSH_stream_read(ssh, data + sz, maxSz - sz);
        if (ret > 0) {
            sz += ret;
        }
    } while (sz < maxSz && ret > 0);
    if (ret < 0) {
        WFREE(data, ssh->ctx->heap, DYNTYPE_BUFFER);
        return ret;
    }

    /* get file handle */
    ato32(data + idx, &sz); idx += UINT32_SZ;
    if (sz + idx > maxSz || sz > WOLFSSH_MAX_HANDLE) {
        WLOG(WS_LOG_SFTP, "Error with file handle size");
        WFREE(data, ssh->ctx->heap, DYNTYPE_BUFFER);
        wolfSSH_SFTP_SendStatus(ssh, WOLFSSH_FTP_FAILURE, reqId,
                "Write File Error", "English");
        return WS_BAD_FILE_E;
    }
    WMEMSET((byte*)&fd, 0, sizeof(WFD));
    WMEMCPY((byte*)&fd, data + idx, sz); idx += sz;

    /* get offset into file */
    ato32(data + idx, &sz); idx += UINT32_SZ;
    ofst = (word64)sz << 32 & 0xFFFFFFFF00000000;
    ato32(data + idx, &sz); idx += UINT32_SZ;
    ofst |= (word64)sz & 0xFFFFFFFF;

    /* get length to be written */
    ato32(data + idx, &sz); idx += UINT32_SZ;

    ret = (int)WPWRITE(fd, data + idx, sz, (long)ofst);
    WFREE(data, ssh->ctx->heap, DYNTYPE_BUFFER);
    if (ret < 0) {
#if defined(WOLFSSL_NUCLEUS) && defined(DEBUG_WOLFSSH)
        if (ret == NUF_NOSPC) {
            WLOG(WS_LOG_SFTP, "Ran out of memory");
        }
#endif
        WLOG(WS_LOG_SFTP, "Error writing to file");
        wolfSSH_SFTP_SendStatus(ssh, WOLFSSH_FTP_FAILURE, reqId,
                "Write File Error", "English");
        return WS_INVALID_STATE_E;
    }

    wolfSSH_SFTP_SendStatus(ssh, WOLFSSH_FTP_OK, reqId,
                "Write File Success", "English");
    return WS_SUCCESS;
}


/* Handles packet to read a file
 *
 * returns WS_SUCCESS on success
 */
int wolfSSH_SFTP_RecvRead(WOLFSSH* ssh, int reqId, word32 maxSz)
{
    WFD    fd;
    word32 sz;
    int    ret;
    byte*  data;
    word32 idx  = 0;
    word64 ofst = 0;

    if (ssh == NULL) {
        return WS_BAD_ARGUMENT;
    }

    WLOG(WS_LOG_SFTP, "Receiving WOLFSSH_FTP_READ");

    data = (byte*)WMALLOC(maxSz, ssh->ctx->heap, DYNTYPE_BUFFER);
    if (data == NULL) {
        return WS_MEMORY_E;
    }
    if ((ret = wolfSSH_stream_read(ssh, data, maxSz)) < 0) {
        WFREE(data, ssh->ctx->heap, DYNTYPE_BUFFER);
        return ret;
    }

    /* get file handle */
    ato32(data + idx, &sz); idx += UINT32_SZ;
    if (sz + idx > maxSz || sz > WOLFSSH_MAX_HANDLE) {
        WFREE(data, ssh->ctx->heap, DYNTYPE_BUFFER);
        return WS_BUFFER_E;
    }
    WMEMSET((byte*)&fd, 0, sizeof(WFD));
    WMEMCPY((byte*)&fd, data + idx, sz); idx += sz;

    /* get offset into file */
    ato32(data + idx, &sz); idx += UINT32_SZ;
    ofst = (word64)sz << 32 & 0xFFFFFFFF00000000;
    ato32(data + idx, &sz); idx += UINT32_SZ;
    ofst |= (word64)sz & 0xFFFFFFFF;

    /* get length to be read */
    ato32(data + idx, &sz);
    WFREE(data, ssh->ctx->heap, DYNTYPE_BUFFER);


    /* read from handle and send data back to client */
    data = (byte*)WMALLOC(sz, ssh->ctx->heap, DYNTYPE_BUFFER);
    if (data == NULL) {
        return WS_MEMORY_E;
    }

    ret = (int)WPREAD(fd, data, sz, (long)ofst);
    if (ret < 0) {
        WLOG(WS_LOG_SFTP, "Error reading from file");
        WFREE(data, ssh->ctx->heap, DYNTYPE_BUFFER);
        wolfSSH_SFTP_SendStatus(ssh, WOLFSSH_FTP_FAILURE, reqId,
                "Read File Error", "English");
        return WS_BAD_FILE_E;
    }

    /* eof */
    if (ret == 0) {
        WLOG(WS_LOG_SFTP, "Error reading from file");
        WFREE(data, ssh->ctx->heap, DYNTYPE_BUFFER);
        wolfSSH_SFTP_SendStatus(ssh, WOLFSSH_FTP_EOF, reqId,
                "Read EOF", "English");
        return WS_SUCCESS; /* end of file is not fatal error */
    }

    SendPacketType(ssh, WOLFSSH_FTP_DATA, data, ret);
    WFREE(data, ssh->ctx->heap, DYNTYPE_BUFFER);

    return WS_SUCCESS;
}


/* Handles packet to close a file
 *
 * returns WS_SUCCESS on success
 */
int wolfSSH_SFTP_RecvClose(WOLFSSH* ssh, int reqId, word32 maxSz)
{
    WFD    fd;
    word32 sz;
    byte*  data;
    word32 idx  = 0;
    int    ret;

    if (ssh == NULL) {
        return WS_BAD_ARGUMENT;
    }

    WLOG(WS_LOG_SFTP, "Receiving WOLFSSH_FTP_CLOSE");

    data = (byte*)WMALLOC(maxSz, ssh->ctx->heap, DYNTYPE_BUFFER);
    if (data == NULL) {
        return WS_MEMORY_E;
    }
    if ((ret = wolfSSH_stream_read(ssh, data, maxSz)) < 0) {
        WFREE(data, ssh->ctx->heap, DYNTYPE_BUFFER);
        return ret;
    }

    /* get file handle */
    ato32(data + idx, &sz); idx += UINT32_SZ;
    if (sz + idx > maxSz || sz > WOLFSSH_MAX_HANDLE) {
        WFREE(data, ssh->ctx->heap, DYNTYPE_BUFFER);
        return WS_BUFFER_E;
    }

#ifndef NO_WOLFSSH_DIR
    /* check if is a handle for a directory */
    if (sz == sizeof(word64)) {
        ret = wolfSSH_SFTP_RecvCloseDir(ssh, data + idx, sz);
    }
    else
#endif /* NO_WOLFSSH_DIR */
    if (sz == sizeof(WFD)) {
        WMEMSET((byte*)&fd, 0, sizeof(WFD));
        WMEMCPY((byte*)&fd, data + idx, sz);
        ret = WCLOSE(fd);
    #ifdef WOLFSSH_STOREHANDLE
        if (SFTP_RemoveHandleNode(ssh, data + idx, sz) != WS_SUCCESS) {
            WLOG(WS_LOG_SFTP, "Unable to remove handle from list");
            ret = WS_FATAL_ERROR;
        }
    #endif
    }
    else {
        ret = WS_FATAL_ERROR;
    }
    WFREE(data, ssh->ctx->heap, DYNTYPE_BUFFER);

    if (ret < 0) {
        WLOG(WS_LOG_SFTP, "Error closing file");
        wolfSSH_SFTP_SendStatus(ssh, WOLFSSH_FTP_FAILURE, reqId,
                "Close File Error", "English");
        return WS_BAD_FILE_E;
    }
    else {
        wolfSSH_SFTP_SendStatus(ssh, WOLFSSH_FTP_OK, reqId,
                "Closed File", "English");
    }

    return WS_SUCCESS;
}



/* Handles packet to remove a file
 *
 * returns WS_SUCCESS on success
 */
int wolfSSH_SFTP_RecvRemove(WOLFSSH* ssh, int reqId, word32 maxSz)
{
    word32 sz;
    byte*  data;
    char*  name;
    word32 idx = 0;
    int    ret = WS_SUCCESS;

    if (ssh == NULL) {
        return WS_BAD_ARGUMENT;
    }

    WLOG(WS_LOG_SFTP, "Receiving WOLFSSH_FTP_REMOVE");

    data = (byte*)WMALLOC(maxSz, ssh->ctx->heap, DYNTYPE_BUFFER);
    if (data == NULL) {
        return WS_MEMORY_E;
    }
    if ((ret = wolfSSH_stream_read(ssh, data, maxSz)) < 0) {
        WFREE(data, ssh->ctx->heap, DYNTYPE_BUFFER);
        return ret;
    }

    /* get file name */
    ato32(data + idx, &sz); idx += UINT32_SZ;
    if (sz + idx > maxSz || sz > WOLFSSH_MAX_HANDLE) {
        WFREE(data, ssh->ctx->heap, DYNTYPE_BUFFER);
        return WS_BUFFER_E;
    }
    name = (char*)WMALLOC(sz + 1, ssh->ctx->heap, DYNTYPE_BUFFER);
    if (name == NULL) {
        WFREE(data, ssh->ctx->heap, DYNTYPE_BUFFER);
        return WS_MEMORY_E;
    }
    WMEMCPY(name, data + idx, sz);
    name[sz] = '\0';
    WFREE(data, ssh->ctx->heap, DYNTYPE_BUFFER);

    clean_path(name);
    if ((ret = WREMOVE(name)) < 0) {
        WLOG(WS_LOG_SFTP, "Error removing file");
    #if defined(WOLFSSL_NUCLEUS) && defined(DEBUG_WOLFSSH)
        if (ret == NUF_ACCES)
            WLOG(WS_LOG_SFTP, "access error");
        if (ret == NUF_BAD_USER)
            WLOG(WS_LOG_SFTP, "bad user");
        if (ret == NUF_IO_ERROR)
            WLOG(WS_LOG_SFTP, "io error");
        if (ret == NUF_NOFILE)
            WLOG(WS_LOG_SFTP, "%s file not found", name);
    #endif
        ret = WS_BAD_FILE_E;
    }
    else {
        ret = WS_SUCCESS;
    }

    /* Let the client know the results from trying to remove the file */
    WFREE(name, ssh->ctx->heap, DYNTYPE_BUFFER);
    if (ret != WS_SUCCESS) {
        wolfSSH_SFTP_SendStatus(ssh, WOLFSSH_FTP_FAILURE, reqId,
                "Remove File Error", "English");
    }
    else {
        wolfSSH_SFTP_SendStatus(ssh, WOLFSSH_FTP_OK, reqId,
                "Removed File", "English");
    }

    return ret;
}


/* Handles packet to rename a file
 *
 * returns WS_SUCCESS on success
 */
int wolfSSH_SFTP_RecvRename(WOLFSSH* ssh, int reqId, word32 maxSz)
{
    word32 sz = 0;
    byte*  data;
    char*  old;
    char*  nw;
    word32 idx = 0;
    int    ret = WS_SUCCESS;

    if (ssh == NULL) {
        return WS_BAD_ARGUMENT;
    }

    WLOG(WS_LOG_SFTP, "Receiving WOLFSSH_FTP_RENAME");

    data = (byte*)WMALLOC(maxSz, ssh->ctx->heap, DYNTYPE_BUFFER);
    if (data == NULL) {
        return WS_MEMORY_E;
    }

    /* @TODO for now trying to read all of expected data */
    while (ret == WS_SUCCESS && sz < maxSz) {
        ret = wolfSSH_stream_read(ssh, data + sz, maxSz - sz);
        if (ret > 0) {
            sz += ret;
            ret = WS_SUCCESS;
        }
    }

    /* get old file name */
    ato32(data + idx, &sz); idx += UINT32_SZ;
    if (sz + idx > maxSz) {
        ret = WS_BUFFER_E;
    }
    old = (char*)WMALLOC(sz + 1, ssh->ctx->heap, DYNTYPE_BUFFER);
    if (old == NULL) {
        ret = WS_MEMORY_E;
    }
    if (ret == WS_SUCCESS) {
        WMEMCPY(old, data + idx, sz); idx += sz;
        old[sz] = '\0';
    }

    /* get new file name */
    ato32(data + idx, &sz); idx += UINT32_SZ;
    if (sz + idx > maxSz) {
        ret = WS_BUFFER_E;
    }
    nw = (char*)WMALLOC(sz + 1, ssh->ctx->heap, DYNTYPE_BUFFER);
    if (nw == NULL) {
        ret = WS_MEMORY_E;
    }
    if (ret == WS_SUCCESS) {
        WMEMCPY(nw, data + idx, sz);
        nw[sz] = '\0';
    }
    WFREE(data, ssh->ctx->heap, DYNTYPE_BUFFER);

    clean_path(old);
    clean_path(nw);
    if (ret == WS_SUCCESS && WRENAME(old, nw) < 0) {
        WLOG(WS_LOG_SFTP, "Error renaming file");
        ret = WS_BAD_FILE_E;
    }

    /* Let the client know the results from trying to rename the file */
    WFREE(old, ssh->ctx->heap, DYNTYPE_BUFFER);
    WFREE(nw, ssh->ctx->heap, DYNTYPE_BUFFER);
    if (ret != WS_SUCCESS) {
        wolfSSH_SFTP_SendStatus(ssh, WOLFSSH_FTP_FAILURE, reqId,
                "Rename File Error", "English");
    }
    else {
        wolfSSH_SFTP_SendStatus(ssh, WOLFSSH_FTP_OK, reqId,
                "Renamed File", "English");
    }

    return ret;
}


#ifdef WOLFSSH_STOREHANDLE
/* some systems do not have a fstat function to allow for attribute lookup given
 * a file descriptor. In those cases we keep track of an internal list matching
 * handles to file names */

struct WS_HANDLE_LIST {
    byte handle[WOLFSSH_MAX_HANDLE];
    word32 handleSz;
    char name[WOLFSSH_MAX_FILENAME];
    struct WS_HANDLE_LIST* next;
    struct WS_HANDLE_LIST* prev;
};


/* get a handle node from the list
 * returns WS_HANDLE_LIST pointer on success and NULL on failure */
static WS_HANDLE_LIST* SFTP_GetHandleNode(WOLFSSH* ssh, byte* handle,
        word32 handleSz)
{
    WS_HANDLE_LIST* cur = ssh->handleList;

    if (handle == NULL) {
        return NULL;
    }

    /* for Nucleus need to find name from handle */
    while (cur != NULL) {
        if(handleSz == cur->handleSz && WMEMCMP(handle, cur->handle, handleSz) == 0) {
            break; /* found handle */
        }
        cur = cur->next;
    }

    return cur;
}


/* add a name and handle to the handle list
 * return WS_SUCCESS on success */
int SFTP_AddHandleNode(WOLFSSH* ssh, byte* handle, word32 handleSz, char* name)
{
    WS_HANDLE_LIST* cur;
    int sz;

    if (handle == NULL || name == NULL) {
        return WS_BAD_ARGUMENT;
    }

    cur = (WS_HANDLE_LIST*)WMALLOC(sizeof(WS_HANDLE_LIST), ssh->ctx->heap,
            DYNTYPE_SFTP);
    if (cur == NULL) {
        return WS_MEMORY_E;
    }

    WMEMCPY(cur->handle, handle, handleSz);
    cur->handleSz = handleSz;

    sz = (int)WSTRLEN(name);
    if (sz + 1 >= WOLFSSH_MAX_FILENAME) {
        WFREE(cur, ssh->ctx->heap, DYNTYPE_SFTP);
        return WS_BUFFER_E;
    }
    WMEMCPY(cur->name, name, sz);
    cur->name[sz] = '\0';

    cur->prev = NULL;
    cur->next = ssh->handleList;
    if (ssh->handleList != NULL) {
         ssh->handleList->prev = cur;
    }
    ssh->handleList = cur;

    return WS_SUCCESS;
}


/* remove a handle node from the list
 * returns WS_SUCCESS on success */
int SFTP_RemoveHandleNode(WOLFSSH* ssh, byte* handle, word32 handleSz)
{
    WS_HANDLE_LIST* cur;

    if (ssh == NULL || handle == NULL) {
        return WS_BAD_ARGUMENT;
    }

    cur = SFTP_GetHandleNode(ssh, handle, handleSz);
    if (cur == NULL) {
        WLOG(WS_LOG_SFTP, "Fatal Error! Trying to remove a handle that was not in the list");
        return WS_FATAL_ERROR;
    }

    if (cur->next != NULL) {
        cur->next->prev = cur->prev;
    }

    if (cur->prev != NULL) {
        cur->prev->next = cur->next;
    }

    if (cur->next == NULL && cur->prev == NULL) {
        ssh->handleList = NULL;
    }

    WFREE(cur, ssh->ctx->heap, DYNTYPE_SFTP);

    return WS_SUCCESS;
}
#endif /* WOLFSSH_STOREHANDLE */


#ifdef WOLFSSL_NUCLEUS

#ifndef NO_WOLFSSH_MKTIME

#define WS_GETDAY(d) ((d) & 0x001f)
#define WS_GETMON(d) (((d) >> 5) & 0x000f)
/* number of years since 1900. year + 1980 - 1900 */
#define WS_GETYEAR(d) ((((d) >> 9) & 0x007f) + 80)
#define WS_GETHOUR(t) (((t) >> 11) & 0x001f)
#define WS_GETMIN(t)  (((t) >> 5 ) & 0x003f)
#define WS_GETSEC(t)  (((t) << 1 ) & 0x003f)

/* convert nucleus date and time shorts to word32
 * returns results in Unix time stamp */
static word32 TimeTo32(word16 d, word16 t)
{
    struct tm tmp = {0};

    tmp.tm_mday = WS_GETDAY(d);
    tmp.tm_mon  = WS_GETMON(d);
    tmp.tm_year = WS_GETYEAR(d);
    tmp.tm_hour = WS_GETHOUR(t);
    tmp.tm_min  = WS_GETMIN(t);
    tmp.tm_sec  = WS_GETSEC(t);

    return mktime(&tmp);
}
#endif /* NO_WOLFSSH_MKTIME */


/* @TODO can be overriden by user for portability
 * NOTE: if atr->flags is set to a value of 0 then no attributes are set.
 * Fills out a WS_SFTP_FILEATRB structure
 * returns WS_SUCCESS on success
 */
int SFTP_GetAttributes(const char* fileName, WS_SFTP_FILEATRB* atr, byte link)
{
    DSTAT stats;
    int sz = (int)WSTRLEN(fileName);
    int ret;

    if (link) {
        ret = WLSTAT(fileName, &stats);
    }
    else {
        ret = WSTAT(fileName, &stats);
    }

    WMEMSET(atr, 0, sizeof(WS_SFTP_FILEATRB));
    if (sz > 2 && fileName[sz - 2] == ':' && ret == NUF_NOFILE) {
        atr->flags |= WOLFSSH_FILEATRB_PERM;
        atr->per |= 0x4000;
        return WS_SUCCESS;
    }

    /* handle case of "/" */
    if (sz < 3 && fileName[0] == WS_DELIM && ret == NUF_NOFILE) {
        atr->flags |= WOLFSSH_FILEATRB_PERM;
        atr->per |= 0x4000;
        return WS_SUCCESS;
    }

    if (ret != NU_SUCCESS) {
        return WS_BAD_FILE_E;
    }

    atr->flags |= WOLFSSH_FILEATRB_SIZE;
    atr->sz     = (word64)stats.fsize;

    /* get additional attributes */
    {
        byte atrib = stats.fattribute;
        atr->flags |= WOLFSSH_FILEATRB_PERM;
        if (atrib & ADIRENT) {
            atr->per |= 0x41ED; /* 755 with directory */
        }
        else {
            atr->per |= 0x8000;
        }
        if ((atrib & 0x01) == ANORMAL) {
            atr->per |= 0x1ED; /* octal 755 */
        }
        if (atrib & ARDONLY) {
            atr->per |= 0x124; /* octal 444 */
        }
    }

#ifndef NO_WOLFSSH_MKTIME
    /* get file times */
    atr->flags |= WOLFSSH_FILEATRB_TIME;
    atr->atime = TimeTo32(stats.faccdate, 0); /* only access date */
    atr->mtime = TimeTo32(stats.fupdate, stats.fuptime);
#endif /* NO_WOLFSSH_MKTIME */

    /* @TODO handle attribute extensions */

    NU_Done(&stats);
    return WS_SUCCESS;
}


/* @TODO can be overriden by user for portability
 * Gets attributes based on file descriptor
 * NOTE: if atr->flags is set to a value of 0 then no attributes are set.
 * Fills out a WS_SFTP_FILEATRB structure
 * returns WS_SUCCESS on success
 */
int SFTP_GetAttributes_Handle(WOLFSSH* ssh, byte* handle, int handleSz,
        WS_SFTP_FILEATRB* atr)
{
    DSTAT stats;
    WS_HANDLE_LIST* cur;

    if (handle == NULL || atr == NULL) {
        return WS_FATAL_ERROR;
    }

    cur = SFTP_GetHandleNode(ssh, handle, handleSz);
    if (cur == NULL) {
        WLOG(WS_LOG_SFTP, "Unknown handle");
        return WS_BAD_FILE_E;
    }

    if (WSTAT(cur->name, &stats) != NU_SUCCESS) {
        return WS_FATAL_ERROR;
    }

    WMEMSET(atr, 0, sizeof(WS_SFTP_FILEATRB));

    atr->flags |= WOLFSSH_FILEATRB_SIZE;
    atr->sz     = (word64)stats.fsize;

    {
        byte atrib = stats.fattribute;
        atr->flags |= WOLFSSH_FILEATRB_PERM;
        if (atrib & ADIRENT) {
            atr->per |= 0x41ED; /* 755 with directory */
        }
        else {
            atr->per |= 0x8000;
        }
        if ((atrib & 0x01) == ANORMAL) {
            atr->per |= 0x1ED; /* octal 755 */
        }
        if (atrib & ARDONLY) {
            atr->per |= 0x124; /* octal 444 */
        }
    }

#ifndef NO_WOLFSSH_MKTIME
    /* get file times */
    atr->flags |= WOLFSSH_FILEATRB_TIME;
    atr->atime = TimeTo32(stats.faccdate, 0); /* only access date */
    atr->mtime = TimeTo32(stats.fupdate, stats.fuptime);
#endif /* NO_WOLFSSH_MKTIME */

    /* @TODO handle attribute extensions */

    NU_Done(&stats);
    return WS_SUCCESS;
}
#else

/* @TODO can be overriden by user for portability
 * NOTE: if atr->flags is set to a value of 0 then no attributes are set.
 * Fills out a WS_SFTP_FILEATRB structure
 * returns WS_SUCCESS on success
 */
int SFTP_GetAttributes(const char* fileName, WS_SFTP_FILEATRB* atr, byte link)
{
    WSTAT_T stats;

    if (link) {
        /* Note, for windows, we treat WSTAT and WLSTAT the same. */
        if (WLSTAT(fileName, &stats) != 0) {
            return WS_BAD_FILE_E;
        }
    }
    else {
        if (WSTAT(fileName, &stats) != 0) {
            return WS_BAD_FILE_E;
        }
    }

    WMEMSET(atr, 0, sizeof(WS_SFTP_FILEATRB));

    atr->flags |= WOLFSSH_FILEATRB_SIZE;
    atr->sz     = (word64)stats.st_size;

    atr->flags |= WOLFSSH_FILEATRB_UIDGID;
    atr->uid = (word32)stats.st_uid;
    atr->gid = (word32)stats.st_gid;

    atr->flags |= WOLFSSH_FILEATRB_PERM;
    atr->per = (word32)stats.st_mode;

    atr->flags |= WOLFSSH_FILEATRB_TIME;
    atr->atime = (word32)stats.st_atime;
    atr->mtime = (word32)stats.st_mtime;

    /* @TODO handle attribute extensions */

    return WS_SUCCESS;
}


/* @TODO can be overriden by user for portability
 * Gets attributes based on file descriptor
 * NOTE: if atr->flags is set to a value of 0 then no attributes are set.
 * Fills out a WS_SFTP_FILEATRB structure
 * returns WS_SUCCESS on success
 */
int SFTP_GetAttributes_Handle(WOLFSSH* ssh, byte* handle, int handleSz,
        WS_SFTP_FILEATRB* atr)
{
    struct stat stats;

    if (handleSz != sizeof(word32)) {
        WLOG(WS_LOG_SFTP, "Unexpected handle size SFTP_GetAttributes_Handle()");
    }

    if (fstat(*(int*)handle, &stats) != 0) {
            return WS_BAD_FILE_E;
    }

    WMEMSET(atr, 0, sizeof(WS_SFTP_FILEATRB));

    atr->flags |= WOLFSSH_FILEATRB_SIZE;
    atr->sz     = (word64)stats.st_size;

    atr->flags |= WOLFSSH_FILEATRB_UIDGID;
    atr->uid = (word32)stats.st_uid;
    atr->gid = (word32)stats.st_gid;

    atr->flags |= WOLFSSH_FILEATRB_PERM;
    atr->per = (word32)stats.st_mode;

    atr->flags |= WOLFSSH_FILEATRB_TIME;
    atr->atime = (word32)stats.st_atime;
    atr->mtime = (word32)stats.st_mtime;

    /* @TODO handle attribute extensions */

    (void)ssh;
    return WS_SUCCESS;
}
#endif


/* Handles receiving fstat packet
 * returns WS_SUCCESS on success
 */
int wolfSSH_SFTP_RecvFSTAT(WOLFSSH* ssh, int reqId, word32 maxSz)
{
    WS_SFTP_FILEATRB atr;
    word32 handleSz;
    word32 sz;
    byte*  data;
    byte*  handle;
    word32 idx = 0;

    if (ssh == NULL) {
        return WS_BAD_ARGUMENT;
    }

    WLOG(WS_LOG_SFTP, "Receiving WOLFSSH_FTP_FSTAT");

    data = (byte*)WMALLOC(maxSz, ssh->ctx->heap, DYNTYPE_BUFFER);
    if (data == NULL) {
        return WS_MEMORY_E;
    }
    wolfSSH_stream_read(ssh, data, maxSz);

    ato32(data + idx, &handleSz); idx += UINT32_SZ;
    if (handleSz + idx > maxSz) {
        WFREE(data, ssh->ctx->heap, DYNTYPE_BUFFER);
        return WS_BUFFER_E;
    }
    handle = data + idx;

    /* try to get file attributes and send back to client */
    WMEMSET((byte*)&atr, 0, sizeof(WS_SFTP_FILEATRB));
    if (SFTP_GetAttributes_Handle(ssh, handle, handleSz, &atr) != WS_SUCCESS) {
        WFREE(data, ssh->ctx->heap, DYNTYPE_BUFFER);
        WLOG(WS_LOG_SFTP, "Unable to get fstat of file/directory");
        wolfSSH_SFTP_SendStatus(ssh, WOLFSSH_FTP_FAILURE, reqId,
                "STAT error", "English");
        return WS_BAD_FILE_E;
    }
    WFREE(data, ssh->ctx->heap, DYNTYPE_BUFFER);

    sz = SFTP_AtributesSz(ssh, &atr);
    data = (byte*)WMALLOC(sz + WOLFSSH_SFTP_HEADER, ssh->ctx->heap,
            DYNTYPE_BUFFER);
    if (data == NULL) {
        return WS_MEMORY_E;
    }

    if (SFTP_SetHeader(ssh, reqId, WOLFSSH_FTP_ATTRS, sz, data) != WS_SUCCESS) {
        WFREE(data, ssh->ctx->heap, DYNTYPE_BUFFER);
        return WS_FATAL_ERROR;
    }
    SFTP_SetAttributes(ssh, data + WOLFSSH_SFTP_HEADER, sz, &atr);
    if (wolfSSH_stream_send(ssh, data, sz + WOLFSSH_SFTP_HEADER) < 0) {
        WFREE(data, ssh->ctx->heap, DYNTYPE_BUFFER);
        return WS_FATAL_ERROR;
    }
    WFREE(data, ssh->ctx->heap, DYNTYPE_BUFFER);

    return WS_SUCCESS;
}


/* Handles receiving stat packet
 * returns WS_SUCCESS on success
 */
int wolfSSH_SFTP_RecvSTAT(WOLFSSH* ssh, int reqId, word32 maxSz)
{
    WS_SFTP_FILEATRB atr;
    char* name = NULL;
    int   ret;

    word32 sz;
    byte*  data;
    word32 idx = 0;

    if (ssh == NULL) {
        return WS_BAD_ARGUMENT;
    }

    WLOG(WS_LOG_SFTP, "Receiving WOLFSSH_FTP_STAT");

    data = (byte*)WMALLOC(maxSz, ssh->ctx->heap, DYNTYPE_BUFFER);
    if (data == NULL) {
        return WS_MEMORY_E;
    }
    ret = wolfSSH_stream_read(ssh, data, maxSz);
    if (ret < 0 || ret != (int)maxSz) {
        WFREE(data, ssh->ctx->heap, DYNTYPE_BUFFER);
        return WS_FATAL_ERROR;
    }

    ato32(data + idx, &sz); idx += UINT32_SZ;
    if (sz + idx > maxSz) {
        WFREE(data, ssh->ctx->heap, DYNTYPE_BUFFER);
        return WS_BUFFER_E;
    }

    /* plus one to make sure is null terminated */
    name = (char*)WMALLOC(sz + 1, ssh->ctx->heap, DYNTYPE_BUFFER);
    if (name == NULL) {
        WFREE(data, ssh->ctx->heap, DYNTYPE_BUFFER);
        return WS_MEMORY_E;
    }
    WMEMCPY(name, data + idx, sz);
    name[sz] = '\0';
    WFREE(data, ssh->ctx->heap, DYNTYPE_BUFFER);

    /* try to get file attributes and send back to client */
    clean_path(name);
    WMEMSET((byte*)&atr, 0, sizeof(WS_SFTP_FILEATRB));
    if (SFTP_GetAttributes(name, &atr, 0) != WS_SUCCESS) {
        WFREE(name, ssh->ctx->heap, DYNTYPE_BUFFER);
        WLOG(WS_LOG_SFTP, "Unable to get stat of file/directory");
        wolfSSH_SFTP_SendStatus(ssh, WOLFSSH_FTP_FAILURE, reqId,
                "STAT error", "English");
        return WS_BAD_FILE_E;
    }
    WFREE(name, ssh->ctx->heap, DYNTYPE_BUFFER);

    sz = SFTP_AtributesSz(ssh, &atr);
    data = (byte*)WMALLOC(sz + WOLFSSH_SFTP_HEADER, ssh->ctx->heap,
            DYNTYPE_BUFFER);
    if (data == NULL) {
        return WS_MEMORY_E;
    }

    if (SFTP_SetHeader(ssh, reqId, WOLFSSH_FTP_ATTRS, sz, data) != WS_SUCCESS) {
        WFREE(data, ssh->ctx->heap, DYNTYPE_BUFFER);
        return WS_FATAL_ERROR;
    }
    SFTP_SetAttributes(ssh, data + WOLFSSH_SFTP_HEADER, sz, &atr);
    if (wolfSSH_stream_send(ssh, data, sz + WOLFSSH_SFTP_HEADER) < 0) {
        WFREE(data, ssh->ctx->heap, DYNTYPE_BUFFER);
        return WS_FATAL_ERROR;
    }
    WFREE(data, ssh->ctx->heap, DYNTYPE_BUFFER);

    return WS_SUCCESS;
}


/* Handles receiving lstat packet
 * returns WS_SUCCESS on success
 */
int wolfSSH_SFTP_RecvLSTAT(WOLFSSH* ssh, int reqId, word32 maxSz)
{
    WS_SFTP_FILEATRB atr;
    char* name = NULL;
    int   ret;

    word32 sz;
    byte*  data;
    word32 idx = 0;

    if (ssh == NULL) {
        return WS_BAD_ARGUMENT;
    }

    WLOG(WS_LOG_SFTP, "Receiving WOLFSSH_FTP_LSTAT");

    data = (byte*)WMALLOC(maxSz, ssh->ctx->heap, DYNTYPE_BUFFER);
    if (data == NULL) {
        return WS_MEMORY_E;
    }
    if (wolfSSH_stream_read(ssh, data, maxSz) < 0) {
        WFREE(data, ssh->ctx->heap, DYNTYPE_BUFFER);
        return WS_FATAL_ERROR;
    }

    ato32(data + idx, &sz); idx += UINT32_SZ;
    if (sz + idx > maxSz) {
        WFREE(data, ssh->ctx->heap, DYNTYPE_BUFFER);
        return WS_BUFFER_E;
    }

    /* plus one to make sure is null terminated */
    name = (char*)WMALLOC(sz + 1, ssh->ctx->heap, DYNTYPE_BUFFER);
    if (name == NULL) {
        WFREE(data, ssh->ctx->heap, DYNTYPE_BUFFER);
        return WS_MEMORY_E;
    }
    WMEMCPY(name, data + idx, sz);
    name[sz] = '\0';
    WFREE(data, ssh->ctx->heap, DYNTYPE_BUFFER);
    clean_path(name);

    /* try to get file attributes and send back to client */
    WMEMSET((byte*)&atr, 0, sizeof(WS_SFTP_FILEATRB));
    if ((ret = SFTP_GetAttributes(name, &atr, 1)) != WS_SUCCESS) {
        WFREE(name, ssh->ctx->heap, DYNTYPE_BUFFER);

        /* tell peer that was not ok */
        WLOG(WS_LOG_SFTP, "Unable to get lstat of file/directory");
        wolfSSH_SFTP_SendStatus(ssh, WOLFSSH_FTP_FAILURE, reqId,
                "LSTAT error", "English");
        return WS_BAD_FILE_E;
    }
    WFREE(name, ssh->ctx->heap, DYNTYPE_BUFFER);

    sz = SFTP_AtributesSz(ssh, &atr);
    data = (byte*)WMALLOC(sz + WOLFSSH_SFTP_HEADER, ssh->ctx->heap,
            DYNTYPE_BUFFER);
    if (data == NULL) {
        return WS_MEMORY_E;
    }

    if (SFTP_SetHeader(ssh, reqId, WOLFSSH_FTP_ATTRS, sz, data) != WS_SUCCESS) {
        WFREE(data, ssh->ctx->heap, DYNTYPE_BUFFER);
        return WS_FATAL_ERROR;
    }
    SFTP_SetAttributes(ssh, data + WOLFSSH_SFTP_HEADER, sz, &atr);
    if (wolfSSH_stream_send(ssh, data, sz + WOLFSSH_SFTP_HEADER) < 0) {
        WFREE(data, ssh->ctx->heap, DYNTYPE_BUFFER);
        return WS_FATAL_ERROR;
    }
    WFREE(data, ssh->ctx->heap, DYNTYPE_BUFFER);

    return WS_SUCCESS;
}


/* Set the files mode
 * return WS_SUCCESS on success */
static int SFTP_SetMode(WOLFSSH* ssh, char* name, word32 mode) {
    (void)ssh;
    if (WCHMOD(name, mode) != 0) {
        return WS_BAD_FILE_E;
    }
    return WS_SUCCESS;
}


/* sets a files attributes
 * returns WS_SUCCESS on success */
static int SFTP_SetFileAttributes(WOLFSSH* ssh, char* name, WS_SFTP_FILEATRB* atr)
{
    int ret = WS_SUCCESS;

    /* check if size attribute present */
    if (atr->flags & WOLFSSH_FILEATRB_SIZE) {
        /* @TODO set file size */
    }

    /* check if uid and gid attribute present */
    if (atr->flags & WOLFSSH_FILEATRB_UIDGID) {
        /* @TODO set group and user id */
    }

    /* check if permissions attribute present */
    if (atr->flags & WOLFSSH_FILEATRB_PERM) {
        ret = SFTP_SetMode(ssh, name, atr->per);
    }

    /* check if time attribute present */
    if (atr->flags & WOLFSSH_FILEATRB_TIME) {
        /* @TODO set time */
    }

    /* check if extended attributes are present */
    if (atr->flags & WOLFSSH_FILEATRB_EXT) {
        /* @TODO handle extensions */
    }

    (void)ssh;
    return ret ;
}


/* Handles a packet sent to set attributes of path
 *
 * returns WS_SUCCESS on success
 */
int wolfSSH_SFTP_RecvSetSTAT(WOLFSSH* ssh, int reqId, word32 maxSz)
{
    WS_SFTP_FILEATRB atr;
    char* name = NULL;
    int   ret;

    word32 sz;
    byte*  data;
    word32 idx = 0;

    if (ssh == NULL) {
        return WS_BAD_ARGUMENT;
    }

    WLOG(WS_LOG_SFTP, "Receiving WOLFSSH_FTP_SETSTAT");

    data = (byte*)WMALLOC(maxSz, ssh->ctx->heap, DYNTYPE_BUFFER);
    if (data == NULL) {
        return WS_MEMORY_E;
    }
    if (wolfSSH_stream_read(ssh, data, maxSz) < 0) {
        WFREE(data, ssh->ctx->heap, DYNTYPE_BUFFER);
        return WS_FATAL_ERROR;
    }

    ato32(data + idx, &sz); idx += UINT32_SZ;
    if (sz + idx > maxSz) {
        WFREE(data, ssh->ctx->heap, DYNTYPE_BUFFER);
        return WS_BUFFER_E;
    }

    /* plus one to make sure is null terminated */
    name = (char*)WMALLOC(sz + 1, ssh->ctx->heap, DYNTYPE_BUFFER);
    if (name == NULL) {
        WFREE(data, ssh->ctx->heap, DYNTYPE_BUFFER);
        return WS_MEMORY_E;
    }
    WMEMCPY(name, data + idx, sz); idx += sz;
    name[sz] = '\0';
    clean_path(name);

    if (SFTP_ParseAtributes_buffer(ssh, &atr, data + idx, maxSz - idx) != 0) {
        wolfSSH_SFTP_SendStatus(ssh, WOLFSSH_FTP_FAILURE, reqId,
                "Unable to parse attributes error", "English");
        return WS_BAD_FILE_E;
    }
    WFREE(data, ssh->ctx->heap, DYNTYPE_BUFFER);

    /* try to set file attributes and send status back to client */
    if ((ret = SFTP_SetFileAttributes(ssh, name, &atr))
            != WS_SUCCESS) {
        WFREE(name, ssh->ctx->heap, DYNTYPE_BUFFER);

        /* tell peer that was not ok */
        WLOG(WS_LOG_SFTP, "Unable to get set attributes of file/directory");
        wolfSSH_SFTP_SendStatus(ssh, WOLFSSH_FTP_FAILURE, reqId,
                "Unable to set attributes error", "English");
        return WS_BAD_FILE_E;
    }
    WFREE(name, ssh->ctx->heap, DYNTYPE_BUFFER);

    wolfSSH_SFTP_SendStatus(ssh, WOLFSSH_FTP_OK, reqId, "Set Attirbutes",
            "English");

    return WS_SUCCESS;
}
#endif /* !NO_WOLFSSH_SERVER */


#ifndef NO_WOLFSSH_CLIENT

/* unique from other packets because the request ID is not also sent.
 *
 * returns WS_SUCCESS on success
 */
static int SFTP_ClientRecvInit(WOLFSSH* ssh) {
    int  len;
    byte id;
    word32 sz = 0;
    word32 version = 0;
    byte buf[LENGTH_SZ + MSG_ID_SZ + UINT32_SZ];

    switch (ssh->sftpState) {
        case SFTP_RECV:
            if ((len = wolfSSH_stream_read(ssh, buf, sizeof(buf)))
                    != sizeof(buf)) {
                /* @TODO partial read on small packet */
                return len;
            }

            ato32(buf, &sz);
            if (sz < MSG_ID_SZ + UINT32_SZ) {
                return WS_BUFFER_E;
            }

            /* expecting */
            id = buf[LENGTH_SZ];
            if (id != WOLFSSH_FTP_VERSION) {
                WLOG(WS_LOG_SFTP, "Unexpected SFTP type received");
                return WS_BUFFER_E;
            }

            ato32(buf + LENGTH_SZ + MSG_ID_SZ, &version);
            sz = sz - MSG_ID_SZ - UINT32_SZ;
            ssh->sftpExtSz = sz;
            ssh->sftpState = SFTP_EXT;
            FALL_THROUGH;
            /* no break */

        case SFTP_EXT:
            /* silently ignore extensions if not supported */
            if (ssh->sftpExtSz > 0) {
                byte* data = (byte*)WMALLOC(ssh->sftpExtSz, ssh->ctx->heap,
                        DYNTYPE_BUFFER);
                if (data ==  NULL) return WS_MEMORY_E;
                if ((len = wolfSSH_stream_read(ssh, data, ssh->sftpExtSz))
                        <= 0) {
                    WFREE(data, ssh->ctx->heap, DYNTYPE_BUFFER);
                    return len;
                }
                WFREE(data, ssh->ctx->heap, DYNTYPE_BUFFER);

                /* case where expecting more */
                if (len < ssh->sftpExtSz) {
                    ssh->sftpExtSz -= len;
                    ssh->error = WS_WANT_READ;
                    return WS_FATAL_ERROR;
                }
            }
            break;

        default:
            WLOG(WS_LOG_SFTP, "Unexpected SFTP connect state");
            return WS_FATAL_ERROR;

    }

    ssh->reqId++;
    return WS_SUCCESS;
}


/* unique from SendPacketType because the request ID is not also sent.
 *
 * returns WS_SUCCESS on success
 */
static int SFTP_ClientSendInit(WOLFSSH* ssh) {
    int  ret;
    byte buf[LENGTH_SZ + MSG_ID_SZ + UINT32_SZ];

    c32toa(MSG_ID_SZ + UINT32_SZ, buf);
    buf[LENGTH_SZ] = WOLFSSH_FTP_INIT;

    /* version */
    c32toa((word32)WOLFSSH_SFTP_VERSION, buf + LENGTH_SZ + MSG_ID_SZ);
    if ((ret = wolfSSH_stream_send(ssh, buf, sizeof(buf))) != sizeof(buf)) {
        return ret;
    }

    return WS_SUCCESS;
}


/* Completes SFTP connection to server
 * returns WS_SUCCESS on success
 */
int wolfSSH_SFTP_connect(WOLFSSH* ssh)
{
    int ret = WS_SUCCESS;

    if (ssh == NULL) {
        return WS_BAD_ARGUMENT;
    }

    if (ssh->error == WS_WANT_READ || ssh->error == WS_WANT_WRITE)
        ssh->error = WS_SUCCESS;

    /* check connect is done, if not call wolfSSH connect */
    if (ssh->connectState < CONNECT_SERVER_CHANNEL_REQUEST_DONE) {
        byte name[] = "sftp";

        WLOG(WS_LOG_SFTP, "Trying to do SSH connect first");
        if ((ret = wolfSSH_SetChannelType(ssh, WOLFSSH_SESSION_SUBSYSTEM,
                            name, sizeof(name) - 1)) != WS_SUCCESS) {
            WLOG(WS_LOG_SFTP, "Unable to set subsystem channel type");
            return ret;
        }

        if ((ret = wolfSSH_connect(ssh)) != WS_SUCCESS) {
            return ret;
        }
    }

    switch (ssh->sftpState) {
        case SFTP_BEGIN:
            if ((ssh->error = SFTP_ClientSendInit(ssh)) != WS_SUCCESS) {
                return WS_FATAL_ERROR;
            }
            ssh->sftpState = SFTP_RECV;
            FALL_THROUGH;
            /* no break */

        case SFTP_RECV:
        case SFTP_EXT:
            if ((ssh->error = SFTP_ClientRecvInit(ssh)) != WS_SUCCESS) {
                return WS_FATAL_ERROR;
            }
            ssh->sftpState = SFTP_DONE;
            WLOG(WS_LOG_SFTP, "SFTP connection established");
            break;

        default:
            ret = WS_FATAL_ERROR;
    }

    return ret;
}
#endif /* NO_WOLFSSH_CLIENT */


/* Tries to do SFTP accept or connect based on server/client side
 * returns WS_SUCCESS on success
 */
int wolfSSH_SFTP_negotiate(WOLFSSH* ssh)
{
    int ret = WS_FATAL_ERROR;

    if (ssh == NULL) {
        return WS_BAD_ARGUMENT;
    }

#ifndef NO_WOLFSSH_SERVER
    if (ssh->ctx->side == WOLFSSH_ENDPOINT_SERVER) {
        WLOG(WS_LOG_SFTP, "Trying to do SSH accept first");
        ret = wolfSSH_SFTP_accept(ssh);
    }
#endif

#ifndef NO_WOLFSSH_CLIENT
    if (ssh->ctx->side == WOLFSSH_ENDPOINT_CLIENT) {
        ret = wolfSSH_SFTP_connect(ssh);
    }
#endif

    return ret;
}


/* Sends generic packet structure for packets that only have one field in type
 * specific data.
 * [ packet header ] [ size ] [ type specific data (buf) ]
 *
 * type  is the type of packet to send
 * buf   holds the type specific data
 * bufSz is amount of type specific data
 *
 * returns WS_SUCCESS on success
 */
int SendPacketType(WOLFSSH* ssh, byte type, byte* buf, word32 bufSz)
{
    int ret = WS_SUCCESS;
    word32 idx;
    word32 sent = 0;

    if (ssh == NULL || buf == NULL) {
        return WS_BAD_ARGUMENT;
    }

    if (ssh->sftpState != SFTP_DONE) {
        WLOG(WS_LOG_SFTP, "SFTP connection not complete, trying to finish");
        ret = wolfSSH_SFTP_negotiate(ssh);
    }

    if (ret == WS_SUCCESS) {
        byte* data = (byte*)WMALLOC(bufSz + WOLFSSH_SFTP_HEADER +
                UINT32_SZ, NULL, DYNTYPE_BUFFER);
        if (data == NULL) {
            return WS_MEMORY_E;
        }

        if (SFTP_SetHeader(ssh, ssh->reqId, type, bufSz + UINT32_SZ, data)
                != WS_SUCCESS) {
            WFREE(data, NULL, DYNTYPE_BUFFER);
            return WS_FATAL_ERROR;
        }

        idx = WOLFSSH_SFTP_HEADER;
        c32toa(bufSz, data + idx);       idx += UINT32_SZ;
        WMEMCPY(data + idx, buf, bufSz); idx += bufSz;

        /* send header and type specific data, looping over send because
         * channel could have restrictions on how much data can be sent at
         * one time */
        do {
            ret = wolfSSH_stream_send(ssh, data + sent, idx - sent);
            wolfSSH_CheckReceivePending(ssh); /* check for adjust window packet */
            sent += (word32)ret;
        } while (ret > 0 && sent < idx);

        if (ret > 0) {
            ret = WS_SUCCESS;
        }
        WFREE(data, NULL, DYNTYPE_BUFFER);
    }

    return ret;
}


/* process a status packet
 *
 * assuming that request ID has already been read
 *
 * structure of status packet is as follows
 * {
 *  uint32 error code
 *  string error msg
 *  string language
 * }
 *
 * returns error code, i.e. WOLFSSH_FTP_OK, WOLFSSH_FTP_EOF ...
 */
static int wolfSSH_SFTP_DoStatus(WOLFSSH* ssh, word32 reqId)
{
    byte   buf[UINT32_SZ];
    int    ret;
    word32 sz;
    word32 status = WOLFSSH_FTP_FAILURE;
    (void)reqId;

    ret = wolfSSH_stream_read(ssh, buf, UINT32_SZ);
    if (ret != UINT32_SZ) {
        return WS_FATAL_ERROR;
    }
    ato32(buf, &status);

    /* read error message */
    ret = wolfSSH_stream_read(ssh, buf, UINT32_SZ);
    if (ret != UINT32_SZ) {
        return WS_FATAL_ERROR;
    }
    ato32(buf, &sz);

    if (sz > 0) {
        byte* s = (byte*)WMALLOC(sz + 1, ssh->ctx->heap, DYNTYPE_BUFFER);
        if (s == NULL) {
            return WS_MEMORY_E;
        }

        ret = wolfSSH_stream_read(ssh, s, sz);
        if (ret < 0) {
            WFREE(s, ssh->ctx->heap, DYNTYPE_BUFFER);
            return ret;
        }

        s[sz] = '\0';
        WLOG(WS_LOG_SFTP, "Status Recv : %s", s);
        WFREE(s, ssh->ctx->heap, DYNTYPE_BUFFER);
    }

    /* read language tag */
    ret = wolfSSH_stream_read(ssh, buf, UINT32_SZ);
    if (ret != UINT32_SZ) {
        return WS_FATAL_ERROR;
    }
    ato32(buf, &sz);

    if (sz > 0) {
        byte* s = (byte*)WMALLOC(sz + 1, ssh->ctx->heap, DYNTYPE_BUFFER);
        if (s == NULL) {
            return WS_MEMORY_E;
        }

        ret = wolfSSH_stream_read(ssh, s, sz);
        if (ret < 0) {
            WFREE(s, ssh->ctx->heap, DYNTYPE_BUFFER);
            return ret;
        }

        s[sz] = '\0';
        WLOG(WS_LOG_SFTP, "Status Language : %s", s);
        WFREE(s, ssh->ctx->heap, DYNTYPE_BUFFER);
    }
    return status;
}


/* create a new initialized sftp name structure
 * returns a new structure on success and null on fail */
WS_SFTPNAME* wolfSSH_SFTPNAME_new(void* heap)
{
    WS_SFTPNAME* n = (WS_SFTPNAME*)WMALLOC(sizeof(WS_SFTPNAME), heap,
            DYNTYPE_SFTP );
    if (n != NULL) {
        WMEMSET(n, 0, sizeof(WS_SFTPNAME));
        n->heap = heap;
    }

    return n;
}


/* free's a single sftp name structure. Note that this could destroy a list if
 * used on a single node in the list.
 */
void wolfSSH_SFTPNAME_free(WS_SFTPNAME* n)
{
    if (n != NULL) {
        WFREE(n->fName, n->heap, DYNTYPE_SFTP);
        WFREE(n->lName, n->heap, DYNTYPE_SFTP);
        WFREE(n, n->heap, DYNTYPE_SFTP);
    }
}


/* free's linked list of sftp name structures */
void wolfSSH_SFTPNAME_list_free(WS_SFTPNAME* n)
{
    WS_SFTPNAME* tmp = NULL;

    while (n != NULL) {
        tmp = n->next;
        wolfSSH_SFTPNAME_free(n);
        n = tmp;
    }
}


/* parse out file attributes from a buffer
 *
 * returns WS_SUCCESS on success
 */
int SFTP_ParseAtributes_buffer(WOLFSSH* ssh,  WS_SFTP_FILEATRB* atr, byte* buf,
        word32 bufSz)
{
    word32 idx = 0;

    WMEMSET(atr, 0, sizeof(WS_SFTP_FILEATRB));

    /* get flags */
    ato32(buf, &atr->flags); idx += UINT32_SZ;

    /* check if size attribute present */
    if (atr->flags & WOLFSSH_FILEATRB_SIZE) {
        word32 tmp;

        ato32(buf + idx, &tmp); idx += UINT32_SZ;
        atr->sz = tmp; atr->sz = atr->sz << 32;
        ato32(buf + idx, &tmp); idx += UINT32_SZ;
        atr->sz |= tmp;
    }

    /* check if uid and gid attribute present */
    if (atr->flags & WOLFSSH_FILEATRB_UIDGID) {
        ato32(buf + idx, &atr->uid); idx += UINT32_SZ;
        ato32(buf + idx, &atr->gid); idx += UINT32_SZ;
    }

    /* check if permissions attribute present */
    if (atr->flags & WOLFSSH_FILEATRB_PERM) {
        ato32(buf + idx, &atr->per); idx += UINT32_SZ;
    }

    /* check if time attribute present */
    if (atr->flags & WOLFSSH_FILEATRB_TIME) {
        ato32(buf + idx, &atr->atime); idx += UINT32_SZ;
        ato32(buf + idx, &atr->mtime); idx += UINT32_SZ;
    }

    /* check if extended attributes are present */
    if (atr->flags & WOLFSSH_FILEATRB_EXT) {
        word32 i;
        word32 sz;

        ato32(buf + idx, &atr->extCount); idx += UINT32_SZ;

        for (i = 0; i < atr->extCount; i++) {
            /* @TODO in the process of storing attributes */
            ato32(buf + idx, &sz); idx += UINT32_SZ;

            if (sz > 0) {
                /* @TODO extension type */
                idx += sz;
            }

            /* @TODO in the process of storing attributes */
            ato32(buf + idx, &sz); idx += UINT32_SZ;

            if (sz > 0) {
                /* @TODO extension data */
                idx += sz;
            }
        }
    }

    (void)ssh;
    (void)bufSz;
    return WS_SUCCESS;
}


/* parse out file attributes from I/O stream
 *
 * returns WS_SUCCESS on success
 */
int SFTP_ParseAtributes(WOLFSSH* ssh,  WS_SFTP_FILEATRB* atr)
{
    byte buf[UINT32_SZ * 2];
    int ret;

    WMEMSET(atr, 0, sizeof(WS_SFTP_FILEATRB));
    /* get flags */
    ret = wolfSSH_stream_read(ssh, buf, UINT32_SZ);
    if (ret != UINT32_SZ) {
        return WS_FATAL_ERROR;
    }
    ato32(buf, &atr->flags);

    /* check if size attribute present */
    if (atr->flags & WOLFSSH_FILEATRB_SIZE) {
        word32 tmp;

        ret = wolfSSH_stream_read(ssh, buf, UINT32_SZ * 2);
        if (ret != UINT32_SZ * 2) {
            return WS_FATAL_ERROR;
        }
        ato32(buf, &tmp);
        atr->sz = tmp; atr->sz = atr->sz << 32;
        ato32(buf + UINT32_SZ, &tmp);
        atr->sz |= tmp;
    }

    /* check if uid and gid attribute present */
    if (atr->flags & WOLFSSH_FILEATRB_UIDGID) {
        ret = wolfSSH_stream_read(ssh, buf, UINT32_SZ*2);
        if (ret != UINT32_SZ*2) {
            return WS_FATAL_ERROR;
        }
        ato32(buf, &atr->uid);
        ato32(buf+UINT32_SZ, &atr->gid);
    }

    /* check if permissions attribute present */
    if (atr->flags & WOLFSSH_FILEATRB_PERM) {
        ret = wolfSSH_stream_read(ssh, buf, UINT32_SZ);
        if (ret != UINT32_SZ) {
            return WS_FATAL_ERROR;
        }
        ato32(buf, &atr->per);
    }

    /* check if time attribute present */
    if (atr->flags & WOLFSSH_FILEATRB_TIME) {
        ret = wolfSSH_stream_read(ssh, buf, UINT32_SZ*2);
        if (ret != UINT32_SZ*2) {
            return WS_FATAL_ERROR;
        }
        ato32(buf, &atr->atime);
        ato32(buf+UINT32_SZ, &atr->mtime);
    }

    /* check if extended attributes are present */
    if (atr->flags & WOLFSSH_FILEATRB_EXT) {
        word32 i;
        word32 sz;

        ret = wolfSSH_stream_read(ssh, buf, UINT32_SZ);
        if (ret != UINT32_SZ) {
            return WS_FATAL_ERROR;
        }
        ato32(buf, &atr->extCount);

        for (i = 0; i < atr->extCount; i++) {
            /* read extension [ string ] [ string ] */
            ret = wolfSSH_stream_read(ssh, buf, UINT32_SZ);
            if (ret != UINT32_SZ) {
                return WS_FATAL_ERROR;
            }

            /* @TODO in the process of storing attributes */
            ato32(buf, &sz);

            if (sz > 0) {
                /* extension type */
                byte* tmp = (byte*)WMALLOC(sz, NULL, DYNTYPE_BUFFER);
                ret = wolfSSH_stream_read(ssh, tmp, sz);
                if (ret < 0) {
                    WFREE(tmp, NULL, DYNTYPE_BUFFER);
                    return ret;
                }
                WFREE(tmp, NULL, DYNTYPE_BUFFER);
            }

            ret = wolfSSH_stream_read(ssh, buf, UINT32_SZ);
            if (ret != UINT32_SZ) {
                return WS_FATAL_ERROR;
            }

            /* @TODO in the process of storing attributes */
            ato32(buf, &sz);

            if (sz > 0) {
                /* extension data */
                byte* tmp = (byte*)WMALLOC(sz, NULL, DYNTYPE_BUFFER);
                ret = wolfSSH_stream_read(ssh, tmp, sz);
                WFREE(tmp, NULL, DYNTYPE_BUFFER);
                if (ret < 0) {
                    return ret;
                }
            }
        }
    }

    return WS_SUCCESS;
}


/* process a name packet. Creates a linked list of WS_SFTPNAME structures
 *
 * Syntax of name packet is as follows
 * {
 *  uint32 id
 *  uint32 count
 *  for count times:
 *      string filename
 *      string longname
 *      ATTRS  atributes
 * }
 *
 * A pointer to a malloc'd WS_SFTPNAME list is returned on success and NULL is
 * returned with failure.
 */
static WS_SFTPNAME* wolfSSH_SFTP_DoName(WOLFSSH* ssh)
{
    /* process name */
    WS_SFTPNAME* n = NULL;
    byte buf[UINT32_SZ];
    word32 maxSz;
    word32 count;
    word32 reqId;
    byte   type = 0;
    int    ret;

    maxSz = SFTP_GetHeader(ssh, &reqId, &type);
    if (maxSz <= 0) {
        return NULL;
    }

    if (type != WOLFSSH_FTP_NAME) {
        WLOG(WS_LOG_SFTP, "Unexpected packet type %d", type);
        /* check for status msg */
        if (type == WOLFSSH_FTP_STATUS) {
            wolfSSH_SFTP_DoStatus(ssh, reqId);
        }
        return NULL;
    }

    if (reqId != ssh->reqId) {
        WLOG(WS_LOG_SFTP, "unexpected ID");
        return NULL;
    }
    ssh->reqId += 1;

    /* get number of files */
    ret = wolfSSH_stream_read(ssh, buf, UINT32_SZ);
    if (ret != UINT32_SZ) return NULL;

    ato32(buf, &count);
    while (count > 0) {
        word32 sz;
        WS_SFTPNAME* tmp = wolfSSH_SFTPNAME_new(ssh->ctx->heap);

        count--;
        if (tmp == NULL) {
            /* error case free list and exit */
            WLOG(WS_LOG_SFTP, "Memory error when creating new name structure");
            ret = WS_MEMORY_E;
            break;
        }

        /* push tmp onto front of name list */
        tmp->next = n;
        n = tmp;

        /* get filename size and name */
        ret = wolfSSH_stream_read(ssh, buf, UINT32_SZ);
        if (ret != UINT32_SZ) {
            ret = WS_FATAL_ERROR;
            break;
        }

        ato32(buf, &sz);
        tmp->fSz   = sz;
        if (sz > 0) {
            tmp->fName = (char*)WMALLOC(sz + 1, tmp->heap, DYNTYPE_SFTP);
            if (tmp->fName == NULL) {
                ret = WS_MEMORY_E;
                break;
            }
            ret = wolfSSH_stream_read(ssh, (byte*)tmp->fName, sz);
            if (ret < 0 || (word32)ret != sz) {
                ret = WS_FATAL_ERROR;
                break;
            }
            tmp->fName[sz] = '\0';
        }

        /* get longname size and name */
        ret = wolfSSH_stream_read(ssh, buf, UINT32_SZ);
        if (ret != UINT32_SZ) {
            ret = WS_FATAL_ERROR;
            break;
        }

        ato32(buf, &sz);
        tmp->lSz   = sz;
        if (sz > 0) {
            tmp->lName = (char*)WMALLOC(sz + 1, tmp->heap, DYNTYPE_SFTP);
            if (tmp->lName == NULL) {
                ret = WS_MEMORY_E;
                break;
            }
            ret = wolfSSH_stream_read(ssh, (byte*)tmp->lName, sz);
            if (ret < 0 || (word32)ret != sz) {
                ret = WS_FATAL_ERROR;
                break;
            }
            tmp->lName[sz] = '\0';
        }

        /* get attributes */
        ret = SFTP_ParseAtributes(ssh,  &tmp->atrb);
        if (ret != WS_SUCCESS) {
            break;
        }

        ret = WS_SUCCESS;
    }

    if (ret != WS_SUCCESS) {
        WLOG(WS_LOG_SFTP, "Error with reading file names");
        wolfSSH_SFTPNAME_list_free(n);
        return NULL;
    }

    (void)maxSz;
    return n;
}


/* get the file handle from SSH stream
 *
 * handle   buffer to hold result
 * handleSz gets set to size of resulting handle. Initially this should be
 *          passed in set to the size of "handle" buffer.
 *
 * returns WS_SUCCESS on success
 */
static int wolfSSH_SFTP_GetHandle(WOLFSSH* ssh, byte* handle, word32* handleSz)
{
    /* process handle*/
    byte buf[WOLFSSH_MAX_HANDLE + UINT32_SZ];
    word32 reqId;
    word32 bufSz;
    byte type = 0;

    WLOG(WS_LOG_SFTP, "Entering wolfSSH_SFTP_GetHandle");
    bufSz = SFTP_GetHeader(ssh, &reqId, &type);
    if (bufSz <= 0) {
        return WS_FATAL_ERROR;
    }

    if (type != WOLFSSH_FTP_HANDLE) {
        if (type == WOLFSSH_FTP_STATUS) {
            return wolfSSH_SFTP_DoStatus(ssh, reqId);
        }
        WLOG(WS_LOG_SFTP, "Unexpected packet type with getting handle");
        return WS_FATAL_ERROR;
    }

    /* @TODO packets do not need to be in order, may need mechanisim to
     * handle out of order ID's ?  */
    if (reqId != ssh->reqId) {
        WLOG(WS_LOG_SFTP, "Unexpected ID");
        return WS_FATAL_ERROR;
    }
    ssh->reqId += 1;

    if (bufSz > sizeof(buf)) {
        WLOG(WS_LOG_SFTP, "Handle found is too large for buffer");
        return WS_BUFFER_E;
    }
    if (wolfSSH_stream_read(ssh, buf, bufSz) != (int)bufSz) {
        return WS_FATAL_ERROR;
    }

    /* RFC specifies that handle size should not be larger than max size */
    ato32(buf, &bufSz);
    if (bufSz > WOLFSSH_MAX_HANDLE || *handleSz < bufSz) {
        WLOG(WS_LOG_SFTP, "Handle size found was too big");
        return WS_BUFFER_E;
    }
    *handleSz = bufSz;
    WMEMCPY(handle, (buf + UINT32_SZ), *handleSz);

    return WS_SUCCESS;
}


/* Used to get a list of all files and their attributes from a directory.
 *
 * dir  NULL terminated string of the directory to list
 *
 * returns a linked list of files in the directory on success, NULL on failure
 */
WS_SFTPNAME* wolfSSH_SFTP_LS(WOLFSSH* ssh, char* dir)
{
    WS_SFTPNAME* name;
    byte handle[WOLFSSH_MAX_HANDLE];
    word32 handleSz;

    if (ssh == NULL || dir == NULL) {
        WLOG(WS_LOG_SFTP, "Bad argument passed in");
        return NULL;
    }

    name = wolfSSH_SFTP_RealPath(ssh, dir);
    if (name == NULL) {
        return NULL;
    }

    if (wolfSSH_SFTP_OpenDir(ssh, (byte*)name->fName, name->fSz) != WS_SUCCESS) {
        WLOG(WS_LOG_SFTP, "Unable to open directory");
        wolfSSH_SFTPNAME_list_free(name); name = NULL;
        return NULL;
    }
    wolfSSH_SFTPNAME_list_free(name); name = NULL;

    /* get the handle from opening the directory and read with it */
    handleSz = WOLFSSH_MAX_HANDLE;
    if (wolfSSH_SFTP_GetHandle(ssh, handle, &handleSz) != WS_SUCCESS) {
        WLOG(WS_LOG_SFTP, "Unable to get handle");
        return NULL;
    }

    /* now read the dir */
    name = wolfSSH_SFTP_ReadDir(ssh, handle, handleSz);
    if (name == NULL) {
        WLOG(WS_LOG_SFTP, "Error reading directory");
        /* fall through because the handle should always be closed */
    }

    /* close dir when finished */
    if (wolfSSH_SFTP_Close(ssh, handle, handleSz) != WS_SUCCESS) {
        WLOG(WS_LOG_SFTP, "Error closing handle");
        wolfSSH_SFTPNAME_list_free(name);
        name = NULL;
    }

    return name;
}


/* Takes in an octal file permissions value and sets it to the file/directory
 * returns WS_SUCCESS on success
 */
int wolfSSH_SFTP_CHMOD(WOLFSSH* ssh, char* n, char* oct)
{
    int ret;
    int mode;
    WS_SFTP_FILEATRB atr;

    if (ssh == NULL || n == NULL || oct == NULL) {
        return WS_BAD_ARGUMENT;
    }

    /* convert from octal to decimal */
    mode = wolfSSH_oct2dec(ssh, (byte*)oct, (word32)WSTRLEN(oct));
    if (mode < 0) {
        return mode;
    }

    /* get current attributes of path */
    WMEMSET(&atr, 0, sizeof(WS_SFTP_FILEATRB));
    if ((ret = wolfSSH_SFTP_STAT(ssh, n, &atr)) != WS_SUCCESS) {
        return ret;
    }

    /* update permissions */
    atr.per = mode;
    return wolfSSH_SFTP_SetSTAT(ssh, n, &atr);
}


/* helper function for common code between LSTAT and STAT
 *
 * returns WS_SUCCESS on success
 */
static int SFTP_STAT(WOLFSSH* ssh, char* dir, WS_SFTP_FILEATRB* atr, byte type)
{
    WS_SFTP_LSTAT_STATE* state = NULL;
    int ret;

    WLOG(WS_LOG_SFTP, "Entering SFTP_STAT()");
    if (ssh == NULL || dir == NULL)
        return WS_BAD_ARGUMENT;

    state = ssh->lstatState;
    if (state == NULL) {
        state = (WS_SFTP_LSTAT_STATE*)WMALLOC(sizeof(WS_SFTP_LSTAT_STATE),
                ssh->ctx->heap, DYNTYPE_SFTP_STATE);
        if (state == NULL) {
            ssh->error = WS_MEMORY_E;
            return WS_FATAL_ERROR;
        }
        WMEMSET(state, 0, sizeof(WS_SFTP_GET_STATE));
        ssh->lstatState = state;
        state->state = STATE_LSTAT_INIT;
    }

    WLOG(WS_LOG_SFTP, "Sending WOLFSSH_FTP_[L]STAT");

    for (;;) {
        switch (state->state) {

            case STATE_LSTAT_INIT:
                WLOG(WS_LOG_SFTP, "SFTP LSTAT STATE: INIT");
                state->dirSz = (word32)WSTRLEN(dir);
                state->state = STATE_LSTAT_SEND_TYPE_REQ;
                FALL_THROUGH;

            case STATE_LSTAT_SEND_TYPE_REQ:
                WLOG(WS_LOG_SFTP, "SFTP LSTAT STATE: SEND_TYPE_REQ");
                ret = SendPacketType(ssh, type, (byte*)dir, state->dirSz);
                if (ret != WS_SUCCESS) {
                    return WS_FATAL_ERROR;
                }
                state->state = STATE_LSTAT_GET_HEADER;
                FALL_THROUGH;

            case STATE_LSTAT_GET_HEADER:
                WLOG(WS_LOG_SFTP, "SFTP LSTAT STATE: GET_HEADER");
                /* get attributes response */
                ret = SFTP_GetHeader(ssh, &state->reqId, &type);
                if (ret <= 0) {
                    return WS_FATAL_ERROR;
                }
                state->state = STATE_LSTAT_CHECK_REQ_ID;
                FALL_THROUGH;

            case STATE_LSTAT_CHECK_REQ_ID:
                /* check request ID */
                if (state->reqId != ssh->reqId) {
                    WLOG(WS_LOG_SFTP, "Bad request ID received");
                    return WS_FATAL_ERROR;
                }
                else {
                    ssh->reqId++;
                }
                state->state = STATE_LSTAT_PARSE_REPLY;
                FALL_THROUGH;

            case STATE_LSTAT_PARSE_REPLY:
                WLOG(WS_LOG_SFTP, "SFTP LSTAT STATE: PARSE_REPLY");
                if (type == WOLFSSH_FTP_ATTRS) {
                    ret = SFTP_ParseAtributes(ssh, atr);
                    if (ret != WS_SUCCESS) {
                        return ret;
                    }
                }
                else if (type == WOLFSSH_FTP_STATUS) {
                    ret = wolfSSH_SFTP_DoStatus(ssh, state->reqId);
                    if (ret != WOLFSSH_FTP_OK) {
                        if (ret == WOLFSSH_FTP_PERMISSION) {
                            return WS_PERMISSIONS;
                        }
                        return WS_FATAL_ERROR;
                    }
                }
                else {
                    WLOG(WS_LOG_SFTP, "Unexpected packet received");
                    return WS_FATAL_ERROR;
                }
                state->state = STATE_LSTAT_CLEANUP;
                FALL_THROUGH;

            case STATE_LSTAT_CLEANUP:
                WLOG(WS_LOG_SFTP, "SFTP LSTAT STATE: CLEANUP");
                if (ssh->lstatState != NULL) {
                    WFREE(ssh->lstatState, ssh->ctx->heap, DYNTYPE_SFTP_STATE);
                    ssh->lstatState = NULL;
                }
                return WS_SUCCESS;

            default:
                WLOG(WS_LOG_DEBUG, "Bad SFTP LSTAT state, program error");
                return WS_INPUT_CASE_E;
        }
    }

    return WS_SUCCESS;
}


/* follows symbolic links
 *
 * dir NULL terminated string of file name
 * atr structure to hold parsed file attributes
 *
 * returns WS_SUCCESS on success
 */
int wolfSSH_SFTP_STAT(WOLFSSH* ssh, char* dir, WS_SFTP_FILEATRB* atr)
{
    return SFTP_STAT(ssh, dir, atr, WOLFSSH_FTP_STAT);
}


/* does not follow symbolic links
 *
 * dir NULL terminated string of file name
 * atr structure to hold parsed file attributes
 *
 * returns WS_SUCCESS on success
 */
int wolfSSH_SFTP_LSTAT(WOLFSSH* ssh, char* dir, WS_SFTP_FILEATRB* atr)
{
    return SFTP_STAT(ssh, dir, atr, WOLFSSH_FTP_LSTAT);
}


/* Sends packet to set the attributes of path
 *
 * dir NULL terminated string of path
 * atr structure holding file attributes to use
 *
 * returns WS_SUCCESS on success
 */
int wolfSSH_SFTP_SetSTAT(WOLFSSH* ssh, char* dir, WS_SFTP_FILEATRB* atr)
{
    int dirSz, atrSz, status;
    word32 maxSz, reqId;
    byte type;
    byte* data;
    word32 idx;

    WLOG(WS_LOG_SFTP, "Entering wolfSSH_SFTP_SetSTAT()");
    if (ssh == NULL || dir == NULL || atr == NULL) {
        return WS_BAD_ARGUMENT;
    }

    dirSz = (int)WSTRLEN(dir);
    atrSz = SFTP_AtributesSz(ssh, atr);
    data = (byte*)WMALLOC(dirSz + atrSz + WOLFSSH_SFTP_HEADER + UINT32_SZ,
            ssh->ctx->heap, DYNTYPE_BUFFER);
    if (data == NULL) {
        return WS_MEMORY_E;
    }

    if (SFTP_SetHeader(ssh, ssh->reqId, WOLFSSH_FTP_SETSTAT,
                dirSz + atrSz + UINT32_SZ, data) != WS_SUCCESS) {
        WFREE(data, NULL, DYNTYPE_BUFFER);
        return WS_FATAL_ERROR;
    }

    idx = WOLFSSH_SFTP_HEADER;
    c32toa(dirSz, data + idx);              idx += UINT32_SZ;
    WMEMCPY(data + idx, (byte*)dir, dirSz); idx += dirSz;
    SFTP_SetAttributes(ssh, data + idx, atrSz, atr); idx += atrSz;

    /* send header and type specific data */
    if (wolfSSH_stream_send(ssh, data, idx) < 0) {
        WFREE(data, NULL, DYNTYPE_BUFFER);
        return WS_FATAL_ERROR;
    }
    WFREE(data, NULL, DYNTYPE_BUFFER);

    maxSz = SFTP_GetHeader(ssh, &reqId, &type);
    if (maxSz <= 0) {
        return WS_FATAL_ERROR;
    }

    if (type != WOLFSSH_FTP_STATUS) {
        WLOG(WS_LOG_SFTP, "Unexpected packet type %d", type);
        return WS_FATAL_ERROR;
    }
    else {
        status = wolfSSH_SFTP_DoStatus(ssh, reqId);
        if (status != WOLFSSH_FTP_OK) {
            return WS_BAD_FILE_E;
        }
    }
    (void)maxSz;

    return WS_SUCCESS;
}


/* Open a file for reading/writing
 *
 * dir      NULL terminated string holding file name
 * reason   the reason file is being opened for i.e. WOLFSSH_FXF_READ,
 *          WOLFSSH_FXF_WRITE, ....
 * atr      attributes of file
 * handle   resulting handle from opening the file
 * handleSz gets set to resulting handle size. Should initially be size of
 *          handle buffer when passed in
 *
 * returns WS_SUCCESS on success
 */
int wolfSSH_SFTP_Open(WOLFSSH* ssh, char* dir, word32 reason,
        WS_SFTP_FILEATRB* atr, byte* handle, word32* handleSz)
{
    WS_SFTP_OPEN_STATE* state = NULL;
    int ret = WS_SUCCESS;

    WLOG(WS_LOG_SFTP, "Entering wolfSSH_SFTP_Open()");
    if (ssh == NULL || dir == NULL) {
        return WS_BAD_ARGUMENT;
    }

    if (ssh->error == WS_WANT_READ || ssh->error == WS_WANT_WRITE)
        ssh->error = WS_SUCCESS;

    state = ssh->openState;
    if (ssh->openState == NULL) {
        state = (WS_SFTP_OPEN_STATE*)WMALLOC(sizeof(WS_SFTP_OPEN_STATE),
                ssh->ctx->heap, DYNTYPE_SFTP_STATE);
        if (state == NULL) {
            ssh->error = WS_MEMORY_E;
            return WS_FATAL_ERROR;
        }
        WMEMSET(state, 0, sizeof(WS_SFTP_OPEN_STATE));
        ssh->openState = state;
        state->state = STATE_OPEN_INIT;
    }

    for (;;) {
        switch (state->state) {
            case STATE_OPEN_INIT:
                WLOG(WS_LOG_SFTP, "SFTP OPEN STATE: INIT");
                state->sz = (int)WSTRLEN(dir);
                state->data =
                        (byte*)WMALLOC(
                            state->sz + WOLFSSH_SFTP_HEADER + UINT32_SZ * 3,
                            ssh->ctx->heap, DYNTYPE_BUFFER);
                if (state->data == NULL) {
                    ssh->error = WS_MEMORY_E;
                    return WS_FATAL_ERROR;
                }

                ret = SFTP_SetHeader(ssh, ssh->reqId, WOLFSSH_FTP_OPEN,
                                     state->sz + UINT32_SZ * 3, state->data);
                if (ret != WS_SUCCESS) {
                    WFREE(state->data, NULL, DYNTYPE_BUFFER);
                    state->data = NULL;
                    return WS_FATAL_ERROR;
                }

                state->idx = WOLFSSH_SFTP_HEADER;
                c32toa(state->sz, state->data + state->idx);
                state->idx += UINT32_SZ;
                WMEMCPY(state->data + state->idx, (byte*)dir, state->sz);
                state->idx += state->sz;
                c32toa(reason, state->data + state->idx);
                state->idx += UINT32_SZ;

                /* @TODO handle adding attributes here */
                (void)atr;
                c32toa(0x00000000, state->data + state->idx);
                state->idx += UINT32_SZ;

                state->state = STATE_OPEN_SEND;
                FALL_THROUGH;

            case STATE_OPEN_SEND:
                WLOG(WS_LOG_SFTP, "SFTP OPEN STATE: SEND");
                /* send header and type specific data */
                ret = wolfSSH_stream_send(ssh, state->data, state->idx);
                if (ret < 0) {
                    if (ssh->error != WS_WANT_READ &&
                        ssh->error != WS_WANT_WRITE) {

                        WFREE(state->data, NULL, DYNTYPE_BUFFER);
                        state->data = NULL;
                    }
                    return WS_FATAL_ERROR;
                }
                WFREE(state->data, NULL, DYNTYPE_BUFFER);
                state->data = NULL;
                state->state = STATE_OPEN_GETHANDLE;
                FALL_THROUGH;

            case STATE_OPEN_GETHANDLE:
                WLOG(WS_LOG_SFTP, "SFTP OPEN STATE: GETHANDLE");
                ret = wolfSSH_SFTP_GetHandle(ssh, handle, handleSz);
                if (ret != WS_SUCCESS) {
                    WLOG(WS_LOG_SFTP, "Error getting handle");
                    return WS_FATAL_ERROR;
                }
                state->state = STATE_OPEN_CLEANUP;
                FALL_THROUGH;

            case STATE_OPEN_CLEANUP:
                WLOG(WS_LOG_SFTP, "SFTP OPEN STATE: CLEANUP");
                if (ssh->openState != NULL) {
                    WFREE(ssh->openState, ssh->ctx->heap, DYNTYPE_SFTP_STATE);
                    ssh->openState = NULL;
                }
                return WS_SUCCESS;

            default:
                WLOG(WS_LOG_DEBUG, "Bad SFTP Open state, program error");
                return WS_INPUT_CASE_E;
        }
    }

    return WS_SUCCESS;
}


/* Writes data from buffer to the file handle
 *
 * handle   file handle given by sftp server
 * handleSz size of handle
 * ofst     offset to start writing at
 * in       data to be written
 * inSz     amount of data to be written from "in" buffer
 * 
 * returns the amount written on success
 */
int wolfSSH_SFTP_SendWritePacket(WOLFSSH* ssh, byte* handle, word32 handleSz,
        word64 ofst, byte* in, word32 inSz)
{
    int ret;
    int status;
    byte* data;
    byte type;
    word32 reqId;
    word32 idx;

    WLOG(WS_LOG_SFTP, "Entering wolfSSH_SFTP_SendWritePacket()");
    if (ssh == NULL || handle == NULL || in == NULL) {
        return WS_BAD_ARGUMENT;
    }

    data = (byte*)WMALLOC(handleSz + WOLFSSH_SFTP_HEADER + UINT32_SZ * 4,
            ssh->ctx->heap, DYNTYPE_BUFFER);
    if (data == NULL) {
        return WS_MEMORY_E;
    }

    if (SFTP_SetHeader(ssh, ssh->reqId, WOLFSSH_FTP_WRITE,
                handleSz + UINT32_SZ * 4 + inSz, data) != WS_SUCCESS) {
        return WS_FATAL_ERROR;
    }

    idx = WOLFSSH_SFTP_HEADER;
    c32toa(handleSz, data + idx); idx += UINT32_SZ;
    WMEMCPY(data + idx, (byte*)handle, handleSz); idx += handleSz;

    /* offset to start reading from */
    c32toa((word32)(ofst >> 32), data + idx); idx += UINT32_SZ;
    c32toa((word32)ofst, data + idx); idx += UINT32_SZ;

    /* data to be written */
    c32toa(inSz, data + idx); idx += UINT32_SZ;

    /* send header and type specific data */
    ret = wolfSSH_stream_send(ssh, data, idx);
    if (ret < 0) {
        WFREE(data, NULL, DYNTYPE_BUFFER);
        return ret;
    }

    ret = wolfSSH_stream_send(ssh, in, inSz);
    if (ret < 0) {
        WFREE(data, NULL, DYNTYPE_BUFFER);
        return ret;
    }
    WFREE(data, NULL, DYNTYPE_BUFFER);

    /* Get response */
    if (SFTP_GetHeader(ssh, &reqId, &type) <= 0) {
        return WS_FATAL_ERROR;
    }

    /* check request ID */
    if (reqId != ssh->reqId) {
        WLOG(WS_LOG_SFTP, "Bad request ID received");
        return WS_FATAL_ERROR;
    }
    else {
        ssh->reqId++;
    }

    if (type == WOLFSSH_FTP_STATUS) {
        status = wolfSSH_SFTP_DoStatus(ssh, reqId);
        if (status == WOLFSSH_FTP_OK) {
            /* a okay */
        }
        else {
            /* @TODO better error value description i.e permissions... */
            ret = WS_FATAL_ERROR;
        }
    }
    else {
        WLOG(WS_LOG_SFTP, "Unexpected packet type");
        return WS_FATAL_ERROR;
    }


    return ret;
}


/* Reads data from file and places it in "out" buffer
 *
 * handle   file handle given by sftp server
 * handleSz size of handle
 * ofst     offset to start reading at
 * out      buffer to hold resulting data read
 * outSz    size of "out" buffer
 *
 * returns the number of bytes read on success
 */
int wolfSSH_SFTP_SendReadPacket(WOLFSSH* ssh, byte* handle, word32 handleSz,
        word64 ofst, byte* out, word32 outSz)
{
    WS_SFTP_SEND_READ_STATE* state = NULL;
    byte szFlat[UINT32_SZ];
    int ret = WS_SUCCESS;

    WLOG(WS_LOG_SFTP, "Entering wolfSSH_SFTP_SendReadPacket()");
    if (ssh == NULL || handle == NULL || out == NULL)
        return WS_BAD_ARGUMENT;

    state = ssh->sendReadState;
    if (state == NULL) {
        state = (WS_SFTP_SEND_READ_STATE*)WMALLOC(
                    sizeof(WS_SFTP_SEND_READ_STATE),
                    ssh->ctx->heap, DYNTYPE_SFTP_STATE);
        if (state == NULL) {
            ssh->error = WS_MEMORY_E;
            return WS_FATAL_ERROR;
        }
        WMEMSET(state, 0, sizeof(WS_SFTP_SEND_READ_STATE));
        ssh->sendReadState = state;
        state->state = STATE_SEND_READ_INIT;
    }

    for (;;) {
        switch (state->state) {

            case STATE_SEND_READ_INIT:
                state->data = (byte*)WMALLOC(
                            handleSz + WOLFSSH_SFTP_HEADER + UINT32_SZ * 4,
                            ssh->ctx->heap, DYNTYPE_BUFFER);
                if (state->data == NULL) {
                    ssh->error = WS_MEMORY_E;
                    return WS_FATAL_ERROR;
                }

                ret = SFTP_SetHeader(ssh, ssh->reqId, WOLFSSH_FTP_READ,
                            handleSz + UINT32_SZ * 4, state->data);
                if (ret != WS_SUCCESS)
                    return WS_FATAL_ERROR;

                state->idx = WOLFSSH_SFTP_HEADER;
                c32toa(handleSz, state->data + state->idx);
                state->idx += UINT32_SZ;
                WMEMCPY(state->data + state->idx, (byte*)handle, handleSz);
                state->idx += handleSz;

                /* offset to start reading from */
                c32toa((word32)(ofst >> 32), state->data + state->idx);
                state->idx += UINT32_SZ;
                c32toa((word32)ofst, state->data + state->idx);
                state->idx += UINT32_SZ;

                /* max length to read */
                c32toa(outSz, state->data + state->idx);
                state->idx += UINT32_SZ;

                state->state = STATE_SEND_READ_SEND_REQ;
                FALL_THROUGH;

            case STATE_SEND_READ_SEND_REQ:
                /* send header and type specific data */
                ret = wolfSSH_stream_send(ssh, state->data, state->idx);
                WFREE(state->data, ssh->ctx->heap, DYNTYPE_BUFFER);
                state->data = NULL;
                if (ret < 0) {
                    return ret;
                }

                state->state = STATE_SEND_READ_GET_HEADER;
                FALL_THROUGH;

            case STATE_SEND_READ_GET_HEADER:
                /* Get response */
                if (SFTP_GetHeader(ssh, &state->reqId, &state->type) <= 0)
                    return WS_FATAL_ERROR;

                state->state = STATE_SEND_READ_CHECK_REQ_ID;
                FALL_THROUGH;

            case STATE_SEND_READ_CHECK_REQ_ID:
                /* check request ID */
                if (state->reqId != ssh->reqId) {
                    WLOG(WS_LOG_SFTP, "Bad request ID received");
                    return WS_FATAL_ERROR;
                }
                else
                    ssh->reqId++;

                if (state->type == WOLFSSH_FTP_DATA)
                    state->state = STATE_SEND_READ_FTP_DATA;
                else if (state->type == WOLFSSH_FTP_STATUS)
                    state->state = STATE_SEND_READ_FTP_STATUS;
                else {
                    WLOG(WS_LOG_SFTP, "Unexpected packet type");
                    return WS_FATAL_ERROR;
                }
                continue;

            case STATE_SEND_READ_FTP_DATA:
                /* get size of string and place it into out buffer */
                ret = wolfSSH_stream_read(ssh, szFlat, UINT32_SZ);
                if (ret < 0) {
                    return ret;
                }
                ato32(szFlat, &state->sz);
                if (state->sz > outSz) {
                    WLOG(WS_LOG_SFTP, "Server sent more data then expected");
                    return WS_FATAL_ERROR;
                }

                state->state = STATE_SEND_READ_REMAINDER;
                FALL_THROUGH;

            case STATE_SEND_READ_REMAINDER:
                ret = wolfSSH_stream_read(ssh, out, state->sz);
                if (ret < 0) {
                    return ret;
                }
                ret = state->sz;

                state->state = STATE_SEND_READ_CLEANUP;
                continue;

            case STATE_SEND_READ_FTP_STATUS:
                ret = wolfSSH_SFTP_DoStatus(ssh, state->reqId);
                if (ret == WOLFSSH_FTP_OK || ret == WOLFSSH_FTP_EOF) {
                    WLOG(WS_LOG_SFTP, "OK or EOF found");
                    ret = 0; /* nothing was read */
                }

                state->state = STATE_SEND_READ_CLEANUP;
                FALL_THROUGH;

            case STATE_SEND_READ_CLEANUP:
                WLOG(WS_LOG_SFTP, "SFTP SEND_READ STATE: CLEANUP");
                if (ssh->sendReadState != NULL) {
                    if (ssh->sendReadState->data != NULL) {
                        WFREE(ssh->sendReadState->data,
                              ssh->ctx->heap, DYNTYPE_SFTP_STATE);
                        ssh->sendReadState->data = NULL;
                    }
                    WFREE(ssh->sendReadState,
                          ssh->ctx->heap, DYNTYPE_SFTP_STATE);
                    ssh->sendReadState = NULL;
                }
                return WS_SUCCESS;

            default:
                WLOG(WS_LOG_DEBUG, "Bad SFTP Send Read Packet state, "
                                   "program error");
                return WS_INPUT_CASE_E;
        }
    }

    return ret;
}


/* Sends packet to make a directory
 *
 * dir NULL terminated string with the name of the new directory to create
 * atr attributes of the new directory
 *
 * returns WS_SUCCESS on success
 */
int wolfSSH_SFTP_MKDIR(WOLFSSH* ssh, char* dir, WS_SFTP_FILEATRB* atr)
{
    int   sz;
    int   ret;
    byte* data;
    word32 reqId;
    byte type;
    word32 idx;

    WLOG(WS_LOG_SFTP, "Sending WOLFSSH_FTP_MKDIR");
    if (ssh == NULL || dir == NULL) {
        return WS_BAD_ARGUMENT;
    }

    sz = (int)WSTRLEN(dir);
    data = (byte*)WMALLOC(sz + WOLFSSH_SFTP_HEADER + UINT32_SZ * 3 ,
            ssh->ctx->heap, DYNTYPE_BUFFER);
    if (data == NULL) {
        return WS_MEMORY_E;
    }

    if (SFTP_SetHeader(ssh, ssh->reqId, WOLFSSH_FTP_MKDIR,
                sz + UINT32_SZ * 3, data) != WS_SUCCESS) {
        return WS_FATAL_ERROR;
    }

    idx = WOLFSSH_SFTP_HEADER;
    c32toa(sz, data + idx);              idx += UINT32_SZ;
    WMEMCPY(data + idx, (byte*)dir, sz); idx += sz;
    c32toa(UINT32_SZ, data + idx);       idx += UINT32_SZ;

    /* @TODO handle setting attributes */
    (void)atr;
    c32toa(0x000001FF, data + idx);      idx += UINT32_SZ;

    /* send header and type specific data */
    ret = wolfSSH_stream_send(ssh, data, idx);
    if (ret < 0) {
        return ret;
    }
    WFREE(data, NULL, DYNTYPE_BUFFER);

    /* Get response */
    if (SFTP_GetHeader(ssh, &reqId, &type) <= 0) {
        return WS_FATAL_ERROR;
    }
    if (type != WOLFSSH_FTP_STATUS) {
        WLOG(WS_LOG_SFTP, "Unexpected packet type received");
        return WS_FATAL_ERROR;
    }

    /* check request ID */
    if (reqId != ssh->reqId) {
        WLOG(WS_LOG_SFTP, "Bad request ID received");
        return WS_FATAL_ERROR;
    }
    else {
        ssh->reqId++;
    }

    if ((ret = wolfSSH_SFTP_DoStatus(ssh, reqId)) != WOLFSSH_FTP_OK) {
        if (ret == WOLFSSH_FTP_PERMISSION) {
            return WS_PERMISSIONS;
        }
        return WS_FATAL_ERROR;
    }

    return WS_SUCCESS;
}


/* Reads an open handle and returns a name list on success
 *
 * handle   the directory handle to read
 * handleSz size of handle passed in
 *
 * returns a pointer to linked name list on success and NULL on failure
 */
WS_SFTPNAME* wolfSSH_SFTP_ReadDir(WOLFSSH* ssh, byte* handle,
        word32 handleSz)
{
    int ret;

    WLOG(WS_LOG_SFTP, "Sending WOLFSSH_FTP_READDIR");
    if (ssh == NULL || handle == NULL) {
        WLOG(WS_LOG_SFTP, "Bad argument passed in");
        return NULL;
    }

    ret = SendPacketType(ssh, WOLFSSH_FTP_READDIR, handle, handleSz);
    if (ret != WS_SUCCESS) {
        return NULL;
    }

    return wolfSSH_SFTP_DoName(ssh);
}


/* Sends close dir command on a handle
 *
 * handle   the directory handle to read
 * handleSz size of handle passed in
 *
 * returns WS_SUCCESS on success
 */
int wolfSSH_SFTP_Close(WOLFSSH* ssh, byte* handle, word32 handleSz)
{
    int    ret;
    word32 reqId;
    byte   type = 0;

    WLOG(WS_LOG_SFTP, "Sending WOLFSSH_FTP_CLOSE");
    if (ssh == NULL || handle == NULL) {
        return WS_BAD_ARGUMENT;
    }

    ret = SendPacketType(ssh, WOLFSSH_FTP_CLOSE, handle, handleSz);
    if (ret != WS_SUCCESS) {
        return ret;
    }

    ret = SFTP_GetHeader(ssh, &reqId, &type);
    if (type != WOLFSSH_FTP_STATUS || ret <= 0) {
        WLOG(WS_LOG_SFTP, "Unexpected packet type");
        return WS_FATAL_ERROR;
    }

    ret = wolfSSH_SFTP_DoStatus(ssh, reqId);
    if (ret == WOLFSSH_FTP_OK) {
        return WS_SUCCESS;
    }
    else {
        return WS_FATAL_ERROR;
    }
}


/* Gets the real path name from a directory
 *
 * dir NULL terminated string with path to get real path of
 *
 * returns a WS_SFTPNAME structure on success and NULL on failure
 */
WS_SFTPNAME* wolfSSH_SFTP_RealPath(WOLFSSH* ssh, char* dir)
{
    int sz;

    WLOG(WS_LOG_SFTP, "Sending WOLFSSH_FTP_REALPATH");
    if (ssh == NULL || dir == NULL) {
        WLOG(WS_LOG_SFTP, "Bad argument passed in");
        return NULL;
    }

    sz = (int)WSTRLEN(dir);
    if (SendPacketType(ssh, WOLFSSH_FTP_REALPATH, (byte*)dir, sz) !=
            WS_SUCCESS) {
        return NULL;
    }

    /* read name response from Real Path packet */
    return wolfSSH_SFTP_DoName(ssh);
}


/* Send open directory packet, currently this function leaves handling response
 * to the caller
 *
 * dir      name of directory to read
 * dirSz    size of "dir" buffer
 *
 * returns WS_SUCCESS on success
 */
int wolfSSH_SFTP_OpenDir(WOLFSSH* ssh, byte* dir, word32 dirSz)
{
    WLOG(WS_LOG_SFTP, "Entering WOLFSSH_FTP_OPENDIR");
    if (ssh == NULL || dir == NULL) {
        return WS_BAD_ARGUMENT;
    }

    return SendPacketType(ssh, WOLFSSH_FTP_OPENDIR, dir, dirSz);
}


/* rename a file path
 *
 * old  null terminated old name
 * nw   null terminated resulting name after rename
 *
 * returns WS_SUCCESS on success
 */
int wolfSSH_SFTP_Rename(WOLFSSH* ssh, const char* old, const char* nw)
{
    WS_SFTP_FILEATRB atrb;
    byte* data;
    int   sz;
    int   ret;
    word32 reqId;
    word32 idx;
    byte   type;

    WLOG(WS_LOG_SFTP, "Entering wolfSSH_SFTP_Rename");
    if (ssh == NULL || old == NULL || nw == NULL) {
        return WS_BAD_ARGUMENT;
    }

    /* check that file exists */
    if ((ret = wolfSSH_SFTP_STAT(ssh, (char*)old, &atrb)) != WS_SUCCESS) {
        WLOG(WS_LOG_SFTP, "Error finding file to rename");
        return ret;
    }

    sz = (int)(WSTRLEN(old) + WSTRLEN(nw));
    data = (byte*)WMALLOC(sz + WOLFSSH_SFTP_HEADER + UINT32_SZ * 2,
            ssh->ctx->heap, DYNTYPE_BUFFER);
    if (data == NULL) {
        return WS_MEMORY_E;
    }

    if (SFTP_SetHeader(ssh, ssh->reqId, WOLFSSH_FTP_RENAME,
                sz + UINT32_SZ * 2, data) != WS_SUCCESS) {
        return WS_FATAL_ERROR;
    }

    /* add old name to the packet */
    idx = WOLFSSH_SFTP_HEADER;
    c32toa((word32)WSTRLEN(old), data + idx); idx += UINT32_SZ;
    WMEMCPY(data + idx, (byte*)old, WSTRLEN(old)); idx += (word32)WSTRLEN(old);

    /* add new name to the packet */
    c32toa((word32)WSTRLEN(nw), data + idx); idx += UINT32_SZ;
    WMEMCPY(data + idx, (byte*)nw, WSTRLEN(nw)); idx += (word32)WSTRLEN(nw);

    /* send header and type specific data */
    ret = wolfSSH_stream_send(ssh, data, idx);
    WFREE(data, NULL, DYNTYPE_BUFFER);
    if (ret < 0) {
        return ret;
    }

    /* Get response */
    ret = SFTP_GetHeader(ssh, &reqId, &type);
    if (ret <= 0 || type != WOLFSSH_FTP_STATUS) {
        return WS_FATAL_ERROR;
    }

    /* check request ID */
    if (reqId != ssh->reqId) {
        WLOG(WS_LOG_SFTP, "Bad request ID received");
        return WS_FATAL_ERROR;
    }
    else {
        ssh->reqId++;
    }

    if ((ret = wolfSSH_SFTP_DoStatus(ssh, reqId)) != WOLFSSH_FTP_OK) {
        if (ret == WOLFSSH_FTP_PERMISSION) {
            return WS_PERMISSIONS;
        }
        return WS_FATAL_ERROR;
    }

    return WS_SUCCESS;
}


/* removes a file
 *
 * f   file name to be removed
 * fSz size of file name
 *
 * returns WS_SUCCESS on success
 */
int wolfSSH_SFTP_Remove(WOLFSSH* ssh, char* f)
{
    WS_SFTP_FILEATRB atrb;
    int    ret;
    word32 reqId;
    byte   type;

    WLOG(WS_LOG_SFTP, "Sending WOLFSSH_FTP_REMOVE");
    if (ssh == NULL || f == NULL) {
        return WS_BAD_ARGUMENT;
    }

    /* check file is there to be removed */
    if ((ret = wolfSSH_SFTP_LSTAT(ssh, f, &atrb)) != WS_SUCCESS) {
        WLOG(WS_LOG_SFTP, "Error verifying file");
        return ret;
    }

    ret = SendPacketType(ssh, WOLFSSH_FTP_REMOVE, (byte*)f, (word32)WSTRLEN(f));
    if (ret != WS_SUCCESS) {
        return ret;
    }

    ret = SFTP_GetHeader(ssh, &reqId, &type);
    if (ret <= 0 || type != WOLFSSH_FTP_STATUS) {
        WLOG(WS_LOG_SFTP, "Unexpected packet type");
        return WS_FATAL_ERROR;
    }

    ret = wolfSSH_SFTP_DoStatus(ssh, reqId);
    if (ret == WOLFSSH_FTP_OK) {
        return WS_SUCCESS;
    }
    else {
        /* @TODO can return better error value i.e. permissions */
        return WS_FATAL_ERROR;
    }
}


/* removes a directory
 *
 * dir   name of directory to remove
 *
 * returns WS_SUCCESS on success
 */
int wolfSSH_SFTP_RMDIR(WOLFSSH* ssh, char* dir)
{
    int    ret;
    word32 reqId;
    byte   type;

    WLOG(WS_LOG_SFTP, "Sending WOLFSSH_FTP_RMDIR");
    if (ssh == NULL || dir == NULL) {
        return WS_BAD_ARGUMENT;
    }

    ret = SendPacketType(ssh, WOLFSSH_FTP_RMDIR, (byte*)dir,
            (word32)WSTRLEN(dir));
    if (ret != WS_SUCCESS) {
        return ret;
    }

    ret = SFTP_GetHeader(ssh, &reqId, &type);
    if (ret <= 0 || type != WOLFSSH_FTP_STATUS) {
        WLOG(WS_LOG_SFTP, "Unexpected packet type");
        return WS_FATAL_ERROR;
    }

    ret = wolfSSH_SFTP_DoStatus(ssh, reqId);
    if (ret == WOLFSSH_FTP_OK) {
        return WS_SUCCESS;
    }
    else {
        /* @TODO can return better error value i.e. permissions */
        ssh->error = ret;
        return WS_FATAL_ERROR;
    }
}


/* save an offset for later reget or reput command
 * frm and to should be null terminated strings
 *
 * frm      NULL terminated string holding the from name
 * to       NULL terminated string holding the to name
 * ofst     offset into file that should be saved
 *
 * return WS_SUCCESS on success
 */
int wolfSSH_SFTP_SaveOfst(WOLFSSH* ssh, char* frm, char* to, word64 ofst)
{
    int idx;
    SFTP_OFST* current;
    int frmSz, toSz;

    if (ssh == NULL || frm == NULL || to == NULL) {
        return WS_BAD_ARGUMENT;
    }

    frmSz = (int)WSTRLEN(frm);
    toSz = (int)WSTRLEN(to);

    /* find if able to save */
    for (idx = 0; idx < WOLFSSH_MAX_SFTPOFST; idx++) {
        if (ssh->sftpOfst[idx].offset == 0) {
            break;
        }
    }

    if (idx == WOLFSSH_MAX_SFTPOFST) {
        WLOG(WS_LOG_SFTP, "No free save spots found");
        return WS_MEMORY_E;
    }

    if (frmSz > WOLFSSH_MAX_FILENAME || toSz > WOLFSSH_MAX_FILENAME) {
        WLOG(WS_LOG_SFTP, "File name is too large");
        return WS_BUFFER_E;
    }

    current = &ssh->sftpOfst[idx];
    WMEMCPY(current->from, frm, frmSz);
    current->from[frmSz] = '\0';
    WMEMCPY(current->to, to, toSz);
    current->to[toSz] = '\0';
    current->offset = ofst;

    return WS_SUCCESS;
}


/* Compares the from and to name to stored values and if a match is found the
 * stored offset is returned.
 *
 * frm      NULL terminated string holding the from name
 * to       NULL terminated string holding the to name
 *
 * returns ofst size, 0 is returned if no saved offset was found
 */
word64 wolfSSH_SFTP_GetOfst(WOLFSSH* ssh, char* frm, char* to)
{
    int    idx;
    word64 ofst = 0;
    int frmSz, toSz;

    if (ssh == NULL || frm == NULL || to == NULL) {
        return WS_BAD_ARGUMENT;
    }

    frmSz = (int)WSTRLEN(frm);
    toSz  = (int)WSTRLEN(to);

    /* check if in saved list */
    for (idx = 0; idx < WOLFSSH_MAX_SFTPOFST; idx++) {
        /* check "from" file name is same */
        if ((frmSz == (int)WSTRLEN(ssh->sftpOfst[idx].from)) &&
                (WMEMCMP(frm, ssh->sftpOfst[idx].from, frmSz) == 0)) {
            /* check "to" file name is same */
            if ((toSz == (int)WSTRLEN(ssh->sftpOfst[idx].to)) &&
                (WMEMCMP(to, ssh->sftpOfst[idx].to, toSz) == 0)) {
                WLOG(WS_LOG_SFTP, "Found saved offset");
                ofst = ssh->sftpOfst[idx].offset;
                /* clear offset */
                WMEMSET(&ssh->sftpOfst[idx], 0, sizeof(SFTP_OFST));
                break;
            }
        }
    }

    return ofst;
}


/* clears out all get/put offset status stored
 *
 * returns WS_SUCCESS on success
 */
int wolfSSH_SFTP_ClearOfst(WOLFSSH* ssh)
{
    int i;

    if (ssh == NULL) {
        return WS_BAD_ARGUMENT;
    }

    for (i = 0; i < WOLFSSH_MAX_SFTPOFST; i++) {
        WMEMSET(&ssh->sftpOfst[i], 0, sizeof(SFTP_OFST));
    }

    return WS_SUCCESS;
}


/* set interrupt for get/put. This can be called by the application to break out
 * of and store the current offset of a wolfSSH_SFTP_Get or wolfSSH_SFTP_Put
 * call
 */
void wolfSSH_SFTP_Interrupt(WOLFSSH* ssh)
{
    if (ssh != NULL) {
        ssh->sftpInt = 1;
    }
}


/* Continuously loops over wolfSSH_SFTP_SendReadPacket() getting all data.
 *
 * resume   if set to 1 then stored offsets are searched for from -> to
 * statusCb can be NULL. If not NULL then callback function is called on each
 *          loop with bytes written.
 *
 * returns WS_SUCCESS on success
 */
int wolfSSH_SFTP_Get(WOLFSSH* ssh, char* from,
        char* to, byte resume, WS_STATUS_CB* statusCb)
{
    WS_SFTP_GET_STATE* state = NULL;
    long sz;
    int ret = WS_SUCCESS;

    WLOG(WS_LOG_SFTP, "Entering wolfSSH_SFTP_Get()");
    if (ssh == NULL || from == NULL || to == NULL)
        return WS_BAD_ARGUMENT;

    if (ssh->error == WS_WANT_READ || ssh->error == WS_WANT_WRITE)
        ssh->error = WS_SUCCESS;

    state = ssh->getState;
    if (state == NULL) {
        state = (WS_SFTP_GET_STATE*)WMALLOC(sizeof(WS_SFTP_GET_STATE),
                ssh->ctx->heap, DYNTYPE_SFTP_STATE);
        if (state == NULL) {
            ssh->error = WS_MEMORY_E;
            return WS_FATAL_ERROR;
        }
        WMEMSET(state, 0, sizeof(WS_SFTP_GET_STATE));
        ssh->getState = state;
        state->state = STATE_GET_INIT;
    }

    for (;;) {
        switch (state->state) {

            case STATE_GET_INIT:
                WLOG(WS_LOG_SFTP, "SFTP GET STATE: INIT");
                state->state = STATE_GET_LSTAT;
                FALL_THROUGH;

            case STATE_GET_LSTAT:
                WLOG(WS_LOG_SFTP, "SFTP GET STATE: LSTAT");
                ret = wolfSSH_SFTP_LSTAT(ssh, from, &state->attrib);
                if (ret != WS_SUCCESS) {
                    WLOG(WS_LOG_SFTP, "Error verifying file");
                    return WS_FATAL_ERROR;
                }
                state->handleSz = WOLFSSH_MAX_HANDLE;
                state->state = STATE_GET_OPEN_REMOTE;
                FALL_THROUGH;

            case STATE_GET_OPEN_REMOTE:
                WLOG(WS_LOG_SFTP, "SFTP GET STATE: OPEN REMOTE");
                /* open file and get handle */
                ret = wolfSSH_SFTP_Open(ssh, from, WOLFSSH_FXF_READ, NULL,
                        state->handle, &state->handleSz);
                if (ret != WS_SUCCESS) {
                    WLOG(WS_LOG_SFTP, "Error getting handle");
                    return WS_FATAL_ERROR;
                }
                state->state = STATE_GET_LOOKUP_OFFSET;
                FALL_THROUGH;

            case STATE_GET_LOOKUP_OFFSET:
                WLOG(WS_LOG_SFTP, "SFTP GET STATE: LOOKUP OFFSET");
                /* if resuming then check for saved offset */
                if (resume) {
                    state->gOfst = (long)wolfSSH_SFTP_GetOfst(ssh, from, to);
                }
                state->state = STATE_GET_OPEN_LOCAL;
                FALL_THROUGH;

            case STATE_GET_OPEN_LOCAL:
                WLOG(WS_LOG_SFTP, "SFTP GET STATE: OPEN LOCAL");
                if (state->gOfst > 0)
                    ret = WFOPEN(&state->fl, to, "ab");
                else
                    ret = WFOPEN(&state->fl, to, "wb");
                if (ret != 0) {
                    WLOG(WS_LOG_SFTP, "Unable to open output file");
                    ssh->error = WS_BAD_FILE_E;
                    return WS_FATAL_ERROR;
                }
                state->state = STATE_GET_READ;
                FALL_THROUGH;

            case STATE_GET_READ:
                WLOG(WS_LOG_SFTP, "SFTP GET STATE: GET READ");
                ret = WS_SUCCESS;
                do {
                    sz = wolfSSH_SFTP_SendReadPacket(ssh,
                            state->handle, state->handleSz,
                            state->gOfst, state->r,
                            WOLFSSH_MAX_SFTP_RW);
                    if (sz > 0) {
                        if ((long)WFWRITE(state->r, 1,
                                          sz, state->fl) != sz) {
                            WLOG(WS_LOG_SFTP, "Error writing to file");
                            ret = WS_FATAL_ERROR;
                            break;
                        }
                        state->gOfst += sz;
                        if (statusCb != NULL) {
                            statusCb(ssh, state->gOfst, from);
                        }
                    }
                } while (sz > 0 && ssh->sftpInt == 0);
                if (ssh->sftpInt) {
                    WLOG(WS_LOG_SFTP, "Interrupted, trying to save offset");
                    wolfSSH_SFTP_SaveOfst(ssh, from, to, state->gOfst);
                }
                ssh->sftpInt = 0;
                state->state = STATE_GET_CLOSE_LOCAL;
                FALL_THROUGH;

            case STATE_GET_CLOSE_LOCAL:
                WLOG(WS_LOG_SFTP, "SFTP GET STATE: CLOSE LOCAL");
                WFCLOSE(state->fl);
                state->state = STATE_GET_CLOSE_REMOTE;
                FALL_THROUGH;

            case STATE_GET_CLOSE_REMOTE:
                WLOG(WS_LOG_SFTP, "SFTP GET STATE: CLOSE REMOTE");
                ret = wolfSSH_SFTP_Close(ssh,
                                         state->handle, state->handleSz);
                if (ret != WS_SUCCESS) {
                    WLOG(WS_LOG_SFTP, "Error closing handle");
                    return WS_FATAL_ERROR;
                }
                state->state = STATE_GET_CLEANUP;
                FALL_THROUGH;

            case STATE_GET_CLEANUP:
                WLOG(WS_LOG_SFTP, "SFTP GET STATE: CLEANUP");
                if (ssh->getState != NULL) {
                    WFREE(ssh->getState, ssh->ctx->heap, DYNTYPE_SFTP_STATE);
                    ssh->getState = NULL;
                }
                return WS_SUCCESS;

            default:
                WLOG(WS_LOG_DEBUG, "Bad SFTP Get state, program error");
                return WS_INPUT_CASE_E;
        }
    }

    return WS_SUCCESS;
}


/* Higher level command for pushing data to SFTP server. Loops over
 * wolfSSH_SFTP_Write
 *
 * resume   if set to 1 then stored offsets are searched for from -> to
 * statusCb can be NULL. If not NULL then callback function is called on each
 *          loop with bytes written.
 *
 * returns WS_SUCCESS on success
 */
int wolfSSH_SFTP_Put(WOLFSSH* ssh, char* from, char* to, byte resume,
        WS_STATUS_CB* statusCb)
{
    byte handle[WOLFSSH_MAX_HANDLE];
    WFILE* fl;
    long   pOfst = 0;
    word32 handleSz;
    int    ret;

    if (ssh == NULL || from == NULL || to == NULL) {
        return WS_BAD_ARGUMENT;
    }

    if (resume) {
        /* check if offset was stored */
        pOfst = (long)wolfSSH_SFTP_GetOfst(ssh, from, to);
    }

    /* open file and get handle */
    handleSz = WOLFSSH_MAX_HANDLE;
    if ((ret = wolfSSH_SFTP_Open(ssh, to, (WOLFSSH_FXF_WRITE |
                    WOLFSSH_FXF_CREAT | WOLFSSH_FXF_TRUNC), NULL,
            handle, &handleSz)) != WS_SUCCESS) {
        WLOG(WS_LOG_SFTP, "Error getting handle");
        return ret;
    }

    ret = WFOPEN(&fl, from, "rb");

    if (ret != 0) {
        WLOG(WS_LOG_SFTP, "Unable to open file");
        ret = WS_FATAL_ERROR;
    }
    else {
        byte r[WOLFSSH_MAX_SFTP_RW];
        int rSz;
        int sz;

        ret = WS_SUCCESS;
        do {
            rSz = (int)WFREAD(r, 1, WOLFSSH_MAX_SFTP_RW, fl);
            if (rSz <= 0 ) {
                break; /* either at end of file or error */
            }
            sz = wolfSSH_SFTP_SendWritePacket(ssh, handle, handleSz, pOfst,
                    r, rSz);
            if (sz > 0) {
                pOfst += sz;
                if (statusCb != NULL) {
                    statusCb(ssh, pOfst, from);
                }
            }
            wolfSSH_CheckReceivePending(ssh); /* check for adjust window packet */
        } while (sz > 0 && ssh->sftpInt == 0);
        if (ssh->sftpInt) {
            wolfSSH_SFTP_SaveOfst(ssh, from, to, pOfst);
        }
        ssh->sftpInt = 0;
        WFCLOSE(fl);
    }

    if (wolfSSH_SFTP_Close(ssh, handle, handleSz) != WS_SUCCESS) {
        WLOG(WS_LOG_SFTP, "Error closing handle");
        if (ret == WS_SUCCESS) ret = WS_FATAL_ERROR;
    }

    return ret;
}


/* called when wolfSSH_free() is called
 * return WS_SUCCESS on success */
int wolfSSH_SFTP_free(WOLFSSH* ssh)
{
    (void)ssh;
#ifdef WOLFSSH_STOREHANDLE
    {
        WS_HANDLE_LIST* cur = ssh->handleList;

        /* go through and free handles and make sure files are closed */
        while (cur != NULL) {
            WCLOSE(*((WFD*)cur->handle));
            if (SFTP_RemoveHandleNode(ssh, cur->handle, cur->handleSz)
                    != WS_SUCCESS) {
                return WS_FATAL_ERROR;
            }
            cur = ssh->handleList;
        }
    }
#endif
    wolfSSH_SFTP_ClearState(ssh, STATE_ID_ALL);
    return WS_SUCCESS;
}

#endif /* WOLFSSH_SFTP */

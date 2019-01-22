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
    STATE_ID_ALL        = 0, /* default to select all */
    STATE_ID_LSTAT      = 0x01,
    STATE_ID_OPEN       = 0x02,
    STATE_ID_GET        = 0x04,
    STATE_ID_SEND_READ  = 0x08,
    STATE_ID_CLOSE      = 0x10,
    STATE_ID_GET_HANDLE = 0x20,
    STATE_ID_NAME       = 0x40,
    STATE_ID_SEND       = 0x80,
    STATE_ID_LS         = 0x100,
    STATE_ID_READDIR    = 0x200,
    STATE_ID_PUT        = 0x0400,
    STATE_ID_SEND_WRITE = 0x0800,
    STATE_ID_RM         = 0x1000,
    STATE_ID_MKDIR      = 0x2000,
    STATE_ID_RMDIR      = 0x4000,
    STATE_ID_RENAME     = 0x8000,
    STATE_ID_RECV       = 0x10000,
};

enum WS_SFTP_RMDIR_STATE_ID {
    STATE_RMDIR_SEND,
    STATE_RMDIR_GET,
    STATE_RMDIR_STATUS
};

enum WS_SFTP_MKDIR_STATE_ID {
    STATE_MKDIR_SEND,
    STATE_MKDIR_GET,
    STATE_MKDIR_STATUS
};

enum WS_SFTP_RM_STATE_ID {
    STATE_RM_LSTAT,
    STATE_RM_SEND,
    STATE_RM_GET,
    STATE_RM_DOSTATUS
};

enum WS_SFTP_NAME_STATE_ID {
    SFTP_NAME_GETHEADER_PACKET,
    SFTP_NAME_DO_STATUS,
    SFTP_NAME_GET_PACKET
};

enum WS_SFTP_REAL_STATE_ID {
    SFTP_REAL_SEND_PACKET,
    SFTP_REAL_GET_PACKET
};

enum WS_SFTP_RECV_STATE_ID {
    STATE_RECV_READ,
    STATE_RECV_DO,
    STATE_RECV_SEND
};

enum WS_SFTP_READDIR_STATE_ID {
    STATE_READDIR_SEND,
    STATE_READDIR_NAME
};

enum WS_SFTP_SEND_STATE_ID {
    SFTP_BUILD_PACKET,
    SFTP_SEND_PACKET
};

enum WS_SFTP_LS_STATE_ID {
    STATE_LS_REALPATH,
    STATE_LS_OPENDIR,
    STATE_LS_GETHANDLE,
    STATE_LS_READDIR,
    STATE_LS_CLOSE
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

    byte*  data;
    word32 sz;
    word32 idx;
    byte   type;
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


/* similar to open state, could refactor */
typedef struct WS_SFTP_NAME_STATE {
    enum WS_SFTP_NAME_STATE_ID state;
    byte* data;
    int sz;
    word32 idx;
} WS_SFTP_NAME_STATE;

/* similar to open state, could refactor */
typedef struct WS_SFTP_SEND_STATE {
    enum WS_SFTP_SEND_STATE_ID state;
    byte* data;
    int sz;
    word32 idx;
} WS_SFTP_SEND_STATE;

/* similar to open state, could refactor */
typedef struct WS_SFTP_READDIR_STATE {
    enum WS_SFTP_READDIR_STATE_ID state;
    byte* data;
    int sz;
    word32 idx;
} WS_SFTP_READDIR_STATE;

/* similar to open state, could refactor */
typedef struct WS_SFTP_RM_STATE {
    enum WS_SFTP_RM_STATE_ID state;
    byte* data;
    int sz;
    word32 idx;
} WS_SFTP_RM_STATE;

/* similar to open state, could refactor */
typedef struct WS_SFTP_MKDIR_STATE {
    enum WS_SFTP_MKDIR_STATE_ID state;
    byte* data;
    int sz;
    word32 idx;
} WS_SFTP_MKDIR_STATE;

/* similar to open state, could refactor */
typedef struct WS_SFTP_RMDIR_STATE {
    enum WS_SFTP_RMDIR_STATE_ID state;
    byte* data;
    int sz;
    word32 idx;
} WS_SFTP_RMDIR_STATE;

typedef struct WS_SFTP_RECV_STATE {
    enum WS_SFTP_RECV_STATE_ID state;
    byte* data;
    int sz;
    word32 idx;
    byte type;
    byte toSend;
    int reqId;
} WS_SFTP_RECV_STATE;

typedef struct WS_SFTP_LS_STATE {
    enum WS_SFTP_LS_STATE_ID state;
    byte handle[WOLFSSH_MAX_HANDLE];
    int sz;
    WS_SFTPNAME* name;
} WS_SFTP_LS_STATE;


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
#ifndef USE_WINDOWS_API
    WFILE* fl;
#else
    HANDLE fileHandle;
    OVERLAPPED offset;
#endif
    long gOfst;
    word32 handleSz;
    byte handle[WOLFSSH_MAX_HANDLE];
    byte r[WOLFSSH_MAX_SFTP_RW];
} WS_SFTP_GET_STATE;


enum WS_SFTP_PUT_STATE_ID {
    STATE_PUT_INIT,
    STATE_PUT_LOOKUP_OFFSET,
    STATE_PUT_OPEN_REMOTE,
    STATE_PUT_OPEN_LOCAL,
    STATE_PUT_WRITE,
    STATE_PUT_CLOSE_LOCAL,
    STATE_PUT_CLOSE_REMOTE,
    STATE_PUT_CLEANUP
};

typedef struct WS_SFTP_PUT_STATE {
    enum WS_SFTP_PUT_STATE_ID state;
#ifndef USE_WINDOWS_API
    WFILE* fl;
#else
    HANDLE fileHandle;
    OVERLAPPED offset;
#endif
    long pOfst;
    word32 handleSz;
    int rSz;
    byte handle[WOLFSSH_MAX_HANDLE];
    byte r[WOLFSSH_MAX_SFTP_RW];
} WS_SFTP_PUT_STATE;


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


enum WS_SFTP_SEND_WRITE_STATE_ID {
    STATE_SEND_WRITE_INIT,
    STATE_SEND_WRITE_SEND_HEADER,
    STATE_SEND_WRITE_SEND_BODY,
    STATE_SEND_WRITE_GET_HEADER,
    STATE_SEND_WRITE_READ_STATUS,
    STATE_SEND_WRITE_DO_STATUS,
    STATE_SEND_WRITE_CLEANUP
};

typedef struct WS_SFTP_SEND_WRITE_STATE {
    enum WS_SFTP_SEND_WRITE_STATE_ID state;
    byte* data;
    word32 reqId;
    word32 idx;
    int maxSz;
    int sentSz;
} WS_SFTP_SEND_WRITE_STATE;


enum WS_SFTP_CLOSE_STATE_ID {
    STATE_CLOSE_INIT,
    STATE_CLOSE_SEND,
    STATE_CLOSE_GET_HEADER,
    STATE_CLOSE_DO_STATUS,
    STATE_CLOSE_CLEANUP
};

typedef struct WS_SFTP_CLOSE_STATE {
    enum WS_SFTP_CLOSE_STATE_ID state;
    word32 reqId;
    int    sz;
    byte*  data;
} WS_SFTP_CLOSE_STATE;


enum WS_SFTP_GET_HANDLE_STATE_ID {
    STATE_GET_HANDLE_INIT,
    STATE_GET_HANDLE_GET_HEADER,
    STATE_GET_HANDLE_DO_STATUS,
    STATE_GET_HANDLE_CHECK_REQ_ID,
    STATE_GET_HANDLE_READ,
    STATE_GET_HANDLE_CLEANUP
};

typedef struct WS_SFTP_GET_HANDLE_STATE {
    enum WS_SFTP_GET_HANDLE_STATE_ID state;
    word32 reqId;
    word32 bufSz;
    byte buf[WOLFSSH_MAX_HANDLE + UINT32_SZ];
} WS_SFTP_GET_HANDLE_STATE;


enum WS_SFTP_RENAME_STATE_ID {
    STATE_RENAME_INIT,
    STATE_RENAME_GET_STAT,
    STATE_RENAME_SEND,
    STATE_RENAME_GET_HEADER,
    STATE_RENAME_READ_STATUS,
    STATE_RENAME_DO_STATUS,
    STATE_RENAME_CLEANUP
};

typedef struct WS_SFTP_RENAME_STATE {
    enum WS_SFTP_RENAME_STATE_ID state;
    WS_SFTP_FILEATRB atrb;
    byte* data;
    int sz;
    int maxSz;
    word32 reqId;
    word32 idx;
} WS_SFTP_RENAME_STATE;


static int SendPacketType(WOLFSSH* ssh, byte type, byte* buf, word32 bufSz);
static int SFTP_ParseAtributes_buffer(WOLFSSH* ssh,  WS_SFTP_FILEATRB* atr,
        byte* buf, word32* idx, word32 maxIdx);
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
            ssh->getState = NULL;
        }

        if (state & STATE_ID_LSTAT) {
            if (ssh->lstatState) {
                XFREE(ssh->lstatState->data, ssh->ctx->heap, DYNTYPE_BUFFER);
                XFREE(ssh->lstatState, ssh->ctx->heap, DYNTYPE_SFTP_STATE);
                ssh->lstatState = NULL;
            }
        }

        if (state & STATE_ID_OPEN) {
            XFREE(ssh->openState, ssh->ctx->heap, DYNTYPE_SFTP_STATE);
            ssh->openState = NULL;
        }

        if (state & STATE_ID_SEND_READ) {
            XFREE(ssh->sendReadState, ssh->ctx->heap, DYNTYPE_SFTP_STATE);
            ssh->sendReadState = NULL;
        }

        if (state & STATE_ID_CLOSE) {
            XFREE(ssh->closeState, ssh->ctx->heap, DYNTYPE_SFTP_STATE);
            ssh->closeState  = NULL;
        }

        if (state & STATE_ID_GET_HANDLE) {
            XFREE(ssh->getHandleState, ssh->ctx->heap, DYNTYPE_SFTP_STATE);
            ssh->getHandleState = NULL;
        }

        if (state & STATE_ID_NAME) {
            if (ssh->nameState) {
                XFREE(ssh->nameState->data, ssh->ctx->heap, DYNTYPE_BUFFER);
                XFREE(ssh->nameState, ssh->ctx->heap, DYNTYPE_SFTP_STATE);
                ssh->nameState = NULL;
            }
        }

        if (state & STATE_ID_SEND) {
            if (ssh->sendState) {
                XFREE(ssh->sendState->data, ssh->ctx->heap, DYNTYPE_BUFFER);
                XFREE(ssh->sendState, ssh->ctx->heap, DYNTYPE_SFTP_STATE);
                ssh->sendState = NULL;
            }
        }

        if (state & STATE_ID_LS) {
            if (ssh->lsState) {
                XFREE(ssh->lsState, ssh->ctx->heap, DYNTYPE_SFTP_STATE);
                ssh->lsState = NULL;
            }
        }

        if (state & STATE_ID_READDIR) {
            if (ssh->readDirState) {
                XFREE(ssh->readDirState, ssh->ctx->heap, DYNTYPE_SFTP_STATE);
                ssh->readDirState = NULL;
            }
        }

        if (state & STATE_ID_PUT) {
            XFREE(ssh->putState, ssh->ctx->heap, DYNTYPE_SFTP_STATE);
            ssh->putState = NULL;
        }

        if (state & STATE_ID_SEND_WRITE) {
            XFREE(ssh->sendWriteState, ssh->ctx->heap, DYNTYPE_SFTP_STATE);
            ssh->sendWriteState = NULL;
        }

        if (state & STATE_ID_RM) {
            if (ssh->rmState != NULL)
                XFREE(ssh->rmState->data, ssh->ctx->heap, DYNTYPE_BUFFER);
            XFREE(ssh->rmState, ssh->ctx->heap, DYNTYPE_SFTP_STATE);
            ssh->rmState = NULL;
        }

        if (state & STATE_ID_MKDIR) {
            if (ssh->mkdirState != NULL)
                XFREE(ssh->mkdirState->data, ssh->ctx->heap, DYNTYPE_BUFFER);
            XFREE(ssh->mkdirState, ssh->ctx->heap, DYNTYPE_SFTP_STATE);
            ssh->mkdirState = NULL;
        }

        if (state & STATE_ID_RMDIR) {
            if (ssh->rmdirState != NULL)
                XFREE(ssh->rmdirState->data, ssh->ctx->heap, DYNTYPE_BUFFER);
            XFREE(ssh->rmdirState, ssh->ctx->heap, DYNTYPE_SFTP_STATE);
            ssh->rmdirState = NULL;
        }

        if (state & STATE_ID_RENAME) {
            if (ssh->renameState != NULL)
                XFREE(ssh->renameState->data, ssh->ctx->heap, DYNTYPE_BUFFER);
            XFREE(ssh->renameState, ssh->ctx->heap, DYNTYPE_SFTP_STATE);
            ssh->renameState = NULL;
        }

        if (state & STATE_ID_RECV) {
            if (ssh->recvState != NULL)
                XFREE(ssh->recvState->data, ssh->ctx->heap, DYNTYPE_BUFFER);
            XFREE(ssh->recvState, ssh->ctx->heap, DYNTYPE_SFTP_STATE);
            ssh->recvState = NULL;
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
        return WS_BAD_ARGUMENT;
    }

    ret = wolfSSH_stream_read(ssh, buf, sizeof(buf));
    if (ret < 0) {
        return ret;
    }

    if (ret < WOLFSSH_SFTP_HEADER) {
        WLOG(WS_LOG_SFTP, "Unable to read SFTP header");
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

static int SFTP_CreatePacket(WOLFSSH* ssh, byte type, byte* out, word32 outSz,
        byte* data, word32 dataSz)
{
    if (outSz < WOLFSSH_SFTP_HEADER + UINT32_SZ ||
            (data == NULL && dataSz > 0) ||
            out == NULL || ssh == NULL) {
        return WS_BAD_ARGUMENT;
    }

    if (SFTP_SetHeader(ssh, ssh->reqId, type, outSz - WOLFSSH_SFTP_HEADER, out)
            != WS_SUCCESS) {
        return WS_FATAL_ERROR;
    }
    c32toa(outSz - WOLFSSH_SFTP_HEADER - UINT32_SZ, out + WOLFSSH_SFTP_HEADER);
    if (data) {
        if (dataSz + UINT32_SZ + WOLFSSH_SFTP_HEADER > outSz) {
            WLOG(WS_LOG_SFTP, "Data size was to large for packet buffer");
            return WS_BUFFER_E;
        }
        WMEMCPY(out + UINT32_SZ + WOLFSSH_SFTP_HEADER, data, dataSz);
    }
    return WS_SUCCESS;
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


#ifndef NO_WOLFSSH_SERVER

static int SFTP_GetAttributes(const char* fileName, WS_SFTP_FILEATRB* atr,
        byte link);
static int SFTP_GetAttributes_Handle(WOLFSSH* ssh, byte* handle, int handleSz,
        WS_SFTP_FILEATRB* atr);

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


/* store a buffer to send from wolfSSH_SFTP_read. Free's previous data in
 * ssh->recvState and takes over control of "buf"
 */
static void wolfSSH_SFTP_RecvSetSend(WOLFSSH* ssh, byte* buf, int sz)
{
    WS_SFTP_RECV_STATE* state = NULL;

    if (ssh == NULL || sz < 0 || buf == NULL) {
        return;
    }

    state = ssh->recvState;
    if (state == NULL) {
        return;
    }

    /* free up existing data if needed */
    if (buf != state->data && state->data != NULL) {
        WFREE(state->data, ssh->ctx->heap, DYNTYPE_BUFFER);
        state->data = NULL;
    }

    /* take over control of buffer */
    state->data = buf;
    state->sz   = sz;
    state->toSend = 1;
}


/* Getter function for data pointer */
static byte* wolfSSH_SFTP_RecvGetData(WOLFSSH* ssh)
{
    if (ssh && ssh->recvState)
        return ssh->recvState->data;
    return NULL;
}


/* returns WS_SUCCESS on success */
static int wolfSSH_SFTP_RecvRealPath(WOLFSSH* ssh, int reqId, byte* data,
        int maxSz)
{
    WS_SFTP_FILEATRB atr;
    char  r[WOLFSSH_MAX_FILENAME];
    word32 rSz;
    word32 lidx = 0;
    word32 i;
    byte* out;
    word32 outSz = 0;

    WLOG(WS_LOG_SFTP, "Receiving WOLFSSH_FTP_REALPATH");

    if (ssh == NULL) {
        WLOG(WS_LOG_SFTP, "Bad argument passed in");
        return WS_BAD_ARGUMENT;
    }

    if (maxSz < UINT32_SZ) {
        /* not enough for an ato32 call */
        return WS_BUFFER_E;
    }

    ato32(data + lidx, &rSz);
    if (rSz > WOLFSSH_MAX_FILENAME || (int)(rSz + UINT32_SZ) > maxSz) {
        return WS_BUFFER_E;
    }
    lidx += UINT32_SZ;
    WMEMCPY(r, data + lidx, rSz);
    r[rSz] = '\0';

    /* get working directory in the case of receiving non absolute path */
    if (r[0] != '/' && r[1] != ':') {
        char wd[WOLFSSH_MAX_FILENAME];
        if (ssh->sftpDefaultPath) {
            XSTRNCPY(wd, ssh->sftpDefaultPath, sizeof(wd));
        }
        else {
        #ifndef USE_WINDOWS_API
            if (WGETCWD(wd, WOLFSSH_MAX_FILENAME) == NULL) {
                WLOG(WS_LOG_SFTP, "Unable to get current working directory");
                if (wolfSSH_SFTP_CreateStatus(ssh, WOLFSSH_FTP_FAILURE, reqId,
                        "Directory error", "English", NULL, &outSz)
                        != WS_SIZE_ONLY) {
                    return WS_FATAL_ERROR;
                }
                out = (byte*) WMALLOC(outSz, ssh->ctx->heap, DYNTYPE_BUFFER);
                if (out == NULL) {
                    return WS_MEMORY_E;
                }
                if (wolfSSH_SFTP_CreateStatus(ssh, WOLFSSH_FTP_FAILURE, reqId,
                        "Directory error", "English", out, &outSz)
                        != WS_SUCCESS) {
                    WFREE(out, ssh->ctx->heap, DYNTYPE_BUFFER);
                    return WS_FATAL_ERROR;
                }
                wolfSSH_SFTP_RecvSetSend(ssh, out, outSz);
                return WS_BAD_FILE_E;
            }
        #endif
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
    outSz = WOLFSSH_SFTP_HEADER + (UINT32_SZ * 3) + (rSz * 2);
    WMEMSET(&atr, 0, sizeof(WS_SFTP_FILEATRB));
    outSz += SFTP_AtributesSz(ssh, &atr);
    lidx = 0;

    /* reuse state buffer if large enough */
    out = (outSz > (word32)maxSz)?
            (byte*)WMALLOC(outSz, ssh->ctx->heap, DYNTYPE_BUFFER) :
            wolfSSH_SFTP_RecvGetData(ssh);
    if (out == NULL) {
        return WS_MEMORY_E;
    }

    SFTP_SetHeader(ssh, reqId, WOLFSSH_FTP_NAME,
            outSz - WOLFSSH_SFTP_HEADER, out);
    lidx += WOLFSSH_SFTP_HEADER;

    /* set number of files */
    c32toa(1, out + lidx); lidx += UINT32_SZ; /* only sending one file name */

    /* set file name size and string */
    c32toa(rSz, out + lidx); lidx += UINT32_SZ;
    WMEMCPY(out + lidx, r, rSz); lidx += rSz;

    /* set long name size and string */
    c32toa(rSz, out + lidx); lidx += UINT32_SZ;
    WMEMCPY(out + lidx, r, rSz); lidx += rSz;

    /* set attributes */
    SFTP_SetAttributes(ssh, out + lidx, outSz - lidx, &atr);

    /* set send out buffer, "out" buffer is taken over by "ssh" */
    wolfSSH_SFTP_RecvSetSend(ssh, out, outSz);
    return WS_SUCCESS;
}


/* Look for incoming packet and handle it
 *
 * returns WS_SUCCESS on success
 */
int wolfSSH_SFTP_read(WOLFSSH* ssh)
{
    int maxSz, ret = WS_SUCCESS;
    WS_SFTP_RECV_STATE* state = NULL;

    if (ssh == NULL)
        return WS_BAD_ARGUMENT;

    if (ssh->error == WS_WANT_READ || ssh->error == WS_WANT_WRITE)
        ssh->error = WS_SUCCESS;

    state = ssh->recvState;
    if (state == NULL) {
        state = (WS_SFTP_RECV_STATE*)WMALLOC(sizeof(WS_SFTP_RECV_STATE),
                ssh->ctx->heap, DYNTYPE_SFTP_STATE);
        if (state == NULL) {
            ssh->error = WS_MEMORY_E;
            return WS_FATAL_ERROR;
        }
        WMEMSET(state, 0, sizeof(WS_SFTP_RECV_STATE));
        ssh->recvState = state;
        state->state = STATE_RECV_READ;
    }

    switch (state->state) {
        case STATE_RECV_READ:
            /* Wait for packet to come in then handle it, maxSz is the size of
             * packet expected to come. */
            state->sz = SFTP_GetHeader(ssh, (word32*)&state->reqId, &state->type);
            if (state->sz <= 0) {
                return WS_FATAL_ERROR;
            }

            ssh->reqId  = state->reqId;
            state->data = (byte*)WMALLOC(state->sz, ssh->ctx->heap,
                    DYNTYPE_BUFFER);
            if (state->data == NULL) {
                return WS_MEMORY_E;
            }

            state->state = STATE_RECV_DO;
            FALL_THROUGH;
            /* no break */

        case STATE_RECV_DO:
            do {
                ret = wolfSSH_stream_read(ssh, state->data + state->idx,
                        state->sz - state->idx);
                if (ret < 0) {
                    if (ssh->error != WS_WANT_READ && ssh->error != WS_WANT_WRITE)
                        wolfSSH_SFTP_ClearState(ssh, STATE_ID_RECV);
                    return ret;
                }
                state->idx += ret;
            } while ((int)state->idx < state->sz);

            switch (state->type) {
                case WOLFSSH_FTP_REALPATH:
                    ret = wolfSSH_SFTP_RecvRealPath(ssh, state->reqId,
                            state->data, state->sz);
                    break;
            #ifndef _WIN32_WCE
                case WOLFSSH_FTP_RMDIR:
                    ret = wolfSSH_SFTP_RecvRMDIR(ssh, state->reqId,
                            state->data, state->sz);
                    break;

                case WOLFSSH_FTP_MKDIR:
                    ret = wolfSSH_SFTP_RecvMKDIR(ssh, state->reqId,
                            state->data, state->sz);
                    break;

                case WOLFSSH_FTP_STAT:
                    ret = wolfSSH_SFTP_RecvSTAT(ssh, state->reqId,
                            state->data, state->sz);
                    break;
            #endif

                case WOLFSSH_FTP_LSTAT:
                    ret = wolfSSH_SFTP_RecvLSTAT(ssh, state->reqId,
                            state->data, state->sz);
                    break;

            #ifndef USE_WINDOWS_API
                case WOLFSSH_FTP_FSTAT:
                    ret = wolfSSH_SFTP_RecvFSTAT(ssh, state->reqId,
                            state->data, state->sz);
                    break;
            #endif

                case WOLFSSH_FTP_OPEN:
                    ret = wolfSSH_SFTP_RecvOpen(ssh, state->reqId,
                            state->data, state->sz);
                    break;

                case WOLFSSH_FTP_READ:
                    ret = wolfSSH_SFTP_RecvRead(ssh, state->reqId,
                            state->data, state->sz);
                    break;

                case WOLFSSH_FTP_WRITE:
                    ret = wolfSSH_SFTP_RecvWrite(ssh, state->reqId,
                            state->data, state->sz);
                    break;

                case WOLFSSH_FTP_CLOSE:
                    ret = wolfSSH_SFTP_RecvClose(ssh, state->reqId,
                            state->data, state->sz);
                    break;

                case WOLFSSH_FTP_REMOVE:
                    ret = wolfSSH_SFTP_RecvRemove(ssh, state->reqId,
                            state->data, state->sz);
                    break;

                case WOLFSSH_FTP_RENAME:
                    ret = wolfSSH_SFTP_RecvRename(ssh, state->reqId,
                            state->data, state->sz);
                    break;
            #ifndef _WIN32_WCE
                case WOLFSSH_FTP_SETSTAT:
                    ret = wolfSSH_SFTP_RecvSetSTAT(ssh, state->reqId,
                            state->data, state->sz);
                    break;
            #endif

            #ifndef NO_WOLFSSH_DIR
                case WOLFSSH_FTP_OPENDIR:
                    ret = wolfSSH_SFTP_RecvOpenDir(ssh, state->reqId,
                            state->data, state->sz);
                    break;

                case WOLFSSH_FTP_READDIR:
                    ret = wolfSSH_SFTP_RecvReadDir(ssh, state->reqId,
                            state->data, state->sz);
                    break;
            #endif

                default:
                    WLOG(WS_LOG_SFTP, "Unknown packet type [%d] received",
                            state->type);
                    if (wolfSSH_SFTP_CreateStatus(ssh, WOLFSSH_FTP_FAILURE,
                                state->reqId, "Unknown/Unsupported packet type",
                                "English", NULL, (word32*)&maxSz) != WS_SIZE_ONLY) {
                        wolfSSH_SFTP_ClearState(ssh, STATE_ID_RECV);
                        return WS_FATAL_ERROR;
                    }


                    if (maxSz > state->sz) {
                        WFREE(state->data, ssh->ctx->heap, DYNTYPE_BUFFER);
                        state->data = (byte*)WMALLOC(maxSz, ssh->ctx->heap,
                                DYNTYPE_BUFFER);
                        if (state->data == NULL) {
                            wolfSSH_SFTP_ClearState(ssh, STATE_ID_RECV);
                            return WS_FATAL_ERROR;
                        }
                        state->sz = maxSz;
                    }
                    ret = wolfSSH_SFTP_CreateStatus(ssh, WOLFSSH_FTP_FAILURE,
                            state->reqId,
                            "Unknown/Unsupported packet type", "English",
                            state->data, (word32*)&state->sz);
                    if (ret == WS_SUCCESS) {
                        wolfSSH_SFTP_RecvSetSend(ssh, state->data, state->sz);
                    }
            }

            /* break out if encountering an error with nothing stored to send */
            if (ret < 0 && !state->toSend) {
                if (ssh->error != WS_WANT_READ && ssh->error != WS_WANT_WRITE)
                    wolfSSH_SFTP_ClearState(ssh, STATE_ID_RECV);
                return ret;
            }
            state->idx   = 0;
            state->state = STATE_RECV_SEND;
            FALL_THROUGH;
            /* no break */

        case STATE_RECV_SEND:
            if (state->toSend) {
                do {
                    int err;
                    ret = wolfSSH_stream_send(ssh, state->data + state->idx,
                            state->sz - state->idx);
                    if (ret < 0) {
                        if (ssh->error != WS_WANT_READ &&
                                ssh->error != WS_WANT_WRITE)
                            wolfSSH_SFTP_ClearState(ssh, STATE_ID_RECV);
                        return WS_FATAL_ERROR;
                    }

                    /* check if there is more to be sent. This could be due to
                     * limit on channel size */
                    state->idx += ret;

                    /* do not block on receive pending */
                    err = wolfSSH_get_error(ssh);
                    wolfSSH_CheckReceivePending(ssh);
                    ssh->error = err;
                } while ((int)state->idx < state->sz);
                ret = WS_SUCCESS;
                state->toSend = 0;
            }
            wolfSSH_SFTP_ClearState(ssh, STATE_ID_RECV);
            return ret;

        default:
            WLOG(WS_LOG_SFTP, "Unknown SFTP read state");
            wolfSSH_SFTP_ClearState(ssh, STATE_ID_RECV);
            return WS_FATAL_ERROR;

    }

    return WS_SUCCESS;
}


/* Create a status packet
 *
 * structure of status packet is as follows
 * {
 *  uint32 error code
 *  string error msg
 *  string language
 * }
 *
 * If out == NULL then outSz is set to the size of buffer required.
 *  WS_SIZE_ONLY is returned in this case.
 *
 * returns WS_SUCCESS on success
 */
int wolfSSH_SFTP_CreateStatus(WOLFSSH* ssh, word32 status, word32 reqId,
        const char* reason, const char* lang, byte* out, word32* outSz)
{
    word32 sz;
    word32 maxSz;
    word32 idx = 0;

    if (ssh == NULL || outSz == NULL) {
        return WS_BAD_ARGUMENT;
    }

    maxSz = WOLFSSH_SFTP_HEADER + (UINT32_SZ * 3);
    if (reason != NULL) {
        maxSz += (word32)WSTRLEN(reason);
    }
    if (lang != NULL) {
        maxSz += (word32)WSTRLEN(lang);
    }

    if (out == NULL) {
        *outSz = maxSz;
        return WS_SIZE_ONLY;
    }

    if (maxSz > *outSz) {
        WLOG(WS_LOG_SFTP, "Not enough room in buffer for status packet");
        return WS_BUFFER_E;
    }

    idx += WOLFSSH_SFTP_HEADER;
    if (SFTP_SetHeader(ssh, reqId, WOLFSSH_FTP_STATUS, maxSz - idx, out)
            != WS_SUCCESS) {
        return WS_FATAL_ERROR;
    }
    c32toa(status, out + idx); idx += UINT32_SZ;

    sz = (reason != NULL)? (int)WSTRLEN(reason): 0;
    if (sz + idx + UINT32_SZ > maxSz) {
        return WS_BUFFER_E;
    }

    c32toa(sz, out + idx); idx += UINT32_SZ;
    if (reason != NULL) {
        WMEMCPY(out + idx, reason, sz); idx += sz;
    }

    sz = (lang != NULL)? (int)WSTRLEN(lang): 0;
    if (sz + idx + UINT32_SZ > maxSz) {
        return WS_BUFFER_E;
    }

    c32toa(sz, out + idx); idx += UINT32_SZ;
    if (lang != NULL) {
        WMEMCPY(out + idx, lang, sz);
    }
    *outSz = idx + sz;

    return WS_SUCCESS;
}


#ifndef _WIN32_WCE

/* Handles packet to remove a directory
 *
 * returns WS_SUCCESS on success
 */
int wolfSSH_SFTP_RecvRMDIR(WOLFSSH* ssh, int reqId, byte* data, word32 maxSz)
{
    word32 sz;
    int    ret;
    char*  dir;
    word32 idx = 0;
    byte*  out;
    word32 outSz = 0;
    byte   type;

    char err[] = "Remove Directory Error";
    char suc[] = "Removed Directory";
    char* res  = NULL;

    if (ssh == NULL) {
        return WS_BAD_ARGUMENT;
    }

    WLOG(WS_LOG_SFTP, "Receiving WOLFSSH_FTP_RMDIR");

    ato32(data + idx, &sz); idx += UINT32_SZ;
    if (sz + idx > maxSz) {
        return WS_BUFFER_E;
    }

    /* plus one to make sure is null terminated */
    dir = (char*)WMALLOC(sz + 1, ssh->ctx->heap, DYNTYPE_BUFFER);
    if (dir == NULL) {
        return WS_MEMORY_E;
    }
    WMEMCPY(dir, data + idx, sz);
    dir[sz] = '\0';

    clean_path(dir);
    ret = WRMDIR(dir);
    WFREE(dir, ssh->ctx->heap, DYNTYPE_BUFFER);

    res  = (ret != 0)? err : suc;
    type = (ret != 0)? WOLFSSH_FTP_FAILURE : WOLFSSH_FTP_OK;
    if (wolfSSH_SFTP_CreateStatus(ssh, type, reqId, res,
                "English", NULL, &outSz) != WS_SIZE_ONLY) {
        return WS_FATAL_ERROR;
    }

    out = (byte*)WMALLOC(outSz, ssh->ctx->heap, DYNTYPE_BUFFER);
    if (out == NULL) {
        return WS_MEMORY_E;
    }

    if (ret != 0) {
        /* @TODO errno holds reason for rmdir failure. Status sent could be
         * better if using errno value to send reason i.e. permissions .. */
        WLOG(WS_LOG_SFTP, "Error removing directory %s", dir);
        ret = WS_BAD_FILE_E;
    }
    else {
        ret = WS_SUCCESS;
    }

    if (wolfSSH_SFTP_CreateStatus(ssh, type, reqId, res, "English", out,
                &outSz) != WS_SUCCESS) {
        WFREE(out, ssh->ctx->heap, DYNTPE_BUFFER);
        return WS_FATAL_ERROR;
    }
    wolfSSH_SFTP_RecvSetSend(ssh, out, outSz);
    return ret;
}


/* Handles packet to make a directory
 *
 * returns WS_SUCCESS on success
 */
int wolfSSH_SFTP_RecvMKDIR(WOLFSSH* ssh, int reqId, byte* data, word32 maxSz)
{
    word32 sz;
    int    ret;
    char*  dir;
    word32 mode = 0;
    word32 idx  = 0;
    byte*  out;
    word32 outSz = 0;
    byte   type;

    char err[] = "Create Directory Error";
    char suc[] = "Created Directory";
    char* res  = NULL;


    if (ssh == NULL) {
        return WS_BAD_ARGUMENT;
    }

    WLOG(WS_LOG_SFTP, "Receiving WOLFSSH_FTP_MKDIR");

    ato32(data + idx, &sz); idx += UINT32_SZ;
    if (sz + idx > maxSz) {
        return WS_BUFFER_E;
    }

    /* plus one to make sure is null terminated */
    dir = (char*)WMALLOC(sz + 1, ssh->ctx->heap, DYNTYPE_BUFFER);
    if (dir == NULL) {
        return WS_MEMORY_E;
    }
    WMEMCPY(dir, data + idx, sz);
    dir[sz] = '\0';
    idx += sz;
    if (idx + UINT32_SZ > maxSz) {
        return WS_BUFFER_E;
    }

    ato32(data + idx, &sz); idx += UINT32_SZ;
    if (idx + sz > maxSz) {
        return WS_BUFFER_E;
    }
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
    WFREE(dir, ssh->ctx->heap, DYNTYPE_BUFFER);

    res  = (ret != 0)? err : suc;
    type = (ret != 0)? WOLFSSH_FTP_FAILURE : WOLFSSH_FTP_OK;
    if (ret != 0) {
        WLOG(WS_LOG_SFTP, "Error creating directory %s", dir);
        ret  = WS_BAD_FILE_E;
    }
    else {
        ret  = WS_SUCCESS;
    }

    if (wolfSSH_SFTP_CreateStatus(ssh, type, reqId, res,
                "English", NULL, &outSz) != WS_SIZE_ONLY) {
        return WS_FATAL_ERROR;
    }
    out = (byte*)WMALLOC(outSz, ssh->ctx->heap, DYNTYPE_BUFFER);
    if (out == NULL) {
        return WS_MEMORY_E;
    }

    if (wolfSSH_SFTP_CreateStatus(ssh, type, reqId, res, "English", out,
                &outSz) != WS_SUCCESS) {
        WFREE(out, ssh->ctx->heap, DYNTYPE_BUFFER);
        return WS_FATAL_ERROR;
    }
    wolfSSH_SFTP_RecvSetSend(ssh, out, outSz);
    return ret;
}

#endif /* _WIN32_WCE */


/* Handles packet to open a file
 *
 * returns WS_SUCCESS on success
 */
int wolfSSH_SFTP_RecvOpen(WOLFSSH* ssh, int reqId, byte* data, word32 maxSz)
#ifndef USE_WINDOWS_API
{
    WS_SFTP_FILEATRB atr;
    WFD    fd;
    word32 sz;
    char*  dir;
    word32 reason;
    word32 idx = 0;
    int m = 0;
    int ret = WS_SUCCESS;

    word32 outSz = sizeof(WFD) + UINT32_SZ + WOLFSSH_SFTP_HEADER;
    byte*  out = NULL;

    char* res   = NULL;
    char  ier[] = "Internal Failure";
    char  oer[] = "Open File Error";

    if (ssh == NULL) {
        return WS_BAD_ARGUMENT;
    }

    WLOG(WS_LOG_SFTP, "Receiving WOLFSSH_FTP_OPEN");

    if (sizeof(WFD) > WOLFSSH_MAX_HANDLE) {
        WLOG(WS_LOG_SFTP, "Handle size is too large");
        return WS_FATAL_ERROR;
    }

    ato32(data + idx, &sz); idx += UINT32_SZ;
    if (sz + idx > maxSz) {
        return WS_BUFFER_E;
    }

    /* plus one to make sure is null terminated */
    dir = (char*)WMALLOC(sz + 1, ssh->ctx->heap, DYNTYPE_BUFFER);
    if (dir == NULL) {
        return WS_MEMORY_E;
    }
    WMEMCPY(dir, data + idx, sz);
    dir[sz] = '\0';
    idx += sz;

    /* get reason for opening file */
    ato32(data + idx, &reason); idx += UINT32_SZ;


    /* @TODO handle attributes */
    SFTP_ParseAtributes_buffer(ssh, &atr, data, &idx, maxSz);
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
        res = oer;
        if (wolfSSH_SFTP_CreateStatus(ssh, WOLFSSH_FTP_FAILURE, reqId, res,
                "English", NULL, &outSz) != WS_SIZE_ONLY) {
            return WS_FATAL_ERROR;
        }
        ret = WS_BAD_FILE_E;
    }

#ifdef WOLFSSH_STOREHANDLE
    if (ret == WS_SUCCESS) {
        if ((ret = SFTP_AddHandleNode(ssh, (byte*)&fd, sizeof(WFD), dir)) != WS_SUCCESS) {
            WLOG(WS_LOG_SFTP, "Unable to store handle");
            res = ier;
            if (wolfSSH_SFTP_CreateStatus(ssh, WOLFSSH_FTP_FAILURE, reqId, res,
                "English", NULL, &outSz) != WS_SIZE_ONLY) {
                return WS_FATAL_ERROR;
            }
            ret = WS_FATAL_ERROR;
        }
    }
#endif
    WFREE(dir, ssh->ctx->heap, DYNTYPE_BUFFER);

    /* create packet */
    out = (byte*)WMALLOC(outSz, ssh->ctx->heap, DYNTYPE_BUFFER);
    if (out == NULL) {
        return WS_MEMORY_E;
    }
    if (ret == WS_SUCCESS) {
        if (SFTP_CreatePacket(ssh, WOLFSSH_FTP_HANDLE, out, outSz,
            (byte*)&fd, sizeof(WFD)) != WS_SUCCESS) {
            return WS_FATAL_ERROR;
        }
    }
    else {
        if (wolfSSH_SFTP_CreateStatus(ssh, WOLFSSH_FTP_FAILURE, reqId, res,
                "English", out, &outSz) != WS_SUCCESS) {
            WFREE(out, ssh->ctx->heap, DYNTYPE_BUFFER);
            return WS_FATAL_ERROR;
        }
    }
    wolfSSH_SFTP_RecvSetSend(ssh, out, outSz);

    (void)ier;
    return ret;
}
#else /* USE_WINDOWS_API */
{
    WS_SFTP_FILEATRB atr;
    HANDLE fileHandle;
    word32 sz;
    char* dir;
    word32 reason;
    word32 idx = 0;
    DWORD desiredAccess = 0;
    DWORD shareMode = 0;
    DWORD creationDisp = 0;
    DWORD flagsAndAttrs = 0;
    int ret = WS_SUCCESS;

    word32 outSz = sizeof(HANDLE) + UINT32_SZ + WOLFSSH_SFTP_HEADER;
    byte*  out = NULL;

    char* res   = NULL;
    char  ier[] = "Internal Failure";
    char  oer[] = "Open File Error";

    if (ssh == NULL) {
        return WS_BAD_ARGUMENT;
    }

    WLOG(WS_LOG_SFTP, "Receiving WOLFSSH_FTP_OPEN");

    if (sizeof(HANDLE) > WOLFSSH_MAX_HANDLE) {
        WLOG(WS_LOG_SFTP, "Handle size is too large");
        return WS_FATAL_ERROR;
    }

    ato32(data + idx, &sz); idx += UINT32_SZ;
    if (sz + idx > maxSz) {
        return WS_BUFFER_E;
    }

    /* plus one to make sure is null terminated */
    dir = (char*)WMALLOC(sz + 1, ssh->ctx->heap, DYNTYPE_BUFFER);
    if (dir == NULL) {
        return WS_MEMORY_E;
    }
    WMEMCPY(dir, data + idx, sz);
    dir[sz] = '\0';
    idx += sz;

    /* get reason for opening file */
    ato32(data + idx, &reason); idx += UINT32_SZ;


#if 0
    /* @TODO handle attributes */
    SFTP_ParseAtributes_buffer(ssh, &atr, data, &idx, maxSz);
#endif

    WFREE(data, ssh->ctx->heap, DYNTYPE_BUFFER);

    if (reason & WOLFSSH_FXF_READ)
        desiredAccess |= GENERIC_READ;
    if (reason & WOLFSSH_FXF_WRITE)
        desiredAccess |= GENERIC_WRITE;
    if (reason & WOLFSSH_FXF_APPEND)
        desiredAccess |= FILE_APPEND_DATA;

    if (reason & WOLFSSH_FXF_CREAT)
        creationDisp |= CREATE_ALWAYS;
    if (reason & WOLFSSH_FXF_TRUNC)
        creationDisp |= TRUNCATE_EXISTING;
    if (reason & WOLFSSH_FXF_EXCL)
        creationDisp |= CREATE_NEW;

#if 0
    /* if file permissions not set then use default */
    if (!(atr.flags & WOLFSSH_FILEATRB_PERM)) {
        atr.per = 0644;
    }
#endif
    atr.per = FILE_ATTRIBUTE_NORMAL;

    clean_path(dir);
    fileHandle = CreateFileA(dir, desiredAccess, shareMode, NULL, creationDisp,
            atr.per, NULL);
    if (fileHandle == INVALID_HANDLE_VALUE) {
        WLOG(WS_LOG_SFTP, "Error opening file %s", dir);
        res = oer;
        if (wolfSSH_SFTP_CreateStatus(ssh, WOLFSSH_FTP_FAILURE, reqId, res,
                "English", NULL, &outSz) != WS_SIZE_ONLY) {
            return WS_FATAL_ERROR;
        }
        ret = WS_BAD_FILE_E;
    }

#ifdef WOLFSSH_STOREHANDLE
    if (SFTP_AddHandleNode(ssh,
                (byte*)&fileHandle, sizeof(HANDLE), dir) != WS_SUCCESS) {
            WLOG(WS_LOG_SFTP, "Unable to store handle");
            res = ier;
            if (wolfSSH_SFTP_CreateStatus(ssh, WOLFSSH_FTP_FAILURE, reqId, res,
                "English", NULL, &outSz) != WS_SIZE_ONLY) {
                return WS_FATAL_ERROR;
            }
            ret = WS_FATAL_ERROR;
    }
#endif
    WFREE(dir, ssh->ctx->heap, DYNTYPE_BUFFER);

    /* create packet */
    out = (byte*)WMALLOC(outSz, ssh->ctx->heap, DYNTYPE_BUFFER);
    if (out == NULL) {
        return WS_MEMORY_E;
    }
    if (ret == WS_SUCCESS) {
        if (SFTP_CreatePacket(ssh, WOLFSSH_FTP_HANDLE, out, outSz,
            (byte*)&fileHandle, sizeof(HANDLE)) != WS_SUCCESS) {
            return WS_FATAL_ERROR;
        }
    }
    else {
        if (wolfSSH_SFTP_CreateStatus(ssh, WOLFSSH_FTP_FAILURE, reqId, res,
                "English", out, &outSz) != WS_SUCCESS) {
            WFREE(out, ssh->ctx->heap, DYNTYPE_BUFFER);
            return WS_FATAL_ERROR;
        }
    }
    wolfSSH_SFTP_RecvSetSend(ssh, out, outSz);

    (void)ier;
    return ret;
}
#endif /* USE_WINDOWS_API */


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


/* Handles packet to open a directory
 *
 * returns WS_SUCCESS on success
 */
int wolfSSH_SFTP_RecvOpenDir(WOLFSSH* ssh, int reqId, byte* data, word32 maxSz)
#ifndef USE_WINDOWS_API
{
    WDIR  ctx;
    word32 sz;
    char*  dir;
    word32 idx = 0;
    int   ret = WS_SUCCESS;

    word32 outSz = sizeof(word64) + WOLFSSH_SFTP_HEADER + UINT32_SZ;
    byte*  out = NULL;
    word64 id;

    if (ssh == NULL) {
        return WS_BAD_ARGUMENT;
    }

    WLOG(WS_LOG_SFTP, "Receiving WOLFSSH_FTP_OPENDIR");

    if (sizeof(WFD) > WOLFSSH_MAX_HANDLE) {
        WLOG(WS_LOG_SFTP, "Handle size is too large");
        return WS_FATAL_ERROR;
    }

    /* get directory name */
    ato32(data + idx, &sz); idx += UINT32_SZ;
    if (sz + idx > maxSz) {
        return WS_BUFFER_E;
    }

    /* plus one to make sure is null terminated */
    dir = (char*)WMALLOC(sz + 1, ssh->ctx->heap, DYNTYPE_BUFFER);
    if (dir == NULL) {
        return WS_MEMORY_E;
    }
    WMEMCPY(dir, data + idx, sz);
    dir[sz] = '\0';

    /* get directory handle */
    clean_path(dir);
    if (WOPENDIR(&ctx, dir) != 0) {
        WLOG(WS_LOG_SFTP, "Error with opening directory");
        WFREE(dir, ssh->ctx->heap, DYNTYPE_BUFFER);
        if (wolfSSH_SFTP_CreateStatus(ssh, WOLFSSH_FTP_NOFILE, reqId,
                "Unable To Open Directory", "English", NULL, &outSz)
                != WS_SIZE_ONLY) {
                return WS_FATAL_ERROR;
        }
        ret = WS_BAD_FILE_E;
    }

    (void)reqId;

    /* add to directory list @TODO locking for thread safety */
    if (ret == WS_SUCCESS) {
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
        cur->id    = id = idCount++;
        cur->isEof = 0;
        cur->next  = dirList;
        dirList    = cur;
        dirList->dirName = dir; /* take over ownership of buffer */
    }

    out = (byte*)WMALLOC(outSz, ssh->ctx->heap, DYNTYPE_BUFFER);
    if (out == NULL) {
        return WS_MEMORY_E;
    }

    if (ret == WS_SUCCESS) {
        SFTP_CreatePacket(ssh, WOLFSSH_FTP_HANDLE, out, outSz,
                (byte*)&id, sizeof(word64));
    }
    else {
        if (wolfSSH_SFTP_CreateStatus(ssh, WOLFSSH_FTP_NOFILE, reqId,
                "Unable To Open Directory", "English", out, &outSz)
                != WS_SUCCESS) {
            WFREE(out, ssh->ctx->heap, DYNTYPE_BUFFER);
            return WS_FATAL_ERROR;
        }
    }
    wolfSSH_SFTP_RecvSetSend(ssh, out, outSz);

    return ret;
}
#else /* USE_WINDOWS_API */
{
    word32 sz;
    char* dirName;
    word32 idx = 0;
    HANDLE findHandle;
    WIN32_FIND_DATAA findData;
    int ret = WS_SUCCESS;

    word32 outSz = sizeof(word64) + WOLFSSH_SFTP_HEADER + UINT32_SZ;
    byte*  out = NULL;
    word64 id;

    if (ssh == NULL) {
        return WS_BAD_ARGUMENT;
    }

    WLOG(WS_LOG_SFTP, "Receiving WOLFSSH_FTP_OPENDIR");

    if (sizeof(HANDLE) > WOLFSSH_MAX_HANDLE) {
        WLOG(WS_LOG_SFTP, "Handle size is too large");
        return WS_FATAL_ERROR;
    }

    /* get directory name */
    ato32(data + idx, &sz);
    idx += UINT32_SZ;
    if (sz + idx > maxSz) {
        return WS_BUFFER_E;
    }

    /* plus one to make sure is null terminated */
    dirName = (char*)WMALLOC(sz + 1, ssh->ctx->heap, DYNTYPE_BUFFER);
    if (dirName == NULL) {
        return WS_MEMORY_E;
    }
    WMEMCPY(dirName, data + idx, sz);
    dirName[sz] = '\0';
    clean_path(dirName);

    /* get directory handle */
    findHandle = FindFirstFileA(dirName, &findData);
    if (findHandle == INVALID_HANDLE_VALUE ||
        !(findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {

        WLOG(WS_LOG_SFTP, "Error with opening directory");
        WFREE(dirName, ssh->ctx->heap, DYNTYPE_BUFFER);

        if (wolfSSH_SFTP_CreateStatus(ssh, WOLFSSH_FTP_NOFILE, reqId,
                "Unable To Open Directory", "English", NULL, &outSz)
                != WS_SIZE_ONLY) {
                return WS_FATAL_ERROR;
        }
        ret = WS_BAD_FILE_E;
    }
    FindClose(findHandle);

    (void)reqId;

    /* add to directory list @TODO locking for thread safety */
    if (ret == WS_SUCCESS) {
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

    }

    out = (byte*)WMALLOC(outSz, ssh->ctx->heap, DYNTYPE_BUFFER);
    if (out == NULL) {
        return WS_MEMORY_E;
    }

    if (ret == WS_SUCCESS) {
        SFTP_CreatePacket(ssh, WOLFSSH_FTP_HANDLE, out, outSz,
                (byte*)&id, sizeof(word64));
    }
    else {
        if (wolfSSH_SFTP_CreateStatus(ssh, WOLFSSH_FTP_NOFILE, reqId,
                "Unable To Open Directory", "English", out, &outSz)
                != WS_SUCCESS) {
            WFREE(out, ssh->ctx->heap, DYNTYPE_BUFFER);
            return WS_FATAL_ERROR;
        }
    }
    wolfSSH_SFTP_RecvSetSend(ssh, out, outSz);

    return ret;
}
#endif /* USE_WINDOWS_API */


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


int wolfSSH_SFTP_SetDefaultPath(WOLFSSH* ssh, const char* path)
{
    if (ssh == NULL)
        return WS_BAD_ARGUMENT;

    if (path != NULL) {
        word32 sftpDefaultPathSz;
        sftpDefaultPathSz = (word32)XSTRLEN(path) + 1;
        ssh->sftpDefaultPath = (char*)XMALLOC(sftpDefaultPathSz,
                ssh->ctx->heap, DYNTYPE_STRING);
        if (ssh->sftpDefaultPath == NULL) {
            ssh->error = WS_MEMORY_E;
            return WS_FATAL_ERROR;
        }
        XSTRNCPY(ssh->sftpDefaultPath, path, sftpDefaultPathSz);
    }
    return WS_SUCCESS;
}


/* Handles packet to read a directory
 *
 * returns WS_SUCCESS on success
 */
int wolfSSH_SFTP_RecvReadDir(WOLFSSH* ssh, int reqId, byte* data, word32 maxSz)
{
    WDIR   dir;
    word64 handle = 0;
    word32 sz;
    word32 idx = 0;
    int count = 0;
    int ret;
    WS_SFTPNAME* name = NULL;
    WS_SFTPNAME* list = NULL;
    word32 outSz = 0;
    DIR_HANDLE* cur = dirList;
    char* dirName = NULL;
    byte* out;

    if (ssh == NULL) {
        return WS_BAD_ARGUMENT;
    }

    WLOG(WS_LOG_SFTP, "Receiving WOLFSSH_FTP_READDIR");

    #ifdef USE_WINDOWS_API
        dir = INVALID_HANDLE_VALUE;
    #endif

    /* get directory handle */
    ato32(data + idx, &sz); idx += UINT32_SZ;
    if (sz + idx > maxSz || sz > WOLFSSH_MAX_HANDLE) {
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

    if (list == NULL || cur->isEof) {
        if (wolfSSH_SFTP_CreateStatus(ssh, WOLFSSH_FTP_EOF, reqId,
                "No More Files In Directory", "English", NULL, &outSz)
                != WS_SIZE_ONLY) {
            return WS_FATAL_ERROR;
        }
        out = (byte*)WMALLOC(outSz, ssh->ctx->heap, DYNTYPE_BUFFER);
        if (out == NULL) {
            return WS_MEMORY_E;
        }
        if (wolfSSH_SFTP_CreateStatus(ssh, WOLFSSH_FTP_EOF, reqId,
                "No More Files In Directory", "English", out, &outSz)
                != WS_SUCCESS) {
            WFREE(out, ssh->ctx->heap, DYNTYPE_BUFFER);
            return WS_FATAL_ERROR;
        }
        wolfSSH_SFTP_RecvSetSend(ssh, out, outSz);
        return WS_SUCCESS;
    }

    /* if next state would cause an error then set EOF flag for when called
     * again */
    if (ret == WS_NEXT_ERROR) {
        cur->isEof = 1;
    }

    out = (byte*)WMALLOC(outSz, ssh->ctx->heap, DYNTYPE_BUFFER);
    if (out == NULL) {
        return WS_MEMORY_E;
    }

    if (wolfSSH_SFTP_SendName(ssh, list, count, out, &outSz, reqId)
            != WS_SUCCESS) {
        WFREE(out, ssh->ctx->heap, DYNTYPE_BUFFER);
        return WS_FATAL_ERROR;
    }
    wolfSSH_SFTPNAME_list_free(list);
    wolfSSH_SFTP_RecvSetSend(ssh, out, outSz);
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
int wolfSSH_SFTP_RecvWrite(WOLFSSH* ssh, int reqId, byte* data, word32 maxSz)
#ifndef USE_WINDOWS_API
{
    WFD    fd;
    word32 sz;
    int    ret  = WS_SUCCESS;
    word32 idx  = 0;
    word64 ofst = 0;

    word32 outSz = 0;
    byte*  out   = NULL;

    char  suc[] = "Write File Success";
    char  err[] = "Write File Error";
    char* res  = suc;
    byte  type = WOLFSSH_FTP_OK;

    if (ssh == NULL) {
        return WS_BAD_ARGUMENT;
    }

    WLOG(WS_LOG_SFTP, "Receiving WOLFSSH_FTP_WRITE");

    /* get file handle */
    ato32(data + idx, &sz); idx += UINT32_SZ;
    if (sz + idx > maxSz || sz > WOLFSSH_MAX_HANDLE) {
        WLOG(WS_LOG_SFTP, "Error with file handle size");
        res  = err;
        type = WOLFSSH_FTP_FAILURE;
        ret  = WS_BAD_FILE_E;
    }

    if (ret == WS_SUCCESS) {
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
        if (ret < 0) {
    #if defined(WOLFSSL_NUCLEUS) && defined(DEBUG_WOLFSSH)
            if (ret == NUF_NOSPC) {
                WLOG(WS_LOG_SFTP, "Ran out of memory");
            }
    #endif
            WLOG(WS_LOG_SFTP, "Error writing to file");
            res  = err;
            type = WOLFSSH_FTP_FAILURE;
            ret  = WS_INVALID_STATE_E;
        }
        else {
            ret = WS_SUCCESS;
        }
    }

    if (wolfSSH_SFTP_CreateStatus(ssh, type, reqId, res, "English", NULL,
                &outSz) != WS_SIZE_ONLY) {
        return WS_FATAL_ERROR;
    }
    out = (byte*)WMALLOC(outSz, ssh->ctx->heap, DYNTYPE_BUFFER);
    if (out == NULL) {
        return WS_MEMORY_E;
    }
    if (wolfSSH_SFTP_CreateStatus(ssh, type, reqId, res, "English", out,
                &outSz) != WS_SUCCESS) {
        WFREE(out, ssh->ctx->heap, DYNTYPE_BUFFER);
        return WS_FATAL_ERROR;
    }
    wolfSSH_SFTP_RecvSetSend(ssh, out, outSz);
    return WS_SUCCESS;
}
#else /* USE_WINDOWS_API */
{
    OVERLAPPED offset;
    HANDLE fd;
    DWORD bytesWritten;
    word32 sz;
    int ret = WS_SUCCESS;
    word32 idx  = 0;

    word32 outSz = 0;
    byte*  out   = NULL;

    char  suc[] = "Write File Success";
    char  err[] = "Write File Error";
    char* res  = suc;
    byte  type = WOLFSSH_FTP_OK;

    if (ssh == NULL) {
        return WS_BAD_ARGUMENT;
    }

    WLOG(WS_LOG_SFTP, "Receiving WOLFSSH_FTP_WRITE");

    /* get file handle */
    ato32(data + idx, &sz);
    idx += UINT32_SZ;
    if (sz + idx > maxSz || sz > WOLFSSH_MAX_HANDLE) {
        WLOG(WS_LOG_SFTP, "Error with file handle size");
        res  = err;
        type = WOLFSSH_FTP_FAILURE;
        ret  = WS_BAD_FILE_E;
    }

    if (ret == WS_SUCCESS) {
        WMEMSET((byte*)&fd, 0, sizeof(HANDLE));
        WMEMCPY((byte*)&fd, data + idx, sz);
        idx += sz;

        /* get offset into file */
        WMEMSET(&offset, 0, sizeof(OVERLAPPED));
        ato32(data + idx, &sz);
        idx += UINT32_SZ;
        offset.OffsetHigh = (DWORD)sz;
        ato32(data + idx, &sz);
        idx += UINT32_SZ;
        offset.Offset = (DWORD)sz;

        /* get length to be written */
        ato32(data + idx, &sz);
        idx += UINT32_SZ;

        if (WriteFile(fd, data, sz, &bytesWritten, &offset) == 0) {
            WLOG(WS_LOG_SFTP, "Error writing to file");
            res  = err;
            type = WOLFSSH_FTP_FAILURE;
            ret  = WS_INVALID_STATE_E;
        }
        else {
            ret = WS_SUCCESS;
        }
    }

    if (wolfSSH_SFTP_CreateStatus(ssh, type, reqId, res, "English", NULL,
                &outSz) != WS_SIZE_ONLY) {
        return WS_FATAL_ERROR;
    }
    out = (byte*)WMALLOC(outSz, ssh->ctx->heap, DYNTYPE_BUFFER);
    if (out == NULL) {
        return WS_MEMORY_E;
    }
    if (wolfSSH_SFTP_CreateStatus(ssh, type, reqId, res, "English", out,
                &outSz) != WS_SUCCESS) {
        WFREE(out, ssh->ctx->heap, DYNTYPE_BUFFER);
        return WS_FATAL_ERROR;
    }
    wolfSSH_SFTP_RecvSetSend(ssh, out, outSz);
    return WS_SUCCESS;
}

#endif /* USE_WINDOWS_API */


/* Handles packet to read a file
 *
 * returns WS_SUCCESS on success
 */
int wolfSSH_SFTP_RecvRead(WOLFSSH* ssh, int reqId, byte* data, word32 maxSz)
#ifndef USE_WINDOWS_API
{
    WFD    fd;
    word32 sz;
    int    ret;
    word32 idx  = 0;
    word64 ofst = 0;

    byte*  out;
    word32 outSz;

    char* res  = NULL;
    char err[] = "Read File Error";
    char eof[] = "Read EOF";
    byte type = WOLFSSH_FTP_FAILURE;

    if (ssh == NULL) {
        return WS_BAD_ARGUMENT;
    }

    WLOG(WS_LOG_SFTP, "Receiving WOLFSSH_FTP_READ");

    /* get file handle */
    ato32(data + idx, &sz); idx += UINT32_SZ;
    if (sz + idx > maxSz || sz > WOLFSSH_MAX_HANDLE) {
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

    /* read from handle and send data back to client */
    out = (byte*)WMALLOC(sz + WOLFSSH_SFTP_HEADER + UINT32_SZ,
            ssh->ctx->heap, DYNTYPE_BUFFER);
    if (out == NULL) {
        return WS_MEMORY_E;
    }

    ret = (int)WPREAD(fd, out + UINT32_SZ + WOLFSSH_SFTP_HEADER, sz, (long)ofst);
    if (ret < 0 || (word32)ret > sz) {
        WLOG(WS_LOG_SFTP, "Error reading from file");
        res  = err;
        type = WOLFSSH_FTP_FAILURE;
        ret  = WS_BAD_FILE_E;
    }
    else {
        outSz = (word32)ret + WOLFSSH_SFTP_HEADER + UINT32_SZ;
    }

    /* eof */
    if (ret == 0) {
        WLOG(WS_LOG_SFTP, "Error reading from file");
        res = eof;
        type = WOLFSSH_FTP_EOF;
        ret = WS_SUCCESS; /* end of file is not fatal error */
    }

    if (res != NULL) {
        if (wolfSSH_SFTP_CreateStatus(ssh, type, reqId, res, "English", NULL,
                &outSz) != WS_SIZE_ONLY) {
            return WS_FATAL_ERROR;
        }
        if (outSz > sz) {
            /* need to increase buffer size for holding status packet */
            WFREE(out, ssh->ctx->heap, DYNTYPE_BUFFER);
            out = (byte*)WMALLOC(outSz, ssh->ctx->heap, DYNTYPE_BUFFER);
            if (out == NULL) {
                return WS_MEMORY_E;
            }
        }
        if (wolfSSH_SFTP_CreateStatus(ssh, type, reqId, res, "English", out,
                    &outSz) != WS_SUCCESS) {
            WFREE(out, ssh->ctx->heap, DYNTYPE_BUFFER);
            return WS_FATAL_ERROR;
        }
    }
    else {
        SFTP_CreatePacket(ssh, WOLFSSH_FTP_DATA, out, outSz, NULL, 0);
    }

    wolfSSH_SFTP_RecvSetSend(ssh, out, outSz);
    return ret;
}
#else /* USE_WINDOWS_API */
{
    OVERLAPPED offset;
    HANDLE fd;
    DWORD bytesRead;
    word32 sz;
    int ret;
    word32 idx  = 0;

    byte*  out;
    word32 outSz;

    char* res  = NULL;
    char err[] = "Read File Error";
    char eof[] = "Read EOF";
    byte type = WOLFSSH_FTP_FAILURE;

    if (ssh == NULL) {
        return WS_BAD_ARGUMENT;
    }

    WLOG(WS_LOG_SFTP, "Receiving WOLFSSH_FTP_READ");

    /* get file handle */
    ato32(data + idx, &sz); idx += UINT32_SZ;
    if (sz + idx > maxSz || sz > WOLFSSH_MAX_HANDLE) {
        return WS_BUFFER_E;
    }
    WMEMSET((byte*)&fd, 0, sizeof(HANDLE));
    WMEMCPY((byte*)&fd, data + idx, sz); idx += sz;

    WMEMSET(&offset, 0, sizeof(OVERLAPPED));

    /* get offset into file */
    ato32(data + idx, &sz);
    idx += UINT32_SZ;
    offset.OffsetHigh = (DWORD)sz;
    ato32(data + idx, &sz);
    idx += UINT32_SZ;
    offset.Offset = (DWORD)sz;

    /* get length to be read */
    ato32(data + idx, &sz);

    /* read from handle and send data back to client */
    out = (byte*)WMALLOC(sz + WOLFSSH_SFTP_HEADER + UINT32_SZ,
            ssh->ctx->heap, DYNTYPE_BUFFER);
    if (out == NULL) {
        return WS_MEMORY_E;
    }

    if (ReadFile(fd, data, sz, &bytesRead, &offset) == 0) {
        if (GetLastError() == ERROR_HANDLE_EOF) {
            ret = 0; /* return 0 for end of file */
        }
        else {
            ret = -1;
        }
    }
    else {
        ret = (int)bytesRead;
        outSz = (word32)ret + WOLFSSH_SFTP_HEADER + UINT32_SZ;
    }

    if (ret < 0) {
        WLOG(WS_LOG_SFTP, "Error reading from file");
        res  = err;
        type = WOLFSSH_FTP_FAILURE;
        ret  = WS_BAD_FILE_E;
    }

    /* eof */
    if (ret == 0) {
        WLOG(WS_LOG_SFTP, "Error reading from file");
        res = eof;
        type = WOLFSSH_FTP_EOF;
        ret = WS_SUCCESS; /* end of file is not fatal error */
    }

    if (res != NULL) {
        if (wolfSSH_SFTP_CreateStatus(ssh, type, reqId, res, "English", NULL,
                &outSz) != WS_SIZE_ONLY) {
            return WS_FATAL_ERROR;
        }
        if (outSz > sz) {
            /* need to increase buffer size for holding status packet */
            WFREE(out, ssh->ctx->heap, DYNTYPE_BUFFER);
            out = (byte*)WMALLOC(outSz, ssh->ctx->heap, DYNTYPE_BUFFER);
            if (out == NULL) {
                return WS_MEMORY_E;
            }
        }
        if (wolfSSH_SFTP_CreateStatus(ssh, type, reqId, res, "English", out,
                    &outSz) != WS_SUCCESS) {
            WFREE(out, ssh->ctx->heap, DYNTYPE_BUFFER);
            return WS_FATAL_ERROR;
        }
    }
    else {
        SFTP_CreatePacket(ssh, WOLFSSH_FTP_DATA, out, outSz, NULL, 0);
    }

    wolfSSH_SFTP_RecvSetSend(ssh, out, outSz);
    return ret;
}

#endif /* USE_WINDOWS_API */


/* Handles packet to close a file
 *
 * returns WS_SUCCESS on success
 */
int wolfSSH_SFTP_RecvClose(WOLFSSH* ssh, int reqId, byte* data, word32 maxSz)
#ifndef USE_WINDOWS_API
{
    WFD    fd;
    word32 sz;
    word32 idx = 0;
    int    ret;

    byte* out = NULL;
    word32 outSz = 0;

    char* res = NULL;
    char  suc[] = "Closed File";
    char  err[] = "Close File Error";
    byte  type = WOLFSSH_FTP_FAILURE;

    if (ssh == NULL) {
        return WS_BAD_ARGUMENT;
    }

    WLOG(WS_LOG_SFTP, "Receiving WOLFSSH_FTP_CLOSE");

    /* get file handle */
    ato32(data + idx, &sz); idx += UINT32_SZ;
    if (sz + idx > maxSz || sz > WOLFSSH_MAX_HANDLE) {
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

    if (ret < 0) {
        WLOG(WS_LOG_SFTP, "Error closing file");
        res = err;
        ret = WS_BAD_FILE_E;
    }
    else {
        res  = suc;
        type = WOLFSSH_FTP_OK;
        ret  = WS_SUCCESS;
    }

    if (wolfSSH_SFTP_CreateStatus(ssh, type, reqId, res, "English", NULL,
                &outSz) != WS_SIZE_ONLY) {
        return WS_FATAL_ERROR;
    }
    out = (byte*)WMALLOC(outSz, ssh->ctx->heap, DYNTYPE_BUFFER);
    if (out == NULL) {
        return WS_MEMORY_E;
    }
    if (wolfSSH_SFTP_CreateStatus(ssh, type, reqId, res, "English", out,
                &outSz) != WS_SUCCESS) {
        WFREE(out, ssh->ctx->heap, DYNTYPE_BUFFER);
        return WS_FATAL_ERROR;
    }
    wolfSSH_SFTP_RecvSetSend(ssh, out, outSz);
    return ret;
}
#else /* USE_WINDOWS_API */
{
    HANDLE fd;
    word32 sz;
    word32 idx  = 0;
    int    ret;

    byte* out = NULL;
    word32 outSz = 0;

    char* res = NULL;
    char  suc[] = "Closed File";
    char  err[] = "Close File Error";
    byte  type = WOLFSSH_FTP_FAILURE;

    if (ssh == NULL) {
        return WS_BAD_ARGUMENT;
    }

    WLOG(WS_LOG_SFTP, "Receiving WOLFSSH_FTP_CLOSE");

    /* get file handle */
    ato32(data + idx, &sz); idx += UINT32_SZ;
    if (sz + idx > maxSz || sz > WOLFSSH_MAX_HANDLE) {
        return WS_BUFFER_E;
    }

    if (sz == sizeof(HANDLE)) {
        WMEMSET((byte*)&fd, 0, sizeof(HANDLE));
        WMEMCPY((byte*)&fd, data + idx, sz);
        CloseHandle(fd);
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

    if (ret < 0) {
        WLOG(WS_LOG_SFTP, "Error closing file");
        res = err;
        ret = WS_BAD_FILE_E;
    }
    else {
        res  = suc;
        type = WOLFSSH_FTP_OK;
        ret  = WS_SUCCESS;
    }

    if (wolfSSH_SFTP_CreateStatus(ssh, type, reqId, res, "English", NULL,
                &outSz) != WS_SIZE_ONLY) {
        return WS_FATAL_ERROR;
    }
    out = (byte*)WMALLOC(outSz, ssh->ctx->heap, DYNTYPE_BUFFER);
    if (out == NULL) {
        return WS_MEMORY_E;
    }
    if (wolfSSH_SFTP_CreateStatus(ssh, type, reqId, res, "English", out,
                &outSz) != WS_SUCCESS) {
        WFREE(out, ssh->ctx->heap, DYNTYPE_BUFFER);
        return WS_FATAL_ERROR;
    }
    wolfSSH_SFTP_RecvSetSend(ssh, out, outSz);
    return ret;
}
#endif /* USE_WINDOWS_API */



/* Handles packet to remove a file
 *
 * returns WS_SUCCESS on success
 */
int wolfSSH_SFTP_RecvRemove(WOLFSSH* ssh, int reqId, byte* data, word32 maxSz)
{
    word32 sz;
    char*  name;
    word32 idx = 0;
    int    ret = WS_SUCCESS;

    byte*  out;
    word32 outSz;

    byte type = WOLFSSH_FTP_OK;
    char  suc[] = "Removed File";
    char  err[] = "Remove File Error";
    char* res   = suc;

    if (ssh == NULL) {
        return WS_BAD_ARGUMENT;
    }

    WLOG(WS_LOG_SFTP, "Receiving WOLFSSH_FTP_REMOVE");

    /* get file name */
    ato32(data + idx, &sz); idx += UINT32_SZ;
    if (sz + idx > maxSz || sz > WOLFSSH_MAX_HANDLE) {
        return WS_BUFFER_E;
    }
    name = (char*)WMALLOC(sz + 1, ssh->ctx->heap, DYNTYPE_BUFFER);
    if (name == NULL) {
        return WS_MEMORY_E;
    }
    WMEMCPY(name, data + idx, sz);
    name[sz] = '\0';

    clean_path(name);
#if 0
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
#endif
    ret = WS_BAD_FILE_E;

    /* Let the client know the results from trying to remove the file */
    WFREE(name, ssh->ctx->heap, DYNTYPE_BUFFER);
    if (ret != WS_SUCCESS) {
        res = err;
        type = WOLFSSH_FTP_FAILURE;
    }

    if (wolfSSH_SFTP_CreateStatus(ssh, type, reqId, res, "English", NULL,
                &outSz) != WS_SIZE_ONLY) {
        return WS_FATAL_ERROR;
    }
    out = (byte*)WMALLOC(outSz, ssh->ctx->heap, DYNTYPE_BUFFER);
    if (out == NULL) {
        return WS_MEMORY_E;
    }
    if (wolfSSH_SFTP_CreateStatus(ssh, type, reqId, res, "English", out,
                &outSz) != WS_SUCCESS) {
        WFREE(out, ssh->ctx->heap, DYNTYPE_BUFFER);
        return WS_FATAL_ERROR;
    }
    wolfSSH_SFTP_RecvSetSend(ssh, out, outSz);
    return ret;
}


/* Handles packet to rename a file
 *
 * returns WS_SUCCESS on success
 */
int wolfSSH_SFTP_RecvRename(WOLFSSH* ssh, int reqId, byte* data, word32 maxSz)
{
    word32 sz = 0;
    char*  old;
    char*  nw;
    word32 idx = 0;
    int    ret = WS_SUCCESS;

    byte*  out;
    word32 outSz;

    byte type = WOLFSSH_FTP_OK;
    char  suc[] = "Renamed File";
    char  err[] = "Rename File Error";
    char* res   = suc;

    if (ssh == NULL) {
        return WS_BAD_ARGUMENT;
    }

    WLOG(WS_LOG_SFTP, "Receiving WOLFSSH_FTP_RENAME");

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

    clean_path(old);
    clean_path(nw);
#if 0
    if (ret == WS_SUCCESS && WRENAME(old, nw) < 0) {
        WLOG(WS_LOG_SFTP, "Error renaming file");
        ret = WS_BAD_FILE_E;
    }
#endif
    ret = WS_BAD_FILE_E;

    /* Let the client know the results from trying to rename the file */
    WFREE(old, ssh->ctx->heap, DYNTYPE_BUFFER);
    WFREE(nw, ssh->ctx->heap, DYNTYPE_BUFFER);
    if (ret != WS_SUCCESS) {
        type = WOLFSSH_FTP_FAILURE;
        res  = err;
    }

    if (wolfSSH_SFTP_CreateStatus(ssh, type, reqId, res, "English", NULL,
                &outSz) != WS_SIZE_ONLY) {
        return WS_FATAL_ERROR;
    }
    out = (byte*)WMALLOC(outSz, ssh->ctx->heap, DYNTYPE_BUFFER);
    if (out == NULL) {
        return WS_MEMORY_E;
    }
    if (wolfSSH_SFTP_CreateStatus(ssh, type, reqId, res, "English", out,
                &outSz) != WS_SUCCESS) {
        WFREE(out, ssh->ctx->heap, DYNTYPE_BUFFER);
        return WS_FATAL_ERROR;
    }
    wolfSSH_SFTP_RecvSetSend(ssh, out, outSz);
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

#elif defined(USE_WINDOWS_API)

/* @TODO can be overriden by user for portability
 * NOTE: if atr->flags is set to a value of 0 then no attributes are set.
 * Fills out a WS_SFTP_FILEATRB structure
 * returns WS_SUCCESS on success
 */
int SFTP_GetAttributes(const char* fileName, WS_SFTP_FILEATRB* atr, byte link)
{
    BOOL error;
    WIN32_FILE_ATTRIBUTE_DATA stats;

    (void)link;
    /* @TODO add proper Windows link support */
    /* Note, for windows, we treat WSTAT and WLSTAT the same. */
    error = !GetFileAttributesExA(fileName, GetFileExInfoStandard, &stats);
    if (error)
        return WS_BAD_FILE_E;

    WMEMSET(atr, 0, sizeof(WS_SFTP_FILEATRB));

    atr->flags |= WOLFSSH_FILEATRB_SIZE;
    atr->sz = (((word64)stats.nFileSizeHigh << 32) | stats.nFileSizeLow);

    atr->flags |= WOLFSSH_FILEATRB_PERM;
    atr->per = (word32)stats.dwFileAttributes;

#if 0
    /* @TODO handle the constellation of possible Windows FILETIMEs */
    atr->flags |= WOLFSSH_FILEATRB_TIME;
    atr->atime = (word32)stats.ftLastAccessTime;
    atr->mtime = (word32)stats.ftLastWriteTime;
#endif

    /* @TODO handle attribute extensions */

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


#ifndef USE_WINDOWS_API
/* Handles receiving fstat packet
 * returns WS_SUCCESS on success
 */
int wolfSSH_SFTP_RecvFSTAT(WOLFSSH* ssh, int reqId, byte* data, word32 maxSz)
{
    WS_SFTP_FILEATRB atr;
    word32 handleSz;
    word32 sz;
    byte*  handle;
    word32 idx = 0;
    int ret;

    byte*  out   = NULL;
    word32 outSz = 0;

    if (ssh == NULL) {
        return WS_BAD_ARGUMENT;
    }

    WLOG(WS_LOG_SFTP, "Receiving WOLFSSH_FTP_FSTAT");

    ato32(data + idx, &handleSz); idx += UINT32_SZ;
    if (handleSz + idx > maxSz) {
        return WS_BUFFER_E;
    }
    handle = data + idx;

    /* try to get file attributes and send back to client */
    WMEMSET((byte*)&atr, 0, sizeof(WS_SFTP_FILEATRB));
    if (SFTP_GetAttributes_Handle(ssh, handle, handleSz, &atr) != WS_SUCCESS) {
        WLOG(WS_LOG_SFTP, "Unable to get fstat of file/directory");
        if (wolfSSH_SFTP_CreateStatus(ssh, WOLFSSH_FTP_FAILURE, reqId,
                "STAT error", "English", NULL, &outSz) != WS_SIZE_ONLY) {
            return WS_FATAL_ERROR;
        }
        ret = WS_BAD_FILE_E;
    }
    else {
        sz = SFTP_AtributesSz(ssh, &atr);
        outSz = sz + WOLFSSH_SFTP_HEADER;
    }

    out = (byte*)WMALLOC(outSz, ssh->ctx->heap, DYNTYPE_BUFFER);
    if (out == NULL) {
        return WS_MEMORY_E;
    }

    if (ret == WS_SUCCESS) {
        if (SFTP_SetHeader(ssh, reqId, WOLFSSH_FTP_ATTRS, sz, out) != WS_SUCCESS) {
            return WS_FATAL_ERROR;
        }
        SFTP_SetAttributes(ssh, out + WOLFSSH_SFTP_HEADER, sz, &atr);
    }
    else {
        if (wolfSSH_SFTP_CreateStatus(ssh, WOLFSSH_FTP_FAILURE, reqId,
                "STAT error", "English", out, &outSz) != WS_SUCCESS) {
            WFREE(out, ssh->ctx->heap, DYNTYPE_BUFFER);
            return WS_FATAL_ERROR;
        }
    }
    wolfSSH_SFTP_RecvSetSend(ssh, out, outSz);
    return ret;
}
#endif


#ifndef _WIN32_WCE

/* Handles receiving stat packet
 * returns WS_SUCCESS on success
 */
int wolfSSH_SFTP_RecvSTAT(WOLFSSH* ssh, int reqId, byte* data, word32 maxSz)
{
    WS_SFTP_FILEATRB atr;
    char* name = NULL;
    int   ret = WS_SUCCESS;

    word32 sz;
    word32 idx = 0;

    byte*  out = NULL;
    word32 outSz = 0;

    if (ssh == NULL) {
        return WS_BAD_ARGUMENT;
    }

    WLOG(WS_LOG_SFTP, "Receiving WOLFSSH_FTP_STAT");

    ato32(data + idx, &sz); idx += UINT32_SZ;
    if (sz + idx > maxSz) {
        return WS_BUFFER_E;
    }

    /* plus one to make sure is null terminated */
    name = (char*)WMALLOC(sz + 1, ssh->ctx->heap, DYNTYPE_BUFFER);
    if (name == NULL) {
        return WS_MEMORY_E;
    }
    WMEMCPY(name, data + idx, sz);
    name[sz] = '\0';

    /* try to get file attributes and send back to client */
    clean_path(name);
    WMEMSET((byte*)&atr, 0, sizeof(WS_SFTP_FILEATRB));
    if (SFTP_GetAttributes(name, &atr, 0) != WS_SUCCESS) {
        WLOG(WS_LOG_SFTP, "Unable to get stat of file/directory");
        if (wolfSSH_SFTP_CreateStatus(ssh, WOLFSSH_FTP_FAILURE, reqId,
                "STAT error", "English", NULL, &outSz) != WS_SIZE_ONLY) {
            return WS_FATAL_ERROR;
        }
        ret = WS_BAD_FILE_E;
    }
    else {
        sz = SFTP_AtributesSz(ssh, &atr);
        outSz = sz + WOLFSSH_SFTP_HEADER;
    }
    WFREE(name, ssh->ctx->heap, DYNTYPE_BUFFER);

    out = (byte*)WMALLOC(outSz, ssh->ctx->heap, DYNTYPE_BUFFER);
    if (out == NULL) {
        return WS_MEMORY_E;
    }

    if (ret != WS_SUCCESS) {
        if (wolfSSH_SFTP_CreateStatus(ssh, WOLFSSH_FTP_FAILURE, reqId,
                "STAT error", "English", out, &outSz) != WS_SUCCESS) {
            WFREE(out, ssh->ctx->heap, DYNTYPE_BUFFER);
            return WS_FATAL_ERROR;
        }
    }
    else {
        if (SFTP_SetHeader(ssh, reqId, WOLFSSH_FTP_ATTRS, sz, out) != WS_SUCCESS) {
            WFREE(out, ssh->ctx->heap, DYNTYPE_BUFFER);
            return WS_FATAL_ERROR;
        }
        SFTP_SetAttributes(ssh, out + WOLFSSH_SFTP_HEADER, sz, &atr);
    }

    wolfSSH_SFTP_RecvSetSend(ssh, out, outSz);
    return ret;
}


/* Handles receiving lstat packet
 * returns WS_SUCCESS on success
 */
int wolfSSH_SFTP_RecvLSTAT(WOLFSSH* ssh, int reqId, byte* data, word32 maxSz)
{
    WS_SFTP_FILEATRB atr;
    char* name = NULL;
    int   ret;

    word32 sz;
    word32 idx = 0;

    byte*  out = NULL;
    word32 outSz = 0;

    if (ssh == NULL) {
        return WS_BAD_ARGUMENT;
    }

    WLOG(WS_LOG_SFTP, "Receiving WOLFSSH_FTP_LSTAT");

    ato32(data + idx, &sz); idx += UINT32_SZ;
    if (sz + idx > maxSz) {
        return WS_BUFFER_E;
    }

    /* plus one to make sure is null terminated */
    name = (char*)WMALLOC(sz + 1, ssh->ctx->heap, DYNTYPE_BUFFER);
    if (name == NULL) {
        return WS_MEMORY_E;
    }
    WMEMCPY(name, data + idx, sz);
    name[sz] = '\0';
    clean_path(name);

    /* try to get file attributes and send back to client */
    WMEMSET((byte*)&atr, 0, sizeof(WS_SFTP_FILEATRB));
    if ((ret = SFTP_GetAttributes(name, &atr, 1)) != WS_SUCCESS) {
        /* tell peer that was not ok */
        WLOG(WS_LOG_SFTP, "Unable to get lstat of file/directory");
        if (wolfSSH_SFTP_CreateStatus(ssh, WOLFSSH_FTP_FAILURE, reqId,
                "LSTAT error", "English", NULL, &outSz) != WS_SIZE_ONLY) {
            return WS_FATAL_ERROR;
        }
        ret = WS_BAD_FILE_E;
    }
    else {
        sz = SFTP_AtributesSz(ssh, &atr);
        outSz = sz + WOLFSSH_SFTP_HEADER;
    }
    WFREE(name, ssh->ctx->heap, DYNTYPE_BUFFER);

    out = (byte*)WMALLOC(outSz, ssh->ctx->heap, DYNTYPE_BUFFER);
    if (out == NULL) {
        return WS_MEMORY_E;
    }

    if (ret != WS_SUCCESS) {
        if (wolfSSH_SFTP_CreateStatus(ssh, WOLFSSH_FTP_FAILURE, reqId,
                "LSTAT error", "English", out, &outSz) != WS_SUCCESS) {
            WFREE(out, ssh->ctx->heap, DYNTYPE_BUFFER);
            return WS_FATAL_ERROR;
        }
    }
    else {
        if (SFTP_SetHeader(ssh, reqId, WOLFSSH_FTP_ATTRS, sz, out) != WS_SUCCESS) {
            WFREE(out, ssh->ctx->heap, DYNTYPE_BUFFER);
            return WS_FATAL_ERROR;
        }
        SFTP_SetAttributes(ssh, out + WOLFSSH_SFTP_HEADER, sz, &atr);
    }

    wolfSSH_SFTP_RecvSetSend(ssh, out, outSz);
    return ret;
}

#endif /* _WIN32_WCE */


#ifndef USE_WINDOWS_API
/* Set the files mode
 * return WS_SUCCESS on success */
static int SFTP_SetMode(WOLFSSH* ssh, char* name, word32 mode) {
    (void)ssh;
    if (WCHMOD(name, mode) != 0) {
        return WS_BAD_FILE_E;
    }
    return WS_SUCCESS;
}
#endif


#ifndef _WIN32_WCE

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

#ifndef USE_WINDOWS_API
    /* check if permissions attribute present */
    if (atr->flags & WOLFSSH_FILEATRB_PERM) {
        ret = SFTP_SetMode(ssh, name, atr->per);
    }
#endif

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
int wolfSSH_SFTP_RecvSetSTAT(WOLFSSH* ssh, int reqId, byte* data, word32 maxSz)
{
    WS_SFTP_FILEATRB atr;
    char* name = NULL;
    int   ret = WS_SUCCESS;

    word32 sz;
    word32 idx = 0;

    byte*  out = NULL;
    word32 outSz = 0;

    char  suc[] = "Set Attirbutes";
    char  ser[] = "Unable to set attributes error";
    char  per[] = "Unable to parse attributes error";
    char* res   = suc;
    byte  type  = WOLFSSH_FTP_OK;

    if (ssh == NULL) {
        return WS_BAD_ARGUMENT;
    }

    WLOG(WS_LOG_SFTP, "Receiving WOLFSSH_FTP_SETSTAT");

    ato32(data + idx, &sz); idx += UINT32_SZ;
    if (sz + idx > maxSz) {
        return WS_BUFFER_E;
    }

    /* plus one to make sure is null terminated */
    name = (char*)WMALLOC(sz + 1, ssh->ctx->heap, DYNTYPE_BUFFER);
    if (name == NULL) {
        return WS_MEMORY_E;
    }
    WMEMCPY(name, data + idx, sz); idx += sz;
    name[sz] = '\0';
    clean_path(name);

    if (SFTP_ParseAtributes_buffer(ssh, &atr, data, &idx, maxSz) != 0) {
        type = WOLFSSH_FTP_FAILURE;
        res  = per;
        ret  = WS_BAD_FILE_E;
    }

    /* try to set file attributes and send status back to client */
    if (ret == WS_SUCCESS && (ret = SFTP_SetFileAttributes(ssh, name, &atr))
            != WS_SUCCESS) {
        /* tell peer that was not ok */
        WLOG(WS_LOG_SFTP, "Unable to get set attributes of file/directory");
        type = WOLFSSH_FTP_FAILURE;
        res  = ser;
        ret  = WS_BAD_FILE_E;
    }
    WFREE(name, ssh->ctx->heap, DYNTYPE_BUFFER);

    if (wolfSSH_SFTP_CreateStatus(ssh, type, reqId, res, "English", NULL,
                &outSz) != WS_SIZE_ONLY) {
        return WS_FATAL_ERROR;
    }
    out = (byte*)WMALLOC(outSz, ssh->ctx->heap, DYNTYPE_BUFFER);
    if (out == NULL) {
        return WS_MEMORY_E;
    }
    if (wolfSSH_SFTP_CreateStatus(ssh, type, reqId, res, "English", out,
                &outSz) != WS_SUCCESS) {
        WFREE(out, ssh->ctx->heap, DYNTYPE_BUFFER);
        return WS_FATAL_ERROR;
    }
    wolfSSH_SFTP_RecvSetSend(ssh, out, outSz);
    return ret;
}

#endif /* _WIN32_WCE */
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
            if (SFTP_ClientRecvInit(ssh) != WS_SUCCESS) {
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
    WS_SFTP_SEND_STATE* state = NULL;

    if (ssh == NULL || buf == NULL) {
        return WS_BAD_ARGUMENT;
    }

    state = ssh->sendState;
    if (state == NULL) {
        state = (WS_SFTP_SEND_STATE*)WMALLOC(sizeof(WS_SFTP_SEND_STATE),
                ssh->ctx->heap, DYNTYPE_SFTP_STATE);
        if (state == NULL) {
            ssh->error = WS_MEMORY_E;
            return WS_FATAL_ERROR;
        }
        WMEMSET(state, 0, sizeof(WS_SFTP_SEND_STATE));
        ssh->sendState = state;
        state->state = SFTP_BUILD_PACKET;
    }

    switch (state->state) {
        case SFTP_BUILD_PACKET:
            if (ssh->sftpState != SFTP_DONE) {
                WLOG(WS_LOG_SFTP, "SFTP connection not complete");
                ret = wolfSSH_SFTP_negotiate(ssh);
            }

            if (ret == WS_SUCCESS) {
                state->sz = bufSz + WOLFSSH_SFTP_HEADER + UINT32_SZ;
                state->data = (byte*)WMALLOC(state->sz, ssh->ctx->heap,
                        DYNTYPE_BUFFER);
                if (state->data == NULL) {
                    wolfSSH_SFTP_ClearState(ssh, STATE_ID_SEND);
                    return WS_MEMORY_E;
                }

                if (SFTP_SetHeader(ssh, ssh->reqId, type, bufSz + UINT32_SZ,
                            state->data) != WS_SUCCESS) {
                    wolfSSH_SFTP_ClearState(ssh, STATE_ID_SEND);
                    return WS_FATAL_ERROR;
                }

                state->idx = WOLFSSH_SFTP_HEADER;
                c32toa(bufSz, state->data + state->idx);
                state->idx += UINT32_SZ;
                WMEMCPY(state->data + state->idx, buf, bufSz);
                state->idx = 0; /* reset state for sending data */
            }
            state->state = SFTP_SEND_PACKET;
            FALL_THROUGH;
            /* no break */

        case SFTP_SEND_PACKET:
            /* send header and type specific state->data, looping over send
             * because channel could have restrictions on how much
             * state->data can be sent at one time */
            do {
                int err;
                ret = wolfSSH_stream_send(ssh, state->data + state->idx,
                        state->sz - state->idx);

                /* check for adjust window packet */
                err = wolfSSH_get_error(ssh);
                wolfSSH_CheckReceivePending(ssh);
                ssh->error = err; /* don't save potential want read here */
                if (ret > 0)
                    state->idx += (word32)ret;
            } while (ret > 0 && state->idx < (word32)state->sz);

            if (ret > 0) {
                ret = WS_SUCCESS;
                wolfSSH_SFTP_ClearState(ssh, STATE_ID_SEND);
            }
            break;

        default:
            WLOG(WS_LOG_SFTP, "Unknown packet state!");
            break;
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
static int wolfSSH_SFTP_DoStatus(WOLFSSH* ssh, word32 reqId, byte* buf,
        word32* idx, word32 maxIdx)
{
    word32 sz;
    word32 status = WOLFSSH_FTP_FAILURE;
    word32 localIdx = *idx;

    (void)reqId;
    if (localIdx + UINT32_SZ > maxIdx) {
        return WS_FATAL_ERROR;
    }
    ato32(buf + localIdx, &status);
    localIdx += UINT32_SZ;

    /* read error message */
    if (localIdx + UINT32_SZ > maxIdx) {
        return WS_FATAL_ERROR;
    }
    ato32(buf + localIdx, &sz);
    localIdx += UINT32_SZ;

    if (sz > 0) {
        byte* s;

        if (localIdx + sz > maxIdx) {
            return WS_FATAL_ERROR;
        }
        s = (byte*)WMALLOC(sz + 1, ssh->ctx->heap, DYNTYPE_BUFFER);
        if (s == NULL) {
            return WS_MEMORY_E;
        }

        /* make sure is null terminated string */
        WMEMCPY(s, buf + localIdx, sz);
        s[sz] = '\0';
        WLOG(WS_LOG_SFTP, "Status Recv : %s", s);
        WFREE(s, ssh->ctx->heap, DYNTYPE_BUFFER);
        localIdx += sz;
    }

    /* read language tag */
    if (localIdx + UINT32_SZ > maxIdx) {
        return WS_FATAL_ERROR;
    }
    ato32(buf + localIdx, &sz);
    localIdx += UINT32_SZ;

    if (sz > 0) {
        byte* s;

        if (localIdx + sz > maxIdx) {
            return WS_FATAL_ERROR;
        }
        s = (byte*)WMALLOC(sz + 1, ssh->ctx->heap, DYNTYPE_BUFFER);
        if (s == NULL) {
            return WS_MEMORY_E;
        }

        /* make sure is null terminated string */
        WMEMCPY(s, buf + localIdx, sz);
        s[sz] = '\0';
        WLOG(WS_LOG_SFTP, "Status Language : %s", s);
        WFREE(s, ssh->ctx->heap, DYNTYPE_BUFFER);
        localIdx += sz;
    }

    *idx = localIdx;
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
        word32* idx, word32 maxIdx)
{
    word32 localIdx = *idx;

    WMEMSET(atr, 0, sizeof(WS_SFTP_FILEATRB));

    if (localIdx + UINT32_SZ > maxIdx) {
        return WS_BUFFER_E;
    }

    /* get flags */
    ato32(buf + localIdx, &atr->flags); localIdx += UINT32_SZ;

    /* check if size attribute present */
    if (atr->flags & WOLFSSH_FILEATRB_SIZE) {
        word32 tmp;

        if (localIdx + (2*UINT32_SZ) > maxIdx) {
            return WS_BUFFER_E;
        }
        ato32(buf + localIdx, &tmp); localIdx += UINT32_SZ;
        atr->sz = tmp; atr->sz = atr->sz << 32;
        ato32(buf + localIdx, &tmp); localIdx += UINT32_SZ;
        atr->sz |= tmp;
    }

    /* check if uid and gid attribute present */
    if (atr->flags & WOLFSSH_FILEATRB_UIDGID) {
        if (localIdx + (2*UINT32_SZ) > maxIdx) {
            return WS_BUFFER_E;
        }
        ato32(buf + localIdx, &atr->uid); localIdx += UINT32_SZ;
        ato32(buf + localIdx, &atr->gid); localIdx += UINT32_SZ;
    }

    /* check if permissions attribute present */
    if (atr->flags & WOLFSSH_FILEATRB_PERM) {
        if (localIdx + UINT32_SZ > maxIdx) {
            return WS_BUFFER_E;
        }
        ato32(buf + localIdx, &atr->per); localIdx += UINT32_SZ;
    }

    /* check if time attribute present */
    if (atr->flags & WOLFSSH_FILEATRB_TIME) {
        if (localIdx + (2*UINT32_SZ) > maxIdx) {
            return WS_BUFFER_E;
        }
        ato32(buf + localIdx, &atr->atime); localIdx += UINT32_SZ;
        ato32(buf + localIdx, &atr->mtime); localIdx += UINT32_SZ;
    }

    /* check if extended attributes are present */
    if (atr->flags & WOLFSSH_FILEATRB_EXT) {
        word32 i;
        word32 sz;

        if (localIdx + UINT32_SZ > maxIdx) {
            return WS_BUFFER_E;
        }
        ato32(buf + localIdx, &atr->extCount); localIdx += UINT32_SZ;

        for (i = 0; i < atr->extCount; i++) {
            /* @TODO in the process of storing attributes */
            if (localIdx + UINT32_SZ > maxIdx) {
                return WS_BUFFER_E;
            }
            ato32(buf + localIdx, &sz); localIdx += UINT32_SZ;

            if (sz > 0) {
                if (localIdx + sz > maxIdx) {
                    return WS_BUFFER_E;
                }
                /* @TODO extension type */
                localIdx += sz;
            }

            /* @TODO in the process of storing attributes */
            if (localIdx + UINT32_SZ > maxIdx) {
                return WS_BUFFER_E;
            }
            ato32(buf + localIdx, &sz); localIdx += UINT32_SZ;

            if (sz > 0) {
                if (localIdx + sz > maxIdx) {
                    return WS_BUFFER_E;
                }
                /* @TODO extension data */
                localIdx += sz;
            }
        }
    }

    *idx = localIdx;
    (void)ssh;
    return WS_SUCCESS;
}


#if 0
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
#endif


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
    WS_SFTP_NAME_STATE* state = NULL;
    WS_SFTPNAME* n = NULL;
    int maxSz;
    word32 count;
    word32 reqId = 0;
    byte   type = WOLFSSH_FTP_STATUS;
    int    ret;

    if (ssh->error == WS_WANT_READ || ssh->error == WS_WANT_WRITE)
        ssh->error = WS_SUCCESS;

    state = ssh->nameState;
    if (state == NULL) {
        state = (WS_SFTP_NAME_STATE*)WMALLOC(sizeof(WS_SFTP_NAME_STATE),
                ssh->ctx->heap, DYNTYPE_SFTP_STATE);
        if (state == NULL) {
            ssh->error = WS_MEMORY_E;
            return NULL;
        }
        WMEMSET(state, 0, sizeof(WS_SFTP_NAME_STATE));
        ssh->nameState = state;
        state->state = SFTP_NAME_GETHEADER_PACKET;
    }

    switch (state->state) {

        case SFTP_NAME_GETHEADER_PACKET:
            maxSz = SFTP_GetHeader(ssh, &reqId, &type);
            if (maxSz <= 0 || ssh->error == WS_WANT_READ) {
                return NULL;
            }

            if (reqId != ssh->reqId) {
                WLOG(WS_LOG_SFTP, "unexpected ID");
                return NULL;
            }

            if (type != WOLFSSH_FTP_NAME) {
                WLOG(WS_LOG_SFTP, "Unexpected packet type %d", type);
                /* check for status msg */
                if (type == WOLFSSH_FTP_STATUS) {
                    state->state = SFTP_NAME_DO_STATUS;
                }
                else {
                    return NULL;
                }
            }
            else {
                ssh->reqId += 1;
                state->state = SFTP_NAME_GET_PACKET;
            }
            state->sz = maxSz;
            state->data = (byte*)WMALLOC(state->sz, ssh->ctx->heap,
                    DYNTYPE_BUFFER);
            state->idx = 0;
            if (state->data == NULL) {
                WLOG(WS_LOG_SFTP, "Could not malloc memory");
                wolfSSH_SFTP_ClearState(ssh, STATE_ID_NAME);
                return NULL;
            }
            FALL_THROUGH;
            /* no break */

        case SFTP_NAME_DO_STATUS:
            if (state->state == SFTP_NAME_DO_STATUS) {
                ret = wolfSSH_stream_read(ssh, state->data, state->sz);
                if (ret < 0) {
                    if (ssh->error != WS_WANT_READ) {
                        wolfSSH_SFTP_ClearState(ssh, STATE_ID_NAME);
                    }
                    return NULL;
                }

                wolfSSH_SFTP_DoStatus(ssh, reqId, state->data, &state->idx,
                        state->sz);
                return NULL;
            }
            FALL_THROUGH;
            /* no break */


        case SFTP_NAME_GET_PACKET:
            /* get number of files */
            ret = wolfSSH_stream_read(ssh, state->data, state->sz);
            if (ret < 0) {
                if (ssh->error != WS_WANT_READ) {
                    wolfSSH_SFTP_ClearState(ssh, STATE_ID_NAME);
                }
                return NULL;
            }

            if (state->idx + UINT32_SZ > (word32)state->sz) {
                ssh->error = WS_BUFFER_E;
                wolfSSH_SFTP_ClearState(ssh, STATE_ID_NAME);
                return NULL;
            }
            ato32(state->data, &count); state->idx += UINT32_SZ;
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
                if (state->idx + UINT32_SZ > (word32)state->sz) {
                    ret = WS_BUFFER_E;
                    break;
                }
                ato32(state->data + state->idx, &sz); state->idx += UINT32_SZ;
                tmp->fSz = sz;
                if (sz > 0) {
                    tmp->fName = (char*)WMALLOC(sz + 1, tmp->heap, DYNTYPE_SFTP);
                    if (tmp->fName == NULL) {
                        ret = WS_MEMORY_E;
                        break;
                    }

                    if (state->idx + sz > (word32)state->sz) {
                        ret = WS_FATAL_ERROR;
                        break;
                    }
                    WMEMCPY(tmp->fName, state->data + state->idx, sz);
                    state->idx += sz;
                    tmp->fName[sz] = '\0';
                }

                /* get longname size and name */
                if (state->idx + UINT32_SZ > (word32)state->sz) {
                    ret = WS_BUFFER_E;
                    break;
                }
                ato32(state->data + state->idx, &sz); state->idx += UINT32_SZ;
                tmp->lSz   = sz;
                if (sz > 0) {
                    tmp->lName = (char*)WMALLOC(sz + 1,
                            tmp->heap, DYNTYPE_SFTP);
                    if (tmp->lName == NULL) {
                        ret = WS_MEMORY_E;
                        break;
                    }

                    if (state->idx + sz > (word32)state->sz) {
                        ret = WS_FATAL_ERROR;
                        break;
                    }
                    WMEMCPY(tmp->lName, state->data + state->idx, sz);
                    state->idx += sz;
                    tmp->lName[sz] = '\0';
                }

                /* get attributes */
                ret = SFTP_ParseAtributes_buffer(ssh, &tmp->atrb, state->data,
                        &state->idx, state->sz);
                if (ret != WS_SUCCESS) {
                    break;
                }

                ret = WS_SUCCESS;
            }

            wolfSSH_SFTP_ClearState(ssh, STATE_ID_NAME);
            if (ret != WS_SUCCESS) {
                WLOG(WS_LOG_SFTP, "Error with reading file names");
                wolfSSH_SFTPNAME_list_free(n);
                return NULL;
            }
            break;
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
    WS_SFTP_GET_HANDLE_STATE* state = NULL;
    byte* data = NULL;
    int ret = WS_SUCCESS;
    word32 idx;
    byte type = 0;

    WLOG(WS_LOG_SFTP, "Entering wolfSSH_SFTP_GetHandle");

    state = ssh->getHandleState;
    if (state == NULL) {
        state = (WS_SFTP_GET_HANDLE_STATE*)WMALLOC(
                sizeof(WS_SFTP_GET_HANDLE_STATE),
                ssh->ctx->heap, DYNTYPE_SFTP_STATE);
        if (state == NULL) {
            ssh->error = WS_MEMORY_E;
            return WS_FATAL_ERROR;
        }
        WMEMSET(state, 0, sizeof(WS_SFTP_GET_HANDLE_STATE));
        ssh->getHandleState = state;
        state->state = STATE_GET_HANDLE_INIT;
    }

    for (;;) {
        switch (state->state) {

            case STATE_GET_HANDLE_INIT:
                WLOG(WS_LOG_SFTP, "SFTP GET HANDLE STATE: INIT");
                state->state = STATE_GET_HANDLE_GET_HEADER;
                FALL_THROUGH;

            case STATE_GET_HANDLE_GET_HEADER:
                WLOG(WS_LOG_SFTP, "SFTP GET HANDLE STATE: GET_HEADER");
                ret = SFTP_GetHeader(ssh, &state->reqId, &type);
                if (ret <= 0) {
                    if (ssh->error == WS_WANT_READ ||
                            ssh->error == WS_WANT_WRITE) {
                        return WS_FATAL_ERROR;
                    }
                    else {
                        state->state = STATE_GET_HANDLE_CLEANUP;
                        ret = WS_FATAL_ERROR;
                        continue;
                    }
                }
                state->bufSz = (word32)ret;

                if (type == WOLFSSH_FTP_HANDLE)
                    state->state = STATE_GET_HANDLE_CHECK_REQ_ID;
                else if (type == WOLFSSH_FTP_STATUS) {
                    state->state = STATE_GET_HANDLE_DO_STATUS;
                }
                else {
                    WLOG(WS_LOG_SFTP,
                         "Unexpected packet type with getting handle");
                    state->state = STATE_GET_HANDLE_CLEANUP;
                    ret = WS_FATAL_ERROR;
                }
                continue;

            case STATE_GET_HANDLE_DO_STATUS:
                WLOG(WS_LOG_SFTP, "SFTP GET HANDLE STATE: DO_STATUS");

                /* @TODO */
                data = (byte*)WMALLOC(state->bufSz,
                        ssh->ctx->heap, DYNTYPE_BUFFER);
                ret = wolfSSH_stream_read(ssh, state->buf, state->bufSz);
                if (ret < 0) {
                    WFREE(data, ssh->ctx->heap, DYNTYPE_BUFFER);
                    return WS_FATAL_ERROR;
                }

                idx = 0;
                ret = wolfSSH_SFTP_DoStatus(ssh, state->reqId, state->buf,
                        &idx, state->bufSz);
                WFREE(data, ssh->ctx->heap, DYNTYPE_BUFFER);
                if (ret == WOLFSSH_FTP_OK)
                    ret = WS_SUCCESS;
                else
                    ret = WS_FATAL_ERROR;
                state->state = STATE_GET_HANDLE_CLEANUP;
                continue;

            case STATE_GET_HANDLE_CHECK_REQ_ID:
                WLOG(WS_LOG_SFTP, "SFTP GET HANDLE STATE: CHECK_REQ_ID");
                /* @TODO packets do not need to be in order, may need
                 * mechanism to handle out of order ID's?  */
                if (state->reqId != ssh->reqId) {
                    WLOG(WS_LOG_SFTP, "Unexpected ID");
                    ret = WS_FATAL_ERROR;
                    state->state = STATE_GET_HANDLE_CLEANUP;
                    continue;
                }
                ssh->reqId++;

                if (state->bufSz > sizeof(state->buf)) {
                    WLOG(WS_LOG_SFTP, "Handle found is too large for buffer");
                    ssh->error = WS_BUFFER_E;
                    ret = WS_FATAL_ERROR;
                    state->state = STATE_GET_HANDLE_CLEANUP;
                    continue;
                }
                state->state = STATE_GET_HANDLE_READ;
                FALL_THROUGH;

            case STATE_GET_HANDLE_READ:
                WLOG(WS_LOG_SFTP, "SFTP GET HANDLE STATE: READ");
                ret = wolfSSH_stream_read(ssh, state->buf, state->bufSz);
                if (ret != (int)state->bufSz) {
                    return WS_FATAL_ERROR;
                }
                ret = WS_SUCCESS;

                /* RFC specifies that handle size should not be larger than
                 * max size */
                ato32(state->buf, &state->bufSz);
                if (state->bufSz > WOLFSSH_MAX_HANDLE ||
                        *handleSz < state->bufSz) {
                    WLOG(WS_LOG_SFTP, "Handle size found was too big");
                    ssh->error = WS_BUFFER_E;
                    ret = WS_FATAL_ERROR;
                    state->state = STATE_GET_HANDLE_CLEANUP;
                    continue;
                }
                *handleSz = state->bufSz;
                WMEMCPY(handle, (state->buf + UINT32_SZ), *handleSz);
                state->state = STATE_GET_HANDLE_CLEANUP;
                FALL_THROUGH;

            case STATE_GET_HANDLE_CLEANUP:
                WLOG(WS_LOG_SFTP, "SFTP GET HANDLE STATE: CLEANUP");
                if (ssh->getHandleState != NULL) {
                    WFREE(ssh->getHandleState,
                          ssh->ctx->heap, DYNTYPE_SFTP_STATE);
                    ssh->getHandleState = NULL;
                }
                return ret;

            default:
                WLOG(WS_LOG_DEBUG, "Bad SFTP GetHandle state, program error");
                return WS_INPUT_CASE_E;
        }
    }

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
    struct WS_SFTP_LS_STATE* state = NULL;
    WS_SFTPNAME* name = NULL;
    int ret;

    if (ssh == NULL || dir == NULL) {
        WLOG(WS_LOG_SFTP, "Bad argument passed in");
        return NULL;
    }

    state = ssh->lsState;
    if (state == NULL) {
        state = (WS_SFTP_LS_STATE*)WMALLOC(sizeof(WS_SFTP_LS_STATE),
                ssh->ctx->heap, DYNTYPE_SFTP_STATE);
        if (state == NULL) {
            ssh->error = WS_MEMORY_E;
            return NULL;
        }
        WMEMSET(state, 0, sizeof(WS_SFTP_LS_STATE));
        ssh->lsState = state;
        state->state = STATE_LS_REALPATH;
    }

    switch (state->state) {
        case STATE_LS_REALPATH:
            state->name = wolfSSH_SFTP_RealPath(ssh, dir);
            if (state->name == NULL) {
                if (ssh->error != WS_WANT_READ && ssh->error != WS_WANT_WRITE) {
                    wolfSSH_SFTP_ClearState(ssh, STATE_ID_LS);
                }
                return NULL;
            }
            state->state = STATE_LS_OPENDIR;
            FALL_THROUGH;
            /* no break */

        case STATE_LS_OPENDIR:
            if (wolfSSH_SFTP_OpenDir(ssh, (byte*)state->name->fName,
                        state->name->fSz) != WS_SUCCESS) {
                WLOG(WS_LOG_SFTP, "Unable to open directory");
                if (ssh->error != WS_WANT_READ && ssh->error != WS_WANT_WRITE) {
                    wolfSSH_SFTPNAME_list_free(state->name); state->name = NULL;
                    wolfSSH_SFTP_ClearState(ssh, STATE_ID_LS);
                }
                return NULL;
            }
            wolfSSH_SFTPNAME_list_free(state->name); state->name = NULL;
            state->sz    = WOLFSSH_MAX_HANDLE;
            state->state = STATE_LS_GETHANDLE;
            FALL_THROUGH;
            /* no break */

        case STATE_LS_GETHANDLE:
            /* get the handle from opening the directory and read with it */
            if (wolfSSH_SFTP_GetHandle(ssh, state->handle, (word32*)&state->sz)
                    != WS_SUCCESS) {
                WLOG(WS_LOG_SFTP, "Unable to get handle");
                if (ssh->error != WS_WANT_READ && ssh->error != WS_WANT_WRITE) {
                    wolfSSH_SFTP_ClearState(ssh, STATE_ID_LS);
                }
                return NULL;
            }
            state->state = STATE_LS_READDIR;
            FALL_THROUGH;
            /* no break */

        case STATE_LS_READDIR:
            /* now read the dir */
            state->name = wolfSSH_SFTP_ReadDir(ssh, state->handle, state->sz);
            if (state->name == NULL) {
                if (ssh->error == WS_WANT_READ || ssh->error == WS_WANT_WRITE) {
                    return NULL;
                }
                WLOG(WS_LOG_SFTP, "Error reading directory");
                /* fall through because the handle should always be closed */
            }
            state->state = STATE_LS_CLOSE;
            FALL_THROUGH;
            /* no break */

        case STATE_LS_CLOSE:
            /* close dir when finished */
            if ((ret = wolfSSH_SFTP_Close(ssh, state->handle, state->sz))
                    != WS_SUCCESS) {
                WLOG(WS_LOG_SFTP, "Error closing handle");
                if (ssh->error != WS_WANT_READ && ssh->error != WS_WANT_WRITE) {
                    wolfSSH_SFTPNAME_list_free(state->name);
                    state->name = NULL;
                    wolfSSH_SFTP_ClearState(ssh, STATE_ID_LS);
                }
                return NULL;
            }
            break;

        default:
            return NULL;
    }

    /* on success free'ing state->name is up to caller */
    name = state->name;
    wolfSSH_SFTP_ClearState(ssh, STATE_ID_LS);
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
        WMEMSET(state, 0, sizeof(WS_SFTP_LSTAT_STATE));
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
                    if (ssh->error == WS_WANT_READ ||
                            ssh->error == WS_WANT_WRITE)
                        return WS_FATAL_ERROR;
                    else {
                        state->state = STATE_LSTAT_CLEANUP;
                        continue;
                    }
                }
                state->state = STATE_LSTAT_GET_HEADER;
                FALL_THROUGH;

            case STATE_LSTAT_GET_HEADER:
                WLOG(WS_LOG_SFTP, "SFTP LSTAT STATE: GET_HEADER");
                /* get attributes response */
                ret = SFTP_GetHeader(ssh, &state->reqId, &state->type);
                if (ret <= 0) {
                    if (ssh->error == WS_WANT_READ ||
                            ssh->error == WS_WANT_WRITE)
                        return WS_FATAL_ERROR;
                    else {
                        state->state = STATE_LSTAT_CLEANUP;
                        continue;
                    }
                }
                state->sz    = (word32)ret;
                state->state = STATE_LSTAT_CHECK_REQ_ID;
                state->data  = (byte*)WMALLOC(state->sz, ssh->ctx->heap,
                        DYNTYPE_BUFFER);
                if (state->data == NULL) {
                    ssh->error = WS_MEMORY_E;
                    return WS_FATAL_ERROR;
                }
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
                ret = wolfSSH_stream_read(ssh, state->data, state->sz);
                if (ret < 0) {
                    if (ssh->error != WS_WANT_READ) {
                        wolfSSH_SFTP_ClearState(ssh, STATE_ID_LSTAT);
                    }
                    return WS_FATAL_ERROR;
                }
                WLOG(WS_LOG_SFTP, "SFTP LSTAT STATE: PARSE_REPLY");
                if (state->type == WOLFSSH_FTP_ATTRS) {
                    ret = SFTP_ParseAtributes_buffer(ssh, atr, state->data,
                            &state->idx, state->sz);
                    if (ret != WS_SUCCESS) {
                        if (ssh->error == WS_WANT_READ ||
                                ssh->error == WS_WANT_WRITE)
                            return WS_FATAL_ERROR;
                        else {
                            state->state = STATE_LSTAT_CLEANUP;
                            continue;
                        }
                    }
                }
                else if (state->type == WOLFSSH_FTP_STATUS) {
                    word32 idx = 0;

                    ret = wolfSSH_SFTP_DoStatus(ssh, state->reqId, state->data,
                            &idx, state->sz);
                    if (ret != WOLFSSH_FTP_OK) {
                        wolfSSH_SFTP_ClearState(ssh, STATE_ID_LSTAT);
                        if (ret == WOLFSSH_FTP_PERMISSION) {
                            return WS_PERMISSIONS;
                        }
                        return WS_FATAL_ERROR;
                    }
                }
                else {
                    WLOG(WS_LOG_SFTP, "Unexpected packet received");
                    wolfSSH_SFTP_ClearState(ssh, STATE_ID_LSTAT);
                    return WS_FATAL_ERROR;
                }
                state->state = STATE_LSTAT_CLEANUP;
                FALL_THROUGH;

            case STATE_LSTAT_CLEANUP:
                WLOG(WS_LOG_SFTP, "SFTP LSTAT STATE: CLEANUP");
                if (ssh->lstatState != NULL) {
                    if (ssh->lstatState->data != NULL) {
                        WFREE(ssh->lstatState->data, ssh->ctx->heap,
                                DYNTYPE_BUFFER);
                        ssh->lstatState->data = NULL;
                    }
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
    byte* data;
    int dirSz, atrSz, status;
    int maxSz;
    word32 reqId;
    word32 idx;
    byte type;

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
        idx = 0;
        data = (byte*)WMALLOC(maxSz, ssh->ctx->heap, DYNTYPE_BUFFER);
        wolfSSH_stream_read(ssh, data, maxSz);
        status = wolfSSH_SFTP_DoStatus(ssh, reqId, data, &idx, maxSz);
        WFREE(data, ssh->ctx->heap, DYNTYPE_BUFFER);
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
    if (state == NULL) {
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
                    ret = WS_FATAL_ERROR;
                    state->state = STATE_OPEN_CLEANUP;
                    continue;
                }

                ret = SFTP_SetHeader(ssh, ssh->reqId, WOLFSSH_FTP_OPEN,
                                     state->sz + UINT32_SZ * 3, state->data);
                if (ret != WS_SUCCESS) {
                    state->state = STATE_OPEN_CLEANUP;
                    continue;
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
                    if (ssh->error == WS_WANT_READ ||
                            ssh->error == WS_WANT_WRITE)
                        return WS_FATAL_ERROR;
                    else {
                        state->state = STATE_OPEN_CLEANUP;
                        continue;
                    }
                }
                WFREE(state->data, NULL, DYNTYPE_BUFFER);
                state->data = NULL;
                state->state = STATE_OPEN_GETHANDLE;
                FALL_THROUGH;

            case STATE_OPEN_GETHANDLE:
                WLOG(WS_LOG_SFTP, "SFTP OPEN STATE: GETHANDLE");
                ret = wolfSSH_SFTP_GetHandle(ssh, handle, handleSz);
                if (ret != WS_SUCCESS) {
                    if (ssh->error == WS_WANT_READ ||
                            ssh->error == WS_WANT_WRITE)
                        return WS_FATAL_ERROR;
                    else {
                        WLOG(WS_LOG_SFTP, "Error getting handle");
                        /* Fall through to cleanup. */
                    }
                }
                state->state = STATE_OPEN_CLEANUP;
                FALL_THROUGH;

            case STATE_OPEN_CLEANUP:
                WLOG(WS_LOG_SFTP, "SFTP OPEN STATE: CLEANUP");
                if (ssh->openState != NULL) {
                    if (state->data != NULL) {
                        WFREE(state->data, ssh->ctx->heap, DYNTYPE_BUFFER);
                        state->data = NULL;
                    }
                    WFREE(ssh->openState, ssh->ctx->heap, DYNTYPE_SFTP_STATE);
                    ssh->openState = NULL;
                }
                return ret;

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
    WS_SFTP_SEND_WRITE_STATE* state = NULL;
    int ret = WS_FATAL_ERROR;
    int status;
    byte type;

    WLOG(WS_LOG_SFTP, "Entering wolfSSH_SFTP_SendWritePacket()");
    if (ssh == NULL || handle == NULL || in == NULL) {
        return WS_BAD_ARGUMENT;
    }

    state = ssh->sendWriteState;
    if (state == NULL) {
        state = (WS_SFTP_SEND_WRITE_STATE*)WMALLOC(
                    sizeof(WS_SFTP_SEND_WRITE_STATE),
                    ssh->ctx->heap, DYNTYPE_SFTP_STATE);
        if (state == NULL) {
            ssh->error = WS_MEMORY_E;
            return WS_FATAL_ERROR;
        }
        WMEMSET(state, 0, sizeof(WS_SFTP_SEND_WRITE_STATE));
        ssh->sendWriteState = state;
        state->state = STATE_SEND_WRITE_INIT;
    }

    for (;;) {
        switch (state->state) {

            case STATE_SEND_WRITE_INIT:
                WLOG(WS_LOG_SFTP, "SFTP SEND_WRITE STATE: INIT");
                state->sentSz = 0;
                state->data = (byte*)WMALLOC(
                        handleSz + WOLFSSH_SFTP_HEADER + UINT32_SZ * 4,
                        ssh->ctx->heap, DYNTYPE_BUFFER);
                if (state->data == NULL) {
                    ssh->error = WS_MEMORY_E;
                    return WS_FATAL_ERROR;
                }

                ret = SFTP_SetHeader(ssh, ssh->reqId, WOLFSSH_FTP_WRITE,
                        handleSz + UINT32_SZ * 4 + inSz, state->data);
                if (ret != WS_SUCCESS) {
                    state->state = STATE_SEND_WRITE_CLEANUP;
                    continue;
                }

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

                /* data to be written */
                c32toa(inSz, state->data + state->idx);
                state->idx += UINT32_SZ;

                state->state = STATE_SEND_WRITE_SEND_HEADER;
                FALL_THROUGH;

            case STATE_SEND_WRITE_SEND_HEADER:
                WLOG(WS_LOG_SFTP, "SFTP SEND_WRITE STATE: SEND_HEADER");
                /* send header and type specific data */
                ret = wolfSSH_stream_send(ssh, state->data, state->idx);
                if (ret < 0) {
                    if (ssh->error == WS_WANT_READ ||
                            ssh->error == WS_WANT_WRITE) {
                        return WS_FATAL_ERROR;
                    }
                    state->state = STATE_SEND_WRITE_CLEANUP;
                    continue;
                }
                state->state = STATE_SEND_WRITE_SEND_BODY;
                FALL_THROUGH;

            case STATE_SEND_WRITE_SEND_BODY:
                WLOG(WS_LOG_SFTP, "SFTP SEND_WRITE STATE: SEND_BODY");
                state->sentSz = wolfSSH_stream_send(ssh, in, inSz);
                if (state->sentSz <= 0) {
                    if (ssh->error == WS_WANT_READ ||
                            ssh->error == WS_WANT_WRITE) {
                        return WS_FATAL_ERROR;
                    }
                    ssh->error = state->sentSz;
                    ret = WS_FATAL_ERROR;
                    state->state = STATE_SEND_WRITE_CLEANUP;
                    continue;
                }
                WFREE(state->data, ssh->ctx->heap, DYNTYPE_BUFFER);
                state->data = NULL;
                state->state = STATE_SEND_WRITE_GET_HEADER;
                FALL_THROUGH;

            case STATE_SEND_WRITE_GET_HEADER:
                WLOG(WS_LOG_SFTP, "SFTP SEND_WRITE STATE: GET_HEADER");
                /* Get response */
                state->maxSz = SFTP_GetHeader(ssh, &state->reqId, &type);
                if (state->maxSz <= 0) {
                    if (ssh->error == WS_WANT_READ ||
                            ssh->error == WS_WANT_WRITE) {
                        return WS_FATAL_ERROR;
                    }
                    state->state = STATE_SEND_WRITE_CLEANUP;
                    continue;
                }
                /* check request ID */
                if (state->reqId != ssh->reqId) {
                    WLOG(WS_LOG_SFTP, "Bad request ID received");
                    ret = WS_FATAL_ERROR;
                    ssh->error = WS_SFTP_BAD_REQ_ID;
                    state->state = STATE_SEND_WRITE_CLEANUP;
                    continue;
                }

                ssh->reqId++;

                if (type != WOLFSSH_FTP_STATUS) {
                    WLOG(WS_LOG_SFTP, "Unexpected packet type");
                    ret = WS_FATAL_ERROR;
                    ssh->error = WS_SFTP_BAD_REQ_TYPE;
                    state->state = STATE_SEND_WRITE_CLEANUP;
                    continue;
                }

                state->idx = 0;
                state->data = (byte*)WMALLOC(state->maxSz,
                        ssh->ctx->heap, DYNTYPE_BUFFER);
                if (state->data == NULL) {
                    ssh->error = WS_MEMORY_E;
                    ret = WS_FATAL_ERROR;
                    state->state = STATE_SEND_WRITE_CLEANUP;
                    continue;
                }
                state->state = STATE_SEND_WRITE_READ_STATUS;
                FALL_THROUGH;

            case STATE_SEND_WRITE_READ_STATUS:
                WLOG(WS_LOG_SFTP, "SFTP SEND_WRITE STATE: READ_STATUS");
                ret = wolfSSH_stream_read(ssh, state->data, state->maxSz);
                if (ret <= 0) {
                    if (ssh->error == WS_WANT_READ ||
                            ssh->error == WS_WANT_WRITE) {
                        return WS_FATAL_ERROR;
                    }
                    state->state = STATE_SEND_WRITE_CLEANUP;
                    continue;
                }
                state->state = STATE_SEND_WRITE_DO_STATUS;
                FALL_THROUGH;

            case STATE_SEND_WRITE_DO_STATUS:
                WLOG(WS_LOG_SFTP, "SFTP SEND_WRITE STATE: DO_STATUS");
                status = wolfSSH_SFTP_DoStatus(ssh, state->reqId, state->data,
                        &state->idx, state->maxSz);
                if (status < 0) {
                    ret = WS_FATAL_ERROR;
                }
                else if (status != WOLFSSH_FTP_OK) {
                    /* @TODO better error value description i.e permissions */
                    ssh->error = WS_SFTP_STATUS_NOT_OK;
                    ret = WS_FATAL_ERROR;
                }
                if (ret >= WS_SUCCESS)
                    ret = state->sentSz;
                state->state = STATE_SEND_WRITE_CLEANUP;
                FALL_THROUGH;

            case STATE_SEND_WRITE_CLEANUP:
                WLOG(WS_LOG_SFTP, "SFTP SEND_WRITE STATE: CLEANUP");
                if (ssh->sendWriteState != NULL) {
                    if (ssh->sendWriteState->data != NULL) {
                        WFREE(ssh->sendWriteState->data,
                              ssh->ctx->heap, DYNTYPE_SFTP_STATE);
                        ssh->sendWriteState->data = NULL;
                    }
                    WFREE(ssh->sendWriteState,
                          ssh->ctx->heap, DYNTYPE_SFTP_STATE);
                    ssh->sendWriteState = NULL;
                }
                return ret;

            default:
                WLOG(WS_LOG_DEBUG, "Bad SFTP Send Write Packet state, "
                                   "program error");
                ssh->error = WS_INPUT_CASE_E;
                return WS_FATAL_ERROR;
        }
    }

    return WS_SUCCESS;
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
                WLOG(WS_LOG_SFTP, "SFTP SEND_READ STATE: INIT");
                state->data = (byte*)WMALLOC(
                            handleSz + WOLFSSH_SFTP_HEADER + UINT32_SZ * 4,
                            ssh->ctx->heap, DYNTYPE_BUFFER);
                if (state->data == NULL) {
                    ssh->error = WS_MEMORY_E;
                    return WS_FATAL_ERROR;
                }

                ret = SFTP_SetHeader(ssh, ssh->reqId, WOLFSSH_FTP_READ,
                            handleSz + UINT32_SZ * 4, state->data);
                if (ret != WS_SUCCESS) {
                    state->state = STATE_SEND_READ_CLEANUP;
                    continue;
                }

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
                WLOG(WS_LOG_SFTP, "SFTP SEND_READ STATE: SEND_REQ");
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
                WLOG(WS_LOG_SFTP, "SFTP SEND_READ STATE: GET_HEADER");
                /* Get response */
                if ((ret = SFTP_GetHeader(ssh, &state->reqId, &state->type))
                        <= 0)
                    return WS_FATAL_ERROR;

                state->sz = ret;
                state->state = STATE_SEND_READ_CHECK_REQ_ID;
                FALL_THROUGH;

            case STATE_SEND_READ_CHECK_REQ_ID:
                WLOG(WS_LOG_SFTP, "SFTP SEND_READ STATE: CHECK_REQ_ID");
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
                WLOG(WS_LOG_SFTP, "SFTP SEND_READ STATE: FTP_DATA");
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
                WLOG(WS_LOG_SFTP, "SFTP SEND_READ STATE: READ_REMAINDER");
                ret = wolfSSH_stream_read(ssh, out, state->sz);
                if (ret < 0) {
                    return ret;
                }
                ret = state->sz;

                state->state = STATE_SEND_READ_CLEANUP;
                continue;

            case STATE_SEND_READ_FTP_STATUS:
                WLOG(WS_LOG_SFTP, "SFTP SEND_READ STATE: READ_FTP_STATUS");
                {
                    word32 lidx = 0;
                    byte* data = (byte*)WMALLOC(state->sz,
                            ssh->ctx->heap, DYNTYPE_BUFFER);
                    ret = wolfSSH_stream_read(ssh, data, state->sz);
                    if (ret < 0) {
                        return WS_FATAL_ERROR;
                    }
                    ret = wolfSSH_SFTP_DoStatus(ssh, state->reqId, data,
                            &lidx, state->sz);
                    WFREE(data, ssh->ctx->heap, DYNTYPE_BUFFER);
                    if (ret == WOLFSSH_FTP_OK || ret == WOLFSSH_FTP_EOF) {
                        WLOG(WS_LOG_SFTP, "OK or EOF found");
                        ret = 0; /* nothing was read */
                    }
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
                return ret;

            default:
                WLOG(WS_LOG_DEBUG, "Bad SFTP Send Read Packet state, "
                                   "program error");
                ssh->error = WS_INPUT_CASE_E;
                return WS_FATAL_ERROR;
        }
    }

    return WS_SUCCESS;
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
    struct WS_SFTP_MKDIR_STATE* state;
    int   ret;
    word32 reqId;
    byte type;
    word32 idx;

    WLOG(WS_LOG_SFTP, "Sending WOLFSSH_FTP_MKDIR");
    if (ssh == NULL || dir == NULL) {
        return WS_BAD_ARGUMENT;
    }

    state = ssh->mkdirState;
    if (state == NULL) {
        state = (WS_SFTP_MKDIR_STATE*)WMALLOC(sizeof(WS_SFTP_MKDIR_STATE),
                    ssh->ctx->heap, DYNTYPE_SFTP_STATE);
        if (state == NULL) {
            ssh->error = WS_MEMORY_E;
            return WS_FATAL_ERROR;
        }
        WMEMSET(state, 0, sizeof(WS_SFTP_MKDIR_STATE));
        ssh->mkdirState = state;
        state->state = STATE_MKDIR_SEND;
    }

    switch (state->state) {
        case STATE_MKDIR_SEND:
            if (state->sz == 0) { /* packet not created yet */
                state->sz = (int)WSTRLEN(dir);
                state->data = (byte*)WMALLOC(state->sz + WOLFSSH_SFTP_HEADER
                        + UINT32_SZ * 3 , ssh->ctx->heap, DYNTYPE_BUFFER);
                if (state->data == NULL) {
                    return WS_MEMORY_E;
                }

                if (SFTP_SetHeader(ssh, ssh->reqId, WOLFSSH_FTP_MKDIR,
                    state->sz + UINT32_SZ * 3, state->data) != WS_SUCCESS) {
                    return WS_FATAL_ERROR;
                }

                idx = WOLFSSH_SFTP_HEADER;
                c32toa(state->sz, state->data + idx);
                idx += UINT32_SZ;
                WMEMCPY(state->data + idx, (byte*)dir, state->sz);
                idx += state->sz;
                c32toa(UINT32_SZ, state->data + idx);
                idx += UINT32_SZ;

                /* @TODO handle setting attributes */
                (void)atr;
                c32toa(0x000001FF, state->data + idx);
                idx += UINT32_SZ;
                state->sz = idx;
            }

            /* send header and type specific data */
            ret = wolfSSH_stream_send(ssh, state->data, state->sz);
            if (ret < 0) {
                if (ssh->error != WS_WANT_READ && ssh->error != WS_WANT_WRITE)
                    wolfSSH_SFTP_ClearState(ssh, STATE_ID_MKDIR);
                return ret;
            }

            /* free data pointer to reuse it later */
            WFREE(state->data, ssh->ctx->heap, DYNTYPE_BUFFER);
            state->data = NULL;
            state->state = STATE_MKDIR_GET;
            FALL_THROUGH;
            /* no break */

        case STATE_MKDIR_GET:
            /* Get response */
            if ((state->sz = SFTP_GetHeader(ssh, &reqId, &type)) <= 0) {
                if (ssh->error != WS_WANT_READ && ssh->error != WS_WANT_WRITE)
                    wolfSSH_SFTP_ClearState(ssh, STATE_ID_MKDIR);
                return WS_FATAL_ERROR;
            }
            if (type != WOLFSSH_FTP_STATUS) {
                WLOG(WS_LOG_SFTP, "Unexpected packet type received");
                wolfSSH_SFTP_ClearState(ssh, STATE_ID_MKDIR);
                return WS_FATAL_ERROR;
            }

            /* check request ID */
            if (reqId != ssh->reqId) {
                WLOG(WS_LOG_SFTP, "Bad request ID received");
                wolfSSH_SFTP_ClearState(ssh, STATE_ID_MKDIR);
                return WS_FATAL_ERROR;
            }
            else {
                ssh->reqId++;
            }

            state->data = (byte*)WMALLOC(state->sz, ssh->ctx->heap,
                    DYNTYPE_BUFFER);
            if (state->data == NULL) {
                wolfSSH_SFTP_ClearState(ssh, STATE_ID_MKDIR);
                return WS_FATAL_ERROR;
            }
            state->state = STATE_MKDIR_STATUS;
            FALL_THROUGH;
            /* no break */

        case STATE_MKDIR_STATUS:
            if ((ret = wolfSSH_stream_read(ssh, state->data, state->sz)) < 0) {
                if (ssh->error != WS_WANT_READ && ssh->error != WS_WANT_WRITE)
                    wolfSSH_SFTP_ClearState(ssh, STATE_ID_MKDIR);
                return WS_FATAL_ERROR;
            }

            idx = 0;
            ret = wolfSSH_SFTP_DoStatus(ssh, reqId, state->data, &idx,
                    state->sz);
            wolfSSH_SFTP_ClearState(ssh, STATE_ID_MKDIR);
            if (ret != WOLFSSH_FTP_OK) {
                if (ret == WOLFSSH_FTP_PERMISSION) {
                    return WS_PERMISSIONS;
                }
                return WS_FATAL_ERROR;
            }
            return WS_SUCCESS;

        default:
            WLOG(WS_LOG_SFTP, "Unkinwon SFTP MKDIR state");
            return WS_FATAL_ERROR;
    }
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
    struct WS_SFTP_READDIR_STATE* state = NULL;
    WS_SFTPNAME* name = NULL;

    WLOG(WS_LOG_SFTP, "Sending WOLFSSH_FTP_READDIR");
    if (ssh == NULL || handle == NULL) {
        WLOG(WS_LOG_SFTP, "Bad argument passed in");
        return NULL;
    }

    state = ssh->readDirState;
    if (state == NULL) {
        state = (WS_SFTP_READDIR_STATE*)WMALLOC(sizeof(WS_SFTP_READDIR_STATE),
                ssh->ctx->heap, DYNTYPE_SFTP_STATE);
        if (state == NULL) {
            ssh->error = WS_MEMORY_E;
            return NULL;
        }
        WMEMSET(state, 0, sizeof(WS_SFTP_READDIR_STATE));
        ssh->readDirState = state;
        state->state = STATE_READDIR_SEND;
    }

    switch (state->state) {
        case STATE_READDIR_SEND:
            ret = SendPacketType(ssh, WOLFSSH_FTP_READDIR, handle, handleSz);
            if (ret != WS_SUCCESS) {
                return NULL;
            }
            state->state = STATE_READDIR_NAME;
            FALL_THROUGH;
            /* no break */

        case STATE_READDIR_NAME:
            name = wolfSSH_SFTP_DoName(ssh);
            if (name == NULL) {
                if (ssh->error != WS_WANT_READ && ssh->error != WS_WANT_WRITE) {
                    wolfSSH_SFTP_ClearState(ssh, STATE_ID_READDIR);
                }
                return NULL;
            }
            wolfSSH_SFTP_ClearState(ssh, STATE_ID_READDIR);
            return name;
    }

    return NULL;
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
    WS_SFTP_CLOSE_STATE* state;
    int    ret = WS_SUCCESS;
    byte   type = 0;

    WLOG(WS_LOG_SFTP, "Sending WOLFSSH_FTP_CLOSE");
    if (ssh == NULL || handle == NULL)
        return WS_BAD_ARGUMENT;

    state = ssh->closeState;
    if (state == NULL) {
        state = (WS_SFTP_CLOSE_STATE*)WMALLOC(sizeof(WS_SFTP_CLOSE_STATE),
                ssh->ctx->heap, DYNTYPE_SFTP_STATE);
        if (state == NULL) {
            ssh->error = WS_MEMORY_E;
            return WS_FATAL_ERROR;
        }
        WMEMSET(state, 0, sizeof(WS_SFTP_CLOSE_STATE));
        ssh->closeState = state;
        state->state = STATE_CLOSE_INIT;
    }

    for (;;) {
        switch (state->state) {
            case STATE_CLOSE_INIT:
                WLOG(WS_LOG_SFTP, "SFTP CLOSE STATE: INIT");
                state->state = STATE_CLOSE_SEND;
                FALL_THROUGH;

            case STATE_CLOSE_SEND:
                WLOG(WS_LOG_SFTP, "SFTP CLOSE STATE: SEND");
                ret = SendPacketType(ssh, WOLFSSH_FTP_CLOSE, handle, handleSz);
                if (ssh->error == WS_WANT_WRITE || ssh->error == WS_WANT_READ)
                {
                    return ret;
                }

                if (ret != WS_SUCCESS) {
                    state->state = STATE_CLOSE_CLEANUP;
                    continue;
                }
                state->state = STATE_CLOSE_GET_HEADER;
                FALL_THROUGH;

            case STATE_CLOSE_GET_HEADER:
                WLOG(WS_LOG_SFTP, "SFTP CLOSE STATE: GET_HEADER");
                ret = SFTP_GetHeader(ssh, &state->reqId, &type);
                if (ret <= 0 &&
                        (ssh->error == WS_WANT_WRITE ||
                         ssh->error == WS_WANT_READ))
                    return ret;

                if (type != WOLFSSH_FTP_STATUS || ret <= 0) {
                    WLOG(WS_LOG_SFTP, "Unexpected packet type");
                    ret = WS_FATAL_ERROR;
                    state->state = STATE_CLOSE_CLEANUP;
                    continue;
                }
                state->sz = ret;
                state->state = STATE_CLOSE_DO_STATUS;
                state->data = (byte*)WMALLOC(state->sz,
                        ssh->ctx->heap, DYNTYPE_BUFFER);
                FALL_THROUGH;

            case STATE_CLOSE_DO_STATUS:
                WLOG(WS_LOG_SFTP, "SFTP CLOSE STATE: DO_STATUS");
                {
                    word32 idx = 0;
                    ret = wolfSSH_stream_read(ssh, state->data, state->sz);
                    if (ret < 0) {
                        if (ssh->error != WS_WANT_WRITE &&
                                ssh->error != WS_WANT_READ) {
                            WFREE(state->data, ssh->ctx->heap, DYNTYPE_BUFFER);
                        }
                        return WS_FATAL_ERROR;
                    }

                    ret = wolfSSH_SFTP_DoStatus(ssh, state->reqId, state->data,
                            &idx, state->sz);
                    WFREE(state->data, ssh->ctx->heap, DYNTYPE_BUFFER);
                    state->data = NULL;
                }
                if (ret == WOLFSSH_FTP_OK)
                    ret = WS_SUCCESS;
                else
                    ret = WS_FATAL_ERROR;
                state->state = STATE_CLOSE_CLEANUP;
                FALL_THROUGH;

            case STATE_CLOSE_CLEANUP:
                WLOG(WS_LOG_SFTP, "SFTP CLOSE STATE: CLEANUP");
                if (ssh->closeState != NULL) {
                    WFREE(ssh->closeState, ssh->ctx->heap, DYNTYPE_SFTP_STATE);
                    ssh->closeState = NULL;
                }
                return ret;

            default:
                WLOG(WS_LOG_DEBUG, "Bad SFTP Close state, program error");
                return WS_INPUT_CASE_E;
        }
    }

    return WS_SUCCESS;
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
    WS_SFTPNAME* ret = NULL;

    WLOG(WS_LOG_SFTP, "Sending WOLFSSH_FTP_REALPATH");
    if (ssh == NULL || dir == NULL) {
        WLOG(WS_LOG_SFTP, "Bad argument passed in");
        return NULL;
    }

    switch (ssh->realState) {
        case SFTP_REAL_SEND_PACKET:
            sz = (int)WSTRLEN(dir);
            if (SendPacketType(ssh, WOLFSSH_FTP_REALPATH, (byte*)dir, sz) !=
                WS_SUCCESS) {
                return NULL;
            }
            ssh->realState = SFTP_REAL_GET_PACKET;
            FALL_THROUGH;
            /* no break */

        case SFTP_REAL_GET_PACKET:
            /* read name response from Real Path packet */
            ret = wolfSSH_SFTP_DoName(ssh);
            if (ret != NULL || (ret == NULL && ssh->error != WS_WANT_READ)) {
                wolfSSH_SFTP_ClearState(ssh, STATE_ID_NAME);
                ssh->realState = SFTP_REAL_SEND_PACKET;
            }
            break;
    }

    return ret;
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
    WS_SFTP_RENAME_STATE* state;
    int ret = WS_SUCCESS;
    byte type;

    WLOG(WS_LOG_SFTP, "Entering wolfSSH_SFTP_Rename");
    if (ssh == NULL || old == NULL || nw == NULL) {
        return WS_BAD_ARGUMENT;
    }

    if (ssh->error == WS_WANT_READ || ssh->error == WS_WANT_WRITE)
        ssh->error = WS_SUCCESS;

    state = ssh->renameState;
    if (state == NULL) {
        state = (WS_SFTP_RENAME_STATE*)WMALLOC(sizeof(WS_SFTP_RENAME_STATE),
                ssh->ctx->heap, DYNTYPE_SFTP_STATE);
        if (state == NULL) {
            ssh->error = WS_MEMORY_E;
            return WS_FATAL_ERROR;
        }
        WMEMSET(state, 0, sizeof(WS_SFTP_RENAME_STATE));
        ssh->renameState = state;
        state->state = STATE_RENAME_INIT;
    }

    for (;;) {
        switch (state->state) {

            case STATE_RENAME_INIT:
                WLOG(WS_LOG_SFTP, "SFTP RENAME STATE: INIT");
                FALL_THROUGH;

            case STATE_RENAME_GET_STAT:
                WLOG(WS_LOG_SFTP, "SFTP RENAME STATE: GET_STAT");
                /* check that file exists */
                ret = wolfSSH_SFTP_STAT(ssh, (char*)old, &state->atrb);
                if (ret != WS_SUCCESS) {
                    if (ssh->error == WS_WANT_READ ||
                            ssh->error == WS_WANT_WRITE) {
                        return WS_FATAL_ERROR;
                    }
                    WLOG(WS_LOG_SFTP, "Error finding file to rename");
                    state->state = STATE_RENAME_CLEANUP;
                    continue;
                }

                state->sz = (int)(WSTRLEN(old) + WSTRLEN(nw));
                state->data = (byte*)WMALLOC(
                        state->sz + WOLFSSH_SFTP_HEADER + UINT32_SZ * 2,
                        ssh->ctx->heap, DYNTYPE_BUFFER);
                if (state->data == NULL) {
                    ssh->error = WS_MEMORY_E;
                    ret = WS_FATAL_ERROR;
                    state->state = STATE_RENAME_CLEANUP;
                    continue;
                }

                ret = SFTP_SetHeader(ssh, ssh->reqId, WOLFSSH_FTP_RENAME,
                            state->sz + UINT32_SZ * 2, state->data);
                if (ret != WS_SUCCESS) {
                    state->state = STATE_RENAME_CLEANUP;
                    continue;
                }

                /* add old name to the packet */
                state->idx = WOLFSSH_SFTP_HEADER;
                c32toa((word32)WSTRLEN(old), state->data + state->idx);
                state->idx += UINT32_SZ;
                WMEMCPY(state->data + state->idx, (byte*)old, WSTRLEN(old));
                state->idx += (word32)WSTRLEN(old);

                /* add new name to the packet */
                c32toa((word32)WSTRLEN(nw), state->data + state->idx);
                state->idx += UINT32_SZ;
                WMEMCPY(state->data + state->idx, (byte*)nw, WSTRLEN(nw));
                state->idx += (word32)WSTRLEN(nw);

                state->state = STATE_RENAME_SEND;
                FALL_THROUGH;

            case STATE_RENAME_SEND:
                WLOG(WS_LOG_SFTP, "SFTP RENAME STATE: SEND");
                /* send header and type specific data */
                ret = wolfSSH_stream_send(ssh, state->data, state->idx);
                if (ret <= 0) {
                    if (ssh->error == WS_WANT_READ ||
                            ssh->error == WS_WANT_WRITE) {
                        return WS_FATAL_ERROR;
                    }
                    state->state = STATE_RENAME_CLEANUP;
                    continue;
                }
                WFREE(state->data, ssh->ctx->heap, DYNTYPE_BUFFER);
                state->data = NULL;
                state->state = STATE_RENAME_GET_HEADER;
                FALL_THROUGH;

            case STATE_RENAME_GET_HEADER:
                WLOG(WS_LOG_SFTP, "SFTP RENAME STATE: GET_HEADER");
                /* Get response */
                state->maxSz = SFTP_GetHeader(ssh, &state->reqId, &type);
                if (state->maxSz <= 0) {
                    if (ssh->error == WS_WANT_READ ||
                            ssh->error == WS_WANT_WRITE) {
                        return WS_FATAL_ERROR;
                    }
                    state->state = STATE_RENAME_CLEANUP;
                    continue;
                }
                /* check request ID */
                if (state->reqId != ssh->reqId) {
                    WLOG(WS_LOG_SFTP, "Bad request ID received");
                    ret = WS_FATAL_ERROR;
                    ssh->error = WS_SFTP_BAD_REQ_ID;
                    state->state = STATE_RENAME_CLEANUP;
                    continue;
                }

                ssh->reqId++;

                if (type != WOLFSSH_FTP_STATUS) {
                    WLOG(WS_LOG_SFTP, "Unexpected packet type");
                    ret = WS_FATAL_ERROR;
                    ssh->error = WS_SFTP_BAD_REQ_TYPE;
                    state->state = STATE_RENAME_CLEANUP;
                    continue;
                }

                state->idx = 0;
                state->data = (byte*)WMALLOC(state->maxSz,
                        ssh->ctx->heap, DYNTYPE_BUFFER);
                if (state->data == NULL) {
                    ssh->error = WS_MEMORY_E;
                    ret = WS_FATAL_ERROR;
                    state->state = STATE_RENAME_CLEANUP;
                    continue;
                }
                state->state = STATE_RENAME_READ_STATUS;
                FALL_THROUGH;

            case STATE_RENAME_READ_STATUS:
                WLOG(WS_LOG_SFTP, "SFTP RENAME STATE: READ_STATUS");
                ret = wolfSSH_stream_read(ssh, state->data, state->maxSz);
                if (ret <= 0) {
                    if (ssh->error == WS_WANT_READ ||
                            ssh->error == WS_WANT_WRITE) {
                        return WS_FATAL_ERROR;
                    }
                    state->state = STATE_RENAME_CLEANUP;
                    continue;
                }
                state->state = STATE_RENAME_DO_STATUS;
                FALL_THROUGH;

            case STATE_RENAME_DO_STATUS:
                WLOG(WS_LOG_SFTP, "SFTP RENAME STATE: DO_STATUS");
                ret = wolfSSH_SFTP_DoStatus(ssh, state->reqId, state->data,
                        &state->idx, state->maxSz);
                WLOG(WS_LOG_SFTP, "Status = %d", ret);
                if (ret < 0) {
                    ret = WS_FATAL_ERROR;
                }
                else if (ret == WOLFSSH_FTP_PERMISSION) {
                    ssh->error = WS_PERMISSIONS;
                    ret = WS_FATAL_ERROR;
                }
                else if (ret != WOLFSSH_FTP_OK) {
                    ssh->error = WS_SFTP_STATUS_NOT_OK;
                    ret = WS_FATAL_ERROR;
                }
                state->state = STATE_RENAME_CLEANUP;
                FALL_THROUGH;

            case STATE_RENAME_CLEANUP:
                WLOG(WS_LOG_SFTP, "SFTP RENAME STATE: CLEANUP");
                if (ssh->renameState != NULL) {
                    if (ssh->renameState->data != NULL) {
                        WFREE(ssh->renameState->data, ssh->ctx->heap,
                                DYNTYPE_SFTP_STATE);
                        ssh->renameState->data = NULL;
                    }
                    WFREE(ssh->renameState, ssh->ctx->heap, DYNTYPE_SFTP_STATE);
                    ssh->renameState = NULL;
                }
                return ret;

            default:
                WLOG(WS_LOG_DEBUG, "Bad SFTP Rename state, program error");
                ssh->error = WS_INPUT_CASE_E;
                return WS_FATAL_ERROR;
        }
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
    struct WS_SFTP_RM_STATE* state;
    WS_SFTP_FILEATRB atrb;
    int    ret;
    word32 reqId;
    word32 idx = 0;
    byte   type;

    WLOG(WS_LOG_SFTP, "Sending WOLFSSH_FTP_REMOVE");
    if (ssh == NULL || f == NULL) {
        return WS_BAD_ARGUMENT;
    }

    if (ssh->error == WS_WANT_WRITE || ssh->error == WS_WANT_READ)
        ssh->error = WS_SUCCESS;

    state = ssh->rmState;
    if (state == NULL) {
        state = (WS_SFTP_RM_STATE*)WMALLOC(sizeof(WS_SFTP_RM_STATE),
                ssh->ctx->heap, DYNTYPE_SFTP_STATE);
        if (state == NULL) {
            ssh->error = WS_MEMORY_E;
            return WS_FATAL_ERROR;
        }
        WMEMSET(state, 0, sizeof(WS_SFTP_RM_STATE));
        ssh->rmState = state;
        state->state = STATE_RM_LSTAT;
    }

    switch (state->state) {
        case STATE_RM_LSTAT:
            /* check file is there to be removed */
            if ((ret = wolfSSH_SFTP_LSTAT(ssh, f, &atrb)) != WS_SUCCESS) {
                if (ssh->error != WS_WANT_READ && ssh->error != WS_WANT_READ) {
                    WLOG(WS_LOG_SFTP, "Error verifying file");
                    wolfSSH_SFTP_ClearState(ssh, STATE_ID_RM);
                }
                return ret;
            }
            state->state = STATE_RM_SEND;
            FALL_THROUGH;
            /* no break */

        case STATE_RM_SEND:
            ret = SendPacketType(ssh, WOLFSSH_FTP_REMOVE, (byte*)f,
                    (word32)WSTRLEN(f));
            if (ret != WS_SUCCESS) {
                if (ssh->error != WS_WANT_READ && ssh->error != WS_WANT_READ) {
                    wolfSSH_SFTP_ClearState(ssh, STATE_ID_RM);
                }
                return ret;
            }
            state->state = STATE_RM_GET;
            FALL_THROUGH;
            /* no break */

        case STATE_RM_GET:
            ret = SFTP_GetHeader(ssh, &reqId, &type);
            if (ret <= 0 || type != WOLFSSH_FTP_STATUS) {
                if (ssh->error != WS_WANT_READ && ssh->error != WS_WANT_READ) {
                    WLOG(WS_LOG_SFTP, "Unexpected packet type");
                    wolfSSH_SFTP_ClearState(ssh, STATE_ID_RM);
                }
                return WS_FATAL_ERROR;
            }
            state->sz = ret;
            state->data = (byte*)WMALLOC(state->sz, ssh->ctx->heap,
                    DYNTYPE_BUFFER);
            if (state->data == NULL) {
                wolfSSH_SFTP_ClearState(ssh, STATE_ID_RM);
                return WS_FATAL_ERROR;
            }
            state->state = STATE_RM_DOSTATUS;
            FALL_THROUGH;
            /* no break */

       case STATE_RM_DOSTATUS:
            if ((ret = wolfSSH_stream_read(ssh, state->data, state->sz)) < 0) {
                if (ssh->error != WS_WANT_READ && ssh->error != WS_WANT_READ) {
                    WLOG(WS_LOG_SFTP, "Unexpected packet type");
                    wolfSSH_SFTP_ClearState(ssh, STATE_ID_RM);
                }
                return WS_FATAL_ERROR;
            }

            ret = wolfSSH_SFTP_DoStatus(ssh, reqId, state->data, &idx,
                    state->sz);
            wolfSSH_SFTP_ClearState(ssh, STATE_ID_RM);
            if (ret == WOLFSSH_FTP_OK) {
                return WS_SUCCESS;
            }
            else {
                /* @TODO can return better error value i.e. permissions */
                return WS_FATAL_ERROR;
            }

        default:
            WLOG(WS_LOG_SFTP, "Unknown SFTP remove state");
    }

    return WS_FATAL_ERROR;
}


/* removes a directory
 *
 * dir   name of directory to remove
 *
 * returns WS_SUCCESS on success
 */
int wolfSSH_SFTP_RMDIR(WOLFSSH* ssh, char* dir)
{
    struct WS_SFTP_RMDIR_STATE* state = NULL;
    int    ret;
    word32 reqId;
    byte   type;
    word32 idx = 0;

    WLOG(WS_LOG_SFTP, "Sending WOLFSSH_FTP_RMDIR");
    if (ssh == NULL || dir == NULL) {
        return WS_BAD_ARGUMENT;
    }

    state = ssh->rmdirState;
    if (state == NULL) {
        state = (WS_SFTP_RMDIR_STATE*)WMALLOC(sizeof(WS_SFTP_RMDIR_STATE),
                    ssh->ctx->heap, DYNTYPE_SFTP_STATE);
        if (state == NULL) {
            ssh->error = WS_MEMORY_E;
            return WS_FATAL_ERROR;
        }
        WMEMSET(state, 0, sizeof(WS_SFTP_RMDIR_STATE));
        ssh->rmdirState = state;
        state->state = STATE_RMDIR_SEND;
    }

    switch (state->state) {
        case STATE_RMDIR_SEND:
            ret = SendPacketType(ssh, WOLFSSH_FTP_RMDIR, (byte*)dir,
                (word32)WSTRLEN(dir));
            if (ret != WS_SUCCESS) {
                if (ssh->error != WS_WANT_READ && ssh->error != WS_WANT_WRITE) {
                    wolfSSH_SFTP_ClearState(ssh, STATE_ID_RMDIR);
                }
                return ret;
            }
            state->state = STATE_RMDIR_GET;
            FALL_THROUGH;
            /* no break */

        case STATE_RMDIR_GET:
            ret = SFTP_GetHeader(ssh, &reqId, &type);
            if (ret <= 0 || type != WOLFSSH_FTP_STATUS) {
                if (ssh->error != WS_WANT_READ) {
                    wolfSSH_SFTP_ClearState(ssh, STATE_ID_RMDIR);
                    WLOG(WS_LOG_SFTP, "Unexpected packet type");
                }
                return WS_FATAL_ERROR;
            }
            state->sz = ret;
            state->data = (byte*)WMALLOC(state->sz, ssh->ctx->heap,
                    DYNTYPE_BUFFER);
            if (state->data == NULL) {
                wolfSSH_SFTP_ClearState(ssh, STATE_ID_RMDIR);
                return WS_MEMORY_E;
            }
            state->state = STATE_RMDIR_STATUS;
            FALL_THROUGH;
            /* no break */

        case STATE_RMDIR_STATUS:
            if ((ret = wolfSSH_stream_read(ssh, state->data, state->sz)) < 0) {
                if (ssh->error != WS_WANT_READ)
                    wolfSSH_SFTP_ClearState(ssh, STATE_ID_RMDIR);
                return WS_FATAL_ERROR;
            }

            ret = wolfSSH_SFTP_DoStatus(ssh, reqId, state->data, &idx,
                    state->sz);
            wolfSSH_SFTP_ClearState(ssh, STATE_ID_RMDIR);
            if (ret == WOLFSSH_FTP_OK) {
                return WS_SUCCESS;
            }
            else {
                /* @TODO can return better error value i.e. permissions */
                ssh->error = ret;
                return WS_FATAL_ERROR;
            }

        default:
            wolfSSH_SFTP_ClearState(ssh, STATE_ID_RMDIR);
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
                    if (ssh->error == WS_WANT_READ ||
                            ssh->error == WS_WANT_WRITE)
                        return WS_FATAL_ERROR;
                    WLOG(WS_LOG_SFTP, "Error verifying file");
                    state->state = STATE_GET_CLEANUP;
                    continue;
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
                    if (ssh->error == WS_WANT_READ ||
                            ssh->error == WS_WANT_WRITE) {
                        return WS_FATAL_ERROR;
                    }
                    WLOG(WS_LOG_SFTP, "Error getting handle");
                    state->state = STATE_GET_CLEANUP;
                    continue;
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
                #ifndef USE_WINDOWS_API
                    if (state->gOfst > 0)
                        ret = WFOPEN(&state->fl, to, "ab");
                    else
                        ret = WFOPEN(&state->fl, to, "wb");
                #else /* USE_WINDOWS_API */
                    {
                        DWORD desiredAccess = GENERIC_WRITE;
                        if (state->gOfst > 0)
                            desiredAccess |= FILE_APPEND_DATA;
                        state->fileHandle = CreateFileA(to, desiredAccess,
                                0, NULL, CREATE_NEW,
                                FILE_ATTRIBUTE_NORMAL, NULL);
                    }
                    if (resume) {
                        WMEMSET(&state->offset, 0, sizeof(OVERLAPPED));
                        state->offset.OffsetHigh = 0;
                        state->offset.Offset = (DWORD)state->gOfst;
                    }
                #endif /* USE_WINDOWS_API */
                if (ret != 0) {
                    WLOG(WS_LOG_SFTP, "Unable to open output file");
                    ssh->error = WS_BAD_FILE_E;
                    ret = WS_FATAL_ERROR;
                    state->state = STATE_GET_CLEANUP;
                    continue;
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
                    if (sz < 0) {
                        if (ssh->error == WS_WANT_READ ||
                                ssh->error == WS_WANT_WRITE) {
                            return WS_FATAL_ERROR;
                        }
                        WLOG(WS_LOG_SFTP, "Error reading packet");
                        ret = WS_FATAL_ERROR;
                        state->state = STATE_GET_CLEANUP;
                        break;
                    }
                    else {
                    #ifndef USE_WINDOWS_API
                        if ((long)WFWRITE(state->r, 1,
                                          sz, state->fl) != sz) {
                            WLOG(WS_LOG_SFTP, "Error writing to file");
                            ssh->error = WS_BAD_FILE_E;
                            ret = WS_FATAL_ERROR;
                            state->state = STATE_GET_CLEANUP;
                            break;
                        }
                    #else /* USE_WINDOWS_API */
                        {
                            DWORD bytesWritten;
                            if (WriteFile(state->fileHandle, state->r, sz,
                                         &bytesWritten, &state->offset) == 0 ||
                                    (DWORD)sz != bytesWritten) {
                                break; /* either at end of file or error */
                            }
                        }
                    #endif /* USE_WINDOWS_API */
                        state->gOfst += sz;
                        #ifdef USE_WINDOWS_API
                            state->offset.OffsetHigh = 0;
                            state->offset.Offset = (DWORD)state->gOfst;
                        #endif /* USE_WINDOWS_API */
                        if (statusCb != NULL) {
                            statusCb(ssh, state->gOfst, from);
                        }
                    }
                } while (sz > 0 && ssh->sftpInt == 0);
                if (ret != WS_SUCCESS)
                    continue;
                if (ssh->sftpInt) {
                    WLOG(WS_LOG_SFTP, "Interrupted, trying to save offset");
                    wolfSSH_SFTP_SaveOfst(ssh, from, to, state->gOfst);
                }
                ssh->sftpInt = 0;
                state->state = STATE_GET_CLOSE_LOCAL;
                FALL_THROUGH;

            case STATE_GET_CLOSE_LOCAL:
                WLOG(WS_LOG_SFTP, "SFTP GET STATE: CLOSE LOCAL");
                #ifndef USE_WINDOWS_API
                    WFCLOSE(state->fl);
                #else /* USE_WINDOWS_API */
                    CloseHandle(state->fileHandle);
                #endif /* USE_WINDOWS_API */
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
                return ret;

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
    WS_SFTP_PUT_STATE* state = NULL;
    int ret = WS_SUCCESS;
    int sz;

    if (ssh == NULL || from == NULL || to == NULL) {
        return WS_BAD_ARGUMENT;
    }

    if (ssh->error == WS_WANT_READ || ssh->error == WS_WANT_WRITE)
        ssh->error = WS_SUCCESS;

    state = ssh->putState;
    if (state == NULL) {
        state = (WS_SFTP_PUT_STATE*)WMALLOC(sizeof(WS_SFTP_PUT_STATE),
                ssh->ctx->heap, DYNTYPE_SFTP_STATE);
        if (state == NULL) {
            ssh->error = WS_MEMORY_E;
            return WS_FATAL_ERROR;
        }
        WMEMSET(state, 0, sizeof(WS_SFTP_PUT_STATE));
        ssh->putState = state;
        state->state = STATE_PUT_INIT;
    }

    for (;;) {
        switch (state->state) {

            case STATE_PUT_INIT:
                WLOG(WS_LOG_SFTP, "SFTP PUT STATE: INIT");
                state->pOfst = 0;
                state->state = STATE_PUT_LOOKUP_OFFSET;
                FALL_THROUGH;

            case STATE_PUT_LOOKUP_OFFSET:
                WLOG(WS_LOG_SFTP, "SFTP PUT STATE: LOOKUP OFFSET");
                if (resume) {
                    /* check if offset was stored */
                    state->pOfst = (long)wolfSSH_SFTP_GetOfst(ssh, from, to);
                }
                state->handleSz = WOLFSSH_MAX_HANDLE;
                state->state = STATE_PUT_OPEN_LOCAL;
                FALL_THROUGH;

            case STATE_PUT_OPEN_LOCAL:
                WLOG(WS_LOG_SFTP, "SFTP PUT STATE: OPEN LOCAL");
            #ifndef USE_WINDOWS_API
                ret = WFOPEN(&state->fl, from, "rb");
                if (ret != 0) {
                    WLOG(WS_LOG_SFTP, "Unable to open input file");
                    ssh->error = WS_SFTP_FILE_DNE;
                    ret = WS_FATAL_ERROR;
                    state->state = STATE_PUT_CLEANUP;
                    continue;
                }
                if (resume) {
                    WFSEEK(state->fl, state->pOfst, 0);
                }
            #else /* USE_WINDOWS_API */
                state->fileHandle = CreateFileA(from, GENERIC_READ,
                        FILE_SHARE_READ, NULL, OPEN_EXISTING,
                        FILE_ATTRIBUTE_NORMAL, NULL);
                if (resume) {
                    WMEMSET(&state->offset, 0, sizeof(OVERLAPPED));
                    state->offset.OffsetHigh = 0;
                    state->offset.Offset = (DWORD)state->pOfst;
                }
            #endif /* USE_WINDOWS_API */
                state->rSz = 0;
                state->state = STATE_PUT_OPEN_REMOTE;
                FALL_THROUGH;

            case STATE_PUT_OPEN_REMOTE:
                WLOG(WS_LOG_SFTP, "SFTP PUT STATE: OPEN REMOTE");
                /* open file and get handle */
                ret = wolfSSH_SFTP_Open(ssh, to, (WOLFSSH_FXF_WRITE |
                            WOLFSSH_FXF_CREAT | WOLFSSH_FXF_TRUNC), NULL,
                            state->handle, &state->handleSz);
                if (ret != WS_SUCCESS) {
                    if (ssh->error == WS_WANT_READ ||
                            ssh->error == WS_WANT_WRITE) {
                        return WS_FATAL_ERROR;
                    }
                    WLOG(WS_LOG_SFTP, "Error getting handle");
                    state->state = STATE_PUT_CLEANUP;
                    continue;
                }
                state->state = STATE_PUT_WRITE;
                FALL_THROUGH;

            case STATE_PUT_WRITE:
                WLOG(WS_LOG_SFTP, "SFTP PUT STATE: WRITE");
                do {
                    if (state->rSz == 0) {
                    #ifndef USE_WINDOWS_API
                        state->rSz = (int)WFREAD(state->r,
                                1, WOLFSSH_MAX_SFTP_RW, state->fl);
                        if (state->rSz <= 0) {
                            break; /* either at end of file or error */
                        }
                    #else /* USE_WINDOWS_API */
                        if (ReadFile(state->fileHandle, state->r,
                                     WOLFSSH_MAX_SFTP_RW, &state->rSz,
                                     &state->offset) == 0) {
                            break; /* either at end of file or error */
                        }
                    #endif /* USE_WINDOWS_API */
                    }
                    sz = wolfSSH_SFTP_SendWritePacket(ssh,
                            state->handle, state->handleSz, state->pOfst,
                            state->r, state->rSz);
                    if (sz <= 0) {
                        if (ssh->error == WS_WANT_READ ||
                                ssh->error == WS_WANT_WRITE)
                            return WS_FATAL_ERROR;
                    }
                    else {
                        state->pOfst += sz;
                        #ifdef USE_WINDOWS_API
                            state->offset.OffsetHigh = 0;
                            state->offset.Offset = (DWORD)state->pOfst;
                        #endif /* USE_WINDOWS_API */
                        state->rSz -= sz;
                        if (statusCb != NULL) {
                            statusCb(ssh, state->pOfst, from);
                        }
                    }
                    /* check for adjust window packet */
                    wolfSSH_CheckReceivePending(ssh);
                } while (sz > 0 && ssh->sftpInt == 0);

                if (ssh->sftpInt) {
                    wolfSSH_SFTP_SaveOfst(ssh, from, to, state->pOfst);
                    ssh->sftpInt = 0;
                }
                FALL_THROUGH;

            case STATE_PUT_CLOSE_LOCAL:
                WLOG(WS_LOG_SFTP, "SFTP PUT STATE: CLOSE LOCAL");
            #ifndef USE_WINDOWS_API
                WFCLOSE(state->fl);
            #else /* USE_WINDOWS_API */
                CloseHandle(state->fileHandle);
            #endif /* USE_WINDOWS_API */
                state->state = STATE_PUT_CLOSE_REMOTE;
                FALL_THROUGH;

            case STATE_PUT_CLOSE_REMOTE:
                WLOG(WS_LOG_SFTP, "SFTP PUT STATE: CLOSE REMOTE");
                ret = wolfSSH_SFTP_Close(ssh, state->handle, state->handleSz);
                if (ret != WS_SUCCESS) {
                    if (ssh->error == WS_WANT_READ ||
                            ssh->error == WS_WANT_WRITE) {
                        return WS_FATAL_ERROR;
                    }
                    WLOG(WS_LOG_SFTP, "Error closing handle");
                    /* Fall through to cleanup. */
                }
                state->state = STATE_PUT_CLEANUP;
                FALL_THROUGH;

            case STATE_PUT_CLEANUP:
                WLOG(WS_LOG_SFTP, "SFTP PUT STATE: CLEANUP");
                if (ssh->putState != NULL) {
                    WFREE(ssh->putState, ssh->ctx->heap, DYNTYPE_SFTP_STATE);
                    ssh->putState = NULL;
                }
                return ret;

            default:
                WLOG(WS_LOG_DEBUG, "Bad SFTP Put state, program error");
                return WS_INPUT_CASE_E;
        }
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

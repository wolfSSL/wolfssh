/* wolfsftp.c
 *
 * Copyright (C) 2014-2024 wolfSSL Inc.
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
    #if defined(WOLFSSL_NUCLEUS)
        #include "src/wolfssh_misc.c"
    #else
        #include "src/misc.c"
    #endif
#endif

/* for XGMTIME if defined */
#include <wolfssl/wolfcrypt/wc_port.h>


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
    STATE_ID_CHMOD      = 0x20000,
    STATE_ID_SETATR     = 0x40000,
    STATE_ID_RECV_INIT  = 0x80000,
};

enum WS_SFTP_CHMOD_STATE_ID {
    STATE_CHMOD_GET,
    STATE_CHMOD_SEND
};

enum WS_SFTP_SETATR_STATE_ID {
    STATE_SET_ATR_INIT,
    STATE_SET_ATR_SEND,
    STATE_SET_ATR_GET,
    STATE_SET_ATR_STATUS
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

/* This structure is to help with nonblocking and keeping track of state.
 * If adding any read/writes use the wolfSSH_SFTP_buffer_read/send functions */
typedef struct WS_SFTP_BUFFER {
    byte*  data;
    word32 sz;
    word32 idx;
} WS_SFTP_BUFFER;

typedef struct WS_SFTP_CHMOD_STATE {
    enum WS_SFTP_CHMOD_STATE_ID state;
    WS_SFTP_FILEATRB atr;
} WS_SFTP_CHMOD_STATE;


typedef struct WS_SFTP_SETATR_STATE {
    enum WS_SFTP_SETATR_STATE_ID state;
    WS_SFTP_BUFFER buffer;
    word32 reqId;
} WS_SFTP_SETATR_STATE;


typedef struct WS_SFTP_LSTAT_STATE {
    enum WS_SFTP_LSTAT_STATE_ID state;
    word32 reqId;
    word32 dirSz;

    WS_SFTP_BUFFER buffer;
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
    WS_SFTP_BUFFER buffer;
} WS_SFTP_OPEN_STATE;


/* similar to open state, could refactor */
typedef struct WS_SFTP_NAME_STATE {
    enum WS_SFTP_NAME_STATE_ID state;
    WS_SFTP_BUFFER buffer;
} WS_SFTP_NAME_STATE;

/* similar to open state, could refactor */
typedef struct WS_SFTP_SEND_STATE {
    enum WS_SFTP_SEND_STATE_ID state;
    WS_SFTP_BUFFER buffer;
} WS_SFTP_SEND_STATE;

/* similar to open state, could refactor */
typedef struct WS_SFTP_READDIR_STATE {
    enum WS_SFTP_READDIR_STATE_ID state;
    WS_SFTP_BUFFER buffer;
} WS_SFTP_READDIR_STATE;

/* similar to open state, could refactor */
typedef struct WS_SFTP_RM_STATE {
    enum WS_SFTP_RM_STATE_ID state;
    WS_SFTP_BUFFER buffer;
    word32 reqId;
} WS_SFTP_RM_STATE;

/* similar to open state, could refactor */
typedef struct WS_SFTP_MKDIR_STATE {
    enum WS_SFTP_MKDIR_STATE_ID state;
    WS_SFTP_BUFFER buffer;
    word32 reqId;
} WS_SFTP_MKDIR_STATE;

/* similar to open state, could refactor */
typedef struct WS_SFTP_RMDIR_STATE {
    enum WS_SFTP_RMDIR_STATE_ID state;
    WS_SFTP_BUFFER buffer;
    word32 reqId;
} WS_SFTP_RMDIR_STATE;

typedef struct WS_SFTP_RECV_STATE {
    enum WS_SFTP_RECV_STATE_ID state;
    WS_SFTP_BUFFER buffer;
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


typedef struct WS_SFTP_RECV_INIT_STATE {
    WS_SFTP_BUFFER buffer;
    word32 extSz;
} WS_SFTP_RECV_INIT_STATE;

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
    #ifdef WOLFSSL_NUCLEUS
    int   fd; /* file descriptor, in the case of Nucleus fp points to fd */
    #endif
#else
    HANDLE fileHandle;
    OVERLAPPED offset;
#endif
    word32 gOfst[2];
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
    #ifdef WOLFSSL_NUCLEUS
    int   fd; /* file descriptor, in the case of Nucleus fp points to fd */
    #endif
#else
    HANDLE fileHandle;
    OVERLAPPED offset;
#endif
    word32 pOfst[2];
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
    word32 reqId;
    WS_SFTP_BUFFER buffer;
    word32 recvSz;
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
    word32 reqId;
    WS_SFTP_BUFFER buffer;
    int maxSz;
    int sentSz;
    int sentSzSave;
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
    WS_SFTP_BUFFER buffer;
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
    WS_SFTP_BUFFER buffer;
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
    WS_SFTP_BUFFER buffer;
    int maxSz;
    word32 reqId;
} WS_SFTP_RENAME_STATE;


static int SendPacketType(WOLFSSH* ssh, byte type, byte* buf, word32 bufSz);
static int SFTP_ParseAtributes_buffer(WOLFSSH* ssh,  WS_SFTP_FILEATRB* atr,
        byte* buf, word32* idx, word32 maxIdx);
static WS_SFTPNAME* wolfSSH_SFTPNAME_new(void* heap);
static int SFTP_CreateLongName(WS_SFTPNAME* name);


/* A few errors are OK to get. They are a notice rather that a fault.
 * return TRUE if ssh->error is one of the following: */
static INLINE int NoticeError(WOLFSSH* ssh)
{
    return (ssh->error == WS_WANT_READ ||
            ssh->error == WS_WANT_WRITE ||
            ssh->error == WS_CHAN_RXD ||
            ssh->error == WS_REKEYING);
}


static byte* wolfSSH_SFTP_buffer_data(WS_SFTP_BUFFER* buffer)
{
    byte* ret = NULL;
    if (buffer != NULL) {
        ret = buffer->data;
    }
    return ret;
}


/* sets the size of internal buffer, can not set to larger size than internal
 * buffer (the buffer should be recreated in that case)
 * returns a negative value on fail, WS_SUCCESS on success
 */
static int wolfSSH_SFTP_buffer_set_size(WS_SFTP_BUFFER* buffer, word32 sz)
{
    if (buffer == NULL || sz > buffer->sz) {
        WLOG(WS_LOG_SFTP, "Error setting size, buffer null or increase in sz");
        return WS_BAD_ARGUMENT;
    }

    buffer->sz = sz;
    return WS_SUCCESS;
}


/* returns the size of the buffer */
static word32 wolfSSH_SFTP_buffer_size(WS_SFTP_BUFFER* buffer)
{
    word32 ret = 0;
    if (buffer != NULL) {
        ret = buffer->sz;
    }
    return ret;
}


/* sets the current idx into the buffer */
static void wolfSSH_SFTP_buffer_seek(WS_SFTP_BUFFER* buffer,
        word32 start, word32 ofst)
{
    if (buffer != NULL) {
        buffer->idx = start + ofst;
    }
}


/* c32toa function and advance idx */
static void wolfSSH_SFTP_buffer_c32toa(WS_SFTP_BUFFER* buffer,
        word32 value)
{
    if (buffer != NULL) {
        c32toa(value, buffer->data + buffer->idx);
        buffer->idx += UINT32_SZ;
    }
}


/* returns WS_SUCCESS on success */
static int wolfSSH_SFTP_buffer_ato32(WS_SFTP_BUFFER* buffer, word32* out)
{
    if (buffer == NULL || out == NULL ||
            buffer->idx + UINT32_SZ > buffer->sz) {
        return WS_BAD_ARGUMENT;
    }
    ato32(buffer->data + buffer->idx, out);
    buffer->idx += UINT32_SZ;
    return WS_SUCCESS;
}


/* getter function for current buffer idx */
static word32 wolfSSH_SFTP_buffer_idx(WS_SFTP_BUFFER* buffer)
{
    word32 ret = 0;
    if (buffer != NULL) {
        ret = buffer->idx;
    }
    return ret;
}


/* rewinds reading the buffer, resetting it idx value to 0 */
static void wolfSSH_SFTP_buffer_rewind(WS_SFTP_BUFFER* buffer)
{
    if (buffer != NULL)
        buffer->idx = 0;
}


/* try to send the rest of the buffer (buffer.sz - buffer.idx)
 * increments idx with amount sent */
static int wolfSSH_SFTP_buffer_send(WOLFSSH* ssh, WS_SFTP_BUFFER* buffer)
{
    int ret = WS_SUCCESS;
    int err;

    if (buffer == NULL) {
        return WS_BAD_ARGUMENT;
    }

    if (buffer->idx > buffer->sz) {
        return WS_BUFFER_E;
    }

    /* Call wolfSSH worker if rekeying or adjusting window size */
    err = wolfSSH_get_error(ssh);
    if (err == WS_WINDOW_FULL || err == WS_REKEYING) {
        (void)wolfSSH_worker(ssh, NULL);
    }

    if (buffer->idx < buffer->sz) {
        ret = wolfSSH_stream_send(ssh, buffer->data + buffer->idx,
            buffer->sz - buffer->idx);
        if (ret > 0) {
            buffer->idx += ret;
        }
        WLOG(WS_LOG_SFTP, "SFTP buffer sent %d / %d bytes", buffer->idx,
            buffer->sz);
    }

    return ret;
}


/* returns the amount read on success */
static int wolfSSH_SFTP_buffer_read(WOLFSSH* ssh, WS_SFTP_BUFFER* buffer,
        int readSz)
{
    int ret;
    byte peekBuf[1];

    if (buffer == NULL || ssh == NULL) {
        return WS_FATAL_ERROR;
    }

    if (readSz == 0) {
        return 0;
    }

    if (buffer->data == NULL) {
        buffer->idx = 0;
        buffer->sz  = readSz;
        buffer->data = (byte*)WMALLOC(buffer->sz, ssh->ctx->heap,
               DYNTYPE_BUFFER);
        if (buffer->data == NULL) {
            return WS_MEMORY_E;
        }
    }

    do {
        if (!wolfSSH_stream_peek(ssh, peekBuf, 1)) {
            /* poll more data off the wire */
            ret = wolfSSH_worker(ssh, NULL);
        }
        else {
            ret = WS_CHAN_RXD; /* existing data found with peek */
        }

        if (ret == WS_CHAN_RXD) {
            ret = wolfSSH_stream_read(ssh, buffer->data + buffer->idx,
                buffer->sz - buffer->idx);
        }
        if (ret < 0) {
            return WS_FATAL_ERROR;
        }
        buffer->idx += (word32)ret;
        WLOG(WS_LOG_SFTP, "SFTP buffer read %d / %d bytes", buffer->idx,
            buffer->sz);
    } while (buffer->idx < buffer->sz);

    return buffer->sz;
}


static void wolfSSH_SFTP_buffer_free(WOLFSSH* ssh, WS_SFTP_BUFFER* buffer)
{
    if (ssh != NULL && buffer != NULL) {
        buffer->idx = 0;
        buffer->sz  = 0;
        if (buffer->data != NULL) {
            WFREE(buffer->data, ssh->ctx->heap, DYNTYPE_BUFFER);
            buffer->data = NULL;
        }
    }
}


/* return WS_SUCCESS on success, creates a new buffer if one does not already
 * exist */
static int wolfSSH_SFTP_buffer_create(WOLFSSH* ssh, WS_SFTP_BUFFER* buffer,
        word32 sz)
{
    if (ssh == NULL || buffer == NULL) {
        return WS_BAD_ARGUMENT;
    }

    if (buffer->data == NULL ||
            (buffer->data != NULL && buffer->sz != sz)) {
        wolfSSH_SFTP_buffer_free(ssh, buffer);
        buffer->data = (byte*)WMALLOC(sz, ssh->ctx->heap, DYNTYPE_BUFFER);
        if (buffer->data == NULL)
            return WS_MEMORY_E;
        buffer->idx = 0;
        buffer->sz  = sz;
    }
    return WS_SUCCESS;
}


/* Used to clear and free all states. Should be when returning errors or
 * success. Must be called when free'ing the SFTP. For now static since only
 * used in wolfsftp.c
 *
 * Note: Most cases an error will free all states and a success will free
 *       specific state ID.
 */
static void wolfSSH_SFTP_ClearState(WOLFSSH* ssh, enum WS_SFTP_STATE_ID state)
{
    if (ssh) {

        if (state == 0)
            state = (enum WS_SFTP_STATE_ID)~state; /* set all bits hot */

        if (state & STATE_ID_GET) {
            if (ssh->getState) {
                WFREE(ssh->getState, ssh->ctx->heap, DYNTYPE_SFTP_STATE);
                ssh->getState = NULL;
            }
        }

        if (state & STATE_ID_LSTAT) {
            if (ssh->lstatState) {
                wolfSSH_SFTP_buffer_free(ssh, &ssh->lstatState->buffer);
                WFREE(ssh->lstatState, ssh->ctx->heap, DYNTYPE_SFTP_STATE);
                ssh->lstatState = NULL;
            }
        }

        if (state & STATE_ID_OPEN) {
            if (ssh->openState) {
                wolfSSH_SFTP_buffer_free(ssh, &ssh->openState->buffer);
                WFREE(ssh->openState, ssh->ctx->heap, DYNTYPE_SFTP_STATE);
                ssh->openState = NULL;
            }
        }

        if (state & STATE_ID_SEND_READ) {
            if (ssh->sendReadState) {
                wolfSSH_SFTP_buffer_free(ssh, &ssh->sendReadState->buffer);
                WFREE(ssh->sendReadState, ssh->ctx->heap, DYNTYPE_SFTP_STATE);
                ssh->sendReadState = NULL;
            }
        }

        if (state & STATE_ID_CLOSE) {
            if (ssh->closeState) {
                wolfSSH_SFTP_buffer_free(ssh, &ssh->closeState->buffer);
                WFREE(ssh->closeState, ssh->ctx->heap, DYNTYPE_SFTP_STATE);
                ssh->closeState  = NULL;
            }
        }

        if (state & STATE_ID_GET_HANDLE) {
            if (ssh->getHandleState) {
                wolfSSH_SFTP_buffer_free(ssh, &ssh->getHandleState->buffer);
                WFREE(ssh->getHandleState, ssh->ctx->heap, DYNTYPE_SFTP_STATE);
                ssh->getHandleState = NULL;
            }
        }

        if (state & STATE_ID_NAME) {
            if (ssh->nameState) {
                wolfSSH_SFTP_buffer_free(ssh, &ssh->nameState->buffer);
                WFREE(ssh->nameState, ssh->ctx->heap, DYNTYPE_SFTP_STATE);
                ssh->nameState = NULL;
            }
        }

        if (state & STATE_ID_SEND) {
            if (ssh->sendState) {
                wolfSSH_SFTP_buffer_free(ssh, &ssh->sendState->buffer);
                WFREE(ssh->sendState, ssh->ctx->heap, DYNTYPE_SFTP_STATE);
                ssh->sendState = NULL;
            }
        }

        if (state & STATE_ID_LS) {
            if (ssh->lsState) {
                WFREE(ssh->lsState, ssh->ctx->heap, DYNTYPE_SFTP_STATE);
                ssh->lsState = NULL;
            }
        }

        if (state & STATE_ID_READDIR) {
            if (ssh->readDirState) {
                wolfSSH_SFTP_buffer_free(ssh, &ssh->readDirState->buffer);
                WFREE(ssh->readDirState, ssh->ctx->heap, DYNTYPE_SFTP_STATE);
                ssh->readDirState = NULL;
            }
        }

        if (state & STATE_ID_PUT) {
            if (ssh->putState) {
                WFREE(ssh->putState, ssh->ctx->heap, DYNTYPE_SFTP_STATE);
                ssh->putState = NULL;
            }
        }

        if (state & STATE_ID_SEND_WRITE) {
            if (ssh->sendWriteState) {
                wolfSSH_SFTP_buffer_free(ssh, &ssh->sendWriteState->buffer);
                WFREE(ssh->sendWriteState, ssh->ctx->heap, DYNTYPE_SFTP_STATE);
                ssh->sendWriteState = NULL;
            }
        }

        if (state & STATE_ID_RM) {
            if (ssh->rmState != NULL) {
                wolfSSH_SFTP_buffer_free(ssh, &ssh->rmState->buffer);
                WFREE(ssh->rmState, ssh->ctx->heap, DYNTYPE_SFTP_STATE);
                ssh->rmState = NULL;
            }
        }

        if (state & STATE_ID_MKDIR) {
            if (ssh->mkdirState != NULL) {
                wolfSSH_SFTP_buffer_free(ssh, &ssh->mkdirState->buffer);
                WFREE(ssh->mkdirState, ssh->ctx->heap, DYNTYPE_SFTP_STATE);
                ssh->mkdirState = NULL;
            }
        }

        if (state & STATE_ID_RMDIR) {
            if (ssh->rmdirState != NULL) {
                wolfSSH_SFTP_buffer_free(ssh, &ssh->rmdirState->buffer);
                WFREE(ssh->rmdirState, ssh->ctx->heap, DYNTYPE_SFTP_STATE);
                ssh->rmdirState = NULL;
            }
        }

        if (state & STATE_ID_RENAME) {
            if (ssh->renameState != NULL) {
                wolfSSH_SFTP_buffer_free(ssh, &ssh->renameState->buffer);
                WFREE(ssh->renameState, ssh->ctx->heap, DYNTYPE_SFTP_STATE);
                ssh->renameState = NULL;
            }
        }

        if (state & STATE_ID_RECV) {
            if (ssh->recvState != NULL) {
                wolfSSH_SFTP_buffer_free(ssh, &ssh->recvState->buffer);
                WFREE(ssh->recvState, ssh->ctx->heap, DYNTYPE_SFTP_STATE);
                ssh->recvState = NULL;
            }
        }

        if (state & STATE_ID_CHMOD) {
            if (ssh->chmodState) {
                WFREE(ssh->chmodState, ssh->ctx->heap, DYNTYPE_SFTP_STATE);
                ssh->chmodState = NULL;
            }
        }

        if (state & STATE_ID_SETATR) {
            if (ssh->setatrState) {
                wolfSSH_SFTP_buffer_free(ssh, &ssh->setatrState->buffer);
                WFREE(ssh->setatrState, ssh->ctx->heap, DYNTYPE_SFTP_STATE);
                ssh->setatrState = NULL;
            }
        }

        if (state & STATE_ID_RECV_INIT) {
            if (ssh->recvInitState) {
                wolfSSH_SFTP_buffer_free(ssh, &ssh->recvInitState->buffer);
                WFREE(ssh->recvInitState, ssh->ctx->heap, DYNTYPE_SFTP_STATE);
                ssh->recvInitState = NULL;
            }
        }
    }
}


/* Returns 1 if there is pending data to be sent and 0 if not */
int wolfSSH_SFTP_PendingSend(WOLFSSH* ssh)
{
    int isSet = 0;

    if (ssh) {
        if (ssh->recvState != NULL && ssh->recvState->toSend)
            isSet = 1;
    }
    return isSet;
}


/* Gets packet header information
 * request Id, type, and size of type specific data
 * return value is length of type specific data still on the wire to be read
 */
static int SFTP_GetHeader(WOLFSSH* ssh, word32* reqId, byte* type,
        WS_SFTP_BUFFER* buffer)
{
    int    ret;
    word32 len;
    WLOG(WS_LOG_SFTP, "Entering SFTP_GetHeader()");

    if (type == NULL || reqId == NULL || ssh == NULL) {
        WLOG(WS_LOG_SFTP, "NULL argument error");
        return WS_BAD_ARGUMENT;
    }

    ret = wolfSSH_SFTP_buffer_read(ssh, buffer, WOLFSSH_SFTP_HEADER);
    if (ret < 0) {
        return WS_FATAL_ERROR;
    }

    if (ret < WOLFSSH_SFTP_HEADER) {
        WLOG(WS_LOG_SFTP, "Unable to read SFTP header");
        return WS_FATAL_ERROR;
    }

    ato32(buffer->data, &len);
    *type = buffer->data[LENGTH_SZ];
    ato32(buffer->data + UINT32_SZ + MSG_ID_SZ, reqId);

    wolfSSH_SFTP_buffer_free(ssh, buffer);
    WLOG(WS_LOG_SFTP, "Leaving SFTP_GetHeader(), packet length = %d id = %d"
           " type = %d", len - UINT32_SZ - MSG_ID_SZ, *reqId, *type);
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

    WOLFSSH_UNUSED(ssh);

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

    WOLFSSH_UNUSED(ssh);

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

    WOLFSSH_UNUSED(ssh);
    WOLFSSH_UNUSED(bufSz);

    /* get flags */
    c32toa(atr->flags, buf); idx += UINT32_SZ;

    /* check if size attribute present */
    if (atr->flags & WOLFSSH_FILEATRB_SIZE) {
        c32toa(atr->sz[1], buf + idx); idx += UINT32_SZ;
        c32toa(atr->sz[0], buf + idx); idx += UINT32_SZ;
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


static INLINE int SFTP_GetSz(byte* buf, word32* sz,
        word32 lowerBound, word32 upperBound)
{
    int ret = WS_SUCCESS;

    if (buf == NULL || sz == NULL) {
        ret = WS_BAD_ARGUMENT;
    }

    if (ret == WS_SUCCESS) {
        word32 val;

        ato32(buf, &val);
        if (val < lowerBound || val > upperBound)
            ret = WS_BUFFER_E;
        else
            *sz = val;
    }

    return ret;
}


#ifndef NO_WOLFSSH_SERVER

#if !defined(WOLFSSH_USER_FILESYSTEM)
static int SFTP_GetAttributes(void* fs, const char* fileName,
        WS_SFTP_FILEATRB* atr, byte noFollow, void* heap);
static int SFTP_GetAttributes_Handle(WOLFSSH* ssh, byte* handle, int handleSz,
        char* name, WS_SFTP_FILEATRB* atr);
#endif

/* unique from other packets because the request ID is not also sent.
 *
 * returns WS_SUCCESS on success
 */
static int SFTP_ServerRecvInit(WOLFSSH* ssh) {
    enum {
        RECV_INIT_SIZE = LENGTH_SZ + MSG_ID_SZ + UINT32_SZ
    };

    int ret;
    byte id;
    word32 sz = 0;
    word32 version = 0;
    WS_SFTP_RECV_INIT_STATE *state;

    state = ssh->recvInitState;
    if (state == NULL) {
        state = (WS_SFTP_RECV_INIT_STATE*)WMALLOC(
                sizeof(WS_SFTP_RECV_INIT_STATE),
                ssh->ctx->heap, DYNTYPE_SFTP_STATE);
        if (state == NULL) {
            ssh->error = WS_MEMORY_E;
            return WS_FATAL_ERROR;
        }
        WMEMSET(state, 0, sizeof(WS_SFTP_RECV_INIT_STATE));
        ssh->recvInitState = state;
    }

    switch (ssh->sftpState) {
        case SFTP_BEGIN:
            ret = wolfSSH_SFTP_buffer_read(ssh,
                    &state->buffer, RECV_INIT_SIZE);
            if (ret < 0) {
                return WS_FATAL_ERROR;
            }

            if (ret < WOLFSSH_SFTP_HEADER) {
                WLOG(WS_LOG_SFTP, "Unable to read SFTP INIT message");
                return WS_FATAL_ERROR;
            }

            if (SFTP_GetSz(state->buffer.data, &sz, MSG_ID_SZ + UINT32_SZ,
                        WOLFSSH_MAX_SFTP_RECV) != WS_SUCCESS) {
                wolfSSH_SFTP_ClearState(ssh, STATE_ID_ALL);
                return WS_BUFFER_E;
            }

            /* compare versions supported */
            id = state->buffer.data[LENGTH_SZ];
            if (id != WOLFSSH_FTP_INIT) {
                WLOG(WS_LOG_SFTP, "Unexpected SFTP type received");
                wolfSSH_SFTP_ClearState(ssh, STATE_ID_ALL);
                return WS_BUFFER_E;
            }

            ato32(state->buffer.data + LENGTH_SZ + MSG_ID_SZ, &version);
            /* versions greater than WOLFSSH_SFTP_VERSION should fall back to
             * ours versions less than WOLFSSH_SFTP_VERSION we should bail out
             * on or implement a fall back */
            if (version < WOLFSSH_SFTP_VERSION) {
                WLOG(WS_LOG_SFTP,
                        "Unsupported SFTP version, sending version 3");
                wolfSSH_SFTP_ClearState(ssh, STATE_ID_ALL);
                return WS_VERSION_E;
            }

            wolfSSH_SFTP_buffer_free(ssh, &state->buffer);

            state->extSz = sz - MSG_ID_SZ - UINT32_SZ;
            ssh->sftpState = SFTP_EXT;
            FALL_THROUGH;

        case SFTP_EXT:
            /* silently ignore extensions if not supported */
            if (state->extSz > 0) {
                ret = wolfSSH_SFTP_buffer_read(ssh,
                        &state->buffer, (int)state->extSz);
                if (ret < 0) {
                    return WS_FATAL_ERROR;
                }

                if (ret < (int)state->extSz) {
                    WLOG(WS_LOG_SFTP, "Unable to read SFTP INIT extensions");
                    return WS_FATAL_ERROR;
                }

                wolfSSH_SFTP_buffer_free(ssh, &state->buffer);
            }
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
    int ret = WS_FATAL_ERROR;

    if (ssh == NULL) {
        return WS_BAD_ARGUMENT;
    }

    if (ssh->error == WS_WANT_READ || ssh->error == WS_WANT_WRITE)
        ssh->error = WS_SUCCESS;

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
        case SFTP_EXT:
            ret = SFTP_ServerRecvInit(ssh);
            if (ret != WS_SUCCESS) {
                if (ssh->error != WS_WANT_READ && ssh->error != WS_WANT_WRITE)
                    wolfSSH_SFTP_ClearState(ssh, STATE_ID_ALL);
                return ret;
            }
            ssh->sftpState = SFTP_RECV;
            FALL_THROUGH;

        case SFTP_RECV:
            ret = SFTP_ServerSendInit(ssh);
            if (ret != WS_SUCCESS) {
                return ret;
            }
            ssh->sftpState = SFTP_DONE;
            WLOG(WS_LOG_SFTP, "SFTP connection established");
            wolfSSH_SFTP_ClearState(ssh, STATE_ID_RECV_INIT);
            ret = WS_SFTP_COMPLETE;
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
    WLOG(WS_LOG_SFTP, "Loading up send buffer");

    /* free up existing data if needed */
    if (buf != state->buffer.data && state->buffer.data != NULL) {
        WFREE(state->buffer.data, ssh->ctx->heap, DYNTYPE_BUFFER);
        state->buffer.data = NULL;
    }

    /* take over control of buffer */
    state->buffer.data = buf;
    state->buffer.sz   = sz;
    state->toSend = 1;
}


/* Getter function for data pointer */
static byte* wolfSSH_SFTP_RecvGetData(WOLFSSH* ssh)
{
    if (ssh && ssh->recvState)
        return ssh->recvState->buffer.data;
    return NULL;
}


/* returns WS_SUCCESS on success */
static int wolfSSH_SFTP_RecvRealPath(WOLFSSH* ssh, int reqId, byte* data,
        int maxSz)
{
    WS_SFTP_FILEATRB atr;
    char  r[WOLFSSH_MAX_FILENAME];
    char  s[WOLFSSH_MAX_FILENAME];
    word32 rSz, sSz;
    word32 lidx = 0;
    int    ret = 0;
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
    if (rSz >= WOLFSSH_MAX_FILENAME || (int)(rSz + UINT32_SZ) > maxSz) {
        return WS_BUFFER_E;
    }
    lidx += UINT32_SZ;
    WMEMCPY(r, data + lidx, rSz);
    r[rSz] = '\0';
    WLOG(WS_LOG_SFTP, "Real Path Request = %s", r);

    /* If the default path isn't set, try to get it. */
    if (ssh->sftpDefaultPath == NULL) {
        char wd[WOLFSSH_MAX_FILENAME];

        WMEMSET(wd, 0, WOLFSSH_MAX_FILENAME);
        ret = WS_SUCCESS;

        #ifdef WOLFSSH_ZEPHYR
        WSTRNCPY(wd, CONFIG_WOLFSSH_SFTP_DEFAULT_DIR, WOLFSSH_MAX_FILENAME);
        #elif !defined(USE_WINDOWS_API)
        if (WGETCWD(ssh->fs, wd, sizeof(wd)-1) == NULL) {
            ret = WS_INVALID_PATH_E;
        }
        #else
        if (GetCurrentDirectoryA(sizeof(wd)-1, wd) == 0) {
            ret = WS_INVALID_PATH_E;
        }
        #endif

        if (ret == WS_SUCCESS) {
            wd[sizeof(wd) - 1] = 0;
            ret = wolfSSH_RealPath(NULL, wd, s, sizeof s);
        }
        if (ret == WS_SUCCESS) {
            ret = wolfSSH_SFTP_SetDefaultPath(ssh, s);
        }
    }

    /* If the default path still isn't set, send error to peer. */
    if (ssh->sftpDefaultPath == NULL) {
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
        /* take over control of buffer */
        wolfSSH_SFTP_RecvSetSend(ssh, out, outSz);
        return ret;
    }

    ret = wolfSSH_RealPath(ssh->sftpDefaultPath, r, s, sizeof s);
    if (ret != WS_SUCCESS) {
        return ret;
    }
    sSz = (word32)WSTRLEN(s);

    WLOG(WS_LOG_SFTP, "Real Path Directory = %s", s);

    /* send response */
    outSz = WOLFSSH_SFTP_HEADER + (UINT32_SZ * 3) + (sSz * 2);
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
    c32toa(sSz, out + lidx); lidx += UINT32_SZ;
    WMEMCPY(out + lidx, s, sSz); lidx += sSz;

    /* set long name size and string */
    c32toa(sSz, out + lidx); lidx += UINT32_SZ;
    WMEMCPY(out + lidx, s, sSz); lidx += sSz;

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

    WLOG(WS_LOG_SFTP, "Entering wolfSSH_SFTP_read()");

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
            ret = SFTP_GetHeader(ssh, (word32*)&state->reqId,
                    &state->type, &state->buffer);
            if (ret <= 0) {
                return WS_FATAL_ERROR;
            }
            if (wolfSSH_SFTP_buffer_create(ssh, &state->buffer, ret) !=
                    WS_SUCCESS) {
                return WS_MEMORY_E;
            }
            ssh->reqId  = state->reqId;

            state->state = STATE_RECV_DO;
            FALL_THROUGH;

        case STATE_RECV_DO:
            ret = wolfSSH_SFTP_buffer_read(ssh, &state->buffer,
                    state->buffer.sz);
            if (ret < 0) {
                if (!NoticeError(ssh)) {
                    wolfSSH_SFTP_ClearState(ssh, STATE_ID_RECV);
                }
                return ret;
            }

            switch (state->type) {
                case WOLFSSH_FTP_REALPATH:
                    ret = wolfSSH_SFTP_RecvRealPath(ssh, state->reqId,
                            wolfSSH_SFTP_buffer_data(&state->buffer),
                            wolfSSH_SFTP_buffer_size(&state->buffer));
                    break;

                case WOLFSSH_FTP_RMDIR:
                    ret = wolfSSH_SFTP_RecvRMDIR(ssh, state->reqId,
                            wolfSSH_SFTP_buffer_data(&state->buffer),
                            wolfSSH_SFTP_buffer_size(&state->buffer));
                    break;

                case WOLFSSH_FTP_MKDIR:
                    ret = wolfSSH_SFTP_RecvMKDIR(ssh, state->reqId,
                            wolfSSH_SFTP_buffer_data(&state->buffer),
                            wolfSSH_SFTP_buffer_size(&state->buffer));
                    break;

                case WOLFSSH_FTP_STAT:
                    ret = wolfSSH_SFTP_RecvSTAT(ssh, state->reqId,
                            wolfSSH_SFTP_buffer_data(&state->buffer),
                            wolfSSH_SFTP_buffer_size(&state->buffer));
                    break;

                case WOLFSSH_FTP_LSTAT:
                    ret = wolfSSH_SFTP_RecvLSTAT(ssh, state->reqId,
                            wolfSSH_SFTP_buffer_data(&state->buffer),
                            wolfSSH_SFTP_buffer_size(&state->buffer));
                    break;

            #ifndef USE_WINDOWS_API
                case WOLFSSH_FTP_FSTAT:
                    ret = wolfSSH_SFTP_RecvFSTAT(ssh, state->reqId,
                            wolfSSH_SFTP_buffer_data(&state->buffer),
                            wolfSSH_SFTP_buffer_size(&state->buffer));
                    break;
            #endif

                case WOLFSSH_FTP_OPEN:
                    ret = wolfSSH_SFTP_RecvOpen(ssh, state->reqId,
                            wolfSSH_SFTP_buffer_data(&state->buffer),
                            wolfSSH_SFTP_buffer_size(&state->buffer));
                    break;

                case WOLFSSH_FTP_READ:
                    ret = wolfSSH_SFTP_RecvRead(ssh, state->reqId,
                            wolfSSH_SFTP_buffer_data(&state->buffer),
                            wolfSSH_SFTP_buffer_size(&state->buffer));
                    break;

                case WOLFSSH_FTP_WRITE:
                    ret = wolfSSH_SFTP_RecvWrite(ssh, state->reqId,
                            wolfSSH_SFTP_buffer_data(&state->buffer),
                            wolfSSH_SFTP_buffer_size(&state->buffer));
                    break;

                case WOLFSSH_FTP_CLOSE:
                    ret = wolfSSH_SFTP_RecvClose(ssh, state->reqId,
                            wolfSSH_SFTP_buffer_data(&state->buffer),
                            wolfSSH_SFTP_buffer_size(&state->buffer));
                    break;

                case WOLFSSH_FTP_REMOVE:
                    ret = wolfSSH_SFTP_RecvRemove(ssh, state->reqId,
                            wolfSSH_SFTP_buffer_data(&state->buffer),
                            wolfSSH_SFTP_buffer_size(&state->buffer));
                    break;

                case WOLFSSH_FTP_RENAME:
                    ret = wolfSSH_SFTP_RecvRename(ssh, state->reqId,
                            wolfSSH_SFTP_buffer_data(&state->buffer),
                            wolfSSH_SFTP_buffer_size(&state->buffer));
                    break;
            #if !defined(_WIN32_WCE) && !defined(WOLFSSH_ZEPHYR) && \
                !defined(WOLFSSH_FATFS)
                case WOLFSSH_FTP_SETSTAT:
                    ret = wolfSSH_SFTP_RecvSetSTAT(ssh, state->reqId,
                            wolfSSH_SFTP_buffer_data(&state->buffer),
                            wolfSSH_SFTP_buffer_size(&state->buffer));
                    break;
                case WOLFSSH_FTP_FSETSTAT:
                    ret = wolfSSH_SFTP_RecvFSetSTAT(ssh, state->reqId,
                            wolfSSH_SFTP_buffer_data(&state->buffer),
                            wolfSSH_SFTP_buffer_size(&state->buffer));
                    break;
            #endif

            #ifndef NO_WOLFSSH_DIR
                case WOLFSSH_FTP_OPENDIR:
                    ret = wolfSSH_SFTP_RecvOpenDir(ssh, state->reqId,
                            wolfSSH_SFTP_buffer_data(&state->buffer),
                            wolfSSH_SFTP_buffer_size(&state->buffer));
                    break;

                case WOLFSSH_FTP_READDIR:
                    ret = wolfSSH_SFTP_RecvReadDir(ssh, state->reqId,
                            wolfSSH_SFTP_buffer_data(&state->buffer),
                            wolfSSH_SFTP_buffer_size(&state->buffer));
                    break;
            #endif

                default:
                    WLOG(WS_LOG_SFTP, "Unknown packet type [%d] received",
                            state->type);
                    if (wolfSSH_SFTP_CreateStatus(ssh, WOLFSSH_FTP_FAILURE,
                                state->reqId,
                                "Unknown/Unsupported packet type",
                                "English", NULL, (word32*)&maxSz)
                            != WS_SIZE_ONLY) {
                        wolfSSH_SFTP_ClearState(ssh, STATE_ID_RECV);
                        return WS_FATAL_ERROR;
                    }


                    if (maxSz > (int)wolfSSH_SFTP_buffer_size(&state->buffer)) {
                        if (wolfSSH_SFTP_buffer_create(ssh, &state->buffer,
                                    maxSz) != WS_SUCCESS) {
                            wolfSSH_SFTP_ClearState(ssh, STATE_ID_RECV);
                            return WS_FATAL_ERROR;
                        }
                    }

                    maxSz = (int)wolfSSH_SFTP_buffer_size(&state->buffer);
                    ret = wolfSSH_SFTP_CreateStatus(ssh, WOLFSSH_FTP_FAILURE,
                            state->reqId,
                            "Unknown/Unsupported packet type", "English",
                            wolfSSH_SFTP_buffer_data(&state->buffer),
                            (word32*)(&maxSz));

                    if (ret == WS_SUCCESS) {
                        ret = wolfSSH_SFTP_buffer_set_size(&state->buffer,
                                (word32)maxSz);
                    }

                    if (ret == WS_SUCCESS) {
                        /* set send out buffer, state data is taken by ssh */
                        wolfSSH_SFTP_RecvSetSend(ssh,
                            wolfSSH_SFTP_buffer_data(&state->buffer),
                            wolfSSH_SFTP_buffer_size(&state->buffer));
                    }
            }

            /* break out if encountering an error with nothing stored to send */
            if (ret < 0 && !state->toSend) {
                if (ssh->error != WS_WANT_READ && ssh->error != WS_WANT_WRITE)
                    wolfSSH_SFTP_ClearState(ssh, STATE_ID_RECV);
                return ret;
            }
            state->buffer.idx   = 0;
            state->state = STATE_RECV_SEND;
            FALL_THROUGH;

        case STATE_RECV_SEND:
            if (state->toSend) {
                ret = wolfSSH_SFTP_buffer_send(ssh, &state->buffer);
                if (ret < 0) {
                    if (ret == WS_REKEYING || ssh->error == WS_REKEYING) {
                        return WS_REKEYING;
                    }
                    if (ssh->error != WS_WANT_READ &&
                            ssh->error != WS_WANT_WRITE &&
                            ssh->error != WS_WINDOW_FULL) {
                        wolfSSH_SFTP_ClearState(ssh, STATE_ID_RECV);
                    }
                    return WS_FATAL_ERROR;
                }
                if (wolfSSH_SFTP_buffer_idx(&state->buffer)
                        < wolfSSH_SFTP_buffer_size(&state->buffer)) {
                    ssh->error = WS_WANT_WRITE;
                    return WS_FATAL_ERROR;
                }
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


/*
 * This is a wrapper around the function wolfSSH_RealPath. Since it modifies
 * the source path value, copy the path from the data stream into a local
 * array and use that as the source.
 *
 * @param defaultPath pointer to the defaultPath
 * @param data        input data stream at the location of the path name
 * @param sz          size of the path name in bytes
 * @param s           destination buffer for the Real Path
 * @param sSz         size of s in bytes
 * @return            0 for success or negative error code
 */
static int GetAndCleanPath(const char* defaultPath,
        const byte* data, word32 sz, char* s, word32 sSz)
{
    char r[WOLFSSH_MAX_FILENAME];

    if (sz >= sizeof r)
        return WS_BUFFER_E;
    WMEMCPY(r, data, sz);
    r[sz] = '\0';

    return wolfSSH_RealPath(defaultPath, r, s, sSz);
}


/* Handles packet to remove a directory
 *
 * returns WS_SUCCESS on success
 */
int wolfSSH_SFTP_RecvRMDIR(WOLFSSH* ssh, int reqId, byte* data, word32 maxSz)
{
    word32 sz;
    int    ret = 0;
    char   dir[WOLFSSH_MAX_FILENAME];
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

    if (maxSz < UINT32_SZ) {
        /* not enough for an ato32 call */
        return WS_BUFFER_E;
    }

    ato32(data + idx, &sz); idx += UINT32_SZ;
    if (sz > maxSz - idx) {
        return WS_BUFFER_E;
    }

    ret = GetAndCleanPath(ssh->sftpDefaultPath,
            data + idx, sz, dir, sizeof(dir));

    if (ret == 0) {
    #ifndef USE_WINDOWS_API
        ret = WRMDIR(ssh->fs, dir);
    #else /* USE_WINDOWS_API */
        ret = WS_RemoveDirectoryA(dir, ssh->ctx->heap) == 0;
    #endif /* USE_WINDOWS_API */
    }

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
        WFREE(out, ssh->ctx->heap, DYNTYPE_BUFFER);
        return WS_FATAL_ERROR;
    }

    /* set send out buffer, "out" is taken by ssh  */
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
    char   dir[WOLFSSH_MAX_FILENAME];
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

    if (maxSz < UINT32_SZ) {
        /* not enough for an ato32 call */
        return WS_BUFFER_E;
    }

    ato32(data + idx, &sz); idx += UINT32_SZ;
    if (sz > maxSz - idx) {
        return WS_BUFFER_E;
    }

    ret = GetAndCleanPath(ssh->sftpDefaultPath,
            data + idx, sz, dir, sizeof(dir));
    if (ret != WS_SUCCESS) {
        return ret;
    }

    idx += sz;
    if (idx + UINT32_SZ > maxSz) {
        return WS_BUFFER_E;
    }

    ato32(data + idx, &sz); idx += UINT32_SZ;
    if (sz > maxSz - idx) {
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

#ifndef USE_WINDOWS_API
    ret = WMKDIR(ssh->fs, dir, mode);
#else /* USE_WINDOWS_API */
    ret = WS_CreateDirectoryA(dir, ssh->ctx->heap) == 0;
#endif /* USE_WINDOWS_API */

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

    /* set send out buffer, "out" is taken by ssh  */
    wolfSSH_SFTP_RecvSetSend(ssh, out, outSz);
    return ret;
}


#ifdef WOLFSSH_FATFS
#ifndef WOLFSSH_FATFS_MAX_FILES
    #define WOLFSSH_FATFS_MAX_FILES 32
#endif


struct fd_entry {
    FIL f;
    int used;
};

static struct fd_entry fd_pool[WOLFSSH_FATFS_MAX_FILES] = { };

int ff_open(const char *fname, int flag, int perm)
{
    int i;
    BYTE mode;
    WOLFSSH_UNUSED(perm);
    PRINTF("\r\nfatFS open: %s", fname);

    if (flag & WOLFSSH_O_RDONLY) {
        mode = FA_READ;

    } else if (flag & WOLFSSH_O_RDWR) {
        if ((flag & WOLFSSH_O_CREAT) &&
                (flag & WOLFSSH_O_TRUNC)) {
            mode = FA_READ | FA_WRITE | FA_CREATE_ALWAYS;

        } else if ((flag & WOLFSSH_O_CREAT) &&
                (flag & WOLFSSH_O_APPEND)) {
            mode = FA_READ | FA_WRITE | FA_CREATE_NEW | FA_OPEN_APPEND;

        } else {
            mode = AM_ARC;
        }
    } else if (flag & WOLFSSH_O_WRONLY) {
        if ((flag & WOLFSSH_O_CREAT) &&
                (flag & WOLFSSH_O_TRUNC)) {
            mode = FA_READ | FA_CREATE_ALWAYS | FA_WRITE;
        } else if ((flag & WOLFSSH_O_CREAT) &&
                (flag & WOLFSSH_O_APPEND)) {
            mode = FA_READ | FA_WRITE | FA_CREATE_NEW | FA_OPEN_APPEND;
        }
    } else {
        return -1;
    }


    for (i = 0; i < WOLFSSH_FATFS_MAX_FILES; i++) {
        if (fd_pool[i].used == 0) {
            if (f_open(&(fd_pool[i].f), fname, mode) == FR_OK) {
                fd_pool[i].used = 1;
                PRINTF("\r\nfatFS open success: %d", i);
                return i;

            } else {
                return -1;
            }
        }
    }
    return -1;
}

int ff_close(int fd)
{
    f_close(&fd_pool[fd].f);
    if (fd_pool[fd].used)
        fd_pool[fd].used = 0;
    return 0;
}

int ff_pwrite(int fd, const byte *buffer, int sz)
{
    FIL *f = &fd_pool[fd].f;
    FRESULT ret;
    unsigned int rsz;
    if (fd_pool[fd].used == 0)
        return -1;
    ret = f_write(f, buffer, sz, &rsz);
    if (ret != FR_OK)
        return -1;
    return rsz;
}
int ff_pread(int fd, byte *buffer, int sz)
{
    FIL *f = &fd_pool[fd].f;
    FRESULT ret;
    unsigned int rsz;
    if (fd_pool[fd].used == 0)
        return -1;
    ret = f_read(f, buffer, sz, &rsz);
    if (ret != FR_OK)
        return -1;
    return rsz;
}


#endif /* WOLFSSH_FATFS */

/* Handles packet to open a file
 *
 * returns WS_SUCCESS on success
 */
int wolfSSH_SFTP_RecvOpen(WOLFSSH* ssh, int reqId, byte* data, word32 maxSz)
#ifndef USE_WINDOWS_API
{
    WS_SFTP_FILEATRB atr;
    WFD    fd;
    word32 sz, dirSz;
    char   dir[WOLFSSH_MAX_FILENAME];
    word32 reason;
    word32 idx = 0;
    int m = 0;
    int ret = WS_SUCCESS;

    word32 outSz = sizeof(WFD) + UINT32_SZ + WOLFSSH_SFTP_HEADER;
    byte*  out = NULL;

    char* res   = NULL;
    char  ier[] = "Internal Failure";
    char  oer[] = "Open File Error";
    char  naf[] = "Not A File";

    if (ssh == NULL) {
        return WS_BAD_ARGUMENT;
    }

    WLOG(WS_LOG_SFTP, "Receiving WOLFSSH_FTP_OPEN");

    #ifdef MICROCHIP_MPLAB_HARMONY
        fd = WBADFILE;
    #else
        fd = -1;
    #endif

    if (sizeof(WFD) > WOLFSSH_MAX_HANDLE) {
        WLOG(WS_LOG_SFTP, "Handle size is too large");
        return WS_FATAL_ERROR;
    }

    if (maxSz < UINT32_SZ) {
        /* not enough for an ato32 call */
        return WS_BUFFER_E;
    }

    ato32(data + idx, &sz); idx += UINT32_SZ;
    if (sz > maxSz - idx) {
        return WS_BUFFER_E;
    }

    dirSz = sizeof(dir);
    if (wolfSSH_GetPath(ssh->sftpDefaultPath, data + idx, sz, dir, &dirSz)
            != WS_SUCCESS) {
        WLOG(WS_LOG_SFTP, "Creating path for file to open failed");
        return WS_FATAL_ERROR;
    }
    idx += sz;

    /* get reason for opening file */
    ato32(data + idx, &reason); idx += UINT32_SZ;

    /* @TODO handle attributes */
    SFTP_ParseAtributes_buffer(ssh, &atr, data, &idx, maxSz);
    if ((reason & WOLFSSH_FXF_READ) && (reason & WOLFSSH_FXF_WRITE)) {
        WLOG(WS_LOG_SFTP, "Opening file with WOLFSSH_O_RDWR");
        m |= WOLFSSH_O_RDWR;
    }
    else {
        if (reason & WOLFSSH_FXF_READ) {
            WLOG(WS_LOG_SFTP, "Opening file with WOLFSSH_O_RDONLY");
            m |= WOLFSSH_O_RDONLY;
        }
        if (reason & WOLFSSH_FXF_WRITE) {
            WLOG(WS_LOG_SFTP, "Opening file with WOLFSSH_O_WRONLY");
            m |= WOLFSSH_O_WRONLY;
        }
    }

    if (reason & WOLFSSH_FXF_APPEND) {
        WLOG(WS_LOG_SFTP, "Opening file with WOLFSSH_O_APPEND");
        m |= WOLFSSH_O_APPEND;
    }
    if (reason & WOLFSSH_FXF_CREAT) {
        WLOG(WS_LOG_SFTP, "Opening file with WOLFSSH_O_CREAT");
        m |= WOLFSSH_O_CREAT;
    }
    if (reason & WOLFSSH_FXF_TRUNC) {
        WLOG(WS_LOG_SFTP, "Opening file with WOLFSSH_O_TRUNC");
        m |= WOLFSSH_O_TRUNC;
    }
    if (reason & WOLFSSH_FXF_EXCL) {
        WLOG(WS_LOG_SFTP, "Opening file with WOLFSSH_O_EXCL");
        m |= WOLFSSH_O_EXCL;
    }

    {
        WS_SFTP_FILEATRB fileAtr;
        WMEMSET(&fileAtr, 0, sizeof(fileAtr));
        if (SFTP_GetAttributes(ssh->fs,
                        dir, &fileAtr, 0, ssh->ctx->heap) == WS_SUCCESS) {
            if ((fileAtr.per & FILEATRB_PER_MASK_TYPE)
                        != FILEATRB_PER_FILE) {
                ssh->error = WS_SFTP_NOT_FILE_E;

                res = naf;
                if (wolfSSH_SFTP_CreateStatus(ssh, WOLFSSH_FTP_FAILURE, reqId,
                            res, "English", NULL, &outSz) != WS_SIZE_ONLY) {
                    return WS_FATAL_ERROR;
                }
                ret = WS_FATAL_ERROR;
            }
        }
    }

    if (ret == WS_SUCCESS) {
        /* if file permissions not set then use default */
        if (!(atr.flags & WOLFSSH_FILEATRB_PERM)) {
            atr.per = 0644;
        }

    #ifdef MICROCHIP_MPLAB_HARMONY
        {
            WFILE* f = &fd;
            if (WFOPEN(ssh->fs, &f, dir, m) != WS_SUCCESS) {
                fd = -1;
            }
        }
    #else
        fd = WOPEN(ssh->fs, dir, m, atr.per);
    #endif
        if (fd < 0) {
            WLOG(WS_LOG_SFTP, "Error opening file %s", dir);
            res = oer;
            if (wolfSSH_SFTP_CreateStatus(ssh, WOLFSSH_FTP_FAILURE, reqId, res,
                    "English", NULL, &outSz) != WS_SIZE_ONLY) {
                return WS_FATAL_ERROR;
            }
            ret = WS_BAD_FILE_E;
        }
    }

#ifdef WOLFSSH_STOREHANDLE
    if (ret == WS_SUCCESS) {
        if ((ret = SFTP_AddHandleNode(ssh, (byte*)&fd, sizeof(WFD), dir))
                != WS_SUCCESS) {
            WLOG(WS_LOG_SFTP, "Unable to store handle");
            res = ier;
            if (wolfSSH_SFTP_CreateStatus(ssh, WOLFSSH_FTP_FAILURE, reqId, res,
                    "English", NULL, &outSz) != WS_SIZE_ONLY) {
                WCLOSE(ssh->fs, fd);
                return WS_FATAL_ERROR;
            }
            ret = WS_FATAL_ERROR;
        }
    }
#endif

    if (ret == WS_SUCCESS) {
        /* create packet */
        out = (byte*)WMALLOC(outSz, ssh->ctx->heap, DYNTYPE_BUFFER);
        if (out == NULL) {
            WCLOSE(ssh->fs, fd);
            return WS_MEMORY_E;
        }
    }
    if (ret == WS_SUCCESS) {
        if (SFTP_CreatePacket(ssh, WOLFSSH_FTP_HANDLE, out, outSz,
            (byte*)&fd, sizeof(WFD)) != WS_SUCCESS) {
            WCLOSE(ssh->fs, fd);
            return WS_FATAL_ERROR;
        }
    }
    else {
        if (wolfSSH_SFTP_CreateStatus(ssh, WOLFSSH_FTP_FAILURE, reqId, res,
                "English", out, &outSz) != WS_SUCCESS) {
            WFREE(out, ssh->ctx->heap, DYNTYPE_BUFFER);
            if (fd >= 0) {
                WCLOSE(ssh->fs, fd);
            }
            return WS_FATAL_ERROR;
        }
    }

    /* set send out buffer, "out" is taken by ssh  */
    wolfSSH_SFTP_RecvSetSend(ssh, out, outSz);

    WOLFSSH_UNUSED(ier);
    return ret;
}
#else /* USE_WINDOWS_API */
{
/*    WS_SFTP_FILEATRB atr;*/
    HANDLE fileHandle;
    word32 sz, dirSz;
    char   dir[WOLFSSH_MAX_FILENAME];
    word32 reason;
    word32 idx = 0;
    DWORD desiredAccess = 0;
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

    if (maxSz < UINT32_SZ) {
        /* not enough for an ato32 call */
        return WS_BUFFER_E;
    }

    ato32(data + idx, &sz); idx += UINT32_SZ;
    if (sz > maxSz - idx) {
        return WS_BUFFER_E;
    }

    dirSz = sizeof(dir);
    if (wolfSSH_GetPath(ssh->sftpDefaultPath, data + idx, sz, dir, &dirSz)
            != WS_SUCCESS) {
        WLOG(WS_LOG_SFTP, "Creating path for file to open failed");
        return WS_FATAL_ERROR;
    }
    idx += sz;

    /* get reason for opening file */
    ato32(data + idx, &reason); idx += UINT32_SZ;

#if 0
    /* @TODO handle attributes */
    SFTP_ParseAtributes_buffer(ssh, &atr, data, &idx, maxSz);
#endif

    if (reason & WOLFSSH_FXF_READ) {
        desiredAccess |= GENERIC_READ;
        creationDisp |= OPEN_EXISTING;
    }
    if (reason & WOLFSSH_FXF_WRITE) {
        desiredAccess |= GENERIC_WRITE;
        if (reason & WOLFSSH_FXF_CREAT)
            creationDisp |= CREATE_ALWAYS;
    #if 0
        if (reason & WOLFSSH_FXF_TRUNC)
            creationDisp |= TRUNCATE_EXISTING;
        if (reason & WOLFSSH_FXF_EXCL)
            creationDisp |= CREATE_NEW;
        if (reason & WOLFSSH_FXF_APPEND)
            desiredAccess |= FILE_APPEND_DATA;
    #endif
    }

#if 0
    /* if file permissions not set then use default */
    if (!(atr.flags & WOLFSSH_FILEATRB_PERM)) {
        atr.per = 0644;
    }
#endif

    fileHandle = WS_CreateFileA(dir, desiredAccess,
            (FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE),
            creationDisp, FILE_ATTRIBUTE_NORMAL, ssh->ctx->heap);
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

    /* set send out buffer, "out" is taken by ssh  */
    wolfSSH_SFTP_RecvSetSend(ssh, out, outSz);

    WOLFSSH_UNUSED(ier);
    return ret;
}
#endif /* USE_WINDOWS_API */


#ifndef NO_WOLFSSH_DIR

/* hold pointers to directory handles */
struct WS_DIR_LIST {
    WDIR dir;
    char* dirName; /* base name of directory */
    byte isEof;    /* flag for if read everything */
    word32 id[2];  /* handle ID */
    struct WS_DIR_LIST* next;
};


/* Handles packet to open a directory
 *
 * returns WS_SUCCESS on success
 */
int wolfSSH_SFTP_RecvOpenDir(WOLFSSH* ssh, int reqId, byte* data, word32 maxSz)
#ifndef USE_WINDOWS_API
{
    WDIR  ctx;
    word32 sz;
    char   dir[WOLFSSH_MAX_FILENAME];
    word32 idx = 0;
    int   ret = WS_SUCCESS;

    word32 outSz = sizeof(word32)*2 + WOLFSSH_SFTP_HEADER + UINT32_SZ;
    byte*  out = NULL;
    word32 id[2];
    byte idFlat[sizeof(word32) * 2];

    if (ssh == NULL) {
        return WS_BAD_ARGUMENT;
    }

    WLOG(WS_LOG_SFTP, "Receiving WOLFSSH_FTP_OPENDIR");

    if (sizeof(WFD) > WOLFSSH_MAX_HANDLE) {
        WLOG(WS_LOG_SFTP, "Handle size is too large");
        return WS_FATAL_ERROR;
    }

    if (maxSz < UINT32_SZ) {
        /* not enough for an ato32 call */
        return WS_BUFFER_E;
    }

    /* get directory name */
    ato32(data + idx, &sz); idx += UINT32_SZ;
    if (sz > maxSz - idx) {
        return WS_BUFFER_E;
    }

    if (GetAndCleanPath(ssh->sftpDefaultPath,
                data + idx, sz, dir, sizeof(dir)) < 0) {
        return WS_BUFFER_E;
    }

    if (WOPENDIR(ssh->fs, ssh->ctx->heap, &ctx, dir) != 0) {
        WLOG(WS_LOG_SFTP, "Error with opening directory: %s", dir);
        if (wolfSSH_SFTP_CreateStatus(ssh, WOLFSSH_FTP_NOFILE, reqId,
                "Unable To Open Directory", "English", NULL, &outSz)
                != WS_SIZE_ONLY) {
                return WS_FATAL_ERROR;
        }
        ret = WS_BAD_FILE_E;
    }

    WOLFSSH_UNUSED(reqId);

    if (ret == WS_SUCCESS) {
        WS_DIR_LIST* cur = NULL;
        char* dirName = NULL;
        word32 dirNameSz;

        cur = (WS_DIR_LIST*)WMALLOC(sizeof(WS_DIR_LIST),
                ssh->ctx->heap, DYNTYPE_SFTP);
        if (cur == NULL) {
            WCLOSEDIR(ssh->fs, &ctx);
            return WS_MEMORY_E;
        }
        dirNameSz = (word32)WSTRLEN(dir) + 1;
        dirName = (char*)WMALLOC(dirNameSz,
                ssh->ctx->heap, DYNTYPE_PATH);
        if (dirName == NULL) {
            WCLOSEDIR(ssh->fs, &ctx);
            WFREE(cur, ssh->ctx->heap, DYNTYPE_SFTP);
            return WS_MEMORY_E;
        }
        WMEMCPY(dirName, dir, dirNameSz);
#ifdef WOLFSSL_NUCLEUS
        WMEMCPY(&cur->dir, &ctx, sizeof(WDIR));
#else
        cur->dir  = ctx;
#endif
        cur->id[0] = id[0] = ssh->dirIdCount[0];
        cur->id[1] = id[1] = ssh->dirIdCount[1];
        c32toa(id[0], idFlat);
        c32toa(id[1], idFlat + UINT32_SZ);
        AddAssign64(ssh->dirIdCount, 1);
        cur->isEof = 0;
        cur->next  = ssh->dirList;
        ssh->dirList          = cur;
        ssh->dirList->dirName = dirName; /* take over ownership of buffer */
    }

    out = (byte*)WMALLOC(outSz, ssh->ctx->heap, DYNTYPE_BUFFER);
    if (out == NULL) {
        return WS_MEMORY_E;
    }

    if (ret == WS_SUCCESS) {
        SFTP_CreatePacket(ssh, WOLFSSH_FTP_HANDLE, out, outSz,
                idFlat, sizeof(idFlat));
    }
    else {
        if (wolfSSH_SFTP_CreateStatus(ssh, WOLFSSH_FTP_NOFILE, reqId,
                "Unable To Open Directory", "English", out, &outSz)
                != WS_SUCCESS) {
            WFREE(out, ssh->ctx->heap, DYNTYPE_BUFFER);
            return WS_FATAL_ERROR;
        }
    }

    /* set send out buffer, "out" is taken by ssh  */
    wolfSSH_SFTP_RecvSetSend(ssh, out, outSz);

    return ret;
}
#else /* USE_WINDOWS_API */
{
    word32 sz;
    char* dirName;
    word32 idx = 0;
    HANDLE findHandle;
    char realName[MAX_PATH];
    int isDir = 0;
    int ret = WS_SUCCESS;

    word32 outSz = sizeof(word32) * 2 + WOLFSSH_SFTP_HEADER + UINT32_SZ;
    byte*  out = NULL;
    word32 id[2];
    byte idFlat[sizeof(word32) * 2];
    char name[MAX_PATH];

    if (ssh == NULL) {
        return WS_BAD_ARGUMENT;
    }

    WLOG(WS_LOG_SFTP, "Receiving WOLFSSH_FTP_OPENDIR");

    if (sizeof(HANDLE) > WOLFSSH_MAX_HANDLE) {
        WLOG(WS_LOG_SFTP, "Handle size is too large");
        return WS_FATAL_ERROR;
    }

    if (maxSz < UINT32_SZ) {
        /* not enough for an ato32 call */
        return WS_BUFFER_E;
    }

    /* get directory name */
    ato32(data + idx, &sz);
    idx += UINT32_SZ;
    if (sz > maxSz - idx) {
        return WS_BUFFER_E;
    }

    /* plus one to make sure is null terminated */
    dirName = (char*)WMALLOC(sz + 1, ssh->ctx->heap, DYNTYPE_BUFFER);
    if (dirName == NULL) {
        return WS_MEMORY_E;
    }
    WMEMCPY(dirName, data + idx, sz);
    dirName[sz] = '\0';

    /* Special case in Windows for the root directory above the drives. */
    if (dirName[0] == '/' && dirName[1] == 0) {
        DWORD drives, mask;
        UINT driveType;
        char driveName[] = " :\\";
        int i;

        WMEMSET(ssh->driveList, 0, sizeof ssh->driveList);
        ssh->driveListCount = 0;

        drives = GetLogicalDrives();
        for (i = 0, mask = 1; i < (sizeof ssh->driveList); i++, mask <<= 1) {
            if (drives & mask) {
                driveName[0] = 'A' + i;
                driveType = GetDriveTypeA(driveName);
                if (driveType == DRIVE_FIXED || driveType == DRIVE_REMOTE) {
                    ssh->driveList[ssh->driveListCount++] = driveName[0];
                }
            }
        }
        ssh->driveIdx = 0;
    }
    else {
        if (sz > MAX_PATH - 2) {
            WLOG(WS_LOG_SFTP, "Path name is too long.");
            return WS_FATAL_ERROR;
        }
        WSTRNCPY(name, dirName, MAX_PATH);
        WSTRNCAT(name, "/*", MAX_PATH);

        /* get directory handle - see if directory exists */
        findHandle = (HANDLE)WS_FindFirstFileA(name,
                realName, sizeof(realName), &isDir, ssh->ctx->heap);
        if (findHandle == INVALID_HANDLE_VALUE || !isDir) {

            WLOG(WS_LOG_SFTP, "Error with opening directory: %s", name);
            WFREE(dirName, ssh->ctx->heap, DYNTYPE_BUFFER);

            if (wolfSSH_SFTP_CreateStatus(ssh, WOLFSSH_FTP_NOFILE, reqId,
                    "Unable To Open Directory", "English", NULL, &outSz)
                    != WS_SIZE_ONLY) {
                    return WS_FATAL_ERROR;
            }
            ret = WS_BAD_FILE_E;
        }
        if (findHandle != NULL && findHandle != INVALID_HANDLE_VALUE)
            FindClose(findHandle);
    }

    WOLFSSH_UNUSED(reqId);

    if (ret == WS_SUCCESS) {
        WS_DIR_LIST* cur = (WS_DIR_LIST*)WMALLOC(sizeof(WS_DIR_LIST),
                ssh->ctx->heap, DYNTYPE_SFTP);
        if (cur == NULL) {
            WFREE(dirName, ssh->ctx->heap, DYNTYPE_BUFFER);
            return WS_MEMORY_E;
        }
        cur->dir = INVALID_HANDLE_VALUE;
        cur->id[0] = id[0] = ssh->dirIdCount[0];
        cur->id[1] = id[1] = ssh->dirIdCount[1];
        c32toa(id[0], idFlat);
        c32toa(id[1], idFlat + UINT32_SZ);
        AddAssign64(ssh->dirIdCount, 1);
        cur->isEof = 0;
        cur->dirName = dirName; /* take over ownership of buffer */
        cur->next    = ssh->dirList;
        ssh->dirList = cur;

    }

    out = (byte*)WMALLOC(outSz, ssh->ctx->heap, DYNTYPE_BUFFER);
    if (out == NULL) {
        return WS_MEMORY_E;
    }

    if (ret == WS_SUCCESS) {
        SFTP_CreatePacket(ssh, WOLFSSH_FTP_HANDLE, out, outSz,
                idFlat, sizeof(idFlat));
    }
    else {
        if (wolfSSH_SFTP_CreateStatus(ssh, WOLFSSH_FTP_NOFILE, reqId,
                "Unable To Open Directory", "English", out, &outSz)
                != WS_SUCCESS) {
            WFREE(out, ssh->ctx->heap, DYNTYPE_BUFFER);
            return WS_FATAL_ERROR;
        }
    }

    /* set send out buffer, "out" is taken by ssh  */
    wolfSSH_SFTP_RecvSetSend(ssh, out, outSz);

    return ret;
}
#endif /* USE_WINDOWS_API */

#define WS_DATE_SIZE 12

#if defined(XGMTIME) && defined(XSNPRINTF)
/* converts epoch time to recommended calender time from
 * draft-ietf-secsh-filexfer-02.txt */
static void getDate(char* buf, int len, struct tm* t)
{
    int idx;

    if (len < WS_DATE_SIZE + 1)
        return;

    /* place month in buffer */
    buf[0] = '\0';
    switch(t->tm_mon) {
        case 0:  XSTRNCAT(buf, "Jan ", 5); break;
        case 1:  XSTRNCAT(buf, "Feb ", 5); break;
        case 2:  XSTRNCAT(buf, "Mar ", 5); break;
        case 3:  XSTRNCAT(buf, "Apr ", 5); break;
        case 4:  XSTRNCAT(buf, "May ", 5); break;
        case 5:  XSTRNCAT(buf, "Jun ", 5); break;
        case 6:  XSTRNCAT(buf, "Jul ", 5); break;
        case 7:  XSTRNCAT(buf, "Aug ", 5); break;
        case 8:  XSTRNCAT(buf, "Sep ", 5); break;
        case 9:  XSTRNCAT(buf, "Oct ", 5); break;
        case 10: XSTRNCAT(buf, "Nov ", 5); break;
        case 11: XSTRNCAT(buf, "Dec ", 5); break;
        default:
            return;

    }
    idx = 4; /* use idx now for char buffer */

    XSNPRINTF(buf + idx, len - idx, "%2d %02d:%02d",
              t->tm_mday, t->tm_hour, t->tm_min);
    buf[WS_DATE_SIZE] = '\0';
}
#endif

/* used by all ports to create a long name given the file attributes and fname
 * return WS_SUCCESS on success */
static int SFTP_CreateLongName(WS_SFTPNAME* name)
{
#if defined(XGMTIME) && defined(XSNPRINTF)
    char sizeStr[32];
    char perm[11];
    int linkCount = 1; /* @TODO set to correct value */
    char date[WS_DATE_SIZE + 1]; /* +1 for null terminator */
    struct tm* localTime = NULL;
    int i;
    WS_SFTP_FILEATRB* atr;
#endif
    int totalSz = 0;

    if (name == NULL) {
        return WS_BAD_ARGUMENT;
    }

#if defined(XGMTIME) && defined(XSNPRINTF)
    atr = &name->atrb;

    /* get date as calendar date */
    localTime = XGMTIME((const time_t*)&atr->mtime, &localTime);
    if (localTime == NULL) {
        return WS_MEMORY_E;
    }
    getDate(date, sizeof(date), localTime);
    totalSz += WS_DATE_SIZE;

    /* set permissions */
    for (i = 0; i < 10; i++) {
        perm[i] = '-';
    }

    if (atr->flags & WOLFSSH_FILEATRB_PERM) {
        word32 tmp = atr->per;

        i = 0;
        if ((tmp & FILEATRB_PER_MASK_TYPE) == FILEATRB_PER_DIR) {
            perm[i++] = 'd';
        }
        else if ((tmp & FILEATRB_PER_MASK_TYPE) == FILEATRB_PER_LINK) {
            perm[i++] = 'l';
        }
        else {
            perm[i++] = '-';
        }
        perm[i++] = (tmp & 0x100)?'r':'-';
        perm[i++] = (tmp & 0x080)?'w':'-';
        perm[i++] = (tmp & 0x040)?'x':'-';

        perm[i++] = (tmp & 0x020)?'r':'-';
        perm[i++] = (tmp & 0x010)?'w':'-';
        perm[i++] = (tmp & 0x008)?'x':'-';

        perm[i++] = (tmp & 0x004)?'r':'-';
        perm[i++] = (tmp & 0x002)?'w':'-';
        perm[i++] = (tmp & 0x001)?'x':'-';
    }
    totalSz += i;
    perm[i] = '\0';

    totalSz += name->fSz; /* size of file name */
    totalSz += 7; /* for all ' ' spaces */
    totalSz += 3 + 8 + 8; /* linkCount + uid + gid */
    WSNPRINTF(sizeStr, sizeof(sizeStr) - 1, "%8lld",
            ((long long int)atr->sz[1] << 32) + (long long int)(atr->sz[0]));
    totalSz += (int)WSTRLEN(sizeStr);
#else
    totalSz = name->fSz;
#endif

    name->lName = (char*)WMALLOC(totalSz + 1, name->heap, DYNTYPE_SFTP);
    if (name->lName == NULL) {
        WFREE(name->lName, name->heap, DYNTYPE_SFTP);
        return WS_MEMORY_E;
    }
    name->lSz = totalSz;
    name->lName[totalSz] = '\0';

#if defined(XGMTIME) && defined(XSNPRINTF)
    WSNPRINTF(name->lName, totalSz, "%s %3d %8d %8d %s %s %s",
            perm, linkCount, atr->uid, atr->gid, sizeStr, date, name->fName);
#else
    WMEMCPY(name->lName, name->fName, totalSz);
#endif

    return WS_SUCCESS;
}

#if defined(WOLFSSH_SFTP_NAME_READDIR)
/* helper function that gets file information from reading directory.
 * Internally uses SFTP_Name_readdir to delegate the work to the User
 * Filesystem.
 *
 * returns WS_SUCCESS on success
 */
static int wolfSSH_SFTPNAME_readdir(WOLFSSH* ssh, WDIR* dir, WS_SFTPNAME* out,
                                    char* dirName)
{
    WOLFSSH_UNUSED(dirName);
    int res;

    if (dir == NULL || ssh == NULL || out == NULL) {
        return WS_BAD_ARGUMENT;
    }

    res = SFTP_Name_readdir(ssh->fs, dir, out);
    if (res != WS_SUCCESS) {
        return res;
    }

    if (out->fName == NULL) {
        return WS_MEMORY_E;
    }

    /* Use attributes and fName to create long name */
    if (SFTP_CreateLongName(out) != WS_SUCCESS) {
        WLOG(WS_LOG_DEBUG, "Error creating long name for %s", out->fName);
        WFREE(out->fName, out->heap, DYNTYPE_SFTP);
        return WS_FATAL_ERROR;
    }

    return WS_SUCCESS;
}

#elif defined(WOLFSSL_NUCLEUS)
/* For Nucleus port
 * helper function that gets file information from reading directory
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

    /* use long name on Nucleus because sfname has only the file name and in
     * all caps */
    sz = (int)WSTRLEN(dir->lfname);
    out->fName = (char*)WMALLOC(sz + 1, out->heap, DYNTYPE_SFTP);
    if (out->fName == NULL) {
        return WS_MEMORY_E;
    }
    WMEMCPY(out->fName, dir->lfname, sz);
    out->fName[sz] = '\0';
    out->fSz = sz;

    {
        char  r[WOLFSSH_MAX_FILENAME];
        char  s[WOLFSSH_MAX_FILENAME];

        if (!special) { /* do not add dir name in special case */
            if (WSNPRINTF(r, sizeof(r), "%s/%s", dirName, out->fName)
                    >= (int)sizeof(r)) {
                WLOG(WS_LOG_SFTP, "Path length too large");
                WFREE(out->fName, out->heap, DYNTYPE_SFTP);
                return WS_FATAL_ERROR;
            }
        }
        else {
            if (out->fSz + 1 > (sizeof r)) {
                WLOG(WS_LOG_SFTP, "Path length too large");
                WFREE(out->fName, out->heap, DYNTYPE_SFTP);
                return WS_FATAL_ERROR;
            }
            WSTRNCPY(r, out->fName, sizeof(r));
        }

        if (wolfSSH_RealPath(ssh->sftpDefaultPath, r, s, sizeof(s)) < 0) {
            WLOG(WS_LOG_SFTP, "Error cleaning path to get attributes");
            WFREE(out->fName, out->heap, DYNTYPE_SFTP);
            return WS_FATAL_ERROR;
        }

        if (SFTP_GetAttributes(ssh->fs, s, &out->atrb, 0, ssh->ctx->heap)
                != WS_SUCCESS) {
            WLOG(WS_LOG_SFTP, "Unable to get attribute values for %s", buf);
        }
    }

    if (!special && (WREADDIR(ssh->fs, dir)) == NULL) {
        ret = WS_NEXT_ERROR;
    }

    if (special) {
        sz = WSTRLEN(out->fName);

        if ((out->fName[sz - 1] == '/') || (out->fName[sz - 1] == WS_DELIM)) {
            out->fName[sz - 1] = '\0';
            out->fSz--;
        }
    }

    /* Use attributes and fName to create long name */
    if (SFTP_CreateLongName(out) != WS_SUCCESS) {
        WLOG(WS_LOG_DEBUG, "Error creating long name for %s", out->fName);
        WFREE(out->fName, out->heap, DYNTYPE_SFTP);
        return WS_FATAL_ERROR;
    }

    return ret;
}
#elif defined(FREESCALE_MQX)
/* Freescale MQX 4.2
  * helper function that gets file information from reading directory
  *
  * returns WS_SUCCESS on success */
static int wolfSSH_SFTPNAME_readdir(WOLFSSH* ssh, WDIR* dir, WS_SFTPNAME* out,
        char* dirName)
{
    int ret, sz;
    char tmpName[MQX_DEFAULT_SFTP_NAME_SZ];
    MQXDIR* mqxdir = NULL;

    if (ssh == NULL || dir == NULL || out == NULL) {
        return WS_BAD_ARGUMENT;
    }
    mqxdir = *dir;

    if (_io_is_fs_valid(ssh->fs) == 0) {
        WLOG(WS_LOG_SFTP, "Invalid file system pointer");
        return WS_FATAL_ERROR;
    }

    ret = _io_mfs_dir_read(mqxdir->dirStruct, tmpName, sizeof(tmpName));
    if (ret < 0) {
        WLOG(WS_LOG_SFTP, "_io_mfs_dir_read() failed");
        return WS_FATAL_ERROR;
    }
    sz = (int)WSTRLEN(tmpName);

    /* remove /r/n that _io_mfs_dir_read() adds */
    if ((sz >= 2) && (WSTRNCMP(tmpName + sz - 2, "\r\n", 2) == 0)) {
        tmpName[sz - 2] = '\0';
        sz -= 2;
    }

    out->fName = (char*)WMALLOC(sz + 1, out->heap, DYNTYPE_SFTP);
    if (out->fName == NULL) {
        return WS_MEMORY_E;
    }
    WMEMCPY(out->fName, tmpName, sz);
    out->fName[sz] = '\0';
    out->fSz = sz;

    /* attempt to get file attributes. Could be directory or have none */
    {
        char  r[WOLFSSH_MAX_FILENAME];
        char  s[WOLFSSH_MAX_FILENAME];

        if (WSNPRINTF(r, sizeof(r), "%s/%s", dirName, out->fName)
                >= (int)sizeof(r)) {
            WLOG(WS_LOG_SFTP, "Path length too large");
            WFREE(out->fName, out->heap, DYNTYPE_SFTP);
            return WS_FATAL_ERROR;
        }

        if (wolfSSH_RealPath(ssh->sftpDefaultPath, r, s, sizeof(s)) < 0) {
            WLOG(WS_LOG_SFTP, "Error cleaning path to get attributes");
            WFREE(out->fName, out->heap, DYNTYPE_SFTP);
            return WS_FATAL_ERROR;
        }

        if (SFTP_GetAttributes(ssh->fs, s, &out->atrb, 0, ssh->ctx->heap)
                != WS_SUCCESS) {
            WLOG(WS_LOG_SFTP, "Unable to get attribute values for %s",
                    out->fName);
        }
    }

    /* Use attributes and fName to create long name */
    if (SFTP_CreateLongName(out) != WS_SUCCESS) {
        WLOG(WS_LOG_DEBUG, "Error creating long name for %s", out->fName);
        WFREE(out->fName, out->heap, DYNTYPE_SFTP);
        return WS_FATAL_ERROR;
    }

    return WS_SUCCESS;
}

#elif defined(USE_WINDOWS_API)

/* helper function that gets file information from reading directory
*
* returns WS_SUCCESS on success
*/
static int wolfSSH_SFTPNAME_readdir(WOLFSSH* ssh, WDIR* dir, WS_SFTPNAME* out,
        char* dirName)
{
    int sz, special = 0;
    HANDLE findHandle;
    char realFileName[MAX_PATH];

    if (dir == NULL || ssh == NULL || out == NULL) {
        return WS_BAD_ARGUMENT;
    }

    /* special case of getting drives at "/" */
    if (dirName[0] == '/' && dirName[1] == 0) {
        if (ssh->driveIdx >= ssh->driveListCount)
            return WS_FATAL_ERROR;
        realFileName[0] = ssh->driveList[ssh->driveIdx++];
        realFileName[1] = ':';
        realFileName[2] = '\0';
        special = 1;
    }
    else if (*dir == INVALID_HANDLE_VALUE) {
        char name[MAX_PATH];
        word32 nameLen = (word32)WSTRLEN(dirName);

        if (nameLen > MAX_PATH - 2) {
            WLOG(WS_LOG_SFTP, "Path name is too long.");
            return WS_FATAL_ERROR;
        }
        WSTRNCPY(name, dirName, MAX_PATH);
        WSTRNCAT(name, "/*", MAX_PATH);

        findHandle = (HANDLE)WS_FindFirstFileA(name,
                realFileName, sizeof(realFileName), NULL, ssh->ctx->heap);

        if (findHandle == INVALID_HANDLE_VALUE)
            return WS_FATAL_ERROR;
        else
            *dir = findHandle;
    }
    else {
        findHandle = *dir;
        if (WS_FindNextFileA(findHandle,
                    realFileName, sizeof(realFileName)) == 0) {
            return WS_FATAL_ERROR;
        }
    }

    sz = (int)WSTRLEN(realFileName);
    out->fName = (char*)WMALLOC(sz + 1, out->heap, DYNTYPE_SFTP);
    if (out->fName == NULL) {
        return WS_MEMORY_E;
    }
    WMEMCPY(out->fName, realFileName, sz);
    out->fName[sz] = '\0';
    out->fSz = sz;

    /* attempt to get file attributes. Could be directory or have none */
    {
        char* buf;
        int   bufSz;

        bufSz = out->fSz + (int)WSTRLEN(dirName) + 2; /* /+nul */
        buf = (char*)WMALLOC(bufSz, out->heap, DYNTYPE_SFTP);
        if (buf == NULL) {
            WFREE(out->fName, out->heap, DYNTYPE_SFTP);
            return WS_MEMORY_E;
        }

        if (!special) {
            WSNPRINTF(buf, bufSz, "%s/%s", dirName, out->fName);
        }
        else {
            WSNPRINTF(buf, bufSz, "%s/", realFileName);
        }
        if (SFTP_GetAttributes(ssh->fs, buf, &out->atrb, 0, ssh->ctx->heap)
                != WS_SUCCESS) {
            WLOG(WS_LOG_SFTP, "Unable to get attribute values for %s",
                out->fName);
        }
        WFREE(buf, out->heap, DYNTYPE_SFTP);
    }

    /* Use attributes and fName to create long name */
    if (SFTP_CreateLongName(out) != WS_SUCCESS) {
        WLOG(WS_LOG_DEBUG, "Error creating long name for %s", out->fName);
        WFREE(out->fName, out->heap, DYNTYPE_SFTP);
        return WS_FATAL_ERROR;
    }

    return WS_SUCCESS;
}

#elif defined(WOLFSSH_FATFS)

/* helper function that gets file information from reading directory
 *
 * returns WS_SUCCESS on success
 */
static int wolfSSH_SFTPNAME_readdir(WOLFSSH* ssh, WDIR* dir, WS_SFTPNAME* out,
        char* dirName)
{
    FILINFO f;
    FILINFO *dp;
    int sz;

    if (dir == NULL || ssh == NULL || out == NULL) {
        return WS_BAD_ARGUMENT;
    }
    dp = &f;

    if (f_readdir(dir, dp) != FR_OK) {
        return WS_FATAL_ERROR;
    }
    sz = (int)WSTRLEN(dp->fname);
    out->fName = (char*)WMALLOC(sz + 1, out->heap, DYNTYPE_SFTP);
    if (out->fName == NULL) {
        return WS_MEMORY_E;
    }

    WMEMCPY(out->fName, dp->fname, sz);
    out->fName[sz] = '\0';
    out->fSz = sz;

    /* attempt to get file attributes. Could be directory or have none */
    {
        char  r[WOLFSSH_MAX_FILENAME];
        char  s[WOLFSSH_MAX_FILENAME];

        if (WSNPRINTF(r, sizeof(r), "%s/%s", dirName, out->fName)
                >= (int)sizeof(r)) {
            WLOG(WS_LOG_SFTP, "Path length too large");
            WFREE(out->fName, out->heap, DYNTYPE_SFTP);
            return WS_FATAL_ERROR;
        }

        if (wolfSSH_RealPath(ssh->sftpDefaultPath, r, s, sizeof(s)) < 0) {
            WLOG(WS_LOG_SFTP, "Error cleaning path to get attributes");
            WFREE(out->fName, out->heap, DYNTYPE_SFTP);
            return WS_FATAL_ERROR;
        }
        if (SFTP_GetAttributes(ssh->fs, s, &out->atrb, 0, ssh->ctx->heap)
                != WS_SUCCESS) {
            WLOG(WS_LOG_SFTP, "Unable to get attribute values for %s",
                    out->fName);
            WFREE(out->fName, out->heap, DYNTYPE_SFTP);
            return WS_FATAL_ERROR;
        }
    }

    /* Use attributes and fName to create long name */
    if (SFTP_CreateLongName(out) != WS_SUCCESS) {
        WLOG(WS_LOG_DEBUG, "Error creating long name for %s", out->fName);
        WFREE(out->fName, out->heap, DYNTYPE_SFTP);
        return WS_FATAL_ERROR;
    }
    return WS_SUCCESS;
}

#elif defined(WOLFSSH_ZEPHYR)

/* helper function that gets file information from reading directory
 *
 * returns WS_SUCCESS on success
 */
static int wolfSSH_SFTPNAME_readdir(WOLFSSH* ssh, WDIR* dir, WS_SFTPNAME* out,
        char* dirName)
{
    struct fs_dirent dp;
    int sz;

    if (dir == NULL || ssh == NULL || out == NULL) {
        return WS_BAD_ARGUMENT;
    }

    /* 0 return and dp.name[0] == 0 means end-of-dir */
    if (fs_readdir(dir, &dp) != 0 || dp.name[0] == 0) {
        return WS_FATAL_ERROR;
    }

    sz = (int)WSTRLEN(dp.name);
    out->fName = (char*)WMALLOC(sz + 1, out->heap, DYNTYPE_SFTP);
    if (out->fName == NULL) {
        return WS_MEMORY_E;
    }

    WMEMCPY(out->fName, dp.name, sz);
    out->fName[sz] = '\0';
    out->fSz = sz;

    /* attempt to get file attributes. Could be directory or have none */
    {
        char  r[WOLFSSH_MAX_FILENAME];
        char  s[WOLFSSH_MAX_FILENAME];

        if (WSNPRINTF(r, sizeof(r), "%s/%s", dirName, out->fName)
                >= (int)sizeof(r)) {
            WLOG(WS_LOG_SFTP, "Path length too large");
            WFREE(out->fName, out->heap, DYNTYPE_SFTP);
            return WS_FATAL_ERROR;
        }

        if (wolfSSH_RealPath(ssh->sftpDefaultPath, r, s, sizeof(s)) < 0) {
            WFREE(out->fName, out->heap, DYNTYPE_SFTP);
            WLOG(WS_LOG_SFTP, "Error cleaning path to get attributes");
            return WS_FATAL_ERROR;
        }

        if (SFTP_GetAttributes(ssh->fs, s, &out->atrb, 0, ssh->ctx->heap)
                != WS_SUCCESS) {
            WLOG(WS_LOG_SFTP, "Unable to get attribute values for %s",
                    out->fName);
        }
    }

    /* Use attributes and fName to create long name */
    if (SFTP_CreateLongName(out) != WS_SUCCESS) {
        WLOG(WS_LOG_DEBUG, "Error creating long name for %s", out->fName);
        WFREE(out->fName, out->heap, DYNTYPE_SFTP);
        return WS_FATAL_ERROR;
    }

    return WS_SUCCESS;
}

#elif defined(MICROCHIP_MPLAB_HARMONY)
#ifndef WOLFSSH_USER_FILESYSTEM
int SFTP_GetAttributesStat(WS_SFTP_FILEATRB* atr, WSTAT_T* stats);
#endif

/* helper function that gets file information from reading directory
 *
 * returns WS_SUCCESS on success
 */
static int wolfSSH_SFTPNAME_readdir(WOLFSSH* ssh, WDIR* dir, WS_SFTPNAME* out,
        char* dirName)
{
    WSTAT_T stat;
    int sz;

    if (dir == NULL || ssh == NULL || out == NULL) {
        return WS_BAD_ARGUMENT;
    }

    if (*dir == SYS_FS_HANDLE_INVALID) {
        WLOG(WS_LOG_SFTP, "READ dir attempted with invalid handle");
        return WS_BAD_ARGUMENT;
    }
    WMEMSET(&stat, 0, sizeof(WSTAT_T));

    /* 0 return and dp.name[0] == 0 means end-of-dir */
    if (SYS_FS_DirRead(*dir, &stat) != SYS_FS_RES_SUCCESS ||
            stat.fname[0] == '\0') {
        return WS_FATAL_ERROR;
    }
    WLOG(WS_LOG_SFTP, "READ dir got nam %s", stat.fname);

    sz = (int)WSTRLEN(stat.fname);
    out->fName = (char*)WMALLOC(sz + 1, out->heap, DYNTYPE_SFTP);
    if (out->fName == NULL) {
        return WS_MEMORY_E;
    }

    WMEMCPY(out->fName, stat.fname, sz);
    out->fName[sz] = '\0';
    out->fSz = sz;

    if (SFTP_GetAttributesStat(&out->atrb, &stat) != WS_SUCCESS) {
        WLOG(WS_LOG_SFTP, "Unable to get attribute values for %s",
                out->fName);
    }

    /* Use attributes and fName to create long name */
    if (SFTP_CreateLongName(out) != WS_SUCCESS) {
        WLOG(WS_LOG_DEBUG, "Error creating long name for %s", out->fName);
        WFREE(out->fName, out->heap, DYNTYPE_SFTP);
        return WS_FATAL_ERROR;
    }
    return WS_SUCCESS;
}

#else

/* helper function that gets file information from reading directory
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

    dp = WREADDIR(ssh->fs, dir);
    if (dp == NULL) {
        return WS_FATAL_ERROR;
    }

    sz = (int)WSTRLEN(dp->d_name);
    out->fName = (char*)WMALLOC(sz + 1, out->heap, DYNTYPE_SFTP);
    if (out->fName == NULL) {
        return WS_MEMORY_E;
    }

    WMEMCPY(out->fName, dp->d_name, sz);
    out->fName[sz] = '\0';
    out->fSz = sz;

    /* attempt to get file attributes. Could be directory or have none */
    {
        char  r[WOLFSSH_MAX_FILENAME];
        char  s[WOLFSSH_MAX_FILENAME];

        if (WSNPRINTF(r, sizeof(r), "%s/%s", dirName, out->fName)
                >= (int)sizeof(r)) {
            WLOG(WS_LOG_SFTP, "Path length too large");
            WFREE(out->fName, out->heap, DYNTYPE_SFTP);
            out->fName = NULL;
            out->fSz = 0;
            return WS_FATAL_ERROR;
        }

        if (wolfSSH_RealPath(ssh->sftpDefaultPath, r, s, sizeof(s)) < 0) {
            WFREE(out->fName, out->heap, DYNTYPE_SFTP);
            WLOG(WS_LOG_SFTP, "Error cleaning path to get attributes");
            out->fName = NULL;
            out->fSz = 0;
            return WS_FATAL_ERROR;
        }

        if (SFTP_GetAttributes(ssh->fs, s, &out->atrb, 1, ssh->ctx->heap)
                != WS_SUCCESS) {
            WLOG(WS_LOG_SFTP, "Unable to get attribute values for %s",
                    out->fName);
        }
    }

    /* Use attributes and fName to create long name */
    if (SFTP_CreateLongName(out) != WS_SUCCESS) {
        WLOG(WS_LOG_DEBUG, "Error creating long name for %s", out->fName);
        WFREE(out->fName, out->heap, DYNTYPE_SFTP);
        out->fName = NULL;
        out->fSz = 0;
        return WS_FATAL_ERROR;
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
        ssh->sftpDefaultPath = (char*)WMALLOC(sftpDefaultPathSz,
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
    WDIR*  dir = NULL;
    word32 handle[2] = {0, 0};
    word32 sz;
    word32 idx = 0;
    int count = 0;
    int ret;
    WS_SFTPNAME* name = NULL;
    WS_SFTPNAME* list = NULL;
    word32 outSz = 0;
    WS_DIR_LIST* cur;
    char* dirName = NULL;
    byte* out;

    if (ssh == NULL) {
        return WS_BAD_ARGUMENT;
    }

    WLOG(WS_LOG_SFTP, "Receiving WOLFSSH_FTP_READDIR");

    cur = ssh->dirList;
    #ifdef USE_WINDOWS_API
        dir = INVALID_HANDLE_VALUE;
    #endif

    if (maxSz < UINT32_SZ) {
        /* not enough for an ato32 call */
        return WS_BUFFER_E;
    }

    /* get directory handle */
    ato32(data + idx, &sz); idx += UINT32_SZ;
    if (sz + idx > maxSz || sz > WOLFSSH_MAX_HANDLE) {
        return WS_BUFFER_E;
    }

    if (sz != (sizeof(word32) * 2)) {
        WLOG(WS_LOG_SFTP, "Unexpected handle size");
        return WS_FATAL_ERROR;
    }
    ato32(data + idx, &handle[0]);
    ato32(data + idx + UINT32_SZ, &handle[1]);

    /* find DIR given handle */
    while (cur != NULL) {
        if (cur->id[0] == handle[0] && cur->id[1] == handle[1]) {
            dir = &cur->dir;
            dirName = cur->dirName;
            break;
        }
        cur = cur->next;
    }
    if (cur == NULL) {
        /* unable to find handle */
        WLOG(WS_LOG_SFTP, "Unable to find handle");
        return WS_FATAL_ERROR;
    }

    /* get directory information */
    outSz += UINT32_SZ + WOLFSSH_SFTP_HEADER; /* hold header+number of files */
    if (!cur->isEof) {
        do {
            name = wolfSSH_SFTPNAME_new(ssh->ctx->heap);
            ret = wolfSSH_SFTPNAME_readdir(ssh, dir, name, dirName);
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
    }

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

        /* set send out buffer, "out" is taken by ssh  */
        wolfSSH_SFTP_RecvSetSend(ssh, out, outSz);
        return WS_SUCCESS;
    }

    /* if next state would cause an error then set EOF flag for when called
     * again */
    cur->isEof = 1;
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

    /* set send out buffer, "out" is taken by ssh  */
    wolfSSH_SFTP_RecvSetSend(ssh, out, outSz);
    return WS_SUCCESS;
}


/* Handles packet to close a directory
 *
 * returns 0 on success
 */
int wolfSSH_SFTP_RecvCloseDir(WOLFSSH* ssh, byte* handle, word32 handleSz)
{
    WS_DIR_LIST* cur;
    word32 h[2] = {0,0};

    if (ssh == NULL || handle == NULL || handleSz != (sizeof(word32)*2)) {
        return WS_BAD_ARGUMENT;
    }

    WLOG(WS_LOG_SFTP, "Receiving WOLFSSH_FTP_CLOSE Directory");

    /* find DIR given handle */
    cur = ssh->dirList;
    ato32(handle, &h[0]);
    ato32(handle + UINT32_SZ, &h[1]);
    while (cur != NULL) {
        if (cur->id[0] == h[0] && cur->id[1] == h[1]) {
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
    WCLOSEDIR(ssh->fs, &cur->dir);
#endif

    /* remove directory from list */
    if (cur != NULL) {
        WS_DIR_LIST* pre = ssh->dirList;

        WLOG(WS_LOG_SFTP, "Free'ing and closing handle %d%d pointer of [%p]",
                cur->id[1], cur->id[0], cur);
        /* case where node is at head of list */
        if (pre == cur) {
            ssh->dirList = cur->next;
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
    word32 ofst[2] = {0,0};

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

    if (maxSz < UINT32_SZ) {
        /* not enough for an ato32 call */
        return WS_BUFFER_E;
    }

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
        ato32(data + idx, &ofst[1]); idx += UINT32_SZ;
        ato32(data + idx, &ofst[0]); idx += UINT32_SZ;

        /* get length to be written */
        ato32(data + idx, &sz); idx += UINT32_SZ;
        if (sz > maxSz - idx) {
            return WS_BUFFER_E;
        }

        ret = WPWRITE(ssh->fs, fd, data + idx, sz, ofst);
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

    if (sz > maxSz - idx) {
        return WS_BUFFER_E;
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

    /* set send out buffer, "out" is taken by ssh  */
    wolfSSH_SFTP_RecvSetSend(ssh, out, outSz);
    return ret;
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

    if (maxSz < UINT32_SZ) {
        /* not enough for an ato32 call */
        return WS_BUFFER_E;
    }

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
        if (sz > maxSz - idx) {
            return WS_BUFFER_E;
        }

        if (WriteFile(fd, data + idx, sz, &bytesWritten, &offset) == 0) {
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

    /* set send out buffer, "out" is taken by ssh  */
    wolfSSH_SFTP_RecvSetSend(ssh, out, outSz);
    return ret;
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
    word32 ofst[2] = {0, 0};

    byte*  out;
    word32 outSz = 0;

    char* res  = NULL;
    char err[] = "Read File Error";
    char eof[] = "Read EOF";
    byte type = WOLFSSH_FTP_FAILURE;

    if (ssh == NULL) {
        return WS_BAD_ARGUMENT;
    }

    WLOG(WS_LOG_SFTP, "Receiving WOLFSSH_FTP_READ");

    if (maxSz < UINT32_SZ) {
        /* not enough for an ato32 call */
        return WS_BUFFER_E;
    }

    /* get file handle */
    ato32(data + idx, &sz); idx += UINT32_SZ;
    if (sz + idx > maxSz || sz > WOLFSSH_MAX_HANDLE) {
        return WS_BUFFER_E;
    }
    WMEMSET((byte*)&fd, 0, sizeof(WFD));
    WMEMCPY((byte*)&fd, data + idx, sz); idx += sz;

    /* get offset into file */
    ato32(data + idx, &ofst[1]); idx += UINT32_SZ;
    ato32(data + idx, &ofst[0]); idx += UINT32_SZ;

    /* get length to be read */
    ato32(data + idx, &sz);
    if (sz > maxSz - WOLFSSH_SFTP_HEADER - UINT32_SZ - idx) {
        return WS_BUFFER_E;
    }

    /* read from handle and send data back to client */
    out = (byte*)WMALLOC(sz + WOLFSSH_SFTP_HEADER + UINT32_SZ,
            ssh->ctx->heap, DYNTYPE_BUFFER);
    if (out == NULL) {
        return WS_MEMORY_E;
    }

    ret = WPREAD(ssh->fs, fd, out + UINT32_SZ + WOLFSSH_SFTP_HEADER, sz, ofst);
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
        WLOG(WS_LOG_SFTP, "Error reading from file, EOF");
        res = eof;
        type = WOLFSSH_FTP_EOF;
        ret = WS_SUCCESS; /* end of file is not fatal error */
    }

    if (res != NULL) {
        if (wolfSSH_SFTP_CreateStatus(ssh, type, reqId, res, "English", NULL,
                &outSz) != WS_SIZE_ONLY) {
            WFREE(out, ssh->ctx->heap, DYNTYPE_BUFFER);
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

    /* set send out buffer, "out" is taken by ssh  */
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
    word32 outSz = 0;

    char* res  = NULL;
    char err[] = "Read File Error";
    char eof[] = "Read EOF";
    byte type = WOLFSSH_FTP_FAILURE;

    if (ssh == NULL) {
        return WS_BAD_ARGUMENT;
    }

    WLOG(WS_LOG_SFTP, "Receiving WOLFSSH_FTP_READ");

    if (maxSz < UINT32_SZ) {
        /* not enough for an ato32 call */
        return WS_BUFFER_E;
    }

    /* get file handle */
    ato32(data + idx, &sz); idx += UINT32_SZ;
    if (sz > maxSz - idx || sz > WOLFSSH_MAX_HANDLE) {
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
    if (sz > maxSz - WOLFSSH_SFTP_HEADER - UINT32_SZ - idx) {
        return WS_BUFFER_E;
    }

    /* read from handle and send data back to client */
    out = (byte*)WMALLOC(sz + WOLFSSH_SFTP_HEADER + UINT32_SZ,
            ssh->ctx->heap, DYNTYPE_BUFFER);
    if (out == NULL) {
        return WS_MEMORY_E;
    }

    if (ReadFile(fd, out + UINT32_SZ + WOLFSSH_SFTP_HEADER, sz,
                &bytesRead, &offset) == 0) {
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
        WLOG(WS_LOG_SFTP, "Error reading from file, EOF");
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

    /* set send out buffer, "out" is taken by ssh  */
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
    int    ret = WS_FATAL_ERROR;

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

    if (maxSz < UINT32_SZ) {
        /* not enough for an ato32 call */
        return WS_BUFFER_E;
    }

    /* get file handle */
    ato32(data + idx, &sz); idx += UINT32_SZ;
    if (sz + idx > maxSz || sz > WOLFSSH_MAX_HANDLE) {
        return WS_BUFFER_E;
    }

#ifndef NO_WOLFSSH_DIR
    /* check if is a handle for a directory */
    if (sz == (sizeof(word32) * 2)) {
        ret = wolfSSH_SFTP_RecvCloseDir(ssh, data + idx, sz);
    }
    if (ret != WS_SUCCESS) {
#endif /* NO_WOLFSSH_DIR */
    if (sz == sizeof(WFD)) {
        WMEMSET((byte*)&fd, 0, sizeof(WFD));
        WMEMCPY((byte*)&fd, data + idx, sz);

#ifdef MICROCHIP_MPLAB_HARMONY
        ret = WFCLOSE(ssh->fs, &fd);
#else
        ret = WCLOSE(ssh->fs, fd);
#endif
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
#ifndef NO_WOLFSSH_DIR
    }
#endif

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

    /* set send out buffer, "out" is taken by ssh  */
    wolfSSH_SFTP_RecvSetSend(ssh, out, outSz);
    return ret;
}
#else /* USE_WINDOWS_API */
{
    HANDLE fd;
    word32 sz;
    word32 idx  = 0;
    int    ret = WS_FATAL_ERROR;

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

    if (maxSz < UINT32_SZ) {
        /* not enough for an ato32 call */
        return WS_BUFFER_E;
    }

    /* get file handle */
    ato32(data + idx, &sz); idx += UINT32_SZ;
    if (sz + idx > maxSz || sz > WOLFSSH_MAX_HANDLE) {
        return WS_BUFFER_E;
    }

#ifndef NO_WOLFSSH_DIR
    /* check if is a handle for a directory */
    if (sz == (sizeof(word32) * 2)) {
        ret = wolfSSH_SFTP_RecvCloseDir(ssh, data + idx, sz);
    }
    if (ret != WS_SUCCESS) {
#endif /* NO_WOLFSSH_DIR */
    if (sz == sizeof(HANDLE)) {
        WMEMSET((byte*)&fd, 0, sizeof(HANDLE));
        WMEMCPY((byte*)&fd, data + idx, sz);
        CloseHandle(fd);
        ret = WS_SUCCESS;
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
#ifndef NO_WOLFSSH_DIR
    }
#endif

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

    /* set send out buffer, "out" is taken by ssh  */
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
    char   name[WOLFSSH_MAX_FILENAME];
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

    if (maxSz < UINT32_SZ) {
        /* not enough for an ato32 call */
        return WS_BUFFER_E;
    }

    /* get file name */
    ato32(data + idx, &sz); idx += UINT32_SZ;
    if (sz + idx > maxSz || sz > WOLFSSH_MAX_HANDLE) {
        return WS_BUFFER_E;
    }

    ret = GetAndCleanPath(ssh->sftpDefaultPath, data + idx, sz,
            name, sizeof(name));

    if (ret == WS_SUCCESS) {
    #ifndef USE_WINDOWS_API
        if (WREMOVE(ssh->fs, name) < 0)
    #else /* USE_WINDOWS_API */
        if (WS_DeleteFileA(name, ssh->ctx->heap) == 0)
    #endif /* USE_WINDOWS_API */
        {
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
    }

    /* Let the client know the results from trying to remove the file */
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

    /* set send out buffer, "out" is taken by ssh  */
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
    char   old[WOLFSSH_MAX_FILENAME];
    char   name[WOLFSSH_MAX_FILENAME];
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

    if (maxSz < UINT32_SZ) {
        /* not enough for an ato32 call */
        return WS_BUFFER_E;
    }

    /* get old file name */
    ato32(data + idx, &sz); idx += UINT32_SZ;
    if (sz > maxSz - idx) {
        ret = WS_BUFFER_E;
    }
    if (ret == WS_SUCCESS) {
        ret = GetAndCleanPath(ssh->sftpDefaultPath, data + idx, sz,
                old, sizeof(old));
    }
    if (ret == WS_SUCCESS) {
        idx += sz;
        /* get new file name */
        ato32(data + idx, &sz); idx += UINT32_SZ;
        if (sz > maxSz - idx) {
            ret = WS_BUFFER_E;
        }
    }
    if (ret == WS_SUCCESS) {
        ret = GetAndCleanPath(ssh->sftpDefaultPath, data + idx, sz,
                name, sizeof(name));
    }

    if (ret == WS_SUCCESS) {
    #ifndef USE_WINDOWS_API
        if (WRENAME(ssh->fs, old, name) < 0)
    #else /* USE_WINDOWS_API */
        if (WS_MoveFileA(old, name, ssh->ctx->heap) == 0)
    #endif /* USE_WINDOWS_API */
        {
            WLOG(WS_LOG_SFTP, "Error renaming file");
            ret = WS_BAD_FILE_E;
        }
    }

    /* Let the client know the results from trying to rename the file */
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

    /* set send out buffer, "out" is taken by ssh  */
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
        if (handleSz == cur->handleSz
                && WMEMCMP(handle, cur->handle, handleSz) == 0) {
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
        WLOG(WS_LOG_SFTP,
            "Fatal Error! Trying to remove a handle that was not in the list");
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


#if defined(WOLFSSH_USER_FILESYSTEM)
    /* User-defined I/O support */

#elif defined(WOLFSSL_NUCLEUS)

#ifndef NO_WOLFSSH_MKTIME

#define WS_GETDAY(d) ((d) & 0x001f)
#define _GETMON(d) (((d) >> 5) & 0x000f)
/* number of years since 1900. year + 1980 - 1900 */
#define WS_GETYEAR(d) ((((d) >> 9) & 0x007f) + 80)
#define _GETHOUR(t) (((t) >> 11) & 0x001f)
#define WS_GETMIN(t)  (((t) >> 5 ) & 0x003f)
#define WS_GETSEC(t)  (((t) << 1 ) & 0x003f)
#ifdef WOLFSSL_NUCLEUS
    /* mktime() expects month from 0 to 11. Nucleus months
    * are saved as 1 to 12. Hence 1 is being deducted to
    * make it compatible with Unix time stamp. */
    #define WS_GETMON(d) (_GETMON(d) - 5)
    #define WS_GETHOUR(t) (_GETHOUR(t) - 1)
#else
    #define WS_GETMON(d) _GETMON(d)
    #define WS_GETHOUR(t) _GETHOUR(t)
#endif

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
int SFTP_GetAttributes(void* fs, const char* fileName, WS_SFTP_FILEATRB* atr,
        byte noFollow, void* heap)
{
    DSTAT stats;
    int sz = (int)WSTRLEN(fileName);
    int ret;

    WOLFSSH_UNUSED(heap);
    WOLFSSH_UNUSED(fs);

    if (noFollow) {
        ret = WLSTAT(ssh->fs, fileName, &stats);
    }
    else {
        ret = WSTAT(ssh->fs, fileName, &stats);
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
    atr->sz[0]  = (word32)(stats.fsize);
    atr->sz[1]  = (word32)(0);

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
        char* name, WS_SFTP_FILEATRB* atr)
{
    DSTAT stats;

    if (handle == NULL || atr == NULL) {
        return WS_FATAL_ERROR;
    }

    if (WSTAT(ssh->fs, name, &stats) != NU_SUCCESS) {
        return WS_FATAL_ERROR;
    }

    WMEMSET(atr, 0, sizeof(WS_SFTP_FILEATRB));

    atr->flags |= WOLFSSH_FILEATRB_SIZE;
    atr->sz[0]  = (word32)(stats.fsize);
    atr->sz[1]  = (word32)(0);

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
int SFTP_GetAttributes(void* fs, const char* fileName, WS_SFTP_FILEATRB* atr,
        byte noFollow, void* heap)
{
    BOOL error;
    WIN32_FILE_ATTRIBUTE_DATA stats;

    WLOG(WS_LOG_SFTP, "Entering SFTP_GetAttributes()");
    WOLFSSH_UNUSED(noFollow);
    WOLFSSH_UNUSED(fs);

    /* @TODO add proper Windows link support */
    /* Note, for windows, we treat WSTAT and WLSTAT the same. */
    error = !WS_GetFileAttributesExA(fileName, &stats, heap);
    if (error)
        return WS_BAD_FILE_E;

    WMEMSET(atr, 0, sizeof(WS_SFTP_FILEATRB));

    atr->flags |= WOLFSSH_FILEATRB_SIZE;
    atr->sz[1] = stats.nFileSizeHigh;
    atr->sz[0] = stats.nFileSizeLow;

    atr->flags |= WOLFSSH_FILEATRB_PERM;
    atr->per = 0555 |
        ((stats.dwFileAttributes | FILE_ATTRIBUTE_READONLY) ? 0 : 0200);
    atr->per |= ((stats.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        ? FILEATRB_PER_DIR : FILEATRB_PER_FILE);

#if 0
    /* @TODO handle the constellation of possible Windows FILETIMEs */
    atr->flags |= WOLFSSH_FILEATRB_TIME;
    atr->atime = (word32)stats.ftLastAccessTime;
    atr->mtime = (word32)stats.ftLastWriteTime;
#endif

    /* @TODO handle attribute extensions */

    return WS_SUCCESS;
}

#elif defined(FREESCALE_MQX)

/* @TODO can be overriden by user for portability
 * NOTE: if atr->flags is set to a value of 0 then no attributes are set.
 * Fills out a WS_SFTP_FILEATRB structure
 * returns WS_SUCCESS on success */
int SFTP_GetAttributes(void* fs, const char* fileName, WS_SFTP_FILEATRB* atr,
                       byte noFollow, void* heap)
{
    int err, sz;
    MQX_FILE_PTR mfs_ptr;
    MFS_SEARCH_DATA search_data;
    MFS_SEARCH_PARAM search;

    if (fileName == NULL || atr == NULL) {
        return WS_BAD_FILE_E;
    }
    mfs_ptr = (MQX_FILE_PTR)fs;
    sz = (int)WSTRLEN(fileName);

    /* handle case of '<drive>:/.' */
    if ((sz >= 3) && (WSTRNCMP(fileName + sz - 3, ":/.", 3) == 0)) {
        atr->flags |= WOLFSSH_FILEATRB_PERM;
        atr->per |= 0x4000;
        return WS_SUCCESS;
    }

    search.ATTRIBUTE = MFS_SEARCH_ANY;
    search.WILDCARD = (char*)fileName;
    search.SEARCH_DATA_PTR = &search_data;

    err = ioctl(mfs_ptr, IO_IOCTL_FIND_FIRST_FILE, (uint32_t*)&search);
    if (err != MFS_NO_ERROR) {
        return WS_FATAL_ERROR;
    }

    WMEMSET(atr, 0, sizeof(WS_SFTP_FILEATRB));

    /* file size */
    atr->flags |= WOLFSSH_FILEATRB_SIZE;
    atr->sz[0] = (word32)search_data.FILE_SIZE;
    atr->sz[1] = (word32)(0);

    /* file permissions */
    atr->flags |= WOLFSSH_FILEATRB_PERM;
    if (search_data.ATTRIBUTE & MFS_ATTR_DIR_NAME) {
        atr->per |= 0x41ED; /* 755 with directory */
    } else {
        atr->per |= 0x8000;
    }

    /* check for read only */
    if (search_data.ATTRIBUTE & MFS_ATTR_READ_ONLY) {
        atr->per |= 0x124; /* octal 444 */
    } else {
        atr->per |= 0x1ED; /* octal 755 */
    }

    return WS_SUCCESS;
}

/* @TODO can be overriden by user for portability
 * Gets attributes based on file descriptor
 * NOTE: if atr->flags is set to a value of 0 then no attributes are set.
 * Fills out a WS_SFTP_FILEATRB structure
 * returns WS_SUCCESS on success */
int SFTP_GetAttributes_Handle(WOLFSSH* ssh, byte* handle, int handleSz,
                              char* name, WS_SFTP_FILEATRB* atr)
{
    int err;
    MQX_FILE_PTR mfs_ptr;
    MFS_SEARCH_DATA search_data;
    MFS_SEARCH_PARAM search;

    if (handle == NULL || atr == NULL || ssh == NULL) {
        return WS_FATAL_ERROR;
    }
    mfs_ptr = (MQX_FILE_PTR)ssh->fs;

    search.ATTRIBUTE = MFS_SEARCH_ANY;
    search.WILDCARD = name;
    search.SEARCH_DATA_PTR = &search_data;

    err = ioctl(mfs_ptr, IO_IOCTL_FIND_FIRST_FILE, (uint32_t*)&search);
    if (err != MFS_NO_ERROR) {
        return WS_FATAL_ERROR;
    }

    WMEMSET(atr, 0, sizeof(WS_SFTP_FILEATRB));

    /* file size */
    atr->flags |= WOLFSSH_FILEATRB_SIZE;
    atr->sz[0] = (word32)search_data.FILE_SIZE;
    atr->sz[1] = (word32)(0);

    /* file permissions */
    atr->flags |= WOLFSSH_FILEATRB_PERM;
    if (search_data.ATTRIBUTE & MFS_ATTR_DIR_NAME) {
        atr->per |= 0x41ED; /* 755 with directory */
    } else {
        atr->per |= 0x8000;
    }

    /* check for read only */
    if (search_data.ATTRIBUTE & MFS_ATTR_READ_ONLY) {
        atr->per |= 0x124; /* octal 444 */
    } else {
        atr->per |= 0x1ED; /* octal 755 */
    }

    return WS_SUCCESS;
}

#elif defined(WOLFSSH_FATFS)

/* FatFs has its own structure for file attributes */

static int SFTP_GetAttributes(void* fs, const char* fileName,
        WS_SFTP_FILEATRB* atr, byte noFollow, void* heap)
{
    FILINFO info;
    FRESULT ret;
    int sz = (int)WSTRLEN(fileName);

    (void) fs;
    (void) noFollow;
    (void) heap;

    ret = f_stat(fileName, &info);
    if (ret != FR_OK)
        return -1;
    WMEMSET(atr, 0, sizeof(WS_SFTP_FILEATRB));
    if (sz > 2 && fileName[sz - 2] == ':') {
        atr->flags |= WOLFSSH_FILEATRB_PERM;
        atr->per |= 0x4000;
        return WS_SUCCESS;
    }

    /* handle case of "/" */
    if (sz < 3 && fileName[0] == WS_DELIM) {
        atr->flags |= WOLFSSH_FILEATRB_PERM;
        atr->per |= 0x4000;
        return WS_SUCCESS;
    }

    if (ret != FR_OK) {
        return WS_BAD_FILE_E;
    }

    atr->flags |= WOLFSSH_FILEATRB_SIZE;
    atr->sz[0]  = (word32)(info.fsize);
    atr->sz[1]  = (word32)(0);

    /* get additional attributes */
    {
        byte atrib = info.fattrib;
        atr->flags |= WOLFSSH_FILEATRB_PERM;
        if (atrib & AM_DIR) {
            atr->per |= 0x41ED; /* 755 with directory */
        }
        else {
            atr->per |= 0x8000;
        }
        if ((atrib & AM_ARC) == AM_ARC) {
            atr->per |= 0x1ED; /* octal 755 */
        }
        if ((atrib & AM_SYS) || (atrib & AM_RDO)) {
            atr->per |= 0x124; /* octal 444 */
        }
    }

#ifndef NO_WOLFSSH_MKTIME
    /* get file times */
    atr->flags |= WOLFSSH_FILEATRB_TIME;
    atr->atime = info.fdate;
    atr->mtime = info.fdate;
#endif /* NO_WOLFSSH_MKTIME */
    return WS_SUCCESS;
}

static int SFTP_GetAttributes_Handle(WOLFSSH* ssh, byte* handle, int handleSz,
        char* name, WS_SFTP_FILEATRB* atr)
{
    FILINFO info;

    if (handle == NULL || atr == NULL) {
        return WS_FATAL_ERROR;
    }

    if (f_stat(name, &info) != FR_OK) {
        return WS_FATAL_ERROR;
    }

    WMEMSET(atr, 0, sizeof(WS_SFTP_FILEATRB));

    atr->flags |= WOLFSSH_FILEATRB_SIZE;
    atr->sz[0]  = (word32)(info.fsize);
    atr->sz[1]  = (word32)(0);

    {
        byte atrib = info.fattrib;
        atr->flags |= WOLFSSH_FILEATRB_PERM;
        if (atrib & AM_DIR) {
            atr->per |= 0x41ED; /* 755 with directory */
        }
        else {
            atr->per |= 0x8000;
        }
        if ((atrib & AM_ARC) == AM_ARC) {
            atr->per |= 0x1ED; /* octal 755 */
        }
        if ((atrib & AM_RDO) || (atrib & AM_SYS)) {
            atr->per |= 0x124; /* octal 444 */
        }
    }

#ifndef NO_WOLFSSH_MKTIME
    /* get file times */
    atr->flags |= WOLFSSH_FILEATRB_TIME;
    atr->atime = info.ftime;
    atr->mtime = info.ftime;
#endif /* NO_WOLFSSH_MKTIME */

    WOLFSSH_UNUSED(ssh);
    WOLFSSH_UNUSED(handleSz);
    return WS_SUCCESS;
}

#elif defined(WOLFSSH_ZEPHYR)

static int PopulateAttributes(WS_SFTP_FILEATRB* atr, WSTAT_T* stats)
{
    WMEMSET(atr, 0, sizeof(WS_SFTP_FILEATRB));

    atr->flags |= WOLFSSH_FILEATRB_SIZE;
    atr->sz[0] = (word32)(stats->size & 0xFFFFFFFF);

    atr->flags |= WOLFSSH_FILEATRB_PERM;
    /* Default perms */
    atr->per = 0755;
    /* Mimic S_IFMT */
    if (stats->type == FS_DIR_ENTRY_FILE)
        atr->per |= FILEATRB_PER_FILE;
    else if (stats->type == FS_DIR_ENTRY_DIR)
        atr->per |= FILEATRB_PER_DIR;
    else
        return WS_BAD_FILE_E;

    return WS_SUCCESS;
}

int SFTP_GetAttributes(void* fs, const char* fileName, WS_SFTP_FILEATRB* atr,
        byte noFollow, void* heap)
{
    WSTAT_T stats;

    WOLFSSH_UNUSED(heap);
    WOLFSSH_UNUSED(noFollow);

    if (WSTAT(fs, fileName, &stats) != 0) {
        return WS_BAD_FILE_E;
    }

    return PopulateAttributes(atr, &stats);
}

int SFTP_GetAttributes_Handle(WOLFSSH* ssh, byte* handle, int handleSz,
        char* name, WS_SFTP_FILEATRB* atr)
{
    WOLFSSH_UNUSED(ssh);
    WOLFSSH_UNUSED(handle);
    WOLFSSH_UNUSED(handleSz);
    WOLFSSH_UNUSED(atr);
    WOLFSSH_UNUSED(name);

    WLOG(WS_LOG_SFTP, "SFTP_GetAttributes_Handle() not implemented yet");
    return WS_NOT_COMPILED;
}

#elif defined(MICROCHIP_MPLAB_HARMONY)
int SFTP_GetAttributesStat(WS_SFTP_FILEATRB* atr, WSTAT_T* stats)
{
    /* file size */
    atr->flags |= WOLFSSH_FILEATRB_SIZE;
    atr->sz[0] = (word32)stats->fsize;
    atr->sz[1] = (word32)(0);

    /* file permissions */
    atr->flags |= WOLFSSH_FILEATRB_PERM;
    if ((stats->fattrib & SYS_FS_ATTR_DIR) & SYS_FS_ATTR_MASK) {
        atr->per |= 0x41ED; /* 755 with directory */
    }
    else {
        atr->per |= 0x8000;
    }

    /* check for read only */
    if ((stats->fattrib & SYS_FS_ATTR_RDO) & SYS_FS_ATTR_MASK) {
        atr->per |= 0x124; /* octal 444 */
    }
    else {
        atr->per |= 0x1ED; /* octal 755 */
    }

    /* last modified time */
    atr->mtime = stats->ftime;

    return WS_SUCCESS;
}


static int SFTP_GetAttributesHelper(WS_SFTP_FILEATRB* atr, const char* fName)
{
    WSTAT_T stats;
    SYS_FS_RESULT res;
    char buffer[255];

    WMEMSET(atr, 0, sizeof(WS_SFTP_FILEATRB));
    WMEMSET(buffer, 0, sizeof(buffer));
    res = SYS_FS_CurrentDriveGet(buffer);
    if (res == SYS_FS_RES_SUCCESS) {
        if (WSTRCMP(fName, buffer) == 0) {
            atr->flags |= WOLFSSH_FILEATRB_PERM;
            atr->per |= 0x41ED; /* 755 with directory */
            atr->per |= 0x1ED;  /* octal 755 */

            atr->flags |= WOLFSSH_FILEATRB_SIZE;
            atr->sz[0] = 0;
            atr->sz[1] = 0;

            atr->mtime = 30912;
            WLOG(WS_LOG_SFTP, "Setting mount point as directory");
            return WS_SUCCESS;
        }
    }

    if (WSTAT(ssh->fs, fName, &stats) != 0) {
        WLOG(WS_LOG_SFTP, "Issue with WSTAT call");
        return WS_BAD_FILE_E;
    }
    return SFTP_GetAttributesStat(atr, &stats);
}


/* @TODO can be overriden by user for portability
 * NOTE: if atr->flags is set to a value of 0 then no attributes are set.
 * Fills out a WS_SFTP_FILEATRB structure
 * returns WS_SUCCESS on success
 */
int SFTP_GetAttributes(void* fs, const char* fileName, WS_SFTP_FILEATRB* atr,
        byte noFollow, void* heap)
{
    WOLFSSH_UNUSED(heap);
    WOLFSSH_UNUSED(fs);

    return SFTP_GetAttributesHelper(atr, fileName);
}


/* @TODO can be overriden by user for portability
 * Gets attributes based on file descriptor
 * NOTE: if atr->flags is set to a value of 0 then no attributes are set.
 * Fills out a WS_SFTP_FILEATRB structure
 * returns WS_SUCCESS on success
 */
int SFTP_GetAttributes_Handle(WOLFSSH* ssh, byte* handle, int handleSz,
        char* name, WS_SFTP_FILEATRB* atr)
{
    return SFTP_GetAttributesHelper(atr, cur->name);
}

#else

/* NOTE: if atr->flags is set to a value of 0 then no attributes are set.
 * Fills out a WS_SFTP_FILEATRB structure
 * returns WS_SUCCESS on success
 */
int SFTP_GetAttributes(void* fs, const char* fileName, WS_SFTP_FILEATRB* atr,
        byte noFollow, void* heap)
{
    WSTAT_T stats;

    WOLFSSH_UNUSED(heap);
    WOLFSSH_UNUSED(fs);

    if (noFollow) {
        /* Note, for windows, we treat WSTAT and WLSTAT the same. */
        if (WLSTAT(fs, fileName, &stats) != 0) {
            return WS_BAD_FILE_E;
        }
    }
    else {
        if (WSTAT(fs, fileName, &stats) != 0) {
            return WS_BAD_FILE_E;
        }
    }

    WMEMSET(atr, 0, sizeof(WS_SFTP_FILEATRB));

    atr->flags |= WOLFSSH_FILEATRB_SIZE;
    atr->sz[0] = (word32)(stats.st_size & 0xFFFFFFFF);
#if SIZEOF_OFF_T == 8
    atr->sz[1] = (word32)((stats.st_size >> 32) & 0xFFFFFFFF);
#endif

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
        char* name, WS_SFTP_FILEATRB* atr)
{
    struct stat stats;

    if (handleSz != sizeof(word32)) {
        WLOG(WS_LOG_SFTP, "Unexpected handle size SFTP_GetAttributes_Handle()");
    }

    if (WFSTAT(ssh->fs, *(int*)handle, &stats) != 0) {
            return WS_BAD_FILE_E;
    }

    WMEMSET(atr, 0, sizeof(WS_SFTP_FILEATRB));

    atr->flags |= WOLFSSH_FILEATRB_SIZE;
    atr->sz[0] = (word32)(stats.st_size & 0xFFFFFFFF);
#if SIZEOF_OFF_T == 8
    atr->sz[1] = (word32)((stats.st_size >> 32) & 0xFFFFFFFF);
#endif

    atr->flags |= WOLFSSH_FILEATRB_UIDGID;
    atr->uid = (word32)stats.st_uid;
    atr->gid = (word32)stats.st_gid;

    atr->flags |= WOLFSSH_FILEATRB_PERM;
    atr->per = (word32)stats.st_mode;

    atr->flags |= WOLFSSH_FILEATRB_TIME;
    atr->atime = (word32)stats.st_atime;
    atr->mtime = (word32)stats.st_mtime;

    /* @TODO handle attribute extensions */

    WOLFSSH_UNUSED(ssh);
    WOLFSSH_UNUSED(name);
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
    word32 sz = 0;
    byte*  handle;
    word32 idx = 0;
    int ret = WS_SUCCESS;
    char* name = NULL;

    byte*  out   = NULL;
    word32 outSz = 0;

    if (ssh == NULL) {
        return WS_BAD_ARGUMENT;
    }

    WLOG(WS_LOG_SFTP, "Receiving WOLFSSH_FTP_FSTAT");

    if (maxSz < UINT32_SZ) {
        /* not enough for an ato32 call */
        return WS_BUFFER_E;
    }

    ato32(data + idx, &handleSz); idx += UINT32_SZ;
    if (handleSz + idx > maxSz) {
        return WS_BUFFER_E;
    }
    handle = data + idx;

#ifdef WOLFSSH_STOREHANDLE
    if (handleSz != sizeof(word32)) {
        WLOG(WS_LOG_SFTP, "Unexpected handle size for stored handles");
    }
    else {
        WS_HANDLE_LIST* cur;

        cur = SFTP_GetHandleNode(ssh, handle, handleSz);

        if (cur == NULL) {
            WLOG(WS_LOG_SFTP, "Unknown handle");
            return WS_BAD_FILE_E;
        }
        name = cur->name;
    }
#endif

    /* try to get file attributes and send back to client */
    WMEMSET((byte*)&atr, 0, sizeof(WS_SFTP_FILEATRB));
    if (SFTP_GetAttributes_Handle(ssh, handle, handleSz, name, &atr)
            != WS_SUCCESS) {
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
        if (SFTP_SetHeader(ssh, reqId, WOLFSSH_FTP_ATTRS, sz, out)
                != WS_SUCCESS) {
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

    /* set send out buffer, "out" is taken by ssh  */
    wolfSSH_SFTP_RecvSetSend(ssh, out, outSz);
    return ret;
}
#endif


/* Handles receiving stat packet
 * returns WS_SUCCESS on success
 */
int wolfSSH_SFTP_RecvSTAT(WOLFSSH* ssh, int reqId, byte* data, word32 maxSz)
{
    WS_SFTP_FILEATRB atr;
    char  name[WOLFSSH_MAX_FILENAME];
    int   ret = WS_SUCCESS;

    word32 sz;
    word32 idx = 0;

    byte*  out = NULL;
    word32 outSz = 0;

    if (ssh == NULL) {
        return WS_BAD_ARGUMENT;
    }

    WLOG(WS_LOG_SFTP, "Receiving WOLFSSH_FTP_STAT");

    if (maxSz < UINT32_SZ) {
        /* not enough for an ato32 call */
        return WS_BUFFER_E;
    }

    ato32(data + idx, &sz); idx += UINT32_SZ;
    if (sz > maxSz - idx) {
        return WS_BUFFER_E;
    }

    /* try to get file attributes and send back to client */
    if (GetAndCleanPath(ssh->sftpDefaultPath,
                data + idx, sz, name, sizeof(name)) < 0) {
        if (wolfSSH_SFTP_CreateStatus(ssh, WOLFSSH_FTP_FAILURE, reqId,
                "STAT error", "English", NULL, &outSz) != WS_SIZE_ONLY) {
            return WS_FATAL_ERROR;
        }
        ret = WS_FATAL_ERROR;
    }

    if (ret == WS_SUCCESS) {
        WMEMSET((byte*)&atr, 0, sizeof(WS_SFTP_FILEATRB));
        if (SFTP_GetAttributes(ssh->fs, name, &atr, 0, ssh->ctx->heap)
            != WS_SUCCESS) {
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
    }

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
        if (SFTP_SetHeader(ssh, reqId, WOLFSSH_FTP_ATTRS, sz, out)
                != WS_SUCCESS) {
            WFREE(out, ssh->ctx->heap, DYNTYPE_BUFFER);
            return WS_FATAL_ERROR;
        }
        SFTP_SetAttributes(ssh, out + WOLFSSH_SFTP_HEADER, sz, &atr);
    }

    /* set send out buffer, "out" is taken by ssh  */
    wolfSSH_SFTP_RecvSetSend(ssh, out, outSz);
    return ret;
}


/* Handles receiving lstat packet
 * returns WS_SUCCESS on success
 */
int wolfSSH_SFTP_RecvLSTAT(WOLFSSH* ssh, int reqId, byte* data, word32 maxSz)
{
    WS_SFTP_FILEATRB atr;
    char  name[WOLFSSH_MAX_FILENAME];
    int   ret = WS_SUCCESS;

    word32 sz;
    word32 idx = 0;

    byte*  out = NULL;
    word32 outSz = 0;

    if (ssh == NULL) {
        return WS_BAD_ARGUMENT;
    }

    WLOG(WS_LOG_SFTP, "Receiving WOLFSSH_FTP_LSTAT");
    if (maxSz < UINT32_SZ) {
        /* not enough for an ato32 call */
        return WS_BUFFER_E;
    }

    ato32(data + idx, &sz); idx += UINT32_SZ;
    if (sz > maxSz - idx) {
        return WS_BUFFER_E;
    }

    if (GetAndCleanPath(ssh->sftpDefaultPath,
                data + idx, sz, name, sizeof(name)) < 0) {
        WLOG(WS_LOG_SFTP, "Unable to clean path");
        if (wolfSSH_SFTP_CreateStatus(ssh, WOLFSSH_FTP_FAILURE, reqId,
                "LSTAT error", "English", NULL, &outSz) != WS_SIZE_ONLY) {
            return WS_FATAL_ERROR;
        }
        ret = WS_FATAL_ERROR;
    }

    /* try to get file attributes and send back to client */
    if (ret == WS_SUCCESS) {
        WMEMSET((byte*)&atr, 0, sizeof(WS_SFTP_FILEATRB));
        if ((ret = SFTP_GetAttributes(ssh->fs, name, &atr, 1, ssh->ctx->heap))
                != WS_SUCCESS) {
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
    }

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
        if (SFTP_SetHeader(ssh, reqId, WOLFSSH_FTP_ATTRS, sz, out)
                != WS_SUCCESS) {
            WFREE(out, ssh->ctx->heap, DYNTYPE_BUFFER);
            return WS_FATAL_ERROR;
        }
        SFTP_SetAttributes(ssh, out + WOLFSSH_SFTP_HEADER, sz, &atr);
    }

    /* set send out buffer, "out" is taken by ssh  */
    wolfSSH_SFTP_RecvSetSend(ssh, out, outSz);
    return ret;
}

#if !defined(USE_WINDOWS_API) && !defined(WOLFSSH_ZEPHYR) \
    && !defined(WOLFSSH_SFTP_SETMODE) && !defined(WOLFSSH_FATFS)
/* Set the files mode
 * return WS_SUCCESS on success */
static int SFTP_SetMode(void* fs, char* name, word32 mode) {
    WOLFSSH_UNUSED(fs);
    if (WCHMOD(fs, name, mode) != 0) {
        return WS_BAD_FILE_E;
    }
    return WS_SUCCESS;
}
#endif

#if !defined(USE_WINDOWS_API) && !defined(WOLFSSH_ZEPHYR) \
    && !defined(WOLFSSH_SFTP_SETMODEHANDLE) && !defined(WOLFSSH_FATFS)
/* Set the files mode
 * return WS_SUCCESS on success */
static int SFTP_SetModeHandle(void* fs, WFD handle, word32 mode) {
    WOLFSSH_UNUSED(fs);
    if (WFCHMOD(fs, handle, mode) != 0) {
        return WS_BAD_FILE_E;
    }
    return WS_SUCCESS;
}
#endif

#if !defined(_WIN32_WCE) && !defined(WOLFSSH_ZEPHYR) && !defined(WOLFSSH_FATFS)

/* sets a files attributes
 * returns WS_SUCCESS on success */
static int SFTP_SetFileAttributes(WOLFSSH* ssh,
        char* name, WS_SFTP_FILEATRB* atr)
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

#if !defined(USE_WINDOWS_API) && !defined(WOLFSSH_ZEPHYR)
    /* check if permissions attribute present */
    if (atr->flags & WOLFSSH_FILEATRB_PERM) {
        ret = SFTP_SetMode(ssh->fs, name, atr->per);
    }
#endif

    /* check if time attribute present */
    if (ret == WS_SUCCESS && (atr->flags & WOLFSSH_FILEATRB_TIME)) {
        if (WSETTIME(ssh->fs, name, atr->atime, atr->mtime) != 0) {
            ret = WS_BAD_FILE_E;
        }
    }

    /* check if extended attributes are present */
    if (atr->flags & WOLFSSH_FILEATRB_EXT) {
        /* @TODO handle extensions */
    }

    WOLFSSH_UNUSED(ssh);
    return ret ;
}


/* sets a files attributes
 * returns WS_SUCCESS on success */
static int SFTP_SetFileAttributesHandle(WOLFSSH* ssh,
        WFD handle, WS_SFTP_FILEATRB* atr)
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
        ret = SFTP_SetModeHandle(ssh->fs, handle, atr->per);
    }
#endif

    /* check if time attribute present */
    if (ret == WS_SUCCESS && (atr->flags & WOLFSSH_FILEATRB_TIME)) {
        if (WFSETTIME(ssh->fs, handle, atr->atime, atr->mtime) != 0) {
            ret = WS_BAD_FILE_E;
        }
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
    char  name[WOLFSSH_MAX_FILENAME];
    int   ret = WS_SUCCESS;

    word32 sz;
    word32 idx = 0;

    byte*  out = NULL;
    word32 outSz = 0;

    char  suc[] = "Set Attributes";
    char  ser[] = "Unable to set attributes error";
    char  per[] = "Unable to parse attributes error";
    char* res   = suc;
    byte  type  = WOLFSSH_FTP_OK;

    if (ssh == NULL) {
        return WS_BAD_ARGUMENT;
    }

    WLOG(WS_LOG_SFTP, "Receiving WOLFSSH_FTP_SETSTAT");

    if (maxSz < UINT32_SZ) {
        /* not enough for an ato32 call */
        return WS_BUFFER_E;
    }

    ato32(data + idx, &sz); idx += UINT32_SZ;
    if (sz > maxSz - idx) {
        return WS_BUFFER_E;
    }

    /* plus one to make sure is null terminated */
    if (GetAndCleanPath(ssh->sftpDefaultPath,
                data + idx, sz, name, sizeof(name)) < 0) {
        ret = WS_BUFFER_E;
    }
    idx += sz;

    if (ret == WS_SUCCESS &&
            SFTP_ParseAtributes_buffer(ssh, &atr, data, &idx, maxSz) != 0) {
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

    /* set send out buffer, "out" is taken by ssh  */
    wolfSSH_SFTP_RecvSetSend(ssh, out, outSz);
    return ret;
}


/* Handles a packet sent to set attributes of file handle
 *
 * returns WS_SUCCESS on success
 */
int wolfSSH_SFTP_RecvFSetSTAT(WOLFSSH* ssh, int reqId, byte* data, word32 maxSz)
{
    WS_SFTP_FILEATRB atr;
    int   ret = WS_SUCCESS;

    WFD    fd;
    word32 sz;
    word32 idx = 0;

    byte*  out = NULL;
    word32 outSz = 0;

    char  suc[] = "Set Attributes";
    char  ser[] = "Unable to set attributes error";
    char  per[] = "Unable to parse attributes error";
    char* res   = suc;
    byte  type  = WOLFSSH_FTP_OK;

    if (ssh == NULL) {
        return WS_BAD_ARGUMENT;
    }

    WLOG(WS_LOG_SFTP, "Receiving WOLFSSH_FTP_FSETSTAT");

    if (maxSz < UINT32_SZ) {
        /* not enough for an ato32 call */
        return WS_BUFFER_E;
    }

    /* get file handle */
    ato32(data + idx, &sz); idx += UINT32_SZ;
    if (sz + idx > maxSz || sz > WOLFSSH_MAX_HANDLE) {
        return WS_BUFFER_E;
    }
    WMEMSET((byte*)&fd, 0, sizeof(WFD));
    WMEMCPY((byte*)&fd, data + idx, sz); idx += sz;

    if (ret == WS_SUCCESS &&
            SFTP_ParseAtributes_buffer(ssh, &atr, data, &idx, maxSz) != 0) {
        type = WOLFSSH_FTP_FAILURE;
        res  = per;
        ret  = WS_BAD_FILE_E;
    }



    /* try to set file attributes and send status back to client */
    if (ret == WS_SUCCESS && (ret = SFTP_SetFileAttributesHandle(ssh, fd, &atr))
            != WS_SUCCESS) {
        /* tell peer that was not ok */
        WLOG(WS_LOG_SFTP, "Unable to get set attributes of open file");
        type = WOLFSSH_FTP_FAILURE;
        res  = ser;
        ret  = WS_BAD_FILE_E;
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

    /* set send out buffer, "out" is taken by ssh  */
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
    int  len, ret;
    byte id;
    word32 sz = 0;
    word32 version = 0;
    byte buf[LENGTH_SZ + MSG_ID_SZ + UINT32_SZ];

    switch (ssh->sftpState) {
        case SFTP_RECV:
            ret = wolfSSH_worker(ssh,NULL);
            if (ret != WS_CHAN_RXD) {
                return ret;
            }

            if ((len = wolfSSH_stream_read(ssh, buf, sizeof(buf)))
                    != sizeof(buf)) {
                /* @TODO partial read on small packet */
                return len;
            }

            if (SFTP_GetSz(buf, &sz,
                        MSG_ID_SZ + UINT32_SZ,
                        WOLFSSH_MAX_SFTP_RECV) != WS_SUCCESS) {
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
                if ((word32)len < ssh->sftpExtSz) {
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
            if (SFTP_ClientSendInit(ssh) != WS_SUCCESS) {
                return WS_FATAL_ERROR;
            }
            ssh->sftpState = SFTP_RECV;
            FALL_THROUGH;

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
                if (wolfSSH_SFTP_buffer_create(ssh, &state->buffer,
                        bufSz + WOLFSSH_SFTP_HEADER + UINT32_SZ) !=
                        WS_SUCCESS) {
                    wolfSSH_SFTP_ClearState(ssh, STATE_ID_SEND);
                    return WS_MEMORY_E;
                }

                if (SFTP_SetHeader(ssh, ssh->reqId, type, bufSz + UINT32_SZ,
                            wolfSSH_SFTP_buffer_data(&state->buffer))
                            != WS_SUCCESS) {
                    wolfSSH_SFTP_ClearState(ssh, STATE_ID_SEND);
                    return WS_FATAL_ERROR;
                }

                wolfSSH_SFTP_buffer_seek(&state->buffer, 0,WOLFSSH_SFTP_HEADER);
                wolfSSH_SFTP_buffer_c32toa(&state->buffer, bufSz);
                WMEMCPY(wolfSSH_SFTP_buffer_data(&state->buffer)
                        + wolfSSH_SFTP_buffer_idx(&state->buffer),
                        buf, bufSz);

                /* reset state for sending data */
                wolfSSH_SFTP_buffer_rewind(&state->buffer);
            }
            state->state = SFTP_SEND_PACKET;
            FALL_THROUGH;

        case SFTP_SEND_PACKET:
            /* send header and type specific state->data, looping over send
             * because channel could have restrictions on how much
             * state->data can be sent at one time */
            do {
                ret = wolfSSH_SFTP_buffer_send(ssh, &state->buffer);
            } while (ret > 0 &&
                    wolfSSH_SFTP_buffer_idx(&state->buffer) <
                    wolfSSH_SFTP_buffer_size(&state->buffer));

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
static int wolfSSH_SFTP_DoStatus(WOLFSSH* ssh, word32 reqId,
        WS_SFTP_BUFFER* buffer)
{
    word32 sz;
    word32 status = WOLFSSH_FTP_FAILURE;
    word32 localIdx = wolfSSH_SFTP_buffer_idx(buffer);
    word32 maxIdx = wolfSSH_SFTP_buffer_size(buffer);
    byte* buf = wolfSSH_SFTP_buffer_data(buffer);

    WOLFSSH_UNUSED(reqId);
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

        if (sz > maxIdx - localIdx) {
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

        if (sz > maxIdx - localIdx) {
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

    wolfSSH_SFTP_buffer_seek(buffer, 0, localIdx);
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


/* takes in the head of the list and free's all nodes in the list of sftp name
 * structures */
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
        if (localIdx + (2*UINT32_SZ) > maxIdx) {
            return WS_BUFFER_E;
        }
        ato32(buf + localIdx, &atr->sz[1]); localIdx += UINT32_SZ;
        ato32(buf + localIdx, &atr->sz[0]); localIdx += UINT32_SZ;
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
    WOLFSSH_UNUSED(ssh);
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
    word32 count, localIdx;
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
            maxSz = SFTP_GetHeader(ssh, &reqId, &type, &state->buffer);
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

            if (wolfSSH_SFTP_buffer_create(ssh, &state->buffer, maxSz) !=
                    WS_SUCCESS) {
                WLOG(WS_LOG_SFTP, "Could not malloc memory");
                wolfSSH_SFTP_ClearState(ssh, STATE_ID_NAME);
                return NULL;
            }
            FALL_THROUGH;

        case SFTP_NAME_DO_STATUS:
            if (state->state == SFTP_NAME_DO_STATUS) {
                ret = wolfSSH_SFTP_buffer_read(ssh, &state->buffer,
                        wolfSSH_SFTP_buffer_size(&state->buffer));
                if (ret < 0) {
                    if (ssh->error != WS_WANT_READ) {
                        wolfSSH_SFTP_ClearState(ssh, STATE_ID_NAME);
                    }
                    return NULL;
                }

                wolfSSH_SFTP_buffer_rewind(&state->buffer);
                wolfSSH_SFTP_DoStatus(ssh, reqId, &state->buffer);
                if (ssh->error != WS_WANT_READ) {
                    wolfSSH_SFTP_ClearState(ssh, STATE_ID_NAME);
                }
                return NULL;
            }
            FALL_THROUGH;


        case SFTP_NAME_GET_PACKET:
            /* get number of files */
            /* using idx as an offset for partial reads */
            ret = wolfSSH_SFTP_buffer_read(ssh, &state->buffer,
                    wolfSSH_SFTP_buffer_size(&state->buffer) -
                    wolfSSH_SFTP_buffer_idx(&state->buffer));
            if (ret <= 0) {
                if (ssh->error != WS_WANT_READ) {
                    wolfSSH_SFTP_ClearState(ssh, STATE_ID_NAME);
                }
                return NULL;
            }

            /* Reset idx back to 0 for parsing the buffer. */
            wolfSSH_SFTP_buffer_rewind(&state->buffer);
            if (wolfSSH_SFTP_buffer_ato32(&state->buffer, &count) !=
                    WS_SUCCESS) {
                ssh->error = WS_BUFFER_E;
                wolfSSH_SFTP_ClearState(ssh, STATE_ID_NAME);
                return NULL;
            }

            while (count > 0) {
                word32 sz;
                WS_SFTPNAME* tmp = wolfSSH_SFTPNAME_new(ssh->ctx->heap);

                count--;
                if (tmp == NULL) {
                    /* error case free list and exit */
                    WLOG(WS_LOG_SFTP,
                            "Memory error when creating new name structure");
                    ret = WS_MEMORY_E;
                    break;
                }

                /* push tmp onto front of name list */
                tmp->next = n;
                n = tmp;

                /* get filename size and name */
                if (wolfSSH_SFTP_buffer_ato32(&state->buffer, &sz) !=
                        WS_SUCCESS) {
                    ret = WS_BUFFER_E;
                    break;
                }
                tmp->fSz = sz;
                if (sz > 0) {
                    tmp->fName = (char*)WMALLOC(sz + 1,
                            tmp->heap, DYNTYPE_SFTP);
                    if (tmp->fName == NULL) {
                        ret = WS_MEMORY_E;
                        break;
                    }

                    if (wolfSSH_SFTP_buffer_idx(&state->buffer) + sz >
                            wolfSSH_SFTP_buffer_size(&state->buffer)) {
                        ret = WS_FATAL_ERROR;
                        break;
                    }
                    WMEMCPY(tmp->fName,
                            wolfSSH_SFTP_buffer_data(&state->buffer) +
                            wolfSSH_SFTP_buffer_idx(&state->buffer),
                            sz);
                    wolfSSH_SFTP_buffer_seek(&state->buffer,
                            wolfSSH_SFTP_buffer_idx(&state->buffer), sz);
                    tmp->fName[sz] = '\0';
                }

                /* get longname size and name */
                if (wolfSSH_SFTP_buffer_ato32(&state->buffer, &sz) !=
                        WS_SUCCESS) {
                    ret = WS_BUFFER_E;
                    break;
                }
                tmp->lSz   = sz;
                if (sz > 0) {
                    tmp->lName = (char*)WMALLOC(sz + 1,
                            tmp->heap, DYNTYPE_SFTP);
                    if (tmp->lName == NULL) {
                        ret = WS_MEMORY_E;
                        break;
                    }

                    if (wolfSSH_SFTP_buffer_idx(&state->buffer) + sz >
                            wolfSSH_SFTP_buffer_size(&state->buffer)) {
                        ret = WS_FATAL_ERROR;
                        break;
                    }
                    WMEMCPY(tmp->lName,
                            wolfSSH_SFTP_buffer_data(&state->buffer) +
                            wolfSSH_SFTP_buffer_idx(&state->buffer),
                            sz);
                    wolfSSH_SFTP_buffer_seek(&state->buffer,
                            wolfSSH_SFTP_buffer_idx(&state->buffer), sz);
                    tmp->lName[sz] = '\0';
                }

                /* get attributes */
                localIdx = wolfSSH_SFTP_buffer_idx(&state->buffer);
                ret = SFTP_ParseAtributes_buffer(ssh, &tmp->atrb,
                        wolfSSH_SFTP_buffer_data(&state->buffer),
                        &localIdx,
                        wolfSSH_SFTP_buffer_size(&state->buffer));
                wolfSSH_SFTP_buffer_seek(&state->buffer, 0, localIdx);
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

    WOLFSSH_UNUSED(maxSz);
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
    byte type = 0;
    word32 sz;

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
                ret = SFTP_GetHeader(ssh, &state->reqId, &type, &state->buffer);
                if (ret <= 0) {
                    if (NoticeError(ssh)) {
                        return WS_FATAL_ERROR;
                    }
                    else {
                        state->state = STATE_GET_HANDLE_CLEANUP;
                        ret = WS_FATAL_ERROR;
                        continue;
                    }
                }

                if (wolfSSH_SFTP_buffer_create(ssh, &state->buffer, ret) !=
                        WS_SUCCESS) {
                    state->state = STATE_GET_HANDLE_CLEANUP;
                    ret = WS_MEMORY_E;
                    continue;
                }

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

                ret = wolfSSH_SFTP_buffer_read(ssh, &state->buffer,
                        wolfSSH_SFTP_buffer_size(&state->buffer));
                if (ret < 0) {
                    WFREE(data, ssh->ctx->heap, DYNTYPE_BUFFER);
                    return WS_FATAL_ERROR;
                }

                wolfSSH_SFTP_buffer_rewind(&state->buffer);
                ret = wolfSSH_SFTP_DoStatus(ssh, state->reqId, &state->buffer);
                WFREE(data, ssh->ctx->heap, DYNTYPE_BUFFER);
                if (ret == WOLFSSH_FTP_OK)
                    ret = WS_SUCCESS;
                else {
                    *handleSz = 0; /* error getting handle */
                    ret = WS_SFTP_STATUS_NOT_OK;
                }
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

                state->state = STATE_GET_HANDLE_READ;
                FALL_THROUGH;

            case STATE_GET_HANDLE_READ:
                WLOG(WS_LOG_SFTP, "SFTP GET HANDLE STATE: READ");
                ret = wolfSSH_SFTP_buffer_read(ssh, &state->buffer,
                        wolfSSH_SFTP_buffer_size(&state->buffer));
                if (ret != (int)wolfSSH_SFTP_buffer_size(&state->buffer)) {
                    return WS_FATAL_ERROR;
                }
                ret = WS_SUCCESS;

                /* RFC specifies that handle size should not be larger than
                 * max size */
                wolfSSH_SFTP_buffer_rewind(&state->buffer);
                if (wolfSSH_SFTP_buffer_ato32(&state->buffer, &sz) != WS_SUCCESS
                       || sz > WOLFSSH_MAX_HANDLE || *handleSz < sz) {
                    WLOG(WS_LOG_SFTP, "Handle size found was too big");
                    WLOG(WS_LOG_SFTP, "Check size set in input handleSz");
                    ssh->error = WS_BUFFER_E;
                    ret = WS_FATAL_ERROR;
                    state->state = STATE_GET_HANDLE_CLEANUP;
                    continue;
                }
                *handleSz = sz;
                WMEMCPY(handle,
                        (wolfSSH_SFTP_buffer_data(&state->buffer) + UINT32_SZ),
                        *handleSz);
                state->state = STATE_GET_HANDLE_CLEANUP;
                FALL_THROUGH;

            case STATE_GET_HANDLE_CLEANUP:
                WLOG(WS_LOG_SFTP, "SFTP GET HANDLE STATE: CLEANUP");
                wolfSSH_SFTP_buffer_free(ssh, &state->buffer);
                if (ssh->getHandleState != NULL) {
                    WFREE(ssh->getHandleState,
                          ssh->ctx->heap, DYNTYPE_SFTP_STATE);
                    ssh->getHandleState = NULL;
                }
                return ret;

            default:
                WLOG(WS_LOG_SFTP, "Bad SFTP GetHandle state, program error");
                return WS_INPUT_CASE_E;
        }
    }
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
    WS_SFTPNAME* names = NULL;

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
                if (ssh->error != WS_WANT_READ
                        && ssh->error != WS_WANT_WRITE
                        && ssh->error != WS_REKEYING) {
                    wolfSSH_SFTP_ClearState(ssh, STATE_ID_LS);
                }
                return NULL;
            }
            state->state = STATE_LS_OPENDIR;
            FALL_THROUGH;

        case STATE_LS_OPENDIR:
            if (wolfSSH_SFTP_OpenDir(ssh, (byte*)state->name->fName,
                        state->name->fSz) != WS_SUCCESS) {
                WLOG(WS_LOG_SFTP, "Unable to open directory");
                if (ssh->error != WS_WANT_READ
                        && ssh->error != WS_WANT_WRITE
                        && ssh->error != WS_REKEYING) {
                    wolfSSH_SFTPNAME_list_free(state->name); state->name = NULL;
                    wolfSSH_SFTP_ClearState(ssh, STATE_ID_LS);
                }
                return NULL;
            }
            wolfSSH_SFTPNAME_list_free(state->name); state->name = NULL;
            state->sz    = WOLFSSH_MAX_HANDLE;
            state->state = STATE_LS_GETHANDLE;
            FALL_THROUGH;

        case STATE_LS_GETHANDLE:
            /* get the handle from opening the directory and read with it */
            if (wolfSSH_SFTP_GetHandle(ssh, state->handle, (word32*)&state->sz)
                    != WS_SUCCESS) {
                WLOG(WS_LOG_SFTP, "Unable to get handle");
                if (ssh->error != WS_WANT_READ
                        && ssh->error != WS_WANT_WRITE
                        && ssh->error != WS_REKEYING) {
                    wolfSSH_SFTP_ClearState(ssh, STATE_ID_LS);
                }
                return NULL;
            }
            state->state = STATE_LS_READDIR;
            FALL_THROUGH;

        case STATE_LS_READDIR:
            /* Now read the dir. Note in non-blocking we might get here multiple
             * times so we have to assign to state->name later. */
            names = wolfSSH_SFTP_ReadDir(ssh, state->handle, state->sz);
            if (names == NULL) {
                if (ssh->error == WS_WANT_READ
                        || ssh->error == WS_WANT_WRITE
                        || ssh->error == WS_REKEYING) {
                    return NULL;
                }
                WLOG(WS_LOG_SFTP, "Error reading directory");
                /* fall through because the handle should always be closed */
            }

            while (names != NULL) {
                if (state->name == NULL) {
                    state->name = names;
                }
                else {
                    WS_SFTPNAME* runner = NULL;
                    /* Got more entries so we append them. */
                    for (runner = state->name;
                         runner->next != NULL;
                         runner = runner->next);
                    runner->next = names;
                }
                names = wolfSSH_SFTP_ReadDir(ssh, state->handle, state->sz);
                if (names == NULL) {
                    if (ssh->error == WS_WANT_READ
                        || ssh->error == WS_WANT_WRITE
                        || ssh->error == WS_REKEYING) {
                        /* State does not change so we will get back to this
                         * case clause in non-blocking mode. */
                        return NULL;
                    }
                    WLOG(WS_LOG_SFTP, "Error reading directory");
                    /* fall through, the handle should always be closed */
                }
            }

            state->state = STATE_LS_CLOSE;
            FALL_THROUGH;

        case STATE_LS_CLOSE:
            /* close dir when finished */
            if (wolfSSH_SFTP_Close(ssh, state->handle, state->sz)
                    != WS_SUCCESS) {
                WLOG(WS_LOG_SFTP, "Error closing handle");
                if (ssh->error != WS_WANT_READ
                        && ssh->error != WS_WANT_WRITE
                        && ssh->error != WS_REKEYING) {
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
    struct WS_SFTP_CHMOD_STATE* state = NULL;
    int ret = WS_FATAL_ERROR;
    int mode;

    if (ssh == NULL || n == NULL || oct == NULL) {
        return WS_BAD_ARGUMENT;
    }

    state = ssh->chmodState;
    if (state == NULL) {
        state = (WS_SFTP_CHMOD_STATE*)WMALLOC(sizeof(WS_SFTP_CHMOD_STATE),
                ssh->ctx->heap, DYNTYPE_SFTP_STATE);
        if (state == NULL) {
            ssh->error = WS_MEMORY_E;
            return WS_FATAL_ERROR;
        }
        WMEMSET(state, 0, sizeof(WS_SFTP_CHMOD_STATE));
        ssh->chmodState = state;
        state->state = STATE_CHMOD_GET;
    }

    switch (state->state) {
        case STATE_CHMOD_GET:
            /* get current attributes of path */
            if ((ret = wolfSSH_SFTP_STAT(ssh, n, &state->atr)) != WS_SUCCESS) {
                if (ssh->error != WS_WANT_READ
                        && ssh->error != WS_WANT_WRITE) {
                    break;
                }
                return ret;
            }

            /* convert from octal to decimal */
            mode = wolfSSH_oct2dec(ssh, (byte*)oct, (word32)WSTRLEN(oct));
            if (mode < 0) {
                ret = WS_FATAL_ERROR;
                break;
            }

            /* update permissions */
            state->atr.per = mode;
            state->state = STATE_CHMOD_SEND;
            FALL_THROUGH;

        case STATE_CHMOD_SEND:
            ret = wolfSSH_SFTP_SetSTAT(ssh, n, &state->atr);
            if (ssh->error == WS_WANT_READ || ssh->error == WS_WANT_WRITE) {
                return ret;
            }
            break;


        default:
            WLOG(WS_LOG_SFTP, "Unknown CHMOD state");
    }
    wolfSSH_SFTP_ClearState(ssh, STATE_ID_CHMOD);
    return ret;
}


/* helper function for common code between LSTAT and STAT
 *
 * returns WS_SUCCESS on success
 */
static int SFTP_STAT(WOLFSSH* ssh, char* dir, WS_SFTP_FILEATRB* atr, byte type)
{
    WS_SFTP_LSTAT_STATE* state = NULL;
    int ret;
    int ret_fatal = 0;
    word32 localIdx;

    WLOG(WS_LOG_SFTP, "Entering SFTP_STAT()");
    if (ssh == NULL || dir == NULL)
        return WS_BAD_ARGUMENT;

    if (ssh->error == WS_WANT_READ || ssh->error == WS_WANT_WRITE)
        ssh->error = WS_SUCCESS;

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
                        ret_fatal = 1;
                        state->state = STATE_LSTAT_CLEANUP;
                        continue;
                    }
                }
                state->state = STATE_LSTAT_GET_HEADER;
                FALL_THROUGH;

            case STATE_LSTAT_GET_HEADER:
                WLOG(WS_LOG_SFTP, "SFTP LSTAT STATE: GET_HEADER");
                /* get attributes response */
                ret = SFTP_GetHeader(ssh, &state->reqId, &state->type,
                        &state->buffer);
                if (ret <= 0) {
                    if (ssh->error == WS_WANT_READ ||
                            ssh->error == WS_WANT_WRITE)
                        return WS_FATAL_ERROR;
                    else {
                        state->state = STATE_LSTAT_CLEANUP;
                        ret_fatal = 1;
                        continue;
                    }
                }

                state->state = STATE_LSTAT_CHECK_REQ_ID;
                if (wolfSSH_SFTP_buffer_create(ssh, &state->buffer, ret)
                        != WS_SUCCESS) {
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
                ret = wolfSSH_SFTP_buffer_read(ssh, &state->buffer,
                        wolfSSH_SFTP_buffer_size(&state->buffer));
                if (ret < 0) {
                    if (ssh->error != WS_WANT_READ) {
                        wolfSSH_SFTP_ClearState(ssh, STATE_ID_LSTAT);
                    }
                    return WS_FATAL_ERROR;
                }
                WLOG(WS_LOG_SFTP, "SFTP LSTAT STATE: PARSE_REPLY");

                /* after doing a 'read' the buffers index is now set to just
                 * after the data that has been read, rewind here to set the
                 * index to the beginning of data read and then process it */
                wolfSSH_SFTP_buffer_rewind(&state->buffer);
                if (state->type == WOLFSSH_FTP_ATTRS) {
                    localIdx = wolfSSH_SFTP_buffer_idx(&state->buffer);
                    ret = SFTP_ParseAtributes_buffer(ssh, atr,
                            wolfSSH_SFTP_buffer_data(&state->buffer),
                            &localIdx,
                            wolfSSH_SFTP_buffer_size(&state->buffer));
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
                    ret = wolfSSH_SFTP_DoStatus(ssh, state->reqId,
                            &state->buffer);
                    if (ret != WOLFSSH_FTP_OK) {
                        wolfSSH_SFTP_ClearState(ssh, STATE_ID_LSTAT);
                        if (ret == WOLFSSH_FTP_PERMISSION) {
                            return WS_PERMISSIONS;
                        }
                        return WS_SFTP_STATUS_NOT_OK;
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
                    wolfSSH_SFTP_buffer_free(ssh, &ssh->lstatState->buffer);
                    WFREE(ssh->lstatState, ssh->ctx->heap, DYNTYPE_SFTP_STATE);
                    ssh->lstatState = NULL;
                }
                if(ret_fatal)
                    return WS_FATAL_ERROR;
                else
                    return WS_SUCCESS;

            default:
                WLOG(WS_LOG_SFTP, "Bad SFTP LSTAT state, program error");
                return WS_INPUT_CASE_E;
        }
    }
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
    struct WS_SFTP_SETATR_STATE* state = NULL;
    int dirSz, atrSz, status;
    int maxSz, ret = WS_FATAL_ERROR;
    byte type;

    WLOG(WS_LOG_SFTP, "Entering wolfSSH_SFTP_SetSTAT()");
    if (ssh == NULL || dir == NULL || atr == NULL) {
        return WS_BAD_ARGUMENT;
    }

    state = ssh->setatrState;
    if (state == NULL) {
        state = (WS_SFTP_SETATR_STATE*)WMALLOC(sizeof(WS_SFTP_SETATR_STATE),
                ssh->ctx->heap, DYNTYPE_SFTP_STATE);
        if (state == NULL) {
            ssh->error = WS_MEMORY_E;
            return WS_FATAL_ERROR;
        }
        WMEMSET(state, 0, sizeof(WS_SFTP_SETATR_STATE));
        ssh->setatrState = state;
        state->state = STATE_SET_ATR_INIT;
    }


    switch (state->state) {
        case STATE_SET_ATR_INIT:
            dirSz = (int)WSTRLEN(dir);
            atrSz = SFTP_AtributesSz(ssh, atr);
            if (wolfSSH_SFTP_buffer_create(ssh, &state->buffer,
                        dirSz + atrSz + WOLFSSH_SFTP_HEADER + UINT32_SZ) !=
                    WS_SUCCESS) {
                ret = WS_MEMORY_E;
                break;
            }

            if (SFTP_SetHeader(ssh, ssh->reqId, WOLFSSH_FTP_SETSTAT, dirSz +
                        atrSz + UINT32_SZ,
                        wolfSSH_SFTP_buffer_data(&state->buffer)) !=
                    WS_SUCCESS) {
                ret =  WS_FATAL_ERROR;
                break;
            }

            wolfSSH_SFTP_buffer_seek(&state->buffer, 0, WOLFSSH_SFTP_HEADER);
            wolfSSH_SFTP_buffer_c32toa(&state->buffer, dirSz);
            WMEMCPY(wolfSSH_SFTP_buffer_data(&state->buffer) +
                    wolfSSH_SFTP_buffer_idx(&state->buffer),
                    (byte*)dir, dirSz);
            wolfSSH_SFTP_buffer_seek(&state->buffer,
                    wolfSSH_SFTP_buffer_idx(&state->buffer), dirSz);

            SFTP_SetAttributes(ssh,
                    wolfSSH_SFTP_buffer_data(&state->buffer) +
                    wolfSSH_SFTP_buffer_idx(&state->buffer), atrSz, atr);
            ret = wolfSSH_SFTP_buffer_set_size(&state->buffer,
                    wolfSSH_SFTP_buffer_idx(&state->buffer) + atrSz);
            if (ret != WS_SUCCESS) {
                ret = WS_FATAL_ERROR;
                break;
            }

            wolfSSH_SFTP_buffer_rewind(&state->buffer);
            state->state = STATE_SET_ATR_SEND;
            FALL_THROUGH;

        /* send header and type specific data */
        case STATE_SET_ATR_SEND:
            if (wolfSSH_SFTP_buffer_send(ssh, &state->buffer) < 0) {
                if (ssh->error != WS_WANT_READ
                        && ssh->error != WS_WANT_WRITE) {
                    ret = WS_FATAL_ERROR;
                    break;
                }
                return WS_FATAL_ERROR;
            }

            /* free up the buffer used to send data so that a new fresh buffer
             * can be created when next reading the attribute packet header */
            wolfSSH_SFTP_buffer_free(ssh, &state->buffer);
            state->state = STATE_SET_ATR_GET;
            FALL_THROUGH;


        case STATE_SET_ATR_GET:
            maxSz = SFTP_GetHeader(ssh, &state->reqId, &type, &state->buffer);
            if (maxSz <= 0) {
                if (ssh->error != WS_WANT_READ
                        && ssh->error != WS_WANT_WRITE) {
                    ret = WS_FATAL_ERROR;
                    break;
                }
                return WS_FATAL_ERROR;
            }

            if (type != WOLFSSH_FTP_STATUS) {
                WLOG(WS_LOG_SFTP, "Unexpected packet type %d", type);
                ret = WS_FATAL_ERROR;
                break;
            }

            if (wolfSSH_SFTP_buffer_create(ssh, &state->buffer, maxSz)
                    != WS_SUCCESS) {
                ret = WS_MEMORY_E;
                break;
            }

            state->state = STATE_SET_ATR_STATUS;
            FALL_THROUGH;


        case STATE_SET_ATR_STATUS:
            ret = wolfSSH_SFTP_buffer_read(ssh, &state->buffer,
                    wolfSSH_SFTP_buffer_size(&state->buffer));
            if (ret < 0) {
                if (ssh->error != WS_WANT_READ
                        && ssh->error != WS_WANT_WRITE) {
                    ret = WS_FATAL_ERROR;
                    break;
                }
                return ret;
            }
            wolfSSH_SFTP_buffer_rewind(&state->buffer);
            status = wolfSSH_SFTP_DoStatus(ssh, state->reqId, &state->buffer);
            ret    = WS_SUCCESS;
            if (status != WOLFSSH_FTP_OK) {
                ret = WS_BAD_FILE_E;
            }
            break;

        default:
            WLOG(WS_LOG_SFTP, "Unknown set attribute state");
    }

    wolfSSH_SFTP_ClearState(ssh, STATE_ID_SETATR);
    return ret;
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
    int sz;

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
                sz = (int)WSTRLEN(dir);
                if (wolfSSH_SFTP_buffer_create(ssh, &state->buffer, sz +
                            WOLFSSH_SFTP_HEADER + UINT32_SZ * 3) !=
                        WS_SUCCESS) {
                    ssh->error = WS_MEMORY_E;
                    ret = WS_FATAL_ERROR;
                    state->state = STATE_OPEN_CLEANUP;
                    continue;
                }

                ret = SFTP_SetHeader(ssh, ssh->reqId, WOLFSSH_FTP_OPEN,
                                     sz + UINT32_SZ * 3,
                                     wolfSSH_SFTP_buffer_data(&state->buffer));
                if (ret != WS_SUCCESS) {
                    state->state = STATE_OPEN_CLEANUP;
                    continue;
                }

                wolfSSH_SFTP_buffer_seek(&state->buffer, 0,
                        WOLFSSH_SFTP_HEADER);
                wolfSSH_SFTP_buffer_c32toa(&state->buffer, sz);
                WMEMCPY(wolfSSH_SFTP_buffer_data(&state->buffer) +
                    wolfSSH_SFTP_buffer_idx(&state->buffer),
                    (byte*)dir, sz);
                wolfSSH_SFTP_buffer_seek(&state->buffer,
                    wolfSSH_SFTP_buffer_idx(&state->buffer), sz);
                wolfSSH_SFTP_buffer_c32toa(&state->buffer, reason);

                /* @TODO handle adding attributes here */
                WOLFSSH_UNUSED(atr);
                wolfSSH_SFTP_buffer_c32toa(&state->buffer, 0x00000000);
                ret = wolfSSH_SFTP_buffer_set_size(&state->buffer,
                        wolfSSH_SFTP_buffer_idx(&state->buffer));
                if (ret != WS_SUCCESS) {
                    state->state = STATE_OPEN_CLEANUP;
                    continue;
                }
                wolfSSH_SFTP_buffer_rewind(&state->buffer);

                state->state = STATE_OPEN_SEND;
                FALL_THROUGH;

            case STATE_OPEN_SEND:
                WLOG(WS_LOG_SFTP, "SFTP OPEN STATE: SEND");
                /* send header and type specific data */
                ret = wolfSSH_SFTP_buffer_send(ssh, &state->buffer);
                if (ret < 0) {
                    if (ssh->error == WS_WANT_READ ||
                            ssh->error == WS_WANT_WRITE)
                        return WS_FATAL_ERROR;
                    else {
                        state->state = STATE_OPEN_CLEANUP;
                        continue;
                    }
                }
                wolfSSH_SFTP_buffer_free(ssh, &state->buffer);
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
                    wolfSSH_SFTP_buffer_free(ssh, &state->buffer);
                    WFREE(ssh->openState, ssh->ctx->heap, DYNTYPE_SFTP_STATE);
                    ssh->openState = NULL;
                }
                return ret;

            default:
                WLOG(WS_LOG_SFTP, "Bad SFTP Open state, program error");
                return WS_INPUT_CASE_E;
        }
    }
}


/* Writes data from buffer to the file handle
 *
 * handle   file handle given by sftp server
 * handleSz size of handle
 * ofst     offset to start reading at. 2 word32 array with value at ofst[0]
 *          being the lower and ofst[1] being the upper.
 * in       data to be written
 * inSz     amount of data to be written from "in" buffer
 *
 * returns the amount written on success
 */
int wolfSSH_SFTP_SendWritePacket(WOLFSSH* ssh, byte* handle, word32 handleSz,
        const word32* ofst, byte* in, word32 inSz)
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
                state->sentSzSave = 0;
                if (wolfSSH_SFTP_buffer_create(ssh, &state->buffer,
                        handleSz + WOLFSSH_SFTP_HEADER + UINT32_SZ * 4) !=
                        WS_SUCCESS) {
                    ssh->error = WS_MEMORY_E;
                    return WS_FATAL_ERROR;
                }

                ret = SFTP_SetHeader(ssh, ssh->reqId, WOLFSSH_FTP_WRITE,
                        handleSz + UINT32_SZ * 4 + inSz, state->buffer.data);
                if (ret != WS_SUCCESS) {
                    state->state = STATE_SEND_WRITE_CLEANUP;
                    continue;
                }

                wolfSSH_SFTP_buffer_seek(&state->buffer, 0,
                        WOLFSSH_SFTP_HEADER);
                wolfSSH_SFTP_buffer_c32toa(&state->buffer, handleSz);
                WMEMCPY(wolfSSH_SFTP_buffer_data(&state->buffer) +
                    wolfSSH_SFTP_buffer_idx(&state->buffer),
                    (byte*)handle, handleSz);
                wolfSSH_SFTP_buffer_seek(&state->buffer,
                    wolfSSH_SFTP_buffer_idx(&state->buffer), handleSz);

                /* offset to start reading from */
                wolfSSH_SFTP_buffer_c32toa(&state->buffer, ofst[1]);
                wolfSSH_SFTP_buffer_c32toa(&state->buffer, ofst[0]);

                /* buffer.data to be written */
                wolfSSH_SFTP_buffer_c32toa(&state->buffer, inSz);
                ret = wolfSSH_SFTP_buffer_set_size(&state->buffer,
                        wolfSSH_SFTP_buffer_idx(&state->buffer));
                if (ret != WS_SUCCESS) {
                    state->state = STATE_SEND_WRITE_CLEANUP;
                    continue;
                }
                wolfSSH_SFTP_buffer_rewind(&state->buffer);

                state->state = STATE_SEND_WRITE_SEND_HEADER;
                FALL_THROUGH;

            case STATE_SEND_WRITE_SEND_HEADER:
                WLOG(WS_LOG_SFTP, "SFTP SEND_WRITE STATE: SEND_HEADER");
                /* send header and type specific data */
                ret = wolfSSH_SFTP_buffer_send(ssh, &state->buffer);
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
                if (state->sentSz == WS_WINDOW_FULL ||
                        state->sentSz == WS_REKEYING ||
                        state->sentSz == WS_WANT_READ ||
                        state->sentSz == WS_WANT_WRITE) {
                    ret = wolfSSH_worker(ssh, NULL);
                    continue; /* skip past rest and send more */
                }
                if (state->sentSz <= 0) {
                    ssh->error = state->sentSz;
                    ret = WS_FATAL_ERROR;
                    state->state = STATE_SEND_WRITE_CLEANUP;
                    continue;
                }

                state->sentSzSave += state->sentSz;
                if (inSz > (word32)state->sentSz) {
                    in += state->sentSz;
                    inSz -= state->sentSz;
                    continue;
                }

                wolfSSH_SFTP_buffer_free(ssh, &state->buffer);
                state->state = STATE_SEND_WRITE_GET_HEADER;
                FALL_THROUGH;

            case STATE_SEND_WRITE_GET_HEADER:
                WLOG(WS_LOG_SFTP, "SFTP SEND_WRITE STATE: GET_HEADER");
                /* Get response */
                state->maxSz = SFTP_GetHeader(ssh, &state->reqId, &type,
                        &state->buffer);
                if (state->maxSz <= 0) {
                    if (ssh->error == WS_WANT_READ ||
                            ssh->error == WS_WANT_WRITE) {
                        return WS_FATAL_ERROR;
                    }
                    ssh->error = WS_SFTP_BAD_HEADER;
                    ret = WS_FATAL_ERROR;
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

                if (wolfSSH_SFTP_buffer_create(ssh, &state->buffer,
                            state->maxSz) != WS_SUCCESS) {
                    ssh->error = WS_MEMORY_E;
                    ret = WS_FATAL_ERROR;
                    state->state = STATE_SEND_WRITE_CLEANUP;
                    continue;
                }
                state->state = STATE_SEND_WRITE_READ_STATUS;
                FALL_THROUGH;

            case STATE_SEND_WRITE_READ_STATUS:
                WLOG(WS_LOG_SFTP, "SFTP SEND_WRITE STATE: READ_STATUS");
                ret = wolfSSH_SFTP_buffer_read(ssh, &state->buffer,
                        state->maxSz);
                if (ret <= 0) {
                    if (ssh->error == WS_WANT_READ ||
                            ssh->error == WS_WANT_WRITE) {
                        return WS_FATAL_ERROR;
                    }
                    state->state = STATE_SEND_WRITE_CLEANUP;
                    continue;
                }
                wolfSSH_SFTP_buffer_rewind(&state->buffer);
                state->state = STATE_SEND_WRITE_DO_STATUS;
                FALL_THROUGH;

            case STATE_SEND_WRITE_DO_STATUS:
                WLOG(WS_LOG_SFTP, "SFTP SEND_WRITE STATE: DO_STATUS");
                status = wolfSSH_SFTP_DoStatus(ssh,
                        state->reqId, &state->buffer);
                if (status < 0) {
                    ret = WS_FATAL_ERROR;
                }
                else if (status != WOLFSSH_FTP_OK) {
                    /* @TODO better error value description i.e permissions */
                    ret = WS_SFTP_STATUS_NOT_OK;
                }
                if (ret >= WS_SUCCESS)
                    ret = state->sentSzSave;
                state->state = STATE_SEND_WRITE_CLEANUP;
                FALL_THROUGH;

            case STATE_SEND_WRITE_CLEANUP:
                WLOG(WS_LOG_SFTP, "SFTP SEND_WRITE STATE: CLEANUP");
                if (ssh->sendWriteState != NULL) {
                    wolfSSH_SFTP_buffer_free(ssh, &state->buffer);
                    WFREE(ssh->sendWriteState,
                          ssh->ctx->heap, DYNTYPE_SFTP_STATE);
                    ssh->sendWriteState = NULL;
                }
                return ret;

            default:
                WLOG(WS_LOG_SFTP, "Bad SFTP Send Write Packet state, "
                                   "program error");
                ssh->error = WS_INPUT_CASE_E;
                return WS_FATAL_ERROR;
        }
    }
}


/* Reads data from file and places it in "out" buffer
 *
 * handle   file handle given by sftp server
 * handleSz size of handle
 * ofst     offset to start reading at. 2 word32 array with value at ofst[0]
 *          being the lower and ofst[1] being the upper.
 * out      buffer to hold resulting data read
 * outSz    size of "out" buffer
 *
 * returns the number of bytes read on success
 */
int wolfSSH_SFTP_SendReadPacket(WOLFSSH* ssh, byte* handle, word32 handleSz,
        const word32* ofst, byte* out, word32 outSz)
{
    WS_SFTP_SEND_READ_STATE* state = NULL;
    byte szFlat[UINT32_SZ];
    int ret = WS_SUCCESS;
    word32 sz;

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
                if (wolfSSH_SFTP_buffer_create(ssh, &state->buffer,
                    handleSz + WOLFSSH_SFTP_HEADER + UINT32_SZ * 4) !=
                        WS_SUCCESS) {
                    ssh->error = WS_MEMORY_E;
                    return WS_FATAL_ERROR;
                }

                ret = SFTP_SetHeader(ssh, ssh->reqId, WOLFSSH_FTP_READ,
                            handleSz + UINT32_SZ * 4,
                            wolfSSH_SFTP_buffer_data(&state->buffer));
                if (ret != WS_SUCCESS) {
                    state->state = STATE_SEND_READ_CLEANUP;
                    continue;
                }

                wolfSSH_SFTP_buffer_seek(&state->buffer, 0,
                        WOLFSSH_SFTP_HEADER);
                wolfSSH_SFTP_buffer_c32toa(&state->buffer, handleSz);
                WMEMCPY(wolfSSH_SFTP_buffer_data(&state->buffer) +
                    wolfSSH_SFTP_buffer_idx(&state->buffer),
                    (byte*)handle, handleSz);
                wolfSSH_SFTP_buffer_seek(&state->buffer,
                    wolfSSH_SFTP_buffer_idx(&state->buffer), handleSz);

                /* offset to start reading from */
                wolfSSH_SFTP_buffer_c32toa(&state->buffer, ofst[1]);
                wolfSSH_SFTP_buffer_c32toa(&state->buffer, ofst[0]);

                /* max length to read */
                wolfSSH_SFTP_buffer_c32toa(&state->buffer, outSz);
                ret = wolfSSH_SFTP_buffer_set_size(&state->buffer,
                        wolfSSH_SFTP_buffer_idx(&state->buffer));
                if (ret != WS_SUCCESS) {
                    state->state = STATE_SEND_READ_CLEANUP;
                    continue;
                }
                wolfSSH_SFTP_buffer_rewind(&state->buffer);

                state->state = STATE_SEND_READ_SEND_REQ;

                FALL_THROUGH;

            case STATE_SEND_READ_SEND_REQ:
                WLOG(WS_LOG_SFTP, "SFTP SEND_READ STATE: SEND_REQ");
                /* send header and type specific data */
                ret = wolfSSH_SFTP_buffer_send(ssh, &state->buffer);
                if (ret < 0) {
                    if (ret == WS_REKEYING) {
                        return ret;
                    }
                    if (ssh->error != WS_WANT_READ &&
                            ssh->error != WS_WANT_WRITE) {
                        state->state = STATE_SEND_READ_CLEANUP;
                        continue;
                    }
                    return ret;
                }
                wolfSSH_SFTP_buffer_free(ssh, &state->buffer);
                state->state = STATE_SEND_READ_GET_HEADER;
                FALL_THROUGH;

            case STATE_SEND_READ_GET_HEADER:
                WLOG(WS_LOG_SFTP, "SFTP SEND_READ STATE: GET_HEADER");
                /* Get response */
                if ((ret = SFTP_GetHeader(ssh, &state->reqId, &state->type,
                                &state->buffer)) <= 0) {
                    if (ssh->error != WS_WANT_READ &&
                            ssh->error != WS_WANT_WRITE) {
                        state->state = STATE_SEND_READ_CLEANUP;
                        continue;
                    }
                    return WS_FATAL_ERROR;
                }

                ret = wolfSSH_SFTP_buffer_create(ssh, &state->buffer, ret);
                if (ret != WS_SUCCESS) {
                    state->state = STATE_SEND_READ_CLEANUP;
                    continue;
                }
                state->state = STATE_SEND_READ_CHECK_REQ_ID;
                FALL_THROUGH;

            case STATE_SEND_READ_CHECK_REQ_ID:
                WLOG(WS_LOG_SFTP, "SFTP SEND_READ STATE: CHECK_REQ_ID");
                /* check request ID */
                if (state->reqId != ssh->reqId) {
                    WLOG(WS_LOG_SFTP, "Bad request ID received");
                    ret = WS_FATAL_ERROR;
                    state->state = STATE_SEND_READ_CLEANUP;
                    continue;
                }
                else
                    ssh->reqId++;

                if (state->type == WOLFSSH_FTP_DATA)
                    state->state = STATE_SEND_READ_FTP_DATA;
                else if (state->type == WOLFSSH_FTP_STATUS)
                    state->state = STATE_SEND_READ_FTP_STATUS;
                else {
                    WLOG(WS_LOG_SFTP, "Unexpected packet type");
                    ret = WS_FATAL_ERROR;
                    state->state = STATE_SEND_READ_CLEANUP;
                }
                continue;

            case STATE_SEND_READ_FTP_DATA:
                WLOG(WS_LOG_SFTP, "SFTP SEND_READ STATE: FTP_DATA");
                /* get size of string and place it into out buffer */
                ret = wolfSSH_stream_read(ssh, szFlat, UINT32_SZ);
                if (ret < 0) {
                    if (ssh->error != WS_WANT_READ &&
                            ssh->error != WS_WANT_WRITE) {
                        state->state = STATE_SEND_READ_CLEANUP;
                        continue;
                    }
                    return ret;
                }
                ato32(szFlat, &sz);
                wolfSSH_SFTP_buffer_create(ssh, &state->buffer, sz);
                if (wolfSSH_SFTP_buffer_size(&state->buffer) > outSz) {
                    WLOG(WS_LOG_SFTP, "Server sent more data then expected");
                    ret = WS_FATAL_ERROR;
                    state->state = STATE_SEND_READ_CLEANUP;
                    continue;
                }

                state->state = STATE_SEND_READ_REMAINDER;
                FALL_THROUGH;

            case STATE_SEND_READ_REMAINDER:
                WLOG(WS_LOG_SFTP, "SFTP SEND_READ STATE: READ_REMAINDER");
                do {
                    ret = wolfSSH_stream_read(ssh,
                            out + state->recvSz,
                            wolfSSH_SFTP_buffer_size(&state->buffer));
                    if (ret < 0) {
                        if (ssh->error == WS_WANT_READ ||
                                ssh->error == WS_WANT_WRITE) {
                            return WS_FATAL_ERROR;
                        }
                        WLOG(WS_LOG_SFTP, "Error reading remainder of data");
                        state->state = STATE_SEND_READ_CLEANUP;
                        break;
                    }

                    state->recvSz += ret;
                    wolfSSH_SFTP_buffer_set_size(&state->buffer,
                            wolfSSH_SFTP_buffer_size(&state->buffer) - ret);
                } while (wolfSSH_SFTP_buffer_size(&state->buffer) != 0);

                if (ret < 0) {
                    /* error state was hit in earlier loop, continue on to
                     * cleanup */
                    continue;
                }
                ret = state->recvSz;

                state->state = STATE_SEND_READ_CLEANUP;
                continue;

            case STATE_SEND_READ_FTP_STATUS:
                WLOG(WS_LOG_SFTP, "SFTP SEND_READ STATE: READ_FTP_STATUS");
                {
                    if (wolfSSH_SFTP_buffer_create(ssh, &state->buffer,
                                wolfSSH_SFTP_buffer_size(&state->buffer))
                            != 0) {
                        ret = WS_MEMORY_E;
                        state->state = STATE_SEND_READ_CLEANUP;
                        continue;
                    }

                    ret = wolfSSH_SFTP_buffer_read(ssh, &state->buffer,
                            wolfSSH_SFTP_buffer_size(&state->buffer));
                    if (ret < 0) {
                        if (ssh->error != WS_WANT_READ &&
                            ssh->error != WS_WANT_WRITE) {
                            state->state = STATE_SEND_READ_CLEANUP;
                            continue;
                        }
                        return WS_FATAL_ERROR;
                    }
                    wolfSSH_SFTP_buffer_rewind(&state->buffer);
                    ret = wolfSSH_SFTP_DoStatus(ssh,
                            state->reqId, &state->buffer);
                    wolfSSH_SFTP_buffer_free(ssh, &state->buffer);
                    if (ret == WOLFSSH_FTP_OK || ret == WOLFSSH_FTP_EOF) {
                        WLOG(WS_LOG_SFTP, "OK or EOF found");
                        ret = 0; /* nothing was read */
                    }
                    else {
                        ret = WS_FATAL_ERROR;
                    }
                }
                state->state = STATE_SEND_READ_CLEANUP;
                FALL_THROUGH;

            case STATE_SEND_READ_CLEANUP:
                WLOG(WS_LOG_SFTP, "SFTP SEND_READ STATE: CLEANUP");
                if (ssh->sendReadState != NULL) {
                    wolfSSH_SFTP_buffer_free(ssh, &state->buffer);
                    WFREE(ssh->sendReadState,
                          ssh->ctx->heap, DYNTYPE_SFTP_STATE);
                    ssh->sendReadState = NULL;
                }
                return ret;

            default:
                WLOG(WS_LOG_SFTP, "Bad SFTP Send Read Packet state, "
                                   "program error");
                ssh->error = WS_INPUT_CASE_E;
                return WS_FATAL_ERROR;
        }
    }
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
    byte type;

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
            if (wolfSSH_SFTP_buffer_size(&state->buffer) == 0) {
                /* packet not created yet */
                int sz = (int)WSTRLEN(dir);
                if (wolfSSH_SFTP_buffer_create(ssh, &state->buffer, sz +
                            WOLFSSH_SFTP_HEADER + UINT32_SZ * 3) != 0) {
                    return WS_MEMORY_E;
                }

                if (SFTP_SetHeader(ssh, ssh->reqId, WOLFSSH_FTP_MKDIR,
                    sz + UINT32_SZ * 3,
                    wolfSSH_SFTP_buffer_data(&state->buffer)) != WS_SUCCESS) {
                    return WS_FATAL_ERROR;
                }

                wolfSSH_SFTP_buffer_seek(&state->buffer, 0,
                        WOLFSSH_SFTP_HEADER);
                wolfSSH_SFTP_buffer_c32toa(&state->buffer, sz);
                WMEMCPY(wolfSSH_SFTP_buffer_data(&state->buffer) +
                    wolfSSH_SFTP_buffer_idx(&state->buffer),
                    (byte*)dir, sz);
                wolfSSH_SFTP_buffer_seek(&state->buffer,
                    wolfSSH_SFTP_buffer_idx(&state->buffer), sz);

                wolfSSH_SFTP_buffer_c32toa(&state->buffer, UINT32_SZ);

                /* @TODO handle setting attributes */
                WOLFSSH_UNUSED(atr);
                wolfSSH_SFTP_buffer_c32toa(&state->buffer, 0x000001FF);

                ret = wolfSSH_SFTP_buffer_set_size(&state->buffer,
                        wolfSSH_SFTP_buffer_idx(&state->buffer));
                if (ret != WS_SUCCESS) {
                    wolfSSH_SFTP_ClearState(ssh, STATE_ID_MKDIR);
                    return ret;
                }
                wolfSSH_SFTP_buffer_rewind(&state->buffer);
            }

            /* send header and type specific data */
            ret = wolfSSH_SFTP_buffer_send(ssh, &state->buffer);
            if (ret < 0) {
                if (ssh->error != WS_WANT_READ && ssh->error != WS_WANT_WRITE)
                    wolfSSH_SFTP_ClearState(ssh, STATE_ID_MKDIR);
                return ret;
            }

            /* free data pointer to reuse it later */
            wolfSSH_SFTP_buffer_free(ssh, &state->buffer);
            state->state = STATE_MKDIR_GET;
            FALL_THROUGH;

        case STATE_MKDIR_GET:
            /* Get response */
            if ((ret = SFTP_GetHeader(ssh, &state->reqId, &type,
                            &state->buffer)) <= 0) {
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
            if (state->reqId != ssh->reqId) {
                WLOG(WS_LOG_SFTP, "Bad request ID received");
                wolfSSH_SFTP_ClearState(ssh, STATE_ID_MKDIR);
                return WS_FATAL_ERROR;
            }
            else {
                ssh->reqId++;
            }

            if (wolfSSH_SFTP_buffer_create(ssh, &state->buffer, ret) != 0) {
                wolfSSH_SFTP_ClearState(ssh, STATE_ID_MKDIR);
                return WS_FATAL_ERROR;
            }
            state->state = STATE_MKDIR_STATUS;
            FALL_THROUGH;

        case STATE_MKDIR_STATUS:
            ret = wolfSSH_SFTP_buffer_read(ssh, &state->buffer,
                    wolfSSH_SFTP_buffer_size(&state->buffer));
            if (ret < 0) {
                if (ssh->error != WS_WANT_READ && ssh->error != WS_WANT_WRITE)
                    wolfSSH_SFTP_ClearState(ssh, STATE_ID_MKDIR);
                return WS_FATAL_ERROR;
            }

            wolfSSH_SFTP_buffer_rewind(&state->buffer);
            ret = wolfSSH_SFTP_DoStatus(ssh, state->reqId, &state->buffer);
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

        case STATE_READDIR_NAME:
            name = wolfSSH_SFTP_DoName(ssh);
            if (name == NULL) {
                if (ssh->error != WS_WANT_READ
                        && ssh->error != WS_WANT_WRITE) {
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
                if (NoticeError(ssh)) {
                    return WS_FATAL_ERROR;
                }

                if (ret != WS_SUCCESS) {
                    state->state = STATE_CLOSE_CLEANUP;
                    continue;
                }
                state->state = STATE_CLOSE_GET_HEADER;
                FALL_THROUGH;

            case STATE_CLOSE_GET_HEADER:
                WLOG(WS_LOG_SFTP, "SFTP CLOSE STATE: GET_HEADER");
                ret = SFTP_GetHeader(ssh, &state->reqId, &type, &state->buffer);
                if (ret <= 0 && NoticeError(ssh)) {
                    return WS_FATAL_ERROR;
                }

                if (type != WOLFSSH_FTP_STATUS || ret <= 0) {
                    WLOG(WS_LOG_SFTP, "Unexpected packet type");
                    ret = WS_FATAL_ERROR;
                    state->state = STATE_CLOSE_CLEANUP;
                    continue;
                }

                if (wolfSSH_SFTP_buffer_create(ssh, &state->buffer, ret) != 0) {
                    ret = WS_MEMORY_E;
                    state->state = STATE_CLOSE_CLEANUP;
                    continue;
                }
                state->state = STATE_CLOSE_DO_STATUS;
                FALL_THROUGH;

            case STATE_CLOSE_DO_STATUS:
                WLOG(WS_LOG_SFTP, "SFTP CLOSE STATE: DO_STATUS");
                ret = wolfSSH_SFTP_buffer_read(ssh, &state->buffer,
                        wolfSSH_SFTP_buffer_size(&state->buffer));
                if (ret < 0) {
                    if (ssh->error != WS_WANT_WRITE &&
                                ssh->error != WS_WANT_READ) {
                        wolfSSH_SFTP_buffer_free(ssh, &state->buffer);
                    }
                    return WS_FATAL_ERROR;
                }
                wolfSSH_SFTP_buffer_rewind(&state->buffer);
                ret = wolfSSH_SFTP_DoStatus(ssh, state->reqId, &state->buffer);
                wolfSSH_SFTP_buffer_free(ssh, &state->buffer);
                if (ret == WOLFSSH_FTP_OK)
                    ret = WS_SUCCESS;
                else
                    ret = WS_FATAL_ERROR;
                state->state = STATE_CLOSE_CLEANUP;
                FALL_THROUGH;

            case STATE_CLOSE_CLEANUP:
                WLOG(WS_LOG_SFTP, "SFTP CLOSE STATE: CLEANUP");
                if (ssh->closeState != NULL) {
                    wolfSSH_SFTP_buffer_free(ssh, &state->buffer);
                    WFREE(ssh->closeState, ssh->ctx->heap, DYNTYPE_SFTP_STATE);
                    ssh->closeState = NULL;
                }
                return ret;

            default:
                WLOG(WS_LOG_SFTP, "Bad SFTP Close state, program error");
                return WS_INPUT_CASE_E;
        }
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

        case SFTP_REAL_GET_PACKET:
            /* read name response from Real Path packet */
            ret = wolfSSH_SFTP_DoName(ssh);
            if (ret != NULL || (ret == NULL && !NoticeError(ssh))) {
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
    int ret = WS_SUCCESS, sz;
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

                sz = (int)(WSTRLEN(old) + WSTRLEN(nw));
                if (wolfSSH_SFTP_buffer_create(ssh, &state->buffer,
                        sz + WOLFSSH_SFTP_HEADER + UINT32_SZ * 2) != 0) {
                    ssh->error = WS_MEMORY_E;
                    ret = WS_FATAL_ERROR;
                    state->state = STATE_RENAME_CLEANUP;
                    continue;
                }

                ret = SFTP_SetHeader(ssh, ssh->reqId, WOLFSSH_FTP_RENAME,
                            sz + UINT32_SZ * 2,
                            wolfSSH_SFTP_buffer_data(&state->buffer));
                if (ret != WS_SUCCESS) {
                    state->state = STATE_RENAME_CLEANUP;
                    continue;
                }

                /* add old name to the packet */
                wolfSSH_SFTP_buffer_seek(&state->buffer, 0,
                        WOLFSSH_SFTP_HEADER);
                wolfSSH_SFTP_buffer_c32toa(&state->buffer,
                        (word32)WSTRLEN(old));
                WMEMCPY(wolfSSH_SFTP_buffer_data(&state->buffer) +
                    wolfSSH_SFTP_buffer_idx(&state->buffer),
                    (byte*)old, WSTRLEN(old));
                wolfSSH_SFTP_buffer_seek(&state->buffer,
                    wolfSSH_SFTP_buffer_idx(&state->buffer),
                    (word32)WSTRLEN(old));

                /* add new name to the packet */
                wolfSSH_SFTP_buffer_c32toa(&state->buffer,
                        (word32)WSTRLEN(nw));
                WMEMCPY(wolfSSH_SFTP_buffer_data(&state->buffer) +
                    wolfSSH_SFTP_buffer_idx(&state->buffer),
                    (byte*)nw, WSTRLEN(nw));
                wolfSSH_SFTP_buffer_seek(&state->buffer,
                    wolfSSH_SFTP_buffer_idx(&state->buffer),
                    (word32)WSTRLEN(nw));

                /* reset size and rewind */
                ret = wolfSSH_SFTP_buffer_set_size(&state->buffer,
                        wolfSSH_SFTP_buffer_idx(&state->buffer));
                if (ret != WS_SUCCESS) {
                    state->state = STATE_RENAME_CLEANUP;
                    continue;
                }
                wolfSSH_SFTP_buffer_rewind(&state->buffer);

                state->state = STATE_RENAME_SEND;
                FALL_THROUGH;

            case STATE_RENAME_SEND:
                WLOG(WS_LOG_SFTP, "SFTP RENAME STATE: SEND");
                /* send header and type specific data */
                ret = wolfSSH_SFTP_buffer_send(ssh, &state->buffer);
                if (ret <= 0) {
                    if (ssh->error == WS_WANT_READ ||
                            ssh->error == WS_WANT_WRITE) {
                        return WS_FATAL_ERROR;
                    }
                    state->state = STATE_RENAME_CLEANUP;
                    continue;
                }
                wolfSSH_SFTP_buffer_free(ssh, &state->buffer);
                state->state = STATE_RENAME_GET_HEADER;
                FALL_THROUGH;

            case STATE_RENAME_GET_HEADER:
                WLOG(WS_LOG_SFTP, "SFTP RENAME STATE: GET_HEADER");
                /* Get response */
                ret = SFTP_GetHeader(ssh, &state->reqId,
                        &type, &state->buffer);
                if (ret <= 0) {
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

                if (wolfSSH_SFTP_buffer_create(ssh, &state->buffer, ret) != 0) {
                    ssh->error = WS_MEMORY_E;
                    ret = WS_FATAL_ERROR;
                    state->state = STATE_RENAME_CLEANUP;
                    continue;
                }
                state->state = STATE_RENAME_READ_STATUS;
                FALL_THROUGH;

            case STATE_RENAME_READ_STATUS:
                WLOG(WS_LOG_SFTP, "SFTP RENAME STATE: READ_STATUS");
                ret = wolfSSH_SFTP_buffer_read(ssh, &state->buffer,
                        wolfSSH_SFTP_buffer_size(&state->buffer));
                if (ret <= 0) {
                    if (ssh->error == WS_WANT_READ ||
                            ssh->error == WS_WANT_WRITE) {
                        return WS_FATAL_ERROR;
                    }
                    state->state = STATE_RENAME_CLEANUP;
                    continue;
                }
                wolfSSH_SFTP_buffer_rewind(&state->buffer);
                state->state = STATE_RENAME_DO_STATUS;
                FALL_THROUGH;

            case STATE_RENAME_DO_STATUS:
                WLOG(WS_LOG_SFTP, "SFTP RENAME STATE: DO_STATUS");
                ret = wolfSSH_SFTP_DoStatus(ssh, state->reqId, &state->buffer);
                WLOG(WS_LOG_SFTP, "Status = %d", ret);
                if (ret < 0) {
                    ret = WS_FATAL_ERROR;
                }
                else if (ret == WOLFSSH_FTP_PERMISSION) {
                    ssh->error = WS_PERMISSIONS;
                    ret = WS_FATAL_ERROR;
                }
                else if (ret != WOLFSSH_FTP_OK) {
                    ret = WS_SFTP_STATUS_NOT_OK;
                }
                state->state = STATE_RENAME_CLEANUP;
                FALL_THROUGH;

            case STATE_RENAME_CLEANUP:
                WLOG(WS_LOG_SFTP, "SFTP RENAME STATE: CLEANUP");
                if (ssh->renameState != NULL) {
                    wolfSSH_SFTP_buffer_free(ssh, &state->buffer);
                    WFREE(ssh->renameState, ssh->ctx->heap, DYNTYPE_SFTP_STATE);
                    ssh->renameState = NULL;
                }
                return ret;

            default:
                WLOG(WS_LOG_SFTP, "Bad SFTP Rename state, program error");
                ssh->error = WS_INPUT_CASE_E;
                return WS_FATAL_ERROR;
        }
    }
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
                if (ssh->error != WS_WANT_WRITE
                        && ssh->error != WS_WANT_READ) {
                    WLOG(WS_LOG_SFTP, "Error verifying file");
                    wolfSSH_SFTP_ClearState(ssh, STATE_ID_RM);
                }
                return ret;
            }
            state->state = STATE_RM_SEND;
            FALL_THROUGH;

        case STATE_RM_SEND:
            ret = SendPacketType(ssh, WOLFSSH_FTP_REMOVE, (byte*)f,
                    (word32)WSTRLEN(f));
            if (ret != WS_SUCCESS) {
                if (ssh->error != WS_WANT_WRITE
                        && ssh->error != WS_WANT_READ) {
                    wolfSSH_SFTP_ClearState(ssh, STATE_ID_RM);
                }
                return ret;
            }
            state->state = STATE_RM_GET;
            FALL_THROUGH;

        case STATE_RM_GET:
            ret = SFTP_GetHeader(ssh, &state->reqId, &type, &state->buffer);
            if (ret <= 0 || type != WOLFSSH_FTP_STATUS) {
                if (ssh->error != WS_WANT_WRITE
                        && ssh->error != WS_WANT_READ) {
                    WLOG(WS_LOG_SFTP, "Unexpected packet type");
                    wolfSSH_SFTP_ClearState(ssh, STATE_ID_RM);
                }
                return WS_FATAL_ERROR;
            }

            if (wolfSSH_SFTP_buffer_create(ssh, &state->buffer, ret) != 0) {
                wolfSSH_SFTP_ClearState(ssh, STATE_ID_RM);
                return WS_FATAL_ERROR;
            }
            state->state = STATE_RM_DOSTATUS;
            FALL_THROUGH;

       case STATE_RM_DOSTATUS:
            ret = wolfSSH_SFTP_buffer_read(ssh, &state->buffer,
                    wolfSSH_SFTP_buffer_size(&state->buffer));
            if (ret < 0) {
                if (ssh->error != WS_WANT_WRITE
                        && ssh->error != WS_WANT_READ) {
                    WLOG(WS_LOG_SFTP, "Unexpected packet type");
                    wolfSSH_SFTP_ClearState(ssh, STATE_ID_RM);
                }
                return WS_FATAL_ERROR;
            }

            wolfSSH_SFTP_buffer_rewind(&state->buffer);
            ret = wolfSSH_SFTP_DoStatus(ssh, state->reqId, &state->buffer);
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
    byte   type;

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
                if (ssh->error != WS_WANT_READ
                        && ssh->error != WS_WANT_WRITE) {
                    wolfSSH_SFTP_ClearState(ssh, STATE_ID_RMDIR);
                }
                return ret;
            }
            state->state = STATE_RMDIR_GET;
            FALL_THROUGH;

        case STATE_RMDIR_GET:
            ret = SFTP_GetHeader(ssh, &state->reqId, &type, &state->buffer);
            if (ret <= 0 || type != WOLFSSH_FTP_STATUS) {
                if (ssh->error != WS_WANT_READ) {
                    wolfSSH_SFTP_ClearState(ssh, STATE_ID_RMDIR);
                    WLOG(WS_LOG_SFTP, "Unexpected packet type");
                }
                return WS_FATAL_ERROR;
            }
            if (wolfSSH_SFTP_buffer_create(ssh, &state->buffer, ret) != 0) {
                wolfSSH_SFTP_ClearState(ssh, STATE_ID_RMDIR);
                return WS_MEMORY_E;
            }
            state->state = STATE_RMDIR_STATUS;
            FALL_THROUGH;

        case STATE_RMDIR_STATUS:
            ret = wolfSSH_SFTP_buffer_read(ssh, &state->buffer,
                    wolfSSH_SFTP_buffer_size(&state->buffer));
            if (ret < 0) {
                if (ssh->error != WS_WANT_READ)
                    wolfSSH_SFTP_ClearState(ssh, STATE_ID_RMDIR);
                return WS_FATAL_ERROR;
            }

            wolfSSH_SFTP_buffer_rewind(&state->buffer);
            ret = wolfSSH_SFTP_DoStatus(ssh, state->reqId, &state->buffer);
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
 * ofst     offset into file that should be saved. 2 word32 array with value at
 *          ofst[0] being the lower and ofst[1] being the upper.
 *
 * return WS_SUCCESS on success
 */
int wolfSSH_SFTP_SaveOfst(WOLFSSH* ssh, char* frm, char* to, const word32* ofst)
{
    int idx;
    SFTP_OFST* current;
    int frmSz, toSz;

    if (ssh == NULL || frm == NULL || to == NULL || ofst == NULL) {
        return WS_BAD_ARGUMENT;
    }

    frmSz = (int)WSTRLEN(frm);
    toSz = (int)WSTRLEN(to);

    /* find if able to save */
    for (idx = 0; idx < WOLFSSH_MAX_SFTPOFST; idx++) {
        if (!ssh->sftpOfst[idx].offset[0] && !ssh->sftpOfst[idx].offset[1]) {
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
    current->offset[0] = ofst[0];
    current->offset[1] = ofst[1];

    return WS_SUCCESS;
}


/* Compares the from and to name to stored values and if a match is found the
 * stored offset is returned.
 *
 * frm      NULL terminated string holding the from name
 * to       NULL terminated string holding the to name
 * ofst     put the offset here, set to zero then updated. 2 word32 array with
 *          value at ofst[0] being the lower and ofst[1] being the upper.
 *
 * returns WS_SUCCESS is returned
 */
int wolfSSH_SFTP_GetOfst(WOLFSSH* ssh, char* frm, char* to, word32* ofst)
{
    int    idx;
    int frmSz, toSz;

    if (ssh == NULL || frm == NULL || to == NULL || ofst == NULL) {
        return WS_BAD_ARGUMENT;
    }

    ofst[0] = 0;
    ofst[1] = 0;

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
                ofst[0] = ssh->sftpOfst[idx].offset[0];
                ofst[1] = ssh->sftpOfst[idx].offset[1];
                /* clear offset */
                WMEMSET(&ssh->sftpOfst[idx], 0, sizeof(SFTP_OFST));
                break;
            }
        }
    }

    return WS_SUCCESS;
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
 * returns WS_FATAL_ERROR on low level error or SSH level error
 *                        call wolfSSH_get_error(ssh) to try to get SSH error
 * other reuturn values are error states during the SFTP get process
 */
int wolfSSH_SFTP_Get(WOLFSSH* ssh, char* from,
        char* to, byte resume, WS_STATUS_CB* statusCb)
{
    WS_SFTP_GET_STATE* state = NULL;
    int sz;
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
        #ifdef WOLFSSL_NUCLEUS
        state->fl = &state->fd;
        #endif
    }

    for (;;) {
        switch (state->state) {

            case STATE_GET_INIT:
                WLOG(WS_LOG_SFTP, "SFTP GET STATE: INIT");
                state->state = STATE_GET_LSTAT;
                FALL_THROUGH;

            case STATE_GET_LSTAT:
                WLOG(WS_LOG_SFTP, "SFTP GET STATE: STAT");
                ret = wolfSSH_SFTP_STAT(ssh, from, &state->attrib);
                if (ret != WS_SUCCESS) {
                    if (ssh->error == WS_WANT_READ ||
                            ssh->error == WS_WANT_WRITE)
                        return WS_FATAL_ERROR;
                    WLOG(WS_LOG_SFTP, "Error verifying file");
                    state->state = STATE_GET_CLEANUP;
                    continue;
                }
                if ((state->attrib.per & FILEATRB_PER_MASK_TYPE)
                        != FILEATRB_PER_FILE
                    && (state->attrib.per & FILEATRB_PER_MASK_TYPE)
                        != FILEATRB_PER_LINK) {
                    WLOG(WS_LOG_SFTP, "Not a file");
                    ssh->error = WS_SFTP_NOT_FILE_E;
                    ret = WS_FATAL_ERROR;
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
                    wolfSSH_SFTP_GetOfst(ssh, from, to, state->gOfst);
                }
                state->state = STATE_GET_OPEN_LOCAL;
                FALL_THROUGH;

            case STATE_GET_OPEN_LOCAL:
                WLOG(WS_LOG_SFTP, "SFTP GET STATE: OPEN LOCAL");
             #ifdef MICROCHIP_MPLAB_HARMONY
                    if (state->gOfst[0] > 0 || state->gOfst[1] > 0)
                        ret = WFOPEN(ssh->fs, &state->fl, to, WOLFSSH_O_APPEND);
                    else
                        ret = WFOPEN(ssh->fs, &state->fl, to, WOLFSSH_O_WRONLY);
            #elif defined(USE_WINDOWS_API)
                    {
                        DWORD desiredAccess = GENERIC_WRITE;
                        if (state->gOfst > 0)
                            desiredAccess |= FILE_APPEND_DATA;
                        state->fileHandle = WS_CreateFileA(to, desiredAccess,
                            (FILE_SHARE_DELETE | FILE_SHARE_READ |
                             FILE_SHARE_WRITE), CREATE_ALWAYS,
                            FILE_ATTRIBUTE_NORMAL, ssh->ctx->heap);
                    }
                    if (resume) {
                        WMEMSET(&state->offset, 0, sizeof(OVERLAPPED));
                        state->offset.OffsetHigh = state->gOfst[1];
                        state->offset.Offset = state->gOfst[0];
                    }
                #else
                    if (state->gOfst[0] > 0 || state->gOfst[1] > 0)
                        ret = WFOPEN(ssh->fs, &state->fl, to, "ab");
                    else
                        ret = WFOPEN(ssh->fs, &state->fl, to, "wb");
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
                        if (NoticeError(ssh)) {
                            return WS_FATAL_ERROR;
                        }
                        WLOG(WS_LOG_SFTP, "Error reading packet");
                        ret = WS_FATAL_ERROR;
                        state->state = STATE_GET_CLOSE_LOCAL;
                        break;
                    }
                    else {
                    #ifndef USE_WINDOWS_API
                        if ((long)WFWRITE(ssh->fs, state->r, 1,
                                          sz, state->fl) != sz) {
                            WLOG(WS_LOG_SFTP, "Error writing to file");
                            ssh->error = WS_BAD_FILE_E;
                            ret = WS_FATAL_ERROR;
                            state->state = STATE_GET_CLEANUP;
                            break;
                        }
                    #else /* USE_WINDOWS_API */
                        {
                            DWORD bytesWritten = 0;
                            if ((WriteFile(state->fileHandle, state->r, sz,
                                         &bytesWritten, &state->offset) == 0)
                                    || ((DWORD)sz != bytesWritten))
                                {
                                WLOG(WS_LOG_SFTP, "Error writing to file");
                                ssh->error = WS_BAD_FILE_E;
                                ret = WS_FATAL_ERROR;
                                state->state = STATE_GET_CLEANUP;
                                break; /* either at end of file or error */
                            }
                        }
                    #endif /* USE_WINDOWS_API */
                        AddAssign64(state->gOfst, sz);
                        #ifdef USE_WINDOWS_API
                            state->offset.OffsetHigh = state->gOfst[1];
                            state->offset.Offset = state->gOfst[0];
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
                state->state = STATE_GET_CLOSE_REMOTE;
                FALL_THROUGH;

            case STATE_GET_CLOSE_REMOTE:
                if (state->handleSz > 0) {
                    WLOG(WS_LOG_SFTP, "SFTP GET STATE: CLOSE REMOTE");
                    ret = wolfSSH_SFTP_Close(ssh,
                                         state->handle, state->handleSz);
                    if (ret != WS_SUCCESS) {
                        if (ssh->error == WS_WANT_READ ||
                                ssh->error == WS_WANT_WRITE) {
                            return WS_FATAL_ERROR;
                        }
                        WLOG(WS_LOG_SFTP, "Error closing remote handle");
                    }
                }
                state->state = STATE_GET_CLOSE_LOCAL;
                FALL_THROUGH;

            case STATE_GET_CLOSE_LOCAL:
                WLOG(WS_LOG_SFTP, "SFTP GET STATE: CLOSE LOCAL");
                #ifndef USE_WINDOWS_API
                    WFCLOSE(ssh->fs, state->fl);
                #else /* USE_WINDOWS_API */
                    if (CloseHandle(state->fileHandle) == 0) {
                        WLOG(WS_LOG_SFTP, "Error closing file.");
                        ret = WS_FATAL_ERROR;
                        ssh->error = WS_CLOSE_FILE_E;
                    }
                #endif /* USE_WINDOWS_API */
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
                WLOG(WS_LOG_SFTP, "Bad SFTP Get state, program error");
                return WS_INPUT_CASE_E;
        }
    }
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
        #ifdef WOLFSSL_NUCLEUS
        state->fl = &state->fd;
        #endif
    }

    for (;;) {
        switch (state->state) {

            case STATE_PUT_INIT:
                WLOG(WS_LOG_SFTP, "SFTP PUT STATE: INIT");
                state->pOfst[0] = 0;
                state->pOfst[1] = 0;
                state->state = STATE_PUT_LOOKUP_OFFSET;
                FALL_THROUGH;

            case STATE_PUT_LOOKUP_OFFSET:
                WLOG(WS_LOG_SFTP, "SFTP PUT STATE: LOOKUP OFFSET");
                if (resume) {
                    /* check if offset was stored */
                    wolfSSH_SFTP_GetOfst(ssh, from, to, state->pOfst);
                }
                state->handleSz = WOLFSSH_MAX_HANDLE;
                state->state = STATE_PUT_OPEN_LOCAL;
                FALL_THROUGH;

            case STATE_PUT_OPEN_LOCAL:
                WLOG(WS_LOG_SFTP, "SFTP PUT STATE: OPEN LOCAL");
            #ifndef USE_WINDOWS_API
                {
                    WS_SFTP_FILEATRB fileAtr;
                    WMEMSET(&fileAtr, 0, sizeof(fileAtr));
                    if (SFTP_GetAttributes(ssh->fs,
                                from, &fileAtr, 1, ssh->ctx->heap)
                            == WS_SUCCESS) {
                        if ((fileAtr.per & FILEATRB_PER_MASK_TYPE)
                                != FILEATRB_PER_FILE) {
                            WLOG(WS_LOG_SFTP, "Not a file");
                            ssh->error = WS_SFTP_NOT_FILE_E;
                            ret = WS_FATAL_ERROR;
                            state->state = STATE_PUT_CLEANUP;
                            continue;
                        }
                    }
                }
            #if defined(MICROCHIP_MPLAB_HARMONY)
                ret = WFOPEN(ssh->fs, &state->fl, from, WOLFSSH_O_RDONLY);
            #else
                ret = WFOPEN(ssh->fs, &state->fl, from, "rb");
            #endif
                if (ret != 0) {
                    WLOG(WS_LOG_SFTP, "Unable to open input file");
                    ssh->error = WS_SFTP_FILE_DNE;
                    ret = WS_FATAL_ERROR;
                    state->state = STATE_PUT_CLEANUP;
                    continue;
                }
                if (resume) {
                    long offset = state->pOfst[0];

                #if SIZEOF_OFF_T == 8
                    offset = (((word64)state->pOfst[1]) << 32) | offset;
                #endif
                    WFSEEK(ssh->fs, state->fl, offset, 0);
                }
            #else /* USE_WINDOWS_API */
                state->fileHandle = WS_CreateFileA(from, GENERIC_READ,
                        FILE_SHARE_READ, OPEN_EXISTING,
                        FILE_ATTRIBUTE_NORMAL, ssh->ctx->heap);
                if (state->fileHandle == INVALID_HANDLE_VALUE) {
                    ssh->error = WS_SFTP_FILE_DNE;
                    ret = WS_FATAL_ERROR;
                    state->state = STATE_PUT_CLEANUP;
                    continue;
                }
                if (resume) {
                    WMEMSET(&state->offset, 0, sizeof(OVERLAPPED));
                    state->offset.OffsetHigh = state->pOfst[1];
                    state->offset.Offset = state->pOfst[0];
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
                    state->state = STATE_PUT_CLOSE_LOCAL;
                    continue;
                }
                state->state = STATE_PUT_WRITE;
                FALL_THROUGH;

            case STATE_PUT_WRITE:
                WLOG(WS_LOG_SFTP, "SFTP PUT STATE: WRITE");
                do {
                    if (state->rSz == 0) {
                    #ifndef USE_WINDOWS_API
                        state->rSz = (int)WFREAD(ssh->fs, state->r,
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
                                ssh->error == WS_WANT_WRITE ||
                                ssh->error == WS_WINDOW_FULL)
                            return WS_FATAL_ERROR;
                    }
                    else {
                        AddAssign64(state->pOfst, sz);
                        #ifdef USE_WINDOWS_API
                            state->offset.OffsetHigh = state->pOfst[1];
                            state->offset.Offset = state->pOfst[0];
                        #endif /* USE_WINDOWS_API */
                        state->rSz -= sz;
                        if (statusCb != NULL) {
                            statusCb(ssh, state->pOfst, from);
                        }
                    }
                } while (sz > 0 && ssh->sftpInt == 0);

                if (ssh->sftpInt) {
                    wolfSSH_SFTP_SaveOfst(ssh, from, to, state->pOfst);
                    ssh->sftpInt = 0;
                }
                FALL_THROUGH;

            case STATE_PUT_CLOSE_LOCAL:
                WLOG(WS_LOG_SFTP, "SFTP PUT STATE: CLOSE LOCAL");
            #ifndef USE_WINDOWS_API
                WFCLOSE(ssh->fs, state->fl);
            #else /* USE_WINDOWS_API */
                CloseHandle(state->fileHandle);
            #endif /* USE_WINDOWS_API */
                state->state = STATE_PUT_CLOSE_REMOTE;
                FALL_THROUGH;

            case STATE_PUT_CLOSE_REMOTE:
                if (state->handleSz > 0) {
                    WLOG(WS_LOG_SFTP, "SFTP PUT STATE: CLOSE REMOTE");
                    ret = wolfSSH_SFTP_Close(ssh, state->handle,
                        state->handleSz);
                    if (ret != WS_SUCCESS) {
                        if (NoticeError(ssh)) {
                            return WS_FATAL_ERROR;
                        }
                        WLOG(WS_LOG_SFTP, "Error closing handle");
                        /* Fall through to cleanup. */
                    }
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
                WLOG(WS_LOG_SFTP, "Bad SFTP Put state, program error");
                return WS_INPUT_CASE_E;
        }
    }
}

#ifdef WOLFSSH_STOREHANDLE
static int SFTP_FreeHandles(WOLFSSH* ssh)
{
    WS_HANDLE_LIST* cur = ssh->handleList;

    /* go through and free handles and make sure files are closed */
    while (cur != NULL) {
    #ifdef MICROCHIP_MPLAB_HARMONY
        WFCLOSE(ssh->fs, ((WFILE*)cur->handle));
    #else
        WCLOSE(ssh->fs, *((WFD*)cur->handle));
    #endif
        if (SFTP_RemoveHandleNode(ssh, cur->handle, cur->handleSz)
                != WS_SUCCESS) {
            return WS_FATAL_ERROR;
        }
        cur = ssh->handleList;
    }

    return WS_SUCCESS;
}
#endif

/* called when wolfSSH_free() is called
 * return WS_SUCCESS on success */
int wolfSSH_SFTP_free(WOLFSSH* ssh)
{
    int ret = WS_SUCCESS;

    WOLFSSH_UNUSED(ssh);
#ifdef WOLFSSH_STOREHANDLE
    ret = SFTP_FreeHandles(ssh);
#endif

#ifndef NO_WOLFSSH_DIR
    {
        /* free all dirs if hung up on */
        WS_DIR_LIST* cur = ssh->dirList;

        /* find DIR given handle */
        while (cur != NULL) {
            WS_DIR_LIST* toFree = cur;

            cur = cur->next;
        #ifdef USE_WINDOWS_API
            FindClose(toFree->dir);
        #else
            WCLOSEDIR(ssh->fs, &toFree->dir);
        #endif
            if (toFree->dirName != NULL)
                WFREE(toFree->dirName, ssh->ctx->heap, DYNTYPE_SFTP);
            WFREE(toFree, ssh->ctx->heap, DYNTYPE_SFTP);
        }
        ssh->dirList = NULL;
    }
#endif /* NO_WOLFSSH_DIR */

    wolfSSH_SFTP_ClearState(ssh, STATE_ID_ALL);
    return ret;
}

#ifdef WOLFSSH_SHOW_SIZES

void wolfSSH_SFTP_ShowSizes(void)
{
    fprintf(stderr, "wolfSFTP struct sizes:\n");
    fprintf(stderr, "  sizeof(struct %s) = %u\n", "WS_SFTP_CHMOD_STATE",
            (word32)sizeof(struct WS_SFTP_CHMOD_STATE));
    fprintf(stderr, "  sizeof(struct %s) = %u\n", "WS_SFTP_SETATR_STATE",
            (word32)sizeof(struct WS_SFTP_SETATR_STATE));
    fprintf(stderr, "  sizeof(struct %s) = %u\n", "WS_SFTP_LSTAT_STATE",
            (word32)sizeof(struct WS_SFTP_LSTAT_STATE));
    fprintf(stderr, "  sizeof(struct %s) = %u\n", "WS_SFTP_OPEN_STATE",
            (word32)sizeof(struct WS_SFTP_OPEN_STATE));
    fprintf(stderr, "  sizeof(struct %s) = %u\n", "WS_SFTP_NAME_STATE",
            (word32)sizeof(struct WS_SFTP_NAME_STATE));
    fprintf(stderr, "  sizeof(struct %s) = %u\n", "WS_SFTP_SEND_STATE",
            (word32)sizeof(struct WS_SFTP_SEND_STATE));
    fprintf(stderr, "  sizeof(struct %s) = %u\n", "WS_SFTP_READDIR_STATE",
            (word32)sizeof(struct WS_SFTP_READDIR_STATE));
    fprintf(stderr, "  sizeof(struct %s) = %u\n", "WS_SFTP_RM_STATE",
            (word32)sizeof(struct WS_SFTP_RM_STATE));
    fprintf(stderr, "  sizeof(struct %s) = %u\n", "WS_SFTP_MKDIR_STATE",
            (word32)sizeof(struct WS_SFTP_MKDIR_STATE));
    fprintf(stderr, "  sizeof(struct %s) = %u\n", "WS_SFTP_RMDIR_STATE",
            (word32)sizeof(struct WS_SFTP_RMDIR_STATE));
    fprintf(stderr, "  sizeof(struct %s) = %u\n", "WS_SFTP_RECV_STATE",
            (word32)sizeof(struct WS_SFTP_RECV_STATE));
    fprintf(stderr, "  sizeof(struct %s) = %u\n", "WS_SFTP_LS_STATE",
            (word32)sizeof(struct WS_SFTP_LS_STATE));
    fprintf(stderr, "  sizeof(struct %s) = %u\n", "WS_SFTP_GET_STATE",
            (word32)sizeof(struct WS_SFTP_GET_STATE));
    fprintf(stderr, "  sizeof(struct %s) = %u\n", "WS_SFTP_PUT_STATE",
            (word32)sizeof(struct WS_SFTP_PUT_STATE));
    fprintf(stderr, "  sizeof(struct %s) = %u\n", "WS_SFTP_SEND_READ_STATE",
            (word32)sizeof(struct WS_SFTP_SEND_READ_STATE));
    fprintf(stderr, "  sizeof(struct %s) = %u\n", "WS_SFTP_SEND_WRITE_STATE",
            (word32)sizeof(struct WS_SFTP_SEND_WRITE_STATE));
    fprintf(stderr, "  sizeof(struct %s) = %u\n", "WS_SFTP_CLOSE_STATE",
            (word32)sizeof(struct WS_SFTP_CLOSE_STATE));
    fprintf(stderr, "  sizeof(struct %s) = %u\n", "WS_SFTP_GET_HANDLE_STATE",
            (word32)sizeof(struct WS_SFTP_GET_HANDLE_STATE));
    fprintf(stderr, "  sizeof(struct %s) = %u\n", "WS_SFTP_RENAME_STATE",
            (word32)sizeof(struct WS_SFTP_RENAME_STATE));
}

#endif /* WOLFSSH_SHOW_SIZES */

#endif /* WOLFSSH_SFTP */

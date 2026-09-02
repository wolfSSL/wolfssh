/* wolfscp.h
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


#ifndef _WOLFSSH_WOLFSCP_H_
#define _WOLFSSH_WOLFSCP_H_


#include <wolfssh/settings.h>
#include <wolfssh/ssh.h>
#include <wolfssh/port.h>

#ifdef WOLFSSH_SCP

#ifdef __cplusplus
extern "C" {
#endif

#ifndef NULL
    #include <stddef.h>
#endif

/* size of scp protocol message buffer, dependent mostly on
 * path and file name lengths, on the stack */
#ifndef DEFAULT_SCP_MSG_SZ
    #define DEFAULT_SCP_MSG_SZ 1024
#endif

#ifndef DEFAULT_SCP_FILE_NAME_SZ
    #define DEFAULT_SCP_FILE_NAME_SZ 1024
#endif

/* size of scp file transfer buffer, allocated dynamically */
#ifndef DEFAULT_SCP_BUFFER_SZ
    #define DEFAULT_SCP_BUFFER_SZ DEFAULT_MAX_PACKET_SZ
#endif

enum WS_ScpFileStates {
    /* sink */
    WOLFSSH_SCP_NEW_REQUEST = 0,
    WOLFSSH_SCP_NEW_FILE,
    WOLFSSH_SCP_FILE_PART,
    WOLFSSH_SCP_FILE_DONE,
    WOLFSSH_SCP_NEW_DIR,
    WOLFSSH_SCP_END_DIR,
    /* source */
    WOLFSSH_SCP_SINGLE_FILE_REQUEST,
    WOLFSSH_SCP_RECURSIVE_REQUEST,
    WOLFSSH_SCP_CONTINUE_FILE_TRANSFER
};


#if !defined(WOLFSSH_SCP_USER_CALLBACKS)
#if !defined(NO_FILESYSTEM)
    #include <time.h>
    #ifdef HAVE_SYS_TIME_H
        #include <sys/time.h>
    #endif
    #include <errno.h>

    typedef struct ScpSendCtx {
    #ifdef WOLFSSL_NUCLEUS
        int   fd; /* file descriptor, in the case of Nucleus fp points to fd */
        DSTAT s;
        int   nextError;
    #elif defined(USE_WINDOWS_API)
        char* entry;
        WIN32_FILE_ATTRIBUTE_DATA s;
    #elif defined(WOLFSSH_ZEPHYR)
        struct fs_dirent entry;
        WSTAT_T s;                              /* stat info from file */
    #else
        struct dirent* entry;                   /* file entry, from readdir() */
        struct stat s;                          /* stat info from file */
    #endif
        WFILE* fp;                              /* file pointer */
        struct ScpDir* currentDir;              /* dir being copied, stack */
        char dirName[DEFAULT_SCP_FILE_NAME_SZ]; /* current dir name */
    } ScpSendCtx;

    typedef struct ScpDir {
        WDIR dir;                            /* dir pointer, from opendir() */
        struct ScpDir* next;                 /* previous directory in stack */
    } ScpDir;
#else
    /* Use a buffer for built in no filesystem send/recv */
    typedef struct ScpBuffer ScpBuffer;
    struct ScpBuffer {
        char   name[DEFAULT_SCP_FILE_NAME_SZ];
        byte*  buffer;
        word64 mTime;
        word32 bufferSz; /* size of "buffer" */
        word32 fileSz;   /* size of file in "buffer" */
        word32 idx;      /* current index into "buffer" */
        word32 nameSz;
        int   mode;
        int (*status)(WOLFSSH* ssh, const char* fileName, enum WS_ScpFileStates state, ScpBuffer* file);
    };
#endif /* NO_FILESYSTEM */
#endif /* WOLFSSH_SCP_USER_CALLBACKS */

typedef int (*WS_CallbackScpRecv)(WOLFSSH* ssh, int state,
                                  const char* basePath, const char* fileName,
                                  int fileMode, word64 mTime, word64 aTime,
                                  word32 totalFileSz, byte* buf, word32 bufSz,
                                  word32 fileOffset, void* ctx);
/* Send callback. Returns the number of octets placed in "buf", or one of the
 * WS_SCP_* status codes, or a negative error to abort the transfer.
 *
 * "fileNameSz" is the capacity of the "fileName" buffer, not the length of any
 * name already in it.
 *
 * Returning 0 is only valid on the call that fills in metadata (file name,
 * mode, times, totalFileSz) and has no data ready yet; the library then sends
 * the file header and calls back with WOLFSSH_SCP_CONTINUE_FILE_TRANSFER. A
 * second 0 in a row while "fileOffset" is still short of "totalFileSz" is
 * treated as a stalled callback and aborts the transfer, since there is no
 * "no data right now" status in this API. Callbacks that can block should do
 * so rather than returning 0. */
typedef int (*WS_CallbackScpSend)(WOLFSSH* ssh, int state,
                                  const char* peerRequest, char* fileName,
                                  word32 fileNameSz, word64* mTime,
                                  word64* aTime, int* fileMode,
                                  word32 fileOffset, word32* totalFileSz,
                                  byte* buf, word32 bufSz, void* ctx);

WOLFSSH_API void  wolfSSH_SetScpRecv(WOLFSSH_CTX* ctx, WS_CallbackScpRecv cb);
WOLFSSH_API void  wolfSSH_SetScpSend(WOLFSSH_CTX* ctx, WS_CallbackScpSend cb);

WOLFSSH_API void  wolfSSH_SetScpRecvCtx(WOLFSSH* ssh, void* ctx);
WOLFSSH_API void  wolfSSH_SetScpSendCtx(WOLFSSH* ssh, void* ctx);

WOLFSSH_API void* wolfSSH_GetScpRecvCtx(WOLFSSH* ssh);
WOLFSSH_API void* wolfSSH_GetScpSendCtx(WOLFSSH* ssh);

/* NULL ssh or message returns WS_BAD_ARGUMENT */
WOLFSSH_API int   wolfSSH_SetScpErrorMsg(WOLFSSH* ssh, const char* message);

WOLFSSH_API int   wolfSSH_SCP_connect(WOLFSSH* ssh, byte* cmd);
WOLFSSH_API int   wolfSSH_SCP_to(WOLFSSH* ssh, const char* src,
        const char* dst);
WOLFSSH_API int   wolfSSH_SCP_from(WOLFSSH* ssh, const char* src,
        const char* dst);
/* Server side. Drives an SCP transfer on a channel whose "exec scp ..."
 * command is already bound. This is the same work wolfSSH_accept() does
 * through its WS_SCP_INIT re-entry, exposed so an application can start the
 * transfer itself; use one or the other, not both. Call it once
 * wolfSSH_accept() has returned and the exec channel-request callback has
 * reported an SCP command, not from inside that callback.
 *
 * Returns WS_SCP_COMPLETE when the transfer is done. On a non-blocking
 * socket it returns WS_WANT_READ or WS_WANT_WRITE with the transfer part
 * done; call it again on the same session until it completes. */
WOLFSSH_API int   wolfSSH_SCP_accept(WOLFSSH* ssh);


#ifdef __cplusplus
}
#endif

#endif /* WOLFSSH_SCP */

#endif /* _WOLFSSH_WOLFSCP_H_ */


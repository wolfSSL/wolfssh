/* wolfscp.h
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

#pragma once

#ifndef WOLFSSH_WOLFSCP_H
#define WOLFSSH_WOLFSCP_H

#include <wolfssh/settings.h>
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

#if !defined(SCP_USER_CALLBACKS) && !defined(NO_FILESYSTEM)
    /* for utimes() */
    #include <sys/time.h>
    #include <errno.h>

    typedef struct ScpSendCtx {
        struct dirent* entry;                   /* file entry, from readdir() */
        struct ScpDir* currentDir;              /* dir being copied, stack */
        WFILE* fp;                              /* file pointer */
        struct stat s;                          /* stat info from file */
        char dirName[DEFAULT_SCP_FILE_NAME_SZ]; /* current dir name */
    } ScpSendCtx;

    typedef struct ScpDir {
        DIR* dir;                            /* dir pointer, from opendir() */
        struct ScpDir* next;                 /* previous directory in stack */
    } ScpDir;

#endif /* SCP_USER_CALLBACKS */

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

typedef int (*WS_CallbackScpRecv)(WOLFSSH*, int, const char*, const char*,
                                  int, word64, word64, word32, byte*, word32,
                                  word32, void*);
typedef int (*WS_CallbackScpSend)(WOLFSSH*, int, const char*, char*, word32,
                                  word64*, word64*, int*, word32, word32*,
                                  byte*, word32, void*);

WOLFSSH_API void  wolfSSH_SetScpRecv(WOLFSSH_CTX*, WS_CallbackScpRecv);
WOLFSSH_API void  wolfSSH_SetScpSend(WOLFSSH_CTX*, WS_CallbackScpSend);

WOLFSSH_API void  wolfSSH_SetScpRecvCtx(WOLFSSH*, void*);
WOLFSSH_API void  wolfSSH_SetScpSendCtx(WOLFSSH*, void*);

WOLFSSH_API void* wolfSSH_GetScpRecvCtx(WOLFSSH*);
WOLFSSH_API void* wolfSSH_GetScpSendCtx(WOLFSSH*);

WOLFSSH_API int   wolfSSH_SetScpErrorMsg(WOLFSSH*, const char*);


#ifdef __cplusplus
}
#endif

#endif /* WOLFSSH_SCP */

#endif /* WOLFSSH_WOLFSCP_H */


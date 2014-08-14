/* ssh.h
 *
 * Copyright (C) 2014 wolfSSL Inc.
 *
 * This file is part of wolfSSH.
 *
 * wolfSSH is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSH is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA  02110-1301, USA.
 */


/*
 * The ssh module contains the public API for wolfSSH.
 */


#pragma once

#include <wolfssh/settings.h>
#include <wolfssh/version.h>
#include <wolfssh/port.h>
#include <wolfssh/error.h>

#ifdef __cplusplus
extern "C" {
#endif


typedef struct WOLFSSH_CTX  WOLFSSH_CTX;
typedef struct WOLFSSH      WOLFSSH;


WOLFSSH_API int  wolfSSH_Init(void);
WOLFSSH_API int  wolfSSH_Cleanup(void);

/* debugging output functions */
WOLFSSH_API int  wolfSSH_Debugging_ON(void);
WOLFSSH_API void wolfSSH_Debugging_OFF(void);

/* context functions */
WOLFSSH_API WOLFSSH_CTX* wolfSSH_CTX_new(uint8_t, void*);
WOLFSSH_API void         wolfSSH_CTX_free(WOLFSSH_CTX*);

/* ssh session functions */
WOLFSSH_API WOLFSSH* wolfSSH_new(WOLFSSH_CTX*);
WOLFSSH_API void     wolfSSH_free(WOLFSSH*);

WOLFSSH_API int  wolfSSH_set_fd(WOLFSSH*, int);
WOLFSSH_API int  wolfSSH_get_fd(const WOLFSSH*);

WOLFSSH_API int wolfSSH_get_error(const WOLFSSH*);
WOLFSSH_API const char* wolfSSH_get_error_name(const WOLFSSH*);

/* I/O callbacks */
typedef int (*WS_CallbackIORecv)(WOLFSSH*, void*, uint32_t, void*);
typedef int (*WS_CallbackIOSend)(WOLFSSH*, void*, uint32_t, void*);

WOLFSSH_API void wolfSSH_SetIORecv(WOLFSSH_CTX*, WS_CallbackIORecv);
WOLFSSH_API void wolfSSH_SetIOSend(WOLFSSH_CTX*, WS_CallbackIOSend);

WOLFSSH_API void wolfSSH_SetIOReadCtx(WOLFSSH* ssh, void* ctx);
WOLFSSH_API void wolfSSH_SetIOWriteCtx(WOLFSSH* ssh, void* ctx);

WOLFSSH_API void* wolfSSH_GetIOReadCtx(WOLFSSH* ssh);
WOLFSSH_API void* wolfSSH_GetIOWriteCtx(WOLFSSH* ssh);

WOLFSSH_API int wolfSSH_accept(WOLFSSH* ssh);


enum WS_EndpointTypes {
    WOLFSSH_SERVER = 0,
    WOLFSSH_CLIENT = 1
};


/* dynamic memory types */
enum WS_DynamicTypes {
    WOLFSSH_CTX_TYPE       = 1,
    WOLFSSH_TYPE           = 2,
    WOLFSSH_TYPE_BUFFER    = 3,
    WOLFSSH_ID_TYPE        = 4,
    WOLFSSH_HANDSHAKE_TYPE = 5
};


#ifdef __cplusplus
}
#endif


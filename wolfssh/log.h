/* log.h
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */


#pragma once

#include <wolfssh/settings.h>

#ifdef __cplusplus
extern "C" {
#endif


enum wolfSSH_LogLevel {
    WS_LOG_USER  = 5,
    WS_LOG_ERROR = 4,
    WS_LOG_WARN  = 3,
    WS_LOG_INFO  = 2,
    WS_LOG_DEBUG = 1,
    WS_LOG_DEFAULT = WS_LOG_DEBUG
};


typedef void (*wolfSSH_LoggingCb)(enum wolfSSH_LogLevel,
                                  const char *const logMsg);

WOLFSSH_API int  wolfSSH_SetLoggingCb(wolfSSH_LoggingCb logF);


#ifdef DEBUG_WOLFSSH
    WOLFSSH_API void WLOG(enum wolfSSH_LogLevel,const char *const logMsg, ...)
    #ifdef __GNUC__
        __attribute__((format(printf, 2, 3)));
    #else
        ;  /* end decl */
    #endif /* __GNUC__ */
#else
    #define WLOG(a, b, ...)
#endif /* DEBUG_WOLFSSH */


#ifdef __cplusplus
}
#endif


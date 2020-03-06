/* log.h
 *
 * Copyright (C) 2014-2020 wolfSSL Inc.
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
 * The log module contains the interface to the logging function. When
 * debugging is enabled and turned on, the logger will output to STDOUT.
 * A custom logging callback may be installed.
 */


#pragma once

#include <wolfssh/settings.h>

#ifdef __cplusplus
extern "C" {
#endif


#ifdef NO_TIMESTAMP
    /* The NO_TIMESTAMP tag is deprecated. Convert to new name. */
    #define WOLFSSH_NO_TIMESTAMP
#endif


enum wolfSSH_LogLevel {
    WS_LOG_ALL = 0,
    WS_LOG_TRACE,
    WS_LOG_DEBUG,
    WS_LOG_INFO,
    WS_LOG_WARN,
    WS_LOG_ERROR,
    WS_LOG_FATAL,
    WS_LOG_OFF
};


enum wolfSSH_LogDomain {
    WS_LOG_DOMAIN_GENERAL = 0,
    WS_LOG_DOMAIN_INIT,
    WS_LOG_DOMAIN_SETUP,
    WS_LOG_DOMAIN_CONNECT,
    WS_LOG_DOMAIN_ACCEPT,
    WS_LOG_DOMAIN_CBIO,
    WS_LOG_DOMAIN_KEX,
    WS_LOG_DOMAIN_USER_AUTH,
    WS_LOG_DOMAIN_SFTP,
    WS_LOG_DOMAIN_SCP,
    WS_LOG_DOMAIN_KEYGEN,
    WS_LOG_DOMAIN_TERM
};


typedef void (*wolfSSH_LoggingCb)(enum wolfSSH_LogLevel,
                                  const char *const);
WOLFSSH_API void wolfSSH_SetLoggingCb(wolfSSH_LoggingCb);
WOLFSSH_API int wolfSSH_LogEnabled(void);
WOLFSSH_API enum wolfSSH_LogLevel wolfSSH_GetLogLevel(void);
WOLFSSH_API void wolfSSH_SetLogLevel(enum wolfSSH_LogLevel);


#ifdef __GNUC__
    #define FMTCHECK __attribute__((format(printf,3,4)))
#else
    #define FMTCHECK
#endif /* __GNUC__ */


WOLFSSH_API void wolfSSH_Log(enum wolfSSH_LogLevel,
                             enum wolfSSH_LogDomain,
                             const char *const, ...) FMTCHECK;

#ifndef WOLFSSH_NO_LOGGING
    #define WLOG(...) do { wolfSSH_Log(__VA_ARGS__); } while (0)
#else
    #define WLOG(...) do { ; } while (0)
#endif

#ifdef __cplusplus
}
#endif


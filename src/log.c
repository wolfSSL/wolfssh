/* log.c
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


#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssh/ssh.h>
#include <wolfssh/log.h>
#include <wolfssh/error.h>

#ifndef WOLFSSH_NO_LOGGING

#include <stdlib.h>
#include <stdarg.h>
#ifndef FREESCALE_MQX
    #include <stdio.h>
    #ifndef WOLFSSH_NO_TIMESTAMP
        #include <time.h>
    #endif
#endif


#ifndef WOLFSSH_DEFAULT_LOG_WIDTH
    #define WOLFSSH_DEFAULT_LOG_WIDTH 120
#endif


#ifndef WOLFSSL_NO_DEFAULT_LOGGING_CB
    static void DefaultLoggingCb(enum wolfSSH_LogLevel, const char *const);
    static wolfSSH_LoggingCb logFunction = DefaultLoggingCb;
#else /* WOLFSSH_NO_DEFAULT_LOGGING_CB */
    static wolfSSH_LoggingCb logFunction = NULL;
#endif /* WOLFSSH_NO_DEFAULT_LOGGING_CB */


static enum wolfSSH_LogLevel logLevel = WS_LOG_OFF;


/* turn debugging on if supported */
void wolfSSH_Debugging_ON(void)
{
    logLevel = WS_LOG_ALL;
}


/* turn debugging off */
void wolfSSH_Debugging_OFF(void)
{
    logLevel = WS_LOG_OFF;
}


/* set logging callback function */
void wolfSSH_SetLoggingCb(wolfSSH_LoggingCb logF)
{
    if (logF)
        logFunction = logF;
}


int wolfSSH_LogEnabled(void)
{
    return logLevel != WS_LOG_OFF;
}


enum wolfSSH_LogLevel wolfSSH_GetLogLevel(void)
{
    return logLevel;
}


void wolfSSH_SetLogLevel(enum wolfSSH_LogLevel level)
{
    if (level >= WS_LOG_OFF) {
        level = WS_LOG_OFF;
    }
    logLevel = level;
}


#ifndef WOLFSSH_NO_DEFAULT_LOGGING_CB
/* log level string */
static const char* GetLogLevelStr(enum wolfSSH_LogLevel level)
{
    switch (level) {
        case WS_LOG_ALL:
            return "ALL";
        case WS_LOG_TRACE:
            return "TRACE";
        case WS_LOG_DEBUG:
            return "DEBUG";
        case WS_LOG_INFO:
            return "INFO";
        case WS_LOG_WARN:
            return "WARNING";
        case WS_LOG_ERROR:
            return "ERROR";
        case WS_LOG_FATAL:
            return "FATAL";
        case WS_LOG_OFF:
            return "OFF";
        default:
            return "UNKNOWN";
    }
}


#if 0 /* Future use */
/* log domain string */
static const char* GetLogDomainStr(enum wolfSSH_LogDomain domain)
{
    switch (domain) {
        case WS_LOG_DOMAIN_GENERAL:
            return "GENERAL";
        case WS_LOG_DOMAIN_INIT:
            return "INIT";
        case WS_LOG_DOMAIN_SETUP:
            return "SETUP";
        case WS_LOG_DOMAIN_CONNECT:
            return "CONNECT";
        case WS_LOG_DOMAIN_ACCEPT:
            return "ACCEPT";
        case WS_LOG_DOMAIN_CBIO:
            return "CBIO";
        case WS_LOG_DOMAIN_KEX:
            return "KEX";
        case WS_LOG_DOMAIN_USER_AUTH:
            return "USERAUTH";
        case WS_LOG_DOMAIN_SFTP:
            return "SFTP";
        case WS_LOG_DOMAIN_SCP:
            return "SCP";
        case WS_LOG_DOMAIN_KEYGEN:
            return "KEYGEN";
        case WS_LOG_DOMAIN_TERM:
            return "TERM";
        default:
            return "UNKNOWN";
    }
}
#endif /* 0 */


void DefaultLoggingCb(enum wolfSSH_LogLevel level, const char *const msgStr)
{
    char timeStr[24];
    timeStr[0] = '\0';
#ifndef WOLFSSH_NO_TIMESTAMP
    {
        time_t  current;
        struct  tm local;

        current = WTIME(NULL);
        if (WLOCALTIME(&current, &local)) {
            /* make pretty */
            strftime(timeStr, sizeof(timeStr), "%F %T ", &local);
        }
    }
#endif /* WOLFSSH_NO_TIMESTAMP */
    fprintf(stdout, "%s[%s] %s\r\n", timeStr, GetLogLevelStr(level), msgStr);
}
#endif /* WOLFSSH_NO_DEFAULT_LOGGING_CB */


/* our default logger */
void wolfSSH_Log(enum wolfSSH_LogLevel level, enum wolfSSH_LogDomain domain,
        const char *const fmt, ...)
{
    va_list vlist;
    char    msgStr[WOLFSSH_DEFAULT_LOG_WIDTH];

    (void)domain;

    if (level < logLevel)
        return;   /* don't need to output */

    /* format msg */
    va_start(vlist, fmt);
    WVSNPRINTF(msgStr, sizeof(msgStr), fmt, vlist);
    va_end(vlist);

    if (logFunction)
        logFunction(level, msgStr);
}

#endif /* WOLFSSH_NO_LOGGING */

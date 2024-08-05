/* wolfsshd.c
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

#ifdef WOLFSSL_USER_SETTINGS
    #include <wolfssl/wolfcrypt/settings.h>
#else
    #include <wolfssl/options.h>
#endif

#ifdef WOLFSSH_SSHD

#include <wolfssh/ssh.h>
#include <wolfssh/internal.h>
#include <wolfssh/log.h>
#include <wolfssl/wolfcrypt/wc_port.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/asn_public.h>

#define WOLFSSH_TEST_SERVER
#include <wolfssh/test.h>

#include "configuration.h"
#include "auth.h"

#include <signal.h>

#ifdef NO_INLINE
    #include <wolfssh/misc.h>
#else
    #define WOLFSSH_MISC_INCLUDED
    #include "src/misc.c"
#endif

#ifndef WOLFSSHD_TIMEOUT
    #define WOLFSSHD_TIMEOUT 1
#endif

#if defined(WOLFSSH_SHELL) && !defined(_WIN32)
    #ifdef HAVE_PTY_H
        #include <pty.h>
    #endif
    #ifdef HAVE_UTIL_H
        #include <util.h>
    #endif
    #ifdef HAVE_TERMIOS_H
        #include <termios.h>
    #endif
    #include <pwd.h>
    #include <signal.h>
    #include <sys/wait.h>
#if defined(__QNX__) || defined(__QNXNTO__)
    #include <errno.h>
    #include <unix.h>
#else
    #include <sys/errno.h>
#endif

    static volatile int ChildRunning = 0;
    static void ChildSig(int sig)
    {
        (void)sig;
        ChildRunning = 0;
    }

    static void ConnClose(int sig)
    {
#ifndef WIN32
        pid_t p;
        int   ret;
        p = wait(&ret);
        if (p == 0 || p == -1)
            return; /* parent or error state*/
        (void)ret;
#endif
        (void)sig;
    }
#endif /* WOLFSSH_SHELL */

static volatile byte debugMode = 0; /* default to off */
static WFILE* logFile = NULL;

/* catch interrupts and close down gracefully */
static volatile byte quit = 0;

/* Initial connection information to pass on to threads/forks */
typedef struct WOLFSSHD_CONNECTION {
    WOLFSSH_CTX*   ctx;
    WOLFSSHD_AUTH* auth;
    int            fd;
    int            listenFd;
    char           ip[INET6_ADDRSTRLEN];
    byte           isThreaded;
} WOLFSSHD_CONNECTION;

#ifdef __unix__

#include <syslog.h>

static void SyslogCb(enum wolfSSH_LogLevel level, const char *const msgStr)
{
    int priority;

    switch (level) {
        case WS_LOG_WARN:
            priority = LOG_WARNING;
            break;
        case WS_LOG_ERROR:
            priority = LOG_ERR;
            break;
        case WS_LOG_DEBUG:
            priority = LOG_DEBUG;
            break;
        case WS_LOG_INFO:
        case WS_LOG_USER:
        case WS_LOG_SFTP:
        case WS_LOG_SCP:
        case WS_LOG_AGENT:
        case WS_LOG_CERTMAN:
        default:
            priority = LOG_INFO;
            break;
    }
    openlog("sshd", LOG_PID, LOG_DAEMON);
    syslog(priority, "%s", msgStr);
    closelog();
}

#endif

#ifdef _WIN32
static void ServiceDebugCb(enum wolfSSH_LogLevel level, const char* const msgStr)
#ifdef UNICODE
{
    WCHAR* wc;
    size_t szWord = WSTRLEN(msgStr) + 3;  /* + 3 for null terminator and new
                                           * line */
    size_t sz     = szWord *sizeof(wchar_t);
    wc = (WCHAR*)WMALLOC(sz, NULL, DYNAMIC_TYPE_LOG);
    if (wc) {
        size_t con;

        if (mbstowcs_s(&con, wc, szWord, msgStr, szWord-1) == 0) {
            wc[con - 1] = L'\r';
            wc[con] = L'\n';
            wc[con + 1] = L'\0';
            OutputDebugString(wc);
        }
        WFREE(wc, NULL, DYNAMIC_TYPE_LOG);
    }
    WOLFSSH_UNUSED(level);
}
#else
{
    OutputDebugString(msgStr);
    WOLFSSH_UNUSED(level);
}
#endif
#endif /* _WIN32 */

static void ShowUsage(void)
{
    printf("wolfsshd %s\n", LIBWOLFSSH_VERSION_STRING);
    printf(" -?             display this help and exit\n");
    printf(" -f <file name> Configuration file to use, default is "
                            "/etc/ssh/sshd_config\n");
    printf(" -p <int>       Port number to listen on\n");
    printf(" -d             Turn on debug mode\n");
    printf(" -D             Run in foreground (do not detach)\n");
    printf(" -h <file name> host private key file to use\n");
    printf(" -E <file name> append to log file\n");
}


/* catch if interupted */
static void interruptCatch(int in)
{
    (void)in;
    if (logFile)
        fprintf(logFile, "Closing down wolfSSHD\n");
    quit = 1;
}

#ifdef WIN32
    #include <processthreadsapi.h>
    #define WGETPID GetCurrentProcessId
#else
    #define WGETPID getpid
#endif

/* redirect logging to a specific file and add the PID value */
static void wolfSSHDLoggingCb(enum wolfSSH_LogLevel lvl, const char *const str)
{
    /* always log errors and optionally log other info/debug level messages */
    if (lvl == WS_LOG_ERROR) {
        fprintf(logFile, "[PID %d]: %s\n", WGETPID(), str);
    }
    else if (debugMode) {
        fprintf(logFile, "[PID %d]: %s\n", WGETPID(), str);
    }
}


#ifndef NO_FILESYSTEM
static void freeBufferFromFile(byte* buf, void* heap)
{
    if (buf != NULL)
        WFREE(buf, heap, DYNTYPE_SSHD);
    (void)heap;
}


/* set bufSz to size wanted if too small and buf is null */
static byte* getBufferFromFile(const char* fileName, word32* bufSz, void* heap)
{
    FILE* file;
    byte* buf = NULL;
    word32 fileSz;
    word32 readSz;

    if (fileName == NULL) return NULL;

    if (WFOPEN(NULL, &file, fileName, "rb") != 0)
        return NULL;
    WFSEEK(NULL, file, 0, WSEEK_END);
    fileSz = (word32)WFTELL(NULL, file);
    WREWIND(NULL, file);

    buf = (byte*)WMALLOC(fileSz + 1, heap, DYNTYPE_SSHD);
    if (buf != NULL) {
        readSz = (word32)WFREAD(NULL, buf, 1, fileSz, file);
        if (readSz < fileSz) {
            WFCLOSE(NULL, file);
            WFREE(buf, heap, DYNTYPE_SSHD);
            return NULL;
        }
        if (bufSz)
            *bufSz = readSz;
        WFCLOSE(NULL, file);
    }

    (void)heap;
    return buf;
}
#endif /* NO_FILESYSTEM */


static int UserAuthResult(byte result,
        WS_UserAuthData* authData, void* userAuthResultCtx);


/* Frees up the WOLFSSH_CTX struct */
static void CleanupCTX(WOLFSSHD_CONFIG* conf, WOLFSSH_CTX** ctx,
        byte** banner)
{
    if (banner != NULL && *banner != NULL) {
#ifndef NO_FILESYSTEM
        freeBufferFromFile(*banner, NULL);
#endif
        *banner = NULL;
    }
    if (ctx != NULL && *ctx != NULL) {
        wolfSSH_CTX_free(*ctx);
        *ctx = NULL;
    }
    (void)conf;
}

/* Initializes and sets up the WOLFSSH_CTX struct based on the configure options
 * return WS_SUCCESS on success
 */
static int SetupCTX(WOLFSSHD_CONFIG* conf, WOLFSSH_CTX** ctx,
        byte** banner)
{
    int ret = WS_SUCCESS;
    DerBuffer* der = NULL;
    byte* privBuf;
    word32 privBufSz;
    void* heap = NULL;

    if (ctx == NULL) {
        return WS_BAD_ARGUMENT;
    }

    /* create a new WOLFSSH_CTX */
    *ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_SERVER, NULL);
    if (ctx == NULL) {
        wolfSSH_Log(WS_LOG_ERROR, "[SSHD] Couldn't allocate SSH CTX data.");
        ret = WS_MEMORY_E;
    }

    /* setup authority callback for checking peer connections */
    if (ret == WS_SUCCESS) {
        wolfSSH_SetUserAuth(*ctx, DefaultUserAuth);
        wolfSSH_SetUserAuthResult(*ctx, UserAuthResult);
    }

    /* set banner to display on connection */
    if (ret == WS_SUCCESS) {
#ifndef NO_FILESYSTEM
        *banner = getBufferFromFile(wolfSSHD_ConfigGetBanner(conf),
                NULL, heap);
#endif
        if (*banner) {
            wolfSSH_CTX_SetBanner(*ctx, (char*)*banner);
        }
    }

    /* Load in host private key */
    if (ret == WS_SUCCESS) {

        char* hostKey = wolfSSHD_ConfigGetHostKeyFile(conf);

        if (hostKey == NULL) {
            wolfSSH_Log(WS_LOG_ERROR, "[SSHD] No host private key set");
            ret = WS_BAD_ARGUMENT;
        }
        else {
            byte* data;
            word32 dataSz = 0;

            data = getBufferFromFile(hostKey, &dataSz, heap);
            if (data == NULL) {
                wolfSSH_Log(WS_LOG_ERROR,
                    "[SSHD] Error reading host key file.");
                ret = WS_MEMORY_E;

            }

            if (ret == WS_SUCCESS) {
                if (wc_PemToDer(data, dataSz, PRIVATEKEY_TYPE, &der, NULL,
                                NULL, NULL) != 0) {
                    wolfSSH_Log(WS_LOG_DEBUG, "[SSHD] Failed to convert host "
                                "private key from PEM. Assuming key in DER "
                                "format.");
                    privBuf = data;
                    privBufSz = dataSz;
                }
                else {
                    privBuf = der->buffer;
                    privBufSz = der->length;
                }

                if (wolfSSH_CTX_UsePrivateKey_buffer(*ctx, privBuf, privBufSz,
                                                     WOLFSSH_FORMAT_ASN1) < 0) {
                    wolfSSH_Log(WS_LOG_ERROR,
                        "[SSHD] Failed to use host private key.");
                    ret = WS_BAD_ARGUMENT;
                }

                freeBufferFromFile(data, heap);
                wc_FreeDer(&der);
            }
        }
    }

#if defined(WOLFSSH_OSSH_CERTS) || defined(WOLFSSH_CERTS)
    if (ret == WS_SUCCESS) {
        /* TODO: Create a helper function that uses a file instead. */
        char* hostCert = wolfSSHD_ConfigGetHostCertFile(conf);

        if (hostCert != NULL) {
            byte*  data;
            word32 dataSz = 0;

            data = getBufferFromFile(hostCert, &dataSz, heap);
            if (data == NULL) {
                wolfSSH_Log(WS_LOG_ERROR,
                    "[SSHD] Error reading host key file.");
                ret = WS_MEMORY_E;

            }

            if (ret == WS_SUCCESS) {
            #ifdef WOLFSSH_OPENSSH_CERTS
                if (wolfSSH_CTX_UseOsshCert_buffer(*ctx, data, dataSz) < 0) {
                    wolfSSH_Log(WS_LOG_ERROR,
                        "[SSHD] Failed to use host certificate.");
                    ret = WS_BAD_ARGUMENT;
                }
            #endif
            #ifdef WOLFSSH_CERTS
                if (ret == WS_SUCCESS || ret == WS_BAD_ARGUMENT) {
                    ret = wolfSSH_CTX_UseCert_buffer(*ctx, data, dataSz,
                        WOLFSSH_FORMAT_PEM);
                    if (ret != WS_SUCCESS) {
                        ret = wolfSSH_CTX_UseCert_buffer(*ctx, data, dataSz,
                            WOLFSSH_FORMAT_ASN1);
                    }
                    if (ret != WS_SUCCESS) {
                        wolfSSH_Log(WS_LOG_ERROR,
                            "[SSHD] Failed to load in host certificate.");
                    }
                }
            #endif

                freeBufferFromFile(data, heap);
            }
        }
    }
#endif /* WOLFSSH_OSSH_CERTS || WOLFSSH_CERTS */

#ifdef WOLFSSH_CERTS
    if (ret == WS_SUCCESS) {
        char* caCert = wolfSSHD_ConfigGetUserCAKeysFile(conf);
        if (caCert != NULL) {
            byte*  data;
            word32 dataSz = 0;


            wolfSSH_Log(WS_LOG_INFO, "[SSHD] Using CA keys file %s", caCert);
            data = getBufferFromFile(caCert, &dataSz, heap);
            if (data == NULL) {
                wolfSSH_Log(WS_LOG_ERROR,
                    "[SSHD] Error reading CA cert file.");
                ret = WS_MEMORY_E;

            }

            if (ret == WS_SUCCESS) {
                ret = wolfSSH_CTX_AddRootCert_buffer(*ctx, data, dataSz,
                    WOLFSSH_FORMAT_PEM);
                if (ret != WS_SUCCESS) {
                    ret = wolfSSH_CTX_AddRootCert_buffer(*ctx, data, dataSz,
                        WOLFSSH_FORMAT_ASN1);
                }
                if (ret != WS_SUCCESS) {
                #ifdef WOLFSSH_OPENSSH_CERTS
                    wolfSSH_Log(WS_LOG_INFO,
                        "[SSHD] Continuing on in case CA is openssh "
                        "style.");
                    ret = WS_SUCCESS;
                #else
                    wolfSSH_Log(WS_LOG_ERROR,
                        "[SSHD] Failed to load in CA certificate.");
                #endif
                }

                freeBufferFromFile(data, heap);
            }
        }
    }
#endif

    if (ret == WS_SUCCESS) {
        wolfSSH_SetUserAuthTypes(*ctx, DefaultUserAuthTypes);
    }

    /* @TODO Load in host public key */

    /* Set allowed connection type, i.e. public key / password */

    (void)heap;
    return ret;
}

#ifndef _WIN32
/* return 1 if set, 0 if not set and negative values on error */
static int SetupChroot(WOLFSSHD_CONFIG* usrConf)
{
    int ret = 0;
    char* chrootPath;

    /* check for chroot set */
    chrootPath = wolfSSHD_ConfigGetChroot(usrConf);
    if (chrootPath != NULL) {
        ret = 1;
        wolfSSH_Log(WS_LOG_INFO, "[SSHD] chroot to path  %s", chrootPath);
        if (chdir(chrootPath) != 0) {
            wolfSSH_Log(WS_LOG_ERROR,
                "[SSHD] chdir to chroot path failed, %s", chrootPath);
            ret = WS_FATAL_ERROR;
        }
        if (chroot(chrootPath) != 0) {
            wolfSSH_Log(WS_LOG_ERROR,
                "[SSHD] chroot failed to path %s", chrootPath);
            ret = WS_FATAL_ERROR;
        }
        if (chdir("/") != 0) {
            wolfSSH_Log(WS_LOG_ERROR,
                "[SSHD] chdir after chroot failed");
            ret = WS_FATAL_ERROR;
        }
   }
    return ret;
}
#endif

#ifdef WOLFSSH_SCP
static int SCP_Subsystem(WOLFSSHD_CONNECTION* conn, WOLFSSH* ssh,
    WPASSWD* pPasswd, WOLFSSHD_CONFIG* usrConf)
{
    int ret   = WS_SUCCESS;
    int error = WS_SUCCESS;
    int select_ret = 0;

#ifndef _WIN32
    /* temporarily elevate permissions to get users information */
    if (wolfSSHD_AuthRaisePermissions(conn->auth) != WS_SUCCESS) {
        wolfSSH_Log(WS_LOG_ERROR,
            "[SSHD] Failure to raise permissions for auth");
        return WS_FATAL_ERROR;
    }

    /* set additional groups if needed */
    if (wolfSSHD_AuthSetGroups(conn->auth, wolfSSH_GetUsername(ssh),
            pPasswd->pw_gid) != WS_SUCCESS) {
        wolfSSH_Log(WS_LOG_ERROR, "[SSHD] Error setting groups");
        ret = WS_FATAL_ERROR;
    }

    if (ret == WS_SUCCESS) {
        error = SetupChroot(usrConf);
        if (error < 0) {
            ret = error; /* error case with setup chroot */
        }
    }

    if (wolfSSHD_AuthReducePermissionsUser(conn->auth, pPasswd->pw_uid,
            pPasswd->pw_gid) != WS_SUCCESS) {
        wolfSSH_Log(WS_LOG_ERROR, "[SSHD] Error setting user ID");
        if (wolfSSHD_AuthReducePermissions(conn->auth) != WS_SUCCESS) {
            /* stop everything if not able to reduce permissions level */
            exit(1);
        }

        return WS_FATAL_ERROR;
    }
#else
    /* impersonate the logged on user for file permissions */
    if (ImpersonateLoggedOnUser(wolfSSHD_GetAuthToken(conn->auth)) == FALSE) {
        wolfSSH_Log(WS_LOG_ERROR,
            "[SSHD] Error impersonating logged on user");
        ret = WS_FATAL_ERROR;
    }
#endif

    if (ret == WS_SUCCESS) {
        ret = wolfSSH_accept(ssh);
        error = wolfSSH_get_error(ssh);
        while (ret != WS_SUCCESS && ret != WS_SCP_COMPLETE
                && (error == WS_WANT_READ || error == WS_WANT_WRITE)) {

            select_ret = tcp_select(conn->fd, 1);
            if (select_ret == WS_SELECT_RECV_READY  ||
                select_ret == WS_SELECT_ERROR_READY ||
                error      == WS_WANT_WRITE)
            {
                ret = wolfSSH_accept(ssh);
                error = wolfSSH_get_error(ssh);
            }
            else if (select_ret == WS_SELECT_TIMEOUT)
                error = WS_WANT_READ;
            else
                error = WS_FATAL_ERROR;
        }
    }

    if (ret != WS_SUCCESS && ret != WS_SCP_COMPLETE) {
        wolfSSH_Log(WS_LOG_ERROR,
            "[SSHD] Failed to finish SCP operation from IP %s",
            conn->ip);
    }

    (void)conn;
#ifdef _WIN32
    /* stop impersonating the user */
    RevertToSelf();
#endif
    return ret;
}
#endif /* WOLFSSH_SCP */

#ifdef WOLFSSH_SFTP
#define TEST_SFTP_TIMEOUT 1
#define TEST_SFTP_TIMEOUT_NONE 0

/* handle SFTP operations
 * returns WS_SUCCESS on success
 */
static int SFTP_Subsystem(WOLFSSHD_CONNECTION* conn, WOLFSSH* ssh,
    WPASSWD* pPasswd, WOLFSSHD_CONFIG* usrConf)
{
    int ret   = WS_SUCCESS;
    int error = WS_SUCCESS;
    WS_SOCKET_T sockfd;
    int select_ret = 0;
    int timeout = TEST_SFTP_TIMEOUT_NONE;
    byte peek_buf[1];

#ifndef _WIN32
    /* temporarily elevate permissions to get users information */
    if (wolfSSHD_AuthRaisePermissions(conn->auth) != WS_SUCCESS) {
        wolfSSH_Log(WS_LOG_ERROR,
            "[SSHD] Failure to raise permissions for auth");
        return WS_FATAL_ERROR;
    }

    /* set additional groups if needed */
    if (wolfSSHD_AuthSetGroups(conn->auth, wolfSSH_GetUsername(ssh),
            pPasswd->pw_gid) != WS_SUCCESS) {
        wolfSSH_Log(WS_LOG_ERROR, "[SSHD] Error setting groups");
        ret = WS_FATAL_ERROR;
    }

    if (ret == WS_SUCCESS) {
        error = SetupChroot(usrConf);
        if (error == 1) {
            /* chroot was executed */
            if (wolfSSH_SFTP_SetDefaultPath(ssh, "/") != WS_SUCCESS) {
                wolfSSH_Log(WS_LOG_ERROR,
                        "[SSHD] Error setting SFTP default path");
                ret = WS_FATAL_ERROR;
            }
        }
        else if (error < 0) {
            ret = error; /* error case with setup chroot */
        }
    }


    /* set starting SFTP directory */
    if (ret == WS_SUCCESS) {
        WDIR dir;

        /* if home directory exists than set it as the default */
        if (WOPENDIR(NULL, NULL, &dir, pPasswd->pw_dir) == 0) {
            if (wolfSSH_SFTP_SetDefaultPath(ssh, pPasswd->pw_dir)
                    != WS_SUCCESS) {
                wolfSSH_Log(WS_LOG_ERROR,
                    "[SSHD] Error setting SFTP default home path");
                ret = WS_FATAL_ERROR;
            }
            WCLOSEDIR(NULL, &dir);
        }
    }

    if (wolfSSHD_AuthReducePermissionsUser(conn->auth, pPasswd->pw_uid,
            pPasswd->pw_gid) != WS_SUCCESS) {
        wolfSSH_Log(WS_LOG_ERROR, "[SSHD] Error setting user ID");
        if (wolfSSHD_AuthReducePermissions(conn->auth) != WS_SUCCESS) {
            /* stop everything if not able to reduce permissions level */
            exit(1);
        }

        return WS_FATAL_ERROR;
    }
#else
    char r[MAX_PATH];
    size_t rSz = 0;
    WCHAR h[MAX_PATH];

    ret = wolfSSHD_GetHomeDirectory(conn->auth, ssh, h, MAX_PATH);

    /* convert home directory from wchar type to char */
    if (ret == WS_SUCCESS) {
        if (wcstombs_s(&rSz, r, MAX_PATH, h, MAX_PATH - 1) != 0) {
            ret = WS_FATAL_ERROR;
        }
    }

    if (ret == WS_SUCCESS) {
        wolfSSH_Log(WS_LOG_INFO,
            "[SSHD] Using directory %s for SFTP connection", r);
        if (wolfSSH_SFTP_SetDefaultPath(ssh, r) != WS_SUCCESS) {
            wolfSSH_Log(WS_LOG_ERROR,
                "[SSHD] Error setting SFTP default home path");
            ret = WS_FATAL_ERROR;
        }
    }

    /* impersonate the logged on user for file permissions */
    if (ImpersonateLoggedOnUser(wolfSSHD_GetAuthToken(conn->auth)) == FALSE) {
        wolfSSH_Log(WS_LOG_ERROR,
            "[SSHD] Error impersonating logged on user");
        ret = WS_FATAL_ERROR;
    }
#endif

    if (ret == WS_SUCCESS) {
        sockfd = (WS_SOCKET_T)wolfSSH_get_fd(ssh);
        do {
            if (wolfSSH_SFTP_PendingSend(ssh)) {
                /* Yes, process the SFTP data. */
                ret = wolfSSH_SFTP_read(ssh);
                error = wolfSSH_get_error(ssh);
                timeout = (ret == WS_REKEYING) ?
                    TEST_SFTP_TIMEOUT : TEST_SFTP_TIMEOUT_NONE;
                if (error == WS_WANT_READ || error == WS_WANT_WRITE ||
                    error == WS_CHAN_RXD || error == WS_REKEYING ||
                    error == WS_WINDOW_FULL)
                    ret = error;
                if (error == WS_WANT_WRITE && wolfSSH_SFTP_PendingSend(ssh)) {
                    continue; /* no need to spend time attempting to pull data
                                * if there is still pending sends */
                }
                if (error == WS_EOF) {
                    break;
                }
            }

            select_ret = tcp_select(sockfd, timeout);
            if (select_ret == WS_SELECT_ERROR_READY) {
                break;
            }

            if (ret == WS_WANT_READ || ret == WS_WANT_WRITE ||
                    select_ret == WS_SELECT_RECV_READY) {
                ret = wolfSSH_worker(ssh, NULL);
                error = wolfSSH_get_error(ssh);
                if (ret == WS_REKEYING) {
                    /* In a rekey, keeping turning the crank. */
                    timeout = TEST_SFTP_TIMEOUT;
                    continue;
                }

                if (error == WS_WANT_READ || error == WS_WANT_WRITE ||
                    error == WS_WINDOW_FULL) {
                    timeout = TEST_SFTP_TIMEOUT;
                    ret = error;
                    continue;
                }

                if (error == WS_EOF) {
                    break;
                }
                if (ret != WS_SUCCESS && ret != WS_CHAN_RXD) {
                    /* If not successful and no channel data, leave. */
                    break;
                }
            }

            ret = wolfSSH_stream_peek(ssh, peek_buf, sizeof(peek_buf));
            if (ret > 0) {
                /* Yes, process the SFTP data. */
                ret = wolfSSH_SFTP_read(ssh);
                error = wolfSSH_get_error(ssh);
                timeout = (ret == WS_REKEYING) ?
                    TEST_SFTP_TIMEOUT : TEST_SFTP_TIMEOUT_NONE;
                if (error == WS_WANT_READ || error == WS_WANT_WRITE ||
                    error == WS_CHAN_RXD || error == WS_REKEYING ||
                    error == WS_WINDOW_FULL)
                    ret = error;
                if (error == WS_EOF)
                    break;
                continue;
            }
            else if (ret == WS_REKEYING) {
                timeout = TEST_SFTP_TIMEOUT;
                continue;
            }
            else if (ret < 0) {
                error = wolfSSH_get_error(ssh);
                if (error == WS_EOF)
                    break;
            }

            if (ret == WS_FATAL_ERROR && error == 0) {
                WOLFSSH_CHANNEL* channel =
                    wolfSSH_ChannelNext(ssh, NULL);
                if (channel && wolfSSH_ChannelGetEof(channel)) {
                    ret = 0;
                    break;
                }
            }

        } while (ret != WS_FATAL_ERROR);
    }

    (void)conn;
#ifdef _WIN32
    /* stop impersonating the user */
    RevertToSelf();
#endif
    return ret;
}
#endif


#ifdef WOLFSSH_SHELL

#ifndef MAX_COMMAND_SZ
#define MAX_COMMAND_SZ 80
#endif

#ifdef WIN32

/* handles creating a new shell env. and maintains SSH connection for incoming
 * user input as well as output of the shell.
 * return WS_SUCCESS on success */
static int SHELL_Subsystem(WOLFSSHD_CONNECTION* conn, WOLFSSH* ssh,
    WPASSWD* pPasswd, WOLFSSHD_CONFIG* usrConf, const char* subCmd)
{
    BOOL ret;
    word32 shellChannelId = 0;
#ifndef EXAMPLE_BUFFER_SZ
#define EXAMPLE_BUFFER_SZ 4096
#endif
    byte shellBuffer[EXAMPLE_BUFFER_SZ];
    int cnt_r, cnt_w;
    HANDLE ptyIn = NULL, ptyOut = NULL;
    HANDLE cnslIn = NULL, cnslOut = NULL;
    STARTUPINFOEX ext;
    PCWSTR sysCmd = L"c:\\windows\\system32\\cmd.exe";
#if 0
    /* start powershell instead */
    PCWSTR sysCmd = L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
#endif
    PWSTR cmd = NULL;
    size_t cmdSz = 0;
    PROCESS_INFORMATION processInfo;
    size_t sz = 0;
    WCHAR h[MAX_PATH];
    char* forcedCmd;

    forcedCmd = wolfSSHD_ConfigGetForcedCmd(usrConf);

    /* @TODO check for conpty support LoadLibrary()and GetProcAddress(). */

    if (forcedCmd != NULL && WSTRCMP(forcedCmd, "internal-sftp") == 0) {
        wolfSSH_Log(WS_LOG_ERROR,
            "[SSHD] Only SFTP connections allowed for user "
            "%s", wolfSSH_GetUsername(ssh));
        return WS_FATAL_ERROR;
    }

    ret = wolfSSHD_GetHomeDirectory(conn->auth, ssh, h, MAX_PATH);
    if (ret == WS_SUCCESS) {
        ZeroMemory(&ext, sizeof(STARTUPINFOEX));
        ZeroMemory(&processInfo, sizeof(PROCESS_INFORMATION));

        /* use forced command if set over subCmd */
        if (forcedCmd == NULL && subCmd != NULL) {
            forcedCmd = (char*)subCmd;
        }

        if (forcedCmd != NULL) { /* copy over set command if present */
             /* +1 for terminator and +2 for quotes */
            cmdSz = WSTRLEN(forcedCmd) + wcslen(sysCmd) + WSTRLEN(" /C ") + 3;
            cmd = (PWSTR)WMALLOC(sizeof(wchar_t) * cmdSz, NULL, DYNTYPE_SSHD);
            if (cmd == NULL) {
                ret = WS_MEMORY_E;
            }
            else {
                WCHAR* tmp = (WCHAR*)WMALLOC(sizeof(wchar_t) * cmdSz, NULL,
                    DYNTYPE_SSHD);
                if (tmp == NULL) {
                    ret = WS_MEMORY_E;
                }

                if (ret == WS_SUCCESS) {
                    size_t wr = 0;
                    if (mbstowcs_s(&wr, tmp, cmdSz, forcedCmd, cmdSz - 1) != 0) {
                        ret = WS_FATAL_ERROR;
                    }
                }

                if (ret == WS_SUCCESS) {
                    swprintf(cmd, cmdSz, L"%s /C %s", sysCmd, tmp);
                }

                if (tmp != NULL) {
                    WFREE(tmp, NULL, DYNTYPE_SSHD);
                }

                /* read in case a window-change packet might be queued */
                {
                    int rc;
                    word32 lastChannel = 0;

                    do {
                        rc = wolfSSH_worker(ssh, &lastChannel);
                        if (rc < 0) {
                            rc = wolfSSH_get_error(ssh);
                        }
                    } while (rc == WS_WANT_WRITE);
                }
            }
        }
        else { /* when set command is not present start 'cmd.exe' */
            cmdSz = wcslen(sysCmd) + 1; /* +1 for terminator */
            cmd = (PWSTR)WMALLOC(sizeof(wchar_t) * cmdSz, NULL, DYNTYPE_SSHD);
            if (cmd == NULL) {
                ret = WS_MEMORY_E;
            }
            else {
                wcscpy_s(cmd, cmdSz, sysCmd);
            }
        }
    }

    if (ImpersonateLoggedOnUser(wolfSSHD_GetAuthToken(conn->auth)) == FALSE) {
        ret = WS_FATAL_ERROR;
    }

    if (ret == WS_SUCCESS) {
        SECURITY_ATTRIBUTES saAttr;

        ZeroMemory(&saAttr, sizeof(saAttr));
        saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
        saAttr.bInheritHandle = TRUE;
        saAttr.lpSecurityDescriptor = NULL;

        if (CreatePipe(&cnslIn, &ptyIn, &saAttr, 0) != TRUE) {
            ret = WS_FATAL_ERROR;
        }

        if (CreatePipe(&ptyOut, &cnslOut, &saAttr, 0) != TRUE) {
            ret = WS_FATAL_ERROR;
        }
    }

    if (ret == WS_SUCCESS) {
        STARTUPINFOW si;
        PCWSTR conCmd = L"wolfsshd.exe -r ";
        PWSTR conCmdPtr;
        size_t conCmdSz;

        SetHandleInformation(ptyIn, HANDLE_FLAG_INHERIT, 0);
        SetHandleInformation(ptyOut, HANDLE_FLAG_INHERIT, 0);

        wolfSSH_SetTerminalResizeCtx(ssh, (void*)&ptyIn);

        conCmdSz = wcslen(conCmd) + cmdSz + 3;
            /* +1 for terminator, +2 for quotes */
        conCmdPtr = (PWSTR)WMALLOC(sizeof(wchar_t) * conCmdSz,
                NULL, DYNTYPE_SSHD);
        if (conCmdPtr == NULL) {
            ret = WS_MEMORY_E;
        }
        else {
            _snwprintf_s(conCmdPtr, conCmdSz, conCmdSz,
                L"wolfsshd.exe -r \"%s\"", cmd);
        }

        ZeroMemory(&si, sizeof(si));
        si.cb = sizeof(si);

        si.hStdInput  = cnslIn;
        si.hStdOutput = cnslOut;
        si.hStdError  = cnslOut;
        si.dwFlags    = STARTF_USESTDHANDLES;
        si.lpDesktop  = NULL;

        if (CreateProcessAsUserW(wolfSSHD_GetAuthToken(conn->auth), NULL, conCmdPtr,
            NULL, NULL, TRUE, DETACHED_PROCESS, NULL, h,
            &si, &processInfo) != TRUE) {
            wolfSSH_Log(WS_LOG_ERROR,
                "[SSHD] Issue creating process, Windows error %d", GetLastError());
            return WS_FATAL_ERROR;
        }

        CloseHandle(cnslIn);
        CloseHandle(cnslOut);

        WFREE(conCmdPtr, NULL, DYNTYPE_SSHD);
    }

    if (ret == WS_SUCCESS) {
        char cmdWSize[20];
        int cmdWSizeSz = 20;
        DWORD wrtn = 0;

        wolfSSH_Log(WS_LOG_INFO, "[SSHD] Successfully created process for "
            "console, waiting for it to start");

        WaitForInputIdle(processInfo.hProcess, 1000);

        /* Send initial terminal size to pseudo console with VT control sequence */
        cmdWSizeSz = snprintf(cmdWSize, cmdWSizeSz, "\x1b[8;%d;%dt", ssh->heightRows, ssh->widthChar);
        if (WriteFile(ptyIn, cmdWSize, cmdWSizeSz, &wrtn, 0) != TRUE) {
            WLOG(WS_LOG_ERROR, "Issue with pseudo console resize");
            ret = WS_FATAL_ERROR;
        }
    }

    if (ret == WS_SUCCESS) {
        SOCKET sshFd;
        byte tmp[2];
        fd_set readFds;
        WS_SOCKET_T maxFd;
        int pending = 0;
        int readPending = 0;
        int rc = 0;
        DWORD processState;
        DWORD ava;
        struct timeval t;

        t.tv_sec = 0;
        t.tv_usec = 800;

        sshFd = wolfSSH_get_fd(ssh);
        maxFd = sshFd;

        FD_ZERO(&readFds);
        FD_SET(sshFd, &readFds);

        do {
            /* @TODO currently not blocking till data comes in */
            if (PeekNamedPipe(ptyOut, NULL, 0, NULL, &ava, NULL) == TRUE) {
                if (ava > 0) {
                    readPending = 1;
                }
            }

            if (readPending == 0) {
                /* check if process is still running before waiting to read */
                if (GetExitCodeProcess(processInfo.hProcess, &processState)
                    == TRUE) {
                    if (processState != STILL_ACTIVE) {
                        wolfSSH_Log(WS_LOG_INFO,
                            "[SSHD] Process has exited, exit state = %d, "
                            "close down SSH connection", processState);
                        Sleep(100); /* give the stdout/stderr of process a
                                     * little time to write to pipe */
                        if (PeekNamedPipe(ptyOut, NULL, 0, NULL, &ava, NULL)
                            == TRUE) {
                            if (ava > 0) {
                                /* if data still pending then continue
                                 * sending it over SSH */
                                readPending = 1;
                                continue;
                            }
                        }
                        break;
                    }
                }
                if (wolfSSH_stream_peek(ssh, tmp, 1) <= 0) {
                    rc = select((int)maxFd + 1, &readFds, NULL, NULL, &t);
                    if (rc == -1) {
                        wolfSSH_Log(WS_LOG_INFO,
                            "[SSHD] select call waiting on socket failed");
                        break;
                    }
                    /* when select times out and no socket is set as ready
                       Windows overwrites readFds with 0. Reset the fd here
                       for next select call */
                    if (rc == 0) {
                        FD_SET(sshFd, &readFds);
                    }
                }
                else {
                    pending = 1;
                }
            }

            if (rc != 0 && (pending || FD_ISSET(sshFd, &readFds))) {
                word32 lastChannel = 0;

                /* The following tries to read from the first channel inside
                   the stream. If the pending data in the socket is for
                   another channel, this will return an error with id
                   WS_CHAN_RXD. That means the agent has pending data in its
                   channel. The additional channel is only used with the
                   agent. */
                cnt_r = wolfSSH_worker(ssh, &lastChannel);
                if (cnt_r < 0) {
                    rc = wolfSSH_get_error(ssh);
                    if (rc == WS_CHAN_RXD) {
                        if (lastChannel == shellChannelId) {
                            cnt_r = wolfSSH_ChannelIdRead(ssh,
                                shellChannelId, shellBuffer,
                                sizeof shellBuffer);
                            if (cnt_r <= 0)
                                break;
                            pending = 0;
                            if (WriteFile(ptyIn, shellBuffer, cnt_r, &cnt_r,
                                NULL) != TRUE) {
                                wolfSSH_Log(WS_LOG_INFO,
                                    "[SSHD] Error writing to pipe for "
                                    "console");
                                break;
                            }
                        }
                    }
                    else if (rc == WS_CHANNEL_CLOSED) {
                        continue;
                    }
                    else if (rc != WS_WANT_READ) {
                        break;
                    }
                }
            }

            if (readPending) {
                WMEMSET(shellBuffer, 0, EXAMPLE_BUFFER_SZ);

                if (ReadFile(ptyOut, shellBuffer, EXAMPLE_BUFFER_SZ, &cnt_r,
                    NULL) != TRUE) {
                    wolfSSH_Log(WS_LOG_INFO,
                        "[SSHD] Error reading from pipe for console");
                    break;
                }
                else {
                    readPending = 0;
                    if (cnt_r > 0) {
                        cnt_w = wolfSSH_ChannelIdSend(ssh, shellChannelId,
                            shellBuffer, cnt_r);
                        if (cnt_w < 0)
                            break;
                    }
                }
            }
        } while (1);

        if (cmd != NULL) {
            WFREE(cmd, NULL, DYNTYPE_SSHD);
        }
        wolfSSH_Log(WS_LOG_INFO,
            "[SSHD] Closing down process for console");

        if (ext.lpAttributeList != NULL) {
            HeapFree(GetProcessHeap(), 0, ext.lpAttributeList);
        }

        if (wolfSSH_SetExitStatus(ssh, processState) !=
            WS_SUCCESS) {
            wolfSSH_Log(WS_LOG_ERROR, "[SSHD] Issue sending childs exit "
                "status");
        }

        CloseHandle(processInfo.hThread);
        CloseHandle(wolfSSHD_GetAuthToken(conn->auth));
    }

    RevertToSelf();
    return ret;
}
#else
#if defined(HAVE_SYS_IOCTL_H)
    #include <sys/ioctl.h>
#endif

/* handles creating a new shell env. and maintains SSH connection for incoming
 * user input as well as output of the shell.
 * return WS_SUCCESS on success */
static int SHELL_Subsystem(WOLFSSHD_CONNECTION* conn, WOLFSSH* ssh,
    WPASSWD* pPasswd, WOLFSSHD_CONFIG* usrConf, const char* subCmd)
{
    WS_SOCKET_T sshFd = 0;
    int rc;
    WS_SOCKET_T childFd = 0;
    int stdoutPipe[2], stderrPipe[2];
    pid_t childPid;

#ifndef EXAMPLE_BUFFER_SZ
    #define EXAMPLE_BUFFER_SZ 4096
#endif
#ifndef MAX_IDLE_COUNT
    #define MAX_IDLE_COUNT 2
#endif
    byte shellBuffer[EXAMPLE_BUFFER_SZ];
    byte channelBuffer[EXAMPLE_BUFFER_SZ];
    char* forcedCmd;
    int   windowFull = 0; /* Contains size of bytes from shellBuffer that did
                           * not get passed on to wolfSSH yet. This happens
                           * with window full errors or when rekeying.  */
    int   wantWrite  = 0;
    int   peerConnected = 1;
    int   stdoutEmpty = 0;

    childFd = -1;
    stdoutPipe[0] = -1;
    stdoutPipe[1] = -1;
    stderrPipe[0] = -1;
    stderrPipe[1] = -1;

    forcedCmd = wolfSSHD_ConfigGetForcedCmd(usrConf);

    /* do not overwrite a forced command with 'exec' sub shell. Only set the
     * 'exec' command when no forced command is set */
    if (forcedCmd == NULL) {
        forcedCmd = (char*)subCmd;
    }

    if (forcedCmd != NULL && WSTRCMP(forcedCmd, "internal-sftp") == 0) {
        wolfSSH_Log(WS_LOG_ERROR,
                                "[SSHD] Only SFTP connections allowed for user "
                                "%s", wolfSSH_GetUsername(ssh));
        return WS_FATAL_ERROR;
    }

    /* temporarily elevate permissions to get users information */
    if (wolfSSHD_AuthRaisePermissions(conn->auth) != WS_SUCCESS) {
        wolfSSH_Log(WS_LOG_ERROR, "[SSHD] Failure to raise permissions for auth");
        return WS_FATAL_ERROR;
    }

    /* create pipes for stdout and stderr */
    if (forcedCmd) {
        if (pipe(stdoutPipe) != 0) {
            wolfSSH_Log(WS_LOG_ERROR, "[SSHD] Issue creating stdout pipe");
            return WS_FATAL_ERROR;
        }
        if (pipe(stderrPipe) != 0) {
            close(stdoutPipe[0]);
            close(stderrPipe[1]);
            wolfSSH_Log(WS_LOG_ERROR, "[SSHD] Issue creating stderr pipe");
            return WS_FATAL_ERROR;
        }
    }

    ChildRunning = 1;
    childPid = forkpty(&childFd, NULL, NULL, NULL);
    if (childPid < 0) {
        /* forkpty failed, so return */
        ChildRunning = 0;
        wolfSSH_Log(WS_LOG_ERROR, "[SSHD] Issue creating new forkpty");
        return WS_FATAL_ERROR;
    }
    else if (childPid == 0) {
        /* Child process */
        const char *args[] = {"-sh", NULL, NULL, NULL};
        char cmd[MAX_COMMAND_SZ];
        char shell[MAX_COMMAND_SZ];
        int ret;

        signal(SIGINT,  SIG_DFL);
        signal(SIGCHLD, SIG_DFL);

        if (forcedCmd) {
            close(stdoutPipe[0]);
            close(stderrPipe[0]);
            stdoutPipe[0] = -1;
            stderrPipe[0] = -1;
            if (dup2(stdoutPipe[1], STDOUT_FILENO) == -1) {
                wolfSSH_Log(WS_LOG_ERROR,
                    "[SSHD] Error redirecting stdout pipe");
                if (wolfSSHD_AuthReducePermissions(conn->auth) != WS_SUCCESS) {
                    exit(1);
                }

                return WS_FATAL_ERROR;
            }
            if (dup2(stderrPipe[1], STDERR_FILENO) == -1) {
                wolfSSH_Log(WS_LOG_ERROR,
                    "[SSHD] Error redirecting stderr pipe");
                if (wolfSSHD_AuthReducePermissions(conn->auth) != WS_SUCCESS) {
                    exit(1);
                }

                return WS_FATAL_ERROR;
            }
        }

        /* set additional groups if needed */
        if (wolfSSHD_AuthSetGroups(conn->auth, wolfSSH_GetUsername(ssh),
                pPasswd->pw_gid) != WS_SUCCESS) {
            wolfSSH_Log(WS_LOG_ERROR, "[SSHD] Error setting groups");
            if (wolfSSHD_AuthReducePermissions(conn->auth) != WS_SUCCESS) {
                /* stop everything if not able to reduce permissions level */
                exit(1);
            }

            return WS_FATAL_ERROR;
        }

        rc = SetupChroot(usrConf);
        if (rc < 0) {
            wolfSSH_Log(WS_LOG_ERROR, "[SSHD] Error setting chroot");
            if (wolfSSHD_AuthReducePermissions(conn->auth) != WS_SUCCESS) {
                /* stop everything if not able to reduce permissions level */
                exit(1);
            }

            return WS_FATAL_ERROR;
        }
        else if (rc == 1) {
            rc = chdir("/");
            if (rc != 0) {
                wolfSSH_Log(WS_LOG_ERROR,
                    "[SSHD] Error going to / after chroot");
                if (wolfSSHD_AuthReducePermissions(conn->auth) != WS_SUCCESS) {
                    /* stop everything if not able to reduce permissions level */
                    exit(1);
                }

                return WS_FATAL_ERROR;
            }
        }

        if (wolfSSHD_AuthReducePermissionsUser(conn->auth, pPasswd->pw_uid,
            pPasswd->pw_gid) != WS_SUCCESS) {
            wolfSSH_Log(WS_LOG_ERROR, "[SSHD] Error setting user ID");
            if (wolfSSHD_AuthReducePermissions(conn->auth) != WS_SUCCESS) {
                /* stop everything if not able to reduce permissions level */
                exit(1);
            }

            return WS_FATAL_ERROR;
        }

        setenv("HOME", pPasswd->pw_dir, 1);
        setenv("LOGNAME", pPasswd->pw_name, 1);
        setenv("SHELL", pPasswd->pw_shell, 1);

        if (pPasswd->pw_shell) {
            if (WSTRLEN(pPasswd->pw_shell) < sizeof(shell)) {
                char* cursor;
                char* start;

                WSTRNCPY(shell, pPasswd->pw_shell, sizeof(shell));
                cursor = shell;
                do {
                    start = cursor;
                    *cursor = '-';
                    cursor = WSTRCHR(start, '/');
                } while (cursor && *cursor != '\0');
                args[0] = start;
            }
        }

        rc = chdir(pPasswd->pw_dir);
        if (rc != 0) {
            /* not error'ing out if unable to find home directory */
            wolfSSH_Log(WS_LOG_ERROR, "[SSHD] Error going to user home dir %s",
            pPasswd->pw_dir);
        }

        /* default to /bin/sh if user shell is not set */
        if (pPasswd->pw_shell && WSTRLEN(pPasswd->pw_shell)) {
            WSNPRINTF(cmd, sizeof(cmd), "%s", pPasswd->pw_shell);
        }
        else {
            WSNPRINTF(cmd, sizeof(cmd), "%s", "/bin/sh");
        }

        errno = 0;
        if (forcedCmd) {
            args[1] = "-c";
            args[2] = forcedCmd;
            ret = execv(cmd, (char**)args);
            close(stdoutPipe[1]);
            close(stderrPipe[1]);
        }
        else {
            ret = execv(cmd, (char**)args);
        }
        if (ret && errno) {
            wolfSSH_Log(WS_LOG_ERROR, "[SSHD] Issue opening shell");
            exit(1);
        }
        exit(ret); /* exit child process and close down SSH connection */
    }

    if (wolfSSHD_AuthReducePermissionsUser(conn->auth, pPasswd->pw_uid,
        pPasswd->pw_gid) != WS_SUCCESS) {
        wolfSSH_Log(WS_LOG_ERROR, "[SSHD] Error setting user ID");
        if (wolfSSHD_AuthReducePermissions(conn->auth) != WS_SUCCESS) {
            /* stop everything if not able to reduce permissions level */
            exit(1);
        }

        return WS_FATAL_ERROR;
    }
    sshFd = wolfSSH_get_fd(ssh);

    struct termios tios;
    word32 shellChannelId = 0;
    signal(SIGCHLD, ChildSig);
    signal(SIGINT, SIG_DFL);

    rc = tcgetattr(childFd, &tios);
    if (rc != 0) {
        return WS_FATAL_ERROR;
    }
    rc = tcsetattr(childFd, TCSAFLUSH, &tios);
    if (rc != 0) {
        return WS_FATAL_ERROR;
    }

    /* set initial size of terminal based on saved size */
#if defined(HAVE_SYS_IOCTL_H)
    wolfSSH_DoModes(ssh->modes, ssh->modesSz, childFd);
    {
        struct winsize s;

        WMEMSET(&s, 0, sizeof(s));
        s.ws_col = ssh->widthChar;
        s.ws_row = ssh->heightRows;
        s.ws_xpixel = ssh->widthPixels;
        s.ws_ypixel = ssh->heightPixels;

        ioctl(childFd, TIOCSWINSZ, &s);
    }
#endif

    wolfSSH_SetTerminalResizeCtx(ssh, (void*)&childFd);
    if (forcedCmd) {
        close(stdoutPipe[1]);
        close(stderrPipe[1]);
    }

    while (ChildRunning || windowFull || !stdoutEmpty || peerConnected) {
        byte tmp[2];
        fd_set readFds;
        fd_set writeFds;
        WS_SOCKET_T maxFd;
        int cnt_r;
        int cnt_w;
        int pending = 0;

        FD_ZERO(&readFds);
        FD_SET(sshFd, &readFds);
        maxFd = sshFd;

        FD_ZERO(&writeFds);
        if (windowFull || wantWrite) {
            FD_SET(sshFd, &writeFds);
        }

        /* select on stdout/stderr pipes with forced commands */
        if (forcedCmd) {
            FD_SET(stdoutPipe[0], &readFds);
            if (stdoutPipe[0] > maxFd)
                maxFd = stdoutPipe[0];

            FD_SET(stderrPipe[0], &readFds);
            if (stderrPipe[0] > maxFd)
                maxFd = stderrPipe[0];
        }
        else {
            FD_SET(childFd, &readFds);
            if (childFd > maxFd)
                maxFd = childFd;
        }

        if (wolfSSH_stream_peek(ssh, tmp, 1) <= 0) {
            rc = select((int)maxFd + 1, &readFds, &writeFds, NULL, NULL);
            if (rc == -1)
                break;
        }
        else {
            pending = 1; /* found some pending SSH data */
        }

        if (wantWrite || windowFull || pending || FD_ISSET(sshFd, &readFds)) {
            word32 lastChannel = 0;

            wantWrite = 0;
            /* The following tries to read from the first channel inside
               the stream. If the pending data in the socket is for
               another channel, this will return an error with id
               WS_CHAN_RXD. That means the agent has pending data in its
               channel. The additional channel is only used with the
               agent. */
            cnt_r = wolfSSH_worker(ssh, &lastChannel);
            if (cnt_r < 0) {
                rc = wolfSSH_get_error(ssh);
                if (rc == WS_CHAN_RXD) {
                    if (!windowFull) { /* don't rewrite channeldBuffer if full
                                        * of windowFull left overs */
                        if (lastChannel == shellChannelId) {
                            cnt_r = wolfSSH_ChannelIdRead(ssh, shellChannelId,
                                channelBuffer,
                                sizeof channelBuffer);
                            if (cnt_r <= 0)
                                break;
                            cnt_w = (int)write(childFd,
                                    channelBuffer, cnt_r);
                            if (cnt_w <= 0)
                                break;
                        }
                    }
                }
                else if (rc == WS_CHANNEL_CLOSED) {
                    peerConnected = 0;
                    continue;
                }
                else if (rc == WS_WANT_WRITE) {
                    wantWrite = 1;
                    continue;
                }
                else if (rc == WS_REKEYING) {
                    wantWrite = 1;
                    continue;
                }
                else if (rc != WS_WANT_READ) {
                    break;
                }
            }
        }

        /* if the window was previously full, try resending the data */
        if (windowFull) {
            cnt_w = wolfSSH_ChannelIdSend(ssh, shellChannelId,
                    shellBuffer, windowFull);
            if (cnt_w == WS_WINDOW_FULL || cnt_w == WS_REKEYING) {
                continue;
            }
            else if (cnt_w == WS_WANT_WRITE) {
                wantWrite = 1;
                continue;
            }
            else {
                windowFull -= cnt_w;
                if (windowFull > 0) {
                    WMEMMOVE(shellBuffer, shellBuffer + cnt_w, windowFull);
                    continue;
                }
                if (windowFull < 0)
                    windowFull = 0;
            }
        }

        if (forcedCmd) {
            if (FD_ISSET(stderrPipe[0], &readFds)) {
                cnt_r = (int)read(stderrPipe[0], shellBuffer,
                    sizeof shellBuffer);
                /* This read will return 0 on EOF */
                if (cnt_r <= 0) {
                    int err = errno;
                    if (err != EAGAIN && err != 0) {
                        break;
                    }
                }
                else {
                    if (cnt_r > 0) {
                        cnt_w = wolfSSH_extended_data_send(ssh, shellBuffer,
                            cnt_r);
                        if (cnt_w > 0 && cnt_w < cnt_r) { /* partial send */
                            windowFull = cnt_r - cnt_w;
                            WMEMMOVE(shellBuffer, shellBuffer + cnt_w,
                                windowFull);
                        }
                        else if (cnt_w == WS_WINDOW_FULL ||
                                 cnt_w == WS_REKEYING) {
                            windowFull = cnt_r; /* save amount to be sent */
                            continue;
                        }
                        else if (cnt_w == WS_WANT_WRITE) {
                            wantWrite = 1;
                            continue;
                        }
                        else if (cnt_w < 0)
                            break;
                    }
                }
            }

            /* handle stdout */
            if (FD_ISSET(stdoutPipe[0], &readFds)) {
                cnt_r = (int)read(stdoutPipe[0], shellBuffer,
                    sizeof shellBuffer);
                /* This read will return 0 on EOF */
                if (cnt_r < 0) {
                    int err = errno;
                    if (err != EAGAIN && err != 0) {
                        break;
                    }
                }
                else if (cnt_r == 0) {
                    stdoutEmpty = 1;
                }
                else {
                    if (cnt_r > 0) {
                        cnt_w = wolfSSH_ChannelIdSend(ssh, shellChannelId,
                                shellBuffer, cnt_r);
                        if (cnt_w > 0 && cnt_w < cnt_r) { /* partial send */
                            windowFull = cnt_r - cnt_w;
                            WMEMMOVE(shellBuffer, shellBuffer + cnt_w,
                                windowFull);
                        }
                        else if (cnt_w == WS_WINDOW_FULL ||
                                 cnt_w == WS_REKEYING) {
                            windowFull = cnt_r; /* save amount to be sent */
                            continue;
                        }
                        else if (cnt_w == WS_WANT_WRITE) {
                            wantWrite = 1;
                            continue;
                        }
                        else if (cnt_w < 0) {
                            kill(childPid, SIGINT);
                            break;
                        }
                    }
                }
            }
        }
        else {
            if (FD_ISSET(childFd, &readFds)) {
                cnt_r = (int)read(childFd, shellBuffer, sizeof shellBuffer);
                /* This read will return 0 on EOF */
                if (cnt_r <= 0) {
                    int err = errno;
                    if (err != EAGAIN && err != 0) {
                        break;
                    }
                }
                else {
                    if (cnt_r > 0) {
                        cnt_w = wolfSSH_ChannelIdSend(ssh, shellChannelId,
                                shellBuffer, cnt_r);
                        if (cnt_w > 0 && cnt_w < cnt_r) { /* partial send */
                            windowFull = cnt_r - cnt_w;
                            WMEMMOVE(shellBuffer, shellBuffer + cnt_w,
                                windowFull);
                        }
                        else if (cnt_w == WS_WINDOW_FULL ||
                                 cnt_w == WS_REKEYING) {
                            windowFull = cnt_r;
                            continue;
                        }
                        else if (cnt_w == WS_WANT_WRITE) {
                            wantWrite = 1;
                            continue;
                        }
                        else if (cnt_w < 0) {
                            kill(childPid, SIGINT);
                            break;
                        }
                    }
                }
            }
        }

        if (!ChildRunning && peerConnected && stdoutEmpty && !windowFull) {
            peerConnected = 0;
        }
    }

    /* get return value of child process */
    {
        int waitStatus;

        do {
            rc = waitpid(childPid, &waitStatus, 0);
            /* if the waitpid experinced an interupt then try again */
        } while (rc < 0 && errno == EINTR);

        if (rc < 0) {
            wolfSSH_Log(WS_LOG_ERROR, "[SSHD] Issue waiting for childs exit "
                    "status");
        }
        else {
            if (wolfSSH_SetExitStatus(ssh, (word32)WEXITSTATUS(waitStatus)) !=
                WS_SUCCESS) {
                wolfSSH_Log(WS_LOG_ERROR, "[SSHD] Issue setting childs exit "
                    "status");
            }
        }
    }

    /* check for any left over data in pipes then close them */
    if (forcedCmd) {
        int readSz;

        fcntl(stdoutPipe[0], F_SETFL, fcntl(stdoutPipe[0], F_GETFL)
            | O_NONBLOCK);
        readSz = (int)read(stdoutPipe[0], shellBuffer, sizeof shellBuffer);
        if (readSz > 0) {
            wolfSSH_ChannelIdSend(ssh, shellChannelId, shellBuffer, readSz);
        }

        fcntl(stderrPipe[0], F_SETFL, fcntl(stderrPipe[0], F_GETFL)
            | O_NONBLOCK);
        readSz = (int)read(stderrPipe[0], shellBuffer, sizeof shellBuffer);
        if (readSz > 0) {
            wolfSSH_extended_data_send(ssh, shellBuffer, readSz);
        }
        close(stdoutPipe[0]);
        close(stderrPipe[0]);
    }

    (void)conn;
    return WS_SUCCESS;
}
#endif
#endif

#ifdef WIN32
static volatile int timeOut = 0;
#else
static __thread int timeOut = 0;
#endif
static void alarmCatch(int signum)
{
    timeOut = 1;
    (void)signum;
}

static int UserAuthResult(byte result,
        WS_UserAuthData* authData, void* userAuthResultCtx)
{
    (void)authData;
    (void)userAuthResultCtx;

    if (result == WOLFSSH_USERAUTH_SUCCESS) {
    #ifndef WIN32
        /* @TODO alarm catch on windows */
        alarm(0);
    #endif
    }

    return WS_SUCCESS;
}

/* handle wolfSSH accept and directing to correct subsystem */
#ifdef _WIN32
static DWORD HandleConnection(void* arg)
#else
static void* HandleConnection(void* arg)
#endif
{
    int ret = WS_SUCCESS;
    int error;

    WOLFSSHD_CONNECTION* conn = NULL;
    WOLFSSH* ssh = NULL;

    if (arg == NULL) {
        ret = WS_BAD_ARGUMENT;
    }

    if (ret == WS_SUCCESS) {
        conn = (WOLFSSHD_CONNECTION*)arg;
        ssh = wolfSSH_new(conn->ctx);
        if (ssh == NULL) {
            wolfSSH_Log(WS_LOG_ERROR,
                "[SSHD] Failed to create new WOLFSSH struct");
            ret = -1;
        }
    }

    if (ret == WS_SUCCESS) {
        int select_ret = 0;
        long graceTime;

        wolfSSH_set_fd(ssh, conn->fd);
        wolfSSH_SetUserAuthCtx(ssh, conn->auth);

        /* set alarm for login grace time */
        graceTime = wolfSSHD_AuthGetGraceTime(conn->auth);
        if (graceTime > 0) {
    #ifdef WIN32
            /* @TODO SetTimer(NULL, NULL, graceTime, alarmCatch); */
    #else
            signal(SIGALRM, alarmCatch);
            alarm((unsigned int)graceTime);
    #endif
        }

        ret = wolfSSH_accept(ssh);
        error = wolfSSH_get_error(ssh);
        while (timeOut == 0 && (ret != WS_SUCCESS
                && ret != WS_SCP_INIT && ret != WS_SFTP_COMPLETE)
                && (error == WS_WANT_READ || error == WS_WANT_WRITE)) {

            select_ret = tcp_select(conn->fd, 1);
            if (select_ret == WS_SELECT_RECV_READY  ||
                select_ret == WS_SELECT_ERROR_READY ||
                error      == WS_WANT_WRITE)
            {
                ret = wolfSSH_accept(ssh);
                error = wolfSSH_get_error(ssh);
            }
            else if (select_ret == WS_SELECT_TIMEOUT)
                error = WS_WANT_READ;
            else
                error = WS_FATAL_ERROR;
        }

        wolfSSH_Log(WS_LOG_ERROR,
                    "[SSHD] grace time = %ld timeout = %d", graceTime, timeOut);
        if (graceTime > 0) {
            if (timeOut) {
                wolfSSH_Log(WS_LOG_ERROR,
                    "[SSHD] Failed login within grace period");
             }

    #ifdef WIN32
            /* @TODO SetTimer(NULL, NULL, graceTime, alarmCatch); */
    #else
            alarm(0); /* cancel any alarm */
    #endif
        }

        if (ret != WS_SUCCESS && ret != WS_SFTP_COMPLETE &&
            ret != WS_SCP_INIT) {
            wolfSSH_Log(WS_LOG_ERROR,
                "[SSHD] Failed to accept WOLFSSH connection from %s error %d",
                conn->ip, ret);
        }
    }

    if (ret == WS_SUCCESS || ret == WS_SFTP_COMPLETE || ret == WS_SCP_INIT) {
        WPASSWD* pPasswd = NULL;
        WOLFSSHD_CONFIG* usrConf;
        char* usr;

        /* get configuration for user */
        usr     = wolfSSH_GetUsername(ssh);
        usrConf = wolfSSHD_AuthGetUserConf(conn->auth, usr, NULL, NULL,
            NULL, NULL, NULL);
        if (usrConf == NULL) {
            wolfSSH_Log(WS_LOG_ERROR,
                "[SSHD] Error getting user configuration");
            ret = WS_FATAL_ERROR;
        }

    #ifndef WIN32
        if (ret == WS_SUCCESS || ret == WS_SFTP_COMPLETE ||
            ret == WS_SCP_INIT) {
            pPasswd = getpwnam((const char *)usr);
            if (pPasswd == NULL) {
                wolfSSH_Log(WS_LOG_ERROR, "[SSHD] Error getting user info");
                ret = WS_FATAL_ERROR;
            }
        }
    #endif

        if (ret != WS_FATAL_ERROR) {
            /* check for any forced command set for the user */
            switch (wolfSSH_GetSessionType(ssh)) {
                case WOLFSSH_SESSION_SHELL:
                #ifdef WOLFSSH_SHELL
                    if (ret == WS_SUCCESS) {
                        wolfSSH_Log(WS_LOG_INFO, "[SSHD] Entering new shell");
                        SHELL_Subsystem(conn, ssh, pPasswd, usrConf, NULL);
                    }
                #else
                    wolfSSH_Log(WS_LOG_ERROR,
                        "[SSHD] Shell support is disabled");
                    ret = WS_NOT_COMPILED;
                #endif
                    break;

                case WOLFSSH_SESSION_SUBSYSTEM:
                    /* test for known subsystems */
                    switch (ret) {
                        case WS_SFTP_COMPLETE:
                        #ifdef WOLFSSH_SFTP
                            ret = SFTP_Subsystem(conn, ssh, pPasswd, usrConf);
                        #else
                            err_sys("SFTP not compiled in. Please use "
                                    "--enable-sftp");
                        #endif
                            break;

                        case WS_SCP_INIT:
                        #ifdef WOLFSSH_SCP
                            ret = SCP_Subsystem(conn, ssh, pPasswd, usrConf);
                        #else
                            err_sys("SCP not compiled in. Please use "
                                    "--enable-scp");
                        #endif
                            break;

                        default:
                            wolfSSH_Log(WS_LOG_ERROR,
                                "[SSHD] Unknown or build not supporting sub"
                                "system found [%s]",
                                wolfSSH_GetSessionCommand(ssh));
                            ret = WS_NOT_COMPILED;
                    }
                    break;

                case WOLFSSH_SESSION_UNKNOWN:
                case WOLFSSH_SESSION_EXEC:
                #if defined(WOLFSSH_SHELL)
                    if (ret == WS_SUCCESS) {
                        wolfSSH_Log(WS_LOG_INFO,
                            "[SSHD] Entering exec session [%s]",
                                wolfSSH_GetSessionCommand(ssh));
                        SHELL_Subsystem(conn, ssh, pPasswd, usrConf,
                                wolfSSH_GetSessionCommand(ssh));
                    }
                #endif /* WOLFSSH_SHELL */

                    /* SCP can be an exec type */
                    if (ret == WS_SCP_INIT) {
                    #ifdef WOLFSSH_SCP
                        ret = SCP_Subsystem(conn, ssh, pPasswd, usrConf);
                    #else
                        err_sys("SCP not compiled in. Please use "
                                "--enable-scp");
                    #endif
                    }
                    break;

                case WOLFSSH_SESSION_TERMINAL:
                default:
                    wolfSSH_Log(WS_LOG_ERROR,
                        "[SSHD] Unknown or build not supporting session type "
                        "found");
                    ret = WS_NOT_COMPILED;
            }
        }
    }

    error = wolfSSH_get_error(ssh);
    if (error != WS_SOCKET_ERROR_E && error != WS_FATAL_ERROR) {
        wolfSSH_Log(WS_LOG_INFO, "[SSHD] Attempting to close down connection");
        ret = wolfSSH_shutdown(ssh);

        /* peer hung up, stop shutdown */
        if (ret == WS_SOCKET_ERROR_E) {
            ret = 0;
        }

        error = wolfSSH_get_error(ssh);
        if (error != WS_SOCKET_ERROR_E &&
                (error == WS_WANT_READ || error == WS_WANT_WRITE)) {
            int maxAttempt = 10; /* make 10 attempts max before giving up */
            int attempt;

            for (attempt = 0; attempt < maxAttempt; attempt++) {
                ret = wolfSSH_worker(ssh, NULL);
                error = wolfSSH_get_error(ssh);

                /* peer succesfully closed down gracefully */
                if (ret == WS_CHANNEL_CLOSED) {
                    ret = 0;
                    break;
                }

                /* peer hung up, stop shutdown */
                if (ret == WS_SOCKET_ERROR_E) {
                    ret = 0;
                    break;
                }

                if (ret == WS_FATAL_ERROR &&
                   (error != WS_WANT_READ &&
                    error != WS_WANT_WRITE)) {
                    break;
                }
            #ifdef _WIN32
                Sleep(1);
            #else
                usleep(100000);
            #endif
            }

            if (attempt == maxAttempt) {
                wolfSSH_Log(WS_LOG_INFO,
                    "[SSHD] Gave up on gracefull shutdown, closing the socket");
            }
        }
    }

    /* check if there is a response to the shutdown */
    wolfSSH_free(ssh);
    if (conn != NULL) {
        byte sc[1024];
        shutdown(conn->fd, 1);
        /* Spin until socket closes. */
        do {
            ret = (int)recv(conn->fd, sc, 1024, 0);
        } while (ret > 0);

        WCLOSESOCKET(conn->fd);
    }
    wolfSSH_Log(WS_LOG_INFO, "[SSHD] Return from closing connection = %d", ret);
    WFREE(conn, NULL, DYNTYPE_SSHD);

#ifdef _WIN32
    return 0;
#else
    return NULL;
#endif
}


/* returns WS_SUCCESS on success */
static int NewConnection(WOLFSSHD_CONNECTION* conn)
{

    int ret = WS_SUCCESS;
#ifndef WIN32
    int pd = 0;

    pd = fork();
    if (pd < 0) {
        wolfSSH_Log(WS_LOG_ERROR, "[SSHD] Issue spawning new process");
        ret = -1;
    }

    if (ret == WS_SUCCESS) {
        if (pd == 0) {
            /* child process */
            WCLOSESOCKET(conn->listenFd);
            signal(SIGINT, SIG_DFL);
            (void)HandleConnection((void*)conn);
            exit(0);
        }
        else {
            /* do not wait for status of child process, and signal that the
               child can be reaped to avoid zombie processes when running in
               the foreground */
            signal(SIGCHLD, SIG_IGN);

            wolfSSH_Log(WS_LOG_INFO, "[SSHD] Spawned new process %d\n", pd);
            WCLOSESOCKET(conn->fd);
        }
    }
#else
    HANDLE t;
    DWORD id;

    if (conn->isThreaded) {
        t = CreateThread(NULL, 0, HandleConnection, (void*)conn, 0, &id);
        if (t == NULL) {
            wolfSSH_Log(WS_LOG_ERROR, "[SSHD] Issue creating new thread");
            ret = WS_FATAL_ERROR;
        }
        else {
            wolfSSH_Log(WS_LOG_INFO, "[SSHD] Spawned new thread %d\n", id);
            CloseHandle(t);
        }
    }
    else {
        HandleConnection((void*)conn);
    }
#endif

    return ret;
}


/* return non zero value for a pending connection */
static int PendingConnection(WS_SOCKET_T fd)
{
    int ret;
    struct timeval t;
    fd_set r, w, e;
    WS_SOCKET_T nfds = fd + 1;

    t.tv_usec = 0;
    t.tv_sec  = WOLFSSHD_TIMEOUT;

    FD_ZERO(&r);
    FD_ZERO(&w);
    FD_ZERO(&e);

    FD_SET(fd, &r);
    errno = 0;
    ret = select((int)nfds, &r, &w, &e, &t);
    if (ret < 0) {
        /* a socket level issue happend, could just be a system call int. */
        if (errno != EINTR) {
            wolfSSH_Log(WS_LOG_ERROR, "[SSHD] TCP socket error on select()");
            quit = 1;
        }
        ret  = 0;
    }
    else if (ret > 0) {
        if (FD_ISSET(fd, &r)) {
            wolfSSH_Log(WS_LOG_INFO, "[SSHD] Incoming TCP data found");
        }
        else {
            wolfSSH_Log(WS_LOG_INFO, "[SSHD] Found TCP write or error data");
            ret = 0; /* nothing to read */
        }
    }
    return ret;
}

int   myoptind = 0;
char* myoptarg = NULL;

#ifdef _WIN32
#include <tchar.h>
#include <shellapi.h>

SERVICE_STATUS        serviceStatus = { 0 };
SERVICE_STATUS_HANDLE serviceStatusHandle = NULL;
HANDLE                serviceStop = INVALID_HANDLE_VALUE;

#define WOLFSSHD_SERVICE_NAME  _T("wolfSSHd")


static void wolfSSHD_ServiceCb(DWORD CtrlCode)
{
    switch (CtrlCode) {
        case SERVICE_CONTROL_STOP:
            if (serviceStatus.dwCurrentState != SERVICE_RUNNING)
                break;
            serviceStatus.dwControlsAccepted = 0;
            serviceStatus.dwCurrentState = SERVICE_STOP_PENDING;
            serviceStatus.dwWin32ExitCode = 0;
            serviceStatus.dwCheckPoint = 4;

            if (SetServiceStatus(serviceStatusHandle, &serviceStatus) == FALSE) {
                wolfSSH_Log(WS_LOG_ERROR, "[SSHD] Issue setting service status");
            }

            /* send out signal that the service is stopping */
            SetEvent(serviceStop);
            break;

        default:
            break;
    }
}


static char* _convertHelper(WCHAR* in, void* heap) {
    int retSz;
    char* ret;
    
    retSz = (int)wcslen(in) * 2;
    ret   = (char*)WMALLOC(retSz + 1, heap, DYNTYPE_SSHD);
    if (ret != NULL) {
        size_t numConv = 0;
        if (wcstombs_s(&numConv, ret, retSz, in, retSz) != 0) {
            WFREE(ret, heap, DYNTYPE_SSHD);
            ret = NULL;
        }
    }
    return ret;
}

static void StartSSHD(DWORD argc, LPTSTR* wargv)
#else
static int StartSSHD(int argc, char** argv)
#endif
{
    int ret = WS_SUCCESS;
    word16 port = 0;
    WS_SOCKET_T listenFd = 0;
    int ch;
    WOLFSSHD_CONFIG* conf = NULL;
    WOLFSSHD_AUTH* auth = NULL;
    WOLFSSH_CTX* ctx = NULL;
    byte isDaemon = 1;
    byte testMode = 0;

    const char* configFile = "/etc/ssh/sshd_config";
    const char* hostKeyFile = NULL;
    byte* banner = NULL;

    logFile = stderr;
    wolfSSH_SetLoggingCb(wolfSSHDLoggingCb);
#ifdef DEBUG_WOLFSSL
    wolfSSL_Debugging_ON();
#endif

#ifdef _WIN32
    char** argv = NULL;
    DWORD i;
    LPWSTR* cmdArgs = NULL;
    LPWSTR cmdLn;
    int cmdArgC = 0;

    /* get what the command line was and parse arguments from it */
    cmdLn   = GetCommandLineW();
    cmdArgs = CommandLineToArgvW(cmdLn, &cmdArgC);
    if (cmdArgs == NULL) {
        ret = WS_FATAL_ERROR;
    }
    argc = cmdArgC;

    if (ret == WS_SUCCESS) {
        for (i = 0; i < argc; i++) {
            if (WSTRCMP((char*)(cmdArgs[i]), "-D") == 0) {
                isDaemon = 0;
            }
        }
    }

    if (isDaemon) {
        /* Set the logging to go to OutputDebugString */
        wolfSSH_SetLoggingCb(ServiceDebugCb);

        if (ret == WS_SUCCESS) {
            /* we want the arguments to be normal char strings not wchar_t */
            argv = (char**)WMALLOC(argc * sizeof(char*), NULL, DYNTYPE_SSHD);
            if (argv == NULL) {
                ret = WS_MEMORY_E;
            }
            else {
                unsigned int z;
                for (z = 0; z < argc; z++) {
                    argv[z] = _convertHelper(cmdArgs[z], NULL);
                }
            }
        }
    }
    else {
        argv = (char**)wargv;
    }
#endif

    signal(SIGINT, interruptCatch);
    WSTARTTCP();

    if (ret == WS_SUCCESS) {
        wolfSSH_Init();
    }

    if (ret == WS_SUCCESS) {
        conf = wolfSSHD_ConfigNew(NULL);
        if (conf == NULL) {
            ret = WS_MEMORY_E;
        }
    }

    while ((ch = mygetopt(argc, argv, "?f:p:h:dDE:o:t")) != -1) {
        switch (ch) {
        case 'f':
            configFile = myoptarg;
            break;

        case 'p':
            if (ret == WS_SUCCESS) {
                if (myoptarg == NULL) {
                    ret = WS_BAD_ARGUMENT;
                    break;
                }

                ret = XATOI(myoptarg);
                if (ret < 0) {
                    fprintf(stderr, "Issue parsing port number %s\n",
                        myoptarg);
                    ret = WS_BAD_ARGUMENT;
                }
                else {
                    if (ret <= (word16)-1) {
                        port = (word16)ret;
                        ret = WS_SUCCESS;
                    }
                    else {
                        fprintf(stderr, "Port number %d too big.\n", ret);
                        ret = WS_BAD_ARGUMENT;
                    }
                }
            }
            break;

        case 'h':
            hostKeyFile = myoptarg;
            break;

        case 'd':
            debugMode = 1; /* turn on debug mode */
            break;

        case 'D':
            isDaemon = 0;
            break;

        case 'E':
            ret = WFOPEN(NULL, &logFile, myoptarg, "ab");
            if (ret != 0 || logFile == WBADFILE) {
                fprintf(stderr, "Unable to open log file %s\n", myoptarg);
                ret = WS_FATAL_ERROR;
            }
            break;

        case 'o':
        #ifdef WOLFSSH_IGNORE_UNKNOWN_CONFIG
            wolfSSH_Log(WS_LOG_DEBUG, "[SSHD] ignoring -o.");
            break;
        #else
            ShowUsage();
            #ifndef _WIN32
            return WS_FATAL_ERROR;
            #else
            return;
            #endif
        #endif

        case 't':
            testMode = 1;
            break;

        case '?':
            ShowUsage();
        #ifndef _WIN32
            return WS_SUCCESS;
        #else
            return;
        #endif

        default:
            ShowUsage();
        #ifndef _WIN32
            return WS_SUCCESS;
        #else
            return;
        #endif
        }
    }

    if (ret == WS_SUCCESS) {
        ret = wolfSSHD_ConfigLoad(conf, configFile);
        if (ret != WS_SUCCESS) {
            wolfSSH_Log(WS_LOG_ERROR, "Error reading in configure file %s\n",
                configFile);
        }
    }

    /* port was not overridden with argument, read from config file */
    if (ret == WS_SUCCESS && port == 0) {
        port = wolfSSHD_ConfigGetPort(conf);
    }

    /* check if host key file was passed in */
    if (hostKeyFile != NULL) {
        wolfSSHD_ConfigSetHostKeyFile(conf, hostKeyFile);
    }

    if (ret == WS_SUCCESS) {
        wolfSSH_Log(WS_LOG_INFO, "[SSHD] Starting wolfSSH SSHD application");
        ret = SetupCTX(conf, &ctx, &banner);
    }

    if (ret == WS_SUCCESS) {
        auth = wolfSSHD_AuthCreateUser(NULL, conf);
        if (auth == NULL) {
            wolfSSH_Log(WS_LOG_ERROR, "[SSHD] Issue creating auth struct");
            ret = WS_MEMORY_E;
        }
    }

    if (logFile == NULL) {
        logFile = stderr;
    }

    /* run as a daemon or service */
#ifndef WIN32
    if (ret == WS_SUCCESS && isDaemon) {
        pid_t p;

#ifdef __unix__
        /* Daemonizing in POSIX, so set a syslog based log */
        if (logFile == stderr) {
            wolfSSH_SetLoggingCb(SyslogCb);
        }
#endif
        p = fork();
        if (p < 0) {
            fprintf(stderr, "Failed to fork process\n");
            exit(EXIT_FAILURE);
        }
        if (p > 0) {
            exit(EXIT_SUCCESS); /* stop parent process */
        }

        if (setsid() < 0) {
            fprintf(stderr, "Failed to set a new session");
            ret = WS_FATAL_ERROR;
        }
        else {
            signal(SIGCHLD, ConnClose);
            p = fork();
            if (p < 0) {
                fprintf(stderr, "Failed to fork process\n");
                exit(EXIT_FAILURE);
            }
            if (p > 0) {
                exit(EXIT_SUCCESS);
            }

            umask(0);
            if (chdir("/") < 0) {
                ret = WS_FATAL_ERROR;
            }

            if (ret == WS_SUCCESS) {
                int fd;

                fd = open("/dev/null", O_RDWR);
                if (fd < 0) {
                    ret = WS_FATAL_ERROR;
                }
                else {
                    if (dup2(fd, STDIN_FILENO) < 0 ||
                        dup2(fd, STDOUT_FILENO) < 0 ||
                        dup2(fd, STDERR_FILENO) < 0) {
                        ret = WS_FATAL_ERROR;
                    }
                    close(fd);
                }
            }
        }
    }
#else
    if (isDaemon) {
        /* Set function to handle service query and commands */
        serviceStatusHandle = RegisterServiceCtrlHandler(WOLFSSHD_SERVICE_NAME, wolfSSHD_ServiceCb);
        if (serviceStatusHandle == NULL) {
            ret = WS_FATAL_ERROR;
        }
        else {
            /* Update service status as 'start pending' */
            ZeroMemory(&serviceStatus, sizeof(serviceStatus));
            serviceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
            serviceStatus.dwCurrentState = SERVICE_START_PENDING;
            if (SetServiceStatus(serviceStatusHandle, &serviceStatus) == FALSE) {
                wolfSSH_Log(WS_LOG_ERROR, "[SSHD] Issue updating service status");
            }
        }
        if (ret == WS_SUCCESS) {
            /* Create a stop event to watch on */
            serviceStop = CreateEvent(NULL, TRUE, FALSE, NULL);
            if (serviceStop == NULL) {
                serviceStatus.dwControlsAccepted = 0;
                serviceStatus.dwCurrentState = SERVICE_STOPPED;
                serviceStatus.dwWin32ExitCode = GetLastError();
                serviceStatus.dwCheckPoint = 1;

                if (SetServiceStatus(serviceStatusHandle, &serviceStatus) == FALSE) {
                    wolfSSH_Log(WS_LOG_ERROR, "[SSHD] Issue updating service status");
                }
                return;
            }
        }
        if (cmdArgs != NULL) {
            LocalFree(cmdArgs);
        }
    }
#endif

    if (ret == WS_SUCCESS && !testMode) {
        wolfSSHD_ConfigSavePID(conf);
        wolfSSH_Log(WS_LOG_INFO, "[SSHD] Starting to listen on port %d", port);
        tcp_listen(&listenFd, &port, 1);
        wolfSSH_Log(WS_LOG_INFO, "[SSHD] Listening on port %d", port);
        if (wolfSSHD_AuthReducePermissions(auth) != WS_SUCCESS) {
            wolfSSH_Log(WS_LOG_INFO, "[SSHD] Error lowering permissions level");
            ret = WS_FATAL_ERROR;
        }

    #ifdef WIN32
        if (ret == WS_SUCCESS && isDaemon) {
            /* update service status as started */
            serviceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
            serviceStatus.dwCurrentState = SERVICE_RUNNING;
            serviceStatus.dwWin32ExitCode = 0;
            serviceStatus.dwCheckPoint = 0;

            if (SetServiceStatus(serviceStatusHandle, &serviceStatus) == FALSE) {
                wolfSSH_Log(WS_LOG_ERROR, "[SSHD] Issue updating service status");
            }
        }
    #endif
        /* wait for incoming connections and fork them off */
        while (ret == WS_SUCCESS && quit == 0) {
            WOLFSSHD_CONNECTION* conn;
#ifdef WOLFSSL_NUCLEUS
            struct addr_struct clientAddr;
#else
            struct sockaddr_in6 clientAddr;
            socklen_t           clientAddrSz = sizeof(clientAddr);
#endif
            conn = (WOLFSSHD_CONNECTION*)WMALLOC(sizeof(WOLFSSHD_CONNECTION), NULL, DYNTYPE_SSHD);
            if (conn == NULL) {
                wolfSSH_Log(WS_LOG_ERROR, "[SSHD] Failed to malloc memory for connection");
                break;
            }

            conn->auth = auth;
            conn->listenFd = (int)listenFd;
            conn->isThreaded = isDaemon;

            /* wait for a connection */
            if (PendingConnection(listenFd)) {
                conn->ctx = ctx;
#ifdef WOLFSSL_NUCLEUS
                conn->fd = NU_Accept(listenFd, &clientAddr, 0);
#else
                conn->fd = (int)accept(listenFd, (struct sockaddr*)&clientAddr,
                    &clientAddrSz);
                if (conn->fd >= 0) {
                    if (clientAddr.sin6_family == AF_INET) {
                        struct sockaddr_in* addr4 =
                            (struct sockaddr_in*)&clientAddr;
                        inet_ntop(AF_INET, &addr4->sin_addr, conn->ip,
                              INET_ADDRSTRLEN);
                    }
                    else if (clientAddr.sin6_family == AF_INET6) {
                        inet_ntop(AF_INET6, &clientAddr.sin6_addr, conn->ip,
                              INET6_ADDRSTRLEN);
                    }
                }
#endif

                {
#ifdef USE_WINDOWS_API
                    unsigned long blocking = 1;
                    if (ioctlsocket(conn->fd, FIONBIO, &blocking)
                        == SOCKET_ERROR) {
                        WLOG(WS_LOG_DEBUG, "wolfSSH non-fatal error: "
                                "ioctlsocket failed");
                        WCLOSESOCKET(conn->fd);
                        WFREE(conn, NULL, DYNTYPE_SSHD);
                        continue;
                    }
#elif defined(WOLFSSL_MDK_ARM) || defined(WOLFSSL_KEIL_TCP_NET) \
                        || defined (WOLFSSL_TIRTOS)|| defined(WOLFSSL_VXWORKS) || \
                        defined(WOLFSSL_NUCLEUS)
                    /* non blocking not supported, for now */
#else
                    int flags = fcntl(conn->fd, F_GETFL, 0);
                    if (flags < 0) {
                        WLOG(WS_LOG_DEBUG, "wolfSSH non-fatal error: "
                                "fcntl get failed");
                        WCLOSESOCKET(conn->fd);
                        WFREE(conn, NULL, DYNTYPE_SSHD);
                        continue;
                    }
                    flags = fcntl(conn->fd, F_SETFL, flags | O_NONBLOCK);
                    if (flags < 0) {
                        WLOG(WS_LOG_DEBUG, "wolfSSH non-fatal error: "
                                "fcntl set failed");
                        WCLOSESOCKET(conn->fd);
                        WFREE(conn, NULL, DYNTYPE_SSHD);
                        continue;
                    }
#endif
                }
                ret = NewConnection(conn);
            }
#ifdef _WIN32
            /* check if service has been shutdown */
            if (isDaemon && WaitForSingleObject(serviceStop, 0) == WAIT_OBJECT_0) {
                quit = 1;
            }
#endif
        }
    }

#ifdef _WIN32
    /* close down windows service */
    if (isDaemon) {
        CloseHandle(serviceStop);

        serviceStatus.dwControlsAccepted = 0;
        serviceStatus.dwCurrentState = SERVICE_STOPPED;
        serviceStatus.dwWin32ExitCode = 0;
        serviceStatus.dwCheckPoint = 3;

        if (serviceStatusHandle != NULL &&
            SetServiceStatus(serviceStatusHandle, &serviceStatus) == FALSE) {
            wolfSSH_Log(WS_LOG_ERROR, "[SSHD] Issue updating service status");
        }
    }
#endif

    CleanupCTX(conf, &ctx, &banner);
    if (banner) {
        WFREE(banner, NULL, DYNTYPE_STRING);
    }
    wolfSSHD_ConfigFree(conf);
    wolfSSHD_AuthFreeUser(auth);
    wolfSSH_Cleanup();

#ifdef _WIN32
    if (isDaemon) { /* free up temporary memory used for conversion of args from wchar_t */
        unsigned int z;
        for (z = 0; z < argc; z++) {
            WFREE(argv[z], NULL, DYNTYPE_SSHD);
        }
        WFREE(argv, NULL, DYNTYPE_SSHD);
    }
#else
    return 0;
#endif
}

#ifdef _WIN32
/* Used to setup a console and run command as a user.
 * returns the process exit value */
static int SetupConsole(char* inCmd)
{
    HANDLE sOut;
    HANDLE sIn;
    HPCON pCon = 0;
    COORD cord = { 80,24 }; /* Default to 80x24. Updated later. */
    STARTUPINFOEXW ext;
    int ret = WS_SUCCESS;
    PWSTR cmd    = NULL;
    size_t cmdSz = 0;
    PROCESS_INFORMATION processInfo;
    size_t sz = 0;
    DWORD processState = 0;
    PCSTR shellCmd = "c:\\windows\\system32\\cmd.exe";

    if (inCmd == NULL) {
        return -1;
    }

    sIn  = GetStdHandle(STD_INPUT_HANDLE);

    if (WSTRCMP(shellCmd, inCmd) != 0) {
        /* if not opening a shell, pipe virtual terminal sequences to 'nul' */
        if (CreatePseudoConsole(cord, sIn, INVALID_HANDLE_VALUE, 0, &pCon) != S_OK) {
            ret = WS_FATAL_ERROR;
        }
        else {
            CloseHandle(sIn);
        }
    }
    else
    {
        /* if opening a shell, pipe virtual terminal sequences back to calling process */
        sOut = GetStdHandle(STD_OUTPUT_HANDLE);
        if (CreatePseudoConsole(cord, sIn, sOut, 0, &pCon) != S_OK) {
            ret = WS_FATAL_ERROR;
        }
        else {
            CloseHandle(sIn);
            CloseHandle(sOut);
        }
    }

    /* setup startup extended info for pseudo terminal */
    ZeroMemory(&ext, sizeof(ext));
    if (ret == WS_SUCCESS) {
        ext.StartupInfo.cb = sizeof(STARTUPINFOEX);
        (void)InitializeProcThreadAttributeList(NULL, 1, 0, &sz);
        if (sz == 0) {
            ret = WS_FATAL_ERROR;
        }

        if (ret == WS_SUCCESS) {
            /* Using HeapAlloc for better support when possibly passing
               memory between Windows Modules */
            ext.lpAttributeList =
                (PPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, sz);
            if (ext.lpAttributeList == NULL) {
                ret = WS_FATAL_ERROR;
            }
        }

        if (ret == WS_SUCCESS) {
            if (InitializeProcThreadAttributeList(ext.lpAttributeList, 1, 0,
                &sz) != TRUE) {
                ret = WS_FATAL_ERROR;
            }
        }

        if (ret == WS_SUCCESS) {
            if (UpdateProcThreadAttribute(ext.lpAttributeList, 0,
                PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE,
                pCon, sizeof(HPCON), NULL, NULL) != TRUE) {
                ret = WS_FATAL_ERROR;
            }
        }
    }

    if (ret == WS_SUCCESS) {
        cmdSz = WSTRLEN(inCmd) + 1; /* +1 for terminator */
        cmd   = (PWSTR)HeapAlloc(GetProcessHeap(), 0, sizeof(wchar_t) * cmdSz);
        if (cmd == NULL) {
            ret = WS_MEMORY_E;
        }
        else {
            size_t numConv = 0;

            WMEMSET(cmd, 0, sizeof(wchar_t) * cmdSz);
            mbstowcs_s(&numConv, cmd, cmdSz, inCmd, strlen(inCmd));
        }
    }

    ZeroMemory(&processInfo, sizeof(processInfo));
    if (ret == WS_SUCCESS) {
        if (CreateProcessW(NULL, cmd,
            NULL, NULL, FALSE, EXTENDED_STARTUPINFO_PRESENT, NULL, NULL,
            &ext.StartupInfo, &processInfo) != TRUE) {
            return WS_FATAL_ERROR;
        }
        else {
            DWORD ava = 0;

            WaitForInputIdle(processInfo.hProcess, 1000);

            do {
                /* wait indefinitly for console process to exit */
                if (ava == 0) {
                    if (WaitForSingleObject(processInfo.hProcess, INFINITE) == WAIT_FAILED) {
                        break;
                    }
                }

                /* check if process is still running and give time to drain pipes */
                if (GetExitCodeProcess(processInfo.hProcess, &processState)
                    == TRUE) {
                    if (processState != STILL_ACTIVE) {
                        Sleep(100); /* give the stdout/stderr of process a
                                     * little time to write to pipe */
                        if (PeekNamedPipe(GetStdHandle(STD_OUTPUT_HANDLE), NULL, 0, NULL, &ava, NULL)
                            == TRUE) {
                            if (ava > 0) {
                                /* if data still pending then continue
                                 * sending it over SSH */
                                continue;
                            }
                        }
                        break;
                    }
                }
            } while (1);
            CloseHandle(processInfo.hThread);
        }
    }

    if (cmd != NULL) {
        HeapFree(GetProcessHeap(), 0, cmd);
    }

    if (ext.lpAttributeList != NULL) {
        HeapFree(GetProcessHeap(), 0, ext.lpAttributeList);
    }

    if (pCon != 0) {
        ClosePseudoConsole(pCon);
    }

    return processState;
}
#endif /* _WIN32 */

int main(int argc, char** argv)
{
#ifdef _WIN32
    /* First look if this is a service being started */
    int i, isService = 1;
    for (i = 0; i < argc; i++) {
        if (WSTRCMP(argv[i], "-D") == 0) {
            isService = 0;
        }
        if (WSTRCMP(argv[i], "-r") == 0) {
            if (argc < i + 1) {
                /* was expecting command to run after -r argument */
                return -1;
            }
            return SetupConsole(argv[i + 1]);
        }
    }

    if (isService) {
        SERVICE_TABLE_ENTRY ServiceTable[] =
        {
            {_T("wolfSSHd"), (LPSERVICE_MAIN_FUNCTION)StartSSHD},
            {NULL, NULL}
        };

        if (StartServiceCtrlDispatcher(ServiceTable) == FALSE) {
            printf("StartServiceCtrlDispatcher failed\n");
            return GetLastError();
        }
    }
    else {
        StartSSHD(argc, (LPTSTR*)argv);
    }
    return 0;
#else
    return StartSSHD(argc, argv);
#endif
}

#else

#include <stdio.h>

/* helpful print out if compiling without SSHD feature enabled */
int main(int argc, char** argv)
{
    printf("Not compiled in. Please recompile wolfSSH with :\n");
    printf("--enable-sshd (user_settings.h macro define WOLFSSH_SSHD\n");
    return -1;
}
#endif /* WOLFSSH_SSHD */

/* wolfsshd.c
 *
 * Copyright (C) 2014-2021 wolfSSL Inc.
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

#ifdef WOLFSSH_SSHD

#include <wolfssh/ssh.h>
#include <wolfssh/internal.h>
#include <wolfssh/log.h>
#include <wolfssl/wolfcrypt/wc_port.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#define WOLFSSH_TEST_SERVER
#include <wolfssh/test.h>

#include "wolfsshd.h"

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

/* catch interrupts and close down gracefully */
static volatile byte quit = 0;
static const char defaultBanner[] = "wolfSSHD\n";

/* Initial connection information to pass on to threads/forks */
typedef struct WOLFSSHD_CONNECTION {
    WOLFSSH_CTX* ctx;
    int          fd;
} WOLFSSHD_CONNECTION;

static void ShowUsage(void)
{
    printf("wolfsshd %s\n", LIBWOLFSSH_VERSION_STRING);
    printf(" -?             display this help and exit\n");
    printf(" -f <file name> Configuration file to use, default is /usr/locacl/etc/ssh/sshd_config\n");
    printf(" -p <int>       Port number to listen on\n");
}

static void interruptCatch(int in)
{
    (void)in;
    printf("Closing down wolfSSHD\n");
    quit = 1;
}

static void wolfSSHDLoggingCb(enum wolfSSH_LogLevel lvl, const char *const str)
{
    fprintf(stderr, "[PID %d]: %s\n", getpid(), str);
    (void)lvl;
}

static int wsUserAuth(byte authType,
                      WS_UserAuthData* authData,
                      void* ctx)
{
    if (ctx == NULL) {
        fprintf(stderr, "wsUserAuth: ctx not set");
        return WOLFSSH_USERAUTH_FAILURE;
    }

    if (authType != WOLFSSH_USERAUTH_PASSWORD &&
#ifdef WOLFSSH_ALLOW_USERAUTH_NONE
        authType != WOLFSSH_USERAUTH_NONE &&
#endif
        authType != WOLFSSH_USERAUTH_PUBLICKEY) {

        return WOLFSSH_USERAUTH_FAILURE;
    }

    (void)ctx;
    (void)authData;

    /* @TODO allows all connections */
    return WOLFSSH_USERAUTH_SUCCESS;
}


static int SetupCTX(WOLFSSHD_CONFIG* conf, WOLFSSH_CTX** ctx)
{
    int ret = WS_SUCCESS;
    const char* banner;

    /* create a new WOLFSSH_CTX */
    *ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_SERVER, NULL);
    if (ctx == NULL) {
        wolfSSH_Log(WS_LOG_ERROR, "[SSHD] Couldn't allocate SSH CTX data.");
        ret = WS_MEMORY_E;
    }

    /* setup authority callback for checking peer connections */
    if (ret == WS_SUCCESS) {
        wolfSSH_SetUserAuth(*ctx, wsUserAuth);
    }

    /* set banner to display on connection */
    if (ret == WS_SUCCESS) {
        banner = wolfSSHD_GetBanner(conf);
        if (banner == NULL) {
            banner = defaultBanner;
        }
        wolfSSH_CTX_SetBanner(*ctx, banner);
    }

#ifdef WOLFSSH_AGENT
    /* check if using an agent is enabled */
    if (ret == WS_SUCCESS) {
        wolfSSH_CTX_set_agent_cb(ctx, wolfSSH_AGENT_DefaultActions, NULL);
    }
#endif

#ifdef WOLFSSH_FWD
    /* check if port forwarding is enabled */
    if (ret == WS_SUCCESS) {
        wolfSSH_CTX_SetFwdCb(ctx, wolfSSH_FwdDefaultActions, NULL);
    }
#endif

    /* Load in host private key */
//    {
//        const char* bufName = NULL;
//        #ifndef WOLFSSH_SMALL_STACK
//            byte buf[EXAMPLE_KEYLOAD_BUFFER_SZ];
//        #endif
//        byte* keyLoadBuf;
//        word32 bufSz;
//
//        #ifdef WOLFSSH_SMALL_STACK
//            keyLoadBuf = (byte*)WMALLOC(EXAMPLE_KEYLOAD_BUFFER_SZ,
//                    NULL, 0);
//            if (keyLoadBuf == NULL) {
//                WEXIT(EXIT_FAILURE);
//            }
//        #else
//            keyLoadBuf = buf;
//        #endif
//        bufSz = EXAMPLE_KEYLOAD_BUFFER_SZ;
//
//        bufSz = load_key(peerEcc, keyLoadBuf, bufSz);
//        if (bufSz == 0) {
//            fprintf(stderr, "Couldn't load key file.\n");
//            WEXIT(EXIT_FAILURE);
//        }
//        if (wolfSSH_CTX_UsePrivateKey_buffer(ctx, keyLoadBuf, bufSz,
//                                             WOLFSSH_FORMAT_ASN1) < 0) {
//            fprintf(stderr, "Couldn't use key buffer.\n");
//            WEXIT(EXIT_FAILURE);
//        }
//
//    }

    /* Load in host public key */
//    {
//        if (userPubKey) {
//            byte* userBuf = NULL;
//            word32 userBufSz = 0;
//
//            /* get the files size */
//            load_file(userPubKey, NULL, &userBufSz);
//
//            /* create temp buffer and load in file */
//            if (userBufSz == 0) {
//                fprintf(stderr, "Couldn't find size of file %s.\n", userPubKey);
//                WEXIT(EXIT_FAILURE);
//            }
//
//            userBuf = (byte*)WMALLOC(userBufSz, NULL, 0);
//            if (userBuf == NULL) {
//                fprintf(stderr, "WMALLOC failed\n");
//                WEXIT(EXIT_FAILURE);
//            }
//            load_file(userPubKey, userBuf, &userBufSz);
//            LoadPublicKeyBuffer(userBuf, userBufSz, &pwMapList);
//        }
//
//        bufSz = (word32)WSTRLEN(samplePasswordBuffer);
//        WMEMCPY(keyLoadBuf, samplePasswordBuffer, bufSz);
//        keyLoadBuf[bufSz] = 0;
//        LoadPasswordBuffer(keyLoadBuf, bufSz, &pwMapList);
//
//        if (userEcc) {
//        #ifndef WOLFSSH_NO_ECC
//            bufName = samplePublicKeyEccBuffer;
//        #endif
//        }
//        else {
//        #ifndef WOLFSSH_NO_RSA
//            bufName = samplePublicKeyRsaBuffer;
//        #endif
//        }
//        if (bufName != NULL) {
//            bufSz = (word32)WSTRLEN(bufName);
//            WMEMCPY(keyLoadBuf, bufName, bufSz);
//            keyLoadBuf[bufSz] = 0;
//            LoadPublicKeyBuffer(keyLoadBuf, bufSz, &pwMapList);
//        }
//
//        bufSz = (word32)WSTRLEN(sampleNoneBuffer);
//        WMEMCPY(keyLoadBuf, sampleNoneBuffer, bufSz);
//        keyLoadBuf[bufSz] = 0;
//        LoadNoneBuffer(keyLoadBuf, bufSz, &pwMapList);
//
//        #ifdef WOLFSSH_SMALL_STACK
//            WFREE(keyLoadBuf, NULL, 0);
//        #endif
//    }

    /* Load in authorized keys */


    /* Set allowed connection type, i.e. public key / password */

    return ret;
}


#if 0
int SFTP_Subsystem()
{

}

int SCP_Subsystem()
{

}
#endif

//static int SHELL_Subsystem(WOLFSSHD_CONNECTION* conn, WOLFSSH* ssh)
//{
//    (void)conn;
//    (void)ssh;
//    return WS_SUCCESS;
//}


/* handle wolfSSH accept and directing to correct subsystem */
static void* wolfSSHD_HandleConnection(void* arg)
{
    int ret = WS_SUCCESS;

    WOLFSSHD_CONNECTION* conn = NULL;
    WOLFSSH* ssh = NULL;

    if (arg == NULL) {
        ret = BAD_FUNC_ARG;
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
        wolfSSH_set_fd(ssh, conn->fd);
        ret = wolfSSH_accept(ssh);
    }

    wolfSSH_free(ssh);
    if (conn != NULL) {
        WCLOSESOCKET(conn->fd);
    }
    return NULL;
}


/* returns WS_SUCCESS on success */
static int wolfSSHD_NewConnection(WOLFSSHD_CONNECTION* conn)
{
    int pd;
    int ret = WS_SUCCESS;

    pd = fork();
    if (pd < 0) {
        wolfSSH_Log(WS_LOG_ERROR, "[SSHD] Issue spawning new process");
        ret = -1;
    }

    if (pd == 0) {
        /* child process */
        (void)wolfSSHD_HandleConnection((void*)conn);
    }
    else {
        wolfSSH_Log(WS_LOG_INFO, "[SSHD] Spawned new process %d\n", pd);
    }

    return ret;
}


/* return non zero value for a pending connection */
static int wolfSSHD_PendingConnection(WS_SOCKET_T fd)
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
    ret = select(nfds, &r, &w, &e, &t);
    if (ret < 0) {
        /* a socket level issue happend */
        printf("Error waiting for connection on socket\n");
        quit = 1;
        ret  = 0;
    }
    else if (ret > 0) {
        if (FD_ISSET(fd, &r)) {
            printf("Connection found\n");
        }
        else {
            printf("Found write or error data\n");
            ret = 0; /* nothing to read */
        } 
    }
    //    printf("Timeout waiting for connection\n");
    return ret;
}


int   myoptind = 0;
char* myoptarg = NULL;

int main(int argc, char** argv)
{
    int ret  = WS_SUCCESS;
    word16 port = 0;
    WS_SOCKET_T listenFd = 0;
    int ch;
    WOLFSSHD_CONFIG* conf = NULL;
    WOLFSSH_CTX* ctx = NULL;

    const char* configFile = "/usr/local/etc/ssh/sshd_config";

    signal(SIGINT, interruptCatch);

    wolfSSH_SetLoggingCb(wolfSSHDLoggingCb);
    #ifdef DEBUG_WOLFSSH
        wolfSSH_Debugging_ON();
    #endif
    #ifdef DEBUG_WOLFSSL
        wolfSSL_Debugging_ON();
    #endif

    if (ret == WS_SUCCESS) {
        wolfSSH_Init();
    }

    if (ret == WS_SUCCESS) {
        conf = wolfSSHD_NewConfig(NULL);
        if (conf == NULL) {
            ret = WS_MEMORY_E;
        }
    }


    while ((ch = mygetopt(argc, argv, "?f:p:")) != -1) {
        switch (ch) {
            case 'f':
                configFile = myoptarg;
                break;

            case 'p':
                ret = XATOI(myoptarg);
                if (ret < 0) {
                    printf("Issue parsing port number %s\n", myoptarg);
                    ret = BAD_FUNC_ARG;
                }
                else {
                    port = (word16)ret;
                    ret = WS_SUCCESS;
                }
                break;

            case '?':
                ShowUsage();
                return WS_SUCCESS;

            default:
                ShowUsage();
                return WS_SUCCESS;
        }
    }

    if (ret == WS_SUCCESS) {
        ret = wolfSSHD_LoadSSHD(conf, configFile);
        if (ret != WS_SUCCESS)
            printf("Error reading in configure file %s\n", configFile);
    }

    /* port was not overridden with argument, read from config file */
    if (port == 0) {
        port = wolfSSHD_GetPort(conf);
    }

    wolfSSH_Log(WS_LOG_INFO, "[SSHD] Starting wolfSSH SSHD application");

    if (ret == WS_SUCCESS) {
        ret = SetupCTX(conf, &ctx);
    }

    tcp_listen(&listenFd, &port, 1);
    wolfSSH_Log(WS_LOG_INFO, "[SSHD] Listening on port %d", port);

    /* wait for incoming connections and fork them off */
    while (ret == WS_SUCCESS && quit == 0) {
        WOLFSSHD_CONNECTION conn;
    #ifdef WOLFSSL_NUCLEUS
        struct addr_struct clientAddr;
    #else
        SOCKADDR_IN_T clientAddr;
        socklen_t     clientAddrSz = sizeof(clientAddr);
    #endif

        /* wait for a connection */
        if (wolfSSHD_PendingConnection(listenFd)) {
            conn.ctx = ctx;
        #ifdef WOLFSSL_NUCLEUS
            conn.fd = NU_Accept(listenFd, &clientAddr, 0);
        #else
            conn.fd = accept(listenFd, (struct sockaddr*)&clientAddr,
                                                         &clientAddrSz);
        #endif

            ret = wolfSSHD_NewConnection(&conn);
        }
    }

    wolfSSHD_FreeConfig(conf);
    wolfSSH_Cleanup();
    return 0;
}
#endif /* WOLFSSH_SSHD */

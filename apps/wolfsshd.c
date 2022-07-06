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
#include "wolfauth.h"

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

#ifdef WOLFSSH_SHELL
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
    #include <sys/errno.h>

    static volatile int ChildRunning = 0;
    static void ChildSig(int sig)
    {
        (void)sig;
        ChildRunning = 0;
    }
#endif /* WOLFSSH_SHELL */

static volatile byte debugMode = 0; /* default to off */

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
    printf(" -d             Turn on debug mode\n");
}

static void interruptCatch(int in)
{
    (void)in;
    printf("Closing down wolfSSHD\n");
    quit = 1;
}

static void wolfSSHDLoggingCb(enum wolfSSH_LogLevel lvl, const char *const str)
{
    if (debugMode) {
        fprintf(stderr, "[PID %d]: %s\n", getpid(), str);
    }
    (void)lvl;
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
        wolfSSH_SetUserAuth(*ctx, DefaultUserAuth);
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
    if (ret == WS_SUCCESS) {
        char* hostKey = wolfSSHD_GetHostPrivateKey(conf);

        if (hostKey == NULL) {
            wolfSSH_Log(WS_LOG_ERROR, "[SSHD] No host private key set");
            ret = WS_BAD_ARGUMENT;
        }
        else {
            FILE* f;

            f = fopen(hostKey, "rb");
            if (f == NULL) {
                wolfSSH_Log(WS_LOG_ERROR,
                        "[SSHD] Unable to open host private key");
                ret = WS_BAD_ARGUMENT;
            }
            else {
                byte* data;
                int   dataSz = 4096;

                data = (byte*)WMALLOC(dataSz, NULL, 0);

                dataSz = (int)fread(data, 1, dataSz, f);
                fclose(f);
                if (wolfSSH_CTX_UsePrivateKey_buffer(*ctx, data, dataSz,
                                             WOLFSSH_FORMAT_ASN1) < 0) {
                    wolfSSH_Log(WS_LOG_ERROR,
                        "[SSHD] Unable parse host private key");
                    ret = WS_BAD_ARGUMENT;
                }
                WFREE(data, NULL, 0);
            }
        }
    }

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


#ifdef WOLFSSH_SFTP
/* handle SFTP operations
 * returns 0 on success
 */
static int SFTP_Subsystem(WOLFSSH* ssh, WOLFSSHD_CONNECTION* conn)
{
    byte tmp[1];
    int ret   = WS_SUCCESS;
    int error = WS_SUCCESS;
    WS_SOCKET_T sockfd;
    int select_ret = 0;

    sockfd = (WS_SOCKET_T)wolfSSH_get_fd(ssh);
    do {
//        if (threadCtx->nonBlock) {
//            if (error == WS_WANT_READ)
//                printf("... sftp server would read block\n");
//            else if (error == WS_WANT_WRITE)
//                printf("... sftp server would write block\n");
//        }

        if (wolfSSH_stream_peek(ssh, tmp, 1) > 0) {
            select_ret = WS_SELECT_RECV_READY;
        }
        else {
            select_ret = tcp_select(sockfd, TEST_SFTP_TIMEOUT);
        }

        if (select_ret == WS_SELECT_RECV_READY ||
            select_ret == WS_SELECT_ERROR_READY ||
            error == WS_WANT_WRITE)
        {
            ret = wolfSSH_SFTP_read(ssh);
            error = wolfSSH_get_error(ssh);
        }
        else if (select_ret == WS_SELECT_TIMEOUT)
            error = WS_WANT_READ;
        else
            error = WS_FATAL_ERROR;

        if (error == WS_WANT_READ || error == WS_WANT_WRITE ||
            error == WS_CHAN_RXD || error == WS_REKEYING ||
            error == WS_WINDOW_FULL)
            ret = error;

        if (ret == WS_FATAL_ERROR && error == 0) {
            WOLFSSH_CHANNEL* channel =
                wolfSSH_ChannelNext(ssh, NULL);
            if (channel && wolfSSH_ChannelGetEof(channel)) {
                ret = 0;
                break;
            }
        }
    } while (ret != WS_FATAL_ERROR);

    return ret;
}
#endif


#ifdef WOLFSSH_SCP
int SCP_Subsystem()
{

}
#endif

#ifdef WOLFSSH_SHELL
static int SHELL_Subsystem(WOLFSSHD_CONNECTION* conn, WOLFSSH* ssh)
{
    WS_SOCKET_T sshFd = 0;
    int rc;
    const char *userName;
    struct passwd *p_passwd;
    WS_SOCKET_T childFd = 0;
    pid_t childPid;
#ifndef EXAMPLE_BUFFER_SZ
    #define EXAMPLE_BUFFER_SZ 4096
#endif
    byte shellBuffer[EXAMPLE_BUFFER_SZ];
    byte channelBuffer[EXAMPLE_BUFFER_SZ];

    userName = wolfSSH_GetUsername(ssh);
    p_passwd = getpwnam((const char *)userName);
    if (p_passwd == NULL) {
        /* Not actually a user on the system. */
        wolfSSH_Log(WS_LOG_ERROR, "[SSHD] Invalid user name found");
        return WS_FATAL_ERROR;
    }

    ChildRunning = 1;
    childPid = forkpty(&childFd, NULL, NULL, NULL);

    if (childPid < 0) {
        /* forkpty failed, so return */
        ChildRunning = 0;
        return WS_FATAL_ERROR;
    }
    else if (childPid == 0) {
        /* Child process */
        const char *args[] = {"-sh", NULL};

        signal(SIGINT, SIG_DFL);

        printf("userName is %s\n", userName);
        system("env");

        setenv("HOME", p_passwd->pw_dir, 1);
        setenv("LOGNAME", p_passwd->pw_name, 1);
        rc = chdir(p_passwd->pw_dir);
        if (rc != 0) {
            return WS_FATAL_ERROR;
        }

        execv("/bin/sh", (char **)args);
    }

    struct termios tios;
    word32 shellChannelId = 0;
    printf("In childPid > 0; getpid=%d\n", (int)getpid());
    signal(SIGCHLD, ChildSig);

    rc = tcgetattr(childFd, &tios);
    if (rc != 0) {
        return WS_FATAL_ERROR;
    }
    rc = tcsetattr(childFd, TCSAFLUSH, &tios);
    if (rc != 0) {
        return WS_FATAL_ERROR;
    }

#ifdef SHELL_DEBUG
    termios_show(childFd);
#endif

    while (ChildRunning) {
        fd_set readFds;
        WS_SOCKET_T maxFd;
        int cnt_r;
        int cnt_w;

        FD_ZERO(&readFds);
        FD_SET(sshFd, &readFds);
        maxFd = sshFd;

        FD_SET(childFd, &readFds);
        if (childFd > maxFd)
            maxFd = childFd;
        rc = select((int)maxFd + 1, &readFds, NULL, NULL, NULL);
        if (rc == -1)
            break;

        if (FD_ISSET(sshFd, &readFds)) {
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
                else if (rc == WS_CHANNEL_CLOSED) {
                    continue;
                }
                else if (rc != WS_WANT_READ) {
                    break;
                }
            }
        }

        if (FD_ISSET(childFd, &readFds)) {
            cnt_r = (int)read(childFd, shellBuffer, sizeof shellBuffer);
            /* This read will return 0 on EOF */
            if (cnt_r <= 0) {
                int err = errno;
                if (err != EAGAIN) {
                    break;
                }
            }
            else {
                if (cnt_r > 0) {
                    cnt_w = wolfSSH_ChannelIdSend(ssh, shellChannelId,
                            shellBuffer, cnt_r);
                    if (cnt_w < 0)
                        break;
                }
            }
        }
    }
    (void)conn;
    return WS_SUCCESS;
}
#endif


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
        if (ret != WS_SUCCESS) {
            wolfSSH_Log(WS_LOG_ERROR,
                "[SSHD] Failed to accept WOLFSSH connection");
        }
    }

    switch (ret) {
        case WS_SFTP_COMPLETE:
        #ifdef WOLFSSH_SFTP
            ret = SFTP_Subsystem(ssh, conn);
        #else
            err_sys("SFTP not compiled in. Please use --enable-sftp");
        #endif
            break;

       case WS_SUCCESS: /* default success case to shell */
    #ifdef WOLFSSH_SHELL
        printf("ret of accept = %d\n",ret);
        if (ret == WS_SUCCESS) {
            wolfSSH_Log(WS_LOG_INFO, "[SSHD] Entering new shell");
            SHELL_Subsystem(conn, ssh);
        }
    #endif
        break;
    }

    wolfSSH_shutdown(ssh);
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

    const char* configFile  = "/usr/local/etc/ssh/sshd_config";
    const char* hostKeyFile = NULL;

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


    while ((ch = mygetopt(argc, argv, "?f:p:h:d")) != -1) {
        switch (ch) {
            case 'f':
                configFile = myoptarg;
                break;

            case 'p':
                if (ret == WS_SUCCESS) {
                    ret = XATOI(myoptarg);
                    if (ret < 0) {
                        printf("Issue parsing port number %s\n", myoptarg);
                        ret = BAD_FUNC_ARG;
                    }
                    else {
                        port = (word16)ret;
                        ret = WS_SUCCESS;
                    }
                }
                break;

            case 'h':
                hostKeyFile = myoptarg;
                break;

            case 'd':
                debugMode = 1; /* turn on debug mode */
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

    /* check if host key file was passed in */
    if (hostKeyFile != NULL) {
        wolfSSHD_SetHostPrivateKey(conf, hostKeyFile);
    }

    wolfSSH_Log(WS_LOG_INFO, "[SSHD] Starting wolfSSH SSHD application");

    if (ret == WS_SUCCESS) {
        ret = SetupCTX(conf, &ctx);
    }

    wolfSSH_Log(WS_LOG_INFO, "[SSHD] Starting to listen on port %d", port);
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

/* client.c
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

#define WOLFSSH_TEST_CLIENT

#ifdef WOLFSSL_USER_SETTINGS
    #include <wolfssl/wolfcrypt/settings.h>
#else
    #include <wolfssl/options.h>
#endif

#include <wolfssh/ssh.h>
#include <wolfssh/internal.h>
#include <wolfssh/test.h>
#ifdef WOLFSSH_AGENT
    #include <wolfssh/agent.h>
#endif
#include <wolfssl/wolfcrypt/ecc.h>
#include "examples/client/client.h"
#include "examples/client/common.h"
#if !defined(USE_WINDOWS_API) && !defined(MICROCHIP_PIC32) && \
    defined(WOLFSSH_TERM) && !defined(NO_FILESYSTEM)
    #include <termios.h>
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
    #ifndef USE_WINDOWS_API
        #include <pwd.h>
    #endif
#endif /* WOLFSSH_SHELL */

#ifdef WOLFSSH_AGENT
    #include <errno.h>
    #include <stddef.h>
    #include <sys/socket.h>
    #include <sys/un.h>
#endif /* WOLFSSH_AGENT */

#ifdef HAVE_SYS_SELECT_H
    #include <sys/select.h>
#endif

#ifdef WOLFSSH_CERTS
    #include <wolfssl/wolfcrypt/asn.h>
#endif


#ifndef NO_WOLFSSH_CLIENT

static const char testString[] = "Hello, wolfSSH!";


static void ShowUsage(void)
{
    printf("client %s\n", LIBWOLFSSH_VERSION_STRING);
    printf(" -?            display this help and exit\n");
    printf(" -h <host>     host to connect to, default %s\n", wolfSshIp);
    printf(" -p <num>      port to connect on, default %d\n", wolfSshPort);
    printf(" -u <username> username to authenticate as (REQUIRED)\n");
    printf(" -P <password> password for username, prompted if omitted\n");
    printf(" -i <filename> filename for the user's private key\n");
    printf(" -j <filename> filename for the user's public key\n");
    printf(" -x            exit after successful connection without doing\n"
           "               read/write\n");
#ifdef WOLFSSH_TEST_BLOCK
    printf("-N            non-blocking sockets required when compiled with "
                          "WOLFSSH_TEST_BLOCK\n");
#else
    printf(" -N            use non-blocking sockets\n");
#endif
#ifdef WOLFSSH_TERM
    printf(" -t            use psuedo terminal\n");
#endif
#if !defined(SINGLE_THREADED) && !defined(WOLFSSL_NUCLEUS)
    printf(" -c <command>  executes remote command and pipe stdin/stdout\n");
#ifdef USE_WINDOWS_API
    printf(" -R            raw untranslated output\n");
#endif
#endif
#ifdef WOLFSSH_AGENT
    printf(" -a            Attempt to use SSH-AGENT\n");
#endif
#ifdef WOLFSSH_CERTS
    printf(" -J <filename> filename for DER certificate to use\n");
    printf("               Certificate example : client -u orange \\\n");
    printf("               -J orange-cert.der -i orange-key.der\n");
    printf(" -A <filename> filename for DER CA certificate to verify host\n");
    printf(" -X            Ignore IP checks on peer vs peer certificate\n");
#endif
    printf(" -E            List all possible algos\n");
    printf(" -k            set the list of key algos to use\n");
}


static const char* pubKeyName = NULL;
static const char* certName = NULL;
static const char* caCert   = NULL;


static int NonBlockSSH_connect(WOLFSSH* ssh)
{
    int ret;
    int error;
    SOCKET_T sockfd;
    int select_ret = 0;

    ret = wolfSSH_connect(ssh);
    error = wolfSSH_get_error(ssh);
    sockfd = (SOCKET_T)wolfSSH_get_fd(ssh);

    while (ret != WS_SUCCESS &&
            (error == WS_WANT_READ || error == WS_WANT_WRITE))
    {
        if (error == WS_WANT_READ)
            printf("... client would read block\n");
        else if (error == WS_WANT_WRITE)
            printf("... client would write block\n");

        select_ret = tcp_select(sockfd, 1);

        /* Continue in want write cases even if did not select on socket
         * because there could be pending data to be written. Added continue
         * on want write for test cases where a forced want read was introduced
         * and the socket will not be receiving more data. */
        if (error == WS_WANT_WRITE || error == WS_WANT_READ ||
            select_ret == WS_SELECT_RECV_READY ||
            select_ret == WS_SELECT_ERROR_READY)
        {
            ret = wolfSSH_connect(ssh);
            error = wolfSSH_get_error(ssh);
        }
        else if (select_ret == WS_SELECT_TIMEOUT)
            error = WS_WANT_READ;
        else
            error = WS_FATAL_ERROR;
    }

    return ret;
}

#if !defined(SINGLE_THREADED) && !defined(WOLFSSL_NUCLEUS) && \
    defined(WOLFSSH_TERM) && !defined(NO_FILESYSTEM)

typedef struct thread_args {
    WOLFSSH* ssh;
    wolfSSL_Mutex lock;
    byte rawMode;
    byte quit;
} thread_args;

#ifdef _POSIX_THREADS
    #define THREAD_RET void*
    #define THREAD_RET_SUCCESS NULL
#elif defined(_MSC_VER)
    #define THREAD_RET DWORD WINAPI
    #define THREAD_RET_SUCCESS 0
#else
    #define THREAD_RET int
    #define THREAD_RET_SUCCESS 0
#endif


#ifdef WOLFSSH_TERM
static int sendCurrentWindowSize(thread_args* args)
{
    int ret;
    word32 col = 80, row = 24, xpix = 0, ypix = 0;

    wc_LockMutex(&args->lock);
#if defined(_MSC_VER)
    {
        CONSOLE_SCREEN_BUFFER_INFO cs;

        if (GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &cs) != 0) {
            col = cs.srWindow.Right - cs.srWindow.Left + 1;
            row = cs.srWindow.Bottom - cs.srWindow.Top + 1;
        }
    }
#else
    {
        struct winsize windowSize = { 0,0,0,0 };

        ioctl(STDOUT_FILENO, TIOCGWINSZ, &windowSize);
        col = windowSize.ws_col;
        row = windowSize.ws_row;
        xpix = windowSize.ws_xpixel;
        ypix = windowSize.ws_ypixel;
    }
#endif
    ret = wolfSSH_ChangeTerminalSize(args->ssh, col, row, xpix, ypix);
    wc_UnLockMutex(&args->lock);

    return ret;
}
#endif


#ifdef WOLFSSH_TERM
#ifndef _MSC_VER

#if (defined(__OSX__) || defined(__APPLE__))
#include <dispatch/dispatch.h>
dispatch_semaphore_t windowSem;
#else
#include <semaphore.h>
static sem_t windowSem;
#endif

/* capture window change signales */
static void WindowChangeSignal(int sig)
{
#if (defined(__OSX__) || defined(__APPLE__))
    dispatch_semaphore_signal(windowSem);
#else
    sem_post(&windowSem);
#endif
    (void)sig;
}

/* thread for handling window size adjustments */
static THREAD_RET windowMonitor(void* in)
{
    thread_args* args;
    int ret;

    args = (thread_args*)in;
    do {
    #if (defined(__OSX__) || defined(__APPLE__))
        dispatch_semaphore_wait(windowSem, DISPATCH_TIME_FOREVER);
    #else
        sem_wait(&windowSem);
    #endif
        if (args->quit) {
            break;
        }
        ret = sendCurrentWindowSize(args);
        (void)ret;
    } while (1);

    return THREAD_RET_SUCCESS;
}
#else /* _MSC_VER */
/* no SIGWINCH on Windows, poll current terminal size */
static word32 prevCol, prevRow;

static int windowMonitor(thread_args* args)
{
    word32 row, col;
    int ret = WS_SUCCESS;
    CONSOLE_SCREEN_BUFFER_INFO cs;

    if (GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &cs) != 0) {
        col = cs.srWindow.Right - cs.srWindow.Left + 1;
        row = cs.srWindow.Bottom - cs.srWindow.Top + 1;

        if (prevCol != col || prevRow != row) {
            prevCol = col;
            prevRow = row;

            wc_LockMutex(&args->lock);
            ret = wolfSSH_ChangeTerminalSize(args->ssh, col, row, 0, 0);
            wc_UnLockMutex(&args->lock);
        }
    }

    return ret;
}
#endif /* _MSC_VER */
#endif /* WOLFSSH_TERM */


static THREAD_RET readInput(void* in)
{
    byte buf[256];
    int  bufSz = sizeof(buf);
    thread_args* args = (thread_args*)in;
    int ret = 0;
    word32 sz = 0;
#ifdef USE_WINDOWS_API
    HANDLE stdinHandle = GetStdHandle(STD_INPUT_HANDLE);
#endif

    while (ret >= 0) {
        WMEMSET(buf, 0, bufSz);
    #ifdef USE_WINDOWS_API
        /* Using A version to avoid potential 2 byte chars */
        ret = ReadConsoleA(stdinHandle, (void*)buf, bufSz - 1, (DWORD*)&sz,
                NULL);
        (void)windowMonitor(args);
    #else
        ret = (int)read(STDIN_FILENO, buf, bufSz -1);
        sz  = (word32)ret;
    #endif
        if (ret <= 0) {
            fprintf(stderr, "Error reading stdin\n");
            return THREAD_RET_SUCCESS;
        }
        /* lock SSH structure access */
        wc_LockMutex(&args->lock);
        ret = wolfSSH_stream_send(args->ssh, buf, sz);
        wc_UnLockMutex(&args->lock);
        if (ret <= 0) {
            fprintf(stderr, "Couldn't send data\n");
            return THREAD_RET_SUCCESS;
        }
    }
#if !defined(WOLFSSH_NO_ECC) && defined(FP_ECC) && defined(HAVE_THREAD_LS)
    wc_ecc_fp_free();  /* free per thread cache */
#endif
    return THREAD_RET_SUCCESS;
}

#if defined(WOLFSSH_AGENT)
static inline void ato32(const byte* c, word32* u32)
{
    *u32 = (c[0] << 24) | (c[1] << 16) | (c[2] << 8) | c[3];
}
#endif

static THREAD_RET readPeer(void* in)
{
    byte buf[256];
    int  bufSz = sizeof(buf);
    thread_args* args = (thread_args*)in;
    int ret = 0;
    int fd = (int)wolfSSH_get_fd(args->ssh);
    word32 bytes;
#ifdef USE_WINDOWS_API
    HANDLE stdoutHandle = GetStdHandle(STD_OUTPUT_HANDLE);
#endif
    fd_set readSet;
    fd_set errSet;

    FD_ZERO(&readSet);
    FD_ZERO(&errSet);
    FD_SET(fd, &readSet);
    FD_SET(fd, &errSet);

#ifdef USE_WINDOWS_API
    if (args->rawMode == 0) {
        DWORD wrd;

        /* get console mode will fail on handles that are not a console,
         * i.e. if the stdout is being redirected to a file */
        if (GetConsoleMode(stdoutHandle, &wrd) != FALSE) {
            /* depend on the terminal to process VT characters */
            #ifndef _WIN32_WINNT_WIN10
                /* support for virtual terminal processing was introduced in windows 10 */
                #define _WIN32_WINNT_WIN10 0x0A00
            #endif
            #if defined(WINVER) && (WINVER >= _WIN32_WINNT_WIN10)
                wrd |= (ENABLE_VIRTUAL_TERMINAL_PROCESSING | ENABLE_PROCESSED_OUTPUT);
            #endif
            if (SetConsoleMode(stdoutHandle, wrd) == FALSE) {
                err_sys("Unable to set console mode");
            }
        }
    }

    /* set handle to use for window resize */
    wc_LockMutex(&args->lock);
    wolfSSH_SetTerminalResizeCtx(args->ssh, stdoutHandle);
    wc_UnLockMutex(&args->lock);
#endif

    while (ret >= 0) {
    #ifdef USE_WINDOWS_API
        (void)windowMonitor(args);
    #endif

        bytes = select(fd + 1, &readSet, NULL, &errSet, NULL);
        wc_LockMutex(&args->lock);
        while (bytes > 0 && (FD_ISSET(fd, &readSet) || FD_ISSET(fd, &errSet))) {
            /* there is something to read off the wire */
            WMEMSET(buf, 0, bufSz);
            ret = wolfSSH_stream_read(args->ssh, buf, bufSz - 1);
            if (ret == WS_EXTDATA) { /* handle extended data */
                do {
                    WMEMSET(buf, 0, bufSz);
                    ret = wolfSSH_extended_data_read(args->ssh, buf, bufSz - 1);
                    if (ret < 0)
                        err_sys("Extended data read failed.");
                    buf[bufSz - 1] = '\0';
                #ifdef USE_WINDOWS_API
                    fprintf(stderr, "%s", buf);
                #else
                    if (write(STDERR_FILENO, buf, ret) < 0) {
                        perror("Issue with stderr write ");
                    }
                #endif
                } while (ret > 0);
            }
            else if (ret <= 0) {
                if (ret == WS_FATAL_ERROR) {
                    ret = wolfSSH_get_error(args->ssh);
                    if (ret == WS_WANT_READ) {
                        /* If WANT_READ, not an error. */
                        ret = WS_SUCCESS;
                    }
                    #ifdef WOLFSSH_AGENT
                    else if (ret == WS_CHAN_RXD) {
                        byte agentBuf[512];
                        int rxd, txd;
                        word32 channel = 0;

                        wolfSSH_GetLastRxId(args->ssh, &channel);
                        rxd = wolfSSH_ChannelIdRead(args->ssh, channel,
                                agentBuf, sizeof(agentBuf));
                        if (rxd > 4) {
                            word32 msgSz = 0;

                            ato32(agentBuf, &msgSz);
                            if (msgSz > (word32)rxd - 4) {
                                rxd += wolfSSH_ChannelIdRead(args->ssh, channel,
                                        agentBuf + rxd,
                                        sizeof(agentBuf) - rxd);
                            }

                            txd = rxd;
                            rxd = sizeof(agentBuf);
                            ret = wolfSSH_AGENT_Relay(args->ssh,
                                    agentBuf, (word32*)&txd,
                                    agentBuf, (word32*)&rxd);
                            if (ret == WS_SUCCESS) {
                                ret = wolfSSH_ChannelIdSend(args->ssh, channel,
                                        agentBuf, rxd);
                            }
                        }
                        WMEMSET(agentBuf, 0, sizeof(agentBuf));
                        continue;
                    }
                    #endif /* WOLFSSH_AGENT */
                }
                else if (ret != WS_EOF) {
                    err_sys("Stream read failed.");
                }
            }
            else {
            #ifdef USE_WINDOWS_API
                DWORD writtn = 0;
            #endif
                buf[bufSz - 1] = '\0';

            #ifdef USE_WINDOWS_API
                if (WriteFile(stdoutHandle, buf, bufSz, &writtn, NULL) == FALSE) {
                    err_sys("Failed to write to stdout handle");
                }
            #else
                if (write(STDOUT_FILENO, buf, ret) < 0) {
                    perror("write to stdout error ");
                }
            #endif
                WFFLUSH(stdout);
            }
            if (wolfSSH_stream_peek(args->ssh, buf, bufSz) <= 0) {
                bytes = 0; /* read it all */
            }
        }
        wc_UnLockMutex(&args->lock);
    }
#if !defined(WOLFSSH_NO_ECC) && defined(FP_ECC) && defined(HAVE_THREAD_LS)
    wc_ecc_fp_free();  /* free per thread cache */
#endif

    return THREAD_RET_SUCCESS;
}
#endif /* !SINGLE_THREADED && !WOLFSSL_NUCLEUS */



#if defined(WOLFSSL_PTHREADS) && defined(WOLFSSL_TEST_GLOBAL_REQ)

static int callbackGlobalReq(WOLFSSH *ssh, void *buf, word32 sz, int reply, void *ctx)
{
    char reqStr[] = "SampleRequest";

    if ((WOLFSSH *)ssh != *(WOLFSSH **)ctx)
    {
        printf("ssh(%x) != ctx(%x)\n", (unsigned int)ssh, (unsigned int)*(WOLFSSH **)ctx);
        return WS_FATAL_ERROR;
    }

    if (strlen(reqStr) == sz && (strncmp((char *)buf, reqStr, sz) == 0)
        && reply == 1){
        printf("Global Request\n");
        return WS_SUCCESS;
    } else {
        return WS_FATAL_ERROR;
    }

}
#endif


#ifdef WOLFSSH_AGENT
typedef struct WS_AgentCbActionCtx {
    struct sockaddr_un name;
    int fd;
    int state;
} WS_AgentCbActionCtx;

static const char EnvNameAuthPort[] = "SSH_AUTH_SOCK";

static int wolfSSH_AGENT_DefaultActions(WS_AgentCbAction action, void* vCtx)
{
    WS_AgentCbActionCtx* ctx = (WS_AgentCbActionCtx*)vCtx;
    int ret = WS_AGENT_SUCCESS;

    if (action == WOLFSSH_AGENT_LOCAL_SETUP) {
        const char* sockName;
        struct sockaddr_un* name = &ctx->name;
        size_t size;
        int err;

        sockName = getenv(EnvNameAuthPort);
        if (sockName == NULL)
            ret = WS_AGENT_NOT_AVAILABLE;

        if (ret == WS_AGENT_SUCCESS) {
            memset(name, 0, sizeof(struct sockaddr_un));
            name->sun_family = AF_LOCAL;
            strncpy(name->sun_path, sockName, sizeof(name->sun_path));
            name->sun_path[sizeof(name->sun_path) - 1] = '\0';
            size = strlen(sockName) +
                    offsetof(struct sockaddr_un, sun_path);

            ctx->fd = socket(AF_UNIX, SOCK_STREAM, 0);
            if (ctx->fd == -1) {
                ret = WS_AGENT_SETUP_E;
                err = errno;
                fprintf(stderr, "socket() = %d\n", err);
            }
        }

        if (ret == WS_AGENT_SUCCESS) {
            ret = connect(ctx->fd,
                    (struct sockaddr *)name, (socklen_t)size);
            if (ret < 0) {
                ret = WS_AGENT_SETUP_E;
                err = errno;
                fprintf(stderr, "connect() = %d", err);
            }
        }

        if (ret == WS_AGENT_SUCCESS)
            ctx->state = AGENT_STATE_CONNECTED;
    }
    else if (action == WOLFSSH_AGENT_LOCAL_CLEANUP) {
        int err;

        err = close(ctx->fd);
        if (err != 0) {
            err = errno;
            fprintf(stderr, "close() = %d", err);
            if (ret == 0)
                ret = WS_AGENT_SETUP_E;
        }
    }
    else
        ret = WS_AGENT_INVALID_ACTION;

    return ret;
}


static int wolfSSH_AGENT_IO_Cb(WS_AgentIoCbAction action,
        void* buf, word32 bufSz, void* vCtx)
{
    WS_AgentCbActionCtx* ctx = (WS_AgentCbActionCtx*)vCtx;
    int ret = WS_AGENT_INVALID_ACTION;

    if (action == WOLFSSH_AGENT_IO_WRITE) {
        const byte* wBuf = (const byte*)buf;
        ret = (int)write(ctx->fd, wBuf, bufSz);
        if (ret < 0) {
            ret = WS_CBIO_ERR_GENERAL;
        }
    }
    else if (action == WOLFSSH_AGENT_IO_READ) {
        byte* rBuf = (byte*)buf;
        ret = (int)read(ctx->fd, rBuf, bufSz);
        if (ret < 0) {
            ret = WS_CBIO_ERR_GENERAL;
        }
    }

    return ret;
}


#endif /* WOLFSSH_AGENT */


THREAD_RETURN WOLFSSH_THREAD client_test(void* args)
{
    WOLFSSH_CTX* ctx = NULL;
    WOLFSSH* ssh = NULL;
    SOCKET_T sockFd = WOLFSSH_SOCKET_INVALID;
    SOCKADDR_IN_T clientAddr;
    socklen_t clientAddrSz = sizeof(clientAddr);
    char rxBuf[80];
    int ret = 0;
    int ch;
    int userEcc = 0;
    word16 port = wolfSshPort;
    char* host = (char*)wolfSshIp;
    const char* username = NULL;
    const char* password = NULL;
    const char* cmd      = NULL;
    const char* privKeyName = NULL;
    const char* keyList = NULL;
    byte imExit = 0;
    byte listAlgos = 0;
    byte nonBlock = 0;
    byte keepOpen = 0;
#ifdef USE_WINDOWS_API
    byte rawMode = 0;
#endif
#ifdef WOLFSSH_AGENT
    byte useAgent = 0;
    WS_AgentCbActionCtx agentCbCtx;
#endif

    int     argc = ((func_args*)args)->argc;
    char**  argv = ((func_args*)args)->argv;
    ((func_args*)args)->return_code = 0;

    (void)keepOpen;

    while ((ch = mygetopt(argc, argv, "?ac:h:i:j:p:tu:xzNP:RJ:A:XeEk:")) != -1) {
        switch (ch) {
            case 'h':
                host = myoptarg;
                break;

            case 'z':
            #ifdef WOLFSSH_SHOW_SIZES
                wolfSSH_ShowSizes();
                exit(EXIT_SUCCESS);
            #endif
                break;

            case 'e':
                userEcc = 1;
                break;

            case 'p':
                if (myoptarg == NULL) {
                    err_sys("port number cannot be NULL");
                }
                port = (word16)atoi(myoptarg);
                #if !defined(NO_MAIN_DRIVER) || defined(USE_WINDOWS_API)
                    if (port == 0)
                        err_sys("port number cannot be 0");
                #endif
                break;

            case 'u':
                username = myoptarg;
                break;

            case 'P':
                password = myoptarg;
                break;

            case 'i':
                privKeyName = myoptarg;
                break;

            case 'j':
                pubKeyName = myoptarg;
                break;

        #ifdef WOLFSSH_CERTS
            case 'J':
                certName = myoptarg;
                break;

            case 'A':
                caCert = myoptarg;
                break;

            #if defined(OPENSSL_ALL) || defined(WOLFSSL_IP_ALT_NAME)
            case 'X':
                ClientIPOverride(1);
                break;
            #endif
        #endif

            case 'E':
                listAlgos = 1;
                break;

            case 'x':
                /* exit after successful connection without read/write */
                imExit = 1;
                break;

            case 'N':
                nonBlock = 1;
                break;

            case 'k':
                keyList = myoptarg;
                break;

        #if !defined(SINGLE_THREADED) && !defined(WOLFSSL_NUCLEUS)
            case 'c':
                cmd = myoptarg;
                break;
        #ifdef USE_WINDOWS_API
           case 'R':
                rawMode = 1;
                break;
        #endif /* USE_WINDOWS_API */
        #endif

        #ifdef WOLFSSH_TERM
            case 't':
                keepOpen = 1;
                break;
        #endif

        #ifdef WOLFSSH_AGENT
            case 'a':
                useAgent = 1;
                break;
        #endif

            case '?':
                ShowUsage();
                exit(EXIT_SUCCESS);

            default:
                ShowUsage();
                exit(MY_EX_USAGE);
        }
    }
    myoptind = 0;      /* reset for test cases */

    if (username == NULL)
        err_sys("client requires a username parameter.");

#ifdef SINGLE_THREADED
    if (keepOpen)
        err_sys("Threading needed for terminal session\n");
#endif

    if ((pubKeyName == NULL && certName == NULL) && privKeyName != NULL) {
        err_sys("If setting priv key, need pub key.");
    }

    ret = ClientSetPrivateKey(privKeyName, userEcc, NULL);
    if (ret != 0) {
        err_sys("Error setting private key");
    }

#ifdef WOLFSSH_CERTS
    /* passed in certificate to use */
    if (certName) {
        ret = ClientUseCert(certName, NULL);
    }
    else
#endif
    if (pubKeyName) {
        ret = ClientUsePubKey(pubKeyName, userEcc, NULL);
    }
    if (ret != 0) {
        err_sys("Error setting public key");
    }

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_CLIENT, NULL);
    if (ctx == NULL)
        err_sys("Couldn't create wolfSSH client context.");

    if (keyList) {
        if (wolfSSH_CTX_SetAlgoListKey(ctx, NULL) != WS_SUCCESS) {
            err_sys("Error setting key list.\n");
        }
    }

    if (((func_args*)args)->user_auth == NULL)
        wolfSSH_SetUserAuth(ctx, ClientUserAuth);
    else
        wolfSSH_SetUserAuth(ctx, ((func_args*)args)->user_auth);

#ifdef WOLFSSH_AGENT
    if (useAgent) {
        wolfSSH_CTX_set_agent_cb(ctx,
                wolfSSH_AGENT_DefaultActions, wolfSSH_AGENT_IO_Cb);
        wolfSSH_CTX_AGENT_enable(ctx, 1);
    }
#endif

#ifdef WOLFSSH_CERTS
    ClientLoadCA(ctx, caCert);
#else
    (void)caCert;
#endif /* WOLFSSH_CERTS */

    wolfSSH_CTX_SetPublicKeyCheck(ctx, ClientPublicKeyCheck);

    ssh = wolfSSH_new(ctx);
    if (ssh == NULL)
        err_sys("Couldn't create wolfSSH session.");

#if defined(WOLFSSL_PTHREADS) && defined(WOLFSSL_TEST_GLOBAL_REQ)
    wolfSSH_SetGlobalReq(ctx, callbackGlobalReq);
    wolfSSH_SetGlobalReqCtx(ssh, &ssh); /* dummy ctx */
#endif

    if (password != NULL)
        wolfSSH_SetUserAuthCtx(ssh, (void*)password);

#ifdef WOLFSSH_AGENT
    if (useAgent) {
        memset(&agentCbCtx, 0, sizeof(agentCbCtx));
        agentCbCtx.state = AGENT_STATE_INIT;
        wolfSSH_set_agent_cb_ctx(ssh, &agentCbCtx);
    }
#endif
    wolfSSH_SetPublicKeyCheckCtx(ssh, (void*)host);

    ret = wolfSSH_SetUsername(ssh, username);
    if (ret != WS_SUCCESS)
        err_sys("Couldn't set the username.");

    if (listAlgos) {
        word32 idx = 0;
        const char* current = NULL;

        printf("KEX:\n");
        do {
            current = wolfSSH_QueryKex(&idx);
            if (current) {
                printf("\t%d: %s\n", idx, current);
            }
        } while (current != NULL);
        printf("Set KEX: %s\n\n", wolfSSH_GetAlgoListKex(ssh));

        idx = 0;
        printf("Key:\n");
        do {
            current = wolfSSH_QueryKey(&idx);
            if (current) {
                printf("\t%d: %s\n", idx, current);
            }
        } while (current != NULL);
        printf("Set Key: %s\n\n", wolfSSH_GetAlgoListKey(ssh));

        idx = 0;
        printf("Cipher:\n");
        do {
            current = wolfSSH_QueryCipher(&idx);
            if (current) {
                printf("\t%d: %s\n", idx, current);
            }
        } while (current != NULL);
        printf("Set Cipher: %s\n\n", wolfSSH_GetAlgoListCipher(ssh));

        idx = 0;
        printf("Mac:\n");
        do {
            current = wolfSSH_QueryMac(&idx);
            if (current) {
                printf("\t%d: %s\n", idx, current);
            }
        } while (current != NULL);
        printf("Set Mac: %s\n", wolfSSH_GetAlgoListMac(ssh));

        wolfSSH_free(ssh);
        wolfSSH_CTX_free(ctx);
        WOLFSSL_RETURN_FROM_THREAD(0);
    }

    build_addr(&clientAddr, host, port);
    tcp_socket(&sockFd, ((struct sockaddr_in *)&clientAddr)->sin_family);

    ret = connect(sockFd, (const struct sockaddr *)&clientAddr, clientAddrSz);
    if (ret != 0)
        err_sys("Couldn't connect to server.");

    if (nonBlock)
        tcp_set_nonblocking(&sockFd);

    ret = wolfSSH_set_fd(ssh, (int)sockFd);
    if (ret != WS_SUCCESS)
        err_sys("Couldn't set the session's socket.");

    if (cmd != NULL) {
        ret = wolfSSH_SetChannelType(ssh, WOLFSSH_SESSION_EXEC,
                            (byte*)cmd, (word32)WSTRLEN((char*)cmd));
        if (ret != WS_SUCCESS)
            err_sys("Couldn't set the channel type.");
    }

#ifdef WOLFSSH_TERM
    if (keepOpen) {
        ret = wolfSSH_SetChannelType(ssh, WOLFSSH_SESSION_TERMINAL, NULL, 0);
        if (ret != WS_SUCCESS)
            err_sys("Couldn't set the terminal channel type.");
    }
#endif

    if (!nonBlock)
        ret = wolfSSH_connect(ssh);
    else
        ret = NonBlockSSH_connect(ssh);
    if (ret != WS_SUCCESS)
        err_sys("Couldn't connect SSH stream.");

#if !defined(SINGLE_THREADED) && !defined(WOLFSSL_NUCLEUS) && \
    defined(WOLFSSH_TERM) && !defined(NO_FILESYSTEM)
    if (keepOpen) /* set up for psuedo-terminal */
        ClientSetEcho(2);

    if (cmd != NULL || keepOpen == 1) {
    #if defined(_POSIX_THREADS)
        thread_args arg;
        pthread_t   thread[3];

        arg.ssh = ssh;
        arg.quit = 0;
        wc_InitMutex(&arg.lock);
#ifdef WOLFSSH_TERM
    #if (defined(__OSX__) || defined(__APPLE__))
        windowSem = dispatch_semaphore_create(0);
    #else
        sem_init(&windowSem, 0, 0);
    #endif

        if (cmd) {
            int err;

            /* exec command does not contain initial terminal size, unlike pty-req.
             * Send an inital terminal size for recieving the results of the command */
            err = sendCurrentWindowSize(&arg);
            if (err != WS_SUCCESS) {
                fprintf(stderr, "Issue sending exec initial terminal size\n\r");
            }
        }
        signal(SIGWINCH, WindowChangeSignal);
        pthread_create(&thread[0], NULL, windowMonitor, (void*)&arg);
#endif /* WOLFSSH_TERM */
        pthread_create(&thread[1], NULL, readInput, (void*)&arg);
        pthread_create(&thread[2], NULL, readPeer, (void*)&arg);
        pthread_join(thread[2], NULL);
#ifdef WOLFSSH_TERM
        /* Wake the windowMonitor thread so it can exit. */
        arg.quit = 1;
    #if (defined(__OSX__) || defined(__APPLE__))
        dispatch_semaphore_signal(windowSem);
    #else
        sem_post(&windowSem);
    #endif
        pthread_join(thread[0], NULL);
#endif /* WOLFSSH_TERM */
        pthread_cancel(thread[1]);
        pthread_join(thread[1], NULL);
#ifdef WOLFSSH_TERM
    #if (defined(__OSX__) || defined(__APPLE__))
        dispatch_release(windowSem);
    #else
        sem_destroy(&windowSem);
    #endif
#endif /* WOLFSSH_TERM */
    #elif defined(_MSC_VER)
        thread_args arg;
        HANDLE thread[2];

        arg.ssh     = ssh;
        arg.rawMode = rawMode;
        wc_InitMutex(&arg.lock);

        if (cmd) {
            int err;

            /* exec command does not contain initial terminal size, unlike pty-req.
             * Send an inital terminal size for recieving the results of the command */
            err = sendCurrentWindowSize(&arg);
            if (err != WS_SUCCESS) {
                fprintf(stderr, "Issue sending exec initial terminal size\n\r");
            }
        }

        thread[0] = CreateThread(NULL, 0, readInput, (void*)&arg, 0, 0);
        thread[1] = CreateThread(NULL, 0, readPeer, (void*)&arg, 0, 0);
        WaitForSingleObject(thread[1], INFINITE);
        CloseHandle(thread[0]);
        CloseHandle(thread[1]);
    #else
        err_sys("No threading to use");
    #endif
        if (keepOpen)
            ClientSetEcho(1);
    }
    else
#endif

#if defined(WOLFSSL_PTHREADS) && defined(WOLFSSL_TEST_GLOBAL_REQ)
    while (!imExit) {
#else
    if (!imExit) {
#endif
        ret = wolfSSH_stream_send(ssh, (byte*)testString,
                                  (word32)strlen(testString));
        if (ret <= 0)
            err_sys("Couldn't send test string.");

        do {
            ret = wolfSSH_stream_read(ssh, (byte*)rxBuf, sizeof(rxBuf) - 1);
            if (ret <= 0) {
                ret = wolfSSH_get_error(ssh);
                if (ret != WS_WANT_READ && ret != WS_WANT_WRITE &&
                        ret != WS_CHAN_RXD)
                    err_sys("Stream read failed.");
            }
        } while (ret == WS_WANT_READ || ret == WS_WANT_WRITE);

        rxBuf[ret] = '\0';
        printf("Server said: %s\n", rxBuf);

#if defined(WOLFSSL_PTHREADS) && defined(WOLFSSL_TEST_GLOBAL_REQ)
        sleep(10);
#endif
    }
    ret = wolfSSH_shutdown(ssh);
    /* do not continue on with shutdown process if peer already disconnected */
    if (ret != WS_SOCKET_ERROR_E && wolfSSH_get_error(ssh) != WS_SOCKET_ERROR_E
            && wolfSSH_get_error(ssh) != WS_CHANNEL_CLOSED) {
        if (ret != WS_SUCCESS) {
            err_sys("Sending the shutdown messages failed.");
        }
        ret = wolfSSH_worker(ssh, NULL);
        if (ret != WS_SUCCESS && ret != WS_SOCKET_ERROR_E &&
            ret != WS_CHANNEL_CLOSED) {
            err_sys("Failed to listen for close messages from the peer.");
        }
    }
    WCLOSESOCKET(sockFd);

#if defined(WOLFSSH_TERM) || defined(WOLFSSH_SHELL)
    ((func_args*)args)->return_code = wolfSSH_GetExitStatus(ssh);
#endif

    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);
    if (ret != WS_SUCCESS && ret != WS_SOCKET_ERROR_E &&
            ret != WS_CHANNEL_CLOSED) {
        err_sys("Closing client stream failed");
    }

    ClientFreeBuffers(pubKeyName, privKeyName, NULL);
#if !defined(WOLFSSH_NO_ECC) && defined(FP_ECC) && defined(HAVE_THREAD_LS)
    wc_ecc_fp_free();  /* free per thread cache */
#endif

    WOLFSSL_RETURN_FROM_THREAD(0);
}

#endif /* NO_WOLFSSH_CLIENT */


#ifndef NO_MAIN_DRIVER

    int main(int argc, char** argv)
    {
        func_args args;

        args.argc = argc;
        args.argv = argv;
        args.return_code = 0;
        args.user_auth = NULL;

        WSTARTTCP();

        #ifdef DEBUG_WOLFSSH
            wolfSSH_Debugging_ON();
        #endif

        wolfSSH_Init();

        ChangeToWolfSshRoot();
#ifndef NO_WOLFSSH_CLIENT
        client_test(&args);
#endif

        wolfSSH_Cleanup();

        return args.return_code;
    }

    int myoptind = 0;
    char* myoptarg = NULL;

#endif /* NO_MAIN_DRIVER */

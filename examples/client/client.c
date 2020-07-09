/* client.c
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

#define WOLFSSH_TEST_CLIENT

#include <wolfssh/ssh.h>
#include <wolfssh/test.h>
#ifdef WOLFSSH_AGENT
    #include <wolfssh/agent.h>
#endif
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/coding.h>
#include "examples/client/client.h"
#if !defined(USE_WINDOWS_API) && !defined(MICROCHIP_PIC32)
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
    #include <errno.h>
    #include <stdlib.h>
    #include <sys/select.h>
    #include <sys/wait.h>
    #include <sys/types.h>
    #include <syslog.h>
    #include <stdarg.h>
    #include <pwd.h>
    #include <stddef.h>
    #include <sys/socket.h>
    #include <sys/un.h>
#endif


#ifndef NO_WOLFSSH_CLIENT

static const char testString[] = "Hello, wolfSSH!";


/* type = 2 : shell / execute command settings
 * type = 0 : password
 * type = 1 : restore default
 * return 0 on success */
static int SetEcho(int type)
{
#if !defined(USE_WINDOWS_API) && !defined(MICROCHIP_PIC32)
    static int echoInit = 0;
    static struct termios originalTerm;

    if (!echoInit) {
        if (tcgetattr(STDIN_FILENO, &originalTerm) != 0) {
            printf("Couldn't get the original terminal settings.\n");
            return -1;
        }
        echoInit = 1;
    }
    if (type == 1) {
        if (tcsetattr(STDIN_FILENO, TCSANOW, &originalTerm) != 0) {
            printf("Couldn't restore the terminal settings.\n");
            return -1;
        }
    }
    else {
        struct termios newTerm;
        memcpy(&newTerm, &originalTerm, sizeof(struct termios));

        newTerm.c_lflag &= ~ECHO;
        if (type == 2) {
            newTerm.c_lflag &= ~(ICANON | ECHOE | ECHOK | ECHONL | ISIG);
        }
        else {
            newTerm.c_lflag |= (ICANON | ECHONL);
        }

        if (tcsetattr(STDIN_FILENO, TCSANOW, &newTerm) != 0) {
            printf("Couldn't turn off echo.\n");
            return -1;
        }
    }
#else
    static int echoInit = 0;
    static DWORD originalTerm;
    static CONSOLE_SCREEN_BUFFER_INFO screenOrig;
    HANDLE stdinHandle = GetStdHandle(STD_INPUT_HANDLE);
    if (!echoInit) {
        if (GetConsoleMode(stdinHandle, &originalTerm) == 0) {
            printf("Couldn't get the original terminal settings.\n");
            return -1;
        }
        echoInit = 1;
    }
    if (type == 1) {
        if (SetConsoleMode(stdinHandle, originalTerm) == 0) {
            printf("Couldn't restore the terminal settings.\n");
            return -1;
        }
    }
    else if (type == 2) {
        DWORD newTerm = originalTerm;

        newTerm &= ~ENABLE_PROCESSED_INPUT;
        newTerm &= ~ENABLE_PROCESSED_OUTPUT;
        newTerm &= ~ENABLE_LINE_INPUT;
        newTerm &= ~ENABLE_ECHO_INPUT;
        newTerm &= ~(ENABLE_EXTENDED_FLAGS | ENABLE_INSERT_MODE);

        if (SetConsoleMode(stdinHandle, newTerm) == 0) {
            printf("Couldn't turn off echo.\n");
            return -1;
        }
    }
    else {
        DWORD newTerm = originalTerm;

        newTerm &= ~ENABLE_ECHO_INPUT;

        if (SetConsoleMode(stdinHandle, newTerm) == 0) {
            printf("Couldn't turn off echo.\n");
            return -1;
        }
    }
#endif

    return 0;
}


static void ShowUsage(void)
{
    printf("client %s\n", LIBWOLFSSH_VERSION_STRING);
    printf(" -?            display this help and exit\n");
    printf(" -h <host>     host to connect to, default %s\n", wolfSshIp);
    printf(" -p <num>      port to connect on, default %d\n", wolfSshPort);
    printf(" -u <username> username to authenticate as (REQUIRED)\n");
    printf(" -P <password> password for username, prompted if omitted\n");
    printf(" -x            exit after successful connection without doing\n"
           "               read/write\n");
    printf(" -N            use non-blocking sockets\n");
#ifdef WOLFSSH_TERM
    printf(" -t            use psuedo terminal\n");
#endif
#if !defined(SINGLE_THREADED) && !defined(WOLFSSL_NUCLEUS)
    printf(" -c <command>  executes remote command and pipe stdin/stdout\n");
#ifdef USE_WINDOWS_API
    printf(" -R            raw untranslated output\n");
#endif
#endif
}


static byte userPassword[256];
static byte userPublicKeyType[32];
static byte userPublicKey[512];
static word32 userPublicKeySz;


static const char junkTestKeyEcc[] =
    "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBN"
    "kI5JTP6D0lF42tbxX19cE87hztUS6FSDoGvPfiU0CgeNSbI+aFdKIzT"
    "P5CQEJSvm25qUzgDtH7oyaQROUnNvk=";


static int wsUserAuth(byte authType,
                      WS_UserAuthData* authData,
                      void* ctx)
{
    const char* defaultPassword = (const char*)ctx;
    word32 passwordSz = 0;
    int ret = WOLFSSH_USERAUTH_SUCCESS;
    (void)authType;

#ifdef DEBUG_WOLFSSH
    /* inspect supported types from server */
    printf("Server supports ");
    if (authData->type & WOLFSSH_USERAUTH_PASSWORD) {
        printf("password authentication");
    }
    if (authData->type & WOLFSSH_USERAUTH_PUBLICKEY) {
        printf(" and public key authentication");
    }
    printf("\n");
    printf("wolfSSH requesting to use type %d\n", authType);
#endif

    if (authData->type & WOLFSSH_USERAUTH_PUBLICKEY) {
        WS_UserAuthData_PublicKey* pk = &authData->sf.publicKey;

        /* we only have nobody's junk key loaded */
        if (authData->username != NULL && authData->usernameSz > 0 &&
                XSTRNCMP((char*)authData->username, "nobody",
                    authData->usernameSz) == 0) {
            pk->publicKeyType = userPublicKeyType;
            pk->publicKeyTypeSz = (word32)WSTRLEN((char*)userPublicKeyType);
            pk->publicKey = userPublicKey;
            pk->publicKeySz = userPublicKeySz;
            pk->privateKey = NULL;
            pk->privateKeySz = 0;
            ret = WOLFSSH_USERAUTH_SUCCESS;
        }
    }
    else if (authData->type & WOLFSSH_USERAUTH_PASSWORD) {
        if (defaultPassword != NULL) {
            passwordSz = (word32)strlen(defaultPassword);
            memcpy(userPassword, defaultPassword, passwordSz);
        }
        else {
            printf("Password: ");
            fflush(stdout);
            SetEcho(0);
            if (fgets((char*)userPassword, sizeof(userPassword), stdin) == NULL) {
                printf("Getting password failed.\n");
                ret = WOLFSSH_USERAUTH_FAILURE;
            }
            else {
                char* c = strpbrk((char*)userPassword, "\r\n");;
                if (c != NULL)
                    *c = '\0';
            }
            passwordSz = (word32)strlen((const char*)userPassword);
            SetEcho(1);
            #ifdef USE_WINDOWS_API
                printf("\r\n");
            #endif
        }

        if (ret == WOLFSSH_USERAUTH_SUCCESS) {
            authData->sf.password.password = userPassword;
            authData->sf.password.passwordSz = passwordSz;
        }
    }

    return ret;
}


static int wsPublicKeyCheck(const byte* pubKey, word32 pubKeySz, void* ctx)
{
    #ifdef DEBUG_WOLFSSH
        printf("Sample public key check callback\n"
               "  public key = %p\n"
               "  public key size = %u\n"
               "  ctx = %s\n", pubKey, pubKeySz, (const char*)ctx);
    #else
        (void)pubKey;
        (void)pubKeySz;
        (void)ctx;
    #endif
    return 0;
}


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
        if (select_ret == WS_SELECT_RECV_READY ||
            select_ret == WS_SELECT_ERROR_READY)
        {
            ret = wolfSSH_connect(ssh);
        }
        else if (select_ret == WS_SELECT_TIMEOUT)
            error = WS_WANT_READ;
        else
            error = WS_FATAL_ERROR;
    }

    return ret;
}

#if !defined(SINGLE_THREADED) && !defined(WOLFSSL_NUCLEUS)

typedef struct thread_args {
    WOLFSSH* ssh;
    wolfSSL_Mutex lock;
    byte rawMode;
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
    #else
        ret = (int)read(STDIN_FILENO, buf, bufSz -1);
        sz  = (word32)ret;
    #endif
        if (ret <= 0) {
            err_sys("Error reading stdin");
        }
        /* lock SSH structure access */
        wc_LockMutex(&args->lock);
        ret = wolfSSH_stream_send(args->ssh, buf, sz);
        wc_UnLockMutex(&args->lock);
        if (ret <= 0)
            err_sys("Couldn't send data");
    }
#if defined(HAVE_ECC) && defined(FP_ECC) && defined(HAVE_THREAD_LS)
    wc_ecc_fp_free();  /* free per thread cache */
#endif
    return THREAD_RET_SUCCESS;
}


static THREAD_RET readPeer(void* in)
{
    byte buf[80];
    int  bufSz = sizeof(buf);
    thread_args* args = (thread_args*)in;
    int ret = 0;
    int fd = wolfSSH_get_fd(args->ssh);
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

    while (ret >= 0) {
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
                    fprintf(stderr, "%s", buf);
                } while (ret > 0);
            }
            else if (ret <= 0) {
                #ifdef WOLFSSH_AGENT
                if (ret == WS_FATAL_ERROR) {
                    ret = wolfSSH_get_error(args->ssh);
                    if (ret == WS_CHAN_RXD) {
                        byte agentBuf[512];
                        int rxd, txd;

                        rxd = wolfSSH_ChannelIdRead(args->ssh, 1,
                                agentBuf, sizeof(agentBuf));
                        txd = rxd;
                        rxd = sizeof(agentBuf);
                        ret = wolfSSH_AGENT_Relay(args->ssh,
                                agentBuf, (word32*)&txd,
                                agentBuf, (word32*)&rxd);
                        txd = wolfSSH_ChannelIdSend(args->ssh, 1,
                                agentBuf, rxd);
                        WMEMSET(agentBuf, 0, sizeof(agentBuf));
                        continue;
                    }
                }
                #endif
                if (ret != WS_EOF) {
                    err_sys("Stream read failed.");
                }
            }
            else {
                buf[bufSz - 1] = '\0';

            #ifdef USE_WINDOWS_API
                if (args->rawMode == 0) {
                    ret = wolfSSH_ConvertConsole(args->ssh, stdoutHandle, buf,
                            ret);
                    if (ret != WS_SUCCESS && ret != WS_WANT_READ) {
                        err_sys("issue with print out");
                    }
                    if (ret == WS_WANT_READ) {
                        ret = 0;
                    }
                }
                else {
                    printf("%s", buf);
                    fflush(stdout);
                }
            #else
                printf("%s", buf);
                fflush(stdout);
            #endif
            }
            if (wolfSSH_stream_peek(args->ssh, buf, bufSz) <= 0) {
                bytes = 0; /* read it all */
            }
        }
        wc_UnLockMutex(&args->lock);
    }
#if defined(HAVE_ECC) && defined(FP_ECC) && defined(HAVE_THREAD_LS)
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


#ifdef WOLFSSH_SHELL

#ifdef WOLFSSH_AGENT
typedef struct WS_AgentCbActionCtx {
    struct sockaddr_un name;
    int fd;
    int state;
} WS_AgentCbActionCtx;
#endif

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


#endif /* WOLFSSH_SHELL */


THREAD_RETURN WOLFSSH_THREAD client_test(void* args)
{
    WOLFSSH_CTX* ctx = NULL;
    WOLFSSH* ssh = NULL;
    SOCKET_T sockFd = WOLFSSH_SOCKET_INVALID;
    SOCKADDR_IN_T clientAddr;
    socklen_t clientAddrSz = sizeof(clientAddr);
    char rxBuf[80];
    int ret;
    int ch;
    word16 port = wolfSshPort;
    char* host = (char*)wolfSshIp;
    const char* username = NULL;
    const char* password = NULL;
    const char* cmd      = NULL;
    byte imExit = 0;
    byte nonBlock = 0;
    byte keepOpen = 0;
#ifdef USE_WINDOWS_API
    byte rawMode = 0;
#endif
#ifdef WOLFSSH_AGENT
    WS_AgentCbActionCtx agentCbCtx;
#endif

    int     argc = ((func_args*)args)->argc;
    char**  argv = ((func_args*)args)->argv;
    ((func_args*)args)->return_code = 0;

    while ((ch = mygetopt(argc, argv, "?NP:h:p:u:xc:Rtz")) != -1) {
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

            case 'p':
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

            case 'x':
                /* exit after successful connection without read/write */
                imExit = 1;
                break;

            case 'N':
                nonBlock = 1;
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

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_CLIENT, NULL);
    if (ctx == NULL)
        err_sys("Couldn't create wolfSSH client context.");

    userPublicKeySz = (word32)sizeof(userPublicKey);
    Base64_Decode((byte*)junkTestKeyEcc,
            (word32)WSTRLEN(junkTestKeyEcc),
            (byte*)userPublicKey, &userPublicKeySz);

    WSTRNCPY((char*)userPublicKeyType, "ecdsa-sha2-nistp256",
            sizeof(userPublicKeyType));

    if (((func_args*)args)->user_auth == NULL)
        wolfSSH_SetUserAuth(ctx, wsUserAuth);
    else
        wolfSSH_SetUserAuth(ctx, ((func_args*)args)->user_auth);

#ifdef WOLFSSH_AGENT
    wolfSSH_CTX_set_agent_cb(ctx,
            wolfSSH_AGENT_DefaultActions, wolfSSH_AGENT_IO_Cb);
    wolfSSH_CTX_AGENT_enable(ctx, 1);
#endif

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
    memset(&agentCbCtx, 0, sizeof(agentCbCtx));
    agentCbCtx.state = AGENT_STATE_INIT;
    wolfSSH_set_agent_cb_ctx(ssh, &agentCbCtx);
#endif

    wolfSSH_CTX_SetPublicKeyCheck(ctx, wsPublicKeyCheck);
    wolfSSH_SetPublicKeyCheckCtx(ssh, (void*)"You've been sampled!");

    ret = wolfSSH_SetUsername(ssh, username);
    if (ret != WS_SUCCESS)
        err_sys("Couldn't set the username.");

    build_addr(&clientAddr, host, port);
    tcp_socket(&sockFd);
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

#if !defined(SINGLE_THREADED) && !defined(WOLFSSL_NUCLEUS)
    if (keepOpen) /* set up for psuedo-terminal */
        SetEcho(2);

    if (cmd != NULL || keepOpen == 1) {
    #if defined(_POSIX_THREADS)
        thread_args arg;
        pthread_t   thread[2];

        arg.ssh = ssh;
        wc_InitMutex(&arg.lock);
        pthread_create(&thread[0], NULL, readInput, (void*)&arg);
        pthread_create(&thread[1], NULL, readPeer, (void*)&arg);
        pthread_join(thread[1], NULL);
        pthread_cancel(thread[0]);
    #elif defined(_MSC_VER)
        thread_args arg;
        HANDLE thread[2];

        arg.ssh     = ssh;
        arg.rawMode = rawMode;
        wc_InitMutex(&arg.lock);
        thread[0] = CreateThread(NULL, 0, readInput, (void*)&arg, 0, 0);
        thread[1] = CreateThread(NULL, 0, readPeer, (void*)&arg, 0, 0);
        WaitForSingleObject(thread[1], INFINITE);
        CloseHandle(thread[0]);
        CloseHandle(thread[1]);
    #else
        err_sys("No threading to use");
    #endif
        if (keepOpen)
            SetEcho(1);
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
                if (ret != WS_WANT_READ && ret != WS_WANT_WRITE)
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
    WCLOSESOCKET(sockFd);
    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);
    if (ret != WS_SUCCESS)
        err_sys("Closing stream failed. Connection could have been closed by peer");

#if defined(HAVE_ECC) && defined(FP_ECC) && defined(HAVE_THREAD_LS)
    wc_ecc_fp_free();  /* free per thread cache */
#endif

    return 0;
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

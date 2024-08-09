/* wolfssh.c
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
#include <wolfssh/version.h>
#include <wolfssl/version.h>
#include <wolfssh/test.h>
#ifdef WOLFSSH_AGENT
    #include <wolfssh/agent.h>
#endif
#include <wolfssl/wolfcrypt/ecc.h>
#include "examples/client/client.h"
#include "apps/wolfssh/common.h"
#if !defined(USE_WINDOWS_API) && !defined(MICROCHIP_PIC32)
    #include <termios.h>
#endif

#include <sys/param.h>
#include <libgen.h>

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


int myoptind = 0;
char* myoptarg = NULL;


static void ShowUsage(char* appPath)
{
    const char* appName;

    appName = basename(appPath);
    /* Attempt to use the actual program name from the caller. Otherwise,
     * default to "wolfssh". */
    if (appName == NULL) {
        appName = "wolfssh";
    }

    printf("%s v%s\n", appName, LIBWOLFSSH_VERSION_STRING);
    printf("usage: %s [-E logfile] [-G] [-l login_name] [-N] [-p port] "
            "[-V] destination\n",
            appName);
}


#ifdef WOLFSSH_CERTS
static const char* certName = NULL;
static const char* caCert   = NULL;
#endif


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

#if defined(HAVE_TERMIOS_H) && defined(WOLFSSH_TERM)
WOLFSSH_TERMIOS oldTerm;

static void modes_store(void)
{
    tcgetattr(STDIN_FILENO, &oldTerm);
}

static void modes_clear(void)
{
    WOLFSSH_TERMIOS term = oldTerm;

    term.c_lflag &= ~(ICANON | ISIG | IEXTEN | ECHO | ECHOE
        | ECHOK | ECHONL | NOFLSH | TOSTOP);

    /* check macros set for some BSD dependent and missing on
     * QNX flags */
#ifdef ECHOPRT
    term.c_lflag &= ~(ECHOPRT);
#endif
#ifdef FLUSHO
    term.c_lflag &= ~(FLUSHO);
#endif
#ifdef PENDIN
    term.c_lflag &= ~(PENDIN);
#endif
#ifdef EXTPROC
    term.c_lflag &= ~(EXTPROC);
#endif

    term.c_iflag &= ~(ISTRIP | INLCR | ICRNL | IGNCR | IXON
        | IXOFF | IXANY | IGNBRK | INPCK | PARMRK);
#ifdef IUCLC
    term.c_iflag &= ~IUCLC;
#endif
    term.c_iflag |= IGNPAR;

    term.c_oflag &= ~(OPOST | ONOCR | ONLRET);
#ifdef OUCLC
    term.c_oflag &= ~OLCUC;
#endif

    term.c_cflag &= ~(CSTOPB | PARENB | PARODD | CLOCAL);
#ifdef CRTSCTS
    term.c_cflag &= ~(CRTSCTS);
#endif
    tcsetattr(STDIN_FILENO, TCSANOW, &term);
}

static void modes_reset(void)
{
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &oldTerm);
}

#define MODES_STORE() modes_store()
#define MODES_CLEAR() modes_clear()
#define MODES_RESET() modes_reset()
#else /* HAVE_TERMIOS_H && WOLFSSH_TERM */
#define MODES_STORE() do {} while(0)
#define MODES_CLEAR() do {} while(0)
#define MODES_RESET() do {} while(0)
#endif /* HAVE_TERMIOS_H && WOLFSSH_TERM */

#if !defined(SINGLE_THREADED) && !defined(WOLFSSL_NUCLEUS)

#if defined(WOLFSSH_AGENT)
static inline void ato32(const byte* c, word32* u32)
{
    *u32 = (c[0] << 24) | (c[1] << 16) | (c[2] << 8) | c[3];
}
#endif

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

        if (GetConsoleScreenBufferInfo(
                    GetStdHandle(STD_OUTPUT_HANDLE), &cs) != 0) {
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


static THREAD_RET readPeer(void* in)
{
    byte buf[256];
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
    #if defined(WOLFSSH_TERM) && defined(USE_WINDOWS_API)
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
                        continue;
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
            }
            ret = wolfSSH_stream_peek(args->ssh, buf, bufSz);
            if (ret <= 0) {
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

static int callbackGlobalReq(WOLFSSH *ssh, void *buf, word32 sz,
        int reply, void *ctx)
{
    char reqStr[] = "SampleRequest";

    if ((WOLFSSH *)ssh != *(WOLFSSH **)ctx) {
        printf("ssh(%p) != ctx(%p)\n", ssh, *(WOLFSSH **)ctx);
        return WS_FATAL_ERROR;
    }

    if (WSTRLEN(reqStr) == sz
            && (WSTRNCMP((char *)buf, reqStr, sz) == 0)
            && reply == 1) {
        printf("Global Request\n");
        return WS_SUCCESS;
    }
    else {
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
            WMEMSET(name, 0, sizeof(struct sockaddr_un));
            name->sun_family = AF_LOCAL;
            WSTRNCPY(name->sun_path, sockName, sizeof(name->sun_path));
            name->sun_path[sizeof(name->sun_path) - 1] = '\0';
            size = WSTRLEN(sockName) +
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


struct config {
    char* logFile;
    char* user;
    char* hostname;
    char* keyFile;
    char* pubKeyFile;
    char* command;
    word32 printConfig:1;
    word32 noCommand:1;
    word16 port;
};


static int config_init_default(struct config* config)
{
    char* env;
    size_t sz;

    WMEMSET(config, 0, sizeof(*config));
    config->port = 22;

    env = getenv("USER");
    if (env != NULL) {
        char* user;

        sz = WSTRLEN(env) + 1;
        user = (char*)WMALLOC(sz, NULL, 0);
        if (user != NULL) {
            strcpy(user, env);
            config->user = user;
        }
    }

    env = getenv("HOME");
    if (env != NULL) {
        const char* defaultName = "/.ssh/id_ecdsa";
        const char* pubSuffix = ".pub";
        char* keyFile;

        sz = WSTRLEN(env) + WSTRLEN(defaultName) + 1;
        keyFile = (char*)WMALLOC(sz, NULL, 0);
        if (keyFile != NULL) {
            strcpy(keyFile, env);
            strcat(keyFile, defaultName);
            config->keyFile = keyFile;
        }

        sz += WSTRLEN(pubSuffix);
        keyFile = (char*)WMALLOC(sz, NULL, 0);
        if (keyFile != NULL) {
            strcpy(keyFile, env);
            strcat(keyFile, defaultName);
            strcat(keyFile, pubSuffix);
            config->pubKeyFile = keyFile;
        }
    }

    return 0;
}


static int config_parse_command_line(struct config* config,
        int argc, char** argv)
{
    int ch;

    while ((ch = mygetopt(argc, argv, "E:Gl:Np:V")) != -1) {
        switch (ch) {
            case 'E':
                config->logFile = myoptarg;
                break;

            case 'G':
                config->printConfig = 1;
                break;

            case 'l':
                config->user = myoptarg;
                break;

            case 'N':
                config->noCommand = 1;
                break;

            case 'p':
                config->port = (word16)atoi(myoptarg);
                break;

            case 'V':
                fprintf(stderr, "wolfSSH v%s, wolfSSL v%s\n",
                        LIBWOLFSSH_VERSION_STRING,
                        LIBWOLFSSL_VERSION_STRING);
                exit(EXIT_SUCCESS);

            default:
                ShowUsage(argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    /* Parse the destination. Either:
     *  - [user@]hostname
     *  - ssh://[user@]hostname[:port] */
    if (myoptind < argc) {
        const char* uriPrefix = "ssh://";
        char* dest;
        char* cursor;
        char* found;
        size_t sz;
        int checkPort;

        myoptarg = argv[myoptind];

        sz = WSTRLEN(myoptarg) + 1;
        dest = (char*)WMALLOC(sz, NULL, 0);
        WMEMCPY(dest, myoptarg, sz);
        cursor = dest;

        if (WSTRSTR(cursor, uriPrefix)) {
            checkPort = 1;
            cursor += WSTRLEN(uriPrefix);
        }
        else {
            checkPort = 0;
        }

        found = WSTRCHR(cursor, '@');
        if (found == cursor) {
            fprintf(stderr, "can't start destination with just an @\n");
        }
        if (found != NULL) {
            *found = '\0';
            if (config->user) {
                free(config->user);
            }
            sz = WSTRLEN(cursor);
            config->user = (char*)WMALLOC(sz + 1, NULL, 0);
            strcpy(config->user, cursor);
            cursor = found + 1;
        }

        if (checkPort) {
            found = WSTRCHR(cursor, ':');
            if (found != NULL) {
                *found = '\0';
                sz = WSTRLEN(cursor);
                config->hostname = (char*)WMALLOC(sz + 1, NULL, 0);
                strcpy(config->hostname, cursor);
                cursor = found + 1;
                if (*cursor != 0) {
                    config->port = atoi(cursor);
                }
            }
        }
        else {
            sz = WSTRLEN(cursor);
            config->hostname = (char*)WMALLOC(sz + 1, NULL, 0);
            strcpy(config->hostname, cursor);
        }

        free(dest);
        myoptind++;
    }

    if (myoptind < argc) {
        int i;
        size_t commandSz;
        char* cursor;
        char* command;

        /* Count the spaces needed. The following will calculate one extra
         * space but that's for the nul termination. */
        commandSz = argc - myoptind;
        for (i = myoptind; i < argc; i++) {
            commandSz += WSTRLEN(argv[i]);
        }

        command = (char*)WMALLOC(commandSz, NULL, 0);
        config->command = command;
        cursor = command;

        for (i = myoptind; i < argc; i++) {
            cursor = stpcpy(cursor, argv[i]);
            *cursor = ' ';
            cursor++;
        }
        *(--cursor) = '\0';
        myoptind++;
    }

    return 0;
}


static int config_print(struct config* config)
{
    if (config->printConfig) {
        printf("user %s\n", config->user ? config->user : "none");
        printf("hostname %s\n", config->hostname ? config->hostname : "none");
        printf("port %u\n", config->port);
        printf("keyFile %s\n", config->keyFile ? config->keyFile : "none");
        printf("pubKeyFile %s\n",
                config->keyFile ? config->keyFile : "none");
        printf("noCommand %s\n", config->noCommand ? "true" : "false");
        printf("logfile %s\n", config->logFile ? config->logFile : "default");
        printf("command %s\n", config->command ? config->command : "none");
    }

    return 0;
}


static int config_cleanup(struct config* config)
{
    if (config->user) {
        WFREE(config->user, NULL, 0);
    }
    if (config->hostname) {
        WFREE(config->hostname, NULL, 0);
    }
    if (config->keyFile) {
        WFREE(config->keyFile, NULL, 0);
    }
    if (config->pubKeyFile) {
        WFREE(config->pubKeyFile, NULL, 0);
    }
    if (config->command) {
        WFREE(config->command, NULL, 0);
    }

    return 0;
}


static THREAD_RETURN WOLFSSH_THREAD wolfSSH_Client(void* args)
{
    WOLFSSH_CTX* ctx = NULL;
    WOLFSSH* ssh = NULL;
    SOCKET_T sockFd = WOLFSSH_SOCKET_INVALID;
    SOCKADDR_IN_T clientAddr;
    socklen_t clientAddrSz = sizeof(clientAddr);
    int ret = 0;
    const char* password = NULL;
    byte keepOpen = 1;
#ifdef USE_WINDOWS_API
    byte rawMode = 0;
#endif
#ifdef WOLFSSH_AGENT
    byte useAgent = 0;
    WS_AgentCbActionCtx agentCbCtx;
#endif
    struct config config;

    MODES_STORE();

    ((func_args*)args)->return_code = 0;

    config_init_default(&config);
    config_parse_command_line(&config,
            ((func_args*)args)->argc, ((func_args*)args)->argv);
    config_print(&config);

    if (config.user == NULL)
        err_sys("client requires a username parameter.");

#ifdef SINGLE_THREADED
    if (keepOpen)
        err_sys("Threading needed for terminal session\n");
#endif

    if (config.keyFile) {
        ret = ClientSetPrivateKey(config.keyFile);
        if (ret == 0) {
        #ifdef WOLFSSH_CERTS
            /* passed in certificate to use */
            if (certName) {
                (void)ClientUseCert(certName);
            }
            else
        #endif
            if (config.pubKeyFile) {
                (void)ClientUsePubKey(config.pubKeyFile);
            }
        }
    }

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_CLIENT, NULL);
    if (ctx == NULL)
        err_sys("Couldn't create wolfSSH client context.");

    wolfSSH_SetUserAuth(ctx, ClientUserAuth);

#ifdef WOLFSSH_AGENT
    if (useAgent) {
        wolfSSH_CTX_set_agent_cb(ctx,
                wolfSSH_AGENT_DefaultActions, wolfSSH_AGENT_IO_Cb);
        wolfSSH_CTX_AGENT_enable(ctx, 1);
    }
#endif

#ifdef WOLFSSH_CERTS
    ClientLoadCA(ctx, caCert);
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
        WMEMSET(&agentCbCtx, 0, sizeof(agentCbCtx));
        agentCbCtx.state = AGENT_STATE_INIT;
        wolfSSH_set_agent_cb_ctx(ssh, &agentCbCtx);
    }
#endif

    wolfSSH_SetPublicKeyCheckCtx(ssh, (void*)config.hostname);

    ret = wolfSSH_SetUsername(ssh, config.user);
    if (ret != WS_SUCCESS)
        err_sys("Couldn't set the username.");

    build_addr(&clientAddr, config.hostname, config.port);
    tcp_socket(&sockFd, ((struct sockaddr_in *)&clientAddr)->sin_family);

    ret = connect(sockFd, (const struct sockaddr *)&clientAddr, clientAddrSz);
    if (ret != 0)
        err_sys("Couldn't connect to server.");

    tcp_set_nonblocking(&sockFd);

    ret = wolfSSH_set_fd(ssh, (int)sockFd);
    if (ret != WS_SUCCESS)
        err_sys("Couldn't set the session's socket.");

    if (config.command != NULL) {
        ret = wolfSSH_SetChannelType(ssh, WOLFSSH_SESSION_EXEC,
                            (byte*)config.command,
                            (word32)WSTRLEN((char*)config.command));
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

    ret = NonBlockSSH_connect(ssh);
    if (ret != WS_SUCCESS)
        err_sys("Couldn't connect SSH stream.");

    MODES_CLEAR();

#if !defined(SINGLE_THREADED) && !defined(WOLFSSL_NUCLEUS)
#if 0
    if (keepOpen) /* set up for psuedo-terminal */
        ClientSetEcho(2);
#endif

    if (config.command != NULL || keepOpen == 1) {
    #if defined(_POSIX_THREADS)
        thread_args arg;
        pthread_t   thread[3];

        wc_InitMutex(&arg.lock);
        arg.ssh = ssh;
#ifdef WOLFSSH_TERM
        arg.quit = 0;
    #if (defined(__OSX__) || defined(__APPLE__))
        windowSem = dispatch_semaphore_create(0);
    #else
        sem_init(&windowSem, 0, 0);
    #endif

        if (config.command) {
            int err;

            /* exec command does not contain initial terminal size,
             * unlike pty-req. Send an inital terminal size for recieving
             * the results of the command */
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

        if (config.command) {
            int err;

            /* exec command does not contain initial terminal size,
             * unlike pty-req. Send an inital terminal size for recieving
             * the results of the command */
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
#endif

    ret = wolfSSH_shutdown(ssh);
    /* do not continue on with shutdown process if peer already disconnected */
    if (ret != WS_SOCKET_ERROR_E
            && wolfSSH_get_error(ssh) != WS_SOCKET_ERROR_E) {
        if (ret != WS_SUCCESS) {
            WLOG(WS_LOG_DEBUG, "Sending the shutdown messages failed.");
        }
        else {
            ret = wolfSSH_worker(ssh, NULL);
        }
        if (ret == WS_CHANNEL_CLOSED) {
            /* Shutting down, channel closing isn't a fail. */
            ret = WS_SUCCESS;
        }
        else if (ret != WS_SUCCESS) {
            WLOG(WS_LOG_DEBUG,
                "Failed to listen for close messages from the peer.");
        }
    }
    WCLOSESOCKET(sockFd);

#if defined(WOLFSSH_TERM) || defined(WOLFSSH_SHELL)
    ((func_args*)args)->return_code = wolfSSH_GetExitStatus(ssh);
#endif

    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);
    if (ret != WS_SUCCESS && ret != WS_SOCKET_ERROR_E) {
        WLOG(WS_LOG_DEBUG, "Closing client stream failed");
    #if defined(WOLFSSH_TERM) || defined(WOLFSSH_SHELL)
        /* override return value, do not want to return success if connection
         * close failed */
        ((func_args*)args)->return_code = 1;
    #endif
    }

    ClientFreeBuffers();
#if !defined(WOLFSSH_NO_ECC) && defined(FP_ECC) && defined(HAVE_THREAD_LS)
    wc_ecc_fp_free();  /* free per thread cache */
#endif

    config_cleanup(&config);
    MODES_RESET();

    return 0;
}


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

    wolfSSH_Client(&args);

    wolfSSH_Cleanup();

    return args.return_code;
}

/* portfwd.c
 *
 * Copyright (C) 2014-2026 wolfSSL Inc.
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
#define WOLFSSH_TEST_SERVER

#ifdef WOLFSSL_USER_SETTINGS
    #include <wolfssl/wolfcrypt/settings.h>
#else
    #include <wolfssl/options.h>
#endif

#include <stdio.h>
#ifdef HAVE_TERMIOS_H
    #include <termios.h>
#endif
#include <errno.h>
#ifdef HAVE_SYS_SELECT_H
    #include <sys/select.h>
#endif
#include <wolfssh/ssh.h>
#include <wolfssh/internal.h>
#include <wolfssh/test.h>
#include <wolfssh/port.h>
#include <wolfssl/wolfcrypt/ecc.h>

#ifndef NO_WOLFSSH_CLIENT
#include "examples/portfwd/wolfssh_portfwd.h"


/* The portfwd tool will be a client or server in the port forwarding
 * interaction.
 *
 * The portfwd client will connect to an SSH server and request a tunnel.
 * The client acts like a server for the local user application. It forwards
 * the packets received to the SSH server who will then forward the packet
 * to its local application server.
 *
 * The portfwd server will listen for SSH connections, and when it receives
 * one will only accept forward requests from the connection. All data for
 * the forwarding channel are sent to the local application server and
 * data from the server is forwarded to the client.
 */


#ifndef EXAMPLE_BUFFER_SZ
    #define EXAMPLE_BUFFER_SZ 4096
#endif

#define INVALID_FWD_PORT 0
/* wolfSSH_worker() calls to wait for a want-reply tcpip-forward answer. */
#define MAX_REPLY_TRIES 100
static const char defaultFwdFromHost[] = "0.0.0.0";


static inline int findMax(int a, int b)
{
    return (a > b) ? a : b;
}


/* Parse a port option. atoi() would wrap an out of range value into a valid
 * looking port; 65536 becoming 0 is the bad one, since 0 asks the peer to
 * allocate the reverse listener. */
static word16 parsePort(const char* arg, const char* opt)
{
    char* end = NULL;
    long val;

    val = strtol(arg, &end, 10);
    if (end == arg || *end != '\0' || val < 0 || val > 65535) {
        printf("Port for %s must be 0 to 65535, got \"%s\".\n", opt, arg);
        err_sys("bad port argument");
    }
    return (word16)val;
}

static void ShowUsage(void)
{
    printf("portfwd %s linked with wolfSSL %s\n"
           " -?            display this help and exit\n"
           " -h <host>     host to connect to, default %s\n"
           " -p <num>      port to connect on, default %u\n"
           " -u <username> username to authenticate as (REQUIRED)\n"
           " -P <password> password for username, prompted if omitted\n"
           " -F <host>     host to forward from, default %s\n"
           " -f <num>      host port to forward from (REQUIRED), 0 with -r\n"
           "               lets the peer pick the listener port\n"
           " -T <host>     host to forward to, default to host\n"
           " -t <num>      port to forward to (REQUIRED)\n"
           " -r            remote (reverse) forward: ask the SSH server to\n"
           "               listen on -F/-f and tunnel connections back to\n"
           "               the local -T/-t target\n",
           LIBWOLFSSH_VERSION_STRING,
           LIBWOLFSSL_VERSION_STRING,
           wolfSshIp, wolfSshPort, defaultFwdFromHost);
}


static int SetEcho(int on)
{
#ifndef USE_WINDOWS_API
    static int echoInit = 0;
    static struct termios originalTerm;
    if (!echoInit) {
        if (tcgetattr(STDIN_FILENO, &originalTerm) != 0) {
            printf("Couldn't get the original terminal settings.\n");
            return -1;
        }
        echoInit = 1;
    }
    if (on) {
        if (tcsetattr(STDIN_FILENO, TCSANOW, &originalTerm) != 0) {
            printf("Couldn't restore the terminal settings.\n");
            return -1;
        }
    }
    else {
        struct termios newTerm;
        memcpy(&newTerm, &originalTerm, sizeof(struct termios));

        newTerm.c_lflag &= ~ECHO;
        newTerm.c_lflag |= (ICANON | ECHONL);

        if (tcsetattr(STDIN_FILENO, TCSANOW, &newTerm) != 0) {
            printf("Couldn't turn off echo.\n");
            return -1;
        }
    }
#else
    static int echoInit = 0;
    static DWORD originalTerm;
    HANDLE stdinHandle = GetStdHandle(STD_INPUT_HANDLE);
    if (!echoInit) {
        if (GetConsoleMode(stdinHandle, &originalTerm) == 0) {
            printf("Couldn't get the original terminal settings.\n");
            return -1;
        }
        echoInit = 1;
    }
    if (on) {
        if (SetConsoleMode(stdinHandle, originalTerm) == 0) {
            printf("Couldn't restore the terminal settings.\n");
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


byte userPassword[256];


static int wsUserAuth(byte authType,
                      WS_UserAuthData* authData,
                      void* ctx)
{
    const char* defaultPassword = (const char*)ctx;
    word32 passwordSz = 0;
    int ret = WOLFSSH_USERAUTH_SUCCESS;

    (void)authType;
    if (defaultPassword != NULL) {
        passwordSz = (word32)strlen(defaultPassword);
        if (passwordSz > (word32)sizeof(userPassword))
            passwordSz = (word32)sizeof(userPassword);
        memcpy(userPassword, defaultPassword, passwordSz);
    }
    else {
        printf("Password: ");
        SetEcho(0);
        if (WFGETS((char*)userPassword, sizeof(userPassword), stdin) == NULL) {
            printf("Getting password failed.\n");
            ret = WOLFSSH_USERAUTH_FAILURE;
        }
        else {
            char* c = strpbrk((char*)userPassword, "\r\n");;
            if (c != NULL)
                *c = '\0';
            passwordSz = (word32)strlen((const char*)userPassword);
        }
        SetEcho(1);
#ifdef USE_WINDOWS_API
        printf("\r\n");
#endif
    }

    if (ret == WOLFSSH_USERAUTH_SUCCESS) {
        authData->sf.password.password = userPassword;
        authData->sf.password.passwordSz = passwordSz;
    }

    return ret;
}


static int wsPublicKeyCheck(const byte* pubKey, word32 pubKeySz, void* ctx)
{
    printf("Sample public key check callback\n"
           "  public key = %p\n"
           "  public key size = %u\n"
           "  ctx = %s\n", pubKey, pubKeySz, (const char*)ctx);
    return 0;
}


/* State shared with the remote-forward callbacks. One reverse connection at a
 * time; a second concurrent channel is refused rather than tracked, since a
 * single appFd cannot carry two. A production tool would key a table by
 * channel id. */
typedef struct PortfwdState {
    const char* fwdToHost;  /* local target to connect inbound channels to */
    word16 fwdToPort;
    SOCKADDR_IN_T targetAddr;  /* fwdToHost:fwdToPort, resolved at startup */
    SOCKET_T appFd;         /* socket to the local target, -1 when idle */
    word32 channelId;       /* id of the inbound forwarded-tcpip channel */
    int pending;            /* a new channel is waiting to be wired up */
    int replied;            /* peer answered the tcpip-forward request */
    int refused;            /* ...and the answer was a refusal */
    int badPort;            /* ...or named a port outside 1..65535 */
    int wantPortZero;       /* the request asked the peer to pick the port */
    word16 boundPort;       /* port the peer reported binding */
} PortfwdState;


/* Open a TCP connection to the pre-resolved forward target. Returns -1 on
 * failure. Unlike tcp_socket(), nothing here exits the process: this runs
 * inside a channel-open callback, where the right answer is to refuse the one
 * channel. The address is resolved once at startup so build_addr()'s err_sys()
 * on an unresolvable host cannot fire from here. */
static SOCKET_T connectTarget(const SOCKADDR_IN_T* addr)
{
    SOCKET_T fd;

    fd = socket(((const struct sockaddr_in*)addr)->sin_family, SOCK_STREAM, 0);
    if (fd == (SOCKET_T)-1) {
        return (SOCKET_T)-1;
    }
#ifdef SO_NOSIGPIPE
    {
        int on = 1;
        (void)setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &on,
                (socklen_t)sizeof(on));
    }
#endif
    if (connect(fd, (const struct sockaddr*)addr, sizeof(*addr)) != 0) {
        WCLOSESOCKET(fd);
        return (SOCKET_T)-1;
    }
    return fd;
}


/* Forwarding callback for client-side remote forwarding. Each connection to
 * the peer's listener arrives here as a LOCAL_SETUP then a CHANNEL_ID. */
static int portfwdRemoteFwdCb(WS_FwdCbAction action, void* ctx,
        const char* address, word32 port)
{
    PortfwdState* st = (PortfwdState*)ctx;
    int ret = WS_FWD_SUCCESS;

    switch (action) {
        case WOLFSSH_FWD_LOCAL_SETUP:
            /* address/port name the peer's listener, not our target. */
            (void)address;
            (void)port;
            if (st->appFd != (SOCKET_T)-1 || st->pending) {
                /* Only one tunnelled connection is tracked. Refuse the extra
                 * channel instead of overwriting the live one, which would
                 * misdeliver its data and orphan its socket. */
                printf("Refusing a second concurrent forwarded connection.\n");
                ret = WS_FWD_SETUP_E;
                break;
            }
            st->appFd = connectTarget(&st->targetAddr);
            if (st->appFd == (SOCKET_T)-1) {
                printf("Couldn't connect to forward target %s:%u\n",
                        st->fwdToHost, st->fwdToPort);
                ret = WS_FWD_SETUP_E;
            }
            break;
        case WOLFSSH_FWD_CHANNEL_ID:
            /* The new channel's id arrives in the port argument. */
            st->channelId = port;
            st->pending = 1;
            break;
        case WOLFSSH_FWD_LOCAL_CLEANUP:
            /* The library does not currently emit this action, so this branch
             * never runs. The target socket is closed when portfwd_worker()
             * leaves its loop. Kept so the handler is right if that changes. */
            (void)address;
            (void)port;
            if (st->appFd != (SOCKET_T)-1) {
                WCLOSESOCKET(st->appFd);
                st->appFd = (SOCKET_T)-1;
            }
            break;
        case WOLFSSH_FWD_REMOTE_SETUP:
        case WOLFSSH_FWD_REMOTE_CLEANUP:
            /* Server-side actions; a requesting client never sees these. */
        default:
            break;
    }

    return ret;
}


/* Request-success callback. Per RFC 4254 7.1 the trailing port is only
 * meaningful when 0 was requested, so it is consulted only then; for a fixed
 * port the request already names the listener. */
static int portfwdReqSuccessCb(WOLFSSH* ssh, void* buf, word32 sz, void* ctx)
{
    PortfwdState* st = (PortfwdState*)ctx;
    const byte* p = (const byte*)buf;

    (void)ssh;
    if (!st->wantPortZero) {
        printf("Remote forward established.\n");
    }
    else if (p != NULL && sz >= 4) {
        word32 boundPort = ((word32)p[0] << 24) | ((word32)p[1] << 16) |
                ((word32)p[2] << 8) | (word32)p[3];

        /* Don't narrow a bogus port into a plausible one. */
        if (boundPort == 0 || boundPort > 65535) {
            printf("Peer reported an out of range bound port %u\n", boundPort);
            st->badPort = 1;
        }
        else {
            st->boundPort = (word16)boundPort;
            printf("Remote forward established; peer bound port %u\n",
                    boundPort);
        }
    }
    else {
        /* A port-0 request has no other way to learn the listener's port. */
        printf("Peer did not report a bound port for a port 0 request.\n");
        st->badPort = 1;
    }
    st->replied = 1;
    return WS_SUCCESS;
}


/* Request-failure callback. The peer refused the remote listener. */
static int portfwdReqFailureCb(WOLFSSH* ssh, void* buf, word32 sz, void* ctx)
{
    PortfwdState* st = (PortfwdState*)ctx;

    (void)ssh;
    (void)buf;
    (void)sz;
    st->replied = 1;
    st->refused = 1;
    return WS_SUCCESS;
}


/*
 * fwdFromHost - address to bind the local listener socket to (default: any)
 * fwdFromHostPort - port number to bind the local listener socket to
 * fwdToHost - address to tell the remote peer to connect to on behalf of the
 *      client (actual server address)
 * fwdToHostPort - port number to tell the remote peer to connect to on behalf
 *      of the client (actual server port)
 * host - peer SSH server address to connect to
 * hostPort - peer SSH server port number to connect to
 */

THREAD_RETURN WOLFSSH_THREAD portfwd_worker(void* args)
{
    WOLFSSH* ssh;
    WOLFSSH_CTX* ctx;
    char* host = (char*)wolfSshIp;
    word16 port = wolfSshPort;
    word16 fwdFromPort = INVALID_FWD_PORT;
    word16 fwdToPort = INVALID_FWD_PORT;
    const char* fwdFromHost = defaultFwdFromHost;
    const char* fwdToHost = NULL;
    const char* username = NULL;
    const char* password = NULL;
    const char* readyFile = NULL;
    SOCKADDR_IN_T hostAddr;
    socklen_t hostAddrSz = sizeof(hostAddr);
    SOCKET_T sshFd;
    SOCKADDR_IN_T fwdFromHostAddr;
    socklen_t fwdFromHostAddrSz = sizeof(fwdFromHostAddr);
    SOCKET_T listenFd = -1;
    SOCKET_T appFd = -1;
    int argc = ((func_args*)args)->argc;
    char** argv = ((func_args*)args)->argv;
    fd_set templateFds;
    fd_set rxFds;
    fd_set errFds;
    int nFds;
    int ret;
    int ch;
    int appFdSet = 0;
    int reverse = 0;
    int fwdFromPortSet = 0;
    PortfwdState fwdState;
    int replyTries;
    struct timeval to;
    WOLFSSH_CHANNEL* fwdChannel = NULL;
    byte* appBuffer = NULL;
    byte* sshBuffer = NULL;
    word32 appBufferSz = 0;
    word32 appBufferUsed = 0;
    word32 sshBufferSz = 0;
    word32 sshBufferUsed = 0;
#ifndef WOLFSSH_SMALL_STACK
    byte appBuffer_s[EXAMPLE_BUFFER_SZ];
    byte sshBuffer_s[EXAMPLE_BUFFER_SZ];
#endif

    ((func_args*)args)->return_code = 0;

    /* Initialized up front: the reads below are guarded by "reverse", but the
     * guard and the initializer would otherwise sit in different branches. */
    memset(&fwdState, 0, sizeof(fwdState));
    fwdState.appFd = (SOCKET_T)-1;

    while ((ch = mygetopt(argc, argv, "?rf:h:p:t:u:F:P:R:T:")) != -1) {
        switch (ch) {
            case 'h':
                host = myoptarg;
                break;

            case 'f':
                if (myoptarg == NULL)
                    err_sys("null argument found");
                fwdFromPort = parsePort(myoptarg, "-f");
                fwdFromPortSet = 1;
                break;

            case 'p':
                if (myoptarg == NULL)
                    err_sys("null argument found");
                port = parsePort(myoptarg, "-p");
                #if !defined(NO_MAIN_DRIVER) || defined(USE_WINDOWS_API)
                    if (port == 0)
                        err_sys("port number cannot be 0");
                #endif
                break;

            case 't':
                if (myoptarg == NULL)
                    err_sys("null argument found");
                fwdToPort = parsePort(myoptarg, "-t");
                break;

            case 'u':
                username = myoptarg;
                break;

            case 'F':
                fwdFromHost = myoptarg;
                break;

            case 'P':
                password = myoptarg;
                break;

            case 'R':
                readyFile = myoptarg;
                break;

            case 'T':
                fwdToHost = myoptarg;
                break;

            case 'r':
                reverse = 1;
                break;

            case '?':
                ShowUsage();
                exit(EXIT_SUCCESS);

            default:
                ShowUsage();
                exit(MY_EX_USAGE);
        }
    }
    myoptind = 0;

    if (username == NULL)
        err_sys("client requires a username parameter.");
    if (fwdToPort == INVALID_FWD_PORT)
        err_sys("requires a port to forward to");
    if (!fwdFromPortSet)
        err_sys("requires a port to forward from");
    /* Port 0 asks the peer to allocate the port, so it needs a peer that
     * listens. */
    if (fwdFromPort == INVALID_FWD_PORT && !reverse)
        err_sys("port 0 to forward from requires reverse mode");

    if (fwdToHost == NULL)
        fwdToHost = host;

    printf("portfwd options\n"
           " * ssh host: %s:%u\n"
           " * username: %s\n"
           " * password: %s\n"
           " * forward from: %s:%u\n"
           " * forward to: %s:%u\n",
           host, port, username, password ? password : "",
           fwdFromHost, fwdFromPort,
           fwdToHost, fwdToPort);

#ifdef WOLFSSH_SMALL_STACK
    appBuffer = (byte*)WMALLOC(EXAMPLE_BUFFER_SZ, NULL, 0);
    sshBuffer = (byte*)WMALLOC(EXAMPLE_BUFFER_SZ, NULL, 0);
    if (appBuffer == NULL || sshBuffer == NULL) {
        WFREE(appBuffer, NULL, 0);
        WFREE(sshBuffer, NULL, 0);
        err_sys("couldn't allocate buffers");
    }
    appBufferSz = EXAMPLE_BUFFER_SZ;
    sshBufferSz = EXAMPLE_BUFFER_SZ;
#else
    appBuffer = appBuffer_s;
    sshBuffer = sshBuffer_s;
    appBufferSz = sizeof appBuffer_s;
    sshBufferSz = sizeof sshBuffer_s;
#endif

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_CLIENT, NULL);
    if (ctx == NULL)
        err_sys("couldn't create the ssh client");

    if (((func_args*)args)->user_auth == NULL)
        wolfSSH_SetUserAuth(ctx, wsUserAuth);
    else
        wolfSSH_SetUserAuth(ctx, ((func_args*)args)->user_auth);

    ssh = wolfSSH_new(ctx);
    if (ssh == NULL)
        err_sys("Couldn't create wolfSSH session.");

    if (password != NULL)
        wolfSSH_SetUserAuthCtx(ssh, (void*)password);

    wolfSSH_CTX_SetPublicKeyCheck(ctx, wsPublicKeyCheck);
    wolfSSH_SetPublicKeyCheckCtx(ssh, (void*)"You've been sampled.");

    ret = wolfSSH_SetUsername(ssh, username);
    if (ret != WS_SUCCESS)
        err_sys("Couldn't set the username.");

    if (reverse) {
        /* The peer listens; its inbound channels reach us through the
         * forwarding callback, the bound port through request-success. */
        fwdState.fwdToHost = fwdToHost;
        fwdState.fwdToPort = fwdToPort;
        fwdState.wantPortZero = (fwdFromPort == 0);
        /* Resolved once here, where err_sys() on a bad host is appropriate,
         * so the per-channel callback never has to resolve. */
        build_addr(&fwdState.targetAddr, fwdToHost, fwdToPort);
        wolfSSH_CTX_SetFwdCb(ctx, portfwdRemoteFwdCb, NULL);
        wolfSSH_SetFwdCbCtx(ssh, &fwdState);
        wolfSSH_SetReqSuccess(ctx, portfwdReqSuccessCb);
        wolfSSH_SetReqSuccessCtx(ssh, &fwdState);
        wolfSSH_SetReqFailure(ctx, portfwdReqFailureCb);
        wolfSSH_SetReqFailureCtx(ssh, &fwdState);
    }

    /* Socket to SSH peer. */
    build_addr(&hostAddr, host, port);
    tcp_socket(&sshFd, ((struct sockaddr_in *)&hostAddr)->sin_family);

    if (!reverse) {
        /* Receive from client application or connect to server application. */
        build_addr(&fwdFromHostAddr, fwdFromHost, fwdFromPort);
        tcp_socket(&listenFd,
                ((struct sockaddr_in *)&fwdFromHostAddr)->sin_family);

        tcp_listen(&listenFd, &fwdFromPort, 1);
    }

    printf("Connecting to the SSH server...\n");
    ret = connect(sshFd, (const struct sockaddr *)&hostAddr, hostAddrSz);
    if (ret != 0)
        err_sys("Couldn't connect to server.");

    ret = wolfSSH_set_fd(ssh, (int)sshFd);
    if (ret != WS_SUCCESS)
        err_sys("Couldn't set the session's socket.");

    ret = wolfSSH_connect(ssh);
    if (ret != WS_SUCCESS)
        err_sys("Couldn't connect SFTP");

    if (reverse) {
        /* Ask the server to open a listener and tunnel connections back. */
        ret = wolfSSH_FwdRemoteSetup(ssh, fwdFromHost, fwdFromPort, 1);
        if (ret != WS_SUCCESS)
            err_sys("Couldn't request remote port forward.");

        /* No listener until the peer answers, and want-reply owes us one.
         * Back-pressure and a rekey are progress, not failure. Bounded so a
         * peer that never answers is distinguishable from one that refuses. */
        for (replyTries = 0; !fwdState.replied && replyTries < MAX_REPLY_TRIES;
                replyTries++) {
            ret = wolfSSH_worker(ssh, NULL);
            if (ret != WS_SUCCESS && ret != WS_CHAN_RXD &&
                    ret != WS_WANT_READ && ret != WS_WANT_WRITE &&
                    ret != WS_WINDOW_FULL && ret != WS_REKEYING)
                err_sys("Couldn't get the remote forward reply.");
        }
        if (!fwdState.replied)
            err_sys("Peer never answered the remote port forward request.");
        if (fwdState.refused)
            err_sys("Peer refused the remote port forward request.");
        if (fwdState.badPort)
            err_sys("Peer reported an unusable bound port.");

        /* With -f 0 the peer picked the port. It is the listener's real port,
         * so both the ready file and the cancel below must name it. */
        if (fwdState.wantPortZero)
            fwdFromPort = fwdState.boundPort;
    }

    if (readyFile != NULL) {
    #ifndef NO_FILESYSTEM
        WFILE* f = NULL;
        word16 readyPort = fwdFromPort;

        ret = WFOPEN(NULL, &f, readyFile, "w");
        if (f != NULL && ret == 0) {
            char portStr[10];
            int l;

            l = WSNPRINTF(portStr, sizeof(portStr), "%d\n", (int)readyPort);
            if (l > 0) {
                WFWRITE(NULL, portStr, MIN((size_t)l, sizeof(portStr)), 1, f);
            }
            WFCLOSE(NULL, f);
        }
    #else
        err_sys("cannot create readyFile with no file system.\r\n");
    #endif
    }

    FD_ZERO(&templateFds);
    FD_SET(sshFd, &templateFds);
    if (!reverse) {
        FD_SET(listenFd, &templateFds);
        nFds = findMax(sshFd, listenFd) + 1;
    }
    else {
        nFds = (int)sshFd + 1;
    }

    for (;;) {
        rxFds = templateFds;
        errFds = templateFds;

        to.tv_sec = 1;
        to.tv_usec = 0;
        ret = select(nFds, &rxFds, NULL, &errFds, &to);
        if (ret == 0) {
            ret = wolfSSH_SendIgnore(ssh, NULL, 0);
            if (ret != WS_SUCCESS)
                err_sys("Couldn't send an ignore message.");
            continue;
        }
        else if (ret < 0)
            err_sys("select failed\n");

        if ((appFdSet && FD_ISSET(appFd, &errFds)) ||
            FD_ISSET(sshFd, &errFds) ||
            (!reverse && FD_ISSET(listenFd, &errFds))) {

                err_sys("some socket had an error");
            }
        if (appFdSet && FD_ISSET(appFd, &rxFds)) {
            int rxd;
            rxd = (int)recv(appFd,
                    appBuffer + appBufferUsed, appBufferSz - appBufferUsed, 0);
            if (rxd > 0)
                appBufferUsed += rxd;
            else
                break;
        }
        if (FD_ISSET(sshFd, &rxFds)) {
            word32 channelId = 0;

            ret = wolfSSH_worker(ssh, &channelId);

            /* The worker may have taken a reverse channel. Wire its target
             * socket in before the read below, which would otherwise consume
             * the first chunk with nowhere to put it. */
            if (reverse && fwdState.pending && !appFdSet) {
                WOLFSSH_CHANNEL* newChannel;

                newChannel = wolfSSH_ChannelFind(ssh, fwdState.channelId,
                        WS_CHANNEL_ID_SELF);
                if (fwdState.appFd != (SOCKET_T)-1 && newChannel != NULL) {
                    appFd = fwdState.appFd;
                    fwdChannel = newChannel;
                    FD_SET(appFd, &templateFds);
                    nFds = findMax((int)sshFd, (int)appFd) + 1;
                    appFdSet = 1;
                }
                else if (fwdState.appFd != (SOCKET_T)-1) {
                    /* The channel did not survive the open. Drop the target
                     * socket rather than leave it connected but unpolled. */
                    WCLOSESOCKET(fwdState.appFd);
                    fwdState.appFd = (SOCKET_T)-1;
                }
                fwdState.pending = 0;
            }

            if (ret == WS_CHANNEL_CLOSED) {
                /* The worker tore down the forwarding channel; fwdChannel now
                 * dangles. Stop before the send at the bottom of the loop can
                 * touch the freed channel. */
                fwdChannel = NULL;
                break;
            }

            if (ret == WS_CHAN_RXD) {
                WOLFSSH_CHANNEL* readChannel;

                sshBufferUsed = sshBufferSz;
                readChannel = wolfSSH_ChannelFind(ssh,
                        channelId, WS_CHANNEL_ID_SELF);
                ret = (readChannel == NULL) ? WS_INVALID_CHANID : WS_SUCCESS;

                if (ret == WS_SUCCESS)
                    ret = wolfSSH_ChannelRead(readChannel,
                            sshBuffer, sshBufferUsed);
                if (ret > 0) {
                    sshBufferUsed = (word32)ret;
                    if (appFd != -1) {
                        ret = (int)send(appFd, sshBuffer, sshBufferUsed, 0);
                        if (ret != (int)sshBufferUsed)
                            break;
                    }
                }
            }
        }
        if (!reverse && !appFdSet && FD_ISSET(listenFd, &rxFds)) {
            appFd = accept(listenFd,
                    (struct sockaddr*)&fwdFromHostAddr, &fwdFromHostAddrSz);
            if (appFd < 0)
                break;
            FD_SET(appFd, &templateFds);
            nFds = appFd + 1;
            appFdSet = 1;
            fwdChannel = wolfSSH_ChannelFwdNew(ssh, fwdToHost, fwdToPort,
                    fwdFromHost, fwdFromPort);
            continue;
        }
        if (appBufferUsed > 0) {
            ret = wolfSSH_ChannelSend(fwdChannel, appBuffer, appBufferUsed);
            if (ret > 0)
                appBufferUsed -= ret;
            else if (ret == WS_CHANNEL_NOT_CONF || ret == WS_CHAN_RXD) {
            #ifdef SHELL_DEBUG
                printf("Waiting for channel open confirmation.\n");
            #endif
            }
        }
    }

    if (reverse) {
        /* Best effort: the session is going away regardless, but a failure
         * here means the peer's listener may outlive us. */
        ret = wolfSSH_FwdRemoteCancel(ssh, fwdFromHost, fwdFromPort, 0);
        if (ret != WS_SUCCESS)
            printf("Couldn't cancel the remote port forward, ret = %d\n", ret);
    }

    ret = wolfSSH_shutdown(ssh);
    if (ret != WS_SUCCESS)
        err_sys("Closing port forward stream failed.");

    WCLOSESOCKET(sshFd);
    if (listenFd != (SOCKET_T)-1)
        WCLOSESOCKET(listenFd);
    WCLOSESOCKET(appFd);
    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);
#ifdef WOLFSSH_SMALL_STACK
    WFREE(appBuffer, NULL, 0);
    WFREE(sshBuffer, NULL, 0);
#endif
#if !defined(WOLFSSH_NO_ECC) && defined(FP_ECC) && defined(HAVE_THREAD_LS)
    wc_ecc_fp_free();  /* free per thread cache */
#endif

    return 0;
}


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
    portfwd_worker(&args);

    wolfSSH_Cleanup();

    return args.return_code;
}

int myoptind = 0;
char* myoptarg = NULL;


#endif /* NO_MAIN_DRIVER */
#else
int main()
{
    printf("NO_WOLFSSH_CLIENT macro used, wolfSSH client not compiled in.\n");
    return -1;
}
#endif /* NO_WOLFSSH_CLIENT */

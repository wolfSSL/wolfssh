/* echoserver.c
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

#define WOLFSSH_TEST_SERVER
#define WOLFSSH_TEST_ECHOSERVER

#ifdef WOLFSSL_USER_SETTINGS
    #include <wolfssl/wolfcrypt/settings.h>
#else
    #include <wolfssl/options.h>
#endif

#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/coding.h>
#include <wolfssl/wolfcrypt/wc_port.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssh/ssh.h>
#include <wolfssh/internal.h>
#include <wolfssh/wolfsftp.h>
#include <wolfssh/agent.h>
#include <wolfssh/test.h>
#include <wolfssl/wolfcrypt/ecc.h>

#include "examples/echoserver/echoserver.h"

#if defined(WOLFSSL_PTHREADS) && defined(WOLFSSL_TEST_GLOBAL_REQ)
    #include <pthread.h>
#endif

#if defined(WOLFSSH_SHELL) && defined(USE_WINDOWS_API)
#pragma message ("echoserver with shell on windows is not supported, use wolfSSHd instead")
#undef WOLFSSH_SHELL
#endif

#if defined(WOLFSSL_NUCLEUS) || defined(WOLFSSH_ZEPHYR)
    /* use buffers for keys with server */
    #define NO_FILESYSTEM
    #define WOLFSSH_NO_EXIT
#endif

#ifdef NO_FILESYSTEM
    #include <wolfssh/certs_test.h>
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
    #include <signal.h>
#if defined(__QNX__) || defined(__QNXNTO__)
    #include <errno.h>
    #include <unix.h>

#elif defined(USE_WINDOWS_API)
    #include <errno.h>
#else
    #include <sys/errno.h>
#endif
#endif /* WOLFSSH_SHELL */

#ifdef WOLFSSH_AGENT
    #include <stddef.h>
    #include <sys/socket.h>
    #include <sys/un.h>
#endif /* WOLFSSH_AGENT */

#ifdef HAVE_SYS_SELECT_H
    #include <sys/select.h>
#endif

#ifndef USE_WINDOWS_API
    #include <errno.h>
    #define SOCKET_ERRNO errno
    #define SOCKET_ECONNRESET ECONNRESET
    #define SOCKET_ECONNABORTED ECONNABORTED
    #define SOCKET_EWOULDBLOCK EWOULDBLOCK
#else
    #include <WS2tcpip.h>
    #define SOCKET_ERRNO WSAGetLastError()
    #define SOCKET_ECONNRESET WSAECONNRESET
    #define SOCKET_ECONNABORTED WSAECONNABORTED
    #define SOCKET_EWOULDBLOCK WSAEWOULDBLOCK
#endif


#ifndef NO_WOLFSSH_SERVER

static const char echoserverBanner[] = "wolfSSH Example Echo Server\n";

static int quit = 0;
wolfSSL_Mutex doneLock;
#define MAX_PASSWD_RETRY 3
static int passwdRetry = MAX_PASSWD_RETRY;


#ifndef EXAMPLE_HIGHWATER_MARK
    #define EXAMPLE_HIGHWATER_MARK 0x3FFF8000 /* 1GB - 32kB */
#endif

#ifndef EXAMPLE_BUFFER_SZ
    #define EXAMPLE_BUFFER_SZ 4096
#endif

#ifndef EXAMPLE_KEYLOAD_BUFFER_SZ
    #define EXAMPLE_KEYLOAD_BUFFER_SZ 1200
#endif


#ifdef WOLFSSH_AGENT
typedef struct WS_AgentCbActionCtx {
    struct sockaddr_un name;
    WS_SOCKET_T listenFd;
    WS_SOCKET_T fd;
    pid_t pid;
    int state;
} WS_AgentCbActionCtx;
#endif


#ifdef WOLFSSH_FWD
enum FwdStates {
    FWD_STATE_INIT,
    FWD_STATE_LISTEN,
    FWD_STATE_CONNECT,
    FWD_STATE_CONNECTED,
    FWD_STATE_DIRECT,
};

typedef struct WS_FwdCbActionCtx {
    void* heap;
    char* hostName;
    char* originName;
    word16 hostPort;
    word16 originPort;
    WS_SOCKET_T listenFd;
    WS_SOCKET_T appFd;
    int error;
    int state;
    int isDirect;
    word32 channelId;
} WS_FwdCbActionCtx;
#endif


typedef struct {
    WOLFSSH* ssh;
    WS_SOCKET_T fd;
    word32 id;
    int echo;
    char nonBlock;
#if defined(WOLFSSL_PTHREADS) && defined(WOLFSSL_TEST_GLOBAL_REQ)
    WOLFSSH_CTX *ctx;
#endif
#ifdef WOLFSSH_AGENT
    WS_AgentCbActionCtx agentCbCtx;
    byte agentBuffer[EXAMPLE_BUFFER_SZ];
#endif
#ifdef WOLFSSH_FWD
    WS_FwdCbActionCtx fwdCbCtx;
    byte fwdBuffer[EXAMPLE_BUFFER_SZ];
#endif
#ifdef WOLFSSH_SHELL
    byte shellBuffer[EXAMPLE_BUFFER_SZ];
#endif
    byte channelBuffer[EXAMPLE_BUFFER_SZ];
    char statsBuffer[EXAMPLE_BUFFER_SZ];
} thread_ctx_t;


static byte find_char(const byte* str, const byte* buf, word32 bufSz)
{
    const byte* cur;

    while (bufSz) {
        cur = str;
        while (*cur != '\0') {
            if (*cur == *buf)
                return *cur;
            cur++;
        }
        buf++;
        bufSz--;
    }

    return 0;
}


static int dump_stats(thread_ctx_t* ctx)
{
    word32 statsSz;
    word32 txCount, rxCount, seq, peerSeq;

    wolfSSH_GetStats(ctx->ssh, &txCount, &rxCount, &seq, &peerSeq);

    WSNPRINTF(ctx->statsBuffer, sizeof ctx->statsBuffer,
            "Statistics for Thread #%u:\r\n"
            "  txCount = %u\r\n  rxCount = %u\r\n"
            "  seq = %u\r\n  peerSeq = %u\r\n",
            ctx->id, txCount, rxCount, seq, peerSeq);
    statsSz = (word32)WSTRLEN(ctx->statsBuffer);

    fprintf(stderr, "%s", ctx->statsBuffer);
    return wolfSSH_stream_send(ctx->ssh, (byte*)ctx->statsBuffer, statsSz);
}


static int process_bytes(thread_ctx_t* threadCtx,
        const byte* buffer, word32 bufferSz)
{
    int stop = 0;
    byte c;
    const byte matches[] = { 0x03, 0x05, 0x06, 0x00 };

    c = find_char(matches, buffer, bufferSz);
    switch (c) {
        case 0x03:
            stop = 1;
            break;
        case 0x05:
            if (dump_stats(threadCtx) <= 0)
                stop = 1;
            break;
        case 0x06:
            if (wolfSSH_TriggerKeyExchange(threadCtx->ssh) != WS_SUCCESS)
                stop = 1;
            break;
    }
    return stop;
}


#if defined(WOLFSSL_PTHREADS) && defined(WOLFSSL_TEST_GLOBAL_REQ)

#define SSH_TIMEOUT 10

static int callbackReqSuccess(WOLFSSH *ssh, void *buf, word32 sz, void *ctx)
{
    if ((WOLFSSH *)ssh != *(WOLFSSH **)ctx){
        printf("ssh(%x) != ctx(%x)\n", (unsigned int)ssh,
                (unsigned int)*(WOLFSSH **)ctx);
        return WS_FATAL_ERROR;
    }
    printf("Global Request Success[%d]: %s\n", sz, sz>0?buf:"No payload");
    return WS_SUCCESS;
}

static int callbackReqFailure(WOLFSSH *ssh, void *buf, word32 sz, void *ctx)
{
    if ((WOLFSSH *)ssh != *(WOLFSSH **)ctx)
    {
        printf("ssh(%x) != ctx(%x)\n", (unsigned int)ssh,
                (unsigned int)*(WOLFSSH **)ctx);
        return WS_FATAL_ERROR;
    }
    printf("Global Request Failure[%d]: %s\n", sz, sz > 0 ? buf : "No payload");
    return WS_SUCCESS;
}


static void *global_req(void *ctx)
{
    int ret;
    const char str[] = "SampleRequest";
    thread_ctx_t *threadCtx = (thread_ctx_t *)ctx;
    byte buf[0];

    wolfSSH_SetReqSuccess(threadCtx->ctx, callbackReqSuccess);
    wolfSSH_SetReqSuccessCtx(threadCtx->ssh, &threadCtx->ssh); /* dummy ctx */
    wolfSSH_SetReqFailure(threadCtx->ctx, callbackReqFailure);
    wolfSSH_SetReqFailureCtx(threadCtx->ssh, &threadCtx->ssh); /* dummy ctx */

    while(1){

        sleep(SSH_TIMEOUT);

        ret = wolfSSH_global_request(threadCtx->ssh, (const unsigned char *)str,
                WSTRLEN(str), 1);
        if (ret != WS_SUCCESS)
        {
            printf("Global Request Failed.\n");
            wolfSSH_shutdown(threadCtx->ssh);
            return NULL;
        }

        wolfSSH_stream_read(threadCtx->ssh, buf, 0);
        if (ret != WS_SUCCESS)
        {
            printf("wolfSSH_stream_read Failed.\n");
            wolfSSH_shutdown(threadCtx->ssh);
            return NULL;
        }
    }
    return NULL;
}

#endif


static void printKeyCompleteText(WOLFSSH* ssh, WS_Text id, const char* tag)
{
    char str[200];
    size_t strSz = sizeof(str);
    size_t ret;

    ret = wolfSSH_GetText(ssh, id, str, strSz);
    if (ret == strSz) {
        printf("\tString size was not large enough for %s\n", tag);
    }
    printf("\t%-30s : %s\n", tag, str);
}


static void callbackKeyingComplete(void* ctx)
{
    WOLFSSH* ssh = (WOLFSSH*)ctx;

    if (ssh != NULL) {
        printf("Keying Complete:\n");
        printKeyCompleteText(ssh, WOLFSSH_TEXT_KEX_ALGO,
                                    "WOLFSSH_TEXT_KEX_ALGO");

        printKeyCompleteText(ssh, WOLFSSH_TEXT_KEX_CURVE,
                                    "WOLFSSH_TEXT_KEX_CURVE");

        printKeyCompleteText(ssh, WOLFSSH_TEXT_KEX_HASH,
                                    "WOLFSSH_TEXT_KEX_HASH");

        printKeyCompleteText(ssh, WOLFSSH_TEXT_CRYPTO_IN_CIPHER,
                                    "WOLFSSH_TEXT_CRYPTO_IN_CIPHER");

        printKeyCompleteText(ssh, WOLFSSH_TEXT_CRYPTO_IN_MAC,
                                    "WOLFSSH_TEXT_CRYPTO_IN_MAC");

        printKeyCompleteText(ssh, WOLFSSH_TEXT_CRYPTO_OUT_CIPHER,
                                    "WOLFSSH_TEXT_CRYPTO_OUT_CIPHER");

        printKeyCompleteText(ssh, WOLFSSH_TEXT_CRYPTO_OUT_MAC,
                                    "WOLFSSH_TEXT_CRYPTO_OUT_MAC");
    }
}


#ifdef WOLFSSH_AGENT

static const char EnvNameAuthPort[] = "SSH_AUTH_SOCK";

static int wolfSSH_AGENT_DefaultActions(WS_AgentCbAction action, void* vCtx)
{
    WS_AgentCbActionCtx* ctx = (WS_AgentCbActionCtx*)vCtx;
    int ret = 0;

    if (action == WOLFSSH_AGENT_LOCAL_SETUP) {
        struct sockaddr_un* name = &ctx->name;
        size_t size;

        WMEMSET(name, 0, sizeof(struct sockaddr_un));
        ctx->pid = getpid();
        name->sun_family = AF_LOCAL;

        ret = snprintf(name->sun_path, sizeof(name->sun_path),
                "/tmp/wolfserver.%d", ctx->pid);

        if (ret == 0) {
            name->sun_path[sizeof(name->sun_path) - 1] = '\0';
            size = WSTRLEN(name->sun_path) +
                    offsetof(struct sockaddr_un, sun_path);
            ctx->listenFd = socket(AF_UNIX, SOCK_STREAM, 0);
            if (ctx->listenFd == -1) {
                ret = -1;
            }
        }

        if (ret == 0) {
            ret = bind(ctx->listenFd,
                    (struct sockaddr *)name, (socklen_t)size);
        }

        if (ret == 0) {
            ret = setenv(EnvNameAuthPort, name->sun_path, 1);
        }

        if (ret == 0) {
            ret = listen(ctx->listenFd, 5);
        }

        if (ret == 0) {
            ctx->state = AGENT_STATE_LISTEN;
        }
        else {
            ret = WS_AGENT_SETUP_E;
        }
    }
    else if (action == WOLFSSH_AGENT_LOCAL_CLEANUP) {
        WCLOSESOCKET(ctx->listenFd);
        unlink(ctx->name.sun_path);
        unsetenv(EnvNameAuthPort);
    }
    else
        ret = WS_AGENT_INVALID_ACTION;

    return ret;
}

#endif


#ifdef WOLFSSH_FWD

static WS_SOCKET_T connect_addr(const char* name, word16 port)
{
    WS_SOCKET_T newSocket = -1;
    int ret;
    struct addrinfo hints, *hint, *hint0 = NULL;
    char portStr[6];

    WMEMSET(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    snprintf(portStr, sizeof portStr, "%u", port);

    ret = getaddrinfo(name, portStr, &hints, &hint0);
    if (ret)
        return -1;

    for (hint = hint0; hint != NULL; hint = hint->ai_next) {
        newSocket = socket(hint->ai_family,
                hint->ai_socktype, hint->ai_protocol);

        if (newSocket < 0)
            continue;

        if (connect(newSocket, hint->ai_addr,
                (WS_SOCKLEN_T)hint->ai_addrlen) < 0) {
            WCLOSESOCKET(newSocket);
            newSocket = -1;
            continue;
        }

        break;
    }

    freeaddrinfo(hint0);

    return newSocket;
}


static int wolfSSH_FwdDefaultActions(WS_FwdCbAction action, void* vCtx,
        const char* name, word32 port)
{
    WS_FwdCbActionCtx* ctx = (WS_FwdCbActionCtx*)vCtx;
    int ret = 0;

    if (action == WOLFSSH_FWD_LOCAL_SETUP) {
        ctx->hostName = WSTRDUP(name, NULL, 0);
        ctx->hostPort = port;
        ctx->isDirect = 1;
        ctx->state = FWD_STATE_DIRECT;
    }
    else if (action == WOLFSSH_FWD_LOCAL_CLEANUP) {
        WCLOSESOCKET(ctx->appFd);
        if (ctx->hostName) {
            WFREE(ctx->hostName, NULL, 0);
            ctx->hostName = NULL;
        }
        if (ctx->originName) {
            WFREE(ctx->originName, NULL, 0);
            ctx->originName = NULL;
        }
        ctx->state = FWD_STATE_INIT;
    }
    else if (action == WOLFSSH_FWD_REMOTE_SETUP) {
        struct sockaddr_in addr;
        socklen_t addrSz = 0;

        ctx->hostName = WSTRDUP(name, NULL, 0);
        ctx->hostPort = port;

        ctx->listenFd = socket(AF_INET, SOCK_STREAM, 0);
        if (ctx->listenFd == -1) {
            ret = -1;
        }

        if (ret == 0) {

            WMEMSET(&addr, 0, sizeof addr);
            if (WSTRCMP(name, "") == 0 ||
                WSTRCMP(name, "0.0.0.0") == 0 ||
                WSTRCMP(name, "localhost") == 0 ||
                WSTRCMP(name, "127.0.0.1") == 0) {

                addr.sin_addr.s_addr = INADDR_ANY;
                addr.sin_family = AF_INET;
                addr.sin_port = htons((word16)port);
                addrSz = sizeof addr;
            }
            else {
                printf("Not using IPv6 yet.\n");
                ret = WS_FWD_SETUP_E;
            }
        }

        if (ret == 0) {
            ret = bind(ctx->listenFd,
                    (const struct sockaddr*)&addr, addrSz);
        }

        if (ret == 0) {
            ret = listen(ctx->listenFd, 5);
        }

        if (ret == 0) {
            ctx->state = FWD_STATE_LISTEN;
        }
        else {
            if (ctx->hostName != NULL) {
                WFREE(ctx->hostName, NULL, 0);
                ctx->hostName = NULL;
            }
            if (ctx->listenFd != -1) {
                WCLOSESOCKET(ctx->listenFd);
                ctx->listenFd = -1;
            }
            ret = WS_FWD_SETUP_E;
        }
    }
    else if (action == WOLFSSH_FWD_REMOTE_CLEANUP) {
        if (ctx->hostName) {
            WFREE(ctx->hostName, NULL, 0);
            ctx->hostName = NULL;
        }
        if (ctx->originName) {
            WFREE(ctx->originName, NULL, 0);
            ctx->originName = NULL;
        }
        if (ctx->listenFd != -1) {
            WCLOSESOCKET(ctx->listenFd);
            ctx->listenFd = -1;
        }
        ctx->state = FWD_STATE_INIT;
    }
    else if (action == WOLFSSH_FWD_CHANNEL_ID) {
        ctx->channelId = port;
    }
    else
        ret = WS_FWD_INVALID_ACTION;

    return ret;
}

#endif /* WOLFSSH_FWD */


#ifdef SHELL_DEBUG

static void display_ascii(char *p_buf,
                          int count)
{
  int i;

  printf("  *");
  for (i = 0; i < count; i++) {
    char      tmp_char    = p_buf[i];

    if ((isalnum(tmp_char) || ispunct(tmp_char)) && (tmp_char > 0))
        printf("%c", tmp_char);
    else
        printf(".");
  }
  printf("*\n");
}


static void buf_dump(unsigned char *buf, int len)
{
    int i;

    printf("\n");
    for (i = 0; i<len; i++) {
        if ((i%16) == 0) {
            printf("%04x :", i);
        }
        printf("%02x ", (unsigned char)buf[i]);

        if (((i + 1)%16) == 0) {
            display_ascii((char*)(buf+i - 15), 16);
        }
    }
    if ((len % 16) != 0) {
        display_ascii((char*)(buf +len -len%16), (len%16));
    }
    return;
}


#ifdef WOLFSSH_SHELL
static int termios_show(int fd)
{
    struct termios tios;
    int i;
    int rc;

    WMEMSET((void *) &tios, 0, sizeof(tios));
    rc = tcgetattr(fd, &tios);
    printf("tcgetattr returns=%x\n", rc);

    printf("iflag/oflag/cflag/lflag = %x/%x/%x/%x\n",
            (unsigned int)tios.c_iflag, (unsigned int)tios.c_oflag,
            (unsigned int)tios.c_cflag, (unsigned int)tios.c_lflag);
    printf("c_ispeed/c_ospeed = %x/%x\n",
            (unsigned int)tios.c_ispeed, (unsigned int)tios.c_ospeed);
    for (i = 0; i < NCCS; i++) {
        printf("c_cc[%d] = %hhx\n", i, tios.c_cc[i]);
    }
    return 0;
}
#endif /* WOLFSSH_SHELL */

#endif /* SHELL_DEBUG */


#ifdef WOLFSSH_STATIC_MEMORY
    #ifndef WOLFSSL_STATIC_MEMORY
        #error Requires the static memory functions from wolfSSL
    #endif
    #if defined(WOLFSSH_SCP) || defined(WOLFSSH_SHELL) || defined(WOLFSSH_FWD)
        #warning Static memory configuration for SFTP, results may vary.
    #endif
    typedef WOLFSSL_HEAP_HINT ES_HEAP_HINT;

     /* This static buffer is tuned for building with SFTP only. The static
      * buffer size is calulated by multiplying the pairs of sizeList items
      * and distList items and summing (32*64 + 128*118 + ...) and adding
      * the sum of the distList values times the sizeof wc_Memory (rounded up
      * to a word, 24). This total was 288kb plus change, rounded up to 289. */
    #ifndef ES_STATIC_SIZES
        #define ES_STATIC_SIZES 32,128,384,800,3120,8400,17552,32846,131072
    #endif
    #ifndef ES_STATIC_DISTS
        #define ES_STATIC_DISTS 64,118,3,4,6,2,2,2,1
    #endif
    #ifndef ES_STATIC_LISTSZ
        #define ES_STATIC_LISTSZ 9
    #endif
    #ifndef ES_STATIC_BUFSZ
        #define ES_STATIC_BUFSZ (289*1024)
    #endif
    static const word32 static_sizeList[] = {ES_STATIC_SIZES};
    static const word32 static_distList[] = {ES_STATIC_DISTS};
    static byte static_buffer[ES_STATIC_BUFSZ];

    static void wolfSSH_MemoryPrintStats(ES_HEAP_HINT* hint)
    {
        if (hint != NULL) {
            word16 i;
            WOLFSSL_MEM_STATS stats;

            wolfSSL_GetMemStats(hint->memory, &stats);

            /* print to stderr so is on the same pipe as WOLFSSL_DEBUG */
            fprintf(stderr, "Total mallocs        = %d\n", stats.totalAlloc);
            fprintf(stderr, "Total frees          = %d\n", stats.totalFr);
            fprintf(stderr, "Current mallocs      = %d\n", stats.curAlloc);
            fprintf(stderr, "Available IO         = %d\n", stats.avaIO);
            fprintf(stderr, "Max con. handshakes  = %d\n", stats.maxHa);
            fprintf(stderr, "Max con. IO          = %d\n", stats.maxIO);
            fprintf(stderr, "State of memory blocks: size : available\n");
            for (i = 0; i < WOLFMEM_MAX_BUCKETS; i++) {
                fprintf(stderr, "                    %8d : %d\n",
                        stats.blockSz[i], stats.avaBlock[i]);
            }
        }
    }

    static void wolfSSH_MemoryConnPrintStats(ES_HEAP_HINT* hint)
    {
        if (hint != NULL) {
            WOLFSSL_MEM_CONN_STATS* stats = hint->stats;

            /* fill out statistics if wanted and WOLFMEM_TRACK_STATS flag */
            if (hint->memory->flag & WOLFMEM_TRACK_STATS
                    && hint->stats != NULL) {
                fprintf(stderr, "peak connection memory    = %d\n",
                        stats->peakMem);
                fprintf(stderr, "current memory in use     = %d\n",
                        stats->curMem);
                fprintf(stderr, "peak connection allocs    = %d\n",
                        stats->peakAlloc);
                fprintf(stderr, "current connection allocs = %d\n",
                        stats->curAlloc);
                fprintf(stderr, "total connection allocs   = %d\n",
                        stats->totalAlloc);
                fprintf(stderr, "total connection frees    = %d\n\n",
                        stats->totalFr);
            }
        }
    }
#else
    typedef void ES_HEAP_HINT;
#endif


int ChildRunning = 0;

#ifdef WOLFSSH_SHELL
static void ChildSig(int sig)
{
    (void)sig;
    ChildRunning = 0;
}
#endif

static int ssh_worker(thread_ctx_t* threadCtx)
{
    WOLFSSH* ssh;
    WS_SOCKET_T sshFd;
    int rc = 0;
#ifdef WOLFSSH_SHELL
    const char *userName;
    struct passwd *p_passwd;
    WS_SOCKET_T childFd = 0;
    pid_t childPid;
#endif
#if defined(WOLFSSL_PTHREADS) && defined(WOLFSSL_TEST_GLOBAL_REQ)
    pthread_t globalReq_th;
#endif

    if (threadCtx == NULL)
        return 1;

    ssh = threadCtx->ssh;
    if (ssh == NULL)
        return WS_FATAL_ERROR;

    sshFd = wolfSSH_get_fd(ssh);

#if defined(WOLFSSL_PTHREADS) && defined(WOLFSSL_TEST_GLOBAL_REQ)
    /* submit Global Request for keep-alive */
    rc = pthread_create(&globalReq_th, NULL, global_req, threadCtx);
    if (rc != 0)
        printf("pthread_create() failed.\n");
#endif

#ifdef WOLFSSH_SHELL
    if (!threadCtx->echo) {

        userName = wolfSSH_GetUsername(ssh);
        p_passwd = getpwnam((const char *)userName);
        if (p_passwd == NULL) {
            /* Not actually a user on the system. */
            #ifdef SHELL_DEBUG
                fprintf(stderr, "user %s does not exist\n", userName);
            #endif
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

            #ifdef SHELL_DEBUG
                printf("userName is %s\n", userName);
                system("env");
            #endif

            setenv("HOME", p_passwd->pw_dir, 1);
            setenv("LOGNAME", p_passwd->pw_name, 1);
            rc = chdir(p_passwd->pw_dir);
            if (rc != 0) {
                return WS_FATAL_ERROR;
            }

            execv("/bin/sh", (char **)args);
        }
    }
#endif
    {
        /* Parent process */
#ifdef WOLFSSH_SHELL
        struct termios tios;
#endif
        word32 shellChannelId = 0;
#ifdef WOLFSSH_AGENT
        WS_SOCKET_T agentFd = -1;
        WS_SOCKET_T agentListenFd = threadCtx->agentCbCtx.listenFd;
        word32 agentChannelId = -1;
#endif
#ifdef WOLFSSH_FWD
        WS_SOCKET_T fwdFd = -1;
        WS_SOCKET_T fwdListenFd = threadCtx->fwdCbCtx.listenFd;
        word32 fwdBufferIdx = 0;
#endif

#ifdef WOLFSSH_SHELL
        if (!threadCtx->echo) {
            #ifdef SHELL_DEBUG
                printf("In childPid > 0; getpid=%d\n", (int)getpid());
            #endif
            signal(SIGCHLD, ChildSig);

            rc = tcgetattr(childFd, &tios);
            if (rc != 0) {
                printf("tcgetattr failed: rc =%d,errno=%x\n", rc, errno);
                return WS_FATAL_ERROR;
            }
            rc = tcsetattr(childFd, TCSAFLUSH, &tios);
            if (rc != 0) {
                printf("tcsetattr failed: rc =%d,errno=%x\n", rc, errno);
                return WS_FATAL_ERROR;
            }

            #ifdef SHELL_DEBUG
                termios_show(childFd);
            #endif
        }
        else
            ChildRunning = 1;
#else
        ChildRunning = 1;
#endif

#if defined(WOLFSSH_TERM) && defined(WOLFSSH_SHELL)
    /* set initial size of terminal based on saved size */
#if defined(HAVE_SYS_IOCTL_H)
    wolfSSH_DoModes(ssh->modes, ssh->modesSz, childFd);
    {
        struct winsize s = {0};

        s.ws_col = ssh->widthChar;
        s.ws_row = ssh->heightRows;
        s.ws_xpixel = ssh->widthPixels;
        s.ws_ypixel = ssh->heightPixels;

        ioctl(childFd, TIOCSWINSZ, &s);
    }
#endif /* HAVE_SYS_IOCTL_H */

        wolfSSH_SetTerminalResizeCtx(ssh, (void*)&childFd);
#endif /* WOLFSSH_TERM && WOLFSSH_SHELL */

        while (ChildRunning) {
            fd_set readFds;
            WS_SOCKET_T maxFd;
            int cnt_r;
            int cnt_w;

            FD_ZERO(&readFds);
            FD_SET(sshFd, &readFds);
            maxFd = sshFd;

#ifdef WOLFSSH_SHELL
            if (!threadCtx->echo) {
                FD_SET(childFd, &readFds);
                if (childFd > maxFd)
                    maxFd = childFd;
            }
#endif
#ifdef WOLFSSH_AGENT
            if (threadCtx->agentCbCtx.state == AGENT_STATE_LISTEN) {
                FD_SET(agentListenFd, &readFds);
                if (agentListenFd > maxFd)
                    maxFd = agentListenFd;
            }
            if (agentFd >= 0 && threadCtx->agentCbCtx.state == AGENT_STATE_CONNECTED) {
                FD_SET(agentFd, &readFds);
                if (agentFd > maxFd)
                    maxFd = agentFd;
            }
#endif
#ifdef WOLFSSH_FWD
            if (threadCtx->fwdCbCtx.state == FWD_STATE_LISTEN) {
                FD_SET(fwdListenFd, &readFds);
                if (fwdListenFd > maxFd)
                    maxFd = fwdListenFd;
            }
            if (fwdFd >= 0 && threadCtx->fwdCbCtx.state == FWD_STATE_CONNECTED) {
                FD_SET(fwdFd, &readFds);
                if (fwdFd > maxFd)
                    maxFd = fwdFd;
            }
#endif
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
                                    threadCtx->channelBuffer,
                                    sizeof threadCtx->channelBuffer);
                            if (cnt_r <= 0)
                                break;
                            #ifdef SHELL_DEBUG
                                buf_dump(threadCtx->channelBuffer, cnt_r);
                            #endif
                            #ifdef WOLFSSH_SHELL
                                if (!threadCtx->echo) {
                                    cnt_w = (int)write(childFd,
                                            threadCtx->channelBuffer, cnt_r);
                                }
                                else {
                                    cnt_w = wolfSSH_ChannelIdSend(ssh,
                                            shellChannelId,
                                            threadCtx->channelBuffer, cnt_r);
                                    if (cnt_r > 0) {
                                        int doStop = process_bytes(threadCtx,
                                                threadCtx->channelBuffer,
                                                cnt_r);
                                        ChildRunning = !doStop;
                                    }
                                }
                            #else
                            cnt_w = wolfSSH_ChannelIdSend(ssh, shellChannelId,
                                    threadCtx->channelBuffer, cnt_r);
                            if (cnt_r > 0) {
                                int doStop = process_bytes(threadCtx,
                                        threadCtx->channelBuffer, cnt_r);
                                ChildRunning = !doStop;
                            }
                            #endif
                            if (cnt_w <= 0)
                                break;
                        }
                        #ifdef WOLFSSH_AGENT
                        if (lastChannel == agentChannelId) {
                            cnt_r = wolfSSH_ChannelIdRead(ssh, agentChannelId,
                                    threadCtx->channelBuffer,
                                    sizeof threadCtx->channelBuffer);
                            if (cnt_r <= 0)
                                break;
                            #ifdef SHELL_DEBUG
                                buf_dump(threadCtx->channelBuffer, cnt_r);
                            #endif
                            cnt_w = (int)send(agentFd,
                                    threadCtx->channelBuffer, cnt_r, 0);
                            if (cnt_w <= 0)
                                break;
                        }
                        #endif
                        #ifdef WOLFSSH_FWD
                        if (threadCtx->fwdCbCtx.state == FWD_STATE_CONNECTED &&
                            lastChannel == threadCtx->fwdCbCtx.channelId) {

                            cnt_r = wolfSSH_ChannelIdRead(ssh,
                                    threadCtx->fwdCbCtx.channelId,
                                    threadCtx->channelBuffer,
                                    sizeof threadCtx->channelBuffer);
                            if (cnt_r <= 0)
                                break;
                            #ifdef SHELL_DEBUG
                                buf_dump(threadCtx->channelBuffer, cnt_r);
                            #endif
                            cnt_w = (int)send(fwdFd, threadCtx->channelBuffer,
                                    cnt_r, 0);
                            if (cnt_w <= 0)
                                break;
                        }
                        #endif
                    }
                    else if (rc == WS_CHANNEL_CLOSED) {
                        #ifdef WOLFSSH_FWD
                        if (threadCtx->fwdCbCtx.state == FWD_STATE_CONNECTED &&
                            lastChannel == threadCtx->fwdCbCtx.channelId) {
                            /* Read zero-returned. Socket is closed. Go back
                               to listening. */
                            if (fwdFd != -1) {
                                WCLOSESOCKET(fwdFd);
                                fwdFd = -1;
                            }
                            if (threadCtx->fwdCbCtx.originName != NULL) {
                                WFREE(threadCtx->fwdCbCtx.originName,
                                        NULL, 0);
                                threadCtx->fwdCbCtx.originName = NULL;
                            }
                            threadCtx->fwdCbCtx.state = FWD_STATE_LISTEN;
                        }
                        #endif
                        continue;
                    }
                    else if (rc != WS_WANT_READ) {
                        #ifdef SHELL_DEBUG
                            printf("Break:read sshFd returns %d: errno =%x\n",
                                    cnt_r, errno);
                        #endif
                        break;
                    }
                }
            }

            #ifdef WOLFSSH_SHELL
            if (!threadCtx->echo) {
                if (FD_ISSET(childFd, &readFds)) {
                    cnt_r = (int)read(childFd,
                            threadCtx->shellBuffer,
                            sizeof threadCtx->shellBuffer);
                    /* This read will return 0 on EOF */
                    if (cnt_r <= 0) {
                        int err = errno;
                        if (err != EAGAIN) {
                            #ifdef SHELL_DEBUG
                                printf("Break:read childFd returns %d: "
                                        "errno =%x\n",
                                        cnt_r, err);
                            #endif
                            break;
                        }
                    }
                    else {
                        #ifdef SHELL_DEBUG
                            buf_dump(threadCtx->shellBuffer, cnt_r);
                        #endif
                        if (cnt_r > 0) {
                            cnt_w = wolfSSH_ChannelIdSend(ssh, shellChannelId,
                                    threadCtx->shellBuffer, cnt_r);
                            if (cnt_w < 0)
                                break;
                        }
                    }
                }
            }
            #endif
            #ifdef WOLFSSH_AGENT
            if (agentFd >= 0 && threadCtx->agentCbCtx.state == AGENT_STATE_CONNECTED) {
                if (FD_ISSET(agentFd, &readFds)) {
                    #ifdef SHELL_DEBUG
                        printf("agentFd set in readfd\n");
                    #endif
                    cnt_r = (int)recv(agentFd,
                            threadCtx->agentBuffer,
                            sizeof threadCtx->agentBuffer, 0);
                    if (cnt_r == 0) {
                        /* Read zero-returned. Socket is closed. Go back
                           to listening. */
                        threadCtx->agentCbCtx.state = AGENT_STATE_LISTEN;
                        continue;
                    }
                    else if (cnt_r < 0) {
                        int err = SOCKET_ERRNO;
                        #ifdef SHELL_DEBUG
                            printf("Break:read agentFd returns %d: "
                                   "errno = %d\n", cnt_r, err);
                        #endif
                        if (err == SOCKET_ECONNRESET ||
                                err == SOCKET_ECONNABORTED) {
                            /* Connection reset. Socket is closed.
                             * Go back to listening. */
                            threadCtx->agentCbCtx.state = AGENT_STATE_LISTEN;
                            continue;
                        }
                        break;
                    }
                    else {
                        #ifdef SHELL_DEBUG
                            buf_dump(threadCtx->agentBuffer, cnt_r);
                        #endif
                        cnt_w = wolfSSH_ChannelIdSend(ssh, agentChannelId,
                                threadCtx->agentBuffer, cnt_r);
                        if (cnt_w <= 0) {
                            break;
                        }
                    }
                }
            }
            if (threadCtx->agentCbCtx.state == AGENT_STATE_LISTEN) {
                if (FD_ISSET(agentListenFd, &readFds)) {
                    #ifdef SHELL_DEBUG
                        printf("accepting agent connection\n");
                    #endif
                    agentFd = accept(agentListenFd, NULL, NULL);
                    if (agentFd == -1) {
                        rc = errno;
                        if (rc != SOCKET_EWOULDBLOCK) {
                            break;
                        }
                    }
                    else {
                        threadCtx->agentCbCtx.state = AGENT_STATE_CONNECTED;
                        threadCtx->agentCbCtx.fd = agentFd;
                    }
                }
            }
            #endif
            #ifdef WOLFSSH_FWD
            if (fwdFd >= 0 && threadCtx->fwdCbCtx.state == FWD_STATE_CONNECTED) {
                if (FD_ISSET(fwdFd, &readFds)) {
                    #ifdef SHELL_DEBUG
                        printf("fwdFd set in readfd\n");
                    #endif
                    cnt_r = (int)recv(fwdFd,
                            threadCtx->fwdBuffer + fwdBufferIdx,
                            sizeof threadCtx->fwdBuffer - fwdBufferIdx, 0);
                    if (cnt_r == 0) {
                        /* Read zero-returned. Socket is closed. Go back
                           to listening. */
                        WCLOSESOCKET(fwdFd);
                        fwdFd = -1;
                        if (threadCtx->fwdCbCtx.hostName != NULL) {
                            WFREE(threadCtx->fwdCbCtx.hostName,
                                    NULL, 0);
                            threadCtx->fwdCbCtx.hostName = NULL;
                        }
                        threadCtx->fwdCbCtx.state = FWD_STATE_LISTEN;
                        continue;
                    }
                    else if (cnt_r < 0) {
                        int err = SOCKET_ERRNO;

                        #ifdef SHELL_DEBUG
                            printf("Break:read fwdFd returns %d: "
                                   "errno = %d\n", cnt_r, err);
                        #endif
                        if (err == SOCKET_ECONNRESET ||
                                err == SOCKET_ECONNABORTED) {
                            /* Connection reset. Socket is closed.
                             * Go back to listening. */
                            WCLOSESOCKET(fwdFd);
                            threadCtx->fwdCbCtx.state = FWD_STATE_LISTEN;
                            continue;
                        }
                        break;
                    }
                    else {
                    #ifdef SHELL_DEBUG
                        buf_dump(threadCtx->fwdBuffer, cnt_r);
                    #endif
                        fwdBufferIdx += cnt_r;
                    }
                }
                if (fwdBufferIdx > 0) {
                    cnt_w = wolfSSH_ChannelIdSend(ssh,
                            threadCtx->fwdCbCtx.channelId,
                            threadCtx->fwdBuffer, fwdBufferIdx);
                    if (cnt_w > 0) {
                        fwdBufferIdx = 0;
                    }
                    else if (cnt_w == WS_CHANNEL_NOT_CONF ||
                            cnt_w == WS_CHAN_RXD) {
                    #ifdef SHELL_DEBUG
                        printf("Waiting for channel open confirmation.\n");
                    #endif
                    }
                    else {
                        break;
                    }
                }
            }
            if (threadCtx->fwdCbCtx.state == FWD_STATE_LISTEN) {
                if (FD_ISSET(fwdListenFd, &readFds)) {
                    #ifdef SHELL_DEBUG
                        printf("accepting fwd connection\n");
                    #endif
                    fwdFd = accept(fwdListenFd, NULL, NULL);
                    if (fwdFd == -1) {
                        rc = errno;
                        if (rc != SOCKET_EWOULDBLOCK) {
                            break;
                        }
                    }
                    else {
                        struct sockaddr_in6 originAddr;
                        socklen_t originAddrSz;
                        const char* out = NULL;
                        char addr[200];

                        threadCtx->fwdCbCtx.state = FWD_STATE_CONNECT;
                        threadCtx->fwdCbCtx.appFd = fwdFd;
                        originAddrSz = sizeof originAddr;
                        WMEMSET(&originAddr, 0, originAddrSz);
                        if (getpeername(fwdFd,
                                (struct sockaddr*)&originAddr,
                                &originAddrSz) == 0) {

                            if (originAddr.sin6_family == AF_INET) {
                                struct sockaddr_in* addr4 =
                                    (struct sockaddr_in*)&originAddr;
                                out = inet_ntop(AF_INET,
                                        &addr4->sin_addr,
                                        addr, sizeof addr);
                            }
                            else if (originAddr.sin6_family == AF_INET6) {
                                out = inet_ntop(AF_INET6,
                                        &originAddr.sin6_addr,
                                        addr, sizeof addr);
                            }
                        }
                        if (out != NULL) {
                            threadCtx->fwdCbCtx.originName =
                                WSTRDUP(addr, NULL, 0);
                            threadCtx->fwdCbCtx.originPort =
                                ntohs(originAddr.sin6_port);
                        }
                    }
                }
            }
            if (threadCtx->fwdCbCtx.state == FWD_STATE_CONNECT) {
                WOLFSSH_CHANNEL* newChannel;

                newChannel = wolfSSH_ChannelFwdNewRemote(ssh,
                        threadCtx->fwdCbCtx.hostName,
                        threadCtx->fwdCbCtx.hostPort,
                        threadCtx->fwdCbCtx.originName,
                        threadCtx->fwdCbCtx.originPort);
                if (newChannel != NULL) {
                    threadCtx->fwdCbCtx.state = FWD_STATE_CONNECTED;
                }
            }
            if (threadCtx->fwdCbCtx.state == FWD_STATE_DIRECT) {
                fwdFd = connect_addr(threadCtx->fwdCbCtx.hostName,
                        threadCtx->fwdCbCtx.hostPort);

                if (fwdFd > 0) {
                    threadCtx->fwdCbCtx.state = FWD_STATE_CONNECTED;
                }
            }
            #endif
        }
#ifdef WOLFSSH_SHELL
        if (!threadCtx->echo)
            WCLOSESOCKET(childFd);
#endif
    }

#if defined(WOLFSSL_PTHREADS) && defined(WOLFSSL_TEST_GLOBAL_REQ)
    pthread_join(globalReq_th, NULL);
#endif

    return 0;
}


#ifdef WOLFSSH_SFTP

#define TEST_SFTP_TIMEOUT_SHORT 0
#define TEST_SFTP_TIMEOUT 1
#define TEST_SFTP_TIMEOUT_LONG 60

/* handle SFTP operations
 * returns 0 on success
 */
static int sftp_worker(thread_ctx_t* threadCtx)
{
    WOLFSSH* ssh = threadCtx->ssh;
    WS_SOCKET_T s;
    int ret = WS_SUCCESS;
    int error = -1;
    int selected;
    unsigned char peek_buf[1];
    int timeout = TEST_SFTP_TIMEOUT;

    s = (WS_SOCKET_T)wolfSSH_get_fd(ssh);

    do {
        if (wolfSSH_SFTP_PendingSend(ssh)) {
            /* Yes, process the SFTP data. */
            ret = wolfSSH_SFTP_read(ssh);
            error = wolfSSH_get_error(ssh);

            if (ret == WS_REKEYING) {
                timeout = TEST_SFTP_TIMEOUT;
            }
            else if (error == WS_WINDOW_FULL) {
                timeout = TEST_SFTP_TIMEOUT_LONG;
            }
            else {
                timeout = TEST_SFTP_TIMEOUT_SHORT;
            }

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

        selected = tcp_select(s, timeout);
        if (selected == WS_SELECT_ERROR_READY) {
            break;
        }
        else if (selected == WS_SELECT_TIMEOUT) {
            timeout = TEST_SFTP_TIMEOUT_LONG;
        }
        else if (selected == WS_SELECT_RECV_READY) {
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
                TEST_SFTP_TIMEOUT : TEST_SFTP_TIMEOUT_SHORT;
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

    return ret;
}
#endif

static int NonBlockSSH_accept(WOLFSSH* ssh)
{
    int ret;
    int error;
    WS_SOCKET_T sockfd;
    int select_ret = 0;

    ret = wolfSSH_accept(ssh);
    error = wolfSSH_get_error(ssh);
    sockfd = (WS_SOCKET_T)wolfSSH_get_fd(ssh);

    while ((ret != WS_SUCCESS
                && ret != WS_SCP_COMPLETE && ret != WS_SFTP_COMPLETE)
            && (error == WS_WANT_READ || error == WS_WANT_WRITE ||
                error == WS_AUTH_PENDING)) {

        if (error == WS_WANT_READ)
            printf("... server would read block\n");
        else if (error == WS_WANT_WRITE)
            printf("... server would write block\n");

        select_ret = tcp_select(sockfd, 1);
        if (select_ret == WS_SELECT_RECV_READY  ||
            select_ret == WS_SELECT_ERROR_READY ||
            error      == WS_WANT_WRITE ||
            error      == WS_AUTH_PENDING)
        {
            ret = wolfSSH_accept(ssh);
            error = wolfSSH_get_error(ssh);
        }
        else if (select_ret == WS_SELECT_TIMEOUT)
            error = WS_WANT_READ;
        else
            error = WS_FATAL_ERROR;
    }

    return ret;
}


static THREAD_RETURN WOLFSSH_THREAD server_worker(void* vArgs)
{
    int ret = 0, error = 0;
    thread_ctx_t* threadCtx = (thread_ctx_t*)vArgs;

    passwdRetry = MAX_PASSWD_RETRY;

    if (!threadCtx->nonBlock) {
        ret = wolfSSH_accept(threadCtx->ssh);
        if (wolfSSH_get_error(threadCtx->ssh) == WS_AUTH_PENDING) {
            printf("Auth pending error, use -N for non blocking\n");
            printf("Trying to close down the connection\n");
        }
    }
    else {
        ret = NonBlockSSH_accept(threadCtx->ssh);
    }
#ifdef WOLFSSH_SCP
    /* finish off SCP operation */
    if (ret == WS_SCP_INIT) {
        if (!threadCtx->nonBlock)
            ret = wolfSSH_accept(threadCtx->ssh);
        else
            ret = NonBlockSSH_accept(threadCtx->ssh);
    }
#endif

    switch (ret) {
        case WS_SCP_COMPLETE:
            printf("scp file transfer completed\n");
            ret = 0;
            break;

        #ifdef WOLFSSH_SFTP
        case WS_SFTP_COMPLETE:
            ret = sftp_worker(threadCtx);
            break;
        #endif

        case WS_SUCCESS:
            ret = ssh_worker(threadCtx);
            break;
    }

    if (ret == WS_FATAL_ERROR) {
        const char* errorStr;
        error = wolfSSH_get_error(threadCtx->ssh);

        errorStr = wolfSSH_ErrorToName(error);

        if (error == WS_VERSION_E) {
            ret = 0; /* don't break out of loop with version miss match */
            printf("%s\n", errorStr);
        }
        else if (error == WS_USER_AUTH_E) {
            wolfSSH_SendDisconnect(threadCtx->ssh,
                    WOLFSSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE);
            ret = 0; /* don't break out of loop with user auth error */
            printf("%s\n", errorStr);
        }
        else if (error == WS_SOCKET_ERROR_E) {
            ret = 0;
            printf("%s\n", errorStr);
        }
    }

    if (error != WS_SOCKET_ERROR_E && error != WS_FATAL_ERROR) {
        ret = wolfSSH_shutdown(threadCtx->ssh);

        /* peer hung up, stop shutdown */
        if (ret == WS_SOCKET_ERROR_E) {
            ret = 0;
        }

        error = wolfSSH_get_error(threadCtx->ssh);
        if (error != WS_SOCKET_ERROR_E &&
                (error == WS_WANT_READ || error == WS_WANT_WRITE)) {
            int maxAttempt = 10; /* make 10 attempts max before giving up */
            int attempt;

            for (attempt = 0; attempt < maxAttempt; attempt++) {
                ret = wolfSSH_worker(threadCtx->ssh, NULL);
                error = wolfSSH_get_error(threadCtx->ssh);

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

                if (error == WS_WANT_READ || error == WS_WANT_WRITE) {
                    /* Wanting read or wanting write. Clear ret. */
                    ret = 0;
                }
                else {
                    break;
                }
            }

            if (attempt == maxAttempt) {
                printf("Gave up on gracefull shutdown, closing the socket\n");
            }
        }
    }

    if (threadCtx->fd != -1) {
        WCLOSESOCKET(threadCtx->fd);
        threadCtx->fd = -1;
    }
#ifdef WOLFSSH_FWD
    if (threadCtx->fwdCbCtx.hostName != NULL) {
        WFREE(threadCtx->fwdCbCtx.hostName, NULL, 0);
        threadCtx->fwdCbCtx.hostName = NULL;
    }
    if (threadCtx->fwdCbCtx.originName != NULL) {
        WFREE(threadCtx->fwdCbCtx.originName, NULL, 0);
        threadCtx->fwdCbCtx.originName = NULL;
    }
#endif

#ifdef WOLFSSH_STATIC_MEMORY
    wolfSSH_MemoryConnPrintStats(threadCtx->ssh->ctx->heap);
#endif

    wolfSSH_free(threadCtx->ssh);

    if (ret != 0) {
        fprintf(stderr, "Error [%d] \"%s\" with handling connection.\n", ret,
                wolfSSH_ErrorToName(error));
    #ifndef WOLFSSH_NO_EXIT
        wc_LockMutex(&doneLock);
        quit = 1;
        wc_UnLockMutex(&doneLock);
    #endif
    }

    WFREE(threadCtx, NULL, 0);

    WOLFSSL_RETURN_FROM_THREAD(0);
}

#ifndef NO_FILESYSTEM
/* set bufSz to size wanted if too small and buf is null */
static int load_file(const char* fileName, byte* buf, word32* bufSz)
{
    WFILE* file;
    word32 fileSz;
    word32 readSz;

    if (fileName == NULL) return 0;

    if (WFOPEN(NULL, &file, fileName, "rb") != 0)
        return 0;
    WFSEEK(NULL, file, 0, WSEEK_END);
    fileSz = (word32)WFTELL(NULL, file);
    WREWIND(NULL, file);

    if (buf == NULL || fileSz > *bufSz) {
        *bufSz = fileSz;
        WFCLOSE(NULL, file);
        return 0;
    }

    readSz = (word32)WFREAD(NULL, buf, 1, fileSz, file);
    WFCLOSE(NULL, file);

    if (readSz < fileSz) {
        fileSz = 0;
    }

    return fileSz;
}
#endif /* NO_FILESYSTEM */

#ifdef WOLFSSH_NO_ECDSA_SHA2_NISTP256
    #define ECC_PATH "./keys/server-key-ecc-521.der"
#else
    #define ECC_PATH "./keys/server-key-ecc.der"
#endif

/* returns buffer size on success */
static int load_key(byte isEcc, byte* buf, word32 bufSz)
{
    word32 sz = 0;

#ifndef NO_FILESYSTEM
    const char* bufName;
    bufName = isEcc ? ECC_PATH : "./keys/server-key-rsa.der" ;
    sz = load_file(bufName, buf, &bufSz);
#else
    /* using buffers instead */
    if (isEcc) {
        if ((word32)sizeof_ecc_key_der_256 > bufSz) {
            return 0;
        }
        WMEMCPY(buf, ecc_key_der_256, sizeof_ecc_key_der_256);
        sz = sizeof_ecc_key_der_256;
    }
    else {
        if ((word32)sizeof_rsa_key_der_2048 > bufSz) {
            return 0;
        }
        WMEMCPY(buf, (byte*)rsa_key_der_2048, sizeof_rsa_key_der_2048);
        sz = sizeof_rsa_key_der_2048;
    }
#endif

    return sz;
}


typedef struct StrList {
    const char* str;
    struct StrList* next;
} StrList;


static StrList* StrListAdd(StrList* list, const char* str)
{
    if (str != NULL) {
        StrList* newStr = (StrList*)WMALLOC(sizeof *newStr, NULL, 0);

        if (newStr != NULL) {
            newStr->str = str;
            newStr->next = list;
            list = newStr;
        }
    }

    return list;
}

static void StrListFree(StrList* list)
{
    StrList* curStr;

    while (list != NULL) {
        curStr = list;
        list = list->next;
        WFREE(curStr, NULL, 0);
    }
}


/* Map user names to passwords */
/* Use arrays for username and p. The password or public key can
 * be hashed and the hash stored here. Then I won't need the type. */
typedef struct PwMap {
    byte type;
    byte username[32];
    word32 usernameSz;
    byte p[WC_SHA256_DIGEST_SIZE];
    struct PwMap* next;
} PwMap;


typedef struct PwMapList {
    PwMap* head;
} PwMapList;


static PwMap* PwMapNew(PwMapList* list, byte type, const byte* username,
                       word32 usernameSz, const byte* p, word32 pSz)
{
    PwMap* map;

    map = (PwMap*)WMALLOC(sizeof(PwMap), NULL, 0);
    if (map != NULL) {
        map->type = type;
        if (usernameSz >= sizeof(map->username))
            usernameSz = sizeof(map->username) - 1;
        WMEMCPY(map->username, username, usernameSz + 1);
        map->username[usernameSz] = 0;
        map->usernameSz = usernameSz;

        if (type != WOLFSSH_USERAUTH_NONE) {
            wc_Sha256Hash(p, pSz, map->p);
        }

        map->next = list->head;
        list->head = map;
    }

    return map;
}


static void PwMapListDelete(PwMapList* list)
{
    if (list != NULL) {
        PwMap* head = list->head;

        while (head != NULL) {
            PwMap* cur = head;
            head = head->next;
            WMEMSET(cur, 0, sizeof(PwMap));
            WFREE(cur, NULL, 0);
        }
    }
}


static const char samplePasswordBuffer[] =
    "jill:upthehill\n"
    "jack:fetchapail\n";


#ifndef WOLFSSH_NO_ECC
#ifndef WOLFSSH_NO_ECDSA_SHA2_NISTP256
static const char samplePublicKeyEccBuffer[] =
    "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAA"
    "BBBNkI5JTP6D0lF42tbxX19cE87hztUS6FSDoGvPfiU0CgeNSbI+aFdKIzTP5CQEJSvm25"
    "qUzgDtH7oyaQROUnNvk= hansel\n"
    "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAA"
    "BBBKAtH8cqaDbtJFjtviLobHBmjCtG56DMkP6A4M2H9zX2/YCg1h9bYS7WHd9UQDwXO1Hh"
    "IZzRYecXh7SG9P4GhRY= gretel\n";
#elif !defined(WOLFSSH_NO_ECDSA_SHA2_NISTP521)
static const char samplePublicKeyEccBuffer[] =
    "ecdsa-sha2-nistp521 AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHA1MjEAAA"
    "CFBAET/BOzBb9Jx9b52VIHFP4g/uk5KceDpz2M+/Ln9WiDjsMfb4NgNCAB+EMNJUX/TNBL"
    "FFmqr7c6+zUH+QAo2qstvQDsReyFkETRB2vZD//nCZfcAe0RMtKZmgtQLKXzSlimUjXBM4"
    "/zE5lwE05aXADp88h8nuaT/X4bll9cWJlH0fUykA== hansel\n"
    "ecdsa-sha2-nistp521 AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHA1MjEAAA"
    "CFBAD3gANmzvkxOBN8MYwRBYO6B//7TTCtA2vwG/W5bqiVVxznXWj0xiFrgayApvH7FDpL"
    "HiJ8+c1vUsRVEa8PY5QPsgFow+xv0P2WSrRkn4/UUquftPs1ZHPhdr06LjS19ObvWM8xFZ"
    "YU6n0i28UWCUR5qE+BCTzZDWYT8V24YD8UhpaYIw== gretel\n";
#else
    #error "Enable an ECC Curve or disable ECC."
#endif
#endif

#ifndef WOLFSSH_NO_RSA
static const char samplePublicKeyRsaBuffer[] =
    "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC9P3ZFowOsONXHD5MwWiCciXytBRZGho"
    "MNiisWSgUs5HdHcACuHYPi2W6Z1PBFmBWT9odOrGRjoZXJfDDoPi+j8SSfDGsc/hsCmc3G"
    "p2yEhUZUEkDhtOXyqjns1ickC9Gh4u80aSVtwHRnJZh9xPhSq5tLOhId4eP61s+a5pwjTj"
    "nEhBaIPUJO2C/M0pFnnbZxKgJlX7t1Doy7h5eXxviymOIvaCZKU+x5OopfzM/wFkey0EPW"
    "NmzI5y/+pzU5afsdeEWdiQDIQc80H6Pz8fsoFPvYSG+s4/wz0duu7yeeV1Ypoho65Zr+pE"
    "nIf7dO0B8EblgWt+ud+JI8wrAhfE4x hansel\n"
    "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCqDwRVTRVk/wjPhoo66+Mztrc31KsxDZ"
    "+kAV0139PHQ+wsueNpba6jNn5o6mUTEOrxrz0LMsDJOBM7CmG0983kF4gRIihECpQ0rcjO"
    "P6BSfbVTE9mfIK5IsUiZGd8SoE9kSV2pJ2FvZeBQENoAxEFk0zZL9tchPS+OCUGbK4SDjz"
    "uNZl/30Mczs73N3MBzi6J1oPo7sFlqzB6ecBjK2Kpjus4Y1rYFphJnUxtKvB0s+hoaadru"
    "biE57dK6BrH5iZwVLTQKux31uCJLPhiktI3iLbdlGZEctJkTasfVSsUizwVIyRjhVKmbdI"
    "RGwkU38D043AR1h0mUoGCPIKuqcFMf gretel\n";
#endif


#ifdef WOLFSSH_ALLOW_USERAUTH_NONE

static const char sampleNoneBuffer[] =
    "holmes\n"
    "watson\n";


static int LoadNoneBuffer(byte* buf, word32 bufSz, PwMapList* list)
{
    char* str = (char*)buf;
    char* username;

    /* Each line of none list is in the format
     *     username\n
     * This function modifies the passed-in buffer. */

    if (list == NULL)
        return -1;

    if (buf == NULL || bufSz == 0)
        return 0;

    while (*str != 0) {
        username = str;
        str = WSTRCHR(username, '\n');
        if (str == NULL) {
            return -1;
        }
        *str = 0;
        str++;
        if (PwMapNew(list, WOLFSSH_USERAUTH_NONE,
                     (byte*)username, (word32)WSTRLEN(username),
                     NULL, 0) == NULL ) {

            return -1;
        }
    }

    return 0;
}

#endif /* WOLFSSH_ALLOW_USERAUTH_NONE */

static int LoadPasswordBuffer(byte* buf, word32 bufSz, PwMapList* list)
{
    char* str = (char*)buf;
    char* delimiter;
    char* username;
    char* password;

    /* Each line of passwd.txt is in the format
     *     username:password\n
     * This function modifies the passed-in buffer. */

    if (list == NULL)
        return -1;

    if (buf == NULL || bufSz == 0)
        return 0;

    while (*str != 0) {
        delimiter = WSTRCHR(str, ':');
        if (delimiter == NULL) {
            return -1;
        }
        username = str;
        *delimiter = 0;
        password = delimiter + 1;
        str = WSTRCHR(password, '\n');
        if (str == NULL) {
            return -1;
        }
        *str = 0;
        str++;
        if (PwMapNew(list, WOLFSSH_USERAUTH_PASSWORD,
                     (byte*)username, (word32)WSTRLEN(username),
                     (byte*)password, (word32)WSTRLEN(password)) == NULL ) {

            return -1;
        }
    }

    return 0;
}


static int LoadPublicKeyBuffer(byte* buf, word32 bufSz, PwMapList* list)
{
    char* str = (char*)buf;
    char* delimiter;
    char* end = (char*)buf + bufSz;
    byte* publicKey64;
    word32 publicKey64Sz;
    byte* username;
    word32 usernameSz;
    byte*  publicKey;
    word32 publicKeySz;

    /* Each line of passwd.txt is in the format
     *     ssh-rsa AAAB3BASE64ENCODEDPUBLICKEYBLOB username\n
     * This function modifies the passed-in buffer. */
    if (list == NULL)
        return -1;

    if (buf == NULL || bufSz == 0)
        return 0;

    while (str < end && *str != 0) {
        /* Skip the public key type. This example will always be ssh-rsa. */
        delimiter = WSTRCHR(str, ' ');
        if (delimiter == NULL) {
            return -1;
        }
        if (str >= end)
            break;
        str = delimiter + 1;
        delimiter = WSTRCHR(str, ' ');
        if (delimiter == NULL) {
            return -1;
        }
        publicKey64 = (byte*)str;
        *delimiter = 0;
        publicKey64Sz = (word32)(delimiter - str);
        if (str >= end)
            break;
        str = delimiter + 1;
        delimiter = WSTRCHR(str, '\n');
        if (delimiter == NULL) {
            return -1;
        }
        username = (byte*)str;
        *delimiter = 0;
        usernameSz = (word32)(delimiter - str);
        str = delimiter + 1;

        /* more than enough space for base64 decode
         * not using WMALLOC because internal.h is not included for DYNTYPE_* */
        publicKey = (byte*)WMALLOC(publicKey64Sz, NULL, 0);
        if (publicKey == NULL) {
            fprintf(stderr, "error with WMALLOC\n");
            return -1;
        }
        publicKeySz = publicKey64Sz;

        if (Base64_Decode(publicKey64, publicKey64Sz,
                          publicKey, &publicKeySz) != 0) {

            WFREE(publicKey, NULL, 0);
            return -1;
        }

    #ifdef DEBUG_WOLFSSH
        printf("Adding public key for user : %s\n", username);
    #endif

        if (PwMapNew(list, WOLFSSH_USERAUTH_PUBLICKEY,
                     username, usernameSz,
                     publicKey, publicKeySz) == NULL ) {

            WFREE(publicKey, NULL, 0);
            return -1;
        }
        WFREE(publicKey, NULL, 0);
    }

    return 0;
}


static int LoadPasswdList(StrList* strList, PwMapList* mapList)
{
    char names[256];
    char* passwd;
    int count = 0;

    while (strList) {
        WSTRNCPY(names, strList->str, sizeof names - 1);
        passwd = WSTRCHR(names, ':');
        if (passwd != NULL) {
            *passwd = 0;
            passwd++;

            PwMapNew(mapList, WOLFSSH_USERAUTH_PASSWORD,
                    (byte*)names, (word32)WSTRLEN(names),
                    (byte*)passwd, (word32)WSTRLEN(passwd));
        }
        else {
            fprintf(stderr, "Ignoring password: %s\n", names);
        }

        strList = strList->next;
        count++;
    }

    return count;
}

#ifndef NO_FILESYSTEM
static int LoadPubKeyList(StrList* strList, int format, PwMapList* mapList)
{
    char names[256];
    char* fileName;
    byte* buf;
    word32 bufSz;
    int count = 0;

    while (strList) {
        buf = NULL;
        bufSz = 0;

        WSTRNCPY(names, strList->str, sizeof names - 1);
        fileName = WSTRCHR(names, ':');
        if (fileName != NULL) {
            *fileName = 0;
            fileName++;

            load_file(fileName, NULL, &bufSz);
            buf = (byte*)WMALLOC(bufSz, NULL, 0);
            bufSz = load_file(fileName, buf, &bufSz);
            if (bufSz > 0) {
                if (format == WOLFSSH_FORMAT_SSH) {
                    const byte* type = NULL;
                    byte* out = NULL;
                    word32 typeSz, outSz;

                    wolfSSH_ReadKey_buffer(buf, bufSz, WOLFSSH_FORMAT_SSH,
                            &out, &outSz, &type, &typeSz, NULL);

                    (void)type;
                    (void)typeSz;

                    WFREE(buf, NULL, 0);
                    buf = out;
                    bufSz = outSz;
                }
                else if (format == WOLFSSH_FORMAT_PEM) {
                    byte* out = NULL;
                    word32 outSz;

                    out = (byte*)WMALLOC(bufSz, NULL, 0);
                    outSz = wc_CertPemToDer(buf, bufSz, out, bufSz, CERT_TYPE);

                    WFREE(buf, NULL, 0);
                    buf = out;
                    bufSz = outSz;
                }

                PwMapNew(mapList, WOLFSSH_USERAUTH_PUBLICKEY,
                        (byte*)names, (word32)WSTRLEN(names), buf, bufSz);
            }
            else {
                fprintf(stderr, "File error: %s\n", names);
            }
        }
        else {
            fprintf(stderr, "Ignoring key: %s\n", names);
        }

        WFREE(buf, NULL, 0);
        strList = strList->next;
        count++;
    }

    return count;
}
#endif

static int wsUserAuthResult(byte res,
                      WS_UserAuthData* authData,
                      void* ctx)
{
    printf("In auth result callback, auth = %s\n",
        (res == WOLFSSH_USERAUTH_SUCCESS) ? "Success" : "Failure");
    (void)authData;
    (void)ctx;
    return WS_SUCCESS;
}


static int userAuthWouldBlock = 0;
static int wsUserAuth(byte authType,
                      WS_UserAuthData* authData,
                      void* ctx)
{
    PwMapList* list;
    PwMap* map;
    byte authHash[WC_SHA256_DIGEST_SIZE];

    if (ctx == NULL) {
        fprintf(stderr, "wsUserAuth: ctx not set");
        return WOLFSSH_USERAUTH_FAILURE;
    }

    if (userAuthWouldBlock > 0) {
        printf("User Auth would block ....\n");
        userAuthWouldBlock--;
        return WOLFSSH_USERAUTH_WOULD_BLOCK;
    }

    if (authType != WOLFSSH_USERAUTH_PASSWORD &&
#ifdef WOLFSSH_ALLOW_USERAUTH_NONE
        authType != WOLFSSH_USERAUTH_NONE &&
#endif
        authType != WOLFSSH_USERAUTH_PUBLICKEY) {

        return WOLFSSH_USERAUTH_FAILURE;
    }

    if (authType == WOLFSSH_USERAUTH_PASSWORD) {
        wc_Sha256Hash(authData->sf.password.password,
                authData->sf.password.passwordSz,
                authHash);
    }
    else if (authType == WOLFSSH_USERAUTH_PUBLICKEY) {
        wc_Sha256Hash(authData->sf.publicKey.publicKey,
                authData->sf.publicKey.publicKeySz,
                authHash);
    #if defined(WOLFSSH_CERTS) && !defined(WOLFSSH_NO_FPKI) && \
        defined(WOLFSSL_FPKI)
        /* Display FPKI info UUID and FASC-N, getter function for FASC-N and
         * UUID are dependent on wolfSSL version newer than 5.3.0 so gatting
         * on the macro WOLFSSL_FPKI here too */
        if (authData->sf.publicKey.isCert) {
            DecodedCert cert;
            byte* uuid = NULL;
            word32 fascnSz;
            word32 uuidSz;
            word32 i;
            int ret;

            printf("Peer connected with FPKI certificate\n");
            wc_InitDecodedCert(&cert, authData->sf.publicKey.publicKey,
                authData->sf.publicKey.publicKeySz, NULL);
            ret = wc_ParseCert(&cert, CERT_TYPE, 0, NULL);

            /* some profiles supported due not require FASC-N */
            if (ret == 0 &&
                wc_GetFASCNFromCert(&cert, NULL, &fascnSz) == LENGTH_ONLY_E) {
                byte* fascn;

                fascn = (byte*)WMALLOC(fascnSz, NULL, 0);
                if (fascn != NULL &&
                        wc_GetFASCNFromCert(&cert, fascn, &fascnSz) == 0) {
                    printf("HEX of FASC-N :");
                    for (i = 0; i < fascnSz; i++)
                        printf("%02X", fascn[i]);
                    printf("\n");
                }
                if (fascn != NULL)
                    WFREE(fascn, NULL, 0);
            }

            /* all profiles supported must have a UUID */
            if (ret == 0) {
                ret = wc_GetUUIDFromCert(&cert, NULL, &uuidSz);
                if (ret == LENGTH_ONLY_E) { /* expected error value */
                    ret = 0;
                }

                if (ret == 0 ) {
                    uuid = (byte*)WMALLOC(uuidSz, NULL, 0);
                    if (uuid == NULL) {
                        ret = WS_MEMORY_E;
                    }
                }

                if (ret == 0) {
                    ret = wc_GetUUIDFromCert(&cert, uuid, &uuidSz);
                    printf("UUID string : ");
                    for (i = 0; i < uuidSz; i++)
                        printf("%c", uuid[i]);
                    printf("\n");
                }

                if (uuid != NULL)
                    WFREE(uuid, NULL, 0);
            }

            /* failed to at least get UUID string */
            if (ret != 0) {
                return WOLFSSH_USERAUTH_INVALID_PUBLICKEY;
            }
        }
    #endif /* WOLFSSH_CERTS && !WOLFSSH_NO_FPKI */
    }

    list = (PwMapList*)ctx;
    map = list->head;

    while (map != NULL) {
        if (authData->usernameSz == map->usernameSz &&
            WMEMCMP(authData->username, map->username, map->usernameSz) == 0 &&
            authData->type == map->type) {

            if (authData->type == WOLFSSH_USERAUTH_PUBLICKEY) {
                if (WMEMCMP(map->p, authHash, WC_SHA256_DIGEST_SIZE) == 0) {
                    return WOLFSSH_USERAUTH_SUCCESS;
                }
                else {
                   return WOLFSSH_USERAUTH_INVALID_PUBLICKEY;
                }
            }
            else if (authData->type == WOLFSSH_USERAUTH_PASSWORD) {
                if (WMEMCMP(map->p, authHash, WC_SHA256_DIGEST_SIZE) == 0) {
                    return WOLFSSH_USERAUTH_SUCCESS;
                }
                else {
                    passwdRetry--;
                    return (passwdRetry > 0) ?
                        WOLFSSH_USERAUTH_INVALID_PASSWORD :
                        WOLFSSH_USERAUTH_REJECTED;
                 }
            }
            #ifdef WOLFSSH_ALLOW_USERAUTH_NONE
            else if (authData->type == WOLFSSH_USERAUTH_NONE) {
                return WOLFSSH_USERAUTH_SUCCESS;
            }
            #endif /* WOLFSSH_ALLOW_USERAUTH_NONE */
            else {
                 return WOLFSSH_USERAUTH_INVALID_AUTHTYPE;
            }
        }
        map = map->next;
    }

    return WOLFSSH_USERAUTH_INVALID_USER;
}


#ifdef WOLFSSH_SFTP
/*
 * Sets the WOLFSSH object's default SFTP path to the value provided by
 * defaultSftpPath, or uses the current working directory from where the
 * echoserver is run. The new default path is cleaned up with the real
 * path function.
 *
 * @param ssh             WOLFSSH object to update
 * @param defaultSftpPath command line provided default SFTP path
 * @return                0 for success or error code
 */
static int SetDefaultSftpPath(WOLFSSH* ssh, const char* defaultSftpPath)
{
    char path[WOLFSSH_MAX_FILENAME];
    char realPath[WOLFSSH_MAX_FILENAME];
    int ret = 0;

    if (defaultSftpPath == NULL) {
    #ifndef NO_FILESYSTEM
    #ifdef USE_WINDOWS_API
        if (GetCurrentDirectoryA(sizeof(path)-1, path) == 0) {
            ret = WS_INVALID_PATH_E;
        }
    #else
        if (getcwd(path, sizeof(path)-1) == NULL) {
            ret = WS_INVALID_PATH_E;
        }
    #endif
    #elif defined(WOLFSSH_ZEPHYR)
        WSTRNCPY(path, CONFIG_WOLFSSH_SFTP_DEFAULT_DIR, WOLFSSH_MAX_FILENAME);
    #else
        ret = WS_INVALID_PATH_E;
    #endif
    }
    else {
        if (WSTRLEN(defaultSftpPath) >= sizeof(path)) {
            ret = WS_INVALID_PATH_E;
        }
        else {
            WSTRNCPY(path, defaultSftpPath, sizeof(path));
        }
    }

    if (ret == 0) {
        path[sizeof(path) - 1] = 0;
        ret = wolfSSH_RealPath(NULL, path, realPath, sizeof(realPath));
    }

    if (ret == WS_SUCCESS) {
        ret = wolfSSH_SFTP_SetDefaultPath(ssh, realPath);
    }

    return ret;
}
#endif


static void ShowUsage(void)
{
    printf("echoserver %s\n", LIBWOLFSSH_VERSION_STRING);
    printf(" -?            display this help and exit\n");
    printf(" -1            exit after single (one) connection\n");
    printf(" -e            expect ECC public key from client\n");
    printf(" -E            load ECC private key first\n");
#ifdef WOLFSSH_SHELL
    printf(" -f            echo input\n");
#endif
    printf(" -p <num>      port to connect on, default %d\n", wolfSshPort);
    printf(" -N            use non-blocking sockets\n");
#ifdef WOLFSSH_SFTP
    printf(" -d <string>   set the home directory for SFTP connections\n");
#endif
    printf(" -j <file>     load in a SSH public key to accept from peer\n"
           "               (user assumed in comment)\n");
    printf(" -I <name>:<file>\n"
           "               load in a SSH public key to accept from peer\n");
    printf(" -J <name>:<file>\n"
           "               load in an X.509 PEM cert to accept from peer\n");
    printf(" -K <name>:<file>\n"
           "               load in an X.509 DER cert to accept from peer\n");
    printf(" -P <name>:<password>\n"
           "               add password to accept from peer\n");
#ifdef WOLFSSH_CERTS
    printf(" -a <file>     load in a root CA certificate file\n");
#endif
    printf(" -k            set the list of key algos to use\n");
    printf(" -b <num>      test user auth would block\n");
}


static INLINE void SignalTcpReady(tcp_ready* ready, word16 port)
{
#if defined(_POSIX_THREADS) && defined(NO_MAIN_DRIVER) && \
    !defined(__MINGW32__) && !defined(SINGLE_THREADED)
    pthread_mutex_lock(&ready->mutex);
    ready->ready = 1;
    ready->port = port;
    pthread_cond_signal(&ready->cond);
    pthread_mutex_unlock(&ready->mutex);
#else
    WOLFSSH_UNUSED(ready);
    WOLFSSH_UNUSED(port);
#endif
}

#define ES_ERROR(...) do { \
    fprintf(stderr, __VA_ARGS__); \
    serverArgs->return_code = EXIT_FAILURE; \
    WOLFSSL_RETURN_FROM_THREAD(0); \
} while(0)

THREAD_RETURN WOLFSSH_THREAD echoserver_test(void* args)
{
    func_args* serverArgs = (func_args*)args;
    WOLFSSH_CTX* ctx = NULL;
    PwMapList pwMapList;
    #ifndef NO_FILESYSTEM
        StrList* sshPubKeyList = NULL;
        StrList* pemPubKeyList = NULL;
        StrList* derPubKeyList = NULL;
    #endif
    StrList* passwdList = NULL;
    WS_SOCKET_T listenFd = WOLFSSH_SOCKET_INVALID;
    word32 defaultHighwater = EXAMPLE_HIGHWATER_MARK;
    word32 threadCount = 0;
    const char* keyList = NULL;
    ES_HEAP_HINT* heap = NULL;
    int multipleConnections = 1;
    int userEcc = 0;
    int peerEcc = 0;
    int echo = 0;
    int ch;
    word16 port = wolfSshPort;
    char* readyFile = NULL;
    const char* defaultSftpPath = NULL;
    char  nonBlock  = 0;
    #ifndef NO_FILESYSTEM
        char* userPubKey = NULL;
    #endif
    #ifdef WOLFSSH_CERTS
        char* caCert = NULL;
    #endif

    int     argc = serverArgs->argc;
    char**  argv = serverArgs->argv;
    serverArgs->return_code = EXIT_SUCCESS;

    if (argc > 0) {
        const char* optlist = "?1a:d:efEp:R:Ni:j:I:J:K:P:k:b:";
        myoptind = 0;
        while ((ch = mygetopt(argc, argv, optlist)) != -1) {
            switch (ch) {
                case '?' :
                    ShowUsage();
                    serverArgs->return_code = MY_EX_USAGE;
                    WOLFSSL_RETURN_FROM_THREAD(0);

                case '1':
                    multipleConnections = 0;
                    break;

                case 'a':
                    #ifdef WOLFSSH_CERTS
                        caCert = myoptarg;
                    #endif
                    break;
                case 'e' :
                    userEcc = 1;
                    break;

                case 'k' :
                    keyList = myoptarg;
                    break;

                case 'E':
                    peerEcc = 1;
                    break;

                case 'f':
                    #ifdef WOLFSSH_SHELL
                        echo = 1;
                    #endif
                    break;

                case 'p':
                    if (myoptarg == NULL) {
                        ES_ERROR("NULL port value");
                    }
                    else {
                        port = (word16)atoi(myoptarg);
                        #if !defined(NO_MAIN_DRIVER) || defined(USE_WINDOWS_API)
                            if (port == 0) {
                                ES_ERROR("port number cannot be 0");
                            }
                        #endif
                    }
                    break;

                case 'R':
                    readyFile = myoptarg;
                    break;

                case 'N':
                    nonBlock = 1;
                    break;

                case 'd':
                    defaultSftpPath = myoptarg;
                    break;

#ifndef NO_FILESYSTEM
                case 'j':
                    userPubKey = myoptarg;
                    break;

                case 'I':
                    sshPubKeyList = StrListAdd(sshPubKeyList, myoptarg);
                    break;

                case 'J':
                    pemPubKeyList = StrListAdd(pemPubKeyList, myoptarg);
                    break;

                case 'K':
                    derPubKeyList = StrListAdd(derPubKeyList, myoptarg);
                    break;
#endif

                case 'P':
                    passwdList = StrListAdd(passwdList, myoptarg);
                    break;

                case 'b':
                    userAuthWouldBlock = atoi(myoptarg);
                    break;

                default:
                    ShowUsage();
                    serverArgs->return_code = MY_EX_USAGE;
                    WOLFSSL_RETURN_FROM_THREAD(0);
            }
        }
    }
    myoptind = 0;      /* reset for test cases */
    wc_InitMutex(&doneLock);

#ifdef WOLFSSH_TEST_BLOCK
    if (!nonBlock) {
        ES_ERROR("Use -N when testing forced non blocking");
    }
#endif

#ifdef WOLFSSH_NO_RSA
    /* If wolfCrypt isn't built with RSA, force ECC on. */
    userEcc = 1;
    peerEcc = 1;
#endif
#ifdef WOLFSSH_NO_ECC
    /* If wolfCrypt isn't built with ECC, force ECC off. */
    userEcc = 0;
    peerEcc = 0;
#endif
    (void)userEcc;

    if (wolfSSH_Init() != WS_SUCCESS) {
        ES_ERROR("Couldn't initialize wolfSSH.\n");
    }

    #ifdef WOLFSSH_STATIC_MEMORY
    {
        int ret;

        ret = wc_LoadStaticMemory_ex(&heap,
                ES_STATIC_LISTSZ, static_sizeList, static_distList,
                static_buffer, sizeof(static_buffer),
                WOLFMEM_GENERAL|WOLFMEM_TRACK_STATS, 0);
        if (ret != 0) {
            ES_ERROR("Couldn't set up static memory pool.\n");
        }
    }
    #endif /* WOLFSSH_STATIC_MEMORY */

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_SERVER, heap);
    if (ctx == NULL) {
        ES_ERROR("Couldn't allocate SSH CTX data.\n");
    }

    wolfSSH_SetKeyingCompletionCb(ctx, callbackKeyingComplete);
    if (keyList) {
        if (wolfSSH_CTX_SetAlgoListKey(ctx, keyList) != WS_SUCCESS) {
            ES_ERROR("Error setting key list.\n");
        }
    }

    WMEMSET(&pwMapList, 0, sizeof(pwMapList));
    if (serverArgs->user_auth == NULL)
        wolfSSH_SetUserAuth(ctx, wsUserAuth);
    else
        wolfSSH_SetUserAuth(ctx, ((func_args*)args)->user_auth);
    wolfSSH_SetUserAuthResult(ctx, wsUserAuthResult);
    wolfSSH_CTX_SetBanner(ctx, echoserverBanner);
#ifdef WOLFSSH_AGENT
    wolfSSH_CTX_set_agent_cb(ctx, wolfSSH_AGENT_DefaultActions, NULL);
#endif
#ifdef WOLFSSH_FWD
    wolfSSH_CTX_SetFwdCb(ctx, wolfSSH_FwdDefaultActions, NULL);
#endif

#ifndef NO_FILESYSTEM
    if (sshPubKeyList) {
        LoadPubKeyList(sshPubKeyList, WOLFSSH_FORMAT_SSH, &pwMapList);
        StrListFree(sshPubKeyList);
        sshPubKeyList = NULL;
    }
    if (pemPubKeyList) {
        LoadPubKeyList(pemPubKeyList, WOLFSSH_FORMAT_PEM, &pwMapList);
        StrListFree(pemPubKeyList);
        pemPubKeyList = NULL;
    }
    if (derPubKeyList) {
        LoadPubKeyList(derPubKeyList, WOLFSSH_FORMAT_ASN1, &pwMapList);
        StrListFree(derPubKeyList);
        derPubKeyList = NULL;
    }
#endif
    if (passwdList) {
        LoadPasswdList(passwdList, &pwMapList);
        StrListFree(passwdList);
        passwdList = NULL;
    }

    {
        const char* bufName = NULL;
    #ifndef WOLFSSH_SMALL_STACK
        byte buf[EXAMPLE_KEYLOAD_BUFFER_SZ];
    #endif
        byte* keyLoadBuf;
        word32 bufSz;

        #ifdef WOLFSSH_SMALL_STACK
            keyLoadBuf = (byte*)WMALLOC(EXAMPLE_KEYLOAD_BUFFER_SZ,
                    NULL, 0);
            if (keyLoadBuf == NULL) {
                ES_ERROR("Error allocating keyLoadBuf");
            }
        #else
            keyLoadBuf = buf;
        #endif
        bufSz = EXAMPLE_KEYLOAD_BUFFER_SZ;

        bufSz = load_key(peerEcc, keyLoadBuf, bufSz);
        if (bufSz == 0) {
            ES_ERROR("Couldn't load first key file.\n");
        }
        if (wolfSSH_CTX_UsePrivateKey_buffer(ctx, keyLoadBuf, bufSz,
                                             WOLFSSH_FORMAT_ASN1) < 0) {
            ES_ERROR("Couldn't use first key buffer.\n");
        }

        #if !defined(WOLFSSH_NO_RSA) && !defined(WOLFSSH_NO_ECC)
        peerEcc = !peerEcc;
        bufSz = EXAMPLE_KEYLOAD_BUFFER_SZ;

        bufSz = load_key(peerEcc, keyLoadBuf, bufSz);
        if (bufSz == 0) {
            ES_ERROR("Couldn't load second key file.\n");
        }
        if (wolfSSH_CTX_UsePrivateKey_buffer(ctx, keyLoadBuf, bufSz,
                                             WOLFSSH_FORMAT_ASN1) < 0) {
            ES_ERROR("Couldn't use second key buffer.\n");
        }
        #endif

        #ifndef NO_FILESYSTEM
        if (userPubKey) {
            byte* userBuf = NULL;
            word32 userBufSz = 0;

            /* get the files size */
            load_file(userPubKey, NULL, &userBufSz);

            /* create temp buffer and load in file */
            if (userBufSz == 0) {
                ES_ERROR("Couldn't find size of file %s.\n", userPubKey);
            }

            userBuf = (byte*)WMALLOC(userBufSz, NULL, 0);
            if (userBuf == NULL) {
                ES_ERROR("WMALLOC failed\n");
            }
            load_file(userPubKey, userBuf, &userBufSz);
            LoadPublicKeyBuffer(userBuf, userBufSz, &pwMapList);
            WFREE(userBuf, NULL, 0);
        }
        #endif

        #ifdef WOLFSSH_CERTS
        if (caCert) {
            byte* certBuf = NULL;
            word32 certBufSz = 0;
            int ret = 0;

            load_file(caCert, NULL, &certBufSz);

            if (certBufSz == 0) {
                ES_ERROR("Couldn't find size of file %s.\n", caCert);
            }

            certBuf = (byte*)WMALLOC(certBufSz, NULL, 0);
            if (certBuf == NULL) {
                ES_ERROR("WMALLOC failed\n");
            }
            load_file(caCert, certBuf, &certBufSz);
            ret = wolfSSH_CTX_AddRootCert_buffer(ctx, certBuf, certBufSz,
                    WOLFSSH_FORMAT_PEM);
            if (ret != 0) {
                ES_ERROR("Couldn't add root cert\n");
            }
            WFREE(certBuf, NULL, 0);
        }
        #endif

        bufSz = (word32)WSTRLEN(samplePasswordBuffer);
        WMEMCPY(keyLoadBuf, samplePasswordBuffer, bufSz);
        keyLoadBuf[bufSz] = 0;
        LoadPasswordBuffer(keyLoadBuf, bufSz, &pwMapList);

        if (userEcc) {
        #ifndef WOLFSSH_NO_ECC
            bufName = samplePublicKeyEccBuffer;
        #endif
        }
        else {
        #ifndef WOLFSSH_NO_RSA
            bufName = samplePublicKeyRsaBuffer;
        #endif
        }
        if (bufName != NULL) {
            bufSz = (word32)WSTRLEN(bufName);
            WMEMCPY(keyLoadBuf, bufName, bufSz);
            keyLoadBuf[bufSz] = 0;
            LoadPublicKeyBuffer(keyLoadBuf, bufSz, &pwMapList);
        }

        #ifdef WOLFSSH_ALLOW_USERAUTH_NONE
            bufSz = (word32)WSTRLEN(sampleNoneBuffer);
            WMEMCPY(keyLoadBuf, sampleNoneBuffer, bufSz);
            keyLoadBuf[bufSz] = 0;
            LoadNoneBuffer(keyLoadBuf, bufSz, &pwMapList);
        #endif /* WOLFSSH_ALLOW_USERAUTH_NONE */

        #ifdef WOLFSSH_SMALL_STACK
            WFREE(keyLoadBuf, NULL, 0);
        #endif
    }
#ifdef WOLFSSL_NUCLEUS
    {
        int i;
        int ret = !NU_SUCCESS;

        /* wait for network and storage device */
        if (NETBOOT_Wait_For_Network_Up(NU_SUSPEND) != NU_SUCCESS) {
            ES_ERROR("Couldn't find network.\r\n");
        }

        for(i = 0; i < 15 && ret != NU_SUCCESS; i++)
        {
            fprintf(stdout, "Checking for storage device\r\n");

            ret = NU_Storage_Device_Wait(NU_NULL, NU_PLUS_TICKS_PER_SEC);
        }

        if (ret != NU_SUCCESS) {
            ES_ERROR("Couldn't find storage device.\r\n");
        }
    }
#endif

    /* if creating a ready file with port then override port to be 0 */
    if (readyFile != NULL) {
    #ifdef NO_FILESYSTEM
        ES_ERROR("cannot create readyFile with no file system.\r\n");
    #else
        port = 0;
    #endif
    }
    tcp_listen(&listenFd, &port, 1);
    /* write out port number listing to, to user set ready file */
    if (readyFile != NULL) {
    #ifndef NO_FILESYSTEM
        WFILE* f = NULL;
        int    ret;
        ret = WFOPEN(NULL, &f, readyFile, "w");
        if (f != NULL && ret == 0) {
            char portStr[10];
            int l = WSNPRINTF(portStr, sizeof(portStr), "%d\n", (int)port);
            WFWRITE(NULL, portStr, MIN((size_t)l, sizeof(portStr)), 1, f);
            WFCLOSE(NULL, f);
        }
    #endif
    }

    SignalTcpReady(serverArgs->signal, port);

    do {
        WS_SOCKET_T      clientFd = WOLFSSH_SOCKET_INVALID;
    #ifdef WOLFSSL_NUCLEUS
        struct addr_struct clientAddr;
    #else
        SOCKADDR_IN_T clientAddr;
        socklen_t     clientAddrSz = sizeof(clientAddr);
    #endif
        WOLFSSH*      ssh;
        thread_ctx_t* threadCtx;

        threadCtx = (thread_ctx_t*)WMALLOC(sizeof(thread_ctx_t),
                NULL, 0);
        if (threadCtx == NULL) {
            ES_ERROR("Couldn't allocate thread context data.\n");
        }
        WMEMSET(threadCtx, 0, sizeof *threadCtx);

        ssh = wolfSSH_new(ctx);
        if (ssh == NULL) {
            WFREE(threadCtx, NULL, 0);
            ES_ERROR("Couldn't allocate SSH data.\n");
        }
    #ifdef WOLFSSH_STATIC_MEMORY
        wolfSSH_MemoryConnPrintStats(heap);
    #endif
        wolfSSH_SetUserAuthCtx(ssh, &pwMapList);
        wolfSSH_SetKeyingCompletionCbCtx(ssh, (void*)ssh);
        /* Use the session object for its own highwater callback ctx */
        if (defaultHighwater > 0) {
            wolfSSH_SetHighwaterCtx(ssh, (void*)ssh);
            wolfSSH_SetHighwater(ssh, defaultHighwater);
        }

    #ifdef WOLFSSH_SFTP
        if (SetDefaultSftpPath(ssh, defaultSftpPath) != 0) {
            ES_ERROR("Couldn't store default sftp path.\n");
        }
    #endif

    #ifdef WOLFSSL_NUCLEUS
        {
            byte   ipaddr[MAX_ADDRESS_SIZE];
            char   buf[16];
            short  addrLength;
            struct sockaddr_struct sock;

            addrLength = sizeof(struct sockaddr_struct);

            /* Get the local IP address for the socket.
             * 0.0.0.0 if ip adder any */
            if (NU_Get_Sock_Name(listenFd, &sock, &addrLength) != NU_SUCCESS) {
                ES_ERROR("Couldn't find network.\r\n");
            }

            WMEMCPY(ipaddr, &sock.ip_num, MAX_ADDRESS_SIZE);
            NU_Inet_NTOP(NU_FAMILY_IP, &ipaddr[0], buf, 16);
            fprintf(stdout, "Listening on %s:%d\r\n", buf, port);
        }
    #endif

    #ifdef WOLFSSL_NUCLEUS
        clientFd = NU_Accept(listenFd, &clientAddr, 0);
    #else
        clientFd = accept(listenFd, (struct sockaddr*)&clientAddr,
                                                         &clientAddrSz);
    #endif
        if (clientFd == -1) {
            ES_ERROR("tcp accept failed");
        }

        if (nonBlock)
            tcp_set_nonblocking(&clientFd);

        wolfSSH_set_fd(ssh, (int)clientFd);

#if defined(WOLFSSL_PTHREADS) && defined(WOLFSSL_TEST_GLOBAL_REQ)
        threadCtx->ctx = ctx;
#endif
        threadCtx->ssh = ssh;
        threadCtx->fd = clientFd;
        threadCtx->id = threadCount++;
        threadCtx->nonBlock = nonBlock;
        threadCtx->echo = echo;
#ifdef WOLFSSH_AGENT
        wolfSSH_set_agent_cb_ctx(ssh, &threadCtx->agentCbCtx);
#endif
#ifdef WOLFSSH_FWD
        threadCtx->fwdCbCtx.state = FWD_STATE_INIT;
        threadCtx->fwdCbCtx.listenFd = -1;
        threadCtx->fwdCbCtx.appFd = -1;
        wolfSSH_SetFwdCbCtx(ssh, &threadCtx->fwdCbCtx);
#endif
        server_worker(threadCtx);

    } while (multipleConnections && !quit);

    if (listenFd != WOLFSSH_SOCKET_INVALID) {
        WCLOSESOCKET(listenFd);
    }
    wc_FreeMutex(&doneLock);
    PwMapListDelete(&pwMapList);
    wolfSSH_CTX_free(ctx);
#ifdef WOLFSSH_STATIC_MEMORY
    wolfSSH_MemoryPrintStats(heap);
#endif

    if (wolfSSH_Cleanup() != WS_SUCCESS) {
        ES_ERROR("Couldn't clean up wolfSSH.\n");
    }
#if !defined(WOLFSSH_NO_ECC) && defined(FP_ECC) && defined(HAVE_THREAD_LS)
    wc_ecc_fp_free();  /* free per thread cache */
#endif

    (void)defaultSftpPath;
    WOLFSSL_RETURN_FROM_THREAD(0);
}

#endif /* NO_WOLFSSH_SERVER */


void wolfSSL_Debugging_ON(void);

int wolfSSH_Echoserver(int argc, char** argv)
{
    func_args args;

    WMEMSET(&args, 0, sizeof(args));
    args.argc = argc;
    args.argv = argv;

    WSTARTTCP();

    #ifdef DEBUG_WOLFSSH
        wolfSSL_Debugging_ON();
        wolfSSH_Debugging_ON();
    #endif

#if !defined(WOLFSSL_NUCLEUS) && !defined(INTEGRITY) && !defined(__INTEGRITY)
    ChangeToWolfSshRoot();
#endif
#ifndef NO_WOLFSSH_SERVER
    echoserver_test(&args);
#else
    printf("wolfSSH compiled without server support\n");
#endif

    wolfSSH_Cleanup();

    return args.return_code;
}


#ifndef NO_MAIN_DRIVER

    int main(int argc, char** argv)
    {
        return wolfSSH_Echoserver(argc, argv);
    }

    int myoptind = 0;
    char* myoptarg = NULL;

#endif /* NO_MAIN_DRIVER */

#ifdef WOLFSSL_NUCLEUS

    #define WS_TASK_SIZE 200000
    #define WS_TASK_PRIORITY 31
    static  NU_TASK serverTask;

    /* expecting void return on main function */
    static VOID main_nucleus(UNSIGNED argc, VOID* argv)
    {
        main((int)argc, (char**)argv);
    }


    /* using port 8080 because it was an open port on QEMU */
    VOID Application_Initialize (NU_MEMORY_POOL* memPool,
                                 NU_MEMORY_POOL* uncachedPool)
    {
        void* pt;
        int   ret;

        UNUSED_PARAMETER(uncachedPool);

        ret = NU_Allocate_Memory(memPool, &pt, WS_TASK_SIZE, NU_NO_SUSPEND);
        if (ret == NU_SUCCESS) {
            ret = NU_Create_Task(&serverTask, "wolfSSH Server", main_nucleus, 0,
                    NU_NULL, pt, WS_TASK_SIZE, WS_TASK_PRIORITY, 0,
                    NU_PREEMPT, NU_START);
            if (ret != NU_SUCCESS) {
                NU_Deallocate_Memory(pt);
            }
        }
    }
#endif /* WOLFSSL_NUCLEUS */

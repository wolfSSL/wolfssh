/* server.c
 *
 * Copyright (C) 2014-2016 wolfSSL Inc.
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


#include <ctype.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <stdio.h>
#include <pthread.h>
#include <wolfssh/ssh.h>
#ifndef SO_NOSIGPIPE
    #include <signal.h>
#endif


typedef int SOCKET_T;
#ifdef TEST_IPV6
    typedef struct sockaddr_in6 SOCKADDR_IN_T;
    #define AF_INET_V           AF_INET6
    static const char*          wolfsshIP = "::1";
#else
    typedef struct sockaddr_in  SOCKADDR_IN_T;
    #define AF_INET_V           AF_INET
    static const char*          wolfsshIP = "127.0.0.1";
#endif
#define SERVER_PORT_NUMBER      22222
#define SCRATCH_BUFFER_SIZE     1200

#if defined(__MACH__) || defined(USE_WINDOWS_API)
    #ifndef _SOCKLEN_T
        typedef int socklen_t;
    #endif
#endif
/* HPUX doesn't use socklent_t for third parameter to accept, unless
   _XOPEN_SOURCE_EXTENDED is defined */
#if !defined(__hpux__) && !defined(CYASSL_MDK_ARM) && !defined(CYASSL_IAR_ARM)
    typedef socklen_t SOCKLEN_T;
#else
    #if defined _XOPEN_SOURCE_EXTENDED
        typedef socklen_t SOCKLEN_T;
    #else
        typedef int       SOCKLEN_T;
    #endif
#endif


#if defined(_POSIX_THREADS) && !defined(__MINGW32__)
    typedef void*         THREAD_RETURN;
    typedef pthread_t     THREAD_TYPE;
    #define CYASSL_THREAD
    #define INFINITE -1
    #define WAIT_OBJECT_0 0L
#elif defined(CYASSL_MDK_ARM)
    typedef unsigned int  THREAD_RETURN;
    typedef int           THREAD_TYPE;
    #define CYASSL_THREAD
#else
    typedef unsigned int  THREAD_RETURN;
    typedef intptr_t      THREAD_TYPE;
    #define CYASSL_THREAD __stdcall
#endif

typedef struct {
    SOCKET_T clientFd;
} thread_ctx_t;


#ifdef __GNUC__
    #define WS_NORETURN __attribute__((noreturn))
#else
    #define WS_NORETURN
#endif


static INLINE WS_NORETURN void err_sys(const char* msg)
{
    printf("server error: %s\n", msg);

#ifndef __GNUC__
    /* scan-build (which pretends to be gnuc) can get confused and think the
     * msg pointer can be null even when hardcoded and then it won't exit,
     * making null pointer checks above the err_sys() call useless.
     * We could just always exit() but some compilers will complain about no
     * possible return, with gcc we know the attribute to handle that with
     * WS_NORETURN. */
    if (msg)
#endif
    {
        exit(EXIT_FAILURE);
    }
}


static INLINE void build_addr(SOCKADDR_IN_T* addr, const char* peer,
                              word16 port)
{
    int useLookup = 0;
    (void)useLookup;

    memset(addr, 0, sizeof(SOCKADDR_IN_T));

#ifndef TEST_IPV6
    /* peer could be in human readable form */
    if ( (peer != INADDR_ANY) && isalpha((int)peer[0])) {
        #ifdef CYASSL_MDK_ARM
            int err;
            struct hostent* entry = gethostbyname(peer, &err);
        #else
            struct hostent* entry = gethostbyname(peer);
        #endif

        if (entry) {
            memcpy(&addr->sin_addr.s_addr, entry->h_addr_list[0],
                   entry->h_length);
            useLookup = 1;
        }
        else
            err_sys("no entry for host");
    }
#endif

#ifndef TEST_IPV6
    #if defined(CYASSL_MDK_ARM)
        addr->sin_family = PF_INET;
    #else
        addr->sin_family = AF_INET_V;
    #endif
    addr->sin_port = htons(port);
    if (peer == INADDR_ANY)
        addr->sin_addr.s_addr = INADDR_ANY;
    else {
        if (!useLookup)
            addr->sin_addr.s_addr = inet_addr(peer);
    }
#else
    addr->sin6_family = AF_INET_V;
    addr->sin6_port = htons(port);
    if (peer == INADDR_ANY)
        addr->sin6_addr = in6addr_any;
    else {
        #ifdef HAVE_GETADDRINFO
            struct addrinfo  hints;
            struct addrinfo* answer = NULL;
            int    ret;
            char   strPort[80];

            memset(&hints, 0, sizeof(hints));

            hints.ai_family   = AF_INET_V;
            hints.ai_socktype = udp ? SOCK_DGRAM : SOCK_STREAM;
            hints.ai_protocol = udp ? IPPROTO_UDP : IPPROTO_TCP;

            SNPRINTF(strPort, sizeof(strPort), "%d", port);
            strPort[79] = '\0';

            ret = getaddrinfo(peer, strPort, &hints, &answer);
            if (ret < 0 || answer == NULL)
                err_sys("getaddrinfo failed");

            memcpy(addr, answer->ai_addr, answer->ai_addrlen);
            freeaddrinfo(answer);
        #else
            printf("no ipv6 getaddrinfo, loopback only tests/examples\n");
            addr->sin6_addr = in6addr_loopback;
        #endif
    }
#endif
}


static INLINE void tcp_socket(SOCKET_T* sockFd)
{
    *sockFd = socket(AF_INET_V, SOCK_STREAM, 0);

#ifdef USE_WINDOWS_API
    if (*sockFd == INVALID_SOCKET)
        err_sys("socket failed\n");
#else
    if (*sockFd < 0)
        err_sys("socket failed\n");
#endif

#ifndef USE_WINDOWS_API
#ifdef SO_NOSIGPIPE
    {
        int       on = 1;
        socklen_t len = sizeof(on);
        int       res = setsockopt(*sockFd, SOL_SOCKET, SO_NOSIGPIPE, &on, len);
        if (res < 0)
            err_sys("setsockopt SO_NOSIGPIPE failed\n");
    }
#elif defined(CYASSL_MDK_ARM)
    /* nothing to define */
#else  /* no S_NOSIGPIPE */
    signal(SIGPIPE, SIG_IGN);
#endif /* S_NOSIGPIPE */

#if defined(TCP_NODELAY)
    {
        int       on = 1;
        socklen_t len = sizeof(on);
        int       res = setsockopt(*sockFd, IPPROTO_TCP, TCP_NODELAY, &on, len);
        if (res < 0)
            err_sys("setsockopt TCP_NODELAY failed\n");
    }
#endif
#endif  /* USE_WINDOWS_API */
}


static INLINE void tcp_bind(SOCKET_T* sockFd, word16 port, int useAnyAddr)
{
    SOCKADDR_IN_T addr;

    /* don't use INADDR_ANY by default, firewall may block, make user switch
       on */
    build_addr(&addr, (useAnyAddr ? INADDR_ANY : wolfsshIP), port);
    tcp_socket(sockFd);

#if !defined(USE_WINDOWS_API) && !defined(CYASSL_MDK_ARM)
    {
        int       res, on  = 1;
        socklen_t len = sizeof(on);
        res = setsockopt(*sockFd, SOL_SOCKET, SO_REUSEADDR, &on, len);
        if (res < 0)
            err_sys("setsockopt SO_REUSEADDR failed\n");
    }
#endif

    if (bind(*sockFd, (const struct sockaddr*)&addr, sizeof(addr)) != 0)
        err_sys("tcp bind failed");
}


static THREAD_RETURN CYASSL_THREAD server_worker(void* vArgs)
{
    WOLFSSH* ssh = (WOLFSSH*)vArgs;
    SOCKET_T clientFd = wolfSSH_get_fd(ssh);
    const char* msgA = "Who's there?!\r\n";
    const char* msgB = "Go away!\r\n";

    char rxBuf[4096];
    int  rxBufSz;

    if (wolfSSH_accept(ssh) == WS_SUCCESS) {

        wolfSSH_stream_send(ssh, (byte*)msgA, (word32)strlen(msgA));

        rxBufSz = wolfSSH_stream_read(ssh, (byte*)rxBuf, sizeof(rxBuf));
        if (rxBufSz > 0) {
            rxBuf[rxBufSz] = 0;
            printf("client sent %d bytes\n%s", rxBufSz, rxBuf);
        }
        else
            printf("wolfSSH_stream_read returned %d\n", rxBufSz);

        wolfSSH_stream_send(ssh, (byte*)msgB, (word32)strlen(msgB));
    }
    close(clientFd);
    wolfSSH_free(ssh);

    return 0;
}


static int load_file(const char* fileName, byte* buf, word32 bufSz)
{
    FILE* file;
    word32 fileSz;
    word32 readSz;

    if (fileName == NULL) return 0;

    file = fopen(fileName, "rb");
    if (file == NULL) return 0;
    fseek(file, 0, SEEK_END);
    fileSz = (word32)ftell(file);
    rewind(file);

    if (fileSz > bufSz) {
        fclose(file);
        return 0;
    }

    readSz = (word32)fread(buf, 1, fileSz, file);
    if (readSz < fileSz) {
        fclose(file);
        return 0;
    }

    return fileSz;
}


int main(void)
{
    WOLFSSH_CTX* ctx = NULL;
    SOCKET_T listenFd = 0;

    #ifdef DEBUG_WOLFSSH
        wolfSSH_Debugging_ON();
    #endif

    if (wolfSSH_Init() != WS_SUCCESS) {
        fprintf(stderr, "Couldn't initialize wolfSSH.\n");
        exit(EXIT_FAILURE);
    }

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_SERVER, NULL);
    if (ctx == NULL) {
        fprintf(stderr, "Couldn't allocate SSH CTX data.\n");
        exit(EXIT_FAILURE);
    }

    {
        byte buf[SCRATCH_BUFFER_SIZE];
        word32 bufSz;

        bufSz = load_file("./certs/server-cert.der", buf, SCRATCH_BUFFER_SIZE);
        if (bufSz == 0) {
            fprintf(stderr, "Couldn't load certificate file.\n");
            exit(EXIT_FAILURE);
        }
        if (wolfSSH_CTX_UseCert_buffer(ctx,
                                         buf, bufSz, WOLFSSH_FORMAT_ASN1) < 0) {
            fprintf(stderr, "Couldn't use certificate buffer.\n");
            exit(EXIT_FAILURE);
        }

        bufSz = load_file("./certs/server-key.der", buf, SCRATCH_BUFFER_SIZE);
        if (bufSz == 0) {
            fprintf(stderr, "Couldn't load key file.\n");
            exit(EXIT_FAILURE);
        }
        if (wolfSSH_CTX_UsePrivateKey_buffer(ctx,
                                         buf, bufSz, WOLFSSH_FORMAT_ASN1) < 0) {
            fprintf(stderr, "Couldn't use key buffer.\n");
            exit(EXIT_FAILURE);
        }
    }

    tcp_bind(&listenFd, SERVER_PORT_NUMBER, 0);

    for (;;) {
        SOCKET_T      clientFd = 0;
        SOCKADDR_IN_T clientAddr;
        SOCKLEN_T     clientAddrSz = sizeof(clientAddr);
        THREAD_TYPE   thread;
        WOLFSSH*      ssh;

        ssh = wolfSSH_new(ctx);
        if (ssh == NULL) {
            fprintf(stderr, "Couldn't allocate SSH data.\n");
            exit(EXIT_FAILURE);
        }

        if (listen(listenFd, 5) != 0)
            err_sys("tcp listen failed");

        clientFd = accept(listenFd, (struct sockaddr*)&clientAddr,
                                                                 &clientAddrSz);
        if (clientFd == -1)
            err_sys("tcp accept failed");

        wolfSSH_set_fd(ssh, clientFd);

        pthread_create(&thread, 0, server_worker, ssh);
        pthread_detach(thread);
    }

    if (wolfSSH_Cleanup() != WS_SUCCESS) {
        fprintf(stderr, "Couldn't clean up wolfSSH.\n");
        exit(EXIT_FAILURE);
    }

    return 0;
}


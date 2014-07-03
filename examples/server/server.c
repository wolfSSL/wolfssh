/* server.c 
 *
 * Copyright (C) 2014 wolfSSL Inc.
 *
 * This file is part of wolfSSH.
 *
 * wolfSSH is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSH is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
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


static WINLINE void err_sys(const char* msg)
{
    printf("server error: %s\n", msg);
    if (msg)
        exit(EXIT_FAILURE);
}


static WINLINE void build_addr(SOCKADDR_IN_T* addr, const char* peer,
                              uint16_t port)
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


static WINLINE void tcp_socket(SOCKET_T* sockFd)
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


static WINLINE void tcp_bind(SOCKET_T* sockFd, uint16_t port, int useAnyAddr)
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
    thread_ctx_t* threadCtx = (thread_ctx_t*)vArgs;
    SOCKET_T clientFd = threadCtx->clientFd;
    const char* msgA = "Who's there?!\n";
    const char* msgB = "Go away!\n";

    send(clientFd, msgA, strlen(msgA), 0);
    sleep(1);
    send(clientFd, msgB, strlen(msgB), 0);
    close(clientFd);
    free(threadCtx);

    return 0;
}


int main(void)
{
    SOCKET_T listenFd = 0;

    #ifdef DEBUG_WOLFSSH
        wolfSSH_Debugging_ON();
    #endif

    if (wolfSSH_Init() != WS_SUCCESS) {
        fprintf(stderr, "Couldn't initialize wolfSSH.\n");
        exit(EXIT_FAILURE);
    }

    tcp_bind(&listenFd, 22222, 0);

    for (;;) {
        SOCKET_T      clientFd = 0;
        SOCKADDR_IN_T clientAddr;
        SOCKLEN_T     clientAddrSz = sizeof(clientAddr);
        THREAD_TYPE   thread;
        thread_ctx_t* threadCtx =
                                 (thread_ctx_t*)calloc(1, sizeof(thread_ctx_t));

        if (threadCtx == NULL) {
            fprintf(stderr, "Couldn't allocate thread data.\n");
            exit(EXIT_FAILURE);
        }

        if (listen(listenFd, 5) != 0)
            err_sys("tcp listen failed");

        clientFd = accept(listenFd, (struct sockaddr*)&clientAddr,
                                                                 &clientAddrSz);

        if (clientFd == -1)
            err_sys("tcp accept failed");

        threadCtx->clientFd = clientFd;

        pthread_create(&thread, 0, server_worker, threadCtx);
        pthread_detach(thread);
    }

    if (wolfSSH_Cleanup() != WS_SUCCESS) {
        fprintf(stderr, "Couldn't clean up wolfSSH.\n");
        exit(EXIT_FAILURE);
    }

    return 0;
}


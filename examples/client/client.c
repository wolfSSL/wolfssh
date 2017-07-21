/* client.c
 *
 * Copyright (C) 2014-2017 wolfSSL Inc.
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
#include <stdio.h>
#include <unistd.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#ifndef SO_NOSIGPIPE
    #include <signal.h>
#endif

#include <wolfssh/ssh.h>


const char testString[] = "Hello, wolfSSH!";
#define SERVER_PORT_NUMBER      22222


#ifdef __GNUC__
    #define WS_NORETURN __attribute__((noreturn))
#else
    #define WS_NORETURN
#endif

static INLINE WS_NORETURN void err_sys(const char* msg)
{
    printf("client error: %s\n", msg);

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



static void ShowUsage(void)
{
    printf("client %s\n", LIBWOLFSSH_VERSION_STRING);
    printf(" -?          display this help and exit\n");
}


static INLINE void build_addr(SOCKADDR_IN_T* addr, const char* peer,
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


#define MY_EX_USAGE 2

extern int   myoptind;
extern char* myoptarg;

static INLINE int mygetopt(int argc, char** argv, const char* optstring)
{
    static char* next = NULL;

    char  c;
    char* cp;

    if (myoptind == 0)
        next = NULL;   /* we're starting new/over */

    if (next == NULL || *next == '\0') {
        if (myoptind == 0)
            myoptind++;

        if (myoptind >= argc || argv[myoptind][0] != '-' ||
                                argv[myoptind][1] == '\0') {
            myoptarg = NULL;
            if (myoptind < argc)
                myoptarg = argv[myoptind];

            return -1;
        }

        if (strcmp(argv[myoptind], "--") == 0) {
            myoptind++;
            myoptarg = NULL;

            if (myoptind < argc)
                myoptarg = argv[myoptind];

            return -1;
        }

        next = argv[myoptind];
        next++;                  /* skip - */
        myoptind++;
    }

    c  = *next++;
    /* The C++ strchr can return a different value */
    cp = (char*)strchr(optstring, c);

    if (cp == NULL || c == ':')
        return '?';

    cp++;

    if (*cp == ':') {
        if (*next != '\0') {
            myoptarg = next;
            next     = NULL;
        }
        else if (myoptind < argc) {
            myoptarg = argv[myoptind];
            myoptind++;
        }
        else
            return '?';
    }

    return c;
}


static int runClient(void)
{
    WOLFSSH_CTX* ctx = NULL;
    WOLFSSH* ssh = NULL;
    SOCKET_T sockFd = 0;
    SOCKADDR_IN_T clientAddr;
    SOCKLEN_T clientAddrSz = sizeof(clientAddr);
    char rxBuf[80];
    int ret;

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_CLIENT, NULL);
    if (ctx == NULL)
        err_sys("Couldn't create wolfSSH client context.");

    ssh = wolfSSH_new(ctx);
    if (ssh == NULL)
        err_sys("Couldn't create wolfSSH session.");

    build_addr(&clientAddr, wolfsshIP, SERVER_PORT_NUMBER);
    tcp_socket(&sockFd);
    ret = connect(sockFd, (const struct sockaddr *)&clientAddr, clientAddrSz);
    if (ret != 0)
        err_sys("Couldn't connect to server.");

    ret = wolfSSH_set_fd(ssh, sockFd);
    if (ret != WS_SUCCESS)
        err_sys("Couldn't set the session's socket.");

    ret = wolfSSH_connect(ssh);
    if (ret != WS_SUCCESS)
        err_sys("Couldn't connect SSH stream.");

    ret = wolfSSH_stream_send(ssh, (uint8_t*)testString,
                              (uint32_t)strlen(testString));
    if (ret != WS_SUCCESS)
        err_sys("Couldn't send test string.");

    ret = wolfSSH_stream_read(ssh, (uint8_t*)rxBuf, sizeof(rxBuf) - 1);
    if (ret <= 0)
        err_sys("Stream read failed.");
    rxBuf[ret] = '\0';
    printf("Server said: %s\n", rxBuf);

    ret = wolfSSH_shutdown(ssh);
    if (ret != WS_SUCCESS)
        err_sys("Closing stream failed.");

    close(sockFd);
    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);

    return 0;
}


int main(int argc, char** argv)
{
    int result = 0;
    char ch;

    #ifdef DEBUG_WOLFSSH
        wolfSSH_Debugging_ON();
    #endif

    while ((ch = mygetopt(argc, argv, "?")) != -1) {
        switch (ch) {
            case 'h' :
                ShowUsage();
                exit(EXIT_SUCCESS);

            default:
                ShowUsage();
                exit(MY_EX_USAGE);
        }
    }
    myoptind = 0;      /* reset for test cases */

    if (runClient() != 0)
        result = 1;

    return result;
}

int myoptind = 0;
char* myoptarg = NULL;

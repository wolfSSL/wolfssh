/* test.h
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

/*
 * This file contains some utility code shared between the wolfSSH test
 * tools and examples. This is divided into a few sets of functions that
 * may be enabled with flags included before including this file:
 *
 *  WOLFSSH_TEST_CLIENT: Client utility functions
 *  WOLFSSH_TEST_SERVER: Server utility functions
 *  WOLFSSH_TEST_LOCKING: Mutex wrappers
 *  WOLFSSH_TEST_THREADING: Threading wrappers
 *  WOLFSSH_TEST_HEX2BIN: Hex2Bin conversion
 *  TEST_IPV6: IPv6 addressing options
 */

#ifndef _WOLFSSH_TEST_H_
#define _WOLFSSH_TEST_H_

#ifndef NO_STDIO_FILESYSTEM
#include <stdio.h>
/*#include <stdlib.h>*/
#include <ctype.h>
/*#include <wolfssh/error.h>*/
#endif

#ifdef USE_WINDOWS_API
    #ifndef _WIN32_WCE
        #include <process.h>
    #endif
    #include <assert.h>
    #ifdef TEST_IPV6            /* don't require newer SDK for IPV4 */
        #include <ws2tcpip.h>
        #include <wspiapi.h>
    #endif
    #define SOCKET_T SOCKET
    #define NUM_SOCKETS 5
#elif defined(WOLFSSL_VXWORKS)
    #include <unistd.h>
    #include <hostLib.h>
    #include <sockLib.h>
    #include <arpa/inet.h>
    #include <string.h>
    #include <selectLib.h>
    #include <sys/types.h>
    #include <netinet/in.h>
    #include <netinet/tcp.h>
    #include <ipcom_sock.h>
    #include <fcntl.h>
    #include <sys/time.h>
    #include <netdb.h>
    #include <pthread.h>
    #define SOCKET_T int

    /*#define SINGLE_THREADED*/

    #ifndef STDIN_FILENO
    #define STDIN_FILENO   0
    #endif
    #ifndef STDOUT_FILENO
    #define STDOUT_FILENO   1
    #endif
    #ifndef STDERR_FILENO
    #define STDERR_FILENO   2
    #endif
    #define NUM_SOCKETS 2
#elif defined(MICROCHIP_MPLAB_HARMONY) || defined(MICROCHIP_TCPIP)
    #include "tcpip/tcpip.h"
    #include <signal.h>
    #ifdef MICROCHIP_MPLAB_HARMONY
        #ifndef htons
            #define htons TCPIP_Helper_htons
        #endif
        #define SOCKET_T TCP_SOCKET
        #define XNTOHS TCPIP_Helper_ntohs
    #endif
    #define socklen_t int
    #define NUM_SOCKETS 1
#elif defined(WOLFSSL_NUCLEUS)
    #include "nucleus.h"
    #include "networking/nu_networking.h"
    #define SOCKET_T int
    #define socklen_t int
    #define NUM_SOCKETS 1
    #define INADDR_ANY IP_ADDR_ANY
    #define AF_INET NU_FAMILY_IP
    #define SOCK_STREAM NU_TYPE_STREAM

    #define sin_addr id
    #define s_addr is_ip_addrs

    #define sin_family family
    #define sin_port port
#elif defined(FREESCALE_MQX)
    #ifndef SO_NOSIGPIPE
        #include <signal.h>  /* ignore SIGPIPE */
    #endif

    #define NUM_SOCKETS 5
#elif defined(WOLFSSH_LWIP)
    #include <unistd.h>
    #include <sys/socket.h>
    #include <pthread.h>
    #include <lwip/tcp.h>
    #include <lwip/inet.h>
    #include <lwip/netdb.h>
    #ifndef SO_NOSIGPIPE
        #include <signal.h>  /* ignore SIGPIPE */
    #endif
    #define SOCKET_T int
    #define NUM_SOCKETS 5
#elif defined(WOLFSSH_ZEPHYR)
    #include <zephyr/kernel.h>
    #include <zephyr/posix/posix_types.h>
    #include <zephyr/posix/pthread.h>
    #include <zephyr/posix/fcntl.h>
    #include <zephyr/net/socket.h>
    #include <zephyr/sys/printk.h>
    #include <zephyr/sys/util.h>
    #include <stdlib.h>
    #define SOCKET_T int
    #define NUM_SOCKETS 5
#if (defined(WOLFSSH_TEST_CLIENT) || defined(WOLFSSH_TEST_SERVER)) && \
    !defined(TEST_IPV6)
    static unsigned long inet_addr(const char *cp)
    {
        unsigned int a[4]; unsigned long ret;
        int i, j;
        for (i=0, j=0; i<4; i++) {
            a[i] = 0;
            while (cp[j] != '.' && cp[j] != '\0') {
                a[i] *= 10;
                a[i] += cp[j] - '0';
                j++;
            }
        }
        ret = ((a[3]<<24) + (a[2]<<16) + (a[1]<<8) + a[0]) ;
        return(ret) ;
    }
#endif
#elif defined(WOLFSSH_USER_IO)
    #include <unistd.h>
    #include <pthread.h>
    #include <fcntl.h>
    #include "userio_template.h"
    #ifndef SO_NOSIGPIPE
        #include <signal.h>  /* ignore SIGPIPE */
    #endif
    #define SOCKET_T int
    #define NUM_SOCKETS 5
#elif defined(WOLFSSL_ESPIDF)
    #include "sdkconfig.h"
    #include <esp_idf_version.h>
    #include <esp_log.h>
    #include <lwip/sockets.h>
    #include <lwip/netdb.h>
    #define SOCKET_T int
    #define NUM_SOCKETS 5
#else /* USE_WINDOWS_API */
    #include <unistd.h>
    #include <sys/socket.h>
    #include <sys/select.h>
    #include <pthread.h>
    #include <netdb.h>
    #include <netinet/in.h>
    #include <netinet/tcp.h>
    #include <arpa/inet.h>
    #include <sys/ioctl.h>
    #include <fcntl.h>
    #ifndef SO_NOSIGPIPE
        #include <signal.h>  /* ignore SIGPIPE */
    #endif
    #define SOCKET_T int
    #define NUM_SOCKETS 5
#endif /* USE_WINDOWS_API */


/* Socket Handling */
#ifndef WOLFSSH_SOCKET_INVALID
#if defined(USE_WINDOWS_API) || defined(MICROCHIP_MPLAB_HARMONY)
    #define WOLFSSH_SOCKET_INVALID  ((SOCKET_T)INVALID_SOCKET)
#elif defined(WOLFSSH_TIRTOS)
    #define WOLFSSH_SOCKET_INVALID  ((SOCKET_T)-1)
#else
    #define WOLFSSH_SOCKET_INVALID  (SOCKET_T)(-1)
#endif
#endif /* WOLFSSH_SOCKET_INVALID */

#ifndef WOLFSSL_SOCKET_IS_INVALID
#if defined(USE_WINDOWS_API) || defined(WOLFSSL_TIRTOS)
    #define WOLFSSL_SOCKET_IS_INVALID(s)  ((SOCKET_T)(s) == WOLFSSL_SOCKET_INVALID)
#else
    #define WOLFSSL_SOCKET_IS_INVALID(s)  ((SOCKET_T)(s) < WOLFSSL_SOCKET_INVALID)
#endif
#endif /* WOLFSSL_SOCKET_IS_INVALID */


#if defined(__MACH__) || defined(USE_WINDOWS_API) || defined(FREESCALE_MQX)
    #ifndef _SOCKLEN_T
        typedef int socklen_t;
    #endif
#endif


#ifdef USE_WINDOWS_API
    #define WCLOSESOCKET(s) closesocket(s)
    #define WSTARTTCP() do { WSADATA wsd; (void)WSAStartup(0x0002, &wsd); } while(0)
#elif defined(MICROCHIP_TCPIP) || defined(MICROCHIP_MPLAB_HARMONY)
    #ifdef MICROCHIP_MPLAB_HARMONY
        #define WCLOSESOCKET(s) TCPIP_TCP_Close((s))
    #else
        #define WCLOSESOCKET(s) closesocket((s))
    #endif
    #define WSTARTTCP()
#elif defined(WOLFSSL_NUCLEUS)
    #define WCLOSESOCKET(s) NU_Close_Socket((s))
    #define WSTARTTCP()
#else
    #define WCLOSESOCKET(s) close(s)
    #define WSTARTTCP()
#endif


#ifdef TEST_IPV6
    typedef struct sockaddr_in6 SOCKADDR_IN_T;
    #define AF_INET_V AF_INET6
#else
    #ifndef WOLFSSL_NUCLEUS
        typedef struct sockaddr_in SOCKADDR_IN_T;
    #endif
    #define AF_INET_V AF_INET
#endif


#define serverKeyRsaPemFile "./keys/server-key-rsa.pem"


#ifdef WOLFSSH_ZEPHYR
    static const char* const wolfSshIp = "192.0.2.1";
#elif !defined(TEST_IPV6)
    static const char* const wolfSshIp = "127.0.0.1";
#else /* TEST_IPV6 */
    static const char* const wolfSshIp = "::1";
#endif /* TEST_IPV6 */

#ifdef WOLFSSL_NUCLEUS
    /* port 8080 was open with QEMU */
    static const word16 wolfSshPort = 8080;
#else
    static const word16 wolfSshPort = 22222;
#endif

#ifdef __GNUC__
    #define WS_NORETURN __attribute__((noreturn))
#else
    #define WS_NORETURN
#endif

#ifdef WOLFSSL_VXWORKS
static INLINE void err_sys(const char* msg)
{
    printf("wolfSSH error: %s\n", msg);
    return;
}
#elif defined(INTEGRITY) || defined(__INTEGRITY)
static INLINE void err_sys(const char* msg)
{
    printf("wolfSSH error: %s\n", msg);
}
#elif defined(WOLFSSH_ZEPHYR)
static INLINE void err_sys(const char* msg)
{
    printf("wolfSSH error: %s errno: %d\n", msg, errno);
    exit(EXIT_FAILURE);
}
#else
static INLINE WS_NORETURN void err_sys(const char* msg)
{
    printf("wolfSSH error: %s\n", msg);

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
#endif

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


#ifdef USE_WINDOWS_API
    #pragma warning(push)
    #pragma warning(disable:4996)
    /* For Windows builds, disable compiler warnings for:
    * - 4996: deprecated function */
#endif

#if (defined(WOLFSSH_TEST_CLIENT) || defined(WOLFSSH_TEST_SERVER)) && !defined(FREESCALE_MQX)

#ifdef WOLFSSL_NUCLEUS
static INLINE void build_addr(struct addr_struct* addr, const char* peer,
                              word16 port)
{
    int useLookup = 0;
    (void)useLookup;

    memset(addr, 0, sizeof(struct addr_struct));

#ifndef TEST_IPV6
    /* peer could be in human readable form */
    if ( ((size_t)peer != INADDR_ANY) && isalpha((int)peer[0])) {

        NU_HOSTENT* entry;
        NU_HOSTENT h;
        entry = &h;
        NU_Get_Host_By_Name((char*)peer, entry);

        if (entry) {
            memcpy(&addr->id.is_ip_addrs, entry->h_addr_list[0],
                entry->h_length);
            useLookup = 1;
        }
        else
            err_sys("no entry for host");
    }
#endif

#ifndef TEST_IPV6
    addr->family = NU_FAMILY_IP;
    addr->port = port;

    /* @TODO always setting any ip addr here */
    PUT32(addr->id.is_ip_addrs, 0, IP_ADDR_ANY);
#endif
}
#else
static INLINE void build_addr(SOCKADDR_IN_T* addr, const char* peer,
                              word16 port)
{
    int useLookup = 0;
    (void)useLookup;

    memset(addr, 0, sizeof(SOCKADDR_IN_T));

#ifndef TEST_IPV6
    /* peer could be in human readable form */
    if ( ((size_t)peer != INADDR_ANY) && isalnum((int)peer[0])) {
    #ifdef WOLFSSH_ZEPHYR
        struct zsock_addrinfo hints, *addrInfo;
        char portStr[6];
        XSNPRINTF(portStr, sizeof(portStr), "%d", port);
        XMEMSET(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;
        if (getaddrinfo((char*)peer, portStr, &hints, &addrInfo) == 0) {
            XMEMCPY(addr, addrInfo->ai_addr, sizeof(*addr));
            freeaddrinfo(addrInfo);
            useLookup = 1;
        }
    #else
        #ifdef CYASSL_MDK_ARM
            int err;
            struct hostent* entry = gethostbyname(peer, &err);
        #elif defined(MICROCHIP_MPLAB_HARMONY)
            struct hostent* entry = gethostbyname((char*)peer);
        #elif defined(WOLFSSL_NUCLEUS)
            NU_HOSTENT* entry;
            NU_HOSTENT h;
            entry = &h;
            NU_Get_Host_By_Name((char*)peer, entry);
        #elif defined(WOLFSSH_ZEPHYR)
        #else
            struct hostent* entry = gethostbyname(peer);
        #endif

        if (entry) {
#ifdef WOLFSSL_NUCLEUS
        memcpy(&addr->id.is_ip_addrs, entry->h_addr_list[0],
                entry->h_length);
#else
            memcpy(&addr->sin_addr.s_addr, entry->h_addr_list[0],
                   entry->h_length);
#endif
            useLookup = 1;
        }
        else
            err_sys("no entry for host");
    #endif
    }
#endif

#ifndef TEST_IPV6
    #if defined(CYASSL_MDK_ARM)
        addr->sin_family = PF_INET;
    #else
        addr->sin_family = AF_INET_V;
    #endif
    addr->sin_port = htons(port);
    if ((size_t)peer == INADDR_ANY)
#ifdef WOLFSSL_NUCLEUS
        PUT32(addr->id.is_ip_addrs, 0, INADDR_ANY);
#else
        addr->sin_addr.s_addr = INADDR_ANY;
#endif
    else {
        if (!useLookup) {
    #ifdef MICROCHIP_MPLAB_HARMONY
            IPV4_ADDR ip4;
            TCPIP_Helper_StringToIPAddress(peer, &ip4);
            addr->sin_addr.s_addr = ip4.Val;
    #else
            addr->sin_addr.s_addr = inet_addr(peer);
    #endif
        }
    }
#else
    addr->sin6_family = AF_INET_V;
    addr->sin6_port = htons(port);
    if ((size_t)peer == INADDR_ANY)
        addr->sin6_addr = in6addr_any;
    else {
        #ifdef HAVE_GETADDRINFO
            struct addrinfo  hints;
            struct addrinfo* answer = NULL;
            int    ret;
            char   strPort[80];

            memset(&hints, 0, sizeof(hints));

            hints.ai_family   = AF_UNSPEC;
            hints.ai_socktype = SOCK_STREAM;
            hints.ai_protocol = IPPROTO_TCP;

            WSNPRINTF(strPort, sizeof(strPort), "%d", port);
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
#endif /* WOLFSSH_NUCLEUS */

#ifdef USE_WINDOWS_API
    #pragma warning(pop)
#endif


static INLINE void tcp_socket(WS_SOCKET_T* sockFd, int targetProtocol)
{
    /* targetProtocol is only used if none of these platforms are defined. */
    WOLFSSH_UNUSED(targetProtocol);
#ifdef MICROCHIP_MPLAB_HARMONY
    /* creates socket in listen or connect */
    *sockFd = 0;
#elif defined(MICROCHIP_TCPIP)
    *sockFd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
#elif defined(WOLFSSH_ZEPHYR)
    *sockFd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
#elif defined(WOLFSSL_NUCLEUS)
    *sockFd = NU_Socket(NU_FAMILY_IP, NU_TYPE_STREAM, 0);
#else
    *sockFd = socket(targetProtocol, SOCK_STREAM, 0);
#endif

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
#elif defined(MICROCHIP_MPLAB_HARMONY) && !defined(_FULL_SIGNAL_IMPLEMENTATION)
    /* not full signal implementation */
#elif defined(WOLFSSL_NUCLEUS)
    /* nothing to define */
#elif defined(WOLFSSL_ESPIDF)
    /* nothing to define */
#elif defined(WOLFSSL_ZEPHYR)
    /* nothing to define */
#else  /* no S_NOSIGPIPE */
    signal(SIGPIPE, SIG_IGN);
#endif /* S_NOSIGPIPE */

#if defined(TCP_NODELAY)
    {
    #ifdef MICROCHIP_MPLAB_HARMONY
        if (!TCPIP_TCP_OptionsSet(*sockFd, TCP_OPTION_NODELAY, (void*)1)) {
            err_sys("setsockopt TCP_NODELAY failed\n");
        }
    #elif defined(WOLFSSL_NUCLEUS)
    #else
        int       on = 1;
        socklen_t len = sizeof(on);
        int       res = setsockopt(*sockFd, IPPROTO_TCP, TCP_NODELAY, &on, len);
        if (res < 0)
            err_sys("setsockopt TCP_NODELAY failed\n");
    #endif
    }
#endif
#endif  /* USE_WINDOWS_API */
}

#endif /* WOLFSSH_TEST_CLIENT || WOLFSSH_TEST_SERVER */


#ifndef XNTOHS
    #define XNTOHS(a) ntohs((a))
#endif


#if defined(WOLFSSH_TEST_SERVER) && !defined(FREESCALE_MQX)\
                                 && !defined(WOLFSSH_LWIP)

static INLINE void tcp_listen(WS_SOCKET_T* sockfd, word16* port, int useAnyAddr)
{
#ifdef MICROCHIP_MPLAB_HARMONY
    /* does bind and listen and returns the socket */
    *sockfd = TCPIP_TCP_ServerOpen(IP_ADDRESS_TYPE_IPV4, *port, 0);
    return;
#else
    #ifdef WOLFSSL_NUCLEUS
        struct addr_struct addr;
    #else
        SOCKADDR_IN_T addr;
    #endif
    /* don't use INADDR_ANY by default, firewall may block, make user switch
       on */
    build_addr(&addr, (useAnyAddr ? INADDR_ANY : wolfSshIp), *port);
    tcp_socket(sockfd, ((struct sockaddr_in *)&addr)->sin_family);
#if !defined(USE_WINDOWS_API) && !defined(WOLFSSL_MDK_ARM) \
                              && !defined(WOLFSSL_KEIL_TCP_NET) \
                              && !defined(WOLFSSL_NUCLEUS) \
                              && !defined(WOLFSSH_ZEPHYR)
    {
        int res;
    #ifdef MICROCHIP_TCPIP
        const byte on = 1; /* account for function signature */
    #else
        int on  = 1;
    #endif
        socklen_t len = sizeof(on);
        res = setsockopt(*sockfd, SOL_SOCKET, SO_REUSEADDR, &on, len);
        if (res < 0)
            err_sys("setsockopt SO_REUSEADDR failed\n");
    }
#endif

#ifdef WOLFSSL_NUCLEUS
    /* any NU_Bind return greater than or equal to 0 is a success */
    if (NU_Bind(*sockfd, &addr, sizeof(addr)) < 0)
        err_sys("tcp bind failed");
    if (NU_Listen(*sockfd, NUM_SOCKETS) != NU_SUCCESS)
        err_sys("tcp listen failed");
#else
    if (bind(*sockfd, (const struct sockaddr*)&addr, sizeof(addr)) != 0)
        err_sys("tcp bind failed");
    if (listen(*sockfd, NUM_SOCKETS) != 0)
        err_sys("tcp listen failed");
#endif

    #if !defined(USE_WINDOWS_API) && !defined(WOLFSSL_TIRTOS) && !defined(WOLFSSL_NUCLEUS)
        if (*port == 0) {
            socklen_t len = sizeof(addr);
            if (getsockname(*sockfd, (struct sockaddr*)&addr, &len) == 0) {
                #ifndef TEST_IPV6
                    *port = XNTOHS(addr.sin_port);
                #else
                    *port = XNTOHS(addr.sin6_port);
                #endif
            }
        }
    #endif
#endif /* MICROCHIP_MPLAB_HARMONY */
}

#endif /* WOLFSSH_TEST_SERVER */

enum {
    WS_SELECT_FAIL,
    WS_SELECT_TIMEOUT,
    WS_SELECT_RECV_READY,
    WS_SELECT_ERROR_READY
};

#if (defined(WOLFSSH_TEST_SERVER) || defined(WOLFSSH_TEST_CLIENT)) && !defined(FREESCALE_MQX)

static INLINE void tcp_set_nonblocking(WS_SOCKET_T* sockfd)
{
    #ifdef USE_WINDOWS_API
        unsigned long blocking = 1;
        int ret = ioctlsocket(*sockfd, FIONBIO, &blocking);
        if (ret == SOCKET_ERROR)
            err_sys("ioctlsocket failed");
    #elif defined(WOLFSSL_MDK_ARM) || defined(WOLFSSL_KEIL_TCP_NET) \
        || defined (WOLFSSL_TIRTOS)|| defined(WOLFSSL_VXWORKS) || \
        defined(WOLFSSL_NUCLEUS)
         /* non blocking not supported, for now */
    #else
        int flags = fcntl(*sockfd, F_GETFL, 0);
        if (flags < 0)
            err_sys("fcntl get failed");
        flags = fcntl(*sockfd, F_SETFL, flags | O_NONBLOCK);
        if (flags < 0)
            err_sys("fcntl set failed");
    #endif
}


#ifdef WOLFSSL_NUCLEUS
    #define WFD_SET_TYPE FD_SET
    #define WFD_SET NU_FD_Set
    #define WFD_ZERO NU_FD_Init
    #define WFD_ISSET NU_FD_Check
#else
    #define WFD_SET_TYPE fd_set
    #define WFD_SET FD_SET
    #define WFD_ZERO FD_ZERO
    #define WFD_ISSET FD_ISSET
#endif

/* returns 1 or greater when something is ready to be read */
static INLINE int wSelect(int nfds, WFD_SET_TYPE* recvfds,
        WFD_SET_TYPE *writefds, WFD_SET_TYPE *errfds,  struct timeval* timeout)
{
#ifdef WOLFSSL_NUCLEUS
    int ret = NU_Select (nfds, recvfds,  writefds, errfds,
            (UNSIGNED)timeout->tv_sec);
    if (ret == NU_SUCCESS) {
        return 1;
    }
    return 0;
#else
    return select(nfds, recvfds, writefds, errfds, timeout);
#endif
}

static INLINE int tcp_select(SOCKET_T socketfd, int to_sec)
{
    WFD_SET_TYPE recvfds, errfds;
    int nfds = (int)socketfd + 1;
    struct timeval timeout = {(to_sec > 0) ? to_sec : 0, 100};
    int result;

    WFD_ZERO(&recvfds);
    WFD_SET(socketfd, &recvfds);
    WFD_ZERO(&errfds);
    WFD_SET(socketfd, &errfds);

    result = wSelect(nfds, &recvfds, NULL, &errfds, &timeout);

    if (result == 0)
        return WS_SELECT_TIMEOUT;
    else if (result > 0) {
        if (WFD_ISSET(socketfd, &recvfds))
            return WS_SELECT_RECV_READY;
        else if(WFD_ISSET(socketfd, &errfds))
            return WS_SELECT_ERROR_READY;
    }

    return WS_SELECT_FAIL;
}

#endif /* WOLFSSH_TEST_SERVER || WOLFSSH_TEST_CLIENT */


/* Wolf Root Directory Helper */
/* KEIL-RL File System does not support relative directory */
#if !defined(WOLFSSL_MDK_ARM) && !defined(WOLFSSL_KEIL_FS) && !defined(WOLFSSL_TIRTOS) \
    && !defined(WOLFSSL_NUCLEUS)
    /* Maximum depth to search for WolfSSL root */
    #define MAX_WOLF_ROOT_DEPTH 5

    static INLINE int ChangeToWolfSshRoot(void)
    {
        #if !defined(NO_FILESYSTEM) && !defined(NO_WOLFSSL_DIR)
            int depth, res;
            WFILE* file;
            for(depth = 0; depth <= MAX_WOLF_ROOT_DEPTH; depth++) {
                if (WFOPEN(NULL, &file, serverKeyRsaPemFile, "rb") == 0) {
                    WFCLOSE(NULL, file);
                    return depth;
                }
            #ifdef USE_WINDOWS_API
                res = SetCurrentDirectoryA("..\\");
            #else
                res = chdir("../");
            #endif
                if (res < 0) {
                    printf("chdir to ../ failed!\n");
                    break;
                }
            }

            err_sys("wolfSSH root not found");
            return -1;
        #else
            return 0;
        #endif
    }
#endif /* !defined(WOLFSSL_MDK_ARM) && !defined(WOLFSSL_KEIL_FS) && !defined(WOL
FSSL_TIRTOS) */


typedef struct tcp_ready {
    word16 ready;     /* predicate */
    word16 port;
    char* srfName;     /* server ready file name */
#if defined(_POSIX_THREADS) && !defined(__MINGW32__)
    pthread_mutex_t mutex;
    pthread_cond_t  cond;
#endif
} tcp_ready;


#ifdef WOLFSSH_SFTP
typedef int (*WS_CallbackSftpCommand)(const char* in, char* out, int outSz);
#endif

typedef struct func_args {
    int    argc;
    char** argv;
    int    return_code;
    tcp_ready* signal;
    WS_CallbackUserAuth user_auth;
#ifdef WOLFSSH_SFTP
    /* callback for example sftp client commands instead of WFGETS */
    WS_CallbackSftpCommand sftp_cb;
#endif
} func_args;


#ifdef WOLFSSH_TEST_LOCKING

static INLINE void InitTcpReady(tcp_ready* ready)
{
    ready->ready = 0;
    ready->port = 0;
    ready->srfName = NULL;
#if defined(_POSIX_THREADS) && defined(NO_MAIN_DRIVER) && \
    !defined(__MINGW32__) && !defined(SINGLE_THREADED)
    pthread_mutex_init(&ready->mutex, NULL);
    pthread_cond_init(&ready->cond, NULL);
#endif
}


static INLINE void FreeTcpReady(tcp_ready* ready)
{
#if defined(_POSIX_THREADS) && defined(NO_MAIN_DRIVER) && \
    !defined(__MINGW32__) && !defined(SINGLE_THREADED)
    pthread_mutex_destroy(&ready->mutex);
    pthread_cond_destroy(&ready->cond);
#else
    WOLFSSH_UNUSED(ready);
#endif
}


static INLINE void WaitTcpReady(tcp_ready* ready)
{
#if defined(_POSIX_THREADS) && defined(NO_MAIN_DRIVER) && \
    !defined(__MINGW32__) && !defined(SINGLE_THREADED)
    pthread_mutex_lock(&ready->mutex);

    while (!ready->ready) {
        pthread_cond_wait(&ready->cond, &ready->mutex);
    }

    pthread_mutex_unlock(&ready->mutex);
#ifdef WOLFSSH_ZEPHYR
    /* It's like the server isn't ready to accept connections it is
     * listening for despite this conditional variable. A 300ms wait
     * seems to help. This is not ideal. (XXX) */
    k_sleep(Z_TIMEOUT_TICKS(300));
#endif /* WOLFSSH_ZEPHYR */
#else
    WOLFSSH_UNUSED(ready);
#endif
}


#endif /* WOLFSSH_TEST_LOCKING */


#include <wolfssl/version.h>

/*
 * Somewhere before the release of wolfSSL v5.5.1, these threading
 * wrappers and types were moved from wolfssl/test.h to
 * wolfssl/wolfcrypt/types.h and are now present in the wolfSSH build.
 * This is good, because it keeps the compatibility code in wolfCrypt.
 * The tag WOLFSSL_THREAD is defined as a part of this compatibility, and
 * will also be checked for. Note that the following types and defines are
 * used by the examples to define themselves for use as threads by the test
 * tools, but they themselves do not use threading. Before v5.6.4, a new
 * macro for return from threads was added.
 */
#define WOLFSSL_V5_5_2 0x05005002
#define WOLFSSL_V5_6_4 0x05006004

#if (LIBWOLFSSL_VERSION_HEX < WOLFSSL_V5_5_2) && !defined(WOLFSSL_THREAD)
    #define WOLFSSH_OLDER_THREADING
    #ifdef SINGLE_THREADED
        typedef unsigned int  THREAD_RETURN;
        typedef void*         THREAD_TYPE;
        #define WOLFSSH_THREAD
    #else
        #if defined(_POSIX_THREADS) && !defined(__MINGW32__)
            typedef void*         THREAD_RETURN;
            typedef pthread_t     THREAD_TYPE;
            #define WOLFSSH_THREAD
            #define WAIT_OBJECT_0 0L
        #elif defined(WOLFSSL_NUCLEUS) || defined(FREESCALE_MQX)
            typedef unsigned int  THREAD_RETURN;
            typedef intptr_t      THREAD_TYPE;
            #define WOLFSSH_THREAD
        #else
            typedef unsigned int  THREAD_RETURN;
            typedef intptr_t      THREAD_TYPE;
            #define WOLFSSH_THREAD __stdcall
        #endif
    #endif
#else
    #ifndef WOLFSSH_THREAD
        #define WOLFSSH_THREAD WOLFSSL_THREAD
    #endif
#endif

#if (LIBWOLFSSL_VERSION_HEX < WOLFSSL_V5_6_4) \
        && !defined(WOLFSSL_RETURN_FROM_THREAD)
    #define WOLFSSL_RETURN_FROM_THREAD(x) return (THREAD_RETURN)(x)
    #define WOLFSSH_OLD_THREADING
#endif


#ifdef WOLFSSH_TEST_THREADING


#if !defined(WOLFSSH_OLD_THREADING) && !defined(WOLFSSH_OLDER_THREADING)

static INLINE void ThreadStart(THREAD_CB fun, void* args, THREAD_TYPE* thread)
{
    (void)wolfSSL_NewThread(thread, fun, args);
}

static INLINE void ThreadJoin(THREAD_TYPE thread)
{
    (void)wolfSSL_JoinThread(thread);
}

#ifdef WOLFSSL_THREAD_NO_JOIN
static INLINE void ThreadStartNoJoin(THREAD_CB fun, void* args)
{
    (void)wolfSSL_NewThreadNoJoin(fun, args);
}
#endif

#else
typedef THREAD_RETURN (WOLFSSH_THREAD *THREAD_FUNC)(void*);


static INLINE void ThreadStart(THREAD_FUNC fun, void* args, THREAD_TYPE* thread)
{
#ifdef SINGLE_THREADED
    (void)fun;
    (void)args;
    (void)thread;
#elif defined(_POSIX_THREADS) && !defined(__MINGW32__)
    #ifdef WOLFSSL_VXWORKS
    {
        pthread_attr_t myattr;
        pthread_attr_init(&myattr);
        pthread_attr_setstacksize(&myattr, 0x10000);
        pthread_create(thread, &myattr, fun, args);
    }
    #else
        pthread_create(thread, 0, fun, args);
    #endif
#elif defined(WOLFSSL_TIRTOS)
    {
        /* Initialize the defaults and set the parameters. */
        Task_Params taskParams;
        Task_Params_init(&taskParams);
        taskParams.arg0 = (UArg)args;
        taskParams.stackSize = 65535;
        *thread = Task_create((Task_FuncPtr)fun, &taskParams, NULL);
        if (*thread == NULL) {
            printf("Failed to create new Task\n");
        }
        Task_yield();
    }
#elif defined(USE_WINDOWS_API)
    *thread = (THREAD_TYPE)_beginthreadex(0, 0, fun, args, 0, 0);
#else
    (void)fun;
    (void)args;
    (void)thread;
#endif
}


static INLINE void ThreadJoin(THREAD_TYPE thread)
{
#ifdef SINGLE_THREADED
    (void)thread;
#elif defined(_POSIX_THREADS) && !defined(__MINGW32__)
    pthread_join(thread, 0);
#elif defined(WOLFSSL_TIRTOS)
    while(1) {
        if (Task_getMode(thread) == Task_Mode_TERMINATED) {
            Task_sleep(5);
            break;
        }
        Task_yield();
    }
#elif defined(USE_WINDOWS_API)
    {
        int res = WaitForSingleObject((HANDLE)thread, INFINITE);
        assert(res == WAIT_OBJECT_0);
        res = CloseHandle((HANDLE)thread);
        assert(res);
        (void)res; /* Suppress un-used variable warning */
    }
#else
    (void)thread;
#endif
}


static INLINE void ThreadDetach(THREAD_TYPE thread)
{
#ifdef SINGLE_THREADED
    (void)thread;
#elif defined(_POSIX_THREADS) && !defined(__MINGW32__)
    pthread_detach(thread);
#elif defined(WOLFSSL_TIRTOS)
#if 0
    while(1) {
        if (Task_getMode(thread) == Task_Mode_TERMINATED) {
            Task_sleep(5);
            break;
        }
        Task_yield();
    }
#endif
#elif defined(USE_WINDOWS_API)
    {
        int res = CloseHandle((HANDLE)thread);
        assert(res);
        (void)res; /* Suppress un-used variable warning */
    }
#else
    (void)thread;
#endif
}

static INLINE void ThreadStartNoJoin(THREAD_FUNC fun, void* args)
{
    THREAD_TYPE thread;
    ThreadStart(fun, args, &thread);
    ThreadDetach(thread);
}

#endif /* !WOLFSSH_OLD_THREADING && !WOLFSSH_OLDER_THREADING */

#endif /* WOLFSSH_TEST_THREADING */

#ifdef TEST_IPV6
static INLINE void build_addr_ipv6(struct sockaddr_in6* addr, const char* peer,
                              word16 port)
{
    memset(addr, 0, sizeof(struct sockaddr_in6));

    addr->sin6_family = AF_INET6;
    addr->sin6_port = htons(port);
    if ((size_t)peer == INADDR_ANY)
        addr->sin6_addr = in6addr_any;
    else {
        struct addrinfo  hints;
        struct addrinfo* answer = NULL;
        int    ret;
        char   strPort[80];

        memset(&hints, 0, sizeof(hints));
        hints.ai_family   = AF_INET6;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;

        WSNPRINTF(strPort, sizeof(strPort), "%d", port);
        strPort[79] = '\0';

        ret = getaddrinfo(peer, strPort, &hints, &answer);
        if (ret < 0 || answer == NULL)
            err_sys("getaddrinfo failed");

        memcpy(addr, answer->ai_addr, answer->ai_addrlen);
        freeaddrinfo(answer);
    }
}
#endif /* TEST_IPV6 */


#ifdef WOLFSSH_TEST_HEX2BIN

#define BAD 0xFF

static const byte hexDecode[] =
{
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
    BAD, BAD, BAD, BAD, BAD, BAD, BAD,
    10, 11, 12, 13, 14, 15,  /* upper case A-F */
    BAD, BAD, BAD, BAD, BAD, BAD, BAD, BAD,
    BAD, BAD, BAD, BAD, BAD, BAD, BAD, BAD,
    BAD, BAD, BAD, BAD, BAD, BAD, BAD, BAD,
    BAD, BAD,  /* G - ` */
    10, 11, 12, 13, 14, 15   /* lower case a-f */
};  /* A starts at 0x41 not 0x3A */


static int Base16_Decode(const byte* in, word32 inLen,
                         byte* out, word32* outLen)
{
    word32 inIdx = 0;
    word32 outIdx = 0;

    if (in == NULL || out == NULL || outLen == NULL)
        return WS_BAD_ARGUMENT;

    if (inLen == 1 && *outLen && in) {
        byte b = in[inIdx] - 0x30;  /* 0 starts at 0x30 */

        /* sanity check */
        if (b >=  sizeof(hexDecode)/sizeof(hexDecode[0]))
            return -1;

        b  = hexDecode[b];

        if (b == BAD)
            return -1;

        out[outIdx++] = b;

        *outLen = outIdx;
        return 0;
    }

    if (inLen % 2)
        return -1;

    if (*outLen < (inLen / 2))
        return -1;

    while (inLen) {
        byte b = in[inIdx++] - 0x30;  /* 0 starts at 0x30 */
        byte b2 = in[inIdx++] - 0x30;

        /* sanity checks */
        if (b >=  sizeof(hexDecode)/sizeof(hexDecode[0]))
            return -1;
        if (b2 >= sizeof(hexDecode)/sizeof(hexDecode[0]))
            return -1;

        b  = hexDecode[b];
        b2 = hexDecode[b2];

        if (b == BAD || b2 == BAD)
            return -1;

        out[outIdx++] = (byte)((b << 4) | b2);
        inLen -= 2;
    }

    *outLen = outIdx;
    return 0;
}


static void FreeBins(byte* b1, byte* b2, byte* b3, byte* b4)
{
    if (b1 != NULL) free(b1);
    if (b2 != NULL) free(b2);
    if (b3 != NULL) free(b3);
    if (b4 != NULL) free(b4);
}


/* convert hex string to binary, store size, 0 success (free mem on failure) */
static int ConvertHexToBin(const char* h1, byte** b1, word32* b1Sz,
                           const char* h2, byte** b2, word32* b2Sz,
                           const char* h3, byte** b3, word32* b3Sz,
                           const char* h4, byte** b4, word32* b4Sz)
{
    int ret;

    /* b1 */
    if (h1 && b1 && b1Sz) {
        *b1Sz = (word32)strlen(h1) / 2;
        *b1 = (byte*)malloc(*b1Sz);
        if (*b1 == NULL)
            return -1;
        ret = Base16_Decode((const byte*)h1, (word32)strlen(h1),
                            *b1, b1Sz);
        if (ret != 0) {
            FreeBins(*b1, NULL, NULL, NULL);
            *b1 = NULL;
            return -1;
        }
    }

    /* b2 */
    if (h2 && b2 && b2Sz) {
        *b2Sz = (word32)strlen(h2) / 2;
        *b2 = (byte*)malloc(*b2Sz);
        if (*b2 == NULL) {
            FreeBins(b1 ? *b1 : NULL, NULL, NULL, NULL);
            if (b1) *b1 = NULL;
            return -1;
        }
        ret = Base16_Decode((const byte*)h2, (word32)strlen(h2),
                            *b2, b2Sz);
        if (ret != 0) {
            FreeBins(b1 ? *b1 : NULL, *b2, NULL, NULL);
            if (b1) *b1 = NULL;
            *b2 = NULL;
            return -1;
        }
    }

    /* b3 */
    if (h3 && b3 && b3Sz) {
        *b3Sz = (word32)strlen(h3) / 2;
        *b3 = (byte*)malloc(*b3Sz);
        if (*b3 == NULL) {
            FreeBins(b1 ? *b1 : NULL, b2 ? *b2 : NULL, NULL, NULL);
            if (b1) *b1 = NULL;
            if (b2) *b2 = NULL;
            return -1;
        }
        ret = Base16_Decode((const byte*)h3, (word32)strlen(h3),
                            *b3, b3Sz);
        if (ret != 0) {
            FreeBins(b1 ? *b1 : NULL, b2 ? *b2 : NULL, *b3, NULL);
            if (b1) *b1 = NULL;
            if (b2) *b2 = NULL;
            *b3 = NULL;
            return -1;
        }
    }

    /* b4 */
    if (h4 && b4 && b4Sz) {
        *b4Sz = (word32)strlen(h4) / 2;
        *b4 = (byte*)malloc(*b4Sz);
        if (*b4 == NULL) {
            FreeBins(b1 ? *b1 : NULL, b2 ? *b2 : NULL, b3 ? *b3 : NULL, NULL);
            if (b1) *b1 = NULL;
            if (b2) *b2 = NULL;
            if (b3) *b3 = NULL;
            return -1;
        }
        ret = Base16_Decode((const byte*)h4, (word32)strlen(h4),
                            *b4, b4Sz);
        if (ret != 0) {
            FreeBins(b1 ? *b1 : NULL, b2 ? *b2 : NULL, b3 ? *b3 : NULL, *b4);
            if (b1) *b1 = NULL;
            if (b2) *b2 = NULL;
            if (b3) *b3 = NULL;
            *b4 = NULL;
            return -1;
        }
    }

    return 0;
}

#endif /* WOLFSSH_TEST_HEX2BIN */

#endif /* _WOLFSSH_TEST_H_ */

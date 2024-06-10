/* scpclient.c
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

#include <stdio.h>
#if !defined(USE_WINDOWS_API) && !defined(MICROCHIP_PIC32) && \
    !defined(WOLFSSH_ZEPHYR)
    #include <termios.h>
#endif
#include <wolfssh/ssh.h>
#include <wolfssh/internal.h>
#include <wolfssh/wolfscp.h>
#include <wolfssh/test.h>
#include <wolfssh/port.h>

#ifndef NO_WOLFSSH_CLIENT
#if !defined(WOLFSSH_NO_ECC) && defined(FP_ECC) && defined(HAVE_THREAD_LS)
    #include <wolfssl/wolfcrypt/ecc.h>
#endif
#include "examples/scpclient/scpclient.h"
#include "examples/client/common.h"

#define USAGE_WIDE "12"
static void ShowUsage(void)
{
    printf("wolfscp %s\n", LIBWOLFSSH_VERSION_STRING);
    printf(" -%c %-" USAGE_WIDE "s %s\n", 'h', "",
            "display this help and exit");
    printf(" -%c %-" USAGE_WIDE "s %s, default %s\n", 'H', "<host>",
            "host to connect to", wolfSshIp);
    printf(" -%c %-" USAGE_WIDE "s %s, default %u\n", 'p', "<num>",
            "port to connect on", wolfSshPort);
    printf(" -%c %-" USAGE_WIDE "s %s\n", 'u', "<username>",
            "username to authenticate as (REQUIRED)");
    printf(" -%c %-" USAGE_WIDE "s %s\n", 'P', "<password>",
            "password for username, prompted if omitted");
    printf(" -%c %-" USAGE_WIDE "s %s\n", 'L', "<from>:<to>",
            "copy from local to server");
    printf(" -%c %-" USAGE_WIDE "s %s\n", 'S', "<from>:<to>",
            "copy from server to local");
    printf(" -%c %-" USAGE_WIDE "s %s\n", 'i', "<filename>",
            "filename for the user's private key");
    printf(" -%c %-" USAGE_WIDE "s %s\n", 'j', "<filename>",
            "filename for the user's public key");
#ifdef WOLFSSH_CERTS
    printf(" -%c %-" USAGE_WIDE "s %s\n", 'J', "<filename>",
            "filename for DER certificate to use");
    printf("     %-" USAGE_WIDE "s %s\n", "",
            "Certificate example : client -u orange ");
    printf("     %-" USAGE_WIDE "s %s\n", "",
            "-J orange-cert.der -i orange-key.der");
    printf(" -%c %-" USAGE_WIDE "s %s\n", 'A', "<filename>",
            "filename for DER CA certificate to verify host");
    printf(" -%c %-" USAGE_WIDE "s %s\n", 'X', "",
            "Ignore IP checks on peer vs peer certificate");
#endif
}


enum copyDir {copyNone, copyToSrv, copyFromSrv};


THREAD_RETURN WOLFSSH_THREAD scp_client(void* args)
{
    WOLFSSH_CTX* ctx = NULL;
    WOLFSSH* ssh = NULL;
    SOCKET_T sockFd = WOLFSSH_SOCKET_INVALID;
    SOCKADDR_IN_T clientAddr;
    socklen_t clientAddrSz = sizeof(clientAddr);
#ifdef TEST_IPV6
    struct sockaddr_in6 clientAddr6;
    socklen_t clientAddrSz6 = sizeof(clientAddr6);
#endif
    int argc = ((func_args*)args)->argc;
    int ret = 0;
    char** argv = ((func_args*)args)->argv;
    const char* username = NULL;
    const char* password = NULL;
    char* host = (char*)wolfSshIp;
    char* path1 = NULL;
    char* path2 = NULL;
    word16 port = wolfSshPort;
    byte nonBlock = 0;
    enum copyDir dir = copyNone;
    int ch;
    char* pubKeyName = NULL;
    char* privKeyName = NULL;
    char* certName = NULL;
    char* caCert   = NULL;

    ((func_args*)args)->return_code = 0;

    while ((ch = mygetopt(argc, argv, "H:L:NP:S:hp:u:XJ:A:i:j:")) != -1) {
        switch (ch) {
            case 'H':
                host = myoptarg;
                break;

            case 'L':
                dir = copyToSrv;
                path1 = myoptarg;
                break;

            case 'N':
                nonBlock = 1;
                break;

            case 'P':
                password = myoptarg;
                break;

            case 'S':
                dir = copyFromSrv;
                path1 = myoptarg;
                break;

            case 'h':
                ShowUsage();
                exit(EXIT_SUCCESS);

            case 'u':
                username = myoptarg;
                break;

            case 'p':
                if (myoptarg == NULL)
                    err_sys("null argument found");

                port = (word16)atoi(myoptarg);
                #if !defined(NO_MAIN_DRIVER) || defined(USE_WINDOWS_API)
                    if (port == 0)
                        err_sys("port number cannot be 0");
                #endif
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

            default:
                ShowUsage();
                exit(MY_EX_USAGE);
                break;
        }
    }

    myoptind = 0;      /* reset for test cases */

    if (username == NULL)
        err_sys("client requires a username parameter.");

    if (dir == copyNone)
        err_sys("didn't specify a copy direction");

    /* split file path */
    if (path1 == NULL) {
        err_sys("Missing path value");
    }

    path2 = strchr(path1, ':');
    if (path2 == NULL) {
        err_sys("Missing colon separator");
    }

    *path2 = 0;
    path2++;

    if (strlen(path1) == 0 || strlen(path2) == 0) {
        err_sys("Empty path values");
    }

    ret = ClientSetPrivateKey(privKeyName, 0, NULL);
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
    {
        ret = ClientUsePubKey(pubKeyName, 0, NULL);
    }
    if (ret != 0) {
        err_sys("Error setting public key");
    }

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_CLIENT, NULL);
    if (ctx == NULL)
        err_sys("Couldn't create wolfSSH client context.");

    if (((func_args*)args)->user_auth == NULL)
        wolfSSH_SetUserAuth(ctx, ClientUserAuth);
    else
        wolfSSH_SetUserAuth(ctx, ((func_args*)args)->user_auth);

#ifdef WOLFSSH_CERTS
    ClientLoadCA(ctx, caCert);
#else
    (void)caCert;
    (void)certName;
#endif /* WOLFSSH_CERTS */

    wolfSSH_CTX_SetPublicKeyCheck(ctx, ClientPublicKeyCheck);

    ssh = wolfSSH_new(ctx);
    if (ssh == NULL)
        err_sys("Couldn't create wolfSSH session.");

    wolfSSH_SetPublicKeyCheckCtx(ssh, (void*)host);

    if (password != NULL)
        wolfSSH_SetUserAuthCtx(ssh, (void*)password);

    ret = wolfSSH_SetUsername(ssh, username);
    if (ret != WS_SUCCESS)
        err_sys("Couldn't set the username.");

#ifdef TEST_IPV6
    /* If it is an IPV6 address */
    if (WSTRCHR(host, ':')) {
        printf("IPV6 address\n");
        build_addr_ipv6(&clientAddr6, host, port);
        sockFd = socket(AF_INET6, SOCK_STREAM, 0);
        ret = connect(sockFd, (const struct sockaddr *)&clientAddr6, clientAddrSz6);
    }
    else
#endif
    {
        printf("IPV4 address\n");
        build_addr(&clientAddr, host, port);
        tcp_socket(&sockFd, ((struct sockaddr_in *)&clientAddr)->sin_family);
        ret = connect(sockFd, (const struct sockaddr *)&clientAddr,
                      clientAddrSz);
    }

    if (ret != 0)
        err_sys("Couldn't connect to server.");

    if (nonBlock)
        tcp_set_nonblocking(&sockFd);

    ret = wolfSSH_set_fd(ssh, (int)sockFd);
    if (ret != WS_SUCCESS)
        err_sys("Couldn't set the session's socket.");

    if (ret != WS_SUCCESS)
        err_sys("Couldn't set the channel type.");

    do {
        if (dir == copyFromSrv)
            ret = wolfSSH_SCP_from(ssh, path1, path2);
        else if (dir == copyToSrv)
            ret = wolfSSH_SCP_to(ssh, path1, path2);
        if (ret != WS_SUCCESS && ret == WS_FATAL_ERROR) {
            ret = wolfSSH_get_error(ssh);
        }
    } while (ret == WS_WANT_READ || ret == WS_WANT_WRITE ||
                    ret == WS_CHAN_RXD || ret == WS_REKEYING);
    if (ret != WS_SUCCESS)
        err_sys("Couldn't copy the file.");

    ret = wolfSSH_shutdown(ssh);
    /* do not continue on with shutdown process if peer already disconnected */
    if (ret != WS_CHANNEL_CLOSED && ret != WS_SOCKET_ERROR_E &&
            wolfSSH_get_error(ssh) != WS_SOCKET_ERROR_E &&
            wolfSSH_get_error(ssh) != WS_CHANNEL_CLOSED) {
        if (ret != WS_SUCCESS) {
            err_sys("Sending the shutdown messages failed.");
        }
        ret = wolfSSH_worker(ssh, NULL);
        if (ret != WS_SUCCESS && ret != WS_CHANNEL_CLOSED) {
            err_sys("Failed to listen for close messages from the peer.");
        }
    }
    WCLOSESOCKET(sockFd);
    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);
    if (ret != WS_SUCCESS && ret != WS_SOCKET_ERROR_E &&
            ret != WS_CHANNEL_CLOSED) {
        err_sys("Closing scp stream failed. Connection could have been closed by peer");
    }

    ClientFreeBuffers(pubKeyName, privKeyName, NULL);
#if !defined(WOLFSSH_NO_ECC) && defined(FP_ECC) && defined(HAVE_THREAD_LS)
    wc_ecc_fp_free();  /* free per thread cache */
#endif

    return 0;
}


#ifndef NO_MAIN_DRIVER

int main(int argc, char* argv[])
{
    func_args args;

    args.argc = argc;
    args.argv = argv;
    args.return_code = 0;
    args.user_auth = NULL;

    #ifdef DEBUG_WOLFSSH
        wolfSSH_Debugging_ON();
    #endif

    wolfSSH_Init();

    scp_client(&args);

    wolfSSH_Cleanup();

    return args.return_code;
}


int myoptind = 0;
char* myoptarg = NULL;

#endif /* NO_MAIN_DRIVER */
#else
int main()
{
    printf("wolfSSH built with NO_WOLFSSH_CLIENT\n");
    printf("SCP client unavailable\n");
    return -1;
}
#endif /* NO_WOLFSSH_CLIENT */


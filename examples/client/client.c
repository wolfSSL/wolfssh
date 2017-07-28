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


#include <wolfssh/ssh.h>
#include <wolfssh/test.h>
#include "examples/client/client.h"


const char testString[] = "Hello, wolfSSH!";
int gHasTty = 0; /* Allows client to pretend to be interactive or not. */


static void ShowUsage(void)
{
    printf("client %s\n", LIBWOLFSSH_VERSION_STRING);
    printf(" -?            display this help and exit\n");
    printf(" -h <host>     host to connect to, default %s\n", wolfSshIp);
    printf(" -p <num>      port to connect on, default %d\n", wolfSshPort);
    printf(" -u <username> username to authenticate as, default \"nobody\"\n");
    printf(" -P <password> password for username, default \"password\"\n");
    printf(" -B            disable banner display\n");
}


THREAD_RETURN WOLFSSH_THREAD client_test(void* args)
{
    WOLFSSH_CTX* ctx = NULL;
    WOLFSSH* ssh = NULL;
    SOCKET_T sockFd = WOLFSSH_SOCKET_INVALID;
    SOCKADDR_IN_T clientAddr;
    socklen_t clientAddrSz = sizeof(clientAddr);
    char rxBuf[80];
    int ret;
    char ch;
    uint16_t port = wolfSshPort;
    char* host = (char*)wolfSshIp;
    const char* username = "nobody";
    const char* password = "password";
    int displayBanner = 1;

    int     argc = ((func_args*)args)->argc;
    char**  argv = ((func_args*)args)->argv;
    ((func_args*)args)->return_code = 0;

    while ((ch = mygetopt(argc, argv, "?h:p:u:BP:")) != -1) {
        switch (ch) {
            case 'h':
                host = myoptarg;
                break;

            case 'p':
                port = (uint16_t)atoi(myoptarg);
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

            case 'B':
                displayBanner = 0;
                break;

            case '?':
                ShowUsage();
                exit(EXIT_SUCCESS);

            default:
                ShowUsage();
                exit(MY_EX_USAGE);
        }
    }
    myoptind = 0;      /* reset for test cases */

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_CLIENT, NULL);
    if (ctx == NULL)
        err_sys("Couldn't create wolfSSH client context.");

    ssh = wolfSSH_new(ctx);
    if (ssh == NULL)
        err_sys("Couldn't create wolfSSH session.");

    build_addr(&clientAddr, host, port);
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


#ifndef NO_MAIN_DRIVER

    int main(int argc, char** argv)
    {
        func_args args;

        args.argc = argc;
        args.argv = argv;
        args.return_code = 0;

        StartTCP();
        gHasTty = isatty(fileno(stdin));

        #ifdef DEBUG_WOLFSSH
            wolfSSH_Debugging_ON();
        #endif

        wolfSSH_Init();

        ChangeToWolfSshRoot();
        #ifndef NO_WOLFSSH_CLIENT
            client_test(&args);
        #endif /* NO_WOLFSSH_CLIENT */

        wolfSSH_Cleanup();

        return args.return_code;
    }

    int myoptind = 0;
    char* myoptarg = NULL;

#endif /* NO_MAIN_DRIVER */

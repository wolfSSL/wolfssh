/* sftp.c
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

#include <stdio.h>
#ifdef WOLFSSL_USER_SETTINGS
    #include <wolfssl/wolfcrypt/settings.h>
#else
    #include <wolfssl/options.h>
#endif
#include <wolfssh/settings.h>

#if defined(WOLFSSH_SFTP) && !defined(SINGLE_THREADED)

#include <wolfssh/ssh.h>
#include <wolfssh/wolfsftp.h>

#define WOLFSSH_TEST_LOCKING
#define WOLFSSH_TEST_THREADING
#include <wolfssh/test.h>

#include "tests/sftp.h"
#include "examples/echoserver/echoserver.h"
#include "examples/sftpclient/sftpclient.h"

static const char* cmds[] = {
    "mkdir a",
    "cd a",
    "pwd",
    "ls",
#ifdef WOLFSSH_ZEPHYR
    "put " CONFIG_WOLFSSH_SFTP_DEFAULT_DIR "/configure.ac",
#else
    "put configure.ac",
#endif
    "ls",
#ifdef WOLFSSH_ZEPHYR
    "get configure.ac " CONFIG_WOLFSSH_SFTP_DEFAULT_DIR "/test-get",
#else
    "get configure.ac test-get",
#endif
    "rm configure.ac",
    "cd ../",
    "ls",
    "rename test-get test-get-2",
    "rmdir a",
    "ls",
    "chmod 600 test-get-2",
    "rm test-get-2",
    "ls -s",
    "exit"
};
static int commandIdx = 0;
static char inBuf[1024] = {0};

/* return 0 on success */
static int Expected(int command)
{
    int i;

    switch (command) {
        case 3: /* pwd */
            /* working directory should not contain a '.' at the end */
            for (i = 0; i < (int)sizeof(inBuf); i++) {
                if (inBuf[i] == '\n') {
                    inBuf[i] = '\0';
                    break;
                }
            }

            if (inBuf[WSTRLEN(inBuf) - 2] != '/') {
                printf("unexpected pwd of %s\n looking for '/'\n", inBuf);
                return -1;
            }
            if (inBuf[WSTRLEN(inBuf) - 1] != 'a') {
                printf("unexpected pwd of %s\n looking for 'a'\n", inBuf);
                return -1;
            }
            break;

        case 4:
            {
#ifdef WOLFSSH_ZEPHYR
                /* No . and .. in zephyr fs API */
                char expt1[] = "wolfSSH sftp> ";
                char expt2[] = "wolfSSH sftp> ";
#else
                char expt1[] = ".\n..\nwolfSSH sftp> ";
                char expt2[] = "..\n.\nwolfSSH sftp> ";
#endif
                if (WMEMCMP(expt1, inBuf, sizeof(expt1)) != 0 &&
                    WMEMCMP(expt2, inBuf, sizeof(expt2)) != 0) {
                    printf("unexpected ls\n");
                    printf("\texpected \n%s\n\tor\n%s\n\tbut got\n%s\n", expt1,
                            expt2, inBuf);
                    return -1;
                }
                else
                    return 0;

            }

        case 6:
            if (WSTRNSTR(inBuf, "configure.ac", sizeof(inBuf)) == NULL) {
                fprintf(stderr, "configure.ac not found in %s\n", inBuf);
                return 1;
            }
            else {
                return 0;
            }

        case 10:
            return (WSTRNSTR(inBuf, "test-get", sizeof(inBuf)) == NULL);

        case 13:
            return (WSTRNSTR(inBuf, "test-get-2", sizeof(inBuf)) == NULL);

        case 16:
            return (WSTRNSTR(inBuf, "size in bytes", sizeof(inBuf)) == NULL);

        default:
            break;
    }
    WMEMSET(inBuf, 0, sizeof(inBuf));
    return 0;
}


static int commandCb(const char* in, char* out, int outSz)
{
    int ret = 0;

    if (in) {
        /* print out */
        WSTRNCAT(inBuf, in, sizeof(inBuf));
    }

    /* get command input */
    if (out) {
        int sz = (int)WSTRLEN(cmds[commandIdx]);
        if (outSz < sz) {
            ret = -1;
        }
        else {
            WMEMCPY(out, cmds[commandIdx], sz);
        }

        if (Expected(commandIdx) != 0) {
            fprintf(stderr, "Failed on command index %d\n", commandIdx);
            exit(1); /* abort out */
        }
        commandIdx++;
    }
    return ret;
}


/* test SFTP commands, if flag is set to 1 then use non blocking
 * return 0 on success */
int wolfSSH_SftpTest(int flag)
{
    func_args ser;
    func_args cli;
    tcp_ready ready;
    int ret = 0;
    int argsCount;

    const char* args[10];
#ifndef USE_WINDOWS_API
    char  portNumber[8];
#endif

    THREAD_TYPE serThread;

    wolfSSH_Init();

    WMEMSET(&ser, 0, sizeof(func_args));
    WMEMSET(&cli, 0, sizeof(func_args));
    commandIdx = 0;

    wolfSSH_Debugging_ON();

    argsCount = 0;
    args[argsCount++] = ".";
    args[argsCount++] = "-1";
#ifndef USE_WINDOWS_API
    args[argsCount++] = "-p";
    args[argsCount++] = "0";
#endif
    if (flag)
        args[argsCount++] = "-N";

    ser.argv   = (char**)args;
    ser.argc    = argsCount;
    ser.signal = &ready;
    InitTcpReady(ser.signal);
    ThreadStart(echoserver_test, (void*)&ser, &serThread);
    WaitTcpReady(&ready);

    argsCount = 0;
    args[argsCount++] = ".";
    args[argsCount++] = "-u";
    args[argsCount++] = "jill";
    args[argsCount++] = "-P";
    args[argsCount++] = "upthehill";

#ifndef USE_WINDOWS_API
    /* use port that server has found */
    args[argsCount++] = "-p";
    snprintf(portNumber, sizeof(portNumber), "%d", ready.port);
    args[argsCount++] = portNumber;
#endif

    if (flag)
        args[argsCount++] = "-N";

    cli.argv    = (char**)args;
    cli.argc    = argsCount;
    cli.signal  = &ready;
    cli.sftp_cb = commandCb;
    sftpclient_test(&cli);

#ifdef WOLFSSH_ZEPHYR
    /* Weird deadlock without this sleep */
    k_sleep(Z_TIMEOUT_TICKS(100));
#endif

    ThreadJoin(serThread);
    wolfSSH_Cleanup();
    FreeTcpReady(&ready);

    return ret;
}
#endif /* WOLFSSH_SFTP */



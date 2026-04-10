/* sftp.c
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

/*
 * Each test command is paired with an optional check function that
 * validates the output it produces. This eliminates the fragile
 * index-based coupling between the command array and the validator.
 */
typedef int (*SftpTestCheck)(void);

typedef struct {
    const char* cmd;
    SftpTestCheck check; /* validates output from THIS cmd, or NULL */
} SftpTestCmd;

/* Test buffer */
static char inBuf[1024] = {0};

/* check that pwd output ends in /a */
static int checkPwdInA(void)
{
    int i;
    int len;

    for (i = 0; i < (int)sizeof(inBuf); i++) {
        if (inBuf[i] == '\n') {
            inBuf[i] = '\0';
            break;
        }
    }

    len = (int)WSTRLEN(inBuf);
    if (len < 2) {
        printf("pwd output too short: %s\n", inBuf);
        return -1;
    }
    if (inBuf[len - 2] != '/') {
        printf("unexpected pwd of %s, looking for '/'\n", inBuf);
        return -1;
    }
    if (inBuf[len - 1] != 'a') {
        printf("unexpected pwd of %s, looking for 'a'\n", inBuf);
        return -1;
    }
    return 0;
}

/* check that ls of empty dir shows only . and .. */
static int checkLsEmpty(void)
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
        printf("\texpected \n%s\n\tor\n%s\n\tbut got\n%s\n",
            expt1, expt2, inBuf);
        return -1;
    }
    return 0;
}

/* check that ls output contains a specific file */
static int checkLsHasConfigureAc(void)
{
    if (WSTRNSTR(inBuf, "configure.ac", sizeof(inBuf)) == NULL) {
        fprintf(stderr, "configure.ac not found in %s\n", inBuf);
        return 1;
    }
    return 0;
}

static int checkLsHasTestGet(void)
{
    return (WSTRNSTR(inBuf, "test-get",
                sizeof(inBuf)) == NULL) ? 1 : 0;
}

static int checkLsHasTestGet2(void)
{
    return (WSTRNSTR(inBuf, "test-get-2",
                sizeof(inBuf)) == NULL) ? 1 : 0;
}

static int checkLsSize(void)
{
    return (WSTRNSTR(inBuf, "size in bytes",
                sizeof(inBuf)) == NULL) ? 1 : 0;
}

static const SftpTestCmd cmds[] = {
    /* If a prior run was interrupted, files and directories
     * created during the test may still exist in the working
     * directory, causing mkdir to fail and ls checks to see
     * unexpected entries. Remove them here before starting.
     * These run as SFTP commands rather than local syscalls
     * so they are portable across all platforms (Windows,
     * Zephyr, POSIX). Failures are silently ignored since
     * the files may not exist. */
    { "rm a/configure.ac", NULL },
    { "rmdir a",        NULL },
    { "rm test-get",    NULL },
    { "rm test-get-2",  NULL },

    /* --- test sequence starts here --- */
    { "mkdir a",        NULL },
    { "cd a",           NULL },
    { "pwd",            checkPwdInA },
    { "ls",             checkLsEmpty },
#ifdef WOLFSSH_ZEPHYR
    { "put " CONFIG_WOLFSSH_SFTP_DEFAULT_DIR "/configure.ac", NULL },
#else
    { "put configure.ac", NULL },
#endif
    { "ls",             checkLsHasConfigureAc },
#ifdef WOLFSSH_ZEPHYR
    { "get configure.ac "
      CONFIG_WOLFSSH_SFTP_DEFAULT_DIR "/test-get", NULL },
#else
    { "get configure.ac test-get", NULL },
#endif
    { "rm configure.ac", NULL },
    { "cd ../",         NULL },
    { "ls",             checkLsHasTestGet },
    { "rename test-get test-get-2", NULL },
    { "rmdir a",        NULL },
    { "ls",             checkLsHasTestGet2 },
    { "chmod 600 test-get-2", NULL },
    { "rm test-get-2",  NULL },
    { "ls -s",          checkLsSize },
    /* empty arg tests: must not underflow on pt[sz-1] */
    { "mkdir",          NULL },
    { "cd",             NULL },
    { "ls",             NULL },
    { "chmod",          NULL },
    { "rmdir",          NULL },
    { "rm",             NULL },
    { "rename",         NULL },
    { "get",            NULL },
    { "put",            NULL },
    { "exit",           NULL },
};
static int commandIdx = 0;


static int commandCb(const char* in, char* out, int outSz)
{
    int ret = 0;

    if (in) {
        /* print out */
        WSTRNCAT(inBuf, in, sizeof(inBuf));
    }

    /* get command input */
    if (out) {
        int sz = (int)WSTRLEN(cmds[commandIdx].cmd);
        if (outSz < sz) {
            ret = -1;
        }
        else {
            WMEMCPY(out, cmds[commandIdx].cmd, sz);
        }

        /* validate output from the previous command */
        if (commandIdx > 0 &&
                cmds[commandIdx - 1].check != NULL) {
            if (cmds[commandIdx - 1].check() != 0) {
                fprintf(stderr,
                    "Check failed for \"%s\" (index %d)\n",
                    cmds[commandIdx - 1].cmd,
                    commandIdx - 1);
                exit(1);
            }
        }
        WMEMSET(inBuf, 0, sizeof(inBuf));
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



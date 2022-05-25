/* wolfsshd.c
 *
 * Copyright (C) 2014-2021 wolfSSL Inc.
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

#ifdef WOLFSSH_SSHD

#include <wolfssh/ssh.h>
#include <wolfssh/internal.h>
#include <wolfssh/test.h>
#include <wolfssh/log.h>
#include <wolfssl/wolfcrypt/wc_port.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#include "wolfsshd.h"

#include <signal.h>

#ifdef NO_INLINE
    #include <wolfssh/misc.h>
#else
    #define WOLFSSH_MISC_INCLUDED
    #include "src/misc.c"
#endif

/* catch interrupts and close down gracefully */
static volatile byte quit = 0;

static void ShowUsage(void)
{
    printf("wolfsshd %s\n", LIBWOLFSSH_VERSION_STRING);
    printf(" -?             display this help and exit\n");
    printf(" -f <file name> Configuration file to use, default is /usr/locacl/etc/ssh/sshd_config\n");
}

static void interruptCatch(int in)
{
    (void)in;
    printf("Closing down wolfSSHD\n");
    quit = 1;
}

int   myoptind = 0;
char* myoptarg = NULL;

int main(int argc, char** argv)
{
    int ret = WS_SUCCESS;
    int ch;
    WOLFSSHD_CONFIG* conf = NULL;

    const char* configFile = "/usr/local/etc/ssh/sshd_config";

    signal(SIGINT, interruptCatch);
    while ((ch = mygetopt(argc, argv, "?f:")) != -1) {
        switch (ch) {
            case 'f':
                configFile = myoptarg;
                break;

            case '?':
                ShowUsage();
                return WS_SUCCESS;

            default:
                ShowUsage();
                return WS_SUCCESS;
        }
    }

    if (ret == WS_SUCCESS) {
        wolfSSH_Init();
    }

    if (ret == WS_SUCCESS) {
        conf = wolfSSH_NewConfig(NULL);
        if (conf == NULL) {
            ret = WS_MEMORY_E;
        }
    }

    if (wolfSSH_LoadSSHD(conf, configFile) != WS_SUCCESS) {
        printf("Error reading in configure file %s\n", configFile);
    }

    printf("wolfSSH SSHD application\n");

    /* wait for incoming connections and fork them off */
    do {

    } while (ret == WS_SUCCESS && quit == 0);

    wolfSSH_FreeConfig(conf);
    wolfSSH_Cleanup();
    return 0;
}
#endif /* WOLFSSH_SSHD */

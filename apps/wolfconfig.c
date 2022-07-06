/* wolfconfig.c
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
/* functions for parsing out options from a config file and for handling loading
 * key/certs using the env. filesystem */

#include <wolfssh/ssh.h>
#include <wolfssh/internal.h>
#include <wolfssh/log.h>
#include <wolfssl/wolfcrypt/wc_port.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#ifdef NO_INLINE
    #include <wolfssh/misc.h>
#else
    #define WOLFSSH_MISC_INCLUDED
    #include "src/misc.c"
#endif

#include "wolfsshd.h"

struct WOLFSSHD_CONFIG {
    void* heap;
    char* banner;
    char* chrootDir;
    char* ciphers;
    char* hostKey;
    char* hostKeyAlgos;
    char* kekAlgos;
    char* listenAddress;
    char* authKeysFile;
    word16 port;
    byte usePrivilegeSeparation;
    byte passwordAuth:1;
    byte pubKeyAuth:1;
    byte permitRootLogin:1;
    byte permitEmptyPasswords:1;
};

/* returns WS_SUCCESS on success */
static int wolfSSHD_CreateString(char** out, const char* in, int inSz,
        void* heap)
{
    int ret = WS_SUCCESS;
    int idx = 0;

    /* remove white spaces */
    while (idx < inSz && in[idx] == ' ') idx++;

    if (idx == inSz) {
        ret = WS_BAD_ARGUMENT;
    }

    /* malloc new string and set it */
    if (ret == WS_SUCCESS) {
        *out = (char*)WMALLOC((inSz - idx) + 1, heap, DYNTYPE_SSHD);
        if (*out == NULL) {
            ret = WS_MEMORY_E;
        }
        else {
            XMEMCPY(*out, in + idx, inSz - idx);
            *(*out + (inSz - idx)) = '\0';
        }
    }

    return ret;
}

static void wolfSSHD_FreeString(char** in, void* heap)
{
    if (*in != NULL) {
        WFREE(*in, heap, DYNTYPE_SSHD);
        *in = NULL;
    }
    (void)heap;
}

WOLFSSHD_CONFIG* wolfSSHD_NewConfig(void* heap)
{
    WOLFSSHD_CONFIG* ret;

    ret = (WOLFSSHD_CONFIG*)WMALLOC(sizeof(WOLFSSHD_CONFIG), heap,
                DYNTYPE_SSHD);
    if (ret == NULL) {
        printf("issue mallocing config structure for sshd\n");
    }
    else {
        WMEMSET(ret, 0, sizeof(WOLFSSHD_CONFIG));

        /* default values */
        ret->port = 22;
    }
    return ret;

}

void wolfSSHD_FreeConfig(WOLFSSHD_CONFIG* conf)
{
    void* heap;

    if (conf != NULL) {
        heap = conf->heap;

        wolfSSHD_FreeString(&conf->authKeysFile, heap);

        WFREE(conf, heap, DYNTYPE_SSHD);
    }
}

#define MAX_LINE_SIZE 160

/* returns WS_SUCCESS on success
 * Fails if any option is found that is unknown/unsupported
 */
static int wolfSSHD_ParseConfigLine(WOLFSSHD_CONFIG* conf, const char* l,
        int lSz)
{
    int ret = WS_BAD_ARGUMENT;
    int sz;

    /* supported config options */
    const char authKeyFile[]         = "AuthorizedKeysFile";
    const char privilegeSeparation[] = "UsePrivilegeSeparation";

    sz = (int)XSTRLEN(authKeyFile);
    if (lSz > sz && XSTRNCMP(l, authKeyFile, sz) == 0) {
        ret = wolfSSHD_CreateString(&conf->authKeysFile, l + sz, lSz - sz,
                conf->heap);
    }

    sz = (int)XSTRLEN(privilegeSeparation);
    if (lSz > sz && XSTRNCMP(l, privilegeSeparation, sz) == 0) {
        char* privType = NULL;
        ret = wolfSSHD_CreateString(&privType, l + sz, lSz - sz, conf->heap);
        
        /* check if is an allowed option */
        if (XSTRNCMP(privType, "sandbox", 7) == 0) {
            wolfSSH_Log(WS_LOG_INFO, "[SSHD] Sandbox privilege separation");
            ret = WS_SUCCESS;
        }

        if (XSTRNCMP(privType, "yes", 3) == 0) {
            wolfSSH_Log(WS_LOG_INFO, "[SSHD] Privilege separation enabled");
            ret = WS_SUCCESS;
        }

        if (XSTRNCMP(privType, "no", 2) == 0) {
            wolfSSH_Log(WS_LOG_INFO, "[SSHD] Turning off privilege separation!");
            ret = WS_SUCCESS;
        }

        if (ret != WS_SUCCESS) {
            wolfSSH_Log(WS_LOG_ERROR,
                    "[SSHD] Unknown/supported privilege separation!");
        }
        wolfSSHD_FreeString(&privType, conf->heap);
    }

    if (XSTRNCMP(l, "Subsystem", 9) == 0) {

        ret = WS_SUCCESS;
    }

    if (XSTRNCMP(l, "ChallengeResponseAuthentication", 31) == 0) {
        ret = WS_SUCCESS;
    }

    if (XSTRNCMP(l, "UsePAM", 6) == 0) {
        ret = WS_SUCCESS;
    }

    if (XSTRNCMP(l, "X11Forwarding", 13) == 0) {
        ret = WS_SUCCESS;
    }

    if (XSTRNCMP(l, "PrintMotd", 9) == 0) {
        ret = WS_SUCCESS;
    }

    if (XSTRNCMP(l, "AcceptEnv", 9) == 0) {
        ret = WS_SUCCESS;
    }



    if (ret == WS_BAD_ARGUMENT) {
        printf("unknown / unsuported config line\n");
    }

    (void)conf;(void)lSz;
    return ret;
}


int wolfSSHD_LoadSSHD(WOLFSSHD_CONFIG* conf, const char* filename)
{
    XFILE f;
    int ret = WS_SUCCESS;
    char buf[MAX_LINE_SIZE];
    const char* current;

    if (conf == NULL || filename == NULL)
        return BAD_FUNC_ARG;

    f = XFOPEN(filename, "rb");
    if (f == XBADFILE) {
        wolfSSH_Log(WS_LOG_ERROR, "Unable to open SSHD config file %s\n",
                filename);
        return BAD_FUNC_ARG;
    }
    wolfSSH_Log(WS_LOG_INFO, "[SSHD] parsing config file %s", filename);

    while ((current = XFGETS(buf, MAX_LINE_SIZE, f)) != NULL) {
        int currentSz = (int)XSTRLEN(current);

        /* remove leading spaces */
        while (currentSz > 0 && current[0] == ' ') {
            currentSz = currentSz - 1;
            current   = current + 1;
        }

        if (currentSz <= 1) {
            continue; /* empty line */
        }

        if (current[0] == '#') {
            //printf("read commented out line\n%s\n", current);
            continue; /* commented out line */
        }

        ret = wolfSSHD_ParseConfigLine(conf, current, currentSz);
        if (ret != WS_SUCCESS) {
            printf("Unable to parse config line : %s\n", current);
            break;
        }
    }
    XFCLOSE(f);

    return ret;
}

char* wolfSSHD_GetBanner(WOLFSSHD_CONFIG* conf)
{
    if (conf != NULL)
        return conf->banner;
    return NULL;
}

char* wolfSSHD_GetHostPrivateKey(WOLFSSHD_CONFIG* conf)
{
    if (conf != NULL)
        return conf->hostKey;
    return NULL;
}

int wolfSSHD_SetHostPrivateKey(WOLFSSHD_CONFIG* conf, const char* hostKeyFile)
{
    if (conf == NULL)
        return WS_BAD_ARGUMENT;

    conf->hostKey = (char*)hostKeyFile;
    return WS_SUCCESS;
}

word16 wolfSSHD_GetPort(WOLFSSHD_CONFIG* conf)
{
    if (conf != NULL)
        return conf->port;
    return 0;
}
#endif /* WOLFSSH_SSHD */

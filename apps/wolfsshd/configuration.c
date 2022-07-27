/* configuration.c
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

#include "configuration.h"

struct WOLFSSHD_CONFIG {
    void* heap;
    char* banner;
    char* chrootDir;
    char* ciphers;
    char* hostKeyFile;
    char* hostKeyAlgos;
    char* kekAlgos;
    char* listenAddress;
    char* authKeysFile;
    long  loginTimer;
    word16 port;
    byte usePrivilegeSeparation;
    byte passwordAuth:1;
    byte pubKeyAuth:1;
    byte permitRootLogin:1;
    byte permitEmptyPasswords:1;
};


/* convert a string into seconds, handles if 'm' for minutes follows the string
 * number, i.e. 2m
 * Returns the value on success and negative value on failure */
static long GetConfigInt(const char* in, int inSz, int isTime, void* heap)
{
    long ret = 0;
    int mult = 1; /* multiplier */
    int sz   = inSz;

    /* check for multipliers */
    if (isTime) {
        if (in[sz - 1] == 'm') {
            sz--;
            mult = 60;
        }
        if (in[sz - 1] == 'h') {
            sz--;
            mult = 60*60;
        }
    }

    if (ret == 0) {
        char* num = (char*)WMALLOC(sz + 1, heap, DYNTYPE_SSHD);
        if (num == NULL) {
            ret = WS_MEMORY_E;
        }
        else {
            WMEMCPY(num, in, sz);
            num[sz] = '\0';
            ret = atol(num);
            if (ret > 0) {
                ret = ret * mult;
            }
            WFREE(num, heap, DYNTYPE_SSHD);
        }
    }

    return ret;
}

/* returns WS_SUCCESS on success */
static int CreateString(char** out, const char* in, int inSz, void* heap)
{
    int ret = WS_SUCCESS;
    int idx = 0;

    /* remove leading white spaces */
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

static void FreeString(char** in, void* heap)
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
        ret->passwordAuth = 1;
    }
    return ret;

}

void wolfSSHD_ConfigFree(WOLFSSHD_CONFIG* conf)
{
    void* heap;

    if (conf != NULL) {
        heap = conf->heap;

        FreeString(&conf->authKeysFile, heap);
        FreeString(&conf->hostKeyFile, heap);

        WFREE(conf, heap, DYNTYPE_SSHD);
    }
}

#define MAX_LINE_SIZE 160

typedef struct {
    int tag;
    const char* name;
} CONFIG_OPTION;

enum {
    OPT_AUTH_KEYS_FILE          = 0,
    OPT_PRIV_SEP                = 1,
    OPT_PERMIT_EMPTY_PW         = 2,
    OPT_SUBSYSTEM               = 3,
    OPT_CHALLENGE_RESPONSE_AUTH = 4,
    OPT_USE_PAM                 = 5,
    OPT_X11_FORWARDING          = 6,
    OPT_PRINT_MOTD              = 7,
    OPT_ACCEPT_ENV              = 8,
    OPT_PROTOCOL                = 9,
    OPT_LOGIN_GRACE_TIME        = 10,
    OPT_HOST_KEY                = 11,
    OPT_PASSWORD_AUTH           = 12,
    OPT_PORT                    = 13
};
enum {
    NUM_OPTIONS = 14
};

static const CONFIG_OPTION options[NUM_OPTIONS] = {
    {OPT_AUTH_KEYS_FILE,          "AuthorizedKeysFile"},
    {OPT_PRIV_SEP,                "UsePrivilegeSeparation"},
    {OPT_PERMIT_EMPTY_PW,         "PermitEmptyPasswords"},
    {OPT_SUBSYSTEM,               "Subsystem"},
    {OPT_CHALLENGE_RESPONSE_AUTH, "ChallengeResponseAuthentication"},
    {OPT_USE_PAM,                 "UsePAM"},
    {OPT_X11_FORWARDING,          "X11Forwarding"},
    {OPT_PRINT_MOTD,              "PrintMotd"},
    {OPT_ACCEPT_ENV,              "AcceptEnv"},
    {OPT_PROTOCOL,                "Protocol"},
    {OPT_LOGIN_GRACE_TIME,        "LoginGraceTime"},
    {OPT_HOST_KEY,                "HostKey"},
    {OPT_PASSWORD_AUTH,           "PasswordAuthentication"},
    {OPT_PORT,                    "Port"}
};

static int HandlePrivSep(WOLFSSHD_CONFIG* conf, const char* value)
{
    int ret = WS_SUCCESS;

    if (conf == NULL || value == NULL) {
        ret = WS_BAD_ARGUMENT;
    }

    if (ret == WS_SUCCESS) {
        if (WSTRCMP(value, "sandbox") == 0) {
            wolfSSH_Log(WS_LOG_INFO, "[SSHD] Sandbox privilege separation");
        }

        if (WSTRCMP(value, "yes") == 0) {
            wolfSSH_Log(WS_LOG_INFO, "[SSHD] Privilege separation enabled");
        }

        if (WSTRCMP(value, "no") == 0) {
            wolfSSH_Log(WS_LOG_INFO,
                        "[SSHD] Turning off privilege separation!");
        }

        if (ret != WS_SUCCESS) {
            wolfSSH_Log(WS_LOG_ERROR,
                        "[SSHD] Unknown/supported privilege separation!");
            ret = WS_BAD_ARGUMENT;
        }
    }

    return ret;
}

static int HandleLoginGraceTime(WOLFSSHD_CONFIG* conf, const char* value)
{
    int ret = WS_SUCCESS;
    long num;

    if (conf == NULL || value == NULL) {
        ret = WS_BAD_ARGUMENT;
    }

    if (ret == WS_SUCCESS) {
        num = GetConfigInt(value, XSTRLEN(value), 1, conf->heap);
        if (num < 0) {
            wolfSSH_Log(WS_LOG_ERROR, "[SSHD] Issue getting login grace "
                        "time");
            ret = num;
        }
        else {
            conf->loginTimer = num;
            wolfSSH_Log(WS_LOG_INFO, "[SSHD] Setting login grace time to "
                        "%ld", num);
        }
    }

    return ret;
}

static int HandlePermitEmptyPw(WOLFSSHD_CONFIG* conf, const char* value)
{
    int ret = WS_SUCCESS;

    if (conf == NULL || value == NULL) {
        ret = WS_BAD_ARGUMENT;
    }

    if (ret == WS_SUCCESS) {
        if (WSTRCMP(value, "no") == 0) {
            conf->permitEmptyPasswords = 0;
        }
        else if (WSTRCMP(value, "yes") == 0) {
            conf->permitEmptyPasswords = 1;
        }
        else {
            ret = WS_BAD_ARGUMENT;
        }
    }

    return ret;
}

static int HandlePwAuth(WOLFSSHD_CONFIG* conf, const char* value)
{
    int ret = WS_SUCCESS;

    if (conf == NULL || value == NULL) {
        ret = WS_BAD_ARGUMENT;
    }

    if (ret == WS_SUCCESS) {
        if (WSTRCMP(value, "no") == 0) {
            conf->passwordAuth = 0;
        }
        else if (WSTRCMP(value, "yes") == 0) {
            conf->passwordAuth = 1;
        }
        else {
            ret = WS_BAD_ARGUMENT;
        }
    }

    return ret;
}

static int HandlePort(WOLFSSHD_CONFIG* conf, const char* value)
{
    int ret = WS_SUCCESS;
    int portInt;

    if (conf == NULL || value == NULL) {
        ret = WS_BAD_ARGUMENT;
    }

    if (ret == WS_SUCCESS) {
        portInt = XATOI(value);
        if (portInt < 0) {
            wolfSSH_Log(WS_LOG_ERROR, "[SSHD] Unable to parse port number: %s.",
                        value);
            ret = WS_BAD_ARGUMENT;
        }
        else {
            if (portInt <= (word16)-1) {
                conf->port = (word16)portInt;
            }
            else {
                wolfSSH_Log(WS_LOG_ERROR, "[SSHD] Port number %d too big.",
                            portInt);
                ret = WS_BAD_ARGUMENT;
            }
        }
    }

    return ret;
}

static int HandleConfigOption(WOLFSSHD_CONFIG* conf, int opt, const char* value)
{
    int ret = WS_BAD_ARGUMENT;

    switch (opt) {
        case OPT_AUTH_KEYS_FILE:
            ret = wolfSSHD_ConfigSetAuthKeysFile(conf, value);
            break;
        case OPT_PRIV_SEP:
            ret = HandlePrivSep(conf, value);
            break;
        case OPT_PERMIT_EMPTY_PW:
            ret = HandlePermitEmptyPw(conf, value);
            break;
        case OPT_SUBSYSTEM:
            /* TODO */
            ret = WS_SUCCESS;
            break;
        case OPT_CHALLENGE_RESPONSE_AUTH:
            /* TODO */
            ret = WS_SUCCESS;
            break;
        case OPT_USE_PAM:
            /* TODO */
            ret = WS_SUCCESS;
            break;
        case OPT_X11_FORWARDING:
            /* TODO */
            ret = WS_SUCCESS;
            break;
        case OPT_PRINT_MOTD:
            /* TODO */
            ret = WS_SUCCESS;
            break;
        case OPT_ACCEPT_ENV:
            /* TODO */
            ret = WS_SUCCESS;
            break;
        case OPT_PROTOCOL:
            /* TODO */
            ret = WS_SUCCESS;
            break;
        case OPT_LOGIN_GRACE_TIME:
            ret = HandleLoginGraceTime(conf, value);
            break;
        case OPT_HOST_KEY:
            /* TODO: Add logic to check if file exists? */
            ret = wolfSSHD_ConfigSetHostKeyFile(conf, value);
            break;
        case OPT_PASSWORD_AUTH:
            ret = HandlePwAuth(conf, value);
            break;
        case OPT_PORT:
            ret = HandlePort(conf, value);
        default:
            break;
    }

    return ret;
}

static int CountWhitespace(const char* in, int inSz, byte inv)
{
    int i = 0;

    if (in != NULL) {
        for (; i < inSz; ++i) {
            if (inv) {
                if (isspace(in[i])) {
                    break;
                }
            }
            else {
                if (!isspace(in[i])) {
                    break;
                }
            }
        }
    }

    return i;
}

/* returns WS_SUCCESS on success
 * Fails if any option is found that is unknown/unsupported
 */
static int ParseConfigLine(WOLFSSHD_CONFIG* conf, const char* l, int lSz)
{
    int ret = WS_BAD_ARGUMENT;
    int sz;
    char tmp[MAX_FILENAME_SZ];
    int idx;
    const CONFIG_OPTION* found = NULL;

    for (idx = 0; idx < NUM_OPTIONS; ++idx) {
        sz = (int)WSTRLEN(options[idx].name);
        if (lSz >= sz && WSTRNCMP(l, options[idx].name, sz) == 0) {
            found = &options[idx];
            break;
        }
    }

    if (found != NULL) {
        /*
         * Count leading and trailing whitespace. Use that information to cut
         * out just the string itself when creating tmp.
         */
        idx = sz;
        idx += CountWhitespace(l + idx, lSz - sz, 0);
        sz = CountWhitespace(l + idx, lSz - sz, 1);
        if (sz >= MAX_FILENAME_SZ) {
            wolfSSH_Log(WS_LOG_ERROR, "[SSHD] Filename too long.");
            ret = WS_FATAL_ERROR;
        }
        else {
            WMEMCPY(tmp, l + idx, sz);
            tmp[sz] = 0;
            ret = HandleConfigOption(conf, found->tag, tmp);
        }
    }
    else {
        wolfSSH_Log(WS_LOG_ERROR, "[SSHD] Error parsing config line.");
        ret = WS_FATAL_ERROR;
    }

    return ret;
}


int wolfSSHD_ConfigLoad(WOLFSSHD_CONFIG* conf, const char* filename)
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

        ret = ParseConfigLine(conf, current, currentSz);
        if (ret != WS_SUCCESS) {
            printf("Unable to parse config line : %s\n", current);
            break;
        }
    }
    XFCLOSE(f);

    SetAuthKeysPattern(conf->authKeysFile);

    return ret;
}

char* wolfSSHD_ConfigGetAuthKeysFile(const WOLFSSHD_CONFIG* conf)
{
    char* ret = NULL;

    if (conf != NULL) {
        ret = conf->authKeysFile;
    }

    return ret;
}

int wolfSSHD_ConfigSetAuthKeysFile(WOLFSSHD_CONFIG* conf, const char* file)
{
    int ret = WS_SUCCESS;

    if (conf == NULL) {
        ret = WS_BAD_ARGUMENT;
    }

    if (ret == WS_SUCCESS) {
        if (conf->authKeysFile != NULL) {
            FreeString(&conf->authKeysFile, conf->heap);
            conf->authKeysFile = NULL;
        }

        if (file != NULL) {
            ret = CreateString(&conf->authKeysFile, file,
                                        WSTRLEN(file), conf->heap);
        }
    }

    return ret;
}

char* wolfSSHD_ConfigGetBanner(const WOLFSSHD_CONFIG* conf)
{
    char* ret = NULL;

    if (conf != NULL) {
        ret = conf->banner;
    }

    return ret;
}

char* wolfSSHD_ConfigGetHostKeyFile(const WOLFSSHD_CONFIG* conf)
{
    char* ret = NULL;

    if (conf != NULL) {
        ret = conf->hostKeyFile;
    }

    return ret;
}

int wolfSSHD_ConfigSetHostKeyFile(WOLFSSHD_CONFIG* conf, const char* file)
{
    int ret = WS_SUCCESS;

    if (conf == NULL) {
        ret = WS_BAD_ARGUMENT;
    }

    if (ret == WS_SUCCESS) {
        if (conf->hostKeyFile != NULL) {
            FreeString(&conf->hostKeyFile, conf->heap);
            conf->hostKeyFile = NULL;
        }

        if (file != NULL) {
            ret = CreateString(&conf->hostKeyFile, file,
                                        WSTRLEN(file), conf->heap);
        }
    }

    return ret;
}

word16 wolfSSHD_ConfigGetPort(const WOLFSSHD_CONFIG* conf)
{
    word16 ret = 0;

    if (conf != NULL) {
        ret = conf->port;
    }

    return ret;
}

byte wolfSSHD_ConfigGetPermitEmptyPw(const WOLFSSHD_CONFIG* conf)
{
    byte ret = 0;

    if (conf != NULL) {
        ret = conf->permitEmptyPasswords;
    }

    return ret;
}

byte wolfSSHD_ConfigGetPwAuth(const WOLFSSHD_CONFIG* conf)
{
    byte ret = 0;

    if (conf != NULL) {
        ret = conf->passwordAuth;
    }

    return ret;
}

long wolfSSHD_ConfigGetGraceTime(const WOLFSSHD_CONFIG* conf)
{
    long ret = WS_BAD_ARGUMENT;

    if (conf != NULL) {
        ret = conf->loginTimer;
    }

    return ret;
}
#endif /* WOLFSSH_SSHD */

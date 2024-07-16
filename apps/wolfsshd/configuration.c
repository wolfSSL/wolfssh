/* configuration.c
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

#ifdef WOLFSSL_USER_SETTINGS
    #include <wolfssl/wolfcrypt/settings.h>
#else
    #include <wolfssl/options.h>
#endif

#ifdef WOLFSSH_SSHD
/* functions for parsing out options from a config file and for handling loading
 * key/certs using the env. filesystem */

#ifdef WOLFSSHD_UNIT_TEST
#define WOLFSSHD_STATIC
#else
#define WOLFSSHD_STATIC static
#endif

#include <wolfssh/ssh.h>
#include <wolfssh/internal.h>
#include <wolfssh/log.h>
#include <wolfssh/port.h>
#include <wolfssl/wolfcrypt/wc_port.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#ifdef NO_INLINE
    #include <wolfssh/misc.h>
#else
    #define WOLFSSH_MISC_INCLUDED
    #include "src/misc.c"
#endif

#include "configuration.h"

#ifndef WIN32
#include <dirent.h>
#endif
#ifdef WIN32
#include <process.h>
#endif
#ifdef HAVE_LIMITS_H
    #include <limits.h>
#endif

struct WOLFSSHD_CONFIG {
    void* heap;
    char* usrAppliesTo;   /* NULL means all users */
    char* groupAppliesTo; /* NULL means all groups */
    char* banner;
    char* chrootDir;
    char* ciphers;
    char* hostKeyFile;
    char* hostCertFile;
    char* userCAKeysFile;
    char* hostKeyAlgos;
    char* kekAlgos;
    char* listenAddress;
    char* authKeysFile;
    char* forceCmd;
    char* pidFile;
    WOLFSSHD_CONFIG* next; /* next config in list */
    long  loginTimer;
    word16 port;
    byte usePrivilegeSeparation:2;
    byte passwordAuth:1;
    byte pubKeyAuth:1;
    byte permitRootLogin:1;
    byte permitEmptyPasswords:1;
    byte authKeysFileSet:1; /* if not set then no explicit authorized keys */
};

int CountWhitespace(const char* in, int inSz, byte inv);
int SetFileString(char** dst, const char* src, void* heap);

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
            if (ret == 0 && WSTRCMP(in, "0") != 0) {
                ret = WS_BAD_ARGUMENT;
            }
            else if (ret > 0) {
                ret = ret * mult;
            }
            WFREE(num, heap, DYNTYPE_SSHD);
        }
    }

    return ret;
}

/* returns WS_SUCCESS on success, removes trailng newlines */
static int CreateString(char** out, const char* in, int inSz, void* heap)
{
    int ret = WS_SUCCESS;
    int idx = 0, tail, sz = 0;

    if (in == NULL && inSz != 0) {
        return WS_BAD_ARGUMENT;
    }

    if (in == NULL) {
        /* "created" an empty string */
        return ret;
    }

    /* remove leading white spaces */
    while (idx < inSz && in[idx] == ' ') idx++;

    if (idx == inSz) {
        ret = WS_BAD_ARGUMENT;
    }

    if (ret == WS_SUCCESS) {
        for (tail = inSz - 1; tail > idx; tail--) {
            if (in[tail] != '\n' && in[tail] != ' ' && in[tail] != '\r') {
                break;
            }
        }

        sz = tail - idx + 1; /* +1 to account for index of 0 */
        if (sz > inSz - idx) {
            ret = WS_BAD_ARGUMENT;
        }
    }

    /* malloc new string and set it */
    if (ret == WS_SUCCESS) {
        *out = (char*)WMALLOC(sz + 1, heap, DYNTYPE_SSHD);
        if (*out == NULL) {
            ret = WS_MEMORY_E;
        }
        else {
            XMEMCPY(*out, in + idx, sz);
            *(*out + sz) = '\0';
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


/* returns a new WOLFSSHD_CONFIG on success and NULL on failure */
WOLFSSHD_CONFIG* wolfSSHD_ConfigNew(void* heap)
{
    WOLFSSHD_CONFIG* ret;

    ret = (WOLFSSHD_CONFIG*)WMALLOC(sizeof(WOLFSSHD_CONFIG), heap,
                DYNTYPE_SSHD);
    if (ret == NULL) {
        fprintf(stderr, "Issue malloc'ing config structure for sshd\n");
    }
    else {
        WMEMSET(ret, 0, sizeof(WOLFSSHD_CONFIG));

        /* default values */
        ret->port = 22;
        ret->passwordAuth = 1;
    }
    return ret;

}


/* on success return a newly create WOLFSSHD_CONFIG structure that has the
 * same values set as the input 'conf'. User and group match values are not
 * copied */
static WOLFSSHD_CONFIG* wolfSSHD_ConfigCopy(WOLFSSHD_CONFIG* conf)
{
    int ret = WS_SUCCESS;
    WOLFSSHD_CONFIG* newConf;

    newConf = wolfSSHD_ConfigNew(conf->heap);
    if (newConf != NULL) {
        if (conf->banner) {
            ret = CreateString(&newConf->banner, conf->banner,
                                        (int)WSTRLEN(conf->banner),
                                        newConf->heap);
        }

        if (ret == WS_SUCCESS && conf->chrootDir) {
            ret = CreateString(&newConf->chrootDir, conf->chrootDir,
                                        (int)WSTRLEN(conf->chrootDir),
                                        newConf->heap);
        }

        if (ret == WS_SUCCESS && conf->ciphers) {
            ret = CreateString(&newConf->ciphers, conf->ciphers,
                                        (int)WSTRLEN(conf->ciphers),
                                        newConf->heap);
        }

        if (ret == WS_SUCCESS && conf->hostKeyFile) {
            ret = CreateString(&newConf->hostKeyFile, conf->hostKeyFile,
                                        (int)WSTRLEN(conf->hostKeyFile),
                                        newConf->heap);
        }

        if (ret == WS_SUCCESS && conf->hostKeyAlgos) {
            ret = CreateString(&newConf->hostKeyAlgos, conf->hostKeyAlgos,
                                        (int)WSTRLEN(conf->hostKeyAlgos),
                                        newConf->heap);
        }

        if (ret == WS_SUCCESS && conf->kekAlgos) {
            ret = CreateString(&newConf->kekAlgos, conf->kekAlgos,
                                        (int)WSTRLEN(conf->kekAlgos),
                                        newConf->heap);
        }

        if (ret == WS_SUCCESS && conf->listenAddress) {
            ret = CreateString(&newConf->listenAddress, conf->listenAddress,
                                        (int)WSTRLEN(conf->listenAddress),
                                        newConf->heap);
        }

        if (ret == WS_SUCCESS && conf->authKeysFile) {
            ret = CreateString(&newConf->authKeysFile, conf->authKeysFile,
                                        (int)WSTRLEN(conf->authKeysFile),
                                        newConf->heap);
        }

        if (ret == WS_SUCCESS) {
            newConf->loginTimer   = conf->loginTimer;
            newConf->port         = conf->port;
            newConf->passwordAuth = conf->passwordAuth;
            newConf->pubKeyAuth   = conf->pubKeyAuth;
            newConf->usePrivilegeSeparation = conf->usePrivilegeSeparation;
            newConf->permitRootLogin        = conf->permitRootLogin;
            newConf->permitEmptyPasswords   = conf->permitEmptyPasswords;
        }
    }

    return newConf;
}


void wolfSSHD_ConfigFree(WOLFSSHD_CONFIG* conf)
{
    WOLFSSHD_CONFIG* current;
    void* heap;

    current = conf;
    while (current != NULL) {
        WOLFSSHD_CONFIG* next = current->next;
        heap = current->heap;

        FreeString(&current->banner,    heap);
        FreeString(&current->chrootDir, heap);
        FreeString(&current->ciphers,   heap);
        FreeString(&current->kekAlgos,  heap);
        FreeString(&current->hostKeyAlgos,  heap);
        FreeString(&current->listenAddress, heap);
        FreeString(&current->authKeysFile,  heap);
        FreeString(&current->hostKeyFile,   heap);
        FreeString(&current->hostCertFile,  heap);
        FreeString(&current->pidFile,  heap);

        WFREE(current, heap, DYNTYPE_SSHD);
        current = next;
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
    OPT_PORT                    = 13,
    OPT_PERMIT_ROOT             = 14,
    OPT_USE_DNS                 = 15,
    OPT_INCLUDE                 = 16,
    OPT_CHROOT_DIR              = 17,
    OPT_MATCH                   = 18,
    OPT_FORCE_CMD               = 19,
    OPT_HOST_CERT               = 20,
    OPT_TRUSTED_USER_CA_KEYS    = 21,
    OPT_PIDFILE                 = 22,
    OPT_BANNER                  = 23,
};
enum {
    NUM_OPTIONS = 24
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
    {OPT_PORT,                    "Port"},
    {OPT_PERMIT_ROOT,             "PermitRootLogin"},
    {OPT_USE_DNS,                 "UseDNS"},
    {OPT_INCLUDE,                 "Include"},
    {OPT_CHROOT_DIR,              "ChrootDirectory"},
    {OPT_MATCH,                   "Match"},
    {OPT_FORCE_CMD,               "ForceCommand"},
    {OPT_HOST_CERT,               "HostCertificate"},
    {OPT_TRUSTED_USER_CA_KEYS,    "TrustedUserCAKeys"},
    {OPT_PIDFILE,                 "PidFile"},
    {OPT_BANNER,                  "Banner"},
};

/* returns WS_SUCCESS on success */
static int HandlePrivSep(WOLFSSHD_CONFIG* conf, const char* value)
{
    int ret = WS_SUCCESS;

    if (conf == NULL || value == NULL) {
        ret = WS_BAD_ARGUMENT;
    }

    if (ret == WS_SUCCESS) {
        if (WSTRCMP(value, "sandbox") == 0) {
            wolfSSH_Log(WS_LOG_INFO, "[SSHD] Sandbox privilege separation");
            conf->usePrivilegeSeparation = WOLFSSHD_PRIV_SANDBOX;
        }
        else if (WSTRCMP(value, "yes") == 0) {
            wolfSSH_Log(WS_LOG_INFO, "[SSHD] Privilege separation enabled");
            conf->usePrivilegeSeparation = WOLFSSHD_PRIV_SEPARAT;
        }
        else if (WSTRCMP(value, "no") == 0) {
            wolfSSH_Log(WS_LOG_INFO,
                        "[SSHD] Turning off privilege separation!");
            conf->usePrivilegeSeparation = WOLFSSHD_PRIV_OFF;
        }
        else {
            wolfSSH_Log(WS_LOG_ERROR,
                        "[SSHD] Unknown/supported privilege separation!");
            ret = WS_BAD_ARGUMENT;
        }
    }

    return ret;
}

/* returns WS_SUCCESS on success */
static int HandleLoginGraceTime(WOLFSSHD_CONFIG* conf, const char* value)
{
    int ret = WS_SUCCESS;
    long num;

    if (conf == NULL || value == NULL) {
        ret = WS_BAD_ARGUMENT;
    }

    if (ret == WS_SUCCESS) {
        num = GetConfigInt(value, (int)XSTRLEN(value), 1, conf->heap);
        if (num < 0) {
            wolfSSH_Log(WS_LOG_ERROR, "[SSHD] Issue getting login grace "
                        "time");
            ret = (int)num;
        }
        else {
            conf->loginTimer = num;
            wolfSSH_Log(WS_LOG_INFO, "[SSHD] Setting login grace time to "
                        "%ld", num);
        }
    }

    return ret;
}

/* returns WS_SUCCESS on success */
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

/* returns WS_SUCCESS on success */
static int HandlePermitRoot(WOLFSSHD_CONFIG* conf, const char* value)
{
    int ret = WS_SUCCESS;

    if (conf == NULL || value == NULL) {
        ret = WS_BAD_ARGUMENT;
    }

    if (ret == WS_SUCCESS) {
        if (WSTRCMP(value, "no") == 0) {
            conf->permitRootLogin = 0;
        }
        else if (WSTRCMP(value, "yes") == 0) {
            conf->permitRootLogin = 1;
        }
        else {
            ret = WS_BAD_ARGUMENT;
        }
    }

    return ret;
}

/* returns WS_SUCCESS on success */
static int HandlePwAuth(WOLFSSHD_CONFIG* conf, const char* value)
{
    int ret = WS_SUCCESS;

    if (conf == NULL || value == NULL) {
        ret = WS_BAD_ARGUMENT;
    }

    if (ret == WS_SUCCESS) {
        if (WSTRCMP(value, "no") == 0) {
            wolfSSH_Log(WS_LOG_INFO, "[SSHD] password authentication disabled");
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

#define WOLFSSH_PROTOCOL_VERSION 2

/* returns WS_SUCCESS on success */
static int HandleProtocol(WOLFSSHD_CONFIG* conf, const char* value)
{
    int ret = WS_SUCCESS;
    long portInt;

    if (conf == NULL || value == NULL) {
        ret = WS_BAD_ARGUMENT;
    }

    if (ret == WS_SUCCESS) {
        portInt = GetConfigInt(value, (int)WSTRLEN(value), 0, conf->heap);
        if (portInt <= 0) {
            wolfSSH_Log(WS_LOG_ERROR, "[SSHD] Invalid protocol number: %s.",
                        value);
            ret = WS_BAD_ARGUMENT;
        }
        else {
            if (portInt != WOLFSSH_PROTOCOL_VERSION) {
                wolfSSH_Log(WS_LOG_ERROR, "[SSHD] Protocol number %ld not "
                    "supported.", portInt);
                ret = WS_BAD_ARGUMENT;
            }
        }
    }

    return ret;
}

/* returns WS_SUCCESS on success */
static int HandlePort(WOLFSSHD_CONFIG* conf, const char* value)
{
    int ret = WS_SUCCESS;
    long portInt;

    if (conf == NULL || value == NULL) {
        ret = WS_BAD_ARGUMENT;
    }

    if (ret == WS_SUCCESS) {
        portInt = GetConfigInt(value, (int)WSTRLEN(value), 0, conf->heap);
        if (portInt <= 0) {
            wolfSSH_Log(WS_LOG_ERROR, "[SSHD] Invalid port number: %s.",
                        value);
            ret = WS_BAD_ARGUMENT;
        }
        else {
            if (portInt <= (word16)-1) {
                conf->port = (word16)portInt;
            }
            else {
                wolfSSH_Log(WS_LOG_ERROR, "[SSHD] Port number %ld too big.",
                            portInt);
                ret = WS_BAD_ARGUMENT;
            }
        }
    }

    return ret;
}

static int HandleInclude(WOLFSSHD_CONFIG *conf, const char *value)
{
    const char *ptr;
    const char *ptr2;
    const char *postfix = NULL;
    const char *prefix = NULL;
    int prefixLen = 0;
    int found = 0;
    int ret = WS_SUCCESS;

    /* No value, nothing to do */
    if (!value || value[0] == '\0') {
        ret = WS_BAD_ARGUMENT;
    }

    if (ret == WS_SUCCESS) {
        /* Ignore trailing whitespace */
        ptr = value + WSTRLEN(value) - 1;
        while (ptr != value) {
            if (WISSPACE(*ptr)) {
                ptr--;
            }
            else {
                break;
            }
        }

        /* Find wildcards */
        ptr2 = ptr;
        while (ptr2 != value) {
            if (*ptr2 == '*') {
                /* Wildcard found */
                found = 1;
                if (ptr != ptr2) {
                    postfix = ptr2 + 1;
                }
                break;
            }
            if (*ptr2 == '/') {
                /* Found slash before wildcard directory-wildcards
                 * not supported */
                break;
            }
            ptr2--;
        }
        ptr = ptr2;

        /* Use wildcard */
        if (found) {
#if defined(__unix__) || defined(__unix) || \
        (defined(__APPLE__) && defined(__MACH__))
            struct dirent *dir;
            WDIR d;
            char *path = NULL;
            char *filepath = (char*)WMALLOC(PATH_MAX, conf->heap, DYNTYPE_PATH);

            if (filepath == NULL) {
                ret = WS_MEMORY_E;
            }

            if (ret == WS_SUCCESS) {
                /* Back find the full path */
                while (ptr2 != value) {
                    if (*ptr2 == '/') {
                        break;
                    }
                    ptr2--;
                }

                if (ptr2 != value) {
                    path = (char*)WMALLOC(ptr2 - value + 1,
                            conf->heap, DYNTYPE_PATH);
                    if (path == NULL) {
                        ret = WS_MEMORY_E;
                    }
                    else {
                        WMEMCPY(path, value, ptr2 - value);
                        path[ptr2 - value] = '\0';
                        prefix = ptr2 + 1;
                        prefixLen = (int)(ptr - ptr2 - 1);
                    }
                }
                else {
                    path = (char*)WMALLOC(2, conf->heap, DYNTYPE_PATH);
                    if (path == NULL) {
                        ret = WS_MEMORY_E;
                    }
                    else {
                        WMEMCPY(path, ".", 1);
                        path[1] = '\0';
                        prefix = value;
                        prefixLen = (int)(ptr - value);
                    }
                }
            }

            if (ret == WS_SUCCESS) {
                if (!WOPENDIR(NULL, conf->heap, &d, path)) {
                    word32 fileCount = 0, i, j;
                    char** fileNames = NULL;

                    /* Count up the number of files */
                    while ((dir = WREADDIR(NULL, &d)) != NULL) {
                        /* Skip sub-directories */
                    #if defined(__QNX__) || defined(__QNXNTO__)
                        struct stat s;

                        lstat(dir->d_name, &s);
                        if (!S_ISDIR(s.st_mode))
                    #else
                        if (dir->d_type != DT_DIR)
                    #endif
                        {
                            fileCount++;
                        }
                    }
                    WREWINDDIR(NULL, &d);

                    if (fileCount > 0) {
                        fileNames = (char**)WMALLOC(fileCount * sizeof(char*),
                                conf->heap, DYNTYPE_PATH);
                        if (fileNames == NULL) {
                            ret = WS_MEMORY_E;
                        }
                    }

                    if (ret == WS_SUCCESS) {
                        i = 0;
                        while (i < fileCount && (dir = WREADDIR(NULL, &d)) != NULL) {
                            /* Skip sub-directories */
                        #if defined(__QNX__) || defined(__QNXNTO__)
                            struct stat s;

                            lstat(dir->d_name, &s);
                            if (!S_ISDIR(s.st_mode))
                        #else
                            if (dir->d_type != DT_DIR)
                        #endif
                            {
                                /* Insert in string order */
                                for (j = 0; j < i; j++) {
                                    if (WSTRCMP(dir->d_name, fileNames[j])
                                            < 0) {
                                        WMEMMOVE(fileNames+j+1, fileNames+j,
                                                (i - j)*sizeof(char*));
                                        break;
                                    }
                                }
                                fileNames[j] = dir->d_name;
                                i++;
                            }
                        }

                        for (i = 0; i < fileCount; i++) {
                            /* Check if filename prefix matches */
                            if (prefixLen > 0) {
                                if ((int)WSTRLEN(fileNames[i]) <= prefixLen) {
                                    continue;
                                }
                                if (WSTRNCMP(fileNames[i], prefix, prefixLen)
                                        != 0) {
                                    continue;
                                }
                            }
                            if (postfix) {
                                /* Skip if file is too short */
                                if (WSTRLEN(fileNames[i]) <= WSTRLEN(postfix)) {
                                    continue;
                                }
                                if (WSTRNCMP(fileNames[i] +
                                            WSTRLEN(fileNames[i]) -
                                            WSTRLEN(postfix),
                                            postfix, WSTRLEN(postfix))
                                        == 0) {
                                    WSNPRINTF(filepath, PATH_MAX, "%s/%s", path,
                                             fileNames[i]);
                                }
                                else {
                                    /* Not a match */
                                    continue;
                                }
                            }
                            else {
                                WSNPRINTF(filepath, PATH_MAX, "%s/%s", path,
                                         fileNames[i]);
                            }
                            ret = wolfSSHD_ConfigLoad(conf, filepath);
                            if (ret != WS_SUCCESS) {
                                break;
                            }
                        }

                        if (fileNames != NULL) {
                            WFREE(fileNames, conf->heap, DYNTYPE_PATH);
                        }
                    }
                    WCLOSEDIR(NULL, &d);
                }
                else {
                    /* Bad directory */
                    ret = WS_INVALID_PATH_E;
                }
            }
            if (path != NULL) {
                WFREE(path, conf->heap, DYNTYPE_PATH);
            }
            if (filepath != NULL) {
                WFREE(filepath, conf->heap, DYNTYPE_PATH);
            }
#else
            (void)postfix;
            (void)prefixLen;
            (void)prefix;
            /* Don't support wildcards here */
            ret = WS_BAD_ARGUMENT;
#endif
        }
        else {
            ret = wolfSSHD_ConfigLoad(conf, value);
        }
    }
    return ret;
}


/* returns WS_SUCCESS on success */
static int HandleChrootDir(WOLFSSHD_CONFIG* conf, const char* value)
{
    int ret = WS_SUCCESS;

    if (conf == NULL || value == NULL) {
        ret = WS_BAD_ARGUMENT;
    }

    if (ret == WS_SUCCESS) {
        if (conf->chrootDir != NULL) {
            FreeString(&conf->chrootDir, conf->heap);
            conf->chrootDir = NULL;
        }
        ret = CreateString(&conf->chrootDir, value,
                                        (int)WSTRLEN(value), conf->heap);
    }

    return ret;
}


/* returns WS_SUCCESS on success, helps with adding a restricted case to the
 * config */
static int AddRestrictedCase(WOLFSSHD_CONFIG* config, const char* mtch,
    const char* value, char** out)
{
    int ret = WS_SUCCESS;
    char* pt;

    pt = (char*)XSTRSTR(value, mtch);
    if (pt != NULL) {
        int sz, i;

        pt += (int)XSTRLEN(mtch);
        sz   = (int)XSTRLEN(pt);

        /* remove spaces between 'mtch' and the user name */
        for (i = 0; i < sz; i++) {
            if (pt[i] != ' ') break;
        }
        if (i == sz) {
            wolfSSH_Log(WS_LOG_ERROR,
                "[SSHD] No valid input found with Match");
            ret = WS_FATAL_ERROR;
        }

        if (ret == WS_SUCCESS) {
            pt += i;
            sz  -= i;

            /* get the actual size of the user name */
            for (i = 0; i < sz; i++) {
                if (pt[i] == ' ' || pt[i] == '\r' || pt[i] == '\n') break;
            }
            sz = i;

            ret = CreateString(out, pt, sz, config->heap);
        }
    }
    return ret;
}


/* returns WS_SUCCESS on success, on success it update the conf pointed to
 * and makes it point to the newly created conf node */
static int HandleMatch(WOLFSSHD_CONFIG** conf, const char* value, int valueSz)
{
    WOLFSSHD_CONFIG* newConf = NULL;
    int ret = WS_SUCCESS;

    if (conf == NULL || *conf == NULL || value == NULL) {
        ret = WS_BAD_ARGUMENT;
    }

    /* create new configure for altered options specific to the match */
    if (ret == WS_SUCCESS) {
        newConf = wolfSSHD_ConfigCopy(*conf);
        if (newConf == NULL) {
            ret = WS_MEMORY_E;
        }
    }

    /* users the settings apply to */
    if (ret == WS_SUCCESS) {
        ret = AddRestrictedCase(newConf, "User", value,
            &newConf->usrAppliesTo);
    }

    /* groups the settings apply to */
    if (ret == WS_SUCCESS) {
        ret = AddRestrictedCase(newConf, "Group", value,
            &newConf->groupAppliesTo);
    }

    /* @TODO handle , seperated user/group list */

    /* update current config being processed */
    if (ret == WS_SUCCESS) {
        (*conf)->next = newConf;
        (*conf)       = newConf;
    }

    (void)valueSz;
    return ret;
}


/* returns WS_SUCCESS on success */
static int HandleForcedCommand(WOLFSSHD_CONFIG* conf, const char* value,
    int valueSz)
{
    int ret = WS_SUCCESS;

    if (conf == NULL || value == NULL) {
        ret = WS_BAD_ARGUMENT;
    }

    if (ret == WS_SUCCESS) {
        if (conf->forceCmd != NULL) {
            FreeString(&conf->forceCmd, conf->heap);
            conf->forceCmd = NULL;
        }

        ret = CreateString(&conf->forceCmd, value, valueSz, conf->heap);
    }


    (void)valueSz;
    return ret;
}

/* returns WS_SUCCESS on success */
static int HandleConfigOption(WOLFSSHD_CONFIG** conf, int opt,
        const char* value, const char* full, int fullSz)
{
    int ret = WS_BAD_ARGUMENT;

    switch (opt) {
        case OPT_AUTH_KEYS_FILE:
            (*conf)->authKeysFileSet = 1;
            ret = wolfSSHD_ConfigSetAuthKeysFile(*conf, value);
            break;
        case OPT_PRIV_SEP:
            ret = HandlePrivSep(*conf, value);
            break;
        case OPT_PERMIT_EMPTY_PW:
            ret = HandlePermitEmptyPw(*conf, value);
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
            ret = HandleProtocol(*conf, value);
            break;
        case OPT_LOGIN_GRACE_TIME:
            ret = HandleLoginGraceTime(*conf, value);
            break;
        case OPT_HOST_KEY:
            /* TODO: Add logic to check if file exists? */
            ret = wolfSSHD_ConfigSetHostKeyFile(*conf, value);
            break;
        case OPT_HOST_CERT:
            /* TODO: Add logic to check if file exists? */
            ret = wolfSSHD_ConfigSetHostCertFile(*conf, value);
            break;
        case OPT_PASSWORD_AUTH:
            ret = HandlePwAuth(*conf, value);
            break;
        case OPT_PORT:
            ret = HandlePort(*conf, value);
            break;
        case OPT_PERMIT_ROOT:
            ret = HandlePermitRoot(*conf, value);
            break;
        case OPT_USE_DNS:
            /* TODO */
            ret = WS_SUCCESS;
            break;
        case OPT_INCLUDE:
            ret = HandleInclude(*conf, value);
            break;
        case OPT_CHROOT_DIR:
            ret = HandleChrootDir(*conf, value);
            break;
        case OPT_MATCH:
            /* makes new config and appends it to the list */
            ret = HandleMatch(conf, full, fullSz);
            break;
        case OPT_FORCE_CMD:
            ret = HandleForcedCommand(*conf, full, fullSz);
            break;
        case OPT_TRUSTED_USER_CA_KEYS:
            /* TODO: Add logic to check if file exists? */
            ret = wolfSSHD_ConfigSetUserCAKeysFile(*conf, value);
            break;
        case OPT_PIDFILE:
            ret = SetFileString(&(*conf)->pidFile, value, (*conf)->heap);
            break;
        case OPT_BANNER:
            ret = SetFileString(&(*conf)->banner, value, (*conf)->heap);
            break;
        default:
            break;
    }

    return ret;
}

/* helper function to count white spaces, returns the number of white spaces on
 * success */
int CountWhitespace(const char* in, int inSz, byte inv)
{
    int i = 0;

    if (in != NULL) {
        for (; i < inSz; ++i) {
            if (inv) {
                if (WISSPACE(in[i])) {
                    break;
                }
            }
            else {
                if (!WISSPACE(in[i])) {
                    break;
                }
            }
        }
    }

    return i;
}

/* returns WS_SUCCESS on success
 * Fails if any option is found that is unknown/unsupported
 * Match command will create new configs for specific matching cases
 */
WOLFSSHD_STATIC int ParseConfigLine(WOLFSSHD_CONFIG** conf, const char* l,
                                    int lSz)
{
    int ret = WS_BAD_ARGUMENT;
    int sz  = 0;
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
            ret = HandleConfigOption(conf, found->tag, tmp, l + idx, lSz - idx);
        }
    }
    else {
    #ifdef WOLFSSH_IGNORE_UNKNOWN_CONFIG
        wolfSSH_Log(WS_LOG_DEBUG, "[SSHD] ignoring config line %s.", l);
        ret = WS_SUCCESS;
    #else
        wolfSSH_Log(WS_LOG_ERROR, "[SSHD] Error parsing config line.");
        ret = WS_FATAL_ERROR;
    #endif
    }

    return ret;
}


/* parses and loads in the given configuration file 'filename'
 * returns WS_SUCCESS on success
 */
int wolfSSHD_ConfigLoad(WOLFSSHD_CONFIG* conf, const char* filename)
{
    WFILE *f;
    WOLFSSHD_CONFIG* currentConfig;
    int ret = WS_SUCCESS;
    char buf[MAX_LINE_SIZE];
    const char* current;

    if (conf == NULL || filename == NULL)
        return BAD_FUNC_ARG;

    if (WFOPEN(NULL, &f, filename, "rb") != 0) {
        wolfSSH_Log(WS_LOG_ERROR, "Unable to open SSHD config file %s",
                filename);
        return BAD_FUNC_ARG;
    }
    wolfSSH_Log(WS_LOG_INFO, "[SSHD] parsing config file %s", filename);

    currentConfig = conf;
    while ((current = XFGETS(buf, MAX_LINE_SIZE, f)) != NULL) {
        int currentSz = (int)XSTRLEN(current);

        /* remove leading spaces and tabs */
        while (currentSz > 0 &&
                (current[0] == ' ' || current[0] == '\t')) {
            currentSz = currentSz - 1;
            current   = current + 1;
        }

        if (currentSz <= 2) { /* \n or \r\n */
            continue; /* empty line */
        }

        if (current[0] == '#') {
            continue; /* commented out line */
        }

        ret = ParseConfigLine(&currentConfig, current, currentSz);
        if (ret != WS_SUCCESS) {
            fprintf(stderr, "Unable to parse config line : %s\n", current);
            break;
        }
    }
    WFCLOSE(NULL, f);

    SetAuthKeysPattern(conf->authKeysFile);

    return ret;
}


/* returns the config associated with the user */
WOLFSSHD_CONFIG* wolfSSHD_GetUserConf(const WOLFSSHD_CONFIG* conf,
        const char* usr, const char* grp, const char* host,
        const char* localAdr, word16* localPort, const char* RDomain,
        const char* adr)
{
    WOLFSSHD_CONFIG* ret;
    WOLFSSHD_CONFIG* current;

    /* default to return head of list */
    ret = current = (WOLFSSHD_CONFIG*)conf;
    while (current != NULL) {
        /* compare current configs user */
        if (usr != NULL && current->usrAppliesTo != NULL) {
            if (XSTRCMP(current->usrAppliesTo, usr) == 0) {
                ret = current;
                break;
            }
        }

        /* compare current configs group */
        if (grp != NULL && current->groupAppliesTo != NULL) {
            if (XSTRCMP(current->groupAppliesTo, grp) == 0) {
                ret = current;
                break;
            }
        }

        current = current->next;
    }

    /* @TODO */
    (void)host;
    (void)localAdr;
    (void)localPort;
    (void)RDomain;
    (void)adr;

    return ret;
}


char* wolfSSHD_ConfigGetForcedCmd(const WOLFSSHD_CONFIG* conf)
{
    char* ret = NULL;

    if (conf != NULL) {
        ret = conf->forceCmd;
    }

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


/* returns 1 if the authorized keys file was set and 0 if not */
int wolfSSHD_ConfigGetAuthKeysFileSet(const WOLFSSHD_CONFIG* conf)
{
    int ret = 0;

    if (conf != NULL) {
        ret = conf->authKeysFileSet;
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
                                        (int)WSTRLEN(file), conf->heap);
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

char* wolfSSHD_ConfigGetChroot(const WOLFSSHD_CONFIG* conf)
{
    char* ret = NULL;

    if (conf != NULL) {
        ret = conf->chrootDir;
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

char* wolfSSHD_ConfigGetHostCertFile(const WOLFSSHD_CONFIG* conf)
{
    char* ret = NULL;

    if (conf != NULL) {
        ret = conf->hostCertFile;
    }

    return ret;
}

char* wolfSSHD_ConfigGetUserCAKeysFile(const WOLFSSHD_CONFIG* conf)
{
    char* ret = NULL;

    if (conf != NULL) {
        ret = conf->userCAKeysFile;
    }

    return ret;
}

int SetFileString(char** dst, const char* src, void* heap)
{
    int ret = WS_SUCCESS;

    if (dst == NULL) {
        ret = WS_BAD_ARGUMENT;
    }

    if (ret == WS_SUCCESS) {
        if (*dst != NULL) {
            FreeString(dst, heap);
            *dst = NULL;
        }

        if (src != NULL) {
            ret = CreateString(dst, src, (int)WSTRLEN(src), heap);
        }
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
        ret = SetFileString(&conf->hostKeyFile, file, conf->heap);
    }

    return ret;
}

int wolfSSHD_ConfigSetHostCertFile(WOLFSSHD_CONFIG* conf, const char* file)
{
    int ret = WS_SUCCESS;

    if (conf == NULL) {
        ret = WS_BAD_ARGUMENT;
    }

    if (ret == WS_SUCCESS) {
        ret = SetFileString(&conf->hostCertFile, file, conf->heap);
    }

    return ret;
}

int wolfSSHD_ConfigSetUserCAKeysFile(WOLFSSHD_CONFIG* conf, const char* file)
{
    int ret = WS_SUCCESS;

    if (conf == NULL) {
        ret = WS_BAD_ARGUMENT;
    }

    if (ret == WS_SUCCESS) {
        ret = SetFileString(&conf->userCAKeysFile, file, conf->heap);
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

byte wolfSSHD_ConfigGetPrivilegeSeparation(const WOLFSSHD_CONFIG* conf)
{
    byte ret = 0;

    if (conf != NULL) {
        ret = conf->usePrivilegeSeparation;
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

byte wolfSSHD_ConfigGetPermitRoot(const WOLFSSHD_CONFIG* conf)
{
    byte ret = 0;

    if (conf != NULL) {
        ret = conf->permitRootLogin;
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


/* Used to save out the PID of SSHD to a file */
void wolfSSHD_ConfigSavePID(const WOLFSSHD_CONFIG* conf)
{
    FILE* f;
    char buf[12]; /* large enough to hold 'int' type with null terminator */

    if (conf->pidFile != NULL) {
        WMEMSET(buf, 0, sizeof(buf));
        if (WFOPEN(NULL, &f, conf->pidFile, "wb") == 0) {
    #ifndef WIN32
            WSNPRINTF(buf, sizeof(buf), "%d", getpid());
    #else
            WSNPRINTF(buf, sizeof(buf), "%d", _getpid());
    #endif
            WFWRITE(NULL, buf, 1, WSTRLEN(buf), f);
            WFCLOSE(NULL, f);
        }
    }
}

#endif /* WOLFSSH_SSHD */

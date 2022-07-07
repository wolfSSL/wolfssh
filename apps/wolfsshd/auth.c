/* auth.c
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
#include <wolfssh/log.h>
#include <wolfssl/wolfcrypt/wc_port.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/coding.h>

#ifdef NO_INLINE
    #include <wolfssh/misc.h>
#else
    #define WOLFSSH_MISC_INCLUDED
    #include "src/misc.c"
#endif

#include "auth.h"

#include <unistd.h>

#ifndef _WIN32
#include <sys/types.h>
#include <pwd.h>
#include <uuid/uuid.h>
#include <errno.h>
#endif

#if 0
static byte passwdRetry = 3;

/* Map user names to passwords */
/* Use arrays for username and p. The password or public key can
 * be hashed and the hash stored here. Then I won't need the type. */
struct USER_NODE {
    byte   type;
    byte   username[32];
    word32 usernameSz;
    byte   fingerprint[WC_SHA256_DIGEST_SIZE];
    struct USER_NODE* next;
};


/* Takes a users input and adds it to the list of accepted users
 * 'value' can be a users password / public key / or certificate
 * returns an updated list on success (i.e. 'new' -> 'list' -> ...) or NULL
 *  on failure
 */
USER_NODE* AddNewUser(USER_NODE* list, byte type, const byte* username,
                       word32 usernameSz, const byte* value, word32 valueSz)
{
    USER_NODE* map;

    map = (USER_NODE*)WMALLOC(sizeof(USER_NODE), NULL, 0);
    if (map != NULL) {
        map->type = type;
        if (usernameSz >= sizeof(map->username))
            usernameSz = sizeof(map->username) - 1;
        WMEMCPY(map->username, username, usernameSz + 1);
        map->username[usernameSz] = 0;
        map->usernameSz = usernameSz;

        if (type != WOLFSSH_USERAUTH_NONE) {
            wc_Sha256Hash(value, valueSz, map->fingerprint);
        }

        map->next = list;
    }

    return map;
}

int DefaultUserAuth(byte authType, WS_UserAuthData* authData, void* ctx)
{
    USER_NODE* map;
    byte authHash[WC_SHA256_DIGEST_SIZE];
    int ret;

    if (authType != WOLFSSH_USERAUTH_PASSWORD &&
#ifdef WOLFSSH_ALLOW_USERAUTH_NONE
        authType != WOLFSSH_USERAUTH_NONE &&
#endif
        authType != WOLFSSH_USERAUTH_PUBLICKEY) {

        return WOLFSSH_USERAUTH_FAILURE;
    }
    map = (USER_NODE*)ctx;

    /* check if password on system */
    if (authData->type == WOLFSSH_USERAUTH_PASSWORD) {
        if (CheckPassword(authData->username, authData->sf.password.password,
                authData->sf.password.passwordSz) == WS_SUCCESS) {
            wolfSSH_Log(WS_LOG_INFO, "[SSHD] Password and user on system");
            return WOLFSSH_USERAUTH_SUCCESS;
        }
    }
    
    if (authType == WOLFSSH_USERAUTH_PASSWORD) {
        wc_Sha256Hash(authData->sf.password.password,
                authData->sf.password.passwordSz,
                authHash);
    }
    else if (authType == WOLFSSH_USERAUTH_PUBLICKEY) {
        wc_Sha256Hash(authData->sf.publicKey.publicKey,
                authData->sf.publicKey.publicKeySz,
                authHash);
    }

    while (map != NULL) {
        if (authData->usernameSz == map->usernameSz &&
            WMEMCMP(authData->username, map->username, map->usernameSz) == 0 &&
            authData->type == map->type) {

            if (authData->type == WOLFSSH_USERAUTH_PUBLICKEY) {
                if (WMEMCMP(map->fingerprint, authHash,
                            WC_SHA256_DIGEST_SIZE) == 0) {
                    return WOLFSSH_USERAUTH_SUCCESS;
                }
                else {
                   return WOLFSSH_USERAUTH_INVALID_PUBLICKEY;
                }
            }
            else if (authData->type == WOLFSSH_USERAUTH_PASSWORD) {
                if (WMEMCMP(map->fingerprint, authHash,
                            WC_SHA256_DIGEST_SIZE) == 0) {
                    return WOLFSSH_USERAUTH_SUCCESS;
                }
                else {
                    passwdRetry--;
                    return (passwdRetry > 0) ?
                        WOLFSSH_USERAUTH_INVALID_PASSWORD :
                        WOLFSSH_USERAUTH_REJECTED;
                 }
            }
#ifdef WOLFSSH_ALLOW_USERAUTH_NONE
            else if (authData->type == WOLFSSH_USERAUTH_NONE) {
                return WOLFSSH_USERAUTH_SUCCESS;
            }
#endif /* WOLFSSH_ALLOW_USERAUTH_NONE */
            else {
                 return WOLFSSH_USERAUTH_INVALID_AUTHTYPE;
            }

            if (authData->type == map->type) {
                if (WMEMCMP(map->fingerprint, authHash,
                            WC_SHA256_DIGEST_SIZE) == 0) {
                    return WOLFSSH_USERAUTH_SUCCESS;
                }
                else {
                    if (authType == WOLFSSH_USERAUTH_PASSWORD) {
                        passwdRetry--;
                        ret = (passwdRetry > 0) ?
                            WOLFSSH_USERAUTH_INVALID_PASSWORD :
                            WOLFSSH_USERAUTH_REJECTED;
                    }
                    else {
                        ret = WOLFSSH_USERAUTH_INVALID_PUBLICKEY;
                    }
                    return ret;
                }
            }
            else {
                return WOLFSSH_USERAUTH_INVALID_AUTHTYPE;
            }
        }
        map = map->next;
    }

    return WOLFSSH_USERAUTH_INVALID_USER;
}
#endif

static int CheckAuthKeysLine(char* line, word32 lineSz, const byte* key,
                             word32 keySz)
{
    int ret = WS_SUCCESS;
    char* type;
    char* keyCandBase64; /* cand == candidate */
    word32 keyCandBase64Sz;
    byte* keyCand = NULL;
    word32 keyCandSz;
    char* last;
    enum {
        NUM_ALLOWED_TYPES = 5
    };
    static const char* allowedTypes[NUM_ALLOWED_TYPES] = {
        "ssh-rsa",
        "ssh-ed25519",
        "ecdsa-sha2-nistp256",
        "ecdsa-sha2-nistp384",
        "ecdsa-sha2-nistp521"
    };
    int typeOk = 0;
    int i;

    if (line == NULL || lineSz == 0 || key == NULL || keySz == 0) {
        ret = WS_BAD_ARGUMENT;
    }

    if (ret == WS_SUCCESS) {
        if ((type = WSTRTOK(line, " ", &last)) == NULL) {
            ret = WS_FATAL_ERROR;
        }
        else if ((keyCandBase64 = WSTRTOK(NULL, " ", &last)) == NULL) {
            ret = WS_FATAL_ERROR;
        }
    }
    if (ret == WS_SUCCESS) {
        for (i = 0; i < NUM_ALLOWED_TYPES; ++i) {
            if (WSTRCMP(type, allowedTypes[i]) == 0) {
                typeOk = 1;
                break;
            }
        }
        if (!typeOk) {
            ret = WS_FATAL_ERROR;
        }
    }
    if (ret == WS_SUCCESS) {
        keyCandBase64Sz = XSTRLEN(keyCandBase64);
        keyCandSz = (keyCandBase64Sz * 3 + 3) / 4;
        keyCand = (byte*)WMALLOC(keyCandSz, NULL, DYNTYPE_BUFFER);
        if (keyCand == NULL) {
            ret = WS_MEMORY_E;
        }
        else {
            if (Base64_Decode((byte*)keyCandBase64, keyCandBase64Sz, keyCand,
                              &keyCandSz) != 0) {
                ret = WS_FATAL_ERROR;
            }
        }
    }
    if (ret == WS_SUCCESS && keyCandSz == keySz &&
        WMEMCMP(key, keyCand, keySz) == 0) {
        ret = 1;
    }

    if (keyCand != NULL) {
        WFREE(keyCand, NULL, DYNTYPE_BUFFER);
    }

    return ret;
}

/* returns WS_SUCCESS if user/password found */
static int CheckPassword(const byte* usr, const byte* pw, int pwSz)
{
    int ret = WS_SUCCESS;
    struct passwd* pwInfo;
//    struct spwd*   spwInfo;
    char* encPw; /* encrypted version of password */
    char tmp[256];
    
    pwInfo = getpwnam((const char*)usr);
    if (pwInfo == NULL) {
        /* user name not found on system */
        ret = WS_FATAL_ERROR;
    }

    /* check for shadow password record */
//    spwInfo = getspnam(usr);
//    if (spwInfo != NULL) {
//        pwInfo->pw_passwd = spwInfo->sp_pwdp;
//    }
//
{
    int z;
    for (z = 0; z < pwSz; z++)
        tmp[z] = pw[z];
    tmp[z] = '\0';
}

    if (ret == WS_SUCCESS) {
        encPw = crypt((const char*)tmp, pwInfo->pw_passwd);
        if (encPw == NULL) {
            /* error encrypting password for comparison */
            ret = WS_FATAL_ERROR;
        }
    }

{
    int z;
    printf("peer pw : ");
    for (z = 0; z < pwSz; z++)
        printf("%02X", pw[z]);
    printf("\n");
    printf("     pw : ");
    for (z = 0; z < pwSz; z++)
        printf("%02X", pwInfo->pw_passwd[z]);
    printf("\n");
    printf("    enc : ");
    for (z = 0; z < pwSz; z++)
        printf("%02X", encPw[z]);
    printf("\n");
}
    if (ret == WS_SUCCESS) {
        if (XSTRCMP(encPw, pwInfo->pw_passwd) == 0) {
            wolfSSH_Log(WS_LOG_INFO, "[SSHD] User %s log in successful", usr);
        }
        else {
            wolfSSH_Log(WS_LOG_INFO, "[SSHD] User %s log in fail", usr);
            ret = WS_FATAL_ERROR;
        }
    }
    (void)pwSz;

    return ret;
}

enum {
    USER_LOOKUP_ERROR   = -1,
    USER_LOOKUP_FAILURE =  0,
    USER_LOOKUP_SUCCESS =  1
};

#ifndef _WIN32
static int CheckUserUnix(const char* name) {
    int ret = USER_LOOKUP_FAILURE;
    struct passwd* pwInfo;

    errno = 0;
    pwInfo = getpwnam(name);
    if (pwInfo == NULL) {
        if (errno != 0) {
            wolfSSH_Log(WS_LOG_ERROR, "[SSHD] Error calling getpwnam for user "
                                      "%s.", name);
            ret = USER_LOOKUP_ERROR;
        }
    }
    else {
        ret = USER_LOOKUP_SUCCESS;
    }

    return ret;
}

static const char authKeysDefault[] = ".ssh/authorized_keys";
static char authKeysPattern[32] = {0};

void SetAuthKeysPattern(const char* pattern)
{
    if (pattern != NULL) {
        WMEMSET(authKeysPattern, 0, sizeof(authKeysPattern));
        WSTRNCPY(authKeysPattern, pattern, sizeof(authKeysPattern));
    }
}

static int ResolveAuthKeysPath(const char* homeDir, char* resolved)
{
    int ret = WS_SUCCESS;
    char* idx;
    int homeDirSz;
    const char* suffix = authKeysDefault;

    if (homeDir == NULL || resolved == NULL) {
        ret = WS_BAD_ARGUMENT;
    }

    if (ret == WS_SUCCESS) {
        if (*authKeysPattern != 0) {
            /* TODO: token substitutions (e.g. %h) */
            if (*authKeysPattern == '/') {
                /* TODO: handle absolute path case */
                ret = WS_FATAL_ERROR;
            }
            else {
                suffix = authKeysPattern;
            }
        }
    }
    if (ret == WS_SUCCESS) {
        idx = resolved;
        homeDirSz = XSTRLEN(homeDir);
        XMEMCPY(idx, homeDir, homeDirSz);
        idx += homeDirSz;
        *(idx++) = '/';
        /* Intentionally copying the null term from suffix. */
        XMEMCPY(idx, suffix, WSTRLEN(suffix));
    }

    return ret;
}

static int CheckPublicKeyUnix(const byte* name, const byte* key, word32 keySz)
{
    int ret = WS_SUCCESS;
    struct passwd* pwInfo;
    char* authKeysFile = NULL;
    XFILE f;
    enum {
        /* TODO: Probably needs to be even bigger for larger key sizes. */
        MAX_LINE_SZ = 500,
        MAX_PATH_SZ = 80
    };
    char* lineBuf = NULL;
    char* current;
    word32 currentSz;
    int foundKey = 0;
    int rc;
    char authKeysPath[MAX_PATH_SZ];
    
    errno = 0;
    pwInfo = getpwnam((const char*)name);
    if (pwInfo == NULL) {
        if (errno != 0) {
            wolfSSH_Log(WS_LOG_ERROR, "[SSHD] Error calling getpwnam for user "
                                     "%s.", name);
            ret = WS_ERROR;
        }
    }
    if (ret == WS_SUCCESS) {
        WMEMSET(authKeysPath, 0, sizeof(authKeysPath));
        ret = ResolveAuthKeysPath(pwInfo->pw_dir, authKeysPath);
    }
    if (ret == WS_SUCCESS) {
        f = XFOPEN(authKeysPath, "rb");
        if (f == XBADFILE) {
            wolfSSH_Log(WS_LOG_ERROR, "[SSHD] Unable to open %s",
                        authKeysPath);
            ret = WS_BAD_FILE_E;
        }
    }
    if (ret == WS_SUCCESS) {
        lineBuf = (char*)WMALLOC(MAX_LINE_SZ, NULL, DYNTYPE_BUFFER);
        if (lineBuf == NULL) {
            ret = WS_MEMORY_E;
        }
    }
    while (ret == WS_SUCCESS &&
           (current = XFGETS(lineBuf, MAX_LINE_SZ, f)) != NULL) {
        currentSz = XSTRLEN(current);

        /* remove leading spaces */
        while (currentSz > 0 && current[0] == ' ') {
            currentSz = currentSz - 1;
            current   = current + 1;
        }

        if (currentSz <= 1) {
            continue; /* empty line */
        }

        if (current[0] == '#') {
            continue; /* commented out line */
        }

        rc = CheckAuthKeysLine(current, currentSz, key, keySz);
        if (rc == 1) {
            foundKey = 1;
            break;
        }
        else if (rc < 0) {
            ret = rc;
            break;
        }
    }
    XFCLOSE(f);

    if (ret == WS_SUCCESS && !foundKey) {
        ret = WS_ERROR;
    }

    if (lineBuf != NULL) {
        WFREE(lineBuf, NULL, DYNTYPE_BUFFER);
    }
    if (authKeysFile != NULL) {
        WFREE(authKeysFile, NULL, DYNTYPE_STRING);
    }

    return ret;
}
#endif /* !_WIN32*/

static int CheckUser(const char* name)
{
    int ret = USER_LOOKUP_FAILURE;

#ifdef _WIN32
    /* TODO: Implement for Windows. */
#else
    ret = CheckUserUnix(name);
#endif

    if (ret == USER_LOOKUP_FAILURE) {
        wolfSSH_Log(WS_LOG_INFO, "[SSHD] User %s doesn't exist.", name);
    }
    else if (ret == USER_LOOKUP_ERROR) {
        wolfSSH_Log(WS_LOG_INFO, "[SSHD] Error looking up user %s.", name);
    }
    else {
        wolfSSH_Log(WS_LOG_INFO, "[SSHD] User ok.");
    }

    return ret;
}

static int CheckPublicKey(const byte* name, const byte* key, word32 keySz)
{
    int ret = 0;

#ifdef _WIN32
    /* TODO: Implement for Windows. */
#else
    ret = CheckPublicKeyUnix(name, key, keySz);
#endif

    return ret;
}

int DefaultUserAuth(byte authType, WS_UserAuthData* authData, void* ctx)
{
    int ret = WOLFSSH_USERAUTH_FAILURE;

    (void)ctx;
    /* TODO: Auth will need some info from the config. For example, the auth
     * keys file path or the allowed users, if not all users are allowed. Could
     * pass the config in the ctx pointer...
     */

    if (authType != WOLFSSH_USERAUTH_PASSWORD &&
#ifdef WOLFSSH_ALLOW_USERAUTH_NONE
        authType != WOLFSSH_USERAUTH_NONE &&
#endif
        authType != WOLFSSH_USERAUTH_PUBLICKEY) {

        ret = WOLFSSH_USERAUTH_INVALID_AUTHTYPE;
    }

    /* Check user exists. */
    if (ret == WOLFSSH_USERAUTH_SUCCESS) {
        /* TODO: Is authData and its members guaranteed to be non-NULL? */
        if (CheckUser((const char*)authData->username) <= 0) {
            ret = WOLFSSH_USERAUTH_INVALID_USER;
        }
    }

    /* Check if password is valid for this user. */
    if (authData->type == WOLFSSH_USERAUTH_PASSWORD) {
        if (CheckPassword(authData->username, authData->sf.password.password,
                authData->sf.password.passwordSz) == WS_SUCCESS) {
            wolfSSH_Log(WS_LOG_INFO, "[SSHD] Password ok.");
            ret = WOLFSSH_USERAUTH_SUCCESS;
        }
        else {
            wolfSSH_Log(WS_LOG_INFO, "[SSHD] Password incorrect.");
            ret = WOLFSSH_USERAUTH_INVALID_PASSWORD;
        }
    }
    /* Check if public key is in this user's authorized_keys file. */
    else if (authData->type == WOLFSSH_USERAUTH_PUBLICKEY) {
        if (CheckPublicKey(authData->username, authData->sf.publicKey.publicKey,
                authData->sf.publicKey.publicKeySz) == WS_SUCCESS) {
            wolfSSH_Log(WS_LOG_INFO, "[SSHD] Public key ok.");
            ret = WOLFSSH_USERAUTH_SUCCESS;
        }
        else {
            wolfSSH_Log(WS_LOG_INFO, "[SSHD] Public key not authorized.");
            ret = WOLFSSH_USERAUTH_INVALID_PUBLICKEY;
        }
    }

    return ret;
}
#endif /* WOLFSSH_SSHD */

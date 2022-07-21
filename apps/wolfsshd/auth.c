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

#ifdef __linux__
    #define _XOPEN_SOURCE
#endif
#include <unistd.h>

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

#include "wolfsshd.h"

#ifndef _WIN32
#include <sys/types.h>
#include <pwd.h>
#include <shadow.h>
#include <errno.h>
#endif

struct WOLFSSHD_AUTH {
    CallbackCheckUser      CheckUserCb;
    CallbackCheckPassword  CheckPasswordCb;
    CallbackCheckPublicKey CheckPublicKeyCb;
    WOLFSSHD_CONFIG* conf;
    void* heap;
};


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

enum {
    WSSHD_AUTH_FAILURE =  0,
    WSSHD_AUTH_SUCCESS =  1
};

static int CheckAuthKeysLine(char* line, word32 lineSz, const byte* key,
                             word32 keySz)
{
    int ret = WSSHD_AUTH_SUCCESS;
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

    if (ret == WSSHD_AUTH_SUCCESS) {
        if ((type = WSTRTOK(line, " ", &last)) == NULL) {
            ret = WS_FATAL_ERROR;
        }
        else if ((keyCandBase64 = WSTRTOK(NULL, " ", &last)) == NULL) {
            ret = WS_FATAL_ERROR;
        }
    }
    if (ret == WSSHD_AUTH_SUCCESS) {
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
    if (ret == WSSHD_AUTH_SUCCESS) {
        keyCandBase64Sz = (word32)XSTRLEN(keyCandBase64);
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
    if (ret == WSSHD_AUTH_SUCCESS) {
        if (keyCandSz != keySz || WMEMCMP(key, keyCand, keySz) != 0) {
            ret = WSSHD_AUTH_FAILURE;
        }
    }

    if (keyCand != NULL) {
        WFREE(keyCand, NULL, DYNTYPE_BUFFER);
    }

    return ret;
}

#ifndef _WIN32

#ifdef WOLFSSH_USE_PAM
static int CheckPasswordPAM(const byte* usr, const byte* pw, int pwSz)
{
    (void)usr;
    (void)pw;
    (void)pwSz;
    return 0;
}
#else

#if defined(WOLFSSH_HAVE_LIBCRYPT)
static int ExtractSalt(char* hash, char** salt, int saltSz)
{
    int ret = WS_SUCCESS;
    int idx = 0;
    char* p;

    if (hash == NULL || salt == NULL || *salt == NULL || saltSz <= 0) {
        ret = WS_SUCCESS;
    }

    if (ret == 0) {
        if (hash[idx] != '$') {
            ret = WS_FATAL_ERROR;
        }
        else {
            ++idx;
            if (idx >= saltSz) {
                ret = WS_BUFFER_E;
            }
        }
    }
    if (ret == 0) {
        p = strstr(hash + idx, "$");
        if (p == NULL) {
            ret = -1;
        }
        else {
            idx += (p - hash);
            if (idx >= saltSz) {
                ret = WS_BUFFER_E;
            }
        }
    }
    if (ret == 0) {
        p = strstr(p + 1, "$");
        if (p == NULL) {
            ret = WS_FATAL_ERROR;
        }
        else {
            idx += (p - (hash + idx) + 1);
            if (idx >= saltSz) {
                ret = WS_BUFFER_E;
            }
        }
    }
    if (ret == 0) {
        memcpy(*salt, hash, idx);
        (*salt)[idx] = 0;
    }

    return ret;
}
#endif /* WOLFSSH_HAVE_LIBCRYPT */

#if defined(WOLFSSH_HAVE_LIBCRYPT) || defined(WOLFSSH_HAVE_LIBLOGIN)
static int CheckPasswordHashUnix(const char* input, char* stored)
{
    int ret = WSSHD_AUTH_SUCCESS;
    char* hashedInput;

    if (input == NULL || stored == NULL) {
        ret = WS_BAD_ARGUMENT;
    }

    if (ret == WSSHD_AUTH_SUCCESS) {
        hashedInput = crypt(input, stored);
        if (hashedInput == NULL) {
            ret = WS_FATAL_ERROR;
        }
        else {
            if (WMEMCMP(hashedInput, stored, WSTRLEN(stored)) != 0) {
                ret = WSSHD_AUTH_FAILURE;
            }
        }
    }

    return ret;
}
#endif /* WOLFSSH_HAVE_LIBCRYPT || WOLFSSH_HAVE_LIBLOGIN */

static int CheckPasswordUnix(const char* usr, const byte* pw, word32 pwSz)
{
    int ret = WS_SUCCESS;
    char* pwStr = NULL;
    struct passwd* pwInfo;
    struct spwd* shadowInfo;
    /* The hash of the user's password stored on the system. */
    char* storedHash;
    char* storedHashCpy = NULL;

    if (usr == NULL || pw == NULL) {
        ret = WS_BAD_ARGUMENT;
    }

    if (ret == WS_SUCCESS) {
        pwStr = (char*)WMALLOC(pwSz + 1, NULL, DYNTYPE_STRING);
        if (pwStr == NULL) {
            ret = WS_MEMORY_E;
        }
        else {
            XMEMCPY(pwStr, pw, pwSz);
            pwStr[pwSz] = 0;
        }
    }

    pwInfo = getpwnam((const char*)usr);
    if (pwInfo == NULL) {
        /* user name not found on system */
        ret = WS_FATAL_ERROR;
    }

    if (ret == WS_SUCCESS) {
        if (pwInfo->pw_passwd[0] == 'x') {
        #ifdef WOLFSSH_HAVE_LIBCRYPT
            shadowInfo = getspnam((const char*)usr);
        #else
            shadowInfo = getspnam((char*)usr);
        #endif
            if (shadowInfo == NULL) {
                wolfSSH_Log(WS_LOG_ERROR,
                    "[SSHD] Error getting user password info");
                wolfSSH_Log(WS_LOG_ERROR,
                    "[SSHD] Possibly permisions level error?"
                    " i.e SSHD not ran as sudo");
                ret = WS_FATAL_ERROR;
            }
            else {
                storedHash = shadowInfo->sp_pwdp;
            }
        }
        else {
            storedHash = pwInfo->pw_passwd;
        }
    }
    if (ret == WS_SUCCESS) {
        storedHashCpy = WSTRDUP(storedHash, NULL, DYNTYPE_STRING);
        if (storedHash == NULL) {
            ret = WS_MEMORY_E;
        }
    }

    if (ret == WS_SUCCESS) {
    #if defined(WOLFSSH_HAVE_LIBCRYPT) || defined(WOLFSSH_HAVE_LIBLOGIN)
        ret = CheckPasswordHashUnix(pwStr, storedHashCpy);
    #else
        wolfSSH_Log(WS_LOG_ERROR, "[SSHD] No compiled in password check");
        ret = WS_NOT_COMPILED;
    #endif
    }

    if (pwStr != NULL) {
        WFREE(pwStr, NULL, DYNTYPE_STRING);
    }
    if (storedHashCpy != NULL) {
        WFREE(storedHashCpy, NULL, DYNTYPE_STRING);
    }

    return ret;
}
#endif /* WOLFSSH_USE_PAM */
#endif /* !_WIN32 */

#ifndef _WIN32
static int CheckUserUnix(const char* name) {
    int ret = WSSHD_AUTH_FAILURE;
    struct passwd* pwInfo;

    wolfSSH_Log(WS_LOG_INFO, "[SSHD] Unix check user");
    errno = 0;
    pwInfo = getpwnam(name);
    if (pwInfo == NULL) {
        if (errno != 0) {
            wolfSSH_Log(WS_LOG_ERROR, "[SSHD] Error calling getpwnam for user "
                                      "%s.", name);
            ret = WS_FATAL_ERROR;
        }
    }
    else {
        ret = WSSHD_AUTH_SUCCESS;
    }

    return ret;
}

static const char authKeysDefault[] = ".ssh/authorized_keys";
static char authKeysPattern[32] = {0};

void SetAuthKeysPattern(const char* pattern)
{
    if (pattern != NULL) {
        WMEMSET(authKeysPattern, 0, sizeof(authKeysPattern));
        WSTRNCPY(authKeysPattern, pattern, sizeof(authKeysPattern) - 1);
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
        homeDirSz = (int)XSTRLEN(homeDir);
        XMEMCPY(idx, homeDir, homeDirSz);
        idx += homeDirSz;
        *(idx++) = '/';
        /* Intentionally copying the null term from suffix. */
        XMEMCPY(idx, suffix, WSTRLEN(suffix));
    }

    return ret;
}

static int CheckPublicKeyUnix(const char* name, const byte* key, word32 keySz)
{
    int ret = WSSHD_AUTH_SUCCESS;
    int rc;
    struct passwd* pwInfo;
    char* authKeysFile = NULL;
    XFILE f = NULL;
    enum {
        /* TODO: Probably needs to be even bigger for larger key sizes. */
        MAX_LINE_SZ = 500,
        MAX_PATH_SZ = 80
    };
    char* lineBuf = NULL;
    char* current;
    word32 currentSz;
    int foundKey = 0;
    char authKeysPath[MAX_PATH_SZ];

    errno = 0;
    pwInfo = getpwnam((const char*)name);
    if (pwInfo == NULL) {
        if (errno != 0) {
            wolfSSH_Log(WS_LOG_ERROR, "[SSHD] Error calling getpwnam for user "
                                     "%s.", name);
            ret = WS_FATAL_ERROR;
        }
    }
    if (ret == WSSHD_AUTH_SUCCESS) {
        WMEMSET(authKeysPath, 0, sizeof(authKeysPath));
        rc = ResolveAuthKeysPath(pwInfo->pw_dir, authKeysPath);
        if (rc != WS_SUCCESS) {
            wolfSSH_Log(WS_LOG_ERROR, "[SSHD] Failed to resolve authorized keys"
                                      " file path.");
            ret = rc;
        }
    }
    if (ret == WSSHD_AUTH_SUCCESS) {
        f = XFOPEN(authKeysPath, "rb");
        if (f == XBADFILE) {
            wolfSSH_Log(WS_LOG_ERROR, "[SSHD] Unable to open %s",
                        authKeysPath);
            ret = WS_BAD_FILE_E;
        }
    }
    if (ret == WSSHD_AUTH_SUCCESS) {
        lineBuf = (char*)WMALLOC(MAX_LINE_SZ, NULL, DYNTYPE_BUFFER);
        if (lineBuf == NULL) {
            ret = WS_MEMORY_E;
        }
    }
    while (ret == WSSHD_AUTH_SUCCESS &&
           (current = XFGETS(lineBuf, MAX_LINE_SZ, f)) != NULL) {
        currentSz = (word32)XSTRLEN(current);

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
        if (rc == WSSHD_AUTH_SUCCESS) {
            foundKey = 1;
            break;
        }
        else if (rc < 0) {
            ret = rc;
            break;
        }
    }
    XFCLOSE(f);

    if (ret == WSSHD_AUTH_SUCCESS && !foundKey) {
        ret = WSSHD_AUTH_FAILURE;
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


static int DoCheckUser(const char* usr, WOLFSSHD_AUTH* auth)
{
    int ret = WOLFSSH_USERAUTH_FAILURE;
    int rc;

    wolfSSH_Log(WS_LOG_INFO, "[SSHD] Checking user name %s", usr);
    rc = auth->CheckUserCb(usr);
    if (rc == WSSHD_AUTH_SUCCESS) {
        wolfSSH_Log(WS_LOG_INFO, "[SSHD] User ok.");
        ret = WOLFSSH_USERAUTH_SUCCESS;
    }
    else if (ret == WSSHD_AUTH_FAILURE) {
        wolfSSH_Log(WS_LOG_INFO, "[SSHD] User %s doesn't exist.", usr);
        ret = WOLFSSH_USERAUTH_INVALID_USER;
    }
    else {
        wolfSSH_Log(WS_LOG_ERROR, "[SSHD] Error looking up user %s.", usr);
        ret = WOLFSSH_USERAUTH_FAILURE;
    }
    return ret;
}


/* @TODO this will take in a pipe or equivilant to talk to a privliged thread
 * rathar than having WOLFSSHD_AUTH directly with privilige seperation */
static int RequestAuthentication(const char* usr, int type, const byte* data,
    int dataSz, WOLFSSHD_AUTH* auth)
{
    int ret;

    ret = DoCheckUser(usr, auth);
    if (ret == WOLFSSH_USERAUTH_SUCCESS && type == WOLFSSH_USERAUTH_PASSWORD) {
        int rc;

        /* Check if password is valid for this user. */
        /* first handle empty password cases */
        if (dataSz == 0 && wolfSSHD_ConfigOptionEnabled(auth->conf,
            WOLFSSHD_EMPTY_PASSWORD) != 1) {
            wolfSSH_Log(WS_LOG_ERROR, "[SSHD] Empty passwords not allowed!");
            ret = WOLFSSH_USERAUTH_FAILURE;
        }
        else {
            rc = auth->CheckPasswordCb(usr, data, dataSz);
            if (rc == WSSHD_AUTH_SUCCESS) {
                wolfSSH_Log(WS_LOG_INFO, "[SSHD] Password ok.");
            }
            else if (rc == WSSHD_AUTH_FAILURE) {
                wolfSSH_Log(WS_LOG_INFO, "[SSHD] Password incorrect.");
                ret = WOLFSSH_USERAUTH_INVALID_PASSWORD;
            }
            else {
                wolfSSH_Log(WS_LOG_ERROR, "[SSHD] Error checking password.");
                ret = WOLFSSH_USERAUTH_FAILURE;
            }
        }
    }


    if (ret == WOLFSSH_USERAUTH_SUCCESS && type == WOLFSSH_USERAUTH_PUBLICKEY) {
        int rc;

        rc = auth->CheckPublicKeyCb(usr, data, dataSz);
        if (rc == WSSHD_AUTH_SUCCESS) {
            wolfSSH_Log(WS_LOG_INFO, "[SSHD] Public key ok.");
            ret = WOLFSSH_USERAUTH_SUCCESS;
        }
        else if (rc == WSSHD_AUTH_FAILURE) {
            wolfSSH_Log(WS_LOG_INFO, "[SSHD] Public key not authorized.");
            ret = WOLFSSH_USERAUTH_INVALID_PUBLICKEY;
        }
        else {
            wolfSSH_Log(WS_LOG_ERROR, "[SSHD] Error checking public key.");
            ret = WOLFSSH_USERAUTH_FAILURE;
        }
    }

    return ret;
}


int DefaultUserAuth(byte authType, WS_UserAuthData* authData, void* ctx)
{
    int ret = WOLFSSH_USERAUTH_SUCCESS;
    WOLFSSHD_AUTH* auth;

    if (ctx == NULL) {
        wolfSSH_Log(WS_LOG_ERROR, "[SSHD] No auth callbacks passed in");
        return WOLFSSH_USERAUTH_FAILURE;
    }
    else {
        auth = (WOLFSSHD_AUTH*)ctx;
        if (auth->CheckUserCb == NULL) {
            wolfSSH_Log(WS_LOG_ERROR, "[SSHD] No way to check the user is set");
            return WOLFSSH_USERAUTH_FAILURE;
        }
    }

    if (authData == NULL) {
        wolfSSH_Log(WS_LOG_ERROR, "[SSHD] No authData passed in");
        return WOLFSSH_USERAUTH_FAILURE;
    }

    if (authType != WOLFSSH_USERAUTH_PASSWORD &&
#ifdef WOLFSSH_ALLOW_USERAUTH_NONE
        authType != WOLFSSH_USERAUTH_NONE &&
#endif
        authType != WOLFSSH_USERAUTH_PUBLICKEY) {

        ret = WOLFSSH_USERAUTH_INVALID_AUTHTYPE;
    }

    /* call to possibly privilaged authentecator for password check */
    if (ret == WOLFSSH_USERAUTH_SUCCESS &&
            authData->type == WOLFSSH_USERAUTH_PASSWORD) {
        ret = RequestAuthentication((const char*)authData->username,
            authData->type,
            authData->sf.password.password,
            authData->sf.password.passwordSz, auth);
    }

    /* call to possibly privilaged authentecator for public key check */
    if (ret == WOLFSSH_USERAUTH_SUCCESS &&
            authData->type == WOLFSSH_USERAUTH_PUBLICKEY) {
        ret = RequestAuthentication((const char*)authData->username,
            authData->type,
            authData->sf.publicKey.publicKey,
            authData->sf.publicKey.publicKeySz, auth);
    }

    return ret;
}


static int SetDefaultUserCheck(WOLFSSHD_AUTH* auth)
{
    int ret = WS_NOT_COMPILED;

#ifdef _WIN32
    /* TODO: Implement for Windows. */
#else
    wolfSSH_Log(WS_LOG_INFO, "[SSHD] Setting default Unix user name check");
    auth->CheckUserCb = CheckUserUnix;
    ret = WS_SUCCESS;
#endif

    return ret;
}


static int SetDefaultPasswordCheck(WOLFSSHD_AUTH* auth)
{
    int ret = WS_NOT_COMPILED;

#ifdef _WIN32
    /* TODO: Add CheckPasswordWin. */
#elif defined(WOLFSSH_USE_PAM)
    wolfSSH_Log(WS_LOG_INFO, "[SSHD] Setting PAM password check");
    auth->CheckPasswordCb = CheckPasswordPAM;
    ret = WS_SUCCESS;
#else
    wolfSSH_Log(WS_LOG_INFO, "[SSHD] Setting Unix password check");
    auth->CheckPasswordCb = CheckPasswordUnix;
    ret = WS_SUCCESS;
#endif
    return ret;
}


static int SetDefaultPublicKeyCheck(WOLFSSHD_AUTH* auth)
{
    int ret = WS_NOT_COMPILED;

#ifdef _WIN32
    /* TODO: Implement for Windows. */
#else
    wolfSSH_Log(WS_LOG_INFO, "[SSHD] Setting Unix public key check");
    auth->CheckPublicKeyCb = CheckPublicKeyUnix;
    ret = WS_SUCCESS;
#endif
    return ret;
}


/* Sets the default functions to be used for authentication of peer.
 * Later the default functions could be overriden if needed.
 * returns a newly created WOLFSSHD_AUTH struct success */
WOLFSSHD_AUTH * wolfSSHD_CreateUserAuth(void* heap, WOLFSSHD_CONFIG* conf)
{
    WOLFSSHD_AUTH* auth;

    auth = (WOLFSSHD_AUTH*)WMALLOC(sizeof(WOLFSSHD_AUTH), heap, DYNTYPE_SSHD);
    if (auth != NULL) {
        int ret;

        auth->heap = heap;
        auth->conf = conf;

        /* set the default user checking based on build */
        ret = SetDefaultUserCheck(auth);
        if (ret != WS_SUCCESS) {
            wolfSSH_Log(WS_LOG_ERROR, "[SSHD] Error setting default user check.");
        }

        /* set the default password checking based on build */
        if (ret == WS_SUCCESS) {
            ret = SetDefaultPasswordCheck(auth);
            if (ret != WS_SUCCESS) {
                wolfSSH_Log(WS_LOG_ERROR, "[SSHD] Error setting default "
                    "password check.");
            }
        }

        /* set the default public key checking based on build */
        if (ret == WS_SUCCESS) {
            ret = SetDefaultPublicKeyCheck(auth);
            if (ret != WS_SUCCESS) {
                wolfSSH_Log(WS_LOG_ERROR, "[SSHD] Error setting default "
                    "public key check.");
            }
        }

        /* error case in setting one of the default callbacks */
        if (ret != WS_SUCCESS) {
            (void)wolfSSHD_FreeUserAuth(auth);
            auth = NULL;
        }
    }


    return auth;
}


/* returns WS_SUCCESS on success */
int wolfSSHD_FreeUserAuth(WOLFSSHD_AUTH* auth)
{
    if (auth != NULL) {
        WFREE(auth, auth->heap, DYNTYPE_SSHD);
    }
    return WS_SUCCESS;
}
#endif /* WOLFSSH_SSHD */

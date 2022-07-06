/* wolfauth.c
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

#ifdef NO_INLINE
    #include <wolfssh/misc.h>
#else
    #define WOLFSSH_MISC_INCLUDED
    #include "src/misc.c"
#endif

#include "wolfauth.h"

#include <unistd.h>

#include <sys/types.h>
#include <pwd.h>
#include <uuid/uuid.h>

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
#endif /* WOLFSSH_SSHD */

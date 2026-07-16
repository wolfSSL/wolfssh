/* auth.h
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

#ifndef WOLFAUTH_H
#define WOLFAUTH_H

#ifndef WOLFSSH_SSHD_USER
    #define WOLFSSH_SSHD_USER sshd
#endif
#define WOLFSSH_USER_GET_STRING(x) #x
#define WOLFSSH_USER_STRING(x) WOLFSSH_USER_GET_STRING(x)

#if 0

typedef struct USER_NODE USER_NODE;

USER_NODE* AddNewUser(USER_NODE* list, byte type, const byte* username,
                       word32 usernameSz, const byte* value, word32 valueSz);
#endif

int DefaultUserAuth(byte authType, WS_UserAuthData* authData, void* ctx);
int DefaultUserAuthTypes(WOLFSSH* ssh, void* ctx);

typedef struct WOLFSSHD_AUTH WOLFSSHD_AUTH;

enum {
    WSSHD_AUTH_FAILURE =  0,
    WSSHD_AUTH_SUCCESS =  1
};

/*
 * Returns WSSHD_AUTH_SUCCESS if user found, WSSHD_AUTH_FAILURE if user not
 * found, and negative values if an error occurs during checking.
 */
typedef int (*CallbackCheckUser)(const char* usr);


/*
 * Returns WSSHD_AUTH_SUCCESS if user found, WSSHD_AUTH_FAILURE if user not
 * found, and negative values if an error occurs during checking.
 */
typedef int (*CallbackCheckPassword)(const char* usr, const byte* psw,
    word32 pswSz, WOLFSSHD_AUTH* authCtx);

/*
 * Returns WSSHD_AUTH_SUCCESS if public key ok, WSSHD_AUTH_FAILURE if key not
 * ok, and negative values if an error occurs during checking.
 */
typedef int (*CallbackCheckPublicKey)(const char* usr,
                                      const WS_UserAuthData_PublicKey* pubKey,
                                      const char* usrCaKeysFile,
                                      const char* authorizedKeysFile,
                                      WOLFSSHD_AUTH* authCtx);

WOLFSSHD_AUTH* wolfSSHD_AuthCreateUser(void* heap, const WOLFSSHD_CONFIG* conf);
int wolfSSHD_AuthFreeUser(WOLFSSHD_AUTH* auth);
int wolfSSHD_AuthReducePermissions(WOLFSSHD_AUTH* auth);
int wolfSSHD_AuthRaisePermissions(WOLFSSHD_AUTH* auth);
int wolfSSHD_AuthReducePermissionsUser(WOLFSSHD_AUTH* auth, WUID_T uid,
    WGID_T gid);
int wolfSSHD_AuthSetGroups(const WOLFSSHD_AUTH* auth, const char* usr,
    WGID_T gid);
long wolfSSHD_AuthGetGraceTime(const WOLFSSHD_AUTH* auth);
WOLFSSHD_CONFIG* wolfSSHD_AuthGetUserConf(const WOLFSSHD_AUTH* auth,
        const char* usr, const char* host,
        const char* localAdr, word16* localPort, const char* RDomain,
        const char* adr);
#ifdef _WIN32
HANDLE wolfSSHD_GetAuthToken(const WOLFSSHD_AUTH* auth);
int wolfSSHD_GetHomeDirectory(WOLFSSHD_AUTH* auth, WOLFSSH* ssh, WCHAR* out, int outSz);
#endif

/* Secure open for trusted files, shared by the authorized_keys path (auth.c)
 * and the trust-anchor loads in wolfsshd.c (host key, host cert, user CA keys).
 * See the definition in auth.c for the meaning of each argument. */
int wolfSSHD_OpenSecureFile(const char* path, WUID_T ownerUid,
    int rejectReadable, void* heap, WFILE** out);

#ifdef WOLFSSHD_UNIT_TEST
#ifndef _WIN32
extern int (*wsshd_setregid_cb)(WGID_T, WGID_T);
extern int (*wsshd_setreuid_cb)(WUID_T, WUID_T);
extern int (*wsshd_setegid_cb)(WGID_T);
extern int (*wsshd_seteuid_cb)(WUID_T);
extern struct passwd* (*wsshd_getpwnam_cb)(const char*);
extern int (*wsshd_setgroups_cb)(int, const WGID_T*);
extern int (*wsshd_getgrouplist_cb)(const char*, WGID_T, WGID_T*, int*);
int wolfSSHD_GetUserGroupNames(void* heap, const char* usr, WGID_T primaryGid,
        char*** outNames, word32* outCount);
void wolfSSHD_FreeUserGroupNames(void* heap, char** names, word32 count);
int SearchForPubKey(const char* path, const char* authKeysFile,
                    const WS_UserAuthData_PublicKey* pubKeyCtx,
                    WUID_T uid, int strictModes);
#endif
#if defined(WOLFSSH_HAVE_LIBCRYPT) || defined(WOLFSSH_HAVE_LIBLOGIN)
int CheckPasswordHashUnix(const char* input, char* stored);
#endif
int CheckAuthKeysLine(char* line, word32 lineSz, const byte* key,
                      word32 keySz);
int ResolveAuthKeysPath(const char* homeDir, const char* pattern,
                        const char* user, char* resolved);
int CAKeysFileDiffers(const char* a, const char* b);
int MatchUPNToUser(const char* usr, const char* name, int nameSz,
                   const char* allowList);
int wolfSSHD_GetUserAuthTypes(const WOLFSSHD_CONFIG* usrConf);
#endif
#endif /* WOLFAUTH_H */

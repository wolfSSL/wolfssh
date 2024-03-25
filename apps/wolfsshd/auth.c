/* auth.c
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

#ifdef __linux__
    #define _XOPEN_SOURCE
    #ifndef _GNU_SOURCE
        #define _GNU_SOURCE
    #endif
#endif

#ifndef _WIN32
#include <unistd.h>
#else
/* avoid macro redefinition warnings on STATUS values when include ntstatus.h */
#undef UMDF_USING_NTSTATUS
#define UMDF_USING_NTSTATUS
#undef UNICODE
#define UNICODE
#endif

#include <wolfssh/ssh.h>
#include <wolfssh/internal.h>
#include <wolfssh/log.h>
#include <wolfssl/wolfcrypt/wc_port.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/coding.h>

#ifdef WOLFSSL_FPKI
#include <wolfssl/wolfcrypt/asn.h>
#endif

#ifdef NO_INLINE
    #include <wolfssh/misc.h>
#else
    #define WOLFSSH_MISC_INCLUDED
    #include "src/misc.c"
#endif

#include "configuration.h"

#ifndef _WIN32
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <errno.h>
#endif

#if !defined(_WIN32) && !(defined(__OSX__) || defined(__APPLE__))
#include <shadow.h>
#define HAVE_SHADOW
#endif

struct WOLFSSHD_AUTH {
    CallbackCheckUser      checkUserCb;
    CallbackCheckPassword  checkPasswordCb;
    CallbackCheckPublicKey checkPublicKeyCb;
    const WOLFSSHD_CONFIG* conf;
#if defined(_WIN32)
    HANDLE token; /* a users token */
#endif
    int gid;
    int uid;
    int sGid; /* saved gid */
    int sUid; /* saved uid */
    int attempts;
    void* heap;
};

#ifndef WOLFSSHD_MAX_PASSWORD_ATTEMPTS
    #define WOLFSSHD_MAX_PASSWORD_ATTEMPTS 3
#endif

#ifndef MAX_LINE_SZ
    #define MAX_LINE_SZ 900
#endif
#ifndef MAX_PATH_SZ
    #define MAX_PATH_SZ 80
#endif

#if 0
/* this could potentially be useful in a deeply embeded future port */

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
#endif

enum {
    WSSHD_AUTH_FAILURE =  0,
    WSSHD_AUTH_SUCCESS =  1
};

/* TODO: Can use wolfSSH_ReadKey_buffer? */
static int CheckAuthKeysLine(char* line, word32 lineSz, const byte* key,
                             word32 keySz)
{
    int ret = WSSHD_AUTH_SUCCESS;
    char* type = NULL;
    char* keyCandBase64 = NULL; /* cand == candidate */
    word32 keyCandBase64Sz;
    byte* keyCand = NULL;
    word32 keyCandSz = 0;
    char* last = NULL;

    enum {
    #ifdef WOLFSSH_CERTS
        NUM_ALLOWED_TYPES = 9
    #else
        NUM_ALLOWED_TYPES = 5
    #endif
    };
    static const char* allowedTypes[NUM_ALLOWED_TYPES] = {
        "ssh-rsa",
        "ssh-ed25519",
        "ecdsa-sha2-nistp256",
        "ecdsa-sha2-nistp384",
        "ecdsa-sha2-nistp521",
    #ifdef WOLFSSH_CERTS
        "x509v3-ssh-rsa",
        "x509v3-ecdsa-sha2-nistp256",
        "x509v3-ecdsa-sha2-nistp384",
        "x509v3-ecdsa-sha2-nistp521",
    #endif
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
static int CheckPasswordPAM(const char* usr, const byte* pw, word32 pwSz)
{
    (void)usr;
    (void)pw;
    (void)pwSz;
    return 0;
}
#else

#if 0
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
#endif

#if defined(WOLFSSH_HAVE_LIBCRYPT) || defined(WOLFSSH_HAVE_LIBLOGIN)
static int CheckPasswordHashUnix(const char* input, char* stored)
{
    int ret = WSSHD_AUTH_SUCCESS;
    char* hashedInput;
    word32 hashedInputSz = 0, storedSz = 0;

    if (input == NULL || stored == NULL) {
        ret = WS_BAD_ARGUMENT;
    }

    /* empty password case */
    if (stored[0] == 0 && WSTRLEN(input) == 0) {
        wolfSSH_Log(WS_LOG_INFO,
                    "[SSHD] User logged in with empty password");
        return ret;
    }

    if (ret == WSSHD_AUTH_SUCCESS) {
        hashedInput = crypt(input, stored);
        if (hashedInput == NULL) {
            ret = WS_FATAL_ERROR;
        }
        else {
            hashedInputSz = (word32)WSTRLEN(hashedInput);
            storedSz = (word32)WSTRLEN(stored);

            if (storedSz == 0 || stored[0] == '*' ||
                    hashedInputSz == 0 || hashedInput[0] == '*' ||
                    hashedInputSz != storedSz ||
                    WMEMCMP(hashedInput, stored, storedSz) != 0) {
                ret = WSSHD_AUTH_FAILURE;
            }
        }
    }

    return ret;
}
#endif /* WOLFSSH_HAVE_LIBCRYPT || WOLFSSH_HAVE_LIBLOGIN */

static int CheckPasswordUnix(const char* usr, const byte* pw, word32 pwSz, WOLFSSHD_AUTH* authCtx)
{
    int ret = WS_SUCCESS;
    char* pwStr = NULL;
    struct passwd* pwInfo;
#ifdef HAVE_SHADOW
    struct spwd* shadowInfo;
#endif
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

    if (ret == WS_SUCCESS) {
        pwInfo = getpwnam((const char*)usr);
        if (pwInfo == NULL) {
            /* user name not found on system */
            ret = WS_FATAL_ERROR;
            wolfSSH_Log(WS_LOG_ERROR,
                    "[SSHD] User name not found on system");
        }
    }

    if (ret == WS_SUCCESS) {
    #ifdef HAVE_SHADOW
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
        else
    #endif
        {
            storedHash = pwInfo->pw_passwd;
        }
    }
    if (ret == WS_SUCCESS) {
        storedHashCpy = WSTRDUP(storedHash, NULL, DYNTYPE_STRING);
        if (storedHash == NULL) {
            wolfSSH_Log(WS_LOG_ERROR,
                    "[SSHD] Error getting stored hash copy");
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

    WOLFSSH_UNUSED(authCtx);
    return ret;
}
#endif /* WOLFSSH_USE_PAM */
#endif /* !_WIN32 */



static const char authKeysDefault[] = ".ssh/authorized_keys";
static char authKeysPattern[MAX_PATH_SZ] = { 0 };

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
                WSTRNCPY(resolved, authKeysPattern, MAX_PATH_SZ);
                return WS_SUCCESS;
            }
            else {
                suffix = authKeysPattern;
            }
        }
    }

    if (ret == WS_SUCCESS) {
        idx = resolved;
        homeDirSz = (int)XSTRLEN(homeDir);
        if (homeDirSz + 1 + WSTRLEN(suffix) >= MAX_PATH_SZ) {
            wolfSSH_Log(WS_LOG_ERROR,
                "[SSHD] Path for key file larger than max allowed");
            ret = WS_FATAL_ERROR;
        }

        if (ret == WS_SUCCESS) {
            XMEMCPY(idx, homeDir, homeDirSz);
            idx += homeDirSz;
            *(idx++) = '/';
            /* Intentionally copying the null term from suffix. */
            XMEMCPY(idx, suffix, WSTRLEN(suffix));
        }
    }

    return ret;
}

static int SearchForPubKey(const char* path, const WS_UserAuthData_PublicKey* pubKeyCtx)
{
    int ret = WSSHD_AUTH_SUCCESS;
    char authKeysPath[MAX_PATH_SZ];
    WFILE *f = XBADFILE;
    char* lineBuf = NULL;
    char* current;
    word32 currentSz;
    int foundKey = 0;
    int rc = 0;

    WMEMSET(authKeysPath, 0, sizeof(authKeysPath));
    rc = ResolveAuthKeysPath(path, authKeysPath);
    if (rc != WS_SUCCESS) {
        wolfSSH_Log(WS_LOG_ERROR, "[SSHD] Failed to resolve authorized keys"
            " file path.");
        ret = rc;
    }

    if (ret == WSSHD_AUTH_SUCCESS) {
        if (WFOPEN(NULL, &f, authKeysPath, "rb") != 0) {
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
        (current = WFGETS(lineBuf, MAX_LINE_SZ, f)) != NULL) {
        currentSz = (word32)WSTRLEN(current);

        /* remove leading spaces */
        while (currentSz > 0 && current[0] == ' ') {
            currentSz = currentSz - 1;
            current = current + 1;
        }

        if (currentSz <= 1) {
            continue; /* empty line */
        }

        if (current[0] == '#') {
            continue; /* commented out line */
        }

        rc = CheckAuthKeysLine(current, currentSz, pubKeyCtx->publicKey,
            pubKeyCtx->publicKeySz);
        if (rc == WSSHD_AUTH_SUCCESS) {
            foundKey = 1;
            break;
        }
        else if (rc < 0) {
            ret = rc;
            break;
        }
    }

    if (f != WBADFILE) {
        WFCLOSE(NULL, f);
    }

    if (ret == WSSHD_AUTH_SUCCESS && !foundKey) {
        ret = WSSHD_AUTH_FAILURE;
    }

    return ret;
}

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

static int CheckPublicKeyUnix(const char* name,
                              const WS_UserAuthData_PublicKey* pubKeyCtx,
                              const char* usrCaKeysFile, WOLFSSHD_AUTH* authCtx)
{
    int ret = WSSHD_AUTH_SUCCESS;
    struct passwd* pwInfo;

#ifdef WOLFSSH_OSSH_CERTS
    if (pubKeyCtx->isOsshCert) {
        int rc;
        byte* caKey = NULL;
        word32 caKeySz;
        const byte* caKeyType = NULL;
        word32 caKeyTypeSz;
        byte fingerprint[WC_SHA256_DIGEST_SIZE];

        if (pubKeyCtx->caKey == NULL ||
            pubKeyCtx->caKeySz != WC_SHA256_DIGEST_SIZE) {
            ret = WS_FATAL_ERROR;
        }

        if (ret == WSSHD_AUTH_SUCCESS) {
            f = XFOPEN(usrCaKeysFile, "rb");
            if (f == XBADFILE) {
                wolfSSH_Log(WS_LOG_ERROR, "[SSHD] Unable to open %s",
                            usrCaKeysFile);
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

            rc = wolfSSH_ReadKey_buffer((const byte*)current, currentSz,
                                        WOLFSSH_FORMAT_SSH, &caKey, &caKeySz,
                                        &caKeyType, &caKeyTypeSz, NULL);
            if (rc == WS_SUCCESS) {
                rc = wc_Hash(WC_HASH_TYPE_SHA256, caKey, caKeySz, fingerprint,
                             WC_SHA256_DIGEST_SIZE);
                if (rc == 0 && WMEMCMP(fingerprint, pubKeyCtx->caKey,
                                       WC_SHA256_DIGEST_SIZE) == 0) {
                    foundKey = 1;
                    break;
                }
            }
        }
    }
    else
    #endif /* WOLFSSH_OSSH_CERTS */
    {
        errno = 0;
        pwInfo = getpwnam((const char*)name);
        if (pwInfo == NULL) {
            if (errno != 0) {
                wolfSSH_Log(WS_LOG_ERROR, "[SSHD] Error calling getpwnam for user "
                                         "%s.", name);
            }
            ret = WS_FATAL_ERROR;
        }

        if (ret == WSSHD_AUTH_SUCCESS) {
            ret = SearchForPubKey(pwInfo->pw_dir, pubKeyCtx);
        }
    }

    WOLFSSH_UNUSED(usrCaKeysFile);
    WOLFSSH_UNUSED(authCtx);
    return ret;
}
#endif /* !_WIN32*/

#ifdef _WIN32

#include <ntstatus.h>
#include <Ntsecapi.h>
#include <Shlobj.h>

#include <UserEnv.h>
#include <KnownFolders.h>

/* Pulled in from Advapi32.dll */
extern BOOL WINAPI LogonUserExExW(LPTSTR usr,
    LPTSTR dmn,
    LPTSTR paswd,
    DWORD logonType,
    DWORD logonProv,
    PTOKEN_GROUPS tokenGrp,
    PHANDLE tokenPh,
    PSID* loginSid,
    PVOID* pBuffer,
    LPDWORD pBufferLen ,
    PQUOTA_LIMITS quotaLimits
);

#define MAX_USERNAME 256

static int _GetHomeDirectory(WOLFSSHD_AUTH* auth, const char* usr, WCHAR* out, int outSz)
{
    int ret = WS_SUCCESS;
    WCHAR usrW[MAX_USERNAME];
    wchar_t* homeDir;
    HRESULT hr;
    size_t wr;

    /* convert user name to Windows wchar type */
    mbstowcs_s(&wr, usrW, MAX_USERNAME, usr, MAX_USERNAME-1);

    hr = SHGetKnownFolderPath((REFKNOWNFOLDERID)&FOLDERID_Profile,
        0, wolfSSHD_GetAuthToken(auth), &homeDir);
    if (SUCCEEDED(hr)) {
        wcscpy_s(out, outSz, homeDir);
        CoTaskMemFree(homeDir);
    }
    else {
        PROFILEINFO pInfo = { 0 };

        /* failed with get known folder path, try with loading the user profile */
        pInfo.dwFlags = PI_NOUI;
        pInfo.lpUserName = usrW;
        if (LoadUserProfileW(wolfSSHD_GetAuthToken(auth), &pInfo) != TRUE) {
            wolfSSH_Log(WS_LOG_ERROR,
                "[SSHD] Error %d loading user %s", GetLastError(), usr);
            ret = WS_FATAL_ERROR;
        }

        /* get home directory env. for user */
        if (ret == WS_SUCCESS &&
            ExpandEnvironmentStringsW(L"%USERPROFILE%", out, outSz) == 0) {
            wolfSSH_Log(WS_LOG_ERROR,
                "[SSHD] Error getting user %s's home path", usr);
            ret = WS_FATAL_ERROR;
        }

        /* @TODO is unload of user needed here?
           UnloadUserProfileW(wolfSSHD_GetAuthToken(conn->auth), pInfo.hProfile);
         */
    }

    return ret;
}


int wolfSSHD_GetHomeDirectory(WOLFSSHD_AUTH* auth, WOLFSSH* ssh, WCHAR* out, int outSz)
{
    return _GetHomeDirectory(auth, wolfSSH_GetUsername(ssh), out, outSz);
}


/* Returns the users token from LogonUserW call */
HANDLE wolfSSHD_GetAuthToken(const WOLFSSHD_AUTH* auth)
{
    if (auth == NULL)
        return NULL;
    return auth->token;
}

static int CheckPasswordWIN(const char* usr, const byte* pw, word32 pwSz, WOLFSSHD_AUTH* authCtx)
{
    int ret;
    WCHAR* usrW = NULL;
    WCHAR* pwW  = NULL;
    WCHAR  dmW[] = L"."; /* currently hard set to use local domain */
    size_t usrWSz = 0;
    int    pwWSz  = 0;

    wolfSSH_Log(WS_LOG_INFO, "[SSHD] Windows check password");

    ret = WSSHD_AUTH_SUCCESS;

    usrWSz = WSTRLEN(usr) * sizeof(WCHAR);

    usrW = (WCHAR*)WMALLOC((usrWSz * sizeof(WCHAR)) + sizeof(WCHAR), authCtx->heap, DYNTYPE_SSHD);
    if (usrW == NULL) {
        wolfSSH_Log(WS_LOG_ERROR, "[SSHD] Ran out of memory");
        ret = WSSHD_AUTH_FAILURE;
    }

    if (ret == WSSHD_AUTH_SUCCESS) {
        size_t wr = 0;
        if (mbstowcs_s(&wr, usrW, usrWSz, usr, usrWSz-1) != 0) {
            ret = WSSHD_AUTH_FAILURE;
        }
    }

    if (ret == WSSHD_AUTH_SUCCESS) {
        pwWSz = MultiByteToWideChar(CP_UTF8, 0, pw, pwSz, NULL, 0);
        if (pwWSz <= 0) {
            ret = WSSHD_AUTH_FAILURE;
        }
    }

    if (ret == WSSHD_AUTH_SUCCESS) {
        pwW = (WCHAR*)WMALLOC((pwWSz * sizeof(WCHAR)) + sizeof(WCHAR), authCtx->heap, DYNTYPE_SSHD);
        if (pwW == NULL) {
            ret = WSSHD_AUTH_FAILURE;
        }
    }
    
    if (ret == WSSHD_AUTH_SUCCESS) {
        if (MultiByteToWideChar(CP_UTF8, 0, pw, pwSz, pwW, pwWSz) != pwSz) {
            ret = WSSHD_AUTH_FAILURE;
        }
        else {
            pwW[pwWSz] = L'\0';
        }
    }

    if (ret == WSSHD_AUTH_SUCCESS) {
        if (LogonUserExExW(usrW, dmW, pwW, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, NULL,
            &authCtx->token, NULL, NULL, NULL, NULL) != TRUE) {
            wolfSSH_Log(WS_LOG_ERROR, "[SSHD] Windows failed with error %d when login in as user %s, "
                "bad username or password", GetLastError(), usr);
            wolfSSH_Log(WS_LOG_INFO, "[SSHD] Check user is allowed to 'Log on as batch job'");
            ret = WSSHD_AUTH_FAILURE;
        }
    }

    if (usrW != NULL) {
        WFREE(usrW, authCtx->heap, DYNTYPE_SSHD);
    }

    if (pwW != NULL) {
        WFREE(pwW, authCtx->heap, DYNTYPE_SSHD);
    }

    return ret;
}


static int CheckUserWIN(const char* name)
{
    int ret = WSSHD_AUTH_FAILURE;

    wolfSSH_Log(WS_LOG_INFO, "[SSHD] Windows user check happens with password/public key check");

    ret = WSSHD_AUTH_SUCCESS;
 
    return ret;
}


/* Helper function to setup the user token in cases where public key
 * auth is used. Return WSSHD_AUTH_SUCCESS on success */
static int SetupUserTokenWin(const char* usr,
    const WS_UserAuthData_PublicKey* pubKeyCtx,
    const char* usrCaKeysFile, WOLFSSHD_AUTH* authCtx)
{
    int ret;
    WCHAR* usrW = NULL;
    WCHAR  dmW[] = L"."; /* currently hard set to use local domain */
    ULONG rc;
    HANDLE lsaHandle = NULL;
    ULONG authId = 0;
    void* authInfo = NULL;
    ULONG authInfoSz = 0;
    TOKEN_SOURCE sourceContext;

    size_t usrWSz;

    wolfSSH_Log(WS_LOG_INFO, "[SSHD] Windows public key get user token");

    ret = WSSHD_AUTH_SUCCESS;

    usrWSz = WSTRLEN(usr);
    usrW = (WCHAR*)WMALLOC((usrWSz + 1) * sizeof(WCHAR), NULL, DYNTYPE_SSHD);
    if (usrW == NULL) {
        ret = WS_MEMORY_E;
    }

    if (ret == WSSHD_AUTH_SUCCESS) {
        size_t wr;
        if (mbstowcs_s(&wr, usrW, usrWSz + 1, usr, usrWSz) != 0) {
            ret = WSSHD_AUTH_FAILURE;
        }
    }

    if (ret == WSSHD_AUTH_SUCCESS) {
        LSA_OPERATIONAL_MODE oMode;
        LSA_STRING processName;

        WMEMSET(&processName, 0, sizeof(LSA_STRING));
        processName.Buffer = "wolfsshd";
        processName.Length = (USHORT)WSTRLEN("wolfsshd");
        processName.MaximumLength = processName.Length + 1;


        if ((rc = LsaRegisterLogonProcess(&processName, &lsaHandle, &oMode)) != STATUS_SUCCESS) {
            wolfSSH_Log(WS_LOG_ERROR, "[SSHD] LSA Register Logon Process Error %d", LsaNtStatusToWinError(rc));
            ret = WSSHD_AUTH_FAILURE;
        }
    }

    if (ret == WSSHD_AUTH_SUCCESS) {
        LSA_STRING authName;

        WMEMSET(&authName, 0, sizeof(LSA_STRING));
        authName.Buffer = MSV1_0_PACKAGE_NAME;
        authName.Length = (USHORT)WSTRLEN(MSV1_0_PACKAGE_NAME);
        authName.MaximumLength = authName.Length + 1;
        if (rc = LsaLookupAuthenticationPackage(lsaHandle, &authName, &authId) != STATUS_SUCCESS) {
            wolfSSH_Log(WS_LOG_ERROR, "[SSHD] LSA Lookup Authentication Package Error %d", rc);
            ret = WSSHD_AUTH_FAILURE;
        }
    }

    if (ret == WSSHD_AUTH_SUCCESS) {
        /* size of logon struct plus computer and user name */
        authInfoSz = (ULONG)(sizeof(MSV1_0_S4U_LOGON) +
            (wcslen(usrW) + wcslen(dmW)) * sizeof(wchar_t));
        authInfo = (void*)WMALLOC(authInfoSz, NULL, DYNTYPE_SSHD);
        if (authInfo == NULL) {
            ret = WSSHD_AUTH_FAILURE;
        }
        else {
            MSV1_0_S4U_LOGON* l;

            WMEMSET(authInfo, 0, authInfoSz);
            l = (MSV1_0_S4U_LOGON*)authInfo;
            l->MessageType = MsV1_0S4ULogon;

            /* write user name after the MSV1_0_S4U_LOGON structure in buffer */
            l->UserPrincipalName.Length = (USHORT)(wcslen(usrW) * sizeof(wchar_t));
            l->UserPrincipalName.MaximumLength = l->UserPrincipalName.Length;
            l->UserPrincipalName.Buffer = (WCHAR*)((byte*)l + sizeof(MSV1_0_S4U_LOGON));
            memcpy_s(l->UserPrincipalName.Buffer, l->UserPrincipalName.Length, usrW, l->UserPrincipalName.Length);

            /* write domain name after the user name in buffer */
            l->DomainName.Length = (USHORT)(wcslen(dmW) * sizeof(wchar_t));
            l->DomainName.MaximumLength = l->UserPrincipalName.Length;
            l->DomainName.Buffer = (WCHAR*)((byte*)(l->UserPrincipalName.Buffer) + l->UserPrincipalName.Length);
            memcpy_s(l->DomainName.Buffer, l->DomainName.Length, dmW, l->DomainName.Length);
        }
    }

    if (ret == WSSHD_AUTH_SUCCESS) {
        strcpy_s(sourceContext.SourceName, TOKEN_SOURCE_LENGTH, "sshd");
        if (AllocateLocallyUniqueId(&sourceContext.SourceIdentifier) != TRUE) {
            wolfSSH_Log(WS_LOG_ERROR, "[SSHD] Windows failed to allocate locally unique source context id");
            ret = WSSHD_AUTH_FAILURE;
        }
    }

    if (ret == WSSHD_AUTH_SUCCESS) {
        LSA_STRING   originName;
        NTSTATUS     subStatus;
        QUOTA_LIMITS quotas;
        DWORD        profileSz;
        PKERB_INTERACTIVE_PROFILE profile = NULL;
        LUID logonId = { 0, 0 };

        WMEMSET(&originName, 0, sizeof(LSA_STRING));
        originName.Buffer = "wolfsshd";
        originName.Length = (USHORT)WSTRLEN("wolfsshd");
        originName.MaximumLength = originName.Length + 1;

        if ((rc = LsaLogonUser(lsaHandle, &originName, Network, authId, authInfo, authInfoSz, NULL, &sourceContext, &profile, &profileSz, &logonId, &authCtx->token, &quotas, &subStatus)) != STATUS_SUCCESS) {
            wolfSSH_Log(WS_LOG_ERROR, "[SSHD] Windows failed with status %X, SubStatus %d, when login in as user %s",
                rc, subStatus, usr);
            ret = WSSHD_AUTH_FAILURE;
        }

        /* currently not using the profile returned, free it here */
        if (profile != NULL) {
            LsaFreeReturnBuffer(profile);
        }
    }

    if (authInfo != NULL) {
        WFREE(authInfo, NULL, DYNTYPE_SSHD);
    }

    if (lsaHandle != NULL) {
        LsaDeregisterLogonProcess(lsaHandle);
    }

    return ret;
}

/* Uses Windows LSA for getting an impersination token */
static int CheckPublicKeyWIN(const char* usr,
    const WS_UserAuthData_PublicKey* pubKeyCtx,
    const char* usrCaKeysFile, WOLFSSHD_AUTH* authCtx)
{
    int ret;

    wolfSSH_Log(WS_LOG_INFO, "[SSHD] Windows check public key");

    ret = SetupUserTokenWin(usr, pubKeyCtx,usrCaKeysFile, authCtx);

    /* after successful logon check the public key sent */
    if (ret == WSSHD_AUTH_SUCCESS) {
        WCHAR h[MAX_PATH];

        if (_GetHomeDirectory(authCtx, usr, h, MAX_PATH) == WS_SUCCESS) {
            CHAR r[MAX_PATH];
            size_t rSz;

            if (wcstombs_s(&rSz, r, MAX_PATH, h, MAX_PATH - 1) != 0) {
                ret = WSSHD_AUTH_FAILURE;
            }

            if (ret == WSSHD_AUTH_SUCCESS) {
                r[rSz-1] = L'\0';

                ret = SearchForPubKey(r, pubKeyCtx);
                if (ret != WSSHD_AUTH_SUCCESS) {
                    wolfSSH_Log(WS_LOG_ERROR,
                        "[SSHD] Failed to find public key for user %s", usr);
                    ret = WSSHD_AUTH_FAILURE;
                }
            }
        }
        else {
            wolfSSH_Log(WS_LOG_ERROR,
                "[SSHD] Windows failed to get home directory for user %s", usr);
            ret = WSSHD_AUTH_FAILURE;
        }
    }

    return ret;
}
#endif /* _WIN32*/

/* return WOLFSSH_USERAUTH_SUCCESS on success */
static int DoCheckUser(const char* usr, WOLFSSHD_AUTH* auth)
{
    int ret = WOLFSSH_USERAUTH_SUCCESS;
    int rc;

    wolfSSH_Log(WS_LOG_INFO, "[SSHD] Checking user name %s", usr);

    if (wolfSSHD_ConfigGetPermitRoot(auth->conf) == 0) {
        if (XSTRCMP(usr, "root") == 0) {
            wolfSSH_Log(WS_LOG_ERROR, "[SSHD] Login as root not permited");
            ret = WOLFSSH_USERAUTH_REJECTED;
        }
    }

    if (ret == WOLFSSH_USERAUTH_SUCCESS) {
        rc = auth->checkUserCb(usr);
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
    }

    return ret;
}


/* @TODO this will take in a pipe or equivalent to talk to a privileged thread
 * rathar than having WOLFSSHD_AUTH directly with privilege separation */
static int RequestAuthentication(WS_UserAuthData* authData,
                                 WOLFSSHD_AUTH* authCtx)
{
    int ret;
    int rc;
    const char* usr;

    if (authData == NULL || authCtx == NULL) {
        return WOLFSSH_USERAUTH_FAILURE;
    }

    usr = (const char*)authData->username;
    ret = DoCheckUser(usr, authCtx);
    /* temporarily elevate permissions */
    if (ret == WOLFSSH_USERAUTH_SUCCESS &&
            wolfSSHD_AuthRaisePermissions(authCtx) != WS_SUCCESS) {
        wolfSSH_Log(WS_LOG_ERROR,
                "[SSHD] Failure to raise permissions for auth");
        ret = WOLFSSH_USERAUTH_FAILURE;
    }

    if (ret == WOLFSSH_USERAUTH_SUCCESS &&
        authData->type == WOLFSSH_USERAUTH_PASSWORD) {

        if (wolfSSHD_ConfigGetPwAuth(authCtx->conf) != 1) {
            wolfSSH_Log(WS_LOG_ERROR, "[SSHD] Password authentication not "
                        "allowed by configuration!");
            ret = WOLFSSH_USERAUTH_REJECTED;
        }
        /* Check if password is valid for this user. */
        /* first handle empty password cases */
        else if (authData->sf.password.passwordSz == 0 &&
                 wolfSSHD_ConfigGetPermitEmptyPw(authCtx->conf) != 1) {
            wolfSSH_Log(WS_LOG_ERROR, "[SSHD] Empty passwords not allowed by "
                        "configuration!");
            ret = WOLFSSH_USERAUTH_FAILURE;
        }
        else {
            rc = authCtx->checkPasswordCb(usr, authData->sf.password.password,
                                     authData->sf.password.passwordSz, authCtx);
            if (rc == WSSHD_AUTH_SUCCESS) {
                wolfSSH_Log(WS_LOG_INFO, "[SSHD] Password ok.");
            }
            else if (rc == WSSHD_AUTH_FAILURE) {
                wolfSSH_Log(WS_LOG_INFO, "[SSHD] Password incorrect.");
                ret = WOLFSSH_USERAUTH_INVALID_PASSWORD;

                authCtx->attempts--;
                if (authCtx->attempts == 0) {
                    wolfSSH_Log(WS_LOG_ERROR,
                        "[SSHD] Too many bad password attempts!");
                    ret =  WOLFSSH_USERAUTH_REJECTED;
                }
            }
            else {
                wolfSSH_Log(WS_LOG_ERROR, "[SSHD] Error checking password.");
                ret = WOLFSSH_USERAUTH_FAILURE;
            }
        }
    }


    if (ret == WOLFSSH_USERAUTH_SUCCESS &&
        authData->type == WOLFSSH_USERAUTH_PUBLICKEY) {

    #ifdef WOLFSSL_FPKI
        /* compare user name to UPN in certificate */
        if (authData->sf.publicKey.isCert) {
            DecodedCert* dCert;
        #ifdef WOLFSSH_SMALL_STACK
            dCert = (DecodedCert*)WMALLOC(sizeof(DecodedCert), NULL,
                DYNTYPE_CERT);
        #else
            DecodedCert sdCert;
            dCert = &sdCert;
        #endif

            if (dCert == NULL) {
                wolfSSH_Log(WS_LOG_ERROR, "[SSHD] Error creating cert struct");
                ret = WOLFSSH_USERAUTH_INVALID_PUBLICKEY;
            }
            else {
                wc_InitDecodedCert(dCert, authData->sf.publicKey.publicKey,
                        authData->sf.publicKey.publicKeySz, NULL);
                if (wc_ParseCert(dCert, CERT_TYPE, NO_VERIFY, NULL) != 0) {
                    wolfSSH_Log(WS_LOG_ERROR, "[SSHD] Unable to parse peer "
                        "cert.");
                    ret = WOLFSSH_USERAUTH_INVALID_PUBLICKEY;
                }
                else {
                    int usrMatch = 0;
                    DNS_entry* current = dCert->altNames;

                    while (current != NULL) {
                        if (current->type == ASN_OTHER_TYPE &&
                                current->oidSum == UPN_OID) {
                            /* found UPN oid, check name against user */
                            int idx;

                            for (idx = 0; idx < current->len; idx++) {
                                if (current->name[idx] == '@') break;
                                /* UPN format is <user>@<domain>
                                 * since currently not doing any checks on
                                 * domain it is  not treated as an error if only
                                 * the user name is present without the domain
                                 */
                            }

                            if ((int)XSTRLEN(usr) == idx &&
                                    XSTRNCMP(usr, current->name, idx) == 0) {
                                usrMatch = 1;
                            }
                        }
                        current = current->next;
                    }

                    if (usrMatch == 0) {
                        wolfSSH_Log(WS_LOG_ERROR, "[SSHD] incorrect user cert "
                            "sent");
                        ret = WOLFSSH_USERAUTH_INVALID_PUBLICKEY;
                    }
                }
                FreeDecodedCert(dCert);
            #ifdef WOLFSSH_SMALL_STACK
                WFREE(dCert, NULL, DYNTYPE_CERT);
            #endif
            }
        }
    #endif

        if (ret == WOLFSSH_USERAUTH_SUCCESS) {
            /* if this is a certificate and no specific authorized keys file has
             * been set then rely on CA to have verified the cert */
            if (authData->sf.publicKey.isCert &&
                    !wolfSSHD_ConfigGetAuthKeysFileSet(authCtx->conf)) {
                wolfSSH_Log(WS_LOG_INFO,
                    "[SSHD] Relying on CA for public key check");
            #ifdef WIN32
                /* Still need to get users token on Windows */
                rc = SetupUserTokenWin(usr, &authData->sf.publicKey,
                    wolfSSHD_ConfigGetUserCAKeysFile(authCtx->conf), authCtx);
                if (rc == WSSHD_AUTH_SUCCESS) {
                    wolfSSH_Log(WS_LOG_INFO, "[SSHD] Got users token ok.");
                    ret = WOLFSSH_USERAUTH_SUCCESS;
                }
                else {
                    wolfSSH_Log(WS_LOG_ERROR,
                        "[SSHD] Error getting users token.");
                    ret = WOLFSSH_USERAUTH_FAILURE;
                }
            #else
                ret = WOLFSSH_USERAUTH_SUCCESS;
            #endif
            }
            else {
                /* if not a certificate then parse through authorized key file */
                rc = authCtx->checkPublicKeyCb(usr, &authData->sf.publicKey,
                                wolfSSHD_ConfigGetUserCAKeysFile(authCtx->conf),
                                authCtx);
                if (rc == WSSHD_AUTH_SUCCESS) {
                    wolfSSH_Log(WS_LOG_INFO, "[SSHD] Public key ok.");
                    ret = WOLFSSH_USERAUTH_SUCCESS;
                }
                else if (rc == WSSHD_AUTH_FAILURE) {
                    wolfSSH_Log(WS_LOG_INFO,
                        "[SSHD] Public key not authorized.");
                    ret = WOLFSSH_USERAUTH_INVALID_PUBLICKEY;
                }
                else {
                    wolfSSH_Log(WS_LOG_ERROR,
                        "[SSHD] Error checking public key.");
                    ret = WOLFSSH_USERAUTH_FAILURE;
                }
            }
        }
    }


    if (wolfSSHD_AuthReducePermissions(authCtx) != WS_SUCCESS) {
        /* stop everything if not able to reduce permissions level */
        exit(1);
    }

    return ret;
}


/* return WOLFSSH_USERAUTH_SUCCESS on success */
int DefaultUserAuth(byte authType, WS_UserAuthData* authData, void* ctx)
{
    int ret = WOLFSSH_USERAUTH_SUCCESS;
    WOLFSSHD_AUTH* authCtx;

    if (ctx == NULL) {
        wolfSSH_Log(WS_LOG_ERROR, "[SSHD] No auth callbacks passed in");
        return WOLFSSH_USERAUTH_FAILURE;
    }
    else {
        authCtx = (WOLFSSHD_AUTH*)ctx;
        if (authCtx->checkUserCb == NULL) {
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

    /* call to possibly privileged authenticator for password check */
    if (ret == WOLFSSH_USERAUTH_SUCCESS) {
        ret = RequestAuthentication(authData, authCtx);
    }

    return ret;
}


int DefaultUserAuthTypes(WOLFSSH* ssh, void* ctx)
{
    WOLFSSHD_CONFIG* usrConf;
    WOLFSSHD_AUTH* authCtx;
    char* usr;
    int   ret = 0;

    if (ssh == NULL || ctx == NULL)
        return WS_BAD_ARGUMENT;
    authCtx = (WOLFSSHD_AUTH*)ctx;

    /* get configuration for user */
    usr     = wolfSSH_GetUsername(ssh);
    usrConf = wolfSSHD_AuthGetUserConf(authCtx, usr, NULL, NULL,
            NULL, NULL, NULL);
    if (usrConf == NULL) {
        ret = WS_BAD_ARGUMENT;
    }
    else {
        if (wolfSSHD_ConfigGetPwAuth(usrConf) == 1) {
            ret |= WOLFSSH_USERAUTH_PASSWORD;
        }
        ret |= WOLFSSH_USERAUTH_PUBLICKEY;
    }

    return ret;
}


static int SetDefaultUserCheck(WOLFSSHD_AUTH* auth)
{
    int ret = WS_NOT_COMPILED;

#ifdef _WIN32
    wolfSSH_Log(WS_LOG_INFO, "[SSHD] Setting default Windows user name check");
    auth->checkUserCb = CheckUserWIN;
    ret = WS_SUCCESS;
#else
    wolfSSH_Log(WS_LOG_INFO, "[SSHD] Setting default Unix user name check");
    auth->checkUserCb = CheckUserUnix;
    ret = WS_SUCCESS;
#endif

    return ret;
}


static int SetDefaultPasswordCheck(WOLFSSHD_AUTH* auth)
{
    int ret = WS_NOT_COMPILED;

#ifdef _WIN32
    wolfSSH_Log(WS_LOG_INFO, "[SSHD] Setting Windows password check");
    auth->checkPasswordCb = CheckPasswordWIN;
    ret = WS_SUCCESS;
#elif defined(WOLFSSH_USE_PAM)
    wolfSSH_Log(WS_LOG_INFO, "[SSHD] Setting PAM password check");
    auth->checkPasswordCb = CheckPasswordPAM;
    ret = WS_SUCCESS;
#else
    wolfSSH_Log(WS_LOG_INFO, "[SSHD] Setting Unix password check");
    auth->checkPasswordCb = CheckPasswordUnix;
    ret = WS_SUCCESS;
#endif
    return ret;
}


static int SetDefaultPublicKeyCheck(WOLFSSHD_AUTH* auth)
{
    int ret = WS_NOT_COMPILED;

#ifdef _WIN32
    wolfSSH_Log(WS_LOG_INFO, "[SSHD] Setting Windows public key check");
    auth->checkPublicKeyCb = CheckPublicKeyWIN;
    ret = WS_SUCCESS;
#else
    wolfSSH_Log(WS_LOG_INFO, "[SSHD] Setting Unix public key check");
    auth->checkPublicKeyCb = CheckPublicKeyUnix;
    ret = WS_SUCCESS;
#endif
    return ret;
}

#ifndef WOLFSSH_SSHD_USER
    #define WOLFSSH_SSHD_USER sshd
#endif
#define WOLFSSH_USER_GET_STRING(x) #x
#define WOLFSSH_USER_STRING(x) WOLFSSH_USER_GET_STRING(x)

static int SetDefualtUserID(WOLFSSHD_AUTH* auth)
{
#ifdef _WIN32
    /* TODO: Implement for Windows. */
    return 0;
#else
    struct passwd* pwInfo;
    int ret = WS_SUCCESS;

    pwInfo = getpwnam(WOLFSSH_USER_STRING(WOLFSSH_SSHD_USER));
    if (pwInfo == NULL) {
        /* user name not found on system */
        wolfSSH_Log(WS_LOG_INFO, "[SSHD] No %s user found to use",
            WOLFSSH_USER_STRING(WOLFSSH_SSHD_USER));
        ret = WS_FATAL_ERROR;
    }

    if (ret == WS_SUCCESS) {
        auth->gid = pwInfo->pw_gid;
        auth->uid = pwInfo->pw_uid;
        auth->sGid = getgid();
        auth->sUid = getuid();
    }
    return ret;
#endif
}


/* Sets the default functions to be used for authentication of peer.
 * Later the default functions could be overriden if needed.
 * returns a newly created WOLFSSHD_AUTH struct success */
WOLFSSHD_AUTH* wolfSSHD_AuthCreateUser(void* heap, const WOLFSSHD_CONFIG* conf)
{
    WOLFSSHD_AUTH* auth;

    auth = (WOLFSSHD_AUTH*)WMALLOC(sizeof(WOLFSSHD_AUTH), heap, DYNTYPE_SSHD);
    if (auth != NULL) {
        int ret;

        auth->heap = heap;
        auth->conf = conf;
        auth->attempts = WOLFSSHD_MAX_PASSWORD_ATTEMPTS;

        /* set the default user checking based on build */
        ret = SetDefaultUserCheck(auth);
        if (ret != WS_SUCCESS) {
            wolfSSH_Log(WS_LOG_ERROR,
                "[SSHD] Error setting default user check.");
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

        if (ret == WS_SUCCESS) {
            ret = SetDefualtUserID(auth);
            if (ret != WS_SUCCESS) {
                wolfSSH_Log(WS_LOG_ERROR, "[SSHD] Error setting default "
                    "user ID.");
            }
        }

        /* error case in setting one of the default callbacks */
        if (ret != WS_SUCCESS) {
            (void)wolfSSHD_AuthFreeUser(auth);
            auth = NULL;
        }
    }


    return auth;
}


/* returns WS_SUCCESS on success */
int wolfSSHD_AuthFreeUser(WOLFSSHD_AUTH* auth)
{
    if (auth != NULL) {
        WFREE(auth, auth->heap, DYNTYPE_SSHD);
    }
    return WS_SUCCESS;
}


/* return WS_SUCCESS on success */
int wolfSSHD_AuthRaisePermissions(WOLFSSHD_AUTH* auth)
{
    int ret = 0;

    wolfSSH_Log(WS_LOG_INFO, "[SSHD] Attempting to raise permissions level");
#ifndef WIN32
    if (auth) {
        if (setegid(auth->sGid) != 0) {
            wolfSSH_Log(WS_LOG_ERROR, "[SSHD] Error rasing gid");
            ret = WS_FATAL_ERROR;
        }

        if (seteuid(auth->sUid) != 0) {
            wolfSSH_Log(WS_LOG_ERROR, "[SSHD] Error rasing uid");
            ret = WS_FATAL_ERROR;
        }
    }
    else {
        ret = WS_BAD_ARGUMENT;
    }
#endif

    return ret;
}


/* return WS_SUCCESS on success */
int wolfSSHD_AuthReducePermissionsUser(WOLFSSHD_AUTH* auth, WUID_T uid,
    WGID_T gid)
{
#ifndef WIN32
    if (setregid(gid, gid) != 0) {
        wolfSSH_Log(WS_LOG_ERROR, "[SSHD] Error setting user gid");
        return WS_FATAL_ERROR;
    }

    if (setreuid(uid, uid) != 0) {
        wolfSSH_Log(WS_LOG_ERROR, "[SSHD] Error setting user uid");
        return WS_FATAL_ERROR;
    }
#endif
    (void)auth;
    return WS_SUCCESS;
}


/* return WS_SUCCESS on success */
int wolfSSHD_AuthReducePermissions(WOLFSSHD_AUTH* auth)
{
    byte flag = 0;
    int ret = WS_SUCCESS;

    flag = wolfSSHD_ConfigGetPrivilegeSeparation(auth->conf);
#ifndef WIN32
    if (flag == WOLFSSHD_PRIV_SEPARAT || flag == WOLFSSHD_PRIV_SANDBOX) {
        wolfSSH_Log(WS_LOG_INFO, "[SSHD] Lowering permissions level");
        if (auth) {
            if (setegid(auth->gid) != 0) {
                wolfSSH_Log(WS_LOG_ERROR, "[SSHD] Error setting sshd gid");
                ret = WS_FATAL_ERROR;
            }

            if (seteuid(auth->uid) != 0) {
                wolfSSH_Log(WS_LOG_ERROR, "[SSHD] Error setting sshd uid");
                ret = WS_FATAL_ERROR;
            }
        }
        else {
            ret = WS_BAD_ARGUMENT;
        }
    }
#endif
    return ret;
}

#ifndef WIN32
#if defined(__OSX__) || defined( __APPLE__)
    #define WGETGROUPLIST(x,y,z,w) getgrouplist((x),(y),(int*)(z),(w))
#else
    #define WGETGROUPLIST(x,y,z,w) getgrouplist((x),(y),(z),(w))
#endif
#endif /* WIN32 */

/* sets the extended groups the user is in, returns WS_SUCCESS on success */
int wolfSSHD_AuthSetGroups(const WOLFSSHD_AUTH* auth, const char* usr,
        WGID_T gid)
{
    int ret = WS_SUCCESS;
#ifndef WIN32
    int grpListSz = 0;
    gid_t* grpList = NULL;

#if defined(__QNX__) || defined(__QNXNTO__)
    /* QNX does not support getting the exact group list size ahead of time,
       only the max group list size */
    grpListSz = sysconf( _SC_NGROUPS_MAX );
#else
    /* should return -1 if grpListSz is smaller than actual groups */
    if (WGETGROUPLIST(usr, gid, NULL, &grpListSz) == -1)
#endif
    {
        grpList = (gid_t*)WMALLOC(sizeof(gid_t) * grpListSz, auth->heap,
            DYNTYPE_SSHD);
        if (grpList == NULL) {
            ret = WS_MEMORY_E;
        }
        else {
            int res;

            res = WGETGROUPLIST(usr, gid, grpList, &grpListSz);
        #if defined(__QNX__) || defined(__QNXNTO__)
            if (res != 0) {
                ret = WS_FATAL_ERROR;
            }
        #else
            if (res != grpListSz) {
                ret = WS_FATAL_ERROR;
            }
        #endif

            if (ret == WS_SUCCESS &&
                    setgroups(grpListSz, grpList) == -1) {
                ret = WS_FATAL_ERROR;
            }
            WFREE(grpList, auth->heap, DYNTYPE_SSHD);
        }
    }
#else
    WOLFSSH_UNUSED(auth);
    WOLFSSH_UNUSED(usr);
    WOLFSSH_UNUSED(gid);
#endif
    return ret;
}


/* return the time in seconds for grace timeout period */
long wolfSSHD_AuthGetGraceTime(const WOLFSSHD_AUTH* auth)
{
    long ret = WS_BAD_ARGUMENT;

    if (auth != NULL && auth->conf != NULL) {
        ret = wolfSSHD_ConfigGetGraceTime(auth->conf);
    }

    return ret;
}


/* return the user configuration */
WOLFSSHD_CONFIG* wolfSSHD_AuthGetUserConf(const WOLFSSHD_AUTH* auth,
        const char* usr, const char* host,
        const char* localAdr, word16* localPort, const char* RDomain,
        const char* adr)
{
    WOLFSSHD_CONFIG* ret = NULL;

    if (auth != NULL) {
        char* gName = NULL;

        if (usr != NULL) {
#ifdef WIN32
            //LogonUserEx()
#else
            struct passwd* p_passwd;
            struct group* g = NULL;

            p_passwd = getpwnam((const char *)usr);
            if (p_passwd == NULL) {
                return NULL;
            }

            g = getgrgid(p_passwd->pw_gid);
            if (g == NULL) {
                return NULL;
            }
            gName = g->gr_name;
#endif
        }

        ret = wolfSSHD_GetUserConf(auth->conf, usr, gName, host, localAdr,
            localPort, RDomain, adr);
    }
    return ret;
}
#endif /* WOLFSSH_SSHD */

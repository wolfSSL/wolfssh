/* ssh.h
 *
 * Copyright (C) 2014-2016 wolfSSL Inc.
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


/*
 * The ssh module contains the public API for wolfSSH.
 */


#pragma once

#ifdef WOLFSSL_USER_SETTINGS
#include <wolfssl/wolfcrypt/settings.h>
#else
#include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssh/settings.h>
#include <wolfssh/version.h>
#include <wolfssh/port.h>
#include <wolfssh/error.h>

#ifdef __cplusplus
extern "C" {
#endif


typedef struct WOLFSSH_CTX WOLFSSH_CTX;
typedef struct WOLFSSH WOLFSSH;
typedef struct WOLFSSH_CHANNEL WOLFSSH_CHANNEL;


WOLFSSH_API int wolfSSH_Init(void);
WOLFSSH_API int wolfSSH_Cleanup(void);

/* debugging output functions */
WOLFSSH_API void wolfSSH_Debugging_ON(void);
WOLFSSH_API void wolfSSH_Debugging_OFF(void);

/* context functions */
WOLFSSH_API WOLFSSH_CTX* wolfSSH_CTX_new(byte, void*);
WOLFSSH_API void wolfSSH_CTX_free(WOLFSSH_CTX*);

/* ssh session functions */
WOLFSSH_API WOLFSSH* wolfSSH_new(WOLFSSH_CTX*);
WOLFSSH_API void wolfSSH_free(WOLFSSH*);

WOLFSSH_API int wolfSSH_set_fd(WOLFSSH*, int);
WOLFSSH_API int wolfSSH_get_fd(const WOLFSSH*);

/* data high water mark functions */
WOLFSSH_API int wolfSSH_SetHighwater(WOLFSSH*, word32);
WOLFSSH_API word32 wolfSSH_GetHighwater(WOLFSSH*);

typedef int (*WS_CallbackHighwater)(byte, void*);
WOLFSSH_API void wolfSSH_SetHighwaterCb(WOLFSSH_CTX*, word32,
                                        WS_CallbackHighwater);
WOLFSSH_API void wolfSSH_SetHighwaterCtx(WOLFSSH*, void*);
WOLFSSH_API void* wolfSSH_GetHighwaterCtx(WOLFSSH*);


WOLFSSH_API int wolfSSH_get_error(const WOLFSSH*);
WOLFSSH_API const char* wolfSSH_get_error_name(const WOLFSSH*);
WOLFSSH_API const char* wolfSSH_ErrorToName(int);

/* I/O callbacks */
typedef int (*WS_CallbackIORecv)(WOLFSSH*, void*, word32, void*);
typedef int (*WS_CallbackIOSend)(WOLFSSH*, void*, word32, void*);
WOLFSSH_API void wolfSSH_SetIORecv(WOLFSSH_CTX*, WS_CallbackIORecv);
WOLFSSH_API void wolfSSH_SetIOSend(WOLFSSH_CTX*, WS_CallbackIOSend);
WOLFSSH_API void wolfSSH_SetIOReadCtx(WOLFSSH*, void*);
WOLFSSH_API void wolfSSH_SetIOWriteCtx(WOLFSSH*, void*);
WOLFSSH_API void* wolfSSH_GetIOReadCtx(WOLFSSH*);
WOLFSSH_API void* wolfSSH_GetIOWriteCtx(WOLFSSH*);

/* User Authentication callback */
typedef struct WS_UserAuthData_Password {
    byte* password;
    word32 passwordSz;
    /* The following are present for future use. */
    byte hasNewPassword;
    byte* newPassword;
    word32 newPasswordSz;
} WS_UserAuthData_Password;

typedef struct WS_UserAuthData_PublicKey {
    byte* dataToSign;
    byte* publicKeyType;
    word32 publicKeyTypeSz;
    byte* publicKey;
    word32 publicKeySz;
    byte hasSignature;
    byte* signature;
    word32 signatureSz;
} WS_UserAuthData_PublicKey;

typedef struct WS_UserAuthData {
    byte type;
    byte* username;
    word32 usernameSz;
    byte* serviceName;
    word32 serviceNameSz;
    byte* authName;
    word32 authNameSz;
    union {
        WS_UserAuthData_Password password;
        WS_UserAuthData_PublicKey publicKey;
    } sf;
} WS_UserAuthData;

typedef int (*WS_CallbackUserAuth)(byte, WS_UserAuthData*, void*);
WOLFSSH_API void wolfSSH_SetUserAuth(WOLFSSH_CTX*, WS_CallbackUserAuth);
WOLFSSH_API void wolfSSH_SetUserAuthCtx(WOLFSSH*, void*);
WOLFSSH_API void* wolfSSH_GetUserAuthCtx(WOLFSSH*);

WOLFSSH_API int wolfSSH_SetUsername(WOLFSSH*, const char*);

WOLFSSH_API int wolfSSH_CTX_SetBanner(WOLFSSH_CTX*, const char*);
WOLFSSH_API int wolfSSH_CTX_UsePrivateKey_buffer(WOLFSSH_CTX*,
                                                 const byte*, word32, int);

WOLFSSH_API int wolfSSH_accept(WOLFSSH*);
WOLFSSH_API int wolfSSH_connect(WOLFSSH*);
WOLFSSH_API int wolfSSH_shutdown(WOLFSSH*);
WOLFSSH_API int wolfSSH_stream_read(WOLFSSH*, byte*, word32);
WOLFSSH_API int wolfSSH_stream_send(WOLFSSH*, byte*, word32);
WOLFSSH_API int wolfSSH_stream_exit(WOLFSSH*, int);
WOLFSSH_API int wolfSSH_TriggerKeyExchange(WOLFSSH*);

WOLFSSH_API void wolfSSH_GetStats(WOLFSSH*,
                                  word32*, word32*, word32*, word32*);

WOLFSSH_API int wolfSSH_KDF(byte, byte, byte*, word32, const byte*, word32,
                            const byte*, word32, const byte*, word32);


typedef enum {
    WOLFSSH_SESSION_UNKNOWN = 0,
    WOLFSSH_SESSION_SHELL,
    WOLFSSH_SESSION_EXEC,
    WOLFSSH_SESSION_SUBSYSTEM,
} WS_SessionType;

WOLFSSH_API WS_SessionType wolfSSH_GetSessionType(const WOLFSSH*);
WOLFSSH_API const char* wolfSSH_GetSessionCommand(const WOLFSSH*);
WOLFSSH_API int wolfSSH_SetChannelType(WOLFSSH*, byte, byte*, word32);


enum WS_HighwaterSide {
    WOLFSSH_HWSIDE_TRANSMIT,
    WOLFSSH_HWSIDE_RECEIVE
};


enum WS_EndpointTypes {
    WOLFSSH_ENDPOINT_SERVER,
    WOLFSSH_ENDPOINT_CLIENT
};


enum WS_FormatTypes {
    WOLFSSH_FORMAT_ASN1,
    WOLFSSH_FORMAT_PEM,
    WOLFSSH_FORMAT_RAW
};


enum WS_UserAuthTypes {
    WOLFSSH_USERAUTH_PASSWORD,
    WOLFSSH_USERAUTH_PUBLICKEY
};


enum WS_UserAuthResults {
    WOLFSSH_USERAUTH_SUCCESS,
    WOLFSSH_USERAUTH_FAILURE,
    WOLFSSH_USERAUTH_INVALID_AUTHTYPE,
    WOLFSSH_USERAUTH_INVALID_USER,
    WOLFSSH_USERAUTH_INVALID_PASSWORD,
    WOLFSSH_USERAUTH_INVALID_PUBLICKEY
};


enum WS_DisconnectReasonCodes {
    WOLFSSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT    = 1,
    WOLFSSH_DISCONNECT_PROTOCOL_ERROR                 = 2,
    WOLFSSH_DISCONNECT_KEY_EXCHANGE_FAILED            = 3,
    WOLFSSH_DISCONNECT_RESERVED                       = 4,
    WOLFSSH_DISCONNECT_MAC_ERROR                      = 5,
    WOLFSSH_DISCONNECT_COMPRESSION_ERROR              = 6,
    WOLFSSH_DISCONNECT_SERVICE_NOT_AVAILABLE          = 7,
    WOLFSSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED = 8,
    WOLFSSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE        = 9,
    WOLFSSH_DISCONNECT_CONNECTION_LOST                = 10,
    WOLFSSH_DISCONNECT_BY_APPLICATION                 = 11,
    WOLFSSH_DISCONNECT_TOO_MANY_CONNECTIONS           = 12,
    WOLFSSH_DISCONNECT_AUTH_CANCELLED_BY_USER         = 13,
    WOLFSSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE = 14,
    WOLFSSH_DISCONNECT_ILLEGAL_USER_NAME              = 15
};


#ifndef WOLFSSH_MAX_FILENAME
    #define WOLFSSH_MAX_FILENAME 256
#endif
#define WOLFSSH_MAX_OCTET_LEN 6


#ifdef __cplusplus
}
#endif


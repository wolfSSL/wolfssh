/* ssh.h
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


/*
 * The ssh module contains the public API for wolfSSH.
 */


#ifndef _WOLFSSH_SSH_H_
#define _WOLFSSH_SSH_H_


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

#ifdef WOLFSSH_TPM
#include <wolftpm/tpm2_wrap.h>
#endif

#ifdef WOLFSSH_WINDOWS_CERT_STORE
/* The Windows certificate store API below uses wchar_t strings. */
#include <wchar.h>
#endif

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
WOLFSSH_API WOLFSSH_CTX* wolfSSH_CTX_new(byte side, void* heap);
WOLFSSH_API void wolfSSH_CTX_free(WOLFSSH_CTX* ctx);

/* ssh session functions */
WOLFSSH_API WOLFSSH* wolfSSH_new(WOLFSSH_CTX* ctx);
WOLFSSH_API void wolfSSH_free(WOLFSSH* ssh);

WOLFSSH_API int wolfSSH_worker(WOLFSSH* ssh, word32* channelId);
WOLFSSH_API int wolfSSH_GetLastRxId(WOLFSSH* ssh, word32* channelId);

WOLFSSH_API int wolfSSH_set_fd(WOLFSSH* ssh, WS_SOCKET_T fd);
WOLFSSH_API WS_SOCKET_T wolfSSH_get_fd(const WOLFSSH* ssh);

WOLFSSH_API int wolfSSH_SetFilesystemHandle(WOLFSSH* ssh, void* handle);
WOLFSSH_API void* wolfSSH_GetFilesystemHandle(WOLFSSH* ssh);

/* data high water mark functions (RFC 4253 Sec 9) */
typedef int (*WS_CallbackHighwater)(byte side, void* ctx);
WOLFSSH_API void wolfSSH_SetHighwaterCb(WOLFSSH_CTX* ctx, word32 level,
        WS_CallbackHighwater cb);
WOLFSSH_API void wolfSSH_SetHighwaterCtx(WOLFSSH* ssh, void* ctx);
WOLFSSH_API void* wolfSSH_GetHighwaterCtx(WOLFSSH* ssh);
WOLFSSH_API int wolfSSH_SetHighwater(WOLFSSH* ssh, word32 level);
WOLFSSH_API word32 wolfSSH_GetHighwater(WOLFSSH* ssh);
/* packet count high water mark functions (RFC 4344 Sec 3.1) */
WOLFSSH_API void wolfSSH_CTX_SetMsgHighwater(WOLFSSH_CTX* ctx, word32 level);
WOLFSSH_API void wolfSSH_SetMsgHighwater(WOLFSSH* ssh, word32 level);
WOLFSSH_API word32 wolfSSH_GetMsgHighwater(WOLFSSH* ssh);

WOLFSSH_API int wolfSSH_ReadKey_buffer_ex(const byte* in, word32 inSz, int format,
        byte** out, word32* outSz, const byte** outType, word32* outTypeSz,
        int isPrivate, void* heap);

WOLFSSH_API int wolfSSH_ReadKey_buffer(const byte* in, word32 inSz, int format,
        byte** out, word32* outSz, const byte** outType, word32* outTypeSz,
        void* heap);
WOLFSSH_API int wolfSSH_ReadPublicKey_buffer(const byte* in, word32 inSz, int format,
        byte** out, word32* outSz, const byte** outType, word32* outTypeSz,
        void* heap);
WOLFSSH_API int wolfSSH_ReadKey_file(const char* name,
        byte** out, word32* outSz, const byte** outType, word32* outTypeSz,
        byte* isPrivate, void* heap);

WOLFSSH_API int wolfSSH_CTX_SetAlgoListKex(WOLFSSH_CTX* ctx, const char* list);
WOLFSSH_API const char* wolfSSH_CTX_GetAlgoListKex(WOLFSSH_CTX* ctx);
WOLFSSH_API int wolfSSH_SetAlgoListKex(WOLFSSH* ssh, const char* list);
WOLFSSH_API const char* wolfSSH_GetAlgoListKex(WOLFSSH* ssh);

WOLFSSH_API int wolfSSH_CTX_SetAlgoListKey(WOLFSSH_CTX* ctx, const char* list);
WOLFSSH_API const char* wolfSSH_CTX_GetAlgoListKey(WOLFSSH_CTX* ctx);
WOLFSSH_API int wolfSSH_SetAlgoListKey(WOLFSSH* ssh, const char* list);
WOLFSSH_API const char* wolfSSH_GetAlgoListKey(WOLFSSH* ssh);

WOLFSSH_API int wolfSSH_CTX_SetAlgoListCipher(WOLFSSH_CTX* ctx,
        const char* list);
WOLFSSH_API const char* wolfSSH_CTX_GetAlgoListCipher(WOLFSSH_CTX* ctx);
WOLFSSH_API int wolfSSH_SetAlgoListCipher(WOLFSSH* ssh, const char* list);
WOLFSSH_API const char* wolfSSH_GetAlgoListCipher(WOLFSSH* ssh);

WOLFSSH_API int wolfSSH_CTX_SetAlgoListMac(WOLFSSH_CTX* ctx, const char* list);
WOLFSSH_API const char* wolfSSH_CTX_GetAlgoListMac(WOLFSSH_CTX* ctx);
WOLFSSH_API int wolfSSH_SetAlgoListMac(WOLFSSH* ssh, const char* list);
WOLFSSH_API const char* wolfSSH_GetAlgoListMac(WOLFSSH* ssh);

WOLFSSH_API int wolfSSH_CTX_SetAlgoListKeyAccepted(WOLFSSH_CTX* ctx,
        const char* list);
WOLFSSH_API const char* wolfSSH_CTX_GetAlgoListKeyAccepted(WOLFSSH_CTX* ctx);
WOLFSSH_API int wolfSSH_SetAlgoListKeyAccepted(WOLFSSH* ssh, const char* list);
WOLFSSH_API const char* wolfSSH_GetAlgoListKeyAccepted(WOLFSSH* ssh);

WOLFSSH_API int wolfSSH_CheckAlgoName(const char* name);

WOLFSSH_API const char* wolfSSH_QueryKex(word32* idx);
WOLFSSH_API const char* wolfSSH_QueryKey(word32* idx);
WOLFSSH_API const char* wolfSSH_QueryCipher(word32* idx);
WOLFSSH_API const char* wolfSSH_QueryMac(word32* idx);

typedef enum WS_Text {
    WOLFSSH_TEXT_KEX_ALGO,
    WOLFSSH_TEXT_KEX_CURVE,
    WOLFSSH_TEXT_KEX_HASH,

    WOLFSSH_TEXT_CRYPTO_IN_CIPHER,
    WOLFSSH_TEXT_CRYPTO_IN_MAC,
    WOLFSSH_TEXT_CRYPTO_OUT_CIPHER,
    WOLFSSH_TEXT_CRYPTO_OUT_MAC,
} WS_Text;

/*
 * Outputs the c-string representation of the data entry identified by the id to
 * the character string str, writing no more than strSz bytes, including the
 * terminating null byte ('\0').
 *
 * Returns the number of characters written (excluding the null byte used to end
 * output to strings), unless the output was truncated, in which case the return
 * value is the number of characters (excluding the terminating null byte) which
 * would have been written to the final string if enough space had been
 * available.
 *
 * Thus, a return value of strSz or more means that the output was truncated.
 */

WOLFSSH_API size_t wolfSSH_GetText(WOLFSSH *ssh, WS_Text id, char *str,
        size_t strSz);

typedef void (*WS_CallbackKeyingCompletion)(void* ctx);
WOLFSSH_API void wolfSSH_SetKeyingCompletionCb(WOLFSSH_CTX* ctx,
        WS_CallbackKeyingCompletion cb);
WOLFSSH_API void wolfSSH_SetKeyingCompletionCbCtx(WOLFSSH* ssh,
        void* ctx);

#define WS_CHANNEL_ID_SELF 0
#define WS_CHANNEL_ID_PEER 1


typedef enum {
    WOLFSSH_SESSION_UNKNOWN = 0,
    WOLFSSH_SESSION_SHELL,
    WOLFSSH_SESSION_EXEC,
    WOLFSSH_SESSION_SUBSYSTEM,
    WOLFSSH_SESSION_TERMINAL,
} WS_SessionType;


typedef enum WS_FwdCbAction {
    WOLFSSH_FWD_LOCAL_SETUP,
    WOLFSSH_FWD_LOCAL_CLEANUP,
    WOLFSSH_FWD_REMOTE_SETUP,
    WOLFSSH_FWD_REMOTE_CLEANUP,
    WOLFSSH_FWD_CHANNEL_ID,
} WS_FwdCbAction;

typedef enum WS_FwdIoCbAction {
    WOLFSSH_FWD_IO_WRITE,
    WOLFSSH_FWD_IO_READ,
} WS_FwdIoCbAction;

typedef enum WS_FwdCbError {
    WS_FWD_SUCCESS,
    WS_FWD_SETUP_E,
    WS_FWD_NOT_AVAILABLE,
    WS_FWD_INVALID_ACTION,
    WS_FWD_PEER_E,
} WS_FwdCbError;

#ifndef WS_FWD_PORT_CHECK
    /* Boundary of the WS_CallbackFwd return convention below; not an error
     * code. The lowest unprivileged port, and must stay above WS_FWD_PEER_E. */
    #define WS_FWD_PORT_CHECK 1024
#else
    #if (WS_FWD_PEER_E > WS_FWD_PORT_CHECK)
        #error "WS_FWD_PORT_CHECK set to value in WS_FwdCbError range."
    #endif
#endif

/* Return value: below WS_FWD_PORT_CHECK is a WS_FwdCbError status
 * (WS_FWD_SUCCESS is success); at or above it is the unprivileged port a
 * WOLFSSH_FWD_REMOTE_SETUP allocated for a port-0 request, for the server to
 * report to the peer. A rejected port-0 setup gets a WOLFSSH_FWD_REMOTE_CLEANUP
 * even though the setup returned success. */
typedef int (*WS_CallbackFwd)(WS_FwdCbAction action, void* fwdCbCtx,
        const char* address, word32 port);
typedef int (*WS_CallbackFwdIO)(WS_FwdIoCbAction action, void* buf,
        word32 bufSz, void* fwdCbCtx);


WOLFSSH_API WOLFSSH_CHANNEL* wolfSSH_ChannelFwdNewLocal(WOLFSSH* ssh,
        const char* host, word32 hostPort, const char* origin,
        word32 originPort);
WOLFSSH_API WOLFSSH_CHANNEL* wolfSSH_ChannelFwdNewRemote(WOLFSSH* ssh,
        const char* host, word32 hostPort, const char* origin,
        word32 originPort);
WOLFSSH_API int wolfSSH_CTX_SetFwdCb(WOLFSSH_CTX* ctx,
        WS_CallbackFwd fwdCb, WS_CallbackFwdIO fwdIoCb);
WOLFSSH_API int wolfSSH_SetFwdCbCtx(WOLFSSH* ssh, void* ctx);
WOLFSSH_API int wolfSSH_CTX_SetFwdEnable(WOLFSSH_CTX* ctx, byte enable);
WOLFSSH_API int wolfSSH_SetFwdEnable(WOLFSSH* ssh, byte enable);
DEPRECATED WOLFSSH_API WOLFSSH_CHANNEL* wolfSSH_ChannelFwdNew(WOLFSSH* ssh,
        const char* host, word32 hostPort, const char* origin,
        word32 originPort);
DEPRECATED WOLFSSH_API int wolfSSH_ChannelSetFwdFd(WOLFSSH_CHANNEL* channel,
        int fwdFd);
DEPRECATED WOLFSSH_API int wolfSSH_ChannelGetFwdFd(
        const WOLFSSH_CHANNEL* channel);

WOLFSSH_API int wolfSSH_ChannelFree(WOLFSSH_CHANNEL* channel);
WOLFSSH_API int wolfSSH_ChannelGetId(WOLFSSH_CHANNEL* channel, word32* id,
        byte peer);
WOLFSSH_API WOLFSSH_CHANNEL* wolfSSH_ChannelFind(WOLFSSH* ssh, word32 id,
        byte peer);
WOLFSSH_API WOLFSSH_CHANNEL* wolfSSH_ChannelNext(WOLFSSH* ssh,
        WOLFSSH_CHANNEL* channel);
WOLFSSH_API int wolfSSH_ChannelRead(WOLFSSH_CHANNEL* channel, byte* buf,
        word32 bufSz);
WOLFSSH_API int wolfSSH_ChannelSend(WOLFSSH_CHANNEL* channel, const byte* buf,
        word32 bufSz);
WOLFSSH_API int wolfSSH_ChannelExit(WOLFSSH_CHANNEL* channel);
WOLFSSH_API int wolfSSH_ChannelGetEof(WOLFSSH_CHANNEL* channel);
WOLFSSH_API const char* wolfSSH_ChannelGetType(
        const WOLFSSH_CHANNEL* channel);
WOLFSSH_API WS_SessionType wolfSSH_ChannelGetSessionType(
        const WOLFSSH_CHANNEL* channel);
WOLFSSH_API const char* wolfSSH_ChannelGetSessionCommand(
        const WOLFSSH_CHANNEL* channel);
WOLFSSH_API int wolfSSH_ChannelIsPty(const WOLFSSH_CHANNEL* channel);

/* Channel callbacks */
typedef int (*WS_CallbackChannelOpen)(WOLFSSH_CHANNEL* channel, void* ctx);
WOLFSSH_API int wolfSSH_CTX_SetChannelOpenCb(WOLFSSH_CTX* ctx,
        WS_CallbackChannelOpen cb);
WOLFSSH_API int wolfSSH_CTX_SetChannelOpenRespCb(WOLFSSH_CTX* ctx,
        WS_CallbackChannelOpen confCb, WS_CallbackChannelOpen failCb);
WOLFSSH_API int wolfSSH_SetChannelOpenCtx(WOLFSSH* ssh, void* ctx);
WOLFSSH_API void* wolfSSH_GetChannelOpenCtx(WOLFSSH* ssh);

typedef int (*WS_CallbackChannelReq)(WOLFSSH_CHANNEL* channel, void* ctx);
WOLFSSH_API int wolfSSH_CTX_SetChannelReqShellCb(WOLFSSH_CTX* ctx,
        WS_CallbackChannelReq cb);
WOLFSSH_API int wolfSSH_CTX_SetChannelReqExecCb(WOLFSSH_CTX* ctx,
        WS_CallbackChannelReq cb);
WOLFSSH_API int wolfSSH_CTX_SetChannelReqSubsysCb(WOLFSSH_CTX* ctx,
        WS_CallbackChannelReq cb);
WOLFSSH_API int wolfSSH_SetChannelReqCtx(WOLFSSH* ssh, void* ctx);
WOLFSSH_API void* wolfSSH_GetChannelReqCtx(WOLFSSH* ssh);

typedef int (*WS_CallbackChannelEof)(WOLFSSH_CHANNEL* channel, void* ctx);
WOLFSSH_API int wolfSSH_CTX_SetChannelEofCb(WOLFSSH_CTX* ctx,
        WS_CallbackChannelEof cb);
WOLFSSH_API int wolfSSH_SetChannelEofCtx(WOLFSSH* ssh, void* ctx);
WOLFSSH_API void* wolfSSH_GetChannelEofCtx(WOLFSSH* ssh);

typedef int (*WS_CallbackChannelClose)(WOLFSSH_CHANNEL* channel, void* ctx);
WOLFSSH_API int wolfSSH_CTX_SetChannelCloseCb(WOLFSSH_CTX* ctx,
        WS_CallbackChannelClose cb);
WOLFSSH_API int wolfSSH_SetChannelCloseCtx(WOLFSSH* ssh, void* ctx);
WOLFSSH_API void* wolfSSH_GetChannelCloseCtx(WOLFSSH* ssh);

WOLFSSH_API int wolfSSH_get_error(const WOLFSSH* ssh);
WOLFSSH_API const char* wolfSSH_get_error_name(const WOLFSSH* ssh);
WOLFSSH_API const char* wolfSSH_ErrorToName(int err);

/* TPM 2.0 integration related functions */
#ifdef WOLFSSH_TPM
WOLFSSH_API void wolfSSH_SetTpmDev(WOLFSSH* ssh, WOLFTPM2_DEV* dev);
WOLFSSH_API void wolfSSH_SetTpmKey(WOLFSSH* ssh, WOLFTPM2_KEY* key);
WOLFSSH_API void* wolfSSH_GetTpmDev(WOLFSSH* ssh);
WOLFSSH_API void* wolfSSH_GetTpmKey(WOLFSSH* ssh);
WOLFSSH_API int wolfSSH_CTX_UseTpmHostKey(WOLFSSH_CTX* ctx,
        WOLFTPM2_DEV* dev, WOLFTPM2_KEY* key);
#endif /* WOLFSSH_TPM */

/* I/O callbacks */
typedef int (*WS_CallbackIORecv)(WOLFSSH* ssh, void* buf, word32 sz,
        void* ctx);
typedef int (*WS_CallbackIOSend)(WOLFSSH* ssh, void* buf, word32 sz,
        void* ctx);
WOLFSSH_API void wolfSSH_SetIORecv(WOLFSSH_CTX* ctx, WS_CallbackIORecv cb);
WOLFSSH_API void wolfSSH_SetIOSend(WOLFSSH_CTX* ctx, WS_CallbackIOSend cb);
WOLFSSH_API void wolfSSH_SetIOReadCtx(WOLFSSH* ssh, void* ctx);
WOLFSSH_API void wolfSSH_SetIOWriteCtx(WOLFSSH* ssh, void* ctx);
WOLFSSH_API void* wolfSSH_GetIOReadCtx(WOLFSSH* ssh);
WOLFSSH_API void* wolfSSH_GetIOWriteCtx(WOLFSSH* ssh);

/* Global Request callbacks */
typedef int (*WS_CallbackGlobalReq)(WOLFSSH* ssh, void* buf, word32 sz,
        int reply, void* ctx);
WOLFSSH_API void wolfSSH_SetGlobalReq(WOLFSSH_CTX* ctx,
        WS_CallbackGlobalReq cb);
WOLFSSH_API void wolfSSH_SetGlobalReqCtx(WOLFSSH* ssh, void* ctx);
WOLFSSH_API void *wolfSSH_GetGlobalReqCtx(WOLFSSH* ssh);
typedef int (*WS_CallbackReqSuccess)(WOLFSSH* ssh, void* buf, word32 sz,
        void* ctx);
WOLFSSH_API void wolfSSH_SetReqSuccess(WOLFSSH_CTX* ctx,
        WS_CallbackReqSuccess cb);
WOLFSSH_API void wolfSSH_SetReqSuccessCtx(WOLFSSH* ssh, void * ctx);
WOLFSSH_API void* wolfSSH_GetReqSuccessCtx(WOLFSSH* ssh);
typedef int (*WS_CallbackReqFailure)(WOLFSSH* ssh, void* buf, word32 sz,
        void* ctx);
WOLFSSH_API void wolfSSH_SetReqFailure(WOLFSSH_CTX * ctx,
        WS_CallbackReqSuccess cb);
WOLFSSH_API void wolfSSH_SetReqFailureCtx(WOLFSSH * ssh, void * ctx);
WOLFSSH_API void *wolfSSH_GetReqFailureCtx(WOLFSSH * ssh);

/* User Authentication callback */
typedef struct WS_UserAuthData_Password {
    const byte* password;
    word32 passwordSz;
    /* The following are present for future use. */
    byte hasNewPassword;
    const byte* newPassword;
    word32 newPasswordSz;
} WS_UserAuthData_Password;

#ifdef WOLFSSH_KEYBOARD_INTERACTIVE
typedef struct WS_UserAuthData_Keyboard {
    word32 promptCount;
    word32 responseCount;
    word32 promptNameSz;
    word32 promptInstructionSz;
    word32 promptLanguageSz;
    byte* promptName;
    byte* promptInstruction;
    byte* promptLanguage;
    word32* promptLengths;
    word32* responseLengths;
    byte* promptEcho;
    byte** responses;
    byte** prompts;
} WS_UserAuthData_Keyboard;
#endif

typedef struct WS_UserAuthData_PublicKey {
    const byte* dataToSign;
    const byte* publicKeyType;
    word32 publicKeyTypeSz;
    const byte* publicKey;
    word32 publicKeySz;
    const byte* privateKey;
    word32 privateKeySz;
    byte hasSignature;
    const byte* signature;
    word32 signatureSz;
    byte isCert:1;
} WS_UserAuthData_PublicKey;

typedef struct WS_UserAuthData {
    byte type;
    const byte* username;
    word32 usernameSz;
    const byte* serviceName;
    word32 serviceNameSz;
    const byte* authName;
    word32 authNameSz;
    union {
        WS_UserAuthData_Password password;
        WS_UserAuthData_PublicKey publicKey;
#ifdef WOLFSSH_KEYBOARD_INTERACTIVE
        WS_UserAuthData_Keyboard keyboard;
#endif
    } sf;
} WS_UserAuthData;

typedef int (*WS_CallbackUserAuth)(byte authType, WS_UserAuthData* authData,
        void* ctx);
WOLFSSH_API void wolfSSH_SetUserAuth(WOLFSSH_CTX* ctx, WS_CallbackUserAuth cb);
typedef int (*WS_CallbackUserAuthTypes)(WOLFSSH* ssh, void* ctx);
WOLFSSH_API void wolfSSH_SetUserAuthTypes(WOLFSSH_CTX* ctx,
    WS_CallbackUserAuthTypes cb);
WOLFSSH_API void wolfSSH_SetUserAuthCtx(WOLFSSH* ssh, void* userAuthCtx);
WOLFSSH_API void* wolfSSH_GetUserAuthCtx(WOLFSSH* ssh);

typedef int (*WS_CallbackUserAuthResult)(byte result,
        WS_UserAuthData* authData, void* userAuthResultCtx);
WOLFSSH_API void wolfSSH_SetUserAuthResult(WOLFSSH_CTX* ctx,
        WS_CallbackUserAuthResult cb);
WOLFSSH_API void wolfSSH_SetUserAuthResultCtx(WOLFSSH* ssh,
        void* userAuthResultCtx);
WOLFSSH_API void* wolfSSH_GetUserAuthResultCtx(WOLFSSH* ssh);

/* Public Key Check Callback */
typedef int (*WS_CallbackPublicKeyCheck)(const byte* publicKey,
        word32 publicKeySz, void* ctx);
WOLFSSH_API void wolfSSH_CTX_SetPublicKeyCheck(WOLFSSH_CTX* ctx,
                                               WS_CallbackPublicKeyCheck cb);
WOLFSSH_API void wolfSSH_SetPublicKeyCheckCtx(WOLFSSH* ssh,
        void* publicKeyCheckCtx);
WOLFSSH_API void* wolfSSH_GetPublicKeyCheckCtx(WOLFSSH* ssh);

WOLFSSH_API int wolfSSH_SetUsernameRaw(WOLFSSH* ssh, const byte* username,
        word32 usernameSz);
WOLFSSH_API int wolfSSH_SetUsername(WOLFSSH* ssh, const char* username);
WOLFSSH_API char* wolfSSH_GetUsername(WOLFSSH* ssh);

WOLFSSH_API int wolfSSH_CTX_SetBanner(WOLFSSH_CTX* ctx, const char* newBanner);
WOLFSSH_API int wolfSSH_CTX_SetSshProtoIdStr(WOLFSSH_CTX* ctx,
        const char* protoIdStr);
WOLFSSH_API int wolfSSH_CTX_UsePrivateKey_buffer(WOLFSSH_CTX* ctx,
                                                 const byte* in, word32 inSz,
                                                 int format);
#ifdef WOLFSSH_CERTS
    WOLFSSH_API int wolfSSH_CTX_UseCert_buffer(WOLFSSH_CTX* ctx,
            const byte* cert, word32 certSz, int format);
    WOLFSSH_API int wolfSSH_CTX_AddRootCert_buffer(WOLFSSH_CTX* ctx,
            const byte* cert, word32 certSz, int format);
#ifdef WOLFSSH_WINDOWS_CERT_STORE
    WOLFSSH_API int wolfSSH_CTX_UsePrivateKey_fromStore(WOLFSSH_CTX* ctx,
            const wchar_t* storeName, word32 dwFlags,
            const wchar_t* subjectName);
#endif /* WOLFSSH_WINDOWS_CERT_STORE */
#endif /* WOLFSSH_CERTS */
WOLFSSH_API int wolfSSH_CTX_SetWindowPacketSize(WOLFSSH_CTX* ctx,
        word32 windowSz, word32 maxPacketSz);

WOLFSSH_API int wolfSSH_accept(WOLFSSH* ssh);
WOLFSSH_API int wolfSSH_connect(WOLFSSH* ssh);
WOLFSSH_API int wolfSSH_shutdown(WOLFSSH* ssh);
WOLFSSH_API int wolfSSH_stream_peek(WOLFSSH* ssh, byte* buf, word32 bufSz);
WOLFSSH_API int wolfSSH_stream_read(WOLFSSH* ssh, byte* buf, word32 bufSz);
WOLFSSH_API int wolfSSH_stream_send(WOLFSSH* ssh, byte* buf, word32 bufSz);
WOLFSSH_API int wolfSSH_stream_exit(WOLFSSH* ssh, int status);
WOLFSSH_API int wolfSSH_extended_data_send(WOLFSSH* ssh, byte* buf, word32 bufSz);
WOLFSSH_API int wolfSSH_extended_data_read(WOLFSSH* ssh, byte* out,
        word32 outSz);
WOLFSSH_API int wolfSSH_TriggerKeyExchange(WOLFSSH* ssh);
WOLFSSH_API int wolfSSH_SendIgnore(WOLFSSH* ssh, const byte* buf, word32 bufSz);
WOLFSSH_API int wolfSSH_SendDisconnect(WOLFSSH* ssh, word32 reason);
WOLFSSH_API int wolfSSH_global_request(WOLFSSH* ssh, const unsigned char* data,
        word32 dataSz, int reply);
WOLFSSH_API int wolfSSH_ChannelIdRead(WOLFSSH* ssh, word32 channelId,
        byte* buf, word32 bufSz);
WOLFSSH_API int wolfSSH_ChannelIdSend(WOLFSSH* ssh, word32 channelId,
        byte* buf, word32 bufSz);

WOLFSSH_API void wolfSSH_GetStats(WOLFSSH* ssh,
                                  word32* txCount, word32* rxCount,
                                  word32* seq, word32* peerSeq);

WOLFSSH_API int wolfSSH_KDF(byte hashId, byte keyId, byte* key, word32 keySz,
                            const byte* k, word32 kSz,
                            const byte* h, word32 hSz,
                            const byte* sessionId, word32 sessionIdSz);

#ifdef USE_WINDOWS_API
WOLFSSH_API int wolfSSH_ConvertConsole(WOLFSSH* ssh, WOLFSSH_HANDLE handle,
        byte* buf, word32 bufSz);
#endif


WOLFSSH_API int wolfSSH_DoModes(const byte* modes, word32 modesSz, int fd);
WOLFSSH_API WS_SessionType wolfSSH_GetSessionType(const WOLFSSH* ssh);
WOLFSSH_API const char* wolfSSH_GetSessionCommand(const WOLFSSH* ssh);
WOLFSSH_API int wolfSSH_SetChannelType(WOLFSSH* ssh, byte type, byte* name,
        word32 nameSz);
WOLFSSH_API int wolfSSH_ChangeTerminalSize(WOLFSSH* ssh, word32 columns,
    word32 rows, word32 widthPixels, word32 heightPixels);
typedef int (*WS_CallbackTerminalSize)(WOLFSSH* ssh, word32 columns,
    word32 rows, word32 widthPixels, word32 heightPixels, void* ctx);
WOLFSSH_API void wolfSSH_SetTerminalResizeCb(WOLFSSH* ssh,
    WS_CallbackTerminalSize cb);
WOLFSSH_API void wolfSSH_SetTerminalResizeCtx(WOLFSSH* ssh, void* usrCtx);
WOLFSSH_API int wolfSSH_GetExitStatus(WOLFSSH* ssh);
WOLFSSH_API int wolfSSH_SetExitStatus(WOLFSSH* ssh, word32 exitStatus);


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
    WOLFSSH_FORMAT_RAW,
    WOLFSSH_FORMAT_SSH,
    WOLFSSH_FORMAT_OPENSSH
};


/* bit map */
#define WOLFSSH_USERAUTH_PASSWORD  0x01
#define WOLFSSH_USERAUTH_PUBLICKEY 0x02
#define WOLFSSH_USERAUTH_KEYBOARD  0x04
#define WOLFSSH_USERAUTH_NONE      0x08
#define WOLFSSH_USERAUTH_KEYBOARD_SETUP 0x10

enum WS_UserAuthResults
{
    WOLFSSH_USERAUTH_SUCCESS,
    WOLFSSH_USERAUTH_FAILURE,
    WOLFSSH_USERAUTH_INVALID_AUTHTYPE,
    WOLFSSH_USERAUTH_INVALID_USER,
    WOLFSSH_USERAUTH_INVALID_PASSWORD,
    WOLFSSH_USERAUTH_REJECTED,
    WOLFSSH_USERAUTH_INVALID_PUBLICKEY,
    WOLFSSH_USERAUTH_PARTIAL_SUCCESS,
    WOLFSSH_USERAUTH_SUCCESS_ANOTHER,
    WOLFSSH_USERAUTH_WOULD_BLOCK
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


WOLFSSH_API int wolfSSH_RealPath(const char* defaultPath, char* in,
        char* out, word32 outSz);


WOLFSSH_API void wolfSSH_ShowSizes(void);


#ifndef WOLFSSH_MAX_FILENAME
    #define WOLFSSH_MAX_FILENAME 256
#endif
#define WOLFSSH_MAX_OCTET_LEN 6
#define WOLFSSH_EXT_DATA_STDERR 1


#ifdef __cplusplus
}
#endif

#endif /* _WOLFSSH_SSH_H_ */


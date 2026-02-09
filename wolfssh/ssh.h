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

/* Services the connection: reads what is pending and flushes what is queued.
 * Returns WS_SUCCESS, or one of several non-fatal statuses that callers must
 * not treat as errors:
 *   WS_CHAN_RXD       channel data arrived; read it with wolfSSH_stream_read()
 *                     or wolfSSH_ChannelIdRead()
 *   WS_EXTDATA        extended (stderr) data arrived; drain it with
 *                     wolfSSH_ChannelIdReadExt()
 *   WS_EOF            the peer half-closed a channel; it sends no more data,
 *                     but the channel is still open for sending. Raised once,
 *                     on arrival, and a back-pressure status from the flush
 *                     that follows can supersede it, so an application that
 *                     must not miss one tests wolfSSH_ChannelGetEof() or takes
 *                     the channel EOF callback. Reply, if the protocol wants
 *                     one, with wolfSSH_ChannelSendEof(); the library does
 *                     not.
 *   WS_CHANNEL_CLOSED the peer closed a channel, which has been retired
 *   WS_WANT_READ / WS_WANT_WRITE / WS_REKEYING / WS_WINDOW_FULL
 *                     transient; call again
 * Anything else is an error: WS_BAD_ARGUMENT, or WS_FATAL_ERROR with the
 * cause in wolfSSH_get_error() -- WS_DISCONNECT for the peer's disconnect,
 * which is how most sessions end.
 *
 * For WS_CHAN_RXD, WS_EXTDATA, WS_EOF and WS_SUCCESS, channelId (when not
 * NULL) names the channel the event belongs to. It is left alone for every
 * other status, WS_CHANNEL_CLOSED included; use wolfSSH_GetLastRxId() there.
 *
 * Note that after a peer half-close wolfSSH_stream_send() keeps working: the
 * library latches only the EOF it sends, not the one it receives. */
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

#if defined(WOLFSSH_CERTS) || defined(WOLFSSH_OSSH_CERTS)
/* Decodes a PEM/DER X.509 cert or OpenSSH cert line, detected from content.
 * Of several PEM certs, only the first is read. Caller frees out via heap; on
 * failure out params are cleared. An undecodable body gives WS_PARSE_E,
 * WS_BAD_FILE_E comes from _file alone. */
WOLFSSH_API int wolfSSH_ReadCert_buffer(const byte* in, word32 inSz,
        byte** out, word32* outSz, const byte** outType, word32* outTypeSz,
        byte* flavor, void* heap);
#if !defined(NO_FILESYSTEM) && !defined(WOLFSSH_USER_FILESYSTEM)
WOLFSSH_API int wolfSSH_ReadCert_file(const char* name,
        byte** out, word32* outSz, const byte** outType, word32* outTypeSz,
        byte* flavor, void* heap);
#endif
#endif /* WOLFSSH_CERTS || WOLFSSH_OSSH_CERTS */

/* SetAlgoList* validate the list, returning WS_SUCCESS, WS_INVALID_ALGO_ID for
 * a bad list, or WS_SSH_CTX_NULL_E / WS_SSH_NULL_E for a NULL ctx / ssh.
 * Kex/Cipher/Mac reject NULL. Key accepts NULL only on a server, restoring the
 * default of deriving the host key list from the loaded private keys; a client
 * has no such fallback. KeyAccepted accepts NULL on either side, but that
 * empties the list rather than restoring a default: the server then advertises
 * an empty RFC 8308 "server-sig-algs", telling clients it accepts no signature
 * algorithms, which stops OpenSSH clients offering rsa-sha2-256/512. */
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
/* Reserved. wolfSSH_CTX_SetFwdCb() stores one of these, but nothing in the
 * library calls it: forwarded data moves through the channel API. The
 * parameter is kept so existing calls still compile. */
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
DEPRECATED WOLFSSH_API WOLFSSH_CHANNEL* wolfSSH_ChannelFwdNew(WOLFSSH* ssh,
        const char* host, word32 hostPort, const char* origin,
        word32 originPort);
DEPRECATED WOLFSSH_API int wolfSSH_ChannelSetFwdFd(WOLFSSH_CHANNEL* channel,
        int fwdFd);
DEPRECATED WOLFSSH_API int wolfSSH_ChannelGetFwdFd(
        const WOLFSSH_CHANNEL* channel);
/* Ask the peer to listen on bindAddr:bindPort and tunnel what arrives back as
 * "forwarded-tcpip" channels. Client-only, per RFC 4254 7.1. bindPort 0 asks
 * the peer to choose, and needs wantReply, since its reply is the only place
 * the bound port is named; without it the call returns WS_BAD_ARGUMENT.
 *
 * A client refuses any "forwarded-tcpip" open naming a bind it has not
 * registered, per RFC 4254 7.2, from the session's start rather than from the
 * first call here, so one that registers nothing refuses them all. A bind of
 * "", "*", "0.0.0.0", or an IPv6 any-address matches on port alone; anything
 * else must equal the address the peer reports. Register the spelling the peer
 * will echo back, or a wildcard: a peer that canonicalises the bind, answering
 * an open for "127.0.0.1" against a registered "localhost", has those opens
 * refused. wolfSSH_SetFwdRemoteMatch() relaxes this for peers that need it.
 *
 * One bindAddr:bindPort is one registration however often it is registered,
 * since it is one listener on the peer, so one cancel undoes it. That covers a
 * port-0 request the peer answers with a port already registered, and a repeat
 * the peer refuses because it already has that listener keeps what the first
 * request registered.
 *
 * Several requests can name one bind at once, and the last one sent governs.
 * Registering again while a cancel is outstanding brings the forward back as
 * the request goes out, and no answer to that older cancel takes it away
 * again, whatever order the peer answers in. A request one of these calls
 * makes from a callback it fires is no different: it goes out behind this
 * one, so it is the one that governs.
 *
 * WS_WANT_WRITE means the request is framed and goes out on the next flush,
 * with the forward registered. So does an error reported after the request
 * reached the peer: the rekey a send can trigger runs once the last byte is
 * out and fails here. Retrying then is a repeat setup, which is harmless. Only
 * an error that kept the request off the wire leaves nothing registered.
 *
 * Cancel takes the port the peer bound, which after a port-0 request is the
 * one it reported, not 0; the forward cannot be cancelled before that reply
 * arrives. The forward stops matching as the cancel goes out, so revoking one
 * never waits on the peer and an open racing it is refused. Without wantReply
 * that is the end of it. With it the registration is held until the peer
 * answers: a refusal leaves the listener up and puts the forward back, and a
 * confirmation drops it. With several cancels outstanding, every one of them
 * has to be refused for the forward to come back. */
WOLFSSH_API int wolfSSH_FwdRemoteSetup(WOLFSSH* ssh, const char* bindAddr,
        word32 bindPort, int wantReply);
WOLFSSH_API int wolfSSH_FwdRemoteCancel(WOLFSSH* ssh, const char* bindAddr,
        word32 bindPort, int wantReply);

/* How strictly an inbound "forwarded-tcpip" open must name a registration
 * made with wolfSSH_FwdRemoteSetup(). */
enum WS_FwdRemoteMatch {
    WOLFSSH_FWD_MATCH_STRICT = 0, /* bind and port, the default */
    WOLFSSH_FWD_MATCH_PORT   = 1, /* port alone, the bind is not compared */
    WOLFSSH_FWD_MATCH_OFF    = 2  /* accept any open, matching nothing */
};

/* Relax the match this session holds inbound "forwarded-tcpip" opens to. A
 * client matches them from the start, so a session that registered nothing
 * refuses them all; set this before the peer can send one.
 *
 * STRICT is the default and is what RFC 4254 7.2 asks for. PORT is for a peer
 * that rewrites the bind address it echoes back but keeps the port, which
 * STRICT refuses every open from. OFF accepts any "forwarded-tcpip" open, as
 * wolfSSH did before this check existed, leaving the channel-open policy
 * callback as the only thing standing between the peer and a new channel.
 *
 * Returns WS_BAD_ARGUMENT for a NULL session or an unknown setting. */
WOLFSSH_API int wolfSSH_SetFwdRemoteMatch(WOLFSSH* ssh, byte match);

WOLFSSH_API int wolfSSH_ChannelFree(WOLFSSH_CHANNEL* channel);
WOLFSSH_API int wolfSSH_ChannelGetId(WOLFSSH_CHANNEL* channel, word32* id,
        byte peer);
WOLFSSH_API WOLFSSH_CHANNEL* wolfSSH_ChannelFind(WOLFSSH* ssh, word32 id,
        byte peer);
WOLFSSH_API WOLFSSH_CHANNEL* wolfSSH_ChannelNext(WOLFSSH* ssh,
        WOLFSSH_CHANNEL* channel);
/* Drains buffered data from the named channel: returns 0 when empty, never
 * receives, never reports EOF. Carries wolfSSH_stream_read()'s window-adjust
 * contract but does not clear ssh->error on entry; check it after the call. */
WOLFSSH_API int wolfSSH_ChannelRead(WOLFSSH_CHANNEL* channel, byte* buf,
        word32 bufSz);
WOLFSSH_API int wolfSSH_ChannelSend(WOLFSSH_CHANNEL* channel, const byte* buf,
        word32 bufSz);
/* The Ext variants carry extended data (stderr) rather than normal data. See
 * wolfSSH_extended_data_read() below for the drain contract; these read and
 * write the named channel instead of the first one in the channel list. */
WOLFSSH_API int wolfSSH_ChannelReadExt(WOLFSSH_CHANNEL* channel, byte* buf,
        word32 bufSz);
WOLFSSH_API int wolfSSH_ChannelSendExt(WOLFSSH_CHANNEL* channel,
        const byte* buf, word32 bufSz);
/* Sends EOF then SSH_MSG_CHANNEL_CLOSE. The channel stays on the list, and the
 * pointer stays valid, until the peer's close arrives and wolfSSH_worker()
 * reports WS_CHANNEL_CLOSED. A walk with wolfSSH_ChannelNext() has to step
 * past a channel it has exited rather than re-read the head, which no longer
 * moves.
 *
 * A WS_WANT_WRITE means the teardown is incomplete: the close is only built
 * once the EOF is away, so call again until it reports something else. The
 * retry costs nothing, a bundled EOF is not sent twice. WS_SUCCESS means both
 * messages are bundled, not that they reached the peer: keep driving
 * wolfSSH_worker() until it stops reporting WS_WANT_WRITE before dropping the
 * socket. A channel whose open the peer has not confirmed has no peer id to
 * address and reports WS_CHANNEL_NOT_CONF.
 *
 * A peer that never answers leaves the channel on the list for the life of
 * the session; there is no reclaim short of wolfSSH_free(). */
WOLFSSH_API int wolfSSH_ChannelExit(WOLFSSH_CHANNEL* channel);
/* Sends SSH_MSG_CHANNEL_EOF, closing the sending direction and leaving the
 * receiving direction open (the half-close of RFC 4254 section 5.3). Data
 * sends on the channel then fail with WS_EOF -- wolfSSH_ChannelSend(),
 * wolfSSH_stream_send() and the extended-data variants; requests, the exit
 * status and the teardown messages still go out. Reads work until the peer
 * sends its own EOF or closes. Idempotent: a second call puts no second EOF
 * on the wire.
 *
 * The library never answers a received EOF with one of its own. It reports it
 * as WS_EOF and through the channel EOF callback, and the application decides
 * whether to reply, with this call or wolfSSH_stream_send_eof(). A
 * back-pressure status can supersede the WS_EOF from wolfSSH_worker();
 * wolfSSH_ChannelGetEof() is the durable check.
 * wolfSSH_ChannelExit() and wolfSSH_shutdown() send an EOF themselves while
 * tearing the channel down.
 *
 * Returns WS_SUCCESS, WS_BAD_ARGUMENT on a NULL channel,
 * WS_CHANNEL_NOT_CONF if the peer has not confirmed the channel open yet,
 * WS_REKEYING during a key exchange, WS_FATAL_ERROR with WS_DISCONNECT
 * latched once the session is over, or a send-path status such as
 * WS_WANT_WRITE. */
WOLFSSH_API int wolfSSH_ChannelSendEof(WOLFSSH_CHANNEL* channel);
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
    word32 dataToSignSz; /* signed request length; 0 = derive from the fields */
#ifdef WOLFSSH_OSSH_CERTS
    /* Set while isOsshCert; the callback must trust-check caKey. Keep last so
     * the members above hold their offsets in both builds. */
    byte isOsshCert:1;
    const byte* caKey;
    word32 caKeySz;
    const byte* principals;
    word32 principalsSz;
    word64 validAfter;  /* epoch seconds */
    word64 validBefore;
    /* NULL when absent; sourceAddress is a comma-separated CIDR list. */
    const byte* forceCommand;
    word32 forceCommandSz;
    const byte* sourceAddress;
    word32 sourceAddressSz;
#endif /* WOLFSSH_OSSH_CERTS */
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

/* User Authentication Callback
 *
 * A server-side callback that decides whether to authenticate a client.
 * Return WOLFSSH_USERAUTH_SUCCESS only on a positive authentication
 * decision. WOLFSSH_USERAUTH_PARTIAL_SUCCESS reports that one factor of
 * a multi-method authentication passed, WOLFSSH_USERAUTH_SUCCESS_ANOTHER
 * reports that a keyboard-interactive round passed and asks for the next
 * round, WOLFSSH_USERAUTH_WOULD_BLOCK asks for the request to be
 * retried, and WOLFSSH_USERAUTH_REJECTED is a hard rejection: the server
 * answers with USERAUTH_FAILURE, then ends the session. Any other value
 * is treated as an ordinary failure.
 *
 * WARNING: WOLFSSH_USERAUTH_SUCCESS has the value 0, the same as
 * WS_SUCCESS and the C "no error" idiom. A bare "return 0;", a forwarded
 * WS_SUCCESS from a helper, or a fall-through default of 0 silently
 * authenticates the client. Return WOLFSSH_USERAUTH_FAILURE for any
 * authType or code path the callback does not explicitly handle.
 *
 * For WOLFSSH_USERAUTH_PUBLICKEY, the callback must check the offered
 * public key against the user's authorized keys; returning success on an
 * unchecked key authorizes an attacker-supplied key. The library verifies
 * the signature, not the key's authorization. */
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

/* Public Key Check Callback
 *
 * A client-side callback that decides whether to trust the server's host
 * key, the client's only defense against a man-in-the-middle. Return 0 to
 * accept the key; return non-zero to reject it and fail the key exchange.
 *
 * WARNING: 0 accepts, so a stub that defaults to "return 0;" accepts any
 * server host key and defeats MITM protection. The callback must match
 * the key against a trust store, e.g. a known-hosts list; see
 * ClientPublicKeyCheck() in the examples. If no callback is registered,
 * the host key is rejected (WS_PUBKEY_REJECTED_E). */
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
/* ProtoIdStr is checked for validity and will be rejected unless
 * it adheres to these criteria:
 * MUST begin with "SSH-2.0-"
 * MUST be between 11 and 255 bytes in length, counting the "SSH-2.0-"
 *     prefix and the trailing "\r\n"
 * MUST end with '\r\n'
 * MUST NOT contain '\r' or '\n' in the body
 * If these are not adhered to the function will return WS_BAD_ARGUMENT
 * and not load the ProtoId in to the WOLFSSH_CTX struct.
 * ProtoIdStr is stored by reference and is not copied, so it must remain
 * valid for the lifetime of the WOLFSSH_CTX. */
WOLFSSH_API int wolfSSH_CTX_SetSshProtoIdStr(WOLFSSH_CTX* ctx,
        const char* protoIdStr);
/* Set the server-side limit on failed userauth attempts per connection. The
 * default is DEFAULT_MAX_AUTH_ATTEMPTS (6), the same value as the OpenSSH
 * MaxAuthTries default. When the limit is reached the server sends an
 * SSH_MSG_DISCONNECT and drops the connection. A value <= 0 restores the
 * built-in default; there is no "unlimited" setting. Every request that does
 * not fully authenticate is charged, including a partial success; only the
 * opening "none" probe clients use to learn the method list is exempt.
 * The WOLFSSH setter overrides the value inherited from the CTX for one
 * session; the getters return the current value or WS_BAD_ARGUMENT. */
WOLFSSH_API int wolfSSH_CTX_SetMaxAuthAttempts(WOLFSSH_CTX* ctx, int value);
WOLFSSH_API int wolfSSH_CTX_GetMaxAuthAttempts(WOLFSSH_CTX* ctx);
WOLFSSH_API int wolfSSH_SetMaxAuthAttempts(WOLFSSH* ssh, int value);
WOLFSSH_API int wolfSSH_GetMaxAuthAttempts(WOLFSSH* ssh);
WOLFSSH_API int wolfSSH_CTX_UsePrivateKey_buffer(WOLFSSH_CTX* ctx,
                                                 const byte* in, word32 inSz,
                                                 int format);
#ifdef WOLFSSH_CERTS
    /* Takes the leaf; of several PEM certs, only the first is read. The
     * trusted form is for root CAs, so it is declined here. */
    WOLFSSH_API int wolfSSH_CTX_UseCert_buffer(WOLFSSH_CTX* ctx,
            const byte* cert, word32 certSz, int format);
    /* Loads every PEM cert, plain or trusted (wolfSSL 5.8.0+), so a bundle
     * installs all its CAs. A failing block is skipped; no CA fails the call. */
    WOLFSSH_API int wolfSSH_CTX_AddRootCert_buffer(WOLFSSH_CTX* ctx,
            const byte* cert, word32 certSz, int format);
    #if !defined(NO_FILESYSTEM) && !defined(WOLFSSH_USER_FILESYSTEM)
    /* PEM or DER is detected from the file's content. */
    WOLFSSH_API int wolfSSH_CTX_UseCert_file(WOLFSSH_CTX* ctx,
            const char* name);
    WOLFSSH_API int wolfSSH_CTX_AddRootCert_file(WOLFSSH_CTX* ctx,
            const char* name);
    #endif
    #ifdef WOLFSSH_WINDOWS_CERT_STORE
    WOLFSSH_API int wolfSSH_CTX_UsePrivateKey_fromStore(WOLFSSH_CTX* ctx,
            const wchar_t* storeName, word32 dwFlags,
            const wchar_t* subjectName);
    #endif
#endif /* WOLFSSH_CERTS */
WOLFSSH_API int wolfSSH_CTX_SetWindowPacketSize(WOLFSSH_CTX* ctx,
        word32 windowSz, word32 maxPacketSz);

WOLFSSH_API int wolfSSH_accept(WOLFSSH* ssh);
WOLFSSH_API int wolfSSH_connect(WOLFSSH* ssh);
WOLFSSH_API int wolfSSH_shutdown(WOLFSSH* ssh);
/* A disconnect, sent or received, ends the session. Nothing more goes out:
 * wolfSSH_shutdown() above this comment, and every send call below it,
 * report WS_DISCONNECT from then on, as do wolfSSH_accept(),
 * wolfSSH_connect() and wolfSSH_worker(). None of the three flushes a
 * disconnect of ours left queued by a short send; wolfSSH_shutdown() or
 * another wolfSSH_SendDisconnect() owns that. Inbound traffic is dropped:
 * the receive path skips every message but a DISCONNECT, so late channel
 * data is discarded and the channel callbacks stop firing. Reads are not
 * gated, so channel data that arrived before the disconnect can still be
 * drained; wolfSSH_stream_read() and wolfSSH_stream_peek() report
 * WS_DISCONNECT once their buffer runs dry. A CHANNEL_EOF received on that
 * channel is drained the same way, and is the one reported when both are
 * pending. RFC 4253 section 11.1. */
WOLFSSH_API int wolfSSH_stream_peek(WOLFSSH* ssh, byte* buf, word32 bufSz);
/* Returns the bytes read; the next read clears the status. WS_WANT_WRITE
 * from wolfSSH_get_error() means the adjust is queued; it goes out on the
 * next send or a wolfSSH_worker() whose receive succeeded. Others failed. */
WOLFSSH_API int wolfSSH_stream_read(WOLFSSH* ssh, byte* buf, word32 bufSz);
WOLFSSH_API int wolfSSH_stream_send(WOLFSSH* ssh, byte* buf, word32 bufSz);
/* Half-closes the first channel in the list. See wolfSSH_ChannelSendEof().
 * Unlike wolfSSH_stream_send(), which returns WS_FATAL_ERROR with the cause
 * latched, this reports WS_REKEYING itself, the way wolfSSH_stream_peek()
 * does. */
WOLFSSH_API int wolfSSH_stream_send_eof(WOLFSSH* ssh);
WOLFSSH_API int wolfSSH_stream_exit(WOLFSSH* ssh, int status);
WOLFSSH_API int wolfSSH_extended_data_send(WOLFSSH* ssh, byte* buf, word32 bufSz);
/* Reads the buffered stderr of the first channel in the channel list into out;
 * returns the number of bytes read (>= 0) or a negative WS_ error. outSz of 0
 * is WS_BAD_ARGUMENT. This is the stderr counterpart of wolfSSH_stream_read(),
 * and reads the same channel it does.
 *
 * Apps MUST drain stderr: it shares the channel receive window with stdout
 * (RFC 4254 5.2) and the window is only replenished here, so unread stderr
 * eventually stalls the channel. Call after wolfSSH_stream_read() returns
 * WS_EXTDATA, until this returns 0.
 *
 * A session with more than one open channel cannot be served by this pair:
 * wolfSSH_stream_read() reports data, normal or extended, only for the first
 * channel and fails with WS_ERROR on anything else. Read those channels with
 * wolfSSH_ChannelIdRead() and wolfSSH_ChannelIdReadExt(), which name the
 * channel, and drain each one's stderr for the same reason;
 * wolfSSH_worker() names the channel the extended data arrived on when it
 * returns WS_EXTDATA.
 *
 * Draining sends the peer a window adjust. On a non-blocking socket that send
 * can be short: the byte count is still returned, but wolfSSH_get_error() is
 * left at WS_WANT_WRITE to show a flush is owed. An app that only reads must
 * then flush, with wolfSSH_worker(), or the peer's window is never replenished
 * and the channel stalls. After a disconnect there is nothing to flush: the
 * credit is parked on the channel rather than sent.
 *
 * The buffer lives on the channel: anything unread when the channel is removed
 * (the peer's CHANNEL_CLOSE) is discarded with it. */
WOLFSSH_API int wolfSSH_extended_data_read(WOLFSSH* ssh, byte* out,
        word32 outSz);
WOLFSSH_API int wolfSSH_TriggerKeyExchange(WOLFSSH* ssh);
WOLFSSH_API int wolfSSH_SendIgnore(WOLFSSH* ssh, const byte* buf, word32 bufSz);
/* One disconnect ends the session, so a second call reports WS_DISCONNECT.
 * The exception is a disconnect of this side's own, left short by a
 * non-blocking socket: while it is still queued, calling again retries the
 * flush, since bundled bytes are not new traffic. wolfSSH_shutdown() retries
 * it too, with or without a channel. A disconnect from the peer is not that
 * case: it leaves only unrelated traffic queued, and that stays put. */
WOLFSSH_API int wolfSSH_SendDisconnect(WOLFSSH* ssh, word32 reason);
/* Send a global request under a name the caller supplies. The request-specific
 * data RFC 4254 7.1 puts after the want-reply boolean cannot be carried here,
 * so requests needing it have their own calls. Replies carry no request id, so
 * with reply set this claims a place in the same send-order queue
 * wolfSSH_FwdRemoteSetup() uses. */
WOLFSSH_API int wolfSSH_global_request(WOLFSSH* ssh, const unsigned char* data,
        word32 dataSz, int reply);
/* Reads the channel named by channelId, with wolfSSH_ChannelRead()'s
 * contract, except that wolfSSH_ChannelIdRead() reads during a rekey where
 * wolfSSH_ChannelRead() returns WS_REKEYING. */
WOLFSSH_API int wolfSSH_ChannelIdRead(WOLFSSH* ssh, word32 channelId,
        byte* buf, word32 bufSz);
WOLFSSH_API int wolfSSH_ChannelIdSend(WOLFSSH* ssh, word32 channelId,
        byte* buf, word32 bufSz);
WOLFSSH_API int wolfSSH_ChannelIdReadExt(WOLFSSH* ssh, word32 channelId,
        byte* buf, word32 bufSz);
WOLFSSH_API int wolfSSH_ChannelIdSendExt(WOLFSSH* ssh, word32 channelId,
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


/* X.509 certificates are consumed by UseCert/AddRootCert, OpenSSH ones by
   the trusted user CA machinery. UNKNOWN leads so that a zeroed flavor is
   not a claim about the content. */
enum WS_CertFlavors {
    WOLFSSH_CERT_FLAVOR_UNKNOWN,
    WOLFSSH_CERT_FLAVOR_X509,
    WOLFSSH_CERT_FLAVOR_OSSH
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


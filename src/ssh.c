/* ssh.c
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


/* CompareStringOrdinal() and friends need a Vista-or-later SDK profile;
 * mingw-w64 has historically defaulted _WIN32_WINNT to pre-Vista, so raise
 * the floor before the first header that pulls in <windows.h> (wolfssh/ssh.h
 * via port.h does). The undefined case is raised only under mingw: MSVC's
 * SDK defaults an undefined _WIN32_WINNT to its newest profile, which a
 * 0x0600 define here would silently lower. An explicit pre-Vista target is
 * raised on any compiler since this file cannot build against it. WINVER is
 * pinned alongside so the two profiles cannot disagree. Keyed on _WIN32
 * rather than WOLFSSH_WINDOWS_CERT_STORE: this is the only macro guaranteed
 * defined this early, since a user_settings.h build defines
 * WOLFSSH_WINDOWS_CERT_STORE only once <wolfssh/ssh.h> pulls in settings.h
 * below, after <windows.h> has already been seen. Harmless for
 * non-cert-store Windows builds. */
#if defined(_WIN32) && \
    ((defined(__MINGW32__) && !defined(_WIN32_WINNT)) || \
     (defined(_WIN32_WINNT) && _WIN32_WINNT < 0x0600))
    #undef  _WIN32_WINNT
    #define _WIN32_WINNT 0x0600
    #undef  WINVER
    #define WINVER 0x0600
#endif

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssh/ssh.h>
#include <wolfssh/internal.h>
#include <wolfssh/log.h>
#include <wolfssl/wolfcrypt/wc_port.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/random.h>

#ifdef WOLFSSH_WINDOWS_CERT_STORE
    #include <windows.h>
    #include <wincrypt.h>
    #include <ncrypt.h>
    #include <string.h>
    #include <wchar.h>
    /* Fallbacks for SDKs that predate these wincrypt.h/ncrypt.h
     * definitions. The values must match the SDK headers exactly. The
     * CERT_SYSTEM_STORE_* location constants are consumed only by
     * src/certman.c, which carries its own fallbacks. */
    #ifndef CERT_NCRYPT_KEY_SPEC
        #define CERT_NCRYPT_KEY_SPEC 0xFFFFFFFF
    #endif
    #ifndef CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG
        #define CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG 0x00040000
    #endif
    #ifndef NCRYPT_KEY_USAGE_PROPERTY
        #define NCRYPT_KEY_USAGE_PROPERTY L"Key Usage"
    #endif
    #ifndef NCRYPT_ALLOW_DECRYPT_FLAG
        #define NCRYPT_ALLOW_DECRYPT_FLAG 0x00000001
    #endif
    #ifndef NCRYPT_ALLOW_SIGNING_FLAG
        #define NCRYPT_ALLOW_SIGNING_FLAG 0x00000002
    #endif
#endif /* WOLFSSH_WINDOWS_CERT_STORE */

#ifdef NO_INLINE
    #include <wolfssh/misc.h>
#else
    #define WOLFSSH_MISC_INCLUDED
    #if defined(WOLFSSL_NUCLEUS)
        #include "src/wolfssh_misc.c"
    #else
        #include "src/misc.c"
    #endif
#endif

#ifdef HAVE_FIPS
#include <wolfssl/wolfcrypt/fips_test.h>
static void myFipsCb(int ok, int err, const char* hash)
{
    printf("in my Fips callback, ok = %d, err = %d\n", ok, err);
    printf("message = %s\n", wc_GetErrorString(err));
    printf("hash = %s\n", hash);

    if (err == IN_CORE_FIPS_E) {
        printf("In core integrity hash check failure, copy above hash\n");
        printf("into verifyCore[] in fips_test.c and rebuild\n");
    }
}
#endif /* HAVE_FIPS */

int wolfSSH_Init(void)
{
    int ret = WS_SUCCESS;

    WLOG(WS_LOG_DEBUG, "Entering wolfSSH_Init()");
    if (wolfCrypt_Init() != 0)
        ret = WS_CRYPTO_FAILED;

#ifdef HAVE_FIPS
    wolfCrypt_SetCb_fips(myFipsCb);
#endif
#if defined(WC_RNG_SEED_CB) && defined(HAVE_HASHDRBG)
    wc_SetSeed_Cb(wc_GenerateSeed);
#endif
#if !defined(NO_FILESYSTEM) && defined(WOLFSSH_ZEPHYR) && \
        (defined(WOLFSSH_SFTP) || defined(WOLFSSH_SCP))
    if (wssh_z_fds_init() != 0)
        ret = WS_CRYPTO_FAILED;
#endif

    WLOG(WS_LOG_DEBUG, "Leaving wolfSSH_Init(), returning %d", ret);
    return ret;
}


int wolfSSH_Cleanup(void)
{
    int ret = WS_SUCCESS;

    WLOG(WS_LOG_DEBUG, "Entering wolfSSH_Cleanup()");

    if (wolfCrypt_Cleanup() != 0)
        ret = WS_CRYPTO_FAILED;
#if !defined(NO_FILESYSTEM) && defined(WOLFSSH_ZEPHYR) && \
        (defined(WOLFSSH_SFTP) || defined(WOLFSSH_SCP))
    if (wssh_z_fds_cleanup() != 0)
        ret = WS_CRYPTO_FAILED;
#endif

    WLOG(WS_LOG_DEBUG, "Leaving wolfSSH_Cleanup(), returning %d", ret);
    return ret;
}


WOLFSSH_CTX* wolfSSH_CTX_new(byte side, void* heap)
{
    WOLFSSH_CTX* ctx;

    WLOG(WS_LOG_DEBUG, "Entering wolfSSH_CTX_new()");

    if (side != WOLFSSH_ENDPOINT_SERVER && side != WOLFSSH_ENDPOINT_CLIENT) {
        WLOG(WS_LOG_DEBUG, "Invalid endpoint type");
        return NULL;
    }

    ctx = (WOLFSSH_CTX*)WMALLOC(sizeof(WOLFSSH_CTX), heap, DYNTYPE_CTX);
    if (CtxInit(ctx, side, heap) == NULL) {
        WFREE(ctx, heap, DYNTYPE_CTX);
        ctx = NULL;
    }

    WLOG(WS_LOG_DEBUG, "Leaving wolfSSH_CTX_new(), ctx = %p", ctx);

    return ctx;
}


void wolfSSH_CTX_free(WOLFSSH_CTX* ctx)
{
    WLOG(WS_LOG_DEBUG, "Entering wolfSSH_CTX_free()");

    if (ctx) {
        CtxResourceFree(ctx);
        WFREE(ctx, ctx->heap, DYNTYPE_CTX);
    }
}


WOLFSSH* wolfSSH_new(WOLFSSH_CTX* ctx)
{
    WOLFSSH* ssh;
    void*    heap = NULL;

    WOLFSSH_UNUSED(heap);

    WLOG(WS_LOG_DEBUG, "Entering wolfSSH_new()");

    if (ctx)
        heap = ctx->heap;
    else {
        WLOG(WS_LOG_ERROR, "Trying to init a wolfSSH w/o wolfSSH_CTX");
        return NULL;
    }

    ssh = (WOLFSSH*)WMALLOC(sizeof(WOLFSSH), heap, DYNTYPE_SSH);
    ssh = SshInit(ssh, ctx);

    WLOG(WS_LOG_DEBUG, "Leaving wolfSSH_new(), ssh = %p", ssh);

    return ssh;
}


void wolfSSH_free(WOLFSSH* ssh)
{
    WLOG(WS_LOG_DEBUG, "Entering wolfSSH_free()");

    if (ssh) {
        void* heap = ssh->ctx ? ssh->ctx->heap : NULL;
    #ifdef WOLFSSH_SFTP
        if (wolfSSH_SFTP_free(ssh) != WS_SUCCESS) {
            WLOG(WS_LOG_SFTP, "Error cleaning up SFTP connection");
        }
    #endif
    #ifdef WOLFSSH_AGENT
        if (ssh->agent != NULL)
            wolfSSH_AGENT_free(ssh->agent);
    #endif /* WOLFSSH_AGENT */
        SshResourceFree(ssh, heap);
        WFREE(ssh, heap, DYNTYPE_SSH);
    }
}


int wolfSSH_set_fd(WOLFSSH* ssh, WS_SOCKET_T fd)
{
    WLOG(WS_LOG_DEBUG, "Entering wolfSSH_set_fd()");

    if (ssh) {
        ssh->rfd = fd;
        ssh->wfd = fd;

        ssh->ioReadCtx  = &ssh->rfd;
        ssh->ioWriteCtx = &ssh->wfd;

        return WS_SUCCESS;
    }
    return WS_BAD_ARGUMENT;
}


WS_SOCKET_T wolfSSH_get_fd(const WOLFSSH* ssh)
{
    WLOG(WS_LOG_DEBUG, "Entering wolfSSH_get_fd()");

    if (ssh)
        return ssh->rfd;

#ifdef USE_WINDOWS_API
    return INVALID_SOCKET;
#else
    return WS_BAD_ARGUMENT;
#endif
}


int wolfSSH_SetFilesystemHandle(WOLFSSH* ssh, void* handle)
{
    WLOG(WS_LOG_DEBUG, "Entering wolfSSH_SetFilesystemHandle()");

    if (ssh) {
        ssh->fs = handle;

        return WS_SUCCESS;
    }

    return WS_BAD_ARGUMENT;
}


void* wolfSSH_GetFilesystemHandle(WOLFSSH* ssh)
{
    WLOG(WS_LOG_DEBUG, "Entering wolfSSH_GetFilesystemHandle()");

    if (ssh)
        return ssh->fs;

    return NULL;
}


int wolfSSH_SetHighwater(WOLFSSH* ssh, word32 level)
{
    WLOG(WS_LOG_DEBUG, "Entering wolfSSH_SetHighwater()");

    if (ssh) {
        ssh->highwaterMark = level;

        return WS_SUCCESS;
    }

    return WS_BAD_ARGUMENT;
}


word32 wolfSSH_GetHighwater(WOLFSSH* ssh)
{
    WLOG(WS_LOG_DEBUG, "Entering wolfSSH_GetHighwater()");

    if (ssh)
        return ssh->highwaterMark;

    return 0;
}


void wolfSSH_CTX_SetMsgHighwater(WOLFSSH_CTX* ctx, word32 level)
{
    WLOG(WS_LOG_DEBUG, "Entering wolfSSH_CTX_SetMsgHighwater()");

    if (ctx)
        ctx->msgHighwaterMark = level;
}


void wolfSSH_SetMsgHighwater(WOLFSSH* ssh, word32 level)
{
    WLOG(WS_LOG_DEBUG, "Entering wolfSSH_SetMsgHighwater()");

    if (ssh)
        ssh->msgHighwaterMark = level;
}


word32 wolfSSH_GetMsgHighwater(WOLFSSH* ssh)
{
    WLOG(WS_LOG_DEBUG, "Entering wolfSSH_GetMsgHighwater()");

    if (ssh)
        return ssh->msgHighwaterMark;

    return 0;
}


void wolfSSH_SetHighwaterCb(WOLFSSH_CTX* ctx, word32 level,
        WS_CallbackHighwater cb)
{
    WLOG(WS_LOG_DEBUG, "Entering wolfSSH_SetHighwaterCb()");

    if (ctx) {
        ctx->highwaterMark = level;
        ctx->highwaterCb = cb;
    }
}


void wolfSSH_SetHighwaterCtx(WOLFSSH* ssh, void* ctx)
{
    WLOG(WS_LOG_DEBUG, "Entering wolfSSH_SetHighwaterCtx()");

    if (ssh)
        ssh->highwaterCtx = ctx;
}


void* wolfSSH_GetHighwaterCtx(WOLFSSH* ssh)
{
    WLOG(WS_LOG_DEBUG, "Entering wolfSSH_GetHighwaterCtx()");

    if (ssh)
        return ssh->highwaterCtx;

    return NULL;
}

void wolfSSH_SetGlobalReq(WOLFSSH_CTX *ctx, WS_CallbackGlobalReq cb)
{
    if (ctx)
        ctx->globalReqCb = cb;
}

void wolfSSH_SetReqSuccess(WOLFSSH_CTX *ctx, WS_CallbackReqSuccess cb)
{
    if (ctx)
        ctx->reqSuccessCb = cb;
}

void wolfSSH_SetReqFailure(WOLFSSH_CTX *ctx, WS_CallbackReqSuccess cb)
{
    if (ctx)
        ctx->reqFailureCb = cb;
}

void wolfSSH_SetGlobalReqCtx(WOLFSSH* ssh, void *ctx)
{
    WLOG(WS_LOG_DEBUG, "Entering wolfSSH_SetGlobalReqCtx()");

    if (ssh)
        ssh->globalReqCtx = ctx;
}

void *wolfSSH_GetGlobalReqCtx(WOLFSSH* ssh)
{
    WLOG(WS_LOG_DEBUG, "Entering wolfSSH_GetGlobalReqCtx()");

    if (ssh)
        return ssh->globalReqCtx;

    return NULL;
}

void wolfSSH_SetReqSuccessCtx(WOLFSSH *ssh, void *ctx)
{
    WLOG(WS_LOG_DEBUG, "Entering wolfSSH_SetReqSuccessCtx()");

    if (ssh)
        ssh->reqSuccessCtx = ctx;
}

void *wolfSSH_GetReqSuccessCtx(WOLFSSH *ssh)
{
    WLOG(WS_LOG_DEBUG, "Entering wolfSSH_GetReqSuccessCtx()");

    if (ssh)
        return ssh->reqSuccessCtx;

    return NULL;
}

void wolfSSH_SetReqFailureCtx(WOLFSSH *ssh, void *ctx)
{
    WLOG(WS_LOG_DEBUG, "Entering wolfSSH_SetReqFailureCtx()");

    if (ssh)
        ssh->reqFailureCtx = ctx;
}

void *wolfSSH_GetReqFailureCtx(WOLFSSH *ssh)
{
    WLOG(WS_LOG_DEBUG, "Entering wolfSSH_GetReqFailureCtx()");

    if (ssh)
        return ssh->reqFailureCtx;

    return NULL;
}

int wolfSSH_get_error(const WOLFSSH* ssh)
{
    WLOG(WS_LOG_DEBUG, "Entering wolfSSH_get_error()");

    if (ssh)
        return ssh->error;

    return WS_SSH_NULL_E;
}


const char* wolfSSH_get_error_name(const WOLFSSH* ssh)
{
    WLOG(WS_LOG_DEBUG, "Entering wolfSSH_get_error_name()");

    if (ssh)
        return GetErrorString(ssh->error);

    return GetErrorString(WS_SSH_NULL_E);
}


const char* wolfSSH_ErrorToName(int err)
{
    WLOG(WS_LOG_DEBUG, "Entering wolfSSH_ErrorToName()");

    return GetErrorString(err);
}


#ifdef WOLFSSH_TPM
void wolfSSH_SetTpmDev(WOLFSSH* ssh, WOLFTPM2_DEV* dev)
{
    WLOG(WS_LOG_DEBUG, "Entering wolfSSH_SetTpmDev()");

    if (ssh && ssh->ctx) {
        ssh->ctx->tpmDev = dev;

        if (ssh->ctx->tpmDev == NULL) {
            WLOG(WS_LOG_DEBUG, "wolfSSH_SetTpmDev: Set tpm dev failed");
        }
    }
}


void wolfSSH_SetTpmKey(WOLFSSH* ssh, WOLFTPM2_KEY* key)
{
    WLOG(WS_LOG_DEBUG, "Entering wolfSSH_SetTpmKey()");

    if (ssh && ssh->ctx) {
        ssh->ctx->tpmKey = key;

        if (ssh->ctx->tpmKey == NULL) {
            WLOG(WS_LOG_DEBUG, "wolfSSH_SetTpmKey: Set tpm key failed");
        }
    }
}


void* wolfSSH_GetTpmDev(WOLFSSH* ssh)
{
    WLOG(WS_LOG_DEBUG, "Entering wolfSSH_SetTpmDev()");

    if (ssh && ssh->ctx) {
        return ssh->ctx->tpmDev;
    }
    return NULL;
}


void* wolfSSH_GetTpmKey(WOLFSSH* ssh)
{
    WLOG(WS_LOG_DEBUG, "Entering wolfSSH_SetTpmKey()");

    if (ssh && ssh->ctx) {
        return ssh->ctx->tpmKey;
    }
    return NULL;
}


int wolfSSH_CTX_UseTpmHostKey(WOLFSSH_CTX* ctx,
        WOLFTPM2_DEV* dev, WOLFTPM2_KEY* key)
{
    int ret = WS_SUCCESS;
    byte keyId = ID_NONE;

    WLOG(WS_LOG_DEBUG, "Entering wolfSSH_CTX_UseTpmHostKey()");

    if (ctx == NULL || dev == NULL || key == NULL) {
        ret = WS_BAD_ARGUMENT;
    }

    /* Only one TPM host key is supported per context (single ctx->tpmKey). */
    if (ret == WS_SUCCESS && ctx->tpmKey != NULL && ctx->tpmKey != key) {
        WLOG(WS_LOG_DEBUG,
            "wolfSSH_CTX_UseTpmHostKey: a TPM host key is already set");
        ret = WS_BAD_ARGUMENT;
    }

    if (ret == WS_SUCCESS) {
        if (key->pub.publicArea.type == TPM_ALG_ECC) {
            switch (key->pub.publicArea.parameters.eccDetail.curveID) {
            #ifndef WOLFSSH_NO_ECDSA_SHA2_NISTP256
                case TPM_ECC_NIST_P256:
                    keyId = ID_ECDSA_SHA2_NISTP256;
                    break;
            #endif
            #ifndef WOLFSSH_NO_ECDSA_SHA2_NISTP384
                case TPM_ECC_NIST_P384:
                    keyId = ID_ECDSA_SHA2_NISTP384;
                    break;
            #endif
            #ifndef WOLFSSH_NO_ECDSA_SHA2_NISTP521
                case TPM_ECC_NIST_P521:
                    keyId = ID_ECDSA_SHA2_NISTP521;
                    break;
            #endif
                default:
                    ret = WS_INVALID_PRIME_CURVE;
            }
        }
        else if (key->pub.publicArea.type == TPM_ALG_RSA) {
        #if !defined(WOLFSSH_NO_RSA) && \
            (!defined(WOLFSSH_NO_RSA_SHA2_256) || \
             !defined(WOLFSSH_NO_RSA_SHA2_512) || \
             (defined(WOLFSSH_NO_SHA1_SOFT_DISABLE) && \
              !defined(WOLFSSH_NO_SSH_RSA_SHA1)))
            keyId = ID_SSH_RSA;
        #else
            ret = WS_INVALID_ALGO_ID;
        #endif
        }
        else {
            ret = WS_INVALID_ALGO_ID;
        }
    }

    if (ret == WS_SUCCESS) {
        ctx->tpmDev = dev;
        ctx->tpmKey = key;
        ret = wolfSSH_SetHostTpmKey(ctx, keyId);
    }

    WLOG(WS_LOG_DEBUG,
            "Leaving wolfSSH_CTX_UseTpmHostKey(), ret = %d", ret);
    return ret;
}
#endif /* WOLFSSH_TPM */


#if !defined(NO_WOLFSSH_SERVER) || !defined(NO_WOLFSSH_CLIENT)

/* A peer's CHANNEL_EOF is legal once its channel is open, RFC 4254 section
 * 5.3, not a handshake failure. */
static int DoReceiveHandshake(WOLFSSH* ssh)
{
    int ret = DoReceive(ssh);

    if (ret == WS_EOF)
        ret = WS_SUCCESS;

    return ret;
}

#endif /* !NO_WOLFSSH_SERVER || !NO_WOLFSSH_CLIENT */


/* Defined below, ahead of both drivers; either can be the only one built. */
static int SendAfterDisconnect(WOLFSSH* ssh);


#ifndef NO_WOLFSSH_SERVER

const char acceptError[] = "accept error: %s, %d";
const char acceptState[] = "accept state: %s";


int wolfSSH_accept(WOLFSSH* ssh)
{
    WLOG(WS_LOG_DEBUG, "Entering wolfSSH_accept()");

    if (ssh == NULL)
        return WS_BAD_ARGUMENT;

    /* No handshake on a session that is over. The pending-send block below
     * would flush a queued disconnect as the next handshake message. */
    if (SendAfterDisconnect(ssh))
        return WS_FATAL_ERROR;

    /* clear want read/writes for retry */
    if (ssh->error == WS_WANT_READ || ssh->error == WS_WANT_WRITE || ssh->error == WS_AUTH_PENDING)
        ssh->error = 0;

    if (ssh->error != 0) {
        WLOG(WS_LOG_DEBUG, "Calling wolfSSH_accept in error state");
        return WS_INVALID_STATE_E;
    }

    /* check if data pending to be sent */
    if (ssh->outputBuffer.length > 0 &&
            ssh->acceptState < ACCEPT_CLIENT_SESSION_ESTABLISHED) {
        if ((ssh->error = wolfSSH_SendPacket(ssh)) == WS_SUCCESS) {
            WLOG(WS_LOG_DEBUG, "Sent pending packet");

            /* adjust state, a couple of them use multiple sends */
            if (ssh->acceptState != ACCEPT_SERVER_VERSION_SENT &&
                ssh->acceptState != ACCEPT_SERVER_USERAUTH_ACCEPT_SENT &&
                ssh->acceptState != ACCEPT_SERVER_KEXINIT_SENT &&
                ssh->acceptState != ACCEPT_KEYED &&
                ssh->acceptState != ACCEPT_SERVER_CHANNEL_ACCEPT_SENT) {
                WLOG(WS_LOG_DEBUG, "Advancing accept state");
                ssh->acceptState++;
            }

            /* handle in process reply state */
            if (ssh->processReplyState == PROCESS_PACKET) {
                WLOG(WS_LOG_DEBUG, "PR3: peerMacSz = %u", ssh->peerMacSz);
                ssh->inputBuffer.idx += ssh->peerMacSz;
                WLOG(WS_LOG_DEBUG, "PR4: Shrinking input buffer");
                ShrinkBuffer(&ssh->inputBuffer, 1);
                ssh->processReplyState = PROCESS_INIT;

                WLOG(WS_LOG_DEBUG, "PR5: txCount = %u, rxCount = %u",
                    ssh->txCount, ssh->rxCount);
            }
        }
        else {
            return WS_FATAL_ERROR;
        }
    }

    while (ssh->acceptState != ACCEPT_CLIENT_SESSION_ESTABLISHED) {
        switch (ssh->acceptState) {

            case ACCEPT_BEGIN:
                if ( (ssh->error = SendProtoId(ssh)) < WS_SUCCESS) {
                    WLOG(WS_LOG_DEBUG, acceptError, "BEGIN", ssh->error);
                    return WS_FATAL_ERROR;
                }
                ssh->acceptState = ACCEPT_SERVER_VERSION_SENT;
                WLOG(WS_LOG_DEBUG, acceptState, "SERVER_VERSION_SENT");
                FALL_THROUGH;

            case ACCEPT_SERVER_VERSION_SENT:
                while (ssh->clientState < CLIENT_VERSION_DONE) {
                    if ( (ssh->error = DoProtoId(ssh)) < WS_SUCCESS) {
                        WLOG(WS_LOG_DEBUG, acceptError,
                             "SERVER_VERSION_SENT", ssh->error);
                        return WS_FATAL_ERROR;
                    }
                }
                ssh->acceptState = ACCEPT_CLIENT_VERSION_DONE;
                WLOG(WS_LOG_DEBUG, acceptState, "CLIENT_VERSION_DONE");
                FALL_THROUGH;

            case ACCEPT_CLIENT_VERSION_DONE:
                if ( (ssh->error = SendKexInit(ssh)) < WS_SUCCESS) {
                    WLOG(WS_LOG_DEBUG, acceptError,
                         "CLIENT_VERSION_DONE", ssh->error);
                    return WS_FATAL_ERROR;
                }
                ssh->acceptState = ACCEPT_SERVER_KEXINIT_SENT;
                WLOG(WS_LOG_DEBUG, acceptState, "SERVER_KEXINIT_SENT");
                FALL_THROUGH;

            case ACCEPT_SERVER_KEXINIT_SENT:
                while (ssh->isKeying) {
                    if (DoReceive(ssh) < WS_SUCCESS) {
                        WLOG(WS_LOG_DEBUG, acceptError,
                             "SERVER_KEXINIT_SENT", ssh->error);
                        return WS_FATAL_ERROR;
                    }
                }
                ssh->acceptState = ACCEPT_KEYED;
                WLOG(WS_LOG_DEBUG, acceptState, "KEYED");
                FALL_THROUGH;

            case ACCEPT_KEYED:
                while (ssh->clientState < CLIENT_USERAUTH_REQUEST_DONE) {
                    if (DoReceive(ssh) < 0) {
                        WLOG(WS_LOG_DEBUG, acceptError,
                             "KEYED", ssh->error);
                        return WS_FATAL_ERROR;
                    }
                }
                ssh->acceptState = ACCEPT_CLIENT_USERAUTH_REQUEST_DONE;
                WLOG(WS_LOG_DEBUG, acceptState, "CLIENT_USERAUTH_REQUEST_DONE");
                FALL_THROUGH;

            case ACCEPT_CLIENT_USERAUTH_REQUEST_DONE:
                if ( (ssh->error = SendServiceAccept(ssh,
                                ID_SERVICE_USERAUTH)) < WS_SUCCESS) {
                    WLOG(WS_LOG_DEBUG, acceptError,
                         "CLIENT_USERAUTH_REQUEST_DONE", ssh->error);
                    return WS_FATAL_ERROR;
                }
                ssh->acceptState = ACCEPT_SERVER_USERAUTH_ACCEPT_SENT;
                WLOG(WS_LOG_DEBUG, acceptState,
                     "ACCEPT_SERVER_USERAUTH_ACCEPT_SENT");
                FALL_THROUGH;

            case ACCEPT_SERVER_USERAUTH_ACCEPT_SENT:
                while (ssh->clientState < CLIENT_USERAUTH_DONE) {
                    if (DoReceive(ssh) < 0) {
                        WLOG(WS_LOG_DEBUG, acceptError,
                             "SERVER_USERAUTH_ACCEPT_SENT", ssh->error);
                        return WS_FATAL_ERROR;
                    }
                }
                ssh->acceptState = ACCEPT_CLIENT_USERAUTH_DONE;
                WLOG(WS_LOG_DEBUG, acceptState, "CLIENT_USERAUTH_DONE");
                FALL_THROUGH;

            case ACCEPT_CLIENT_USERAUTH_DONE:
                if ( (ssh->error = SendUserAuthSuccess(ssh)) < WS_SUCCESS) {
                    WLOG(WS_LOG_DEBUG, acceptError,
                         "CLIENT_USERAUTH_DONE", ssh->error);
                    return WS_FATAL_ERROR;
                }
                ssh->acceptState = ACCEPT_SERVER_USERAUTH_SENT;
                WLOG(WS_LOG_DEBUG, acceptState, "SERVER_USERAUTH_SENT");
                FALL_THROUGH;

            case ACCEPT_SERVER_USERAUTH_SENT:
                while (ssh->clientState < CLIENT_CHANNEL_OPEN_DONE) {
                    if (DoReceive(ssh) < 0) {
                        WLOG(WS_LOG_DEBUG, acceptError,
                             "SERVER_USERAUTH_SENT", ssh->error);
                        return WS_FATAL_ERROR;
                    }
                }
                ssh->acceptState = ACCEPT_SERVER_CHANNEL_ACCEPT_SENT;
                WLOG(WS_LOG_DEBUG, acceptState, "SERVER_CHANNEL_ACCEPT_SENT");
                FALL_THROUGH;

            case ACCEPT_SERVER_CHANNEL_ACCEPT_SENT:
                while (ssh->clientState < CLIENT_DONE) {
                    if (DoReceiveHandshake(ssh) < 0) {
                        WLOG(WS_LOG_DEBUG, acceptError,
                             "SERVER_CHANNEL_ACCEPT_SENT", ssh->error);
                        return WS_FATAL_ERROR;
                    }
                }

#ifdef WOLFSSH_SCP
                if (ChannelCommandIsScp(ssh)) {
                    ssh->acceptState = ACCEPT_INIT_SCP_TRANSFER;
                    WLOG(WS_LOG_DEBUG, acceptState, "ACCEPT_INIT_SCP_TRANSFER");
                    return WS_SCP_INIT;
                }
#endif
#if defined(WOLFSSH_SFTP) && !defined(NO_WOLFSSH_SERVER)
                {
                    const char* cmd = wolfSSH_GetSessionCommand(ssh);
                    if (cmd != NULL &&
                        WOLFSSH_SESSION_SUBSYSTEM == wolfSSH_GetSessionType(ssh)
                        && (WSTRNCMP(cmd, "sftp", 4) == 0)) {
                        ssh->acceptState = ACCEPT_INIT_SFTP;
                        return wolfSSH_SFTP_accept(ssh);
                    }
                }
#endif /* WOLFSSH_SFTP and !NO_WOLFSSH_SERVER */
#ifdef WOLFSSH_AGENT
                if (ssh->useAgent) {
                    WOLFSSH_AGENT_CTX* newAgent;
                    WOLFSSH_CHANNEL* newChannel;

                    WLOG(WS_LOG_AGENT, "Starting agent channel");

                    newAgent = wolfSSH_AGENT_new(ssh->ctx->heap);
                    if (newAgent == NULL) {
                        ssh->error = WS_MEMORY_E;
                        WLOG(WS_LOG_DEBUG, acceptError,
                            "SERVER_USERAUTH_ACCEPT_DONE", ssh->error);
                        return WS_ERROR;
                    }

                    newChannel = ChannelNew(ssh, ID_CHANTYPE_AUTH_AGENT,
                            ssh->ctx->windowSz, ssh->ctx->maxPacketSz);
                    if (newChannel == NULL) {
                        wolfSSH_AGENT_free(newAgent);
                        ssh->error = WS_MEMORY_E;
                        WLOG(WS_LOG_DEBUG, acceptError,
                            "SERVER_USERAUTH_ACCEPT_DONE", ssh->error);
                        return WS_FATAL_ERROR;
                    }

                    ssh->error = SendChannelOpenSession(ssh, newChannel);
                    if (ssh->error < WS_SUCCESS) {
                        if (ssh->error == WS_WANT_WRITE ||
                                ssh->error == WS_WANT_READ) {
                            ChannelAppend(ssh, newChannel);
                        }
                        else {
                            ChannelDelete(newChannel, ssh->ctx->heap);
                            wolfSSH_AGENT_free(newAgent);
                        }
                        WLOG(WS_LOG_DEBUG, acceptError,
                            "SERVER_USERAUTH_ACCEPT_DONE", ssh->error);
                        return WS_FATAL_ERROR;
                    }
                    ChannelAppend(ssh, newChannel);
                    newAgent->channel = newChannel->channel;
                    if (ssh->ctx->agentCb) {
                        ssh->ctx->agentCb(WOLFSSH_AGENT_LOCAL_SETUP,
                                ssh->agentCbCtx);
                    }
                    if (ssh->agent != NULL)
                        wolfSSH_AGENT_free(ssh->agent);
                    ssh->agent = newAgent;
                }
#endif /* WOLFSSH_AGENT */
                ssh->acceptState = ACCEPT_CLIENT_SESSION_ESTABLISHED;
                WLOG(WS_LOG_DEBUG, acceptState, "CLIENT_SESSION_ESTABLISHED");
                break;

#ifdef WOLFSSH_SCP
            case ACCEPT_INIT_SCP_TRANSFER:
                if (DoScpRequest(ssh) < 0) {
                    WLOG(WS_LOG_DEBUG, acceptError, "INIT_SCP_TRANSFER",
                         ssh->error);
                    return WS_FATAL_ERROR;
                }
                return WS_SCP_COMPLETE;
#endif
#ifdef WOLFSSH_SFTP
            case ACCEPT_INIT_SFTP:
                return wolfSSH_SFTP_accept(ssh);
#endif

        }
    } /* end while */

    return WS_SUCCESS;
}

#endif /* NO_WOLFSSH_SERVER */


#ifndef NO_WOLFSSH_CLIENT

const char connectError[] = "connect error: %s, %d";
const char connectState[] = "connect state: %s";


int wolfSSH_connect(WOLFSSH* ssh)
{
    WLOG(WS_LOG_DEBUG, "Entering wolfSSH_connect()");

    if (ssh == NULL)
        return WS_BAD_ARGUMENT;

    /* See wolfSSH_accept(). No error-state test here, so the peer's
     * disconnect reaches the state machine like a local one. */
    if (SendAfterDisconnect(ssh))
        return WS_FATAL_ERROR;

    /* check if data pending to be sent */
    if (ssh->outputBuffer.length > 0 &&
            ssh->connectState < CONNECT_SERVER_CHANNEL_REQUEST_DONE) {
        if ((ssh->error = wolfSSH_SendPacket(ssh)) == WS_SUCCESS) {
            WLOG(WS_LOG_DEBUG, "Sent pending packet");

            /* adjust state, a couple of them use multiple sends */
            if (ssh->connectState != CONNECT_CLIENT_VERSION_SENT &&
                ssh->connectState != CONNECT_CLIENT_KEXINIT_SENT &&
                ssh->connectState != CONNECT_CLIENT_KEXDH_INIT_SENT &&
                ssh->connectState != CONNECT_CLIENT_USERAUTH_REQUEST_SENT &&
                ssh->connectState != CONNECT_CLIENT_USERAUTH_SENT &&
                ssh->connectState != CONNECT_CLIENT_CHANNEL_OPEN_SESSION_SENT &&
                ssh->connectState != CONNECT_CLIENT_CHANNEL_REQUEST_SENT) {
                WLOG(WS_LOG_DEBUG, "Advancing connect state");
                ssh->connectState++;
            }

            /* handle in process reply state */
            if (ssh->processReplyState == PROCESS_PACKET) {
                WLOG(WS_LOG_DEBUG, "PR3: peerMacSz = %u", ssh->peerMacSz);
                ssh->inputBuffer.idx += ssh->peerMacSz;
                WLOG(WS_LOG_DEBUG, "PR4: Shrinking input buffer");
                ShrinkBuffer(&ssh->inputBuffer, 1);
                ssh->processReplyState = PROCESS_INIT;

                WLOG(WS_LOG_DEBUG, "PR5: txCount = %u, rxCount = %u",
                    ssh->txCount, ssh->rxCount);
            }
        }
        else {
            return WS_FATAL_ERROR;
        }
    }

    switch (ssh->connectState) {

        case CONNECT_BEGIN:
            if ( (ssh->error = SendProtoId(ssh)) < WS_SUCCESS) {
                WLOG(WS_LOG_DEBUG, connectError, "BEGIN", ssh->error);
                return WS_FATAL_ERROR;
            }
            ssh->connectState = CONNECT_CLIENT_VERSION_SENT;
            WLOG(WS_LOG_DEBUG, connectState, "CLIENT_VERSION_SENT");
            FALL_THROUGH;

        case CONNECT_CLIENT_VERSION_SENT:
            while (ssh->serverState < SERVER_VERSION_DONE) {
                if ( (ssh->error = DoProtoId(ssh)) < WS_SUCCESS) {
                    WLOG(WS_LOG_DEBUG, connectError,
                         "CLIENT_VERSION_SENT", ssh->error);
                    return WS_FATAL_ERROR;
                }
            }
            ssh->connectState = CONNECT_SERVER_VERSION_DONE;
            WLOG(WS_LOG_DEBUG, connectState, "SERVER_VERSION_DONE");
            FALL_THROUGH;

        case CONNECT_SERVER_VERSION_DONE:
            if ( (ssh->error = SendKexInit(ssh)) < WS_SUCCESS) {
                WLOG(WS_LOG_DEBUG, connectError,
                     "SERVER_VERSION_DONE", ssh->error);
                return WS_FATAL_ERROR;
            }
            ssh->connectState = CONNECT_CLIENT_KEXINIT_SENT;
            WLOG(WS_LOG_DEBUG, connectState, "CLIENT_KEXINIT_SENT");
            FALL_THROUGH;

        case CONNECT_CLIENT_KEXINIT_SENT:
            while (ssh->serverState < SERVER_KEXINIT_DONE) {
                if (DoReceive(ssh) < WS_SUCCESS) {
                    WLOG(WS_LOG_DEBUG, connectError,
                         "CLIENT_KEXINIT_SENT", ssh->error);
                    return WS_FATAL_ERROR;
                }
            }
            ssh->connectState = CONNECT_SERVER_KEXINIT_DONE;
            WLOG(WS_LOG_DEBUG, connectState, "SERVER_KEXINIT_DONE");
            FALL_THROUGH;

        case CONNECT_SERVER_KEXINIT_DONE:
            if (ssh->handshake == NULL) {
                return WS_FATAL_ERROR;
            }

            if (ssh->handshake->kexId == ID_DH_GEX_SHA256) {
#if !defined(WOLFSSH_NO_DH) && !defined(WOLFSSH_NO_DH_GEX_SHA256)
                ssh->error = SendKexDhGexRequest(ssh);
#endif
            }
            else
                ssh->error = SendKexDhInit(ssh);
            if (ssh->error < WS_SUCCESS) {
                WLOG(WS_LOG_DEBUG, connectError,
                     "SERVER_KEXINIT_DONE", ssh->error);
                return WS_FATAL_ERROR;
            }
            ssh->connectState = CONNECT_CLIENT_KEXDH_INIT_SENT;
            WLOG(WS_LOG_DEBUG, connectState, "CLIENT_KEXDH_INIT_SENT");
            FALL_THROUGH;

        case CONNECT_CLIENT_KEXDH_INIT_SENT:
            while (ssh->isKeying) {
                if (DoReceive(ssh) < WS_SUCCESS) {
                    WLOG(WS_LOG_DEBUG, connectError,
                         "CLIENT_KEXDH_INIT_SENT", ssh->error);
                    return WS_FATAL_ERROR;
                }
            }
            ssh->connectState = CONNECT_KEYED;
            WLOG(WS_LOG_DEBUG, connectState, "KEYED");
            FALL_THROUGH;

        case CONNECT_KEYED:
            if ( (ssh->error = SendServiceRequest(ssh, ID_SERVICE_USERAUTH)) <
                                                                  WS_SUCCESS) {
                WLOG(WS_LOG_DEBUG, connectError, "KEYED", ssh->error);
                return WS_FATAL_ERROR;
            }
            ssh->connectState = CONNECT_CLIENT_USERAUTH_REQUEST_SENT;
            WLOG(WS_LOG_DEBUG, connectState, "CLIENT_USERAUTH_REQUEST_SENT");
            FALL_THROUGH;

        case CONNECT_CLIENT_USERAUTH_REQUEST_SENT:
            while (ssh->serverState < SERVER_USERAUTH_REQUEST_DONE) {
                if (DoReceive(ssh) < WS_SUCCESS) {
                    WLOG(WS_LOG_DEBUG, connectError,
                         "CLIENT_USERAUTH_REQUEST_SENT", ssh->error);
                    return WS_FATAL_ERROR;
                }
            }
            ssh->connectState = CONNECT_SERVER_USERAUTH_REQUEST_DONE;
            WLOG(WS_LOG_DEBUG, connectState, "SERVER_USERAUTH_REQUEST_DONE");
            FALL_THROUGH;

        case CONNECT_SERVER_USERAUTH_REQUEST_DONE:
            #ifdef WOLFSSH_AGENT
                if (ssh->agentEnabled) {
                    ssh->agent = wolfSSH_AGENT_new(ssh->ctx->heap);
                    if (ssh->agent == NULL) {
                        ssh->agentEnabled = 0;
                        WLOG(WS_LOG_INFO, "Unable to create agent. Disabling.");
                    }
                }
            #endif

            if ( (ssh->error = SendUserAuthRequest(ssh, ID_NONE, 0)) <
                                                                  WS_SUCCESS) {
                WLOG(WS_LOG_DEBUG, connectError,
                     "SERVER_USERAUTH_REQUEST_DONE", ssh->error);
                return WS_FATAL_ERROR;
            }
            ssh->connectState = CONNECT_CLIENT_USERAUTH_SENT;
            WLOG(WS_LOG_DEBUG, connectState, "CLIENT_USERAUTH_SENT");
            FALL_THROUGH;

        case CONNECT_CLIENT_USERAUTH_SENT:
            while (ssh->serverState < SERVER_USERAUTH_ACCEPT_DONE) {
                if (DoReceive(ssh) < WS_SUCCESS) {
                    WLOG(WS_LOG_DEBUG, connectError,
                         "CLIENT_USERAUTH_SENT", ssh->error);
                    return WS_FATAL_ERROR;
                }
            }
            ssh->connectState = CONNECT_SERVER_USERAUTH_ACCEPT_DONE;
            WLOG(WS_LOG_DEBUG, connectState, "SERVER_USERAUTH_ACCEPT_DONE");
            FALL_THROUGH;

        case CONNECT_SERVER_USERAUTH_ACCEPT_DONE:
            {
                WOLFSSH_CHANNEL* newChannel;

                newChannel = ChannelNew(ssh, ID_CHANTYPE_SESSION,
                        ssh->ctx->windowSz, ssh->ctx->maxPacketSz);
                if (newChannel == NULL) {
                    ssh->error = WS_MEMORY_E;
                    WLOG(WS_LOG_DEBUG, connectError,
                        "SERVER_USERAUTH_ACCEPT_DONE", ssh->error);
                    return WS_FATAL_ERROR;
                }
                if ( (ssh->error =
                        SendChannelOpenSession(ssh, newChannel)) < WS_SUCCESS) {
                    if (ssh->error == WS_WANT_WRITE ||
                            ssh->error == WS_WANT_READ) {
                        ChannelAppend(ssh, newChannel);
                    }
                    else {
                        ChannelDelete(newChannel, ssh->ctx->heap);
                    }
                    WLOG(WS_LOG_DEBUG, connectError,
                        "SERVER_USERAUTH_ACCEPT_DONE", ssh->error);
                    return WS_FATAL_ERROR;
                }
                ChannelAppend(ssh, newChannel);
            }
            ssh->connectState = CONNECT_CLIENT_CHANNEL_OPEN_SESSION_SENT;
            WLOG(WS_LOG_DEBUG, connectState,
                 "CLIENT_CHANNEL_OPEN_SESSION_SENT");
            FALL_THROUGH;

        case CONNECT_CLIENT_CHANNEL_OPEN_SESSION_SENT:
            while (ssh->serverState < SERVER_CHANNEL_OPEN_DONE) {
                if (DoReceiveHandshake(ssh) < WS_SUCCESS) {
                    WLOG(WS_LOG_DEBUG, connectError,
                         "CLIENT_CHANNEL_OPEN_SESSION_SENT", ssh->error);
                    return WS_FATAL_ERROR;
                }
            }
            ssh->connectState = CONNECT_SERVER_CHANNEL_OPEN_SESSION_DONE;
            WLOG(WS_LOG_DEBUG, connectState,
                 "SERVER_CHANNEL_OPEN_SESSION_DONE");
            FALL_THROUGH;

        case CONNECT_SERVER_CHANNEL_OPEN_SESSION_DONE:
        #ifdef WOLFSSH_AGENT
            if (ssh->agentEnabled) {
                if ( (ssh->error = SendChannelAgentRequest(ssh))
                        < WS_SUCCESS) {
                    WLOG(WS_LOG_DEBUG, connectError,
                     "SERVER_CHANNEL_OPEN_SESSION_DONE", ssh->error);
                    return WS_FATAL_ERROR;
                }
            }
        #endif
            WLOG(WS_LOG_DEBUG, connectState,
                    "CLIENT_CHANNEL_AGENT_REQUEST_SENT");
            ssh->connectState = CONNECT_CLIENT_CHANNEL_AGENT_REQUEST_SENT;
            FALL_THROUGH;

        case CONNECT_CLIENT_CHANNEL_AGENT_REQUEST_SENT:
        #if defined(WOLFSSH_TERM) && !defined(NO_FILESYSTEM)
            if (ssh->sendTerminalRequest) {
                if ( (ssh->error = SendChannelTerminalRequest(ssh))
                        < WS_SUCCESS) {
                    WLOG(WS_LOG_DEBUG, connectError,
                            "CLIENT_CHANNEL_AGENT_REQUEST_SENT", ssh->error);
                    return WS_FATAL_ERROR;
                }
            }
        #endif
            WLOG(WS_LOG_DEBUG, connectState,
                    "CLIENT_CHANNEL_TERMINAL_REQUEST_SENT");
            ssh->connectState = CONNECT_CLIENT_CHANNEL_TERMINAL_REQUEST_SENT;
            FALL_THROUGH;

        case CONNECT_CLIENT_CHANNEL_TERMINAL_REQUEST_SENT:
            if ( (ssh->error = SendChannelRequest(ssh, ssh->channelName,
                            ssh->channelNameSz)) < WS_SUCCESS) {
                WLOG(WS_LOG_DEBUG, connectError,
                     "SERVER_CHANNEL_OPEN_SESSION_DONE", ssh->error);
                return WS_FATAL_ERROR;
            }
            ssh->connectState = CONNECT_CLIENT_CHANNEL_REQUEST_SENT;
            WLOG(WS_LOG_DEBUG, connectState,
                 "CLIENT_CHANNEL_REQUEST_SENT");
            FALL_THROUGH;

        case CONNECT_CLIENT_CHANNEL_REQUEST_SENT:
            while (ssh->serverState < SERVER_DONE) {
                if (DoReceiveHandshake(ssh) < WS_SUCCESS) {
                    WLOG(WS_LOG_DEBUG, connectError,
                         "CLIENT_CHANNEL_REQUEST_SENT", ssh->error);
                    return WS_FATAL_ERROR;
                }
            }
            ssh->connectState = CONNECT_SERVER_CHANNEL_REQUEST_DONE;
            WLOG(WS_LOG_DEBUG, connectState,
                 "SERVER_CHANNEL_REQUEST_DONE");
    }

    WLOG(WS_LOG_DEBUG, "Leaving wolfSSH_connect()");
    return WS_SUCCESS;
}

#endif /* NO_WOLFSSH_CLIENT */


/* A disconnect, sent or received, ends the session, so nothing further may
 * go out. RFC 4253 section 11.1. Reads are deliberately not gated on this:
 * channel data that arrived before the disconnect is still the caller's.
 * Call only after ssh has been checked for NULL. */
static int SendAfterDisconnect(WOLFSSH* ssh)
{
    if (ssh->disconnected) {
        WLOG(WS_LOG_DEBUG, "Send attempted after a disconnect");
        ssh->error = WS_DISCONNECT;
        return 1;
    }
    return 0;
}


/* Whatever a short send left in the output buffer still has to reach the
 * peer, and flushing bytes that are already bundled is not the new traffic
 * RFC 4253 section 11.1 forbids. Once the peer has disconnected, though,
 * only our own queued disconnect still qualifies: anything else in there
 * belongs to a session that is over. Call only after a NULL check of ssh. */
static int FlushQueuedOutput(WOLFSSH* ssh)
{
    if (!wolfSSH_OutputPending(ssh))
        return 0;

    if (ssh->disconnected && !ssh->disconnectTxd)
        return 0;

    WLOG(WS_LOG_DEBUG, "Flushing output left queued by a short send");
    return 1;
}


int wolfSSH_shutdown(WOLFSSH* ssh)
{
    int ret = WS_SUCCESS;
    int flushRet = WS_SUCCESS;
    int flushed = 0;
    WOLFSSH_CHANNEL* channel = NULL;

    WLOG(WS_LOG_DEBUG, "Entering wolfSSH_shutdown()");

    if (ssh == NULL)
        ret = WS_BAD_ARGUMENT;

    /* This is a teardown call, so anything a short send left queued goes out
     * here, with or without a channel to tear down. A rejected auth's
     * USERAUTH_FAILURE has no channel, and a channel close is retired off
     * the channel the moment it is bundled. */
    if (ret == WS_SUCCESS && FlushQueuedOutput(ssh)) {
        flushRet = wolfSSH_SendPacket(ssh);
        flushed = flushRet == WS_SUCCESS;
    }

    if (ret == WS_SUCCESS && ssh->channelList == NULL)
        ret = WS_BAD_ARGUMENT;

    /* The session channel is the head of the list. */
    if (ret == WS_SUCCESS) {
        channel = ssh->channelList;
    }

    /* Session already over. Drop the channel to skip the teardown sends
     * and the wait for a close that will not come. RFC 4253 section 11.1. */
    if (channel != NULL && ssh->disconnected) {
        WLOG(WS_LOG_DEBUG, "Session already disconnected, nothing to send");
        channel = NULL;
    }

    /* Report the dead session with or without a channel to drop: callers
     * gate their retry on ssh->error, and the flush above may have just
     * emptied the output buffer they would be retrying for. An unfinished
     * flush owns the error instead, since that retry is still owed. */
    if (ssh != NULL && ssh->disconnected && flushRet == WS_SUCCESS)
        ssh->error = WS_DISCONNECT;

    /* A live session has no WS_DISCONNECT to displace that stale error with,
     * and the widened flush reaches sessions that are still up. The write the
     * short send latched WS_WANT_WRITE for is the one that just finished, so
     * it is not owed twice. */
    else if (flushed && ssh->error == WS_WANT_WRITE)
        ssh->error = WS_SUCCESS;

    /* if channel close was not already sent then send it */
    if (channel != NULL && !channel->closeTxd) {
       if (ret == WS_SUCCESS) {
           ret = SendChannelEof(ssh, channel->peerChannel);
       }

       /* continue on success and in case where queueing up send packets */
       if (ret == WS_SUCCESS ||
               (ret != WS_BAD_ARGUMENT && ssh->error == WS_WANT_WRITE)) {
           ret = SendChannelExit(ssh, channel->peerChannel,
           #if defined(WOLFSSH_TERM) || defined(WOLFSSH_SHELL)
               ssh->exitStatus);
           #else
               0);
           #endif
       }

       /* continue on success and in case where queueing up send packets */
       if (ret == WS_SUCCESS ||
               (ret != WS_BAD_ARGUMENT && ssh->error == WS_WANT_WRITE))
           ret = SendChannelClose(ssh, channel->peerChannel);
    }


    /* if the channel was not yet removed then read to get
     * response to SendChannelClose. Not while the flush left output queued:
     * the peer cannot answer a close it has not finished receiving, and the
     * worker has nothing to read, so a want-read from it would send the
     * caller to wait on the wrong side of the socket. */
    if (channel != NULL && ret == WS_SUCCESS && !wolfSSH_OutputPending(ssh)) {
        ret = wolfSSH_worker(ssh, NULL);
        if (ret == WS_CHAN_RXD || ret == WS_EOF) {
            /* received response */
            ret = WS_SUCCESS;
        }
    }

    if (ssh != NULL && ssh->channelList == NULL) {
        WLOG(WS_LOG_DEBUG, "channel list was already removed");
        ret = WS_CHANNEL_CLOSED;
    }

    /* An unfinished flush outranks the channel status: the caller has to
     * come back for the rest of the disconnect. Not so once a teardown send
     * has carried the leftovers out with it: that write is settled, and the
     * teardown result stands. Nor does it outrank a teardown send that
     * failed: a reset leaves the buffer intact, so the flush still reads as
     * owed while the send holds the real reason. A flush that failed
     * outright reports whatever else happened. */
    if (flushRet != WS_SUCCESS &&
            (flushRet != WS_WANT_WRITE ||
                (wolfSSH_OutputPending(ssh) &&
                    (ret == WS_SUCCESS || ret == WS_CHANNEL_CLOSED))))
        ret = flushRet;

    WLOG(WS_LOG_DEBUG, "Leaving wolfSSH_shutdown(), ret = %d", ret);
    return ret;
}


int wolfSSH_TriggerKeyExchange(WOLFSSH* ssh)
{
    int ret = WS_SUCCESS;

    WLOG(WS_LOG_DEBUG, "Entering wolfSSH_TriggerKeyExchange()");
    if (ssh == NULL)
        ret = WS_BAD_ARGUMENT;

    if (ret == WS_SUCCESS && SendAfterDisconnect(ssh))
        ret = WS_FATAL_ERROR;

    if (ret == WS_SUCCESS)
        ret = ssh->error = SendKexInit(ssh);

    WLOG(WS_LOG_DEBUG, "Leaving wolfSSH_TriggerKeyExchange(), ret = %d", ret);
    return ret;
}


/* gets current input buffer if any without advancing the internal index.
 * returns number of bytes was able to peek at on success */
int wolfSSH_stream_peek(WOLFSSH* ssh, byte* buf, word32 bufSz)
{
    WOLFSSH_BUFFER* inputBuffer;
    word32 avail;

    WLOG(WS_LOG_DEBUG, "Entering wolfSSH_stream_peek()");

    if (ssh == NULL)
        return WS_BAD_ARGUMENT;

    if (ssh->channelList == NULL) {
        /* No channel left to drain, so the disconnect is all there is. */
        if (ssh->disconnected) {
            ssh->error = WS_DISCONNECT;
            return WS_FATAL_ERROR;
        }
        return WS_BAD_ARGUMENT;
    }

    /* A rekey the peer abandoned with a disconnect never completes, since
     * only NEWKEYS clears the flag. Report the dead session instead, or the
     * caller turns the crank forever. */
    if (ssh->isKeying && !ssh->disconnected) {
        ssh->error = WS_REKEYING;
        return WS_REKEYING;
    }

    inputBuffer = &ssh->channelList->inputBuffer;
    avail = inputBuffer->length - inputBuffer->idx;

    /* Report the EOF only once the buffered data is drained. */
    if (avail == 0 && ssh->channelList->eofRxd) {
        ssh->error = WS_EOF;
        return WS_ERROR;
    }

    /* Report the disconnect only once the buffered data is drained, the
     * same way wolfSSH_stream_read() does. Callers use this to tell a
     * drained channel from one with more to come, and a dead session is
     * neither. The EOF above outranks it: it names the channel. */
    if (avail == 0 && ssh->disconnected) {
        ssh->error = WS_DISCONNECT;
        return WS_FATAL_ERROR;
    }

    bufSz = min(bufSz, avail);
    if (buf != NULL) {
        WMEMCPY(buf, inputBuffer->buffer + inputBuffer->idx, bufSz);
    }
    return (int)bufSz;
}


static int _UpdateChannelWindow(WOLFSSH_CHANNEL* channel);
static int _ChannelReadExt(WOLFSSH_CHANNEL* channel, byte* buf, word32 bufSz);


/* Wrapper function for ease of use to get data after it has been decrypted from
 * the SSH connection. This function handles low level operations in addition to
 * the read, such as window adjustment and high water checking.
 *
 * In non blocking mode check wolfSSH_get_error(ssh) after the read: it holds
 * WS_WANT_READ / WS_WANT_WRITE for a fail case, and for a success the status
 * of a window adjust that could not be sent.
 *
 * Returns the number of bytes read on success, negative values on fail
 */
int wolfSSH_stream_read(WOLFSSH* ssh, byte* buf, word32 bufSz)
{
    int ret = WS_SUCCESS;
    WOLFSSH_BUFFER* inputBuffer;
    word32 headId;

    WLOG(WS_LOG_DEBUG, "Entering wolfSSH_stream_read()");

    if (ssh == NULL || buf == NULL || bufSz == 0)
        return WS_BAD_ARGUMENT;

    if (ssh->channelList == NULL) {
        /* No channel left to drain, so the disconnect is all there is. */
        if (ssh->disconnected) {
            ssh->error = WS_DISCONNECT;
            return WS_FATAL_ERROR;
        }
        return WS_BAD_ARGUMENT;
    }

    inputBuffer = &ssh->channelList->inputBuffer;
    /* inputBuffer belongs to this channel; DoReceive() can retire it. */
    headId = ssh->channelList->channel;

    /* Report the EOF only once the buffered data is drained. */
    if (inputBuffer->length - inputBuffer->idx == 0
            && ssh->channelList->eofRxd) {
        ssh->error = WS_EOF;
        return WS_ERROR;
    }

    /* See wolfSSH_stream_peek(): a disconnect ends a rekey that can no
     * longer finish, so it outranks it here too. */
    if (ssh->isKeying && !ssh->disconnected) {
        ssh->error = WS_REKEYING;
        return WS_FATAL_ERROR;
    }

    ssh->error = WS_SUCCESS;

    /* Hand back whatever arrived before the disconnect, then report it once
     * the buffer runs dry rather than going back to a dead transport. */
    if (ssh->disconnected && inputBuffer->length - inputBuffer->idx == 0) {
        ssh->error = WS_DISCONNECT;
        return WS_FATAL_ERROR;
    }

    if (ret == WS_SUCCESS) {
        WLOG(WS_LOG_DEBUG, "    Stream read index of %u", inputBuffer->idx);
        WLOG(WS_LOG_DEBUG, "    Stream read ava data %u", inputBuffer->length);
        while (inputBuffer->length - inputBuffer->idx == 0) {
            WLOG(WS_LOG_DEBUG,
                    "Starting to receive data at current index of %u",
                    inputBuffer->idx);
            ret = DoReceive(ssh);
            /* Off the current head: DoReceive() may have retired the old. */
            if (ssh->channelList == NULL
                    || (ssh->channelList->eofRxd
                        && ssh->channelList->inputBuffer.length
                           - ssh->channelList->inputBuffer.idx == 0))
                ret = WS_EOF;
            if (ret == WS_EOF && ssh->channelList != NULL
                    && ssh->channelList->channel == headId
                    && ssh->lastRxId != headId) {
                /* Another channel's EOF is not this read's; the head is
                 * still open. Loop only while the head is unchanged, since
                 * inputBuffer points into it. */
                continue;
            }
            if (ret == WS_EXTDATA &&
                    ssh->lastRxId != ssh->channelList->channel) {
                /* Extended data for another channel. wolfSSH_extended_data_read()
                 * only drains the head of the list, so reporting it here would
                 * strand the data with its window charged. Filter it like
                 * WS_CHAN_RXD below; multi-channel apps read with
                 * wolfSSH_ChannelIdReadExt(). */
                ret = WS_ERROR;
                break;
            }
            if (ret < 0 && ret != WS_CHAN_RXD) {
                break;
            }
            if (ssh->error == WS_CHAN_RXD) {
                if (ssh->lastRxId != ssh->channelList->channel) {
                    ret = WS_ERROR;
                    break;
                }
                else {
                    ret = WS_SUCCESS;
                }
            }
        }
    }

    /* update internal input buffer based on data read. DoReceive() above may
     * have started a rekey, which holds the copy back -- unless a disconnect
     * came with it, since then the rekey never finishes and the buffered data
     * would never be handed back. */
    if (ret == WS_SUCCESS && (!ssh->isKeying || ssh->disconnected)) {
        int n;

        n = min(bufSz, inputBuffer->length - inputBuffer->idx);
        if (n <= 0)
            ret = WS_BUFFER_E;
        else {
            WMEMCPY(buf, inputBuffer->buffer + inputBuffer->idx, n);
            inputBuffer->idx += n;
            ret = _UpdateChannelWindow(ssh->channelList);
            if (ret != WS_SUCCESS) {
                ssh->error = ret;
                if (ret != WS_WANT_WRITE) {
                    WLOG(WS_LOG_ERROR,
                         "wolfSSH_stream_read: window adjust send failed "
                         "(%d); read still succeeded", ret);
                }
            }
            ret = n;
        }
    }

    WLOG(WS_LOG_DEBUG, "Leaving wolfSSH_stream_read(), rxd = %d", ret);
    return ret;
}


int wolfSSH_stream_send(WOLFSSH* ssh, byte* buf, word32 bufSz)
{
    int bytesTxd = 0;

    WLOG(WS_LOG_DEBUG, "Entering wolfSSH_stream_send()");

    if (ssh == NULL || buf == NULL)
        return WS_BAD_ARGUMENT;

    if (SendAfterDisconnect(ssh))
        return WS_FATAL_ERROR;

    if (ssh->channelList == NULL)
        return WS_BAD_ARGUMENT;

    if (ssh->isKeying) {
        ssh->error = WS_REKEYING;
        return WS_FATAL_ERROR;
    }

    bytesTxd = SendChannelData(ssh, ssh->channelList->channel, buf, bufSz);

    WLOG(WS_LOG_DEBUG, "Leaving wolfSSH_stream_send(), txd = %d", bytesTxd);
    return bytesTxd;
}


int wolfSSH_ChannelIdSend(WOLFSSH* ssh, word32 channelId,
        byte* buf, word32 bufSz)
{
    WOLFSSH_CHANNEL* channel;
    int ret = WS_SUCCESS;

    WLOG(WS_LOG_DEBUG, "Entering wolfSSH_ChannelIdSend(), ID = %u",
            channelId);

    if (ssh == NULL || buf == NULL)
        ret = WS_BAD_ARGUMENT;

    if (ret == WS_SUCCESS && SendAfterDisconnect(ssh))
        ret = WS_FATAL_ERROR;

    if (ret == WS_SUCCESS) {
        channel = ChannelFind(ssh, channelId, WS_CHANNEL_ID_SELF);
        if (channel == NULL) {
            WLOG(WS_LOG_DEBUG, "Invalid channel");
            ret = WS_INVALID_CHANID;
        }
        else {
            if (!channel->openConfirmed) {
                WLOG(WS_LOG_DEBUG, "Channel not confirmed yet.");
                ret = WS_CHANNEL_NOT_CONF;
            }
        }
    }

    if (ret == WS_SUCCESS) {
        WLOG(WS_LOG_DEBUG, "Sending data.");
        ret = SendChannelData(ssh, channelId, buf, bufSz);
    }

    WLOG(WS_LOG_DEBUG, "Leaving wolfSSH_ChannelIdSend(), txd = %d", ret);
    return ret;
}


int wolfSSH_ChannelIdSendExt(WOLFSSH* ssh, word32 channelId,
        byte* buf, word32 bufSz)
{
    WOLFSSH_CHANNEL* channel;
    int ret = WS_SUCCESS;

    WLOG(WS_LOG_DEBUG, "Entering wolfSSH_ChannelIdSendExt(), ID = %u",
            channelId);

    if (ssh == NULL || buf == NULL)
        ret = WS_BAD_ARGUMENT;

    if (ret == WS_SUCCESS && SendAfterDisconnect(ssh))
        ret = WS_FATAL_ERROR;

    if (ret == WS_SUCCESS) {
        channel = ChannelFind(ssh, channelId, WS_CHANNEL_ID_SELF);
        if (channel == NULL) {
            WLOG(WS_LOG_DEBUG, "Invalid channel");
            ret = WS_INVALID_CHANID;
        }
        else {
            if (!channel->openConfirmed) {
                WLOG(WS_LOG_DEBUG, "Channel not confirmed yet.");
                ret = WS_CHANNEL_NOT_CONF;
            }
        }
    }

    if (ret == WS_SUCCESS) {
        WLOG(WS_LOG_DEBUG, "Sending extended data.");
        ret = SendChannelExtendedData(ssh, channelId, buf, bufSz);
    }

    WLOG(WS_LOG_DEBUG, "Leaving wolfSSH_ChannelIdSendExt(), txd = %d", ret);
    return ret;
}


int wolfSSH_stream_send_eof(WOLFSSH* ssh)
{
    int ret = WS_SUCCESS;

    WLOG(WS_LOG_DEBUG, "Entering wolfSSH_stream_send_eof()");

    if (ssh == NULL)
        ret = WS_BAD_ARGUMENT;

    /* Ahead of the channel-list test, like the other stream calls, so a
     * torn-down session reports the disconnect and not a bad argument. */
    if (ret == WS_SUCCESS && SendAfterDisconnect(ssh))
        ret = WS_FATAL_ERROR;

    if (ret == WS_SUCCESS && ssh->channelList == NULL)
        ret = WS_BAD_ARGUMENT;

    /* Only KEX traffic may go out mid-rekey, RFC 4253 section 7.1. */
    if (ret == WS_SUCCESS && ssh->isKeying) {
        ssh->error = WS_REKEYING;
        ret = WS_REKEYING;
    }

    /* Same peer-id lookup as wolfSSH_ChannelSendEof(), so the same guard. */
    if (ret == WS_SUCCESS && !ssh->channelList->openConfirmed) {
        WLOG(WS_LOG_DEBUG, "Channel not confirmed yet.");
        ret = WS_CHANNEL_NOT_CONF;
    }

    if (ret == WS_SUCCESS)
        ret = SendChannelEof(ssh, ssh->channelList->peerChannel);

    WLOG(WS_LOG_DEBUG, "Leaving wolfSSH_stream_send_eof(), ret = %d", ret);
    return ret;
}


int wolfSSH_stream_exit(WOLFSSH* ssh, int status)
{
    int ret = WS_SUCCESS;

    WLOG(WS_LOG_DEBUG, "Entering wolfSSH_stream_exit(), status = %d", status);

    if (ssh == NULL)
        ret = WS_BAD_ARGUMENT;

    /* Ahead of the channel-list test, like the other stream calls, so a
     * torn-down session reports the disconnect and not a bad argument. */
    if (ret == WS_SUCCESS && SendAfterDisconnect(ssh))
        ret = WS_FATAL_ERROR;

    if (ret == WS_SUCCESS && ssh->channelList == NULL)
        ret = WS_BAD_ARGUMENT;

    if (ret == WS_SUCCESS)
        ret = SendChannelExit(ssh, ssh->channelList->peerChannel, status);

    if (ret == WS_SUCCESS)
        ret = SendChannelEow(ssh, ssh->channelList->peerChannel);

    if (ret == WS_SUCCESS)
        ret = SendChannelEof(ssh, ssh->channelList->peerChannel);

    if (ret == WS_SUCCESS)
        ret = SendChannelClose(ssh, ssh->channelList->peerChannel);

    WLOG(WS_LOG_DEBUG, "Leaving wolfSSH_stream_exit()");
    return ret;
}

int wolfSSH_global_request(WOLFSSH *ssh, const unsigned char* data, word32 dataSz, int reply)
{
    int ret;
#ifdef WOLFSSH_FWD
    WOLFSSH_FWD_PENDING pend;
#endif

    WLOG(WS_LOG_DEBUG, "Entering wolfSSH_global_request");
    if (ssh == NULL || data == NULL)
        return WS_BAD_ARGUMENT;
    if (reply != 0 && reply != 1)
        return WS_BAD_ARGUMENT;
    if (SendAfterDisconnect(ssh))
        return WS_FATAL_ERROR;

#ifdef WOLFSSH_FWD
    /* A want-reply request consumes one of the peer's replies, so it takes a
     * place in the same queue the forwarding requests use; otherwise its reply
     * reads as the answer to an outstanding tcpip-forward. */
    if (reply) {
        int sent = 0;

        ret = FwdReplyPrepare(ssh, &pend);
        if (ret != WS_SUCCESS)
            return ret;

        /* A request the peer received is owed a reply whatever this call
         * returns, so the slot goes by what reached the wire, not by the
         * error. */
        ret = SendGlobalRequest(ssh, data, dataSz, reply, &sent);
        if (sent)
            FwdPendingCommit(ssh, &pend);
        else
            FwdPendingDiscard(ssh, &pend);

        return ret;
    }
#endif /* WOLFSSH_FWD */

    ret = SendGlobalRequest(ssh, data, dataSz, reply, NULL);

    return ret;
}


int wolfSSH_extended_data_send(WOLFSSH* ssh, byte* buf, word32 bufSz)
{
    int bytesTxd = 0;

    WLOG(WS_LOG_DEBUG, "Entering wolfSSH_extended_data_send()");

    if (ssh == NULL || buf == NULL)
        return WS_BAD_ARGUMENT;

    if (SendAfterDisconnect(ssh))
        return WS_FATAL_ERROR;

    if (ssh->channelList == NULL)
        return WS_BAD_ARGUMENT;

    if (ssh->isKeying) {
        ssh->error = WS_REKEYING;
        return WS_REKEYING;
    }

    bytesTxd = SendChannelExtendedData(ssh, ssh->channelList->channel, buf, bufSz);

    WLOG(WS_LOG_DEBUG, "Leaving wolfSSH_extended_data_send(), txd = %d", bytesTxd);
    return bytesTxd;
}


/* Reads STDERR from the channel at the head of the channel list, like
 * wolfSSH_stream_read(). See wolfssh/ssh.h for the contract. */
int wolfSSH_extended_data_read(WOLFSSH* ssh, byte* out, word32 outSz)
{
    int bytesRxd;

    WLOG(WS_LOG_DEBUG, "Entering wolfSSH_extended_data_read()");

    if (ssh == NULL || out == NULL || ssh->channelList == NULL)
        return WS_BAD_ARGUMENT;

    bytesRxd = _ChannelReadExt(ssh->channelList, out, outSz);

    WLOG(WS_LOG_DEBUG, "Leaving wolfSSH_extended_data_read(), rxd = %d",
            bytesRxd);
    return bytesRxd;
}


int wolfSSH_SendIgnore(WOLFSSH* ssh, const byte* buf, word32 bufSz)
{
    byte scratch[128];

    WOLFSSH_UNUSED(buf);
    WOLFSSH_UNUSED(bufSz);

    if (ssh == NULL)
        return WS_BAD_ARGUMENT;

    if (SendAfterDisconnect(ssh))
        return WS_FATAL_ERROR;

    WMEMSET(scratch, 0, sizeof(scratch));

    return SendIgnore(ssh, scratch, sizeof(scratch));
}


int wolfSSH_SendDisconnect(WOLFSSH *ssh, word32 reason)
{
    WLOG(WS_LOG_DEBUG, "Entering wolfSSH_SendDisconnect");

    if (ssh == NULL)
        return WS_BAD_ARGUMENT;

    /* One disconnect ends the session; a second is more traffic on a
     * connection that is already over. A short send leaves the first one
     * queued, though, so that retry goes through. */
    if (SendAfterDisconnect(ssh)) {
        if (FlushQueuedOutput(ssh))
            return wolfSSH_SendPacket(ssh);
        return WS_FATAL_ERROR;
    }

    return SendDisconnect(ssh, reason);
}

void wolfSSH_SetUserAuth(WOLFSSH_CTX* ctx, WS_CallbackUserAuth cb)
{
    if (ctx != NULL) {
        ctx->userAuthCb = cb;
    }
}


void wolfSSH_SetUserAuthTypes(WOLFSSH_CTX* ctx, WS_CallbackUserAuthTypes cb)
{
    if (ctx != NULL) {
        ctx->userAuthTypesCb = cb;
    }
}


void wolfSSH_SetUserAuthCtx(WOLFSSH* ssh, void* userAuthCtx)
{
    if (ssh != NULL) {
        ssh->userAuthCtx = userAuthCtx;
    }
}


void* wolfSSH_GetUserAuthCtx(WOLFSSH* ssh)
{
    if (ssh != NULL) {
        return ssh->userAuthCtx;
    }
    return NULL;
}


void wolfSSH_SetUserAuthResult(WOLFSSH_CTX* ctx,
        WS_CallbackUserAuthResult cb)
{
    if (ctx != NULL) {
        ctx->userAuthResultCb = cb;
    }
}


void wolfSSH_SetUserAuthResultCtx(WOLFSSH* ssh, void* userAuthResultCtx)
{
    if (ssh != NULL) {
        ssh->userAuthResultCtx = userAuthResultCtx;
    }
}


void* wolfSSH_GetUserAuthResultCtx(WOLFSSH* ssh)
{
    if (ssh != NULL) {
        return ssh->userAuthResultCtx;
    }
    return NULL;
}


void wolfSSH_CTX_SetPublicKeyCheck(WOLFSSH_CTX* ctx,
        WS_CallbackPublicKeyCheck cb)
{
    if (ctx != NULL) {
        ctx->publicKeyCheckCb = cb;
    }
}


void wolfSSH_SetPublicKeyCheckCtx(WOLFSSH* ssh, void* publicKeyCheckCtx)
{
    if (ssh != NULL) {
        ssh->publicKeyCheckCtx = publicKeyCheckCtx;
    }
}


void* wolfSSH_GetPublicKeyCheckCtx(WOLFSSH* ssh)
{
    if (ssh != NULL) {
        return ssh->publicKeyCheckCtx;
    }
    return NULL;
}


#if defined(WOLFSSH_TERM) && !defined(NO_FILESYSTEM)
/* Used to resize terminal window with shell connections
 * returns WS_SUCCESS on success */
int wolfSSH_ChangeTerminalSize(WOLFSSH* ssh, word32 columns, word32 rows,
    word32 widthPixels, word32 heightPixels)
{
    int ret = WS_SUCCESS;

    WLOG(WS_LOG_DEBUG, "Entering wolfSSH_ChangeWindowDimension()");

    if (ssh == NULL)
        ret = WS_BAD_ARGUMENT;

    if (ret == WS_SUCCESS && SendAfterDisconnect(ssh))
        ret = WS_FATAL_ERROR;

    if (ret == WS_SUCCESS) {
        ret = SendChannelTerminalResize(ssh, columns, rows, widthPixels,
        heightPixels);
    }

    WLOG(WS_LOG_DEBUG, "Leaving wolfSSH_ChangeWindowDimension(), ret = %d",
        ret);
    return ret;
}


void wolfSSH_SetTerminalResizeCb(WOLFSSH* ssh, WS_CallbackTerminalSize cb)
{
    ssh->termResizeCb = cb;
}


void wolfSSH_SetTerminalResizeCtx(WOLFSSH* ssh, void* usrCtx)
{
    ssh->termCtx = usrCtx;
}
#endif


#if defined(WOLFSSH_TERM) || defined(WOLFSSH_SHELL)
/* returns the exit status captured from the connection if any */
int wolfSSH_GetExitStatus(WOLFSSH* ssh)
{
    if (ssh == NULL) {
        WLOG(WS_LOG_DEBUG, "wolfSSH_GetExitStatus WOLFSSH struct was NULL");
        return WS_BAD_ARGUMENT;
    }
    return ssh->exitStatus;
}


/* Sets the exit status to send on shutdown
 * returns WS_SUCCESS on success */
int wolfSSH_SetExitStatus(WOLFSSH* ssh, word32 exitStatus)
{
    if (ssh == NULL) {
        WLOG(WS_LOG_DEBUG, "wolfSSH_SetExitStatus WOLFSSH struct was NULL");
        return WS_BAD_ARGUMENT;
    }
    WLOG(WS_LOG_DEBUG, "wolfSSH_SetExitStatus sending exit status %u",
        exitStatus);
    ssh->exitStatus = exitStatus;
    return WS_SUCCESS;
}
#endif


/* Used to set the channel request type sent in wolfSSH connect. The default
 * type set is shell if this function is not called.
 *
 * type     channel type i.e. WOLFSSH_SESSION_SUBSYSTEM
 * name     name or command in the case of subsystem and exec channel types
 * nameSz   size of name buffer
 *
 * Exec and subsystem carry a name string the peer requires, so one must be
 * available. Passing none keeps the name an earlier call stored; with
 * nothing stored the call is refused rather than sending a request the peer
 * reads as malformed. Shell and terminal take no name and drop any stored
 * one. A refused call changes nothing, the selected type included.
 *
 * returns WS_SUCCESS on success
 * returns WS_BAD_ARGUMENT for a NULL ssh or an unknown type, for exec on
 *   the server side, for a name at or above WOLFSSH_MAX_CHN_NAMESZ, for a
 *   nameSz with no name behind it, and for exec or subsystem with no name
 *   given and none stored
 * returns WS_MEMORY_E if the name cannot be allocated
 */
int wolfSSH_SetChannelType(WOLFSSH* ssh, byte type, byte* name, word32 nameSz)
{
    if (ssh == NULL) {
        return WS_BAD_ARGUMENT;
    }

    switch (type) {
        case WOLFSSH_SESSION_SHELL:
            /* shell has no name; drop any name left by a prior subsystem/exec */
            if (ssh->channelName != NULL) {
                WFREE(ssh->channelName, ssh->ctx->heap, DYNTYPE_STRING);
                ssh->channelName = NULL;
            }
            ssh->channelNameSz = 0;
            ssh->connectChannelId = type;
            break;

        case WOLFSSH_SESSION_EXEC:
            if (ssh->ctx->side == WOLFSSH_ENDPOINT_SERVER) {
                WLOG(WS_LOG_DEBUG, "Server side exec unsupported");
                return WS_BAD_ARGUMENT;
            }
            FALL_THROUGH;

        case WOLFSSH_SESSION_SUBSYSTEM: {
            byte* newName;

            if (name == NULL && nameSz > 0) {
                WLOG(WS_LOG_DEBUG, "Channel name size without a name");
                return WS_BAD_ARGUMENT;
            }
            if (name != NULL && nameSz >= WOLFSSH_MAX_CHN_NAMESZ) {
                /* Report it. Dropping the name sends a request with no name
                 * string, which the peer rejects as malformed. */
                WLOG(WS_LOG_DEBUG, "Channel name too large");
                return WS_BAD_ARGUMENT;
            }

            if (name != NULL && nameSz > 0) {
                /* only (re)allocate when the name changed; SFTP/SCP retry
                 * loops re-set the same name on every poll */
                if (ssh->channelName == NULL || ssh->channelNameSz != nameSz ||
                        WMEMCMP(ssh->channelName, name, nameSz) != 0) {
                    newName = (byte*)WMALLOC(nameSz + 1, ssh->ctx->heap,
                            DYNTYPE_STRING);
                    if (newName == NULL) {
                        return WS_MEMORY_E;
                    }
                    WMEMCPY(newName, name, nameSz);
                    newName[nameSz] = 0;
                    if (ssh->channelName != NULL) {
                        WFREE(ssh->channelName, ssh->ctx->heap, DYNTYPE_STRING);
                    }
                    ssh->channelName = newName;
                    ssh->channelNameSz = nameSz;
                }
            }
            else if (ssh->channelName == NULL) {
                /* No name now and none from an earlier call. Same reason as
                 * the oversize case: exec and subsystem both carry a
                 * required name string, and SendChannelRequest() leaves the
                 * field out entirely when it has nothing to put there. */
                WLOG(WS_LOG_DEBUG, "No channel name to send");
                return WS_BAD_ARGUMENT;
            }
            else {
                /* keep the name an earlier call stored; SFTP/SCP retry
                 * loops re-enter with nothing to say */
                WLOG(WS_LOG_DEBUG, "Keeping the stored channel name");
            }
            ssh->connectChannelId = type;
            break;
        }

#ifdef WOLFSSH_TERM
        case WOLFSSH_SESSION_TERMINAL:
            /* send a pseudo-terminal request and shell channel */
            ssh->sendTerminalRequest = 1;
            if (ssh->channelName != NULL) {
                WFREE(ssh->channelName, ssh->ctx->heap, DYNTYPE_STRING);
                ssh->channelName = NULL;
            }
            ssh->channelNameSz = 0;
            ssh->connectChannelId = WOLFSSH_SESSION_SHELL;
            break;
#endif

        default:
            WLOG(WS_LOG_DEBUG, "Unknown channel type");
            return WS_BAD_ARGUMENT;
    }

    return WS_SUCCESS;
}


int wolfSSH_SetUsernameRaw(WOLFSSH* ssh,
        const byte* username, word32 usernameSz)
{
    char* newUsername = NULL;
    int ret = WS_SUCCESS;

    if (ssh == NULL)
        ret = WS_BAD_ARGUMENT;
    if (username == NULL || usernameSz == 0)
        ret = WS_BAD_ARGUMENT;

    if (ret == WS_SUCCESS) {
        newUsername = (char*)WMALLOC(usernameSz + 1,
                ssh->ctx->heap, DYNTYPE_STRING);
        if (newUsername == NULL)
            ret = WS_MEMORY_E;
        else {
            WMEMCPY(newUsername, username, usernameSz);
            newUsername[usernameSz] = 0;
            if (ssh->userName != NULL)
                WFREE(ssh->userName, ssh->ctx->heap, DYNTYPE_STRING);
            ssh->userName = newUsername;
            ssh->userNameSz = usernameSz;
        }
    }

    return ret;
}


int wolfSSH_SetUsername(WOLFSSH* ssh, const char* username)
{
    int ret = WS_SUCCESS;

    if (ssh == NULL || username == NULL)
        ret = WS_BAD_ARGUMENT;

    if (ret == WS_SUCCESS) {
        ret = wolfSSH_SetUsernameRaw(ssh,
                (const byte*)username, (word32)WSTRLEN(username));
    }

    return ret;
}


char* wolfSSH_GetUsername(WOLFSSH* ssh)
{
    char* name = NULL;

    if (ssh != NULL)
        name = ssh->userName;

    return name;
}


#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/coding.h>
#ifndef WOLFSSH_NO_MLDSA
    #include <wolfssl/wolfcrypt/dilithium.h>
#endif
#ifdef WOLFSSH_OSSH_CERTS
    #include <wolfssh/ossh.h>
#endif

union wolfSSH_key {
#ifndef WOLFSSH_NO_RSA
    RsaKey rsa;
#endif
#ifndef WOLFSSH_NO_ECDSA
    ecc_key ecc;
#endif
};

#if !defined(NO_FILESYSTEM) && !defined(WOLFSSH_USER_FILESYSTEM)
    /* currently only used in wolfSSH_ReadKey_file() */
    static const char* PrivBeginOpenSSH = "-----BEGIN OPENSSH PRIVATE KEY-----";
    static const char* PrivBeginPrefix = "-----BEGIN ";
    /* static const char* PrivEndPrefix = "-----END "; */
    static const char* PrivSuffix = " PRIVATE KEY-----";
#endif

static int DoSshPubKey(const byte* in, word32 inSz, byte** out,
        word32* outSz, const byte** outType, word32* outTypeSz,
        void* heap)
{
    byte* newKey = NULL;
    char* c;
    char* last;
    char* type = NULL;
    char* key = NULL;
    int ret = WS_SUCCESS;
    word32 newKeySz, typeSz = 0;

    WOLFSSH_UNUSED(inSz);
    WOLFSSH_UNUSED(heap);

    /*
       SSH format is:
       type AAAABASE64ENCODEDKEYDATA comment

       allocate a copy to tokenize, add a null terminator.
    */
    c = (char*)WMALLOC(inSz + 1, heap, DYNTYPE_STRING);
    if (c != NULL) {
        WMEMCPY(c, in, inSz);
        c[inSz] = 0;
        type = WSTRTOK(c, " \n", &last);
        key = WSTRTOK(NULL, " \n", &last);
    }
    else {
        ret = WS_MEMORY_E;
    }

    if (ret == WS_SUCCESS) {
        if (type == NULL || key == NULL) {
            ret = WS_PARSE_E;
        }
    }

    if (ret == WS_SUCCESS) {
        typeSz = (word32)WSTRLEN(type);
        /* set size based on sanity check in wolfSSL base64 decode
         * function */
        newKeySz = ((word32)WSTRLEN(key) * 3 + 3) / 4;
        if (*out == NULL) {
            newKey = (byte*)WMALLOC(newKeySz, heap, DYNTYPE_PRIVKEY);
            if (newKey == NULL) {
                ret = WS_MEMORY_E;
            }
        }
        else {
            if (*outSz < newKeySz) {
                WLOG(WS_LOG_DEBUG, "PEM private key output size too small");
                ret = WS_BUFFER_E;
            }
            else {
                newKey = *out;
            }
        }
    }

    if (ret == WS_SUCCESS) {
        ret = Base64_Decode((byte*)key, (word32)WSTRLEN(key),
                newKey, &newKeySz);

        if (ret == 0) {
            *out = newKey;
            *outSz = newKeySz;
            *outType = (const byte *)IdToName(NameToId(type, typeSz));
            *outTypeSz = (word32)WSTRLEN((const char*)*outType);
            ret = WS_SUCCESS;
        }
        else {
            WLOG(WS_LOG_DEBUG, "Base64 decode of public key failed.");
            if (*out == NULL) {
                WFREE(newKey, heap, DYNTYPE_PRIVKEY);
            }
            ret = WS_PARSE_E;
        }
    }

    WFREE(c, heap, DYNTYPE_STRING);
    return ret;
}


static int DoAsn1Key(const byte* in, word32 inSz, byte** out,
        word32* outSz, const byte** outType, word32* outTypeSz,
        int isPrivate, void* heap)
{
    int ret = WS_SUCCESS;
    byte* newKey = NULL;
    WS_KeySignature* key = NULL;

    WOLFSSH_UNUSED(heap);

    ret = IdentifyAsn1Key(in, inSz, isPrivate, heap, &key);
    if (ret <= 0) {
        WLOG(WS_LOG_DEBUG, "Unable to identify ASN.1 key");
    }

    if (ret > 0 && !isPrivate) {
        *outType = (const byte*)IdToName(ret);
        *outTypeSz = (word32)WSTRLEN((const char*)*outType);

#ifndef WOLFSSH_NO_MLDSA
        if (
#ifndef WOLFSSH_NO_MLDSA44
            ret == ID_MLDSA44 ||
#endif
#ifndef WOLFSSH_NO_MLDSA65
            ret == ID_MLDSA65 ||
#endif
#ifndef WOLFSSH_NO_MLDSA87
            ret == ID_MLDSA87 ||
#endif
            0) {
            byte* rawPub = NULL;
            word32 rawPubSz = WOLFSSH_MLDSA_MAX_PUB_KEY_SZ;
            const char* name = (const char*)*outType;
            word32 nameLen = *outTypeSz;
            word32 localIdx = 0;

            rawPub = (byte*)WMALLOC(rawPubSz, heap, DYNTYPE_PUBKEY);
            if (rawPub == NULL) {
                ret = WS_MEMORY_E;
            }
            else {
                int wcRet = wc_MlDsaKey_ExportPubRaw(&key->ks.mldsa.key,
                                                      rawPub, &rawPubSz);
                if (wcRet != 0) {
                    ret = WS_CRYPTO_FAILED;
                }
                else {
                    *outSz = LENGTH_SZ + nameLen + LENGTH_SZ + rawPubSz;
                    newKey = (byte*)WMALLOC(*outSz, heap, DYNTYPE_PRIVKEY);
                    if (newKey == NULL) {
                        ret = WS_MEMORY_E;
                    }
                    else {
                        c32toa(nameLen, &newKey[localIdx]);
                        localIdx += LENGTH_SZ;
                        WMEMCPY(&newKey[localIdx], name, nameLen);
                        localIdx += nameLen;
                        c32toa(rawPubSz, &newKey[localIdx]);
                        localIdx += LENGTH_SZ;
                        WMEMCPY(&newKey[localIdx], rawPub, rawPubSz);
                        *out = newKey;
                        ret = WS_SUCCESS;
                    }
                }
                WFREE(rawPub, heap, DYNTYPE_PUBKEY);
            }
        }
        /* Each arm's else sits inside that arm's guard, so a disabled key
         * type drops its if and its else together and the chain stays
         * well formed. */
        else
#endif /* WOLFSSH_NO_MLDSA */
#ifndef WOLFSSH_NO_ECDSA
        if (ret == ID_ECDSA_SHA2_NISTP256 ||
            ret == ID_ECDSA_SHA2_NISTP384 ||
            ret == ID_ECDSA_SHA2_NISTP521) {
            byte* q = NULL;
            /* uncompressed x963 point: leading tag byte plus X and Y */
            word32 qSz = 1 + 2 * MAX_ECC_BYTES;
            const char* curveName;
            word32 curveNameSz;
            word32 localIdx = 0;

            if (ret == ID_ECDSA_SHA2_NISTP384) {
                curveName = IdToName(ID_CURVE_NISTP384);
            }
            else if (ret == ID_ECDSA_SHA2_NISTP521) {
                curveName = IdToName(ID_CURVE_NISTP521);
            }
            else {
                curveName = IdToName(ID_CURVE_NISTP256);
            }
            curveNameSz = (word32)WSTRLEN(curveName);

            q = (byte*)WMALLOC(qSz, heap, DYNTYPE_PUBKEY);
            if (q == NULL) {
                ret = WS_MEMORY_E;
            }
            else {
                int wcRet;

                PRIVATE_KEY_UNLOCK();
                wcRet = wc_ecc_export_x963(&key->ks.ecc.key, q, &qSz);
                PRIVATE_KEY_LOCK();

                if (wcRet != 0) {
                    ret = WS_CRYPTO_FAILED;
                }
                else {
                    *outSz = LENGTH_SZ + *outTypeSz + LENGTH_SZ + curveNameSz +
                        LENGTH_SZ + qSz;
                    newKey = (byte*)WMALLOC(*outSz, heap, DYNTYPE_PRIVKEY);
                    if (newKey == NULL) {
                        ret = WS_MEMORY_E;
                    }
                    else {
                        c32toa(*outTypeSz, &newKey[localIdx]);
                        localIdx += LENGTH_SZ;
                        WMEMCPY(&newKey[localIdx], *outType, *outTypeSz);
                        localIdx += *outTypeSz;
                        c32toa(curveNameSz, &newKey[localIdx]);
                        localIdx += LENGTH_SZ;
                        WMEMCPY(&newKey[localIdx], curveName, curveNameSz);
                        localIdx += curveNameSz;
                        c32toa(qSz, &newKey[localIdx]);
                        localIdx += LENGTH_SZ;
                        WMEMCPY(&newKey[localIdx], q, qSz);
                        *out = newKey;
                        ret = WS_SUCCESS;
                    }
                }
                WFREE(q, heap, DYNTYPE_PUBKEY);
            }
        }
        else
#endif /* WOLFSSH_NO_ECDSA */
#ifndef WOLFSSH_NO_ED25519
        if (ret == ID_ED25519) {
            byte q[ED25519_PUB_KEY_SIZE];
            word32 qSz = (word32)sizeof(q);
            word32 localIdx = 0;
            int wcRet;

            wcRet = wc_ed25519_export_public(&key->ks.ed25519.key, q, &qSz);
            if (wcRet != 0) {
                ret = WS_CRYPTO_FAILED;
            }
            else {
                *outSz = LENGTH_SZ + *outTypeSz + LENGTH_SZ + qSz;
                newKey = (byte*)WMALLOC(*outSz, heap, DYNTYPE_PRIVKEY);
                if (newKey == NULL) {
                    ret = WS_MEMORY_E;
                }
                else {
                    c32toa(*outTypeSz, &newKey[localIdx]);
                    localIdx += LENGTH_SZ;
                    WMEMCPY(&newKey[localIdx], *outType, *outTypeSz);
                    localIdx += *outTypeSz;
                    c32toa(qSz, &newKey[localIdx]);
                    localIdx += LENGTH_SZ;
                    WMEMCPY(&newKey[localIdx], q, qSz);
                    *out = newKey;
                    ret = WS_SUCCESS;
                }
            }
        }
        else
#endif /* WOLFSSH_NO_ED25519 */
#ifndef WOLFSSH_NO_RSA
        if (ret == ID_SSH_RSA) {
            long e;
            byte n[RSA_MAX_SIZE]; /* TODO: Handle small stack */
            word32 nSz = (word32)sizeof(n), eSz = (word32)sizeof(e);
            const char* keyFormat = "ssh-rsa";
            word32 idx = 0;
            int nMsb = 0;
            int wcRet;

            wcRet = wc_RsaFlattenPublicKey(&key->ks.rsa.key, (byte*)&e, &eSz,
                    n, &nSz);
            if (wcRet != 0) {
                ret = WS_CRYPTO_FAILED;
            }
            else {
                ret = WS_SUCCESS;
            }
            if (ret == WS_SUCCESS) {
                if (n[0] & 0x80) {
                    /* if MSB is set need leading zero */
                    nMsb = 1;
                }
                *outSz = LENGTH_SZ + (word32)WSTRLEN(keyFormat) +
                    LENGTH_SZ + eSz +
                    LENGTH_SZ + nSz + nMsb;

                newKey = (byte*)WMALLOC(*outSz, heap, DYNTYPE_PRIVKEY);
                if (newKey == NULL) {
                    ret = WS_MEMORY_E;
                }
            }
            if (ret == WS_SUCCESS) {
                /* encode the key format string */
                c32toa((word32)WSTRLEN(keyFormat), &newKey[idx]);
                idx += LENGTH_SZ;
                WMEMCPY(&newKey[idx], keyFormat, (word32)WSTRLEN(keyFormat));
                idx += (word32)WSTRLEN(keyFormat);

                /* encode public exponent (e) */
                c32toa(eSz, &newKey[idx]);
                idx += LENGTH_SZ;
                WMEMCPY(&newKey[idx], &e, eSz);
                idx += eSz;

                /* encode public modulus (n) */
                c32toa(nSz + nMsb, &newKey[idx]);
                idx += LENGTH_SZ;
                if (nMsb) {
                    newKey[idx++] = 0;
                }
                WMEMCPY(&newKey[idx], n, nSz);

                *out = newKey;
            }
        }
        else
#endif /* WOLFSSH_NO_RSA */
        {
            WLOG(WS_LOG_DEBUG, "DoAsn1Key unsupported public key type");
            ret = WS_UNIMPLEMENTED_E;
        }
    }
    else if (ret > 0 && isPrivate) {
        if (*out == NULL) {
            newKey = (byte*)WMALLOC(inSz, heap, DYNTYPE_PRIVKEY);
            if (newKey == NULL) {
                ret = WS_MEMORY_E;
            }
        }
        else if (*outSz < inSz) {
            WLOG(WS_LOG_DEBUG, "DER private key output size too small");
            ret = WS_BUFFER_E;
        }
        else {
            newKey = *out;
        }
        if (ret > 0) {
            *out = newKey;
            *outSz = inSz;
            WMEMCPY(newKey, in, inSz);
            *outType = (const byte*)IdToName(ret);
            *outTypeSz = (word32)WSTRLEN((const char*)*outType);
        }
    }

    wolfSSH_KEY_clean(key);
    WFREE(key, heap, isPrivate ? DYNTYPE_PRIVKEY : DYNTYPE_PUBKEY);

    if (*out == NULL) {
        WFREE(newKey, heap, DYNTYPE_PRIVKEY);
    }

    if (ret > 0) {
        ret = WS_SUCCESS;
    }

    return ret;
}


static int DoPemKey(const byte* in, word32 inSz, byte** out,
        word32* outSz, const byte** outType, word32* outTypeSz,
        int isPrivate, void* heap)
{
    int ret = WS_SUCCESS;
    byte* newKey = NULL;
    word32 newKeySz = inSz; /* binary will be smaller than PEM */

    WOLFSSH_UNUSED(heap);

    if (*out == NULL) {
        newKey = (byte*)WMALLOC(newKeySz, heap, DYNTYPE_PRIVKEY);
        if (newKey == NULL) {
            return WS_MEMORY_E;
        }
    }
    else {
        if (*outSz < inSz) {
            WLOG(WS_LOG_DEBUG, "PEM private key output size too small");
            return WS_BUFFER_E;
        }
        newKey = *out;
        newKeySz = *outSz;
    }

    /* If it is PEM, convert to ASN1 then process. */
    if (isPrivate) {
        ret = wc_KeyPemToDer(in, inSz, newKey, newKeySz, NULL);
    }
    else {
    #ifdef WOLFSSH_TPM
        ret = wc_PubKeyPemToDer(in, inSz, newKey, newKeySz);
    #else
        ret = NOT_COMPILED_IN;
    #endif
    }
    if (ret > 0) {
        newKeySz = (word32)ret;
        ret = WS_SUCCESS;
    }
    else {
        WLOG(WS_LOG_DEBUG, "Base64 decode of public key failed.");
        ret = WS_PARSE_E;
    }

    if (ret == WS_SUCCESS) {
        ret = IdentifyAsn1Key(newKey, newKeySz, isPrivate, heap, NULL);
    }

    if (ret > 0) {
        *out = newKey;
        *outSz = newKeySz;
        *outType = (const byte*)IdToName(ret);
        *outTypeSz = (word32)WSTRLEN((const char*)*outType);
        ret = WS_SUCCESS;
    }
    else {
        WLOG(WS_LOG_DEBUG, "Unable to identify PEM key");
        WS_FORCEZERO(newKey, newKeySz);
        if (*out == NULL) {
            WFREE(newKey, heap, DYNTYPE_PRIVKEY);
        }
    }

    return ret;
}


static int DoOpenSshKey(const byte* in, word32 inSz, byte** out,
        word32* outSz, const byte** outType, word32* outTypeSz,
        void* heap)
{
    int ret = WS_SUCCESS;
    byte* newKey = NULL;
    word32 newKeySz = inSz; /* binary will be smaller than PEM */

    if (*out == NULL) {
        newKey = (byte*)WMALLOC(newKeySz, heap, DYNTYPE_PRIVKEY);
        if (newKey == NULL) {
            return WS_MEMORY_E;
        }
    }
    else {
        if (*outSz < inSz) {
            WLOG(WS_LOG_DEBUG, "PEM private key output size too small");
            return WS_BUFFER_E;
        }
        newKey = *out;
        newKeySz = *outSz;
    }

    /* locates the begin/end markers and base64-decodes the block between
     * them; shared with wolfSSH_ProcessBuffer()'s OPENSSH format path */
    ret = WS_StripOpenSshPem(in, inSz, newKey, &newKeySz);
    if (ret != WS_SUCCESS) {
        WLOG(WS_LOG_DEBUG, "OpenSSH private key marker/decode failed.");
    }

    if (ret == WS_SUCCESS) {
        ret = IdentifyOpenSshKey(newKey, newKeySz, heap);
        if (ret <= 0) {
            WLOG(WS_LOG_DEBUG, "Unable to identify key");
        }
    }

    if (ret > 0) {
        *out = newKey;
        *outSz = newKeySz;
        *outType = (const byte*)IdToName(ret);
        *outTypeSz = (word32)WSTRLEN((const char*)*outType);
        ret = WS_SUCCESS;
    }
    else {
        WS_FORCEZERO(newKey, newKeySz);
        if (*out == NULL) {
            WFREE(newKey, heap, DYNTYPE_PRIVKEY);
        }
    }

    return ret;
}


/* Reads a key from the buffer in to out. If the out buffer doesn't exist
   it is created. The type of key is stored in outType. It'll be a pointer
   to a constant string. Format indicates the format of the key, currently
   either SSH format (a public key) or ASN.1 in DER or PEM format (a
   private key). */
int wolfSSH_ReadKey_buffer_ex(const byte* in, word32 inSz, int format,
        byte** out, word32* outSz, const byte** outType, word32* outTypeSz,
        int isPrivate, void* heap)
{
    int ret = WS_SUCCESS;

    if (in == NULL || inSz == 0 || out == NULL || outSz == NULL ||
            outType == NULL || outTypeSz == NULL)
        return WS_BAD_ARGUMENT;

    if (format == WOLFSSH_FORMAT_SSH) {
        ret = DoSshPubKey(in, inSz, out, outSz, outType, outTypeSz, heap);
    }
    else if (format == WOLFSSH_FORMAT_ASN1) {
        ret = DoAsn1Key(in, inSz, out, outSz, outType, outTypeSz,
            isPrivate, heap);
    }
    else if (format == WOLFSSH_FORMAT_PEM) {
        ret = DoPemKey(in, inSz, out, outSz, outType, outTypeSz,
            isPrivate, heap);
    }
    else if (format == WOLFSSH_FORMAT_OPENSSH) {
        ret = DoOpenSshKey(in, inSz, out, outSz, outType, outTypeSz, heap);
    }
    else {
        WLOG(WS_LOG_DEBUG, "Invalid key format");
        ret = WS_BAD_ARGUMENT;
    }

    return ret;
}
int wolfSSH_ReadKey_buffer(const byte* in, word32 inSz, int format,
        byte** out, word32* outSz, const byte** outType, word32* outTypeSz,
        void* heap)
{
    return wolfSSH_ReadKey_buffer_ex(in, inSz, format, out, outSz,
        outType, outTypeSz, 1, heap);
}

int wolfSSH_ReadPublicKey_buffer(const byte* in, word32 inSz, int format,
        byte** out, word32* outSz, const byte** outType, word32* outTypeSz,
        void* heap)
{
    return wolfSSH_ReadKey_buffer_ex(in, inSz, format, out, outSz,
        outType, outTypeSz, 0, heap);
}


#if defined(WOLFSSH_CERTS) || defined(WOLFSSH_OSSH_CERTS)

#ifdef WOLFSSH_CERTS
    static const char* CertBeginPrefix = "-----BEGIN CERTIFICATE-----";
#endif
#ifdef WOLFSSH_HAVE_TRUSTED_CERT_PEM
    static const char* TrustedCertBeginPrefix =
            "-----BEGIN TRUSTED CERTIFICATE-----";
#endif

/* Longest algorithm name is ecdsa-sha2-nistp521-cert-v01@openssh.com. */
#define WOLFSSH_MAX_CERT_ALGO_NAME_SZ 48

/* Identifies a certificate from its content, without decoding or allocating.
   An x509v3-* line holds a wire chain, not a certificate, so it is declined.
   The trusted form is PEM too; the decoders decide who takes it. */
static int SniffCertForm(const byte* in, word32 inSz, byte* flavor,
        byte* certId)
{
#ifdef WOLFSSH_OSSH_CERTS
    word32 tokenSz = 0;
    byte id;
#endif
    int ret = WS_BAD_FILETYPE_E;

#ifdef WOLFSSH_CERTS
    if (in[0] == 0x30) {
        *flavor = WOLFSSH_CERT_FLAVOR_X509;
        ret = WOLFSSH_FORMAT_ASN1;
    }
    /* Searched for, not anchored: openssl writes a dump ahead of the header. */
    else if (WSTRNSTR((const char*)in, CertBeginPrefix, inSz) != NULL) {
        *flavor = WOLFSSH_CERT_FLAVOR_X509;
        ret = WOLFSSH_FORMAT_PEM;
    }
#ifdef WOLFSSH_HAVE_TRUSTED_CERT_PEM
    else if (WSTRNSTR((const char*)in, TrustedCertBeginPrefix, inSz) != NULL) {
        *flavor = WOLFSSH_CERT_FLAVOR_X509;
        ret = WOLFSSH_FORMAT_PEM;
    }
#endif /* WOLFSSH_HAVE_TRUSTED_CERT_PEM */
#endif /* WOLFSSH_CERTS */

#ifdef WOLFSSH_OSSH_CERTS
    if (ret == WS_BAD_FILETYPE_E) {
        while (tokenSz < inSz && tokenSz < WOLFSSH_MAX_CERT_ALGO_NAME_SZ
                && in[tokenSz] != ' ' && in[tokenSz] != '\t'
                && in[tokenSz] != '\r' && in[tokenSz] != '\n') {
            tokenSz++;
        }

        if (tokenSz > 0 && tokenSz < WOLFSSH_MAX_CERT_ALGO_NAME_SZ) {
            id = NameToId((const char*)in, tokenSz);

            switch (id) {
                case ID_OSSH_CERT_RSA:
                case ID_OSSH_CERT_ECDSA_SHA2_NISTP256:
                case ID_OSSH_CERT_ECDSA_SHA2_NISTP384:
                case ID_OSSH_CERT_ECDSA_SHA2_NISTP521:
                case ID_OSSH_CERT_ED25519:
                    *flavor = WOLFSSH_CERT_FLAVOR_OSSH;
                    *certId = id;
                    ret = WOLFSSH_FORMAT_SSH;
                    break;
                default:
                    break;
            }
        }
    }
#else
    WOLFSSH_UNUSED(certId);
#endif /* WOLFSSH_OSSH_CERTS */

    return ret;
}


#ifdef WOLFSSH_CERTS

/* Decodes a PEM certificate to DER and identifies it. */
static int DoPemCert(const byte* in, word32 inSz, byte** out, word32* outSz,
        const byte** outType, word32* outTypeSz, void* heap)
{
    byte* der;
    word32 derSz = 0;
    int ret;

#ifdef WOLFSSH_HAVE_TRUSTED_CERT_PEM
    if (IsTrustedCertPem(in, inSz)) {
        /* The trust data behind the certificate means nothing to a peer. */
        WLOG(WS_LOG_DEBUG, "Trusted certificate form is for root CAs");
        return WS_BAD_FILETYPE_E;
    }
#endif

    der = (byte*)WMALLOC(inSz, heap, DYNTYPE_CERT);
    if (der == NULL) {
        return WS_MEMORY_E;
    }

    ret = wc_CertPemToDer(in, (int)inSz, der, (int)inSz, CERT_TYPE);
    if (ret <= 0) {
        WLOG(WS_LOG_DEBUG, "PEM certificate body would not decode.");
        WFREE(der, heap, DYNTYPE_CERT);
        return WS_PARSE_E;
    }
    derSz = (word32)ret;

    ret = IdentifyCert(der, derSz, heap);
    if (ret < 0) {
        WFREE(der, heap, DYNTYPE_CERT);
    }
    else {
        *out = der;
        *outSz = derSz;
        *outType = (const byte*)IdToName((byte)ret);
        *outTypeSz = (word32)WSTRLEN((const char*)*outType);
        ret = WS_SUCCESS;
    }

    return ret;
}


/* Identifies a DER certificate before copying it out. */
static int DoDerCert(const byte* in, word32 inSz, byte** out, word32* outSz,
        const byte** outType, word32* outTypeSz, void* heap)
{
    byte* der;
    int ret;

    ret = IdentifyCert(in, inSz, heap);

    if (ret >= 0) {
        der = (byte*)WMALLOC(inSz, heap, DYNTYPE_CERT);
        if (der == NULL) {
            ret = WS_MEMORY_E;
        }
        else {
            WMEMCPY(der, in, inSz);
            *out = der;
            *outSz = inSz;
            *outType = (const byte*)IdToName((byte)ret);
            *outTypeSz = (word32)WSTRLEN((const char*)*outType);
            ret = WS_SUCCESS;
        }
    }

    return ret;
}

#endif /* WOLFSSH_CERTS */


#ifdef WOLFSSH_OSSH_CERTS

/* Decodes an OpenSSH certificate line and checks that it parses. */
static int DoOsshCert(const byte* in, word32 inSz, byte certId, byte** out,
        word32* outSz, const byte** outType, word32* outTypeSz, void* heap)
{
    WS_OsshCert cert;
    byte* blob;
    int ret;

    blob = (byte*)WMALLOC(inSz, heap, DYNTYPE_CERT);
    if (blob == NULL) {
        return WS_MEMORY_E;
    }

    /* DoSshPubKey decodes into a non-NULL *out rather than allocating, so it
       fills blob and leaves it ours to free. Were it to allocate instead,
       blob would leak and the free below would take the wrong type. */
    *out = blob;
    *outSz = inSz;

    ret = DoSshPubKey(in, inSz, out, outSz, outType, outTypeSz, heap);

    if (ret == WS_SUCCESS) {
        /* The blob has no envelope, so only a parse tells it from a key. */
        ret = OsshCertParse(&cert, certId, *out, *outSz);
        if (ret != WS_SUCCESS) {
            WLOG(WS_LOG_DEBUG, "OpenSSH certificate is malformed.");
        }
    }

    if (ret != WS_SUCCESS) {
        WFREE(blob, heap, DYNTYPE_CERT);
        *out = NULL;
        *outSz = 0;
    }

    return ret;
}

#endif /* WOLFSSH_OSSH_CERTS */


/* Reads a certificate from the buffer in to out, detecting its form from the
   content. See ssh.h for what the caller owns. */
int wolfSSH_ReadCert_buffer(const byte* in, word32 inSz,
        byte** out, word32* outSz, const byte** outType, word32* outTypeSz,
        byte* flavor, void* heap)
{
    byte certId = ID_UNKNOWN;
    int format;
    int ret;

    if (in == NULL || inSz == 0 || out == NULL || outSz == NULL ||
            outType == NULL || outTypeSz == NULL || flavor == NULL) {
        return WS_BAD_ARGUMENT;
    }

    *out = NULL;
    *outSz = 0;
    *outType = NULL;
    *outTypeSz = 0;
    *flavor = WOLFSSH_CERT_FLAVOR_UNKNOWN;

    format = SniffCertForm(in, inSz, flavor, &certId);
    if (format < 0) {
        WLOG(WS_LOG_DEBUG, "Unable to identify the certificate");
        return format;
    }

    ret = WS_BAD_FILETYPE_E;

    switch (format) {
    #ifdef WOLFSSH_CERTS
        case WOLFSSH_FORMAT_PEM:
            ret = DoPemCert(in, inSz, out, outSz, outType, outTypeSz, heap);
            break;

        case WOLFSSH_FORMAT_ASN1:
            ret = DoDerCert(in, inSz, out, outSz, outType, outTypeSz, heap);
            break;
    #endif /* WOLFSSH_CERTS */
    #ifdef WOLFSSH_OSSH_CERTS
        case WOLFSSH_FORMAT_SSH:
            ret = DoOsshCert(in, inSz, certId, out, outSz, outType, outTypeSz,
                    heap);
            break;
    #endif /* WOLFSSH_OSSH_CERTS */
        default:
            break;
    }

    /* The sniff names the form and a decoder may fill an out parameter before
       failing, so a failure clears them all rather than leave a partial
       answer. Decoders free whatever they allocated. */
    if (ret != WS_SUCCESS) {
        *out = NULL;
        *outSz = 0;
        *outType = NULL;
        *outTypeSz = 0;
        *flavor = WOLFSSH_CERT_FLAVOR_UNKNOWN;
    }

    return ret;
}

#endif /* WOLFSSH_CERTS || WOLFSSH_OSSH_CERTS */


#if !defined(NO_FILESYSTEM) && !defined(WOLFSSH_USER_FILESYSTEM)

/* Reads the file name into a buffer allocated with an extra byte holding a
   nul terminator. The caller frees out with DYNTYPE_FILE. */
static int ReadFileIntoBuffer(const char* name, byte** out, word32* outSz,
        void* heap)
{
    WFILE* file;
#ifdef MICROCHIP_MPLAB_HARMONY
    WFILE f = WBADFILE;
#endif
    byte* in;
    word32 inSz;
    int ret;

#ifdef MICROCHIP_MPLAB_HARMONY
    file = &f;
    ret = WFOPEN(NULL, &file, name, WOLFSSH_O_RDONLY);
    if (ret != 0 || *file == WBADFILE) return WS_BAD_FILE_E;
#else
    ret = WFOPEN(NULL, &file, name, "rb");
    if (ret != 0 || file == WBADFILE) return WS_BAD_FILE_E;
#endif

    if (!WFSEEK_SUCCESS(WFSEEK(NULL, file, 0, WSEEK_END))) {
        WFCLOSE(NULL, file);
        return WS_BAD_FILE_E;
    }
    inSz = (word32)WFTELL(NULL, file);
    WREWIND(NULL, file);

    if (inSz > WOLFSSH_MAX_FILE_SIZE || inSz == 0) {
        WFCLOSE(NULL, file);
        return WS_BAD_FILE_E;
    }

    in = (byte*)WMALLOC(inSz + 1, heap, DYNTYPE_FILE);
    if (in == NULL) {
        WFCLOSE(NULL, file);
        return WS_MEMORY_E;
    }

    ret = (int)WFREAD(NULL, in, 1, inSz, file);
    WFCLOSE(NULL, file);

    if (ret <= 0 || (word32)ret != inSz) {
        WS_FORCEZERO(in, inSz);
        WFREE(in, heap, DYNTYPE_FILE);
        return WS_BAD_FILE_E;
    }

    in[inSz] = 0;
    *out = in;
    *outSz = inSz;

    return WS_SUCCESS;
}


/* Reads a key from the file name into a buffer. An SSH algorithm name marks
   an SSH format public key and "-----BEGIN " a PEM one, otherwise it is an
   ASN.1 private key. The buffer goes to wolfSSH_ReadKey_buffer_ex(). */
int wolfSSH_ReadKey_file(const char* name,
        byte** out, word32* outSz, const byte** outType, word32* outTypeSz,
        byte* isPrivate, void* heap)
{
    byte* in;
    word32 inSz;
    int format;
    int ret;

    if (name == NULL)
        return WS_BAD_FILE_E;

    if (out == NULL || outSz == NULL || outType == NULL || outTypeSz == NULL ||
            isPrivate == NULL)
        return WS_BAD_ARGUMENT;

    ret = ReadFileIntoBuffer(name, &in, &inSz, heap);
    if (ret == WS_SUCCESS) {
        if (WSTRNSTR((const char*)in, "ssh-rsa", inSz) == (const char*)in
                || WSTRNSTR((const char*)in,
                    "ecdsa-sha2-nistp", inSz) == (const char*)in
                || WSTRNSTR((const char*)in,
                    "ssh-ed25519", inSz) == (const char*)in
                || WSTRNSTR((const char*)in,
                    "ssh-mldsa-", inSz) == (const char*)in
                || WSTRNSTR((const char*)in,
                    "x509v3-ssh-mldsa-", inSz) == (const char*)in) {
            *isPrivate = 0;
            format = WOLFSSH_FORMAT_SSH;
        }
        else if (WSTRNSTR((const char*)in, PrivBeginOpenSSH, inSz) != NULL) {
            *isPrivate = 1;
            format = WOLFSSH_FORMAT_OPENSSH;
        }
        else if ((WSTRNSTR((const char*)in, PrivBeginPrefix, inSz)
                    == (const char*)in)
                && (WSTRNSTR((const char*)in, PrivSuffix, inSz)
                    != NULL)) {
            *isPrivate = 1;
            format = WOLFSSH_FORMAT_PEM;
        }
        else {
            *isPrivate = 1;
            format = WOLFSSH_FORMAT_ASN1;
        }

        ret = wolfSSH_ReadKey_buffer_ex(in, inSz, format,
                out, outSz, outType, outTypeSz, *isPrivate, heap);

        WS_FORCEZERO(in, inSz);
        WFREE(in, heap, DYNTYPE_FILE);
    }

    return ret;
}


#if defined(WOLFSSH_CERTS) || defined(WOLFSSH_OSSH_CERTS)

/* Reads a certificate file and passes it to wolfSSH_ReadCert_buffer(). */
int wolfSSH_ReadCert_file(const char* name,
        byte** out, word32* outSz, const byte** outType, word32* outTypeSz,
        byte* flavor, void* heap)
{
    byte* in;
    word32 inSz;
    int ret;

    if (name == NULL)
        return WS_BAD_FILE_E;

    if (out == NULL || outSz == NULL || outType == NULL || outTypeSz == NULL ||
            flavor == NULL)
        return WS_BAD_ARGUMENT;

    *out = NULL;
    *outSz = 0;
    *outType = NULL;
    *outTypeSz = 0;
    *flavor = WOLFSSH_CERT_FLAVOR_UNKNOWN;

    ret = ReadFileIntoBuffer(name, &in, &inSz, heap);
    if (ret == WS_SUCCESS) {
        ret = wolfSSH_ReadCert_buffer(in, inSz,
                out, outSz, outType, outTypeSz, flavor, heap);

        /* A certificate is public, but the file may hold a private key
           beside it, so scrub it like the key reader does. */
        WS_FORCEZERO(in, inSz);
        WFREE(in, heap, DYNTYPE_FILE);
    }

    return ret;
}

#endif /* WOLFSSH_CERTS || WOLFSSH_OSSH_CERTS */

#endif


int wolfSSH_CTX_SetAlgoListKex(WOLFSSH_CTX* ctx, const char* list)
{
    int ret = WS_SSH_CTX_NULL_E;

    if (ctx) {
        ret = CheckAlgoList(list, TYPE_KEX);
        if (ret == WS_SUCCESS) {
            ctx->algoListKex = list;
        }
    }

    return ret;
}


const char* wolfSSH_CTX_GetAlgoListKex(WOLFSSH_CTX* ctx)
{
    const char* list = NULL;

    if (ctx) {
        list = ctx->algoListKex;
    }

    return list;
}


int wolfSSH_SetAlgoListKex(WOLFSSH* ssh, const char* list)
{
    int ret = WS_SSH_NULL_E;

    if (ssh) {
        ret = CheckAlgoList(list, TYPE_KEX);
        if (ret == WS_SUCCESS) {
            ssh->algoListKex = list;
        }
    }

    return ret;
}


const char* wolfSSH_GetAlgoListKex(WOLFSSH* ssh)
{
    const char* list = NULL;

    if (ssh) {
        list = ssh->algoListKex;
    }

    return list;
}


int wolfSSH_CTX_SetAlgoListKey(WOLFSSH_CTX* ctx, const char* list)
{
    int ret = WS_SSH_CTX_NULL_E;

    if (ctx) {
        /* NULL restores the server's auto-derived list; a client has none. */
        if (list == NULL) {
            ret = (ctx->side == WOLFSSH_ENDPOINT_SERVER) ?
                WS_SUCCESS : WS_INVALID_ALGO_ID;
        }
        else {
            ret = CheckAlgoList(list, TYPE_KEY);
        }
        if (ret == WS_SUCCESS) {
            ctx->algoListKey = list;
        }
    }

    return ret;
}


const char* wolfSSH_CTX_GetAlgoListKey(WOLFSSH_CTX* ctx)
{
    const char* list = NULL;

    if (ctx) {
        list = ctx->algoListKey;
    }

    return list;
}


int wolfSSH_SetAlgoListKey(WOLFSSH* ssh, const char* list)
{
    int ret = WS_SSH_NULL_E;

    if (ssh) {
        /* NULL is server-only. */
        if (list == NULL) {
            ret = (ssh->ctx != NULL
                    && ssh->ctx->side == WOLFSSH_ENDPOINT_SERVER) ?
                WS_SUCCESS : WS_INVALID_ALGO_ID;
        }
        else {
            ret = CheckAlgoList(list, TYPE_KEY);
        }
        if (ret == WS_SUCCESS) {
            ssh->algoListKey = list;
        }
    }

    return ret;
}


const char* wolfSSH_GetAlgoListKey(WOLFSSH* ssh)
{
    const char* list = NULL;

    if (ssh) {
        list = ssh->algoListKey;
    }

    return list;
}


int wolfSSH_CTX_SetAlgoListCipher(WOLFSSH_CTX* ctx, const char* list)
{
    int ret = WS_SSH_CTX_NULL_E;

    if (ctx) {
        ret = CheckAlgoList(list, TYPE_CIPHER);
        if (ret == WS_SUCCESS) {
            ctx->algoListCipher = list;
        }
    }

    return ret;
}


const char* wolfSSH_CTX_GetAlgoListCipher(WOLFSSH_CTX* ctx)
{
    const char* list = NULL;

    if (ctx) {
        list = ctx->algoListCipher;
    }

    return list;
}


int wolfSSH_SetAlgoListCipher(WOLFSSH* ssh, const char* list)
{
    int ret = WS_SSH_NULL_E;

    if (ssh) {
        ret = CheckAlgoList(list, TYPE_CIPHER);
        if (ret == WS_SUCCESS) {
            ssh->algoListCipher = list;
        }
    }

    return ret;
}


const char* wolfSSH_GetAlgoListCipher(WOLFSSH* ssh)
{
    const char* list = NULL;

    if (ssh) {
        list = ssh->algoListCipher;
    }

    return list;
}


int wolfSSH_CTX_SetAlgoListMac(WOLFSSH_CTX* ctx, const char* list)
{
    int ret = WS_SSH_CTX_NULL_E;

    if (ctx) {
        ret = CheckAlgoList(list, TYPE_MAC);
        if (ret == WS_SUCCESS) {
            ctx->algoListMac = list;
        }
    }

    return ret;
}


const char* wolfSSH_CTX_GetAlgoListMac(WOLFSSH_CTX* ctx)
{
    const char* list = NULL;

    if (ctx) {
        list = ctx->algoListMac;
    }

    return list;
}


int wolfSSH_SetAlgoListMac(WOLFSSH* ssh, const char* list)
{
    int ret = WS_SSH_NULL_E;

    if (ssh) {
        ret = CheckAlgoList(list, TYPE_MAC);
        if (ret == WS_SUCCESS) {
            ssh->algoListMac = list;
        }
    }

    return ret;
}


const char* wolfSSH_GetAlgoListMac(WOLFSSH* ssh)
{
    const char* list = NULL;

    if (ssh) {
        list = ssh->algoListMac;
    }

    return list;
}


int wolfSSH_CTX_SetAlgoListKeyAccepted(WOLFSSH_CTX* ctx, const char* list)
{
    int ret = WS_SSH_CTX_NULL_E;

    if (ctx) {
        /* NULL empties the advertised list, it does not restore a default. */
        ret = (list == NULL) ? WS_SUCCESS : CheckAlgoList(list, TYPE_KEY);
        if (ret == WS_SUCCESS) {
            ctx->algoListKeyAccepted = list;
        }
    }

    return ret;
}


const char* wolfSSH_CTX_GetAlgoListKeyAccepted(WOLFSSH_CTX* ctx)
{
    const char* list = NULL;

    if (ctx) {
        list = ctx->algoListKeyAccepted;
    }

    return list;
}


int wolfSSH_SetAlgoListKeyAccepted(WOLFSSH* ssh, const char* list)
{
    int ret = WS_SSH_NULL_E;

    if (ssh) {
        /* NULL empties the advertised list, it does not restore a default. */
        ret = (list == NULL) ? WS_SUCCESS : CheckAlgoList(list, TYPE_KEY);
        if (ret == WS_SUCCESS) {
            ssh->algoListKeyAccepted = list;
        }
    }

    return ret;
}


const char* wolfSSH_GetAlgoListKeyAccepted(WOLFSSH* ssh)
{
    const char* list = NULL;

    if (ssh) {
        list = ssh->algoListKeyAccepted;
    }

    return list;
}


int wolfSSH_CheckAlgoName(const char* name)
{
    int ret = WS_INVALID_ALGO_ID;

    if (name) {
        word32 nameSz = (word32)WSTRLEN(name);
        if (NameToId(name, nameSz) != ID_UNKNOWN) {
            ret = WS_SUCCESS;
        }
    }

    return ret;
}


const char* wolfSSH_QueryKex(word32* idx)
{
    return NameByIndexType(TYPE_KEX, idx);
}


const char* wolfSSH_QueryKey(word32* idx)
{
    return NameByIndexType(TYPE_KEY, idx);
}


const char* wolfSSH_QueryCipher(word32* idx)
{
    return NameByIndexType(TYPE_CIPHER, idx);
}


const char* wolfSSH_QueryMac(word32* idx)
{
    return NameByIndexType(TYPE_MAC, idx);
}


int wolfSSH_CTX_SetBanner(WOLFSSH_CTX* ctx,
                          const char* newBanner)
{
    word32 newBannerSz = 0;

    WLOG(WS_LOG_DEBUG, "Entering wolfSSH_CTX_SetBanner()");

    if (ctx == NULL)
        return WS_BAD_ARGUMENT;

    if (newBanner != NULL) {
        WLOG(WS_LOG_INFO, "  setting banner to: \"%s\"", newBanner);
        newBannerSz = (word32)WSTRLEN(newBanner);
    }

    ctx->banner = newBanner;
    ctx->bannerSz = newBannerSz;

    return WS_SUCCESS;
}

int wolfSSH_CTX_SetMaxAuthAttempts(WOLFSSH_CTX* ctx, int value)
{
    WLOG(WS_LOG_DEBUG, "Entering wolfSSH_CTX_SetMaxAuthAttempts()");

    if (ctx == NULL)
        return WS_BAD_ARGUMENT;

    /* A value <= 0 restores the built-in default. */
    if (value <= 0)
        ctx->maxAuthAttempts = DEFAULT_MAX_AUTH_ATTEMPTS;
    else
        ctx->maxAuthAttempts = (word32)value;

    return WS_SUCCESS;
}


int wolfSSH_CTX_GetMaxAuthAttempts(WOLFSSH_CTX* ctx)
{
    return (ctx == NULL) ? WS_BAD_ARGUMENT : (int)ctx->maxAuthAttempts;
}


int wolfSSH_SetMaxAuthAttempts(WOLFSSH* ssh, int value)
{
    WLOG(WS_LOG_DEBUG, "Entering wolfSSH_SetMaxAuthAttempts()");

    if (ssh == NULL)
        return WS_BAD_ARGUMENT;

    /* A value <= 0 restores the built-in default. */
    if (value <= 0)
        ssh->maxAuthAttempts = DEFAULT_MAX_AUTH_ATTEMPTS;
    else
        ssh->maxAuthAttempts = (word32)value;

    return WS_SUCCESS;
}


int wolfSSH_GetMaxAuthAttempts(WOLFSSH* ssh)
{
    return (ssh == NULL) ? WS_BAD_ARGUMENT : (int)ssh->maxAuthAttempts;
}

int wolfSSH_CTX_SetSshProtoIdStr(WOLFSSH_CTX* ctx,
                                          const char* protoIdStr)
{
    int ret;
    WLOG(WS_LOG_DEBUG, "Entering wolfSSH_CTX_SetSshProtoIdStr()");

    if (!ctx || !protoIdStr) {
        return WS_BAD_ARGUMENT;
    }

    if ((ret = ValidateProtoId(protoIdStr, (word32)WSTRLEN(protoIdStr))) !=
            WS_SUCCESS) {
        return ret;
    }

    ctx->sshProtoIdStr = protoIdStr;
    return WS_SUCCESS;
}

int wolfSSH_CTX_UsePrivateKey_buffer(WOLFSSH_CTX* ctx,
                                   const byte* in, word32 inSz, int format)
{
    int ret = WS_SUCCESS;

    WLOG(WS_LOG_DEBUG, "Entering wolfSSH_CTX_UsePrivateKey_buffer()");

    ret = wolfSSH_ProcessBuffer(ctx, in, inSz, format, BUFTYPE_PRIVKEY);

    WLOG(WS_LOG_DEBUG,
            "Leaving wolfSSH_CTX_UsePrivateKey_buffer(), ret = %d", ret);
    return ret;
}


#ifdef WOLFSSH_CERTS

/* load in a X509 certificate that has public key to use
 * return WS_SUCCESS on success
 */
int wolfSSH_CTX_UseCert_buffer(WOLFSSH_CTX* ctx,
        const byte* cert, word32 certSz, int format)
{
    int ret = WS_SUCCESS;

    WLOG(WS_LOG_DEBUG, "Entering wolfSSH_CTX_UseCert_buffer()");

    ret = wolfSSH_ProcessBuffer(ctx, cert, certSz, format, BUFTYPE_CERT);

    WLOG(WS_LOG_DEBUG, "Leaving wolfSSH_CTX_UseCert_buffer(), ret = %d", ret);
    return ret;
}


/* Add a CA for verifying the peer's certificate with.
 * returns WS_SUCCESS on success
 */
int wolfSSH_CTX_AddRootCert_buffer(WOLFSSH_CTX* ctx,
        const byte* cert, word32 certSz, int format)
{
    int ret = WS_SUCCESS;

    WLOG(WS_LOG_DEBUG, "Entering wolfSSH_CTX_AddRootCert_buffer()");

    ret = wolfSSH_ProcessBuffer(ctx, cert, certSz, format, BUFTYPE_CA);

    WLOG(WS_LOG_DEBUG,
            "Leaving wolfSSH_CTX_AddRootCert_buffer(), ret = %d", ret);
    return ret;
}


#if !defined(NO_FILESYSTEM) && !defined(WOLFSSH_USER_FILESYSTEM)

/* Reads a certificate file and hands the PEM or DER it holds to the CTX. */
static int UseCertFile(WOLFSSH_CTX* ctx, const char* name, int type)
{
    byte* in;
    word32 inSz;
    byte certId = ID_UNKNOWN;
    byte flavor = WOLFSSH_CERT_FLAVOR_UNKNOWN;
    int format;
    int ret;

    if (ctx == NULL || name == NULL) {
        return WS_BAD_ARGUMENT;
    }

    ret = ReadFileIntoBuffer(name, &in, &inSz, ctx->heap);
    if (ret == WS_SUCCESS) {
        format = SniffCertForm(in, inSz, &flavor, &certId);

        if (format < 0) {
            ret = format;
        }
        else if (format == WOLFSSH_FORMAT_SSH) {
            /* A CTX takes the certificate itself, not a public key line. */
            WLOG(WS_LOG_DEBUG, "Certificate file is not PEM or DER");
            ret = WS_BAD_FILETYPE_E;
        }
        else {
            ret = wolfSSH_ProcessBuffer(ctx, in, inSz, format, type);
        }

        WS_FORCEZERO(in, inSz);
        WFREE(in, ctx->heap, DYNTYPE_FILE);
    }

    return ret;
}


/* Load in a X509 certificate file that has public key to use
 * return WS_SUCCESS on success
 */
int wolfSSH_CTX_UseCert_file(WOLFSSH_CTX* ctx, const char* name)
{
    int ret;

    WLOG(WS_LOG_DEBUG, "Entering wolfSSH_CTX_UseCert_file()");

    ret = UseCertFile(ctx, name, BUFTYPE_CERT);

    WLOG(WS_LOG_DEBUG, "Leaving wolfSSH_CTX_UseCert_file(), ret = %d", ret);
    return ret;
}


/* Add a CA file for verifying the peer's certificate with.
 * returns WS_SUCCESS on success
 */
int wolfSSH_CTX_AddRootCert_file(WOLFSSH_CTX* ctx, const char* name)
{
    int ret;

    WLOG(WS_LOG_DEBUG, "Entering wolfSSH_CTX_AddRootCert_file()");

    ret = UseCertFile(ctx, name, BUFTYPE_CA);

    WLOG(WS_LOG_DEBUG,
            "Leaving wolfSSH_CTX_AddRootCert_file(), ret = %d", ret);
    return ret;
}

#endif /* !NO_FILESYSTEM && !WOLFSSH_USER_FILESYSTEM */

#ifdef WOLFSSH_WINDOWS_CERT_STORE
/* Result of CertKeyCanSign(): whether the certificate's private key can
 * actually be used for signing. NONE and NOSIGN are both unusable, but are
 * kept distinct so the final diagnostic can tell an inaccessible key (fix
 * the ACL) from a key enrolled without signing usage (enroll a signing
 * certificate). */
#define WS_CERT_KEY_NONE    0 /* key not acquirable (missing, ACL, CSP) */
#define WS_CERT_KEY_UNKNOWN 1 /* key acquired but usage is not reported */
#define WS_CERT_KEY_SIGNS   2 /* key acquired and reports signing usage */
#define WS_CERT_KEY_NOSIGN  3 /* key acquired, usage excludes signing */

/* Classify the certificate's private key for signing use.
 * CERT_KEY_PROV_INFO_PROP_ID is not enough: it is also set for legacy
 * CryptoAPI/CSP keys, which CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG rejects.
 * Use the same acquisition the signing path performs so a candidate that
 * cannot sign is not chosen. Several smart-card / third-party KSPs do not
 * implement NCRYPT_KEY_USAGE_PROPERTY; those keys are reported as
 * usage-unknown so the caller can rank them below a key that definitely
 * signs instead of failing open on the first one enumerated. */
static int CertKeyCanSign(PCCERT_CONTEXT pCertContext)
{
    HCRYPTPROV_OR_NCRYPT_KEY_HANDLE hKey = 0;
    DWORD dwKeySpec = 0;
    BOOL fCallerFree = FALSE;
    DWORD keyUsage = 0;
    DWORD cbOut = 0;
    SECURITY_STATUS status;
    int canSign = WS_CERT_KEY_SIGNS;

    if (!CryptAcquireCertificatePrivateKey(pCertContext,
            CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG | CRYPT_ACQUIRE_SILENT_FLAG,
            NULL, &hKey, &dwKeySpec, &fCallerFree)) {
        return WS_CERT_KEY_NONE;
    }

    /* CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG means dwKeySpec is documented to
     * always be CERT_NCRYPT_KEY_SPEC; verify before handing the union-typed
     * handle to CNG. A legacy CSP key cannot sign through NCryptSignHash()
     * later, so reject it here rather than misreport it as usable. */
    if (dwKeySpec != CERT_NCRYPT_KEY_SPEC) {
        if (fCallerFree) {
            /* a CSP handle is not an NCRYPT object; release it as a CSP */
            CryptReleaseContext(hKey, 0);
        }
        return WS_CERT_KEY_NONE;
    }

    /* An acquirable key is not necessarily a signing key: an enterprise My
     * store commonly holds a keyEncipherment-only RSA certificate next to
     * the signing one with the same CN. Require NCRYPT_ALLOW_SIGNING_FLAG
     * when the provider exposes the usage property. */
    status = NCryptGetProperty(hKey, NCRYPT_KEY_USAGE_PROPERTY,
            (PBYTE)&keyUsage, (DWORD)sizeof(keyUsage), &cbOut, 0);
    if (status == 0 && cbOut == (DWORD)sizeof(keyUsage)) {
        if ((keyUsage & NCRYPT_ALLOW_SIGNING_FLAG) == 0) {
            WLOG(WS_LOG_DEBUG, "CertKeyCanSign: key usage 0x%lx does not "
                    "allow signing", (unsigned long)keyUsage);
            canSign = WS_CERT_KEY_NOSIGN;
        }
    }
    else {
        WLOG(WS_LOG_DEBUG, "CertKeyCanSign: NCRYPT_KEY_USAGE_PROPERTY not "
                "readable (status 0x%lx), key usage unknown",
                (unsigned long)status);
        canSign = WS_CERT_KEY_UNKNOWN;
    }

    if (fCallerFree) {
        /* Only NCRYPT keys reach this point; a CSP key was released and
         * rejected right after acquisition. */
        NCryptFreeObject(hKey);
    }

    return canSign;
}


/* Find the certificate in hStore whose Common Name matches subjectName.
 * subjectName may include a leading "CN=" prefix.
 * CERT_FIND_SUBJECT_STR_W is only used as a substring pre-filter to
 * enumerate candidates; each candidate's CN is then compared in full so
 * that a lookup for "server1" does not select "server1.example" or
 * "myserver1". The compare is ordinal and case insensitive, so it cannot
 * change with the thread locale. Candidates are ranked by how usable they
 * are: time-valid whose key definitely signs first, then time-valid whose
 * provider does not report key usage, then (only when
 * WOLFSSH_CERT_STORE_ALLOW_EXPIRED is defined) expired over not yet
 * valid, then the latest NotAfter. Without that opt-in, a match that is
 * not time-valid fails with WS_CERT_EXPIRED_E rather than silently
 * presenting an expired credential. A candidate with no usable key is
 * never selected -- the caller repeats the same key acquisition and would
 * only fail with a misleading error -- so a public-only duplicate neither
 * ends the search nor is returned. The selected certificate is stored in
 * out, and is NULL when no match exists. The caller frees it with
 * CertFreeCertificateContext.
 * Returns WS_SUCCESS on success, WS_CRYPTO_FAILED when the CN matched
 * only certificates whose private key is not accessible. */
static int FindCertByExactCN(void* heap, HCERTSTORE hStore,
        const wchar_t* subjectName, PCCERT_CONTEXT* out)
{
    PCCERT_CONTEXT pCertContext;
    PCCERT_CONTEXT keyedMatch;
    PCCERT_CONTEXT validUnknown;
    const wchar_t* cn;
    wchar_t* certCn;
    DWORD certCnSz;
    int match;
    int hasKey;
    int timeValidity;
    int keyedEarly;
    int keyedSigns;
    int keylessSeen;
    int nosignSeen;
    int better;
    int ret;

    *out = NULL;
    ret = WS_SUCCESS;
    keyedEarly = 0;
    keyedSigns = 0;
    keylessSeen = 0;
    nosignSeen = 0;
    validUnknown = NULL;

    /* Strip an optional "CN=" prefix from the requested name. */
    cn = subjectName;
    if (wcslen(cn) >= 3 &&
            CompareStringOrdinal(cn, 3, L"CN=", 3, TRUE) == CSTR_EQUAL) {
        cn = cn + 3;
    }
    if (*cn == L'\0') {
        WLOG(WS_LOG_ERROR, "FindCertByExactCN: Empty common name requested");
        return WS_BAD_ARGUMENT;
    }

    pCertContext = NULL;
    keyedMatch = NULL;
    for (;;) {
        /* Passing the previous context frees it and continues the search. */
        pCertContext = CertFindCertificateInStore(hStore,
                X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                0, CERT_FIND_SUBJECT_STR_W, cn, pCertContext);
        if (pCertContext == NULL) {
            break;
        }
        certCnSz = CertGetNameStringW(pCertContext, CERT_NAME_ATTR_TYPE, 0,
                (void*)szOID_COMMON_NAME, NULL, 0);
        if (certCnSz <= 1) {
            continue;
        }
        certCn = (wchar_t*)WMALLOC(certCnSz * sizeof(wchar_t), heap,
                DYNTYPE_TEMP);
        if (certCn == NULL) {
            CertFreeCertificateContext(pCertContext);
            pCertContext = NULL;
            ret = WS_MEMORY_E;
            break;
        }
        certCnSz = CertGetNameStringW(pCertContext, CERT_NAME_ATTR_TYPE, 0,
                (void*)szOID_COMMON_NAME, certCn, certCnSz);
        match = (certCnSz > 1 &&
                CompareStringOrdinal(certCn, -1, cn, -1, TRUE) == CSTR_EQUAL);
        WFREE(certCn, heap, DYNTYPE_TEMP);
        if (!match) {
            continue;
        }

        /* A duplicate that cannot sign must not end the search.
         * CertVerifyTimeValidity returns -1 before the validity period and
         * +1 after it. */
        hasKey = CertKeyCanSign(pCertContext);
        timeValidity = CertVerifyTimeValidity(NULL, pCertContext->pCertInfo);
        if (hasKey == WS_CERT_KEY_SIGNS && timeValidity == 0) {
            break;
        }

        if (hasKey == WS_CERT_KEY_UNKNOWN && timeValidity == 0) {
            /* Time-valid but the provider does not report key usage: keep
             * the first one as a candidate and keep searching for a
             * sibling that definitely signs, so an encryption-only key in
             * a usage-silent KSP cannot shadow the signing one. */
            if (validUnknown == NULL) {
                validUnknown = CertDuplicateCertificateContext(pCertContext);
                if (validUnknown == NULL) {
                    ret = WS_MEMORY_E;
                }
            }
        }
        else if (hasKey == WS_CERT_KEY_SIGNS ||
                hasKey == WS_CERT_KEY_UNKNOWN) {
            /* Deterministic fallback ranking, matching the time-valid path:
             * a key that definitely signs beats one whose usage is unknown,
             * then expired beats not yet valid, and within the same class
             * the latest NotAfter wins. */
            better = 0;
            if (keyedMatch == NULL) {
                better = 1;
            }
            else if (keyedSigns != (hasKey == WS_CERT_KEY_SIGNS)) {
                better = (hasKey == WS_CERT_KEY_SIGNS);
            }
            else if (keyedEarly && timeValidity > 0) {
                better = 1;
            }
            else if (keyedEarly == (timeValidity < 0) &&
                    CompareFileTime(&pCertContext->pCertInfo->NotAfter,
                        &keyedMatch->pCertInfo->NotAfter) > 0) {
                better = 1;
            }
            if (better) {
                if (keyedMatch != NULL) {
                    CertFreeCertificateContext(keyedMatch);
                }
                keyedMatch = CertDuplicateCertificateContext(pCertContext);
                keyedEarly = (timeValidity < 0);
                keyedSigns = (hasKey == WS_CERT_KEY_SIGNS);
                if (keyedMatch == NULL) {
                    ret = WS_MEMORY_E;
                }
            }
        }
        else if (hasKey == WS_CERT_KEY_NOSIGN) {
            nosignSeen = 1;
        }
        else {
            keylessSeen = 1;
        }

        if (ret != WS_SUCCESS) {
            CertFreeCertificateContext(pCertContext);
            pCertContext = NULL;
            break;
        }
    }

    /* An allocation failure is reported as such rather than falling back
     * to a candidate the enumeration had already rejected. */
    if (ret == WS_SUCCESS && pCertContext == NULL) {
        if (validUnknown != NULL) {
            WLOG(WS_LOG_INFO, "FindCertByExactCN: No candidate reports "
                    "signing usage; using a time-valid '%ls' whose key "
                    "usage is unknown", subjectName);
            pCertContext = validUnknown;
            validUnknown = NULL;
        }
        else if (keyedMatch != NULL) {
#ifdef WOLFSSH_CERT_STORE_ALLOW_EXPIRED
            /* WS_LOG_ERROR so the fallback is as visible as logging in
             * this build allows; still only compiled in when logging is. */
            WLOG(WS_LOG_ERROR, "FindCertByExactCN: No time-valid match, using "
                    "a %s '%ls' that has a private key",
                    keyedEarly ? "not yet valid" : "expired", subjectName);
            pCertContext = keyedMatch;
            keyedMatch = NULL;
#else
            /* Fail closed by default: in a non-logging build a silent
             * fallback would present an expired host credential with
             * WS_SUCCESS and no local indication of the cause. Define
             * WOLFSSH_CERT_STORE_ALLOW_EXPIRED to opt into the old
             * behavior. */
            WLOG(WS_LOG_ERROR, "FindCertByExactCN: '%ls' matched only a %s "
                    "certificate; rejecting (define "
                    "WOLFSSH_CERT_STORE_ALLOW_EXPIRED to use it anyway)",
                    subjectName, keyedEarly ? "not yet valid" : "expired");
            ret = WS_CERT_EXPIRED_E;
#endif
        }
        else if (keylessSeen) {
            WLOG(WS_LOG_ERROR, "FindCertByExactCN: '%ls' matched only "
                    "certificates with no usable private key", subjectName);
            ret = WS_CRYPTO_FAILED;
        }
        else if (nosignSeen) {
            WLOG(WS_LOG_ERROR, "FindCertByExactCN: '%ls' matched only "
                    "certificates whose private key is not a signing key; "
                    "enroll a signing certificate", subjectName);
            ret = WS_CRYPTO_FAILED;
        }
    }
    if (keyedMatch != NULL) {
        CertFreeCertificateContext(keyedMatch);
    }
    if (validUnknown != NULL) {
        CertFreeCertificateContext(validUnknown);
    }

    if (ret != WS_SUCCESS) {
        if (pCertContext != NULL) {
            CertFreeCertificateContext(pCertContext);
        }
        WLOG(WS_LOG_ERROR, "FindCertByExactCN: Failed, ret = %d", ret);
    }
    else {
        *out = pCertContext;
    }

    return ret;
}


/* Resources for one cert-store backed private key slot. Everything is
 * allocated before any slot is modified so that registering the plain key
 * type and the matching X.509 type is all or nothing. */
typedef struct CertStoreSlot {
    PCCERT_CONTEXT context;
    byte*  cert;
    word32 certSz;
    word32 keyIdx;
    byte   keyId;
} CertStoreSlot;


/* Release resources of a slot that was prepared but never committed. */
static void FreeCertStoreSlot(void* heap, CertStoreSlot* slot)
{
    if (slot->context != NULL) {
        CertFreeCertificateContext(slot->context);
    }
    if (slot->cert != NULL) {
        WFREE(slot->cert, heap, DYNTYPE_CERT);
    }
    WMEMSET(slot, 0, sizeof(*slot));
}


/* Allocate the resources slot keyIdx needs, without modifying the
 * context. The slot takes its own reference on pCertContext and its own
 * copy of the certificate DER so that every slot can be freed
 * independently by CtxResourceFree.
 * Returns WS_SUCCESS on success. */
static int PrepCertStoreSlot(void* heap, byte keyId, word32 keyIdx,
        PCCERT_CONTEXT pCertContext, CertStoreSlot* slot)
{
    /* Validating the index here, before anything is mutated, is what lets
     * CommitCertStoreSlot() be infallible. */
    if (keyIdx >= WOLFSSH_MAX_PVT_KEYS) {
        WLOG(WS_LOG_ERROR, "PrepCertStoreSlot: Slot index out of range");
        return WS_BAD_ARGUMENT;
    }

    /* A zero-length certificate would be committed to the slot and later
     * advertised as an x509v3 host key with an empty K_S. */
    if (pCertContext->pbCertEncoded == NULL
            || pCertContext->cbCertEncoded == 0) {
        WLOG(WS_LOG_ERROR, "PrepCertStoreSlot: Store certificate is empty");
        return WS_BAD_ARGUMENT;
    }

    WMEMSET(slot, 0, sizeof(*slot));
    slot->keyId = keyId;
    slot->keyIdx = keyIdx;
    slot->certSz = pCertContext->cbCertEncoded;

    slot->cert = (byte*)WMALLOC(slot->certSz, heap, DYNTYPE_CERT);
    slot->context = CertDuplicateCertificateContext(pCertContext);
    if (slot->cert == NULL || slot->context == NULL) {
        FreeCertStoreSlot(heap, slot);
        WLOG(WS_LOG_ERROR, "PrepCertStoreSlot: Memory allocation failed");
        return WS_MEMORY_E;
    }
    WMEMCPY(slot->cert, pCertContext->pbCertEncoded, slot->certSz);

    return WS_SUCCESS;
}


/* Move the prepared resources into the context. The slot may previously
 * have held either a cert-store key or a file-based key/cert, so clear
 * both kinds of resources. Infallible by design: PrepCertStoreSlot()
 * validates the slot index before anything is prepared, which is what
 * makes the two-slot commit in wolfSSH_CTX_UsePrivateKey_fromStore()
 * all-or-nothing. */
static void CommitCertStoreSlot(WOLFSSH_CTX* ctx, CertStoreSlot* slot)
{
    WOLFSSH_PVT_KEY* pvtKey;
    void* heap;

    heap = ctx->heap;
    pvtKey = &ctx->privateKey[slot->keyIdx];

    if (pvtKey->certStoreContext != NULL) {
        CertFreeCertificateContext(
                (PCCERT_CONTEXT)pvtKey->certStoreContext);
    }
    if (pvtKey->key != NULL) {
        /* Defensive only: wolfSSH_CTX_UsePrivateKey_fromStore() rejects a
         * slot holding file-based credentials before preparing it, the
         * same way SetHostPrivateKey() rejects the mirror-image order. */
        WLOG(WS_LOG_ERROR, "CommitCertStoreSlot: Replacing the file-based "
             "host key for this algorithm with the certificate store key");
        WS_FORCEZERO(pvtKey->key, pvtKey->keySz);
        WFREE(pvtKey->key, heap, DYNTYPE_PRIVKEY);
        pvtKey->key = NULL;
        pvtKey->keySz = 0;
    }
    if (pvtKey->cert != NULL) {
        WFREE(pvtKey->cert, heap, DYNTYPE_CERT);
    }

    pvtKey->publicKeyFmt     = slot->keyId;
#ifdef WOLFSSH_TPM
    /* A stale TPM mark would route signing through the TPM. */
    pvtKey->isTpm            = 0;
#endif
    pvtKey->useCertStore     = 1;
    pvtKey->certStoreContext = (void*)slot->context;
    pvtKey->cert             = slot->cert;
    pvtKey->certSz           = slot->certSz;

    /* Ownership moved to the context. */
    WMEMSET(slot, 0, sizeof(*slot));
}


#ifndef WOLFSSH_NO_ECDSA
/* DER-encoded named-curve OIDs as they appear in a certificate's
 * SubjectPublicKeyInfo algorithm parameters. */
#ifndef WOLFSSH_NO_ECDSA_SHA2_NISTP256
static const byte certStoreOidP256[] = {
    0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07
};
#endif
#ifndef WOLFSSH_NO_ECDSA_SHA2_NISTP384
static const byte certStoreOidP384[] = {
    0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22
};
#endif
#ifndef WOLFSSH_NO_ECDSA_SHA2_NISTP521
static const byte certStoreOidP521[] = {
    0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x23
};
#endif
#endif /* WOLFSSH_NO_ECDSA */


/* Load a private key from MS Certificate Store
 * storeName: Certificate store name (e.g., L"My", L"Root")
 * dwFlags: Certificate store location, and only a location (e.g.
 *     CERT_SYSTEM_STORE_CURRENT_USER). Control flags such as
 *     CERT_STORE_DELETE_FLAG would make CertOpenStore destructive and are
 *     rejected. The store is opened read-only.
 * subjectName: Certificate subject Common Name for lookup, with or without
 *     a "CN=" prefix. The CN must match in full, case insensitively;
 *     thumbprint lookup is not currently implemented.
 * The key is registered both as its plain key type and, mirroring the
 * file-based HostKey plus HostCertificate pairing, as the matching
 * RFC6187 x509v3-* type so the store certificate itself can be sent as
 * the public host key to peers that negotiate certificate algorithms.
 * The x509v3-* registration is skipped when the build compiles out the
 * x509v3 algorithm for the key type (WOLFSSH_NO_SSH_RSA_SHA1, per-curve
 * ECDSA gates) and for RSA when SHA-1 is soft disabled, since
 * x509v3-ssh-rsa signs with SHA-1 and is then never advertised.
 * returns WS_SUCCESS on success
 */
int wolfSSH_CTX_UsePrivateKey_fromStore(WOLFSSH_CTX* ctx,
        const wchar_t* storeName, word32 dwFlags,
        const wchar_t* subjectName)
{
    int ret = WS_SUCCESS;
    HCERTSTORE hStore = NULL;
    PCCERT_CONTEXT pCertContext = NULL;
    byte keyId = ID_NONE;
    byte certId = ID_NONE;
    PCERT_PUBLIC_KEY_INFO pPubKeyInfo = NULL;
    CertStoreSlot keySlot;
    CertStoreSlot certSlot;
    word32 keyIdx;
    word32 certIdx;
    word32 newCount;
    byte   haveCertSlot;
#ifndef WOLFSSH_NO_ECDSA
    const byte* params = NULL;
    DWORD paramsSz = 0;
#endif

    WLOG(WS_LOG_DEBUG, "Entering wolfSSH_CTX_UsePrivateKey_fromStore()");

    if (ctx == NULL || storeName == NULL || subjectName == NULL) {
        WLOG(WS_LOG_DEBUG, "wolfSSH_CTX_UsePrivateKey_fromStore: Bad argument");
        return WS_BAD_ARGUMENT;
    }

    /* Only accept an assigned system-store location. Anything else is
     * either not a location or a control flag (e.g. CERT_STORE_DELETE_FLAG)
     * that would make CertOpenStore destructive. */
    if (!wolfSSH_CertStoreLocationValid(dwFlags)) {
        WLOG(WS_LOG_ERROR, "wolfSSH_CTX_UsePrivateKey_fromStore: Store "
             "flags are not a system store location");
        return WS_BAD_ARGUMENT;
    }

    /* Open the certificate store. Read-only, both because nothing here
     * writes to it and because a read/write open of a LOCAL_MACHINE store
     * fails for a non-administrator service account. */
    hStore = CertOpenStore(CERT_STORE_PROV_SYSTEM_W, 0, (HCRYPTPROV_LEGACY)0,
            (DWORD)dwFlags | CERT_STORE_OPEN_EXISTING_FLAG
            | CERT_STORE_READONLY_FLAG, storeName);
    if (hStore == NULL) {
        WLOG(WS_LOG_ERROR, "wolfSSH_CTX_UsePrivateKey_fromStore: Failed to "
             "open store, error: %lu", (unsigned long)GetLastError());
        return WS_BAD_FILE_E;
    }

    /* Find the certificate by full Common Name match. */
    ret = FindCertByExactCN(ctx->heap, hStore, subjectName, &pCertContext);
    if (ret == WS_CRYPTO_FAILED) {
        CertCloseStore(hStore, 0);
        WLOG(WS_LOG_ERROR, "wolfSSH_CTX_UsePrivateKey_fromStore: Certificate "
             "matched but its private key is not usable for signing; see "
             "the FindCertByExactCN message above for whether the key is "
             "inaccessible (check key permissions for the service account) "
             "or enrolled without signing usage");
        return WS_CRYPTO_FAILED;
    }
    if (ret != WS_SUCCESS) {
        CertCloseStore(hStore, 0);
        return ret;
    }
    if (pCertContext == NULL) {
        CertCloseStore(hStore, 0);
        WLOG(WS_LOG_ERROR, "wolfSSH_CTX_UsePrivateKey_fromStore: Certificate "
             "not found with subject '%ls'", subjectName);
        return WS_FATAL_ERROR;
    }

    /* Determine key type from certificate */
    /* Get the public key info to determine algorithm */
    pPubKeyInfo = &pCertContext->pCertInfo->SubjectPublicKeyInfo;

    /* Check algorithm OID to determine key type. Only algorithms and
     * curves compiled into this build are accepted; anything else leaves
     * keyId as ID_NONE and is rejected below rather than registering a
     * host key type that cannot be used for signing. */
    if (pPubKeyInfo->Algorithm.pszObjId != NULL) {
        /* Compare OID strings (they are ASCII, not wide) */
        if (WSTRCMP(pPubKeyInfo->Algorithm.pszObjId, szOID_RSA_RSA) == 0) {
        /* An RSA slot is useless without an RSA signature algorithm to
         * negotiate, so require one the way wolfSSH_CTX_UseTpmHostKey does
         * rather than consuming a slot RefreshPublicKeyAlgo will not
         * advertise. */
        #if !defined(WOLFSSH_NO_RSA) && \
            (!defined(WOLFSSH_NO_RSA_SHA2_256) || \
             !defined(WOLFSSH_NO_RSA_SHA2_512) || \
             (defined(WOLFSSH_NO_SHA1_SOFT_DISABLE) && \
              !defined(WOLFSSH_NO_SSH_RSA_SHA1)))
            keyId = ID_SSH_RSA;
        #else
            WLOG(WS_LOG_ERROR, "wolfSSH_CTX_UsePrivateKey_fromStore: "
                "No usable RSA signature algorithm is compiled in");
        #endif
        }
        else if (WSTRCMP(pPubKeyInfo->Algorithm.pszObjId,
                    szOID_ECC_PUBLIC_KEY) == 0) {
        #ifndef WOLFSSH_NO_ECDSA
            /* The algorithm parameters hold the DER-encoded named-curve
             * OID; match its raw bytes to select the ECDSA key type. */
            params   = pPubKeyInfo->Algorithm.Parameters.pbData;
            paramsSz = pPubKeyInfo->Algorithm.Parameters.cbData;

            if (params == NULL) {
                paramsSz = 0;
            }
        #ifndef WOLFSSH_NO_ECDSA_SHA2_NISTP256
            if (paramsSz == sizeof(certStoreOidP256) &&
                    WMEMCMP(params, certStoreOidP256,
                        sizeof(certStoreOidP256)) == 0) {
                keyId = ID_ECDSA_SHA2_NISTP256;
            }
            else
        #endif
        #ifndef WOLFSSH_NO_ECDSA_SHA2_NISTP384
            if (paramsSz == sizeof(certStoreOidP384) &&
                    WMEMCMP(params, certStoreOidP384,
                        sizeof(certStoreOidP384)) == 0) {
                keyId = ID_ECDSA_SHA2_NISTP384;
            }
            else
        #endif
        #ifndef WOLFSSH_NO_ECDSA_SHA2_NISTP521
            if (paramsSz == sizeof(certStoreOidP521) &&
                    WMEMCMP(params, certStoreOidP521,
                        sizeof(certStoreOidP521)) == 0) {
                keyId = ID_ECDSA_SHA2_NISTP521;
            }
            else
        #endif
            {
                /* With all curves disabled paramsSz is set but never read. */
                WOLFSSH_UNUSED(paramsSz);
                WLOG(WS_LOG_ERROR, "wolfSSH_CTX_UsePrivateKey_fromStore: "
                    "Unsupported ECC curve parameters");
            }
        #else
            WLOG(WS_LOG_ERROR, "wolfSSH_CTX_UsePrivateKey_fromStore: "
                "ECDSA is not compiled in");
        #endif /* WOLFSSH_NO_ECDSA */
        }
        else {
            WLOG(WS_LOG_ERROR, "wolfSSH_CTX_UsePrivateKey_fromStore: "
                "Unsupported key algorithm: %s",
                pPubKeyInfo->Algorithm.pszObjId);
        }
    }
    else {
        WLOG(WS_LOG_ERROR,
            "wolfSSH_CTX_UsePrivateKey_fromStore: No algorithm OID");
    }

    if (keyId == ID_NONE) {
        CertFreeCertificateContext(pCertContext);
        CertCloseStore(hStore, 0);
        return WS_BAD_ARGUMENT;
    }

    /* FindCertByExactCN only returns a certificate whose private key
     * CertKeyCanSign() could acquire, so key access is already verified. */

    /* Register the key under its plain type so peers without RFC6187
     * support get a raw public key, and under the matching X.509 type so
     * the store certificate can be sent as K_S when a peer negotiates an
     * x509v3-* algorithm. Both slots are located and prepared before
     * either is committed, so a failure leaves the context, including any
     * host key already in these slots, exactly as it was. */
    WMEMSET(&keySlot, 0, sizeof(keySlot));
    WMEMSET(&certSlot, 0, sizeof(certSlot));
    newCount = ctx->privateKeyCount;
    keyIdx = FindPvtKeyIdx(ctx, keyId);
    /* Mirror of SetHostPrivateKey()/SetHostCertificate(): a store key must
     * not silently replace file- or TPM-based credentials already loaded
     * for this algorithm, so the mixed configuration is rejected in both
     * load orders. Replacing a previous store key is still allowed. */
    if (keyIdx != WOLFSSH_MAX_PVT_KEYS &&
            !ctx->privateKey[keyIdx].useCertStore) {
        WLOG(WS_LOG_ERROR, "wolfSSH_CTX_UsePrivateKey_fromStore: A host key "
             "for this algorithm is already loaded from a file or TPM; it "
             "cannot be paired with a store key");
        CertFreeCertificateContext(pCertContext);
        CertCloseStore(hStore, 0);
        return WS_BAD_ARGUMENT;
    }
    if (keyIdx == WOLFSSH_MAX_PVT_KEYS) {
        keyIdx = newCount++;
    }

    /* CertTypeForId returns keyId unchanged when the build has no X509
     * equivalent; skip the X509 ID slot in that case. haveCertSlot rather
     * than a certIdx sentinel, so the "skip" marker cannot be confused with
     * an index a full table legitimately computes. */
    certId = CertTypeForId(keyId);
#if !defined(WOLFSSH_NO_SHA1_SOFT_DISABLE)
    /* x509v3-ssh-rsa signs with SHA-1; with SHA-1 soft disabled do not
     * register a slot for it. Note the canned lists only gate the client
     * default; a server would advertise the slot via RefreshPublicKeyAlgo,
     * which is exactly why it must not be registered. If an earlier
     * file-based load already claimed that slot, reject the mixed
     * configuration outright rather than leaving a stale file key and
     * certificate advertised beside the store key. */
    if (certId == ID_X509V3_SSH_RSA) {
        if (FindPvtKeyIdx(ctx, certId) != WOLFSSH_MAX_PVT_KEYS) {
            WLOG(WS_LOG_ERROR, "wolfSSH_CTX_UsePrivateKey_fromStore: An "
                 "x509v3-ssh-rsa file host key/certificate is already "
                 "loaded; it cannot be paired with a store key");
            CertFreeCertificateContext(pCertContext);
            CertCloseStore(hStore, 0);
            return WS_BAD_ARGUMENT;
        }
        certId = keyId;
    }
#endif
    certIdx = 0;
    haveCertSlot = 0;
    if (certId != keyId) {
        certIdx = FindPvtKeyIdx(ctx, certId);
        /* Same mixed-configuration rejection for the x509v3 slot, so a
         * file HostCertificate is never silently destroyed either. */
        if (certIdx != WOLFSSH_MAX_PVT_KEYS &&
                !ctx->privateKey[certIdx].useCertStore) {
            WLOG(WS_LOG_ERROR, "wolfSSH_CTX_UsePrivateKey_fromStore: A host "
                 "certificate for this algorithm is already loaded from a "
                 "file; it cannot be paired with a store key");
            CertFreeCertificateContext(pCertContext);
            CertCloseStore(hStore, 0);
            return WS_BAD_ARGUMENT;
        }
        if (certIdx == WOLFSSH_MAX_PVT_KEYS) {
            certIdx = newCount++;
        }
        haveCertSlot = 1;
    }
    else {
        WLOG(WS_LOG_INFO, "wolfSSH_CTX_UsePrivateKey_fromStore: No x509v3 "
             "algorithm for key type %d in this build, registering the "
             "plain host key only", keyId);
    }

    if (newCount > WOLFSSH_MAX_PVT_KEYS) {
        WLOG(WS_LOG_ERROR, "wolfSSH_CTX_UsePrivateKey_fromStore: Not enough "
             "free key slots; a store key needs one for the plain type and "
             "one for the x509v3 type");
        ret = WS_CTX_KEY_COUNT_E;
    }
    if (ret == WS_SUCCESS) {
        ret = PrepCertStoreSlot(ctx->heap, keyId, keyIdx, pCertContext,
                &keySlot);
    }
    if (ret == WS_SUCCESS && haveCertSlot) {
        ret = PrepCertStoreSlot(ctx->heap, certId, certIdx, pCertContext,
                &certSlot);
    }

    if (ret == WS_SUCCESS) {
        /* Committing cannot fail (see CommitCertStoreSlot), so once both
         * slots are prepared the context update is atomic from the caller's
         * point of view. */
        CommitCertStoreSlot(ctx, &keySlot);
        if (haveCertSlot) {
            CommitCertStoreSlot(ctx, &certSlot);
        }
        ctx->privateKeyCount = newCount;
    }
    else {
        FreeCertStoreSlot(ctx->heap, &keySlot);
        FreeCertStoreSlot(ctx->heap, &certSlot);
    }

    /* Each registered slot holds its own reference on the certificate
     * context for later signing operations, so release the lookup
     * reference from CertFindCertificateInStore. Closing the store does
     * not invalidate the slot contexts.
     * Note: if the certificate is removed from the store while we hold
     * these contexts, CryptAcquireCertificatePrivateKey may fail at
     * signing time. */
    CertFreeCertificateContext(pCertContext);
    CertCloseStore(hStore, 0);

    if (ret == WS_SUCCESS) {
        /* Refresh public key algorithm list */
        RefreshPublicKeyAlgo(ctx);
    }

    WLOG(WS_LOG_DEBUG, "Leaving wolfSSH_CTX_UsePrivateKey_fromStore(), "
         "ret = %d", ret);
    return ret;
}


/* Report the certificate a cert-store host key is bound to, so an
 * application can offer it for certificate user auth without reaching into
 * the private CTX layout. Returns the first cert-store backed slot
 * registered under an x509v3 algorithm: cert/certSz point at the DER copy
 * owned by the CTX (valid until the CTX is freed or the slot replaced) and
 * algoName at the static SSH algorithm name string. Any out pointer may be
 * NULL to skip it. Returns WS_SUCCESS, WS_BAD_ARGUMENT on a NULL ctx, or
 * WS_FATAL_ERROR when no such slot exists (e.g. the x509v3 form of the key
 * type is compiled out or soft disabled). */
int wolfSSH_CTX_GetCertStoreCert(WOLFSSH_CTX* ctx, const byte** cert,
        word32* certSz, const char** algoName)
{
    const WOLFSSH_PVT_KEY* pvtKey;
    word32 i;
    int isX509Id;

    if (ctx == NULL) {
        return WS_BAD_ARGUMENT;
    }

    for (i = 0; i < ctx->privateKeyCount && i < WOLFSSH_MAX_PVT_KEYS; i++) {
        pvtKey = &ctx->privateKey[i];
        if (!pvtKey->useCertStore || pvtKey->certStoreContext == NULL ||
                pvtKey->key != NULL ||
                pvtKey->cert == NULL || pvtKey->certSz == 0) {
            continue;
        }
        switch (pvtKey->publicKeyFmt) {
            case ID_X509V3_SSH_RSA:
            case ID_X509V3_ECDSA_SHA2_NISTP256:
            case ID_X509V3_ECDSA_SHA2_NISTP384:
            case ID_X509V3_ECDSA_SHA2_NISTP521:
                isX509Id = 1;
                break;
            default:
                isX509Id = 0;
                break;
        }
        if (!isX509Id) {
            continue;
        }
        if (cert != NULL) {
            *cert = pvtKey->cert;
        }
        if (certSz != NULL) {
            *certSz = pvtKey->certSz;
        }
        if (algoName != NULL) {
            *algoName = IdToName(pvtKey->publicKeyFmt);
        }
        return WS_SUCCESS;
    }

    return WS_FATAL_ERROR;
}
#endif /* WOLFSSH_WINDOWS_CERT_STORE */
#endif /* WOLFSSH_CERTS */


int wolfSSH_CTX_SetWindowPacketSize(WOLFSSH_CTX* ctx,
                                    word32 windowSz, word32 maxPacketSz)
{
    WLOG(WS_LOG_DEBUG, "Entering wolfSSH_CTX_SetWindowPacketSize()");

    if (ctx == NULL)
        return WS_BAD_ARGUMENT;

    if (windowSz != 0 && windowSz > WINDOW_SZ_UPPER_BOUND)
        return WS_BAD_ARGUMENT;
    if (windowSz == 0)
        windowSz = DEFAULT_WINDOW_SZ;
    if (maxPacketSz != 0 && maxPacketSz > MAX_CHANNEL_PACKET_SZ)
        return WS_BAD_ARGUMENT;
    if (maxPacketSz == 0)
        maxPacketSz = DEFAULT_MAX_PACKET_SZ;

    ctx->windowSz = windowSz;
    ctx->maxPacketSz = maxPacketSz;

    return WS_SUCCESS;
}


void wolfSSH_GetStats(WOLFSSH* ssh, word32* txCount, word32* rxCount,
                      word32* seq, word32* peerSeq)
{
    word32 rTxCount = 0;
    word32 rRxCount = 0;
    word32 rSeq = 0;
    word32 rPeerSeq = 0;

    if (ssh != NULL) {
        rTxCount = ssh->txCount;
        rRxCount = ssh->rxCount;
        rSeq = ssh->seq;
        rPeerSeq = ssh->peerSeq;
    }

    if (txCount != NULL)
        *txCount = rTxCount;
    if (rxCount != NULL)
        *rxCount = rRxCount;
    if (seq != NULL)
        *seq = rSeq;
    if (peerSeq != NULL)
        *peerSeq = rPeerSeq;
}


int wolfSSH_KDF(byte hashId, byte keyId,
                byte* key, word32 keySz,
                const byte* k, word32 kSz,
                const byte* h, word32 hSz,
                const byte* sessionId, word32 sessionIdSz)
{
    int doKeyPadding = 1;
    WLOG(WS_LOG_DEBUG, "Entering wolfSSH_KDF()");
    return GenerateKey(hashId, keyId, key, keySz, k, kSz, h, hSz,
                       sessionId, sessionIdSz, doKeyPadding);
}


WS_SessionType wolfSSH_GetSessionType(const WOLFSSH* ssh)
{
    WLOG(WS_LOG_DEBUG, "Entering wolfSSH_GetSessionType()");

    if (ssh && ssh->channelList)
        return (WS_SessionType)ssh->channelList->sessionType;

    return WOLFSSH_SESSION_UNKNOWN;
}


const char* wolfSSH_GetSessionCommand(const WOLFSSH* ssh)
{
    WLOG(WS_LOG_DEBUG, "Entering wolfSSH_GetSessionCommand()");

    if (ssh && ssh->channelList)
        return ssh->channelList->command;

    return NULL;
}


int wolfSSH_worker(WOLFSSH* ssh, word32* channelId)
{
    int ret = WS_SUCCESS;

    WLOG(WS_LOG_DEBUG, "Entering wolfSSH_worker()");

    if (ssh == NULL)
        ret = WS_BAD_ARGUMENT;

    /* Nothing left to drive: no reply may go out and inbound messages are
     * skipped, so every pass from here on would answer WS_SUCCESS off a
     * dispatch that did nothing and a caller turning the crank would never
     * see the session end. What arrived before the disconnect is still the
     * caller's, through the read calls. RFC 4253 section 11.1. */
    if (ret == WS_SUCCESS && SendAfterDisconnect(ssh)) {
        WLOG(WS_LOG_DEBUG, "Leaving wolfSSH_worker(), session disconnected");
        return WS_FATAL_ERROR;
    }

#ifdef WOLFSSH_TEST_BLOCK
    /* In forced non-blocking test mode, keep legacy ordering (send before
     * receive) to match the harness expectations and avoid synthetic spins. */
    if (ret == WS_SUCCESS) {
        if (ssh->outputBuffer.length != 0)
            ret = wolfSSH_SendPacket(ssh);
    }
    if (ret == WS_SUCCESS)
        ret = DoReceive(ssh);
#else
    /* Always service inbound data first so window updates can unblock sends. */
    if (ret == WS_SUCCESS) {
        ret = DoReceive(ssh);
    }

    /* If receive only wanted read or delivered channel data, still try to
     * flush any pending outbound packets. */
    if (ret == WS_SUCCESS || ret == WS_WANT_READ || ret == WS_CHAN_RXD
            || ret == WS_EOF) {
        int sendRet = WS_SUCCESS;

        if (ssh->outputBuffer.length != 0)
            sendRet = wolfSSH_SendPacket(ssh);

        /* If send is back-pressured, immediately try another receive to pick
         * up potential window-adjusts and then return the send status. The
         * send status wins; a peer EOF stays latched on the channel. */
        if (sendRet == WS_WANT_WRITE || sendRet == WS_WINDOW_FULL) {
            int recv2 = DoReceive(ssh);
            if (recv2 == WS_SUCCESS || recv2 == WS_WANT_READ || recv2 == WS_CHAN_RXD
                    || recv2 == WS_EOF)
                ret = sendRet;
            else
                ret = recv2;
        }
        else {
            /* Preserve meaningful receive status when send succeeded. */
            if (sendRet != WS_SUCCESS)
                ret = sendRet;
            /* else leave ret as prior receive result (SUCCESS/WANT_READ/CHAN_RXD). */
        }
    }
#endif /* WOLFSSH_TEST_BLOCK */

    /* DoChannelClose() bundles the reply inside DoReceive(), and callers
     * treat the close as terminal, so flush it here. The close stays the
     * return value; a short flush leaves WS_WANT_WRITE latched. */
    if (ret == WS_CHANNEL_CLOSED && ssh->outputBuffer.length != 0) {
        int closeErr = ssh->error;

        if (wolfSSH_SendPacket(ssh) == WS_SUCCESS)
            ssh->error = closeErr;
    }

    /* WS_EXTDATA and WS_EOF report the channel too, so a multi-channel caller
     * can route the drain, or see which channel half-closed. */
    if (ret == WS_SUCCESS || ret == WS_CHAN_RXD || ret == WS_EXTDATA
            || ret == WS_EOF) {
        if (channelId != NULL) {
            *channelId = ssh->lastRxId;
        }

        /* WS_EXTDATA and WS_EOF are raised once, on arrival; masking either
         * strands the event, and the stderr window credit with it. A
         * disconnect cannot be seen here: the gate at the top returns before
         * this, and the DISCONNECT that sets the flag mid-pass leaves ret
         * fatal. */
        if (ssh->isKeying && ret != WS_EXTDATA && ret != WS_EOF) {
            ssh->error = WS_REKEYING;
            return WS_REKEYING;
        }
    }

    if (ret == WS_CHAN_RXD) {
        WLOG(WS_LOG_DEBUG, "Leaving wolfSSH_worker(), "
                           "data received on channel %u", ssh->lastRxId);
    }
    else {
        WLOG(WS_LOG_DEBUG, "Leaving wolfSSH_worker(), ret = %d", ret);
    }
    return ret;
}


int wolfSSH_GetLastRxId(WOLFSSH* ssh, word32* channelId)
{
    int ret = WS_SUCCESS;

    if (ssh == NULL || channelId == NULL)
        ret = WS_ERROR;

    if (ret == WS_SUCCESS)
        *channelId = ssh->lastRxId;

    return ret;
}


#ifdef WOLFSSH_FWD

int wolfSSH_CTX_SetFwdCb(WOLFSSH_CTX* ctx,
        WS_CallbackFwd fwdCb, WS_CallbackFwdIO fwdIoCb)
{
    int ret = WS_SUCCESS;

    if (ctx == NULL)
        ret = WS_BAD_ARGUMENT;

    if (ret == WS_SUCCESS) {
        ctx->fwdCb = fwdCb;
        ctx->fwdIoCb = fwdIoCb;
    }

    return ret;
}


int wolfSSH_SetFwdCbCtx(WOLFSSH* ssh, void* ctx)
{
    int ret = WS_SUCCESS;

    if (ssh == NULL)
        ret = WS_BAD_ARGUMENT;

    if (ret == WS_SUCCESS) {
        ssh->fwdCbCtx = ctx;
    }

    return ret;
}


WOLFSSH_CHANNEL* wolfSSH_ChannelFwdNewLocal(WOLFSSH* ssh,
        const char* host, word32 hostPort,
        const char* origin, word32 originPort)
{
    WOLFSSH_CHANNEL* newChannel = NULL;
    int ret = WS_SUCCESS;

    WLOG(WS_LOG_DEBUG, "Entering wolfSSH_ChannelFwdNewLocal()");

    if (ssh == NULL || ssh->ctx == NULL || host == NULL || origin == NULL)
        ret = WS_BAD_ARGUMENT;

    if (ret == WS_SUCCESS && SendAfterDisconnect(ssh))
        ret = WS_FATAL_ERROR;

    if (ret == WS_SUCCESS) {
        newChannel = ChannelNew(ssh, ID_CHANTYPE_TCPIP_DIRECT,
                ssh->ctx->windowSz, ssh->ctx->maxPacketSz);
        if (newChannel == NULL)
            ret = WS_MEMORY_E;
    }
    if (ret == WS_SUCCESS)
        ret = ChannelUpdateForward(newChannel,
                host, hostPort, origin, originPort, 1);
    if (ret == WS_SUCCESS)
        ret = SendChannelOpenForward(ssh, newChannel);

    if (ret != WS_SUCCESS) {
        void* heap = (ssh != NULL && ssh->ctx != NULL) ? ssh->ctx->heap : NULL;
        ChannelDelete(newChannel, heap);
        newChannel = NULL;
    }

    if (newChannel != NULL)
        ChannelAppend(ssh, newChannel);

    WLOG(WS_LOG_DEBUG, "Leaving wolfSSH_ChannelFwdNewLocal(), newChannel = %p",
            newChannel);
    return newChannel;
}


WOLFSSH_CHANNEL* wolfSSH_ChannelFwdNewRemote(WOLFSSH* ssh,
        const char* host, word32 hostPort,
        const char* origin, word32 originPort)
{
    WOLFSSH_CHANNEL* newChannel = NULL;
    int ret = WS_SUCCESS;

    WLOG(WS_LOG_DEBUG, "Entering wolfSSH_ChannelFwdNewRemote()");

    if (ssh == NULL || ssh->ctx == NULL || host == NULL || origin == NULL)
        ret = WS_BAD_ARGUMENT;

    if (ret == WS_SUCCESS && SendAfterDisconnect(ssh))
        ret = WS_FATAL_ERROR;

    if (ret == WS_SUCCESS) {
        newChannel = ChannelNew(ssh, ID_CHANTYPE_TCPIP_FORWARD,
                ssh->ctx->windowSz, ssh->ctx->maxPacketSz);
        if (newChannel == NULL)
            ret = WS_MEMORY_E;
    }
    if (ret == WS_SUCCESS)
        ret = ChannelUpdateForward(newChannel,
                host, hostPort, origin, originPort, 0);
    if (ret == WS_SUCCESS)
        ret = SendChannelOpenForward(ssh, newChannel);
    if (ret == WS_SUCCESS) {
        if (ssh->ctx->fwdCb) {
            ret = ssh->ctx->fwdCb(WOLFSSH_FWD_CHANNEL_ID, ssh->fwdCbCtx,
                    NULL, newChannel->channel);
        }
    }

    if (ret != WS_SUCCESS) {
        void* heap = (ssh != NULL && ssh->ctx != NULL) ? ssh->ctx->heap : NULL;
        ChannelDelete(newChannel, heap);
        newChannel = NULL;
    }

    if (newChannel != NULL)
        ChannelAppend(ssh, newChannel);

    WLOG(WS_LOG_DEBUG, "Leaving wolfSSH_ChannelFwdNewRemote(), newChannel = %p, ret = %d",
            newChannel, ret);
    return newChannel;
}


WOLFSSH_CHANNEL* wolfSSH_ChannelFwdNew(WOLFSSH* ssh,
        const char* host, word32 hostPort,
        const char* origin, word32 originPort)
{
    return wolfSSH_ChannelFwdNewLocal(ssh, host, hostPort, origin, originPort);
}


/* Send "tcpip-forward" and register the forward. See wolfssh/ssh.h for the
 * matching rules and what a port-0 request needs. */
int wolfSSH_FwdRemoteSetup(WOLFSSH* ssh, const char* bindAddr,
        word32 bindPort, int wantReply)
{
    WOLFSSH_FWD_PENDING pend;
    int ret = WS_SUCCESS;

    WLOG(WS_LOG_DEBUG, "Entering wolfSSH_FwdRemoteSetup()");

    if (ssh == NULL || ssh->ctx == NULL || bindAddr == NULL)
        ret = WS_BAD_ARGUMENT;

    /* A port is 16 bits on the wire; 0 asks the peer to allocate one. */
    if (ret == WS_SUCCESS && bindPort > 65535)
        ret = WS_BAD_ARGUMENT;

    if (ret == WS_SUCCESS && wantReply != 0 && wantReply != 1)
        ret = WS_BAD_ARGUMENT;

    /* The peer's reply is the only place a port-0 request learns the port it
     * got, and neither the caller nor the forwarded-tcpip check works without
     * one. */
    if (ret == WS_SUCCESS && bindPort == 0 && !wantReply)
        ret = WS_BAD_ARGUMENT;

    if (ret == WS_SUCCESS && ssh->ctx->side != WOLFSSH_ENDPOINT_CLIENT)
        ret = WS_BAD_ARGUMENT;

    if (ret == WS_SUCCESS && SendAfterDisconnect(ssh))
        ret = WS_FATAL_ERROR;

    /* A global request must not go out mid-rekey; only KEX traffic may. */
    if (ret == WS_SUCCESS && ssh->isKeying)
        ret = WS_REKEYING;

    /* Everything that can fail is allocated before the request goes out, so an
     * error from here means the peer heard nothing. */
    if (ret == WS_SUCCESS)
        ret = FwdRemotePrepare(ssh, bindAddr, bindPort, wantReply, 0, &pend);

    /* The send settles pend: what reached the peer registers, even when the
     * post-send highwater callback reports an error afterwards. */
    if (ret == WS_SUCCESS)
        ret = SendGlobalRequestFwd(ssh, bindAddr, bindPort, 0, wantReply,
                &pend);

    WLOG(WS_LOG_DEBUG, "Leaving wolfSSH_FwdRemoteSetup(), ret = %d", ret);
    return ret;
}


/* Send "cancel-tcpip-forward", tearing down a wolfSSH_FwdRemoteSetup()
 * listener. See wolfssh/ssh.h for when the registration actually drops. */
int wolfSSH_FwdRemoteCancel(WOLFSSH* ssh, const char* bindAddr,
        word32 bindPort, int wantReply)
{
    WOLFSSH_FWD_PENDING pend;
    int ret = WS_SUCCESS;

    WLOG(WS_LOG_DEBUG, "Entering wolfSSH_FwdRemoteCancel()");

    if (ssh == NULL || ssh->ctx == NULL || bindAddr == NULL)
        ret = WS_BAD_ARGUMENT;

    /* Unlike the setup, 0 names no listener the peer could have bound. */
    if (ret == WS_SUCCESS && (bindPort == 0 || bindPort > 65535))
        ret = WS_BAD_ARGUMENT;

    if (ret == WS_SUCCESS && wantReply != 0 && wantReply != 1)
        ret = WS_BAD_ARGUMENT;

    if (ret == WS_SUCCESS && ssh->ctx->side != WOLFSSH_ENDPOINT_CLIENT)
        ret = WS_BAD_ARGUMENT;

    if (ret == WS_SUCCESS && SendAfterDisconnect(ssh))
        ret = WS_FATAL_ERROR;

    /* A global request must not go out mid-rekey; only KEX traffic may. */
    if (ret == WS_SUCCESS && ssh->isKeying)
        ret = WS_REKEYING;

    if (ret == WS_SUCCESS)
        ret = FwdRemotePrepare(ssh, bindAddr, bindPort, wantReply, 1, &pend);

    if (ret == WS_SUCCESS)
        ret = SendGlobalRequestFwd(ssh, bindAddr, bindPort, 1, wantReply,
                &pend);

    WLOG(WS_LOG_DEBUG, "Leaving wolfSSH_FwdRemoteCancel(), ret = %d", ret);
    return ret;
}


int wolfSSH_SetFwdRemoteMatch(WOLFSSH* ssh, byte match)
{
    int ret = WS_SUCCESS;

    WLOG(WS_LOG_DEBUG, "Entering wolfSSH_SetFwdRemoteMatch()");

    if (ssh == NULL || match > WOLFSSH_FWD_MATCH_OFF)
        ret = WS_BAD_ARGUMENT;
    else
        ssh->fwdRemoteMatch = match;

    WLOG(WS_LOG_DEBUG, "Leaving wolfSSH_SetFwdRemoteMatch(), ret = %d", ret);
    return ret;
}

#endif /* WOLFSSH_FWD */


int wolfSSH_ChannelFree(WOLFSSH_CHANNEL* channel)
{
    int ret;

    WLOG(WS_LOG_DEBUG, "Entering wolfSSH_ChannelFree()");

    if (channel != NULL) {
        ret = ChannelRemove(channel->ssh,
                channel->channel, WS_CHANNEL_ID_SELF);
    }
    else
        ret = WS_BAD_ARGUMENT;

    WLOG(WS_LOG_DEBUG, "Leaving wolfSSH_ChannelFree(), ret = %d", ret);
    return ret;
}


int wolfSSH_ChannelGetId(WOLFSSH_CHANNEL* channel, word32* id, byte peer)
{
    int ret = WS_SUCCESS;

    WLOG(WS_LOG_DEBUG, "Entering wolfSSH_ChannelGetId()");

    if (channel == NULL || id == NULL)
        ret = WS_BAD_ARGUMENT;
    else {
        *id = (peer == WS_CHANNEL_ID_SELF) ?
            channel->channel : channel->peerChannel;
    }

    WLOG(WS_LOG_DEBUG, "Leaving wolfSSH_ChannelGetId(), ret = %d", ret);
    return ret;
}


WOLFSSH_CHANNEL* wolfSSH_ChannelFind(WOLFSSH* ssh, word32 id, byte peer)
{
    return ChannelFind(ssh, id, peer);
}


#ifdef WOLFSSH_FWD

int wolfSSH_ChannelSetFwdFd(WOLFSSH_CHANNEL* channel, int fwdFd)
{
    int ret = WS_SUCCESS;

    WLOG(WS_LOG_DEBUG, "Entering wolfSSH_ChannelSetFwdFd()");

    if (channel != NULL)
        channel->fwdFd = fwdFd;
    else
        ret = WS_BAD_ARGUMENT;

    WLOG(WS_LOG_DEBUG, "Leaving wolfSSH_ChannelSetFwdFd(), ret = %d", ret);
    return ret;
}


int wolfSSH_ChannelGetFwdFd(const WOLFSSH_CHANNEL* channel)
{
    int fwdFd = -1;

    WLOG(WS_LOG_DEBUG, "Entering wolfSSH_ChannelGetFwdFd()");

    if (channel != NULL)
        fwdFd = channel->fwdFd;

    WLOG(WS_LOG_DEBUG, "Leaving wolfSSH_ChannelGetFwdFd(), ret = %d", fwdFd);
    return fwdFd;
}

#endif /* WOLFSSH_FWD */


/* moves the window for more room
 * returns WS_SUCCESS on success */
static int _UpdateChannelWindow(WOLFSSH_CHANNEL* channel)
{
    WOLFSSH_BUFFER* inputBuffer;
    int sendResult = WS_SUCCESS;

    if (channel == NULL)
        return WS_BAD_ARGUMENT;

    inputBuffer = &channel->inputBuffer;

    if ((inputBuffer->length > inputBuffer->bufferSz / 2) ||
         (channel->windowSz == 0)) {

        word32 usedSz = inputBuffer->length - inputBuffer->idx;
        word32 bytesToAdd = inputBuffer->idx;

        WLOG(WS_LOG_DEBUG, "Making more room: %u", usedSz);
        if (usedSz) {
            WLOG(WS_LOG_DEBUG, "  ...moving data down");
            WMEMMOVE(inputBuffer->buffer,
                     inputBuffer->buffer + bytesToAdd, usedSz);
        }

        /* Credit through the channel, not a direct send: credit that cannot go
         * out now is parked (mid-rekey per RFC 4253 section 7.1, or a failed
         * send) and a zero-byte adjust is suppressed. Stderr charges the window
         * without consuming this buffer, so windowSz == 0 above can fire with
         * nothing read here. */
        sendResult = ChannelCreditWindow(channel->ssh, channel, bytesToAdd);

        WLOG(WS_LOG_INFO, "  bytesToAdd = %u", bytesToAdd);
        WLOG(WS_LOG_INFO, "  windowSz = %u", channel->windowSz);
        channel->windowSz += bytesToAdd;
        WLOG(WS_LOG_INFO, "  update windowSz = %u", channel->windowSz);

        inputBuffer->length = usedSz;
        inputBuffer->idx = 0;
    }

    return sendResult;
}


/* Drains buffered channel data and credits the window for the bytes taken.
 * Reports the bytes copied; an adjust that could not go out lands in
 * ssh->error. */
static int _ChannelRead(WOLFSSH_CHANNEL* channel, byte* buf, word32 bufSz)
{
    WOLFSSH_BUFFER* inputBuffer;
    WOLFSSH* ssh;
    word32 creditedSz;
    int updateResult = WS_SUCCESS;
    int savedError;

    if (channel == NULL || buf == NULL || bufSz == 0)
        return WS_BAD_ARGUMENT;

    ssh = channel->ssh;
    inputBuffer = &channel->inputBuffer;

    if (inputBuffer->idx > inputBuffer->length) {
        WLOG(WS_LOG_ERROR, "Bad internal state for buffer index");
        return WS_INVALID_STATE_E;
    }

    bufSz = min(bufSz, inputBuffer->length - inputBuffer->idx);
    WMEMCPY(buf, inputBuffer->buffer + inputBuffer->idx, bufSz);
    inputBuffer->idx += bufSz;

    /* Unguarded by bufSz: also compacts, and carries credit left behind. */
    savedError = ssh->error;
    creditedSz = inputBuffer->idx;
    updateResult = _UpdateChannelWindow(channel);
    if (updateResult == WS_SUCCESS) {
        /* Clear the old WS_WANT_WRITE only if this read sent an adjust of
         * its own and the output buffer is now empty. */
        if (savedError == WS_WANT_WRITE && creditedSz != 0
                && inputBuffer->idx == 0 && ssh->outputBuffer.length == 0) {
            ssh->error = WS_SUCCESS;
        }
        else {
            ssh->error = savedError;
        }
    }
    else {
        /* SendPacket() records only WS_WANT_WRITE, so a hard failure has to
         * be recorded here; rewriting WS_WANT_WRITE is deliberate. */
        ssh->error = updateResult;
        if (updateResult != WS_WANT_WRITE) {
            WLOG(WS_LOG_ERROR,
                 "_ChannelRead: window adjust send failed (%d); read still "
                 "succeeded", updateResult);
        }
    }

    return (int)bufSz;
}


/* Drains buffered extended data (stderr) and credits the channel window for the
 * bytes taken, releasing the back-pressure DoChannelExtendedData() applied.
 * Always reports the bytes copied, even when the window adjust cannot go out:
 * they are already in the caller's buffer, and ChannelCreditWindow() keeps the
 * credit owed. */
static int _ChannelReadExt(WOLFSSH_CHANNEL* channel, byte* buf, word32 bufSz)
{
    WOLFSSH_BUFFER* extDataBuffer;
    WOLFSSH* ssh;

    if (channel == NULL || buf == NULL || bufSz == 0)
        return WS_BAD_ARGUMENT;

    ssh = channel->ssh;
    extDataBuffer = &channel->extDataBuffer;

    /* sanity check to make sure idx is not in a bad state */
    if (extDataBuffer->idx > extDataBuffer->length) {
        WLOG(WS_LOG_ERROR, "Bad internal state for buffer index");
        return WS_INVALID_STATE_E;
    }

    bufSz = min(bufSz, extDataBuffer->length - extDataBuffer->idx);
    WMEMCPY(buf, extDataBuffer->buffer + extDataBuffer->idx, bufSz);
    extDataBuffer->idx += bufSz;

    if (bufSz > 0) {
        int adjustResult;
        int savedError = ssh->error;

        /* Credit locally regardless of the send result; ChannelCreditWindow()
         * owns getting it to the peer. */
        channel->windowSz += bufSz;

        /* Fully drained: release the allocation. */
        if (extDataBuffer->idx == extDataBuffer->length)
            ShrinkBuffer(extDataBuffer, 0);

        adjustResult = ChannelCreditWindow(ssh, channel, bufSz);
        if (adjustResult == WS_SUCCESS) {
            /* Don't restore an owed-flush status once the buffer has drained. */
            if (savedError == WS_WANT_WRITE && ssh->outputBuffer.length == 0)
                ssh->error = WS_SUCCESS;
            else
                ssh->error = savedError;
        }
        else {
            /* SendPacket() sets ssh->error only for WS_WANT_WRITE, so hard
             * failures must be recorded here or they stay hidden. */
            ssh->error = adjustResult;
            if (adjustResult != WS_WANT_WRITE) {
                WLOG(WS_LOG_ERROR,
                     "_ChannelReadExt: window adjust send failed (%d); read "
                     "still succeeded", adjustResult);
            }
        }
    }

    return (int)bufSz;
}


int wolfSSH_ChannelIdRead(WOLFSSH* ssh, word32 channelId,
        byte* buf, word32 bufSz)
{
    WOLFSSH_CHANNEL* channel = NULL;

    WLOG(WS_LOG_DEBUG, "Entering wolfSSH_ChannelIdRead()");

    if (ssh == NULL || buf == NULL)
        return WS_BAD_ARGUMENT;

    channel = ChannelFind(ssh, channelId, WS_CHANNEL_ID_SELF);
    if (channel == NULL)
        return WS_INVALID_CHANID;

    bufSz = _ChannelRead(channel, buf, bufSz);

    WLOG(WS_LOG_DEBUG, "Leaving wolfSSH_ChannelIdRead(), rxd = %d", bufSz);
    return bufSz;
}


int wolfSSH_ChannelRead(WOLFSSH_CHANNEL* channel, byte* buf, word32 bufSz)
{

    WLOG(WS_LOG_DEBUG, "Entering wolfSSH_ChannelRead()");

    if (channel == NULL || buf == NULL || bufSz == 0)
        return WS_BAD_ARGUMENT;

    if (channel->ssh->isKeying) {
        channel->ssh->error = WS_REKEYING;
        return WS_REKEYING;
    }

    bufSz = _ChannelRead(channel, buf, bufSz);

    WLOG(WS_LOG_DEBUG, "Leaving wolfSSH_ChannelRead(), bytesRxd = %d",
            bufSz);
    return bufSz;
}


int wolfSSH_ChannelIdReadExt(WOLFSSH* ssh, word32 channelId,
        byte* buf, word32 bufSz)
{
    WOLFSSH_CHANNEL* channel = NULL;
    int bytesRxd;

    WLOG(WS_LOG_DEBUG, "Entering wolfSSH_ChannelIdReadExt(), ID = %u",
            channelId);

    if (ssh == NULL || buf == NULL)
        return WS_BAD_ARGUMENT;

    channel = ChannelFind(ssh, channelId, WS_CHANNEL_ID_SELF);
    if (channel == NULL)
        return WS_INVALID_CHANID;

    bytesRxd = _ChannelReadExt(channel, buf, bufSz);

    WLOG(WS_LOG_DEBUG, "Leaving wolfSSH_ChannelIdReadExt(), rxd = %d",
            bytesRxd);
    return bytesRxd;
}


/* Unlike wolfSSH_ChannelRead(), this does not fail with WS_REKEYING while
 * keying: the bytes are already buffered, and the window credit the read owes
 * is parked until the rekey completes. Failing here would drop the data. */
int wolfSSH_ChannelReadExt(WOLFSSH_CHANNEL* channel, byte* buf, word32 bufSz)
{
    int bytesRxd;

    WLOG(WS_LOG_DEBUG, "Entering wolfSSH_ChannelReadExt()");

    if (channel == NULL || buf == NULL || bufSz == 0)
        return WS_BAD_ARGUMENT;

    bytesRxd = _ChannelReadExt(channel, buf, bufSz);

    WLOG(WS_LOG_DEBUG, "Leaving wolfSSH_ChannelReadExt(), bytesRxd = %d",
            bytesRxd);
    return bytesRxd;
}


int wolfSSH_ChannelSend(WOLFSSH_CHANNEL* channel,
        const byte* buf, word32 bufSz)
{
    int bytesTxd = 0;

    if (channel == NULL || buf == NULL) {
        WLOG(WS_LOG_DEBUG, "Entering wolfSSH_ChannelSend() with bad argument");
        return WS_BAD_ARGUMENT;
    }

    WLOG(WS_LOG_DEBUG, "Entering wolfSSH_ChannelSend(), ID = %d, peerID = %d",
            channel->channel, channel->peerChannel);

    if (channel->ssh != NULL && SendAfterDisconnect(channel->ssh))
        return WS_FATAL_ERROR;

#ifdef DEBUG_WOLFSSH
    DumpOctetString(buf, bufSz);
#endif

    if (!channel->openConfirmed) {
        WLOG(WS_LOG_DEBUG, "Channel not confirmed yet.");
        bytesTxd = WS_CHANNEL_NOT_CONF;
    }
    else {
        WLOG(WS_LOG_DEBUG, "Sending data.");
        bytesTxd = SendChannelData(channel->ssh, channel->channel,
                (byte*)buf, bufSz);
    }

    WLOG(WS_LOG_DEBUG, "Leaving wolfSSH_ChannelSend(), bytesTxd = %d",
            bytesTxd);
    return bytesTxd;
}


int wolfSSH_ChannelSendExt(WOLFSSH_CHANNEL* channel,
        const byte* buf, word32 bufSz)
{
    int bytesTxd = 0;

    if (channel == NULL || buf == NULL) {
        WLOG(WS_LOG_DEBUG,
                "Entering wolfSSH_ChannelSendExt() with bad argument");
        return WS_BAD_ARGUMENT;
    }

    WLOG(WS_LOG_DEBUG,
            "Entering wolfSSH_ChannelSendExt(), ID = %d, peerID = %d",
            channel->channel, channel->peerChannel);

    if (channel->ssh != NULL && SendAfterDisconnect(channel->ssh))
        return WS_FATAL_ERROR;

#ifdef DEBUG_WOLFSSH
    DumpOctetString(buf, bufSz);
#endif

    if (!channel->openConfirmed) {
        WLOG(WS_LOG_DEBUG, "Channel not confirmed yet.");
        bytesTxd = WS_CHANNEL_NOT_CONF;
    }
    else {
        WLOG(WS_LOG_DEBUG, "Sending extended data.");
        bytesTxd = SendChannelExtendedData(channel->ssh, channel->channel,
                (byte*)buf, bufSz);
    }

    WLOG(WS_LOG_DEBUG, "Leaving wolfSSH_ChannelSendExt(), bytesTxd = %d",
            bytesTxd);
    return bytesTxd;
}


int wolfSSH_ChannelExit(WOLFSSH_CHANNEL* channel)
{
    int ret = WS_SUCCESS;

    WLOG(WS_LOG_DEBUG, "Entering wolfSSH_ChannelExit()");

    if (channel == NULL)
        ret = WS_BAD_ARGUMENT;

    if (ret == WS_SUCCESS && channel->ssh != NULL &&
            SendAfterDisconnect(channel->ssh))
        ret = WS_FATAL_ERROR;

    /* Both sends address the peer id, 0 until the open is confirmed, so
     * this would tear down whichever channel holds 0. */
    if (ret == WS_SUCCESS && !channel->openConfirmed) {
        WLOG(WS_LOG_DEBUG, "Channel not confirmed yet.");
        ret = WS_CHANNEL_NOT_CONF;
    }

    if (ret == WS_SUCCESS)
        ret = SendChannelEof(channel->ssh, channel->peerChannel);

    if (ret == WS_SUCCESS)
        ret = SendChannelClose(channel->ssh, channel->peerChannel);

    WLOG(WS_LOG_DEBUG, "Leaving wolfSSH_ChannelExit(), ret = %d", ret);
    return ret;
}


int wolfSSH_ChannelSendEof(WOLFSSH_CHANNEL* channel)
{
    int ret = WS_SUCCESS;

    WLOG(WS_LOG_DEBUG, "Entering wolfSSH_ChannelSendEof()");

    /* Every gate below reaches through ssh, so take it up front. */
    if (channel == NULL || channel->ssh == NULL)
        ret = WS_BAD_ARGUMENT;

    if (ret == WS_SUCCESS && SendAfterDisconnect(channel->ssh))
        ret = WS_FATAL_ERROR;

    /* Only KEX traffic may go out mid-rekey, RFC 4253 section 7.1. */
    if (ret == WS_SUCCESS && channel->ssh->isKeying) {
        channel->ssh->error = WS_REKEYING;
        ret = WS_REKEYING;
    }

    /* peerChannel is 0 until the open is confirmed, and SendChannelEof()
     * resolves by peer id. */
    if (ret == WS_SUCCESS && !channel->openConfirmed) {
        WLOG(WS_LOG_DEBUG, "Channel not confirmed yet.");
        ret = WS_CHANNEL_NOT_CONF;
    }

    if (ret == WS_SUCCESS)
        ret = SendChannelEof(channel->ssh, channel->peerChannel);

    WLOG(WS_LOG_DEBUG, "Leaving wolfSSH_ChannelSendEof(), ret = %d", ret);
    return ret;
}


WOLFSSH_CHANNEL* wolfSSH_ChannelNext(WOLFSSH* ssh, WOLFSSH_CHANNEL* channel)
{
    WOLFSSH_CHANNEL* nextChannel = NULL;

    WLOG(WS_LOG_DEBUG, "Entering wolfSSH_ChannelNext()");

    if (ssh != NULL && channel == NULL)
        nextChannel = ssh->channelList;
    else if (channel != NULL)
        nextChannel = channel->next;

    WLOG(WS_LOG_DEBUG, "Leaving wolfSSH_ChannelNext(), %s",
            nextChannel == NULL ? "none" : "NEXT!");
    return nextChannel;
}


int wolfSSH_ChannelGetEof(WOLFSSH_CHANNEL* channel)
{
    int eof = 1;

    WLOG(WS_LOG_DEBUG, "Entering wolfSSH_ChannelGetEof()");

    if (channel)
        eof = (int)channel->eofRxd;

    WLOG(WS_LOG_DEBUG, "Leaving wolfSSH_ChannelGetEof(), %s",
            eof ? "true" : "false");
    return eof;
}

static const char* HashNameForId(byte id)
{
    enum wc_HashType hash = HashForId(id);

    if (hash == WC_HASH_TYPE_SHA)
        return "SHA-1";

    if (hash == WC_HASH_TYPE_SHA256)
        return "SHA-256";

    if (hash == WC_HASH_TYPE_SHA384)
        return "SHA-384";

    if (hash == WC_HASH_TYPE_SHA512)
        return "SHA-512";

    return "";
}

static const char* CurveNameForId(byte id)
{
#if !defined(WOLFSSH_NO_ECDSA) || !defined(WOLFSSH_NO_ECDH)
    switch (wcPrimeForId(id)) {
        case ECC_SECP256R1:
            return "nistp256";

        case ECC_SECP384R1:
            return "nistp384";

        case ECC_SECP521R1:
            return "nistp521";

#ifdef HAVE_CURVE25519
        case ECC_X25519:
            return "Curve25519";
#endif
    }
#endif
    return "";
}

static const char* CipherNameForId(byte id)
{
    switch (id) {
        case ID_AES128_CBC:
            return "AES-128 CBC";

        case ID_AES192_CBC:
            return "AES-192 CBC";

        case ID_AES256_CBC:
            return "AES-256 CBC";

        case ID_AES128_CTR:
            return "AES-128 SDCTR";

        case ID_AES192_CTR:
            return "AES-192 SDCTR";

        case ID_AES256_CTR:
            return "AES-256 SDCTR";

        case ID_AES128_GCM:
            return "AES-128 GCM";

        case ID_AES192_GCM:
            return "AES-192 GCM";

        case ID_AES256_GCM:
            return "AES-256 GCM";
    }

    return "";
}

static const char* MacNameForId(byte macid, byte cipherid)
{
    if (macid != ID_NONE) {
        switch (macid) {
            case ID_HMAC_SHA1:
                return "HMAC-SHA-1";

            case ID_HMAC_SHA1_96:
                return "HMAC-SHA-1-96";

            case ID_HMAC_SHA2_256:
                return "HMAC-SHA-256";

            case ID_HMAC_SHA2_512:
                return "HMAC-SHA-512";
        }
    }
    else {
        switch (cipherid) {
            case ID_AES128_GCM:
                return "AES128 GCM (in ETM mode)";

            case ID_AES192_GCM:
                return "AES192 GCM (in ETM mode)";

            case ID_AES256_GCM:
                return "AES256 GCM (in ETM mode)";
        }
    }

    return "";
}

size_t wolfSSH_GetText(WOLFSSH *ssh, WS_Text id, char *str, size_t strSz)
{
    int ret = 0;

#ifndef WOLFSSH_NO_DH
    static const char standard_dh_format[] =
        "%d-bit Diffie-Hellman with standard group %d";
#endif

    if (!ssh || str == NULL || strSz <= 0)
        return 0;

    switch (id) {
        case WOLFSSH_TEXT_KEX_HASH:
            ret = WSNPRINTF(str, strSz, "%s", HashNameForId(ssh->kexId));
            break;

        case WOLFSSH_TEXT_KEX_CURVE:
            ret = WSNPRINTF(str, strSz, "%s", CurveNameForId(ssh->kexId));
            break;

        case WOLFSSH_TEXT_CRYPTO_IN_CIPHER:
            ret = WSNPRINTF(str, strSz, "%s",
                CipherNameForId(ssh->peerEncryptId));
            break;

        case WOLFSSH_TEXT_CRYPTO_OUT_CIPHER:
            ret = WSNPRINTF(str, strSz, "%s", CipherNameForId(ssh->encryptId));
            break;

        case WOLFSSH_TEXT_CRYPTO_IN_MAC:
            ret = WSNPRINTF(str, strSz, "%s", MacNameForId(ssh->peerMacId,
                ssh->peerEncryptId));
            break;

        case WOLFSSH_TEXT_CRYPTO_OUT_MAC:
            ret = WSNPRINTF(str, strSz, "%s", MacNameForId(ssh->macId,
                ssh->encryptId));
            break;

        case WOLFSSH_TEXT_KEX_ALGO:
            switch (ssh->kexId) {
                case ID_ECDH_SHA2_NISTP256:
                case ID_ECDH_SHA2_NISTP384:
                case ID_ECDH_SHA2_NISTP521:
            #ifndef WOLFSSH_NO_CURVE25519_SHA256
                case ID_CURVE25519_SHA256:
                case ID_CURVE25519_SHA256_LIBSSH:
            #endif
                    ret = WSNPRINTF(str, strSz, "%s", "ECDH");
                    break;

            #ifndef WOLFSSH_NO_NISTP256_MLKEM768_SHA256
                case ID_NISTP256_MLKEM768_SHA256:
                    ret = WSNPRINTF(str, strSz, "%s",
                            "ECDH-NISTP256-MLKEM768");
                    break;
            #endif

            #ifndef WOLFSSH_NO_NISTP384_MLKEM1024_SHA384
                case ID_NISTP384_MLKEM1024_SHA384:
                    ret = WSNPRINTF(str, strSz, "%s",
                            "ECDH-NISTP384-MLKEM1024");
                    break;
            #endif

            #ifndef WOLFSSH_NO_CURVE25519_MLKEM768_SHA256
                case ID_CURVE25519_MLKEM768_SHA256:
                    ret = WSNPRINTF(str, strSz, "%s",
                            "ECDH-CURVE25519-MLKEM768");
                    break;
            #endif

            #ifndef WOLFSSH_NO_DH
                case ID_DH_GROUP1_SHA1:
                    ret = WSNPRINTF(str, strSz, standard_dh_format,
                        ssh->primeGroupSz*8, 1);
                    break;

                case ID_DH_GROUP14_SHA1:
                case ID_DH_GROUP14_SHA256:
                    ret = WSNPRINTF(str, strSz, standard_dh_format,
                        ssh->primeGroupSz*8, 14);
                    break;

                case ID_DH_GROUP16_SHA512:
                    ret = WSNPRINTF(str, strSz, standard_dh_format,
                        ssh->primeGroupSz*8, 16);
                    break;

                case ID_DH_GEX_SHA256:
                    ret = WSNPRINTF(str, strSz,
                        "%d-bit Diffie-Hellman with server-supplied group",
                        ssh->primeGroupSz*8);
                    break;
            #endif /* !WOLFSSH_NO_DH */

                case ID_EXTINFO_S:
                   #if defined(__CCRX__)
                    ret = WSNPRINTF0(str, strSz, "Server extensions KEX");
                   #else
                    ret = WSNPRINTF(str, strSz, "Server extensions KEX");
                   #endif
                    break;

                case ID_EXTINFO_C:
                   #if defined(__CCRX__)
                    ret = WSNPRINTF0(str, strSz, "Client extensions KEX");
                   #else
                    ret = WSNPRINTF(str, strSz, "Client extensions KEX");
                   #endif
                    break;

            }
            break;
    }

    return ret < 0 ? 0 : (size_t)ret;
}

void wolfSSH_SetKeyingCompletionCb(WOLFSSH_CTX* ctx, WS_CallbackKeyingCompletion cb)
{
    WLOG(WS_LOG_DEBUG, "Entering wolfSSH_SetKeyingCompletionCb()");

    if (ctx)
        ctx->keyingCompletionCb = cb;
}

void wolfSSH_SetKeyingCompletionCbCtx(WOLFSSH* ssh, void* ctx)
{
    WLOG(WS_LOG_DEBUG, "Entering wolfSSH_SetKeyingCompletionCbCtx()");

    if (ssh)
        ssh->keyingCompletionCtx = ctx;
}


const char* wolfSSH_ChannelGetType(const WOLFSSH_CHANNEL* channel)
{
    const char* name = NULL;

    WLOG(WS_LOG_DEBUG, "Entering wolfSSH_ChannelGetType()");

    if (channel != NULL) {
        name = IdToName(channel->channelType);
    }

    WLOG(WS_LOG_DEBUG, "Leaving wolfSSH_ChannelGetType(), name = %s",
            channel ? name : "null channel");
    return name;
}


WS_SessionType wolfSSH_ChannelGetSessionType(const WOLFSSH_CHANNEL* channel)
{
    WS_SessionType type = WOLFSSH_SESSION_UNKNOWN;

    WLOG(WS_LOG_DEBUG, "Entering wolfSSH_ChannelGetSessionType()");

    if (channel) {
        type = (WS_SessionType)channel->sessionType;
    }

    WLOG(WS_LOG_DEBUG, "Leaving wolfSSH_ChannelGetSessionType(), type = %d",
            type);
    return type;
}


#if defined(WOLFSSH_TERM)
/* returns 1 if a PTY was requested, 0 if not, and negative on failure */
int wolfSSH_ChannelIsPty(const WOLFSSH_CHANNEL* channel)
{
    if (channel == NULL) {
        return WS_BAD_ARGUMENT;
    }
    return channel->ptyReq;
}
#endif


const char* wolfSSH_ChannelGetSessionCommand(const WOLFSSH_CHANNEL* channel)
{
    const char* cmd = NULL;

    WLOG(WS_LOG_DEBUG, "Entering wolfSSH_ChannelGetCommand()");

    if (channel) {
        cmd = channel->command;
    }

    return cmd;
}


int wolfSSH_CTX_SetChannelOpenCb(WOLFSSH_CTX* ctx, WS_CallbackChannelOpen cb)
{
    int ret = WS_SSH_CTX_NULL_E;

    if (ctx != NULL) {
        ctx->channelOpenCb = cb;
        ret = WS_SUCCESS;
    }

    return ret;
}


int wolfSSH_CTX_SetChannelOpenRespCb(WOLFSSH_CTX* ctx,
        WS_CallbackChannelOpen confCb, WS_CallbackChannelOpen failCb)
{
    int ret = WS_SSH_CTX_NULL_E;

    if (ctx != NULL) {
        ctx->channelOpenConfCb = confCb;
        ctx->channelOpenFailCb = failCb;
        ret = WS_SUCCESS;
    }

    return ret;
}


int wolfSSH_CTX_SetChannelReqShellCb(WOLFSSH_CTX* ctx,
        WS_CallbackChannelReq cb)
{
    int ret = WS_SSH_CTX_NULL_E;

    if (ctx != NULL) {
        ctx->channelReqShellCb = cb;
        ret = WS_SUCCESS;
    }

    return ret;
}


int wolfSSH_CTX_SetChannelReqExecCb(WOLFSSH_CTX* ctx,
        WS_CallbackChannelReq cb)
{
    int ret = WS_SSH_CTX_NULL_E;

    if (ctx != NULL) {
        ctx->channelReqExecCb = cb;
        ret = WS_SUCCESS;
    }

    return ret;
}


int wolfSSH_CTX_SetChannelReqSubsysCb(WOLFSSH_CTX* ctx,
        WS_CallbackChannelReq cb)
{
    int ret = WS_SSH_CTX_NULL_E;

    if (ctx != NULL) {
        ctx->channelReqSubsysCb = cb;
        ret = WS_SUCCESS;
    }

    return ret;
}


int wolfSSH_SetChannelOpenCtx(WOLFSSH* ssh, void* ctx)
{
    int ret = WS_SSH_NULL_E;

    if (ssh != NULL) {
        ssh->channelOpenCtx = ctx;
        ret = WS_SUCCESS;
    }

    return ret;
}


void* wolfSSH_GetChannelOpenCtx(WOLFSSH* ssh)
{
    void* ctx = NULL;

    if (ssh != NULL) {
        ctx = ssh->channelOpenCtx;
    }

    return ctx;
}


int wolfSSH_SetChannelReqCtx(WOLFSSH* ssh, void* ctx)
{
    int ret = WS_SSH_NULL_E;

    if (ssh != NULL) {
        ssh->channelReqCtx = ctx;
        ret = WS_SUCCESS;
    }

    return ret;
}


void* wolfSSH_GetChannelReqCtx(WOLFSSH* ssh)
{
    void* ctx = NULL;

    if (ssh != NULL) {
        ctx = ssh->channelReqCtx;
    }

    return ctx;
}


int wolfSSH_CTX_SetChannelEofCb(WOLFSSH_CTX* ctx, WS_CallbackChannelEof cb)
{
    int ret = WS_SSH_CTX_NULL_E;

    if (ctx != NULL) {
        ctx->channelEofCb = cb;
        ret = WS_SUCCESS;
    }

    return ret;
}


int wolfSSH_SetChannelEofCtx(WOLFSSH* ssh, void* ctx)
{
    int ret = WS_SSH_NULL_E;

    if (ssh != NULL) {
        ssh->channelEofCtx = ctx;
        ret = WS_SUCCESS;
    }

    return ret;
}


void* wolfSSH_GetChannelEofCtx(WOLFSSH* ssh)
{
    void* ctx = NULL;

    if (ssh != NULL) {
        ctx = ssh->channelEofCtx;
    }

    return ctx;
}


int wolfSSH_CTX_SetChannelCloseCb(WOLFSSH_CTX* ctx, WS_CallbackChannelClose cb)
{
    int ret = WS_SSH_CTX_NULL_E;

    if (ctx != NULL) {
        ctx->channelCloseCb = cb;
        ret = WS_SUCCESS;
    }

    return ret;
}


int wolfSSH_SetChannelCloseCtx(WOLFSSH* ssh, void* ctx)
{
    int ret = WS_SSH_NULL_E;

    if (ssh != NULL) {
        ssh->channelCloseCtx = ctx;
        ret = WS_SUCCESS;
    }

    return ret;
}


void* wolfSSH_GetChannelCloseCtx(WOLFSSH* ssh)
{
    void* ctx = NULL;

    if (ssh != NULL) {
        ctx = ssh->channelCloseCtx;
    }

    return ctx;
}


#if (defined(WOLFSSH_SFTP) || defined(WOLFSSH_SCP)) && \
    !defined(NO_WOLFSSH_SERVER)

/*
 * Paths starting with a slash are absolute, rooted at "/". Any path that
 * doesn't have a starting slash is assumed to be relative to the default
 * path. If the path is empty, return the default path.
 *
 * The path "/." is stripped out. The path "/.." strips out the previous
 * path value. The root path, "/", is always present.
 *
 * Trailing delimiters are stripped, i.e /tmp/path/ becomes /tmp/path
 *
 * Example: "/home/fred/frob/frizz/../../../barney/bar/baz/./././../.."
 * will return "/home/barney". "/../.." will return "/". "." will return
 * the default path.
 *
 * Note, this function does not care about OS and filesystem issues. The
 * SFTP protocol describes how paths are handled in SFTP. Specialized
 * behaviors are handled when actually calling the OS functions. Paths
 * are further massaged there. For example, the C: drive is treated as
 * the path "/C:", and is a directory like any other.
 *
 * @param defaultPath RealPath of the default directory, usually user's
 * @param in          requested new path
 * @param out         output of real path cleanup
 * @param outSz       size in bytes of buffer 'out'
 * @return            WS_SUCCESS, WS_BAD_ARGUMENT, or WS_INVALID_PATH_E
 */
int wolfSSH_RealPath(const char* defaultPath, char* in,
        char* out, word32 outSz)
{
    char* tail = NULL;
    char* seg;
    word32 inSz, segSz, curSz;

    if (in == NULL || out == NULL || outSz == 0) {
        return WS_BAD_ARGUMENT;
    }

    WMEMSET(out, 0, outSz);
    inSz = (word32)WSTRLEN(in);
    out[0] = '/';
    curSz = 1;
    if (inSz == 0 || (!WOLFSSH_SFTP_IS_DELIM(in[0]) &&
        !WOLFSSH_SFTP_IS_WINPATH(inSz, in))) {
        if (defaultPath != NULL) {
            curSz = (word32)WSTRLEN(defaultPath);
            if (curSz >= outSz) {
                return WS_INVALID_PATH_E;
            }
            WSTRNCPY(out, defaultPath, outSz);
        }
    }
    out[curSz] = 0;

    for (seg = WSTRTOK(in, WOLFSSH_SFTP_DELIM, &tail);
            seg;
            seg = WSTRTOK(NULL, WOLFSSH_SFTP_DELIM, &tail)) {
        segSz = (word32)WSTRLEN(seg);

        /* Try to match "." */
        if (segSz == 1 && seg[0] == '.') {
            /* Do nothing. Keep current directory. */
        }
        /* Try to match ".." */
        else if (segSz == 2 && seg[0] == '.' && seg[1] == '.') {
            char* prev = strrchr(out, '/');

            if (prev != NULL) {
                if (prev != out
#ifdef WOLFSSH_ZEPHYR
                        /* Zephyr FAT fs path names follow the format of '/RAM:'
                         * and we want to preserve the '/' after this mount
                         * point definition too. */
                        && prev[-1] != ':'
#endif
                        ) {
                    prev[0] = 0;
                    curSz = (word32)WSTRLEN(out);
                }
                else {
                    /* preserve the root / */
                    prev[1] = 0;
                    curSz = 1;
                }
            }
        }
        /* Everything else is copied */
        else {
            word32 sepSz = (curSz != 1) ? 1 : 0;

            /* Need room for the optional separator, the segment, and the
             * terminating null. Guard the subtraction against underflow. */
            if (segSz >= outSz || curSz + sepSz >= outSz - segSz) {
                return WS_INVALID_PATH_E;
            }

            /* Pass the full buffer size to WSTRNCAT: it measures the current
             * contents itself and returns NULL if the append would not fit,
             * so a truncated append is reported rather than silently kept. */
            if (curSz != 1) {
                if (WSTRNCAT(out, "/", outSz) == NULL) {
                    return WS_INVALID_PATH_E;
                }
                curSz++;
            }
            if (WSTRNCAT(out, seg, outSz) == NULL) {
                return WS_INVALID_PATH_E;
            }
            curSz += segSz;
        }
    }

    return WS_SUCCESS;
}
#endif /* WOLFSSH_SFTP || WOLFSSH_SCP */


#ifdef WOLFSSH_SHOW_SIZES

void wolfSSH_ShowSizes(void)
{
    fprintf(stderr, "wolfSSH struct sizes:\n");
    fprintf(stderr, "  sizeof(struct %s) = %u\n", "WOLFSSH_CTX",
            (word32)sizeof(struct WOLFSSH_CTX));
    fprintf(stderr, "  sizeof(struct %s) = %u\n", "WOLFSSH",
            (word32)sizeof(struct WOLFSSH));
    fprintf(stderr, "  sizeof(struct %s) = %u\n", "HandshakeInfo",
            (word32)sizeof(struct HandshakeInfo));
    fprintf(stderr, "  sizeof(struct %s) = %u\n", "WOLFSSH_CHANNEL",
            (word32)sizeof(struct WOLFSSH_CHANNEL));
    fprintf(stderr, "  sizeof(struct %s) = %u\n", "WOLFSSH_BUFFER",
            (word32)sizeof(struct WOLFSSH_BUFFER));
    #ifdef WOLFSSH_SFTP
        wolfSSH_SFTP_ShowSizes();
    #endif
}

#endif /* WOLFSSH_SHOW_SIZES */

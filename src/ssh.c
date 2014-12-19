/* ssh.c 
 *
 * Copyright (C) 2014 wolfSSL Inc.
 *
 * This file is part of wolfSSH.
 *
 * wolfSSH is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSH is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA  02110-1301, USA.
 */


/*
 * The ssh module contains the public API for wolfSSH.
 */


#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssh/ssh.h>
#include <wolfssh/internal.h>
#include <wolfssh/log.h>
#include <cyassl/ctaocrypt/rsa.h>
#include <cyassl/ctaocrypt/asn.h>


int wolfSSH_Init(void)
{
    WLOG(WS_LOG_DEBUG, "Enter wolfSSH_Init()");
    WLOG(WS_LOG_DEBUG, "Leaving wolfSSH_Init(), returning %d", WS_SUCCESS);
    return WS_SUCCESS;
}


int wolfSSH_Cleanup(void)
{
    WLOG(WS_LOG_DEBUG, "Enter wolfSSH_Cleanup()");
    WLOG(WS_LOG_DEBUG, "Leaving wolfSSH_Cleanup(), returning %d", WS_SUCCESS);
    return WS_SUCCESS;
}


static WOLFSSH_CTX* CtxInit(WOLFSSH_CTX* ctx, void* heap)
{
    WLOG(WS_LOG_DEBUG, "Enter CtxInit()");

    if (ctx == NULL)
        return ctx;

    WMEMSET(ctx, 0, sizeof(WOLFSSH_CTX));

    if (heap)
        ctx->heap = heap;

#ifndef WOLFSSH_USER_IO
    ctx->ioRecvCb = wsEmbedRecv;
    ctx->ioSendCb = wsEmbedSend;
#endif /* WOLFSSH_USER_IO */

    return ctx;
}


WOLFSSH_CTX* wolfSSH_CTX_new(uint8_t side, void* heap)
{
    WOLFSSH_CTX* ctx;

    WLOG(WS_LOG_DEBUG, "Enter wolfSSH_CTX_new()");

    if (side != WOLFSSH_ENDPOINT_SERVER && side != WOLFSSH_ENDPOINT_CLIENT) {
        WLOG(WS_LOG_DEBUG, "Invalid endpoint type");
        return NULL;
    }

    ctx = (WOLFSSH_CTX*)WMALLOC(sizeof(WOLFSSH_CTX), heap, DYNTYPE_CTX);
    ctx = CtxInit(ctx, heap);

    WLOG(WS_LOG_DEBUG, "Leaving wolfSSH_CTX_new(), ctx = %p", ctx);

    return ctx;
}


static void CtxResourceFree(WOLFSSH_CTX* ctx)
{
    WLOG(WS_LOG_DEBUG, "Enter CtxResourceFree()");
    if (ctx->privateKey) {
        WMEMSET(ctx->privateKey, 0, ctx->privateKeySz);
        WFREE(ctx->privateKey, heap, DYNTYPE_KEY);
    }
    WFREE(ctx->cert, heap, DYNTYPE_CERT);
    WFREE(ctx->caCert, heap, DYNTYPE_CA);
}


void wolfSSH_CTX_free(WOLFSSH_CTX* ctx)
{
    WLOG(WS_LOG_DEBUG, "Enter wolfSSH_CTX_free()");

    if (ctx) {
        CtxResourceFree(ctx);
        WFREE(ctx, ctx->heap, DYNTYPE_CTX);
    }
}


static WOLFSSH* SshInit(WOLFSSH* ssh, WOLFSSH_CTX* ctx)
{
    HandshakeInfo* handshake;
    RNG*           rng;

    WLOG(WS_LOG_DEBUG, "Enter SshInit()");

    if (ssh == NULL)
        return ssh;

    handshake = (HandshakeInfo*)WMALLOC(sizeof(HandshakeInfo),
                                        ctx->heap, DYNTYPE_HS);
    if (handshake == NULL) {
        wolfSSH_free(ssh);
        return NULL;
    }

    rng = (RNG*)WMALLOC(sizeof(RNG), ctx->heap, DYNTYPE_RNG);
    if (rng == NULL || InitRng(rng) != 0) {
        wolfSSH_free(ssh);
        return NULL;
    }

    WMEMSET(ssh, 0, sizeof(WOLFSSH));  /* default init to zeros */
    WMEMSET(handshake, 0, sizeof(HandshakeInfo));

    ssh->ctx         = ctx;
    ssh->error       = WS_SUCCESS;
    ssh->rfd         = -1;         /* set to invalid */
    ssh->wfd         = -1;         /* set to invalid */
    ssh->ioReadCtx   = &ssh->rfd;  /* prevent invalid access if not correctly */
    ssh->ioWriteCtx  = &ssh->wfd;  /* set */
    ssh->acceptState = ACCEPT_BEGIN;
    ssh->clientState = CLIENT_BEGIN;
    ssh->blockSz     = MIN_BLOCK_SZ;
    ssh->encryptId   = ID_NONE;
    ssh->macId       = ID_NONE;
    ssh->peerBlockSz = MIN_BLOCK_SZ;
    ssh->rng         = rng;
    ssh->kSz         = sizeof(ssh->k);
    ssh->handshake   = handshake;
    handshake->kexId = ID_NONE;
    handshake->pubKeyId  = ID_NONE;
    handshake->encryptId = ID_NONE;
    handshake->macId = ID_NONE;
    handshake->blockSz = MIN_BLOCK_SZ;

    if (BufferInit(&ssh->inputBuffer, 0, ctx->heap) != WS_SUCCESS ||
        BufferInit(&ssh->outputBuffer, 0, ctx->heap) != WS_SUCCESS ||
        InitSha(&ssh->handshake->hash) != 0) {

        wolfSSH_free(ssh);
        ssh = NULL;
    }

    return ssh;
}


WOLFSSH* wolfSSH_new(WOLFSSH_CTX* ctx)
{
    WOLFSSH* ssh;
    void*    heap = NULL;

    if (ctx)
        heap = ctx->heap;
    else {
        WLOG(WS_LOG_ERROR, "Trying to init a wolfSSH w/o wolfSSH_CTX");
        return NULL;
    }

    WLOG(WS_LOG_DEBUG, "Enter wolfSSH_new()");

    ssh = (WOLFSSH*)WMALLOC(sizeof(WOLFSSH), heap, DYNTYPE_SSH);
    ssh = SshInit(ssh, ctx);

    WLOG(WS_LOG_DEBUG, "Leaving wolfSSH_new(), ssh = %p", ssh);

    return ssh;
}


static void SshResourceFree(WOLFSSH* ssh, void* heap)
{
    /* when ssh holds resources, free here */
    (void)heap;

    WLOG(WS_LOG_DEBUG, "Enter sshResourceFree()");
    ShrinkBuffer(&ssh->inputBuffer, 1);
    ShrinkBuffer(&ssh->outputBuffer, 1);
    if (ssh->k) {
        WMEMSET(ssh->k, 0, ssh->kSz);
    }
    if (ssh->handshake) {
        WMEMSET(ssh->handshake, 0, sizeof(HandshakeInfo));
        WFREE(ssh->handshake, heap, DYNTYPE_HS);
    }
    if (ssh->rng) {
        /* FreeRng(ssh->rng); */
        WFREE(ssh->rng, heap, DYNTYPE_RNG);
    }
}


void wolfSSH_free(WOLFSSH* ssh)
{
    void* heap = ssh->ctx ? ssh->ctx->heap : NULL;
    WLOG(WS_LOG_DEBUG, "Enter wolfSSH_free()");

    if (ssh) {
        SshResourceFree(ssh, heap);
        WFREE(ssh, heap, DYNTYPE_SSH);
    }
}


int wolfSSH_set_fd(WOLFSSH* ssh, int fd)
{
    WLOG(WS_LOG_DEBUG, "Enter wolfSSH_set_fd()");

    if (ssh) {
        ssh->rfd = fd;
        ssh->wfd = fd;

        ssh->ioReadCtx  = &ssh->rfd;
        ssh->ioWriteCtx = &ssh->wfd;

        return WS_SUCCESS;
    }
    return WS_BAD_ARGUMENT;
}


int wolfSSH_get_fd(const WOLFSSH* ssh)
{
    WLOG(WS_LOG_DEBUG, "Enter wolfSSH_get_fd()");

    if (ssh)
        return ssh->rfd;

    return WS_BAD_ARGUMENT;
}


int wolfSSH_get_error(const WOLFSSH* ssh)
{
    WLOG(WS_LOG_DEBUG, "Enter wolfSSH_get_error()");
    if (ssh)
        return ssh->error;

    return WS_BAD_ARGUMENT;
}


const char* wolfSSH_get_error_name(const WOLFSSH* ssh)
{
    WLOG(WS_LOG_DEBUG, "Enter wolfSSH_get_error_name()");
    if (ssh)
        return GetErrorString(ssh->error);

    return NULL;
}


const char acceptError[] = "accept error: %s, %d";
const char acceptState[] = "accept state: %s";


int wolfSSH_accept(WOLFSSH* ssh)
{
    switch (ssh->acceptState) {
        case ACCEPT_BEGIN:
            while (ssh->clientState < CLIENT_VERSION_DONE) {
                if ( (ssh->error = ProcessClientVersion(ssh)) < WS_SUCCESS) {
                    WLOG(WS_LOG_DEBUG, acceptError, "BEGIN", ssh->error);
                    return WS_FATAL_ERROR;
                }
            }
            ssh->acceptState = ACCEPT_CLIENT_VERSION_DONE;
            WLOG(WS_LOG_DEBUG, acceptState, "CLIENT_VERSION_DONE");

        case ACCEPT_CLIENT_VERSION_DONE:
            if ( (ssh->error = SendServerVersion(ssh)) < WS_SUCCESS) {
                WLOG(WS_LOG_DEBUG, acceptError,
                     "CLIENT_VERSION_DONE", ssh->error);
                return WS_FATAL_ERROR;
            }
            ssh->acceptState = ACCEPT_SERVER_VERSION_SENT;
            WLOG(WS_LOG_DEBUG, acceptState, "SERVER_VERSION_SENT");

        case ACCEPT_SERVER_VERSION_SENT:
            while (ssh->clientState < CLIENT_KEXINIT_DONE) {
                if ( (ssh->error = ProcessReply(ssh)) < WS_SUCCESS) {
                    WLOG(WS_LOG_DEBUG, acceptError,
                         "SERVER_VERSION_SENT", ssh->error);
                    return WS_FATAL_ERROR;
                }
            }
            ssh->acceptState = ACCEPT_CLIENT_KEXINIT_DONE;
            WLOG(WS_LOG_DEBUG, acceptState, "CLIENT_KEXINIT_DONE");

        case ACCEPT_CLIENT_KEXINIT_DONE:
            if ( (ssh->error = SendKexInit(ssh)) < WS_SUCCESS) {
                WLOG(WS_LOG_DEBUG, acceptError,
                     "CLIENT_KEXINIT_DONE", ssh->error);
                return WS_FATAL_ERROR;
            }
            ssh->acceptState = ACCEPT_SERVER_KEXINIT_SENT;
            WLOG(WS_LOG_DEBUG, acceptState, "SERVER_KEXINIT_SENT");

        case ACCEPT_SERVER_KEXINIT_SENT:
            while (ssh->clientState < CLIENT_KEXDH_INIT_DONE) {
                if ( (ssh->error = ProcessReply(ssh)) < 0) {
                    WLOG(WS_LOG_DEBUG, acceptError,
                         "SERVER_KEXINIT_SENT", ssh->error);
                    return WS_FATAL_ERROR;
                }
            }
            ssh->acceptState = ACCEPT_CLIENT_KEXDH_INIT_DONE;
            WLOG(WS_LOG_DEBUG, acceptState, "CLIENT_KEXDH_INIT_DONE");

        case ACCEPT_CLIENT_KEXDH_INIT_DONE:
            if ( (ssh->error = SendKexDhReply(ssh)) < WS_SUCCESS) {
                WLOG(WS_LOG_DEBUG, acceptError,
                     "CLIENT_KEXDH_INIT_DONE", ssh->error);
                return WS_FATAL_ERROR;
            }
            ssh->acceptState = ACCEPT_SERVER_KEXDH_REPLY_SENT;
            WLOG(WS_LOG_DEBUG, acceptState, "SERVER_KEXDH_REPLY_SENT");

        case ACCEPT_SERVER_KEXDH_REPLY_SENT:
            while (ssh->clientState < CLIENT_USING_KEYS) {
                if ( (ssh->error = ProcessReply(ssh)) < 0) {
                    WLOG(WS_LOG_DEBUG, acceptError,
                         "SERVER_KEXDH_REPLY_SENT", ssh->error);
                    return WS_FATAL_ERROR;
                }
            }
            ssh->acceptState = ACCEPT_USING_KEYS;
            WLOG(WS_LOG_DEBUG, acceptState, "USING_KEYS");

        case ACCEPT_USING_KEYS:
            while (ssh->clientState < CLIENT_USERAUTH_DONE) {
                if ( (ssh->error = ProcessReply(ssh)) < 0) {
                    WLOG(WS_LOG_DEBUG, acceptError,
                         "USING_KEYS", ssh->error);
                    return WS_FATAL_ERROR;
                }
            }
            ssh->acceptState = ACCEPT_CLIENT_USERAUTH_DONE;
            WLOG(WS_LOG_DEBUG, acceptState, "CLIENT_USERAUTH_DONE");

        case ACCEPT_CLIENT_USERAUTH_DONE:
            while (ssh->clientState < CLIENT_DONE) {
                if ( (ssh->error = ProcessReply(ssh)) < 0) {
                    WLOG(WS_LOG_DEBUG, acceptError,
                         "CLIENT_USERAUTH_DONE", ssh->error);
                    return WS_FATAL_ERROR;
                }
            }
    }

    return WS_FATAL_ERROR;
}


static int ProcessBuffer(WOLFSSH_CTX* ctx, const uint8_t* in, uint32_t inSz,
                                                           int format, int type)
{
    int dynamicType;
    void* heap;
    uint8_t* der;
    uint32_t derSz;

    if (ctx == NULL || in == NULL || inSz == 0)
        return WS_BAD_ARGUMENT;

    if (format != WOLFSSH_FORMAT_ASN1 && format != WOLFSSH_FORMAT_PEM &&
                                         format != WOLFSSH_FORMAT_RAW)
        return WS_BAD_FILETYPE_E;

    if (type == BUFTYPE_CA)
        dynamicType = DYNTYPE_CA;
    else if (type == BUFTYPE_CERT)
        dynamicType = DYNTYPE_CERT;
    else if (type == BUFTYPE_PRIVKEY)
        dynamicType = DYNTYPE_KEY;
    else
        return WS_BAD_ARGUMENT;

    heap = ctx->heap;

    if (format == WOLFSSH_FORMAT_PEM)
        return WS_UNIMPLEMENTED_E;
    else {
        /* format is ASN1 or RAW */
        der = (uint8_t*)WMALLOC(inSz, heap, dynamicType);
        if (der == NULL)
            return WS_MEMORY_E;
        WMEMCPY(der, in, inSz);
        derSz = inSz;
    }

    /* Maybe decrypt */

    if (type == BUFTYPE_CERT) {
        if (ctx->cert)
            WFREE(ctx->cert, heap, dynamicType);
        ctx->cert = der;
        ctx->certSz = derSz;
    }
    else if (type == BUFTYPE_PRIVKEY) {
        if (ctx->privateKey)
            WFREE(ctx->privateKey, heap, dynamicType);
        ctx->privateKey = der;
        ctx->privateKeySz = derSz;
    }
    else {
        WFREE(der, heap, dynamicType);
        return WS_UNIMPLEMENTED_E;
    }

    if (type == BUFTYPE_PRIVKEY && format != WOLFSSH_FORMAT_RAW) {
        /* Check RSA key */
        RsaKey key;
        uint32_t scratch = 0;

        if (InitRsaKey(&key, NULL) < 0)
            return WS_RSA_E;

        if (RsaPrivateKeyDecode(der, &scratch, &key, derSz) < 0)
            return WS_BAD_FILE_E;

        FreeRsaKey(&key);
    }

    return WS_SUCCESS;
}


int wolfSSH_CTX_UsePrivateKey_buffer(WOLFSSH_CTX* ctx,
                                   const uint8_t* in, uint32_t inSz, int format)
{
    WLOG(WS_LOG_DEBUG, "Enter wolfSSH_CTX_use_private_key_buffer()");
    return ProcessBuffer(ctx, in, inSz, format, BUFTYPE_PRIVKEY); 
}


int wolfSSH_CTX_UseCert_buffer(WOLFSSH_CTX* ctx,
                                   const uint8_t* in, uint32_t inSz, int format)
{
    WLOG(WS_LOG_DEBUG, "Enter wolfSSH_CTX_use_certificate_buffer()");
    return ProcessBuffer(ctx, in, inSz, format, BUFTYPE_CERT);
}


int wolfSSH_CTX_UseCaCert_buffer(WOLFSSH_CTX* ctx,
                                   const uint8_t* in, uint32_t inSz, int format)
{
    WLOG(WS_LOG_DEBUG, "Enter wolfSSH_CTX_use_ca_certificate_buffer()");
    return ProcessBuffer(ctx, in, inSz, format, BUFTYPE_CA);
}



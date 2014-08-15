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
    /* when context holds resources, free here */
    (void)ctx;

    WLOG(WS_LOG_DEBUG, "Enter CtxResourceFree()");
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

    WLOG(WS_LOG_DEBUG, "Enter SshInit()");

    if (ssh == NULL)
        return ssh;

    handshake = (HandshakeInfo*)WMALLOC(sizeof(HandshakeInfo), ctx->heap, DYNTYPE_HS);
    if (handshake == NULL) {
        wolfSSH_free(ssh);
        return NULL;
    }

    WMEMSET(ssh, 0, sizeof(WOLFSSH));  /* default init to zeros */
    WMEMSET(handshake, 0, sizeof(HandshakeInfo));

    ssh->ctx         = ctx;
    ssh->rfd         = -1;         /* set to invalid */
    ssh->wfd         = -1;         /* set to invalid */
    ssh->ioReadCtx   = &ssh->rfd;  /* prevent invalid access if not correctly */
    ssh->ioWriteCtx  = &ssh->wfd;  /* set */
    ssh->blockSz     = 8;
    ssh->keyExchangeId = ID_NONE;
    ssh->publicKeyId   = ID_NONE;
    ssh->encryptionId  = ID_NONE;
    ssh->integrityId   = ID_NONE;
    ssh->handshake = handshake;
    handshake->keyExchangeId = ID_NONE;
    handshake->publicKeyId   = ID_NONE;
    handshake->encryptionId  = ID_NONE;
    handshake->integrityId   = ID_NONE;

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
    if (ssh->handshake) {
        XMEMSET(ssh->handshake, 0, sizeof(HandshakeInfo));
        XFREE(ssh->handshake, heap, DYNTYPE_HS);
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


int wolfSSH_accept(WOLFSSH* ssh)
{
    switch (ssh->acceptState) {
        case ACCEPT_BEGIN:
            while (ssh->clientState < CLIENT_VERSION_DONE) {
                if ( (ssh->error = ProcessClientVersion(ssh)) < 0) {
                    WLOG(WS_LOG_DEBUG, "accept reply error: %d", ssh->error);
                    return WS_FATAL_ERROR;
                }
            }
            ssh->acceptState = ACCEPT_CLIENT_VERSION_DONE;
            WLOG(WS_LOG_DEBUG, "accept state ACCEPT_CLIENT_VERSION_DONE");

        case ACCEPT_CLIENT_VERSION_DONE:
            SendServerVersion(ssh);
            ssh->acceptState = SERVER_VERSION_SENT;
            WLOG(WS_LOG_DEBUG, "accept state SERVER_VERSION_SENT");

        case SERVER_VERSION_SENT:
            while (ssh->clientState < CLIENT_ALGO_DONE) {
                if ( (ssh->error = ProcessReply(ssh)) < 0) {
                    WLOG(WS_LOG_DEBUG, "accept reply error: %d", ssh->error);
                    return WS_FATAL_ERROR;
                }
            }
            break;
    }

    return WS_FATAL_ERROR;
}


static int ProcessBuffer(WOLFSSH_CTX* ctx, const uint8_t* in, uint32_t inSz,
                                                           int format, int type)
{
    (void)ctx;
    (void)in;
    (void)inSz;
    (void)format;
    (void)type;

    return WS_SUCCESS;
}


int wolfSSH_CTX_use_private_key_buffer(WOLFSSH_CTX* ctx,
                                   const uint8_t* in, uint32_t inSz, int format)
{
    WLOG(WS_LOG_DEBUG, "Enter wolfSSH_CTX_use_private_key_buffer()");
    return ProcessBuffer(ctx, in, inSz, format, BUFTYPE_PRIVKEY); 
}


int wolfSSH_CTX_use_cert_buffer(WOLFSSH_CTX* ctx,
                                   const uint8_t* in, uint32_t inSz, int format)
{
    WLOG(WS_LOG_DEBUG, "Enter wolfSSH_CTX_use_certificate_buffer()");
    return ProcessBuffer(ctx, in, inSz, format, BUFTYPE_CERT);
}


int wolfSSH_CTX_use_ca_cert_buffer(WOLFSSH_CTX* ctx,
                                   const uint8_t* in, uint32_t inSz, int format)
{
    WLOG(WS_LOG_DEBUG, "Enter wolfSSH_CTX_use_ca_certificate_buffer()");
    return ProcessBuffer(ctx, in, inSz, format, BUFTYPE_CA);
}



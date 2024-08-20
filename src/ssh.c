/* ssh.c
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


/*
 * The ssh module contains the public API for wolfSSH.
 */


#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssh/ssh.h>
#include <wolfssh/internal.h>
#include <wolfssh/log.h>
#include <wolfssl/wolfcrypt/wc_port.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/random.h>

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
#ifdef WC_RNG_SEED_CB
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


int wolfSSH_SetHighwater(WOLFSSH* ssh, word32 highwater)
{
    WLOG(WS_LOG_DEBUG, "Entering wolfSSH_SetHighwater()");

    if (ssh) {
        ssh->highwaterMark = highwater;

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


void wolfSSH_SetHighwaterCb(WOLFSSH_CTX* ctx, word32 highwater,
                            WS_CallbackHighwater cb)
{
    WLOG(WS_LOG_DEBUG, "Entering wolfSSH_SetHighwaterCb()");

    if (ctx) {
        ctx->highwaterMark = highwater;
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


#ifndef NO_WOLFSSH_SERVER

const char acceptError[] = "accept error: %s, %d";
const char acceptState[] = "accept state: %s";


int wolfSSH_accept(WOLFSSH* ssh)
{
    WLOG(WS_LOG_DEBUG, "Entering wolfSSH_accept()");

    if (ssh == NULL)
        return WS_BAD_ARGUMENT;

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
                NO_BREAK;

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
                NO_BREAK;

            case ACCEPT_CLIENT_VERSION_DONE:
                if ( (ssh->error = SendKexInit(ssh)) < WS_SUCCESS) {
                    WLOG(WS_LOG_DEBUG, acceptError,
                         "CLIENT_VERSION_DONE", ssh->error);
                    return WS_FATAL_ERROR;
                }
                ssh->acceptState = ACCEPT_SERVER_KEXINIT_SENT;
                WLOG(WS_LOG_DEBUG, acceptState, "SERVER_KEXINIT_SENT");
                NO_BREAK;

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
                NO_BREAK;

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
                NO_BREAK;

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
                NO_BREAK;

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
                NO_BREAK;

            case ACCEPT_CLIENT_USERAUTH_DONE:
                if ( (ssh->error = SendUserAuthSuccess(ssh)) < WS_SUCCESS) {
                    WLOG(WS_LOG_DEBUG, acceptError,
                         "CLIENT_USERAUTH_DONE", ssh->error);
                    return WS_FATAL_ERROR;
                }
                ssh->acceptState = ACCEPT_SERVER_USERAUTH_SENT;
                WLOG(WS_LOG_DEBUG, acceptState, "SERVER_USERAUTH_SENT");
                NO_BREAK;

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
                NO_BREAK;

            case ACCEPT_SERVER_CHANNEL_ACCEPT_SENT:
                while (ssh->clientState < CLIENT_DONE) {
                    if (DoReceive(ssh) < 0) {
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
            NO_BREAK;

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
            NO_BREAK;

        case CONNECT_SERVER_VERSION_DONE:
            if ( (ssh->error = SendKexInit(ssh)) < WS_SUCCESS) {
                WLOG(WS_LOG_DEBUG, connectError,
                     "SERVER_VERSION_DONE", ssh->error);
                return WS_FATAL_ERROR;
            }
            ssh->connectState = CONNECT_CLIENT_KEXINIT_SENT;
            WLOG(WS_LOG_DEBUG, connectState, "CLIENT_KEXINIT_SENT");
            NO_BREAK;

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
            NO_BREAK;

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
            NO_BREAK;

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
            NO_BREAK;

        case CONNECT_KEYED:
            if ( (ssh->error = SendServiceRequest(ssh, ID_SERVICE_USERAUTH)) <
                                                                  WS_SUCCESS) {
                WLOG(WS_LOG_DEBUG, connectError, "KEYED", ssh->error);
                return WS_FATAL_ERROR;
            }
            ssh->connectState = CONNECT_CLIENT_USERAUTH_REQUEST_SENT;
            WLOG(WS_LOG_DEBUG, connectState, "CLIENT_USERAUTH_REQUEST_SENT");
            NO_BREAK;

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
            NO_BREAK;

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
            NO_BREAK;

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
            NO_BREAK;

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
            NO_BREAK;

        case CONNECT_CLIENT_CHANNEL_OPEN_SESSION_SENT:
            while (ssh->serverState < SERVER_CHANNEL_OPEN_DONE) {
                if (DoReceive(ssh) < WS_SUCCESS) {
                    WLOG(WS_LOG_DEBUG, connectError,
                         "CLIENT_CHANNEL_OPEN_SESSION_SENT", ssh->error);
                    return WS_FATAL_ERROR;
                }
            }
            ssh->connectState = CONNECT_SERVER_CHANNEL_OPEN_SESSION_DONE;
            WLOG(WS_LOG_DEBUG, connectState,
                 "SERVER_CHANNEL_OPEN_SESSION_DONE");
            NO_BREAK;

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
            NO_BREAK;

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
            NO_BREAK;

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
            NO_BREAK;

        case CONNECT_CLIENT_CHANNEL_REQUEST_SENT:
            while (ssh->serverState < SERVER_DONE) {
                if (DoReceive(ssh) < WS_SUCCESS) {
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


int wolfSSH_shutdown(WOLFSSH* ssh)
{
    int ret = WS_SUCCESS;
    WOLFSSH_CHANNEL* channel = NULL;

    WLOG(WS_LOG_DEBUG, "Entering wolfSSH_shutdown()");

    if (ssh == NULL || ssh->channelList == NULL)
        ret = WS_BAD_ARGUMENT;

    /* look up the channel if it still exists */
    if (ret == WS_SUCCESS) {
        channel = ChannelFind(ssh, ssh->channelList->peerChannel, WS_CHANNEL_ID_SELF);
    }

    /* if channel close was not already sent then send it */
    if (channel != NULL && !channel->closeTxd) {
       if (ret == WS_SUCCESS) {
           ret = SendChannelEof(ssh, ssh->channelList->peerChannel);
       }

       /* continue on success and in case where queing up send packets */
       if (ret == WS_SUCCESS ||
               (ret != WS_BAD_ARGUMENT && ssh->error == WS_WANT_WRITE)) {
           ret = SendChannelExit(ssh, ssh->channelList->peerChannel,
           #if defined(WOLFSSH_TERM) || defined(WOLFSSH_SHELL)
               ssh->exitStatus);
           #else
               0);
           #endif
       }

       /* continue on success and in case where queing up send packets */
       if (ret == WS_SUCCESS ||
               (ret != WS_BAD_ARGUMENT && ssh->error == WS_WANT_WRITE))
           ret = SendChannelClose(ssh, ssh->channelList->peerChannel);
    }


    /* if the channel was not yet removed then read to get
     * response to SendChannelClose */
    if (channel != NULL && ret == WS_SUCCESS) {
        ret = wolfSSH_worker(ssh, NULL);
    }

    if (ssh != NULL && ssh->channelList == NULL) {
        WLOG(WS_LOG_DEBUG, "channel list was already removed");
        ret = WS_CHANNEL_CLOSED;
    }

    WLOG(WS_LOG_DEBUG, "Leaving wolfSSH_shutdown(), ret = %d", ret);
    return ret;
}


int wolfSSH_TriggerKeyExchange(WOLFSSH* ssh)
{
    int ret = WS_SUCCESS;

    WLOG(WS_LOG_DEBUG, "Entering wolfSSH_TriggerKeyExchange()");
    if (ssh == NULL)
        ret = WS_BAD_ARGUMENT;

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

    WLOG(WS_LOG_DEBUG, "Entering wolfSSH_stream_peek()");

    if (ssh == NULL || ssh->channelList == NULL)
        return WS_BAD_ARGUMENT;

    if (ssh->isKeying) {
        ssh->error = WS_REKEYING;
        return WS_REKEYING;
    }
    if (ssh->channelList->eofRxd) {
        ssh->error = WS_EOF;
        return WS_ERROR;
    }

    inputBuffer = &ssh->channelList->inputBuffer;
    bufSz = min(bufSz, inputBuffer->length - inputBuffer->idx);
    if (buf != NULL) {
        WMEMCPY(buf, inputBuffer->buffer + inputBuffer->idx, bufSz);
    }
    return bufSz;
}


static int _UpdateChannelWindow(WOLFSSH_CHANNEL* channel);


/* Wrapper function for ease of use to get data after it has been decrypted from
 * the SSH connection. This function handles low level operations in addition to
 * the read, such as window adjustment and high water checking.
 *
 * In non blocking mode use the function wolfSSH_get_error(ssh) to check for
 * WS_WANT_READ / WS_WANT_WRITE after a fail case was hit with
 * wolfSSH_stream_read().
 *
 * Returns the number of bytes read on success, negative values on fail
 */
int wolfSSH_stream_read(WOLFSSH* ssh, byte* buf, word32 bufSz)
{
    int ret = WS_SUCCESS;
    WOLFSSH_BUFFER* inputBuffer;

    WLOG(WS_LOG_DEBUG, "Entering wolfSSH_stream_read()");

    if (ssh == NULL || buf == NULL || bufSz == 0 || ssh->channelList == NULL)
        return WS_BAD_ARGUMENT;

    if (ssh->channelList->eofRxd) {
        ssh->error = WS_EOF;
        return WS_ERROR;
    }

    inputBuffer = &ssh->channelList->inputBuffer;
    ssh->error = WS_SUCCESS;

    if (ret == WS_SUCCESS) {
        WLOG(WS_LOG_DEBUG, "    Stream read index of %u", inputBuffer->idx);
        WLOG(WS_LOG_DEBUG, "    Stream read ava data %u", inputBuffer->length);
        while (inputBuffer->length - inputBuffer->idx == 0) {
            WLOG(WS_LOG_DEBUG,
                    "Starting to recieve data at current index of %u",
                    inputBuffer->idx);
            ret = DoReceive(ssh);
            if (ssh->channelList == NULL || ssh->channelList->eofRxd)
                ret = WS_EOF;
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

    /* update internal input buffer based on data read */
    if (ret == WS_SUCCESS) {
        int n;

        n = min(bufSz, inputBuffer->length - inputBuffer->idx);
        if (n <= 0)
            ret = WS_BUFFER_E;
        else {
            WMEMCPY(buf, inputBuffer->buffer + inputBuffer->idx, n);
            ret = _UpdateChannelWindow(ssh->channelList);
            if (ret == WS_SUCCESS) {
                inputBuffer->idx += n;
                ret = n;
            }
        }
    }

    WLOG(WS_LOG_DEBUG, "Leaving wolfSSH_stream_read(), rxd = %d", ret);
    return ret;
}


int wolfSSH_stream_send(WOLFSSH* ssh, byte* buf, word32 bufSz)
{
    int bytesTxd = 0;

    WLOG(WS_LOG_DEBUG, "Entering wolfSSH_stream_send()");

    if (ssh == NULL || buf == NULL || ssh->channelList == NULL)
        return WS_BAD_ARGUMENT;

    if (ssh->isKeying) {
        ssh->error = WS_REKEYING;
        return WS_REKEYING;
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


int wolfSSH_stream_exit(WOLFSSH* ssh, int status)
{
    int ret = WS_SUCCESS;

    WLOG(WS_LOG_DEBUG, "Entering wolfSSH_stream_exit(), status = %d", status);

    if (ssh == NULL || ssh->channelList == NULL)
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
    WLOG(WS_LOG_DEBUG, "Entering wolfSSH_global_request");
    if (ssh == NULL || data == NULL)
        return WS_BAD_ARGUMENT;
    if (reply != 0 && reply != 1)
        return WS_BAD_ARGUMENT;
    return SendGlobalRequest(ssh, data, dataSz, reply);
}


int wolfSSH_extended_data_send(WOLFSSH* ssh, byte* buf, word32 bufSz)
{
    int bytesTxd = 0;

    WLOG(WS_LOG_DEBUG, "Entering wolfSSH_extended_data_send()");

    if (ssh == NULL || buf == NULL || ssh->channelList == NULL)
        return WS_BAD_ARGUMENT;

    if (ssh->isKeying) {
        ssh->error = WS_REKEYING;
        return WS_REKEYING;
    }

    bytesTxd = SendChannelExtendedData(ssh, ssh->channelList->channel, buf, bufSz);

    WLOG(WS_LOG_DEBUG, "Leaving wolfSSH_extended_data_send(), txd = %d", bytesTxd);
    return bytesTxd;
}


/* Reads pending data from extended data buffer. Currently can be used to get
 * STDERR information sent across the channel.
 * Returns the number of bytes read on success */
int wolfSSH_extended_data_read(WOLFSSH* ssh, byte* out, word32 outSz)
{
    byte*  buf;
    word32 bufSz;

    if (ssh == NULL || out == NULL) {
        return WS_BAD_ARGUMENT;
    }

    /* sanity check to make sure idx is not in a bad state */
    if (ssh->extDataBuffer.idx > ssh->extDataBuffer.length) {
        WLOG(WS_LOG_ERROR, "Bad internal state for buffer index");
        return WS_INVALID_STATE_E;
    }
    bufSz = min(outSz, ssh->extDataBuffer.length - ssh->extDataBuffer.idx);
    buf = ssh->extDataBuffer.buffer + ssh->extDataBuffer.idx;
    WMEMCPY(out, buf, bufSz);
    ssh->extDataBuffer.idx += bufSz;
    return bufSz;
}


int wolfSSH_SendIgnore(WOLFSSH* ssh, const byte* buf, word32 bufSz)
{
    byte scratch[128];

    WOLFSSH_UNUSED(buf);
    WOLFSSH_UNUSED(bufSz);
    WMEMSET(scratch, 0, sizeof(scratch));

    return SendIgnore(ssh, scratch, sizeof(scratch));
}


int wolfSSH_SendDisconnect(WOLFSSH *ssh, word32 reason)
{
    WLOG(WS_LOG_DEBUG, "Entering wolfSSH_SendDisconnect");
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
 * returns WS_SUCCESS on success
 */
int wolfSSH_SetChannelType(WOLFSSH* ssh, byte type, byte* name, word32 nameSz)
{
    if (ssh == NULL) {
        return WS_BAD_ARGUMENT;
    }

    switch (type) {
        case WOLFSSH_SESSION_SHELL:
            ssh->connectChannelId = type;
            break;

        case WOLFSSH_SESSION_EXEC:
            if (ssh->ctx->side == WOLFSSH_ENDPOINT_SERVER) {
                WLOG(WS_LOG_DEBUG, "Server side exec unsupported");
                return WS_BAD_ARGUMENT;
            }
            NO_BREAK;

        case WOLFSSH_SESSION_SUBSYSTEM:
            ssh->connectChannelId = type;
            if (name != NULL && nameSz < WOLFSSH_MAX_CHN_NAMESZ) {
                WMEMCPY(ssh->channelName, name, nameSz);
                ssh->channelNameSz = nameSz;
            }
            else {
                WLOG(WS_LOG_DEBUG, "No subsystem name or name was too large");
            }
            break;

#ifdef WOLFSSH_TERM
        case WOLFSSH_SESSION_TERMINAL:
            /* send a pseudo-terminal request and shell channel */
            ssh->sendTerminalRequest = 1;
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

union wolfSSH_key {
#ifndef WOLFSSH_NO_RSA
    RsaKey rsa;
#endif
#ifndef WOLFSSH_NO_ECDSA
    ecc_key ecc;
#endif
};

static const char* PrivBeginOpenSSH = "-----BEGIN OPENSSH PRIVATE KEY-----";
static const char* PrivEndOpenSSH = "-----END OPENSSH PRIVATE KEY-----";

#if !defined(NO_FILESYSTEM) && !defined(WOLFSSH_USER_FILESYSTEM)
    /* currently only used in wolfSSH_ReadKey_file() */
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
    */
    c = WSTRDUP((const char*)in, heap, DYNTYPE_STRING);
    if (c != NULL) {
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
        void* heap)
{
    int ret = WS_SUCCESS;
    byte* newKey = NULL;

    WOLFSSH_UNUSED(heap);

    if (*out == NULL) {
        newKey = (byte*)WMALLOC(inSz, heap, DYNTYPE_PRIVKEY);
        if (newKey == NULL) {
            return WS_MEMORY_E;
        }
    }
    else {
        if (*outSz < inSz) {
            WLOG(WS_LOG_DEBUG, "DER private key output size too small");
            return WS_BUFFER_E;
        }
        newKey = *out;
    }

    ret = IdentifyAsn1Key(in, inSz, 1, heap);

    if (ret > 0) {
        *out = newKey;
        *outSz = inSz;
        WMEMCPY(newKey, in, inSz);
        *outType = (const byte*)IdToName(ret);
        *outTypeSz = (word32)WSTRLEN((const char*)*outType);
        ret = WS_SUCCESS;
    }
    else {
        WLOG(WS_LOG_DEBUG, "Unable to identify ASN.1 key");
        if (*out == NULL) {
            WFREE(newKey, heap, DYNTYPE_PRIVKEY);
        }
    }

    return ret;
}


static int DoPemKey(const byte* in, word32 inSz, byte** out,
        word32* outSz, const byte** outType, word32* outTypeSz,
        void* heap)
{
    int ret = WS_SUCCESS;
    byte* newKey = NULL;
    word32 newKeySz = inSz; /* binary will be smaller than PEM */

    WOLFSSH_UNUSED(heap);

    if (*out == NULL) {
        newKey = (byte*)WMALLOC(inSz, heap, DYNTYPE_PRIVKEY);
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
    }

    /* If it is PEM, convert to ASN1 then process. */
    ret = wc_KeyPemToDer(in, inSz, newKey, newKeySz, NULL);
    if (ret > 0) {
        newKeySz = (word32)ret;
        ret = WS_SUCCESS;
    }
    else {
        WLOG(WS_LOG_DEBUG, "Base64 decode of public key failed.");
        ret = WS_PARSE_E;
    }

    if (ret == WS_SUCCESS) {
        ret = IdentifyAsn1Key(newKey, newKeySz, 1, heap);
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
    }

    in += WSTRLEN(PrivBeginOpenSSH);
    inSz -= (word32)(WSTRLEN(PrivBeginOpenSSH) + WSTRLEN(PrivEndOpenSSH) + 2);

    ret = Base64_Decode((byte*)in, inSz, newKey, &newKeySz);
    if (ret == 0) {
        ret = WS_SUCCESS;
    }
    else {
        WLOG(WS_LOG_DEBUG, "Base64 decode of public key failed.");
        ret = WS_PARSE_E;
    }

    if (ret == WS_SUCCESS) {
        ret = IdentifyOpenSshKey(newKey, newKeySz, heap);
    }

    if (ret > 0) {
        *out = newKey;
        *outSz = newKeySz;
        *outType = (const byte*)IdToName(ret);
        *outTypeSz = (word32)WSTRLEN((const char*)*outType);
        ret = WS_SUCCESS;
    }
    else {
        WLOG(WS_LOG_DEBUG, "Unable to identify key");
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
int wolfSSH_ReadKey_buffer(const byte* in, word32 inSz, int format,
        byte** out, word32* outSz, const byte** outType, word32* outTypeSz,
        void* heap)
{
    int ret = WS_SUCCESS;

    if (in == NULL || inSz == 0 || out == NULL || outSz == NULL ||
            outType == NULL || outTypeSz == NULL)
        return WS_BAD_ARGUMENT;

    if (format == WOLFSSH_FORMAT_SSH) {
        ret = DoSshPubKey(in, inSz, out, outSz, outType, outTypeSz, heap);
    }
    else if (format == WOLFSSH_FORMAT_ASN1) {
        ret = DoAsn1Key(in, inSz, out, outSz, outType, outTypeSz, heap);
    }
    else if (format == WOLFSSH_FORMAT_PEM) {
        ret = DoPemKey(in, inSz, out, outSz, outType, outTypeSz, heap);
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


#if !defined(NO_FILESYSTEM) && !defined(WOLFSSH_USER_FILESYSTEM)

/* Reads a key from the file name into a buffer. If the key starts with the
   string "ssh-rsa" or "ecdsa-sha2-nistp256", it is considered an SSH format
   public key, if it has "----BEGIN" it is considered PEM formatted,
   otherwise it is considered an ASN.1 private key. The buffer is passed to
   wolfSSH_ReadKey_buffer() for processing. */
int wolfSSH_ReadKey_file(const char* name,
        byte** out, word32* outSz, const byte** outType, word32* outTypeSz,
        byte* isPrivate, void* heap)
{
    WFILE* file;
    byte* in;
    word32 inSz;
    int format;
    int ret;

    if (name == NULL)
        return WS_BAD_FILE_E;

    if (out == NULL || outSz == NULL || outType == NULL || outTypeSz == NULL ||
            isPrivate == NULL)
        return WS_BAD_ARGUMENT;

    ret = WFOPEN(NULL, &file, name, "rb");
    if (ret != 0 || file == WBADFILE) return WS_BAD_FILE_E;
    if (WFSEEK(NULL, file, 0, WSEEK_END) != 0) {
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
    if (ret <= 0 || (word32)ret != inSz) {
        ret = WS_BAD_FILE_E;
    }
    else {
        if (WSTRNSTR((const char*)in, "ssh-rsa", inSz) == (const char*)in
                || WSTRNSTR((const char*)in,
                    "ecdsa-sha2-nistp", inSz) == (const char*)in
                || WSTRNSTR((const char*)in,
                    "ssh-ed25519", inSz) == (const char*)in) {
            *isPrivate = 0;
            format = WOLFSSH_FORMAT_SSH;
            in[inSz] = 0;
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

        ret = wolfSSH_ReadKey_buffer(in, inSz, format,
                out, outSz, outType, outTypeSz, heap);
    }

    WFCLOSE(ssh->fs, file);
    WFREE(in, heap, DYNTYPE_FILE);

    return ret;
}

#endif


int wolfSSH_CTX_SetAlgoListKex(WOLFSSH_CTX* ctx, const char* list)
{
    int ret = WS_SSH_CTX_NULL_E;

    if (ctx) {
        ctx->algoListKex = list;
        ret = WS_SUCCESS;
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
        ssh->algoListKex = list;
        ret = WS_SUCCESS;
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
        ctx->algoListKey = list;
        ret = WS_SUCCESS;
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
        ssh->algoListKey = list;
        ret = WS_SUCCESS;
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
        ctx->algoListCipher = list;
        ret = WS_SUCCESS;
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
        ssh->algoListCipher = list;
        ret = WS_SUCCESS;
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
        ctx->algoListMac = list;
        ret = WS_SUCCESS;
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
        ssh->algoListMac = list;
        ret = WS_SUCCESS;
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
        ctx->algoListKeyAccepted = list;
        ret = WS_SUCCESS;
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
        ssh->algoListKeyAccepted = list;
        ret = WS_SUCCESS;
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


const char* wolfSSH_QueryKex(word32* index)
{
    return NameByIndexType(TYPE_KEX, index);
}


const char* wolfSSH_QueryKey(word32* index)
{
    return NameByIndexType(TYPE_KEY, index);
}


const char* wolfSSH_QueryCipher(word32* index)
{
    return NameByIndexType(TYPE_CIPHER, index);
}


const char* wolfSSH_QueryMac(word32* index)
{
    return NameByIndexType(TYPE_MAC, index);
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

int wolfSSH_CTX_SetSshProtoIdStr(WOLFSSH_CTX* ctx,
                                          const char* protoIdStr)
{
    if (!ctx || !protoIdStr) {
        return WS_BAD_ARGUMENT;
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


/* Add a CA for verifiying the peer's certificate with.
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

#endif /* WOLFSSH_CERTS */


int wolfSSH_CTX_SetWindowPacketSize(WOLFSSH_CTX* ctx,
                                    word32 windowSz, word32 maxPacketSz)
{
    WLOG(WS_LOG_DEBUG, "Entering wolfSSH_CTX_SetWindowPacketSize()");

    if (ctx == NULL)
        return WS_BAD_ARGUMENT;

    if (windowSz == 0)
        windowSz = DEFAULT_WINDOW_SZ;
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

    /* Attempt to send any data pending in the outputBuffer. */
    if (ret == WS_SUCCESS) {
        if (ssh->outputBuffer.length != 0)
            ret = wolfSSH_SendPacket(ssh);
    }

    /* Attempt to receive data from the peer. */
    if (ret == WS_SUCCESS) {
        ret = DoReceive(ssh);
    }

    if (ret == WS_SUCCESS) {
        if (channelId != NULL) {
            *channelId = ssh->lastRxId;
        }

        if (ssh->isKeying) {
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

        sendResult = SendChannelWindowAdjust(channel->ssh, channel->channel,
                                             bytesToAdd);

        WLOG(WS_LOG_INFO, "  bytesToAdd = %u", bytesToAdd);
        WLOG(WS_LOG_INFO, "  windowSz = %u", channel->windowSz);
        channel->windowSz += bytesToAdd;
        WLOG(WS_LOG_INFO, "  update windowSz = %u", channel->windowSz);

        inputBuffer->length = usedSz;
        inputBuffer->idx = 0;
    }

    return sendResult;
}


static int _ChannelRead(WOLFSSH_CHANNEL* channel, byte* buf, word32 bufSz)
{
    WOLFSSH_BUFFER* inputBuffer;
    int updateResult = WS_SUCCESS;

    if (channel == NULL || buf == NULL || bufSz == 0)
        return WS_BAD_ARGUMENT;

    inputBuffer = &channel->inputBuffer;
    bufSz = min(bufSz, inputBuffer->length - inputBuffer->idx);
    WMEMCPY(buf, inputBuffer->buffer + inputBuffer->idx, bufSz);
    inputBuffer->idx += bufSz;

    updateResult = _UpdateChannelWindow(channel);
    if (updateResult == WS_SUCCESS)
        updateResult = bufSz;

    return updateResult;
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

    bufSz = _ChannelRead(channel, buf, bufSz);

    WLOG(WS_LOG_DEBUG, "Leaving wolfSSH_ChannelRead(), bytesRxd = %d",
            bufSz);
    return bufSz;
}


int wolfSSH_ChannelSend(WOLFSSH_CHANNEL* channel,
        const byte* buf, word32 bufSz)
{
    int bytesTxd = 0;

    WLOG(WS_LOG_DEBUG, "Entering wolfSSH_ChannelSend(), ID = %d, peerID = %d",
            channel->channel, channel->peerChannel);

#ifdef DEBUG_WOLFSSH
    DumpOctetString(buf, bufSz);
#endif
    if (channel == NULL || buf == NULL)
        bytesTxd = WS_BAD_ARGUMENT;
    else if (!channel->openConfirmed) {
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


int wolfSSH_ChannelExit(WOLFSSH_CHANNEL* channel)
{
    int ret = WS_SUCCESS;

    WLOG(WS_LOG_DEBUG, "Entering wolfSSH_ChannelExit()");

    if (channel == NULL)
        ret = WS_BAD_ARGUMENT;

    if (ret == WS_SUCCESS)
        ret = SendChannelEof(channel->ssh, channel->peerChannel);

    if (ret == WS_SUCCESS)
        ret = SendChannelClose(channel->ssh, channel->peerChannel);

    if (ret == WS_SUCCESS)
        ret = ChannelRemove(channel->ssh,
                channel->peerChannel, WS_CHANNEL_ID_PEER);

    WLOG(WS_LOG_DEBUG, "Leaving wolfSSH_ChannelExit(), ret = %d", ret);
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
                case ID_ECDH_SHA2_ED25519:
                case ID_ECDH_SHA2_ED25519_LIBSSH:
            #ifndef WOLFSSH_NO_CURVE25519_SHA256
                case ID_CURVE25519_SHA256:
            #endif
                    ret = WSNPRINTF(str, strSz, "%s", "ECDH");
                    break;

            #ifndef WOLFSSH_NO_ECDH_NISTP256_KYBER_LEVEL1_SHA256
                case ID_ECDH_NISTP256_KYBER_LEVEL1_SHA256:
                    ret = WSNPRINTF(str, strSz, "%s", "ECDH-KYBER512");
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

                case ID_DH_GEX_SHA256:
                    ret = WSNPRINTF(str, strSz,
                        "%d-bit Diffie-Hellman with server-supplied group",
                        ssh->primeGroupSz*8);
                    break;
            #endif /* !WOLFSSH_NO_DH */

                case ID_EXTINFO_S:
                    ret = WSNPRINTF(str, strSz, "Server extensions KEX");
                    break;

                case ID_EXTINFO_C:
                    ret = WSNPRINTF(str, strSz, "Client extensions KEX");
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


WS_SessionType wolfSSH_ChannelGetSessionType(const WOLFSSH_CHANNEL* channel)
{
    WS_SessionType type = WOLFSSH_SESSION_UNKNOWN;

    WLOG(WS_LOG_DEBUG, "Entering wolfSSH_ChannelGetType()");

    if (channel) {
        type = (WS_SessionType)channel->sessionType;
    }

    return type;
}


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

#define DELIM "/\\"
#define IS_DELIM(x) ((x) == '/' || (x) == '\\')
#define IS_WINPATH(x,y) ((x) > 1 && (y)[1] == ':')

/*
 * Paths starting with a slash are absolute, rooted at "/". Any path that
 * doesn't have a starting slash is assumed to be relative to the default
 * path. If the path is empty, return the default path.
 *
 * The path "/." is stripped out. The path "/.." strips out the previous
 * path value. The root path, "/", is always present.
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
    if (inSz == 0 || (!IS_DELIM(in[0]) && !IS_WINPATH(inSz, in))) {
        if (defaultPath != NULL) {
            curSz = (word32)WSTRLEN(defaultPath);
            if (curSz >= outSz) {
                return WS_INVALID_PATH_E;
            }
            WSTRNCPY(out, defaultPath, outSz);
        }
    }
    out[curSz] = 0;

    for (seg = WSTRTOK(in, DELIM, &tail);
            seg;
            seg = WSTRTOK(NULL, DELIM, &tail)) {
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
            if (curSz >= outSz - segSz) {
                return WS_INVALID_PATH_E;
            }

            if (curSz != 1) {
                WSTRNCAT(out, "/", outSz - curSz);
                curSz++;
            }
            WSTRNCAT(out, seg, outSz - curSz);
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
    fprintf(stderr, "  sizeof(struct %s) = %u\n", "Buffer",
            (word32)sizeof(struct Buffer));
    #ifdef WOLFSSH_SFTP
        wolfSSH_SFTP_ShowSizes();
    #endif
}

#endif /* WOLFSSH_SHOW_SIZES */

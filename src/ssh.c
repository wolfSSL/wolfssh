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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */


#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssh/ssh.h>
#include <wolfssh/internal.h>
#include <wolfssh/log.h>


/* convert opaque to 32 bit integer */
static /*INLINE*/ void ato32(const uint8_t* c, uint32_t* u32)
{
    *u32 = (c[0] << 24) | (c[1] << 16) | (c[2] << 8) | c[3];
}


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


WOLFSSH_CTX* wolfSSH_CTX_new(void* heap)
{
    WOLFSSH_CTX* ctx;

    WLOG(WS_LOG_DEBUG, "Enter wolfSSH_CTX_new()");

    ctx = (WOLFSSH_CTX*)WMALLOC(sizeof(WOLFSSH_CTX), heap, WOLFSSH_CTX_TYPE);
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
        WFREE(ctx, ctx->heap, WOLFSSH_CTX_TYPE);
    }
}


static WOLFSSH* SshInit(WOLFSSH* ssh, WOLFSSH_CTX* ctx)
{
    WLOG(WS_LOG_DEBUG, "Enter SshInit()");

    if (ssh == NULL)
        return ssh;

    WMEMSET(ssh, 0, sizeof(WOLFSSH));  /* default init to zeros */

    if (ctx)
        ssh->ctx = ctx;
    else {
        WLOG(WS_LOG_ERROR, "Trying to init a wolfSSH w/o wolfSSH_CTX");
        wolfSSH_free(ssh);
        return NULL;
    }

    ssh->rfd         = -1;         /* set to invalid */
    ssh->wfd         = -1;         /* set to invalid */
    ssh->ioReadCtx   = &ssh->rfd;  /* prevent invalid access if not correctly */
    ssh->ioWriteCtx  = &ssh->wfd;  /* set */
    ssh->blockSz     = 8;
    ssh->inputBuffer = BufferNew(0, ctx->heap);
    ssh->outputBuffer = BufferNew(0, ctx->heap);

    return ssh;
}


WOLFSSH* wolfSSH_new(WOLFSSH_CTX* ctx)
{
    WOLFSSH* ssh;
    void*    heap = NULL;

    if (ctx)
        heap = ctx->heap;

    WLOG(WS_LOG_DEBUG, "Enter wolfSSH_new()");

    ssh = (WOLFSSH*)WMALLOC(sizeof(WOLFSSH), heap, WOLFSSH_TYPE);
    ssh = SshInit(ssh, ctx);

    WLOG(WS_LOG_DEBUG, "Leaving wolfSSH_new(), ssh = %p", ssh);

    return ssh;
}


static void SshResourceFree(WOLFSSH* ssh, void* heap)
{
    /* when ssh holds resources, free here */
    (void)heap;

    WLOG(WS_LOG_DEBUG, "Enter sshResourceFree()");
    WFREE(ssh->peerId, heap, WOLFSSH_ID_TYPE);
    BufferFree(ssh->inputBuffer);
    BufferFree(ssh->outputBuffer);
}


void wolfSSH_free(WOLFSSH* ssh)
{
    void* heap = ssh->ctx ? ssh->ctx->heap : NULL;
    WLOG(WS_LOG_DEBUG, "Enter wolfSSH_free()");

    if (ssh) {
        SshResourceFree(ssh, heap);
        WFREE(ssh, heap, WOLFSSH_TYPE);
    }
}


static WOLFSSH_CHAN* SshChanInit(WOLFSSH_CHAN* chan, WOLFSSH* ssh)
{
    WLOG(WS_LOG_DEBUG, "Enter SshChanInit()");

    if (chan == NULL)
        return chan;

    WMEMSET(chan, 0, sizeof(WOLFSSH_CHAN));  /* default init to zeros */

    if (ssh) {
        chan->ssh = ssh;
        chan->ctx = ssh->ctx;
    }
    else {
        WLOG(WS_LOG_ERROR, "Trying to init a wolfSSH_CHAN w/o wolfSSH");
        wolfSSH_CHAN_free(chan);
        return NULL; 
    }

    return chan;
}


WOLFSSH_CHAN* wolfSSH_CHAN_new(WOLFSSH* ssh)
{
    WOLFSSH_CHAN* chan;
    void*         heap = NULL;

    WLOG(WS_LOG_DEBUG, "Enter wolfSSH_CHAN_new()");

    if (ssh != NULL && ssh->ctx != NULL)
        heap = ssh->ctx->heap;

    chan = (WOLFSSH_CHAN*)WMALLOC(sizeof(WOLFSSH_CHAN),
                                                       heap, WOLFSSH_CHAN_TYPE);

    chan = SshChanInit(chan, ssh);

    WLOG(WS_LOG_DEBUG, "Leaving wolfSSH_CHAN_new(), chan = %p", chan);

    return chan;
}


static void SshChanResourceFree(WOLFSSH_CHAN* chan)
{
    /* when ssh channel holds resources, free here */
    (void)chan;

    WLOG(WS_LOG_DEBUG, "Enter SshChanResourceFree()");
}


void wolfSSH_CHAN_free(WOLFSSH_CHAN* chan)
{
    WLOG(WS_LOG_DEBUG, "Enter wolfSCEP_free()");

    if (chan) {
        SshChanResourceFree(chan);
        WFREE(chan, chan->ctx ? chan->ctx->heap : NULL, WOLFSCEP_TYPE);
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


static int Receive(WOLFSSH* ssh, uint8_t* buf, uint32_t sz)
{
    int recvd;

    if (ssh->ctx->ioRecvCb == NULL) {
        WLOG(WS_LOG_DEBUG, "Your IO Recv callback is null, please set");
        return -1;
    }

retry:
    recvd = ssh->ctx->ioRecvCb(ssh, buf, sz, ssh->ioReadCtx);
    if (recvd < 0)
        switch (recvd) {
            case WS_CBIO_ERR_GENERAL:        /* general/unknown error */
                return -1;

            case WS_CBIO_ERR_WANT_READ:      /* want read, would block */
                return WS_WANT_READ;

            case WS_CBIO_ERR_CONN_RST:       /* connection reset */
                ssh->connReset = 1;
                return -1;

            case WS_CBIO_ERR_ISR:            /* interrupt */
                goto retry;

            case WS_CBIO_ERR_CONN_CLOSE:     /* peer closed connection */
                ssh->isClosed = 1;
                return -1;

            case WS_CBIO_ERR_TIMEOUT:
                return -1;

            default:
                return recvd;
        }

    return recvd;
}


static int GetInputText(WOLFSSH* ssh)
{
    int gotLine = 0;
    int inSz = 255;
    int in;

    if (GrowBuffer(ssh->inputBuffer, inSz) < 0)
        return WS_MEMORY_E;

    do {
        in = Receive(ssh,
                     ssh->inputBuffer->buffer + ssh->inputBuffer->length, inSz);

        if (in == -1)
            return WS_SOCKET_ERROR_E;
   
        if (in == WS_WANT_READ)
            return WS_WANT_READ;

        if (in > inSz)
            return WS_RECV_OVERFLOW_E;

        ssh->inputBuffer->length += in;
        inSz -= in;

        if (ssh->inputBuffer->length > 2) {
            if (ssh->inputBuffer->buffer[ssh->inputBuffer->length - 2] == '\r' &&
                ssh->inputBuffer->buffer[ssh->inputBuffer->length - 1] == '\n') {

                gotLine = 1;
            }
        }
    } while (!gotLine);

    return WS_SUCCESS;
}


static int SendBuffer(WOLFSSH* ssh)
{
    if (ssh->ctx->ioSendCb == NULL) {
        WLOG(WS_LOG_DEBUG, "Your IO Send callback is null, please set");
        return -1;
    }

    while (ssh->outputBuffer->length > 0) {
        int sent = ssh->ctx->ioSendCb(ssh,
                             ssh->outputBuffer->buffer + ssh->outputBuffer->idx,
                             ssh->outputBuffer->length, ssh->ioWriteCtx);

        if (sent < 0) {
            return WS_SOCKET_ERROR_E;
        }

        if (sent > (int)ssh->outputBuffer->length) {
            WLOG(WS_LOG_DEBUG, "Out of bounds read");
            return WS_SEND_OOB_READ_E;
        }

        ssh->outputBuffer->idx += sent;
        ssh->outputBuffer->length -= sent;
    }

    ssh->outputBuffer->idx = 0;
    ShrinkBuffer(ssh->outputBuffer);

    return WS_SUCCESS;
}


static int SendText(WOLFSSH* ssh, const char* text, uint32_t textLen)
{
    GrowBuffer(ssh->outputBuffer, textLen);
    WMEMCPY(ssh->outputBuffer->buffer, text, textLen);
    ssh->outputBuffer->length = textLen;

    return SendBuffer(ssh);
}


static int GetInputData(WOLFSSH* ssh, uint32_t size)
{
    int in;
    int inSz;
    int maxLength;
    int usedLength;

    
    /* check max input length */
    usedLength = ssh->inputBuffer->length - ssh->inputBuffer->idx;
    maxLength  = ssh->inputBuffer->bufferSz - usedLength;
    inSz       = (int)(size - usedLength);      /* from last partial read */

    if (inSz <= 0)
        return WS_BUFFER_E;
    
    /* Put buffer data at start if not there */
    if (usedLength > 0 && ssh->inputBuffer->idx != 0)
        WMEMMOVE(ssh->inputBuffer->buffer,
                ssh->inputBuffer->buffer + ssh->inputBuffer->idx,
                usedLength);
    
    /* remove processed data */
    ssh->inputBuffer->idx    = 0;
    ssh->inputBuffer->length = usedLength;
  
    /* read data from network */
    do {
        in = Receive(ssh,
                     ssh->inputBuffer->buffer + ssh->inputBuffer->length, inSz);
        if (in == -1)
            return WS_SOCKET_ERROR_E;
   
        if (in == WS_WANT_READ)
            return WS_WANT_READ;

        if (in > inSz)
            return WS_RECV_OVERFLOW_E;
        
        ssh->inputBuffer->length += in;
        inSz -= in;

    } while (ssh->inputBuffer->length < size);

    return 0;
}


static int DoKexInit(uint8_t* buf, uint32_t len, uint32_t* idx)
{
}


static int DoPacket(WOLFSSH* ssh)
{
    uint8_t* buf = (uint8_t*)ssh->inputBuffer->buffer;
    uint32_t idx = ssh->inputBuffer->idx;
    uint32_t len = ssh->inputBuffer->length;
    uint8_t msg;

    /* Advance past packet size and padding size */
    idx += 5;

    msg = buf[idx++];
    switch (msg) {

        case SSH_MSG_KEXINIT:
            WLOG(WS_LOG_DEBUG, "Decoding SSH_MSG_KEXINIT (%d)", len);
            DoKexInit(buf, len, &idx);
            break;

        default:
            WLOG(WS_LOG_DEBUG, "Unsupported message ID");
            break;
    }

    ssh->inputBuffer->idx = idx;
    return WS_SUCCESS;
}


int ProcessReply(WOLFSSH* ssh)
{
    int ret = WS_FATAL_ERROR;
    int readSz;

    (void)readSz;
    for (;;) {
        switch (ssh->processReplyState) {
            case PROCESS_INIT:
                readSz = ssh->blockSz;
                if ((ret = GetInputData(ssh, readSz)) < 0) {
                    return ret;
                }
                ssh->processReplyState = PROCESS_PACKET_LENGTH;

            /* Decrypt first block if encrypted */

            case PROCESS_PACKET_LENGTH:
                ato32(ssh->inputBuffer->buffer + ssh->inputBuffer->idx, &ssh->curSz);
                ssh->processReplyState = PROCESS_PACKET_FINISH;

            case PROCESS_PACKET_FINISH:
                if ((ret = GetInputData(ssh, ssh->curSz)) < 0) {

                    return ret;
                }
                ssh->processReplyState = PROCESS_PACKET;

            /* Decrypt rest of packet here */

            /* Check MAC here. */

            case PROCESS_PACKET:
                if ( (ret = DoPacket(ssh)) < 0) {
                    return ret;
                }
                break;

            default:
                WLOG(WS_LOG_DEBUG, "Bad process input state, programming error");
                return WS_INPUT_CASE_E;
        }
        ssh->processReplyState = PROCESS_INIT;
        return WS_SUCCESS;
    }
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
                ProcessReply(ssh);
            }
            break;
    }

    return WS_FATAL_ERROR;
}


const char sshIdStr[] = "SSH-2.0-wolfSSHv" LIBWOLFSSH_VERSION_STRING "\r\n";


int ProcessClientVersion(WOLFSSH* ssh)
{
    int error;
    size_t protoLen = 7; /* Length of the SSH-2.0 portion of the ID str */

    if ( (error = GetInputText(ssh)) < 0) {
        WLOG(WS_LOG_DEBUG, "get input text failed");
        return error;
    }

    if (WSTRNCASECMP((char*)ssh->inputBuffer->buffer,
                                                     sshIdStr, protoLen) == 0) {
        ssh->clientState = CLIENT_VERSION_DONE;
    }
    else {
        WLOG(WS_LOG_DEBUG, "SSH version mismatch");
        return WS_VERSION_E;
    }

    ssh->peerId = (char*)WMALLOC(ssh->inputBuffer->length-1, ssh->ctx->heap, WOLFSSH_ID_TYPE);
    if (ssh->peerId == NULL) {
        return WS_MEMORY_E;
    }

    WMEMCPY(ssh->peerId, ssh->inputBuffer->buffer, ssh->inputBuffer->length-2);
    ssh->peerId[ssh->inputBuffer->length - 1] = 0;
    ssh->inputBuffer->idx += ssh->inputBuffer->length;
    WLOG(WS_LOG_DEBUG, "%s", ssh->peerId);

    return WS_SUCCESS;
}


int SendServerVersion(WOLFSSH* ssh)
{
    (void)ssh;

    WLOG(WS_LOG_DEBUG, "%s", sshIdStr);
    SendText(ssh, sshIdStr, (uint32_t)WSTRLEN(sshIdStr));

    return WS_FATAL_ERROR;
}



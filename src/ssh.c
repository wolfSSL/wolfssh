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
    ssh->keyExchangeId = ID_NONE;
    ssh->publicKeyId   = ID_NONE;
    ssh->encryptionId  = ID_NONE;
    ssh->integrityId   = ID_NONE;
    ssh->pendingKeyExchangeId = ID_NONE;
    ssh->pendingPublicKeyId   = ID_NONE;
    ssh->pendingEncryptionId  = ID_NONE;
    ssh->pendingIntegrityId   = ID_NONE;
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
    WLOG(WS_LOG_DEBUG, "Receive: recvd = %d", recvd);
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

    if (GrowBuffer(ssh->inputBuffer, inSz, 0) < 0)
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
    GrowBuffer(ssh->outputBuffer, textLen, 0);
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

    WLOG(WS_LOG_DEBUG, "GID: size = %d", size);
    WLOG(WS_LOG_DEBUG, "GID: usedLength = %d", usedLength);
    WLOG(WS_LOG_DEBUG, "GID: maxLength = %d", maxLength);
    WLOG(WS_LOG_DEBUG, "GID: inSz = %d", inSz);

    /*
     * usedLength - how much untouched data is in the buffer
     * maxLength - how much empty space is in the buffer
     * inSz - difference between requested data and empty space in the buffer
     *        how much more we need to allocate
     */

    if (inSz <= 0)
        return WS_BUFFER_E;
    
    /*
     * If we need more space than there is left in the buffer grow buffer.
     * Growing the buffer also compresses empty space at the head of the
     * buffer and resets idx to 0.
     */
    if (inSz > maxLength) {
        if (GrowBuffer(ssh->inputBuffer, size, usedLength) < 0)
            return WS_MEMORY_E;
    }

    /* Put buffer data at start if not there */
    /* Compress the buffer if needed, i.e. buffer idx is non-zero */
    if (usedLength > 0 && ssh->inputBuffer->idx != 0) {
        WMEMMOVE(ssh->inputBuffer->buffer,
                ssh->inputBuffer->buffer + ssh->inputBuffer->idx,
                usedLength);
    }
    
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


static int DoNameList(uint8_t* list, uint8_t* listSz,
                                      uint8_t* buf, uint32_t len, uint32_t* idx)
{
    uint8_t i = 0;
    uint32_t nameListSz;
    uint32_t begin = *idx;
    (void)list;

    if (begin >= len || begin + 4 >= len)
        return -1;

    ato32(buf + begin, &nameListSz);
    begin += 4;
    if (begin + nameListSz > len)
        return -1;

    begin += nameListSz;
    /* list[0] = NameToId(nextName, 0); */

    *listSz = i;
    *idx = begin;

    return WS_SUCCESS;
}


static int DoKexInit(WOLFSSH* ssh, uint8_t* buf, uint32_t len, uint32_t* idx)
{
    uint8_t list[3];
    uint8_t listSz;
    uint32_t skipSz;
    uint32_t begin = *idx;

    /*
     * I don't need to save what the client sends here. I should decode
     * each list into a local array of IDs, and pick the one the peer is
     * using that's on my known list, or verify that the one the peer can
     * support the other direction is on my known list. All I need to do
     * is save the actual values.
     *
     * Save the cookie for now. Maybe that is used in KEX.
     *
     * byte[16]     cookie
     * name-list    kex_algorithms (2)
     * name-list    server_host_key_algorithms (1)
     * name-list    encryption_algorithms_client_to_server (3)
     * name-list    encryption_algorithms_server_to_client (3)
     * name-list    mac_algorithms_client_to_server (2)
     * name-list    mac_algorithms_server_to_client (2)
     * name-list    compression_algorithms_client_to_server (1)
     * name-list    compression_algorithms_server_to_client (1)
     * name-list    languages_client_to_server (0, skip)
     * name-list    languages_server_to_client (0, skip)
     * boolean      first_kex_packet_follows
     * uint32       0 (reserved for future extension)
     */

    /* Check that the cookie exists inside the message */
    if (begin + COOKIE_SZ > len) {
        /* error, out of bounds */
        return -1;
    }
    /* Move past the cookie. */
    begin += COOKIE_SZ;

    /* KEX Algorithms */
    listSz = 2;
    DoNameList(list, &listSz, buf, len, &begin);

    /* Server Host Key Algorithms */
    listSz = 1;
    DoNameList(list, &listSz, buf, len, &begin);

    /* Enc Algorithms - Client to Server */
    listSz = 3;
    DoNameList(list, &listSz, buf, len, &begin);

    /* Enc Algorithms - Server to Client */
    listSz = 3;
    DoNameList(list, &listSz, buf, len, &begin);

    /* MAC Algorithms - Client to Server */
    listSz = 2;
    DoNameList(list, &listSz, buf, len, &begin);

    /* MAC Algorithms - Server to Client */
    listSz = 2;
    DoNameList(list, &listSz, buf, len, &begin);

    /* Compression Algorithms - Client to Server */
    listSz = 1;
    DoNameList(list, &listSz, buf, len, &begin);
    /* verify the list contains "none" */

    /* Compression Algorithms - Server to Client */
    listSz = 1;
    DoNameList(list, &listSz, buf, len, &begin);
    /* verify the list contains "none" */

    /* Languages - Client to Server, skip */
    ato32(buf + begin, &skipSz);
    begin += 4 + skipSz;

    /* Languages - Server to Client, skip */
    ato32(buf + begin, &skipSz);
    begin += 4 + skipSz;

    /* First KEX Packet Follows */
    ssh->kexPacketFollows = buf[begin];
    begin += 1;

    /* Skip the "for future use" length. */
    ato32(buf + begin, &skipSz);
    begin += 4 + skipSz;

    *idx = begin;

    return WS_SUCCESS;
}


static int DoPacket(WOLFSSH* ssh)
{
    uint8_t* buf = (uint8_t*)ssh->inputBuffer->buffer;
    uint32_t idx = ssh->inputBuffer->idx;
    uint32_t len = ssh->inputBuffer->length;
    uint8_t msg;
    uint8_t padSz;

    padSz = buf[idx++];

    msg = buf[idx++];
    switch (msg) {

        case SSH_MSG_KEXINIT:
            WLOG(WS_LOG_DEBUG, "Decoding SSH_MSG_KEXINIT (len = %d)", len);
            DoKexInit(ssh, buf, len, &idx);
            break;

        default:
            WLOG(WS_LOG_DEBUG, "Unsupported message ID (%d)", msg);
            break;
    }

    if (idx + padSz > len) {
        return -1;
    }
    idx += padSz;

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
                WLOG(WS_LOG_DEBUG, "PR1: size = %d", readSz);
                if ((ret = GetInputData(ssh, readSz)) < 0) {
                    return ret;
                }
                ssh->processReplyState = PROCESS_PACKET_LENGTH;

            /* Decrypt first block if encrypted */

            case PROCESS_PACKET_LENGTH:
                ato32(ssh->inputBuffer->buffer + ssh->inputBuffer->idx, &ssh->curSz);
                ssh->inputBuffer->idx += LENGTH_SZ;
                ssh->processReplyState = PROCESS_PACKET_FINISH;

            case PROCESS_PACKET_FINISH:
                WLOG(WS_LOG_DEBUG, "PR2: size = %d", ssh->curSz);
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
                if ( (ssh->error = ProcessReply(ssh)) < 0) {
                    WLOG(WS_LOG_DEBUG, "accept reply error: %d", ssh->error);
                    return WS_FATAL_ERROR;
                }
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



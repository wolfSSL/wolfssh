/* internal.c 
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
 * The internal module contains the private data and functions. The public
 * API calls into this module to do the work of processing the connections.
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


const char* GetErrorString(int err)
{
#ifdef NO_WOLFSSH_STRINGS
    return "No wolfSSH strings available";
#else
    switch (err) {
        case WS_SUCCESS:
            return "function success";

        case WS_FATAL_ERROR:
            return "general function failure";

        case WS_BAD_ARGUMENT:
            return "bad function argument";

        case WS_MEMORY_E:
            return "memory allocation failure";

        case WS_BUFFER_E:
            return "input/output buffer size error";

        case WS_PARSE_E:
            return "general parsing error";

        case WS_NOT_COMPILED:
            return "feature not compiled in";

        case WS_OVERFLOW_E:
            return "would overflow if continued failure";

        case WS_BAD_USAGE:
            return "bad example usage";

        case WS_SOCKET_ERROR_E:
            return "socket error";

        case WS_WANT_READ:
            return "I/O callback would read block error";

        case WS_WANT_WRITE:
            return "I/O callback would write block error";

        case WS_RECV_OVERFLOW_E:
            return "receive buffer overflow";

        default:
            return "Unknown error code";
    }
#endif
}


typedef struct {
    uint8_t id;
    const char* name;
} NameIdPair;


static const NameIdPair NameIdMap[] = {
    { ID_NONE, "none" },
    { ID_AES128_CBC, "aes128-cbc" },
    { ID_AES128_CTR, "aes128-ctr" },
    { ID_AES128_GCM_WOLF, "aes128-gcm@wolfssl.com" },
    { ID_HMAC_SHA1, "hmac-sha1" },
    { ID_HMAC_SHA1_96, "hmac-sha1-96" },
    { ID_DH_GROUP1_SHA1, "diffie-hellman-group1-sha1" },
    { ID_DH_GROUP14_SHA1, "diffie-hellman-group14-sha1" },
    { ID_SSH_RSA, "ssh-rsa" }
};


uint8_t NameToId(const char* name, uint32_t nameSz)
{
    uint8_t id = ID_UNKNOWN;
    uint32_t i;
(void)nameSz;
    for (i = 0; i < (sizeof(NameIdMap)/sizeof(NameIdPair)); i++) {
        if (nameSz == WSTRLEN(NameIdMap[i].name) &&
            WSTRNCMP(name, NameIdMap[i].name, nameSz) == 0) {

            id = NameIdMap[i].id;
            break;
        }
    }

    return id;
}


const char* IdToName(uint8_t id)
{
    const char* name = NULL;
    uint32_t i;

    for (i = 0; i < (sizeof(NameIdMap)/sizeof(NameIdPair)); i++) {
        if (NameIdMap[i].id == id) {
            name = NameIdMap[i].name;
            break;
        }
    }

    return name;
}


int BufferInit(Buffer* buffer, uint32_t size, void* heap)
{
    if (buffer == NULL)
        return WS_BAD_ARGUMENT;

    if (size <= STATIC_BUFFER_LEN)
        size = STATIC_BUFFER_LEN;

    WMEMSET(buffer, 0, sizeof(Buffer));
    buffer->heap = heap;
    buffer->bufferSz = size;
    if (size > STATIC_BUFFER_LEN) {
        buffer->buffer = (uint8_t*)WMALLOC(size, heap, WOLFSSH_TYPE_BUFFER);
        if (buffer->buffer == NULL)
            return WS_MEMORY_E;
        buffer->dynamicFlag = 1;
    }
    else
        buffer->buffer = buffer->staticBuffer;

    return WS_SUCCESS;
}


int GrowBuffer(Buffer* buf, uint32_t sz, uint32_t usedSz)
{
    WLOG(WS_LOG_DEBUG, "GB: buf = %p", buf);
    WLOG(WS_LOG_DEBUG, "GB: sz = %d", sz);
    WLOG(WS_LOG_DEBUG, "GB: usedSz = %d", usedSz);
    /* New buffer will end up being sz+usedSz long
     * empty space at the head of the buffer will be compressed */
    if (buf != NULL) {
        uint32_t newSz = sz + usedSz;
        WLOG(WS_LOG_DEBUG, "GB: newSz = %d", newSz);

        if (newSz > buf->bufferSz) {
            uint8_t* newBuffer = (uint8_t*)WMALLOC(newSz,
                                                buf->heap, WOLFSSH_TYPE_BUFFER);

            WLOG(WS_LOG_DEBUG, "Growing buffer");

            if (newBuffer == NULL)
                return WS_MEMORY_E;

            WLOG(WS_LOG_DEBUG, "GB: resizing buffer");
            if (buf->length > 0)
                WMEMCPY(newBuffer, buf->buffer + buf->idx, buf->length);

            if (!buf->dynamicFlag)
                buf->dynamicFlag = 1;
            else
                WFREE(buf->buffer, buf->heap, WOLFSSH_TYPE_BUFFER);

            buf->buffer = newBuffer;
            buf->bufferSz = newSz;
            buf->length = usedSz;
            buf->idx = 0;
        }
    }

    return WS_SUCCESS;
}


void ShrinkBuffer(Buffer* buf, int forcedFree)
{
    if (buf != NULL) {
        uint32_t usedSz = buf->length - buf->idx;

        if (!forcedFree && usedSz > STATIC_BUFFER_LEN)
            return;

        WLOG(WS_LOG_DEBUG, "Shrinking buffer");

        if (!forcedFree && usedSz)
            WMEMCPY(buf->staticBuffer, buf->buffer + buf->idx, usedSz);

        if (buf->dynamicFlag)
            WFREE(buf->buffer, buf->heap, WOLFSSH_TYPE_BUFFER);
        buf->dynamicFlag = 0;
        buf->buffer = buf->staticBuffer;
        buf->bufferSz = STATIC_BUFFER_LEN;
        buf->length = forcedFree ? 0 : usedSz;
        buf->idx = 0;
    }
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

    if (GrowBuffer(&ssh->inputBuffer, inSz, 0) < 0)
        return WS_MEMORY_E;

    do {
        in = Receive(ssh,
                     ssh->inputBuffer.buffer + ssh->inputBuffer.length, inSz);

        if (in == -1)
            return WS_SOCKET_ERROR_E;

        if (in == WS_WANT_READ)
            return WS_WANT_READ;

        if (in > inSz)
            return WS_RECV_OVERFLOW_E;

        ssh->inputBuffer.length += in;
        inSz -= in;

        if (ssh->inputBuffer.length > 2) {
            if (ssh->inputBuffer.buffer[ssh->inputBuffer.length - 2] == '\r' &&
                ssh->inputBuffer.buffer[ssh->inputBuffer.length - 1] == '\n') {

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

    while (ssh->outputBuffer.length > 0) {
        int sent = ssh->ctx->ioSendCb(ssh,
                             ssh->outputBuffer.buffer + ssh->outputBuffer.idx,
                             ssh->outputBuffer.length, ssh->ioWriteCtx);

        if (sent < 0) {
            return WS_SOCKET_ERROR_E;
        }

        if (sent > (int)ssh->outputBuffer.length) {
            WLOG(WS_LOG_DEBUG, "Out of bounds read");
            return WS_SEND_OOB_READ_E;
        }

        ssh->outputBuffer.idx += sent;
        ssh->outputBuffer.length -= sent;
    }

    ssh->outputBuffer.idx = 0;
    ShrinkBuffer(&ssh->outputBuffer, 0);

    return WS_SUCCESS;
}


static int SendText(WOLFSSH* ssh, const char* text, uint32_t textLen)
{
    GrowBuffer(&ssh->outputBuffer, textLen, 0);
    WMEMCPY(ssh->outputBuffer.buffer, text, textLen);
    ssh->outputBuffer.length = textLen;

    return SendBuffer(ssh);
}


static int GetInputData(WOLFSSH* ssh, uint32_t size)
{
    int in;
    int inSz;
    int maxLength;
    int usedLength;

    /* check max input length */
    usedLength = ssh->inputBuffer.length - ssh->inputBuffer.idx;
    maxLength  = ssh->inputBuffer.bufferSz - usedLength;
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
        if (GrowBuffer(&ssh->inputBuffer, size, usedLength) < 0)
            return WS_MEMORY_E;
    }

    /* Put buffer data at start if not there */
    /* Compress the buffer if needed, i.e. buffer idx is non-zero */
    if (usedLength > 0 && ssh->inputBuffer.idx != 0) {
        WMEMMOVE(ssh->inputBuffer.buffer,
                ssh->inputBuffer.buffer + ssh->inputBuffer.idx,
                usedLength);
    }

    /* remove processed data */
    ssh->inputBuffer.idx    = 0;
    ssh->inputBuffer.length = usedLength;

    /* read data from network */
    do {
        in = Receive(ssh,
                     ssh->inputBuffer.buffer + ssh->inputBuffer.length, inSz);
        if (in == -1)
            return WS_SOCKET_ERROR_E;

        if (in == WS_WANT_READ)
            return WS_WANT_READ;

        if (in > inSz)
            return WS_RECV_OVERFLOW_E;

        ssh->inputBuffer.length += in;
        inSz -= in;

    } while (ssh->inputBuffer.length < size);

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
    ssh->handshake->kexPacketFollows = buf[begin];
    begin += 1;

    /* Skip the "for future use" length. */
    ato32(buf + begin, &skipSz);
    begin += 4 + skipSz;

    *idx = begin;

    return WS_SUCCESS;
}


static int DoPacket(WOLFSSH* ssh)
{
    uint8_t* buf = (uint8_t*)ssh->inputBuffer.buffer;
    uint32_t idx = ssh->inputBuffer.idx;
    uint32_t len = ssh->inputBuffer.length;
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

    ssh->inputBuffer.idx = idx;
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
                ato32(ssh->inputBuffer.buffer + ssh->inputBuffer.idx, &ssh->curSz);
                ssh->inputBuffer.idx += LENGTH_SZ;
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


static const char sshIdStr[] = "SSH-2.0-wolfSSHv" LIBWOLFSSH_VERSION_STRING "\r\n";


int ProcessClientVersion(WOLFSSH* ssh)
{
    int error;
    size_t protoLen = 7; /* Length of the SSH-2.0 portion of the ID str */

    if ( (error = GetInputText(ssh)) < 0) {
        WLOG(WS_LOG_DEBUG, "get input text failed");
        return error;
    }

    if (WSTRNCASECMP((char*)ssh->inputBuffer.buffer,
                                                     sshIdStr, protoLen) == 0) {
        ssh->clientState = CLIENT_VERSION_DONE;
    }
    else {
        WLOG(WS_LOG_DEBUG, "SSH version mismatch");
        return WS_VERSION_E;
    }

    ShaUpdate(&ssh->handshake->hash, ssh->inputBuffer.buffer,
                                                   ssh->inputBuffer.length - 2);
    ssh->inputBuffer.idx += ssh->inputBuffer.length;

    return WS_SUCCESS;
}


int SendServerVersion(WOLFSSH* ssh)
{
    uint32_t sshIdStrSz = (uint32_t)WSTRLEN(sshIdStr);

    WLOG(WS_LOG_DEBUG, "%s", sshIdStr);
    SendText(ssh, sshIdStr, (uint32_t)WSTRLEN(sshIdStr));
    ShaUpdate(&ssh->handshake->hash, (const uint8_t*)sshIdStr, sshIdStrSz);

    return WS_FATAL_ERROR;
}



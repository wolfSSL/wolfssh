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
#include <cyassl/ctaocrypt/aes.h>


/* convert opaque to 32 bit integer */
static INLINE void ato32(const uint8_t* c, uint32_t* u32)
{
    *u32 = (c[0] << 24) | (c[1] << 16) | (c[2] << 8) | c[3];
}


/* convert 32 bit integer to opaque */
static INLINE void c32toa(uint32_t u32, uint8_t* c)
{
    c[0] = (u32 >> 24) & 0xff;
    c[1] = (u32 >> 16) & 0xff;
    c[2] = (u32 >>  8) & 0xff;
    c[3] =  u32 & 0xff;
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

        case WS_VERSION_E:
            return "peer version unsupported";

        case WS_SEND_OOB_READ_E:
            return "attempted to read buffer out of bounds";

        case WS_INPUT_CASE_E:
            return "bad process input state, programming error";

        case WS_BAD_FILETYPE_E:
            return "bad filetype";

        case WS_UNIMPLEMENTED_E:
            return "feature not implemented";

        case WS_RSA_E:
            return "RSA buffer error";

        case WS_BAD_FILE_E:
            return "bad file";

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

    /* Encryption IDs */
    { ID_AES128_CBC, "aes128-cbc" },
    { ID_AES128_CTR, "aes128-ctr" },
    { ID_AES128_GCM_WOLF, "aes128-gcm@wolfssl.com" },

    /* Integrity IDs */
    { ID_HMAC_SHA1, "hmac-sha1" },
    { ID_HMAC_SHA1_96, "hmac-sha1-96" },

    /* Key Exchange IDs */
    { ID_DH_GROUP1_SHA1, "diffie-hellman-group1-sha1" },
    { ID_DH_GROUP14_SHA1, "diffie-hellman-group14-sha1" },

    /* Public Key IDs */
    { ID_SSH_RSA, "ssh-rsa" }
};


uint8_t NameToId(const char* name, uint32_t nameSz)
{
    uint8_t id = ID_UNKNOWN;
    uint32_t i;

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
        buffer->buffer = (uint8_t*)WMALLOC(size, heap, DYNTYPE_BUFFER);
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
                                                     buf->heap, DYNTYPE_BUFFER);

            WLOG(WS_LOG_DEBUG, "Growing buffer");

            if (newBuffer == NULL)
                return WS_MEMORY_E;

            WLOG(WS_LOG_DEBUG, "GB: resizing buffer");
            if (buf->length > 0)
                WMEMCPY(newBuffer, buf->buffer + buf->idx, buf->length);

            if (!buf->dynamicFlag)
                buf->dynamicFlag = 1;
            else
                WFREE(buf->buffer, buf->heap, DYNTYPE_BUFFER);

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
            WFREE(buf->buffer, buf->heap, DYNTYPE_BUFFER);
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


static int SendBuffered(WOLFSSH* ssh)
{
    if (ssh->ctx->ioSendCb == NULL) {
        WLOG(WS_LOG_DEBUG, "Your IO Send callback is null, please set");
        return WS_SOCKET_ERROR_E;
    }

    while (ssh->outputBuffer.length > 0) {
        int sent = ssh->ctx->ioSendCb(ssh,
                               ssh->outputBuffer.buffer + ssh->outputBuffer.idx,
                               ssh->outputBuffer.length, ssh->ioReadCtx);

        if (sent < 0) {
            switch (sent) {
                case WS_CBIO_ERR_WANT_WRITE:     /* want write, would block */
                    return WS_WANT_WRITE;

                case WS_CBIO_ERR_CONN_RST:       /* connection reset */
                    ssh->connReset = 1;
                    break;

                case WS_CBIO_ERR_CONN_CLOSE:     /* peer closed connection */
                    ssh->isClosed = 1;
                    break;
            }
            return WS_SOCKET_ERROR_E;
        }

        if ((uint32_t)sent > ssh->outputBuffer.length) {
            WLOG(WS_LOG_DEBUG, "SendBuffered() out of bounds read");
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

    return SendBuffered(ssh);
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


static int DoNameList(uint8_t* idList, uint32_t* idListSz,
                                      uint8_t* buf, uint32_t len, uint32_t* idx)
{
    uint8_t idListIdx;
    uint32_t nameListSz, nameListIdx;
    uint32_t begin = *idx;
    uint8_t* name;
    uint32_t nameSz;

    /*
     * This iterates across a name list and finds names that end in either the
     * comma delimeter or with the end of the list.
     */

    if (begin >= len || begin + 4 >= len)
        return -1;

    ato32(buf + begin, &nameListSz);
    begin += 4;
    if (begin + nameListSz > len)
        return -1;

    /* The strings we want are now in the bounds of the message, and the
     * length of the list. Find the commas, or end of list, and then decode
     * the values. */
    name = buf + begin;
    nameSz = 0;
    nameListIdx = 0;
    idListIdx = 0;

    while (nameListIdx < nameListSz) {
        nameListIdx++;

        if (nameListIdx == nameListSz)
            nameSz++;

        if (nameListIdx == nameListSz || name[nameSz] == ',') {
            uint8_t id;

            id = NameToId((char*)name, nameSz);
            {
                const char* displayName = IdToName(id);
                if (displayName)
                    WLOG(WS_LOG_DEBUG, "DNL: name ID = %s", displayName);
            }
            if (id != ID_UNKNOWN)
                idList[idListIdx++] = id;

            name += 1 + nameSz;
            nameSz = 0;
        }
        else
            nameSz++;
    }

    begin += nameListSz;
    *idListSz = idListIdx;
    *idx = begin;

    return WS_SUCCESS;
}


static const uint8_t  cannedEncAlgo[] = {ID_AES128_CBC};
static const uint8_t  cannedMacAlgo[] = {ID_HMAC_SHA1_96, ID_HMAC_SHA1};
static const uint8_t  cannedKeyAlgo[] = {ID_SSH_RSA};
static const uint8_t  cannedKexAlgo[] = {ID_DH_GROUP14_SHA1, ID_DH_GROUP1_SHA1};

static const uint32_t cannedEncAlgoSz = sizeof(cannedEncAlgo);
static const uint32_t cannedMacAlgoSz = sizeof(cannedMacAlgo);
static const uint32_t cannedKeyAlgoSz = sizeof(cannedKeyAlgo);
static const uint32_t cannedKexAlgoSz = sizeof(cannedKexAlgo);


static uint8_t MatchIdLists(const uint8_t* left, uint32_t leftSz,
                            const uint8_t* right, uint32_t rightSz)
{
    uint32_t i, j;

    if (left != NULL && leftSz > 0 && right != NULL && rightSz > 0) {
        for (i = 0; i < leftSz; i++) {
            for (j = 0; i < rightSz; j++) {
                if (left[i] == right[j]) {
                    WLOG(WS_LOG_DEBUG, "MID: matched %s", IdToName(left[i]));
                    return left[i];
                }
            }
        }
    }

    return ID_UNKNOWN;
}


static INLINE uint8_t BlockSzForId(uint8_t id)
{
    switch (id) {
        case ID_AES128_CBC:
        case ID_AES128_CTR:
            return AES_BLOCK_SIZE;
        default:
            return 0;
    }
}


static INLINE uint8_t MacSzForId(uint8_t id)
{
    switch (id) {
        case ID_HMAC_SHA1:
            return SHA_DIGEST_SIZE;
        case ID_HMAC_SHA1_96:
            return (96/8); /* 96 bits */
        default:
            return 0;
    }
}


static int DoKexInit(WOLFSSH* ssh, uint8_t* buf, uint32_t len, uint32_t* idx)
{
    uint8_t algoId;
    uint8_t list[3];
    uint32_t listSz;
    uint32_t skipSz;
    uint32_t begin = *idx;

    /*
     * I don't need to save what the client sends here. I should decode
     * each list into a local array of IDs, and pick the one the peer is
     * using that's on my known list, or verify that the one the peer can
     * support the other direction is on my known list. All I need to do
     * is save the actual values.
     */

    ShaUpdate(&ssh->handshake->hash, buf - 1, len + 1);
    /* The -1/+1 adjustment is for the message ID. */

    /* Check that the cookie exists inside the message */
    if (begin + COOKIE_SZ > len) {
        /* error, out of bounds */
        return WS_FATAL_ERROR;
    }
    /* Move past the cookie. */
    begin += COOKIE_SZ;

    /* KEX Algorithms */
    WLOG(WS_LOG_DEBUG, "DKI: KEX Algorithms");
    listSz = 2;
    DoNameList(list, &listSz, buf, len, &begin);
    algoId = MatchIdLists(cannedKexAlgo, cannedKexAlgoSz, list, listSz);
    if (algoId == ID_UNKNOWN) {
        WLOG(WS_LOG_DEBUG, "Unable to negotiate KEX Algo");
        return WS_INVALID_ALGO_ID;
    }

    ssh->handshake->keyExchangeId = algoId;

    /* Server Host Key Algorithms */
    WLOG(WS_LOG_DEBUG, "DKI: Server Host Key Algorithms");
    listSz = 1;
    DoNameList(list, &listSz, buf, len, &begin);
    algoId = MatchIdLists(cannedKeyAlgo, cannedKeyAlgoSz, list, listSz);
    if (algoId == ID_UNKNOWN) {
        WLOG(WS_LOG_DEBUG, "Unable to negotiate Server Host Key Algo");
        return WS_INVALID_ALGO_ID;
    }

    ssh->handshake->publicKeyId = algoId;

    /* Enc Algorithms - Client to Server */
    WLOG(WS_LOG_DEBUG, "DKI: Enc Algorithms - Client to Server");
    listSz = 3;
    DoNameList(list, &listSz, buf, len, &begin);
    algoId = MatchIdLists(cannedEncAlgo, cannedEncAlgoSz, list, listSz);
    if (algoId == ID_UNKNOWN) {
        WLOG(WS_LOG_DEBUG, "Unable to negotiate Encryption Algo C2S");
        return WS_INVALID_ALGO_ID;
    }

    /* Enc Algorithms - Server to Client */
    WLOG(WS_LOG_DEBUG, "DKI: Enc Algorithms - Server to Client");
    listSz = 3;
    DoNameList(list, &listSz, buf, len, &begin);
    if (MatchIdLists(&algoId, 1, list, listSz) == ID_UNKNOWN) {
        WLOG(WS_LOG_DEBUG, "Unable to negotiate Encryption Algo S2C");
        return WS_INVALID_ALGO_ID;
    }

    ssh->handshake->encryptionId = algoId;
    ssh->handshake->blockSz = BlockSzForId(algoId);

    /* MAC Algorithms - Client to Server */
    WLOG(WS_LOG_DEBUG, "DKI: MAC Algorithms - Client to Server");
    listSz = 2;
    DoNameList(list, &listSz, buf, len, &begin);
    algoId = MatchIdLists(cannedMacAlgo, cannedMacAlgoSz, list, listSz);
    if (algoId == ID_UNKNOWN) {
        WLOG(WS_LOG_DEBUG, "Unable to negotiate MAC Algo C2S");
        return WS_INVALID_ALGO_ID;
    }

    /* MAC Algorithms - Server to Client */
    WLOG(WS_LOG_DEBUG, "DKI: MAC Algorithms - Server to Client");
    listSz = 2;
    DoNameList(list, &listSz, buf, len, &begin);
    if (MatchIdLists(&algoId, 1, list, listSz) == ID_UNKNOWN) {
        WLOG(WS_LOG_DEBUG, "Unable to negotiate MAC Algo S2C");
        return WS_INVALID_ALGO_ID;
    }

    ssh->handshake->integrityId = algoId;
    ssh->handshake->macSz = MacSzForId(algoId);

    /* The compression algorithm lists should have none as a value. */
    algoId = ID_NONE;

    /* Compression Algorithms - Client to Server */
    WLOG(WS_LOG_DEBUG, "DKI: Compression Algorithms - Client to Server");
    listSz = 1;
    DoNameList(list, &listSz, buf, len, &begin);
    if (MatchIdLists(&algoId, 1, list, listSz) == ID_UNKNOWN) {
        WLOG(WS_LOG_DEBUG, "Unable to negotiate Compression Algo C2S");
        return WS_INVALID_ALGO_ID;
    }

    /* Compression Algorithms - Server to Client */
    WLOG(WS_LOG_DEBUG, "DKI: Compression Algorithms - Server to Client");
    listSz = 1;
    DoNameList(list, &listSz, buf, len, &begin);
    if (MatchIdLists(&algoId, 1, list, listSz) == ID_UNKNOWN) {
        WLOG(WS_LOG_DEBUG, "Unable to negotiate Compression Algo S2C");
        return WS_INVALID_ALGO_ID;
    }

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

    ssh->clientState = CLIENT_ALGO_DONE;
    return WS_SUCCESS;
}


static int DoPacket(WOLFSSH* ssh)
{
    uint8_t* buf = (uint8_t*)ssh->inputBuffer.buffer;
    uint32_t idx = ssh->inputBuffer.idx;
    uint32_t len = ssh->inputBuffer.length;
    uint32_t payloadSz;
    uint8_t  padSz;
    uint8_t  msg;

    /* Problem: len is equal to the amount of data left in the input buffer.
     *          The beginning part of that data is the packet we want to
     *          decode. The remainder is the pad and the MAC. */
    padSz = buf[idx++];
    payloadSz = ssh->curSz - PAD_LENGTH_SZ - padSz;

    msg = buf[idx++];
    switch (msg) {

        case MSGID_KEXINIT:
            WLOG(WS_LOG_DEBUG, "Decoding MSGID_KEXINIT (len = %d)", payloadSz);
            DoKexInit(ssh, buf, payloadSz, &idx);
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


static int PreparePacket(WOLFSSH* ssh, uint32_t payloadSz)
{
    int      ret;
    uint8_t* output;
    uint32_t outputSz;
    uint32_t packetSz;
    uint8_t  paddingSz;

    /* Minimum value for paddingSz is 4. */
    paddingSz = (LENGTH_SZ + PAD_LENGTH_SZ + payloadSz) % ssh->blockSz;
    if (paddingSz < 4)
        paddingSz += ssh->blockSz;
    ssh->paddingSz = paddingSz;
    packetSz = PAD_LENGTH_SZ + payloadSz + paddingSz;
    outputSz = LENGTH_SZ + packetSz + ssh->macSz;

    if ( (ret = GrowBuffer(&ssh->outputBuffer, outputSz, 0)) != WS_SUCCESS)
        return ret;

    output = ssh->outputBuffer.buffer + ssh->outputBuffer.length;

    /* fill in the packetSz, paddingSz */
    c32toa(packetSz, output);
    output[LENGTH_SZ] = paddingSz;

    ssh->outputBuffer.length += LENGTH_SZ + PAD_LENGTH_SZ;

    return ret;
}


static int BundlePacket(WOLFSSH* ssh)
{
    uint8_t* output;
    uint32_t idx;
    uint8_t  paddingSz;

    output = ssh->outputBuffer.buffer;
    idx = ssh->outputBuffer.length;
    paddingSz = ssh->paddingSz;

    /* Add the padding */
    WMEMSET(output + idx, 0, paddingSz);
    idx += paddingSz;

    /* Need to MAC the sequence number and the unencrypted packet */
    switch (ssh->integrityId) {
        case ID_NONE:
            break;
#if 0
        case ID_HMAC_SHA1_96:
            break;

        case ID_HMAC_SHA1:
            break;
#endif
        default:
            WLOG(WS_LOG_DEBUG, "Invalid Mac ID");
            return WS_FATAL_ERROR;
    }

    ssh->seq++;

    /* Encrypt the packet */
    switch (ssh->encryptionId) {
        case ID_NONE:
            break;
#if 0
        case ID_AES128_CBC:
            break;
#endif
        default:
            WLOG(WS_LOG_DEBUG, "Invalid Encrypt ID");
            return WS_FATAL_ERROR;
    }

    ssh->outputBuffer.length = idx;

    return WS_SUCCESS;
}


static INLINE void CopyNameList(uint8_t* buf, uint32_t* idx,
                                                const char* src, uint32_t srcSz)
{
    uint32_t begin = *idx;

    c32toa(srcSz, buf + begin);
    begin += LENGTH_SZ;
    WMEMCPY(buf + begin, src, srcSz);
    begin += srcSz;

    *idx = begin;
}


static const char     cannedEncAlgoNames[] = "aes128-cbc";
static const char     cannedMacAlgoNames[] = "hmac-sha1-96,hmac-sha1";
static const char     cannedKeyAlgoNames[] = "ssh-rsa";
static const char     cannedKexAlgoNames[] = "diffie-hellman-group14-sha1,"
                                             "diffie-hellman-group1-sha1";
static const char     cannedNoneNames[]    = "none";

static const uint32_t cannedEncAlgoNamesSz = sizeof(cannedEncAlgoNames) - 1;
static const uint32_t cannedMacAlgoNamesSz = sizeof(cannedMacAlgoNames) - 1;
static const uint32_t cannedKeyAlgoNamesSz = sizeof(cannedKeyAlgoNames) - 1;
static const uint32_t cannedKexAlgoNamesSz = sizeof(cannedKexAlgoNames) - 1;
static const uint32_t cannedNoneNamesSz    = sizeof(cannedNoneNames) - 1;


int SendKexInit(WOLFSSH* ssh)
{
    uint8_t* output;
    uint8_t* payload;
    uint32_t idx = 0;
    uint32_t payloadSz;
    int ret = WS_SUCCESS;

    payloadSz = MSG_ID_SZ + COOKIE_SZ + (LENGTH_SZ * 11) + BOOLEAN_SZ +
               cannedKexAlgoNamesSz + cannedKeyAlgoNamesSz +
               (cannedEncAlgoNamesSz * 2) +
               (cannedMacAlgoNamesSz * 2) +
               (cannedNoneNamesSz * 2);
    PreparePacket(ssh, payloadSz);

    output = ssh->outputBuffer.buffer;
    idx = ssh->outputBuffer.length;
    payload = output + idx;

    output[idx++] = MSGID_KEXINIT;

    RNG_GenerateBlock(ssh->rng, output + idx, COOKIE_SZ);
    idx += COOKIE_SZ;

    CopyNameList(output, &idx, cannedKexAlgoNames, cannedKexAlgoNamesSz);
    CopyNameList(output, &idx, cannedKeyAlgoNames, cannedKeyAlgoNamesSz);
    CopyNameList(output, &idx, cannedEncAlgoNames, cannedEncAlgoNamesSz);
    CopyNameList(output, &idx, cannedEncAlgoNames, cannedEncAlgoNamesSz);
    CopyNameList(output, &idx, cannedMacAlgoNames, cannedMacAlgoNamesSz);
    CopyNameList(output, &idx, cannedMacAlgoNames, cannedMacAlgoNamesSz);
    CopyNameList(output, &idx, cannedNoneNames, cannedNoneNamesSz);
    CopyNameList(output, &idx, cannedNoneNames, cannedNoneNamesSz);
    c32toa(0, output + idx); /* Languages - Client To Server (0) */
    idx += LENGTH_SZ;
    c32toa(0, output + idx); /* Languages - Server To Client (0) */
    idx += LENGTH_SZ;
    output[idx++] = 0;       /* First KEX packet follows (false) */
    c32toa(0, output + idx); /* Reserved (0) */
    idx += LENGTH_SZ;

    ssh->outputBuffer.length = idx;

    ShaUpdate(&ssh->handshake->hash, payload, payloadSz);

    BundlePacket(ssh);
    SendBuffered(ssh);

    return ret;
}



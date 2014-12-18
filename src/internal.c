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
#include <cyassl/ctaocrypt/asn.h>
#include <cyassl/ctaocrypt/rsa.h>
#include <cyassl/ctaocrypt/hmac.h>


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
    (void)err;

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

        case WS_DECRYPT_E:
            return "decrypt error";

        case WS_ENCRYPT_E:
            return "encrypt error";

        case WS_VERIFY_MAC_E:
            return "verify mac error";

        case WS_CREATE_MAC_E:
            return "verify mac error";

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
    const char* name = "unknown";
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

    WLOG(WS_LOG_DEBUG, "GID: size = %u", size);
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
                if (displayName) {
                    WLOG(WS_LOG_DEBUG, "DNL: name ID = %s", displayName);
		}
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
            for (j = 0; j < rightSz; j++) {
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
            return SHA1_96_SZ;
        default:
            return 0;
    }
}


static INLINE uint8_t KeySzForId(uint8_t id)
{
    switch (id) {
        case ID_HMAC_SHA1:
        case ID_HMAC_SHA1_96:
            return SHA_DIGEST_SIZE;
        case ID_AES128_CBC:
        case ID_AES128_CTR:
            return AES_BLOCK_SIZE;
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
    algoId = MatchIdLists(list, listSz, cannedKexAlgo, cannedKexAlgoSz);
    if (algoId == ID_UNKNOWN) {
        WLOG(WS_LOG_DEBUG, "Unable to negotiate KEX Algo");
        return WS_INVALID_ALGO_ID;
    }

    ssh->handshake->kexId = algoId;

    /* Server Host Key Algorithms */
    WLOG(WS_LOG_DEBUG, "DKI: Server Host Key Algorithms");
    listSz = 1;
    DoNameList(list, &listSz, buf, len, &begin);
    algoId = MatchIdLists(list, listSz, cannedKeyAlgo, cannedKeyAlgoSz);
    if (algoId == ID_UNKNOWN) {
        WLOG(WS_LOG_DEBUG, "Unable to negotiate Server Host Key Algo");
        return WS_INVALID_ALGO_ID;
    }

    ssh->handshake->pubKeyId = algoId;

    /* Enc Algorithms - Client to Server */
    WLOG(WS_LOG_DEBUG, "DKI: Enc Algorithms - Client to Server");
    listSz = 3;
    DoNameList(list, &listSz, buf, len, &begin);
    algoId = MatchIdLists(list, listSz, cannedEncAlgo, cannedEncAlgoSz);
    if (algoId == ID_UNKNOWN) {
        WLOG(WS_LOG_DEBUG, "Unable to negotiate Encryption Algo C2S");
        return WS_INVALID_ALGO_ID;
    }

    /* Enc Algorithms - Server to Client */
    WLOG(WS_LOG_DEBUG, "DKI: Enc Algorithms - Server to Client");
    listSz = 3;
    DoNameList(list, &listSz, buf, len, &begin);
    if (MatchIdLists(list, listSz, &algoId, 1) == ID_UNKNOWN) {
        WLOG(WS_LOG_DEBUG, "Unable to negotiate Encryption Algo S2C");
        return WS_INVALID_ALGO_ID;
    }

    ssh->handshake->encryptId = algoId;
    ssh->handshake->blockSz = ssh->ivClientSz = ssh->ivServerSz
                                                         = BlockSzForId(algoId);
    ssh->encKeyClientSz = ssh->encKeyServerSz = KeySzForId(algoId);

    /* MAC Algorithms - Client to Server */
    WLOG(WS_LOG_DEBUG, "DKI: MAC Algorithms - Client to Server");
    listSz = 2;
    DoNameList(list, &listSz, buf, len, &begin);
    algoId = MatchIdLists(list, listSz, cannedMacAlgo, cannedMacAlgoSz);
    if (algoId == ID_UNKNOWN) {
        WLOG(WS_LOG_DEBUG, "Unable to negotiate MAC Algo C2S");
        return WS_INVALID_ALGO_ID;
    }

    /* MAC Algorithms - Server to Client */
    WLOG(WS_LOG_DEBUG, "DKI: MAC Algorithms - Server to Client");
    listSz = 2;
    DoNameList(list, &listSz, buf, len, &begin);
    if (MatchIdLists(list, listSz, &algoId, 1) == ID_UNKNOWN) {
        WLOG(WS_LOG_DEBUG, "Unable to negotiate MAC Algo S2C");
        return WS_INVALID_ALGO_ID;
    }

    ssh->handshake->macId = algoId;
    ssh->handshake->macSz = MacSzForId(algoId);
    ssh->macKeyClientSz = ssh->macKeyServerSz = KeySzForId(algoId);

    /* The compression algorithm lists should have none as a value. */
    algoId = ID_NONE;

    /* Compression Algorithms - Client to Server */
    WLOG(WS_LOG_DEBUG, "DKI: Compression Algorithms - Client to Server");
    listSz = 1;
    DoNameList(list, &listSz, buf, len, &begin);
    if (MatchIdLists(list, listSz, &algoId, 1) == ID_UNKNOWN) {
        WLOG(WS_LOG_DEBUG, "Unable to negotiate Compression Algo C2S");
        return WS_INVALID_ALGO_ID;
    }

    /* Compression Algorithms - Server to Client */
    WLOG(WS_LOG_DEBUG, "DKI: Compression Algorithms - Server to Client");
    listSz = 1;
    DoNameList(list, &listSz, buf, len, &begin);
    if (MatchIdLists(list, listSz, &algoId, 1) == ID_UNKNOWN) {
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

    ssh->clientState = CLIENT_KEXINIT_DONE;
    return WS_SUCCESS;
}


static const uint8_t dhGenerator[] = { 2 };
static const uint8_t dhPrimeGroup1[] = {
    /* SSH DH Group 1 (Oakley Group 2, 1024-bit MODP Group, RFC 2409) */
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
    0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
    0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74,
    0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22,
    0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
    0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B,
    0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37,
    0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
    0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6,
    0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B,
    0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
    0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5,
    0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6,
    0x49, 0x28, 0x66, 0x51, 0xEC, 0xE6, 0x53, 0x81,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};
static const uint8_t dhPrimeGroup14[] = {
    /* SSH DH Group 14 (Oakley Group 14, 2048-bit MODP Group, RFC 3526) */
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
    0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
    0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74,
    0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22,
    0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
    0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B,
    0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37,
    0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
    0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6,
    0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B,
    0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
    0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5,
    0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6,
    0x49, 0x28, 0x66, 0x51, 0xEC, 0xE4, 0x5B, 0x3D,
    0xC2, 0x00, 0x7C, 0xB8, 0xA1, 0x63, 0xBF, 0x05,
    0x98, 0xDA, 0x48, 0x36, 0x1C, 0x55, 0xD3, 0x9A,
    0x69, 0x16, 0x3F, 0xA8, 0xFD, 0x24, 0xCF, 0x5F,
    0x83, 0x65, 0x5D, 0x23, 0xDC, 0xA3, 0xAD, 0x96,
    0x1C, 0x62, 0xF3, 0x56, 0x20, 0x85, 0x52, 0xBB,
    0x9E, 0xD5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6D,
    0x67, 0x0C, 0x35, 0x4E, 0x4A, 0xBC, 0x98, 0x04,
    0xF1, 0x74, 0x6C, 0x08, 0xCA, 0x18, 0x21, 0x7C,
    0x32, 0x90, 0x5E, 0x46, 0x2E, 0x36, 0xCE, 0x3B,
    0xE3, 0x9E, 0x77, 0x2C, 0x18, 0x0E, 0x86, 0x03,
    0x9B, 0x27, 0x83, 0xA2, 0xEC, 0x07, 0xA2, 0x8F,
    0xB5, 0xC5, 0x5D, 0xF0, 0x6F, 0x4C, 0x52, 0xC9,
    0xDE, 0x2B, 0xCB, 0xF6, 0x95, 0x58, 0x17, 0x18,
    0x39, 0x95, 0x49, 0x7C, 0xEA, 0x95, 0x6A, 0xE5,
    0x15, 0xD2, 0x26, 0x18, 0x98, 0xFA, 0x05, 0x10,
    0x15, 0x72, 0x8E, 0x5A, 0x8A, 0xAC, 0xAA, 0x68,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};
static const uint32_t dhGeneratorSz = sizeof(dhGenerator);
static const uint32_t dhPrimeGroup1Sz = sizeof(dhPrimeGroup1);
static const uint32_t dhPrimeGroup14Sz = sizeof(dhPrimeGroup14);


static int DoKexDhInit(WOLFSSH* ssh, uint8_t* buf, uint32_t len, uint32_t* idx)
{
    /* First get the length of the MP_INT, and then add in the hash of the
     * mp_int value of e as it appears in the packet. After that, decode e
     * into an mp_int struct for the DH calculation by wolfCrypt. */
    /* DYNTYPE_DH */

    uint8_t* e;
    uint32_t eSz;
    uint32_t begin = *idx;

    (void)len;

    ato32(buf + begin, &eSz);
    begin += LENGTH_SZ;

    e = buf + begin;
    begin += eSz;

    if (eSz <= sizeof(ssh->handshake->e)) {
        WMEMCPY(ssh->handshake->e, e, eSz);
        ssh->handshake->eSz = eSz;
    }

    ssh->clientState = CLIENT_KEXDH_INIT_DONE;
    *idx = begin;
    return WS_SUCCESS;
}


static int DoNewKeys(WOLFSSH* ssh, uint8_t* buf, uint32_t len, uint32_t* idx)
{
    (void)buf;
    (void)len;
    (void)idx;

    ssh->peerEncryptId = ssh->handshake->encryptId;
    ssh->peerMacId = ssh->handshake->macId;
    ssh->peerBlockSz = ssh->handshake->blockSz;
    ssh->peerMacSz = ssh->handshake->macSz;

    switch (ssh->peerEncryptId) {
        case ID_NONE:
            WLOG(WS_LOG_DEBUG, "DNK: peer using cipher none");
            break;

        case ID_AES128_CBC:
            WLOG(WS_LOG_DEBUG, "DNK: peer using cipher aes128-cbc");
            AesSetKey(&ssh->decryptCipher.aes,
                      ssh->encKeyClient, ssh->encKeyClientSz,
                      ssh->ivClient, AES_DECRYPTION);
            break;

        default:
            WLOG(WS_LOG_DEBUG, "DNK: peer using cipher invalid");
            break;
    }

    ssh->clientState = CLIENT_USING_KEYS;

    return WS_SUCCESS;
}


static int GenerateKey(uint8_t* key, uint32_t keySz, uint8_t keyId,
                       const uint8_t* k, uint32_t kSz,
                       const uint8_t* h, uint32_t hSz,
                       const uint8_t* sessionId, uint32_t sessionIdSz)
{
    uint32_t blocks, remainder;
    Sha sha;
    uint8_t kPad = 0;
    uint8_t pad = 0;
    uint8_t kSzFlat[LENGTH_SZ];

    if (k[0] & 0x80) kPad = 1;
    c32toa(kSz + kPad, kSzFlat);

    blocks = keySz / SHA_DIGEST_SIZE;
    remainder = keySz % SHA_DIGEST_SIZE;

    InitSha(&sha);
    ShaUpdate(&sha, kSzFlat, LENGTH_SZ);
    if (kPad) ShaUpdate(&sha, &pad, 1);
    ShaUpdate(&sha, k, kSz);
    ShaUpdate(&sha, h, hSz);
    ShaUpdate(&sha, &keyId, sizeof(keyId));
    ShaUpdate(&sha, sessionId, sessionIdSz);

    if (blocks == 0) {
        if (remainder > 0) {
            uint8_t lastBlock[SHA_DIGEST_SIZE];
            ShaFinal(&sha, lastBlock);
            WMEMCPY(key, lastBlock, remainder);
        }
    }
    else {
        uint32_t runningKeySz, curBlock;

        ShaFinal(&sha, key);
        runningKeySz = SHA_DIGEST_SIZE;

        for (curBlock = 1; curBlock < blocks; curBlock++) {
            InitSha(&sha);
            ShaUpdate(&sha, kSzFlat, LENGTH_SZ);
            if (kPad) ShaUpdate(&sha, &pad, 1);
            ShaUpdate(&sha, k, kSz);
            ShaUpdate(&sha, h, hSz);
            ShaUpdate(&sha, key, runningKeySz);
            ShaFinal(&sha, key + runningKeySz);
            runningKeySz += SHA_DIGEST_SIZE;
        }

        if (remainder > 0) {
            uint8_t lastBlock[SHA_DIGEST_SIZE];
            InitSha(&sha);
            ShaUpdate(&sha, kSzFlat, LENGTH_SZ);
            if (kPad) ShaUpdate(&sha, &pad, 1);
            ShaUpdate(&sha, k, kSz);
            ShaUpdate(&sha, h, hSz);
            ShaUpdate(&sha, key, runningKeySz);
            ShaFinal(&sha, lastBlock);
            WMEMCPY(key + runningKeySz, lastBlock, remainder);
        }
    }

    printf("Key ID %c:", keyId);
    DumpOctetString(key, keySz);

    return 0;
}


static int GenerateKeys(WOLFSSH* ssh)
{
    if (ssh == NULL)
        return WS_BAD_ARGUMENT;

    GenerateKey(ssh->ivClient, ssh->ivClientSz, 'A', ssh->k, ssh->kSz,
                ssh->h, ssh->hSz, ssh->sessionId, ssh->sessionIdSz);
    GenerateKey(ssh->ivServer, ssh->ivServerSz, 'B', ssh->k, ssh->kSz,
                ssh->h, ssh->hSz, ssh->sessionId, ssh->sessionIdSz);
    GenerateKey(ssh->encKeyClient, ssh->encKeyClientSz, 'C', ssh->k, ssh->kSz,
                ssh->h, ssh->hSz, ssh->sessionId, ssh->sessionIdSz);
    GenerateKey(ssh->encKeyServer, ssh->encKeyServerSz, 'D', ssh->k, ssh->kSz,
                ssh->h, ssh->hSz, ssh->sessionId, ssh->sessionIdSz);
    GenerateKey(ssh->macKeyClient, ssh->macKeyClientSz, 'E', ssh->k, ssh->kSz,
                ssh->h, ssh->hSz, ssh->sessionId, ssh->sessionIdSz);
    GenerateKey(ssh->macKeyServer, ssh->macKeyServerSz, 'F', ssh->k, ssh->kSz,
                ssh->h, ssh->hSz, ssh->sessionId, ssh->sessionIdSz);

    return 0;
}


static int DoIgnore(WOLFSSH* ssh, uint8_t* buf, uint32_t len, uint32_t* idx)
{
    uint32_t dataSz;
    uint32_t begin = *idx;

    (void)ssh;
    (void)len;

    ato32(buf + begin, &dataSz);
    begin += LENGTH_SZ + dataSz;

    *idx = begin;

    return WS_SUCCESS;
}


static int DoDebug(WOLFSSH* ssh, uint8_t* buf, uint32_t len, uint32_t* idx)
{
    uint8_t  alwaysDisplay;
    char*    msg = NULL;
    char*    lang = NULL;
    uint32_t strSz;
    uint32_t begin = *idx;

    (void)ssh;
    (void)len;

    alwaysDisplay = buf[begin++];

    ato32(buf + begin, &strSz);
    begin += LENGTH_SZ;
    if (strSz > 0) {
        msg = (char*)WMALLOC(strSz + 1, ssh->ctx->heap, DYNTYPE_STRING);
        if (msg != NULL) {
            WMEMCPY(msg, buf + begin, strSz);
            msg[strSz] = 0;
        }
        else {
            return WS_MEMORY_E;
        }
        begin += strSz;
    }

    ato32(buf + begin, &strSz);
    begin += LENGTH_SZ;
    if (strSz > 0) {
        lang = (char*)WMALLOC(strSz + 1, ssh->ctx->heap, DYNTYPE_STRING);
        if (lang != NULL) {
            WMEMCPY(lang, buf + begin, strSz);
            lang[strSz] = 0;
        }
        else {
            WFREE(msg, ssh->ctx->heap, DYNTYPE_STRING);
            return WS_MEMORY_E;
        }
        begin += strSz;
    }

    if (alwaysDisplay) {
        WLOG(WS_LOG_DEBUG, "DEBUG MSG (%s): %s",
             (lang == NULL) ? "none" : lang,
             (msg == NULL) ? "no message" : msg);
    }

    *idx = begin;

    WFREE(msg, ssh->ctx->heap, DYNTYPE_STRING);
    WFREE(lang, ssh->ctx->heap, DYNTYPE_STRING);

    return WS_SUCCESS;
}


static int DoUnimplemented(WOLFSSH* ssh,
                           uint8_t* buf, uint32_t len, uint32_t* idx)
{
    uint32_t seq;
    uint32_t begin = *idx;

    (void)ssh;
    (void)len;

    ato32(buf + begin, &seq);
    begin += UINT32_SZ;

    WLOG(WS_LOG_DEBUG, "UNIMPLEMENTED: seq %u", seq);

    *idx = begin;

    return WS_SUCCESS;
}


static int DoDisconnect(WOLFSSH* ssh, uint8_t* buf, uint32_t len, uint32_t* idx)
{
    uint32_t    reason;
    const char* reasonStr;
    uint32_t    begin = *idx;

    (void)ssh;
    (void)len;
    (void)reasonStr;

    ato32(buf + begin, &reason);
    begin += UINT32_SZ;

#ifdef NO_WOLFSSH_STRINGS
    WLOG(WS_LOG_DEBUG, "DISCONNECT: (%u)", reason);
#else
    switch (reason) {
        case WOLFSSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT:
            reasonStr = "host not allowed to connect"; break;
        case WOLFSSH_DISCONNECT_PROTOCOL_ERROR:
            reasonStr = "protocol error"; break;
        case WOLFSSH_DISCONNECT_KEY_EXCHANGE_FAILED:
            reasonStr = "key exchange failed"; break;
        case WOLFSSH_DISCONNECT_RESERVED:
            reasonStr = "reserved"; break;
        case WOLFSSH_DISCONNECT_MAC_ERROR:
            reasonStr = "mac error"; break;
        case WOLFSSH_DISCONNECT_COMPRESSION_ERROR:
            reasonStr = "compression error"; break;
        case WOLFSSH_DISCONNECT_SERVICE_NOT_AVAILABLE:
            reasonStr = "service not available"; break;
        case WOLFSSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED:
            reasonStr = "protocol version not supported"; break;
        case WOLFSSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE:
            reasonStr = "host key not verifiable"; break;
        case WOLFSSH_DISCONNECT_CONNECTION_LOST:
            reasonStr = "connection lost"; break;
        case WOLFSSH_DISCONNECT_BY_APPLICATION:
            reasonStr = "disconnect by application"; break;
        case WOLFSSH_DISCONNECT_TOO_MANY_CONNECTIONS:
            reasonStr = "too many connections"; break;
        case WOLFSSH_DISCONNECT_AUTH_CANCELLED_BY_USER:
            reasonStr = "auth cancelled by user"; break;
        case WOLFSSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE:
            reasonStr = "no more auth methods available"; break;
        case WOLFSSH_DISCONNECT_ILLEGAL_USER_NAME:
            reasonStr = "illegal user name"; break;
        default:
            reasonStr = "unknown reason";
    }
    WLOG(WS_LOG_DEBUG, "DISCONNECT: (%u) %s", reason, reasonStr);
#endif

    *idx = begin;

    return WS_SUCCESS;
}


static const char serviceNameUserAuth[] = "ssh-userauth";
/*static const char serviceNameConnection[] = "ssh-connection";*/


static int DoServiceRequest(WOLFSSH* ssh,
                            uint8_t* buf, uint32_t len, uint32_t* idx)
{
    uint32_t    begin = *idx;
    uint32_t    nameSz;
    char foo[32];
    (void)ssh;
    (void)buf;
    (void)len;

    ato32(buf + begin, &nameSz);
    begin += LENGTH_SZ;

    XMEMCPY(foo, buf + begin, nameSz);
    foo[nameSz] = 0;

    printf("Requesting service: %s\n", foo);
    SendServiceAccept(ssh, serviceNameUserAuth);

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

    WLOG(WS_LOG_DEBUG, "DoPacket sequence number: %d", ssh->peerSeq);

    idx += LENGTH_SZ;
    padSz = buf[idx++];
    payloadSz = ssh->curSz - PAD_LENGTH_SZ - padSz - MSG_ID_SZ;

    msg = buf[idx++];

    switch (msg) {

        case MSGID_DISCONNECT:
            WLOG(WS_LOG_DEBUG, "Decoding MSGID_KEXDH_INIT");
            DoDisconnect(ssh, buf, payloadSz, &idx);
            break;

        case MSGID_IGNORE:
            WLOG(WS_LOG_DEBUG, "Decoding MSGID_KEXDH_INIT");
            DoIgnore(ssh, buf, payloadSz, &idx);
            break;

        case MSGID_UNIMPLEMENTED:
            WLOG(WS_LOG_DEBUG, "Decoding MSGID_KEXDH_INIT");
            DoUnimplemented(ssh, buf, payloadSz, &idx);
            break;

        case MSGID_DEBUG:
            WLOG(WS_LOG_DEBUG, "Decoding MSGID_KEXDH_INIT");
            DoDebug(ssh, buf, payloadSz, &idx);
            break;

        case MSGID_KEXINIT:
            {
                uint8_t scratchLen[LENGTH_SZ];

                WLOG(WS_LOG_DEBUG, "Decoding MSGID_KEXINIT");
                c32toa(payloadSz + sizeof(msg), scratchLen);
                ShaUpdate(&ssh->handshake->hash, scratchLen, LENGTH_SZ);
                ShaUpdate(&ssh->handshake->hash, &msg, sizeof(msg));
                ShaUpdate(&ssh->handshake->hash, buf + idx, payloadSz);
                DoKexInit(ssh, buf, payloadSz, &idx);
            }
            break;

        case MSGID_NEWKEYS:
            WLOG(WS_LOG_DEBUG, "Decoding MSGID_NEWKEYS");
            DoNewKeys(ssh, buf, payloadSz, &idx);
            break;

        case MSGID_KEXDH_INIT:
            WLOG(WS_LOG_DEBUG, "Decoding MSGID_KEXDH_INIT");
            /* The mpint is 256 bytes long, the length is the standard 4 bytes,
             * and the msg ID is 1 byte. We pass the start of the payload data,
             * after the msg ID, to the Do function, but the length is the
             * payloadSz, which is +1 than the actual data. */
            DoKexDhInit(ssh, buf, payloadSz, &idx);
            break;

        case MSGID_SERVICE_REQUEST:
            WLOG(WS_LOG_DEBUG, "Decoding MSGID_SERVICE_REQUEST");
            DoServiceRequest(ssh, buf, payloadSz, &idx);
            break;

        default:
            WLOG(WS_LOG_DEBUG, "Unimplemented message ID (%d)", msg);
            DumpOctetString(buf + idx, payloadSz);
            SendUnimplemented(ssh);
            break;
    }

    if (idx + padSz > len) {
        WLOG(WS_LOG_DEBUG, "Not enough data in buffer for pad.");
        return WS_BUFFER_E;
    }
    idx += padSz;

    ssh->inputBuffer.idx = idx;
    ssh->peerSeq++;

    return WS_SUCCESS;
}


static INLINE int Encrypt(WOLFSSH* ssh, uint8_t* cipher, const uint8_t* input,
                          uint16_t sz)
{
    int ret = WS_SUCCESS;

    if (ssh == NULL || cipher == NULL || input == NULL || sz == 0)
        return WS_BAD_ARGUMENT;

    WLOG(WS_LOG_DEBUG, "Encrypt %s", IdToName(ssh->encryptId));

    switch (ssh->encryptId) {
        case ID_NONE:
            break;

        case ID_AES128_CBC:
            if (AesCbcEncrypt(&ssh->encryptCipher.aes, cipher, input, sz) < 0)
                ret = WS_ENCRYPT_E;
            break;

        default:
            ret = WS_INVALID_ALGO_ID;
    }

    return ret;
}


static INLINE int Decrypt(WOLFSSH* ssh, uint8_t* plain, const uint8_t* input,
                          uint16_t sz)
{
    int ret = WS_SUCCESS;

    if (ssh == NULL || plain == NULL || input == NULL || sz == 0)
        return WS_BAD_ARGUMENT;

    WLOG(WS_LOG_DEBUG, "Decrypt %s", IdToName(ssh->peerEncryptId));

    switch (ssh->peerEncryptId) {
        case ID_NONE:
            break;

        case ID_AES128_CBC:
            if (AesCbcDecrypt(&ssh->decryptCipher.aes, plain, input, sz) < 0)
                ret = WS_DECRYPT_E;
            break;

        default:
            ret = WS_INVALID_ALGO_ID;
    }

    return ret;
}


static INLINE int CreateMac(WOLFSSH* ssh, const uint8_t* in, uint32_t inSz,
                            uint8_t* mac)
{
    uint8_t  flatSeq[LENGTH_SZ];

    c32toa(ssh->seq++, flatSeq);

    /* Need to MAC the sequence number and the unencrypted packet */
    switch (ssh->macId) {
        case ID_NONE:
            break;

        case ID_HMAC_SHA1_96:
            {
                Hmac hmac;
                uint8_t digest[SHA_DIGEST_SIZE];

                HmacSetKey(&hmac, SHA, ssh->macKeyServer, ssh->macKeyServerSz);
                HmacUpdate(&hmac, flatSeq, sizeof(flatSeq));
                HmacUpdate(&hmac, in, inSz);
                HmacFinal(&hmac, digest);
                WMEMCPY(mac, digest, SHA1_96_SZ);
            }
            break;

        case ID_HMAC_SHA1:
            {
                Hmac hmac;

                HmacSetKey(&hmac, SHA, ssh->macKeyServer, ssh->macKeyServerSz);
                HmacUpdate(&hmac, flatSeq, sizeof(flatSeq));
                HmacUpdate(&hmac, in, inSz);
                HmacFinal(&hmac, mac);
            }
            break;

        default:
            WLOG(WS_LOG_DEBUG, "Invalid Mac ID");
            return WS_FATAL_ERROR;
    }

    return WS_SUCCESS;
}


static INLINE int VerifyMac(WOLFSSH* ssh, const uint8_t* in, uint32_t inSz,
                            const uint8_t* mac)
{
    int     ret = WS_SUCCESS;
    uint8_t flatSeq[LENGTH_SZ];
    uint8_t checkMac[SHA_DIGEST_SIZE];
    Hmac    hmac;

    c32toa(ssh->peerSeq, flatSeq);

    WLOG(WS_LOG_DEBUG, "VerifyMac %s", IdToName(ssh->peerMacId));
    WLOG(WS_LOG_DEBUG, "VM: inSz = %u", inSz);
    WLOG(WS_LOG_DEBUG, "VM: seq = %u", ssh->peerSeq);
    WLOG(WS_LOG_DEBUG, "VM: keyLen = %u", ssh->macKeyClientSz);

    switch (ssh->peerMacId) {
        case ID_NONE:
            break;

        case ID_HMAC_SHA1:
        case ID_HMAC_SHA1_96:
            HmacSetKey(&hmac, SHA, ssh->macKeyClient, ssh->macKeyClientSz);
            HmacUpdate(&hmac, flatSeq, sizeof(flatSeq));
            HmacUpdate(&hmac, in, inSz);
            HmacFinal(&hmac, checkMac);
            if (WMEMCMP(checkMac, mac, ssh->peerMacSz) != 0)
                ret = WS_VERIFY_MAC_E;
            break;

        default:
            ret = WS_INVALID_ALGO_ID;
    }

    return ret;
}


int ProcessReply(WOLFSSH* ssh)
{
    int ret = WS_FATAL_ERROR;
    uint32_t readSz;
    uint8_t peerBlockSz = ssh->peerBlockSz;
    uint8_t peerMacSz = ssh->peerMacSz;

    for (;;) {
        switch (ssh->processReplyState) {
            case PROCESS_INIT:
                readSz = peerBlockSz;
                WLOG(WS_LOG_DEBUG, "PR1: size = %u", readSz);
                if ((ret = GetInputData(ssh, readSz)) < 0) {
                    return ret;
                }
                ssh->processReplyState = PROCESS_PACKET_LENGTH;
                WLOG(WS_LOG_DEBUG, "idx = %u, length = %u",
                     ssh->inputBuffer.idx, ssh->inputBuffer.length);

                /* Decrypt first block if encrypted */
                ret = Decrypt(ssh,
                              ssh->inputBuffer.buffer + ssh->inputBuffer.idx,
                              ssh->inputBuffer.buffer + ssh->inputBuffer.idx,
                              readSz);

            case PROCESS_PACKET_LENGTH:
                /* Peek at the packet_length field. */
                ato32(ssh->inputBuffer.buffer + ssh->inputBuffer.idx,
                      &ssh->curSz);
                ssh->processReplyState = PROCESS_PACKET_FINISH;

            case PROCESS_PACKET_FINISH:
                readSz = ssh->curSz + LENGTH_SZ + peerMacSz;
                WLOG(WS_LOG_DEBUG, "PR2: size = %u", readSz);
                if (readSz > 0) {
                    if ((ret = GetInputData(ssh, readSz)) < 0) {
                        return ret;
                    }

                    ret = Decrypt(ssh,
                                  ssh->inputBuffer.buffer +
                                     ssh->inputBuffer.idx + peerBlockSz,
                                  ssh->inputBuffer.buffer +
                                     ssh->inputBuffer.idx + peerBlockSz,
                                  ssh->curSz + LENGTH_SZ - peerBlockSz);
                    if (ret != WS_SUCCESS) {
                        WLOG(WS_LOG_DEBUG, "PR: Decrypt fail");
                        return ret;
                    }

                    /* Verify the buffer is big enough for the data and mac. */
                    ret = VerifyMac(ssh,
                                    ssh->inputBuffer.buffer +
                                        ssh->inputBuffer.idx,
                                    ssh->curSz + LENGTH_SZ,
                                    ssh->inputBuffer.buffer +
                                        ssh->inputBuffer.idx +
                                        LENGTH_SZ + ssh->curSz);
                    if (ret != WS_SUCCESS) {
                        WLOG(WS_LOG_DEBUG, "PR: VerifyMac fail");
                        return ret;
                    }
                }
                ssh->processReplyState = PROCESS_PACKET;

            case PROCESS_PACKET:
                if ( (ret = DoPacket(ssh)) < 0) {
                    return ret;
                }
                WLOG(WS_LOG_DEBUG, "PR3: peerMacSz = %u", peerMacSz);
                ssh->inputBuffer.idx += peerMacSz;
                break;

            default:
                WLOG(WS_LOG_DEBUG, "Bad process input state, program error");
                return WS_INPUT_CASE_E;
        }
        ssh->processReplyState = PROCESS_INIT;
        return WS_SUCCESS;
    }
}


static const char sshIdStr[] = "SSH-2.0-wolfSSHv"
                               LIBWOLFSSH_VERSION_STRING
                               "\r\n";


int ProcessClientVersion(WOLFSSH* ssh)
{
    int error;
    uint32_t protoLen = 7; /* Length of the SSH-2.0 portion of the ID str */
    uint8_t scratch[LENGTH_SZ];

    if ( (error = GetInputText(ssh)) < 0) {
        WLOG(WS_LOG_DEBUG, "get input text failed");
        return error;
    }

    if (WSTRNCASECMP((char*)ssh->inputBuffer.buffer, sshIdStr, protoLen) == 0) {
        ssh->clientState = CLIENT_VERSION_DONE;
    }
    else {
        WLOG(WS_LOG_DEBUG, "SSH version mismatch");
        return WS_VERSION_E;
    }

    c32toa(ssh->inputBuffer.length - 2, scratch);
    ShaUpdate(&ssh->handshake->hash, scratch, LENGTH_SZ);
    ShaUpdate(&ssh->handshake->hash, ssh->inputBuffer.buffer,
                                                   ssh->inputBuffer.length - 2);
    ssh->inputBuffer.idx += ssh->inputBuffer.length;

    return WS_SUCCESS;
}


int SendServerVersion(WOLFSSH* ssh)
{
    uint32_t sshIdStrSz = (uint32_t)WSTRLEN(sshIdStr);
    uint8_t  scratch[LENGTH_SZ];

    WLOG(WS_LOG_DEBUG, "%s", sshIdStr);
    SendText(ssh, sshIdStr, (uint32_t)WSTRLEN(sshIdStr));
    sshIdStrSz -= 2; /* Remove the CRLF */
    c32toa(sshIdStrSz, scratch);
    ShaUpdate(&ssh->handshake->hash, scratch, LENGTH_SZ);
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
    paddingSz = ssh->blockSz -
                (LENGTH_SZ + PAD_LENGTH_SZ + payloadSz) % ssh->blockSz;
    if (paddingSz < 4)
        paddingSz += ssh->blockSz;
    ssh->paddingSz = paddingSz;
    packetSz = PAD_LENGTH_SZ + payloadSz + paddingSz;
    outputSz = LENGTH_SZ + packetSz + ssh->macSz;

    if ( (ret = GrowBuffer(&ssh->outputBuffer, outputSz, 0)) != WS_SUCCESS)
        return ret;

    ssh->packetStartIdx = ssh->outputBuffer.length;
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
    WLOG(WS_LOG_DEBUG, "paddingSz = %u", paddingSz);
    if (ssh->encryptId == ID_NONE)
        WMEMSET(output + idx, 0, paddingSz);
    else
        RNG_GenerateBlock(ssh->rng, output + idx, paddingSz);
    idx += paddingSz;

    CreateMac(ssh, ssh->outputBuffer.buffer + ssh->packetStartIdx,
              ssh->outputBuffer.length - ssh->packetStartIdx + paddingSz,
              output + idx);
    idx += ssh->macSz;

    WLOG(WS_LOG_DEBUG, "packetStartIdx = %u", ssh->packetStartIdx);
    WLOG(WS_LOG_DEBUG, "length = %u", ssh->outputBuffer.length);
    WLOG(WS_LOG_DEBUG, "Before encrypt:");
    DumpOctetString(ssh->outputBuffer.buffer + ssh->packetStartIdx,
                    ssh->outputBuffer.length - ssh->packetStartIdx + paddingSz);

    Encrypt(ssh,
            ssh->outputBuffer.buffer + ssh->packetStartIdx,
            ssh->outputBuffer.buffer + ssh->packetStartIdx,
            ssh->outputBuffer.length - ssh->packetStartIdx + paddingSz);

    WLOG(WS_LOG_DEBUG, "After encrypt:");
    DumpOctetString(ssh->outputBuffer.buffer + ssh->packetStartIdx,
                    ssh->outputBuffer.length - ssh->packetStartIdx + paddingSz);

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

    {
        uint8_t scratchLen[LENGTH_SZ];
        c32toa(payloadSz, scratchLen);
        ShaUpdate(&ssh->handshake->hash, scratchLen, LENGTH_SZ);
    }
    ShaUpdate(&ssh->handshake->hash, payload, payloadSz);

    BundlePacket(ssh);
    SendBuffered(ssh);

    return ret;
}


int SendKexDhReply(WOLFSSH* ssh)
{
    DhKey    dhKey;
    uint8_t  f[256];
    uint32_t fSz = sizeof(f);
    uint8_t  fPad = 0;
    uint8_t  y[256];
    uint32_t ySz = sizeof(y);
    uint8_t  kPad = 0;

    RsaKey   rsaKey;
    uint8_t  rsaE[257];
    uint32_t rsaESz = sizeof(rsaE);
    uint8_t  rsaEPad = 0;
    uint8_t  rsaN[257];
    uint32_t rsaNSz = sizeof(rsaN);
    uint8_t  rsaNPad = 0;
    uint32_t rsaKeyBlockSz;

    uint8_t  sig[512];
    uint32_t sigSz = sizeof(sig);
    uint32_t sigBlockSz;

    uint32_t payloadSz;
    uint8_t  scratchLen[LENGTH_SZ];
    uint32_t scratch = 0;
    uint8_t* output;
    uint32_t idx;
    int ret;

    InitDhKey(&dhKey);

    switch (ssh->handshake->kexId) {
        case ID_DH_GROUP1_SHA1:
            DhSetKey(&dhKey, dhPrimeGroup1, dhPrimeGroup1Sz,
                     dhGenerator, dhGeneratorSz);
            break;

        case ID_DH_GROUP14_SHA1:
            DhSetKey(&dhKey, dhPrimeGroup14, dhPrimeGroup14Sz,
                     dhGenerator, dhGeneratorSz);
            break;

        default:
            return -1;
    }

    /* Hash in the server's RSA key. */
    InitRsaKey(&rsaKey, ssh->ctx->heap);
    ret = RsaPrivateKeyDecode(ssh->ctx->privateKey, &scratch,
                              &rsaKey, (int)ssh->ctx->privateKeySz);
    if (ret < 0)
        return ret;
    RsaFlattenPublicKey(&rsaKey, rsaE, &rsaESz, rsaN, &rsaNSz);
    if (rsaE[0] & 0x80) rsaEPad = 1;
    if (rsaN[0] & 0x80) rsaNPad = 1;
    rsaKeyBlockSz = (LENGTH_SZ * 3) + 7 + rsaESz + rsaEPad + rsaNSz + rsaNPad;
        /* The 7 is for the name "ssh-rsa". */
    c32toa(rsaKeyBlockSz, scratchLen);
    ShaUpdate(&ssh->handshake->hash, scratchLen, LENGTH_SZ);
    c32toa(7, scratchLen);
    ShaUpdate(&ssh->handshake->hash, scratchLen, LENGTH_SZ);
    ShaUpdate(&ssh->handshake->hash, (const uint8_t*)"ssh-rsa", 7);
    c32toa(rsaESz + rsaEPad, scratchLen);
    ShaUpdate(&ssh->handshake->hash, scratchLen, LENGTH_SZ);
    if (rsaEPad) {
        scratchLen[0] = 0;
        ShaUpdate(&ssh->handshake->hash, scratchLen, 1);
    }
    ShaUpdate(&ssh->handshake->hash, rsaE, rsaESz);
    c32toa(rsaNSz + rsaNPad, scratchLen);
    ShaUpdate(&ssh->handshake->hash, scratchLen, LENGTH_SZ);
    if (rsaNPad) {
        scratchLen[0] = 0;
        ShaUpdate(&ssh->handshake->hash, scratchLen, 1);
    }
    ShaUpdate(&ssh->handshake->hash, rsaN, rsaNSz);

    /* Hash in the client's DH e-value. */
    c32toa(ssh->handshake->eSz, scratchLen);
    ShaUpdate(&ssh->handshake->hash, scratchLen, LENGTH_SZ);
    ShaUpdate(&ssh->handshake->hash, ssh->handshake->e, ssh->handshake->eSz);

    /* Make the server's DH f-value, and the shared secret k. */
    DhGenerateKeyPair(&dhKey, ssh->rng, y, &ySz, f, &fSz);
    if (f[0] & 0x80) fPad = 1;
    DhAgree(&dhKey,
            ssh->k, &ssh->kSz,
            y, ySz,
            ssh->handshake->e, ssh->handshake->eSz);
    if (ssh->k[0] & 0x80) kPad = 1;
    FreeDhKey(&dhKey);

#ifdef SHOW_MASTER_SECRET
    printf("Master secret:\n");
    DumpOctetString(ssh->k, ssh->kSz);
#endif

    /* Hash in the server's DH f-value. */
    c32toa(fSz + fPad, scratchLen);
    ShaUpdate(&ssh->handshake->hash, scratchLen, LENGTH_SZ);
    if (fPad) {
        scratchLen[0] = 0;
        ShaUpdate(&ssh->handshake->hash, scratchLen, 1);
    }
    ShaUpdate(&ssh->handshake->hash, f, fSz);

    /* Hash in the shared secret k. */
    c32toa(ssh->kSz + kPad, scratchLen);
    ShaUpdate(&ssh->handshake->hash, scratchLen, LENGTH_SZ);
    if (kPad) {
        scratchLen[0] = 0;
        ShaUpdate(&ssh->handshake->hash, scratchLen, 1);
    }
    ShaUpdate(&ssh->handshake->hash, ssh->k, ssh->kSz);

    /* Save the handshake hash value h, and session ID. */
    ShaFinal(&ssh->handshake->hash, ssh->h);
    ssh->hSz = SHA_DIGEST_SIZE;
#ifdef SHOW_MASTER_SECRET
    printf("Handshake hash:\n");
    DumpOctetString(ssh->h, ssh->hSz);
#endif
    if (ssh->sessionIdSz == 0) {
        WMEMCPY(ssh->sessionId, ssh->h, ssh->hSz);
        ssh->sessionIdSz = ssh->hSz;
    }

    /* Sign h with the server's RSA private key. */
    {
        Sha sha;
        uint8_t digest[SHA_DIGEST_SIZE];
        uint8_t encSig[512];
        uint32_t encSigSz;

        InitSha(&sha);
        ShaUpdate(&sha, ssh->h, ssh->hSz);
        ShaFinal(&sha, digest);

        encSigSz = EncodeSignature(encSig, digest, sizeof(digest), SHAh);
        if (encSigSz <= 0) {
            WLOG(WS_LOG_DEBUG, "SendKexDhReply: Bad Encode Sig");
        }
        else {
            /* At this point, sigSz should already be sizeof(sig) */
            sigSz = RsaSSL_Sign(encSig, encSigSz,
                                sig, sigSz, &rsaKey, ssh->rng);
            if (sigSz <= 0) {
                WLOG(WS_LOG_DEBUG, "SendKexDhReply: Bad RSA Sign");
            }
            else {
                /* Success */
            }
        }
    }
    FreeRsaKey(&rsaKey);
    sigBlockSz = (LENGTH_SZ * 2) + 7 + sigSz;

    GenerateKeys(ssh);

    /* Get the buffer, copy the packet data, once f is laid into the buffer,
     * add it to the hash and then add K. */
    payloadSz = MSG_ID_SZ + (LENGTH_SZ * 3) +
                rsaKeyBlockSz + fSz + fPad + sigBlockSz;
    PreparePacket(ssh, payloadSz);
    output = ssh->outputBuffer.buffer;
    idx = ssh->outputBuffer.length;

    output[idx++] = MSGID_KEXDH_REPLY;

    /* Copy the rsaKeyBlock into the buffer. */
    c32toa(rsaKeyBlockSz, output + idx);
    idx += LENGTH_SZ;
    c32toa(7, output + idx);
    idx += LENGTH_SZ;
    WMEMCPY(output + idx, "ssh-rsa", 7);
    idx += 7;
    c32toa(rsaESz + rsaEPad, output + idx);
    idx += LENGTH_SZ;
    if (rsaEPad) output[idx++] = 0;
    WMEMCPY(output + idx, rsaE, rsaESz);
    idx += rsaESz;
    c32toa(rsaNSz + rsaNPad, output + idx);
    idx += LENGTH_SZ;
    if (rsaNPad) output[idx++] = 0;
    WMEMCPY(output + idx, rsaN, rsaNSz);
    idx += rsaNSz;

    c32toa(fSz + fPad, output + idx);
    idx += LENGTH_SZ;
    if (fPad) output[idx++] = 0;
    WMEMCPY(output + idx, f, fSz);
    idx += fSz;

    c32toa(sigBlockSz, output + idx);
    idx += LENGTH_SZ;
    c32toa(7, output + idx);
    idx += LENGTH_SZ;
    WMEMCPY(output + idx, "ssh-rsa", 7);
    idx += 7;
    c32toa(sigSz, output + idx);
    idx += LENGTH_SZ;
    WMEMCPY(output + idx, sig, sigSz);
    idx += sigSz;

    ssh->outputBuffer.length = idx;

    BundlePacket(ssh);
    SendBuffered(ssh);

    return 0;
}


int SendNewKeys(WOLFSSH* ssh)
{
    uint8_t* output;
    uint32_t idx = 0;

    PreparePacket(ssh, MSG_ID_SZ);

    output = ssh->outputBuffer.buffer;
    idx = ssh->outputBuffer.length;

    output[idx++] = MSGID_NEWKEYS;
    
    ssh->outputBuffer.length = idx;

    BundlePacket(ssh);
    SendBuffered(ssh);

    ssh->blockSz = ssh->handshake->blockSz;
    ssh->encryptId = ssh->handshake->encryptId;
    ssh->macSz = ssh->handshake->macSz;
    ssh->macId = ssh->handshake->macId;

    switch (ssh->encryptId) {
        case ID_NONE:
            WLOG(WS_LOG_DEBUG, "SNK: using cipher none");
            break;

        case ID_AES128_CBC:
            WLOG(WS_LOG_DEBUG, "SNK: using cipher aes128-cbc");
            AesSetKey(&ssh->encryptCipher.aes,
                      ssh->encKeyServer, ssh->encKeyServerSz,
                      ssh->ivServer, AES_ENCRYPTION);
            break;

        default:
            WLOG(WS_LOG_DEBUG, "SNK: using cipher invalid");
            break;
    }

    return WS_SUCCESS;
}


int SendUnimplemented(WOLFSSH* ssh)
{
    uint8_t* output;
    uint32_t idx = 0;

    PreparePacket(ssh, MSG_ID_SZ + LENGTH_SZ);

    output = ssh->outputBuffer.buffer;
    idx = ssh->outputBuffer.length;

    output[idx++] = MSGID_UNIMPLEMENTED;
    c32toa(ssh->peerSeq, output + idx);
    idx += UINT32_SZ;

    ssh->outputBuffer.length = idx;

    BundlePacket(ssh);
    SendBuffered(ssh);

    return WS_SUCCESS;
}


int SendDisconnect(WOLFSSH* ssh, uint32_t reason)
{
    uint8_t* output;
    uint32_t idx = 0;

    PreparePacket(ssh, MSG_ID_SZ + UINT32_SZ + (LENGTH_SZ * 2));

    output = ssh->outputBuffer.buffer;
    idx = ssh->outputBuffer.length;

    output[idx++] = MSGID_DISCONNECT;
    c32toa(reason, output + idx);
    idx += UINT32_SZ;
    c32toa(0, output + idx);
    idx += LENGTH_SZ;
    c32toa(0, output + idx);
    idx += LENGTH_SZ;

    ssh->outputBuffer.length = idx;

    BundlePacket(ssh);
    SendBuffered(ssh);

    return WS_SUCCESS;
}


int SendIgnore(WOLFSSH* ssh, const unsigned char* data, uint32_t dataSz)
{
    uint8_t* output;
    uint32_t idx = 0;

    if (ssh == NULL || (data == NULL && dataSz > 0))
        return WS_BAD_ARGUMENT;

    PreparePacket(ssh, MSG_ID_SZ + LENGTH_SZ + dataSz);

    output = ssh->outputBuffer.buffer;
    idx = ssh->outputBuffer.length;

    output[idx++] = MSGID_IGNORE;
    c32toa(dataSz, output + idx);
    idx += LENGTH_SZ;
    if (dataSz > 0) {
        WMEMCPY(output + idx, data, dataSz);
        idx += dataSz;
    }

    ssh->outputBuffer.length = idx;

    BundlePacket(ssh);
    SendBuffered(ssh);

    return WS_SUCCESS;
}


static const char     cannedLangTag[] = "en-us";
static const uint32_t cannedLangTagSz = sizeof(cannedLangTag) - 1;


int SendDebug(WOLFSSH* ssh, byte alwaysDisplay, const char* msg)
{
    uint32_t msgSz;
    uint8_t* output;
    uint32_t idx = 0;

    if (ssh == NULL)
        return WS_BAD_ARGUMENT;

    msgSz = (msg != NULL) ? (uint32_t)WSTRLEN(msg) : 0;

    PreparePacket(ssh,
                  MSG_ID_SZ + BOOLEAN_SZ + (LENGTH_SZ * 2) +
                  msgSz + cannedLangTagSz);

    output = ssh->outputBuffer.buffer;
    idx = ssh->outputBuffer.length;

    output[idx++] = MSGID_DEBUG;
    output[idx++] = (alwaysDisplay != 0);
    c32toa(msgSz, output + idx);
    idx += LENGTH_SZ;
    if (msgSz > 0) {
        WMEMCPY(output + idx, msg, msgSz);
        idx += msgSz;
    }
    c32toa(cannedLangTagSz, output + idx);
    idx += LENGTH_SZ;
    WMEMCPY(output + idx, cannedLangTag, cannedLangTagSz);
    idx += cannedLangTagSz;

    ssh->outputBuffer.length = idx;

    BundlePacket(ssh);
    SendBuffered(ssh);

    return WS_SUCCESS;
}


int SendServiceAccept(WOLFSSH* ssh, const char* name)
{
    uint32_t nameSz;
    uint8_t* output;
    uint32_t idx;

    if (ssh == NULL || name == NULL)
        return WS_BAD_ARGUMENT;

    nameSz = (uint32_t)WSTRLEN(name);
    PreparePacket(ssh, MSG_ID_SZ + LENGTH_SZ + nameSz);

    output = ssh->outputBuffer.buffer;
    idx = ssh->outputBuffer.length;

    output[idx++] = MSGID_SERVICE_ACCEPT;
    c32toa(nameSz, output + idx);
    idx += LENGTH_SZ;
    WMEMCPY(output + idx, name, nameSz);
    idx += nameSz;

    ssh->outputBuffer.length = idx;

    BundlePacket(ssh);
    SendBuffered(ssh);

    return WS_SUCCESS;
}


#define LINE_WIDTH 16
void DumpOctetString(const uint8_t* input, uint32_t inputSz)
{
    int rows = inputSz / LINE_WIDTH;
    int remainder = inputSz % LINE_WIDTH;
    int i,j;

    for (i = 0; i < rows; i++) {
        printf("%04X: ", i * LINE_WIDTH);
        for (j = 0; j < LINE_WIDTH; j++) {
            printf("%02X ", input[i * LINE_WIDTH + j]);
        }
        printf("\n");
    }
    if (remainder) {
        printf("%04X: ", i * LINE_WIDTH);
        for (j = 0; j < remainder; j++) {
            printf("%02X ", input[i * LINE_WIDTH + j]);
        }
        printf("\n");
    }
}


/* regress.c
 *
 * Regression coverage for message ordering / keying state handling.
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

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#ifdef WOLFSSL_USER_SETTINGS
    #include <wolfssl/wolfcrypt/settings.h>
#else
    #include <wolfssl/options.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#include <wolfssh/port.h>
#include <wolfssh/ssh.h>
#include <wolfssh/internal.h>
#ifdef WOLFSSH_SFTP
    #include <wolfssh/wolfsftp.h>
#endif
#include "apps/wolfssh/common.h"

#ifndef WOLFSSH_NO_ABORT
    #define WABORT() abort()
#else
    #define WABORT()
#endif

#define PrintError(description, result) do {                                   \
    printf("\nERROR - %s line %d failed with:", __FILE__, __LINE__);           \
    printf("\n    expected: "); printf description;                            \
    printf("\n    result:   "); printf result; printf("\n\n");                 \
} while(0)

#define Fail(description, result) do {                                         \
    PrintError(description, result);                                           \
    WABORT();                                                                  \
} while(0)

#define Assert(test, description, result) if (!(test)) Fail(description, result)

#define AssertTrue(x)    Assert((x), ("%s is true",     #x), (#x " => FALSE"))
#define AssertFalse(x)   Assert(!(x), ("%s is false",    #x), (#x " => TRUE"))
#define AssertNotNull(x) Assert((x), ("%s is not null", #x), (#x " => NULL"))
#define AssertIntEQ(x, y) do { int _x = (int)(x); int _y = (int)(y);           \
    Assert(_x == _y, ("%s == %s", #x, #y), ("%d != %d", _x, _y)); } while (0)


static void ResetSession(WOLFSSH* ssh)
{
    if (ssh->handshake != NULL) {
        WFREE(ssh->handshake, ssh->ctx->heap, DYNTYPE_HS);
        ssh->handshake = NULL;
    }
    ssh->isKeying = 0;
    ssh->connectState = CONNECT_BEGIN;
    ssh->error = 0;
}


static HandshakeInfo* AllocHandshake(WOLFSSH* ssh)
{
    HandshakeInfo* hs;

    hs = (HandshakeInfo*)WMALLOC(sizeof(HandshakeInfo), ssh->ctx->heap,
            DYNTYPE_HS);
    AssertNotNull(hs);
    WMEMSET(hs, 0, sizeof(HandshakeInfo));
    hs->blockSz = MIN_BLOCK_SZ;
    hs->eSz = (word32)sizeof(hs->e);
    hs->xSz = (word32)sizeof(hs->x);

    return hs;
}

/* Build a minimal SSH binary packet carrying only a message ID.
 * Layout: uint32 packetLen, byte padLen, payload[msgId], pad[padLen].
 * Choose padLen so total is 8-byte aligned for the clear transport case. */
static word32 BuildPacket(byte msgId, byte* out, word32 outSz)
{
    byte padLen = 6; /* 1 (msgId) +1 (padLen) +6 = 8 */
    word32 packetLen = 1 + 1 + padLen; /* payload + padLen field + pad */
    word32 need = 4 + packetLen;

    AssertTrue(outSz >= need);
    out[0] = (byte)(packetLen >> 24);
    out[1] = (byte)(packetLen >> 16);
    out[2] = (byte)(packetLen >> 8);
    out[3] = (byte)(packetLen);
    out[4] = padLen;
    out[5] = msgId;
    WMEMSET(out + 6, 0, padLen);
    return need;
}

static byte ParseMsgId(const byte* pkt, word32 sz)
{
    AssertTrue(sz >= 6);
    return pkt[5];
}

static word32 AppendByte(byte* buf, word32 bufSz, word32 idx, byte value)
{
    AssertTrue(idx < bufSz);
    buf[idx++] = value;
    return idx;
}

static word32 AppendUint32(byte* buf, word32 bufSz, word32 idx, word32 value)
{
    word32 netValue = htonl(value);

    AssertTrue(idx + UINT32_SZ <= bufSz);
    WMEMCPY(buf + idx, &netValue, UINT32_SZ);
    idx += UINT32_SZ;
    return idx;
}

static word32 AppendData(byte* buf, word32 bufSz, word32 idx,
        const byte* data, word32 dataSz)
{
    AssertTrue(idx + dataSz <= bufSz);
    if (dataSz > 0) {
        WMEMCPY(buf + idx, data, dataSz);
        idx += dataSz;
    }
    return idx;
}

static word32 AppendString(byte* buf, word32 bufSz, word32 idx,
        const char* value)
{
    word32 valueSz = (word32)WSTRLEN(value);

    idx = AppendUint32(buf, bufSz, idx, valueSz);
    return AppendData(buf, bufSz, idx, (const byte*)value, valueSz);
}

static word32 WrapPacket(byte msgId, const byte* payload, word32 payloadSz,
        byte* out, word32 outSz)
{
    word32 idx = 0;
    word32 packetLen;
    word32 need;
    byte padLen = MIN_PAD_LENGTH;

    while (((UINT32_SZ + PAD_LENGTH_SZ + MSG_ID_SZ + payloadSz + padLen) %
            MIN_BLOCK_SZ) != 0) {
        padLen++;
    }

    packetLen = PAD_LENGTH_SZ + MSG_ID_SZ + payloadSz + padLen;
    need = UINT32_SZ + packetLen;

    AssertTrue(outSz >= need);

    idx = AppendUint32(out, outSz, idx, packetLen);
    idx = AppendByte(out, outSz, idx, padLen);
    idx = AppendByte(out, outSz, idx, msgId);
    idx = AppendData(out, outSz, idx, payload, payloadSz);
    AssertTrue(idx + padLen <= outSz);
    WMEMSET(out + idx, 0, padLen);
    idx += padLen;

    return idx;
}

static word32 BuildChannelOpenPacket(const char* type, word32 peerChannelId,
        word32 peerInitialWindowSz, word32 peerMaxPacketSz,
        const byte* extra, word32 extraSz, byte* out, word32 outSz)
{
    byte payload[256];
    word32 idx = 0;

    idx = AppendString(payload, sizeof(payload), idx, type);
    idx = AppendUint32(payload, sizeof(payload), idx, peerChannelId);
    idx = AppendUint32(payload, sizeof(payload), idx, peerInitialWindowSz);
    idx = AppendUint32(payload, sizeof(payload), idx, peerMaxPacketSz);
    idx = AppendData(payload, sizeof(payload), idx, extra, extraSz);

    return WrapPacket(MSGID_CHANNEL_OPEN, payload, idx, out, outSz);
}

#ifdef WOLFSSH_FWD
static word32 BuildDirectTcpipExtra(const char* host, word32 hostPort,
        const char* origin, word32 originPort, byte* out, word32 outSz)
{
    word32 idx = 0;

    idx = AppendString(out, outSz, idx, host);
    idx = AppendUint32(out, outSz, idx, hostPort);
    idx = AppendString(out, outSz, idx, origin);
    idx = AppendUint32(out, outSz, idx, originPort);

    return idx;
}
#endif

/* Simple in-memory transport harness */
typedef struct {
    byte* in;      /* data to feed into client */
    word32 inSz;
    word32 inOff;
    byte* out;     /* data written by client */
    word32 outSz;
    word32 outCap;
} MemIo;

static int MemRecv(WOLFSSH* ssh, void* buf, word32 sz, void* ctx)
{
    (void)ssh;
    MemIo* io = (MemIo*)ctx;
    word32 remain = io->inSz - io->inOff;
    if (remain == 0)
        return WS_CBIO_ERR_WANT_READ;
    if (sz > remain)
        sz = remain;
    WMEMCPY(buf, io->in + io->inOff, sz);
    io->inOff += sz;
    return (int)sz;
}

static int MemSend(WOLFSSH* ssh, void* buf, word32 sz, void* ctx)
{
    (void)ssh;
    MemIo* io = (MemIo*)ctx;
    if (io->outSz + sz > io->outCap) {
        return WS_CBIO_ERR_GENERAL;
    }
    WMEMCPY(io->out + io->outSz, buf, sz);
    io->outSz += sz;
    return (int)sz;
}

static void MemIoInit(MemIo* io, byte* in, word32 inSz, byte* out, word32 outCap)
{
    io->in = in;
    io->inSz = inSz;
    io->inOff = 0;
    io->out = out;
    io->outSz = 0;
    io->outCap = outCap;
}

typedef struct {
    WOLFSSH_CTX* ctx;
    WOLFSSH* ssh;
    MemIo io;
    byte out[256];
} ChannelOpenHarness;

static void InitChannelOpenHarness(ChannelOpenHarness* harness,
        byte* in, word32 inSz)
{
    WMEMSET(harness, 0, sizeof(*harness));

    harness->ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_SERVER, NULL);
    AssertNotNull(harness->ctx);

    wolfSSH_SetIORecv(harness->ctx, MemRecv);
    wolfSSH_SetIOSend(harness->ctx, MemSend);

    harness->ssh = wolfSSH_new(harness->ctx);
    AssertNotNull(harness->ssh);

    MemIoInit(&harness->io, in, inSz, harness->out, sizeof(harness->out));
    wolfSSH_SetIOReadCtx(harness->ssh, &harness->io);
    wolfSSH_SetIOWriteCtx(harness->ssh, &harness->io);
    harness->ssh->acceptState = ACCEPT_SERVER_USERAUTH_SENT;
}

static void FreeChannelOpenHarness(ChannelOpenHarness* harness)
{
    if (harness->ssh != NULL)
        wolfSSH_free(harness->ssh);
    if (harness->ctx != NULL)
        wolfSSH_CTX_free(harness->ctx);
}

#if !defined(NO_WOLFSSH_SERVER) && !defined(NO_WOLFSSH_CLIENT) && \
    !defined(WOLFSSH_NO_RSA) && !defined(NO_FILESYSTEM)
    #if !defined(WOLFSSH_NO_DH_GROUP14_SHA256)
        #define KEXDH_REPLY_REGRESS_KEX_ALGO "diffie-hellman-group14-sha256"
    #elif !defined(WOLFSSH_NO_DH_GROUP16_SHA512)
        #define KEXDH_REPLY_REGRESS_KEX_ALGO "diffie-hellman-group16-sha512"
    #elif !defined(WOLFSSH_NO_DH_GROUP14_SHA1)
        #define KEXDH_REPLY_REGRESS_KEX_ALGO "diffie-hellman-group14-sha1"
    #elif !defined(WOLFSSH_NO_DH_GROUP1_SHA1)
        #define KEXDH_REPLY_REGRESS_KEX_ALGO "diffie-hellman-group1-sha1"
    #endif
#endif

#ifdef KEXDH_REPLY_REGRESS_KEX_ALGO

#define REGRESS_DUPLEX_QUEUE_SZ 32768U
#define REGRESS_MUTATION_SCRATCH_SZ 4096U
#define REGRESS_SERVER_KEY_PATH "keys/server-key-rsa.der"
#define REGRESS_USERNAME "jill"
#define REGRESS_PASSWORD "upthehill"
#define REGRESS_MAX_HANDSHAKE_STEPS 2048
#define REGRESS_SSH_PROTO_PREFIX "SSH-"
#define REGRESS_SSH_PROTO_PREFIX_SZ 4U

typedef struct {
    byte data[REGRESS_DUPLEX_QUEUE_SZ];
    word32 len;
} DuplexQueue;

typedef struct {
    byte enabled;
    int parseError;
    word32 matchedPackets;
    word32 mutatedPackets;
    byte scratch[REGRESS_MUTATION_SCRATCH_SZ];
    word32 scratchSz;
} KexReplyMutator;

typedef struct DuplexEndpoint {
    DuplexQueue inbound;
    struct DuplexEndpoint* peer;
    KexReplyMutator* mutator;
    byte isServer;
} DuplexEndpoint;

typedef struct {
    WOLFSSH_CTX* clientCtx;
    WOLFSSH_CTX* serverCtx;
    WOLFSSH* client;
    WOLFSSH* server;
    DuplexEndpoint clientIo;
    DuplexEndpoint serverIo;
    KexReplyMutator mutator;
} KexReplyHarness;

typedef struct {
    int clientRet;
    int clientErr;
    int serverRet;
    int serverErr;
    int clientSuccess;
    int serverSuccess;
    word32 steps;
} KexReplyRunResult;

static word32 ReadUint32(const byte* buf)
{
    return ((word32)buf[0] << 24) | ((word32)buf[1] << 16) |
            ((word32)buf[2] << 8) | (word32)buf[3];
}

static int ReadStringRef(word32* strSz, const byte** str,
        const byte* buf, word32 len, word32* idx)
{
    if (strSz == NULL || str == NULL || buf == NULL || idx == NULL) {
        return WS_BAD_ARGUMENT;
    }

    if (*idx > len || len - *idx < LENGTH_SZ) {
        return WS_PARSE_E;
    }

    *strSz = ReadUint32(buf + *idx);
    *idx += LENGTH_SZ;
    if (*strSz > len - *idx) {
        return WS_PARSE_E;
    }

    *str = buf + *idx;
    *idx += *strSz;

    return WS_SUCCESS;
}

static word32 AppendBlob(byte* buf, word32 bufSz, word32 idx,
        const byte* data, word32 dataSz)
{
    idx = AppendUint32(buf, bufSz, idx, dataSz);
    return AppendData(buf, bufSz, idx, data, dataSz);
}

static word32 LoadFileBuffer(const char* path, byte* buf, word32 bufSz)
{
    WFILE* file;
    long fileSz;
    word32 readSz;

    if (path == NULL || buf == NULL || bufSz == 0) {
        return 0;
    }

    if (WFOPEN(NULL, &file, path, "rb") != 0 || file == WBADFILE) {
        return 0;
    }
    WFSEEK(NULL, file, 0, WSEEK_END);
    fileSz = WFTELL(NULL, file);
    WREWIND(NULL, file);

    if (fileSz <= 0 || (word32)fileSz > bufSz) {
        WFCLOSE(NULL, file);
        return 0;
    }

    readSz = (word32)WFREAD(NULL, buf, 1, fileSz, file);
    WFCLOSE(NULL, file);

    if (readSz != (word32)fileSz) {
        return 0;
    }

    return readSz;
}

static int RegressionClientUserAuth(byte authType,
        WS_UserAuthData* authData, void* ctx)
{
    static const char password[] = REGRESS_PASSWORD;

    (void)ctx;

    if (authType != WOLFSSH_USERAUTH_PASSWORD || authData == NULL) {
        return WOLFSSH_USERAUTH_INVALID_AUTHTYPE;
    }

    authData->sf.password.password = (byte*)password;
    authData->sf.password.passwordSz = (word32)WSTRLEN(password);

    return WOLFSSH_USERAUTH_SUCCESS;
}

static int RegressionServerUserAuth(byte authType,
        WS_UserAuthData* authData, void* ctx)
{
    static const char password[] = REGRESS_PASSWORD;
    word32 passwordSz = (word32)WSTRLEN(password);

    (void)ctx;

    if (authType != WOLFSSH_USERAUTH_PASSWORD || authData == NULL) {
        return WOLFSSH_USERAUTH_FAILURE;
    }

    if (authData->sf.password.password == NULL ||
            authData->sf.password.passwordSz != passwordSz) {
        return WOLFSSH_USERAUTH_FAILURE;
    }

    if (WMEMCMP(authData->sf.password.password, password, passwordSz) != 0) {
        return WOLFSSH_USERAUTH_FAILURE;
    }

    return WOLFSSH_USERAUTH_SUCCESS;
}

static int AcceptAnyServerHostKey(const byte* pubKey, word32 pubKeySz,
        void* ctx)
{
    (void)pubKey;
    (void)pubKeySz;
    (void)ctx;

    return 0;
}

static int QueueAppend(DuplexQueue* queue, const byte* data, word32 dataSz)
{
    if (queue == NULL || data == NULL) {
        return WS_BAD_ARGUMENT;
    }

    if (dataSz > sizeof(queue->data) - queue->len) {
        return WS_BUFFER_E;
    }

    WMEMCPY(queue->data + queue->len, data, dataSz);
    queue->len += dataSz;

    return WS_SUCCESS;
}

static int RewriteSingleKexDhReplyPacket(const byte* packet, word32 packetSz,
        const char* replacement, byte* out, word32 outSz, word32* outLen)
{
    const byte* payload;
    const byte* pubKey;
    const byte* f;
    const byte* sigBlob;
    const byte* sigName;
    const byte* sigData;
    word32 packetLen, padLen, payloadSz;
    word32 pubKeySz, fSz, sigBlobSz;
    word32 sigNameSz, sigDataSz;
    word32 idx = 0;
    word32 innerIdx = 0;
    word32 outerIdx = 0;
    word32 innerSigSz;
    byte payloadBuf[REGRESS_MUTATION_SCRATCH_SZ];
    byte innerSig[REGRESS_MUTATION_SCRATCH_SZ];

    if (replacement == NULL || out == NULL || outLen == NULL) {
        return WS_BAD_ARGUMENT;
    }

    if (packetSz < UINT32_SZ + PAD_LENGTH_SZ + MSG_ID_SZ) {
        return 0;
    }

    packetLen = ReadUint32(packet);
    if (packetLen + UINT32_SZ != packetSz) {
        return 0;
    }

    padLen = packet[UINT32_SZ];
    if (packetLen < PAD_LENGTH_SZ + MSG_ID_SZ + padLen) {
        return WS_PARSE_E;
    }

    if (packet[UINT32_SZ + PAD_LENGTH_SZ] != MSGID_KEXDH_REPLY) {
        return 0;
    }

    payload = packet + UINT32_SZ + PAD_LENGTH_SZ + MSG_ID_SZ;
    payloadSz = packetSz - UINT32_SZ - PAD_LENGTH_SZ - MSG_ID_SZ - padLen;

    if (ReadStringRef(&pubKeySz, &pubKey, payload, payloadSz, &idx) !=
            WS_SUCCESS) {
        return WS_PARSE_E;
    }
    if (ReadStringRef(&fSz, &f, payload, payloadSz, &idx) != WS_SUCCESS) {
        return WS_PARSE_E;
    }
    if (ReadStringRef(&sigBlobSz, &sigBlob, payload, payloadSz, &idx) !=
            WS_SUCCESS) {
        return WS_PARSE_E;
    }

    if (ReadStringRef(&sigNameSz, &sigName, sigBlob, sigBlobSz, &innerIdx) !=
            WS_SUCCESS) {
        return WS_PARSE_E;
    }
    if (ReadStringRef(&sigDataSz, &sigData, sigBlob, sigBlobSz, &innerIdx) !=
            WS_SUCCESS) {
        return WS_PARSE_E;
    }

    if (innerIdx != sigBlobSz) {
        return WS_PARSE_E;
    }

    (void)sigName;
    (void)sigNameSz;

    innerSigSz = 0;
    innerSigSz = AppendString(innerSig, sizeof(innerSig), innerSigSz,
            replacement);
    innerSigSz = AppendBlob(innerSig, sizeof(innerSig), innerSigSz,
            sigData, sigDataSz);

    outerIdx = 0;
    outerIdx = AppendBlob(payloadBuf, sizeof(payloadBuf), outerIdx,
            pubKey, pubKeySz);
    outerIdx = AppendBlob(payloadBuf, sizeof(payloadBuf), outerIdx, f, fSz);
    outerIdx = AppendBlob(payloadBuf, sizeof(payloadBuf), outerIdx,
            innerSig, innerSigSz);
    *outLen = WrapPacket(MSGID_KEXDH_REPLY, payloadBuf, outerIdx, out, outSz);

    return 1;
}

static int RewriteKexDhReplySignatureName(const byte* packet, word32 packetSz,
        const char* replacement, byte* out, word32 outSz, word32* outLen)
{
    word32 offset = 0;

    if (packet == NULL || replacement == NULL || out == NULL || outLen == NULL) {
        return WS_BAD_ARGUMENT;
    }

    while (packetSz - offset >= UINT32_SZ + PAD_LENGTH_SZ + MSG_ID_SZ) {
        word32 curPacketSz = ReadUint32(packet + offset) + UINT32_SZ;
        int rewriteRet;

        if (curPacketSz > packetSz - offset) {
            return 0;
        }

        if (packet[offset + UINT32_SZ + PAD_LENGTH_SZ] == MSGID_KEXDH_REPLY) {
            rewriteRet = RewriteSingleKexDhReplyPacket(packet + offset,
                    curPacketSz, replacement, out, outSz, outLen);
            if (rewriteRet <= 0) {
                return rewriteRet;
            }

            if (packetSz - offset - curPacketSz > outSz - *outLen) {
                return WS_BUFFER_E;
            }

            WMEMCPY(out + *outLen, packet + offset + curPacketSz,
                    packetSz - offset - curPacketSz);
            *outLen += packetSz - offset - curPacketSz;

            return 1;
        }

        offset += curPacketSz;
    }

    return 0;
}

static int DuplexRecv(WOLFSSH* ssh, void* buf, word32 sz, void* ctx)
{
    DuplexEndpoint* endpoint = (DuplexEndpoint*)ctx;
    word32 readSz;

    (void)ssh;

    if (endpoint == NULL || buf == NULL) {
        return WS_CBIO_ERR_GENERAL;
    }

    if (endpoint->inbound.len == 0) {
        return WS_CBIO_ERR_WANT_READ;
    }

    readSz = sz;
    if (readSz > endpoint->inbound.len) {
        readSz = endpoint->inbound.len;
    }

    WMEMCPY(buf, endpoint->inbound.data, readSz);
    endpoint->inbound.len -= readSz;
    if (endpoint->inbound.len > 0) {
        WMEMMOVE(endpoint->inbound.data, endpoint->inbound.data + readSz,
                endpoint->inbound.len);
    }

    return (int)readSz;
}

static int DuplexSend(WOLFSSH* ssh, void* buf, word32 sz, void* ctx)
{
    DuplexEndpoint* endpoint = (DuplexEndpoint*)ctx;
    const byte* output = (const byte*)buf;
    word32 outputSz = sz;
    int ret;

    (void)ssh;

    if (endpoint == NULL || endpoint->peer == NULL || buf == NULL) {
        return WS_CBIO_ERR_GENERAL;
    }

    if (endpoint->isServer && endpoint->mutator != NULL &&
            endpoint->mutator->enabled &&
            endpoint->mutator->mutatedPackets == 0 &&
            outputSz >= UINT32_SZ + PAD_LENGTH_SZ + MSG_ID_SZ &&
            !(outputSz >= REGRESS_SSH_PROTO_PREFIX_SZ &&
              WMEMCMP(output, REGRESS_SSH_PROTO_PREFIX,
                      REGRESS_SSH_PROTO_PREFIX_SZ) == 0)) {
        word32 mutatedSz = 0;
        int mutateRet;

        mutateRet = RewriteKexDhReplySignatureName(output, outputSz, "ssh-rsa",
                endpoint->mutator->scratch,
                (word32)sizeof(endpoint->mutator->scratch), &mutatedSz);
        if (mutateRet < 0) {
            endpoint->mutator->parseError = mutateRet;
            return WS_CBIO_ERR_GENERAL;
        }
        if (mutateRet > 0) {
            endpoint->mutator->matchedPackets++;
            endpoint->mutator->mutatedPackets++;
            endpoint->mutator->scratchSz = mutatedSz;
            output = endpoint->mutator->scratch;
            outputSz = mutatedSz;
        }
    }

    ret = QueueAppend(&endpoint->peer->inbound, output, outputSz);
    if (ret != WS_SUCCESS) {
        return WS_CBIO_ERR_GENERAL;
    }

    return (int)sz;
}

static void InitDuplexPair(DuplexEndpoint* client, DuplexEndpoint* server,
        KexReplyMutator* mutator)
{
    WMEMSET(client, 0, sizeof(*client));
    WMEMSET(server, 0, sizeof(*server));

    client->peer = server;
    server->peer = client;
    server->mutator = mutator;
    server->isServer = 1;
}

static void FreeKexReplyHarness(KexReplyHarness* harness)
{
    if (harness->client != NULL) {
        wolfSSH_free(harness->client);
    }
    if (harness->server != NULL) {
        wolfSSH_free(harness->server);
    }
    if (harness->clientCtx != NULL) {
        wolfSSH_CTX_free(harness->clientCtx);
    }
    if (harness->serverCtx != NULL) {
        wolfSSH_CTX_free(harness->serverCtx);
    }
}

static void InitKexReplyHarness(KexReplyHarness* harness,
        const char* keyAlgo, byte mutateReply)
{
    byte keyBuf[2048];
    word32 keySz;

    WMEMSET(harness, 0, sizeof(*harness));

    InitDuplexPair(&harness->clientIo, &harness->serverIo, &harness->mutator);
    harness->mutator.enabled = mutateReply;

    harness->clientCtx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_CLIENT, NULL);
    AssertNotNull(harness->clientCtx);
    harness->serverCtx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_SERVER, NULL);
    AssertNotNull(harness->serverCtx);

    AssertIntEQ(wolfSSH_CTX_SetAlgoListKex(harness->clientCtx,
            KEXDH_REPLY_REGRESS_KEX_ALGO), WS_SUCCESS);
    AssertIntEQ(wolfSSH_CTX_SetAlgoListKex(harness->serverCtx,
            KEXDH_REPLY_REGRESS_KEX_ALGO), WS_SUCCESS);
    AssertIntEQ(wolfSSH_CTX_SetAlgoListKey(harness->clientCtx, keyAlgo),
            WS_SUCCESS);
    AssertIntEQ(wolfSSH_CTX_SetAlgoListKey(harness->serverCtx, keyAlgo),
            WS_SUCCESS);

    wolfSSH_SetIORecv(harness->clientCtx, DuplexRecv);
    wolfSSH_SetIOSend(harness->clientCtx, DuplexSend);
    wolfSSH_SetIORecv(harness->serverCtx, DuplexRecv);
    wolfSSH_SetIOSend(harness->serverCtx, DuplexSend);

    wolfSSH_SetUserAuth(harness->clientCtx, RegressionClientUserAuth);
    wolfSSH_SetUserAuth(harness->serverCtx, RegressionServerUserAuth);
    wolfSSH_CTX_SetPublicKeyCheck(harness->clientCtx, AcceptAnyServerHostKey);

    keySz = LoadFileBuffer(REGRESS_SERVER_KEY_PATH, keyBuf, sizeof(keyBuf));
    AssertTrue(keySz > 0);
    AssertIntEQ(wolfSSH_CTX_UsePrivateKey_buffer(harness->serverCtx, keyBuf,
            keySz, WOLFSSH_FORMAT_ASN1), WS_SUCCESS);

    harness->client = wolfSSH_new(harness->clientCtx);
    AssertNotNull(harness->client);
    harness->server = wolfSSH_new(harness->serverCtx);
    AssertNotNull(harness->server);

    wolfSSH_SetIOReadCtx(harness->client, &harness->clientIo);
    wolfSSH_SetIOWriteCtx(harness->client, &harness->clientIo);
    wolfSSH_SetIOReadCtx(harness->server, &harness->serverIo);
    wolfSSH_SetIOWriteCtx(harness->server, &harness->serverIo);

    AssertIntEQ(wolfSSH_SetUsername(harness->client, REGRESS_USERNAME),
            WS_SUCCESS);
}

static int IsHandshakeRetryable(int err)
{
    return err == WS_WANT_READ || err == WS_WANT_WRITE ||
            err == WS_AUTH_PENDING;
}

static void RunKexReplyHandshake(KexReplyHarness* harness,
        KexReplyRunResult* result)
{
    word32 step;

    WMEMSET(result, 0, sizeof(*result));
    result->clientRet = WS_FATAL_ERROR;
    result->serverRet = WS_FATAL_ERROR;

    for (step = 0; step < REGRESS_MAX_HANDSHAKE_STEPS; step++) {
        if (!result->clientSuccess) {
            result->clientRet = wolfSSH_connect(harness->client);
            result->clientErr = wolfSSH_get_error(harness->client);
            if (result->clientRet == WS_SUCCESS) {
                result->clientSuccess = 1;
            }
            else if (!IsHandshakeRetryable(result->clientErr)) {
                result->steps = step + 1;
                return;
            }
        }

        if (!result->serverSuccess) {
            result->serverRet = wolfSSH_accept(harness->server);
            result->serverErr = wolfSSH_get_error(harness->server);
            if (result->serverRet == WS_SUCCESS) {
                result->serverSuccess = 1;
            }
            else if (!IsHandshakeRetryable(result->serverErr)) {
                result->steps = step + 1;
                return;
            }
        }

        if (result->clientSuccess && result->serverSuccess) {
            result->steps = step + 1;
            return;
        }
    }

    result->steps = REGRESS_MAX_HANDSHAKE_STEPS;
}

static void AssertHandshakeSucceeds(const char* keyAlgo)
{
    KexReplyHarness harness;
    KexReplyRunResult result;

    InitKexReplyHarness(&harness, keyAlgo, 0);
    RunKexReplyHandshake(&harness, &result);

    AssertTrue(result.clientSuccess);
    AssertTrue(result.serverSuccess);
    AssertIntEQ(harness.mutator.mutatedPackets, 0);
    AssertIntEQ(harness.client->connectState, CONNECT_SERVER_CHANNEL_REQUEST_DONE);
    AssertIntEQ(harness.server->acceptState, ACCEPT_CLIENT_SESSION_ESTABLISHED);

    FreeKexReplyHarness(&harness);
}

static void AssertHandshakeRejectsMutatedReply(const char* keyAlgo)
{
    KexReplyHarness harness;
    KexReplyRunResult result;

    InitKexReplyHarness(&harness, keyAlgo, 1);
    RunKexReplyHandshake(&harness, &result);

    AssertIntEQ(harness.mutator.parseError, 0);
    AssertIntEQ(harness.mutator.matchedPackets, 1);
    AssertIntEQ(harness.mutator.mutatedPackets, 1);
    AssertFalse(result.clientSuccess);
    AssertFalse(harness.client->connectState >= CONNECT_KEYED);
    AssertTrue(result.clientRet == WS_FATAL_ERROR);
    AssertTrue(result.clientErr != WS_WANT_READ && result.clientErr != WS_WANT_WRITE);

    FreeKexReplyHarness(&harness);
}

#ifndef WOLFSSH_NO_RSA_SHA2_256
static void TestKexDhReplyRejectsRsaSha2_256SigNameDowngrade(void)
{
    AssertHandshakeSucceeds("rsa-sha2-256");
    AssertHandshakeRejectsMutatedReply("rsa-sha2-256");
}
#endif

#ifndef WOLFSSH_NO_RSA_SHA2_512
static void TestKexDhReplyRejectsRsaSha2_512SigNameDowngrade(void)
{
    AssertHandshakeSucceeds("rsa-sha2-512");
    AssertHandshakeRejectsMutatedReply("rsa-sha2-512");
}
#endif

#endif /* KEXDH_REPLY_REGRESS_KEX_ALGO */

static void AssertChannelOpenFailResponse(const ChannelOpenHarness* harness,
        int ret)
{
    byte msgId;

    AssertIntEQ(ret, WS_SUCCESS);
    AssertIntEQ(harness->io.inOff, harness->io.inSz);
    AssertTrue(harness->io.outSz > 0);
    AssertTrue(harness->io.outSz <= harness->io.outCap);

    msgId = ParseMsgId(harness->io.out, harness->io.outSz);
    AssertIntEQ(msgId, MSGID_CHANNEL_OPEN_FAIL);
    AssertFalse(msgId == MSGID_REQUEST_FAILURE);
}

static int RejectChannelOpenCb(WOLFSSH_CHANNEL* channel, void* ctx)
{
    (void)channel;
    (void)ctx;

    return WS_BAD_ARGUMENT;
}

#ifdef WOLFSSH_FWD
static int RejectDirectTcpipSetup(WS_FwdCbAction action, void* ctx,
        const char* host, word32 port)
{
    (void)ctx;
    (void)host;
    (void)port;

    if (action == WOLFSSH_FWD_LOCAL_SETUP)
        return WS_FWD_SETUP_E;

    return WS_SUCCESS;
}
#endif


/* Reject auth messages while the peer is still keying and the client
 * expects the KEX reply. */
static void TestAuthMessageBlockedDuringKeying(WOLFSSH* ssh)
{
    int allowed;

    ResetSession(ssh);
    ssh->isKeying = WOLFSSH_PEER_IS_KEYING;
    ssh->connectState = CONNECT_CLIENT_KEXDH_INIT_SENT;
    ssh->handshake = AllocHandshake(ssh);
    ssh->handshake->expectMsgId = MSGID_KEXDH_REPLY;

    allowed = wolfSSH_TestIsMessageAllowed(ssh, MSGID_USERAUTH_FAILURE,
            WS_MSG_RECV);
    AssertFalse(allowed);

    /* The expected message must be allowed and clear the expectation. */
    allowed = wolfSSH_TestIsMessageAllowed(ssh, MSGID_KEXDH_REPLY,
            WS_MSG_RECV);
    AssertTrue(allowed);
    AssertIntEQ(ssh->handshake->expectMsgId, MSGID_NONE);
}

/* Reject USERAUTH_FAILURE with password list during keying (password-leak PoC). */
static void TestUserauthFailureDuringKeying(WOLFSSH* ssh)
{
    byte buf[32];
    word32 sz;
    int allowed;

    ResetSession(ssh);
    ssh->isKeying = WOLFSSH_PEER_IS_KEYING;
    ssh->connectState = CONNECT_CLIENT_KEXDH_INIT_SENT;
    ssh->handshake = AllocHandshake(ssh);
    ssh->handshake->expectMsgId = MSGID_KEXDH_REPLY;

    sz = BuildPacket(MSGID_USERAUTH_FAILURE, buf, sizeof(buf));
    allowed = wolfSSH_TestIsMessageAllowed(ssh, ParseMsgId(buf, sz),
            WS_MSG_RECV);
    AssertFalse(allowed);
}


/* Expect an abort/error to be set when password-leak sequence hits during keying. */
static void TestPasswordLeakAborts(WOLFSSH* ssh)
{
    byte buf[32];
    word32 sz;
    int allowed;

    ResetSession(ssh);
    ssh->isKeying = WOLFSSH_PEER_IS_KEYING;
    ssh->connectState = CONNECT_CLIENT_KEXDH_INIT_SENT;
    ssh->handshake = AllocHandshake(ssh);
    ssh->handshake->expectMsgId = MSGID_KEXDH_REPLY;

    sz = BuildPacket(MSGID_USERAUTH_FAILURE, buf, sizeof(buf));
    allowed = wolfSSH_TestIsMessageAllowed(ssh, ParseMsgId(buf, sz),
            WS_MSG_RECV);
    AssertFalse(allowed);
    AssertTrue(ssh->error != 0); /* should set an error / abort path */
}


/* Reject USERAUTH_SUCCESS before the client has even sent a userauth request. */
static void TestPrematureUserauthSuccess(WOLFSSH* ssh)
{
    int allowed;

    ResetSession(ssh);
    ssh->connectState = CONNECT_KEYED;

    allowed = wolfSSH_TestIsMessageAllowed(ssh, MSGID_USERAUTH_SUCCESS,
            WS_MSG_RECV);
    AssertFalse(allowed);
}


/* Reject a spoofed sequence: bogus USERAUTH_SUCCESS followed by channel msgs. */
static void TestChannelSpoofSequence(WOLFSSH* ssh)
{
    byte buf[32];
    word32 sz;
    int allowed;

    ResetSession(ssh);
    ssh->connectState = CONNECT_KEYED;

    sz = BuildPacket(MSGID_USERAUTH_SUCCESS, buf, sizeof(buf));
    allowed = wolfSSH_TestIsMessageAllowed(ssh, ParseMsgId(buf, sz),
            WS_MSG_RECV);
    AssertFalse(allowed);

    sz = BuildPacket(MSGID_CHANNEL_OPEN_CONF, buf, sizeof(buf));
    allowed = wolfSSH_TestIsMessageAllowed(ssh, ParseMsgId(buf, sz),
            WS_MSG_RECV);
    AssertFalse(allowed);

    sz = BuildPacket(MSGID_CHANNEL_SUCCESS, buf, sizeof(buf));
    allowed = wolfSSH_TestIsMessageAllowed(ssh, ParseMsgId(buf, sz),
            WS_MSG_RECV);
    AssertFalse(allowed);

    sz = BuildPacket(MSGID_CHANNEL_DATA, buf, sizeof(buf));
    allowed = wolfSSH_TestIsMessageAllowed(ssh, ParseMsgId(buf, sz),
            WS_MSG_RECV);
    AssertFalse(allowed);
}

/* Expect abort/error on spoofed auth+channel sequence. */
static void TestChannelSpoofAborts(WOLFSSH* ssh)
{
    byte buf[32];
    word32 sz;
    int allowed;

    ResetSession(ssh);
    ssh->connectState = CONNECT_KEYED;

    sz = BuildPacket(MSGID_USERAUTH_SUCCESS, buf, sizeof(buf));
    allowed = wolfSSH_TestIsMessageAllowed(ssh, ParseMsgId(buf, sz),
            WS_MSG_RECV);
    AssertFalse(allowed);

    sz = BuildPacket(MSGID_CHANNEL_OPEN_CONF, buf, sizeof(buf));
    allowed = wolfSSH_TestIsMessageAllowed(ssh, ParseMsgId(buf, sz),
            WS_MSG_RECV);
    AssertFalse(allowed);

    AssertTrue(ssh->error != 0);
}


/* Reject USERAUTH_FAILURE(publickey) before any auth request (static-signature PoC). */
static void TestPublicKeyFailureBeforeRequest(WOLFSSH* ssh)
{
    byte buf[32];
    word32 sz;
    int allowed;

    ResetSession(ssh);
    ssh->connectState = CONNECT_KEYED;

    sz = BuildPacket(MSGID_USERAUTH_FAILURE, buf, sizeof(buf));
    allowed = wolfSSH_TestIsMessageAllowed(ssh, ParseMsgId(buf, sz),
            WS_MSG_RECV);
    AssertFalse(allowed);
}

/* Expect abort/error when publickey failure arrives before any request. */
static void TestPublicKeyFailureAborts(WOLFSSH* ssh)
{
    byte buf[32];
    word32 sz;
    int allowed;

    ResetSession(ssh);
    ssh->connectState = CONNECT_KEYED;

    sz = BuildPacket(MSGID_USERAUTH_FAILURE, buf, sizeof(buf));
    allowed = wolfSSH_TestIsMessageAllowed(ssh, ParseMsgId(buf, sz),
            WS_MSG_RECV);
    AssertFalse(allowed);
    AssertTrue(ssh->error != 0);
}


/* Reject channel messages before user authentication completes. */
static void TestChannelBlockedBeforeAuth(WOLFSSH* ssh)
{
    int allowed;

    ResetSession(ssh);
    ssh->connectState = CONNECT_KEYED;

    allowed = wolfSSH_TestIsMessageAllowed(ssh, MSGID_CHANNEL_OPEN,
            WS_MSG_RECV);
    AssertFalse(allowed);
}


/* Allow channel messages after user authentication completes. */
static void TestChannelAllowedAfterAuth(WOLFSSH* ssh)
{
    int allowed;

    ResetSession(ssh);
    ssh->connectState = CONNECT_SERVER_USERAUTH_ACCEPT_DONE;

    allowed = wolfSSH_TestIsMessageAllowed(ssh, MSGID_CHANNEL_OPEN,
            WS_MSG_RECV);
    AssertTrue(allowed);
}

static void TestChannelOpenCallbackRejectSendsOpenFail(void)
{
    ChannelOpenHarness harness;
    byte in[128];
    word32 inSz;
    int ret;

    inSz = BuildChannelOpenPacket("session", 7, 0x4000, 0x8000,
            NULL, 0, in, sizeof(in));

    InitChannelOpenHarness(&harness, in, inSz);
    AssertIntEQ(wolfSSH_CTX_SetChannelOpenCb(harness.ctx, RejectChannelOpenCb),
            WS_SUCCESS);

    ret = DoReceive(harness.ssh);
    AssertChannelOpenFailResponse(&harness, ret);

    FreeChannelOpenHarness(&harness);
}

#ifdef WOLFSSH_FWD
static void TestDirectTcpipRejectSendsOpenFail(void)
{
    ChannelOpenHarness harness;
    byte extra[128];
    byte in[192];
    word32 extraSz;
    word32 inSz;
    int ret;

    extraSz = BuildDirectTcpipExtra("127.0.0.1", 8080, "127.0.0.1", 2222,
            extra, sizeof(extra));
    inSz = BuildChannelOpenPacket("direct-tcpip", 9, 0x4000, 0x8000,
            extra, extraSz, in, sizeof(in));

    InitChannelOpenHarness(&harness, in, inSz);
    AssertIntEQ(wolfSSH_CTX_SetFwdCb(harness.ctx, RejectDirectTcpipSetup, NULL),
            WS_SUCCESS);

    ret = DoReceive(harness.ssh);
    AssertChannelOpenFailResponse(&harness, ret);

    FreeChannelOpenHarness(&harness);
}
#endif

#ifdef WOLFSSH_AGENT
static void TestAgentChannelNullAgentSendsOpenFail(void)
{
    ChannelOpenHarness harness;
    byte in[128];
    word32 inSz;
    int ret;

    inSz = BuildChannelOpenPacket("auth-agent@openssh.com", 11, 0x4000,
            0x8000, NULL, 0, in, sizeof(in));

    InitChannelOpenHarness(&harness, in, inSz);
    AssertTrue(harness.ssh->agent == NULL);

    ret = DoReceive(harness.ssh);
    AssertChannelOpenFailResponse(&harness, ret);

    FreeChannelOpenHarness(&harness);
}
#endif


/* Reject a peer KEXINIT once keying is in progress. */
static void TestKexInitRejectedWhenKeying(WOLFSSH* ssh)
{
    int allowed;

    ResetSession(ssh);
    ssh->isKeying = WOLFSSH_PEER_IS_KEYING;
    ssh->connectState = CONNECT_SERVER_KEXINIT_DONE;

    allowed = wolfSSH_TestIsMessageAllowed(ssh, MSGID_KEXINIT, WS_MSG_RECV);
    AssertFalse(allowed);
}

/* Ensure client buffer cleanup tolerates multiple invocations after allocs. */
static void TestClientBuffersIdempotent(void)
{
    int ret;

    ret = ClientUsePubKey("keys/gretel-key-rsa.pub");
    AssertIntEQ(ret, 0);
    ret = ClientSetPrivateKey("keys/gretel-key-rsa.pem");
    AssertIntEQ(ret, 0);

    ClientFreeBuffers();
    /* Should be safe to call again without double free. */
    ClientFreeBuffers();
}

/* Simulate Ctrl+D (stdin EOF) during password prompt; expect failure but no crash. */
static void TestPasswordEofNoCrash(void)
{
    WS_UserAuthData auth;
    int savedStdin, devNull, ret;

    if (!isatty(STDIN_FILENO)) {
        return; /* headless/CI: skip tty-dependent check */
    }

    WMEMSET(&auth, 0, sizeof(auth));

    savedStdin = dup(STDIN_FILENO);
    devNull = open("/dev/null", O_RDONLY);
    AssertTrue(devNull >= 0);
    AssertTrue(dup2(devNull, STDIN_FILENO) >= 0);

    ret = ClientUserAuth(WOLFSSH_USERAUTH_PASSWORD, &auth, NULL);
    printf("TestPasswordEofNoCrash ret=%d\n", ret);
    AssertIntEQ(ret, WOLFSSH_USERAUTH_FAILURE);

    close(devNull);
    dup2(savedStdin, STDIN_FILENO);
    close(savedStdin);

    ClientFreeBuffers();
}

/* When the send path is back-pressured (WANT_WRITE), wolfSSH_worker()
 * still needs to service Receive() so window-adjusts can arrive and
 * unblock the flow control. Verify the receive callback is invoked even
 * when the first send attempt would block. */
#ifndef WOLFSSH_TEST_BLOCK
static int recvCallCount;

static int WantWriteSend(WOLFSSH* ssh, void* buf, word32 sz, void* ctx)
{
    (void)ssh; (void)buf; (void)sz; (void)ctx;
    return WS_CBIO_ERR_WANT_WRITE;
}

static int WantReadRecv(WOLFSSH* ssh, void* buf, word32 sz, void* ctx)
{
    (void)ssh; (void)buf; (void)sz; (void)ctx;
    recvCallCount++;
    return WS_CBIO_ERR_WANT_READ;
}

#ifndef WOLFSSH_TEST_BLOCK
static void TestWorkerReadsWhenSendWouldBlock(void)
{
    WOLFSSH_CTX* ctx;
    WOLFSSH* ssh;
    int ret;

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_CLIENT, NULL);
    AssertNotNull(ctx);

    wolfSSH_SetIOSend(ctx, WantWriteSend);
    wolfSSH_SetIORecv(ctx, WantReadRecv);

    ssh = wolfSSH_new(ctx);
    AssertNotNull(ssh);

    /* prime with pending outbound data so wolfSSH_SendPacket() is hit */
    ssh->outputBuffer.length = 1;
    ssh->outputBuffer.idx = 0;
    ssh->outputBuffer.buffer[0] = 0;

    recvCallCount = 0;

    /* call worker; expect it to attempt send, notice back-pressure, and have
     * invoked recv once. Depending on how DoReceive handles WANT_READ, the
     * return may be WANT_WRITE or a fatal error; the important part is that
     * recv was exercised. */
    ret = wolfSSH_worker(ssh, NULL);

    AssertTrue(ret == WS_WANT_WRITE || ret == WS_FATAL_ERROR);
    AssertIntEQ(recvCallCount, 1);

    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);
}
#endif /* !WOLFSSH_TEST_BLOCK */
#endif


#ifdef WOLFSSH_SFTP
/* Test that wolfSSH_SFTP_buffer_send() properly handles WS_WANT_WRITE when
 * SSH output buffer has pending data. This is a regression test for
 * the SFTP hang issue with non-blocking sockets.
 *
 * The fix checks for pending data in ssh->outputBuffer at the start of
 * wolfSSH_SFTP_buffer_send() and returns WS_WANT_WRITE if the flush fails. */
static int sftpWantWriteCallCount = 0;

static int SftpWantWriteSendCb(WOLFSSH* ssh, void* buf, word32 sz, void* ctx)
{
    (void)ssh; (void)buf; (void)ctx;
    sftpWantWriteCallCount++;
    /* First call returns WANT_WRITE, subsequent calls succeed */
    if (sftpWantWriteCallCount == 1) {
        return WS_CBIO_ERR_WANT_WRITE;
    }
    return (int)sz;
}

static int SftpDummyRecv(WOLFSSH* ssh, void* buf, word32 sz, void* ctx)
{
    (void)ssh; (void)buf; (void)sz; (void)ctx;
    return WS_CBIO_ERR_WANT_READ;
}

static void TestSftpBufferSendPendingOutput(void)
{
    WOLFSSH_CTX* ctx;
    WOLFSSH* ssh;
    byte testData[16];
    int ret;

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_SERVER, NULL);
    AssertNotNull(ctx);

    wolfSSH_SetIOSend(ctx, SftpWantWriteSendCb);
    wolfSSH_SetIORecv(ctx, SftpDummyRecv);

    ssh = wolfSSH_new(ctx);
    AssertNotNull(ssh);

    WMEMSET(testData, 0x42, sizeof(testData));

    /* Simulate pending data in SSH output buffer (as if previous send
     * returned WS_WANT_WRITE and data was buffered).
     * Note: outputBuffer is initialized by BufferInit() with bufferSz set
     * to at least STATIC_BUFFER_LEN (16 bytes), so we use a smaller value. */
    ssh->outputBuffer.length = 8;   /* 8 bytes pending */
    ssh->outputBuffer.idx = 0;      /* none sent yet */

    sftpWantWriteCallCount = 0;

    /* Call wolfSSH_TestSftpBufferSend - should return WS_WANT_WRITE because
     * the fix detects pending data in outputBuffer and tries to flush it,
     * which fails with WS_WANT_WRITE from our callback.
     *
     * Before the fix, the function would ignore the pending SSH output buffer
     * data and proceed to send new SFTP data, leading to a hang because the
     * pending data was never flushed. */
    ret = wolfSSH_TestSftpBufferSend(ssh, testData, sizeof(testData), 0);
    AssertIntEQ(ret, WS_WANT_WRITE);

    /* Verify the SSH output buffer still has pending data */
    AssertTrue(ssh->outputBuffer.length > ssh->outputBuffer.idx);

    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);
}
#endif /* WOLFSSH_SFTP */


int main(int argc, char** argv)
{
    WOLFSSH_CTX* ctx;
    WOLFSSH* ssh;

    (void)argc;
    (void)argv;

    wolfSSH_Init();

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_CLIENT, NULL);
    AssertNotNull(ctx);

    ssh = wolfSSH_new(ctx);
    AssertNotNull(ssh);

    TestAuthMessageBlockedDuringKeying(ssh);
    TestUserauthFailureDuringKeying(ssh);
    TestPasswordLeakAborts(ssh);
    TestPrematureUserauthSuccess(ssh);
    TestChannelSpoofSequence(ssh);
    TestChannelSpoofAborts(ssh);
    TestPublicKeyFailureBeforeRequest(ssh);
    TestPublicKeyFailureAborts(ssh);
    TestChannelBlockedBeforeAuth(ssh);
    TestChannelAllowedAfterAuth(ssh);
    TestChannelOpenCallbackRejectSendsOpenFail();
#ifdef WOLFSSH_FWD
    TestDirectTcpipRejectSendsOpenFail();
#endif
#ifdef WOLFSSH_AGENT
    TestAgentChannelNullAgentSendsOpenFail();
#endif
    TestKexInitRejectedWhenKeying(ssh);
    TestClientBuffersIdempotent();
    TestPasswordEofNoCrash();
#ifndef WOLFSSH_TEST_BLOCK
    TestWorkerReadsWhenSendWouldBlock();
#endif

#ifdef KEXDH_REPLY_REGRESS_KEX_ALGO
    #ifndef WOLFSSH_NO_RSA_SHA2_256
    TestKexDhReplyRejectsRsaSha2_256SigNameDowngrade();
    #endif
    #ifndef WOLFSSH_NO_RSA_SHA2_512
    TestKexDhReplyRejectsRsaSha2_512SigNameDowngrade();
    #endif
#endif

#ifdef WOLFSSH_SFTP
    TestSftpBufferSendPendingOutput();
#endif

    /* TODO: add app-level regressions that simulate stdin EOF/password
     * prompts and mid-session socket closes once the test harness can
     * drive the wolfssh client without real sockets/tty. */

    ResetSession(ssh);
    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);
    wolfSSH_Cleanup();

    printf("regress: PASS\n");
    return 0;
}

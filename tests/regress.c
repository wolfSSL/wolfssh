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

static word32 BuildDisconnectPacket(word32 reason, byte* out, word32 outSz)
{
    byte payload[64];
    word32 idx = 0;

    idx = AppendUint32(payload, sizeof(payload), idx, reason);
    idx = AppendUint32(payload, sizeof(payload), idx, 0);
    idx = AppendUint32(payload, sizeof(payload), idx, 0);

    return WrapPacket(MSGID_DISCONNECT, payload, idx, out, outSz);
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

static word32 BuildGlobalRequestFwdPacket(const char* bindAddr, word32 bindPort,
        int isCancel, byte wantReply, byte* out, word32 outSz)
{
    byte payload[256];
    word32 idx = 0;
    const char* reqName = isCancel ? "cancel-tcpip-forward" : "tcpip-forward";

    idx = AppendString(payload, sizeof(payload), idx, reqName);
    idx = AppendByte  (payload, sizeof(payload), idx, wantReply);
    idx = AppendString(payload, sizeof(payload), idx, bindAddr);
    idx = AppendUint32(payload, sizeof(payload), idx, bindPort);

    return WrapPacket(MSGID_GLOBAL_REQUEST, payload, idx, out, outSz);
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

static int RejectAnyServerHostKey(const byte* pubKey, word32 pubKeySz,
        void* ctx)
{
    (void)pubKey;
    (void)pubKeySz;
    (void)ctx;

    return 1;
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

static void InitKexReplyHarnessEx(KexReplyHarness* harness,
        const char* keyAlgo, byte mutateReply, byte skipPublicKeyCheck)
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
    if (!skipPublicKeyCheck) {
        wolfSSH_CTX_SetPublicKeyCheck(harness->clientCtx, AcceptAnyServerHostKey);
    }

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

static void InitKexReplyHarness(KexReplyHarness* harness,
        const char* keyAlgo, byte mutateReply)
{
    InitKexReplyHarnessEx(harness, keyAlgo, mutateReply, 0);
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

static void AssertHandshakeRejectsWithNoPublicKeyCheck(const char* keyAlgo)
{
    KexReplyHarness harness;
    KexReplyRunResult result;

    InitKexReplyHarnessEx(&harness, keyAlgo, 0, 1 /* skipPublicKeyCheck */);
    RunKexReplyHandshake(&harness, &result);

    AssertFalse(result.clientSuccess);
    AssertTrue(result.clientRet == WS_FATAL_ERROR);
    AssertTrue(result.clientErr != WS_WANT_READ && result.clientErr != WS_WANT_WRITE);
    AssertIntEQ(result.clientErr, WS_PUBKEY_REJECTED_E);
    AssertFalse(harness.client->connectState >= CONNECT_KEYED);

    FreeKexReplyHarness(&harness);
}

static void TestKexDhReplyRejectsNoPublicKeyCheck(void)
{
#ifndef WOLFSSH_NO_RSA_SHA2_256
    AssertHandshakeRejectsWithNoPublicKeyCheck("rsa-sha2-256");
#endif
#ifndef WOLFSSH_NO_RSA_SHA2_512
    AssertHandshakeRejectsWithNoPublicKeyCheck("rsa-sha2-512");
#endif
}

static void AssertHandshakeRejectsWhenCallbackRejects(const char* keyAlgo)
{
    KexReplyHarness harness;
    KexReplyRunResult result;

    InitKexReplyHarness(&harness, keyAlgo, 0);
    wolfSSH_CTX_SetPublicKeyCheck(harness.clientCtx, RejectAnyServerHostKey);
    RunKexReplyHandshake(&harness, &result);

    AssertFalse(result.clientSuccess);
    AssertTrue(result.clientRet == WS_FATAL_ERROR);
    AssertTrue(result.clientErr != WS_WANT_READ && result.clientErr != WS_WANT_WRITE);
    AssertIntEQ(result.clientErr, WS_PUBKEY_REJECTED_E);
    AssertFalse(harness.client->connectState >= CONNECT_KEYED);

    FreeKexReplyHarness(&harness);
}

static void TestKexDhReplyRejectsWhenCallbackRejects(void)
{
#ifndef WOLFSSH_NO_RSA_SHA2_256
    AssertHandshakeRejectsWhenCallbackRejects("rsa-sha2-256");
#endif
#ifndef WOLFSSH_NO_RSA_SHA2_512
    AssertHandshakeRejectsWhenCallbackRejects("rsa-sha2-512");
#endif
}

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
    AssertIntEQ(harness->ssh->channelListSz, 0);
    AssertTrue(harness->ssh->channelList == NULL);
}

#ifdef WOLFSSH_FWD
static word32 ParsePayloadLen(const byte* packet, word32 packetSz)
{
    word32 packetLen;
    byte padLen;

    AssertNotNull(packet);
    AssertTrue(packetSz >= 6);

    WMEMCPY(&packetLen, packet, sizeof(packetLen));
    packetLen = ntohl(packetLen);
    padLen = packet[4];

    AssertTrue(packetLen >= (word32)padLen + 1);
    AssertTrue(packetSz >= packetLen + 4);

    return packetLen - padLen - 1;
}

static const byte* ParseGlobalRequestName(const byte* packet, word32 packetSz,
        word32* nameSz)
{
    word32 packetLen;
    word32 payloadLen;
    word32 strSz;
    const byte* payload;

    AssertNotNull(packet);
    AssertNotNull(nameSz);
    AssertTrue(packetSz >= 10);

    WMEMCPY(&packetLen, packet, sizeof(packetLen));
    packetLen = ntohl(packetLen);
    AssertTrue(packetSz >= packetLen + 4);

    payloadLen = ParsePayloadLen(packet, packetSz);
    payload = packet + 5;

    AssertTrue(payloadLen >= 1 + sizeof(word32));
    AssertIntEQ(payload[0], MSGID_GLOBAL_REQUEST);

    WMEMCPY(&strSz, payload + 1, sizeof(strSz));
    strSz = ntohl(strSz);
    AssertTrue(payloadLen >= 1 + sizeof(word32) + strSz);

    *nameSz = strSz;
    return payload + 1 + sizeof(word32);
}

static void AssertGlobalRequestReply(const ChannelOpenHarness* harness,
        byte expectedMsgId)
{
    byte msgId;
    word32 payloadLen;

    AssertTrue(harness->io.outSz > 0);
    msgId = ParseMsgId(harness->io.out, harness->io.outSz);
    AssertIntEQ(msgId, expectedMsgId);

    payloadLen = ParsePayloadLen(harness->io.out, harness->io.outSz);
    if (expectedMsgId == MSGID_REQUEST_FAILURE) {
        AssertIntEQ(payloadLen, 1);
    }
    else if (expectedMsgId == MSGID_REQUEST_SUCCESS) {
        const byte* reqName;
        word32 reqNameSz;

        reqName = ParseGlobalRequestName(harness->io.in, harness->io.inSz,
                &reqNameSz);

        if (reqNameSz == sizeof("tcpip-forward") - 1 &&
                WMEMCMP(reqName, "tcpip-forward",
                sizeof("tcpip-forward") - 1) == 0) {
            AssertIntEQ(payloadLen, 5);
        }
        else if (reqNameSz == sizeof("cancel-tcpip-forward") - 1 &&
                WMEMCMP(reqName, "cancel-tcpip-forward",
                sizeof("cancel-tcpip-forward") - 1) == 0) {
            AssertIntEQ(payloadLen, 1);
        }
        else {
            Fail(("unexpected global request name"),
                    ("%.*s", (int)reqNameSz, reqName));
        }
    }
}
#endif

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

static int AcceptFwdCb(WS_FwdCbAction action, void* ctx,
        const char* host, word32 port)
{
    (void)action;
    (void)ctx;
    (void)host;
    (void)port;

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

static void TestDirectTcpipNoFwdCbSendsOpenFail(void)
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
    /* Intentionally do NOT register fwdCb */

    ret = DoReceive(harness.ssh);
    AssertChannelOpenFailResponse(&harness, ret);

    FreeChannelOpenHarness(&harness);
}

static void TestGlobalRequestFwdNoCbSendsFailure(void)
{
    ChannelOpenHarness harness;
    byte in[256];
    word32 inSz;
    int ret;

    inSz = BuildGlobalRequestFwdPacket("0.0.0.0", 2222, 0, 1, in, sizeof(in));
    InitChannelOpenHarness(&harness, in, inSz);
    /* no fwdCb registered */

    ret = DoReceive(harness.ssh);

    AssertIntEQ(ret, WS_SUCCESS);
    AssertGlobalRequestReply(&harness, MSGID_REQUEST_FAILURE);

    FreeChannelOpenHarness(&harness);
}

static void TestGlobalRequestFwdNoCbNoReplyKeepsConnection(void)
{
    ChannelOpenHarness harness;
    byte in[256];
    word32 inSz;
    int ret;

    /* wantReply=0: no reply sent, connection must stay alive */
    inSz = BuildGlobalRequestFwdPacket("0.0.0.0", 2222, 0, 0, in, sizeof(in));
    InitChannelOpenHarness(&harness, in, inSz);
    /* no fwdCb registered */

    ret = DoReceive(harness.ssh);

    AssertIntEQ(ret, WS_SUCCESS);
    AssertIntEQ(harness.io.outSz, 0); /* no reply sent */

    FreeChannelOpenHarness(&harness);
}

static void TestGlobalRequestFwdWithCbSendsSuccess(void)
{
    ChannelOpenHarness harness;
    byte in[256];
    word32 inSz;
    int ret;

    inSz = BuildGlobalRequestFwdPacket("0.0.0.0", 2222, 0, 1, in, sizeof(in));
    InitChannelOpenHarness(&harness, in, inSz);
    AssertIntEQ(wolfSSH_CTX_SetFwdCb(harness.ctx, AcceptFwdCb, NULL), WS_SUCCESS);

    ret = DoReceive(harness.ssh);

    AssertIntEQ(ret, WS_SUCCESS);
    AssertGlobalRequestReply(&harness, MSGID_REQUEST_SUCCESS);

    FreeChannelOpenHarness(&harness);
}

static void TestGlobalRequestFwdCancelNoCbSendsFailure(void)
{
    ChannelOpenHarness harness;
    byte in[256];
    word32 inSz;
    int ret;

    inSz = BuildGlobalRequestFwdPacket("0.0.0.0", 2222, 1, 1, in, sizeof(in));
    InitChannelOpenHarness(&harness, in, inSz);

    ret = DoReceive(harness.ssh);

    AssertIntEQ(ret, WS_SUCCESS);
    AssertGlobalRequestReply(&harness, MSGID_REQUEST_FAILURE);

    FreeChannelOpenHarness(&harness);
}

static void TestGlobalRequestFwdCancelWithCbSendsSuccess(void)
{
    ChannelOpenHarness harness;
    byte in[256];
    word32 inSz;
    int ret;

    inSz = BuildGlobalRequestFwdPacket("0.0.0.0", 2222, 1, 1, in, sizeof(in));
    InitChannelOpenHarness(&harness, in, inSz);
    AssertIntEQ(wolfSSH_CTX_SetFwdCb(harness.ctx, AcceptFwdCb, NULL), WS_SUCCESS);

    ret = DoReceive(harness.ssh);

    AssertIntEQ(ret, WS_SUCCESS);
    AssertGlobalRequestReply(&harness, MSGID_REQUEST_SUCCESS);

    FreeChannelOpenHarness(&harness);
}

/* Verify DoRequestSuccess correctly consumes a uint32 port payload (RFC 4254
 * §4) without treating it as a length prefix, which would overrun the buffer
 * and produce WS_BUFFER_E. */
static void TestRequestSuccessWithPortParsesCorrectly(void)
{
    ChannelOpenHarness harness;
    byte payload[UINT32_SZ];
    byte in[64];
    word32 inSz;
    word32 idx = 0;
    int ret;

    idx = AppendUint32(payload, sizeof(payload), idx, 2222);
    inSz = WrapPacket(MSGID_REQUEST_SUCCESS, payload, idx, in, sizeof(in));

    InitChannelOpenHarness(&harness, in, inSz);

    ret = DoReceive(harness.ssh);

    AssertIntEQ(ret, WS_SUCCESS);

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

static void TestDisconnectSetsDisconnectError(void)
{
    WOLFSSH_CTX* ctx;
    WOLFSSH* ssh;
    MemIo io;
    byte in[128];
    byte out[32];
    word32 inSz;
    int ret;

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_CLIENT, NULL);
    AssertNotNull(ctx);

    wolfSSH_SetIORecv(ctx, MemRecv);
    wolfSSH_SetIOSend(ctx, MemSend);

    ssh = wolfSSH_new(ctx);
    AssertNotNull(ssh);

    inSz = BuildDisconnectPacket(WOLFSSH_DISCONNECT_BY_APPLICATION,
            in, sizeof(in));
    MemIoInit(&io, in, inSz, out, sizeof(out));
    wolfSSH_SetIOReadCtx(ssh, &io);
    wolfSSH_SetIOWriteCtx(ssh, &io);

    ret = DoReceive(ssh);
    AssertIntEQ(ret, WS_FATAL_ERROR);
    AssertIntEQ(wolfSSH_get_error(ssh), WS_DISCONNECT);
    AssertIntEQ(io.inOff, io.inSz);

    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);
}

#ifdef WOLFSSH_SFTP
static void TestOct2DecRejectsInvalidNonLeadingDigit(void)
{
    WOLFSSH_CTX* ctx;
    WOLFSSH* ssh;
    byte invalidOct[] = "0718";
    int ret;

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_CLIENT, NULL);
    AssertNotNull(ctx);

    ssh = wolfSSH_new(ctx);
    AssertNotNull(ssh);

    ret = wolfSSH_oct2dec(ssh, invalidOct, (word32)WSTRLEN((char*)invalidOct));
    AssertIntEQ(ret, WS_BAD_ARGUMENT);

    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);
}

#ifdef WOLFSSH_STOREHANDLE
static void TestSftpRemoveHandleHeadUpdate(void)
{
    WOLFSSH_CTX* ctx;
    WOLFSSH* ssh;
    byte firstHandle[] = { 0x01, 0x02, 0x03, 0x04 };
    byte secondHandle[] = { 0x10, 0x20, 0x30, 0x40 };
    int ret;

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_CLIENT, NULL);
    AssertNotNull(ctx);

    ssh = wolfSSH_new(ctx);
    AssertNotNull(ssh);

    ret = SFTP_AddHandleNode(ssh, firstHandle, sizeof(firstHandle), "first");
    AssertIntEQ(ret, WS_SUCCESS);

    ret = SFTP_AddHandleNode(ssh, secondHandle, sizeof(secondHandle), "second");
    AssertIntEQ(ret, WS_SUCCESS);

    ret = SFTP_RemoveHandleNode(ssh, secondHandle, sizeof(secondHandle));
    AssertIntEQ(ret, WS_SUCCESS);

    AssertNotNull(ssh->handleList);
    AssertTrue(ssh->handleList->prev == NULL);
    AssertIntEQ(ssh->handleList->handleSz, (int)sizeof(firstHandle));
    AssertIntEQ(WMEMCMP(ssh->handleList->handle, firstHandle,
            sizeof(firstHandle)), 0);

    ret = SFTP_RemoveHandleNode(ssh, firstHandle, sizeof(firstHandle));
    AssertIntEQ(ret, WS_SUCCESS);

    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);
}
#endif
#endif

#if !(defined(WOLFSSH_NO_RSA) && defined(WOLFSSH_NO_ECDSA_SHA2_NISTP256))
/* Ensure client buffer cleanup tolerates multiple invocations after allocs. */
static void TestClientBuffersIdempotent(void)
{
#ifndef WOLFSSH_NO_RSA
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
#endif

#ifndef WOLFSSH_NO_ECDSA_SHA2_NISTP256
    {
        int ret;

        ret = ClientUsePubKey("keys/gretel-key-ecc.pub");
        AssertIntEQ(ret, 0);
        ret = ClientSetPrivateKey("keys/gretel-key-ecc.pem");
        AssertIntEQ(ret, 0);

        ClientFreeBuffers();
        /* Should be safe to call again without double free. */
        ClientFreeBuffers();
    }
#endif
}
#endif

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
    AssertTrue(savedStdin >= 0);
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
#if defined(WOLFSSL_NUCLEUS) && !defined(NO_WOLFSSH_MKTIME)
static void TestNucleusMonthConversion(void)
{
    AssertIntEQ(wolfSSH_TestNucleusMonthFromDate((word16)(1U << 5)), 0);
    AssertIntEQ(wolfSSH_TestNucleusMonthFromDate((word16)(12U << 5)), 11);
}
#endif
#endif /* WOLFSSH_SFTP */


#ifdef WOLFSSH_KEYBOARD_INTERACTIVE
static int KbPreparePacketFailUserAuth(byte authType, WS_UserAuthData* authData,
        void* ctx)
{
    static byte* responses[1];
    static word32 responseLens[1];
    static byte response[] = "regress";

    (void)ctx;

    if (authType != WOLFSSH_USERAUTH_KEYBOARD || authData == NULL) {
        return WOLFSSH_USERAUTH_INVALID_AUTHTYPE;
    }

    if (authData->sf.keyboard.promptCount != 1 ||
            authData->sf.keyboard.prompts == NULL) {
        return WOLFSSH_USERAUTH_INVALID_PASSWORD;
    }

    responses[0] = response;
    responseLens[0] = (word32)sizeof(response) - 1;
    authData->sf.keyboard.responseCount = 1;
    authData->sf.keyboard.responseLengths = responseLens;
    authData->sf.keyboard.responses = responses;

    return WOLFSSH_USERAUTH_SUCCESS;
}

static void TestKeyboardResponsePreparePacketFailure(WOLFSSH* ssh,
        WOLFSSH_CTX* ctx)
{
    byte* prompt;
    byte** prompts;
    byte* promptEcho;
    int ret;

    AssertNotNull(ssh);
    AssertNotNull(ctx);

    ResetSession(ssh);
    wolfSSH_SetUserAuth(ctx, KbPreparePacketFailUserAuth);

    prompt = (byte*)WMALLOC(9, ctx->heap, DYNTYPE_STRING); /* "Password" */
    prompts = (byte**)WMALLOC(sizeof(byte*), ctx->heap, DYNTYPE_STRING);
    promptEcho = (byte*)WMALLOC(1, ctx->heap, DYNTYPE_STRING);
    AssertNotNull(prompt);
    AssertNotNull(prompts);
    AssertNotNull(promptEcho);

    WMEMCPY(prompt, "Password", 8);
    prompt[8] = '\0';
    prompts[0] = prompt;
    promptEcho[0] = 0;

    ssh->kbAuth.promptCount = 1;
    ssh->kbAuth.prompts = prompts;
    ssh->kbAuth.promptEcho = promptEcho;
    ssh->kbAuth.promptName = NULL;
    ssh->kbAuth.promptInstruction = NULL;
    ssh->kbAuth.promptLanguage = NULL;

    /* Force PreparePacket() to fail with WS_OVERFLOW_E. */
    ssh->outputBuffer.length = 0;
    ssh->outputBuffer.idx = 1;

    ret = SendUserAuthKeyboardResponse(ssh);
    AssertIntEQ(ret, WS_OVERFLOW_E);

    /* Ensure packet purge/reset happened cleanly. */
    AssertIntEQ(ssh->outputBuffer.idx, 0);
    AssertIntEQ(ssh->outputBuffer.length, 0);

    /* Verify SendUserAuthKeyboardResponse() cleaned up kbAuth state. */
    AssertIntEQ(ssh->kbAuth.promptCount, 0);
    AssertTrue(ssh->kbAuth.prompts == NULL);
    AssertTrue(ssh->kbAuth.promptEcho == NULL);
}

static void TestKeyboardResponseNoUserAuthCallback(WOLFSSH* ssh,
        WOLFSSH_CTX* ctx)
{
    int ret;

    AssertNotNull(ssh);
    AssertNotNull(ctx);

    ResetSession(ssh);
    wolfSSH_SetUserAuth(ctx, NULL);

    ret = SendUserAuthKeyboardResponse(ssh);
    AssertIntEQ(ret, WS_INVALID_STATE_E);

    /* No packet should have been started. */
    AssertIntEQ(ssh->outputBuffer.length, 0);
    AssertIntEQ(ssh->outputBuffer.idx, 0);
}

static void TestKeyboardResponseNullSsh(void)
{
    int ret;

    ret = SendUserAuthKeyboardResponse(NULL);
    AssertIntEQ(ret, WS_BAD_ARGUMENT);
}

static void TestKeyboardResponseNullCtx(WOLFSSH* ssh)
{
    WOLFSSH_CTX* savedCtx;
    int ret;

    AssertNotNull(ssh);

    savedCtx = ssh->ctx;
    ssh->ctx = NULL;

    ret = SendUserAuthKeyboardResponse(ssh);
    AssertIntEQ(ret, WS_BAD_ARGUMENT);

    ssh->ctx = savedCtx;
}
#endif /* WOLFSSH_KEYBOARD_INTERACTIVE */


#if !defined(WOLFSSH_NO_ECDH_SHA2_NISTP256) \
    && !defined(WOLFSSH_NO_RSA) \
    && !defined(WOLFSSH_NO_CURVE25519_SHA256) \
    && !defined(WOLFSSH_NO_RSA_SHA2_256)

#define FPF_KEX_GOOD "ecdh-sha2-nistp256"
#define FPF_KEX_BAD  "curve25519-sha256"
#define FPF_KEY_GOOD "ssh-rsa"
#define FPF_KEY_BAD  "rsa-sha2-256"

/* Build a KEXINIT payload using the server ssh's own canned cipher/MAC lists
 * so negotiation succeeds whichever AES/HMAC modes are compiled in. */
static word32 BuildKexInitPayload(WOLFSSH* ssh, const char* kexList,
        const char* keyList, byte firstPacketFollows,
        byte* out, word32 outSz)
{
    word32 idx = 0;

    /* cookie */
    AssertTrue(idx + COOKIE_SZ <= outSz);
    WMEMSET(out + idx, 0, COOKIE_SZ);
    idx += COOKIE_SZ;

    idx = AppendString(out, outSz, idx, kexList);
    idx = AppendString(out, outSz, idx, keyList);
    idx = AppendString(out, outSz, idx, ssh->algoListCipher);
    idx = AppendString(out, outSz, idx, ssh->algoListCipher);
    idx = AppendString(out, outSz, idx, ssh->algoListMac);
    idx = AppendString(out, outSz, idx, ssh->algoListMac);
    idx = AppendString(out, outSz, idx, "none");
    idx = AppendString(out, outSz, idx, "none");
    idx = AppendString(out, outSz, idx, "");
    idx = AppendString(out, outSz, idx, "");

    idx = AppendByte(out, outSz, idx, firstPacketFollows);
    idx = AppendUint32(out, outSz, idx, 0); /* reserved */

    return idx;
}

#if !defined(WOLFSSH_NO_AES_CBC) && !defined(WOLFSSH_NO_AES_CTR) \
    && !defined(WOLFSSH_NO_HMAC_SHA1) && !defined(WOLFSSH_NO_HMAC_SHA2_256)
/* Like BuildKexInitPayload but with explicit per-direction cipher/MAC lists. */
static word32 BuildKexInitPayloadFull(const char* kexList,
        const char* keyList, const char* encC2S, const char* encS2C,
        const char* macC2S, const char* macS2C,
        byte firstPacketFollows, byte* out, word32 outSz)
{
    word32 idx = 0;

    AssertTrue(idx + COOKIE_SZ <= outSz);
    WMEMSET(out + idx, 0, COOKIE_SZ);
    idx += COOKIE_SZ;
    idx = AppendString(out, outSz, idx, kexList);
    idx = AppendString(out, outSz, idx, keyList);
    idx = AppendString(out, outSz, idx, encC2S);
    idx = AppendString(out, outSz, idx, encS2C);
    idx = AppendString(out, outSz, idx, macC2S);
    idx = AppendString(out, outSz, idx, macS2C);
    idx = AppendString(out, outSz, idx, "none");
    idx = AppendString(out, outSz, idx, "none");
    idx = AppendString(out, outSz, idx, "");
    idx = AppendString(out, outSz, idx, "");
    idx = AppendByte(out, outSz, idx, firstPacketFollows);
    idx = AppendUint32(out, outSz, idx, 0); /* reserved */

    return idx;
}
#endif /* AES_CBC + AES_CTR + HMAC guards (BuildKexInitPayloadFull) */

typedef struct {
    const char* description;
    const char* kexList;
    const char* keyList;
    byte firstPacketFollows;
    byte expectIgnore;
} FirstPacketFollowsCase;

static const FirstPacketFollowsCase firstPacketFollowsCases[] = {
    { "follows=0, guesses irrelevant: flag stays off",
      FPF_KEX_BAD "," FPF_KEX_GOOD, FPF_KEY_BAD "," FPF_KEY_GOOD, 0, 0 },
    { "follows=1, both guesses match: do not skip",
      FPF_KEX_GOOD, FPF_KEY_GOOD, 1, 0 },
    { "follows=1, KEX guess wrong: skip",
      FPF_KEX_BAD "," FPF_KEX_GOOD, FPF_KEY_GOOD, 1, 1 },
    { "follows=1, host-key guess wrong: skip", /* regression case */
      FPF_KEX_GOOD, FPF_KEY_BAD "," FPF_KEY_GOOD, 1, 1 },
    { "follows=1, both guesses wrong: skip",
      FPF_KEX_BAD "," FPF_KEX_GOOD, FPF_KEY_BAD "," FPF_KEY_GOOD, 1, 1 },
};

static void RunFirstPacketFollowsCase(const FirstPacketFollowsCase* tc)
{
    WOLFSSH_CTX* ctx;
    WOLFSSH* ssh;
    byte payload[512];
    word32 payloadSz;
    word32 idx = 0;

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_SERVER, NULL);
    AssertNotNull(ctx);

    ssh = wolfSSH_new(ctx);
    AssertNotNull(ssh);

    AssertIntEQ(wolfSSH_SetAlgoListKex(ssh, FPF_KEX_GOOD), WS_SUCCESS);
    AssertIntEQ(wolfSSH_SetAlgoListKey(ssh, FPF_KEY_GOOD), WS_SUCCESS);

    payloadSz = BuildKexInitPayload(ssh, tc->kexList, tc->keyList,
            tc->firstPacketFollows, payload, sizeof(payload));

    /* DoKexInit's tail hashes and sends a response; on a stripped-down
     * WOLFSSH without a loaded host key or a primed peer proto id, that
     * tail errors. We only care about the parse path up through
     * first_packet_follows, where ignoreNextKexMsg is set. */
    (void)wolfSSH_TestDoKexInit(ssh, payload, payloadSz, &idx);

    AssertNotNull(ssh->handshake);
    if (ssh->handshake->ignoreNextKexMsg != tc->expectIgnore) {
        Fail(("ignoreNextKexMsg == %u (%s)",
                    tc->expectIgnore, tc->description),
             ("%u", ssh->handshake->ignoreNextKexMsg));
    }

    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);
}

typedef int (*FirstPacketFollowsSkipFn)(WOLFSSH* ssh, byte* buf, word32 len,
        word32* idx);

/* With ignoreNextKexMsg set, the target Do* handler must consume the packet,
 * clear the flag, and not advance clientState past CLIENT_KEXINIT_DONE. */
static void RunFirstPacketFollowsSkipCase(FirstPacketFollowsSkipFn fn,
        const char* label)
{
    WOLFSSH_CTX* ctx;
    WOLFSSH* ssh;
    byte payload[8];
    word32 idx = 0;
    int ret;

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_SERVER, NULL);
    AssertNotNull(ctx);

    ssh = wolfSSH_new(ctx);
    AssertNotNull(ssh);
    AssertNotNull(ssh->handshake);

    ssh->handshake->ignoreNextKexMsg = 1;
    ssh->clientState = CLIENT_KEXINIT_DONE;

    /* Garbage payload — must never be parsed when skipped. */
    WMEMSET(payload, 0xAB, sizeof(payload));

    ret = fn(ssh, payload, sizeof(payload), &idx);
    if (ret != WS_SUCCESS) {
        Fail(("%s returns WS_SUCCESS when skipping", label), ("%d", ret));
    }
    AssertIntEQ(idx, sizeof(payload));
    AssertIntEQ(ssh->handshake->ignoreNextKexMsg, 0);
    AssertIntEQ(ssh->clientState, CLIENT_KEXINIT_DONE);

    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);
}

static void TestFirstPacketFollowsSkipped(void)
{
    RunFirstPacketFollowsSkipCase(wolfSSH_TestDoKexDhInit, "DoKexDhInit");
#ifndef WOLFSSH_NO_DH_GEX_SHA256
    RunFirstPacketFollowsSkipCase(wolfSSH_TestDoKexDhGexRequest,
            "DoKexDhGexRequest");
#endif
}

static void TestFirstPacketFollows(void)
{
    size_t i;
    size_t n = sizeof(firstPacketFollowsCases)
            / sizeof(firstPacketFollowsCases[0]);

    for (i = 0; i < n; i++) {
        RunFirstPacketFollowsCase(&firstPacketFollowsCases[i]);
    }
    TestFirstPacketFollowsSkipped();
}

#if !defined(WOLFSSH_NO_AES_CBC) && !defined(WOLFSSH_NO_AES_CTR) \
    && !defined(WOLFSSH_NO_HMAC_SHA1) && !defined(WOLFSSH_NO_HMAC_SHA2_256)
static void TestIndependentAlgoNegotiation(void)
{
    WOLFSSH_CTX* ctx;
    WOLFSSH* ssh;
    byte payload[512];
    word32 payloadSz;
    word32 idx;

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_SERVER, NULL);
    AssertNotNull(ctx);

    /* Sub-test A: different non-AEAD cipher and MAC per direction */
    ssh = wolfSSH_new(ctx);
    AssertNotNull(ssh);
    AssertIntEQ(wolfSSH_SetAlgoListKex(ssh, FPF_KEX_GOOD), WS_SUCCESS);
    AssertIntEQ(wolfSSH_SetAlgoListKey(ssh, FPF_KEY_GOOD), WS_SUCCESS);
    AssertIntEQ(wolfSSH_SetAlgoListCipher(ssh,
            "aes128-cbc,aes256-ctr"), WS_SUCCESS);
    AssertIntEQ(wolfSSH_SetAlgoListMac(ssh,
            "hmac-sha1,hmac-sha2-256"), WS_SUCCESS);
    idx = 0;
    payloadSz = BuildKexInitPayloadFull(
            FPF_KEX_GOOD, FPF_KEY_GOOD,
            "aes128-cbc",    /* C2S enc */
            "aes256-ctr",    /* S2C enc */
            "hmac-sha1",     /* C2S MAC */
            "hmac-sha2-256", /* S2C MAC */
            0, payload, (word32)sizeof(payload));
    (void)wolfSSH_TestDoKexInit(ssh, payload, payloadSz, &idx);
    AssertNotNull(ssh->handshake);
    AssertIntEQ(ssh->handshake->peerEncryptId, ID_AES128_CBC);
    AssertIntEQ(ssh->handshake->encryptId,     ID_AES256_CTR);
    AssertIntEQ(ssh->handshake->peerMacId,     ID_HMAC_SHA1);
    AssertIntEQ(ssh->handshake->macId,         ID_HMAC_SHA2_256);
    AssertIntEQ(ssh->handshake->peerAeadMode,  0);
    AssertIntEQ(ssh->handshake->aeadMode,      0);
    /* Key sizes — server: C2S→peerKeys, S2C→keys. Validates the
     * side-aware DoKexInit fix: wrong mapping would swap these sizes. */
    AssertIntEQ(ssh->handshake->peerKeys.encKeySz, AES_128_KEY_SIZE);
    AssertIntEQ(ssh->handshake->keys.encKeySz,     AES_256_KEY_SIZE);
    AssertIntEQ(ssh->handshake->peerKeys.ivSz,     AES_BLOCK_SIZE);
    AssertIntEQ(ssh->handshake->keys.ivSz,         AES_BLOCK_SIZE);
    AssertIntEQ(ssh->handshake->peerKeys.macKeySz, WC_SHA_DIGEST_SIZE);
    AssertIntEQ(ssh->handshake->keys.macKeySz,     WC_SHA256_DIGEST_SIZE);
    wolfSSH_free(ssh);

#ifndef WOLFSSH_NO_AES_GCM
    /* Sub-test B: AEAD S2C, non-AEAD C2S — MAC only negotiated for C2S */
    ssh = wolfSSH_new(ctx);
    AssertNotNull(ssh);
    AssertIntEQ(wolfSSH_SetAlgoListKex(ssh, FPF_KEX_GOOD), WS_SUCCESS);
    AssertIntEQ(wolfSSH_SetAlgoListKey(ssh, FPF_KEY_GOOD), WS_SUCCESS);
    AssertIntEQ(wolfSSH_SetAlgoListCipher(ssh,
            "aes128-cbc,aes256-gcm@openssh.com"), WS_SUCCESS);
    AssertIntEQ(wolfSSH_SetAlgoListMac(ssh,
            "hmac-sha1,hmac-sha2-256"), WS_SUCCESS);
    idx = 0;
    payloadSz = BuildKexInitPayloadFull(
            FPF_KEX_GOOD, FPF_KEY_GOOD,
            "aes128-cbc",             /* C2S enc: non-AEAD */
            "aes256-gcm@openssh.com", /* S2C enc: AEAD */
            "hmac-sha1",              /* C2S MAC: negotiated */
            "hmac-sha2-256",          /* S2C MAC: skipped (aeadMode) */
            0, payload, (word32)sizeof(payload));
    (void)wolfSSH_TestDoKexInit(ssh, payload, payloadSz, &idx);
    AssertNotNull(ssh->handshake);
    AssertIntEQ(ssh->handshake->peerEncryptId, ID_AES128_CBC);
    AssertIntEQ(ssh->handshake->encryptId,     ID_AES256_GCM);
    AssertIntEQ(ssh->handshake->peerAeadMode,  0);
    AssertIntEQ(ssh->handshake->aeadMode,      1);
    AssertIntEQ(ssh->handshake->peerMacId,     ID_HMAC_SHA1);
    AssertIntEQ(ssh->handshake->macId,         ID_NONE);
    /* Key sizes for split-AEAD case. */
    AssertIntEQ(ssh->handshake->peerKeys.encKeySz, AES_128_KEY_SIZE);
    AssertIntEQ(ssh->handshake->keys.encKeySz,     AES_256_KEY_SIZE);
    AssertIntEQ(ssh->handshake->peerKeys.ivSz,     AES_BLOCK_SIZE);
    AssertIntEQ(ssh->handshake->keys.ivSz,         AEAD_NONCE_SZ);
    AssertIntEQ(ssh->handshake->peerKeys.macKeySz, WC_SHA_DIGEST_SIZE);
    AssertIntEQ(ssh->handshake->keys.macKeySz,     0);
    wolfSSH_free(ssh);
#endif /* !WOLFSSH_NO_AES_GCM */

    wolfSSH_CTX_free(ctx);
}

static void TestIndependentAlgoNegotiationClient(void)
{
    WOLFSSH_CTX* ctx;
    WOLFSSH* ssh;
    byte payload[512];
    word32 payloadSz;
    word32 idx;

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_CLIENT, NULL);
    AssertNotNull(ctx);

    /* Sub-test A: different non-AEAD cipher and MAC per direction.
     * Client mapping is the mirror of server: C2S→keys/encryptId,
     * S2C→peerKeys/peerEncryptId.  A swap bug would make these asserts fail. */
    ssh = wolfSSH_new(ctx);
    AssertNotNull(ssh);
    AssertIntEQ(wolfSSH_SetAlgoListKex(ssh, FPF_KEX_GOOD), WS_SUCCESS);
    AssertIntEQ(wolfSSH_SetAlgoListKey(ssh, FPF_KEY_GOOD), WS_SUCCESS);
    AssertIntEQ(wolfSSH_SetAlgoListCipher(ssh,
            "aes128-cbc,aes256-ctr"), WS_SUCCESS);
    AssertIntEQ(wolfSSH_SetAlgoListMac(ssh,
            "hmac-sha1,hmac-sha2-256"), WS_SUCCESS);
    idx = 0;
    payloadSz = BuildKexInitPayloadFull(
            FPF_KEX_GOOD, FPF_KEY_GOOD,
            "aes128-cbc",    /* C2S enc */
            "aes256-ctr",    /* S2C enc */
            "hmac-sha1",     /* C2S MAC */
            "hmac-sha2-256", /* S2C MAC */
            0, payload, (word32)sizeof(payload));
    (void)wolfSSH_TestDoKexInit(ssh, payload, payloadSz, &idx);
    AssertNotNull(ssh->handshake);
    /* Client: C2S is local outgoing → encryptId/keys */
    AssertIntEQ(ssh->handshake->encryptId,     ID_AES128_CBC);
    AssertIntEQ(ssh->handshake->peerEncryptId, ID_AES256_CTR);
    AssertIntEQ(ssh->handshake->macId,         ID_HMAC_SHA1);
    AssertIntEQ(ssh->handshake->peerMacId,     ID_HMAC_SHA2_256);
    AssertIntEQ(ssh->handshake->aeadMode,      0);
    AssertIntEQ(ssh->handshake->peerAeadMode,  0);
    AssertIntEQ(ssh->handshake->keys.encKeySz,     AES_128_KEY_SIZE);
    AssertIntEQ(ssh->handshake->peerKeys.encKeySz, AES_256_KEY_SIZE);
    AssertIntEQ(ssh->handshake->keys.ivSz,         AES_BLOCK_SIZE);
    AssertIntEQ(ssh->handshake->peerKeys.ivSz,     AES_BLOCK_SIZE);
    AssertIntEQ(ssh->handshake->keys.macKeySz,     WC_SHA_DIGEST_SIZE);
    AssertIntEQ(ssh->handshake->peerKeys.macKeySz, WC_SHA256_DIGEST_SIZE);
    wolfSSH_free(ssh);

#ifndef WOLFSSH_NO_AES_GCM
    /* Sub-test B: AEAD S2C, non-AEAD C2S — client perspective. */
    ssh = wolfSSH_new(ctx);
    AssertNotNull(ssh);
    AssertIntEQ(wolfSSH_SetAlgoListKex(ssh, FPF_KEX_GOOD), WS_SUCCESS);
    AssertIntEQ(wolfSSH_SetAlgoListKey(ssh, FPF_KEY_GOOD), WS_SUCCESS);
    AssertIntEQ(wolfSSH_SetAlgoListCipher(ssh,
            "aes128-cbc,aes256-gcm@openssh.com"), WS_SUCCESS);
    AssertIntEQ(wolfSSH_SetAlgoListMac(ssh,
            "hmac-sha1,hmac-sha2-256"), WS_SUCCESS);
    idx = 0;
    payloadSz = BuildKexInitPayloadFull(
            FPF_KEX_GOOD, FPF_KEY_GOOD,
            "aes128-cbc",             /* C2S enc: non-AEAD */
            "aes256-gcm@openssh.com", /* S2C enc: AEAD */
            "hmac-sha1",              /* C2S MAC: negotiated */
            "hmac-sha2-256",          /* S2C MAC: skipped (aeadMode) */
            0, payload, (word32)sizeof(payload));
    (void)wolfSSH_TestDoKexInit(ssh, payload, payloadSz, &idx);
    AssertNotNull(ssh->handshake);
    /* Client: C2S→encryptId/keys, S2C→peerEncryptId/peerKeys */
    AssertIntEQ(ssh->handshake->encryptId,     ID_AES128_CBC);
    AssertIntEQ(ssh->handshake->peerEncryptId, ID_AES256_GCM);
    AssertIntEQ(ssh->handshake->aeadMode,      0);
    AssertIntEQ(ssh->handshake->peerAeadMode,  1);
    AssertIntEQ(ssh->handshake->macId,         ID_HMAC_SHA1);
    AssertIntEQ(ssh->handshake->peerMacId,     ID_NONE);
    AssertIntEQ(ssh->handshake->keys.encKeySz,     AES_128_KEY_SIZE);
    AssertIntEQ(ssh->handshake->peerKeys.encKeySz, AES_256_KEY_SIZE);
    AssertIntEQ(ssh->handshake->keys.ivSz,         AES_BLOCK_SIZE);
    AssertIntEQ(ssh->handshake->peerKeys.ivSz,     AEAD_NONCE_SZ);
    AssertIntEQ(ssh->handshake->keys.macKeySz,     WC_SHA_DIGEST_SIZE);
    AssertIntEQ(ssh->handshake->peerKeys.macKeySz, 0);
    wolfSSH_free(ssh);
#endif /* !WOLFSSH_NO_AES_GCM */

    wolfSSH_CTX_free(ctx);
}

static void TestGenerateKeysSplit(void)
{
    WOLFSSH_CTX* ctx;
    WOLFSSH* ssh;
    byte payload[512];
    word32 payloadSz;
    word32 idx;
    byte zeros[AES_256_KEY_SIZE];

    WMEMSET(zeros, 0, sizeof(zeros));

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_SERVER, NULL);
    AssertNotNull(ctx);

    /* Sub-test A: aes128-cbc C2S / aes256-ctr S2C, non-AEAD both dirs.
     * Verifies GenerateKeys uses the correct key size for each direction. */
    ssh = wolfSSH_new(ctx);
    AssertNotNull(ssh);
    AssertIntEQ(wolfSSH_SetAlgoListKex(ssh, FPF_KEX_GOOD), WS_SUCCESS);
    AssertIntEQ(wolfSSH_SetAlgoListKey(ssh, FPF_KEY_GOOD), WS_SUCCESS);
    AssertIntEQ(wolfSSH_SetAlgoListCipher(ssh,
            "aes128-cbc,aes256-ctr"), WS_SUCCESS);
    AssertIntEQ(wolfSSH_SetAlgoListMac(ssh,
            "hmac-sha1,hmac-sha2-256"), WS_SUCCESS);
    idx = 0;
    payloadSz = BuildKexInitPayloadFull(
            FPF_KEX_GOOD, FPF_KEY_GOOD,
            "aes128-cbc",    /* C2S enc */
            "aes256-ctr",    /* S2C enc */
            "hmac-sha1",     /* C2S MAC */
            "hmac-sha2-256", /* S2C MAC */
            0, payload, (word32)sizeof(payload));
    (void)wolfSSH_TestDoKexInit(ssh, payload, payloadSz, &idx);
    AssertNotNull(ssh->handshake);

    /* Synthetic K/H/sessionId — any non-zero values produce valid key material. */
    WMEMSET(ssh->k, 0xAA, WC_SHA256_DIGEST_SIZE);
    ssh->kSz = WC_SHA256_DIGEST_SIZE;
    WMEMSET(ssh->h, 0xBB, WC_SHA256_DIGEST_SIZE);
    ssh->hSz = WC_SHA256_DIGEST_SIZE;
    WMEMCPY(ssh->sessionId, ssh->h, ssh->hSz);
    ssh->sessionIdSz = ssh->hSz;

    AssertIntEQ(wolfSSH_TestGenerateKeys(ssh), WS_SUCCESS);

    /* C2S direction (server: peerKeys) — aes128-cbc + hmac-sha1. */
    AssertIntEQ(ssh->handshake->peerKeys.encKeySz, AES_128_KEY_SIZE);
    AssertTrue(WMEMCMP(ssh->handshake->peerKeys.encKey, zeros,
                       AES_128_KEY_SIZE) != 0);
    AssertIntEQ(ssh->handshake->peerKeys.macKeySz, WC_SHA_DIGEST_SIZE);
    AssertTrue(WMEMCMP(ssh->handshake->peerKeys.macKey, zeros,
                       WC_SHA_DIGEST_SIZE) != 0);

    /* S2C direction (server: keys) — aes256-ctr + hmac-sha2-256. */
    AssertIntEQ(ssh->handshake->keys.encKeySz, AES_256_KEY_SIZE);
    AssertTrue(WMEMCMP(ssh->handshake->keys.encKey, zeros,
                       AES_256_KEY_SIZE) != 0);
    AssertIntEQ(ssh->handshake->keys.macKeySz, WC_SHA256_DIGEST_SIZE);
    AssertTrue(WMEMCMP(ssh->handshake->keys.macKey, zeros,
                       WC_SHA256_DIGEST_SIZE) != 0);

    /* C2S and S2C enc keys must be independent (different RFC labels C/D). */
    AssertTrue(WMEMCMP(ssh->handshake->peerKeys.encKey,
                       ssh->handshake->keys.encKey, AES_128_KEY_SIZE) != 0);

    wolfSSH_free(ssh);

#ifndef WOLFSSH_NO_AES_GCM
    /* Sub-test B: aes128-cbc C2S (non-AEAD) / aes256-gcm S2C (AEAD).
     * Verifies that key 'F' is skipped for the AEAD direction (macKeySz==0). */
    ssh = wolfSSH_new(ctx);
    AssertNotNull(ssh);
    AssertIntEQ(wolfSSH_SetAlgoListKex(ssh, FPF_KEX_GOOD), WS_SUCCESS);
    AssertIntEQ(wolfSSH_SetAlgoListKey(ssh, FPF_KEY_GOOD), WS_SUCCESS);
    AssertIntEQ(wolfSSH_SetAlgoListCipher(ssh,
            "aes128-cbc,aes256-gcm@openssh.com"), WS_SUCCESS);
    AssertIntEQ(wolfSSH_SetAlgoListMac(ssh,
            "hmac-sha1,hmac-sha2-256"), WS_SUCCESS);
    idx = 0;
    payloadSz = BuildKexInitPayloadFull(
            FPF_KEX_GOOD, FPF_KEY_GOOD,
            "aes128-cbc",             /* C2S enc: non-AEAD */
            "aes256-gcm@openssh.com", /* S2C enc: AEAD */
            "hmac-sha1",              /* C2S MAC */
            "hmac-sha2-256",          /* S2C MAC: skipped */
            0, payload, (word32)sizeof(payload));
    (void)wolfSSH_TestDoKexInit(ssh, payload, payloadSz, &idx);
    AssertNotNull(ssh->handshake);

    WMEMSET(ssh->k, 0xAA, WC_SHA256_DIGEST_SIZE);
    ssh->kSz = WC_SHA256_DIGEST_SIZE;
    WMEMSET(ssh->h, 0xBB, WC_SHA256_DIGEST_SIZE);
    ssh->hSz = WC_SHA256_DIGEST_SIZE;
    WMEMCPY(ssh->sessionId, ssh->h, ssh->hSz);
    ssh->sessionIdSz = ssh->hSz;

    AssertIntEQ(wolfSSH_TestGenerateKeys(ssh), WS_SUCCESS);

    /* C2S hmac-sha1 MAC key must be generated. */
    AssertIntEQ(ssh->handshake->peerKeys.macKeySz, WC_SHA_DIGEST_SIZE);
    AssertTrue(WMEMCMP(ssh->handshake->peerKeys.macKey, zeros,
                       WC_SHA_DIGEST_SIZE) != 0);

    /* S2C AEAD: macKeySz==0 so key 'F' was skipped; macKey stays all-zero. */
    AssertIntEQ(ssh->handshake->keys.macKeySz, 0);
    AssertIntEQ(WMEMCMP(ssh->handshake->keys.macKey, zeros,
                        WC_SHA_DIGEST_SIZE), 0);

    wolfSSH_free(ssh);
#endif /* !WOLFSSH_NO_AES_GCM */

    wolfSSH_CTX_free(ctx);
}
static void TestGenerateKeysSplitClient(void)
{
    WOLFSSH_CTX* ctx;
    WOLFSSH* ssh;
    byte payload[512];
    word32 payloadSz;
    word32 idx;
    byte zeros[AES_256_KEY_SIZE];

    WMEMSET(zeros, 0, sizeof(zeros));

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_CLIENT, NULL);
    AssertNotNull(ctx);

    /* Sub-test A: aes128-cbc C2S / aes256-ctr S2C — client mapping.
     * Client: C2S→keys (local outgoing), S2C→peerKeys (peer outgoing). */
    ssh = wolfSSH_new(ctx);
    AssertNotNull(ssh);
    AssertIntEQ(wolfSSH_SetAlgoListKex(ssh, FPF_KEX_GOOD), WS_SUCCESS);
    AssertIntEQ(wolfSSH_SetAlgoListKey(ssh, FPF_KEY_GOOD), WS_SUCCESS);
    AssertIntEQ(wolfSSH_SetAlgoListCipher(ssh,
            "aes128-cbc,aes256-ctr"), WS_SUCCESS);
    AssertIntEQ(wolfSSH_SetAlgoListMac(ssh,
            "hmac-sha1,hmac-sha2-256"), WS_SUCCESS);
    idx = 0;
    payloadSz = BuildKexInitPayloadFull(
            FPF_KEX_GOOD, FPF_KEY_GOOD,
            "aes128-cbc",    /* C2S enc */
            "aes256-ctr",    /* S2C enc */
            "hmac-sha1",     /* C2S MAC */
            "hmac-sha2-256", /* S2C MAC */
            0, payload, (word32)sizeof(payload));
    (void)wolfSSH_TestDoKexInit(ssh, payload, payloadSz, &idx);
    AssertNotNull(ssh->handshake);

    WMEMSET(ssh->k, 0xAA, WC_SHA256_DIGEST_SIZE);
    ssh->kSz = WC_SHA256_DIGEST_SIZE;
    WMEMSET(ssh->h, 0xBB, WC_SHA256_DIGEST_SIZE);
    ssh->hSz = WC_SHA256_DIGEST_SIZE;
    WMEMCPY(ssh->sessionId, ssh->h, ssh->hSz);
    ssh->sessionIdSz = ssh->hSz;

    AssertIntEQ(wolfSSH_TestGenerateKeys(ssh), WS_SUCCESS);

    /* C2S direction (client: keys) — aes128-cbc + hmac-sha1. */
    AssertIntEQ(ssh->handshake->keys.encKeySz, AES_128_KEY_SIZE);
    AssertTrue(WMEMCMP(ssh->handshake->keys.encKey, zeros,
                       AES_128_KEY_SIZE) != 0);
    AssertIntEQ(ssh->handshake->keys.macKeySz, WC_SHA_DIGEST_SIZE);
    AssertTrue(WMEMCMP(ssh->handshake->keys.macKey, zeros,
                       WC_SHA_DIGEST_SIZE) != 0);

    /* S2C direction (client: peerKeys) — aes256-ctr + hmac-sha2-256. */
    AssertIntEQ(ssh->handshake->peerKeys.encKeySz, AES_256_KEY_SIZE);
    AssertTrue(WMEMCMP(ssh->handshake->peerKeys.encKey, zeros,
                       AES_256_KEY_SIZE) != 0);
    AssertIntEQ(ssh->handshake->peerKeys.macKeySz, WC_SHA256_DIGEST_SIZE);
    AssertTrue(WMEMCMP(ssh->handshake->peerKeys.macKey, zeros,
                       WC_SHA256_DIGEST_SIZE) != 0);

    /* C2S and S2C enc keys must be independent. */
    AssertTrue(WMEMCMP(ssh->handshake->keys.encKey,
                       ssh->handshake->peerKeys.encKey, AES_128_KEY_SIZE) != 0);

    wolfSSH_free(ssh);

#ifndef WOLFSSH_NO_AES_GCM
    /* Sub-test B: aes128-cbc C2S (non-AEAD) / aes256-gcm S2C (AEAD) — client.
     * keys.macKeySz must be set; peerKeys.macKeySz must be 0 (AEAD, no MAC). */
    ssh = wolfSSH_new(ctx);
    AssertNotNull(ssh);
    AssertIntEQ(wolfSSH_SetAlgoListKex(ssh, FPF_KEX_GOOD), WS_SUCCESS);
    AssertIntEQ(wolfSSH_SetAlgoListKey(ssh, FPF_KEY_GOOD), WS_SUCCESS);
    AssertIntEQ(wolfSSH_SetAlgoListCipher(ssh,
            "aes128-cbc,aes256-gcm@openssh.com"), WS_SUCCESS);
    AssertIntEQ(wolfSSH_SetAlgoListMac(ssh,
            "hmac-sha1,hmac-sha2-256"), WS_SUCCESS);
    idx = 0;
    payloadSz = BuildKexInitPayloadFull(
            FPF_KEX_GOOD, FPF_KEY_GOOD,
            "aes128-cbc",             /* C2S enc: non-AEAD */
            "aes256-gcm@openssh.com", /* S2C enc: AEAD */
            "hmac-sha1",              /* C2S MAC */
            "hmac-sha2-256",          /* S2C MAC: skipped */
            0, payload, (word32)sizeof(payload));
    (void)wolfSSH_TestDoKexInit(ssh, payload, payloadSz, &idx);
    AssertNotNull(ssh->handshake);

    WMEMSET(ssh->k, 0xAA, WC_SHA256_DIGEST_SIZE);
    ssh->kSz = WC_SHA256_DIGEST_SIZE;
    WMEMSET(ssh->h, 0xBB, WC_SHA256_DIGEST_SIZE);
    ssh->hSz = WC_SHA256_DIGEST_SIZE;
    WMEMCPY(ssh->sessionId, ssh->h, ssh->hSz);
    ssh->sessionIdSz = ssh->hSz;

    AssertIntEQ(wolfSSH_TestGenerateKeys(ssh), WS_SUCCESS);

    /* C2S hmac-sha1 MAC key (client: keys) must be generated. */
    AssertIntEQ(ssh->handshake->keys.macKeySz, WC_SHA_DIGEST_SIZE);
    AssertTrue(WMEMCMP(ssh->handshake->keys.macKey, zeros,
                       WC_SHA_DIGEST_SIZE) != 0);

    /* S2C AEAD (client: peerKeys): macKeySz==0, macKey stays all-zero. */
    AssertIntEQ(ssh->handshake->peerKeys.macKeySz, 0);
    AssertIntEQ(WMEMCMP(ssh->handshake->peerKeys.macKey, zeros,
                        WC_SHA_DIGEST_SIZE), 0);

    wolfSSH_free(ssh);
#endif /* !WOLFSSH_NO_AES_GCM */

    wolfSSH_CTX_free(ctx);
}
#endif /* AES_CBC + AES_CTR + HMAC guards */

#endif /* first_packet_follows coverage guard */


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
    TestDirectTcpipNoFwdCbSendsOpenFail();
    TestGlobalRequestFwdNoCbSendsFailure();
    TestGlobalRequestFwdNoCbNoReplyKeepsConnection();
    TestGlobalRequestFwdWithCbSendsSuccess();
    TestGlobalRequestFwdCancelNoCbSendsFailure();
    TestGlobalRequestFwdCancelWithCbSendsSuccess();
    TestRequestSuccessWithPortParsesCorrectly();
#endif
#ifdef WOLFSSH_AGENT
    TestAgentChannelNullAgentSendsOpenFail();
#endif
    TestKexInitRejectedWhenKeying(ssh);
#if !defined(WOLFSSH_NO_ECDH_SHA2_NISTP256) && !defined(WOLFSSH_NO_RSA) \
    && !defined(WOLFSSH_NO_CURVE25519_SHA256) \
    && !defined(WOLFSSH_NO_RSA_SHA2_256)
    TestFirstPacketFollows();
#endif
#if !defined(WOLFSSH_NO_ECDH_SHA2_NISTP256) && !defined(WOLFSSH_NO_RSA) \
    && !defined(WOLFSSH_NO_CURVE25519_SHA256) \
    && !defined(WOLFSSH_NO_RSA_SHA2_256) \
    && !defined(WOLFSSH_NO_AES_CBC) && !defined(WOLFSSH_NO_AES_CTR) \
    && !defined(WOLFSSH_NO_HMAC_SHA1) && !defined(WOLFSSH_NO_HMAC_SHA2_256)
    TestIndependentAlgoNegotiation();
    TestIndependentAlgoNegotiationClient();
    TestGenerateKeysSplit();
    TestGenerateKeysSplitClient();
#endif
    TestDisconnectSetsDisconnectError();
#if !(defined(WOLFSSH_NO_RSA) && defined(WOLFSSH_NO_ECDSA_SHA2_NISTP256))
    TestClientBuffersIdempotent();
#endif
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
    TestKexDhReplyRejectsNoPublicKeyCheck();
    TestKexDhReplyRejectsWhenCallbackRejects();
#endif

#ifdef WOLFSSH_SFTP
    TestOct2DecRejectsInvalidNonLeadingDigit();
    #ifdef WOLFSSH_STOREHANDLE
    TestSftpRemoveHandleHeadUpdate();
    #endif
    TestSftpBufferSendPendingOutput();
    #if defined(WOLFSSL_NUCLEUS) && !defined(NO_WOLFSSH_MKTIME)
    TestNucleusMonthConversion();
    #endif
#endif

#ifdef WOLFSSH_KEYBOARD_INTERACTIVE
    TestKeyboardResponsePreparePacketFailure(ssh, ctx);
    TestKeyboardResponseNoUserAuthCallback(ssh, ctx);
    TestKeyboardResponseNullSsh();
    TestKeyboardResponseNullCtx(ssh);
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

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
#include <sys/stat.h>

#include <wolfssl/wolfcrypt/coding.h>
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
#define AssertNull(x)    Assert(!(x), ("%s is null",    #x), (#x " => NOT NULL"))
#define AssertIntEQ(x, y) do { int _x = (int)(x); int _y = (int)(y);           \
    Assert(_x == _y, ("%s == %s", #x, #y), ("%d != %d", _x, _y)); } while (0)
#define AssertStrEQ(x, y) do { const char* _x = (const char*)(x);              \
    const char* _y = (const char*)(y);                                         \
    Assert(WSTRCMP(_x, _y) == 0, ("%s == %s", #x, #y),                         \
        ("\"%s\" != \"%s\"", _x, _y)); } while (0)


static void ResetSession(WOLFSSH* ssh)
{
    if (ssh->handshake != NULL) {
        WFREE(ssh->handshake, ssh->ctx->heap, DYNTYPE_HS);
        ssh->handshake = NULL;
    }
    ssh->isKeying = 0;
    ssh->connectState = CONNECT_BEGIN;
    ssh->acceptState = ACCEPT_BEGIN;
    ssh->error = 0;
    ssh->disconnected = 0;
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
 * Layout: uint32 packetLen, byte padLen, payload[msgId], pad[padLen]. */
static word32 BuildPacket(byte msgId, byte* out, word32 outSz)
{
    byte padLen = 10; /* 4 (len) +1 (padLen) +1 (msgId) +10 = 16 */
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

/* Callers sit in separate conditional blocks; some builds have none. */
static WS_MAYBE_UNUSED word32 ParsePayloadLen(const byte* packet,
        word32 packetSz)
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

/* Callers sit in separate conditional blocks; some builds have none. */
static WS_MAYBE_UNUSED word32 ReadUint32(const byte* buf)
{
    return ((word32)buf[0] << 24) | ((word32)buf[1] << 16) |
            ((word32)buf[2] << 8) | (word32)buf[3];
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

/* One EXT_INFO carrying a single server-sig-algs extension. Callers sit in
 * separate conditional blocks; some builds have none. */
static WS_MAYBE_UNUSED word32 BuildExtInfoSigAlgs(byte* buf, word32 bufSz,
        const char* sigAlgs)
{
    word32 idx = 0;

    idx = AppendUint32(buf, bufSz, idx, 1);
    idx = AppendString(buf, bufSz, idx, "server-sig-algs");
    return AppendString(buf, bufSz, idx, sigAlgs);
}

static word32 BuildChannelClosePacket(word32 peerChannelId, byte* out,
        word32 outSz)
{
    byte payload[16];
    word32 idx = 0;

    idx = AppendUint32(payload, sizeof(payload), idx, peerChannelId);

    return WrapPacket(MSGID_CHANNEL_CLOSE, payload, idx, out, outSz);
}


static word32 BuildChannelDataPacket(word32 peerChannelId, const char* data,
        byte* out, word32 outSz)
{
    byte payload[64];
    word32 idx = 0;

    idx = AppendUint32(payload, sizeof(payload), idx, peerChannelId);
    idx = AppendString(payload, sizeof(payload), idx, data);

    return WrapPacket(MSGID_CHANNEL_DATA, payload, idx, out, outSz);
}


#ifdef WOLFSSH_FWD
/* Callers sit in separate conditional blocks; some builds have none. */
static WS_MAYBE_UNUSED word32 BuildDirectTcpipExtra(const char* host,
        word32 hostPort, const char* origin, word32 originPort, byte* out,
        word32 outSz)
{
    word32 idx = 0;

    idx = AppendString(out, outSz, idx, host);
    idx = AppendUint32(out, outSz, idx, hostPort);
    idx = AppendString(out, outSz, idx, origin);
    idx = AppendUint32(out, outSz, idx, originPort);

    return idx;
}

static WS_MAYBE_UNUSED word32 BuildGlobalRequestFwdPacket(const char* bindAddr,
        word32 bindPort, int isCancel, byte wantReply, byte* out, word32 outSz)
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
    byte blockNext; /* make the next send report a would-block */
    byte isrNext;   /* make the next send report an interrupted call */
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
    if (io->blockNext) {
        io->blockNext = 0;
        return WS_CBIO_ERR_WANT_WRITE;
    }
    if (io->isrNext) {
        io->isrNext = 0;
        return WS_CBIO_ERR_ISR;
    }
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
    io->blockNext = 0;
    io->isrNext = 0;
}

/* The in-memory session harness. The struct and its teardown are shared; the
 * client-side setup drives a client session, so the forwarding tests built on
 * it run without a server. */
typedef struct {
    WOLFSSH_CTX* ctx;
    WOLFSSH* ssh;
    MemIo io;
    byte out[256];
} ChannelOpenHarness;

static WS_MAYBE_UNUSED void FreeChannelOpenHarness(ChannelOpenHarness* harness)
{
    if (harness->ssh != NULL)
        wolfSSH_free(harness->ssh);
    if (harness->ctx != NULL)
        wolfSSH_CTX_free(harness->ctx);
}

#if defined(WOLFSSH_FWD) && !defined(NO_WOLFSSH_CLIENT)
/* The same harness on the client side, sitting past userauth so an inbound
 * channel open is allowed through. */
static void InitChannelOpenHarnessClient(ChannelOpenHarness* harness,
        byte* in, word32 inSz)
{
    WMEMSET(harness, 0, sizeof(*harness));

    harness->ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_CLIENT, NULL);
    AssertNotNull(harness->ctx);

    wolfSSH_SetIORecv(harness->ctx, MemRecv);
    wolfSSH_SetIOSend(harness->ctx, MemSend);

    harness->ssh = wolfSSH_new(harness->ctx);
    AssertNotNull(harness->ssh);

    MemIoInit(&harness->io, in, inSz, harness->out, sizeof(harness->out));
    wolfSSH_SetIOReadCtx(harness->ssh, &harness->io);
    wolfSSH_SetIOWriteCtx(harness->ssh, &harness->io);
    /* A rekey cannot fit the 256-byte mem buffer, so keep a build-time
     * DEFAULT_HIGHWATER_MARK from firing one mid-test. */
    AssertIntEQ(wolfSSH_SetHighwater(harness->ssh, 0), WS_SUCCESS);
    harness->ssh->connectState = CONNECT_SERVER_USERAUTH_ACCEPT_DONE;
}
#endif /* WOLFSSH_FWD && !NO_WOLFSSH_CLIENT */

/* The tests below drive a server-side session. With NO_WOLFSSH_SERVER the
 * message filter has no server branch, so every message on such a session is
 * refused and those tests cannot run. */
#ifndef NO_WOLFSSH_SERVER

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
    /* A rekey cannot fit the 256-byte mem buffer, so keep a build-time
     * DEFAULT_HIGHWATER_MARK from firing one mid-test. */
    AssertIntEQ(wolfSSH_SetHighwater(harness->ssh, 0), WS_SUCCESS);
    harness->ssh->acceptState = ACCEPT_SERVER_USERAUTH_SENT;
}


#ifdef WOLFSSH_KEYBOARD_INTERACTIVE
/* Build a plaintext SSH_MSG_USERAUTH_INFO_RESPONSE. The wire response count is
 * "responseCount"; "stringCount" "x" response strings are actually appended.
 * The count-mismatch guard rejects before parsing the body, so a short body is
 * sufficient to drive it. */
static word32 BuildInfoResponsePacket(word32 responseCount, word32 stringCount,
        byte* out, word32 outSz)
{
    byte payload[128];
    word32 idx = 0;
    word32 i;

    idx = AppendUint32(payload, sizeof(payload), idx, responseCount);
    for (i = 0; i < stringCount; i++) {
        idx = AppendString(payload, sizeof(payload), idx, "x");
    }

    return WrapPacket(MSGID_USERAUTH_INFO_RESPONSE, payload, idx, out, outSz);
}

/* Place the server mid keyboard-interactive auth, expecting an INFO_RESPONSE
 * for "promptCount" prompts. */
static void InitKbInfoResponseHarness(ChannelOpenHarness* harness,
        byte* in, word32 inSz, word32 promptCount)
{
    InitChannelOpenHarness(harness, in, inSz);
    harness->ssh->acceptState = ACCEPT_CLIENT_USERAUTH_REQUEST_DONE;
    harness->ssh->authId = ID_USERAUTH_KEYBOARD;
    harness->ssh->kbAuth.promptCount = promptCount;
}

/* Post-condition for a rejected INFO_RESPONSE: the transport survives and the
 * server's reply is a USERAUTH_FAILURE rather than a teardown. */
static void AssertKbInfoResponseSentFailure(const ChannelOpenHarness* harness,
        int ret)
{
    AssertIntEQ(ret, WS_SUCCESS);
    AssertIntEQ(harness->io.inOff, harness->io.inSz);
    AssertTrue(harness->io.outSz > 0);
    AssertIntEQ(ParseMsgId(harness->io.out, harness->io.outSz),
            MSGID_USERAUTH_FAILURE);
}

/* A response count that disagrees with the server's prompt count must yield a
 * USERAUTH_FAILURE, not a transport teardown (RFC 4256). */
static void TestKbInfoResponseCountMismatchSendsFailure(void)
{
    ChannelOpenHarness harness;
    byte in[128];
    word32 inSz;
    int ret;

    /* Server expects 1 response; client sends 2. */
    inSz = BuildInfoResponsePacket(2, 2, in, sizeof(in));
    InitKbInfoResponseHarness(&harness, in, inSz, 1);

    ret = DoReceive(harness.ssh);

    AssertKbInfoResponseSentFailure(&harness, ret);

    FreeChannelOpenHarness(&harness);
}

/* A rejected INFO_RESPONSE must leave packet framing intact: the next packet on
 * the surviving connection still parses and draws its own failure. */
static void TestKbInfoResponseMismatchKeepsFraming(void)
{
    ChannelOpenHarness harness;
    byte in[256];
    word32 inSz, nextSz, firstOutSz;
    int ret;

    /* Two back-to-back responses, both disagreeing with a prompt count of 1. */
    inSz = BuildInfoResponsePacket(2, 2, in, sizeof(in));
    nextSz = BuildInfoResponsePacket(3, 3, in + inSz,
            (word32)sizeof(in) - inSz);
    InitKbInfoResponseHarness(&harness, in, inSz + nextSz, 1);

    ret = DoReceive(harness.ssh);
    AssertIntEQ(ret, WS_SUCCESS);
    AssertTrue(harness.io.outSz > 0);
    AssertIntEQ(ParseMsgId(harness.io.out, harness.io.outSz),
            MSGID_USERAUTH_FAILURE);
    firstOutSz = harness.io.outSz;

    ret = DoReceive(harness.ssh);
    AssertIntEQ(ret, WS_SUCCESS);
    AssertIntEQ(harness.io.inOff, harness.io.inSz);
    AssertTrue(harness.io.outSz > firstOutSz);
    AssertIntEQ(ParseMsgId(harness.io.out + firstOutSz,
            harness.io.outSz - firstOutSz), MSGID_USERAUTH_FAILURE);

    FreeChannelOpenHarness(&harness);
}

#endif /* WOLFSSH_KEYBOARD_INTERACTIVE */

#endif /* NO_WOLFSSH_SERVER */

/* Needs server, client, key files, and one covered host-key algorithm. */
#if !defined(NO_WOLFSSH_SERVER) && !defined(NO_WOLFSSH_CLIENT) && \
    !defined(NO_FILESYSTEM) && \
    (!defined(WOLFSSH_NO_RSA_SHA2_256) || \
     !defined(WOLFSSH_NO_RSA_SHA2_512) || \
     !defined(WOLFSSH_NO_ECDSA_SHA2_NISTP256) || !defined(WOLFSSH_NO_ED25519))
    #if !defined(WOLFSSH_NO_DH_GROUP14_SHA256)
        #define KEXDH_REPLY_REGRESS_KEX_ALGO "diffie-hellman-group14-sha256"
    #elif !defined(WOLFSSH_NO_DH_GROUP16_SHA512)
        #define KEXDH_REPLY_REGRESS_KEX_ALGO "diffie-hellman-group16-sha512"
    #elif !defined(WOLFSSH_NO_DH_GROUP14_SHA1)
        #define KEXDH_REPLY_REGRESS_KEX_ALGO "diffie-hellman-group14-sha1"
    #elif !defined(WOLFSSH_NO_DH_GROUP1_SHA1)
        #define KEXDH_REPLY_REGRESS_KEX_ALGO "diffie-hellman-group1-sha1"
    #elif !defined(WOLFSSH_NO_CURVE25519_SHA256)
        #define KEXDH_REPLY_REGRESS_KEX_ALGO "curve25519-sha256"
    #elif !defined(WOLFSSH_NO_ECDH_SHA2_NISTP256)
        #define KEXDH_REPLY_REGRESS_KEX_ALGO "ecdh-sha2-nistp256"
    #endif
#endif

/* Read a whole file into buf, returning the byte count (0 on any failure).
 * Used by the DH KEX regression below and by TestAppendKeyToFile, so it is
 * available whenever either of those is compiled. */
#if defined(KEXDH_REPLY_REGRESS_KEX_ALGO) || defined(WOLFSSH_TEST_INTERNAL)
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
    if (!WFSEEK_SUCCESS(WFSEEK(NULL, file, 0, WSEEK_END))) {
        WFCLOSE(NULL, file);
        return 0;
    }
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
#endif /* KEXDH_REPLY_REGRESS_KEX_ALGO || WOLFSSH_TEST_INTERNAL */

#ifdef KEXDH_REPLY_REGRESS_KEX_ALGO

#define REGRESS_DUPLEX_QUEUE_SZ 32768U
#define REGRESS_MUTATION_SCRATCH_SZ 4096U
#define REGRESS_SERVER_KEY_PATH "keys/server-key-rsa.der"
#define REGRESS_SERVER_KEY_ECC_PATH "keys/server-key-ecc.der"
#define REGRESS_SERVER_KEY_ED25519_PATH "keys/server-key-ed25519.der"
#define REGRESS_USERNAME "jill"
#define REGRESS_PASSWORD "upthehill"
#define REGRESS_MAX_HANDSHAKE_STEPS 2048
#define REGRESS_SSH_PROTO_PREFIX "SSH-"
#define REGRESS_SSH_PROTO_PREFIX_SZ 4U

/* Host key used by the tests that are not tied to one key algorithm. */
#if !defined(WOLFSSH_NO_RSA_SHA2_256)
    #define REGRESS_DEFAULT_KEY_ALGO "rsa-sha2-256"
    #define REGRESS_DEFAULT_KEY_PATH REGRESS_SERVER_KEY_PATH
#elif !defined(WOLFSSH_NO_RSA_SHA2_512)
    #define REGRESS_DEFAULT_KEY_ALGO "rsa-sha2-512"
    #define REGRESS_DEFAULT_KEY_PATH REGRESS_SERVER_KEY_PATH
#elif !defined(WOLFSSH_NO_ECDSA_SHA2_NISTP256)
    #define REGRESS_DEFAULT_KEY_ALGO "ecdsa-sha2-nistp256"
    #define REGRESS_DEFAULT_KEY_PATH REGRESS_SERVER_KEY_ECC_PATH
#else
    #define REGRESS_DEFAULT_KEY_ALGO "ssh-ed25519"
    #define REGRESS_DEFAULT_KEY_PATH REGRESS_SERVER_KEY_ED25519_PATH
#endif

/* KEX algorithm for the truncated peer-key tests */
#if !defined(WOLFSSH_NO_CURVE25519_SHA256)
    #define REGRESS_TRUNC_KEX_ALGO "curve25519-sha256"
#elif !defined(WOLFSSH_NO_ECDH_SHA2_NISTP256)
    #define REGRESS_TRUNC_KEX_ALGO "ecdh-sha2-nistp256"
#endif

/* KEX algorithm for the GEX group test */
#ifndef WOLFSSH_NO_DH_GEX_SHA256
    #define REGRESS_GEX_KEX_ALGO "diffie-hellman-group-exchange-sha256"
    /* Well under WOLFSSH_DH_GEX_MIN_BITS, so the client's range check
     * rejects the group before any primality work. */
    #define REGRESS_GEX_SHRUNK_PRIME_SZ 128U
#endif

#define REGRESS_MUTATE_SIG_NAME 0
#define REGRESS_MUTATE_SIG_DATA 1
#define REGRESS_MUTATE_SIG_NAME_OVERRUN 2
#define REGRESS_MUTATE_F_TRUNC 3
#define REGRESS_MUTATE_E_TRUNC 4
#define REGRESS_MUTATE_E_EMPTY 5
#define REGRESS_MUTATE_GEX_GROUP_SHRINK 6
#define REGRESS_MUTATE_GEX_GEN_BAD 7

typedef struct {
    byte data[REGRESS_DUPLEX_QUEUE_SZ];
    word32 len;
} DuplexQueue;

typedef struct {
    const char* replaceName;
    byte enabled;
    int parseError;
    word32 matchedPackets;
    word32 mutatedPackets;
    byte scratch[REGRESS_MUTATION_SCRATCH_SZ];
    word32 scratchSz;
    byte mode;
} KexReplyMutator;

typedef struct DuplexEndpoint {
    DuplexQueue inbound;
    struct DuplexEndpoint* peer;
    KexReplyMutator* mutator;
    word32 disconnectReason;
    byte isServer;
    byte sawDisconnect;
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

/* Locate the payload of an unbundled packet carrying msgId. Returns 1 with
 * payload set, 0 when the packet does not match, negative on bad framing. */
static int LocateSinglePacketPayload(const byte* packet, word32 packetSz,
        byte msgId, const byte** payload, word32* payloadSz)
{
    word32 packetLen, padLen;

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

    if (packet[UINT32_SZ + PAD_LENGTH_SZ] != msgId) {
        return 0;
    }

    *payload = packet + UINT32_SZ + PAD_LENGTH_SZ + MSG_ID_SZ;
    *payloadSz = packetSz - UINT32_SZ - PAD_LENGTH_SZ - MSG_ID_SZ - padLen;

    return 1;
}

/* SIG_NAME replaces the signature name; SIG_DATA flips a signature byte. */
static int RewriteSingleKexDhReplyPacket(const byte* packet, word32 packetSz,
        byte mode, const char* replacement, byte* out, word32 outSz,
        word32* outLen)
{
    const byte* payload;
    const byte* pubKey;
    const byte* f;
    const byte* sigBlob;
    const byte* sigName;
    const byte* sigData;
    word32 payloadSz;
    word32 pubKeySz, fSz, sigBlobSz;
    word32 sigNameSz, sigDataSz;
    word32 idx = 0;
    word32 innerIdx = 0;
    word32 outerIdx = 0;
    word32 innerSigSz;
    int ret;
    byte payloadBuf[REGRESS_MUTATION_SCRATCH_SZ];
    byte innerSig[REGRESS_MUTATION_SCRATCH_SZ];

    if (out == NULL || outLen == NULL) {
        return WS_BAD_ARGUMENT;
    }
    if (mode == REGRESS_MUTATE_SIG_NAME && replacement == NULL) {
        return WS_BAD_ARGUMENT;
    }

    ret = LocateSinglePacketPayload(packet, packetSz, MSGID_KEXDH_REPLY,
            &payload, &payloadSz);
    if (ret != 1) {
        return ret;
    }

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

    innerSigSz = 0;
    if (mode == REGRESS_MUTATE_SIG_DATA) {
        word32 dataStart;
        word32 flipIdx;

        if (sigDataSz <= LENGTH_SZ) {
            return WS_PARSE_E;
        }
        innerSigSz = AppendBlob(innerSig, sizeof(innerSig), innerSigSz,
                sigName, sigNameSz);
        /* Signature data value bytes start after their length prefix. */
        dataStart = innerSigSz + LENGTH_SZ;
        innerSigSz = AppendBlob(innerSig, sizeof(innerSig), innerSigSz,
                sigData, sigDataSz);

        if (sigNameSz == sizeof("ssh-ed25519") - 1
                && WMEMCMP(sigName, "ssh-ed25519", sigNameSz) == 0) {
            /* Raw R || S: flip a byte of S so the verify rejects it. */
            flipIdx = dataStart + sigDataSz / 2;
        }
        else {
            /* RSA raw signature or ECC mpint r: flip an interior data byte. */
            flipIdx = dataStart + LENGTH_SZ;
        }
        innerSig[flipIdx] ^= 0xFF;
    }
    else if (mode == REGRESS_MUTATE_SIG_NAME_OVERRUN) {
        /* Nothing but a name length prefix, so the name it claims runs off
         * the end of the blob. */
        innerSigSz = AppendUint32(innerSig, sizeof(innerSig), innerSigSz,
                sigNameSz);
    }
    else if (mode == REGRESS_MUTATE_F_TRUNC) {
        /* Signature blob is copied through untouched; only f shrinks below. */
        if (fSz == 0) {
            return WS_PARSE_E;
        }
        fSz--;
        innerSigSz = AppendBlob(innerSig, sizeof(innerSig), innerSigSz,
                sigName, sigNameSz);
        innerSigSz = AppendBlob(innerSig, sizeof(innerSig), innerSigSz,
                sigData, sigDataSz);
    }
    else {
        innerSigSz = AppendString(innerSig, sizeof(innerSig), innerSigSz,
                replacement);
        innerSigSz = AppendBlob(innerSig, sizeof(innerSig), innerSigSz,
                sigData, sigDataSz);
    }

    outerIdx = 0;
    outerIdx = AppendBlob(payloadBuf, sizeof(payloadBuf), outerIdx,
            pubKey, pubKeySz);
    outerIdx = AppendBlob(payloadBuf, sizeof(payloadBuf), outerIdx, f, fSz);
    outerIdx = AppendBlob(payloadBuf, sizeof(payloadBuf), outerIdx,
            innerSig, innerSigSz);
    *outLen = WrapPacket(MSGID_KEXDH_REPLY, payloadBuf, outerIdx, out, outSz);

    return 1;
}

static int RewriteKexDhReplyPacket(const byte* packet, word32 packetSz,
        byte mode, const char* replacement, byte* out, word32 outSz,
        word32* outLen)
{
    word32 offset = 0;

    if (packet == NULL || out == NULL || outLen == NULL) {
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
                    curPacketSz, mode, replacement, out, outSz, outLen);
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

/* Drop one byte from the peer public key string e of a KEXDH_INIT. */
static int RewriteSingleKexDhInitPacket(const byte* packet, word32 packetSz,
        byte mode, byte* out, word32 outSz, word32* outLen)
{
    const byte* payload;
    const byte* e;
    word32 payloadSz;
    word32 eSz;
    word32 idx = 0;
    word32 outerIdx = 0;
    int ret;
    byte payloadBuf[REGRESS_MUTATION_SCRATCH_SZ];

    if (out == NULL || outLen == NULL) {
        return WS_BAD_ARGUMENT;
    }

    ret = LocateSinglePacketPayload(packet, packetSz, MSGID_KEXDH_INIT,
            &payload, &payloadSz);
    if (ret != 1) {
        return ret;
    }

    if (ReadStringRef(&eSz, &e, payload, payloadSz, &idx) != WS_SUCCESS) {
        return WS_PARSE_E;
    }
    if (eSz == 0) {
        return WS_PARSE_E;
    }

    /* E_EMPTY keeps the framing valid but leaves e zero length, which is what
     * DoKexDhInit's range check rejects. E_TRUNC drops one byte instead. */
    if (mode == REGRESS_MUTATE_E_EMPTY) {
        outerIdx = AppendBlob(payloadBuf, sizeof(payloadBuf), outerIdx, e, 0);
    }
    else {
        outerIdx = AppendBlob(payloadBuf, sizeof(payloadBuf), outerIdx, e,
                eSz - 1);
    }
    *outLen = WrapPacket(MSGID_KEXDH_INIT, payloadBuf, outerIdx, out, outSz);

    return 1;
}

#ifdef REGRESS_GEX_KEX_ALGO
/* Rewrite a KEXDH_GEX_GROUP: SHRINK puts the prime under the client's
 * requested floor, GEN_BAD drops the generator below 2. */
static int RewriteSingleKexDhGexGroupPacket(const byte* packet,
        word32 packetSz, byte mode, byte* out, word32 outSz, word32* outLen)
{
    const byte* payload;
    const byte* primeGroup;
    const byte* generator;
    word32 payloadSz;
    word32 primeGroupSz, generatorSz;
    word32 idx = 0;
    word32 outerIdx = 0;
    int ret;
    byte badGenerator = 1;
    byte payloadBuf[REGRESS_MUTATION_SCRATCH_SZ];

    if (out == NULL || outLen == NULL) {
        return WS_BAD_ARGUMENT;
    }

    ret = LocateSinglePacketPayload(packet, packetSz, MSGID_KEXDH_GEX_GROUP,
            &payload, &payloadSz);
    if (ret != 1) {
        return ret;
    }

    if (ReadStringRef(&primeGroupSz, &primeGroup, payload, payloadSz, &idx)
            != WS_SUCCESS) {
        return WS_PARSE_E;
    }
    if (ReadStringRef(&generatorSz, &generator, payload, payloadSz, &idx)
            != WS_SUCCESS) {
        return WS_PARSE_E;
    }

    if (mode == REGRESS_MUTATE_GEX_GROUP_SHRINK) {
        /* A group already at the target size would leave the test asserting
         * nothing, so fail loudly rather than pass the group through. */
        if (primeGroupSz <= REGRESS_GEX_SHRUNK_PRIME_SZ) {
            return WS_PARSE_E;
        }
        primeGroupSz = REGRESS_GEX_SHRUNK_PRIME_SZ;
    }
    else {
        /* Leave the prime valid so the range check passes and the generator
         * check is what rejects the group. */
        generator = &badGenerator;
        generatorSz = 1;
    }

    outerIdx = AppendBlob(payloadBuf, sizeof(payloadBuf), outerIdx,
            primeGroup, primeGroupSz);
    outerIdx = AppendBlob(payloadBuf, sizeof(payloadBuf), outerIdx,
            generator, generatorSz);
    *outLen = WrapPacket(MSGID_KEXDH_GEX_GROUP, payloadBuf, outerIdx,
            out, outSz);

    return 1;
}
#endif /* REGRESS_GEX_KEX_ALGO */

/* SIG_*, F_TRUNC and the GEX_* modes rewrite the server's messages;
 * E_TRUNC and E_EMPTY the client's init. */
static int MutatorTargetsEndpoint(byte mode, byte isServer)
{
    if (mode == REGRESS_MUTATE_E_TRUNC || mode == REGRESS_MUTATE_E_EMPTY) {
        return !isServer;
    }
    return isServer != 0;
}

/* Record a plaintext DISCONNECT leaving this endpoint. KEX-time traffic is
 * unencrypted, so the reason code is readable straight off the wire. */
static void NoteOutboundDisconnect(DuplexEndpoint* endpoint,
        const byte* packet, word32 packetSz)
{
    word32 offset = 0;
    word32 packetLen;
    word32 padLen;

    while (packetSz - offset >= UINT32_SZ + PAD_LENGTH_SZ + MSG_ID_SZ) {
        word32 curPacketSz = ReadUint32(packet + offset) + UINT32_SZ;

        /* Valid framing carries a pad length, a message id and the minimum
         * padding, so a shorter declared packet cannot hold the id read
         * below. */
        if (curPacketSz > packetSz - offset ||
                curPacketSz < UINT32_SZ + PAD_LENGTH_SZ + MSG_ID_SZ +
                        MIN_PAD_LENGTH) {
            return;
        }

        /* The reason code lives in the payload, so bound it against the
         * payload rather than the buffer: padding is not readable content. */
        packetLen = curPacketSz - UINT32_SZ;
        padLen = packet[offset + UINT32_SZ];
        if (packet[offset + UINT32_SZ + PAD_LENGTH_SZ] == MSGID_DISCONNECT &&
                packetLen >= padLen + PAD_LENGTH_SZ + MSG_ID_SZ + UINT32_SZ) {
            endpoint->sawDisconnect = 1;
            endpoint->disconnectReason = ReadUint32(packet + offset +
                    UINT32_SZ + PAD_LENGTH_SZ + MSG_ID_SZ);
            return;
        }

        offset += curPacketSz;
    }
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

    if (endpoint == NULL || endpoint->peer == NULL || buf == NULL) {
        return WS_CBIO_ERR_GENERAL;
    }

    if (endpoint->mutator != NULL &&
            endpoint->mutator->enabled &&
            MutatorTargetsEndpoint(endpoint->mutator->mode,
                    endpoint->isServer) &&
            endpoint->mutator->mutatedPackets == 0 &&
            outputSz >= UINT32_SZ + PAD_LENGTH_SZ + MSG_ID_SZ &&
            !(outputSz >= REGRESS_SSH_PROTO_PREFIX_SZ &&
              WMEMCMP(output, REGRESS_SSH_PROTO_PREFIX,
                      REGRESS_SSH_PROTO_PREFIX_SZ) == 0)) {
        word32 mutatedSz = 0;
        int mutateRet;

        if (endpoint->mutator->mode == REGRESS_MUTATE_E_TRUNC ||
                endpoint->mutator->mode == REGRESS_MUTATE_E_EMPTY) {
            /* KEXDH_INIT is never bundled, so no packet scan is needed. */
            mutateRet = RewriteSingleKexDhInitPacket(output, outputSz,
                    endpoint->mutator->mode, endpoint->mutator->scratch,
                    (word32)sizeof(endpoint->mutator->scratch), &mutatedSz);
        }
#ifdef REGRESS_GEX_KEX_ALGO
        else if (endpoint->mutator->mode == REGRESS_MUTATE_GEX_GROUP_SHRINK ||
                endpoint->mutator->mode == REGRESS_MUTATE_GEX_GEN_BAD) {
            /* GEX_GROUP answers a request of its own, so it is not bundled. */
            mutateRet = RewriteSingleKexDhGexGroupPacket(output, outputSz,
                    endpoint->mutator->mode, endpoint->mutator->scratch,
                    (word32)sizeof(endpoint->mutator->scratch), &mutatedSz);
        }
#endif
        else {
            mutateRet = RewriteKexDhReplyPacket(output, outputSz,
                    endpoint->mutator->mode, endpoint->mutator->replaceName,
                    endpoint->mutator->scratch,
                    (word32)sizeof(endpoint->mutator->scratch), &mutatedSz);
        }
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

    /* Only scan plaintext records. AEAD modes send the packet length as
     * cleartext AAD, so an encrypted payload byte can look like a message
     * id and trip the sniffer. Every disconnect under test predates NEWKEYS. */
    if (ssh != NULL && ssh->encryptId == ID_NONE &&
            !(outputSz >= REGRESS_SSH_PROTO_PREFIX_SZ &&
              WMEMCMP(output, REGRESS_SSH_PROTO_PREFIX,
                      REGRESS_SSH_PROTO_PREFIX_SZ) == 0)) {
        NoteOutboundDisconnect(endpoint, output, outputSz);
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
    client->mutator = mutator;
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

static void InitKexReplyHarnessKex(KexReplyHarness* harness,
        const char* kexAlgo, const char* keyAlgo, const char* keyPath,
        byte mutateReply, byte mutateMode, const char* replaceName,
        byte skipPublicKeyCheck)
{
    byte keyBuf[2048];
    word32 keySz;

    if (kexAlgo == NULL) {
        kexAlgo = KEXDH_REPLY_REGRESS_KEX_ALGO;
    }

    WMEMSET(harness, 0, sizeof(*harness));

    InitDuplexPair(&harness->clientIo, &harness->serverIo, &harness->mutator);
    harness->mutator.enabled = mutateReply;
    harness->mutator.mode = mutateMode;
    harness->mutator.replaceName = replaceName;

    harness->clientCtx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_CLIENT, NULL);
    AssertNotNull(harness->clientCtx);
    harness->serverCtx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_SERVER, NULL);
    AssertNotNull(harness->serverCtx);

    AssertIntEQ(wolfSSH_CTX_SetAlgoListKex(harness->clientCtx, kexAlgo),
            WS_SUCCESS);
    AssertIntEQ(wolfSSH_CTX_SetAlgoListKex(harness->serverCtx, kexAlgo),
            WS_SUCCESS);
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

    keySz = LoadFileBuffer(keyPath, keyBuf, sizeof(keyBuf));
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

static void InitKexReplyHarnessEx(KexReplyHarness* harness,
        const char* keyAlgo, const char* keyPath, byte mutateReply,
        byte mutateMode, const char* replaceName, byte skipPublicKeyCheck)
{
    InitKexReplyHarnessKex(harness, NULL, keyAlgo, keyPath, mutateReply,
            mutateMode, replaceName, skipPublicKeyCheck);
}

static void InitKexReplyHarness(KexReplyHarness* harness,
        const char* keyAlgo, const char* keyPath, byte mutateReply,
        const char* replaceName)
{
    InitKexReplyHarnessEx(harness, keyAlgo, keyPath,
            mutateReply, REGRESS_MUTATE_SIG_NAME, replaceName, 0);
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

static void AssertHandshakeSucceeds(const char* keyAlgo, const char* keyPath)
{
    KexReplyHarness harness;
    KexReplyRunResult result;

    InitKexReplyHarnessEx(&harness, keyAlgo, keyPath, 0,
            REGRESS_MUTATE_SIG_NAME, NULL, 0);
    RunKexReplyHandshake(&harness, &result);

    AssertTrue(result.clientSuccess);
    AssertTrue(result.serverSuccess);
    AssertIntEQ(harness.mutator.mutatedPackets, 0);
    AssertIntEQ(harness.client->connectState, CONNECT_SERVER_CHANNEL_REQUEST_DONE);
    AssertIntEQ(harness.server->acceptState, ACCEPT_CLIENT_SESSION_ESTABLISHED);
    /* A clean handshake sends no disconnect, so the sniffer the rejection
     * tests rely on is proven not to fire on its own. */
    AssertFalse(harness.clientIo.sawDisconnect);
    AssertFalse(harness.serverIo.sawDisconnect);

    FreeKexReplyHarness(&harness);
}

static void AssertHandshakeRejectsMutatedReply(const char* keyAlgo,
        const char* keyPath, const char* replaceName, int expectedErr)
{
    KexReplyHarness harness;
    KexReplyRunResult result;

    InitKexReplyHarness(&harness, keyAlgo, keyPath, 1, replaceName);
    RunKexReplyHandshake(&harness, &result);

    AssertIntEQ(harness.mutator.parseError, 0);
    AssertIntEQ(harness.mutator.matchedPackets, 1);
    AssertIntEQ(harness.mutator.mutatedPackets, 1);
    AssertFalse(result.clientSuccess);
    AssertFalse(harness.client->connectState >= CONNECT_KEYED);
    AssertTrue(result.clientRet == WS_FATAL_ERROR);
    AssertTrue(result.clientErr != WS_WANT_READ && result.clientErr != WS_WANT_WRITE);
    AssertIntEQ(result.clientErr, expectedErr);

    FreeKexReplyHarness(&harness);
}

#ifndef WOLFSSH_NO_RSA_SHA2_256
static void TestKexDhReplyRejectsRsaSha2_256SigNameDowngrade(void)
{
    AssertHandshakeSucceeds("rsa-sha2-256", REGRESS_SERVER_KEY_PATH);
    /* Same-length wrong name reaches the WMEMCMP, not just the length check. */
    AssertHandshakeRejectsMutatedReply("rsa-sha2-256", REGRESS_SERVER_KEY_PATH,
            "rsa-sha2-512", WS_PARSE_E);
}
#endif

#ifndef WOLFSSH_NO_RSA_SHA2_512
static void TestKexDhReplyRejectsRsaSha2_512SigNameDowngrade(void)
{
    AssertHandshakeSucceeds("rsa-sha2-512", REGRESS_SERVER_KEY_PATH);
    AssertHandshakeRejectsMutatedReply("rsa-sha2-512", REGRESS_SERVER_KEY_PATH,
            "rsa-sha2-256", WS_PARSE_E);
}
#endif

#ifndef WOLFSSH_NO_ECDSA_SHA2_NISTP256
static void TestKexDhReplyRejectsEccSigNameDowngrade(void)
{
    AssertHandshakeSucceeds("ecdsa-sha2-nistp256", REGRESS_SERVER_KEY_ECC_PATH);
    AssertHandshakeRejectsMutatedReply("ecdsa-sha2-nistp256",
            REGRESS_SERVER_KEY_ECC_PATH, "ecdsa-sha2-nistp384", WS_PARSE_E);
}
#endif

#ifndef WOLFSSH_NO_ED25519
static void TestKexDhReplyRejectsEd25519SigNameDowngrade(void)
{
    AssertHandshakeSucceeds("ssh-ed25519", REGRESS_SERVER_KEY_ED25519_PATH);
    /* No same-length sibling; "ssh-rsa" hits the length-check branch. */
    AssertHandshakeRejectsMutatedReply("ssh-ed25519",
            REGRESS_SERVER_KEY_ED25519_PATH, "ssh-rsa", WS_PARSE_E);
}
#endif

static void AssertHandshakeRejectsWithNoPublicKeyCheck(const char* keyAlgo,
        const char* keyPath)
{
    KexReplyHarness harness;
    KexReplyRunResult result;

    InitKexReplyHarnessEx(&harness, keyAlgo, keyPath, 0,
            REGRESS_MUTATE_SIG_NAME, NULL, 1 /* skipPublicKeyCheck */);
    RunKexReplyHandshake(&harness, &result);

    AssertFalse(result.clientSuccess);
    AssertTrue(result.clientRet == WS_FATAL_ERROR);
    AssertTrue(result.clientErr != WS_WANT_READ && result.clientErr != WS_WANT_WRITE);
    AssertIntEQ(result.clientErr, WS_PUBKEY_REJECTED_E);
    AssertFalse(harness.client->connectState >= CONNECT_KEYED);
    AssertTrue(harness.clientIo.sawDisconnect);
    AssertIntEQ(harness.clientIo.disconnectReason,
            WOLFSSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE);

    FreeKexReplyHarness(&harness);
}

static void TestKexDhReplyRejectsNoPublicKeyCheck(void)
{
    AssertHandshakeRejectsWithNoPublicKeyCheck(REGRESS_DEFAULT_KEY_ALGO,
            REGRESS_DEFAULT_KEY_PATH);
#if !defined(WOLFSSH_NO_RSA_SHA2_256) && !defined(WOLFSSH_NO_RSA_SHA2_512)
    AssertHandshakeRejectsWithNoPublicKeyCheck("rsa-sha2-512",
            REGRESS_SERVER_KEY_PATH);
#endif
}

static void AssertHandshakeRejectsWhenCallbackRejects(const char* keyAlgo,
        const char* keyPath)
{
    KexReplyHarness harness;
    KexReplyRunResult result;

    InitKexReplyHarness(&harness, keyAlgo, keyPath, 0, NULL);
    wolfSSH_CTX_SetPublicKeyCheck(harness.clientCtx, RejectAnyServerHostKey);
    RunKexReplyHandshake(&harness, &result);

    AssertFalse(result.clientSuccess);
    AssertTrue(result.clientRet == WS_FATAL_ERROR);
    AssertTrue(result.clientErr != WS_WANT_READ && result.clientErr != WS_WANT_WRITE);
    AssertIntEQ(result.clientErr, WS_PUBKEY_REJECTED_E);
    AssertFalse(harness.client->connectState >= CONNECT_KEYED);
    AssertTrue(harness.clientIo.sawDisconnect);
    AssertIntEQ(harness.clientIo.disconnectReason,
            WOLFSSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE);

    FreeKexReplyHarness(&harness);
}

static void TestKexDhReplyRejectsWhenCallbackRejects(void)
{
    AssertHandshakeRejectsWhenCallbackRejects(REGRESS_DEFAULT_KEY_ALGO,
            REGRESS_DEFAULT_KEY_PATH);
#if !defined(WOLFSSH_NO_RSA_SHA2_256) && !defined(WOLFSSH_NO_RSA_SHA2_512)
    AssertHandshakeRejectsWhenCallbackRejects("rsa-sha2-512",
            REGRESS_SERVER_KEY_PATH);
#endif
}

/* Valid name, flipped data byte: the client reaches the verify and rejects. */
static void AssertHandshakeRejectsCorruptedSig(const char* keyAlgo,
        const char* keyPath, int expectedErr)
{
    KexReplyHarness harness;
    KexReplyRunResult result;

    InitKexReplyHarnessEx(&harness, keyAlgo, keyPath, 1,
            REGRESS_MUTATE_SIG_DATA, NULL, 0);
    RunKexReplyHandshake(&harness, &result);

    AssertIntEQ(harness.mutator.parseError, 0);
    AssertIntEQ(harness.mutator.matchedPackets, 1);
    AssertIntEQ(harness.mutator.mutatedPackets, 1);
    AssertFalse(result.clientSuccess);
    AssertFalse(harness.client->connectState >= CONNECT_KEYED);
    AssertTrue(result.clientRet == WS_FATAL_ERROR);
    AssertTrue(result.clientErr != WS_WANT_READ &&
            result.clientErr != WS_WANT_WRITE);
    AssertIntEQ(result.clientErr, expectedErr);

    FreeKexReplyHarness(&harness);
}

#ifndef WOLFSSH_NO_RSA_SHA2_256
static void TestKexDhReplyRejectsRsaSha2_256CorruptSig(void)
{
    AssertHandshakeRejectsCorruptedSig("rsa-sha2-256",
            REGRESS_SERVER_KEY_PATH, WS_RSA_E);
}
#endif

#ifndef WOLFSSH_NO_RSA_SHA2_512
static void TestKexDhReplyRejectsRsaSha2_512CorruptSig(void)
{
    AssertHandshakeRejectsCorruptedSig("rsa-sha2-512",
            REGRESS_SERVER_KEY_PATH, WS_RSA_E);
}
#endif

#ifndef WOLFSSH_NO_ECDSA_SHA2_NISTP256
/* The flip preserves r's mpint length, so the verify fails with WS_ECC_E. */
static void TestKexDhReplyRejectsEccCorruptSig(void)
{
    AssertHandshakeRejectsCorruptedSig("ecdsa-sha2-nistp256",
            REGRESS_SERVER_KEY_ECC_PATH, WS_ECC_E);
}
#endif

#ifndef WOLFSSH_NO_ED25519
static void TestKexDhReplyRejectsEd25519CorruptSig(void)
{
    AssertHandshakeRejectsCorruptedSig("ssh-ed25519",
            REGRESS_SERVER_KEY_ED25519_PATH, WS_ED25519_E);
}
#endif

/* A signature blob holding only a name length prefix. The bounded read
 * rejects it before the name is compared, whatever the host key type. */
static void TestKexDhReplyRejectsSigNameOverrun(void)
{
    KexReplyHarness harness;
    KexReplyRunResult result;

    InitKexReplyHarnessEx(&harness, REGRESS_DEFAULT_KEY_ALGO,
            REGRESS_DEFAULT_KEY_PATH, 1,
            REGRESS_MUTATE_SIG_NAME_OVERRUN, NULL, 0);
    RunKexReplyHandshake(&harness, &result);

    AssertIntEQ(harness.mutator.parseError, 0);
    AssertIntEQ(harness.mutator.matchedPackets, 1);
    AssertIntEQ(harness.mutator.mutatedPackets, 1);
    AssertFalse(result.clientSuccess);
    AssertFalse(harness.client->connectState >= CONNECT_KEYED);
    AssertTrue(result.clientRet == WS_FATAL_ERROR);
    AssertIntEQ(result.clientErr, WS_BUFFER_E);

    FreeKexReplyHarness(&harness);
}

#ifdef REGRESS_TRUNC_KEX_ALGO
/* RFC 8731 sec. 3: a peer public key of the wrong length aborts with a
 * disconnect. The truncated key is rejected during key agreement, before
 * signature verification. */
static void TestKexDhReplyTruncatedFSendsDisconnect(void)
{
    KexReplyHarness harness;
    KexReplyRunResult result;

    InitKexReplyHarnessKex(&harness, REGRESS_TRUNC_KEX_ALGO,
            REGRESS_DEFAULT_KEY_ALGO, REGRESS_DEFAULT_KEY_PATH, 1,
            REGRESS_MUTATE_F_TRUNC, NULL, 0);
    RunKexReplyHandshake(&harness, &result);

    AssertIntEQ(harness.mutator.parseError, 0);
    AssertIntEQ(harness.mutator.mutatedPackets, 1);
    AssertFalse(result.clientSuccess);
    AssertFalse(harness.client->connectState >= CONNECT_KEYED);
    AssertTrue(result.clientRet == WS_FATAL_ERROR);
    AssertIntEQ(result.clientErr, WS_CRYPTO_FAILED);
    AssertTrue(harness.clientIo.sawDisconnect);
    AssertIntEQ(harness.clientIo.disconnectReason,
            WOLFSSH_DISCONNECT_KEY_EXCHANGE_FAILED);

    FreeKexReplyHarness(&harness);
}

static void TestKexDhInitTruncatedESendsDisconnect(void)
{
    KexReplyHarness harness;
    KexReplyRunResult result;

    InitKexReplyHarnessKex(&harness, REGRESS_TRUNC_KEX_ALGO,
            REGRESS_DEFAULT_KEY_ALGO, REGRESS_DEFAULT_KEY_PATH, 1,
            REGRESS_MUTATE_E_TRUNC, NULL, 0);
    RunKexReplyHandshake(&harness, &result);

    AssertIntEQ(harness.mutator.parseError, 0);
    AssertIntEQ(harness.mutator.mutatedPackets, 1);
    AssertFalse(result.serverSuccess);
    AssertTrue(result.serverRet == WS_FATAL_ERROR);
    AssertIntEQ(result.serverErr, WS_CRYPTO_FAILED);
    AssertTrue(harness.serverIo.sawDisconnect);
    AssertIntEQ(harness.serverIo.disconnectReason,
            WOLFSSH_DISCONNECT_KEY_EXCHANGE_FAILED);

    FreeKexReplyHarness(&harness);
}
/* Covers the WS_PUBKEY_REJECTED_E arm of the server's disconnect guard, which
 * the truncated-e case cannot reach. */
static void TestKexDhInitEmptyESendsDisconnect(void)
{
    KexReplyHarness harness;
    KexReplyRunResult result;

    InitKexReplyHarnessKex(&harness, REGRESS_TRUNC_KEX_ALGO,
            REGRESS_DEFAULT_KEY_ALGO, REGRESS_DEFAULT_KEY_PATH, 1,
            REGRESS_MUTATE_E_EMPTY, NULL, 0);
    RunKexReplyHandshake(&harness, &result);

    AssertIntEQ(harness.mutator.parseError, 0);
    AssertIntEQ(harness.mutator.mutatedPackets, 1);
    AssertFalse(result.serverSuccess);
    AssertIntEQ(result.serverErr, WS_PUBKEY_REJECTED_E);
    AssertTrue(harness.serverIo.sawDisconnect);
    AssertIntEQ(harness.serverIo.disconnectReason,
            WOLFSSH_DISCONNECT_KEY_EXCHANGE_FAILED);

    FreeKexReplyHarness(&harness);
}
#endif /* REGRESS_TRUNC_KEX_ALGO */

#ifdef REGRESS_GEX_KEX_ALGO
/* A GEX group below the floor this client enforces (RFC 8270) ends the key
 * exchange. Covers the WS_DH_SIZE_E arm of the client's guard, which no
 * other mutator reaches. */
static void TestKexDhGexGroupShrunkPrimeSendsDisconnect(void)
{
    KexReplyHarness harness;
    KexReplyRunResult result;

    InitKexReplyHarnessKex(&harness, REGRESS_GEX_KEX_ALGO,
            REGRESS_DEFAULT_KEY_ALGO, REGRESS_DEFAULT_KEY_PATH, 1,
            REGRESS_MUTATE_GEX_GROUP_SHRINK, NULL, 0);
    RunKexReplyHandshake(&harness, &result);

    AssertIntEQ(harness.mutator.parseError, 0);
    AssertIntEQ(harness.mutator.mutatedPackets, 1);
    AssertFalse(result.clientSuccess);
    AssertFalse(harness.client->connectState >= CONNECT_KEYED);
    AssertTrue(result.clientRet == WS_FATAL_ERROR);
    AssertIntEQ(result.clientErr, WS_DH_SIZE_E);
    AssertTrue(harness.clientIo.sawDisconnect);
    AssertIntEQ(harness.clientIo.disconnectReason,
            WOLFSSH_DISCONNECT_KEY_EXCHANGE_FAILED);

    FreeKexReplyHarness(&harness);
}

/* Covers the WS_CRYPTO_FAILED arm of the client's GEX guard, which the
 * shrunk-prime case cannot reach. */
static void TestKexDhGexGroupBadGeneratorSendsDisconnect(void)
{
    KexReplyHarness harness;
    KexReplyRunResult result;

    InitKexReplyHarnessKex(&harness, REGRESS_GEX_KEX_ALGO,
            REGRESS_DEFAULT_KEY_ALGO, REGRESS_DEFAULT_KEY_PATH, 1,
            REGRESS_MUTATE_GEX_GEN_BAD, NULL, 0);
    RunKexReplyHandshake(&harness, &result);

    AssertIntEQ(harness.mutator.parseError, 0);
    AssertIntEQ(harness.mutator.mutatedPackets, 1);
    AssertFalse(result.clientSuccess);
    AssertFalse(harness.client->connectState >= CONNECT_KEYED);
    AssertTrue(result.clientRet == WS_FATAL_ERROR);
    AssertIntEQ(result.clientErr, WS_CRYPTO_FAILED);
    AssertTrue(harness.clientIo.sawDisconnect);
    AssertIntEQ(harness.clientIo.disconnectReason,
            WOLFSSH_DISCONNECT_KEY_EXCHANGE_FAILED);

    FreeKexReplyHarness(&harness);
}
#endif /* REGRESS_GEX_KEX_ALGO */

#endif /* KEXDH_REPLY_REGRESS_KEX_ALGO */

/* Shared with the client-side forwarding tests below. */
static WS_MAYBE_UNUSED word32 ParseChannelOpenFailReason(const byte* pkt,
        word32 sz)
{
    word32 reason;
    /* SSH binary-packet layout: 4 (len) + 1 (pad_len) + 1 (msg_id) + 4 (chan) = 10;
     * + 4 for the reason field itself gives the 14-byte minimum. */
    AssertTrue(sz >= 14);
    AssertIntEQ(pkt[5], MSGID_CHANNEL_OPEN_FAIL);
    WMEMCPY(&reason, pkt + 10, sizeof(reason));
    return ntohl(reason);
}

static WS_MAYBE_UNUSED void AssertChannelOpenFailResponse(
        const ChannelOpenHarness* harness, int ret)
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
/* The port a peer picks for a port-0 forward in these tests. */
#define REGRESS_FWD_ALLOC_PORT 49152

static WS_MAYBE_UNUSED int AcceptFwdCb(WS_FwdCbAction action, void* ctx,
        const char* host, word32 port)
{
    (void)action;
    (void)ctx;
    (void)host;
    (void)port;

    return WS_SUCCESS;
}
#endif /* WOLFSSH_FWD */

#ifndef NO_WOLFSSH_SERVER

static word32 ParseChannelOpenFailRecipient(const byte* pkt, word32 sz)
{
    word32 chan;
    /* SSH binary-packet layout: 4 (len) + 1 (pad_len) + 1 (msg_id) = 6;
     * + 4 for the recipient_channel field itself gives the 10-byte minimum. */
    AssertTrue(sz >= 10);
    AssertIntEQ(pkt[5], MSGID_CHANNEL_OPEN_FAIL);
    WMEMCPY(&chan, pkt + 6, sizeof(chan));
    return ntohl(chan);
}

#ifdef WOLFSSH_FWD
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

static word32 ParseGlobalRequestSuccessPort(const byte* packet, word32 packetSz)
{
    word32 port;

    AssertNotNull(packet);
    AssertTrue(packetSz >= 10);
    AssertIntEQ(packet[5], MSGID_REQUEST_SUCCESS);
    WMEMCPY(&port, packet + 6, sizeof(port));

    return ntohl(port);
}
#endif

static int RejectChannelOpenCb(WOLFSSH_CHANNEL* channel, void* ctx)
{
    (void)channel;
    (void)ctx;

    return WS_BAD_ARGUMENT;
}

#ifdef WOLFSSH_FWD
static int AcceptChannelOpenCb(WOLFSSH_CHANNEL* channel, void* ctx)
{
    (void)channel;
    (void)ctx;

    return WS_SUCCESS;
}

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

/* Counts every action the library asks for. File scope rather than reached
 * through the callback ctx, so a zero reading means the hook did not run and
 * cannot instead mean the ctx stopped being delivered. */
static word32 fwdCbCallCount;

static int CountingFwdCb(WS_FwdCbAction action, void* ctx,
        const char* host, word32 port)
{
    (void)action;
    (void)ctx;
    (void)host;
    (void)port;

    fwdCbCallCount++;

    return WS_SUCCESS;
}

/* Counts, and rejects the channel-id handoff that follows a successful
 * LOCAL_SETUP -- the second of DoChannelOpen()'s two fwdCb consultations. */
static int CountingRejectChannelIdFwdCb(WS_FwdCbAction action, void* ctx,
        const char* host, word32 port)
{
    (void)ctx;
    (void)host;
    (void)port;

    fwdCbCallCount++;

    if (action == WOLFSSH_FWD_CHANNEL_ID)
        return WS_FWD_NOT_AVAILABLE;

    return WS_SUCCESS;
}

static int AllocatePortFwdCb(WS_FwdCbAction action, void* ctx,
        const char* host, word32 port)
{
    (void)ctx;
    (void)host;

    /* A return at or above WS_FWD_PORT_CHECK reports the allocated port for a
     * port-0 request; WS_FWD_SUCCESS (0) otherwise. */
    if (action == WOLFSSH_FWD_REMOTE_SETUP && port == 0)
        return REGRESS_FWD_ALLOC_PORT;

    return WS_SUCCESS;
}

/* Accepts the remote setup but never reports an allocated port. Records
 * whether the server asks it to clean the setup back up. */
static int NoPortFwdCb(WS_FwdCbAction action, void* ctx,
        const char* host, word32 port)
{
    int* cleanupCalled = (int*)ctx;
    (void)host;
    (void)port;

    if (action == WOLFSSH_FWD_REMOTE_CLEANUP && cleanupCalled != NULL)
        *cleanupCalled = 1;

    return WS_SUCCESS;
}

/* Rejects the remote setup with a WS_FwdCbError status. The server must send a
 * failure and must NOT ask for cleanup, since the setup never succeeded. */
static int RejectRemoteSetupFwdCb(WS_FwdCbAction action, void* ctx,
        const char* host, word32 port)
{
    int* cleanupCalled = (int*)ctx;
    (void)host;
    (void)port;

    if (action == WOLFSSH_FWD_REMOTE_SETUP)
        return WS_FWD_SETUP_E;
    if (action == WOLFSSH_FWD_REMOTE_CLEANUP && cleanupCalled != NULL)
        *cleanupCalled = 1;

    return WS_SUCCESS;
}
#endif


#endif /* NO_WOLFSSH_SERVER */

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


/* Reject connection-protocol messages in every state before user
 * authentication completes, keying or not. */
static void TestChannelBlockedEveryPreAuthState(WOLFSSH* ssh)
{
    static const byte connMsgs[] = {
        MSGID_GLOBAL_REQUEST, MSGID_CHANNEL_OPEN, MSGID_CHANNEL_DATA,
        MSGID_CHANNEL_REQUEST, MSGIDLIMIT_CONN_MAX
    };
    int state;
    word32 i;
    byte keying;

    for (keying = 0; keying <= 1; keying++) {
        for (state = CONNECT_BEGIN;
                state < CONNECT_SERVER_USERAUTH_ACCEPT_DONE; state++) {
            for (i = 0; i < sizeof(connMsgs)/sizeof(*connMsgs); i++) {
                int allowed;

                ResetSession(ssh);
                ssh->isKeying = keying ? WOLFSSH_PEER_IS_KEYING : 0;
                ssh->connectState = (byte)state;

                allowed = wolfSSH_TestIsMessageAllowed(ssh, connMsgs[i],
                        WS_MSG_RECV);
                AssertFalse(allowed);
                AssertIntEQ(ssh->error, WS_MSGID_NOT_ALLOWED_E);
            }
        }
    }
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


/* Reject the key exchange messages that only the client sends. */
static void TestClientOnlyKexMsgsBlocked(WOLFSSH* ssh)
{
    int allowed;

    ResetSession(ssh);
    /* Our KEXINIT is out, the server's group has not arrived. */
    ssh->connectState = CONNECT_CLIENT_KEXINIT_SENT;
    ssh->isKeying = WOLFSSH_PEER_IS_KEYING;
    ssh->handshake = AllocHandshake(ssh);
    ssh->handshake->kexId = ID_DH_GEX_SHA256;

    allowed = wolfSSH_TestIsMessageAllowed(ssh, MSGID_KEXDH_INIT,
            WS_MSG_RECV);
    AssertFalse(allowed);
    AssertIntEQ(ssh->error, WS_MSGID_NOT_ALLOWED_E);

    ssh->error = 0;
    allowed = wolfSSH_TestIsMessageAllowed(ssh, MSGID_KEXDH_GEX_INIT,
            WS_MSG_RECV);
    AssertFalse(allowed);
    AssertIntEQ(ssh->error, WS_MSGID_NOT_ALLOWED_E);

    ssh->error = 0;
    allowed = wolfSSH_TestIsMessageAllowed(ssh, MSGID_KEXDH_GEX_REQUEST,
            WS_MSG_RECV);
    AssertFalse(allowed);
    AssertIntEQ(ssh->error, WS_MSGID_NOT_ALLOWED_E);

    /* 31 is the server's answer to a group request, so it stays allowed
     * where the client expects it. */
    ssh->error = 0;
    ssh->handshake->expectMsgId = MSGID_KEXDH_GEX_GROUP;
    allowed = wolfSSH_TestIsMessageAllowed(ssh, MSGID_KEXDH_GEX_GROUP,
            WS_MSG_RECV);
    AssertTrue(allowed);
    AssertIntEQ(ssh->handshake->expectMsgId, MSGID_NONE);

    /* Same answer during a rekey on an established session. */
    ssh->error = 0;
    ssh->connectState = CONNECT_DONE;

    allowed = wolfSSH_TestIsMessageAllowed(ssh, MSGID_KEXDH_GEX_REQUEST,
            WS_MSG_RECV);
    AssertFalse(allowed);
    AssertIntEQ(ssh->error, WS_MSGID_NOT_ALLOWED_E);
}


/* A service accept is allowed only when no key exchange is in flight.
 * connectState does not see a rekey, so isKeying is checked too. */
static void TestClientServiceAcceptBlockedDuringKeying(WOLFSSH* ssh)
{
    int allowed;

    ResetSession(ssh);
    ssh->connectState = CONNECT_CLIENT_USERAUTH_REQUEST_SENT;

    allowed = wolfSSH_TestIsMessageAllowed(ssh, MSGID_SERVICE_ACCEPT,
            WS_MSG_RECV);
    AssertTrue(allowed);

    /* Same connectState, peer's rekey KEXINIT arrived first. */
    ssh->isKeying = WOLFSSH_PEER_IS_KEYING;

    allowed = wolfSSH_TestIsMessageAllowed(ssh, MSGID_SERVICE_ACCEPT,
            WS_MSG_RECV);
    AssertFalse(allowed);
    AssertIntEQ(ssh->error, WS_MSGID_NOT_ALLOWED_E);

    /* Allowed when only this side has started a rekey: RFC 4253 section 7.1
     * requires tolerating what the peer sent before it saw our KEXINIT. */
    ResetSession(ssh);
    ssh->connectState = CONNECT_CLIENT_USERAUTH_REQUEST_SENT;
    ssh->isKeying = WOLFSSH_SELF_IS_KEYING;

    allowed = wolfSSH_TestIsMessageAllowed(ssh, MSGID_SERVICE_ACCEPT,
            WS_MSG_RECV);
    AssertTrue(allowed);
}


/* Drive the whole receive path with a CHANNEL_OPEN sent from a pre-auth
 * connectState: no channel created, and the only thing sent back is the
 * disconnect RFC 4252 section 6 asks for. The connectState gate does the
 * rejecting; isKeying below is scene-setting only. */
static void TestChannelOpenRejectedBeforeKex(byte connectState)
{
    WOLFSSH_CTX* ctx;
    WOLFSSH* ssh;
    MemIo io;
    byte pkt[256];
    byte out[256];
    word32 pktSz;

    pktSz = BuildChannelOpenPacket("session", 0, 131072, 16384, NULL, 0,
            pkt, sizeof(pkt));

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_CLIENT, NULL);
    AssertNotNull(ctx);
    wolfSSH_SetIORecv(ctx, MemRecv);
    wolfSSH_SetIOSend(ctx, MemSend);

    ssh = wolfSSH_new(ctx);
    AssertNotNull(ssh);

    MemIoInit(&io, pkt, pktSz, out, sizeof(out));
    wolfSSH_SetIOReadCtx(ssh, &io);
    wolfSSH_SetIOWriteCtx(ssh, &io);

    ssh->connectState = connectState;
    ssh->isKeying = WOLFSSH_PEER_IS_KEYING;

    AssertIntEQ(wolfSSH_TestDoReceive(ssh), WS_FATAL_ERROR);
    AssertIntEQ(ssh->error, WS_MSGID_NOT_ALLOWED_E);
    AssertNull(ssh->channelList);
    AssertIntEQ(ssh->channelListSz, 0);
    /* Not silence: the peer is told why the session ended, and the message
     * is a disconnect rather than anything answering the channel open. */
    AssertTrue(io.outSz > 0);
    AssertIntEQ(ParseMsgId(io.out, io.outSz), MSGID_DISCONNECT);
    AssertTrue(ssh->disconnected);

    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);
}


#ifndef NO_WOLFSSH_SERVER
/* The client gate tests above run against a client endpoint, so the server
 * branch of IsMessageAllowed was never exercised. The tests below drive a
 * server endpoint to cover its pre-authentication message gate. */

/* Reject connection-protocol messages on the server before user
 * authentication completes. */
static void TestServerChannelBlockedBeforeAuth(WOLFSSH* ssh)
{
    int allowed;

    ResetSession(ssh);
    /* The state just below the auth-complete boundary
     * (ACCEPT_SERVER_USERAUTH_SENT). */
    ssh->acceptState = ACCEPT_CLIENT_USERAUTH_DONE;

    allowed = wolfSSH_TestIsMessageAllowed(ssh, MSGID_CHANNEL_OPEN,
            WS_MSG_RECV);
    AssertFalse(allowed);

    allowed = wolfSSH_TestIsMessageAllowed(ssh, MSGID_GLOBAL_REQUEST,
            WS_MSG_RECV);
    AssertFalse(allowed);
}


/* Allow connection-protocol messages on the server once user authentication
 * completes. Pins the acceptState boundary against a relaxed comparison. */
static void TestServerChannelAllowedAfterAuth(WOLFSSH* ssh)
{
    int allowed;

    ResetSession(ssh);
    ssh->acceptState = ACCEPT_SERVER_USERAUTH_SENT;

    allowed = wolfSSH_TestIsMessageAllowed(ssh, MSGID_CHANNEL_OPEN,
            WS_MSG_RECV);
    AssertTrue(allowed);

    allowed = wolfSSH_TestIsMessageAllowed(ssh, MSGID_GLOBAL_REQUEST,
            WS_MSG_RECV);
    AssertTrue(allowed);
}


/* Reject the user auth request while the server is still keying, then accept
 * it once keyed. Pins the pre-keyed message-range bound. */
static void TestServerUserauthBlockedBeforeKeyed(WOLFSSH* ssh)
{
    int allowed;

    ResetSession(ssh);
    ssh->acceptState = ACCEPT_SERVER_KEXINIT_SENT;

    allowed = wolfSSH_TestIsMessageAllowed(ssh, MSGID_USERAUTH_REQUEST,
            WS_MSG_RECV);
    AssertFalse(allowed);

    ssh->acceptState = ACCEPT_CLIENT_USERAUTH_DONE;

    allowed = wolfSSH_TestIsMessageAllowed(ssh, MSGID_USERAUTH_REQUEST,
            WS_MSG_RECV);
    AssertTrue(allowed);
}


/* One packet fed to a keyed but unauthenticated server. The cases below
 * differ only in the packet and the answer it draws. */
static void RunServerMsgIdAtKeyed(const byte* pkt, word32 pktSz,
        int expectRet, int expectErr, byte expectReplyMsgId,
        int expectDisconnected)
{
    WOLFSSH_CTX* ctx;
    WOLFSSH* ssh;
    MemIo io;
    byte out[256];

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_SERVER, NULL);
    AssertNotNull(ctx);
    wolfSSH_SetIORecv(ctx, MemRecv);
    wolfSSH_SetIOSend(ctx, MemSend);

    ssh = wolfSSH_new(ctx);
    AssertNotNull(ssh);

    MemIoInit(&io, (byte*)pkt, pktSz, out, sizeof(out));
    wolfSSH_SetIOReadCtx(ssh, &io);
    wolfSSH_SetIOWriteCtx(ssh, &io);

    /* Past the key exchange, short of user auth being answered. */
    ssh->acceptState = ACCEPT_KEYED;

    AssertIntEQ(wolfSSH_TestDoReceive(ssh), expectRet);
    AssertIntEQ(ssh->error, expectErr);
    /* Nothing the filter refuses may leave a channel behind. */
    AssertNull(ssh->channelList);
    AssertIntEQ(ssh->channelListSz, 0);
    AssertTrue(io.outSz > 0);
    AssertIntEQ(ParseMsgId(io.out, io.outSz), expectReplyMsgId);
    AssertIntEQ(ssh->disconnected != 0, expectDisconnected);

    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);
}


/* The case RFC 4252 section 6 names: an id of 80 or higher before user auth.
 * Keyed, so the post-userauth limit rejects it, not the pre-keyed range. */
static void TestServerHighMsgIdBeforeAuthDisconnects(void)
{
    byte pkt[256];
    word32 pktSz;

    pktSz = BuildChannelOpenPacket("session", 0, 131072, 16384, NULL, 0,
            pkt, sizeof(pkt));

    RunServerMsgIdAtKeyed(pkt, pktSz, WS_FATAL_ERROR, WS_MSGID_NOT_ALLOWED_E,
            MSGID_DISCONNECT, 1);
}


/* Id 79 is refused too, but it is unimplemented and below 80, so RFC 4253
 * section 11.4 rules: UNIMPLEMENTED, and the session lives. */
static void TestServerUnknownMsgIdBeforeAuthUnimplemented(void)
{
    byte pkt[256];
    word32 pktSz;

    pktSz = WrapPacket(79, NULL, 0, pkt, sizeof(pkt));

    RunServerMsgIdAtKeyed(pkt, pktSz, WS_SUCCESS, WS_SUCCESS,
            MSGID_UNIMPLEMENTED, 0);
}


/* Below 80 the dispatch decides: 53 has a case, so it disconnects where
 * 79 does not. */
static void TestServerKnownAuthMsgIdBeforeAuthDisconnects(void)
{
    byte pkt[256];
    word32 pktSz;

    pktSz = WrapPacket(MSGID_USERAUTH_BANNER, NULL, 0, pkt, sizeof(pkt));

    RunServerMsgIdAtKeyed(pkt, pktSz, WS_FATAL_ERROR, WS_MSGID_NOT_ALLOWED_E,
            MSGID_DISCONNECT, 1);
}


/* At 80 and above the range decides instead: id 200 disconnects though
 * nothing dispatches it. */
static void TestServerUnknownHighMsgIdBeforeAuthDisconnects(void)
{
    byte pkt[256];
    word32 pktSz;

    pktSz = WrapPacket(200, NULL, 0, pkt, sizeof(pkt));

    RunServerMsgIdAtKeyed(pkt, pktSz, WS_FATAL_ERROR, WS_MSGID_NOT_ALLOWED_E,
            MSGID_DISCONNECT, 1);
}


/* Reject the user auth messages that only the server sends, while still
 * accepting the keyboard-interactive info response that it receives. */
static void TestServerOnlyUserauthMsgsBlocked(WOLFSSH* ssh)
{
    int allowed;

    ResetSession(ssh);
    ssh->acceptState = ACCEPT_CLIENT_USERAUTH_DONE;

    allowed = wolfSSH_TestIsMessageAllowed(ssh, MSGID_USERAUTH_FAILURE,
            WS_MSG_RECV);
    AssertFalse(allowed);

    allowed = wolfSSH_TestIsMessageAllowed(ssh, MSGID_USERAUTH_SUCCESS,
            WS_MSG_RECV);
    AssertFalse(allowed);

    allowed = wolfSSH_TestIsMessageAllowed(ssh, MSGID_USERAUTH_INFO_RESPONSE,
            WS_MSG_RECV);
    AssertTrue(allowed);
}


/* Reject the key exchange messages that only the server sends. */
static void TestServerOnlyKexMsgsBlocked(WOLFSSH* ssh)
{
    int allowed;

    ResetSession(ssh);
    /* The peer's KEXINIT has landed, its GEX request has not. */
    ssh->acceptState = ACCEPT_SERVER_KEXINIT_SENT;
    ssh->isKeying = WOLFSSH_PEER_IS_KEYING;
    ssh->handshake = AllocHandshake(ssh);
    ssh->handshake->kexId = ID_DH_GEX_SHA256;
    /* The server expects no particular message yet, so the expectMsgId
     * check cannot catch these, the role check has to. */
    AssertIntEQ(ssh->handshake->expectMsgId, MSGID_NONE);

    allowed = wolfSSH_TestIsMessageAllowed(ssh, MSGID_KEXDH_GEX_GROUP,
            WS_MSG_RECV);
    AssertFalse(allowed);
    AssertIntEQ(ssh->error, WS_MSGID_NOT_ALLOWED_E);

    ssh->error = 0;
    allowed = wolfSSH_TestIsMessageAllowed(ssh, MSGID_KEXDH_GEX_REPLY,
            WS_MSG_RECV);
    AssertFalse(allowed);
    AssertIntEQ(ssh->error, WS_MSGID_NOT_ALLOWED_E);

    /* The message a conformant client sends in this state is unaffected. */
    ssh->error = 0;
    allowed = wolfSSH_TestIsMessageAllowed(ssh, MSGID_KEXDH_GEX_REQUEST,
            WS_MSG_RECV);
    AssertTrue(allowed);
    AssertIntEQ(ssh->error, WS_SUCCESS);

    /* 32 sits between the two blocked ids and has to stay allowed. Assert
     * it where the server actually expects it, once it has sent the
     * group. */
    ssh->error = 0;
    ssh->handshake->expectMsgId = MSGID_KEXDH_GEX_INIT;
    allowed = wolfSSH_TestIsMessageAllowed(ssh, MSGID_KEXDH_GEX_INIT,
            WS_MSG_RECV);
    AssertTrue(allowed);
    AssertIntEQ(ssh->handshake->expectMsgId, MSGID_NONE);

    /* Same answer during a rekey on an established session. The pre-keyed
     * range check does not run this far along, so a check placed there
     * would leave this window open. */
    ssh->error = 0;
    ssh->acceptState = ACCEPT_CLIENT_SESSION_ESTABLISHED;

    allowed = wolfSSH_TestIsMessageAllowed(ssh, MSGID_KEXDH_GEX_GROUP,
            WS_MSG_RECV);
    AssertFalse(allowed);
    AssertIntEQ(ssh->error, WS_MSGID_NOT_ALLOWED_E);

    ssh->error = 0;
    allowed = wolfSSH_TestIsMessageAllowed(ssh, MSGID_KEXDH_GEX_REPLY,
            WS_MSG_RECV);
    AssertFalse(allowed);
    AssertIntEQ(ssh->error, WS_MSGID_NOT_ALLOWED_E);
}


/* The server accepts a service request only once keyed, and never accepts
 * the service accept that only it sends. */
static void TestServerServiceRequestStateGated(WOLFSSH* ssh)
{
    int allowed;

    ResetSession(ssh);
    ssh->acceptState = ACCEPT_KEYED;

    allowed = wolfSSH_TestIsMessageAllowed(ssh, MSGID_SERVICE_REQUEST,
            WS_MSG_RECV);
    AssertTrue(allowed);

    ssh->acceptState = ACCEPT_SERVER_KEXINIT_SENT;

    allowed = wolfSSH_TestIsMessageAllowed(ssh, MSGID_SERVICE_REQUEST,
            WS_MSG_RECV);
    AssertFalse(allowed);

    allowed = wolfSSH_TestIsMessageAllowed(ssh, MSGID_SERVICE_ACCEPT,
            WS_MSG_RECV);
    AssertFalse(allowed);
    /* Of the messages exercised here, only SERVICE_ACCEPT sets an error
     * on reject. */
    AssertIntEQ(ssh->error, WS_MSGID_NOT_ALLOWED_E);
}


/* Drive the receive path with a SERVICE_REQUEST arriving mid-rekey.
 * acceptState sits at ACCEPT_KEYED throughout, so only isKeying catches
 * it. */
static void TestServerServiceRequestRejectedDuringKeying(void)
{
    WOLFSSH_CTX* ctx;
    WOLFSSH* ssh;
    MemIo io;
    byte payload[64];
    byte pkt[128];
    byte out[128];
    word32 pktSz;
    word32 idx = 0;

    idx = AppendString(payload, sizeof(payload), idx, "ssh-userauth");
    pktSz = WrapPacket(MSGID_SERVICE_REQUEST, payload, idx, pkt, sizeof(pkt));

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_SERVER, NULL);
    AssertNotNull(ctx);
    wolfSSH_SetIORecv(ctx, MemRecv);
    wolfSSH_SetIOSend(ctx, MemSend);

    ssh = wolfSSH_new(ctx);
    AssertNotNull(ssh);

    MemIoInit(&io, pkt, pktSz, out, sizeof(out));
    wolfSSH_SetIOReadCtx(ssh, &io);
    wolfSSH_SetIOWriteCtx(ssh, &io);

    ssh->acceptState = ACCEPT_KEYED;
    /* The peer's rekey KEXINIT arrived, its NEWKEYS has not. */
    ssh->isKeying = WOLFSSH_PEER_IS_KEYING;

    AssertIntEQ(wolfSSH_TestDoReceive(ssh), WS_FATAL_ERROR);
    AssertIntEQ(ssh->error, WS_MSGID_NOT_ALLOWED_E);
    /* Not dispatched, so acceptState did not advance. */
    AssertIntEQ(ssh->clientState, CLIENT_BEGIN);
    AssertIntEQ(ssh->acceptState, ACCEPT_KEYED);
    /* Not silence: nothing answers the service request, but the peer is told
     * the session ended on a protocol error. */
    AssertTrue(io.outSz > 0);
    AssertIntEQ(ParseMsgId(io.out, io.outSz), MSGID_DISCONNECT);
    AssertTrue(ssh->disconnected);

    /* Allowed when only this side has started a rekey. */
    ssh->error = 0;
    ssh->isKeying = WOLFSSH_SELF_IS_KEYING;
    AssertTrue(wolfSSH_TestIsMessageAllowed(ssh, MSGID_SERVICE_REQUEST,
            WS_MSG_RECV));

    /* Allowed once the key exchange is done. */
    ssh->error = 0;
    ssh->isKeying = 0;
    AssertTrue(wolfSSH_TestIsMessageAllowed(ssh, MSGID_SERVICE_REQUEST,
            WS_MSG_RECV));

    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);
}


/* A send the transport refuses discards the packet it had framed, and plainSz
 * counted that packet's plaintext. Left standing over an emptied buffer, it
 * has the next SendChannelData() flush nothing and call that a success. */
static void TestFailedSendClearsPendingPlaintext(void)
{
    ChannelOpenHarness harness;
    WOLFSSH_CHANNEL* channel;
    byte payload[16];

    InitChannelOpenHarness(&harness, NULL, 0);
    WMEMSET(payload, 'a', sizeof(payload));

    channel = ChannelNew(harness.ssh, ID_CHANTYPE_SESSION, 1024, 1024);
    AssertNotNull(channel);
    AssertIntEQ(ChannelUpdatePeer(channel, 0, 1024, 1024), WS_SUCCESS);
    AssertIntEQ(ChannelAppend(harness.ssh, channel), WS_SUCCESS);

    /* The transport blocks, so the packet stays framed and the caller is told
     * its data was taken. */
    harness.io.blockNext = 1;
    AssertIntEQ(wolfSSH_stream_send(harness.ssh, payload, sizeof(payload)),
            (int)sizeof(payload));
    AssertIntEQ(harness.ssh->outputBuffer.plainSz, (int)sizeof(payload));
    AssertIntEQ(wolfSSH_OutputPending(harness.ssh), 1);

    /* The next call flushes that packet first, and this send fails outright,
     * so what it was flushing is thrown away. */
    harness.io.outSz = harness.io.outCap;
    AssertIntEQ(wolfSSH_stream_send(harness.ssh, payload, sizeof(payload)),
            WS_SOCKET_ERROR_E);

    /* Nothing is framed any more, so nothing may still be counted as
     * pending. */
    AssertIntEQ(wolfSSH_OutputPending(harness.ssh), 0);
    AssertIntEQ(harness.ssh->outputBuffer.plainSz, 0);

    FreeChannelOpenHarness(&harness);
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

static void TestSecondSessionChannelRejected(void)
{
    ChannelOpenHarness harness;
    byte in1[128];
    byte in2[128];
    word32 in1Sz;
    word32 in2Sz;
    int ret;

    in1Sz = BuildChannelOpenPacket("session", 7, 0x4000, 0x8000,
            NULL, 0, in1, sizeof(in1));
    in2Sz = BuildChannelOpenPacket("session", 8, 0x4000, 0x8000,
            NULL, 0, in2, sizeof(in2));

    InitChannelOpenHarness(&harness, in1, in1Sz);

    /* First channel open must succeed */
    ret = DoReceive(harness.ssh);
    AssertIntEQ(ret, WS_SUCCESS);
    AssertIntEQ(harness.io.inOff, harness.io.inSz);
    AssertTrue(harness.io.outSz > 0);
    AssertIntEQ(ParseMsgId(harness.io.out, harness.io.outSz),
            MSGID_CHANNEL_OPEN_CONF);
    AssertIntEQ(harness.ssh->channelListSz, 1);

    /* Repoint input and rewind outSz so the second response writes from offset 0.
     * io.out and outCap need no change - both still refer to harness.out[256]. */
    harness.io.in    = in2;
    harness.io.inSz  = in2Sz;
    harness.io.inOff = 0;
    harness.io.outSz = 0;

    /* Second session channel open must be rejected */
    ret = DoReceive(harness.ssh);
    AssertIntEQ(ret, WS_SUCCESS);
    AssertIntEQ(harness.io.inOff, harness.io.inSz);
    AssertTrue(harness.io.outSz > 0);
    AssertIntEQ(ParseMsgId(harness.io.out, harness.io.outSz),
            MSGID_CHANNEL_OPEN_FAIL);
    AssertIntEQ(ParseChannelOpenFailRecipient(harness.io.out, harness.io.outSz),
            8); /* RFC 4254 5.1: server must echo the peer's channel ID */
    AssertIntEQ(ParseChannelOpenFailReason(harness.io.out, harness.io.outSz),
            OPEN_ADMINISTRATIVELY_PROHIBITED);
    AssertIntEQ(harness.ssh->channelListSz, 1); /* original channel intact */

    FreeChannelOpenHarness(&harness);
}

/* Records the username the auth callback was invoked with, so a test can prove
 * which identity a userauth request bound to. */
static char authCbUserName[64];
static word32 authCbUserNameSz;
static int authCbInvoked;

static void ResetAuthCbRecord(void)
{
    WMEMSET(authCbUserName, 0, sizeof(authCbUserName));
    authCbUserNameSz = 0;
    authCbInvoked = 0;
}

static int RecordUserAuthCb(byte authType, WS_UserAuthData* authData, void* ctx)
{
    (void)ctx;
#ifndef WOLFSSH_KEYBOARD_INTERACTIVE
    (void)authType;
#endif

#ifdef WOLFSSH_KEYBOARD_INTERACTIVE
    if (authType == WOLFSSH_USERAUTH_KEYBOARD_SETUP) {
        static byte kbPrompt[] = "Password: ";
        static byte* kbPrompts[1];
        static word32 kbPromptLengths[1];
        static byte kbPromptEcho[1];

        kbPrompts[0] = kbPrompt;
        kbPromptLengths[0] = (word32)sizeof(kbPrompt) - 1;
        kbPromptEcho[0] = 0;
        authData->sf.keyboard.promptCount = 1;
        authData->sf.keyboard.prompts = kbPrompts;
        authData->sf.keyboard.promptLengths = kbPromptLengths;
        authData->sf.keyboard.promptEcho = kbPromptEcho;
        authData->sf.keyboard.promptName = NULL;
        authData->sf.keyboard.promptInstruction = NULL;
        authData->sf.keyboard.promptLanguage = NULL;
        return WOLFSSH_USERAUTH_SUCCESS;
    }
#endif

    authCbInvoked = 1;
    authCbUserNameSz = authData->usernameSz;
    if (authCbUserNameSz >= (word32)sizeof(authCbUserName))
        authCbUserNameSz = (word32)sizeof(authCbUserName) - 1;
    if (authData->username != NULL && authCbUserNameSz > 0)
        WMEMCPY(authCbUserName, authData->username, authCbUserNameSz);
    authCbUserName[authCbUserNameSz] = '\0';

#ifdef WOLFSSH_KEYBOARD_INTERACTIVE
    if (authType == WOLFSSH_USERAUTH_KEYBOARD)
        return WOLFSSH_USERAUTH_SUCCESS;
#endif
    /* Reject other methods so the connection stays up for the next request
     * without completing authentication. */
    return WOLFSSH_USERAUTH_INVALID_PASSWORD;
}

static word32 BuildUserAuthPasswordRequest(const char* user, const char* pw,
        byte* out, word32 outSz)
{
    byte payload[256];
    word32 idx = 0;

    idx = AppendString(payload, sizeof(payload), idx, user);
    idx = AppendString(payload, sizeof(payload), idx, "ssh-connection");
    idx = AppendString(payload, sizeof(payload), idx, "password");
    idx = AppendByte(payload, sizeof(payload), idx, 0); /* not changing pw */
    idx = AppendString(payload, sizeof(payload), idx, pw);

    return WrapPacket(MSGID_USERAUTH_REQUEST, payload, idx, out, outSz);
}

/* Drive a userauth request against a fresh in-memory server harness. The accept
 * state is rewound to before userauth completes so USERAUTH_REQUEST and
 * USERAUTH_INFO_RESPONSE are accepted by the message filter. */
static void InitUserAuthHarness(ChannelOpenHarness* harness,
        byte* in, word32 inSz)
{
    InitChannelOpenHarness(harness, in, inSz);
    wolfSSH_SetUserAuth(harness->ctx, RecordUserAuthCb);
    harness->ssh->acceptState = ACCEPT_SERVER_USERAUTH_ACCEPT_SENT;
}

static void RepointHarnessInput(ChannelOpenHarness* harness,
        byte* in, word32 inSz)
{
    harness->io.in = in;
    harness->io.inSz = inSz;
    harness->io.inOff = 0;
    harness->io.outSz = 0;
}

/* A username change after the first userauth request must end the session. */
static void TestUsernameChangeDisconnects(void)
{
    ChannelOpenHarness harness;
    byte inAlice[128];
    byte inBob[128];
    word32 inAliceSz;
    word32 inBobSz;

    inAliceSz = BuildUserAuthPasswordRequest("alice", "pw",
            inAlice, sizeof(inAlice));
    inBobSz = BuildUserAuthPasswordRequest("bob", "pw", inBob, sizeof(inBob));

    ResetAuthCbRecord();
    InitUserAuthHarness(&harness, inAlice, inAliceSz);

    /* First request binds the username; callback sees alice and rejects. */
    AssertIntEQ(DoReceive(harness.ssh), WS_SUCCESS);
    AssertStrEQ(authCbUserName, "alice");

    /* Second request changes the username: session must be torn down and the
     * callback must not be invoked as bob. */
    ResetAuthCbRecord();
    RepointHarnessInput(&harness, inBob, inBobSz);
    AssertIntEQ(DoReceive(harness.ssh), WS_FATAL_ERROR);
    AssertIntEQ(harness.ssh->error, WS_INVALID_STATE_E);
    AssertTrue(harness.io.outSz > 0);
    AssertIntEQ(ParseMsgId(harness.io.out, harness.io.outSz), MSGID_DISCONNECT);
    AssertIntEQ(authCbInvoked, 0);

    FreeChannelOpenHarness(&harness);
}

/* A second userauth request that keeps the username is the normal retry path
 * (failed password, or publickey probe then password) and must be accepted. */
static void TestSameUserRetryAllowed(void)
{
    ChannelOpenHarness harness;
    byte inFirst[128];
    byte inSecond[128];
    word32 inFirstSz;
    word32 inSecondSz;

    inFirstSz = BuildUserAuthPasswordRequest("alice", "wrong",
            inFirst, sizeof(inFirst));
    inSecondSz = BuildUserAuthPasswordRequest("alice", "pw",
            inSecond, sizeof(inSecond));

    ResetAuthCbRecord();
    InitUserAuthHarness(&harness, inFirst, inFirstSz);

    /* First request binds alice; the callback rejects the password. */
    AssertIntEQ(DoReceive(harness.ssh), WS_SUCCESS);
    AssertIntEQ(authCbInvoked, 1);
    AssertStrEQ(authCbUserName, "alice");
    AssertIntEQ(ParseMsgId(harness.io.out, harness.io.outSz),
            MSGID_USERAUTH_FAILURE);

    /* Retry as the same user: accepted, callback runs again bound to alice. */
    ResetAuthCbRecord();
    RepointHarnessInput(&harness, inSecond, inSecondSz);
    AssertIntEQ(DoReceive(harness.ssh), WS_SUCCESS);
    AssertIntEQ(harness.ssh->error, WS_SUCCESS);
    AssertIntEQ(authCbInvoked, 1);
    AssertStrEQ(authCbUserName, "alice");
    AssertTrue(harness.io.outSz > 0);
    AssertIntEQ(ParseMsgId(harness.io.out, harness.io.outSz),
            MSGID_USERAUTH_FAILURE);

    FreeChannelOpenHarness(&harness);
}

#ifdef WOLFSSH_KEYBOARD_INTERACTIVE
static word32 BuildUserAuthKeyboardRequest(const char* user,
        byte* out, word32 outSz)
{
    byte payload[256];
    word32 idx = 0;

    idx = AppendString(payload, sizeof(payload), idx, user);
    idx = AppendString(payload, sizeof(payload), idx, "ssh-connection");
    idx = AppendString(payload, sizeof(payload), idx, "keyboard-interactive");
    idx = AppendString(payload, sizeof(payload), idx, ""); /* language tag */
    idx = AppendString(payload, sizeof(payload), idx, ""); /* submethods */

    return WrapPacket(MSGID_USERAUTH_REQUEST, payload, idx, out, outSz);
}

static word32 BuildUserAuthInfoResponse(const char* response,
        byte* out, word32 outSz)
{
    byte payload[128];
    word32 idx = 0;

    idx = AppendUint32(payload, sizeof(payload), idx, 1); /* responseCount */
    idx = AppendString(payload, sizeof(payload), idx, response);

    return WrapPacket(MSGID_USERAUTH_INFO_RESPONSE, payload, idx, out, outSz);
}

/* The reported attack: pipeline a keyboard-interactive request for alice then
 * bob before answering. The bob request must end the session, not rebind the
 * pending challenge. */
static void TestKbUsernameChangeDisconnects(void)
{
    ChannelOpenHarness harness;
    byte inAlice[128];
    byte inBob[128];
    word32 inAliceSz;
    word32 inBobSz;

    inAliceSz = BuildUserAuthKeyboardRequest("alice", inAlice, sizeof(inAlice));
    inBobSz = BuildUserAuthKeyboardRequest("bob", inBob, sizeof(inBob));

    ResetAuthCbRecord();
    InitUserAuthHarness(&harness, inAlice, inAliceSz);

    /* alice's request opens the challenge: server emits an INFO_REQUEST. */
    AssertIntEQ(DoReceive(harness.ssh), WS_SUCCESS);
    AssertTrue(harness.io.outSz > 0);
    AssertIntEQ(ParseMsgId(harness.io.out, harness.io.outSz),
            MSGID_USERAUTH_INFO_REQUEST);
    AssertIntEQ(authCbInvoked, 0); /* setup only, no response yet */

    /* bob's pipelined request must disconnect, never reach the callback. */
    ResetAuthCbRecord();
    RepointHarnessInput(&harness, inBob, inBobSz);
    AssertIntEQ(DoReceive(harness.ssh), WS_FATAL_ERROR);
    AssertIntEQ(harness.ssh->error, WS_INVALID_STATE_E);
    AssertTrue(harness.io.outSz > 0);
    AssertIntEQ(ParseMsgId(harness.io.out, harness.io.outSz), MSGID_DISCONNECT);
    AssertIntEQ(authCbInvoked, 0);

    FreeChannelOpenHarness(&harness);
}

/* A single-user keyboard-interactive exchange still reaches the callback bound
 * to the originating user. */
static void TestKbSameUserResponseSucceeds(void)
{
    ChannelOpenHarness harness;
    byte inReq[128];
    byte inResp[128];
    word32 inReqSz;
    word32 inRespSz;

    inReqSz = BuildUserAuthKeyboardRequest("alice", inReq, sizeof(inReq));
    inRespSz = BuildUserAuthInfoResponse("secret", inResp, sizeof(inResp));

    ResetAuthCbRecord();
    InitUserAuthHarness(&harness, inReq, inReqSz);

    AssertIntEQ(DoReceive(harness.ssh), WS_SUCCESS);
    AssertIntEQ(ParseMsgId(harness.io.out, harness.io.outSz),
            MSGID_USERAUTH_INFO_REQUEST);

    RepointHarnessInput(&harness, inResp, inRespSz);
    AssertIntEQ(DoReceive(harness.ssh), WS_SUCCESS);
    AssertIntEQ(authCbInvoked, 1);
    AssertStrEQ(authCbUserName, "alice");

    FreeChannelOpenHarness(&harness);
}
#endif /* WOLFSSH_KEYBOARD_INTERACTIVE */

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

/* Both a channelOpenCb and a fwdCb registered, open callback rejects. The
 * rejection has to stand: the forwarding hook must not run, and must not
 * overwrite the rejection with its own return. That clobber shipped in
 * v1.5.0, where no test registered both callbacks at once. */
static void TestDirectTcpipOpenCbRejectBeatsFwdCb(void)
{
    ChannelOpenHarness harness;
    byte extra[128];
    byte in[192];
    word32 extraSz;
    word32 inSz;
    int ret;

    fwdCbCallCount = 0;

    extraSz = BuildDirectTcpipExtra("127.0.0.1", 8080, "127.0.0.1", 2222,
            extra, sizeof(extra));
    inSz = BuildChannelOpenPacket("direct-tcpip", 9, 0x4000, 0x8000,
            extra, extraSz, in, sizeof(in));

    InitChannelOpenHarness(&harness, in, inSz);
    AssertIntEQ(wolfSSH_CTX_SetChannelOpenCb(harness.ctx, RejectChannelOpenCb),
            WS_SUCCESS);
    AssertIntEQ(wolfSSH_CTX_SetFwdCb(harness.ctx, CountingFwdCb, NULL),
            WS_SUCCESS);

    ret = DoReceive(harness.ssh);
    AssertChannelOpenFailResponse(&harness, ret);
    AssertIntEQ(ParseChannelOpenFailRecipient(harness.io.out, harness.io.outSz),
            9); /* RFC 4254 5.1: the peer's channel ID comes back */
    AssertIntEQ(ParseChannelOpenFailReason(harness.io.out, harness.io.outSz),
            OPEN_ADMINISTRATIVELY_PROHIBITED);
    AssertIntEQ(fwdCbCallCount, 0);

    FreeChannelOpenHarness(&harness);
}

/* The other half of the pair: the open callback accepts, so the fwdCb decides,
 * and its rejection must reach the peer. */
static void TestDirectTcpipFwdCbRejectAfterOpenCbAccept(void)
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
    AssertIntEQ(wolfSSH_CTX_SetChannelOpenCb(harness.ctx, AcceptChannelOpenCb),
            WS_SUCCESS);
    AssertIntEQ(wolfSSH_CTX_SetFwdCb(harness.ctx, RejectDirectTcpipSetup, NULL),
            WS_SUCCESS);

    ret = DoReceive(harness.ssh);
    AssertChannelOpenFailResponse(&harness, ret);
    AssertIntEQ(ParseChannelOpenFailRecipient(harness.io.out, harness.io.outSz),
            9);
    AssertIntEQ(ParseChannelOpenFailReason(harness.io.out, harness.io.outSz),
            OPEN_ADMINISTRATIVELY_PROHIBITED);

    FreeChannelOpenHarness(&harness);
}

/* DoChannelOpen() consults the fwdCb twice. A rejection at the second
 * consultation, the channel-id handoff, must fail the open the same way the
 * setup rejection does. The count doubles as the positive control for the
 * zero asserted above: the same counter reaches 2 here. */
static void TestDirectTcpipFwdCbRejectsChannelId(void)
{
    ChannelOpenHarness harness;
    byte extra[128];
    byte in[192];
    word32 extraSz;
    word32 inSz;
    int ret;

    fwdCbCallCount = 0;

    extraSz = BuildDirectTcpipExtra("127.0.0.1", 8080, "127.0.0.1", 2222,
            extra, sizeof(extra));
    inSz = BuildChannelOpenPacket("direct-tcpip", 9, 0x4000, 0x8000,
            extra, extraSz, in, sizeof(in));

    InitChannelOpenHarness(&harness, in, inSz);
    AssertIntEQ(wolfSSH_CTX_SetFwdCb(harness.ctx,
            CountingRejectChannelIdFwdCb, NULL), WS_SUCCESS);

    ret = DoReceive(harness.ssh);
    AssertChannelOpenFailResponse(&harness, ret);
    AssertIntEQ(ParseChannelOpenFailRecipient(harness.io.out, harness.io.outSz),
            9);
    /* This path leaves fail_reason at OPEN_OK and leans on the default,
     * unlike the rejections that set the reason themselves. */
    AssertIntEQ(ParseChannelOpenFailReason(harness.io.out, harness.io.outSz),
            OPEN_ADMINISTRATIVELY_PROHIBITED);
    AssertIntEQ(fwdCbCallCount, 2);

    FreeChannelOpenHarness(&harness);
}

static void TestForwardedTcpipOnServerSendsOpenFail(void)
{
    ChannelOpenHarness harness;
    byte extra[128];
    byte in[192];
    word32 extraSz;
    word32 inSz;
    int ret;

    /* forwarded-tcpip is only ever sent server-to-client. A server receiving
     * one is the wrong direction and must be rejected even with a fwdCb set,
     * before the forwarding policy hook runs. */
    extraSz = BuildDirectTcpipExtra("127.0.0.1", 8080, "127.0.0.1", 2222,
            extra, sizeof(extra));
    inSz = BuildChannelOpenPacket("forwarded-tcpip", 9, 0x4000, 0x8000,
            extra, extraSz, in, sizeof(in));

    InitChannelOpenHarness(&harness, in, inSz);
    AssertIntEQ(wolfSSH_CTX_SetFwdCb(harness.ctx, AcceptFwdCb, NULL),
            WS_SUCCESS);

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

#ifndef NO_WOLFSSH_CLIENT
/* A client is the side that asks for a remote forward, so a tcpip-forward it
 * receives is answered with a failure and never registered. RFC 4254 section
 * 7.1. A fwdCb is registered throughout: without the role check that callback
 * is the only gate, and it would answer success. */
static void TestGlobalRequestFwdOnClientSendsFailure(void)
{
    ChannelOpenHarness harness;
    byte in[256];
    word32 inSz;
    int ret;

    inSz = BuildGlobalRequestFwdPacket("0.0.0.0", 2222, 0, 1, in, sizeof(in));
    InitChannelOpenHarnessClient(&harness, in, inSz);
    AssertIntEQ(wolfSSH_CTX_SetFwdCb(harness.ctx, AcceptFwdCb, NULL),
            WS_SUCCESS);

    ret = DoReceive(harness.ssh);

    AssertIntEQ(ret, WS_SUCCESS);
    AssertGlobalRequestReply(&harness, MSGID_REQUEST_FAILURE);

    FreeChannelOpenHarness(&harness);
}

/* cancel-tcpip-forward travels the same direction, so a client refuses it on
 * the same grounds. */
static void TestGlobalRequestFwdCancelOnClientSendsFailure(void)
{
    ChannelOpenHarness harness;
    byte in[256];
    word32 inSz;
    int ret;

    inSz = BuildGlobalRequestFwdPacket("0.0.0.0", 2222, 1, 1, in, sizeof(in));
    InitChannelOpenHarnessClient(&harness, in, inSz);
    AssertIntEQ(wolfSSH_CTX_SetFwdCb(harness.ctx, AcceptFwdCb, NULL),
            WS_SUCCESS);

    ret = DoReceive(harness.ssh);

    AssertIntEQ(ret, WS_SUCCESS);
    AssertGlobalRequestReply(&harness, MSGID_REQUEST_FAILURE);

    FreeChannelOpenHarness(&harness);
}

/* The refusal is silent when the peer did not ask for a reply: nothing goes
 * back, and the session carries on. Silence alone would also be the answer
 * without the role check, since a request the callback accepts and that asks
 * for no reply sends nothing either, so the callback is the discriminator
 * here: the request must be turned away before it reaches one. */
static void TestGlobalRequestFwdOnClientNoReplyStaysQuiet(void)
{
    ChannelOpenHarness harness;
    byte in[256];
    word32 inSz;
    int ret;

    inSz = BuildGlobalRequestFwdPacket("0.0.0.0", 2222, 0, 0, in, sizeof(in));
    InitChannelOpenHarnessClient(&harness, in, inSz);
    AssertIntEQ(wolfSSH_CTX_SetFwdCb(harness.ctx, CountingFwdCb, NULL),
            WS_SUCCESS);
    fwdCbCallCount = 0;

    ret = DoReceive(harness.ssh);

    AssertIntEQ(ret, WS_SUCCESS);
    AssertIntEQ(harness.io.outSz, 0);
    AssertIntEQ(fwdCbCallCount, 0);

    FreeChannelOpenHarness(&harness);
}

#endif /* !NO_WOLFSSH_CLIENT */

/* The role check must not cost the server anything: the same request that a
 * client refuses is still honoured here. */
static void TestGlobalRequestFwdOnServerStillSucceeds(void)
{
    ChannelOpenHarness harness;
    byte in[256];
    word32 inSz;
    int ret;

    inSz = BuildGlobalRequestFwdPacket("0.0.0.0", 2222, 0, 1, in, sizeof(in));
    InitChannelOpenHarness(&harness, in, inSz);
    AssertIntEQ(wolfSSH_CTX_SetFwdCb(harness.ctx, AcceptFwdCb, NULL),
            WS_SUCCESS);

    ret = DoReceive(harness.ssh);

    AssertIntEQ(ret, WS_SUCCESS);
    AssertGlobalRequestReply(&harness, MSGID_REQUEST_SUCCESS);

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

static void TestGlobalRequestFwdPort0ReturnsAllocatedPort(void)
{
    ChannelOpenHarness harness;
    byte in[256];
    word32 inSz;
    int ret;

    /* A bind port of 0 asks the server to allocate a port. The success reply
     * must carry the port the callback allocated, not the requested 0. */
    inSz = BuildGlobalRequestFwdPacket("0.0.0.0", 0, 0, 1, in, sizeof(in));
    InitChannelOpenHarness(&harness, in, inSz);
    AssertIntEQ(wolfSSH_CTX_SetFwdCb(harness.ctx, AllocatePortFwdCb, NULL),
            WS_SUCCESS);

    ret = DoReceive(harness.ssh);

    AssertIntEQ(ret, WS_SUCCESS);
    AssertGlobalRequestReply(&harness, MSGID_REQUEST_SUCCESS);
    AssertIntEQ(ParseGlobalRequestSuccessPort(harness.io.out, harness.io.outSz),
            REGRESS_FWD_ALLOC_PORT);

    FreeChannelOpenHarness(&harness);
}

static void TestGlobalRequestFwdPort0NoAllocSendsFailure(void)
{
    ChannelOpenHarness harness;
    byte in[256];
    word32 inSz;
    int ret;
    int cleanupCalled = 0;

    /* The peer asked the server to choose a port (0), but the callback
     * accepts without reporting one. The server must reject and tear the
     * setup back down rather than reply with a non-compliant port 0. */
    inSz = BuildGlobalRequestFwdPacket("0.0.0.0", 0, 0, 1, in, sizeof(in));
    InitChannelOpenHarness(&harness, in, inSz);
    AssertIntEQ(wolfSSH_CTX_SetFwdCb(harness.ctx, NoPortFwdCb, NULL),
            WS_SUCCESS);
    AssertIntEQ(wolfSSH_SetFwdCbCtx(harness.ssh, &cleanupCalled), WS_SUCCESS);

    ret = DoReceive(harness.ssh);

    AssertIntEQ(ret, WS_SUCCESS);
    AssertGlobalRequestReply(&harness, MSGID_REQUEST_FAILURE);
    AssertIntEQ(cleanupCalled, 1);

    FreeChannelOpenHarness(&harness);
}

static void TestGlobalRequestFwdRemoteSetupErrorSendsFailure(void)
{
    ChannelOpenHarness harness;
    byte in[256];
    word32 inSz;
    int ret;
    int cleanupCalled = 0;

    /* The callback rejects the remote setup with a WS_FwdCbError status (below
     * WS_FWD_PORT_CHECK). The server must reply with failure and must not run
     * cleanup, since the setup never succeeded. */
    inSz = BuildGlobalRequestFwdPacket("0.0.0.0", 2222, 0, 1, in, sizeof(in));
    InitChannelOpenHarness(&harness, in, inSz);
    AssertIntEQ(wolfSSH_CTX_SetFwdCb(harness.ctx, RejectRemoteSetupFwdCb, NULL),
            WS_SUCCESS);
    AssertIntEQ(wolfSSH_SetFwdCbCtx(harness.ssh, &cleanupCalled), WS_SUCCESS);

    ret = DoReceive(harness.ssh);

    AssertIntEQ(ret, WS_SUCCESS);
    AssertGlobalRequestReply(&harness, MSGID_REQUEST_FAILURE);
    AssertIntEQ(cleanupCalled, 0);

    FreeChannelOpenHarness(&harness);
}

static void TestGlobalRequestFwdPort0NoAllocNoReplyKeepsConnection(void)
{
    ChannelOpenHarness harness;
    byte in[256];
    word32 inSz;
    int ret;
    int cleanupCalled = 0;

    /* Same port-0 rejection as above, but wantReply=0. The server must still
     * tear the setup back down, send no reply, and keep the connection alive
     * rather than treating the rejection as a fatal error. */
    inSz = BuildGlobalRequestFwdPacket("0.0.0.0", 0, 0, 0, in, sizeof(in));
    InitChannelOpenHarness(&harness, in, inSz);
    AssertIntEQ(wolfSSH_CTX_SetFwdCb(harness.ctx, NoPortFwdCb, NULL),
            WS_SUCCESS);
    AssertIntEQ(wolfSSH_SetFwdCbCtx(harness.ssh, &cleanupCalled), WS_SUCCESS);

    ret = DoReceive(harness.ssh);

    AssertIntEQ(ret, WS_SUCCESS);
    AssertIntEQ(harness.io.outSz, 0); /* no reply sent */
    AssertIntEQ(cleanupCalled, 1);

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
 * sec 4) without treating it as a length prefix, which would overrun the
 * buffer and produce WS_BUFFER_E. */
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


#endif /* NO_WOLFSSH_SERVER */

#if defined(WOLFSSH_AGENT) && !defined(WOLFSSH_NO_ED25519) \
    && !defined(NO_WOLFSSH_CLIENT)

#define AGENT_ED25519_NAME "ssh-ed25519"

/* Canned agent state: the sign response handed back on a read, and the
 * public key blob the user auth callback offers. */
typedef struct {
    byte response[128];
    word32 responseSz;
    byte pubKeyBlob[64];
    word32 pubKeyBlobSz;
    byte sigBlob[128];
    word32 sigBlobSz;
} AgentEd25519Ctx;

static int AgentEd25519Cb(WS_AgentCbAction action, void* agentCbCtx)
{
    (void)agentCbCtx;

    if (action == WOLFSSH_AGENT_LOCAL_SETUP ||
            action == WOLFSSH_AGENT_LOCAL_CLEANUP) {
        return WS_AGENT_SUCCESS;
    }

    return WS_AGENT_INVALID_ACTION;
}

static int AgentEd25519IoCb(WS_AgentIoCbAction action, void* buf,
        word32 bufSz, void* agentCbCtx)
{
    AgentEd25519Ctx* agentCtx = (AgentEd25519Ctx*)agentCbCtx;

    if (action == WOLFSSH_AGENT_IO_WRITE)
        return (int)bufSz;

    if (bufSz < agentCtx->responseSz)
        return 0;
    WMEMCPY(buf, agentCtx->response, agentCtx->responseSz);
    return (int)agentCtx->responseSz;
}

/* Offer an Ed25519 public key with no private key, as an agent-backed
 * client does. */
static int AgentEd25519UserAuth(byte authType, WS_UserAuthData* authData,
        void* ctx)
{
    AgentEd25519Ctx* agentCtx = (AgentEd25519Ctx*)ctx;

    if (authType != WOLFSSH_USERAUTH_PUBLICKEY || authData == NULL)
        return WOLFSSH_USERAUTH_INVALID_AUTHTYPE;

    authData->sf.publicKey.publicKeyType = (const byte*)AGENT_ED25519_NAME;
    authData->sf.publicKey.publicKeyTypeSz =
            (word32)WSTRLEN(AGENT_ED25519_NAME);
    authData->sf.publicKey.publicKey = agentCtx->pubKeyBlob;
    authData->sf.publicKey.publicKeySz = agentCtx->pubKeyBlobSz;
    authData->sf.publicKey.privateKey = NULL;
    authData->sf.publicKey.privateKeySz = 0;

    return WOLFSSH_USERAUTH_SUCCESS;
}

static void InitAgentEd25519Ctx(AgentEd25519Ctx* agentCtx, word32 sigSz)
{
    byte pubKey[ED25519_PUB_KEY_SIZE];
    byte sig[ED25519_SIG_SIZE + 1];
    byte body[128];
    word32 idx;

    AssertTrue(sigSz <= (word32)sizeof(sig));

    WMEMSET(agentCtx, 0, sizeof(*agentCtx));
    WMEMSET(pubKey, 0x5a, sizeof(pubKey));
    WMEMSET(sig, 0xa5, sizeof(sig));

    idx = AppendString(agentCtx->pubKeyBlob, sizeof(agentCtx->pubKeyBlob), 0,
            AGENT_ED25519_NAME);
    idx = AppendUint32(agentCtx->pubKeyBlob, sizeof(agentCtx->pubKeyBlob), idx,
            (word32)sizeof(pubKey));
    agentCtx->pubKeyBlobSz = AppendData(agentCtx->pubKeyBlob,
            sizeof(agentCtx->pubKeyBlob), idx, pubKey, (word32)sizeof(pubKey));

    /* The blob an agent returns holds the algorithm name and signature. */
    idx = AppendString(agentCtx->sigBlob, sizeof(agentCtx->sigBlob), 0,
            AGENT_ED25519_NAME);
    idx = AppendUint32(agentCtx->sigBlob, sizeof(agentCtx->sigBlob), idx,
            sigSz);
    agentCtx->sigBlobSz = AppendData(agentCtx->sigBlob,
            sizeof(agentCtx->sigBlob), idx, sig, sigSz);

    idx = AppendUint32(body, sizeof(body), 0, agentCtx->sigBlobSz);
    idx = AppendData(body, sizeof(body), idx, agentCtx->sigBlob,
            agentCtx->sigBlobSz);

    agentCtx->responseSz = AppendUint32(agentCtx->response,
            sizeof(agentCtx->response), 0, MSG_ID_SZ + idx);
    agentCtx->responseSz = AppendByte(agentCtx->response,
            sizeof(agentCtx->response), agentCtx->responseSz,
            MSGID_AGENT_SIGN_RESPONSE);
    agentCtx->responseSz = AppendData(agentCtx->response,
            sizeof(agentCtx->response), agentCtx->responseSz, body, idx);
}

/* Record the peer's signature algorithms the way a server would, through
 * an EXT_INFO carrying server-sig-algs. */
static void SetPeerSigAlgs(WOLFSSH* ssh, const char* sigAlgs)
{
    byte payload[128];
    word32 payloadSz;
    word32 idx = 0;

    payloadSz = BuildExtInfoSigAlgs(payload, sizeof(payload), sigAlgs);
    AssertIntEQ(wolfSSH_TestDoExtInfo(ssh, payload, payloadSz, &idx),
            WS_SUCCESS);
    AssertIntEQ(ssh->peerSigIdSz, 1);
    AssertIntEQ(ssh->peerSigId[0], ID_ED25519);
}

/* Walk the fields of the sent USERAUTH_REQUEST and hand back the trailing
 * signature. */
static void ParseUserAuthSignature(const byte* packet, word32 packetSz,
        word32* sigSz, const byte** sig)
{
    const byte* payload;
    const byte* field;
    word32 payloadSz;
    word32 fieldSz;
    word32 idx = 0;
    byte hasSignature = 0;
    int i;

    AssertIntEQ(ParseMsgId(packet, packetSz), MSGID_USERAUTH_REQUEST);
    payloadSz = ParsePayloadLen(packet, packetSz);
    payload = packet + UINT32_SZ + PAD_LENGTH_SZ + MSG_ID_SZ;
    payloadSz -= MSG_ID_SZ;

    /* user name, service name, method name */
    for (i = 0; i < 3; i++) {
        AssertIntEQ(GetStringRef(&fieldSz, &field, payload, payloadSz, &idx),
                WS_SUCCESS);
    }

    AssertIntEQ(GetBoolean(&hasSignature, payload, payloadSz, &idx),
            WS_SUCCESS);
    AssertIntEQ(hasSignature, 1);

    /* public key algorithm name and public key blob */
    AssertIntEQ(GetStringRef(&fieldSz, &field, payload, payloadSz, &idx),
            WS_SUCCESS);
    AssertIntEQ(GetStringRef(&fieldSz, &field, payload, payloadSz, &idx),
            WS_SUCCESS);

    AssertIntEQ(GetStringRef(sigSz, sig, payload, payloadSz, &idx),
            WS_SUCCESS);
    /* The signature ends the payload, which is what proves the room the
     * request reserved and the bytes it wrote agree. */
    AssertIntEQ(idx, payloadSz);
}

/* Stand up a client session that authenticates with an Ed25519 key held by
 * the mock agent. */
static void InitAgentEd25519Session(AgentEd25519Ctx* agentCtx,
        WOLFSSH_CTX** ctx, WOLFSSH** ssh, MemIo* io, byte* out, word32 outSz)
{
    *ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_CLIENT, NULL);
    AssertNotNull(*ctx);
    wolfSSH_SetIORecv(*ctx, MemRecv);
    wolfSSH_SetIOSend(*ctx, MemSend);
    wolfSSH_SetUserAuth(*ctx, AgentEd25519UserAuth);
    AssertIntEQ(wolfSSH_CTX_AGENT_enable(*ctx, 1), WS_SUCCESS);
    AssertIntEQ(wolfSSH_CTX_set_agent_cb(*ctx, AgentEd25519Cb,
            AgentEd25519IoCb), WS_SUCCESS);

    *ssh = wolfSSH_new(*ctx);
    AssertNotNull(*ssh);
    AssertNotNull((*ssh)->agent = wolfSSH_AGENT_new((*ctx)->heap));
    AssertIntEQ(wolfSSH_AGENT_enable(*ssh, 1), WS_SUCCESS);
    AssertIntEQ(wolfSSH_set_agent_cb_ctx(*ssh, agentCtx), WS_SUCCESS);
    wolfSSH_SetUserAuthCtx(*ssh, agentCtx);
    AssertIntEQ(wolfSSH_SetUsername(*ssh, "gretel"), WS_SUCCESS);

    MemIoInit(io, NULL, 0, out, outSz);
    wolfSSH_SetIOReadCtx(*ssh, io);
    wolfSSH_SetIOWriteCtx(*ssh, io);

    (*ssh)->sessionIdSz = WC_SHA256_DIGEST_SIZE;
    WMEMSET((*ssh)->sessionId, 0x33, (*ssh)->sessionIdSz);
    SetPeerSigAlgs(*ssh, AGENT_ED25519_NAME);
}

/* An agent-backed Ed25519 publickey request has to carry the signature the
 * agent produced. Leaving it out makes a request the server cannot parse. */
static void TestAgentEd25519UserAuthEmitsSignature(void)
{
    AgentEd25519Ctx agentCtx;
    WOLFSSH_CTX* ctx;
    WOLFSSH* ssh;
    MemIo io;
    byte out[512];
    const byte* sig = NULL;
    word32 sigSz = 0;

    InitAgentEd25519Ctx(&agentCtx, ED25519_SIG_SIZE);
    InitAgentEd25519Session(&agentCtx, &ctx, &ssh, &io, out,
            (word32)sizeof(out));

    AssertIntEQ(SendUserAuthRequest(ssh, WOLFSSH_USERAUTH_PUBLICKEY, 1),
            WS_SUCCESS);

    ParseUserAuthSignature(io.out, io.outSz, &sigSz, &sig);
    AssertIntEQ(sigSz, agentCtx.sigBlobSz);
    AssertIntEQ(WMEMCMP(sig, agentCtx.sigBlob, sigSz), 0);

    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);
}

/* An agent that answers nothing leaves the request unsigned. The error has
 * to reach the caller instead of a half-built request going out. */
static void TestAgentEd25519UserAuthPropagatesAgentError(void)
{
    AgentEd25519Ctx agentCtx;
    WOLFSSH_CTX* ctx;
    WOLFSSH* ssh;
    MemIo io;
    byte out[512];

    InitAgentEd25519Ctx(&agentCtx, ED25519_SIG_SIZE);
    agentCtx.responseSz = 0;
    InitAgentEd25519Session(&agentCtx, &ctx, &ssh, &io, out,
            (word32)sizeof(out));

    AssertIntEQ(SendUserAuthRequest(ssh, WOLFSSH_USERAUTH_PUBLICKEY, 1),
            WS_AGENT_NO_KEY_E);
    AssertIntEQ(io.outSz, 0);

    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);
}

/* The capacity the request hands the agent is the room it reserved. A blob
 * a byte past it has to be refused with nothing written. */
static void TestAgentEd25519UserAuthRejectsOversizeSignature(void)
{
    AgentEd25519Ctx agentCtx;
    WOLFSSH_CTX* ctx;
    WOLFSSH* ssh;
    MemIo io;
    byte out[512];

    InitAgentEd25519Ctx(&agentCtx, ED25519_SIG_SIZE + 1);
    InitAgentEd25519Session(&agentCtx, &ctx, &ssh, &io, out,
            (word32)sizeof(out));

    AssertIntEQ(SendUserAuthRequest(ssh, WOLFSSH_USERAUTH_PUBLICKEY, 1),
            WS_BUFFER_E);
    AssertIntEQ(io.outSz, 0);

    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);
}

#endif /* WOLFSSH_AGENT && !WOLFSSH_NO_ED25519 && !NO_WOLFSSH_CLIENT */



/* The client-side forwarding tests. They drive a client session, so they
 * run whether or not this build has a server. */
#if defined(WOLFSSH_FWD) && !defined(NO_WOLFSSH_CLIENT)

static word32 BuildRequestSuccessPortPacket(word32 port,
        byte* out, word32 outSz)
{
    byte payload[UINT32_SZ];
    word32 idx = 0;

    idx = AppendUint32(payload, sizeof(payload), idx, port);

    return WrapPacket(MSGID_REQUEST_SUCCESS, payload, idx, out, outSz);
}

/* Swap in one packet and run a receive pass, dropping whatever the client
 * wrote earlier so the response starts at offset 0. */
static int FeedOnePacket(ChannelOpenHarness* harness, byte* pkt, word32 pktSz)
{
    harness->io.in    = pkt;
    harness->io.inSz  = pktSz;
    harness->io.inOff = 0;
    harness->io.outSz = 0;

    return DoReceive(harness->ssh);
}

static void FeedRequestSuccess(ChannelOpenHarness* harness)
{
    byte reply[64];
    word32 replySz;

    replySz = WrapPacket(MSGID_REQUEST_SUCCESS, NULL, 0, reply, sizeof(reply));
    AssertIntEQ(FeedOnePacket(harness, reply, replySz), WS_SUCCESS);
}

static void FeedRequestFailure(ChannelOpenHarness* harness)
{
    byte reply[64];
    word32 replySz;

    replySz = WrapPacket(MSGID_REQUEST_FAILURE, NULL, 0, reply, sizeof(reply));
    AssertIntEQ(FeedOnePacket(harness, reply, replySz), WS_SUCCESS);
}

static word32 BuildForwardedTcpipOpen(const char* openAddr, word32 openPort,
        byte* out, word32 outSz)
{
    byte extra[128];
    word32 extraSz;

    extraSz = BuildDirectTcpipExtra(openAddr, openPort, "10.0.0.5", 4321,
            extra, sizeof(extra));

    return BuildChannelOpenPacket("forwarded-tcpip", 9, 0x4000, 0x8000,
            extra, extraSz, out, outSz);
}

/* A refused open asserts the channel list is empty, so within one harness
 * every refusal has to be checked before the first accepted open. */
static void AssertForwardedOpenRefused(ChannelOpenHarness* harness,
        const char* openAddr, word32 openPort)
{
    byte in[192];
    word32 inSz;
    int ret;

    inSz = BuildForwardedTcpipOpen(openAddr, openPort, in, sizeof(in));

    ret = FeedOnePacket(harness, in, inSz);
    AssertChannelOpenFailResponse(harness, ret);
    AssertIntEQ(ParseChannelOpenFailReason(harness->io.out, harness->io.outSz),
            OPEN_ADMINISTRATIVELY_PROHIBITED);
}

static void AssertForwardedOpenAccepted(ChannelOpenHarness* harness,
        const char* openAddr, word32 openPort, word32 expectChannels)
{
    byte in[192];
    word32 inSz;
    int ret;

    inSz = BuildForwardedTcpipOpen(openAddr, openPort, in, sizeof(in));

    ret = FeedOnePacket(harness, in, inSz);
    AssertIntEQ(ret, WS_SUCCESS);
    AssertTrue(harness->io.outSz > 0);
    AssertIntEQ(ParseMsgId(harness->io.out, harness->io.outSz),
            MSGID_CHANNEL_OPEN_CONF);
    AssertIntEQ(harness->ssh->channelListSz, expectChannels);
}

/* A client past userauth with the accepting fwdCb and no pending input. */
static void InitFwdRemoteHarness(ChannelOpenHarness* harness)
{
    InitChannelOpenHarnessClient(harness, NULL, 0);
    AssertIntEQ(wolfSSH_CTX_SetFwdCb(harness->ctx, AcceptFwdCb, NULL),
            WS_SUCCESS);
}

/* Set up a client that asked for one remote forward, then hand it a
 * forwarded-tcpip open naming openAddr:openPort. The request the setup sends
 * is dropped from the output so the open's response starts at offset 0. */
static void RunForwardedTcpipMatchModeTest(byte match, const char* bindAddr,
        word32 bindPort, const char* openAddr, word32 openPort,
        int expectAccept)
{
    ChannelOpenHarness harness;
    byte extra[128];
    byte in[192];
    word32 extraSz;
    word32 inSz;
    int ret;

    extraSz = BuildDirectTcpipExtra(openAddr, openPort, "10.0.0.5", 4321,
            extra, sizeof(extra));
    inSz = BuildChannelOpenPacket("forwarded-tcpip", 9, 0x4000, 0x8000,
            extra, extraSz, in, sizeof(in));

    InitChannelOpenHarnessClient(&harness, in, inSz);
    AssertIntEQ(wolfSSH_CTX_SetFwdCb(harness.ctx, AcceptFwdCb, NULL),
            WS_SUCCESS);
    AssertIntEQ(wolfSSH_SetFwdRemoteMatch(harness.ssh, match), WS_SUCCESS);

    AssertIntEQ(wolfSSH_FwdRemoteSetup(harness.ssh, bindAddr, bindPort, 1),
            WS_SUCCESS);
    harness.io.outSz = 0;

    ret = DoReceive(harness.ssh);

    if (expectAccept) {
        AssertIntEQ(ret, WS_SUCCESS);
        AssertTrue(harness.io.outSz > 0);
        AssertIntEQ(ParseMsgId(harness.io.out, harness.io.outSz),
                MSGID_CHANNEL_OPEN_CONF);
        AssertIntEQ(harness.ssh->channelListSz, 1);
    }
    else {
        AssertChannelOpenFailResponse(&harness, ret);
        AssertIntEQ(ParseChannelOpenFailReason(harness.io.out,
                    harness.io.outSz), OPEN_ADMINISTRATIVELY_PROHIBITED);
    }

    FreeChannelOpenHarness(&harness);
}

static void RunForwardedTcpipMatchTest(const char* bindAddr, word32 bindPort,
        const char* openAddr, word32 openPort, int expectAccept)
{
    RunForwardedTcpipMatchModeTest(WOLFSSH_FWD_MATCH_STRICT, bindAddr,
            bindPort, openAddr, openPort, expectAccept);
}

static void TestForwardedTcpipRegisteredIsAccepted(void)
{
    /* The open names the forward the client registered, so it goes through. */
    RunForwardedTcpipMatchTest("127.0.0.1", 8080, "127.0.0.1", 8080, 1);
}

static void TestForwardedTcpipUnregisteredSendsOpenFail(void)
{
    /* RFC 4254 7.2: a forwarded-tcpip answers a forward the client asked for.
     * Neither of these was requested, so the peer invented them. */
    RunForwardedTcpipMatchTest("127.0.0.1", 8080, "10.0.0.1", 9999, 0);
    RunForwardedTcpipMatchTest("127.0.0.1", 8080, "127.0.0.1", 9999, 0);
    RunForwardedTcpipMatchTest("127.0.0.1", 8080, "10.0.0.1", 8080, 0);
}

static void TestForwardedTcpipWildcardBindMatchesAnyAddr(void)
{
    /* A wildcard bind doesn't pin down what the peer will echo back, so the
     * port alone decides the match. RFC 4254 7.1 names the empty string and
     * "::"; "*" and "0.0.0.0" are the common spellings. */
    RunForwardedTcpipMatchTest("0.0.0.0", 8080, "192.168.1.7", 8080, 1);
    RunForwardedTcpipMatchTest("0.0.0.0", 8080, "192.168.1.7", 9999, 0);

    RunForwardedTcpipMatchTest("", 8080, "192.168.1.7", 8080, 1);
    RunForwardedTcpipMatchTest("", 8080, "192.168.1.7", 9999, 0);

    RunForwardedTcpipMatchTest("*", 8080, "192.168.1.7", 8080, 1);
    RunForwardedTcpipMatchTest("*", 8080, "192.168.1.7", 9999, 0);

    RunForwardedTcpipMatchTest("::", 8080, "fe80::1", 8080, 1);
    RunForwardedTcpipMatchTest("::", 8080, "fe80::1", 9999, 0);

    /* The other spellings of the IPv6 any-address mean the same thing. */
    RunForwardedTcpipMatchTest("::0", 8080, "fe80::1", 8080, 1);
    RunForwardedTcpipMatchTest("0:0:0:0:0:0:0:0", 8080, "fe80::1", 8080, 1);
    RunForwardedTcpipMatchTest("::ffff:0.0.0.0", 8080, "192.168.1.7", 8080, 1);
}

static void TestForwardedTcpipCancelledSendsOpenFail(void)
{
    ChannelOpenHarness harness;
    byte extra[128];
    byte in[192];
    word32 extraSz;
    word32 inSz;
    int ret;

    extraSz = BuildDirectTcpipExtra("127.0.0.1", 8080, "10.0.0.5", 4321,
            extra, sizeof(extra));
    inSz = BuildChannelOpenPacket("forwarded-tcpip", 9, 0x4000, 0x8000,
            extra, extraSz, in, sizeof(in));

    InitChannelOpenHarnessClient(&harness, in, inSz);
    AssertIntEQ(wolfSSH_CTX_SetFwdCb(harness.ctx, AcceptFwdCb, NULL),
            WS_SUCCESS);

    /* Without want-reply there is nothing to wait for, so the cancel drops
     * the registration as it goes out. */
    AssertIntEQ(wolfSSH_FwdRemoteSetup(harness.ssh, "127.0.0.1", 8080, 0),
            WS_SUCCESS);
    AssertIntEQ(wolfSSH_FwdRemoteCancel(harness.ssh, "127.0.0.1", 8080, 0),
            WS_SUCCESS);
    harness.io.outSz = 0;

    ret = DoReceive(harness.ssh);
    AssertChannelOpenFailResponse(&harness, ret);

    FreeChannelOpenHarness(&harness);
}

static void TestForwardedTcpipPortZeroMatchesBoundPort(void)
{
    ChannelOpenHarness harness;
    byte extra[128];
    byte reply[64];
    byte in[192];
    word32 extraSz;
    word32 replySz;
    word32 inSz;
    int ret;

    replySz = BuildRequestSuccessPortPacket(REGRESS_FWD_ALLOC_PORT,
            reply, sizeof(reply));

    InitChannelOpenHarnessClient(&harness, reply, replySz);
    AssertIntEQ(wolfSSH_CTX_SetFwdCb(harness.ctx, AcceptFwdCb, NULL),
            WS_SUCCESS);

    /* Port 0 asks the peer to allocate. Until its reply names the port, the
     * registration has nothing to match on. */
    AssertIntEQ(wolfSSH_FwdRemoteSetup(harness.ssh, "127.0.0.1", 0, 1),
            WS_SUCCESS);
    harness.io.outSz = 0;

    ret = DoReceive(harness.ssh);
    AssertIntEQ(ret, WS_SUCCESS);

    /* An open on the port the peer reported now matches. */
    extraSz = BuildDirectTcpipExtra("127.0.0.1", REGRESS_FWD_ALLOC_PORT,
            "10.0.0.5", 4321, extra, sizeof(extra));
    inSz = BuildChannelOpenPacket("forwarded-tcpip", 9, 0x4000, 0x8000,
            extra, extraSz, in, sizeof(in));

    harness.io.in    = in;
    harness.io.inSz  = inSz;
    harness.io.inOff = 0;
    harness.io.outSz = 0;

    ret = DoReceive(harness.ssh);
    AssertIntEQ(ret, WS_SUCCESS);
    AssertTrue(harness.io.outSz > 0);
    AssertIntEQ(ParseMsgId(harness.io.out, harness.io.outSz),
            MSGID_CHANNEL_OPEN_CONF);
    AssertIntEQ(harness.ssh->channelListSz, 1);

    FreeChannelOpenHarness(&harness);
}

static void TestForwardedTcpipRefusedForwardSendsOpenFail(void)
{
    ChannelOpenHarness harness;
    byte extra[128];
    byte reply[64];
    byte in[192];
    word32 extraSz;
    word32 replySz;
    word32 inSz;
    int ret;

    replySz = WrapPacket(MSGID_REQUEST_FAILURE, NULL, 0, reply,
            sizeof(reply));

    InitChannelOpenHarnessClient(&harness, reply, replySz);
    AssertIntEQ(wolfSSH_CTX_SetFwdCb(harness.ctx, AcceptFwdCb, NULL),
            WS_SUCCESS);

    AssertIntEQ(wolfSSH_FwdRemoteSetup(harness.ssh, "127.0.0.1", 8080, 1),
            WS_SUCCESS);
    harness.io.outSz = 0;

    /* The peer refused the forward, so it bound no listener and nothing may
     * arrive for it. */
    ret = DoReceive(harness.ssh);
    AssertIntEQ(ret, WS_SUCCESS);

    extraSz = BuildDirectTcpipExtra("127.0.0.1", 8080, "10.0.0.5", 4321,
            extra, sizeof(extra));
    inSz = BuildChannelOpenPacket("forwarded-tcpip", 9, 0x4000, 0x8000,
            extra, extraSz, in, sizeof(in));

    harness.io.in    = in;
    harness.io.inSz  = inSz;
    harness.io.inOff = 0;
    harness.io.outSz = 0;

    ret = DoReceive(harness.ssh);
    AssertChannelOpenFailResponse(&harness, ret);

    FreeChannelOpenHarness(&harness);
}

static void TestForwardedTcpipUntrackedClientUnchanged(void)
{
    ChannelOpenHarness harness;
    byte extra[128];
    byte in[192];
    word32 extraSz;
    word32 inSz;
    int ret;

    extraSz = BuildDirectTcpipExtra("10.0.0.1", 9999, "10.0.0.5", 4321,
            extra, sizeof(extra));
    inSz = BuildChannelOpenPacket("forwarded-tcpip", 9, 0x4000, 0x8000,
            extra, extraSz, in, sizeof(in));

    InitChannelOpenHarnessClient(&harness, in, inSz);
    AssertIntEQ(wolfSSH_CTX_SetFwdCb(harness.ctx, AcceptFwdCb, NULL),
            WS_SUCCESS);

    /* A client that frames tcpip-forward itself registers nothing, so there
     * is no list to match against and its fwdCb stays the only gate. */
    ret = DoReceive(harness.ssh);
    AssertIntEQ(ret, WS_SUCCESS);
    AssertTrue(harness.io.outSz > 0);
    AssertIntEQ(ParseMsgId(harness.io.out, harness.io.outSz),
            MSGID_CHANNEL_OPEN_CONF);
    AssertIntEQ(harness.ssh->channelListSz, 1);

    FreeChannelOpenHarness(&harness);
}

static void TestForwardedTcpipCancelConfirmedSendsOpenFail(void)
{
    ChannelOpenHarness harness;

    InitFwdRemoteHarness(&harness);

    AssertIntEQ(wolfSSH_FwdRemoteSetup(harness.ssh, "127.0.0.1", 8080, 0),
            WS_SUCCESS);
    /* With want-reply the registration stays until the peer confirms, since
     * until then its listener may still be feeding channels. */
    AssertIntEQ(wolfSSH_FwdRemoteCancel(harness.ssh, "127.0.0.1", 8080, 1),
            WS_SUCCESS);

    FeedRequestSuccess(&harness);

    /* Confirmed, so the listener is down and nothing may arrive for it. */
    AssertForwardedOpenRefused(&harness, "127.0.0.1", 8080);

    FreeChannelOpenHarness(&harness);
}

/* Revoking is not the peer's decision to delay: the forward stops matching as
 * the cancel goes out, so a peer that never answers cannot hold a cancelled
 * forward open. */
static void TestForwardedTcpipCancelPendingStopsMatching(void)
{
    ChannelOpenHarness harness;

    InitFwdRemoteHarness(&harness);

    AssertIntEQ(wolfSSH_FwdRemoteSetup(harness.ssh, "127.0.0.1", 8080, 1),
            WS_SUCCESS);
    FeedRequestSuccess(&harness);

    AssertIntEQ(wolfSSH_FwdRemoteCancel(harness.ssh, "127.0.0.1", 8080, 1),
            WS_SUCCESS);

    /* No reply yet, and none needed. */
    AssertForwardedOpenRefused(&harness, "127.0.0.1", 8080);
    AssertNotNull(harness.ssh->fwdRemoteList);

    FreeChannelOpenHarness(&harness);
}

/* The registration is held while the cancel is unanswered, so a refusal can
 * put the forward back. */
static void TestForwardedTcpipCancelRefusedRestoresMatching(void)
{
    ChannelOpenHarness harness;

    InitFwdRemoteHarness(&harness);

    AssertIntEQ(wolfSSH_FwdRemoteSetup(harness.ssh, "127.0.0.1", 8080, 1),
            WS_SUCCESS);
    FeedRequestSuccess(&harness);

    AssertIntEQ(wolfSSH_FwdRemoteCancel(harness.ssh, "127.0.0.1", 8080, 1),
            WS_SUCCESS);
    AssertForwardedOpenRefused(&harness, "127.0.0.1", 8080);

    /* The peer kept its listener, so what it opens is asked for again. */
    FeedRequestFailure(&harness);
    AssertForwardedOpenAccepted(&harness, "127.0.0.1", 8080, 1);

    FreeChannelOpenHarness(&harness);
}

static void TestForwardedTcpipCancelRefusedKeepsForward(void)
{
    ChannelOpenHarness harness;

    InitFwdRemoteHarness(&harness);

    AssertIntEQ(wolfSSH_FwdRemoteSetup(harness.ssh, "127.0.0.1", 8080, 0),
            WS_SUCCESS);
    AssertIntEQ(wolfSSH_FwdRemoteCancel(harness.ssh, "127.0.0.1", 8080, 1),
            WS_SUCCESS);

    FeedRequestFailure(&harness);

    /* The peer refused the cancel, so its listener is still up and the
     * channels it opens are still ones the client asked for. */
    AssertForwardedOpenAccepted(&harness, "127.0.0.1", 8080, 1);

    FreeChannelOpenHarness(&harness);
}

static void TestForwardedTcpipUnmatchedCancelKeepsForward(void)
{
    ChannelOpenHarness harness;

    InitFwdRemoteHarness(&harness);

    AssertIntEQ(wolfSSH_FwdRemoteSetup(harness.ssh, "127.0.0.1", 8080, 0),
            WS_SUCCESS);

    /* Neither names the registered forward, so both drop nothing. */
    AssertIntEQ(wolfSSH_FwdRemoteCancel(harness.ssh, "10.0.0.1", 9999, 0),
            WS_SUCCESS);
    AssertIntEQ(wolfSSH_FwdRemoteCancel(harness.ssh, "127.0.0.1", 9999, 0),
            WS_SUCCESS);
    AssertIntEQ(wolfSSH_FwdRemoteCancel(harness.ssh, "10.0.0.1", 8080, 0),
            WS_SUCCESS);

    AssertForwardedOpenAccepted(&harness, "127.0.0.1", 8080, 1);

    FreeChannelOpenHarness(&harness);
}

/* A cancel sent while the setup's reply is still outstanding leaves two
 * replies owed on one forward. They have to be answered in send order, or the
 * setup's reply gets read as the cancel's. */
static void TestForwardedTcpipCancelBeforeSetupReply(void)
{
    ChannelOpenHarness harness;

    InitFwdRemoteHarness(&harness);

    AssertIntEQ(wolfSSH_FwdRemoteSetup(harness.ssh, "127.0.0.1", 8080, 1),
            WS_SUCCESS);
    AssertIntEQ(wolfSSH_FwdRemoteCancel(harness.ssh, "127.0.0.1", 8080, 1),
            WS_SUCCESS);

    /* The first reply answers the setup: the peer refused it and bound
     * nothing, so an open naming it is the peer's invention. */
    FeedRequestFailure(&harness);
    AssertForwardedOpenRefused(&harness, "127.0.0.1", 8080);

    /* The second answers the cancel. The forward it named is already gone,
     * so a confirmed cancel changes nothing. */
    FeedRequestSuccess(&harness);
    AssertForwardedOpenRefused(&harness, "127.0.0.1", 8080);

    FreeChannelOpenHarness(&harness);
}

/* The same overlap with both requests refused. The setup bound no listener,
 * so the cancel's refusal is only the peer saying it has none to drop, and
 * nothing is left to hold the registration open. */
static void TestForwardedTcpipSetupAndCancelBothRefusedDrops(void)
{
    ChannelOpenHarness harness;

    InitFwdRemoteHarness(&harness);

    AssertIntEQ(wolfSSH_FwdRemoteSetup(harness.ssh, "127.0.0.1", 8080, 1),
            WS_SUCCESS);
    AssertIntEQ(wolfSSH_FwdRemoteCancel(harness.ssh, "127.0.0.1", 8080, 1),
            WS_SUCCESS);

    /* The setup is refused, but the queued cancel still names the forward, so
     * it is held for that answer. */
    FeedRequestFailure(&harness);
    AssertNotNull(harness.ssh->fwdRemoteList);

    /* The cancel is refused too. Nothing establishes the forward and nothing
     * is owed an answer on it, so it goes rather than sitting unmatchable
     * until the session ends. */
    FeedRequestFailure(&harness);
    AssertNull(harness.ssh->fwdRemoteList);

    AssertForwardedOpenRefused(&harness, "127.0.0.1", 8080);

    FreeChannelOpenHarness(&harness);
}

/* The same overlap, but with a second forward outstanding behind it. The
 * cancelled forward's reply must not be spent on the one still waiting. */
static void TestForwardedTcpipCancelBeforeSetupReplyKeepsOther(void)
{
    ChannelOpenHarness harness;

    InitFwdRemoteHarness(&harness);

    AssertIntEQ(wolfSSH_FwdRemoteSetup(harness.ssh, "127.0.0.1", 8080, 1),
            WS_SUCCESS);
    AssertIntEQ(wolfSSH_FwdRemoteSetup(harness.ssh, "127.0.0.1", 9090, 1),
            WS_SUCCESS);
    AssertIntEQ(wolfSSH_FwdRemoteCancel(harness.ssh, "127.0.0.1", 8080, 1),
            WS_SUCCESS);

    /* Answers the first setup, which was refused. */
    FeedRequestFailure(&harness);
    AssertForwardedOpenRefused(&harness, "127.0.0.1", 8080);

    /* Answers the second setup, which the peer bound. */
    FeedRequestSuccess(&harness);
    AssertForwardedOpenAccepted(&harness, "127.0.0.1", 9090, 1);

    FreeChannelOpenHarness(&harness);
}

/* Asking for the same bind twice is one listener on the peer, so it is one
 * registration here and one cancel undoes it. */
static void TestForwardedTcpipDuplicateSetupIsOneForward(void)
{
    ChannelOpenHarness harness;

    InitFwdRemoteHarness(&harness);

    AssertIntEQ(wolfSSH_FwdRemoteSetup(harness.ssh, "127.0.0.1", 8080, 0),
            WS_SUCCESS);
    AssertIntEQ(wolfSSH_FwdRemoteSetup(harness.ssh, "127.0.0.1", 8080, 0),
            WS_SUCCESS);
    AssertIntEQ(wolfSSH_FwdRemoteCancel(harness.ssh, "127.0.0.1", 8080, 0),
            WS_SUCCESS);

    AssertForwardedOpenRefused(&harness, "127.0.0.1", 8080);

    FreeChannelOpenHarness(&harness);
}

/* A peer that already has the listener refuses the repeat bind. That refusal
 * answers only the second request, so the forward the first one established
 * has to survive it. */
static void TestForwardedTcpipDuplicateSetupRefusalKeepsForward(void)
{
    ChannelOpenHarness harness;

    InitFwdRemoteHarness(&harness);

    AssertIntEQ(wolfSSH_FwdRemoteSetup(harness.ssh, "127.0.0.1", 8080, 1),
            WS_SUCCESS);
    AssertIntEQ(wolfSSH_FwdRemoteSetup(harness.ssh, "127.0.0.1", 8080, 1),
            WS_SUCCESS);

    /* The peer bound the listener, then refused the duplicate. */
    FeedRequestSuccess(&harness);
    FeedRequestFailure(&harness);

    AssertForwardedOpenAccepted(&harness, "127.0.0.1", 8080, 1);

    FreeChannelOpenHarness(&harness);
}

/* The same pair answered the other way round: the first request is refused
 * while a second is still outstanding, so the forward waits on that one
 * instead of going on the first refusal. */
static void TestForwardedTcpipDuplicateSetupLaterSuccessBinds(void)
{
    ChannelOpenHarness harness;

    InitFwdRemoteHarness(&harness);

    AssertIntEQ(wolfSSH_FwdRemoteSetup(harness.ssh, "127.0.0.1", 8080, 1),
            WS_SUCCESS);
    AssertIntEQ(wolfSSH_FwdRemoteSetup(harness.ssh, "127.0.0.1", 8080, 1),
            WS_SUCCESS);

    FeedRequestFailure(&harness);
    FeedRequestSuccess(&harness);

    AssertForwardedOpenAccepted(&harness, "127.0.0.1", 8080, 1);

    FreeChannelOpenHarness(&harness);
}

/* Both requests refused leaves nothing bound, so the registration goes. */
static void TestForwardedTcpipDuplicateSetupBothRefusedDrops(void)
{
    ChannelOpenHarness harness;

    InitFwdRemoteHarness(&harness);

    AssertIntEQ(wolfSSH_FwdRemoteSetup(harness.ssh, "127.0.0.1", 8080, 1),
            WS_SUCCESS);
    AssertIntEQ(wolfSSH_FwdRemoteSetup(harness.ssh, "127.0.0.1", 8080, 1),
            WS_SUCCESS);

    FeedRequestFailure(&harness);
    FeedRequestFailure(&harness);

    AssertForwardedOpenRefused(&harness, "127.0.0.1", 8080);

    FreeChannelOpenHarness(&harness);
}

/* Asking for the bind again while its cancel is unanswered overrides that
 * cancel: however the peer answers it, only the new request's own reply says
 * whether the listener is up. */
static void TestForwardedTcpipSetupAfterPendingCancelKeepsForward(void)
{
    ChannelOpenHarness harness;

    InitFwdRemoteHarness(&harness);

    AssertIntEQ(wolfSSH_FwdRemoteSetup(harness.ssh, "127.0.0.1", 8080, 1),
            WS_SUCCESS);
    FeedRequestSuccess(&harness);

    AssertIntEQ(wolfSSH_FwdRemoteCancel(harness.ssh, "127.0.0.1", 8080, 1),
            WS_SUCCESS);
    AssertIntEQ(wolfSSH_FwdRemoteSetup(harness.ssh, "127.0.0.1", 8080, 1),
            WS_SUCCESS);

    /* Answers the overridden cancel, which now decides nothing. */
    FeedRequestSuccess(&harness);
    /* Answers the second setup, which is what binds the listener. */
    FeedRequestSuccess(&harness);

    AssertForwardedOpenAccepted(&harness, "127.0.0.1", 8080, 1);

    FreeChannelOpenHarness(&harness);
}

/* The same overlap where the peer refuses the re-setup. The earlier
 * confirmation cannot stand in for it, so nothing is left registered. */
static void TestForwardedTcpipSetupAfterPendingCancelRefusedDrops(void)
{
    ChannelOpenHarness harness;

    InitFwdRemoteHarness(&harness);

    AssertIntEQ(wolfSSH_FwdRemoteSetup(harness.ssh, "127.0.0.1", 8080, 1),
            WS_SUCCESS);
    FeedRequestSuccess(&harness);

    AssertIntEQ(wolfSSH_FwdRemoteCancel(harness.ssh, "127.0.0.1", 8080, 1),
            WS_SUCCESS);
    AssertIntEQ(wolfSSH_FwdRemoteSetup(harness.ssh, "127.0.0.1", 8080, 1),
            WS_SUCCESS);

    FeedRequestSuccess(&harness);
    FeedRequestFailure(&harness);

    AssertForwardedOpenRefused(&harness, "127.0.0.1", 8080);

    FreeChannelOpenHarness(&harness);
}

/* A refused cancel leaves its listener up, and a setup sent behind it names
 * that same listener rather than a second entry, so one later cancel revokes
 * the bind. */
static void TestForwardedTcpipRefusedCancelThenCancelDrops(void)
{
    ChannelOpenHarness harness;

    InitFwdRemoteHarness(&harness);

    AssertIntEQ(wolfSSH_FwdRemoteSetup(harness.ssh, "127.0.0.1", 8080, 1),
            WS_SUCCESS);
    FeedRequestSuccess(&harness);

    AssertIntEQ(wolfSSH_FwdRemoteCancel(harness.ssh, "127.0.0.1", 8080, 1),
            WS_SUCCESS);
    AssertIntEQ(wolfSSH_FwdRemoteSetup(harness.ssh, "127.0.0.1", 8080, 1),
            WS_SUCCESS);

    /* The refusal answers a cancel the later setup already overrode, and the
     * success answers that setup. */
    FeedRequestFailure(&harness);
    FeedRequestSuccess(&harness);

    AssertIntEQ(wolfSSH_FwdRemoteCancel(harness.ssh, "127.0.0.1", 8080, 1),
            WS_SUCCESS);
    FeedRequestSuccess(&harness);

    AssertForwardedOpenRefused(&harness, "127.0.0.1", 8080);

    FreeChannelOpenHarness(&harness);
}

/* Two cancels in flight on one bind. The first one's answer must not settle
 * the second's: a refusal there cannot bring the forward back while a cancel
 * the peer went on to confirm is still unanswered. */
static void TestForwardedTcpipOverlappingCancelsLastOneSettles(void)
{
    ChannelOpenHarness harness;

    InitFwdRemoteHarness(&harness);

    AssertIntEQ(wolfSSH_FwdRemoteSetup(harness.ssh, "127.0.0.1", 8080, 1),
            WS_SUCCESS);
    FeedRequestSuccess(&harness);

    AssertIntEQ(wolfSSH_FwdRemoteCancel(harness.ssh, "127.0.0.1", 8080, 1),
            WS_SUCCESS);
    AssertIntEQ(wolfSSH_FwdRemoteSetup(harness.ssh, "127.0.0.1", 8080, 1),
            WS_SUCCESS);
    AssertIntEQ(wolfSSH_FwdRemoteCancel(harness.ssh, "127.0.0.1", 8080, 1),
            WS_SUCCESS);

    /* The peer refused the first cancel, bound the setup, then honoured the
     * second cancel. Every answer is one a conforming peer can give. */
    FeedRequestFailure(&harness);
    FeedRequestSuccess(&harness);
    FeedRequestSuccess(&harness);

    /* The peer has no listener there, so nothing may arrive for it. */
    AssertTrue(harness.ssh->fwdRemoteList == NULL);
    AssertForwardedOpenRefused(&harness, "127.0.0.1", 8080);

    FreeChannelOpenHarness(&harness);
}

/* A cancel without want-reply is unconditional even with an earlier cancel
 * still unanswered: the registration goes as the request leaves. */
static void TestForwardedTcpipNoReplyCancelOverridesPending(void)
{
    ChannelOpenHarness harness;

    InitFwdRemoteHarness(&harness);

    AssertIntEQ(wolfSSH_FwdRemoteSetup(harness.ssh, "127.0.0.1", 8080, 1),
            WS_SUCCESS);
    FeedRequestSuccess(&harness);

    AssertIntEQ(wolfSSH_FwdRemoteCancel(harness.ssh, "127.0.0.1", 8080, 1),
            WS_SUCCESS);
    AssertIntEQ(wolfSSH_FwdRemoteCancel(harness.ssh, "127.0.0.1", 8080, 0),
            WS_SUCCESS);

    AssertTrue(harness.ssh->fwdRemoteList == NULL);
    AssertForwardedOpenRefused(&harness, "127.0.0.1", 8080);

    /* The first cancel is still owed an answer, and it now names nothing. */
    FeedRequestFailure(&harness);
    AssertForwardedOpenRefused(&harness, "127.0.0.1", 8080);

    FreeChannelOpenHarness(&harness);
}

static int MemoryErrorHighwaterCb(byte side, void* ctx)
{
    WOLFSSH_UNUSED(side);
    WOLFSSH_UNUSED(ctx);

    /* What a rekey that cannot allocate its handshake state returns. */
    return WS_MEMORY_E;
}

static int SocketErrorHighwaterCb(byte side, void* ctx)
{
    WOLFSSH_UNUSED(side);
    WOLFSSH_UNUSED(ctx);

    /* What a rekey whose own KEXINIT send fails returns, which is also what a
     * send that lost the packet returns. */
    return WS_SOCKET_ERROR_E;
}

static void RunForwardedTcpipPostSendErrorTest(WS_CallbackHighwater cb,
        int expectRet)
{
    ChannelOpenHarness harness;

    InitFwdRemoteHarness(&harness);

    wolfSSH_SetHighwaterCb(harness.ctx, 1, cb);
    /* Cross the mark on the request's own send. */
    harness.ssh->highwaterMark = 1;
    harness.ssh->txCount = 1;

    AssertIntEQ(wolfSSH_FwdRemoteSetup(harness.ssh, "127.0.0.1", 8080, 0),
            expectRet);
    AssertNotNull(harness.ssh->fwdRemoteList);
    AssertIntEQ(harness.ssh->fwdRemoteTracked, 1);

    harness.io.outSz = 0;

    /* Matching has to be live, or an accepted open would only mean the check
     * never ran. Refusals first: an open failure asserts an empty list. */
    AssertForwardedOpenRefused(&harness, "10.0.0.1", 9999);
    AssertForwardedOpenAccepted(&harness, "127.0.0.1", 8080, 1);

    FreeChannelOpenHarness(&harness);
}

/* The highwater callback runs after the last byte of the request is on the
 * wire, so an error it returns arrives with the peer already holding the
 * request. The return code cannot tell that from a send that lost the packet,
 * so what reached the wire has to. */
static void TestForwardedTcpipPostSendErrorStillRegisters(void)
{
    RunForwardedTcpipPostSendErrorTest(MemoryErrorHighwaterCb, WS_MEMORY_E);
    RunForwardedTcpipPostSendErrorTest(SocketErrorHighwaterCb,
            WS_SOCKET_ERROR_E);
}

/* A send that never reached the peer leaves the session exactly as it was:
 * nothing registered, nothing owed, and matching still off. */
static void TestForwardedTcpipFailedSendRegistersNothing(void)
{
    ChannelOpenHarness harness;

    InitFwdRemoteHarness(&harness);

    /* No room left in the transport, so MemSend reports a general error. */
    harness.io.outSz = harness.io.outCap;

    AssertIntEQ(wolfSSH_FwdRemoteSetup(harness.ssh, "127.0.0.1", 8080, 1),
            WS_SOCKET_ERROR_E);

    AssertTrue(harness.ssh->fwdRemoteList == NULL);
    AssertTrue(harness.ssh->fwdReplyHead == NULL);
    AssertTrue(harness.ssh->fwdReplyTail == NULL);
    AssertIntEQ(harness.ssh->fwdRemoteTracked, 0);

    FreeChannelOpenHarness(&harness);
}

static word32 FwdRemoteCount(WOLFSSH* ssh)
{
    WOLFSSH_FWD_REMOTE* cur;
    word32 count = 0;

    for (cur = ssh->fwdRemoteList; cur != NULL; cur = cur->next)
        count++;

    return count;
}

static int SetupDuringSendHighwaterCb(byte side, void* ctx)
{
    WOLFSSH* ssh = (WOLFSSH*)ctx;

    WOLFSSH_UNUSED(side);

    /* Reentering the library from here is the established pattern: the default
     * callback starts a rekey. */
    if (ssh != NULL)
        wolfSSH_FwdRemoteSetup(ssh, "127.0.0.1", 8080, 0);

    return WS_SUCCESS;
}

/* A callback the send runs can register the very bind the request in flight is
 * registering. One listener on the peer is one registration here, whichever
 * call links it first. */
static void TestForwardedTcpipReentrantSetupDuringSend(void)
{
    ChannelOpenHarness harness;

    InitFwdRemoteHarness(&harness);

    wolfSSH_SetHighwaterCb(harness.ctx, 1, SetupDuringSendHighwaterCb);
    wolfSSH_SetHighwaterCtx(harness.ssh, harness.ssh);
    /* Cross the mark on the request's own send. */
    harness.ssh->highwaterMark = 1;
    harness.ssh->txCount = 1;

    AssertIntEQ(wolfSSH_FwdRemoteSetup(harness.ssh, "127.0.0.1", 8080, 1),
            WS_SUCCESS);

    AssertIntEQ(FwdRemoteCount(harness.ssh), 1);

    harness.io.outSz = 0;
    AssertForwardedOpenAccepted(&harness, "127.0.0.1", 8080, 1);

    FreeChannelOpenHarness(&harness);
}

static int GlobalRequestDuringSendHighwaterCb(byte side, void* ctx)
{
    WOLFSSH* ssh = (WOLFSSH*)ctx;
    const byte req[] = "keepalive@openssh.com";

    WOLFSSH_UNUSED(side);

    /* This goes out behind the request being sent, so it has to be answered
     * behind it too. */
    if (ssh != NULL)
        wolfSSH_global_request(ssh, req, (word32)sizeof(req) - 1, 1);

    return WS_SUCCESS;
}

/* A want-reply request a callback sends from inside another request's send
 * leaves the wire in one order and the queue in another, unless the place in
 * the queue is claimed before the send rather than after it. */
static void TestForwardedTcpipReentrantRequestKeepsSendOrder(void)
{
    ChannelOpenHarness harness;

    InitFwdRemoteHarness(&harness);

    wolfSSH_SetHighwaterCb(harness.ctx, 1,
            GlobalRequestDuringSendHighwaterCb);
    wolfSSH_SetHighwaterCtx(harness.ssh, harness.ssh);
    /* Cross the mark on the forward request's own send. */
    harness.ssh->highwaterMark = 1;
    harness.ssh->txCount = 1;

    AssertIntEQ(wolfSSH_FwdRemoteSetup(harness.ssh, "127.0.0.1", 8080, 1),
            WS_SUCCESS);

    harness.io.outSz = 0;

    /* The forward went out first, so the first reply is its own: refused. */
    FeedRequestFailure(&harness);
    AssertForwardedOpenRefused(&harness, "127.0.0.1", 8080);

    /* The second answers the callback's request and touches no forward. */
    FeedRequestSuccess(&harness);
    AssertForwardedOpenRefused(&harness, "127.0.0.1", 8080);

    FreeChannelOpenHarness(&harness);
}

/* What the callback feeds back during the send, and whether it then sends a
 * request of its own. */
static byte replyDuringSendMsgId = MSGID_REQUEST_SUCCESS;
static const byte* replyDuringSendData;
static word32 replyDuringSendDataSz;
static int replyDuringSendRequests;

static int ReplyDuringSendHighwaterCb(byte side, void* ctx)
{
    ChannelOpenHarness* harness = (ChannelOpenHarness*)ctx;
    const byte req[] = "keepalive@openssh.com";
    byte reply[64];
    word32 replySz;

    WOLFSSH_UNUSED(side);

    if (harness != NULL) {
        /* The request is on the wire and its slot committed before this runs,
         * so a peer answering it at once answers a settled slot. The window
         * where the sender still owns it is the IO send callback's, covered
         * by the FromSend tests below. */
        replySz = WrapPacket(replyDuringSendMsgId, replyDuringSendData,
                replyDuringSendDataSz, reply, sizeof(reply));
        FeedOnePacket(harness, reply, replySz);

        /* A request sent after that answer takes a slot of its own, which the
         * allocator is free to place where the answered one was. */
        if (replyDuringSendRequests) {
            wolfSSH_global_request(harness->ssh, req,
                    (word32)sizeof(req) - 1, 1);
        }
    }

    return WS_SUCCESS;
}

static void InitReplyDuringSendHarness(ChannelOpenHarness* harness, byte msgId,
        const byte* data, word32 dataSz, int alsoRequests)
{
    replyDuringSendMsgId = msgId;
    replyDuringSendData = data;
    replyDuringSendDataSz = dataSz;
    replyDuringSendRequests = alsoRequests;

    InitFwdRemoteHarness(harness);

    wolfSSH_SetHighwaterCb(harness->ctx, 1, ReplyDuringSendHighwaterCb);
    wolfSSH_SetHighwaterCtx(harness->ssh, harness);
    /* Cross the mark on the request's own send. */
    harness->ssh->highwaterMark = 1;
    harness->ssh->txCount = 1;
}

/* A refusal from the post-send callback says the peer bound nothing. The
 * forward is registered by then, so the verdict has to unwind it rather than
 * be dropped, which would leave a refused forward matching. */
static void TestForwardedTcpipRefusalDuringSendDropsForward(void)
{
    ChannelOpenHarness harness;

    InitReplyDuringSendHarness(&harness, MSGID_REQUEST_FAILURE, NULL, 0, 0);

    AssertIntEQ(wolfSSH_FwdRemoteSetup(harness.ssh, "127.0.0.1", 8080, 1),
            WS_SUCCESS);

    AssertIntEQ(FwdRemoteCount(harness.ssh), 0);
    AssertTrue(harness.ssh->fwdReplyHead == NULL);
    AssertTrue(harness.ssh->fwdReplyTail == NULL);

    harness.io.outSz = 0;
    AssertForwardedOpenRefused(&harness, "127.0.0.1", 8080);

    FreeChannelOpenHarness(&harness);
}

/* A port-0 request answered from the post-send callback: the port the answer
 * named has to reach the registration, or it stays unmatchable for the life of
 * the session with nothing left to resolve it. */
static void TestForwardedTcpipPortZeroReplyDuringSendBinds(void)
{
    ChannelOpenHarness harness;
    byte port[UINT32_SZ];
    word32 portSz;

    portSz = AppendUint32(port, sizeof(port), 0, REGRESS_FWD_ALLOC_PORT);
    InitReplyDuringSendHarness(&harness, MSGID_REQUEST_SUCCESS, port, portSz,
            0);

    AssertIntEQ(wolfSSH_FwdRemoteSetup(harness.ssh, "127.0.0.1", 0, 1),
            WS_SUCCESS);

    AssertIntEQ(FwdRemoteCount(harness.ssh), 1);
    AssertIntEQ(harness.ssh->fwdRemoteList->portPending, 0);
    AssertIntEQ(harness.ssh->fwdRemoteList->bindPort, REGRESS_FWD_ALLOC_PORT);

    harness.io.outSz = 0;
    AssertForwardedOpenAccepted(&harness, "127.0.0.1", REGRESS_FWD_ALLOC_PORT,
            1);

    FreeChannelOpenHarness(&harness);
}

/* The answer frees a slot, and the request the callback sends next may be
 * handed the same address. A send that identified its own slot by address
 * alone would apply that request's answer to this forward. */
static void TestForwardedTcpipRequestAfterReplyDuringSend(void)
{
    ChannelOpenHarness harness;

    InitReplyDuringSendHarness(&harness, MSGID_REQUEST_SUCCESS, NULL, 0, 1);

    AssertIntEQ(wolfSSH_FwdRemoteSetup(harness.ssh, "127.0.0.1", 8080, 1),
            WS_SUCCESS);

    /* The peer bound the forward, and the keepalive is the one thing still
     * owed an answer. */
    AssertIntEQ(FwdRemoteCount(harness.ssh), 1);
    AssertNotNull(harness.ssh->fwdReplyHead);
    AssertTrue(harness.ssh->fwdReplyHead->entry == NULL);
    AssertTrue(harness.ssh->fwdReplyHead->next == NULL);

    /* So the keepalive being refused says nothing about the forward. */
    harness.io.outSz = 0;
    FeedRequestFailure(&harness);
    AssertIntEQ(FwdRemoteCount(harness.ssh), 1);

    harness.io.outSz = 0;
    AssertForwardedOpenAccepted(&harness, "127.0.0.1", 8080, 1);

    FreeChannelOpenHarness(&harness);
}

/* The answer pops the slot and frees it. The commit that follows the send has
 * to find the queue empty rather than write through a slot that is gone. */
static void TestForwardedTcpipReplyDuringSendTakesSlot(void)
{
    ChannelOpenHarness harness;

    InitReplyDuringSendHarness(&harness, MSGID_REQUEST_SUCCESS, NULL, 0, 0);

    AssertIntEQ(wolfSSH_FwdRemoteSetup(harness.ssh, "127.0.0.1", 8080, 1),
            WS_SUCCESS);

    /* The answer settled the forward and took its slot with it, so the queue
     * owes nothing further. */
    AssertTrue(harness.ssh->fwdReplyHead == NULL);
    AssertTrue(harness.ssh->fwdReplyTail == NULL);

    /* The peer bound the listener, so the forward stands confirmed. */
    AssertIntEQ(FwdRemoteCount(harness.ssh), 1);
    AssertIntEQ(harness.ssh->fwdRemoteList->confirmed, 1);

    harness.io.outSz = 0;
    AssertForwardedOpenRefused(&harness, "10.0.0.1", 9999);
    AssertForwardedOpenAccepted(&harness, "127.0.0.1", 8080, 1);

    FreeChannelOpenHarness(&harness);
}

/* The highwater callback runs after the request has committed, so the answers
 * it pumps in find a settled slot. The IO send callback is the one place a
 * peer's answer can still land while the sender owns its slot, and no
 * ordering closes that window: the callback reenters from inside the flush.
 * These drive the reply from there. */
typedef struct {
    ChannelOpenHarness* harness;
    byte msgId;
    const byte* data;
    word32 dataSz;
    word32 chunkSz;   /* short-write size, 0 to write the whole buffer */
    byte failNext;    /* fail the send that follows the answer */
    int calls;
} FwdReplyFromSend;

static FwdReplyFromSend fwdReplyFromSend;

static int FwdReplyFromSendCb(WOLFSSH* ssh, void* buf, word32 sz, void* ctx)
{
    FwdReplyFromSend* state = &fwdReplyFromSend;
    byte reply[64];
    word32 replySz;
    int ret;

    state->calls++;

    /* The answer is in, so the rest of the request never makes it out. */
    if (state->calls > 1 && state->failNext)
        return WS_CBIO_ERR_GENERAL;

    if (state->chunkSz != 0 && sz > state->chunkSz)
        sz = state->chunkSz;

    ret = MemSend(ssh, buf, sz, ctx);

    /* Enough of the request is on the wire for the peer to answer it, and the
     * send it answers has yet to commit. */
    if (state->calls == 1 && ret > 0 && state->harness != NULL) {
        replySz = WrapPacket(state->msgId, state->data, state->dataSz, reply,
                sizeof(reply));
        FeedOnePacket(state->harness, reply, replySz);
    }

    return ret;
}

static void InitReplyFromSendHarness(ChannelOpenHarness* harness, byte msgId,
        const byte* data, word32 dataSz)
{
    InitFwdRemoteHarness(harness);
    wolfSSH_SetIOSend(harness->ctx, FwdReplyFromSendCb);

    WMEMSET(&fwdReplyFromSend, 0, sizeof(fwdReplyFromSend));
    fwdReplyFromSend.harness = harness;
    fwdReplyFromSend.msgId = msgId;
    fwdReplyFromSend.data = data;
    fwdReplyFromSend.dataSz = dataSz;
}

/* The answer arrives with the slot still uncommitted, so its verdict parks
 * there for the commit to apply. The forward stands confirmed all the same. */
static void TestForwardedTcpipReplyFromSendCommits(void)
{
    ChannelOpenHarness harness;

    InitReplyFromSendHarness(&harness, MSGID_REQUEST_SUCCESS, NULL, 0);

    AssertIntEQ(wolfSSH_FwdRemoteSetup(harness.ssh, "127.0.0.1", 8080, 1),
            WS_SUCCESS);

    /* The parked verdict was applied and the slot freed with it. */
    AssertTrue(harness.ssh->fwdReplyHead == NULL);
    AssertTrue(harness.ssh->fwdReplyTail == NULL);
    AssertIntEQ(harness.ssh->fwdReplyCount, 0);

    AssertIntEQ(FwdRemoteCount(harness.ssh), 1);
    AssertIntEQ(harness.ssh->fwdRemoteList->confirmed, 1);

    harness.io.outSz = 0;
    AssertForwardedOpenRefused(&harness, "10.0.0.1", 9999);
    AssertForwardedOpenAccepted(&harness, "127.0.0.1", 8080, 1);

    FreeChannelOpenHarness(&harness);
}

/* A refusal parked the same way. The forward it names is registered by the
 * commit and unwound by the verdict the commit then applies, so nothing is
 * left matching a listener the peer never bound. */
static void TestForwardedTcpipRefusalFromSendDropsForward(void)
{
    ChannelOpenHarness harness;

    InitReplyFromSendHarness(&harness, MSGID_REQUEST_FAILURE, NULL, 0);

    AssertIntEQ(wolfSSH_FwdRemoteSetup(harness.ssh, "127.0.0.1", 8080, 1),
            WS_SUCCESS);

    AssertIntEQ(FwdRemoteCount(harness.ssh), 0);
    AssertTrue(harness.ssh->fwdReplyHead == NULL);

    /* Matching is on from the first registration, so the open is refused. */
    harness.io.outSz = 0;
    AssertForwardedOpenRefused(&harness, "127.0.0.1", 8080);

    FreeChannelOpenHarness(&harness);
}

/* A port-0 request answered in that window. The port the answer named has to
 * survive being parked, or the registration stays unmatchable for the life of
 * the session with nothing left to resolve it. */
static void TestForwardedTcpipPortZeroReplyFromSendBinds(void)
{
    ChannelOpenHarness harness;
    byte port[UINT32_SZ];
    word32 portSz;

    portSz = AppendUint32(port, sizeof(port), 0, REGRESS_FWD_ALLOC_PORT);
    InitReplyFromSendHarness(&harness, MSGID_REQUEST_SUCCESS, port, portSz);

    AssertIntEQ(wolfSSH_FwdRemoteSetup(harness.ssh, "127.0.0.1", 0, 1),
            WS_SUCCESS);

    AssertIntEQ(FwdRemoteCount(harness.ssh), 1);
    AssertIntEQ(harness.ssh->fwdRemoteList->portPending, 0);
    AssertIntEQ(harness.ssh->fwdRemoteList->bindPort, REGRESS_FWD_ALLOC_PORT);

    harness.io.outSz = 0;
    AssertForwardedOpenAccepted(&harness, "127.0.0.1", REGRESS_FWD_ALLOC_PORT,
            1);

    FreeChannelOpenHarness(&harness);
}

/* The peer answered what it had seen of the request, then the rest of the
 * send failed. The request never reached the peer whole, so the parked
 * verdict settles nothing and goes back with the slot. */
static void TestForwardedTcpipFailedSendDiscardsAnsweredSlot(void)
{
    ChannelOpenHarness harness;

    InitReplyFromSendHarness(&harness, MSGID_REQUEST_SUCCESS, NULL, 0);
    /* Short-write the request so a second send is owed, and lose that one. */
    fwdReplyFromSend.chunkSz = 8;
    fwdReplyFromSend.failNext = 1;

    AssertIntEQ(wolfSSH_FwdRemoteSetup(harness.ssh, "127.0.0.1", 8080, 1),
            WS_SOCKET_ERROR_E);

    /* The session is as it was: nothing registered, nothing owed. */
    AssertTrue(harness.ssh->fwdRemoteList == NULL);
    AssertTrue(harness.ssh->fwdReplyHead == NULL);
    AssertTrue(harness.ssh->fwdReplyTail == NULL);
    AssertIntEQ(harness.ssh->fwdReplyCount, 0);
    AssertIntEQ(harness.ssh->fwdRemoteTracked, 0);

    FreeChannelOpenHarness(&harness);
}

/* An answer settling an earlier request has to see the one still in its send
 * window, which names its forward by the bind it will register rather than by
 * the entry. Here a setup is refused while the cancel that follows it is on
 * its way out: the cancel is still owed an answer, so the forward it names
 * stays put for that answer to settle. */
static void TestForwardedTcpipRefusalFromSendSeesSendingCancel(void)
{
    ChannelOpenHarness harness;

    InitReplyFromSendHarness(&harness, MSGID_REQUEST_FAILURE, NULL, 0);
    /* The setup goes out on the plain transport; the cancel's send is the one
     * that answers it. */
    fwdReplyFromSend.harness = NULL;

    AssertIntEQ(wolfSSH_FwdRemoteSetup(harness.ssh, "127.0.0.1", 8080, 1),
            WS_SUCCESS);
    AssertIntEQ(FwdRemoteCount(harness.ssh), 1);
    AssertIntEQ(harness.ssh->fwdRemoteList->confirmed, 0);

    fwdReplyFromSend.harness = &harness;
    fwdReplyFromSend.calls = 0;
    harness.io.outSz = 0;

    AssertIntEQ(wolfSSH_FwdRemoteCancel(harness.ssh, "127.0.0.1", 8080, 1),
            WS_SUCCESS);

    /* The setup's refusal found the cancel mid-send naming the same bind, so
     * it left the forward for that cancel to answer for. */
    AssertIntEQ(FwdRemoteCount(harness.ssh), 1);
    AssertNotNull(harness.ssh->fwdReplyHead);
    AssertIntEQ(harness.ssh->fwdReplyHead->isCancel, 1);
    AssertTrue(harness.ssh->fwdReplyHead->entry == harness.ssh->fwdRemoteList);

    /* A cancel stops matching as it goes out, before the peer answers. */
    harness.io.outSz = 0;
    AssertForwardedOpenRefused(&harness, "127.0.0.1", 8080);

    /* The peer took the listener down, and nothing is left to hold the
     * registration. */
    harness.io.outSz = 0;
    FeedRequestSuccess(&harness);
    AssertIntEQ(FwdRemoteCount(harness.ssh), 0);
    AssertTrue(harness.ssh->fwdReplyHead == NULL);

    FreeChannelOpenHarness(&harness);
}

static int CancelAnsweredDuringSendHighwaterCb(byte side, void* ctx)
{
    ChannelOpenHarness* harness = (ChannelOpenHarness*)ctx;
    byte reply[64];
    word32 replySz;

    WOLFSSH_UNUSED(side);

    /* Answers the cancel queued ahead of the setup now going out. */
    if (harness != NULL) {
        replySz = WrapPacket(MSGID_REQUEST_SUCCESS, NULL, 0, reply,
                sizeof(reply));
        FeedOnePacket(harness, reply, replySz);
    }

    return WS_SUCCESS;
}

/* The peer confirming a cancel while a fresh setup for the same bind is still
 * in its send window. That setup's slot does not name the forward until it
 * commits, so a scan that only reads committed slots finds nothing standing
 * for the forward and unlinks it -- leaving a request on the wire the peer
 * will bind and no registration for its opens to match. */
static void TestForwardedTcpipCancelAnsweredDuringResetupKeepsForward(void)
{
    ChannelOpenHarness harness;

    InitFwdRemoteHarness(&harness);

    AssertIntEQ(wolfSSH_FwdRemoteSetup(harness.ssh, "127.0.0.1", 8080, 1),
            WS_SUCCESS);
    harness.io.outSz = 0;
    FeedRequestSuccess(&harness);
    AssertIntEQ(FwdRemoteCount(harness.ssh), 1);
    AssertIntEQ(harness.ssh->fwdRemoteList->confirmed, 1);

    /* The registration is held until the peer answers the cancel. */
    AssertIntEQ(wolfSSH_FwdRemoteCancel(harness.ssh, "127.0.0.1", 8080, 1),
            WS_SUCCESS);
    AssertIntEQ(FwdRemoteCount(harness.ssh), 1);

    /* Cross the mark on the re-setup's own send. */
    wolfSSH_SetHighwaterCb(harness.ctx, 1,
            CancelAnsweredDuringSendHighwaterCb);
    wolfSSH_SetHighwaterCtx(harness.ssh, &harness);
    harness.ssh->highwaterMark = 1;
    harness.ssh->highwaterFlag = 0;
    harness.ssh->txCount = 1;
    harness.io.outSz = 0;

    AssertIntEQ(wolfSSH_FwdRemoteSetup(harness.ssh, "127.0.0.1", 8080, 1),
            WS_SUCCESS);

    /* The cancel took the listener down and the setup asked for it back, so
     * the registration stands and waits on that answer instead of going. */
    AssertIntEQ(FwdRemoteCount(harness.ssh), 1);
    AssertIntEQ(harness.ssh->fwdRemoteList->confirmed, 0);
    AssertNotNull(harness.ssh->fwdReplyHead);
    AssertTrue(harness.ssh->fwdReplyHead->entry == harness.ssh->fwdRemoteList);
    AssertIntEQ(harness.ssh->fwdReplyHead->uncommitted, 0);
    AssertTrue(harness.ssh->fwdReplyHead->next == NULL);

    harness.io.outSz = 0;
    FeedRequestSuccess(&harness);
    AssertIntEQ(FwdRemoteCount(harness.ssh), 1);
    AssertIntEQ(harness.ssh->fwdRemoteList->confirmed, 1);

    harness.io.outSz = 0;
    AssertForwardedOpenAccepted(&harness, "127.0.0.1", 8080, 1);

    FreeChannelOpenHarness(&harness);
}

/* A peer that canonicalises the bind it echoes back has every open refused
 * under the default, so the port it was asked for can be made the whole
 * test. */
static int CancelFirstSetupHighwaterCb(byte side, void* ctx)
{
    WOLFSSH* ssh = (WOLFSSH*)ctx;

    WOLFSSH_UNUSED(side);

    if (ssh != NULL)
        wolfSSH_FwdRemoteCancel(ssh, "127.0.0.1", 8080, 0);

    return WS_SUCCESS;
}

/* The callback cancels the very forward the request in flight is establishing,
 * and with no earlier registration to find it has nothing to work from but
 * what this request left. The cancel went out behind the setup, so the peer
 * holds no listener and neither may this side. */
static void TestForwardedTcpipReentrantCancelOfFirstSetup(void)
{
    ChannelOpenHarness harness;

    InitFwdRemoteHarness(&harness);

    wolfSSH_SetHighwaterCb(harness.ctx, 1, CancelFirstSetupHighwaterCb);
    wolfSSH_SetHighwaterCtx(harness.ssh, harness.ssh);
    /* Cross the mark on the request's own send. */
    harness.ssh->highwaterMark = 1;
    harness.ssh->txCount = 1;

    AssertIntEQ(wolfSSH_FwdRemoteSetup(harness.ssh, "127.0.0.1", 8080, 0),
            WS_SUCCESS);

    AssertIntEQ(FwdRemoteCount(harness.ssh), 0);

    harness.io.outSz = 0;
    AssertForwardedOpenRefused(&harness, "127.0.0.1", 8080);

    FreeChannelOpenHarness(&harness);
}

static int SetupDuringCancelHighwaterCb(byte side, void* ctx)
{
    WOLFSSH* ssh = (WOLFSSH*)ctx;

    WOLFSSH_UNUSED(side);

    if (ssh != NULL)
        wolfSSH_FwdRemoteSetup(ssh, "127.0.0.1", 8080, 0);

    return WS_SUCCESS;
}

/* The same window the other way around: the callback re-establishes the
 * forward the cancel in flight is taking down. The setup went out behind the
 * cancel, so the peer binds a listener and this side keeps matching for it. */
static void TestForwardedTcpipReentrantSetupDuringCancel(void)
{
    ChannelOpenHarness harness;

    InitFwdRemoteHarness(&harness);

    AssertIntEQ(wolfSSH_FwdRemoteSetup(harness.ssh, "127.0.0.1", 8080, 0),
            WS_SUCCESS);

    wolfSSH_SetHighwaterCb(harness.ctx, 1, SetupDuringCancelHighwaterCb);
    wolfSSH_SetHighwaterCtx(harness.ssh, harness.ssh);
    harness.ssh->highwaterMark = 1;
    harness.ssh->txCount = 1;

    AssertIntEQ(wolfSSH_FwdRemoteCancel(harness.ssh, "127.0.0.1", 8080, 0),
            WS_SUCCESS);

    AssertIntEQ(FwdRemoteCount(harness.ssh), 1);

    harness.io.outSz = 0;
    AssertForwardedOpenRefused(&harness, "10.0.0.1", 9999);
    AssertForwardedOpenAccepted(&harness, "127.0.0.1", 8080, 1);

    FreeChannelOpenHarness(&harness);
}

static int InboundOpenDuringSendHighwaterCb(byte side, void* ctx)
{
    ChannelOpenHarness* harness = (ChannelOpenHarness*)ctx;

    WOLFSSH_UNUSED(side);

    /* The request is on the wire, so matching has to be live already: this is
     * the first setup, and until it registers nothing is tracked and every
     * open goes unchecked. */
    AssertIntEQ(harness->ssh->fwdRemoteTracked, 1);
    AssertForwardedOpenRefused(harness, "10.0.0.1", 9999);

    return WS_SUCCESS;
}

/* A callback that pumps the session sees the forwards the request in flight
 * established, not the ones it found on the way in. */
static void TestForwardedTcpipInboundOpenDuringSend(void)
{
    ChannelOpenHarness harness;

    InitFwdRemoteHarness(&harness);

    wolfSSH_SetHighwaterCb(harness.ctx, 1, InboundOpenDuringSendHighwaterCb);
    wolfSSH_SetHighwaterCtx(harness.ssh, &harness);
    harness.ssh->highwaterMark = 1;
    harness.ssh->txCount = 1;

    AssertIntEQ(wolfSSH_FwdRemoteSetup(harness.ssh, "127.0.0.1", 8080, 0),
            WS_SUCCESS);

    harness.io.outSz = 0;
    AssertForwardedOpenAccepted(&harness, "127.0.0.1", 8080, 1);

    FreeChannelOpenHarness(&harness);
}

static void TestFwdRemoteMatchPortIgnoresBindAddr(void)
{
    RunForwardedTcpipMatchModeTest(WOLFSSH_FWD_MATCH_STRICT, "localhost", 8080,
            "127.0.0.1", 8080, 0);
    RunForwardedTcpipMatchModeTest(WOLFSSH_FWD_MATCH_PORT, "localhost", 8080,
            "127.0.0.1", 8080, 1);

    /* Relaxing the address does not relax the port. */
    RunForwardedTcpipMatchModeTest(WOLFSSH_FWD_MATCH_PORT, "localhost", 8080,
            "127.0.0.1", 9999, 0);
}

/* Off is what wolfSSH did before the check existed: the open reaches the
 * channel-open policy callback whatever it names. */
static void TestFwdRemoteMatchOffAcceptsUnregistered(void)
{
    RunForwardedTcpipMatchModeTest(WOLFSSH_FWD_MATCH_OFF, "127.0.0.1", 8080,
            "10.0.0.1", 9999, 1);
}

static void TestFwdRemoteMatchRejectsBadSetting(void)
{
    ChannelOpenHarness harness;

    InitFwdRemoteHarness(&harness);

    AssertIntEQ(wolfSSH_SetFwdRemoteMatch(NULL, WOLFSSH_FWD_MATCH_OFF),
            WS_BAD_ARGUMENT);
    AssertIntEQ(wolfSSH_SetFwdRemoteMatch(harness.ssh,
                WOLFSSH_FWD_MATCH_OFF + 1), WS_BAD_ARGUMENT);

    /* A refused setting leaves the default in place. */
    AssertIntEQ(harness.ssh->fwdRemoteMatch, WOLFSSH_FWD_MATCH_STRICT);

    FreeChannelOpenHarness(&harness);
}

/* Only the peer gives a reply slot back, so a peer that never answers would
 * let the queue grow for the life of the session and lengthen every match.
 * Refusing has to happen before the request is framed: one whose slot was
 * never queued would mispair every later reply. */
static void TestFwdReplyQueueIsCapped(void)
{
    ChannelOpenHarness harness;
    const byte req[] = "keepalive@openssh.com";
    word32 i;

    InitFwdRemoteHarness(&harness);

    for (i = 0; i < WOLFSSH_MAX_FWD_REPLIES; i++) {
        harness.io.outSz = 0;
        AssertIntEQ(wolfSSH_global_request(harness.ssh, req,
                    (word32)sizeof(req) - 1, 1), WS_SUCCESS);
    }
    AssertIntEQ(harness.ssh->fwdReplyCount, WOLFSSH_MAX_FWD_REPLIES);

    harness.io.outSz = 0;
    AssertIntEQ(wolfSSH_global_request(harness.ssh, req,
                (word32)sizeof(req) - 1, 1), WS_RESOURCE_E);
    AssertIntEQ(harness.io.outSz, 0);
    AssertIntEQ(harness.ssh->fwdReplyCount, WOLFSSH_MAX_FWD_REPLIES);

    /* Forward requests share the queue, so they share the cap, and a refused
     * one registers nothing. */
    harness.io.outSz = 0;
    AssertIntEQ(wolfSSH_FwdRemoteSetup(harness.ssh, "127.0.0.1", 8080, 1),
            WS_RESOURCE_E);
    AssertIntEQ(harness.io.outSz, 0);
    AssertIntEQ(FwdRemoteCount(harness.ssh), 0);

    /* Without wantReply nothing is queued, so nothing is capped. */
    harness.io.outSz = 0;
    AssertIntEQ(wolfSSH_FwdRemoteSetup(harness.ssh, "127.0.0.1", 8080, 0),
            WS_SUCCESS);
    AssertIntEQ(FwdRemoteCount(harness.ssh), 1);

    /* An answer gives a slot back, and the next request fits in it. */
    harness.io.outSz = 0;
    FeedRequestSuccess(&harness);
    AssertIntEQ(harness.ssh->fwdReplyCount, WOLFSSH_MAX_FWD_REPLIES - 1);
    harness.io.outSz = 0;
    AssertIntEQ(wolfSSH_global_request(harness.ssh, req,
                (word32)sizeof(req) - 1, 1), WS_SUCCESS);

    FreeChannelOpenHarness(&harness);
}

static int CancelDuringSendHighwaterCb(byte side, void* ctx)
{
    WOLFSSH* ssh = (WOLFSSH*)ctx;

    WOLFSSH_UNUSED(side);

    if (ssh != NULL)
        wolfSSH_FwdRemoteCancel(ssh, "127.0.0.1", 8080, 0);

    return WS_SUCCESS;
}

/* The same window, with the callback taking the forward instead of adding it.
 * Committing against a registration resolved before the send would write to
 * freed memory and leave the queued slot naming it. */
static void TestForwardedTcpipReentrantCancelDuringSend(void)
{
    ChannelOpenHarness harness;

    InitFwdRemoteHarness(&harness);

    AssertIntEQ(wolfSSH_FwdRemoteSetup(harness.ssh, "127.0.0.1", 8080, 0),
            WS_SUCCESS);

    wolfSSH_SetHighwaterCb(harness.ctx, 1, CancelDuringSendHighwaterCb);
    wolfSSH_SetHighwaterCtx(harness.ssh, harness.ssh);
    harness.ssh->highwaterMark = 1;
    harness.ssh->txCount = 1;

    /* This one names the registration the callback cancels. */
    AssertIntEQ(wolfSSH_FwdRemoteSetup(harness.ssh, "127.0.0.1", 8080, 1),
            WS_SUCCESS);

    /* The cancel had no want-reply, so it took the registration as it went
     * out, and this request's own reply answers for nothing. */
    AssertIntEQ(FwdRemoteCount(harness.ssh), 0);

    harness.io.outSz = 0;
    FeedRequestFailure(&harness);
    AssertForwardedOpenRefused(&harness, "127.0.0.1", 8080);

    FreeChannelOpenHarness(&harness);
}

/* A want-reply global request the application framed itself answers nothing
 * of ours, so its reply must not be spent on a forward. */
static void TestForwardedTcpipAppRequestKeepsItsOwnReply(void)
{
    ChannelOpenHarness harness;
    const byte req[] = "keepalive@openssh.com";

    InitFwdRemoteHarness(&harness);

    AssertIntEQ(wolfSSH_global_request(harness.ssh, req,
                (word32)sizeof(req) - 1, 1), WS_SUCCESS);
    AssertIntEQ(wolfSSH_FwdRemoteSetup(harness.ssh, "127.0.0.1", 8080, 1),
            WS_SUCCESS);

    /* This answers the application's request, not the forward. */
    FeedRequestFailure(&harness);

    /* So the forward is still waiting, and its own reply binds it. */
    FeedRequestSuccess(&harness);
    AssertForwardedOpenAccepted(&harness, "127.0.0.1", 8080, 1);

    FreeChannelOpenHarness(&harness);
}

/* A would-block send still leaves the request framed and waiting to flush, so
 * the peer binds the listener and the forward has to be registered. */
static void TestForwardedTcpipWantWriteStillRegisters(void)
{
    ChannelOpenHarness harness;

    InitFwdRemoteHarness(&harness);

    harness.io.blockNext = 1;
    AssertIntEQ(wolfSSH_FwdRemoteSetup(harness.ssh, "127.0.0.1", 8080, 0),
            WS_WANT_WRITE);

    /* The request is still framed and waiting; let it out, then drop it so
     * the open's response starts at offset 0. */
    AssertIntEQ(wolfSSH_SendPacket(harness.ssh), WS_SUCCESS);
    AssertTrue(harness.io.outSz > 0);
    harness.io.outSz = 0;

    /* Matching has to be live, or "registered" would just mean the check
     * never ran: a bind nobody asked for is still refused. */
    AssertForwardedOpenRefused(&harness, "10.0.0.1", 9999);
    AssertForwardedOpenAccepted(&harness, "127.0.0.1", 8080, 1);

    FreeChannelOpenHarness(&harness);
}

/* A signal interrupts the send, which retries rather than reporting it, so the
 * request goes out and the forward registers like any other. */
static void TestForwardedTcpipInterruptedSendStillRegisters(void)
{
    ChannelOpenHarness harness;

    InitFwdRemoteHarness(&harness);

    harness.io.isrNext = 1;
    AssertIntEQ(wolfSSH_FwdRemoteSetup(harness.ssh, "127.0.0.1", 8080, 0),
            WS_SUCCESS);

    /* Retried and out, with nothing left framed and the session unharmed. */
    AssertTrue(harness.io.outSz > 0);
    AssertIntEQ(wolfSSH_OutputPending(harness.ssh), 0);
    AssertIntEQ(harness.ssh->connReset, 0);
    AssertIntEQ(harness.ssh->isClosed, 0);

    harness.io.outSz = 0;
    AssertForwardedOpenRefused(&harness, "10.0.0.1", 9999);
    AssertForwardedOpenAccepted(&harness, "127.0.0.1", 8080, 1);

    FreeChannelOpenHarness(&harness);
}

/* The same retry on a sender unrelated to forwarding: it is in
 * wolfSSH_SendPacket(), so it governs every send in the library. */
static void TestInterruptedSendRetriesForAnySender(void)
{
    ChannelOpenHarness harness;
    const byte req[] = "keepalive@openssh.com";

    InitFwdRemoteHarness(&harness);

    harness.io.isrNext = 1;
    AssertIntEQ(wolfSSH_global_request(harness.ssh, req,
                (word32)sizeof(req) - 1, 0), WS_SUCCESS);

    AssertTrue(harness.io.outSz > 0);
    AssertIntEQ(wolfSSH_OutputPending(harness.ssh), 0);

    FreeChannelOpenHarness(&harness);
}

/* A request the application sends without want-reply is answered by nothing,
 * so it must not take a place in the reply queue and eat the answer owed to an
 * outstanding tcpip-forward. */
static void TestGlobalRequestNoReplyQueuesNothing(void)
{
    ChannelOpenHarness harness;
    const byte req[] = "keepalive@openssh.com";

    InitFwdRemoteHarness(&harness);

    AssertIntEQ(wolfSSH_global_request(harness.ssh, req,
                (word32)sizeof(req) - 1, 0), WS_SUCCESS);
    AssertTrue(harness.ssh->fwdReplyHead == NULL);
    AssertTrue(harness.ssh->fwdReplyTail == NULL);

    /* So the forward sent behind it still gets its own answer. */
    AssertIntEQ(wolfSSH_FwdRemoteSetup(harness.ssh, "127.0.0.1", 8080, 1),
            WS_SUCCESS);
    FeedRequestFailure(&harness);

    AssertTrue(harness.ssh->fwdRemoteList == NULL);
    AssertForwardedOpenRefused(&harness, "127.0.0.1", 8080);

    FreeChannelOpenHarness(&harness);
}

/* A confirmed cancel tears down the listener a setup sent behind it will
 * rebind. What the old listener settled cannot outlive it: refuse that setup
 * and nothing may arrive for the bind. */
static void TestForwardedTcpipConfirmedCancelDropsEarlierSuccess(void)
{
    ChannelOpenHarness harness;

    InitFwdRemoteHarness(&harness);

    AssertIntEQ(wolfSSH_FwdRemoteSetup(harness.ssh, "127.0.0.1", 8080, 1),
            WS_SUCCESS);
    AssertIntEQ(wolfSSH_FwdRemoteCancel(harness.ssh, "127.0.0.1", 8080, 1),
            WS_SUCCESS);
    AssertIntEQ(wolfSSH_FwdRemoteSetup(harness.ssh, "127.0.0.1", 8080, 1),
            WS_SUCCESS);

    /* The peer bound the first, honoured the cancel, then refused to bind
     * again. Every answer is one a conforming peer can give. */
    FeedRequestSuccess(&harness);
    FeedRequestSuccess(&harness);
    FeedRequestFailure(&harness);

    AssertTrue(harness.ssh->fwdRemoteList == NULL);
    AssertForwardedOpenRefused(&harness, "127.0.0.1", 8080);

    FreeChannelOpenHarness(&harness);
}

/* The same three requests with the peer binding the last one: the forward
 * stands on that answer alone. */
static void TestForwardedTcpipConfirmedCancelThenSetupBinds(void)
{
    ChannelOpenHarness harness;

    InitFwdRemoteHarness(&harness);

    AssertIntEQ(wolfSSH_FwdRemoteSetup(harness.ssh, "127.0.0.1", 8080, 1),
            WS_SUCCESS);
    AssertIntEQ(wolfSSH_FwdRemoteCancel(harness.ssh, "127.0.0.1", 8080, 1),
            WS_SUCCESS);
    AssertIntEQ(wolfSSH_FwdRemoteSetup(harness.ssh, "127.0.0.1", 8080, 1),
            WS_SUCCESS);

    FeedRequestSuccess(&harness);
    FeedRequestSuccess(&harness);
    FeedRequestSuccess(&harness);

    AssertIntEQ(FwdRemoteCount(harness.ssh), 1);
    harness.io.outSz = 0;
    AssertForwardedOpenAccepted(&harness, "127.0.0.1", 8080, 1);

    FreeChannelOpenHarness(&harness);
}

/* A port-0 setup the peer answers with a port another registration already
 * stands for. There is one listener there, so the older registration is stale
 * and the bind is left with one entry. */
static void TestForwardedTcpipPortZeroReplyFoldsDuplicate(void)
{
    ChannelOpenHarness harness;
    byte reply[64];
    word32 replySz;

    InitFwdRemoteHarness(&harness);

    AssertIntEQ(wolfSSH_FwdRemoteSetup(harness.ssh, "127.0.0.1", 8080, 1),
            WS_SUCCESS);
    AssertIntEQ(wolfSSH_FwdRemoteSetup(harness.ssh, "127.0.0.1", 0, 1),
            WS_SUCCESS);

    FeedRequestSuccess(&harness);
    AssertIntEQ(FwdRemoteCount(harness.ssh), 2);

    /* The peer names the port the first registration already stands for. */
    replySz = BuildRequestSuccessPortPacket(8080, reply, sizeof(reply));
    AssertIntEQ(FeedOnePacket(&harness, reply, replySz), WS_SUCCESS);

    AssertIntEQ(FwdRemoteCount(harness.ssh), 1);

    /* One entry, so one cancel revokes the bind. */
    AssertIntEQ(wolfSSH_FwdRemoteCancel(harness.ssh, "127.0.0.1", 8080, 1),
            WS_SUCCESS);
    AssertForwardedOpenRefused(&harness, "127.0.0.1", 8080);

    FreeChannelOpenHarness(&harness);
}

/* A cancel queued against the entry the fold drops still names that bind, so
 * the surviving registration is what it answers for. */
static void TestForwardedTcpipPortZeroFoldSettlesQueuedCancel(void)
{
    ChannelOpenHarness harness;
    byte reply[64];
    word32 replySz;

    InitFwdRemoteHarness(&harness);

    AssertIntEQ(wolfSSH_FwdRemoteSetup(harness.ssh, "127.0.0.1", 8080, 1),
            WS_SUCCESS);
    AssertIntEQ(wolfSSH_FwdRemoteSetup(harness.ssh, "127.0.0.1", 0, 1),
            WS_SUCCESS);
    AssertIntEQ(wolfSSH_FwdRemoteCancel(harness.ssh, "127.0.0.1", 8080, 1),
            WS_SUCCESS);
    AssertIntEQ(FwdRemoteCount(harness.ssh), 2);

    /* The peer refused the explicit setup, but the cancel still names that
     * registration, so it stands for now. */
    FeedRequestFailure(&harness);
    AssertIntEQ(FwdRemoteCount(harness.ssh), 2);

    /* The port-0 request got the port the refused one asked for. One bind,
     * one registration. */
    replySz = BuildRequestSuccessPortPacket(8080, reply, sizeof(reply));
    AssertIntEQ(FeedOnePacket(&harness, reply, replySz), WS_SUCCESS);
    AssertIntEQ(FwdRemoteCount(harness.ssh), 1);

    /* The cancel went out after both setups, so it is the last word on the
     * bind and matching stops on it alone. */
    AssertForwardedOpenRefused(&harness, "127.0.0.1", 8080);

    /* Confirming it takes the merged registration down with it. */
    FeedRequestSuccess(&harness);
    AssertIntEQ(FwdRemoteCount(harness.ssh), 0);
    AssertForwardedOpenRefused(&harness, "127.0.0.1", 8080);

    FreeChannelOpenHarness(&harness);
}

static void TestForwardedTcpipRepliesPairInSendOrder(void)
{
    ChannelOpenHarness harness;

    InitFwdRemoteHarness(&harness);

    /* Replies carry no request id, so they pair with the outstanding
     * requests in the order those went out. */
    AssertIntEQ(wolfSSH_FwdRemoteSetup(harness.ssh, "127.0.0.1", 8080, 1),
            WS_SUCCESS);
    AssertIntEQ(wolfSSH_FwdRemoteSetup(harness.ssh, "127.0.0.1", 8081, 1),
            WS_SUCCESS);
    AssertIntEQ(wolfSSH_FwdRemoteSetup(harness.ssh, "127.0.0.1", 8082, 1),
            WS_SUCCESS);

    FeedRequestSuccess(&harness);
    FeedRequestFailure(&harness);
    FeedRequestSuccess(&harness);

    /* Only the second forward was refused. Refusals first: an open failure
     * asserts the channel list is empty. */
    AssertForwardedOpenRefused(&harness, "127.0.0.1", 8081);
    AssertForwardedOpenAccepted(&harness, "127.0.0.1", 8080, 1);
    AssertForwardedOpenAccepted(&harness, "127.0.0.1", 8082, 2);

    FreeChannelOpenHarness(&harness);
}

/* A port-0 request whose reply names no usable port leaves nothing to match
 * on, so the registration goes. */
static void RunForwardedTcpipBadPortReplyTest(const byte* reply,
        word32 replySz)
{
    ChannelOpenHarness harness;
    byte replyCopy[64];

    AssertTrue(replySz <= sizeof(replyCopy));
    WMEMCPY(replyCopy, reply, replySz);

    InitFwdRemoteHarness(&harness);

    AssertIntEQ(wolfSSH_FwdRemoteSetup(harness.ssh, "127.0.0.1", 0, 1),
            WS_SUCCESS);

    AssertIntEQ(FeedOnePacket(&harness, replyCopy, replySz), WS_SUCCESS);

    AssertForwardedOpenRefused(&harness, "127.0.0.1", REGRESS_FWD_ALLOC_PORT);

    FreeChannelOpenHarness(&harness);
}

static void TestForwardedTcpipUnusablePortReplySendsOpenFail(void)
{
    byte reply[64];
    word32 replySz;

    /* Port 0 is not a port the peer could have bound. */
    replySz = BuildRequestSuccessPortPacket(0, reply, sizeof(reply));
    RunForwardedTcpipBadPortReplyTest(reply, replySz);

    /* A port is 16 bits on the wire. */
    replySz = BuildRequestSuccessPortPacket(70000, reply, sizeof(reply));
    RunForwardedTcpipBadPortReplyTest(reply, replySz);

    /* Want-reply on a port-0 request means the reply carries the port; a
     * success without one names nothing. */
    replySz = WrapPacket(MSGID_REQUEST_SUCCESS, NULL, 0, reply, sizeof(reply));
    RunForwardedTcpipBadPortReplyTest(reply, replySz);
}

static void TestForwardedTcpipPortZeroOtherPortSendsOpenFail(void)
{
    ChannelOpenHarness harness;
    byte reply[64];
    word32 replySz;

    InitFwdRemoteHarness(&harness);

    AssertIntEQ(wolfSSH_FwdRemoteSetup(harness.ssh, "127.0.0.1", 0, 1),
            WS_SUCCESS);

    replySz = BuildRequestSuccessPortPacket(REGRESS_FWD_ALLOC_PORT,
            reply, sizeof(reply));
    AssertIntEQ(FeedOnePacket(&harness, reply, replySz), WS_SUCCESS);

    /* Once the reply resolves the port, that port is the only match. */
    AssertForwardedOpenRefused(&harness, "127.0.0.1",
            REGRESS_FWD_ALLOC_PORT + 1);
    AssertForwardedOpenAccepted(&harness, "127.0.0.1",
            REGRESS_FWD_ALLOC_PORT, 1);

    FreeChannelOpenHarness(&harness);
}

#endif /* WOLFSSH_FWD && !NO_WOLFSSH_CLIENT */


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
    byte data[8];
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

    /* The disconnect is terminal, not just this call's error. Later stream
     * calls must report it rather than clearing the error and reading or
     * writing more. */
    AssertTrue(ssh->disconnected);

    WMEMSET(data, 0, sizeof(data));
    ret = wolfSSH_stream_read(ssh, data, sizeof(data));
    AssertIntEQ(ret, WS_FATAL_ERROR);
    AssertIntEQ(wolfSSH_get_error(ssh), WS_DISCONNECT);

    ret = wolfSSH_stream_send(ssh, data, sizeof(data));
    AssertIntEQ(ret, WS_FATAL_ERROR);
    AssertIntEQ(wolfSSH_get_error(ssh), WS_DISCONNECT);

    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);
}


/* Append a bare session channel so the stream calls have a channel to work
 * on, the state a disconnect actually arrives in. */
static void AddSessionChannel(WOLFSSH* ssh)
{
    WOLFSSH_CHANNEL* ch;

    ch = ChannelNew(ssh, ID_CHANTYPE_SESSION, 1024, 1024);
    AssertNotNull(ch);
    AssertIntEQ(ChannelAppend(ssh, ch), WS_SUCCESS);
    ch->openConfirmed = 1;
    /* Credit the peer's window too. Left at 0, SendChannelData() bails with
     * WS_WINDOW_FULL before the wire, and the "nothing went out" checks
     * would hold with the gates removed. */
    ch->peerWindowSz = 1024;
    ch->peerMaxPacketSz = 1024;
}


/* The same received disconnect on an established session. Without a channel
 * the stream calls bail out on the NULL channel list before they reach
 * anything, so this is the case that shows the gate doing work. */
static void TestDisconnectTerminalWithChannel(void)
{
    WOLFSSH_CTX* ctx;
    WOLFSSH* ssh;
    MemIo io;
    byte in[128];
    byte out[128];
    byte data[8];
    word32 inSz;
    int ret;

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_CLIENT, NULL);
    AssertNotNull(ctx);

    wolfSSH_SetIORecv(ctx, MemRecv);
    wolfSSH_SetIOSend(ctx, MemSend);

    ssh = wolfSSH_new(ctx);
    AssertNotNull(ssh);
    AddSessionChannel(ssh);
    /* Past userauth, or the message filter blocks the sends on its own. */
    ssh->connectState = CONNECT_SERVER_USERAUTH_ACCEPT_DONE;

    inSz = BuildDisconnectPacket(WOLFSSH_DISCONNECT_BY_APPLICATION,
            in, sizeof(in));
    MemIoInit(&io, in, inSz, out, sizeof(out));
    wolfSSH_SetIOReadCtx(ssh, &io);
    wolfSSH_SetIOWriteCtx(ssh, &io);

    ret = DoReceive(ssh);
    AssertIntEQ(ret, WS_FATAL_ERROR);
    AssertIntEQ(wolfSSH_get_error(ssh), WS_DISCONNECT);
    AssertTrue(ssh->disconnected);

    WMEMSET(data, 0, sizeof(data));
    ret = wolfSSH_stream_read(ssh, data, sizeof(data));
    AssertIntEQ(ret, WS_FATAL_ERROR);
    AssertIntEQ(wolfSSH_get_error(ssh), WS_DISCONNECT);

    /* Nothing may go out on the channel either. */
    ret = wolfSSH_stream_send(ssh, data, sizeof(data));
    AssertIntEQ(ret, WS_FATAL_ERROR);
    AssertIntEQ(wolfSSH_get_error(ssh), WS_DISCONNECT);
    AssertIntEQ(io.outSz, 0);

    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);
}


/* The disconnect stops sends, not reads. Channel data that arrived before
 * it is still the caller's, and only once that runs dry does the read
 * report the disconnect. */
static void TestDisconnectDrainsBufferedData(void)
{
    WOLFSSH_CTX* ctx;
    WOLFSSH* ssh;
    MemIo io;
    byte in[128];
    byte out[128];
    byte data[16];
    byte payload[] = { 'h', 'e', 'l', 'l', 'o' };
    word32 inSz;
    int ret;

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_CLIENT, NULL);
    AssertNotNull(ctx);

    wolfSSH_SetIORecv(ctx, MemRecv);
    wolfSSH_SetIOSend(ctx, MemSend);

    ssh = wolfSSH_new(ctx);
    AssertNotNull(ssh);
    AddSessionChannel(ssh);

    AssertIntEQ(ChannelPutData(ssh->channelList, payload, sizeof(payload)),
            WS_SUCCESS);

    inSz = BuildDisconnectPacket(WOLFSSH_DISCONNECT_BY_APPLICATION,
            in, sizeof(in));
    MemIoInit(&io, in, inSz, out, sizeof(out));
    wolfSSH_SetIOReadCtx(ssh, &io);
    wolfSSH_SetIOWriteCtx(ssh, &io);

    ret = DoReceive(ssh);
    AssertIntEQ(ret, WS_FATAL_ERROR);
    AssertIntEQ(wolfSSH_get_error(ssh), WS_DISCONNECT);
    AssertTrue(ssh->disconnected);

    /* Peek is the drain gate the shell loops use, so it has to tell a
     * channel with data left from a session that is over. */
    ret = wolfSSH_stream_peek(ssh, NULL, 1);
    AssertIntEQ(ret, 1);

    WMEMSET(data, 0, sizeof(data));
    ret = wolfSSH_stream_read(ssh, data, sizeof(data));
    AssertIntEQ(ret, (int)sizeof(payload));
    AssertIntEQ(WMEMCMP(data, payload, sizeof(payload)), 0);

    /* Buffer is dry now, so the disconnect is what is left to report. */
    ret = wolfSSH_stream_peek(ssh, NULL, 1);
    AssertIntEQ(ret, WS_FATAL_ERROR);
    AssertIntEQ(wolfSSH_get_error(ssh), WS_DISCONNECT);

    ret = wolfSSH_stream_read(ssh, data, sizeof(data));
    AssertIntEQ(ret, WS_FATAL_ERROR);
    AssertIntEQ(wolfSSH_get_error(ssh), WS_DISCONNECT);

    /* With the channel gone there is no buffer left to drain, so both
     * report the disconnect rather than a bad argument. */
    AssertIntEQ(ChannelRemove(ssh, ssh->channelList->channel,
            WS_CHANNEL_ID_SELF), WS_SUCCESS);
    AssertNull(ssh->channelList);

    ret = wolfSSH_stream_peek(ssh, NULL, 1);
    AssertIntEQ(ret, WS_FATAL_ERROR);
    AssertIntEQ(wolfSSH_get_error(ssh), WS_DISCONNECT);

    ret = wolfSSH_stream_read(ssh, data, sizeof(data));
    AssertIntEQ(ret, WS_FATAL_ERROR);
    AssertIntEQ(wolfSSH_get_error(ssh), WS_DISCONNECT);

    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);
}


/* Every send entry point refuses after a disconnect, not just the stream
 * calls. wolfsshd and echoserver drive their channels through the
 * channel-id and extended-data calls and never touch wolfSSH_stream_send(). */
static void TestDisconnectBlocksEverySend(void)
{
    WOLFSSH_CTX* ctx;
    WOLFSSH* ssh;
    MemIo io;
    byte out[256];
    byte data[8];
    word32 quietSz;
    word32 channelId;
    int ret;

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_CLIENT, NULL);
    AssertNotNull(ctx);

    wolfSSH_SetIORecv(ctx, MemRecv);
    wolfSSH_SetIOSend(ctx, MemSend);

    ssh = wolfSSH_new(ctx);
    AssertNotNull(ssh);
    AddSessionChannel(ssh);
    channelId = ssh->channelList->channel;
    /* Past userauth, or the message filter blocks the sends on its own and
     * the wire check below proves nothing. */
    ssh->connectState = CONNECT_SERVER_USERAUTH_ACCEPT_DONE;

    MemIoInit(&io, NULL, 0, out, sizeof(out));
    wolfSSH_SetIOReadCtx(ssh, &io);
    wolfSSH_SetIOWriteCtx(ssh, &io);

    AssertIntEQ(wolfSSH_SendDisconnect(ssh, WOLFSSH_DISCONNECT_BY_APPLICATION),
            WS_SUCCESS);
    AssertTrue(ssh->disconnected);
    quietSz = io.outSz;

    WMEMSET(data, 0, sizeof(data));

    ret = wolfSSH_stream_send(ssh, data, sizeof(data));
    AssertIntEQ(ret, WS_FATAL_ERROR);
    AssertIntEQ(wolfSSH_get_error(ssh), WS_DISCONNECT);

    ret = wolfSSH_ChannelIdSend(ssh, channelId, data, sizeof(data));
    AssertIntEQ(ret, WS_FATAL_ERROR);
    AssertIntEQ(wolfSSH_get_error(ssh), WS_DISCONNECT);

    ret = wolfSSH_ChannelIdSendExt(ssh, channelId, data, sizeof(data));
    AssertIntEQ(ret, WS_FATAL_ERROR);
    AssertIntEQ(wolfSSH_get_error(ssh), WS_DISCONNECT);

    ret = wolfSSH_extended_data_send(ssh, data, sizeof(data));
    AssertIntEQ(ret, WS_FATAL_ERROR);
    AssertIntEQ(wolfSSH_get_error(ssh), WS_DISCONNECT);

    ret = wolfSSH_global_request(ssh, data, sizeof(data), 0);
    AssertIntEQ(ret, WS_FATAL_ERROR);
    AssertIntEQ(wolfSSH_get_error(ssh), WS_DISCONNECT);

    ret = wolfSSH_stream_exit(ssh, 0);
    AssertIntEQ(ret, WS_FATAL_ERROR);
    AssertIntEQ(wolfSSH_get_error(ssh), WS_DISCONNECT);

    ret = wolfSSH_TriggerKeyExchange(ssh);
    AssertIntEQ(ret, WS_FATAL_ERROR);
    AssertIntEQ(wolfSSH_get_error(ssh), WS_DISCONNECT);

    ret = wolfSSH_SendIgnore(ssh, data, sizeof(data));
    AssertIntEQ(ret, WS_FATAL_ERROR);
    AssertIntEQ(wolfSSH_get_error(ssh), WS_DISCONNECT);

    /* Including a second disconnect. */
    ret = wolfSSH_SendDisconnect(ssh, WOLFSSH_DISCONNECT_BY_APPLICATION);
    AssertIntEQ(ret, WS_FATAL_ERROR);
    AssertIntEQ(wolfSSH_get_error(ssh), WS_DISCONNECT);

    /* Not one byte left the session after the disconnect. */
    AssertIntEQ(io.outSz, quietSz);

    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);
}


/* Sending SSH_MSG_DISCONNECT ends the session the same way receiving one
 * does: RFC 4253 section 11.1 says the connection is over once the message
 * goes out, so the stream calls must refuse afterwards. */
static void TestSendDisconnectIsTerminal(void)
{
    WOLFSSH_CTX* ctx;
    WOLFSSH* ssh;
    MemIo io;
    byte out[128];
    byte data[8];
    int ret;

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_CLIENT, NULL);
    AssertNotNull(ctx);

    wolfSSH_SetIORecv(ctx, MemRecv);
    wolfSSH_SetIOSend(ctx, MemSend);

    ssh = wolfSSH_new(ctx);
    AssertNotNull(ssh);
    AddSessionChannel(ssh);
    /* Past userauth, or the message filter blocks the sends on its own. */
    ssh->connectState = CONNECT_SERVER_USERAUTH_ACCEPT_DONE;

    MemIoInit(&io, NULL, 0, out, sizeof(out));
    wolfSSH_SetIOReadCtx(ssh, &io);
    wolfSSH_SetIOWriteCtx(ssh, &io);

    ret = wolfSSH_SendDisconnect(ssh, WOLFSSH_DISCONNECT_BY_APPLICATION);
    AssertIntEQ(ret, WS_SUCCESS);
    AssertTrue(ssh->disconnected);
    AssertTrue(io.outSz > 0);

    WMEMSET(data, 0, sizeof(data));
    ret = wolfSSH_stream_send(ssh, data, sizeof(data));
    AssertIntEQ(ret, WS_FATAL_ERROR);
    AssertIntEQ(wolfSSH_get_error(ssh), WS_DISCONNECT);

    ret = wolfSSH_stream_read(ssh, data, sizeof(data));
    AssertIntEQ(ret, WS_FATAL_ERROR);
    AssertIntEQ(wolfSSH_get_error(ssh), WS_DISCONNECT);

    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);
}


/* The reads that drain what arrived before a disconnect must not put a
 * window adjust on the wire. The credit is parked on the channel instead,
 * so the read still reports its bytes rather than a send failure. */
static void TestDisconnectQuietWindowAdjust(void)
{
    WOLFSSH_CTX* ctx;
    WOLFSSH* ssh;
    WOLFSSH_CHANNEL* channel;
    MemIo io;
    byte in[128];
    byte out[256];
    byte payload[600];
    byte extPayload[64];
    byte data[600];
    word32 inSz;
    word32 windowSz;
    word32 pendingSz;
    int ret;

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_CLIENT, NULL);
    AssertNotNull(ctx);

    wolfSSH_SetIORecv(ctx, MemRecv);
    wolfSSH_SetIOSend(ctx, MemSend);

    ssh = wolfSSH_new(ctx);
    AssertNotNull(ssh);
    AddSessionChannel(ssh);
    channel = ssh->channelList;
    /* Past userauth, or the message filter blocks the adjust on its own and
     * the wire check below proves nothing. */
    ssh->connectState = CONNECT_SERVER_USERAUTH_ACCEPT_DONE;

    /* More than half the channel buffer, so draining it trips the window
     * update in _UpdateChannelWindow(). */
    WMEMSET(payload, 'a', sizeof(payload));
    AssertIntEQ(ChannelPutData(channel, payload, sizeof(payload)), WS_SUCCESS);

    /* Buffered stderr for the extended-data drain. */
    WMEMSET(extPayload, 'e', sizeof(extPayload));
    AssertIntEQ(GrowBuffer(&channel->extDataBuffer, sizeof(extPayload)),
            WS_SUCCESS);
    WMEMCPY(channel->extDataBuffer.buffer, extPayload, sizeof(extPayload));
    channel->extDataBuffer.length = sizeof(extPayload);
    channel->extDataBuffer.idx = 0;

    inSz = BuildDisconnectPacket(WOLFSSH_DISCONNECT_BY_APPLICATION,
            in, sizeof(in));
    MemIoInit(&io, in, inSz, out, sizeof(out));
    wolfSSH_SetIOReadCtx(ssh, &io);
    wolfSSH_SetIOWriteCtx(ssh, &io);

    ret = DoReceive(ssh);
    AssertIntEQ(ret, WS_FATAL_ERROR);
    AssertTrue(ssh->disconnected);
    io.outSz = 0;

    /* Two reads: the first leaves the index non-zero, the second is the one
     * with credit to return. */
    ret = wolfSSH_stream_read(ssh, data, 300);
    AssertIntEQ(ret, 300);
    ret = wolfSSH_stream_read(ssh, data, 300);
    AssertIntEQ(ret, 300);
    AssertIntEQ(io.outSz, 0);

    /* The credit is owed, not lost. The window update runs before the read
     * advances the index, so the second read is the one that credits the
     * first read's 300 bytes. */
    AssertIntEQ(channel->pendingWindowAdjust, 300);
    pendingSz = channel->pendingWindowAdjust;
    windowSz = channel->windowSz;

    ret = wolfSSH_extended_data_read(ssh, data, sizeof(extPayload));
    AssertIntEQ(ret, (int)sizeof(extPayload));
    AssertIntEQ(io.outSz, 0);
    AssertIntEQ(channel->pendingWindowAdjust,
            pendingSz + (word32)sizeof(extPayload));
    AssertIntEQ(channel->windowSz, windowSz + (word32)sizeof(extPayload));

    /* wolfsshd and echoserver read by channel ID, so cover that drain too. */
    AssertIntEQ(ChannelPutData(channel, payload, sizeof(payload)), WS_SUCCESS);
    ret = wolfSSH_ChannelIdRead(ssh, channel->channel, data, sizeof(payload));
    AssertIntEQ(ret, (int)sizeof(payload));
    AssertIntEQ(io.outSz, 0);

    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);
}


/* The channel-pointer and forwarding APIs are send calls too. */
static void TestDisconnectBlocksChannelAndFwdSends(void)
{
    WOLFSSH_CTX* ctx;
    WOLFSSH* ssh;
    WOLFSSH_CHANNEL* channel;
    MemIo io;
    byte out[256];
    byte data[8];
    word32 quietSz;

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_CLIENT, NULL);
    AssertNotNull(ctx);

    wolfSSH_SetIORecv(ctx, MemRecv);
    wolfSSH_SetIOSend(ctx, MemSend);

    ssh = wolfSSH_new(ctx);
    AssertNotNull(ssh);
    AddSessionChannel(ssh);
    channel = ssh->channelList;
    ssh->connectState = CONNECT_SERVER_USERAUTH_ACCEPT_DONE;

    MemIoInit(&io, NULL, 0, out, sizeof(out));
    wolfSSH_SetIOReadCtx(ssh, &io);
    wolfSSH_SetIOWriteCtx(ssh, &io);

    AssertIntEQ(wolfSSH_SendDisconnect(ssh, WOLFSSH_DISCONNECT_BY_APPLICATION),
            WS_SUCCESS);
    quietSz = io.outSz;

    WMEMSET(data, 0, sizeof(data));

    AssertIntEQ(wolfSSH_ChannelSend(channel, data, sizeof(data)),
            WS_FATAL_ERROR);
    AssertIntEQ(wolfSSH_get_error(ssh), WS_DISCONNECT);

    AssertIntEQ(wolfSSH_ChannelSendExt(channel, data, sizeof(data)),
            WS_FATAL_ERROR);
    AssertIntEQ(wolfSSH_get_error(ssh), WS_DISCONNECT);

    AssertIntEQ(wolfSSH_ChannelExit(channel), WS_FATAL_ERROR);
    AssertIntEQ(wolfSSH_get_error(ssh), WS_DISCONNECT);

#ifdef WOLFSSH_FWD
    AssertIntEQ(wolfSSH_FwdRemoteSetup(ssh, "127.0.0.1", 22, 0),
            WS_FATAL_ERROR);
    AssertIntEQ(wolfSSH_get_error(ssh), WS_DISCONNECT);

    AssertIntEQ(wolfSSH_FwdRemoteCancel(ssh, "127.0.0.1", 22, 0),
            WS_FATAL_ERROR);
    AssertIntEQ(wolfSSH_get_error(ssh), WS_DISCONNECT);

    AssertNull(wolfSSH_ChannelFwdNewLocal(ssh, "127.0.0.1", 22,
            "127.0.0.1", 22));
    AssertIntEQ(wolfSSH_get_error(ssh), WS_DISCONNECT);

    AssertNull(wolfSSH_ChannelFwdNewRemote(ssh, "127.0.0.1", 22,
            "127.0.0.1", 22));
    AssertIntEQ(wolfSSH_get_error(ssh), WS_DISCONNECT);
#endif

    /* The channel is still whole: nothing was torn down either. */
    AssertIntEQ(channel->eofTxd, 0);
    AssertIntEQ(channel->closeTxd, 0);
    AssertIntEQ(io.outSz, quietSz);

    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);
}


/* wolfSSH_stream_exit() answers like the rest of its family on a session
 * whose channel is already gone: the disconnect, not a bad argument. */
static void TestStreamExitReportsDisconnect(void)
{
    WOLFSSH_CTX* ctx;
    WOLFSSH* ssh;
    MemIo io;
    byte out[256];

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_CLIENT, NULL);
    AssertNotNull(ctx);

    wolfSSH_SetIORecv(ctx, MemRecv);
    wolfSSH_SetIOSend(ctx, MemSend);

    ssh = wolfSSH_new(ctx);
    AssertNotNull(ssh);
    AddSessionChannel(ssh);
    ssh->connectState = CONNECT_SERVER_USERAUTH_ACCEPT_DONE;

    MemIoInit(&io, NULL, 0, out, sizeof(out));
    wolfSSH_SetIOReadCtx(ssh, &io);
    wolfSSH_SetIOWriteCtx(ssh, &io);

    AssertIntEQ(wolfSSH_SendDisconnect(ssh, WOLFSSH_DISCONNECT_BY_APPLICATION),
            WS_SUCCESS);
    AssertIntEQ(ChannelRemove(ssh, ssh->channelList->channel,
            WS_CHANNEL_ID_SELF), WS_SUCCESS);
    AssertNull(ssh->channelList);

    AssertIntEQ(wolfSSH_stream_exit(ssh, 0), WS_FATAL_ERROR);
    AssertIntEQ(wolfSSH_get_error(ssh), WS_DISCONNECT);

    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);
}


/* wolfSSH_shutdown() is a send path too: no teardown on the wire, and no
 * wait for a close that will not come. */
static void TestShutdownQuietAfterDisconnect(void)
{
    WOLFSSH_CTX* ctx;
    WOLFSSH* ssh;
    WOLFSSH_CHANNEL* channel;
    MemIo io;
    byte in[128];
    byte out[256];
    word32 inSz;
    int ret;

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_CLIENT, NULL);
    AssertNotNull(ctx);

    wolfSSH_SetIORecv(ctx, MemRecv);
    wolfSSH_SetIOSend(ctx, MemSend);

    ssh = wolfSSH_new(ctx);
    AssertNotNull(ssh);
    AddSessionChannel(ssh);
    channel = ssh->channelList;
    /* Past userauth, or the message filter blocks the teardown on its own
     * and the wire check below proves nothing. */
    ssh->connectState = CONNECT_SERVER_USERAUTH_ACCEPT_DONE;

    inSz = BuildDisconnectPacket(WOLFSSH_DISCONNECT_BY_APPLICATION,
            in, sizeof(in));
    MemIoInit(&io, in, inSz, out, sizeof(out));
    wolfSSH_SetIOReadCtx(ssh, &io);
    wolfSSH_SetIOWriteCtx(ssh, &io);

    ret = DoReceive(ssh);
    AssertIntEQ(ret, WS_FATAL_ERROR);
    AssertTrue(ssh->disconnected);
    io.outSz = 0;

    /* Nothing left to tear down. */
    ret = wolfSSH_shutdown(ssh);
    AssertIntEQ(ret, WS_SUCCESS);
    AssertIntEQ(wolfSSH_get_error(ssh), WS_DISCONNECT);
    AssertIntEQ(io.outSz, 0);
    AssertIntEQ(channel->eofTxd, 0);
    AssertIntEQ(channel->closeTxd, 0);

    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);
}
/* A send callback that reports "would block" for its first ProbeWantWrite
 * calls, the way a full socket does. */
static int MemSendWantWriteCount;

static int MemSendWantWrite(WOLFSSH* ssh, void* buf, word32 sz, void* ctx)
{
    if (MemSendWantWriteCount > 0) {
        MemSendWantWriteCount--;
        return WS_CBIO_ERR_WANT_WRITE;
    }
    return MemSend(ssh, buf, sz, ctx);
}




/* The mark firing on the disconnect packet must not fail a send that
 * went out fine. */
static void TestHighwaterQuietAfterDisconnect(void)
{
    WOLFSSH_CTX* ctx;
    WOLFSSH* ssh;
    MemIo io;
    byte out[256];
    int ret;

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_CLIENT, NULL);
    AssertNotNull(ctx);

    wolfSSH_SetIORecv(ctx, MemRecv);
    wolfSSH_SetIOSend(ctx, MemSend);

    ssh = wolfSSH_new(ctx);
    AssertNotNull(ssh);
    AddSessionChannel(ssh);

    MemIoInit(&io, NULL, 0, out, sizeof(out));
    wolfSSH_SetIOReadCtx(ssh, &io);
    wolfSSH_SetIOWriteCtx(ssh, &io);

    /* Low enough that the disconnect packet trips it. */
    AssertIntEQ(wolfSSH_SetHighwater(ssh, 1), WS_SUCCESS);

    ret = wolfSSH_SendDisconnect(ssh, WOLFSSH_DISCONNECT_BY_APPLICATION);
    AssertIntEQ(ret, WS_SUCCESS);
    AssertTrue(ssh->highwaterFlag);
    AssertTrue(ssh->disconnected);

    /* The mark fired, but no key exchange was started. */
    AssertIntEQ(ssh->isKeying, 0);

    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);
}


/* A disconnect from the peer sets the same flag ours does, but leaves only
 * unrelated traffic queued. That traffic belongs to a session that is over,
 * so neither teardown call may push it out. */
static void TestPeerDisconnectKeepsTrafficQueued(int useShutdown)
{
    WOLFSSH_CTX* ctx;
    WOLFSSH* ssh;
    MemIo io;
    byte in[128];
    byte out[512];
    byte data[32];
    word32 inSz;
    int ret;

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_CLIENT, NULL);
    AssertNotNull(ctx);

    wolfSSH_SetIORecv(ctx, MemRecv);
    wolfSSH_SetIOSend(ctx, MemSendWantWrite);

    ssh = wolfSSH_new(ctx);
    AssertNotNull(ssh);
    AddSessionChannel(ssh);
    ssh->connectState = CONNECT_SERVER_USERAUTH_ACCEPT_DONE;

    inSz = BuildDisconnectPacket(WOLFSSH_DISCONNECT_BY_APPLICATION,
            in, sizeof(in));
    MemIoInit(&io, in, inSz, out, sizeof(out));
    wolfSSH_SetIOReadCtx(ssh, &io);
    wolfSSH_SetIOWriteCtx(ssh, &io);

    /* Channel data the socket would not take. */
    WMEMSET(data, 'x', sizeof(data));
    MemSendWantWriteCount = 1;
    AssertIntEQ(wolfSSH_stream_send(ssh, data, sizeof(data)),
            (int)sizeof(data));
    AssertIntEQ(wolfSSH_get_error(ssh), WS_WANT_WRITE);
    AssertTrue(wolfSSH_OutputPending(ssh));
    AssertIntEQ(io.outSz, 0);

    /* The peer disconnects while those bytes are still queued. */
    AssertIntEQ(DoReceive(ssh), WS_FATAL_ERROR);
    AssertTrue(ssh->disconnected);
    AssertFalse(ssh->disconnectTxd);
    AssertTrue(wolfSSH_OutputPending(ssh));

    if (useShutdown) {
        /* The socket takes bytes now, so only the gate keeps them back. */
        ret = wolfSSH_shutdown(ssh);
        AssertIntEQ(wolfSSH_get_error(ssh), WS_DISCONNECT);
    }
    else {
        ret = wolfSSH_SendDisconnect(ssh, WOLFSSH_DISCONNECT_BY_APPLICATION);
        AssertIntEQ(ret, WS_FATAL_ERROR);
        AssertIntEQ(wolfSSH_get_error(ssh), WS_DISCONNECT);
    }

    /* Not one byte of the stale channel data reached the peer. */
    AssertIntEQ(io.outSz, 0);
    AssertTrue(wolfSSH_OutputPending(ssh));

    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);
}


/* The queued-disconnect flush does not need a channel: the peer's close can
 * retire the last one between the short send and the shutdown. */
static void TestShutdownFlushesWithNoChannel(void)
{
    WOLFSSH_CTX* ctx;
    WOLFSSH* ssh;
    MemIo io;
    byte out[256];
    int ret;

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_CLIENT, NULL);
    AssertNotNull(ctx);

    wolfSSH_SetIORecv(ctx, MemRecv);
    wolfSSH_SetIOSend(ctx, MemSendWantWrite);

    ssh = wolfSSH_new(ctx);
    AssertNotNull(ssh);
    AddSessionChannel(ssh);
    ssh->connectState = CONNECT_SERVER_USERAUTH_ACCEPT_DONE;

    MemIoInit(&io, NULL, 0, out, sizeof(out));
    wolfSSH_SetIOReadCtx(ssh, &io);
    wolfSSH_SetIOWriteCtx(ssh, &io);

    MemSendWantWriteCount = 1;
    AssertIntEQ(wolfSSH_SendDisconnect(ssh, WOLFSSH_DISCONNECT_BY_APPLICATION),
            WS_WANT_WRITE);
    AssertTrue(ssh->disconnectTxd);
    AssertIntEQ(io.outSz, 0);

    AssertIntEQ(ChannelRemove(ssh, ssh->channelList->channel,
            WS_CHANNEL_ID_SELF), WS_SUCCESS);
    AssertNull(ssh->channelList);

    ret = wolfSSH_shutdown(ssh);
    AssertIntEQ(ret, WS_CHANNEL_CLOSED);
    AssertFalse(wolfSSH_OutputPending(ssh));
    AssertIntEQ(out[LENGTH_SZ + 1], MSGID_DISCONNECT);
    /* The flush finished, so the WS_WANT_WRITE that queued it is stale.
     * Leaving it sends the caller back for a write that is already done. */
    AssertIntEQ(wolfSSH_get_error(ssh), WS_DISCONNECT);

    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);
}


/* The highwater callback is the application's, and its return propagates out
 * of wolfSSH_SendPacket(). A mark firing on the disconnect packet must not
 * fail a send that went out fine, whoever owns the callback. */
static int RekeyingHighwaterCb(byte side, void* ctx)
{
    WOLFSSH* ssh = (WOLFSSH*)ctx;

    WOLFSSH_UNUSED(side);
    return wolfSSH_TriggerKeyExchange(ssh);
}

static void TestAppHighwaterQuietAfterDisconnect(void)
{
    WOLFSSH_CTX* ctx;
    WOLFSSH* ssh;
    MemIo io;
    byte out[256];

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_CLIENT, NULL);
    AssertNotNull(ctx);

    wolfSSH_SetIORecv(ctx, MemRecv);
    wolfSSH_SetIOSend(ctx, MemSend);
    /* Low enough that the disconnect packet trips it. */
    wolfSSH_SetHighwaterCb(ctx, 1, RekeyingHighwaterCb);

    ssh = wolfSSH_new(ctx);
    AssertNotNull(ssh);
    AddSessionChannel(ssh);
    wolfSSH_SetHighwaterCtx(ssh, ssh);
    ssh->connectState = CONNECT_SERVER_USERAUTH_ACCEPT_DONE;

    MemIoInit(&io, NULL, 0, out, sizeof(out));
    wolfSSH_SetIOReadCtx(ssh, &io);
    wolfSSH_SetIOWriteCtx(ssh, &io);

    AssertIntEQ(wolfSSH_SendDisconnect(ssh, WOLFSSH_DISCONNECT_BY_APPLICATION),
            WS_SUCCESS);
    AssertTrue(io.outSz > 0);
    AssertIntEQ(ssh->isKeying, 0);

    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);
}


/* A disconnect left queued by a short send still has to reach the peer.
 * The gate refuses new traffic, not a flush of what is already bundled. */
static void TestQueuedDisconnectFlushes(void)
{
    WOLFSSH_CTX* ctx;
    WOLFSSH* ssh;
    MemIo io;
    byte out[256];
    word32 sentSz;
    int ret;

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_CLIENT, NULL);
    AssertNotNull(ctx);

    wolfSSH_SetIORecv(ctx, MemRecv);
    wolfSSH_SetIOSend(ctx, MemSendWantWrite);

    ssh = wolfSSH_new(ctx);
    AssertNotNull(ssh);
    AddSessionChannel(ssh);
    ssh->connectState = CONNECT_SERVER_USERAUTH_ACCEPT_DONE;

    MemIoInit(&io, NULL, 0, out, sizeof(out));
    wolfSSH_SetIOReadCtx(ssh, &io);
    wolfSSH_SetIOWriteCtx(ssh, &io);

    MemSendWantWriteCount = 1;
    ret = wolfSSH_SendDisconnect(ssh, WOLFSSH_DISCONNECT_BY_APPLICATION);
    AssertIntEQ(ret, WS_WANT_WRITE);
    AssertTrue(ssh->disconnected);
    AssertIntEQ(io.outSz, 0);
    AssertTrue(wolfSSH_OutputPending(ssh));

    /* Calling again retries the queued packet rather than refusing it. */
    ret = wolfSSH_SendDisconnect(ssh, WOLFSSH_DISCONNECT_BY_APPLICATION);
    AssertIntEQ(ret, WS_SUCCESS);
    AssertFalse(wolfSSH_OutputPending(ssh));
    AssertTrue(io.outSz > 0);
    /* Unencrypted framing: length, padding length, then the message ID. */
    AssertIntEQ(out[LENGTH_SZ + 1], MSGID_DISCONNECT);
    sentSz = io.outSz;

    /* Nothing queued now, so a second disconnect is refused as before. */
    ret = wolfSSH_SendDisconnect(ssh, WOLFSSH_DISCONNECT_BY_APPLICATION);
    AssertIntEQ(ret, WS_FATAL_ERROR);
    AssertIntEQ(wolfSSH_get_error(ssh), WS_DISCONNECT);
    AssertIntEQ(io.outSz, sentSz);

    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);
}


/* wolfSSH_shutdown() after a short disconnect send: no teardown on the wire,
 * but the queued disconnect goes out. */
static void TestShutdownFlushesQueuedDisconnect(void)
{
    WOLFSSH_CTX* ctx;
    WOLFSSH* ssh;
    WOLFSSH_CHANNEL* channel;
    MemIo io;
    byte out[256];
    int ret;

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_CLIENT, NULL);
    AssertNotNull(ctx);

    wolfSSH_SetIORecv(ctx, MemRecv);
    wolfSSH_SetIOSend(ctx, MemSendWantWrite);

    ssh = wolfSSH_new(ctx);
    AssertNotNull(ssh);
    AddSessionChannel(ssh);
    channel = ssh->channelList;
    ssh->connectState = CONNECT_SERVER_USERAUTH_ACCEPT_DONE;

    MemIoInit(&io, NULL, 0, out, sizeof(out));
    wolfSSH_SetIOReadCtx(ssh, &io);
    wolfSSH_SetIOWriteCtx(ssh, &io);

    MemSendWantWriteCount = 1;
    AssertIntEQ(wolfSSH_SendDisconnect(ssh, WOLFSSH_DISCONNECT_BY_APPLICATION),
            WS_WANT_WRITE);
    AssertIntEQ(io.outSz, 0);

    ret = wolfSSH_shutdown(ssh);
    AssertIntEQ(ret, WS_SUCCESS);
    AssertFalse(wolfSSH_OutputPending(ssh));
    AssertIntEQ(out[LENGTH_SZ + 1], MSGID_DISCONNECT);

    /* The disconnect, and only the disconnect. */
    AssertIntEQ(channel->eofTxd, 0);
    AssertIntEQ(channel->closeTxd, 0);

    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);
}


/* A rekey that the peer abandons with a DISCONNECT never completes: only
 * NEWKEYS clears isKeying, and nothing more arrives. The read calls test
 * isKeying first, so they report WS_REKEYING forever and the caller's
 * "keep turning the crank" branch spins for the life of the connection.
 * A dead session outranks a rekey that can no longer finish. */
static void TestDisconnectOutranksRekey(void)
{
    WOLFSSH_CTX* ctx;
    WOLFSSH* ssh;
    WOLFSSH_CHANNEL* channel;
    MemIo io;
    byte in[128];
    byte out[256];
    byte payload[32];
    byte data[64];
    word32 inSz;
    int ret;

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_CLIENT, NULL);
    AssertNotNull(ctx);

    wolfSSH_SetIORecv(ctx, MemRecv);
    wolfSSH_SetIOSend(ctx, MemSend);

    ssh = wolfSSH_new(ctx);
    AssertNotNull(ssh);
    AddSessionChannel(ssh);
    channel = ssh->channelList;
    ssh->connectState = CONNECT_SERVER_USERAUTH_ACCEPT_DONE;

    /* Channel data that arrived before the rekey started. */
    WMEMSET(payload, 'a', sizeof(payload));
    AssertIntEQ(ChannelPutData(channel, payload, sizeof(payload)), WS_SUCCESS);

    /* The peer's KEXINIT, the way DoKexInit records it. */
    ssh->isKeying |= WOLFSSH_PEER_IS_KEYING;

    /* DISCONNECT is a transport-generic message, so the rekey filter in
     * IsMessageAllowed() lets it through. */
    inSz = BuildDisconnectPacket(WOLFSSH_DISCONNECT_BY_APPLICATION,
            in, sizeof(in));
    MemIoInit(&io, in, inSz, out, sizeof(out));
    wolfSSH_SetIOReadCtx(ssh, &io);
    wolfSSH_SetIOWriteCtx(ssh, &io);

    AssertIntEQ(DoReceive(ssh), WS_FATAL_ERROR);
    AssertTrue(ssh->disconnected);
    /* The rekey is stuck: no NEWKEYS is ever coming. */
    AssertTrue(ssh->isKeying != 0);
    io.outSz = 0;

    /* What arrived before the disconnect is still the caller's. */
    ret = wolfSSH_stream_peek(ssh, data, sizeof(data));
    AssertIntEQ(ret, (int)sizeof(payload));
    ret = wolfSSH_stream_read(ssh, data, sizeof(data));
    AssertIntEQ(ret, (int)sizeof(payload));

    /* Drained, so both report the disconnect instead of a rekey that will
     * never finish. */
    ret = wolfSSH_stream_peek(ssh, data, sizeof(data));
    AssertIntEQ(ret, WS_FATAL_ERROR);
    AssertIntEQ(wolfSSH_get_error(ssh), WS_DISCONNECT);
    ret = wolfSSH_stream_read(ssh, data, sizeof(data));
    AssertIntEQ(ret, WS_FATAL_ERROR);
    AssertIntEQ(wolfSSH_get_error(ssh), WS_DISCONNECT);

    /* The drain stayed quiet, as it does outside a rekey. */
    AssertIntEQ(io.outSz, 0);

    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);
}


/* wolfSSH_worker() is the other drive loop, and the one the SFTP and SCP
 * layers turn. Once the session is over it has nothing to drive: the
 * dispatch is skipped, so a post-disconnect message would leave
 * ssh->error at WS_SUCCESS and the worker would keep reporting a healthy
 * session for as long as the peer talks. It also outranks a rekey the peer
 * abandoned, which only NEWKEYS could clear. RFC 4253 section 11.1. */
static void TestWorkerReportsDisconnect(void)
{
    WOLFSSH_CTX* ctx;
    WOLFSSH* ssh;
    MemIo io;
    byte in[256];
    byte out[256];
    word32 inSz;
    word32 idx;

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_CLIENT, NULL);
    AssertNotNull(ctx);

    wolfSSH_SetIORecv(ctx, MemRecv);
    wolfSSH_SetIOSend(ctx, MemSend);

    ssh = wolfSSH_new(ctx);
    AssertNotNull(ssh);
    AddSessionChannel(ssh);
    ssh->connectState = CONNECT_SERVER_USERAUTH_ACCEPT_DONE;

    /* The peer's KEXINIT, the way DoKexInit records it. Nothing clears it
     * after the disconnect below, so it latches for the session. */
    ssh->isKeying |= WOLFSSH_PEER_IS_KEYING;

    /* The peer's disconnect, then a message behind it. An IGNORE draws no
     * reply of its own, so what goes out can only come from the worker. */
    idx = BuildDisconnectPacket(WOLFSSH_DISCONNECT_BY_APPLICATION,
            in, sizeof(in));
    inSz = idx + BuildPacket(MSGID_IGNORE, in + idx, sizeof(in) - idx);
    MemIoInit(&io, in, inSz, out, sizeof(out));
    wolfSSH_SetIOReadCtx(ssh, &io);
    wolfSSH_SetIOWriteCtx(ssh, &io);

    AssertIntEQ(wolfSSH_worker(ssh, NULL), WS_FATAL_ERROR);
    AssertIntEQ(wolfSSH_get_error(ssh), WS_DISCONNECT);
    AssertTrue(ssh->disconnected);
    AssertTrue(ssh->isKeying != 0);
    io.outSz = 0;

    /* The message behind it is still queued, and every further pass reports
     * the disconnect rather than the WS_SUCCESS of a skipped dispatch or the
     * WS_REKEYING of a rekey that cannot finish. */
    AssertIntEQ(wolfSSH_worker(ssh, NULL), WS_FATAL_ERROR);
    AssertIntEQ(wolfSSH_get_error(ssh), WS_DISCONNECT);
    AssertIntEQ(wolfSSH_worker(ssh, NULL), WS_FATAL_ERROR);
    AssertIntEQ(wolfSSH_get_error(ssh), WS_DISCONNECT);

    /* Nothing went out on any of them. */
    AssertIntEQ(io.outSz, 0);

    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);
}



#ifndef NO_WOLFSSH_SERVER

/* wolfSSH_accept() drives the handshake, so a session that is already over
 * must stop it the way it stops every other sender. The short-send case is
 * the sharp one: the pending-send block at the top would push out a
 * disconnect left queued by a short send and then count it as the handshake
 * message the state machine was waiting for. RFC 4253 section 11.1. */
static void TestDisconnectGatesAccept(void)
{
    WOLFSSH_CTX* ctx;
    WOLFSSH* ssh;
    MemIo io;
    byte in[128];
    byte out[512];
    word32 inSz;
    word32 quietSz;
    byte state;
    int ret;

    /* A local disconnect leaves ssh->error clear, so the "in error state"
     * test in wolfSSH_accept() never sees it. */
    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_SERVER, NULL);
    AssertNotNull(ctx);
    wolfSSH_SetIORecv(ctx, MemRecv);
    wolfSSH_SetIOSend(ctx, MemSend);

    ssh = wolfSSH_new(ctx);
    AssertNotNull(ssh);
    AddSessionChannel(ssh);
    /* Not one of the states wolfSSH_accept() holds back, so an unwanted
     * advance shows up in the assertions below. */
    ssh->acceptState = ACCEPT_SERVER_USERAUTH_SENT;

    MemIoInit(&io, NULL, 0, out, sizeof(out));
    wolfSSH_SetIOReadCtx(ssh, &io);
    wolfSSH_SetIOWriteCtx(ssh, &io);

    AssertIntEQ(wolfSSH_SendDisconnect(ssh, WOLFSSH_DISCONNECT_BY_APPLICATION),
            WS_SUCCESS);
    AssertTrue(ssh->disconnected);
    AssertIntEQ(wolfSSH_get_error(ssh), 0);
    quietSz = io.outSz;
    state = ssh->acceptState;

    ret = wolfSSH_accept(ssh);
    AssertIntEQ(ret, WS_FATAL_ERROR);
    AssertIntEQ(wolfSSH_get_error(ssh), WS_DISCONNECT);
    /* No handshake packet, and the state machine did not move. */
    AssertIntEQ(io.outSz, quietSz);
    AssertIntEQ(ssh->acceptState, state);

    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);

    /* Our disconnect short-sends, so it is sitting in the output buffer
     * with a flush owed. wolfSSH_shutdown() and wolfSSH_SendDisconnect()
     * own that flush; wolfSSH_accept() must leave it alone. */
    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_SERVER, NULL);
    AssertNotNull(ctx);
    wolfSSH_SetIORecv(ctx, MemRecv);
    wolfSSH_SetIOSend(ctx, MemSendWantWrite);

    ssh = wolfSSH_new(ctx);
    AssertNotNull(ssh);
    AddSessionChannel(ssh);
    /* Not one of the states wolfSSH_accept() holds back, so an unwanted
     * advance shows up in the assertions below. */
    ssh->acceptState = ACCEPT_SERVER_USERAUTH_SENT;

    MemIoInit(&io, NULL, 0, out, sizeof(out));
    wolfSSH_SetIOReadCtx(ssh, &io);
    wolfSSH_SetIOWriteCtx(ssh, &io);

    MemSendWantWriteCount = 1;
    AssertIntEQ(wolfSSH_SendDisconnect(ssh, WOLFSSH_DISCONNECT_BY_APPLICATION),
            WS_WANT_WRITE);
    AssertTrue(ssh->disconnected);
    AssertTrue(ssh->disconnectTxd);
    AssertTrue(wolfSSH_OutputPending(ssh));
    AssertIntEQ(io.outSz, 0);
    state = ssh->acceptState;

    ret = wolfSSH_accept(ssh);
    AssertIntEQ(ret, WS_FATAL_ERROR);
    AssertIntEQ(wolfSSH_get_error(ssh), WS_DISCONNECT);
    /* Still queued, and not mistaken for the awaited handshake message. */
    AssertIntEQ(io.outSz, 0);
    AssertTrue(wolfSSH_OutputPending(ssh));
    AssertIntEQ(ssh->acceptState, state);

    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);

    /* The peer's disconnect latches WS_DISCONNECT, which the error-state
     * test below the gate used to answer with WS_INVALID_STATE_E. */
    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_SERVER, NULL);
    AssertNotNull(ctx);
    wolfSSH_SetIORecv(ctx, MemRecv);
    wolfSSH_SetIOSend(ctx, MemSend);

    ssh = wolfSSH_new(ctx);
    AssertNotNull(ssh);
    AddSessionChannel(ssh);
    ssh->acceptState = ACCEPT_SERVER_USERAUTH_SENT;

    inSz = BuildDisconnectPacket(WOLFSSH_DISCONNECT_BY_APPLICATION,
            in, sizeof(in));
    MemIoInit(&io, in, inSz, out, sizeof(out));
    wolfSSH_SetIOReadCtx(ssh, &io);
    wolfSSH_SetIOWriteCtx(ssh, &io);

    AssertIntEQ(DoReceive(ssh), WS_FATAL_ERROR);
    AssertTrue(ssh->disconnected);
    AssertIntEQ(wolfSSH_get_error(ssh), WS_DISCONNECT);
    quietSz = io.outSz;
    state = ssh->acceptState;

    ret = wolfSSH_accept(ssh);
    AssertIntEQ(ret, WS_FATAL_ERROR);
    AssertIntEQ(wolfSSH_get_error(ssh), WS_DISCONNECT);
    AssertIntEQ(io.outSz, quietSz);
    AssertIntEQ(ssh->acceptState, state);

    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);
}

#endif /* !NO_WOLFSSH_SERVER */


#ifndef NO_WOLFSSH_CLIENT

/* The same gate on the client's driver, which has no error-state test of
 * its own. Split from the accept test so a single-sided build keeps the
 * coverage that applies to it. */
static void TestDisconnectGatesConnect(void)
{
    WOLFSSH_CTX* ctx;
    WOLFSSH* ssh;
    MemIo io;
    byte in[128];
    byte out[512];
    word32 inSz;
    byte state;
    int ret;

    /* wolfSSH_connect() has no error-state test of its own, so it reaches
     * the state machine after a disconnect from either side. */
    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_CLIENT, NULL);
    AssertNotNull(ctx);
    wolfSSH_SetIORecv(ctx, MemRecv);
    wolfSSH_SetIOSend(ctx, MemSendWantWrite);

    ssh = wolfSSH_new(ctx);
    AssertNotNull(ssh);
    AddSessionChannel(ssh);
    ssh->connectState = CONNECT_SERVER_USERAUTH_ACCEPT_DONE;

    MemIoInit(&io, NULL, 0, out, sizeof(out));
    wolfSSH_SetIOReadCtx(ssh, &io);
    wolfSSH_SetIOWriteCtx(ssh, &io);

    MemSendWantWriteCount = 1;
    AssertIntEQ(wolfSSH_SendDisconnect(ssh, WOLFSSH_DISCONNECT_BY_APPLICATION),
            WS_WANT_WRITE);
    AssertTrue(ssh->disconnected);
    AssertTrue(wolfSSH_OutputPending(ssh));
    AssertIntEQ(io.outSz, 0);
    state = ssh->connectState;

    ret = wolfSSH_connect(ssh);
    AssertIntEQ(ret, WS_FATAL_ERROR);
    AssertIntEQ(wolfSSH_get_error(ssh), WS_DISCONNECT);
    AssertIntEQ(io.outSz, 0);
    AssertTrue(wolfSSH_OutputPending(ssh));
    AssertIntEQ(ssh->connectState, state);

    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);

    /* The peer's disconnect reaches the same gate. */
    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_CLIENT, NULL);
    AssertNotNull(ctx);
    wolfSSH_SetIORecv(ctx, MemRecv);
    wolfSSH_SetIOSend(ctx, MemSend);

    ssh = wolfSSH_new(ctx);
    AssertNotNull(ssh);
    AddSessionChannel(ssh);
    ssh->connectState = CONNECT_SERVER_USERAUTH_ACCEPT_DONE;

    inSz = BuildDisconnectPacket(WOLFSSH_DISCONNECT_BY_APPLICATION,
            in, sizeof(in));
    MemIoInit(&io, in, inSz, out, sizeof(out));
    wolfSSH_SetIOReadCtx(ssh, &io);
    wolfSSH_SetIOWriteCtx(ssh, &io);

    AssertIntEQ(DoReceive(ssh), WS_FATAL_ERROR);
    AssertTrue(ssh->disconnected);
    AssertIntEQ(wolfSSH_get_error(ssh), WS_DISCONNECT);
    state = ssh->connectState;

    ret = wolfSSH_connect(ssh);
    AssertIntEQ(ret, WS_FATAL_ERROR);
    AssertIntEQ(wolfSSH_get_error(ssh), WS_DISCONNECT);
    AssertIntEQ(io.outSz, 0);
    AssertIntEQ(ssh->connectState, state);

    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);
}

#endif /* !NO_WOLFSSH_CLIENT */


/* The public senders sit behind the disconnect gate, but the replies the
 * library builds in answer to inbound traffic did not. A channel close
 * draws an EOF and a close of ours out of DoChannelClose(), and a channel
 * open a confirmation or a failure out of DoChannelOpen(); on a session
 * that is already over, none of that may reach the peer. RFC 4253
 * section 11.1. */
static void TestDisconnectSilencesInboundReplies(void)
{
    WOLFSSH_CTX* ctx;
    WOLFSSH* ssh;
    WOLFSSH_CHANNEL* channel;
    MemIo io;
    byte in[256];
    byte out[512];
    word32 inSz;
    word32 quietSz;
    word32 channelId;

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_CLIENT, NULL);
    AssertNotNull(ctx);

    wolfSSH_SetIORecv(ctx, MemRecv);
    wolfSSH_SetIOSend(ctx, MemSend);

    ssh = wolfSSH_new(ctx);
    AssertNotNull(ssh);
    AddSessionChannel(ssh);
    channel = ssh->channelList;
    channelId = channel->channel;
    /* Past userauth, or the message filter turns the inbound messages away
     * on its own and the wire check below proves nothing. */
    ssh->connectState = CONNECT_SERVER_USERAUTH_ACCEPT_DONE;

    inSz = BuildChannelClosePacket(channelId, in, sizeof(in));
    MemIoInit(&io, in, inSz, out, sizeof(out));
    wolfSSH_SetIOReadCtx(ssh, &io);
    wolfSSH_SetIOWriteCtx(ssh, &io);

    /* Our own disconnect goes out first, and is the last thing that may. */
    AssertIntEQ(wolfSSH_SendDisconnect(ssh, WOLFSSH_DISCONNECT_BY_APPLICATION),
            WS_SUCCESS);
    AssertTrue(ssh->disconnected);
    quietSz = io.outSz;
    AssertTrue(quietSz > 0);

    /* The peer's close arrives anyway: a caller's own wolfSSH_worker() loop
     * still reads after a disconnect, and shutdown's pump can find packets
     * queued behind the peer's DISCONNECT. A skipped packet
     * is not an error; assert that, so the quiet-wire checks below cannot
     * pass on a receive that never reached DoPacket(). */
    AssertIntEQ(DoReceive(ssh), WS_SUCCESS);

    /* No EOF and no close went out, and the handler never ran, so the
     * channel it would have torn down is still on the list. */
    AssertIntEQ(io.outSz, quietSz);
    AssertNotNull(ssh->channelList);
    AssertIntEQ(ssh->channelList->channel, channelId);
    AssertFalse(channel->eofTxd);
    AssertFalse(channel->closeTxd);

    /* A channel open is the other half: it answers with a confirmation or
     * a failure, and neither may go out now. */
    inSz = BuildChannelOpenPacket("session", 99, 1024, 1024, NULL, 0,
            in, sizeof(in));
    MemIoInit(&io, in, inSz, out, sizeof(out));
    io.outSz = quietSz;
    wolfSSH_SetIOReadCtx(ssh, &io);
    wolfSSH_SetIOWriteCtx(ssh, &io);

    AssertIntEQ(DoReceive(ssh), WS_SUCCESS);
    AssertIntEQ(io.outSz, quietSz);

    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);
}


/* Skipping the dispatch is all the gate does: the frame advance steps over
 * the whole packet on its own, so a packet behind a skipped one is still
 * found where it should be. And a DISCONNECT is not skipped -- DoDisconnect()
 * sends nothing, and it is what latches WS_DISCONNECT for the caller, so
 * swallowing the peer's would report a live session on a dead one. */
static void TestDisconnectKeepsStreamInStep(void)
{
    WOLFSSH_CTX* ctx;
    WOLFSSH* ssh;
    WOLFSSH_CHANNEL* channel;
    MemIo io;
    byte in[256];
    byte out[512];
    word32 inSz;
    word32 quietSz;
    word32 channelId;

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_CLIENT, NULL);
    AssertNotNull(ctx);

    wolfSSH_SetIORecv(ctx, MemRecv);
    wolfSSH_SetIOSend(ctx, MemSend);

    ssh = wolfSSH_new(ctx);
    AssertNotNull(ssh);
    AddSessionChannel(ssh);
    channel = ssh->channelList;
    channelId = channel->channel;
    ssh->connectState = CONNECT_SERVER_USERAUTH_ACCEPT_DONE;

    /* A channel close for the gate to skip, with the peer's disconnect behind
     * it in the same read. */
    inSz = BuildChannelClosePacket(channelId, in, sizeof(in));
    inSz += BuildDisconnectPacket(WOLFSSH_DISCONNECT_BY_APPLICATION,
            in + inSz, (word32)sizeof(in) - inSz);
    MemIoInit(&io, in, inSz, out, sizeof(out));
    wolfSSH_SetIOReadCtx(ssh, &io);
    wolfSSH_SetIOWriteCtx(ssh, &io);

    /* Ours goes out first, and is the last thing that may. */
    AssertIntEQ(wolfSSH_SendDisconnect(ssh, WOLFSSH_DISCONNECT_BY_APPLICATION),
            WS_SUCCESS);
    AssertTrue(ssh->disconnected);
    quietSz = io.outSz;
    AssertTrue(quietSz > 0);

    /* The close is skipped, so no reply and the channel stays. */
    AssertIntEQ(DoReceive(ssh), WS_SUCCESS);
    AssertIntEQ(io.outSz, quietSz);
    AssertNotNull(ssh->channelList);
    AssertIntEQ(ssh->channelList->channel, channelId);
    AssertFalse(channel->eofTxd);
    AssertFalse(channel->closeTxd);

    /* The disconnect behind it decodes and latches, and still answers
     * nothing. */
    AssertIntEQ(DoReceive(ssh), WS_FATAL_ERROR);
    AssertIntEQ(wolfSSH_get_error(ssh), WS_DISCONNECT);
    AssertIntEQ(io.outSz, quietSz);

    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);
}


/* Skipping the dispatch drops what arrives, it does not queue it: the gate
 * covers inbound data, not only replies. A caller that can no longer send has
 * nothing to do with it. Pinned because the read path still hands back data
 * that arrived before the disconnect, and the two are easy to confuse. */
static void TestDisconnectDropsLateChannelData(void)
{
    WOLFSSH_CTX* ctx;
    WOLFSSH* ssh;
    MemIo io;
    byte in[256];
    byte out[512];
    byte buf[32];
    word32 inSz;
    word32 channelId;

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_CLIENT, NULL);
    AssertNotNull(ctx);

    wolfSSH_SetIORecv(ctx, MemRecv);
    wolfSSH_SetIOSend(ctx, MemSend);

    ssh = wolfSSH_new(ctx);
    AssertNotNull(ssh);
    AddSessionChannel(ssh);
    channelId = ssh->channelList->channel;
    ssh->connectState = CONNECT_SERVER_USERAUTH_ACCEPT_DONE;

    inSz = BuildChannelDataPacket(channelId, "late", in, sizeof(in));
    MemIoInit(&io, in, inSz, out, sizeof(out));
    wolfSSH_SetIOReadCtx(ssh, &io);
    wolfSSH_SetIOWriteCtx(ssh, &io);

    AssertIntEQ(wolfSSH_SendDisconnect(ssh, WOLFSSH_DISCONNECT_BY_APPLICATION),
            WS_SUCCESS);
    AssertTrue(ssh->disconnected);

    /* Read it, and it is gone: nothing buffered on the channel. */
    AssertIntEQ(DoReceive(ssh), WS_SUCCESS);
    AssertNotNull(ssh->channelList);
    AssertIntEQ(ssh->channelList->inputBuffer.length
            - ssh->channelList->inputBuffer.idx, 0);

    /* So the read reports the dead session rather than the dropped bytes. */
    AssertIntEQ(wolfSSH_stream_read(ssh, buf, sizeof(buf)), WS_FATAL_ERROR);
    AssertIntEQ(wolfSSH_get_error(ssh), WS_DISCONNECT);

    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);
}

/* disconnectTxd means "a flush is owed", not "a disconnect was sent". Once
 * ours has gone out, a teardown call must not push whatever the internal
 * senders queued behind it. */
static void TestDisconnectTxdClearsOnFlush(void)
{
    WOLFSSH_CTX* ctx;
    WOLFSSH* ssh;
    WOLFSSH_CHANNEL* channel;
    MemIo io;
    byte out[512];
    int ret;

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_CLIENT, NULL);
    AssertNotNull(ctx);

    wolfSSH_SetIORecv(ctx, MemRecv);
    wolfSSH_SetIOSend(ctx, MemSendWantWrite);

    ssh = wolfSSH_new(ctx);
    AssertNotNull(ssh);
    AddSessionChannel(ssh);
    channel = ssh->channelList;
    ssh->connectState = CONNECT_SERVER_USERAUTH_ACCEPT_DONE;

    MemIoInit(&io, NULL, 0, out, sizeof(out));
    wolfSSH_SetIOReadCtx(ssh, &io);
    wolfSSH_SetIOWriteCtx(ssh, &io);

    /* Our disconnect short-sends, so a flush is owed. */
    MemSendWantWriteCount = 1;
    AssertIntEQ(wolfSSH_SendDisconnect(ssh, WOLFSSH_DISCONNECT_BY_APPLICATION),
            WS_WANT_WRITE);
    AssertTrue(ssh->disconnectTxd);
    AssertTrue(wolfSSH_OutputPending(ssh));
    AssertIntEQ(io.outSz, 0);

    /* The caller's retry loop pumps it out in full, so nothing is owed. */
    AssertIntEQ(wolfSSH_SendPacket(ssh), WS_SUCCESS);
    AssertFalse(wolfSSH_OutputPending(ssh));
    AssertFalse(ssh->disconnectTxd);
    AssertIntEQ(out[LENGTH_SZ + 1], MSGID_DISCONNECT);
    io.outSz = 0;

    /* An in-flight CHANNEL_EOF draws a reply out of DoChannelEof(); the
     * internal senders are not behind the disconnect gate. It short-sends,
     * so it sits in the output buffer. */
    MemSendWantWriteCount = 1;
    AssertIntEQ(SendChannelEof(ssh, channel->peerChannel), WS_WANT_WRITE);
    AssertTrue(wolfSSH_OutputPending(ssh));
    AssertIntEQ(io.outSz, 0);

    /* Teardown must leave it there: the disconnect is already gone, so this
     * would be traffic after it. RFC 4253 section 11.1. */
    ret = wolfSSH_shutdown(ssh);
    AssertIntEQ(ret, WS_SUCCESS);
    AssertIntEQ(wolfSSH_get_error(ssh), WS_DISCONNECT);
    AssertIntEQ(io.outSz, 0);
    AssertTrue(wolfSSH_OutputPending(ssh));

    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);
}


/* A flush that is itself short owns ssh->error. Callers gate their retry on
 * WS_WANT_WRITE, so the disconnect gate must not overwrite it. */
static void TestShutdownKeepsFlushWantWrite(void)
{
    WOLFSSH_CTX* ctx;
    WOLFSSH* ssh;
    WOLFSSH_CHANNEL* channel;
    MemIo io;
    byte out[256];

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_CLIENT, NULL);
    AssertNotNull(ctx);

    wolfSSH_SetIORecv(ctx, MemRecv);
    wolfSSH_SetIOSend(ctx, MemSendWantWrite);

    ssh = wolfSSH_new(ctx);
    AssertNotNull(ssh);
    AddSessionChannel(ssh);
    channel = ssh->channelList;
    ssh->connectState = CONNECT_SERVER_USERAUTH_ACCEPT_DONE;

    MemIoInit(&io, NULL, 0, out, sizeof(out));
    wolfSSH_SetIOReadCtx(ssh, &io);
    wolfSSH_SetIOWriteCtx(ssh, &io);

    /* One short send for the disconnect, another for the flush below. */
    MemSendWantWriteCount = 2;
    AssertIntEQ(wolfSSH_SendDisconnect(ssh, WOLFSSH_DISCONNECT_BY_APPLICATION),
            WS_WANT_WRITE);
    AssertIntEQ(io.outSz, 0);

    /* The channel is still listed, so the disconnect gate runs, but the
     * unfinished flush is what the caller has to act on. */
    AssertNotNull(ssh->channelList);
    AssertIntEQ(wolfSSH_shutdown(ssh), WS_WANT_WRITE);
    AssertIntEQ(wolfSSH_get_error(ssh), WS_WANT_WRITE);
    AssertTrue(wolfSSH_OutputPending(ssh));
    AssertIntEQ(io.outSz, 0);

    /* Retrying gets it out, and only it. */
    AssertIntEQ(wolfSSH_shutdown(ssh), WS_SUCCESS);
    AssertFalse(wolfSSH_OutputPending(ssh));
    AssertIntEQ(out[LENGTH_SZ + 1], MSGID_DISCONNECT);
    AssertIntEQ(channel->eofTxd, 0);
    AssertIntEQ(channel->closeTxd, 0);

    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);
}


#if defined(WOLFSSH_TERM) && !defined(NO_FILESYSTEM)
/* A window-change request is a send like any other. */
static void TestTerminalResizeBlockedAfterDisconnect(void)
{
    WOLFSSH_CTX* ctx;
    WOLFSSH* ssh;
    MemIo io;
    byte out[256];
    word32 quietSz;
    int ret;

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_CLIENT, NULL);
    AssertNotNull(ctx);

    wolfSSH_SetIORecv(ctx, MemRecv);
    wolfSSH_SetIOSend(ctx, MemSend);

    ssh = wolfSSH_new(ctx);
    AssertNotNull(ssh);
    AddSessionChannel(ssh);

    MemIoInit(&io, NULL, 0, out, sizeof(out));
    wolfSSH_SetIOReadCtx(ssh, &io);
    wolfSSH_SetIOWriteCtx(ssh, &io);

    AssertIntEQ(wolfSSH_SendDisconnect(ssh, WOLFSSH_DISCONNECT_BY_APPLICATION),
            WS_SUCCESS);
    quietSz = io.outSz;

    ret = wolfSSH_ChangeTerminalSize(ssh, 80, 24, 0, 0);
    AssertIntEQ(ret, WS_FATAL_ERROR);
    AssertIntEQ(wolfSSH_get_error(ssh), WS_DISCONNECT);
    AssertIntEQ(io.outSz, quietSz);

    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);
}
#endif /* WOLFSSH_TERM && !NO_FILESYSTEM */

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

#endif /* WOLFSSH_SFTP */

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

#if !defined(NO_WOLFSSH_SERVER) && !defined(USE_WINDOWS_API) && \
        !defined(NO_FILESYSTEM)
/* Write a big-endian uint32 (the SFTP wire encoding). */
static void SftpPutU32(word32 val, byte* out)
{
    out[0] = (byte)(val >> 24);
    out[1] = (byte)(val >> 16);
    out[2] = (byte)(val >> 8);
    out[3] = (byte)(val);
}

/* Read a big-endian uint32 (the SFTP wire encoding). */
static word32 SftpGetU32(const byte* in)
{
    return ((word32)in[0] << 24) | ((word32)in[1] << 16) |
           ((word32)in[2] << 8)  | (word32)in[3];
}

/* Return 1 if needle occurs in haystack, 0 otherwise. */
static int SftpBufContains(const byte* hay, word32 haySz,
        const byte* needle, word32 needleSz)
{
    word32 i;

    if (hay == NULL || needle == NULL || needleSz == 0 || haySz < needleSz) {
        return 0;
    }
    for (i = 0; i + needleSz <= haySz; i++) {
        if (WMEMCMP(hay + i, needle, needleSz) == 0) {
            return 1;
        }
    }
    return 0;
}

/* Adversarial regression test for the SFTP file-handle IDOR class affecting
 * RecvWrite -> pwrite, RecvRead -> pread, RecvFSetSTAT -> fchmod, and
 * RecvClose -> close.
 *
 * Before the per-session opaque-handle rework these handlers accepted a raw
 * file-descriptor integer from the peer after only a byte-length check and
 * passed it straight to the matching syscall. This test opens a descriptor the
 * server holds but never handed out over SFTP, then forges SFTP handles that
 * encode that descriptor and confirms every handler rejects them and leaves the
 * victim file untouched. A legitimately opened handle is exercised first as a
 * positive control so a blanket-reject regression cannot pass silently.
 *
 * Two forged handle encodings are tried against every handler: the original
 * exploit form (raw sizeof(WFD) bytes), which must now fail the 8-byte size
 * check, and a correctly sized opaque ID whose first word is the victim fd,
 * which must fail the per-session ownership lookup. POSIX only. */
static void TestSftpForgedHandleRejected(void)
{
    WOLFSSH_CTX* ctx;
    WOLFSSH* ssh;
    int f;
    int rid = 100;
    int rc;
    WFD victimFd = -1;
    WFD ownedRead;
    WSTAT_T st;
    word32 victimMode;
    word32 idx;
    word32 replySz;
    word32 ofst[2] = {0, 0};
    const byte* reply;

    char ownedPath[64];
    char victimPath[64];
    const char sentinel[]   = "DAEMON-PRIVATE-SECRET";
    const char positive[]   = "POSITIVE-CONTROL-DATA";
    const char attack[]     = "HANDLE-IDOR-OVERWRITE";

    byte legitHandle[WOLFSSH_HANDLE_ID_SZ]; /* first opened file -> id {0,0} */
    byte forgedId[WOLFSSH_HANDLE_ID_SZ];    /* 8-byte id whose word[0]==fd   */
    byte forgedRaw[sizeof(WFD)];            /* original raw-fd exploit bytes  */
    const byte* fHandle[2];
    word32      fHandleSz[2];
    byte pkt[256];
    byte rbuf[64];
    char cwd[WOLFSSH_MAX_FILENAME];

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_SERVER, NULL);
    AssertNotNull(ctx);
    ssh = wolfSSH_new(ctx);
    AssertNotNull(ssh);

    /* unique per-process fixture names so parallel runs don't collide and we
     * never clobber a same-named file in the working directory */
    WSNPRINTF(ownedPath, sizeof(ownedPath), "wolfssh_poc_owned_%d.tmp",
            (int)getpid());
    WSNPRINTF(victimPath, sizeof(victimPath), "wolfssh_poc_victim_%d.tmp",
            (int)getpid());

    /* capture the handlers' buffered replies instead of leaking them */
    AssertIntEQ(wolfSSH_SFTP_TestRecvStateInit(ssh), WS_SUCCESS);

    /* confine the server to an absolute working directory */
    WMEMSET(cwd, 0, sizeof(cwd));
    AssertNotNull(WGETCWD(ssh->fs, cwd, sizeof(cwd) - 1));
    AssertIntEQ(wolfSSH_SFTP_SetDefaultPath(ssh, cwd), WS_SUCCESS);
    AssertIntEQ(wolfSSH_SFTP_SetConfinePath(ssh, cwd), WS_SUCCESS);

    /* ---- positive control: legitimately open a file over SFTP ----
     * RecvOpen assigns the first handle the per-session id {0,0}. */
    WMEMSET(legitHandle, 0, sizeof(legitHandle));

    idx = 0;
    SftpPutU32((word32)WSTRLEN(ownedPath), pkt + idx); idx += UINT32_SZ;
    WMEMCPY(pkt + idx, ownedPath, WSTRLEN(ownedPath));
    idx += (word32)WSTRLEN(ownedPath);
    SftpPutU32(WOLFSSH_FXF_READ | WOLFSSH_FXF_WRITE | WOLFSSH_FXF_CREAT |
            WOLFSSH_FXF_TRUNC, pkt + idx); idx += UINT32_SZ;
    SftpPutU32(0, pkt + idx); idx += UINT32_SZ;          /* no attributes */
    AssertIntEQ(wolfSSH_SFTP_RecvOpen(ssh, rid++, pkt, idx), WS_SUCCESS);

    /* write through the legitimate handle: must succeed */
    idx = 0;
    SftpPutU32(WOLFSSH_HANDLE_ID_SZ, pkt + idx); idx += UINT32_SZ;
    WMEMCPY(pkt + idx, legitHandle, WOLFSSH_HANDLE_ID_SZ);
    idx += WOLFSSH_HANDLE_ID_SZ;
    SftpPutU32(0, pkt + idx); idx += UINT32_SZ;          /* offset hi */
    SftpPutU32(0, pkt + idx); idx += UINT32_SZ;          /* offset lo */
    SftpPutU32((word32)(sizeof(positive) - 1), pkt + idx); idx += UINT32_SZ;
    WMEMCPY(pkt + idx, positive, sizeof(positive) - 1);
    idx += (word32)(sizeof(positive) - 1);
    AssertIntEQ(wolfSSH_SFTP_RecvWrite(ssh, rid++, pkt, idx), WS_SUCCESS);

    /* confirm the bytes really landed in the owned file */
    ownedRead = WOPEN(ssh->fs, ownedPath, WOLFSSH_O_RDONLY, 0);
    AssertTrue(ownedRead >= 0);
    WMEMSET(rbuf, 0, sizeof(rbuf));
    rc = WPREAD(ssh->fs, ownedRead, rbuf, (word32)(sizeof(positive) - 1), ofst);
    AssertIntEQ(rc, (int)(sizeof(positive) - 1));
    AssertIntEQ(WMEMCMP(rbuf, positive, sizeof(positive) - 1), 0);
    WCLOSE(ssh->fs, ownedRead);

    /* positive control: FSTAT on the legitimate handle must report the owned
     * file's real size (the bytes just written). The handle is the opaque id
     * {0,0}; a regression that fstat()s the handle bytes as a raw descriptor
     * would stat fd 0 (stdin) and return the wrong size, which this catches. */
    idx = 0;
    SftpPutU32(WOLFSSH_HANDLE_ID_SZ, pkt + idx); idx += UINT32_SZ;
    WMEMCPY(pkt + idx, legitHandle, WOLFSSH_HANDLE_ID_SZ);
    idx += WOLFSSH_HANDLE_ID_SZ;
    AssertIntEQ(wolfSSH_SFTP_RecvFSTAT(ssh, rid++, pkt, idx), WS_SUCCESS);
    reply = wolfSSH_SFTP_TestRecvReply(ssh, &replySz);
    AssertNotNull(reply);
    /* header(9) = len(4) type(1) reqId(4); ATTRS payload = flags(4) szHi(4) szLo(4) */
    AssertTrue(replySz >= WOLFSSH_SFTP_HEADER + (UINT32_SZ * 3));
    AssertIntEQ(reply[LENGTH_SZ], WOLFSSH_FTP_ATTRS);
    AssertTrue((SftpGetU32(reply + WOLFSSH_SFTP_HEADER) & WOLFSSH_FILEATRB_SIZE)
            != 0);
    AssertIntEQ((int)SftpGetU32(reply + WOLFSSH_SFTP_HEADER + (UINT32_SZ * 2)),
            (int)(sizeof(positive) - 1));

    /* ---- victim: a descriptor the server holds, never opened over SFTP ---- */
    victimFd = WOPEN(ssh->fs, victimPath,
            WOLFSSH_O_RDWR | WOLFSSH_O_CREAT | WOLFSSH_O_TRUNC, 0600);
    AssertTrue(victimFd >= 0);
    AssertIntEQ(WPWRITE(ssh->fs, victimFd, (byte*)sentinel,
            (word32)(sizeof(sentinel) - 1), ofst),
            (int)(sizeof(sentinel) - 1));
    AssertIntEQ(WFCHMOD(ssh->fs, victimFd, 0600), 0);
    AssertIntEQ(WFSTAT(ssh->fs, victimFd, &st), 0);
    victimMode = (word32)(st.st_mode & 0777);

    /* the two forged handle encodings every handler must reject */
    WMEMCPY(forgedRaw, &victimFd, sizeof(WFD));
    SftpPutU32((word32)victimFd, forgedId);
    SftpPutU32(0, forgedId + UINT32_SZ);
    fHandle[0]   = forgedRaw; fHandleSz[0] = (word32)sizeof(WFD);
    fHandle[1]   = forgedId;  fHandleSz[1] = WOLFSSH_HANDLE_ID_SZ;

    for (f = 0; f < 2; f++) {
        /* --- 4232: forged WRITE must not pwrite() the victim fd --- */
        idx = 0;
        SftpPutU32(fHandleSz[f], pkt + idx); idx += UINT32_SZ;
        WMEMCPY(pkt + idx, fHandle[f], fHandleSz[f]); idx += fHandleSz[f];
        SftpPutU32(0, pkt + idx); idx += UINT32_SZ;
        SftpPutU32(0, pkt + idx); idx += UINT32_SZ;
        SftpPutU32((word32)(sizeof(attack) - 1), pkt + idx); idx += UINT32_SZ;
        WMEMCPY(pkt + idx, attack, sizeof(attack) - 1);
        idx += (word32)(sizeof(attack) - 1);
        AssertTrue(wolfSSH_SFTP_RecvWrite(ssh, rid++, pkt, idx) != WS_SUCCESS);

        /* --- 4346: forged READ must not pread() the victim fd --- */
        idx = 0;
        SftpPutU32(fHandleSz[f], pkt + idx); idx += UINT32_SZ;
        WMEMCPY(pkt + idx, fHandle[f], fHandleSz[f]); idx += fHandleSz[f];
        SftpPutU32(0, pkt + idx); idx += UINT32_SZ;
        SftpPutU32(0, pkt + idx); idx += UINT32_SZ;
        SftpPutU32((word32)(sizeof(sentinel) - 1), pkt + idx); idx += UINT32_SZ;
        AssertTrue(wolfSSH_SFTP_RecvRead(ssh, rid++, pkt, idx) != WS_SUCCESS);
        /* the secret must never appear in the buffered reply */
        reply = wolfSSH_SFTP_TestRecvReply(ssh, &replySz);
        AssertIntEQ(SftpBufContains(reply, replySz, (const byte*)sentinel,
                (word32)(sizeof(sentinel) - 1)), 0);

        /* --- 4343: forged FSETSTAT must not fchmod() the victim fd --- */
        idx = 0;
        SftpPutU32(fHandleSz[f], pkt + idx); idx += UINT32_SZ;
        WMEMCPY(pkt + idx, fHandle[f], fHandleSz[f]); idx += fHandleSz[f];
        SftpPutU32(WOLFSSH_FILEATRB_PERM, pkt + idx); idx += UINT32_SZ;
        SftpPutU32(0777, pkt + idx); idx += UINT32_SZ;
        AssertTrue(wolfSSH_SFTP_RecvFSetSTAT(ssh, rid++, pkt, idx) != WS_SUCCESS);

        /* --- forged FSTAT must not fstat() the victim fd --- */
        idx = 0;
        SftpPutU32(fHandleSz[f], pkt + idx); idx += UINT32_SZ;
        WMEMCPY(pkt + idx, fHandle[f], fHandleSz[f]); idx += fHandleSz[f];
        AssertTrue(wolfSSH_SFTP_RecvFSTAT(ssh, rid++, pkt, idx) != WS_SUCCESS);

        /* --- 4349: forged CLOSE must not close() the victim fd --- */
        idx = 0;
        SftpPutU32(fHandleSz[f], pkt + idx); idx += UINT32_SZ;
        WMEMCPY(pkt + idx, fHandle[f], fHandleSz[f]); idx += fHandleSz[f];
        AssertTrue(wolfSSH_SFTP_RecvClose(ssh, rid++, pkt, idx) != WS_SUCCESS);
    }

    /* ---- verify the victim was left completely untouched ---- */
    WMEMSET(rbuf, 0, sizeof(rbuf));
    rc = WPREAD(ssh->fs, victimFd, rbuf, (word32)(sizeof(sentinel) - 1), ofst);
    AssertTrue(rc >= 0);                                  /* 4349: not closed */
    AssertIntEQ(rc, (int)(sizeof(sentinel) - 1));
    AssertIntEQ(WMEMCMP(rbuf, sentinel, sizeof(sentinel) - 1), 0); /* 4232 */
    AssertIntEQ(WFSTAT(ssh->fs, victimFd, &st), 0);
    AssertIntEQ((int)(st.st_mode & 0777), (int)victimMode);       /* 4343 */

    /* the legitimate handle must still be open and owned: a real CLOSE on it
     * succeeds, proving the forged closes did not disturb the session list */
    idx = 0;
    SftpPutU32(WOLFSSH_HANDLE_ID_SZ, pkt + idx); idx += UINT32_SZ;
    WMEMCPY(pkt + idx, legitHandle, WOLFSSH_HANDLE_ID_SZ);
    idx += WOLFSSH_HANDLE_ID_SZ;
    AssertIntEQ(wolfSSH_SFTP_RecvClose(ssh, rid++, pkt, idx), WS_SUCCESS);

    if (victimFd >= 0) {
        WCLOSE(ssh->fs, victimFd);
    }
    (void)WREMOVE(ssh->fs, ownedPath);
    (void)WREMOVE(ssh->fs, victimPath);
    wolfSSH_SFTP_TestRecvStateFree(ssh);
    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);
}

#ifndef NO_WOLFSSH_DIR
/* File and directory handle IDs are drawn from a single shared counter
 * (ssh->handleIdCount), so a file handle and a directory handle can never
 * collide. This test confirms that property and that each SFTP operation
 * routes only to its own resource type:
 *   - a directory handle is rejected by the file handlers (READ/WRITE/FSETSTAT)
 *   - a file handle is rejected by the directory handler (READDIR)
 *   - closing the file leaves the directory handle valid (no cross-type close)
 * With per-type counters both handles could share id {0,0} and a CLOSE could
 * match the wrong resource. */
static void TestSftpHandleNamespaceIsolation(void)
{
    WOLFSSH_CTX* ctx;
    WOLFSSH* ssh;
    int rid = 200;
    word32 idx;
    word32 replySz;
    const byte* reply;
    const word32 hOff = WOLFSSH_SFTP_HEADER + UINT32_SZ; /* handle in reply */

    char ownedPath[64];
    const char attack[]    = "WRONG-TYPE";
    byte dirHandle[WOLFSSH_HANDLE_ID_SZ];
    byte fileHandle[WOLFSSH_HANDLE_ID_SZ];
    byte pkt[256];
    char cwd[WOLFSSH_MAX_FILENAME];

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_SERVER, NULL);
    AssertNotNull(ctx);
    ssh = wolfSSH_new(ctx);
    AssertNotNull(ssh);
    AssertIntEQ(wolfSSH_SFTP_TestRecvStateInit(ssh), WS_SUCCESS);

    /* unique per-process fixture name (see TestSftpForgedHandleRejected) */
    WSNPRINTF(ownedPath, sizeof(ownedPath), "wolfssh_poc_ns_%d.tmp",
            (int)getpid());

    WMEMSET(cwd, 0, sizeof(cwd));
    AssertNotNull(WGETCWD(ssh->fs, cwd, sizeof(cwd) - 1));
    AssertIntEQ(wolfSSH_SFTP_SetDefaultPath(ssh, cwd), WS_SUCCESS);
    AssertIntEQ(wolfSSH_SFTP_SetConfinePath(ssh, cwd), WS_SUCCESS);

    /* open a directory -> first id from the shared counter */
    idx = 0;
    SftpPutU32(1, pkt + idx); idx += UINT32_SZ;      /* path "." */
    pkt[idx++] = '.';
    AssertIntEQ(wolfSSH_SFTP_RecvOpenDir(ssh, rid++, pkt, idx), WS_SUCCESS);
    reply = wolfSSH_SFTP_TestRecvReply(ssh, &replySz);
    AssertNotNull(reply);
    AssertTrue(replySz >= hOff + WOLFSSH_HANDLE_ID_SZ);
    WMEMCPY(dirHandle, reply + hOff, WOLFSSH_HANDLE_ID_SZ);

    /* open a file -> next id from the same counter */
    idx = 0;
    SftpPutU32((word32)WSTRLEN(ownedPath), pkt + idx); idx += UINT32_SZ;
    WMEMCPY(pkt + idx, ownedPath, WSTRLEN(ownedPath));
    idx += (word32)WSTRLEN(ownedPath);
    SftpPutU32(WOLFSSH_FXF_READ | WOLFSSH_FXF_WRITE | WOLFSSH_FXF_CREAT |
            WOLFSSH_FXF_TRUNC, pkt + idx); idx += UINT32_SZ;
    SftpPutU32(0, pkt + idx); idx += UINT32_SZ;
    AssertIntEQ(wolfSSH_SFTP_RecvOpen(ssh, rid++, pkt, idx), WS_SUCCESS);
    reply = wolfSSH_SFTP_TestRecvReply(ssh, &replySz);
    AssertNotNull(reply);
    AssertTrue(replySz >= hOff + WOLFSSH_HANDLE_ID_SZ);
    WMEMCPY(fileHandle, reply + hOff, WOLFSSH_HANDLE_ID_SZ);

    /* shared namespace: the file and directory handles must not collide */
    AssertTrue(WMEMCMP(dirHandle, fileHandle, WOLFSSH_HANDLE_ID_SZ) != 0);

    /* --- file handlers must reject the directory handle --- */
    idx = 0;                                         /* READ */
    SftpPutU32(WOLFSSH_HANDLE_ID_SZ, pkt + idx); idx += UINT32_SZ;
    WMEMCPY(pkt + idx, dirHandle, WOLFSSH_HANDLE_ID_SZ);
    idx += WOLFSSH_HANDLE_ID_SZ;
    SftpPutU32(0, pkt + idx); idx += UINT32_SZ;
    SftpPutU32(0, pkt + idx); idx += UINT32_SZ;
    SftpPutU32(16, pkt + idx); idx += UINT32_SZ;
    AssertTrue(wolfSSH_SFTP_RecvRead(ssh, rid++, pkt, idx) != WS_SUCCESS);

    idx = 0;                                         /* WRITE */
    SftpPutU32(WOLFSSH_HANDLE_ID_SZ, pkt + idx); idx += UINT32_SZ;
    WMEMCPY(pkt + idx, dirHandle, WOLFSSH_HANDLE_ID_SZ);
    idx += WOLFSSH_HANDLE_ID_SZ;
    SftpPutU32(0, pkt + idx); idx += UINT32_SZ;
    SftpPutU32(0, pkt + idx); idx += UINT32_SZ;
    SftpPutU32((word32)(sizeof(attack) - 1), pkt + idx); idx += UINT32_SZ;
    WMEMCPY(pkt + idx, attack, sizeof(attack) - 1);
    idx += (word32)(sizeof(attack) - 1);
    AssertTrue(wolfSSH_SFTP_RecvWrite(ssh, rid++, pkt, idx) != WS_SUCCESS);

    idx = 0;                                         /* FSETSTAT */
    SftpPutU32(WOLFSSH_HANDLE_ID_SZ, pkt + idx); idx += UINT32_SZ;
    WMEMCPY(pkt + idx, dirHandle, WOLFSSH_HANDLE_ID_SZ);
    idx += WOLFSSH_HANDLE_ID_SZ;
    SftpPutU32(WOLFSSH_FILEATRB_PERM, pkt + idx); idx += UINT32_SZ;
    SftpPutU32(0777, pkt + idx); idx += UINT32_SZ;
    AssertTrue(wolfSSH_SFTP_RecvFSetSTAT(ssh, rid++, pkt, idx) != WS_SUCCESS);

    idx = 0;                                         /* FSTAT */
    SftpPutU32(WOLFSSH_HANDLE_ID_SZ, pkt + idx); idx += UINT32_SZ;
    WMEMCPY(pkt + idx, dirHandle, WOLFSSH_HANDLE_ID_SZ);
    idx += WOLFSSH_HANDLE_ID_SZ;
    AssertTrue(wolfSSH_SFTP_RecvFSTAT(ssh, rid++, pkt, idx) != WS_SUCCESS);

    /* --- directory handler must reject the file handle --- */
    idx = 0;                                         /* READDIR */
    SftpPutU32(WOLFSSH_HANDLE_ID_SZ, pkt + idx); idx += UINT32_SZ;
    WMEMCPY(pkt + idx, fileHandle, WOLFSSH_HANDLE_ID_SZ);
    idx += WOLFSSH_HANDLE_ID_SZ;
    AssertTrue(wolfSSH_SFTP_RecvReadDir(ssh, rid++, pkt, idx) != WS_SUCCESS);

    /* closing the file must not disturb the directory handle: close the file,
     * then the directory close still succeeds (it would fail if the ids had
     * collided and the file close had matched the directory). */
    idx = 0;
    SftpPutU32(WOLFSSH_HANDLE_ID_SZ, pkt + idx); idx += UINT32_SZ;
    WMEMCPY(pkt + idx, fileHandle, WOLFSSH_HANDLE_ID_SZ);
    idx += WOLFSSH_HANDLE_ID_SZ;
    AssertIntEQ(wolfSSH_SFTP_RecvClose(ssh, rid++, pkt, idx), WS_SUCCESS);

    idx = 0;
    SftpPutU32(WOLFSSH_HANDLE_ID_SZ, pkt + idx); idx += UINT32_SZ;
    WMEMCPY(pkt + idx, dirHandle, WOLFSSH_HANDLE_ID_SZ);
    idx += WOLFSSH_HANDLE_ID_SZ;
    AssertIntEQ(wolfSSH_SFTP_RecvClose(ssh, rid++, pkt, idx), WS_SUCCESS);

    (void)WREMOVE(ssh->fs, ownedPath);
    wolfSSH_SFTP_TestRecvStateFree(ssh);
    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);
}
#endif /* NO_WOLFSSH_DIR */

/* A refused request must still answer the peer with an FXP_STATUS carrying the
 * expected code. Asserting only that the call returned non-success would not
 * catch a refusal that dropped the reply and left the session hung.
 * The request id is checked too: TestRecvReply returns whatever is currently
 * buffered, so a handler that dropped its reply would otherwise pass here by
 * re-presenting the previous request's status. */
static void AssertSftpStatusReply(WOLFSSH* ssh, int reqId, word32 code)
{
    const byte* reply;
    word32 replySz;

    reply = wolfSSH_SFTP_TestRecvReply(ssh, &replySz);
    AssertNotNull(reply);
    AssertTrue(replySz >= WOLFSSH_SFTP_HEADER + UINT32_SZ);
    AssertIntEQ(reply[LENGTH_SZ], WOLFSSH_FTP_STATUS);
    AssertIntEQ((int)SftpGetU32(reply + LENGTH_SZ + MSG_ID_SZ), reqId);
    AssertIntEQ((int)SftpGetU32(reply + WOLFSSH_SFTP_HEADER), (int)code);
}

/* The per-session open-file-handle count is capped at WOLFSSH_MAX_SFTP_HANDLES
 * to bound memory and keep the linear handle lookup from becoming a CPU DoS
 * vector. Open exactly the cap's worth of handles (all must succeed), confirm
 * the next open is refused, then close one and confirm a fresh open succeeds
 * again -- proving the cap tracks the live count rather than latching shut. */
static void TestSftpHandleLimit(void)
{
    WOLFSSH_CTX* ctx;
    WOLFSSH* ssh;
    int rid = 300;
    int reqId;
    int i;
    word32 idx;
    word32 replySz;
    const byte* reply;
    const word32 hOff = WOLFSSH_SFTP_HEADER + UINT32_SZ; /* handle in reply */
    byte handles[WOLFSSH_MAX_SFTP_HANDLES][WOLFSSH_HANDLE_ID_SZ];
    byte pkt[256];
    char cwd[WOLFSSH_MAX_FILENAME];
    char path[64];
    char victim[64];
    word32 pathSz;
    FILE* vf;
    long vsz;

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_SERVER, NULL);
    AssertNotNull(ctx);
    ssh = wolfSSH_new(ctx);
    AssertNotNull(ssh);
    AssertIntEQ(wolfSSH_SFTP_TestRecvStateInit(ssh), WS_SUCCESS);

    /* unique per-process fixture names (see TestSftpForgedHandleRejected) */
    WSNPRINTF(path, sizeof(path), "wolfssh_limit_%d.tmp", (int)getpid());
    WSNPRINTF(victim, sizeof(victim), "wolfssh_limit_victim_%d.tmp",
            (int)getpid());
    pathSz = (word32)WSTRLEN(path);

    WMEMSET(cwd, 0, sizeof(cwd));
    AssertNotNull(WGETCWD(ssh->fs, cwd, sizeof(cwd) - 1));
    AssertIntEQ(wolfSSH_SFTP_SetDefaultPath(ssh, cwd), WS_SUCCESS);
    AssertIntEQ(wolfSSH_SFTP_SetConfinePath(ssh, cwd), WS_SUCCESS);

    /* open the cap's worth of handles against one file; all must succeed */
    for (i = 0; i < WOLFSSH_MAX_SFTP_HANDLES; i++) {
        idx = 0;
        SftpPutU32(pathSz, pkt + idx); idx += UINT32_SZ;
        WMEMCPY(pkt + idx, path, pathSz);
        idx += pathSz;
        SftpPutU32(WOLFSSH_FXF_READ | WOLFSSH_FXF_WRITE | WOLFSSH_FXF_CREAT,
                pkt + idx); idx += UINT32_SZ;
        SftpPutU32(0, pkt + idx); idx += UINT32_SZ;
        AssertIntEQ(wolfSSH_SFTP_RecvOpen(ssh, rid++, pkt, idx), WS_SUCCESS);
        reply = wolfSSH_SFTP_TestRecvReply(ssh, &replySz);
        AssertNotNull(reply);
        AssertTrue(replySz >= hOff + WOLFSSH_HANDLE_ID_SZ);
        WMEMCPY(handles[i], reply + hOff, WOLFSSH_HANDLE_ID_SZ);
    }
    AssertIntEQ(wolfSSH_SFTP_TestFileHandleCount(ssh),
            WOLFSSH_MAX_SFTP_HANDLES);

    /* one past the cap must be refused, and must not grow the list */
    idx = 0;
    SftpPutU32(pathSz, pkt + idx); idx += UINT32_SZ;
    WMEMCPY(pkt + idx, path, pathSz);
    idx += pathSz;
    SftpPutU32(WOLFSSH_FXF_READ | WOLFSSH_FXF_WRITE | WOLFSSH_FXF_CREAT,
            pkt + idx); idx += UINT32_SZ;
    SftpPutU32(0, pkt + idx); idx += UINT32_SZ;
    reqId = rid++;
    AssertTrue(wolfSSH_SFTP_RecvOpen(ssh, reqId, pkt, idx) != WS_SUCCESS);
    AssertIntEQ(wolfSSH_SFTP_TestFileHandleCount(ssh),
            WOLFSSH_MAX_SFTP_HANDLES);
    /* the peer must be told, and told it was a failure rather than silence */
    AssertSftpStatusReply(ssh, reqId, WOLFSSH_FTP_FAILURE);

    /* A refused open must leave the filesystem alone. The cap is checked
     * before the open, so the O_CREAT|O_TRUNC a "put" carries must not reach
     * the file -- otherwise the peer's data is destroyed by a request the
     * server reported as failed. Seed a victim file, aim a truncating open at
     * it while over the cap, and confirm the contents survive. */
    vf = fopen(victim, "wb");
    AssertNotNull(vf);
    AssertIntEQ((int)fwrite("0123456789", 1, 10, vf), 10);
    fclose(vf);

    idx = 0;
    SftpPutU32((word32)WSTRLEN(victim), pkt + idx); idx += UINT32_SZ;
    WMEMCPY(pkt + idx, victim, WSTRLEN(victim));
    idx += (word32)WSTRLEN(victim);
    SftpPutU32(WOLFSSH_FXF_WRITE | WOLFSSH_FXF_CREAT | WOLFSSH_FXF_TRUNC,
            pkt + idx); idx += UINT32_SZ;
    SftpPutU32(0, pkt + idx); idx += UINT32_SZ;
    reqId = rid++;
    AssertTrue(wolfSSH_SFTP_RecvOpen(ssh, reqId, pkt, idx) != WS_SUCCESS);
    AssertSftpStatusReply(ssh, reqId, WOLFSSH_FTP_FAILURE);

    vf = fopen(victim, "rb");
    AssertNotNull(vf);
    fseek(vf, 0, SEEK_END);
    vsz = ftell(vf);
    fclose(vf);
    AssertIntEQ((int)vsz, 10);
    (void)WREMOVE(ssh->fs, victim);

    /* free one slot; a fresh open must now succeed again */
    idx = 0;
    SftpPutU32(WOLFSSH_HANDLE_ID_SZ, pkt + idx); idx += UINT32_SZ;
    WMEMCPY(pkt + idx, handles[0], WOLFSSH_HANDLE_ID_SZ);
    idx += WOLFSSH_HANDLE_ID_SZ;
    AssertIntEQ(wolfSSH_SFTP_RecvClose(ssh, rid++, pkt, idx), WS_SUCCESS);
    AssertIntEQ(wolfSSH_SFTP_TestFileHandleCount(ssh),
            WOLFSSH_MAX_SFTP_HANDLES - 1);

    idx = 0;
    SftpPutU32(pathSz, pkt + idx); idx += UINT32_SZ;
    WMEMCPY(pkt + idx, path, pathSz);
    idx += pathSz;
    SftpPutU32(WOLFSSH_FXF_READ | WOLFSSH_FXF_WRITE | WOLFSSH_FXF_CREAT,
            pkt + idx); idx += UINT32_SZ;
    SftpPutU32(0, pkt + idx); idx += UINT32_SZ;
    AssertIntEQ(wolfSSH_SFTP_RecvOpen(ssh, rid++, pkt, idx), WS_SUCCESS);
    reply = wolfSSH_SFTP_TestRecvReply(ssh, &replySz);
    AssertNotNull(reply);
    AssertTrue(replySz >= hOff + WOLFSSH_HANDLE_ID_SZ);
    WMEMCPY(handles[0], reply + hOff, WOLFSSH_HANDLE_ID_SZ);
    AssertIntEQ(wolfSSH_SFTP_TestFileHandleCount(ssh),
            WOLFSSH_MAX_SFTP_HANDLES);

    /* close every handle and clean up */
    for (i = 0; i < WOLFSSH_MAX_SFTP_HANDLES; i++) {
        idx = 0;
        SftpPutU32(WOLFSSH_HANDLE_ID_SZ, pkt + idx); idx += UINT32_SZ;
        WMEMCPY(pkt + idx, handles[i], WOLFSSH_HANDLE_ID_SZ);
        idx += WOLFSSH_HANDLE_ID_SZ;
        AssertIntEQ(wolfSSH_SFTP_RecvClose(ssh, rid++, pkt, idx), WS_SUCCESS);
    }
    AssertIntEQ(wolfSSH_SFTP_TestFileHandleCount(ssh), 0);

    (void)WREMOVE(ssh->fs, path);
    wolfSSH_SFTP_TestRecvStateFree(ssh);
    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);
}

#ifndef NO_WOLFSSH_DIR
/* Directory handles live on ssh->dirList, a separate list from the file
 * handles, so the SFTP_AddFileHandle cap does not apply to them. Without its
 * own limit a peer could loop on OPENDIR and grow that list without bound.
 * Same shape as TestSftpHandleLimit: fill to the cap, confirm the next OPENDIR
 * is refused, close one and confirm a fresh OPENDIR succeeds again. */
static void TestSftpDirHandleLimit(void)
{
    WOLFSSH_CTX* ctx;
    WOLFSSH* ssh;
    int rid = 400;
    int reqId;
    int i;
    word32 idx;
    word32 replySz;
    const byte* reply;
    const word32 hOff = WOLFSSH_SFTP_HEADER + UINT32_SZ; /* handle in reply */
    byte handles[WOLFSSH_MAX_SFTP_HANDLES][WOLFSSH_HANDLE_ID_SZ];
    byte pkt[256];
    char cwd[WOLFSSH_MAX_FILENAME];

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_SERVER, NULL);
    AssertNotNull(ctx);
    ssh = wolfSSH_new(ctx);
    AssertNotNull(ssh);
    AssertIntEQ(wolfSSH_SFTP_TestRecvStateInit(ssh), WS_SUCCESS);

    WMEMSET(cwd, 0, sizeof(cwd));
    AssertNotNull(WGETCWD(ssh->fs, cwd, sizeof(cwd) - 1));
    AssertIntEQ(wolfSSH_SFTP_SetDefaultPath(ssh, cwd), WS_SUCCESS);
    AssertIntEQ(wolfSSH_SFTP_SetConfinePath(ssh, cwd), WS_SUCCESS);

    /* open the cap's worth of handles on "."; all must succeed */
    for (i = 0; i < WOLFSSH_MAX_SFTP_HANDLES; i++) {
        idx = 0;
        SftpPutU32(1, pkt + idx); idx += UINT32_SZ;
        pkt[idx++] = '.';
        AssertIntEQ(wolfSSH_SFTP_RecvOpenDir(ssh, rid++, pkt, idx), WS_SUCCESS);
        reply = wolfSSH_SFTP_TestRecvReply(ssh, &replySz);
        AssertNotNull(reply);
        AssertTrue(replySz >= hOff + WOLFSSH_HANDLE_ID_SZ);
        WMEMCPY(handles[i], reply + hOff, WOLFSSH_HANDLE_ID_SZ);
    }
    AssertIntEQ(wolfSSH_SFTP_TestDirHandleCount(ssh),
            WOLFSSH_MAX_SFTP_HANDLES);

    /* one past the cap must be refused, and must not grow the list */
    idx = 0;
    SftpPutU32(1, pkt + idx); idx += UINT32_SZ;
    pkt[idx++] = '.';
    reqId = rid++;
    AssertTrue(wolfSSH_SFTP_RecvOpenDir(ssh, reqId, pkt, idx) != WS_SUCCESS);
    AssertIntEQ(wolfSSH_SFTP_TestDirHandleCount(ssh),
            WOLFSSH_MAX_SFTP_HANDLES);
    /* the peer must be told, and told it was a failure rather than silence */
    AssertSftpStatusReply(ssh, reqId, WOLFSSH_FTP_FAILURE);

    /* free one slot; a fresh OPENDIR must now succeed again */
    idx = 0;
    SftpPutU32(WOLFSSH_HANDLE_ID_SZ, pkt + idx); idx += UINT32_SZ;
    WMEMCPY(pkt + idx, handles[0], WOLFSSH_HANDLE_ID_SZ);
    idx += WOLFSSH_HANDLE_ID_SZ;
    AssertIntEQ(wolfSSH_SFTP_RecvClose(ssh, rid++, pkt, idx), WS_SUCCESS);
    AssertIntEQ(wolfSSH_SFTP_TestDirHandleCount(ssh),
            WOLFSSH_MAX_SFTP_HANDLES - 1);

    idx = 0;
    SftpPutU32(1, pkt + idx); idx += UINT32_SZ;
    pkt[idx++] = '.';
    AssertIntEQ(wolfSSH_SFTP_RecvOpenDir(ssh, rid++, pkt, idx), WS_SUCCESS);
    reply = wolfSSH_SFTP_TestRecvReply(ssh, &replySz);
    AssertNotNull(reply);
    AssertTrue(replySz >= hOff + WOLFSSH_HANDLE_ID_SZ);
    WMEMCPY(handles[0], reply + hOff, WOLFSSH_HANDLE_ID_SZ);
    AssertIntEQ(wolfSSH_SFTP_TestDirHandleCount(ssh),
            WOLFSSH_MAX_SFTP_HANDLES);

    /* close every handle and clean up */
    for (i = 0; i < WOLFSSH_MAX_SFTP_HANDLES; i++) {
        idx = 0;
        SftpPutU32(WOLFSSH_HANDLE_ID_SZ, pkt + idx); idx += UINT32_SZ;
        WMEMCPY(pkt + idx, handles[i], WOLFSSH_HANDLE_ID_SZ);
        idx += WOLFSSH_HANDLE_ID_SZ;
        AssertIntEQ(wolfSSH_SFTP_RecvClose(ssh, rid++, pkt, idx), WS_SUCCESS);
    }
    AssertIntEQ(wolfSSH_SFTP_TestDirHandleCount(ssh), 0);

    wolfSSH_SFTP_TestRecvStateFree(ssh);
    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);
}
#endif /* NO_WOLFSSH_DIR */

/* A failed close() must still drop the handle from the session tracking list;
 * otherwise the stale descriptor lingers and is closed a second time when the
 * session is torn down. Open a file, invalidate its descriptor out of band so
 * RecvClose's close() fails, then confirm RecvClose reports the failure yet
 * the handle is gone from the list. */
static void TestSftpCloseFailureRemovesHandle(void)
{
    WOLFSSH_CTX* ctx;
    WOLFSSH* ssh;
    int rid = 400;
    word32 idx;
    word32 replySz;
    const byte* reply;
    const word32 hOff = WOLFSSH_SFTP_HEADER + UINT32_SZ; /* handle in reply */
    byte handle[WOLFSSH_HANDLE_ID_SZ];
    byte pkt[256];
    char cwd[WOLFSSH_MAX_FILENAME];
    char path[64];

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_SERVER, NULL);
    AssertNotNull(ctx);
    ssh = wolfSSH_new(ctx);
    AssertNotNull(ssh);
    AssertIntEQ(wolfSSH_SFTP_TestRecvStateInit(ssh), WS_SUCCESS);

    /* unique per-process fixture name (see TestSftpForgedHandleRejected) */
    WSNPRINTF(path, sizeof(path), "wolfssh_closefail_%d.tmp", (int)getpid());

    WMEMSET(cwd, 0, sizeof(cwd));
    AssertNotNull(WGETCWD(ssh->fs, cwd, sizeof(cwd) - 1));
    AssertIntEQ(wolfSSH_SFTP_SetDefaultPath(ssh, cwd), WS_SUCCESS);
    AssertIntEQ(wolfSSH_SFTP_SetConfinePath(ssh, cwd), WS_SUCCESS);

    idx = 0;
    SftpPutU32((word32)WSTRLEN(path), pkt + idx); idx += UINT32_SZ;
    WMEMCPY(pkt + idx, path, WSTRLEN(path));
    idx += (word32)WSTRLEN(path);
    SftpPutU32(WOLFSSH_FXF_READ | WOLFSSH_FXF_WRITE | WOLFSSH_FXF_CREAT |
            WOLFSSH_FXF_TRUNC, pkt + idx); idx += UINT32_SZ;
    SftpPutU32(0, pkt + idx); idx += UINT32_SZ;
    AssertIntEQ(wolfSSH_SFTP_RecvOpen(ssh, rid++, pkt, idx), WS_SUCCESS);
    reply = wolfSSH_SFTP_TestRecvReply(ssh, &replySz);
    AssertNotNull(reply);
    AssertTrue(replySz >= hOff + WOLFSSH_HANDLE_ID_SZ);
    WMEMCPY(handle, reply + hOff, WOLFSSH_HANDLE_ID_SZ);
    AssertIntEQ(wolfSSH_SFTP_TestFileHandleCount(ssh), 1);

    /* close the underlying descriptor behind the server's back */
    AssertIntEQ(wolfSSH_SFTP_TestInvalidateHeadFd(ssh), WS_SUCCESS);

    /* RecvClose now sees close() fail, but must still remove the handle */
    idx = 0;
    SftpPutU32(WOLFSSH_HANDLE_ID_SZ, pkt + idx); idx += UINT32_SZ;
    WMEMCPY(pkt + idx, handle, WOLFSSH_HANDLE_ID_SZ);
    idx += WOLFSSH_HANDLE_ID_SZ;
    AssertTrue(wolfSSH_SFTP_RecvClose(ssh, rid++, pkt, idx) != WS_SUCCESS);
    AssertIntEQ(wolfSSH_SFTP_TestFileHandleCount(ssh), 0);

    /* a second close of the same handle finds nothing and still fails */
    idx = 0;
    SftpPutU32(WOLFSSH_HANDLE_ID_SZ, pkt + idx); idx += UINT32_SZ;
    WMEMCPY(pkt + idx, handle, WOLFSSH_HANDLE_ID_SZ);
    idx += WOLFSSH_HANDLE_ID_SZ;
    AssertTrue(wolfSSH_SFTP_RecvClose(ssh, rid++, pkt, idx) != WS_SUCCESS);

    (void)WREMOVE(ssh->fs, path);
    wolfSSH_SFTP_TestRecvStateFree(ssh);
    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);
}

/* Build the attribute block of a SETSTAT/FSETSTAT payload. Optional fields go
 * in flag-bit order, matching SFTP_ParseAttributes_buffer. */
static word32 SftpBuildAttrs(byte* out, const WS_SFTP_FILEATRB* atr)
{
    word32 idx = 0;

    SftpPutU32(atr->flags, out + idx); idx += UINT32_SZ;
    if (atr->flags & WOLFSSH_FILEATRB_SIZE) {
        SftpPutU32(atr->sz[1], out + idx); idx += UINT32_SZ;
        SftpPutU32(atr->sz[0], out + idx); idx += UINT32_SZ;
    }
    if (atr->flags & WOLFSSH_FILEATRB_UIDGID) {
        SftpPutU32(atr->uid, out + idx); idx += UINT32_SZ;
        SftpPutU32(atr->gid, out + idx); idx += UINT32_SZ;
    }
    if (atr->flags & WOLFSSH_FILEATRB_PERM) {
        SftpPutU32(atr->per, out + idx); idx += UINT32_SZ;
    }
    if (atr->flags & WOLFSSH_FILEATRB_TIME) {
        SftpPutU32(atr->atime, out + idx); idx += UINT32_SZ;
        SftpPutU32(atr->mtime, out + idx); idx += UINT32_SZ;
    }
    return idx;
}


/* Sends an FXP_SETSTAT for path and returns the handler's return code. */
static int SftpSendSetSTAT(WOLFSSH* ssh, int reqId, const char* path,
        const WS_SFTP_FILEATRB* atr)
{
    byte   pkt[UINT32_SZ + WOLFSSH_MAX_FILENAME + (UINT32_SZ * 8)];
    word32 idx = 0;
    word32 sz  = (word32)WSTRLEN(path);

    SftpPutU32(sz, pkt + idx); idx += UINT32_SZ;
    WMEMCPY(pkt + idx, path, sz); idx += sz;
    idx += SftpBuildAttrs(pkt + idx, atr);

    return wolfSSH_SFTP_RecvSetSTAT(ssh, reqId, pkt, idx);
}


/* Sends an FXP_FSETSTAT for an open handle and returns the handler's code. */
static int SftpSendFSetSTAT(WOLFSSH* ssh, int reqId, const byte* handle,
        const WS_SFTP_FILEATRB* atr)
{
    byte   pkt[UINT32_SZ + WOLFSSH_HANDLE_ID_SZ + (UINT32_SZ * 8)];
    word32 idx = 0;

    SftpPutU32(WOLFSSH_HANDLE_ID_SZ, pkt + idx); idx += UINT32_SZ;
    WMEMCPY(pkt + idx, handle, WOLFSSH_HANDLE_ID_SZ);
    idx += WOLFSSH_HANDLE_ID_SZ;
    idx += SftpBuildAttrs(pkt + idx, atr);

    return wolfSSH_SFTP_RecvFSetSTAT(ssh, reqId, pkt, idx);
}


/* SETSTAT and FSETSTAT must apply every attribute they acknowledge. Answering
 * FTP_OK for a size, ownership or timestamp change that never reached the file
 * leaves the client believing a truncate or a chown happened. */
static void TestSftpSetStatAttributes(void)
{
    WOLFSSH_CTX* ctx;
    WOLFSSH* ssh;
    WS_SFTP_FILEATRB atr;
    WSTAT_T st;
    const byte* reply;
    const word32 hOff = WOLFSSH_SFTP_HEADER + UINT32_SZ; /* handle in reply */
#if defined(WSETTIME) || defined(WFSETTIME)
    const word32 when = 1000000000;
#endif
    const char body[] = "0123456789abcdef";
    word32 ofst[2] = {0, 0};
    word32 idx;
    word32 replySz;
    word32 origUid;
    word32 origGid;
    int rid = 500;
    int fd;
    byte handle[WOLFSSH_HANDLE_ID_SZ];
    byte pkt[256];
    char cwd[WOLFSSH_MAX_FILENAME];
    char path[64];

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_SERVER, NULL);
    AssertNotNull(ctx);
    ssh = wolfSSH_new(ctx);
    AssertNotNull(ssh);
    AssertIntEQ(wolfSSH_SFTP_TestRecvStateInit(ssh), WS_SUCCESS);

    /* unique per-process fixture name (see TestSftpForgedHandleRejected) */
    WSNPRINTF(path, sizeof(path), "wolfssh_setstat_%d.tmp", (int)getpid());

    WMEMSET(cwd, 0, sizeof(cwd));
    AssertNotNull(WGETCWD(ssh->fs, cwd, sizeof(cwd) - 1));
    AssertIntEQ(wolfSSH_SFTP_SetDefaultPath(ssh, cwd), WS_SUCCESS);
    AssertIntEQ(wolfSSH_SFTP_SetConfinePath(ssh, cwd), WS_SUCCESS);

    /* fixture: a file of known length owned by this process */
    fd = WOPEN(ssh->fs, path,
            WOLFSSH_O_RDWR | WOLFSSH_O_CREAT | WOLFSSH_O_TRUNC, 0600);
    AssertTrue(fd >= 0);
    AssertIntEQ(WPWRITE(ssh->fs, fd, (byte*)body, (word32)(sizeof(body) - 1),
            ofst), (int)(sizeof(body) - 1));
    AssertIntEQ(WCLOSE(ssh->fs, fd), 0);
    AssertIntEQ(WSTAT(ssh->fs, path, &st), 0);
    AssertIntEQ((int)st.st_size, (int)(sizeof(body) - 1));

    /* a SETSTAT that shrinks the file has to truncate it */
    WMEMSET(&atr, 0, sizeof(atr));
    atr.flags = WOLFSSH_FILEATRB_SIZE;
    atr.sz[0] = 4;
    AssertIntEQ(SftpSendSetSTAT(ssh, rid, path, &atr), WS_SUCCESS);
    AssertSftpStatusReply(ssh, rid++, WOLFSSH_FTP_OK);
    AssertIntEQ(WSTAT(ssh->fs, path, &st), 0);
    AssertIntEQ((int)st.st_size, 4);

    /* and one that grows it has to extend the file */
    atr.sz[0] = 32;
    AssertIntEQ(SftpSendSetSTAT(ssh, rid, path, &atr), WS_SUCCESS);
    AssertSftpStatusReply(ssh, rid++, WOLFSSH_FTP_OK);
    AssertIntEQ(WSTAT(ssh->fs, path, &st), 0);
    AssertIntEQ((int)st.st_size, 32);

    /* a size past the offset ceiling of the port is refused outright rather
     * than wrapped through the cast, and the file is left alone */
    WMEMSET(&atr, 0, sizeof(atr));
    atr.flags = WOLFSSH_FILEATRB_SIZE;
    atr.sz[1] = 0x80000000;
    AssertTrue(SftpSendSetSTAT(ssh, rid, path, &atr) != WS_SUCCESS);
    AssertSftpStatusReply(ssh, rid++, WOLFSSH_FTP_FAILURE);
    AssertIntEQ(WSTAT(ssh->fs, path, &st), 0);
    AssertIntEQ((int)st.st_size, 32);

#ifdef WSETTIME
    /* a requested timestamp has to reach the file */
    WMEMSET(&atr, 0, sizeof(atr));
    atr.flags = WOLFSSH_FILEATRB_TIME;
    atr.atime = when;
    atr.mtime = when;
    AssertIntEQ(SftpSendSetSTAT(ssh, rid, path, &atr), WS_SUCCESS);
    AssertSftpStatusReply(ssh, rid++, WOLFSSH_FTP_OK);
    AssertIntEQ(WSTAT(ssh->fs, path, &st), 0);
    AssertIntEQ((int)st.st_mtime, (int)when);
#endif

    /* a chown to the file's existing owner is a no-op and stays accepted */
    WMEMSET(&atr, 0, sizeof(atr));
    atr.flags = WOLFSSH_FILEATRB_UIDGID;
    atr.uid = (word32)st.st_uid;
    atr.gid = (word32)st.st_gid;
    AssertIntEQ(SftpSendSetSTAT(ssh, rid, path, &atr), WS_SUCCESS);
    AssertSftpStatusReply(ssh, rid++, WOLFSSH_FTP_OK);

    /* giving the file away is refused for an unprivileged server, and that
     * refusal has to reach the client instead of an OK */
    origUid = (word32)st.st_uid;
    origGid = (word32)st.st_gid;
    if (geteuid() != 0) {
        atr.uid = origUid + 1;
        AssertTrue(SftpSendSetSTAT(ssh, rid, path, &atr) != WS_SUCCESS);
        AssertSftpStatusReply(ssh, rid++, WOLFSSH_FTP_FAILURE);
        AssertIntEQ(WSTAT(ssh->fs, path, &st), 0);
        AssertIntEQ((int)st.st_uid, (int)geteuid());
    }
    else {
        /* root may give the file away, so prove the chown reached the file
         * instead of relying on the no-op case above, then put it back */
        atr.uid = origUid + 1;
        AssertIntEQ(SftpSendSetSTAT(ssh, rid, path, &atr), WS_SUCCESS);
        AssertSftpStatusReply(ssh, rid++, WOLFSSH_FTP_OK);
        AssertIntEQ(WSTAT(ssh->fs, path, &st), 0);
        AssertIntEQ((int)st.st_uid, (int)(origUid + 1));

        atr.uid = origUid;
        atr.gid = origGid;
        AssertIntEQ(SftpSendSetSTAT(ssh, rid, path, &atr), WS_SUCCESS);
        AssertSftpStatusReply(ssh, rid++, WOLFSSH_FTP_OK);
        AssertIntEQ(WSTAT(ssh->fs, path, &st), 0);
        AssertIntEQ((int)st.st_uid, (int)origUid);
    }

    /* the same contract holds for FSETSTAT against an open handle */
    idx = 0;
    SftpPutU32((word32)WSTRLEN(path), pkt + idx); idx += UINT32_SZ;
    WMEMCPY(pkt + idx, path, WSTRLEN(path));
    idx += (word32)WSTRLEN(path);
    SftpPutU32(WOLFSSH_FXF_READ | WOLFSSH_FXF_WRITE, pkt + idx);
    idx += UINT32_SZ;
    SftpPutU32(0, pkt + idx); idx += UINT32_SZ;
    AssertIntEQ(wolfSSH_SFTP_RecvOpen(ssh, rid++, pkt, idx), WS_SUCCESS);
    reply = wolfSSH_SFTP_TestRecvReply(ssh, &replySz);
    AssertNotNull(reply);
    AssertTrue(replySz >= hOff + WOLFSSH_HANDLE_ID_SZ);
    WMEMCPY(handle, reply + hOff, WOLFSSH_HANDLE_ID_SZ);

    WMEMSET(&atr, 0, sizeof(atr));
    atr.flags = WOLFSSH_FILEATRB_SIZE;
    atr.sz[0] = 8;
    AssertIntEQ(SftpSendFSetSTAT(ssh, rid, handle, &atr), WS_SUCCESS);
    AssertSftpStatusReply(ssh, rid++, WOLFSSH_FTP_OK);
    AssertIntEQ(WSTAT(ssh->fs, path, &st), 0);
    AssertIntEQ((int)st.st_size, 8);

    WMEMSET(&atr, 0, sizeof(atr));
    atr.flags = WOLFSSH_FILEATRB_SIZE;
    atr.sz[1] = 0x80000000;
    AssertTrue(SftpSendFSetSTAT(ssh, rid, handle, &atr) != WS_SUCCESS);
    AssertSftpStatusReply(ssh, rid++, WOLFSSH_FTP_FAILURE);
    AssertIntEQ(WSTAT(ssh->fs, path, &st), 0);
    AssertIntEQ((int)st.st_size, 8);

    /* ownership over the handle, the same pair of cases as the path form */
    WMEMSET(&atr, 0, sizeof(atr));
    atr.flags = WOLFSSH_FILEATRB_UIDGID;
    atr.uid = (word32)st.st_uid;
    atr.gid = (word32)st.st_gid;
    AssertIntEQ(SftpSendFSetSTAT(ssh, rid, handle, &atr), WS_SUCCESS);
    AssertSftpStatusReply(ssh, rid++, WOLFSSH_FTP_OK);

    origUid = (word32)st.st_uid;
    origGid = (word32)st.st_gid;
    if (geteuid() != 0) {
        atr.uid = origUid + 1;
        AssertTrue(SftpSendFSetSTAT(ssh, rid, handle, &atr) != WS_SUCCESS);
        AssertSftpStatusReply(ssh, rid++, WOLFSSH_FTP_FAILURE);
        AssertIntEQ(WSTAT(ssh->fs, path, &st), 0);
        AssertIntEQ((int)st.st_uid, (int)geteuid());
    }
    else {
        atr.uid = origUid + 1;
        AssertIntEQ(SftpSendFSetSTAT(ssh, rid, handle, &atr), WS_SUCCESS);
        AssertSftpStatusReply(ssh, rid++, WOLFSSH_FTP_OK);
        AssertIntEQ(WSTAT(ssh->fs, path, &st), 0);
        AssertIntEQ((int)st.st_uid, (int)(origUid + 1));

        atr.uid = origUid;
        atr.gid = origGid;
        AssertIntEQ(SftpSendFSetSTAT(ssh, rid, handle, &atr), WS_SUCCESS);
        AssertSftpStatusReply(ssh, rid++, WOLFSSH_FTP_OK);
        AssertIntEQ(WSTAT(ssh->fs, path, &st), 0);
        AssertIntEQ((int)st.st_uid, (int)origUid);
    }

#ifdef WFSETTIME
    WMEMSET(&atr, 0, sizeof(atr));
    atr.flags = WOLFSSH_FILEATRB_TIME;
    atr.atime = when + 100;
    atr.mtime = when + 100;
    AssertIntEQ(SftpSendFSetSTAT(ssh, rid, handle, &atr), WS_SUCCESS);
    AssertSftpStatusReply(ssh, rid++, WOLFSSH_FTP_OK);
    AssertIntEQ(WSTAT(ssh->fs, path, &st), 0);
    AssertIntEQ((int)st.st_mtime, (int)(when + 100));
#endif

    idx = 0;
    SftpPutU32(WOLFSSH_HANDLE_ID_SZ, pkt + idx); idx += UINT32_SZ;
    WMEMCPY(pkt + idx, handle, WOLFSSH_HANDLE_ID_SZ);
    idx += WOLFSSH_HANDLE_ID_SZ;
    AssertIntEQ(wolfSSH_SFTP_RecvClose(ssh, rid++, pkt, idx), WS_SUCCESS);

    (void)WREMOVE(ssh->fs, path);
    wolfSSH_SFTP_TestRecvStateFree(ssh);
    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);
}

/* Sends an FXP_STAT for path and returns the handler's return code. */
static int SftpStatPath(WOLFSSH* ssh, int reqId, const char* path)
{
    byte   pkt[WOLFSSH_MAX_FILENAME + UINT32_SZ];
    word32 idx = 0;
    word32 sz  = (word32)WSTRLEN(path);

    SftpPutU32(sz, pkt); idx += UINT32_SZ;
    WMEMCPY(pkt + idx, path, sz); idx += sz;

    return wolfSSH_SFTP_RecvSTAT(ssh, reqId, pkt, idx);
}

/* An accepted STAT answers with FXP_ATTRS carrying the same request id. */
static void AssertSftpAttrsReply(WOLFSSH* ssh, int reqId)
{
    const byte* reply;
    word32 replySz;

    reply = wolfSSH_SFTP_TestRecvReply(ssh, &replySz);
    AssertNotNull(reply);
    AssertTrue(replySz >= WOLFSSH_SFTP_HEADER + UINT32_SZ);
    AssertIntEQ(reply[LENGTH_SZ], WOLFSSH_FTP_ATTRS);
    AssertIntEQ((int)SftpGetU32(reply + LENGTH_SZ + MSG_ID_SZ), reqId);
}

/* The start path and the confinement root are separate settings: a relative
 * request resolves against the start path, while the jail boundary is the
 * confinement root.  Start the session in a subdirectory of the root and
 * confirm requests are judged against the root - a sibling of the start
 * directory is reachable, anything above the root is not.  The tests that pass
 * the same directory to both setters cannot tell the two apart, so they would
 * still pass if confinement went back to following the start path. */
static void TestSftpStartPathInsideConfineRoot(void)
{
    WOLFSSH_CTX* ctx;
    WOLFSSH* ssh;
    int rid = 500;
    /* short enough that any fixture suffix below still fits a full path */
    char cwd[WOLFSSH_MAX_FILENAME - 64];
    char root[WOLFSSH_MAX_FILENAME];
    char start[WOLFSSH_MAX_FILENAME];
    char sibling[WOLFSSH_MAX_FILENAME];
    char startFile[WOLFSSH_MAX_FILENAME];
    char sibFile[WOLFSSH_MAX_FILENAME];
    char nearMiss[WOLFSSH_MAX_FILENAME];
    WFILE* fp = NULL;

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_SERVER, NULL);
    AssertNotNull(ctx);
    ssh = wolfSSH_new(ctx);
    AssertNotNull(ssh);
    AssertIntEQ(wolfSSH_SFTP_TestRecvStateInit(ssh), WS_SUCCESS);

    WMEMSET(cwd, 0, sizeof(cwd));

    /* the fixture paths below hang off the working directory; skip rather
     * than test truncated paths if it is too deep to leave room for them */
    if (WGETCWD(ssh->fs, cwd, sizeof(cwd) - 1) == NULL) {
        wolfSSH_SFTP_TestRecvStateFree(ssh);
        wolfSSH_free(ssh);
        wolfSSH_CTX_free(ctx);
        return;
    }

    /* unique per-process fixture names (see TestSftpForgedHandleRejected),
     * each spelled out from cwd so the lengths stay provably in bounds */
    #define CONFINE_ROOT "%s/wolfssh_confine_%d"
    WSNPRINTF(root, sizeof(root), CONFINE_ROOT, cwd, (int)getpid());
    WSNPRINTF(start, sizeof(start), CONFINE_ROOT "/start", cwd, (int)getpid());
    WSNPRINTF(sibling, sizeof(sibling), CONFINE_ROOT "/sibling",
            cwd, (int)getpid());
    WSNPRINTF(startFile, sizeof(startFile), CONFINE_ROOT "/start/start_file",
            cwd, (int)getpid());
    WSNPRINTF(sibFile, sizeof(sibFile), CONFINE_ROOT "/sibling/sib_file",
            cwd, (int)getpid());
    WSNPRINTF(nearMiss, sizeof(nearMiss), CONFINE_ROOT "_evil",
            cwd, (int)getpid());
    #undef CONFINE_ROOT

    AssertIntEQ(WMKDIR(ssh->fs, root, 0755), 0);
    AssertIntEQ(WMKDIR(ssh->fs, start, 0755), 0);
    AssertIntEQ(WMKDIR(ssh->fs, sibling, 0755), 0);
    AssertIntEQ(WFOPEN(ssh->fs, &fp, startFile, "wb"), 0);
    AssertNotNull(fp);
    WFCLOSE(ssh->fs, fp);
    AssertIntEQ(WFOPEN(ssh->fs, &fp, sibFile, "wb"), 0);
    AssertNotNull(fp);
    WFCLOSE(ssh->fs, fp);

    /* start deeper than the jail: the session opens in start, the boundary
     * stays at root */
    AssertIntEQ(wolfSSH_SFTP_SetDefaultPath(ssh, start), WS_SUCCESS);
    AssertIntEQ(wolfSSH_SFTP_SetConfinePath(ssh, root), WS_SUCCESS);

    /* a relative request resolves against the start path: start_file exists
     * only there, not at the root */
    AssertIntEQ(SftpStatPath(ssh, ++rid, "start_file"), WS_SUCCESS);
    AssertSftpAttrsReply(ssh, rid);

    /* a sibling of the start directory is inside the root, so it is reachable
     * both by absolute path and by climbing out of the start directory */
    AssertIntEQ(SftpStatPath(ssh, ++rid, sibFile), WS_SUCCESS);
    AssertSftpAttrsReply(ssh, rid);
    AssertIntEQ(SftpStatPath(ssh, ++rid, "../sibling/sib_file"), WS_SUCCESS);
    AssertSftpAttrsReply(ssh, rid);

    /* the root itself is in bounds, reached relatively or absolutely */
    AssertIntEQ(SftpStatPath(ssh, ++rid, ".."), WS_SUCCESS);
    AssertSftpAttrsReply(ssh, rid);
    AssertIntEQ(SftpStatPath(ssh, ++rid, root), WS_SUCCESS);
    AssertSftpAttrsReply(ssh, rid);

    /* above the root is out of bounds, however it is spelled */
    AssertIntEQ(SftpStatPath(ssh, ++rid, "../.."), WS_BAD_FILE_E);
    AssertSftpStatusReply(ssh, rid, WOLFSSH_FTP_PERMISSION);
    AssertIntEQ(SftpStatPath(ssh, ++rid, cwd), WS_BAD_FILE_E);
    AssertSftpStatusReply(ssh, rid, WOLFSSH_FTP_PERMISSION);
    AssertIntEQ(SftpStatPath(ssh, ++rid, "/"), WS_BAD_FILE_E);
    AssertSftpStatusReply(ssh, rid, WOLFSSH_FTP_PERMISSION);

    /* a sibling of the root sharing its string prefix is not under it */
    AssertIntEQ(SftpStatPath(ssh, ++rid, nearMiss), WS_BAD_FILE_E);
    AssertSftpStatusReply(ssh, rid, WOLFSSH_FTP_PERMISSION);

    (void)WREMOVE(ssh->fs, startFile);
    (void)WREMOVE(ssh->fs, sibFile);
    (void)WRMDIR(ssh->fs, start);
    (void)WRMDIR(ssh->fs, sibling);
    (void)WRMDIR(ssh->fs, root);
    wolfSSH_SFTP_TestRecvStateFree(ssh);
    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);
}

#endif /* !NO_WOLFSSH_SERVER && !USE_WINDOWS_API && !NO_FILESYSTEM */

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

/* AppendString for one of the library's own canned algorithm lists. Those are
 * built by concatenating "name," fragments, so they carry a trailing comma
 * that AlgoListSz() trims before the list goes on the wire. Trim it here too,
 * or the payload holds a zero-length name that no peer would send. */
static word32 AppendAlgoList(byte* buf, word32 bufSz, word32 idx,
        const char* value)
{
    word32 valueSz = (word32)WSTRLEN(value);

    if (valueSz > 0 && value[valueSz - 1] == ',') {
        valueSz--;
    }

    idx = AppendUint32(buf, bufSz, idx, valueSz);
    return AppendData(buf, bufSz, idx, (const byte*)value, valueSz);
}

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
    idx = AppendAlgoList(out, outSz, idx, ssh->algoListCipher);
    idx = AppendAlgoList(out, outSz, idx, ssh->algoListCipher);
    idx = AppendAlgoList(out, outSz, idx, ssh->algoListMac);
    idx = AppendAlgoList(out, outSz, idx, ssh->algoListMac);
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
 * clear the flag, and not advance the peer's state past KEXINIT_DONE. */
static void RunFirstPacketFollowsSkipCase(FirstPacketFollowsSkipFn fn,
        const char* label, byte endpointType, byte initState)
{
    WOLFSSH_CTX* ctx;
    WOLFSSH* ssh;
    byte payload[8];
    word32 idx = 0;
    int ret;

    ctx = wolfSSH_CTX_new(endpointType, NULL);
    AssertNotNull(ctx);

    ssh = wolfSSH_new(ctx);
    AssertNotNull(ssh);
    AssertNotNull(ssh->handshake);

    ssh->handshake->ignoreNextKexMsg = 1;
    if (endpointType == WOLFSSH_ENDPOINT_SERVER)
        ssh->clientState = initState;
    else
        ssh->serverState = initState;

    /* Garbage payload that must never be parsed when skipped. */
    WMEMSET(payload, 0xAB, sizeof(payload));

    ret = fn(ssh, payload, sizeof(payload), &idx);
    if (ret != WS_SUCCESS) {
        Fail(("%s returns WS_SUCCESS when skipping", label), ("%d", ret));
    }
    AssertIntEQ(idx, sizeof(payload));
    AssertIntEQ(ssh->handshake->ignoreNextKexMsg, 0);
    if (endpointType == WOLFSSH_ENDPOINT_SERVER)
        AssertIntEQ(ssh->clientState, initState);
    else
        AssertIntEQ(ssh->serverState, initState);

    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);
}

/* Drives a server-side session through the message filter, so it needs the
 * server build. */
#if !defined(WOLFSSH_NO_DH_GEX_SHA256) && !defined(NO_WOLFSSH_SERVER)
/* After skipping a wrong-guess packet, the real first packet of the negotiated
 * KEX must still pass the message gate even when it sits across the GEX
 * boundary from the guess. Drives skip-then-real through IsMessageAllowed and
 * checks the skip did not pin expectMsgId to the discarded message's ID. */
static void RunFirstPacketFollowsCrossBoundaryCase(FirstPacketFollowsSkipFn fn,
        const char* label, byte realMsg)
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

    ssh->clientState = CLIENT_KEXINIT_DONE;
    ssh->isKeying |= WOLFSSH_PEER_IS_KEYING;
    ssh->handshake->ignoreNextKexMsg = 1;
    ssh->handshake->expectMsgId = MSGID_NONE;

    WMEMSET(payload, 0xAB, sizeof(payload));

    ret = fn(ssh, payload, sizeof(payload), &idx);
    if (ret != WS_SUCCESS)
        Fail(("%s returns WS_SUCCESS when skipping", label), ("%d", ret));

    /* Gate must not be pinned to the discarded guess's ID. */
    AssertIntEQ(ssh->handshake->expectMsgId, MSGID_NONE);
    /* The negotiated first-KEX packet must be accepted. */
    AssertIntEQ(wolfSSH_TestIsMessageAllowed(ssh, realMsg, 0), 1);

    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);
}
#endif /* WOLFSSH_NO_DH_GEX_SHA256 && NO_WOLFSSH_SERVER */

static void TestFirstPacketFollowsSkipped(void)
{
    RunFirstPacketFollowsSkipCase(wolfSSH_TestDoKexDhInit,
            "DoKexDhInit", WOLFSSH_ENDPOINT_SERVER, CLIENT_KEXINIT_DONE);
#ifndef WOLFSSH_NO_DH_GEX_SHA256
    RunFirstPacketFollowsSkipCase(wolfSSH_TestDoKexDhGexRequest,
            "DoKexDhGexRequest", WOLFSSH_ENDPOINT_SERVER, CLIENT_KEXINIT_DONE);
    RunFirstPacketFollowsSkipCase(wolfSSH_TestDoKexDhGexGroup,
            "DoKexDhGexGroup", WOLFSSH_ENDPOINT_CLIENT, SERVER_KEXINIT_DONE);
    /* Guess/negotiation straddling the GEX boundary, both directions. */
#ifndef NO_WOLFSSH_SERVER
    RunFirstPacketFollowsCrossBoundaryCase(wolfSSH_TestDoKexDhInit,
            "DoKexDhInit->GEX_REQUEST", MSGID_KEXDH_GEX_REQUEST);
    RunFirstPacketFollowsCrossBoundaryCase(wolfSSH_TestDoKexDhGexRequest,
            "DoKexDhGexRequest->KEXDH_INIT", MSGID_KEXDH_INIT);
#endif /* NO_WOLFSSH_SERVER */
#endif /* WOLFSSH_NO_DH_GEX_SHA256 */
    RunFirstPacketFollowsSkipCase(wolfSSH_TestDoKexDhReply,
            "DoKexDhReply", WOLFSSH_ENDPOINT_CLIENT, SERVER_KEXINIT_DONE);
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

/* RFC 4253 7.1: the trailing uint32 in KEXINIT is reserved and must be zero.
 * DoKexInit used to advance begin by that value (treating it as a length);
 * the current code rejects any non-zero value with WS_PARSE_E. Lock the
 * strict-rejection branch in so a regression that re-relaxes the check or
 * reverts to skipping skipSz bytes would fail this test. */
static void TestKexInitReservedNonZeroRejected(void)
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

    payloadSz = BuildKexInitPayload(ssh, FPF_KEX_GOOD, FPF_KEY_GOOD,
            0, payload, (word32)sizeof(payload));

    /* BuildKexInitPayload puts the reserved uint32 in the final 4 bytes.
     * Overwrite them with a non-zero value to exercise the strict branch. */
    AssertTrue(payloadSz >= UINT32_SZ);
    (void)AppendUint32(payload, (word32)sizeof(payload),
            payloadSz - UINT32_SZ, 0xDEADBEEFu);

    AssertIntEQ(wolfSSH_TestDoKexInit(ssh, payload, payloadSz, &idx),
            WS_PARSE_E);

    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);
}

/* Run a KEXINIT whose KEX-algorithms field is kexList through DoKexInit,
 * against a local list of FPF_KEX_GOOD. A list of unknown tokens fails to
 * match (WS_MATCH_KEX_ALGO_E); one rejected by the caps returns WS_BUFFER_E.
 * kexIdOut, when given, reports the algorithm negotiated or ID_UNKNOWN. */
static int RunKexInitKexListCase(const char* kexList, byte* kexIdOut)
{
    WOLFSSH_CTX* ctx;
    WOLFSSH* ssh;
    byte* payload;
    word32 payloadSz;
    word32 idx = 0;
    int ret;
    word32 bufSz = WOLFSSH_MAX_NAMELIST_SZ + 2048;

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_SERVER, NULL);
    AssertNotNull(ctx);
    ssh = wolfSSH_new(ctx);
    AssertNotNull(ssh);
    AssertIntEQ(wolfSSH_SetAlgoListKex(ssh, FPF_KEX_GOOD), WS_SUCCESS);
    AssertIntEQ(wolfSSH_SetAlgoListKey(ssh, FPF_KEY_GOOD), WS_SUCCESS);

    payload = (byte*)WMALLOC(bufSz, NULL, DYNTYPE_BUFFER);
    AssertNotNull(payload);

    payloadSz = BuildKexInitPayload(ssh, kexList, FPF_KEY_GOOD, 0,
            payload, bufSz);
    ret = wolfSSH_TestDoKexInit(ssh, payload, payloadSz, &idx);

    /* The tail (host key/send) errors on this bare ssh, but negotiation runs
     * first and records the result in handshake->kexId. */
    if (kexIdOut != NULL) {
        AssertNotNull(ssh->handshake);
        *kexIdOut = (ret == WS_MATCH_KEX_ALGO_E)
            ? ID_UNKNOWN : ssh->handshake->kexId;
    }

    WFREE(payload, NULL, DYNTYPE_BUFFER);
    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);

    return ret;
}

/* Build "a,a,...,a" with count unknown tokens into a freshly allocated,
 * NULL-terminated buffer. */
static char* BuildTokenListStr(word32 count)
{
    char* list;
    word32 listSz;
    word32 i;

    AssertTrue(count > 0);
    listSz = (count * 2) - 1;

    list = (char*)WMALLOC(listSz + 1, NULL, DYNTYPE_STRING);
    AssertNotNull(list);
    for (i = 0; i < count; i++) {
        list[i * 2] = 'a';
        if (i + 1 < count)
            list[(i * 2) + 1] = ',';
    }
    list[listSz] = '\0';

    return list;
}

/* Build a single unknown token of byteSz 'a' characters. */
static char* BuildSingleTokenStr(word32 byteSz)
{
    char* list;

    list = (char*)WMALLOC(byteSz + 1, NULL, DYNTYPE_STRING);
    AssertNotNull(list);
    WMEMSET(list, 'a', byteSz);
    list[byteSz] = '\0';

    return list;
}

/* Lock in both KEXINIT name-list boundaries (name count and byte size) so a
 * future retune or refactor that disables the bound or flips the off-by-one
 * fails here. */
static void TestKexInitNameListCaps(void)
{
    char* list;

    /* Exactly the name-count cap parses (then fails to match). */
    list = BuildTokenListStr(WOLFSSH_MAX_NAMELIST_CNT);
    AssertIntEQ(RunKexInitKexListCase(list, NULL), WS_MATCH_KEX_ALGO_E);
    WFREE(list, NULL, DYNTYPE_STRING);

    /* One past the name-count cap is rejected. */
    list = BuildTokenListStr(WOLFSSH_MAX_NAMELIST_CNT + 1);
    AssertIntEQ(RunKexInitKexListCase(list, NULL), WS_BUFFER_E);
    WFREE(list, NULL, DYNTYPE_STRING);

    /* Exactly the byte cap parses (then fails to match). */
    list = BuildSingleTokenStr(WOLFSSH_MAX_NAMELIST_SZ);
    AssertIntEQ(RunKexInitKexListCase(list, NULL), WS_MATCH_KEX_ALGO_E);
    WFREE(list, NULL, DYNTYPE_STRING);

    /* One past the byte cap is rejected. */
    list = BuildSingleTokenStr(WOLFSSH_MAX_NAMELIST_SZ + 1);
    AssertIntEQ(RunKexInitKexListCase(list, NULL), WS_BUFFER_E);
    WFREE(list, NULL, DYNTYPE_STRING);
}

typedef struct {
    const char* kexList;
    byte expectId;
    const char* description;
} EmptyNameCase;

/* RFC 4251 section 5: a name-list holds zero or more names separated by
 * commas, and every name has a non-zero length. So an empty element -- what a
 * leading, doubled, or trailing comma leaves behind -- can't be a name, and
 * the list ends there. Names past it are dropped rather than rejected, which
 * is what OpenSSH's match_list() does with a peer proposal. A local list never
 * arrives here with an empty element: CheckAlgoList() rejects one up front,
 * except for the single trailing comma that AlgoListSz() strips. */
static const EmptyNameCase emptyNameCases[] = {
    /* Nothing before the empty element, so nothing to negotiate with. */
    { "",                            ID_UNKNOWN, "zero names" },
    { ",",                           ID_UNKNOWN, "one bare comma" },
    { ",,",                          ID_UNKNOWN, "two bare commas" },
    { "," FPF_KEX_GOOD,              ID_UNKNOWN, "leading comma" },
    { ",," FPF_KEX_GOOD,             ID_UNKNOWN, "two leading commas" },

    /* A usable name before the empty element still negotiates. */
    { FPF_KEX_GOOD,                  ID_ECDH_SHA2_NISTP256, "no commas" },
    { FPF_KEX_BAD "," FPF_KEX_GOOD,  ID_ECDH_SHA2_NISTP256, "separators" },
    { FPF_KEX_GOOD ",",              ID_ECDH_SHA2_NISTP256, "trailing" },
    { FPF_KEX_GOOD ",,",             ID_ECDH_SHA2_NISTP256, "trailing pair" },
    { FPF_KEX_GOOD ",," FPF_KEX_BAD, ID_ECDH_SHA2_NISTP256, "doubled" },

    /* The name that would have matched sits past the empty element, so it is
     * never seen. This is the case that pins the truncation down. */
    { FPF_KEX_BAD ",," FPF_KEX_GOOD, ID_UNKNOWN, "match past the gap" },
};

static void TestKexInitEmptyName(void)
{
    word32 i;

    for (i = 0; i < sizeof(emptyNameCases)/sizeof(*emptyNameCases); i++) {
        const EmptyNameCase* tc = &emptyNameCases[i];
        byte kexId = ID_NONE;

        (void)RunKexInitKexListCase(tc->kexList, &kexId);

        Assert(kexId == tc->expectId,
                ("kexId == %d (%s)", tc->expectId, tc->description),
                ("%d != %d", kexId, tc->expectId));
    }
}

/* Run one EXT_INFO carrying a single server-sig-algs extension, reporting how
 * many peer signature algorithms it left recorded. When peerSigIdOut is given,
 * the recorded IDs are copied out before the ssh is freed, up to
 * peerSigIdOutSz of them. The payload is heap allocated so a case can hand
 * over a list at the byte cap. */
static int RunExtInfoSigAlgsCase(const char* sigAlgs, word32* peerSigIdSz,
        byte* peerSigIdOut, word32 peerSigIdOutSz)
{
    WOLFSSH_CTX* ctx;
    WOLFSSH* ssh;
    byte* payload;
    word32 payloadSz = 0;
    word32 idx = 0;
    int ret;
    word32 bufSz = WOLFSSH_MAX_NAMELIST_SZ + 2048;

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_CLIENT, NULL);
    AssertNotNull(ctx);
    ssh = wolfSSH_new(ctx);
    AssertNotNull(ssh);

    payload = (byte*)WMALLOC(bufSz, NULL, DYNTYPE_BUFFER);
    AssertNotNull(payload);

    payloadSz = BuildExtInfoSigAlgs(payload, bufSz, sigAlgs);

    ret = wolfSSH_TestDoExtInfo(ssh, payload, payloadSz, &idx);
    *peerSigIdSz = ssh->peerSigIdSz;

    if (peerSigIdOut != NULL && ssh->peerSigId != NULL) {
        word32 copySz = (ssh->peerSigIdSz < peerSigIdOutSz)
            ? ssh->peerSigIdSz : peerSigIdOutSz;

        WMEMCPY(peerSigIdOut, ssh->peerSigId, copySz);
    }

    WFREE(payload, NULL, DYNTYPE_BUFFER);
    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);

    return ret;
}

typedef struct {
    const char* sigAlgs;
    int expectRet;
    word32 expectSz;
    const byte* expectIds;
    const char* description;
} ExtInfoEmptyNameCase;

/* Expected ssh->peerSigId contents for the cases that record something. Both
 * names are compiled into the ID map by the guard around this block, so
 * NameToId() resolves them in any build that runs these tests. Recording a
 * name is not the same as accepting it: FPF_KEY_GOOD is in the map either
 * way, while its place in the client's own accepted list depends on the SHA-1
 * build flags, so the match has to come from FPF_KEY_BAD. */
static const byte extInfoIdsOne[] = { ID_RSA_SHA2_256 };
static const byte extInfoIdsTwo[] = { ID_RSA_SHA2_256, ID_SSH_RSA };
static const byte extInfoIdsUnknownFirst[] = {
    ID_UNKNOWN, ID_RSA_SHA2_256, ID_SSH_RSA
};

/* server-sig-algs is a name-list too, and it is the second caller of
 * GetNameListRaw(): it parses into a fixed ids[] array rather than DoKexInit's
 * buffer, and treats an empty result as "no extension" instead of a
 * negotiation failure. The same parser decides where a list ends, so the
 * verdicts have to line up with the KEXINIT table above. FPF_KEY_BAD is only
 * "bad" against the test server list; it is in the client's own accepted
 * set. */
static const ExtInfoEmptyNameCase extInfoEmptyNameCases[] = {
    /* Nothing usable before the empty element. An extension naming no
     * algorithms is not an error, it just advertises nothing. */
    { "",                      WS_SUCCESS, 0, NULL, "zero names" },
    { ",",                     WS_SUCCESS, 0, NULL, "one bare comma" },
    { ",,",                    WS_SUCCESS, 0, NULL, "two bare commas" },
    { "," FPF_KEY_BAD,         WS_SUCCESS, 0, NULL, "leading comma" },

    /* Names this build can't sign with. Advisory too, so nothing is recorded
     * and the connection stays up; userauth fails later if pubkey is tried. */
    { "bogus",                 WS_SUCCESS, 0, NULL, "all names unknown" },
    { "bogus,alsobogus",       WS_SUCCESS, 0, NULL, "several unknown" },

    /* A usable name before the empty element is recorded. */
    { FPF_KEY_BAD,             WS_SUCCESS, 1, extInfoIdsOne, "no commas" },
    { FPF_KEY_BAD ",",         WS_SUCCESS, 1, extInfoIdsOne, "trailing" },
    { FPF_KEY_BAD ",,",        WS_SUCCESS, 1, extInfoIdsOne, "trailing pair" },
    { FPF_KEY_BAD ",,bogus",   WS_SUCCESS, 1, extInfoIdsOne, "doubled" },

    /* More than one name is recorded, in order. These are what cover the copy
     * out of the parse buffer: a fixed-length copy, or one that keeps only
     * the first ID, passes every single-name case above. */
    { FPF_KEY_BAD "," FPF_KEY_GOOD,
      WS_SUCCESS, 2, extInfoIdsTwo, "two names" },

    /* An unknown name is recorded only when it is the first one, so these two
     * differ by one ID even though both name the same three algorithms. */
    { "bogus," FPF_KEY_BAD "," FPF_KEY_GOOD,
      WS_SUCCESS, 3, extInfoIdsUnknownFirst, "unknown first is kept" },
    { FPF_KEY_BAD ",bogus," FPF_KEY_GOOD,
      WS_SUCCESS, 2, extInfoIdsTwo, "unknown in the middle is dropped" },

    /* The name that would have matched sits past the empty element, so it is
     * never seen and nothing is recorded. Not an error: server-sig-algs is
     * advisory, and 0 here against 1 for the trailing cases above is what
     * pins the truncation down. */
    { "bogus,," FPF_KEY_BAD,   WS_SUCCESS, 0, NULL, "match past the gap" },
};

static void TestExtInfoEmptyName(void)
{
    word32 i;

    for (i = 0; i < sizeof(extInfoEmptyNameCases)/sizeof(*extInfoEmptyNameCases);
            i++) {
        const ExtInfoEmptyNameCase* tc = &extInfoEmptyNameCases[i];
        word32 peerSigIdSz = 0;
        byte peerSigId[8];
        int ret;

        WMEMSET(peerSigId, ID_NONE, sizeof(peerSigId));
        ret = RunExtInfoSigAlgsCase(tc->sigAlgs, &peerSigIdSz,
                peerSigId, (word32)sizeof(peerSigId));

        Assert(ret == tc->expectRet,
                ("ret == %d (%s)", tc->expectRet, tc->description),
                ("%d != %d", ret, tc->expectRet));
        Assert(peerSigIdSz == tc->expectSz,
                ("peerSigIdSz == %u (%s)", tc->expectSz, tc->description),
                ("%u != %u", peerSigIdSz, tc->expectSz));

        if (tc->expectIds != NULL) {
            word32 j;

            AssertTrue(tc->expectSz <= (word32)sizeof(peerSigId));
            for (j = 0; j < tc->expectSz; j++) {
                Assert(peerSigId[j] == tc->expectIds[j],
                        ("peerSigId[%u] == %d (%s)", j, tc->expectIds[j],
                         tc->description),
                        ("%d != %d", peerSigId[j], tc->expectIds[j]));
            }
        }
    }
}

/* Lock in the name-list boundaries on the ext-info path too. This caller
 * parses into a fixed ids[WOLFSSH_MAX_NAMELIST_CNT] array, so the name-count
 * cap is what keeps that array in bounds: it holds at most one ID per name,
 * and the parser refuses a list longer than the cap. */
static void TestExtInfoNameListCaps(void)
{
    char* list;
    word32 peerSigIdSz = 0;

    /* Exactly the name-count cap parses. All tokens unknown, so nothing is
     * recorded, and that is not an error. */
    list = BuildTokenListStr(WOLFSSH_MAX_NAMELIST_CNT);
    AssertIntEQ(RunExtInfoSigAlgsCase(list, &peerSigIdSz, NULL, 0), WS_SUCCESS);
    AssertIntEQ(peerSigIdSz, 0);
    WFREE(list, NULL, DYNTYPE_STRING);

    /* One past the name-count cap is rejected before ids[] can fill. */
    list = BuildTokenListStr(WOLFSSH_MAX_NAMELIST_CNT + 1);
    AssertIntEQ(RunExtInfoSigAlgsCase(list, &peerSigIdSz, NULL, 0),
            WS_BUFFER_E);
    AssertIntEQ(peerSigIdSz, 0);
    WFREE(list, NULL, DYNTYPE_STRING);

    /* Exactly the byte cap parses (recording nothing usable). */
    list = BuildSingleTokenStr(WOLFSSH_MAX_NAMELIST_SZ);
    AssertIntEQ(RunExtInfoSigAlgsCase(list, &peerSigIdSz, NULL, 0), WS_SUCCESS);
    AssertIntEQ(peerSigIdSz, 0);
    WFREE(list, NULL, DYNTYPE_STRING);

    /* One past the byte cap is rejected. */
    list = BuildSingleTokenStr(WOLFSSH_MAX_NAMELIST_SZ + 1);
    AssertIntEQ(RunExtInfoSigAlgsCase(list, &peerSigIdSz, NULL, 0),
            WS_BUFFER_E);
    AssertIntEQ(peerSigIdSz, 0);
    WFREE(list, NULL, DYNTYPE_STRING);
}

/* RFC 8308 section 2.4 allows a second EXT_INFO, so server-sig-algs can be
 * recorded twice on one session and the second pass frees the first list.
 * Shrinking catches a size left behind with the freed buffer. */
static void TestExtInfoSigAlgsReplace(void)
{
    WOLFSSH_CTX* ctx;
    WOLFSSH* ssh;
    byte payload[256];
    word32 payloadSz;
    word32 idx;

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_CLIENT, NULL);
    AssertNotNull(ctx);
    ssh = wolfSSH_new(ctx);
    AssertNotNull(ssh);

    idx = 0;
    payloadSz = BuildExtInfoSigAlgs(payload, (word32)sizeof(payload),
            "bogus," FPF_KEY_BAD "," FPF_KEY_GOOD);
    AssertIntEQ(wolfSSH_TestDoExtInfo(ssh, payload, payloadSz, &idx),
            WS_SUCCESS);
    AssertIntEQ(ssh->peerSigIdSz, 3);
    AssertNotNull(ssh->peerSigId);
    AssertIntEQ(ssh->peerSigId[1], ID_RSA_SHA2_256);

    idx = 0;
    payloadSz = BuildExtInfoSigAlgs(payload, (word32)sizeof(payload),
            FPF_KEY_BAD);
    AssertIntEQ(wolfSSH_TestDoExtInfo(ssh, payload, payloadSz, &idx),
            WS_SUCCESS);
    AssertIntEQ(ssh->peerSigIdSz, 1);
    AssertIntEQ(ssh->peerSigId[0], ID_RSA_SHA2_256);

    /* A later list naming nothing usable supersedes rather than leaving the
     * recorded one in place. OpenSSH's kex_ext_info_client_parse() replaces
     * server_sig_algs on every EXT_INFO, empty value included. */
    idx = 0;
    payloadSz = BuildExtInfoSigAlgs(payload, (word32)sizeof(payload), "bogus");
    AssertIntEQ(wolfSSH_TestDoExtInfo(ssh, payload, payloadSz, &idx),
            WS_SUCCESS);
    AssertIntEQ(ssh->peerSigIdSz, 0);
    AssertNull(ssh->peerSigId);

    /* Same for an empty list, from a good one again. */
    idx = 0;
    payloadSz = BuildExtInfoSigAlgs(payload, (word32)sizeof(payload),
            FPF_KEY_BAD);
    AssertIntEQ(wolfSSH_TestDoExtInfo(ssh, payload, payloadSz, &idx),
            WS_SUCCESS);
    AssertIntEQ(ssh->peerSigIdSz, 1);

    idx = 0;
    payloadSz = BuildExtInfoSigAlgs(payload, (word32)sizeof(payload), "");
    AssertIntEQ(wolfSSH_TestDoExtInfo(ssh, payload, payloadSz, &idx),
            WS_SUCCESS);
    AssertIntEQ(ssh->peerSigIdSz, 0);
    AssertNull(ssh->peerSigId);

    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);
}

/* The two KEXINIT language name-lists were skipped with an unchecked
 * begin += skipSz, so a bogus length could wrap begin back into the payload
 * and let a malformed packet parse as valid. GetSkip now bounds the declared
 * length against the remaining payload; an overlong language length must be
 * rejected. */
static void TestKexInitLanguageLengthOverflow(void)
{
    WOLFSSH_CTX* ctx;
    WOLFSSH* ssh;
    byte payload[512];
    word32 payloadSz;
    word32 idx = 0;
    word32 off;
    int i;

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_SERVER, NULL);
    AssertNotNull(ctx);
    ssh = wolfSSH_new(ctx);
    AssertNotNull(ssh);
    AssertIntEQ(wolfSSH_SetAlgoListKex(ssh, FPF_KEX_GOOD), WS_SUCCESS);
    AssertIntEQ(wolfSSH_SetAlgoListKey(ssh, FPF_KEY_GOOD), WS_SUCCESS);

    payloadSz = BuildKexInitPayload(ssh, FPF_KEX_GOOD, FPF_KEY_GOOD,
            0, payload, (word32)sizeof(payload));

    /* Walk past the cookie and the eight algorithm name-lists to reach the
     * first (client-to-server) language length field. */
    off = COOKIE_SZ;
    for (i = 0; i < 8; i++)
        off += UINT32_SZ + ReadUint32(payload + off);

    /* Overlong length (2^32-4) causes integer wraparound; GetSkip must
     * reject with WS_BUFFER_E instead of failing downstream. */
    (void)AppendUint32(payload, (word32)sizeof(payload), off, 0xFFFFFFFCu);

    AssertIntEQ(wolfSSH_TestDoKexInit(ssh, payload, payloadSz, &idx),
            WS_BUFFER_E);

    wolfSSH_free(ssh);

    /* Sub-test 2: Corrupt the second (server-to-client) language length.
     * Create a fresh ssh context to reset state. */
    ssh = wolfSSH_new(ctx);
    AssertNotNull(ssh);
    AssertIntEQ(wolfSSH_SetAlgoListKex(ssh, FPF_KEX_GOOD), WS_SUCCESS);
    AssertIntEQ(wolfSSH_SetAlgoListKey(ssh, FPF_KEY_GOOD), WS_SUCCESS);

    payloadSz = BuildKexInitPayload(ssh, FPF_KEX_GOOD, FPF_KEY_GOOD,
            0, payload, (word32)sizeof(payload));

    /* Walk past the cookie and the eight algorithm name-lists, then the
     * first (client-to-server) language name-list, to reach the second
     * (server-to-client) language length field. */
    off = COOKIE_SZ;
    for (i = 0; i < 8; i++)
        off += UINT32_SZ + ReadUint32(payload + off);
    off += UINT32_SZ + ReadUint32(payload + off);

    /* Corrupt the S2C language length with the same overflow value to
     * verify GetSkip rejects it with WS_BUFFER_E, confirming the fix is
     * applied to both language name-list skips at internal.c:4730 and 4736. */
    (void)AppendUint32(payload, (word32)sizeof(payload), off, 0xFFFFFFFCu);

    idx = 0;
    AssertIntEQ(wolfSSH_TestDoKexInit(ssh, payload, payloadSz, &idx),
            WS_BUFFER_E);

    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);
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
    /* DoKexInit's tail calls SendKexInit, which fails without a loaded host
     * key. We only care about the negotiated algorithm IDs set during parse. */
    (void)wolfSSH_TestDoKexInit(ssh, payload, payloadSz, &idx);
    AssertNotNull(ssh->handshake);
    AssertIntEQ(ssh->handshake->peerEncryptId, ID_AES128_CBC);
    AssertIntEQ(ssh->handshake->encryptId,     ID_AES256_CTR);
    AssertIntEQ(ssh->handshake->peerMacId,     ID_HMAC_SHA1);
    AssertIntEQ(ssh->handshake->macId,         ID_HMAC_SHA2_256);
    AssertIntEQ(ssh->handshake->peerAeadMode,  0);
    AssertIntEQ(ssh->handshake->aeadMode,      0);
    /* Key sizes -- server: C2S->peerKeys, S2C->keys. Validates the
     * side-aware DoKexInit fix: wrong mapping would swap these sizes. */
    AssertIntEQ(ssh->handshake->peerKeys.encKeySz, AES_128_KEY_SIZE);
    AssertIntEQ(ssh->handshake->keys.encKeySz,     AES_256_KEY_SIZE);
    AssertIntEQ(ssh->handshake->peerKeys.ivSz,     AES_BLOCK_SIZE);
    AssertIntEQ(ssh->handshake->keys.ivSz,         AES_BLOCK_SIZE);
    AssertIntEQ(ssh->handshake->peerKeys.macKeySz, WC_SHA_DIGEST_SIZE);
    AssertIntEQ(ssh->handshake->keys.macKeySz,     WC_SHA256_DIGEST_SIZE);
    /* Block/mac sizes -- server: C2S->peer*, S2C->local. */
    AssertIntEQ(ssh->handshake->peerBlockSz, AES_BLOCK_SIZE);
    AssertIntEQ(ssh->handshake->blockSz,     AES_BLOCK_SIZE);
    AssertIntEQ(ssh->handshake->peerMacSz,   WC_SHA_DIGEST_SIZE);
    AssertIntEQ(ssh->handshake->macSz,       WC_SHA256_DIGEST_SIZE);
    wolfSSH_free(ssh);

#ifndef WOLFSSH_NO_AES_GCM
    /* Sub-test B: AEAD S2C, non-AEAD C2S -- MAC only negotiated for C2S */
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
    /* DoKexInit's tail calls SendKexInit, which fails without a loaded host
     * key. We only care about the negotiated algorithm IDs set during parse. */
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
    /* Block/mac sizes: C2S non-AEAD peerMacSz=SHA1, S2C AEAD macSz=blockSz. */
    AssertIntEQ(ssh->handshake->peerBlockSz, AES_BLOCK_SIZE);
    AssertIntEQ(ssh->handshake->blockSz,     AES_BLOCK_SIZE);
    AssertIntEQ(ssh->handshake->peerMacSz,   WC_SHA_DIGEST_SIZE);
    AssertIntEQ(ssh->handshake->macSz,       AES_BLOCK_SIZE);
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
     * Client mapping is the mirror of server: C2S->keys/encryptId,
     * S2C->peerKeys/peerEncryptId.  A swap bug would make these asserts fail. */
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
    /* DoKexInit's tail calls wolfSSH_SendPacket, which fails because no IO
     * callback is set up. We only care about the negotiated algorithm IDs. */
    (void)wolfSSH_TestDoKexInit(ssh, payload, payloadSz, &idx);
    AssertNotNull(ssh->handshake);
    /* Client: C2S is local outgoing -> encryptId/keys */
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
    /* Block/mac sizes -- client: C2S->local (block/macSz), S2C->peer (peerBlock/MacSz). */
    AssertIntEQ(ssh->handshake->blockSz,     AES_BLOCK_SIZE);
    AssertIntEQ(ssh->handshake->peerBlockSz, AES_BLOCK_SIZE);
    AssertIntEQ(ssh->handshake->macSz,       WC_SHA_DIGEST_SIZE);
    AssertIntEQ(ssh->handshake->peerMacSz,   WC_SHA256_DIGEST_SIZE);
    wolfSSH_free(ssh);

#ifndef WOLFSSH_NO_AES_GCM
    /* Sub-test B: AEAD S2C, non-AEAD C2S -- client perspective. */
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
    /* DoKexInit's tail calls wolfSSH_SendPacket, which fails because no IO
     * callback is set up. We only care about the negotiated algorithm IDs. */
    (void)wolfSSH_TestDoKexInit(ssh, payload, payloadSz, &idx);
    AssertNotNull(ssh->handshake);
    /* Client: C2S->encryptId/keys, S2C->peerEncryptId/peerKeys */
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
    /* Block/mac sizes: C2S non-AEAD macSz=SHA1, S2C AEAD peerMacSz=peerBlockSz. */
    AssertIntEQ(ssh->handshake->blockSz,     AES_BLOCK_SIZE);
    AssertIntEQ(ssh->handshake->peerBlockSz, AES_BLOCK_SIZE);
    AssertIntEQ(ssh->handshake->macSz,       WC_SHA_DIGEST_SIZE);
    AssertIntEQ(ssh->handshake->peerMacSz,   AES_BLOCK_SIZE);
    wolfSSH_free(ssh);
#endif /* !WOLFSSH_NO_AES_GCM */

    wolfSSH_CTX_free(ctx);
}

/* Verify WS_MATCH_ENC_ALGO_E when exactly one direction's cipher list has no
 * match in the local algoListCipher -- the new per-direction S2C matching path
 * introduced by the independent-algo-negotiation change. */
static void TestEncMismatch(void)
{
    WOLFSSH_CTX* ctx;
    WOLFSSH* ssh;
    byte payload[512];
    word32 payloadSz;
    word32 idx;

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_SERVER, NULL);
    AssertNotNull(ctx);

    /* Sub-test A: C2S matches, S2C does not.
     * Local list accepts aes128-cbc and aes256-ctr.
     * Peer offers C2S=aes128-cbc (in list) and S2C=3des-cbc (not in list).
     * Expected: WS_MATCH_ENC_ALGO_E from the S2C block. */
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
            "aes128-cbc", /* C2S enc: in local list */
            "3des-cbc",   /* S2C enc: not in local list */
            "hmac-sha1",  /* C2S MAC */
            "hmac-sha1",  /* S2C MAC */
            0, payload, (word32)sizeof(payload));
    AssertIntEQ(wolfSSH_TestDoKexInit(ssh, payload, payloadSz, &idx),
            WS_MATCH_ENC_ALGO_E);
    wolfSSH_free(ssh);

    /* Sub-test B: S2C matches, C2S does not.
     * Peer offers C2S=3des-cbc (not in list) and S2C=aes256-ctr (in list).
     * Expected: WS_MATCH_ENC_ALGO_E from the C2S block. */
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
            "3des-cbc",   /* C2S enc: not in local list */
            "aes256-ctr", /* S2C enc: in local list */
            "hmac-sha1",  /* C2S MAC */
            "hmac-sha1",  /* S2C MAC */
            0, payload, (word32)sizeof(payload));
    AssertIntEQ(wolfSSH_TestDoKexInit(ssh, payload, payloadSz, &idx),
            WS_MATCH_ENC_ALGO_E);
    wolfSSH_free(ssh);

    wolfSSH_CTX_free(ctx);
}

/* Verify WS_MATCH_MAC_ALGO_E when exactly one direction's MAC list has no
 * match in the local algoListMac -- the new per-direction S2C MAC matching path.
 * Both cipher directions must succeed so that MAC negotiation is reached. */
static void TestMacMismatch(void)
{
    WOLFSSH_CTX* ctx;
    WOLFSSH* ssh;
    byte payload[512];
    word32 payloadSz;
    word32 idx;

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_SERVER, NULL);
    AssertNotNull(ctx);

    /* Sub-test A: C2S MAC matches, S2C MAC does not.
     * Local MAC list accepts hmac-sha1 and hmac-sha2-256.
     * Peer offers C2S=hmac-sha1 (in list) and S2C=hmac-md5 (not in list).
     * Expected: WS_MATCH_MAC_ALGO_E from the S2C MAC block. */
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
            "aes128-cbc",    /* C2S enc: in local list */
            "aes256-ctr",    /* S2C enc: in local list */
            "hmac-sha1",     /* C2S MAC: in local list */
            "hmac-md5",      /* S2C MAC: not in local list */
            0, payload, (word32)sizeof(payload));
    AssertIntEQ(wolfSSH_TestDoKexInit(ssh, payload, payloadSz, &idx),
            WS_MATCH_MAC_ALGO_E);
    wolfSSH_free(ssh);

    /* Sub-test B: S2C MAC matches, C2S MAC does not.
     * Peer offers C2S=hmac-md5 (not in list) and S2C=hmac-sha2-256 (in list).
     * Expected: WS_MATCH_MAC_ALGO_E from the C2S MAC block. */
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
            "aes128-cbc",    /* C2S enc: in local list */
            "aes256-ctr",    /* S2C enc: in local list */
            "hmac-md5",      /* C2S MAC: not in local list */
            "hmac-sha2-256", /* S2C MAC: in local list */
            0, payload, (word32)sizeof(payload));
    AssertIntEQ(wolfSSH_TestDoKexInit(ssh, payload, payloadSz, &idx),
            WS_MATCH_MAC_ALGO_E);
    wolfSSH_free(ssh);

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

    /* Sub-test 0 (negative): GenerateKeys returns WS_BAD_ARGUMENT when
     * ssh->handshake is NULL, exercising the guard added in GenerateKeys. */
    ssh = wolfSSH_new(ctx);
    AssertNotNull(ssh);
    wolfSSH_TestFreeHandshake(ssh);  /* properly frees before NULLing */
    AssertIntEQ(wolfSSH_TestGenerateKeys(ssh, 0), WS_BAD_ARGUMENT);
    wolfSSH_free(ssh);

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
    /* DoKexInit's tail calls SendKexInit, which fails without a loaded host
     * key. We only care about the handshake state set during parse. */
    (void)wolfSSH_TestDoKexInit(ssh, payload, payloadSz, &idx);
    AssertNotNull(ssh->handshake);

    /* Synthetic K/H/sessionId -- any non-zero values produce valid key material. */
    WMEMSET(ssh->k, 0xAA, WC_SHA256_DIGEST_SIZE);
    ssh->kSz = WC_SHA256_DIGEST_SIZE;
    WMEMSET(ssh->h, 0xBB, WC_SHA256_DIGEST_SIZE);
    ssh->hSz = WC_SHA256_DIGEST_SIZE;
    WMEMCPY(ssh->sessionId, ssh->h, ssh->hSz);
    ssh->sessionIdSz = ssh->hSz;

    AssertIntEQ(wolfSSH_TestGenerateKeys(ssh, ssh->handshake->kexHashId), WS_SUCCESS);

    /* C2S direction (server: peerKeys) -- aes128-cbc + hmac-sha1. */
    AssertIntEQ(ssh->handshake->peerKeys.encKeySz, AES_128_KEY_SIZE);
    AssertTrue(WMEMCMP(ssh->handshake->peerKeys.encKey, zeros,
                       AES_128_KEY_SIZE) != 0);
    AssertIntEQ(ssh->handshake->peerKeys.macKeySz, WC_SHA_DIGEST_SIZE);
    AssertTrue(WMEMCMP(ssh->handshake->peerKeys.macKey, zeros,
                       WC_SHA_DIGEST_SIZE) != 0);

    /* S2C direction (server: keys) -- aes256-ctr + hmac-sha2-256. */
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
    /* DoKexInit's tail calls SendKexInit, which fails without a loaded host
     * key. We only care about the handshake state set during parse. */
    (void)wolfSSH_TestDoKexInit(ssh, payload, payloadSz, &idx);
    AssertNotNull(ssh->handshake);

    WMEMSET(ssh->k, 0xAA, WC_SHA256_DIGEST_SIZE);
    ssh->kSz = WC_SHA256_DIGEST_SIZE;
    WMEMSET(ssh->h, 0xBB, WC_SHA256_DIGEST_SIZE);
    ssh->hSz = WC_SHA256_DIGEST_SIZE;
    WMEMCPY(ssh->sessionId, ssh->h, ssh->hSz);
    ssh->sessionIdSz = ssh->hSz;

    AssertIntEQ(wolfSSH_TestGenerateKeys(ssh, ssh->handshake->kexHashId), WS_SUCCESS);

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

#ifndef WOLFSSH_NO_AES_GCM
    /* Sub-test C: aes256-gcm C2S (AEAD) / aes128-cbc S2C (non-AEAD) -- mirror.
     * Verifies that key 'E' is skipped (peerKeys.macKeySz==0) while key 'F'
     * is generated for the non-AEAD S2C direction. */
    ssh = wolfSSH_new(ctx);
    AssertNotNull(ssh);
    AssertIntEQ(wolfSSH_SetAlgoListKex(ssh, FPF_KEX_GOOD), WS_SUCCESS);
    AssertIntEQ(wolfSSH_SetAlgoListKey(ssh, FPF_KEY_GOOD), WS_SUCCESS);
    AssertIntEQ(wolfSSH_SetAlgoListCipher(ssh,
            "aes256-gcm@openssh.com,aes128-cbc"), WS_SUCCESS);
    AssertIntEQ(wolfSSH_SetAlgoListMac(ssh,
            "hmac-sha1,hmac-sha2-256"), WS_SUCCESS);
    idx = 0;
    payloadSz = BuildKexInitPayloadFull(
            FPF_KEX_GOOD, FPF_KEY_GOOD,
            "aes256-gcm@openssh.com", /* C2S enc: AEAD */
            "aes128-cbc",             /* S2C enc: non-AEAD */
            "hmac-sha1",              /* C2S MAC: skipped (AEAD) */
            "hmac-sha2-256",          /* S2C MAC: negotiated */
            0, payload, (word32)sizeof(payload));
    (void)wolfSSH_TestDoKexInit(ssh, payload, payloadSz, &idx);
    AssertNotNull(ssh->handshake);

    WMEMSET(ssh->k, 0xAA, WC_SHA256_DIGEST_SIZE);
    ssh->kSz = WC_SHA256_DIGEST_SIZE;
    WMEMSET(ssh->h, 0xBB, WC_SHA256_DIGEST_SIZE);
    ssh->hSz = WC_SHA256_DIGEST_SIZE;
    WMEMCPY(ssh->sessionId, ssh->h, ssh->hSz);
    ssh->sessionIdSz = ssh->hSz;

    AssertIntEQ(wolfSSH_TestGenerateKeys(ssh, ssh->handshake->kexHashId), WS_SUCCESS);

    /* C2S AEAD (server: peerKeys): macKeySz==0, key 'E' skipped. */
    AssertIntEQ(ssh->handshake->peerKeys.macKeySz, 0);
    AssertIntEQ(WMEMCMP(ssh->handshake->peerKeys.macKey, zeros,
                        WC_SHA_DIGEST_SIZE), 0);

    /* S2C hmac-sha2-256 MAC key (server: keys) must be generated. */
    AssertIntEQ(ssh->handshake->keys.macKeySz, WC_SHA256_DIGEST_SIZE);
    AssertTrue(WMEMCMP(ssh->handshake->keys.macKey, zeros,
                       WC_SHA256_DIGEST_SIZE) != 0);

    wolfSSH_free(ssh);

    /* Sub-test D: aes256-gcm C2S (AEAD) / aes256-gcm S2C (AEAD) -- symmetric.
     * Both macKeySz==0; both key 'E' and key 'F' generation skipped.
     * Directly validates the per-direction macKeySz>0 guards in GenerateKeys. */
    ssh = wolfSSH_new(ctx);
    AssertNotNull(ssh);
    AssertIntEQ(wolfSSH_SetAlgoListKex(ssh, FPF_KEX_GOOD), WS_SUCCESS);
    AssertIntEQ(wolfSSH_SetAlgoListKey(ssh, FPF_KEY_GOOD), WS_SUCCESS);
    AssertIntEQ(wolfSSH_SetAlgoListCipher(ssh,
            "aes256-gcm@openssh.com"), WS_SUCCESS);
    AssertIntEQ(wolfSSH_SetAlgoListMac(ssh, "hmac-sha1"), WS_SUCCESS);
    idx = 0;
    payloadSz = BuildKexInitPayloadFull(
            FPF_KEX_GOOD, FPF_KEY_GOOD,
            "aes256-gcm@openssh.com", /* C2S enc: AEAD */
            "aes256-gcm@openssh.com", /* S2C enc: AEAD */
            "hmac-sha1",              /* C2S MAC: skipped (AEAD) */
            "hmac-sha1",              /* S2C MAC: skipped (AEAD) */
            0, payload, (word32)sizeof(payload));
    (void)wolfSSH_TestDoKexInit(ssh, payload, payloadSz, &idx);
    AssertNotNull(ssh->handshake);

    WMEMSET(ssh->k, 0xAA, WC_SHA256_DIGEST_SIZE);
    ssh->kSz = WC_SHA256_DIGEST_SIZE;
    WMEMSET(ssh->h, 0xBB, WC_SHA256_DIGEST_SIZE);
    ssh->hSz = WC_SHA256_DIGEST_SIZE;
    WMEMCPY(ssh->sessionId, ssh->h, ssh->hSz);
    ssh->sessionIdSz = ssh->hSz;

    AssertIntEQ(wolfSSH_TestGenerateKeys(ssh, ssh->handshake->kexHashId), WS_SUCCESS);

    /* C2S AEAD (server: peerKeys): macKeySz==0, key 'E' skipped. */
    AssertIntEQ(ssh->handshake->peerKeys.macKeySz, 0);
    AssertIntEQ(WMEMCMP(ssh->handshake->peerKeys.macKey, zeros,
                        WC_SHA_DIGEST_SIZE), 0);

    /* S2C AEAD (server: keys): macKeySz==0, key 'F' skipped. */
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

    /* Sub-test A: aes128-cbc C2S / aes256-ctr S2C -- client mapping.
     * Client: C2S->keys (local outgoing), S2C->peerKeys (peer outgoing). */
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
    /* DoKexInit's tail calls wolfSSH_SendPacket, which fails because no IO
     * callback is set up. We only care about the handshake state set during parse. */
    (void)wolfSSH_TestDoKexInit(ssh, payload, payloadSz, &idx);
    AssertNotNull(ssh->handshake);

    WMEMSET(ssh->k, 0xAA, WC_SHA256_DIGEST_SIZE);
    ssh->kSz = WC_SHA256_DIGEST_SIZE;
    WMEMSET(ssh->h, 0xBB, WC_SHA256_DIGEST_SIZE);
    ssh->hSz = WC_SHA256_DIGEST_SIZE;
    WMEMCPY(ssh->sessionId, ssh->h, ssh->hSz);
    ssh->sessionIdSz = ssh->hSz;

    AssertIntEQ(wolfSSH_TestGenerateKeys(ssh, ssh->handshake->kexHashId), WS_SUCCESS);

    /* C2S direction (client: keys) -- aes128-cbc + hmac-sha1. */
    AssertIntEQ(ssh->handshake->keys.encKeySz, AES_128_KEY_SIZE);
    AssertTrue(WMEMCMP(ssh->handshake->keys.encKey, zeros,
                       AES_128_KEY_SIZE) != 0);
    AssertIntEQ(ssh->handshake->keys.macKeySz, WC_SHA_DIGEST_SIZE);
    AssertTrue(WMEMCMP(ssh->handshake->keys.macKey, zeros,
                       WC_SHA_DIGEST_SIZE) != 0);

    /* S2C direction (client: peerKeys) -- aes256-ctr + hmac-sha2-256. */
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
    /* Sub-test B: aes128-cbc C2S (non-AEAD) / aes256-gcm S2C (AEAD) -- client.
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
    /* DoKexInit's tail calls wolfSSH_SendPacket, which fails because no IO
     * callback is set up. We only care about the handshake state set during parse. */
    (void)wolfSSH_TestDoKexInit(ssh, payload, payloadSz, &idx);
    AssertNotNull(ssh->handshake);

    WMEMSET(ssh->k, 0xAA, WC_SHA256_DIGEST_SIZE);
    ssh->kSz = WC_SHA256_DIGEST_SIZE;
    WMEMSET(ssh->h, 0xBB, WC_SHA256_DIGEST_SIZE);
    ssh->hSz = WC_SHA256_DIGEST_SIZE;
    WMEMCPY(ssh->sessionId, ssh->h, ssh->hSz);
    ssh->sessionIdSz = ssh->hSz;

    AssertIntEQ(wolfSSH_TestGenerateKeys(ssh, ssh->handshake->kexHashId), WS_SUCCESS);

    /* C2S hmac-sha1 MAC key (client: keys) must be generated. */
    AssertIntEQ(ssh->handshake->keys.macKeySz, WC_SHA_DIGEST_SIZE);
    AssertTrue(WMEMCMP(ssh->handshake->keys.macKey, zeros,
                       WC_SHA_DIGEST_SIZE) != 0);

    /* S2C AEAD (client: peerKeys): macKeySz==0, macKey stays all-zero. */
    AssertIntEQ(ssh->handshake->peerKeys.macKeySz, 0);
    AssertIntEQ(WMEMCMP(ssh->handshake->peerKeys.macKey, zeros,
                        WC_SHA_DIGEST_SIZE), 0);

    wolfSSH_free(ssh);

    /* Sub-test C: aes256-gcm C2S (AEAD) / aes128-cbc S2C (non-AEAD) -- mirror.
     * Client: C2S->keys (local outgoing), S2C->peerKeys (peer outgoing).
     * Verifies key 'E' skipped (keys.macKeySz==0) and key 'F' generated. */
    ssh = wolfSSH_new(ctx);
    AssertNotNull(ssh);
    AssertIntEQ(wolfSSH_SetAlgoListKex(ssh, FPF_KEX_GOOD), WS_SUCCESS);
    AssertIntEQ(wolfSSH_SetAlgoListKey(ssh, FPF_KEY_GOOD), WS_SUCCESS);
    AssertIntEQ(wolfSSH_SetAlgoListCipher(ssh,
            "aes256-gcm@openssh.com,aes128-cbc"), WS_SUCCESS);
    AssertIntEQ(wolfSSH_SetAlgoListMac(ssh,
            "hmac-sha1,hmac-sha2-256"), WS_SUCCESS);
    idx = 0;
    payloadSz = BuildKexInitPayloadFull(
            FPF_KEX_GOOD, FPF_KEY_GOOD,
            "aes256-gcm@openssh.com", /* C2S enc: AEAD */
            "aes128-cbc",             /* S2C enc: non-AEAD */
            "hmac-sha1",              /* C2S MAC: skipped (AEAD) */
            "hmac-sha2-256",          /* S2C MAC: negotiated */
            0, payload, (word32)sizeof(payload));
    (void)wolfSSH_TestDoKexInit(ssh, payload, payloadSz, &idx);
    AssertNotNull(ssh->handshake);

    WMEMSET(ssh->k, 0xAA, WC_SHA256_DIGEST_SIZE);
    ssh->kSz = WC_SHA256_DIGEST_SIZE;
    WMEMSET(ssh->h, 0xBB, WC_SHA256_DIGEST_SIZE);
    ssh->hSz = WC_SHA256_DIGEST_SIZE;
    WMEMCPY(ssh->sessionId, ssh->h, ssh->hSz);
    ssh->sessionIdSz = ssh->hSz;

    AssertIntEQ(wolfSSH_TestGenerateKeys(ssh, ssh->handshake->kexHashId), WS_SUCCESS);

    /* C2S AEAD (client: keys): macKeySz==0, key 'E' skipped. */
    AssertIntEQ(ssh->handshake->keys.macKeySz, 0);
    AssertIntEQ(WMEMCMP(ssh->handshake->keys.macKey, zeros,
                        WC_SHA_DIGEST_SIZE), 0);

    /* S2C hmac-sha2-256 MAC key (client: peerKeys) must be generated. */
    AssertIntEQ(ssh->handshake->peerKeys.macKeySz, WC_SHA256_DIGEST_SIZE);
    AssertTrue(WMEMCMP(ssh->handshake->peerKeys.macKey, zeros,
                       WC_SHA256_DIGEST_SIZE) != 0);

    wolfSSH_free(ssh);

    /* Sub-test D: aes256-gcm C2S (AEAD) / aes256-gcm S2C (AEAD) -- symmetric.
     * Both macKeySz==0; both key 'E' and key 'F' generation skipped. */
    ssh = wolfSSH_new(ctx);
    AssertNotNull(ssh);
    AssertIntEQ(wolfSSH_SetAlgoListKex(ssh, FPF_KEX_GOOD), WS_SUCCESS);
    AssertIntEQ(wolfSSH_SetAlgoListKey(ssh, FPF_KEY_GOOD), WS_SUCCESS);
    AssertIntEQ(wolfSSH_SetAlgoListCipher(ssh,
            "aes256-gcm@openssh.com"), WS_SUCCESS);
    AssertIntEQ(wolfSSH_SetAlgoListMac(ssh, "hmac-sha1"), WS_SUCCESS);
    idx = 0;
    payloadSz = BuildKexInitPayloadFull(
            FPF_KEX_GOOD, FPF_KEY_GOOD,
            "aes256-gcm@openssh.com", /* C2S enc: AEAD */
            "aes256-gcm@openssh.com", /* S2C enc: AEAD */
            "hmac-sha1",              /* C2S MAC: skipped (AEAD) */
            "hmac-sha1",              /* S2C MAC: skipped (AEAD) */
            0, payload, (word32)sizeof(payload));
    (void)wolfSSH_TestDoKexInit(ssh, payload, payloadSz, &idx);
    AssertNotNull(ssh->handshake);

    WMEMSET(ssh->k, 0xAA, WC_SHA256_DIGEST_SIZE);
    ssh->kSz = WC_SHA256_DIGEST_SIZE;
    WMEMSET(ssh->h, 0xBB, WC_SHA256_DIGEST_SIZE);
    ssh->hSz = WC_SHA256_DIGEST_SIZE;
    WMEMCPY(ssh->sessionId, ssh->h, ssh->hSz);
    ssh->sessionIdSz = ssh->hSz;

    AssertIntEQ(wolfSSH_TestGenerateKeys(ssh, ssh->handshake->kexHashId), WS_SUCCESS);

    /* C2S AEAD (client: keys): macKeySz==0, key 'E' skipped. */
    AssertIntEQ(ssh->handshake->keys.macKeySz, 0);
    AssertIntEQ(WMEMCMP(ssh->handshake->keys.macKey, zeros,
                        WC_SHA_DIGEST_SIZE), 0);

    /* S2C AEAD (client: peerKeys): macKeySz==0, key 'F' skipped. */
    AssertIntEQ(ssh->handshake->peerKeys.macKeySz, 0);
    AssertIntEQ(WMEMCMP(ssh->handshake->peerKeys.macKey, zeros,
                        WC_SHA_DIGEST_SIZE), 0);

    wolfSSH_free(ssh);
#endif /* !WOLFSSH_NO_AES_GCM */

    wolfSSH_CTX_free(ctx);
}
static void TestDoNewKeys(void)
{
    WOLFSSH_CTX* ctx;
    WOLFSSH* ssh;
    byte payload[512];
    word32 payloadSz;
    word32 idx;
    byte expectedPeerEncryptId;
    byte expectedPeerMacId;
    byte expectedPeerAeadMode;
    Keys savedPeerKeys;

    /* Sub-test A: aes128-cbc C2S / aes256-ctr S2C -- non-AEAD both dirs.
     * After DoNewKeys on the server, ssh->peer* must reflect the C2S (peer
     * outgoing) direction, not the S2C (local outgoing) direction. */
    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_SERVER, NULL);
    AssertNotNull(ctx);
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

    AssertIntEQ(wolfSSH_TestGenerateKeys(ssh, ssh->handshake->kexHashId), WS_SUCCESS);

    /* Capture expected values before DoNewKeys frees handshake. */
    expectedPeerEncryptId = ssh->handshake->peerEncryptId;
    expectedPeerMacId     = ssh->handshake->peerMacId;
    expectedPeerAeadMode  = ssh->handshake->peerAeadMode;
    AssertIntEQ(expectedPeerAeadMode, 0); /* non-AEAD C2S */
    WMEMCPY(&savedPeerKeys, &ssh->handshake->peerKeys, sizeof(Keys));

    /* Peer has sent NewKeys; self has already sent its own (not keying). */
    ssh->isKeying = WOLFSSH_PEER_IS_KEYING;
    AssertIntEQ(wolfSSH_TestDoNewKeys(ssh, NULL, 0, NULL), WS_SUCCESS);

    /* handshake freed by DoNewKeys. */
    AssertTrue(ssh->handshake == NULL);

    /* ssh->peer* must reflect C2S direction, not S2C. */
    AssertIntEQ(ssh->peerEncryptId, expectedPeerEncryptId);
    AssertIntEQ(ssh->peerMacId,     expectedPeerMacId);
    AssertIntEQ(ssh->peerAeadMode,  0);
    AssertTrue(WMEMCMP(&ssh->peerKeys, &savedPeerKeys, sizeof(Keys)) == 0);

    /* Cipher lifecycle: DoNewKeys must init and key the decrypt cipher and
     * record its type, so wolfSSH_free()'s CipherClear frees exactly one
     * initialized AES context (aes128-cbc, non-AEAD). */
    AssertIntEQ(ssh->decryptCipher.isInit, 1);
    AssertIntEQ(ssh->decryptCipher.cipherType, expectedPeerEncryptId);

    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);

#ifndef WOLFSSH_NO_AES_GCM
    /* Sub-test B: aes256-gcm C2S (AEAD) / aes128-cbc S2C (non-AEAD).
     * Verifies peerAeadMode==1 (C2S AEAD) rather than 0 (S2C non-AEAD),
     * catching any regression back to handshake->aeadMode (S2C direction). */
    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_SERVER, NULL);
    AssertNotNull(ctx);
    ssh = wolfSSH_new(ctx);
    AssertNotNull(ssh);
    AssertIntEQ(wolfSSH_SetAlgoListKex(ssh, FPF_KEX_GOOD), WS_SUCCESS);
    AssertIntEQ(wolfSSH_SetAlgoListKey(ssh, FPF_KEY_GOOD), WS_SUCCESS);
    AssertIntEQ(wolfSSH_SetAlgoListCipher(ssh,
            "aes256-gcm@openssh.com,aes128-cbc"), WS_SUCCESS);
    AssertIntEQ(wolfSSH_SetAlgoListMac(ssh,
            "hmac-sha1,hmac-sha2-256"), WS_SUCCESS);
    idx = 0;
    payloadSz = BuildKexInitPayloadFull(
            FPF_KEX_GOOD, FPF_KEY_GOOD,
            "aes256-gcm@openssh.com", /* C2S enc: AEAD */
            "aes128-cbc",             /* S2C enc: non-AEAD */
            "hmac-sha1",              /* C2S MAC: skipped (AEAD) */
            "hmac-sha2-256",          /* S2C MAC: negotiated */
            0, payload, (word32)sizeof(payload));
    (void)wolfSSH_TestDoKexInit(ssh, payload, payloadSz, &idx);
    AssertNotNull(ssh->handshake);

    WMEMSET(ssh->k, 0xAA, WC_SHA256_DIGEST_SIZE);
    ssh->kSz = WC_SHA256_DIGEST_SIZE;
    WMEMSET(ssh->h, 0xBB, WC_SHA256_DIGEST_SIZE);
    ssh->hSz = WC_SHA256_DIGEST_SIZE;
    WMEMCPY(ssh->sessionId, ssh->h, ssh->hSz);
    ssh->sessionIdSz = ssh->hSz;

    AssertIntEQ(wolfSSH_TestGenerateKeys(ssh, ssh->handshake->kexHashId), WS_SUCCESS);

    expectedPeerEncryptId = ssh->handshake->peerEncryptId;
    expectedPeerMacId     = ssh->handshake->peerMacId;
    expectedPeerAeadMode  = ssh->handshake->peerAeadMode;
    AssertIntEQ(expectedPeerAeadMode, 1); /* AEAD C2S */
    WMEMCPY(&savedPeerKeys, &ssh->handshake->peerKeys, sizeof(Keys));

    ssh->isKeying = WOLFSSH_PEER_IS_KEYING;
    AssertIntEQ(wolfSSH_TestDoNewKeys(ssh, NULL, 0, NULL), WS_SUCCESS);

    AssertTrue(ssh->handshake == NULL);

    AssertIntEQ(ssh->peerEncryptId, expectedPeerEncryptId);
    AssertIntEQ(ssh->peerMacId,     expectedPeerMacId);
    AssertIntEQ(ssh->peerAeadMode,  1); /* must be C2S AEAD, not S2C non-AEAD */
    AssertTrue(WMEMCMP(&ssh->peerKeys, &savedPeerKeys, sizeof(Keys)) == 0);

    /* Cipher lifecycle for the AEAD path: aes256-gcm decrypt cipher inited
     * and typed. */
    AssertIntEQ(ssh->decryptCipher.isInit, 1);
    AssertIntEQ(ssh->decryptCipher.cipherType, expectedPeerEncryptId);

    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);
#endif /* !WOLFSSH_NO_AES_GCM */

    /* Sub-test C: client mirror of A -- aes128-cbc C2S / aes256-ctr S2C.
     * Client: C2S->keys (local), S2C->peerKeys (peer).  After DoNewKeys,
     * ssh->peer* must reflect the S2C (server outgoing) direction. */
    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_CLIENT, NULL);
    AssertNotNull(ctx);
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

    AssertIntEQ(wolfSSH_TestGenerateKeys(ssh, ssh->handshake->kexHashId), WS_SUCCESS);

    /* Capture expected values before DoNewKeys frees handshake. */
    expectedPeerEncryptId = ssh->handshake->peerEncryptId; /* S2C on client */
    expectedPeerMacId     = ssh->handshake->peerMacId;
    expectedPeerAeadMode  = ssh->handshake->peerAeadMode;
    AssertIntEQ(expectedPeerAeadMode, 0); /* non-AEAD S2C */
    WMEMCPY(&savedPeerKeys, &ssh->handshake->peerKeys, sizeof(Keys));

    ssh->isKeying = WOLFSSH_PEER_IS_KEYING;
    AssertIntEQ(wolfSSH_TestDoNewKeys(ssh, NULL, 0, NULL), WS_SUCCESS);

    AssertTrue(ssh->handshake == NULL);

    /* ssh->peer* must reflect S2C direction, not C2S. */
    AssertIntEQ(ssh->peerEncryptId, expectedPeerEncryptId);
    AssertIntEQ(ssh->peerMacId,     expectedPeerMacId);
    AssertIntEQ(ssh->peerAeadMode,  0);
    AssertTrue(WMEMCMP(&ssh->peerKeys, &savedPeerKeys, sizeof(Keys)) == 0);

    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);

#ifndef WOLFSSH_NO_AES_GCM
    /* Sub-test D: client mirror of B -- aes128-cbc C2S (non-AEAD) /
     * aes256-gcm S2C (AEAD).  Verifies peerAeadMode==1 (S2C AEAD) rather
     * than 0 (C2S non-AEAD), catching regression to handshake->aeadMode. */
    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_CLIENT, NULL);
    AssertNotNull(ctx);
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
            "hmac-sha2-256",          /* S2C MAC: skipped (AEAD) */
            0, payload, (word32)sizeof(payload));
    (void)wolfSSH_TestDoKexInit(ssh, payload, payloadSz, &idx);
    AssertNotNull(ssh->handshake);

    WMEMSET(ssh->k, 0xAA, WC_SHA256_DIGEST_SIZE);
    ssh->kSz = WC_SHA256_DIGEST_SIZE;
    WMEMSET(ssh->h, 0xBB, WC_SHA256_DIGEST_SIZE);
    ssh->hSz = WC_SHA256_DIGEST_SIZE;
    WMEMCPY(ssh->sessionId, ssh->h, ssh->hSz);
    ssh->sessionIdSz = ssh->hSz;

    AssertIntEQ(wolfSSH_TestGenerateKeys(ssh, ssh->handshake->kexHashId), WS_SUCCESS);

    expectedPeerEncryptId = ssh->handshake->peerEncryptId;
    expectedPeerMacId     = ssh->handshake->peerMacId;
    expectedPeerAeadMode  = ssh->handshake->peerAeadMode;
    AssertIntEQ(expectedPeerAeadMode, 1); /* AEAD S2C */
    WMEMCPY(&savedPeerKeys, &ssh->handshake->peerKeys, sizeof(Keys));

    ssh->isKeying = WOLFSSH_PEER_IS_KEYING;
    /* Exercise the len != 0 rejection while handshake is still allocated,
     * so the guard is reached and not short-circuited by handshake == NULL. */
    AssertIntEQ(wolfSSH_TestDoNewKeys(ssh, NULL, 1, NULL), WS_BAD_ARGUMENT);
    AssertNotNull(ssh->handshake);
    AssertIntEQ(wolfSSH_TestDoNewKeys(ssh, NULL, 0, NULL), WS_SUCCESS);

    AssertTrue(ssh->handshake == NULL);

    AssertIntEQ(ssh->peerEncryptId, expectedPeerEncryptId);
    AssertIntEQ(ssh->peerMacId,     expectedPeerMacId);
    AssertIntEQ(ssh->peerAeadMode,  1); /* must be S2C AEAD, not C2S non-AEAD */
    AssertTrue(WMEMCMP(&ssh->peerKeys, &savedPeerKeys, sizeof(Keys)) == 0);

    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);
#endif /* !WOLFSSH_NO_AES_GCM */

    /* Sub-test E: SELF_IS_KEYING guard - DoNewKeys must return
     * WS_INVALID_STATE_E when the local side has not yet sent its own
     * NEWKEYS (WOLFSSH_SELF_IS_KEYING still set). */
    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_SERVER, NULL);
    AssertNotNull(ctx);
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

    /* peer has sent NEWKEYS but local NEWKEYS not yet sent.
     * Key-material setup (k, h, sessionId, GenerateKeys) is intentionally
     * absent - SELF_IS_KEYING must fire before key derivation reads those fields. */
    ssh->isKeying = WOLFSSH_SELF_IS_KEYING | WOLFSSH_PEER_IS_KEYING;
    AssertIntEQ(wolfSSH_TestDoNewKeys(ssh, NULL, 0, NULL), WS_INVALID_STATE_E);

    /* DoNewKeys bailed before cleanup - handshake must still be allocated. */
    AssertNotNull(ssh->handshake);

    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);

    /* Sub-test F: never-keyed free. A session that never reached NEWKEYS has
     * uninitialized cipher contexts (isInit == 0); wolfSSH_free() must run
     * clean without calling wc_AesFree() on them. Locks in the uninitialized-
     * free behavior this PR's CipherClear guard fixes (best observed under
     * valgrind/ASan). */
    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_SERVER, NULL);
    AssertNotNull(ctx);
    ssh = wolfSSH_new(ctx);
    AssertNotNull(ssh);

    AssertIntEQ(ssh->encryptCipher.isInit, 0);
    AssertIntEQ(ssh->decryptCipher.isInit, 0);

    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);
}

#endif /* AES_CBC + AES_CTR + HMAC guards */

/* DoKexInit's PEER_IS_KEYING guard must return WS_INVALID_STATE_E when a
 * second SSH_MSG_KEXINIT arrives while a key exchange is already in progress,
 * preventing HandshakeInfo corruption if the outer IsMessageAllowed filter
 * were ever bypassed. */
static void TestDoKexInitRejectsWhenPeerIsKeying(void)
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

    payloadSz = BuildKexInitPayload(ssh, FPF_KEX_GOOD, FPF_KEY_GOOD, 0,
            payload, (word32)sizeof(payload));

    ssh->isKeying |= WOLFSSH_PEER_IS_KEYING;

    AssertIntEQ(wolfSSH_TestDoKexInit(ssh, payload, payloadSz, &idx),
            WS_INVALID_STATE_E);
    /* wolfSSH_new pre-allocates handshake; DoKexInit must not free it on
     * early return, so the ongoing key-exchange state is preserved. */
    AssertNotNull(ssh->handshake);

    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);
}

#endif /* first_packet_follows coverage guard */


/* Regression coverage for issue 5575: the documented ssh://hostname form must
 * set the hostname even without an explicit port, and a malformed destination
 * with no host text must leave the hostname unset so the client can reject it.
 */
static void TestClientParseDestination(void)
{
    char* user;
    char* hostname;
    word16 port;

    /* ssh:// without an explicit port: hostname set, default port kept. */
    user = NULL; hostname = NULL; port = 22;
    AssertIntEQ(ClientParseDestination("ssh://127.0.0.1",
                &user, &hostname, &port), WS_SUCCESS);
    AssertNotNull(hostname);
    AssertIntEQ(WSTRCMP(hostname, "127.0.0.1"), 0);
    AssertIntEQ(port, 22);
    AssertTrue(user == NULL);
    WFREE(hostname, NULL, 0);

    /* ssh://user@host without a port: user and hostname set, default port. */
    user = NULL; hostname = NULL; port = 22;
    AssertIntEQ(ClientParseDestination("ssh://tester@127.0.0.1",
                &user, &hostname, &port), WS_SUCCESS);
    AssertNotNull(user);
    AssertIntEQ(WSTRCMP(user, "tester"), 0);
    AssertNotNull(hostname);
    AssertIntEQ(WSTRCMP(hostname, "127.0.0.1"), 0);
    AssertIntEQ(port, 22);
    WFREE(user, NULL, 0);
    WFREE(hostname, NULL, 0);

    /* ssh://host:port: explicit port parsed. */
    user = NULL; hostname = NULL; port = 22;
    AssertIntEQ(ClientParseDestination("ssh://127.0.0.1:2222",
                &user, &hostname, &port), WS_SUCCESS);
    AssertNotNull(hostname);
    AssertIntEQ(WSTRCMP(hostname, "127.0.0.1"), 0);
    AssertIntEQ(port, 2222);
    AssertTrue(user == NULL);
    WFREE(hostname, NULL, 0);

    /* ssh://user@host:port: all parts parsed. */
    user = NULL; hostname = NULL; port = 22;
    AssertIntEQ(ClientParseDestination("ssh://tester@127.0.0.1:2222",
                &user, &hostname, &port), WS_SUCCESS);
    AssertNotNull(user);
    AssertIntEQ(WSTRCMP(user, "tester"), 0);
    AssertNotNull(hostname);
    AssertIntEQ(WSTRCMP(hostname, "127.0.0.1"), 0);
    AssertIntEQ(port, 2222);
    WFREE(user, NULL, 0);
    WFREE(hostname, NULL, 0);

    /* Plain (non-URI) hostname. */
    user = NULL; hostname = NULL; port = 22;
    AssertIntEQ(ClientParseDestination("127.0.0.1",
                &user, &hostname, &port), WS_SUCCESS);
    AssertNotNull(hostname);
    AssertIntEQ(WSTRCMP(hostname, "127.0.0.1"), 0);
    AssertIntEQ(port, 22);
    AssertTrue(user == NULL);
    WFREE(hostname, NULL, 0);

    /* Plain (non-URI) user@hostname. */
    user = NULL; hostname = NULL; port = 22;
    AssertIntEQ(ClientParseDestination("tester@127.0.0.1",
                &user, &hostname, &port), WS_SUCCESS);
    AssertNotNull(user);
    AssertIntEQ(WSTRCMP(user, "tester"), 0);
    AssertNotNull(hostname);
    AssertIntEQ(WSTRCMP(hostname, "127.0.0.1"), 0);
    AssertIntEQ(port, 22);
    WFREE(user, NULL, 0);
    WFREE(hostname, NULL, 0);

    /* Malformed URI with no host text: hostname stays unset. */
    user = NULL; hostname = NULL; port = 22;
    AssertIntEQ(ClientParseDestination("ssh://",
                &user, &hostname, &port), WS_SUCCESS);
    AssertTrue(hostname == NULL);
    AssertTrue(user == NULL);

    /* Malformed URI with a user but no host text: user set, hostname unset. */
    user = NULL; hostname = NULL; port = 22;
    AssertIntEQ(ClientParseDestination("ssh://tester@",
                &user, &hostname, &port), WS_SUCCESS);
    AssertNotNull(user);
    AssertIntEQ(WSTRCMP(user, "tester"), 0);
    AssertTrue(hostname == NULL);
    WFREE(user, NULL, 0);

    /* A pre-seeded user (as config_init_default does from $USER) is freed and
     * replaced when the destination carries its own user. */
    hostname = NULL; port = 22;
    user = (char*)WMALLOC(WSTRLEN("seeded") + 1, NULL, 0);
    AssertNotNull(user);
    WMEMCPY(user, "seeded", WSTRLEN("seeded") + 1);
    AssertIntEQ(ClientParseDestination("tester@127.0.0.1",
                &user, &hostname, &port), WS_SUCCESS);
    AssertNotNull(user);
    AssertIntEQ(WSTRCMP(user, "tester"), 0);
    AssertNotNull(hostname);
    AssertIntEQ(WSTRCMP(hostname, "127.0.0.1"), 0);
    WFREE(user, NULL, 0);
    WFREE(hostname, NULL, 0);

    /* A leading '@' (no user text) is accepted with an empty user string. */
    user = NULL; hostname = NULL; port = 22;
    AssertIntEQ(ClientParseDestination("ssh://@127.0.0.1",
                &user, &hostname, &port), WS_SUCCESS);
    AssertNotNull(user);
    AssertIntEQ(WSTRCMP(user, ""), 0);
    AssertNotNull(hostname);
    AssertIntEQ(WSTRCMP(hostname, "127.0.0.1"), 0);
    WFREE(user, NULL, 0);
    WFREE(hostname, NULL, 0);

    /* Non-URI "user@" with no host text: user set, hostname stays unset. */
    user = NULL; hostname = NULL; port = 22;
    AssertIntEQ(ClientParseDestination("tester@",
                &user, &hostname, &port), WS_SUCCESS);
    AssertNotNull(user);
    AssertIntEQ(WSTRCMP(user, "tester"), 0);
    AssertTrue(hostname == NULL);
    WFREE(user, NULL, 0);

    /* Non-URI leading '@': empty user, hostname set (no ssh:// prefix). */
    user = NULL; hostname = NULL; port = 22;
    AssertIntEQ(ClientParseDestination("@127.0.0.1",
                &user, &hostname, &port), WS_SUCCESS);
    AssertNotNull(user);
    AssertIntEQ(WSTRCMP(user, ""), 0);
    AssertNotNull(hostname);
    AssertIntEQ(WSTRCMP(hostname, "127.0.0.1"), 0);
    WFREE(user, NULL, 0);
    WFREE(hostname, NULL, 0);

    /* An out-of-range port is rejected (not silently truncated) and the
     * caller's port and outputs are left untouched. */
    user = NULL; hostname = NULL; port = 22;
    AssertIntEQ(ClientParseDestination("ssh://127.0.0.1:70000",
                &user, &hostname, &port), WS_BAD_ARGUMENT);
    AssertIntEQ(port, 22);
    AssertTrue(user == NULL);
    AssertTrue(hostname == NULL);

    /* Non-numeric, trailing-garbage, and zero ports are rejected too. */
    user = NULL; hostname = NULL; port = 22;
    AssertIntEQ(ClientParseDestination("ssh://127.0.0.1:abc",
                &user, &hostname, &port), WS_BAD_ARGUMENT);
    AssertIntEQ(port, 22);
    user = NULL; hostname = NULL; port = 22;
    AssertIntEQ(ClientParseDestination("ssh://127.0.0.1:22x",
                &user, &hostname, &port), WS_BAD_ARGUMENT);
    AssertIntEQ(port, 22);
    user = NULL; hostname = NULL; port = 22;
    AssertIntEQ(ClientParseDestination("ssh://127.0.0.1:0",
                &user, &hostname, &port), WS_BAD_ARGUMENT);
    AssertIntEQ(port, 22);

    /* A valid in-range port is still accepted. */
    user = NULL; hostname = NULL; port = 22;
    AssertIntEQ(ClientParseDestination("ssh://127.0.0.1:65535",
                &user, &hostname, &port), WS_SUCCESS);
    AssertIntEQ(port, 65535);
    WFREE(hostname, NULL, 0);

    /* "ssh://" is only a prefix when it starts the string; a later occurrence
     * is treated as ordinary host text, not a URI. */
    user = NULL; hostname = NULL; port = 22;
    AssertIntEQ(ClientParseDestination("user@ssh://127.0.0.1",
                &user, &hostname, &port), WS_SUCCESS);
    AssertNotNull(user);
    AssertIntEQ(WSTRCMP(user, "user"), 0);
    AssertNotNull(hostname);
    AssertIntEQ(WSTRCMP(hostname, "ssh://127.0.0.1"), 0);
    AssertIntEQ(port, 22);
    WFREE(user, NULL, 0);
    WFREE(hostname, NULL, 0);

    /* Each NULL output pointer (and a NULL input) is rejected. */
    user = NULL; hostname = NULL; port = 22;
    AssertIntEQ(ClientParseDestination(NULL, &user, &hostname, &port),
            WS_BAD_ARGUMENT);
    AssertIntEQ(ClientParseDestination("127.0.0.1", NULL, &hostname, &port),
            WS_BAD_ARGUMENT);
    AssertIntEQ(ClientParseDestination("127.0.0.1", &user, NULL, &port),
            WS_BAD_ARGUMENT);
    AssertIntEQ(ClientParseDestination("127.0.0.1", &user, &hostname, NULL),
            WS_BAD_ARGUMENT);
    /* No output should have been touched by the rejected calls. */
    AssertTrue(user == NULL);
    AssertTrue(hostname == NULL);
}


#if defined(WOLFSSH_TEST_INTERNAL) || defined(WOLFSSL_BASE64_ENCODE)
/* Write contents to path exactly as given, with no terminator added, so a
 * test can seed a file whose last line ends without a newline. */
static void WriteTextFile(const char* path, const char* contents)
{
    WFILE* f = WBADFILE;
    word32 sz = (word32)WSTRLEN(contents);

    AssertIntEQ(WFOPEN(NULL, &f, path, "wb"), 0);
    AssertTrue(f != WBADFILE);
    /* With WOLFSSH_NO_ABORT the asserts above do not stop the run, so return
     * rather than write through a handle the open never produced. */
    if (f == WBADFILE) {
        return;
    }
    AssertIntEQ((word32)WFWRITE(NULL, contents, 1, sz, f), sz);
    AssertIntEQ(WFCLOSE(NULL, f), 0);
}
#endif


#ifdef WOLFSSH_TEST_INTERNAL
/* AppendKeyToFile must refuse a host name or key type that carries whitespace
 * or control bytes, so an attacker-controlled value cannot inject extra fields
 * or a forged entry into the known_hosts file. Exercised through the
 * wolfSSH_TestAppendKeyToFile hook. */
static void TestAppendKeyToFile(void)
{
    const char* path = "regress_known_hosts.tmp";
    char buf[128];
    word32 readSz;

    /* A clean name and type write one well-formed, newline-terminated entry. */
    (void)remove(path);
    AssertIntEQ(wolfSSH_TestAppendKeyToFile(path, "host.example.com",
                "ssh-rsa", "AAAA"), WS_SUCCESS);
    WMEMSET(buf, 0, sizeof(buf));
    readSz = LoadFileBuffer(path, (byte*)buf, sizeof(buf) - 1);
    AssertTrue(readSz > 0);
    AssertIntEQ(WSTRCMP(buf, "host.example.com ssh-rsa AAAA\n"), 0);

    /* A second call appends rather than truncating, preserving the first
     * entry (the file is opened in append mode). */
    AssertIntEQ(wolfSSH_TestAppendKeyToFile(path, "host2.example.com",
                "ssh-ed25519", "BBBB"), WS_SUCCESS);
    WMEMSET(buf, 0, sizeof(buf));
    readSz = LoadFileBuffer(path, (byte*)buf, sizeof(buf) - 1);
    AssertTrue(readSz > 0);
    AssertIntEQ(WSTRCMP(buf,
                "host.example.com ssh-rsa AAAA\n"
                "host2.example.com ssh-ed25519 BBBB\n"), 0);

    /* A newline in the name would forge an extra entry; it is rejected and
     * nothing is written to the file. */
    (void)remove(path);
    AssertIntEQ(wolfSSH_TestAppendKeyToFile(path,
                "127.0.0.1\nevil.example.com ssh-rsa BBBB", "ssh-rsa", "CCCC"),
            WS_BAD_ARGUMENT);
    AssertIntEQ(LoadFileBuffer(path, (byte*)buf, sizeof(buf) - 1), 0);

    /* A space in the name would forge extra fields; it is rejected. */
    (void)remove(path);
    AssertIntEQ(wolfSSH_TestAppendKeyToFile(path, "real.example.com other",
                "ssh-rsa", "CCCC"), WS_BAD_ARGUMENT);
    AssertIntEQ(LoadFileBuffer(path, (byte*)buf, sizeof(buf) - 1), 0);

    /* The key type is peer-supplied and is checked the same way: a newline in
     * it is rejected and nothing is written. */
    (void)remove(path);
    AssertIntEQ(wolfSSH_TestAppendKeyToFile(path, "host.example.com",
                "ssh-rsa\nevil.example.com ssh-rsa DDDD", "EEEE"),
            WS_BAD_ARGUMENT);
    AssertIntEQ(LoadFileBuffer(path, (byte*)buf, sizeof(buf) - 1), 0);

    /* Tab, carriage return, and DEL (0x7f) are rejected too, and each leaves
     * the file unwritten. */
    (void)remove(path);
    AssertIntEQ(wolfSSH_TestAppendKeyToFile(path, "host\tname", "ssh-rsa",
                "CCCC"), WS_BAD_ARGUMENT);
    AssertIntEQ(LoadFileBuffer(path, (byte*)buf, sizeof(buf) - 1), 0);
    AssertIntEQ(wolfSSH_TestAppendKeyToFile(path, "host\rname", "ssh-rsa",
                "CCCC"), WS_BAD_ARGUMENT);
    AssertIntEQ(LoadFileBuffer(path, (byte*)buf, sizeof(buf) - 1), 0);
    AssertIntEQ(wolfSSH_TestAppendKeyToFile(path, "host\x7fname", "ssh-rsa",
                "CCCC"), WS_BAD_ARGUMENT);
    AssertIntEQ(LoadFileBuffer(path, (byte*)buf, sizeof(buf) - 1), 0);

    /* A NULL or empty name, type, or key is rejected and nothing is written.
     * The key check guards fprintf against a NULL or empty value. */
    AssertIntEQ(wolfSSH_TestAppendKeyToFile(path, NULL, "ssh-rsa", "CCCC"),
            WS_BAD_ARGUMENT);
    AssertIntEQ(wolfSSH_TestAppendKeyToFile(path, "", "ssh-rsa", "CCCC"),
            WS_BAD_ARGUMENT);
    AssertIntEQ(wolfSSH_TestAppendKeyToFile(path, "host.example.com", "",
                "CCCC"), WS_BAD_ARGUMENT);
    AssertIntEQ(wolfSSH_TestAppendKeyToFile(path, "host.example.com", "ssh-rsa",
                NULL), WS_BAD_ARGUMENT);
    AssertIntEQ(wolfSSH_TestAppendKeyToFile(path, "host.example.com", "ssh-rsa",
                ""), WS_BAD_ARGUMENT);
    AssertIntEQ(LoadFileBuffer(path, (byte*)buf, sizeof(buf) - 1), 0);

    /* High-bit (non-ASCII) bytes are only above the control range, so an
     * internationalized host name is stored intact rather than rejected. This
     * pins the unsigned-char handling: a signed-char compare would wrongly
     * reject 0x80-0xff. */
    (void)remove(path);
    AssertIntEQ(wolfSSH_TestAppendKeyToFile(path, "h\xC3\xA9st", "ssh-rsa",
                "AAAA"), WS_SUCCESS);
    WMEMSET(buf, 0, sizeof(buf));
    readSz = LoadFileBuffer(path, (byte*)buf, sizeof(buf) - 1);
    AssertTrue(readSz > 0);
    AssertIntEQ(WSTRCMP(buf, "h\xC3\xA9st ssh-rsa AAAA\n"), 0);

    /* When the file cannot be opened (here, a path under a directory that does
     * not exist), the function reports the failure rather than claiming
     * success. */
    AssertTrue(wolfSSH_TestAppendKeyToFile("regress_no_such_dir/known_hosts",
                "host.example.com", "ssh-rsa", "AAAA") != WS_SUCCESS);

    (void)remove(path);
}


/* POSIX lets the last line of a text file end without a newline. An appended
 * entry has to start on its own line, otherwise it runs onto the last stored
 * entry and both are corrupted: the old host ends up pinned to a key it never
 * had, and the new host is never stored at all. */
static void TestAppendNoTrailingNewline(void)
{
    const char* path = "regress_known_hosts_nl.tmp";
    static const struct {
        const char* seed;
        const char* expected;
    } cases[] = {
        /* Unterminated last line: the entry gets a separator of its own. */
        { "a.example.com ssh-rsa AAAA",
          "a.example.com ssh-rsa AAAA\nb.example.com ssh-rsa BBBB\n" },
        /* Already terminated: no separator, so no blank line. */
        { "a.example.com ssh-rsa AAAA\n",
          "a.example.com ssh-rsa AAAA\nb.example.com ssh-rsa BBBB\n" },
        /* CRLF ends in a newline too, and the seed is kept byte for byte. */
        { "a.example.com ssh-rsa AAAA\r\n",
          "a.example.com ssh-rsa AAAA\r\nb.example.com ssh-rsa BBBB\n" },
        /* An empty file has no last line to run onto. */
        { "", "b.example.com ssh-rsa BBBB\n" }
    };
    char buf[128];
    word32 readSz;
    unsigned int i;

    for (i = 0; i < sizeof(cases)/sizeof(cases[0]); i++) {
        (void)remove(path);
        WriteTextFile(path, cases[i].seed);
        AssertIntEQ(wolfSSH_TestAppendKeyToFile(path, "b.example.com",
                    "ssh-rsa", "BBBB"), WS_SUCCESS);
        WMEMSET(buf, 0, sizeof(buf));
        readSz = LoadFileBuffer(path, (byte*)buf, sizeof(buf) - 1);
        AssertTrue(readSz > 0);
        AssertStrEQ(buf, cases[i].expected);
    }

    /* An absent file is created, and needs no separator either. */
    (void)remove(path);
    AssertIntEQ(wolfSSH_TestAppendKeyToFile(path, "b.example.com",
                "ssh-rsa", "BBBB"), WS_SUCCESS);
    WMEMSET(buf, 0, sizeof(buf));
    readSz = LoadFileBuffer(path, (byte*)buf, sizeof(buf) - 1);
    AssertTrue(readSz > 0);
    AssertStrEQ(buf, "b.example.com ssh-rsa BBBB\n");

    (void)remove(path);
}
#endif /* WOLFSSH_TEST_INTERNAL */


#ifdef WOLFSSL_BASE64_ENCODE

/* Every known_hosts rejection returns -1: a known host with the wrong key, and
 * an unrecognized host whose "add it?" prompt reads EOF. Only the message
 * tells them apart, so run the check with stdout captured and let the caller
 * assert on what was printed. Returns the check's own return value. */
static int KnownHostsCheckCapture(const byte* pubKey, word32 pubKeySz,
        char* targetName, char* out, word32 outSz)
{
    char capPath[64];
    int savedStdout, capFd, ret;
    long readSz = 0;
    WFILE* f = WBADFILE;

    WSNPRINTF(capPath, sizeof(capPath), "wolfssh_kh_out_%d.tmp", (int)getpid());
    out[0] = 0;

    capFd = open(capPath, O_RDWR | O_CREAT | O_TRUNC, 0600);
    AssertTrue(capFd >= 0);
    savedStdout = dup(STDOUT_FILENO);
    AssertTrue(savedStdout >= 0);
    fflush(stdout);
    AssertTrue(dup2(capFd, STDOUT_FILENO) >= 0);

    ret = ClientPublicKeyCheck(pubKey, pubKeySz, targetName);

    /* stdout is a file here, so it is fully buffered; flush before restoring */
    fflush(stdout);
    AssertTrue(dup2(savedStdout, STDOUT_FILENO) >= 0);
    close(savedStdout);
    close(capFd);

    if (WFOPEN(NULL, &f, capPath, "rb") == 0 && f != WBADFILE) {
        readSz = (long)WFREAD(NULL, out, 1, outSz - 1, f);
        WFCLOSE(NULL, f);
    }
    if (readSz < 0) {
        readSz = 0;
    }
    out[readSz] = 0;
    (void)remove(capPath);

    return ret;
}


/* known_hosts is a text file and POSIX lets its last line end without a
 * newline, and a file written on Windows ends its lines with CRLF. Match the
 * last entry with a trailing newline, without one, and with CRLF line
 * endings, then check that a wrong key on that same last entry is still
 * rejected. */
static void TestKnownHostsLastEntry(void)
{
    /* string("ssh-rsa"), then a zero certificate count so the RFC 6187 parse
     * declines this blob, then filler. Only the name and the base64 of the
     * whole blob matter to the known_hosts search. */
    static const byte pubKey[] = {
        0x00, 0x00, 0x00, 0x07, 's', 's', 'h', '-', 'r', 's', 'a',
        0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04
    };
    static const struct {
        const char* sep;
        const char* tail;
        const char* label;
    } cases[] = {
        { "\n",   "\n",   "trailing newline" },
        { "\n",   "",     "no trailing newline" },
        { "\r\n", "\r\n", "CRLF endings" },
    };
    char targetName[] = "last.example.com";
    char homeDir[64];
    char sshDir[80];
    char hostsPath[112];
    char encoded[64];
    char wrongKey[64];
    char contents[256];
    char captured[512];
    char* savedHome = NULL;
    const char* home;
    word32 encodedSz = (word32)sizeof(encoded);
    int savedStdin, devNull, ready;
    unsigned int i;

    WSNPRINTF(homeDir, sizeof(homeDir), "wolfssh_kh_%d.tmp", (int)getpid());
    WSNPRINTF(sshDir, sizeof(sshDir), "%s/.ssh", homeDir);
    WSNPRINTF(hostsPath, sizeof(hostsPath), "%s/known_hosts", sshDir);

    AssertIntEQ(Base64_Encode_NoNl(pubKey, (word32)sizeof(pubKey),
                (byte*)encoded, &encodedSz), 0);
    AssertTrue(encodedSz < sizeof(encoded));
    encoded[encodedSz] = 0;

    /* Same length and alphabet, different key, for the rejection case. */
    WMEMCPY(wrongKey, encoded, encodedSz + 1);
    wrongKey[0] = (encoded[0] == 'A') ? 'B' : 'A';

    home = getenv("HOME");
    if (home != NULL) {
        savedHome = (char*)WMALLOC(WSTRLEN(home) + 1, NULL, 0);
        AssertNotNull(savedHome);
        WSTRCPY(savedHome, home);
    }

    /* The name only varies by pid, so an aborted run can leave the tree
     * behind and make the mkdir below fail. Clear it first. */
    (void)remove(hostsPath);
    (void)rmdir(sshDir);
    (void)rmdir(homeDir);

    /* Use a single flag to avoid duplicate errors below. */
    ready = (mkdir(homeDir, 0700) == 0)
            && (mkdir(sshDir, 0700) == 0)
            && (setenv("HOME", homeDir, 1) == 0);
    AssertTrue(ready);

    /* A regression falls through to the "add it to known hosts?" prompt, so
     * point stdin at EOF: the test then fails rather than waiting forever.
     * Check each step, otherwise a failure here leaves the prompt reading
     * the real stdin. */
    savedStdin = dup(STDIN_FILENO);
    devNull = open("/dev/null", O_RDONLY);
    ready = ready && (savedStdin >= 0) && (devNull >= 0)
            && (dup2(devNull, STDIN_FILENO) >= 0);
    AssertTrue(ready);

    for (i = 0; ready && i < sizeof(cases)/sizeof(cases[0]); i++) {
        printf("    known_hosts with %s.\n", cases[i].label);

        /* An entry for a different host goes first, so the match lands on the
         * last line, the one the terminator used to overwrite. */
        WSNPRINTF(contents, sizeof(contents),
                "other.example.com ssh-rsa AAAA%s%s ssh-rsa %s%s",
                cases[i].sep, targetName, encoded, cases[i].tail);
        WriteTextFile(hostsPath, contents);
        AssertIntEQ(ClientPublicKeyCheck(pubKey, (word32)sizeof(pubKey),
                    targetName), 0);

        /* The same host listed with a different key is a known host with an
         * unknown key, which must be rejected rather than prompted for. A
         * regression that never parses the last entry also returns non-zero,
         * by prompting and reading EOF, so require the message that only the
         * known-host-wrong-key path prints and reject the prompt text. */
        WSNPRINTF(contents, sizeof(contents),
                "other.example.com ssh-rsa AAAA%s%s ssh-rsa %s%s",
                cases[i].sep, targetName, wrongKey, cases[i].tail);
        WriteTextFile(hostsPath, contents);
        AssertTrue(KnownHostsCheckCapture(pubKey, (word32)sizeof(pubKey),
                    targetName, captured, (word32)sizeof(captured)) != 0);
        AssertNotNull(WSTRSTR(captured,
                    "That server is known, but that key is not."));
        AssertNull(WSTRSTR(captured, "Shall I add it to the known hosts?"));

        /* The CR strip makes a non-matching host's key compare equal under
         * CRLF, which is the only way the "matches other servers" branch is
         * reached with those endings. Same key on both lines: the first
         * reports the other server, the last one still matches the target. */
        WSNPRINTF(contents, sizeof(contents),
                "other.example.com ssh-rsa %s%s%s ssh-rsa %s%s",
                encoded, cases[i].sep, targetName, encoded, cases[i].tail);
        WriteTextFile(hostsPath, contents);
        AssertIntEQ(KnownHostsCheckCapture(pubKey, (word32)sizeof(pubKey),
                    targetName, captured, (word32)sizeof(captured)), 0);
        AssertNotNull(WSTRSTR(captured, "This key matches other servers:"));
        AssertNotNull(WSTRSTR(captured, "other.example.com"));
    }

    if (savedStdin >= 0) {
        AssertTrue(dup2(savedStdin, STDIN_FILENO) >= 0);
        close(savedStdin);
    }
    if (devNull >= 0) {
        close(devNull);
    }

    if (savedHome != NULL) {
        AssertIntEQ(setenv("HOME", savedHome, 1), 0);
        WFREE(savedHome, NULL, 0);
    }
    else {
        unsetenv("HOME");
    }

    (void)remove(hostsPath);
    (void)rmdir(sshDir);
    (void)rmdir(homeDir);
}
#endif /* WOLFSSL_BASE64_ENCODE */


int main(int argc, char** argv)
{
    WOLFSSH_CTX* ctx;
    WOLFSSH* ssh;
#ifndef NO_WOLFSSH_SERVER
    WOLFSSH_CTX* serverCtx;
    WOLFSSH* serverSsh;
#endif

    (void)argc;
    (void)argv;

    wolfSSH_Init();

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_CLIENT, NULL);
    AssertNotNull(ctx);

    ssh = wolfSSH_new(ctx);
    AssertNotNull(ssh);

#ifndef NO_WOLFSSH_SERVER
    serverCtx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_SERVER, NULL);
    AssertNotNull(serverCtx);

    serverSsh = wolfSSH_new(serverCtx);
    AssertNotNull(serverSsh);
#endif

    TestClientParseDestination();
#ifdef WOLFSSH_TEST_INTERNAL
    TestAppendKeyToFile();
    TestAppendNoTrailingNewline();
#endif
#ifdef WOLFSSL_BASE64_ENCODE
    TestKnownHostsLastEntry();
#endif
    TestAuthMessageBlockedDuringKeying(ssh);
    TestUserauthFailureDuringKeying(ssh);
    TestPasswordLeakAborts(ssh);
    TestPrematureUserauthSuccess(ssh);
    TestChannelSpoofSequence(ssh);
    TestChannelSpoofAborts(ssh);
    TestPublicKeyFailureBeforeRequest(ssh);
    TestPublicKeyFailureAborts(ssh);
    TestChannelBlockedBeforeAuth(ssh);
    TestChannelBlockedEveryPreAuthState(ssh);
    TestChannelAllowedAfterAuth(ssh);
    TestClientOnlyKexMsgsBlocked(ssh);
    TestClientServiceAcceptBlockedDuringKeying(ssh);
    TestChannelOpenRejectedBeforeKex(CONNECT_CLIENT_KEXINIT_SENT);
    TestChannelOpenRejectedBeforeKex(CONNECT_CLIENT_KEXDH_INIT_SENT);
#ifndef NO_WOLFSSH_SERVER
    TestServerChannelBlockedBeforeAuth(serverSsh);
    TestServerChannelAllowedAfterAuth(serverSsh);
    TestServerUserauthBlockedBeforeKeyed(serverSsh);
    TestServerHighMsgIdBeforeAuthDisconnects();
    TestServerUnknownMsgIdBeforeAuthUnimplemented();
    TestServerKnownAuthMsgIdBeforeAuthDisconnects();
    TestServerUnknownHighMsgIdBeforeAuthDisconnects();
    TestServerOnlyUserauthMsgsBlocked(serverSsh);
    TestServerOnlyKexMsgsBlocked(serverSsh);
    TestServerServiceRequestStateGated(serverSsh);
    TestServerServiceRequestRejectedDuringKeying();
    TestFailedSendClearsPendingPlaintext();
    TestChannelOpenCallbackRejectSendsOpenFail();
    TestSecondSessionChannelRejected();
    TestUsernameChangeDisconnects();
    TestSameUserRetryAllowed();
#ifdef WOLFSSH_KEYBOARD_INTERACTIVE
    TestKbInfoResponseCountMismatchSendsFailure();
    TestKbInfoResponseMismatchKeepsFraming();
#endif
#ifdef WOLFSSH_FWD
    TestDirectTcpipRejectSendsOpenFail();
    TestDirectTcpipNoFwdCbSendsOpenFail();
    TestDirectTcpipOpenCbRejectBeatsFwdCb();
    TestDirectTcpipFwdCbRejectAfterOpenCbAccept();
    TestDirectTcpipFwdCbRejectsChannelId();
    TestForwardedTcpipOnServerSendsOpenFail();
    TestGlobalRequestFwdNoCbSendsFailure();
#ifndef NO_WOLFSSH_CLIENT
    TestGlobalRequestFwdOnClientSendsFailure();
    TestGlobalRequestFwdCancelOnClientSendsFailure();
    TestGlobalRequestFwdOnClientNoReplyStaysQuiet();
#endif
    TestGlobalRequestFwdOnServerStillSucceeds();
    TestGlobalRequestFwdNoCbNoReplyKeepsConnection();
    TestGlobalRequestFwdWithCbSendsSuccess();
    TestGlobalRequestFwdPort0ReturnsAllocatedPort();
    TestGlobalRequestFwdPort0NoAllocSendsFailure();
    TestGlobalRequestFwdRemoteSetupErrorSendsFailure();
    TestGlobalRequestFwdPort0NoAllocNoReplyKeepsConnection();
    TestGlobalRequestFwdCancelNoCbSendsFailure();
    TestGlobalRequestFwdCancelWithCbSendsSuccess();
    TestRequestSuccessWithPortParsesCorrectly();
#endif
#ifdef WOLFSSH_AGENT
    TestAgentChannelNullAgentSendsOpenFail();
#endif
#endif /* NO_WOLFSSH_SERVER */
#if defined(WOLFSSH_AGENT) && !defined(WOLFSSH_NO_ED25519) \
    && !defined(NO_WOLFSSH_CLIENT)
    TestAgentEd25519UserAuthEmitsSignature();
    TestAgentEd25519UserAuthPropagatesAgentError();
    TestAgentEd25519UserAuthRejectsOversizeSignature();
#endif
#if defined(WOLFSSH_FWD) && !defined(NO_WOLFSSH_CLIENT)
    TestForwardedTcpipRegisteredIsAccepted();
    TestForwardedTcpipUnregisteredSendsOpenFail();
    TestForwardedTcpipWildcardBindMatchesAnyAddr();
    TestForwardedTcpipCancelledSendsOpenFail();
    TestForwardedTcpipPortZeroMatchesBoundPort();
    TestForwardedTcpipRefusedForwardSendsOpenFail();
    TestForwardedTcpipUntrackedClientUnchanged();
    TestForwardedTcpipCancelConfirmedSendsOpenFail();
    TestForwardedTcpipCancelPendingStopsMatching();
    TestForwardedTcpipCancelRefusedRestoresMatching();
    TestForwardedTcpipCancelRefusedKeepsForward();
    TestForwardedTcpipUnmatchedCancelKeepsForward();
    TestForwardedTcpipCancelBeforeSetupReply();
    TestForwardedTcpipCancelBeforeSetupReplyKeepsOther();
    TestForwardedTcpipSetupAndCancelBothRefusedDrops();
    TestForwardedTcpipDuplicateSetupIsOneForward();
    TestForwardedTcpipDuplicateSetupRefusalKeepsForward();
    TestForwardedTcpipDuplicateSetupLaterSuccessBinds();
    TestForwardedTcpipDuplicateSetupBothRefusedDrops();
    TestForwardedTcpipSetupAfterPendingCancelKeepsForward();
    TestForwardedTcpipSetupAfterPendingCancelRefusedDrops();
    TestForwardedTcpipRefusedCancelThenCancelDrops();
    TestForwardedTcpipOverlappingCancelsLastOneSettles();
    TestForwardedTcpipNoReplyCancelOverridesPending();
    TestForwardedTcpipConfirmedCancelDropsEarlierSuccess();
    TestForwardedTcpipConfirmedCancelThenSetupBinds();
    TestForwardedTcpipPortZeroReplyFoldsDuplicate();
    TestForwardedTcpipPortZeroFoldSettlesQueuedCancel();
    TestForwardedTcpipPostSendErrorStillRegisters();
    TestForwardedTcpipFailedSendRegistersNothing();
    TestForwardedTcpipReentrantSetupDuringSend();
    TestForwardedTcpipReentrantRequestKeepsSendOrder();
    TestForwardedTcpipReplyDuringSendTakesSlot();
    TestForwardedTcpipReplyFromSendCommits();
    TestForwardedTcpipRefusalFromSendDropsForward();
    TestForwardedTcpipPortZeroReplyFromSendBinds();
    TestForwardedTcpipFailedSendDiscardsAnsweredSlot();
    TestForwardedTcpipRefusalFromSendSeesSendingCancel();
    TestForwardedTcpipRefusalDuringSendDropsForward();
    TestForwardedTcpipPortZeroReplyDuringSendBinds();
    TestForwardedTcpipRequestAfterReplyDuringSend();
    TestForwardedTcpipCancelAnsweredDuringResetupKeepsForward();
    TestForwardedTcpipReentrantCancelDuringSend();
    TestForwardedTcpipReentrantCancelOfFirstSetup();
    TestForwardedTcpipReentrantSetupDuringCancel();
    TestForwardedTcpipInboundOpenDuringSend();
    TestFwdRemoteMatchPortIgnoresBindAddr();
    TestFwdRemoteMatchOffAcceptsUnregistered();
    TestFwdRemoteMatchRejectsBadSetting();
    TestFwdReplyQueueIsCapped();
    TestForwardedTcpipAppRequestKeepsItsOwnReply();
    TestForwardedTcpipWantWriteStillRegisters();
    TestForwardedTcpipInterruptedSendStillRegisters();
    TestInterruptedSendRetriesForAnySender();
    TestGlobalRequestNoReplyQueuesNothing();
    TestForwardedTcpipRepliesPairInSendOrder();
    TestForwardedTcpipUnusablePortReplySendsOpenFail();
    TestForwardedTcpipPortZeroOtherPortSendsOpenFail();
#endif /* WOLFSSH_FWD && !NO_WOLFSSH_CLIENT */
    TestKexInitRejectedWhenKeying(ssh);
#if !defined(WOLFSSH_NO_ECDH_SHA2_NISTP256) && !defined(WOLFSSH_NO_RSA) \
    && !defined(WOLFSSH_NO_CURVE25519_SHA256) \
    && !defined(WOLFSSH_NO_RSA_SHA2_256)
    TestFirstPacketFollows();
    TestKexInitReservedNonZeroRejected();
    TestKexInitNameListCaps();
    TestKexInitEmptyName();
    TestExtInfoEmptyName();
    TestExtInfoNameListCaps();
    TestExtInfoSigAlgsReplace();
    TestKexInitLanguageLengthOverflow();
    TestDoKexInitRejectsWhenPeerIsKeying();
#endif
#if !defined(WOLFSSH_NO_ECDH_SHA2_NISTP256) && !defined(WOLFSSH_NO_RSA) \
    && !defined(WOLFSSH_NO_CURVE25519_SHA256) \
    && !defined(WOLFSSH_NO_RSA_SHA2_256) \
    && !defined(WOLFSSH_NO_AES_CBC) && !defined(WOLFSSH_NO_AES_CTR) \
    && !defined(WOLFSSH_NO_HMAC_SHA1) && !defined(WOLFSSH_NO_HMAC_SHA2_256)
    TestIndependentAlgoNegotiation();
    TestIndependentAlgoNegotiationClient();
    TestEncMismatch();
    TestMacMismatch();
    TestGenerateKeysSplit();
    TestGenerateKeysSplitClient();
    TestDoNewKeys();
#endif
    TestDisconnectSetsDisconnectError();
    TestDisconnectTerminalWithChannel();
    TestDisconnectDrainsBufferedData();
    TestDisconnectBlocksEverySend();
    TestSendDisconnectIsTerminal();
#ifndef NO_WOLFSSH_SERVER
    TestDisconnectGatesAccept();
#endif
#ifndef NO_WOLFSSH_CLIENT
    TestDisconnectGatesConnect();
#endif
    TestDisconnectSilencesInboundReplies();
    TestDisconnectKeepsStreamInStep();
    TestDisconnectDropsLateChannelData();
    TestDisconnectQuietWindowAdjust();
    TestDisconnectBlocksChannelAndFwdSends();
    TestStreamExitReportsDisconnect();
    TestShutdownQuietAfterDisconnect();
    TestHighwaterQuietAfterDisconnect();
    TestAppHighwaterQuietAfterDisconnect();
    TestPeerDisconnectKeepsTrafficQueued(0);
    TestPeerDisconnectKeepsTrafficQueued(1);
    TestShutdownFlushesWithNoChannel();
    TestQueuedDisconnectFlushes();
    TestShutdownFlushesQueuedDisconnect();
    TestShutdownKeepsFlushWantWrite();
    TestDisconnectTxdClearsOnFlush();
    TestDisconnectOutranksRekey();
    TestWorkerReportsDisconnect();
#if defined(WOLFSSH_TERM) && !defined(NO_FILESYSTEM)
    TestTerminalResizeBlockedAfterDisconnect();
#endif
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
    #ifndef WOLFSSH_NO_ECDSA_SHA2_NISTP256
    TestKexDhReplyRejectsEccSigNameDowngrade();
    #endif
    #ifndef WOLFSSH_NO_ED25519
    TestKexDhReplyRejectsEd25519SigNameDowngrade();
    #endif
    TestKexDhReplyRejectsNoPublicKeyCheck();
    TestKexDhReplyRejectsWhenCallbackRejects();
    #ifndef WOLFSSH_NO_RSA_SHA2_256
    TestKexDhReplyRejectsRsaSha2_256CorruptSig();
    #endif
    #ifndef WOLFSSH_NO_RSA_SHA2_512
    TestKexDhReplyRejectsRsaSha2_512CorruptSig();
    #endif
    #ifndef WOLFSSH_NO_ECDSA_SHA2_NISTP256
    TestKexDhReplyRejectsEccCorruptSig();
    #endif
    #ifndef WOLFSSH_NO_ED25519
    TestKexDhReplyRejectsEd25519CorruptSig();
    #endif
    TestKexDhReplyRejectsSigNameOverrun();
    #ifdef REGRESS_TRUNC_KEX_ALGO
    TestKexDhReplyTruncatedFSendsDisconnect();
    TestKexDhInitTruncatedESendsDisconnect();
    TestKexDhInitEmptyESendsDisconnect();
    #endif
    #ifdef REGRESS_GEX_KEX_ALGO
    TestKexDhGexGroupShrunkPrimeSendsDisconnect();
    TestKexDhGexGroupBadGeneratorSendsDisconnect();
    #endif
#endif

#ifdef WOLFSSH_SFTP
    TestOct2DecRejectsInvalidNonLeadingDigit();
    TestSftpBufferSendPendingOutput();
    #if !defined(NO_WOLFSSH_SERVER) && !defined(USE_WINDOWS_API) && \
            !defined(NO_FILESYSTEM)
    /* fenrir 4232/4343/4346/4349: forged SFTP file handles must be rejected */
    TestSftpForgedHandleRejected();
    #ifndef NO_WOLFSSH_DIR
    /* file and directory handle IDs share one namespace and never cross-close */
    TestSftpHandleNamespaceIsolation();
    #endif
    /* open file handles are capped per session */
    TestSftpHandleLimit();
    #ifndef NO_WOLFSSH_DIR
    /* open directory handles are capped per session */
    TestSftpDirHandleLimit();
    #endif
    /* a failed close still drops the handle from the tracking list */
    TestSftpCloseFailureRemovesHandle();
    /* confinement follows the confine root, not the start path */
    TestSftpStartPathInsideConfineRoot();
    /* SETSTAT/FSETSTAT apply the attributes they acknowledge */
    TestSftpSetStatAttributes();
    #endif
    #if defined(WOLFSSL_NUCLEUS) && !defined(NO_WOLFSSH_MKTIME)
    TestNucleusMonthConversion();
    #endif
#endif

#ifdef WOLFSSH_KEYBOARD_INTERACTIVE
    TestKeyboardResponsePreparePacketFailure(ssh, ctx);
    TestKeyboardResponseNoUserAuthCallback(ssh, ctx);
    TestKeyboardResponseNullSsh();
    TestKeyboardResponseNullCtx(ssh);
    TestKbUsernameChangeDisconnects();
    TestKbSameUserResponseSucceeds();
#endif

    /* TODO: add app-level regressions that simulate stdin EOF/password
     * prompts and mid-session socket closes once the test harness can
     * drive the wolfssh client without real sockets/tty. */

    ResetSession(ssh);
    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);
#ifndef NO_WOLFSSH_SERVER
    ResetSession(serverSsh);
    wolfSSH_free(serverSsh);
    wolfSSH_CTX_free(serverCtx);
#endif
    wolfSSH_Cleanup();

    printf("regress: PASS\n");
    return 0;
}

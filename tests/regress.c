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

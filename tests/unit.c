/* unit.c
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
#include <wolfssh/ssh.h>
#include <wolfssh/keygen.h>
#include <wolfssh/error.h>
#include <wolfssh/internal.h>
#include <wolfssl/wolfcrypt/memory.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/integer.h>
#include <wolfssl/wolfcrypt/hmac.h>
#ifndef WOLFSSH_NO_RSA
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/asn.h>
#endif

#define WOLFSSH_TEST_HEX2BIN
#include <wolfssh/test.h>
#include "unit.h"

/* Regression coverage for non-CA intermediate promotion.
 * Needs WOLFSSH_TEST_INTERNAL (the test bodies are in that section), the cert
 * manager, runtime cert generation to forge the attack cert, ECDSA (the test
 * certs are ECC), and a filesystem to load the test certs. */
#if defined(WOLFSSH_TEST_INTERNAL) && defined(WOLFSSH_CERTS) && \
    defined(WOLFSSL_CERT_GEN) && !defined(WOLFSSH_NO_ECDSA) && \
    !defined(NO_FILESYSTEM)
    #define WOLFSSH_TEST_CERTMAN_PROMOTE
    /* The certman helpers use malloc/free and LONG_MAX; pull these in here so
     * the tests build even when the SCP block below is not compiled. */
    #include <limits.h>
    #include <stdlib.h>
    #include <wolfssl/wolfcrypt/asn_public.h>
    #include <wolfssl/wolfcrypt/ecc.h>
    #include <wolfssh/certman.h>
#endif

#ifdef WOLFSSH_SFTP
#include <wolfssh/wolfsftp.h>
#endif

#if defined(WOLFSSH_SCP) && !defined(WOLFSSH_SCP_USER_CALLBACKS) && \
    !defined(NO_FILESYSTEM) && !defined(WOLFSSL_NUCLEUS) && \
    !defined(_WIN32) && !defined(WOLFSSH_ZEPHYR)
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif


#ifdef WOLFSSH_TEST_INTERNAL

typedef struct {
    const char* name;
    const char* proto;
    int ioError;
    int expected;
    int side;       /* WOLFSSH_ENDPOINT_CLIENT or WOLFSSH_ENDPOINT_SERVER */
} ProtoIdTestVector;

typedef struct {
    const ProtoIdTestVector* tv;
    word32 offset;
} ProtoIdTestState;

static const ProtoIdTestVector protoIdTestVectors[] = {
    /* Pre-version banner lines (RFC 4253 Section 4.2). DoProtoId on the
     * client skips informational lines before the version string. */
    { "banner lines LF before version",
      "this is a test\n"
      "more test line\n"
      "SSH-2.0-wolfSSHv" LIBWOLFSSH_VERSION_STRING "\n",
      0, WS_SUCCESS, WOLFSSH_ENDPOINT_CLIENT },
    { "banner lines CRLF before version",
      "this is a test\r\n"
      "more test line\r\n"
      "SSH-2.0-wolfSSHv" LIBWOLFSSH_VERSION_STRING "\r\n",
      0, WS_SUCCESS, WOLFSSH_ENDPOINT_CLIENT },

    /* Valid version strings with no banner. */
    { "version with comment CRLF",
      "SSH-2.0-wolfSSHv" LIBWOLFSSH_VERSION_STRING " some comment\r\n",
      0, WS_SUCCESS, WOLFSSH_ENDPOINT_CLIENT },
    { "version CRLF no comment",
      "SSH-2.0-wolfSSHv" LIBWOLFSSH_VERSION_STRING "\r\n",
      0, WS_SUCCESS, WOLFSSH_ENDPOINT_CLIENT },
    { "version LF only",
      "SSH-2.0-wolfSSHv" LIBWOLFSSH_VERSION_STRING "\n",
      0, WS_SUCCESS, WOLFSSH_ENDPOINT_CLIENT },

    /* Case rejection. DoProtoId uses WSTRNCMP. */
    { "lowercase ssh prefix",
      "ssh-2.0-wolfSSHv" LIBWOLFSSH_VERSION_STRING "\r\n",
      0, WS_SOCKET_ERROR_E, WOLFSSH_ENDPOINT_CLIENT },
    { "mixed case SSH prefix",
      "Ssh-2.0-wolfSSHv" LIBWOLFSSH_VERSION_STRING "\r\n",
      0, WS_SOCKET_ERROR_E, WOLFSSH_ENDPOINT_CLIENT },

    /* Case rejection. DoProtoId uses WSTRNCMP. */
    { "lowercase ssh prefix",
      "ssh-2.0-wolfSSHv" LIBWOLFSSH_VERSION_STRING "\r\n",
      0, WS_VERSION_E, WOLFSSH_ENDPOINT_SERVER },
    { "mixed case SSH prefix",
      "Ssh-2.0-wolfSSHv" LIBWOLFSSH_VERSION_STRING "\r\n",
      0, WS_VERSION_E, WOLFSSH_ENDPOINT_SERVER },

    /* OpenSSH peer identification. */
    { "OpenSSH version string",
      "SSH-2.0-OpenSSH_8.9\r\n",
      0, WS_SUCCESS, WOLFSSH_ENDPOINT_CLIENT },

    /* Wrong SSH versions. */
    { "SSH-1.99 version",
      "SSH-1.99-server\r\n",
      0, WS_VERSION_E, WOLFSSH_ENDPOINT_CLIENT },
    { "SSH-1.0 version",
      "SSH-1.0-old\r\n",
      0, WS_VERSION_E, WOLFSSH_ENDPOINT_CLIENT },
    { "SSH-3.0 future version",
      "SSH-3.0-future\r\n",
      0, WS_VERSION_E, WOLFSSH_ENDPOINT_CLIENT },

    /* Malformed or missing version strings. Cases where the peer sends
     * incomplete data and then closes the connection map to
     * WS_SOCKET_ERROR_E because GetInputLine treats a 0-byte recv as EOF. */
    { "no newline terminator",
      "SSH-2.0-wolfSSHv" LIBWOLFSSH_VERSION_STRING,
      0, WS_SOCKET_ERROR_E, WOLFSSH_ENDPOINT_CLIENT },
    { "empty line only",
      "\r\n",
      0, WS_SOCKET_ERROR_E, WOLFSSH_ENDPOINT_CLIENT },
    { "bare newline",
      "\n",
      0, WS_SOCKET_ERROR_E, WOLFSSH_ENDPOINT_CLIENT },
    { "not SSH at all",
      "HTTP/1.1 200 OK\r\n",
      0, WS_SOCKET_ERROR_E, WOLFSSH_ENDPOINT_CLIENT },
    { "SSH- prefix but truncated",
      "SSH-\r\n",
      0, WS_VERSION_E, WOLFSSH_ENDPOINT_CLIENT },

    /* Line longer than the 255-byte per-line cap (RFC 4253 4.2). */
    { "overlong line before version",
      "01234567890123456789012345678901234567890123456789"
      "01234567890123456789012345678901234567890123456789"
      "01234567890123456789012345678901234567890123456789"
      "01234567890123456789012345678901234567890123456789"
      "01234567890123456789012345678901234567890123456789"
      "01234567890123456789012345678901234567890123456789"
      "SSH-2.0-wolfSSHv" LIBWOLFSSH_VERSION_STRING "\r\n",
      0, WS_VERSION_E, WOLFSSH_ENDPOINT_CLIENT },

    /* Banner line of exactly 255 bytes including CRLF (253 chars + CRLF).
     * The cap is inclusive so this line should be accepted. */
    { "banner exactly 255 bytes",
      "01234567890123456789012345678901234567890123456789"
      "01234567890123456789012345678901234567890123456789"
      "01234567890123456789012345678901234567890123456789"
      "01234567890123456789012345678901234567890123456789"
      "01234567890123456789012345678901234567890123456789"
      "012\r\n"
      "SSH-2.0-wolfSSHv" LIBWOLFSSH_VERSION_STRING "\r\n",
      0, WS_SUCCESS, WOLFSSH_ENDPOINT_CLIENT },

    /* Banner consumed, then peer closes mid-version-line. Exercises a
     * second GetInputLine call returning WS_SOCKET_ERROR_E after a prior
     * call succeeded. */
    { "banner then truncated SSH line",
      "banner line\nSSH-2.0-",
      0, WS_SOCKET_ERROR_E, WOLFSSH_ENDPOINT_CLIENT },

    /* More than WOLFSSH_MAX_BANNER_LINES (default 10) banner lines before
     * the version string. The 11th banner line trips the cap. */
    { "too many banner lines",
      "b1\nb2\nb3\nb4\nb5\nb6\nb7\nb8\nb9\nb10\nb11\n"
      "SSH-2.0-wolfSSHv" LIBWOLFSSH_VERSION_STRING "\r\n",
      0, WS_VERSION_E, WOLFSSH_ENDPOINT_CLIENT },

    /* IO error cases. The IO callback returns WS_CBIO_ERR_* values.
     * ReceiveData maps WS_CBIO_ERR_GENERAL to -1, and GetInputLine
     * returns WS_SOCKET_ERROR_E for that. WS_CBIO_ERR_WANT_READ is
     * mapped to WS_WANT_READ by ReceiveData and GetInputLine. */
    { "IO recv general error",
      "", WS_CBIO_ERR_GENERAL, WS_SOCKET_ERROR_E, WOLFSSH_ENDPOINT_CLIENT },
    { "IO recv want read",
      "", WS_CBIO_ERR_WANT_READ, WS_WANT_READ, WOLFSSH_ENDPOINT_CLIENT },

    /* Server-side: a wolfSSH server reading the client's identification
     * string MUST reject any non-"SSH-" line. The client is required to
     * send the version string first per RFC 4253 4.2. */
    { "server accepts SSH- line",
      "SSH-2.0-OpenSSH_8.9\r\n",
      0, WS_SUCCESS, WOLFSSH_ENDPOINT_SERVER },
    { "server rejects banner before SSH-",
      "client banner\r\n"
      "SSH-2.0-OpenSSH_8.9\r\n",
      0, WS_VERSION_E, WOLFSSH_ENDPOINT_SERVER },
    { "server rejects non-SSH protocol",
      "GET / HTTP/1.1\r\n",
      0, WS_VERSION_E, WOLFSSH_ENDPOINT_SERVER },
};

static int RecvFromPtr(WOLFSSH* ssh, void* data, word32 sz, void* ctx)
{
    ProtoIdTestState* state;
    const ProtoIdTestVector* tv;
    word32 protoSz;
    word32 remaining;

    WOLFSSH_UNUSED(ssh);

    state = (ProtoIdTestState*)ctx;
    tv = state->tv;

    if (tv->ioError)
        return tv->ioError;

    protoSz = (word32)WSTRLEN(tv->proto);
    if (state->offset >= protoSz) {
        /* Simulate the peer closing the connection after sending all the
         * data in the test vector. */
        return 0;
    }
    remaining = protoSz - state->offset;
    if (remaining < sz)
        sz = remaining;
    WMEMCPY(data, tv->proto + state->offset, sz);
    state->offset += sz;

    return sz;
}

/* Scripted IO mock for testing non-blocking control flow. A script is a
 * sequence of steps. Each step either delivers a chunk of bytes or signals
 * a single WS_CBIO_ERR_WANT_READ to the caller. After the script is
 * exhausted the mock returns 0 (clean EOF). Long byte chunks are delivered
 * across multiple IO callback invocations as needed. */
typedef struct {
    const char* bytes;       /* NULL means "return WS_CBIO_ERR_WANT_READ" */
    word32 sz;               /* 0 means strlen(bytes) */
} ProtoIdScriptStep;

typedef struct {
    const ProtoIdScriptStep* steps;
    word32 stepCount;
    word32 stepIdx;
    word32 stepOffset;
} ProtoIdScriptState;

typedef struct {
    const char* name;
    const ProtoIdScriptStep* steps;
    word32 stepCount;
    int side;
    int expected;
} ProtoIdScriptVector;

static int RecvFromScript(WOLFSSH* ssh, void* data, word32 sz, void* ctx)
{
    ProtoIdScriptState* s;
    const ProtoIdScriptStep* step;
    word32 stepSz;
    word32 remaining;

    WOLFSSH_UNUSED(ssh);

    s = (ProtoIdScriptState*)ctx;

    while (s->stepIdx < s->stepCount) {
        step = &s->steps[s->stepIdx];

        if (step->bytes == NULL) {
            /* WANT_READ marker; consume the step exactly once. */
            s->stepIdx++;
            s->stepOffset = 0;
            return WS_CBIO_ERR_WANT_READ;
        }

        stepSz = step->sz ? step->sz : (word32)WSTRLEN(step->bytes);
        if (s->stepOffset >= stepSz) {
            s->stepIdx++;
            s->stepOffset = 0;
            continue;
        }
        remaining = stepSz - s->stepOffset;
        if (remaining < sz)
            sz = remaining;
        WMEMCPY(data, step->bytes + s->stepOffset, sz);
        s->stepOffset += sz;
        if (s->stepOffset == stepSz) {
            s->stepIdx++;
            s->stepOffset = 0;
        }
        return (int)sz;
    }

    /* Script exhausted: simulate peer closing the connection. */
    return 0;
}

/* WANT_READ delivered partway through a banner line. Driver retries and
 * the partial line is completed cleanly. */
static const ProtoIdScriptStep wantReadMidBannerSteps[] = {
    { "this is a part", 0 },
    { NULL, 0 },
    { "ial banner\n"
      "SSH-2.0-wolfSSHv" LIBWOLFSSH_VERSION_STRING "\r\n", 0 },
};

/* WANT_READ delivered partway through the SSH version line itself. */
static const ProtoIdScriptStep wantReadMidVersionSteps[] = {
    { "SSH-2.0-wolf", 0 },
    { NULL, 0 },
    { "SSHv" LIBWOLFSSH_VERSION_STRING "\r\n", 0 },
};

/* Eleven banner lines, each followed by WS_WANT_READ. WOLFSSH_MAX_BANNER_LINES
 * defaults to 10, so the eleventh line must trip the cap. This is a
 * regression guard: an earlier version kept the banner counter as a
 * DoProtoId stack local, which got reset on every WS_WANT_READ retry and
 * effectively bypassed the cap. */
static const ProtoIdScriptStep manyBannersWantReadSteps[] = {
    { "b1\n",  0 }, { NULL, 0 },
    { "b2\n",  0 }, { NULL, 0 },
    { "b3\n",  0 }, { NULL, 0 },
    { "b4\n",  0 }, { NULL, 0 },
    { "b5\n",  0 }, { NULL, 0 },
    { "b6\n",  0 }, { NULL, 0 },
    { "b7\n",  0 }, { NULL, 0 },
    { "b8\n",  0 }, { NULL, 0 },
    { "b9\n",  0 }, { NULL, 0 },
    { "b10\n", 0 }, { NULL, 0 },
    { "b11\n", 0 },
};

#define SCRIPT_LEN(s) (word32)(sizeof(s)/sizeof((s)[0]))

static const ProtoIdScriptVector protoIdScriptVectors[] = {
    { "WANT_READ mid-banner resumes",
      wantReadMidBannerSteps, SCRIPT_LEN(wantReadMidBannerSteps),
      WOLFSSH_ENDPOINT_CLIENT, WS_SUCCESS },
    { "WANT_READ mid-SSH-version resumes",
      wantReadMidVersionSteps, SCRIPT_LEN(wantReadMidVersionSteps),
      WOLFSSH_ENDPOINT_CLIENT, WS_SUCCESS },
    { "banners across WANT_READ still trip cap",
      manyBannersWantReadSteps, SCRIPT_LEN(manyBannersWantReadSteps),
      WOLFSSH_ENDPOINT_CLIENT, WS_VERSION_E },
};

/* DoProtoId() Unit Test */
static int test_DoProtoId(void)
{
    WOLFSSH_CTX* clientCtx;
    WOLFSSH_CTX* serverCtx;
    WOLFSSH_CTX* ctx;
    WOLFSSH* ssh;
    const ProtoIdTestVector* tv;
    int tc = (int)(sizeof(protoIdTestVectors)/sizeof(protoIdTestVectors[0]));
    int i;
    int ret;
    int failures = 0;

    clientCtx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_CLIENT, NULL);
    if (clientCtx == NULL)
        return -100;
    serverCtx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_SERVER, NULL);
    if (serverCtx == NULL) {
        wolfSSH_CTX_free(clientCtx);
        return -101;
    }
    wolfSSH_SetIORecv(clientCtx, RecvFromPtr);
    wolfSSH_SetIORecv(serverCtx, RecvFromPtr);

    for (i = 0, tv = protoIdTestVectors; i < tc; i++, tv++) {
        ProtoIdTestState state;

        state.tv = tv;
        state.offset = 0;

        ctx = (tv->side == WOLFSSH_ENDPOINT_SERVER) ? serverCtx : clientCtx;
        ssh = wolfSSH_new(ctx);
        if (ssh == NULL) {
            fprintf(stderr, "\t[%d] \"%s\" FAIL: wolfSSH_new returned NULL\n",
                    i, tv->name);
            failures++;
            continue;
        }
        wolfSSH_SetIOReadCtx(ssh, &state);
        ret = wolfSSH_TestDoProtoId(ssh);
        if (ret != tv->expected) {
            fprintf(stderr, "\t[%d] \"%s\" FAIL: got %d, expected %d\n",
                    i, tv->name, ret, tv->expected);
            failures++;
        }
        wolfSSH_free(ssh);
    }

    /* Scripted-IO vectors: exercise non-blocking flow where ReceiveData
     * returns WS_WANT_READ partway through a line. The driver re-enters
     * DoProtoId until it returns something other than WS_WANT_READ. */
    wolfSSH_SetIORecv(clientCtx, RecvFromScript);
    wolfSSH_SetIORecv(serverCtx, RecvFromScript);

    {
        const ProtoIdScriptVector* sv;
        int sc = (int)(sizeof(protoIdScriptVectors)
                       / sizeof(protoIdScriptVectors[0]));

        for (i = 0, sv = protoIdScriptVectors; i < sc; i++, sv++) {
            ProtoIdScriptState scriptState;

            scriptState.steps = sv->steps;
            scriptState.stepCount = sv->stepCount;
            scriptState.stepIdx = 0;
            scriptState.stepOffset = 0;

            ctx = (sv->side == WOLFSSH_ENDPOINT_SERVER)
                  ? serverCtx : clientCtx;
            ssh = wolfSSH_new(ctx);
            if (ssh == NULL) {
                fprintf(stderr,
                        "\t[script %d] \"%s\" FAIL: wolfSSH_new returned NULL\n",
                        i, sv->name);
                failures++;
                continue;
            }
            wolfSSH_SetIOReadCtx(ssh, &scriptState);

            do {
                ret = wolfSSH_TestDoProtoId(ssh);
            } while (ret == WS_WANT_READ);

            if (ret != sv->expected) {
                fprintf(stderr,
                        "\t[script %d] \"%s\" FAIL: got %d, expected %d\n",
                        i, sv->name, ret, sv->expected);
                failures++;
            }
            wolfSSH_free(ssh);
        }
    }

    wolfSSH_CTX_free(serverCtx);
    wolfSSH_CTX_free(clientCtx);

    return failures;
}


/* GetMpint() Unit Test */

typedef struct {
    const char* name;
    const byte* input;
    word32 inputSz;
    int expected;       /* expected return value */
    word32 expectedSz;  /* expected mpint size on success */
} GetMpintTestVector;

static const byte mpintPositive[] = { 0, 0, 0, 4, 0x12, 0x34, 0x56, 0x78 };
static const byte mpintLeadZero[] = { 0, 0, 0, 3, 0x00, 0x80, 0x01 };
static const byte mpintZeroLen[] = { 0, 0, 0, 0 };
static const byte mpintNegative[] = { 0, 0, 0, 2, 0x80, 0x01 };
static const byte mpintNegOne[] = { 0, 0, 0, 1, 0xFF };
static const byte mpintShort[] = { 0, 0, 0, 5, 0x01, 0x02 };

static const GetMpintTestVector getMpintTestVectors[] = {
    { "positive", mpintPositive, sizeof(mpintPositive), WS_SUCCESS, 4 },
    { "canonical leading zero", mpintLeadZero, sizeof(mpintLeadZero),
        WS_SUCCESS, 3 },
    { "zero length", mpintZeroLen, sizeof(mpintZeroLen), WS_SUCCESS, 0 },
    { "negative", mpintNegative, sizeof(mpintNegative), WS_PARSE_E, 0 },
    { "negative one", mpintNegOne, sizeof(mpintNegOne), WS_PARSE_E, 0 },
    { "length past end of buffer", mpintShort, sizeof(mpintShort),
        WS_BUFFER_E, 0 },
};

static int test_GetMpint(void)
{
    const GetMpintTestVector* tv;
    int tc = (int)(sizeof(getMpintTestVectors)/sizeof(getMpintTestVectors[0]));
    int i;
    int ret;
    int failures = 0;

    for (i = 0, tv = getMpintTestVectors; i < tc; i++, tv++) {
        const byte* mpint = NULL;
        word32 mpintSz = 0;
        word32 idx = 0;

        ret = GetMpint(&mpintSz, &mpint, tv->input, tv->inputSz, &idx);
        if (ret != tv->expected) {
            fprintf(stderr, "\t[%d] \"%s\" FAIL: got %d, expected %d\n",
                    i, tv->name, ret, tv->expected);
            failures++;
            continue;
        }
        if (ret == WS_SUCCESS) {
            const byte* expectedPtr =
                (tv->expectedSz > 0) ? tv->input + LENGTH_SZ : NULL;

            if (mpintSz != tv->expectedSz) {
                fprintf(stderr,
                        "\t[%d] \"%s\" FAIL: size %u, expected %u\n",
                        i, tv->name, mpintSz, tv->expectedSz);
                failures++;
            }
            else if (mpint != expectedPtr || idx != LENGTH_SZ + mpintSz) {
                fprintf(stderr,
                        "\t[%d] \"%s\" FAIL: bad pointer or index\n",
                        i, tv->name);
                failures++;
            }
        }
    }

    return failures;
}

#endif /* WOLFSSH_TEST_INTERNAL */


/* Key Derivation Function (KDF) Unit Test */

typedef struct {
    byte hashId;
    byte keyId;
    const char* k;
    const char* h;
    const char* sessionId;
    const char* expectedKey;
} KdfTestVector;


#ifndef NO_SHA
/** Test Vector Set #1: SHA-1 **/
const char kdfTvSet1k[] =
    "35618FD3AABF980A5F766408961600D4933C60DD7B22D69EEB4D7A987C938F6F"
    "7BB2E60E0F638BB4289297B588E6109057325F010D021DF60EBF8BE67AD9C3E2"
    "6376A326A16210C7AF07B3FE562B8DD1DCBECB17AA7BFAF38708B0136120B2FC"
    "723E93EF4237AC3737BAE3A16EC03F605C7EEABFD526B38C826B506BBAECD2F7"
    "9932F1371AEABFBEB4F8222313506677330C714A2A6FDC70CB859B581AA18625"
    "ECCB6BA9DDEEAECF0E41D9E5076B899B477112E59DDADC4B4D9C13E9F07E1107"
    "B560FEFDC146B8ED3E73441D05345031C35F9E6911B00319481D80015855BE4D"
    "1C7D7ACC8579B1CC2E5F714109C0882C3B57529ABDA1F2255D2B27C4A83AE11E";
const char kdfTvSet1h[]         = "40555741F6DE70CDC4E740104A97E75473F49064";
const char kdfTvSet1sid[]       = "40555741F6DE70CDC4E740104A97E75473F49064";
const char kdfTvSet1a[]         = "B2EC4CF6943632C39972EE2801DC7393";
const char kdfTvSet1b[]         = "BC92238B6FA69ECC10B2B013C2FC9785";
const char kdfTvSet1c[]         = "9EF0E2053F66C56F3E4503DA1C2FBD6B";
const char kdfTvSet1d[]         = "47C8395B08277020A0645DA3959FA1A9";
const char kdfTvSet1e[]         = "EE436BFDABF9B0313224EC800E7390445E2F575E";
const char kdfTvSet1f[]         = "FB9FDEEC78B0FB258F1A4F47F6BCE166680994BB";

/** Test Vector Set #2: SHA-1 **/
const char kdfTvSet2k[] =
    "19FA2B7C7F4FE7DE61CDE17468C792CCEAB0E3F2CE37CDE2DAA0974BCDFFEDD4"
    "A29415CDB330FA6A97ECA742359DC1223B581D8AC61B43CFFDF66D20952840B0"
    "2593B48354E352E2A396BDF7F1C9D414FD31C2BF47E6EED306069C4F4F5F66C3"
    "003A90E85412A1FBE89CDFB457CDA0D832E8DA701627366ADEC95B70E8A8B7BF"
    "3F85775CCF36E40631B83B32CF643088F01A82C97C5C3A820EB4149F551CAF8C"
    "C98EE6B3065E6152FF877823F7C618C1CD93CE26DB9FAAFED222F1C93E8F4068"
    "BFDA4480432E14F98FFC821F05647693040B07D71DC273121D53866294434D46"
    "0E95CFA4AB4414705BF1F8224655F907A418A6A893F2A71019225869CB7FE988";
const char kdfTvSet2h[]         = "DFB748905CC8647684C3E0B7F26A3E8E7414AC51";
const char kdfTvSet2sid[]       = "DFB748905CC8647684C3E0B7F26A3E8E7414AC51";
const char kdfTvSet2a[]         = "52EDBFD5E414A3CC6C7F7A0F4EA60503";
const char kdfTvSet2b[]         = "926C6987696C5FFCC6511BFE34557878";
const char kdfTvSet2c[]         = "CB6D56EC5B9AFECD326D544DA2D22DED";
const char kdfTvSet2d[]         = "F712F6451F1BD6CE9BAA597AC87C5A24";
const char kdfTvSet2e[]         = "E42FC62C76B76B37818F78292D3C2226D0264760";
const char kdfTvSet2f[]         = "D14BE4DD0093A3E759580233C80BB8399CE4C4E7";
#endif

/** Test Vector Set #3: SHA-256 **/
const char kdfTvSet3k[] =
    "6AC382EAACA093E125E25C24BEBC84640C11987507344B5C739CEB84A9E0B222"
    "B9A8B51C839E5EBE49CFADBFB39599764ED522099DC912751950DC7DC97FBDC0"
    "6328B68F22781FD315AF568009A5509E5B87A11BF527C056DAFFD82AB6CBC25C"
    "CA37143459E7BC63BCDE52757ADEB7DF01CF12173F1FEF8102EC5AB142C213DD"
    "9D30696278A8D8BC32DDE9592D28C078C6D92B947D825ACAAB6494846A49DE24"
    "B9623F4889E8ADC38E8C669EFFEF176040AD945E90A7D3EEC15EFEEE78AE7104"
    "3C96511103A16BA7CAF0ACD0642EFDBE809934FAA1A5F1BD11043649B25CCD1F"
    "EE2E38815D4D5F5FC6B4102969F21C22AE1B0E7D3603A556A13262FF628DE222";
const char kdfTvSet3h[] =
    "7B7001185E256D4493445F39A55FB905E6321F4B5DD8BBF3100D51BA0BDA3D2D";
const char kdfTvSet3sid[] =
    "7B7001185E256D4493445F39A55FB905E6321F4B5DD8BBF3100D51BA0BDA3D2D";
const char kdfTvSet3a[]         = "81F0330EF6F05361B3823BFDED6E1DE9";
const char kdfTvSet3b[]         = "3F6FD2065EEB2B0B1D93195A1FED48A5";
const char kdfTvSet3c[]         = "C35471034E6FD6547613178E23435F21";
const char kdfTvSet3d[]         = "7E9D79032090D99F98B015634DD9F462";
const char kdfTvSet3e[] =
    "24EE559AD7CE712B685D0B2271E443C17AB1D1DCEB5A360569D25D5DC243002F";
const char kdfTvSet3f[] =
    "C3419C2B966235869D714BA5AC48DDB7D9E35C8C19AAC73422337A373453607E";

/** Test Vector Set #4: SHA-256 **/
const char kdfTvSet4k[] =
    "44708C76616F700BD31B0C155EF74E36390EEB39BC5C32CDC90E21922B0ED930"
    "B5B519C8AFEBEF0F4E4FB5B41B81D649D2127506620B594E9899F7F0D442ECDD"
    "D68308307B82F00065E9D75220A5A6F5641795772132215A236064EA965C6493"
    "C21F89879730EBBC3C20A22D8F5BFD07B525B194323B22D8A49944D1AA58502E"
    "756101EF1E8A91C9310E71F6DB65A3AD0A542CFA751F83721A99E89F1DBE5497"
    "1A3620ECFFC967AA55EED1A42D6E7A138B853557AC84689889F6D0C8553575FB"
    "89B4E13EAB5537DA72EF16F0D72F5E8505D97F110745193D550FA315FE88F672"
    "DB90D73843E97BA1F3D087BA8EB39025BBFFAD37589A6199227303D9D8E7F1E3";
const char kdfTvSet4h[] =
    "FE3727FD99A5AC7987C2CFBE062129E3027BF5E10310C6BCCDE9C916C8329DC2";
const char kdfTvSet4sid[] =
    "FFFA598BC0AD2AE84DC8DC05B1F72C5B0134025AE7EDF8A2E8DB11472E18E1FC";
const char kdfTvSet4a[]         = "36730BAE8DE5CB98898D6B4A00B37058";
const char kdfTvSet4b[]         = "5DFE446A83F40E8358D28CB97DF8F340";
const char kdfTvSet4c[]         = "495B7AFED0872B761437728E9E94E2B8";
const char kdfTvSet4d[]         = "C1474B3925BEC36F0B7F6CC698E949C8";
const char kdfTvSet4e[] =
    "B730F8DF6A0697645BE261169486C32A11612229276CBAC5D8B3669AFB2E4262";
const char kdfTvSet4f[] =
    "14A5EA98245FB058978B82A3CB092B1CCA7CE0109A4F98C16E1529579D58B819";

#define HASH_SHA WC_HASH_TYPE_SHA
#define HASH_SHA256 WC_HASH_TYPE_SHA256

static const KdfTestVector kdfTestVectors[] = {
#ifndef NO_SHA
    {HASH_SHA, 'A', kdfTvSet1k, kdfTvSet1h, kdfTvSet1sid, kdfTvSet1a},
    {HASH_SHA, 'B', kdfTvSet1k, kdfTvSet1h, kdfTvSet1sid, kdfTvSet1b},
    {HASH_SHA, 'C', kdfTvSet1k, kdfTvSet1h, kdfTvSet1sid, kdfTvSet1c},
    {HASH_SHA, 'D', kdfTvSet1k, kdfTvSet1h, kdfTvSet1sid, kdfTvSet1d},
    {HASH_SHA, 'E', kdfTvSet1k, kdfTvSet1h, kdfTvSet1sid, kdfTvSet1e},
    {HASH_SHA, 'F', kdfTvSet1k, kdfTvSet1h, kdfTvSet1sid, kdfTvSet1f},
    {HASH_SHA, 'A', kdfTvSet2k, kdfTvSet2h, kdfTvSet2sid, kdfTvSet2a},
    {HASH_SHA, 'B', kdfTvSet2k, kdfTvSet2h, kdfTvSet2sid, kdfTvSet2b},
    {HASH_SHA, 'C', kdfTvSet2k, kdfTvSet2h, kdfTvSet2sid, kdfTvSet2c},
    {HASH_SHA, 'D', kdfTvSet2k, kdfTvSet2h, kdfTvSet2sid, kdfTvSet2d},
    {HASH_SHA, 'E', kdfTvSet2k, kdfTvSet2h, kdfTvSet2sid, kdfTvSet2e},
    {HASH_SHA, 'F', kdfTvSet2k, kdfTvSet2h, kdfTvSet2sid, kdfTvSet2f},
#endif
    {HASH_SHA256, 'A', kdfTvSet3k, kdfTvSet3h, kdfTvSet3sid, kdfTvSet3a},
    {HASH_SHA256, 'B', kdfTvSet3k, kdfTvSet3h, kdfTvSet3sid, kdfTvSet3b},
    {HASH_SHA256, 'C', kdfTvSet3k, kdfTvSet3h, kdfTvSet3sid, kdfTvSet3c},
    {HASH_SHA256, 'D', kdfTvSet3k, kdfTvSet3h, kdfTvSet3sid, kdfTvSet3d},
    {HASH_SHA256, 'E', kdfTvSet3k, kdfTvSet3h, kdfTvSet3sid, kdfTvSet3e},
    {HASH_SHA256, 'F', kdfTvSet3k, kdfTvSet3h, kdfTvSet3sid, kdfTvSet3f},
    {HASH_SHA256, 'A', kdfTvSet4k, kdfTvSet4h, kdfTvSet4sid, kdfTvSet4a},
    {HASH_SHA256, 'B', kdfTvSet4k, kdfTvSet4h, kdfTvSet4sid, kdfTvSet4b},
    {HASH_SHA256, 'C', kdfTvSet4k, kdfTvSet4h, kdfTvSet4sid, kdfTvSet4c},
    {HASH_SHA256, 'D', kdfTvSet4k, kdfTvSet4h, kdfTvSet4sid, kdfTvSet4d},
    {HASH_SHA256, 'E', kdfTvSet4k, kdfTvSet4h, kdfTvSet4sid, kdfTvSet4e},
    {HASH_SHA256, 'F', kdfTvSet4k, kdfTvSet4h, kdfTvSet4sid, kdfTvSet4f}
};


static int test_KDF(void)
{
    int result = 0;
    word32 i;
    word32 tc = sizeof(kdfTestVectors)/sizeof(KdfTestVector);
    const KdfTestVector* tv = NULL;
    byte* k = NULL;
    byte* h = NULL;
    byte* sId = NULL;
    byte* eKey = NULL;
    word32 kSz = 0, hSz = 0, sIdSz = 0, eKeySz = 0;
    byte cKey[32]; /* Greater of SHA256_DIGEST_SIZE and AES_BLOCK_SIZE */
    /* sId - Session ID, eKey - Expected Key, cKey - Calculated Key */

    for (i = 0, tv = kdfTestVectors; i < tc; i++, tv++) {

        result = ConvertHexToBin(tv->k, &k, &kSz,
                                 tv->h, &h, &hSz,
                                 tv->sessionId, &sId, &sIdSz,
                                 tv->expectedKey, &eKey, &eKeySz);
        if (result != 0 || eKey == NULL) {
            printf("KDF: Could not convert test vector %u.\n", i);
            result = -100;
        }

        if (result == 0) {
            result = wolfSSH_KDF(tv->hashId, tv->keyId, cKey, eKeySz,
                    k, kSz, h, hSz, sId, sIdSz);

            if (result != 0) {
                printf("KDF: Could not derive key.\n");
                result = -101;
            }
        }

        if (result == 0) {
            if (memcmp(cKey, eKey, eKeySz) != 0) {
                printf("KDF: Calculated Key does not match Expected Key.\n");
                result = -102;
            }
        }

        FreeBins(k, h, sId, eKey);
        k = NULL;
        h = NULL;
        sId = NULL;
        eKey = NULL;

        if (result != 0) break;
    }

    return result;
}


/* Key Generation Unit Test */

#ifdef WOLFSSH_KEYGEN

#ifndef WOLFSSH_NO_RSA
static int test_RsaKeyGen(void)
{
    int result = 0;
    byte der[1200];
    int derSz;

    derSz = wolfSSH_MakeRsaKey(der, sizeof(der),
                               WOLFSSH_RSAKEY_DEFAULT_SZ,
                               WOLFSSH_RSAKEY_DEFAULT_E);
    if (derSz < 0) {
        printf("RsaKeyGen: MakeRsaKey failed\n");
        result = -103;
    }

    return result;
}
#endif

#ifndef WOLFSSH_NO_ECDSA
static int test_EcdsaKeyGen(void)
{
    int result = 0;
    byte der[1200];
    int derSz;

    derSz = wolfSSH_MakeEcdsaKey(der, sizeof(der),
                               WOLFSSH_ECDSAKEY_PRIME256);
    if (derSz < 0) {
        printf("EcdsaKeyGen: MakeEcdsaKey failed\n");
        result = -104;
    }

    return result;
}
#endif

#if !defined(WOLFSSH_NO_ED25519) && defined(HAVE_ED25519) && \
    defined(HAVE_ED25519_MAKE_KEY) && defined(HAVE_ED25519_KEY_EXPORT)
static int test_Ed25519KeyGen(void)
{
    int result = 0;
    byte der[1200];
    int derSz;

    derSz = wolfSSH_MakeEd25519Key(der, sizeof(der), WOLFSSH_ED25519KEY);
    if (derSz < 0) {
        printf("Ed25519KeyGen: MakeEd25519Key failed\n");
        result = -105;
    }

    return result;
}
#endif

#ifndef WOLFSSH_NO_MLDSA
static int test_MlDsaKeyGen(void)
{
    static const struct {
        word32 level;
        word32 derSz;
        const char* name;
    } params[] = {
    #ifndef WOLFSSH_NO_MLDSA44
        { WOLFSSH_MLDSAKEY_44, WC_MLDSA_44_BOTH_KEY_DER_SIZE, "44" },
    #endif
    #ifndef WOLFSSH_NO_MLDSA65
        { WOLFSSH_MLDSAKEY_65, WC_MLDSA_65_BOTH_KEY_DER_SIZE, "65" },
    #endif
    #ifndef WOLFSSH_NO_MLDSA87
        { WOLFSSH_MLDSAKEY_87, WC_MLDSA_87_BOTH_KEY_DER_SIZE, "87" },
    #endif
    };
    word32 i;
    int result = 0;

    for (i = 0; i < (word32)(sizeof(params) / sizeof(params[0])); i++) {
        byte* der;
        int sz;

        der = (byte*)WMALLOC(params[i].derSz, NULL, DYNTYPE_BUFFER);
        if (der == NULL) {
            printf("MlDsaKeyGen: alloc failed for level %s\n", params[i].name);
            result = -106;
            break;
        }

        sz = wolfSSH_MakeMlDsaKey(der, params[i].derSz, params[i].level);
        if (sz < 0) {
            printf("MlDsaKeyGen: MakeMlDsaKey level %s failed (%d)\n",
                   params[i].name, sz);
            WFREE(der, NULL, DYNTYPE_BUFFER);
            result = -106;
            break;
        }

        sz = wolfSSH_MakeMlDsaKey(der, params[i].derSz - 1, params[i].level);
        if (sz != WS_CRYPTO_FAILED) {
            printf("MlDsaKeyGen: undersized buffer wrong result %d, level %s\n",
                   sz, params[i].name);
            WFREE(der, NULL, DYNTYPE_BUFFER);
            result = -107;
            break;
        }

        WFREE(der, NULL, DYNTYPE_BUFFER);
    }

    if (result == 0) {
        int sz = wolfSSH_MakeMlDsaKey(NULL, 0, 9999);
        if (sz != WS_BAD_ARGUMENT) {
            printf("MlDsaKeyGen: invalid level wrong result %d\n", sz);
            result = -108;
        }
    }

    return result;
}
#endif

#endif


#if defined(WOLFSSH_TEST_INTERNAL) && \
    (!defined(WOLFSSH_NO_HMAC_SHA1) || \
     !defined(WOLFSSH_NO_HMAC_SHA1_96) || \
     !defined(WOLFSSH_NO_HMAC_SHA2_256) || \
     !defined(WOLFSSH_NO_HMAC_SHA2_512))

/* Minimal SSH binary packet: uint32 length, padding_length, msgId, padding.
 * Same layout as tests/regress.c BuildPacket (8-byte aligned body). */
static word32 BuildMacTestPacketPrefix(byte msgId, byte* out, word32 outSz)
{
    byte padLen = 6;
    word32 packetLen = (word32)(1 + 1 + padLen);
    word32 need = UINT32_SZ + packetLen;

    if (outSz < need)
        return 0;
    out[0] = (byte)(packetLen >> 24);
    out[1] = (byte)(packetLen >> 16);
    out[2] = (byte)(packetLen >> 8);
    out[3] = (byte)(packetLen);
    out[4] = padLen;
    out[5] = msgId;
    WMEMSET(out + 6, 0, padLen);
    return need;
}


static int test_DoReceive_VerifyMacFailure(void)
{
    WOLFSSH_CTX* ctx = NULL;
    WOLFSSH* ssh = NULL;
    int ret = WS_SUCCESS;
    int result = 0;
    byte flatSeq[LENGTH_SZ];
    byte macKey[MAX_HMAC_SZ];
    Hmac hmac;
    word32 prefixLen;
    word32 totalLen;
    byte pkt[UINT32_SZ + 8 + MAX_HMAC_SZ];
    int i;
    struct {
        byte macId;
        int hmacType;
        byte macSz;
        byte keySz;
    } cases[] = {
#ifndef WOLFSSH_NO_HMAC_SHA1
        { ID_HMAC_SHA1, WC_SHA, WC_SHA_DIGEST_SIZE, WC_SHA_DIGEST_SIZE },
#endif
    #ifndef WOLFSSH_NO_HMAC_SHA1_96
        { ID_HMAC_SHA1_96, WC_SHA, SHA1_96_SZ, WC_SHA_DIGEST_SIZE },
    #endif
#ifndef WOLFSSH_NO_HMAC_SHA2_256
        { ID_HMAC_SHA2_256, WC_SHA256, WC_SHA256_DIGEST_SIZE,
          WC_SHA256_DIGEST_SIZE },
#endif
#ifndef WOLFSSH_NO_HMAC_SHA2_512
        { ID_HMAC_SHA2_512, WC_SHA512, WC_SHA512_DIGEST_SIZE,
          WC_SHA512_DIGEST_SIZE },
#endif
    };

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_CLIENT, NULL);
    if (ctx == NULL)
        return -200;
    ssh = wolfSSH_new(ctx);
    if (ssh == NULL) {
        wolfSSH_CTX_free(ctx);
        return -201;
    }

    WMEMSET(macKey, 0xA5, sizeof(macKey));

    for (i = 0; i < (int)(sizeof(cases) / sizeof(cases[0])); i++) {
        prefixLen = BuildMacTestPacketPrefix(MSGID_IGNORE, pkt, sizeof(pkt));
        if (prefixLen == 0) {
            result = -202;
            goto done;
        }
        totalLen = prefixLen + cases[i].macSz;

        ssh->peerEncryptId = ID_NONE;
        ssh->peerAeadMode = 0;
        ssh->peerBlockSz = MIN_BLOCK_SZ;
        ssh->peerMacId = cases[i].macId;
        ssh->peerMacSz = cases[i].macSz;
        WMEMCPY(ssh->peerKeys.macKey, macKey, cases[i].keySz);
        ssh->peerKeys.macKeySz = cases[i].keySz;
        ssh->peerSeq = 0;
        ssh->curSz = 0;
        ssh->processReplyState = PROCESS_INIT;
        ssh->error = 0;

        flatSeq[0] = (byte)(ssh->peerSeq >> 24);
        flatSeq[1] = (byte)(ssh->peerSeq >> 16);
        flatSeq[2] = (byte)(ssh->peerSeq >> 8);
        flatSeq[3] = (byte)(ssh->peerSeq);
        ret = wc_HmacInit(&hmac, ssh->ctx->heap, INVALID_DEVID);
        if (ret != WS_SUCCESS) {
            result = -203;
            goto done;
        }
        {
            byte digest[WC_MAX_DIGEST_SIZE];
            ret = wc_HmacSetKey(&hmac, cases[i].hmacType,
                    ssh->peerKeys.macKey, ssh->peerKeys.macKeySz);
            if (ret == WS_SUCCESS)
                ret = wc_HmacUpdate(&hmac, flatSeq, sizeof(flatSeq));
            if (ret == WS_SUCCESS)
                ret = wc_HmacUpdate(&hmac, pkt, prefixLen);
            if (ret == WS_SUCCESS)
                ret = wc_HmacFinal(&hmac, digest);
            wc_HmacFree(&hmac);
            if (ret == WS_SUCCESS)
                WMEMCPY(pkt + prefixLen, digest, cases[i].macSz);
        }
        if (ret != WS_SUCCESS) {
            result = -204;
            goto done;
        }

        pkt[prefixLen] ^= 0x01;

        ShrinkBuffer(&ssh->inputBuffer, 1);
        ret = GrowBuffer(&ssh->inputBuffer, totalLen);
        if (ret != WS_SUCCESS) {
            result = -205;
            goto done;
        }
        WMEMCPY(ssh->inputBuffer.buffer, pkt, totalLen);
        ssh->inputBuffer.length = totalLen;
        ssh->inputBuffer.idx = 0;

        ret = wolfSSH_TestDoReceive(ssh);
        if (ret != WS_FATAL_ERROR) {
            result = -206;
            goto done;
        }
        if (ssh->error != WS_VERIFY_MAC_E) {
            result = -207;
            goto done;
        }
    }

done:
    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);
    return result;
}
#endif /* WOLFSSH_TEST_INTERNAL && any HMAC SHA variant enabled */


#ifdef WOLFSSH_TEST_INTERNAL
/* Verify DoReceive rejects a binary packet whose padding_length is below the
 * RFC 4253 section 6 minimum of four bytes, returning WS_BUFFER_E. The packet
 * is delivered in the clear (no cipher, no MAC), matching the pre-key-exchange
 * transport, so DoPacket's padding check is what rejects it. */
static int test_DoReceive_RejectsShortPadding(void)
{
    WOLFSSH_CTX* ctx = NULL;
    WOLFSSH* ssh = NULL;
    int ret;
    int result = 0;
    /* A well-formed MSGID_IGNORE packet carrying an empty string, but with
     * padding_length = 1 (below MIN_PAD_LENGTH). Aside from the short padding
     * the packet parses cleanly, so the padding check is the only thing that
     * can reject it. Layout: uint32 packet_length=7, padding_length=1,
     * msgId, uint32 string_len=0, 1 pad byte => 11 bytes total. */
    byte pkt[11];
    word32 totalLen = (word32)sizeof(pkt);

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_CLIENT, NULL);
    if (ctx == NULL)
        return -760;
    ssh = wolfSSH_new(ctx);
    if (ssh == NULL) {
        wolfSSH_CTX_free(ctx);
        return -761;
    }

    pkt[0] = 0; pkt[1] = 0; pkt[2] = 0; pkt[3] = 7; /* packet_length */
    pkt[4] = 1;             /* padding_length, below MIN_PAD_LENGTH (4) */
    pkt[5] = MSGID_IGNORE;
    pkt[6] = 0; pkt[7] = 0; pkt[8] = 0; pkt[9] = 0; /* string_len = 0 */
    pkt[10] = 0;            /* padding */

    ssh->peerEncryptId = ID_NONE;
    ssh->peerAeadMode = 0;
    ssh->peerBlockSz = MIN_BLOCK_SZ;
    ssh->peerMacId = ID_NONE;
    ssh->peerMacSz = 0;
    ssh->peerSeq = 0;
    ssh->curSz = 0;
    ssh->processReplyState = PROCESS_INIT;
    ssh->error = 0;

    ShrinkBuffer(&ssh->inputBuffer, 1);
    ret = GrowBuffer(&ssh->inputBuffer, totalLen);
    if (ret != WS_SUCCESS) {
        result = -762;
        goto done2;
    }
    WMEMCPY(ssh->inputBuffer.buffer, pkt, totalLen);
    ssh->inputBuffer.length = totalLen;
    ssh->inputBuffer.idx = 0;

    ret = wolfSSH_TestDoReceive(ssh);
    if (ret != WS_FATAL_ERROR) {
        result = -763;
        goto done2;
    }
    if (ssh->error != WS_BUFFER_E) {
        result = -764;
        goto done2;
    }

done2:
    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);
    return result;
}
#endif /* WOLFSSH_TEST_INTERNAL */


#if defined(WOLFSSH_TEST_INTERNAL) && !defined(WOLFSSH_NO_DH_GEX_SHA256)

typedef struct {
    const char* candidate;
    const char* generator;
    word32 minBits;
    word32 maxBits;
    int expectedResult;
} PrimeTestVector;

static const PrimeTestVector primeTestVectors[] = {
    {
        /*
         * For testing the ValidateKexDhGexGroup() function, we need to
         * verify that the function detects unsafe primes. The following
         * unsafe prime is the prime used with GOST-ECC. (RFC 7836) It is
         * prime and fine for its application. It isn't safe for DH, as
         * q = (p-1)/2 is not prime.
         */
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffdc7",
        "02",
        512, 8192, WS_CRYPTO_FAILED
    },
    {
        /*
         * We need to verify that the function detects safe primes. The
         * following safePrime is the MODP 2048-bit group from RFC 3526.
         */
        "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74"
        "020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f1437"
        "4fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7ed"
        "ee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf05"
        "98da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb"
        "9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3b"
        "e39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf695581718"
        "3995497cea956ae515d2261898fa051015728e5a8aacaa68ffffffffffffffff",
        "02",
        2048, 8192, WS_SUCCESS
    },
    {
        /*
         * This checks for g = p - 1.
         */
        "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74"
        "020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f1437"
        "4fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7ed"
        "ee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf05"
        "98da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb"
        "9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3b"
        "e39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf695581718"
        "3995497cea956ae515d2261898fa051015728e5a8aacaa68ffffffffffffffff",
        "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74"
        "020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f1437"
        "4fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7ed"
        "ee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf05"
        "98da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb"
        "9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3b"
        "e39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf695581718"
        "3995497cea956ae515d2261898fa051015728e5a8aacaa68fffffffffffffffe",
        2048, 8192, WS_CRYPTO_FAILED
    },
    {
        /*
         * This checks for g = 1.
         */
        "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74"
        "020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f1437"
        "4fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7ed"
        "ee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf05"
        "98da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb"
        "9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3b"
        "e39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf695581718"
        "3995497cea956ae515d2261898fa051015728e5a8aacaa68ffffffffffffffff",
        "01",
        2048, 8192, WS_CRYPTO_FAILED
    },
    {
        /*
         * This checks prime size less than minBits.
         */
        "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74"
        "020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f1437"
        "4fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7ed"
        "ee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf05"
        "98da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb"
        "9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3b"
        "e39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf695581718"
        "3995497cea956ae515d2261898fa051015728e5a8aacaa68ffffffffffffffff",
        "02",
        3072, 8192, WS_DH_SIZE_E
    },
    {
        /*
         * This checks prime size greater than maxBits.
         */
        "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74"
        "020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f1437"
        "4fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7ed"
        "ee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf05"
        "98da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb"
        "9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3b"
        "e39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf695581718"
        "3995497cea956ae515d2261898fa051015728e5a8aacaa68ffffffffffffffff",
        "02",
        512, 1024, WS_DH_SIZE_E
    },
    {
        /*
         * This checks for even p.
         */
        "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74"
        "020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f1437"
        "4fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7ed"
        "ee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf05"
        "98da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb"
        "9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3b"
        "e39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf695581718"
        "3995497cea956ae515d2261898fa051015728e5a8aacaa68fffffffffffffffe",
        "02",
        2048, 8192, WS_CRYPTO_FAILED
    },
    {
        /*
         * A well known composite number that breaks some MR implementations.
         * This is calculated by wolfCrypt for one of its prime tests.
         */
        "000000000088cbf655be37a612fa535b4a9b81d394854ecbedfe1a4afbecdc7b"
        "a6a263549dd3c17882b054329384962576e7c5aa281e04ab5a0e7245584ad324"
        "9c7ac4de7caf5663bae95f6bb9e8bec4124e04d82eac54a246bda49a5c5c2a1b"
        "366ef8c085fc7c5f87478a55832d1b2184154c24260df67561d17c4359724403",
        "02",
        512, 8192, WS_CRYPTO_FAILED
    },
};

static int test_DhGexGroupValidate(void)
{
    WC_RNG rng;
    const PrimeTestVector* tv;
    byte* candidate;
    byte* generator;
    word32 candidateSz;
    word32 generatorSz;
    int tc = (int)(sizeof(primeTestVectors)/sizeof(primeTestVectors[0]));
    int result = 0, ret, i;

    if (wc_InitRng(&rng) != 0) {
        printf("DhGexGroupValidate: wc_InitRng failed\n");
        return -110;
    }

    for (i = 0, tv = primeTestVectors; i < tc && !result; i++, tv++) {
        candidate = NULL;
        candidateSz = 0;
        generator = NULL;
        generatorSz = 0;

        ret = ConvertHexToBin(tv->candidate, &candidate, &candidateSz,
                tv->generator, &generator, &generatorSz,
                NULL, NULL, NULL, NULL, NULL, NULL);
        if (ret != 0) {
            result = -113;
            break;
        }

        ret = wolfSSH_TestValidateKexDhGexGroup(candidate, candidateSz,
                generator, generatorSz, tv->minBits, tv->maxBits, &rng);
        if (ret != tv->expectedResult) {
            printf("DhGexGroupValidate: validator returned %d, expected %d\n",
                    ret, tv->expectedResult);
            result = -121;
        }

        FreeBins(candidate, generator, NULL, NULL);
    }

    wc_FreeRng(&rng);
    return result;
}

#endif /* WOLFSSH_TEST_INTERNAL && !WOLFSSH_NO_DH_GEX_SHA256 */


#ifdef WOLFSSH_TEST_INTERNAL

/* Verify DoUserAuthBanner fully consumes the payload, including a non-empty
 * language tag. Before the fix, the tag's data bytes were left unconsumed,
 * which would misalign packet decoding for subsequent messages. */
static int test_DoUserAuthBanner(void)
{
    WOLFSSH_CTX* ctx = NULL;
    WOLFSSH* ssh = NULL;
    int result = 0;

    /* Payload layout: [4-byte banner len][banner][4-byte lang len][lang] */
    struct {
        const char* banner;
        word32      bannerSz;
        const char* lang;
        word32      langSz;
        int         expectRet;
        const char* label;
    } cases[] = {
        { "Welcome", 7, "",     0, WS_SUCCESS,   "empty lang tag"    },
        { "Welcome", 7, "en-US", 5, WS_SUCCESS,  "non-empty lang tag" },
        { NULL,      0, NULL,   0, WS_BAD_ARGUMENT, "null ssh"       },
    };
    int i;

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_CLIENT, NULL);
    if (ctx == NULL)
        return -300;
    ssh = wolfSSH_new(ctx);
    if (ssh == NULL) {
        wolfSSH_CTX_free(ctx);
        return -301;
    }
    ctx->showBanner = 0;

    for (i = 0; i < (int)(sizeof(cases)/sizeof(cases[0])); i++) {
        byte   buf[128];
        word32 idx = 0;
        word32 len = 0;
        int    ret;

        if (cases[i].banner == NULL) {
            /* null-ssh case: pass NULL ssh, dummy non-null buf */
            buf[0] = 0;
            len = 1;
            ret = wolfSSH_TestDoUserAuthBanner(NULL, buf, len, &idx);
        }
        else {
            /* encode banner string */
            buf[len++] = (byte)(cases[i].bannerSz >> 24);
            buf[len++] = (byte)(cases[i].bannerSz >> 16);
            buf[len++] = (byte)(cases[i].bannerSz >>  8);
            buf[len++] = (byte)(cases[i].bannerSz);
            WMEMCPY(buf + len, cases[i].banner, cases[i].bannerSz);
            len += cases[i].bannerSz;
            /* encode language tag string */
            buf[len++] = (byte)(cases[i].langSz >> 24);
            buf[len++] = (byte)(cases[i].langSz >> 16);
            buf[len++] = (byte)(cases[i].langSz >>  8);
            buf[len++] = (byte)(cases[i].langSz);
            WMEMCPY(buf + len, cases[i].lang, cases[i].langSz);
            len += cases[i].langSz;

            ret = wolfSSH_TestDoUserAuthBanner(ssh, buf, len, &idx);
        }

        if (ret != cases[i].expectRet) {
            printf("DoUserAuthBanner[%s]: ret=%d, expected=%d\n",
                    cases[i].label, ret, cases[i].expectRet);
            result = -302 - i;
            break;
        }

        /* On success the entire payload must be consumed. */
        if (ret == WS_SUCCESS && idx != len) {
            printf("DoUserAuthBanner[%s]: idx=%u, len=%u (unconsumed bytes)\n",
                    cases[i].label, idx, len);
            result = -310 - i;
            break;
        }
    }

    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);
    return result;
}

#if defined(WOLFSSH_TEST_INTERNAL) && defined(WOLFSSH_SCP)
/* Verify GetScpFileMode strips setuid/setgid/sticky bits from a peer-supplied
 * SCP C/D record mode, matching the masking already done on the send path.
 * The receive path cannot be exercised end-to-end because both peers mask the
 * mode before transmitting, so this drives the parser directly. */
static int test_ScpGetFileMode(void)
{
    WOLFSSH_CTX* ctx = NULL;
    WOLFSSH* ssh = NULL;
    static const char* hdrs[] = {
        "C4755 0 f\n",  /* setuid set */
        "D2755 0 d\n",  /* setgid set */
        "D1755 0 d\n",  /* sticky set */
        "D7777 0 d\n",  /* all special bits set */
        "C0644 0 f\n"   /* ordinary mode, unaffected */
    };
    static const int expected[] = { 0755, 0755, 0755, 0777, 0644 };
    /* records the parser must reject */
    static const char* badHdrs[] = {
        "C8755 0 f\n",  /* '8' is not an octal digit */
        "X4755 0 f\n",  /* prefix is neither 'C' nor 'D' */
        "C75"           /* shorter than the mode field */
    };
    int result = 0;
    int ret;
    int i;
    word32 idx;

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_SERVER, NULL);
    if (ctx == NULL)
        return -420;
    ssh = wolfSSH_new(ctx);
    if (ssh == NULL) {
        wolfSSH_CTX_free(ctx);
        return -421;
    }

    for (i = 0; i < (int)(sizeof(hdrs) / sizeof(hdrs[0])); i++) {
        idx = 0;
        ssh->scpFileMode = 0;
        ret = wolfSSH_TestScpGetFileMode(ssh, (byte*)hdrs[i],
                (word32)WSTRLEN(hdrs[i]), &idx);
        if (ret != WS_SUCCESS) {
            result = -422;
            break;
        }
        if (ssh->scpFileMode != expected[i]) {
            result = -423;
            break;
        }
        /* index advances past the 'C'/'D', four mode octets, and the
         * trailing space */
        if (idx != 6) {
            result = -424;
            break;
        }
    }

    for (i = 0; result == 0 &&
            i < (int)(sizeof(badHdrs) / sizeof(badHdrs[0])); i++) {
        idx = 0;
        ret = wolfSSH_TestScpGetFileMode(ssh, (byte*)badHdrs[i],
                (word32)WSTRLEN(badHdrs[i]), &idx);
        if (ret != WS_BAD_ARGUMENT) {
            result = -425;
            break;
        }
    }

    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);
    return result;
}
#endif /* WOLFSSH_TEST_INTERNAL && WOLFSSH_SCP */

static int test_ChannelPutData(void)
{
    WOLFSSH_CTX* ctx = NULL;
    WOLFSSH* ssh = NULL;
    WOLFSSH_CHANNEL* channel = NULL;
    byte data[110];
    int result = 0;
    int ret;

    WMEMSET(data, 0xAB, sizeof(data));

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_SERVER, NULL);
    if (ctx == NULL)
        return -400;
    ssh = wolfSSH_new(ctx);
    if (ssh == NULL) {
        wolfSSH_CTX_free(ctx);
        return -401;
    }

    /* Window of 100 bytes, matching the input buffer size. */
    channel = ChannelNew(ssh, ID_CHANTYPE_SESSION, 100, 100);
    if (channel == NULL) {
        wolfSSH_free(ssh);
        wolfSSH_CTX_free(ctx);
        return -402;
    }

    /* NULL channel */
    ret = wolfSSH_TestChannelPutData(NULL, data, 10);
    if (ret != WS_BAD_ARGUMENT) {
        result = -403;
        goto done;
    }

    /* NULL data */
    ret = wolfSSH_TestChannelPutData(channel, NULL, 10);
    if (ret != WS_BAD_ARGUMENT) {
        result = -404;
        goto done;
    }

    /* dataSz exceeds windowSz: 101 > 100 */
    ret = wolfSSH_TestChannelPutData(channel, data, 101);
    if (ret != WS_FATAL_ERROR) {
        result = -405;
        goto done;
    }

    /* Valid write consuming half the window */
    ret = wolfSSH_TestChannelPutData(channel, data, 50);
    if (ret != WS_SUCCESS) {
        result = -406;
        goto done;
    }

    /* Remaining windowSz is 50; sending 51 must be rejected */
    ret = wolfSSH_TestChannelPutData(channel, data, 51);
    if (ret != WS_FATAL_ERROR) {
        result = -407;
        goto done;
    }

done:
    ChannelDelete(channel, ctx->heap);
    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);
    return result;
}

/* Counter callback for test_MsgHighwater. Records each invocation without
 * triggering wolfSSH_TriggerKeyExchange (which needs a live session). */
typedef struct HwTestCtx {
    int  count;
    byte lastSide;
} HwTestCtx;

static int HwTestCb(byte side, void* ctx)
{
    HwTestCtx* hc = (HwTestCtx*)ctx;
    if (hc != NULL) {
        hc->count++;
        hc->lastSide = side;
    }
    return WS_SUCCESS;
}

/* Exercise the wolfSSH_*MsgHighwater APIs and the per-key packet-count
 * threshold path inside HighwaterCheck. Covers:
 *   - NULL safety on getters/setters
 *   - CTX default value matches WOLFSSH_DEFAULT_MSG_HIGHWATER_MARK
 *   - CTX/SSH setter round-trip and CTX -> SSH inheritance on wolfSSH_new
 *   - SSH setter does not bleed back into the CTX
 *   - Threshold crossing fires the highwater callback exactly once per epoch
 *     (msgHighwaterFlag gates re-firing under the same keys)
 *   - Receive side fires independently of the transmit side
 *   - msgHighwaterMark == 0 disables the per-key packet check */
static int test_MsgHighwater(void)
{
    WOLFSSH_CTX* ctx = NULL;
    WOLFSSH*     ssh = NULL;
    HwTestCtx    hc;
    int          result = 0;

    if (wolfSSH_GetMsgHighwater(NULL) != 0)
        return -800;
    wolfSSH_CTX_SetMsgHighwater(NULL, 1234);
    wolfSSH_SetMsgHighwater(NULL, 1234);

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_SERVER, NULL);
    if (ctx == NULL)
        return -801;

    if (ctx->msgHighwaterMark != WOLFSSH_DEFAULT_MSG_HIGHWATER_MARK) {
        result = -802;
        goto done;
    }

    wolfSSH_CTX_SetMsgHighwater(ctx, 4096);
    if (ctx->msgHighwaterMark != 4096) {
        result = -803;
        goto done;
    }

    ssh = wolfSSH_new(ctx);
    if (ssh == NULL) {
        result = -804;
        goto done;
    }
    if (wolfSSH_GetMsgHighwater(ssh) != 4096) {
        result = -805;
        goto done;
    }

    wolfSSH_SetMsgHighwater(ssh, 16);
    if (wolfSSH_GetMsgHighwater(ssh) != 16) {
        result = -806;
        goto done;
    }
    if (ctx->msgHighwaterMark != 4096) {
        result = -807;
        goto done;
    }

    /* Install a counter callback. ssh->highwaterMark stays at the inherited
     * default (~1 GiB) and txCount/rxCount are not touched, so the byte-count
     * branch cannot fire and only the packet-count branch is under test. */
    WMEMSET(&hc, 0, sizeof(hc));
    wolfSSH_SetHighwaterCb(ctx, ctx->highwaterMark, HwTestCb);
    wolfSSH_SetHighwaterCtx(ssh, &hc);
    wolfSSH_SetMsgHighwater(ssh, 8);

    ssh->txMsgCount = 7;
    if (wolfSSH_TestHighwaterCheck(ssh, WOLFSSH_HWSIDE_TRANSMIT) != WS_SUCCESS
            || hc.count != 0) {
        result = -808;
        goto done;
    }

    ssh->txMsgCount = 8;
    if (wolfSSH_TestHighwaterCheck(ssh, WOLFSSH_HWSIDE_TRANSMIT) != WS_SUCCESS
            || hc.count != 1
            || hc.lastSide != WOLFSSH_HWSIDE_TRANSMIT) {
        result = -809;
        goto done;
    }

    /* Flag-gated: further packets in the same epoch must not re-fire. */
    ssh->txMsgCount = 100;
    if (wolfSSH_TestHighwaterCheck(ssh, WOLFSSH_HWSIDE_TRANSMIT) != WS_SUCCESS
            || hc.count != 1) {
        result = -810;
        goto done;
    }

    /* Simulate a fresh key epoch (msgHighwaterFlag and rx/txMsgCount are
     * reset by DoNewKeys/SendNewKeys) and verify the receive side fires. */
    ssh->msgHighwaterFlag = 0;
    ssh->rxMsgCount = 8;
    if (wolfSSH_TestHighwaterCheck(ssh, WOLFSSH_HWSIDE_RECEIVE) != WS_SUCCESS
            || hc.count != 2
            || hc.lastSide != WOLFSSH_HWSIDE_RECEIVE) {
        result = -811;
        goto done;
    }

    /* mark == 0 disables the per-key packet check entirely. */
    wolfSSH_SetMsgHighwater(ssh, 0);
    ssh->msgHighwaterFlag = 0;
    ssh->txMsgCount = 0xFFFFFFFFu;
    ssh->rxMsgCount = 0xFFFFFFFFu;
    if (wolfSSH_TestHighwaterCheck(ssh, WOLFSSH_HWSIDE_TRANSMIT) != WS_SUCCESS
            || hc.count != 2) {
        result = -812;
        goto done;
    }

done:
    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);
    return result;
}

static int test_DoChannelSuccess(void)
{
    WOLFSSH_CTX*     ctx = NULL;
    WOLFSSH*         ssh = NULL;
    WOLFSSH_CHANNEL* ch  = NULL;
    int              result = 0;
    int              ret;
    word32           idx;

    /* Short buffer: only 3 bytes, GetUint32 needs 4. */
    static const byte payShort[]   = { 0x00, 0x00, 0x00 };
    /* Unknown channel id = 99 (0x63). */
    static const byte payUnknown[] = { 0x00, 0x00, 0x00, 0x63 };
    /* Happy path: channel id = 0. */
    static const byte payOk[]      = { 0x00, 0x00, 0x00, 0x00 };

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_CLIENT, NULL);
    if (ctx == NULL)
        return -500;

    ssh = wolfSSH_new(ctx);
    if (ssh == NULL) { result = -501; goto done; }

    ch = ChannelNew(ssh, ID_CHANTYPE_SESSION,
                    DEFAULT_WINDOW_SZ, DEFAULT_MAX_PACKET_SZ);
    if (ch == NULL) { result = -502; goto done; }
    if (ChannelAppend(ssh, ch) != WS_SUCCESS) {
        ChannelDelete(ch, ssh->ctx->heap);
        result = -503;
        goto done;
    }

    /* Short buffer -> WS_BUFFER_E */
    idx = 0;
    ret = wolfSSH_TestDoChannelSuccess(ssh, (byte*)payShort,
                                       (word32)sizeof(payShort), &idx);
    if (ret != WS_BUFFER_E) { result = -510; goto done; }
    if (idx != 0) { result = -514; goto done; }

    /* Unknown channel -> WS_INVALID_CHANID */
    idx = 0;
    ret = wolfSSH_TestDoChannelSuccess(ssh, (byte*)payUnknown,
                                       (word32)sizeof(payUnknown), &idx);
    if (ret != WS_INVALID_CHANID) { result = -511; goto done; }
    if (idx != 4) { result = -515; goto done; }

    /* Happy path -> WS_SUCCESS, serverState == SERVER_DONE */
    idx = 0;
    ret = wolfSSH_TestDoChannelSuccess(ssh, (byte*)payOk,
                                       (word32)sizeof(payOk), &idx);
    if (ret != WS_SUCCESS) { result = -512; goto done; }
    if (ssh->serverState != SERVER_DONE) { result = -513; goto done; }
    if (idx != 4) { result = -516; goto done; }

done:
    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);
    return result;
}

static int test_DoChannelFailure(void)
{
    WOLFSSH_CTX*     ctx = NULL;
    WOLFSSH*         ssh = NULL;
    WOLFSSH_CHANNEL* ch  = NULL;
    int              result = 0;
    int              ret;
    word32           idx;

    static const byte payShort[]   = { 0x00, 0x00, 0x00 };
    static const byte payUnknown[] = { 0x00, 0x00, 0x00, 0x63 };
    static const byte payOk[]      = { 0x00, 0x00, 0x00, 0x00 };

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_CLIENT, NULL);
    if (ctx == NULL)
        return -520;

    ssh = wolfSSH_new(ctx);
    if (ssh == NULL) { result = -521; goto done; }

    ch = ChannelNew(ssh, ID_CHANTYPE_SESSION,
                    DEFAULT_WINDOW_SZ, DEFAULT_MAX_PACKET_SZ);
    if (ch == NULL) { result = -522; goto done; }
    if (ChannelAppend(ssh, ch) != WS_SUCCESS) {
        ChannelDelete(ch, ssh->ctx->heap);
        result = -523;
        goto done;
    }

    /* Short buffer -> WS_BUFFER_E */
    idx = 0;
    ret = wolfSSH_TestDoChannelFailure(ssh, (byte*)payShort,
                                       (word32)sizeof(payShort), &idx);
    if (ret != WS_BUFFER_E) { result = -530; goto done; }
    if (idx != 0) { result = -533; goto done; }

    /* Unknown channel -> WS_INVALID_CHANID */
    idx = 0;
    ret = wolfSSH_TestDoChannelFailure(ssh, (byte*)payUnknown,
                                       (word32)sizeof(payUnknown), &idx);
    if (ret != WS_INVALID_CHANID) { result = -531; goto done; }
    if (idx != 4) { result = -534; goto done; }

    /* Happy path -> WS_CHANOPEN_FAILED */
    idx = 0;
    ret = wolfSSH_TestDoChannelFailure(ssh, (byte*)payOk,
                                       (word32)sizeof(payOk), &idx);
    if (ret != WS_CHANOPEN_FAILED) { result = -532; goto done; }
    if (idx != 4) { result = -535; goto done; }

done:
    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);
    return result;
}

static int test_DoChannelData_overflow(void)
{
    WOLFSSH_CTX*     ctx = NULL;
    WOLFSSH*         ssh = NULL;
    WOLFSSH_CHANNEL* ch  = NULL;
    int              result = 0;
    int              ret;
    word32           idx;

    /* Channel id=0, dataSz=65 (> maxPacketSz of 64): overflow case.
     * Buffer holds header only; dataSz > maxPacketSz triggers the guard
     * before ChannelPutData is ever called. */
    static const byte payOver[] = {
        0x00, 0x00, 0x00, 0x00,   /* channelId = 0  */
        0x00, 0x00, 0x00, 0x41,   /* dataSz = 65    */
        /* 65 payload bytes follow (all zeroes) */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00
    };

    /* Channel id=0, dataSz=32 (< maxPacketSz of 64): within-limit case. */
    static const byte payOk[] = {
        0x00, 0x00, 0x00, 0x00,   /* channelId = 0  */
        0x00, 0x00, 0x00, 0x20,   /* dataSz = 32    */
        /* 32 payload bytes */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_SERVER, NULL);
    if (ctx == NULL)
        return -540;

    ssh = wolfSSH_new(ctx);
    if (ssh == NULL) { result = -541; goto done; }

    /* windowSz=128, maxPacketSz=64 */
    ch = ChannelNew(ssh, ID_CHANTYPE_SESSION, 128, 64);
    if (ch == NULL) { result = -542; goto done; }
    if (ChannelAppend(ssh, ch) != WS_SUCCESS) {
        ChannelDelete(ch, ssh->ctx->heap);
        result = -543;
        goto done;
    }

    /* dataSz=65 > maxPacketSz=64 -> WS_RECV_OVERFLOW_E */
    idx = 0;
    ret = wolfSSH_TestDoChannelData(ssh, (byte*)payOver,
                                    (word32)sizeof(payOver), &idx);
    if (ret != WS_RECV_OVERFLOW_E) { result = -550; goto done; }

    /* dataSz=32 <= maxPacketSz=64 -> WS_CHAN_RXD */
    idx = 0;
    ret = wolfSSH_TestDoChannelData(ssh, (byte*)payOk,
                                    (word32)sizeof(payOk), &idx);
    if (ret != WS_CHAN_RXD) { result = -551; goto done; }

done:
    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);
    return result;
}

static int DiscardIoSend(WOLFSSH* ssh, void* buf, word32 sz, void* ctx)
{
    (void)ssh; (void)buf; (void)ctx;
    return (int)sz;
}

static int test_DoChannelExtendedData_overflow(void)
{
    WOLFSSH_CTX*     ctx = NULL;
    WOLFSSH*         ssh = NULL;
    WOLFSSH_CHANNEL* ch  = NULL;
    int              result = 0;
    int              ret;
    word32           idx;

    /* channelId=0, dataTypeCode=1 (stderr), dataSz=65 (> maxPacketSz=64) */
    static const byte payOver[] = {
        0x00, 0x00, 0x00, 0x00,   /* channelId = 0            */
        0x00, 0x00, 0x00, 0x01,   /* dataTypeCode = 1 (stderr)*/
        0x00, 0x00, 0x00, 0x41,   /* dataSz = 65              */
        /* 65 payload bytes */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00
    };

    /* channelId=0, dataTypeCode=1 (stderr), dataSz=32 (< maxPacketSz=64) */
    static const byte payOk[] = {
        0x00, 0x00, 0x00, 0x00,   /* channelId = 0            */
        0x00, 0x00, 0x00, 0x01,   /* dataTypeCode = 1 (stderr)*/
        0x00, 0x00, 0x00, 0x20,   /* dataSz = 32              */
        /* 32 payload bytes */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_SERVER, NULL);
    if (ctx == NULL)
        return -580;
    wolfSSH_SetIOSend(ctx, DiscardIoSend);

    ssh = wolfSSH_new(ctx);
    if (ssh == NULL) { result = -581; goto done; }
    /* Allow MSGID_CHANNEL_WINDOW_ADJUST on this bare session. */
    ssh->acceptState = ACCEPT_SERVER_USERAUTH_SENT;

    /* windowSz=128, maxPacketSz=64 */
    ch = ChannelNew(ssh, ID_CHANTYPE_SESSION, 128, 64);
    if (ch == NULL) { result = -582; goto done; }
    if (ChannelAppend(ssh, ch) != WS_SUCCESS) {
        ChannelDelete(ch, ssh->ctx->heap);
        result = -583;
        goto done;
    }

    /* dataSz=65 > maxPacketSz=64 -> WS_RECV_OVERFLOW_E */
    idx = 0;
    ret = wolfSSH_TestDoChannelExtendedData(ssh, (byte*)payOver,
                                            (word32)sizeof(payOver), &idx);
    if (ret != WS_RECV_OVERFLOW_E) { result = -590; goto done; }

    /* dataSz=32 <= maxPacketSz=64 -> WS_EXTDATA */
    idx = 0;
    ret = wolfSSH_TestDoChannelExtendedData(ssh, (byte*)payOk,
                                            (word32)sizeof(payOk), &idx);
    if (ret != WS_EXTDATA) { result = -591; goto done; }

done:
    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);
    return result;
}

static int test_SendChannelData_eofTxd(void)
{
    WOLFSSH_CTX*     ctx = NULL;
    WOLFSSH*         ssh = NULL;
    WOLFSSH_CHANNEL* ch  = NULL;
    int              result = 0;
    int              ret;
    byte             buf[4] = { 0x00, 0x01, 0x02, 0x03 };

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_CLIENT, NULL);
    if (ctx == NULL)
        return -560;

    ssh = wolfSSH_new(ctx);
    if (ssh == NULL) { result = -561; goto done; }

    ch = ChannelNew(ssh, ID_CHANTYPE_SESSION,
                    DEFAULT_WINDOW_SZ, DEFAULT_MAX_PACKET_SZ);
    if (ch == NULL) { result = -562; goto done; }
    if (ChannelAppend(ssh, ch) != WS_SUCCESS) {
        ChannelDelete(ch, ssh->ctx->heap);
        result = -563;
        goto done;
    }

    ch->eofTxd = 1;

    /* SendChannelData after EOF -> WS_EOF */
    ret = SendChannelData(ssh, ch->channel, buf, (word32)sizeof(buf));
    if (ret != WS_EOF) { result = -570; goto done; }

    /* SendChannelExtendedData after EOF -> WS_EOF */
    ret = SendChannelExtendedData(ssh, ch->channel, buf, (word32)sizeof(buf));
    if (ret != WS_EOF) { result = -571; goto done; }

done:
    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);
    return result;
}

/* Plaintext SSH packet from IoSend (before encryption/MAC): LENGTH_SZ,
 * PAD_LENGTH_SZ, then payload starting with the message ID (RFC 4253;
 * wolfSSH PreparePacket/BundlePacket). Not for encrypted payloads or
 * arbitrary truncated chunks. */
static int CaptureMsgId(const byte* buf, word32 len)
{
    word32 off = LENGTH_SZ + PAD_LENGTH_SZ;

    if (len <= off)
        return -1;
    return (int)buf[off];
}

/* Verify DoChannelRequest sends CHANNEL_SUCCESS for known types and
 * CHANNEL_FAILURE for unrecognized ones (RFC 4254 Section 5.4).
 *
 * A custom IoSend callback captures the outgoing packet in plaintext
 * (no cipher negotiated on a fresh session). Message ID is read via
 * CaptureMsgId() using LENGTH_SZ + PAD_LENGTH_SZ. */
static byte   s_chanReqCapture[256];
static word32 s_chanReqCaptureSz = 0;

static int CaptureIoSendChanReq(WOLFSSH* ssh, void* buf, word32 sz, void* ctx)
{
    (void)ssh; (void)ctx;
    s_chanReqCaptureSz = (sz < (word32)sizeof(s_chanReqCapture))
                         ? sz : (word32)sizeof(s_chanReqCapture);
    WMEMCPY(s_chanReqCapture, buf, s_chanReqCaptureSz);
    return (int)sz;
}

static int test_DoChannelRequest(void)
{
    WOLFSSH_CTX*     ctx = NULL;
    WOLFSSH*         ssh = NULL;
    WOLFSSH_CHANNEL* ch  = NULL;
    int              result = 0;
    int              i;

    /* Payloads: [uint32 channelId=0][string type][byte wantReply=1][extra] */
    static const byte payShell[] = {
        0x00,0x00,0x00,0x00,              /* channelId = 0   */
        0x00,0x00,0x00,0x05,              /* typeSz = 5      */
        0x73,0x68,0x65,0x6C,0x6C,         /* "shell"         */
        0x01                              /* wantReply = 1   */
    };
    static const byte payExec[] = {
        0x00,0x00,0x00,0x00,              /* channelId = 0   */
        0x00,0x00,0x00,0x04,              /* typeSz = 4      */
        0x65,0x78,0x65,0x63,              /* "exec"          */
        0x01,                             /* wantReply = 1   */
        0x00,0x00,0x00,0x02,              /* cmdSz = 2       */
        0x6C,0x73                         /* "ls"            */
    };
    static const byte payUnknown[] = {
        0x00,0x00,0x00,0x00,              /* channelId = 0   */
        0x00,0x00,0x00,0x0C,              /* typeSz = 12     */
        0x75,0x6E,0x6B,0x6E,0x6F,0x77,
        0x6E,0x2D,0x74,0x79,0x70,0x65,   /* "unknown-type"  */
        0x01                              /* wantReply = 1   */
    };

    struct {
        const char* label;
        const byte* payload;
        word32      payloadSz;
        int         expectRet;
        byte        expectMsgId;
    } cases[] = {
        { "shell",
          payShell,   (word32)sizeof(payShell),
          WS_SUCCESS, MSGID_CHANNEL_SUCCESS },
        { "exec",
          payExec,    (word32)sizeof(payExec),
          WS_SUCCESS, MSGID_CHANNEL_SUCCESS },
        { "unknown-type",
          payUnknown, (word32)sizeof(payUnknown),
          WS_SUCCESS, MSGID_CHANNEL_FAILURE },
    };

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_SERVER, NULL);
    if (ctx == NULL)
        return -400;
    wolfSSH_SetIOSend(ctx, CaptureIoSendChanReq);

    ssh = wolfSSH_new(ctx);
    if (ssh == NULL) {
        result = -401;
        goto done;
    }

    ch = ChannelNew(ssh, ID_CHANTYPE_SESSION,
                    DEFAULT_WINDOW_SZ, DEFAULT_MAX_PACKET_SZ);
    if (ch == NULL) {
        result = -402;
        goto done;
    }
    if (ChannelAppend(ssh, ch) != WS_SUCCESS) {
        ChannelDelete(ch, ssh->ctx->heap);
        result = -403;
        goto done;
    }

    for (i = 0; i < (int)(sizeof(cases) / sizeof(cases[0])); i++) {
        word32 idx = 0;
        int    ret;

        s_chanReqCaptureSz = 0;
        WMEMSET(s_chanReqCapture, 0, sizeof(s_chanReqCapture));

        ret = wolfSSH_TestDoChannelRequest(ssh,
                (byte*)cases[i].payload, cases[i].payloadSz, &idx);

        if (ret != cases[i].expectRet) {
            printf("DoChannelRequest[%s]: ret=%d, expected=%d\n",
                    cases[i].label, ret, cases[i].expectRet);
            result = -404 - i;
            goto done;
        }

        {
            int capMsgId = CaptureMsgId(s_chanReqCapture, s_chanReqCaptureSz);

            if (capMsgId < 0) {
                printf("DoChannelRequest[%s]: captured packet too short (%u)\n",
                        cases[i].label, s_chanReqCaptureSz);
                result = -410 - i;
                goto done;
            }

            if (capMsgId != (int)cases[i].expectMsgId) {
                printf("DoChannelRequest[%s]: msg_id=0x%02x, expected=0x%02x\n",
                        cases[i].label,
                        capMsgId, cases[i].expectMsgId);
                result = -420 - i;
                goto done;
            }
        }
    }

    /* RFC 4254 sec 6.10: exit-status and exit-signal must not send a reply
     * even if the wire wantReply byte is 1. DoChannelRequest overrides
     * wantReply=0 for these types, so no CHANNEL_SUCCESS/FAILURE packet
     * should be emitted. */
#if defined(WOLFSSH_TERM) || defined(WOLFSSH_SHELL)
    {
        static const byte payExitStatus[] = {
            0x00,0x00,0x00,0x00,              /* channelId = 0        */
            0x00,0x00,0x00,0x0B,              /* typeSz = 11          */
            0x65,0x78,0x69,0x74,0x2D,         /* "exit-"              */
            0x73,0x74,0x61,0x74,0x75,0x73,    /* "status"             */
            0x01,                             /* wantReply = 1 (wire) */
            0x00,0x00,0x00,0x00               /* exitStatus = 0       */
        };
        /* exit-signal: sigName="TERM", coreDumped=0, errorMsg="",
         * languageTag="" */
        static const byte payExitSignal[] = {
            0x00,0x00,0x00,0x00,                    /* channelId = 0        */
            0x00,0x00,0x00,0x0B,                    /* typeSz = 11          */
            0x65,0x78,0x69,0x74,0x2D,               /* "exit-"              */
            0x73,0x69,0x67,0x6E,0x61,0x6C,          /* "signal"             */
            0x01,                                   /* wantReply = 1 (wire) */
            0x00,0x00,0x00,0x04,                    /* sigNameSz = 4        */
            0x54,0x45,0x52,0x4D,                    /* "TERM"               */
            0x00,                                   /* coreDumped = false   */
            0x00,0x00,0x00,0x00,                    /* errorMsg = ""        */
            0x00,0x00,0x00,0x00                     /* languageTag = ""     */
        };
        struct { const char* label; const byte* buf; word32 sz; int errBase; }
        noReplyCases[] = {
            { "exit-status", payExitStatus, (word32)sizeof(payExitStatus), -430 },
            { "exit-signal", payExitSignal, (word32)sizeof(payExitSignal), -440 },
        };
        int k;

        for (k = 0; k < (int)(sizeof(noReplyCases)/sizeof(noReplyCases[0]));
                k++) {
            word32 idx2 = 0;
            int    ret2;

            s_chanReqCaptureSz = 0;
            WMEMSET(s_chanReqCapture, 0, sizeof(s_chanReqCapture));

            ret2 = wolfSSH_TestDoChannelRequest(ssh, (byte*)noReplyCases[k].buf,
                    noReplyCases[k].sz, &idx2);
            if (ret2 != WS_SUCCESS) {
                printf("DoChannelRequest[%s]: ret=%d, expected=%d\n",
                        noReplyCases[k].label, ret2, WS_SUCCESS);
                result = noReplyCases[k].errBase;
                goto done;
            }
            if (s_chanReqCaptureSz != 0) {
                printf("DoChannelRequest[%s]: unexpected reply packet "
                        "(sz=%u)\n", noReplyCases[k].label,
                        s_chanReqCaptureSz);
                result = noReplyCases[k].errBase - 1;
                goto done;
            }
        }
    }
#endif /* WOLFSSH_TERM || WOLFSSH_SHELL */

    /* RFC 4254 sec 6.7: window-change must not send a reply even if the
     * wire wantReply byte is 1. */
#if defined(WOLFSSH_SHELL) && defined(WOLFSSH_TERM)
    {
        static const byte payWindowChange[] = {
            0x00,0x00,0x00,0x00,                    /* channelId = 0        */
            0x00,0x00,0x00,0x0D,                    /* typeSz = 13          */
            0x77,0x69,0x6E,0x64,0x6F,0x77,0x2D,    /* "window-"            */
            0x63,0x68,0x61,0x6E,0x67,0x65,         /* "change"             */
            0x01,                                   /* wantReply = 1 (wire) */
            0x00,0x00,0x00,0x50,                    /* widthChar = 80       */
            0x00,0x00,0x00,0x18,                    /* heightRows = 24      */
            0x00,0x00,0x00,0x00,                    /* widthPixels = 0      */
            0x00,0x00,0x00,0x00                     /* heightPixels = 0     */
        };
        word32 idx2 = 0;
        int    ret2;

        s_chanReqCaptureSz = 0;
        WMEMSET(s_chanReqCapture, 0, sizeof(s_chanReqCapture));

        ret2 = wolfSSH_TestDoChannelRequest(ssh, (byte*)payWindowChange,
                (word32)sizeof(payWindowChange), &idx2);
        if (ret2 != WS_SUCCESS) {
            printf("DoChannelRequest[window-change]: ret=%d, expected=%d\n",
                    ret2, WS_SUCCESS);
            result = -450;
            goto done;
        }
        if (s_chanReqCaptureSz != 0) {
            printf("DoChannelRequest[window-change]: unexpected reply packet "
                    "(sz=%u)\n", s_chanReqCaptureSz);
            result = -451;
            goto done;
        }
    }
#endif /* WOLFSSH_SHELL && WOLFSSH_TERM */

done:
    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);
    return result;
}

/* Capture buffer for the service-name unit test. Separate from the channel-
 * request capture so the two tests can run independently in any order. */
static byte   s_authSvcCapture[256];
static word32 s_authSvcCaptureSz = 0;
static word32 s_authSvcSendCount = 0;

static int CaptureIoSendAuthSvc(WOLFSSH* ssh, void* buf, word32 sz, void* ctx)
{
    (void)ssh; (void)ctx;
    s_authSvcCaptureSz = (sz < (word32)sizeof(s_authSvcCapture))
                         ? sz : (word32)sizeof(s_authSvcCapture);
    WMEMCPY(s_authSvcCapture, buf, s_authSvcCaptureSz);
    s_authSvcSendCount++;
    return (int)sz;
}

/* Verify DoUserAuthRequest rejects non-"ssh-connection" service names per
 * RFC 4252 Section 5.  For each case we assert:
 *   1. ret == WS_SUCCESS (connection stays open for retry)
 *   2. SSH_MSG_USERAUTH_FAILURE is actually sent (see CaptureMsgId():
 *      LENGTH_SZ + PAD_LENGTH_SZ then msg id)
 *   3. *idx == len (entire payload consumed; buffer stays aligned)
 *
 * For invalid-service cases the auth-method field is intentionally omitted
 * from the payload.  DoUserAuthRequest must short-circuit at the service-name
 * check and still satisfy all three assertions - proving it never tries to
 * parse the missing auth-method field.  If the short-circuit were absent,
 * GetSize() for authNameSz would hit end-of-buffer and return WS_BUFFER_E,
 * failing assertion 1.
 *
 * For the valid-service case, auth method "xyz-unknown" (always unsupported
 * regardless of compile-time options) is included.  The function reaches
 * auth-method dispatch, falls to the unknown-method else-branch, and sends
 * USERAUTH_FAILURE via that normal path.
 *
 * A second valid-service row appends fake password-style bytes after the
 * method name.  That proves DoUserAuthRequest() consumes trailing
 * method-specific payload (begin = len in the unknown-method branch); without
 * it, DoReceive() could advance inputBuffer.idx short of the packet end and
 * misalign decoding. */
static const byte s_unknownAuthTrailingFakePassword[] = {
    0x00, /* "change password" FALSE */
    0x00, 0x00, 0x00, 0x08,
    'p', 'a', 's', 's', 'w', 'o', 'r', 'd',
};

static int test_DoUserAuthRequest_serviceName(void)
{
    WOLFSSH_CTX* ctx = NULL;
    WOLFSSH* ssh = NULL;
    int result = 0;
    struct {
        const char* svcName;
        word32      svcNameSz;
        const char* authMethod;   /* NULL = omit field (proves short-circuit) */
        word32      authMethodSz;
        int         expectRet;
        const char* label;
        const byte* authTrailing; /* bytes after auth method; NULL if none */
        word32      authTrailingSz;
    } cases[] = {
        /* valid service: auth dispatch fires, fails on unknown method */
        { "ssh-connection", 14, "xyz-unknown", 11, WS_SUCCESS,
          "valid svc unknown auth", NULL, 0 },
        /* same but trailing junk must be skipped so *idx reaches len */
        { "ssh-connection", 14, "xyz-unknown", 11, WS_SUCCESS,
          "valid svc unknown auth trailing junk",
          s_unknownAuthTrailingFakePassword,
          (word32)sizeof(s_unknownAuthTrailingFakePassword) },
        /* invalid service: short-circuit, auth-method field absent */
        { "ssh-agent",       9, NULL,           0, WS_SUCCESS,
          "invalid ssh-agent svc", NULL, 0 },
        { "bad",             3, NULL,           0, WS_SUCCESS,
          "invalid bad svc", NULL, 0 },
        /* zero-length service name: NameToId("",0)==ID_UNKNOWN, must reject */
        { "",                0, NULL,           0, WS_SUCCESS,
          "zero-length svc", NULL, 0 },
        /* ssh-userauth: NameToId returns ID_SERVICE_USERAUTH, not
         * ID_SERVICE_CONNECTION, so must also be rejected */
        { "ssh-userauth",   12, NULL,           0, WS_SUCCESS,
          "invalid ssh-userauth svc", NULL, 0 },
    };
    int i;

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_SERVER, NULL);
    if (ctx == NULL) return -500;
    wolfSSH_SetIOSend(ctx, CaptureIoSendAuthSvc);

    for (i = 0; i < (int)(sizeof(cases)/sizeof(cases[0])); i++) {
        byte   buf[128];
        word32 len = 0, idx = 0;
        word32 snsz = cases[i].svcNameSz;
        int    ret;

        ssh = wolfSSH_new(ctx);
        if (ssh == NULL) { result = -501; goto done; }

        s_authSvcCaptureSz = 0;
        s_authSvcSendCount = 0;
        WMEMSET(s_authSvcCapture, 0, sizeof(s_authSvcCapture));

        /* username: "user" */
        buf[len++] = 0; buf[len++] = 0; buf[len++] = 0; buf[len++] = 4;
        WMEMCPY(buf + len, "user", 4); len += 4;

        /* service name */
        buf[len++] = (byte)(snsz >> 24); buf[len++] = (byte)(snsz >> 16);
        buf[len++] = (byte)(snsz >>  8); buf[len++] = (byte)snsz;
        if (snsz > 0) { WMEMCPY(buf + len, cases[i].svcName, snsz); }
        len += snsz;

        /* auth method: omit for invalid-service cases to prove short-circuit */
        if (cases[i].authMethod != NULL) {
            word32 amsz = cases[i].authMethodSz;
            buf[len++] = (byte)(amsz >> 24); buf[len++] = (byte)(amsz >> 16);
            buf[len++] = (byte)(amsz >>  8); buf[len++] = (byte)amsz;
            WMEMCPY(buf + len, cases[i].authMethod, amsz); len += amsz;
            if (cases[i].authTrailingSz > 0U) {
                WMEMCPY(buf + len, cases[i].authTrailing,
                        cases[i].authTrailingSz);
                len += cases[i].authTrailingSz;
            }
        }

        ret = wolfSSH_TestDoUserAuthRequest(ssh, buf, len, &idx);

        if (s_authSvcSendCount != 1) {
            printf("DoUserAuthRequest_svcName[%s]: expected 1 send, got %u\n",
                   cases[i].label, s_authSvcSendCount);
            result = -540 - i;
            goto done;
        }

        if (ret != cases[i].expectRet) {
            printf("DoUserAuthRequest_svcName[%s]: ret=%d expected=%d\n",
                   cases[i].label, ret, cases[i].expectRet);
            result = -502 - i;
            goto done;
        }

        /* MSGID_USERAUTH_FAILURE must be in the captured packet. */
        {
            int capMsgId = CaptureMsgId(s_authSvcCapture, s_authSvcCaptureSz);

            if (capMsgId < 0 || capMsgId != MSGID_USERAUTH_FAILURE) {
                printf("DoUserAuthRequest_svcName[%s]: USERAUTH_FAILURE not "
                       "sent (capSz=%u msg_id=0x%02x)\n", cases[i].label,
                       s_authSvcCaptureSz,
                       capMsgId >= 0 ? capMsgId : 0);
                result = -520 - i;
                goto done;
            }
        }

        /* All cases must consume the entire payload. */
        if (idx != len) {
            printf("DoUserAuthRequest_svcName[%s]: idx=%u expected len=%u\n",
                   cases[i].label, idx, len);
            result = -510 - i;
            goto done;
        }

        /* Invalid-service cases must NOT record the username. */
        if (cases[i].authMethod == NULL && ssh->userName != NULL) {
            printf("DoUserAuthRequest_svcName[%s]: userName set on invalid "
                   "service (expected NULL)\n", cases[i].label);
            result = -530 - i;
            goto done;
        }

        wolfSSH_free(ssh);
        ssh = NULL;
    }

done:
    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);
    return result;
}


/* userauth callback that records whether it was invoked. Returns SUCCESS so
 * that, if it were ever reached for a password-change request, the request
 * would be (incorrectly) authenticated - making a missed rejection visible. */
static int s_pwChangeCbCalled = 0;
static int UnitAuthAlwaysSucceed(byte authType, WS_UserAuthData* authData,
        void* ctx)
{
    (void)authData;
    (void)ctx;
    if (authType == WOLFSSH_USERAUTH_PASSWORD) {
        s_pwChangeCbCalled = 1;
    }
    return WOLFSSH_USERAUTH_SUCCESS;
}

/* Verify DoUserAuthRequest rejects a password request that sets the
 * password-change flag (RFC 4252 Section 8: an expired password MUST NOT be
 * used for authentication). The request is otherwise well-formed and the
 * userauth callback would return SUCCESS, so a missing rejection would let the
 * old password authenticate. Asserts:
 *   1. ret == WS_SUCCESS (connection stays open for retry)
 *   2. the userauth callback is never invoked
 *   3. exactly one packet is sent and it is SSH_MSG_USERAUTH_FAILURE
 *   4. *idx == len (the new-password field is fully consumed) */
static int test_DoUserAuthRequest_rejectsPasswordChange(void)
{
    WOLFSSH_CTX* ctx = NULL;
    WOLFSSH* ssh = NULL;
    int result = 0;
    int ret;
    int capMsgId;
    byte buf[128];
    word32 len = 0, idx = 0;

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_SERVER, NULL);
    if (ctx == NULL)
        return -660;
    wolfSSH_SetIOSend(ctx, CaptureIoSendAuthSvc);
    wolfSSH_SetUserAuth(ctx, UnitAuthAlwaysSucceed);

    ssh = wolfSSH_new(ctx);
    if (ssh == NULL) {
        result = -661;
        goto out;
    }

    s_pwChangeCbCalled = 0;
    s_authSvcCaptureSz = 0;
    s_authSvcSendCount = 0;
    WMEMSET(s_authSvcCapture, 0, sizeof(s_authSvcCapture));

    /* username: "user" */
    buf[len++] = 0; buf[len++] = 0; buf[len++] = 0; buf[len++] = 4;
    WMEMCPY(buf + len, "user", 4); len += 4;
    /* service name: "ssh-connection" */
    buf[len++] = 0; buf[len++] = 0; buf[len++] = 0; buf[len++] = 14;
    WMEMCPY(buf + len, "ssh-connection", 14); len += 14;
    /* auth method: "password" */
    buf[len++] = 0; buf[len++] = 0; buf[len++] = 0; buf[len++] = 8;
    WMEMCPY(buf + len, "password", 8); len += 8;
    /* password-change flag: TRUE */
    buf[len++] = 1;
    /* current password: "oldpass" */
    buf[len++] = 0; buf[len++] = 0; buf[len++] = 0; buf[len++] = 7;
    WMEMCPY(buf + len, "oldpass", 7); len += 7;
    /* new password: "newpass" */
    buf[len++] = 0; buf[len++] = 0; buf[len++] = 0; buf[len++] = 7;
    WMEMCPY(buf + len, "newpass", 7); len += 7;

    ret = wolfSSH_TestDoUserAuthRequest(ssh, buf, len, &idx);

    if (ret != WS_SUCCESS) {
        result = -662;
        goto out;
    }
    if (s_pwChangeCbCalled) {
        /* The callback must not run for a password-change request. */
        result = -663;
        goto out;
    }
    if (s_authSvcSendCount != 1) {
        result = -664;
        goto out;
    }
    capMsgId = CaptureMsgId(s_authSvcCapture, s_authSvcCaptureSz);
    if (capMsgId != MSGID_USERAUTH_FAILURE) {
        result = -665;
        goto out;
    }
    if (idx != len) {
        result = -666;
        goto out;
    }

out:
    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);
    return result;
}


/* userAuthTypesCb that advertises no methods (returns mask 0). Mirrors a
 * wolfsshd configuration with both PasswordAuthentication no and
 * PubkeyAuthentication no. */
static int UnitAuthTypesReturnZero(WOLFSSH* ssh, void* ctx)
{
    (void)ssh;
    (void)ctx;
    return 0;
}

/* Regression test for the 0-mask case (issue 4115 follow-up). When the
 * userAuthTypesCb advertises no methods, SendUserAuthFailure must still emit a
 * well-formed USERAUTH_FAILURE carrying an empty "authentications that can
 * continue" name-list (RFC 4252 Section 5.1) and return WS_SUCCESS, instead of
 * underflowing the name-list length to -1 and dropping the connection.
 *
 * Asserts:
 *   1. wolfSSH_TestSendUserAuthFailure() returns WS_SUCCESS (not negative).
 *   2. Exactly one packet is emitted (connection not dropped).
 *   3. The packet's message id is MSGID_USERAUTH_FAILURE.
 *   4. The name-list length field is 0 (empty method list).
 *
 * The control case (a permissive callback advertising publickey+password)
 * confirms the same path produces a non-empty name-list, so the empty result
 * is specific to the 0-mask input rather than the test always seeing 0. */
static int test_SendUserAuthFailure_emptyMethods(void)
{
    WOLFSSH_CTX* ctx = NULL;
    WOLFSSH* ssh = NULL;
    int result = 0;
    int i;
    struct {
        WS_CallbackUserAuthTypes cb;
        int    expectEmpty;   /* 1 = name-list must be empty, 0 = non-empty */
        const char* label;
    } cases[] = {
        { UnitAuthTypesReturnZero, 1, "no methods advertised" },
        { NULL,                    0, "default methods advertised" },
    };
    word32 off = LENGTH_SZ + PAD_LENGTH_SZ;

    for (i = 0; i < (int)(sizeof(cases)/sizeof(cases[0])); i++) {
        word32 nameListSz;
        int    capMsgId;
        int    ret;

        ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_SERVER, NULL);
        if (ctx == NULL) { result = -600; break; }
        if (cases[i].cb != NULL) {
            wolfSSH_SetUserAuthTypes(ctx, cases[i].cb);
        }
        wolfSSH_SetIOSend(ctx, CaptureIoSendAuthSvc);

        ssh = wolfSSH_new(ctx);
        if (ssh == NULL) { result = -601; break; }

        s_authSvcCaptureSz = 0;
        s_authSvcSendCount = 0;
        WMEMSET(s_authSvcCapture, 0, sizeof(s_authSvcCapture));

        ret = wolfSSH_TestSendUserAuthFailure(ssh, 0);

        if (ret != WS_SUCCESS) {
            printf("SendUserAuthFailure[%s]: ret=%d expected WS_SUCCESS\n",
                   cases[i].label, ret);
            result = -602 - i;
            break;
        }

        if (s_authSvcSendCount != 1) {
            printf("SendUserAuthFailure[%s]: expected 1 send, got %u\n",
                   cases[i].label, s_authSvcSendCount);
            result = -610 - i;
            break;
        }

        capMsgId = CaptureMsgId(s_authSvcCapture, s_authSvcCaptureSz);
        if (capMsgId != MSGID_USERAUTH_FAILURE) {
            printf("SendUserAuthFailure[%s]: msgId=%d expected"
                   " USERAUTH_FAILURE\n", cases[i].label, capMsgId);
            result = -620 - i;
            break;
        }

        /* name-list length is the 4 bytes following the message id */
        if (s_authSvcCaptureSz < off + MSG_ID_SZ + LENGTH_SZ) {
            printf("SendUserAuthFailure[%s]: packet too short (%u)\n",
                   cases[i].label, s_authSvcCaptureSz);
            result = -630 - i;
            break;
        }
        nameListSz =
            ((word32)s_authSvcCapture[off + MSG_ID_SZ]     << 24) |
            ((word32)s_authSvcCapture[off + MSG_ID_SZ + 1] << 16) |
            ((word32)s_authSvcCapture[off + MSG_ID_SZ + 2] <<  8) |
            ((word32)s_authSvcCapture[off + MSG_ID_SZ + 3]);

        if (cases[i].expectEmpty && nameListSz != 0) {
            printf("SendUserAuthFailure[%s]: nameListSz=%u expected 0\n",
                   cases[i].label, nameListSz);
            result = -640 - i;
            break;
        }
        if (!cases[i].expectEmpty && nameListSz == 0) {
            printf("SendUserAuthFailure[%s]: nameListSz=0 expected non-empty\n",
                   cases[i].label);
            result = -650 - i;
            break;
        }

        wolfSSH_free(ssh);
        ssh = NULL;
        wolfSSH_CTX_free(ctx);
        ctx = NULL;
    }

    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);
    return result;
}


#if !defined(WOLFSSH_NO_RSA)

/* 2048-bit RSA private key (PKCS#1 DER).
 * Same key as tests/auth.c hanselPrivateRsa - copied here so this
 * test has no dependency on WOLFSSH_KEYGEN. */
static const byte unitTestRsaPrivKey[] = {
  0x30, 0x82, 0x04, 0xa3, 0x02, 0x01, 0x00, 0x02, 0x82, 0x01, 0x01, 0x00,
  0xbd, 0x3f, 0x76, 0x45, 0xa3, 0x03, 0xac, 0x38, 0xd5, 0xc7, 0x0f, 0x93,
  0x30, 0x5a, 0x20, 0x9c, 0x89, 0x7c, 0xad, 0x05, 0x16, 0x46, 0x86, 0x83,
  0x0d, 0x8a, 0x2b, 0x16, 0x4a, 0x05, 0x2c, 0xe4, 0x77, 0x47, 0x70, 0x00,
  0xae, 0x1d, 0x83, 0xe2, 0xd9, 0x6e, 0x99, 0xd4, 0xf0, 0x45, 0x98, 0x15,
  0x93, 0xf6, 0x87, 0x4e, 0xac, 0x64, 0x63, 0xa1, 0x95, 0xc9, 0x7c, 0x30,
  0xe8, 0x3e, 0x2f, 0xa3, 0xf1, 0x24, 0x9f, 0x0c, 0x6b, 0x1c, 0xfe, 0x1b,
  0x02, 0x99, 0xcd, 0xc6, 0xa7, 0x6c, 0x84, 0x85, 0x46, 0x54, 0x12, 0x40,
  0xe1, 0xb4, 0xe5, 0xf2, 0xaa, 0x39, 0xec, 0xd6, 0x27, 0x24, 0x0b, 0xd1,
  0xa1, 0xe2, 0xef, 0x34, 0x69, 0x25, 0x6d, 0xc0, 0x74, 0x67, 0x25, 0x98,
  0x7d, 0xc4, 0xf8, 0x52, 0xab, 0x9b, 0x4b, 0x3a, 0x12, 0x1d, 0xe1, 0xe3,
  0xfa, 0xd6, 0xcf, 0x9a, 0xe6, 0x9c, 0x23, 0x4e, 0x39, 0xc4, 0x84, 0x16,
  0x88, 0x3d, 0x42, 0x4e, 0xd8, 0x2f, 0xcc, 0xd2, 0x91, 0x67, 0x9d, 0xb6,
  0x71, 0x2a, 0x02, 0x65, 0x5f, 0xbb, 0x75, 0x0e, 0x8c, 0xbb, 0x87, 0x97,
  0x97, 0xc6, 0xf8, 0xb2, 0x98, 0xe2, 0x2f, 0x68, 0x26, 0x4a, 0x53, 0xec,
  0x79, 0x3a, 0x8a, 0x5f, 0xcc, 0xcf, 0xf0, 0x16, 0x47, 0xb2, 0xd0, 0x43,
  0xd6, 0x36, 0x6c, 0xc8, 0xe7, 0x2f, 0xfe, 0xa7, 0x35, 0x39, 0x69, 0xfb,
  0x1d, 0x78, 0x45, 0x9d, 0x89, 0x00, 0xc8, 0x41, 0xcf, 0x34, 0x1f, 0xa3,
  0xf3, 0xf1, 0xfb, 0x28, 0x14, 0xfb, 0xd8, 0x48, 0x6f, 0xac, 0xe3, 0xfc,
  0x33, 0xd1, 0xdb, 0xae, 0xef, 0x27, 0x9e, 0x57, 0x56, 0x29, 0xa2, 0x1a,
  0x3a, 0xe5, 0x9a, 0xfe, 0xa4, 0x49, 0xc8, 0x7f, 0xb7, 0x4e, 0xd0, 0x1f,
  0x04, 0x6e, 0x58, 0x16, 0xb7, 0xeb, 0x9d, 0xf8, 0x92, 0x3c, 0xc2, 0xb0,
  0x21, 0x7c, 0x4e, 0x31, 0x02, 0x03, 0x01, 0x00, 0x01, 0x02, 0x82, 0x01,
  0x01, 0x00, 0x8d, 0xa4, 0x61, 0x06, 0x2f, 0xc3, 0x40, 0xf4, 0x6c, 0xf4,
  0x87, 0x30, 0xb8, 0x00, 0xcc, 0xe5, 0xbc, 0x75, 0x87, 0x1e, 0x06, 0x95,
  0x14, 0x7a, 0x23, 0xf9, 0x24, 0xd4, 0x92, 0xe4, 0x1a, 0xbc, 0x88, 0x95,
  0xfc, 0x3b, 0x56, 0x16, 0x1b, 0x2e, 0xff, 0x64, 0x2b, 0x58, 0xd7, 0xd8,
  0x8e, 0xc2, 0x9f, 0xb2, 0xe5, 0x84, 0xb9, 0xbc, 0x8d, 0x61, 0x54, 0x35,
  0xb0, 0x70, 0xfe, 0x72, 0x04, 0xc0, 0x24, 0x6d, 0x2f, 0x69, 0x61, 0x06,
  0x1b, 0x1d, 0xe6, 0x2d, 0x6d, 0x79, 0x60, 0xb7, 0xf4, 0xdb, 0xb7, 0x4e,
  0x97, 0x36, 0xde, 0x77, 0xc1, 0x9f, 0x85, 0x4e, 0xc3, 0x77, 0x69, 0x66,
  0x2e, 0x3e, 0x61, 0x76, 0xf3, 0x67, 0xfb, 0xc6, 0x9a, 0xc5, 0x6f, 0x99,
  0xff, 0xe6, 0x89, 0x43, 0x92, 0x44, 0x75, 0xd2, 0x4e, 0x54, 0x91, 0x58,
  0xb2, 0x48, 0x2a, 0xe6, 0xfa, 0x0d, 0x4a, 0xca, 0xd4, 0x14, 0x9e, 0xf6,
  0x27, 0x67, 0xb7, 0x25, 0x7a, 0x43, 0xbb, 0x2b, 0x67, 0xd1, 0xfe, 0xd1,
  0x68, 0x23, 0x06, 0x30, 0x7c, 0xbf, 0x60, 0x49, 0xde, 0xcc, 0x7e, 0x26,
  0x5a, 0x3b, 0xfe, 0xa6, 0xa6, 0xe7, 0xa8, 0xdd, 0xac, 0xb9, 0xaf, 0x82,
  0x9a, 0x3a, 0x41, 0x7e, 0x61, 0x21, 0x37, 0xa3, 0x08, 0xe4, 0xc4, 0xbc,
  0x11, 0xf5, 0x3b, 0x8e, 0x4d, 0x51, 0xf3, 0xbd, 0xda, 0xba, 0xb2, 0xc5,
  0xee, 0xfb, 0xcf, 0xdf, 0x83, 0xa1, 0x82, 0x01, 0xe1, 0x51, 0x9d, 0x07,
  0x5a, 0x5d, 0xd8, 0xc7, 0x5b, 0x3f, 0x97, 0x13, 0x6a, 0x4d, 0x1e, 0x8d,
  0x39, 0xac, 0x40, 0x95, 0x82, 0x6c, 0xa2, 0xa1, 0xcc, 0x8a, 0x9b, 0x21,
  0x32, 0x3a, 0x58, 0xcc, 0xe7, 0x2d, 0x1a, 0x79, 0xa4, 0x31, 0x50, 0xb1,
  0x4b, 0x76, 0x23, 0x1b, 0xb3, 0x40, 0x3d, 0x3d, 0x72, 0x72, 0x32, 0xec,
  0x5f, 0x38, 0xb5, 0x8d, 0xb2, 0x8d, 0x02, 0x81, 0x81, 0x00, 0xed, 0x5a,
  0x7e, 0x8e, 0xa1, 0x62, 0x7d, 0x26, 0x5c, 0x78, 0xc4, 0x87, 0x71, 0xc9,
  0x41, 0x57, 0x77, 0x94, 0x93, 0x93, 0x26, 0x78, 0xc8, 0xa3, 0x15, 0xbd,
  0x59, 0xcb, 0x1b, 0xb4, 0xb2, 0x6b, 0x0f, 0xe7, 0x80, 0xf2, 0xfa, 0xfc,
  0x8e, 0x32, 0xa9, 0x1b, 0x1e, 0x7f, 0xe1, 0x26, 0xef, 0x00, 0x25, 0xd8,
  0xdd, 0xc9, 0x1a, 0x23, 0x00, 0x26, 0x3b, 0x46, 0x23, 0xc0, 0x50, 0xe7,
  0xce, 0x62, 0xb2, 0x36, 0xb2, 0x98, 0x09, 0x16, 0x34, 0x18, 0x9e, 0x46,
  0xbc, 0xaf, 0x2c, 0x28, 0x94, 0x2f, 0xe0, 0x5d, 0xc9, 0xb2, 0xc8, 0xfb,
  0x5d, 0x13, 0xd5, 0x36, 0xaa, 0x15, 0x0f, 0x89, 0xa5, 0x16, 0x59, 0x5d,
  0x22, 0x74, 0xa4, 0x47, 0x5d, 0xfa, 0xfb, 0x0c, 0x5e, 0x80, 0xbf, 0x0f,
  0xc2, 0x9c, 0x95, 0x0f, 0xe7, 0xaa, 0x7f, 0x16, 0x1b, 0xd4, 0xdb, 0x38,
  0x7d, 0x58, 0x2e, 0x57, 0x78, 0x2f, 0x02, 0x81, 0x81, 0x00, 0xcc, 0x1d,
  0x7f, 0x74, 0x36, 0x6d, 0xb4, 0x92, 0x25, 0x62, 0xc5, 0x50, 0xb0, 0x5c,
  0xa1, 0xda, 0xf3, 0xb2, 0xfd, 0x1e, 0x98, 0x0d, 0x8b, 0x05, 0x69, 0x60,
  0x8e, 0x5e, 0xd2, 0x89, 0x90, 0x4a, 0x0d, 0x46, 0x7e, 0xe2, 0x54, 0x69,
  0xae, 0x16, 0xe6, 0xcb, 0xd5, 0xbd, 0x7b, 0x30, 0x2b, 0x7b, 0x5c, 0xee,
  0x93, 0x12, 0xcf, 0x63, 0x89, 0x9c, 0x3d, 0xc8, 0x2d, 0xe4, 0x7a, 0x61,
  0x09, 0x5e, 0x80, 0xfb, 0x3c, 0x03, 0xb3, 0x73, 0xd6, 0x98, 0xd0, 0x84,
  0x0c, 0x59, 0x9f, 0x4e, 0x80, 0xf3, 0x46, 0xed, 0x03, 0x9d, 0xd5, 0xdc,
  0x8b, 0xe7, 0xb1, 0xe8, 0xaa, 0x57, 0xdc, 0xd1, 0x41, 0x55, 0x07, 0xc7,
  0xdf, 0x67, 0x3c, 0x72, 0x78, 0xb0, 0x60, 0x8f, 0x85, 0xa1, 0x90, 0x99,
  0x0c, 0xa5, 0x67, 0xab, 0xf0, 0xb6, 0x74, 0x90, 0x03, 0x55, 0x7b, 0x5e,
  0xcc, 0xc5, 0xbf, 0xde, 0xa7, 0x9f, 0x02, 0x81, 0x80, 0x40, 0x81, 0x6e,
  0x91, 0xae, 0xd4, 0x88, 0x74, 0xab, 0x7e, 0xfa, 0xd2, 0x60, 0x9f, 0x34,
  0x8d, 0xe3, 0xe6, 0xd2, 0x30, 0x94, 0xad, 0x10, 0xc2, 0x19, 0xbf, 0x6b,
  0x2e, 0xe2, 0xe9, 0xb9, 0xef, 0x94, 0xd3, 0xf2, 0xdc, 0x96, 0x4f, 0x9b,
  0x09, 0xb3, 0xa1, 0xb6, 0x29, 0x44, 0xf4, 0x82, 0xd1, 0xc4, 0x77, 0x6a,
  0xd7, 0x23, 0xae, 0x4d, 0x75, 0x16, 0x78, 0xda, 0x70, 0x82, 0xcc, 0x6c,
  0xef, 0xaf, 0xc5, 0x63, 0xc6, 0x23, 0xfa, 0x0f, 0xd0, 0x7c, 0xfb, 0x76,
  0x7e, 0x18, 0xff, 0x32, 0x3e, 0xcc, 0xb8, 0x50, 0x7f, 0xb1, 0x55, 0x77,
  0x17, 0x53, 0xc3, 0xd6, 0x77, 0x80, 0xd0, 0x84, 0xb8, 0x4d, 0x33, 0x1d,
  0x91, 0x1b, 0xb0, 0x75, 0x9f, 0x27, 0x29, 0x56, 0x69, 0xa1, 0x03, 0x54,
  0x7d, 0x9f, 0x99, 0x41, 0xf9, 0xb9, 0x2e, 0x36, 0x04, 0x24, 0x4b, 0xf6,
  0xec, 0xc7, 0x33, 0x68, 0x6b, 0x02, 0x81, 0x80, 0x60, 0x35, 0xcb, 0x3c,
  0xd0, 0xe6, 0xf7, 0x05, 0x28, 0x20, 0x1d, 0x57, 0x82, 0x39, 0xb7, 0x85,
  0x07, 0xf7, 0xa7, 0x3d, 0xc3, 0x78, 0x26, 0xbe, 0x3f, 0x44, 0x66, 0xf7,
  0x25, 0x0f, 0xf8, 0x76, 0x1f, 0x39, 0xca, 0x57, 0x0e, 0x68, 0xdd, 0xc9,
  0x27, 0xb2, 0x8e, 0xa6, 0x08, 0xa9, 0xd4, 0xe5, 0x0a, 0x11, 0xde, 0x3b,
  0x30, 0x8b, 0xff, 0x72, 0x28, 0xe0, 0xf1, 0x58, 0xcf, 0xa2, 0x6b, 0x93,
  0x23, 0x02, 0xc8, 0xf0, 0x09, 0xa7, 0x21, 0x50, 0xd8, 0x80, 0x55, 0x7d,
  0xed, 0x0c, 0x48, 0xd5, 0xe2, 0xe9, 0x97, 0x19, 0xcf, 0x93, 0x6c, 0x52,
  0xa2, 0xd6, 0x43, 0x6c, 0xb4, 0xc5, 0xe1, 0xa0, 0x9d, 0xd1, 0x45, 0x69,
  0x58, 0xe1, 0xb0, 0x27, 0x9a, 0xec, 0x2b, 0x95, 0xd3, 0x1d, 0x81, 0x0b,
  0x7a, 0x09, 0x5e, 0xa5, 0xf1, 0xdd, 0x6b, 0xe4, 0xe0, 0x08, 0xf8, 0x46,
  0x81, 0xc1, 0x06, 0x8b, 0x02, 0x81, 0x80, 0x00, 0xf6, 0xf2, 0xeb, 0x25,
  0xba, 0x78, 0x04, 0xad, 0x0e, 0x0d, 0x2e, 0xa7, 0x69, 0xd6, 0x57, 0xe6,
  0x36, 0x32, 0x50, 0xd2, 0xf2, 0xeb, 0xad, 0x31, 0x46, 0x65, 0xc0, 0x07,
  0x97, 0x83, 0x6c, 0x66, 0x27, 0x3e, 0x94, 0x2c, 0x05, 0x01, 0x5f, 0x5c,
  0xe0, 0x31, 0x30, 0xec, 0x61, 0xd2, 0x74, 0x35, 0xb7, 0x9f, 0x38, 0xe7,
  0x8e, 0x67, 0xb1, 0x50, 0x08, 0x68, 0xce, 0xcf, 0xd8, 0xee, 0x88, 0xfd,
  0x5d, 0xc4, 0xcd, 0xe2, 0x86, 0x3d, 0x4a, 0x0e, 0x04, 0x7f, 0xee, 0x8a,
  0xe8, 0x9b, 0x16, 0xa1, 0xfc, 0x09, 0x82, 0xe2, 0x62, 0x03, 0x3c, 0xe8,
  0x25, 0x7f, 0x3c, 0x9a, 0xaa, 0x83, 0xf8, 0xd8, 0x93, 0xd1, 0x54, 0xf9,
  0xce, 0xb4, 0xfa, 0x35, 0x36, 0xcc, 0x18, 0x54, 0xaa, 0xf2, 0x90, 0xb7,
  0x7c, 0x97, 0x0b, 0x27, 0x2f, 0xae, 0xfc, 0xc3, 0x93, 0xaf, 0x1a, 0x75,
  0xec, 0x18, 0xdb
};
static const word32 unitTestRsaPrivKeySz =
        (word32)sizeof(unitTestRsaPrivKey);
#endif /* WOLFSSH_NO_RSA */

/* Keys for test_IdentifyAsn1Key: inline DER so the test is self-contained
 * in both filesystem and NO_FILESYSTEM builds.  Each array matches the
 * corresponding file under keys/. */
#ifndef WOLFSSH_NO_ECDSA_SHA2_NISTP256
/* keys/server-key-ecc.der - P-256 RFC-5915 ECPrivateKey */
static const byte unitTestEcc256PrivKey[] = {
    0x30, 0x77, 0x02, 0x01, 0x01, 0x04, 0x20, 0x61, 0x09, 0x99,
    0x0B, 0x79, 0xD2, 0x5F, 0x28, 0x5A, 0x0F, 0x5D, 0x15, 0xCC,
    0xA1, 0x56, 0x54, 0xF9, 0x2B, 0x39, 0x87, 0x21, 0x2D, 0xA7,
    0x7D, 0x85, 0x7B, 0xB8, 0x7F, 0x38, 0xC6, 0x6D, 0xD5, 0xA0,
    0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01,
    0x07, 0xA1, 0x44, 0x03, 0x42, 0x00, 0x04, 0x81, 0x13, 0xFF,
    0xA4, 0x2B, 0xB7, 0x9C, 0x45, 0x74, 0x7A, 0x83, 0x4C, 0x61,
    0xF3, 0x3F, 0xAD, 0x26, 0xCF, 0x22, 0xCD, 0xA9, 0xA3, 0xBC,
    0xA5, 0x61, 0xB4, 0x7C, 0xE6, 0x62, 0xD4, 0xC2, 0xF7, 0x55,
    0x43, 0x9A, 0x31, 0xFB, 0x80, 0x11, 0x20, 0xB5, 0x12, 0x4B,
    0x24, 0xF5, 0x78, 0xD7, 0xFD, 0x22, 0xEF, 0x46, 0x35, 0xF0,
    0x05, 0x58, 0x6B, 0x5F, 0x63, 0xC8, 0xDA, 0x1B, 0xC4, 0xF5,
    0x69
};
#endif /* WOLFSSH_NO_ECDSA_SHA2_NISTP256 */

#ifndef WOLFSSH_NO_ECDSA_SHA2_NISTP384
/* keys/server-key-ecc-384.der - P-384 RFC-5915 ECPrivateKey */
static const byte unitTestEcc384PrivKey[] = {
    0x30, 0x81, 0xA4, 0x02, 0x01, 0x01, 0x04, 0x30, 0x3E, 0xAD,
    0xD2, 0xBB, 0xBF, 0x05, 0xA7, 0xBE, 0x3A, 0x3F, 0x7C, 0x28,
    0x15, 0x12, 0x89, 0xDE, 0x5B, 0xB3, 0x64, 0x4D, 0x70, 0x11,
    0x76, 0x1D, 0xB5, 0x6F, 0x2A, 0x03, 0x62, 0xFB, 0xA6, 0x4F,
    0x98, 0xE6, 0x4F, 0xF9, 0x86, 0xDC, 0x4F, 0xB8, 0xEF, 0xDB,
    0x2D, 0x6B, 0x8D, 0xA5, 0x71, 0x42, 0xA0, 0x07, 0x06, 0x05,
    0x2B, 0x81, 0x04, 0x00, 0x22, 0xA1, 0x64, 0x03, 0x62, 0x00,
    0x04, 0x38, 0xD6, 0x2B, 0xE4, 0x18, 0xFF, 0x57, 0x3F, 0xD0,
    0xE0, 0x20, 0xD4, 0x88, 0x76, 0xC4, 0xE1, 0x12, 0x1D, 0xFB,
    0x2D, 0x6E, 0xBE, 0xE4, 0x89, 0x5D, 0x77, 0x24, 0x31, 0x6D,
    0x46, 0xA2, 0x31, 0x05, 0x87, 0x3F, 0x29, 0x86, 0xD5, 0xC7,
    0x12, 0x80, 0x3A, 0x6F, 0x47, 0x1A, 0xB8, 0x68, 0x50, 0xEB,
    0x06, 0x3E, 0x10, 0x89, 0x61, 0x34, 0x9C, 0xF8, 0xB4, 0xC6,
    0xA4, 0xCF, 0x5E, 0x97, 0xBD, 0x7E, 0x51, 0xE9, 0x75, 0xE3,
    0xE9, 0x21, 0x72, 0x61, 0x50, 0x6E, 0xB9, 0xCF, 0x3C, 0x49,
    0x3D, 0x3E, 0xB8, 0x8D, 0x46, 0x7B, 0x5F, 0x27, 0xEB, 0xAB,
    0x21, 0x61, 0xC0, 0x00, 0x66, 0xFE, 0xBD
};
#endif /* WOLFSSH_NO_ECDSA_SHA2_NISTP384 */

#ifndef WOLFSSH_NO_ECDSA_SHA2_NISTP521
/* keys/server-key-ecc-521.der - P-521 RFC-5915 ECPrivateKey */
static const byte unitTestEcc521PrivKey[] = {
    0x30, 0x81, 0xDC, 0x02, 0x01, 0x01, 0x04, 0x42, 0x00, 0x4C,
    0xA4, 0xD8, 0x64, 0x28, 0xD9, 0x40, 0x0E, 0x7B, 0x2D, 0xF3,
    0x91, 0x2E, 0xB9, 0x96, 0xC1, 0x95, 0x89, 0x50, 0x43, 0xAF,
    0x92, 0xE8, 0x6D, 0xE7, 0x0A, 0xE4, 0xDF, 0x46, 0xF2, 0x2A,
    0x29, 0x1A, 0x6B, 0xB2, 0x74, 0x8A, 0xAE, 0x82, 0x58, 0x0D,
    0xF6, 0xC3, 0x9F, 0x49, 0xB3, 0xED, 0x82, 0xF1, 0x78, 0x9E,
    0xCE, 0x1B, 0x65, 0x7D, 0x45, 0x43, 0x8C, 0xFF, 0x15, 0x65,
    0x34, 0x35, 0x45, 0x75, 0xA0, 0x07, 0x06, 0x05, 0x2B, 0x81,
    0x04, 0x00, 0x23, 0xA1, 0x81, 0x89, 0x03, 0x81, 0x86, 0x00,
    0x04, 0x01, 0xF8, 0xD0, 0xA7, 0xC3, 0xC5, 0x8D, 0x84, 0x19,
    0x57, 0x96, 0x9F, 0x21, 0x3A, 0x94, 0xF3, 0xDA, 0x55, 0x0E,
    0xDF, 0x76, 0xD8, 0xDD, 0x17, 0x15, 0x31, 0xF3, 0x5B, 0xB0,
    0x69, 0xC8, 0xBC, 0x30, 0x0D, 0x6F, 0x6B, 0x37, 0xD1, 0x80,
    0x46, 0xA9, 0x71, 0x7F, 0x2C, 0x6F, 0x59, 0x51, 0x9C, 0x82,
    0x70, 0x95, 0xB2, 0x9A, 0x63, 0x13, 0x30, 0x62, 0x18, 0xC2,
    0x35, 0x76, 0x94, 0x00, 0xD0, 0xF9, 0x6D, 0x00, 0x0A, 0x19,
    0x3B, 0xA3, 0x46, 0x65, 0x2B, 0xEB, 0x40, 0x9A, 0x9A, 0x45,
    0xC5, 0x97, 0xA3, 0xED, 0x93, 0x2D, 0xD5, 0xAA, 0xAE, 0x96,
    0xBF, 0x2F, 0x31, 0x7E, 0x5A, 0x7A, 0xC7, 0x45, 0x8B, 0x3C,
    0x6C, 0xDB, 0xAA, 0x90, 0xC3, 0x55, 0x38, 0x2C, 0xDF, 0xCD,
    0xCA, 0x73, 0x77, 0xD9, 0x2E, 0xB2, 0x0A, 0x5E, 0x8C, 0x74,
    0x23, 0x7C, 0xA5, 0xA3, 0x45, 0xB1, 0x9E, 0x3F, 0x1A, 0x22,
    0x90, 0xB1, 0x54
};
#endif /* WOLFSSH_NO_ECDSA_SHA2_NISTP521 */

#if !defined(WOLFSSH_NO_ED25519)
/* keys/server-key-ed25519.der - Ed25519 OneAsymmetricKey (RFC 8410) */
static const byte unitTestEd25519PrivKey[] = {
    0x30, 0x50, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b,
    0x65, 0x70, 0x04, 0x22, 0x04, 0x20, 0x6a, 0x67, 0xf3, 0x0e,
    0x64, 0xea, 0x52, 0xfe, 0xf4, 0xad, 0x65, 0x4d, 0x45, 0x60,
    0x61, 0x38, 0x58, 0x11, 0x07, 0x84, 0xf0, 0x03, 0x94, 0x93,
    0x14, 0x7b, 0x7b, 0x33, 0x1a, 0xba, 0xf6, 0x19, 0x81, 0x20,
    0x0f, 0x56, 0x0c, 0x9f, 0x7d, 0x7a, 0x62, 0x87, 0xf0, 0x26,
    0x16, 0x19, 0x31, 0xe4, 0xb2, 0x1d, 0xe9, 0xbd, 0xee, 0x4a,
    0x7f, 0x55, 0xae, 0x26, 0x2d, 0xa1, 0x25, 0xe4, 0xee, 0x4a,
    0x51, 0x00
};
#endif /* !WOLFSSH_NO_ED25519 */

#if !defined(WOLFSSH_NO_MLDSA)
/* keys/server-key-mldsa44.der - MlDsa44 OneAsymmetricKey */
static const byte unitTestMlDsaPrivKey[] = {
    0x30, 0x82, 0x0a, 0x3e, 0x02, 0x01, 0x00, 0x30,
    0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65,
    0x03, 0x04, 0x03, 0x11, 0x04, 0x82, 0x0a, 0x2a,
    0x30, 0x82, 0x0a, 0x26, 0x04, 0x20, 0x07, 0x99,
    0x36, 0x30, 0xd1, 0xef, 0x77, 0x3e, 0x75, 0x79,
    0xbc, 0x3f, 0xb5, 0x78, 0xfa, 0x10, 0x26, 0x77,
    0x79, 0x27, 0x19, 0x34, 0xf7, 0x68, 0x83, 0xce,
    0x08, 0xb6, 0xbb, 0xe9, 0x06, 0x18, 0x04, 0x82,
    0x0a, 0x00, 0x9d, 0x7b, 0x66, 0x85, 0x9a, 0xb3,
    0xcb, 0xdf, 0x19, 0xc5, 0xaa, 0xe2, 0xac, 0x2a,
    0x79, 0xaf, 0xf1, 0xfd, 0xe2, 0xb8, 0x8d, 0x91,
    0xda, 0xf5, 0x8e, 0x86, 0xb4, 0x91, 0x3c, 0x15,
    0x2a, 0x12, 0xc6, 0x98, 0x49, 0x63, 0xed, 0x50,
    0xcb, 0x79, 0x0d, 0x58, 0x43, 0xf2, 0x00, 0x8e,
    0x35, 0x5f, 0x25, 0x2f, 0x3c, 0xcb, 0xab, 0xd9,
    0x04, 0x85, 0x20, 0x1d, 0x5e, 0x55, 0x88, 0x94,
    0x64, 0x37, 0x4f, 0xd3, 0x64, 0x89, 0xbe, 0xe2,
    0xcb, 0xdc, 0x96, 0xcc, 0x62, 0x99, 0x56, 0xde,
    0x26, 0x8c, 0xde, 0x30, 0x18, 0x66, 0xf9, 0xd9,
    0x1b, 0xf1, 0xcf, 0x32, 0xc5, 0x78, 0x48, 0x02,
    0x04, 0xb2, 0x3b, 0x16, 0x3d, 0xe9, 0xa8, 0x6c,
    0x81, 0x06, 0x9f, 0xf4, 0x69, 0x77, 0x7e, 0x86,
    0x34, 0xa5, 0xdd, 0xb1, 0x49, 0x20, 0xe0, 0x2f,
    0x17, 0x2b, 0xdc, 0x62, 0xf9, 0x93, 0x5e, 0x17,
    0x51, 0x38, 0x4a, 0x82, 0x08, 0x48, 0x06, 0x24,
    0x08, 0x48, 0x60, 0x92, 0xb4, 0x51, 0x13, 0x05,
    0x28, 0x1a, 0xb8, 0x8d, 0x89, 0xb4, 0x28, 0x90,
    0xa8, 0x64, 0x0c, 0x81, 0x44, 0xe3, 0xc6, 0x89,
    0x84, 0x16, 0x0e, 0x44, 0x02, 0x40, 0x0b, 0x97,
    0x2d, 0xd9, 0x48, 0x92, 0x01, 0x15, 0x64, 0x42,
    0x38, 0x68, 0x1a, 0x27, 0x8e, 0x13, 0x13, 0x52,
    0x00, 0x31, 0x02, 0xc4, 0x02, 0x26, 0x14, 0x42,
    0x4d, 0x10, 0x28, 0x90, 0x20, 0x31, 0x32, 0x01,
    0xc1, 0x60, 0x0b, 0x01, 0x6c, 0x80, 0x00, 0x6c,
    0x63, 0x26, 0x50, 0x02, 0x80, 0x45, 0x4a, 0xa6,
    0x40, 0x1c, 0xb2, 0x25, 0x08, 0x21, 0x62, 0x24,
    0x49, 0x4e, 0x21, 0x87, 0x48, 0x1b, 0x48, 0x02,
    0x1c, 0x86, 0x64, 0x04, 0xa2, 0x90, 0xda, 0xb0,
    0x89, 0x14, 0x19, 0x4e, 0x49, 0x26, 0x05, 0x18,
    0xc9, 0x00, 0x9a, 0xa4, 0x85, 0xdc, 0xa4, 0x48,
    0x41, 0x22, 0x81, 0x02, 0x35, 0x70, 0x63, 0x26,
    0x8a, 0xd4, 0x10, 0x61, 0x20, 0x44, 0x88, 0xa3,
    0xa2, 0x60, 0x02, 0xa2, 0x81, 0x19, 0xb4, 0x70,
    0x9c, 0x16, 0x84, 0x81, 0x02, 0x41, 0x22, 0xb5,
    0x91, 0xd2, 0x08, 0x51, 0x12, 0x34, 0x41, 0xd3,
    0xb8, 0x11, 0x08, 0x21, 0x32, 0x42, 0x44, 0x65,
    0x00, 0x48, 0x69, 0x92, 0x46, 0x12, 0x22, 0x94,
    0x61, 0xc2, 0xb6, 0x70, 0xe2, 0x98, 0x8d, 0xd3,
    0x26, 0x09, 0x84, 0x22, 0x0a, 0x09, 0xb9, 0x0d,
    0x4c, 0xb0, 0x64, 0x03, 0x24, 0x2e, 0x01, 0x96,
    0x84, 0x99, 0x04, 0x11, 0x9b, 0xc8, 0x11, 0xa3,
    0x12, 0x90, 0x0c, 0x16, 0x0a, 0x8c, 0x20, 0x2c,
    0x94, 0x08, 0x46, 0x04, 0xb6, 0x0d, 0x60, 0xb0,
    0x88, 0xdc, 0x04, 0x22, 0x9a, 0x46, 0x42, 0x21,
    0x42, 0x4d, 0x49, 0x46, 0x29, 0x24, 0x27, 0x62,
    0x13, 0x25, 0x05, 0x0a, 0x84, 0x05, 0x4a, 0x10,
    0x46, 0xa4, 0x06, 0x80, 0x1c, 0x34, 0x82, 0x1a,
    0xa5, 0x4c, 0x19, 0x96, 0x89, 0x24, 0x26, 0x61,
    0x10, 0x46, 0x8c, 0xc1, 0x18, 0x48, 0x1c, 0x19,
    0x6d, 0x04, 0x98, 0x8d, 0x8b, 0x46, 0x02, 0x02,
    0x90, 0x0d, 0x5c, 0x12, 0x65, 0x4a, 0x14, 0x72,
    0x02, 0xc1, 0x65, 0x1b, 0x21, 0x4d, 0x5c, 0x38,
    0x6d, 0x03, 0x41, 0x8c, 0xa4, 0x26, 0x0e, 0x89,
    0xa2, 0x80, 0x4a, 0x40, 0x26, 0x1c, 0x99, 0x69,
    0x81, 0x12, 0x30, 0xc3, 0x40, 0x21, 0x22, 0x46,
    0x61, 0x22, 0x43, 0x72, 0x02, 0x47, 0x26, 0x10,
    0xa1, 0x09, 0x81, 0x22, 0x06, 0xc3, 0x22, 0x2e,
    0x64, 0x32, 0x12, 0x01, 0xb2, 0x01, 0x59, 0x96,
    0x45, 0x04, 0x35, 0x08, 0xc3, 0xb6, 0x8d, 0x14,
    0x30, 0x6c, 0x0c, 0x95, 0x0c, 0xa3, 0x48, 0x80,
    0x63, 0x40, 0x50, 0x00, 0x20, 0x26, 0xdc, 0x20,
    0x24, 0x01, 0x46, 0x71, 0xe1, 0x40, 0x51, 0xc2,
    0x12, 0x0d, 0xc4, 0x10, 0x40, 0x0c, 0x43, 0x24,
    0x02, 0x33, 0x26, 0x02, 0xc8, 0x04, 0x1a, 0x23,
    0x08, 0xe0, 0x16, 0x8a, 0x9a, 0xb0, 0x2d, 0x13,
    0x40, 0x08, 0x43, 0x22, 0x32, 0x44, 0x38, 0x6d,
    0xd1, 0x44, 0x90, 0xd4, 0x86, 0x09, 0x48, 0x82,
    0x00, 0xe2, 0x98, 0x68, 0x12, 0xb1, 0x91, 0x09,
    0x90, 0x6d, 0xc9, 0x30, 0x85, 0xc0, 0x84, 0x80,
    0x9c, 0xc6, 0x4c, 0xe1, 0x10, 0x91, 0xd8, 0x96,
    0x30, 0xda, 0xb6, 0x68, 0xc8, 0xc6, 0x65, 0xe3,
    0x06, 0x50, 0x5c, 0x14, 0x11, 0x02, 0x44, 0x49,
    0x9b, 0xa2, 0x68, 0x5a, 0x32, 0x90, 0x52, 0x80,
    0x45, 0x00, 0x26, 0x30, 0x02, 0x46, 0x4c, 0xd4,
    0xc8, 0x49, 0x9c, 0xb8, 0x90, 0xc4, 0x20, 0x8a,
    0x0c, 0x15, 0x0d, 0x09, 0x37, 0x8e, 0x12, 0x46,
    0x45, 0x08, 0x23, 0x25, 0x21, 0xa1, 0x11, 0x80,
    0x90, 0x65, 0x93, 0x46, 0x72, 0xe1, 0x28, 0x6d,
    0x44, 0x96, 0x51, 0x81, 0x12, 0x80, 0x04, 0x46,
    0x4a, 0x8b, 0x10, 0x6d, 0x13, 0x46, 0x51, 0x53,
    0x36, 0x4a, 0xe1, 0xa6, 0x45, 0xe0, 0x22, 0x01,
    0x48, 0xa6, 0x00, 0x12, 0x91, 0x70, 0x23, 0xb3,
    0x40, 0x02, 0xa8, 0x65, 0xdb, 0x42, 0x06, 0xe0,
    0x06, 0x6a, 0xe3, 0x96, 0x61, 0x48, 0x94, 0x65,
    0x43, 0x22, 0x69, 0xdc, 0x22, 0x85, 0x9b, 0x84,
    0x89, 0x59, 0x18, 0x64, 0x43, 0xb0, 0x20, 0x8b,
    0xa8, 0x29, 0x58, 0x30, 0x24, 0x0a, 0x17, 0x8e,
    0x11, 0x41, 0x2d, 0x24, 0xb8, 0x25, 0x89, 0x14,
    0x20, 0x14, 0x41, 0x91, 0x23, 0xa2, 0x24, 0x21,
    0x17, 0x21, 0x11, 0xb1, 0x04, 0x03, 0x84, 0x4c,
    0x0b, 0x23, 0x62, 0x50, 0x86, 0x65, 0x54, 0x22,
    0x42, 0x42, 0x82, 0x80, 0x08, 0xa5, 0x51, 0xd9,
    0x06, 0x31, 0x23, 0x00, 0x91, 0x10, 0xa9, 0x4d,
    0xe2, 0x04, 0x66, 0x44, 0x36, 0x30, 0x8b, 0xb2,
    0x49, 0x98, 0xc6, 0x70, 0x19, 0xa4, 0x8c, 0x5a,
    0xa6, 0x0d, 0x63, 0x00, 0x2e, 0x9b, 0x94, 0x70,
    0x8a, 0x20, 0x2d, 0x62, 0x26, 0x2c, 0x42, 0x26,
    0x6c, 0x12, 0x13, 0x2e, 0xdb, 0x18, 0x08, 0x11,
    0x21, 0x2e, 0x8a, 0xb0, 0x71, 0x01, 0xc1, 0x2c,
    0xe3, 0x44, 0x62, 0xe3, 0x94, 0x28, 0x0b, 0x38,
    0x70, 0x40, 0x14, 0x65, 0x62, 0xc0, 0x41, 0xa1,
    0x06, 0x21, 0x82, 0xa2, 0x44, 0x94, 0xb0, 0x2c,
    0x21, 0x10, 0x8d, 0x14, 0x96, 0x71, 0x12, 0x14,
    0x05, 0x11, 0x27, 0x04, 0x12, 0x97, 0x65, 0xc4,
    0x02, 0x6e, 0x58, 0xc4, 0x6c, 0xc0, 0x10, 0x70,
    0x84, 0xc0, 0x45, 0x99, 0x12, 0x52, 0x80, 0xa8,
    0x88, 0xd3, 0xb8, 0x28, 0x01, 0x17, 0x70, 0x03,
    0xc3, 0x10, 0x88, 0x18, 0x0a, 0x53, 0x92, 0x40,
    0x53, 0xc6, 0x20, 0x93, 0xc0, 0x81, 0xa4, 0x90,
    0x90, 0x93, 0x92, 0x05, 0x22, 0x88, 0x08, 0xc8,
    0x00, 0x64, 0xf0, 0x19, 0xcf, 0xdf, 0x37, 0x19,
    0x32, 0xc9, 0xaf, 0x0a, 0x3c, 0x4a, 0x8f, 0x9c,
    0xb3, 0xb4, 0x4a, 0x29, 0x5c, 0x6d, 0xd2, 0x81,
    0x10, 0x3f, 0x9f, 0x4d, 0x23, 0x18, 0x65, 0xee,
    0x03, 0xa7, 0xeb, 0x14, 0x99, 0xc0, 0xab, 0x6c,
    0x2e, 0xad, 0x31, 0xa0, 0x15, 0x7f, 0xfd, 0x12,
    0xc3, 0x0b, 0x86, 0x8d, 0x1d, 0x0f, 0x19, 0x8e,
    0x2c, 0xdd, 0xc1, 0xce, 0xf2, 0x75, 0xc2, 0x3f,
    0xff, 0xc3, 0xbc, 0x7d, 0x5c, 0x40, 0x50, 0x81,
    0xd5, 0x92, 0xc9, 0xdc, 0x89, 0x56, 0x00, 0x04,
    0x64, 0x66, 0x27, 0xa9, 0xc0, 0x43, 0xcd, 0x5d,
    0xd6, 0xe6, 0xc7, 0x84, 0xa8, 0xf0, 0x02, 0xda,
    0xa3, 0xf2, 0xd7, 0x27, 0xac, 0x52, 0x30, 0xb3,
    0x95, 0x53, 0x34, 0x31, 0x1f, 0x06, 0xf2, 0x74,
    0xba, 0x58, 0x52, 0xcf, 0xb9, 0x0b, 0xd1, 0x39,
    0x3e, 0x60, 0xfe, 0xd9, 0x55, 0x72, 0xfb, 0xd9,
    0x5c, 0x2d, 0x9e, 0x5f, 0x5d, 0x95, 0xe3, 0xf8,
    0x25, 0x6d, 0x14, 0x70, 0x24, 0xf8, 0x15, 0x04,
    0x24, 0x14, 0x15, 0xab, 0xa5, 0x33, 0xc9, 0xe0,
    0xfd, 0x9c, 0xb3, 0x3d, 0x57, 0xef, 0xf4, 0xe2,
    0x87, 0x21, 0x9b, 0xd4, 0x27, 0x3e, 0x6e, 0x7b,
    0x23, 0x9e, 0x56, 0x7c, 0x67, 0xd2, 0x39, 0xea,
    0x52, 0xb5, 0xbd, 0x6d, 0xda, 0x00, 0xc7, 0x1e,
    0x0a, 0xee, 0x6d, 0x16, 0xfb, 0x9a, 0x34, 0xae,
    0x8b, 0x85, 0x7b, 0x69, 0x9a, 0x98, 0xd6, 0x15,
    0x26, 0x19, 0x4f, 0x09, 0xbd, 0xe0, 0x06, 0x79,
    0x93, 0x2c, 0x9e, 0xaa, 0x87, 0x3c, 0xc6, 0xab,
    0xca, 0x07, 0x98, 0xa9, 0xb4, 0x63, 0x90, 0x78,
    0x13, 0x28, 0xdc, 0x62, 0xf3, 0x04, 0x04, 0xd5,
    0x55, 0x8a, 0x91, 0xfb, 0x8b, 0xdc, 0x1d, 0x6a,
    0x53, 0x16, 0xde, 0x19, 0x88, 0xe7, 0x96, 0xfc,
    0xb1, 0xb5, 0x11, 0xe7, 0x91, 0x4e, 0x62, 0xc6,
    0xa4, 0xb8, 0xab, 0x08, 0x7f, 0x75, 0x06, 0x45,
    0x0b, 0x54, 0x63, 0x78, 0x7d, 0x0a, 0x84, 0x64,
    0x96, 0xa3, 0x9d, 0x44, 0x73, 0xf6, 0x16, 0x74,
    0x46, 0x35, 0x10, 0xa2, 0x9c, 0xbe, 0x5b, 0xc0,
    0xe1, 0x5e, 0xc4, 0xa8, 0x24, 0xab, 0xe1, 0xc2,
    0x59, 0x52, 0x16, 0xd8, 0xc9, 0xb6, 0x3e, 0x58,
    0xad, 0xfb, 0xc8, 0x36, 0x65, 0x7e, 0xf1, 0x8e,
    0x4f, 0x91, 0xc8, 0xe2, 0xf3, 0xa7, 0xd3, 0x28,
    0xab, 0x62, 0x21, 0x96, 0x96, 0x31, 0xef, 0xa1,
    0xaf, 0xe9, 0x2e, 0x36, 0xfe, 0x09, 0xeb, 0xf1,
    0x8d, 0xfa, 0xfb, 0x58, 0x39, 0xa3, 0xce, 0x45,
    0xe4, 0x1f, 0xdd, 0x8c, 0x24, 0xa9, 0xd7, 0x33,
    0x80, 0xf5, 0xbb, 0x05, 0x11, 0x52, 0xcb, 0xbc,
    0xb3, 0x09, 0x14, 0x2e, 0x0a, 0xdd, 0x44, 0xe4,
    0x2f, 0x85, 0x84, 0x4e, 0x09, 0xda, 0x0b, 0x20,
    0x78, 0x61, 0x2a, 0xb9, 0x67, 0x9c, 0x84, 0xe0,
    0xeb, 0xbb, 0x95, 0xd0, 0x31, 0x5d, 0x83, 0x91,
    0x15, 0xbf, 0x27, 0xf5, 0x1e, 0x25, 0xc9, 0xc5,
    0x48, 0xa8, 0xaa, 0x8c, 0xfc, 0xea, 0x60, 0x7a,
    0xcd, 0x97, 0x92, 0xab, 0x07, 0xc7, 0x9e, 0x0b,
    0x54, 0xbc, 0x41, 0xdc, 0x7f, 0xf7, 0x89, 0x72,
    0x12, 0xee, 0x85, 0x18, 0x86, 0x1b, 0xe0, 0x44,
    0xe1, 0x4f, 0x7b, 0x75, 0x3d, 0x27, 0xf7, 0x82,
    0xee, 0x38, 0xf7, 0x61, 0xe3, 0xc9, 0xa5, 0xdb,
    0x59, 0xff, 0x20, 0x0d, 0x7c, 0xb8, 0xd2, 0x2c,
    0xec, 0x88, 0x5d, 0xc4, 0x03, 0x08, 0x67, 0xb4,
    0x72, 0x3b, 0x5c, 0xc6, 0x16, 0xab, 0x1a, 0x6b,
    0x72, 0x99, 0x87, 0x80, 0xa7, 0x35, 0x5a, 0xb9,
    0x91, 0x4e, 0x5c, 0x7a, 0xc6, 0x94, 0x18, 0xd2,
    0xe5, 0x97, 0x7c, 0xd5, 0x91, 0x5d, 0x57, 0x56,
    0xe9, 0xff, 0x5a, 0x64, 0xf9, 0xc8, 0xff, 0x2a,
    0x5a, 0xba, 0xce, 0x0d, 0xcf, 0x67, 0x09, 0xb1,
    0x2d, 0x63, 0xc5, 0x72, 0x78, 0xc7, 0x4f, 0xc1,
    0xc0, 0x23, 0x42, 0xaf, 0xf2, 0xb8, 0x2f, 0x79,
    0xb7, 0xf7, 0x5d, 0xa5, 0xba, 0xd5, 0x0f, 0xa8,
    0x9b, 0xf2, 0xaf, 0x5d, 0x72, 0x92, 0x86, 0xce,
    0x10, 0x52, 0xd3, 0xdd, 0x15, 0x15, 0x65, 0xa8,
    0x38, 0xc2, 0x98, 0x27, 0x47, 0x4e, 0xb1, 0xde,
    0x05, 0x8b, 0xd9, 0x36, 0xd7, 0x0f, 0xf5, 0x33,
    0x6e, 0x4c, 0x9c, 0x49, 0x7d, 0x8e, 0x07, 0x79,
    0x77, 0x14, 0x8a, 0xea, 0x3b, 0x86, 0xc4, 0xaf,
    0xf9, 0x4c, 0x8f, 0x43, 0x26, 0xbf, 0xa4, 0x68,
    0xf4, 0xb3, 0xe7, 0xd2, 0x03, 0xc4, 0x85, 0x1c,
    0xd5, 0x0a, 0x18, 0x55, 0x51, 0xfe, 0xb1, 0x5b,
    0x8e, 0x79, 0xed, 0x07, 0x87, 0x7d, 0xba, 0xd4,
    0x09, 0x98, 0x93, 0xcb, 0xa9, 0x4f, 0x31, 0xce,
    0xe2, 0xab, 0x3a, 0xf2, 0x6d, 0x3a, 0xeb, 0x4f,
    0x2c, 0x1a, 0x6b, 0xf2, 0xff, 0x81, 0xfa, 0xf4,
    0x34, 0xbe, 0xb5, 0x4e, 0x1a, 0xea, 0xf2, 0x10,
    0x7b, 0x3e, 0x96, 0xcf, 0x67, 0x37, 0xd8, 0xae,
    0xf0, 0x3d, 0x03, 0xa8, 0xe6, 0x93, 0x1d, 0x59,
    0xbc, 0x1a, 0x06, 0xb4, 0x1c, 0x0d, 0x68, 0xf2,
    0xbe, 0x27, 0x58, 0x1a, 0x66, 0x92, 0xca, 0x37,
    0x63, 0x67, 0x2a, 0x59, 0x62, 0xbd, 0x40, 0xd5,
    0xe9, 0xd9, 0x4a, 0x49, 0x69, 0x8c, 0x4c, 0xf4,
    0x65, 0x85, 0x34, 0xcc, 0x37, 0xd0, 0x5e, 0x3e,
    0x65, 0x8a, 0x73, 0x6b, 0x32, 0xd2, 0xfa, 0x6c,
    0x54, 0x94, 0xb7, 0x20, 0x75, 0x6e, 0x4a, 0xc9,
    0xf8, 0x72, 0xc8, 0xdc, 0xda, 0x09, 0xca, 0xe3,
    0x94, 0x9b, 0xf8, 0xeb, 0xe8, 0x32, 0xbe, 0xbb,
    0x41, 0x68, 0xb6, 0x01, 0x8d, 0xe9, 0x9f, 0xd3,
    0x7f, 0xfd, 0x91, 0xe2, 0x2b, 0xc0, 0x4e, 0xf9,
    0x42, 0x5b, 0xa2, 0xec, 0xc8, 0x35, 0x0f, 0x36,
    0xd9, 0xd1, 0x88, 0x65, 0xa2, 0x2a, 0xea, 0x50,
    0x99, 0x19, 0x50, 0x31, 0x24, 0x10, 0x7b, 0x56,
    0x67, 0xa4, 0xa5, 0xca, 0xe3, 0xa5, 0xc9, 0x77,
    0xb4, 0xd1, 0x8a, 0xdc, 0xa4, 0xff, 0xca, 0xee,
    0xd8, 0x58, 0x3e, 0x6d, 0xa5, 0xd4, 0xb3, 0x39,
    0x15, 0xa2, 0xcb, 0x02, 0x9c, 0xfe, 0x93, 0x66,
    0x18, 0xd8, 0xd2, 0xce, 0xb2, 0x8d, 0x4d, 0x28,
    0x62, 0xc4, 0x7b, 0x39, 0xe2, 0x2a, 0x02, 0x6e,
    0x38, 0x59, 0xcc, 0x35, 0xda, 0x99, 0xb2, 0xc1,
    0x93, 0x24, 0xb6, 0x63, 0xa8, 0xfe, 0x37, 0x91,
    0x32, 0x78, 0x11, 0xf9, 0x95, 0x72, 0x2d, 0xd1,
    0x51, 0x40, 0x13, 0x90, 0xfa, 0xa7, 0x3d, 0x5d,
    0xfa, 0xce, 0xc1, 0x3d, 0xd4, 0xab, 0xb7, 0x4b,
    0x8c, 0xd1, 0xd9, 0x45, 0xc6, 0x7e, 0x0c, 0xc6,
    0xbc, 0xdd, 0x11, 0xfa, 0x52, 0x83, 0x59, 0x2d,
    0xa7, 0xa8, 0xae, 0x3f, 0xb8, 0x58, 0xa2, 0x84,
    0x14, 0x05, 0x77, 0xf9, 0xb9, 0xfe, 0x05, 0xd1,
    0x4a, 0xf9, 0xe8, 0x7d, 0x1e, 0xb8, 0xb4, 0x39,
    0xfc, 0x80, 0x1d, 0xb2, 0x38, 0x8d, 0xc4, 0x63,
    0xc0, 0xe9, 0x15, 0x5f, 0xfe, 0xf6, 0x81, 0xb2,
    0x3d, 0xe0, 0x13, 0xec, 0xd0, 0x75, 0x1d, 0x03,
    0xb8, 0x6b, 0xdc, 0x13, 0xb6, 0x09, 0xb1, 0x82,
    0xe4, 0x02, 0x12, 0x18, 0xcb, 0x1e, 0x2d, 0xce,
    0xee, 0xf2, 0xc4, 0xa4, 0x9a, 0x1b, 0xa6, 0x51,
    0xc3, 0xfd, 0x73, 0xc1, 0xc5, 0x85, 0xe7, 0xbb,
    0x44, 0xe7, 0x61, 0x9e, 0x00, 0x03, 0x0a, 0x18,
    0xe4, 0x62, 0x86, 0x45, 0xd8, 0xfa, 0x5b, 0x71,
    0x46, 0x86, 0x0e, 0x3a, 0x89, 0x6d, 0xb2, 0xd7,
    0x0e, 0xd7, 0x65, 0x3e, 0xcc, 0x16, 0xe5, 0x9c,
    0x2d, 0xf2, 0x0e, 0x44, 0x64, 0x14, 0xfd, 0xa9,
    0x2f, 0xb6, 0xe8, 0x78, 0xa2, 0x54, 0xa3, 0x45,
    0x5e, 0xb0, 0x14, 0x02, 0xf7, 0xa1, 0xe0, 0x16,
    0x58, 0xd9, 0xc3, 0x58, 0x5a, 0xe6, 0x72, 0xa7,
    0x0a, 0x9f, 0x33, 0xf8, 0xd5, 0x18, 0x54, 0x1e,
    0x80, 0x54, 0x1e, 0x51, 0x69, 0x53, 0x60, 0x57,
    0xf0, 0xf9, 0xc6, 0x97, 0x4b, 0x5b, 0x98, 0xe6,
    0x1a, 0xc1, 0xb4, 0x61, 0xed, 0x3d, 0xc7, 0xe8,
    0x14, 0xd6, 0x92, 0x49, 0x7c, 0x46, 0x1e, 0x3a,
    0x20, 0xb6, 0x20, 0xb3, 0x25, 0xe0, 0xf8, 0x39,
    0xea, 0xc9, 0x7d, 0xcb, 0x38, 0x98, 0x03, 0x95,
    0x9a, 0x99, 0x69, 0xae, 0xd4, 0x0c, 0x1e, 0x50,
    0x34, 0x6d, 0x85, 0x6a, 0x33, 0x2f, 0x8c, 0x03,
    0x6a, 0xa4, 0x1a, 0xfd, 0xac, 0x8a, 0x34, 0x08,
    0xe9, 0x88, 0xb6, 0xa0, 0xb9, 0x96, 0xa7, 0x41,
    0x37, 0x7f, 0xe7, 0xc2, 0xd1, 0xaf, 0xe5, 0x60,
    0x68, 0x06, 0xfe, 0x70, 0x81, 0x80, 0xb4, 0xfe,
    0xf7, 0x6d, 0x88, 0xec, 0xc6, 0x90, 0x38, 0x04,
    0x34, 0x24, 0x1b, 0xb8, 0x57, 0x86, 0x40, 0xd2,
    0x19, 0xec, 0xa1, 0x36, 0x11, 0xff, 0x22, 0x34,
    0x8c, 0x31, 0x3f, 0x63, 0xa1, 0x4f, 0xce, 0x67,
    0x73, 0x5c, 0x78, 0x5d, 0x85, 0xc8, 0xd8, 0x40,
    0x5a, 0x40, 0xdf, 0x88, 0x3d, 0xf3, 0x6d, 0xf4,
    0x9b, 0xb6, 0x29, 0xbf, 0x07, 0xdd, 0xd9, 0x51,
    0x27, 0xa6, 0x97, 0xb2, 0x6f, 0x61, 0xef, 0x1c,
    0xa9, 0x01, 0x52, 0x2b, 0xd0, 0x12, 0xe4, 0x40,
    0xa6, 0xea, 0x25, 0x80, 0xba, 0x80, 0x61, 0x87,
    0xa5, 0x8d, 0x7e, 0x71, 0x09, 0x68, 0xfb, 0xc6,
    0x08, 0x2f, 0x98, 0x2c, 0xe7, 0xab, 0x30, 0xb4,
    0xde, 0x39, 0xb6, 0x71, 0xff, 0x32, 0x90, 0x61,
    0x65, 0xf9, 0xc4, 0x16, 0x7e, 0xda, 0xc4, 0x05,
    0x77, 0x0b, 0xf1, 0xf9, 0xe0, 0xc0, 0x7d, 0x14,
    0x57, 0x6f, 0x48, 0xba, 0xea, 0xe0, 0xc5, 0x93,
    0x60, 0x14, 0xe3, 0xf8, 0x6a, 0x67, 0xb2, 0xdc,
    0x56, 0xe8, 0x37, 0x7f, 0x59, 0x63, 0x5c, 0x77,
    0xd2, 0xe3, 0xa7, 0x73, 0x53, 0x9c, 0x8d, 0xf4,
    0xac, 0xe9, 0x07, 0x8a, 0x1c, 0xbe, 0xa7, 0x4d,
    0x1f, 0x60, 0x36, 0x9f, 0x33, 0x9d, 0xf4, 0x2d,
    0x4f, 0x61, 0xdd, 0x33, 0x40, 0x1f, 0x6e, 0x10,
    0x9f, 0xf7, 0x1f, 0xf0, 0x95, 0x89, 0x62, 0x8c,
    0x04, 0xf7, 0x64, 0xe0, 0x66, 0xd0, 0x4b, 0x4a,
    0x79, 0x96, 0x70, 0x56, 0xdb, 0x07, 0xda, 0xaf,
    0x00, 0xd1, 0x54, 0xec, 0x07, 0xac, 0x09, 0x25,
    0x91, 0x46, 0xd1, 0x4f, 0xbf, 0x50, 0xe9, 0xe6,
    0x54, 0x73, 0x91, 0xc7, 0xfb, 0x67, 0x33, 0xeb,
    0x01, 0x1b, 0xdc, 0x45, 0x5a, 0xdc, 0xa3, 0x96,
    0x35, 0x6c, 0x71, 0x9b, 0xa6, 0xe7, 0x2b, 0x65,
    0x95, 0x2d, 0xae, 0x81, 0x0a, 0x28, 0x31, 0xf0,
    0x2a, 0x9e, 0x01, 0xe2, 0x83, 0x2f, 0xe0, 0xa4,
    0x65, 0xca, 0x92, 0x4a, 0x0f, 0x32, 0x45, 0xb5,
    0xe6, 0x19, 0x24, 0x44, 0x2b, 0x2b, 0xea, 0x64,
    0x46, 0xb2, 0x49, 0xd0, 0x2f, 0xe2, 0x64, 0x0d,
    0x1f, 0xee, 0xe4, 0x29, 0x04, 0x99, 0x80, 0x8b,
    0x7c, 0x7a, 0x3a, 0x4c, 0xd4, 0x18, 0xd4, 0xf7,
    0x3b, 0x0c, 0x44, 0x39, 0x3d, 0x0f, 0x10, 0xd4,
    0x1f, 0x47, 0x7f, 0xb1, 0xdf, 0xd2, 0xc1, 0xd7,
    0x1d, 0x1f, 0xf7, 0x29, 0x36, 0x54, 0x4b, 0x8e,
    0x55, 0x9b, 0xcb, 0x08, 0xf5, 0x31, 0x0f, 0xd4,
    0x0c, 0x5e, 0x18, 0x59, 0x7e, 0xea, 0xef, 0x5a,
    0xd2, 0x0d, 0xc6, 0x94, 0x5d, 0x83, 0xbd, 0x55,
    0xa9, 0x2f, 0xfe, 0x85, 0x82, 0xd9, 0xa9, 0x91,
    0x40, 0xf6, 0xcc, 0xf9, 0x88, 0xba, 0x72, 0x09,
    0x36, 0x9f, 0xa1, 0xc5, 0x7c, 0xea, 0x93, 0xd4,
    0xae, 0x48, 0xaa, 0x2e, 0x91, 0x93, 0x2f, 0x1b,
    0x66, 0x3e, 0x87, 0x0e, 0xdd, 0xa0, 0x1e, 0x19,
    0x8d, 0x25, 0xdf, 0xbf, 0x39, 0x82, 0xdf, 0x7a,
    0x7c, 0x7c, 0x95, 0xb2, 0xbd, 0x27, 0x2b, 0x3d,
    0x76, 0xef, 0x05, 0x38, 0xfc, 0x8a, 0x38, 0x46,
    0x6d, 0xd5, 0xaa, 0x39, 0x6b, 0xa9, 0xca, 0xf5,
    0x9f, 0xfd, 0x81, 0xc2, 0x4f, 0xa5, 0x8c, 0x12,
    0x90, 0xa3, 0x03, 0xe6, 0xfd, 0x79, 0x6a, 0x48,
    0x69, 0x6c, 0xc3, 0x78, 0x30, 0x9d, 0x79, 0xa6,
    0x81, 0xa7, 0xf4, 0xe9, 0xcf, 0x4e, 0x9d, 0x58,
    0x01, 0x10, 0xed, 0x2c, 0x27, 0x2e, 0x5c, 0xaa,
    0xc8, 0xd0, 0x57, 0xef, 0x05, 0xa5, 0xe7, 0x9f,
    0x8d, 0x07, 0xa7, 0xd7, 0x48, 0x05, 0x7b, 0x70,
    0x17, 0xac, 0xe3, 0xd4, 0x4a, 0x09, 0x92, 0xc4,
    0x8e, 0x84, 0x03, 0x74, 0x5a, 0x61, 0x61, 0x0e,
    0x1a, 0x0c, 0x1f, 0x8c, 0x4e, 0xd9, 0x6c, 0x96,
    0x42, 0xac, 0x93, 0x0b, 0xd4, 0x14, 0x6c, 0xd8,
    0x27, 0x0e, 0x9b, 0xb9, 0x77, 0x0d, 0xd5, 0xdd,
    0x82, 0x08, 0xf5, 0x89, 0xdb, 0x44, 0x86, 0x8d,
    0xb2, 0x2c, 0xa8, 0x06, 0x5f, 0xbc, 0x4c, 0x73,
    0x27, 0xfe, 0x32, 0x26, 0x3c, 0x33, 0x83, 0xda,
    0x18, 0xc9
};
#endif /* !WOLFSSH_NO_MLDSA */

#ifndef WOLFSSH_NO_ECDSA
/* P-256 DER with the OID last byte changed 0x07 -> 0x01 (secp192r1).
 * Forces wc_EccPrivateKeyDecode to fail or to return an unsupported curve id,
 * exercising the wc_ecc_free cleanup in both the default: and else paths. */
static const byte unitTestEccUnsupportedCurveKey[] = {
    0x30, 0x77, 0x02, 0x01, 0x01, 0x04, 0x20, 0x61, 0x09, 0x99,
    0x0B, 0x79, 0xD2, 0x5F, 0x28, 0x5A, 0x0F, 0x5D, 0x15, 0xCC,
    0xA1, 0x56, 0x54, 0xF9, 0x2B, 0x39, 0x87, 0x21, 0x2D, 0xA7,
    0x7D, 0x85, 0x7B, 0xB8, 0x7F, 0x38, 0xC6, 0x6D, 0xD5, 0xA0,
    0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01,
    0x01, /* 0x07 (secp256r1) changed to 0x01 (secp192r1) */
    0xA1, 0x44, 0x03, 0x42, 0x00, 0x04, 0x81, 0x13, 0xFF,
    0xA4, 0x2B, 0xB7, 0x9C, 0x45, 0x74, 0x7A, 0x83, 0x4C, 0x61,
    0xF3, 0x3F, 0xAD, 0x26, 0xCF, 0x22, 0xCD, 0xA9, 0xA3, 0xBC,
    0xA5, 0x61, 0xB4, 0x7C, 0xE6, 0x62, 0xD4, 0xC2, 0xF7, 0x55,
    0x43, 0x9A, 0x31, 0xFB, 0x80, 0x11, 0x20, 0xB5, 0x12, 0x4B,
    0x24, 0xF5, 0x78, 0xD7, 0xFD, 0x22, 0xEF, 0x46, 0x35, 0xF0,
    0x05, 0x58, 0x6B, 0x5F, 0x63, 0xC8, 0xDA, 0x1B, 0xC4, 0xF5,
    0x69
};
#endif /* WOLFSSH_NO_ECDSA */

#ifndef WOLFSSH_NO_RSA
/* wolfSSH_RsaVerify unit test
 *
 * Verifies that wolfSSH_RsaVerify returns WS_RSA_E when given a signature
 * whose decoded digest is the correct size but contains wrong content.
 * This makes the `compare = ConstantCompare(...)` term in wolfSSH_RsaVerify
 * load-bearing: deleting it from the condition would silently pass this test.
 */
static int test_RsaVerify_BadDigest(void)
{
    int result = 0;
    int ret;
    RsaKey key;
    WC_RNG rng;
    word32 idx = 0;
    byte data[32];
    byte digest[WC_SHA256_DIGEST_SIZE];
    byte encDigest[MAX_ENCODED_SIG_SZ];
    int  encDigestSz;
    byte badEncDigest[MAX_ENCODED_SIG_SZ];
    byte sig[256]; /* 2048-bit RSA produces a 256-byte signature */
    int  sigSz;

    WMEMSET(data, 0x42, sizeof(data));

    if (wc_InitRng(&rng) != 0) {
        printf("RsaVerify_BadDigest: wc_InitRng failed\n");
        return -500;
    }
    if (wc_InitRsaKey(&key, NULL) != 0) {
        printf("RsaVerify_BadDigest: wc_InitRsaKey failed\n");
        wc_FreeRng(&rng);
        return -501;
    }

    ret = wc_RsaPrivateKeyDecode(unitTestRsaPrivKey, &idx, &key,
            unitTestRsaPrivKeySz);
    if (ret != 0) { result = -502; goto done; }

    /* Hash the payload */
    ret = wc_Hash(WC_HASH_TYPE_SHA256, data, sizeof(data),
            digest, WC_SHA256_DIGEST_SIZE);
    if (ret != 0) { result = -503; goto done; }

    /* Encode as PKCS#1 v1.5 DigestInfo */
    encDigestSz = wc_EncodeSignature(encDigest, digest,
            WC_SHA256_DIGEST_SIZE, wc_HashGetOID(WC_HASH_TYPE_SHA256));
    if (encDigestSz <= 0) { result = -504; goto done; }

    /* Sign */
    sigSz = wc_RsaSSL_Sign(encDigest, (word32)encDigestSz,
            sig, sizeof(sig), &key, &rng);
    if (sigSz <= 0) { result = -505; goto done; }

    /* Positive case: correct sig + correct encDigest must succeed */
    ret = wolfSSH_TestRsaVerify(sig, (word32)sigSz,
            encDigest, (word32)encDigestSz, &key, NULL);
    if (ret != WS_SUCCESS) { result = -506; goto done; }

    /* Negative case: correct sig but tampered encDigest (same size,
     * last byte of the SHA-256 hash flipped) must return WS_RSA_E.
     * This is the scenario that deleting `compare` from the condition
     * inside wolfSSH_RsaVerify would silently pass. */
    WMEMCPY(badEncDigest, encDigest, encDigestSz);
    badEncDigest[encDigestSz - 1] ^= 0xFF;
    ret = wolfSSH_TestRsaVerify(sig, (word32)sigSz,
            badEncDigest, (word32)encDigestSz, &key, NULL);
    if (ret != WS_RSA_E) { result = -507; goto done; }

done:
    wc_FreeRng(&rng);
    wc_FreeRsaKey(&key);
    return result;
}

#endif /* !WOLFSSH_NO_RSA */

#if !defined(WOLFSSH_NO_ED25519) && defined(HAVE_ED25519) && \
    defined(HAVE_ED25519_SIGN) && defined(HAVE_ED25519_VERIFY) && \
    defined(WOLFSSL_ED25519_STREAMING_VERIFY)

/* Locally-generated Ed25519 keypair for the DoUserAuthRequestEd25519 test.
 * 32-byte private seed followed by the 32-byte raw public key. Created with
 * ssh-keygen and decoded from the OpenSSH private key format so the test is
 * deterministic and does not depend on an RNG. */
static const byte unitTestEd25519Priv[32] = {
    0x05, 0xf5, 0x9c, 0x02, 0x55, 0x93, 0x32, 0x93,
    0xb9, 0xc2, 0x2e, 0xa7, 0x20, 0x05, 0x33, 0x0c,
    0x40, 0xcd, 0xfa, 0xff, 0x73, 0xe4, 0x4a, 0xe1,
    0x50, 0x2a, 0x4b, 0x37, 0x20, 0x66, 0xc5, 0x56
};
static const byte unitTestEd25519Pub[32] = {
    0x33, 0x76, 0xaf, 0x20, 0x97, 0xce, 0x38, 0xdf,
    0x5a, 0x76, 0x62, 0xfc, 0xb2, 0x87, 0x6e, 0x9d,
    0xd3, 0x9e, 0x85, 0x87, 0xf3, 0x0e, 0x72, 0x6c,
    0x1e, 0xc0, 0x01, 0xe2, 0x81, 0x96, 0xb8, 0x49
};

/* Write a 32-bit big-endian length prefix at out. */
static void Ed25519Test_PutLen(byte* out, word32 v)
{
    out[0] = (byte)(v >> 24);
    out[1] = (byte)(v >> 16);
    out[2] = (byte)(v >>  8);
    out[3] = (byte)(v);
}

static int test_ParseEd25519PubKey(void)
{
    static const char keyTypeName[] = "ssh-ed25519";
    const word32 keyTypeNameSz = (word32)(sizeof(keyTypeName) - 1);
    WOLFSSH_CTX* ctx = NULL;
    WOLFSSH* ssh = NULL;
    byte blob[64];
    word32 blobSz, off;
    int ret;
    int failures = 0;

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_CLIENT, NULL);
    if (ctx == NULL)
        return 1;
    ssh = wolfSSH_new(ctx);
    if (ssh == NULL) {
        wolfSSH_CTX_free(ctx);
        return 1;
    }

    /* string "ssh-ed25519" || string pubkey */
    off = 0;
    Ed25519Test_PutLen(blob + off, keyTypeNameSz); off += UINT32_SZ;
    WMEMCPY(blob + off, keyTypeName, keyTypeNameSz); off += keyTypeNameSz;
    Ed25519Test_PutLen(blob + off, (word32)sizeof(unitTestEd25519Pub));
    off += UINT32_SZ;
    WMEMCPY(blob + off, unitTestEd25519Pub, sizeof(unitTestEd25519Pub));
    off += (word32)sizeof(unitTestEd25519Pub);
    blobSz = off;

    /* valid blob */
    ret = wolfSSH_TestParseEd25519PubKey(ssh, blob, blobSz);
    if (ret != WS_SUCCESS) {
        fprintf(stderr, "\t\"valid\" FAIL: got %d, expected %d\n",
                ret, WS_SUCCESS);
        failures++;
    }

    /* truncated blob: fails after the key is initialized */
    ret = wolfSSH_TestParseEd25519PubKey(ssh, blob, blobSz - 4);
    if (ret != WS_BUFFER_E) {
        fprintf(stderr, "\t\"truncated\" FAIL: got %d, expected %d\n",
                ret, WS_BUFFER_E);
        failures++;
    }

    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);

    return failures;
}

/* DoUserAuthRequestEd25519 unit test
 *
 * Drives DoUserAuthRequestEd25519 directly with a fully-formed Ed25519
 * USERAUTH_REQUEST and asserts (1) a correct signature returns WS_SUCCESS
 * and (2) a tampered signature returns either WS_ED25519_E or
 * WS_CRYPTO_FAILED. This is the test that makes the
 * `status ? WS_SUCCESS : WS_ED25519_E` style mapping load-bearing -- without
 * the negative case any mutation that hard-codes WS_SUCCESS or inverts the
 * status would silently survive.
 *
 * The Ed25519 verifier in wolfSSL has two failure paths reachable from this
 * function: wc_ed25519_verify_msg_final returns non-zero (WS_CRYPTO_FAILED)
 * or returns zero with status=0 (WS_ED25519_E). Different wolfSSL versions
 * have routed bad signatures through either branch; we accept either failure
 * code so the test stays portable while still killing the most dangerous
 * mutation -- turning either error into WS_SUCCESS.
 */
static int test_DoUserAuthRequestEd25519(void)
{
    static const char keyTypeName[] = "ssh-ed25519";
    static const char username[]    = "wolfssh";
    static const char serviceName[] = "ssh-connection";
    static const char authName[]    = "publickey";
    const word32 keyTypeNameSz = (word32)(sizeof(keyTypeName) - 1);
    const word32 usernameSz    = (word32)(sizeof(username) - 1);
    const word32 serviceNameSz = (word32)(sizeof(serviceName) - 1);
    const word32 authNameSz    = (word32)(sizeof(authName) - 1);

    WOLFSSH_CTX* ctx = NULL;
    WOLFSSH* ssh = NULL;
    ed25519_key signingKey;
    int signingKeyInit = 0;
    WS_UserAuthData authData;
    byte pubKeyBlob[64];
    byte sigBlob[128];
    byte badSigBlob[128];
    byte dataToSign[256];
    byte checkData[512];
    byte sig[ED25519_SIG_SIZE];
    word32 pubKeyBlobSz = 0;
    word32 sigBlobSz    = 0;
    word32 dataToSignSz = 0;
    word32 checkDataSz  = 0;
    word32 sigSz        = sizeof(sig);
    word32 off;
    int result = 0;
    int ret;

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_SERVER, NULL);
    if (ctx == NULL) return -600;
    ssh = wolfSSH_new(ctx);
    if (ssh == NULL) { result = -601; goto done; }

    /* Stub a session id so the verify hash has something to absorb. */
    ssh->sessionIdSz = 16;
    WMEMSET(ssh->sessionId, 0xA5, ssh->sessionIdSz);

    /* Load the embedded Ed25519 keypair for signing. */
    if (wc_ed25519_init(&signingKey) != 0) { result = -602; goto done; }
    signingKeyInit = 1;
    if (wc_ed25519_import_private_key(unitTestEd25519Priv,
                (word32)sizeof(unitTestEd25519Priv),
                unitTestEd25519Pub, (word32)sizeof(unitTestEd25519Pub),
                &signingKey) != 0) {
        result = -603; goto done;
    }

    /* Build the SSH public key blob: string "ssh-ed25519" || string pubkey */
    off = 0;
    Ed25519Test_PutLen(pubKeyBlob + off, keyTypeNameSz); off += UINT32_SZ;
    WMEMCPY(pubKeyBlob + off, keyTypeName, keyTypeNameSz);
    off += keyTypeNameSz;
    Ed25519Test_PutLen(pubKeyBlob + off,
            (word32)sizeof(unitTestEd25519Pub));
    off += UINT32_SZ;
    WMEMCPY(pubKeyBlob + off, unitTestEd25519Pub,
            sizeof(unitTestEd25519Pub));
    off += (word32)sizeof(unitTestEd25519Pub);
    pubKeyBlobSz = off;

    /* Build the dataToSign region the same way the wire packet would lay it
     * out: username || service || authmethod || hasSig=1 || pkAlgo || pkBlob.
     * DoUserAuthRequestEd25519 hashes exactly this region. */
    off = 0;
    Ed25519Test_PutLen(dataToSign + off, usernameSz); off += UINT32_SZ;
    WMEMCPY(dataToSign + off, username, usernameSz); off += usernameSz;
    Ed25519Test_PutLen(dataToSign + off, serviceNameSz); off += UINT32_SZ;
    WMEMCPY(dataToSign + off, serviceName, serviceNameSz);
    off += serviceNameSz;
    Ed25519Test_PutLen(dataToSign + off, authNameSz); off += UINT32_SZ;
    WMEMCPY(dataToSign + off, authName, authNameSz); off += authNameSz;
    dataToSign[off++] = 1; /* hasSignature */
    Ed25519Test_PutLen(dataToSign + off, keyTypeNameSz); off += UINT32_SZ;
    WMEMCPY(dataToSign + off, keyTypeName, keyTypeNameSz);
    off += keyTypeNameSz;
    Ed25519Test_PutLen(dataToSign + off, pubKeyBlobSz); off += UINT32_SZ;
    WMEMCPY(dataToSign + off, pubKeyBlob, pubKeyBlobSz); off += pubKeyBlobSz;
    dataToSignSz = off;

    /* Build the bytes that get signed: sessionIdSz || sessionId ||
     * MSGID_USERAUTH_REQUEST || dataToSign. Mirrors BuildUserAuthRequestEd25519
     * on the client side. */
    off = 0;
    Ed25519Test_PutLen(checkData + off, ssh->sessionIdSz); off += UINT32_SZ;
    WMEMCPY(checkData + off, ssh->sessionId, ssh->sessionIdSz);
    off += ssh->sessionIdSz;
    checkData[off++] = MSGID_USERAUTH_REQUEST;
    WMEMCPY(checkData + off, dataToSign, dataToSignSz);
    off += dataToSignSz;
    checkDataSz = off;

    if (wc_ed25519_sign_msg(checkData, checkDataSz, sig, &sigSz,
                &signingKey) != 0) {
        result = -604; goto done;
    }

    /* Build the SSH signature blob: string "ssh-ed25519" || string sig */
    off = 0;
    Ed25519Test_PutLen(sigBlob + off, keyTypeNameSz); off += UINT32_SZ;
    WMEMCPY(sigBlob + off, keyTypeName, keyTypeNameSz);
    off += keyTypeNameSz;
    Ed25519Test_PutLen(sigBlob + off, sigSz); off += UINT32_SZ;
    WMEMCPY(sigBlob + off, sig, sigSz); off += sigSz;
    sigBlobSz = off;

    /* Populate authData the way DoUserAuthRequest/DoUserAuthRequestPublicKey
     * would before dispatching to DoUserAuthRequestEd25519. */
    WMEMSET(&authData, 0, sizeof(authData));
    authData.type        = WOLFSSH_USERAUTH_PUBLICKEY;
    authData.username    = (const byte*)username;
    authData.usernameSz  = usernameSz;
    authData.serviceName = (const byte*)serviceName;
    authData.serviceNameSz = serviceNameSz;
    authData.authName    = (const byte*)authName;
    authData.authNameSz  = authNameSz;
    authData.sf.publicKey.dataToSign      = dataToSign;
    authData.sf.publicKey.publicKeyType   = (const byte*)keyTypeName;
    authData.sf.publicKey.publicKeyTypeSz = keyTypeNameSz;
    authData.sf.publicKey.publicKey       = pubKeyBlob;
    authData.sf.publicKey.publicKeySz     = pubKeyBlobSz;
    authData.sf.publicKey.hasSignature    = 1;
    authData.sf.publicKey.signature       = sigBlob;
    authData.sf.publicKey.signatureSz     = sigBlobSz;

    /* Positive case: untouched signature must verify. */
    ret = wolfSSH_TestDoUserAuthRequestEd25519(ssh, &authData);
    if (ret != WS_SUCCESS) {
        printf("DoUserAuthRequestEd25519 positive: ret=%d (expected %d)\n",
                ret, WS_SUCCESS);
        result = -605; goto done;
    }

    /* Negative case: flip a byte inside the raw signature (skip past the
     * 4 + keyTypeNameSz + 4 header so we land in the actual signature
     * material). Must NOT return WS_SUCCESS. */
    WMEMCPY(badSigBlob, sigBlob, sigBlobSz);
    badSigBlob[UINT32_SZ + keyTypeNameSz + UINT32_SZ + 10] ^= 0xFF;
    authData.sf.publicKey.signature = badSigBlob;

    ret = wolfSSH_TestDoUserAuthRequestEd25519(ssh, &authData);
    if (ret != WS_ED25519_E && ret != WS_CRYPTO_FAILED) {
        printf("DoUserAuthRequestEd25519 tampered: ret=%d\n", ret);
        result = -606; goto done;
    }

done:
    if (signingKeyInit)
        wc_ed25519_free(&signingKey);
    if (ssh != NULL)
        wolfSSH_free(ssh);
    if (ctx != NULL)
        wolfSSH_CTX_free(ctx);
    return result;
}

#endif /* Ed25519 verify test guards */

#ifndef WOLFSSH_NO_MLDSA
/* Write 32-bit big-endian length into out. */
static void MlDsaTest_PutLen(byte* out, word32 v)
{
    out[0] = (byte)(v >> 24);
    out[1] = (byte)(v >> 16);
    out[2] = (byte)(v >>  8);
    out[3] = (byte)(v);
}

static int test_DoUserAuthRequestMlDsa_Params(const char* keyTypeName,
                                              byte level)
{
    static const char username[]    = "wolfssh";
    static const char serviceName[] = "ssh-connection";
    static const char authName[]    = "publickey";
    const word32 keyTypeNameSz = (word32)(WSTRLEN(keyTypeName));
    const word32 usernameSz    = (word32)(sizeof(username) - 1);
    const word32 serviceNameSz = (word32)(sizeof(serviceName) - 1);
    const word32 authNameSz    = (word32)(sizeof(authName) - 1);

    WOLFSSH_CTX* ctx = NULL;
    WOLFSSH* ssh = NULL;
    MlDsaKey signingKey;
    int signingKeyInit = 0;
    WC_RNG rng;
    int rngInit = 0;
    WS_UserAuthData authData;

    byte* pubKeyBlob = NULL;
    byte* sigBlob = NULL;
    byte* badSigBlob = NULL;
    byte* dataToSign = NULL;
    byte* checkData = NULL;
    byte* sig = NULL;
    byte* pubRaw = NULL;

    word32 pubKeyBlobSz = 0;
    word32 sigBlobSz    = 0;
    word32 dataToSignSz = 0;
    word32 checkDataSz  = 0;
    int    sigSzInt;
    word32 sigSz    = 0;
    int    pubRawSzInt;
    word32 pubRawSz = 0;
    word32 off;
    int result = 0;
    int ret;

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_SERVER, NULL);
    if (ctx == NULL) return -700;
    ssh = wolfSSH_new(ctx);
    if (ssh == NULL) { result = -701; goto done; }

    /* Stub a session id so the verify hash has something to absorb. */
    ssh->sessionIdSz = 16;
    WMEMSET(ssh->sessionId, 0xA5, ssh->sessionIdSz);

    if (wc_InitRng(&rng) != 0) {
        result = -702;
        goto done;
    }
    rngInit = 1;

    if (wc_MlDsaKey_Init(&signingKey, NULL, INVALID_DEVID) != 0) {
        result = -703; goto done;
    }
    signingKeyInit = 1;
    if (wc_MlDsaKey_SetParams(&signingKey, level) != 0) {
        result = -704; goto done;
    }
    if (wc_MlDsaKey_MakeKey(&signingKey, &rng) != 0) {
        result = -705; goto done;
    }

    sigSzInt = wc_MlDsaKey_SigSize(&signingKey);
    if (sigSzInt < 0) { result = -706; goto done; }
    sigSz = (word32)sigSzInt;
    sig = (byte*)WMALLOC(sigSz, NULL, 0);
    if (sig == NULL) { result = -718; goto done; }

    /* Get raw public key to build pubKeyBlob */
    pubRawSzInt = wc_MlDsaKey_PubSize(&signingKey);
    if (pubRawSzInt < 0) { result = -707; goto done; }
    pubRawSz = (word32)pubRawSzInt;
    pubRaw = (byte*)WMALLOC(pubRawSz, NULL, 0);
    if (pubRaw == NULL) { result = -717; goto done; }
    if (wc_MlDsaKey_ExportPubRaw(&signingKey, pubRaw, &pubRawSz) != 0) {
        result = -708; goto done;
    }

    pubKeyBlob = (byte*)WMALLOC(UINT32_SZ * 2 + keyTypeNameSz + pubRawSz,
                                NULL, 0);
    if (pubKeyBlob == NULL) { result = -709; goto done; }

    /* Build the SSH public key blob: string keyTypeName || string pubkey */
    off = 0;
    MlDsaTest_PutLen(pubKeyBlob + off, keyTypeNameSz); off += UINT32_SZ;
    WMEMCPY(pubKeyBlob + off, keyTypeName, keyTypeNameSz);
    off += keyTypeNameSz;
    MlDsaTest_PutLen(pubKeyBlob + off, pubRawSz); off += UINT32_SZ;
    WMEMCPY(pubKeyBlob + off, pubRaw, pubRawSz); off += pubRawSz;
    pubKeyBlobSz = off;

    /* Build dataToSign: user || svc || auth || hasSig || algo || blob. */
    dataToSignSz = UINT32_SZ * 5 + usernameSz + serviceNameSz + authNameSz +
                   1 + keyTypeNameSz + pubKeyBlobSz;
    dataToSign = (byte*)WMALLOC(dataToSignSz, NULL, 0);
    if (dataToSign == NULL) { result = -710; goto done; }

    off = 0;
    MlDsaTest_PutLen(dataToSign + off, usernameSz); off += UINT32_SZ;
    WMEMCPY(dataToSign + off, username, usernameSz); off += usernameSz;
    MlDsaTest_PutLen(dataToSign + off, serviceNameSz); off += UINT32_SZ;
    WMEMCPY(dataToSign + off, serviceName, serviceNameSz); off += serviceNameSz;
    MlDsaTest_PutLen(dataToSign + off, authNameSz); off += UINT32_SZ;
    WMEMCPY(dataToSign + off, authName, authNameSz); off += authNameSz;
    dataToSign[off++] = 1; /* hasSignature */
    MlDsaTest_PutLen(dataToSign + off, keyTypeNameSz); off += UINT32_SZ;
    WMEMCPY(dataToSign + off, keyTypeName, keyTypeNameSz); off += keyTypeNameSz;
    MlDsaTest_PutLen(dataToSign + off, pubKeyBlobSz); off += UINT32_SZ;
    WMEMCPY(dataToSign + off, pubKeyBlob, pubKeyBlobSz); off += pubKeyBlobSz;

    /* Build checkData: session ID || msg ID || dataToSign. */
    checkDataSz = UINT32_SZ + ssh->sessionIdSz + MSG_ID_SZ + dataToSignSz;
    checkData = (byte*)WMALLOC(checkDataSz, NULL, 0);
    if (checkData == NULL) { result = -711; goto done; }

    off = 0;
    MlDsaTest_PutLen(checkData + off, ssh->sessionIdSz); off += UINT32_SZ;
    WMEMCPY(checkData + off, ssh->sessionId, ssh->sessionIdSz);
    off += ssh->sessionIdSz;
    checkData[off++] = MSGID_USERAUTH_REQUEST;
    WMEMCPY(checkData + off, dataToSign, dataToSignSz);

    if (wc_MlDsaKey_SignCtx(&signingKey, NULL, 0, sig, &sigSz, checkData,
                checkDataSz, &rng) != 0) {
        result = -712; goto done;
    }

    /* Build the SSH signature blob: string keyTypeName || string sig */
    sigBlobSz = UINT32_SZ * 2 + keyTypeNameSz + sigSz;
    sigBlob = (byte*)WMALLOC(sigBlobSz, NULL, 0);
    if (sigBlob == NULL) { result = -713; goto done; }

    off = 0;
    MlDsaTest_PutLen(sigBlob + off, keyTypeNameSz); off += UINT32_SZ;
    WMEMCPY(sigBlob + off, keyTypeName, keyTypeNameSz); off += keyTypeNameSz;
    MlDsaTest_PutLen(sigBlob + off, sigSz); off += UINT32_SZ;
    WMEMCPY(sigBlob + off, sig, sigSz); off += sigSz;
    sigBlobSz = off;

    /* Populate authData */
    WMEMSET(&authData, 0, sizeof(authData));
    authData.type        = WOLFSSH_USERAUTH_PUBLICKEY;
    authData.username    = (const byte*)username;
    authData.usernameSz  = usernameSz;
    authData.serviceName = (const byte*)serviceName;
    authData.serviceNameSz = serviceNameSz;
    authData.authName    = (const byte*)authName;
    authData.authNameSz  = authNameSz;
    authData.sf.publicKey.dataToSign      = dataToSign;
    authData.sf.publicKey.publicKeyType   = (const byte*)keyTypeName;
    authData.sf.publicKey.publicKeyTypeSz = keyTypeNameSz;
    authData.sf.publicKey.publicKey       = pubKeyBlob;
    authData.sf.publicKey.publicKeySz     = pubKeyBlobSz;
    authData.sf.publicKey.hasSignature    = 1;
    authData.sf.publicKey.signature       = sigBlob;
    authData.sf.publicKey.signatureSz     = sigBlobSz;

    /* Positive case: untouched signature must verify. */
    ret = wolfSSH_TestDoUserAuthRequestMlDsa(ssh, &authData, pubKeyBlobSz);
    if (ret != WS_SUCCESS) {
        printf("DoUserAuthRequestMlDsa positive (%s): ret=%d (expected %d)\n",
                keyTypeName, ret, WS_SUCCESS);
        result = -714; goto done;
    }

    /* Negative case: flip a byte inside the raw signature */
    badSigBlob = (byte*)WMALLOC(sigBlobSz, NULL, 0);
    if (badSigBlob == NULL) { result = -715; goto done; }
    WMEMCPY(badSigBlob, sigBlob, sigBlobSz);
    badSigBlob[UINT32_SZ + keyTypeNameSz + UINT32_SZ + 10] ^= 0xFF;
    authData.sf.publicKey.signature = badSigBlob;

    ret = wolfSSH_TestDoUserAuthRequestMlDsa(ssh, &authData, pubKeyBlobSz);
    if (ret != WS_MLDSA_E && ret != WS_CRYPTO_FAILED) {
        printf("DoUserAuthRequestMlDsa tampered (%s): ret=%d (expected %d)\n",
                keyTypeName, ret, WS_MLDSA_E);
        result = -716; goto done;
    }

done:
    if (signingKeyInit)
        wc_MlDsaKey_Free(&signingKey);
    if (rngInit)
        wc_FreeRng(&rng);
    if (pubKeyBlob != NULL) WFREE(pubKeyBlob, NULL, 0);
    if (sigBlob != NULL) WFREE(sigBlob, NULL, 0);
    if (badSigBlob != NULL) WFREE(badSigBlob, NULL, 0);
    if (dataToSign != NULL) WFREE(dataToSign, NULL, 0);
    if (checkData != NULL) WFREE(checkData, NULL, 0);
    if (sig != NULL) WFREE(sig, NULL, 0);
    if (pubRaw != NULL) WFREE(pubRaw, NULL, 0);
    if (ssh != NULL) wolfSSH_free(ssh);
    if (ctx != NULL) wolfSSH_CTX_free(ctx);
    return result;
}

/* unknown publicKeyType must be rejected at the boundary */
static int test_DoUserAuthRequestMlDsa_BadAlgo(void)
{
    static const char badAlgo[] = "not-an-mldsa-key";
    WOLFSSH_CTX* ctx = NULL;
    WOLFSSH* ssh = NULL;
    WS_UserAuthData authData;
    int result = 0;
    int ret;

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_SERVER, NULL);
    if (ctx == NULL) return -800;
    ssh = wolfSSH_new(ctx);
    if (ssh == NULL) { result = -801; goto done; }

    WMEMSET(&authData, 0, sizeof(authData));
    authData.type = WOLFSSH_USERAUTH_PUBLICKEY;
    authData.sf.publicKey.publicKeyType =
            (const byte*)badAlgo;
    authData.sf.publicKey.publicKeyTypeSz =
            (word32)(sizeof(badAlgo) - 1);

    /* pubKeyBlobSz=0: the bad key type is rejected before dataToSign is sized,
     * so the value is irrelevant for this code path. */
    ret = wolfSSH_TestDoUserAuthRequestMlDsa(ssh, &authData, 0);
    if (ret != WS_INVALID_ALGO_ID) {
        printf("DoUserAuthRequestMlDsa bad-algo: ret=%d expected %d\n",
                ret, WS_INVALID_ALGO_ID);
        result = -802;
    }

done:
    if (ssh != NULL) wolfSSH_free(ssh);
    if (ctx != NULL) wolfSSH_CTX_free(ctx);
    return result;
}

#ifdef WOLFSSH_CERTS
 /* Confirm the cert branch is entered, ParseCertChainVerify intentionally
 * rejects this. */
static int test_DoUserAuthRequestMlDsa_CertPath(const char* keyTypeName)
{
    static const char username[]    = "wolfssh";
    static const char serviceName[] = "ssh-connection";
    static const char authName[]    = "publickey";
    const word32 keyTypeNameSz = (word32)WSTRLEN(keyTypeName);
    /* NOTE: pubKeyBlob is an RFC 6187 wire blob, not leaf-cert DER. The real
     * server path calls ParseLeafCert() first to extract DER. This test
     * exercises ASN.1-invalid rejection rather than cryptographic rejection —
     * valid for a negative path test, but does not cover the DER-valid case. */
    static const byte junkCert[] = { 0x30, 0x05, 0x00, 0x00, 0x00, 0x00 };
    const word32 junkCertSz = (word32)sizeof(junkCert);
    WOLFSSH_CTX* ctx = NULL;
    WOLFSSH* ssh = NULL;
    WS_UserAuthData authData;
    byte* pubKeyBlob = NULL;
    byte* sigBlob = NULL;
    word32 pubKeyBlobSz, off;
    int result = 0;
    int ret;

    /* RFC 6187 cert chain blob:
     *   string keyTypeName
     *   uint32 certCount=1
     *   string junkCert
     *   uint32 ocspCount=0 */
    pubKeyBlobSz = UINT32_SZ + keyTypeNameSz + UINT32_SZ +
                   UINT32_SZ + junkCertSz + UINT32_SZ;
    pubKeyBlob = (byte*)WMALLOC(pubKeyBlobSz, NULL, 0);
    if (pubKeyBlob == NULL) { result = -820; goto done; }
    off = 0;
    MlDsaTest_PutLen(pubKeyBlob + off, keyTypeNameSz); off += UINT32_SZ;
    WMEMCPY(pubKeyBlob + off, keyTypeName, keyTypeNameSz); off += keyTypeNameSz;
    MlDsaTest_PutLen(pubKeyBlob + off, 1); off += UINT32_SZ;
    MlDsaTest_PutLen(pubKeyBlob + off, junkCertSz); off += UINT32_SZ;
    WMEMCPY(pubKeyBlob + off, junkCert, junkCertSz); off += junkCertSz;
    MlDsaTest_PutLen(pubKeyBlob + off, 0); off += UINT32_SZ;

    /* Minimal sig blob: string keyTypeName || string(1 zero byte) */
    sigBlob = (byte*)WMALLOC(UINT32_SZ * 2 + keyTypeNameSz + 1, NULL, 0);
    if (sigBlob == NULL) { result = -821; goto done; }
    off = 0;
    MlDsaTest_PutLen(sigBlob + off, keyTypeNameSz); off += UINT32_SZ;
    WMEMCPY(sigBlob + off, keyTypeName, keyTypeNameSz); off += keyTypeNameSz;
    MlDsaTest_PutLen(sigBlob + off, 1); off += UINT32_SZ;
    sigBlob[off] = 0x00;

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_SERVER, NULL);
    if (ctx == NULL) { result = -822; goto done; }
    ssh = wolfSSH_new(ctx);
    if (ssh == NULL) { result = -823; goto done; }
    ssh->sessionIdSz = 16;
    WMEMSET(ssh->sessionId, 0xA5, ssh->sessionIdSz);

    WMEMSET(&authData, 0, sizeof(authData));
    authData.type                          = WOLFSSH_USERAUTH_PUBLICKEY;
    authData.username                      = (const byte*)username;
    authData.usernameSz                    = (word32)(sizeof(username) - 1);
    authData.serviceName                   = (const byte*)serviceName;
    authData.serviceNameSz                 = (word32)(sizeof(serviceName) - 1);
    authData.authName                      = (const byte*)authName;
    authData.authNameSz                    = (word32)(sizeof(authName) - 1);
    authData.sf.publicKey.publicKeyType    = (const byte*)keyTypeName;
    authData.sf.publicKey.publicKeyTypeSz  = keyTypeNameSz;
    authData.sf.publicKey.publicKey        = pubKeyBlob;
    authData.sf.publicKey.publicKeySz      = pubKeyBlobSz;
    authData.sf.publicKey.hasSignature     = 1;
    authData.sf.publicKey.signature        = sigBlob;
    authData.sf.publicKey.signatureSz      = UINT32_SZ * 2 + keyTypeNameSz + 1;

    ret = wolfSSH_TestDoUserAuthRequestMlDsa(ssh, &authData, pubKeyBlobSz);
    if (ret == WS_INVALID_ALGO_ID) {
        /* Routing failed: x509v3-mldsa-* was not recognised and hit the
         * unknown-algo guard instead of the cert parse path. */
        printf("DoUserAuthRequestMlDsa cert-path (%s): routing failed\n",
                keyTypeName);
        result = -824;
    }
    else if (ret == WS_SUCCESS) {
        /* Wrongful acceptance: junk cert should have been rejected */
        printf("DoUserAuthRequestMlDsa cert-path (%s): "
               "wrongfully accepted junk cert\n",
                keyTypeName);
        result = -825;
    }
    /* Any other error is expected: junk cert correctly rejected. */

done:
    if (pubKeyBlob != NULL) WFREE(pubKeyBlob, NULL, 0);
    if (sigBlob != NULL) WFREE(sigBlob, NULL, 0);
    if (ssh != NULL) wolfSSH_free(ssh);
    if (ctx != NULL) wolfSSH_CTX_free(ctx);
    return result;
}

#if defined(WOLFSSH_CERTS) && defined(WOLFSSL_CERT_GEN)
/* Positive cert-path test: generate a real ML-DSA self-signed cert, build a
 * valid auth request, and verify that DoUserAuthRequestMlDsa accepts it. */
static int test_DoUserAuthRequestMlDsa_CertPath_Valid(
        const char* keyTypeName, byte level, int certSigType)
{
    static const char username[]    = "wolfssh";
    static const char serviceName[] = "ssh-connection";
    static const char authName[]    = "publickey";
    const word32 keyTypeNameSz = (word32)WSTRLEN(keyTypeName);
    const word32 usernameSz    = (word32)(sizeof(username) - 1);
    const word32 serviceNameSz = (word32)(sizeof(serviceName) - 1);
    const word32 authNameSz    = (word32)(sizeof(authName) - 1);

    WOLFSSH_CTX* ctx = NULL;
    WOLFSSH* ssh = NULL;
    MlDsaKey signingKey;
    int signingKeyInit = 0;
    WC_RNG rng;
    int rngInit = 0;
    Cert myCert;
    WS_UserAuthData authData;

    byte* certDER    = NULL;
    byte* rfcBlob    = NULL;   /* RFC6187 cert chain blob */
    byte* sigBlob    = NULL;
    byte* dataToSign = NULL;
    byte* checkData  = NULL;
    byte* sig        = NULL;

    word32 certDERSz    = 0;
    word32 rfcBlobSz    = 0;
    word32 sigBlobSz    = 0;
    word32 dataToSignSz = 0;
    word32 checkDataSz  = 0;
    int    sigSzInt;
    word32 sigSz        = 0;
    int    mldsaKeyType;
    word32 off;
    int result = 0;
    int ret;

    mldsaKeyType = (level == WC_ML_DSA_44) ? ML_DSA_44_TYPE :
                   (level == WC_ML_DSA_65) ? ML_DSA_65_TYPE : ML_DSA_87_TYPE;

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_SERVER, NULL);
    if (ctx == NULL) return -850;
    ssh = wolfSSH_new(ctx);
    if (ssh == NULL) { result = -851; goto done; }
    ssh->sessionIdSz = 16;
    WMEMSET(ssh->sessionId, 0xA5, ssh->sessionIdSz);

    if (wc_InitRng(&rng) != 0) { result = -852; goto done; }
    rngInit = 1;

    if (wc_MlDsaKey_Init(&signingKey, NULL, INVALID_DEVID) != 0) {
        result = -853; goto done;
    }
    signingKeyInit = 1;
    if (wc_MlDsaKey_SetParams(&signingKey, level) != 0) {
        result = -854; goto done;
    }
    if (wc_MlDsaKey_MakeKey(&signingKey, &rng) != 0) {
        result = -855; goto done;
    }

    /* Generate a self-signed X.509 cert containing the ML-DSA public key.
     * 16384 bytes is sufficient for the largest ML-DSA variant (ML-DSA-87). */
    certDER = (byte*)WMALLOC(16384, NULL, 0);
    if (certDER == NULL) { result = -856; goto done; }

    wc_InitCert(&myCert);
    WSTRNCPY(myCert.subject.commonName, "wolfSSH-mldsa-test",
             CTC_NAME_SIZE - 1);
    myCert.subject.commonNameEnc = CTC_UTF8;
    WSTRNCPY(myCert.subject.country, "US", CTC_NAME_SIZE - 1);
    myCert.daysValid  = 365;
    myCert.selfSigned = 1;
    myCert.sigType    = certSigType;

    ret = wc_MakeCert_ex(&myCert, certDER, 16384, mldsaKeyType,
                         &signingKey, &rng);
    if (ret <= 0) { result = -857; goto done; }
    ret = wc_SignCert_ex(ret, certSigType, certDER, 16384, mldsaKeyType,
                         &signingKey, &rng);
    if (ret <= 0) { result = -858; goto done; }
    certDERSz = (word32)ret;

    /* Build RFC6187 cert chain blob:
     *   string keyTypeName | uint32 certCount=1 | string certDER |
     *   uint32 ocspCount=0 */
    rfcBlobSz = UINT32_SZ + keyTypeNameSz + UINT32_SZ +
                UINT32_SZ + certDERSz + UINT32_SZ;
    rfcBlob = (byte*)WMALLOC(rfcBlobSz, NULL, 0);
    if (rfcBlob == NULL) { result = -859; goto done; }
    off = 0;
    MlDsaTest_PutLen(rfcBlob + off, keyTypeNameSz); off += UINT32_SZ;
    WMEMCPY(rfcBlob + off, keyTypeName, keyTypeNameSz); off += keyTypeNameSz;
    MlDsaTest_PutLen(rfcBlob + off, 1); off += UINT32_SZ;
    MlDsaTest_PutLen(rfcBlob + off, certDERSz); off += UINT32_SZ;
    WMEMCPY(rfcBlob + off, certDER, certDERSz); off += certDERSz;
    MlDsaTest_PutLen(rfcBlob + off, 0); off += UINT32_SZ;

    /* Build dataToSign; pubkey blob length uses RFC6187 blob size. */
    dataToSignSz = UINT32_SZ * 5 + usernameSz + serviceNameSz + authNameSz +
                   1 + keyTypeNameSz + rfcBlobSz;
    dataToSign = (byte*)WMALLOC(dataToSignSz, NULL, 0);
    if (dataToSign == NULL) { result = -860; goto done; }
    off = 0;
    MlDsaTest_PutLen(dataToSign + off, usernameSz);    off += UINT32_SZ;
    WMEMCPY(dataToSign + off, username, usernameSz);   off += usernameSz;
    MlDsaTest_PutLen(dataToSign + off, serviceNameSz); off += UINT32_SZ;
    WMEMCPY(dataToSign + off, serviceName, serviceNameSz); off += serviceNameSz;
    MlDsaTest_PutLen(dataToSign + off, authNameSz);    off += UINT32_SZ;
    WMEMCPY(dataToSign + off, authName, authNameSz);   off += authNameSz;
    dataToSign[off++] = 1; /* hasSig */
    MlDsaTest_PutLen(dataToSign + off, keyTypeNameSz); off += UINT32_SZ;
    WMEMCPY(dataToSign + off, keyTypeName, keyTypeNameSz); off += keyTypeNameSz;
    MlDsaTest_PutLen(dataToSign + off, rfcBlobSz);     off += UINT32_SZ;
    WMEMCPY(dataToSign + off, rfcBlob, rfcBlobSz);     off += rfcBlobSz;

    /* Build checkData and sign it. */
    sigSzInt = wc_MlDsaKey_SigSize(&signingKey);
    if (sigSzInt < 0) { result = -861; goto done; }
    sigSz = (word32)sigSzInt;
    sig = (byte*)WMALLOC(sigSz, NULL, 0);
    if (sig == NULL) { result = -871; goto done; }

    checkDataSz = UINT32_SZ + ssh->sessionIdSz + MSG_ID_SZ + dataToSignSz;
    checkData = (byte*)WMALLOC(checkDataSz, NULL, 0);
    if (checkData == NULL) { result = -862; goto done; }
    off = 0;
    MlDsaTest_PutLen(checkData + off, ssh->sessionIdSz); off += UINT32_SZ;
    WMEMCPY(checkData + off, ssh->sessionId, ssh->sessionIdSz);
    off += ssh->sessionIdSz;
    checkData[off++] = MSGID_USERAUTH_REQUEST;
    WMEMCPY(checkData + off, dataToSign, dataToSignSz);

    if (wc_MlDsaKey_SignCtx(&signingKey, NULL, 0, sig, &sigSz, checkData,
                            checkDataSz, &rng) != 0) {
        result = -863; goto done;
    }

    /* Build signature blob: string keyTypeName || string sig */
    sigBlobSz = UINT32_SZ * 2 + keyTypeNameSz + sigSz;
    sigBlob = (byte*)WMALLOC(sigBlobSz, NULL, 0);
    if (sigBlob == NULL) { result = -864; goto done; }
    off = 0;
    MlDsaTest_PutLen(sigBlob + off, keyTypeNameSz); off += UINT32_SZ;
    WMEMCPY(sigBlob + off, keyTypeName, keyTypeNameSz); off += keyTypeNameSz;
    MlDsaTest_PutLen(sigBlob + off, sigSz); off += UINT32_SZ;
    WMEMCPY(sigBlob + off, sig, sigSz); off += sigSz;
    sigBlobSz = off;

    /* DoUserAuthRequestMlDsa with isCert=1 expects pk->publicKey to be the
     * leaf cert DER. Pass rfcBlobSz explicitly so dataToSign is sized from
     * the wire blob length, not the cert DER length. */
    WMEMSET(&authData, 0, sizeof(authData));
    authData.type                         = WOLFSSH_USERAUTH_PUBLICKEY;
    authData.username                     = (const byte*)username;
    authData.usernameSz                   = usernameSz;
    authData.serviceName                  = (const byte*)serviceName;
    authData.serviceNameSz                = serviceNameSz;
    authData.authName                     = (const byte*)authName;
    authData.authNameSz                   = authNameSz;
    authData.sf.publicKey.dataToSign      = dataToSign;
    authData.sf.publicKey.publicKeyType   = (const byte*)keyTypeName;
    authData.sf.publicKey.publicKeyTypeSz = keyTypeNameSz;
    authData.sf.publicKey.publicKey       = certDER;
    authData.sf.publicKey.publicKeySz     = certDERSz;
    authData.sf.publicKey.hasSignature    = 1;
    authData.sf.publicKey.isCert          = 1;
    authData.sf.publicKey.signature       = sigBlob;
    authData.sf.publicKey.signatureSz     = sigBlobSz;

    ret = wolfSSH_TestDoUserAuthRequestMlDsa(ssh, &authData, rfcBlobSz);
    if (ret != WS_SUCCESS) {
        printf("DoUserAuthRequestMlDsa cert-path valid (%s): "
               "ret=%d expected %d\n",
               keyTypeName, ret, WS_SUCCESS);
        result = -865;
    }

done:
    if (signingKeyInit) wc_MlDsaKey_Free(&signingKey);
    if (rngInit) wc_FreeRng(&rng);
    if (certDER    != NULL) WFREE(certDER,    NULL, 0);
    if (rfcBlob    != NULL) WFREE(rfcBlob,    NULL, 0);
    if (sigBlob    != NULL) WFREE(sigBlob,    NULL, 0);
    if (dataToSign != NULL) WFREE(dataToSign, NULL, 0);
    if (checkData  != NULL) WFREE(checkData,  NULL, 0);
    if (sig        != NULL) WFREE(sig,        NULL, 0);
    if (ssh != NULL) wolfSSH_free(ssh);
    if (ctx != NULL) wolfSSH_CTX_free(ctx);
    return result;
}
/* Cross-level mismatch: cert has ML-DSA key at a different level than
 * keyTypeName claims. PublicKeyDecode fails, should return WS_CRYPTO_FAILED.
 * Requires both MLDSA44 (for the claimed type) and MLDSA65 (for the actual
 * key embedded in the cert). */
#if !defined(WOLFSSH_NO_MLDSA44) && !defined(WOLFSSH_NO_MLDSA65)
static int test_DoUserAuthRequestMlDsa_CertPath_WrongLevel(void)
{
    /* Claim ML-DSA-44 type but embed an ML-DSA-65 key in the cert. */
    static const char keyTypeName[]  = "x509v3-ssh-mldsa-44";
    static const char username[]     = "wolfssh";
    static const char serviceName[]  = "ssh-connection";
    static const char authName[]     = "publickey";
    const word32 keyTypeNameSz  = (word32)WSTRLEN(keyTypeName);
    const word32 usernameSz     = (word32)(sizeof(username)     - 1);
    const word32 serviceNameSz  = (word32)(sizeof(serviceName)  - 1);
    const word32 authNameSz     = (word32)(sizeof(authName)     - 1);

    WOLFSSH_CTX* ctx = NULL;
    WOLFSSH* ssh = NULL;
    MlDsaKey signingKey;
    int signingKeyInit = 0;
    WC_RNG rng;
    int rngInit = 0;
    Cert myCert;
    WS_UserAuthData authData;

    byte* certDER    = NULL;
    byte* sigBlob    = NULL;
    byte* dataToSign = NULL;
    word32 certDERSz    = 0;
    word32 dataToSignSz = 0;
    word32 off;
    int result = 0;
    int ret;

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_SERVER, NULL);
    if (ctx == NULL) return -880;
    ssh = wolfSSH_new(ctx);
    if (ssh == NULL) { result = -881; goto done; }
    ssh->sessionIdSz = 16;
    WMEMSET(ssh->sessionId, 0xA5, ssh->sessionIdSz);

    if (wc_InitRng(&rng) != 0) { result = -882; goto done; }
    rngInit = 1;

    if (wc_MlDsaKey_Init(&signingKey, NULL, INVALID_DEVID) != 0) {
        result = -883; goto done;
    }
    signingKeyInit = 1;
    if (wc_MlDsaKey_SetParams(&signingKey, WC_ML_DSA_65) != 0) {
        result = -884; goto done;
    }
    if (wc_MlDsaKey_MakeKey(&signingKey, &rng) != 0) {
        result = -885; goto done;
    }

    certDER = (byte*)WMALLOC(16384, NULL, 0);
    if (certDER == NULL) { result = -886; goto done; }

    wc_InitCert(&myCert);
    WSTRNCPY(myCert.subject.commonName, "wolfSSH-mldsa-test",
             CTC_NAME_SIZE - 1);
    myCert.subject.commonNameEnc = CTC_UTF8;
    WSTRNCPY(myCert.subject.country, "US", CTC_NAME_SIZE - 1);
    myCert.daysValid  = 365;
    myCert.selfSigned = 1;
    myCert.sigType    = CTC_ML_DSA_65;

    ret = wc_MakeCert_ex(&myCert, certDER, 16384, ML_DSA_65_TYPE,
                         &signingKey, &rng);
    if (ret <= 0) { result = -887; goto done; }
    ret = wc_SignCert_ex(ret, CTC_ML_DSA_65, certDER, 16384,
                         ML_DSA_65_TYPE, &signingKey, &rng);
    if (ret <= 0) { result = -888; goto done; }
    certDERSz = (word32)ret;

    /* Dummy sig blob: keyTypeName || one zero byte. */
    sigBlob = (byte*)WMALLOC(UINT32_SZ * 2 + keyTypeNameSz + 1, NULL, 0);
    if (sigBlob == NULL) { result = -889; goto done; }
    off = 0;
    MlDsaTest_PutLen(sigBlob + off, keyTypeNameSz); off += UINT32_SZ;
    WMEMCPY(sigBlob + off, keyTypeName, keyTypeNameSz); off += keyTypeNameSz;
    MlDsaTest_PutLen(sigBlob + off, 1); off += UINT32_SZ;
    sigBlob[off] = 0x00;

    /* Sized to match the checkData formula in DoUserAuthRequestMlDsa with
     * pubKeyBlobSz=0. Populated with zeros - not a valid payload, but
     * non-NULL so that if key-level enforcement ever relaxes, execution fails
     * at sig verify rather than crashing on a NULL deref. */
    dataToSignSz = UINT32_SZ * 5 + usernameSz + serviceNameSz + authNameSz +
                   BOOLEAN_SZ + keyTypeNameSz;
    dataToSign = (byte*)WMALLOC(dataToSignSz, NULL, 0);
    if (dataToSign == NULL) { result = -890; goto done; }
    WMEMSET(dataToSign, 0, dataToSignSz);

    WMEMSET(&authData, 0, sizeof(authData));
    authData.type                          = WOLFSSH_USERAUTH_PUBLICKEY;
    authData.username                      = (const byte*)username;
    authData.usernameSz                    = usernameSz;
    authData.serviceName                   = (const byte*)serviceName;
    authData.serviceNameSz                 = serviceNameSz;
    authData.authName                      = (const byte*)authName;
    authData.authNameSz                    = authNameSz;
    authData.sf.publicKey.publicKeyType    = (const byte*)keyTypeName;
    authData.sf.publicKey.publicKeyTypeSz  = keyTypeNameSz;
    authData.sf.publicKey.publicKey        = certDER;
    authData.sf.publicKey.publicKeySz      = certDERSz;
    authData.sf.publicKey.hasSignature     = 1;
    authData.sf.publicKey.isCert           = 1;
    authData.sf.publicKey.dataToSign       = dataToSign;
    authData.sf.publicKey.signature        = sigBlob;
    authData.sf.publicKey.signatureSz      = UINT32_SZ * 2 + keyTypeNameSz + 1;

    ret = wolfSSH_TestDoUserAuthRequestMlDsa(ssh, &authData, 0);
    if (ret == WS_SUCCESS) {
        printf("DoUserAuthRequestMlDsa cert-path wrong-level: "
               "wrongfully accepted\n");
        result = -891;
    }
    else if (ret != WS_CRYPTO_FAILED) {
        printf("DoUserAuthRequestMlDsa cert-path wrong-level: "
               "ret=%d expected %d\n",
               ret, WS_CRYPTO_FAILED);
        result = -892;
    }

done:
    if (signingKeyInit) wc_MlDsaKey_Free(&signingKey);
    if (rngInit) wc_FreeRng(&rng);
    if (certDER    != NULL) WFREE(certDER,    NULL, 0);
    if (sigBlob    != NULL) WFREE(sigBlob,    NULL, 0);
    if (dataToSign != NULL) WFREE(dataToSign, NULL, 0);
    if (ssh != NULL) wolfSSH_free(ssh);
    if (ctx != NULL) wolfSSH_CTX_free(ctx);
    return result;
}
#endif /* WOLFSSH_NO_MLDSA44 && WOLFSSH_NO_MLDSA65 */
#endif /* WOLFSSH_CERTS && WOLFSSL_CERT_GEN */
#endif /* WOLFSSH_CERTS */

#ifdef WOLFSSH_KEYGEN
static int test_PrepareUserAuthRequestMlDsa_Params(word32 keygenLevel,
        byte keyId, int derBufSz)
{
    WOLFSSH_CTX* ctx = NULL;
    WOLFSSH* ssh = NULL;
    WS_UserAuthData authData;
    WS_KeySignature keySig;
    byte* derKey = NULL;
    word32 payloadSz;
    int derKeySz;
    int result = 0;
    int ret;

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_CLIENT, NULL);
    if (ctx == NULL) return -900;
    ssh = wolfSSH_new(ctx);
    if (ssh == NULL) { result = -901; goto done; }

    derKey = (byte*)WMALLOC(derBufSz, NULL, 0);
    if (derKey == NULL) { result = -902; goto done; }

    derKeySz = wolfSSH_MakeMlDsaKey(derKey, (word32)derBufSz, keygenLevel);
    if (derKeySz < 0) { result = -903; goto done; }

    /* DER success path */
    WMEMSET(&authData, 0, sizeof(authData));
    WMEMSET(&keySig,   0, sizeof(keySig));
    payloadSz = 0;
    authData.sf.publicKey.privateKey   = derKey;
    authData.sf.publicKey.privateKeySz = (word32)derKeySz;
    authData.sf.publicKey.hasSignature = 0;
    keySig.keyId = keyId;
    keySig.heap  = NULL;
    ret = wolfSSH_TestPrepareUserAuthRequestMlDsa(ssh, &payloadSz,
            &authData, &keySig);
    if (ret != WS_SUCCESS) { result = -904; goto done; }
    wc_MlDsaKey_Free(&keySig.ks.mldsa.key);

    /* Fallback path: garbage fails PrivateKeyDecode, then fails OpenSSH
     * magic check; function must return an error (not leak the Init'd key). */
    {
        static const byte badKey[] = { 0xFF, 0xFE, 0x00, 0x01 };
        WMEMSET(&authData, 0, sizeof(authData));
        WMEMSET(&keySig,   0, sizeof(keySig));
        payloadSz = 0;
        authData.sf.publicKey.privateKey   = badKey;
        authData.sf.publicKey.privateKeySz = sizeof(badKey);
        authData.sf.publicKey.hasSignature = 0;
        keySig.keyId = keyId;
        keySig.heap  = NULL;
        ret = wolfSSH_TestPrepareUserAuthRequestMlDsa(ssh, &payloadSz,
                &authData, &keySig);
        if (ret == WS_SUCCESS) {
            wc_MlDsaKey_Free(&keySig.ks.mldsa.key);
            result = -905;
            goto done;
        }
    }

    /* hasSignature=1 path: exercises payload-size accumulation and sigSz. */
    {
        WMEMSET(&authData, 0, sizeof(authData));
        WMEMSET(&keySig,   0, sizeof(keySig));
        payloadSz = 0;
        authData.sf.publicKey.privateKey    = derKey;
        authData.sf.publicKey.privateKeySz  = (word32)derKeySz;
        authData.sf.publicKey.hasSignature  = 1;
        keySig.keyId = keyId;
        keySig.heap  = NULL;
        ret = wolfSSH_TestPrepareUserAuthRequestMlDsa(ssh, &payloadSz,
                &authData, &keySig);
        /* On failure the function frees the key internally; only free on
         * success paths where the key was left initialized for the caller. */
        if (ret != WS_SUCCESS) { result = -906; goto done; }
        if (keySig.sigSz == 0) {
            wc_MlDsaKey_Free(&keySig.ks.mldsa.key);
            result = -907; goto done;
        }
        if (payloadSz == 0) {
            wc_MlDsaKey_Free(&keySig.ks.mldsa.key);
            result = -908; goto done;
        }
        wc_MlDsaKey_Free(&keySig.ks.mldsa.key);
    }

done:
    WFREE(derKey, NULL, 0);
    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);
    return result;
}

#endif /* WOLFSSH_KEYGEN */

static int test_DoUserAuthRequestMlDsa(void)
{
    int ret;
#ifndef WOLFSSH_NO_MLDSA44
    ret = test_DoUserAuthRequestMlDsa_Params("ssh-mldsa-44", WC_ML_DSA_44);
    if (ret != 0) return ret;
#endif
#ifndef WOLFSSH_NO_MLDSA65
    ret = test_DoUserAuthRequestMlDsa_Params("ssh-mldsa-65", WC_ML_DSA_65);
    if (ret != 0) return ret;
#endif
#ifndef WOLFSSH_NO_MLDSA87
    ret = test_DoUserAuthRequestMlDsa_Params("ssh-mldsa-87", WC_ML_DSA_87);
    if (ret != 0) return ret;
#endif
    ret = test_DoUserAuthRequestMlDsa_BadAlgo();
    if (ret != 0) return ret;
#ifdef WOLFSSH_CERTS
#ifndef WOLFSSH_NO_MLDSA44
    ret = test_DoUserAuthRequestMlDsa_CertPath("x509v3-ssh-mldsa-44");
    if (ret != 0) return ret;
#endif
#ifndef WOLFSSH_NO_MLDSA65
    ret = test_DoUserAuthRequestMlDsa_CertPath("x509v3-ssh-mldsa-65");
    if (ret != 0) return ret;
#endif
#ifndef WOLFSSH_NO_MLDSA87
    ret = test_DoUserAuthRequestMlDsa_CertPath("x509v3-ssh-mldsa-87");
    if (ret != 0) return ret;
#endif
#ifdef WOLFSSL_CERT_GEN
#ifndef WOLFSSH_NO_MLDSA44
    ret = test_DoUserAuthRequestMlDsa_CertPath_Valid(
            "x509v3-ssh-mldsa-44", WC_ML_DSA_44, CTC_ML_DSA_44);
    if (ret != 0) return ret;
#endif
#ifndef WOLFSSH_NO_MLDSA65
    ret = test_DoUserAuthRequestMlDsa_CertPath_Valid(
            "x509v3-ssh-mldsa-65", WC_ML_DSA_65, CTC_ML_DSA_65);
    if (ret != 0) return ret;
#endif
#ifndef WOLFSSH_NO_MLDSA87
    ret = test_DoUserAuthRequestMlDsa_CertPath_Valid(
            "x509v3-ssh-mldsa-87", WC_ML_DSA_87, CTC_ML_DSA_87);
    if (ret != 0) return ret;
#endif
#if !defined(WOLFSSH_NO_MLDSA44) && !defined(WOLFSSH_NO_MLDSA65)
    ret = test_DoUserAuthRequestMlDsa_CertPath_WrongLevel();
    if (ret != 0) return ret;
#endif
#endif /* WOLFSSL_CERT_GEN */
#endif /* WOLFSSH_CERTS */
    return 0;
}

#ifdef WOLFSSH_KEYGEN
static int test_PrepareUserAuthRequestMlDsa(void)
{
    int ret = 0;
#ifndef WOLFSSH_NO_MLDSA44
    ret = test_PrepareUserAuthRequestMlDsa_Params(WOLFSSH_MLDSAKEY_44,
            ID_MLDSA44, WC_MLDSA_44_BOTH_KEY_DER_SIZE);
    if (ret != 0) return ret;
#endif
#ifndef WOLFSSH_NO_MLDSA65
    ret = test_PrepareUserAuthRequestMlDsa_Params(WOLFSSH_MLDSAKEY_65,
            ID_MLDSA65, WC_MLDSA_65_BOTH_KEY_DER_SIZE);
    if (ret != 0) return ret;
#endif
#ifndef WOLFSSH_NO_MLDSA87
    ret = test_PrepareUserAuthRequestMlDsa_Params(WOLFSSH_MLDSAKEY_87,
            ID_MLDSA87, WC_MLDSA_87_BOTH_KEY_DER_SIZE);
    if (ret != 0) return ret;
#endif
    (void)ret;
    return 0;
}

#ifdef WOLFSSH_CERTS
static int test_PrepareUserAuthRequestMlDsaCert_Params(word32 keygenLevel,
        byte keyId, int derBufSz)
{
    WOLFSSH_CTX* ctx = NULL;
    WOLFSSH* ssh = NULL;
    WS_UserAuthData authData;
    WS_KeySignature keySig;
    byte* derKey = NULL;
    word32 payloadSz;
    int derKeySz;
    int result = 0;
    int ret;

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_CLIENT, NULL);
    if (ctx == NULL) return -920;
    ssh = wolfSSH_new(ctx);
    if (ssh == NULL) { result = -921; goto done; }

    derKey = (byte*)WMALLOC(derBufSz, NULL, 0);
    if (derKey == NULL) { result = -922; goto done; }

    derKeySz = wolfSSH_MakeMlDsaKey(derKey, (word32)derBufSz, keygenLevel);
    if (derKeySz < 0) { result = -923; goto done; }

    /* Success path: good key, hasSignature=0 */
    WMEMSET(&authData, 0, sizeof(authData));
    WMEMSET(&keySig,   0, sizeof(keySig));
    payloadSz = 0;
    authData.sf.publicKey.privateKey   = derKey;
    authData.sf.publicKey.privateKeySz = (word32)derKeySz;
    authData.sf.publicKey.hasSignature = 0;
    keySig.keyId = keyId;
    keySig.heap  = NULL;
    ret = wolfSSH_TestPrepareUserAuthRequestMlDsaCert(ssh, &payloadSz,
            &authData, &keySig);
    if (ret != WS_SUCCESS) { result = -924; goto done; }
    wc_MlDsaKey_Free(&keySig.ks.mldsa.key);

    /* Bad key: exercises the PrivateKeyDecode failure free path */
    {
        static const byte badKey[] = { 0xFF, 0xFE, 0x00, 0x01 };
        WMEMSET(&authData, 0, sizeof(authData));
        WMEMSET(&keySig,   0, sizeof(keySig));
        payloadSz = 0;
        authData.sf.publicKey.privateKey   = badKey;
        authData.sf.publicKey.privateKeySz = sizeof(badKey);
        authData.sf.publicKey.hasSignature = 0;
        keySig.keyId = keyId;
        keySig.heap  = NULL;
        ret = wolfSSH_TestPrepareUserAuthRequestMlDsaCert(ssh, &payloadSz,
                &authData, &keySig);
        if (ret == WS_SUCCESS) { result = -925; goto done; }
    }

    /* hasSignature=1 path: exercises sigSz accumulation */
    {
        WMEMSET(&authData, 0, sizeof(authData));
        WMEMSET(&keySig,   0, sizeof(keySig));
        payloadSz = 0;
        authData.sf.publicKey.privateKey   = derKey;
        authData.sf.publicKey.privateKeySz = (word32)derKeySz;
        authData.sf.publicKey.hasSignature = 1;
        keySig.keyId = keyId;
        keySig.heap  = NULL;
        ret = wolfSSH_TestPrepareUserAuthRequestMlDsaCert(ssh, &payloadSz,
                &authData, &keySig);
        if (ret != WS_SUCCESS) {
            wc_MlDsaKey_Free(&keySig.ks.mldsa.key);
            result = -926; goto done;
        }
        if (keySig.sigSz == 0) {
            wc_MlDsaKey_Free(&keySig.ks.mldsa.key);
            result = -927; goto done;
        }
        if (payloadSz == 0) {
            wc_MlDsaKey_Free(&keySig.ks.mldsa.key);
            result = -928; goto done;
        }
        wc_MlDsaKey_Free(&keySig.ks.mldsa.key);
    }

done:
    WFREE(derKey, NULL, 0);
    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);
    return result;
}

static int test_PrepareUserAuthRequestMlDsaCert(void)
{
    int ret = 0;
#ifndef WOLFSSH_NO_MLDSA44
    ret = test_PrepareUserAuthRequestMlDsaCert_Params(WOLFSSH_MLDSAKEY_44,
            ID_X509V3_MLDSA44, WC_MLDSA_44_BOTH_KEY_DER_SIZE);
    if (ret != 0) return ret;
#endif
#ifndef WOLFSSH_NO_MLDSA65
    ret = test_PrepareUserAuthRequestMlDsaCert_Params(WOLFSSH_MLDSAKEY_65,
            ID_X509V3_MLDSA65, WC_MLDSA_65_BOTH_KEY_DER_SIZE);
    if (ret != 0) return ret;
#endif
#ifndef WOLFSSH_NO_MLDSA87
    ret = test_PrepareUserAuthRequestMlDsaCert_Params(WOLFSSH_MLDSAKEY_87,
            ID_X509V3_MLDSA87, WC_MLDSA_87_BOTH_KEY_DER_SIZE);
    if (ret != 0) return ret;
#endif
    (void)ret;
    return 0;
}
#endif /* WOLFSSH_CERTS */

#endif /* WOLFSSH_KEYGEN */

static int test_BuildUserAuthRequestMlDsa(void)
{
#ifndef WOLFSSH_NO_MLDSA44
    WOLFSSH_CTX* ctx = NULL;
    WOLFSSH*     ssh = NULL;
    WS_KeySignature keySig;
    WS_UserAuthData authData;
    byte  output[MLDSA_MAX_SIG_SIZE + 256];
    word32 idx = 0;
    word32 idx0 = 0;
    word32 idxBefore = 0;
    int   sigSz;
    int   result = 0;
    int   ret;

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_CLIENT, NULL);
    if (ctx == NULL) { result = -700; goto done; }
    ssh = wolfSSH_new(ctx);
    if (ssh == NULL) { result = -701; goto done; }

    ssh->sessionIdSz = 16;
    WMEMSET(ssh->sessionId, 0xA5, ssh->sessionIdSz);

    WMEMSET(&keySig, 0, sizeof(keySig));
    keySig.keyId = ID_MLDSA44;
    keySig.heap  = NULL;
    ret = wc_MlDsaKey_Init(&keySig.ks.mldsa.key, NULL, INVALID_DEVID);
    if (ret != 0) { result = -702; goto done; }
    {
        word32 kidx = 0;
        ret = wc_MlDsaKey_PrivateKeyDecode(&keySig.ks.mldsa.key,
                unitTestMlDsaPrivKey,
                (word32)sizeof(unitTestMlDsaPrivKey), &kidx);
    }
    if (ret != 0) {
        wc_MlDsaKey_Free(&keySig.ks.mldsa.key);
        result = -703;
        goto done;
    }
    sigSz = wc_MlDsaKey_SigSize(&keySig.ks.mldsa.key);
    if (sigSz < 0) {
        wc_MlDsaKey_Free(&keySig.ks.mldsa.key);
        result = -704;
        goto done;
    }
    keySig.sigSz = (word32)sigSz;

    WMEMSET(&authData, 0, sizeof(authData));
    authData.sf.publicKey.hasSignature    = 1;
    authData.sf.publicKey.publicKeyType   = (const byte*)"ssh-mldsa-44";
    authData.sf.publicKey.publicKeyTypeSz = 12;

    /* Write minimal auth-request header so (begin - sigStartIdx) > 0. */
    {
        static const char testUser[]   = "user";
        static const char testSvc[]    = "ssh-connection";
        static const char testMethod[] = "publickey";
        output[idx++] = MSGID_USERAUTH_REQUEST;
        MlDsaTest_PutLen(output + idx, (word32)WSTRLEN(testUser));
        idx += UINT32_SZ;
        WMEMCPY(output + idx, testUser, WSTRLEN(testUser));
        idx += (word32)WSTRLEN(testUser);
        MlDsaTest_PutLen(output + idx, (word32)WSTRLEN(testSvc));
        idx += UINT32_SZ;
        WMEMCPY(output + idx, testSvc, WSTRLEN(testSvc));
        idx += (word32)WSTRLEN(testSvc);
        MlDsaTest_PutLen(output + idx, (word32)WSTRLEN(testMethod));
        idx += UINT32_SZ;
        WMEMCPY(output + idx, testMethod, WSTRLEN(testMethod));
        idx += (word32)WSTRLEN(testMethod);
    }

    idxBefore = idx;
    ret = wolfSSH_TestBuildUserAuthRequestMlDsa(ssh, output, &idx,
            &authData, output, idx0, &keySig);

    wc_MlDsaKey_Free(&keySig.ks.mldsa.key);

    if (ret != WS_SUCCESS) {
        printf("BuildUserAuthRequestMlDsa failed: %d\n", ret);
        result = -705;
    }
    else {
        /* 3 length fields + algo name + sig bytes */
        word32 nameSz = (word32)WSTRLEN("ssh-mldsa-44");
        word32 expAdv = 3 * UINT32_SZ + nameSz + (word32)sigSz;
        if (idx - idxBefore != expAdv) {
            printf("BuildUserAuthRequestMlDsa idx advance wrong:"
                   " got %d expected %d\n",
                   (int)(idx - idxBefore), (int)expAdv);
            result = -706;
        }
    }

done:
    if (ssh) wolfSSH_free(ssh);
    if (ctx) wolfSSH_CTX_free(ctx);
    return result;
#else
    return 0;
#endif
}
#endif

/* IdentifyAsn1Key unit test
 *
 * Exercises every new wc_Free* error-path added in IdentifyAsn1Key:
 *  - wc_FreeRsaKey on RSA decode failure
 *  - wc_ecc_free on ECC decode failure
 *  - wc_ecc_free in the default: branch (unsupported curve)
 *  - wc_ed25519_free on Ed25519 decode failure
 * Each happy-path call implicitly exercises the failure-path frees for the
 * other key types.
 */
static int test_IdentifyAsn1Key(void)
{
    int result = 0;
    int ret;

#ifndef WOLFSSH_NO_RSA
    ret = IdentifyAsn1Key(unitTestRsaPrivKey, unitTestRsaPrivKeySz,
                          1, NULL, NULL);
    if (ret != ID_SSH_RSA) {
        printf("IdentifyAsn1Key: RSA priv failed, ret=%d\n", ret);
        result = -600; goto done;
    }
#endif

#ifndef WOLFSSH_NO_ECDSA_SHA2_NISTP256
    ret = IdentifyAsn1Key(unitTestEcc256PrivKey,
                          (word32)sizeof(unitTestEcc256PrivKey),
                          1, NULL, NULL);
    if (ret != ID_ECDSA_SHA2_NISTP256) {
        printf("IdentifyAsn1Key: ECC P-256 priv failed, ret=%d\n", ret);
        result = -601; goto done;
    }
#endif

#ifndef WOLFSSH_NO_ECDSA_SHA2_NISTP384
    ret = IdentifyAsn1Key(unitTestEcc384PrivKey,
                          (word32)sizeof(unitTestEcc384PrivKey),
                          1, NULL, NULL);
    if (ret != ID_ECDSA_SHA2_NISTP384) {
        printf("IdentifyAsn1Key: ECC P-384 priv failed, ret=%d\n", ret);
        result = -602; goto done;
    }
#endif

#ifndef WOLFSSH_NO_ECDSA_SHA2_NISTP521
    ret = IdentifyAsn1Key(unitTestEcc521PrivKey,
                          (word32)sizeof(unitTestEcc521PrivKey),
                          1, NULL, NULL);
    if (ret != ID_ECDSA_SHA2_NISTP521) {
        printf("IdentifyAsn1Key: ECC P-521 priv failed, ret=%d\n", ret);
        result = -603; goto done;
    }
#endif

#if !defined(WOLFSSH_NO_ED25519)
    ret = IdentifyAsn1Key(unitTestEd25519PrivKey,
                          (word32)sizeof(unitTestEd25519PrivKey),
                          1, NULL, NULL);
    if (ret != ID_ED25519) {
        printf("IdentifyAsn1Key: Ed25519 priv failed, ret=%d\n", ret);
        result = -604; goto done;
    }
#endif

#if !defined(WOLFSSH_NO_MLDSA) && !defined(WOLFSSH_NO_MLDSA44)
    ret = IdentifyAsn1Key(unitTestMlDsaPrivKey,
                          (word32)sizeof(unitTestMlDsaPrivKey),
                          1, NULL, NULL);
    if (ret != ID_MLDSA44) {
        printf("IdentifyAsn1Key: MlDsa priv failed, ret=%d\n", ret);
        result = -606;
        goto done;
    }

    /* Raw public key probe path: extract the public key from the private key
     * test vector, then pass the raw bytes (no SPKI wrapper) to
     * IdentifyAsn1Key. This exercises the level-probing fallback added for
     * certificate-extracted public keys. */
    {
        MlDsaKey mlKey;
        byte* mlPub = NULL;
        word32 mlPubSz = 0;
        word32 mlIdx = 0;

        if (wc_MlDsaKey_Init(&mlKey, NULL, INVALID_DEVID) != 0) {
            result = -607; goto done;
        }
        if (wc_MlDsaKey_PrivateKeyDecode(&mlKey, unitTestMlDsaPrivKey,
                                         sizeof(unitTestMlDsaPrivKey),
                                         &mlIdx) != 0) {
            wc_MlDsaKey_Free(&mlKey);
            result = -608; goto done;
        }
        {
            int mlPubSzInt = wc_MlDsaKey_PubSize(&mlKey);
            if (mlPubSzInt < 0) {
                wc_MlDsaKey_Free(&mlKey);
                result = -609; goto done;
            }
            mlPubSz = (word32)mlPubSzInt;
        }
        mlPub = (byte*)WMALLOC(mlPubSz, NULL, 0);
        if (mlPub == NULL) {
            wc_MlDsaKey_Free(&mlKey);
            result = -619; goto done;
        }
        if (wc_MlDsaKey_ExportPubRaw(&mlKey, mlPub, &mlPubSz) != 0) {
            WFREE(mlPub, NULL, 0);
            wc_MlDsaKey_Free(&mlKey);
            result = -610; goto done;
        }
        wc_MlDsaKey_Free(&mlKey);

        ret = IdentifyAsn1Key(mlPub, mlPubSz, 0, NULL, NULL);
        WFREE(mlPub, NULL, 0);
        if (ret != ID_MLDSA44) {
            printf("IdentifyAsn1Key: MlDsa raw pub probe failed, ret=%d\n",
                   ret);
            result = -611; goto done;
        }
    }
#endif

    /* Unsupported ECC curve: triggers wc_ecc_free in the default: branch
     * (wolfSSL has P-192) or the else branch (wolfSSL lacks P-192).
     * Either way the key must be freed and WS_UNIMPLEMENTED_E returned. */
#ifndef WOLFSSH_NO_ECDSA
    ret = IdentifyAsn1Key(unitTestEccUnsupportedCurveKey,
                          (word32)sizeof(unitTestEccUnsupportedCurveKey),
                          1, NULL, NULL);
    if (ret != WS_UNIMPLEMENTED_E) {
        printf("IdentifyAsn1Key: unsupported ECC curve expected "
               "WS_UNIMPLEMENTED_E, got %d\n", ret);
        result = -605; goto done;
    }
#endif

    /* Garbage: all decode attempts fail, all wc_Free* cleanup paths hit */
    {
        static const byte garbage[] = {0x00, 0x01, 0x02, 0x03};
        ret = IdentifyAsn1Key(garbage, (word32)sizeof(garbage), 1, NULL, NULL);
        if (ret != WS_UNIMPLEMENTED_E) {
            printf("IdentifyAsn1Key: garbage expected WS_UNIMPLEMENTED_E, "
                   "got %d\n", ret);
            result = -606; goto done;
        }
    }

done:
    return result;
}

#ifdef WOLFSSH_TEST_CERTMAN_PROMOTE

/* Read a whole file into a freshly malloc'd buffer. Caller frees *buf. */
static int certmanLoadFile(const char* fn, byte** buf, word32* bufSz)
{
    FILE* f;
    long sz;
    size_t rd;

    *buf = NULL;
    *bufSz = 0;

    f = fopen(fn, "rb");
    if (f == NULL)
        return -1;
    if (fseek(f, 0, SEEK_END) != 0 || (sz = ftell(f)) < 0) {
        fclose(f);
        return -1;
    }
#if LONG_MAX > 0xFFFFFFFFL
    /* The size is later stored in a word32; reject anything that would not
     * round-trip so *bufSz stays consistent with the allocated/read size. */
    if (sz > 0xFFFFFFFFL) {
        fclose(f);
        return -1;
    }
#endif
    rewind(f);

    *buf = (byte*)malloc((size_t)sz);
    if (*buf == NULL) {
        fclose(f);
        return -1;
    }
    rd = fread(*buf, 1, (size_t)sz, f);
    fclose(f);
    if (rd != (size_t)sz) {
        free(*buf);
        *buf = NULL;
        return -1;
    }

    *bufSz = (word32)sz;
    return 0;
}

/* Forge an end-entity cert whose issuer is the supplied cert and which is
 * signed with the supplied (non-CA) key. Fills der/derSz on success. */
static int certmanForgeChild(const byte* issuerCert, word32 issuerCertSz,
        const byte* issuerKey, word32 issuerKeySz, byte* der, word32* derSz)
{
    ecc_key key;
    WC_RNG rng;
    Cert cert;
    word32 idx = 0;
    int ret;
    int sz;
    int haveKey = 0, haveRng = 0;

    ret = wc_ecc_init(&key);
    if (ret == 0) {
        haveKey = 1;
        ret = wc_InitRng(&rng);
    }
    if (ret == 0) {
        haveRng = 1;
        ret = wc_EccPrivateKeyDecode(issuerKey, &idx, &key, issuerKeySz);
    }
    if (ret == 0)
        ret = wc_InitCert(&cert);
    if (ret == 0) {
        WSTRNCPY(cert.subject.country, "US", CTC_NAME_SIZE);
        WSTRNCPY(cert.subject.commonName, "Mallory", CTC_NAME_SIZE);
        cert.sigType = CTC_SHA256wECDSA;
        cert.daysValid = 365;
        cert.isCA = 0;
        ret = wc_SetIssuerBuffer(&cert, issuerCert, (int)issuerCertSz);
    }
    if (ret == 0) {
        /* Reuse the issuer key as the subject key; only the issuer and the
         * signature matter for the signer lookup under test. */
        sz = wc_MakeCert(&cert, der, *derSz, NULL, &key, &rng);
        if (sz < 0)
            ret = sz;
    }
    if (ret == 0) {
        sz = wc_SignCert(cert.bodySz, cert.sigType, der, *derSz, NULL, &key,
                &rng);
        if (sz < 0)
            ret = sz;
        else
            *derSz = (word32)sz;
    }

    if (haveRng)
        wc_FreeRng(&rng);
    if (haveKey)
        wc_ecc_free(&key);

    return ret;
}

/* Forge a cert with the given subject CN. When isCA is set the cert asserts
 * basicConstraints CA=TRUE. When keyUsage is non-NULL the cert carries a
 * KeyUsage extension with the named usage(s) (e.g. "keyCertSign" or
 * "digitalSignature"); NULL omits the extension entirely. The issuer name is
 * taken from issuerCert, the subject public key from subjectKey, and the cert
 * is signed with issuerKey. Fills der/derSz on success. */
static int certmanForgeCert(const char* cn, int isCA, const char* keyUsage,
        const byte* issuerCert, word32 issuerCertSz,
        ecc_key* issuerKey, ecc_key* subjectKey, byte* der, word32* derSz)
{
    WC_RNG rng;
    Cert cert;
    int ret;
    int sz;
    int haveRng = 0;

    ret = wc_InitRng(&rng);
    if (ret == 0) {
        haveRng = 1;
        ret = wc_InitCert(&cert);
    }
    if (ret == 0) {
        /* wc_InitCert zeroed the struct, so leaving the final byte untouched
         * keeps the name NUL-terminated and avoids a strncpy truncation
         * warning on the runtime cn pointer. */
        WSTRNCPY(cert.subject.country, "US", CTC_NAME_SIZE - 1);
        WSTRNCPY(cert.subject.commonName, cn, CTC_NAME_SIZE - 1);
        cert.sigType = CTC_SHA256wECDSA;
        cert.daysValid = 365;
        cert.isCA = isCA;
        if (keyUsage != NULL) {
        #ifdef WOLFSSL_CERT_EXT
            ret = wc_SetKeyUsage(&cert, keyUsage);
        #else
            ret = BAD_FUNC_ARG;
        #endif
        }
    }
    if (ret == 0)
        ret = wc_SetIssuerBuffer(&cert, issuerCert, (int)issuerCertSz);
    if (ret == 0) {
        sz = wc_MakeCert(&cert, der, *derSz, NULL, subjectKey, &rng);
        if (sz < 0)
            ret = sz;
    }
    if (ret == 0) {
        sz = wc_SignCert(cert.bodySz, cert.sigType, der, *derSz, NULL,
                issuerKey, &rng);
        if (sz < 0)
            ret = sz;
        else
            *derSz = (word32)sz;
    }

    if (haveRng)
        wc_FreeRng(&rng);

    return ret;
}

static void certmanPutU32(byte* p, word32 v)
{
    p[0] = (byte)(v >> 24);
    p[1] = (byte)(v >> 16);
    p[2] = (byte)(v >> 8);
    p[3] = (byte)(v);
}

/* Append a length-prefixed cert (the framing VerifyCerts_buffer expects).
 * chainCap is the capacity of chain; on insufficient space the chain is left
 * unchanged so a cert-size regression surfaces as a failed assertion rather
 * than memory corruption. The subtractions are ordered to avoid word32
 * underflow. */
static word32 certmanAppendCert(byte* chain, word32 chainCap, word32 chainSz,
        const byte* cert, word32 certSz)
{
    if (chainSz > chainCap ||
            certSz > chainCap - chainSz ||
            UINT32_SZ > chainCap - chainSz - certSz) {
        return chainSz;
    }
    certmanPutU32(chain + chainSz, certSz);
    chainSz += UINT32_SZ;
    WMEMCPY(chain + chainSz, cert, certSz);
    chainSz += certSz;
    return chainSz;
}

/* Regression test: a peer-supplied end-entity (non-CA)
 * certificate presented at an intermediate position in a chain must not be
 * promoted into the cert manager's trust store. If it were, the holder of any
 * ordinary leaf cert issued by a trusted root could then forge certs binding
 * arbitrary SSH principals.
 *
 * Fred's cert is a non-CA leaf issued by the test root (ca-cert-ecc). We forge
 * a child ("Mallory") issued by Fred and signed with Fred's key, then:
 *   1. Sanity: with Fred explicitly trusted as a CA, the forged child gets
 *      past the no-signer stage, proving the child is well-formed and chains
 *      to Fred -- so the regression check below cannot pass vacuously.
 *   2. Regression: run the attack chain [child, fred] through verify (a
 *      vulnerable build promotes Fred here), then confirm the store was not
 *      mutated -- verifying the child alone must now fail with
 *      WS_CERT_NO_SIGNER_E. */
static int test_CertMan_NoPromoteNonCaIntermediate(void)
{
    int result = 0;
    int ret;
    byte* root = NULL;
    byte* fred = NULL;
    byte* fredKey = NULL;
    word32 rootSz = 0, fredSz = 0, fredKeySz = 0;
    byte child[2048];
    word32 childSz = sizeof(child);
    byte chain[6144];
    word32 chainSz;
    WOLFSSH_CERTMAN* cm = NULL;

    if (certmanLoadFile("./keys/ca-cert-ecc.der", &root, &rootSz) != 0) {
        printf("CertMan: can't load root cert\n");
        result = -900; goto done;
    }
    if (certmanLoadFile("./keys/fred-cert.der", &fred, &fredSz) != 0) {
        printf("CertMan: can't load fred cert\n");
        result = -901; goto done;
    }
    if (certmanLoadFile("./keys/fred-key.der", &fredKey, &fredKeySz) != 0) {
        printf("CertMan: can't load fred key\n");
        result = -902; goto done;
    }

    ret = certmanForgeChild(fred, fredSz, fredKey, fredKeySz, child, &childSz);
    if (ret != 0) {
        printf("CertMan: forge child failed, ret=%d\n", ret);
        result = -903; goto done;
    }

    /* 1. Sanity: with Fred explicitly trusted, the child chains to Fred. */
    cm = wolfSSH_CERTMAN_new(NULL);
    if (cm == NULL) {
        result = -904; goto done;
    }
    if (wolfSSH_CERTMAN_LoadRootCA_buffer(cm, root, rootSz) != WS_SUCCESS) {
        result = -905; goto done;
    }
    if (wolfSSH_CERTMAN_LoadRootCA_buffer(cm, fred, fredSz) != WS_SUCCESS) {
        result = -906; goto done;
    }
    chainSz = certmanAppendCert(chain, (word32)sizeof(chain), 0,
            child, childSz);
    ret = wolfSSH_CERTMAN_VerifyCerts_buffer(cm, chain, chainSz, 1);
    if (ret == WS_CERT_NO_SIGNER_E) {
        printf("CertMan: sanity check failed, child didn't chain to Fred\n");
        result = -907; goto done;
    }
    wolfSSH_CERTMAN_free(cm);
    cm = NULL;

    /* 2. Regression: Fred NOT explicitly trusted. Run the attack chain so a
     *    vulnerable build would promote Fred, then confirm the store was not
     *    mutated. */
    cm = wolfSSH_CERTMAN_new(NULL);
    if (cm == NULL) {
        result = -908; goto done;
    }
    if (wolfSSH_CERTMAN_LoadRootCA_buffer(cm, root, rootSz) != WS_SUCCESS) {
        result = -909; goto done;
    }

    chainSz = certmanAppendCert(chain, (word32)sizeof(chain), 0,
            child, childSz);
    chainSz = certmanAppendCert(chain, (word32)sizeof(chain), chainSz,
            fred, fredSz);
    /* The attack chain itself must be rejected. */
    ret = wolfSSH_CERTMAN_VerifyCerts_buffer(cm, chain, chainSz, 2);
    if (ret == WS_SUCCESS) {
        printf("CertMan: attack chain unexpectedly verified\n");
        result = -910; goto done;
    }

    /* The trust store must be unchanged: verifying the forged child alone must
     * now fail with no available signer, proving Fred was not promoted. */
    chainSz = certmanAppendCert(chain, (word32)sizeof(chain), 0,
            child, childSz);
    ret = wolfSSH_CERTMAN_VerifyCerts_buffer(cm, chain, chainSz, 1);
    if (ret != WS_CERT_NO_SIGNER_E) {
        printf("CertMan: non-CA intermediate was promoted! ret=%d\n", ret);
        result = -911; goto done;
    }

done:
    if (cm != NULL)
        wolfSSH_CERTMAN_free(cm);
    free(root);
    free(fred);
    free(fredKey);
    return result;
}

/* Drives CertManIntermediateIsCA through a forged [leaf <- intermediate] chain
 * with only the root trusted, so the intermediate CA must be promoted for the
 * leaf to find a signer.
 *
 * interKeyUsage selects the intermediate's KeyUsage extension:
 *   NULL              omits KeyUsage entirely. Pins the extKeyUsageSet guard:
 *                     without it the intermediate (extKeyUsage==0) would be
 *                     wrongly demoted to non-CA.
 *   "keyCertSign"     the RFC 5280 conforming CA case (needs cert-ext support).
 *   "digitalSignature" has KeyUsage but lacks keyCertSign: intermediate
 *                     CA must be demoted (keyCertSign-rejection branch).
 *
 * expectPromote==1 asserts the intermediate was promoted (verify returns
 * anything but WS_CERT_NO_SIGNER_E); ==0 asserts it was not (verify returns
 * WS_CERT_NO_SIGNER_E). Promotion is the unit under test, not full chain
 * success: with FPKI profile enforcement (--enable-all) a promoted chain's
 * synthetic leaf is rejected later with WS_CERT_PROFILE_E, which is
 * orthogonal -- hence the "anything but WS_CERT_NO_SIGNER_E" success criterion
 * mirroring the negative test's sanity check. */
static int certmanCheckIntermediate(const char* interKeyUsage,
                                     int expectPromote)
{
    int result = 0;
    int ret;
    byte* root = NULL;
    byte* rootKeyBuf = NULL;
    word32 rootSz = 0, rootKeySz = 0;
    byte inter[2048];
    word32 interSz = sizeof(inter);
    byte leaf[2048];
    word32 leafSz = sizeof(leaf);
    byte chain[6144];
    word32 chainSz;
    word32 idx;
    ecc_key rootKey, interKey, leafKey;
    int haveRootKey = 0, haveInterKey = 0, haveLeafKey = 0;
    WC_RNG rng;
    int haveRng = 0;
    WOLFSSH_CERTMAN* cm = NULL;

    if (certmanLoadFile("./keys/ca-cert-ecc.der", &root, &rootSz) != 0) {
        printf("CertMan: can't load root cert\n");
        result = -920; goto done;
    }
    if (certmanLoadFile("./keys/ca-key-ecc.der",
                        &rootKeyBuf, &rootKeySz) != 0) {
        printf("CertMan: can't load root key\n");
        result = -921; goto done;
    }

    if (wc_InitRng(&rng) != 0) {
        result = -922; goto done;
    }
    haveRng = 1;

    /* Only the root key must match the trusted root cert; the intermediate and
     * leaf use freshly generated keys. */
    if (wc_ecc_init(&rootKey) != 0) {
        result = -923; goto done;
    }
    haveRootKey = 1;
    idx = 0;
    if (wc_EccPrivateKeyDecode(rootKeyBuf, &idx, &rootKey, rootKeySz) != 0) {
        result = -924; goto done;
    }
    if (wc_ecc_init(&interKey) != 0) {
        result = -925; goto done;
    }
    haveInterKey = 1;
    if (wc_ecc_make_key(&rng, 32, &interKey) != 0) {
        result = -926; goto done;
    }
    if (wc_ecc_init(&leafKey) != 0) {
        result = -927; goto done;
    }
    haveLeafKey = 1;
    if (wc_ecc_make_key(&rng, 32, &leafKey) != 0) {
        result = -928; goto done;
    }

    /* Intermediate CA signed by the root. */
    ret = certmanForgeCert("IntermediateCA", 1, interKeyUsage,
            root, rootSz, &rootKey, &interKey, inter, &interSz);
    if (ret != 0) {
        printf("CertMan: forge intermediate failed, ret=%d\n", ret);
        result = -929; goto done;
    }

    /* Leaf signed by the intermediate. */
    ret = certmanForgeCert("ValidLeaf", 0, NULL, inter, interSz,
            &interKey, &leafKey, leaf, &leafSz);
    if (ret != 0) {
        printf("CertMan: forge leaf failed, ret=%d\n", ret);
        result = -930; goto done;
    }

    /* Trust only the root; the valid intermediate CA must be promoted so the
     * leaf chains all the way up. */
    cm = wolfSSH_CERTMAN_new(NULL);
    if (cm == NULL) {
        result = -931; goto done;
    }
    if (wolfSSH_CERTMAN_LoadRootCA_buffer(cm, root, rootSz) != WS_SUCCESS) {
        result = -932; goto done;
    }

    chainSz = certmanAppendCert(chain, (word32)sizeof(chain), 0,
            leaf, leafSz);
    chainSz = certmanAppendCert(chain, (word32)sizeof(chain), chainSz,
            inter, interSz);
    ret = wolfSSH_CERTMAN_VerifyCerts_buffer(cm, chain, chainSz, 2);
    if (expectPromote && ret == WS_CERT_NO_SIGNER_E) {
        printf("CertMan: valid intermediate CA not promoted, ret=%d\n", ret);
        result = -933; goto done;
    }
    if (!expectPromote && ret != WS_CERT_NO_SIGNER_E) {
        printf("CertMan: intermediate CA without keyCertSign was promoted, "
               "ret=%d\n", ret);
        result = -934; goto done;
    }

done:
    if (cm != NULL)
        wolfSSH_CERTMAN_free(cm);
    if (haveRootKey)
        wc_ecc_free(&rootKey);
    if (haveInterKey)
        wc_ecc_free(&interKey);
    if (haveLeafKey)
        wc_ecc_free(&leafKey);
    if (haveRng)
        wc_FreeRng(&rng);
    free(root);
    free(rootKeyBuf);
    return result;
}

static int test_CertMan_PromoteValidCaIntermediate(void)
{
    int result;

    /* A CA intermediate with no KeyUsage extension must still be promoted. */
    result = certmanCheckIntermediate(NULL, 1);
#ifdef WOLFSSL_CERT_EXT
    /* As must a CA intermediate that explicitly asserts keyCertSign. */
    if (result == 0)
        result = certmanCheckIntermediate("keyCertSign", 1);
#ifndef ALLOW_INVALID_CERTSIGN
    /* But a CA intermediate carrying a KeyUsage extension that omits
     * keyCertSign must be rejected (the keyCertSign-rejection branch). */
    if (result == 0)
        result = certmanCheckIntermediate("digitalSignature", 0);
#endif
#endif
    return result;
}

#endif /* WOLFSSH_TEST_CERTMAN_PROMOTE */

/* Tests below install a custom allocator via wolfSSL_SetAllocators. The
 * wolfSSL_Malloc_cb / wolfSSL_Free_cb / wolfSSL_Realloc_cb typedefs gain
 * extra parameters when wolfSSL is built with WOLFSSL_STATIC_MEMORY or
 * WOLFSSL_DEBUG_MEMORY, so the capturing-allocator tests only compile
 * against the default signature. */
#if !defined(WOLFSSL_STATIC_MEMORY) && !defined(WOLFSSL_DEBUG_MEMORY)
#define WOLFSSH_TEST_CAPTURING_ALLOCATOR

/* Retain-on-free allocator. Pass-through malloc/realloc; the free
 * callback unconditionally diverts the pointer onto a retain list so
 * the buffer's contents can be inspected after the API under test
 * has called free on it. Install only across the narrow window of
 * interest so allocations made before/after use the default allocator
 * and can be paired with default free. */
typedef struct RetainedBuf {
    void* ptr;
    struct RetainedBuf* next;
} RetainedBuf;

static RetainedBuf* retainedFrees = NULL;

static void* RetainMalloc(size_t size)
{
    return malloc(size);
}

static void RetainFree(void* ptr)
{
    RetainedBuf* node;
    if (ptr == NULL)
        return;
    node = (RetainedBuf*)malloc(sizeof(*node));
    if (node == NULL) {
        /* On bookkeeping failure, fall through to a real free; the
         * test will not be able to inspect this buffer but we do not
         * leak the underlying allocation. */
        free(ptr);
        return;
    }
    node->ptr = ptr;
    node->next = retainedFrees;
    retainedFrees = node;
}

static void* RetainRealloc(void* ptr, size_t size)
{
    return realloc(ptr, size);
}

static int IsRetained(void* p)
{
    RetainedBuf* r;
    for (r = retainedFrees; r != NULL; r = r->next) {
        if (r->ptr == p)
            return 1;
    }
    return 0;
}

static void DrainRetained(void)
{
    RetainedBuf* r = retainedFrees;
    while (r != NULL) {
        RetainedBuf* next = r->next;
        free(r->ptr);
        free(r);
        r = next;
    }
    retainedFrees = NULL;
}

/* Verify SshResourceFree wipes secrets that live inside the WOLFSSH struct
 * before the struct is released:
 *   - ssh->k:       the DH/ECDH shared secret
 *   - ssh->keys:    active session encryption + MAC keys (our direction)
 *   - ssh->peerKeys: active session encryption + MAC keys (peer direction)
 * Mutation testing flagged each ForceZero in SshResourceFree as having no
 * coverage; removing any of them would leave key material in heap memory
 * after wolfSSH_free. To inspect the bytes after free without touching
 * freed memory, the test installs the retain-on-free allocator just
 * around wolfSSH_free so its frees are diverted onto a retain list. */
static int test_SshResourceFree_zeroesSecrets(void)
{
    WOLFSSH_CTX* ctx = NULL;
    WOLFSSH* ssh = NULL;
    word32 markedSz;
    word32 i;
    const byte* keysBytes;
    const byte* peerKeysBytes;
    int result = 0;
    int retainInstalled = 0;
    wolfSSL_Malloc_cb prevMf = NULL;
    wolfSSL_Free_cb prevFf = NULL;
    wolfSSL_Realloc_cb prevRf = NULL;

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_SERVER, NULL);
    if (ctx == NULL)
        return -700;
    ssh = wolfSSH_new(ctx);
    if (ssh == NULL) {
        result = -701;
        goto out;
    }

    markedSz = (word32)sizeof(ssh->k);
    WMEMSET(ssh->k, 0xA5, markedSz);
    ssh->kSz = markedSz;
    WMEMSET(&ssh->keys, 0xA5, sizeof(ssh->keys));
    WMEMSET(&ssh->peerKeys, 0xA5, sizeof(ssh->peerKeys));

    wolfSSL_GetAllocators(&prevMf, &prevFf, &prevRf);
    /* Allocators unchanged on failure; nothing to restore. */
    if (wolfSSL_SetAllocators(RetainMalloc, RetainFree,
                              RetainRealloc) != 0) {
        result = -702;
        goto out;
    }
    retainInstalled = 1;
    wolfSSH_free(ssh);
    wolfSSL_SetAllocators(prevMf, prevFf, prevRf);
    retainInstalled = 0;

    if (!IsRetained(ssh)) {
        result = -703;
        goto out;
    }

    for (i = 0; i < markedSz; i++) {
        if (ssh->k[i] != 0) {
            result = -704;
            goto out;
        }
    }

    keysBytes = (const byte*)&ssh->keys;
    for (i = 0; i < (word32)sizeof(ssh->keys); i++) {
        if (keysBytes[i] != 0) {
            result = -705;
            goto out;
        }
    }

    peerKeysBytes = (const byte*)&ssh->peerKeys;
    for (i = 0; i < (word32)sizeof(ssh->peerKeys); i++) {
        if (peerKeysBytes[i] != 0) {
            result = -706;
            goto out;
        }
    }

out:
    if (retainInstalled)
        wolfSSL_SetAllocators(prevMf, prevFf, prevRf);
    DrainRetained();
    if (ctx != NULL)
        wolfSSH_CTX_free(ctx);
    return result;
}

/* Verify HandshakeInfoFree wipes the HandshakeInfo before releasing it:
 *   - hs->keys / hs->peerKeys: negotiated session enc+MAC keys
 *   - hs->e / hs->x:           KEX public value and ephemeral private
 *   - hs->privKey:             ephemeral KEX key union
 * Mutation testing flagged the ForceZero(hs, sizeof(HandshakeInfo)) in
 * HandshakeInfoFree (src/internal.c) as uncovered; removing it would leave
 * this material in heap memory after free. wolfSSH_TestFreeHandshake exposes
 * the free path; the retain-on-free allocator diverts the freed block so its
 * bytes can be inspected. Only data fields are marked - pointer fields stay
 * NULL (from wolfSSH_new zero-init) and the useX/kexHashId flags stay 0 so no
 * per-key free runs over the poisoned bytes. */
static int test_HandshakeInfoFree_zeroesSecrets(void)
{
    WOLFSSH_CTX* ctx = NULL;
    WOLFSSH* ssh = NULL;
    HandshakeInfo* hs = NULL;
    word32 i;
    const byte* p;
    int result = 0;
    int retainInstalled = 0;
    wolfSSL_Malloc_cb prevMf = NULL;
    wolfSSL_Free_cb prevFf = NULL;
    wolfSSL_Realloc_cb prevRf = NULL;

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_SERVER, NULL);
    if (ctx == NULL)
        return -760;
    ssh = wolfSSH_new(ctx);
    if (ssh == NULL) {
        result = -761;
        goto out;
    }
    hs = ssh->handshake;
    if (hs == NULL) {
        result = -762;
        goto out;
    }

    WMEMSET(&hs->keys, 0xA5, sizeof(hs->keys));
    WMEMSET(&hs->peerKeys, 0xA5, sizeof(hs->peerKeys));
    WMEMSET(hs->e, 0xA5, sizeof(hs->e));
    WMEMSET(hs->x, 0xA5, sizeof(hs->x));
    WMEMSET(&hs->privKey, 0xA5, sizeof(hs->privKey));

    wolfSSL_GetAllocators(&prevMf, &prevFf, &prevRf);
    if (wolfSSL_SetAllocators(RetainMalloc, RetainFree,
                              RetainRealloc) != 0) {
        result = -763;
        goto out;
    }
    retainInstalled = 1;
    wolfSSH_TestFreeHandshake(ssh); /* frees hs via HandshakeInfoFree */
    wolfSSL_SetAllocators(prevMf, prevFf, prevRf);
    retainInstalled = 0;

    if (!IsRetained(hs)) {
        result = -764;
        goto out;
    }

    p = (const byte*)&hs->keys;
    for (i = 0; i < (word32)sizeof(hs->keys); i++)
        if (p[i] != 0) { result = -765; goto out; }
    p = (const byte*)&hs->peerKeys;
    for (i = 0; i < (word32)sizeof(hs->peerKeys); i++)
        if (p[i] != 0) { result = -766; goto out; }
    for (i = 0; i < (word32)sizeof(hs->e); i++)
        if (hs->e[i] != 0) { result = -767; goto out; }
    for (i = 0; i < (word32)sizeof(hs->x); i++)
        if (hs->x[i] != 0) { result = -768; goto out; }
    p = (const byte*)&hs->privKey;
    for (i = 0; i < (word32)sizeof(hs->privKey); i++)
        if (p[i] != 0) { result = -769; goto out; }

out:
    if (retainInstalled)
        wolfSSL_SetAllocators(prevMf, prevFf, prevRf);
    DrainRetained();
    if (ctx != NULL)
        wolfSSH_CTX_free(ctx);
    return result;
}

#endif /* WOLFSSH_TEST_CAPTURING_ALLOCATOR */

#ifndef WOLFSSH_NO_DH
/* Verify KeyAgreeDh_client zeroes the ephemeral DH private key
 * ssh->handshake->x before returning. The ForceZero is unconditional in
 * the function (runs even if wc_DhAgree fails), so the test does not need
 * to feed a valid peer public key - it just needs to observe that x is
 * wiped after the call returns. The test hook wolfSSH_TestKeyAgreeDh_client
 * exposes the static function. */
static int test_KeyAgreeDh_client_zeroesEphemeralPrivKey(void)
{
    WOLFSSH_CTX* ctx = NULL;
    WOLFSSH* ssh = NULL;
    HandshakeInfo* hs = NULL;
    byte bogusF[256];
    word32 markedSz;
    word32 i;
    int result = 0;
    int dhInited = 0;

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_SERVER, NULL);
    if (ctx == NULL)
        return -710;
    ssh = wolfSSH_new(ctx);
    if (ssh == NULL) {
        wolfSSH_CTX_free(ctx);
        return -711;
    }

    /* wolfSSH_new already allocated and zero-initialised ssh->handshake;
     * use it directly. wolfSSH_free will release it via HandshakeInfoFree. */
    hs = ssh->handshake;
    if (hs == NULL) {
        result = -712;
        goto cleanup;
    }

    if (wc_InitDhKey(&hs->privKey.dh) != 0) {
        result = -713;
        goto cleanup;
    }
    dhInited = 1;

    markedSz = (word32)sizeof(hs->x);
    WMEMSET(hs->x, 0xA5, markedSz);
    hs->xSz = markedSz;

    /* No prime group is set, so wc_DhCheckPubKey fails before wc_DhAgree is
     * reached. The ForceZero on x is unconditional and runs regardless. */
    WMEMSET(bogusF, 0xCC, sizeof(bogusF));
    (void)wolfSSH_TestKeyAgreeDh_client(ssh, WC_HASH_TYPE_SHA256,
            bogusF, (word32)sizeof(bogusF));
    /* wc_FreeDhKey was called inside the test hook; do not free again. */
    dhInited = 0;

    for (i = 0; i < markedSz; i++) {
        if (hs->x[i] != 0) {
            result = -714;
            break;
        }
    }

cleanup:
    if (dhInited)
        wc_FreeDhKey(&ssh->handshake->privKey.dh);
    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);
    return result;
}

/* Verify KeyAgreeDh_server rejects a degenerate peer DH public key.
 * The peer public 'e' is read from ssh->handshake->e; a value of 1 sits at
 * the low end of RFC 4253 section 8's permitted [1, p-1] range, but it is a
 * weak/degenerate value that wc_DhCheckPubKey rejects (stricter than the
 * RFC's bare minimum) before the shared secret is computed. Without that
 * guard wc_DhAgree would happily derive the degenerate secret 1. */
static int test_KeyAgreeDh_server_rejectsBadPeerPublic(void)
{
    WOLFSSH_CTX* ctx = NULL;
    WOLFSSH* ssh = NULL;
    byte f[MAX_KEX_KEY_SZ];
    word32 fSz = (word32)sizeof(f);
    int result = 0;

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_SERVER, NULL);
    if (ctx == NULL)
        return -730;
    ssh = wolfSSH_new(ctx);
    if (ssh == NULL || ssh->handshake == NULL) {
        result = -731;
        goto out;
    }
#ifndef WOLFSSH_NO_DH_GROUP14_SHA256
    ssh->handshake->kexId = ID_DH_GROUP14_SHA256;
#elif !defined(WOLFSSH_NO_DH_GROUP16_SHA512)
    ssh->handshake->kexId = ID_DH_GROUP16_SHA512;
#elif !defined(WOLFSSH_NO_DH_GROUP14_SHA1)
    ssh->handshake->kexId = ID_DH_GROUP14_SHA1;
#elif !defined(WOLFSSH_NO_DH_GROUP1_SHA1)
    ssh->handshake->kexId = ID_DH_GROUP1_SHA1;
#else
    /* No fixed DH group enabled; fail rather than silently pass without
     * exercising the peer-key check. */
    result = -733;
    goto out;
#endif

    /* Degenerate peer public key e = 1 (yields the shared secret 1). */
    ssh->handshake->e[0] = 0x01;
    ssh->handshake->eSz = 1;

    if (wolfSSH_TestKeyAgreeDh_server(ssh, WC_HASH_TYPE_SHA256, f, &fSz) == 0) {
        /* The degenerate peer public must not be accepted. */
        result = -732;
    }

out:
    if (ssh != NULL)
        wolfSSH_free(ssh);
    if (ctx != NULL)
        wolfSSH_CTX_free(ctx);
    return result;
}

/* Verify KeyAgreeDh_client rejects a degenerate peer DH public key. The
 * peer public 'f' is passed straight to the function; a value of 1 sits at the
 * low end of RFC 4253 section 8's permitted [1, p-1] range, but it is a
 * weak/degenerate value that the wc_DhCheckPubKey guard rejects (stricter than
 * the RFC's bare minimum) before the shared secret is used.
 * wolfSSH_TestSetDhKexKey installs the prime
 * group and generates a real ephemeral key pair first, mirroring SendKexDhInit,
 * so the rejection is driven by the bad peer key rather than a missing private
 * exponent. This guard is defense-in-depth: wc_DhAgree in wolfCrypt also
 * enforces the same range, so the test confirms the client rejection behavior
 * but does not isolate the wolfSSH check from the underlying wolfCrypt one. */
static int test_KeyAgreeDh_client_rejectsBadPeerPublic(void)
{
    WOLFSSH_CTX* ctx = NULL;
    WOLFSSH* ssh = NULL;
    byte f[1];
    int result = 0;

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_CLIENT, NULL);
    if (ctx == NULL)
        return -750;
    ssh = wolfSSH_new(ctx);
    if (ssh == NULL || ssh->handshake == NULL) {
        result = -751;
        goto out;
    }
#ifndef WOLFSSH_NO_DH_GROUP14_SHA256
    ssh->handshake->kexId = ID_DH_GROUP14_SHA256;
#elif !defined(WOLFSSH_NO_DH_GROUP16_SHA512)
    ssh->handshake->kexId = ID_DH_GROUP16_SHA512;
#elif !defined(WOLFSSH_NO_DH_GROUP14_SHA1)
    ssh->handshake->kexId = ID_DH_GROUP14_SHA1;
#elif !defined(WOLFSSH_NO_DH_GROUP1_SHA1)
    ssh->handshake->kexId = ID_DH_GROUP1_SHA1;
#else
    /* No fixed DH group enabled; fail rather than silently pass without
     * exercising the peer-key check. */
    result = -754;
    goto out;
#endif

    /* Install the prime group on the client's ephemeral DH key, as the client
     * KEX path does before KeyAgreeDh_client runs. */
    if (wolfSSH_TestSetDhKexKey(ssh) != 0) {
        result = -752;
        goto out;
    }

    /* Degenerate peer public key f = 1 (yields the shared secret 1). */
    f[0] = 0x01;

    if (wolfSSH_TestKeyAgreeDh_client(ssh, WC_HASH_TYPE_SHA256, f,
            (word32)sizeof(f)) == 0) {
        /* The degenerate peer public must not be accepted. */
        result = -753;
    }

out:
    if (ssh != NULL)
        wolfSSH_free(ssh);
    if (ctx != NULL)
        wolfSSH_CTX_free(ctx);
    return result;
}

#if defined(WOLFSSH_SMALL_STACK) && defined(WOLFSSH_TEST_CAPTURING_ALLOCATOR)
/* Size-tracked, poisoning capture allocator. AllocHeader stores the
 * user-requested size in front of each allocation so tests can filter
 * captured buffers by size after the API under test has freed them.
 * Every fresh allocation is stamped with 0xCC so tests can tell "byte
 * was untouched" apart from "byte was written and later zeroed". The
 * free callback unconditionally diverts the pointer (with its size)
 * onto a capture list. Install only across the narrow window of the
 * call under test so allocations made outside use the default allocator
 * and don't need header-aware free on exit. */
typedef struct AllocHeader {
    size_t size;
    /* sizeof(AllocHeader) is 2 * sizeof(size_t), which preserves the
     * alignment that the system malloc returns (16 on 64-bit, 8 on
     * 32-bit) for the user pointer that follows. */
    size_t pad;
} AllocHeader;

typedef struct CapturedBuf {
    void* ptr;
    size_t size;
    struct CapturedBuf* next;
} CapturedBuf;

static CapturedBuf* capturedFrees = NULL;

static void* CaptureMalloc(size_t size)
{
    AllocHeader* h = (AllocHeader*)malloc(size + sizeof(AllocHeader));
    if (h == NULL)
        return NULL;
    h->size = size;
    WMEMSET((void*)(h + 1), 0xCC, size);
    return (void*)(h + 1);
}

static void CaptureFree(void* ptr)
{
    AllocHeader* h;
    CapturedBuf* node;
    if (ptr == NULL)
        return;
    h = (AllocHeader*)ptr - 1;
    node = (CapturedBuf*)malloc(sizeof(*node));
    if (node == NULL) {
        /* On bookkeeping failure, fall through to a real free; the
         * test will not be able to inspect this buffer but we do not
         * leak the underlying allocation. */
        free(h);
        return;
    }
    node->ptr = ptr;
    node->size = h->size;
    node->next = capturedFrees;
    capturedFrees = node;
}

static void* CaptureRealloc(void* ptr, size_t size)
{
    AllocHeader* h;
    AllocHeader* h2;
    size_t oldSize;
    if (ptr == NULL)
        return CaptureMalloc(size);
    h = (AllocHeader*)ptr - 1;
    oldSize = h->size;
    h2 = (AllocHeader*)realloc(h, size + sizeof(AllocHeader));
    if (h2 == NULL)
        return NULL;
    h2->size = size;
    if (size > oldSize)
        WMEMSET((byte*)(h2 + 1) + oldSize, 0xCC, size - oldSize);
    return (void*)(h2 + 1);
}

static void DrainCaptured(void)
{
    CapturedBuf* c = capturedFrees;
    while (c != NULL) {
        CapturedBuf* next = c->next;
        free((AllocHeader*)c->ptr - 1);
        free(c);
        c = next;
    }
    capturedFrees = NULL;
}

/* Verify KeyAgreeDh_server zeroes the ephemeral DH private key buffer
 * y_ptr before WFREE returns it to the heap. y_ptr is a stack array in
 * the default build but a heap allocation under WOLFSSH_SMALL_STACK, so
 * the test installs the capturing allocator and inspects the captured
 * buffer afterwards.
 *
 * wc_DhGenerateKeyPair writes only the leading ySz bytes of the
 * MAX_KEX_KEY_SZ allocation (ySz is typically the prime-group size, well
 * below MAX_KEX_KEY_SZ), and ForceZero only wipes those same ySz bytes -
 * so the tail of the buffer is never written by the function under test.
 * The capture allocator stamps every fresh allocation with 0xCC so that
 * after the call:
 *   - present ForceZero  -> [0x00 * ySz] [0xCC * (MAX - ySz)]
 *   - removed ForceZero  -> [priv-key * ySz] [0xCC * (MAX - ySz)]
 * The check requires a captured MAX_KEX_KEY_SZ buffer whose bytes are all
 * either 0x00 or 0xCC AND that contains at least one 0x00. The DH private
 * key emitted by wc_DhGenerateKeyPair is overwhelmingly unlikely to be
 * entirely composed of 0x00 / 0xCC bytes, so this catches the mutation
 * while staying deterministic regardless of underlying malloc state.
 *
 * The peer value ssh->handshake->e is left zero, so the new
 * wc_DhCheckPubKey now fails between wc_DhGenerateKeyPair and wc_DhAgree;
 * the ForceZero on y_ptr is unconditional and still runs, so the buffer
 * assertion above is unaffected. */
static int test_KeyAgreeDh_server_zeroesEphemeralPrivKey(void)
{
    WOLFSSH_CTX* ctx = NULL;
    WOLFSSH* ssh = NULL;
    byte f[MAX_KEX_KEY_SZ];
    word32 fSz = (word32)sizeof(f);
    int result = 0;
    CapturedBuf* c;
    int foundYPtr = 0;
    int captureInstalled = 0;
    wolfSSL_Malloc_cb prevMf = NULL;
    wolfSSL_Free_cb prevFf = NULL;
    wolfSSL_Realloc_cb prevRf = NULL;

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_SERVER, NULL);
    if (ctx == NULL)
        return -720;
    ssh = wolfSSH_new(ctx);
    if (ssh == NULL) {
        result = -721;
        goto out;
    }
    if (ssh->handshake == NULL) {
        result = -722;
        goto out;
    }
#ifndef WOLFSSH_NO_DH_GROUP14_SHA256
    ssh->handshake->kexId = ID_DH_GROUP14_SHA256;
#elif !defined(WOLFSSH_NO_DH_GROUP16_SHA512)
    ssh->handshake->kexId = ID_DH_GROUP16_SHA512;
#elif !defined(WOLFSSH_NO_DH_GROUP14_SHA1)
    ssh->handshake->kexId = ID_DH_GROUP14_SHA1;
#elif !defined(WOLFSSH_NO_DH_GROUP1_SHA1)
    ssh->handshake->kexId = ID_DH_GROUP1_SHA1;
#else
    /* No fixed DH group enabled; nothing to exercise. */
    result = -725;
    goto out;
#endif

    wolfSSL_GetAllocators(&prevMf, &prevFf, &prevRf);
    /* Allocators unchanged on failure; nothing to restore. */
    if (wolfSSL_SetAllocators(CaptureMalloc, CaptureFree,
                              CaptureRealloc) != 0) {
        result = -723;
        goto out;
    }
    captureInstalled = 1;
    (void)wolfSSH_TestKeyAgreeDh_server(ssh, WC_HASH_TYPE_SHA256, f, &fSz);
    wolfSSL_SetAllocators(prevMf, prevFf, prevRf);
    captureInstalled = 0;

    for (c = capturedFrees; c != NULL; c = c->next) {
        const byte* bytes;
        word32 i;
        int hasZero = 0;
        int hasOther = 0;

        if (c->size != MAX_KEX_KEY_SZ)
            continue;
        bytes = (const byte*)c->ptr;
        for (i = 0; i < MAX_KEX_KEY_SZ; i++) {
            if (bytes[i] == 0x00) {
                hasZero = 1;
            }
            else if (bytes[i] != 0xCC) {
                hasOther = 1;
                break;
            }
        }
        if (hasZero && !hasOther) {
            foundYPtr = 1;
            break;
        }
    }
    if (!foundYPtr) {
        result = -724;
    }

out:
    if (captureInstalled)
        wolfSSL_SetAllocators(prevMf, prevFf, prevRf);
    DrainCaptured();
    if (ssh != NULL)
        wolfSSH_free(ssh);
    if (ctx != NULL)
        wolfSSH_CTX_free(ctx);
    return result;
}
#endif /* WOLFSSH_SMALL_STACK && WOLFSSH_TEST_CAPTURING_ALLOCATOR */

/* Verify KeyAgreeDh_server rejects an out-of-range peer public value.
 * The server hook loads the SSH prime group from kexId itself, so feeding
 * ssh->handshake->e a value of 0 or 1 (outside [2, p-2]) must make
 * wc_DhCheckPubKey fail and the call return non-WS_SUCCESS instead of
 * deriving a known shared secret. On a wolfSSL whose wc_DhAgree already
 * validates the peer key this is an equivalent guard; its value is
 * defense-in-depth for builds whose wc_DhAgree does not validate. */
static int test_KeyAgreeDh_server_rejectsOutOfRangePeer(void)
{
    WOLFSSH_CTX* ctx = NULL;
    WOLFSSH* ssh = NULL;
    HandshakeInfo* hs = NULL;
    byte f[MAX_KEX_KEY_SZ];
    word32 fSz;
    word32 c;
    int result = 0;
    static const byte badVals[2] = { 0x00, 0x01 };

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_SERVER, NULL);
    if (ctx == NULL)
        return -740;
    ssh = wolfSSH_new(ctx);
    if (ssh == NULL) {
        wolfSSH_CTX_free(ctx);
        return -741;
    }
    hs = ssh->handshake;
    if (hs == NULL) {
        result = -742;
        goto cleanup;
    }
#ifndef WOLFSSH_NO_DH_GROUP14_SHA256
    hs->kexId = ID_DH_GROUP14_SHA256;
#elif !defined(WOLFSSH_NO_DH_GROUP16_SHA512)
    hs->kexId = ID_DH_GROUP16_SHA512;
#elif !defined(WOLFSSH_NO_DH_GROUP14_SHA1)
    hs->kexId = ID_DH_GROUP14_SHA1;
#elif !defined(WOLFSSH_NO_DH_GROUP1_SHA1)
    hs->kexId = ID_DH_GROUP1_SHA1;
#else
    /* No fixed DH group enabled; fail rather than silently pass. */
    result = -744;
    goto cleanup;
#endif

    for (c = 0; c < (word32)sizeof(badVals); c++) {
        int ret;
        hs->e[0] = badVals[c];
        hs->eSz = 1;
        fSz = (word32)sizeof(f);
        ret = wolfSSH_TestKeyAgreeDh_server(ssh, WC_HASH_TYPE_SHA256, f, &fSz);
        if (ret == WS_SUCCESS) {
            result = -743;
            break;
        }
    }

cleanup:
    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);
    return result;
}

#ifdef HAVE_FFDHE_2048
/* Verify KeyAgreeDh_client rejects an out-of-range peer public value.
 * A real prime group is loaded into ssh->handshake->privKey.dh so that an
 * f of 0 or 1 (outside [2, p-2]) is caught by wc_DhCheckPubKey before key
 * agreement, yielding WS_CRYPTO_FAILED rather than a known shared secret.
 * Equivalent-mutant caveat as in the server case above: it is a regression
 * guard for builds whose wc_DhAgree does not validate the peer key. */
static int test_KeyAgreeDh_client_rejectsOutOfRangePeer(void)
{
    WOLFSSH_CTX* ctx = NULL;
    WOLFSSH* ssh = NULL;
    HandshakeInfo* hs = NULL;
    byte badF[1];
    word32 c;
    int result = 0;
    static const byte badVals[2] = { 0x00, 0x01 };

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_CLIENT, NULL);
    if (ctx == NULL)
        return -750;
    ssh = wolfSSH_new(ctx);
    if (ssh == NULL) {
        wolfSSH_CTX_free(ctx);
        return -751;
    }
    hs = ssh->handshake;
    if (hs == NULL) {
        result = -752;
        goto cleanup;
    }

    for (c = 0; c < (word32)sizeof(badVals); c++) {
        int ret;
        /* The hook frees privKey.dh on return, so re-init each iteration. */
        if (wc_InitDhKey(&hs->privKey.dh) != 0) {
            result = -753;
            break;
        }
        if (wc_DhSetNamedKey(&hs->privKey.dh, WC_FFDHE_2048) != 0) {
            wc_FreeDhKey(&hs->privKey.dh);
            result = -754;
            break;
        }
        /* x is unused on the reject path but ForceZero still runs over it. */
        hs->xSz = 0;
        badF[0] = badVals[c];
        ret = wolfSSH_TestKeyAgreeDh_client(ssh, WC_HASH_TYPE_SHA256,
                badF, (word32)sizeof(badF));
        if (ret != WS_CRYPTO_FAILED) {
            result = -755;
            break;
        }
    }

cleanup:
    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);
    return result;
}
#endif /* HAVE_FFDHE_2048 */
#endif /* !WOLFSSH_NO_DH */

#if !defined(WOLFSSH_NO_ECDH) && !defined(WOLFSSH_NO_ECDH_SHA2_NISTP256)
/* Verify KeyAgreeEcdh_server rejects an off-curve peer ECC point. The peer
 * point is read from ssh->handshake->e as an X9.63 uncompressed point; (1, 1)
 * is a well-formed encoding that is not on P-256. In builds without
 * WOLFSSL_VALIDATE_ECC_IMPORT (the common embedded case this hardening targets)
 * wc_ecc_import_x963 accepts the coordinates, so the wc_ecc_check_key call in
 * the shared EccCheckPeerKey helper is what rejects it before
 * wc_ecc_shared_secret is reached; with WOLFSSL_VALIDATE_ECC_IMPORT the import
 * itself rejects it. Either way the function must fail. P-256 has cofactor 1,
 * so an off-curve point (not a wrong-subgroup one) is the meaningful test. */
static int test_KeyAgreeEcdh_server_rejectsOffCurvePoint(void)
{
    WOLFSSH_CTX* ctx = NULL;
    WOLFSSH* ssh = NULL;
    byte f[MAX_KEX_KEY_SZ];
    word32 fSz = (word32)sizeof(f);
    int result = 0;
    /* X9.63 uncompressed point for P-256: 0x04 || X(32) || Y(32), here the
     * off-curve point (X=1, Y=1). */
    byte point[1 + 32 + 32];

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_SERVER, NULL);
    if (ctx == NULL)
        return -740;
    ssh = wolfSSH_new(ctx);
    if (ssh == NULL || ssh->handshake == NULL) {
        result = -741;
        goto out;
    }
    ssh->handshake->kexId = ID_ECDH_SHA2_NISTP256;

    WMEMSET(point, 0, sizeof(point));
    point[0] = 0x04;                  /* uncompressed */
    point[32] = 0x01;                 /* X = 1 (big-endian, last byte) */
    point[64] = 0x01;                 /* Y = 1 */
    WMEMCPY(ssh->handshake->e, point, sizeof(point));
    ssh->handshake->eSz = (word32)sizeof(point);

    if (wolfSSH_TestKeyAgreeEcdh_server(ssh, WC_HASH_TYPE_SHA256, f, &fSz)
            == 0) {
        /* The off-curve peer point must not be accepted. */
        result = -742;
    }

out:
    if (ssh != NULL)
        wolfSSH_free(ssh);
    if (ctx != NULL)
        wolfSSH_CTX_free(ctx);
    return result;
}

/* Verify KeyAgreeEcdh_client rejects an off-curve peer ECC point. The peer
 * point 'f' is an X9.63 uncompressed encoding; (1, 1) is well-formed but is
 * not on P-256. In builds without WOLFSSL_VALIDATE_ECC_IMPORT (the common
 * embedded case this hardening targets) wc_ecc_import_x963 accepts the
 * coordinates, so the wc_ecc_check_key call in the shared EccCheckPeerKey
 * helper is what rejects it before wc_ecc_shared_secret is reached; with
 * WOLFSSL_VALIDATE_ECC_IMPORT the import itself rejects it. Either way the
 * function must fail. P-256 has cofactor 1, so an off-curve point (not a
 * wrong-subgroup one) is the meaningful test. */
static int test_KeyAgreeEcdh_client_rejectsOffCurvePoint(void)
{
    WOLFSSH_CTX* ctx = NULL;
    WOLFSSH* ssh = NULL;
    int result = 0;
    /* X9.63 uncompressed point for P-256: 0x04 || X(32) || Y(32), here the
     * off-curve point (X=1, Y=1). */
    byte point[1 + 32 + 32];

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_CLIENT, NULL);
    if (ctx == NULL)
        return -770;
    ssh = wolfSSH_new(ctx);
    if (ssh == NULL || ssh->handshake == NULL) {
        result = -771;
        goto out;
    }
    ssh->handshake->kexId = ID_ECDH_SHA2_NISTP256;

    /* Generate a real client ephemeral P-256 key, as SendKexDhInit() does
     * before KeyAgreeEcdh_client() runs. With a live private key in place the
     * only way the call can fail is the peer point validation, so the test
     * actually exercises the wc_ecc_check_key guard rather than tripping over a
     * missing private key. KeyAgreeEcdh_client() frees privKey.ecc on the way
     * out, so the cleanup path stays well defined. */
    if (wc_ecc_init(&ssh->handshake->privKey.ecc) != 0) {
        result = -772;
        goto out;
    }
    ssh->handshake->useEcdh = 1;
#ifdef HAVE_WC_ECC_SET_RNG
    if (wc_ecc_set_rng(&ssh->handshake->privKey.ecc, ssh->rng) != 0) {
        result = -774;
        goto out;
    }
#endif
    if (wc_ecc_make_key_ex(ssh->rng, 32, &ssh->handshake->privKey.ecc,
            ECC_SECP256R1) != 0) {
        result = -775;
        goto out;
    }

    WMEMSET(point, 0, sizeof(point));
    point[0] = 0x04;                  /* uncompressed */
    point[32] = 0x01;                 /* X = 1 (big-endian, last byte) */
    point[64] = 0x01;                 /* Y = 1 */

    if (wolfSSH_TestKeyAgreeEcdh_client(ssh, WC_HASH_TYPE_SHA256, point,
            (word32)sizeof(point)) == 0) {
        /* The off-curve peer point must not be accepted. */
        result = -773;
    }

out:
    if (ssh != NULL)
        wolfSSH_free(ssh);
    if (ctx != NULL)
        wolfSSH_CTX_free(ctx);
    return result;
}
#endif /* !WOLFSSH_NO_ECDH && !WOLFSSH_NO_ECDH_SHA2_NISTP256 */

#if defined(WOLFSSH_SCP) && !defined(WOLFSSH_SCP_USER_CALLBACKS) && \
    !defined(NO_FILESYSTEM) && !defined(WOLFSSL_NUCLEUS) && \
    !defined(_WIN32) && !defined(WOLFSSH_ZEPHYR)

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

static int scpTestSnprintfOk(int n, size_t bufSz)
{
    return (n >= 0 && (size_t)n < bufSz);
}

static int pathsMatch(const char* a, const char* b)
{
    char* aResolved = realpath(a, NULL);
    char* bResolved = realpath(b, NULL);
    int match = 0;

    if (aResolved != NULL && bResolved != NULL)
        match = (WSTRCMP(aResolved, bResolved) == 0);

    free(aResolved);
    free(bResolved);
    return match;
}

static int test_ScpRecvCallback_EndDirDepthGuard(void)
{
    char tmpDir[] = "/tmp/wolfssh_scpXXXXXX";
    char basePathRaw[PATH_MAX];
    char evilPath[PATH_MAX];
    char evilFileInBase[PATH_MAX];
    char subPath[PATH_MAX];
    char cwd[PATH_MAX];
    char origCwd[PATH_MAX];
    char* basePath = NULL;
    char* tmpResolved = NULL;
    struct stat st;
    WOLFSSH_CTX* ctx = NULL;
    WOLFSSH* ssh = NULL;
    int pathsReady = 0;
    int baseMkdirDone = 0;
    int subdirCreated = 0;
    int origCwdSaved = 0;
    int ret;
    int result = 0;

    basePathRaw[0] = '\0';
    evilPath[0] = '\0';
    evilFileInBase[0] = '\0';
    subPath[0] = '\0';

    if (getcwd(origCwd, sizeof(origCwd)) == NULL)
        return -799;
    origCwdSaved = 1;

    if (mkdtemp(tmpDir) == NULL)
        return -800;

    ret = snprintf(basePathRaw, sizeof(basePathRaw), "%s/scp_target", tmpDir);
    if (!scpTestSnprintfOk(ret, sizeof(basePathRaw))) {
        result = -801;
        goto cleanup;
    }

    if (mkdir(basePathRaw, 0755) != 0) {
        result = -802;
        goto cleanup;
    }
    baseMkdirDone = 1;

    basePath = realpath(basePathRaw, NULL);
    tmpResolved = realpath(tmpDir, NULL);
    if (basePath == NULL || tmpResolved == NULL) {
        result = -803;
        goto cleanup;
    }

    ret = snprintf(evilPath, sizeof(evilPath), "%s/EVIL_FILE.txt", tmpResolved);
    if (!scpTestSnprintfOk(ret, sizeof(evilPath))) {
        result = -804;
        goto cleanup;
    }
    ret = snprintf(evilFileInBase, sizeof(evilFileInBase), "%s/EVIL_FILE.txt",
            basePath);
    if (!scpTestSnprintfOk(ret, sizeof(evilFileInBase))) {
        result = -804;
        goto cleanup;
    }
    ret = snprintf(subPath, sizeof(subPath), "%s/subdir", basePath);
    if (!scpTestSnprintfOk(ret, sizeof(subPath))) {
        result = -804;
        goto cleanup;
    }
    pathsReady = 1;

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_SERVER, NULL);
    if (ctx == NULL) {
        result = -805;
        goto cleanup;
    }
    ssh = wolfSSH_new(ctx);
    if (ssh == NULL) {
        result = -806;
        goto cleanup;
    }

    ret = wsScpRecvCallback(ssh, WOLFSSH_SCP_NEW_REQUEST, basePath,
            NULL, 0, 0, 0, 0, NULL, 0, 0, NULL);
    if (ret != WS_SCP_CONTINUE) {
        result = -807;
        goto cleanup;
    }

    ret = wsScpRecvCallback(ssh, WOLFSSH_SCP_END_DIR, basePath,
            NULL, 0, 0, 0, 0, NULL, 0, 0, NULL);
    if (ret != WS_SCP_ABORT) {
        result = -808;
        goto cleanup;
    }

    if (ssh->scpDirDepth != 0) {
        result = -809;
        goto cleanup;
    }

    ret = wsScpRecvCallback(ssh, WOLFSSH_SCP_NEW_FILE, basePath,
            "EVIL_FILE.txt", 0644, 0, 0, 0, NULL, 0, 0, NULL);
    if (ret == WS_SCP_CONTINUE) {
        (void)wsScpRecvCallback(ssh, WOLFSSH_SCP_FILE_DONE, basePath,
                "EVIL_FILE.txt", 0644, 0, 0, 0, NULL, 0, 0,
                wolfSSH_GetScpRecvCtx(ssh));
    }
    if (stat(evilPath, &st) == 0) {
        (void)remove(evilPath);
        result = -810;
        goto cleanup;
    }

    if (getcwd(cwd, sizeof(cwd)) == NULL || !pathsMatch(cwd, basePath)) {
        result = -811;
        goto cleanup;
    }

    ret = wsScpRecvCallback(ssh, WOLFSSH_SCP_NEW_DIR, basePath,
            "subdir", 0755, 0, 0, 0, NULL, 0, 0, NULL);
    if (ret != WS_SCP_CONTINUE) {
        result = -812;
        goto cleanup;
    }
    subdirCreated = 1;

    ret = wsScpRecvCallback(ssh, WOLFSSH_SCP_END_DIR, basePath,
            NULL, 0, 0, 0, 0, NULL, 0, 0, NULL);
    if (ret != WS_SCP_CONTINUE || ssh->scpDirDepth != 0) {
        result = -813;
        goto cleanup;
    }

    if (getcwd(cwd, sizeof(cwd)) == NULL || !pathsMatch(cwd, basePath)) {
        result = -814;
        goto cleanup;
    }

cleanup:
    if (ssh != NULL)
        wolfSSH_free(ssh);
    if (ctx != NULL)
        wolfSSH_CTX_free(ctx);
    free(basePath);
    free(tmpResolved);
    if (pathsReady) {
        (void)remove(evilPath);
        (void)remove(evilFileInBase);
    }
    if (subdirCreated)
        (void)rmdir(subPath);
    if (baseMkdirDone)
        (void)rmdir(basePathRaw);
    (void)rmdir(tmpDir);
    if (origCwdSaved && chdir(origCwd) != 0 && result == 0)
        result = -815;
    return result;
}

static int test_ScpRecvCallback_NewDirChdirFail(void)
{
    char tmpDir[] = "/tmp/wolfssh_scpXXXXXX";
    char basePathRaw[PATH_MAX];
    char noexecSubPath[PATH_MAX];
    char origCwd[PATH_MAX];
    char* basePath = NULL;
    WOLFSSH_CTX* ctx = NULL;
    WOLFSSH* ssh = NULL;
    int baseMkdirDone = 0;
    int noexecCreated = 0;
    int origCwdSaved = 0;
    int ret;
    int result = 0;

    basePathRaw[0] = '\0';
    noexecSubPath[0] = '\0';

    if (getcwd(origCwd, sizeof(origCwd)) == NULL)
        return -820;
    origCwdSaved = 1;

    if (mkdtemp(tmpDir) == NULL)
        return -821;

    ret = snprintf(basePathRaw, sizeof(basePathRaw), "%s/scp_target", tmpDir);
    if (!scpTestSnprintfOk(ret, sizeof(basePathRaw))) {
        result = -822;
        goto cleanup;
    }

    if (mkdir(basePathRaw, 0755) != 0) {
        result = -823;
        goto cleanup;
    }
    baseMkdirDone = 1;

    basePath = realpath(basePathRaw, NULL);
    if (basePath == NULL) {
        result = -824;
        goto cleanup;
    }

    ret = snprintf(noexecSubPath, sizeof(noexecSubPath), "%s/noexec_sub",
            basePath);
    if (!scpTestSnprintfOk(ret, sizeof(noexecSubPath))) {
        result = -825;
        goto cleanup;
    }

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_SERVER, NULL);
    if (ctx == NULL) {
        result = -826;
        goto cleanup;
    }
    ssh = wolfSSH_new(ctx);
    if (ssh == NULL) {
        result = -827;
        goto cleanup;
    }

    ret = wsScpRecvCallback(ssh, WOLFSSH_SCP_NEW_REQUEST, basePath,
            NULL, 0, 0, 0, 0, NULL, 0, 0, NULL);
    if (ret != WS_SCP_CONTINUE) {
        result = -828;
        goto cleanup;
    }

    /* pre-create noexec_sub with mode 0000 so WCHDIR fails after WMKDIR
     * gets EEXIST and continues */
    if (mkdir(noexecSubPath, 0000) != 0) {
        result = -829;
        goto cleanup;
    }
    noexecCreated = 1;

    /* root bypasses directory permission checks; skip the wchdir-fail
     * sub-test to avoid a false failure */
    if (geteuid() == 0)
        goto cleanup;

    ret = wsScpRecvCallback(ssh, WOLFSSH_SCP_NEW_DIR, basePath,
            "noexec_sub", 0755, 0, 0, 0, NULL, 0, 0, NULL);
    if (ret != WS_SCP_ABORT) {
        result = -830;
        goto cleanup;
    }

    if (ssh->scpDirDepth != 0) {
        result = -831;
        goto cleanup;
    }

cleanup:
    if (ssh != NULL)
        wolfSSH_free(ssh);
    if (ctx != NULL)
        wolfSSH_CTX_free(ctx);
    free(basePath);
    if (noexecCreated) {
        (void)chmod(noexecSubPath, 0755);
        (void)rmdir(noexecSubPath);
    }
    if (baseMkdirDone)
        (void)rmdir(basePathRaw);
    (void)rmdir(tmpDir);
    if (origCwdSaved && chdir(origCwd) != 0 && result == 0)
        result = -832;
    return result;
}

/* A pre-existing symlink in the destination directory must not be followed
 * out of that directory, neither when entering it as a directory nor when
 * opening it as a file. */
static int test_ScpRecvCallback_SymlinkGuard(void)
{
#ifndef WOLFSSH_HAVE_SYMLINK
    /* symlink rejection is compiled out on this configuration */
    return 0;
#else
    char tmpDir[] = "/tmp/wolfssh_scpXXXXXX";
    char basePathRaw[PATH_MAX];
    char outsidePath[PATH_MAX];
    char linkDirPath[PATH_MAX];
    char linkFilePath[PATH_MAX];
    char leakedPath[PATH_MAX];
    char origCwd[PATH_MAX];
    char* basePath = NULL;
    struct stat st;
    WOLFSSH_CTX* ctx = NULL;
    WOLFSSH* ssh = NULL;
    int baseMkdirDone = 0;
    int outsideMkdirDone = 0;
    int linkDirDone = 0;
    int linkFileDone = 0;
    int origCwdSaved = 0;
    int ret;
    int result = 0;

    basePathRaw[0] = '\0';
    outsidePath[0] = '\0';
    linkDirPath[0] = '\0';
    linkFilePath[0] = '\0';
    leakedPath[0] = '\0';

    if (getcwd(origCwd, sizeof(origCwd)) == NULL)
        return -840;
    origCwdSaved = 1;

    if (mkdtemp(tmpDir) == NULL)
        return -841;

    ret = snprintf(basePathRaw, sizeof(basePathRaw), "%s/scp_target", tmpDir);
    if (!scpTestSnprintfOk(ret, sizeof(basePathRaw))) {
        result = -842;
        goto cleanup;
    }
    if (mkdir(basePathRaw, 0755) != 0) {
        result = -843;
        goto cleanup;
    }
    baseMkdirDone = 1;

    ret = snprintf(outsidePath, sizeof(outsidePath), "%s/outside", tmpDir);
    if (!scpTestSnprintfOk(ret, sizeof(outsidePath))) {
        result = -844;
        goto cleanup;
    }
    if (mkdir(outsidePath, 0755) != 0) {
        result = -845;
        goto cleanup;
    }
    outsideMkdirDone = 1;

    basePath = realpath(basePathRaw, NULL);
    if (basePath == NULL) {
        result = -846;
        goto cleanup;
    }

    ret = snprintf(linkDirPath, sizeof(linkDirPath), "%s/linkdir", basePath);
    if (!scpTestSnprintfOk(ret, sizeof(linkDirPath))) {
        result = -847;
        goto cleanup;
    }
    ret = snprintf(linkFilePath, sizeof(linkFilePath), "%s/linkfile", basePath);
    if (!scpTestSnprintfOk(ret, sizeof(linkFilePath))) {
        result = -858;
        goto cleanup;
    }
    ret = snprintf(leakedPath, sizeof(leakedPath),
                   "%s/leaked.txt", outsidePath);
    if (!scpTestSnprintfOk(ret, sizeof(leakedPath))) {
        result = -859;
        goto cleanup;
    }

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_SERVER, NULL);
    if (ctx == NULL) {
        result = -848;
        goto cleanup;
    }
    ssh = wolfSSH_new(ctx);
    if (ssh == NULL) {
        result = -849;
        goto cleanup;
    }

    /* NEW_REQUEST changes the working directory into basePath */
    ret = wsScpRecvCallback(ssh, WOLFSSH_SCP_NEW_REQUEST, basePath,
            NULL, 0, 0, 0, 0, NULL, 0, 0, NULL);
    if (ret != WS_SCP_CONTINUE) {
        result = -850;
        goto cleanup;
    }

    /* plant a directory symlink pointing outside basePath */
    if (symlink(outsidePath, linkDirPath) != 0) {
        result = -851;
        goto cleanup;
    }
    linkDirDone = 1;

    /* WMKDIR returns EEXIST for the existing symlink; the callback must
     * refuse to chdir through it rather than escape basePath */
    ret = wsScpRecvCallback(ssh, WOLFSSH_SCP_NEW_DIR, basePath,
            "linkdir", 0755, 0, 0, 0, NULL, 0, 0, NULL);
    if (ret != WS_SCP_ABORT) {
        result = -852;
        goto cleanup;
    }
    if (ssh->scpDirDepth != 0) {
        result = -853;
        goto cleanup;
    }

    /* plant a (dangling) file symlink pointing outside basePath */
    if (symlink(leakedPath, linkFilePath) != 0) {
        result = -854;
        goto cleanup;
    }
    linkFileDone = 1;

    /* the callback must refuse to open the symlink rather than write through
     * it to the outside target */
    ret = wsScpRecvCallback(ssh, WOLFSSH_SCP_NEW_FILE, basePath,
            "linkfile", 0644, 0, 0, 0, NULL, 0, 0, NULL);
    if (ret != WS_SCP_ABORT) {
        result = -855;
        goto cleanup;
    }
    if (stat(leakedPath, &st) == 0) {
        (void)remove(leakedPath);
        result = -856;
        goto cleanup;
    }

cleanup:
    if (ssh != NULL)
        wolfSSH_free(ssh);
    if (ctx != NULL)
        wolfSSH_CTX_free(ctx);
    free(basePath);
    /* NEW_REQUEST changed the process CWD into basePath, so leave it before
     * removing the created directories or the rmdir calls would fail */
    if (origCwdSaved && chdir(origCwd) != 0 && result == 0)
        result = -857;
    if (linkDirDone)
        (void)remove(linkDirPath);
    if (linkFileDone)
        (void)remove(linkFilePath);
    if (outsideMkdirDone)
        (void)rmdir(outsidePath);
    if (baseMkdirDone)
        (void)rmdir(basePathRaw);
    (void)rmdir(tmpDir);
    return result;
#endif /* WOLFSSH_HAVE_SYMLINK */
}

/* Drive the default SCP receive callback through a full single-file receive
 * and confirm the peer-supplied modification/access times end up on the
 * written file.
 *
 * Which code path applies the timestamp is decided at build time, not by this
 * test: when futimens is detected (HAVE_FUTIMENS) the callback sets it on the
 * open descriptor before the closing flush, otherwise it sets it by path after
 * close. Both must yield the peer-supplied times, which is what this end-to-end
 * test asserts. When the descriptor path is compiled in, this also guards its
 * ordering relative to the closing flush: applying the timestamp before the
 * buffered data was flushed would leave the modification time at the current
 * time rather than the peer value. */
static int test_ScpRecvCallback_Timestamp(void)
{
    char tmpDir[] = "/tmp/wolfssh_scptsXXXXXX";
    char filePath[PATH_MAX];
    char origCwd[PATH_MAX];
    const char data[] = "wolfssh scp timestamp regression\n";
    const word64 mTime = 1234567890; /* 2009-02-13 23:31:30 UTC */
    const word64 aTime = 1000000000; /* 2001-09-09 01:46:40 UTC */
    struct stat st;
    WOLFSSH_CTX* ctx = NULL;
    WOLFSSH* ssh = NULL;
    char* basePath = NULL;
    int origCwdSaved = 0;
    int baseReady = 0;
    int ret;
    int result = 0;

    filePath[0] = '\0';

    if (getcwd(origCwd, sizeof(origCwd)) == NULL)
        return -850;
    origCwdSaved = 1;

    if (mkdtemp(tmpDir) == NULL)
        return -851;
    baseReady = 1;

    basePath = realpath(tmpDir, NULL);
    if (basePath == NULL) {
        result = -852;
        goto cleanup;
    }

    ret = snprintf(filePath, sizeof(filePath), "%s/ts_file.txt", basePath);
    if (!scpTestSnprintfOk(ret, sizeof(filePath))) {
        result = -853;
        goto cleanup;
    }

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_SERVER, NULL);
    if (ctx == NULL) {
        result = -854;
        goto cleanup;
    }
    ssh = wolfSSH_new(ctx);
    if (ssh == NULL) {
        result = -855;
        goto cleanup;
    }

    /* enter the destination directory */
    ret = wsScpRecvCallback(ssh, WOLFSSH_SCP_NEW_REQUEST, basePath,
            NULL, 0, 0, 0, 0, NULL, 0, 0, NULL);
    if (ret != WS_SCP_CONTINUE) {
        result = -856;
        goto cleanup;
    }

    /* open the destination file */
    ret = wsScpRecvCallback(ssh, WOLFSSH_SCP_NEW_FILE, basePath,
            "ts_file.txt", 0644, mTime, aTime, sizeof(data) - 1, NULL, 0, 0,
            NULL);
    if (ret != WS_SCP_CONTINUE) {
        result = -857;
        goto cleanup;
    }

    /* write the file contents */
    ret = wsScpRecvCallback(ssh, WOLFSSH_SCP_FILE_PART, basePath,
            "ts_file.txt", 0644, mTime, aTime, sizeof(data) - 1,
            (byte*)data, sizeof(data) - 1, 0, wolfSSH_GetScpRecvCtx(ssh));
    if (ret != WS_SCP_CONTINUE) {
        result = -858;
        goto cleanup;
    }

    /* close the file and apply the peer-supplied timestamps */
    ret = wsScpRecvCallback(ssh, WOLFSSH_SCP_FILE_DONE, basePath,
            "ts_file.txt", 0644, mTime, aTime, sizeof(data) - 1, NULL, 0, 0,
            wolfSSH_GetScpRecvCtx(ssh));
    if (ret != WS_SCP_CONTINUE) {
        result = -859;
        goto cleanup;
    }

    /* the written file must carry the peer-supplied timestamps */
    if (stat(filePath, &st) != 0) {
        result = -860;
        goto cleanup;
    }
    if ((word64)st.st_mtime != mTime) {
        result = -861;
        goto cleanup;
    }
    if ((word64)st.st_atime != aTime) {
        result = -862;
        goto cleanup;
    }

#ifdef HAVE_FUTIMENS
    /* Descriptor build only: a FILE_DONE carrying timestamps but no open file
     * (NULL ctx) must abort rather than silently fall back to a path-based
     * update that could follow a swapped symlink. Use distinct times and
     * confirm the existing file's modification time is left untouched. */
    ret = wsScpRecvCallback(ssh, WOLFSSH_SCP_FILE_DONE, basePath,
            "ts_file.txt", 0644, mTime + 100, aTime + 100, 0, NULL, 0, 0,
            NULL);
    if (ret != WS_SCP_ABORT) {
        result = -864;
        goto cleanup;
    }
    if (stat(filePath, &st) != 0) {
        result = -865;
        goto cleanup;
    }
    if ((word64)st.st_mtime != mTime) {
        result = -866;
        goto cleanup;
    }
#endif

cleanup:
    if (ssh != NULL)
        wolfSSH_free(ssh);
    if (ctx != NULL)
        wolfSSH_CTX_free(ctx);
    if (filePath[0] != '\0')
        (void)remove(filePath);
    free(basePath);
    if (origCwdSaved && chdir(origCwd) != 0 && result == 0)
        result = -863;
    if (baseReady)
        (void)rmdir(tmpDir);
    return result;
}

#if defined(HAVE_UTIMENSAT) && defined(WOLFSSH_HAVE_SYMLINK)
/* Exercise the no-follow path fallback (no descriptor-based call available).
 * Setting times through a symlink must land on the symlink itself, not the
 * target, so a swapped symlink cannot redirect a peer-supplied timestamp. */
static int test_ScpTimestamp_NoFollow(void)
{
    char tmpDir[] = "/tmp/wolfssh_scpnfXXXXXX";
    char canaryPath[PATH_MAX];
    char linkPath[PATH_MAX];
    const word64 mTime = 1222333444; /* distinct from the canary's own time */
    const word64 aTime = 1100000000;
    struct timeval tv[2];
    struct stat st;
    time_t canaryOrig;
    int baseReady = 0;
    int canaryReady = 0;
    int linkReady = 0;
    int ret;
    int result = 0;
    int fd;

    canaryPath[0] = '\0';
    linkPath[0] = '\0';

    if (mkdtemp(tmpDir) == NULL)
        return -870;
    baseReady = 1;

    ret = snprintf(canaryPath, sizeof(canaryPath), "%s/canary.txt", tmpDir);
    if (!scpTestSnprintfOk(ret, sizeof(canaryPath))) {
        result = -871;
        goto cleanup;
    }
    ret = snprintf(linkPath, sizeof(linkPath), "%s/link", tmpDir);
    if (!scpTestSnprintfOk(ret, sizeof(linkPath))) {
        result = -872;
        goto cleanup;
    }

    fd = open(canaryPath, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd < 0) {
        result = -873;
        goto cleanup;
    }
    canaryReady = 1;
    if (write(fd, "canary\n", 7) != 7) {
        close(fd);
        result = -881;
        goto cleanup;
    }
    close(fd);

    if (stat(canaryPath, &st) != 0) {
        result = -874;
        goto cleanup;
    }
    canaryOrig = st.st_mtime;

    if (symlink(canaryPath, linkPath) != 0) {
        result = -875;
        goto cleanup;
    }
    linkReady = 1;

    tv[0].tv_sec = (time_t)aTime;
    tv[0].tv_usec = 0;
    tv[1].tv_sec = (time_t)mTime;
    tv[1].tv_usec = 0;
    if (WUTIMES_NOFOLLOW(linkPath, tv) != 0) {
        result = -876;
        goto cleanup;
    }

    /* the symlink's own modification time must carry the supplied value */
    if (lstat(linkPath, &st) != 0) {
        result = -877;
        goto cleanup;
    }
    if ((word64)st.st_mtime != mTime) {
        result = -878;
        goto cleanup;
    }

    /* the target the symlink points at must be left untouched */
    if (stat(canaryPath, &st) != 0) {
        result = -879;
        goto cleanup;
    }
    if (st.st_mtime != canaryOrig) {
        result = -880;
        goto cleanup;
    }

cleanup:
    if (linkReady)
        (void)remove(linkPath);
    if (canaryReady)
        (void)remove(canaryPath);
    if (baseReady)
        (void)rmdir(tmpDir);
    return result;
}
#endif /* HAVE_UTIMENSAT && WOLFSSH_HAVE_SYMLINK */

#endif /* WOLFSSH_SCP recv callback depth guard test */


/* ParseECCPubKey() Unit Test */

#ifndef WOLFSSH_NO_ECDSA_SHA2_NISTP256

/* The payload of keys/gretel-key-ecc.pub:
 *   string "ecdsa-sha2-nistp256" | string "nistp256" | string Q
 * ParseECCPubKey() must reject blobs whose algorithm name or curve name
 * does not match the negotiated host key algorithm. A MitM must not be
 * able to choose a different curve by lying in the blob. */
static const byte eccPubKeyBlob[] = {
    0x00, 0x00, 0x00, 0x13, 0x65, 0x63, 0x64, 0x73, 0x61, 0x2D, 0x73, 0x68,
    0x61, 0x32, 0x2D, 0x6E, 0x69, 0x73, 0x74, 0x70, 0x32, 0x35, 0x36, 0x00,
    0x00, 0x00, 0x08, 0x6E, 0x69, 0x73, 0x74, 0x70, 0x32, 0x35, 0x36, 0x00,
    0x00, 0x00, 0x41, 0x04, 0xA0, 0x2D, 0x1F, 0xC7, 0x2A, 0x68, 0x36, 0xED,
    0x24, 0x58, 0xED, 0xBE, 0x22, 0xE8, 0x6C, 0x70, 0x66, 0x8C, 0x2B, 0x46,
    0xE7, 0xA0, 0xCC, 0x90, 0xFE, 0x80, 0xE0, 0xCD, 0x87, 0xF7, 0x35, 0xF6,
    0xFD, 0x80, 0xA0, 0xD6, 0x1F, 0x5B, 0x61, 0x2E, 0xD6, 0x1D, 0xDF, 0x54,
    0x40, 0x3C, 0x17, 0x3B, 0x51, 0xE1, 0x21, 0x9C, 0xD1, 0x61, 0xE7, 0x17,
    0x87, 0xB4, 0x86, 0xF4, 0xFE, 0x06, 0x85, 0x16,
};

/* Offsets of interest in eccPubKeyBlob. */
#define ECC_BLOB_ALGO_DIGITS  20 /* the "256" in "ecdsa-sha2-nistp256" */
#define ECC_BLOB_CURVE_DIGITS 32 /* the "256" in "nistp256" */
#define ECC_BLOB_POINT        39 /* leading byte (0x04) of Q */
#define ECC_BLOB_TRUNC_SZ     30 /* cuts the blob mid curve name */

static const byte eccBadPointFormat[] = { 0x05 };

typedef struct {
    const char* name;
    word32 patchIdx;
    const byte* patch;
    word32 patchSz;     /* 0 = no patch */
    word32 blobSz;
    byte pubKeyId;      /* negotiated host key algorithm */
    int expected;
} ParseECCPubKeyTestVector;

static const ParseECCPubKeyTestVector parseECCPubKeyTestVectors[] = {
    { "valid nistp256 blob", 0, NULL, 0, sizeof(eccPubKeyBlob),
        ID_ECDSA_SHA2_NISTP256, WS_SUCCESS },
    { "algo name mismatch", ECC_BLOB_ALGO_DIGITS, (const byte*)"384", 3,
        sizeof(eccPubKeyBlob), ID_ECDSA_SHA2_NISTP256, WS_INVALID_ALGO_ID },
#ifndef WOLFSSH_NO_ECDSA_SHA2_NISTP384
    { "blob downgrades negotiated nistp384", 0, NULL, 0,
        sizeof(eccPubKeyBlob), ID_ECDSA_SHA2_NISTP384, WS_INVALID_ALGO_ID },
#endif
    { "curve name mismatch", ECC_BLOB_CURVE_DIGITS, (const byte*)"384", 3,
        sizeof(eccPubKeyBlob), ID_ECDSA_SHA2_NISTP256,
        WS_INVALID_PRIME_CURVE },
    { "corrupt point format", ECC_BLOB_POINT, eccBadPointFormat, 1,
        sizeof(eccPubKeyBlob), ID_ECDSA_SHA2_NISTP256, WS_ECC_E },
    { "truncated blob", 0, NULL, 0, ECC_BLOB_TRUNC_SZ,
        ID_ECDSA_SHA2_NISTP256, WS_BUFFER_E },
};

static int test_ParseECCPubKey(void)
{
    WOLFSSH_CTX* ctx = NULL;
    WOLFSSH* ssh = NULL;
    const ParseECCPubKeyTestVector* tv;
    int tc = (int)(sizeof(parseECCPubKeyTestVectors)
            / sizeof(parseECCPubKeyTestVectors[0]));
    int i;
    int ret;
    int failures = 0;

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_CLIENT, NULL);
    if (ctx == NULL)
        return 1;
    ssh = wolfSSH_new(ctx);
    if (ssh == NULL || ssh->handshake == NULL) {
        wolfSSH_free(ssh);
        wolfSSH_CTX_free(ctx);
        return 1;
    }

    for (i = 0, tv = parseECCPubKeyTestVectors; i < tc; i++, tv++) {
        byte blob[sizeof(eccPubKeyBlob)];

        WMEMCPY(blob, eccPubKeyBlob, sizeof(eccPubKeyBlob));
        if (tv->patchSz > 0)
            WMEMCPY(blob + tv->patchIdx, tv->patch, tv->patchSz);
        ssh->handshake->pubKeyId = tv->pubKeyId;

        ret = wolfSSH_TestParseECCPubKey(ssh, blob, tv->blobSz);
        if (ret != tv->expected) {
            fprintf(stderr, "\t[%d] \"%s\" FAIL: got %d, expected %d\n",
                    i, tv->name, ret, tv->expected);
            failures++;
        }
    }

    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);

    return failures;
}

#endif /* !WOLFSSH_NO_ECDSA_SHA2_NISTP256 */


/* DoUserAuthRequestRsa() Unit Test */

#if !defined(WOLFSSH_NO_RSA) && !defined(WOLFSSH_NO_SSH_RSA_SHA1)

/* RFC 4253 Section 6.6: the RSA signature blob is a string of raw
 * signature bytes, not an mpint. The fixed signature below was made
 * with keys/hansel-key-rsa.pem over the message
 * "wolfSSH unit test message 1" (SHA-1, PKCS#1 v1.5) and its first
 * byte (0xB7) has the high bit set. An mpint parse would reject it
 * as negative, so this pins the string parse. */

/* string "ssh-rsa" | mpint e | mpint n, from keys/hansel-key-rsa.pem */
static const byte userAuthRsaPubKeyBlob[] = {
    0x00, 0x00, 0x00, 0x07, 0x73, 0x73, 0x68, 0x2D, 0x72, 0x73, 0x61, 0x00,
    0x00, 0x00, 0x03, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x01, 0x00, 0xBD,
    0x3F, 0x76, 0x45, 0xA3, 0x03, 0xAC, 0x38, 0xD5, 0xC7, 0x0F, 0x93, 0x30,
    0x5A, 0x20, 0x9C, 0x89, 0x7C, 0xAD, 0x05, 0x16, 0x46, 0x86, 0x83, 0x0D,
    0x8A, 0x2B, 0x16, 0x4A, 0x05, 0x2C, 0xE4, 0x77, 0x47, 0x70, 0x00, 0xAE,
    0x1D, 0x83, 0xE2, 0xD9, 0x6E, 0x99, 0xD4, 0xF0, 0x45, 0x98, 0x15, 0x93,
    0xF6, 0x87, 0x4E, 0xAC, 0x64, 0x63, 0xA1, 0x95, 0xC9, 0x7C, 0x30, 0xE8,
    0x3E, 0x2F, 0xA3, 0xF1, 0x24, 0x9F, 0x0C, 0x6B, 0x1C, 0xFE, 0x1B, 0x02,
    0x99, 0xCD, 0xC6, 0xA7, 0x6C, 0x84, 0x85, 0x46, 0x54, 0x12, 0x40, 0xE1,
    0xB4, 0xE5, 0xF2, 0xAA, 0x39, 0xEC, 0xD6, 0x27, 0x24, 0x0B, 0xD1, 0xA1,
    0xE2, 0xEF, 0x34, 0x69, 0x25, 0x6D, 0xC0, 0x74, 0x67, 0x25, 0x98, 0x7D,
    0xC4, 0xF8, 0x52, 0xAB, 0x9B, 0x4B, 0x3A, 0x12, 0x1D, 0xE1, 0xE3, 0xFA,
    0xD6, 0xCF, 0x9A, 0xE6, 0x9C, 0x23, 0x4E, 0x39, 0xC4, 0x84, 0x16, 0x88,
    0x3D, 0x42, 0x4E, 0xD8, 0x2F, 0xCC, 0xD2, 0x91, 0x67, 0x9D, 0xB6, 0x71,
    0x2A, 0x02, 0x65, 0x5F, 0xBB, 0x75, 0x0E, 0x8C, 0xBB, 0x87, 0x97, 0x97,
    0xC6, 0xF8, 0xB2, 0x98, 0xE2, 0x2F, 0x68, 0x26, 0x4A, 0x53, 0xEC, 0x79,
    0x3A, 0x8A, 0x5F, 0xCC, 0xCF, 0xF0, 0x16, 0x47, 0xB2, 0xD0, 0x43, 0xD6,
    0x36, 0x6C, 0xC8, 0xE7, 0x2F, 0xFE, 0xA7, 0x35, 0x39, 0x69, 0xFB, 0x1D,
    0x78, 0x45, 0x9D, 0x89, 0x00, 0xC8, 0x41, 0xCF, 0x34, 0x1F, 0xA3, 0xF3,
    0xF1, 0xFB, 0x28, 0x14, 0xFB, 0xD8, 0x48, 0x6F, 0xAC, 0xE3, 0xFC, 0x33,
    0xD1, 0xDB, 0xAE, 0xEF, 0x27, 0x9E, 0x57, 0x56, 0x29, 0xA2, 0x1A, 0x3A,
    0xE5, 0x9A, 0xFE, 0xA4, 0x49, 0xC8, 0x7F, 0xB7, 0x4E, 0xD0, 0x1F, 0x04,
    0x6E, 0x58, 0x16, 0xB7, 0xEB, 0x9D, 0xF8, 0x92, 0x3C, 0xC2, 0xB0, 0x21,
    0x7C, 0x4E, 0x31,
};

/* SHA-1 of "wolfSSH unit test message 1" */
static const byte userAuthRsaDigest[] = {
    0x2A, 0x43, 0xF5, 0x19, 0x09, 0xEE, 0x2D, 0x85, 0x89, 0xD3, 0xE0, 0xCE,
    0xF8, 0xA6, 0x8A, 0xC4, 0xD3, 0x33, 0xB3, 0x30,
};

/* string "ssh-rsa" | string signature */
static const byte userAuthRsaSigBlob[] = {
    0x00, 0x00, 0x00, 0x07, 0x73, 0x73, 0x68, 0x2D, 0x72, 0x73, 0x61, 0x00,
    0x00, 0x01, 0x00, 0xB7, 0xFD, 0xC3, 0x7B, 0x4A, 0xAD, 0x4B, 0x04, 0x28,
    0xD0, 0xAA, 0x41, 0x59, 0x4D, 0xFB, 0x37, 0xBD, 0x2F, 0xA4, 0x93, 0x63,
    0x4D, 0x10, 0xCF, 0x95, 0x59, 0x4C, 0x37, 0xBE, 0x71, 0xF1, 0x3D, 0xF5,
    0x8A, 0x72, 0x92, 0x22, 0xE3, 0x0F, 0xE9, 0xAE, 0x12, 0xA9, 0xD3, 0xC8,
    0x6A, 0x78, 0x66, 0x65, 0x4C, 0xDB, 0xA0, 0xB2, 0x8B, 0x19, 0x0F, 0x05,
    0xC4, 0x05, 0x69, 0x54, 0x13, 0x34, 0x17, 0xB2, 0xEE, 0x77, 0x41, 0x9B,
    0x17, 0xD6, 0x52, 0xA7, 0x1C, 0x81, 0x84, 0xED, 0x60, 0x3D, 0x52, 0xEF,
    0x57, 0xCD, 0xE8, 0x9D, 0x51, 0xCB, 0x38, 0xC8, 0xB2, 0x8E, 0x74, 0x2F,
    0xFD, 0x32, 0xCB, 0x0D, 0x8B, 0xFB, 0x7B, 0xCC, 0x35, 0xFF, 0x75, 0x10,
    0x89, 0x0A, 0x1E, 0xA8, 0x37, 0xC9, 0x39, 0xED, 0x9F, 0xDA, 0x5D, 0xC5,
    0x38, 0xEA, 0xC3, 0xBA, 0x58, 0x89, 0x5A, 0xA0, 0x84, 0x4D, 0x5F, 0x73,
    0xF9, 0x5A, 0xC8, 0xD2, 0xEA, 0xB5, 0x6D, 0x3D, 0xC0, 0x12, 0xA7, 0x79,
    0x30, 0x16, 0xE3, 0x2F, 0xBC, 0xAB, 0x12, 0xA8, 0xA1, 0xAB, 0x4B, 0xB3,
    0x07, 0xF1, 0xDA, 0x1E, 0x3E, 0x5F, 0x02, 0x4B, 0x73, 0x22, 0x26, 0xC5,
    0x51, 0xFB, 0xD1, 0x81, 0x53, 0x3B, 0xBA, 0x5E, 0x36, 0x2A, 0xBF, 0xC2,
    0xB2, 0x9A, 0x0C, 0x8C, 0xB2, 0xCB, 0x6B, 0x9F, 0x30, 0xC8, 0x63, 0xA5,
    0x72, 0xAF, 0x1D, 0x96, 0xE7, 0xB6, 0x17, 0xC4, 0xEB, 0x5F, 0xFD, 0xA4,
    0xFB, 0xF8, 0xE4, 0x69, 0xE4, 0xA3, 0x47, 0x59, 0x2D, 0x8F, 0x4F, 0xB3,
    0xD2, 0xAA, 0xD2, 0xF3, 0xCA, 0x42, 0xD5, 0xF7, 0x25, 0x5B, 0xCD, 0x60,
    0x17, 0xA2, 0x0C, 0xE0, 0xF4, 0xEE, 0xE0, 0xF6, 0xED, 0x41, 0xC9, 0x00,
    0x1B, 0x5A, 0x24, 0xD4, 0x18, 0xBA, 0xAC, 0x40, 0xBD, 0x7F, 0xFD, 0x46,
    0x2F, 0xC5, 0x19, 0xF9, 0xE6, 0x2F, 0x16,
};

/* Offsets of interest in userAuthRsaSigBlob. */
#define RSA_SIG_BLOB_ALGO 4   /* "ssh-rsa" */
#define RSA_SIG_BLOB_LEN  11  /* length of the signature string */
#define RSA_SIG_BLOB_SIG  15  /* first byte of the raw signature */

/* 257: one past the actual signature size */
static const byte userAuthRsaSigLenOverrun[] = { 0x00, 0x00, 0x01, 0x01 };

typedef struct {
    const char* name;
    word32 patchIdx;
    const byte* patch;
    word32 patchSz;     /* 0 = no patch */
    word32 flipIdx;     /* XOR 0x01 into this index; 0 = none */
    int expected;
} UserAuthRsaTestVector;

static const UserAuthRsaTestVector userAuthRsaTestVectors[] = {
    { "high bit signature accepted", 0, NULL, 0, 0, WS_SUCCESS },
    { "corrupt signature rejected", 0, NULL, 0, RSA_SIG_BLOB_SIG + 128,
        WS_RSA_E },
    { "signature length overrun", RSA_SIG_BLOB_LEN, userAuthRsaSigLenOverrun,
        4, 0, WS_BUFFER_E },
    { "signature algo name mismatch", RSA_SIG_BLOB_ALGO,
        (const byte*)"ssh-dss", 7, 0, WS_INVALID_ALGO_ID },
};

static int test_DoUserAuthRequestRsa(void)
{
    WOLFSSH_CTX* ctx = NULL;
    WOLFSSH* ssh = NULL;
    const UserAuthRsaTestVector* tv;
    int tc = (int)(sizeof(userAuthRsaTestVectors)
            / sizeof(userAuthRsaTestVectors[0]));
    int i;
    int ret;
    int failures = 0;

    /* The point of the test is a signature whose leading byte has the
     * high bit set. Guard against the vector being regenerated without
     * that property. */
    if ((userAuthRsaSigBlob[RSA_SIG_BLOB_SIG] & 0x80) == 0) {
        fprintf(stderr, "\tuserAuthRsaSigBlob needs its high bit set\n");
        return 1;
    }

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_SERVER, NULL);
    if (ctx == NULL)
        return 1;
    ssh = wolfSSH_new(ctx);
    if (ssh == NULL) {
        wolfSSH_CTX_free(ctx);
        return 1;
    }

    for (i = 0, tv = userAuthRsaTestVectors; i < tc; i++, tv++) {
        byte sigBlob[sizeof(userAuthRsaSigBlob)];
        byte digest[sizeof(userAuthRsaDigest)];
        WS_UserAuthData_PublicKey pk;

        WMEMCPY(sigBlob, userAuthRsaSigBlob, sizeof(sigBlob));
        WMEMCPY(digest, userAuthRsaDigest, sizeof(digest));
        if (tv->patchSz > 0)
            WMEMCPY(sigBlob + tv->patchIdx, tv->patch, tv->patchSz);
        if (tv->flipIdx > 0)
            sigBlob[tv->flipIdx] ^= 0x01;

        WMEMSET(&pk, 0, sizeof(pk));
        pk.publicKeyType = (const byte*)"ssh-rsa";
        pk.publicKeyTypeSz = 7;
        pk.publicKey = userAuthRsaPubKeyBlob;
        pk.publicKeySz = (word32)sizeof(userAuthRsaPubKeyBlob);
        pk.hasSignature = 1;
        pk.signature = sigBlob;
        pk.signatureSz = (word32)sizeof(sigBlob);

        ret = wolfSSH_TestDoUserAuthRequestRsa(ssh, &pk, WC_HASH_TYPE_SHA,
                digest, (word32)sizeof(digest));
        if (ret != tv->expected) {
            fprintf(stderr, "\t[%d] \"%s\" FAIL: got %d, expected %d\n",
                    i, tv->name, ret, tv->expected);
            failures++;
        }
    }

    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);

    return failures;
}

static int test_ParseRSAPubKey(void)
{
    WOLFSSH_CTX* ctx = NULL;
    WOLFSSH* ssh = NULL;
    byte blob[sizeof(userAuthRsaPubKeyBlob)];
    int ret;
    int failures = 0;

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_CLIENT, NULL);
    if (ctx == NULL)
        return 1;
    ssh = wolfSSH_new(ctx);
    if (ssh == NULL) {
        wolfSSH_CTX_free(ctx);
        return 1;
    }

    WMEMCPY(blob, userAuthRsaPubKeyBlob, sizeof(blob));

    /* valid blob */
    ret = wolfSSH_TestParseRSAPubKey(ssh, blob, (word32)sizeof(blob));
    if (ret != WS_SUCCESS) {
        fprintf(stderr, "\t\"valid\" FAIL: got %d, expected %d\n",
                ret, WS_SUCCESS);
        failures++;
    }

    /* truncated blob: fails after the key is initialized */
    ret = wolfSSH_TestParseRSAPubKey(ssh, blob, (word32)(sizeof(blob) / 2));
    if (ret != WS_RSA_E) {
        fprintf(stderr, "\t\"truncated\" FAIL: got %d, expected %d\n",
                ret, WS_RSA_E);
        failures++;
    }

    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);

    return failures;
}

#ifdef WOLFSSH_CERTS

/* DoUserAuthRequestRsaCert() parses the signature blob the same way as
 * DoUserAuthRequestRsa(), but takes the public key from an X.509
 * certificate. This is a self-signed certificate made from
 * keys/hansel-key-rsa.pem, the same key as the vectors above, so the
 * digest and signature blob are reused. */
static const byte userAuthRsaCertDer[] = {
    0x30, 0x82, 0x03, 0xFB, 0x30, 0x82, 0x02, 0xE3, 0xA0, 0x03, 0x02, 0x01,
    0x02, 0x02, 0x14, 0x1C, 0x71, 0x06, 0xEC, 0x89, 0xF3, 0x37, 0x6F, 0xE7,
    0xBB, 0x3C, 0xE2, 0x74, 0x54, 0x43, 0x1F, 0x75, 0x0A, 0xED, 0xD5, 0x30,
    0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B,
    0x05, 0x00, 0x30, 0x81, 0x8C, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55,
    0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03,
    0x55, 0x04, 0x08, 0x0C, 0x02, 0x57, 0x41, 0x31, 0x10, 0x30, 0x0E, 0x06,
    0x03, 0x55, 0x04, 0x07, 0x0C, 0x07, 0x53, 0x65, 0x61, 0x74, 0x74, 0x6C,
    0x65, 0x31, 0x14, 0x30, 0x12, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x0C, 0x0B,
    0x77, 0x6F, 0x6C, 0x66, 0x53, 0x53, 0x4C, 0x20, 0x49, 0x6E, 0x63, 0x31,
    0x14, 0x30, 0x12, 0x06, 0x03, 0x55, 0x04, 0x0B, 0x0C, 0x0B, 0x44, 0x65,
    0x76, 0x65, 0x6C, 0x6F, 0x70, 0x6D, 0x65, 0x6E, 0x74, 0x31, 0x0F, 0x30,
    0x0D, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x06, 0x48, 0x61, 0x6E, 0x73,
    0x65, 0x6C, 0x31, 0x21, 0x30, 0x1F, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86,
    0xF7, 0x0D, 0x01, 0x09, 0x01, 0x16, 0x12, 0x68, 0x61, 0x6E, 0x73, 0x65,
    0x6C, 0x40, 0x65, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65, 0x2E, 0x63, 0x6F,
    0x6D, 0x30, 0x1E, 0x17, 0x0D, 0x32, 0x36, 0x30, 0x36, 0x31, 0x32, 0x31,
    0x37, 0x34, 0x35, 0x30, 0x39, 0x5A, 0x17, 0x0D, 0x34, 0x38, 0x30, 0x35,
    0x30, 0x37, 0x31, 0x37, 0x34, 0x35, 0x30, 0x39, 0x5A, 0x30, 0x81, 0x8C,
    0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55,
    0x53, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0C, 0x02,
    0x57, 0x41, 0x31, 0x10, 0x30, 0x0E, 0x06, 0x03, 0x55, 0x04, 0x07, 0x0C,
    0x07, 0x53, 0x65, 0x61, 0x74, 0x74, 0x6C, 0x65, 0x31, 0x14, 0x30, 0x12,
    0x06, 0x03, 0x55, 0x04, 0x0A, 0x0C, 0x0B, 0x77, 0x6F, 0x6C, 0x66, 0x53,
    0x53, 0x4C, 0x20, 0x49, 0x6E, 0x63, 0x31, 0x14, 0x30, 0x12, 0x06, 0x03,
    0x55, 0x04, 0x0B, 0x0C, 0x0B, 0x44, 0x65, 0x76, 0x65, 0x6C, 0x6F, 0x70,
    0x6D, 0x65, 0x6E, 0x74, 0x31, 0x0F, 0x30, 0x0D, 0x06, 0x03, 0x55, 0x04,
    0x03, 0x0C, 0x06, 0x48, 0x61, 0x6E, 0x73, 0x65, 0x6C, 0x31, 0x21, 0x30,
    0x1F, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x01,
    0x16, 0x12, 0x68, 0x61, 0x6E, 0x73, 0x65, 0x6C, 0x40, 0x65, 0x78, 0x61,
    0x6D, 0x70, 0x6C, 0x65, 0x2E, 0x63, 0x6F, 0x6D, 0x30, 0x82, 0x01, 0x22,
    0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01,
    0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0F, 0x00, 0x30, 0x82, 0x01, 0x0A,
    0x02, 0x82, 0x01, 0x01, 0x00, 0xBD, 0x3F, 0x76, 0x45, 0xA3, 0x03, 0xAC,
    0x38, 0xD5, 0xC7, 0x0F, 0x93, 0x30, 0x5A, 0x20, 0x9C, 0x89, 0x7C, 0xAD,
    0x05, 0x16, 0x46, 0x86, 0x83, 0x0D, 0x8A, 0x2B, 0x16, 0x4A, 0x05, 0x2C,
    0xE4, 0x77, 0x47, 0x70, 0x00, 0xAE, 0x1D, 0x83, 0xE2, 0xD9, 0x6E, 0x99,
    0xD4, 0xF0, 0x45, 0x98, 0x15, 0x93, 0xF6, 0x87, 0x4E, 0xAC, 0x64, 0x63,
    0xA1, 0x95, 0xC9, 0x7C, 0x30, 0xE8, 0x3E, 0x2F, 0xA3, 0xF1, 0x24, 0x9F,
    0x0C, 0x6B, 0x1C, 0xFE, 0x1B, 0x02, 0x99, 0xCD, 0xC6, 0xA7, 0x6C, 0x84,
    0x85, 0x46, 0x54, 0x12, 0x40, 0xE1, 0xB4, 0xE5, 0xF2, 0xAA, 0x39, 0xEC,
    0xD6, 0x27, 0x24, 0x0B, 0xD1, 0xA1, 0xE2, 0xEF, 0x34, 0x69, 0x25, 0x6D,
    0xC0, 0x74, 0x67, 0x25, 0x98, 0x7D, 0xC4, 0xF8, 0x52, 0xAB, 0x9B, 0x4B,
    0x3A, 0x12, 0x1D, 0xE1, 0xE3, 0xFA, 0xD6, 0xCF, 0x9A, 0xE6, 0x9C, 0x23,
    0x4E, 0x39, 0xC4, 0x84, 0x16, 0x88, 0x3D, 0x42, 0x4E, 0xD8, 0x2F, 0xCC,
    0xD2, 0x91, 0x67, 0x9D, 0xB6, 0x71, 0x2A, 0x02, 0x65, 0x5F, 0xBB, 0x75,
    0x0E, 0x8C, 0xBB, 0x87, 0x97, 0x97, 0xC6, 0xF8, 0xB2, 0x98, 0xE2, 0x2F,
    0x68, 0x26, 0x4A, 0x53, 0xEC, 0x79, 0x3A, 0x8A, 0x5F, 0xCC, 0xCF, 0xF0,
    0x16, 0x47, 0xB2, 0xD0, 0x43, 0xD6, 0x36, 0x6C, 0xC8, 0xE7, 0x2F, 0xFE,
    0xA7, 0x35, 0x39, 0x69, 0xFB, 0x1D, 0x78, 0x45, 0x9D, 0x89, 0x00, 0xC8,
    0x41, 0xCF, 0x34, 0x1F, 0xA3, 0xF3, 0xF1, 0xFB, 0x28, 0x14, 0xFB, 0xD8,
    0x48, 0x6F, 0xAC, 0xE3, 0xFC, 0x33, 0xD1, 0xDB, 0xAE, 0xEF, 0x27, 0x9E,
    0x57, 0x56, 0x29, 0xA2, 0x1A, 0x3A, 0xE5, 0x9A, 0xFE, 0xA4, 0x49, 0xC8,
    0x7F, 0xB7, 0x4E, 0xD0, 0x1F, 0x04, 0x6E, 0x58, 0x16, 0xB7, 0xEB, 0x9D,
    0xF8, 0x92, 0x3C, 0xC2, 0xB0, 0x21, 0x7C, 0x4E, 0x31, 0x02, 0x03, 0x01,
    0x00, 0x01, 0xA3, 0x53, 0x30, 0x51, 0x30, 0x1D, 0x06, 0x03, 0x55, 0x1D,
    0x0E, 0x04, 0x16, 0x04, 0x14, 0x67, 0x59, 0x9C, 0xD7, 0x16, 0x3F, 0xE6,
    0x98, 0x47, 0x4F, 0xAE, 0x62, 0x4F, 0xAE, 0x27, 0x3A, 0xE8, 0xF6, 0x40,
    0xAE, 0x30, 0x1F, 0x06, 0x03, 0x55, 0x1D, 0x23, 0x04, 0x18, 0x30, 0x16,
    0x80, 0x14, 0x67, 0x59, 0x9C, 0xD7, 0x16, 0x3F, 0xE6, 0x98, 0x47, 0x4F,
    0xAE, 0x62, 0x4F, 0xAE, 0x27, 0x3A, 0xE8, 0xF6, 0x40, 0xAE, 0x30, 0x0F,
    0x06, 0x03, 0x55, 0x1D, 0x13, 0x01, 0x01, 0xFF, 0x04, 0x05, 0x30, 0x03,
    0x01, 0x01, 0xFF, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7,
    0x0D, 0x01, 0x01, 0x0B, 0x05, 0x00, 0x03, 0x82, 0x01, 0x01, 0x00, 0x77,
    0x70, 0xC5, 0x15, 0xFE, 0xF8, 0x2D, 0xCB, 0x5C, 0x18, 0x36, 0x87, 0xC9,
    0x82, 0xFD, 0x6D, 0x3C, 0x78, 0xD8, 0xCF, 0xEB, 0x71, 0xFD, 0xEB, 0xD7,
    0x05, 0x9A, 0xAE, 0xBE, 0xE1, 0x55, 0xCF, 0xE9, 0x04, 0xE3, 0xF1, 0xAE,
    0x30, 0xDE, 0x19, 0xC3, 0x5E, 0x25, 0xDE, 0xB7, 0x39, 0x21, 0x57, 0x82,
    0xD5, 0x98, 0xD6, 0x19, 0x49, 0x9D, 0x9F, 0xDE, 0x07, 0x9D, 0xEE, 0xB1,
    0x24, 0xBD, 0x3E, 0xFD, 0xBA, 0x27, 0xA2, 0x9D, 0x0C, 0x08, 0x77, 0xA7,
    0xB1, 0xFA, 0x6E, 0x36, 0xAA, 0xAE, 0x1F, 0xFA, 0xF6, 0xAE, 0x0A, 0x72,
    0x48, 0x5C, 0x89, 0xD6, 0x4F, 0x10, 0x80, 0x3A, 0x2A, 0xA8, 0x6C, 0x00,
    0x06, 0x41, 0x0B, 0xA6, 0xAA, 0x20, 0xE5, 0xEB, 0x38, 0xD4, 0xF7, 0x67,
    0xCC, 0x40, 0x05, 0x61, 0xF9, 0x89, 0x8A, 0xF0, 0xCB, 0x03, 0xD9, 0x19,
    0x8D, 0x63, 0x53, 0xB7, 0x2C, 0x53, 0x13, 0xA5, 0x3C, 0x5B, 0x5D, 0xDA,
    0x20, 0x96, 0xDD, 0x7F, 0xF8, 0x63, 0x5A, 0x47, 0x59, 0x10, 0x48, 0xA7,
    0x35, 0x84, 0xF2, 0x61, 0x4C, 0x3E, 0xAC, 0xE6, 0x06, 0x90, 0x96, 0x07,
    0xA3, 0x7B, 0x2D, 0x36, 0xEF, 0x5D, 0xD0, 0x5C, 0x0A, 0x1C, 0x4D, 0xA2,
    0x81, 0x18, 0xE3, 0x22, 0xFB, 0xBF, 0x9B, 0x12, 0x68, 0xAD, 0x6A, 0xCD,
    0xF2, 0x72, 0xD3, 0xBA, 0x24, 0x63, 0xCC, 0x45, 0x47, 0xDE, 0x83, 0xD6,
    0x8A, 0x94, 0xD2, 0xC1, 0xDC, 0xAB, 0xFD, 0x4E, 0xF0, 0x11, 0x21, 0xB9,
    0x0F, 0xF3, 0xEE, 0x87, 0xF9, 0x03, 0x1A, 0xB4, 0x75, 0x21, 0x81, 0xDA,
    0x2E, 0x1D, 0x82, 0x63, 0x26, 0x34, 0x56, 0x91, 0x2D, 0xDC, 0xFD, 0x0A,
    0xF2, 0x3F, 0xBA, 0x44, 0xCD, 0x81, 0x53, 0x1F, 0x8B, 0xD3, 0x38, 0x22,
    0x02, 0x05, 0x85, 0x35, 0x41, 0x50, 0xE8, 0x48, 0x6E, 0xE3, 0x7D, 0xA9,
    0xFE, 0x5C, 0x39,
};

static int test_DoUserAuthRequestRsaCert(void)
{
    WOLFSSH_CTX* ctx = NULL;
    WOLFSSH* ssh = NULL;
    const UserAuthRsaTestVector* tv;
    int tc = (int)(sizeof(userAuthRsaTestVectors)
            / sizeof(userAuthRsaTestVectors[0]));
    int i;
    int ret;
    int failures = 0;

    if ((userAuthRsaSigBlob[RSA_SIG_BLOB_SIG] & 0x80) == 0) {
        fprintf(stderr, "\tuserAuthRsaSigBlob needs its high bit set\n");
        return 1;
    }

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_SERVER, NULL);
    if (ctx == NULL)
        return 1;
    ssh = wolfSSH_new(ctx);
    if (ssh == NULL) {
        wolfSSH_CTX_free(ctx);
        return 1;
    }

    for (i = 0, tv = userAuthRsaTestVectors; i < tc; i++, tv++) {
        byte sigBlob[sizeof(userAuthRsaSigBlob)];
        byte digest[sizeof(userAuthRsaDigest)];
        WS_UserAuthData_PublicKey pk;

        WMEMCPY(sigBlob, userAuthRsaSigBlob, sizeof(sigBlob));
        WMEMCPY(digest, userAuthRsaDigest, sizeof(digest));
        if (tv->patchSz > 0)
            WMEMCPY(sigBlob + tv->patchIdx, tv->patch, tv->patchSz);
        if (tv->flipIdx > 0)
            sigBlob[tv->flipIdx] ^= 0x01;

        WMEMSET(&pk, 0, sizeof(pk));
        pk.publicKeyType = (const byte*)"x509v3-ssh-rsa";
        pk.publicKeyTypeSz = 14;
        pk.publicKey = userAuthRsaCertDer;
        pk.publicKeySz = (word32)sizeof(userAuthRsaCertDer);
        pk.hasSignature = 1;
        pk.signature = sigBlob;
        pk.signatureSz = (word32)sizeof(sigBlob);

        ret = wolfSSH_TestDoUserAuthRequestRsaCert(ssh, &pk, WC_HASH_TYPE_SHA,
                digest, (word32)sizeof(digest));
        if (ret != tv->expected) {
            fprintf(stderr, "\t[%d] \"%s\" FAIL: got %d, expected %d\n",
                    i, tv->name, ret, tv->expected);
            failures++;
        }
    }

    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);

    return failures;
}

#endif /* WOLFSSH_CERTS */

#endif /* !WOLFSSH_NO_RSA && !WOLFSSH_NO_SSH_RSA_SHA1 */

#ifdef WOLFSSH_SFTP
/* Property test for the server-side received-packet size bound applied in
 * wolfSSH_SFTP_read(). A non-positive size or one above the largest legal
 * inbound SFTP message must be rejected before any buffer is allocated;
 * in-range sizes are accepted. */
static int test_SftpRecvSizeBound(void)
{
    int testVals[7];
    int expectOk;
    int ret;
    int i;
    int maxWriteBody;

    testVals[0] = -1;                          /* underflow / error sentinel */
    testVals[1] = 0;                           /* empty body */
    testVals[2] = 1;                           /* smallest accepted body */
    testVals[3] = WOLFSSH_MAX_SFTP_PACKET;     /* upper bound, accepted */
    testVals[4] = WOLFSSH_MAX_SFTP_PACKET + 1; /* just over the bound */
    testVals[5] = 0x40000000;                  /* the ~1 GB attack value */
    testVals[6] = 0x7FFFFFFF;                  /* INT32_MAX */

    for (i = 0; i < (int)(sizeof(testVals) / sizeof(testVals[0])); i++) {
        ret = wolfSSH_TestSftpRecvSizeCheck(testVals[i]);

        expectOk = (testVals[i] > 0 &&
                    testVals[i] <= WOLFSSH_MAX_SFTP_PACKET);

        if (expectOk) {
            if (ret != WS_SUCCESS)
                return -900 - i;
        }
        else {
            if (ret == WS_SUCCESS)
                return -920 - i;
        }
    }

    /* The bound value must be large enough to admit a real maximum-size WRITE,
     * otherwise legitimate large writes would be silently rejected. A WRITE
     * body is a handle string (length prefix + up to WOLFSSH_MAX_HANDLE), an
     * 8-byte file offset, then a data string (length prefix + up to
     * WOLFSSH_MAX_SFTP_RW). Guards against a future shrink of the bound (e.g.
     * to WOLFSSH_MAX_SFTP_RECV alone). */
    maxWriteBody = UINT32_SZ + WOLFSSH_MAX_HANDLE   /* handle string  */
                 + (2 * UINT32_SZ)                  /* 64-bit offset  */
                 + UINT32_SZ + WOLFSSH_MAX_SFTP_RW; /* data string    */
    if (wolfSSH_TestSftpRecvSizeCheck(maxWriteBody) != WS_SUCCESS)
        return -930;

    return 0;
}

/* IORecv mock that reports no data is available yet. ReceiveData maps this to
 * WS_WANT_READ, letting the receive loop reach its body-read state without a
 * live socket. */
static int RecvAlwaysWantRead(WOLFSSH* ssh, void* data, word32 sz, void* ctx)
{
    WOLFSSH_UNUSED(ssh);
    WOLFSSH_UNUSED(data);
    WOLFSSH_UNUSED(sz);
    WOLFSSH_UNUSED(ctx);
    return WS_CBIO_ERR_WANT_READ;
}

/* Drives a single crafted SFTP request header through wolfSSH_SFTP_read() on a
 * fresh server session. The on-wire length field is set to len and the message
 * type to WRITE; only the 9-byte header is staged in the channel input buffer,
 * never a body. ioRecv, when non-NULL, stands in for the socket if the loop is
 * admitted and reaches its body-read state. On success fills *outRet with the
 * wolfSSH_SFTP_read() return and *outErr with ssh->error, and returns 0; on a
 * setup failure returns a negative sentinel. DiscardIoSend absorbs the
 * window-adjust emitted after the header is consumed, and acceptState is
 * advanced so that adjust is allowed on the bare session. */
static int SftpRecvDriveHeader(word32 len, WS_CallbackIORecv ioRecv,
        int* outRet, int* outErr)
{
    WOLFSSH_CTX*     ctx = NULL;
    WOLFSSH*         ssh = NULL;
    WOLFSSH_CHANNEL* ch  = NULL;
    int  result = 0;
    byte header[WOLFSSH_SFTP_HEADER];

    *outRet = WS_SUCCESS;
    *outErr = WS_SUCCESS;

    header[0] = (byte)((len >> 24) & 0xFF);
    header[1] = (byte)((len >> 16) & 0xFF);
    header[2] = (byte)((len >>  8) & 0xFF);
    header[3] = (byte)( len        & 0xFF);
    header[LENGTH_SZ] = WOLFSSH_FTP_WRITE;            /* message type */
    header[LENGTH_SZ + MSG_ID_SZ + 0] = 0x00;        /* request id = 1 */
    header[LENGTH_SZ + MSG_ID_SZ + 1] = 0x00;
    header[LENGTH_SZ + MSG_ID_SZ + 2] = 0x00;
    header[LENGTH_SZ + MSG_ID_SZ + 3] = 0x01;

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_SERVER, NULL);
    if (ctx == NULL)
        return -1000;
    wolfSSH_SetIOSend(ctx, DiscardIoSend);
    if (ioRecv != NULL)
        wolfSSH_SetIORecv(ctx, ioRecv);

    ssh = wolfSSH_new(ctx);
    if (ssh == NULL) { result = -1001; goto done; }
    /* Allow MSGID_CHANNEL_WINDOW_ADJUST on this bare session. */
    ssh->acceptState = ACCEPT_SERVER_USERAUTH_SENT;

    ch = ChannelNew(ssh, ID_CHANTYPE_SESSION, 1024, 1024);
    if (ch == NULL) { result = -1002; goto done; }
    if (ChannelAppend(ssh, ch) != WS_SUCCESS) {
        ChannelDelete(ch, ssh->ctx->heap);
        result = -1003;
        goto done;
    }

    if (wolfSSH_TestChannelPutData(ssh->channelList, header,
                (word32)sizeof(header)) != WS_SUCCESS) {
        result = -1004;
        goto done;
    }

    *outRet = wolfSSH_SFTP_read(ssh);
    *outErr = wolfSSH_get_error(ssh);

done:
    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);
    return result;
}

/* End-to-end check that the receive loop itself rejects an invalid declared
 * inbound length, not just the SFTP_CheckRecvSz helper in isolation. Drives two
 * crafted headers whose decoded body length the bound must refuse: one well
 * past WOLFSSH_MAX_SFTP_PACKET and one of zero. Each must return WS_FATAL_ERROR
 * with ssh->error == WS_BUFFER_E and allocate no body buffer. The zero case
 * also guards against ssh->error being left at 0, which a caller could misread
 * as a clean channel close. */
static int test_SftpRecvSizeBoundIntegration(void)
{
    word32 lens[2];
    int    rc;
    int    ret;
    int    err;
    int    i;

    /* On-wire length field counts the type byte, request id, and body. */
    lens[0] = (word32)WOLFSSH_MAX_SFTP_PACKET + 100 + MSG_ID_SZ + UINT32_SZ;
    lens[1] = (word32)(MSG_ID_SZ + UINT32_SZ);   /* decoded body length 0 */

    for (i = 0; i < (int)(sizeof(lens) / sizeof(lens[0])); i++) {
        rc = SftpRecvDriveHeader(lens[i], NULL, &ret, &err);
        if (rc != 0)
            return rc;
        if (ret != WS_FATAL_ERROR)
            return -945 - (i * 10);
        if (err != WS_BUFFER_E)
            return -946 - (i * 10);
    }

    return 0;
}

/* End-to-end check that a legitimate maximum-size WRITE is NOT rejected by the
 * server bound. The decoded body length equals the largest real WRITE body
 * (handle + 8-byte offset + max data). The bound must admit it: the loop
 * allocates the body buffer and then asks for the body that has not arrived, so
 * the call returns WS_FATAL_ERROR with ssh->error == WS_WANT_READ (a benign
 * retry) rather than WS_BUFFER_E (a bound rejection). RecvAlwaysWantRead stands
 * in for a non-blocking socket with no data yet. */
static int test_SftpRecvSizeBoundAccept(void)
{
    word32 len;
    int    rc;
    int    ret;
    int    err;

    /* Largest legitimate WRITE body, matching test_SftpRecvSizeBound, plus the
     * type byte and request id the on-wire length field carries. */
    len = (word32)(UINT32_SZ + WOLFSSH_MAX_HANDLE
                 + (2 * UINT32_SZ)
                 + UINT32_SZ + WOLFSSH_MAX_SFTP_RW)
        + MSG_ID_SZ + UINT32_SZ;

    rc = SftpRecvDriveHeader(len, RecvAlwaysWantRead, &ret, &err);
    if (rc != 0)
        return rc;
    if (ret != WS_FATAL_ERROR)
        return -955;
    /* WS_WANT_READ: body accepted, loop waiting; WS_BUFFER_E would mean a
     * legitimate max WRITE was rejected. */
    if (err != WS_WANT_READ)
        return -956;

    return 0;
}
#endif /* WOLFSSH_SFTP */

#if defined(WOLFSSH_TEST_INTERNAL) && defined(WOLFSSH_SCP) && \
    !defined(WOLFSSH_SCP_USER_CALLBACKS)
/* Exercises ExtractFileName, the SCP source helper that splits the leaf name
 * from a request path. A bare name with no path separator must be accepted
 * (the whole string is the file name); this is the recursive-source
 * regression. */
static int test_ScpExtractFileName(void)
{
    char name[64];
    int ret;

    /* bare name, no separator: whole string is the file name (regression) */
    WMEMSET(name, 0, sizeof(name));
    ret = wolfSSH_TestScpExtractFileName("scp_rk_src", name, sizeof(name));
    if (ret != WS_SUCCESS || WSTRCMP(name, "scp_rk_src") != 0)
        return -900;

    /* leading "./" prefix */
    WMEMSET(name, 0, sizeof(name));
    ret = wolfSSH_TestScpExtractFileName("./scp_rk_src", name, sizeof(name));
    if (ret != WS_SUCCESS || WSTRCMP(name, "scp_rk_src") != 0)
        return -901;

    /* relative nested path */
    WMEMSET(name, 0, sizeof(name));
    ret = wolfSSH_TestScpExtractFileName("a/b/c", name, sizeof(name));
    if (ret != WS_SUCCESS || WSTRCMP(name, "c") != 0)
        return -902;

    /* absolute path */
    WMEMSET(name, 0, sizeof(name));
    ret = wolfSSH_TestScpExtractFileName("/tmp/x/y", name, sizeof(name));
    if (ret != WS_SUCCESS || WSTRCMP(name, "y") != 0)
        return -903;

    /* empty path is rejected */
    ret = wolfSSH_TestScpExtractFileName("", name, sizeof(name));
    if (ret != WS_BAD_ARGUMENT)
        return -904;

    /* NULL arguments are rejected */
    ret = wolfSSH_TestScpExtractFileName(NULL, name, sizeof(name));
    if (ret != WS_BAD_ARGUMENT)
        return -905;
    ret = wolfSSH_TestScpExtractFileName("scp_rk_src", NULL, sizeof(name));
    if (ret != WS_BAD_ARGUMENT)
        return -906;

    /* destination too small for name plus null terminator */
    ret = wolfSSH_TestScpExtractFileName("scp_rk_src", name, 4);
    if (ret != WS_SCP_PATH_LEN_E)
        return -907;

    /* bare "." and ".." are accepted as-is (separator-less leaf names); the
     * recursive walk skips "."/".." directory entries separately */
    WMEMSET(name, 0, sizeof(name));
    ret = wolfSSH_TestScpExtractFileName(".", name, sizeof(name));
    if (ret != WS_SUCCESS || WSTRCMP(name, ".") != 0)
        return -908;

    WMEMSET(name, 0, sizeof(name));
    ret = wolfSSH_TestScpExtractFileName("..", name, sizeof(name));
    if (ret != WS_SUCCESS || WSTRCMP(name, "..") != 0)
        return -909;

    /* trailing separator yields an empty leaf name with success */
    WMEMSET(name, 0, sizeof(name));
    ret = wolfSSH_TestScpExtractFileName("a/b/", name, sizeof(name));
    if (ret != WS_SUCCESS || WSTRCMP(name, "") != 0)
        return -910;

    /* exact-fit boundary of the (fileLen + 1 > fileNameSz) size check:
     * "scp_rk_src" is 10 chars, so 11 just fits and 10 is one too small */
    WMEMSET(name, 0, sizeof(name));
    ret = wolfSSH_TestScpExtractFileName("scp_rk_src", name, 11);
    if (ret != WS_SUCCESS || WSTRCMP(name, "scp_rk_src") != 0)
        return -911;
    ret = wolfSSH_TestScpExtractFileName("scp_rk_src", name, 10);
    if (ret != WS_SCP_PATH_LEN_E)
        return -912;

    return 0;
}
#endif /* WOLFSSH_TEST_INTERNAL && WOLFSSH_SCP && !WOLFSSH_SCP_USER_CALLBACKS */

#endif /* WOLFSSH_TEST_INTERNAL */

/* Error Code And Message Test */

static int test_Errors(void)
{
    const char* errStr;
    const char* unknownStr = wolfSSH_ErrorToName(1);
    int result = 0;

#ifdef NO_WOLFSSH_STRINGS
    /* Ensure a valid error code's string matches an invalid code's.
     * The string is that error strings are not available.
     */
    errStr = wolfSSH_ErrorToName(WS_BAD_ARGUMENT);
    if (errStr != unknownStr)
        result = -104;
#else
    int i, j = 0;
    /* Values that are not or no longer error codes. */
    int missing[] = { -1059 };
    int missingSz = (int)sizeof(missing)/sizeof(missing[0]);

    /* Check that all errors have a string and it's the same through the two
     * APIs. Check that the values that are not errors map to the unknown
     * string.  */
    for (i = WS_ERROR; i >= WS_LAST_E; i--) {
        errStr = wolfSSH_ErrorToName(i);

        if (j < missingSz && i == missing[j]) {
            j++;
            if (errStr != unknownStr) {
                result = -105;
                break;
            }
        }
        else {
            if (errStr == unknownStr) {
                result = -106;
                break;
            }
        }
    }

    /* Check if the next possible value has been given a string. */
    if (result == 0) {
        errStr = wolfSSH_ErrorToName(i);
        if (errStr != unknownStr)
            return -107;
    }
#endif

    return result;
}

#if defined(WOLFSSH_SFTP) && defined(WOLFSSH_TEST_INTERNAL)
/* Inject a crafted SFTP NAME header declaring an on-wire payload length of
 * 'wireLen' into a channel, drive wolfSSH_SFTP_DoName, and report ssh->error
 * via outErr. Only the 9-byte header is needed: the NAME size bound is
 * checked before the message body is read. Returns 0 on setup success. */
static int sftpDoNameInjectErr(word32 wireLen, int* outErr)
{
    WOLFSSH_CTX*     ctx = NULL;
    WOLFSSH*         ssh = NULL;
    WOLFSSH_CHANNEL* ch  = NULL;
    byte   hdr[LENGTH_SZ + MSG_ID_SZ + UINT32_SZ];
    int    result = 0;

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_CLIENT, NULL);
    if (ctx == NULL)
        return -560;
    ssh = wolfSSH_new(ctx);
    if (ssh == NULL) {
        wolfSSH_CTX_free(ctx);
        return -561;
    }

    ch = ChannelNew(ssh, ID_CHANTYPE_SESSION, 128, 128);
    if (ch == NULL) {
        result = -562;
        goto done;
    }
    if (ChannelAppend(ssh, ch) != WS_SUCCESS) {
        ChannelDelete(ch, ssh->ctx->heap);
        result = -563;
        goto done;
    }

    /* SFTP header: [uint32 length][byte type][uint32 reqId]. */
    hdr[0] = (byte)(wireLen >> 24);
    hdr[1] = (byte)(wireLen >> 16);
    hdr[2] = (byte)(wireLen >> 8);
    hdr[3] = (byte)(wireLen);
    hdr[LENGTH_SZ] = WOLFSSH_FTP_NAME;
    hdr[LENGTH_SZ + MSG_ID_SZ + 0] = 0;
    hdr[LENGTH_SZ + MSG_ID_SZ + 1] = 0;
    hdr[LENGTH_SZ + MSG_ID_SZ + 2] = 0;
    hdr[LENGTH_SZ + MSG_ID_SZ + 3] = 0;

    /* Leave reqId non-matching so an in-bound header exits at the request-id
     * check without setting WS_BUFFER_E. */
    ssh->reqId = 0xFFFFFFFF;
    ssh->error = WS_SUCCESS;

    if (wolfSSH_TestChannelPutData(ch, hdr, (word32)sizeof(hdr))
            != WS_SUCCESS) {
        result = -564;
        goto done;
    }

    *outErr = wolfSSH_TestSftpDoName(ssh);

done:
    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);
    return result;
}

/* Verify wolfSSH_SFTP_DoName rejects a NAME message larger than
 * WOLFSSH_MAX_SFTP_NAME and accepts one at the limit. SFTP_GetHeader
 * returns the wire length minus the type and request-id fields, so the
 * reported maxSz is wireLen - (UINT32_SZ + MSG_ID_SZ). */
static int test_SftpDoName_sizeBound(void)
{
    word32 overhead = UINT32_SZ + MSG_ID_SZ;
    int    err = 0;
    int    result;

    /* maxSz = WOLFSSH_MAX_SFTP_NAME + 1 -> over the bound, rejected. */
    err = WS_SUCCESS;
    result = sftpDoNameInjectErr(WOLFSSH_MAX_SFTP_NAME + overhead + 1, &err);
    if (result != 0)
        return result;
    if (err != WS_BUFFER_E)
        return -570;

    /* maxSz = WOLFSSH_MAX_SFTP_NAME -> at the bound, not rejected (exits at
     * the request-id check instead). */
    err = WS_SUCCESS;
    result = sftpDoNameInjectErr(WOLFSSH_MAX_SFTP_NAME + overhead, &err);
    if (result != 0)
        return result;
    if (err == WS_BUFFER_E)
        return -571;

    /* A wire length above INT_MAX makes SFTP_GetHeader's int result wrap
     * non-positive; this must be reported as a size error, not a silent
     * NULL with WS_SUCCESS. */
    err = WS_SUCCESS;
    result = sftpDoNameInjectErr(0x80000000U + overhead, &err);
    if (result != 0)
        return result;
    if (err != WS_BUFFER_E)
        return -572;

    return 0;
}
#endif /* WOLFSSH_SFTP && WOLFSSH_TEST_INTERNAL */

int wolfSSH_UnitTest(int argc, char** argv)
{
    int testResult = 0, unitResult = 0;

    (void)argc;
    (void)argv;

    wolfSSH_Init();

    unitResult = test_Errors();
    printf("Errors: %s\n", (unitResult == 0 ? "SUCCESS" : "FAILED"));
    testResult = testResult || unitResult;

    unitResult = test_KDF();
    printf("KDF: %s\n", (unitResult == 0 ? "SUCCESS" : "FAILED"));
    testResult = testResult || unitResult;

#ifdef WOLFSSH_TEST_INTERNAL
    unitResult = test_DoProtoId();
    printf("DoProtoId: %s\n", (unitResult == 0 ? "SUCCESS" : "FAILED"));
    testResult = testResult || unitResult;

    unitResult = test_GetMpint();
    printf("GetMpint: %s\n", (unitResult == 0 ? "SUCCESS" : "FAILED"));
    testResult = testResult || unitResult;
#endif

#if defined(WOLFSSH_TEST_INTERNAL) && \
    (!defined(WOLFSSH_NO_HMAC_SHA1) || \
     !defined(WOLFSSH_NO_HMAC_SHA1_96) || \
     !defined(WOLFSSH_NO_HMAC_SHA2_256) || \
     !defined(WOLFSSH_NO_HMAC_SHA2_512))
    unitResult = test_DoReceive_VerifyMacFailure();
    printf("DoReceiveVerifyMac: %s\n",
            (unitResult == 0 ? "SUCCESS" : "FAILED"));
    testResult = testResult || unitResult;
#endif

#ifdef WOLFSSH_TEST_INTERNAL
    unitResult = test_DoReceive_RejectsShortPadding();
    printf("DoReceiveRejectsShortPadding: %s\n",
            (unitResult == 0 ? "SUCCESS" : "FAILED"));
    testResult = testResult || unitResult;
#endif

#if defined(WOLFSSH_TEST_INTERNAL) && !defined(WOLFSSH_NO_DH_GEX_SHA256)
    unitResult = test_DhGexGroupValidate();
    printf("DhGexGroupValidate: %s\n",
            (unitResult == 0 ? "SUCCESS" : "FAILED"));
    testResult = testResult || unitResult;
#endif

#ifdef WOLFSSH_TEST_INTERNAL
    unitResult = test_DoUserAuthBanner();
    printf("DoUserAuthBanner: %s\n", (unitResult == 0 ? "SUCCESS" : "FAILED"));
    testResult = testResult || unitResult;

    unitResult = test_DoChannelRequest();
    printf("DoChannelRequest: %s\n", (unitResult == 0 ? "SUCCESS" : "FAILED"));
    testResult = testResult || unitResult;

    unitResult = test_DoChannelSuccess();
    printf("DoChannelSuccess: %s\n", (unitResult == 0 ? "SUCCESS" : "FAILED"));
    testResult = testResult || unitResult;

    unitResult = test_DoChannelFailure();
    printf("DoChannelFailure: %s\n", (unitResult == 0 ? "SUCCESS" : "FAILED"));
    testResult = testResult || unitResult;

    unitResult = test_DoChannelData_overflow();
    printf("DoChannelData_overflow: %s\n", (unitResult == 0 ? "SUCCESS" : "FAILED"));
    testResult = testResult || unitResult;

    unitResult = test_DoChannelExtendedData_overflow();
    printf("DoChannelExtendedData_overflow: %s\n",
           (unitResult == 0 ? "SUCCESS" : "FAILED"));
    testResult = testResult || unitResult;

    unitResult = test_SendChannelData_eofTxd();
    printf("SendChannelData_eofTxd: %s\n", (unitResult == 0 ? "SUCCESS" : "FAILED"));
    testResult = testResult || unitResult;

#ifdef WOLFSSH_SFTP
    unitResult = test_SftpDoName_sizeBound();
    printf("SftpDoName_sizeBound: %s\n", (unitResult == 0 ? "SUCCESS" : "FAILED"));
    testResult = testResult || unitResult;
#endif
#if !defined(WOLFSSH_NO_RSA)
    unitResult = test_RsaVerify_BadDigest();
    printf("RsaVerify_BadDigest: %s\n",
            (unitResult == 0 ? "SUCCESS" : "FAILED"));
    testResult = testResult || unitResult;
#endif
#if !defined(WOLFSSH_NO_RSA) && !defined(WOLFSSH_NO_SSH_RSA_SHA1)
    unitResult = test_DoUserAuthRequestRsa();
    printf("DoUserAuthRequestRsa: %s\n",
            (unitResult == 0 ? "SUCCESS" : "FAILED"));
    testResult = testResult || unitResult;

    unitResult = test_ParseRSAPubKey();
    printf("ParseRSAPubKey: %s\n",
            (unitResult == 0 ? "SUCCESS" : "FAILED"));
    testResult = testResult || unitResult;
#ifdef WOLFSSH_CERTS
    unitResult = test_DoUserAuthRequestRsaCert();
    printf("DoUserAuthRequestRsaCert: %s\n",
            (unitResult == 0 ? "SUCCESS" : "FAILED"));
    testResult = testResult || unitResult;
#endif
#endif
#if !defined(WOLFSSH_NO_ECDSA_SHA2_NISTP256)
    unitResult = test_ParseECCPubKey();
    printf("ParseECCPubKey: %s\n",
            (unitResult == 0 ? "SUCCESS" : "FAILED"));
    testResult = testResult || unitResult;
#endif
#if !defined(WOLFSSH_NO_ED25519) && defined(HAVE_ED25519) && \
    defined(HAVE_ED25519_SIGN) && defined(HAVE_ED25519_VERIFY) && \
    defined(WOLFSSL_ED25519_STREAMING_VERIFY)
    unitResult = test_DoUserAuthRequestEd25519();
    printf("DoUserAuthRequestEd25519: %s\n",
            (unitResult == 0 ? "SUCCESS" : "FAILED"));
    testResult = testResult || unitResult;

    unitResult = test_ParseEd25519PubKey();
    printf("ParseEd25519PubKey: %s\n",
            (unitResult == 0 ? "SUCCESS" : "FAILED"));
    testResult = testResult || unitResult;
#endif
#ifndef WOLFSSH_NO_MLDSA
    unitResult = test_DoUserAuthRequestMlDsa();
    printf("DoUserAuthRequestMlDsa: %s (result=%d)\n",
            (unitResult == 0 ? "SUCCESS" : "FAILED"), unitResult);
    testResult = testResult || (unitResult != 0);
#ifdef WOLFSSH_KEYGEN
    unitResult = test_PrepareUserAuthRequestMlDsa();
    printf("PrepareUserAuthRequestMlDsa: %s (result=%d)\n",
            (unitResult == 0 ? "SUCCESS" : "FAILED"), unitResult);
    testResult = testResult || (unitResult != 0);
#ifdef WOLFSSH_CERTS
    unitResult = test_PrepareUserAuthRequestMlDsaCert();
    printf("PrepareUserAuthRequestMlDsaCert: %s (result=%d)\n",
            (unitResult == 0 ? "SUCCESS" : "FAILED"), unitResult);
    testResult = testResult || (unitResult != 0);
#endif /* WOLFSSH_CERTS */
#endif /* WOLFSSH_KEYGEN */
    unitResult = test_BuildUserAuthRequestMlDsa();
    printf("BuildUserAuthRequestMlDsa: %s (result=%d)\n",
            (unitResult == 0 ? "SUCCESS" : "FAILED"), unitResult);
    testResult = testResult || (unitResult != 0);
#endif
    unitResult = test_ChannelPutData();
    printf("ChannelPutData: %s\n", (unitResult == 0 ? "SUCCESS" : "FAILED"));
    testResult = testResult || unitResult;

#if defined(WOLFSSH_TEST_INTERNAL) && defined(WOLFSSH_SCP)
    unitResult = test_ScpGetFileMode();
    printf("ScpGetFileMode: %s\n", (unitResult == 0 ? "SUCCESS" : "FAILED"));
    testResult = testResult || unitResult;
#endif

    unitResult = test_MsgHighwater();
    printf("MsgHighwater: %s\n", (unitResult == 0 ? "SUCCESS" : "FAILED"));
    testResult = testResult || unitResult;

    unitResult = test_DoUserAuthRequest_serviceName();
    printf("DoUserAuthRequest_serviceName: %s\n",
           (unitResult == 0 ? "SUCCESS" : "FAILED"));
    testResult = testResult || unitResult;

    unitResult = test_DoUserAuthRequest_rejectsPasswordChange();
    printf("DoUserAuthRequest_rejectsPasswordChange: %s\n",
           (unitResult == 0 ? "SUCCESS" : "FAILED"));
    testResult = testResult || unitResult;

    unitResult = test_SendUserAuthFailure_emptyMethods();
    printf("SendUserAuthFailure_emptyMethods: %s\n",
           (unitResult == 0 ? "SUCCESS" : "FAILED"));
    testResult = testResult || unitResult;

    unitResult = test_IdentifyAsn1Key();
    printf("IdentifyAsn1Key: %s\n", (unitResult == 0 ? "SUCCESS" : "FAILED"));
    testResult = testResult || unitResult;

#ifdef WOLFSSH_SFTP
    unitResult = test_SftpRecvSizeBound();
    printf("SftpRecvSizeBound: %s\n", (unitResult == 0 ? "SUCCESS" : "FAILED"));
    testResult = testResult || unitResult;

    unitResult = test_SftpRecvSizeBoundIntegration();
    printf("SftpRecvSizeBoundIntegration: %s\n",
            (unitResult == 0 ? "SUCCESS" : "FAILED"));
    testResult = testResult || unitResult;

    unitResult = test_SftpRecvSizeBoundAccept();
    printf("SftpRecvSizeBoundAccept: %s\n",
            (unitResult == 0 ? "SUCCESS" : "FAILED"));
    testResult = testResult || unitResult;
#endif

#if defined(WOLFSSH_SCP) && !defined(WOLFSSH_SCP_USER_CALLBACKS) && \
    !defined(NO_FILESYSTEM) && !defined(WOLFSSL_NUCLEUS) && \
    !defined(_WIN32) && !defined(WOLFSSH_ZEPHYR)
    unitResult = test_ScpRecvCallback_EndDirDepthGuard();
    printf("ScpRecvCallback_EndDirDepthGuard: %s\n",
            (unitResult == 0 ? "SUCCESS" : "FAILED"));
    testResult = testResult || unitResult;

    unitResult = test_ScpRecvCallback_NewDirChdirFail();
    printf("ScpRecvCallback_NewDirChdirFail: %s\n",
            (unitResult == 0 ? "SUCCESS" : "FAILED"));
    testResult = testResult || unitResult;

    unitResult = test_ScpRecvCallback_SymlinkGuard();
    printf("ScpRecvCallback_SymlinkGuard: %s\n",
            (unitResult == 0 ? "SUCCESS" : "FAILED"));
    testResult = testResult || unitResult;

    unitResult = test_ScpRecvCallback_Timestamp();
    printf("ScpRecvCallback_Timestamp: %s\n",
            (unitResult == 0 ? "SUCCESS" : "FAILED"));
    testResult = testResult || unitResult;

#if defined(HAVE_UTIMENSAT) && defined(WOLFSSH_HAVE_SYMLINK)
    unitResult = test_ScpTimestamp_NoFollow();
    printf("ScpTimestamp_NoFollow: %s\n",
            (unitResult == 0 ? "SUCCESS" : "FAILED"));
    testResult = testResult || unitResult;
#endif
#endif

#if defined(WOLFSSH_TEST_INTERNAL) && defined(WOLFSSH_SCP) && \
    !defined(WOLFSSH_SCP_USER_CALLBACKS)
    unitResult = test_ScpExtractFileName();
    printf("ScpExtractFileName: %s\n",
           (unitResult == 0 ? "SUCCESS" : "FAILED"));
    testResult = testResult || unitResult;
#endif

#ifdef WOLFSSH_TEST_CAPTURING_ALLOCATOR
    unitResult = test_SshResourceFree_zeroesSecrets();
    printf("SshResourceFree_zeroesSecrets: %s\n",
            (unitResult == 0 ? "SUCCESS" : "FAILED"));
    testResult = testResult || unitResult;
    unitResult = test_HandshakeInfoFree_zeroesSecrets();
    printf("HandshakeInfoFree_zeroesSecrets: %s\n",
            (unitResult == 0 ? "SUCCESS" : "FAILED"));
    testResult = testResult || unitResult;
#endif

#ifndef WOLFSSH_NO_DH
    unitResult = test_KeyAgreeDh_client_zeroesEphemeralPrivKey();
    printf("KeyAgreeDh_client_zeroesEphemeralPrivKey: %s\n",
            (unitResult == 0 ? "SUCCESS" : "FAILED"));
    testResult = testResult || unitResult;

    unitResult = test_KeyAgreeDh_server_rejectsBadPeerPublic();
    printf("KeyAgreeDh_server_rejectsBadPeerPublic: %s\n",
            (unitResult == 0 ? "SUCCESS" : "FAILED"));
    testResult = testResult || unitResult;

    unitResult = test_KeyAgreeDh_client_rejectsBadPeerPublic();
    printf("KeyAgreeDh_client_rejectsBadPeerPublic: %s\n",
            (unitResult == 0 ? "SUCCESS" : "FAILED"));
    testResult = testResult || unitResult;

#if defined(WOLFSSH_SMALL_STACK) && defined(WOLFSSH_TEST_CAPTURING_ALLOCATOR)
    unitResult = test_KeyAgreeDh_server_zeroesEphemeralPrivKey();
    printf("KeyAgreeDh_server_zeroesEphemeralPrivKey: %s\n",
            (unitResult == 0 ? "SUCCESS" : "FAILED"));
    testResult = testResult || unitResult;
#endif

    unitResult = test_KeyAgreeDh_server_rejectsOutOfRangePeer();
    printf("KeyAgreeDh_server_rejectsOutOfRangePeer: %s\n",
            (unitResult == 0 ? "SUCCESS" : "FAILED"));
    testResult = testResult || unitResult;

#ifdef HAVE_FFDHE_2048
    unitResult = test_KeyAgreeDh_client_rejectsOutOfRangePeer();
    printf("KeyAgreeDh_client_rejectsOutOfRangePeer: %s\n",
            (unitResult == 0 ? "SUCCESS" : "FAILED"));
    testResult = testResult || unitResult;
#endif
#endif /* !WOLFSSH_NO_DH */

#if !defined(WOLFSSH_NO_ECDH) && !defined(WOLFSSH_NO_ECDH_SHA2_NISTP256)
    unitResult = test_KeyAgreeEcdh_server_rejectsOffCurvePoint();
    printf("KeyAgreeEcdh_server_rejectsOffCurvePoint: %s\n",
            (unitResult == 0 ? "SUCCESS" : "FAILED"));
    testResult = testResult || unitResult;

    unitResult = test_KeyAgreeEcdh_client_rejectsOffCurvePoint();
    printf("KeyAgreeEcdh_client_rejectsOffCurvePoint: %s\n",
            (unitResult == 0 ? "SUCCESS" : "FAILED"));
    testResult = testResult || unitResult;
#endif /* !WOLFSSH_NO_ECDH && !WOLFSSH_NO_ECDH_SHA2_NISTP256 */

#endif

#ifdef WOLFSSH_TEST_CERTMAN_PROMOTE
    unitResult = test_CertMan_NoPromoteNonCaIntermediate();
    printf("CertMan_NoPromoteNonCaIntermediate: %s\n",
            (unitResult == 0 ? "SUCCESS" : "FAILED"));
    testResult = testResult || unitResult;

    unitResult = test_CertMan_PromoteValidCaIntermediate();
    printf("CertMan_PromoteValidCaIntermediate: %s\n",
            (unitResult == 0 ? "SUCCESS" : "FAILED"));
    testResult = testResult || unitResult;
#endif

#ifdef WOLFSSH_KEYGEN
#ifndef WOLFSSH_NO_RSA
    unitResult = test_RsaKeyGen();
    printf("RsaKeyGen: %s\n", (unitResult == 0 ? "SUCCESS" : "FAILED"));
    testResult = testResult || unitResult;
#endif
#ifndef WOLFSSH_NO_ECDSA
    unitResult = test_EcdsaKeyGen();
    printf("EcdsaKeyGen: %s\n", (unitResult == 0 ? "SUCCESS" : "FAILED"));
    testResult = testResult || unitResult;
#endif
#if !defined(WOLFSSH_NO_ED25519) && defined(HAVE_ED25519) && \
    defined(HAVE_ED25519_MAKE_KEY) && defined(HAVE_ED25519_KEY_EXPORT)
    unitResult = test_Ed25519KeyGen();
    printf("Ed25519KeyGen: %s\n", (unitResult == 0 ? "SUCCESS" : "FAILED"));
    testResult = testResult || unitResult;
#endif
#ifndef WOLFSSH_NO_MLDSA
    unitResult = test_MlDsaKeyGen();
    printf("MlDsaKeyGen: %s\n", (unitResult == 0 ? "SUCCESS" : "FAILED"));
    testResult = testResult || unitResult;
#endif
#endif

    wolfSSH_Cleanup();

    return (testResult ? 1 : 0);
}

#ifndef NO_UNITTEST_MAIN_DRIVER
int main(int argc, char** argv)
{
    return wolfSSH_UnitTest(argc, argv);
}
#endif

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

#if defined(WOLFSSH_SCP) && !defined(WOLFSSH_SCP_USER_CALLBACKS) && \
    !defined(NO_FILESYSTEM) && !defined(WOLFSSL_NUCLEUS) && \
    !defined(_WIN32) && !defined(WOLFSSH_ZEPHYR)
#include <limits.h>
#include <stdlib.h>
#include <string.h>
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
 *   "digitalSignature" KeyUsage present but lacking keyCertSign: an intermediate
 *                     CA that must be demoted (the keyCertSign-rejection branch).
 *
 * expectPromote==1 asserts the intermediate was promoted (verify returns
 * anything but WS_CERT_NO_SIGNER_E); ==0 asserts it was not (verify returns
 * WS_CERT_NO_SIGNER_E). Promotion is the unit under test, not full chain
 * success: with FPKI profile enforcement (--enable-all) a promoted chain's
 * synthetic leaf is rejected later with WS_CERT_PROFILE_E, which is
 * orthogonal -- hence the "anything but WS_CERT_NO_SIGNER_E" success criterion
 * mirroring the negative test's sanity check. */
static int certmanCheckIntermediate(const char* interKeyUsage, int expectPromote)
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
    if (certmanLoadFile("./keys/ca-key-ecc.der", &rootKeyBuf, &rootKeySz) != 0) {
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

    /* Pass a garbage f to force wc_DhAgree to fail (the DH context has no
     * prime group set). The ForceZero on x runs regardless of the result. */
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
 * while staying deterministic regardless of underlying malloc state. */
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
#elif !defined(WOLFSSH_NO_DH_GROUP14_SHA1)
    ssh->handshake->kexId = ID_DH_GROUP14_SHA1;
#else
    ssh->handshake->kexId = ID_DH_GROUP1_SHA1;
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
#endif /* !WOLFSSH_NO_DH */

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

#endif /* WOLFSSH_SCP recv callback depth guard test */

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
#if !defined(WOLFSSH_NO_RSA)
    unitResult = test_RsaVerify_BadDigest();
    printf("RsaVerify_BadDigest: %s\n",
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
#endif
    unitResult = test_ChannelPutData();
    printf("ChannelPutData: %s\n", (unitResult == 0 ? "SUCCESS" : "FAILED"));
    testResult = testResult || unitResult;

    unitResult = test_MsgHighwater();
    printf("MsgHighwater: %s\n", (unitResult == 0 ? "SUCCESS" : "FAILED"));
    testResult = testResult || unitResult;

    unitResult = test_DoUserAuthRequest_serviceName();
    printf("DoUserAuthRequest_serviceName: %s\n",
           (unitResult == 0 ? "SUCCESS" : "FAILED"));
    testResult = testResult || unitResult;

    unitResult = test_IdentifyAsn1Key();
    printf("IdentifyAsn1Key: %s\n", (unitResult == 0 ? "SUCCESS" : "FAILED"));
    testResult = testResult || unitResult;

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
#endif

#ifdef WOLFSSH_TEST_CAPTURING_ALLOCATOR
    unitResult = test_SshResourceFree_zeroesSecrets();
    printf("SshResourceFree_zeroesSecrets: %s\n",
            (unitResult == 0 ? "SUCCESS" : "FAILED"));
    testResult = testResult || unitResult;
#endif

#ifndef WOLFSSH_NO_DH
    unitResult = test_KeyAgreeDh_client_zeroesEphemeralPrivKey();
    printf("KeyAgreeDh_client_zeroesEphemeralPrivKey: %s\n",
            (unitResult == 0 ? "SUCCESS" : "FAILED"));
    testResult = testResult || unitResult;

#if defined(WOLFSSH_SMALL_STACK) && defined(WOLFSSH_TEST_CAPTURING_ALLOCATOR)
    unitResult = test_KeyAgreeDh_server_zeroesEphemeralPrivKey();
    printf("KeyAgreeDh_server_zeroesEphemeralPrivKey: %s\n",
            (unitResult == 0 ? "SUCCESS" : "FAILED"));
    testResult = testResult || unitResult;
#endif
#endif /* !WOLFSSH_NO_DH */

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

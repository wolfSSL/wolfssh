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

    /* Case-insensitive match. DoProtoId uses WSTRNCASECMP. */
    { "lowercase ssh prefix",
      "ssh-2.0-wolfSSHv" LIBWOLFSSH_VERSION_STRING "\r\n",
      0, WS_SUCCESS, WOLFSSH_ENDPOINT_CLIENT },
    { "mixed case SSH prefix",
      "Ssh-2.0-wolfSSHv" LIBWOLFSSH_VERSION_STRING "\r\n",
      0, WS_SUCCESS, WOLFSSH_ENDPOINT_CLIENT },

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

/* Verify DoChannelRequest sends CHANNEL_SUCCESS for known types and
 * CHANNEL_FAILURE for unrecognized ones (RFC 4254 Section 5.4).
 *
 * A custom IoSend callback captures the outgoing packet in plaintext
 * (no cipher negotiated on a fresh session). The SSH packet layout is:
 *   [4-byte packet_length][1-byte padding_length][1-byte msg_id]...
 * so the message ID lives at byte offset 5. */
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

        if (s_chanReqCaptureSz <= 5) {
            printf("DoChannelRequest[%s]: captured packet too short (%u)\n",
                    cases[i].label, s_chanReqCaptureSz);
            result = -410 - i;
            goto done;
        }

        if (s_chanReqCapture[5] != cases[i].expectMsgId) {
            printf("DoChannelRequest[%s]: msg_id=0x%02x, expected=0x%02x\n",
                    cases[i].label,
                    s_chanReqCapture[5], cases[i].expectMsgId);
            result = -420 - i;
            goto done;
        }
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
#if !defined(WOLFSSH_NO_RSA)
    unitResult = test_RsaVerify_BadDigest();
    printf("RsaVerify_BadDigest: %s\n",
            (unitResult == 0 ? "SUCCESS" : "FAILED"));
    testResult = testResult || unitResult;
#endif
    unitResult = test_ChannelPutData();
    printf("ChannelPutData: %s\n", (unitResult == 0 ? "SUCCESS" : "FAILED"));
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

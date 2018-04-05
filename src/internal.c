/* internal.c
 *
 * Copyright (C) 2014-2016 wolfSSL Inc.
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
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/dh.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/integer.h>
#include <wolfssl/wolfcrypt/signature.h>

#ifdef NO_INLINE
    #include <wolfssh/misc.h>
#else
    #define WOLFSSH_MISC_INCLUDED
    #include "src/misc.c"
#endif


static const char sshProtoIdStr[] = "SSH-2.0-wolfSSHv"
                                    LIBWOLFSSH_VERSION_STRING
                                    "\r\n";
static const char OpenSSH[] = "SSH-2.0-OpenSSH";
#ifndef WOLFSSH_DEFAULT_GEXDH_MIN
    #define WOLFSSH_DEFAULT_GEXDH_MIN 1024
#endif
#ifndef WOLFSSH_DEFAULT_GEXDH_PREFERRED
    #define WOLFSSH_DEFAULT_GEXDH_PREFERRED 3072
#endif
#ifndef WOLFSSH_DEFAULT_GEXDH_MAX
    #define WOLFSSH_DEFAULT_GEXDH_MAX 8192
#endif


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

        case WS_RESOURCE_E:
            return "insufficient resources for new channel";

        case WS_INVALID_CHANTYPE:
            return "peer requested invalid channel type";

        case WS_INVALID_CHANID:
            return "peer requested invalid channel id";

        case WS_INVALID_USERNAME:
            return "invalid user name";

        case WS_CRYPTO_FAILED:
            return "crypto action failed";

        case WS_INVALID_STATE_E:
            return "invalid state";

        case WS_REKEYING:
            return "rekeying with peer";

        case WS_INVALID_PRIME_CURVE:
            return "invalid prime curve in ecc";

        case WS_ECC_E:
            return "ECDSA buffer error";

        case WS_CHANOPEN_FAILED:
            return "peer returned channel open failure";

        case WS_CHANNEL_CLOSED:
            return "channel closed";

        default:
            return "Unknown error code";
    }
#endif
}


static int wsHighwater(byte dir, void* ctx)
{
    int ret = WS_SUCCESS;

    (void)dir;

    if (ctx) {
        WOLFSSH* ssh = (WOLFSSH*)ctx;

        WLOG(WS_LOG_DEBUG, "HIGHWATER MARK: (%u) %s",
             wolfSSH_GetHighwater(ssh),
             (dir == WOLFSSH_HWSIDE_RECEIVE) ? "receive" : "transmit");

        ret = wolfSSH_TriggerKeyExchange(ssh);
    }

    return ret;
}


static INLINE void HighwaterCheck(WOLFSSH* ssh, byte side)
{
    if (!ssh->highwaterFlag && ssh->highwaterMark &&
        (ssh->txCount >= ssh->highwaterMark ||
         ssh->rxCount >= ssh->highwaterMark)) {

        WLOG(WS_LOG_DEBUG, "%s over high water mark",
             (side == WOLFSSH_HWSIDE_TRANSMIT) ? "Transmit" : "Receive");

        ssh->highwaterFlag = 1;

        if (ssh->ctx->highwaterCb)
            ssh->ctx->highwaterCb(side, ssh->highwaterCtx);
    }
}


static HandshakeInfo* HandshakeInfoNew(void* heap)
{
    HandshakeInfo* newHs;

    WLOG(WS_LOG_DEBUG, "Entering HandshakeInfoNew()");
    newHs = (HandshakeInfo*)WMALLOC(sizeof(HandshakeInfo),
                                    heap, DYNTYPE_HS);
    if (newHs != NULL) {
        WMEMSET(newHs, 0, sizeof(HandshakeInfo));
        newHs->kexId = ID_NONE;
        newHs->pubKeyId  = ID_NONE;
        newHs->encryptId = ID_NONE;
        newHs->macId = ID_NONE;
        newHs->blockSz = MIN_BLOCK_SZ;
        newHs->hashId = WC_HASH_TYPE_NONE;
        newHs->dhGexMinSz = WOLFSSH_DEFAULT_GEXDH_MIN;
        newHs->dhGexPreferredSz = WOLFSSH_DEFAULT_GEXDH_PREFERRED;
        newHs->dhGexMaxSz = WOLFSSH_DEFAULT_GEXDH_MAX;
    }

    return newHs;
}


static void HandshakeInfoFree(HandshakeInfo* hs, void* heap)
{
    (void)heap;

    WLOG(WS_LOG_DEBUG, "Entering HandshakeInfoFree()");
    if (hs) {
        WFREE(hs->kexInit, heap, DYNTYPE_STRING);
        WFREE(hs->primeGroup, heap, DYNTYPE_MPINT);
        WFREE(hs->generator, heap, DYNTYPE_MPINT);
        ForceZero(hs, sizeof(HandshakeInfo));
        WFREE(hs, heap, DYNTYPE_HS);
    }
}


#ifdef DEBUG_WOLFSSH

static const char cannedBanner[] =
    "CANNED BANNER\r\n"
    "This server is an example test server. "
    "It should have its own banner, but\r\n"
    "it is currently using a canned one in "
    "the library. Be happy or not.\r\n";
static const word32 cannedBannerSz = sizeof(cannedBanner) - 1;

#endif /* DEBUG_WOLFSSH */


WOLFSSH_CTX* CtxInit(WOLFSSH_CTX* ctx, byte side, void* heap)
{
    WLOG(WS_LOG_DEBUG, "Entering CtxInit()");

    if (ctx == NULL)
        return ctx;

    WMEMSET(ctx, 0, sizeof(WOLFSSH_CTX));

    if (heap)
        ctx->heap = heap;

    ctx->side = side;
#ifndef WOLFSSH_USER_IO
    ctx->ioRecvCb = wsEmbedRecv;
    ctx->ioSendCb = wsEmbedSend;
#endif /* WOLFSSH_USER_IO */
    ctx->highwaterMark = DEFAULT_HIGHWATER_MARK;
    ctx->highwaterCb = wsHighwater;
#ifdef DEBUG_WOLFSSH
    ctx->banner = cannedBanner;
    ctx->bannerSz = cannedBannerSz;
#endif /* DEBUG_WOLFSSH */

    return ctx;
}


void CtxResourceFree(WOLFSSH_CTX* ctx)
{
    WLOG(WS_LOG_DEBUG, "Entering CtxResourceFree()");

    if (ctx->privateKey) {
        ForceZero(ctx->privateKey, ctx->privateKeySz);
        WFREE(ctx->privateKey, ctx->heap, DYNTYPE_PRIVKEY);
    }
}


WOLFSSH* SshInit(WOLFSSH* ssh, WOLFSSH_CTX* ctx)
{
    HandshakeInfo* handshake;
    RNG*           rng;
    void*          heap;

    WLOG(WS_LOG_DEBUG, "Entering SshInit()");

    if (ssh == NULL || ctx == NULL)
        return ssh;
    heap = ctx->heap;

    handshake = HandshakeInfoNew(heap);
    rng = (RNG*)WMALLOC(sizeof(RNG), heap, DYNTYPE_RNG);

    if (handshake == NULL || rng == NULL || wc_InitRng(rng) != 0) {

        WLOG(WS_LOG_DEBUG, "SshInit: Cannot allocate memory.\n");
        WFREE(handshake, heap, DYNTYPE_HS);
        WFREE(rng, heap, DYNTYPE_RNG);
        WFREE(ssh, heap, DYNTYPE_SSH);
        return NULL;
    }

    WMEMSET(ssh, 0, sizeof(WOLFSSH));  /* default init to zeros */

    ssh->ctx         = ctx;
    ssh->error       = WS_SUCCESS;
    ssh->rfd         = -1;         /* set to invalid */
    ssh->wfd         = -1;         /* set to invalid */
    ssh->ioReadCtx   = &ssh->rfd;  /* prevent invalid access if not correctly */
    ssh->ioWriteCtx  = &ssh->wfd;  /* set */
    ssh->highwaterMark = ctx->highwaterMark;
    ssh->highwaterCtx  = (void*)ssh;
    ssh->acceptState = ACCEPT_BEGIN;
    ssh->clientState = CLIENT_BEGIN;
    ssh->isKeying    = 1;
    ssh->nextChannel = DEFAULT_NEXT_CHANNEL;
    ssh->blockSz     = MIN_BLOCK_SZ;
    ssh->encryptId   = ID_NONE;
    ssh->macId       = ID_NONE;
    ssh->peerBlockSz = MIN_BLOCK_SZ;
    ssh->rng         = rng;
    ssh->kSz         = sizeof(ssh->k);
    ssh->handshake   = handshake;

    if (BufferInit(&ssh->inputBuffer, 0, ctx->heap) != WS_SUCCESS ||
        BufferInit(&ssh->outputBuffer, 0, ctx->heap) != WS_SUCCESS) {

        wolfSSH_free(ssh);
        ssh = NULL;
    }

    return ssh;
}


void SshResourceFree(WOLFSSH* ssh, void* heap)
{
    /* when ssh holds resources, free here */
    (void)heap;

    WLOG(WS_LOG_DEBUG, "Entering sshResourceFree()");

    ShrinkBuffer(&ssh->inputBuffer, 1);
    ShrinkBuffer(&ssh->outputBuffer, 1);
    ForceZero(ssh->k, ssh->kSz);
    HandshakeInfoFree(ssh->handshake, heap);
    ForceZero(&ssh->keys, sizeof(Keys));
    ForceZero(&ssh->peerKeys, sizeof(Keys));
    if (ssh->rng) {
        wc_FreeRng(ssh->rng);
        WFREE(ssh->rng, heap, DYNTYPE_RNG);
    }
    if (ssh->userName) {
        WFREE(ssh->userName, heap, DYNTYPE_STRING);
    }
    if (ssh->peerProtoId) {
        WFREE(ssh->peerProtoId, heap, DYNTYPE_STRING);
    }
    if (ssh->channelList) {
        WOLFSSH_CHANNEL* cur = ssh->channelList;
        WOLFSSH_CHANNEL* next;
        while (cur) {
            next = cur->next;
            ChannelDelete(cur, heap);
            cur = next;
        }
    }
}


int wolfSSH_ProcessBuffer(WOLFSSH_CTX* ctx,
                          const byte* in, word32 inSz,
                          int format, int type)
{
    int dynamicType;
    void* heap;
    byte* der;
    word32 derSz;

    if (ctx == NULL || in == NULL || inSz == 0)
        return WS_BAD_ARGUMENT;

    if (format != WOLFSSH_FORMAT_ASN1 && format != WOLFSSH_FORMAT_PEM &&
                                         format != WOLFSSH_FORMAT_RAW)
        return WS_BAD_FILETYPE_E;

    if (type == BUFTYPE_CA)
        dynamicType = DYNTYPE_CA;
    else if (type == BUFTYPE_CERT)
        dynamicType = DYNTYPE_CERT;
    else if (type == BUFTYPE_PRIVKEY)
        dynamicType = DYNTYPE_PRIVKEY;
    else
        return WS_BAD_ARGUMENT;

    heap = ctx->heap;

    if (format == WOLFSSH_FORMAT_PEM)
        return WS_UNIMPLEMENTED_E;
    else {
        /* format is ASN1 or RAW */
        der = (byte*)WMALLOC(inSz, heap, dynamicType);
        if (der == NULL)
            return WS_MEMORY_E;
        WMEMCPY(der, in, inSz);
        derSz = inSz;
    }

    /* Maybe decrypt */

    if (type == BUFTYPE_PRIVKEY) {
        if (ctx->privateKey)
            WFREE(ctx->privateKey, heap, dynamicType);
        ctx->privateKey = der;
        ctx->privateKeySz = derSz;
    }
    else {
        WFREE(der, heap, dynamicType);
        return WS_UNIMPLEMENTED_E;
    }

    if (type == BUFTYPE_PRIVKEY && format != WOLFSSH_FORMAT_RAW) {
        /* Check RSA key */
        union {
            RsaKey rsa;
            ecc_key ecc;
        } key;
        word32 scratch = 0;
        int ret;

        if (wc_InitRsaKey(&key.rsa, NULL) < 0)
            return WS_RSA_E;

        ret = wc_RsaPrivateKeyDecode(der, &scratch, &key.rsa, derSz);
        wc_FreeRsaKey(&key.rsa);

        if (ret < 0) {
            /* Couldn't decode as RSA key. Try decoding as ECC key. */
            scratch = 0;
            if (wc_ecc_init_ex(&key.ecc, ctx->heap, INVALID_DEVID) != 0)
                return WS_ECC_E;

            ret = wc_EccPrivateKeyDecode(ctx->privateKey, &scratch,
                                         &key.ecc, ctx->privateKeySz);
            if (ret == 0) {
                int curveId = wc_ecc_get_curve_id(key.ecc.idx);
                if (curveId == ECC_SECP256R1 ||
                    curveId == ECC_SECP384R1 ||
                    curveId == ECC_SECP521R1) {

                    ctx->useEcc = curveId;
                }
                else
                    ret = WS_BAD_FILE_E;
            }
            wc_ecc_free(&key.ecc);

            if (ret != 0)
                return WS_BAD_FILE_E;
        }
    }

    return WS_SUCCESS;
}


int GenerateKey(byte hashId, byte keyId,
                byte* key, word32 keySz,
                const byte* k, word32 kSz,
                const byte* h, word32 hSz,
                const byte* sessionId, word32 sessionIdSz)
{
    word32 blocks, remainder;
    wc_HashAlg hash;
    byte kPad = 0;
    byte pad = 0;
    byte kSzFlat[LENGTH_SZ];
    int digestSz;
    int ret;

    if (key == NULL || keySz == 0 ||
        k == NULL || kSz == 0 ||
        h == NULL || hSz == 0 ||
        sessionId == NULL || sessionIdSz == 0) {

        WLOG(WS_LOG_DEBUG, "GK: bad argument");
        return WS_BAD_ARGUMENT;
    }

    digestSz = wc_HashGetDigestSize(hashId);
    if (digestSz == 0) {
        WLOG(WS_LOG_DEBUG, "GK: bad hash ID");
        return WS_BAD_ARGUMENT;
    }

    if (k[0] & 0x80) kPad = 1;
    c32toa(kSz + kPad, kSzFlat);

    blocks = keySz / digestSz;
    remainder = keySz % digestSz;

    ret = wc_HashInit(&hash, hashId);
    if (ret == WS_SUCCESS)
        ret = wc_HashUpdate(&hash, hashId, kSzFlat, LENGTH_SZ);
    if (ret == WS_SUCCESS && kPad)
        ret = wc_HashUpdate(&hash, hashId, &pad, 1);
    if (ret == WS_SUCCESS)
        ret = wc_HashUpdate(&hash, hashId, k, kSz);
    if (ret == WS_SUCCESS)
        ret = wc_HashUpdate(&hash, hashId, h, hSz);
    if (ret == WS_SUCCESS)
        ret = wc_HashUpdate(&hash, hashId, &keyId, sizeof(keyId));
    if (ret == WS_SUCCESS)
        ret = wc_HashUpdate(&hash, hashId, sessionId, sessionIdSz);

    if (ret == WS_SUCCESS) {
        if (blocks == 0) {
            if (remainder > 0) {
                byte lastBlock[WC_MAX_DIGEST_SIZE];
                ret = wc_HashFinal(&hash, hashId, lastBlock);
                if (ret == WS_SUCCESS)
                    WMEMCPY(key, lastBlock, remainder);
            }
        }
        else {
            word32 runningKeySz, curBlock;

            runningKeySz = digestSz;
            ret = wc_HashFinal(&hash, hashId, key);

            for (curBlock = 1; curBlock < blocks; curBlock++) {
                ret = wc_HashInit(&hash, hashId);
                if (ret != WS_SUCCESS) break;
                ret = wc_HashUpdate(&hash, hashId, kSzFlat, LENGTH_SZ);
                if (ret != WS_SUCCESS) break;
                if (kPad)
                    ret = wc_HashUpdate(&hash, hashId, &pad, 1);
                if (ret != WS_SUCCESS) break;
                ret = wc_HashUpdate(&hash, hashId, k, kSz);
                if (ret != WS_SUCCESS) break;
                ret = wc_HashUpdate(&hash, hashId, h, hSz);
                if (ret != WS_SUCCESS) break;
                ret = wc_HashUpdate(&hash, hashId, key, runningKeySz);
                if (ret != WS_SUCCESS) break;
                ret = wc_HashFinal(&hash, hashId, key + runningKeySz);
                if (ret != WS_SUCCESS) break;
                runningKeySz += digestSz;
            }

            if (remainder > 0) {
                byte lastBlock[WC_MAX_DIGEST_SIZE];
                if (ret == WS_SUCCESS)
                    ret = wc_HashInit(&hash, hashId);
                if (ret == WS_SUCCESS)
                    ret = wc_HashUpdate(&hash, hashId, kSzFlat, LENGTH_SZ);
                if (ret == WS_SUCCESS && kPad)
                    ret = wc_HashUpdate(&hash, hashId, &pad, 1);
                if (ret == WS_SUCCESS)
                    ret = wc_HashUpdate(&hash, hashId, k, kSz);
                if (ret == WS_SUCCESS)
                    ret = wc_HashUpdate(&hash, hashId, h, hSz);
                if (ret == WS_SUCCESS)
                    ret = wc_HashUpdate(&hash, hashId, key, runningKeySz);
                if (ret == WS_SUCCESS)
                    ret = wc_HashFinal(&hash, hashId, lastBlock);
                if (ret == WS_SUCCESS)
                    WMEMCPY(key + runningKeySz, lastBlock, remainder);
            }
        }
    }

    if (ret != WS_SUCCESS)
        ret = WS_CRYPTO_FAILED;

    return ret;
}


static int GenerateKeys(WOLFSSH* ssh)
{
    Keys* cK;
    Keys* sK;
    byte hashId;
    int ret = WS_SUCCESS;

    if (ssh == NULL)
        ret = WS_BAD_ARGUMENT;
    else {
        if (ssh->ctx->side == WOLFSSH_ENDPOINT_SERVER) {
            cK = &ssh->handshake->peerKeys;
            sK = &ssh->handshake->keys;
        }
        else {
            cK = &ssh->handshake->keys;
            sK = &ssh->handshake->peerKeys;
        }
        hashId = ssh->handshake->hashId;
    }

    if (ret == WS_SUCCESS)
        ret = GenerateKey(hashId, 'A',
                          cK->iv, cK->ivSz,
                          ssh->k, ssh->kSz, ssh->h, ssh->hSz,
                          ssh->sessionId, ssh->sessionIdSz);
    if (ret == WS_SUCCESS)
        ret = GenerateKey(hashId, 'B',
                          sK->iv, sK->ivSz,
                          ssh->k, ssh->kSz, ssh->h, ssh->hSz,
                          ssh->sessionId, ssh->sessionIdSz);
    if (ret == WS_SUCCESS)
        ret = GenerateKey(hashId, 'C',
                          cK->encKey, cK->encKeySz,
                          ssh->k, ssh->kSz, ssh->h, ssh->hSz,
                          ssh->sessionId, ssh->sessionIdSz);
    if (ret == WS_SUCCESS)
        ret = GenerateKey(hashId, 'D',
                          sK->encKey, sK->encKeySz,
                          ssh->k, ssh->kSz, ssh->h, ssh->hSz,
                          ssh->sessionId, ssh->sessionIdSz);
    if (!ssh->handshake->aeadMode) {
        if (ret == WS_SUCCESS)
            ret = GenerateKey(hashId, 'E',
                              cK->macKey, cK->macKeySz,
                              ssh->k, ssh->kSz, ssh->h, ssh->hSz,
                              ssh->sessionId, ssh->sessionIdSz);
        if (ret == WS_SUCCESS)
            ret = GenerateKey(hashId, 'F',
                              sK->macKey, sK->macKeySz,
                              ssh->k, ssh->kSz, ssh->h, ssh->hSz,
                              ssh->sessionId, ssh->sessionIdSz);
    }
#ifdef SHOW_SECRETS
    if (ret == WS_SUCCESS) {
        printf("\n** Showing Secrets **\nK:\n");
        DumpOctetString(ssh->k, ssh->kSz);
        printf("H:\n");
        DumpOctetString(ssh->h, ssh->hSz);
        printf("Session ID:\n");
        DumpOctetString(ssh->sessionId, ssh->sessionIdSz);
        printf("A:\n");
        DumpOctetString(cK->iv, cK->ivSz);
        printf("B:\n");
        DumpOctetString(sK->iv, sK->ivSz);
        printf("C:\n");
        DumpOctetString(cK->encKey, cK->encKeySz);
        printf("D:\n");
        DumpOctetString(sK->encKey, sK->encKeySz);
        printf("E:\n");
        DumpOctetString(cK->macKey, cK->macKeySz);
        printf("F:\n");
        DumpOctetString(sK->macKey, sK->macKeySz);
        printf("\n");
    }
#endif /* SHOW_SECRETS */

    return ret;
}


typedef struct {
    byte id;
    const char* name;
} NameIdPair;


static const NameIdPair NameIdMap[] = {
    { ID_NONE, "none" },

    /* Encryption IDs */
    { ID_AES128_CBC, "aes128-cbc" },
    { ID_AES128_GCM, "aes128-gcm@openssh.com" },

    /* Integrity IDs */
    { ID_HMAC_SHA1, "hmac-sha1" },
    { ID_HMAC_SHA1_96, "hmac-sha1-96" },
    { ID_HMAC_SHA2_256, "hmac-sha2-256" },

    /* Key Exchange IDs */
    { ID_DH_GROUP1_SHA1, "diffie-hellman-group1-sha1" },
    { ID_DH_GROUP14_SHA1, "diffie-hellman-group14-sha1" },
    { ID_DH_GEX_SHA256, "diffie-hellman-group-exchange-sha256" },
    { ID_ECDH_SHA2_NISTP256, "ecdh-sha2-nistp256" },
    { ID_ECDH_SHA2_NISTP384, "ecdh-sha2-nistp384" },
    { ID_ECDH_SHA2_NISTP521, "ecdh-sha2-nistp521" },

    /* Public Key IDs */
    { ID_SSH_RSA, "ssh-rsa" },
    { ID_ECDSA_SHA2_NISTP256, "ecdsa-sha2-nistp256" },
    { ID_ECDSA_SHA2_NISTP384, "ecdsa-sha2-nistp384" },
    { ID_ECDSA_SHA2_NISTP521, "ecdsa-sha2-nistp521" },

    /* Service IDs */
    { ID_SERVICE_USERAUTH, "ssh-userauth" },
    { ID_SERVICE_CONNECTION, "ssh-connection" },

    /* UserAuth IDs */
    { ID_USERAUTH_PASSWORD, "password" },
    { ID_USERAUTH_PUBLICKEY, "publickey" },

    /* Channel Type IDs */
    { ID_CHANTYPE_SESSION, "session" }
};


byte NameToId(const char* name, word32 nameSz)
{
    byte id = ID_UNKNOWN;
    word32 i;

    for (i = 0; i < (sizeof(NameIdMap)/sizeof(NameIdPair)); i++) {
        if (nameSz == WSTRLEN(NameIdMap[i].name) &&
            WSTRNCMP(name, NameIdMap[i].name, nameSz) == 0) {

            id = NameIdMap[i].id;
            break;
        }
    }

    return id;
}


const char* IdToName(byte id)
{
    const char* name = "unknown";
    word32 i;

    for (i = 0; i < (sizeof(NameIdMap)/sizeof(NameIdPair)); i++) {
        if (NameIdMap[i].id == id) {
            name = NameIdMap[i].name;
            break;
        }
    }

    return name;
}


WOLFSSH_CHANNEL* ChannelNew(WOLFSSH* ssh, byte channelType,
                            word32 initialWindowSz, word32 maxPacketSz)
{
    WOLFSSH_CHANNEL* newChannel = NULL;

    WLOG(WS_LOG_DEBUG, "Entering ChannelNew()");
    if (ssh == NULL || ssh->ctx == NULL) {
        WLOG(WS_LOG_DEBUG, "Trying to create new channel without ssh or ctx");
    }
    else {
        void* heap = ssh->ctx->heap;

        newChannel = (WOLFSSH_CHANNEL*)WMALLOC(sizeof(WOLFSSH_CHANNEL),
                                               heap, DYNTYPE_CHANNEL);
        if (newChannel != NULL)
        {
            byte* buffer;

            buffer = (byte*)WMALLOC(initialWindowSz, heap, DYNTYPE_BUFFER);
            if (buffer != NULL) {
                WMEMSET(newChannel, 0, sizeof(WOLFSSH_CHANNEL));
                newChannel->channelType = channelType;
                newChannel->channel = ssh->nextChannel++;
                newChannel->windowSz = initialWindowSz;
                newChannel->maxPacketSz = maxPacketSz;
                /*
                 * In the context of the channel input buffer, the buffer is
                 * a fixed size. The property length will be the insert point
                 * for new received data. The property idx will be the pull
                 * point for the data.
                 */
                newChannel->inputBuffer.heap = heap;
                newChannel->inputBuffer.buffer = buffer;
                newChannel->inputBuffer.bufferSz = initialWindowSz;
                newChannel->inputBuffer.dynamicFlag = 1;
            }
            else {
                WLOG(WS_LOG_DEBUG, "Unable to allocate new channel's buffer");
                WFREE(newChannel, heap, DYNTYPE_CHANNEL);
                newChannel = NULL;
            }
        }
        else {
            WLOG(WS_LOG_DEBUG, "Unable to allocate new channel");
        }
    }

    WLOG(WS_LOG_INFO, "Leaving ChannelNew(), ret = %p", newChannel);

    return newChannel;
}


void ChannelDelete(WOLFSSH_CHANNEL* channel, void* heap)
{
    (void)heap;

    if (channel) {
        WFREE(channel->inputBuffer.buffer,
              channel->inputBuffer.heap, DYNTYPE_BUFFER);
        if (channel->command)
            WFREE(channel->command, heap, DYNTYPE_STRING);
        WFREE(channel, heap, DYNTYPE_CHANNEL);
    }
}


#define FIND_SELF 0
#define FIND_PEER 1

WOLFSSH_CHANNEL* ChannelFind(WOLFSSH* ssh, word32 channel, byte peer)
{
    WOLFSSH_CHANNEL* findChannel = NULL;

    WLOG(WS_LOG_DEBUG, "Entering ChannelFind(): %s %u",
         peer ? "peer" : "self", channel);

    if (ssh == NULL) {
        WLOG(WS_LOG_DEBUG, "Null ssh, not looking for channel");
    }
    else {
        WOLFSSH_CHANNEL* list = ssh->channelList;
        word32 listSz = ssh->channelListSz;

        while (list && listSz) {
            if (channel == ((peer == FIND_PEER) ?
                            list->peerChannel : list->channel)) {
                findChannel = list;
                break;
            }
            list = list->next;
            listSz--;
        }
    }

    WLOG(WS_LOG_DEBUG, "Leaving ChannelFind(): %p", findChannel);

    return findChannel;
}


int ChannelUpdate(WOLFSSH_CHANNEL* channel, word32 peerChannelId,
                  word32 peerInitialWindowSz, word32 peerMaxPacketSz)
{
    int ret = WS_SUCCESS;

    if (channel == NULL)
        ret = WS_BAD_ARGUMENT;
    else {
        channel->peerChannel = peerChannelId;
        channel->peerWindowSz = peerInitialWindowSz;
        channel->peerMaxPacketSz = peerMaxPacketSz;
    }

    return ret;
}


static int ChannelAppend(WOLFSSH* ssh, WOLFSSH_CHANNEL* channel)
{
    int ret = WS_SUCCESS;

    WLOG(WS_LOG_DEBUG, "Entering ChannelAppend()");

    if (ssh == NULL || channel == NULL)
        ret = WS_BAD_ARGUMENT;

    if (ssh->channelList == NULL) {
        ssh->channelList = channel;
        ssh->channelListSz = 1;
    }
    else {
        WOLFSSH_CHANNEL* cur = ssh->channelList;
        while (cur->next != NULL)
            cur = cur->next;
        cur->next = channel;
        ssh->channelListSz++;
    }

    WLOG(WS_LOG_DEBUG, "Leaving ChannelAppend(), ret = %d", ret);
    return ret;
}


int ChannelRemove(WOLFSSH* ssh, word32 channel, byte peer)
{
    int ret = WS_SUCCESS;
    WOLFSSH_CHANNEL* list;

    WLOG(WS_LOG_DEBUG, "Entering ChannelRemove()");

    if (ssh == NULL)
        ret = WS_BAD_ARGUMENT;

    list = ssh->channelList;
    if (list == NULL)
        ret = WS_INVALID_CHANID;

    if (ret == WS_SUCCESS) {
        WOLFSSH_CHANNEL* prev = NULL;
        word32 listSz = ssh->channelListSz;

        while (list && listSz) {
            if (channel == ((peer == FIND_PEER) ?
                            list->peerChannel : list->channel)) {
                if (prev == NULL)
                    ssh->channelList = list->next;
                else
                    prev->next = list->next;
                ChannelDelete(list, ssh->ctx->heap);
                ssh->channelListSz--;

                break;
            }
            prev = list;
            list = list->next;
            listSz--;
        }

        if (listSz == 0)
            ret = WS_INVALID_CHANID;
    }

    WLOG(WS_LOG_DEBUG, "Leaving ChannelRemove(), ret = %d", ret);
    return ret;
}


int ChannelPutData(WOLFSSH_CHANNEL* channel, byte* data, word32 dataSz)
{
    Buffer* inBuf;

    WLOG(WS_LOG_DEBUG, "Entering ChannelPutData()");

    if (channel == NULL || data == NULL)
        return WS_BAD_ARGUMENT;

    inBuf = &channel->inputBuffer;

    if (inBuf->length < inBuf->bufferSz &&
        inBuf->length + dataSz <= inBuf->bufferSz) {

        WMEMCPY(inBuf->buffer + inBuf->length, data, dataSz);
        inBuf->length += dataSz;

        WLOG(WS_LOG_INFO, "  dataSz = %u", dataSz);
        WLOG(WS_LOG_INFO, "  windowSz = %u", channel->windowSz);
        channel->windowSz -= dataSz;
        WLOG(WS_LOG_INFO, "  windowSz = %u", channel->windowSz);
    }
    else {
        return WS_RECV_OVERFLOW_E;
    }

    return WS_SUCCESS;
}


int BufferInit(Buffer* buffer, word32 size, void* heap)
{
    if (buffer == NULL)
        return WS_BAD_ARGUMENT;

    if (size <= STATIC_BUFFER_LEN)
        size = STATIC_BUFFER_LEN;

    WMEMSET(buffer, 0, sizeof(Buffer));
    buffer->heap = heap;
    buffer->bufferSz = size;
    if (size > STATIC_BUFFER_LEN) {
        buffer->buffer = (byte*)WMALLOC(size, heap, DYNTYPE_BUFFER);
        if (buffer->buffer == NULL)
            return WS_MEMORY_E;
        buffer->dynamicFlag = 1;
    }
    else
        buffer->buffer = buffer->staticBuffer;

    return WS_SUCCESS;
}


int GrowBuffer(Buffer* buf, word32 sz, word32 usedSz)
{
#if 0
    WLOG(WS_LOG_DEBUG, "GB: buf = %p", buf);
    WLOG(WS_LOG_DEBUG, "GB: sz = %d", sz);
    WLOG(WS_LOG_DEBUG, "GB: usedSz = %d", usedSz);
#endif
    /* New buffer will end up being sz+usedSz long
     * empty space at the head of the buffer will be compressed */
    if (buf != NULL) {
        word32 newSz = sz + usedSz;
        /*WLOG(WS_LOG_DEBUG, "GB: newSz = %d", newSz);*/

        if (newSz > buf->bufferSz) {
            byte* newBuffer = (byte*)WMALLOC(newSz,
                                                     buf->heap, DYNTYPE_BUFFER);

            if (newBuffer == NULL)
                return WS_MEMORY_E;

            /*WLOG(WS_LOG_DEBUG, "GB: resizing buffer");*/
            if (buf->length > 0)
                WMEMCPY(newBuffer, buf->buffer + buf->idx, usedSz);

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
    WLOG(WS_LOG_DEBUG, "Entering ShrinkBuffer()");

    if (buf != NULL) {
        word32 usedSz = buf->length - buf->idx;

        WLOG(WS_LOG_DEBUG, "SB: usedSz = %u, forcedFree = %u",
             usedSz, forcedFree);

        if (!forcedFree && usedSz > STATIC_BUFFER_LEN)
            return;

        if (!forcedFree && usedSz) {
            WLOG(WS_LOG_DEBUG, "SB: shifting down");
            WMEMCPY(buf->staticBuffer, buf->buffer + buf->idx, usedSz);
        }

        if (buf->dynamicFlag) {
            WLOG(WS_LOG_DEBUG, "SB: releasing dynamic buffer");
            WFREE(buf->buffer, buf->heap, DYNTYPE_BUFFER);
        }
        buf->dynamicFlag = 0;
        buf->buffer = buf->staticBuffer;
        buf->bufferSz = STATIC_BUFFER_LEN;
        buf->length = forcedFree ? 0 : usedSz;
        buf->idx = 0;
    }

    WLOG(WS_LOG_DEBUG, "Leaving ShrinkBuffer()");
}


static int Receive(WOLFSSH* ssh, byte* buf, word32 sz)
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


static int GetInputText(WOLFSSH* ssh, byte** pEol)
{
    int gotLine = 0;
    int inSz = 255;
    int in;
    char *eol;

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

        eol = WSTRNSTR((const char*)ssh->inputBuffer.buffer, "\r\n",
                       ssh->inputBuffer.length);

        if (eol)
            gotLine = 1;

    } while (!gotLine && inSz);

    if (pEol)
        *pEol = (byte*)eol;

    return (gotLine ? WS_SUCCESS : WS_VERSION_E);
}


static int SendBuffered(WOLFSSH* ssh)
{
    WLOG(WS_LOG_DEBUG, "Entering SendBuffered()");

    if (ssh->ctx->ioSendCb == NULL) {
        WLOG(WS_LOG_DEBUG, "Your IO Send callback is null, please set");
        return WS_SOCKET_ERROR_E;
    }

    while (ssh->outputBuffer.length > 0) {
        int sent = ssh->ctx->ioSendCb(ssh,
                               ssh->outputBuffer.buffer + ssh->outputBuffer.idx,
                               ssh->outputBuffer.length, ssh->ioWriteCtx);

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

        if ((word32)sent > ssh->outputBuffer.length) {
            WLOG(WS_LOG_DEBUG, "SendBuffered() out of bounds read");
            return WS_SEND_OOB_READ_E;
        }

        ssh->outputBuffer.idx += sent;
        ssh->outputBuffer.length -= sent;
    }

    ssh->outputBuffer.idx = 0;

    WLOG(WS_LOG_DEBUG, "SB: Shrinking output buffer");
    ShrinkBuffer(&ssh->outputBuffer, 0);

    HighwaterCheck(ssh, WOLFSSH_HWSIDE_TRANSMIT);

    return WS_SUCCESS;
}


static int GetInputData(WOLFSSH* ssh, word32 size)
{
    int in;
    int inSz;
    int maxLength;
    int usedLength;

    /* check max input length */
    usedLength = ssh->inputBuffer.length - ssh->inputBuffer.idx;
    maxLength  = ssh->inputBuffer.bufferSz - usedLength;
    inSz       = (int)(size - usedLength);      /* from last partial read */
#if 0
    WLOG(WS_LOG_DEBUG, "GID: size = %u", size);
    WLOG(WS_LOG_DEBUG, "GID: usedLength = %d", usedLength);
    WLOG(WS_LOG_DEBUG, "GID: maxLength = %d", maxLength);
    WLOG(WS_LOG_DEBUG, "GID: inSz = %d", inSz);
#endif
    /*
     * usedLength - how much untouched data is in the buffer
     * maxLength - how much empty space is in the buffer
     * inSz - difference between requested data and empty space in the buffer
     *        how much more we need to allocate
     */

    if (inSz <= 0)
        return WS_SUCCESS;

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


static int GetBoolean(byte* v, byte* buf, word32 len, word32* idx)
{
    int result = WS_BUFFER_E;

    if (*idx < len) {
        *v = buf[*idx];
        *idx += BOOLEAN_SZ;
        result = WS_SUCCESS;
    }

    return result;
}


static int GetUint32(word32* v, byte* buf, word32 len, word32* idx)
{
    int result = WS_BUFFER_E;

    if (*idx < len && *idx + UINT32_SZ <= len) {
        ato32(buf + *idx, v);
        *idx += UINT32_SZ;
        result = WS_SUCCESS;
    }

    return result;
}


/* Gets the size of the mpint, and puts the pointer to the start of
 * buf's number into *mpint. This function does not copy. */
static int GetMpint(word32* mpintSz, byte** mpint,
                    byte* buf, word32 len, word32* idx)
{
    int result;

    result = GetUint32(mpintSz, buf, len, idx);

    if (result == WS_SUCCESS) {
        result = WS_BUFFER_E;

        if (*idx < len && *idx + *mpintSz <= len) {
            *mpint = buf + *idx;
            *idx += *mpintSz;
            result = WS_SUCCESS;
        }
    }

    return result;
}


/* Gets the size of a string, copies it as much of it as will fit in
 * the provided buffer, and terminates it with a NULL. */
static int GetString(char* s, word32* sSz,
                     byte* buf, word32 len, word32 *idx)
{
    int result;
    word32 strSz;

    result = GetUint32(&strSz, buf, len, idx);

    if (result == WS_SUCCESS) {
        result = WS_BUFFER_E;
        if (*idx < len && *idx + strSz <= len) {
            *sSz = (strSz >= *sSz) ? *sSz : strSz;
            WMEMCPY(s, buf + *idx, *sSz);
            *idx += strSz;
            s[*sSz] = 0;
            result = WS_SUCCESS;
        }
    }

    return result;
}


/* Gets the size of a string, allocates memory to hold it plus a NULL, then
 * copies it into the allocated buffer, and terminates it with a NULL. */
static int GetStringAlloc(WOLFSSH* ssh, char** s,
                          byte* buf, word32 len, word32 *idx)
{
    int result;
    char* str;
    word32 strSz;

    result = GetUint32(&strSz, buf, len, idx);

    if (result == WS_SUCCESS) {
        if (*idx >= len || *idx + strSz > len)
            return WS_BUFFER_E;
        str = (char*)WMALLOC(strSz + 1, ssh->ctx->heap, DYNTYPE_STRING);
        if (str == NULL)
            return WS_MEMORY_E;
        WMEMCPY(str, buf + *idx, strSz);
        *idx += strSz;
        str[strSz] = '\0';
        *s = str;
    }

    return result;
}


static int GetNameList(byte* idList, word32* idListSz,
                       byte* buf, word32 len, word32* idx)
{
    byte idListIdx;
    word32 nameListSz, nameListIdx;
    word32 begin;
    byte* name;
    word32 nameSz;
    int ret = WS_SUCCESS;

    WLOG(WS_LOG_DEBUG, "Entering GetNameList()");

    if (idList == NULL || idListSz == NULL ||
        buf == NULL || len == 0 || idx == NULL) {

        ret = WS_BAD_ARGUMENT;
    }

    /*
     * This iterates across a name list and finds names that end in either the
     * comma delimeter or with the end of the list.
     */

    if (ret == WS_SUCCESS) {
        begin = *idx;
        if (begin >= len || begin + 4 >= len)
            ret = WS_BUFFER_E;
    }

    if (ret == WS_SUCCESS)
        ret = GetUint32(&nameListSz, buf, len, &begin);

    /* The strings we want are now in the bounds of the message, and the
     * length of the list. Find the commas, or end of list, and then decode
     * the values. */
    if (ret == WS_SUCCESS) {
        name = buf + begin;
        nameSz = 0;
        nameListIdx = 0;
        idListIdx = 0;

        while (nameListIdx < nameListSz) {
            nameListIdx++;

            if (nameListIdx == nameListSz)
                nameSz++;

            if (nameListIdx + begin >= len)
                return WS_BUFFER_E;

            if (nameListIdx == nameListSz || name[nameSz] == ',') {
                byte id;

                id = NameToId((char*)name, nameSz);
                {
                    const char* displayName = IdToName(id);
                    if (displayName) {
                        WLOG(WS_LOG_DEBUG, "DNL: name ID = %s", displayName);
                    }
                }
                if (id != ID_UNKNOWN) {
                    if (idListIdx >= *idListSz) {
                        WLOG(WS_LOG_ERROR, "No more space left for names");
                        return WS_BUFFER_E;
                    }
                    idList[idListIdx++] = id;
                }

                name += 1 + nameSz;
                nameSz = 0;
            }
            else
                nameSz++;
        }

        begin += nameListSz;
        *idListSz = idListIdx;
        *idx = begin;
    }

    WLOG(WS_LOG_DEBUG, "Leaving GetNameList(), ret = %d", ret);
    return ret;
}


static const byte  cannedEncAlgo[] = {ID_AES128_GCM, ID_AES128_CBC};
static const byte  cannedMacAlgo[] = {ID_HMAC_SHA2_256, ID_HMAC_SHA1_96,
                                         ID_HMAC_SHA1};
static const byte  cannedKeyAlgoRsa[] = {ID_SSH_RSA};
static const byte  cannedKeyAlgoEcc256[] = {ID_ECDSA_SHA2_NISTP256};
static const byte  cannedKeyAlgoEcc384[] = {ID_ECDSA_SHA2_NISTP384};
static const byte  cannedKeyAlgoEcc521[] = {ID_ECDSA_SHA2_NISTP521};
static const byte  cannedKexAlgo[] = {ID_ECDH_SHA2_NISTP256,
                                         ID_DH_GEX_SHA256,
                                         ID_DH_GROUP14_SHA1,
                                         ID_DH_GROUP1_SHA1};

static const word32 cannedEncAlgoSz = sizeof(cannedEncAlgo);
static const word32 cannedMacAlgoSz = sizeof(cannedMacAlgo);
static const word32 cannedKeyAlgoRsaSz = sizeof(cannedKeyAlgoRsa);
static const word32 cannedKeyAlgoEcc256Sz = sizeof(cannedKeyAlgoEcc256);
static const word32 cannedKeyAlgoEcc384Sz = sizeof(cannedKeyAlgoEcc384);
static const word32 cannedKeyAlgoEcc521Sz = sizeof(cannedKeyAlgoEcc521);
static const word32 cannedKexAlgoSz = sizeof(cannedKexAlgo);


static byte MatchIdLists(const byte* left, word32 leftSz,
                         const byte* right, word32 rightSz)
{
    word32 i, j;

    if (left != NULL && leftSz > 0 && right != NULL && rightSz > 0) {
        for (i = 0; i < leftSz; i++) {
            for (j = 0; j < rightSz; j++) {
                if (left[i] == right[j]) {
#if 0
                    WLOG(WS_LOG_DEBUG, "MID: matched %s", IdToName(left[i]));
#endif
                    return left[i];
                }
            }
        }
    }

    return ID_UNKNOWN;
}


static INLINE byte BlockSzForId(byte id)
{
    switch (id) {
        case ID_AES128_CBC:
        case ID_AES128_GCM:
            return AES_BLOCK_SIZE;
        default:
            return 0;
    }
}


static INLINE byte MacSzForId(byte id)
{
    switch (id) {
        case ID_HMAC_SHA1:
            return SHA_DIGEST_SIZE;
        case ID_HMAC_SHA1_96:
            return SHA1_96_SZ;
        case ID_HMAC_SHA2_256:
            return SHA256_DIGEST_SIZE;
        default:
            return 0;
    }
}


static INLINE byte KeySzForId(byte id)
{
    switch (id) {
        case ID_HMAC_SHA1:
        case ID_HMAC_SHA1_96:
            return SHA_DIGEST_SIZE;
        case ID_HMAC_SHA2_256:
            return SHA256_DIGEST_SIZE;
        case ID_AES128_CBC:
        case ID_AES128_GCM:
            return AES_BLOCK_SIZE;
        default:
            return 0;
    }
}


static INLINE byte HashForId(byte id)
{
    switch (id) {
        case ID_DH_GROUP1_SHA1:
        case ID_DH_GROUP14_SHA1:
        case ID_SSH_RSA:
            return WC_HASH_TYPE_SHA;
        case ID_DH_GEX_SHA256:
        case ID_ECDH_SHA2_NISTP256:
        case ID_ECDSA_SHA2_NISTP256:
            return WC_HASH_TYPE_SHA256;
        case ID_ECDH_SHA2_NISTP384:
        case ID_ECDSA_SHA2_NISTP384:
            return WC_HASH_TYPE_SHA384;
        case ID_ECDH_SHA2_NISTP521:
        case ID_ECDSA_SHA2_NISTP521:
            return WC_HASH_TYPE_SHA512;
        default:
            return WC_HASH_TYPE_NONE;
    }
}


static INLINE int wcPrimeForId(byte id)
{
    switch (id) {
        case ID_ECDH_SHA2_NISTP256:
        case ID_ECDSA_SHA2_NISTP256:
            return ECC_SECP256R1;
        case ID_ECDH_SHA2_NISTP384:
        case ID_ECDSA_SHA2_NISTP384:
            return ECC_SECP384R1;
        case ID_ECDH_SHA2_NISTP521:
        case ID_ECDSA_SHA2_NISTP521:
            return ECC_SECP521R1;
        default:
            return ECC_CURVE_INVALID;
    }
}
static INLINE const char *PrimeNameForId(byte id)
{
    switch (id) {
        case ID_ECDH_SHA2_NISTP256:
        case ID_ECDSA_SHA2_NISTP256:
            return "nistp256";
        case ID_ECDH_SHA2_NISTP384:
        case ID_ECDSA_SHA2_NISTP384:
            return "nistp384";
        case ID_ECDH_SHA2_NISTP521:
        case ID_ECDSA_SHA2_NISTP521:
            return "nistp521";
        default:
            return "unknown";
    }
}


static INLINE byte AeadModeForId(byte id)
{
    return (id == ID_AES128_GCM);
}


static int DoKexInit(WOLFSSH* ssh, byte* buf, word32 len, word32* idx)
{
    int ret = WS_SUCCESS;
    byte algoId;
    byte list[6];
    word32 listSz;
    word32 skipSz;
    word32 begin;

    WLOG(WS_LOG_DEBUG, "Entering DoKexInit()");

    if (ssh == NULL || buf == NULL || len == 0 || idx == NULL)
        ret = WS_BAD_ARGUMENT;

    /*
     * I don't need to save what the client sends here. I should decode
     * each list into a local array of IDs, and pick the one the peer is
     * using that's on my known list, or verify that the one the peer can
     * support the other direction is on my known list. All I need to do
     * is save the actual values.
     */

    if (ssh->handshake == NULL) {
        ssh->handshake = HandshakeInfoNew(ssh->ctx->heap);
        if (ssh->handshake == NULL) {
            WLOG(WS_LOG_DEBUG, "Couldn't allocate handshake info");
            ret = WS_MEMORY_E;
        }
    }

    if (ret == WS_SUCCESS) {
        begin = *idx;

        /* Check that the cookie exists inside the message */
        if (begin + COOKIE_SZ > len) {
            /* error, out of bounds */
            ret = WS_PARSE_E;
        }
        else {
            /* Move past the cookie. */
            begin += COOKIE_SZ;
        }
    }

    /* KEX Algorithms */
    if (ret == WS_SUCCESS) {
        WLOG(WS_LOG_DEBUG, "DKI: KEX Algorithms");
        listSz = sizeof(list);
        ret = GetNameList(list, &listSz, buf, len, &begin);
        if (ret == WS_SUCCESS) {
            algoId = MatchIdLists(list, listSz, cannedKexAlgo, cannedKexAlgoSz);
            if (algoId == ID_UNKNOWN) {
                WLOG(WS_LOG_DEBUG, "Unable to negotiate KEX Algo");
                ret = WS_INVALID_ALGO_ID;
            }
            else {
                ssh->handshake->kexId = algoId;
                ssh->handshake->hashId = HashForId(algoId);
            }
        }
    }

    /* Server Host Key Algorithms */
    if (ret == WS_SUCCESS) {
        WLOG(WS_LOG_DEBUG, "DKI: Server Host Key Algorithms");
        listSz = sizeof(list);
        ret = GetNameList(list, &listSz, buf, len, &begin);
        if (ret == WS_SUCCESS) {
            const byte *cannedKeyAlgo;
            word32 cannedKeyAlgoSz;

            switch (ssh->ctx->useEcc) {
                case ECC_SECP256R1:
                    cannedKeyAlgo = cannedKeyAlgoEcc256;
                    cannedKeyAlgoSz = cannedKeyAlgoEcc256Sz;
                    break;
                case ECC_SECP384R1:
                    cannedKeyAlgo = cannedKeyAlgoEcc384;
                    cannedKeyAlgoSz = cannedKeyAlgoEcc384Sz;
                    break;
                case ECC_SECP521R1:
                    cannedKeyAlgo = cannedKeyAlgoEcc521;
                    cannedKeyAlgoSz = cannedKeyAlgoEcc521Sz;
                    break;
                default:
                    cannedKeyAlgo = cannedKeyAlgoRsa;
                    cannedKeyAlgoSz = cannedKeyAlgoRsaSz;
            }
            algoId = MatchIdLists(list, listSz,
                                  cannedKeyAlgo, cannedKeyAlgoSz);
            if (algoId == ID_UNKNOWN) {
                WLOG(WS_LOG_DEBUG, "Unable to negotiate Server Host Key Algo");
                return WS_INVALID_ALGO_ID;
            }
            else
                ssh->handshake->pubKeyId = algoId;
        }
    }

    /* Enc Algorithms - Client to Server */
    if (ret == WS_SUCCESS) {
        WLOG(WS_LOG_DEBUG, "DKI: Enc Algorithms - Client to Server");
        listSz = sizeof(list);
        ret = GetNameList(list, &listSz, buf, len, &begin);
        if (ret == WS_SUCCESS) {
            algoId = MatchIdLists(list, listSz, cannedEncAlgo, cannedEncAlgoSz);
            if (algoId == ID_UNKNOWN) {
                WLOG(WS_LOG_DEBUG, "Unable to negotiate Encryption Algo C2S");
                ret = WS_INVALID_ALGO_ID;
            }
        }
    }

    /* Enc Algorithms - Server to Client */
    if (ret == WS_SUCCESS) {
        WLOG(WS_LOG_DEBUG, "DKI: Enc Algorithms - Server to Client");
        listSz = sizeof(list);
        ret = GetNameList(list, &listSz, buf, len, &begin);
        if (MatchIdLists(list, listSz, &algoId, 1) == ID_UNKNOWN) {
            WLOG(WS_LOG_DEBUG, "Unable to negotiate Encryption Algo S2C");
            ret = WS_INVALID_ALGO_ID;
        }
        else {
            ssh->handshake->encryptId = algoId;
            ssh->handshake->aeadMode = AeadModeForId(algoId);
            ssh->handshake->blockSz = BlockSzForId(algoId);
            ssh->handshake->keys.encKeySz =
                ssh->handshake->peerKeys.encKeySz =
                KeySzForId(algoId);
            if (!ssh->handshake->aeadMode) {
                ssh->handshake->keys.ivSz =
                    ssh->handshake->peerKeys.ivSz =
                    ssh->handshake->blockSz;
            }
            else {
                ssh->handshake->keys.ivSz =
                    ssh->handshake->peerKeys.ivSz =
                    AEAD_NONCE_SZ;
                ssh->handshake->macSz = ssh->handshake->blockSz;
            }
        }
    }

    /* MAC Algorithms - Client to Server */
    if (ret == WS_SUCCESS) {
        WLOG(WS_LOG_DEBUG, "DKI: MAC Algorithms - Client to Server");
        listSz = sizeof(list);
        ret = GetNameList(list, &listSz, buf, len, &begin);
        if (ret == WS_SUCCESS && !ssh->aeadMode) {
            algoId = MatchIdLists(list, listSz, cannedMacAlgo, cannedMacAlgoSz);
            if (algoId == ID_UNKNOWN) {
                WLOG(WS_LOG_DEBUG, "Unable to negotiate MAC Algo C2S");
                ret = WS_INVALID_ALGO_ID;
            }
        }
    }

    /* MAC Algorithms - Server to Client */
    if (ret == WS_SUCCESS) {
        WLOG(WS_LOG_DEBUG, "DKI: MAC Algorithms - Server to Client");
        listSz = sizeof(list);
        ret = GetNameList(list, &listSz, buf, len, &begin);
        if (ret == WS_SUCCESS && !ssh->handshake->aeadMode) {
            if (MatchIdLists(list, listSz, &algoId, 1) == ID_UNKNOWN) {
                WLOG(WS_LOG_DEBUG, "Unable to negotiate MAC Algo S2C");
                ret = WS_INVALID_ALGO_ID;
            }
            else {
                ssh->handshake->macId = algoId;
                ssh->handshake->macSz = MacSzForId(algoId);
                ssh->handshake->keys.macKeySz =
                    ssh->handshake->peerKeys.macKeySz =
                    KeySzForId(algoId);
            }
        }
    }

    /* Compression Algorithms - Client to Server */
    if (ret == WS_SUCCESS) {
        /* The compression algorithm lists should have none as a value. */
        algoId = ID_NONE;

        WLOG(WS_LOG_DEBUG, "DKI: Compression Algorithms - Client to Server");
        listSz = sizeof(list);
        ret = GetNameList(list, &listSz, buf, len, &begin);
        if (ret == WS_SUCCESS) {
            if (MatchIdLists(list, listSz, &algoId, 1) == ID_UNKNOWN) {
                WLOG(WS_LOG_DEBUG, "Unable to negotiate Compression Algo C2S");
                ret = WS_INVALID_ALGO_ID;
            }
        }
    }

    /* Compression Algorithms - Server to Client */
    if (ret == WS_SUCCESS) {
        WLOG(WS_LOG_DEBUG, "DKI: Compression Algorithms - Server to Client");
        listSz = sizeof(list);
        ret = GetNameList(list, &listSz, buf, len, &begin);
        if (ret == WS_SUCCESS) {
            if (MatchIdLists(list, listSz, &algoId, 1) == ID_UNKNOWN) {
                WLOG(WS_LOG_DEBUG, "Unable to negotiate Compression Algo S2C");
                ret = WS_INVALID_ALGO_ID;
            }
        }
    }

    /* Languages - Client to Server, skip */
    if (ret == WS_SUCCESS) {
        WLOG(WS_LOG_DEBUG, "DKI: Languages - Client to Server");
        ret = GetUint32(&skipSz, buf, len, &begin);
        if (ret == WS_SUCCESS)
            begin += skipSz;
    }

    /* Languages - Server to Client, skip */
    if (ret == WS_SUCCESS) {
        WLOG(WS_LOG_DEBUG, "DKI: Languages - Server to Client");
        ret = GetUint32(&skipSz, buf, len, &begin);
        if (ret == WS_SUCCESS)
            begin += skipSz;
    }

    /* First KEX Packet Follows */
    if (ret == WS_SUCCESS) {
        WLOG(WS_LOG_DEBUG, "DKI: KEX Packet Follows");
        ret = GetBoolean(&ssh->handshake->kexPacketFollows, buf, len, &begin);
    }

    /* Skip the "for future use" length. */
    if (ret == WS_SUCCESS) {
        WLOG(WS_LOG_DEBUG, "DKI: For Future Use");
        ret = GetUint32(&skipSz, buf, len, &begin);
        if (ret == WS_SUCCESS)
            begin += skipSz;
    }

    if (ret == WS_SUCCESS) {
        byte scratchLen[LENGTH_SZ];
        word32 strSz;

        if (!ssh->isKeying) {
            WLOG(WS_LOG_DEBUG, "Keying initiated");
            ret = SendKexInit(ssh);
        }

        if (ret == WS_SUCCESS)
            ret = wc_HashInit(&ssh->handshake->hash, ssh->handshake->hashId);

        if (ret == WS_SUCCESS) {
            if (ssh->ctx->side == WOLFSSH_ENDPOINT_SERVER)
                ret = wc_HashUpdate(&ssh->handshake->hash,
                                    ssh->handshake->hashId,
                                    ssh->peerProtoId, ssh->peerProtoIdSz);
        }

        if (ret == WS_SUCCESS) {
            strSz = (word32)WSTRLEN(sshProtoIdStr) - SSH_PROTO_EOL_SZ;
            c32toa(strSz, scratchLen);
            ret = wc_HashUpdate(&ssh->handshake->hash, ssh->handshake->hashId,
                                scratchLen, LENGTH_SZ);
        }

        if (ret == WS_SUCCESS)
            ret = wc_HashUpdate(&ssh->handshake->hash, ssh->handshake->hashId,
                                (const byte*)sshProtoIdStr, strSz);

        if (ret == WS_SUCCESS) {
            if (ssh->ctx->side == WOLFSSH_ENDPOINT_CLIENT) {
                ret = wc_HashUpdate(&ssh->handshake->hash,
                                    ssh->handshake->hashId,
                                    ssh->peerProtoId, ssh->peerProtoIdSz);
                if (ret == WS_SUCCESS)
                    ret = wc_HashUpdate(&ssh->handshake->hash,
                                        ssh->handshake->hashId,
                                        ssh->handshake->kexInit,
                                        ssh->handshake->kexInitSz);
            }
        }

        if (ret == WS_SUCCESS) {
            c32toa(len + 1, scratchLen);
            ret = wc_HashUpdate(&ssh->handshake->hash, ssh->handshake->hashId,
                                scratchLen, LENGTH_SZ);
        }

        if (ret == WS_SUCCESS) {
            scratchLen[0] = MSGID_KEXINIT;
            ret = wc_HashUpdate(&ssh->handshake->hash, ssh->handshake->hashId,
                                scratchLen, MSG_ID_SZ);
        }

        if (ret == WS_SUCCESS)
            ret = wc_HashUpdate(&ssh->handshake->hash, ssh->handshake->hashId,
                                buf, len);

        if (ret == WS_SUCCESS) {
            if (ssh->ctx->side == WOLFSSH_ENDPOINT_SERVER)
                ret = wc_HashUpdate(&ssh->handshake->hash,
                                    ssh->handshake->hashId,
                                    ssh->handshake->kexInit,
                                    ssh->handshake->kexInitSz);
        }

        if (ret == WS_SUCCESS) {
            *idx = begin;
            if (ssh->ctx->side == WOLFSSH_ENDPOINT_SERVER)
                ssh->clientState = CLIENT_KEXINIT_DONE;
            else
                ssh->serverState = SERVER_KEXINIT_DONE;
        }
    }

    WLOG(WS_LOG_DEBUG, "Leaving DoKexInit(), ret = %d", ret);
    return ret;
}


static const byte dhGenerator[] = { 2 };
static const byte dhPrimeGroup1[] = {
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
static const byte dhPrimeGroup14[] = {
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

static const word32 dhGeneratorSz = sizeof(dhGenerator);
static const word32 dhPrimeGroup1Sz = sizeof(dhPrimeGroup1);
static const word32 dhPrimeGroup14Sz = sizeof(dhPrimeGroup14);


static int DoKexDhInit(WOLFSSH* ssh, byte* buf, word32 len, word32* idx)
{
    /* First get the length of the MP_INT, and then add in the hash of the
     * mp_int value of e as it appears in the packet. After that, decode e
     * into an mp_int struct for the DH calculation by wolfCrypt.
     *
     * This function also works as MSGID_KEXECDH_INIT (30). That message
     * has the same format as MSGID_KEXDH_INIT, except it is the ECDH Q value
     * in the message isn't of the DH e value. Treat the Q as e. */
    /* DYNTYPE_DH */

    byte* e;
    word32 eSz;
    word32 begin;
    int ret = WS_SUCCESS;

    if (ssh == NULL || buf == NULL || len == 0 || idx == NULL)
        ret = WS_BAD_ARGUMENT;

    if (ret == WS_SUCCESS) {
        begin = *idx;
        ret = GetUint32(&eSz, buf, len, &begin);
    }

    if (ret == WS_SUCCESS) {
        e = buf + begin;
        begin += eSz;

        if (eSz <= sizeof(ssh->handshake->e)) {
            WMEMCPY(ssh->handshake->e, e, eSz);
            ssh->handshake->eSz = eSz;
        }

        ssh->clientState = CLIENT_KEXDH_INIT_DONE;
        *idx = begin;

        ret = SendKexDhReply(ssh);
    }

    return ret;
}


static int DoKexDhReply(WOLFSSH* ssh, byte* buf, word32 len, word32* idx)
{
    byte* pubKey = NULL;
    word32 pubKeySz;
    byte* f;
    word32 fSz;
    byte* sig;
    word32 sigSz;
    word32 scratch;
    byte  scratchLen[LENGTH_SZ];
    word32 kPad = 0;
    struct {
        byte useRsa;
        word32 keySz;
        union {
            struct {
                RsaKey   key;
            } rsa;
            struct {
                ecc_key key;
            } ecc;
        } sk;
    } sigKeyBlock;
    word32 begin;
    int ret = WS_SUCCESS;

    WLOG(WS_LOG_DEBUG, "Entering DoKexDhReply()");

    if (ssh == NULL || ssh->handshake == NULL || buf == NULL ||
            len == 0 || idx == NULL)
        ret = WS_BAD_ARGUMENT;

    if (ret == WS_SUCCESS) {
        begin = *idx;
        pubKey = buf + begin;
        ret = GetUint32(&pubKeySz, buf, len, &begin);
    }

    if (ret == WS_SUCCESS)
        ret = wc_HashUpdate(&ssh->handshake->hash,
                            ssh->handshake->hashId,
                            pubKey, pubKeySz + LENGTH_SZ);

    if (ret == WS_SUCCESS) {
        pubKey = buf + begin;
        begin += pubKeySz;
    }

    /* If using DH-GEX include the GEX specific values. */
    if (ssh->handshake->kexId == ID_DH_GEX_SHA256) {
        byte primeGroupPad = 0, generatorPad = 0;

        /* Hash in the client's requested minimum key size. */
        if (ret == 0) {
            c32toa(ssh->handshake->dhGexMinSz, scratchLen);
            ret = wc_HashUpdate(&ssh->handshake->hash,
                                ssh->handshake->hashId,
                                scratchLen, LENGTH_SZ);
        }
        /* Hash in the client's requested preferred key size. */
        if (ret == 0) {
            c32toa(ssh->handshake->dhGexPreferredSz, scratchLen);
            ret = wc_HashUpdate(&ssh->handshake->hash,
                                ssh->handshake->hashId,
                                scratchLen, LENGTH_SZ);
        }
        /* Hash in the client's requested maximum key size. */
        if (ret == 0) {
            c32toa(ssh->handshake->dhGexMaxSz, scratchLen);
            ret = wc_HashUpdate(&ssh->handshake->hash,
                                ssh->handshake->hashId,
                                scratchLen, LENGTH_SZ);
        }
        /* Add a pad byte if the mpint has the MSB set. */
        if (ret == 0) {
            if (ssh->handshake->primeGroup[0] & 0x80)
                primeGroupPad = 1;

            /* Hash in the length of the GEX prime group. */
            c32toa(ssh->handshake->primeGroupSz + primeGroupPad,
                   scratchLen);
            ret = wc_HashUpdate(&ssh->handshake->hash,
                                ssh->handshake->hashId,
                                scratchLen, LENGTH_SZ);
        }
        /* Hash in the pad byte for the GEX prime group. */
        if (ret == 0) {
            if (primeGroupPad) {
                scratchLen[0] = 0;
                ret = wc_HashUpdate(&ssh->handshake->hash,
                                    ssh->handshake->hashId,
                                    scratchLen, 1);
            }
        }
        /* Hash in the GEX prime group. */
        if (ret == 0)
            ret  = wc_HashUpdate(&ssh->handshake->hash,
                                 ssh->handshake->hashId,
                                 ssh->handshake->primeGroup,
                                 ssh->handshake->primeGroupSz);
        /* Add a pad byte if the mpint has the MSB set. */
        if (ret == 0) {
            if (ssh->handshake->generator[0] & 0x80)
                generatorPad = 1;

            /* Hash in the length of the GEX generator. */
            c32toa(ssh->handshake->generatorSz + generatorPad, scratchLen);
            ret = wc_HashUpdate(&ssh->handshake->hash,
                                ssh->handshake->hashId,
                                scratchLen, LENGTH_SZ);
        }
        /* Hash in the pad byte for the GEX generator. */
        if (ret == 0) {
            if (generatorPad) {
                scratchLen[0] = 0;
                ret = wc_HashUpdate(&ssh->handshake->hash,
                                    ssh->handshake->hashId,
                                    scratchLen, 1);
            }
        }
        /* Hash in the GEX generator. */
        if (ret == 0)
            ret = wc_HashUpdate(&ssh->handshake->hash,
                                ssh->handshake->hashId,
                                ssh->handshake->generator,
                                ssh->handshake->generatorSz);
    }

    /* Hash in the size of the client's DH e-value (ECDH Q-value). */
    if (ret == 0) {
        c32toa(ssh->handshake->eSz, scratchLen);
        ret = wc_HashUpdate(&ssh->handshake->hash, ssh->handshake->hashId,
                            scratchLen, LENGTH_SZ);
    }
    /* Hash in the client's DH e-value (ECDH Q-value). */
    if (ret == 0)
        ret = wc_HashUpdate(&ssh->handshake->hash, ssh->handshake->hashId,
                            ssh->handshake->e, ssh->handshake->eSz);

    /* Get and hash in the server's DH f-value (ECDH Q-value) */
    if (ret == WS_SUCCESS) {
        f = buf + begin;
        ret = GetUint32(&fSz, buf, len, &begin);
    }

    if (ret == WS_SUCCESS)
        ret = wc_HashUpdate(&ssh->handshake->hash,
                            ssh->handshake->hashId,
                            f, fSz + LENGTH_SZ);

    if (ret == WS_SUCCESS) {
        f = buf + begin;
        begin += fSz;
        ret = GetUint32(&sigSz, buf, len, &begin);
    }

    if (ret == WS_SUCCESS) {
        sig = buf + begin;
        begin += sigSz;
        *idx = begin;

        /* Load in the server's public signing key */
        sigKeyBlock.useRsa = ssh->handshake->pubKeyId == ID_SSH_RSA;

        if (sigKeyBlock.useRsa) {
            byte* e;
            word32 eSz;
            byte* n;
            word32 nSz;
            word32 pubKeyIdx = 0;

            ret = wc_InitRsaKey(&sigKeyBlock.sk.rsa.key, ssh->ctx->heap);
            if (ret != 0)
                ret = WS_RSA_E;
            if (ret == 0)
                ret = GetUint32(&scratch, pubKey, pubKeySz, &pubKeyIdx);
            /* This is the algo name. */
            if (ret == WS_SUCCESS) {
                pubKeyIdx += scratch;
                ret = GetUint32(&eSz, pubKey, pubKeySz, &pubKeyIdx);
            }
            if (ret == WS_SUCCESS) {
                e = pubKey + pubKeyIdx;
                pubKeyIdx += eSz;
                ret = GetUint32(&nSz, pubKey, pubKeySz, &pubKeyIdx);
            }
            if (ret == WS_SUCCESS) {
                n = pubKey + pubKeyIdx;
                ret = wc_RsaPublicKeyDecodeRaw(n, nSz, e, eSz,
                                               &sigKeyBlock.sk.rsa.key);
            }

            if (ret == 0)
                sigKeyBlock.keySz = sizeof(sigKeyBlock.sk.rsa.key);
            else
                ret = WS_RSA_E;
        }
        else {
            ret = wc_ecc_init_ex(&sigKeyBlock.sk.ecc.key, ssh->ctx->heap,
                                 INVALID_DEVID);
            if (ret == 0)
                ret = wc_ecc_import_x963(pubKey, pubKeySz,
                                         &sigKeyBlock.sk.ecc.key);
            if (ret == 0)
                sigKeyBlock.keySz = sizeof(sigKeyBlock.sk.ecc.key);
            else
                ret = WS_ECC_E;
        }

        /* Generate and hash in the shared secret */
        if (ret == 0) {
            if (!ssh->handshake->useEcc) {
                ret = wc_DhAgree(&ssh->handshake->privKey.dh,
                                 ssh->k, &ssh->kSz,
                                 ssh->handshake->x, ssh->handshake->xSz,
                                 f, fSz);
                ForceZero(ssh->handshake->x, ssh->handshake->xSz);
                wc_FreeDhKey(&ssh->handshake->privKey.dh);
            }
            else {
                ecc_key key;
                ret = wc_ecc_init(&key);
                if (ret == 0)
                    ret = wc_ecc_import_x963(f, fSz, &key);
                if (ret == 0)
                    ret = wc_ecc_shared_secret(&ssh->handshake->privKey.ecc,
                                               &key, ssh->k, &ssh->kSz);
                wc_ecc_free(&key);
                wc_ecc_free(&ssh->handshake->privKey.ecc);
            }
        }

        /* Hash in the shared secret K. */
        if (ret == 0) {
            kPad = (ssh->k[0] & 0x80) ? 1 : 0;
            c32toa(ssh->kSz + kPad, scratchLen);
            ret = wc_HashUpdate(&ssh->handshake->hash, ssh->handshake->hashId,
                                scratchLen, LENGTH_SZ);
        }
        if (ret == 0) {
            if (kPad) {
                scratchLen[0] = 0;
                ret = wc_HashUpdate(&ssh->handshake->hash,
                                    ssh->handshake->hashId, scratchLen, 1);
            }
        }
        if (ret == 0)
            ret = wc_HashUpdate(&ssh->handshake->hash, ssh->handshake->hashId,
                                ssh->k, ssh->kSz);

        /* Save the exchange hash value H, and session ID. */
        if (ret == 0)
            ret = wc_HashFinal(&ssh->handshake->hash,
                               ssh->handshake->hashId, ssh->h);
        if (ret == 0) {
            ssh->hSz = wc_HashGetDigestSize(ssh->handshake->hashId);
            if (ssh->sessionIdSz == 0) {
                WMEMCPY(ssh->sessionId, ssh->h, ssh->hSz);
                ssh->sessionIdSz = ssh->hSz;
            }
        }

        if (ret != WS_SUCCESS)
            ret = WS_CRYPTO_FAILED;
    }

    /* Verify h with the server's public key. */
    if (ret == WS_SUCCESS) {
        /* Skip past the sig name. Check it, though. Other SSH implementations
         * do the verify based on the name, despite what was agreed upon. XXX*/
        begin = 0;
        ret = GetUint32(&scratch, sig, sigSz, &begin);
        if (ret == WS_SUCCESS) {
            begin += scratch;
            ret = GetUint32(&scratch, sig, sigSz, &begin);
        }
        if (ret == WS_SUCCESS) {
            sig = sig + begin;
            sigSz = scratch;

            ret = wc_SignatureVerify(HashForId(ssh->handshake->pubKeyId),
                                     sigKeyBlock.useRsa ?
                                      WC_SIGNATURE_TYPE_RSA_W_ENC :
                                      WC_SIGNATURE_TYPE_ECC,
                                     ssh->h, ssh->hSz, sig, sigSz,
                                     &sigKeyBlock.sk, sigKeyBlock.keySz);
            if (ret != 0) {
                WLOG(WS_LOG_DEBUG,
                     "DoKexDhReply: Signature Verify fail (%d)", ret);
                ret = sigKeyBlock.useRsa ? WS_RSA_E : WS_ECC_E;
            }
        }
    }

    if (sigKeyBlock.useRsa)
        wc_FreeRsaKey(&sigKeyBlock.sk.rsa.key);
    else
        wc_ecc_free(&sigKeyBlock.sk.ecc.key);

    if (ret == WS_SUCCESS)
        ret = GenerateKeys(ssh);

    if (ret == WS_SUCCESS)
        ret = SendNewKeys(ssh);

    WLOG(WS_LOG_DEBUG, "Leaving DoKexDhReply(), ret = %d", ret);
    return ret;
}


static int DoNewKeys(WOLFSSH* ssh, byte* buf, word32 len, word32* idx)
{
    int ret = WS_SUCCESS;

    (void)buf;
    (void)len;
    (void)idx;

    if (ssh == NULL)
        ret = WS_BAD_ARGUMENT;

    if (ret == WS_SUCCESS) {
        ssh->peerEncryptId = ssh->handshake->encryptId;
        ssh->peerMacId = ssh->handshake->macId;
        ssh->peerBlockSz = ssh->handshake->blockSz;
        ssh->peerMacSz = ssh->handshake->macSz;
        ssh->peerAeadMode = ssh->handshake->aeadMode;
        WMEMCPY(&ssh->peerKeys, &ssh->handshake->peerKeys, sizeof(Keys));

        switch (ssh->peerEncryptId) {
            case ID_NONE:
                WLOG(WS_LOG_DEBUG, "DNK: peer using cipher none");
                break;

            case ID_AES128_CBC:
                WLOG(WS_LOG_DEBUG, "DNK: peer using cipher aes128-cbc");
                ret = wc_AesSetKey(&ssh->decryptCipher.aes,
                                   ssh->peerKeys.encKey, ssh->peerKeys.encKeySz,
                                   ssh->peerKeys.iv, AES_DECRYPTION);
                break;

            case ID_AES128_GCM:
                WLOG(WS_LOG_DEBUG, "DNK: peer using cipher aes128-gcm");
                ret = wc_AesGcmSetKey(&ssh->decryptCipher.aes,
                                      ssh->peerKeys.encKey,
                                      ssh->peerKeys.encKeySz);
                break;

            default:
                WLOG(WS_LOG_DEBUG, "DNK: peer using cipher invalid");
                break;
        }

        if (ret == 0)
            ret = WS_SUCCESS;
        else
            ret = WS_CRYPTO_FAILED;
    }

    if (ret == WS_SUCCESS) {
        ssh->rxCount = 0;
        ssh->highwaterFlag = 0;
        ssh->isKeying = 0;
        HandshakeInfoFree(ssh->handshake, ssh->ctx->heap);
        ssh->handshake = NULL;
        WLOG(WS_LOG_DEBUG, "Keying completed");
    }

    return ret;
}


static int DoKexDhGexRequest(WOLFSSH* ssh,
                             byte* buf, word32 len, word32* idx)
{
    word32 begin;
    int ret = WS_SUCCESS;

    if (ssh == NULL || buf == NULL || len == 0 || idx == NULL)
        ret = WS_BAD_ARGUMENT;

    if (ret == WS_SUCCESS) {
        begin = *idx;
        ret = GetUint32(&ssh->handshake->dhGexMinSz, buf, len, &begin);
    }

    if (ret == WS_SUCCESS) {
        ret = GetUint32(&ssh->handshake->dhGexPreferredSz, buf, len, &begin);
    }

    if (ret == WS_SUCCESS) {
        ret = GetUint32(&ssh->handshake->dhGexMaxSz, buf, len, &begin);
    }

    if (ret == WS_SUCCESS) {
        WLOG(WS_LOG_INFO, "  min = %u, preferred = %u, max = %u",
                ssh->handshake->dhGexMinSz,
                ssh->handshake->dhGexPreferredSz,
                ssh->handshake->dhGexMaxSz);
        *idx = begin;
        ret = SendKexDhGexGroup(ssh);
    }

    return ret;
}


static int DoKexDhGexGroup(WOLFSSH* ssh,
                           byte* buf, word32 len, word32* idx)
{
    byte* primeGroup = NULL;
    word32 primeGroupSz;
    byte* generator = NULL;
    word32 generatorSz;
    word32 begin;
    int ret = WS_UNIMPLEMENTED_E;

    if (ssh == NULL || buf == NULL || len == 0 || idx == NULL)
        ret = WS_BAD_ARGUMENT;

    if (ret == WS_SUCCESS) {
        begin = *idx;
        ret = GetMpint(&primeGroupSz, &primeGroup, buf, len, &begin);
    }

    if (ret == WS_SUCCESS)
        ret = GetMpint(&generatorSz, &generator, buf, len, &begin);

    if (ret == WS_SUCCESS) {
        ssh->handshake->primeGroup =
            (byte*)WMALLOC(primeGroupSz + UINT32_SZ,
                           ssh->ctx->heap, DYNTYPE_MPINT);
        if (ssh->handshake->primeGroup == NULL)
            ret = WS_MEMORY_E;
    }

    if (ret == WS_SUCCESS) {
        ssh->handshake->generator =
            (byte*)WMALLOC(generatorSz + UINT32_SZ,
                           ssh->ctx->heap, DYNTYPE_MPINT);
        if (ssh->handshake->generator == NULL) {
            ret = WS_MEMORY_E;
            WFREE(ssh->handshake->primeGroup, ssh->ctx->heap, DYNTYPE_MPINT);
            ssh->handshake->primeGroup = NULL;
        }
    }

    if (WS_SUCCESS) {
        c32toa(primeGroupSz, ssh->handshake->primeGroup);
        WMEMCPY(ssh->handshake->primeGroup + UINT32_SZ,
                primeGroup, primeGroupSz);
        ssh->handshake->primeGroupSz = primeGroupSz;
        c32toa(generatorSz, ssh->handshake->generator);
        WMEMCPY(ssh->handshake->generator + UINT32_SZ,
                generator, generatorSz);
        ssh->handshake->generatorSz = generatorSz;

        *idx = begin;
        ret = SendKexDhInit(ssh);
    }

    return ret;
}


static int DoIgnore(WOLFSSH* ssh, byte* buf, word32 len, word32* idx)
{
    word32 dataSz;
    word32 begin = *idx;

    (void)ssh;
    (void)len;

    ato32(buf + begin, &dataSz);
    begin += LENGTH_SZ + dataSz;

    *idx = begin;

    return WS_SUCCESS;
}


static int DoDebug(WOLFSSH* ssh, byte* buf, word32 len, word32* idx)
{
    byte  alwaysDisplay;
    char*    msg = NULL;
    char*    lang = NULL;
    word32 strSz;
    word32 begin = *idx;

    (void)ssh;
    (void)len;

    alwaysDisplay = buf[begin++];

    ato32(buf + begin, &strSz);
    begin += LENGTH_SZ;
    if (strSz > 0) {
        if (strSz > len - begin) {
            return WS_BUFFER_E;
        }

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
        if (strSz > len - begin) {
            WFREE(msg, ssh->ctx->heap, DYNTYPE_STRING);
            return WS_BUFFER_E;
        }

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
                           byte* buf, word32 len, word32* idx)
{
    word32 seq;
    word32 begin = *idx;

    (void)ssh;
    (void)len;

    ato32(buf + begin, &seq);
    begin += UINT32_SZ;

    WLOG(WS_LOG_DEBUG, "UNIMPLEMENTED: seq %u", seq);

    *idx = begin;

    return WS_SUCCESS;
}


static int DoDisconnect(WOLFSSH* ssh, byte* buf, word32 len, word32* idx)
{
    word32 reason;
    const char* reasonStr;
    word32 begin = *idx;

    (void)ssh;
    (void)len;
    (void)reasonStr;

    ato32(buf + begin, &reason);
    begin += UINT32_SZ;

#ifdef NO_WOLFSSH_STRINGS
    WLOG(WS_LOG_DEBUG, "DISCONNECT: (%u)", reason);
#elif defined(DEBUG_WOLFSSH)
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


static int DoServiceRequest(WOLFSSH* ssh,
                            byte* buf, word32 len, word32* idx)
{
    word32 begin = *idx;
    word32 nameSz;
    char     serviceName[32];

    (void)len;

    ato32(buf + begin, &nameSz);
    begin += LENGTH_SZ;

    WMEMCPY(serviceName, buf + begin, nameSz);
    begin += nameSz;
    serviceName[nameSz] = 0;

    *idx = begin;

    WLOG(WS_LOG_DEBUG, "Requesting service: %s", serviceName);
    ssh->clientState = CLIENT_USERAUTH_REQUEST_DONE;

    return WS_SUCCESS;
}


static int DoServiceAccept(WOLFSSH* ssh,
                           byte* buf, word32 len, word32* idx)
{
    word32 begin = *idx;
    word32 nameSz;
    char     serviceName[32];

    (void)len;

    ato32(buf + begin, &nameSz);
    begin += LENGTH_SZ;

    WMEMCPY(serviceName, buf + begin, nameSz);
    begin += nameSz;
    serviceName[nameSz] = 0;

    *idx = begin;

    WLOG(WS_LOG_DEBUG, "Accepted service: %s", serviceName);
    ssh->serverState = SERVER_USERAUTH_REQUEST_DONE;

    return WS_SUCCESS;
}


/* Utility for DoUserAuthRequest() */
static int DoUserAuthRequestPassword(WOLFSSH* ssh, WS_UserAuthData* authData,
                                     byte* buf, word32 len, word32* idx)
{
    word32 begin;
    WS_UserAuthData_Password* pw;
    int ret = WS_SUCCESS;

    WLOG(WS_LOG_DEBUG, "Entering DoUserAuthRequestPassword()");

    if (ssh == NULL || authData == NULL ||
        buf == NULL || len == 0 || idx == NULL) {

        ret = WS_BAD_ARGUMENT;
    }

    if (ret == WS_SUCCESS) {
        begin = *idx;
        pw = &authData->sf.password;
        authData->type = WOLFSSH_USERAUTH_PASSWORD;
        ret = GetBoolean(&pw->hasNewPassword, buf, len, &begin);
    }

    if (ret == WS_SUCCESS)
        ret = GetUint32(&pw->passwordSz, buf, len, &begin);

    if (ret == WS_SUCCESS) {
        pw->password = buf + begin;
        begin += pw->passwordSz;

        if (pw->hasNewPassword) {
            /* Skip the password change. Maybe error out since we aren't
             * supporting password changes at this time. */
            ret = GetUint32(&pw->newPasswordSz, buf, len, &begin);
            if (ret == WS_SUCCESS) {
                pw->newPassword = buf + begin;
                begin += pw->newPasswordSz;
            }
        }
        else {
            pw->newPassword = NULL;
            pw->newPasswordSz = 0;
        }

        if (ssh->ctx->userAuthCb != NULL) {
            WLOG(WS_LOG_DEBUG, "DUARPW: Calling the userauth callback");
            ret = ssh->ctx->userAuthCb(WOLFSSH_USERAUTH_PASSWORD,
                                       authData, ssh->userAuthCtx);
            if (ret == WOLFSSH_USERAUTH_SUCCESS) {
                WLOG(WS_LOG_DEBUG, "DUARPW: password check successful");
                ssh->clientState = CLIENT_USERAUTH_DONE;
                ret = WS_SUCCESS;
            }
            else {
                WLOG(WS_LOG_DEBUG, "DUARPW: password check failed");
                ret = SendUserAuthFailure(ssh, 0);
            }
        }
        else {
            WLOG(WS_LOG_DEBUG, "DUARPW: No user auth callback");
            ret = SendUserAuthFailure(ssh, 0);
        }
    }

    if (ret == WS_SUCCESS)
        *idx = begin;

    WLOG(WS_LOG_DEBUG, "Leaving DoUserAuthRequestPassword(), ret = %d", ret);
    return ret;
}


/* Utility for DoUserAuthRequestPublicKey() */
/* returns negative for error, positive is size of digest. */
static int DoUserAuthRequestRsa(WOLFSSH* ssh, WS_UserAuthData_PublicKey* pk,
                                byte hashId, byte* digest, word32 digestSz)
{
    RsaKey key;
    byte checkDigest[MAX_ENCODED_SIG_SZ];
    int checkDigestSz;
    byte* publicKeyType;
    word32 publicKeyTypeSz = 0;
    byte* n;
    word32 nSz = 0;
    byte* e;
    word32 eSz = 0;
    word32 i = 0;
    int ret = WS_SUCCESS;

    WLOG(WS_LOG_DEBUG, "Entering DoUserAuthRequestRsa()");

    if (ssh == NULL || pk == NULL || digest == NULL || digestSz == 0)
        ret = WS_BAD_ARGUMENT;

    /* First check that the public key's type matches the one we are
     * expecting. */
    if (ret == WS_SUCCESS)
        ret = GetUint32(&publicKeyTypeSz, pk->publicKey, pk->publicKeySz, &i);

    if (ret == WS_SUCCESS) {
        publicKeyType = pk->publicKey + i;
        i += publicKeyTypeSz;
        if (publicKeyTypeSz != pk->publicKeyTypeSz &&
            WMEMCMP(publicKeyType, pk->publicKeyType, publicKeyTypeSz) != 0) {

            WLOG(WS_LOG_DEBUG,
                "Public Key's type does not match public key type");
            ret = WS_INVALID_ALGO_ID;
        }
    }

    if (ret == WS_SUCCESS)
        ret = GetUint32(&eSz, pk->publicKey, pk->publicKeySz, &i);

    if (ret == WS_SUCCESS) {
        e = pk->publicKey + i;
        i += eSz;
        ret = GetUint32(&nSz, pk->publicKey, pk->publicKeySz, &i);
    }

    if (ret == WS_SUCCESS) {
        n = pk->publicKey + i;

        ret = wc_InitRsaKey(&key, ssh->ctx->heap);
        if (ret == 0)
            ret = wc_RsaPublicKeyDecodeRaw(n, nSz, e, eSz, &key);
        if (ret != 0) {
            WLOG(WS_LOG_DEBUG, "Could not decode public key");
            ret = WS_CRYPTO_FAILED;
        }
    }

    if (ret == WS_SUCCESS) {
        i = 0;
        /* First check that the signature's public key type matches the one
         * we are expecting. */
        ret = GetUint32(&publicKeyTypeSz, pk->publicKey, pk->publicKeySz, &i);
    }

    if (ret == WS_SUCCESS) {
        publicKeyType = pk->publicKey + i;
        i += publicKeyTypeSz;

        if (publicKeyTypeSz != pk->publicKeyTypeSz &&
            WMEMCMP(publicKeyType, pk->publicKeyType, publicKeyTypeSz) != 0) {

            WLOG(WS_LOG_DEBUG,
                 "Signature's type does not match public key type");
            ret = WS_INVALID_ALGO_ID;
        }
    }

    if (ret == WS_SUCCESS)
        ret = GetUint32(&nSz, pk->signature, pk->signatureSz, &i);

    if (ret == WS_SUCCESS) {
        n = pk->signature + i;
        checkDigestSz = wc_RsaSSL_Verify(n, nSz, checkDigest,
                                         sizeof(checkDigest), &key);
        if (checkDigestSz <= 0) {
            WLOG(WS_LOG_DEBUG, "Could not verify signature");
            ret = WS_CRYPTO_FAILED;
        }
    }

    if (ret == WS_SUCCESS) {
        byte encDigest[MAX_ENCODED_SIG_SZ];
        word32 encDigestSz;
        volatile int compare;
        volatile int sizeCompare;

        encDigestSz = wc_EncodeSignature(encDigest, digest,
                                         wc_HashGetDigestSize(hashId),
                                         wc_HashGetOID(hashId));

        compare = ConstantCompare(encDigest, checkDigest,
                                  encDigestSz);
        sizeCompare = encDigestSz != (word32)checkDigestSz;

        if ((compare | sizeCompare) == 0)
            ret = WS_SUCCESS;
        else
            ret = WS_RSA_E;
    }

    wc_FreeRsaKey(&key);

    WLOG(WS_LOG_DEBUG, "Leaving DoUserAuthRequestRsa(), ret = %d", ret);
    return ret;
}


/* Utility for DoUserAuthRequestPublicKey() */
/* returns negative for error, positive is size of digest. */
static int DoUserAuthRequestEcc(WOLFSSH* ssh, WS_UserAuthData_PublicKey* pk,
                                byte hashId, byte* digest, word32 digestSz)
{
    ecc_key key;
    byte* publicKeyType;
    word32 publicKeyTypeSz = 0;
    byte* curveName;
    word32 curveNameSz = 0;
    mp_int r, s;
    byte* q;
    word32 sz, qSz;
    word32 i = 0;
    int ret = WS_SUCCESS;

    (void)hashId;

    WLOG(WS_LOG_DEBUG, "Entering DoUserAuthRequestRsa()");

    if (ssh == NULL || pk == NULL || digest == NULL || digestSz == 0)
        ret = WS_BAD_ARGUMENT;

    /* First check that the public key's type matches the one we are
     * expecting. */
    if (ret == WS_SUCCESS)
        ret = GetUint32(&publicKeyTypeSz, pk->publicKey, pk->publicKeySz, &i);

    if (ret == WS_SUCCESS) {
        publicKeyType = pk->publicKey + i;
        i += publicKeyTypeSz;
        if (publicKeyTypeSz != pk->publicKeyTypeSz &&
            WMEMCMP(publicKeyType, pk->publicKeyType, publicKeyTypeSz) != 0) {

            WLOG(WS_LOG_DEBUG,
                "Public Key's type does not match public key type");
            ret = WS_INVALID_ALGO_ID;
        }
    }

    if (ret == WS_SUCCESS)
        ret = GetUint32(&curveNameSz, pk->publicKey, pk->publicKeySz, &i);

    if (ret == WS_SUCCESS) {
        curveName = pk->publicKey + i;
        (void)curveName; /* Not used at the moment, hush the compiler. */
        i += curveNameSz;
        ret = GetUint32(&qSz, pk->publicKey, pk->publicKeySz, &i);
    }

    if (ret == WS_SUCCESS) {
        q = pk->publicKey + i;
        i += qSz;
        ret = wc_ecc_init_ex(&key, ssh->ctx->heap, INVALID_DEVID);
    }

    if (ret == 0)
        ret = wc_ecc_import_x963(q, qSz, &key);

    if (ret != 0) {
        WLOG(WS_LOG_DEBUG, "Could not decode public key");
        ret = WS_CRYPTO_FAILED;
    }

    if (ret == WS_SUCCESS) {
        i = 0;
        /* First check that the signature's public key type matches the one
         * we are expecting. */
        ret = GetUint32(&publicKeyTypeSz, pk->signature, pk->signatureSz, &i);
    }

    if (ret == WS_SUCCESS) {
        publicKeyType = pk->signature + i;
        i += publicKeyTypeSz;

        if (publicKeyTypeSz != pk->publicKeyTypeSz &&
            WMEMCMP(publicKeyType, pk->publicKeyType, publicKeyTypeSz) != 0) {

            WLOG(WS_LOG_DEBUG,
                 "Signature's type does not match public key type");
            ret = WS_INVALID_ALGO_ID;
        }
    }

    if (ret == WS_SUCCESS) {
        /* Get the size of the signature blob. */
        ret = GetUint32(&sz, pk->signature, pk->signatureSz, &i);
    }

    if (ret == WS_SUCCESS) {
        /* Get R and S. */
        ret = GetUint32(&sz, pk->signature, pk->signatureSz, &i);
    }

    if (ret == WS_SUCCESS) {
        ret = mp_read_unsigned_bin(&r, pk->signature + i, sz);
        if (ret != 0)
            ret = WS_PARSE_E;
        else
            ret = WS_SUCCESS;
    }

    if (ret == WS_SUCCESS) {
        i += sz;
        ret = GetUint32(&sz, pk->signature, pk->signatureSz, &i);
    }

    if (ret == WS_SUCCESS) {
        ret = mp_read_unsigned_bin(&s, pk->signature + i, sz);
        if (ret != 0)
            ret = WS_PARSE_E;
        else
            ret = WS_SUCCESS;
    }

    if (ret == WS_SUCCESS) {
        int status = 0;

        ret = wc_ecc_verify_hash_ex(&r, &s, digest, digestSz, &status, &key);
        if (ret != 0) {
            WLOG(WS_LOG_DEBUG, "Could not verify signature");
            ret = WS_CRYPTO_FAILED;
        }
        else
            ret = status ? WS_SUCCESS : WS_ECC_E;
    }

    mp_clear(&r);
    mp_clear(&s);
    wc_ecc_free(&key);

    WLOG(WS_LOG_DEBUG, "Leaving DoUserAuthRequestEcc(), ret = %d", ret);
    return ret;
}


/* Utility for DoUserAuthRequest() */
static int DoUserAuthRequestPublicKey(WOLFSSH* ssh, WS_UserAuthData* authData,
                                      byte* buf, word32 len, word32* idx)
{
    word32 begin;
    WS_UserAuthData_PublicKey* pk;
    int ret = WS_SUCCESS;
    int authFailure = 0;

    WLOG(WS_LOG_DEBUG, "Entering DoUserAuthRequestPublicKey()");

    if (ssh == NULL || authData == NULL ||
        buf == NULL || len == 0 || idx == NULL) {

        ret = WS_BAD_ARGUMENT;
    }

    if (ret == WS_SUCCESS) {
        begin = *idx;
        pk = &authData->sf.publicKey;
        authData->type = WOLFSSH_USERAUTH_PUBLICKEY;
        ret = GetBoolean(&pk->hasSignature, buf, len, &begin);
    }

    if (ret == WS_SUCCESS)
        ret = GetUint32(&pk->publicKeyTypeSz, buf, len, &begin);

    if (ret == WS_SUCCESS) {
        pk->publicKeyType = buf + begin;
        begin += pk->publicKeyTypeSz;
        ret = GetUint32(&pk->publicKeySz, buf, len, &begin);
    }

    if (ret == WS_SUCCESS) {
        pk->publicKey = buf + begin;
        begin += pk->publicKeySz;

        if (pk->hasSignature) {
            ret = GetUint32(&pk->signatureSz, buf, len, &begin);
            if (ret == WS_SUCCESS) {
                pk->signature = buf + begin;
                begin += pk->signatureSz;
            }
        }
        else {
            pk->signature = NULL;
            pk->signatureSz = 0;
        }

        if (ret == WS_SUCCESS) {
            *idx = begin;

            if (ssh->ctx->userAuthCb != NULL) {
                WLOG(WS_LOG_DEBUG, "DUARPK: Calling the userauth callback");
                ret = ssh->ctx->userAuthCb(WOLFSSH_USERAUTH_PUBLICKEY,
                                           authData, ssh->userAuthCtx);
                WLOG(WS_LOG_DEBUG, "DUARPK: callback result = %d", ret);
                if (ret == WOLFSSH_USERAUTH_SUCCESS)
                    ret = WS_SUCCESS;
                else {
                    ret = SendUserAuthFailure(ssh, 0);
                    authFailure = 1;
                }
            }
            else {
                WLOG(WS_LOG_DEBUG, "DUARPK: no userauth callback set");
                ret = SendUserAuthFailure(ssh, 0);
                authFailure = 1;
            }
        }
    }

    if (ret == WS_SUCCESS && !authFailure) {
        if (pk->signature == NULL) {
            WLOG(WS_LOG_DEBUG, "DUARPK: Send the PK OK");
            ret = SendUserAuthPkOk(ssh, pk->publicKeyType, pk->publicKeyTypeSz,
                                   pk->publicKey, pk->publicKeySz);
        }
        else {
            wc_HashAlg hash;
            byte digest[WC_MAX_DIGEST_SIZE];
            word32 digestSz;
            byte hashId = WC_HASH_TYPE_SHA;
            byte pkTypeId;

            pkTypeId = NameToId((char*)pk->publicKeyType,
                                pk->publicKeyTypeSz);
            if (pkTypeId == ID_UNKNOWN)
                ret = WS_INVALID_ALGO_ID;

            if (ret == WS_SUCCESS) {
                hashId = HashForId(pkTypeId);
                WMEMSET(digest, 0, sizeof(digest));
                digestSz = wc_HashGetDigestSize(hashId);
                ret = wc_HashInit(&hash, hashId);
            }

            if (ret == 0) {
                c32toa(ssh->sessionIdSz, digest);
                ret = wc_HashUpdate(&hash, hashId, digest, UINT32_SZ);
            }

            if (ret == 0)
                ret = wc_HashUpdate(&hash, hashId,
                                    ssh->sessionId, ssh->sessionIdSz);

            if (ret == 0) {
                digest[0] = MSGID_USERAUTH_REQUEST;
                ret = wc_HashUpdate(&hash, hashId, digest, MSG_ID_SZ);
            }

            /* The rest of the fields in the signature are already
             * in the buffer. Just need to account for the sizes. */
            if (ret == 0)
                ret = wc_HashUpdate(&hash, hashId, pk->dataToSign,
                                    authData->usernameSz +
                                    authData->serviceNameSz +
                                    authData->authNameSz + BOOLEAN_SZ +
                                    pk->publicKeyTypeSz + pk->publicKeySz +
                                    (UINT32_SZ * 5));
            if (ret == 0) {
                ret = wc_HashFinal(&hash, hashId, digest);

                if (ret != 0)
                    ret = WS_CRYPTO_FAILED;
                else
                    ret = WS_SUCCESS;
            }

            if (ret == WS_SUCCESS) {
                if (pkTypeId == ID_SSH_RSA)
                    ret = DoUserAuthRequestRsa(ssh, pk,
                                               hashId, digest, digestSz);
                else if (pkTypeId == ID_ECDSA_SHA2_NISTP256 ||
                         pkTypeId == ID_ECDSA_SHA2_NISTP384 ||
                         pkTypeId == ID_ECDSA_SHA2_NISTP521)
                    ret = DoUserAuthRequestEcc(ssh, pk,
                                               hashId, digest, digestSz);
            }

            if (ret != WS_SUCCESS) {
                WLOG(WS_LOG_DEBUG, "DUARPK: signature compare failure");
                ret = SendUserAuthFailure(ssh, 0);
            }
            else {
                ssh->clientState = CLIENT_USERAUTH_DONE;
            }
        }
    }

    WLOG(WS_LOG_DEBUG, "Leaving DoUserAuthRequestPublicKey(), ret = %d", ret);
    return ret;
}


static int DoUserAuthRequest(WOLFSSH* ssh,
                             byte* buf, word32 len, word32* idx)
{
    word32 begin;
    int ret = WS_SUCCESS;
    byte authNameId;
    WS_UserAuthData authData;

    WLOG(WS_LOG_DEBUG, "Entering DoUserAuthRequest()");

    if (ssh == NULL || buf == NULL || len == 0 || idx == NULL)
        ret = WS_BAD_ARGUMENT;

    if (ret == WS_SUCCESS) {
        begin = *idx;
        WMEMSET(&authData, 0, sizeof(authData));
        ret = GetUint32(&authData.usernameSz, buf, len, &begin);
    }

    if (ret == WS_SUCCESS) {
        authData.username = buf + begin;
        begin += authData.usernameSz;

        ret = GetUint32(&authData.serviceNameSz, buf, len, &begin);
    }

    if (ret == WS_SUCCESS) {
        authData.serviceName = buf + begin;
        begin += authData.serviceNameSz;

        ret = GetUint32(&authData.authNameSz, buf, len, &begin);
    }

    if (ret == WS_SUCCESS) {
        authData.authName = buf + begin;
        begin += authData.authNameSz;
        authNameId = NameToId((char*)authData.authName, authData.authNameSz);

        if (authNameId == ID_USERAUTH_PASSWORD)
            ret = DoUserAuthRequestPassword(ssh, &authData, buf, len, &begin);
        else if (authNameId == ID_USERAUTH_PUBLICKEY) {
            authData.sf.publicKey.dataToSign = buf + *idx;
            ret = DoUserAuthRequestPublicKey(ssh, &authData, buf, len, &begin);
        }
#ifdef WOLFSSH_ALLOW_USERAUTH_NONE
        else if (authNameId == ID_NONE) {
            ssh->clientState = CLIENT_USERAUTH_DONE;
        }
#endif
        else {
            WLOG(WS_LOG_DEBUG,
                 "invalid userauth type: %s", IdToName(authNameId));
            ret = SendUserAuthFailure(ssh, 0);
        }

        *idx = begin;
    }

    WLOG(WS_LOG_DEBUG, "Leaving DoUserAuthRequest(), ret = %d", ret);
    return ret;
}


static int DoUserAuthFailure(WOLFSSH* ssh,
                             byte* buf, word32 len, word32* idx)
{
    byte authList[3]; /* Should only ever be password, publickey, hostname */
    word32 authListSz = 3;
    byte partialSuccess;
    byte authId = ID_USERAUTH_PASSWORD;
    int ret = WS_SUCCESS;

    WLOG(WS_LOG_DEBUG, "Entering DoUserAuthFailure()");

    if (ssh == NULL || buf == NULL || len == 0 || idx == NULL)
        ret = WS_BAD_ARGUMENT;

    if (ret == WS_SUCCESS)
        ret = GetNameList(authList, &authListSz, buf, len, idx);

    if (ret == WS_SUCCESS)
        ret = GetBoolean(&partialSuccess, buf, len, idx);

    if (ret == WS_SUCCESS)
        ret = SendUserAuthRequest(ssh, authId);

    WLOG(WS_LOG_DEBUG, "Leaving DoUserAuthFailure(), ret = %d", ret);
    return ret;
}


static int DoUserAuthSuccess(WOLFSSH* ssh,
                             byte* buf, word32 len, word32* idx)
{
    int ret = WS_SUCCESS;

    WLOG(WS_LOG_DEBUG, "Entering DoUserAuthSuccess()");

    /* This message does not have any payload. len should be 0. */
    if (ssh == NULL || buf == NULL || len != 0 || idx == NULL)
        ret = WS_BAD_ARGUMENT;

    ssh->serverState = SERVER_USERAUTH_ACCEPT_DONE;

    WLOG(WS_LOG_DEBUG, "Leaving DoUserAuthSuccess(), ret = %d", ret);
    return ret;
}


static int DoUserAuthBanner(WOLFSSH* ssh, byte* buf, word32 len, word32* idx)
{
    word32 begin;
    char banner[80];
    word32 bannerSz = sizeof(banner);
    int ret = WS_SUCCESS;

    WLOG(WS_LOG_DEBUG, "Entering DoUserAuthBanner()");

    if (ssh == NULL || buf == NULL || len == 0 || idx == NULL)
        ret = WS_BAD_ARGUMENT;

    if (ret == WS_SUCCESS) {
        begin = *idx;
        ret = GetString(banner, &bannerSz, buf, len, idx);
    }

    if (ret == WS_SUCCESS)
        ret = GetUint32(&bannerSz, buf, len, idx);

    if (ret == WS_SUCCESS) {
        begin += bannerSz;
        if (ssh->ctx->showBanner) {
            WLOG(WS_LOG_INFO, "%s", banner);
        }
    }

    WLOG(WS_LOG_DEBUG, "Leaving DoUserAuthBanner(), ret = %d", ret);
    return ret;
}


static int DoGlobalRequest(WOLFSSH* ssh,
                           byte* buf, word32 len, word32* idx)
{
    word32 begin;
    int ret = WS_SUCCESS;
    char name[80];
    word32 nameSz = sizeof(name);
    byte wantReply = 0;

    WLOG(WS_LOG_DEBUG, "Entering DoGlobalRequest()");

    if (ssh == NULL || buf == NULL || len == 0 || idx == NULL)
        ret = WS_BAD_ARGUMENT;

    if (ret == WS_SUCCESS) {
        begin = *idx;
        ret = GetString(name, &nameSz, buf, len, &begin);
    }

    if (ret == WS_SUCCESS) {
        WLOG(WS_LOG_DEBUG, "DGR: request name = %s", name);
        ret = GetBoolean(&wantReply, buf, len, &begin);
    }

    if (ret == WS_SUCCESS) {
        *idx += len;

        if (wantReply)
            ret = SendRequestSuccess(ssh, 0);
    }

    WLOG(WS_LOG_DEBUG, "Leaving DoGlobalRequest(), ret = %d", ret);
    return ret;
}


static int DoChannelOpen(WOLFSSH* ssh,
                         byte* buf, word32 len, word32* idx)
{
    word32 begin = *idx;
    word32 typeSz;
    char type[32];
    byte typeId = ID_UNKNOWN;
    word32 peerChannelId;
    word32 peerInitialWindowSz;
    word32 peerMaxPacketSz;
    int ret;
    WOLFSSH_CHANNEL* newChannel;

    WLOG(WS_LOG_DEBUG, "Entering DoChannelOpen()");

    typeSz = sizeof(type);
    ret = GetString(type, &typeSz, buf, len, &begin);

    if (ret == WS_SUCCESS)
        ret = GetUint32(&peerChannelId, buf, len, &begin);

    if (ret == WS_SUCCESS)
        ret = GetUint32(&peerInitialWindowSz, buf, len, &begin);

    if (ret == WS_SUCCESS)
        ret = GetUint32(&peerMaxPacketSz, buf, len, &begin);

    if (ret == WS_SUCCESS) {
        *idx = begin;

        WLOG(WS_LOG_INFO, "  type = %s", type);
        WLOG(WS_LOG_INFO, "  peerChannelId = %u", peerChannelId);
        WLOG(WS_LOG_INFO, "  peerInitialWindowSz = %u", peerInitialWindowSz);
        WLOG(WS_LOG_INFO, "  peerMaxPacketSz = %u", peerMaxPacketSz);

        typeId = NameToId(type, typeSz);
        if (typeId != ID_CHANTYPE_SESSION)
            ret = WS_INVALID_CHANTYPE;
    }

    if (ret == WS_SUCCESS) {
        newChannel = ChannelNew(ssh, typeId,
                                DEFAULT_WINDOW_SZ, DEFAULT_MAX_PACKET_SZ);
        if (newChannel == NULL)
            ret = WS_RESOURCE_E;
        else {
            ChannelUpdate(newChannel, peerChannelId,
                          peerInitialWindowSz, peerMaxPacketSz);
            if (ssh->channelListSz == 0)
                ssh->defaultPeerChannelId = peerChannelId;
            ChannelAppend(ssh, newChannel);

            ssh->clientState = CLIENT_CHANNEL_OPEN_DONE;
        }
    }

    WLOG(WS_LOG_DEBUG, "Leaving DoChannelOpen(), ret = %d", ret);
    return ret;
}


static int DoChannelOpenConf(WOLFSSH* ssh,
                             byte* buf, word32 len, word32* idx)
{
    WOLFSSH_CHANNEL* channel;
    word32 begin, channelId, peerChannelId,
           peerInitialWindowSz, peerMaxPacketSz;
    int ret = WS_SUCCESS;

    WLOG(WS_LOG_DEBUG, "Entering DoChannelOpenConf()");

    if (ssh == NULL || buf == NULL || len == 0 || idx == NULL)
        ret = WS_BAD_ARGUMENT;

    if (ret == WS_SUCCESS) {
        begin = *idx;
        ret = GetUint32(&channelId, buf, len, &begin);
    }

    if (ret == WS_SUCCESS)
        ret = GetUint32(&peerChannelId, buf, len, &begin);

    if (ret == WS_SUCCESS)
        ret = GetUint32(&peerInitialWindowSz, buf, len, &begin);

    if (ret == WS_SUCCESS)
        ret = GetUint32(&peerMaxPacketSz, buf, len, &begin);

    if (ret == WS_SUCCESS) {
        WLOG(WS_LOG_INFO, "  channelId = %u", channelId);
        WLOG(WS_LOG_INFO, "  peerChannelId = %u", peerChannelId);
        WLOG(WS_LOG_INFO, "  peerInitialWindowSz = %u", peerInitialWindowSz);
        WLOG(WS_LOG_INFO, "  peerMaxPacketSz = %u", peerMaxPacketSz);

        channel = ChannelFind(ssh, channelId, FIND_SELF);
        if (channel == NULL)
            ret = WS_INVALID_CHANID;
    }

    if (ret == WS_SUCCESS)
        ret = ChannelUpdate(channel, peerChannelId,
                            peerInitialWindowSz, peerMaxPacketSz);

    if (ret == WS_SUCCESS)
        ssh->serverState = SERVER_CHANNEL_OPEN_DONE;

    WLOG(WS_LOG_DEBUG, "Leaving DoChannelOpenConf(), ret = %d", ret);
    return ret;
}


static int DoChannelOpenFail(WOLFSSH* ssh,
                             byte* buf, word32 len, word32* idx)
{
    char desc[80];
    word32 begin, channelId, reasonId, descSz, langSz;
    int ret = WS_SUCCESS;

    WLOG(WS_LOG_DEBUG, "Entering DoChannelOpenFail()");

    if (ssh == NULL || buf == NULL || len == 0 || idx == NULL)
        ret = WS_BAD_ARGUMENT;

    if (ret == WS_SUCCESS) {
        begin = *idx;
        ret = GetUint32(&channelId, buf, len, &begin);
    }

    if (ret == WS_SUCCESS)
        ret = GetUint32(&reasonId, buf, len, &begin);

    if (ret == WS_SUCCESS) {
        descSz = sizeof(desc);
        ret = GetString(desc, &descSz, buf, len, &begin);
    }

    if (ret == WS_SUCCESS)
        ret = GetUint32(&langSz, buf, len, &begin);

    if (ret == WS_SUCCESS) {
        *idx = begin + langSz;

        WLOG(WS_LOG_INFO, "channel open failure reason code: %u", reasonId);
        if (descSz > 0) {
            WLOG(WS_LOG_INFO, "description: %s", desc);
        }

        ret = ChannelRemove(ssh, channelId, FIND_SELF);
    }

    if (ret == WS_SUCCESS)
        ret = WS_CHANOPEN_FAILED;

    WLOG(WS_LOG_DEBUG, "Leaving DoChannelOpenFail(), ret = %d", ret);
    return ret;
}


static int DoChannelEof(WOLFSSH* ssh,
                        byte* buf, word32 len, word32* idx)
{
    WOLFSSH_CHANNEL* channel = NULL;
    word32 begin = *idx;
    word32 channelId;
    int      ret;

    WLOG(WS_LOG_DEBUG, "Entering DoChannelEof()");

    ret = GetUint32(&channelId, buf, len, &begin);

    if (ret == WS_SUCCESS) {
        *idx = begin;

        channel = ChannelFind(ssh, channelId, FIND_SELF);
        if (channel == NULL)
            ret = WS_INVALID_CHANID;
    }

    channel->receivedEof = 1;

    WLOG(WS_LOG_DEBUG, "Leaving DoChannelEof(), ret = %d", ret);
    return ret;
}


static int DoChannelClose(WOLFSSH* ssh,
                          byte* buf, word32 len, word32* idx)
{
    WOLFSSH_CHANNEL* channel = NULL;
    word32 begin = *idx;
    word32 channelId;
    int ret;

    WLOG(WS_LOG_DEBUG, "Entering DoChannelClose()");

    ret = GetUint32(&channelId, buf, len, &begin);

    if (ret == WS_SUCCESS) {
        *idx = begin;

        channel = ChannelFind(ssh, channelId, FIND_SELF);
        if (channel == NULL)
            ret = WS_INVALID_CHANID;
    }

    if (ret == WS_SUCCESS)
        ret = SendChannelClose(ssh, channel->peerChannel);

    if (ret == WS_SUCCESS)
        ret = ChannelRemove(ssh, channelId, FIND_SELF);

	if (ret == WS_SUCCESS)
		ret = WS_CHANNEL_CLOSED;

    WLOG(WS_LOG_DEBUG, "Leaving DoChannelClose(), ret = %d", ret);
    return ret;
}


static int DoChannelRequest(WOLFSSH* ssh,
                            byte* buf, word32 len, word32* idx)
{
    WOLFSSH_CHANNEL* channel = NULL;
    word32 begin = *idx;
    word32 channelId;
    word32 typeSz;
    char type[32];
    byte wantReply;
    int ret;

    WLOG(WS_LOG_DEBUG, "Entering DoChannelRequest()");

    ret = GetUint32(&channelId, buf, len, &begin);

    typeSz = sizeof(type);
    if (ret == WS_SUCCESS)
        ret = GetString(type, &typeSz, buf, len, &begin);

    if (ret == WS_SUCCESS)
        ret = GetBoolean(&wantReply, buf, len, &begin);

    if (ret != WS_SUCCESS) {
        WLOG(WS_LOG_DEBUG, "Leaving DoChannelRequest(), ret = %d", ret);
        return ret;
    }

    if (ret == WS_SUCCESS) {
        channel = ChannelFind(ssh, channelId, FIND_SELF);
        if (channel == NULL)
            ret = WS_INVALID_CHANID;
    }

    if (ret == WS_SUCCESS) {
        WLOG(WS_LOG_DEBUG, "  channelId = %u", channelId);
        WLOG(WS_LOG_DEBUG, "  type = %s", type);
        WLOG(WS_LOG_DEBUG, "  wantReply = %u", wantReply);

        if (WSTRNCMP(type, "pty-req", typeSz) == 0) {
            char term[32];
            word32 termSz;
            word32 widthChar, heightRows, widthPixels, heightPixels;
            word32 modesSz;

            termSz = sizeof(term);
            ret = GetString(term, &termSz, buf, len, &begin);
            if (ret == WS_SUCCESS)
                ret = GetUint32(&widthChar, buf, len, &begin);
            if (ret == WS_SUCCESS)
                ret = GetUint32(&heightRows, buf, len, &begin);
            if (ret == WS_SUCCESS)
                ret = GetUint32(&widthPixels, buf, len, &begin);
            if (ret == WS_SUCCESS)
                ret = GetUint32(&heightPixels, buf, len, &begin);
            if (ret == WS_SUCCESS)
                ret = GetUint32(&modesSz, buf, len, &begin);

            if (ret == WS_SUCCESS) {
                WLOG(WS_LOG_DEBUG, "  term = %s", term);
                WLOG(WS_LOG_DEBUG, "  widthChar = %u", widthChar);
                WLOG(WS_LOG_DEBUG, "  heightRows = %u", heightRows);
                WLOG(WS_LOG_DEBUG, "  widthPixels = %u", widthPixels);
                WLOG(WS_LOG_DEBUG, "  heightPixels = %u", heightPixels);
                WLOG(WS_LOG_DEBUG, "  modes = %u", (modesSz - 1) / 5);
            }
        }
        else if (WSTRNCMP(type, "env", typeSz) == 0) {
            char name[32];
            word32 nameSz;
            char value[32];
            word32 valueSz;

            nameSz = sizeof(name);
            valueSz = sizeof(value);
            ret = GetString(name, &nameSz, buf, len, &begin);
            if (ret == WS_SUCCESS)
                ret = GetString(value, &valueSz, buf, len, &begin);

            WLOG(WS_LOG_DEBUG, "  %s = %s", name, value);
        }
        else if (WSTRNCMP(type, "shell", typeSz) == 0) {
            channel->sessionType = WOLFSSH_SESSION_SHELL;
            ssh->clientState = CLIENT_DONE;
        }
        else if (WSTRNCMP(type, "exec", typeSz) == 0) {
            ret = GetStringAlloc(ssh, &channel->command, buf, len, &begin);
            channel->sessionType = WOLFSSH_SESSION_EXEC;
            ssh->clientState = CLIENT_DONE;

            WLOG(WS_LOG_DEBUG, "  command = %s", channel->command);
        }
        else if (WSTRNCMP(type, "subsystem", typeSz) == 0) {
            ret = GetStringAlloc(ssh, &channel->command, buf, len, &begin);
            channel->sessionType = WOLFSSH_SESSION_SUBSYSTEM;
            ssh->clientState = CLIENT_DONE;

            WLOG(WS_LOG_DEBUG, "  subsystem = %s", channel->command);
        }
    }

    if (ret == WS_SUCCESS)
        *idx = len;

    if (wantReply) {
        int replyRet;

        replyRet = SendChannelSuccess(ssh, channelId, (ret == WS_SUCCESS));
        if (replyRet != WS_SUCCESS)
            ret = replyRet;
    }

    WLOG(WS_LOG_DEBUG, "Leaving DoChannelRequest(), ret = %d", ret);
    return ret;
}


static int DoChannelSuccess(WOLFSSH* ssh, byte* buf, word32 len, word32* idx)
{
    int ret = WS_SUCCESS;

    WLOG(WS_LOG_DEBUG, "Entering DoChannelSuccess()");

    if (ssh == NULL || buf == NULL || len == 0 || idx == NULL)
        ret = WS_BAD_ARGUMENT;

    ssh->serverState = SERVER_DONE;

    WLOG(WS_LOG_DEBUG, "Leaving DoChannelSuccess(), ret = %d", ret);
    return ret;
}


static int DoChannelFailure(WOLFSSH* ssh, byte* buf, word32 len, word32* idx)
{
    int ret = WS_SUCCESS;

    WLOG(WS_LOG_DEBUG, "Entering DoChannelFailure()");

    if (ssh == NULL || buf == NULL || len != 0 || idx == NULL)
        ret = WS_BAD_ARGUMENT;

    if (ret == WS_SUCCESS)
        ret = WS_CHANOPEN_FAILED;
    WLOG(WS_LOG_DEBUG, "Leaving DoChannelFailure(), ret = %d", ret);
    return ret;
}


static int DoChannelWindowAdjust(WOLFSSH* ssh,
                                 byte* buf, word32 len, word32* idx)
{
    WOLFSSH_CHANNEL* channel = NULL;
    word32 begin = *idx;
    word32 channelId, bytesToAdd;
    int ret;

    WLOG(WS_LOG_DEBUG, "Entering DoChannelWindowAdjust()");

    ret = GetUint32(&channelId, buf, len, &begin);
    if (ret == WS_SUCCESS)
        ret = GetUint32(&bytesToAdd, buf, len, &begin);

    if (ret == WS_SUCCESS) {
        *idx = begin;

        channel = ChannelFind(ssh, channelId, FIND_SELF);
        if (channel == NULL)
            ret = WS_INVALID_CHANID;
        else {
            WLOG(WS_LOG_INFO, "  channelId = %u", channelId);
            WLOG(WS_LOG_INFO, "  bytesToAdd = %u", bytesToAdd);
            WLOG(WS_LOG_INFO, "  peerWindowSz = %u",
                 channel->peerWindowSz);

            channel->peerWindowSz += bytesToAdd;

            WLOG(WS_LOG_INFO, "  update peerWindowSz = %u",
                 channel->peerWindowSz);

        }
    }

    WLOG(WS_LOG_DEBUG, "Leaving DoChannelWindowAdjust(), ret = %d", ret);
    return ret;
}


static int DoChannelData(WOLFSSH* ssh,
                         byte* buf, word32 len, word32* idx)
{
    WOLFSSH_CHANNEL* channel = NULL;
    word32 begin = *idx;
    word32 dataSz = 0;
    word32 channelId;
    int ret;

    WLOG(WS_LOG_DEBUG, "Entering DoChannelData()");

    ret = GetUint32(&channelId, buf, len, &begin);
    if (ret == WS_SUCCESS)
        ret = GetUint32(&dataSz, buf, len, &begin);

    if (ret == WS_SUCCESS) {
        *idx = begin + dataSz;

        channel = ChannelFind(ssh, channelId, FIND_SELF);
        if (channel == NULL)
            ret = WS_INVALID_CHANID;
        else
            ret = ChannelPutData(channel, buf + begin, dataSz);
    }

    WLOG(WS_LOG_DEBUG, "Leaving DoChannelData(), ret = %d", ret);
    return ret;
}


static int DoPacket(WOLFSSH* ssh)
{
    byte* buf = (byte*)ssh->inputBuffer.buffer;
    word32 idx = ssh->inputBuffer.idx;
    word32 len = ssh->inputBuffer.length;
    word32 payloadSz;
    byte padSz;
    byte msg;
    word32 payloadIdx = 0;
    int ret;

    WLOG(WS_LOG_DEBUG, "DoPacket sequence number: %d", ssh->peerSeq);

    idx += LENGTH_SZ;
    padSz = buf[idx++];
    payloadSz = ssh->curSz - PAD_LENGTH_SZ - padSz - MSG_ID_SZ;

    msg = buf[idx++];
    /* At this point, payload starts at "buf + idx". */

    switch (msg) {

        case MSGID_DISCONNECT:
            WLOG(WS_LOG_DEBUG, "Decoding MSGID_DISCONNECT");
            ret = DoDisconnect(ssh, buf + idx, payloadSz, &payloadIdx);
            break;

        case MSGID_IGNORE:
            WLOG(WS_LOG_DEBUG, "Decoding MSGID_IGNORE");
            ret = DoIgnore(ssh, buf + idx, payloadSz, &payloadIdx);
            break;

        case MSGID_UNIMPLEMENTED:
            WLOG(WS_LOG_DEBUG, "Decoding MSGID_UNIMPLEMENTED");
            ret = DoUnimplemented(ssh, buf + idx, payloadSz, &payloadIdx);
            break;

        case MSGID_DEBUG:
            WLOG(WS_LOG_DEBUG, "Decoding MSGID_DEBUG");
            ret = DoDebug(ssh, buf + idx, payloadSz, &payloadIdx);
            break;

        case MSGID_KEXINIT:
            WLOG(WS_LOG_DEBUG, "Decoding MSGID_KEXINIT");
            ret = DoKexInit(ssh, buf + idx, payloadSz, &payloadIdx);
            break;

        case MSGID_NEWKEYS:
            WLOG(WS_LOG_DEBUG, "Decoding MSGID_NEWKEYS");
            ret = DoNewKeys(ssh, buf + idx, payloadSz, &payloadIdx);
            break;

        case MSGID_KEXDH_INIT:
            WLOG(WS_LOG_DEBUG, "Decoding MSGID_KEXDH_INIT");
            ret = DoKexDhInit(ssh, buf + idx, payloadSz, &payloadIdx);
            break;

        case MSGID_KEXDH_REPLY:
            if (ssh->handshake == NULL) {
                ret = WS_MEMORY_E;
                break;
            }

            if (ssh->handshake->kexId == ID_DH_GEX_SHA256) {
                WLOG(WS_LOG_DEBUG, "Decoding MSGID_KEXDH_GEX_GROUP");
                ret = DoKexDhGexGroup(ssh, buf + idx, payloadSz, &payloadIdx);
            }
            else {
                WLOG(WS_LOG_DEBUG, "Decoding MSGID_KEXDH_REPLY");
                ret = DoKexDhReply(ssh, buf + idx, payloadSz, &payloadIdx);
            }
            break;

        case MSGID_KEXDH_GEX_REQUEST:
            WLOG(WS_LOG_DEBUG, "Decoding MSGID_KEXDH_GEX_REQUEST");
            ret = DoKexDhGexRequest(ssh, buf + idx, payloadSz, &payloadIdx);
            break;

        case MSGID_KEXDH_GEX_INIT:
            WLOG(WS_LOG_DEBUG, "Decoding MSGID_KEXDH_GEX_INIT");
            ret = DoKexDhInit(ssh, buf + idx, payloadSz, &payloadIdx);
            break;

        case MSGID_KEXDH_GEX_REPLY:
            WLOG(WS_LOG_DEBUG, "Decoding MSGID_KEXDH_GEX_INIT");
            ret = DoKexDhReply(ssh, buf + idx, payloadSz, &payloadIdx);
            break;

        case MSGID_SERVICE_REQUEST:
            WLOG(WS_LOG_DEBUG, "Decoding MSGID_SERVICE_REQUEST");
            ret = DoServiceRequest(ssh, buf + idx, payloadSz, &payloadIdx);
            break;

        case MSGID_SERVICE_ACCEPT:
            WLOG(WS_LOG_DEBUG, "Decoding MSGID_SERVER_ACCEPT");
            ret = DoServiceAccept(ssh, buf + idx, payloadSz, &payloadIdx);
            break;

        case MSGID_USERAUTH_REQUEST:
            WLOG(WS_LOG_DEBUG, "Decoding MSGID_USERAUTH_REQUEST");
            ret = DoUserAuthRequest(ssh, buf + idx, payloadSz, &payloadIdx);
            break;

        case MSGID_USERAUTH_FAILURE:
            WLOG(WS_LOG_DEBUG, "Decoding MSGID_USERAUTH_FAILURE");
            ret = DoUserAuthFailure(ssh, buf + idx, payloadSz, &payloadIdx);
            break;

        case MSGID_USERAUTH_SUCCESS:
            WLOG(WS_LOG_DEBUG, "Decoding MSGID_USERAUTH_SUCCESS");
            ret = DoUserAuthSuccess(ssh, buf + idx, payloadSz, &payloadIdx);
            break;

        case MSGID_USERAUTH_BANNER:
            WLOG(WS_LOG_DEBUG, "Decoding MSGID_USERAUTH_BANNER");
            ret = DoUserAuthBanner(ssh, buf + idx, payloadSz, &payloadIdx);
            break;

        case MSGID_GLOBAL_REQUEST:
            WLOG(WS_LOG_DEBUG, "Decoding MSGID_GLOBAL_REQUEST");
            ret = DoGlobalRequest(ssh, buf + idx, payloadSz, &payloadIdx);
            break;

        case MSGID_CHANNEL_OPEN:
            WLOG(WS_LOG_DEBUG, "Decoding MSGID_CHANNEL_OPEN");
            ret = DoChannelOpen(ssh, buf + idx, payloadSz, &payloadIdx);
            break;

        case MSGID_CHANNEL_OPEN_CONF:
            WLOG(WS_LOG_DEBUG, "Decoding MSGID_CHANNEL_OPEN_CONF");
            ret = DoChannelOpenConf(ssh, buf + idx, payloadSz, &payloadIdx);
            break;

        case MSGID_CHANNEL_OPEN_FAIL:
            WLOG(WS_LOG_DEBUG, "Decoding MSGID_CHANNEL_OPEN_FAIL");
            ret = DoChannelOpenFail(ssh, buf + idx, payloadSz, &payloadIdx);
            break;

        case MSGID_CHANNEL_WINDOW_ADJUST:
            WLOG(WS_LOG_DEBUG, "Decoding MSGID_CHANNEL_WINDOW_ADJUST");
            ret = DoChannelWindowAdjust(ssh, buf + idx, payloadSz, &payloadIdx);
            break;

        case MSGID_CHANNEL_DATA:
            WLOG(WS_LOG_DEBUG, "Decoding MSGID_CHANNEL_DATA");
            ret = DoChannelData(ssh, buf + idx, payloadSz, &payloadIdx);
            break;

        case MSGID_CHANNEL_EOF:
            WLOG(WS_LOG_DEBUG, "Decoding MSGID_CHANNEL_EOF");
            ret = DoChannelEof(ssh, buf + idx, payloadSz, &payloadIdx);
            ret = WS_SUCCESS;
            break;

        case MSGID_CHANNEL_CLOSE:
            WLOG(WS_LOG_DEBUG, "Decoding MSGID_CHANNEL_CLOSE");
            ret = DoChannelClose(ssh, buf + idx, payloadSz, &payloadIdx);
            break;

        case MSGID_CHANNEL_REQUEST:
            WLOG(WS_LOG_DEBUG, "Decoding MSGID_CHANNEL_REQUEST");
            ret = DoChannelRequest(ssh, buf + idx, payloadSz, &payloadIdx);
            break;

        case MSGID_CHANNEL_SUCCESS:
            WLOG(WS_LOG_DEBUG, "Decoding MSGID_CHANNEL_SUCCESS");
            ret = DoChannelSuccess(ssh, buf + idx, payloadSz, &payloadIdx);
            break;

        case MSGID_CHANNEL_FAILURE:
            WLOG(WS_LOG_DEBUG, "Decoding MSGID_CHANNEL_FAILURE");
            ret = DoChannelFailure(ssh, buf + idx, payloadSz, &payloadIdx);
            break;

        default:
            WLOG(WS_LOG_DEBUG, "Unimplemented message ID (%d)", msg);
#ifdef SHOW_UNIMPLEMENTED
            DumpOctetString(buf + idx, payloadSz);
#endif
            ret = SendUnimplemented(ssh);
    }

    if (ret == WS_SUCCESS) {
        idx += payloadIdx;

        if (idx + padSz > len) {
            WLOG(WS_LOG_DEBUG, "Not enough data in buffer for pad.");
            ret = WS_BUFFER_E;
        }
    }

    if (ret == WS_SUCCESS) {
        idx += padSz;
        ssh->inputBuffer.idx = idx;
        ssh->peerSeq++;
    }

    return ret;
}


static INLINE int Encrypt(WOLFSSH* ssh, byte* cipher, const byte* input,
                          word16 sz)
{
    int ret = WS_SUCCESS;

    if (ssh == NULL || cipher == NULL || input == NULL || sz == 0)
        return WS_BAD_ARGUMENT;

    WLOG(WS_LOG_DEBUG, "Encrypt %s", IdToName(ssh->encryptId));

    switch (ssh->encryptId) {
        case ID_NONE:
            break;

        case ID_AES128_CBC:
            if (sz % AES_BLOCK_SIZE || wc_AesCbcEncrypt(&ssh->encryptCipher.aes,
                                 cipher, input, sz) < 0) {

                ret = WS_ENCRYPT_E;
            }
            break;

        default:
            ret = WS_INVALID_ALGO_ID;
    }

    ssh->txCount += sz;

    return ret;
}


static INLINE int Decrypt(WOLFSSH* ssh, byte* plain, const byte* input,
                          word16 sz)
{
    int ret = WS_SUCCESS;

    if (ssh == NULL || plain == NULL || input == NULL || sz == 0)
        return WS_BAD_ARGUMENT;

    WLOG(WS_LOG_DEBUG, "Decrypt %s", IdToName(ssh->peerEncryptId));

    switch (ssh->peerEncryptId) {
        case ID_NONE:
            break;

        case ID_AES128_CBC:
            if (sz % AES_BLOCK_SIZE || wc_AesCbcDecrypt(&ssh->decryptCipher.aes,
                                 plain, input, sz) < 0) {

                ret = WS_DECRYPT_E;
            }
            break;

        default:
            ret = WS_INVALID_ALGO_ID;
    }

    ssh->rxCount += sz;
    HighwaterCheck(ssh, WOLFSSH_HWSIDE_RECEIVE);

    return ret;
}


static INLINE int CreateMac(WOLFSSH* ssh, const byte* in, word32 inSz,
                            byte* mac)
{
    byte flatSeq[LENGTH_SZ];
    int ret;

    c32toa(ssh->seq, flatSeq);

    WLOG(WS_LOG_DEBUG, "CreateMac %s", IdToName(ssh->macId));

    /* Need to MAC the sequence number and the unencrypted packet */
    switch (ssh->macId) {
        case ID_NONE:
            ret = WS_SUCCESS;
            break;

        case ID_HMAC_SHA1_96:
            {
                Hmac hmac;
                byte digest[SHA_DIGEST_SIZE];

                ret = wc_HmacSetKey(&hmac, SHA,
                                    ssh->keys.macKey, ssh->keys.macKeySz);
                if (ret == WS_SUCCESS)
                    ret = wc_HmacUpdate(&hmac, flatSeq, sizeof(flatSeq));
                if (ret == WS_SUCCESS)
                    ret = wc_HmacUpdate(&hmac, in, inSz);
                if (ret == WS_SUCCESS)
                    ret = wc_HmacFinal(&hmac, digest);
                if (ret == WS_SUCCESS)
                    WMEMCPY(mac, digest, SHA1_96_SZ);
            }
            break;

        case ID_HMAC_SHA1:
            {
                Hmac hmac;

                ret = wc_HmacSetKey(&hmac, SHA,
                                    ssh->keys.macKey, ssh->keys.macKeySz);
                if (ret == WS_SUCCESS)
                    ret = wc_HmacUpdate(&hmac, flatSeq, sizeof(flatSeq));
                if (ret == WS_SUCCESS)
                    ret = wc_HmacUpdate(&hmac, in, inSz);
                if (ret == WS_SUCCESS)
                    ret = wc_HmacFinal(&hmac, mac);
            }
            break;

        case ID_HMAC_SHA2_256:
            {
                Hmac hmac;

                ret = wc_HmacSetKey(&hmac, WC_SHA256,
                                    ssh->keys.macKey,
                                    ssh->keys.macKeySz);
                if (ret == WS_SUCCESS)
                    ret = wc_HmacUpdate(&hmac, flatSeq, sizeof(flatSeq));
                if (ret == WS_SUCCESS)
                    ret = wc_HmacUpdate(&hmac, in, inSz);
                if (ret == WS_SUCCESS)
                    ret = wc_HmacFinal(&hmac, mac);
            }
            break;

        default:
            WLOG(WS_LOG_DEBUG, "Invalid Mac ID");
            ret = WS_FATAL_ERROR;
    }

    return ret;
}


static INLINE int VerifyMac(WOLFSSH* ssh, const byte* in, word32 inSz,
                            const byte* mac)
{
    int ret;
    byte flatSeq[LENGTH_SZ];
    byte checkMac[MAX_HMAC_SZ];
    Hmac hmac;

    c32toa(ssh->peerSeq, flatSeq);

    WLOG(WS_LOG_DEBUG, "VerifyMac %s", IdToName(ssh->peerMacId));
    WLOG(WS_LOG_DEBUG, "VM: inSz = %u", inSz);
    WLOG(WS_LOG_DEBUG, "VM: seq = %u", ssh->peerSeq);
    WLOG(WS_LOG_DEBUG, "VM: keyLen = %u", ssh->peerKeys.macKeySz);

    WMEMSET(checkMac, 0, sizeof(checkMac));

    switch (ssh->peerMacId) {
        case ID_NONE:
            ret = WS_SUCCESS;
            break;

        case ID_HMAC_SHA1:
        case ID_HMAC_SHA1_96:
            ret = wc_HmacSetKey(&hmac, SHA,
                                ssh->peerKeys.macKey, ssh->peerKeys.macKeySz);
            if (ret == WS_SUCCESS)
                ret = wc_HmacUpdate(&hmac, flatSeq, sizeof(flatSeq));
            if (ret == WS_SUCCESS)
                ret = wc_HmacUpdate(&hmac, in, inSz);
            if (ret == WS_SUCCESS)
                ret = wc_HmacFinal(&hmac, checkMac);
            if (ConstantCompare(checkMac, mac, ssh->peerMacSz) != 0)
                ret = WS_VERIFY_MAC_E;
            break;

        case ID_HMAC_SHA2_256:
            ret = wc_HmacSetKey(&hmac, WC_SHA256,
                                ssh->peerKeys.macKey, ssh->peerKeys.macKeySz);
            if (ret == WS_SUCCESS)
                ret = wc_HmacUpdate(&hmac, flatSeq, sizeof(flatSeq));
            if (ret == WS_SUCCESS)
                ret = wc_HmacUpdate(&hmac, in, inSz);
            if (ret == WS_SUCCESS)
                ret = wc_HmacFinal(&hmac, checkMac);
            if (ConstantCompare(checkMac, mac, ssh->peerMacSz) != 0)
                ret = WS_VERIFY_MAC_E;
            break;

        default:
            ret = WS_INVALID_ALGO_ID;
    }

    return ret;
}


static INLINE void AeadIncrementExpIv(byte* iv)
{
    int i;

    iv += AEAD_IMP_IV_SZ;

    for (i = AEAD_EXP_IV_SZ-1; i >= 0; i--) {
        if (++iv[i]) return;
    }
}


static INLINE int EncryptAead(WOLFSSH* ssh, byte* cipher,
                              const byte* input, word16 sz,
                              byte* authTag, const byte* auth,
                              word16 authSz)
{
    int ret = WS_SUCCESS;

    if (ssh == NULL || cipher == NULL || input == NULL || sz == 0 ||
        authTag == NULL || auth == NULL || authSz == 0)
        return WS_BAD_ARGUMENT;

    WLOG(WS_LOG_DEBUG, "EncryptAead %s", IdToName(ssh->encryptId));

    if (ssh->encryptId == ID_AES128_GCM) {
        ret = wc_AesGcmEncrypt(&ssh->encryptCipher.aes, cipher, input, sz,
                               ssh->keys.iv, ssh->keys.ivSz,
                               authTag, ssh->macSz, auth, authSz);
    }
    else
        ret = WS_INVALID_ALGO_ID;

    AeadIncrementExpIv(ssh->keys.iv);
    ssh->txCount += sz;

    return ret;
}


static INLINE int DecryptAead(WOLFSSH* ssh, byte* plain,
                              const byte* input, word16 sz,
                              const byte* authTag, const byte* auth,
                              word16 authSz)
{
    int ret = WS_SUCCESS;

    if (ssh == NULL || plain == NULL || input == NULL || sz == 0 ||
        authTag == NULL || auth == NULL || authSz == 0)
        return WS_BAD_ARGUMENT;

    WLOG(WS_LOG_DEBUG, "DecryptAead %s", IdToName(ssh->peerEncryptId));

    if (ssh->peerEncryptId == ID_AES128_GCM) {
        ret = wc_AesGcmDecrypt(&ssh->decryptCipher.aes, plain, input, sz,
                               ssh->peerKeys.iv, ssh->peerKeys.ivSz,
                               authTag, ssh->peerMacSz, auth, authSz);
    }
    else
        ret = WS_INVALID_ALGO_ID;

    AeadIncrementExpIv(ssh->peerKeys.iv);
    ssh->rxCount += sz;
    HighwaterCheck(ssh, WOLFSSH_HWSIDE_RECEIVE);

    return ret;
}


int DoReceive(WOLFSSH* ssh)
{
    int ret = WS_FATAL_ERROR;
    int verifyResult;
    word32 readSz;
    byte peerBlockSz = ssh->peerBlockSz;
    byte peerMacSz = ssh->peerMacSz;
    byte aeadMode = ssh->peerAeadMode;

    for (;;) {
        switch (ssh->processReplyState) {
            case PROCESS_INIT:
                readSz = peerBlockSz;
                WLOG(WS_LOG_DEBUG, "PR1: size = %u", readSz);
                if ((ret = GetInputData(ssh, readSz)) < 0) {
                    return ret;
                }
                ssh->processReplyState = PROCESS_PACKET_LENGTH;

                if (!aeadMode) {
                    /* Decrypt first block if encrypted */
                    ret = Decrypt(ssh,
                                  ssh->inputBuffer.buffer +
                                     ssh->inputBuffer.idx,
                                  ssh->inputBuffer.buffer +
                                     ssh->inputBuffer.idx,
                                  readSz);
                    if (ret != WS_SUCCESS) {
                        WLOG(WS_LOG_DEBUG, "PR: First decrypt fail");
                        return ret;
                    }
                }
                FALL_THROUGH;

            case PROCESS_PACKET_LENGTH:
                /* Peek at the packet_length field. */
                ato32(ssh->inputBuffer.buffer + ssh->inputBuffer.idx,
                      &ssh->curSz);
                ssh->processReplyState = PROCESS_PACKET_FINISH;
                FALL_THROUGH;

            case PROCESS_PACKET_FINISH:
                readSz = ssh->curSz + LENGTH_SZ + peerMacSz;
                WLOG(WS_LOG_DEBUG, "PR2: size = %u", readSz);
                if (readSz > 0) {
                    if ((ret = GetInputData(ssh, readSz)) < 0) {
                        return ret;
                    }

                    if (!aeadMode) {
                        if (ssh->curSz + LENGTH_SZ - peerBlockSz > 0) {
                            ret = Decrypt(ssh,
                                          ssh->inputBuffer.buffer +
                                             ssh->inputBuffer.idx + peerBlockSz,
                                          ssh->inputBuffer.buffer +
                                             ssh->inputBuffer.idx + peerBlockSz,
                                          ssh->curSz + LENGTH_SZ - peerBlockSz);
                        }
                        else {
                            WLOG(WS_LOG_INFO,
                                 "Not trying to decrypt short message.");
                        }

                        /* Verify the buffer is big enough for the data and mac.
                         * Even if the decrypt step fails, verify the MAC anyway.
                         * This keeps consistent timing. */
                        verifyResult = VerifyMac(ssh,
                                                 ssh->inputBuffer.buffer +
                                                     ssh->inputBuffer.idx,
                                                 ssh->curSz + LENGTH_SZ,
                                                 ssh->inputBuffer.buffer +
                                                     ssh->inputBuffer.idx +
                                                     LENGTH_SZ + ssh->curSz);
                        if (ret != WS_SUCCESS) {
                            WLOG(WS_LOG_DEBUG, "PR: Decrypt fail");
                            return ret;
                        }
                        if (verifyResult != WS_SUCCESS) {
                            WLOG(WS_LOG_DEBUG, "PR: VerifyMac fail");
                            return verifyResult;
                        }
                    }
                    else {
                        ret = DecryptAead(ssh,
                                          ssh->inputBuffer.buffer +
                                             ssh->inputBuffer.idx +
                                             LENGTH_SZ,
                                          ssh->inputBuffer.buffer +
                                             ssh->inputBuffer.idx +
                                             LENGTH_SZ,
                                          ssh->curSz,
                                          ssh->inputBuffer.buffer +
                                              ssh->inputBuffer.idx +
                                              ssh->curSz + LENGTH_SZ,
                                          ssh->inputBuffer.buffer +
                                              ssh->inputBuffer.idx,
                                          LENGTH_SZ);

                        if (ret != WS_SUCCESS) {
                            WLOG(WS_LOG_DEBUG, "PR: DecryptAead fail");
                            return ret;
                        }
                    }
                }
                ssh->processReplyState = PROCESS_PACKET;
                FALL_THROUGH;

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
        WLOG(WS_LOG_DEBUG, "PR4: Shrinking input buffer");
        ShrinkBuffer(&ssh->inputBuffer, 1);
        ssh->processReplyState = PROCESS_INIT;

        WLOG(WS_LOG_DEBUG, "PR5: txCount = %u, rxCount = %u",
             ssh->txCount, ssh->rxCount);

        return WS_SUCCESS;
    }
}


int DoProtoId(WOLFSSH* ssh)
{
    int ret;
    word32 idSz;
    byte* eol;

    if ( (ret = GetInputText(ssh, &eol)) < 0) {
        WLOG(WS_LOG_DEBUG, "get input text failed");
        return ret;
    }

    if (eol == NULL) {
        WLOG(WS_LOG_DEBUG, "invalid EOL");
        return WS_VERSION_E;
    }

    if (WSTRNCASECMP((char*)ssh->inputBuffer.buffer,
                     sshProtoIdStr, SSH_PROTO_SZ) == 0) {

        if (ssh->ctx->side == WOLFSSH_ENDPOINT_SERVER)
            ssh->clientState = CLIENT_VERSION_DONE;
        else
            ssh->serverState = SERVER_VERSION_DONE;
    }
    else {
        WLOG(WS_LOG_DEBUG, "SSH version mismatch");
        return WS_VERSION_E;
    }
    if (WSTRNCMP((char*)ssh->inputBuffer.buffer,
                 OpenSSH, sizeof(OpenSSH)-1) == 0) {
        ssh->clientOpenSSH = 1;
    }

    *eol = 0;

    idSz = (word32)WSTRLEN((char*)ssh->inputBuffer.buffer);

    /* Store the proto ID for later use. It is used in keying and rekeying. */
    ssh->peerProtoId = (byte*)WMALLOC(idSz + LENGTH_SZ,
                                         ssh->ctx->heap, DYNTYPE_STRING);
    if (ssh->peerProtoId == NULL)
        ret = WS_MEMORY_E;
    else {
        c32toa(idSz, ssh->peerProtoId);
        WMEMCPY(ssh->peerProtoId + LENGTH_SZ, ssh->inputBuffer.buffer, idSz);
        ssh->peerProtoIdSz = idSz + LENGTH_SZ;
    }

    ssh->inputBuffer.idx += idSz + SSH_PROTO_EOL_SZ;
    ShrinkBuffer(&ssh->inputBuffer, 0);

    return ret;
}


int SendProtoId(WOLFSSH* ssh)
{
    int ret = WS_SUCCESS;
    word32 sshProtoIdStrSz;

    if (ssh == NULL)
        ret = WS_BAD_ARGUMENT;

    if (ret == WS_SUCCESS) {
        WLOG(WS_LOG_DEBUG, "%s", sshProtoIdStr);
        sshProtoIdStrSz = (word32)WSTRLEN(sshProtoIdStr);
        ret = GrowBuffer(&ssh->outputBuffer, sshProtoIdStrSz, 0);
    }

    if (ret == WS_SUCCESS) {
        WMEMCPY(ssh->outputBuffer.buffer, sshProtoIdStr, sshProtoIdStrSz);
        ssh->outputBuffer.length = sshProtoIdStrSz;
        ret = SendBuffered(ssh);
    }

    return ret;
}


static int PreparePacket(WOLFSSH* ssh, word32 payloadSz)
{
    int ret = WS_SUCCESS;
    byte* output;
    word32 outputSz;
    word32 packetSz;
    word32 usedSz;
    byte paddingSz;

    if (ssh == NULL)
        ret = WS_BAD_ARGUMENT;

    if (ret == WS_SUCCESS) {
        /* Minimum value for paddingSz is 4. */
        paddingSz = ssh->blockSz -
                    ((ssh->aeadMode ? 0 : LENGTH_SZ) +
                     PAD_LENGTH_SZ + payloadSz) % ssh->blockSz;
        if (paddingSz < MIN_PAD_LENGTH)
            paddingSz += ssh->blockSz;
        ssh->paddingSz = paddingSz;
        packetSz = PAD_LENGTH_SZ + payloadSz + paddingSz;
        outputSz = LENGTH_SZ + packetSz + ssh->macSz;
        usedSz = ssh->outputBuffer.length - ssh->outputBuffer.idx;

        ret = GrowBuffer(&ssh->outputBuffer, outputSz, usedSz);
    }

    if (ret == WS_SUCCESS) {
        ssh->packetStartIdx = ssh->outputBuffer.length;
        output = ssh->outputBuffer.buffer + ssh->outputBuffer.length;

        /* fill in the packetSz, paddingSz */
        c32toa(packetSz, output);
        output[LENGTH_SZ] = paddingSz;

        ssh->outputBuffer.length += LENGTH_SZ + PAD_LENGTH_SZ;
    }

    return ret;
}


static int BundlePacket(WOLFSSH* ssh)
{
    byte* output = NULL;
    word32 idx = 0;
    byte paddingSz = 0;
    int ret = WS_SUCCESS;

    if (ssh == NULL)
        ret = WS_BAD_ARGUMENT;

    if (ret == WS_SUCCESS) {
        output = ssh->outputBuffer.buffer;
        idx = ssh->outputBuffer.length;
        paddingSz = ssh->paddingSz;

        /* Add the padding */
        WLOG(WS_LOG_DEBUG, "BP: paddingSz = %u", paddingSz);
        if (ssh->encryptId == ID_NONE)
            WMEMSET(output + idx, 0, paddingSz);
        else if (wc_RNG_GenerateBlock(ssh->rng, output + idx, paddingSz) < 0)
            ret = WS_CRYPTO_FAILED;
    }

    if (!ssh->aeadMode) {
        if (ret == WS_SUCCESS) {
            idx += paddingSz;
            ret = CreateMac(ssh, ssh->outputBuffer.buffer + ssh->packetStartIdx,
                            ssh->outputBuffer.length -
                                ssh->packetStartIdx + paddingSz,
                            output + idx);
        }
        else {
            WLOG(WS_LOG_DEBUG, "BP: failed to add padding");
        }

        if (ret == WS_SUCCESS) {
            idx += ssh->macSz;
            ret = Encrypt(ssh,
                          ssh->outputBuffer.buffer + ssh->packetStartIdx,
                          ssh->outputBuffer.buffer + ssh->packetStartIdx,
                          ssh->outputBuffer.length -
                              ssh->packetStartIdx + paddingSz);
        }
        else {
            WLOG(WS_LOG_DEBUG, "BP: failed to generate mac");
        }
    }
    else {
        if (ret == WS_SUCCESS) {
            idx += paddingSz;
            ret = EncryptAead(ssh,
                              ssh->outputBuffer.buffer +
                                  ssh->packetStartIdx + LENGTH_SZ,
                              ssh->outputBuffer.buffer +
                                  ssh->packetStartIdx + LENGTH_SZ,
                              ssh->outputBuffer.length -
                                  ssh->packetStartIdx + paddingSz -
                                  LENGTH_SZ,
                              output + idx,
                              ssh->outputBuffer.buffer +
                                  ssh->packetStartIdx,
                              LENGTH_SZ);
            idx += ssh->macSz;
        }
    }

    if (ret == WS_SUCCESS) {
        ssh->seq++;
        ssh->outputBuffer.length = idx;
    }
    else {
        WLOG(WS_LOG_DEBUG, "BP: failed to encrypt buffer");
    }

    return ret;
}


static INLINE void CopyNameList(byte* buf, word32* idx,
                                                const char* src, word32 srcSz)
{
    word32 begin = *idx;

    c32toa(srcSz, buf + begin);
    begin += LENGTH_SZ;
    WMEMCPY(buf + begin, src, srcSz);
    begin += srcSz;

    *idx = begin;
}


static const char cannedEncAlgoNames[] = "aes128-gcm@openssh.com,aes128-cbc";
static const char cannedMacAlgoNames[] = "hmac-sha2-256,hmac-sha1-96,"
                                         "hmac-sha1";
static const char cannedKeyAlgoRsaNames[] = "ssh-rsa";
static const char cannedKeyAlgoEcc256Names[] = "ecdsa-sha2-nistp256";
static const char cannedKeyAlgoEcc384Names[] = "ecdsa-sha2-nistp384";
static const char cannedKeyAlgoEcc521Names[] = "ecdsa-sha2-nistp521";
static const char cannedKexAlgoNames[] = "ecdh-sha2-nistp256,"
                                         "diffie-hellman-group-exchange-sha256,"
                                         "diffie-hellman-group14-sha1,"
                                         "diffie-hellman-group1-sha1";
static const char cannedNoneNames[] = "none";

static const word32 cannedEncAlgoNamesSz = sizeof(cannedEncAlgoNames) - 1;
static const word32 cannedMacAlgoNamesSz = sizeof(cannedMacAlgoNames) - 1;
static const word32 cannedKeyAlgoRsaNamesSz = sizeof(cannedKeyAlgoRsaNames) - 1;
static const word32 cannedKeyAlgoEcc256NamesSz =
                                           sizeof(cannedKeyAlgoEcc256Names) - 1;
static const word32 cannedKeyAlgoEcc384NamesSz =
                                           sizeof(cannedKeyAlgoEcc384Names) - 1;
static const word32 cannedKeyAlgoEcc521NamesSz =
                                           sizeof(cannedKeyAlgoEcc521Names) - 1;
static const word32 cannedKexAlgoNamesSz = sizeof(cannedKexAlgoNames) - 1;
static const word32 cannedNoneNamesSz = sizeof(cannedNoneNames) - 1;


int SendKexInit(WOLFSSH* ssh)
{
    byte* output;
    byte* payload;
    word32 idx = 0;
    word32 payloadSz;
    int ret = WS_SUCCESS;
    const char* cannedKeyAlgoNames;
    word32 cannedKeyAlgoNamesSz;

    WLOG(WS_LOG_DEBUG, "Entering SendKexInit()");

    if (ssh == NULL)
        ret = WS_BAD_ARGUMENT;

    ssh->isKeying = 1;
    if (ssh->handshake == NULL) {
        ssh->handshake = HandshakeInfoNew(ssh->ctx->heap);
        if (ssh->handshake == NULL) {
            WLOG(WS_LOG_DEBUG, "Couldn't allocate handshake info");
            ret = WS_MEMORY_E;
        }
    }

    if (ret == WS_SUCCESS) {
        switch (ssh->ctx->useEcc) {
            case ECC_SECP256R1:
                cannedKeyAlgoNames = cannedKeyAlgoEcc256Names;
                cannedKeyAlgoNamesSz = cannedKeyAlgoEcc256NamesSz;
                break;
            case ECC_SECP384R1:
                cannedKeyAlgoNames = cannedKeyAlgoEcc384Names;
                cannedKeyAlgoNamesSz = cannedKeyAlgoEcc384NamesSz;
                break;
            case ECC_SECP521R1:
                cannedKeyAlgoNames = cannedKeyAlgoEcc521Names;
                cannedKeyAlgoNamesSz = cannedKeyAlgoEcc521NamesSz;
                break;
            default:
                cannedKeyAlgoNames = cannedKeyAlgoRsaNames;
                cannedKeyAlgoNamesSz = cannedKeyAlgoRsaNamesSz;
        }
        payloadSz = MSG_ID_SZ + COOKIE_SZ + (LENGTH_SZ * 11) + BOOLEAN_SZ +
                   cannedKexAlgoNamesSz + cannedKeyAlgoNamesSz +
                   (cannedEncAlgoNamesSz * 2) +
                   (cannedMacAlgoNamesSz * 2) +
                   (cannedNoneNamesSz * 2);
        ret = PreparePacket(ssh, payloadSz);
    }

    if (ret == WS_SUCCESS) {
        output = ssh->outputBuffer.buffer;
        idx = ssh->outputBuffer.length;
        payload = output + idx;

        output[idx++] = MSGID_KEXINIT;

        ret = wc_RNG_GenerateBlock(ssh->rng, output + idx, COOKIE_SZ);
    }

    if (ret == WS_SUCCESS) {
        byte* buf;
        word32 bufSz = payloadSz + LENGTH_SZ;

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

        buf = (byte*)WMALLOC(bufSz, ssh->ctx->heap, DYNTYPE_STRING);
        if (buf == NULL) {
            WLOG(WS_LOG_DEBUG, "Cannot allocate storage for KEX Init msg");
            ret = WS_MEMORY_E;
        }
        else {
            c32toa(payloadSz, buf);
            WMEMCPY(buf + LENGTH_SZ, payload, payloadSz);
            ssh->handshake->kexInit = buf;
            ssh->handshake->kexInitSz = bufSz;
        }
    }

    if (ret == WS_SUCCESS)
        ret = BundlePacket(ssh);

    if (ret == WS_SUCCESS)
        ret = SendBuffered(ssh);

    WLOG(WS_LOG_DEBUG, "Leaving SendKexInit(), ret = %d", ret);
    return ret;
}


/* SendKexDhReply()
 * It is also the funciton used for MSGID_KEXECDH_REPLY. The parameters
 * are analogous between the two messages. Where MSGID_KEXDH_REPLY has
 * server's public host key (K_S), f, and the signature of H;
 * MSGID_KEXECDH_REPLY has K_S, the server'e ephemeral public key (Q_S),
 * and the signature of H. This also applies to the GEX version of this.
 * H is calculated the same for KEXDH and KEXECDH, and has some exceptions
 * for GEXDH. */
int SendKexDhReply(WOLFSSH* ssh)
{
/* This function and DoKexDhReply() are unwieldy and in need of refactoring. */
    const byte* primeGroup = dhPrimeGroup14;
    word32 primeGroupSz = dhPrimeGroup14Sz;
    const byte* generator = dhGenerator;
    word32 generatorSz = dhGeneratorSz;

    byte useEcc = 0;
    byte f[257];
    word32 fSz = sizeof(f);
    byte fPad = 0;
    byte kPad = 0;

    struct {
        byte useRsa;
        word32 sz;
        const char *name;
        word32 nameSz;
        union {
            struct {
                RsaKey key;
                byte e[257];
                word32 eSz;
                byte ePad;
                byte n[257];
                word32 nSz;
                byte nPad;
            } rsa;
            struct {
                ecc_key key;
                word32 keyBlobSz;
                const char *keyBlobName;
                word32 keyBlobNameSz;
                byte q[257];
                word32 qSz;
                byte qPad;
                const char *primeName;
                word32 primeNameSz;
            } ecc;
        } sk;
    } sigKeyBlock;

    byte sig[512];
    word32 sigSz = sizeof(sig);
    word32 sigBlockSz;

    word32 payloadSz;
    byte scratchLen[LENGTH_SZ];
    word32 scratch = 0;
    byte* output;
    word32 idx;
    int ret = WS_SUCCESS;
    byte msgId = MSGID_KEXDH_REPLY;

    WLOG(WS_LOG_DEBUG, "Entering SendKexDhReply()");

    sigKeyBlock.useRsa = ssh->handshake->pubKeyId == ID_SSH_RSA;
    sigKeyBlock.name = IdToName(ssh->handshake->pubKeyId);
    sigKeyBlock.nameSz = (word32)strlen(sigKeyBlock.name);

    switch (ssh->handshake->kexId) {
        case ID_DH_GROUP1_SHA1:
            primeGroup = dhPrimeGroup1;
            primeGroupSz = dhPrimeGroup1Sz;
            break;

        case ID_DH_GROUP14_SHA1:
            /* This is the default case. */
            break;

        case ID_DH_GEX_SHA256:
            msgId = MSGID_KEXDH_GEX_REPLY;
            break;

        case ID_ECDH_SHA2_NISTP256:
        case ID_ECDH_SHA2_NISTP384:
        case ID_ECDH_SHA2_NISTP521:
            useEcc = 1;
            msgId = MSGID_KEXDH_REPLY;
            break;

        default:
            ret = WS_INVALID_ALGO_ID;
    }

    /* At this point, the exchange hash, H, includes items V_C, V_S, I_C,
     * and I_S. Next add K_S, the server's public host key. K_S will
     * either be RSA or ECDSA public key blob. */
    if (ret == WS_SUCCESS) {
        if (sigKeyBlock.useRsa) {
            /* Decode the user-configured RSA private key. */
            sigKeyBlock.sk.rsa.eSz = sizeof(sigKeyBlock.sk.rsa.e);
            sigKeyBlock.sk.rsa.nSz = sizeof(sigKeyBlock.sk.rsa.n);
            ret = wc_InitRsaKey(&sigKeyBlock.sk.rsa.key, ssh->ctx->heap);
            if (ret == 0)
                ret = wc_RsaPrivateKeyDecode(ssh->ctx->privateKey, &scratch,
                                             &sigKeyBlock.sk.rsa.key,
                                             (int)ssh->ctx->privateKeySz);
            /* Flatten the public key into mpint values for the hash. */
            if (ret == 0)
                ret = wc_RsaFlattenPublicKey(&sigKeyBlock.sk.rsa.key,
                                             sigKeyBlock.sk.rsa.e,
                                             &sigKeyBlock.sk.rsa.eSz,
                                             sigKeyBlock.sk.rsa.n,
                                             &sigKeyBlock.sk.rsa.nSz);
            if (ret == 0) {
                /* Add a pad byte if the mpint has the MSB set. */
                sigKeyBlock.sk.rsa.ePad = (sigKeyBlock.sk.rsa.e[0] & 0x80) ?
                                           1 : 0;
                sigKeyBlock.sk.rsa.nPad = (sigKeyBlock.sk.rsa.n[0] & 0x80) ?
                                           1 : 0;
                sigKeyBlock.sz = (LENGTH_SZ * 3) + sigKeyBlock.nameSz +
                                  sigKeyBlock.sk.rsa.eSz +
                                  sigKeyBlock.sk.rsa.ePad +
                                  sigKeyBlock.sk.rsa.nSz +
                                  sigKeyBlock.sk.rsa.nPad;
                c32toa(sigKeyBlock.sz, scratchLen);
                /* Hash in the length of the public key block. */
                ret = wc_HashUpdate(&ssh->handshake->hash,
                                    ssh->handshake->hashId,
                                    scratchLen, LENGTH_SZ);
            }
            /* Hash in the length of the key type string. */
            if (ret == 0) {
                c32toa(sigKeyBlock.nameSz, scratchLen);
                ret = wc_HashUpdate(&ssh->handshake->hash,
                                    ssh->handshake->hashId,
                                    scratchLen, LENGTH_SZ);
            }
            /* Hash in the key type string. */
            if (ret == 0)
                ret = wc_HashUpdate(&ssh->handshake->hash,
                                    ssh->handshake->hashId,
                                    (byte*)sigKeyBlock.name,
                                    sigKeyBlock.nameSz);
            /* Hash in the length of the RSA public key E value. */
            if (ret == 0) {
                c32toa(sigKeyBlock.sk.rsa.eSz + sigKeyBlock.sk.rsa.ePad,
                       scratchLen);
                ret = wc_HashUpdate(&ssh->handshake->hash,
                                    ssh->handshake->hashId,
                                    scratchLen, LENGTH_SZ);
            }
            /* Hash in the pad byte for the RSA public key E value. */
            if (ret == 0) {
                if (sigKeyBlock.sk.rsa.ePad) {
                    scratchLen[0] = 0;
                    ret = wc_HashUpdate(&ssh->handshake->hash,
                                        ssh->handshake->hashId, scratchLen, 1);
                }
            }
            /* Hash in the RSA public key E value. */
            if (ret == 0)
                ret = wc_HashUpdate(&ssh->handshake->hash,
                                    ssh->handshake->hashId,
                                    sigKeyBlock.sk.rsa.e,
                                    sigKeyBlock.sk.rsa.eSz);
            /* Hash in the length of the RSA public key N value. */
            if (ret == 0) {
                c32toa(sigKeyBlock.sk.rsa.nSz + sigKeyBlock.sk.rsa.nPad,
                       scratchLen);
                ret = wc_HashUpdate(&ssh->handshake->hash,
                                    ssh->handshake->hashId,
                                    scratchLen, LENGTH_SZ);
            }
            /* Hash in the pad byte for the RSA public key N value. */
            if (ret == 0) {
                if (sigKeyBlock.sk.rsa.nPad) {
                    scratchLen[0] = 0;
                    ret = wc_HashUpdate(&ssh->handshake->hash,
                                        ssh->handshake->hashId, scratchLen, 1);
                }
            }
            /* Hash in the RSA public key N value. */
            if (ret == 0)
                ret = wc_HashUpdate(&ssh->handshake->hash,
                                    ssh->handshake->hashId,
                                    sigKeyBlock.sk.rsa.n,
                                    sigKeyBlock.sk.rsa.nSz);
        }
        else {
            sigKeyBlock.sk.ecc.primeName =
                                       PrimeNameForId(ssh->handshake->pubKeyId);
            sigKeyBlock.sk.ecc.primeNameSz =
                                 (word32)strlen(sigKeyBlock.sk.ecc.primeName);

            /* Decode the user-configured ECDSA private key. */
            sigKeyBlock.sk.ecc.qSz = sizeof(sigKeyBlock.sk.ecc.q);
            ret = wc_ecc_init_ex(&sigKeyBlock.sk.ecc.key, ssh->ctx->heap,
                                 INVALID_DEVID);
            scratch = 0;
            if (ret == 0)
                ret = wc_EccPrivateKeyDecode(ssh->ctx->privateKey, &scratch,
                                             &sigKeyBlock.sk.ecc.key,
                                             ssh->ctx->privateKeySz);
            /* Flatten the public key into x963 value for the exchange hash. */
            if (ret == 0)
                ret = wc_ecc_export_x963(&sigKeyBlock.sk.ecc.key,
                                         sigKeyBlock.sk.ecc.q,
                                         &sigKeyBlock.sk.ecc.qSz);
            /* Hash in the length of the public key block. */
            if (ret == 0) {
                sigKeyBlock.sz = (LENGTH_SZ * 3) +
                                 sigKeyBlock.nameSz +
                                 sigKeyBlock.sk.ecc.primeNameSz +
                                 sigKeyBlock.sk.ecc.qSz;
                c32toa(sigKeyBlock.sz, scratchLen);
                ret = wc_HashUpdate(&ssh->handshake->hash,
                                    ssh->handshake->hashId,
                                    scratchLen, LENGTH_SZ);
            }
            /* Hash in the length of the key type string. */
            if (ret == 0) {
                c32toa(sigKeyBlock.nameSz, scratchLen);
                ret = wc_HashUpdate(&ssh->handshake->hash,
                                    ssh->handshake->hashId,
                                    scratchLen, LENGTH_SZ);
            }
            /* Hash in the key type string. */
            if (ret == 0)
                ret = wc_HashUpdate(&ssh->handshake->hash,
                                    ssh->handshake->hashId,
                                    (byte*)sigKeyBlock.name,
                                    sigKeyBlock.nameSz);
            /* Hash in the length of the name of the prime. */
            if (ret == 0) {
                c32toa(sigKeyBlock.sk.ecc.primeNameSz, scratchLen);
                ret = wc_HashUpdate(&ssh->handshake->hash,
                                    ssh->handshake->hashId,
                                    scratchLen, LENGTH_SZ);
            }
            /* Hash in the name of the prime. */
            if (ret == 0)
                ret = wc_HashUpdate(&ssh->handshake->hash,
                                   ssh->handshake->hashId,
                                   (const byte*)sigKeyBlock.sk.ecc.primeName,
                                   sigKeyBlock.sk.ecc.primeNameSz);
            /* Hash in the length of the public key. */
            if (ret == 0) {
                c32toa(sigKeyBlock.sk.ecc.qSz, scratchLen);
                ret = wc_HashUpdate(&ssh->handshake->hash,
                                    ssh->handshake->hashId,
                                    scratchLen, LENGTH_SZ);
            }
            /* Hash in the public key. */
            if (ret == 0)
                ret = wc_HashUpdate(&ssh->handshake->hash,
                                    ssh->handshake->hashId,
                                    sigKeyBlock.sk.ecc.q,
                                    sigKeyBlock.sk.ecc.qSz);
        }

        /* If using DH-GEX include the GEX specific values. */
        if (ssh->handshake->kexId == ID_DH_GEX_SHA256) {
            byte primeGroupPad = 0, generatorPad = 0;

            /* Hash in the client's requested minimum key size. */
            if (ret == 0) {
                c32toa(ssh->handshake->dhGexMinSz, scratchLen);
                ret = wc_HashUpdate(&ssh->handshake->hash,
                                    ssh->handshake->hashId,
                                    scratchLen, LENGTH_SZ);
            }
            /* Hash in the client's requested preferred key size. */
            if (ret == 0) {
                c32toa(ssh->handshake->dhGexPreferredSz, scratchLen);
                ret = wc_HashUpdate(&ssh->handshake->hash,
                                    ssh->handshake->hashId,
                                    scratchLen, LENGTH_SZ);
            }
            /* Hash in the client's requested maximum key size. */
            if (ret == 0) {
                c32toa(ssh->handshake->dhGexMaxSz, scratchLen);
                ret = wc_HashUpdate(&ssh->handshake->hash,
                                    ssh->handshake->hashId,
                                    scratchLen, LENGTH_SZ);
            }
            /* Add a pad byte if the mpint has the MSB set. */
            if (ret == 0) {
                if (primeGroup[0] & 0x80)
                    primeGroupPad = 1;

                /* Hash in the length of the GEX prime group. */
                c32toa(primeGroupSz + primeGroupPad, scratchLen);
                ret = wc_HashUpdate(&ssh->handshake->hash,
                                    ssh->handshake->hashId,
                                    scratchLen, LENGTH_SZ);
            }
            /* Hash in the pad byte for the GEX prime group. */
            if (ret == 0) {
                if (primeGroupPad) {
                    scratchLen[0] = 0;
                    ret = wc_HashUpdate(&ssh->handshake->hash,
                                        ssh->handshake->hashId,
                                        scratchLen, 1);
                }
            }
            /* Hash in the GEX prime group. */
            if (ret == 0)
                ret  = wc_HashUpdate(&ssh->handshake->hash,
                                     ssh->handshake->hashId,
                                     primeGroup, primeGroupSz);
            /* Add a pad byte if the mpint has the MSB set. */
            if (ret == 0) {
                if (generator[0] & 0x80)
                    generatorPad = 1;

                /* Hash in the length of the GEX generator. */
                c32toa(generatorSz + generatorPad, scratchLen);
                ret = wc_HashUpdate(&ssh->handshake->hash,
                                    ssh->handshake->hashId,
                                    scratchLen, LENGTH_SZ);
            }
            /* Hash in the pad byte for the GEX generator. */
            if (ret == 0) {
                if (generatorPad) {
                    scratchLen[0] = 0;
                    ret = wc_HashUpdate(&ssh->handshake->hash,
                                        ssh->handshake->hashId,
                                        scratchLen, 1);
                }
            }
            /* Hash in the GEX generator. */
            if (ret == 0)
                ret = wc_HashUpdate(&ssh->handshake->hash,
                                    ssh->handshake->hashId,
                                    generator, generatorSz);
        }

        /* Hash in the size of the client's DH e-value (ECDH Q-value). */
        if (ret == 0) {
            c32toa(ssh->handshake->eSz, scratchLen);
            ret = wc_HashUpdate(&ssh->handshake->hash, ssh->handshake->hashId,
                                scratchLen, LENGTH_SZ);
        }
        /* Hash in the client's DH e-value (ECDH Q-value). */
        if (ret == 0)
            ret = wc_HashUpdate(&ssh->handshake->hash, ssh->handshake->hashId,
                                ssh->handshake->e, ssh->handshake->eSz);

        /* Make the server's DH f-value and the shared secret K. */
        /* Or make the server's ECDH private value, and the shared secret K. */
        if (ret == 0) {
            if (!useEcc) {
                DhKey privKey;
                byte y[256];
                word32 ySz = sizeof(y);

                ret = wc_InitDhKey(&privKey);
                if (ret == 0)
                    ret = wc_DhSetKey(&privKey, primeGroup, primeGroupSz,
                                      generator, generatorSz);
                if (ret == 0)
                    ret = wc_DhGenerateKeyPair(&privKey, ssh->rng,
                                               y, &ySz, f, &fSz);
                if (ret == 0)
                    ret = wc_DhAgree(&privKey, ssh->k, &ssh->kSz, y, ySz,
                                     ssh->handshake->e, ssh->handshake->eSz);
                ForceZero(y, ySz);
                wc_FreeDhKey(&privKey);
            }
            else {
                ecc_key pubKey;
                ecc_key privKey;
                int primeId = wcPrimeForId(ssh->handshake->kexId);

                if (primeId == ECC_CURVE_INVALID)
                    ret = WS_INVALID_PRIME_CURVE;

                if (ret == 0)
                    ret = wc_ecc_init_ex(&pubKey, ssh->ctx->heap,
                                         INVALID_DEVID);
                if (ret == 0)
                    ret = wc_ecc_init_ex(&privKey, ssh->ctx->heap,
                                         INVALID_DEVID);

                if (ret == 0)
                    ret = wc_ecc_import_x963_ex(ssh->handshake->e,
                                                ssh->handshake->eSz,
                                                &pubKey, primeId);

                if (ret == 0)
                    ret = wc_ecc_make_key_ex(ssh->rng,
                                         wc_ecc_get_curve_size_from_id(primeId),
                                         &privKey, primeId);
                if (ret == 0)
                    ret = wc_ecc_export_x963(&privKey, f, &fSz);
                if (ret == 0)
                    ret = wc_ecc_shared_secret(&privKey, &pubKey,
                                               ssh->k, &ssh->kSz);
                wc_ecc_free(&privKey);
                wc_ecc_free(&pubKey);
            }
        }

        /* Hash in the server's DH f-value. */
        if (ret == 0) {
            fPad = (f[0] & 0x80) ? 1 : 0;
            c32toa(fSz + fPad, scratchLen);
            ret = wc_HashUpdate(&ssh->handshake->hash, ssh->handshake->hashId,
                               scratchLen, LENGTH_SZ);
        }
        if (ret == 0) {
            if (fPad) {
                scratchLen[0] = 0;
                ret = wc_HashUpdate(&ssh->handshake->hash,
                                    ssh->handshake->hashId, scratchLen, 1);
            }
        }
        if (ret == 0)
            ret = wc_HashUpdate(&ssh->handshake->hash,
                                ssh->handshake->hashId, f, fSz);

        /* Hash in the shared secret K. */
        if (ret == 0) {
            kPad = (ssh->k[0] & 0x80) ? 1 : 0;
            c32toa(ssh->kSz + kPad, scratchLen);
            ret = wc_HashUpdate(&ssh->handshake->hash, ssh->handshake->hashId,
                                scratchLen, LENGTH_SZ);
        }
        if (ret == 0) {
            if (kPad) {
                scratchLen[0] = 0;
                ret = wc_HashUpdate(&ssh->handshake->hash,
                                    ssh->handshake->hashId, scratchLen, 1);
            }
        }
        if (ret == 0)
            ret = wc_HashUpdate(&ssh->handshake->hash, ssh->handshake->hashId,
                                ssh->k, ssh->kSz);

        /* Save the exchange hash value H, and session ID. */
        if (ret == 0)
            ret = wc_HashFinal(&ssh->handshake->hash,
                               ssh->handshake->hashId, ssh->h);
        if (ret == 0) {
            ssh->hSz = wc_HashGetDigestSize(ssh->handshake->hashId);
            if (ssh->sessionIdSz == 0) {
                WMEMCPY(ssh->sessionId, ssh->h, ssh->hSz);
                ssh->sessionIdSz = ssh->hSz;
            }
        }

        if (ret != WS_SUCCESS)
            ret = WS_CRYPTO_FAILED;
    }

    /* Sign h with the server's private key. */
    if (ret == WS_SUCCESS) {
        wc_HashAlg digestHash;
        byte digest[WC_MAX_DIGEST_SIZE];
        byte sigHashId;

        sigHashId = HashForId(ssh->handshake->pubKeyId);

        ret = wc_HashInit(&digestHash, sigHashId);
        if (ret == 0)
            ret = wc_HashUpdate(&digestHash, sigHashId, ssh->h, ssh->hSz);
        if (ret == 0)
            ret = wc_HashFinal(&digestHash, sigHashId, digest);
        if (ret != 0)
            ret = WS_CRYPTO_FAILED;

        if (ret == WS_SUCCESS) {
            if (sigKeyBlock.useRsa) {
                byte encSig[MAX_ENCODED_SIG_SZ];
                word32 encSigSz;

                encSigSz = wc_EncodeSignature(encSig, digest,
                                              wc_HashGetDigestSize(sigHashId),
                                              wc_HashGetOID(sigHashId));
                if (encSigSz <= 0) {
                    WLOG(WS_LOG_DEBUG, "SendKexDhReply: Bad Encode Sig");
                    ret = WS_CRYPTO_FAILED;
                }
                else {
                    WLOG(WS_LOG_INFO, "Signing hash with RSA.");
                    sigSz = wc_RsaSSL_Sign(encSig, encSigSz, sig, sizeof(sig),
                                           &sigKeyBlock.sk.rsa.key, ssh->rng);
                    if (sigSz <= 0) {
                        WLOG(WS_LOG_DEBUG, "SendKexDhReply: Bad RSA Sign");
                        ret = WS_RSA_E;
                    }
                }
            }
            else {
                WLOG(WS_LOG_INFO, "Signing hash with ECDSA.");
                sigSz = sizeof(sig);
                ret = wc_ecc_sign_hash(digest, wc_HashGetDigestSize(sigHashId),
                                       sig, &sigSz,
                                       ssh->rng, &sigKeyBlock.sk.ecc.key);
                if (ret != MP_OKAY) {
                    WLOG(WS_LOG_DEBUG, "SendKexDhReply: Bad ECDSA Sign");
                    ret = WS_ECC_E;
                }
                else {
                    byte r[257];
                    word32 rSz = sizeof(r);
                    byte rPad;
                    byte s[257];
                    word32 sSz = sizeof(s);
                    byte sPad;

                    ret = wc_ecc_sig_to_rs(sig, sigSz, r, &rSz, s, &sSz);
                    if (ret == 0) {
                        idx = 0;
                        rPad = (r[0] & 0x80) ? 1 : 0;
                        sPad = (s[0] & 0x80) ? 1 : 0;
                        sigSz = (LENGTH_SZ * 2) + rSz + rPad + sSz + sPad;

                        c32toa(rSz + rPad, sig + idx);
                        idx += LENGTH_SZ;
                        if (rPad)
                            sig[idx++] = 0;
                        WMEMCPY(sig + idx, r, rSz);
                        idx += rSz;
                        c32toa(sSz + sPad, sig + idx);
                        idx += LENGTH_SZ;
                        if (sPad)
                            sig[idx++] = 0;
                        WMEMCPY(sig + idx, s, sSz);
                    }
                }
            }
        }
    }

    if (sigKeyBlock.useRsa)
        wc_FreeRsaKey(&sigKeyBlock.sk.rsa.key);
    else
        wc_ecc_free(&sigKeyBlock.sk.ecc.key);

    sigBlockSz = (LENGTH_SZ * 2) + sigKeyBlock.nameSz + sigSz;

    if (ret == WS_SUCCESS)
        ret = GenerateKeys(ssh);

    /* Get the buffer, copy the packet data, once f is laid into the buffer,
     * add it to the hash and then add K. */
    if (ret == WS_SUCCESS) {
        payloadSz = MSG_ID_SZ + (LENGTH_SZ * 3) +
                    sigKeyBlock.sz + fSz + fPad + sigBlockSz;
        ret = PreparePacket(ssh, payloadSz);
    }

    if (ret == WS_SUCCESS) {
        output = ssh->outputBuffer.buffer;
        idx = ssh->outputBuffer.length;

        output[idx++] = msgId;

        /* Copy the rsaKeyBlock into the buffer. */
        c32toa(sigKeyBlock.sz, output + idx);
        idx += LENGTH_SZ;
        c32toa(sigKeyBlock.nameSz, output + idx);
        idx += LENGTH_SZ;
        WMEMCPY(output + idx, sigKeyBlock.name, sigKeyBlock.nameSz);
        idx += sigKeyBlock.nameSz;
        if (sigKeyBlock.useRsa) {
            c32toa(sigKeyBlock.sk.rsa.eSz + sigKeyBlock.sk.rsa.ePad,
                   output + idx);
            idx += LENGTH_SZ;
            if (sigKeyBlock.sk.rsa.ePad) output[idx++] = 0;
            WMEMCPY(output + idx, sigKeyBlock.sk.rsa.e, sigKeyBlock.sk.rsa.eSz);
            idx += sigKeyBlock.sk.rsa.eSz;
            c32toa(sigKeyBlock.sk.rsa.nSz + sigKeyBlock.sk.rsa.nPad,
                   output + idx);
            idx += LENGTH_SZ;
            if (sigKeyBlock.sk.rsa.nPad) output[idx++] = 0;
            WMEMCPY(output + idx, sigKeyBlock.sk.rsa.n, sigKeyBlock.sk.rsa.nSz);
            idx += sigKeyBlock.sk.rsa.nSz;
        }
        else {
            c32toa(sigKeyBlock.sk.ecc.primeNameSz, output + idx);
            idx += LENGTH_SZ;
            WMEMCPY(output + idx, sigKeyBlock.sk.ecc.primeName,
                    sigKeyBlock.sk.ecc.primeNameSz);
            idx += sigKeyBlock.sk.ecc.primeNameSz;
            c32toa(sigKeyBlock.sk.ecc.qSz, output + idx);
            idx += LENGTH_SZ;
            WMEMCPY(output + idx, sigKeyBlock.sk.ecc.q,
                    sigKeyBlock.sk.ecc.qSz);
            idx += sigKeyBlock.sk.ecc.qSz;
        }

        /* Copy the server's public key. F for DE, or Q_S for ECDH. */
        c32toa(fSz + fPad, output + idx);
        idx += LENGTH_SZ;
        if (fPad) output[idx++] = 0;
        WMEMCPY(output + idx, f, fSz);
        idx += fSz;

        /* Copy the signature of the exchange hash. */
        c32toa(sigBlockSz, output + idx);
        idx += LENGTH_SZ;
        c32toa(sigKeyBlock.nameSz, output + idx);
        idx += LENGTH_SZ;
        WMEMCPY(output + idx, sigKeyBlock.name, sigKeyBlock.nameSz);
        idx += sigKeyBlock.nameSz;
        c32toa(sigSz, output + idx);
        idx += LENGTH_SZ;
        WMEMCPY(output + idx, sig, sigSz);
        idx += sigSz;

        ssh->outputBuffer.length = idx;

        ret = BundlePacket(ssh);
    }

    if (ret == WS_SUCCESS)
        ret = SendNewKeys(ssh);

    WLOG(WS_LOG_DEBUG, "Leaving SendKexDhReply(), ret = %d", ret);
    return ret;
}


int SendNewKeys(WOLFSSH* ssh)
{
    byte* output;
    word32 idx = 0;
    int ret = WS_SUCCESS;

    WLOG(WS_LOG_DEBUG, "Entering SendNewKeys()");
    if (ssh == NULL)
        ret = WS_BAD_ARGUMENT;

    if (ret == WS_SUCCESS)
        ret = PreparePacket(ssh, MSG_ID_SZ);

    if (ret == WS_SUCCESS) {
        output = ssh->outputBuffer.buffer;
        idx = ssh->outputBuffer.length;

        output[idx++] = MSGID_NEWKEYS;

        ssh->outputBuffer.length = idx;

        ret = BundlePacket(ssh);
    }

    if (ret == WS_SUCCESS)
        ret = SendBuffered(ssh);

    if (ret == WS_SUCCESS) {
        ssh->blockSz = ssh->handshake->blockSz;
        ssh->encryptId = ssh->handshake->encryptId;
        ssh->macSz = ssh->handshake->macSz;
        ssh->macId = ssh->handshake->macId;
        ssh->aeadMode = ssh->handshake->aeadMode;
        WMEMCPY(&ssh->keys, &ssh->handshake->keys, sizeof(Keys));

        switch (ssh->encryptId) {
            case ID_NONE:
                WLOG(WS_LOG_DEBUG, "SNK: using cipher none");
                break;

            case ID_AES128_CBC:
                WLOG(WS_LOG_DEBUG, "SNK: using cipher aes128-cbc");
                ret = wc_AesSetKey(&ssh->encryptCipher.aes,
                                  ssh->keys.encKey, ssh->keys.encKeySz,
                                  ssh->keys.iv, AES_ENCRYPTION);
                break;

            case ID_AES128_GCM:
                WLOG(WS_LOG_DEBUG, "SNK: using cipher aes128-gcm");
                ret = wc_AesGcmSetKey(&ssh->encryptCipher.aes,
                                     ssh->keys.encKey, ssh->keys.encKeySz);
                break;

            default:
                WLOG(WS_LOG_DEBUG, "SNK: using cipher invalid");
                ret = WS_INVALID_ALGO_ID;
        }
    }

    if (ret == WS_SUCCESS) {
        ssh->txCount = 0;
    }

    WLOG(WS_LOG_DEBUG, "Leaving SendNewKeys(), ret = %d", ret);
    return ret;
}


int SendKexDhGexRequest(WOLFSSH* ssh)
{
    byte* output;
    word32 idx = 0;
    word32 payloadSz;
    int ret = WS_SUCCESS;

    WLOG(WS_LOG_DEBUG, "Entering SendKexDhGexRequest()");
    if (ssh == NULL)
        ret = WS_BAD_ARGUMENT;

    if (ret == WS_SUCCESS) {
        payloadSz = MSG_ID_SZ + (UINT32_SZ * 3);
        ret = PreparePacket(ssh, payloadSz);
    }

    if (ret == WS_SUCCESS) {
        output = ssh->outputBuffer.buffer;
        idx = ssh->outputBuffer.length;

        output[idx++] = MSGID_KEXDH_GEX_REQUEST;

        c32toa(ssh->handshake->dhGexMinSz, output + idx);
        idx += UINT32_SZ;
        c32toa(ssh->handshake->dhGexPreferredSz, output + idx);
        idx += UINT32_SZ;
        c32toa(ssh->handshake->dhGexMaxSz, output + idx);
        idx += UINT32_SZ;

        ssh->outputBuffer.length = idx;

        ret = BundlePacket(ssh);
    }

    if (ret == WS_SUCCESS)
        ret = SendBuffered(ssh);

    WLOG(WS_LOG_DEBUG, "Leaving SendKexDhGexRequest(), ret = %d", ret);
    return ret;
}


int SendKexDhGexGroup(WOLFSSH* ssh)
{
    byte* output;
    word32 idx = 0;
    word32 payloadSz;
    const byte* primeGroup = dhPrimeGroup14;
    word32 primeGroupSz = dhPrimeGroup14Sz;
    const byte* generator = dhGenerator;
    word32 generatorSz = dhGeneratorSz;
    byte primePad = 0;
    byte generatorPad = 0;
    int ret = WS_SUCCESS;

    WLOG(WS_LOG_DEBUG, "Entering SendKexDhGexGroup()");
    if (ssh == NULL)
        ret = WS_BAD_ARGUMENT;

    if (primeGroup[0] & 0x80)
        primePad = 1;

    if (generator[0] & 0x80)
        generatorPad = 1;

    if (ret == WS_SUCCESS) {
        payloadSz = MSG_ID_SZ + (LENGTH_SZ * 2) +
                    primeGroupSz + primePad +
                    generatorSz + generatorPad;
        ret = PreparePacket(ssh, payloadSz);
    }

    if (ret == WS_SUCCESS) {
        output = ssh->outputBuffer.buffer;
        idx = ssh->outputBuffer.length;

        output[idx++] = MSGID_KEXDH_GEX_GROUP;

        c32toa(primeGroupSz + primePad, output + idx);
        idx += LENGTH_SZ;

        if (primePad) {
            output[idx] = 0;
            idx += 1;
        }

        WMEMCPY(output + idx, primeGroup, primeGroupSz);
        idx += primeGroupSz;

        c32toa(generatorSz + generatorPad, output + idx);
        idx += LENGTH_SZ;

        if (generatorPad) {
            output[idx] = 0;
            idx += 1;
        }

        WMEMCPY(output + idx, generator, generatorSz);
        idx += generatorSz;

        ssh->outputBuffer.length = idx;

        ret = BundlePacket(ssh);
    }

    if (ret == WS_SUCCESS)
        ret = SendBuffered(ssh);

    WLOG(WS_LOG_DEBUG, "Leaving SendKexDhGexGroup(), ret = %d", ret);
    return ret;
}


int SendKexDhInit(WOLFSSH* ssh)
{
    byte* output;
    word32 idx = 0;
    word32 payloadSz;
    const byte* primeGroup = dhPrimeGroup14;
    word32 primeGroupSz = dhPrimeGroup14Sz;
    const byte* generator = dhGenerator;
    word32 generatorSz = dhGeneratorSz;
    int ret = WS_SUCCESS;
    byte msgId = MSGID_KEXDH_INIT;
    byte e[256];
    word32 eSz = sizeof(e);
    byte  ePad = 0;

    WLOG(WS_LOG_DEBUG, "Entering SendKexDhInit()");

    switch (ssh->handshake->kexId) {
        case ID_DH_GROUP1_SHA1:
            primeGroup = dhPrimeGroup1;
            primeGroupSz = dhPrimeGroup1Sz;
            break;

        case ID_DH_GROUP14_SHA1:
            /* This is the default case. */
            break;

        case ID_DH_GEX_SHA256:
            primeGroup = ssh->handshake->primeGroup;
            primeGroupSz = ssh->handshake->primeGroupSz;
            generator = ssh->handshake->generator;
            generatorSz = ssh->handshake->generatorSz;
            msgId = MSGID_KEXDH_GEX_INIT;
            break;

        case ID_ECDH_SHA2_NISTP256:
        case ID_ECDH_SHA2_NISTP384:
        case ID_ECDH_SHA2_NISTP521:
            ssh->handshake->useEcc = 1;
            msgId = MSGID_KEXECDH_INIT;
            break;

        default:
            WLOG(WS_LOG_DEBUG, "Invalid algo: %u", ssh->handshake->kexId);
            ret = WS_INVALID_ALGO_ID;
    }


    if (ret == WS_SUCCESS) {
        if (!ssh->handshake->useEcc) {
            DhKey* privKey = &ssh->handshake->privKey.dh;

            ret = wc_InitDhKey(privKey);
            if (ret == 0)
                ret = wc_DhSetKey(privKey, primeGroup, primeGroupSz,
                                  generator, generatorSz);
            if (ret == 0)
                ret = wc_DhGenerateKeyPair(privKey, ssh->rng,
                                           ssh->handshake->x,
                                           &ssh->handshake->xSz,
                                           e, &eSz);
        }
        else {
            ecc_key* privKey = &ssh->handshake->privKey.ecc;
            int primeId = wcPrimeForId(ssh->handshake->kexId);

            if (primeId == ECC_CURVE_INVALID)
                ret = WS_INVALID_PRIME_CURVE;

            if (ret == 0)
                ret = wc_ecc_init_ex(privKey, ssh->ctx->heap,
                                     INVALID_DEVID);

            if (ret == 0)
                ret = wc_ecc_make_key_ex(ssh->rng,
                                     wc_ecc_get_curve_size_from_id(primeId),
                                     privKey, primeId);
            if (ret == 0)
                ret = wc_ecc_export_x963(privKey, e, &eSz);
        }

        if (ret == 0)
            ret = WS_SUCCESS;
    }

    if (ret == WS_SUCCESS) {
        if (e[0] & 0x80)  {
            ePad = 1;
            ssh->handshake->e[0] = 0;
        }
        WMEMCPY(ssh->handshake->e + ePad, e, eSz);
        ssh->handshake->eSz = eSz + ePad;

        payloadSz = MSG_ID_SZ + LENGTH_SZ + eSz + ePad;
        ret = PreparePacket(ssh, payloadSz);
    }

    if (ret == WS_SUCCESS) {
        output = ssh->outputBuffer.buffer;
        idx = ssh->outputBuffer.length;

        output[idx++] = msgId;

        c32toa(eSz + ePad, output + idx);
        idx += LENGTH_SZ;

        if (ePad) {
            output[idx] = 0;
            idx += 1;
        }

        WMEMCPY(output + idx, e, eSz);
        idx += eSz;

        ssh->outputBuffer.length = idx;

        ret = BundlePacket(ssh);
    }

    if (ret == WS_SUCCESS)
        ret = SendBuffered(ssh);

    WLOG(WS_LOG_DEBUG, "Leaving SendKexDhInit(), ret = %d", ret);
    return ret;
}


int SendUnimplemented(WOLFSSH* ssh)
{
    byte* output;
    word32 idx = 0;
    int ret = WS_SUCCESS;

    WLOG(WS_LOG_DEBUG,
         "Entering SendUnimplemented(), peerSeq = %u", ssh->peerSeq);

    if (ssh == NULL)
        ret = WS_BAD_ARGUMENT;

    if (ret == WS_SUCCESS)
        ret = PreparePacket(ssh, MSG_ID_SZ + LENGTH_SZ);

    if (ret == WS_SUCCESS) {
        output = ssh->outputBuffer.buffer;
        idx = ssh->outputBuffer.length;

        output[idx++] = MSGID_UNIMPLEMENTED;
        c32toa(ssh->peerSeq, output + idx);
        idx += UINT32_SZ;

        ssh->outputBuffer.length = idx;

        ret = BundlePacket(ssh);
    }

    if (ret == WS_SUCCESS)
        ret = SendBuffered(ssh);

    WLOG(WS_LOG_DEBUG, "Leaving SendUnimplemented(), ret = %d", ret);
    return ret;
}


int SendDisconnect(WOLFSSH* ssh, word32 reason)
{
    byte* output;
    word32 idx = 0;
    int ret = WS_SUCCESS;

    if (ssh == NULL)
        ret = WS_BAD_ARGUMENT;

    if (ret == WS_SUCCESS)
        ret = PreparePacket(ssh, MSG_ID_SZ + UINT32_SZ + (LENGTH_SZ * 2));

    if (ret == WS_SUCCESS) {
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

        ret = BundlePacket(ssh);
    }

    if (ret == WS_SUCCESS)
        ret = SendBuffered(ssh);

    return ret;
}


int SendIgnore(WOLFSSH* ssh, const unsigned char* data, word32 dataSz)
{
    byte* output;
    word32 idx = 0;
    int ret = WS_SUCCESS;

    if (ssh == NULL || (data == NULL && dataSz > 0))
        ret = WS_BAD_ARGUMENT;

    if (ret == WS_SUCCESS)
        ret = PreparePacket(ssh, MSG_ID_SZ + LENGTH_SZ + dataSz);

    if (ret == WS_SUCCESS) {
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

        ret = BundlePacket(ssh);
    }

    if (ret == WS_SUCCESS)
        ret = SendBuffered(ssh);

    return ret;
}


static const char cannedLangTag[] = "en-us";
static const word32 cannedLangTagSz = sizeof(cannedLangTag) - 1;


int SendDebug(WOLFSSH* ssh, byte alwaysDisplay, const char* msg)
{
    word32 msgSz;
    byte* output;
    word32 idx = 0;
    int ret = WS_SUCCESS;

    if (ssh == NULL)
        ret = WS_BAD_ARGUMENT;

    if (ret == WS_SUCCESS) {
        msgSz = (msg != NULL) ? (word32)WSTRLEN(msg) : 0;

        ret = PreparePacket(ssh,
                            MSG_ID_SZ + BOOLEAN_SZ + (LENGTH_SZ * 2) +
                            msgSz + cannedLangTagSz);
    }

    if (ret == WS_SUCCESS) {
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

        ret = BundlePacket(ssh);
    }

    if (ret == WS_SUCCESS)
        ret = SendBuffered(ssh);

    return ret;
}


int SendServiceRequest(WOLFSSH* ssh, byte serviceId)
{
    const char* serviceName;
    word32 serviceNameSz;
    byte* output;
    word32 idx;
    int ret = WS_SUCCESS;

    WLOG(WS_LOG_DEBUG, "Entering SendServiceRequest()");

    if (ssh == NULL)
        ret = WS_BAD_ARGUMENT;

    if (ret == WS_SUCCESS) {
        serviceName = IdToName(serviceId);
        serviceNameSz = (word32)WSTRLEN(serviceName);

        ret = PreparePacket(ssh,
                            MSG_ID_SZ + LENGTH_SZ + serviceNameSz);
    }

    if (ret == WS_SUCCESS) {
        output = ssh->outputBuffer.buffer;
        idx = ssh->outputBuffer.length;

        output[idx++] = MSGID_SERVICE_REQUEST;
        c32toa(serviceNameSz, output + idx);
        idx += LENGTH_SZ;
        WMEMCPY(output + idx, serviceName, serviceNameSz);
        idx += serviceNameSz;

        ssh->outputBuffer.length = idx;
        ret = BundlePacket(ssh);
    }

    if (ret == WS_SUCCESS)
        ret = SendBuffered(ssh);

    WLOG(WS_LOG_DEBUG, "Leaving SendServiceRequest(), ret = %d", ret);
    return ret;
}


int SendServiceAccept(WOLFSSH* ssh, byte serviceId)
{
    const char* serviceName;
    word32 serviceNameSz;
    byte* output;
    word32 idx;
    int ret = WS_SUCCESS;

    if (ssh == NULL)
        ret = WS_BAD_ARGUMENT;

    if (ret == WS_SUCCESS) {
        serviceName = IdToName(serviceId);
        serviceNameSz = (word32)WSTRLEN(serviceName);
        ret = PreparePacket(ssh, MSG_ID_SZ + LENGTH_SZ + serviceNameSz);
    }

    if (ret == WS_SUCCESS) {
        output = ssh->outputBuffer.buffer;
        idx = ssh->outputBuffer.length;

        output[idx++] = MSGID_SERVICE_ACCEPT;
        c32toa(serviceNameSz, output + idx);
        idx += LENGTH_SZ;
        WMEMCPY(output + idx, serviceName, serviceNameSz);
        idx += serviceNameSz;

        ssh->outputBuffer.length = idx;

        ret = BundlePacket(ssh);
    }

    if (ret == WS_SUCCESS)
        ret = SendUserAuthBanner(ssh);

    return ret;
}


static const char cannedAuths[] = "publickey,password";
static const word32 cannedAuthsSz = sizeof(cannedAuths) - 1;


int SendUserAuthRequest(WOLFSSH* ssh, byte authId)
{
    byte* output;
    word32 idx;
    const char* authName;
    word32 authNameSz;
    const char* serviceName;
    word32 serviceNameSz;
    word32 payloadSz;
    int ret = WS_SUCCESS;
    WS_UserAuthData authData;

    WLOG(WS_LOG_DEBUG, "Entering SendUserAuthRequest()");

    if (ssh == NULL)
        ret = WS_BAD_ARGUMENT;

    if (ret == WS_SUCCESS) {
        if (authId == ID_USERAUTH_PASSWORD && ssh->ctx->userAuthCb != NULL) {
            WLOG(WS_LOG_DEBUG, "SUARPW: Calling the userauth callback");
            ret = ssh->ctx->userAuthCb(WOLFSSH_USERAUTH_PASSWORD,
                                       &authData, ssh->userAuthCtx);
            if (ret != WOLFSSH_USERAUTH_SUCCESS) {
                WLOG(WS_LOG_DEBUG, "SUARPW: Couldn't get password");
                ret = WS_FATAL_ERROR;
            }
        }
    }

    if (ret == WS_SUCCESS) {
        serviceName = IdToName(ID_SERVICE_CONNECTION);
        serviceNameSz = (word32)WSTRLEN(serviceName);
        authName = IdToName(authId);
        authNameSz = (word32)WSTRLEN(authName);

        payloadSz = MSG_ID_SZ + (LENGTH_SZ * 3) +
                    ssh->userNameSz + serviceNameSz + authNameSz;

        if (authId == ID_USERAUTH_PASSWORD) {
            payloadSz += BOOLEAN_SZ + LENGTH_SZ +
                         authData.sf.password.passwordSz;
        }
        else if (authId != ID_NONE)
            ret = WS_INVALID_ALGO_ID;
    }

    if (ret == WS_SUCCESS)
        ret = PreparePacket(ssh, payloadSz);

    if (ret == WS_SUCCESS) {
        output = ssh->outputBuffer.buffer;
        idx = ssh->outputBuffer.length;

        output[idx++] = MSGID_USERAUTH_REQUEST;
        c32toa(ssh->userNameSz, output + idx);
        idx += LENGTH_SZ;
        WMEMCPY(output + idx, ssh->userName, ssh->userNameSz);
        idx += ssh->userNameSz;

        c32toa(serviceNameSz, output + idx);
        idx += LENGTH_SZ;
        WMEMCPY(output + idx, serviceName, serviceNameSz);
        idx += serviceNameSz;

        c32toa(authNameSz, output + idx);
        idx += LENGTH_SZ;
        WMEMCPY(output + idx, authName, authNameSz);
        idx += authNameSz;

        if (authId == ID_USERAUTH_PASSWORD) {
            output[idx++] = 0; /* Boolean "FALSE" for password change */
            c32toa(authData.sf.password.passwordSz, output + idx);
            idx += LENGTH_SZ;
            WMEMCPY(output + idx, authData.sf.password.password,
                    authData.sf.password.passwordSz);
            idx += authData.sf.password.passwordSz;
        }

        ssh->outputBuffer.length = idx;

        ret = BundlePacket(ssh);
    }

    if (ret == WS_SUCCESS)
        ret = SendBuffered(ssh);

    WLOG(WS_LOG_DEBUG, "Leaving SendUserAuthRequest(), ret = %d", ret);
    return ret;
}


int SendUserAuthFailure(WOLFSSH* ssh, byte partialSuccess)
{
    byte* output;
    word32 idx;
    int ret = WS_SUCCESS;

    WLOG(WS_LOG_DEBUG, "Entering SendUserAuthFailure()");

    if (ssh == NULL)
        ret = WS_BAD_ARGUMENT;

    if (ret == WS_SUCCESS)
        ret = PreparePacket(ssh,
                            MSG_ID_SZ + LENGTH_SZ +
                            cannedAuthsSz + BOOLEAN_SZ);

    if (ret == WS_SUCCESS) {
        output = ssh->outputBuffer.buffer;
        idx = ssh->outputBuffer.length;

        output[idx++] = MSGID_USERAUTH_FAILURE;
        c32toa(cannedAuthsSz, output + idx);
        idx += LENGTH_SZ;
        WMEMCPY(output + idx, cannedAuths, cannedAuthsSz);
        idx += cannedAuthsSz;
        output[idx++] = (partialSuccess != 0);

        ssh->outputBuffer.length = idx;

        ret = BundlePacket(ssh);
    }

    if (ret == WS_SUCCESS)
        ret = SendBuffered(ssh);

    return ret;
}


int SendUserAuthSuccess(WOLFSSH* ssh)
{
    byte* output;
    word32 idx;
    int ret = WS_SUCCESS;

    if (ssh == NULL)
        ret = WS_BAD_ARGUMENT;

    if (ret == WS_SUCCESS)
        ret = PreparePacket(ssh, MSG_ID_SZ);

    if (ret == WS_SUCCESS) {
        output = ssh->outputBuffer.buffer;
        idx = ssh->outputBuffer.length;

        output[idx++] = MSGID_USERAUTH_SUCCESS;

        ssh->outputBuffer.length = idx;

        ret = BundlePacket(ssh);
    }

    if (ret == WS_SUCCESS)
        ret = SendBuffered(ssh);

    return ret;
}


int SendUserAuthPkOk(WOLFSSH* ssh,
                     const byte* algoName, word32 algoNameSz,
                     const byte* publicKey, word32 publicKeySz)
{
    byte* output;
    word32 idx;
    int ret = WS_SUCCESS;

    if (ssh == NULL ||
        algoName == NULL || algoNameSz == 0 ||
        publicKey == NULL || publicKeySz == 0) {

        ret = WS_BAD_ARGUMENT;
    }

    if (ret == WS_SUCCESS)
        ret = PreparePacket(ssh, MSG_ID_SZ + (LENGTH_SZ * 2) +
                                 algoNameSz + publicKeySz);

    if (ret == WS_SUCCESS) {
        output = ssh->outputBuffer.buffer;
        idx = ssh->outputBuffer.length;

        output[idx++] = MSGID_USERAUTH_PK_OK;
        c32toa(algoNameSz, output + idx);
        idx += LENGTH_SZ;
        WMEMCPY(output + idx, algoName, algoNameSz);
        idx += algoNameSz;
        c32toa(publicKeySz, output + idx);
        idx += LENGTH_SZ;
        WMEMCPY(output + idx, publicKey, publicKeySz);
        idx += publicKeySz;

        ssh->outputBuffer.length = idx;

        ret = BundlePacket(ssh);
    }

    if (ret == WS_SUCCESS)
        ret = SendBuffered(ssh);

    return ret;
}


int SendUserAuthBanner(WOLFSSH* ssh)
{
    byte* output;
    word32 idx;
    int ret = WS_SUCCESS;
    const char* banner = NULL;
    word32 bannerSz = 0;

    WLOG(WS_LOG_DEBUG, "Entering SendUserAuthBanner()");
    if (ssh == NULL)
        ret = WS_BAD_ARGUMENT;

    if (ret == WS_SUCCESS) {
        banner = ssh->ctx->banner;
        bannerSz = ssh->ctx->bannerSz;
    }

    if (banner != NULL && bannerSz > 0) {
        if (ret == WS_SUCCESS)
            ret = PreparePacket(ssh, MSG_ID_SZ + (LENGTH_SZ * 2) +
                                bannerSz + cannedLangTagSz);

        if (ret == WS_SUCCESS) {
            output = ssh->outputBuffer.buffer;
            idx = ssh->outputBuffer.length;

            output[idx++] = MSGID_USERAUTH_BANNER;
            c32toa(bannerSz, output + idx);
            idx += LENGTH_SZ;
            if (bannerSz > 0)
                WMEMCPY(output + idx, banner, bannerSz);
            idx += bannerSz;
            c32toa(cannedLangTagSz, output + idx);
            idx += LENGTH_SZ;
            WMEMCPY(output + idx, cannedLangTag, cannedLangTagSz);
            idx += cannedLangTagSz;

            ssh->outputBuffer.length = idx;

            ret = BundlePacket(ssh);
        }
    }

    if (ret == WS_SUCCESS)
        ret = SendBuffered(ssh);

    WLOG(WS_LOG_DEBUG, "Leaving SendUserAuthBanner()");
    return ret;
}


int SendRequestSuccess(WOLFSSH* ssh, int success)
{
    byte* output;
    word32 idx;
    int ret = WS_SUCCESS;

    WLOG(WS_LOG_DEBUG, "Entering SendRequestSuccess(), %s",
         success ? "Success" : "Failure");

    if (ssh == NULL)
        ret = WS_BAD_ARGUMENT;

    if (ret == WS_SUCCESS)
        ret = PreparePacket(ssh, MSG_ID_SZ);

    if (ret == WS_SUCCESS) {
        output = ssh->outputBuffer.buffer;
        idx = ssh->outputBuffer.length;

        output[idx++] = success ?
                        MSGID_REQUEST_SUCCESS : MSGID_REQUEST_FAILURE;

        ssh->outputBuffer.length = idx;

        ret = BundlePacket(ssh);
    }

    if (ret == WS_SUCCESS)
        ret = SendBuffered(ssh);

    WLOG(WS_LOG_DEBUG, "Leaving SendRequestSuccess(), ret = %d", ret);
    return ret;
}


int SendChannelOpenSession(WOLFSSH* ssh,
                           word32 initialWindowSz, word32 maxPacketSz)
{
    WOLFSSH_CHANNEL* newChannel;
    byte* output;
    const char* channelType;
    word32 channelTypeSz, channelId, idx;
    int ret = WS_SUCCESS;

    WLOG(WS_LOG_DEBUG, "Entering SendChannelOpenSession()");

    if (ssh == NULL)
        ret = WS_BAD_ARGUMENT;

    if (ret == WS_SUCCESS) {
        channelId = ssh->nextChannel;
        newChannel = ChannelNew(ssh, ID_CHANTYPE_SESSION,
                                initialWindowSz, maxPacketSz);
        if (newChannel == NULL)
            ret = WS_MEMORY_E;

        if (ret == WS_SUCCESS)
            ret = ChannelAppend(ssh, newChannel);
    }

    if (ret == WS_SUCCESS) {
        channelType = IdToName(ID_CHANTYPE_SESSION);
        channelTypeSz = (word32)WSTRLEN(channelType);

        ret = PreparePacket(ssh, MSG_ID_SZ + LENGTH_SZ + channelTypeSz +
                                 (UINT32_SZ * 3));
    }

    if (ret == WS_SUCCESS) {
        output = ssh->outputBuffer.buffer;
        idx = ssh->outputBuffer.length;

        output[idx++] = MSGID_CHANNEL_OPEN;
        c32toa(channelTypeSz, output + idx);
        idx += LENGTH_SZ;
        WMEMCPY(output + idx, channelType, channelTypeSz);
        idx += channelTypeSz;
        c32toa(channelId, output + idx);
        idx += UINT32_SZ;
        c32toa(initialWindowSz, output + idx);
        idx += UINT32_SZ;
        c32toa(maxPacketSz, output + idx);
        idx += UINT32_SZ;

        ssh->outputBuffer.length = idx;

        ret = BundlePacket(ssh);
    }

    if (ret == WS_SUCCESS)
        ret = SendBuffered(ssh);

    WLOG(WS_LOG_DEBUG, "Leaving SendChannelOpenSession(), ret = %d", ret);
    return ret;
}


int SendChannelOpenConf(WOLFSSH* ssh)
{
    byte* output;
    word32 idx;
    int ret = WS_SUCCESS;
    WOLFSSH_CHANNEL* channel;

    WLOG(WS_LOG_DEBUG, "Entering SendChannelOpenConf()");

    if (ssh == NULL)
        ret = WS_BAD_ARGUMENT;

    if (ret == WS_SUCCESS) {
        channel = ChannelFind(ssh, ssh->defaultPeerChannelId, FIND_PEER);
        if (channel == NULL)
            ret = WS_INVALID_CHANID;
    }

    if (ret == WS_SUCCESS)
        ret = PreparePacket(ssh, MSG_ID_SZ + (UINT32_SZ * 4));

    if (ret == WS_SUCCESS) {
        output = ssh->outputBuffer.buffer;
        idx = ssh->outputBuffer.length;

        output[idx++] = MSGID_CHANNEL_OPEN_CONF;
        c32toa(channel->peerChannel, output + idx);
        idx += UINT32_SZ;
        c32toa(channel->channel, output + idx);
        idx += UINT32_SZ;
        c32toa(channel->windowSz, output + idx);
        idx += UINT32_SZ;
        c32toa(channel->maxPacketSz, output + idx);
        idx += UINT32_SZ;

        ssh->outputBuffer.length = idx;

        ret = BundlePacket(ssh);
    }

    if (ret == WS_SUCCESS)
        ret = SendBuffered(ssh);

    WLOG(WS_LOG_DEBUG, "Leaving SendChannelOpenConf(), ret = %d", ret);
    return ret;
}


int SendChannelEof(WOLFSSH* ssh, word32 peerChannelId)
{
    byte* output;
    word32 idx;
    int ret = WS_SUCCESS;
    WOLFSSH_CHANNEL* channel;

    WLOG(WS_LOG_DEBUG, "Entering SendChannelEof()");

    if (ssh == NULL)
        ret = WS_BAD_ARGUMENT;

    if (ret == WS_SUCCESS) {
        channel = ChannelFind(ssh, peerChannelId, FIND_PEER);
        if (channel == NULL)
            ret = WS_INVALID_CHANID;
    }

    if (ret == WS_SUCCESS)
        ret = PreparePacket(ssh, MSG_ID_SZ + UINT32_SZ);

    if (ret == WS_SUCCESS) {
        output = ssh->outputBuffer.buffer;
        idx = ssh->outputBuffer.length;

        output[idx++] = MSGID_CHANNEL_EOF;
        c32toa(channel->peerChannel, output + idx);
        idx += UINT32_SZ;

        ssh->outputBuffer.length = idx;

        ret = BundlePacket(ssh);
    }

    if (ret == WS_SUCCESS)
        ret = SendBuffered(ssh);

    WLOG(WS_LOG_DEBUG, "Leaving SendChannelEof(), ret = %d", ret);
    return ret;
}


int SendChannelEow(WOLFSSH* ssh, word32 peerChannelId)
{
    byte* output;
    word32 idx;
    word32 strSz = sizeof("eow@openssh.com");
    int      ret = WS_SUCCESS;
    WOLFSSH_CHANNEL* channel;

    WLOG(WS_LOG_DEBUG, "Entering SendChannelEow()");

    if (ssh == NULL)
        ret = WS_BAD_ARGUMENT;

    if (!ssh->clientOpenSSH) {
        WLOG(WS_LOG_DEBUG, "Leaving SendChannelEow(), not OpenSSH");
        return ret;
    }

    if (ret == WS_SUCCESS) {
        channel = ChannelFind(ssh, peerChannelId, FIND_PEER);
        if (channel == NULL)
            ret = WS_INVALID_CHANID;
    }

    if (ret == WS_SUCCESS)
        ret = PreparePacket(ssh, MSG_ID_SZ + UINT32_SZ + LENGTH_SZ + strSz +
                            BOOLEAN_SZ);

    if (ret == WS_SUCCESS) {
        output = ssh->outputBuffer.buffer;
        idx = ssh->outputBuffer.length;

        output[idx++] = MSGID_CHANNEL_REQUEST;
        c32toa(channel->peerChannel, output + idx);
        idx += UINT32_SZ;
        c32toa(strSz, output + idx);
        idx += LENGTH_SZ;
        WMEMCPY(output + idx, "eow@openssh.com", strSz);
        idx += strSz;
        output[idx++] = 0;      // false

        ssh->outputBuffer.length = idx;

        ret = BundlePacket(ssh);
    }

    if (ret == WS_SUCCESS)
        ret = SendBuffered(ssh);

    WLOG(WS_LOG_DEBUG, "Leaving SendChannelEow(), ret = %d", ret);
    return ret;
}


int SendChannelExit(WOLFSSH* ssh, word32 peerChannelId, int status)
{
    byte* output;
    word32 idx;
    word32 strSz = sizeof("exit-status");
    int      ret = WS_SUCCESS;
    WOLFSSH_CHANNEL* channel;

    WLOG(WS_LOG_DEBUG, "Entering SendChannelExit(), status = %d", status);

    if (ssh == NULL)
        ret = WS_BAD_ARGUMENT;

    if (ret == WS_SUCCESS) {
        channel = ChannelFind(ssh, peerChannelId, FIND_PEER);
        if (channel == NULL)
            ret = WS_INVALID_CHANID;
    }

    if (ret == WS_SUCCESS)
        ret = PreparePacket(ssh, MSG_ID_SZ + UINT32_SZ + LENGTH_SZ + strSz +
                            BOOLEAN_SZ + UINT32_SZ);

    if (ret == WS_SUCCESS) {
        output = ssh->outputBuffer.buffer;
        idx = ssh->outputBuffer.length;

        output[idx++] = MSGID_CHANNEL_REQUEST;
        c32toa(channel->peerChannel, output + idx);
        idx += UINT32_SZ;
        c32toa(strSz, output + idx);
        idx += LENGTH_SZ;
        WMEMCPY(output + idx, "exit-status", strSz);
        idx += strSz;
        output[idx++] = 0;      // false
        c32toa(status, output + idx);
        idx += UINT32_SZ;

        ssh->outputBuffer.length = idx;

        ret = BundlePacket(ssh);
    }

    if (ret == WS_SUCCESS)
        ret = SendBuffered(ssh);

    WLOG(WS_LOG_DEBUG, "Leaving SendChannelExit(), ret = %d", ret);
    return ret;
}


int SendChannelClose(WOLFSSH* ssh, word32 peerChannelId)
{
    byte* output;
    word32 idx;
    int ret = WS_SUCCESS;
    WOLFSSH_CHANNEL* channel;

    WLOG(WS_LOG_DEBUG, "Entering SendChannelClose()");

    if (ssh == NULL)
        ret = WS_BAD_ARGUMENT;

    if (ret == WS_SUCCESS) {
        channel = ChannelFind(ssh, peerChannelId, FIND_PEER);
        if (channel == NULL)
            ret = WS_INVALID_CHANID;
        else if (channel->closeSent) {
            WLOG(WS_LOG_DEBUG, "Leaving SendChannelClose(), already sent");
            return ret;
        }
    }

    if (ret == WS_SUCCESS)
        ret = PreparePacket(ssh, MSG_ID_SZ + UINT32_SZ);

    if (ret == WS_SUCCESS) {
        output = ssh->outputBuffer.buffer;
        idx = ssh->outputBuffer.length;

        output[idx++] = MSGID_CHANNEL_CLOSE;
        c32toa(channel->peerChannel, output + idx);
        idx += UINT32_SZ;

        ssh->outputBuffer.length = idx;

        ret = BundlePacket(ssh);
    }

    if (ret == WS_SUCCESS) {
        ret = SendBuffered(ssh);
        channel->closeSent = 1;
    }

    WLOG(WS_LOG_DEBUG, "Leaving SendChannelClose(), ret = %d", ret);
    return ret;
}


int SendChannelData(WOLFSSH* ssh, word32 peerChannel,
                    byte* data, word32 dataSz)
{
    byte* output;
    word32 idx;
    int ret = WS_SUCCESS;
    WOLFSSH_CHANNEL* channel;

    WLOG(WS_LOG_DEBUG, "Entering SendChannelData()");

    if (ssh == NULL)
        ret = WS_BAD_ARGUMENT;

    if (ret == WS_SUCCESS) {
        if (ssh->isKeying)
            ret = WS_REKEYING;
    }

    if (ret == WS_SUCCESS) {
        channel = ChannelFind(ssh, peerChannel, FIND_PEER);
        if (channel == NULL) {
            WLOG(WS_LOG_DEBUG, "Invalid peer channel");
            ret = WS_INVALID_CHANID;
        }
    }

    if (ret == WS_SUCCESS) {
        word32 bound = min(channel->peerWindowSz, channel->peerMaxPacketSz);

        if (dataSz > bound) {
            WLOG(WS_LOG_DEBUG,
                 "Trying to send %u, client will only accept %u, limiting",
                 dataSz, bound);
            dataSz = bound;
        }

        ret = PreparePacket(ssh, MSG_ID_SZ + UINT32_SZ + LENGTH_SZ + dataSz);
    }

    if (ret == WS_SUCCESS) {
        output = ssh->outputBuffer.buffer;
        idx = ssh->outputBuffer.length;

        output[idx++] = MSGID_CHANNEL_DATA;
        c32toa(channel->peerChannel, output + idx);
        idx += UINT32_SZ;
        c32toa(dataSz, output + idx);
        idx += LENGTH_SZ;
        WMEMCPY(output + idx, data, dataSz);
        idx += dataSz;

        ssh->outputBuffer.length = idx;

        ret = BundlePacket(ssh);
    }

    if (ret == WS_SUCCESS)
        ret = SendBuffered(ssh);

    if (ret == WS_SUCCESS) {
        WLOG(WS_LOG_INFO, "  dataSz = %u", dataSz);
        WLOG(WS_LOG_INFO, "  peerWindowSz = %u", channel->peerWindowSz);
        channel->peerWindowSz -= dataSz;
        WLOG(WS_LOG_INFO, "  update peerWindowSz = %u", channel->peerWindowSz);
        ret = dataSz;
    }

    WLOG(WS_LOG_DEBUG, "Leaving SendChannelData(), ret = %d", ret);
    return ret;
}


int SendChannelWindowAdjust(WOLFSSH* ssh, word32 peerChannel,
                            word32 bytesToAdd)
{
    byte* output;
    word32 idx;
    int ret = WS_SUCCESS;
    WOLFSSH_CHANNEL* channel;

    WLOG(WS_LOG_DEBUG, "Entering SendChannelWindowAdjust()");

    if (ssh == NULL)
        ret = WS_BAD_ARGUMENT;

    channel = ChannelFind(ssh, peerChannel, FIND_PEER);
    if (channel == NULL) {
        WLOG(WS_LOG_DEBUG, "Invalid peer channel");
        ret = WS_INVALID_CHANID;
    }
    if (ret == WS_SUCCESS)
        ret = PreparePacket(ssh, MSG_ID_SZ + (UINT32_SZ * 2));

    if (ret == WS_SUCCESS) {
        output = ssh->outputBuffer.buffer;
        idx = ssh->outputBuffer.length;

        output[idx++] = MSGID_CHANNEL_WINDOW_ADJUST;
        c32toa(channel->peerChannel, output + idx);
        idx += UINT32_SZ;
        c32toa(bytesToAdd, output + idx);
        idx += UINT32_SZ;

        ssh->outputBuffer.length = idx;

        ret = BundlePacket(ssh);
    }

    if (ret == WS_SUCCESS)
        ret = SendBuffered(ssh);

    WLOG(WS_LOG_DEBUG, "Leaving SendChannelWindowAdjust(), ret = %d", ret);
    return ret;
}


static const char cannedShellName[] = "shell";
static const word32 cannedShellNameSz = sizeof(cannedShellName) - 1;


int SendChannelRequestShell(WOLFSSH* ssh)
{
    byte* output;
    word32 idx;
    int ret = WS_SUCCESS;
    WOLFSSH_CHANNEL* channel;

    WLOG(WS_LOG_DEBUG, "Entering SendChannelRequestShell()");

    if (ssh == NULL)
        ret = WS_BAD_ARGUMENT;

    if (ret == WS_SUCCESS) {
        channel = ChannelFind(ssh, ssh->defaultPeerChannelId, FIND_PEER);
        if (channel == NULL)
            ret = WS_INVALID_CHANID;
    }

    if (ret == WS_SUCCESS)
        ret = PreparePacket(ssh, MSG_ID_SZ + UINT32_SZ + LENGTH_SZ +
                                 cannedShellNameSz + BOOLEAN_SZ);

    if (ret == WS_SUCCESS) {
        output = ssh->outputBuffer.buffer;
        idx = ssh->outputBuffer.length;

        output[idx++] = MSGID_CHANNEL_REQUEST;
        c32toa(channel->peerChannel, output + idx);
        idx += UINT32_SZ;
        c32toa(cannedShellNameSz, output + idx);
        idx += LENGTH_SZ;
        WMEMCPY(output + idx, cannedShellName, cannedShellNameSz);
        idx += cannedShellNameSz;
        output[idx++] = 1;

        ssh->outputBuffer.length = idx;

        ret = BundlePacket(ssh);
    }

    if (ret == WS_SUCCESS)
        ret = SendBuffered(ssh);

    WLOG(WS_LOG_DEBUG, "Leaving SendChannelRequestShell(), ret = %d", ret);
    return ret;
}


int SendChannelSuccess(WOLFSSH* ssh, word32 channelId, int success)
{
    byte* output;
    word32 idx;
    int ret = WS_SUCCESS;
    WOLFSSH_CHANNEL* channel;

    WLOG(WS_LOG_DEBUG, "Entering SendChannelSuccess(), %s",
         success ? "Success" : "Failure");

    if (ssh == NULL)
        ret = WS_BAD_ARGUMENT;

    if (ret == WS_SUCCESS) {
        channel = ChannelFind(ssh, channelId, FIND_SELF);
        if (channel == NULL) {
            WLOG(WS_LOG_DEBUG, "Invalid channel");
            ret = WS_INVALID_CHANID;
        }
    }

    if (ret == WS_SUCCESS)
        ret = PreparePacket(ssh, MSG_ID_SZ + UINT32_SZ);

    if (ret == WS_SUCCESS) {
        output = ssh->outputBuffer.buffer;
        idx = ssh->outputBuffer.length;

        output[idx++] = success ?
                        MSGID_CHANNEL_SUCCESS : MSGID_CHANNEL_FAILURE;
        c32toa(channel->peerChannel, output + idx);
        idx += UINT32_SZ;

        ssh->outputBuffer.length = idx;

        ret = BundlePacket(ssh);
    }

    if (ret == WS_SUCCESS)
        ret = SendBuffered(ssh);

    WLOG(WS_LOG_DEBUG, "Leaving SendChannelSuccess(), ret = %d", ret);
    return ret;
}


#ifdef DEBUG_WOLFSSH

#define LINE_WIDTH 16
void DumpOctetString(const byte* input, word32 inputSz)
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

#endif

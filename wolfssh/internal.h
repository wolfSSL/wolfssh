/* internal.h
 *
 * Copyright (C) 2014-2024 wolfSSL Inc.
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


#ifndef _WOLFSSH_INTERNAL_H_
#define _WOLFSSH_INTERNAL_H_

#include <wolfssh/ssh.h>
#include <wolfssh/wolfsftp.h>

#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/dh.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/curve25519.h>
#include <wolfssl/wolfcrypt/ed25519.h>

#ifdef WOLFSSH_SCP
    #include <wolfssh/wolfscp.h>
#endif
#ifdef WOLFSSH_AGENT
    #include <wolfssh/agent.h>
#endif /* WOLFSSH_AGENT */
#ifdef WOLFSSH_CERTS
    #include <wolfssh/certman.h>
#endif /* WOLFSSH_CERTS */

#ifdef WOLFSSH_TPM
    #include <wolftpm/tpm2_wrap.h>
#endif /* WOLFSSH_TPM */

#if !defined (ALIGN16)
    #if defined (__GNUC__)
        #define ALIGN16 __attribute__ ( (aligned (16)))
    #elif defined(_MSC_VER)
        /* disable align warning, we want alignment ! */
        #pragma warning(disable: 4324)
        #define ALIGN16 __declspec (align (16))
    #else
        #define ALIGN16
    #endif
#endif


#ifdef __cplusplus
extern "C" {
#endif


/*
 * Not ready for rsa-sha2-512 yet.
 */

#undef WOLFSSH_NO_RSA_SHA2_512
#ifndef WOLFSSH_YES_RSA_SHA2_512
    #define WOLFSSH_NO_RSA_SHA2_512
#endif


/*
 * Check options set by wolfSSL and set wolfSSH options as appropriate. If
 * the derived options and any override options leave wolfSSH without
 * at least one algorithm to use, throw an error.
 */

#ifdef NO_RSA
    #undef WOLFSSH_NO_RSA
    #define WOLFSSH_NO_RSA
#endif

#ifndef HAVE_ECC
    #undef WOLFSSH_NO_ECDSA
    #define WOLFSSH_NO_ECDSA
    #undef WOLFSSH_NO_ECDH
    #define WOLFSSH_NO_ECDH
#endif

#ifdef NO_DH
    #undef WOLFSSH_NO_DH
    #define WOLFSSH_NO_DH
#endif

#ifdef NO_SHA
    #undef WOLFSSH_NO_SHA1
    #define WOLFSSH_NO_SHA1
#endif

#if !defined(HAVE_ED25519) \
    || !defined(WOLFSSL_ED25519_STREAMING_VERIFY) \
    || !defined(HAVE_ED25519_KEY_IMPORT) \
    || !defined(HAVE_ED25519_KEY_EXPORT)
    #undef WOLFSSH_NO_ED25519
    #define WOLFSSH_NO_ED25519
#endif

#if defined(NO_HMAC) || defined(WOLFSSH_NO_SHA1)
    #undef WOLFSSH_NO_HMAC_SHA1
    #define WOLFSSH_NO_HMAC_SHA1
#endif
#if defined(NO_HMAC) || defined(WOLFSSH_NO_SHA1)
    #undef WOLFSSH_NO_HMAC_SHA1_96
    #define WOLFSSH_NO_HMAC_SHA1_96
#endif
#if defined(NO_HMAC) || defined(NO_SHA256)
    #undef WOLFSSH_NO_HMAC_SHA2_256
    #define WOLFSSH_NO_HMAC_SHA2_256
#endif
#if defined(NO_HMAC) || defined(NO_SHA512)
    #undef WOLFSSH_NO_HMAC_SHA2_512
    #define WOLFSSH_NO_HMAC_SHA2_512
#endif
#if defined(WOLFSSH_NO_HMAC_SHA1) && \
    defined(WOLFSSH_NO_HMAC_SHA1_96) && \
    defined(WOLFSSH_NO_HMAC_SHA2_256) && \
    defined(WOLFSSH_NO_HMAC_SHA2_512)
    #error "You need at least one MAC algorithm."
#endif


#if defined(WOLFSSH_NO_DH) || defined(WOLFSSH_NO_SHA1)
    #undef WOLFSSH_NO_DH_GROUP1_SHA1
    #define WOLFSSH_NO_DH_GROUP1_SHA1
#endif
#if defined(WOLFSSH_NO_DH) || defined(WOLFSSH_NO_SHA1)
    #undef WOLFSSH_NO_DH_GROUP14_SHA1
    #define WOLFSSH_NO_DH_GROUP14_SHA1
#endif
#if defined(WOLFSSH_NO_DH) || defined(WOLFSSH_NO_SHA256)
    #undef WOLFSSH_NO_DH_GROUP14_SHA256
    #define WOLFSSH_NO_DH_GROUP14_SHA256
#endif
#if defined(WOLFSSH_NO_DH) || defined(WOLFSSH_NO_SHA512)
    #undef WOLFSSH_NO_DH_GROUP16_SHA512
    #define WOLFSSH_NO_DH_GROUP16_SHA512
#endif
#if defined(WOLFSSH_NO_DH) || defined(NO_SHA256)
    #undef WOLFSSH_NO_DH_GEX_SHA256
    #define WOLFSSH_NO_DH_GEX_SHA256
#endif
#if defined(WOLFSSH_NO_ECDH) \
    || defined(NO_SHA256) || defined(NO_ECC256)
    #undef WOLFSSH_NO_ECDH_SHA2_NISTP256
    #define WOLFSSH_NO_ECDH_SHA2_NISTP256
#endif
#if defined(WOLFSSH_NO_ECDH) \
    || !defined(WOLFSSL_SHA384) || \
    (!defined(HAVE_ECC384) && !defined(HAVE_ALL_CURVES))
    #undef WOLFSSH_NO_ECDH_SHA2_NISTP384
    #define WOLFSSH_NO_ECDH_SHA2_NISTP384
#endif
#if defined(WOLFSSH_NO_ECDH) \
    || !defined(WOLFSSL_SHA512) || \
    (!defined(HAVE_ECC521) && !defined(HAVE_ALL_CURVES))
    #undef WOLFSSH_NO_ECDH_SHA2_NISTP521
    #define WOLFSSH_NO_ECDH_SHA2_NISTP521
#endif
#if !defined(WOLFSSL_HAVE_MLKEM) || defined(NO_SHA256) \
    || defined(WOLFSSH_NO_ECDH_SHA2_NISTP256)
    #undef WOLFSSH_NO_NISTP256_MLKEM768_SHA256
    #define WOLFSSH_NO_NISTP256_MLKEM768_SHA256
#endif
#if !defined(HAVE_CURVE25519) || defined(NO_SHA256)
    #undef WOLFSSH_NO_CURVE25519_SHA256
    #define WOLFSSH_NO_CURVE25519_SHA256
#endif

#if defined(WOLFSSH_NO_DH_GROUP1_SHA1) && \
    defined(WOLFSSH_NO_DH_GROUP14_SHA1) && \
    defined(WOLFSSH_NO_DH_GROUP14_SHA256) && \
    defined(WOLFSSH_NO_DH_GROUP16_SHA512) && \
    defined(WOLFSSH_NO_DH_GEX_SHA256) && \
    defined(WOLFSSH_NO_ECDH_SHA2_NISTP256) && \
    defined(WOLFSSH_NO_ECDH_SHA2_NISTP384) && \
    defined(WOLFSSH_NO_ECDH_SHA2_NISTP521) && \
    defined(WOLFSSH_NO_NISTP256_MLKEM768_SHA256) && \
    defined(WOLFSSH_NO_CURVE25519_SHA256)
    #error "You need at least one key agreement algorithm."
#endif

#if defined(WOLFSSH_NO_DH_GROUP1_SHA1) && \
    defined(WOLFSSH_NO_DH_GROUP14_SHA1) && \
    defined(WOLFSSH_NO_DH_GROUP14_SHA256) && \
    defined(WOLFSSH_NO_DH_GROUP16_SHA512) && \
    defined(WOLFSSH_NO_DH_GEX_SHA256)
    #undef WOLFSSH_NO_DH
    #define WOLFSSH_NO_DH
#endif
#if defined(WOLFSSH_NO_ECDH_SHA2_NISTP256) && \
    defined(WOLFSSH_NO_ECDH_SHA2_NISTP384) && \
    defined(WOLFSSH_NO_ECDH_SHA2_NISTP521)
    #undef WOLFSSH_NO_ECDH
    #define WOLFSSH_NO_ECDH
#endif

#if defined(WOLFSSH_NO_RSA) || defined(WOLFSSH_NO_SHA1)
    #undef WOLFSSH_NO_SSH_RSA_SHA1
    #define WOLFSSH_NO_SSH_RSA_SHA1
#endif
#if defined(WOLFSSH_NO_RSA) || defined(NO_SHA256)
    #undef WOLFSSH_NO_RSA_SHA2_256
    #define WOLFSSH_NO_RSA_SHA2_256
#endif
#if defined(WOLFSSH_NO_RSA) || !defined(WOLFSSL_SHA512)
    #undef WOLFSSH_NO_RSA_SHA2_512
    #define WOLFSSH_NO_RSA_SHA2_512
#endif

#if defined(WOLFSSH_NO_ECDSA) || \
    defined(NO_SHA256) || defined(NO_ECC256)
    #undef WOLFSSH_NO_ECDSA_SHA2_NISTP256
    #define WOLFSSH_NO_ECDSA_SHA2_NISTP256
#endif
#if defined(WOLFSSH_NO_ECDSA) || \
    !defined(WOLFSSL_SHA384) || \
    (!defined(HAVE_ECC384) && !defined(HAVE_ALL_CURVES))
    #undef WOLFSSH_NO_ECDSA_SHA2_NISTP384
    #define WOLFSSH_NO_ECDSA_SHA2_NISTP384
#endif
#if defined(WOLFSSH_NO_ECDSA) || \
    !defined(WOLFSSL_SHA512) || \
    (!defined(HAVE_ECC521) && !defined(HAVE_ALL_CURVES))
    #undef WOLFSSH_NO_ECDSA_SHA2_NISTP521
    #define WOLFSSH_NO_ECDSA_SHA2_NISTP521
#endif
#if defined(WOLFSSH_NO_SSH_RSA_SHA1) && \
    defined(WOLFSSH_NO_RSA_SHA2_256) && \
    defined(WOLFSSH_NO_RSA_SHA2_512) && \
    defined(WOLFSSH_NO_ECDSA_SHA2_NISTP256) && \
    defined(WOLFSSH_NO_ECDSA_SHA2_NISTP384) && \
    defined(WOLFSSH_NO_ECDSA_SHA2_NISTP521) && \
    defined(WOLFSSH_NO_ED25519)
    #error "You need at least one signing algorithm."
#endif

#if defined(WOLFSSH_NO_SSH_RSA_SHA1) && \
    defined(WOLFSSH_NO_RSA_SHA2_256) && \
    defined(WOLFSSH_NO_RSA_SHA2_512)
    #undef WOLFSSH_NO_RSA
    #define WOLFSSH_NO_RSA
#endif
#if defined(WOLFSSH_NO_ECDSA_SHA2_NISTP256) && \
    defined(WOLFSSH_NO_ECDSA_SHA2_NISTP384) && \
    defined(WOLFSSH_NO_ECDSA_SHA2_NISTP521)
    #undef WOLFSSH_NO_ECDSA
    #define WOLFSSH_NO_ECDSA
#endif


#ifdef WOLFSSH_NO_AEAD
    #undef WOLFSSH_NO_AES_GCM
    #define WOLFSSH_NO_AES_GCM
#endif

#if defined(NO_AES) || !defined(HAVE_AES_CBC)
    #undef WOLFSSH_NO_AES_CBC
    #define WOLFSSH_NO_AES_CBC
#endif
#if defined(NO_AES) || !defined(WOLFSSL_AES_COUNTER)
    #undef WOLFSSH_NO_AES_CTR
    #define WOLFSSH_NO_AES_CTR
#endif
#if defined(NO_AES) || !defined(HAVE_AESGCM)
    #undef WOLFSSH_NO_AES_GCM
    #define WOLFSSH_NO_AES_GCM
#endif

#if defined(WOLFSSH_NO_AES_CBC) && \
    defined(WOLFSSH_NO_AES_CTR) && \
    defined(WOLFSSH_NO_AES_GCM)
    #error "You need at least one encryption algorithm."
#endif

#if defined(WOLFSSH_NO_AES_GCM)
    #undef WOLFSSH_NO_AEAD
    #define WOLFSSH_NO_AEAD
#endif

/* FPKI support turned off if wolfSSL linking to is not compiled with FPKI */
#if !defined(WOLFSSL_FPKI)
    #undef  WOLFSSH_NO_FPKI
    #define WOLFSSH_NO_FPKI
#endif


WOLFSSH_LOCAL const char* GetErrorString(int);


enum {
    /* Any of the items can be none. */
    ID_NONE,

    /* Encryption IDs */
    ID_AES128_CBC,
    ID_AES192_CBC,
    ID_AES256_CBC,
    ID_AES128_CTR,
    ID_AES192_CTR,
    ID_AES256_CTR,
    ID_AES128_GCM,
    ID_AES192_GCM,
    ID_AES256_GCM,

    /* Integrity IDs */
    ID_HMAC_SHA1,
    ID_HMAC_SHA1_96,
    ID_HMAC_SHA2_256,
    ID_HMAC_SHA2_512,

    /* Key Exchange IDs */
    ID_DH_GROUP1_SHA1,
    ID_DH_GROUP14_SHA1,
    ID_DH_GROUP14_SHA256,
    ID_DH_GROUP16_SHA512,
    ID_DH_GEX_SHA256,
    ID_ECDH_SHA2_NISTP256,
    ID_ECDH_SHA2_NISTP384,
    ID_ECDH_SHA2_NISTP521,
#ifndef WOLFSSH_NO_NISTP256_MLKEM768_SHA256
    ID_NISTP256_MLKEM768_SHA256,
#endif
#ifndef WOLFSSH_NO_CURVE25519_SHA256
    ID_CURVE25519_SHA256,
    ID_CURVE25519_SHA256_LIBSSH,
#endif
    ID_EXTINFO_S, /* Pseudo-KEX to indicate server extensions. */
    ID_EXTINFO_C, /* Pseudo-KEX to indicate client extensions. */

    /* Public Key IDs */
    ID_SSH_RSA,
    ID_RSA_SHA2_256,
    ID_RSA_SHA2_512,
    ID_ECDSA_SHA2_NISTP256,
    ID_ECDSA_SHA2_NISTP384,
    ID_ECDSA_SHA2_NISTP521,
    ID_ED25519,
    ID_X509V3_SSH_RSA,
    ID_X509V3_ECDSA_SHA2_NISTP256,
    ID_X509V3_ECDSA_SHA2_NISTP384,
    ID_X509V3_ECDSA_SHA2_NISTP521,

    /* Service IDs */
    ID_SERVICE_USERAUTH,
    ID_SERVICE_CONNECTION,

    /* UserAuth IDs */
    ID_USERAUTH_PASSWORD,
    ID_USERAUTH_PUBLICKEY,
#ifdef WOLFSSH_KEYBOARD_INTERACTIVE
    ID_USERAUTH_KEYBOARD,
#endif

    /* Channel Type IDs */
    ID_CHANTYPE_SESSION,
    ID_CHANTYPE_TCPIP_FORWARD,
    ID_CHANTYPE_TCPIP_DIRECT,
    ID_CHANTYPE_AUTH_AGENT,

    /* Global Request IDs */
    ID_GLOBREQ_TCPIP_FWD,
    ID_GLOBREQ_TCPIP_FWD_CANCEL,

    ID_EXTINFO_SERVER_SIG_ALGS,

    ID_CURVE_NISTP256,
    ID_CURVE_NISTP384,
    ID_CURVE_NISTP521,

    ID_UNKNOWN
};


enum NameIdType {
    TYPE_KEX, TYPE_KEY, TYPE_CIPHER, TYPE_MAC, TYPE_OTHER
};


#define WOLFSSH_MAX_NAMESZ 32

#ifndef WOLFSSH_MAX_CHN_NAMESZ
    #define WOLFSSH_MAX_CHN_NAMESZ 4096
#endif

#define MAX_ENCRYPTION 3
#define MAX_INTEGRITY 2
#define MAX_KEY_EXCHANGE 2
#define MAX_PUBLIC_KEY 1
#define MIN_RSA_SIG_SZ 2
#define MAX_HMAC_SZ WC_MAX_DIGEST_SIZE
#define MIN_BLOCK_SZ 8
#define COOKIE_SZ 16
#define PAD_LENGTH_SZ 1
#define MIN_PAD_LENGTH 4
#define BOOLEAN_SZ 1
#define MSG_ID_SZ 1
#define SHA1_96_SZ 12
#define UINT32_SZ 4
#define LENGTH_SZ UINT32_SZ
#define SSH_PROTO_SZ 7 /* "SSH-2.0" */
#define TERMINAL_MODE_SZ 5 /* opcode byte + argument uint32 */
#define AEAD_IMP_IV_SZ 4
#define AEAD_EXP_IV_SZ 8
#define AEAD_NONCE_SZ (AEAD_IMP_IV_SZ+AEAD_EXP_IV_SZ)
#ifndef DEFAULT_HIGHWATER_MARK
    #define DEFAULT_HIGHWATER_MARK ((1024 * 1024 * 1024) - (32 * 1024))
#endif
#ifndef DEFAULT_WINDOW_SZ
    #define DEFAULT_WINDOW_SZ (128 * 1024)
#endif
#ifndef DEFAULT_MAX_PACKET_SZ
    /* This is from RFC 4253 section 6.1. */
    #define DEFAULT_MAX_PACKET_SZ 32768
#endif
#ifndef DEFAULT_NEXT_CHANNEL
    #define DEFAULT_NEXT_CHANNEL 0
#endif
#ifndef MAX_PACKET_SZ
    /* This is from RFC 4253 section 6.1. */
    #define MAX_PACKET_SZ 35000
#endif
#ifndef WOLFSSH_DEFAULT_GEXDH_MIN
    #define WOLFSSH_DEFAULT_GEXDH_MIN 1024
#endif
#ifndef WOLFSSH_DEFAULT_GEXDH_PREFERRED
    #define WOLFSSH_DEFAULT_GEXDH_PREFERRED 3072
#endif
#ifndef WOLFSSH_DEFAULT_GEXDH_MAX
    #define WOLFSSH_DEFAULT_GEXDH_MAX 8192
#endif
#ifndef MAX_KEX_KEY_SZ
    #ifndef WOLFSSH_NO_NISTP256_MLKEM768_SHA256
        /* Private key size of ML-KEM 768. Biggest artifact. */
        #define MAX_KEX_KEY_SZ 2400
    #else
        /* This is based on the 8192-bit DH key that is the max size. */
        #define MAX_KEX_KEY_SZ (WOLFSSH_DEFAULT_GEXDH_MAX / 8)
    #endif
#endif
#ifndef WOLFSSH_MAX_FILE_SIZE
    #define WOLFSSH_MAX_FILE_SIZE (1024ul * 1024ul * 4)
#endif
#ifndef WOLFSSH_MAX_PVT_KEYS
    #define WOLFSSH_MAX_PVT_KEYS 8
#endif
#ifndef WOLFSSH_MAX_PUB_KEY_ALGO
    #define WOLFSSH_MAX_PUB_KEY_ALGO (WOLFSSH_MAX_PVT_KEYS + 2)
#endif
#ifndef WOLFSSH_KEY_QUANTITY_REQ
    #define WOLFSSH_KEY_QUANTITY_REQ 1
#endif


WOLFSSH_LOCAL byte NameToId(const char* name, word32 nameSz);
WOLFSSH_LOCAL const char* IdToName(byte id);
WOLFSSH_LOCAL const char* NameByIndexType(byte type, word32* index);


/* For cases when openssl coexist is used */
#ifdef WC_NO_COMPAT_AES_BLOCK_SIZE
    #define AES_BLOCK_SIZE WC_AES_BLOCK_SIZE
#endif

#define STATIC_BUFFER_LEN AES_BLOCK_SIZE
/* This is one AES block size. We always grab one
 * block size first to decrypt to find the size of
 * the rest of the data. */


typedef struct WOLFSSH_BUFFER {
    void* heap;       /* Heap for allocations */
    int   plainSz;    /* amount of plain text bytes to send with WANT_WRITE */
    word32 length;    /* total buffer length used */
    word32 idx;       /* idx to part of length already consumed */
    byte* buffer;     /* place holder for actual buffer */
    word32 bufferSz;  /* current buffer size */
    ALIGN16 byte staticBuffer[STATIC_BUFFER_LEN];
    byte dynamicFlag; /* dynamic memory currently in use */
} WOLFSSH_BUFFER;

WOLFSSH_LOCAL int BufferInit(WOLFSSH_BUFFER* buffer, word32 size, void* heap);
WOLFSSH_LOCAL int GrowBuffer(WOLFSSH_BUFFER* buf, word32 sz);
WOLFSSH_LOCAL void ShrinkBuffer(WOLFSSH_BUFFER* buf, int forcedFree);


typedef struct WOLFSSH_PVT_KEY {
    byte* key;
        /* List of pointers to raw private keys. Owned by CTX. */
    word32 keySz;
#ifdef WOLFSSH_CERTS
    byte* cert;
        /* Pointer to certificates for the private key. Owned by CTX. */
    word32 certSz;
#endif
    byte publicKeyFmt;
        /* Public key format for the private key. Note, some public key
         * formats are used with multiple public key signing algorithms. */
} WOLFSSH_PVT_KEY;


/* our wolfSSH Context */
struct WOLFSSH_CTX {
    void* heap;                       /* heap hint */
    WS_CallbackIORecv ioRecvCb;       /* I/O Receive Callback */
    WS_CallbackIOSend ioSendCb;       /* I/O Send Callback */
    WS_CallbackUserAuth userAuthCb;   /* User Authentication Callback */
    WS_CallbackUserAuthTypes userAuthTypesCb; /* Authentication Types Allowed */
    WS_CallbackUserAuthResult userAuthResultCb; /* User Authentication Result */
    WS_CallbackHighwater highwaterCb; /* Data Highwater Mark Callback */
    WS_CallbackGlobalReq globalReqCb; /* Global Request Callback */
    WS_CallbackReqSuccess reqSuccessCb; /* Global Request Success Callback */
    WS_CallbackReqSuccess reqFailureCb; /* Global Request Failure Callback */
    WS_CallbackChannelOpen channelOpenCb;     /* Channel Open Requested */
    WS_CallbackChannelOpen channelOpenConfCb; /* Channel Open Confirm */
    WS_CallbackChannelOpen channelOpenFailCb; /* Channel Open Fail */
    WS_CallbackChannelReq channelReqShellCb; /* Channel Request "Shell" */
    WS_CallbackChannelReq channelReqExecCb; /* Channel Request "Exec" */
    WS_CallbackChannelReq channelReqSubsysCb; /* Channel Request "Subsystem" */
    WS_CallbackChannelEof channelEofCb; /* Channel Eof Callback */
    WS_CallbackChannelClose channelCloseCb; /* Channel Close Callback */
#ifdef WOLFSSH_SCP
    WS_CallbackScpRecv scpRecvCb;     /* SCP receive callback */
    WS_CallbackScpSend scpSendCb;     /* SCP send callback */
#endif
#ifdef WOLFSSH_AGENT
    WS_CallbackAgent agentCb;         /* WOLFSSH-AGENT callback */
    WS_CallbackAgentIO agentIoCb;     /* WOLFSSH-AGENT IO callback */
#endif /* WOLFSSH_AGENT */
#ifdef WOLFSSH_FWD
    WS_CallbackFwd fwdCb;             /* WOLFSSH-FWD callback */
    WS_CallbackFwdIO fwdIoCb;         /* WOLFSSH-FWD IO callback */
#endif /* WOLFSSH_FWD */
#ifdef WOLFSSH_CERTS
    WOLFSSH_CERTMAN* certMan;
#endif /* WOLFSSH_CERTS */
    WS_CallbackPublicKeyCheck publicKeyCheckCb;
        /* Check server's public key callback */
    WOLFSSH_PVT_KEY privateKey[WOLFSSH_MAX_PVT_KEYS];
    word32 privateKeyCount;
    byte publicKeyAlgo[WOLFSSH_MAX_PUB_KEY_ALGO];
    word32 publicKeyAlgoCount;
    word32 highwaterMark;
    const char* banner;
    const char* sshProtoIdStr;
    const char* algoListKex;
    const char* algoListKey;
    const char* algoListCipher;
    const char* algoListMac;
    const char* algoListKeyAccepted;
    word32 bannerSz;
    word32 windowSz;
    word32 maxPacketSz;
    byte side;                        /* client or server */
    byte showBanner;
#ifdef WOLFSSH_AGENT
    byte agentEnabled;
#endif /* WOLFSSH_AGENT */
#ifdef WOLFSSH_TPM
    WOLFTPM2_DEV* tpmDev;
    WOLFTPM2_KEY* tpmKey;
#endif /* WOLFSSH_TPM */
    WS_CallbackKeyingCompletion keyingCompletionCb;
};


typedef struct Ciphers {
    Aes aes;
} Ciphers;


typedef struct Keys {
    byte iv[AES_BLOCK_SIZE];
    byte ivSz;
    byte encKey[AES_256_KEY_SIZE];
    byte encKeySz;
    byte macKey[MAX_HMAC_SZ];
    byte macKeySz;
} Keys;


typedef struct HandshakeInfo {
    byte kexId;
    byte kexIdGuess;
    byte kexHashId;
    byte pubKeyId;
    byte encryptId;
    byte macId;
    byte kexPacketFollows;
    byte aeadMode;

    byte blockSz;
    byte macSz;

    Keys keys;
    Keys peerKeys;
    wc_HashAlg kexHash;
    byte e[MAX_KEX_KEY_SZ+1]; /* May have a leading zero for unsigned
                                 or is a Q_S value. */
    word32 eSz;
    byte x[MAX_KEX_KEY_SZ+1]; /* May have a leading zero, for unsigned. */
    word32 xSz;
    byte* kexInit;
    word32 kexInitSz;

#ifndef WOLFSSH_NO_DH
    word32 dhGexMinSz;
    word32 dhGexPreferredSz;
    word32 dhGexMaxSz;
    byte* primeGroup;
    word32 primeGroupSz;
    byte* generator;
    word32 generatorSz;
#endif

    byte useDh:1;
    byte useEcc:1;
    byte useEccMlKem:1;
    byte useCurve25519:1;

    union {
#ifndef WOLFSSH_NO_DH
        DhKey dh;
#endif
#ifndef WOLFSSH_NO_ECDH
        ecc_key ecc;
#endif
#ifndef WOLFSSH_NO_CURVE25519_SHA256
        curve25519_key curve25519;
#endif
    } privKey;
} HandshakeInfo;

#if (defined(WOLFSSH_SFTP) || defined(WOLFSSH_SCP)) && \
    !defined(NO_WOLFSSH_SERVER)
WOLFSSH_LOCAL int wolfSSH_GetPath(const char* defaultPath, byte* in,
    word32 inSz, char* out, word32* outSz);
#endif

#ifdef WOLFSSH_SFTP
#define WOLFSSH_MAX_SFTPOFST 3

#ifndef NO_WOLFSSH_DIR
    typedef struct WS_DIR_LIST WS_DIR_LIST;
#endif
typedef struct WS_HANDLE_LIST WS_HANDLE_LIST;
typedef struct SFTP_OFST {
    word32 offset[2];
    char from[WOLFSSH_MAX_FILENAME];
    char to[WOLFSSH_MAX_FILENAME];
} SFTP_OFST;

struct WS_SFTP_RECV_INIT_STATE;
struct WS_SFTP_GET_STATE;
struct WS_SFTP_PUT_STATE;
struct WS_SFTP_LSTAT_STATE;
struct WS_SFTP_OPEN_STATE;
struct WS_SFTP_CLOSE_STATE;
struct WS_SFTP_SEND_READ_STATE;
struct WS_SFTP_SEND_WRITE_STATE;
struct WS_SFTP_GET_HANDLE_STATE;
struct WS_SFTP_PUT_STATE;
struct WS_SFTP_RENAME_STATE;

#ifdef USE_WINDOWS_API
    #define MAX_DRIVE_LETTER 26
#endif /* USE_WINDOWS_API */
#endif /* WOLFSSH_SFTP */

#ifdef USE_WINDOWS_API
#ifndef WOLFSSL_MAX_ESCBUF
#define WOLFSSL_MAX_ESCBUF 19
#endif
#endif

struct WOLFSSH_AGENT_CTX;

/* our wolfSSH session */
struct WOLFSSH {
    WOLFSSH_CTX* ctx;      /* owner context */
    int error;
    WS_SOCKET_T rfd;
    WS_SOCKET_T wfd;
    void* ioReadCtx;       /* I/O Read  Context handle */
    void* ioWriteCtx;      /* I/O Write Context handle */
    int rflags;            /* optional read  flags */
    int wflags;            /* optional write flags */
    word32 txCount;
    word32 rxCount;
    word32 highwaterMark;
    byte highwaterFlag;    /* Set when highwater CB called */
    void* highwaterCtx;    /* Highwater CB context */
    void* globalReqCtx;    /* Global Request CB context */
    void* reqSuccessCtx;   /* Global Request Sucess CB context */
    void* reqFailureCtx;   /* Global Request Failure CB context */
    void* channelOpenCtx;  /* Channel Open CB context */
    void* channelReqCtx;   /* Channel Request CB context */
    void* channelEofCtx;   /* Channel EOF CB context */
    void* channelCloseCtx; /* Channel Close CB context */
    void* fs;              /* File system handle */
    word32 curSz;
    word32 seq;
    word32 peerSeq;
    word32 packetStartIdx; /* Current send packet start index */
    const char* algoListKex;
    const char* algoListKey;
    const char* algoListCipher;
    const char* algoListMac;
    const char* algoListKeyAccepted;
    byte acceptState;
    byte connectState;
    byte clientState;
    byte serverState;
    byte processReplyState;
    byte isKeying;
    byte authId;           /* if using public key or password */
    byte supportedAuth[4]; /* supported auth IDs public key , password */

#ifdef WOLFSSH_SCP
    byte   scpState;
    byte   scpNextState;
    byte   scpRequestState;
    byte   scpFileState;
    byte   scpDirection;          /* indicates sending TO (t) of FROM (f) */
    int    scpConfirm;            /* confirmation state (OK|WARN|FATAL) */
    char*  scpConfirmMsg;         /* dynamic, confirm message string */
    word32 scpConfirmMsgSz;       /* length of confirmMsg, not including \0 */
    char*  scpRecvMsg;            /* reading up to newline delimiter */
    int    scpRecvMsgSz;          /* current size of scp recv message */
    const char* scpBasePath;      /* base path, ptr into channelList->command */
    /* alter base path instead of using chdir */
    char* scpBasePathDynamic;     /* dynamic base path */
    word32 scpBasePathSz;
    byte   scpIsRecursive;        /* recursive transfer requested */
    byte   scpRequestType;        /* directory or single file */
    byte   scpMsgType;
    int    scpFileMode;           /* mode/permission of file/dir */
    word32 scpFileSz;             /* total size of file/dir being transferred */
    char*  scpFileName;           /* file name, dynamic */
    char*  scpFileReName;         /* file rename case, points to scpFileName */
    word32 scpFileNameSz;         /* length of fileName, not including \0 */
    byte   scpTimestamp;          /* did peer request timestamp? {0:1} */
    word64 scpATime;              /* scp file access time, secs since epoch */
    word64 scpMTime;              /* scp file modification time, secs epoch */
    byte*  scpFileBuffer;         /* transfer buffer, dynamic */
    word32 scpFileBufferSz;       /* size of transfer buffer, octets */
    word32 scpFileOffset;         /* current offset into file transfer */
    word32 scpBufferedSz;         /* bytes buffered to send to peer */
#ifdef WOLFSSL_NUCLEUS
    int    scpFd;            /* SCP receive callback context handle */
#endif
    void*  scpRecvCtx;            /* SCP receive callback context handle */
    void*  scpSendCtx;            /* SCP send callback context handle */
    #if !defined(WOLFSSH_SCP_USER_CALLBACKS) && !defined(NO_FILESYSTEM)
    ScpSendCtx scpSendCbCtx;      /* used in default case to for send cb ctx */
    #endif
#endif
    byte connReset;
    byte isClosed;
    byte clientOpenSSH;

    byte kexId;
    byte blockSz;
    byte encryptId;
    byte macId;
    byte macSz;
    byte aeadMode;
    byte peerBlockSz;
    byte peerEncryptId;
    byte peerMacId;
    byte peerMacSz;
    byte peerAeadMode;
#ifndef WOLFSSH_NO_DH
    word32 primeGroupSz;
#endif

    Ciphers encryptCipher;
    Ciphers decryptCipher;

    word32 nextChannel;
    WOLFSSH_CHANNEL* channelList;
    word32 channelListSz;
    word32 defaultPeerChannelId;
    word32 connectChannelId;
    byte channelName[WOLFSSH_MAX_CHN_NAMESZ];
    word32 channelNameSz;
    word32 lastRxId;

    WOLFSSH_BUFFER inputBuffer;
    WOLFSSH_BUFFER outputBuffer;
    WOLFSSH_BUFFER extDataBuffer; /* extended data ready to be read */
    WC_RNG* rng;

    byte h[WC_MAX_DIGEST_SIZE];
    word32 hSz;
    byte k[MAX_KEX_KEY_SZ+1]; /* May have a leading zero, for unsigned. */
    word32 kSz;
    byte sessionId[WC_MAX_DIGEST_SIZE];
    word32 sessionIdSz;

    Keys keys;
    Keys peerKeys;
    HandshakeInfo* handshake;

    void* userAuthCtx;
    void* userAuthResultCtx;
#ifdef WOLFSSH_KEYBOARD_INTERACTIVE
    void* keyboardAuthCtx;
#endif
    char* userName;
    word32 userNameSz;
    char* password;
    word32 passwordSz;
    byte* pkBlob;
    word32 pkBlobSz;
    byte* peerProtoId;     /* Save for rekey */
    word32 peerProtoIdSz;
    void* publicKeyCheckCtx;
    byte  sendTerminalRequest;
    byte userAuthPkDone;
    byte sendExtInfo;
    byte extInfoSent; /* track if the ext info has already been sent */
    byte* peerSigId;
    word32 peerSigIdSz;

#ifdef USE_WINDOWS_API
    word32 defaultAttr; /* default windows attributes */
    byte   defaultAttrSet;
    byte   escBuf[WOLFSSL_MAX_ESCBUF]; /* console codes are about 3 byte and
                                        * have max arguments of 16 */
    byte   escBufSz;
    byte   escState; /* current console translation state */
#endif
#ifdef WOLFSSH_SFTP
    word32 reqId;
    byte   sftpState;
    byte   realState;
    byte   sftpInt;
    word32 sftpExtSz; /* size of extension buffer (buffer not currently used) */
    SFTP_OFST sftpOfst[WOLFSSH_MAX_SFTPOFST];
    char* sftpDefaultPath;
#ifndef NO_WOLFSSH_DIR
    WS_DIR_LIST* dirList;
    word32 dirIdCount[2];
#endif
#ifdef WOLFSSH_STOREHANDLE
    WS_HANDLE_LIST* handleList;
#endif
    struct WS_SFTP_RECV_INIT_STATE* recvInitState;
    struct WS_SFTP_RECV_STATE* recvState;
    struct WS_SFTP_RMDIR_STATE* rmdirState;
    struct WS_SFTP_MKDIR_STATE* mkdirState;
    struct WS_SFTP_RM_STATE* rmState;
    struct WS_SFTP_READDIR_STATE* readDirState;
    struct WS_SFTP_SETATR_STATE* setatrState;
    struct WS_SFTP_CHMOD_STATE* chmodState;
    struct WS_SFTP_LS_STATE* lsState;
    struct WS_SFTP_SEND_STATE* sendState;
    struct WS_SFTP_NAME_STATE* nameState;
    struct WS_SFTP_GET_STATE* getState;
    struct WS_SFTP_PUT_STATE* putState;
    struct WS_SFTP_LSTAT_STATE* lstatState;
    struct WS_SFTP_OPEN_STATE* openState;
    struct WS_SFTP_CLOSE_STATE* closeState;
    struct WS_SFTP_SEND_READ_STATE* sendReadState;
    struct WS_SFTP_SEND_WRITE_STATE* sendWriteState;
    struct WS_SFTP_GET_HANDLE_STATE* getHandleState;
    struct WS_SFTP_RENAME_STATE* renameState;
#ifdef USE_WINDOWS_API
    char driveList[MAX_DRIVE_LETTER];
    word16 driveListCount;
    word16 driveIdx;
#endif
#endif

#ifdef WOLFSSH_AGENT
    struct WOLFSSH_AGENT_CTX* agent;
    void* agentCbCtx;
    byte useAgent;
    byte agentEnabled;
#endif /* WOLFSSH_AGENT */
#ifdef WOLFSSH_FWD
    void* fwdCbCtx;
#endif /* WOLFSSH_FWD */
#ifdef WOLFSSH_TERM
    WS_CallbackTerminalSize termResizeCb;
    void* termCtx;
    word32 widthChar;    /* current terminal width */
    word32 heightRows;   /* current terminal height */
    word32 widthPixels;  /* pixel width  */
    word32 heightPixels; /* pixel height */
    byte* modes;
    word32 modesSz;
#endif
#if defined(WOLFSSH_TERM) || defined(WOLFSSH_SHELL)
    word32 exitStatus;
#endif
    void* keyingCompletionCtx;
#ifdef WOLFSSH_KEYBOARD_INTERACTIVE
    WS_UserAuthData_Keyboard kbAuth;
    byte kbAuthAttempts;
#endif
};


struct WOLFSSH_CHANNEL {
    byte channelType;
    byte sessionType;
    byte closeRxd : 1;
    byte closeTxd : 1;
    byte eofRxd : 1;
    byte eofTxd : 1;
    byte openConfirmed : 1;
    word32 channel;
    word32 windowSz;
    word32 maxPacketSz;
    word32 peerChannel;
    word32 peerWindowSz;
    word32 peerMaxPacketSz;
#ifdef WOLFSSH_FWD
    char* host;
    word32 hostPort;
    char* origin;
    word32 originPort;
    int fwdFd;
    int isDirect;
#endif /* WOLFSSH_FWD */
    WOLFSSH_BUFFER inputBuffer;
    char* command;
    struct WOLFSSH* ssh;
    struct WOLFSSH_CHANNEL* next;
};


WOLFSSH_LOCAL WOLFSSH_CTX* CtxInit(WOLFSSH_CTX*, byte, void*);
WOLFSSH_LOCAL void CtxResourceFree(WOLFSSH_CTX*);
WOLFSSH_LOCAL WOLFSSH* SshInit(WOLFSSH*, WOLFSSH_CTX*);
WOLFSSH_LOCAL void SshResourceFree(WOLFSSH*, void*);

WOLFSSH_LOCAL WOLFSSH_CHANNEL* ChannelNew(WOLFSSH*, byte, word32, word32);
WOLFSSH_LOCAL int ChannelUpdatePeer(WOLFSSH_CHANNEL*, word32, word32, word32);
WOLFSSH_LOCAL int ChannelUpdateForward(WOLFSSH_CHANNEL*,
        const char*, word32, const char*, word32, int);
WOLFSSH_LOCAL int ChannelAppend(WOLFSSH* ssh, WOLFSSH_CHANNEL* channel);
WOLFSSH_LOCAL void ChannelDelete(WOLFSSH_CHANNEL*, void*);
WOLFSSH_LOCAL WOLFSSH_CHANNEL* ChannelFind(WOLFSSH*, word32, byte);
WOLFSSH_LOCAL int ChannelRemove(WOLFSSH*, word32, byte);
WOLFSSH_LOCAL int ChannelPutData(WOLFSSH_CHANNEL*, byte*, word32);
WOLFSSH_LOCAL int wolfSSH_ProcessBuffer(WOLFSSH_CTX*,
                                        const byte*, word32,
                                        int, int);
WOLFSSH_LOCAL int wolfSSH_FwdWorker(WOLFSSH*);


typedef struct WS_KeySignature {
    byte keySigId;
    word32 sigSz;
    const char *name;
    void *heap;
    word32 nameSz;
    union {
#ifndef WOLFSSH_NO_RSA
        struct {
            RsaKey key;
        } rsa;
#endif
#ifndef WOLFSSH_NO_ECDSA
        struct {
            ecc_key key;
        } ecc;
#endif
#ifndef WOLFSSH_NO_ED25519
        struct {
            ed25519_key key;
        } ed25519;
#endif
    } ks;
} WS_KeySignature;

WOLFSSH_LOCAL int IdentifyAsn1Key(const byte* in, word32 inSz, int isPrivate, void* heap,
    WS_KeySignature **pkey);
WOLFSSH_LOCAL void wolfSSH_KEY_clean(WS_KeySignature* key);
WOLFSSH_LOCAL int IdentifyOpenSshKey(const byte* in, word32 inSz, void* heap);


/* Parsing functions */
WOLFSSH_LOCAL int GetBoolean(byte* v,
        const byte* buf, word32 len, word32* idx);
WOLFSSH_LOCAL int GetUint32(word32* v,
        const byte* buf, word32 len, word32* idx);
WOLFSSH_LOCAL int GetSize(word32* v,
        const byte* buf, word32 len, word32* idx);
WOLFSSH_LOCAL int GetSkip(const byte* buf, word32 len, word32* idx);
WOLFSSH_LOCAL int GetMpint(word32* mpintSz, const byte** mpint,
        const byte* buf, word32 len, word32* idx);
WOLFSSH_LOCAL int GetString(char* s, word32* sSz,
        const byte* buf, word32 len, word32* idx);
WOLFSSH_LOCAL int GetStringAlloc(void* heap, char** s,
        const byte* buf, word32 len, word32* idx);
WOLFSSH_LOCAL int GetStringRef(word32* strSz, const byte **str,
        const byte* buf, word32 len, word32* idx);


#ifndef WOLFSSH_USER_IO

/* default I/O handlers */
WOLFSSH_LOCAL int wsEmbedRecv(WOLFSSH*, void*, word32, void*);
WOLFSSH_LOCAL int wsEmbedSend(WOLFSSH*, void*, word32, void*);

#endif /* WOLFSSH_USER_IO */

enum ChannelOpenFailReasons {
    OPEN_OK = 0,
    OPEN_ADMINISTRATIVELY_PROHIBITED,
    OPEN_CONNECT_FAILED,
    OPEN_UNKNOWN_CHANNEL_TYPE,
    OPEN_RESOURCE_SHORTAGE
};

WOLFSSH_LOCAL int DoReceive(WOLFSSH*);
WOLFSSH_LOCAL int DoProtoId(WOLFSSH*);
WOLFSSH_LOCAL int wolfSSH_SendPacket(WOLFSSH*);
WOLFSSH_LOCAL int SendProtoId(WOLFSSH*);
WOLFSSH_LOCAL int SendKexInit(WOLFSSH*);
WOLFSSH_LOCAL int SendKexDhInit(WOLFSSH*);
WOLFSSH_LOCAL int SendKexDhReply(WOLFSSH*);
WOLFSSH_LOCAL int SendKexDhGexRequest(WOLFSSH*);
WOLFSSH_LOCAL int SendKexDhGexGroup(WOLFSSH*);
WOLFSSH_LOCAL int SendNewKeys(WOLFSSH*);
WOLFSSH_LOCAL int SendUnimplemented(WOLFSSH*);
WOLFSSH_LOCAL int SendDisconnect(WOLFSSH*, word32);
WOLFSSH_LOCAL int SendIgnore(WOLFSSH*, const unsigned char*, word32);
WOLFSSH_LOCAL int SendGlobalRequestFwdSuccess(WOLFSSH *, int, word32);
WOLFSSH_LOCAL int SendGlobalRequest(WOLFSSH *, const unsigned char *, word32, int);
WOLFSSH_LOCAL int SendDebug(WOLFSSH*, byte, const char*);
WOLFSSH_LOCAL int SendServiceRequest(WOLFSSH*, byte);
WOLFSSH_LOCAL int SendServiceAccept(WOLFSSH*, byte);
WOLFSSH_LOCAL int SendExtInfo(WOLFSSH* ssh);
WOLFSSH_LOCAL int SendUserAuthRequest(WOLFSSH*, byte, int);
#ifdef WOLFSSH_KEYBOARD_INTERACTIVE
WOLFSSH_LOCAL int SendUserAuthKeyboardResponse(WOLFSSH*);
WOLFSSH_LOCAL int SendUserAuthKeyboardRequest(WOLFSSH*, WS_UserAuthData*);
#endif
WOLFSSH_LOCAL int SendUserAuthSuccess(WOLFSSH*);
WOLFSSH_LOCAL int SendUserAuthFailure(WOLFSSH*, byte);
WOLFSSH_LOCAL int SendUserAuthBanner(WOLFSSH*);
WOLFSSH_LOCAL int SendUserAuthPkOk(WOLFSSH*, const byte*, word32,
                                   const byte*, word32);
WOLFSSH_LOCAL int SendRequestSuccess(WOLFSSH*, int);
WOLFSSH_LOCAL int SendChannelOpenSession(WOLFSSH*, WOLFSSH_CHANNEL*);
WOLFSSH_LOCAL int SendChannelOpenForward(WOLFSSH*, WOLFSSH_CHANNEL*);
WOLFSSH_LOCAL int SendChannelOpenConf(WOLFSSH*, WOLFSSH_CHANNEL*);
WOLFSSH_LOCAL int SendChannelOpenFail(WOLFSSH* ssh, word32 channel,
        word32 reason, const char* description, const char* language);
WOLFSSH_LOCAL int SendChannelEof(WOLFSSH*, word32);
WOLFSSH_LOCAL int SendChannelEow(WOLFSSH*, word32);
WOLFSSH_LOCAL int SendChannelClose(WOLFSSH*, word32);
WOLFSSH_LOCAL int SendChannelExit(WOLFSSH*, word32, int);
WOLFSSH_LOCAL int SendChannelData(WOLFSSH*, word32, byte*, word32);
WOLFSSH_LOCAL int SendChannelExtendedData(WOLFSSH*, word32, byte*, word32);
WOLFSSH_LOCAL int SendChannelWindowAdjust(WOLFSSH*, word32, word32);
WOLFSSH_LOCAL int SendChannelRequest(WOLFSSH*, byte*, word32);
WOLFSSH_LOCAL int SendChannelTerminalResize(WOLFSSH*, word32, word32, word32,
    word32);
WOLFSSH_LOCAL int SendChannelTerminalRequest(WOLFSSH* ssh);
WOLFSSH_LOCAL int SendChannelAgentRequest(WOLFSSH* ssh);
WOLFSSH_LOCAL int SendChannelSuccess(WOLFSSH*, word32, int);
WOLFSSH_LOCAL int SendChannelExitStatus(WOLFSSH* ssh, word32 channelId,
    word32 exitStatus);
WOLFSSH_LOCAL int GenerateKey(byte, byte, byte*, word32, const byte*, word32,
                              const byte*, word32, const byte*, word32, byte doKeyPad);
#if !defined(WOLFSSH_NO_ECDSA) || !defined(WOLFSSH_NO_ECDH)
WOLFSSH_LOCAL int wcPrimeForId(byte);
#endif
WOLFSSH_LOCAL enum wc_HashType HashForId(byte);


enum AcceptStates {
    ACCEPT_BEGIN = 0,
    ACCEPT_SERVER_VERSION_SENT,
    ACCEPT_CLIENT_VERSION_DONE,
    ACCEPT_SERVER_KEXINIT_SENT,
    ACCEPT_KEYED,
    ACCEPT_CLIENT_USERAUTH_REQUEST_DONE,
    ACCEPT_SERVER_USERAUTH_ACCEPT_SENT,
    ACCEPT_CLIENT_USERAUTH_DONE,
    ACCEPT_SERVER_USERAUTH_SENT,
    ACCEPT_SERVER_CHANNEL_ACCEPT_SENT,
    ACCEPT_CLIENT_SESSION_ESTABLISHED,
#ifdef WOLFSSH_SCP
    ACCEPT_INIT_SCP_TRANSFER,
#endif
#ifdef WOLFSSH_SFTP
    ACCEPT_INIT_SFTP,
#endif
#ifdef WOLFSSH_AGENT
    ACCEPT_INIT_AGENT,
#endif
};


enum ConnectStates {
    CONNECT_BEGIN = 0,
    CONNECT_CLIENT_VERSION_SENT,
    CONNECT_SERVER_VERSION_DONE,
    CONNECT_CLIENT_KEXINIT_SENT,
    CONNECT_SERVER_KEXINIT_DONE,
    CONNECT_CLIENT_KEXDH_INIT_SENT,
    CONNECT_KEYED,
    CONNECT_CLIENT_USERAUTH_REQUEST_SENT,
    CONNECT_SERVER_USERAUTH_REQUEST_DONE,
    CONNECT_CLIENT_USERAUTH_SENT,
    CONNECT_SERVER_USERAUTH_ACCEPT_DONE,
    CONNECT_CLIENT_CHANNEL_OPEN_SESSION_SENT,
    CONNECT_SERVER_CHANNEL_OPEN_SESSION_DONE,
    CONNECT_CLIENT_CHANNEL_AGENT_REQUEST_SENT,
    CONNECT_CLIENT_CHANNEL_TERMINAL_REQUEST_SENT,
    CONNECT_CLIENT_CHANNEL_REQUEST_SENT,
    CONNECT_SERVER_CHANNEL_REQUEST_DONE,
    CONNECT_CLIENT_AGENT_REQUEST_SENT,
    CONNECT_SERVER_AGENT_REQUEST_DONE,
    CONNECT_DONE
};


enum ClientStates {
    CLIENT_BEGIN = 0,
    CLIENT_VERSION_DONE,
    CLIENT_KEXINIT_DONE,
    CLIENT_KEXDH_INIT_DONE,
    CLIENT_USERAUTH_REQUEST_DONE,
    CLIENT_USERAUTH_DONE,
    CLIENT_CHANNEL_OPEN_DONE,
    CLIENT_DONE
};


enum ServerStates {
    SERVER_BEGIN = 0,
    SERVER_VERSION_DONE,
    SERVER_KEXINIT_DONE,
    SERVER_USERAUTH_REQUEST_DONE,
    SERVER_USERAUTH_ACCEPT_DONE,
    SERVER_CHANNEL_OPEN_DONE,
    SERVER_DONE
};


enum ProcessReplyStates {
    PROCESS_INIT,
    PROCESS_PACKET_LENGTH,
    PROCESS_PACKET_FINISH,
    PROCESS_PACKET
};


enum WS_MessageIds {
    MSGID_DISCONNECT = 1,
    MSGID_IGNORE = 2,
    MSGID_UNIMPLEMENTED = 3,
    MSGID_DEBUG = 4,
    MSGID_SERVICE_REQUEST = 5,
    MSGID_SERVICE_ACCEPT = 6,
    MSGID_EXT_INFO = 7,

    MSGID_KEXINIT = 20,
    MSGID_NEWKEYS = 21,

    MSGID_KEXDH_INIT = 30,
    MSGID_KEXECDH_INIT = 30,
#ifndef WOLFSSH_NO_NISTP256_MLKEM768_SHA256
    MSGID_KEXKEM_INIT = 30,
#endif

    MSGID_KEXDH_REPLY = 31,
    MSGID_KEXECDH_REPLY = 31,
#ifndef WOLFSSH_NO_NISTP256_MLKEM768_SHA256
    MSGID_KEXKEM_REPLY = 31,
#endif

    MSGID_KEXDH_GEX_GROUP = 31,
    MSGID_KEXDH_GEX_INIT = 32,
    MSGID_KEXDH_GEX_REPLY = 33,
    MSGID_KEXDH_GEX_REQUEST = 34,

    MSGID_USERAUTH_REQUEST = 50,
    MSGID_USERAUTH_FAILURE = 51,
    MSGID_USERAUTH_SUCCESS = 52,
    MSGID_USERAUTH_BANNER = 53,
    MSGID_USERAUTH_PK_OK = 60, /* Public Key OK */
    MSGID_USERAUTH_PW_CHRQ = 60, /* Password Change Request */
    MSGID_USERAUTH_INFO_REQUEST = 60,
    MSGID_USERAUTH_INFO_RESPONSE = 61,

    MSGID_GLOBAL_REQUEST = 80,
    MSGID_REQUEST_SUCCESS = 81,
    MSGID_REQUEST_FAILURE = 82,

    MSGID_CHANNEL_OPEN = 90,
    MSGID_CHANNEL_OPEN_CONF = 91,
    MSGID_CHANNEL_OPEN_FAIL = 92,
    MSGID_CHANNEL_WINDOW_ADJUST = 93,
    MSGID_CHANNEL_DATA = 94,
    MSGID_CHANNEL_EXTENDED_DATA = 95,
    MSGID_CHANNEL_EOF = 96,
    MSGID_CHANNEL_CLOSE = 97,
    MSGID_CHANNEL_REQUEST = 98,
    MSGID_CHANNEL_SUCCESS = 99,
    MSGID_CHANNEL_FAILURE = 100
};


/* Allows the server to receive up to KEXDH GEX Request during KEX. */
#define MSGID_KEXDH_LIMIT MSGID_KEXDH_GEX_REQUEST

/* The endpoints should not allow message IDs greater than or
 * equal to msgid 80 before user authentication is complete.
 * Per RFC 4252 section 6. */
#define MSGID_USERAUTH_LIMIT 80

/* The client should only send the user auth request message
 * (50), it should not accept it. The server should only receive
 * the user auth request message, it should not accept the other
 * user auth messages, it sends them. (>50) */
#define MSGID_USERAUTH_RESTRICT 50


#define CHANNEL_EXTENDED_DATA_STDERR WOLFSSH_EXT_DATA_STDERR


/* dynamic memory types */
enum WS_DynamicTypes {
    DYNTYPE_STRING = 500,
    DYNTYPE_CTX,
    DYNTYPE_SSH,
    DYNTYPE_CHANNEL,
    DYNTYPE_BUFFER,
    DYNTYPE_ID,
    DYNTYPE_HS,
    DYNTYPE_CA,
    DYNTYPE_CERT,
    DYNTYPE_PRIVKEY,
    DYNTYPE_PUBKEY,
    DYNTYPE_DH,
    DYNTYPE_RNG,
    DYNTYPE_MPINT,
    DYNTYPE_SCPCTX,
    DYNTYPE_SCPDIR,
    DYNTYPE_SFTP,
    DYNTYPE_SFTP_STATE,
    DYNTYPE_AGENT,
    DYNTYPE_AGENT_ID,
    DYNTYPE_AGENT_KEY,
    DYNTYPE_AGENT_BUFFER,
    DYNTYPE_CERTMAN,
    DYNTYPE_FILE,
    DYNTYPE_TEMP,
    DYNTYPE_PATH,
    DYNTYPE_SSHD
};


enum WS_BufferTypes {
    BUFTYPE_CA,
    BUFTYPE_CERT,
    BUFTYPE_PRIVKEY,
    BUFTYPE_PUBKEY
};


#ifdef WOLFSSH_SCP

#define SCP_MODE_OCTET_LEN 4     /* file mode is 4 characters (ex: 0777) */
#define SCP_MIN_CONFIRM_SZ 2     /* [cmd_byte]/0 */

#define SCP_CONFIRM_OK    0x00   /* binary 0 */
#define SCP_CONFIRM_ERR   0x01   /* binary 1 */
#define SCP_CONFIRM_FATAL 0x02   /* binary 2 */

enum WS_ScpStates {
    SCP_SETUP = 0,
    SCP_PARSE_COMMAND,
    SCP_SINK,
    SCP_SINK_BEGIN,
    SCP_TRANSFER,
    SCP_SOURCE,
    SCP_SOURCE_BEGIN,
    SCP_SOURCE_INIT,
    SCP_RECEIVE_MESSAGE,
    SCP_SEND_CONFIRMATION,
    SCP_CONFIRMATION_WITH_RECEIPT,
    SCP_RECEIVE_CONFIRMATION_WITH_RECEIPT,
    SCP_RECEIVE_CONFIRMATION,
    SCP_SEND_FILE,
    SCP_RECEIVE_FILE,
    SCP_SEND_FILE_HEADER,
    SCP_SEND_ENTER_DIRECTORY,
    SCP_SEND_EXIT_DIRECTORY,
    SCP_SEND_EXIT_DIRECTORY_FINAL,
    SCP_SEND_TIMESTAMP,
    SCP_DONE
};

enum WS_ScpMsgTypes {
    WOLFSSH_SCP_MSG_FILE = 0,
    WOLFSSH_SCP_MSG_TIME,
    WOLFSSH_SCP_MSG_DIR,
    WOLFSSH_SCP_MSG_END_DIR
};

enum WS_ScpDirection {
    WOLFSSH_SCP_DIR_NONE = 0,
    WOLFSSH_SCP_TO,
    WOLFSSH_SCP_FROM
};

WOLFSSH_LOCAL int ChannelCommandIsScp(WOLFSSH*);
WOLFSSH_LOCAL int DoScpRequest(WOLFSSH*);
WOLFSSH_LOCAL int DoScpSink(WOLFSSH* ssh);
WOLFSSH_LOCAL int DoScpSource(WOLFSSH* ssh);
WOLFSSH_LOCAL int ParseScpCommand(WOLFSSH*);
WOLFSSH_LOCAL int ReceiveScpMessage(WOLFSSH*);
WOLFSSH_LOCAL int ReceiveScpFile(WOLFSSH*);
WOLFSSH_LOCAL int SendScpConfirmation(WOLFSSH*);
WOLFSSH_LOCAL int ReceiveScpConfirmation(WOLFSSH*);

/* default SCP callbacks */
WOLFSSH_LOCAL int wsScpRecvCallback(WOLFSSH*, int, const char*, const char*,
                                    int, word64, word64, word32, byte*,
                                    word32, word32, void*);
WOLFSSH_LOCAL int wsScpSendCallback(WOLFSSH*, int, const char*, char*, word32,
                                    word64*, word64*, int*, word32, word32*,
                                    byte*, word32, void*);
#endif


WOLFSSH_LOCAL int wolfSSH_CleanPath(WOLFSSH* ssh, char* in);
#ifndef WOLFSSH_NO_RSA
WOLFSSH_LOCAL int wolfSSH_RsaVerify(
        const byte *sig, word32 sigSz,
        const byte* encDigest, word32 encDigestSz,
        RsaKey* key, void* heap, const char* loc);
#endif
WOLFSSH_LOCAL void DumpOctetString(const byte*, word32);
WOLFSSH_LOCAL int wolfSSH_oct2dec(WOLFSSH* ssh, byte* oct, word32 octSz);
WOLFSSH_LOCAL void AddAssign64(word32*, word32);

#ifdef WOLFSSH_TERM
/* values from section 8 of rfc 4254 */
enum TerminalModes {
    WOLFSSH_TTY_OP_END = 0,
    WOLFSSH_VINTR,
    WOLFSSH_VQUIT,
    WOLFSSH_VERASE,
    WOLFSSH_VKILL,
    WOLFSSH_VEOF,
    WOLFSSH_VEOL,
    WOLFSSH_VEOL2,
    WOLFSSH_VSTART,
    WOLFSSH_VSTOP,
    WOLFSSH_VSUSP,
    WOLFSSH_VDSUSP,
    WOLFSSH_VREPRINT,
    WOLFSSH_VWERASE,
    WOLFSSH_VLNEXT,
    WOLFSSH_VFLUSH,
    WOLFSSH_VSWTCH,
    WOLFSSH_VSTATUS,
    WOLFSSH_VDISCARD,
    WOLFSSH_IGNPAR = 30,
    WOLFSSH_PARMRK,
    WOLFSSH_INPCK,
    WOLFSSH_ISTRIP,
    WOLFSSH_INLCR,
    WOLFSSH_IGNCR,
    WOLFSSH_ICRNL,
    WOLFSSH_IUCLC,
    WOLFSSH_IXON,
    WOLFSSH_IXANY,
    WOLFSSH_IXOFF,
    WOLFSSH_IMAXBEL,
    WOLFSSH_IUTF8 = 42,
    WOLFSSH_ISIG = 50,
    WOLFSSH_ICANON,
    WOLFSSH_XCASE,
    WOLFSSH_ECHO,
    WOLFSSH_ECHOE,
    WOLFSSH_ECHOK,
    WOLFSSH_ECHONL,
    WOLFSSH_NOFLSH,
    WOLFSSH_TOSTOP,
    WOLFSSH_IEXTEN,
    WOLFSSH_ECHOCTL,
    WOLFSSH_ECHOKE,
    WOLFSSH_PENDIN,
    WOLFSSH_OPOST = 70,
    WOLFSSH_OLCUC,
    WOLFSSH_ONLCR,
    WOLFSSH_OCRNL,
    WOLFSSH_ONOCR,
    WOLFSSH_ONLRET,
    WOLFSSH_CS7 = 90,
    WOLFSSH_CS8,
    WOLFSSH_PARENB,
    WOLFSSH_PARODD,
    WOLFSSH_TTY_OP_ISPEED = 128,
    WOLFSSH_TTY_OP_OSPEED,
    WOLFSSH_TTY_INVALID = 160
};
#endif /* WOLFSSH_TERM */


#define WOLFSSL_V5_0_0 0x05000000
#define WOLFSSL_V5_7_0 0x05007000
#define WOLFSSL_V5_7_2 0x05007002


#ifdef __cplusplus
}
#endif

#endif /* _WOLFSSH_INTERNAL_H_ */


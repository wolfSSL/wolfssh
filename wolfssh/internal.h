/* internal.h
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


#pragma once

#include <wolfssh/ssh.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/dh.h>
#include <wolfssl/wolfcrypt/ecc.h>


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


WOLFSSH_LOCAL const char* GetErrorString(int);


enum {
    /* Any of the items can be none. */
    ID_NONE,

    /* Encryption IDs */
    ID_AES128_CBC,
    ID_AES128_GCM,

    /* Integrity IDs */
    ID_HMAC_SHA1,
    ID_HMAC_SHA1_96,
    ID_HMAC_SHA2_256,

    /* Key Exchange IDs */
    ID_DH_GROUP1_SHA1,
    ID_DH_GROUP14_SHA1,
    ID_DH_GEX_SHA256,
    ID_ECDH_SHA2_NISTP256,
    ID_ECDH_SHA2_NISTP384,
    ID_ECDH_SHA2_NISTP521,

    /* Public Key IDs */
    ID_SSH_RSA,
    ID_ECDSA_SHA2_NISTP256,
    ID_ECDSA_SHA2_NISTP384,
    ID_ECDSA_SHA2_NISTP521,

    /* Service IDs */
    ID_SERVICE_USERAUTH,
    ID_SERVICE_CONNECTION,

    /* UserAuth IDs */
    ID_USERAUTH_PASSWORD,
    ID_USERAUTH_PUBLICKEY,

    /* Channel Type IDs */
    ID_CHANTYPE_SESSION,

    ID_UNKNOWN
};


#define MAX_ENCRYPTION 3
#define MAX_INTEGRITY 2
#define MAX_KEY_EXCHANGE 2
#define MAX_PUBLIC_KEY 1
#define MAX_HMAC_SZ SHA256_DIGEST_SIZE
#define MIN_BLOCK_SZ 8
#define COOKIE_SZ 16
#define LENGTH_SZ 4
#define PAD_LENGTH_SZ 1
#define MIN_PAD_LENGTH 4
#define BOOLEAN_SZ 1
#define MSG_ID_SZ 1
#define SHA1_96_SZ 12
#define UINT32_SZ 4
#define SSH_PROTO_SZ 7 /* "SSH-2.0" */
#define SSH_PROTO_EOL_SZ 2 /* Just the CRLF */
#define AEAD_IMP_IV_SZ 4
#define AEAD_EXP_IV_SZ 8
#define AEAD_NONCE_SZ (AEAD_IMP_IV_SZ+AEAD_EXP_IV_SZ)
#ifndef DEFAULT_HIGHWATER_MARK
    #define DEFAULT_HIGHWATER_MARK ((1024 * 1024 * 1024) - (32 * 1024))
#endif
#ifndef DEFAULT_WINDOW_SZ
    #define DEFAULT_WINDOW_SZ (1024 * 1024)
#endif
#ifndef DEFAULT_MAX_PACKET_SZ
    #define DEFAULT_MAX_PACKET_SZ (16 * 1024)
#endif
#define DEFAULT_NEXT_CHANNEL 13013


WOLFSSH_LOCAL byte NameToId(const char*, word32);
WOLFSSH_LOCAL const char* IdToName(byte);


#define STATIC_BUFFER_LEN AES_BLOCK_SIZE
/* This is one AES block size. We always grab one
 * block size first to decrypt to find the size of
 * the rest of the data. */


typedef struct Buffer {
    void* heap;       /* Heap for allocations */
    word32 length;    /* total buffer length used */
    word32 idx;       /* idx to part of length already consumed */
    byte* buffer;     /* place holder for actual buffer */
    word32 bufferSz;  /* current buffer size */
    ALIGN16 byte staticBuffer[STATIC_BUFFER_LEN];
    byte dynamicFlag; /* dynamic memory currently in use */
} Buffer;


WOLFSSH_LOCAL int BufferInit(Buffer*, word32, void*);
WOLFSSH_LOCAL int GrowBuffer(Buffer*, word32, word32);
WOLFSSH_LOCAL void ShrinkBuffer(Buffer* buf, int);


/* our wolfSSH Context */
struct WOLFSSH_CTX {
    void* heap;                       /* heap hint */
    WS_CallbackIORecv ioRecvCb;       /* I/O Receive Callback */
    WS_CallbackIOSend ioSendCb;       /* I/O Send Callback */
    WS_CallbackUserAuth userAuthCb;   /* User Authentication Callback */
    WS_CallbackHighwater highwaterCb; /* Data Highwater Mark Callback */

    byte* privateKey;                 /* Owned by CTX */
    word32 privateKeySz;
    byte useEcc;                      /* Depends on the private key */
    word32 highwaterMark;
    const char* banner;
    word32 bannerSz;

    byte side;                        /* client or server */
};


typedef struct Ciphers {
    Aes aes;
} Ciphers;


typedef struct Keys {
    byte iv[AES_BLOCK_SIZE];
    byte ivSz;
    byte encKey[AES_BLOCK_SIZE];
    byte encKeySz;
    byte macKey[MAX_HMAC_SZ];
    byte macKeySz;
} Keys;


typedef struct HandshakeInfo {
    byte kexId;
    byte pubKeyId;
    byte encryptId;
    byte macId;
    byte hashId;
    byte kexPacketFollows;
    byte aeadMode;

    byte blockSz;
    byte macSz;

    Keys keys;
    Keys peerKeys;
    wc_HashAlg hash;
    byte e[257]; /* May have a leading zero for unsigned or is a Q_S value. */
    word32 eSz;
    byte x[257]; /* May have a leading zero, for unsigned. */
    word32 xSz;
    byte* kexInit;
    word32 kexInitSz;

    word32 dhGexMinSz;
    word32 dhGexPreferredSz;
    word32 dhGexMaxSz;
    byte* primeGroup;
    word32 primeGroupSz;
    byte* generator;
    word32 generatorSz;

    byte useEcc;
    union {
        DhKey dh;
        ecc_key ecc;
    } privKey;
} HandshakeInfo;


/* our wolfSSH session */
struct WOLFSSH {
    WOLFSSH_CTX* ctx;      /* owner context */
    int error;
    int rfd;
    int wfd;
    void* ioReadCtx;       /* I/O Read  Context handle */
    void* ioWriteCtx;      /* I/O Write Context handle */
    int rflags;            /* optional read  flags */
    int wflags;            /* optional write flags */
    word32 txCount;
    word32 rxCount;
    word32 highwaterMark;
    byte highwaterFlag;    /* Set when highwater CB called */
    void* highwaterCtx;
    word32 curSz;
    word32 seq;
    word32 peerSeq;
    word32 packetStartIdx; /* Current send packet start index */
    byte paddingSz;        /* Current send packet padding size */
    byte acceptState;
    byte connectState;
    byte clientState;
    byte serverState;
    byte processReplyState;
    byte isKeying;

    byte connReset;
    byte isClosed;

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

    Ciphers encryptCipher;
    Ciphers decryptCipher;

    word32 nextChannel;
    WOLFSSH_CHANNEL* channelList;
    word32 channelListSz;
    word32 defaultPeerChannelId;

    Buffer inputBuffer;
    Buffer outputBuffer;
    WC_RNG* rng;

    byte h[WC_MAX_DIGEST_SIZE];
    word32 hSz;
    byte k[257];           /* May have a leading zero, for unsigned. */
    word32 kSz;
    byte sessionId[WC_MAX_DIGEST_SIZE];
    word32 sessionIdSz;

    Keys keys;
    Keys peerKeys;
    HandshakeInfo* handshake;

    void* userAuthCtx;
    byte* userName;
    word32 userNameSz;
    byte* pkBlob;
    word32 pkBlobSz;
    byte* peerProtoId;     /* Save for rekey */
    word32 peerProtoIdSz;
};


struct WOLFSSH_CHANNEL {
    byte channelType;
    word32 channel;
    word32 windowSz;
    word32 maxPacketSz;
    word32 peerChannel;
    word32 peerWindowSz;
    word32 peerMaxPacketSz;
    Buffer inputBuffer;
    struct WOLFSSH* ssh;
    struct WOLFSSH_CHANNEL* next;
};


WOLFSSH_LOCAL WOLFSSH_CTX* CtxInit(WOLFSSH_CTX*, byte, void*);
WOLFSSH_LOCAL void CtxResourceFree(WOLFSSH_CTX*);
WOLFSSH_LOCAL WOLFSSH* SshInit(WOLFSSH*, WOLFSSH_CTX*);
WOLFSSH_LOCAL void SshResourceFree(WOLFSSH*, void*);

WOLFSSH_LOCAL WOLFSSH_CHANNEL* ChannelNew(WOLFSSH*, byte, word32,
                                          word32, word32);
WOLFSSH_LOCAL void ChannelDelete(WOLFSSH_CHANNEL*, void*);
WOLFSSH_LOCAL WOLFSSH_CHANNEL* ChannelFind(WOLFSSH*, word32, byte);
WOLFSSH_LOCAL int ChannelRemove(WOLFSSH*, word32, byte);
WOLFSSH_LOCAL int ChannelPutData(WOLFSSH_CHANNEL*, byte*, word32);
WOLFSSH_LOCAL int ProcessBuffer(WOLFSSH_CTX*, const byte*, word32, int, int);


#ifndef WOLFSSH_USER_IO

/* default I/O handlers */
WOLFSSH_LOCAL int wsEmbedRecv(WOLFSSH*, void*, word32, void*);
WOLFSSH_LOCAL int wsEmbedSend(WOLFSSH*, void*, word32, void*);

#endif /* WOLFSSH_USER_IO */


WOLFSSH_LOCAL int DoReceive(WOLFSSH*);
WOLFSSH_LOCAL int DoProtoId(WOLFSSH*);
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
WOLFSSH_LOCAL int SendDebug(WOLFSSH*, byte, const char*);
WOLFSSH_LOCAL int SendServiceRequest(WOLFSSH*, byte);
WOLFSSH_LOCAL int SendServiceAccept(WOLFSSH*, byte);
WOLFSSH_LOCAL int SendUserAuthRequest(WOLFSSH*, byte);
WOLFSSH_LOCAL int SendUserAuthSuccess(WOLFSSH*);
WOLFSSH_LOCAL int SendUserAuthFailure(WOLFSSH*, byte);
WOLFSSH_LOCAL int SendUserAuthBanner(WOLFSSH*);
WOLFSSH_LOCAL int SendUserAuthPkOk(WOLFSSH*, const byte*, word32,
                                   const byte*, word32);
WOLFSSH_LOCAL int SendRequestSuccess(WOLFSSH*, int);
WOLFSSH_LOCAL int SendChannelOpenConf(WOLFSSH*);
WOLFSSH_LOCAL int SendChannelEof(WOLFSSH*, word32);
WOLFSSH_LOCAL int SendChannelClose(WOLFSSH*, word32);
WOLFSSH_LOCAL int SendChannelData(WOLFSSH*, word32, byte*, word32);
WOLFSSH_LOCAL int SendChannelWindowAdjust(WOLFSSH*, word32, word32);
WOLFSSH_LOCAL int SendChannelSuccess(WOLFSSH*, word32, int);
WOLFSSH_LOCAL int GenerateKey(byte, byte, byte*, word32, const byte*, word32,
                              const byte*, word32, const byte*, word32);


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
    ACCEPT_CLIENT_CHANNEL_REQUEST_DONE,
    ACCEPT_SERVER_CHANNEL_ACCEPT_SENT
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
    CONNECT_SERVER_USERAUTH_ACCEPT_DONE
};


enum ClientStates {
    CLIENT_BEGIN = 0,
    CLIENT_VERSION_DONE,
    CLIENT_KEXINIT_DONE,
    CLIENT_KEXDH_INIT_DONE,
    CLIENT_USERAUTH_REQUEST_DONE,
    CLIENT_USERAUTH_DONE,
    CLIENT_DONE
};


enum ServerStates {
    SERVER_BEGIN = 0,
    SERVER_VERSION_DONE,
    SERVER_KEXINIT_DONE,
    SERVER_USERAUTH_REQUEST_DONE,
    SERVER_USERAUTH_ACCEPT_DONE
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

    MSGID_KEXINIT = 20,
    MSGID_NEWKEYS = 21,

    MSGID_KEXDH_INIT = 30,
    MSGID_KEXECDH_INIT = 30,

    MSGID_KEXDH_REPLY = 31,
    MSGID_KEXECDH_REPLY = 31,
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

    MSGID_GLOBAL_REQUEST = 80,
    MSGID_REQUEST_SUCCESS = 81,
    MSGID_REQUEST_FAILURE = 82,

    MSGID_CHANNEL_OPEN = 90,
    MSGID_CHANNEL_OPEN_CONF = 91,
    MSGID_CHANNEL_WINDOW_ADJUST = 93,
    MSGID_CHANNEL_DATA = 94,
    MSGID_CHANNEL_EOF = 96,
    MSGID_CHANNEL_CLOSE = 97,
    MSGID_CHANNEL_REQUEST = 98,
    MSGID_CHANNEL_SUCCESS = 99,
    MSGID_CHANNEL_FAILURE = 100
};


/* dynamic memory types */
enum WS_DynamicTypes {
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
    DYNTYPE_STRING,
    DYNTYPE_MPINT
};


enum WS_BufferTypes {
    BUFTYPE_CA,
    BUFTYPE_CERT,
    BUFTYPE_PRIVKEY,
    BUFTYPE_PUBKEY
};


WOLFSSH_LOCAL void DumpOctetString(const byte*, word32);


#ifdef __cplusplus
}
#endif


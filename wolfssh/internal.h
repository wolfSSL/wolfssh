/* internal.h
 *
 * Copyright (C) 2014-2016 wolfSSL Inc.
 *
 * This file is part of wolfSSH.
 *
 * wolfSSH is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSH is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA  02110-1301, USA.
 */


/*
 * The internal module contains the private data and functions. The public
 * API calls into this module to do the work of processing the connections.
 */


#pragma once

#include <wolfssh/ssh.h>
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/sha.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/dh.h>
#include <wolfssl/wolfcrypt/aes.h>


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
    ID_AES128_CTR,
    ID_AES128_GCM_WOLF,

    /* Integrity IDs */
    ID_HMAC_SHA1,
    ID_HMAC_SHA1_96,

    /* Key Exchange IDs */
    ID_DH_GROUP1_SHA1,
    ID_DH_GROUP14_SHA1,

    /* Public Key IDs */
    ID_SSH_RSA,

    /* UserAuth IDs */
    ID_USERAUTH_PASSWORD,
    ID_USERAUTH_PUBLICKEY,

    /* Channel Type IDs */
    ID_CHANTYPE_SESSION,

    ID_UNKNOWN
};


#define MAX_ENCRYPTION   3
#define MAX_INTEGRITY    2
#define MAX_KEY_EXCHANGE 2
#define MAX_PUBLIC_KEY   1
#define MIN_BLOCK_SZ     8
#define COOKIE_SZ        16
#define LENGTH_SZ        4
#define PAD_LENGTH_SZ    1
#define BOOLEAN_SZ       1
#define MSG_ID_SZ        1
#define SHA1_96_SZ       12
#define UINT32_SZ        4
#define DEFAULT_WINDOW_SZ     (1024 * 1024)
#define DEFAULT_MAX_PACKET_SZ (16 * 1024)
#define DEFAULT_NEXT_CHANNEL  13013


WOLFSSH_LOCAL uint8_t     NameToId(const char*, uint32_t);
WOLFSSH_LOCAL const char* IdToName(uint8_t);


#define STATIC_BUFFER_LEN AES_BLOCK_SIZE
/* This is one AES block size. We always grab one
 * block size first to decrypt to find the size of
 * the rest of the data. */


typedef struct Buffer {
    void*           heap;         /* Heap for allocations */
    uint32_t        length;       /* total buffer length used */
    uint32_t        idx;          /* idx to part of length already consumed */
    uint8_t*        buffer;       /* place holder for actual buffer */
    uint32_t        bufferSz;     /* current buffer size */
    ALIGN16 uint8_t staticBuffer[STATIC_BUFFER_LEN];
    uint8_t         dynamicFlag;  /* dynamic memory currently in use */
} Buffer;


WOLFSSH_LOCAL int BufferInit(Buffer*, uint32_t, void*);
WOLFSSH_LOCAL int GrowBuffer(Buffer*, uint32_t, uint32_t);
WOLFSSH_LOCAL void ShrinkBuffer(Buffer* buf, int);


/* our wolfSSH Context */
struct WOLFSSH_CTX {
    void*               heap;        /* heap hint */
    WS_CallbackIORecv   ioRecvCb;    /* I/O Receive Callback */
    WS_CallbackIOSend   ioSendCb;    /* I/O Send Callback */
    WS_CallbackUserAuth userAuthCb;  /* User Authentication Callback */

    uint8_t*            cert;        /* Owned by CTX */
    uint32_t            certSz;
    uint8_t*            caCert;      /* Owned by CTX */
    uint32_t            caCertSz;
    uint8_t*            privateKey;  /* Owned by CTX */
    uint32_t            privateKeySz;
};


typedef struct Ciphers {
    Aes aes;
} Ciphers;


typedef struct HandshakeInfo {
    uint8_t        kexId;
    uint8_t        pubKeyId;
    uint8_t        encryptId;
    uint8_t        macId;
    uint8_t        kexPacketFollows;

    uint8_t        blockSz;
    uint8_t        macSz;

    Sha            hash;
    uint8_t        e[257]; /* May have a leading zero, for unsigned. */
    uint32_t       eSz;
} HandshakeInfo;


typedef struct Channel {
    uint8_t  inUse;
    uint8_t  channelType;
    uint32_t channel;
    uint32_t windowSz;
    uint32_t highwaterMark;
    uint32_t maxPacketSz;
    uint32_t peerChannel;
    uint32_t peerWindowSz;
    uint32_t peerMaxPacketSz;
    Buffer   inputBuffer;
} Channel;


/* our wolfSSH session */
struct WOLFSSH {
    WOLFSSH_CTX*   ctx;            /* owner context */
    int            error;
    int            rfd;
    int            wfd;
    void*          ioReadCtx;      /* I/O Read  Context handle */
    void*          ioWriteCtx;     /* I/O Write Context handle */
    int            rflags;         /* optional read  flags */
    int            wflags;         /* optional write flags */
    uint32_t       txCount;
    uint32_t       rxCount;
    uint32_t       countHighwater;
    uint32_t       curSz;
    uint32_t       seq;
    uint32_t       peerSeq;
    uint32_t       packetStartIdx; /* Current send packet start index */
    uint8_t        paddingSz;      /* Current send packet padding size */
    uint8_t        acceptState;
    uint8_t        clientState;
    uint8_t        processReplyState;

    uint8_t        connReset;
    uint8_t        isClosed;

    uint8_t        blockSz;
    uint8_t        encryptId;
    uint8_t        macId;
    uint8_t        macSz;
    uint8_t        peerBlockSz;
    uint8_t        peerEncryptId;
    uint8_t        peerMacId;
    uint8_t        peerMacSz;

    Ciphers        encryptCipher;
    Ciphers        decryptCipher;

    uint32_t       nextChannel;
    Channel        channel;

    Buffer         inputBuffer;
    Buffer         outputBuffer;
    RNG*           rng;

    uint8_t        h[SHA_DIGEST_SIZE];
    uint32_t       hSz;
    uint8_t        k[257]; /* May have a leading zero, for unsigned. */
    uint32_t       kSz;
    uint8_t        sessionId[SHA_DIGEST_SIZE];
    uint32_t       sessionIdSz;

    uint8_t        ivClient[AES_BLOCK_SIZE];
    uint8_t        ivClientSz;
    uint8_t        ivServer[AES_BLOCK_SIZE];
    uint8_t        ivServerSz;
    uint8_t        encKeyClient[AES_BLOCK_SIZE];
    uint8_t        encKeyClientSz;
    uint8_t        encKeyServer[AES_BLOCK_SIZE];
    uint8_t        encKeyServerSz;
    uint8_t        macKeyClient[SHA_DIGEST_SIZE];
    uint8_t        macKeyClientSz;
    uint8_t        macKeyServer[SHA_DIGEST_SIZE];
    uint8_t        macKeyServerSz;

    HandshakeInfo* handshake;

    void*          userAuthCtx;
    uint8_t*       userName;
    uint32_t       userNameSz;
    uint8_t*       pkBlob;
    uint32_t       pkBlobSz;
};


#ifndef WOLFSSH_USER_IO

/* default I/O handlers */
WOLFSSH_LOCAL int wsEmbedRecv(WOLFSSH*, void*, uint32_t, void*);
WOLFSSH_LOCAL int wsEmbedSend(WOLFSSH*, void*, uint32_t, void*);

#endif /* WOLFSSH_USER_IO */


WOLFSSH_LOCAL int ProcessReply(WOLFSSH*);
WOLFSSH_LOCAL int ProcessClientVersion(WOLFSSH*);
WOLFSSH_LOCAL int SendServerVersion(WOLFSSH*);
WOLFSSH_LOCAL int SendKexInit(WOLFSSH*);
WOLFSSH_LOCAL int SendKexDhReply(WOLFSSH*);
WOLFSSH_LOCAL int SendNewKeys(WOLFSSH*);
WOLFSSH_LOCAL int SendUnimplemented(WOLFSSH*);
WOLFSSH_LOCAL int SendDisconnect(WOLFSSH*, uint32_t);
WOLFSSH_LOCAL int SendIgnore(WOLFSSH*, const unsigned char*, uint32_t);
WOLFSSH_LOCAL int SendDebug(WOLFSSH*, byte, const char*);
WOLFSSH_LOCAL int SendServiceAccept(WOLFSSH*);
WOLFSSH_LOCAL int SendUserAuthSuccess(WOLFSSH*);
WOLFSSH_LOCAL int SendUserAuthFailure(WOLFSSH*, uint8_t);
WOLFSSH_LOCAL int SendUserAuthBanner(WOLFSSH*);
WOLFSSH_LOCAL int SendUserAuthPkOk(WOLFSSH*, const uint8_t*, uint32_t,
                                   const uint8_t*, uint32_t);
WOLFSSH_LOCAL int SendChannelOpenConf(WOLFSSH* ssh);
WOLFSSH_LOCAL int SendChannelData(WOLFSSH* ssh, uint32_t, uint8_t*, uint32_t);
WOLFSSH_LOCAL int GenerateKey(uint8_t, uint8_t, uint8_t*, uint32_t,
                              const uint8_t*, uint32_t,
                              const uint8_t*, uint32_t,
                              const uint8_t*, uint32_t);


enum AcceptStates {
    ACCEPT_BEGIN = 0,
    ACCEPT_CLIENT_VERSION_DONE,
    ACCEPT_SERVER_VERSION_SENT,
    ACCEPT_CLIENT_KEXINIT_DONE,
    ACCEPT_SERVER_KEXINIT_SENT,
    ACCEPT_CLIENT_KEXDH_INIT_DONE,
    ACCEPT_SERVER_KEXDH_REPLY_SENT,
    ACCEPT_USING_KEYS,
    ACCEPT_CLIENT_USERAUTH_REQUEST_DONE,
    ACCEPT_SERVER_USERAUTH_ACCEPT_SENT,
    ACCEPT_CLIENT_USERAUTH_DONE,
    ACCEPT_SERVER_USERAUTH_SENT,
    ACCEPT_CLIENT_CHANNEL_REQUEST_DONE,
    ACCEPT_SERVER_CHANNEL_ACCEPT_SENT
};


enum ClientStates {
    CLIENT_BEGIN = 0,
    CLIENT_VERSION_DONE,
    CLIENT_KEXINIT_DONE,
    CLIENT_KEXDH_INIT_DONE,
    CLIENT_USING_KEYS,
    CLIENT_USERAUTH_REQUEST_DONE,
    CLIENT_USERAUTH_DONE,
    CLIENT_DONE
};


enum ProcessReplyStates {
    PROCESS_INIT,
    PROCESS_PACKET_LENGTH,
    PROCESS_PACKET_FINISH,
    PROCESS_PACKET
};


enum WS_MessageIds {
    MSGID_DISCONNECT      = 1,
    MSGID_IGNORE          = 2,
    MSGID_UNIMPLEMENTED   = 3,
    MSGID_DEBUG           = 4,
    MSGID_SERVICE_REQUEST = 5,
    MSGID_SERVICE_ACCEPT  = 6,

    MSGID_KEXINIT         = 20,
    MSGID_NEWKEYS         = 21,

    MSGID_KEXDH_INIT      = 30,
    MSGID_KEXDH_REPLY     = 31,

    MSGID_USERAUTH_REQUEST = 50,
    MSGID_USERAUTH_FAILURE = 51,
    MSGID_USERAUTH_SUCCESS = 52,
    MSGID_USERAUTH_BANNER  = 53,
    MSGID_USERAUTH_PK_OK   = 60,

    MSGID_CHANNEL_OPEN      = 90,
    MSGID_CHANNEL_OPEN_CONF = 91,
    MSGID_CHANNEL_WINDOW_ADJUST = 93,
    MSGID_CHANNEL_DATA      = 94,
    MSGID_CHANNEL_REQUEST   = 98
};


/* dynamic memory types */
enum WS_DynamicTypes {
    DYNTYPE_CTX,
    DYNTYPE_SSH,
    DYNTYPE_BUFFER,
    DYNTYPE_ID,
    DYNTYPE_HS,
    DYNTYPE_CA,
    DYNTYPE_CERT,
    DYNTYPE_KEY,
    DYNTYPE_DH,
    DYNTYPE_RNG,
    DYNTYPE_STRING
};


enum WS_BufferTypes {
    BUFTYPE_CA,
    BUFTYPE_CERT,
    BUFTYPE_PRIVKEY
};


WOLFSSH_LOCAL void DumpOctetString(const uint8_t*, uint32_t);


#ifdef __cplusplus
}
#endif


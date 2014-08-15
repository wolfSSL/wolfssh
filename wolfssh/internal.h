/* internal.h
 *
 * Copyright (C) 2014 wolfSSL Inc.
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
#include <cyassl/ctaocrypt/sha.h>


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

    ID_UNKNOWN
};


#define MAX_ENCRYPTION   3
#define MAX_INTEGRITY    2
#define MAX_KEY_EXCHANGE 2
#define MAX_PUBLIC_KEY   1
#define COOKIE_SZ        16
#define LENGTH_SZ        4
#define PAD_LENGTH_SZ    1


WOLFSSH_LOCAL uint8_t     NameToId(const char*, uint32_t);
WOLFSSH_LOCAL const char* IdToName(uint8_t);


#define STATIC_BUFFER_LEN 16
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
    uint32_t        offset;       /* Offset from start of buffer to data. */
} Buffer;

WOLFSSH_LOCAL int BufferInit(Buffer*, uint32_t, void*);
WOLFSSH_LOCAL int GrowBuffer(Buffer*, uint32_t, uint32_t);
WOLFSSH_LOCAL void ShrinkBuffer(Buffer* buf, int);


/* our wolfSSH Context */
struct WOLFSSH_CTX {
    void*             heap;        /* heap hint */
    WS_CallbackIORecv ioRecvCb;    /* I/O Receive Callback */
    WS_CallbackIOSend ioSendCb;    /* I/O Send    Callback */
};


typedef struct HandshakeInfo {
    uint8_t        keyExchangeId;
    uint8_t        publicKeyId;
    uint8_t        encryptionId;
    uint8_t        integrityId;
    uint8_t        kexPacketFollows;

    Sha            hash;
    uint8_t        session_id[SHA_DIGEST_SIZE];
} HandshakeInfo;


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
    uint32_t       curSz;
    uint32_t       seq;
    uint32_t       peerSeq;
    uint8_t        blockSz;
    uint8_t        acceptState;
    uint8_t        clientState;
    uint8_t        processReplyState;

    uint8_t        connReset;
    uint8_t        isClosed;

    uint8_t        keyExchangeId;
    uint8_t        publicKeyId;
    uint8_t        encryptionId;
    uint8_t        integrityId;

    Buffer         inputBuffer;
    Buffer         outputBuffer;

    uint8_t        H[SHA_DIGEST_SIZE];

    HandshakeInfo* handshake;
};


#ifndef WOLFSSH_USER_IO

/* default I/O handlers */
WOLFSSH_LOCAL int wsEmbedRecv(WOLFSSH*, void*, uint32_t, void*);
WOLFSSH_LOCAL int wsEmbedSend(WOLFSSH*, void*, uint32_t, void*);

#endif /* WOLFSSH_USER_IO */


WOLFSSH_LOCAL int ProcessReply(WOLFSSH*);
WOLFSSH_LOCAL int ProcessClientVersion(WOLFSSH*);
WOLFSSH_LOCAL int SendServerVersion(WOLFSSH*);


enum AcceptStates {
    ACCEPT_BEGIN = 0,
    ACCEPT_CLIENT_VERSION_DONE,
    SERVER_VERSION_SENT,
    ACCEPT_CLIENT_ALGO_DONE,
    SERVER_ALGO_SENT
};


enum ClientStates {
    CLIENT_BEGIN = 0,
    CLIENT_VERSION_DONE,
    CLIENT_ALGO_DONE
};


enum ProcessReplyStates {
    PROCESS_INIT,
    PROCESS_PACKET_LENGTH,
    PROCESS_PACKET_FINISH,
    PROCESS_PACKET
};


enum SshMessageIds {
    SSH_MSG_KEXINIT = 20,
    SSH_MSG_NEWKEYS = 21
};


WOLFSSH_LOCAL int ProcessClientVersion(WOLFSSH*);
WOLFSSH_LOCAL int SendServerVersion(WOLFSSH*);


/* dynamic memory types */
enum WS_DynamicTypes {
    DYNTYPE_CTX,
    DYNTYPE_SSH,
    DYNTYPE_BUFFER,
    DYNTYPE_ID,
    DYNTYPE_HS,
    DYNTYPE_CA,
    DYNTYPE_CERT,
    DYNTYPE_KEY
};


enum WS_BufferTypes {
    BUFTYPE_CA,
    BUFTYPE_CERT,
    BUFTYPE_PRIVKEY
};


#ifdef __cplusplus
}
#endif


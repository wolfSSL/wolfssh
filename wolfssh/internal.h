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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */


#pragma once

#include <wolfssh/ssh.h>


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


enum {
    /* Any of the items can be none. */
    ID_NONE = 0,

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


WOLFSSH_LOCAL uint8_t     NameToId(const char*);
WOLFSSH_LOCAL const char* IdToName(uint8_t);


/* our wolfSSH Context */
struct WOLFSSH_CTX {
    void*             heap;        /* heap hint */
    WS_CallbackIORecv ioRecvCb;    /* I/O Receive Callback */
    WS_CallbackIOSend ioSendCb;    /* I/O Send    Callback */
};


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
    WOLFSSH_CHAN*  channel;        /* single data channel */
    uint32_t       curSz;
    uint8_t        blockSz;
    uint8_t        acceptState;
    uint8_t        clientState;
    uint8_t        processReplyState;
    uint8_t        connReset;
    uint8_t        isClosed;

    uint8_t        encryptionId;
    uint8_t        integrityId;
    uint8_t        keyExchangeId;
    uint8_t        publicKeyId;

    char*          peerId;
    /* The lengths of the lists are contrained to how many of choices
     * we actually support. */
    uint8_t        peerEncryptionList[MAX_ENCRYPTION];
    uint8_t        peerEncryptionListSz;
    uint8_t        peerIntegrityList[MAX_INTEGRITY];
    uint8_t        peerIntegrityListSz;
    uint8_t        peerKeyExchangeList[MAX_KEY_EXCHANGE];
    uint8_t        peerKeyExchangeListSz;
    uint8_t        peerPublicKeyList[MAX_PUBLIC_KEY];
    uint8_t        peerPublicKeyListSz;

    struct Buffer* inputBuffer;
    struct Buffer* outputBuffer;
};


/* wolfSSH channel */
struct WOLFSSH_CHAN {
    WOLFSSH_CTX* ctx;
    WOLFSSH*     ssh;
    int          id;
};


#ifndef WOLFSSH_USER_IO

/* default I/O handlers */
WOLFSSH_LOCAL int wsEmbedRecv(WOLFSSH* ssh, void*, uint32_t sz, void* ctx);
WOLFSSH_LOCAL int wsEmbedSend(WOLFSSH* ssh, void*, uint32_t sz, void* ctx);

#endif /* WOLFSSH_USER_IO */


WOLFSSH_LOCAL int ProcessReply(WOLFSSH*);
WOLFSSH_LOCAL int SendServerVersion(WOLFSSH*);
WOLFSSH_LOCAL int DoClientVersion(WOLFSSH*);


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


WOLFSSH_LOCAL Buffer* BufferNew(uint32_t, void*);
WOLFSSH_LOCAL void BufferFree(Buffer*);
WOLFSSH_LOCAL int GrowBuffer(Buffer*, uint32_t);
WOLFSSH_LOCAL int ShrinkBuffer(Buffer* buf);


WOLFSSH_LOCAL int ProcessClientVersion(WOLFSSH*);
WOLFSSH_LOCAL int SendServerVersion(WOLFSSH*);

#ifdef __cplusplus
}
#endif


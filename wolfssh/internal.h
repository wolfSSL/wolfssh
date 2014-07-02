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

#ifdef __cplusplus
extern "C" {
#endif


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


WOLFSSH_LOCAL uint8_t     NameToId(const char*);
WOLFSSH_LOCAL const char* IdToName(uint8_t);


/* our wolfSSH Context */
struct WOLFSSH_CTX {
    void*             heap;        /* heap hint */
    WS_CallbackIORecv ioRecvCb;    /* I/O Receive Callback */
    WS_CallbackIOSend ioSendCb;    /* I/O Send    Callback */
    uint8_t           compression;
};


/* our wolfSSH session */
struct WOLFSSH {
    WOLFSSH_CTX*  ctx;            /* owner context */
    int           error;
    int           rfd;
    int           wfd;
    void*         ioReadCtx;      /* I/O Read  Context handle */
    void*         ioWriteCtx;     /* I/O Write Context handle */
    int           rflags;         /* optional read  flags */
    int           wflags;         /* optional write flags */
    WOLFSSH_CHAN  *channel;       /* single data channel */
    uint8_t       blockSz;
    uint8_t       acceptState;
    uint8_t       processReply;
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


enum {
    ACCEPT_BEGIN = 0,
    CLIENT_VERSION_DONE,
    SERVER_VERSION_SENT,
};


#ifdef __cplusplus
}
#endif


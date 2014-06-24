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


/* our wolfSSH Context */
struct WOLFSSH_CTX {
    void*             heap;        /* heap hint */
    WS_CallbackIORecv ioRecvCb;    /* I/O Receive Callback */
    WS_CallbackIOSend ioSendCb;    /* I/O Send    Callback */
};


/* our wolfSSH session */
struct WOLFSSH {
    WOLFSSH_CTX*  ctx;            /* owner context */
    void*         ioReadCtx;      /* I/O Read  Context handle */
    void*         ioWriteCtx;     /* I/O Write Context handle */
    int           rflags;         /* optional read  flags */
    int           wflags;         /* optional write flags */
};


#ifndef WOLFSSH_USER_IO

/* default I/O handlers */
WOLFSSH_LOCAL int wsEmbedRecv(WOLFSSH* ssh, void*, uint32_t sz, void* ctx);
WOLFSSH_LOCAL int wsEmbedSend(WOLFSSH* ssh, void*, uint32_t sz, void* ctx);

#endif /* WOLFSSH_USER_IO */

#ifdef __cplusplus
}
#endif


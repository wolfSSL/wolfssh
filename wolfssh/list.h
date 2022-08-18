/* list.h
 *
 * Copyright (C) 2014-2022 wolfSSL Inc.
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

#ifndef _WOLFSSH_LIST_H_
#define _WOLFSSH_LIST_H_

#ifdef WOLFSSL_USER_SETTINGS
#include <wolfssl/wolfcrypt/settings.h>
#else
#include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/types.h>

#include <wolfssh/settings.h>

#ifdef __cplusplus
extern "C" {
#endif

struct WOLFSSH_OSSH_CA_KEY;
struct WOLFSSH_OSSH_PRINCIPAL;

struct WOLFSSH_LIST_NODE {
    byte type;
    union {
    #ifdef WOLFSSH_OSSH_CERTS
        struct WOLFSSH_OSSH_CA_KEY* osshCaKey;
        struct WOLFSSH_OSSH_PRINCIPAL* osshPrincipal;
    #endif /* WOLFSSH_OSSH_CERTS */
        void* raw;
    } data;
    struct WOLFSSH_LIST_NODE* next;
};
typedef struct WOLFSSH_LIST_NODE WOLFSSH_LIST_NODE;

typedef struct {
    byte type;
    WOLFSSH_LIST_NODE* head;
    void* heap;
} WOLFSSH_LIST;

enum {
    LIST_OSSH_CA_KEY = 1,
    LIST_OSSH_PRINCIPAL = 2
};

WOLFSSH_LOCAL WOLFSSH_LIST* ListNew(byte type, void* heap);
WOLFSSH_LOCAL void ListFree(WOLFSSH_LIST* list);
WOLFSSH_LOCAL int ListAdd(WOLFSSH_LIST* list, void* data);
WOLFSSH_LOCAL int ListFind(WOLFSSH_LIST* list, const byte* in, word32 inSz);

#ifdef __cplusplus
}
#endif

#endif /* _WOLFSSH_LIST_H_ */

/* list.c
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

#include <wolfssh/list.h>
#include <wolfssh/internal.h>

/*
 * This is a singly-linked list implementation for use in wolfSSH. It's not
 * designed to be a fully generic linked list; it doesn't support arbitrary
 * types, and some changes are required to the implementation to support a new
 * type. Additionally, not all list operations are supported at this time (e.g.
 * node removal). Only those operations needed have been implemented.
 *
 * We needed a linked list for a few, distinct cases when developing support for
 * OpenSSH-style certs, so we wrote this to improve code reuse.
 */

static INLINE int TypeOk(byte type)
{
    return (type == LIST_OSSH_CA_KEY || type == LIST_OSSH_PRINCIPAL);
}

/*
 * Create a new list of the specified type.
 */
WOLFSSH_LIST* ListNew(byte type, void* heap)
{
    WOLFSSH_LIST* ret = NULL;

    if (TypeOk(type)) {
        ret = (WOLFSSH_LIST*)WMALLOC(sizeof(WOLFSSH_LIST), heap, DYNTYPE_LIST);
        if (ret != NULL) {
            WMEMSET(ret, 0, sizeof(WOLFSSH_LIST));
            ret->type = type;
            ret->heap = heap;
        }
    }

    return ret;
}

static WOLFSSH_LIST_NODE* ListNodeNew(void* heap)
{
    WOLFSSH_LIST_NODE* ret = NULL;

    ret = (WOLFSSH_LIST_NODE*)WMALLOC(sizeof(WOLFSSH_LIST_NODE), heap,
                                      DYNTYPE_LIST_NODE);
    if (ret != NULL) {
        WMEMSET(ret, 0, sizeof(WOLFSSH_LIST_NODE));
    }

    return ret;
}

static void ListNodeFree(byte type, WOLFSSH_LIST_NODE* node)
{
    if (TypeOk(type) && node != NULL) {
        switch (type) {
        #ifdef WOLFSSH_OSSH_CERTS
            case LIST_OSSH_CA_KEY:
                OsshCaKeyFree(node->data.osshCaKey);
                break;
            case LIST_OSSH_PRINCIPAL:
                OsshPrincipalFree(node->data.osshPrincipal);
                break;
        #endif /* WOLFSSH_OSSH_CERTS */
            default:
                break;
        }

        WFREE(node, heap, DYNTYPE_LIST_NODE);
    }
}

/*
 * Free the list, all its individual nodes, and any data owned by those nodes.
 */
void ListFree(WOLFSSH_LIST* list)
{
    WOLFSSH_LIST_NODE* current;
    WOLFSSH_LIST_NODE* next;

    if (list != NULL) {
        current = list->head;

        while (current != NULL) {
            next = current->next;
            ListNodeFree(list->type, current);
            current = next;
        }

        WFREE(list, list->heap, DYNTYPE_LIST);
    }
}

/*
 * Add an element to the front of the list. The data pointer should point to
 * data whose type is supported by the list implementation. Returns WS_SUCCESS
 * on success and negative values on failure.
 */
int ListAdd(WOLFSSH_LIST* list, void* data)
{
    int ret = WS_SUCCESS;
    WOLFSSH_LIST_NODE* node;

    if (list == NULL || data == NULL) {
        ret = WS_BAD_ARGUMENT;
    }

    if (ret == WS_SUCCESS) {
        node = ListNodeNew(list->heap);
        if (node == NULL) {
            ret = WS_MEMORY_E;
        }
        else {
            node->data.raw = data;
            if (list->head == NULL) {
                list->head = node;
            }
            else {
                node->next = list->head;
                list->head = node;
            }
        }
    }

    return ret;
}

/*
 * Search for an element matching in of size inSz in the list. The logic for
 * "finding" such an element is specific to the type being searched for. If
 * the element is in the list, returns 1. If not found, returns 0. If there's
 * an error, returns negative values.
 */
int ListFind(WOLFSSH_LIST* list, const byte* in, word32 inSz)
{
    int ret = 0;
    WOLFSSH_LIST_NODE* node;

    if (list == NULL || in == NULL || inSz == 0) {
        ret = WS_BAD_ARGUMENT;
    }

    node = list->head;

    if (ret == WS_SUCCESS) {
        switch (list->type) {
            WOLFSSH_OSSH_CA_KEY* key;

            case LIST_OSSH_CA_KEY:
            {
                while (node != NULL) {
                    key = node->data.osshCaKey;
                    if (key != NULL &&
                        WC_SHA256_DIGEST_SIZE == inSz &&
                        WMEMCMP(key->fingerprint, in, inSz) == 0) {
                        ret = 1;
                        break;
                    }
                    node = node->next;
                }
                break;
            }
            case LIST_OSSH_PRINCIPAL:
            {
                WOLFSSH_OSSH_PRINCIPAL* principal;

                while (node != NULL) {
                    principal = node->data.osshPrincipal;
                    if (principal != NULL &&
                        principal->nameSz == inSz &&
                        WMEMCMP(principal->name, in, inSz) == 0) {
                        ret = 1;
                        break;
                    }
                    node = node->next;
                }
                break;
            }
            default:
            {
                break;
            }
        }
    }

    return ret;
}

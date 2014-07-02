/* internal.c 
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


#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssh/ssh.h>
#include <wolfssh/internal.h>
#include <wolfssh/log.h>


typedef struct {
    byte id;
    const char* name;
} NameIdPair;


static const NameIdMap[] = {
    { ID_NONE, "none" },
    { ID_AES128_CBC, "aes128-cbc" },
    { ID_AES128_CTR, "aes128-ctr" },
    { ID_AES128_GCM_WOLF, "aes128-gcm@wolfssl.com" },
    { ID_HMAC_SHA1, "hmac-sha1" },
    { ID_HMAC_SHA1_96, "hmac-sha1-96" },
    { ID_DH_GROUP1_SHA1, "diffie-hellman-group1-sha1" },
    { ID_DH_GROUP14_SHA1, "diffie-hellman-group14-sha1" },
    { ID_SSH_RSA, "ssh-rsa" }
};


uint8_t NameToId(const char* name)
{
    uint8_t id = ID_UNKNOWN;
    size_t  nameSz = WSTRLEN(name);

    for (i = 0; i < (sizeof(NameIdName)/sizeof(NameIdPair)); i++) {
        if (nameSz == WSTRLEN(NameIdMap[i].name &&
            XSTRNCMP(name, NameIdMap[i].name, nameSz) == 0)) {

            id = NameIdMap[i].id;
            break;
        }
    }

    return id;
}


const char* IdToName(uint8_t id)
{
    const char* name = NULL;

    for (i = 0; i < (sizeof(NameIdName)/sizeof(NameIdPair)); i++) {
        if (NameIdMap[i].id == id) {
            name = NameIdMap[i].name;
            break;
        }
    }

    return name;
}



/* auth.h
 *
 * Copyright (C) 2014-2021 wolfSSL Inc.
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

#ifndef WOLFAUTH_H
#define WOLFAUTH_H

#if 0
typedef struct USER_NODE USER_NODE;

USER_NODE* AddNewUser(USER_NODE* list, byte type, const byte* username,
                       word32 usernameSz, const byte* value, word32 valueSz);
#endif

void SetAuthKeysPattern(const char* pattern);
int DefaultUserAuth(byte authType, WS_UserAuthData* authData, void* ctx);

typedef struct WOLFSSHD_AUTH WOLFSSHD_AUTH;

/*
 * Returns WSSHD_AUTH_SUCCESS if user found, WSSHD_AUTH_FAILURE if user not
 * found, and negative values if an error occurs during checking.
 */
typedef int (*CallbackCheckUser)(const char* usr);


/*
 * Returns WSSHD_AUTH_SUCCESS if user found, WSSHD_AUTH_FAILURE if user not
 * found, and negative values if an error occurs during checking.
 */
typedef int (*CallbackCheckPassword)(const byte* usr, const byte* psw,
    int pswSz);

/*
 * Returns WSSHD_AUTH_SUCCESS if public key ok, WSSHD_AUTH_FAILURE if key not
 * ok, and negative values if an error occurs during checking.
 */
typedef int (*CallbackCheckPublicKey)(const byte* usr, const byte* key,
    word32 keySz);

WOLFSSHD_AUTH * wolfSSHD_CreateUserAuth(void* heap);
int wolfSSHD_FreeUserAuth(WOLFSSHD_AUTH* auth);
#endif /* WOLFAUTH_H */

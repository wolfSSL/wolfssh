/* common.h
 *
 * Copyright (C) 2014-2024 wolfSSL Inc.
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

#ifndef APPS_WOLFSSH_COMMON_H
#define APPS_WOLFSSH_COMMON_H

WOLFSSH_LOCAL int ClientLoadCA(WOLFSSH_CTX* ctx, const char* caCert);
WOLFSSH_LOCAL int ClientUsePubKey(const char* pubKeyName);
WOLFSSH_LOCAL int ClientSetPrivateKey(const char* privKeyName);
WOLFSSH_LOCAL int ClientUseCert(const char* certName);
WOLFSSH_LOCAL int ClientSetEcho(int type);
WOLFSSH_LOCAL int ClientUserAuth(byte authType, WS_UserAuthData* authData,
        void* ctx);
WOLFSSH_LOCAL int ClientPublicKeyCheck(const byte* pubKey, word32 pubKeySz,
        void* ctx);
WOLFSSH_LOCAL void ClientIPOverride(int flag);
WOLFSSH_LOCAL void ClientFreeBuffers(void);

#endif /* APPS_WOLFSSH_COMMON_H */

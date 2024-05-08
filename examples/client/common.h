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

#ifndef WOLFSSH_COMMON_H
#define WOLFSSH_COMMON_H
int ClientLoadCA(WOLFSSH_CTX* ctx, const char* caCert);
int ClientUsePubKey(const char* pubKeyName, int userEcc, void* heap);
int ClientSetPrivateKey(const char* privKeyName, int userEcc, void* heap);
int ClientUseCert(const char* certName, void* heap);
int ClientSetEcho(int type);
int ClientUserAuth(byte authType,
                      WS_UserAuthData* authData,
                      void* ctx);
int ClientPublicKeyCheck(const byte* pubKey, word32 pubKeySz, void* ctx);
void ClientIPOverride(int flag);
void ClientFreeBuffers(const char* pubKeyName, const char* privKeyName,
        void* heap);

#endif /* WOLFSSH_COMMON_H */


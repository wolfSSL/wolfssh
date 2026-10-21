/* common.h
 *
 * Copyright (C) 2014-2026 wolfSSL Inc.
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

#include <wolfssh/ssh.h>
#ifdef WOLFSSH_WINDOWS_CERT_STORE
    #include <wchar.h>
#endif

int ClientLoadCA(WOLFSSH_CTX* ctx, const char* caCert);
int ClientUsePubKey(const char* pubKeyName, int userEcc, void* heap);
int ClientSetPrivateKey(const char* privKeyName, int userEcc,
        void* heap, const char* tpmKeyAuth);
int ClientUseCert(const char* certName, void* heap);
int ClientSetEcho(int type);
/* Makes stdin unbuffered, so no stdio buffer keeps a copy of a typed
 * password or response. Call before any other stdin I/O; only the first
 * call in a process acts. */
void ClientUnbufferStdin(void);
int ClientUserAuth(byte authType,
        WS_UserAuthData* authData, void* ctx);
int ClientPublicKeyCheck(const byte* pubKey, word32 pubKeySz, void* ctx);
void ClientIPOverride(int flag);
/* Wipes the password and keyboard-interactive responses ClientUserAuth()
 * last read. The library sends them after the callback returns, so call
 * this once connect is done. */
void ClientClearPassword(void);
void ClientFreeBuffers(const char* pubKeyName, const char* privKeyName,
        void* heap);
#ifdef WOLFSSH_TPM
int ClientSetTpm(WOLFSSH* ssh);
#endif
#ifdef WOLFSSH_WINDOWS_CERT_STORE
int ClientSetPrivateKeyFromStore(WOLFSSH_CTX* ctx,
        const wchar_t* storeName, word32 dwFlags, const wchar_t* subjectName);
/* Supersedes ClientUseCert()/ClientUsePubKey()/ClientSetPrivateKey(), any key
 * they loaded is released. Copies the certificate out of ctx; call
 * ClientFreeBuffers() to release the copy. heap must be the same heap
 * previously passed to those loaders and later to ClientFreeBuffers(),
 * since buffers they allocated are freed here. */
int ClientSetupCertStoreAuth(WOLFSSH_CTX* ctx, void* heap);
#endif /* WOLFSSH_WINDOWS_CERT_STORE */

#endif /* WOLFSSH_COMMON_H */


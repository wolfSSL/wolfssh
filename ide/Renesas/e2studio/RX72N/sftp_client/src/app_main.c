/* app_main.c
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */
#ifdef WOLFSSL_USER_SETTINGS
#include <wolfssl/wolfcrypt/settings.h>
#else
#include <wolfssl/options.h>
#endif

#include <wolfssh/ssh.h>
#include <wolfssh/wolfsftp.h>
#include <wolfssh/test.h>
#include <wolfssh/port.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/coding.h>
#include "examples/client/common.h"

int my_IORecv(WOLFSSH* ssh, void* buff, word32 sz, void* ctx);
int my_IOSend(WOLFSSH* ssh, void* buff, word32 sz, void* ctx);
uint16_t t4_connect();
int Open_tcp();
int Close_tcp();
void main(void);
static void sftp_client_connect(WOLFSSH_CTX** ctx, WOLFSSH** ssh, int port);

/* t4 packet id */
uint16_t id = 0;
byte userPassword[256];


static int sftpUserAuth(byte authType, WS_UserAuthData* authData, void* ctx)
{
    int ret = WOLFSSH_USERAUTH_INVALID_AUTHTYPE;

    if (authType == WOLFSSH_USERAUTH_PASSWORD) {
        const char* defaultPassword = (const char*)ctx;
        word32 passwordSz;

        ret = WOLFSSH_USERAUTH_SUCCESS;
        if (defaultPassword != NULL) {
            passwordSz = (word32)strlen(defaultPassword);
            memcpy(userPassword, defaultPassword, passwordSz);
        }
        else {
            printf("Expecting password set for test cases\n");
            return ret;
        }

        if (ret == WOLFSSH_USERAUTH_SUCCESS) {
            authData->sf.password.password = userPassword;
            authData->sf.password.passwordSz = passwordSz;
        }
    }
    return ret;
}

/* preforms connection to port, sets WOLFSSH_CTX and WOLFSSH on success
 * caller needs to free ctx and ssh when done
 */
static void sftp_client_connect(WOLFSSH_CTX** ctx, WOLFSSH** ssh, int port)
{
    const char* username = "jill";
    const char* password = "upthehill";
    
    int ret;

    if (ctx == NULL || ssh == NULL) {
        return;
    }

    *ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_CLIENT, NULL);
    if (*ctx == NULL) {
        printf("failed to allocate ssh ctx object\n");
        return;
    }
    /* set IO callback */
    wolfSSH_SetIORecv(*ctx, my_IORecv);
    wolfSSH_SetIOSend(*ctx, my_IOSend);


    wolfSSH_SetUserAuth(*ctx, sftpUserAuth);
    *ssh = wolfSSH_new(*ctx);
    if (*ssh == NULL) {
        printf("failed to allocate ssh object\n");
        wolfSSH_CTX_free(*ctx);
        *ctx = NULL;
        return;
    }

    id = t4_connect();
    if (id != 1) {
        printf("failed to connect to a server\n");
        goto out;
    }

    wolfSSH_SetUserAuthCtx(*ssh, (void*)password);
    ret = wolfSSH_SetUsername(*ssh, username);
    if (ret == WS_SUCCESS) {
        wolfSSH_SetIOReadCtx(*ssh, (void *)&id);
        wolfSSH_SetIOWriteCtx(*ssh, (void *)&id);
    }
    if (ret == WS_SUCCESS)
        ret = wolfSSH_SFTP_connect(*ssh);

    if (ret != WS_SUCCESS)
        goto out;
    else
        return;
out:
    /* frees all data before client termination */
    if(*ssh) {
        wolfSSH_free(*ssh);
    }
    if(*ctx) {
        wolfSSH_CTX_free(*ctx);
    }
    *ssh = NULL;
    *ctx = NULL;
    return;

}

void main(void)
{
    WOLFSSH_CTX* ctx = NULL;
    WOLFSSH*     ssh = NULL;
    /* list working directory contents */
    WS_SFTPNAME* tmp;
    WS_SFTPNAME* current;
    char* workingDir = NULL;
    /* get current working directory */
    WS_SFTPNAME* n = NULL;
    int port = 1234;
    int ret;
#ifdef DEBUG_WOLFSSH
    wolfSSH_Debugging_ON();
#endif

    wolfSSH_Init();
    Open_tcp();
    sftp_client_connect(&ctx, &ssh, port);

    if (ctx != NULL && ssh != NULL){
        do {
            n = wolfSSH_SFTP_RealPath(ssh, (char*)".");
            ret = wolfSSH_get_error(ssh);
        } while (ret == WS_WANT_READ || ret == WS_WANT_WRITE);

        workingDir = (char*)WMALLOC(n->fSz + 1, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (workingDir == NULL) {
            printf("Unable to create working directory");
            goto out_exit;
        }
        WMEMCPY(workingDir, n->fName, n->fSz);
        workingDir[n->fSz] = '\0';
        
        current = wolfSSH_SFTP_LS(ssh, (char*)workingDir);
        tmp = current;
        while (tmp != NULL) {
            printf("%s\n", tmp->fName);
            tmp = tmp->next;
        }
        wolfSSH_SFTPNAME_list_free(current);
        /* take care of re-keying state before shutdown call */
        while (wolfSSH_get_error(ssh) == WS_REKEYING) {
            wolfSSH_worker(ssh, NULL);
        }
    }

    ret = wolfSSH_shutdown(ssh);
    if (ret == WS_SOCKET_ERROR_E) {
        /* If the socket is closed on shutdown, peer is gone, this is OK. */
        ret = WS_SUCCESS;
    }

out_exit:
    /* frees all data before client termination */
    if (ssh) {
        wolfSSH_free(ssh);
    }
    if (ctx) {
        wolfSSH_CTX_free(ctx);
    }
    ssh = NULL;
    ctx = NULL;
    Close_tcp();
    wolfSSH_Cleanup();

    printf("sftp client completes %d\n", ret);
}

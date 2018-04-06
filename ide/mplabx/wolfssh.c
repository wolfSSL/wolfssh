/* wolfssh.c
 *
 * Copyright (C) 2014-2016 wolfSSL Inc.
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

/* Uses portions of code from the wolfssh/examples/echoserver.c example */

#include "app.h"
#include "tcpip/tcpip.h"

#include <wolfssh/ssh.h>
#include <wolfssh/test.h>
#include <wolfssh/certs_test.h>
#include <wolfssh/log.h>

#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/coding.h>

#define SERVER_PORT 22

typedef enum
{
    APP_SSH_TCPIP_WAIT_INIT,
    APP_SSH_TCPIP_WAIT_FOR_IP,
    APP_SSH_CTX_INIT,
    APP_SSH_USERAUTH_INIT,
    APP_SSH_LOADKEY,
    APP_SSH_CREATE_SOCKET,
    APP_SSH_LISTEN,
    APP_SSH_CLEANUP,
    APP_SSH_OPERATION,
    APP_SSH_ACCEPT,
    APP_SSH_ERROR
} APP_SSH_STATES;


typedef struct APP_SSH_DATA
{
    APP_SSH_STATES state;
    TCP_SOCKET     socket;
} APP_SSH_DATA;


APP_SSH_DATA appData;
static WOLFSSH_CTX* ctx;
static WOLFSSH* ssh;

#ifndef EXAMPLE_HIGHWATER_MARK
    #define EXAMPLE_HIGHWATER_MARK 0x3FFF8000 /* 1GB - 32kB */
#endif
#ifndef EXAMPLE_BUFFER_SZ
    #define EXAMPLE_BUFFER_SZ 4096
#endif
#define SCRATCH_BUFFER_SZ 1200

static INLINE void c32toa(word32 u32, byte* c)
{
    c[0] = (u32 >> 24) & 0xff;
    c[1] = (u32 >> 16) & 0xff;
    c[2] = (u32 >>  8) & 0xff;
    c[3] =  u32 & 0xff;
}

/* Map user names to passwords */
/* Use arrays for username and p. The password or public key can
 * be hashed and the hash stored here. Then I won't need the type. */
typedef struct PwMap {
    byte type;
    byte username[32];
    word32 usernameSz;
    byte p[SHA256_DIGEST_SIZE];
    struct PwMap* next;
} PwMap;

typedef struct PwMapList {
    PwMap* head;
} PwMapList;
PwMapList pwMapList;

static const char echoserverBanner[] = "wolfSSH Example Echo Server\n";

static const char samplePasswordBuffer[] =
    "jill:upthehill\n"
    "jack:fetchapail\n";


static const char samplePublicKeyEccBuffer[] =
    "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAA"
    "BBBNkI5JTP6D0lF42tbxX19cE87hztUS6FSDoGvPfiU0CgeNSbI+aFdKIzTP5CQEJSvm25"
    "qUzgDtH7oyaQROUnNvk= hansel\n"
    "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAA"
    "BBBKAtH8cqaDbtJFjtviLobHBmjCtG56DMkP6A4M2H9zX2/YCg1h9bYS7WHd9UQDwXO1Hh"
    "IZzRYecXh7SG9P4GhRY= gretel\n";


static const char samplePublicKeyRsaBuffer[] =
    "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC9P3ZFowOsONXHD5MwWiCciXytBRZGho"
    "MNiisWSgUs5HdHcACuHYPi2W6Z1PBFmBWT9odOrGRjoZXJfDDoPi+j8SSfDGsc/hsCmc3G"
    "p2yEhUZUEkDhtOXyqjns1ickC9Gh4u80aSVtwHRnJZh9xPhSq5tLOhId4eP61s+a5pwjTj"
    "nEhBaIPUJO2C/M0pFnnbZxKgJlX7t1Doy7h5eXxviymOIvaCZKU+x5OopfzM/wFkey0EPW"
    "NmzI5y/+pzU5afsdeEWdiQDIQc80H6Pz8fsoFPvYSG+s4/wz0duu7yeeV1Ypoho65Zr+pE"
    "nIf7dO0B8EblgWt+ud+JI8wrAhfE4x hansel\n"
    "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCqDwRVTRVk/wjPhoo66+Mztrc31KsxDZ"
    "+kAV0139PHQ+wsueNpba6jNn5o6mUTEOrxrz0LMsDJOBM7CmG0983kF4gRIihECpQ0rcjO"
    "P6BSfbVTE9mfIK5IsUiZGd8SoE9kSV2pJ2FvZeBQENoAxEFk0zZL9tchPS+OCUGbK4SDjz"
    "uNZl/30Mczs73N3MBzi6J1oPo7sFlqzB6ecBjK2Kpjus4Y1rYFphJnUxtKvB0s+hoaadru"
    "biE57dK6BrH5iZwVLTQKux31uCJLPhiktI3iLbdlGZEctJkTasfVSsUizwVIyRjhVKmbdI"
    "RGwkU38D043AR1h0mUoGCPIKuqcFMf gretel\n";


static int wsUserAuth(byte authType,
                      WS_UserAuthData* authData,
                      void* ctx)
{
    PwMapList* list;
    PwMap* map;
    byte authHash[SHA256_DIGEST_SIZE];

    if (ctx == NULL) {
        SYS_CONSOLE_MESSAGE("wsUserAuth: ctx not set");
        return WOLFSSH_USERAUTH_FAILURE;
    }

    if (authType != WOLFSSH_USERAUTH_PASSWORD &&
        authType != WOLFSSH_USERAUTH_PUBLICKEY) {

        return WOLFSSH_USERAUTH_FAILURE;
    }

    /* Hash the password or public key with its length. */
    {
        wc_Sha256 sha;
        byte flatSz[4];
        wc_InitSha256(&sha);
        if (authType == WOLFSSH_USERAUTH_PASSWORD) {
            c32toa(authData->sf.password.passwordSz, flatSz);
            wc_Sha256Update(&sha, flatSz, sizeof(flatSz));
            wc_Sha256Update(&sha,
                            authData->sf.password.password,
                            authData->sf.password.passwordSz);
        }
        else if (authType == WOLFSSH_USERAUTH_PUBLICKEY) {
            c32toa(authData->sf.publicKey.publicKeySz, flatSz);
            wc_Sha256Update(&sha, flatSz, sizeof(flatSz));
            wc_Sha256Update(&sha,
                            authData->sf.publicKey.publicKey,
                            authData->sf.publicKey.publicKeySz);
        }
        wc_Sha256Final(&sha, authHash);
    }

    list = (PwMapList*)ctx;
    map = list->head;

    while (map != NULL) {
        if (authData->usernameSz == map->usernameSz &&
            memcmp(authData->username, map->username, map->usernameSz) == 0) {

            if (authData->type == map->type) {
                if (memcmp(map->p, authHash, SHA256_DIGEST_SIZE) == 0) {
                    return WOLFSSH_USERAUTH_SUCCESS;
                }
                else {
                    return (authType == WOLFSSH_USERAUTH_PASSWORD ?
                            WOLFSSH_USERAUTH_INVALID_PASSWORD :
                            WOLFSSH_USERAUTH_INVALID_PUBLICKEY);
                }
            }
            else {
                return WOLFSSH_USERAUTH_INVALID_AUTHTYPE;
            }
        }
        map = map->next;
    }

    return WOLFSSH_USERAUTH_INVALID_USER;
}


static void PwMapListDelete(PwMapList* list)
{
    if (list != NULL) {
        PwMap* head = list->head;

        while (head != NULL) {
            PwMap* cur = head;
            head = head->next;
            memset(cur, 0, sizeof(PwMap));
            free(cur);
        }
    }
}


static PwMap* PwMapNew(PwMapList* list, byte type, const byte* username,
                       word32 usernameSz, const byte* p, word32 pSz)
{
    PwMap* map;

    map = (PwMap*)malloc(sizeof(PwMap));
    if (map != NULL) {
        Sha256 sha;
        byte flatSz[4];

        map->type = type;
        if (usernameSz >= sizeof(map->username))
            usernameSz = sizeof(map->username) - 1;
        memcpy(map->username, username, usernameSz + 1);
        map->username[usernameSz] = 0;
        map->usernameSz = usernameSz;

        wc_InitSha256(&sha);
        c32toa(pSz, flatSz);
        wc_Sha256Update(&sha, flatSz, sizeof(flatSz));
        wc_Sha256Update(&sha, p, pSz);
        wc_Sha256Final(&sha, map->p);

        map->next = list->head;
        list->head = map;
    }

    return map;
}


static int LoadPublicKeyBuffer(byte* buf, word32 bufSz, PwMapList* list)
{
    char* str = (char*)buf;
    char* delimiter;
    byte* publicKey64;
    word32 publicKey64Sz;
    byte* username;
    word32 usernameSz;
    byte  publicKey[300];
    word32 publicKeySz;

    /* Each line of passwd.txt is in the format
     *     ssh-rsa AAAB3BASE64ENCODEDPUBLICKEYBLOB username\n
     * This function modifies the passed-in buffer. */
    if (list == NULL)
        return -1;

    if (buf == NULL || bufSz == 0)
        return 0;

    while (*str != 0) {
        /* Skip the public key type. This example will always be ssh-rsa. */
        delimiter = strchr(str, ' ');
        str = delimiter + 1;
        delimiter = strchr(str, ' ');
        publicKey64 = (byte*)str;
        *delimiter = 0;
        publicKey64Sz = (word32)(delimiter - str);
        str = delimiter + 1;
        delimiter = strchr(str, '\n');
        username = (byte*)str;
        *delimiter = 0;
        usernameSz = (word32)(delimiter - str);
        str = delimiter + 1;
        publicKeySz = sizeof(publicKey);

        if (Base64_Decode(publicKey64, publicKey64Sz,
                          publicKey, &publicKeySz) != 0) {

            return -1;
        }

        if (PwMapNew(list, WOLFSSH_USERAUTH_PUBLICKEY,
                     username, usernameSz,
                     publicKey, publicKeySz) == NULL ) {

            return -1;
        }
    }

    return 0;
}


static int LoadPasswordBuffer(byte* buf, word32 bufSz, PwMapList* list)
{
    char* str = (char*)buf;
    char* delimiter;
    char* username;
    char* password;

    /* Each line of passwd.txt is in the format
     *     username:password\n
     * This function modifies the passed-in buffer. */

    if (list == NULL)
        return -1;

    if (buf == NULL || bufSz == 0)
        return 0;

    while (*str != 0) {
        delimiter = strchr(str, ':');
        username = str;
        *delimiter = 0;
        password = delimiter + 1;
        str = strchr(password, '\n');
        *str = 0;
        str++;
        if (PwMapNew(list, WOLFSSH_USERAUTH_PASSWORD,
                     (byte*)username, (word32)strlen(username),
                     (byte*)password, (word32)strlen(password)) == NULL ) {

            return -1;
        }
    }

    return 0;
}


#ifndef NO_FILESYSTEM
static int load_file(const char* fileName, byte* buf, word32 bufSz)
{
    FILE* file;
    word32 fileSz;
    word32 readSz;

    if (fileName == NULL) return 0;

    if (WFOPEN(&file, fileName, "rb") != 0)
        return 0;
    fseek(file, 0, SEEK_END);
    fileSz = (word32)ftell(file);
    rewind(file);

    if (fileSz > bufSz) {
        fclose(file);
        return 0;
    }

    readSz = (word32)fread(buf, 1, fileSz, file);
    if (readSz < fileSz) {
        fclose(file);
        return 0;
    }

    fclose(file);

    return fileSz;
}
#endif /* NO_FILESYSTEM */

/* returns buffer size on success */
static int load_key(byte isEcc, byte* buf, word32 bufSz)
{
    word32 sz = 0;

#ifndef NO_FILESYSTEM
    const char* bufName;
    bufName = isEcc ? "./keys/server-key-ecc.der" :
                       "./keys/server-key-rsa.der" ;
    sz = load_file(bufName, buf, SCRATCH_BUFFER_SZ);
#else
    /* using buffers instead */
    if (isEcc) {
        if (sizeof_ecc_key_der_256 > bufSz) {
            return 0;
        }
        WMEMCPY(buf, ecc_key_der_256, sizeof_ecc_key_der_256);
        sz = sizeof_ecc_key_der_256;
    }
    else {
        if (sizeof_rsa_key_der_2048 > bufSz) {
            return 0;
        }
        WMEMCPY(buf, (byte*)rsa_key_der_2048, sizeof_rsa_key_der_2048);
        sz = sizeof_rsa_key_der_2048;
    }
#endif

    return sz;
}


static byte find_char(const byte* str, const byte* buf, word32 bufSz)
{
    const byte* cur;

    while (bufSz) {
        cur = str;
        while (*cur != '\0') {
            if (*cur == *buf)
                return *cur;
            cur++;
        }
        buf++;
        bufSz--;
    }

    return 0;
}


#if 0
static void logCb(enum wolfSSH_LogLevel lvl, const char *const msg)
{
    if (wolfSSH_LogEnabled()) {
        SYS_CONSOLE_PRINT(msg);
        SYS_CONSOLE_PRINT("\r\n");
        SYS_CONSOLE_Tasks(sysObj.sysConsole0);
    }
}
#endif


void APP_SSH_Initialize ( void )
{
    appData.state = APP_SSH_CTX_INIT;
    wolfSSH_Init();
#if 0
    SYS_CONSOLE_PRINT("Turning on wolfSSH debugging\n\r");
    wolfSSH_Debugging_ON();
    wolfSSH_SetLoggingCb(logCb);
#endif
}


void APP_SSH_Tasks ( void )
{
    int useEcc = 0;

    switch(appData.state)
    {
        case APP_SSH_CTX_INIT:
            ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_SERVER, NULL);
            if (ctx == NULL) {
                SYS_CONSOLE_PRINT("Couldn't allocate SSH CTX data.\r\n");
                appData.state = APP_SSH_ERROR;
            }
            appData.state = APP_SSH_USERAUTH_INIT;
            break;

        case APP_SSH_USERAUTH_INIT:
            wolfSSH_SetUserAuth(ctx, wsUserAuth);
            wolfSSH_CTX_SetBanner(ctx, echoserverBanner);
            appData.state = APP_SSH_LOADKEY;
            break;

        case APP_SSH_LOADKEY:
        {
            const char* bufName;
            byte buf[SCRATCH_BUFFER_SZ];
            word32 bufSz;

            bufSz = load_key(useEcc, buf, SCRATCH_BUFFER_SZ);
            if (bufSz == 0) {
                SYS_CONSOLE_PRINT("Couldn't load key file.\r\n");
                appData.state = APP_SSH_ERROR;
                break;
            }
            if (wolfSSH_CTX_UsePrivateKey_buffer(ctx, buf, bufSz,
                                             WOLFSSH_FORMAT_ASN1) < 0) {
                SYS_CONSOLE_PRINT("Couldn't use key buffer.\r\n");
                appData.state = APP_SSH_ERROR;
                break;
            }

            bufSz = (word32)strlen(samplePasswordBuffer);
            memcpy(buf, samplePasswordBuffer, bufSz);
            buf[bufSz] = 0;
            LoadPasswordBuffer(buf, bufSz, &pwMapList);

            bufName = useEcc ? samplePublicKeyEccBuffer :
                               samplePublicKeyRsaBuffer;
            bufSz = (word32)strlen(bufName);
            memcpy(buf, bufName, bufSz);
            buf[bufSz] = 0;
            LoadPublicKeyBuffer(buf, bufSz, &pwMapList);
        }
        appData.state = APP_SSH_CREATE_SOCKET;
        break;

        case APP_SSH_CREATE_SOCKET:
            /* Create a socket for listen and accepting connections on */
            appData.socket = TCPIP_TCP_ServerOpen(IP_ADDRESS_TYPE_IPV4, SERVER_PORT, 0);
            if (!TCPIP_TCP_OptionsSet(appData.socket, TCP_OPTION_NODELAY, (void*)1)) {
                SYS_CONSOLE_PRINT("Unable to set no delay with TCP\r\n");
                appData.state = APP_SSH_ERROR;
                break;
            }
            appData.state = APP_SSH_LISTEN;
            SYS_CONSOLE_PRINT("Waiting for client on to connect on port [%d]\r\n", SERVER_PORT);
            break;

        case APP_SSH_LISTEN:
            if (TCPIP_TCP_IsConnected(appData.socket)) {
                SYS_CONSOLE_PRINT("Creating WOLFSSH struct and doing accept\r\n");
                ssh = wolfSSH_new(ctx);
                if (ssh == NULL) {
                    SYS_CONSOLE_PRINT("Couldn't allocate SSH data.\r\n");
                    appData.state = APP_SSH_ERROR;
                    break;
                }
                wolfSSH_SetUserAuthCtx(ssh, &pwMapList);
                wolfSSH_set_fd(ssh, appData.socket);
                appData.state = APP_SSH_ACCEPT;
            }
            break;

        case APP_SSH_ACCEPT:
        {
            int ret;

            if ((ret = wolfSSH_accept(ssh)) == WS_SUCCESS) {
                byte msg[] = "Successfully connected to wolfSSH PIC32 echoserver\n\r";
                appData.state = APP_SSH_OPERATION;
                SYS_CONSOLE_PRINT("wolfSSH accept success!\r\n");
                wolfSSH_stream_send(ssh, msg, sizeof(msg));
                break;
            }
            ret = wolfSSH_get_error(ssh);
            if (ret != WS_WANT_READ && ret != WS_WANT_WRITE) {
                /* connection was closed or error happened */
                SYS_CONSOLE_PRINT("Error [%d] with wolfSSH connection. Closing socket.\r\n", ret);
                appData.state = APP_SSH_CLEANUP;
            }
        }
            break;

        /* echo ssh input (example code from wolfssh/echoserver/echoserver.c) */
        case APP_SSH_OPERATION:
            {
                byte* buf = NULL;
                byte* tmpBuf;
                int bufSz, backlogSz = 0, rxSz, txSz, stop = 0, txSum;

                bufSz = EXAMPLE_BUFFER_SZ + backlogSz;

                tmpBuf = (byte*)realloc(buf, bufSz);
                if (tmpBuf == NULL)
                    appData.state = APP_SSH_CLEANUP;
                else
                    buf = tmpBuf;

                rxSz = wolfSSH_stream_read(ssh, buf + backlogSz,
                                           EXAMPLE_BUFFER_SZ);
                if (rxSz > 0) {
                    {
                        /* print out HEX value of received data */
                        int i;
                        SYS_CONSOLE_PRINT("wolfSSH server read HEX : \r\n");
                        for (i = 0; i < rxSz; i++) {
                            SYS_CONSOLE_PRINT("%02X", buf[backlogSz + i]);
                        }
                        SYS_CONSOLE_PRINT("\r\n");
                    }
                    backlogSz += rxSz;
                    txSum = 0;
                    txSz = 0;

                    while (backlogSz != txSum && txSz >= 0 && !stop) {
                        txSz = wolfSSH_stream_send(ssh,
                                                   buf + txSum,
                                                   backlogSz - txSum);

                        if (txSz > 0) {
                            byte c;
                            const byte matches[] = { 0x03, 0x05, 0x06, 0x00 };

                            c = find_char(matches, buf + txSum, txSz);
                            switch (c) {
                                case 0x03:
                                    appData.state = APP_SSH_CLEANUP;
                                    break;
                                case 0x06:
                                    if (wolfSSH_TriggerKeyExchange(ssh)
                                            != WS_SUCCESS)
                                        appData.state = APP_SSH_CLEANUP;
                                    break;
                                default:
                                    break;
                            }
                            txSum += txSz;
                        }
                        else if (txSz != WS_REKEYING) {
                            appData.state = APP_SSH_CLEANUP;
                        }
                    }

                    if (txSum < backlogSz)
                        memmove(buf, buf + txSum, backlogSz - txSum);
                    backlogSz -= txSum;
                }
                free(buf);
            }
            break;

        case APP_SSH_CLEANUP:
            SYS_CONSOLE_PRINT("Closing and cleaning up connection\r\n\r\n");
            wolfSSH_free(ssh);
            WCLOSESOCKET(wolfSSH_get_fd(ssh));
            appData.state = APP_SSH_CREATE_SOCKET;
            break;

        case APP_SSH_ERROR:
        {
            static int set = 0;
            if (!set) {
                set = 1;
                wolfSSH_CTX_free(ctx);
                PwMapListDelete(&pwMapList);
                if (wolfSSH_Cleanup() != WS_SUCCESS) {
                    SYS_CONSOLE_PRINT("wolfSSH Cleanup Error.\r\n");
                }
                SYS_CONSOLE_PRINT("In error state\r\n");
            }
        }
        break;

        default:
            SYS_CONSOLE_PRINT("Unknown state!\r\n");
            appData.state = APP_SSH_ERROR;
            break;
    }
}

/* echoserver.c
 *
 * Copyright (C) 2014-2017 wolfSSL Inc.
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


#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/coding.h>
#include <wolfssh/ssh.h>
#include <wolfssh/test.h>
#include "examples/echoserver/echoserver.h"


static const char echoserverBanner[] = "wolfSSH Example Echo Server\n";


typedef struct {
    WOLFSSH* ssh;
    SOCKET_T fd;
    uint32_t id;
} thread_ctx_t;


#ifndef EXAMPLE_HIGHWATER_MARK
    #define EXAMPLE_HIGHWATER_MARK 0x3FFF8000 /* 1GB - 32kB */
#endif
#ifndef EXAMPLE_BUFFER_SZ
    #define EXAMPLE_BUFFER_SZ 4096
#endif
#define SCRATCH_BUFFER_SZ 1200


static uint8_t find_char(const uint8_t* str, const uint8_t* buf, uint32_t bufSz)
{
    const uint8_t* cur;

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


static int dump_stats(thread_ctx_t* ctx)
{
    char stats[1024];
    uint32_t statsSz;
    uint32_t txCount, rxCount, seq, peerSeq;

    wolfSSH_GetStats(ctx->ssh, &txCount, &rxCount, &seq, &peerSeq);

    sprintf(stats,
            "Statistics for Thread #%u:\r\n"
            "  txCount = %u\r\n  rxCount = %u\r\n"
            "  seq = %u\r\n  peerSeq = %u\r\n",
            ctx->id, txCount, rxCount, seq, peerSeq);
    statsSz = (uint32_t)strlen(stats);

    fprintf(stderr, "%s", stats);
    return wolfSSH_stream_send(ctx->ssh, (uint8_t*)stats, statsSz);
}


static THREAD_RETURN WOLFSSH_THREAD server_worker(void* vArgs)
{
    thread_ctx_t* threadCtx = (thread_ctx_t*)vArgs;

    if (wolfSSH_accept(threadCtx->ssh) == WS_SUCCESS) {
        uint8_t* buf = NULL;
        uint8_t* tmpBuf;
        int bufSz, backlogSz = 0, rxSz, txSz, stop = 0, txSum;

        do {
            bufSz = EXAMPLE_BUFFER_SZ + backlogSz;

            tmpBuf = realloc(buf, bufSz);
            if (tmpBuf == NULL)
                stop = 1;
            else
                buf = tmpBuf;

            if (!stop) {
                rxSz = wolfSSH_stream_read(threadCtx->ssh,
                                           buf + backlogSz,
                                           EXAMPLE_BUFFER_SZ);
                if (rxSz > 0) {
                    backlogSz += rxSz;
                    txSum = 0;
                    txSz = 0;

                    while (backlogSz != txSum && txSz >= 0 && !stop) {
                        txSz = wolfSSH_stream_send(threadCtx->ssh,
                                                   buf + txSum,
                                                   backlogSz - txSum);

                        if (txSz > 0) {
                            uint8_t c;
                            const uint8_t matches[] = { 0x03, 0x05, 0x06, 0x00 };

                            c = find_char(matches, buf + txSum, txSz);
                            switch (c) {
                                case 0x03:
                                    stop = 1;
                                    break;
                                case 0x06:
                                    if (wolfSSH_TriggerKeyExchange(threadCtx->ssh)
                                            != WS_SUCCESS)
                                        stop = 1;
                                    break;
                                case 0x05:
                                    if (dump_stats(threadCtx) <= 0)
                                        stop = 1;
                                    break;
                            }
                            txSum += txSz;
                        }
                        else if (txSz != WS_REKEYING)
                            stop = 1;
                    }

                    if (txSum < backlogSz)
                        memmove(buf, buf + txSum, backlogSz - txSum);
                    backlogSz -= txSum;
                }
                else
                    stop = 1;
            }
        } while (!stop);

        free(buf);
    }
    close(threadCtx->fd);
    wolfSSH_free(threadCtx->ssh);
    free(threadCtx);

    return 0;
}


static int load_file(const char* fileName, uint8_t* buf, uint32_t bufSz)
{
    FILE* file;
    uint32_t fileSz;
    uint32_t readSz;

    if (fileName == NULL) return 0;

    file = fopen(fileName, "rb");
    if (file == NULL) return 0;
    fseek(file, 0, SEEK_END);
    fileSz = (uint32_t)ftell(file);
    rewind(file);

    if (fileSz > bufSz) {
        fclose(file);
        return 0;
    }

    readSz = (uint32_t)fread(buf, 1, fileSz, file);
    if (readSz < fileSz) {
        fclose(file);
        return 0;
    }

    fclose(file);

    return fileSz;
}


static inline void c32toa(uint32_t u32, uint8_t* c)
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
    uint8_t type;
    uint8_t username[32];
    uint32_t usernameSz;
    uint8_t p[SHA256_DIGEST_SIZE];
    struct PwMap* next;
} PwMap;


typedef struct PwMapList {
    PwMap* head;
} PwMapList;


static PwMap* PwMapNew(PwMapList* list, uint8_t type, const uint8_t* username,
                       uint32_t usernameSz, const uint8_t* p, uint32_t pSz)
{
    PwMap* map;

    map = (PwMap*)malloc(sizeof(PwMap));
    if (map != NULL) {
        Sha256 sha;
        uint8_t flatSz[4];

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


static const char samplePasswordBuffer[] =
    "jill:upthehill\n"
    "jack:fetchapail\n";


static const char samplePublicKeyBuffer[] =
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


static int LoadPasswordBuffer(uint8_t* buf, uint32_t bufSz, PwMapList* list)
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
                     (uint8_t*)username, (uint32_t)strlen(username),
                     (uint8_t*)password, (uint32_t)strlen(password)) == NULL ) {

            return -1;
        }
    }

    return 0;
}


static int LoadPublicKeyBuffer(uint8_t* buf, uint32_t bufSz, PwMapList* list)
{
    char* str = (char*)buf;
    char* delimiter;
    uint8_t* publicKey64;
    uint32_t publicKey64Sz;
    uint8_t* username;
    uint32_t usernameSz;
    uint8_t  publicKey[300];
    uint32_t publicKeySz;

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
        publicKey64 = (uint8_t*)str;
        *delimiter = 0;
        publicKey64Sz = (uint32_t)(delimiter - str);
        str = delimiter + 1;
        delimiter = strchr(str, '\n');
        username = (uint8_t*)str;
        *delimiter = 0;
        usernameSz = (uint32_t)(delimiter - str);
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


static int wsUserAuth(uint8_t authType,
                      const WS_UserAuthData* authData,
                      void* ctx)
{
    PwMapList* list;
    PwMap* map;
    uint8_t authHash[SHA256_DIGEST_SIZE];

    if (ctx == NULL) {
        fprintf(stderr, "wsUserAuth: ctx not set");
        return WOLFSSH_USERAUTH_FAILURE;
    }

    if (authType != WOLFSSH_USERAUTH_PASSWORD &&
        authType != WOLFSSH_USERAUTH_PUBLICKEY) {

        return WOLFSSH_USERAUTH_FAILURE;
    }

    /* Hash the password or public key with its length. */
    {
        Sha256 sha;
        uint8_t flatSz[4];
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


static void ShowUsage(void)
{
    printf("echoserver %s\n", LIBWOLFSSH_VERSION_STRING);
    printf("-h          Help, print this usage\n");
    printf("-m          Allow multiple connections\n");
    printf("-e          Use ECC private key\n");
}


THREAD_RETURN WOLFSSH_THREAD echoserver_test(void* args)
{
    WOLFSSH_CTX* ctx = NULL;
    PwMapList pwMapList;
    SOCKET_T listenFd = 0;
    uint32_t defaultHighwater = EXAMPLE_HIGHWATER_MARK;
    uint32_t threadCount = 0;
    int multipleConnections = 0;
    int useEcc = 0;
    char ch;
    uint16_t port = wolfSshPort;

    int     argc = ((func_args*)args)->argc;
    char**  argv = ((func_args*)args)->argv;
    ((func_args*)args)->return_code = 0;

    while ((ch = mygetopt(argc, argv, "hme")) != -1) {
        switch (ch) {
            case 'h' :
                ShowUsage();
                exit(EXIT_SUCCESS);

            case 'm' :
                multipleConnections = 1;
                break;

            case 'e' :
                useEcc = 1;
                break;

            default:
                ShowUsage();
                exit(MY_EX_USAGE);
        }
    }
    myoptind = 0;      /* reset for test cases */

    if (wolfSSH_Init() != WS_SUCCESS) {
        fprintf(stderr, "Couldn't initialize wolfSSH.\n");
        exit(EXIT_FAILURE);
    }

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_SERVER, NULL);
    if (ctx == NULL) {
        fprintf(stderr, "Couldn't allocate SSH CTX data.\n");
        exit(EXIT_FAILURE);
    }

    memset(&pwMapList, 0, sizeof(pwMapList));
    wolfSSH_SetUserAuth(ctx, wsUserAuth);
    wolfSSH_CTX_SetBanner(ctx, echoserverBanner);

    {
        uint8_t buf[SCRATCH_BUFFER_SZ];
        uint32_t bufSz;

        bufSz = load_file(useEcc ?
                           "./keys/server-key-ecc.der" :
                           "./keys/server-key-rsa.der",
                          buf, SCRATCH_BUFFER_SZ);
        if (bufSz == 0) {
            fprintf(stderr, "Couldn't load key file.\n");
            exit(EXIT_FAILURE);
        }
        if (wolfSSH_CTX_UsePrivateKey_buffer(ctx, buf, bufSz,
                                             WOLFSSH_FORMAT_ASN1) < 0) {
            fprintf(stderr, "Couldn't use key buffer.\n");
            exit(EXIT_FAILURE);
        }

        bufSz = (uint32_t)strlen((char*)samplePasswordBuffer);
        memcpy(buf, samplePasswordBuffer, bufSz);
        buf[bufSz] = 0;
        LoadPasswordBuffer(buf, bufSz, &pwMapList);

        bufSz = (uint32_t)strlen((char*)samplePublicKeyBuffer);
        memcpy(buf, samplePublicKeyBuffer, bufSz);
        buf[bufSz] = 0;
        LoadPublicKeyBuffer(buf, bufSz, &pwMapList);
    }

    tcp_listen(&listenFd, &port, 0);

    do {
        SOCKET_T      clientFd = 0;
        SOCKADDR_IN_T clientAddr;
        socklen_t     clientAddrSz = sizeof(clientAddr);
        THREAD_TYPE   thread;
        WOLFSSH*      ssh;
        thread_ctx_t* threadCtx;

        threadCtx = (thread_ctx_t*)malloc(sizeof(thread_ctx_t));
        if (threadCtx == NULL) {
            fprintf(stderr, "Couldn't allocate thread context data.\n");
            exit(EXIT_FAILURE);
        }

        ssh = wolfSSH_new(ctx);
        if (ssh == NULL) {
            fprintf(stderr, "Couldn't allocate SSH data.\n");
            exit(EXIT_FAILURE);
        }
        wolfSSH_SetUserAuthCtx(ssh, &pwMapList);
        /* Use the session object for its own highwater callback ctx */
        if (defaultHighwater > 0) {
            wolfSSH_SetHighwaterCtx(ssh, (void*)ssh);
            wolfSSH_SetHighwater(ssh, defaultHighwater);
        }

        clientFd = accept(listenFd, (struct sockaddr*)&clientAddr,
                                                                 &clientAddrSz);
        if (clientFd == -1)
            err_sys("tcp accept failed");

        wolfSSH_set_fd(ssh, clientFd);

        threadCtx->ssh = ssh;
        threadCtx->fd = clientFd;
        threadCtx->id = threadCount++;

        pthread_create(&thread, 0, server_worker, threadCtx);

        if (multipleConnections)
            pthread_detach(thread);
        else
            pthread_join(thread, NULL);

    } while (multipleConnections);

    PwMapListDelete(&pwMapList);
    wolfSSH_CTX_free(ctx);
    if (wolfSSH_Cleanup() != WS_SUCCESS) {
        fprintf(stderr, "Couldn't clean up wolfSSH.\n");
        exit(EXIT_FAILURE);
    }

    return 0;
}

#ifndef NO_MAIN_DRIVER

    int main(int argc, char** argv)
    {
        func_args args;

        args.argc = argc;
        args.argv = argv;
        args.return_code = 0;

        StartTCP();

        ChangeToWolfSshRoot();
        #ifdef DEBUG_WOLFSSH
            wolfSSH_Debugging_ON();
        #endif

        wolfSSH_Init();

        #ifndef NO_WOLFSSH_CLIENT
            echoserver_test(&args);
        #endif /* NO_WOLFSSH_CLIENT */

        wolfSSH_Cleanup();

        return args.return_code;
    }


    int myoptind = 0;
    char* myoptarg = NULL;

#endif /* NO_MAIN_DRIVER */

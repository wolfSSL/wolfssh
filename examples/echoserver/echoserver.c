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

#define WOLFSSH_TEST_SERVER
#define WOLFSSH_TEST_ECHOSERVER


#ifdef WOLFSSL_USER_SETTINGS
    #include <wolfssl/wolfcrypt/settings.h>
#else
    #include <wolfssl/options.h>
#endif

#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/coding.h>
#include <wolfssh/ssh.h>
#include <wolfssh/wolfsftp.h>
#include <wolfssh/test.h>
#include "examples/echoserver/echoserver.h"

#ifdef WOLFSSL_NUCLEUS
    /* use buffers for keys with server */
    #define NO_FILESYSTEM
    #define WOLFSSH_NO_EXIT
#endif

#ifdef NO_FILESYSTEM
    #include <wolfssh/certs_test.h>
#endif


#ifndef NO_WOLFSSH_SERVER

#define TEST_SFTP_TIMEOUT 10

static const char echoserverBanner[] = "wolfSSH Example Echo Server\n";


typedef struct {
    WOLFSSH* ssh;
    SOCKET_T fd;
    word32 id;
    char   nonBlock;
} thread_ctx_t;


#ifndef EXAMPLE_HIGHWATER_MARK
    #define EXAMPLE_HIGHWATER_MARK 0x3FFF8000 /* 1GB - 32kB */
#endif
#ifndef EXAMPLE_BUFFER_SZ
    #define EXAMPLE_BUFFER_SZ 4096
#endif
#define SCRATCH_BUFFER_SZ 1200


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


static int dump_stats(thread_ctx_t* ctx)
{
    char stats[1024];
    word32 statsSz;
    word32 txCount, rxCount, seq, peerSeq;

    wolfSSH_GetStats(ctx->ssh, &txCount, &rxCount, &seq, &peerSeq);

    WSNPRINTF(stats, sizeof(stats),
            "Statistics for Thread #%u:\r\n"
            "  txCount = %u\r\n  rxCount = %u\r\n"
            "  seq = %u\r\n  peerSeq = %u\r\n",
            ctx->id, txCount, rxCount, seq, peerSeq);
    statsSz = (word32)strlen(stats);

    fprintf(stderr, "%s", stats);
    return wolfSSH_stream_send(ctx->ssh, (byte*)stats, statsSz);
}


/* handle SSH echo operations
 * returns 0 on success
 */
static int ssh_worker(thread_ctx_t* threadCtx) {
    byte* buf = NULL;
    byte* tmpBuf;
    int bufSz, backlogSz = 0, rxSz, txSz, stop = 0, txSum;

    do {
        bufSz = EXAMPLE_BUFFER_SZ + backlogSz;

        tmpBuf = (byte*)realloc(buf, bufSz);
        if (tmpBuf == NULL)
            stop = 1;
        else
            buf = tmpBuf;

        if (!stop) {
            if (threadCtx->nonBlock) {
                SOCKET_T sockfd;
                int select_ret = 0;

                sockfd = (SOCKET_T)wolfSSH_get_fd(threadCtx->ssh);

                select_ret = tcp_select(sockfd, 1);
                if (select_ret != WS_SELECT_RECV_READY &&
                    select_ret != WS_SELECT_ERROR_READY &&
                    select_ret != WS_SELECT_TIMEOUT) {
                    break;
                }
            }

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
                        byte c;
                        const byte matches[] = { 0x03, 0x05, 0x06, 0x00 };

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
                    else if (txSz != WS_REKEYING) {
                        int error = wolfSSH_get_error(threadCtx->ssh);
                        if (error != WS_WANT_WRITE) {
                            stop = 1;
                        }
                        else {
                            txSz = 0;
                        }
                    }
                }

                if (txSum < backlogSz)
                    memmove(buf, buf + txSum, backlogSz - txSum);
                backlogSz -= txSum;
            }
            else {
                int error = wolfSSH_get_error(threadCtx->ssh);
                if (error != WS_WANT_READ)
                    stop = 1;
            }
        }
    } while (!stop);

    free(buf);
    return 0;
}


#ifdef WOLFSSH_SFTP
/* handle SFTP operations
 * returns 0 on success
 */
static int sftp_worker(thread_ctx_t* threadCtx) {
    int ret   = WS_SUCCESS;
    int error = WS_SUCCESS;
    SOCKET_T sockfd;
    int select_ret = 0;

    sockfd = (SOCKET_T)wolfSSH_get_fd(threadCtx->ssh);
    do {
        if (error == WS_WANT_READ)
            printf("... sftp server would read block\n");
        else if (error == WS_WANT_WRITE)
            printf("... sftp server would write block\n");

        select_ret = tcp_select(sockfd, TEST_SFTP_TIMEOUT);
        if (select_ret == WS_SELECT_RECV_READY ||
            select_ret == WS_SELECT_ERROR_READY)
        {
            ret = wolfSSH_SFTP_read(threadCtx->ssh);
            error = wolfSSH_get_error(threadCtx->ssh);
        }
        else if (select_ret == WS_SELECT_TIMEOUT)
            error = WS_WANT_READ;
        else
            error = WS_FATAL_ERROR;

        if (error == WS_WANT_READ || error == WS_WANT_WRITE)
            ret = WS_WANT_READ;

    } while (ret != WS_FATAL_ERROR);

    return ret;
}
#endif

static int NonBlockSSH_accept(WOLFSSH* ssh)
{
    int ret;
    int error;
    SOCKET_T sockfd;
    int select_ret = 0;

    ret = wolfSSH_accept(ssh);
    error = wolfSSH_get_error(ssh);
    sockfd = (SOCKET_T)wolfSSH_get_fd(ssh);

    while ((ret != WS_SUCCESS && ret != WS_SCP_COMPLETE && ret != WS_SFTP_COMPLETE)
            && (error == WS_WANT_READ || error == WS_WANT_WRITE))
    {
        if (error == WS_WANT_READ)
            printf("... server would read block\n");
        else if (error == WS_WANT_WRITE)
            printf("... server would write block\n");

        select_ret = tcp_select(sockfd, 1);
        if (select_ret == WS_SELECT_RECV_READY ||
            select_ret == WS_SELECT_ERROR_READY)
        {
            ret = wolfSSH_accept(ssh);
            error = wolfSSH_get_error(ssh);
        }
        else if (select_ret == WS_SELECT_TIMEOUT)
            error = WS_WANT_READ;
        else
            error = WS_FATAL_ERROR;
    }

    return ret;
}


static THREAD_RETURN WOLFSSH_THREAD server_worker(void* vArgs)
{
    int ret = 0;
    thread_ctx_t* threadCtx = (thread_ctx_t*)vArgs;

    if (!threadCtx->nonBlock)
        ret = wolfSSH_accept(threadCtx->ssh);
    else
        ret = NonBlockSSH_accept(threadCtx->ssh);

    switch (ret) {
        case WS_SCP_COMPLETE:
            printf("scp file transfer completed\n");
            ret = 0;
            break;

        case WS_SFTP_COMPLETE:
        #ifdef WOLFSSH_SFTP
            ret = sftp_worker(threadCtx);
        #else
            err_sys("SFTP not compiled in. Please use --enable-sftp");
        #endif
            break;

        case WS_SUCCESS:
            ret = ssh_worker(threadCtx);
            break;
    }

    if (ret == WS_FATAL_ERROR && wolfSSH_get_error(threadCtx->ssh) ==
            WS_VERSION_E) {
        ret = 0; /* don't break out of loop with version miss match */
        printf("Unsupported version error\n");
    }

    if (wolfSSH_shutdown(threadCtx->ssh) != WS_SUCCESS) {
        fprintf(stderr, "Error with SSH shutdown.\n");
    }

    WCLOSESOCKET(threadCtx->fd);
    wolfSSH_free(threadCtx->ssh);

    if (ret != 0) {
        fprintf(stderr, "Error [%d] \"%s\" with handling connection.\n", ret,
                wolfSSH_ErrorToName(ret));
    #ifndef WOLFSSH_NO_EXIT
        exit(EXIT_FAILURE);
    #endif
    }

    free(threadCtx);

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
    sz = load_file(bufName, buf, bufSz);
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


static int wsUserAuth(byte authType,
                      WS_UserAuthData* authData,
                      void* ctx)
{
    PwMapList* list;
    PwMap* map;
    byte authHash[SHA256_DIGEST_SIZE];

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


static void ShowUsage(void)
{
    printf("echoserver %s\n", LIBWOLFSSH_VERSION_STRING);
    printf(" -?            display this help and exit\n");
    printf(" -1            exit after single (one) connection\n");
    printf(" -e            use ECC private key\n");
    printf(" -p <num>      port to connect on, default %d\n", wolfSshPort);
    printf(" -N            use non-blocking sockets\n");
}


static void SignalTcpReady(func_args* serverArgs, word16 port)
{
#if defined(_POSIX_THREADS) && defined(NO_MAIN_DRIVER) && !defined(__MINGW32__)
    tcp_ready* ready = serverArgs->signal;
    pthread_mutex_lock(&ready->mutex);
    ready->ready = 1;
    ready->port = port;
    pthread_cond_signal(&ready->cond);
    pthread_mutex_unlock(&ready->mutex);
#else
    (void)serverArgs;
    (void)port;
#endif
}


THREAD_RETURN WOLFSSH_THREAD echoserver_test(void* args)
{
    func_args* serverArgs = (func_args*)args;
    WOLFSSH_CTX* ctx = NULL;
    PwMapList pwMapList;
    SOCKET_T listenFd = 0;
    word32 defaultHighwater = EXAMPLE_HIGHWATER_MARK;
    word32 threadCount = 0;
    int multipleConnections = 1;
    int useEcc = 0;
    int ch;
    word16 port = wolfSshPort;
    char* readyFile = NULL;
    char  nonBlock  = 0;

    int     argc = serverArgs->argc;
    char**  argv = serverArgs->argv;
    serverArgs->return_code = 0;

    if (argc > 0) {
    while ((ch = mygetopt(argc, argv, "?1ep:R:N")) != -1) {
        switch (ch) {
            case '?' :
                ShowUsage();
                exit(EXIT_SUCCESS);

            case '1':
                multipleConnections = 0;
                break;

            case 'e' :
                useEcc = 1;
                break;

            case 'p':
                port = (word16)atoi(myoptarg);
                #if !defined(NO_MAIN_DRIVER) || defined(USE_WINDOWS_API)
                    if (port == 0)
                        err_sys("port number cannot be 0");
                #endif
                break;

            case 'R':
                readyFile = myoptarg;
                break;

            case 'N':
                nonBlock = 1;
                break;

            default:
                ShowUsage();
                exit(MY_EX_USAGE);
        }
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
    if (serverArgs->user_auth == NULL)
        wolfSSH_SetUserAuth(ctx, wsUserAuth);
    else
        wolfSSH_SetUserAuth(ctx, ((func_args*)args)->user_auth);
    wolfSSH_CTX_SetBanner(ctx, echoserverBanner);

    {
        const char* bufName;
        byte buf[SCRATCH_BUFFER_SZ];
        word32 bufSz;

        bufSz = load_key(useEcc, buf, SCRATCH_BUFFER_SZ);
        if (bufSz == 0) {
            fprintf(stderr, "Couldn't load key file.\n");
            exit(EXIT_FAILURE);
        }
        if (wolfSSH_CTX_UsePrivateKey_buffer(ctx, buf, bufSz,
                                             WOLFSSH_FORMAT_ASN1) < 0) {
            fprintf(stderr, "Couldn't use key buffer.\n");
            exit(EXIT_FAILURE);
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
#ifdef WOLFSSL_NUCLEUS
    {
        int i;
        int ret = !NU_SUCCESS;

        /* wait for network and storage device */
        if (NETBOOT_Wait_For_Network_Up(NU_SUSPEND) != NU_SUCCESS) {
            fprintf(stderr, "Couldn't find network.\r\n");
            exit(EXIT_FAILURE);
        }

        for(i = 0; i < 15 && ret != NU_SUCCESS; i++)
        {
            fprintf(stdout, "Checking for storage device\r\n");

            ret = NU_Storage_Device_Wait(NU_NULL, NU_PLUS_TICKS_PER_SEC);
        }

        if (ret != NU_SUCCESS) {
            fprintf(stderr, "Couldn't find storage device.\r\n");
            exit(EXIT_FAILURE);
        }
    }
#endif

    /* if creating a ready file with port then override port to be 0 */
    if (readyFile != NULL) {
        port = 0;
    }
    tcp_listen(&listenFd, &port, 1);
    /* write out port number listing to, to user set ready file */
    if (readyFile != NULL) {
        WFILE* f = NULL;
        int    ret;
        ret = WFOPEN(&f, readyFile, "w");
        if (f != NULL && ret == 0) {
            fprintf(f, "%d\n", (int)port);
            WFCLOSE(f);
        }
    }

    do {
        SOCKET_T      clientFd = 0;
    #ifdef WOLFSSL_NUCLEUS
        struct addr_struct clientAddr;
    #else
        SOCKADDR_IN_T clientAddr;
        socklen_t     clientAddrSz = sizeof(clientAddr);
    #endif
        WOLFSSH*      ssh;
        thread_ctx_t* threadCtx;

        threadCtx = (thread_ctx_t*)malloc(sizeof(thread_ctx_t));
        if (threadCtx == NULL) {
            fprintf(stderr, "Couldn't allocate thread context data.\n");
            exit(EXIT_FAILURE);
        }

        ssh = wolfSSH_new(ctx);
        if (ssh == NULL) {
            free(threadCtx);
            fprintf(stderr, "Couldn't allocate SSH data.\n");
            exit(EXIT_FAILURE);
        }
        wolfSSH_SetUserAuthCtx(ssh, &pwMapList);
        /* Use the session object for its own highwater callback ctx */
        if (defaultHighwater > 0) {
            wolfSSH_SetHighwaterCtx(ssh, (void*)ssh);
            wolfSSH_SetHighwater(ssh, defaultHighwater);
        }

    #ifdef WOLFSSL_NUCLEUS
        {
            byte   ipaddr[MAX_ADDRESS_SIZE];
            char   buf[16];
            short  addrLength;
            struct sockaddr_struct sock;

            addrLength = sizeof(struct sockaddr_struct);

            /* Get the local IP address for the socket. 0.0.0.0 if ip adder any */
            if (NU_Get_Sock_Name(listenFd, &sock, &addrLength) != NU_SUCCESS) {
                fprintf(stderr, "Couldn't find network.\r\n");
                exit(EXIT_FAILURE);
            }

            WMEMCPY(ipaddr, &sock.ip_num, MAX_ADDRESS_SIZE);
            NU_Inet_NTOP(NU_FAMILY_IP, &ipaddr[0], buf, 16);
            fprintf(stdout, "Listing on %s:%d\r\n", buf, port);
        }
    #endif

        SignalTcpReady(serverArgs, port);

    #ifdef WOLFSSL_NUCLEUS
        clientFd = NU_Accept(listenFd, &clientAddr, 0);
    #else
        clientFd = accept(listenFd, (struct sockaddr*)&clientAddr,
                                                         &clientAddrSz);
    #endif
        if (clientFd == -1)
            err_sys("tcp accept failed");

        if (nonBlock)
            tcp_set_nonblocking(&clientFd);

        wolfSSH_set_fd(ssh, (int)clientFd);

        threadCtx->ssh = ssh;
        threadCtx->fd = clientFd;
        threadCtx->id = threadCount++;
        threadCtx->nonBlock = nonBlock;

        server_worker(threadCtx);

    } while (multipleConnections);

    PwMapListDelete(&pwMapList);
    wolfSSH_CTX_free(ctx);
    if (wolfSSH_Cleanup() != WS_SUCCESS) {
        fprintf(stderr, "Couldn't clean up wolfSSH.\n");
        exit(EXIT_FAILURE);
    }

    return 0;
}

#endif /* NO_WOLFSSH_SERVER */


#ifndef NO_MAIN_DRIVER

    int main(int argc, char** argv)
    {
        func_args args;

        args.argc = argc;
        args.argv = argv;
        args.return_code = 0;
        args.user_auth = NULL;

        WSTARTTCP();

        #ifdef DEBUG_WOLFSSH
            wolfSSH_Debugging_ON();
        #endif

#ifndef WOLFSSL_NUCLEUS
        ChangeToWolfSshRoot();
#endif
#ifndef NO_WOLFSSH_SERVER
        echoserver_test(&args);
#else
        printf("wolfSSH compiled without server support\n");
#endif

        wolfSSH_Cleanup();

        return args.return_code;
    }


    int myoptind = 0;
    char* myoptarg = NULL;

#endif /* NO_MAIN_DRIVER */

#ifdef WOLFSSL_NUCLEUS

    #define WS_TASK_SIZE 200000
    #define WS_TASK_PRIORITY 31
    static  NU_TASK serverTask;

    /* expecting void return on main function */
    static VOID main_nucleus(UNSIGNED argc, VOID* argv)
    {
        main((int)argc, (char**)argv);
    }


    /* using port 8080 because it was an open port on QEMU */
    VOID Application_Initialize (NU_MEMORY_POOL* memPool,
                                 NU_MEMORY_POOL* uncachedPool)
    {
        void* pt;
        int   ret;

        UNUSED_PARAMETER(uncachedPool);

        ret = NU_Allocate_Memory(memPool, &pt, WS_TASK_SIZE, NU_NO_SUSPEND);
        if (ret == NU_SUCCESS) {
            ret = NU_Create_Task(&serverTask, "wolfSSH Server", main_nucleus, 0,
                    NU_NULL, pt, WS_TASK_SIZE, WS_TASK_PRIORITY, 0,
                    NU_PREEMPT, NU_START);
            if (ret != NU_SUCCESS) {
                NU_Deallocate_Memory(pt);
            }
        }
    }
#endif /* WOLFSSL_NUCLEUS */

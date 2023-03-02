/* wolfssh.c
 *
 * Copyright (C) 2014-2023 wolfSSL Inc.
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

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#define WOLFSSH_TEST_CLIENT

#ifdef WOLFSSL_USER_SETTINGS
    #include <wolfssl/wolfcrypt/settings.h>
#else
    #include <wolfssl/options.h>
#endif

#include <wolfssh/ssh.h>
#include <wolfssh/internal.h>
#include <wolfssh/test.h>
#ifdef WOLFSSH_AGENT
    #include <wolfssh/agent.h>
#endif
#include <wolfssl/wolfcrypt/ecc.h>
#include "examples/client/client.h"
#if !defined(USE_WINDOWS_API) && !defined(MICROCHIP_PIC32)
    #include <termios.h>
#endif

#ifdef WOLFSSH_SHELL
    #ifdef HAVE_PTY_H
        #include <pty.h>
    #endif
    #ifdef HAVE_UTIL_H
        #include <util.h>
    #endif
    #ifdef HAVE_TERMIOS_H
        #include <termios.h>
    #endif
    #include <pwd.h>
#endif /* WOLFSSH_SHELL */

#ifdef WOLFSSH_AGENT
    #include <errno.h>
    #include <stddef.h>
    #include <sys/socket.h>
    #include <sys/un.h>
#endif /* WOLFSSH_AGENT */

#ifdef HAVE_SYS_SELECT_H
    #include <sys/select.h>
#endif

#ifdef WOLFSSH_CERTS
    #include <wolfssl/wolfcrypt/asn.h>
#endif


#ifndef NO_WOLFSSH_CLIENT

/* type = 2 : shell / execute command settings
 * type = 0 : password
 * type = 1 : restore default
 * return 0 on success */
static int SetEcho(int type)
{
#if !defined(USE_WINDOWS_API) && !defined(MICROCHIP_PIC32)
    static int echoInit = 0;
    static struct termios originalTerm;

    if (!echoInit) {
        if (tcgetattr(STDIN_FILENO, &originalTerm) != 0) {
            printf("Couldn't get the original terminal settings.\n");
            return -1;
        }
        echoInit = 1;
    }
    if (type == 1) {
        if (tcsetattr(STDIN_FILENO, TCSANOW, &originalTerm) != 0) {
            printf("Couldn't restore the terminal settings.\n");
            return -1;
        }
    }
    else {
        struct termios newTerm;
        memcpy(&newTerm, &originalTerm, sizeof(struct termios));

        newTerm.c_lflag &= ~ECHO;
        if (type == 2) {
            newTerm.c_lflag &= ~(ICANON | ECHOE | ECHOK | ECHONL | ISIG);
        }
        else {
            newTerm.c_lflag |= (ICANON | ECHONL);
        }

        if (tcsetattr(STDIN_FILENO, TCSANOW, &newTerm) != 0) {
            printf("Couldn't turn off echo.\n");
            return -1;
        }
    }
#else
    static int echoInit = 0;
    static DWORD originalTerm;
    static CONSOLE_SCREEN_BUFFER_INFO screenOrig;
    HANDLE stdinHandle = GetStdHandle(STD_INPUT_HANDLE);
    if (!echoInit) {
        if (GetConsoleMode(stdinHandle, &originalTerm) == 0) {
            printf("Couldn't get the original terminal settings.\n");
            return -1;
        }
        echoInit = 1;
    }
    if (type == 1) {
        if (SetConsoleMode(stdinHandle, originalTerm) == 0) {
            printf("Couldn't restore the terminal settings.\n");
            return -1;
        }
    }
    else if (type == 2) {
        DWORD newTerm = originalTerm;

        newTerm &= ~ENABLE_PROCESSED_INPUT;
        newTerm &= ~ENABLE_PROCESSED_OUTPUT;
        newTerm &= ~ENABLE_LINE_INPUT;
        newTerm &= ~ENABLE_ECHO_INPUT;
        newTerm &= ~(ENABLE_EXTENDED_FLAGS | ENABLE_INSERT_MODE);

        if (SetConsoleMode(stdinHandle, newTerm) == 0) {
            printf("Couldn't turn off echo.\n");
            return -1;
        }
    }
    else {
        DWORD newTerm = originalTerm;

        newTerm &= ~ENABLE_ECHO_INPUT;

        if (SetConsoleMode(stdinHandle, newTerm) == 0) {
            printf("Couldn't turn off echo.\n");
            return -1;
        }
    }
#endif

    return 0;
}


static void ShowUsage(void)
{
    printf("client %s\n", LIBWOLFSSH_VERSION_STRING);
    printf("./wolfssh <options> user@host\n");
    printf("./wolfssh <options> -u user -h host\n");
    printf(" -?            display this help and exit\n");
    printf(" -h <host>     host to connect to, default %s\n", wolfSshIp);
    printf(" -p <num>      port to connect on, default %d\n", wolfSshPort);
    printf(" -u <username> username to authenticate as (REQUIRED)\n");
    printf(" -P <password> password for username, prompted if omitted\n");
    printf(" -e            use sample ecc key for user\n");
    printf(" -i <filename> filename for the user's private key\n");
    printf(" -j <filename> filename for the user's public key\n");
    printf(" -x            exit after successful connection without doing\n"
           "               read/write\n");
    printf(" -N            use non-blocking sockets\n");
#if !defined(SINGLE_THREADED) && !defined(WOLFSSL_NUCLEUS)
    printf(" -c <command>  executes remote command and pipe stdin/stdout\n");
#ifdef USE_WINDOWS_API
    printf(" -R            raw untranslated output\n");
#endif
#endif
#ifdef WOLFSSH_AGENT
    printf(" -a            Attempt to use SSH-AGENT\n");
#endif
#ifdef WOLFSSH_CERTS
    printf(" -J <filename> filename for DER certificate to use\n");
    printf("               Certificate example : client -u orange \\\n");
    printf("               -J orange-cert.der -i orange-key.der\n");
    printf(" -A <filename> filename for DER CA certificate to verify host\n");
#endif
}


static byte userPassword[256];
static byte userPublicKeyBuf[512];
static byte* userPublicKey = userPublicKeyBuf;
static const byte* userPublicKeyType = NULL;
static const char* pubKeyName = NULL;
static const char* certName = NULL;
static const char* caCert   = NULL;
static byte userPrivateKeyBuf[1191]; /* Size equal to hanselPrivateRsaSz. */
static byte* userPrivateKey = userPrivateKeyBuf;
static const byte* userPrivateKeyType = NULL;
static word32 userPublicKeySz = 0;
static word32 userPublicKeyTypeSz = 0;
static word32 userPrivateKeySz = sizeof(userPrivateKeyBuf);
static word32 userPrivateKeyTypeSz = 0;
static byte isPrivate = 0;


#ifdef WOLFSSH_CERTS
#if 0
/* compiled in for using RSA certificates instead of ECC certificate */
static const byte publicKeyType[] = "x509v3-ssh-rsa";
static const byte privateKeyType[] = "ssh-rsa";
#else
static const byte publicKeyType[] = "x509v3-ecdsa-sha2-nistp256";
#endif
#endif

static int wsUserAuth(byte authType,
                      WS_UserAuthData* authData,
                      void* ctx)
{
    int ret = WOLFSSH_USERAUTH_SUCCESS;

#ifdef DEBUG_WOLFSSH
    /* inspect supported types from server */
    printf("Server supports:\n");
    if (authData->type & WOLFSSH_USERAUTH_PASSWORD) {
        printf(" - password\n");
    }
    if (authData->type & WOLFSSH_USERAUTH_PUBLICKEY) {
        printf(" - publickey\n");
    }
    printf("wolfSSH requesting to use type %d\n", authType);
#endif

    /* Wait for request of public key on names known to have one */
    if ((authData->type & WOLFSSH_USERAUTH_PUBLICKEY) &&
            authData->username != NULL &&
            authData->usernameSz > 0) {

        /* in the case that the name is hansel or in the case that the user
         * passed in a public key file, use public key auth */
        if ((XSTRNCMP((char*)authData->username, "hansel",
                authData->usernameSz) == 0) ||
            pubKeyName != NULL || certName != NULL) {

            if (authType == WOLFSSH_USERAUTH_PASSWORD) {
                printf("rejecting password type with %s in favor of pub key\n",
                    (char*)authData->username);
                return WOLFSSH_USERAUTH_FAILURE;
            }
        }
    }

    if (authType == WOLFSSH_USERAUTH_PUBLICKEY) {
        WS_UserAuthData_PublicKey* pk = &authData->sf.publicKey;

        pk->publicKeyType = userPublicKeyType;
        pk->publicKeyTypeSz = userPublicKeyTypeSz;
        pk->publicKey = userPublicKey;
        pk->publicKeySz = userPublicKeySz;
        pk->privateKey = userPrivateKey;
        pk->privateKeySz = userPrivateKeySz;

        ret = WOLFSSH_USERAUTH_SUCCESS;
    }
    else if (authType == WOLFSSH_USERAUTH_PASSWORD) {
        const char* defaultPassword = (const char*)ctx;
        word32 passwordSz = 0;

        if (defaultPassword != NULL) {
            passwordSz = (word32)strlen(defaultPassword);
            memcpy(userPassword, defaultPassword, passwordSz);
        }
        else {
            printf("Password: ");
            fflush(stdout);
            SetEcho(0);
            if (fgets((char*)userPassword, sizeof(userPassword), stdin) == NULL) {
                printf("Getting password failed.\n");
                ret = WOLFSSH_USERAUTH_FAILURE;
            }
            else {
                char* c = strpbrk((char*)userPassword, "\r\n");
                if (c != NULL)
                    *c = '\0';
            }
            passwordSz = (word32)strlen((const char*)userPassword);
            SetEcho(1);
            #ifdef USE_WINDOWS_API
                printf("\r\n");
            #endif
        }

        if (ret == WOLFSSH_USERAUTH_SUCCESS) {
            authData->sf.password.password = userPassword;
            authData->sf.password.passwordSz = passwordSz;
        }
    }

    return ret;
}


#if defined(WOLFSSH_AGENT) || \
    (defined(WOLFSSH_CERTS) && \
        (defined(OPENSSL_ALL) || defined(WOLFSSL_IP_ALT_NAME)))
static inline void ato32(const byte* c, word32* u32)
{
    *u32 = (c[0] << 24) | (c[1] << 16) | (c[2] << 8) | c[3];
}
#endif


#if defined(WOLFSSH_CERTS) && \
    (defined(OPENSSL_ALL) || defined(WOLFSSL_IP_ALT_NAME))
static int ParseRFC6187(const byte* in, word32 inSz, byte** leafOut,
    word32* leafOutSz)
{
    int ret = WS_SUCCESS;
    word32 l = 0, m = 0;

    if (inSz < sizeof(word32)) {
        printf("inSz %d too small for holding cert name\n", inSz);
        return WS_BUFFER_E;
    }

    /* Skip the name */
    ato32(in, &l);
    m += l + sizeof(word32);

    /* Get the cert count */
    if (ret == WS_SUCCESS) {
        word32 count;

        if (inSz - m < sizeof(word32))
            return WS_BUFFER_E;

        ato32(in + m, &count);
        m += sizeof(word32);
        if (ret == WS_SUCCESS && count == 0)
            ret = WS_FATAL_ERROR; /* need at least one cert */
    }

    if (ret == WS_SUCCESS) {
        word32 certSz = 0;

        if (inSz - m < sizeof(word32))
            return WS_BUFFER_E;

        ato32(in + m, &certSz);
        m += sizeof(word32);
        if (ret == WS_SUCCESS) {
            /* store leaf cert size to present to user callback */
            *leafOutSz = certSz;
            *leafOut   = (byte*)in + m;
        }

        if (inSz - m < certSz)
            return WS_BUFFER_E;

   }

    return ret;
}
#endif /* WOLFSSH_CERTS */


static int wsPublicKeyCheck(const byte* pubKey, word32 pubKeySz, void* ctx)
{
    int ret = 0;

    #ifdef DEBUG_WOLFSSH
        printf("Sample public key check callback\n"
               "  public key = %p\n"
               "  public key size = %u\n"
               "  ctx = %s\n", pubKey, pubKeySz, (const char*)ctx);
    #else
        (void)pubKey;
        (void)pubKeySz;
        (void)ctx;
    #endif

#ifdef WOLFSSH_CERTS
#if defined(OPENSSL_ALL) || defined(WOLFSSL_IP_ALT_NAME)
    /* try to parse the certificate and check it's IP address */
    if (pubKeySz > 0) {
        DecodedCert dCert;
        byte*  der   = NULL;
        word32 derSz = 0;

        if (ParseRFC6187(pubKey, pubKeySz, &der, &derSz) == WS_SUCCESS) {
            wc_InitDecodedCert(&dCert, der,  derSz, NULL);
            if (wc_ParseCert(&dCert, CERT_TYPE, NO_VERIFY, NULL) != 0) {
                printf("public key not a cert\n");
            }
            else {
                int ipMatch = 0;
                DNS_entry* current = dCert.altNames;

                while (current != NULL) {
                    if (current->type == ASN_IP_TYPE) {
                        printf("host cert alt. name IP : %s\n",
                            current->ipString);
                        printf("\texpecting host IP : %s\n", (char*)ctx);
                        if (XSTRCMP(ctx, current->ipString) == 0) {
                            printf("\tmatched!\n");
                            ipMatch = 1;
                        }
                    }
                    current = current->next;
                }

                if (ipMatch == 0) {
                    printf("IP did not match expected IP\n");
                    ret = -1;
                }
            }
            FreeDecodedCert(&dCert);
        }
    }
#else
    printf("wolfSSL not built with OPENSSL_ALL or WOLFSSL_IP_ALT_NAME\n");
    printf("\tnot checking IP address from peer's cert\n");
#endif
#endif

    return ret;
}


static int NonBlockSSH_connect(WOLFSSH* ssh)
{
    int ret;
    int error;
    SOCKET_T sockfd;
    int select_ret = 0;

    ret = wolfSSH_connect(ssh);
    error = wolfSSH_get_error(ssh);
    sockfd = (SOCKET_T)wolfSSH_get_fd(ssh);

    while (ret != WS_SUCCESS &&
            (error == WS_WANT_READ || error == WS_WANT_WRITE))
    {
        if (error == WS_WANT_READ)
            printf("... client would read block\n");
        else if (error == WS_WANT_WRITE)
            printf("... client would write block\n");

        select_ret = tcp_select(sockfd, 1);
        if (select_ret == WS_SELECT_RECV_READY ||
            select_ret == WS_SELECT_ERROR_READY)
        {
            ret = wolfSSH_connect(ssh);
        }
        else if (select_ret == WS_SELECT_TIMEOUT)
            error = WS_WANT_READ;
        else
            error = WS_FATAL_ERROR;
    }

    return ret;
}

#if !defined(SINGLE_THREADED) && !defined(WOLFSSL_NUCLEUS)

typedef struct thread_args {
    WOLFSSH* ssh;
    wolfSSL_Mutex lock;
    byte rawMode;
} thread_args;

#ifdef _POSIX_THREADS
    #define THREAD_RET void*
    #define THREAD_RET_SUCCESS NULL
#elif defined(_MSC_VER)
    #define THREAD_RET DWORD WINAPI
    #define THREAD_RET_SUCCESS 0
#else
    #define THREAD_RET int
    #define THREAD_RET_SUCCESS 0
#endif

static THREAD_RET readInput(void* in)
{
    byte buf[256];
    int  bufSz = sizeof(buf);
    thread_args* args = (thread_args*)in;
    int ret = 0;
    word32 sz = 0;
#ifdef USE_WINDOWS_API
    HANDLE stdinHandle = GetStdHandle(STD_INPUT_HANDLE);
#endif

    while (ret >= 0) {
        WMEMSET(buf, 0, bufSz);
    #ifdef USE_WINDOWS_API
        /* Using A version to avoid potential 2 byte chars */
        ret = ReadConsoleA(stdinHandle, (void*)buf, bufSz - 1, (DWORD*)&sz,
                NULL);
    #else
        ret = (int)read(STDIN_FILENO, buf, bufSz -1);
        sz  = (word32)ret;
    #endif
        if (ret <= 0) {
            fprintf(stderr, "Error reading stdin\n");
            return THREAD_RET_SUCCESS;
        }
        /* lock SSH structure access */
        wc_LockMutex(&args->lock);
        ret = wolfSSH_stream_send(args->ssh, buf, sz);
        wc_UnLockMutex(&args->lock);
        if (ret <= 0) {
            fprintf(stderr, "Couldn't send data\n");
            return THREAD_RET_SUCCESS;
        }
    }
#if !defined(WOLFSSH_NO_ECC) && defined(FP_ECC) && defined(HAVE_THREAD_LS)
    wc_ecc_fp_free();  /* free per thread cache */
#endif
    return THREAD_RET_SUCCESS;
}


static THREAD_RET readPeer(void* in)
{
    byte buf[80];
    int  bufSz = sizeof(buf);
    thread_args* args = (thread_args*)in;
    int ret = 0;
    int fd = wolfSSH_get_fd(args->ssh);
    word32 bytes;
#ifdef USE_WINDOWS_API
    HANDLE stdoutHandle = GetStdHandle(STD_OUTPUT_HANDLE);
#endif
    fd_set readSet;
    fd_set errSet;

    FD_ZERO(&readSet);
    FD_ZERO(&errSet);
    FD_SET(fd, &readSet);
    FD_SET(fd, &errSet);

    while (ret >= 0) {
        bytes = select(fd + 1, &readSet, NULL, &errSet, NULL);
        wc_LockMutex(&args->lock);
        while (bytes > 0 && (FD_ISSET(fd, &readSet) || FD_ISSET(fd, &errSet))) {
            /* there is something to read off the wire */
            WMEMSET(buf, 0, bufSz);
            ret = wolfSSH_stream_read(args->ssh, buf, bufSz - 1);
            if (ret == WS_EXTDATA) { /* handle extended data */
                do {
                    WMEMSET(buf, 0, bufSz);
                    ret = wolfSSH_extended_data_read(args->ssh, buf, bufSz - 1);
                    if (ret < 0)
                        err_sys("Extended data read failed.");
                    buf[bufSz - 1] = '\0';
                    fprintf(stderr, "%s", buf);
                } while (ret > 0);
            }
            else if (ret <= 0) {
                #ifdef WOLFSSH_AGENT
                if (ret == WS_FATAL_ERROR) {
                    ret = wolfSSH_get_error(args->ssh);
                    if (ret == WS_CHAN_RXD) {
                        byte agentBuf[512];
                        int rxd, txd;
                        word32 channel = 0;

                        wolfSSH_GetLastRxId(args->ssh, &channel);
                        rxd = wolfSSH_ChannelIdRead(args->ssh, channel,
                                agentBuf, sizeof(agentBuf));
                        if (rxd > 4) {
                            word32 msgSz = 0;

                            ato32(agentBuf, &msgSz);
                            if (msgSz > (word32)rxd - 4) {
                                rxd += wolfSSH_ChannelIdRead(args->ssh, channel,
                                        agentBuf + rxd,
                                        sizeof(agentBuf) - rxd);
                            }

                            txd = rxd;
                            rxd = sizeof(agentBuf);
                            ret = wolfSSH_AGENT_Relay(args->ssh,
                                    agentBuf, (word32*)&txd,
                                    agentBuf, (word32*)&rxd);
                            if (ret == WS_SUCCESS) {
                                ret = wolfSSH_ChannelIdSend(args->ssh, channel,
                                        agentBuf, rxd);
                            }
                        }
                        WMEMSET(agentBuf, 0, sizeof(agentBuf));
                        continue;
                    }
                }
                #endif
                if (ret != WS_EOF) {
                    err_sys("Stream read failed.");
                }
            }
            else {
                buf[bufSz - 1] = '\0';

            #ifdef USE_WINDOWS_API
                if (args->rawMode == 0) {
                    ret = wolfSSH_ConvertConsole(args->ssh, stdoutHandle, buf,
                            ret);
                    if (ret != WS_SUCCESS && ret != WS_WANT_READ) {
                        err_sys("issue with print out");
                    }
                    if (ret == WS_WANT_READ) {
                        ret = 0;
                    }
                }
                else {
                    printf("%s", buf);
                    fflush(stdout);
                }
            #else
                printf("%s", buf);
                fflush(stdout);
            #endif
            }
            if (wolfSSH_stream_peek(args->ssh, buf, bufSz) <= 0) {
                bytes = 0; /* read it all */
            }
        }
        wc_UnLockMutex(&args->lock);
    }
#if !defined(WOLFSSH_NO_ECC) && defined(FP_ECC) && defined(HAVE_THREAD_LS)
    wc_ecc_fp_free();  /* free per thread cache */
#endif

    return THREAD_RET_SUCCESS;
}
#endif /* !SINGLE_THREADED && !WOLFSSL_NUCLEUS */


#ifdef WOLFSSH_CERTS

static int load_der_file(const char* filename, byte** out, word32* outSz)
{
    WFILE* file;
    byte* in;
    word32 inSz;
    int ret;

    if (filename == NULL || out == NULL || outSz == NULL)
        return -1;

    ret = WFOPEN(&file, filename, "rb");
    if (ret != 0 || file == WBADFILE)
        return -1;

    if (WFSEEK(file, 0, WSEEK_END) != 0) {
        WFCLOSE(file);
        return -1;
    }
    inSz = (word32)WFTELL(file);
    WREWIND(file);

    if (inSz == 0) {
        WFCLOSE(file);
        return -1;
    }

    in = (byte*)WMALLOC(inSz, NULL, 0);
    if (in == NULL) {
        WFCLOSE(file);
        return -1;
    }

    ret = (int)WFREAD(in, 1, inSz, file);
    if (ret <= 0 || (word32)ret != inSz) {
        ret = -1;
        WFREE(in, NULL, 0);
        in = 0;
        inSz = 0;
    }
    else
        ret = 0;

    *out = in;
    *outSz = inSz;

    WFCLOSE(file);

    return ret;
}

#endif /* WOLFSSH_CERTS */


#if defined(WOLFSSL_PTHREADS) && defined(WOLFSSL_TEST_GLOBAL_REQ)

static int callbackGlobalReq(WOLFSSH *ssh, void *buf, word32 sz, int reply, void *ctx)
{
    char reqStr[] = "SampleRequest";

    if ((WOLFSSH *)ssh != *(WOLFSSH **)ctx)
    {
        printf("ssh(%x) != ctx(%x)\n", (unsigned int)ssh, (unsigned int)*(WOLFSSH **)ctx);
        return WS_FATAL_ERROR;
    }

    if (strlen(reqStr) == sz && (strncmp((char *)buf, reqStr, sz) == 0)
        && reply == 1){
        printf("Global Request\n");
        return WS_SUCCESS;
    } else {
        return WS_FATAL_ERROR;
    }

}
#endif


#ifdef WOLFSSH_AGENT
typedef struct WS_AgentCbActionCtx {
    struct sockaddr_un name;
    int fd;
    int state;
} WS_AgentCbActionCtx;

static const char EnvNameAuthPort[] = "SSH_AUTH_SOCK";

static int wolfSSH_AGENT_DefaultActions(WS_AgentCbAction action, void* vCtx)
{
    WS_AgentCbActionCtx* ctx = (WS_AgentCbActionCtx*)vCtx;
    int ret = WS_AGENT_SUCCESS;

    if (action == WOLFSSH_AGENT_LOCAL_SETUP) {
        const char* sockName;
        struct sockaddr_un* name = &ctx->name;
        size_t size;
        int err;

        sockName = getenv(EnvNameAuthPort);
        if (sockName == NULL)
            ret = WS_AGENT_NOT_AVAILABLE;

        if (ret == WS_AGENT_SUCCESS) {
            memset(name, 0, sizeof(struct sockaddr_un));
            name->sun_family = AF_LOCAL;
            strncpy(name->sun_path, sockName, sizeof(name->sun_path));
            name->sun_path[sizeof(name->sun_path) - 1] = '\0';
            size = strlen(sockName) +
                    offsetof(struct sockaddr_un, sun_path);

            ctx->fd = socket(AF_UNIX, SOCK_STREAM, 0);
            if (ctx->fd == -1) {
                ret = WS_AGENT_SETUP_E;
                err = errno;
                fprintf(stderr, "socket() = %d\n", err);
            }
        }

        if (ret == WS_AGENT_SUCCESS) {
            ret = connect(ctx->fd,
                    (struct sockaddr *)name, (socklen_t)size);
            if (ret < 0) {
                ret = WS_AGENT_SETUP_E;
                err = errno;
                fprintf(stderr, "connect() = %d", err);
            }
        }

        if (ret == WS_AGENT_SUCCESS)
            ctx->state = AGENT_STATE_CONNECTED;
    }
    else if (action == WOLFSSH_AGENT_LOCAL_CLEANUP) {
        int err;

        err = close(ctx->fd);
        if (err != 0) {
            err = errno;
            fprintf(stderr, "close() = %d", err);
            if (ret == 0)
                ret = WS_AGENT_SETUP_E;
        }
    }
    else
        ret = WS_AGENT_INVALID_ACTION;

    return ret;
}


static int wolfSSH_AGENT_IO_Cb(WS_AgentIoCbAction action,
        void* buf, word32 bufSz, void* vCtx)
{
    WS_AgentCbActionCtx* ctx = (WS_AgentCbActionCtx*)vCtx;
    int ret = WS_AGENT_INVALID_ACTION;

    if (action == WOLFSSH_AGENT_IO_WRITE) {
        const byte* wBuf = (const byte*)buf;
        ret = (int)write(ctx->fd, wBuf, bufSz);
        if (ret < 0) {
            ret = WS_CBIO_ERR_GENERAL;
        }
    }
    else if (action == WOLFSSH_AGENT_IO_READ) {
        byte* rBuf = (byte*)buf;
        ret = (int)read(ctx->fd, rBuf, bufSz);
        if (ret < 0) {
            ret = WS_CBIO_ERR_GENERAL;
        }
    }

    return ret;
}


#endif /* WOLFSSH_AGENT */


#define MAX_USERNAME 120
#define MAX_HOSTNAME 25

THREAD_RETURN WOLFSSH_THREAD client_test(void* args)
{
    WOLFSSH_CTX* ctx = NULL;
    WOLFSSH* ssh = NULL;
    SOCKET_T sockFd = WOLFSSH_SOCKET_INVALID;
    SOCKADDR_IN_T clientAddr;
    socklen_t clientAddrSz = sizeof(clientAddr);
    //char rxBuf[80];
    int ret = 0;
    int ch;
    //int userEcc = 0;
    word16 port = wolfSshPort;
    char* host = (char*)wolfSshIp;
    const char* username = NULL;
    const char* password = NULL;
    const char* cmd      = NULL;
    const char* privKeyName = NULL;
    //byte imExit = 0;
    byte nonBlock = 0;
    byte keepOpen = 1;
#ifdef USE_WINDOWS_API
    byte rawMode = 0;
#endif
#ifdef WOLFSSH_AGENT
    byte useAgent = 0;
    WS_AgentCbActionCtx agentCbCtx;
#endif
    char localUsername[MAX_USERNAME];
    char localHostname[MAX_HOSTNAME];
    char localCmd[120];

    int     argc = ((func_args*)args)->argc;
    char**  argv = ((func_args*)args)->argv;
    ((func_args*)args)->return_code = 0;


    /* test if command is set */
    if (argc > 0 && XSTRSTR(argv[argc-1], "@") == NULL &&
            argv[argc-1][0] != '-') {
        int cmdSz;

        cmdSz = (int)XSTRLEN(argv[argc-1]);
        XMEMCPY(localCmd, argv[argc-1], cmdSz);
        localCmd[cmdSz] = '\0';
        cmd = &localCmd[0];
        argc -= 1;
    }

    /* test if user@host is used */
    if (argc > 0 && XSTRSTR(argv[argc-1], "@")) {
        int usernameSz;
        int hostnameSz;

        username = argv[argc-1];
        host = XSTRSTR(username, "@");

        usernameSz = (int)((uintptr_t)host - (uintptr_t)username);
        XMEMCPY(localUsername, username, usernameSz);
        localUsername[usernameSz] = '\0';

        hostnameSz = (int)XSTRLEN(host);
        if (hostnameSz <= 1) {

        }

        XMEMCPY(localHostname, host+1, hostnameSz-1);
        localHostname[hostnameSz-1] = '\0';

        username = &localUsername[0];
        host = &localHostname[0];
        argc -= 1;
    }

    while ((ch = mygetopt(argc, argv, "?ac:eh:i:j:p:tu:xzNP:RJ:A:")) != -1) {
        switch (ch) {
            case 'h':
                host = myoptarg;
                break;

            case 'z':
            #ifdef WOLFSSH_SHOW_SIZES
                wolfSSH_ShowSizes();
                exit(EXIT_SUCCESS);
            #endif
                break;

            case 'e':
                //userEcc = 1;
                break;

            case 'p':
                port = (word16)atoi(myoptarg);
                #if !defined(NO_MAIN_DRIVER) || defined(USE_WINDOWS_API)
                    if (port == 0)
                        err_sys("port number cannot be 0");
                #endif
                break;

            case 'u':
                username = myoptarg;
                break;

            case 'P':
                password = myoptarg;
                break;

            case 'i':
                privKeyName = myoptarg;
                break;

            case 'j':
                pubKeyName = myoptarg;
                break;

        #ifdef WOLFSSH_CERTS
            case 'J':
                certName = myoptarg;
                break;

            case 'A':
                caCert = myoptarg;
                break;

        #endif

            case 'x':
                /* exit after successful connection without read/write */
                //imExit = 1;
                break;

            case 'N':
                nonBlock = 1;
                break;

        #if !defined(SINGLE_THREADED) && !defined(WOLFSSL_NUCLEUS)
            case 'c':
                cmd = myoptarg;
                break;
        #ifdef USE_WINDOWS_API
           case 'R':
                rawMode = 1;
                break;
        #endif /* USE_WINDOWS_API */
        #endif

        #ifdef WOLFSSH_AGENT
            case 'a':
                useAgent = 1;
                break;
        #endif

            case '?':
                ShowUsage();
                exit(EXIT_SUCCESS);

            default:
                ShowUsage();
                exit(MY_EX_USAGE);
        }
    }
    myoptind = 0;      /* reset for test cases */

    if (username == NULL)
        err_sys("client requires a username parameter.");

#ifdef WOLFSSH_NO_RSA
    userEcc = 1;
#endif

#ifdef SINGLE_THREADED
    if (keepOpen)
        err_sys("Threading needed for terminal session\n");
#endif

    if ((pubKeyName == NULL && certName == NULL) && privKeyName != NULL) {
        err_sys("If setting priv key, need pub key.");
    }

    if (privKeyName == NULL) {
//        if (userEcc) {
//        #ifndef WOLFSSH_NO_ECC
//            ret = wolfSSH_ReadKey_buffer(hanselPrivateEcc, hanselPrivateEccSz,
//                    WOLFSSH_FORMAT_ASN1, &userPrivateKey, &userPrivateKeySz,
//                    &userPrivateKeyType, &userPrivateKeyTypeSz, NULL);
//        #endif
//        }
//        else {
//        #ifndef WOLFSSH_NO_RSA
//            ret = wolfSSH_ReadKey_buffer(hanselPrivateRsa, hanselPrivateRsaSz,
//                    WOLFSSH_FORMAT_ASN1, &userPrivateKey, &userPrivateKeySz,
//                    &userPrivateKeyType, &userPrivateKeyTypeSz, NULL);
//        #endif
//        }
//        isPrivate = 1;
//        if (ret != 0) err_sys("Couldn't load private key buffer.");
    }
    else {
    #ifndef NO_FILESYSTEM
        userPrivateKey = NULL; /* create new buffer based on parsed input */
        ret = wolfSSH_ReadKey_file(privKeyName,
                (byte**)&userPrivateKey, &userPrivateKeySz,
                (const byte**)&userPrivateKeyType, &userPrivateKeyTypeSz,
                &isPrivate, NULL);
    #else
        printf("file system not compiled in!\n");
        ret = -1;
    #endif
        if (ret != 0) err_sys("Couldn't load private key file.");
    }

#ifdef WOLFSSH_CERTS
    /* passed in certificate to use */
    if (certName) {
        ret = load_der_file(certName, &userPublicKey, &userPublicKeySz);
        if (ret != 0) err_sys("Couldn't load certificate file.");

        userPublicKeyType = publicKeyType;
        userPublicKeyTypeSz = (word32)WSTRLEN((const char*)publicKeyType);
    }
    else
#endif
    if (pubKeyName == NULL) {
//        byte* p = userPublicKey;
//        userPublicKeySz = sizeof(userPublicKeyBuf);
//
//        if (userEcc) {
//        #ifndef WOLFSSH_NO_ECC
//            ret = wolfSSH_ReadKey_buffer((const byte*)hanselPublicEcc,
//                    (word32)strlen(hanselPublicEcc), WOLFSSH_FORMAT_SSH,
//                    &p, &userPublicKeySz,
//                    &userPublicKeyType, &userPublicKeyTypeSz, NULL);
//        #endif
//        }
//        else {
//        #ifndef WOLFSSH_NO_RSA
//            ret = wolfSSH_ReadKey_buffer((const byte*)hanselPublicRsa,
//                    (word32)strlen(hanselPublicRsa), WOLFSSH_FORMAT_SSH,
//                    &p, &userPublicKeySz,
//                    &userPublicKeyType, &userPublicKeyTypeSz, NULL);
//        #endif
//        }
//        isPrivate = 1;
//        if (ret != 0) err_sys("Couldn't load public key buffer.");
    }
    else {
    #ifndef NO_FILESYSTEM
        userPublicKey = NULL; /* create new buffer based on parsed input */
        ret = wolfSSH_ReadKey_file(pubKeyName,
                &userPublicKey, &userPublicKeySz,
                (const byte**)&userPublicKeyType, &userPublicKeyTypeSz,
                &isPrivate, NULL);
    #else
        printf("file system not compiled in!\n");
        ret = -1;
    #endif
        if (ret != 0) err_sys("Couldn't load public key file.");
    }

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_CLIENT, NULL);
    if (ctx == NULL)
        err_sys("Couldn't create wolfSSH client context.");

    if (((func_args*)args)->user_auth == NULL)
        wolfSSH_SetUserAuth(ctx, wsUserAuth);
    else
        wolfSSH_SetUserAuth(ctx, ((func_args*)args)->user_auth);

#ifdef WOLFSSH_AGENT
    if (useAgent) {
        wolfSSH_CTX_set_agent_cb(ctx,
                wolfSSH_AGENT_DefaultActions, wolfSSH_AGENT_IO_Cb);
        wolfSSH_CTX_AGENT_enable(ctx, 1);
    }
#endif

    ssh = wolfSSH_new(ctx);
    if (ssh == NULL)
        err_sys("Couldn't create wolfSSH session.");

#if defined(WOLFSSL_PTHREADS) && defined(WOLFSSL_TEST_GLOBAL_REQ)
    wolfSSH_SetGlobalReq(ctx, callbackGlobalReq);
    wolfSSH_SetGlobalReqCtx(ssh, &ssh); /* dummy ctx */
#endif

    if (password != NULL)
        wolfSSH_SetUserAuthCtx(ssh, (void*)password);

#ifdef WOLFSSH_AGENT
    if (useAgent) {
        memset(&agentCbCtx, 0, sizeof(agentCbCtx));
        agentCbCtx.state = AGENT_STATE_INIT;
        wolfSSH_set_agent_cb_ctx(ssh, &agentCbCtx);
    }
#endif
#ifdef WOLFSSH_CERTS
    /* CA certificate to verify host cert with */
    if (caCert) {
        byte* der = NULL;
        word32 derSz;

        ret = load_der_file(caCert, &der, &derSz);
        if (ret != 0) err_sys("Couldn't load CA certificate file.");
        if (wolfSSH_CTX_AddRootCert_buffer(ctx, der, derSz,
            WOLFSSH_FORMAT_ASN1) != WS_SUCCESS) {
            err_sys("Couldn't parse in CA certificate.");
        }
        WFREE(der, NULL, 0);
    }

#else
    (void)caCert;
#endif /* WOLFSSH_CERTS */

    wolfSSH_CTX_SetPublicKeyCheck(ctx, wsPublicKeyCheck);
    wolfSSH_SetPublicKeyCheckCtx(ssh, (void*)host);

    ret = wolfSSH_SetUsername(ssh, username);
    if (ret != WS_SUCCESS)
        err_sys("Couldn't set the username.");

    build_addr(&clientAddr, host, port);
    tcp_socket(&sockFd);
    ret = connect(sockFd, (const struct sockaddr *)&clientAddr, clientAddrSz);
    if (ret != 0)
        err_sys("Couldn't connect to server.");

    if (nonBlock)
        tcp_set_nonblocking(&sockFd);

    ret = wolfSSH_set_fd(ssh, (int)sockFd);
    if (ret != WS_SUCCESS)
        err_sys("Couldn't set the session's socket.");

    if (cmd != NULL) {
        ret = wolfSSH_SetChannelType(ssh, WOLFSSH_SESSION_EXEC,
                            (byte*)cmd, (word32)WSTRLEN((char*)cmd));
        if (ret != WS_SUCCESS)
            err_sys("Couldn't set the channel type.");
    }

#ifdef WOLFSSH_TERM
    if (keepOpen && cmd == NULL) {
        ret = wolfSSH_SetChannelType(ssh, WOLFSSH_SESSION_TERMINAL, NULL, 0);
        if (ret != WS_SUCCESS)
            err_sys("Couldn't set the terminal channel type.");
    }
#endif

    if (!nonBlock)
        ret = wolfSSH_connect(ssh);
    else
        ret = NonBlockSSH_connect(ssh);
    if (ret != WS_SUCCESS)
        err_sys("Couldn't connect SSH stream.");

#if !defined(SINGLE_THREADED) && !defined(WOLFSSL_NUCLEUS)
    if (keepOpen) /* set up for psuedo-terminal */
        SetEcho(2);

    if (cmd != NULL || keepOpen == 1) {
    #if defined(_POSIX_THREADS)
        thread_args arg;
        pthread_t   thread[2];

        arg.ssh = ssh;
        wc_InitMutex(&arg.lock);
        pthread_create(&thread[0], NULL, readInput, (void*)&arg);
        pthread_create(&thread[1], NULL, readPeer, (void*)&arg);
        pthread_join(thread[1], NULL);
        pthread_cancel(thread[0]);
    #elif defined(_MSC_VER)
        thread_args arg;
        HANDLE thread[2];

        arg.ssh     = ssh;
        arg.rawMode = rawMode;
        wc_InitMutex(&arg.lock);
        thread[0] = CreateThread(NULL, 0, readInput, (void*)&arg, 0, 0);
        thread[1] = CreateThread(NULL, 0, readPeer, (void*)&arg, 0, 0);
        WaitForSingleObject(thread[1], INFINITE);
        CloseHandle(thread[0]);
        CloseHandle(thread[1]);
    #else
        err_sys("No threading to use");
    #endif
        if (keepOpen)
            SetEcho(1);
    }
//    else
#endif

//#if defined(WOLFSSL_PTHREADS) && defined(WOLFSSL_TEST_GLOBAL_REQ)
//    while (!imExit) {
//#else
//    if (!imExit) {
//#endif
//        ret = wolfSSH_stream_send(ssh, (byte*)testString,
//                                  (word32)strlen(testString));
//        if (ret <= 0)
//            err_sys("Couldn't send test string.");
//
//        do {
//            ret = wolfSSH_stream_read(ssh, (byte*)rxBuf, sizeof(rxBuf) - 1);
//            if (ret <= 0) {
//                ret = wolfSSH_get_error(ssh);
//                if (ret != WS_WANT_READ && ret != WS_WANT_WRITE &&
//                        ret != WS_CHAN_RXD)
//                    err_sys("Stream read failed.");
//            }
//        } while (ret == WS_WANT_READ || ret == WS_WANT_WRITE);
//
//        rxBuf[ret] = '\0';
//        printf("Server said: %s\n", rxBuf);
//
//#if defined(WOLFSSL_PTHREADS) && defined(WOLFSSL_TEST_GLOBAL_REQ)
//        sleep(10);
//#endif
//    }
    ret = wolfSSH_shutdown(ssh);
    if (ret != WS_SUCCESS) {
        err_sys("Sending the shutdown messages failed.");
    }
    ret = wolfSSH_worker(ssh, NULL);
    if (ret != WS_SUCCESS) {
        err_sys("Failed to listen for close messages from the peer.");
    }
    WCLOSESOCKET(sockFd);
    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);
    if (ret != WS_SUCCESS)
        err_sys("Closing client stream failed. Connection could have been closed by peer");

    if (pubKeyName != NULL && userPublicKey != NULL) {
        WFREE(userPublicKey, NULL, DYNTYPE_PRIVKEY);
    }

    if (privKeyName != NULL && userPrivateKey != NULL) {
        WFREE(userPrivateKey, NULL, DYNTYPE_PRIVKEY);
    }
#if !defined(WOLFSSH_NO_ECC) && defined(FP_ECC) && defined(HAVE_THREAD_LS)
    wc_ecc_fp_free();  /* free per thread cache */
#endif

    return 0;
}

#endif /* NO_WOLFSSH_CLIENT */


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

        wolfSSH_Init();

        ChangeToWolfSshRoot();
#ifndef NO_WOLFSSH_CLIENT
        client_test(&args);
#endif

        wolfSSH_Cleanup();

        return args.return_code;
    }

    int myoptind = 0;
    char* myoptarg = NULL;

#endif /* NO_MAIN_DRIVER */

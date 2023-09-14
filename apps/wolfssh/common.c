/* common.c
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

#include <wolfssh/ssh.h>
#include <wolfssh/internal.h>
#include <wolfssh/wolfsftp.h>
#include <wolfssh/port.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/coding.h>
#include "apps/wolfssh/common.h"
#ifndef USE_WINDOWS_API
    #include <termios.h>
#endif

#ifdef WOLFSSH_CERTS
    #include <wolfssl/wolfcrypt/asn.h>
#endif

static byte userPublicKeyBuf[512];
static byte* userPublicKey = userPublicKeyBuf;
static const byte* userPublicKeyType = NULL;
static byte userPassword[256];
static const byte* userPrivateKeyType = NULL;
static word32 userPublicKeySz = 0;
static byte pubKeyLoaded = 0; /* was a public key loaded */
static byte userPrivateKeyBuf[1191];
static byte* userPrivateKey = userPrivateKeyBuf;
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


#if defined(WOLFSSH_CERTS)

static int load_der_file(const char* filename, byte** out, word32* outSz)
{
    WFILE* file;
    byte* in;
    word32 inSz;
    int ret;

    if (filename == NULL || out == NULL || outSz == NULL)
        return -1;

    ret = WFOPEN(NULL, &file, filename, "rb");
    if (ret != 0 || file == WBADFILE)
        return -1;

    if (WFSEEK(NULL, file, 0, WSEEK_END) != 0) {
        WFCLOSE(NULL, file);
        return -1;
    }
    inSz = (word32)WFTELL(NULL, file);
    WREWIND(NULL, file);

    if (inSz == 0) {
        WFCLOSE(NULL, file);
        return -1;
    }

    in = (byte*)WMALLOC(inSz, NULL, 0);
    if (in == NULL) {
        WFCLOSE(NULL, file);
        return -1;
    }

    ret = (int)WFREAD(NULL, in, 1, inSz, file);
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

    WFCLOSE(NULL, file);

    return ret;
}


#if (defined(OPENSSL_ALL) || defined(WOLFSSL_IP_ALT_NAME))
static inline void ato32(const byte* c, word32* u32)
{
    *u32 = (c[0] << 24) | (c[1] << 16) | (c[2] << 8) | c[3];
}

/* when set as true then ignore miss matching IP addresses */
static int IPOverride = 0;

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

void ClientIPOverride(int flag)
{
    IPOverride = flag;
}
#endif /* OPENSSL_ALL || WOLFSSL_IP_ALT_NAME */
#endif /* WOLFSSH_CERTS */


int ClientPublicKeyCheck(const byte* pubKey, word32 pubKeySz, void* ctx)
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
                WLOG(WS_LOG_DEBUG, "public key not a cert");
            }
            else {
                int ipMatch = 0;
                DNS_entry* current = dCert.altNames;

                if (ctx == NULL) {
                    WLOG(WS_LOG_ERROR, "No host IP set to check against!");
                    ret = -1;
                }

                if (ret == 0) {
                    while (current != NULL) {
                        if (current->type == ASN_IP_TYPE) {
                            WLOG(WS_LOG_DEBUG, "host cert alt. name IP : %s",
                                current->ipString);
                            WLOG(WS_LOG_DEBUG,
                                "\texpecting host IP : %s", (char*)ctx);
                            if (XSTRCMP(ctx, current->ipString) == 0) {
                                WLOG(WS_LOG_DEBUG, "\tmatched!");
                                ipMatch = 1;
                            }
                        }
                        current = current->next;
                    }
                }

                if (ipMatch == 0) {
                    printf("IP did not match expected IP");
                    if (!IPOverride) {
                        printf("\n");
                        ret = -1;
                    }
                    else {
                        ret = 0;
                        printf("..overriding\n");
                    }
                }
            }
            FreeDecodedCert(&dCert);
        }
    }
#else
    WLOG(WS_LOG_DEBUG, "wolfSSL not built with OPENSSL_ALL or WOLFSSL_IP_ALT_NAME");
    WLOG(WS_LOG_DEBUG, "\tnot checking IP address from peer's cert");
#endif
#endif

    return ret;
}


int ClientUserAuth(byte authType,
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

        /* in the case that the user passed in a public key file,
         * use public key auth */
        if (pubKeyLoaded == 1) {
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
            ClientSetEcho(0);
            if (fgets((char*)userPassword, sizeof(userPassword), stdin) == NULL) {
                fprintf(stderr, "Getting password failed.\n");
                ret = WOLFSSH_USERAUTH_FAILURE;
            }
            else {
                char* c = strpbrk((char*)userPassword, "\r\n");
                if (c != NULL)
                    *c = '\0';
            }
            passwordSz = (word32)strlen((const char*)userPassword);
            ClientSetEcho(1);
            #ifdef USE_WINDOWS_API
                printf("\r\n");
            #endif
            fflush(stdout);
        }

        if (ret == WOLFSSH_USERAUTH_SUCCESS) {
            authData->sf.password.password = userPassword;
            authData->sf.password.passwordSz = passwordSz;
        }
    }

    return ret;
}


/* type = 2 : shell / execute command settings
 * type = 0 : password
 * type = 1 : restore default
 * return 0 on success */
int ClientSetEcho(int type)
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


/* Set certificate to use and public key.
 * returns 0 on success */
int ClientUseCert(const char* certName)
{
    int ret = 0;

    if (certName != NULL) {
    #ifdef WOLFSSH_CERTS
        ret = load_der_file(certName, &userPublicKey, &userPublicKeySz);
        if (ret == 0) {
            userPublicKeyType = publicKeyType;
            userPublicKeyTypeSz = (word32)WSTRLEN((const char*)publicKeyType);
            pubKeyLoaded = 1;
        }
    #else
        fprintf(stderr, "Certificate support not compiled in");
        ret = WS_NOT_COMPILED;
    #endif
    }

    return ret;
}


/* Reads the private key to use from file name privKeyName.
 * returns 0 on success */
int ClientSetPrivateKey(const char* privKeyName)
{
    int ret;

    userPrivateKey = NULL; /* create new buffer based on parsed input */
    ret = wolfSSH_ReadKey_file(privKeyName,
            (byte**)&userPrivateKey, &userPrivateKeySz,
            (const byte**)&userPrivateKeyType, &userPrivateKeyTypeSz,
            &isPrivate, NULL);

    return ret;
}


/* Set public key to use
 * returns 0 on success */
int ClientUsePubKey(const char* pubKeyName)
{
    int ret;

    userPublicKey = NULL; /* create new buffer based on parsed input */
    ret = wolfSSH_ReadKey_file(pubKeyName,
            &userPublicKey, &userPublicKeySz,
            (const byte**)&userPublicKeyType, &userPublicKeyTypeSz,
            &isPrivate, NULL);

    if (ret == 0) {
        pubKeyLoaded = 1;
    }

    return ret;
}

int ClientLoadCA(WOLFSSH_CTX* ctx, const char* caCert)
{
    int ret = 0;

    /* CA certificate to verify host cert with */
    if (caCert) {
    #ifdef WOLFSSH_CERTS
        byte* der = NULL;
        word32 derSz;

        ret = load_der_file(caCert, &der, &derSz);
        if (ret == 0) {
            if (wolfSSH_CTX_AddRootCert_buffer(ctx, der, derSz,
                WOLFSSH_FORMAT_ASN1) != WS_SUCCESS) {
                fprintf(stderr, "Couldn't parse in CA certificate.");
                ret = WS_PARSE_E;
            }
            WFREE(der, NULL, 0);
        }
    #else
        (void)ctx;
        fprintf(stderr, "Support for certificates not compiled in.");
        ret = WS_NOT_COMPILED;
    #endif
    }
    return ret;
}


void ClientFreeBuffers(const char* pubKeyName, const char* privKeyName)
{
    if (pubKeyName != NULL && userPublicKey != NULL) {
        WFREE(userPublicKey, NULL, DYNTYPE_PRIVKEY);
    }

    if (privKeyName != NULL && userPrivateKey != NULL) {
        WFREE(userPrivateKey, NULL, DYNTYPE_PRIVKEY);
    }
}

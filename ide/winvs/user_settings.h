#ifndef _WIN_USER_SETTINGS_H_
#define _WIN_USER_SETTINGS_H_

/* Verify this is Windows */
#ifndef _WIN32
#error This user_settings.h header is only designed for Windows
#endif

#define WOLFSSL_WOLFSSH
#define WOLFCRYPT_ONLY
#define WOLFSSL_KEY_GEN
#define HAVE_ECC
#define HAVE_AESGCM
#define HAVE_HASHDRBG
#define WOLFSSL_AES_COUNTER
#define WOLFSSL_AES_DIRECT
#define WOLFSSL_SHA384
#define WOLFSSL_SHA512
#define NO_PSK
#define NO_HC128
#define NO_RC4
#define NO_RABBIT
#define NO_DSA
#define NO_MD4
#define WC_RSA_BLINDING
#define WOLFSSL_PUBLIC_MP
#define WC_NO_HARDEN

#define WOLFSSH_TERM
#ifndef WOLFSSH_TERM
    /* Threading is needed for opening a psuedo terminal in the examples */
    #define SINGLE_THREADED
#endif

/* adding X509 support */
#if 0
    /* Uses CertManager which is in the TLS layer */
    #undef WOLFCRYPT_ONLY

    #undef  WOLFSSL_CERT_GEN
    #define WOLFSSL_CERT_GEN

    /* Used for comparing IP of peer with IP found in certificate */
    #undef  WOLFSSL_IP_ALT_NAME
    #define WOLFSSL_IP_ALT_NAME

    #undef  HAVE_TLS_EXTENSIONS
    #define HAVE_TLS_EXTENSIONS

    #undef  OPENSSL_ALL
    #define OPENSSL_ALL

    /* Turn off additional FPKI support checks (Federal PKI) on certificates */
    #undef  WOLFSSH_NO_FPKI
    #define WOLFSSH_NO_FPKI

    #undef WOLFSSH_CERTS
    #define WOLFSSH_CERTS
#endif

/* Host and user keys held in the MS Certificate Store. Needs WOLFSSH_CERTS
 * above, and the projects link crypt32.lib and ncrypt.lib for it. Left
 * commented rather than behind a disabled preprocessor block so enabling
 * the X.509 block above does not silently pull it in (and so CI's global
 * block-enabling sed cannot flip it either).
 *
 * #undef  WOLFSSH_WINDOWS_CERT_STORE
 * #define WOLFSSH_WINDOWS_CERT_STORE
 *
 * An RSA certificate store key is offered as "x509v3-ssh-rsa", which RFC 6187
 * signs with SHA-1, so that combination also needs
 *   #define WOLFSSH_NO_SHA1_SOFT_DISABLE
 * here and, in wolfSSL's user_settings.h,
 *   #define WC_SIG_MIN_HASH_TYPE WC_HASH_TYPE_SHA
 * ECDSA certificate store keys need neither.
 *
 * The store lookup rejects a CN match whose certificate is expired or not
 * yet valid when no time-valid one exists; define
 *   #define WOLFSSH_CERT_STORE_ALLOW_EXPIRED
 * to select such a certificate anyway (the fallback is logged).
 */


/* default SSHD options */
#if 0
    #undef  WOLFSSH_SSHD
    #define WOLFSSH_SSHD

    /* handle shell connections */
    #undef  WOLFSSH_SHELL
    #define WOLFSSH_SHELL

    /* handle SCP connection requests */
    #undef  WOLFSSH_SCP
    #define WOLFSSH_SCP

    /* handle SFTP connection requests */
    #undef  WOLFSSH_SFTP
    #define WOLFSSH_SFTP

#endif

#endif /* _WIN_USER_SETTINGS_H_ */

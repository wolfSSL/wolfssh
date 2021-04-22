#ifndef USER_SETTINGS_H
#define USER_SETTINGS_H

#define BENCH_EMBEDDED
#define NO_WRITEV
#define WOLFSSL_USER_IO
#define NO_DEV_RANDOM
#define USE_CERT_BUFFERS_2048
#define WOLFSSL_USER_CURRTIME
#define SIZEOF_LONG_LONG 8
#define NO_WOLFSSL_DIR
#define WOLFSSL_NO_CURRDIR
#define NO_WOLF_C99
#define NO_MULTIBYTE_PRINT

#define XVALIDATEDATE(d, f,t) (0)
#define WOLFSSL_USER_CURRTIME /* for benchmark */

#define WOLFSSL_GENSEED_FORTEST /* Warning: define your own seed gen */

#define TFM_TIMING_RESISTANT
#define ECC_TIMING_RESISTANT
#define WC_RSA_BLINDING

#define SINGLE_THREADED /* or define RTOS  option */
#define WOLFSSH_THREAD
typedef unsigned int  THREAD_RETURN;

/* #define WOLFSSL_CMSIS_RTOS */
/* #define NO_FILESYSTEM */

/* #define NO_DH */
#define HAVE_AESGCM
#define WOLFSSL_SHA512
#define HAVE_ECC
#define HAVE_CURVE25519
#define CURVE25519_SMALL
#define HAVE_ED25519

#define WOLFSSH_USER_IO
#define WOLFSSL_USER_IO

#define WOLFSSH_SFTP

#define WOLFSSH_USER_FILESYSTEM
#define WOLFSSL_USER_FILESYSTEM
#define NO_WOLFSSH_DIR

/* To be defined for the target Socket API */
#define WSTARTTCP()
#define WCLOSESOCKET(s)
#define ChangeToWolfSshRoot(a)

typedef int SOCKADDR_IN_T;

#define WOLFSSH_LOG_PRINTF
#define WOLFSSL_LOG_PRINTF
#define XFPRINTF(err, ... ) printf(__VA_ARGS__)
#define err_sys(...) printf(__VA_ARGS__)

enum {
    WS_SELECT_FAIL,
    WS_SELECT_TIMEOUT,
    WS_SELECT_RECV_READY,
    WS_SELECT_ERROR_READY
};

#endif

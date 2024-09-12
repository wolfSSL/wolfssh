/* internal.c
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


/*
 * The internal module contains the private data and functions. The public
 * API calls into this module to do the work of processing the connections.
 */


#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <stdio.h>
#include <wolfssh/ssh.h>
#include <wolfssh/internal.h>
#include <wolfssh/log.h>
#include <wolfssl/version.h>
#include <wolfssl/wolfcrypt/asn.h>
#ifndef WOLFSSH_NO_DH
    #include <wolfssl/wolfcrypt/dh.h>
#endif
#include <wolfssl/wolfcrypt/curve25519.h>
#include <wolfssl/wolfcrypt/ed25519.h>
#ifdef WOLFSSH_CERTS
    #include <wolfssl/wolfcrypt/error-crypt.h>
#endif
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/signature.h>

#if (LIBWOLFSSL_VERSION_HEX >= WOLFSSL_V5_0_0) \
    && ((defined(HAVE_FIPS) && FIPS_VERSION_GE(5,2)) \
        || defined(WOLFSSH_NO_ECDH_NISTP256_KYBER_LEVEL1_SHA256))
    #include <wolfssl/wolfcrypt/kdf.h>
#endif

#ifdef WOLFSSL_HAVE_KYBER
#include <wolfssl/wolfcrypt/kyber.h>
#include <wolfssl/wolfcrypt/wc_kyber.h>
#endif

#ifdef NO_INLINE
    #include <wolfssh/misc.h>
#else
    #define WOLFSSH_MISC_INCLUDED
    #if defined(WOLFSSL_NUCLEUS)
        #include "src/wolfssh_misc.c"
    #else
        #include "src/misc.c"
    #endif
#endif


/*
Flags:
  HAVE_WC_ECC_SET_RNG
    Set by configure if wc_ecc_set_rng() discovered in wolfCrypt.  Disables
    use of the function if the flag isn't set. If using wolfCrypt v4.5.0 or
    later, and not building with configure, set this flag.
    default: off
  WOLFSSH_NO_SHA1_SOFT_DISABLE
    SHA-1 is normally soft-disabled. The default configuration will not
    advertise the availability of SHA-1 based algorithms during KEX. SHA-1
    algorithms still work. Setting this flag will advertise SHA-1 based
    algorithms during KEX by default.
  WOLFSSH_NO_SHA1
    Set when SHA1 is disabled. Set to disable use of SHA1 in HMAC and digital
    signature support.
  WOLFSSH_NO_HMAC_SHA1
    Set when HMAC or SHA1 are disabled. Set to disable HMAC-SHA1 support.
  WOLFSSH_NO_HMAC_SHA1_96
    Set when HMAC or SHA1 are disabled. Set to disable HMAC-SHA1-96 support.
  WOLFSSH_NO_HMAC_SHA2_256
    Set when HMAC or SHA2-256 are disabled. Set to disable HMAC-SHA2-256
    support.
  WOLFSSH_NO_DH_GROUP1_SHA1
    Set when DH or SHA1 are disabled. Set to disable use of DH (Oakley 1) and
    SHA1 support.
  WOLFSSH_NO_DH_GROUP14_SHA1
    Set when DH or SHA1 are disabled. Set to disable use of DH (Oakley 14) and
    SHA1 support.
  WOLFSSH_NO_DH_GROUP14_SHA256
    Set when DH or SHA256 are disabled. Set to disable use of DH (Oakley 14)
    and SHA256 support.
  WOLFSSH_NO_DH_GEX_SHA256
    Set when DH or SHA2-256 are disabled. Set to disable use of DH group
    exchange and SHA2-256 support.
  WOLFSSH_NO_ECDH_SHA2_NISTP256
    Set when ECC or SHA2-256 are disabled. Set to disable use of ECDHE key
    exchange with prime NISTP256.
  WOLFSSH_NO_ECDH_SHA2_NISTP384
    Set when ECC or SHA2-384 are disabled. Set to disable use of ECDHE key
    exchange with prime NISTP384.
  WOLFSSH_NO_ECDH_SHA2_NISTP521
    Set when ECC or SHA2-512 are disabled. Set to disable use of ECDHE key
    exchange with prime NISTP521.
  WOLFSSH_NO_RSA
    Set when RSA is disabled. Set to disable use of RSA server and user
    authentication.
  WOLFSSH_NO_SSH_RSA_SHA1
    Set when RSA or SHA1 are disabled. Set to disable use of RSA server
    authentication.
  WOLFSSH_NO_ECDSA
    Set when ECC is disabled. Set to disable use of ECDSA server and user
    authentication.
  WOLFSSH_NO_ECDSA_SHA2_NISTP256
    Set when ECC or SHA2-256 are disabled. Set to disable use of ECDSA server
    authentication with prime NISTP256.
  WOLFSSH_NO_ECDSA_SHA2_NISTP384
    Set when ECC or SHA2-384 are disabled. Set to disable use of ECDSA server
    authentication with prime NISTP384.
  WOLFSSH_NO_ECDSA_SHA2_NISTP521
    Set when ECC or SHA2-512 are disabled. Set to disable use of ECDSA server
    authentication with prime NISTP521.
  WOLFSSH_NO_ECDH_NISTP256_KYBER_LEVEL1_SHA256
    Set when Kyber is disabled in wolfssl. Set to disable use of ECDHE with
    prime NISTP256 hybridized with post-quantum KYBER512 KEM.
  WOLFSSH_NO_AES_CBC
    Set when AES or AES-CBC are disabled. Set to disable use of AES-CBC
    encryption.
  WOLFSSH_NO_AES_CTR
    Set when AES or AES-CTR are disabled. Set to disable use of AES-CTR
    encryption.
  WOLFSSH_NO_AES_GCM
    Set when AES or AES-GCM are disabled. Set to disable use of AES-GCM
    encryption.
  WOLFSSH_NO_AEAD
    Set when AES-GCM is disabled. Set to disable use of AEAD ciphers for
    encryption. Setting this will force all AEAD ciphers off.
  WOLFSSH_NO_DH
    Set when all DH algorithms are disabled. Set to disable use of all DH
    algorithms for key agreement. Setting this will force all DH key agreement
    algorithms off.
  WOLFSSH_NO_ECDH
    Set when all ECDH algorithms are disabled. Set to disable use of all ECDH
    algorithms for key agreement. Setting this will force all ECDH key agreement
    algorithms off.
  WOLFSSH_KEY_QUANTITY_REQ
    Number of keys required to be in an OpenSSH-style key wrapper.
  WOLFSSH_NO_CURVE25519_SHA256
    Set when Curve25519 or SHA2-256 are disabled in wolfSSL. Set to disable use
    of Curve25519 key exchange.
*/

static const char sshProtoIdStr[] = "SSH-2.0-wolfSSHv"
                                    LIBWOLFSSH_VERSION_STRING
                                    "\r\n";
static const char OpenSSH[] = "SSH-2.0-OpenSSH";


const char* GetErrorString(int err)
{
#ifdef NO_WOLFSSH_STRINGS
    WOLFSSH_UNUSED(err);
    return "No wolfSSH strings available";
#else
    switch (err) {
        case WS_SUCCESS:
            return "no error";

        case WS_ERROR:
            return "general function failure";

        case WS_BAD_ARGUMENT:
            return "bad function argument";

        case WS_MEMORY_E:
            return "memory allocation failure";

        case WS_BUFFER_E:
            return "input/output buffer size error";

        case WS_PARSE_E:
            return "general parsing error";

        case WS_NOT_COMPILED:
            return "feature not compiled in";

        case WS_OVERFLOW_E:
            return "would overflow if continued failure";

        case WS_BAD_USAGE:
            return "bad example usage";

        case WS_SOCKET_ERROR_E:
            return "socket error";

        case WS_WANT_READ:
            return "I/O callback would read block error";

        case WS_WANT_WRITE:
            return "I/O callback would write block error";

        case WS_RECV_OVERFLOW_E:
            return "receive buffer overflow";

        case WS_VERSION_E:
            return "peer version unsupported";

        case WS_SEND_OOB_READ_E:
            return "attempted to read buffer out of bounds";

        case WS_INPUT_CASE_E:
            return "bad process input state, programming error";

        case WS_BAD_FILETYPE_E:
            return "bad filetype";

        case WS_UNIMPLEMENTED_E:
            return "feature not implemented";

        case WS_RSA_E:
            return "RSA buffer error";

        case WS_BAD_FILE_E:
            return "bad file";

        case WS_INVALID_ALGO_ID:
            return "invalid algorithm id";

        case WS_DECRYPT_E:
            return "decrypt error";

        case WS_ENCRYPT_E:
            return "encrypt error";

        case WS_VERIFY_MAC_E:
            return "verify mac error";

        case WS_CREATE_MAC_E:
            return "create mac error";

        case WS_RESOURCE_E:
            return "insufficient resources for new channel";

        case WS_INVALID_CHANTYPE:
            return "peer requested invalid channel type";

        case WS_INVALID_CHANID:
            return "peer requested invalid channel id";

        case WS_INVALID_USERNAME:
            return "invalid user name";

        case WS_CRYPTO_FAILED:
            return "crypto action failed";

        case WS_INVALID_STATE_E:
            return "invalid state";

        case WS_EOF:
            return "end of file";

        case WS_REKEYING:
            return "rekeying with peer";

        case WS_INVALID_PRIME_CURVE:
            return "invalid prime curve in ecc";

        case WS_ECC_E:
            return "ECDSA buffer error";

        case WS_CHANOPEN_FAILED:
            return "peer returned channel open failure";

        case WS_CHANNEL_CLOSED:
            return "channel closed";

        case WS_INVALID_PATH_E:
            return "invalid file or directory path";

        case WS_SCP_CMD_E:
            return "invalid scp command";

        case WS_SCP_BAD_MSG_E:
            return "invalid scp message received from peer";

        case WS_SCP_PATH_LEN_E:
            return "scp path length error";

        case WS_SCP_TIMESTAMP_E:
            return "scp timestamp message error";

        case WS_SCP_DIR_STACK_EMPTY_E:
            return "scp directory stack empty";

        case WS_SCP_CONTINUE:
            return "scp continue operation";

        case WS_SCP_ABORT:
            return "scp abort operation";

        case WS_SCP_ENTER_DIR:
            return "scp enter directory operation";

        case WS_SCP_EXIT_DIR:
            return "scp exit directory operation";

        case WS_SCP_EXIT_DIR_FINAL:
            return "scp final exit directory operation";

        case WS_SCP_COMPLETE:
            return "scp operation complete";

        case WS_SCP_INIT:
            return "scp operation verified";

        case WS_MATCH_KEX_ALGO_E:
            return "cannot match KEX algo with peer";

        case WS_MATCH_KEY_ALGO_E:
            return "cannot match key algo with peer";

        case WS_MATCH_ENC_ALGO_E:
            return "cannot match encrypt algo with peer";

        case WS_MATCH_MAC_ALGO_E:
            return "cannot match MAC algo with peer";

        case WS_PERMISSIONS:
            return "file permissions error";

        case WS_SFTP_COMPLETE:
            return "sftp connection established";

        case WS_NEXT_ERROR:
            return "Getting next value/state results in error";

        case WS_CHAN_RXD:
            return "Channel data received";

        case WS_INVALID_EXTDATA:
            return "invalid extended data type";

        case WS_SFTP_BAD_REQ_ID:
            return "sftp bad request id";

        case WS_SFTP_BAD_REQ_TYPE:
            return "sftp bad request response type";

        case WS_SFTP_STATUS_NOT_OK:
            return "sftp status not OK";

        case WS_SFTP_FILE_DNE:
            return "sftp file does not exist";

        case WS_SIZE_ONLY:
            return "Only getting the size of buffer needed";

        case WS_CLOSE_FILE_E:
            return "Unable to close local file";

        case WS_PUBKEY_REJECTED_E:
            return "server's public key is rejected";

        case WS_EXTDATA:
            return "Extended Data available to be read";

        case WS_USER_AUTH_E:
            return "User authentication error";

        case WS_SSH_NULL_E:
            return "ssh pointer was null";

        case WS_SSH_CTX_NULL_E:
            return "ssh ctx pointer was null";

        case WS_CHANNEL_NOT_CONF:
            return "channel open not confirmed";

        case WS_CHANGE_AUTH_E:
            return "changing auth type attempt";

        case WS_WINDOW_FULL:
            return "peer's channel window full";

        case WS_MISSING_CALLBACK:
            return "missing a callback function";

        case WS_DH_SIZE_E:
            return "DH prime group size larger than expected";

        case WS_PUBKEY_SIG_MIN_E:
            return "pubkey signature too small";

        case WS_AGENT_NULL_E:
            return "agent pointer was null";

        case WS_AGENT_NO_KEY_E:
            return "agent doesn't have requested key";

        case WS_AGENT_CXN_FAIL:
            return "agent connection failed";

        case WS_SFTP_BAD_HEADER:
            return "sftp bad header";

        case WS_CERT_NO_SIGNER_E:
            return "no signer certificate";

        case WS_CERT_EXPIRED_E:
            return "certificate expired";

        case WS_CERT_REVOKED_E:
            return "certificate revoked";

        case WS_CERT_SIG_CONFIRM_E:
            return "certificate signature fail";

        case WS_CERT_OTHER_E:
            return "other certificate error";

        case WS_CERT_PROFILE_E:
            return "certificate profile requirements error";

        case WS_CERT_KEY_SIZE_E:
            return "key size too small error";

        case WS_CTX_KEY_COUNT_E:
            return "trying to add too many keys";

        case WS_MATCH_UA_KEY_ID_E:
            return "unable to match user auth key type";

        case WS_KEY_AUTH_MAGIC_E:
            return "key auth magic check error";

        case WS_KEY_CHECK_VAL_E:
            return "key check value error";

        case WS_KEY_FORMAT_E:
            return "key format wrong error";

        case WS_SFTP_NOT_FILE_E:
            return "not a regular file";

        case WS_MSGID_NOT_ALLOWED_E:
            return "message not allowed before user authentication";

        case WS_ED25519_E:
            return "Ed25519 buffer error";

        case WS_AUTH_PENDING:
            return "userauth is still pending (callback would block)";

        case WS_KDF_E:
            return "KDF error";

        default:
            return "Unknown error code";
    }
#endif
}


static int wsHighwater(byte dir, void* ctx)
{
    int ret = WS_SUCCESS;

    WOLFSSH_UNUSED(dir);

    if (ctx) {
        WOLFSSH* ssh = (WOLFSSH*)ctx;

        WLOG(WS_LOG_DEBUG, "HIGHWATER MARK: (%u) %s",
             wolfSSH_GetHighwater(ssh),
             (dir == WOLFSSH_HWSIDE_RECEIVE) ? "receive" : "transmit");

        ret = wolfSSH_TriggerKeyExchange(ssh);
    }

    return ret;
}


/* internal abstract function for hash update
 * returns 0 on success */
static int HashUpdate(wc_HashAlg* hash, enum wc_HashType type,
    const byte* data, word32 dataSz)
{
#if 0
    word32 i;
    printf("Hashing In :");
    for (i = 0; i < dataSz; i++)
        printf("%02X", data[i]);
    printf("\n");
#endif
    return wc_HashUpdate(hash, type, data, dataSz);
}


/* returns WS_SUCCESS on success */
static INLINE int HighwaterCheck(WOLFSSH* ssh, byte side)
{
    int ret = WS_SUCCESS;

    if (!ssh->highwaterFlag && ssh->highwaterMark &&
        (ssh->txCount >= ssh->highwaterMark ||
         ssh->rxCount >= ssh->highwaterMark)) {

        WLOG(WS_LOG_DEBUG, "%s over high water mark",
             (side == WOLFSSH_HWSIDE_TRANSMIT) ? "Transmit" : "Receive");

        ssh->highwaterFlag = 1;

        if (ssh->ctx->highwaterCb)
            ret = ssh->ctx->highwaterCb(side, ssh->highwaterCtx);
    }
    return ret;
}


static HandshakeInfo* HandshakeInfoNew(void* heap)
{
    HandshakeInfo* newHs;

    WLOG(WS_LOG_DEBUG, "Entering HandshakeInfoNew()");
    newHs = (HandshakeInfo*)WMALLOC(sizeof(HandshakeInfo),
                                    heap, DYNTYPE_HS);
    if (newHs != NULL) {
        WMEMSET(newHs, 0, sizeof(HandshakeInfo));
        newHs->kexId = ID_NONE;
        newHs->kexHashId = WC_HASH_TYPE_NONE;
        newHs->pubKeyId  = ID_NONE;
        newHs->encryptId = ID_NONE;
        newHs->macId = ID_NONE;
        newHs->blockSz = MIN_BLOCK_SZ;
        newHs->eSz = (word32)sizeof(newHs->e);
        newHs->xSz = (word32)sizeof(newHs->x);
#ifndef WOLFSSH_NO_DH_GEX_SHA256
        newHs->dhGexMinSz = WOLFSSH_DEFAULT_GEXDH_MIN;
        newHs->dhGexPreferredSz = WOLFSSH_DEFAULT_GEXDH_PREFERRED;
        newHs->dhGexMaxSz = WOLFSSH_DEFAULT_GEXDH_MAX;
#endif
    }

    return newHs;
}


static void HandshakeInfoFree(HandshakeInfo* hs, void* heap)
{
    WOLFSSH_UNUSED(heap);

    WLOG(WS_LOG_DEBUG, "Entering HandshakeInfoFree()");
    if (hs) {
        WFREE(hs->kexInit, heap, DYNTYPE_STRING);
#ifndef WOLFSSH_NO_DH
        WFREE(hs->primeGroup, heap, DYNTYPE_MPINT);
        WFREE(hs->generator, heap, DYNTYPE_MPINT);
#endif
        if (hs->kexHashId != WC_HASH_TYPE_NONE)  {
            wc_HashFree(&hs->kexHash, (enum wc_HashType)hs->kexHashId);
        }
        ForceZero(hs, sizeof(HandshakeInfo));
        WFREE(hs, heap, DYNTYPE_HS);
    }
}


#ifndef NO_WOLFSSH_SERVER
INLINE static int IsMessageAllowedServer(WOLFSSH *ssh, byte msg)
{
    /* Has client userauth started? */
    if (ssh->acceptState < ACCEPT_KEYED) {
        if (msg > MSGID_KEXDH_LIMIT) {
            return 0;
        }
    }
    /* Is server userauth complete? */
    if (ssh->acceptState < ACCEPT_SERVER_USERAUTH_SENT) {
        /* Explicitly check for messages not allowed before user
         * authentication has comleted. */
        if (msg >= MSGID_USERAUTH_LIMIT) {
            WLOG(WS_LOG_DEBUG, "Message ID %u not allowed by server "
                    "before user authentication is complete", msg);
            return 0;
        }
        /* Explicitly check for the user authentication messages that
         * only the server sends, it shouldn't receive them. */
        if (msg > MSGID_USERAUTH_RESTRICT) {
            WLOG(WS_LOG_DEBUG, "Message ID %u not allowed by server "
                    "during user authentication", msg);
            return 0;
        }
    }
    else {
        if (msg >= MSGID_USERAUTH_RESTRICT && msg < MSGID_USERAUTH_LIMIT) {
            WLOG(WS_LOG_DEBUG, "Message ID %u not allowed by server "
                    "after user authentication", msg);
            return 0;
        }
    }

    return 1;
}
#endif /* NO_WOLFSSH_SERVER */


#ifndef NO_WOLFSSH_CLIENT
INLINE static int IsMessageAllowedClient(WOLFSSH *ssh, byte msg)
{
    /* Has client userauth started? */
    if (ssh->connectState < CONNECT_CLIENT_KEXDH_INIT_SENT) {
        if (msg >= MSGID_KEXDH_LIMIT) {
            return 0;
        }
    }
    /* Is client userauth complete? */
    if (ssh->connectState < CONNECT_SERVER_USERAUTH_ACCEPT_DONE) {
        /* Explicitly check for messages not allowed before user
         * authentication has comleted. */
        if (msg >= MSGID_USERAUTH_LIMIT) {
            WLOG(WS_LOG_DEBUG, "Message ID %u not allowed by client "
                    "before user authentication is complete", msg);
            return 0;
        }
        /* Explicitly check for the user authentication message that
         * only the client sends, it shouldn't receive it. */
        if (msg == MSGID_USERAUTH_RESTRICT) {
            WLOG(WS_LOG_DEBUG, "Message ID %u not allowed by client "
                    "during user authentication", msg);
            return 0;
        }
    }
    else {
        if (msg >= MSGID_USERAUTH_RESTRICT && msg < MSGID_USERAUTH_LIMIT) {
            WLOG(WS_LOG_DEBUG, "Message ID %u not allowed by client "
                    "after user authentication", msg);
            return 0;
        }
    }
    return 1;
}
#endif /* NO_WOLFSSH_CLIENT */


INLINE static int IsMessageAllowed(WOLFSSH *ssh, byte msg)
{
#ifndef NO_WOLFSSH_SERVER
    if (ssh->ctx->side == WOLFSSH_ENDPOINT_SERVER) {
        return IsMessageAllowedServer(ssh, msg);
    }
#endif /* NO_WOLFSSH_SERVER */
#ifndef NO_WOLFSSH_CLIENT
    if (ssh->ctx->side == WOLFSSH_ENDPOINT_CLIENT) {
        return IsMessageAllowedClient(ssh, msg);
    }
#endif /* NO_WOLFSSH_CLIENT */
    return 0;
}


static const char cannedKexAlgoNames[] =
#if !defined(WOLFSSH_NO_ECDH_NISTP256_KYBER_LEVEL1_SHA256)
    "ecdh-nistp256-kyber-512r3-sha256-d00@openquantumsafe.org,"
#endif
#ifndef WOLFSSH_NO_CURVE25519_SHA256
    "curve25519-sha256,"
#endif
#if !defined(WOLFSSH_NO_ECDH_SHA2_NISTP521)
    "ecdh-sha2-nistp521,"
#endif
#if !defined(WOLFSSH_NO_ECDH_SHA2_NISTP384)
    "ecdh-sha2-nistp384,"
#endif
#if !defined(WOLFSSH_NO_ECDH_SHA2_NISTP256)
    "ecdh-sha2-nistp256,"
#endif
#if !defined(WOLFSSH_NO_DH_GROUP14_SHA256)
    "diffie-hellman-group14-sha256,"
#endif
#if !defined(WOLFSSH_NO_DH_GEX_SHA256)
    "diffie-hellman-group-exchange-sha256,"
#endif
#ifdef WOLFSSH_NO_SHA1_SOFT_DISABLE
    #if !defined(WOLFSSH_NO_DH_GROUP14_SHA1)
        "diffie-hellman-group14-sha1,"
    #endif
    #if !defined(WOLFSSH_NO_DH_GROUP1_SHA1)
        "diffie-hellman-group1-sha1,"
    #endif
#endif /* WOLFSSH_NO_SHA1_SOFT_DISABLE */
    "";

#ifndef WOLFSSH_NO_SSH_RSA_SHA1
    #ifdef WOLFSSH_CERTS
        static const char cannedKeyAlgoX509RsaNames[] = "x509v3-ssh-rsa";
    #endif
#endif
#ifndef WOLFSSH_NO_ECDSA_SHA2_NISTP256
    static const char cannedKeyAlgoEcc256Names[] = "ecdsa-sha2-nistp256";
    #ifdef WOLFSSH_CERTS
        static const char cannedKeyAlgoX509Ecc256Names[] =
                "x509v3-ecdsa-sha2-nistp256";
    #endif
#endif
#ifndef WOLFSSH_NO_ECDSA_SHA2_NISTP384
    static const char cannedKeyAlgoEcc384Names[] = "ecdsa-sha2-nistp384";
    #ifdef WOLFSSH_CERTS
        static const char cannedKeyAlgoX509Ecc384Names[] =
                "x509v3-ecdsa-sha2-nistp384";
    #endif
#endif
#ifndef WOLFSSH_NO_ECDSA_SHA2_NISTP521
    static const char cannedKeyAlgoEcc521Names[] = "ecdsa-sha2-nistp521";
    #ifdef WOLFSSH_CERTS
        static const char cannedKeyAlgoX509Ecc521Names[] =
                "x509v3-ecdsa-sha2-nistp521";
    #endif
#endif
#ifndef WOLFSSH_NO_SSH_RSA_SHA1
    /* Used for both the signature algorithm and the RSA key format. */
    static const char cannedKeyAlgoSshRsaNames[] = "ssh-rsa";
#endif
#ifndef WOLFSSH_NO_RSA_SHA2_256
    static const char cannedKeyAlgoRsaSha2_256Names[] = "rsa-sha2-256";
#endif
#ifndef WOLFSSH_NO_RSA_SHA2_512
    static const char cannedKeyAlgoRsaSha2_512Names[] = "rsa-sha2-512";
#endif
#ifndef WOLFSSH_NO_ED25519
    static const char cannedKeyAlgoEd25519Name[] = "ssh-ed25519";
#endif

static const char cannedKeyAlgoNames[] =
#ifndef WOLFSSH_NO_ED25519
    "ssh-ed25519,"
#endif /* WOLFSSH_NO_ED25519 */
#ifndef WOLFSSH_NO_RSA_SHA2_256
    "rsa-sha2-256,"
#endif/* WOLFSSH_NO_RSA_SHA2_256 */
#ifndef WOLFSSH_NO_ECDSA_SHA2_NISTP256
    "ecdsa-sha2-nistp256,"
#endif /* WOLFSSH_NO_ECDSA_SHA2_NISTP256 */
#ifdef WOLFSSH_CERTS
    #ifndef WOLFSSH_NO_ECDSA_SHA2_NISTP256
        "x509v3-ecdsa-sha2-nistp256,"
    #endif /* WOLFSSH_NO_ECDSA_SHA2_NISTP256 */
    #ifdef WOLFSSH_NO_SHA1_SOFT_DISABLE
        "x509v3-ssh-rsa,"
    #endif /* WOLFSSH_NO_SHA1_SOFT_DISABLE */
#endif /* WOLFSSH_CERTS */
#ifdef WOLFSSH_NO_SHA1_SOFT_DISABLE
    "ssh-rsa,"
#endif /* WOLFSSH_NO_SHA1_SOFT_DISABLE */
    "";

static const char cannedEncAlgoNames[] =
#if !defined(WOLFSSH_NO_AES_GCM)
    "aes256-gcm@openssh.com,"
    "aes192-gcm@openssh.com,"
    "aes128-gcm@openssh.com,"
#endif
#if !defined(WOLFSSH_NO_AES_CTR)
    "aes256-ctr,"
    "aes192-ctr,"
    "aes128-ctr,"
#endif
#if !defined(WOLFSSH_NO_AES_CBC)
    "aes256-cbc,"
    "aes192-cbc,"
    "aes128-cbc,"
#endif
    "";

static const char cannedMacAlgoNames[] =
#if !defined(WOLFSSH_NO_HMAC_SHA2_256)
    "hmac-sha2-256,"
#endif
#if defined(WOLFSSH_NO_SHA1_SOFT_DISABLE)
    #if !defined(WOLFSSH_NO_HMAC_SHA1_96)
        "hmac-sha1-96,"
    #endif
    #if !defined(WOLFSSH_NO_HMAC_SHA1)
        "hmac-sha1,"
    #endif
#endif /* WOLFSSH_NO_SHA1_SOFT_DISABLE */
    "";

static const char cannedNoneNames[] = "none";


WOLFSSH_CTX* CtxInit(WOLFSSH_CTX* ctx, byte side, void* heap)
{
    word32 idx, count;

    WLOG(WS_LOG_DEBUG, "Entering CtxInit()");

    if (ctx == NULL)
        return ctx;

    WMEMSET(ctx, 0, sizeof(WOLFSSH_CTX));

    if (heap)
        ctx->heap = heap;

    ctx->side = side;
#ifndef WOLFSSH_USER_IO
    ctx->ioRecvCb = wsEmbedRecv;
    ctx->ioSendCb = wsEmbedSend;
#endif /* WOLFSSH_USER_IO */
    ctx->highwaterMark = DEFAULT_HIGHWATER_MARK;
    ctx->highwaterCb = wsHighwater;
#if defined(WOLFSSH_SCP) && !defined(WOLFSSH_SCP_USER_CALLBACKS)
    ctx->scpRecvCb = wsScpRecvCallback;
    ctx->scpSendCb = wsScpSendCallback;
#endif /* WOLFSSH_SCP */
    ctx->banner = NULL;
    ctx->bannerSz = 0;
#ifdef WOLFSSH_CERTS
    ctx->certMan = wolfSSH_CERTMAN_new(ctx->heap);
    if (ctx->certMan == NULL)
        return NULL;
#endif /* WOLFSSH_CERTS */
    ctx->windowSz = DEFAULT_WINDOW_SZ;
    ctx->maxPacketSz = DEFAULT_MAX_PACKET_SZ;
    ctx->sshProtoIdStr = sshProtoIdStr;
    ctx->algoListKex = cannedKexAlgoNames;
    if (side == WOLFSSH_ENDPOINT_CLIENT) {
        ctx->algoListKey = cannedKeyAlgoNames;
    }
    ctx->algoListCipher = cannedEncAlgoNames;
    ctx->algoListMac = cannedMacAlgoNames;
    ctx->algoListKeyAccepted = cannedKeyAlgoNames;

    count = (word32)(sizeof(ctx->privateKey)
            / sizeof(ctx->privateKey[0]));
    for (idx = 0; idx < count; idx++) {
        ctx->privateKey[idx].publicKeyFmt = ID_NONE;
    }
    count = (word32)(sizeof(ctx->publicKeyAlgo)
            / sizeof(ctx->publicKeyAlgo[0]));
    for (idx = 0; idx < count; idx++) {
        ctx->publicKeyAlgo[idx] = ID_NONE;
    }

    return ctx;
}


void CtxResourceFree(WOLFSSH_CTX* ctx)
{
    WLOG(WS_LOG_DEBUG, "Entering CtxResourceFree()");

    if (ctx->privateKeyCount > 0) {
        word32 i;

        for (i = 0; i < ctx->privateKeyCount; i++) {
            if (ctx->privateKey[i].key != NULL) {
                ForceZero(ctx->privateKey[i].key, ctx->privateKey[i].keySz);
                WFREE(ctx->privateKey[i].key, ctx->heap, DYNTYPE_PRIVKEY);
                ctx->privateKey[i].key = NULL;
                ctx->privateKey[i].keySz = 0;
            }
            #ifdef WOLFSSH_CERTS
            if (ctx->privateKey[i].cert != NULL) {
                WFREE(ctx->privateKey[i].cert, ctx->heap, DYNTYPE_CERT);
                ctx->privateKey[i].cert = NULL;
                ctx->privateKey[i].certSz = 0;
            }
            #endif
            ctx->privateKey[i].publicKeyFmt = ID_NONE;
        }
        ctx->privateKeyCount = 0;
    }
#ifdef WOLFSSH_CERTS
    if (ctx->certMan) {
        wolfSSH_CERTMAN_free(ctx->certMan);
    }
    ctx->certMan = NULL;
#endif
}


#ifdef WOLFSSH_TERM
/* default terminal resize handling callbacks */

#if defined(WOLFSSH_SSHD) && !defined(WOLFSSH_RESIZE_NO_DEFUALT)
#if defined(USE_WINDOWS_API)
static int WS_TermResize(WOLFSSH* ssh, word32 col, word32 row, word32 colP,
    word32 rowP, void* usrCtx)
{
    HANDLE* term = (HANDLE*)usrCtx;
    int ret = WS_SUCCESS;

    if (term != NULL) {
        char cmd[20];
        int cmdSz = 20;
        DWORD wrtn = 0;

        /* VT control sequence for resizing window */
        cmdSz = snprintf(cmd, cmdSz, "\x1b[8;%d;%dt", row, col);
        if (WriteFile(*term, cmd, cmdSz, &wrtn, 0) != TRUE) {
            WLOG(WS_LOG_ERROR, "Issue with pseudo console resize");
            ret = WS_FATAL_ERROR;
        }
    }

    return ret;
}
#elif defined(HAVE_SYS_IOCTL_H)

#include <sys/ioctl.h>
static int WS_TermResize(WOLFSSH* ssh, word32 col, word32 row, word32 colP,
    word32 rowP, void* usrCtx)
{
    struct winsize s;
    int ret = WS_SUCCESS;
    int* fd = (int*)usrCtx;

    if (fd != NULL) {
        WMEMSET(&s, 0, sizeof s);
        s.ws_row = row;
        s.ws_col = col;
        s.ws_xpixel = colP;
        s.ws_ypixel = rowP;

        ioctl(*fd, TIOCSWINSZ, &s);
    }

    (void)ssh;
    return ret;
}
#else
    #define WOLFSSH_RESIZE_NO_DEFUALT
#endif
#endif /* WOLFSSH_SSHD */

#endif /* WOLFSSH_TERM */

WOLFSSH* SshInit(WOLFSSH* ssh, WOLFSSH_CTX* ctx)
{
#if defined(STM32F2) || defined(STM32F4) || defined(FREESCALE_MQX)
    /* avoid name conflict in "stm32fnnnxx.h" */
    #undef  RNG
    #define RNG WC_RNG
#endif
    HandshakeInfo* handshake;
    WC_RNG*        rng;
    void*          heap;

    WLOG(WS_LOG_DEBUG, "Entering SshInit()");

    if (ssh == NULL || ctx == NULL)
        return ssh;
    heap = ctx->heap;

#ifdef WOLFSSH_STATIC_MEMORY
    if (heap != NULL) {
        WOLFSSL_HEAP_HINT* hint = (WOLFSSL_HEAP_HINT*)heap;

        if (hint->memory->flag & WOLFMEM_TRACK_STATS) {
            WOLFSSL_MEM_CONN_STATS* stats = NULL;

            stats = (WOLFSSL_MEM_CONN_STATS*)WMALLOC(
                    sizeof(WOLFSSL_MEM_CONN_STATS),
                    heap, DYNTYPE_SSH);
            if (stats == NULL) {
                WLOG(WS_LOG_DEBUG, "SshInit: Cannot track memory stats.\n");
                return NULL;
            }

            XMEMSET(stats, 0, sizeof(WOLFSSL_MEM_CONN_STATS));
            if (hint->stats != NULL) {
                WFREE(hint->stats, heap, DYNTYPE_SSH);
            }
            hint->stats = stats;
        }
    }
#endif /* WOLFSSH_STATIC_MEMORY */

    handshake = HandshakeInfoNew(heap);
    rng = (WC_RNG*)WMALLOC(sizeof(WC_RNG), heap, DYNTYPE_RNG);

    if (handshake == NULL || rng == NULL || wc_InitRng(rng) != 0) {

        WLOG(WS_LOG_DEBUG, "SshInit: Cannot allocate memory.\n");
        WFREE(handshake, heap, DYNTYPE_HS);
        WFREE(rng, heap, DYNTYPE_RNG);
        WFREE(ssh, heap, DYNTYPE_SSH);
        return NULL;
    }

    WMEMSET(ssh, 0, sizeof(WOLFSSH));  /* default init to zeros */

    ssh->ctx         = ctx;
    ssh->error       = WS_SUCCESS;
#ifdef USE_WINDOWS_API
    ssh->rfd         = INVALID_SOCKET;
    ssh->wfd         = INVALID_SOCKET;
#else
    ssh->rfd         = -1;         /* set to invalid */
    ssh->wfd         = -1;         /* set to invalid */
#endif
    ssh->ioReadCtx   = &ssh->rfd;  /* prevent invalid access if not correctly */
    ssh->ioWriteCtx  = &ssh->wfd;  /* set */
    ssh->highwaterMark = ctx->highwaterMark;
    ssh->highwaterCtx  = (void*)ssh;
    ssh->reqSuccessCtx = (void*)ssh;
    ssh->fs            = NULL;
    ssh->acceptState = ACCEPT_BEGIN;
    ssh->clientState = CLIENT_BEGIN;
    ssh->isKeying    = 1;
    ssh->authId      = ID_USERAUTH_PUBLICKEY;
    ssh->supportedAuth[0] = ID_USERAUTH_PUBLICKEY;
    ssh->supportedAuth[1] = ID_USERAUTH_PASSWORD;
    ssh->supportedAuth[2] = ID_NONE; /* ID_NONE is treated as empty slot */
    ssh->nextChannel = DEFAULT_NEXT_CHANNEL;
    ssh->blockSz     = MIN_BLOCK_SZ;
    ssh->encryptId   = ID_NONE;
    ssh->macId       = ID_NONE;
    ssh->peerBlockSz = MIN_BLOCK_SZ;
    ssh->rng         = rng;
    ssh->kSz         = (word32)sizeof(ssh->k);
    ssh->handshake   = handshake;
    ssh->connectChannelId = WOLFSSH_SESSION_SHELL;
    ssh->algoListKex = ctx->algoListKex;
    ssh->algoListKey = ctx->algoListKey;
    ssh->algoListCipher = ctx->algoListCipher;
    ssh->algoListMac = ctx->algoListMac;
    ssh->algoListKeyAccepted = ctx->algoListKeyAccepted;
#ifdef WOLFSSH_SCP
    ssh->scpRequestState = SCP_PARSE_COMMAND;
    ssh->scpConfirmMsg   = NULL;
    ssh->scpConfirmMsgSz = 0;
    ssh->scpRecvMsg      = NULL;
    ssh->scpRecvMsgSz    = 0;
    ssh->scpRecvCtx      = NULL;
    #if !defined(WOLFSSH_SCP_USER_CALLBACKS) && !defined(NO_FILESYSTEM)
    ssh->scpSendCtx      = &(ssh->scpSendCbCtx);
    #else
    ssh->scpSendCtx      = NULL;
    #endif
    ssh->scpFileBuffer   = NULL;
    ssh->scpFileBufferSz = 0;
    ssh->scpFileName     = NULL;
    ssh->scpFileNameSz   = 0;
    ssh->scpTimestamp    = 0;
    ssh->scpATime        = 0;
    ssh->scpMTime        = 0;
    ssh->scpRequestType  = WOLFSSH_SCP_SINGLE_FILE_REQUEST;
    ssh->scpIsRecursive  = 0;
    ssh->scpDirection    = WOLFSSH_SCP_DIR_NONE;
#endif

#ifdef WOLFSSH_SFTP
    ssh->sftpState   = SFTP_BEGIN;
#endif

#ifdef WOLFSSH_AGENT
    ssh->agentEnabled = ctx->agentEnabled;
#endif

#if defined(WOLFSSH_TERM) && defined(WOLFSSH_SSHD)
#ifndef WOLFSSH_RESIZE_NO_DEFUALT
    ssh->termResizeCb = WS_TermResize;
#endif
#endif

    ssh->keyingCompletionCtx = (void*)ssh;

    if (BufferInit(&ssh->inputBuffer, 0, ctx->heap) != WS_SUCCESS  ||
        BufferInit(&ssh->outputBuffer, 0, ctx->heap) != WS_SUCCESS ||
        BufferInit(&ssh->extDataBuffer, 0, ctx->heap) != WS_SUCCESS) {

        wolfSSH_free(ssh);
        ssh = NULL;
    }

    return ssh;
}


void SshResourceFree(WOLFSSH* ssh, void* heap)
{
    /* when ssh holds resources, free here */
    WOLFSSH_UNUSED(heap);

    WLOG(WS_LOG_DEBUG, "Entering sshResourceFree()");

    ShrinkBuffer(&ssh->inputBuffer, 1);
    ShrinkBuffer(&ssh->outputBuffer, 1);
    ShrinkBuffer(&ssh->extDataBuffer, 1);
    ForceZero(ssh->k, ssh->kSz);
    HandshakeInfoFree(ssh->handshake, heap);
    ForceZero(&ssh->keys, sizeof(Keys));
    ForceZero(&ssh->peerKeys, sizeof(Keys));
    if (ssh->rng) {
        wc_FreeRng(ssh->rng);
        WFREE(ssh->rng, heap, DYNTYPE_RNG);
    }
    if (ssh->userName) {
        WFREE(ssh->userName, heap, DYNTYPE_STRING);
    }
    if (ssh->peerProtoId) {
        WFREE(ssh->peerProtoId, heap, DYNTYPE_STRING);
    }
    if (ssh->channelList) {
        WOLFSSH_CHANNEL* cur = ssh->channelList;
        WOLFSSH_CHANNEL* next;
        while (cur) {
            next = cur->next;
            ChannelDelete(cur, heap);
            cur = next;
        }
    }
    wc_AesFree(&ssh->encryptCipher.aes);
    wc_AesFree(&ssh->decryptCipher.aes);
    if (ssh->peerSigId) {
        WFREE(ssh->peerSigId, heap, DYNTYPE_ID);
    }

#ifdef WOLFSSH_SCP
    if (ssh->scpConfirmMsg) {
        WFREE(ssh->scpConfirmMsg, ssh->ctx->heap, DYNTYPE_STRING);
        ssh->scpConfirmMsg = NULL;
        ssh->scpConfirmMsgSz = 0;
    }
    if (ssh->scpFileBuffer) {
        ForceZero(ssh->scpFileBuffer, ssh->scpFileBufferSz);
        WFREE(ssh->scpFileBuffer, ssh->ctx->heap, DYNTYPE_BUFFER);
        ssh->scpFileBuffer = NULL;
        ssh->scpFileBufferSz = 0;
    }
    if (ssh->scpFileName) {
        WFREE(ssh->scpFileName, ssh->ctx->heap, DYNTYPE_STRING);
        ssh->scpFileName = NULL;
        ssh->scpFileNameSz = 0;
    }
    if (ssh->scpRecvMsg) {
        WFREE(ssh->scpRecvMsg, ssh->ctx->heap, DYNTYPE_STRING);
        ssh->scpRecvMsg = NULL;
        ssh->scpRecvMsgSz = 0;
    }
#ifdef WOLFSSL_NUCLEUS
    WFREE(ssh->scpBasePathDynamic, ssh->ctx->heap, DYNTYPE_BUFFER);
    ssh->scpBasePathDynamic = NULL;
    ssh->scpBasePathSz = 0;
#endif
#endif
#ifdef WOLFSSH_SFTP
    if (ssh->sftpDefaultPath) {
        WFREE(ssh->sftpDefaultPath, ssh->ctx->heap, DYNTYPE_STRING);
        ssh->sftpDefaultPath = NULL;
    }
#endif
#ifdef WOLFSSH_TERM
    if (ssh->modes) {
        WFREE(ssh->modes, ssh->ctx->heap, DYNTYPE_STRING);
        ssh->modesSz = 0;
    }
#endif
#ifdef WOLFSSH_STATIC_MEMORY
    if (heap) {
        WOLFSSL_HEAP_HINT* hint = (WOLFSSL_HEAP_HINT*)heap;
        if (hint->memory->flag & WOLFMEM_TRACK_STATS
                && hint->stats != NULL) {
            WFREE(hint->stats, heap, DYNTYPE_SSH);
            hint->stats = NULL;
        }
    }
#endif
}


typedef struct WS_KeySignature {
    byte keySigId;
    word32 sigSz;
    const char *name;
    void *heap;
    word32 nameSz;
    union {
#ifndef WOLFSSH_NO_RSA
        struct {
            RsaKey key;
        } rsa;
#endif
#ifndef WOLFSSH_NO_ECDSA
        struct {
            ecc_key key;
        } ecc;
#endif
#ifndef WOLFSSH_NO_ED25519
        struct {
            ed25519_key key;
        } ed25519;
#endif
    } ks;
} WS_KeySignature;


static void wolfSSH_KEY_clean(WS_KeySignature* key)
{
    if (key != NULL) {
        if (key->keySigId == ID_SSH_RSA) {
#ifndef WOLFSSH_NO_RSA
            wc_FreeRsaKey(&key->ks.rsa.key);
#endif
        }
        else if (key->keySigId == ID_ECDSA_SHA2_NISTP256 ||
                key->keySigId == ID_ECDSA_SHA2_NISTP384 ||
                key->keySigId == ID_ECDSA_SHA2_NISTP521) {
#ifndef WOLFSSH_NO_ECDSA
            wc_ecc_free(&key->ks.ecc.key);
#endif
        }
    }
}


/*
 * Identifies the flavor of an ASN.1 key, RSA or ECDSA, and returns the key
 * type ID. The process is to decode the key as if it was RSA and if that
 * fails try to load it as if ECDSA. Both public and private keys can be
 * decoded. For RSA keys, the key format is described as "ssh-rsa".
 *
 * @param in        key to identify
 * @param inSz      size of key
 * @param isPrivate indicates private or public key
 * @param heap      heap to use for memory allocation
 * @return          keyId as int, WS_MEMORY_E, WS_UNIMPLEMENTED_E
 */
int IdentifyAsn1Key(const byte* in, word32 inSz, int isPrivate, void* heap)
{
    WS_KeySignature *key = NULL;
    word32 idx;
    int ret;
    int dynType = isPrivate ? DYNTYPE_PRIVKEY : DYNTYPE_PUBKEY;
    WOLFSSH_UNUSED(dynType);

    key = (WS_KeySignature*)WMALLOC(sizeof(WS_KeySignature), heap, dynType);

    if (key == NULL) {
        ret = WS_MEMORY_E;
    }
    else {
        WMEMSET(key, 0, sizeof(*key));
        key->keySigId = ID_UNKNOWN;

#ifndef WOLFSSH_NO_RSA
        /* Check RSA key */
        if (key->keySigId == ID_UNKNOWN) {
            idx = 0;
            ret = wc_InitRsaKey(&key->ks.rsa.key, NULL);

            if (ret == 0) {
                if (isPrivate) {
                    ret = wc_RsaPrivateKeyDecode(in, &idx,
                            &key->ks.rsa.key, inSz);
                }
                else {
                    ret = wc_RsaPublicKeyDecode(in, &idx,
                            &key->ks.rsa.key, inSz);
                }

                /* If decode was successful, this is an RSA key. */
                if (ret == 0) {
                    key->keySigId = ID_SSH_RSA;
                }
            }

            wc_FreeRsaKey(&key->ks.rsa.key);
        }
#endif /* WOLFSSH_NO_RSA */
#ifndef WOLFSSH_NO_ECDSA
        /* Check ECDSA key */
        if (key->keySigId == ID_UNKNOWN) {
            idx = 0;
            ret = wc_ecc_init_ex(&key->ks.ecc.key, heap, INVALID_DEVID);

            if (ret == 0) {
                if (isPrivate) {
                    ret = wc_EccPrivateKeyDecode(in, &idx,
                            &key->ks.ecc.key, inSz);
                }
                else {
                    ret = wc_EccPublicKeyDecode(in, &idx,
                            &key->ks.ecc.key, inSz);
                }

                /* If decode was successful, this is an ECDSA key. */
                if (ret == 0) {
                    switch (wc_ecc_get_curve_id(key->ks.ecc.key.idx)) {
                        case ECC_SECP256R1:
                            key->keySigId = ID_ECDSA_SHA2_NISTP256;
                            break;
                        case ECC_SECP384R1:
                            key->keySigId = ID_ECDSA_SHA2_NISTP384;
                            break;
                        case ECC_SECP521R1:
                            key->keySigId = ID_ECDSA_SHA2_NISTP521;
                            break;
                    }
                }
            }

            wc_ecc_free(&key->ks.ecc.key);
        }
#endif /* WOLFSSH_NO_ECDSA */
#if !defined(WOLFSSH_NO_ED25519)
    if (key != NULL) {
        if (key->keySigId == ID_UNKNOWN) {
            idx = 0;
            ret = wc_ed25519_init_ex(&key->ks.ed25519.key, heap, INVALID_DEVID);

            if(ret == 0) {
                if (isPrivate) {
                    ret = wc_Ed25519PrivateKeyDecode(in, &idx,
                            &key->ks.ed25519.key, inSz);
                }
                else {
                    ret = wc_Ed25519PublicKeyDecode(in, &idx,
                            &key->ks.ed25519.key, inSz);
                }
            }

            /* If decode was successful, this is a Ed25519 key. */
            if(ret == 0)
                key->keySigId = ID_ED25519;

            wc_ed25519_free(&key->ks.ed25519.key);
        }
    }
#endif /* WOLFSSH_NO_ED25519 */

        if (key->keySigId == ID_UNKNOWN) {
            ret = WS_UNIMPLEMENTED_E;
        }
        else {
            ret = key->keySigId;
        }

        WFREE(key, heap, dynType);
    }

    return ret;
}


#ifndef WOLFSSH_NO_RSA

#if (LIBWOLFSSL_VERSION_HEX > WOLFSSL_V5_7_0) && !defined(HAVE_FIPS)
/*
 * The function wc_RsaPrivateKeyDecodeRaw() is available
 * from wolfSSL after v5.7.0.
 */

/*
 * Utility for GetOpenSshKey() to read in RSA keys.
 */
static int GetOpenSshKeyRsa(RsaKey* key,
        const byte* buf, word32 len, word32* idx)
{
    const byte *n, *e, *d, *u, *p, *q;
    word32 nSz, eSz, dSz, uSz, pSz, qSz;
    int ret;

    ret = wc_InitRsaKey(key, NULL);
    if (ret == WS_SUCCESS)
        ret = GetMpint(&nSz, &n, buf, len, idx);
    if (ret == WS_SUCCESS)
        ret = GetMpint(&eSz, &e, buf, len, idx);
    if (ret == WS_SUCCESS)
        ret = GetMpint(&dSz, &d, buf, len, idx);
    if (ret == WS_SUCCESS)
        ret = GetMpint(&uSz, &u, buf, len, idx);
    if (ret == WS_SUCCESS)
        ret = GetMpint(&pSz, &p, buf, len, idx);
    if (ret == WS_SUCCESS)
        ret = GetMpint(&qSz, &q, buf, len, idx);
    if (ret == WS_SUCCESS)
        ret = wc_RsaPrivateKeyDecodeRaw(n, nSz, e, eSz, d, dSz,
                u, uSz, p, pSz, q, qSz, NULL, 0, NULL, 0, key);

    if (ret != WS_SUCCESS)
        ret = WS_RSA_E;

    return ret;
}

#else /* LIBWOLFSSL_VERSION_HEX > WOLFSSL_V5_7_0 */

#include <wolfssl/wolfcrypt/wolfmath.h>

/*
 * Utility function to read an Mpint from the stream directly into a mp_int.
 * The RsaKey members u, dP, and dQ do not exist when wolfCrypt is built
 * with RSA_LOW_MEM. (That mode of wolfCrypt isn't using the extra values
 * for the Chinese Remainder Theorem.)
 */
static int GetMpintToMp(mp_int* mp,
        const byte* buf, word32 len, word32* idx)
{
    const byte* val = NULL;
    word32 valSz = 0;
    int ret;

    ret = GetMpint(&valSz, &val, buf, len, idx);
    if (ret == WS_SUCCESS)
        ret = mp_read_unsigned_bin(mp, val, valSz);

    return ret;
}


#ifndef RSA_LOW_MEM
/*
 * For the given RSA key, calculate d mod(p-1) and d mod(q-1).
 * wolfCrypt's RSA code expects them, but the OpenSSH format key
 * doesn't store them.
 */
static int CalcRsaDX(RsaKey* key)
{
    mp_int m;
    int ret;

    ret = mp_init(&m);
    if (ret == MP_OKAY) {
        ret = mp_sub_d(&key->p, 1, &m);
        if (ret == MP_OKAY)
            ret = mp_mod(&key->d, &m, &key->dP);
        if (ret == MP_OKAY)
            ret = mp_sub_d(&key->q, 1, &m);
        if (ret == MP_OKAY)
            ret = mp_mod(&key->d, &m, &key->dQ);
        mp_forcezero(&m);
    }

    return ret;
}
#endif

/*
 * Utility for GetOpenSshKey() to read in RSA keys.
 */
static int GetOpenSshKeyRsa(RsaKey* key,
        const byte* buf, word32 len, word32* idx)
{
    int ret;

    ret = wc_InitRsaKey(key, NULL);
    if (ret == WS_SUCCESS)
        ret = GetMpintToMp(&key->n, buf, len, idx);
    if (ret == WS_SUCCESS)
        ret = GetMpintToMp(&key->e, buf, len, idx);
    if (ret == WS_SUCCESS)
        ret = GetMpintToMp(&key->d, buf, len, idx);
#ifndef RSA_LOW_MEM
    if (ret == WS_SUCCESS)
        ret = GetMpintToMp(&key->u, buf, len, idx);
#else
    /* Skipping the u value in the key. */
    if (ret == WS_SUCCESS)
        ret = GetSkip(buf, len, idx);
#endif
    if (ret == WS_SUCCESS)
        ret = GetMpintToMp(&key->p, buf, len, idx);
    if (ret == WS_SUCCESS)
        ret = GetMpintToMp(&key->q, buf, len, idx);

#ifndef RSA_LOW_MEM
    /* Calculate dP and dQ for wolfCrypt. */
    if (ret == WS_SUCCESS)
        ret = CalcRsaDX(key);
#endif

    if (ret != WS_SUCCESS)
        ret = WS_RSA_E;

    return ret;
}

#endif /* LIBWOLFSSL_VERSION_HEX > WOLFSSL_V5_7_0 */

#endif /* WOLFSSH_NO_RSA */


#ifndef WOLFSSH_NO_ECDSA
/*
 * Utility for GetOpenSshKey() to read in ECDSA keys.
 */
static int GetOpenSshKeyEcc(ecc_key* key,
        const byte* buf, word32 len, word32* idx)
{
    const byte *name = NULL, *priv = NULL, *pub = NULL;
    word32 nameSz = 0, privSz = 0, pubSz = 0;
    int ret;

    ret = wc_ecc_init(key);
    if (ret == WS_SUCCESS)
        ret = GetStringRef(&nameSz, &name, buf, len, idx); /* curve name */
    if (ret == WS_SUCCESS)
        ret = GetStringRef(&pubSz, &pub, buf, len, idx); /* Q */
    if (ret == WS_SUCCESS)
        ret = GetMpint(&privSz, &priv, buf, len, idx); /* d */

    if (ret == WS_SUCCESS)
        ret = wc_ecc_import_private_key_ex(priv, privSz, pub, pubSz,
                key, ECC_CURVE_DEF);

    if (ret != WS_SUCCESS)
        ret = WS_ECC_E;

    return ret;
}
#endif

#ifndef WOLFSSH_NO_ED25519
/*
 * Utility for GetOpenSshKey() to read in Ed25519 keys.
 */
static int GetOpenSshKeyEd25519(ed25519_key* key,
        const byte* buf, word32 len, word32* idx)
{
    const byte *priv = NULL, *pub = NULL;
    word32 privSz = 0, pubSz = 0;
    int ret;

    ret = wc_ed25519_init_ex(key, key->heap, INVALID_DEVID);

    /* OpenSSH key formatting stores the public key, ENC(A), and the
     * private key (k) concatenated with the public key, k || ENC(A). */
    if (ret == WS_SUCCESS)
        ret = GetStringRef(&pubSz, &pub, buf, len, idx); /* ENC(A) */
    if (ret == WS_SUCCESS)
        ret = GetStringRef(&privSz, &priv, buf, len, idx); /* k || ENC(A) */

    if (ret == WS_SUCCESS)
        ret = wc_ed25519_import_private_key(priv, privSz - pubSz,
                pub, pubSz, key);

    if (ret != WS_SUCCESS)
        ret = WS_ECC_E;

    return ret;
}
#endif
/*
 * Decodes an OpenSSH format key.
 */
static int GetOpenSshKey(WS_KeySignature *key,
        const byte* buf, word32 len, word32* idx)
{
    const char AuthMagic[] = "openssh-key-v1";
    const byte* str = NULL;
    word32 keyCount = 0, strSz, i;
    int ret = WS_SUCCESS;

    if (WSTRCMP(AuthMagic, (const char*)buf) != 0) {
        ret = WS_KEY_AUTH_MAGIC_E;
    }

    if (ret == WS_SUCCESS) {
        *idx += (word32)WSTRLEN(AuthMagic) + 1;
        ret = GetSkip(buf, len, idx); /* ciphername */
    }

    if (ret == WS_SUCCESS)
        ret = GetSkip(buf, len, idx); /* kdfname */

    if (ret == WS_SUCCESS)
        ret = GetSkip(buf, len, idx); /* kdfoptions */

    if (ret == WS_SUCCESS)
        ret = GetUint32(&keyCount, buf, len, idx); /* key count */

    if (ret == WS_SUCCESS) {
        if (keyCount != WOLFSSH_KEY_QUANTITY_REQ) {
            ret = WS_KEY_FORMAT_E;
        }
    }

    if (ret == WS_SUCCESS) {
        strSz = 0;
        ret = GetStringRef(&strSz, &str, buf, len, idx);
                /* public buf */
    }

    if (ret == WS_SUCCESS) {
        strSz = 0;
        ret = GetStringRef(&strSz, &str, buf, len, idx);
                /* list of private keys */

        /* If there isn't a private key, the key file is bad. */
        if (ret == WS_SUCCESS && strSz == 0) {
            ret = WS_KEY_FORMAT_E;
        }

        if (ret == WS_SUCCESS) {
            const byte* subStr = NULL;
            word32 subStrSz = 0, subIdx = 0, check1 = 0, check2 = ~0;
            byte keyId;

            idx = 0;
            if (ret == WS_SUCCESS)
                ret = GetUint32(&check1, str, strSz, &subIdx); /* checkint 1 */
            if (ret == WS_SUCCESS)
                ret = GetUint32(&check2, str, strSz, &subIdx); /* checkint 2 */
            if (ret == WS_SUCCESS) {
                if (check1 != check2) {
                    ret = WS_KEY_CHECK_VAL_E;
                }
            }
            if (ret == WS_SUCCESS) {
                for (i = 0; i < keyCount; i++) {
                    ret = GetStringRef(&subStrSz, &subStr,
                            str, strSz, &subIdx);
                    if (ret == WS_SUCCESS) {
                        keyId = NameToId((const char*)subStr, subStrSz);
                        key->keySigId = keyId;
                    }
                    if (ret == WS_SUCCESS) {
                        switch (keyId) {
                        #ifndef WOLFSSH_NO_RSA
                            case ID_SSH_RSA:
                                ret = GetOpenSshKeyRsa(&key->ks.rsa.key,
                                        str, strSz, &subIdx);
                                break;
                        #endif
                        #ifndef WOLFSSH_NO_ECDSA
                            case ID_ECDSA_SHA2_NISTP256:
                            case ID_ECDSA_SHA2_NISTP384:
                            case ID_ECDSA_SHA2_NISTP521:
                                ret = GetOpenSshKeyEcc(&key->ks.ecc.key,
                                        str, strSz, &subIdx);
                                break;
                        #endif
                        #ifndef WOLFSSH_NO_ED25519
                            case ID_ED25519:
                                ret = GetOpenSshKeyEd25519(&key->ks.ed25519.key,
                                        str, strSz, &subIdx);
                                break;
                        #endif
                            default:
                                ret = WS_UNIMPLEMENTED_E;
                                break;
                        }
                        if (ret == WS_SUCCESS)
                            ret = GetSkip(str, strSz, &subIdx);
                                    /* key comment */
                    }
                }
                /* Padding: Add increasing digits to pad to the nearest
                 * block size. Default block size is 8, but depends on
                 * the encryption algo. The private key chunk's length,
                 * and the length of the comment delimit the end of the
                 * encrypted blob. No added padding required. */
                if (ret == WS_SUCCESS) {
                    if (strSz % MIN_BLOCK_SZ == 0) {
                        if (strSz > subIdx) {
                            /* The padding starts at 1. */
                            check2 = strSz - subIdx;
                            for (check1 = 1;
                                 check1 <= check2;
                                 check1++, subIdx++) {
                                if (check1 != str[subIdx]) {
                                    /* Bad pad value. */
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    return ret;
}


/*
 * Identifies the flavor of an OpenSSH key, RSA or ECDSA, and returns the
 * key type ID. The process is to decode the key extracting the identifiers,
 * and try to decode the key as the type indicated type. For RSA keys, the
 * key format is described as "ssh-rsa".
 *
 * @param in        key to identify
 * @param inSz      size of key
 * @param heap      heap to use for memory allocation
 * @return          keyId as int, WS_MEMORY_E, WS_UNIMPLEMENTED_E,
 *                  WS_INVALID_ALGO_ID
 */
int IdentifyOpenSshKey(const byte* in, word32 inSz, void* heap)
{
    WS_KeySignature *key = NULL;
    word32 idx = 0;
    int ret;

    key = (WS_KeySignature*)WMALLOC(sizeof(WS_KeySignature),
            heap, DYNTYPE_PRIVKEY);

    if (key == NULL) {
        ret = WS_MEMORY_E;
    }
    else {
        WMEMSET(key, 0, sizeof(*key));
        key->heap = heap;
        key->keySigId = ID_NONE;

        ret = GetOpenSshKey(key, in, inSz, &idx);

        if (ret == WS_SUCCESS) {
            ret = key->keySigId;
        }
        else if (key->keySigId == ID_UNKNOWN) {
            ret = WS_UNIMPLEMENTED_E;
        }

        wolfSSH_KEY_clean(key);
        WFREE(key, heap, DYNTYPE_PRIVKEY);
    }

    return ret;
}


#ifdef WOLFSSH_CERTS
/*
 * Identifies the flavor of an X.509 certificate, RSA or ECDSA, and returns
 * the key type ID. The process is to decode the certificate and pass the
 * public key to IdentifyAsn1Key.
 *
 * @param in        certificate to identify
 * @param inSz      size of certificate
 * @param heap      heap to use for memory allocation
 * @return          keyId as int, WS_MEMORY_E, WS_UNIMPLEMENTED_E
 */
static int IdentifyCert(const byte* in, word32 inSz, void* heap)
{
    struct DecodedCert* cert = NULL;
#ifndef WOLFSSH_SMALL_STACK
    struct DecodedCert cert_s;
#endif
    byte *key = NULL;
    word32 keySz = 0;
    int ret = 0;

#ifndef WOLFSSH_SMALL_STACK
    cert = &cert_s;
#else
    cert = (struct DecodedCert*)WMALLOC(sizeof(struct DecodedCert),
            heap, DYNTYPE_CERT);
    if (cert == NULL) {
        ret = WS_MEMORY_E;
    }
#endif

    if (ret == 0) {
        wc_InitDecodedCert(cert, in, inSz, heap);
        ret = wc_ParseCert(cert, CERT_TYPE, 0, NULL);
    }
    if (ret == 0) {
        ret = wc_GetPubKeyDerFromCert(cert, NULL, &keySz);
        if (ret == LENGTH_ONLY_E) {
            ret = 0;
            key = (byte*)WMALLOC(keySz, heap, DYNTYPE_PUBKEY);
            if (key == NULL) {
                ret = WS_MEMORY_E;
            }
        }
    }

    if (ret == 0) {
        ret = wc_GetPubKeyDerFromCert(cert, key, &keySz);
    }

    if (ret == 0) {
        ret = IdentifyAsn1Key(key, keySz, 0, heap);
    }

    WFREE(key, heap, DYNTYPE_PUBKEY);
    if (cert != NULL) {
        wc_FreeDecodedCert(cert);
        #ifdef WOLFSSH_SMALL_STACK
            WFREE(cert, heap, DYNTYPE_CERT);
        #endif
    }

    return ret;
}
#endif /* WOLFSSH_CERTS */


static void RefreshPublicKeyAlgo(WOLFSSH_CTX* ctx)
{
    WOLFSSH_PVT_KEY* key;
    byte* publicKeyAlgo = ctx->publicKeyAlgo;
    word32 keyCount = ctx->privateKeyCount, publicKeyAlgoCount = 0, idx;

    for (idx = 0, key = ctx->privateKey; idx < keyCount; idx++, key++) {
        if (key->publicKeyFmt == ID_SSH_RSA) {
        #ifndef WOLFSSH_NO_RSA_SHA2_512
            if (publicKeyAlgoCount < WOLFSSH_MAX_PUB_KEY_ALGO) {
                *publicKeyAlgo = ID_RSA_SHA2_512;
                publicKeyAlgo++;
                publicKeyAlgoCount++;
            }
        #endif
        #ifndef WOLFSSH_NO_RSA_SHA2_256
            if (publicKeyAlgoCount < WOLFSSH_MAX_PUB_KEY_ALGO) {
                *publicKeyAlgo = ID_RSA_SHA2_256;
                publicKeyAlgo++;
                publicKeyAlgoCount++;
            }
        #endif
        #ifdef WOLFSSH_NO_SHA1_SOFT_DISABLE
            #ifndef WOLFSSH_NO_SSH_RSA_SHA1
                if (publicKeyAlgoCount < WOLFSSH_MAX_PUB_KEY_ALGO) {
                    *publicKeyAlgo = ID_SSH_RSA;
                    publicKeyAlgo++;
                    publicKeyAlgoCount++;
                }
            #endif /* WOLFSSH_NO_SSH_RSA_SHA1 */
        #endif /* WOLFSSH_NO_SHA1_SOFT_DISABLE */
        }
        else {
            if (publicKeyAlgoCount < WOLFSSH_MAX_PUB_KEY_ALGO) {
                *publicKeyAlgo = key->publicKeyFmt;
                publicKeyAlgo++;
                publicKeyAlgoCount++;
            }
        }
    }
    ctx->publicKeyAlgoCount = publicKeyAlgoCount;
}


#ifdef WOLFSSH_CERTS

static INLINE byte CertTypeForId(byte id)
{
    switch (id) {
    #ifndef WOLFSSH_NO_SSH_RSA_SHA1
        case ID_SSH_RSA:
            id = ID_X509V3_SSH_RSA;
            break;
    #endif
    #ifndef WOLFSSH_NO_ECDSA_SHA2_NISTP256
        case ID_ECDSA_SHA2_NISTP256:
            id = ID_X509V3_ECDSA_SHA2_NISTP256;
            break;
    #endif
    #ifndef WOLFSSH_NO_ECDSA_SHA2_NISTP384
        case ID_ECDSA_SHA2_NISTP384:
            id = ID_X509V3_ECDSA_SHA2_NISTP384;
            break;
    #endif
    #ifndef WOLFSSH_NO_ECDSA_SHA2_NISTP521
        case ID_ECDSA_SHA2_NISTP521:
            id = ID_X509V3_ECDSA_SHA2_NISTP521;
            break;
    #endif
    }

    WOLFSSH_UNUSED(id);
    return id;
}

#define HINTISSET(x) ((x) != WOLFSSH_MAX_PVT_KEYS)

static int UpdateHostCertificates(WOLFSSH_CTX* ctx,
        word32 keyHint, word32 certHint)
{
    int ret = WS_SUCCESS;
/*
 * 1. Load a private key.
 *    SetHostPrivateKey()
 *      -> UpdateCertificate() does nothing (keyHint set, certHint clear)
 *
 * 2. Load a private key then load a certificate.
 *    SetHostPrivateKey()
 *      -> UpdateCertificate() does nothing (keyHint set, certHint clear)
 *    SetHostCertificate()
 *      -> UpdateCertificate() updates (keyHint set, certHint set)
 *
 * 3. Load a certificate then load a private key.
 *    SetHostCertificate()
 *      -> UpdateCertificate() does nothing (keyHint clear, certHint set)
 *    SetHostPrivateKey()
 *      -> UpdateCertificate() updates (keyHint set, certHint clear/set)
 */

    /* If keyHint is set and certHint is not, scan list for
     * cert and update certHint. */
    if (HINTISSET(keyHint) && !HINTISSET(certHint)) {
        word32 i;
        byte certId;

        certId = CertTypeForId(ctx->privateKey[keyHint].publicKeyFmt);
        for (i = 0; i < ctx->privateKeyCount; i++) {
            if (certId == ctx->privateKey[i].publicKeyFmt) {
                certHint = i;
                break;
            }
        }
    }

    if (HINTISSET(keyHint) && HINTISSET(certHint)) {
        byte* key = NULL;
        word32 keySz;

        keySz = ctx->privateKey[keyHint].keySz;
        key = (byte*)WMALLOC(keySz, ctx->heap, DYNTYPE_PRIVKEY);
        if (key == NULL) {
            ret = WS_MEMORY_E;
        }
        else {
            WMEMCPY(key, ctx->privateKey[keyHint].key, keySz);

            if (ctx->privateKey[certHint].key != NULL) {
                ForceZero(ctx->privateKey[certHint].key,
                        ctx->privateKey[certHint].keySz);
                WFREE(ctx->privateKey[certHint].key,
                        ctx->heap, DYNTYPE_PRIVKEY);
            }
            ctx->privateKey[certHint].key = key;
            ctx->privateKey[certHint].keySz = keySz;
        }
    }

    return ret;
}

static int SetHostCertificate(WOLFSSH_CTX* ctx,
        byte keyId, byte* der, word32 derSz, int dynamicType)
{
    /*
     * The keyId is for the key inside the certificate. wolfSSH_ProcessBuffer
     * will decode the certificate, get the public key inside, and identify
     * that. keyId will be: ssh-rsa, ecdsa-sha2-nistp256, etc.
     */

    word32 destIdx,
           certIdx = WOLFSSH_MAX_PVT_KEYS, keyIdx = WOLFSSH_MAX_PVT_KEYS;
    int ret = WS_SUCCESS;
    byte certId = CertTypeForId(keyId);

    /* Look for the specified certId. Add it if not present,
     * replace it if present. Call UpdateHostCertificate().
     */

    for (destIdx = 0; destIdx < ctx->privateKeyCount; destIdx++) {
        if (ctx->privateKey[destIdx].publicKeyFmt == certId) {
            certIdx = destIdx;
        }
        if (ctx->privateKey[destIdx].publicKeyFmt == keyId) {
            keyIdx = destIdx;
        }
    }

    if (destIdx >= WOLFSSH_MAX_PVT_KEYS) {
        ret = WS_CTX_KEY_COUNT_E;
    }
    else {
        WOLFSSH_PVT_KEY* pvtKey = ctx->privateKey + destIdx;

        if (pvtKey->publicKeyFmt == certId) {
            if (pvtKey->cert != NULL) {
                WFREE(pvtKey->cert, ctx->heap, dynamicType);
            }
        }
        else {
            certIdx = destIdx;
            ctx->privateKeyCount++;
            pvtKey->publicKeyFmt = certId;
        }

        pvtKey->cert = der;
        pvtKey->certSz = derSz;

        if (ret == WS_SUCCESS) {
            ret = UpdateHostCertificates(ctx, keyIdx, certIdx);
        }
        if (ret == WS_SUCCESS) {
            RefreshPublicKeyAlgo(ctx);
        }
    }

    WOLFSSH_UNUSED(dynamicType);

    return ret;
}

#endif


static int SetHostPrivateKey(WOLFSSH_CTX* ctx,
        byte keyId, byte* der, word32 derSz, int dynamicType)
{
    word32 destIdx = 0;
    int ret = WS_SUCCESS;

     /* Look for the specified keyId. Add it if not present,
     * replace it if present. Call UpdateHostCertificate().
     */

    while (destIdx < ctx->privateKeyCount
            && ctx->privateKey[destIdx].publicKeyFmt != keyId) {
        destIdx++;
    }

    if (destIdx >= WOLFSSH_MAX_PVT_KEYS) {
        ret = WS_CTX_KEY_COUNT_E;
    }
    else {
        WOLFSSH_PVT_KEY* pvtKey = ctx->privateKey + destIdx;

        if (pvtKey->publicKeyFmt == keyId) {
            if (pvtKey->key != NULL) {
                ForceZero(pvtKey->key, pvtKey->keySz);
                WFREE(pvtKey->key, ctx->heap, dynamicType);
            }
        }
        else {
            ctx->privateKeyCount++;
            pvtKey->publicKeyFmt = keyId;
        }

        pvtKey->key = der;
        pvtKey->keySz = derSz;

        #ifdef WOLFSSH_CERTS
        if (ret == WS_SUCCESS) {
            ret = UpdateHostCertificates(ctx, destIdx, WOLFSSH_MAX_PVT_KEYS);
        }
        #endif
        if (ret == WS_SUCCESS) {
            RefreshPublicKeyAlgo(ctx);
        }
    }

    WOLFSSH_UNUSED(dynamicType);

    return ret;
}


int wolfSSH_ProcessBuffer(WOLFSSH_CTX* ctx,
                          const byte* in, word32 inSz,
                          int format, int type)
{
    void* heap = NULL;
    byte* der;
    word32 derSz;
    int wcType;
    int ret = WS_SUCCESS;
    int dynamicType = 0;
    byte keyId = ID_NONE;

    if (ctx == NULL || in == NULL || inSz == 0)
        return WS_BAD_ARGUMENT;

    if (format != WOLFSSH_FORMAT_ASN1
            && format != WOLFSSH_FORMAT_PEM
            && format != WOLFSSH_FORMAT_RAW
            && format != WOLFSSH_FORMAT_OPENSSH) {
        return WS_BAD_FILETYPE_E;
    }

    if (type == BUFTYPE_CA) {
        dynamicType = DYNTYPE_CA;
        wcType = CA_TYPE;
    }
    else if (type == BUFTYPE_CERT) {
        dynamicType = DYNTYPE_CERT;
        wcType = CERT_TYPE;
    }
    else if (type == BUFTYPE_PRIVKEY) {
        dynamicType = DYNTYPE_PRIVKEY;
        wcType = PRIVATEKEY_TYPE;
    }
    else {
        return WS_BAD_ARGUMENT;
    }

    heap = ctx->heap;

    if (format == WOLFSSH_FORMAT_ASN1 || format == WOLFSSH_FORMAT_RAW) {
        if (in[0] != 0x30)
            return WS_BAD_FILETYPE_E;
        der = (byte*)WMALLOC(inSz, heap, dynamicType);
        if (der == NULL)
            return WS_MEMORY_E;
        WMEMCPY(der, in, inSz);
        derSz = inSz;
    }
    #ifdef WOLFSSH_CERTS
    else if (format == WOLFSSH_FORMAT_PEM) {
        /* The der size will be smaller than the pem size. */
        der = (byte*)WMALLOC(inSz, heap, dynamicType);
        if (der == NULL)
            return WS_MEMORY_E;

        ret = wc_CertPemToDer(in, inSz, der, inSz, wcType);
        if (ret < 0) {
            WFREE(der, heap, dynamicType);
            return WS_BAD_FILE_E;
        }
        derSz = (word32)ret;
    }
    #endif /* WOLFSSH_CERTS */
    else {
        return WS_UNIMPLEMENTED_E;
    }

    /* Maybe decrypt */

    if (type == BUFTYPE_PRIVKEY) {
        ret = IdentifyAsn1Key(der, derSz, 1, ctx->heap);
        if (ret < 0) {
            WFREE(der, heap, dynamicType);
            return ret;
        }
        keyId = (byte)ret;
        ret = SetHostPrivateKey(ctx, keyId, der, derSz, dynamicType);
    }
    #ifdef WOLFSSH_CERTS
    else if (type == BUFTYPE_CERT) {
        ret = IdentifyCert(der, derSz, ctx->heap);
        if (ret < 0) {
            WFREE(der, heap, dynamicType);
            return ret;
        }
        keyId = (byte)ret;
        ret = SetHostCertificate(ctx, keyId, der, derSz, dynamicType);
    }
    else if (type == BUFTYPE_CA) {
        if (ctx->certMan != NULL) {
            ret = wolfSSH_CERTMAN_LoadRootCA_buffer(ctx->certMan, der, derSz);
        }
        else {
            WLOG(WS_LOG_DEBUG, "Error no cert manager set");
            ret = WS_MEMORY_E;
        }
        WFREE(der, heap, dynamicType);
        if (ret < 0) {
            WLOG(WS_LOG_DEBUG, "Error %d loading in CA buffer", ret);
        }
    }
    #endif /* WOLFSSH_CERTS */

    WOLFSSH_UNUSED(dynamicType);
    WOLFSSH_UNUSED(wcType);
    WOLFSSH_UNUSED(heap);

    return ret;
}


int GenerateKey(byte hashId, byte keyId,
                byte* key, word32 keySz,
                const byte* k, word32 kSz,
                const byte* h, word32 hSz,
                const byte* sessionId, word32 sessionIdSz,
                byte doKeyPad)
#if (LIBWOLFSSL_VERSION_HEX >= WOLFSSL_V5_0_0) \
    && ((defined(HAVE_FIPS) && FIPS_VERSION_GE(5,2)) \
        || defined(WOLFSSH_NO_ECDH_NISTP256_KYBER_LEVEL1_SHA256))
/* Cannot use the SSH KDF with Kyber. With Kyber, doKeyPad must be false,
 * and the FIPS SSH KDF doesn't handle no-padding. Also, the Kyber algorithm
 * isn't in our FIPS boundary. */
{
    int ret = WS_SUCCESS;

    if (!doKeyPad) {
        WLOG(WS_LOG_ERROR, "cannot use FIPS KDF with Kyber");
        ret = WS_INVALID_ALGO_ID;
    }
    else {
        PRIVATE_KEY_UNLOCK();
        ret = wc_SSH_KDF(hashId, keyId, key, keySz,
                k, kSz, h, hSz, sessionId, sessionIdSz);
        PRIVATE_KEY_LOCK();
        if (ret != 0) {
            WLOG(WS_LOG_ERROR, "SSH KDF failed (%d)", ret);
            ret = WS_KDF_E;
        }
    }
    return ret;
}
#else
{
    word32 blocks, remainder;
    wc_HashAlg hash;
    enum wc_HashType enmhashId = (enum wc_HashType)hashId;
    byte kPad = 0;
    byte pad = 0;
    byte kSzFlat[LENGTH_SZ];
    int digestSz;
    int ret;

    WLOG(WS_LOG_DEBUG, "Entering GenerateKey()");

    if (key == NULL || keySz == 0 ||
        k == NULL || kSz == 0 ||
        h == NULL || hSz == 0 ||
        sessionId == NULL || sessionIdSz == 0) {

        return WS_BAD_ARGUMENT;
    }

    digestSz = wc_HashGetDigestSize(enmhashId);
    if (digestSz <= 0) {
        WLOG(WS_LOG_DEBUG, "GK: bad hash ID");
        return WS_BAD_ARGUMENT;
    }

    /* Data can be define as string and mpint. (see Section 5 of RFC4251).
     * This padding is required in the case of an mpint, but not in the case of
     * a string. */
    if (doKeyPad && (k[0] & 0x80)) kPad = 1;
    c32toa(kSz + kPad, kSzFlat);

    blocks = keySz / digestSz;
    remainder = keySz % digestSz;

    ret = wc_HashInit(&hash, enmhashId);
    if (ret == WS_SUCCESS)
        ret = HashUpdate(&hash, enmhashId, kSzFlat, LENGTH_SZ);
    if (ret == WS_SUCCESS && kPad)
        ret = HashUpdate(&hash, enmhashId, &pad, 1);
    if (ret == WS_SUCCESS)
        ret = HashUpdate(&hash, enmhashId, k, kSz);
    if (ret == WS_SUCCESS)
        ret = HashUpdate(&hash, enmhashId, h, hSz);
    if (ret == WS_SUCCESS)
        ret = HashUpdate(&hash, enmhashId, &keyId, sizeof(keyId));
    if (ret == WS_SUCCESS)
        ret = HashUpdate(&hash, enmhashId, sessionId, sessionIdSz);

    if (ret == WS_SUCCESS) {
        if (blocks == 0) {
            if (remainder > 0) {
                byte lastBlock[WC_MAX_DIGEST_SIZE];
                ret = wc_HashFinal(&hash, enmhashId, lastBlock);
                if (ret == WS_SUCCESS)
                    WMEMCPY(key, lastBlock, remainder);
            }
        }
        else {
            word32 runningKeySz, curBlock;

            runningKeySz = digestSz;
            ret = wc_HashFinal(&hash, enmhashId, key);

            for (curBlock = 1; curBlock < blocks; curBlock++) {
                ret = wc_HashInit(&hash, enmhashId);
                if (ret != WS_SUCCESS) break;
                ret = HashUpdate(&hash, enmhashId, kSzFlat, LENGTH_SZ);
                if (ret != WS_SUCCESS) break;
                if (kPad)
                    ret = HashUpdate(&hash, enmhashId, &pad, 1);
                if (ret != WS_SUCCESS) break;
                ret = HashUpdate(&hash, enmhashId, k, kSz);
                if (ret != WS_SUCCESS) break;
                ret = HashUpdate(&hash, enmhashId, h, hSz);
                if (ret != WS_SUCCESS) break;
                ret = HashUpdate(&hash, enmhashId, key, runningKeySz);
                if (ret != WS_SUCCESS) break;
                ret = wc_HashFinal(&hash, enmhashId, key + runningKeySz);
                if (ret != WS_SUCCESS) break;
                runningKeySz += digestSz;
            }

            if (remainder > 0) {
                byte lastBlock[WC_MAX_DIGEST_SIZE];
                if (ret == WS_SUCCESS)
                    ret = wc_HashInit(&hash, enmhashId);
                if (ret == WS_SUCCESS)
                    ret = HashUpdate(&hash, enmhashId, kSzFlat, LENGTH_SZ);
                if (ret == WS_SUCCESS && kPad)
                    ret = HashUpdate(&hash, enmhashId, &pad, 1);
                if (ret == WS_SUCCESS)
                    ret = HashUpdate(&hash, enmhashId, k, kSz);
                if (ret == WS_SUCCESS)
                    ret = HashUpdate(&hash, enmhashId, h, hSz);
                if (ret == WS_SUCCESS)
                    ret = HashUpdate(&hash, enmhashId, key, runningKeySz);
                if (ret == WS_SUCCESS)
                    ret = wc_HashFinal(&hash, enmhashId, lastBlock);
                if (ret == WS_SUCCESS)
                    WMEMCPY(key + runningKeySz, lastBlock, remainder);
            }
        }
    }

    if (ret != WS_SUCCESS)
        ret = WS_CRYPTO_FAILED;
    wc_HashFree(&hash, enmhashId);

    return ret;
}
#endif /* HAVE_FIPS && LIBWOLFSSL_VERSION_HEX >= WOLFSSL_V5_7_2 */


static int GenerateKeys(WOLFSSH* ssh, byte hashId, byte doKeyPad)
{
    Keys* cK = NULL;
    Keys* sK = NULL;
    int ret = WS_SUCCESS;

    if (ssh == NULL)
        ret = WS_BAD_ARGUMENT;
    else {
        if (ssh->ctx->side == WOLFSSH_ENDPOINT_SERVER) {
            cK = &ssh->handshake->peerKeys;
            sK = &ssh->handshake->keys;
        }
        else {
            cK = &ssh->handshake->keys;
            sK = &ssh->handshake->peerKeys;
        }
    }

    if (ret == WS_SUCCESS)
        ret = GenerateKey(hashId, 'A',
                          cK->iv, cK->ivSz,
                          ssh->k, ssh->kSz, ssh->h, ssh->hSz,
                          ssh->sessionId, ssh->sessionIdSz, doKeyPad);
    if (ret == WS_SUCCESS)
        ret = GenerateKey(hashId, 'B',
                          sK->iv, sK->ivSz,
                          ssh->k, ssh->kSz, ssh->h, ssh->hSz,
                          ssh->sessionId, ssh->sessionIdSz, doKeyPad);
    if (ret == WS_SUCCESS)
        ret = GenerateKey(hashId, 'C',
                          cK->encKey, cK->encKeySz,
                          ssh->k, ssh->kSz, ssh->h, ssh->hSz,
                          ssh->sessionId, ssh->sessionIdSz, doKeyPad);
    if (ret == WS_SUCCESS)
        ret = GenerateKey(hashId, 'D',
                          sK->encKey, sK->encKeySz,
                          ssh->k, ssh->kSz, ssh->h, ssh->hSz,
                          ssh->sessionId, ssh->sessionIdSz, doKeyPad);
    if (ret == WS_SUCCESS) {
        if (!ssh->handshake->aeadMode) {
            ret = GenerateKey(hashId, 'E',
                              cK->macKey, cK->macKeySz,
                              ssh->k, ssh->kSz, ssh->h, ssh->hSz,
                              ssh->sessionId, ssh->sessionIdSz, doKeyPad);
            if (ret == WS_SUCCESS) {
                ret = GenerateKey(hashId, 'F',
                                  sK->macKey, sK->macKeySz,
                                  ssh->k, ssh->kSz, ssh->h, ssh->hSz,
                                  ssh->sessionId, ssh->sessionIdSz, doKeyPad);
            }
        }
    }

#ifdef SHOW_SECRETS
    if (ret == WS_SUCCESS) {
        printf("\n** Showing Secrets **\nK:\n");
        DumpOctetString(ssh->k, ssh->kSz);
        printf("H:\n");
        DumpOctetString(ssh->h, ssh->hSz);
        printf("Session ID:\n");
        DumpOctetString(ssh->sessionId, ssh->sessionIdSz);
        printf("A:\n");
        DumpOctetString(cK->iv, cK->ivSz);
        printf("B:\n");
        DumpOctetString(sK->iv, sK->ivSz);
        printf("C:\n");
        DumpOctetString(cK->encKey, cK->encKeySz);
        printf("D:\n");
        DumpOctetString(sK->encKey, sK->encKeySz);
        printf("E:\n");
        DumpOctetString(cK->macKey, cK->macKeySz);
        printf("F:\n");
        DumpOctetString(sK->macKey, sK->macKeySz);
        printf("\n");
    }
#endif /* SHOW_SECRETS */

    return ret;
}


typedef struct {
    byte id;
    byte type;
    const char* name;
} NameIdPair;


static const NameIdPair NameIdMap[] = {
    { ID_NONE, TYPE_OTHER, "none" },

    /* Encryption IDs */
#ifndef WOLFSSH_NO_AES_CBC
    { ID_AES128_CBC, TYPE_CIPHER, "aes128-cbc" },
    { ID_AES192_CBC, TYPE_CIPHER, "aes192-cbc" },
    { ID_AES256_CBC, TYPE_CIPHER, "aes256-cbc" },
#endif
#ifndef WOLFSSH_NO_AES_CTR
    { ID_AES128_CTR, TYPE_CIPHER, "aes128-ctr" },
    { ID_AES192_CTR, TYPE_CIPHER, "aes192-ctr" },
    { ID_AES256_CTR, TYPE_CIPHER, "aes256-ctr" },
#endif
#ifndef WOLFSSH_NO_AES_GCM
    { ID_AES128_GCM, TYPE_CIPHER, "aes128-gcm@openssh.com" },
    { ID_AES192_GCM, TYPE_CIPHER, "aes192-gcm@openssh.com" },
    { ID_AES256_GCM, TYPE_CIPHER, "aes256-gcm@openssh.com" },
#endif

    /* Integrity IDs */
#ifndef WOLFSSH_NO_HMAC_SHA1
    { ID_HMAC_SHA1, TYPE_MAC, "hmac-sha1" },
#endif
#ifndef WOLFSSH_NO_HMAC_SHA1_96
    { ID_HMAC_SHA1_96, TYPE_MAC, "hmac-sha1-96" },
#endif
#ifndef WOLFSSH_NO_HMAC_SHA2_256
    { ID_HMAC_SHA2_256, TYPE_MAC, "hmac-sha2-256" },
#endif

    /* Key Exchange IDs */
#ifndef WOLFSSH_NO_DH_GROUP1_SHA1
    { ID_DH_GROUP1_SHA1, TYPE_KEX, "diffie-hellman-group1-sha1" },
#endif
#ifndef WOLFSSH_NO_DH_GROUP14_SHA1
    { ID_DH_GROUP14_SHA1, TYPE_KEX, "diffie-hellman-group14-sha1" },
#endif
#ifndef WOLFSSH_NO_DH_GROUP14_SHA256
    { ID_DH_GROUP14_SHA256, TYPE_KEX, "diffie-hellman-group14-sha256" },
#endif
#ifndef WOLFSSH_NO_DH_GEX_SHA256
    { ID_DH_GEX_SHA256, TYPE_KEX, "diffie-hellman-group-exchange-sha256" },
#endif
#ifndef WOLFSSH_NO_ECDH_SHA2_NISTP256
    { ID_ECDH_SHA2_NISTP256, TYPE_KEX, "ecdh-sha2-nistp256" },
#endif
#ifndef WOLFSSH_NO_ECDH_SHA2_NISTP384
    { ID_ECDH_SHA2_NISTP384, TYPE_KEX, "ecdh-sha2-nistp384" },
#endif
#ifndef WOLFSSH_NO_ECDH_SHA2_NISTP521
    { ID_ECDH_SHA2_NISTP521, TYPE_KEX, "ecdh-sha2-nistp521" },
#endif
#ifndef WOLFSSH_NO_ECDH_NISTP256_KYBER_LEVEL1_SHA256
    { ID_ECDH_NISTP256_KYBER_LEVEL1_SHA256, TYPE_KEX,
        "ecdh-nistp256-kyber-512r3-sha256-d00@openquantumsafe.org" },
#endif
#ifndef WOLFSSH_NO_CURVE25519_SHA256
    /* See RFC 8731 */
    { ID_CURVE25519_SHA256, TYPE_KEX, "curve25519-sha256" },
#endif
    { ID_EXTINFO_S, TYPE_OTHER, "ext-info-s" },
    { ID_EXTINFO_C, TYPE_OTHER, "ext-info-c" },

    /* Public Key IDs */
#ifndef WOLFSSH_NO_RSA
    { ID_SSH_RSA, TYPE_KEY, "ssh-rsa" },
#ifndef WOLFSSH_NO_RSA_SHA2_256
    { ID_RSA_SHA2_256, TYPE_KEY, "rsa-sha2-256" },
#endif
#ifndef WOLFSSH_NO_RSA_SHA2_512
    { ID_RSA_SHA2_512, TYPE_KEY, "rsa-sha2-512" },
#endif
#endif /* WOLFSSH_NO_RSA */
#ifndef WOLFSSH_NO_ECDSA_SHA2_NISTP256
    { ID_ECDSA_SHA2_NISTP256, TYPE_KEY, "ecdsa-sha2-nistp256" },
#endif
#ifndef WOLFSSH_NO_ECDSA_SHA2_NISTP384
    { ID_ECDSA_SHA2_NISTP384, TYPE_KEY, "ecdsa-sha2-nistp384" },
#endif
#ifndef WOLFSSH_NO_ECDSA_SHA2_NISTP521
    { ID_ECDSA_SHA2_NISTP521, TYPE_KEY, "ecdsa-sha2-nistp521" },
#endif
#ifndef WOLFSSH_NO_ED25519
    { ID_ED25519, TYPE_KEY, "ssh-ed25519" },
#endif
#ifdef WOLFSSH_CERTS
#ifndef WOLFSSH_NO_SSH_RSA_SHA1
    { ID_X509V3_SSH_RSA, TYPE_KEY, "x509v3-ssh-rsa" },
#endif
#ifndef WOLFSSH_NO_ECDSA_SHA2_NISTP256
    { ID_X509V3_ECDSA_SHA2_NISTP256, TYPE_KEY, "x509v3-ecdsa-sha2-nistp256" },
#endif
#ifndef WOLFSSH_NO_ECDSA_SHA2_NISTP384
    { ID_X509V3_ECDSA_SHA2_NISTP384, TYPE_KEY, "x509v3-ecdsa-sha2-nistp384" },
#endif
#ifndef WOLFSSH_NO_ECDSA_SHA2_NISTP521
    { ID_X509V3_ECDSA_SHA2_NISTP521, TYPE_KEY, "x509v3-ecdsa-sha2-nistp521" },
#endif
#endif /* WOLFSSH_CERTS */

    /* Service IDs */
    { ID_SERVICE_USERAUTH, TYPE_OTHER, "ssh-userauth" },
    { ID_SERVICE_CONNECTION, TYPE_OTHER, "ssh-connection" },

    /* UserAuth IDs */
    { ID_USERAUTH_PASSWORD, TYPE_OTHER, "password" },
    { ID_USERAUTH_PUBLICKEY, TYPE_OTHER, "publickey" },

    /* Channel Type IDs */
    { ID_CHANTYPE_SESSION, TYPE_OTHER, "session" },
#ifdef WOLFSSH_FWD
    { ID_CHANTYPE_TCPIP_FORWARD, TYPE_OTHER, "forwarded-tcpip" },
    { ID_CHANTYPE_TCPIP_DIRECT, TYPE_OTHER, "direct-tcpip" },
#endif /* WOLFSSH_FWD */
#ifdef WOLFSSH_AGENT
    { ID_CHANTYPE_AUTH_AGENT, TYPE_OTHER, "auth-agent@openssh.com" },
#endif /* WOLFSSH_AGENT */

    /* Global Request IDs */
#ifdef WOLFSSH_FWD
    { ID_GLOBREQ_TCPIP_FWD, TYPE_OTHER, "tcpip-forward" },
    { ID_GLOBREQ_TCPIP_FWD_CANCEL, TYPE_OTHER, "cancel-tcpip-forward" },
#endif /* WOLFSSH_FWD */

    /* Ext Info IDs */
    { ID_EXTINFO_SERVER_SIG_ALGS, TYPE_OTHER, "server-sig-algs" },

    /* Curve Name IDs */
    { ID_CURVE_NISTP256, TYPE_OTHER, "nistp256" },
    { ID_CURVE_NISTP384, TYPE_OTHER, "nistp384" },
    { ID_CURVE_NISTP521, TYPE_OTHER, "nistp521" },
};


byte NameToId(const char* name, word32 nameSz)
{
    byte id = ID_UNKNOWN;
    word32 i;

    for (i = 0; i < (sizeof(NameIdMap)/sizeof(NameIdPair)); i++) {
        if (nameSz == (word32)WSTRLEN(NameIdMap[i].name) &&
            XMEMCMP(name, NameIdMap[i].name, nameSz) == 0) {

            id = NameIdMap[i].id;
            break;
        }
    }

    return id;
}


const char* IdToName(byte id)
{
    const char* name = "unknown";
    word32 i;

    for (i = 0; i < (sizeof(NameIdMap)/sizeof(NameIdPair)); i++) {
        if (NameIdMap[i].id == id) {
            name = NameIdMap[i].name;
            break;
        }
    }

    return name;
}


const char* NameByIndexType(byte type, word32* index)
{
    const char* name = NULL;

    if (index != NULL) {
        word32 i, mapSz;

        mapSz = (word32)(sizeof(NameIdMap)/sizeof(NameIdPair));

        for (i = *index; i < mapSz; i++) {
            if (NameIdMap[i].type == type) {
                name = NameIdMap[i].name;
                break;
            }
        }

        *index = i + 1;
    }

    return name;
}


WOLFSSH_CHANNEL* ChannelNew(WOLFSSH* ssh, byte channelType,
                            word32 initialWindowSz, word32 maxPacketSz)
{
    WOLFSSH_CHANNEL* newChannel = NULL;

    WLOG(WS_LOG_DEBUG, "Entering ChannelNew()");
    if (ssh == NULL || ssh->ctx == NULL) {
        WLOG(WS_LOG_DEBUG, "Trying to create new channel without ssh or ctx");
    }
    else {
        void* heap = ssh->ctx->heap;

        newChannel = (WOLFSSH_CHANNEL*)WMALLOC(sizeof(WOLFSSH_CHANNEL),
                                               heap, DYNTYPE_CHANNEL);
        if (newChannel != NULL)
        {
            byte* buffer;

            buffer = (byte*)WMALLOC(initialWindowSz, heap, DYNTYPE_BUFFER);
            if (buffer != NULL) {
                WMEMSET(newChannel, 0, sizeof(WOLFSSH_CHANNEL));
                newChannel->ssh = ssh;
                newChannel->channelType = channelType;
                newChannel->channel = ssh->nextChannel++;
                WLOG(WS_LOG_DEBUG, "New channel id = %u", newChannel->channel);
                newChannel->windowSz = initialWindowSz;
                newChannel->maxPacketSz = maxPacketSz;
                /*
                 * In the context of the channel input buffer, the buffer is
                 * a fixed size. The property length will be the insert point
                 * for new received data. The property idx will be the pull
                 * point for the data.
                 */
                newChannel->inputBuffer.heap = heap;
                newChannel->inputBuffer.buffer = buffer;
                newChannel->inputBuffer.bufferSz = initialWindowSz;
                newChannel->inputBuffer.dynamicFlag = 1;
            }
            else {
                WLOG(WS_LOG_DEBUG, "Unable to allocate new channel's buffer");
                WFREE(newChannel, heap, DYNTYPE_CHANNEL);
                newChannel = NULL;
            }
        }
        else {
            WLOG(WS_LOG_DEBUG, "Unable to allocate new channel");
        }
    }

    WLOG(WS_LOG_INFO, "Leaving ChannelNew(), ret = %p", newChannel);

    return newChannel;
}


void ChannelDelete(WOLFSSH_CHANNEL* channel, void* heap)
{
    WOLFSSH_UNUSED(heap);

    if (channel) {
    #ifdef WOLFSSH_FWD
        if (channel->host)
            WFREE(channel->host, heap, DYNTYPE_STRING);
        if (channel->origin)
            WFREE(channel->origin, heap, DYNTYPE_STRING);
    #endif /* WOLFSSH_FWD */
        WFREE(channel->inputBuffer.buffer,
              channel->inputBuffer.heap, DYNTYPE_BUFFER);
        if (channel->command)
            WFREE(channel->command, heap, DYNTYPE_STRING);
        WFREE(channel, heap, DYNTYPE_CHANNEL);
    }
}


WOLFSSH_CHANNEL* ChannelFind(WOLFSSH* ssh, word32 channel, byte peer)
{
    WOLFSSH_CHANNEL* findChannel = NULL;

    WLOG(WS_LOG_DEBUG, "Entering ChannelFind(): %s %u",
         peer ? "peer" : "self", channel);

    if (ssh == NULL) {
        WLOG(WS_LOG_DEBUG, "Null ssh, not looking for channel");
    }
    else {
        WOLFSSH_CHANNEL* list = ssh->channelList;
        word32 listSz = ssh->channelListSz;

        while (list && listSz) {
            if (channel == ((peer == WS_CHANNEL_ID_PEER) ?
                            list->peerChannel : list->channel)) {
                findChannel = list;
                break;
            }
            list = list->next;
            listSz--;
        }
    }

    WLOG(WS_LOG_DEBUG, "Leaving ChannelFind(): %p", findChannel);

    return findChannel;
}


int ChannelUpdatePeer(WOLFSSH_CHANNEL* channel, word32 peerChannelId,
                  word32 peerInitialWindowSz, word32 peerMaxPacketSz)
{
    int ret = WS_SUCCESS;

    if (channel == NULL)
        ret = WS_BAD_ARGUMENT;
    else {
        channel->peerChannel = peerChannelId;
        channel->peerWindowSz = peerInitialWindowSz;
        channel->peerMaxPacketSz = peerMaxPacketSz;
        channel->openConfirmed = 1;
    }

    return ret;
}


#ifdef WOLFSSH_FWD
int ChannelUpdateForward(WOLFSSH_CHANNEL* channel,
                                const char* host, word32 hostPort,
                                const char* origin, word32 originPort,
                                int isDirect)
{
    void* heap = NULL;
    int ret = WS_SUCCESS;
    char* hostCopy = NULL;
    char* originCopy = NULL;
    word32 hostSz;
    word32 originSz;

    WOLFSSH_UNUSED(heap);

    if (channel == NULL || host == NULL || origin == NULL)
        ret = WS_BAD_ARGUMENT;
    else {
        heap = channel->ssh->ctx->heap;
        hostSz = (word32)WSTRLEN(host) + 1;
        originSz = (word32)WSTRLEN(origin) + 1;
        hostCopy = (char*)WMALLOC(hostSz, heap, DYNTYPE_STRING);
        originCopy = (char*)WMALLOC(originSz, heap, DYNTYPE_STRING);
        if (hostCopy == NULL || originCopy == NULL) {
            WFREE(hostCopy, heap, DYNTYPE_STRING);
            WFREE(originCopy, heap, DYNTYPE_STRING);
            ret = WS_MEMORY_E;
        }
    }

    if (ret == WS_SUCCESS) {
        WSTRNCPY(hostCopy, host, hostSz);
        WSTRNCPY(originCopy, origin, originSz);

        /* delete any existing host and origin in the channel */
        if (channel->host)
            WFREE(channel->host, heap, DYNTYPE_STRING);
        if (channel->origin)
            WFREE(channel->origin, heap, DYNTYPE_STRING);

        channel->host = hostCopy;
        channel->hostPort = hostPort;
        channel->origin = originCopy;
        channel->originPort = originPort;
        channel->isDirect = isDirect;
    }

    return ret;
}
#endif /* WOLFSSH_FWD */


int ChannelAppend(WOLFSSH* ssh, WOLFSSH_CHANNEL* channel)
{
    int ret = WS_SUCCESS;

    WLOG(WS_LOG_DEBUG, "Entering ChannelAppend()");

    if (ssh == NULL || channel == NULL) {
        ret = WS_BAD_ARGUMENT;
        WLOG(WS_LOG_DEBUG, "Leaving ChannelAppend(), ret = %d", ret);
        return ret;
    }

    if (ssh->channelList == NULL) {
        ssh->channelList = channel;
        ssh->channelListSz = 1;
    }
    else {
        WOLFSSH_CHANNEL* cur = ssh->channelList;
        while (cur->next != NULL)
            cur = cur->next;
        cur->next = channel;
        ssh->channelListSz++;
    }

    WLOG(WS_LOG_DEBUG, "Leaving ChannelAppend(), ret = %d", ret);
    return ret;
}


int ChannelRemove(WOLFSSH* ssh, word32 channel, byte peer)
{
    int ret = WS_SUCCESS;
    WOLFSSH_CHANNEL* list;

    WLOG(WS_LOG_DEBUG, "Entering ChannelRemove()");

    if (ssh == NULL)
        ret = WS_BAD_ARGUMENT;

    if (ret == WS_SUCCESS) {
        list = ssh->channelList;
        if (list == NULL)
            ret = WS_INVALID_CHANID;
    }

    if (ret == WS_SUCCESS) {
        WOLFSSH_CHANNEL* prev = NULL;
        word32 listSz = ssh->channelListSz;

        while (list && listSz) {
            if (channel == ((peer == WS_CHANNEL_ID_PEER) ?
                            list->peerChannel : list->channel)) {
                if (prev == NULL)
                    ssh->channelList = list->next;
                else
                    prev->next = list->next;
                ChannelDelete(list, ssh->ctx->heap);
                ssh->channelListSz--;

                break;
            }
            prev = list;
            list = list->next;
            listSz--;
        }

        if (listSz == 0)
            ret = WS_INVALID_CHANID;
    }

    WLOG(WS_LOG_DEBUG, "Leaving ChannelRemove(), ret = %d", ret);
    return ret;
}


int ChannelPutData(WOLFSSH_CHANNEL* channel, byte* data, word32 dataSz)
{
    WOLFSSH_BUFFER* inBuf;

    WLOG(WS_LOG_DEBUG, "Entering ChannelPutData()");

    if (channel == NULL || data == NULL)
        return WS_BAD_ARGUMENT;

    inBuf = &channel->inputBuffer;

    /* sanity check the current state to see if is too much data */
    if (dataSz > channel->windowSz) {
        WLOG(WS_LOG_ERROR, "Internal state error, too much data");
        return WS_FATAL_ERROR;
    }

    if (inBuf->length < inBuf->bufferSz &&
        inBuf->length + dataSz <= inBuf->bufferSz) {

        WMEMCPY(inBuf->buffer + inBuf->length, data, dataSz);
        inBuf->length += dataSz;

        WLOG(WS_LOG_INFO, "  dataSz = %u", dataSz);
        WLOG(WS_LOG_INFO, "  windowSz = %u", channel->windowSz);
        channel->windowSz -= dataSz;
        WLOG(WS_LOG_INFO, "  update windowSz = %u", channel->windowSz);
    }
    else {
        return WS_RECV_OVERFLOW_E;
    }

    return WS_SUCCESS;
}


int BufferInit(WOLFSSH_BUFFER* buffer, word32 size, void* heap)
{
    if (buffer == NULL)
        return WS_BAD_ARGUMENT;

    if (size <= STATIC_BUFFER_LEN)
        size = STATIC_BUFFER_LEN;

    WMEMSET(buffer, 0, sizeof(WOLFSSH_BUFFER));
    buffer->heap = heap;
    buffer->bufferSz = size;
    if (size > STATIC_BUFFER_LEN) {
        buffer->buffer = (byte*)WMALLOC(size, heap, DYNTYPE_BUFFER);
        if (buffer->buffer == NULL)
            return WS_MEMORY_E;
        buffer->dynamicFlag = 1;
    }
    else
        buffer->buffer = buffer->staticBuffer;

    return WS_SUCCESS;
}

int GrowBuffer(WOLFSSH_BUFFER* buf, word32 sz)
{
#if 0
    WLOG(WS_LOG_DEBUG, "GB: buf = %p", buf);
    WLOG(WS_LOG_DEBUG, "GB: sz = %d", sz);
    WLOG(WS_LOG_DEBUG, "GB: usedSz = %d", buf->length - buf->idx);
#endif
    /* New buffer will end up being sz+ssh->length-ssh->idx long
     * empty space at the head of the buffer will be compressed */
    if (buf != NULL) {
        word32 newSz = sz + buf->length - buf->idx;

        if (newSz > buf->bufferSz) {
            byte* newBuffer = (byte*)WMALLOC(newSz, buf->heap, DYNTYPE_BUFFER);

            if (newBuffer == NULL) {
                WLOG(WS_LOG_ERROR, "Not enough memory left to grow buffer");
                return WS_MEMORY_E;
            }

            if (buf->length > 0) {
                WMEMCPY(newBuffer, buf->buffer + buf->idx, buf->length - buf->idx);
            }

            if (!buf->dynamicFlag) {
                buf->dynamicFlag = 1;
            }
            else {
                WFREE(buf->buffer, buf->heap, DYNTYPE_BUFFER);
            }

            buf->buffer = newBuffer;
            buf->bufferSz = newSz;
            buf->length -= buf->idx;
            buf->idx = 0;
        }
        else {
            if (buf->length > 0) {
                WMEMMOVE(buf->buffer, buf->buffer + buf->idx, buf->length - buf->idx);
                buf->length -= buf->idx;
                buf->idx = 0;
            }
        }
    }

    return WS_SUCCESS;
}


void ShrinkBuffer(WOLFSSH_BUFFER* buf, int forcedFree)
{
    WLOG(WS_LOG_DEBUG, "Entering ShrinkBuffer()");

    if (buf != NULL) {
        word32 usedSz = buf->length - buf->idx;

        WLOG(WS_LOG_DEBUG, "  buf->bufferSz = %u", buf->bufferSz);
        WLOG(WS_LOG_DEBUG, "  buf->idx = %u", buf->idx);
        WLOG(WS_LOG_DEBUG, "  buf->length = %u", buf->length);
        WLOG(WS_LOG_DEBUG, "SB: usedSz = %u, forcedFree = %u",
             usedSz, forcedFree);

        if (!forcedFree && usedSz > STATIC_BUFFER_LEN)
            return;

        if (!forcedFree && usedSz) {
            WLOG(WS_LOG_DEBUG, "SB: shifting down");
            WMEMCPY(buf->staticBuffer, buf->buffer + buf->idx, usedSz);
        }

        if (buf->dynamicFlag) {
            WLOG(WS_LOG_DEBUG, "SB: releasing dynamic buffer");
            WFREE(buf->buffer, buf->heap, DYNTYPE_BUFFER);
        }
        buf->dynamicFlag = 0;
        buf->buffer = buf->staticBuffer;
        buf->bufferSz = STATIC_BUFFER_LEN;
        buf->length = forcedFree ? 0 : usedSz;
        buf->idx = 0;
    }

    WLOG(WS_LOG_DEBUG, "Leaving ShrinkBuffer()");
}


static int ReceiveData(WOLFSSH* ssh, byte* buf, word32 sz)
{
    int recvd;

    if (ssh->ctx->ioRecvCb == NULL) {
        WLOG(WS_LOG_DEBUG, "Your IO Recv callback is null, please set");
        return -1;
    }

retry:
    recvd = ssh->ctx->ioRecvCb(ssh, buf, sz, ssh->ioReadCtx);
    WLOG(WS_LOG_DEBUG, "Receive: recvd = %d", recvd);
    if (recvd < 0)
        switch (recvd) {
            case WS_CBIO_ERR_GENERAL:        /* general/unknown error */
                return -1;

            case WS_CBIO_ERR_WANT_READ:      /* want read, would block */
                return WS_WANT_READ;

            case WS_CBIO_ERR_CONN_RST:       /* connection reset */
                ssh->connReset = 1;
                return -1;

            case WS_CBIO_ERR_ISR:            /* interrupt */
                goto retry;

            case WS_CBIO_ERR_CONN_CLOSE:     /* peer closed connection */
                ssh->isClosed = 1;
                return -1;

            case WS_CBIO_ERR_TIMEOUT:
                return -1;

            default:
                return recvd;
        }

    return recvd;
}


static int GetInputText(WOLFSSH* ssh, byte** pEol)
{
    int gotLine = 0;
    int inSz = 255;
    int in;
    char *eol = NULL;

    if (GrowBuffer(&ssh->inputBuffer, inSz) < 0)
        return WS_MEMORY_E;

    do {
        in = ReceiveData(ssh,
                     ssh->inputBuffer.buffer + ssh->inputBuffer.length, inSz);

        if (in == -1) {
            return WS_SOCKET_ERROR_E;
        }

        if (in == WS_WANT_READ) {
            return WS_WANT_READ;
        }

        if (in > inSz) {
            return WS_RECV_OVERFLOW_E;
        }

        ssh->inputBuffer.length += in;
        inSz -= in;

        eol = WSTRNSTR((const char*)ssh->inputBuffer.buffer, "\r\n",
                       ssh->inputBuffer.length);

        /* section 4.2 in RFC 4253 states that can be lenient on the CR for
         * interop with older or undocumented versions of SSH */
        if (!eol) {
            WLOG(WS_LOG_DEBUG, "Checking for old version of protocol exchange");
            eol = WSTRNSTR((const char*)ssh->inputBuffer.buffer, "\n",
                       ssh->inputBuffer.length);
        }

        if (eol)
            gotLine = 1;

    } while (!gotLine && inSz);

    if (pEol)
        *pEol = (byte*)eol;

    if (!gotLine) {
        return WS_VERSION_E;
    }

    return WS_SUCCESS;
}


/* returns WS_SUCCESS on success */
int wolfSSH_SendPacket(WOLFSSH* ssh)
{
    WLOG(WS_LOG_DEBUG, "Entering wolfSSH_SendPacket()");

    if (ssh->ctx->ioSendCb == NULL) {
        WLOG(WS_LOG_DEBUG, "Your IO Send callback is null, please set");
        return WS_SOCKET_ERROR_E;
    }

    while (ssh->outputBuffer.length - ssh->outputBuffer.idx > 0) {
        int sent;

        /* sanity check on amount requested to be sent */
        if (ssh->outputBuffer.length > ssh->outputBuffer.bufferSz ||
                ssh->outputBuffer.length < ssh->outputBuffer.idx) {
            WLOG(WS_LOG_ERROR, "Bad buffer state");
            return WS_BUFFER_E;
        }

       sent = ssh->ctx->ioSendCb(ssh,
                               ssh->outputBuffer.buffer + ssh->outputBuffer.idx,
                               ssh->outputBuffer.length - ssh->outputBuffer.idx,
                               ssh->ioWriteCtx);

        if (sent < 0) {
            switch (sent) {
                case WS_CBIO_ERR_WANT_WRITE:     /* want write, would block */
                    ssh->error = WS_WANT_WRITE;
                    return WS_WANT_WRITE;

                case WS_CBIO_ERR_CONN_RST:       /* connection reset */
                    ssh->connReset = 1;
                    break;

                case WS_CBIO_ERR_CONN_CLOSE:     /* peer closed connection */
                    ssh->isClosed = 1;
                    break;

                case WS_CBIO_ERR_GENERAL:
                    ShrinkBuffer(&ssh->outputBuffer, 1);
            }
            return WS_SOCKET_ERROR_E;
        }

        if ((word32)sent > ssh->outputBuffer.length) {
            WLOG(WS_LOG_DEBUG, "wolfSSH_SendPacket() out of bounds read");
            return WS_SEND_OOB_READ_E;
        }

        ssh->outputBuffer.idx += sent;
    }

    ssh->outputBuffer.plainSz = 0;

    WLOG(WS_LOG_DEBUG, "SB: Shrinking output buffer");
    ShrinkBuffer(&ssh->outputBuffer, 0);
    return HighwaterCheck(ssh, WOLFSSH_HWSIDE_TRANSMIT);
}


static int GetInputData(WOLFSSH* ssh, word32 size)
{
    int in;

    /* Take into account the data already in the buffer. Update size
     * for what is missing in the request. */
    word32 haveDataSz;

    /* reset want read state before attempting to read */
    if (ssh->error == WS_WANT_READ) {
        ssh->error = 0;
    }

    haveDataSz = ssh->inputBuffer.length - ssh->inputBuffer.idx;
    if (haveDataSz >= size) {
        WLOG(WS_LOG_INFO, "GID: have enough already, return early");
        return WS_SUCCESS;
    }
    else {
        WLOG(WS_LOG_INFO, "GID: readjust size");
        size -= haveDataSz;
    }

    if (GrowBuffer(&ssh->inputBuffer, size) < 0) {
        ssh->error = WS_MEMORY_E;
        return WS_FATAL_ERROR;
    }

    /* read data from network */
    do {
        in = ReceiveData(ssh,
                     ssh->inputBuffer.buffer + ssh->inputBuffer.length,
                     size);
        if (in == -1) {
            ssh->error = WS_SOCKET_ERROR_E;
            return WS_FATAL_ERROR;
        }

        if (in == WS_WANT_READ) {
            ssh->error = WS_WANT_READ;
            return WS_FATAL_ERROR;
        }

        if (in >= 0) {
            ssh->inputBuffer.length += in;
            size -= in;
        }
        else {
            /* all other unexpected negative values is a failure case */
            ssh->error = WS_SOCKET_ERROR_E;
            return WS_FATAL_ERROR;
        }

    } while (size);

    return WS_SUCCESS;
}


int GetBoolean(byte* v, const byte* buf, word32 len, word32* idx)
{
    int result = WS_BUFFER_E;

    if (*idx < len) {
        *v = buf[*idx];
        *idx += BOOLEAN_SZ;
        result = WS_SUCCESS;
    }

    return result;
}


int GetUint32(word32* v, const byte* buf, word32 len, word32* idx)
{
    int result = WS_BUFFER_E;

    if (*idx < len && UINT32_SZ <= len - *idx) {
        ato32(buf + *idx, v);
        *idx += UINT32_SZ;
        result = WS_SUCCESS;
    }

    return result;
}


int GetSize(word32* v, const byte* buf, word32 len, word32* idx)
{
    int result;

    result = GetUint32(v, buf, len, idx);
    if (result == WS_SUCCESS) {
        if (*v > len - *idx) {
            result = WS_BUFFER_E;
        }
    }

    return result;
}


int GetSkip(const byte* buf, word32 len, word32* idx)
{
    int result;
    word32 sz;

    result = GetUint32(&sz, buf, len, idx);

    if (result == WS_SUCCESS) {
        result = WS_BUFFER_E;

        if (*idx < len && sz <= len - *idx) {
            *idx += sz;
            result = WS_SUCCESS;
        }
    }

    return result;
}


/* Gets the size of the mpint, and puts the pointer to the start of
 * buf's number into *mpint. This function does not copy. */
int GetMpint(word32* mpintSz, const byte** mpint,
        const byte* buf, word32 len, word32* idx)
{
    int result;

    result = GetUint32(mpintSz, buf, len, idx);

    if (result == WS_SUCCESS) {
        result = WS_BUFFER_E;

        if (*idx < len && *mpintSz <= len - *idx) {
            *mpint = buf + *idx;
            *idx += *mpintSz;
            result = WS_SUCCESS;
        }
    }

    return result;
}


/* Gets the size of a string, copies it as much of it as will fit in
 * the provided buffer, and terminates it with a NULL. */
int GetString(char* s, word32* sSz, const byte* buf, word32 len, word32 *idx)
{
    int result;
    word32 strSz;

    result = GetUint32(&strSz, buf, len, idx);

    if (result == WS_SUCCESS) {
        result = WS_BUFFER_E;

        /* This allows 0 length string to be decoded */
        if (*idx <= len && strSz <= len - *idx) {
            *sSz = (strSz >= *sSz) ? *sSz - 1 : strSz; /* -1 for null char */
            WMEMCPY(s, buf + *idx, *sSz);
            *idx += strSz;
            s[*sSz] = 0;
            result = WS_SUCCESS;
        }
    }

    return result;
}


/* Gets the size of a string, allocates memory to hold it plus a NULL, then
 * copies it into the allocated buffer, and terminates it with a NULL. */
int GetStringAlloc(void* heap, char** s, const byte* buf, word32 len, word32 *idx)
{
    int result;
    char* str;
    word32 strSz;

    result = GetUint32(&strSz, buf, len, idx);

    if (result == WS_SUCCESS) {
        if (*idx >= len || strSz > len - *idx)
            return WS_BUFFER_E;
        str = (char*)WMALLOC(strSz + 1, heap, DYNTYPE_STRING);
        if (str == NULL)
            return WS_MEMORY_E;
        WMEMCPY(str, buf + *idx, strSz);
        *idx += strSz;
        str[strSz] = '\0';

        if (*s != NULL)
            WFREE(*s, heap, DYNTYPE_STRING);
        *s = str;
    }

    return result;
}


/* Gets the size of the string, and puts the pointer to the start of
 * buf's string into *str. This function does not copy. */
int GetStringRef(word32* strSz, const byte** str,
        const byte* buf, word32 len, word32* idx)
{
    int result;

    result = GetUint32(strSz, buf, len, idx);

    if (result == WS_SUCCESS) {
        result = WS_BUFFER_E;

        if (*idx < len && *strSz <= len - *idx) {
            *str = buf + *idx;
            *idx += *strSz;
            result = WS_SUCCESS;
        }
    }

    return result;
}


static word32 CountNameList(const byte* buf, word32 len)
{
    word32 count = 0;

    if (buf != NULL && len > 0) {
        word32 i;

        count = 1;
        for (i = 0; i < len; i++) {
            if (buf[i] == ',') {
                count++;
            }
        }
        /* remove leading comma */
        if (count > 0 && buf[0] == ',') {
            count--;
        }
        /* remove trailing comma */
        if (count > 0 && buf[len-1] == ',') {
            count--;
        }
    }

    return count;
}


static int GetNameListRaw(byte* idList, word32* idListSz,
        const byte* nameList, word32 nameListSz)
{
    const byte* name = nameList;
    word32 nameSz = 0, nameListIdx = 0, idListIdx = 0;
    int ret = WS_SUCCESS;

    /*
     * The strings we want are now in the bounds of the message, and the
     * length of the list. Find the commas, or end of list, and then decode
     * the values.
     */

    while (nameListIdx < nameListSz) {
        nameListIdx++;

        if (nameListIdx == nameListSz)
            nameSz++;

        if (nameListIdx == nameListSz || name[nameSz] == ',') {
            byte id;

            id = NameToId((char*)name, nameSz);
            {
                const char* displayName = IdToName(id);
                if (displayName) {
                    WLOG(WS_LOG_DEBUG, "GNL: name ID = %s", displayName);
                }
            }
            if (id != ID_UNKNOWN || idListIdx == 0) {
                /* Intentionally save the first one if unknown. This helps
                 * skipping the KexDhInit if the client sends the wrong one
                 * as a guess. */
                if (idListIdx >= *idListSz) {
                    WLOG(WS_LOG_ERROR, "No more space left for names");
                    return WS_BUFFER_E;
                }
                idList[idListIdx++] = id;
            }

            name += 1 + nameSz;
            nameSz = 0;
        }
        else
            nameSz++;
    }

    *idListSz = idListIdx;

    return ret;
}


static int GetNameList(byte* idList, word32* idListSz,
                       const byte* buf, word32 len, word32* idx)
{
    const byte* nameList;
    word32 nameListSz;
    int ret = WS_SUCCESS;

    WLOG(WS_LOG_DEBUG, "Entering GetNameList()");

    if (idList == NULL || idListSz == NULL ||
        buf == NULL || len == 0 || idx == NULL) {

        ret = WS_BAD_ARGUMENT;
    }

    /*
     * This iterates across a name list and finds names that end in either the
     * comma delimeter or with the end of the list.
     */

    if (ret == WS_SUCCESS) {
        if (*idx >= len || *idx + 4 >= len)
            ret = WS_BUFFER_E;
    }

    if (ret == WS_SUCCESS) {
        ret = GetStringRef(&nameListSz, &nameList, buf, len, idx);
    }

    if (ret == WS_SUCCESS) {
        ret = GetNameListRaw(idList, idListSz, nameList, nameListSz);
    }

    WLOG(WS_LOG_DEBUG, "Leaving GetNameList(), ret = %d", ret);
    return ret;
}

static const byte  cannedKeyAlgoClient[] = {
#ifdef WOLFSSH_CERTS
    #ifndef WOLFSSH_NO_ECDSA_SHA2_NISTP521
        ID_X509V3_ECDSA_SHA2_NISTP521,
    #endif
    #ifndef WOLFSSH_NO_ECDSA_SHA2_NISTP384
        ID_X509V3_ECDSA_SHA2_NISTP384,
    #endif
    #ifndef WOLFSSH_NO_ECDSA_SHA2_NISTP256
        ID_X509V3_ECDSA_SHA2_NISTP256,
    #endif
    #ifdef WOLFSSH_NO_SHA1_SOFT_DISABLE
        #ifndef WOLFSSH_NO_SSH_RSA_SHA1
            ID_X509V3_SSH_RSA,
        #endif /* WOLFSSH_NO_SSH_RSA_SHA1 */
    #endif /* WOLFSSH_NO_SHA1_SOFT_DISABLE */
#endif /* WOLFSSH_CERTS */
#ifndef WOLFSSH_NO_ECDSA_SHA2_NISTP521
    ID_ECDSA_SHA2_NISTP521,
#endif
#ifndef WOLFSSH_NO_ECDSA_SHA2_NISTP384
    ID_ECDSA_SHA2_NISTP384,
#endif
#ifndef WOLFSSH_NO_ECDSA_SHA2_NISTP256
    ID_ECDSA_SHA2_NISTP256,
#endif
#ifndef WOLFSSH_NO_RSA_SHA2_512
    ID_RSA_SHA2_512,
#endif
#ifndef WOLFSSH_NO_RSA_SHA2_256
    ID_RSA_SHA2_256,
#endif
#ifdef WOLFSSH_NO_SHA1_SOFT_DISABLE
    #ifndef WOLFSSH_NO_SSH_RSA_SHA1
        ID_SSH_RSA,
    #endif /* WOLFSSH_NO_SSH_RSA_SHA1 */
#endif /* WOLFSSH_NO_SHA1_SOFT_DISABLE */
#ifndef WOLFSSH_NO_ED25519
    ID_ED25519,
#endif
};

static const word32 cannedKeyAlgoClientSz = (word32)sizeof(cannedKeyAlgoClient);


static byte MatchIdLists(int side, const byte* left, word32 leftSz,
                         const byte* right, word32 rightSz)
{
    word32 i, j;

    /* When matching on the client, swap left and right. Left should be
     * the client's list and right should be the server's list. */
    if (side == WOLFSSH_ENDPOINT_CLIENT) {
        const byte* swap = left;
        word32 swapSz = leftSz;

        left = right;
        right = swap;
        leftSz = rightSz;
        rightSz = swapSz;
    }

    if (left != NULL && leftSz > 0 && right != NULL && rightSz > 0) {
        for (i = 0; i < leftSz; i++) {
            for (j = 0; j < rightSz; j++) {
                if (left[i] == right[j]) {
#if 0
                    WLOG(WS_LOG_DEBUG, "MID: matched %s", IdToName(left[i]));
#endif
                    return left[i];
                }
            }
        }
    }

    return ID_UNKNOWN;
}


static INLINE byte BlockSzForId(byte id)
{
    switch (id) {
#ifndef WOLFSSH_NO_AES_CBC
        case ID_AES128_CBC:
        case ID_AES192_CBC:
        case ID_AES256_CBC:
            return AES_BLOCK_SIZE;
#endif
#ifndef WOLFSSH_NO_AES_CTR
        case ID_AES128_CTR:
        case ID_AES192_CTR:
        case ID_AES256_CTR:
            return AES_BLOCK_SIZE;
#endif
#ifndef WOLFSSH_NO_AES_GCM
        case ID_AES128_GCM:
        case ID_AES192_GCM:
        case ID_AES256_GCM:
            return AES_BLOCK_SIZE;
#endif
        default:
            return 0;
    }
}


static INLINE byte MacSzForId(byte id)
{
    switch (id) {
#ifndef WOLFSSH_NO_HMAC_SHA1
        case ID_HMAC_SHA1:
            return WC_SHA_DIGEST_SIZE;
#endif
#ifndef WOLFSSH_NO_HMAC_SHA1_96
        case ID_HMAC_SHA1_96:
            return SHA1_96_SZ;
#endif
#ifndef WOLFSSH_NO_HMAC_SHA2_256
        case ID_HMAC_SHA2_256:
            return WC_SHA256_DIGEST_SIZE;
#endif
        default:
            return 0;
    }
}


static INLINE byte KeySzForId(byte id)
{
    switch (id) {
#ifndef WOLFSSH_NO_HMAC_SHA1
        case ID_HMAC_SHA1:
            return WC_SHA_DIGEST_SIZE;
#endif
#ifndef WOLFSSH_NO_HMAC_SHA1_96
        case ID_HMAC_SHA1_96:
            return WC_SHA_DIGEST_SIZE;
#endif
#ifndef WOLFSSH_NO_HMAC_SHA2_256
        case ID_HMAC_SHA2_256:
            return WC_SHA256_DIGEST_SIZE;
#endif
#ifndef WOLFSSH_NO_AES_CBC
        case ID_AES128_CBC:
            return AES_128_KEY_SIZE;
        case ID_AES192_CBC:
            return AES_192_KEY_SIZE;
        case ID_AES256_CBC:
            return AES_256_KEY_SIZE;
#endif
#ifndef WOLFSSH_NO_AES_CTR
        case ID_AES128_CTR:
            return AES_128_KEY_SIZE;
        case ID_AES192_CTR:
            return AES_192_KEY_SIZE;
        case ID_AES256_CTR:
            return AES_256_KEY_SIZE;
#endif
#ifndef WOLFSSH_NO_AES_GCM
        case ID_AES128_GCM:
            return AES_128_KEY_SIZE;
        case ID_AES192_GCM:
            return AES_192_KEY_SIZE;
        case ID_AES256_GCM:
            return AES_256_KEY_SIZE;
#endif
        default:
            return 0;
    }
}

enum wc_HashType HashForId(byte id)
{
    switch (id) {

        /* SHA1 */
#ifndef WOLFSSH_NO_DH_GROUP1_SHA1
        case ID_DH_GROUP1_SHA1:
            return WC_HASH_TYPE_SHA;
#endif
#ifndef WOLFSSH_NO_DH_GROUP14_SHA1
        case ID_DH_GROUP14_SHA1:
            return WC_HASH_TYPE_SHA;
#endif
#ifndef WOLFSSH_NO_SSH_RSA_SHA1
        case ID_SSH_RSA:
    #ifdef WOLFSSH_CERTS
        case ID_X509V3_SSH_RSA:
    #endif
            return WC_HASH_TYPE_SHA;
#endif

        /* SHA2-256 */
#ifndef WOLFSSH_NO_DH_GROUP14_SHA256
        case ID_DH_GROUP14_SHA256:
            return WC_HASH_TYPE_SHA256;
#endif
#ifndef WOLFSSH_NO_DH_GEX_SHA256
        case ID_DH_GEX_SHA256:
            return WC_HASH_TYPE_SHA256;
#endif
#ifndef WOLFSSH_NO_ECDH_SHA2_NISTP256
        case ID_ECDH_SHA2_NISTP256:
            return WC_HASH_TYPE_SHA256;
#endif
#ifndef WOLFSSH_NO_ECDSA_SHA2_NISTP256
        case ID_ECDSA_SHA2_NISTP256:
    #ifdef WOLFSSH_CERTS
        case ID_X509V3_ECDSA_SHA2_NISTP256:
    #endif
            return WC_HASH_TYPE_SHA256;
#endif
#ifndef WOLFSSH_NO_ECDH_NISTP256_KYBER_LEVEL1_SHA256
        case ID_ECDH_NISTP256_KYBER_LEVEL1_SHA256:
            return WC_HASH_TYPE_SHA256;
#endif
#ifndef WOLFSSH_NO_CURVE25519_SHA256
        case ID_CURVE25519_SHA256:
            return WC_HASH_TYPE_SHA256;
#endif
#ifndef WOLFSSH_NO_RSA_SHA2_256
        case ID_RSA_SHA2_256:
            return WC_HASH_TYPE_SHA256;
#endif

#ifndef WOLFSSH_NO_ED25519
        case ID_ED25519:
            return WC_HASH_TYPE_SHA512;
#endif
        /* SHA2-384 */
#ifndef WOLFSSH_NO_ECDH_SHA2_NISTP384
        case ID_ECDH_SHA2_NISTP384:
            return WC_HASH_TYPE_SHA384;
#endif
#ifndef WOLFSSH_NO_ECDSA_SHA2_NISTP384
        case ID_ECDSA_SHA2_NISTP384:
    #ifdef WOLFSSH_CERTS
        case ID_X509V3_ECDSA_SHA2_NISTP384:
    #endif
            return WC_HASH_TYPE_SHA384;
#endif

        /* SHA2-512 */
#ifndef WOLFSSH_NO_ECDH_SHA2_NISTP521
        case ID_ECDH_SHA2_NISTP521:
            return WC_HASH_TYPE_SHA512;
#endif
#ifndef WOLFSSH_NO_ECDSA_SHA2_NISTP521
        case ID_ECDSA_SHA2_NISTP521:
    #ifdef WOLFSSH_CERTS
        case ID_X509V3_ECDSA_SHA2_NISTP521:
    #endif
            return WC_HASH_TYPE_SHA512;
#endif
#ifndef WOLFSSH_NO_RSA_SHA2_512
        case ID_RSA_SHA2_512:
            return WC_HASH_TYPE_SHA512;
#endif

        default:
            return WC_HASH_TYPE_NONE;
    }
}


#if !defined(WOLFSSH_NO_ECDSA) || !defined(WOLFSSH_NO_ECDH)
int wcPrimeForId(byte id)
{
    switch (id) {
#ifndef WOLFSSH_NO_ECDH_NISTP256_KYBER_LEVEL1_SHA256
        case ID_ECDH_NISTP256_KYBER_LEVEL1_SHA256:
            return ECC_SECP256R1;
#endif
#ifndef WOLFSSH_NO_ECDH_SHA2_NISTP256
        case ID_ECDH_SHA2_NISTP256:
            return ECC_SECP256R1;
#endif
#ifndef WOLFSSH_NO_ECDSA_SHA2_NISTP256
        case ID_ECDSA_SHA2_NISTP256:
            return ECC_SECP256R1;
#endif
#ifndef WOLFSSH_NO_ECDH_SHA2_NISTP384
        case ID_ECDH_SHA2_NISTP384:
            return ECC_SECP384R1;
#endif
#ifndef WOLFSSH_NO_ECDSA_SHA2_NISTP384
        case ID_ECDSA_SHA2_NISTP384:
            return ECC_SECP384R1;
#endif
#ifndef WOLFSSH_NO_CURVE25519_SHA256
        case ID_CURVE25519_SHA256:
            return ECC_X25519;
#endif
#ifndef WOLFSSH_NO_ECDH_SHA2_NISTP521
        case ID_ECDH_SHA2_NISTP521:
            return ECC_SECP521R1;
#endif
#ifndef WOLFSSH_NO_ECDSA_SHA2_NISTP521
        case ID_ECDSA_SHA2_NISTP521:
            return ECC_SECP521R1;
#endif
        default:
            return ECC_CURVE_INVALID;
    }
}

static INLINE const char *PrimeNameForId(byte id)
{
    switch (id) {
#ifndef WOLFSSH_NO_ECDSA_SHA2_NISTP256
        case ID_ECDSA_SHA2_NISTP256:
            return "nistp256";
#endif
#ifndef WOLFSSH_NO_ECDSA_SHA2_NISTP384
        case ID_ECDSA_SHA2_NISTP384:
            return "nistp384";
#endif
#ifndef WOLFSSH_NO_ECDSA_SHA2_NISTP521
        case ID_ECDSA_SHA2_NISTP521:
            return "nistp521";
#endif
#ifndef WOLFSSH_NO_ED25519
        case ID_ED25519:
            return "ed25519";
#endif
        default:
            return "unknown";
    }
}
#endif /* WOLFSSH_NO_ECDSA */


static INLINE byte AeadModeForId(byte id)
{
    switch (id) {
#ifndef WOLFSSH_NO_AES_GCM
        case ID_AES128_GCM:
        case ID_AES192_GCM:
        case ID_AES256_GCM:
            return 1;
#endif
        default:
            return 0;
    }
}


static word32 AlgoListSz(const char* algoList)
{
    word32 algoListSz;

    algoListSz = (word32)WSTRLEN(algoList);
    if (algoList[algoListSz-1] == ',') {
        --algoListSz;
    }

    return algoListSz;
}


static int DoKexInit(WOLFSSH* ssh, byte* buf, word32 len, word32* idx)
{
    int ret = WS_SUCCESS;
    int side = WOLFSSH_ENDPOINT_SERVER;
    byte algoId;
    byte list[24] = {ID_NONE};
    byte cannedList[24] = {ID_NONE};
    word32 listSz;
    word32 cannedListSz;
    word32 cannedAlgoNamesSz;
    word32 skipSz = 0;
    word32 begin;

    WLOG(WS_LOG_DEBUG, "Entering DoKexInit()");

    if (ssh == NULL || ssh->ctx == NULL ||
            buf == NULL || len == 0 || idx == NULL) {

        ret = WS_BAD_ARGUMENT;
    }

    /*
     * I don't need to save what the client sends here. I should decode
     * each list into a local array of IDs, and pick the one the peer is
     * using that's on my known list, or verify that the one the peer can
     * support the other direction is on my known list. All I need to do
     * is save the actual values.
     */

    if (ret == WS_SUCCESS) {
        if (ssh->handshake == NULL) {
            ssh->handshake = HandshakeInfoNew(ssh->ctx->heap);
            if (ssh->handshake == NULL) {
                WLOG(WS_LOG_DEBUG, "Couldn't allocate handshake info");
                ret = WS_MEMORY_E;
            }
        }
    }

    if (ret == WS_SUCCESS) {
        begin = *idx;
        side = ssh->ctx->side;

        /* Check that the cookie exists inside the message */
        if (begin + COOKIE_SZ > len) {
            /* error, out of bounds */
            ret = WS_PARSE_E;
        }
        else {
            /* Move past the cookie. */
            begin += COOKIE_SZ;
        }
    }

    /* KEX Algorithms */
    if (ret == WS_SUCCESS) {
        WLOG(WS_LOG_DEBUG, "DKI: KEX Algorithms");
        listSz = (word32)sizeof(list);
        ret = GetNameList(list, &listSz, buf, len, &begin);
    }
    if (ret == WS_SUCCESS) {
        cannedAlgoNamesSz = AlgoListSz(ssh->algoListKex);
        cannedListSz = (word32)sizeof(cannedList);
        ret = GetNameListRaw(cannedList, &cannedListSz,
                (const byte*)ssh->algoListKex, cannedAlgoNamesSz);
    }
    if (ret == WS_SUCCESS) {
        ssh->handshake->kexIdGuess = list[0];
        algoId = MatchIdLists(side, list, listSz,
                cannedList, cannedListSz);
        if (algoId == ID_UNKNOWN) {
            WLOG(WS_LOG_DEBUG, "Unable to negotiate KEX Algo");
            ret = WS_MATCH_KEX_ALGO_E;
        }
    }
    if (ret == WS_SUCCESS) {
        ssh->kexId = ssh->handshake->kexId = algoId;
        ssh->handshake->kexHashId = HashForId(algoId);
    }
    /* Extension Info Flag */
    if (ret == WS_SUCCESS) {
        /* Only checking for this is we are server. Our client does
         * not have anything to say to a server, yet. */
        if (side == WOLFSSH_ENDPOINT_SERVER) {
            byte extInfo;

            /* Match the client accepts extInfo. */
            algoId = ID_EXTINFO_C;
            extInfo = MatchIdLists(side, list, listSz, &algoId, 1);
            ssh->sendExtInfo = extInfo == algoId;
        }
    }

    /* Server Host Key Algorithms */
    if (ret == WS_SUCCESS) {
        WLOG(WS_LOG_DEBUG, "DKI: Server Host Key Algorithms");
        listSz = (word32)sizeof(list);
        ret = GetNameList(list, &listSz, buf, len, &begin);
    }
    if (ret == WS_SUCCESS) {
        if (side == WOLFSSH_ENDPOINT_SERVER && !ssh->algoListKey) {
            cannedListSz = ssh->ctx->publicKeyAlgoCount;
            WMEMCPY(cannedList, ssh->ctx->publicKeyAlgo, cannedListSz);
        }
        else {
            cannedAlgoNamesSz = AlgoListSz(ssh->algoListKey);
            cannedListSz = (word32)sizeof(cannedList);
            ret = GetNameListRaw(cannedList, &cannedListSz,
                    (const byte*)ssh->algoListKey, cannedAlgoNamesSz);
        }
    }
    if (ret == WS_SUCCESS) {
        algoId = MatchIdLists(side, list, listSz, cannedList, cannedListSz);
        if (algoId == ID_UNKNOWN) {
            WLOG(WS_LOG_DEBUG, "Unable to negotiate Server Host Key Algo");
            return WS_MATCH_KEY_ALGO_E;
        }
        else {
            ssh->handshake->pubKeyId = algoId;
        }
    }

    /* Enc Algorithms - Client to Server */
    if (ret == WS_SUCCESS) {
        WLOG(WS_LOG_DEBUG, "DKI: Enc Algorithms - Client to Server");
        listSz = (word32)sizeof(list);
        ret = GetNameList(list, &listSz, buf, len, &begin);
    }
    if (ret == WS_SUCCESS) {
        cannedAlgoNamesSz = AlgoListSz(ssh->algoListCipher);
        cannedListSz = (word32)sizeof(cannedList);
        ret = GetNameListRaw(cannedList, &cannedListSz,
                (const byte*)ssh->algoListCipher, cannedAlgoNamesSz);
    }
    if (ret == WS_SUCCESS) {
        algoId = MatchIdLists(side, list, listSz, cannedList, cannedListSz);
        if (algoId == ID_UNKNOWN) {
            WLOG(WS_LOG_DEBUG, "Unable to negotiate Encryption Algo C2S");
            ret = WS_MATCH_ENC_ALGO_E;
        }
    }

    /* Enc Algorithms - Server to Client */
    if (ret == WS_SUCCESS) {
        WLOG(WS_LOG_DEBUG, "DKI: Enc Algorithms - Server to Client");
        listSz = (word32)sizeof(list);
        ret = GetNameList(list, &listSz, buf, len, &begin);
    }
    if (ret == WS_SUCCESS) {
        algoId = MatchIdLists(side, list, listSz, &algoId, 1);
        if (algoId == ID_UNKNOWN) {
            WLOG(WS_LOG_DEBUG, "Unable to negotiate Encryption Algo S2C");
            ret = WS_MATCH_ENC_ALGO_E;
        }
    }
    if (ret == WS_SUCCESS) {
        ssh->handshake->encryptId = algoId;
        ssh->handshake->aeadMode = AeadModeForId(algoId);
        ssh->handshake->blockSz = BlockSzForId(algoId);
        ssh->handshake->keys.encKeySz =
            ssh->handshake->peerKeys.encKeySz =
            KeySzForId(algoId);
        if (!ssh->handshake->aeadMode) {
            ssh->handshake->keys.ivSz =
                ssh->handshake->peerKeys.ivSz =
                ssh->handshake->blockSz;
        }
        else {
#ifndef WOLFSSH_NO_AEAD
            ssh->handshake->keys.ivSz =
                ssh->handshake->peerKeys.ivSz =
                AEAD_NONCE_SZ;
            ssh->handshake->macSz = ssh->handshake->blockSz;
#endif
        }
    }

    /* MAC Algorithms - Client to Server */
    if (ret == WS_SUCCESS) {
        WLOG(WS_LOG_DEBUG, "DKI: MAC Algorithms - Client to Server");
        listSz = (word32)sizeof(list);
        ret = GetNameList(list, &listSz, buf, len, &begin);
    }
    if (ret == WS_SUCCESS && !ssh->handshake->aeadMode) {
        cannedAlgoNamesSz = AlgoListSz(ssh->algoListMac);
        cannedListSz = (word32)sizeof(cannedList);
        ret = GetNameListRaw(cannedList, &cannedListSz,
                (const byte*)ssh->algoListMac, cannedAlgoNamesSz);
        if (ret == WS_SUCCESS) {
            algoId = MatchIdLists(side, list, listSz,
                    cannedList, cannedListSz);
            if (algoId == ID_UNKNOWN) {
                WLOG(WS_LOG_DEBUG, "Unable to negotiate MAC Algo C2S");
                ret = WS_MATCH_MAC_ALGO_E;
            }
        }
    }

    /* MAC Algorithms - Server to Client */
    if (ret == WS_SUCCESS) {
        WLOG(WS_LOG_DEBUG, "DKI: MAC Algorithms - Server to Client");
        listSz = (word32)sizeof(list);
        ret = GetNameList(list, &listSz, buf, len, &begin);
    }
    if (ret == WS_SUCCESS && !ssh->handshake->aeadMode) {
        algoId = MatchIdLists(side, list, listSz, &algoId, 1);
        if (algoId == ID_UNKNOWN) {
            WLOG(WS_LOG_DEBUG, "Unable to negotiate MAC Algo S2C");
            ret = WS_MATCH_MAC_ALGO_E;
        }
        else {
            ssh->handshake->macId = algoId;
            ssh->handshake->macSz = MacSzForId(algoId);
            ssh->handshake->keys.macKeySz =
                ssh->handshake->peerKeys.macKeySz =
                KeySzForId(algoId);
        }
    }

    /* Compression Algorithms - Client to Server */
    if (ret == WS_SUCCESS) {
        /* The compression algorithm lists should have none as a value. */
        algoId = ID_NONE;

        WLOG(WS_LOG_DEBUG, "DKI: Compression Algorithms - Client to Server");
        listSz = (word32)sizeof(list);
        ret = GetNameList(list, &listSz, buf, len, &begin);
    }
    if (ret == WS_SUCCESS) {
        algoId = MatchIdLists(side, list, listSz, &algoId, 1);
        if (algoId == ID_UNKNOWN) {
            WLOG(WS_LOG_DEBUG, "Unable to negotiate Compression Algo C2S");
            ret = WS_INVALID_ALGO_ID;
        }
    }

    /* Compression Algorithms - Server to Client */
    if (ret == WS_SUCCESS) {
        WLOG(WS_LOG_DEBUG, "DKI: Compression Algorithms - Server to Client");
        listSz = (word32)sizeof(list);
        ret = GetNameList(list, &listSz, buf, len, &begin);
    }
    if (ret == WS_SUCCESS) {
        algoId = MatchIdLists(side, list, listSz, &algoId, 1);
        if (algoId == ID_UNKNOWN) {
            WLOG(WS_LOG_DEBUG, "Unable to negotiate Compression Algo S2C");
            ret = WS_INVALID_ALGO_ID;
        }
    }

    /* Languages - Client to Server, skip */
    if (ret == WS_SUCCESS) {
        WLOG(WS_LOG_DEBUG, "DKI: Languages - Client to Server");
        ret = GetUint32(&skipSz, buf, len, &begin);
        if (ret == WS_SUCCESS)
            begin += skipSz;
    }

    /* Languages - Server to Client, skip */
    if (ret == WS_SUCCESS) {
        WLOG(WS_LOG_DEBUG, "DKI: Languages - Server to Client");
        ret = GetUint32(&skipSz, buf, len, &begin);
        if (ret == WS_SUCCESS)
            begin += skipSz;
    }

    /* First KEX Packet Follows */
    if (ret == WS_SUCCESS) {
        WLOG(WS_LOG_DEBUG, "DKI: KEX Packet Follows");
        ret = GetBoolean(&ssh->handshake->kexPacketFollows, buf, len, &begin);
        if (ret == WS_SUCCESS) {
            WLOG(WS_LOG_DEBUG, " packet follows: %s",
                    ssh->handshake->kexPacketFollows ? "yes" : "no");
        }
    }

    /* Skip the "for future use" length. */
    if (ret == WS_SUCCESS) {
        WLOG(WS_LOG_DEBUG, "DKI: For Future Use");
        ret = GetUint32(&skipSz, buf, len, &begin);
        if (ret == WS_SUCCESS)
            begin += skipSz;
    }

    if (ret == WS_SUCCESS) {
        wc_HashAlg* hash = &ssh->handshake->kexHash;
        enum wc_HashType hashId = (enum wc_HashType)ssh->handshake->kexHashId;
        byte scratchLen[LENGTH_SZ];
        word32 strSz = 0;

        if (!ssh->isKeying) {
            WLOG(WS_LOG_DEBUG, "Keying initiated");
            ret = SendKexInit(ssh);
        }

        /* account for possible want write case from SendKexInit */
        if (ret == WS_SUCCESS || ret == WS_WANT_WRITE)
            ret = wc_HashInit(hash, hashId);

        if (ret == WS_SUCCESS) {
            if (ssh->ctx->side == WOLFSSH_ENDPOINT_SERVER) {
                ret = HashUpdate(hash, hashId,
                        ssh->peerProtoId, ssh->peerProtoIdSz);
            }
        }

        if (ret == WS_SUCCESS) {
            byte SSH_PROTO_EOL_SZ = 2;

            strSz = (word32)WSTRLEN(ssh->ctx->sshProtoIdStr) - SSH_PROTO_EOL_SZ;
            c32toa(strSz, scratchLen);
            ret = HashUpdate(hash, hashId, scratchLen, LENGTH_SZ);
        }

        if (ret == WS_SUCCESS) {
            ret = HashUpdate(hash, hashId,
                    (const byte*)ssh->ctx->sshProtoIdStr, strSz);
        }

        if (ret == WS_SUCCESS) {
            if (ssh->ctx->side == WOLFSSH_ENDPOINT_CLIENT) {
                ret = HashUpdate(hash, hashId,
                        ssh->peerProtoId, ssh->peerProtoIdSz);
                if (ret == WS_SUCCESS) {
                    ret = HashUpdate(hash, hashId,
                            ssh->handshake->kexInit, ssh->handshake->kexInitSz);
                }
            }
        }

        if (ret == WS_SUCCESS) {
            c32toa(len + 1, scratchLen);
            ret = HashUpdate(hash, hashId, scratchLen, LENGTH_SZ);
        }

        if (ret == WS_SUCCESS) {
            scratchLen[0] = MSGID_KEXINIT;
            ret = HashUpdate(hash, hashId, scratchLen, MSG_ID_SZ);
        }

        if (ret == WS_SUCCESS)
            ret = HashUpdate(hash, hashId, buf, len);

        if (ret == WS_SUCCESS) {
            if (ssh->ctx->side == WOLFSSH_ENDPOINT_SERVER)
                ret = HashUpdate(hash, hashId,
                        ssh->handshake->kexInit, ssh->handshake->kexInitSz);
        }

        if (ret == WS_SUCCESS) {
            *idx = begin;
            if (ssh->ctx->side == WOLFSSH_ENDPOINT_SERVER)
                ssh->clientState = CLIENT_KEXINIT_DONE;
            else
                ssh->serverState = SERVER_KEXINIT_DONE;

            /* Propagate potential want write case from SendKexInit. */
            if (ssh->error != 0)
                ret = ssh->error;
        }
    }
    WLOG(WS_LOG_DEBUG, "Leaving DoKexInit(), ret = %d", ret);
    return ret;
}


/* create mpint type
 *
 * can decrease size of buf by 1 or more if leading bytes are 0's and not needed
 * the input argument "sz" gets reset if that is the case. Buffer size is never
 * increased.
 *
 * An example of this would be a buffer of 0053 changed to 53.
 * If a padding value is needed then "pad" is set to 1
 *
 */
static int CreateMpint(byte* buf, word32* sz, byte* pad)
{
    word32 i;

    if (buf == NULL || sz == NULL || pad == NULL) {
        WLOG(WS_LOG_ERROR, "Internal argument error with CreateMpint");
        return WS_BAD_ARGUMENT;
    }

    if (*sz == 0)
        return WS_SUCCESS;

    /* check for leading 0's */
    for (i = 0; i < *sz; i++) {
        if (buf[i] != 0x00)
            break;
    }
    *pad = (buf[i] & 0x80) ? 1 : 0;

    /* if padding would be needed and have leading 0's already then do not add
     * extra 0's */
    if (i > 0 && *pad == 1) {
        i = i - 1;
        *pad = 0;
    }

    /* if i is still greater than 0 then the buffer needs shifted to remove
     * leading 0's */
    if (i > 0) {
        WMEMMOVE(buf, buf + i, *sz - i);
        *sz = *sz - i;
    }

    return WS_SUCCESS;
}


#if !defined(WOLFSSH_NO_DH_GROUP1_SHA1) || \
    !defined(WOLFSSH_NO_DH_GROUP14_SHA1) || \
    !defined(WOLFSSH_NO_DH_GEX_SHA256)
static const byte dhGenerator[] = { 2 };
static const word32 dhGeneratorSz = (word32)sizeof(dhGenerator);
#endif

#ifndef WOLFSSH_NO_DH_GROUP1_SHA1
static const byte dhPrimeGroup1[] = {
    /* SSH DH Group 1 (Oakley Group 2, 1024-bit MODP Group, RFC 2409) */
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
    0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
    0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74,
    0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22,
    0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
    0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B,
    0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37,
    0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
    0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6,
    0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B,
    0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
    0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5,
    0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6,
    0x49, 0x28, 0x66, 0x51, 0xEC, 0xE6, 0x53, 0x81,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};
static const word32 dhPrimeGroup1Sz = (word32)sizeof(dhPrimeGroup1);
#endif

#if !defined(WOLFSSH_NO_DH_GROUP14_SHA1) || \
    !defined(WOLFSSH_NO_DH_GROUP14_SHA256) || \
    !defined(WOLFSSH_NO_DH_GEX_SHA256)
static const byte dhPrimeGroup14[] = {
    /* SSH DH Group 14 (Oakley Group 14, 2048-bit MODP Group, RFC 3526) */
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
    0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
    0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74,
    0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22,
    0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
    0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B,
    0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37,
    0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
    0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6,
    0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B,
    0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
    0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5,
    0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6,
    0x49, 0x28, 0x66, 0x51, 0xEC, 0xE4, 0x5B, 0x3D,
    0xC2, 0x00, 0x7C, 0xB8, 0xA1, 0x63, 0xBF, 0x05,
    0x98, 0xDA, 0x48, 0x36, 0x1C, 0x55, 0xD3, 0x9A,
    0x69, 0x16, 0x3F, 0xA8, 0xFD, 0x24, 0xCF, 0x5F,
    0x83, 0x65, 0x5D, 0x23, 0xDC, 0xA3, 0xAD, 0x96,
    0x1C, 0x62, 0xF3, 0x56, 0x20, 0x85, 0x52, 0xBB,
    0x9E, 0xD5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6D,
    0x67, 0x0C, 0x35, 0x4E, 0x4A, 0xBC, 0x98, 0x04,
    0xF1, 0x74, 0x6C, 0x08, 0xCA, 0x18, 0x21, 0x7C,
    0x32, 0x90, 0x5E, 0x46, 0x2E, 0x36, 0xCE, 0x3B,
    0xE3, 0x9E, 0x77, 0x2C, 0x18, 0x0E, 0x86, 0x03,
    0x9B, 0x27, 0x83, 0xA2, 0xEC, 0x07, 0xA2, 0x8F,
    0xB5, 0xC5, 0x5D, 0xF0, 0x6F, 0x4C, 0x52, 0xC9,
    0xDE, 0x2B, 0xCB, 0xF6, 0x95, 0x58, 0x17, 0x18,
    0x39, 0x95, 0x49, 0x7C, 0xEA, 0x95, 0x6A, 0xE5,
    0x15, 0xD2, 0x26, 0x18, 0x98, 0xFA, 0x05, 0x10,
    0x15, 0x72, 0x8E, 0x5A, 0x8A, 0xAC, 0xAA, 0x68,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};
static const word32 dhPrimeGroup14Sz = (word32)sizeof(dhPrimeGroup14);
#endif


static int DoKexDhInit(WOLFSSH* ssh, byte* buf, word32 len, word32* idx)
{
    /* First get the length of the MP_INT, and then add in the hash of the
     * mp_int value of e as it appears in the packet. After that, decode e
     * into an mp_int struct for the DH calculation by wolfCrypt.
     *
     * This function also works as MSGID_KEXECDH_INIT (30). That message
     * has the same format as MSGID_KEXDH_INIT, except it is the ECDH Q value
     * in the message isn't of the DH e value. Treat the Q as e. */
    /* DYNTYPE_DH */

    byte* e;
    word32 eSz;
    word32 begin;
    int ret = WS_SUCCESS;

    if (ssh == NULL || ssh->handshake == NULL || buf == NULL || len == 0 ||
            idx == NULL)
        ret = WS_BAD_ARGUMENT;

    if (ret == WS_SUCCESS) {
        if (ssh->handshake->kexPacketFollows
                && ssh->handshake->kexIdGuess != ssh->handshake->kexId) {

            /* skip this message. */
            WLOG(WS_LOG_DEBUG, "Skipping the client's KEX init function.");
            ssh->handshake->kexPacketFollows = 0;
            *idx += len;
            return WS_SUCCESS;
        }
    }

    if (ret == WS_SUCCESS) {
        begin = *idx;
        ret = GetUint32(&eSz, buf, len, &begin);
    }

    if (ret == WS_SUCCESS) {
        /* Validate eSz */
        if ((len < begin) || (eSz > len - begin)) {
            ret = WS_RECV_OVERFLOW_E;
        }
    }

    if (ret == WS_SUCCESS) {
        e = buf + begin;
        begin += eSz;

        if (eSz <= (word32)sizeof(ssh->handshake->e)) {
            WMEMCPY(ssh->handshake->e, e, eSz);
            ssh->handshake->eSz = eSz;
        }

        ssh->clientState = CLIENT_KEXDH_INIT_DONE;
        *idx = begin;

        ret = SendKexDhReply(ssh);
    }

    return ret;
}


struct wolfSSH_sigKeyBlock {
    byte useRsa:1;
    byte useEcc:1;
    byte useEd25519:1;
    byte keyAllocated:1;
    word32 keySz;
    union {
#ifndef WOLFSSH_NO_RSA
        struct {
            RsaKey   key;
        } rsa;
#endif
#ifndef WOLFSSH_NO_ECDSA
        struct {
            ecc_key key;
        } ecc;
#endif
#ifndef WOLFSSH_NO_ED25519
        struct {
            ed25519_key key;
        } ed25519;
#endif
    } sk;
};


/* Parse out a RAW RSA public key from buffer */
static int ParseRSAPubKey(WOLFSSH *ssh,
    struct wolfSSH_sigKeyBlock *sigKeyBlock_ptr, byte *pubKey, word32 pubKeySz)
{
    int ret;
#ifndef WOLFSSH_NO_RSA
    byte* e = NULL;
    word32 eSz;
    byte* n;
    word32 nSz;
    word32 pubKeyIdx = 0;
    word32 scratch;

    ret = wc_InitRsaKey(&sigKeyBlock_ptr->sk.rsa.key, ssh->ctx->heap);
    if (ret != 0)
        ret = WS_RSA_E;
    if (ret == 0)
        ret = GetUint32(&scratch, pubKey, pubKeySz, &pubKeyIdx);
    /* This is the algo name. */
    if (ret == WS_SUCCESS) {
        pubKeyIdx += scratch;
        ret = GetUint32(&eSz, pubKey, pubKeySz, &pubKeyIdx);
        if (ret == WS_SUCCESS && eSz > pubKeySz - pubKeyIdx)
            ret = WS_BUFFER_E;
    }
    if (ret == WS_SUCCESS) {
        e = pubKey + pubKeyIdx;
        pubKeyIdx += eSz;
        ret = GetUint32(&nSz, pubKey, pubKeySz, &pubKeyIdx);
        if (ret == WS_SUCCESS && nSz > pubKeySz - pubKeyIdx)
            ret = WS_BUFFER_E;
    }
    if (ret == WS_SUCCESS) {
        n = pubKey + pubKeyIdx;
        ret = wc_RsaPublicKeyDecodeRaw(n, nSz, e, eSz,
                                       &sigKeyBlock_ptr->sk.rsa.key);
    }

    if (ret == 0) {
        sigKeyBlock_ptr->keySz = (word32)sizeof(sigKeyBlock_ptr->sk.rsa.key);
        sigKeyBlock_ptr->keyAllocated = 1;
    }
    else
        ret = WS_RSA_E;
#else
    WOLFSSH_UNUSED(ssh);
    WOLFSSH_UNUSED(sigKeyBlock_ptr);
    WOLFSSH_UNUSED(pubKey);
    WOLFSSH_UNUSED(pubKeySz);
    ret = WS_INVALID_ALGO_ID;
#endif
    return ret;
}

/* Parse out a RAW ECC public key from buffer */
static int ParseECCPubKey(WOLFSSH *ssh,
    struct wolfSSH_sigKeyBlock *sigKeyBlock_ptr, byte *pubKey, word32 pubKeySz)
{
    int ret;
#ifndef WOLFSSH_NO_ECDSA
    const byte* q;
    word32 qSz, pubKeyIdx = 0;
    int primeId = 0;
    word32 scratch;

    ret = wc_ecc_init_ex(&sigKeyBlock_ptr->sk.ecc.key, ssh->ctx->heap,
                                 INVALID_DEVID);
#ifdef HAVE_WC_ECC_SET_RNG
    if (ret == 0)
        ret = wc_ecc_set_rng(&sigKeyBlock_ptr->sk.ecc.key, ssh->rng);
#endif
    if (ret != 0)
        ret = WS_ECC_E;
    else
        ret = GetStringRef(&qSz, &q, pubKey, pubKeySz, &pubKeyIdx);

    if (ret == WS_SUCCESS) {
        primeId = (int)NameToId((const char*)q, qSz);
        if (primeId != ID_UNKNOWN) {
            primeId = wcPrimeForId((byte)primeId);
            if (primeId == ECC_CURVE_INVALID)
                ret = WS_INVALID_PRIME_CURVE;
        }
        else
            ret = WS_INVALID_ALGO_ID;
    }

    /* Skip the curve name since we're getting it from the algo. */
    if (ret == WS_SUCCESS)
        ret = GetUint32(&scratch, pubKey, pubKeySz, &pubKeyIdx);

    if (ret == WS_SUCCESS) {
        pubKeyIdx += scratch;
        ret = GetStringRef(&qSz, &q, pubKey, pubKeySz, &pubKeyIdx);
    }

    if (ret == WS_SUCCESS) {
        ret = wc_ecc_import_x963_ex(q, qSz,
                &sigKeyBlock_ptr->sk.ecc.key, primeId);
        if (ret == 0) {
            sigKeyBlock_ptr->keySz =
                (word32)sizeof(sigKeyBlock_ptr->sk.ecc.key);
            sigKeyBlock_ptr->keyAllocated = 1;
        }
        else
            ret = WS_ECC_E;
    }
#else
    WOLFSSH_UNUSED(ssh);
    WOLFSSH_UNUSED(sigKeyBlock_ptr);
    WOLFSSH_UNUSED(pubKey);
    WOLFSSH_UNUSED(pubKeySz);
    ret = WS_INVALID_ALGO_ID;
#endif
    return ret;
}


/* Parse out a RAW Ed25519 public key from buffer */
static int ParseEd25519PubKey(WOLFSSH *ssh,
        struct wolfSSH_sigKeyBlock *sigKeyBlock_ptr,
        byte *pubKey, word32 pubKeySz)
#ifndef WOLFSSH_NO_ED25519
{
    int ret;
    const byte* encA;
    word32 encASz, pubKeyIdx = 0;

    ret = wc_ed25519_init_ex(&sigKeyBlock_ptr->sk.ed25519.key,
            ssh->ctx->heap, INVALID_DEVID);
    if (ret != 0)
        ret = WS_ED25519_E;

    /* Skip the algo name */
    if (ret == WS_SUCCESS) {
        ret = GetSkip(pubKey, pubKeySz, &pubKeyIdx);
    }

    if (ret == WS_SUCCESS) {
        ret = GetStringRef(&encASz, &encA, pubKey, pubKeySz, &pubKeyIdx);
    }

    if (ret == WS_SUCCESS) {
        ret = wc_ed25519_import_public(encA, encASz,
                &sigKeyBlock_ptr->sk.ed25519.key);
        if (ret != 0)
            ret = WS_ED25519_E;
    }
    return ret;
}
#else
{
    WOLFSSH_UNUSED(ssh);
    WOLFSSH_UNUSED(sigKeyBlock_ptr);
    WOLFSSH_UNUSED(pubKey);
    WOLFSSH_UNUSED(pubKeySz);
    return WS_INVALID_ALGO_ID;
}
#endif


#ifdef WOLFSSH_CERTS
/* finds the leaf certificate and optionally the bounds of the cert chain,
 * returns WS_SUCCESS on success */
static int ParseCertChain(byte* in, word32 inSz,
        byte** certChain, word32* certChainSz, word32* certCount,
        byte** leafOut, word32* leafOutSz)
{
    int ret;
    word32 sz = 0, idx = 0;
    word32 ocspCount = 0;
    byte*  chain = NULL;
    word32 chainSz = 0;
    word32 count, countIdx;

    /* Skip the name */
    ret = GetSize(&sz, in, inSz, &idx);

    if (ret == WS_SUCCESS) {
        idx += sz;

        /* Get the cert count */
        ret = GetUint32(&count, in, inSz, &idx);
    }

    if (ret == WS_SUCCESS) {
        WLOG(WS_LOG_INFO, "Peer sent certificate count of %d", count);
        chain = in + idx;

        for (countIdx = count; countIdx > 0; countIdx--) {
            ret = GetSize(&sz, in, inSz, &idx);
            if (ret != WS_SUCCESS) {
                break;
            }
            WLOG(WS_LOG_INFO, "Adding certificate size %u", sz);

            /* store leaf cert size to present to user callback */
            if (countIdx == count) {
                if (leafOut != NULL && leafOutSz != NULL) {
                    *leafOutSz = sz;
                    *leafOut = in + idx;
                }
            }
            chainSz += sz + UINT32_SZ;
            idx += sz;
        }

        /* get OCSP count */
        if (ret == WS_SUCCESS) {
            ret = GetUint32(&ocspCount, in, inSz, &idx);
        }

        if (ret == WS_SUCCESS) {
            WLOG(WS_LOG_INFO, "Peer sent OCSP count of %u", ocspCount);

            /* RFC 6187 section 2.1 OCSP count must not exceed cert count */
            if (ocspCount > count) {
                WLOG(WS_LOG_ERROR, "Error more OCSP then Certs");
                ret = WS_FATAL_ERROR;
            }
        }

        if (ret == WS_SUCCESS) {
            /* @TODO handle OCSP's */
            if (ocspCount > 0) {
                WLOG(WS_LOG_INFO, "Peer sent OCSP's, not yet handled");
            }
        }
    }

    if (ret == WS_SUCCESS) {
        if (certChain != NULL && certChainSz != NULL && certCount != NULL) {
            *certChain = chain;
            *certChainSz = chainSz;
            *certCount = count;
        }
    }

    return ret;
}


static int ParseLeafCert(byte* in, word32 inSz,
        byte** leafOut, word32* leafOutSz)
{
    return ParseCertChain(in, inSz, NULL, NULL, NULL, leafOut, leafOutSz);
}


static int ParseCertChainVerify(WOLFSSH* ssh, byte* in, word32 inSz,
        byte** leafOut, word32* leafOutSz)
{
    byte *certChain = NULL;
    word32 certChainSz = 0, certCount = 0;
    int ret;

    ret = ParseCertChain(in, inSz,
            &certChain, &certChainSz, &certCount,
            leafOut, leafOutSz);

    if (ret == WS_SUCCESS) {
        ret = wolfSSH_CERTMAN_VerifyCerts_buffer(ssh->ctx->certMan,
                    certChain, certChainSz, certCount);
    }

    return ret;
}


/* finds the leaf certificate after having been verified, and extracts the
 * public key in DER format from it
 * this function allocates 'out' buffer, it is up to the caller to free it
 * return WS_SUCCESS on success */
static int ParsePubKeyCert(WOLFSSH* ssh, byte* in, word32 inSz, byte** out,
    word32* outSz)
{
    int ret;
    byte*  leaf   = NULL;
    word32 leafSz = 0;

    ret = ParseCertChainVerify(ssh, in, inSz, &leaf, &leafSz);
    if (ret == WS_SUCCESS) {
        int error = 0;
        struct DecodedCert dCert;

        wc_InitDecodedCert(&dCert, leaf, leafSz, ssh->ctx->heap);
        error = wc_ParseCert(&dCert, CERT_TYPE, 0, NULL);
        if (error == 0) {
            error = wc_GetPubKeyDerFromCert(&dCert, *out, outSz);
            if (error == LENGTH_ONLY_E) {
                error = 0;
                *out = (byte*)WMALLOC(*outSz, NULL, 0);
                if (*out == NULL) {
                    error = WS_MEMORY_E;
                }
            }

            if (error == 0) {
                error = wc_GetPubKeyDerFromCert(&dCert, *out, outSz);
                if (error != 0) {
                    WFREE(*out, NULL, 0);
                }
            }
        }
        wc_FreeDecodedCert(&dCert);

        if (error != 0) {
            ret = error;
        }
    }

    return ret;
}


/* return WS_SUCCESS on success */
static int ParseECCPubKeyCert(WOLFSSH *ssh,
    struct wolfSSH_sigKeyBlock *sigKeyBlock_ptr, byte *pubKey, word32 pubKeySz)
{
    int ret;
#ifndef WOLFSSH_NO_ECDSA
    byte* der = NULL;
    word32 derSz, idx = 0;
    int error;

    ret = ParsePubKeyCert(ssh, pubKey, pubKeySz, &der, &derSz);
    if (ret == WS_SUCCESS) {
        error = wc_ecc_init_ex(&sigKeyBlock_ptr->sk.ecc.key, ssh->ctx->heap,
                                 INVALID_DEVID);
    #ifdef HAVE_WC_ECC_SET_RNG
        if (error == 0)
            error = wc_ecc_set_rng(&sigKeyBlock_ptr->sk.ecc.key, ssh->rng);
    #endif
        if (error == 0)
            error = wc_EccPublicKeyDecode(der, &idx,
                &sigKeyBlock_ptr->sk.ecc.key, derSz);
        if (error == 0) {
            sigKeyBlock_ptr->keySz = (word32)sizeof(sigKeyBlock_ptr->sk.ecc.key);
            sigKeyBlock_ptr->keyAllocated = 1;
        }
        if (error != 0)
            ret = error;
        WFREE(der, NULL, 0);
    }
#else
    WOLFSSH_UNUSED(ssh);
    WOLFSSH_UNUSED(sigKeyBlock_ptr);
    WOLFSSH_UNUSED(pubKey);
    WOLFSSH_UNUSED(pubKeySz);
    ret = WS_INVALID_ALGO_ID;
#endif

    return ret;
}


/* return WS_SUCCESS on success */
static int ParseRSAPubKeyCert(WOLFSSH *ssh,
    struct wolfSSH_sigKeyBlock *sigKeyBlock_ptr, byte *pubKey, word32 pubKeySz)
{

    int ret;
#ifndef WOLFSSH_NO_RSA
    byte* der = NULL;
    word32 derSz, idx = 0;
    int error;

    ret = ParsePubKeyCert(ssh, pubKey, pubKeySz, &der, &derSz);
    if (ret == WS_SUCCESS) {
        error = wc_InitRsaKey(&sigKeyBlock_ptr->sk.rsa.key, ssh->ctx->heap);
        if (error == 0)
            error = wc_RsaPublicKeyDecode(der, &idx,
                                          &sigKeyBlock_ptr->sk.rsa.key, derSz);
        if (error == 0) {
            sigKeyBlock_ptr->keySz =
                (word32)sizeof(sigKeyBlock_ptr->sk.rsa.key);
            sigKeyBlock_ptr->keyAllocated = 1;
        }
        if (error != 0)
            ret = error;
        WFREE(der, NULL, 0);
    }
#else
    WOLFSSH_UNUSED(ssh);
    WOLFSSH_UNUSED(sigKeyBlock_ptr);
    WOLFSSH_UNUSED(pubKey);
    WOLFSSH_UNUSED(pubKeySz);
    ret = WS_INVALID_ALGO_ID;
#endif

    return ret;
}
#endif /* WOLFSSH_CERTS */


/* Parse out a public key from buffer received
 * return WS_SUCCESS on success */
static int ParsePubKey(WOLFSSH *ssh,
    struct wolfSSH_sigKeyBlock *sigKeyBlock_ptr, byte *pubKey, word32 pubKeySz)
{
    int ret;

    switch (ssh->handshake->pubKeyId) {
        case ID_SSH_RSA:
        case ID_RSA_SHA2_256:
        case ID_RSA_SHA2_512:
            sigKeyBlock_ptr->useRsa = 1;
            ret = ParseRSAPubKey(ssh, sigKeyBlock_ptr, pubKey, pubKeySz);
            break;

    #ifdef WOLFSSH_CERTS
        case ID_X509V3_SSH_RSA:
            sigKeyBlock_ptr->useRsa = 1;
            ret = ParseRSAPubKeyCert(ssh, sigKeyBlock_ptr, pubKey, pubKeySz);
            break;
    #endif

        case ID_ECDSA_SHA2_NISTP256:
        case ID_ECDSA_SHA2_NISTP384:
        case ID_ECDSA_SHA2_NISTP521:
            sigKeyBlock_ptr->useEcc = 1;
            ret = ParseECCPubKey(ssh, sigKeyBlock_ptr, pubKey, pubKeySz);
            break;

    #ifdef WOLFSSH_CERTS
        case ID_X509V3_ECDSA_SHA2_NISTP256:
        case ID_X509V3_ECDSA_SHA2_NISTP384:
        case ID_X509V3_ECDSA_SHA2_NISTP521:
            sigKeyBlock_ptr->useEcc = 1;
            ret = ParseECCPubKeyCert(ssh, sigKeyBlock_ptr, pubKey, pubKeySz);
            break;
    #endif

        case ID_ED25519:
            sigKeyBlock_ptr->useEd25519 = 1;
            ret = ParseEd25519PubKey(ssh, sigKeyBlock_ptr, pubKey, pubKeySz);
            break;

        default:
            ret = WS_INVALID_ALGO_ID;
    }

    return ret;
}


static void FreePubKey(struct wolfSSH_sigKeyBlock *p)
{
    if (p && p->keyAllocated) {
        if (p->useRsa) {
        #ifndef WOLFSSH_NO_RSA
            wc_FreeRsaKey(&p->sk.rsa.key);
        #endif
        }
        else if (p->useEcc) {
        #ifndef WOLFSSH_NO_ECDSA
            wc_ecc_free(&p->sk.ecc.key);
        #endif
        }
        p->keyAllocated = 0;
    }
}


/* KeyAgreeDh_client
 * hashId - wolfCrypt hash type ID used
 * f - peer public key
 * fSz - peer public key size
 */
static int KeyAgreeDh_client(WOLFSSH* ssh, byte hashId,
        const byte* f, word32 fSz)
#ifndef WOLFSSH_NO_DH
{
    int ret;

    WLOG(WS_LOG_DEBUG, "Entering KeyAgreeDh_client()");
    WOLFSSH_UNUSED(hashId);

    PRIVATE_KEY_UNLOCK();
    ret = wc_DhAgree(&ssh->handshake->privKey.dh,
                     ssh->k, &ssh->kSz,
                     ssh->handshake->x, ssh->handshake->xSz,
                     f, fSz);
    PRIVATE_KEY_LOCK();
    if (ret != 0) {
        WLOG(WS_LOG_ERROR,
                "Generate DH shared secret failed, %d", ret);
        ret = WS_CRYPTO_FAILED;
    }
    ForceZero(ssh->handshake->x, ssh->handshake->xSz);
    wc_FreeDhKey(&ssh->handshake->privKey.dh);

    WLOG(WS_LOG_DEBUG, "Leaving KeyAgreeDh_client(), ret = %d", ret);
    return ret;
}
#else /* WOLFSSH_NO_DH */
{
    WOLFSSH_UNUSED(ssh);
    WOLFSSH_UNUSED(hashId);
    WOLFSSH_UNUSED(f);
    WOLFSSH_UNUSED(fSz);
    return WS_INVALID_ALGO_ID;
}
#endif /* WOLFSSH_NO_DH */


/* KeyAgreeEcdh_client
 * hashId - wolfCrypt hash type ID used
 * f - peer public key
 * fSz - peer public key size
 */
static int KeyAgreeEcdh_client(WOLFSSH* ssh, byte hashId,
        const byte* f, word32 fSz)
#ifndef WOLFSSH_NO_ECDH
{
    int ret = WS_SUCCESS;
    ecc_key *key_ptr = NULL;
    #ifndef WOLFSSH_SMALL_STACK
        ecc_key key_s;
    #endif

    WLOG(WS_LOG_DEBUG, "Entering KeyAgreeEcdh_client()");
    WOLFSSH_UNUSED(hashId);

    #ifdef WOLFSSH_SMALL_STACK
        key_ptr = (ecc_key*)WMALLOC(sizeof(ecc_key),
                ssh->ctx->heap, DYNTYPE_PRIVKEY);
        if (key_ptr == NULL) {
            ret = WS_MEMORY_E;
        }
    #else /* ! WOLFSSH_SMALL_STACK */
        key_ptr = &key_s;
    #endif /* WOLFSSH_SMALL_STACK */
    ret = wc_ecc_init(key_ptr);
    #ifdef HAVE_WC_ECC_SET_RNG
    if (ret == 0)
        ret = wc_ecc_set_rng(key_ptr, ssh->rng);
    #endif
    if (ret == 0)
        ret = wc_ecc_import_x963(f, fSz, key_ptr);
    if (ret == 0) {
        PRIVATE_KEY_UNLOCK();
        ret = wc_ecc_shared_secret(&ssh->handshake->privKey.ecc,
                key_ptr, ssh->k, &ssh->kSz);
        PRIVATE_KEY_LOCK();
        if (ret != 0) {
            WLOG(WS_LOG_ERROR,
                    "Generate ECC shared secret failed, %d", ret);
            ret = WS_CRYPTO_FAILED;
        }
    }
    wc_ecc_free(key_ptr);
    #ifdef WOLFSSH_SMALL_STACK
    if (key_ptr) {
        WFREE(key_ptr, ssh->ctx->heap, DYNTYPE_PRIVKEY);
    }
    #endif
    wc_ecc_free(&ssh->handshake->privKey.ecc);

    WLOG(WS_LOG_DEBUG, "Leaving KeyAgreeEcdh_client(), ret = %d", ret);
    return ret;
}
#else /* WOLFSSH_NO_ECDH */
{
    WOLFSSH_UNUSED(ssh);
    WOLFSSH_UNUSED(hashId);
    WOLFSSH_UNUSED(f);
    WOLFSSH_UNUSED(fSz);
    return WS_INVALID_ALGO_ID;
}
#endif /* WOLFSSH_NO_ECDH */


/* KeyAgreeCurve25519_client
 * hashId - wolfCrypt hash type ID used
 * f - peer public key
 * fSz - peer public key size
 */
static int KeyAgreeCurve25519_client(WOLFSSH* ssh, byte hashId,
        const byte* f, word32 fSz)
#ifndef WOLFSSH_NO_CURVE25519_SHA256
{
    int ret;
    curve25519_key pub;

    WLOG(WS_LOG_DEBUG, "Entering KeyAgreeCurve25519_client()");
    WOLFSSH_UNUSED(hashId);

    ret = wc_curve25519_init(&pub);
    if (ret == 0) {
        ret = wc_curve25519_check_public(f, fSz,
                EC25519_LITTLE_ENDIAN);
    }

    if (ret == 0) {
        ret = wc_curve25519_import_public_ex(f, fSz, &pub,
                EC25519_LITTLE_ENDIAN);
    }

    if (ret == 0) {
        PRIVATE_KEY_UNLOCK();
        ret = wc_curve25519_shared_secret_ex(
                  &ssh->handshake->privKey.curve25519, &pub,
                  ssh->k, &ssh->kSz, EC25519_LITTLE_ENDIAN);
        PRIVATE_KEY_LOCK();
        if (ret != 0) {
            WLOG(WS_LOG_ERROR,
                    "Gen curve25519 shared secret failed, %d", ret);
            ret = WS_CRYPTO_FAILED;
        }
    }

    wc_curve25519_free(&pub);
    wc_curve25519_free(&ssh->handshake->privKey.curve25519);

    WLOG(WS_LOG_DEBUG, "Leaving KeyAgreeCurve25519_client(), ret = %d", ret);
    return ret;
}
#else /* WOLFSSH_NO_CURVE25519_SHA256 */
{
    WOLFSSH_UNUSED(ssh);
    WOLFSSH_UNUSED(hashId);
    WOLFSSH_UNUSED(f);
    WOLFSSH_UNUSED(fSz);
    return WS_INVALID_ALGO_ID;
}
#endif /* WOLFSSH_NO_CURVE25519_SHA256 */


/* KeyAgreeEcdhKyber512_client
 * hashId - wolfCrypt hash type ID used
 * f - peer public key
 * fSz - peer public key size
 */
static int KeyAgreeEcdhKyber512_client(WOLFSSH* ssh, byte hashId,
        const byte* f, word32 fSz)
#ifndef WOLFSSH_NO_ECDH_NISTP256_KYBER_LEVEL1_SHA256
{
    int ret = WS_SUCCESS;
    byte sharedSecretHashSz = 0;
    byte *sharedSecretHash = NULL;
    ecc_key *key_ptr = NULL;
    KyberKey kem = {0};
    word32 length_ciphertext = 0;
    word32 length_sharedsecret = 0;
    word32 length_privatekey = 0;

    #ifndef WOLFSSH_SMALL_STACK
        ecc_key key_s;
    #endif
    #ifdef WOLFSSH_SMALL_STACK
        key_ptr = (ecc_key*)WMALLOC(sizeof(ecc_key),
                ssh->ctx->heap, DYNTYPE_PRIVKEY);
        if (key_ptr == NULL) {
            ret = WS_MEMORY_E;
        }
    #else /* ! WOLFSSH_SMALL_STACK */
        key_ptr = &key_s;
    #endif /* WOLFSSH_SMALL_STACK */

    WLOG(WS_LOG_DEBUG, "Entering KeyAgreeEcdhKyber512_client()");

    /* This is a a hybrid of ECDHE and a post-quantum KEM. In this
     * case, I need to generated the ECC shared secret and
     * decapsulate the ciphertext of the post-quantum KEM. */

    if (ret == 0) {
        ret = wc_KyberKey_Init(KYBER512, &kem, ssh->ctx->heap, INVALID_DEVID);
    }

    if (ret == 0) {
        ret = wc_KyberKey_CipherTextSize(&kem, &length_ciphertext);
    }

    if (ret == 0) {
        ret = wc_KyberKey_SharedSecretSize(&kem, &length_sharedsecret);
    }

    if (ret == 0) {
        ret = wc_KyberKey_PrivateKeySize(&kem, &length_privatekey);
    }

    if ((ret == 0) && (ssh->handshake->xSz < length_privatekey)) {
        ret = WS_BUFFER_E;
    }

    if ((ret == 0) && (fSz < length_ciphertext)) {
        ret = WS_BUFFER_E;
    }

    if (ret == 0) {
        ret = wc_ecc_init(key_ptr);
    }
    #ifdef HAVE_WC_ECC_SET_RNG
    if (ret == 0) {
        ret = wc_ecc_set_rng(key_ptr, ssh->rng);
    }
    #endif
    if (ret == 0) {
        ret = wc_ecc_import_x963(f + length_ciphertext, fSz - length_ciphertext,
                                 key_ptr);
    }

    if (ret == 0) {
        PRIVATE_KEY_UNLOCK();
        ret = wc_ecc_shared_secret(&ssh->handshake->privKey.ecc,
                                   key_ptr, ssh->k + length_sharedsecret,
                                   &ssh->kSz);
        PRIVATE_KEY_LOCK();
    }
    wc_ecc_free(key_ptr);
    #ifdef WOLFSSH_SMALL_STACK
    if (key_ptr) {
        WFREE(key_ptr, ssh->ctx->heap, DYNTYPE_PRIVKEY);
    }
    #endif
    wc_ecc_free(&ssh->handshake->privKey.ecc);

    if (ret == 0) {
        wc_KyberKey_DecodePrivateKey(&kem, ssh->handshake->x,
                                     length_privatekey);
    }

    if (ret == 0) {
        ret = wc_KyberKey_Decapsulate(&kem, ssh->k, f, length_ciphertext);
    }

    if (ret == 0) {
        ssh->kSz += length_sharedsecret;
    } else {
        ssh->kSz = 0;
        WLOG(WS_LOG_ERROR,
             "Generate ECC-kyber (decap) shared secret failed, %d",
             ret);
    }

    wc_KyberKey_Free(&kem);

    /* Replace the concatenated shared secrets with the hash. That
     * will become the new shared secret. */
    if (ret == 0) {
        sharedSecretHashSz = wc_HashGetDigestSize(hashId);
        sharedSecretHash = (byte *)WMALLOC(sharedSecretHashSz,
                                           ssh->ctx->heap,
                                           DYNTYPE_PRIVKEY);
        if (sharedSecretHash == NULL) {
            ret = WS_MEMORY_E;
        }
    }

    if (ret == 0) {
        ret = wc_Hash(hashId, ssh->k, ssh->kSz, sharedSecretHash,
                      sharedSecretHashSz);
    }

    if (ret == 0) {
        XMEMCPY(ssh->k, sharedSecretHash, sharedSecretHashSz);
        ssh->kSz = sharedSecretHashSz;
    }

    if (sharedSecretHash) {
        ForceZero(sharedSecretHash, sharedSecretHashSz);
        WFREE(sharedSecretHash, ssh->ctx->heap, DYNTYPE_PRIVKEY);
    }

    WLOG(WS_LOG_DEBUG, "Leaving KeyAgreeEcdhKyber512_client(), ret = %d", ret);
    return ret;
}
#else /* WOLFSSH_NO_ECDH_NISTP256_KYBER_LEVEL1_SHA256 */
{
    WOLFSSH_UNUSED(ssh);
    WOLFSSH_UNUSED(hashId);
    WOLFSSH_UNUSED(f);
    WOLFSSH_UNUSED(fSz);
    return WS_INVALID_ALGO_ID;
}
#endif /* WOLFSSH_NO_ECDH_NISTP256_KYBER_LEVEL1_SHA256 */


/* KeyAgree_client
 * hashId - wolfCrypt hash type ID used
 * f - peer public key
 * fSz - peer public key size
 */
static int KeyAgree_client(WOLFSSH* ssh, byte hashId, const byte* f, word32 fSz)
{
    int ret;

    /* reset size here because a previous shared secret could
     * potentially be smaller by a byte than usual and cause buffer
     * issues with re-key */
    ssh->kSz = MAX_KEX_KEY_SZ;

    if (ssh->handshake->useDh) {
        ret = KeyAgreeDh_client(ssh, hashId, f, fSz);
    }
    else if (ssh->handshake->useEcc) {
        ret = KeyAgreeEcdh_client(ssh, hashId, f, fSz);
    }
    else if (ssh->handshake->useCurve25519) {
        ret = KeyAgreeCurve25519_client(ssh, hashId, f, fSz);
    }
    else if (ssh->handshake->useEccKyber) {
        ret = KeyAgreeEcdhKyber512_client(ssh, hashId, f, fSz);
    }
    else {
        ret = WS_INVALID_ALGO_ID;
    }
    return ret;
}


static int DoKexDhReply(WOLFSSH* ssh, byte* buf, word32 len, word32* idx)
{
    struct wolfSSH_sigKeyBlock *sigKeyBlock_ptr = NULL;
    wc_HashAlg* hash = NULL;
    byte* pubKey = NULL;
    byte* f = NULL;
    byte* sig;
    word32 pubKeySz;
    word32 fSz;
    word32 sigSz;
    word32 scratch;
    word32 begin;
    int ret = WS_SUCCESS;
    enum wc_HashType hashId;
    byte scratchLen[LENGTH_SZ];
    byte kPad = 0;

    WLOG(WS_LOG_DEBUG, "Entering DoKexDhReply()");

    if (ssh == NULL || ssh->handshake == NULL || buf == NULL ||
            len == 0 || idx == NULL) {
        ret = WS_BAD_ARGUMENT;
        WLOG(WS_LOG_DEBUG, "Leaving DoKexDhReply(), ret = %d", ret);
        return ret;
    }

    if (ret == WS_SUCCESS && len < LENGTH_SZ*2 + *idx) {
        ret = WS_BUFFER_E;
    }

    if (ret == WS_SUCCESS) {
        begin = *idx;
        ret = GetUint32(&pubKeySz, buf, len, &begin);
        if (ret == WS_SUCCESS && (pubKeySz > len - LENGTH_SZ - begin )) {
            ret = WS_BUFFER_E;
        }
    }

    if (ret == WS_SUCCESS) {
        pubKey = buf + begin;
        if (ssh->ctx->publicKeyCheckCb != NULL) {
            WLOG(WS_LOG_DEBUG, "DKDR: Calling the public key check callback");
            ret = ssh->ctx->publicKeyCheckCb(pubKey, pubKeySz,
                    ssh->publicKeyCheckCtx);
            if (ret == 0) {
                WLOG(WS_LOG_DEBUG, "DKDR: public key accepted");
                ret = WS_SUCCESS;
            }
            else {
                WLOG(WS_LOG_DEBUG, "DKDR: public key rejected");
                ret = WS_PUBKEY_REJECTED_E;
            }
        }
        else {
            WLOG(WS_LOG_DEBUG, "DKDR: no public key check callback, accepted");
            ret = WS_SUCCESS;
        }
    }

    hash = &ssh->handshake->kexHash;
    hashId = (enum wc_HashType)ssh->handshake->kexHashId;

    if (ret == WS_SUCCESS) {
        /* Hash in the raw public key blob from the server including its
         * length which is at LENGTH_SZ offset ahead of pubKey. */
        ret = HashUpdate(hash, hashId,
                pubKey - LENGTH_SZ, pubKeySz + LENGTH_SZ);
    }

    if (ret == WS_SUCCESS)
        begin += pubKeySz;

#ifndef WOLFSSH_NO_DH_GEX_SHA256
    /* If using DH-GEX include the GEX specific values. */
    if (ret == WS_SUCCESS && ssh->handshake->kexId == ID_DH_GEX_SHA256) {
        byte primeGroupPad = 0, generatorPad = 0;

        if (ssh->handshake->primeGroup == NULL ||
                ssh->handshake->generator == NULL) {
            WLOG(WS_LOG_DEBUG,
                    "DKDR: trying GEX without generator or prime group");
            ret = WS_BAD_ARGUMENT;
        }

        /* Hash in the client's requested minimum key size. */
        if (ret == 0) {
            c32toa(ssh->handshake->dhGexMinSz, scratchLen);
            ret = HashUpdate(hash, hashId, scratchLen, LENGTH_SZ);
        }
        /* Hash in the client's requested preferred key size. */
        if (ret == 0) {
            c32toa(ssh->handshake->dhGexPreferredSz, scratchLen);
            ret = HashUpdate(hash, hashId, scratchLen, LENGTH_SZ);
        }
        /* Hash in the client's requested maximum key size. */
        if (ret == 0) {
            c32toa(ssh->handshake->dhGexMaxSz, scratchLen);
            ret = HashUpdate(hash, hashId, scratchLen, LENGTH_SZ);
        }
        /* Add a pad byte if the mpint has the MSB set. */
        if (ret == 0) {
            if (ssh->handshake->primeGroup != NULL &&
                    ssh->handshake->primeGroup[0] & 0x80)
                primeGroupPad = 1;

            /* Hash in the length of the GEX prime group. */
            c32toa(ssh->handshake->primeGroupSz + primeGroupPad,
                   scratchLen);
            ret = HashUpdate(hash, hashId, scratchLen, LENGTH_SZ);
        }
        /* Hash in the pad byte for the GEX prime group. */
        if (ret == 0) {
            if (primeGroupPad) {
                scratchLen[0] = 0;
                ret = HashUpdate(hash, hashId, scratchLen, 1);
            }
        }
        /* Hash in the GEX prime group. */
        if (ret == 0)
            ret  = HashUpdate(hash, hashId,
                    ssh->handshake->primeGroup, ssh->handshake->primeGroupSz);
        /* Add a pad byte if the mpint has the MSB set. */
        if (ret == 0) {
            if (ssh->handshake->generator[0] & 0x80)
                generatorPad = 1;

            /* Hash in the length of the GEX generator. */
            c32toa(ssh->handshake->generatorSz + generatorPad, scratchLen);
            ret = HashUpdate(hash, hashId, scratchLen, LENGTH_SZ);
        }
        /* Hash in the pad byte for the GEX generator. */
        if (ret == 0) {
            if (generatorPad) {
                scratchLen[0] = 0;
                ret = HashUpdate(hash, hashId, scratchLen, 1);
            }
        }
        /* Hash in the GEX generator. */
        if (ret == 0)
            ret = HashUpdate(hash, hashId,
                    ssh->handshake->generator, ssh->handshake->generatorSz);
    }
#endif

    /* Hash in the size of the client's DH e-value (ECDH Q-value). */
    if (ret == 0) {
        c32toa(ssh->handshake->eSz, scratchLen);
        ret = HashUpdate(hash, hashId, scratchLen, LENGTH_SZ);
    }
    /* Hash in the client's DH e-value (ECDH Q-value). */
    if (ret == 0)
        ret = HashUpdate(hash, hashId,
                ssh->handshake->e, ssh->handshake->eSz);

    /* Get and hash in the server's DH f-value (ECDH Q-value) */
    if (ret == WS_SUCCESS) {
        f = buf + begin;
        ret = GetUint32(&fSz, buf, len, &begin);
    }

    if (ret == WS_SUCCESS) {
        if (fSz > len - begin) {
            WLOG(WS_LOG_DEBUG, "F size would result in error");
            ret = WS_PARSE_E;
        }
    }

    if (ret == WS_SUCCESS) {
        ret = HashUpdate(hash, hashId, f, fSz + LENGTH_SZ);
    }

    if (ret == WS_SUCCESS) {
        f = buf + begin;
        begin += fSz;
        ret = GetUint32(&sigSz, buf, len, &begin);
    }

    if (ret == WS_SUCCESS) {
        if (sigSz > len - begin) {
            WLOG(WS_LOG_DEBUG, "Signature size would result in error 1");
            ret = WS_PARSE_E;
        }
    }

    if (ret == WS_SUCCESS) {
        sigKeyBlock_ptr = (struct wolfSSH_sigKeyBlock*)WMALLOC(
                sizeof(struct wolfSSH_sigKeyBlock), ssh->ctx->heap,
                DYNTYPE_PRIVKEY);
        if (sigKeyBlock_ptr == NULL) {
            ret = WS_MEMORY_E;
        }
    }

    if (ret == WS_SUCCESS) {
        WMEMSET(sigKeyBlock_ptr, 0, sizeof(*sigKeyBlock_ptr));
        sig = buf + begin;
        begin += sigSz;
        *idx = begin;

        ret = ParsePubKey(ssh, sigKeyBlock_ptr, pubKey, pubKeySz);
        /* Generate and hash in the shared secret */
        if (ret == WS_SUCCESS) {
            ret = KeyAgree_client(ssh, hashId, f, fSz);
        }

        /* Hash in the shared secret K. */
        if (ret == WS_SUCCESS) {
            if (!ssh->handshake->useEccKyber) {
                ret = CreateMpint(ssh->k, &ssh->kSz, &kPad);
            }
        }

        if (ret == 0) {
            c32toa(ssh->kSz + kPad, scratchLen);
            ret = HashUpdate(hash, hashId, scratchLen, LENGTH_SZ);
        }

        if ((ret == 0) && (kPad)) {
            scratchLen[0] = 0;
            ret = HashUpdate(hash, hashId, scratchLen, 1);
        }

        if (ret == 0) {
            ret = HashUpdate(hash, hashId, ssh->k, ssh->kSz);
        }

        /* Save the exchange hash value H, and session ID. */
        if (ret == 0) {
            ret = wc_HashFinal(hash, hashId, ssh->h);
            wc_HashFree(hash, hashId);
            ssh->handshake->kexHashId = WC_HASH_TYPE_NONE;
        }

        if (ret == 0) {
            ssh->hSz = wc_HashGetDigestSize(hashId);
            if (ssh->sessionIdSz == 0) {
                WMEMCPY(ssh->sessionId, ssh->h, ssh->hSz);
                ssh->sessionIdSz = ssh->hSz;
            }
        }

        if (ret != WS_SUCCESS)
            ret = WS_CRYPTO_FAILED;

        /* Verify h with the server's public key. */
        if (ret == WS_SUCCESS) {
#ifndef WOLFSSH_NO_RSA
        int tmpIdx = begin - sigSz;
#endif
            /* Skip past the sig name. Check it, though. Other SSH
             * implementations do the verify based on the name, despite what
             * was agreed upon. XXX*/
            begin = 0;
            ret = GetUint32(&scratch, sig, sigSz, &begin);
            if (ret == WS_SUCCESS) {
                /* Check that scratch isn't larger than the remainder of the
                 * sig buffer and leaves enough room for another length. */
                if (scratch > sigSz - begin - LENGTH_SZ) {
                    WLOG(WS_LOG_DEBUG, "sig name size is too large");
                    ret = WS_PARSE_E;
                }
            }
            if (ret == WS_SUCCESS) {
                begin += scratch;
                ret = GetUint32(&scratch, sig, sigSz, &begin);
            }
            if (ret == WS_SUCCESS) {
                if (scratch > sigSz - begin) {
                    WLOG(WS_LOG_DEBUG, "sig name size is too large");
                    ret = WS_PARSE_E;
                }
            }
            if (ret == WS_SUCCESS) {
                sig = sig + begin;
                /* In the fuzz, sigSz ends up 1 and it has issues. */
                sigSz = scratch;

                if (sigKeyBlock_ptr->useRsa) {
#ifndef WOLFSSH_NO_RSA
                    if (sigSz < MIN_RSA_SIG_SZ) {
                        WLOG(WS_LOG_DEBUG, "Provided signature is too small.");
                        ret = WS_RSA_E;
                    }

                    if (sigSz + begin + tmpIdx > len) {
                        WLOG(WS_LOG_DEBUG,
                                "Signature size found would result in error 2");
                        ret = WS_BUFFER_E;
                    }

                    if (ret == WS_SUCCESS) {
                        ret = wc_SignatureVerify(
                                HashForId(ssh->handshake->pubKeyId),
                                WC_SIGNATURE_TYPE_RSA_W_ENC,
                                ssh->h, ssh->hSz, sig, sigSz,
                                &sigKeyBlock_ptr->sk, sigKeyBlock_ptr->keySz);
                        if (ret != 0) {
                            WLOG(WS_LOG_DEBUG,
                                "DoKexDhReply: Signature Verify fail (%d)",
                                ret);
                            ret = WS_RSA_E;
                        }
                    }
#endif
                }
                else if (sigKeyBlock_ptr->useEcc) {
#ifndef WOLFSSH_NO_ECDSA
                    const byte* r;
                    const byte* s;
                    word32 rSz, sSz, asnSigSz;
                    byte asnSig[256];

                    begin = 0;
                    asnSigSz = (word32)sizeof(asnSig);
                    XMEMSET(asnSig, 0, asnSigSz);

                    ret = GetStringRef(&rSz, &r, sig, sigSz, &begin);
                    if (ret == WS_SUCCESS)
                        ret = GetStringRef(&sSz, &s, sig, sigSz, &begin);

                    if (ret == WS_SUCCESS)
                        ret = wc_ecc_rs_raw_to_sig(r, rSz, s, sSz,
                                asnSig, &asnSigSz);

                    if (ret == WS_SUCCESS) {
                        ret = wc_SignatureVerify(
                                HashForId(ssh->handshake->pubKeyId),
                                WC_SIGNATURE_TYPE_ECC,
                                ssh->h, ssh->hSz, asnSig, asnSigSz,
                                &sigKeyBlock_ptr->sk, sigKeyBlock_ptr->keySz);
                        if (ret != 0) {
                            WLOG(WS_LOG_DEBUG,
                                "DoKexDhReply: Signature Verify fail (%d)",
                                ret);
                            ret = WS_ECC_E;
                        }
                    }
#endif
                }
                else if (sigKeyBlock_ptr->useEd25519) {
#ifndef WOLFSSH_NO_ED25519
                    int res = 0;

                    ret = wc_ed25519_verify_msg(sig, sigSz,
                            ssh->h, ssh->hSz, &res,
                            &sigKeyBlock_ptr->sk.ed25519.key);
                    if (ret != 0 || res != 1) {
                        WLOG(WS_LOG_DEBUG,
                            "DoKexDhReply: Signature Verify fail (%d)",
                            ret);
                        ret = WS_ED25519_E;
                    }
#endif /* WOLFSSH_NO_ED25519 */
                }
                else {
                    ret = WS_INVALID_ALGO_ID;
                }
            }
        }
        FreePubKey(sigKeyBlock_ptr);
    }

    if (ret == WS_SUCCESS) {
        /* If we aren't using EccKyber, use padding. */
        ret = GenerateKeys(ssh, hashId, !ssh->handshake->useEccKyber);
    }

    if (ret == WS_SUCCESS)
        ret = SendNewKeys(ssh);

    if (sigKeyBlock_ptr)
        WFREE(sigKeyBlock_ptr, ssh->ctx->heap, DYNTYPE_PRIVKEY);
    WLOG(WS_LOG_DEBUG, "Leaving DoKexDhReply(), ret = %d", ret);
    return ret;
}


static int DoNewKeys(WOLFSSH* ssh, byte* buf, word32 len, word32* idx)
{
    int ret = WS_SUCCESS;

    WOLFSSH_UNUSED(buf);
    WOLFSSH_UNUSED(len);
    WOLFSSH_UNUSED(idx);

    if (ssh == NULL || ssh->handshake == NULL)
        ret = WS_BAD_ARGUMENT;

    if (ret == WS_SUCCESS) {
        ssh->peerEncryptId = ssh->handshake->encryptId;
        ssh->peerMacId = ssh->handshake->macId;
        ssh->peerBlockSz = ssh->handshake->blockSz;
        ssh->peerMacSz = ssh->handshake->macSz;
        ssh->peerAeadMode = ssh->handshake->aeadMode;
        WMEMCPY(&ssh->peerKeys, &ssh->handshake->peerKeys, sizeof(Keys));

        switch (ssh->peerEncryptId) {
            case ID_NONE:
                WLOG(WS_LOG_DEBUG, "DNK: peer using cipher none");
                break;

#ifndef WOLFSSH_NO_AES_CBC
            case ID_AES128_CBC:
            case ID_AES192_CBC:
            case ID_AES256_CBC:
                WLOG(WS_LOG_DEBUG, "DNK: peer using cipher aes-cbc");
                ret = wc_AesSetKey(&ssh->decryptCipher.aes,
                                   ssh->peerKeys.encKey, ssh->peerKeys.encKeySz,
                                   ssh->peerKeys.iv, AES_DECRYPTION);
                break;
#endif

#ifndef WOLFSSH_NO_AES_CTR
            case ID_AES128_CTR:
            case ID_AES192_CTR:
            case ID_AES256_CTR:
                WLOG(WS_LOG_DEBUG, "DNK: peer using cipher aes-ctr");
                ret = wc_AesSetKey(&ssh->decryptCipher.aes,
                                   ssh->peerKeys.encKey, ssh->peerKeys.encKeySz,
                                   ssh->peerKeys.iv, AES_ENCRYPTION);
                break;
#endif

#ifndef WOLFSSH_NO_AES_GCM
            case ID_AES128_GCM:
            case ID_AES192_GCM:
            case ID_AES256_GCM:
                WLOG(WS_LOG_DEBUG, "DNK: peer using cipher aes-gcm");
                ret = wc_AesGcmSetKey(&ssh->decryptCipher.aes,
                                      ssh->peerKeys.encKey,
                                      ssh->peerKeys.encKeySz);
                break;
#endif

            default:
                WLOG(WS_LOG_DEBUG, "DNK: peer using cipher invalid");
                break;
        }

        if (ret == 0)
            ret = WS_SUCCESS;
        else
            ret = WS_CRYPTO_FAILED;
    }

    if (ret == WS_SUCCESS) {
        ssh->rxCount = 0;
        ssh->highwaterFlag = 0;
        ssh->isKeying = 0;
        HandshakeInfoFree(ssh->handshake, ssh->ctx->heap);
        ssh->handshake = NULL;
        WLOG(WS_LOG_DEBUG, "Keying completed");

        if (ssh->ctx->keyingCompletionCb)
            ssh->ctx->keyingCompletionCb(ssh->keyingCompletionCtx);
    }

    return ret;
}


#ifndef WOLFSSH_NO_DH_GEX_SHA256
static int DoKexDhGexRequest(WOLFSSH* ssh,
                             byte* buf, word32 len, word32* idx)
{
    word32 begin;
    int ret = WS_SUCCESS;

    if (ssh == NULL || ssh->handshake == NULL || buf == NULL || len == 0 ||
            idx == NULL)
        ret = WS_BAD_ARGUMENT;

    if (ret == WS_SUCCESS) {
        begin = *idx;
        ret = GetUint32(&ssh->handshake->dhGexMinSz, buf, len, &begin);
    }

    if (ret == WS_SUCCESS) {
        ret = GetUint32(&ssh->handshake->dhGexPreferredSz, buf, len, &begin);
    }

    if (ret == WS_SUCCESS) {
        ret = GetUint32(&ssh->handshake->dhGexMaxSz, buf, len, &begin);
    }

    if (ret == WS_SUCCESS) {
        WLOG(WS_LOG_INFO, "  min = %u, preferred = %u, max = %u",
                ssh->handshake->dhGexMinSz,
                ssh->handshake->dhGexPreferredSz,
                ssh->handshake->dhGexMaxSz);
        *idx = begin;
        ret = SendKexDhGexGroup(ssh);
    }

    return ret;
}


static int DoKexDhGexGroup(WOLFSSH* ssh,
                           byte* buf, word32 len, word32* idx)
{
    const byte* primeGroup = NULL;
    word32 primeGroupSz;
    const byte* generator = NULL;
    word32 generatorSz;
    word32 begin;
    int ret = WS_SUCCESS;

    if (ssh == NULL || buf == NULL || len == 0 || idx == NULL)
        ret = WS_BAD_ARGUMENT;

    if (ret == WS_SUCCESS) {
        begin = *idx;
        ret = GetMpint(&primeGroupSz, &primeGroup, buf, len, &begin);
        if (ret == WS_SUCCESS && primeGroupSz > (MAX_KEX_KEY_SZ + 1))
            ret = WS_DH_SIZE_E;
    }

    if (ret == WS_SUCCESS)
        ret = GetMpint(&generatorSz, &generator, buf, len, &begin);

    if (ret == WS_SUCCESS) {
        if (ssh->handshake->primeGroup)
            WFREE(ssh->handshake->primeGroup, ssh->ctx->heap, DYNTYPE_MPINT);
        ssh->handshake->primeGroup =
            (byte*)WMALLOC(primeGroupSz, ssh->ctx->heap, DYNTYPE_MPINT);
        if (ssh->handshake->primeGroup == NULL)
            ret = WS_MEMORY_E;
    }

    if (ret == WS_SUCCESS) {
        if (ssh->handshake->generator)
            WFREE(ssh->handshake->generator, ssh->ctx->heap, DYNTYPE_MPINT);
        ssh->handshake->generator =
            (byte*)WMALLOC(generatorSz, ssh->ctx->heap, DYNTYPE_MPINT);
        if (ssh->handshake->generator == NULL) {
            ret = WS_MEMORY_E;
            WFREE(ssh->handshake->primeGroup, ssh->ctx->heap, DYNTYPE_MPINT);
            ssh->handshake->primeGroup = NULL;
        }
    }

    if (ret == WS_SUCCESS) {
        WMEMCPY(ssh->handshake->primeGroup, primeGroup, primeGroupSz);
        ssh->handshake->primeGroupSz = primeGroupSz;
        WMEMCPY(ssh->handshake->generator, generator, generatorSz);
        ssh->handshake->generatorSz = generatorSz;

        *idx = begin;
        ret = SendKexDhInit(ssh);
    }

    return ret;
}
#endif


static int DoIgnore(WOLFSSH* ssh, byte* buf, word32 len, word32* idx)
{
    word32 dataSz;
    word32 begin = *idx;

    WOLFSSH_UNUSED(ssh);
    WOLFSSH_UNUSED(len);

    ato32(buf + begin, &dataSz);
    begin += LENGTH_SZ + dataSz;

    *idx = begin;

    return WS_SUCCESS;
}

static int DoRequestSuccess(WOLFSSH *ssh, byte *buf, word32 len, word32 *idx)
{
    word32 dataSz;
    word32 begin = *idx;
    int    ret=WS_SUCCESS;

    WOLFSSH_UNUSED(ssh);
    WOLFSSH_UNUSED(len);

    WLOG(WS_LOG_DEBUG, "DoRequestSuccess, *idx=%d, len=%d", *idx, len);
    ato32(buf + begin, &dataSz);
    begin += LENGTH_SZ + dataSz;

    if (ssh->ctx->reqSuccessCb != NULL)
        ret = ssh->ctx->reqSuccessCb(ssh, &(buf[*idx]), len, ssh->reqSuccessCtx);

    *idx = begin;

    return ret;
}

static int DoRequestFailure(WOLFSSH *ssh, byte *buf, word32 len, word32 *idx)
{
    word32 dataSz;
    word32 begin = *idx;
    int ret = WS_SUCCESS;

    WOLFSSH_UNUSED(ssh);
    WOLFSSH_UNUSED(len);

    WLOG(WS_LOG_DEBUG, "DoRequestFalure, *idx=%d, len=%d", *idx, len);
    ato32(buf + begin, &dataSz);
    begin += LENGTH_SZ + dataSz;

    if (ssh->ctx->reqFailureCb != NULL)
        ret = ssh->ctx->reqFailureCb(ssh, &(buf[*idx]), len, ssh->reqFailureCtx);

    *idx = begin;

    return ret;
}

static int DoDebug(WOLFSSH* ssh, byte* buf, word32 len, word32* idx)
{
    byte  alwaysDisplay;
    char*    msg = NULL;
    char*    lang = NULL;
    word32 strSz;
    word32 begin;

    if (ssh == NULL || buf == NULL || idx == NULL ||
            len < (2 * LENGTH_SZ) + 1) {

        return WS_BAD_ARGUMENT;
    }
    begin = *idx;

    alwaysDisplay = buf[begin++];

    ato32(buf + begin, &strSz);
    begin += LENGTH_SZ;
    if (strSz > 0) {
        if (strSz > len - begin) {
            return WS_BUFFER_E;
        }

        msg = (char*)WMALLOC(strSz + 1, ssh->ctx->heap, DYNTYPE_STRING);
        if (msg != NULL) {
            WMEMCPY(msg, buf + begin, strSz);
            msg[strSz] = 0;
        }
        else {
            return WS_MEMORY_E;
        }
        begin += strSz;
    }

    if (LENGTH_SZ > len - begin) {
        WFREE(msg, ssh->ctx->heap, DYNTYPE_STRING);
        return WS_BUFFER_E;
    }

    ato32(buf + begin, &strSz);
    begin += LENGTH_SZ;
    if (strSz > 0) {
        if ((len < begin) || (strSz > len - begin)) {
            WFREE(msg, ssh->ctx->heap, DYNTYPE_STRING);
            return WS_BUFFER_E;
        }

        lang = (char*)WMALLOC(strSz + 1, ssh->ctx->heap, DYNTYPE_STRING);
        if (lang != NULL) {
            WMEMCPY(lang, buf + begin, strSz);
            lang[strSz] = 0;
        }
        else {
            WFREE(msg, ssh->ctx->heap, DYNTYPE_STRING);
            return WS_MEMORY_E;
        }
        begin += strSz;
    }

    if (alwaysDisplay) {
        WLOG(WS_LOG_DEBUG, "DEBUG MSG (%s): %s",
             (lang == NULL) ? "none" : lang,
             (msg == NULL) ? "no message" : msg);
    }

    *idx = begin;

    WFREE(msg, ssh->ctx->heap, DYNTYPE_STRING);
    WFREE(lang, ssh->ctx->heap, DYNTYPE_STRING);

    return WS_SUCCESS;
}


static int DoUnimplemented(WOLFSSH* ssh,
                           byte* buf, word32 len, word32* idx)
{
    word32 seq;
    word32 begin = *idx;

    WOLFSSH_UNUSED(ssh);
    WOLFSSH_UNUSED(len);

    ato32(buf + begin, &seq);
    begin += UINT32_SZ;

    WLOG(WS_LOG_DEBUG, "UNIMPLEMENTED: seq %u", seq);

    *idx = begin;

    return WS_SUCCESS;
}


static int DoDisconnect(WOLFSSH* ssh, byte* buf, word32 len, word32* idx)
{
    word32 reason;
    const char* reasonStr = NULL;
    word32 begin = *idx;

    WOLFSSH_UNUSED(ssh);
    WOLFSSH_UNUSED(len);
    WOLFSSH_UNUSED(reasonStr);

    ato32(buf + begin, &reason);
    begin += UINT32_SZ;

#ifdef NO_WOLFSSH_STRINGS
    WLOG(WS_LOG_DEBUG, "DISCONNECT: (%u)", reason);
#elif defined(DEBUG_WOLFSSH)
    switch (reason) {
        case WOLFSSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT:
            reasonStr = "host not allowed to connect"; break;
        case WOLFSSH_DISCONNECT_PROTOCOL_ERROR:
            reasonStr = "protocol error"; break;
        case WOLFSSH_DISCONNECT_KEY_EXCHANGE_FAILED:
            reasonStr = "key exchange failed"; break;
        case WOLFSSH_DISCONNECT_RESERVED:
            reasonStr = "reserved"; break;
        case WOLFSSH_DISCONNECT_MAC_ERROR:
            reasonStr = "mac error"; break;
        case WOLFSSH_DISCONNECT_COMPRESSION_ERROR:
            reasonStr = "compression error"; break;
        case WOLFSSH_DISCONNECT_SERVICE_NOT_AVAILABLE:
            reasonStr = "service not available"; break;
        case WOLFSSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED:
            reasonStr = "protocol version not supported"; break;
        case WOLFSSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE:
            reasonStr = "host key not verifiable"; break;
        case WOLFSSH_DISCONNECT_CONNECTION_LOST:
            reasonStr = "connection lost"; break;
        case WOLFSSH_DISCONNECT_BY_APPLICATION:
            reasonStr = "disconnect by application"; break;
        case WOLFSSH_DISCONNECT_TOO_MANY_CONNECTIONS:
            reasonStr = "too many connections"; break;
        case WOLFSSH_DISCONNECT_AUTH_CANCELLED_BY_USER:
            reasonStr = "auth cancelled by user"; break;
        case WOLFSSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE:
            reasonStr = "no more auth methods available"; break;
        case WOLFSSH_DISCONNECT_ILLEGAL_USER_NAME:
            reasonStr = "illegal user name"; break;
        default:
            reasonStr = "unknown reason";
    }
    WLOG(WS_LOG_DEBUG, "DISCONNECT: (%u) %s", reason, reasonStr);
#endif

    *idx = begin;

    return WS_SUCCESS;
}


static int DoServiceRequest(WOLFSSH* ssh,
                            byte* buf, word32 len, word32* idx)
{
    word32 begin = *idx;
    word32 nameSz;
    char     serviceName[WOLFSSH_MAX_NAMESZ];

    WOLFSSH_UNUSED(len);

    ato32(buf + begin, &nameSz);
    begin += LENGTH_SZ;

    if (begin + nameSz > len || nameSz >= WOLFSSH_MAX_NAMESZ) {
        return WS_BUFFER_E;
    }

    WMEMCPY(serviceName, buf + begin, nameSz);
    begin += nameSz;
    serviceName[nameSz] = 0;

    *idx = begin;

    WLOG(WS_LOG_DEBUG, "Requesting service: %s", serviceName);
    ssh->clientState = CLIENT_USERAUTH_REQUEST_DONE;

    return WS_SUCCESS;
}


static int DoServiceAccept(WOLFSSH* ssh,
                           byte* buf, word32 len, word32* idx)
{
    word32 begin = *idx;
    word32 nameSz;
    char     serviceName[WOLFSSH_MAX_NAMESZ];

    ato32(buf + begin, &nameSz);
    begin += LENGTH_SZ;

    if (begin + nameSz > len || nameSz >= WOLFSSH_MAX_NAMESZ) {
        return WS_BUFFER_E;
    }

    WMEMCPY(serviceName, buf + begin, nameSz);
    begin += nameSz;
    serviceName[nameSz] = 0;

    *idx = begin;

    WLOG(WS_LOG_DEBUG, "Accepted service: %s", serviceName);
    ssh->serverState = SERVER_USERAUTH_REQUEST_DONE;

    return WS_SUCCESS;
}


static int DoExtInfoServerSigAlgs(WOLFSSH* ssh,
        const byte* names, word32 namesSz)
{
    byte* peerSigId = NULL;
    word32 peerSigIdSz;
    int ret = WS_SUCCESS;
    byte algoId;

    peerSigIdSz = CountNameList(names, namesSz);
    if (peerSigIdSz > 0) {
        peerSigId = (byte*)WMALLOC(peerSigIdSz, ssh->ctx->heap, DYNTYPE_ID);
        if (peerSigId == NULL) {
            ret = WS_MEMORY_E;
        }
    }

    if (ret == WS_SUCCESS) {
        ret = GetNameListRaw(peerSigId, &peerSigIdSz, names, namesSz);
    }

    if (ret == WS_SUCCESS) {
        algoId = MatchIdLists(ssh->ctx->side,
                peerSigId, peerSigIdSz,
                cannedKeyAlgoClient, cannedKeyAlgoClientSz);

        if (algoId == ID_UNKNOWN) {
            ret = WS_MATCH_UA_KEY_ID_E;
        }
    }

    if (ret == WS_SUCCESS) {
        if (ssh->peerSigId != NULL) {
            WFREE(ssh->peerSigId, ssh->ctx->heap, DYNTYPE_ID);
        }
        ssh->peerSigId = peerSigId;
        ssh->peerSigIdSz = peerSigIdSz;
    }
    else {
        WFREE(peerSigId, ssh->ctx->heap, DYNTYPE_ID);
    }

    return ret;
}


static int DoExtInfo(WOLFSSH* ssh, byte* buf, word32 len, word32* idx)
{
    const byte* extName;
    const byte* extValue;
    word32 i, extCount, extNameSz, extValueSz;
    int ret;
    byte matchId;

    ret = GetUint32(&extCount, buf, len, idx);

    for (i = 0; ret == WS_SUCCESS && i < extCount; i++) {
        ret = GetStringRef(&extNameSz, &extName, buf, len, idx);

        if (ret == WS_SUCCESS) {
            ret = GetStringRef(&extValueSz, &extValue, buf, len, idx);
        }

        if (ret == WS_SUCCESS) {
            matchId = NameToId((const char*)extName, extNameSz);
            if (matchId == ID_EXTINFO_SERVER_SIG_ALGS) {
                ret = DoExtInfoServerSigAlgs(ssh, extValue, extValueSz);
            }
        }
    }

    return ret;
}


#ifdef WOLFSSH_ALLOW_USERAUTH_NONE
/* Utility for DoUserAuthRequest() */
static int DoUserAuthRequestNone(WOLFSSH* ssh, WS_UserAuthData* authData,
                                     byte* buf, word32 len, word32* idx)
{
    int ret = WS_SUCCESS;
    WLOG(WS_LOG_DEBUG, "Entering DoUserAuthRequestNone()");

    WOLFSSH_UNUSED(len);

    if (ssh == NULL || authData == NULL ||
        buf == NULL || idx == NULL) {

        ret = WS_BAD_ARGUMENT;
    }

    if (ret == WS_SUCCESS) {
        authData->type = WOLFSSH_USERAUTH_NONE;
        if (ssh->ctx->userAuthCb != NULL) {
            WLOG(WS_LOG_DEBUG, "DUARN: Calling the userauth callback");
            ret = ssh->ctx->userAuthCb(WOLFSSH_USERAUTH_NONE,
                                       authData, ssh->userAuthCtx);
            if (ret == WOLFSSH_USERAUTH_SUCCESS) {
                WLOG(WS_LOG_DEBUG, "DUARN: none check successful");
                ssh->clientState = CLIENT_USERAUTH_DONE;
                ret = WS_SUCCESS;
            }
            else if (ret == WOLFSSH_USERAUTH_REJECTED) {
                WLOG(WS_LOG_DEBUG, "DUARN: password rejected");
                #ifndef NO_FAILURE_ON_REJECTED
                ret = SendUserAuthFailure(ssh, 0);
                if (ret == WS_SUCCESS)
                    ret = WS_USER_AUTH_E;
                #else
                ret = WS_USER_AUTH_E;
                #endif
            }
            else if (ret == WOLFSSH_USERAUTH_WOULD_BLOCK) {
                WLOG(WS_LOG_DEBUG, "DUARN: userauth callback would block");
                ret = WS_AUTH_PENDING;
            }
            else {
                WLOG(WS_LOG_DEBUG, "DUARN: none check failed, retry");
                ret = SendUserAuthFailure(ssh, 0);
            }
        }
        else {
            WLOG(WS_LOG_DEBUG, "DUARN: No user auth callback");
            ret = SendUserAuthFailure(ssh, 0);
            if (ret == WS_SUCCESS)
                ret = WS_FATAL_ERROR;
        }
    }

    WLOG(WS_LOG_DEBUG, "Leaving DoUserAuthRequestNone(), ret = %d", ret);
    return ret;
}
#endif


/* Utility for DoUserAuthRequest() */
static int DoUserAuthRequestPassword(WOLFSSH* ssh, WS_UserAuthData* authData,
                                     byte* buf, word32 len, word32* idx)
{
    word32 begin;
    WS_UserAuthData_Password* pw = NULL;
    int ret = WS_SUCCESS;
    int authFailure = 0;
    byte partialSuccess = 0;

    WLOG(WS_LOG_DEBUG, "Entering DoUserAuthRequestPassword()");

    if (ssh == NULL || authData == NULL ||
        buf == NULL || len == 0 || idx == NULL) {

        ret = WS_BAD_ARGUMENT;
    }

    if (ret == WS_SUCCESS) {
        begin = *idx;
        pw = &authData->sf.password;
        authData->type = WOLFSSH_USERAUTH_PASSWORD;
        ret = GetBoolean(&pw->hasNewPassword, buf, len, &begin);
    }

    if (ret == WS_SUCCESS)
        ret = GetUint32(&pw->passwordSz, buf, len, &begin);

    if (ret == WS_SUCCESS) {
        pw->password = buf + begin;
        begin += pw->passwordSz;

        if (pw->hasNewPassword) {
            /* Skip the password change. Maybe error out since we aren't
             * supporting password changes at this time. */
            ret = GetUint32(&pw->newPasswordSz, buf, len, &begin);
            if (ret == WS_SUCCESS) {
                pw->newPassword = buf + begin;
                begin += pw->newPasswordSz;
            }
        }
        else {
            pw->newPassword = NULL;
            pw->newPasswordSz = 0;
        }

        if (ssh->ctx->userAuthCb != NULL) {
            WLOG(WS_LOG_DEBUG, "DUARPW: Calling the userauth callback");
            ret = ssh->ctx->userAuthCb(WOLFSSH_USERAUTH_PASSWORD,
                                       authData, ssh->userAuthCtx);
            if (ret == WOLFSSH_USERAUTH_SUCCESS) {
                WLOG(WS_LOG_DEBUG, "DUARPW: password check success");
                ret = WS_SUCCESS;
            }
            else if (ret == WOLFSSH_USERAUTH_PARTIAL_SUCCESS) {
                WLOG(WS_LOG_DEBUG, "DUARPW: password check partial success");
                partialSuccess = 1;
                ret = WS_SUCCESS;
            }
            else if (ret == WOLFSSH_USERAUTH_REJECTED) {
                WLOG(WS_LOG_DEBUG, "DUARPW: password rejected");
                #ifndef NO_FAILURE_ON_REJECTED
                    authFailure = 1;
                #endif
                ret = WS_USER_AUTH_E;
            }
            else if (ret == WOLFSSH_USERAUTH_WOULD_BLOCK) {
                WLOG(WS_LOG_DEBUG, "DUARPW: userauth callback would block");
                ret = WS_AUTH_PENDING;
            }
            else {
                WLOG(WS_LOG_DEBUG, "DUARPW: password check failed, retry");
                authFailure = 1;
                ret = WS_SUCCESS;
            }
        }
        else {
            WLOG(WS_LOG_DEBUG, "DUARPW: No user auth callback");
            authFailure = 1;
        }
    }

    if (ret == WS_SUCCESS)
        *idx = begin;

    if (authFailure || partialSuccess) {
        ret = SendUserAuthFailure(ssh, partialSuccess);
    }
    else if (ret == WS_SUCCESS) {
        ssh->clientState = CLIENT_USERAUTH_DONE;
    }

    WLOG(WS_LOG_DEBUG, "Leaving DoUserAuthRequestPassword(), ret = %d", ret);
    return ret;
}

#ifndef WOLFSSH_NO_RSA
/* Utility for DoUserAuthRequestPublicKey() */
/* returns negative for error, positive is size of digest. */
static int DoUserAuthRequestRsa(WOLFSSH* ssh, WS_UserAuthData_PublicKey* pk,
                                enum wc_HashType hashId, byte* digest,
                                word32 digestSz)
{
    const byte* publicKeyType;
    const byte* sig;
    word32 publicKeyTypeSz = 0;
    word32 sigSz;
    word32 encDigestSz;
    word32 i = 0;
    int ret = WS_SUCCESS;
#ifdef WOLFSSH_SMALL_STACK
    byte* encDigest = NULL;
    RsaKey* key = NULL;
#else
    byte encDigest[MAX_ENCODED_SIG_SZ];
    RsaKey key[1];
#endif

    WLOG(WS_LOG_DEBUG, "Entering DoUserAuthRequestRsa()");

    if (ssh == NULL || ssh->ctx == NULL || pk == NULL || digest == NULL ||
            digestSz == 0) {

        ret = WS_BAD_ARGUMENT;
    }

#ifdef WOLFSSH_SMALL_STACK
    if (ret == WS_SUCCESS) {
        encDigest = (byte*)WMALLOC(MAX_ENCODED_SIG_SZ,
                ssh->ctx->heap, DYNTYPE_BUFFER);
        if (encDigest == NULL)
            ret = WS_MEMORY_E;
    }
    if (ret == WS_SUCCESS) {
        key = (RsaKey*)WMALLOC(sizeof(RsaKey), ssh->ctx->heap, DYNTYPE_PUBKEY);
        if (key == NULL)
            ret = WS_MEMORY_E;
    }
#endif

    if (ret == WS_SUCCESS) {
        ret = wc_InitRsaKey(key, ssh->ctx->heap);
        if (ret == 0) {
            ret = WS_SUCCESS;
        }
    }

    /* Check that the pubkey's type matches the expected one. */
    if (ret == WS_SUCCESS) {
        ret = GetStringRef(&publicKeyTypeSz, &publicKeyType,
                pk->publicKey, pk->publicKeySz, &i);
    }

    if (ret == WS_SUCCESS) {
        if (publicKeyTypeSz != 7 &&
            WMEMCMP(publicKeyType, "ssh-rsa", 7) != 0) {

            WLOG(WS_LOG_DEBUG,
                "Public Key's type does not match public key type");
            ret = WS_INVALID_ALGO_ID;
        }
    }

    /* Load up the key. */
    if (ret == WS_SUCCESS) {
        const byte* n = NULL;
        word32 nSz = 0;
        const byte* e = NULL;
        word32 eSz = 0;

        if (ret == WS_SUCCESS) {
            ret = GetMpint(&eSz, &e, pk->publicKey, pk->publicKeySz, &i);
        }

        if (ret == WS_SUCCESS) {
            ret = GetMpint(&nSz, &n, pk->publicKey, pk->publicKeySz, &i);
        }

        if (ret == WS_SUCCESS) {
            ret = wc_RsaPublicKeyDecodeRaw(n, nSz, e, eSz, key);
            if (ret != 0) {
                WLOG(WS_LOG_DEBUG, "Could not decode public key");
                ret = WS_CRYPTO_FAILED;
            }
        }
    }

    if (ret == WS_SUCCESS) {
        i = 0;
        /* Check that the signature's pubkey type matches the expected one. */
        ret = GetStringRef(&publicKeyTypeSz, &publicKeyType,
                pk->signature, pk->signatureSz, &i);
    }

    if (ret == WS_SUCCESS) {
        if (publicKeyTypeSz != pk->publicKeyTypeSz &&
            WMEMCMP(publicKeyType, pk->publicKeyType, publicKeyTypeSz) != 0) {

            WLOG(WS_LOG_DEBUG,
                 "Signature's type does not match public key type");
            ret = WS_INVALID_ALGO_ID;
        }
    }

    if (ret == WS_SUCCESS) {
        ret = GetMpint(&sigSz, &sig, pk->signature, pk->signatureSz, &i);
    }

    if (ret == WS_SUCCESS) {
        encDigestSz = wc_EncodeSignature(encDigest,
                digest, digestSz, wc_HashGetOID(hashId));
        ret = wolfSSH_RsaVerify(sig, sigSz, encDigest, encDigestSz,
                key, ssh->ctx->heap, "DoUserAuthRequestRsa");
    }

    wc_FreeRsaKey(key);
#ifdef WOLFSSH_SMALL_STACK
    if (key) {
        WFREE(key, ssh->ctx->heap, DYNTYPE_PUBKEY);
    }
    if (encDigest) {
        WFREE(encDigest, ssh->ctx->heap, DYNTYPE_BUFFER);
    }
#endif

    WLOG(WS_LOG_DEBUG, "Leaving DoUserAuthRequestRsa(), ret = %d", ret);
    return ret;
}


#ifdef WOLFSSH_CERTS
/* return WS_SUCCESS on success */
static int DoUserAuthRequestRsaCert(WOLFSSH* ssh, WS_UserAuthData_PublicKey* pk,
                                    enum wc_HashType hashId, byte* digest,
                                    word32 digestSz)
{
    const byte* publicKeyType;
    const byte* sig;
    word32 publicKeyTypeSz = 0;
    word32 sigSz;
    word32 encDigestSz;
    word32 i = 0;
    int ret = WS_SUCCESS;
#ifdef WOLFSSH_SMALL_STACK
    byte* encDigest = NULL;
    RsaKey* key = NULL;
#else
    byte encDigest[MAX_ENCODED_SIG_SZ];
    RsaKey key[1];
#endif

    WLOG(WS_LOG_DEBUG, "Entering DoUserAuthRequestRsaCert()");

    if (ssh == NULL || ssh->ctx == NULL || pk == NULL || digest == NULL ||
            digestSz == 0) {

        ret = WS_BAD_ARGUMENT;
    }

#ifdef WOLFSSH_SMALL_STACK
    if (ret == WS_SUCCESS) {
        encDigest = (byte*)WMALLOC(MAX_ENCODED_SIG_SZ,
                ssh->ctx->heap, DYNTYPE_BUFFER);
        if (encDigest == NULL)
            ret = WS_MEMORY_E;
    }
    if (ret == WS_SUCCESS) {
        key = (RsaKey*)WMALLOC(sizeof(RsaKey), ssh->ctx->heap, DYNTYPE_PUBKEY);
        if (key == NULL)
            ret = WS_MEMORY_E;
    }
#endif

    if (ret == WS_SUCCESS) {
        ret = wc_InitRsaKey(key, ssh->ctx->heap);
        if (ret == 0) {
            ret = WS_SUCCESS;
        }
    }

    /* Load up the key. */
    if (ret == WS_SUCCESS) {
        byte*  pub = NULL;
        word32 pubSz;
        DecodedCert cert;

        wc_InitDecodedCert(&cert, pk->publicKey, pk->publicKeySz,
                ssh->ctx->heap);
        ret = wc_ParseCert(&cert, CA_TYPE, 0, NULL);
        if (ret == 0) {
            ret = wc_GetPubKeyDerFromCert(&cert, NULL, &pubSz);
            if (ret == LENGTH_ONLY_E) {
                pub = (byte*)WMALLOC(pubSz, ssh->ctx->heap, DYNTYPE_PUBKEY);
                if (pub == NULL) {
                    ret = WS_MEMORY_E;
                }
                else {
                    ret = wc_GetPubKeyDerFromCert(&cert, pub, &pubSz);
                }
            }
        }

        if (ret == 0) {
            i = 0;
            ret = wc_RsaPublicKeyDecode(pub, &i, key, pubSz);
            if (ret != 0) {
                WLOG(WS_LOG_DEBUG, "Could not decode public key");
                ret = WS_CRYPTO_FAILED;
            }
        }

        if (pub != NULL)
            WFREE(pub, ssh->ctx->heap, DYNTYPE_PUBKEY);
        wc_FreeDecodedCert(&cert);
    }

    if (ret == WS_SUCCESS) {
        int keySz = wc_RsaEncryptSize(key) * 8;
        if (keySz < 2048) {
            WLOG(WS_LOG_DEBUG, "Key size too small (%d)", keySz);
            ret = WS_CERT_KEY_SIZE_E;
        }
    }

    if (ret == WS_SUCCESS) {
        i = 0;
        /* Check that the signature's pubkey type matches the expected one. */
        ret = GetStringRef(&publicKeyTypeSz, &publicKeyType,
                pk->signature, pk->signatureSz, &i);
    }

    if (ret == WS_SUCCESS) {
        if (publicKeyTypeSz != pk->publicKeyTypeSz &&
            WMEMCMP(publicKeyType, pk->publicKeyType, publicKeyTypeSz) != 0) {

            WLOG(WS_LOG_DEBUG,
                 "Signature's type does not match public key type");
            ret = WS_INVALID_ALGO_ID;
        }
    }

    if (ret == WS_SUCCESS) {
        ret = GetMpint(&sigSz, &sig, pk->signature, pk->signatureSz, &i);
    }

    if (ret == WS_SUCCESS) {
        encDigestSz = wc_EncodeSignature(encDigest,
                digest, digestSz, wc_HashGetOID(hashId));
        ret = wolfSSH_RsaVerify(sig, sigSz, encDigest, encDigestSz,
                key, ssh->ctx->heap, "DoUserAuthRequestRsaCert");
    }

    wc_FreeRsaKey(key);
#ifdef WOLFSSH_SMALL_STACK
    if (key) {
        WFREE(key, ssh->ctx->heap, DYNTYPE_PUBKEY);
    }
    if (encDigest) {
        WFREE(encDigest, ssh->ctx->heap, DYNTYPE_BUFFER);
    }
#endif

    WLOG(WS_LOG_DEBUG, "Leaving DoUserAuthRequestRsaCert(), ret = %d", ret);
    return ret;
}
#endif /* WOLFSSH_CERTS */
#endif /* ! WOLFSSH_NO_RSA */


#ifndef WOLFSSH_NO_ECDSA

#define ECDSA_ASN_SIG_SZ 256

/* Utility for DoUserAuthRequestPublicKey() */
/* returns negative for error, positive is size of digest. */
static int DoUserAuthRequestEcc(WOLFSSH* ssh, WS_UserAuthData_PublicKey* pk,
                                enum wc_HashType hashId, byte* digest,
                                word32 digestSz)
{
    const byte* publicKeyType;
    word32 publicKeyTypeSz = 0;
    const byte* curveName;
    word32 curveNameSz = 0;
    const byte* q = NULL;
    const byte* r;
    const byte* s;
    word32 sz, qSz, rSz, sSz;
    word32 i = 0, asnSigSz = ECDSA_ASN_SIG_SZ;
    int ret = WS_SUCCESS;
    ecc_key *key_ptr = NULL;
    byte* asnSig = NULL;
#ifndef WOLFSSH_SMALL_STACK
    ecc_key s_key;
    byte s_asnSig[ECDSA_ASN_SIG_SZ];
#endif

    WLOG(WS_LOG_DEBUG, "Entering DoUserAuthRequestEcc()");

    if (ssh == NULL || ssh->ctx == NULL || pk == NULL || digest == NULL ||
            digestSz == 0) {

        ret = WS_BAD_ARGUMENT;
    }

    if (ret == WS_SUCCESS) {
    #ifdef WOLFSSH_SMALL_STACK
        key_ptr = (ecc_key*)WMALLOC(sizeof(ecc_key), ssh->ctx->heap,
                DYNTYPE_PUBKEY);
        asnSig = (byte*)WMALLOC(asnSigSz, ssh->ctx->heap, DYNTYPE_STRING);
        if (key_ptr == NULL || asnSig == NULL)
            ret = WS_MEMORY_E;
    #else
        key_ptr = &s_key;
        asnSig = s_asnSig;
    #endif
    }

    if (ret == WS_SUCCESS) {
        if (wc_ecc_init_ex(key_ptr, ssh->ctx->heap, INVALID_DEVID) != 0) {
            ret = WS_MEMORY_E;
        }
    }

    /* First check that the public key's type matches the one we are
     * expecting. */
    if (ret == WS_SUCCESS)
        ret = GetSize(&publicKeyTypeSz, pk->publicKey, pk->publicKeySz, &i);

    if (ret == WS_SUCCESS) {
        publicKeyType = pk->publicKey + i;
        i += publicKeyTypeSz;
        if (publicKeyTypeSz != pk->publicKeyTypeSz &&
            WMEMCMP(publicKeyType, pk->publicKeyType, publicKeyTypeSz) != 0) {

            WLOG(WS_LOG_DEBUG,
                "Public Key's type does not match public key type");
            ret = WS_INVALID_ALGO_ID;
        }
    }

    if (ret == WS_SUCCESS)
        ret = GetSize(&curveNameSz, pk->publicKey, pk->publicKeySz, &i);

    if (ret == WS_SUCCESS) {
        curveName = pk->publicKey + i;
        WOLFSSH_UNUSED(curveName);
            /* Not used at the moment, hush the compiler. */
        i += curveNameSz;
        ret = GetSize(&qSz, pk->publicKey, pk->publicKeySz, &i);
    }

    if (ret == WS_SUCCESS) {
        q = pk->publicKey + i;
        i += qSz;
        ret = wc_ecc_import_x963(q, qSz, key_ptr);
    }

    if (ret != 0) {
        WLOG(WS_LOG_DEBUG, "Could not decode public key");
        ret = WS_CRYPTO_FAILED;
    }

    if (ret == WS_SUCCESS) {
        i = 0;
        /* First check that the signature's public key type matches the one
         * we are expecting. */
        ret = GetSize(&publicKeyTypeSz, pk->signature, pk->signatureSz, &i);
    }

    if (ret == WS_SUCCESS) {
        publicKeyType = pk->signature + i;
        i += publicKeyTypeSz;

        if (publicKeyTypeSz != pk->publicKeyTypeSz &&
            WMEMCMP(publicKeyType, pk->publicKeyType, publicKeyTypeSz) != 0) {

            WLOG(WS_LOG_DEBUG,
                 "Signature's type does not match public key type");
            ret = WS_INVALID_ALGO_ID;
        }
    }

    if (ret == WS_SUCCESS) {
        /* Get the size of the signature blob. */
        ret = GetSize(&sz, pk->signature, pk->signatureSz, &i);
    }

    if (ret == WS_SUCCESS) {
        ret = GetStringRef(&rSz, &r, pk->signature, pk->signatureSz, &i);
    }

    if (ret == WS_SUCCESS) {
        ret = GetStringRef(&sSz, &s, pk->signature, pk->signatureSz, &i);
    }

    if (ret == WS_SUCCESS) {
        ret = wc_ecc_rs_raw_to_sig(r, rSz, s, sSz,
                asnSig, &asnSigSz);
        if (ret == 0) {
            ret = WS_SUCCESS;
        }
        else {
            WLOG(WS_LOG_DEBUG,
                "DUARE: ECC RS raw to sig fail (%d)",
                ret);
            ret = WS_ECC_E;
        }
    }

    if (ret == WS_SUCCESS) {
        ret = wc_SignatureVerifyHash(
                         hashId,
                         WC_SIGNATURE_TYPE_ECC,
                         digest, digestSz, asnSig, asnSigSz,
                         key_ptr, sizeof *key_ptr);
        if (ret != 0) {
            WLOG(WS_LOG_DEBUG,
                "DUARE: Signature Verify fail (%d)",
                ret);
            ret = WS_ECC_E;
        }
        else {
            ret = WS_SUCCESS;
        }
    }

    if (key_ptr)
        wc_ecc_free(key_ptr);
#ifdef WOLFSSH_SMALL_STACK
    if (asnSig)
        WFREE(asnSig, ssh->ctx->heap, DYNTYPE_STRING);
    if (key_ptr)
        WFREE(key_ptr, ssh->ctx->heap, DYNTYPE_PUBKEY);
#endif
    WLOG(WS_LOG_DEBUG, "Leaving DoUserAuthRequestEcc(), ret = %d", ret);
    return ret;
}


#ifdef WOLFSSH_CERTS
static int DoUserAuthRequestEccCert(WOLFSSH* ssh, WS_UserAuthData_PublicKey* pk,
                                    enum wc_HashType hashId, byte* digest,
                                    word32 digestSz)
{
    const byte* publicKeyType;
    word32 publicKeyTypeSz = 0;
    const byte* r;
    const byte* s;
    word32 sz, rSz, sSz;
    word32 i = 0, asnSigSz = ECDSA_ASN_SIG_SZ;
    int ret = WS_SUCCESS;
    ecc_key *key_ptr = NULL;
    byte* asnSig = NULL;
#ifndef WOLFSSH_SMALL_STACK
    ecc_key s_key;
    byte s_asnSig[ECDSA_ASN_SIG_SZ];
#endif

    WLOG(WS_LOG_DEBUG, "Entering DoUserAuthRequestEccCert()");

    if (ssh == NULL || ssh->ctx == NULL || pk == NULL || digest == NULL ||
            digestSz == 0) {

        ret = WS_BAD_ARGUMENT;
    }

    if (ret == WS_SUCCESS) {
    #ifdef WOLFSSH_SMALL_STACK
        key_ptr = (ecc_key*)WMALLOC(sizeof(ecc_key), ssh->ctx->heap,
                DYNTYPE_PUBKEY);
        asnSigSz = ECDSA_ASN_SIG_SZ;
        asnSig = (byte*)WMALLOC(asnSigSz, ssh->ctx->heap, DYNTYPE_STRING);
        if (key_ptr == NULL || asnSig == NULL)
            ret = WS_MEMORY_E;
    #else
        key_ptr = &s_key;
        asnSig = s_asnSig;
    #endif
    }

    if (ret == WS_SUCCESS) {
        if (wc_ecc_init_ex(key_ptr, ssh->ctx->heap, INVALID_DEVID) != 0) {
            ret = WS_MEMORY_E;
        }
    }

    if (ret == WS_SUCCESS) {
        byte*  pub = NULL;
        word32 pubSz;
        DecodedCert cert;

        wc_InitDecodedCert(&cert, pk->publicKey, pk->publicKeySz,
                ssh->ctx->heap);
        ret = wc_ParseCert(&cert, CA_TYPE, 0, NULL);
        if (ret == 0) {
            ret = wc_GetPubKeyDerFromCert(&cert, NULL, &pubSz);
            if (ret == LENGTH_ONLY_E) {
                pub = (byte*)WMALLOC(pubSz, ssh->ctx->heap, DYNTYPE_PUBKEY);
                if (pub == NULL) {
                    ret = WS_MEMORY_E;
                }
                else {
                    ret = wc_GetPubKeyDerFromCert(&cert, pub, &pubSz);
                }
            }
        }

        if (ret == 0) {
            word32 idx = 0;
            ret = wc_EccPublicKeyDecode(pub, &idx, key_ptr, pubSz);
        }

        if (pub != NULL)
            WFREE(pub, ssh->ctx->heap, DYNTYPE_PUBKEY);
        wc_FreeDecodedCert(&cert);
    }

    if (ret != 0) {
        WLOG(WS_LOG_DEBUG, "Could not decode public key");
        ret = WS_CRYPTO_FAILED;
    }

    if (ret == WS_SUCCESS) {
        i = 0;
        /* First check that the signature's public key type matches the one
         * we are expecting. */
        ret = GetSize(&publicKeyTypeSz, pk->signature, pk->signatureSz, &i);
    }

    if (ret == WS_SUCCESS) {
        publicKeyType = pk->signature + i;
        i += publicKeyTypeSz;
        WOLFSSH_UNUSED(publicKeyType);
    }

    if (ret == WS_SUCCESS) {
        /* Get the size of the signature blob. */
        ret = GetSize(&sz, pk->signature, pk->signatureSz, &i);
    }

    if (ret == WS_SUCCESS) {
        ret = GetStringRef(&rSz, &r, pk->signature, pk->signatureSz, &i);
    }

    if (ret == WS_SUCCESS) {
        ret = GetStringRef(&sSz, &s, pk->signature, pk->signatureSz, &i);
    }

    if (ret == WS_SUCCESS) {
        ret = wc_ecc_rs_raw_to_sig(r, rSz, s, sSz,
                asnSig, &asnSigSz);
        if (ret == 0) {
            ret = WS_SUCCESS;
        }
        else {
            WLOG(WS_LOG_DEBUG,
                "DUAREC: ECC RS raw to sig fail (%d)",
                ret);
            ret = WS_ECC_E;
        }
    }

    if (ret == WS_SUCCESS) {
        ret = wc_SignatureVerifyHash(
                         hashId,
                         WC_SIGNATURE_TYPE_ECC,
                         digest, digestSz, asnSig, asnSigSz,
                         key_ptr, sizeof *key_ptr);
        if (ret != 0) {
            WLOG(WS_LOG_DEBUG,
                "DUAREC: Signature Verify fail (%d)",
                ret);
            ret = WS_ECC_E;
        }
        else {
            ret = WS_SUCCESS;
        }
    }

    if (key_ptr)
        wc_ecc_free(key_ptr);
#ifdef WOLFSSH_SMALL_STACK
    if (asnSig)
        WFREE(asnSig, ssh->ctx->heap, DYNTYPE_STRING);
    if (key_ptr)
        WFREE(key_ptr, ssh->ctx->heap, DYNTYPE_PUBKEY);
#endif
    WLOG(WS_LOG_DEBUG, "Leaving DoUserAuthRequestEccCert(), ret = %d", ret);
    return ret;
}
#endif /* WOLFSSH_CERTS */
#endif /* ! WOLFSSH_NO_ECDSA */


#ifndef WOLFSSH_NO_ED25519
static int DoUserAuthRequestEd25519(WOLFSSH* ssh,
        WS_UserAuthData_PublicKey* pk, WS_UserAuthData* authData)
{
    const byte* publicKeyType;
    byte temp[32];
    word32 publicKeyTypeSz = 0;
    word32 sz, qSz;
    word32 i = 0;
    int ret = WS_SUCCESS;
    ed25519_key *key_ptr = NULL;
#ifndef WOLFSSH_SMALL_STACK
    ed25519_key s_key;
#endif

    WLOG(WS_LOG_DEBUG, "Entering DoUserAuthRequestEd25519()");

    if (ssh == NULL || ssh->ctx == NULL || pk == NULL || authData == NULL) {
        ret = WS_BAD_ARGUMENT;
    }

    if (ret == WS_SUCCESS) {
#ifdef WOLFSSH_SMALL_STACK
    key_ptr = (ed25519_key*)WMALLOC(sizeof(ed25519_key), ssh->ctx->heap,
            DYNTYPE_PUBKEY);
    if (key_ptr == NULL)
        ret = WS_MEMORY_E;
#else
    key_ptr = &s_key;
#endif
    }

    if (ret == WS_SUCCESS) {
        ret = wc_ed25519_init_ex(key_ptr, ssh->ctx->heap, INVALID_DEVID);
        if (ret == 0) {
            ret = WS_SUCCESS;
        }
    }

    /* First check that the public key's type matches the one we are
     * expecting. */
    if (ret == WS_SUCCESS)
        ret = GetSize(&publicKeyTypeSz, pk->publicKey, pk->publicKeySz, &i);

    if (ret == WS_SUCCESS) {
        publicKeyType = pk->publicKey + i;
        i += publicKeyTypeSz;
        if (publicKeyTypeSz != pk->publicKeyTypeSz
                && WMEMCMP(publicKeyType,
                        pk->publicKeyType, publicKeyTypeSz) != 0) {
            WLOG(WS_LOG_DEBUG,
                "Public Key's type does not match public key type");
            ret = WS_INVALID_ALGO_ID;
        }
    }
    if (ret == WS_SUCCESS) {
        ret = GetSize(&qSz, pk->publicKey, pk->publicKeySz, &i);
    }

    if (ret == WS_SUCCESS) {
        ret = wc_ed25519_import_public(pk->publicKey + i, qSz, key_ptr);
    }

    if (ret != 0) {
        WLOG(WS_LOG_DEBUG, "Could not decode public key");
        ret = WS_CRYPTO_FAILED;
    }

    if (ret == WS_SUCCESS) {
        i = 0;
        /* First check that the signature's public key type matches the one
         * we are expecting. */
        ret = GetSize(&publicKeyTypeSz, pk->signature, pk->signatureSz, &i);
    }

    if (ret == WS_SUCCESS) {
        publicKeyType = pk->signature + i;
        i += publicKeyTypeSz;

        if (publicKeyTypeSz != pk->publicKeyTypeSz &&
            WMEMCMP(publicKeyType, pk->publicKeyType, publicKeyTypeSz) != 0) {

            WLOG(WS_LOG_DEBUG,
                 "Signature's type does not match public key type");
            ret = WS_INVALID_ALGO_ID;
        }
    }

    if (ret == WS_SUCCESS) {
        /* Get the size of the signature blob. */
        ret = GetSize(&sz, pk->signature, pk->signatureSz, &i);
    }

    if (ret == WS_SUCCESS) {
        ret = wc_ed25519_verify_msg_init(pk->signature + i, sz,
                key_ptr, (byte)Ed25519, NULL, 0);
    }

    if (ret == WS_SUCCESS) {
        c32toa(ssh->sessionIdSz, temp);
        ret = wc_ed25519_verify_msg_update(temp, UINT32_SZ, key_ptr);
    }

    if (ret == WS_SUCCESS) {
        ret = wc_ed25519_verify_msg_update(ssh->sessionId, ssh->sessionIdSz,
                key_ptr);
    }

    if(ret == WS_SUCCESS) {
        temp[0] = MSGID_USERAUTH_REQUEST;
        ret = wc_ed25519_verify_msg_update(temp, MSG_ID_SZ, key_ptr);
    }

    /* The rest of the fields in the signature are already
    * in the buffer. Just need to account for the sizes. */
    if(ret == WS_SUCCESS) {
        ret = wc_ed25519_verify_msg_update(pk->dataToSign,
                                    authData->usernameSz +
                                    authData->serviceNameSz +
                                    authData->authNameSz + BOOLEAN_SZ +
                                    pk->publicKeyTypeSz + pk->publicKeySz +
                                    (UINT32_SZ * 5), key_ptr);
    }

    if(ret == WS_SUCCESS) {
        int status = 0;
        ret = wc_ed25519_verify_msg_final(pk->signature + i, sz,
                &status, key_ptr);
        if (ret != 0) {
            WLOG(WS_LOG_DEBUG, "Could not verify signature");
            ret = WS_CRYPTO_FAILED;
        }
        else
            ret = status ? WS_SUCCESS : WS_ED25519_E;
    }

    if (key_ptr) {
        wc_ed25519_free(key_ptr);
#ifdef WOLFSSH_SMALL_STACK
        WFREE(key_ptr, ssh->ctx->heap, DYNTYPE_PUBKEY);
#endif
    }

    WLOG(WS_LOG_DEBUG, "Leaving DoUserAuthRequestEd25519(), ret = %d", ret);
    return ret;
}
#endif /* !WOLFSSH_NO_ED25519 */

#if !defined(WOLFSSH_NO_RSA) || !defined(WOLFSSH_NO_ECDSA)
/* Utility for DoUserAuthRequest() */
static int DoUserAuthRequestPublicKey(WOLFSSH* ssh, WS_UserAuthData* authData,
                                      byte* buf, word32 len, word32* idx)
{
    const byte* pubKeyAlgo = NULL;
    const byte* pubKeyBlob = NULL;
    const byte* pubKeyFmt = NULL;
    const byte* sig = NULL;
    const byte* sigAlgo = NULL;
    const byte* sigBlob = NULL;
    word32 pubKeyAlgoSz = 0;
    word32 pubKeyBlobSz = 0;
    word32 pubKeyFmtSz = 0;
    word32 sigSz = 0;
    word32 sigAlgoSz = 0;
    word32 sigBlobSz = 0;
    word32 begin;
    int ret = WS_SUCCESS;
    int authFailure = 0;
    int partialSuccess = 0;
    byte hasSig = 0;
    byte pkTypeId = ID_NONE;

    WLOG(WS_LOG_DEBUG, "Entering DoUserAuthRequestPublicKey()");

    if (ssh == NULL || authData == NULL ||
        buf == NULL || len == 0 || idx == NULL) {

        ret = WS_BAD_ARGUMENT;
    }

    /* Parse the message first. */
    if (ret == WS_SUCCESS) {
        begin = *idx;
        ret = GetBoolean(&hasSig, buf, len, &begin);
    }
    if (ret == WS_SUCCESS) {
        ret = GetStringRef(&pubKeyAlgoSz, &pubKeyAlgo, buf, len, &begin);
    }
    if (ret == WS_SUCCESS) {
        ret = GetStringRef(&pubKeyBlobSz, &pubKeyBlob, buf, len, &begin);
    }
    if (ret == WS_SUCCESS && hasSig) {
        ret = GetStringRef(&sigSz, &sig, buf, len, &begin);
    }
    if (ret == WS_SUCCESS) {
        *idx = begin;
    }

    /* Fill out the authData. */
    if (ret == WS_SUCCESS) {
        authData->type = WOLFSSH_USERAUTH_PUBLICKEY;
        authData->sf.publicKey.hasSignature = hasSig;
        authData->sf.publicKey.publicKeyType = pubKeyAlgo;
        authData->sf.publicKey.publicKeyTypeSz = pubKeyAlgoSz;
        authData->sf.publicKey.publicKey = pubKeyBlob;
        authData->sf.publicKey.publicKeySz = pubKeyBlobSz;
        authData->sf.publicKey.signature = sig;
        authData->sf.publicKey.signatureSz = sigSz;
    }

    /* Parse the public key format, signature algo, and signature blob. */
    if (ret == WS_SUCCESS) {
        begin = 0;
        ret = GetStringRef(&pubKeyFmtSz, &pubKeyFmt,
                pubKeyBlob, pubKeyBlobSz, &begin);
    }

    if (hasSig) {
        if (ret == WS_SUCCESS) {
            begin = 0;
            ret = GetStringRef(&sigAlgoSz, &sigAlgo, sig, sigSz, &begin);
        }
        if (ret == WS_SUCCESS) {
            ret = GetStringRef(&sigBlobSz, &sigBlob, sig, sigSz, &begin);
        }
    }

    if (ret == WS_SUCCESS) {
        pkTypeId = NameToId((const char*)pubKeyAlgo, pubKeyAlgoSz);
        if (pkTypeId == ID_UNKNOWN) {
            WLOG(WS_LOG_DEBUG, "DUARPK: Unknown / Unsupported key type");
            authFailure = 1;
        }
    }
    if (ret == WS_SUCCESS && !authFailure) {
        byte matchId;

        matchId = MatchIdLists(WOLFSSH_ENDPOINT_SERVER, &pkTypeId, 1,
                cannedKeyAlgoClient, cannedKeyAlgoClientSz);
        if (matchId == ID_UNKNOWN) {
            WLOG(WS_LOG_DEBUG, "DUARPK: Signature type unsupported");
            authFailure = 1;
        }
    }

    #ifdef WOLFSSH_CERTS
    if (ret == WS_SUCCESS && !authFailure) {
        if (pkTypeId == ID_X509V3_SSH_RSA
                || pkTypeId == ID_X509V3_ECDSA_SHA2_NISTP256
                || pkTypeId == ID_X509V3_ECDSA_SHA2_NISTP384
                || pkTypeId == ID_X509V3_ECDSA_SHA2_NISTP521) {
            byte *cert = NULL;
            word32 certSz = 0;

            if (hasSig) {
                ret = ParseCertChainVerify(ssh,
                        (byte*)pubKeyBlob, pubKeyBlobSz, &cert, &certSz);
            }
            else {
                ret = ParseLeafCert((byte*)pubKeyBlob, pubKeyBlobSz,
                        &cert, &certSz);
            }
            if (ret == WS_SUCCESS) {
                authData->sf.publicKey.publicKey = cert;
                authData->sf.publicKey.publicKeySz = certSz;
                authData->sf.publicKey.isCert = 1;
            }
            else {
                WLOG(WS_LOG_DEBUG, "DUARPK: cannot parse client cert chain");
                ret = WS_SUCCESS;
                authFailure = 1;
            }
        }
    }
    #endif /* WOLFSSH_CERTS */

    if (ret == WS_SUCCESS && !authFailure) {
        if (ssh->ctx->userAuthCb != NULL) {
            WLOG(WS_LOG_DEBUG, "DUARPK: Calling the userauth callback");
            ret = ssh->ctx->userAuthCb(WOLFSSH_USERAUTH_PUBLICKEY,
                                       authData, ssh->userAuthCtx);
            WLOG(WS_LOG_DEBUG, "DUARPK: callback result = %d", ret);

        #ifdef DEBUG_WOLFSSH
            switch (ret) {
                case WOLFSSH_USERAUTH_SUCCESS:
                    WLOG(WS_LOG_DEBUG, "DUARPK: user auth success");
                    break;

                case WOLFSSH_USERAUTH_INVALID_PUBLICKEY:
                    WLOG(WS_LOG_DEBUG, "DUARPK: client key invalid");
                    break;

                case WOLFSSH_USERAUTH_INVALID_USER:
                    WLOG(WS_LOG_DEBUG, "DUARPK: public key user rejected");
                    break;

                case WOLFSSH_USERAUTH_FAILURE:
                    WLOG(WS_LOG_DEBUG, "DUARPK: public key general failure");
                    break;

                case WOLFSSH_USERAUTH_INVALID_AUTHTYPE:
                    WLOG(WS_LOG_DEBUG, "DUARPK: public key invalid auth type");
                    break;

                case WOLFSSH_USERAUTH_REJECTED:
                    WLOG(WS_LOG_DEBUG, "DUARPK: public key rejected");
                    break;

                case WOLFSSH_USERAUTH_PARTIAL_SUCCESS:
                    WLOG(WS_LOG_DEBUG, "DUARPK: user auth partial success");
                    break;

                case WOLFSSH_USERAUTH_WOULD_BLOCK:
                    WLOG(WS_LOG_DEBUG, "DUARPK: userauth callback would block");
                    break;

                default:
                    WLOG(WS_LOG_DEBUG,
                        "Unexpected return value from Auth callback");
            }
        #endif

            if (ret == WOLFSSH_USERAUTH_WOULD_BLOCK) {
                ret = WS_AUTH_PENDING;
            }
            else {
                if (ret == WOLFSSH_USERAUTH_PARTIAL_SUCCESS) {
                    partialSuccess = 1;
                }
                else if (ret != WOLFSSH_USERAUTH_SUCCESS) {
                    authFailure = 1;
                }
                ret = WS_SUCCESS;
            }
        }
        else {
            WLOG(WS_LOG_DEBUG, "DUARPK: no userauth callback set");
            authFailure = 1;
        }
    }

    if (ret == WS_SUCCESS && !authFailure) {
        if (!hasSig) {
            WLOG(WS_LOG_DEBUG, "DUARPK: Send the PK OK");
            ret = SendUserAuthPkOk(ssh,
                    pubKeyAlgo, pubKeyAlgoSz, pubKeyBlob, pubKeyBlobSz);
        }
        else {
            if (pkTypeId == ID_ED25519) {
#ifndef WOLFSSH_NO_ED25519
                ret = DoUserAuthRequestEd25519(ssh,
                        &authData->sf.publicKey, authData);
#else
                ret = WS_INVALID_ALGO_ID;
#endif
            } else {
                wc_HashAlg hash;
                byte digest[WC_MAX_DIGEST_SIZE];
                word32 digestSz = 0;
                enum wc_HashType hashId = WC_HASH_TYPE_SHA;

                if (ret == WS_SUCCESS) {
                    hashId = HashForId(pkTypeId);
                    WMEMSET(digest, 0, sizeof(digest));
                    ret = wc_HashGetDigestSize(hashId);
                    if (ret > 0) {
                        digestSz = ret;
                        ret = 0;
                    }
                }

                if (ret == 0)
                    ret = wc_HashInit(&hash, hashId);

                if (ret == 0) {
                    c32toa(ssh->sessionIdSz, digest);
                    ret = HashUpdate(&hash, hashId, digest, UINT32_SZ);
                }

                if (ret == 0)
                    ret = HashUpdate(&hash, hashId,
                                        ssh->sessionId, ssh->sessionIdSz);

                if (ret == 0) {
                    digest[0] = MSGID_USERAUTH_REQUEST;
                    ret = HashUpdate(&hash, hashId, digest, MSG_ID_SZ);
                }

                /* The rest of the fields in the signature are already
                 * in the buffer. Just need to account for the sizes, which
                 * total the length of the buffer minus the signature and
                 * size of signature. */
                if (ret == 0) {
                    ret = HashUpdate(&hash, hashId,
                            authData->sf.publicKey.dataToSign,
                            len - sigSz - LENGTH_SZ);
                }
                if (ret == 0) {
                    ret = wc_HashFinal(&hash, hashId, digest);

                    if (ret != 0)
                        ret = WS_CRYPTO_FAILED;
                    else
                        ret = WS_SUCCESS;
                }
                wc_HashFree(&hash, hashId);

                if (ret == WS_SUCCESS) {
                    WLOG(WS_LOG_DEBUG, "Verify user signature type: %s",
                            IdToName(pkTypeId));

                    switch (pkTypeId) {
                        #ifndef WOLFSSH_NO_RSA
                        case ID_SSH_RSA:
                        case ID_RSA_SHA2_256:
                        case ID_RSA_SHA2_512:
                            ret = DoUserAuthRequestRsa(ssh,
                                    &authData->sf.publicKey,
                                    hashId, digest, digestSz);
                            break;
                        #ifdef WOLFSSH_CERTS
                        case ID_X509V3_SSH_RSA:
                            ret = DoUserAuthRequestRsaCert(ssh,
                                    &authData->sf.publicKey,
                                    hashId, digest, digestSz);
                            break;
                        #endif
                        #endif
                        #ifndef WOLFSSH_NO_ECDSA
                        case ID_ECDSA_SHA2_NISTP256:
                        case ID_ECDSA_SHA2_NISTP384:
                        case ID_ECDSA_SHA2_NISTP521:
                            ret = DoUserAuthRequestEcc(ssh,
                                    &authData->sf.publicKey,
                                    hashId, digest, digestSz);
                            break;
                        #ifdef WOLFSSH_CERTS
                        case ID_X509V3_ECDSA_SHA2_NISTP256:
                        case ID_X509V3_ECDSA_SHA2_NISTP384:
                        case ID_X509V3_ECDSA_SHA2_NISTP521:
                            ret = DoUserAuthRequestEccCert(ssh,
                                    &authData->sf.publicKey,
                                    hashId, digest, digestSz);
                            break;
                        #endif
                        #endif
                        default:
                            ret = WS_INVALID_ALGO_ID;
                    }
                }
            }

            if (ret != WS_SUCCESS) {
                if (ssh->ctx->userAuthResultCb) {
                    ssh->ctx->userAuthResultCb(WOLFSSH_USERAUTH_FAILURE,
                            authData, ssh->userAuthResultCtx);
                }
                WLOG(WS_LOG_DEBUG, "DUARPK: signature compare failure : [%d]",
                        ret);
                authFailure = 1;
            }
            else {
                if (ssh->ctx->userAuthResultCb) {
                    if (ssh->ctx->userAuthResultCb(WOLFSSH_USERAUTH_SUCCESS,
                            authData, ssh->userAuthResultCtx) != WS_SUCCESS) {

                        WLOG(WS_LOG_DEBUG, "DUARPK: user overriding success");
                        authFailure = 1;
                    }
                }
                if (!authFailure && !partialSuccess) {
                    ssh->clientState = CLIENT_USERAUTH_DONE;
                }
            }
        }
    }

    if (authFailure) {
        ret = SendUserAuthFailure(ssh, 0);
    }
    else if (partialSuccess && hasSig) {
        ret = SendUserAuthFailure(ssh, 1);
    }

    WLOG(WS_LOG_DEBUG, "Leaving DoUserAuthRequestPublicKey(), ret = %d", ret);
    return ret;
}
#endif


static int DoUserAuthRequest(WOLFSSH* ssh,
                             byte* buf, word32 len, word32* idx)
{
    word32 begin;
    int ret = WS_SUCCESS;
    byte authNameId;
    WS_UserAuthData authData;

    WLOG(WS_LOG_DEBUG, "Entering DoUserAuthRequest()");

    if (ssh == NULL || buf == NULL || len == 0 || idx == NULL)
        ret = WS_BAD_ARGUMENT;

    if (ret == WS_SUCCESS) {
        begin = *idx;
        WMEMSET(&authData, 0, sizeof(authData));
        ret = GetSize(&authData.usernameSz, buf, len, &begin);
    }

    if (ret == WS_SUCCESS) {
        authData.username = buf + begin;
        begin += authData.usernameSz;

        ret = GetUint32(&authData.serviceNameSz, buf, len, &begin);
    }

    if (ret == WS_SUCCESS) {
        if (authData.serviceNameSz > len - begin) {
            ret = WS_BUFFER_E;
        }
    }

    if (ret == WS_SUCCESS) {
        authData.serviceName = buf + begin;
        begin += authData.serviceNameSz;

        ret = GetSize(&authData.authNameSz, buf, len, &begin);
    }

    if (ret == WS_SUCCESS) {
        authData.authName = buf + begin;
        begin += authData.authNameSz;
        authNameId = NameToId((char*)authData.authName, authData.authNameSz);

        if (authNameId == ID_USERAUTH_PASSWORD)
            ret = DoUserAuthRequestPassword(ssh, &authData, buf, len, &begin);
#if !defined(WOLFSSH_NO_RSA) || !defined(WOLFSSH_NO_ECDSA)
        else if (authNameId == ID_USERAUTH_PUBLICKEY) {
            authData.sf.publicKey.dataToSign = buf + *idx;
            ret = DoUserAuthRequestPublicKey(ssh, &authData, buf, len, &begin);
        }
#endif
#ifdef WOLFSSH_ALLOW_USERAUTH_NONE
        else if (authNameId == ID_NONE) {
            ret = DoUserAuthRequestNone(ssh, &authData, buf, len, &begin);
        }
#endif
        else {
            WLOG(WS_LOG_DEBUG,
                 "invalid userauth type: %s", IdToName(authNameId));
            ret = SendUserAuthFailure(ssh, 0);
        }

        if (ret == WS_SUCCESS) {
            ret = wolfSSH_SetUsernameRaw(ssh,
                    authData.username, authData.usernameSz);
        }

        *idx = begin;
    }

    WLOG(WS_LOG_DEBUG, "Leaving DoUserAuthRequest(), ret = %d", ret);
    return ret;
}


static int DoUserAuthFailure(WOLFSSH* ssh,
                             byte* buf, word32 len, word32* idx)
{
    byte authList[3]; /* Should only ever be password, publickey, hostname */
    word32 authListSz = 3;
    byte partialSuccess;
    byte authType = 0;
    int ret = WS_SUCCESS;

    WLOG(WS_LOG_DEBUG, "Entering DoUserAuthFailure()");

    if (ssh == NULL || buf == NULL || len == 0 || idx == NULL)
        ret = WS_BAD_ARGUMENT;

    if (ret == WS_SUCCESS)
        ret = GetNameList(authList, &authListSz, buf, len, idx);

    if (ret == WS_SUCCESS)
        ret = GetBoolean(&partialSuccess, buf, len, idx);

    if (ret == WS_SUCCESS) {
        word32 i;

        /* check authList to see if authId is there */
        for (i = 0; i < authListSz; i++) {
            word32 j;
            for (j = 0; j < sizeof(ssh->supportedAuth); j++) {
                if (authList[i] == ssh->supportedAuth[j]) {
                    switch(authList[i]) {
                        case ID_USERAUTH_PASSWORD:
                            authType |= WOLFSSH_USERAUTH_PASSWORD;
                            break;
#if !defined(WOLFSSH_NO_RSA) || !defined(WOLFSSH_NO_ECDSA)
                        case ID_USERAUTH_PUBLICKEY:
                            authType |= WOLFSSH_USERAUTH_PUBLICKEY;
                            break;
#endif
                        default:
                            break;
                    }
                }
            }
        }

        /* the auth type attempted was not in the list */
        if (authType == 0) {
            WLOG(WS_LOG_DEBUG, "Did not match any auth IDs in peers list");
            ret = WS_USER_AUTH_E;
        }
    }

    if (ret == WS_SUCCESS) {
        ret = SendUserAuthRequest(ssh, authType, 0);
    }

    WLOG(WS_LOG_DEBUG, "Leaving DoUserAuthFailure(), ret = %d", ret);
    return ret;
}


static int DoUserAuthSuccess(WOLFSSH* ssh,
                             byte* buf, word32 len, word32* idx)
{
    int ret = WS_SUCCESS;

    WLOG(WS_LOG_DEBUG, "Entering DoUserAuthSuccess()");

    /* This message does not have any payload. len should be 0. */
    if (ssh == NULL || buf == NULL || len != 0 || idx == NULL) {
        ret = WS_BAD_ARGUMENT;
        WLOG(WS_LOG_DEBUG, "Leaving DoUserAuthSuccess(), ret = %d", ret);
        return ret;
    }

    ssh->serverState = SERVER_USERAUTH_ACCEPT_DONE;

    WLOG(WS_LOG_DEBUG, "Leaving DoUserAuthSuccess(), ret = %d", ret);
    return ret;
}


static int DoUserAuthBanner(WOLFSSH* ssh, byte* buf, word32 len, word32* idx)
{
    char banner[80];
    word32 bannerSz = (word32)sizeof(banner);
    int ret = WS_SUCCESS;

    WLOG(WS_LOG_DEBUG, "Entering DoUserAuthBanner()");

    if (ssh == NULL || buf == NULL || len == 0 || idx == NULL)
        ret = WS_BAD_ARGUMENT;

    if (ret == WS_SUCCESS)
        ret = GetString(banner, &bannerSz, buf, len, idx);

    if (ret == WS_SUCCESS)
        ret = GetSize(&bannerSz, buf, len, idx);

    if (ret == WS_SUCCESS) {
        if (ssh->ctx->showBanner) {
            WLOG(WS_LOG_INFO, "%s", banner);
        }
    }

    WLOG(WS_LOG_DEBUG, "Leaving DoUserAuthBanner(), ret = %d", ret);
    return ret;
}


#ifdef WOLFSSH_FWD
static int DoGlobalRequestFwd(WOLFSSH* ssh,
        byte* buf, word32 len, word32* idx, int wantReply, int isCancel)
{
    word32 begin;
    int ret = WS_SUCCESS;
    char* bindAddr = NULL;
    word32 bindPort;

    WLOG(WS_LOG_DEBUG, "Entering DoGlobalRequestFwd()");

    if (ssh == NULL || buf == NULL || len == 0 || idx == NULL) {
        ret = WS_BAD_ARGUMENT;
    }

    if (ret == WS_SUCCESS) {
        begin = *idx;
        WLOG(WS_LOG_INFO, "wantReply = %d, isCancel = %d", wantReply, isCancel);
        ret = GetStringAlloc(ssh->ctx->heap, &bindAddr, buf, len, &begin);
    }

    if (ret == WS_SUCCESS) {
        ret = GetUint32(&bindPort, buf, len, &begin);
    }

    if (ret == WS_SUCCESS) {
        WLOG(WS_LOG_INFO, "Requesting forwarding%s for address %s on port %u.",
                isCancel ? " cancel" : "", bindAddr, bindPort);
    }

    if (ret == WS_SUCCESS && wantReply) {
        ret = SendGlobalRequestFwdSuccess(ssh, 1, bindPort);
    }

    if (ret == WS_SUCCESS) {
        if (ssh->ctx->fwdCb) {
            ret = ssh->ctx->fwdCb(isCancel ? WOLFSSH_FWD_REMOTE_CLEANUP :
                        WOLFSSH_FWD_REMOTE_SETUP,
                    ssh->fwdCbCtx, bindAddr, bindPort);
        }
    }

    if (bindAddr != NULL)
        WFREE(bindAddr, ssh->ctx->heap, DYNTYPE_STRING);

    WLOG(WS_LOG_DEBUG, "Leaving DoGlobalRequestFwd(), ret = %d", ret);
    return ret;
}
#endif

static int DoGlobalRequest(WOLFSSH* ssh,
                           byte* buf, word32 len, word32* idx)
{
    word32 begin;
    int ret = WS_SUCCESS;
    char name[80];
    word32 nameSz = (word32)sizeof(name);
    int globReqId = ID_UNKNOWN;
    byte wantReply = 0;

    WLOG(WS_LOG_DEBUG, "Entering DoGlobalRequest()");

    if (ssh == NULL || buf == NULL || len == 0 || idx == NULL) {
        ret = WS_BAD_ARGUMENT;
        WLOG(WS_LOG_DEBUG, "Leaving DoGlobalRequest(), ret = %d", ret);
        return ret;
    }

    if (ret == WS_SUCCESS) {
        begin = *idx;
        ret = GetString(name, &nameSz, buf, len, &begin);
    }

    if (ret == WS_SUCCESS) {
        WLOG(WS_LOG_DEBUG, "DGR: request name = %s", name);
        globReqId = NameToId(name, nameSz);
        ret = GetBoolean(&wantReply, buf, len, &begin);
    }

    if (ret == WS_SUCCESS) {
        switch (globReqId) {
#ifdef WOLFSSH_FWD
            case ID_GLOBREQ_TCPIP_FWD:
                ret = DoGlobalRequestFwd(ssh, buf, len, &begin, wantReply, 0);
                wantReply = 0;
                break;
            case ID_GLOBREQ_TCPIP_FWD_CANCEL:
                ret = DoGlobalRequestFwd(ssh, buf, len, &begin, wantReply, 1);
                wantReply = 0;
                break;
#endif
            default:
                if (ssh->ctx->globalReqCb != NULL) {
                    ret = ssh->ctx->globalReqCb(ssh, name, nameSz, wantReply,
                            (void *)ssh->globalReqCtx);

                    if (wantReply) {
                        ret = SendRequestSuccess(ssh, (ret == WS_SUCCESS));
                    }
                }
                else if (wantReply)
                    ret = SendRequestSuccess(ssh, 0);
                    /* response SSH_MSG_REQUEST_FAILURE to Keep-Alive.
                     * IETF:draft-ssh-global-requests */
                break;
        }
    }

    if (ret == WS_SUCCESS) {
        *idx += len;
    }

    WLOG(WS_LOG_DEBUG, "Leaving DoGlobalRequest(), ret = %d", ret);
    return ret;
}


#ifdef WOLFSSH_FWD
static int DoChannelOpenForward(WOLFSSH* ssh,
                         char** host, word32* hostPort,
                         char** origin, word32* originPort,
                         byte* buf, word32 len, word32* idx)
{
    word32 begin;
    int ret = WS_SUCCESS;

    WLOG(WS_LOG_DEBUG, "Entering DoChannelOpenForward()");

    if (idx == NULL)
        ret = WS_BAD_ARGUMENT;

    if (ret == WS_SUCCESS) {
        begin = *idx;
        ret = GetStringAlloc(ssh->ctx->heap, host, buf, len, &begin);
    }

    if (ret == WS_SUCCESS)
        ret = GetUint32(hostPort, buf, len, &begin);

    if (ret == WS_SUCCESS)
        ret = GetStringAlloc(ssh->ctx->heap, origin, buf, len, &begin);

    if (ret == WS_SUCCESS)
        ret = GetUint32(originPort, buf, len, &begin);

    if (ret == WS_SUCCESS) {
        *idx = begin;
        WLOG(WS_LOG_INFO, "  host = %s:%u", *host, *hostPort);
        WLOG(WS_LOG_INFO, "  origin = %s:%u", *origin, *originPort);
    }
    else {
        WFREE(*host, ssh->ctx->heap, DYNTYPE_STRING);
        WFREE(*origin, ssh->ctx->heap, DYNTYPE_STRING);
        *host = NULL;
        *origin = NULL;
    }

    WLOG(WS_LOG_DEBUG, "Leaving DoChannelOpenForward(), ret = %d", ret);
    return ret;
}
#endif /* WOLFSSH_FWD */


static int DoChannelOpen(WOLFSSH* ssh,
                         byte* buf, word32 len, word32* idx)
{
    word32 begin;
    word32 typeSz;
    char type[32];
    byte typeId = ID_UNKNOWN;
    word32 peerChannelId = 0;
    word32 peerInitialWindowSz;
    word32 peerMaxPacketSz;
#ifdef WOLFSSH_FWD
    char* host = NULL;
    char* origin = NULL;
    word32 hostPort = 0, originPort = 0;
    int isDirect = 0;
#endif /* WOLFSSH_FWD */
    WOLFSSH_CHANNEL* newChannel = NULL;
    int ret = WS_SUCCESS;
    word32 fail_reason = OPEN_OK;

    WLOG(WS_LOG_DEBUG, "Entering DoChannelOpen()");

    if (idx == NULL)
        ret = WS_BAD_ARGUMENT;

    if (ret == WS_SUCCESS) {
        begin = *idx;
        typeSz = (word32)sizeof(type);
        ret = GetString(type, &typeSz, buf, len, &begin);
    }

    if (ret == WS_SUCCESS)
        ret = GetUint32(&peerChannelId, buf, len, &begin);

    if (ret == WS_SUCCESS)
        ret = GetUint32(&peerInitialWindowSz, buf, len, &begin);

    if (ret == WS_SUCCESS)
        ret = GetUint32(&peerMaxPacketSz, buf, len, &begin);

    if (ret == WS_SUCCESS) {
        WLOG(WS_LOG_INFO, "  type = %s", type);
        WLOG(WS_LOG_INFO, "  peerChannelId = %u", peerChannelId);
        WLOG(WS_LOG_INFO, "  peerInitialWindowSz = %u", peerInitialWindowSz);
        WLOG(WS_LOG_INFO, "  peerMaxPacketSz = %u", peerMaxPacketSz);

        typeId = NameToId(type, typeSz);
        switch (typeId) {
            case ID_CHANTYPE_SESSION:
                if (ssh->channelListSz >= 1) {
                    ret = WS_INVALID_CHANID;
                    fail_reason = OPEN_ADMINISTRATIVELY_PROHIBITED;
                }
                break;
        #ifdef WOLFSSH_FWD
            case ID_CHANTYPE_TCPIP_DIRECT:
                isDirect = 1;
                NO_BREAK;
            case ID_CHANTYPE_TCPIP_FORWARD:
                ret = DoChannelOpenForward(ssh,
                                &host, &hostPort, &origin, &originPort,
                                buf, len, &begin);
                break;
        #endif /* WOLFSSH_FWD */
        #ifdef WOLFSSH_AGENT
            case ID_CHANTYPE_AUTH_AGENT:
                WLOG(WS_LOG_INFO, "agent = %p", ssh->agent);
                if (ssh->agent != NULL)
                    ssh->agent->channel = peerChannelId;
                else
                    ret = WS_AGENT_NULL_E;
                break;
        #endif
            default:
                ret = WS_INVALID_CHANTYPE;
                fail_reason = OPEN_UNKNOWN_CHANNEL_TYPE;
        }
    }

    if (ret == WS_SUCCESS) {
        *idx = begin;

        newChannel = ChannelNew(ssh, typeId,
                                ssh->ctx->windowSz, ssh->ctx->maxPacketSz);
        if (newChannel == NULL) {
            ret = WS_RESOURCE_E;
            fail_reason = OPEN_RESOURCE_SHORTAGE;
        }
        else {
            ChannelUpdatePeer(newChannel, peerChannelId,
                          peerInitialWindowSz, peerMaxPacketSz);
            if (ssh->ctx->channelOpenCb) {
                ret = ssh->ctx->channelOpenCb(newChannel, ssh->channelOpenCtx);
            }
            if (ssh->channelListSz == 0)
                ssh->defaultPeerChannelId = peerChannelId;
        #ifdef WOLFSSH_FWD
            if (typeId == ID_CHANTYPE_TCPIP_DIRECT) {
                ChannelUpdateForward(newChannel,
                        host, hostPort, origin, originPort, isDirect);

                if (ssh->ctx->fwdCb) {
                    ret = ssh->ctx->fwdCb(WOLFSSH_FWD_LOCAL_SETUP,
                            ssh->fwdCbCtx, host, hostPort);
                    if (ret == WS_SUCCESS) {
                        ret = ssh->ctx->fwdCb(WOLFSSH_FWD_CHANNEL_ID,
                                ssh->fwdCbCtx, NULL, newChannel->channel);
                    }
                }
            }
        #endif /* WOLFSSH_FWD */
            ChannelAppend(ssh, newChannel);

            ssh->clientState = CLIENT_CHANNEL_OPEN_DONE;
        }
    }

    if (ret == WS_SUCCESS) {
        ret = SendChannelOpenConf(ssh, newChannel);
    }
    else {
        const char *description = NULL;

        if (fail_reason == OPEN_ADMINISTRATIVELY_PROHIBITED)
            description = "Administratively prohibited.";
        else if (fail_reason == OPEN_UNKNOWN_CHANNEL_TYPE)
            description = "Channel type not supported.";
        else if (fail_reason == OPEN_RESOURCE_SHORTAGE)
            description = "Not enough resources.";

        if (description != NULL) {
            ret = SendChannelOpenFail(ssh, peerChannelId,
                    fail_reason, description, "en");
        }
        else
            ret = SendRequestSuccess(ssh, 0); /* XXX Is this right? */
    }

#ifdef WOLFSSH_FWD
    /* ChannelUpdateForward makes new host and origin buffer */
    WFREE(host, ssh->ctx->heap, DYNTYPE_STRING);
    WFREE(origin, ssh->ctx->heap, DYNTYPE_STRING);
#endif /* WOLFSSH_FWD */

    WLOG(WS_LOG_DEBUG, "Leaving DoChannelOpen(), ret = %d", ret);
    return ret;
}


static int DoChannelOpenConf(WOLFSSH* ssh,
                             byte* buf, word32 len, word32* idx)
{
    WOLFSSH_CHANNEL* channel;
    word32 begin, channelId, peerChannelId,
           peerInitialWindowSz, peerMaxPacketSz;
    int ret = WS_SUCCESS;

    WLOG(WS_LOG_DEBUG, "Entering DoChannelOpenConf()");

    if (ssh == NULL || buf == NULL || len == 0 || idx == NULL)
        ret = WS_BAD_ARGUMENT;

    if (ret == WS_SUCCESS) {
        begin = *idx;
        ret = GetUint32(&channelId, buf, len, &begin);
    }

    if (ret == WS_SUCCESS)
        ret = GetUint32(&peerChannelId, buf, len, &begin);

    if (ret == WS_SUCCESS)
        ret = GetUint32(&peerInitialWindowSz, buf, len, &begin);

    if (ret == WS_SUCCESS)
        ret = GetUint32(&peerMaxPacketSz, buf, len, &begin);

    if (ret == WS_SUCCESS) {
        WLOG(WS_LOG_INFO, "  channelId = %u", channelId);
        WLOG(WS_LOG_INFO, "  peerChannelId = %u", peerChannelId);
        WLOG(WS_LOG_INFO, "  peerInitialWindowSz = %u", peerInitialWindowSz);
        WLOG(WS_LOG_INFO, "  peerMaxPacketSz = %u", peerMaxPacketSz);

        channel = ChannelFind(ssh, channelId, WS_CHANNEL_ID_SELF);
        if (channel == NULL)
            ret = WS_INVALID_CHANID;
    }

    if (ret == WS_SUCCESS)
        ret = ChannelUpdatePeer(channel, peerChannelId,
                            peerInitialWindowSz, peerMaxPacketSz);

    if (ret == WS_SUCCESS) {
        if (ssh->ctx->channelOpenConfCb != NULL) {
            ret = ssh->ctx->channelOpenConfCb(channel, ssh->channelOpenCtx);
        }
    }

    if (ret == WS_SUCCESS) {
        ssh->serverState = SERVER_CHANNEL_OPEN_DONE;
        ssh->defaultPeerChannelId = peerChannelId;
    }

    WLOG(WS_LOG_DEBUG, "Leaving DoChannelOpenConf(), ret = %d", ret);
    return ret;
}


static int DoChannelOpenFail(WOLFSSH* ssh,
                             byte* buf, word32 len, word32* idx)
{
    WOLFSSH_CHANNEL* channel = NULL;
    char desc[80];
    word32 begin, channelId, reasonId, descSz, langSz;
    int ret = WS_SUCCESS;

    WLOG(WS_LOG_DEBUG, "Entering DoChannelOpenFail()");

    if (ssh == NULL || buf == NULL || len == 0 || idx == NULL)
        ret = WS_BAD_ARGUMENT;

    if (ret == WS_SUCCESS) {
        begin = *idx;
        ret = GetUint32(&channelId, buf, len, &begin);
    }

    if (ret == WS_SUCCESS)
        ret = GetUint32(&reasonId, buf, len, &begin);

    if (ret == WS_SUCCESS) {
        descSz = (word32)sizeof(desc);
        ret = GetString(desc, &descSz, buf, len, &begin);
    }

    if (ret == WS_SUCCESS)
        ret = GetSize(&langSz, buf, len, &begin);

    if (ret == WS_SUCCESS) {
        *idx = begin + langSz;

        WLOG(WS_LOG_INFO, "channel open failure reason code: %u", reasonId);
        if (descSz > 0) {
            WLOG(WS_LOG_INFO, "description: %s", desc);
        }

        if (ssh->ctx->channelOpenFailCb != NULL) {
            channel = ChannelFind(ssh, channelId, WS_CHANNEL_ID_SELF);

            if (channel != NULL) {
                ret = ssh->ctx->channelOpenFailCb(channel, ssh->channelOpenCtx);
            }
            else {
                ret = WS_INVALID_CHANID;
            }
        }
    }

    if (ret == WS_SUCCESS) {
        ret = ChannelRemove(ssh, channelId, WS_CHANNEL_ID_SELF);
    }

    if (ret == WS_SUCCESS)
        ret = WS_CHANOPEN_FAILED;

    WLOG(WS_LOG_DEBUG, "Leaving DoChannelOpenFail(), ret = %d", ret);
    return ret;
}


static int DoChannelEof(WOLFSSH* ssh,
                        byte* buf, word32 len, word32* idx)
{
    WOLFSSH_CHANNEL* channel = NULL;
    word32 begin = *idx;
    word32 channelId;
    int      ret;

    WLOG(WS_LOG_DEBUG, "Entering DoChannelEof()");

    ret = GetUint32(&channelId, buf, len, &begin);

    if (ret == WS_SUCCESS) {
        *idx = begin;

        channel = ChannelFind(ssh, channelId, WS_CHANNEL_ID_SELF);
        if (channel == NULL)
            ret = WS_INVALID_CHANID;
    }

    if (ret == WS_SUCCESS) {
        if (ssh->ctx->channelEofCb) {
            ssh->ctx->channelEofCb(channel, ssh->channelEofCtx);
        }
    }

    if (ret == WS_SUCCESS) {
        channel->eofRxd = 1;
        if (!channel->eofTxd) {
            ret = SendChannelEof(ssh, channel->peerChannel);
        }
        ssh->lastRxId = channelId;
    }

    WLOG(WS_LOG_DEBUG, "Leaving DoChannelEof(), ret = %d", ret);
    return ret;
}


static int DoChannelClose(WOLFSSH* ssh,
                          byte* buf, word32 len, word32* idx)
{
    WOLFSSH_CHANNEL* channel = NULL;
    word32 begin = *idx;
    word32 channelId;
    int ret;

    WLOG(WS_LOG_DEBUG, "Entering DoChannelClose()");

    ret = GetUint32(&channelId, buf, len, &begin);

    if (ret == WS_SUCCESS) {
        *idx = begin;

        channel = ChannelFind(ssh, channelId, WS_CHANNEL_ID_SELF);
        if (channel == NULL)
            ret = WS_INVALID_CHANID;
    }

    if (ret == WS_SUCCESS) {
        if (ssh->ctx->channelCloseCb) {
            ssh->ctx->channelCloseCb(channel, ssh->channelCloseCtx);
        }
    }

    if (ret == WS_SUCCESS) {
        if (!channel->closeTxd) {
            ret = SendChannelClose(ssh, channel->peerChannel);
        }
    }

    if (ret == WS_SUCCESS) {
        ret = ChannelRemove(ssh, channelId, WS_CHANNEL_ID_SELF);
    }

    if (ret == WS_SUCCESS) {
        ret = WS_CHANNEL_CLOSED;
        ssh->lastRxId = channelId;
    }

    WLOG(WS_LOG_DEBUG, "Leaving DoChannelClose(), ret = %d", ret);
    return ret;
}


#if !defined(NO_TERMIOS) && defined(WOLFSSH_TERM)
#if defined(HAVE_SYS_IOCTL_H)

#define TTY_SET_CHAR(x,y,z) (x)[(y)] = (byte)(z)
#define TTY_SET_FLAG(x,y,z) (x) = (z) ? ((x) | (y)) : ((x) & ~(y))

int wolfSSH_DoModes(const byte* modes, word32 modesSz, int fd)
{
    WOLFSSH_TERMIOS term;
    word32 idx = 0, arg;

    if (!modes || !modesSz || (modesSz % TERMINAL_MODE_SZ > 1))
        return -1;
    /*
     * Modes is a list of opcode-argument pairs. The opcodes are
     * bytes and the arguments are uint32s. TTY_OP_END is an opcode
     * that terminates the list. Of course, it isn't clear if
     * TTY_OP_END has an arguement or note. The RFC doesn't say,
     * but in operation it usually doesn't. Allow for an odd single
     * byte left over.
     */

    tcgetattr(fd, &term);

    while (idx < modesSz && modes[idx] != WOLFSSH_TTY_OP_END
            && modes[idx] < WOLFSSH_TTY_INVALID) {

        ato32(modes + idx + 1, &arg);

        switch (modes[idx]) {
            /* Special Control Characters (c_cc) */
            case WOLFSSH_VINTR:
                TTY_SET_CHAR(term.c_cc, VINTR, arg);
                break;
            case WOLFSSH_VQUIT:
                TTY_SET_CHAR(term.c_cc, VQUIT, arg);
                break;
            case WOLFSSH_VERASE:
                TTY_SET_CHAR(term.c_cc, VERASE, arg);
                break;
            case WOLFSSH_VKILL:
                TTY_SET_CHAR(term.c_cc, VKILL, arg);
                break;
            case WOLFSSH_VEOF:
                TTY_SET_CHAR(term.c_cc, VEOF, arg);
                break;
            case WOLFSSH_VEOL:
                TTY_SET_CHAR(term.c_cc, VEOL, arg);
                break;
            case WOLFSSH_VEOL2:
                TTY_SET_CHAR(term.c_cc, VEOL2, arg);
                break;
            case WOLFSSH_VSTART:
                TTY_SET_CHAR(term.c_cc, VSTART, arg);
                break;
            case WOLFSSH_VSTOP:
                TTY_SET_CHAR(term.c_cc, VSTOP, arg);
                break;
            case WOLFSSH_VSUSP:
                TTY_SET_CHAR(term.c_cc, VSUSP, arg);
                break;
            case WOLFSSH_VDSUSP:
                #ifdef VDSUSP
                    TTY_SET_CHAR(term.c_cc, VDSUSP, arg);
                #endif
                break;
            case WOLFSSH_VREPRINT:
                TTY_SET_CHAR(term.c_cc, VREPRINT, arg);
                break;
            case WOLFSSH_VWERASE:
                TTY_SET_CHAR(term.c_cc, VWERASE, arg);
                break;
            case WOLFSSH_VLNEXT:
                TTY_SET_CHAR(term.c_cc, VLNEXT, arg);
                break;
            case WOLFSSH_VFLUSH:
                #ifdef VFLUSH
                    TTY_SET_CHAR(term.c_cc, VFLUSH, arg);
                #endif
                break;
            case WOLFSSH_VSWTCH:
                #ifdef VSWTCH
                    TTY_SET_CHAR(term.c_cc, VSWTCH, arg);
                #endif
                break;
            case WOLFSSH_VSTATUS:
                #ifdef VSTATUS
                    TTY_SET_CHAR(term.c_cc, VSTATUS, arg);
                #endif
                break;
            case WOLFSSH_VDISCARD:
                TTY_SET_CHAR(term.c_cc, VDISCARD, arg);
                break;

            /* Input Modes (c_iflag) */
            case WOLFSSH_IGNPAR:
                TTY_SET_FLAG(term.c_iflag, IGNPAR, arg);
                break;
            case WOLFSSH_PARMRK:
                TTY_SET_FLAG(term.c_iflag, PARMRK, arg);
                break;
            case WOLFSSH_INPCK:
                TTY_SET_FLAG(term.c_iflag, INPCK, arg);
                break;
            case WOLFSSH_ISTRIP:
                TTY_SET_FLAG(term.c_iflag, ISTRIP, arg);
                break;
            case WOLFSSH_INLCR:
                TTY_SET_FLAG(term.c_iflag, INLCR, arg);
                break;
            case WOLFSSH_IGNCR:
                TTY_SET_FLAG(term.c_iflag, IGNCR, arg);
                break;
            case WOLFSSH_ICRNL:
                TTY_SET_FLAG(term.c_iflag, ICRNL, arg);
                break;
            case WOLFSSH_IUCLC:
                #ifdef IUCLC
                    TTY_SET_FLAG(term.c_iflag, IUCLC, arg);
                #endif
                break;
            case WOLFSSH_IXON:
                TTY_SET_FLAG(term.c_iflag, IXON, arg);
                break;
            case WOLFSSH_IXANY:
                TTY_SET_FLAG(term.c_iflag, IXANY, arg);
                break;
            case WOLFSSH_IXOFF:
                TTY_SET_FLAG(term.c_iflag, IXOFF, arg);
                break;
            case WOLFSSH_IMAXBEL:
                TTY_SET_FLAG(term.c_iflag, IMAXBEL, arg);
                break;
            case WOLFSSH_IUTF8:
                #ifdef IUTF8
                    TTY_SET_FLAG(term.c_iflag, IUTF8, arg);
                #endif
                break;

            /* Local Modes (c_lflag) */
            case WOLFSSH_ISIG:
                TTY_SET_FLAG(term.c_lflag, ISIG, arg);
                break;
            case WOLFSSH_ICANON:
                TTY_SET_FLAG(term.c_lflag, ICANON, arg);
                break;
            case WOLFSSH_XCASE:
                #ifdef XCASE
                    TTY_SET_FLAG(term.c_lflag, XCASE, arg);
                #endif
                break;
            case WOLFSSH_ECHO:
                TTY_SET_FLAG(term.c_lflag, ECHO, arg);
                break;
            case WOLFSSH_ECHOE:
                TTY_SET_FLAG(term.c_lflag, ECHOE, arg);
                break;
            case WOLFSSH_ECHOK:
                TTY_SET_FLAG(term.c_lflag, ECHOK, arg);
                break;
            case WOLFSSH_ECHONL:
                TTY_SET_FLAG(term.c_lflag, ECHONL, arg);
                break;
            case WOLFSSH_NOFLSH:
                TTY_SET_FLAG(term.c_lflag, NOFLSH, arg);
                break;
            case WOLFSSH_TOSTOP:
                TTY_SET_FLAG(term.c_lflag, TOSTOP, arg);
                break;
            case WOLFSSH_IEXTEN:
                TTY_SET_FLAG(term.c_lflag, IEXTEN, arg);
                break;
            case WOLFSSH_ECHOCTL:
                TTY_SET_FLAG(term.c_lflag, ECHOCTL, arg);
                break;
            case WOLFSSH_ECHOKE:
                TTY_SET_FLAG(term.c_lflag, ECHOKE, arg);
                break;
            case WOLFSSH_PENDIN:
                #ifdef PENDIN
                    TTY_SET_FLAG(term.c_lflag, PENDIN, arg);
                #endif
                break;

            /* Output Modes (c_oflag) */
            case WOLFSSH_OPOST:
                TTY_SET_FLAG(term.c_lflag, OPOST, arg);
                break;
            case WOLFSSH_OLCUC:
                #ifdef OLCUC
                    TTY_SET_FLAG(term.c_lflag, OLCUC, arg);
                #endif
                break;
            case WOLFSSH_ONLCR:
                TTY_SET_FLAG(term.c_lflag, ONLCR, arg);
                break;
            case WOLFSSH_OCRNL:
                /* keep as default, adjusting removes echo over shell */
                /* TTY_SET_FLAG(term.c_lflag, OCRNL, arg); */
                break;
            case WOLFSSH_ONOCR:
                TTY_SET_FLAG(term.c_lflag, ONOCR, arg);
                break;
            case WOLFSSH_ONLRET:
                TTY_SET_FLAG(term.c_lflag, ONLRET, arg);
                break;

            /* Control Modes (c_cflag) */
            case WOLFSSH_CS7:
                TTY_SET_FLAG(term.c_cflag, CS7, arg);
                break;
            case WOLFSSH_CS8:
                TTY_SET_FLAG(term.c_cflag, CS8, arg);
                break;
            case WOLFSSH_PARENB:
                TTY_SET_FLAG(term.c_cflag, PARENB, arg);
                break;
            case WOLFSSH_PARODD:
                TTY_SET_FLAG(term.c_cflag, PARODD, arg);
                break;

            /* Baud Rates */
            case WOLFSSH_TTY_OP_ISPEED:
                cfsetispeed(&term, (speed_t)arg);
                break;
            case WOLFSSH_TTY_OP_OSPEED:
                cfsetospeed(&term, (speed_t)arg);
                break;

            default:
                break;
        }
        idx += TERMINAL_MODE_SZ;
    }

    tcsetattr(fd, TCSANOW, &term);

    return 0;
}

#endif /* HAVE_SYS_IOCTL_H */
#endif /* !NO_TERMIOS && WOLFSSH_TERM */


static int DoChannelRequest(WOLFSSH* ssh,
                            byte* buf, word32 len, word32* idx)
{
    WOLFSSH_CHANNEL* channel = NULL;
    word32 begin = *idx;
    word32 channelId;
    word32 typeSz;
    char type[32];
    byte wantReply;
    int ret, rej = 0;

    WLOG(WS_LOG_DEBUG, "Entering DoChannelRequest()");

    ret = GetUint32(&channelId, buf, len, &begin);

    typeSz = (word32)sizeof(type);
    if (ret == WS_SUCCESS)
        ret = GetString(type, &typeSz, buf, len, &begin);

    if (ret == WS_SUCCESS)
        ret = GetBoolean(&wantReply, buf, len, &begin);

    if (ret != WS_SUCCESS) {
        WLOG(WS_LOG_DEBUG, "Leaving DoChannelRequest(), ret = %d", ret);
        return ret;
    }

    if (ret == WS_SUCCESS) {
        channel = ChannelFind(ssh, channelId, WS_CHANNEL_ID_SELF);
        if (channel == NULL)
            ret = WS_INVALID_CHANID;
    }

    if (ret == WS_SUCCESS) {
        WLOG(WS_LOG_DEBUG, "  channelId = %u", channelId);
        WLOG(WS_LOG_DEBUG, "  type = %s", type);
        WLOG(WS_LOG_DEBUG, "  wantReply = %u", wantReply);

        if (WSTRNCMP(type, "env", typeSz) == 0) {
            char name[WOLFSSH_MAX_NAMESZ];
            word32 nameSz;
            char value[32];
            word32 valueSz;

            name[0] = 0;
            value[0] = 0;
            nameSz = (word32)sizeof(name);
            valueSz = (word32)sizeof(value);
            ret = GetString(name, &nameSz, buf, len, &begin);
            if (ret == WS_SUCCESS)
                ret = GetString(value, &valueSz, buf, len, &begin);

            WLOG(WS_LOG_DEBUG, "  %s = %s", name, value);
        }
        else if (WSTRNCMP(type, "shell", typeSz) == 0) {
            channel->sessionType = WOLFSSH_SESSION_SHELL;
            if (ssh->ctx->channelReqShellCb) {
                rej = ssh->ctx->channelReqShellCb(channel, ssh->channelReqCtx);
            }
            ssh->clientState = CLIENT_DONE;
        }
        else if (WSTRNCMP(type, "exec", typeSz) == 0) {
            ret = GetStringAlloc(ssh->ctx->heap, &channel->command,
                    buf, len, &begin);
            channel->sessionType = WOLFSSH_SESSION_EXEC;
            if (ssh->ctx->channelReqExecCb) {
                rej = ssh->ctx->channelReqExecCb(channel, ssh->channelReqCtx);
            }
            ssh->clientState = CLIENT_DONE;

            WLOG(WS_LOG_DEBUG, "  command = %s", channel->command);
        }
        else if (WSTRNCMP(type, "subsystem", typeSz) == 0) {
            ret = GetStringAlloc(ssh->ctx->heap, &channel->command,
                    buf, len, &begin);
            channel->sessionType = WOLFSSH_SESSION_SUBSYSTEM;
            if (ssh->ctx->channelReqSubsysCb) {
                rej = ssh->ctx->channelReqSubsysCb(channel, ssh->channelReqCtx);
            }
            ssh->clientState = CLIENT_DONE;

            WLOG(WS_LOG_DEBUG, "  subsystem = %s", channel->command);
        }
        #ifdef WOLFSSH_TERM
        else if (WSTRNCMP(type, "pty-req", typeSz) == 0) {
            char term[32];
            const byte* modes;
            word32 termSz, modesSz = 0;
            word32 widthChar, heightRows, widthPixels, heightPixels;

            termSz = (word32)sizeof(term);
            ret = GetString(term, &termSz, buf, len, &begin);
            if (ret == WS_SUCCESS)
                ret = GetUint32(&widthChar, buf, len, &begin);
            if (ret == WS_SUCCESS)
                ret = GetUint32(&heightRows, buf, len, &begin);
            if (ret == WS_SUCCESS)
                ret = GetUint32(&widthPixels, buf, len, &begin);
            if (ret == WS_SUCCESS)
                ret = GetUint32(&heightPixels, buf, len, &begin);
            if (ret == WS_SUCCESS)
                ret = GetStringRef(&modesSz, &modes, buf, len, &begin);
            if (ret == WS_SUCCESS) {
                ssh->modes = (byte*)WMALLOC(modesSz,
                        ssh->ctx->heap, DYNTYPE_STRING);
                if (ssh->modes == NULL)
                    ret = WS_MEMORY_E;
            }
            if (ret == WS_SUCCESS) {
                ssh->modesSz = modesSz;
                WMEMCPY(ssh->modes, modes, modesSz);
                WLOG(WS_LOG_DEBUG, "  term = %s", term);
                WLOG(WS_LOG_DEBUG, "  widthChar = %u", widthChar);
                WLOG(WS_LOG_DEBUG, "  heightRows = %u", heightRows);
                WLOG(WS_LOG_DEBUG, "  widthPixels = %u", widthPixels);
                WLOG(WS_LOG_DEBUG, "  heightPixels = %u", heightPixels);
                ssh->widthChar = widthChar;
                ssh->heightRows = heightRows;
                ssh->widthPixels = widthPixels;
                ssh->heightPixels = heightPixels;
                if (ssh->termResizeCb) {
                    if (ssh->termResizeCb(ssh, widthChar, heightRows,
                            widthPixels, heightPixels,
                            ssh->termCtx) != WS_SUCCESS) {
                        ret = WS_FATAL_ERROR;
                    }
                }
            }
        }
        #endif /* WOLFSSH_TERM */
        #if defined(WOLFSSH_SHELL) && defined(WOLFSSH_TERM)
        else if (WSTRNCMP(type, "window-change", typeSz) == 0) {
            word32 widthChar, heightRows, widthPixels, heightPixels;

            ret = GetUint32(&widthChar, buf, len, &begin);
            if (ret == WS_SUCCESS)
                ret = GetUint32(&heightRows, buf, len, &begin);
            if (ret == WS_SUCCESS)
                ret = GetUint32(&widthPixels, buf, len, &begin);
            if (ret == WS_SUCCESS)
                ret = GetUint32(&heightPixels, buf, len, &begin);

            if (ret == WS_SUCCESS) {
                WLOG(WS_LOG_DEBUG, "  widthChar = %u", widthChar);
                WLOG(WS_LOG_DEBUG, "  heightRows = %u", heightRows);
                WLOG(WS_LOG_DEBUG, "  widthPixels = %u", widthPixels);
                WLOG(WS_LOG_DEBUG, "  heightPixels = %u", heightPixels);
                ssh->widthChar = widthChar;
                ssh->heightRows = heightRows;
                ssh->widthPixels = widthPixels;
                ssh->heightPixels = heightPixels;
                if (ssh->termResizeCb) {
                    if (ssh->termResizeCb(ssh, widthChar, heightRows,
                            widthPixels, heightPixels,
                            ssh->termCtx) != WS_SUCCESS) {
                        ret = WS_FATAL_ERROR;
                    }
                }
            }
        }
        #endif /* WOLFSSH_SHELL && WOLFSSH_TERM */
        #if defined(WOLFSSH_TERM) || defined(WOLFSSH_SHELL)
        else if (WSTRNCMP(type, "exit-status", typeSz) == 0) {
            ret = GetUint32(&ssh->exitStatus, buf, len, &begin);
            WLOG(WS_LOG_AGENT, "Got exit status %u.", ssh->exitStatus);
        }
        else if (WSTRNCMP(type, "exit-signal", typeSz) == 0) {
            char sig[WOLFSSH_MAX_NAMESZ];
            word32 sigSz;
            byte coreDumped;

            WLOG(WS_LOG_AGENT, "Got exit signal, remote command terminated");

            sigSz = WOLFSSH_MAX_NAMESZ;
            ret = GetString(sig, &sigSz, buf, len, &begin);
            if (ret == WS_SUCCESS) {
                WLOG(WS_LOG_AGENT, "SIGNAL      : %s", sig);
                ret = GetBoolean(&coreDumped, buf, len, &begin);
            }

            if (ret == WS_SUCCESS) {
                WLOG(WS_LOG_AGENT, "Core Dumped?: %d", coreDumped);
                sigSz = WOLFSSH_MAX_NAMESZ;
                ret = GetString(sig, &sigSz, buf, len, &begin);
            }

            if (ret == WS_SUCCESS) {
                WLOG(WS_LOG_AGENT, "Error Msg  : %s", sig);
                sigSz = WOLFSSH_MAX_NAMESZ;

                /* getting language tag */
                ret = GetString(sig, &sigSz, buf, len, &begin);
            }
        }
        #endif /* WOLFSSH_TERM or WOLFSSH_SHELL */
        #ifdef WOLFSSH_AGENT
        else if (WSTRNCMP(type, "auth-agent-req@openssh.com", typeSz) == 0) {
            WLOG(WS_LOG_AGENT, "  ssh-agent");
            if (ssh->ctx->agentCb != NULL)
                ssh->useAgent = 1;
            else
                WLOG(WS_LOG_AGENT, "Agent callback not set, not using.");
        }
        #endif /* WOLFSSH_AGENT */
    }

    if (ret == WS_SUCCESS) {
        *idx = len;
    }

    if (wantReply) {
        int replyRet;

        if (rej) {
            WLOG(WS_LOG_DEBUG, "Callback rejecting channel request.");
        }
        replyRet = SendChannelSuccess(ssh, channelId,
                (ret == WS_SUCCESS && !rej));
        if (replyRet != WS_SUCCESS)
            ret = replyRet;
    }

    WLOG(WS_LOG_DEBUG, "Leaving DoChannelRequest(), ret = %d", ret);
    return ret;
}


static int DoChannelSuccess(WOLFSSH* ssh, byte* buf, word32 len, word32* idx)
{
    int ret = WS_SUCCESS;

    WLOG(WS_LOG_DEBUG, "Entering DoChannelSuccess()");

    if (ssh == NULL || buf == NULL || len == 0 || idx == NULL) {
        ret = WS_BAD_ARGUMENT;
        WLOG(WS_LOG_DEBUG, "Leaving DoChannelSuccess(), ret = %d", ret);
        return ret;
    }

    ssh->serverState = SERVER_DONE;

    WLOG(WS_LOG_DEBUG, "Leaving DoChannelSuccess(), ret = %d", ret);
    return ret;
}


static int DoChannelFailure(WOLFSSH* ssh, byte* buf, word32 len, word32* idx)
{
    int ret = WS_SUCCESS;

    WLOG(WS_LOG_DEBUG, "Entering DoChannelFailure()");

    if (ssh == NULL || buf == NULL || len != 0 || idx == NULL)
        ret = WS_BAD_ARGUMENT;

    if (ret == WS_SUCCESS)
        ret = WS_CHANOPEN_FAILED;
    WLOG(WS_LOG_DEBUG, "Leaving DoChannelFailure(), ret = %d", ret);
    return ret;
}


static int DoChannelWindowAdjust(WOLFSSH* ssh,
                                 byte* buf, word32 len, word32* idx)
{
    WOLFSSH_CHANNEL* channel = NULL;
    word32 begin = *idx;
    word32 channelId, bytesToAdd;
    int ret;

    WLOG(WS_LOG_DEBUG, "Entering DoChannelWindowAdjust()");

    ret = GetUint32(&channelId, buf, len, &begin);
    if (ret == WS_SUCCESS)
        ret = GetUint32(&bytesToAdd, buf, len, &begin);

    if (ret == WS_SUCCESS) {
        *idx = begin;

        channel = ChannelFind(ssh, channelId, WS_CHANNEL_ID_SELF);
        if (channel == NULL)
            ret = WS_INVALID_CHANID;
        else {
            WLOG(WS_LOG_INFO, "  channelId = %u", channelId);
            WLOG(WS_LOG_INFO, "  bytesToAdd = %u", bytesToAdd);
            WLOG(WS_LOG_INFO, "  peerWindowSz = %u",
                 channel->peerWindowSz);

            channel->peerWindowSz += bytesToAdd;

            WLOG(WS_LOG_INFO, "  update peerWindowSz = %u",
                 channel->peerWindowSz);

        }
    }

    WLOG(WS_LOG_DEBUG, "Leaving DoChannelWindowAdjust(), ret = %d", ret);
    return ret;
}


static int DoChannelData(WOLFSSH* ssh,
                         byte* buf, word32 len, word32* idx)
{
    WOLFSSH_CHANNEL* channel = NULL;
    word32 begin = *idx;
    word32 dataSz = 0;
    word32 channelId;
    int ret;

    WLOG(WS_LOG_DEBUG, "Entering DoChannelData()");

    ret = GetUint32(&channelId, buf, len, &begin);
    if (ret == WS_SUCCESS)
        ret = GetSize(&dataSz, buf, len, &begin);

    /* Validate dataSz */
    if (ret == WS_SUCCESS) {
        if (len < begin) {
            ret = WS_RECV_OVERFLOW_E;
        }
    }

    if (ret == WS_SUCCESS) {
        *idx = begin + dataSz;

        channel = ChannelFind(ssh, channelId, WS_CHANNEL_ID_SELF);
        if (channel == NULL)
            ret = WS_INVALID_CHANID;
        else
            ret = ChannelPutData(channel, buf + begin, dataSz);
    }

    if (ret == WS_SUCCESS) {
        ssh->lastRxId = channelId;
        ret = WS_CHAN_RXD;
    }

    WLOG(WS_LOG_DEBUG, "Leaving DoChannelData(), ret = %d", ret);
    return ret;
}


/* deletes current buffer and updates it
 * return WS_SUCCESS on success */
static int PutBuffer(WOLFSSH_BUFFER* buf, byte* data, word32 dataSz)
{
    int ret;

    /* reset "used" section of buffer back to 0 */
    buf->length = 0;
    buf->idx    = 0;

    if (dataSz > buf->bufferSz) {
        if ((ret = GrowBuffer(buf, dataSz)) != WS_SUCCESS) {
            return ret;
        }
    }
    WMEMCPY(buf->buffer, data, dataSz);
    buf->length = dataSz;

    return WS_SUCCESS;
}


static int DoChannelExtendedData(WOLFSSH* ssh,
                         byte* buf, word32 len, word32* idx)
{
    WOLFSSH_CHANNEL* channel = NULL;
    word32 begin = *idx;
    word32 dataSz = 0;
    word32 channelId;
    word32 dataTypeCode;
    int ret;

    WLOG(WS_LOG_DEBUG, "Entering DoChannelExtendedData()");

    ret = GetUint32(&channelId, buf, len, &begin);
    if (ret == WS_SUCCESS)
        ret = GetUint32(&dataTypeCode, buf, len, &begin);
    if (ret == WS_SUCCESS)
        ret = (dataTypeCode == CHANNEL_EXTENDED_DATA_STDERR) ?
            WS_SUCCESS : WS_INVALID_EXTDATA;
    if (ret == WS_SUCCESS)
        ret = GetSize(&dataSz, buf, len, &begin);

    if (ret == WS_SUCCESS) {
        channel = ChannelFind(ssh, channelId, WS_CHANNEL_ID_SELF);
        if (channel == NULL)
            ret = WS_INVALID_CHANID;
        else {
            ret = PutBuffer(&ssh->extDataBuffer,  buf + begin, dataSz);
            #ifdef DEBUG_WOLFSSH
            DumpOctetString(buf + begin, dataSz);
            #endif
            if (ret == WS_SUCCESS) {
                ret = SendChannelWindowAdjust(ssh, channel->channel, dataSz);
            }
        }
        *idx = begin + dataSz;
    }

    if (ret == WS_SUCCESS) {
        ssh->lastRxId = channelId;
        ret = WS_EXTDATA;
    }

    WLOG(WS_LOG_DEBUG, "Leaving DoChannelExtendedData(), ret = %d", ret);
    return ret;
}


static int DoPacket(WOLFSSH* ssh, byte* bufferConsumed)
{
    byte* buf = (byte*)ssh->inputBuffer.buffer;
    word32 idx = ssh->inputBuffer.idx;
    word32 len = ssh->inputBuffer.length;
    word32 payloadSz;
    byte padSz;
    byte msg;
    word32 payloadIdx = 0;
    int ret = WS_SUCCESS;

    WLOG(WS_LOG_DEBUG, "DoPacket sequence number: %d", ssh->peerSeq);

    *bufferConsumed = 0;

    idx += UINT32_SZ;
    padSz = buf[idx++];

    /* check for underflow */
    if ((word32)(PAD_LENGTH_SZ + padSz + MSG_ID_SZ) > ssh->curSz) {
        return WS_OVERFLOW_E;
    }

    payloadSz = ssh->curSz - PAD_LENGTH_SZ - padSz - MSG_ID_SZ;

    msg = buf[idx++];
    /* At this point, payload starts at "buf + idx". */

    /* sanity check on payloadSz. Uses "or" condition because of the case when
     * adding idx to payloadSz causes it to overflow.
     */
    if ((ssh->inputBuffer.bufferSz < payloadSz + idx) ||
            (payloadSz + idx < payloadSz)) {
        return WS_OVERFLOW_E;
    }

    if (!IsMessageAllowed(ssh, msg)) {
        return WS_MSGID_NOT_ALLOWED_E;
    }

    switch (msg) {

        case MSGID_DISCONNECT:
            WLOG(WS_LOG_DEBUG, "Decoding MSGID_DISCONNECT");
            ret = DoDisconnect(ssh, buf + idx, payloadSz, &payloadIdx);
            break;

        case MSGID_IGNORE:
            WLOG(WS_LOG_DEBUG, "Decoding MSGID_IGNORE");
            ret = DoIgnore(ssh, buf + idx, payloadSz, &payloadIdx);
            break;

        case MSGID_UNIMPLEMENTED:
            WLOG(WS_LOG_DEBUG, "Decoding MSGID_UNIMPLEMENTED");
            ret = DoUnimplemented(ssh, buf + idx, payloadSz, &payloadIdx);
            break;

        case MSGID_REQUEST_SUCCESS:
            WLOG(WS_LOG_DEBUG, "Decoding MSGID_REQUEST_SUCCESS");
            ret = DoRequestSuccess(ssh, buf + idx, payloadSz, &payloadIdx);
            break;

        case MSGID_REQUEST_FAILURE:
            WLOG(WS_LOG_DEBUG, "Decoding MSGID_REQUEST_FAILURE");
            ret = DoRequestFailure(ssh, buf + idx, payloadSz, &payloadIdx);
            break;

        case MSGID_DEBUG:
            WLOG(WS_LOG_DEBUG, "Decoding MSGID_DEBUG");
            ret = DoDebug(ssh, buf + idx, payloadSz, &payloadIdx);
            break;

        case MSGID_EXT_INFO:
            WLOG(WS_LOG_DEBUG, "Decoding MSGID_EXT_INFO");
            ret = DoExtInfo(ssh, buf + idx, payloadSz, &payloadIdx);
            break;

        case MSGID_KEXINIT:
            WLOG(WS_LOG_DEBUG, "Decoding MSGID_KEXINIT");
            ret = DoKexInit(ssh, buf + idx, payloadSz, &payloadIdx);
            if (ssh->isKeying == 1 &&
                    ssh->connectState == CONNECT_SERVER_CHANNEL_REQUEST_DONE) {
                if (ssh->handshake->kexId == ID_DH_GEX_SHA256) {
#if !defined(WOLFSSH_NO_DH) && !defined(WOLFSSH_NO_DH_GEX_SHA256)
                    ssh->error = SendKexDhGexRequest(ssh);
#endif
                }
                else
                    ssh->error = SendKexDhInit(ssh);
            }
            break;

        case MSGID_NEWKEYS:
            WLOG(WS_LOG_DEBUG, "Decoding MSGID_NEWKEYS");
            ret = DoNewKeys(ssh, buf + idx, payloadSz, &payloadIdx);
            break;

        case MSGID_KEXDH_INIT:
            WLOG(WS_LOG_DEBUG, "Decoding MSGID_KEXDH_INIT");
            ret = DoKexDhInit(ssh, buf + idx, payloadSz, &payloadIdx);
            break;

        case MSGID_KEXDH_REPLY:
            if (ssh->handshake == NULL) {
                ret = WS_MEMORY_E;
                break;
            }

            if (ssh->handshake->kexId == ID_DH_GEX_SHA256) {
#ifndef WOLFSSH_NO_DH_GEX_SHA256
                WLOG(WS_LOG_DEBUG, "Decoding MSGID_KEXDH_GEX_GROUP");
                ret = DoKexDhGexGroup(ssh, buf + idx, payloadSz, &payloadIdx);
#endif
            }
            else {
                WLOG(WS_LOG_DEBUG, "Decoding MSGID_KEXDH_REPLY");
                ret = DoKexDhReply(ssh, buf + idx, payloadSz, &payloadIdx);
            }
            break;

#ifndef WOLFSSH_NO_DH_GEX_SHA256
        case MSGID_KEXDH_GEX_REQUEST:
            WLOG(WS_LOG_DEBUG, "Decoding MSGID_KEXDH_GEX_REQUEST");
            ret = DoKexDhGexRequest(ssh, buf + idx, payloadSz, &payloadIdx);
            break;
#endif

        case MSGID_KEXDH_GEX_INIT:
            WLOG(WS_LOG_DEBUG, "Decoding MSGID_KEXDH_GEX_INIT");
            ret = DoKexDhInit(ssh, buf + idx, payloadSz, &payloadIdx);
            break;

        case MSGID_KEXDH_GEX_REPLY:
            WLOG(WS_LOG_DEBUG, "Decoding MSGID_KEXDH_GEX_INIT");
            ret = DoKexDhReply(ssh, buf + idx, payloadSz, &payloadIdx);
            break;

        case MSGID_SERVICE_REQUEST:
            WLOG(WS_LOG_DEBUG, "Decoding MSGID_SERVICE_REQUEST");
            ret = DoServiceRequest(ssh, buf + idx, payloadSz, &payloadIdx);
            break;

        case MSGID_SERVICE_ACCEPT:
            WLOG(WS_LOG_DEBUG, "Decoding MSGID_SERVER_ACCEPT");
            ret = DoServiceAccept(ssh, buf + idx, payloadSz, &payloadIdx);
            break;

        case MSGID_USERAUTH_REQUEST:
            WLOG(WS_LOG_DEBUG, "Decoding MSGID_USERAUTH_REQUEST");
            ret = DoUserAuthRequest(ssh, buf + idx, payloadSz, &payloadIdx);
            break;

        case MSGID_USERAUTH_FAILURE:
            WLOG(WS_LOG_DEBUG, "Decoding MSGID_USERAUTH_FAILURE");
            ret = DoUserAuthFailure(ssh, buf + idx, payloadSz, &payloadIdx);
            break;

        case MSGID_USERAUTH_SUCCESS:
            WLOG(WS_LOG_DEBUG, "Decoding MSGID_USERAUTH_SUCCESS");
            ret = DoUserAuthSuccess(ssh, buf + idx, payloadSz, &payloadIdx);
            break;

        case MSGID_USERAUTH_BANNER:
            WLOG(WS_LOG_DEBUG, "Decoding MSGID_USERAUTH_BANNER");
            ret = DoUserAuthBanner(ssh, buf + idx, payloadSz, &payloadIdx);
            break;

        case MSGID_GLOBAL_REQUEST:
            WLOG(WS_LOG_DEBUG, "Decoding MSGID_GLOBAL_REQUEST");
            ret = DoGlobalRequest(ssh, buf + idx, payloadSz, &payloadIdx);
            break;

        case MSGID_CHANNEL_OPEN:
            WLOG(WS_LOG_DEBUG, "Decoding MSGID_CHANNEL_OPEN");
            ret = DoChannelOpen(ssh, buf + idx, payloadSz, &payloadIdx);
            break;

        case MSGID_CHANNEL_OPEN_CONF:
            WLOG(WS_LOG_DEBUG, "Decoding MSGID_CHANNEL_OPEN_CONF");
            ret = DoChannelOpenConf(ssh, buf + idx, payloadSz, &payloadIdx);
            break;

        case MSGID_CHANNEL_OPEN_FAIL:
            WLOG(WS_LOG_DEBUG, "Decoding MSGID_CHANNEL_OPEN_FAIL");
            ret = DoChannelOpenFail(ssh, buf + idx, payloadSz, &payloadIdx);
            break;

        case MSGID_CHANNEL_WINDOW_ADJUST:
            WLOG(WS_LOG_DEBUG, "Decoding MSGID_CHANNEL_WINDOW_ADJUST");
            ret = DoChannelWindowAdjust(ssh, buf + idx, payloadSz, &payloadIdx);
            break;

        case MSGID_CHANNEL_DATA:
            WLOG(WS_LOG_DEBUG, "Decoding MSGID_CHANNEL_DATA");
            ret = DoChannelData(ssh, buf + idx, payloadSz, &payloadIdx);
            break;

        case MSGID_CHANNEL_EXTENDED_DATA:
            WLOG(WS_LOG_DEBUG, "Decoding MSGID_CHANNEL_EXTENDED_DATA");
            ret = DoChannelExtendedData(ssh, buf + idx, payloadSz, &payloadIdx);
            break;

        case MSGID_CHANNEL_EOF:
            WLOG(WS_LOG_DEBUG, "Decoding MSGID_CHANNEL_EOF");
            ret = DoChannelEof(ssh, buf + idx, payloadSz, &payloadIdx);
            break;

        case MSGID_CHANNEL_CLOSE:
            WLOG(WS_LOG_DEBUG, "Decoding MSGID_CHANNEL_CLOSE");
            ret = DoChannelClose(ssh, buf + idx, payloadSz, &payloadIdx);
            break;

        case MSGID_CHANNEL_REQUEST:
            WLOG(WS_LOG_DEBUG, "Decoding MSGID_CHANNEL_REQUEST");
            ret = DoChannelRequest(ssh, buf + idx, payloadSz, &payloadIdx);
            break;

        case MSGID_CHANNEL_SUCCESS:
            WLOG(WS_LOG_DEBUG, "Decoding MSGID_CHANNEL_SUCCESS");
            ret = DoChannelSuccess(ssh, buf + idx, payloadSz, &payloadIdx);
            break;

        case MSGID_CHANNEL_FAILURE:
            WLOG(WS_LOG_DEBUG, "Decoding MSGID_CHANNEL_FAILURE");
            ret = DoChannelFailure(ssh, buf + idx, payloadSz, &payloadIdx);
            break;

        default:
            WLOG(WS_LOG_DEBUG, "Unimplemented message ID (%d)", msg);
#ifdef SHOW_UNIMPLEMENTED
            DumpOctetString(buf + idx, payloadSz);
#endif
            ret = SendUnimplemented(ssh);
    }

    /* if the auth is still pending, don't discard the packet data */
    if (ret != WS_AUTH_PENDING) {
        if (payloadSz > 0) {
            idx += payloadIdx;
            if (idx + padSz > len) {
                WLOG(WS_LOG_DEBUG, "Not enough data in buffer for pad.");
                ret = WS_BUFFER_E;
            }
        }

        idx += padSz;
        ssh->inputBuffer.idx = idx;
        ssh->peerSeq++;
        *bufferConsumed = 1;
    }

    return ret;
}


#ifndef WOLFSSH_NO_AES_CTR
#if defined(HAVE_FIPS) && defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION == 2)
    /*
     * The FIPSv2 version of wc_AesCtrEncrypt() only works if the input and
     * output are different buffers. This helper copies each block into a
     * scratch buffer, then calling the AesCtrEncrypt() function on the
     * single scratch buffer. But, only in FIPS builds.
     */
    static INLINE int AesCtrEncryptHelper(Aes* aes,
        byte* out, const byte* in, word32 sz)
    {
        int ret = 0;
        byte scratch[AES_BLOCK_SIZE];

        if (aes == NULL || in == NULL || out == NULL || sz == 0)
            return WS_BAD_ARGUMENT;

        if (sz % AES_BLOCK_SIZE)
            return WS_ENCRYPT_E;

        while (ret == 0 && sz) {
            XMEMCPY(scratch, in, AES_BLOCK_SIZE);
            ret = wc_AesCtrEncrypt(aes, out, scratch, AES_BLOCK_SIZE);
            out += AES_BLOCK_SIZE;
            in += AES_BLOCK_SIZE;
            sz -= AES_BLOCK_SIZE;
        }
        ForceZero(scratch, sizeof(scratch));

        return ret;
    }
    #define AESCTRHELPER(a,b,c,d) AesCtrEncryptHelper((a),(b),(c),(d))
#else
    #define AESCTRHELPER(a,b,c,d) wc_AesCtrEncrypt((a),(b),(c),(d))
#endif
#endif


static INLINE int Encrypt(WOLFSSH* ssh, byte* cipher, const byte* input,
                          word16 sz)
{
    int ret = WS_SUCCESS;

    if (ssh == NULL || cipher == NULL || input == NULL || sz == 0)
        return WS_BAD_ARGUMENT;

    WLOG(WS_LOG_DEBUG, "Encrypt %s", IdToName(ssh->encryptId));

    switch (ssh->encryptId) {
        case ID_NONE:
            break;

#ifndef WOLFSSH_NO_AES_CBC
        case ID_AES128_CBC:
        case ID_AES192_CBC:
        case ID_AES256_CBC:
            if (sz % AES_BLOCK_SIZE || wc_AesCbcEncrypt(&ssh->encryptCipher.aes,
                                 cipher, input, sz) < 0) {

                ret = WS_ENCRYPT_E;
            }
            break;
#endif

#ifndef WOLFSSH_NO_AES_CTR
        case ID_AES128_CTR:
        case ID_AES192_CTR:
        case ID_AES256_CTR:
            if (sz % AES_BLOCK_SIZE || AESCTRHELPER(&ssh->encryptCipher.aes,
                                                       cipher, input, sz) < 0) {

                ret = WS_ENCRYPT_E;
            }
            break;
#endif

        default:
            ret = WS_INVALID_ALGO_ID;
    }

    ssh->txCount += sz;

    return ret;
}


static INLINE int Decrypt(WOLFSSH* ssh, byte* plain, const byte* input,
                          word16 sz)
{
    int ret = WS_SUCCESS;

    if (ssh == NULL || plain == NULL || input == NULL || sz == 0)
        return WS_BAD_ARGUMENT;

    WLOG(WS_LOG_DEBUG, "Decrypt %s", IdToName(ssh->peerEncryptId));

    switch (ssh->peerEncryptId) {
        case ID_NONE:
            break;

#ifndef WOLFSSH_NO_AES_CBC
        case ID_AES128_CBC:
        case ID_AES192_CBC:
        case ID_AES256_CBC:
            if (sz % AES_BLOCK_SIZE || wc_AesCbcDecrypt(&ssh->decryptCipher.aes,
                                 plain, input, sz) < 0) {

                ret = WS_DECRYPT_E;
            }
            break;
#endif

#ifndef WOLFSSH_NO_AES_CTR
        case ID_AES128_CTR:
        case ID_AES192_CTR:
        case ID_AES256_CTR:
            if (sz % AES_BLOCK_SIZE || AESCTRHELPER(&ssh->decryptCipher.aes,
                                                        plain, input, sz) < 0) {

                ret = WS_DECRYPT_E;
            }
            break;
#endif

        default:
            ret = WS_INVALID_ALGO_ID;
    }

    ssh->rxCount += sz;

    if (ret == WS_SUCCESS)
        ret = HighwaterCheck(ssh, WOLFSSH_HWSIDE_RECEIVE);

    return ret;
}


static INLINE int CreateMac(WOLFSSH* ssh, const byte* in, word32 inSz,
                            byte* mac)
{
    byte flatSeq[LENGTH_SZ];
    int ret;

    WMEMSET(flatSeq, 0, LENGTH_SZ);
    c32toa(ssh->seq, flatSeq);

    WLOG(WS_LOG_DEBUG, "CreateMac %s", IdToName(ssh->macId));

    /* Need to MAC the sequence number and the unencrypted packet */
    switch (ssh->macId) {
        case ID_NONE:
            ret = WS_SUCCESS;
            break;

#ifndef WOLFSSH_NO_HMAC_SHA1_96
        case ID_HMAC_SHA1_96:
            {
                Hmac hmac;
                byte digest[WC_SHA_DIGEST_SIZE];

                ret = wc_HmacInit(&hmac, ssh->ctx->heap, INVALID_DEVID);
                if (ret == WS_SUCCESS)
                    ret = wc_HmacSetKey(&hmac, WC_SHA,
                                    ssh->keys.macKey, ssh->keys.macKeySz);
                if (ret == WS_SUCCESS)
                    ret = wc_HmacUpdate(&hmac, flatSeq, sizeof(flatSeq));
                if (ret == WS_SUCCESS)
                    ret = wc_HmacUpdate(&hmac, in, inSz);
                if (ret == WS_SUCCESS)
                    ret = wc_HmacFinal(&hmac, digest);
                if (ret == WS_SUCCESS)
                    WMEMCPY(mac, digest, SHA1_96_SZ);
                wc_HmacFree(&hmac);
            }
            break;
#endif

#ifndef WOLFSSH_NO_HMAC_SHA1
        case ID_HMAC_SHA1:
            {
                Hmac hmac;

                ret = wc_HmacInit(&hmac, ssh->ctx->heap, INVALID_DEVID);
                if (ret == WS_SUCCESS)
                    ret = wc_HmacSetKey(&hmac, WC_SHA,
                                    ssh->keys.macKey, ssh->keys.macKeySz);
                if (ret == WS_SUCCESS)
                    ret = wc_HmacUpdate(&hmac, flatSeq, sizeof(flatSeq));
                if (ret == WS_SUCCESS)
                    ret = wc_HmacUpdate(&hmac, in, inSz);
                if (ret == WS_SUCCESS)
                    ret = wc_HmacFinal(&hmac, mac);
                wc_HmacFree(&hmac);
            }
            break;
#endif

        case ID_HMAC_SHA2_256:
            {
                Hmac hmac;

                ret = wc_HmacInit(&hmac, ssh->ctx->heap, INVALID_DEVID);
                if (ret == WS_SUCCESS)
                    ret = wc_HmacSetKey(&hmac, WC_SHA256,
                                    ssh->keys.macKey,
                                    ssh->keys.macKeySz);
                if (ret == WS_SUCCESS)
                    ret = wc_HmacUpdate(&hmac, flatSeq, sizeof(flatSeq));
                if (ret == WS_SUCCESS)
                    ret = wc_HmacUpdate(&hmac, in, inSz);
                if (ret == WS_SUCCESS)
                    ret = wc_HmacFinal(&hmac, mac);
                wc_HmacFree(&hmac);
            }
            break;

        default:
            WLOG(WS_LOG_DEBUG, "Invalid Mac ID");
            ret = WS_FATAL_ERROR;
    }

    return ret;
}


static INLINE int VerifyMac(WOLFSSH* ssh, const byte* in, word32 inSz,
                            const byte* mac)
{
    int ret;
    byte flatSeq[LENGTH_SZ];
    byte checkMac[MAX_HMAC_SZ];
    Hmac hmac;

    c32toa(ssh->peerSeq, flatSeq);

    WLOG(WS_LOG_DEBUG, "VerifyMac %s", IdToName(ssh->peerMacId));
    WLOG(WS_LOG_DEBUG, "VM: inSz = %u", inSz);
    WLOG(WS_LOG_DEBUG, "VM: seq = %u", ssh->peerSeq);
    WLOG(WS_LOG_DEBUG, "VM: keyLen = %u", ssh->peerKeys.macKeySz);

    WMEMSET(checkMac, 0, sizeof(checkMac));
    ret = wc_HmacInit(&hmac, ssh->ctx->heap, INVALID_DEVID);
    if (ret != WS_SUCCESS) {
        WLOG(WS_LOG_ERROR, "VM: Error initializing hmac structure");
    }
    else {
        switch (ssh->peerMacId) {
            case ID_NONE:
                ret = WS_SUCCESS;
                break;

            case ID_HMAC_SHA1:
            case ID_HMAC_SHA1_96:
                ret = wc_HmacSetKey(&hmac, WC_SHA, ssh->peerKeys.macKey,
                        ssh->peerKeys.macKeySz);
                if (ret == WS_SUCCESS)
                    ret = wc_HmacUpdate(&hmac, flatSeq, sizeof(flatSeq));
                if (ret == WS_SUCCESS)
                    ret = wc_HmacUpdate(&hmac, in, inSz);
                if (ret == WS_SUCCESS)
                    ret = wc_HmacFinal(&hmac, checkMac);
                if (ConstantCompare(checkMac, mac, ssh->peerMacSz) != 0)
                    ret = WS_VERIFY_MAC_E;
                break;

            case ID_HMAC_SHA2_256:
                ret = wc_HmacSetKey(&hmac, WC_SHA256, ssh->peerKeys.macKey,
                        ssh->peerKeys.macKeySz);
                if (ret == WS_SUCCESS)
                    ret = wc_HmacUpdate(&hmac, flatSeq, sizeof(flatSeq));
                if (ret == WS_SUCCESS)
                    ret = wc_HmacUpdate(&hmac, in, inSz);
                if (ret == WS_SUCCESS)
                    ret = wc_HmacFinal(&hmac, checkMac);
                if (ConstantCompare(checkMac, mac, ssh->peerMacSz) != 0)
                    ret = WS_VERIFY_MAC_E;
                break;

            default:
                ret = WS_INVALID_ALGO_ID;
        }
        wc_HmacFree(&hmac);
    }

    return ret;
}


#ifndef WOLFSSH_NO_AEAD
static INLINE void AeadIncrementExpIv(byte* iv)
{
    int i;

    iv += AEAD_IMP_IV_SZ;

    for (i = AEAD_EXP_IV_SZ-1; i >= 0; i--) {
        if (++iv[i]) return;
    }
}


static INLINE int EncryptAead(WOLFSSH* ssh, byte* cipher,
                              const byte* input, word16 sz,
                              byte* authTag, const byte* auth,
                              word16 authSz)
{
    int ret = WS_SUCCESS;

    if (ssh == NULL || cipher == NULL || input == NULL || sz == 0 ||
        authTag == NULL || auth == NULL || authSz == 0)
        return WS_BAD_ARGUMENT;

    WLOG(WS_LOG_DEBUG, "EncryptAead %s", IdToName(ssh->encryptId));

    switch (ssh->encryptId) {
#ifndef WOLFSSH_NO_AES_GCM
        case ID_AES128_GCM:
        case ID_AES192_GCM:
        case ID_AES256_GCM:
            ret = wc_AesGcmEncrypt(&ssh->encryptCipher.aes, cipher, input, sz,
                    ssh->keys.iv, ssh->keys.ivSz,
                    authTag, ssh->macSz, auth, authSz);
            break;
#endif

        default:
            ret = WS_INVALID_ALGO_ID;
    }

    AeadIncrementExpIv(ssh->keys.iv);
    ssh->txCount += sz;

    return ret;
}


static INLINE int DecryptAead(WOLFSSH* ssh, byte* plain,
                              const byte* input, word16 sz,
                              const byte* authTag, const byte* auth,
                              word16 authSz)
{
    int ret = WS_SUCCESS;

    if (ssh == NULL || plain == NULL || input == NULL || sz == 0 ||
        authTag == NULL || auth == NULL || authSz == 0)
        return WS_BAD_ARGUMENT;

    WLOG(WS_LOG_DEBUG, "DecryptAead %s", IdToName(ssh->peerEncryptId));

    switch (ssh->peerEncryptId) {
#ifndef WOLFSSH_NO_AES_GCM
        case ID_AES128_GCM:
        case ID_AES192_GCM:
        case ID_AES256_GCM:
            ret = wc_AesGcmDecrypt(&ssh->decryptCipher.aes, plain, input, sz,
                    ssh->peerKeys.iv, ssh->peerKeys.ivSz,
                    authTag, ssh->peerMacSz, auth, authSz);
            break;
#endif

        default:
            ret = WS_INVALID_ALGO_ID;
    }

    AeadIncrementExpIv(ssh->peerKeys.iv);
    ssh->rxCount += sz;

    if (ret == WS_SUCCESS)
        ret = HighwaterCheck(ssh, WOLFSSH_HWSIDE_RECEIVE);

    return ret;
}
#endif /* WOLFSSH_NO_AEAD */


int DoReceive(WOLFSSH* ssh)
{
    int ret = WS_SUCCESS;
    int verifyResult;
    word32 readSz;
    byte peerBlockSz = ssh->peerBlockSz;
    byte peerMacSz = ssh->peerMacSz;
    byte aeadMode = ssh->peerAeadMode;
    byte bufferConsumed = 0;

    switch (ssh->processReplyState) {
        case PROCESS_INIT:
            readSz = peerBlockSz;
            WLOG(WS_LOG_DEBUG, "PR1: size = %u", readSz);
            if ((ret = GetInputData(ssh, readSz)) < 0) {
                return ret;
            }
            ssh->processReplyState = PROCESS_PACKET_LENGTH;

            if (!aeadMode) {
                /* Decrypt first block if encrypted */
                ret = Decrypt(ssh,
                        ssh->inputBuffer.buffer + ssh->inputBuffer.idx,
                        ssh->inputBuffer.buffer + ssh->inputBuffer.idx,
                        readSz);
                if (ret != WS_SUCCESS) {
                    WLOG(WS_LOG_DEBUG, "PR: First decrypt fail");
                    ssh->error = ret;
                    return WS_FATAL_ERROR;
                }
            }
            NO_BREAK;

        case PROCESS_PACKET_LENGTH:
            if (ssh->inputBuffer.idx + UINT32_SZ > ssh->inputBuffer.bufferSz) {
                ssh->error = WS_OVERFLOW_E;
                return WS_FATAL_ERROR;
            }

            /* Peek at the packet_length field. */
            ato32(ssh->inputBuffer.buffer + ssh->inputBuffer.idx, &ssh->curSz);
            if (ssh->curSz > MAX_PACKET_SZ - (word32)peerMacSz - UINT32_SZ) {
                ssh->error = WS_OVERFLOW_E;
                return WS_FATAL_ERROR;
            }
            ssh->processReplyState = PROCESS_PACKET_FINISH;
            NO_BREAK;

        case PROCESS_PACKET_FINISH:
            /* readSz is the full packet size */
            readSz = UINT32_SZ + ssh->curSz + peerMacSz;
            WLOG(WS_LOG_DEBUG, "PR2: size = %u", readSz);
            if (readSz > 0) {
                if ((ret = GetInputData(ssh, readSz)) < 0) {
                    return ret;
                }

                if (!aeadMode) {
                    if (ssh->curSz + UINT32_SZ - peerBlockSz > 0) {
                        ret = Decrypt(ssh,
                                ssh->inputBuffer.buffer + ssh->inputBuffer.idx
                                    + peerBlockSz,
                                ssh->inputBuffer.buffer + ssh->inputBuffer.idx
                                    + peerBlockSz,
                                UINT32_SZ + ssh->curSz - peerBlockSz);
                    }
                    else {
                        /* Entire packet fit in one block, don't need
                         * to decrypt any more data this packet. */
                    }

                    /* Verify the buffer is big enough for the data and mac.
                     * Even if the decrypt step fails, verify the MAC anyway.
                     * This keeps consistent timing. */
                    verifyResult = VerifyMac(ssh,
                            ssh->inputBuffer.buffer + ssh->inputBuffer.idx,
                            UINT32_SZ + ssh->curSz,
                            ssh->inputBuffer.buffer + ssh->inputBuffer.idx
                                + UINT32_SZ + ssh->curSz);
                    if (ret != WS_SUCCESS) {
                        WLOG(WS_LOG_DEBUG, "PR: Decrypt fail");
                        ssh->error = ret;
                        return WS_FATAL_ERROR;
                    }
                    if (verifyResult != WS_SUCCESS) {
                        WLOG(WS_LOG_DEBUG, "PR: VerifyMac fail");
                        ssh->error = verifyResult;
                        return WS_FATAL_ERROR;
                    }
                }
                else {
#ifndef WOLFSSH_NO_AEAD
                    ret = DecryptAead(ssh,
                            ssh->inputBuffer.buffer + ssh->inputBuffer.idx
                                + UINT32_SZ,
                            ssh->inputBuffer.buffer + ssh->inputBuffer.idx
                                + UINT32_SZ,
                            ssh->curSz,
                            ssh->inputBuffer.buffer + ssh->inputBuffer.idx
                                + UINT32_SZ + ssh->curSz,
                            ssh->inputBuffer.buffer + ssh->inputBuffer.idx,
                            UINT32_SZ);

                    if (ret != WS_SUCCESS) {
                        WLOG(WS_LOG_DEBUG, "PR: DecryptAead fail");
                        ssh->error = ret;
                        return WS_FATAL_ERROR;
                    }
#endif
                }
            }
            ssh->processReplyState = PROCESS_PACKET;
            NO_BREAK;

        case PROCESS_PACKET:
            ret = DoPacket(ssh, &bufferConsumed);
            ssh->error = ret;
            if (ret < 0 && !(ret == WS_CHAN_RXD || ret == WS_EXTDATA ||
                    ret == WS_CHANNEL_CLOSED || ret == WS_WANT_WRITE ||
                    ret == WS_REKEYING || ret == WS_WANT_READ)) {
                ret = WS_FATAL_ERROR;
            }
            break;

        default:
            WLOG(WS_LOG_DEBUG, "Bad process input state, program error");
            ssh->error = WS_INPUT_CASE_E;
            return WS_FATAL_ERROR;
    }

    if (bufferConsumed) {
        WLOG(WS_LOG_DEBUG, "PR3: peerMacSz = %u", peerMacSz);
        ssh->inputBuffer.idx += peerMacSz;

        WLOG(WS_LOG_DEBUG, "PR4: Shrinking input buffer");
        ShrinkBuffer(&ssh->inputBuffer, 1);
        ssh->processReplyState = PROCESS_INIT;
    }

    WLOG(WS_LOG_DEBUG, "PR5: txCount = %u, rxCount = %u",
         ssh->txCount, ssh->rxCount);

    return ret;
}


int DoProtoId(WOLFSSH* ssh)
{
    int ret;
    word32 idSz;
    byte* eol;
    byte  SSH_PROTO_EOL_SZ = 1;

    if ( (ret = GetInputText(ssh, &eol)) < 0) {
        WLOG(WS_LOG_DEBUG, "get input text failed");
        return ret;
    }

    if (eol == NULL) {
        WLOG(WS_LOG_DEBUG, "invalid EOL");
        return WS_VERSION_E;
    }

    if (WSTRNCASECMP((char*)ssh->inputBuffer.buffer,
                     ssh->ctx->sshProtoIdStr, SSH_PROTO_SZ) == 0) {

        if (ssh->ctx->side == WOLFSSH_ENDPOINT_SERVER)
            ssh->clientState = CLIENT_VERSION_DONE;
        else
            ssh->serverState = SERVER_VERSION_DONE;
    }
    else {
        WLOG(WS_LOG_DEBUG, "SSH version mismatch");
        return WS_VERSION_E;
    }
    if (WSTRNCMP((char*)ssh->inputBuffer.buffer,
                 OpenSSH, sizeof(OpenSSH)-1) == 0) {
        ssh->clientOpenSSH = 1;
    }

    if (*eol == '\r') {
        SSH_PROTO_EOL_SZ++;
    }
    *eol = 0;

    idSz = (word32)WSTRLEN((char*)ssh->inputBuffer.buffer);

    /* Store the proto ID for later use. It is used in keying and rekeying. */
    ssh->peerProtoId = (byte*)WMALLOC(idSz + LENGTH_SZ,
                                         ssh->ctx->heap, DYNTYPE_STRING);
    if (ssh->peerProtoId == NULL)
        ret = WS_MEMORY_E;
    else {
        c32toa(idSz, ssh->peerProtoId);
        WMEMCPY(ssh->peerProtoId + LENGTH_SZ, ssh->inputBuffer.buffer, idSz);
        ssh->peerProtoIdSz = idSz + LENGTH_SZ;
    }

    ssh->inputBuffer.idx += idSz + SSH_PROTO_EOL_SZ;

    ShrinkBuffer(&ssh->inputBuffer, 0);

    return ret;
}


int SendProtoId(WOLFSSH* ssh)
{
    int ret = WS_SUCCESS;
    word32 sshProtoIdStrSz;

    if (ssh == NULL)
        ret = WS_BAD_ARGUMENT;

    if (ret == WS_SUCCESS) {
        WLOG(WS_LOG_DEBUG, "%s", ssh->ctx->sshProtoIdStr);
        sshProtoIdStrSz = (word32)WSTRLEN(ssh->ctx->sshProtoIdStr);
        ret = GrowBuffer(&ssh->outputBuffer, sshProtoIdStrSz);
    }

    if (ret == WS_SUCCESS) {
        WMEMCPY(ssh->outputBuffer.buffer + ssh->outputBuffer.length,
                ssh->ctx->sshProtoIdStr, sshProtoIdStrSz);
        ssh->outputBuffer.length += sshProtoIdStrSz;
        ret = wolfSSH_SendPacket(ssh);
    }

    return ret;
}


/* payloadSz is an estimate. It should be a worst case. The actual value
 * will be nailed down when the packet is bundled to be sent. */
static int PreparePacket(WOLFSSH* ssh, word32 payloadSz)
{
    int ret = WS_SUCCESS;

    if (ssh == NULL)
        ret = WS_BAD_ARGUMENT;

    if (ret == WS_SUCCESS) {
        if (ssh->outputBuffer.length < ssh->outputBuffer.idx)
            ret = WS_OVERFLOW_E;
    }

    if (ret == WS_SUCCESS) {
        word32 packetSz, outputSz;
        byte paddingSz;

        paddingSz = ssh->blockSz * 2;
        packetSz = PAD_LENGTH_SZ + payloadSz + paddingSz;
        outputSz = LENGTH_SZ + packetSz + ssh->macSz;

        ret = GrowBuffer(&ssh->outputBuffer, outputSz);
    }

    if (ret == WS_SUCCESS) {
        ssh->packetStartIdx = ssh->outputBuffer.length;
        ssh->outputBuffer.length += LENGTH_SZ + PAD_LENGTH_SZ;
    }

    return ret;
}


static int BundlePacket(WOLFSSH* ssh)
{
    byte* output = NULL;
    word32 idx = 0;
    byte paddingSz = 0;
    int ret = WS_SUCCESS;

    if (ssh == NULL)
        ret = WS_BAD_ARGUMENT;

    if (ret == WS_SUCCESS) {
        word32 payloadSz, packetSz;

        output = ssh->outputBuffer.buffer;
        idx = ssh->outputBuffer.length;

        /* Calculate the actual payload size based on the data
         * written into the buffer. packetStartIdx is before the
         * LENGTH and PAD_LENGTH, subtract those out, as well. */
        payloadSz = idx - ssh->packetStartIdx - LENGTH_SZ - PAD_LENGTH_SZ;

        /* Minimum value for paddingSz is 4. */
        paddingSz = ssh->blockSz -
                    ((ssh->aeadMode ? 0 : LENGTH_SZ) +
                     PAD_LENGTH_SZ + payloadSz) % ssh->blockSz;
        if (paddingSz < MIN_PAD_LENGTH)
            paddingSz += ssh->blockSz;

        packetSz = PAD_LENGTH_SZ + payloadSz + paddingSz;

        /* fill in the packetSz, paddingSz */
        c32toa(packetSz, output + ssh->packetStartIdx);
        output[ssh->packetStartIdx + LENGTH_SZ] = paddingSz;

        /* Add the padding */
        WLOG(WS_LOG_DEBUG, "BP: paddingSz = %u", paddingSz);
        if (ssh->encryptId == ID_NONE)
            WMEMSET(output + idx, 0, paddingSz);
        else if (wc_RNG_GenerateBlock(ssh->rng, output + idx, paddingSz) < 0) {
            ret = WS_CRYPTO_FAILED;
            WLOG(WS_LOG_DEBUG, "BP: failed to add padding");
        }
    }

    if (ret == WS_SUCCESS) {
        if (!ssh->aeadMode) {
            byte macSz = MacSzForId(ssh->macId);

            idx += paddingSz;

            WMEMSET(output + idx, 0, macSz);
            if (idx + macSz > ssh->outputBuffer.bufferSz) {
                ret = WS_BUFFER_E;
            }
            else {
                ret = CreateMac(ssh, ssh->outputBuffer.buffer +
                        ssh->packetStartIdx, ssh->outputBuffer.length -
                        ssh->packetStartIdx + paddingSz, output + idx);
            }

            if (ret == WS_SUCCESS) {
                idx += ssh->macSz;
                ret = Encrypt(ssh,
                              ssh->outputBuffer.buffer + ssh->packetStartIdx,
                              ssh->outputBuffer.buffer + ssh->packetStartIdx,
                              ssh->outputBuffer.length -
                                  ssh->packetStartIdx + paddingSz);
            }
            else {
                WLOG(WS_LOG_DEBUG, "BP: failed to generate mac");
            }
        }
        else {
#ifndef WOLFSSH_NO_AEAD
            idx += paddingSz;
            ret = EncryptAead(ssh,
                    ssh->outputBuffer.buffer + ssh->packetStartIdx + LENGTH_SZ,
                    ssh->outputBuffer.buffer + ssh->packetStartIdx + LENGTH_SZ,
                    ssh->outputBuffer.length - ssh->packetStartIdx + paddingSz
                        - LENGTH_SZ,
                    output + idx,
                    ssh->outputBuffer.buffer + ssh->packetStartIdx,
                    LENGTH_SZ);
            idx += ssh->macSz;
#else
            ret = WS_INVALID_ALGO_ID;
#endif
        }
    }

    if (ret == WS_SUCCESS) {
        ssh->seq++;
        ssh->outputBuffer.length = idx;
    }
    else {
        WLOG(WS_LOG_DEBUG, "BP: failed to encrypt buffer");
    }

    return ret;
}


static void PurgePacket(WOLFSSH* ssh)
{
    if (ssh != NULL) {
        ssh->packetStartIdx = 0;
        ssh->outputBuffer.idx = 0;
        ssh->outputBuffer.plainSz = 0;
        ShrinkBuffer(&ssh->outputBuffer, 1);
    }
}


static INLINE void CopyNameList(byte* buf, word32* idx,
                                                const char* src, word32 srcSz)
{
    word32 begin = *idx;

    c32toa(srcSz, buf + begin);
    begin += LENGTH_SZ;
    WMEMCPY(buf + begin, src, srcSz);
    begin += srcSz;

    *idx = begin;
}


static INLINE void CopyNameListPlus(byte* buf, word32* idx,
        const char* src, word32 srcSz, const char* plus, word32 plusSz)
{
    word32 begin = *idx;

    c32toa(srcSz + plusSz, buf + begin);
    begin += LENGTH_SZ;
    WMEMCPY(buf + begin, src, srcSz);
    begin += srcSz;
    if (plusSz) {
        WMEMCPY(buf + begin, plus, plusSz);
    }
    begin += plusSz;

    *idx = begin;
}


/*
 * Iterates over a list of ID values and builds a string of names.
 *
 * @param buf       buffer to write names
 * @param bufSz     size of buffer to write names
 * @param src       source ID list
 * @param srcSz     size of the source ID list
 * @return          string length of buf after writing or WS_BUFFER_E
 */
static int BuildNameList(char* buf, word32 bufSz,
        const byte* src, word32 srcSz)
{
    const char* name;
    int nameSz, idx;

    WLOG(WS_LOG_DEBUG, "Entering BuildNameList()");

    idx = 0;

    do {
        name = IdToName(*src);
        nameSz = (int)WSTRLEN(name);

        if (buf != NULL) {
            WLOG(WS_LOG_DEBUG, "\tAdding name : %s", name);
            if (nameSz + 1 + idx > (int)bufSz) {
                idx = WS_BUFFER_E;
                break;
            }

            WMEMCPY(buf + idx, name, nameSz);
            idx += nameSz;

            src++;
            srcSz--;
            buf[idx++] = (srcSz > 0) ? ',' : '\0';
        }
        else {
            src++;
            srcSz--;
            idx += nameSz + 1;
        }
    } while (srcSz > 0);

    return idx - 1;
}


int SendKexInit(WOLFSSH* ssh)
{
    byte* output = NULL;
    byte* payload = NULL;
    char* keyAlgoNames = NULL;
    const char* kexAlgoNamesPlus = NULL;
    word32 idx = 0, payloadSz = 0,
            kexAlgoNamesSz = 0, kexAlgoNamesPlusSz = 0,
            keyAlgoNamesSz = 0, encAlgoNamesSz = 0,
            macAlgoNamesSz = 0, noneNamesSz = 0;

    int ret = WS_SUCCESS;

    WLOG(WS_LOG_DEBUG, "Entering SendKexInit()");

    if (ssh == NULL)
        ret = WS_BAD_ARGUMENT;

    if (ssh->ctx->side == WOLFSSH_ENDPOINT_SERVER &&
            ssh->ctx->privateKeyCount == 0) {
        WLOG(WS_LOG_DEBUG, "Server needs at least one private key");
        ret = WS_BAD_ARGUMENT;
    }

    if (ret == WS_SUCCESS) {
        ssh->isKeying = 1;
        if (ssh->handshake == NULL) {
            ssh->handshake = HandshakeInfoNew(ssh->ctx->heap);
            if (ssh->handshake == NULL) {
                WLOG(WS_LOG_DEBUG, "Couldn't allocate handshake info");
                ret = WS_MEMORY_E;
            }
        }
    }

    if (ret == WS_SUCCESS) {
        if (!ssh->algoListKey && ssh->ctx->side == WOLFSSH_ENDPOINT_SERVER) {
            keyAlgoNamesSz = BuildNameList(NULL, 0,
                    ssh->ctx->publicKeyAlgo,
                    ssh->ctx->publicKeyAlgoCount)
                + 1;
            keyAlgoNames = (char*)WMALLOC(keyAlgoNamesSz,
                    ssh->ctx->heap, DYNTYPE_STRING);
            if (keyAlgoNames) {
                ret = BuildNameList(keyAlgoNames, keyAlgoNamesSz,
                    ssh->ctx->publicKeyAlgo,
                    ssh->ctx->publicKeyAlgoCount);
                if (ret > 0) {
                    keyAlgoNamesSz = (word32)ret;
                    ret = WS_SUCCESS;
                }
            }
            else {
                ret = WS_MEMORY_E;
            }
        }
    }

    if (ret == WS_SUCCESS) {
        if (ssh->ctx->side == WOLFSSH_ENDPOINT_CLIENT) {
            kexAlgoNamesPlus = ",ext-info-c";
            kexAlgoNamesPlusSz = (word32)WSTRLEN(kexAlgoNamesPlus);
        }

        kexAlgoNamesSz = AlgoListSz(ssh->algoListKex);
        encAlgoNamesSz = AlgoListSz(ssh->algoListCipher);
        if (!keyAlgoNames) {
            keyAlgoNamesSz = AlgoListSz(ssh->algoListKey);
        }
        else {
            keyAlgoNamesSz = AlgoListSz(keyAlgoNames);
        }
        macAlgoNamesSz = AlgoListSz(ssh->algoListMac);
        noneNamesSz = AlgoListSz(cannedNoneNames);
        payloadSz = MSG_ID_SZ + COOKIE_SZ + (LENGTH_SZ * 11) + BOOLEAN_SZ +
            + kexAlgoNamesSz + kexAlgoNamesPlusSz + keyAlgoNamesSz
            + (encAlgoNamesSz * 2) + (macAlgoNamesSz * 2) + (noneNamesSz * 2);
        ret = PreparePacket(ssh, payloadSz);
    }

    if (ret == WS_SUCCESS) {
        output = ssh->outputBuffer.buffer;
        idx = ssh->outputBuffer.length;
        payload = output + idx;

        output[idx++] = MSGID_KEXINIT;

        ret = wc_RNG_GenerateBlock(ssh->rng, output + idx, COOKIE_SZ);
    }

    if (ret == WS_SUCCESS) {
        byte* buf;
        word32 bufSz = payloadSz + LENGTH_SZ;

        idx += COOKIE_SZ;

        CopyNameListPlus(output, &idx,
                ssh->algoListKex, kexAlgoNamesSz,
                kexAlgoNamesPlus, kexAlgoNamesPlusSz);
        if (!keyAlgoNames) {
            CopyNameList(output, &idx, ssh->algoListKey, keyAlgoNamesSz);
        }
        else {
            CopyNameList(output, &idx, keyAlgoNames, keyAlgoNamesSz);
        }
        CopyNameList(output, &idx, ssh->algoListCipher, encAlgoNamesSz);
        CopyNameList(output, &idx, ssh->algoListCipher, encAlgoNamesSz);
        CopyNameList(output, &idx, ssh->algoListMac, macAlgoNamesSz);
        CopyNameList(output, &idx, ssh->algoListMac, macAlgoNamesSz);
        CopyNameList(output, &idx, cannedNoneNames, noneNamesSz);
        CopyNameList(output, &idx, cannedNoneNames, noneNamesSz);
        c32toa(0, output + idx); /* Languages - Client To Server (0) */
        idx += LENGTH_SZ;
        c32toa(0, output + idx); /* Languages - Server To Client (0) */
        idx += LENGTH_SZ;
        output[idx++] = 0;       /* First KEX packet follows (false) */
        c32toa(0, output + idx); /* Reserved (0) */
        idx += LENGTH_SZ;

        if (ssh->handshake->kexInit != NULL) {
            WFREE(ssh->handshake->kexInit, ssh->ctx->heap, DYNTYPE_STRING);
            ssh->handshake->kexInit = NULL;
            ssh->handshake->kexInitSz = 0;
        }

        buf = (byte*)WMALLOC(bufSz, ssh->ctx->heap, DYNTYPE_STRING);
        if (buf == NULL) {
            WLOG(WS_LOG_DEBUG, "Cannot allocate storage for KEX Init msg");
            ret = WS_MEMORY_E;
        }
        else {
            c32toa(payloadSz, buf);
            WMEMCPY(buf + LENGTH_SZ, payload, payloadSz);
            ssh->handshake->kexInit = buf;
            ssh->handshake->kexInitSz = bufSz;
        }
    }

    if (keyAlgoNames) {
        WFREE(keyAlgoNames, ssh->ctx->heap, DYNTYPE_STRING);
    }

    if (ret == WS_SUCCESS) {
        /* increase amount to be sent only if BundlePacket will be called */
        ssh->outputBuffer.length = idx;
        ret = BundlePacket(ssh);
    }

    if (ret == WS_SUCCESS)
        ret = wolfSSH_SendPacket(ssh);

    if (ret != WS_WANT_WRITE && ret != WS_SUCCESS)
        PurgePacket(ssh);

    WLOG(WS_LOG_DEBUG, "Leaving SendKexInit(), ret = %d", ret);
    return ret;
}


struct wolfSSH_sigKeyBlockFull {
        byte pubKeyId; /* handshake->pubKeyId */
        byte pubKeyFmtId;
        word32 sz;
        const char *pubKeyName; /* IdToName(handshake->pubKeyId) */
        word32 pubKeyNameSz;
        const char *pubKeyFmtName;
        word32 pubKeyFmtNameSz;
        union {
#ifndef WOLFSSH_NO_RSA
            struct {
                RsaKey key;
                byte e[1025];
                word32 eSz;
                byte ePad;
                byte n[1025];
                word32 nSz;
                byte nPad;
            } rsa;
#endif
#ifndef WOLFSSH_NO_ECDSA
            struct {
                ecc_key key;
                word32 keyBlobSz;
                const char *keyBlobName;
                word32 keyBlobNameSz;
                byte q[257];
                word32 qSz;
                byte qPad;
                const char *primeName;
                word32 primeNameSz;
            } ecc;

#ifndef WOLFSSH_NO_ED25519
            struct {
                ed25519_key key;
                word32 keyBlobSz;
                const char *keyBlobName;
                word32 keyBlobNameSz;
                byte q[ED25519_PUB_KEY_SIZE+1];
                word32 qSz;
                byte qPad;
            } ed;
#endif
#endif
        } sk;
};

#ifndef WOLFSSH_NO_ECDH_NISTP256_KYBER_LEVEL1_SHA256
    /* Size of Kyber public key (bigger than ciphertext) and some extra for the
     * ECC hybrid component. */
    #define KEX_F_SIZE 1024
#else
    #define KEX_F_SIZE (256 + 1)
#endif

#define KEX_SIG_SIZE (512)

#ifdef WOLFSSH_CERTS
/* places RFC6187 style cert + ocsp into output buffer and advances idx
 * [size of stiring] [string] [cert count] [cert size] [cert] [...]
 *                            [ocsp count] [ocsp size] [ocsp] [...]
 * returns WS_SUCCESS on success
 * returns LENGTH_ONLY_E if output is null, and updates outputSz with required
 *      output buffer size
 */
static int BuildRFC6187Info(WOLFSSH* ssh, int pubKeyID,
            const byte* cert, word32 certSz,
            const byte* ocsp, word32 ocspSz,
            byte* output, word32* outputSz, word32* idx)
{
    int ret = WS_SUCCESS;
    word32 localIdx;
    const byte* publicKeyType;
    word32 publicKeyTypeSz;

    localIdx = *idx;
    switch (pubKeyID) {
        #ifndef WOLFSSH_NO_SSH_RSA_SHA1
        case ID_X509V3_SSH_RSA:
            publicKeyType = (const byte*)cannedKeyAlgoX509RsaNames;
            break;
        #endif

        #ifndef WOLFSSH_NO_ECDSA_SHA2_NISTP256
        case ID_X509V3_ECDSA_SHA2_NISTP256:
            publicKeyType = (const byte*)cannedKeyAlgoX509Ecc256Names;
            break;
        #endif

        #ifndef WOLFSSH_NO_ECDSA_SHA2_NISTP384
        case ID_X509V3_ECDSA_SHA2_NISTP384:
            publicKeyType = (const byte*)cannedKeyAlgoX509Ecc384Names;
            break;
        #endif

        #ifndef WOLFSSH_NO_ECDSA_SHA2_NISTP521
        case ID_X509V3_ECDSA_SHA2_NISTP521:
            publicKeyType = (const byte*)cannedKeyAlgoX509Ecc521Names;
            break;
        #endif

        default:
            return WS_BAD_ARGUMENT;
    }
    publicKeyTypeSz = (word32)WSTRLEN((const char*)publicKeyType);

    /* length of entire bundle of info */
    if (output) {
        c32toa((LENGTH_SZ * 2) + (UINT32_SZ * 2) +
            publicKeyTypeSz + certSz, output + localIdx);
    }
    localIdx += LENGTH_SZ;

    /* add public key type */
    if (output)
        c32toa(publicKeyTypeSz, output + localIdx);
    localIdx += LENGTH_SZ;
    if (output)
        WMEMCPY(output + localIdx, publicKeyType, publicKeyTypeSz);
    localIdx += publicKeyTypeSz;

    /* add cert count (hard set to 1 cert for now @TODO) */
    if (output)
        c32toa(1, output + localIdx);
    localIdx += UINT32_SZ;

    /* add in certificates, note this could later be multiple [certsz][cert] */
    if (output)
        c32toa(certSz, output + localIdx);
    localIdx += LENGTH_SZ;
    if (output)
        WMEMCPY(output + localIdx, cert, certSz);
    localIdx += certSz;

    /* add in ocsp count hard set to 0 */
    if (output)
        c32toa(0, output + localIdx); /* ocsp count */
    localIdx += UINT32_SZ;

    /* here is where OCSP's would be appended [ocsp size][ocsp] */
    WOLFSSH_UNUSED(ocsp);
    WOLFSSH_UNUSED(ocspSz);

    /* update idx on success */
    if (output) {
        *idx = localIdx;
    }
    else {
        *outputSz = localIdx - *idx;
        ret = LENGTH_ONLY_E;
    }

    WOLFSSH_UNUSED(ssh);
    WOLFSSH_UNUSED(outputSz);
    return ret;
}
#endif /* WOLFSSH_CERTS */


#ifndef WOLFSSH_NO_DH
static int GetDHPrimeGroup(int kexId, const byte** primeGroup,
    word32* primeGroupSz, const byte** generator, word32* generatorSz)
{
    int ret = WS_SUCCESS;

    switch (kexId) {
        #ifndef WOLFSSH_NO_DH_GROUP1_SHA1
        case ID_DH_GROUP1_SHA1:
            *primeGroup = dhPrimeGroup1;
            *primeGroupSz = dhPrimeGroup1Sz;
            *generator = dhGenerator;
            *generatorSz = dhGeneratorSz;
            break;
        #endif
        #ifndef WOLFSSH_NO_DH_GROUP14_SHA1
        case ID_DH_GROUP14_SHA1:
            *primeGroup = dhPrimeGroup14;
            *primeGroupSz = dhPrimeGroup14Sz;
            *generator = dhGenerator;
            *generatorSz = dhGeneratorSz;
            break;
        #endif
        #ifndef WOLFSSH_NO_DH_GROUP14_SHA256
        case ID_DH_GROUP14_SHA256:
            *primeGroup = dhPrimeGroup14;
            *primeGroupSz = dhPrimeGroup14Sz;
            *generator = dhGenerator;
            *generatorSz = dhGeneratorSz;
            break;
        #endif
        #ifndef WOLFSSH_NO_DH_GEX_SHA256
        case ID_DH_GEX_SHA256:
            *primeGroup = dhPrimeGroup14;
            *primeGroupSz = dhPrimeGroup14Sz;
            *generator = dhGenerator;
            *generatorSz = dhGeneratorSz;
            break;
        #endif
        default:
            ret = WS_INVALID_ALGO_ID;
    }

    return ret;
}
#endif /* !WOLFSSH_NO_DH */


/* Sets the signing key and hashes in the public key
 * returns WS_SUCCESS on success */
static int SendKexGetSigningKey(WOLFSSH* ssh,
        struct wolfSSH_sigKeyBlockFull *sigKeyBlock_ptr,
        enum wc_HashType hashId, wc_HashAlg* hash, word32 keyIdx)
{
    int ret = 0;
    byte isCert = 0;
    void* heap;
    byte scratchLen[LENGTH_SZ];
    word32 scratch = 0;
#ifndef WOLFSSH_NO_DH_GEX_SHA256
    const byte* primeGroup = NULL;
    word32 primeGroupSz = 0;
    const byte* generator = NULL;
    word32 generatorSz = 0;
#endif


    heap = ssh->ctx->heap;

    switch (sigKeyBlock_ptr->pubKeyId) {
        #ifndef WOLFSSH_NO_RSA
        #ifdef WOLFSSH_CERTS
        case ID_X509V3_SSH_RSA:
            isCert = 1;
            NO_BREAK;
        #endif
        case ID_SSH_RSA:
        case ID_RSA_SHA2_256:
        case ID_RSA_SHA2_512:
            /* Decode the user-configured RSA private key. */
            sigKeyBlock_ptr->sk.rsa.eSz =
                    (word32)sizeof(sigKeyBlock_ptr->sk.rsa.e);
            sigKeyBlock_ptr->sk.rsa.nSz =
                    (word32)sizeof(sigKeyBlock_ptr->sk.rsa.n);
            ret = wc_InitRsaKey(&sigKeyBlock_ptr->sk.rsa.key, heap);
            if (ret == 0)
                ret = wc_RsaPrivateKeyDecode(ssh->ctx->privateKey[keyIdx].key,
                        &scratch, &sigKeyBlock_ptr->sk.rsa.key,
                        (int)ssh->ctx->privateKey[keyIdx].keySz);

            /* hash in usual public key if not RFC6187 style cert use */
            if (!isCert) {
                /* Flatten the public key into mpint values for the hash. */
                if (ret == 0)
                    ret = wc_RsaFlattenPublicKey(&sigKeyBlock_ptr->sk.rsa.key,
                                                 sigKeyBlock_ptr->sk.rsa.e,
                                                 &sigKeyBlock_ptr->sk.rsa.eSz,
                                                 sigKeyBlock_ptr->sk.rsa.n,
                                                 &sigKeyBlock_ptr->sk.rsa.nSz);
                if (ret == 0) {
                    /* Add a pad byte if the mpint has the MSB set. */
                    ret = CreateMpint(sigKeyBlock_ptr->sk.rsa.e,
                            &sigKeyBlock_ptr->sk.rsa.eSz,
                            &sigKeyBlock_ptr->sk.rsa.ePad);
                }
                if (ret == 0) {
                    /* Add a pad byte if the mpint has the MSB set. */
                    ret = CreateMpint(sigKeyBlock_ptr->sk.rsa.n,
                            &sigKeyBlock_ptr->sk.rsa.nSz,
                            &sigKeyBlock_ptr->sk.rsa.nPad);
                }
                if (ret == 0) {
                    sigKeyBlock_ptr->sz = (LENGTH_SZ * 3) +
                                      sigKeyBlock_ptr->pubKeyFmtNameSz +
                                      sigKeyBlock_ptr->sk.rsa.eSz +
                                      sigKeyBlock_ptr->sk.rsa.ePad +
                                      sigKeyBlock_ptr->sk.rsa.nSz +
                                      sigKeyBlock_ptr->sk.rsa.nPad;
                    c32toa(sigKeyBlock_ptr->sz, scratchLen);
                    /* Hash in the length of the public key block. */
                    ret = HashUpdate(hash, hashId, scratchLen, LENGTH_SZ);
                }
                /* Hash in the length of the key type string. */
                if (ret == 0) {
                    c32toa(sigKeyBlock_ptr->pubKeyFmtNameSz, scratchLen);
                    ret = HashUpdate(hash, hashId, scratchLen, LENGTH_SZ);
                }
                /* Hash in the key type string. */
                if (ret == 0)
                    ret = HashUpdate(hash, hashId,
                            (byte*)sigKeyBlock_ptr->pubKeyFmtName,
                            sigKeyBlock_ptr->pubKeyFmtNameSz);
                /* Hash in the length of the RSA public key E value. */
                if (ret == 0) {
                    c32toa(sigKeyBlock_ptr->sk.rsa.eSz +
                        sigKeyBlock_ptr->sk.rsa.ePad, scratchLen);
                    ret = HashUpdate(hash, hashId, scratchLen, LENGTH_SZ);
                }
                /* Hash in the pad byte for the RSA public key E value. */
                if (ret == 0) {
                    if (sigKeyBlock_ptr->sk.rsa.ePad) {
                        scratchLen[0] = 0;
                        ret = HashUpdate(hash, hashId, scratchLen, 1);
                    }
                }
                /* Hash in the RSA public key E value. */
                if (ret == 0)
                    ret = HashUpdate(hash, hashId,
                            sigKeyBlock_ptr->sk.rsa.e,
                            sigKeyBlock_ptr->sk.rsa.eSz);
                /* Hash in the length of the RSA public key N value. */
                if (ret == 0) {
                    c32toa(sigKeyBlock_ptr->sk.rsa.nSz +
                            sigKeyBlock_ptr->sk.rsa.nPad, scratchLen);
                    ret = HashUpdate(hash, hashId, scratchLen, LENGTH_SZ);
                }
                /* Hash in the pad byte for the RSA public key N value. */
                if (ret == 0) {
                    if (sigKeyBlock_ptr->sk.rsa.nPad) {
                        scratchLen[0] = 0;
                        ret = HashUpdate(hash, hashId, scratchLen, 1);
                    }
                }
                /* Hash in the RSA public key N value. */
                if (ret == 0)
                    ret = HashUpdate(hash, hashId,
                            sigKeyBlock_ptr->sk.rsa.n,
                            sigKeyBlock_ptr->sk.rsa.nSz);
            }
            break;
        #endif /* WOLFSSH_NO_RSA */

        #ifndef WOLFSSH_NO_ECDSA
        #ifdef WOLFSSH_CERTS
        case ID_X509V3_ECDSA_SHA2_NISTP256:
        case ID_X509V3_ECDSA_SHA2_NISTP384:
        case ID_X509V3_ECDSA_SHA2_NISTP521:
            isCert = 1;
            NO_BREAK;
        #endif
        case ID_ECDSA_SHA2_NISTP256:
        case ID_ECDSA_SHA2_NISTP384:
        case ID_ECDSA_SHA2_NISTP521:
            sigKeyBlock_ptr->sk.ecc.primeName =
                    PrimeNameForId(ssh->handshake->pubKeyId);
            sigKeyBlock_ptr->sk.ecc.primeNameSz =
                    (word32)WSTRLEN(sigKeyBlock_ptr->sk.ecc.primeName);

            /* Decode the user-configured ECDSA private key. */
            sigKeyBlock_ptr->sk.ecc.qSz =
                    (word32)sizeof(sigKeyBlock_ptr->sk.ecc.q);
            ret = wc_ecc_init_ex(&sigKeyBlock_ptr->sk.ecc.key, heap,
                    INVALID_DEVID);
            scratch = 0;
            if (ret == 0)
                ret = wc_EccPrivateKeyDecode(ssh->ctx->privateKey[keyIdx].key,
                        &scratch, &sigKeyBlock_ptr->sk.ecc.key,
                        ssh->ctx->privateKey[keyIdx].keySz);

            /* hash in usual public key if not RFC6187 style cert use */
            if (!isCert) {
                /* Flatten the public key into x963 value for hash. */
                if (ret == 0) {
                    PRIVATE_KEY_UNLOCK();
                    ret = wc_ecc_export_x963(&sigKeyBlock_ptr->sk.ecc.key,
                                             sigKeyBlock_ptr->sk.ecc.q,
                                             &sigKeyBlock_ptr->sk.ecc.qSz);
                    PRIVATE_KEY_LOCK();
                }
                /* Hash in the length of the public key block. */
                if (ret == 0) {
                    sigKeyBlock_ptr->sz = (LENGTH_SZ * 3) +
                                     sigKeyBlock_ptr->pubKeyFmtNameSz +
                                     sigKeyBlock_ptr->sk.ecc.primeNameSz +
                                     sigKeyBlock_ptr->sk.ecc.qSz;
                    c32toa(sigKeyBlock_ptr->sz, scratchLen);
                    ret = HashUpdate(hash, hashId, scratchLen, LENGTH_SZ);
                }
                /* Hash in the length of the key type string. */
                if (ret == 0) {
                    c32toa(sigKeyBlock_ptr->pubKeyFmtNameSz, scratchLen);
                    ret = HashUpdate(hash, hashId, scratchLen, LENGTH_SZ);
                }
                /* Hash in the key type string. */
                if (ret == 0)
                    ret = HashUpdate(hash, hashId,
                            (byte*)sigKeyBlock_ptr->pubKeyFmtName,
                            sigKeyBlock_ptr->pubKeyFmtNameSz);
                /* Hash in the length of the name of the prime. */
                if (ret == 0) {
                    c32toa(sigKeyBlock_ptr->sk.ecc.primeNameSz, scratchLen);
                    ret = HashUpdate(hash, hashId, scratchLen, LENGTH_SZ);
                }
                /* Hash in the name of the prime. */
                if (ret == 0)
                    ret = HashUpdate(hash, hashId,
                            (const byte*)sigKeyBlock_ptr->sk.ecc.primeName,
                            sigKeyBlock_ptr->sk.ecc.primeNameSz);
                /* Hash in the length of the public key. */
                if (ret == 0) {
                    c32toa(sigKeyBlock_ptr->sk.ecc.qSz, scratchLen);
                    ret = HashUpdate(hash, hashId, scratchLen, LENGTH_SZ);
                }
                /* Hash in the public key. */
                if (ret == 0)
                    ret = HashUpdate(hash, hashId,
                            sigKeyBlock_ptr->sk.ecc.q,
                            sigKeyBlock_ptr->sk.ecc.qSz);
            }
            break;

        #ifndef WOLFSSH_NO_ED25519
        case ID_ED25519:
            WLOG(WS_LOG_DEBUG, "Using Ed25519 Host key");

            /* Decode the user-configured ED25519 private key. */
            sigKeyBlock_ptr->sk.ed.qSz = sizeof(sigKeyBlock_ptr->sk.ed.q);

            ret = wc_ed25519_init(&sigKeyBlock_ptr->sk.ed.key);

            scratch = 0;
            if (ret == 0)
                ret = wc_Ed25519PrivateKeyDecode(ssh->ctx->privateKey[keyIdx].key, &scratch, &sigKeyBlock_ptr->sk.ed.key, ssh->ctx->privateKey[keyIdx].keySz);

            if (ret == 0)
                ret = wc_ed25519_export_public(&sigKeyBlock_ptr->sk.ed.key,
                                                sigKeyBlock_ptr->sk.ed.q,
                                                &sigKeyBlock_ptr->sk.ed.qSz );

            /* Hash in the length of the public key block. */
            if (ret == 0) {
                sigKeyBlock_ptr->sz = (LENGTH_SZ * 2) +
                                 sigKeyBlock_ptr->pubKeyFmtNameSz +
                                 sigKeyBlock_ptr->sk.ed.qSz;
                c32toa(sigKeyBlock_ptr->sz, scratchLen);
                ret = wc_HashUpdate(hash, hashId,
                                    scratchLen, LENGTH_SZ);
            }
            /* Hash in the length of the key type string. */
            if (ret == 0) {
                c32toa(sigKeyBlock_ptr->pubKeyFmtNameSz, scratchLen);
                ret = wc_HashUpdate(hash, hashId,
                                    scratchLen, LENGTH_SZ);
            }
            /* Hash in the key type string. */
            if (ret == 0)
                ret = wc_HashUpdate(hash, hashId,
                                    (byte*)sigKeyBlock_ptr->pubKeyFmtName,
                                    sigKeyBlock_ptr->pubKeyFmtNameSz);
            /* Hash in the length of the public key. */
            if (ret == 0) {
                c32toa(sigKeyBlock_ptr->sk.ed.qSz, scratchLen);
                ret = wc_HashUpdate(hash, hashId,
                                    scratchLen, LENGTH_SZ);
            }
            /* Hash in the public key. */
            if (ret == 0)
                ret = wc_HashUpdate(hash, hashId,
                                    sigKeyBlock_ptr->sk.ed.q,
                                    sigKeyBlock_ptr->sk.ed.qSz);
            break;
        #endif
        #endif

            default:
                ret = WS_INVALID_ALGO_ID;
        }


        /* if is RFC6187 then the hash of the public key is changed */
        if (ret == 0 && isCert) {
        #ifdef WOLFSSH_CERTS
            byte* tmp;
            word32 idx = 0;

            BuildRFC6187Info(ssh, sigKeyBlock_ptr->pubKeyId,
                ssh->ctx->privateKey[keyIdx].cert,
                ssh->ctx->privateKey[keyIdx].certSz,
                NULL, 0, NULL, &sigKeyBlock_ptr->sz, &idx);
            tmp = (byte*)WMALLOC(sigKeyBlock_ptr->sz, heap, DYNTYPE_TEMP);
            if (tmp == NULL) {
                ret = WS_MEMORY_E;
            }
            else {
                idx = 0;
                BuildRFC6187Info(ssh, sigKeyBlock_ptr->pubKeyId,
                    ssh->ctx->privateKey[keyIdx].cert,
                    ssh->ctx->privateKey[keyIdx].certSz,
                    NULL, 0, tmp, &sigKeyBlock_ptr->sz, &idx);
                ret = HashUpdate(hash, hashId, tmp, sigKeyBlock_ptr->sz);
                WFREE(tmp, heap, DYNTYPE_TEMP);
            }
        #else
            ret = WS_NOT_COMPILED;
        #endif
        }


#ifndef WOLFSSH_NO_DH_GEX_SHA256
        /* If using DH-GEX include the GEX specific values. */
        if (ssh->handshake->kexId == ID_DH_GEX_SHA256) {
            byte primeGroupPad = 0, generatorPad = 0;

            if (GetDHPrimeGroup(ssh->handshake->kexId, &primeGroup,
                &primeGroupSz, &generator, &generatorSz) != WS_SUCCESS) {
                ret = WS_BAD_ARGUMENT;
            }

            /* Hash in the client's requested minimum key size. */
            if (ret == 0) {
                c32toa(ssh->handshake->dhGexMinSz, scratchLen);
                ret = HashUpdate(hash, hashId, scratchLen, LENGTH_SZ);
            }
            /* Hash in the client's requested preferred key size. */
            if (ret == 0) {
                c32toa(ssh->handshake->dhGexPreferredSz, scratchLen);
                ret = HashUpdate(hash, hashId, scratchLen, LENGTH_SZ);
            }
            /* Hash in the client's requested maximum key size. */
            if (ret == 0) {
                c32toa(ssh->handshake->dhGexMaxSz, scratchLen);
                ret = HashUpdate(hash, hashId, scratchLen, LENGTH_SZ);
            }
            /* Add a pad byte if the mpint has the MSB set. */
            if (ret == 0) {
                ret = CreateMpint((byte*)primeGroup,
                        &primeGroupSz, &primeGroupPad);
            }
            if (ret == 0) {
                /* Hash in the length of the GEX prime group. */
                c32toa(primeGroupSz + primeGroupPad, scratchLen);
                ret = HashUpdate(hash, hashId, scratchLen, LENGTH_SZ);
            }
            /* Hash in the pad byte for the GEX prime group. */
            if (ret == 0) {
                if (primeGroupPad) {
                    scratchLen[0] = 0;
                    ret = HashUpdate(hash, hashId, scratchLen, 1);
                }
            }
            /* Hash in the GEX prime group. */
            if (ret == 0)
                ret  = HashUpdate(hash, hashId, primeGroup, primeGroupSz);
            /* Add a pad byte if the mpint has the MSB set. */
            if (ret == 0) {
                ret = CreateMpint((byte*)generator,
                        &generatorSz, &generatorPad);
            }
            if (ret == 0) {
                /* Hash in the length of the GEX generator. */
                c32toa(generatorSz + generatorPad, scratchLen);
                ret = HashUpdate(hash, hashId, scratchLen, LENGTH_SZ);
            }
            /* Hash in the pad byte for the GEX generator. */
            if (ret == 0) {
                if (generatorPad) {
                    scratchLen[0] = 0;
                    ret = HashUpdate(hash, hashId, scratchLen, 1);
                }
            }
            /* Hash in the GEX generator. */
            if (ret == 0)
                ret = HashUpdate(hash, hashId, generator, generatorSz);
        }
#endif

        /* Hash in the size of the client's DH e-value (ECDH Q-value). */
        if (ret == 0) {
            c32toa(ssh->handshake->eSz, scratchLen);
            ret = HashUpdate(hash, hashId, scratchLen, LENGTH_SZ);
        }
        /* Hash in the client's DH e-value (ECDH Q-value). */
        if (ret == 0)
            ret = HashUpdate(hash, hashId,
                    ssh->handshake->e, ssh->handshake->eSz);

    return (ret == 0) ? WS_SUCCESS : ret;
}


/* We have pairs of PubKey types that use the same signature,
 * i.e. ecdsa-sha2-nistp256 and x509v3-ecdsa-sha2-nistp256. */
static INLINE byte SigTypeForId(byte id)
{
    WOLFSSH_UNUSED(id);
#ifdef WOLFSSH_CERTS
    switch (id) {
    #ifndef WOLFSSH_NO_SSH_RSA_SHA1
        case ID_X509V3_SSH_RSA:
            id = ID_SSH_RSA;
            break;
    #endif
    #ifndef WOLFSSH_NO_ECDSA_SHA2_NISTP256
        case ID_X509V3_ECDSA_SHA2_NISTP256:
            id = ID_ECDSA_SHA2_NISTP256;
            break;
    #endif
    #ifndef WOLFSSH_NO_ECDSA_SHA2_NISTP384
        case ID_X509V3_ECDSA_SHA2_NISTP384:
            id = ID_ECDSA_SHA2_NISTP384;
            break;
    #endif
    #ifndef WOLFSSH_NO_ECDSA_SHA2_NISTP521
        case ID_X509V3_ECDSA_SHA2_NISTP521:
            id = ID_ECDSA_SHA2_NISTP521;
            break;
    #endif
    }
#endif

    return id;
}


#ifndef WOLFSSH_NO_RSA
/*
 * wolfSSH_RsaVerify
 * sig - signature to verify
 * sigSz - signature size
 * encDigest - encoded digest for verification
 * encDigestSz - encoded digest size
 * key - key used to sign and verify signature
 * heap - allocation heap
 * loc - calling function for logging
 *
 * Takes the provided digest of type digestId and converts it to an
 * encoded digest. Then verifies the signature, comparing the output
 * digest and compares it.
 */
int wolfSSH_RsaVerify(const byte *sig, word32 sigSz,
        const byte* encDigest, word32 encDigestSz,
        RsaKey* key, void* heap, const char* loc)
{
    byte* checkSig = NULL;
    int checkDigestSz;
    word32 keySz;
    int ret = WS_SUCCESS;
#ifdef WOLFSSH_SMALL_STACK
    byte* checkDigest = NULL;
#else
    byte checkDigest[MAX_ENCODED_SIG_SZ];
#endif

    keySz = (word32)wc_RsaEncryptSize(key);

    if (ret == WS_SUCCESS) {
        checkSig = (byte*)WMALLOC(keySz, heap, DYNTYPE_TEMP);
        if (checkSig == NULL)
            ret = WS_MEMORY_E;
    }
#ifdef WOLFSSH_SMALL_STACK
    if (ret == WS_SUCCESS) {
        checkDigest = (byte*)WMALLOC(MAX_ENCODED_SIG_SZ, heap, DYNTYPE_TEMP);
        if (checkDigest == NULL)
            ret = WS_MEMORY_E;
    }
#endif

    /* Normalize the peer's signature. Some SSH implementations remove
     * leading zeros on the signatures they encode. We need to pad the
     * front of the signature to the key size. */
    if (ret == WS_SUCCESS) {
        word32 offset;

        if (keySz > sigSz) {
            offset = keySz - sigSz;
        }
        else {
            sigSz = keySz;
            offset = 0;
        }

        WMEMSET(checkSig, 0, offset);
        WMEMCPY(checkSig + offset, sig, sigSz);
    }

    if (ret == WS_SUCCESS) {
        volatile int sizeCompare;
        volatile int compare;

        checkDigestSz = wc_RsaSSL_Verify(checkSig, keySz,
                checkDigest, MAX_ENCODED_SIG_SZ, key);

        sizeCompare = checkDigestSz > 0 && encDigestSz != (word32)checkDigestSz;
        compare = ConstantCompare(encDigest, checkDigest, encDigestSz);

        if (checkDigestSz < 0 || sizeCompare || compare) {
            WLOG(WS_LOG_DEBUG, "%s: %s", loc, "Bad RSA Verify");
            ret = WS_RSA_E;
        }
    }

#ifdef WOLFSSH_SMALL_STACK
    if (checkDigest)
        WFREE(checkDigest, heap, DYNTYPE_TEMP);
#endif
    if (checkSig)
        WFREE(checkSig, heap, DYNTYPE_TEMP);
    return ret;
}
#endif /* WOLFSSH_NO_RSA */


/* KeyAgreeDh_server
 * hashId - wolfCrypt hash type ID used
 * f - peer public key
 * fSz - peer public key size
 */
static int KeyAgreeDh_server(WOLFSSH* ssh, byte hashId, byte* f, word32* fSz)
#ifndef WOLFSSH_NO_DH
{
    int ret = WS_SUCCESS;
    byte *y_ptr = NULL;
    const byte* primeGroup = NULL;
    const byte* generator = NULL;
    word32 ySz = MAX_KEX_KEY_SZ;
    word32 primeGroupSz = 0;
    word32 generatorSz = 0;
    #ifdef WOLFSSH_SMALL_STACK
    DhKey *privKey = (DhKey*)WMALLOC(sizeof(DhKey), ssh->ctx->heap,
            DYNTYPE_PRIVKEY);
    y_ptr = (byte*)WMALLOC(ySz, ssh->ctx->heap, DYNTYPE_PRIVKEY);
    if (privKey == NULL || y_ptr == NULL)
        ret = WS_MEMORY_E;
    #else
    DhKey privKey[1];
    byte y_s[MAX_KEX_KEY_SZ];
    y_ptr = y_s;
    #endif

    WLOG(WS_LOG_DEBUG, "Entering KeyAgreeDh_server()");
    WOLFSSH_UNUSED(hashId);

    if (ret == WS_SUCCESS) {
        ret = GetDHPrimeGroup(ssh->handshake->kexId, &primeGroup,
            &primeGroupSz, &generator, &generatorSz);

        if (ret == WS_SUCCESS) {
            ssh->primeGroupSz = primeGroupSz;
            ret = wc_InitDhKey(privKey);
        }
        if (ret == 0)
            ret = wc_DhSetKey(privKey, primeGroup, primeGroupSz,
                    generator, generatorSz);
        if (ret == 0)
            ret = wc_DhGenerateKeyPair(privKey, ssh->rng,
                    y_ptr, &ySz, f, fSz);
        if (ret == 0) {
            PRIVATE_KEY_UNLOCK();
            ret = wc_DhAgree(privKey, ssh->k, &ssh->kSz, y_ptr, ySz,
                    ssh->handshake->e, ssh->handshake->eSz);
            PRIVATE_KEY_LOCK();
        }
        ForceZero(y_ptr, ySz);
        wc_FreeDhKey(privKey);
    }
    #ifdef WOLFSSH_SMALL_STACK
    if (y_ptr)
        WFREE(y_ptr, ssh->ctx->heap, DYNTYPE_PRIVKEY);
    if (privKey) {
        WFREE(privKey, ssh->ctx->heap, DYNTYPE_PRIVKEY);
    }
    #endif
    WLOG(WS_LOG_DEBUG, "Leaving KeyAgreeDh_server(), ret = %d", ret);
    return ret;
}
#else /* WOLFSSH_NO_DH */
{
    WOLFSSH_UNUSED(ssh);
    WOLFSSH_UNUSED(hashId);
    WOLFSSH_UNUSED(f);
    WOLFSSH_UNUSED(fSz);
    return WS_INVALID_ALGO_ID;
}
#endif /* WOLFSSH_NO_DH */


/* KeyAgreeEcdh_server
 * hashId - wolfCrypt hash type ID used
 * f - peer public key
 * fSz - peer public key size
 */
static int KeyAgreeEcdh_server(WOLFSSH* ssh, byte hashId, byte* f, word32* fSz)
#ifndef WOLFSSH_NO_ECDH
{
    int ret = WS_SUCCESS;
    void* heap;
#ifdef WOLFSSH_SMALL_STACK
    ecc_key *pubKey = NULL, *privKey = NULL;
    pubKey = (ecc_key*)WMALLOC(sizeof(ecc_key), heap,
            DYNTYPE_PUBKEY);
    privKey = (ecc_key*)WMALLOC(sizeof(ecc_key), heap,
            DYNTYPE_PRIVKEY);
    if (pubKey == NULL || privKey == NULL) {
        ret = WS_MEMORY_E;
    }
#else
    ecc_key pubKey[1];
    ecc_key privKey[1];
#endif
    int primeId;

    WLOG(WS_LOG_DEBUG, "Entering KeyAgreeEcdh_server()");
    WOLFSSH_UNUSED(hashId);

    heap = ssh->ctx->heap;
    primeId  = wcPrimeForId(ssh->handshake->kexId);
    if (primeId == ECC_CURVE_INVALID)
        ret = WS_INVALID_PRIME_CURVE;

    if (ret == 0)
        ret = wc_ecc_init_ex(pubKey, heap, INVALID_DEVID);
    if (ret == 0)
        ret = wc_ecc_init_ex(privKey, heap, INVALID_DEVID);
#ifdef HAVE_WC_ECC_SET_RNG
    if (ret == 0)
        ret = wc_ecc_set_rng(privKey, ssh->rng);
#endif

    if (ret == 0)
        ret = wc_ecc_import_x963_ex(ssh->handshake->e,
                                    ssh->handshake->eSz,
                                    pubKey, primeId);

    if (ret == 0)
        ret = wc_ecc_make_key_ex(ssh->rng,
                             wc_ecc_get_curve_size_from_id(primeId),
                             privKey, primeId);
    if (ret == 0) {
        PRIVATE_KEY_UNLOCK();
        ret = wc_ecc_export_x963(privKey, f, fSz);
        PRIVATE_KEY_LOCK();
    }
    if (ret == 0) {
        PRIVATE_KEY_UNLOCK();
        ret = wc_ecc_shared_secret(privKey, pubKey,
                                   ssh->k, &ssh->kSz);
        PRIVATE_KEY_LOCK();
    }
    wc_ecc_free(privKey);
    wc_ecc_free(pubKey);
#ifdef WOLFSSH_SMALL_STACK
    WFREE(pubKey, heap, DYNTYPE_PUBKEY);
    WFREE(privKey, heap, DYNTYPE_PRIVKEY);
    pubKey  = NULL;
    privKey = NULL;
#endif
    WLOG(WS_LOG_DEBUG, "Leaving KeyAgreeEcdh_server(), ret = %d", ret);
    return ret;
}
#else /* WOLFSSH_NO_ECDH */
{
    WOLFSSH_UNUSED(ssh);
    WOLFSSH_UNUSED(hashId);
    WOLFSSH_UNUSED(f);
    WOLFSSH_UNUSED(fSz);
    return WS_INVALID_ALGO_ID;
}
#endif /* WOLFSSH_NO_ECDH */


/* KeyAgreeCurve25519_server
 * hashId - wolfCrypt hash type ID used
 * f - peer public key
 * fSz - peer public key size
 */
static int KeyAgreeCurve25519_server(WOLFSSH* ssh, byte hashId,
        byte* f, word32* fSz)
#ifndef WOLFSSH_NO_CURVE25519_SHA256
{
    int ret = WS_SUCCESS;
    void* heap = ssh->ctx->heap;
#ifdef WOLFSSH_SMALL_STACK
    curve25519_key *pubKey = NULL, *privKey = NULL;
    pubKey = (curve25519_key*)WMALLOC(sizeof(curve25519_key),
            heap, DYNTYPE_PUBKEY);
    privKey = (curve25519_key*)WMALLOC(sizeof(curve25519_key),
            heap, DYNTYPE_PRIVKEY);
    if (pubKey == NULL || privKey == NULL) {
        ret = WS_MEMORY_E;
    }
#else
    curve25519_key pubKey[1], privKey[1];
#endif

    WLOG(WS_LOG_DEBUG, "Entering KeyAgreeCurve25519_server()");
    WOLFSSH_UNUSED(hashId);

    if (ret == 0)
        ret = wc_curve25519_init_ex(pubKey, heap, INVALID_DEVID);
    if (ret == 0)
        ret = wc_curve25519_init_ex(privKey, heap, INVALID_DEVID);
    if (ret == 0)
        ret = wc_curve25519_check_public(ssh->handshake->e,
                ssh->handshake->eSz, EC25519_LITTLE_ENDIAN);
    if (ret == 0)
        ret = wc_curve25519_import_public_ex(
                ssh->handshake->e, ssh->handshake->eSz,
                pubKey, EC25519_LITTLE_ENDIAN);

    if (ret == 0)
        ret = wc_curve25519_make_key(ssh->rng, CURVE25519_KEYSIZE, privKey);

    if (ret == 0) {
        PRIVATE_KEY_UNLOCK();
        ret = wc_curve25519_export_public_ex(privKey,
                f, fSz, EC25519_LITTLE_ENDIAN);
        PRIVATE_KEY_LOCK();
    }

    if (ret == 0) {
        PRIVATE_KEY_UNLOCK();
        ret = wc_curve25519_shared_secret_ex(privKey, pubKey,
                  ssh->k, &ssh->kSz, EC25519_LITTLE_ENDIAN);
        PRIVATE_KEY_LOCK();
    }
    wc_curve25519_free(privKey);
    wc_curve25519_free(pubKey);
#ifdef WOLFSSH_SMALL_STACK
    WFREE(pubKey, heap, DYNTYPE_PUBKEY);
    WFREE(privKey, heap, DYNTYPE_PRIVKEY);
    pubKey  = NULL;
    privKey = NULL;
#endif
    WLOG(WS_LOG_DEBUG, "Leaving KeyAgreeCurve25519_server(), ret = %d", ret);
    return ret;
}
#else /* WOLFSSH_NO_CURVE25519_SHA256 */
{
    WOLFSSH_UNUSED(ssh);
    WOLFSSH_UNUSED(hashId);
    WOLFSSH_UNUSED(f);
    WOLFSSH_UNUSED(fSz);
    return WS_INVALID_ALGO_ID;
}
#endif /* WOLFSSH_NO_CURVE25519_SHA256 */


/* KeyAgreeEcdhKyber512_server
 * hashId - wolfCrypt hash type ID used
 * f - peer public key
 * fSz - peer public key size
 *
 * This is a hybrid KEM. In this case, I need to generate my ECC
 * keypair, send the public one, use the private one to generate
 * the shared secret, use the post-quantum public key to
 * generate and encapsulate the shared secret and send the
 * ciphertext.
 */
static int KeyAgreeEcdhKyber512_server(WOLFSSH* ssh, byte hashId,
        byte* f, word32* fSz)
#ifndef WOLFSSH_NO_ECDH_NISTP256_KYBER_LEVEL1_SHA256
{
    int ret = WS_SUCCESS;
    byte sharedSecretHashSz = 0;
    byte *sharedSecretHash = NULL;
    KyberKey kem = {0};
    word32 length_publickey = 0;
    word32 length_ciphertext = 0;
    word32 length_sharedsecret = 0;
    ecc_key* pubKey = NULL;
    ecc_key* privKey = NULL;
    int primeId;
#ifndef WOLFSSH_SMALL_STACK
    ecc_key eccKeys[2];
#endif

    WLOG(WS_LOG_DEBUG, "Entering KeyAgreeEcdhKyber512_server()");

#ifdef WOLFSSH_SMALL_STACK
    pubKey = (ecc_key*)WMALLOC(sizeof(ecc_key),
            ssh->ctx->heap, DYNTYPE_PUBKEY);
    privKey = (ecc_key*)WMALLOC(sizeof(ecc_key),
            ssh->ctx->heap, DYNTYPE_PRIVKEY);
    if (pubKey == NULL || privKey == NULL) {
        ret = WS_MEMORY_E;
    }
#else
    pubKey = &eccKeys[0];
    privKey = &eccKeys[1];
#endif

    if (ret == 0) {
        XMEMSET(pubKey, 0, sizeof(*pubKey));
        XMEMSET(privKey, 0, sizeof(*privKey));

        primeId = wcPrimeForId(ssh->handshake->kexId);
        if (primeId == ECC_CURVE_INVALID)
            ret = WS_INVALID_PRIME_CURVE;
    }

    if (ret == 0) {
        ret = wc_KyberKey_Init(KYBER512, &kem, ssh->ctx->heap,
                               INVALID_DEVID);
    }

    if (ret == 0) {
        ret = wc_KyberKey_CipherTextSize(&kem, &length_ciphertext);
    }

    if (ret == 0) {
        ret = wc_KyberKey_SharedSecretSize(&kem, &length_sharedsecret);
    }

    if (ret == 0) {
        ret = wc_KyberKey_PublicKeySize(&kem, &length_publickey);
    }

    if ((ret == 0) && (ssh->handshake->eSz <= length_publickey)) {
        ret = WS_BUFFER_E;
    }

    if (ret == 0) {
        ret = wc_KyberKey_DecodePublicKey(&kem, ssh->handshake->e,
                                          length_publickey);
    }

    if (ret == 0) {
        ret = wc_KyberKey_Encapsulate(&kem, f, ssh->k, ssh->rng);
    }

    if (ret == 0) {
        *fSz -= length_ciphertext;
        ssh->kSz -= length_sharedsecret;
    }
    else {
        ret = WS_PUBKEY_REJECTED_E;
        WLOG(WS_LOG_ERROR,
             "Generate ECC-kyber (encap) shared secret failed, %d", ret);
        *fSz = 0;
        ssh->kSz = 0;
    }

    wc_KyberKey_Free(&kem);

    if (ret == 0) {
        ret = wc_ecc_init_ex(pubKey, ssh->ctx->heap, INVALID_DEVID);
    }
    if (ret == 0) {
        ret = wc_ecc_init_ex(privKey, ssh->ctx->heap, INVALID_DEVID);
    }
#ifdef HAVE_WC_ECC_SET_RNG
    if (ret == 0) {
        ret = wc_ecc_set_rng(privKey, ssh->rng);
    }
#endif
    if (ret == 0) {
        ret = wc_ecc_import_x963_ex(
            ssh->handshake->e + length_publickey,
            ssh->handshake->eSz - length_publickey,
            pubKey, primeId);
    }
    if (ret == 0) {
        ret = wc_ecc_make_key_ex(ssh->rng,
                  wc_ecc_get_curve_size_from_id(primeId),
                  privKey, primeId);
    }
    if (ret == 0) {
        PRIVATE_KEY_UNLOCK();
        ret = wc_ecc_export_x963(privKey, f + length_ciphertext, fSz);
        PRIVATE_KEY_LOCK();
        *fSz += length_ciphertext;
    }
    if (ret == 0) {
        word32 tmp_kSz = ssh->kSz;
        PRIVATE_KEY_UNLOCK();
        ret = wc_ecc_shared_secret(privKey, pubKey,
                  ssh->k + length_sharedsecret, &tmp_kSz);
        PRIVATE_KEY_LOCK();
        ssh->kSz = length_sharedsecret + tmp_kSz;
    }
    wc_ecc_free(privKey);
    wc_ecc_free(pubKey);
#ifdef WOLFSSH_SMALL_STACK
    if (pubKey)
        WFREE(pubKey, ssh->ctx->heap, DYNTYPE_PUBKEY);
    if (privKey)
        WFREE(privKey, ssh->ctx->heap, DYNTYPE_PUBKEY);
#endif

    /* Replace the concatenated shared secrets with the hash. That
     * will become the new shared secret.*/
    if (ret == 0) {
        sharedSecretHashSz = wc_HashGetDigestSize(hashId);
        sharedSecretHash = (byte *)WMALLOC(sharedSecretHashSz,
                ssh->ctx->heap, DYNTYPE_PRIVKEY);
        if (sharedSecretHash == NULL) {
            ret = WS_MEMORY_E;
        }
    }
    if (ret == 0) {
        ret = wc_Hash(hashId, ssh->k, ssh->kSz, sharedSecretHash,
                      sharedSecretHashSz);
    }
    if (ret == 0) {
        XMEMCPY(ssh->k, sharedSecretHash, sharedSecretHashSz);
        ssh->kSz = sharedSecretHashSz;
    }

    if (sharedSecretHash) {
        ForceZero(sharedSecretHash, sharedSecretHashSz);
        WFREE(sharedSecretHash, ssh->ctx->heap, DYNTYPE_PRIVKEY);
    }

    WLOG(WS_LOG_DEBUG, "Leaving KeyAgreeEcdhKyber512_server(), ret = %d", ret);
    return ret;
}
#else /* WOLFSSH_NO_ECDH_NISTP256_KYBER_LEVEL1_SHA256 */
{
    WOLFSSH_UNUSED(ssh);
    WOLFSSH_UNUSED(hashId);
    WOLFSSH_UNUSED(f);
    WOLFSSH_UNUSED(fSz);
    return WS_INVALID_ALGO_ID;
}
#endif /* WOLFSSH_NO_ECDH_NISTP256_KYBER_LEVEL1_SHA256 */


static int SignHRsa(WOLFSSH* ssh, byte* sig, word32* sigSz,
        struct wolfSSH_sigKeyBlockFull *sigKey)
#ifndef WOLFSSH_NO_RSA
{
    void* heap;
    byte* encSig = NULL;
    byte digest[WC_MAX_DIGEST_SIZE];
    word32 digestSz = (word32)sizeof(digest);
    word32 encSigSz;
    int ret = WS_SUCCESS;
    enum wc_HashType hashId;
#ifndef WOLFSSH_SMALL_STACK
    byte encSig_s[MAX_ENCODED_SIG_SZ];
#endif

    WLOG(WS_LOG_DEBUG, "Entering SignHRsa()");

    heap = ssh->ctx->heap;
#ifdef WOLFSSH_SMALL_STACK
    encSig = (byte*)WMALLOC(MAX_ENCODED_SIG_SZ, heap, DYNTYPE_TEMP);
    if (encSig == NULL) {
        ret = WS_MEMORY_E;
    }
#else
    encSig = encSig_s;
#endif

    if (ret == WS_SUCCESS) {
        hashId = HashForId(ssh->handshake->pubKeyId);
        digestSz = wc_HashGetDigestSize(hashId);

        ret = wc_Hash(hashId, ssh->h, ssh->hSz, digest, digestSz);
        if (ret != 0) {
            ret = WS_CRYPTO_FAILED;
        }
    }

    if (ret == WS_SUCCESS) {
        ret = wc_EncodeSignature(encSig, digest, digestSz,
                wc_HashGetOID(hashId));
        if (ret <= 0) {
            WLOG(WS_LOG_DEBUG, "SignHRsa: Bad Encode Sig");
            ret = WS_CRYPTO_FAILED;
        }
        else {
            encSigSz = (word32)ret;
            ret = WS_SUCCESS;
        }
    }

    if (ret == WS_SUCCESS) {
        WLOG(WS_LOG_INFO, "Signing hash with %s.",
            IdToName(ssh->handshake->pubKeyId));
        ret = wc_RsaSSL_Sign(encSig, encSigSz, sig,
                KEX_SIG_SIZE, &sigKey->sk.rsa.key,
                ssh->rng);
        if (ret <= 0) {
            WLOG(WS_LOG_DEBUG, "SignHRsa: Bad RSA Sign");
            ret = WS_RSA_E;
        }
        else {
            *sigSz = (word32)ret;
            ret = WS_SUCCESS;
        }
    }

    if (ret == WS_SUCCESS) {
        ret = wolfSSH_RsaVerify(sig, *sigSz, encSig, encSigSz,
                &sigKey->sk.rsa.key, heap, "SignHRsa");
    }

    #ifdef WOLFSSH_SMALL_STACK
    if (encSig != NULL)
        WFREE(encSig, heap, DYNTYPE_TEMP);
    #endif
    WLOG(WS_LOG_DEBUG, "Leaving SignHRsa(), ret = %d", ret);
    return ret;
}
#else /* WOLFSSH_NO_RSA */
{
    WOLFSSH_UNUSED(ssh);
    WOLFSSH_UNUSED(sig);
    WOLFSSH_UNUSED(sigSz);
    WOLFSSH_UNUSED(sigKey);
    return WS_INVALID_ALGO_ID;
}
#endif /* WOLFSSH_NO_RSA */


static int SignHEcdsa(WOLFSSH* ssh, byte* sig, word32* sigSz,
        struct wolfSSH_sigKeyBlockFull *sigKey)
#ifndef WOLFSSH_NO_ECDSA
{
#ifdef WOLFSSH_SMALL_STACK
    void* heap = NULL;
#endif
    byte *r = NULL, *s = NULL;
    byte digest[WC_MAX_DIGEST_SIZE];
    word32 digestSz = (word32)sizeof(digest);
    int ret = WS_SUCCESS;
    enum wc_HashType hashId;
    word32 rSz = MAX_ECC_BYTES + ECC_MAX_PAD_SZ,
           sSz = MAX_ECC_BYTES + ECC_MAX_PAD_SZ;
    byte rPad, sPad;
#ifndef WOLFSSH_SMALL_STACK
    byte r_s[MAX_ECC_BYTES + ECC_MAX_PAD_SZ];
    byte s_s[MAX_ECC_BYTES + ECC_MAX_PAD_SZ];
#endif

    WLOG(WS_LOG_DEBUG, "Entering SignHEcdsa()");

    hashId = HashForId(ssh->handshake->pubKeyId);
    digestSz = wc_HashGetDigestSize(hashId);

    ret = wc_Hash(hashId, ssh->h, ssh->hSz, digest, digestSz);
    if (ret != 0) {
        ret = WS_CRYPTO_FAILED;
    }

    if (ret == WS_SUCCESS) {
        WLOG(WS_LOG_INFO, "Signing hash with %s.",
                IdToName(ssh->handshake->pubKeyId));
        ret = wc_ecc_sign_hash(digest, digestSz, sig, sigSz, ssh->rng,
                &sigKey->sk.ecc.key);
        if (ret != MP_OKAY) {
            WLOG(WS_LOG_DEBUG, "SignHEcdsa: Bad ECDSA Sign");
            ret = WS_ECC_E;
        }
        else {
            ret = WS_SUCCESS;
        }
    }

    if (ret == WS_SUCCESS) {
#ifdef WOLFSSH_SMALL_STACK
        heap = ssh->ctx->heap;
        r = (byte*)WMALLOC(rSz, heap, DYNTYPE_BUFFER);
        s = (byte*)WMALLOC(sSz, heap, DYNTYPE_BUFFER);
        if (r == NULL || s == NULL) {
            ret = WS_MEMORY_E;
        }
#else
        r = r_s;
        s = s_s;
#endif
    }

    if (ret == WS_SUCCESS) {
        ret = wc_ecc_sig_to_rs(sig, *sigSz, r, &rSz, s, &sSz);
        if (ret != 0) {
            ret = WS_ECC_E;
        }
    }

    if (ret == WS_SUCCESS) {
        int idx = 0;
        rPad = (r[0] & 0x80) ? 1 : 0;
        sPad = (s[0] & 0x80) ? 1 : 0;
        *sigSz = (LENGTH_SZ * 2) + rSz + rPad + sSz + sPad;

        c32toa(rSz + rPad, sig + idx);
        idx += LENGTH_SZ;
        if (rPad)
            sig[idx++] = 0;
        WMEMCPY(sig + idx, r, rSz);
        idx += rSz;
        c32toa(sSz + sPad, sig + idx);
        idx += LENGTH_SZ;
        if (sPad)
            sig[idx++] = 0;
        WMEMCPY(sig + idx, s, sSz);
    }

    #ifdef WOLFSSH_SMALL_STACK
        if (r)
            WFREE(r, heap, DYNTYPE_BUFFER);
        if (s)
            WFREE(s, heap, DYNTYPE_BUFFER);
    #endif

    WLOG(WS_LOG_DEBUG, "Leaving SignHEcdsa(), ret = %d", ret);
    return ret;
}
#else /* WOLFSSH_NO_ECDSA */
{
    WOLFSSH_UNUSED(ssh);
    WOLFSSH_UNUSED(sig);
    WOLFSSH_UNUSED(sigSz);
    WOLFSSH_UNUSED(sigKey);
    return WS_INVALID_ALGO_ID;
}
#endif /* WOLFSSH_NO_ECDSA */


static int SignHEd25519(WOLFSSH* ssh, byte* sig, word32* sigSz,
        struct wolfSSH_sigKeyBlockFull *sigKey)
#ifndef WOLFSSH_NO_ED25519
{
    int ret;

    WLOG(WS_LOG_DEBUG, "Entering SignHEd25519()");

    ret = wc_ed25519_sign_msg(ssh->h, ssh->hSz, sig, sigSz, &sigKey->sk.ed.key);
    if (ret != 0) {
        WLOG(WS_LOG_DEBUG,
                "SignHEd5519: Bad ED25519 Sign (error: %d)", ret);
        ret = WS_ECC_E;
    }

    WLOG(WS_LOG_DEBUG, "Leaving SignHEd25519(), ret = %d", ret);
    return ret;
}
#else /* WOLFSSH_NO_ED25519 */
{
    WOLFSSH_UNUSED(ssh);
    WOLFSSH_UNUSED(sig);
    WOLFSSH_UNUSED(sigSz);
    WOLFSSH_UNUSED(sigKey);
    return WS_INVALID_ALGO_ID;
}
#endif /* WOLFSSH_NO_ED25519 */


static int SignH(WOLFSSH* ssh, byte* sig, word32* sigSz,
        struct wolfSSH_sigKeyBlockFull *sigKey)
{
    int ret;

    switch (sigKey->pubKeyId) {
        case ID_SSH_RSA:
        case ID_X509V3_SSH_RSA:
        case ID_RSA_SHA2_256:
        case ID_RSA_SHA2_512:
            ret = SignHRsa(ssh, sig, sigSz, sigKey);
            break;
        case ID_ECDSA_SHA2_NISTP256:
        case ID_ECDSA_SHA2_NISTP384:
        case ID_ECDSA_SHA2_NISTP521:
        case ID_X509V3_ECDSA_SHA2_NISTP256:
        case ID_X509V3_ECDSA_SHA2_NISTP384:
        case ID_X509V3_ECDSA_SHA2_NISTP521:
            ret = SignHEcdsa(ssh, sig, sigSz, sigKey);
            break;
        case ID_ED25519:
            ret = SignHEd25519(ssh, sig, sigSz, sigKey);
            break;
        default:
            ret = WS_INVALID_ALGO_ID;
    }

    return ret;
}


/* SendKexDhReply()
 * It is also the funciton used for MSGID_KEXECDH_REPLY. The parameters
 * are analogous between the two messages. Where MSGID_KEXDH_REPLY has
 * server's public host key (K_S), f, and the signature of H;
 * MSGID_KEXECDH_REPLY has K_S, the server'e ephemeral public key (Q_S),
 * and the signature of H. This also applies to the GEX version of this.
 * H is calculated the same for KEXDH and KEXECDH, and has some exceptions
 * for GEXDH. */
int SendKexDhReply(WOLFSSH* ssh)
{
    int ret = WS_SUCCESS;
    void *heap  = NULL;
    byte *f_ptr = NULL, *sig_ptr = NULL;
    byte scratchLen[LENGTH_SZ];
    word32 fSz = KEX_F_SIZE;
    word32 sigSz = KEX_SIG_SIZE;
    byte fPad = 0;
    byte kPad = 0;
    word32 sigBlockSz = 0;
    word32 payloadSz = 0;
    byte* output = NULL;
    word32 idx = 0;
    word32 keyIdx = 0;
    enum wc_HashType hashId = WC_HASH_TYPE_NONE;
    wc_HashAlg* hash = NULL;
    struct wolfSSH_sigKeyBlockFull *sigKeyBlock_ptr = NULL;
#ifndef WOLFSSH_SMALL_STACK
    byte f_s[KEX_F_SIZE];
    byte sig_s[KEX_SIG_SIZE];
#endif
    byte msgId = 0;
    byte useDh = 0;
    byte useEcc = 0;
    byte useCurve25519 = 0;
    byte useEccKyber = 0;

    WLOG(WS_LOG_DEBUG, "Entering SendKexDhReply()");

    if (ret == WS_SUCCESS) {
        if (ssh == NULL || ssh->ctx == NULL || ssh->handshake == NULL) {
            ret = WS_BAD_ARGUMENT;
        }
    }

    if (ret == WS_SUCCESS) {
        heap = ssh->ctx->heap;
    }

#ifdef WOLFSSH_SMALL_STACK
    f_ptr = (byte*)WMALLOC(KEX_F_SIZE, heap, DYNTYPE_BUFFER);
    sig_ptr = (byte*)WMALLOC(KEX_SIG_SIZE, heap, DYNTYPE_BUFFER);
    if (f_ptr == NULL || sig_ptr == NULL)
        ret = WS_MEMORY_E;
#else
    f_ptr = f_s;
    sig_ptr = sig_s;
#endif

    sigKeyBlock_ptr = (struct wolfSSH_sigKeyBlockFull*)WMALLOC(
            sizeof(struct wolfSSH_sigKeyBlockFull), heap, DYNTYPE_PRIVKEY);
    if (sigKeyBlock_ptr == NULL)
        ret = WS_MEMORY_E;

    if (ret == WS_SUCCESS) {
        WMEMSET(sigKeyBlock_ptr, 0, sizeof(struct wolfSSH_sigKeyBlockFull));
        sigKeyBlock_ptr->pubKeyId = ID_NONE;
    }

    if (ret == WS_SUCCESS) {
        sigKeyBlock_ptr->pubKeyId = ssh->handshake->pubKeyId;
        sigKeyBlock_ptr->pubKeyName =
            IdToName(SigTypeForId(sigKeyBlock_ptr->pubKeyId));
        sigKeyBlock_ptr->pubKeyNameSz =
                (word32)WSTRLEN(sigKeyBlock_ptr->pubKeyName);
        sigKeyBlock_ptr->pubKeyFmtId = sigKeyBlock_ptr->pubKeyId;
        if (sigKeyBlock_ptr->pubKeyId == ID_RSA_SHA2_256
                || sigKeyBlock_ptr->pubKeyId == ID_RSA_SHA2_512) {
            sigKeyBlock_ptr->pubKeyFmtId = ID_SSH_RSA;
        }
        sigKeyBlock_ptr->pubKeyFmtName =
                IdToName(sigKeyBlock_ptr->pubKeyFmtId);
        sigKeyBlock_ptr->pubKeyFmtNameSz =
                (word32)WSTRLEN(sigKeyBlock_ptr->pubKeyFmtName);

        switch (ssh->handshake->kexId) {
#ifndef WOLFSSH_NO_DH_GROUP1_SHA1
            case ID_DH_GROUP1_SHA1:
                useDh = 1;
                msgId = MSGID_KEXDH_REPLY;
                break;
#endif
#ifndef WOLFSSH_NO_DH_GROUP14_SHA1
            case ID_DH_GROUP14_SHA1:
                useDh = 1;
                msgId = MSGID_KEXDH_REPLY;
                break;
#endif
#ifndef WOLFSSH_NO_DH_GROUP14_SHA256
            case ID_DH_GROUP14_SHA256:
                useDh = 1;
                msgId = MSGID_KEXDH_REPLY;
                break;
#endif
#ifndef WOLFSSH_NO_DH_GEX_SHA256
            case ID_DH_GEX_SHA256:
                useDh = 1;
                msgId = MSGID_KEXDH_GEX_REPLY;
                break;
#endif
#ifndef WOLFSSH_NO_ECDH_SHA2_NISTP256
            case ID_ECDH_SHA2_NISTP256:
                useEcc = 1;
                msgId = MSGID_KEXDH_REPLY;
                break;
#endif
#ifndef WOLFSSH_NO_ECDH_SHA2_NISTP384
            case ID_ECDH_SHA2_NISTP384:
                useEcc = 1;
                msgId = MSGID_KEXDH_REPLY;
                break;
#endif
#ifndef WOLFSSH_NO_ECDH_SHA2_NISTP521
            case ID_ECDH_SHA2_NISTP521:
                useEcc = 1;
                msgId = MSGID_KEXDH_REPLY;
                break;
#endif
#ifndef WOLFSSH_NO_CURVE25519_SHA256
            case ID_CURVE25519_SHA256:
                useCurve25519 = 1;
                msgId = MSGID_KEXDH_REPLY;
                break;
#endif
#ifndef WOLFSSH_NO_ECDH_NISTP256_KYBER_LEVEL1_SHA256
            case ID_ECDH_NISTP256_KYBER_LEVEL1_SHA256:
                useEccKyber = 1; /* Only support level 1 for now. */
                msgId = MSGID_KEXKEM_REPLY;
                break;
#endif
            default:
                ret = WS_INVALID_ALGO_ID;
        }
    }

    if (ret == WS_SUCCESS) {
        hash = &ssh->handshake->kexHash;
        hashId = (enum wc_HashType)ssh->handshake->kexHashId;

        for (keyIdx = 0; keyIdx < ssh->ctx->privateKeyCount; keyIdx++) {
            if (ssh->ctx->privateKey[keyIdx].publicKeyFmt
                    == sigKeyBlock_ptr->pubKeyFmtId) {
                break;
            }
        }
        if (keyIdx == ssh->ctx->privateKeyCount) {
            ret = WS_INVALID_ALGO_ID;
        }
    }

    /* At this point, the exchange hash, H, includes items V_C, V_S, I_C,
     * and I_S. Next add K_S, the server's public host key. K_S will
     * either be RSA or ECDSA public key blob. */
    if (ret == WS_SUCCESS) {
        ret = SendKexGetSigningKey(ssh, sigKeyBlock_ptr, hashId, hash, keyIdx);
    }

    if (ret == WS_SUCCESS) {
        /* reset size here because a previous shared secret could potentially be
         * smaller by a byte than usual and cause buffer issues with re-key */
        ssh->kSz = MAX_KEX_KEY_SZ;

        /* Make the server's DH f-value and the shared secret K. */
        /* Or make the server's ECDH private value, and the shared secret K. */
        if (ret == 0) {
            if (useDh) {
                ret = KeyAgreeDh_server(ssh, hashId, f_ptr, &fSz);
            }
            else if (useEcc) {
                ret = KeyAgreeEcdh_server(ssh, hashId, f_ptr, &fSz);
            }
            if (useCurve25519) {
                ret = KeyAgreeCurve25519_server(ssh, hashId, f_ptr, &fSz);
            }
            else if (useEccKyber) {
                ret = KeyAgreeEcdhKyber512_server(ssh, hashId, f_ptr, &fSz);
            }
        }

        /* Hash in the server's DH f-value. */
        if (ret == 0 && (useDh || useEcc)) {
            ret = CreateMpint(f_ptr, &fSz, &fPad);
        }
        if (ret == 0) {
            c32toa(fSz + fPad, scratchLen);
            ret = HashUpdate(hash, hashId, scratchLen, LENGTH_SZ);
        }
        if ((ret == 0) && (fPad)) {
            scratchLen[0] = 0;
            ret = HashUpdate(hash, hashId, scratchLen, 1);
        }
        if (ret == 0) {
            ret = HashUpdate(hash, hashId, f_ptr, fSz);
        }

        /* Hash in the shared secret K. */
        if (ret == 0 && !useEccKyber) {
            ret = CreateMpint(ssh->k, &ssh->kSz, &kPad);
        }
        if (ret == 0) {
            c32toa(ssh->kSz + kPad, scratchLen);
            ret = HashUpdate(hash, hashId, scratchLen, LENGTH_SZ);
        }
        if ((ret == 0) && (kPad)) {
            scratchLen[0] = 0;
            ret = HashUpdate(hash, hashId, scratchLen, 1);
        }
        if (ret == 0) {
            ret = HashUpdate(hash, hashId, ssh->k, ssh->kSz);
        }

        /* Save the exchange hash value H, and session ID. */
        if (ret == 0) {
            ret = wc_HashGetDigestSize(hashId);
            if (ret > 0) {
                ssh->hSz = ret;
                ret = 0;
            }
        }
        if (ret == 0) {
            ret = wc_HashFinal(hash, hashId, ssh->h);
            wc_HashFree(hash, hashId);
            ssh->handshake->kexHashId = WC_HASH_TYPE_NONE;
        }
        if (ret == 0) {
            if (ssh->sessionIdSz == 0) {
                WMEMCPY(ssh->sessionId, ssh->h, ssh->hSz);
                ssh->sessionIdSz = ssh->hSz;
            }
        }
        if (ret != WS_SUCCESS) {
            ret = WS_CRYPTO_FAILED;
        }
    }

    /* Sign h with the server's private key. */
    if (ret == WS_SUCCESS) {
        ret = SignH(ssh, sig_ptr, &sigSz, sigKeyBlock_ptr);
    }

    if (sigKeyBlock_ptr != NULL) {
        if (sigKeyBlock_ptr->pubKeyFmtId == ID_SSH_RSA) {
#ifndef WOLFSSH_NO_RSA
            wc_FreeRsaKey(&sigKeyBlock_ptr->sk.rsa.key);
#endif
        }
        else if (sigKeyBlock_ptr->pubKeyFmtId == ID_ECDSA_SHA2_NISTP256
                || sigKeyBlock_ptr->pubKeyFmtId == ID_ECDSA_SHA2_NISTP384
                || sigKeyBlock_ptr->pubKeyFmtId == ID_ECDSA_SHA2_NISTP521) {
#ifndef WOLFSSH_NO_ECDSA
            wc_ecc_free(&sigKeyBlock_ptr->sk.ecc.key);
#endif
        }
        else if (sigKeyBlock_ptr->pubKeyId == ID_ED25519) {
#if !defined(WOLFSSH_NO_ED25519)
            wc_ed25519_free(&sigKeyBlock_ptr->sk.ed.key);
#endif
        }
    }

    if (ret == WS_SUCCESS) {
        /* If we aren't using EccKyber, use padding. */
        ret = GenerateKeys(ssh, hashId, !useEccKyber);
    }

    /* Get the buffer, copy the packet data, once f is laid into the buffer,
     * add it to the hash and then add K. */
    if (ret == WS_SUCCESS) {
        sigBlockSz = (LENGTH_SZ * 2) + sigKeyBlock_ptr->pubKeyNameSz + sigSz;
        payloadSz = MSG_ID_SZ + (LENGTH_SZ * 3) +
                    sigKeyBlock_ptr->sz + fSz + fPad + sigBlockSz;
        ret = PreparePacket(ssh, payloadSz);
    }

    if (ret == WS_SUCCESS) {
        output = ssh->outputBuffer.buffer;
        idx = ssh->outputBuffer.length;

        output[idx++] = msgId;

        /* Copy the key block size into the buffer */
        c32toa(sigKeyBlock_ptr->sz, output + idx);
        idx += LENGTH_SZ;

        /* Copy the key name into the buffer */
        c32toa(sigKeyBlock_ptr->pubKeyFmtNameSz, output + idx);
        idx += LENGTH_SZ;
        WMEMCPY(output + idx, sigKeyBlock_ptr->pubKeyFmtName, sigKeyBlock_ptr->pubKeyFmtNameSz);
        idx += sigKeyBlock_ptr->pubKeyFmtNameSz;

        /* add host public key */
        switch (sigKeyBlock_ptr->pubKeyFmtId) {
            case ID_SSH_RSA:
            {
#ifndef WOLFSSH_NO_RSA
            /* Copy the rsaKeyBlock into the buffer. */
            c32toa(sigKeyBlock_ptr->sk.rsa.eSz + sigKeyBlock_ptr->sk.rsa.ePad,
                   output + idx);
            idx += LENGTH_SZ;
            if (sigKeyBlock_ptr->sk.rsa.ePad) output[idx++] = 0;
            WMEMCPY(output + idx,
                    sigKeyBlock_ptr->sk.rsa.e, sigKeyBlock_ptr->sk.rsa.eSz);
            idx += sigKeyBlock_ptr->sk.rsa.eSz;
            c32toa(sigKeyBlock_ptr->sk.rsa.nSz + sigKeyBlock_ptr->sk.rsa.nPad,
                   output + idx);
            idx += LENGTH_SZ;
            if (sigKeyBlock_ptr->sk.rsa.nPad) output[idx++] = 0;
            WMEMCPY(output + idx,
                    sigKeyBlock_ptr->sk.rsa.n, sigKeyBlock_ptr->sk.rsa.nSz);
            idx += sigKeyBlock_ptr->sk.rsa.nSz;
#endif /* WOLFSSH_NO_RSA */
            }
            break;

            case ID_ECDSA_SHA2_NISTP256:
            case ID_ECDSA_SHA2_NISTP384:
            case ID_ECDSA_SHA2_NISTP521:
            {
#ifndef WOLFSSH_NO_ECDSA
            /* Copy the ecdsaKeyBlock into the buffer. */
            c32toa(sigKeyBlock_ptr->sk.ecc.primeNameSz, output + idx);
            idx += LENGTH_SZ;
            WMEMCPY(output + idx, sigKeyBlock_ptr->sk.ecc.primeName,
                    sigKeyBlock_ptr->sk.ecc.primeNameSz);
            idx += sigKeyBlock_ptr->sk.ecc.primeNameSz;
            c32toa(sigKeyBlock_ptr->sk.ecc.qSz, output + idx);
            idx += LENGTH_SZ;
            WMEMCPY(output + idx, sigKeyBlock_ptr->sk.ecc.q,
                    sigKeyBlock_ptr->sk.ecc.qSz);
            idx += sigKeyBlock_ptr->sk.ecc.qSz;
#endif
            }
            break;

            case ID_ED25519:
            {
#if !defined(WOLFSSH_NO_ED25519)
            /* Copy the edKeyBlock into the buffer. */
            c32toa(sigKeyBlock_ptr->sk.ed.qSz, output + idx);
            idx += LENGTH_SZ;
            WMEMCPY(output + idx, sigKeyBlock_ptr->sk.ed.q,
                    sigKeyBlock_ptr->sk.ed.qSz);
            idx += sigKeyBlock_ptr->sk.ed.qSz;
#endif
            }
            break;

        #ifdef WOLFSSH_CERTS
            case ID_X509V3_SSH_RSA:
            case ID_X509V3_ECDSA_SHA2_NISTP256:
            case ID_X509V3_ECDSA_SHA2_NISTP384:
            case ID_X509V3_ECDSA_SHA2_NISTP521:
            {
                ret = BuildRFC6187Info(ssh, sigKeyBlock_ptr->pubKeyId,
                    ssh->ctx->privateKey[keyIdx].cert,
                    ssh->ctx->privateKey[keyIdx].certSz,
                    NULL, 0, output, &ssh->outputBuffer.bufferSz, &idx);
            }
            break;
        #endif
        }
    }

    if (ret == WS_SUCCESS) {
        /* Copy the server's public key. F for DHE, or Q_S for ECDH. */
        c32toa(fSz + fPad, output + idx);
        idx += LENGTH_SZ;
        if (fPad) output[idx++] = 0;
        WMEMCPY(output + idx, f_ptr, fSz);
        idx += fSz;

        /* Copy the signature of the exchange hash. */
        c32toa(sigBlockSz, output + idx);
        idx += LENGTH_SZ;
        c32toa(sigKeyBlock_ptr->pubKeyNameSz, output + idx);
        idx += LENGTH_SZ;
        WMEMCPY(output + idx,
                sigKeyBlock_ptr->pubKeyName, sigKeyBlock_ptr->pubKeyNameSz);
        idx += sigKeyBlock_ptr->pubKeyNameSz;
        c32toa(sigSz, output + idx);
        idx += LENGTH_SZ;
        WMEMCPY(output + idx, sig_ptr, sigSz);
        idx += sigSz;

        ssh->outputBuffer.length = idx;

        ret = BundlePacket(ssh);
    }

    if (ret == WS_SUCCESS)
        ret = SendNewKeys(ssh);

    if (ret == WS_SUCCESS && ssh->sendExtInfo) {
        ret = SendExtInfo(ssh);
    }

    if (ret != WS_WANT_WRITE && ret != WS_SUCCESS)
        PurgePacket(ssh);

    WLOG(WS_LOG_DEBUG, "Leaving SendKexDhReply(), ret = %d", ret);
    if (sigKeyBlock_ptr)
        WFREE(sigKeyBlock_ptr, heap, DYNTYPE_PRIVKEY);
#ifdef WOLFSSH_SMALL_STACK
    if (f_ptr)
        WFREE(f_ptr, heap, DYNTYPE_BUFFER);
    if (sig_ptr)
        WFREE(sig_ptr, heap, DYNTYPE_BUFFER);
#endif
    return ret;
}


int SendNewKeys(WOLFSSH* ssh)
{
    byte* output;
    word32 idx = 0;
    int ret = WS_SUCCESS;

    WLOG(WS_LOG_DEBUG, "Entering SendNewKeys()");
    if (ssh == NULL)
        ret = WS_BAD_ARGUMENT;

    if (ret == WS_SUCCESS)
        ret = PreparePacket(ssh, MSG_ID_SZ);

    if (ret == WS_SUCCESS) {
        output = ssh->outputBuffer.buffer;
        idx = ssh->outputBuffer.length;

        output[idx++] = MSGID_NEWKEYS;

        ssh->outputBuffer.length = idx;

        ret = BundlePacket(ssh);
    }

    if (ret == WS_SUCCESS) {
        ssh->blockSz = ssh->handshake->blockSz;
        ssh->encryptId = ssh->handshake->encryptId;
        ssh->macSz = ssh->handshake->macSz;
        ssh->macId = ssh->handshake->macId;
        ssh->aeadMode = ssh->handshake->aeadMode;
        WMEMCPY(&ssh->keys, &ssh->handshake->keys, sizeof(Keys));

        switch (ssh->encryptId) {
            case ID_NONE:
                WLOG(WS_LOG_DEBUG, "SNK: using cipher none");
                break;

#ifndef WOLFSSH_NO_AES_CBC
            case ID_AES128_CBC:
            case ID_AES192_CBC:
            case ID_AES256_CBC:
                WLOG(WS_LOG_DEBUG, "SNK: using cipher aes-cbc");
                ret = wc_AesSetKey(&ssh->encryptCipher.aes,
                                  ssh->keys.encKey, ssh->keys.encKeySz,
                                  ssh->keys.iv, AES_ENCRYPTION);
                break;
#endif

#ifndef WOLFSSH_NO_AES_CTR
            case ID_AES128_CTR:
            case ID_AES192_CTR:
            case ID_AES256_CTR:
                WLOG(WS_LOG_DEBUG, "SNK: using cipher aes-ctr");
                ret = wc_AesSetKey(&ssh->encryptCipher.aes,
                                  ssh->keys.encKey, ssh->keys.encKeySz,
                                  ssh->keys.iv, AES_ENCRYPTION);
                break;
#endif

#ifndef WOLFSSH_NO_AES_GCM
            case ID_AES128_GCM:
            case ID_AES192_GCM:
            case ID_AES256_GCM:
                WLOG(WS_LOG_DEBUG, "SNK: using cipher aes-gcm");
                ret = wc_AesGcmSetKey(&ssh->encryptCipher.aes,
                                     ssh->keys.encKey, ssh->keys.encKeySz);
                break;
#endif

            default:
                WLOG(WS_LOG_DEBUG, "SNK: using cipher invalid");
                ret = WS_INVALID_ALGO_ID;
        }
    }

    if (ret == WS_SUCCESS) {
        ssh->txCount = 0;
    }

    if (ret == WS_SUCCESS)
        ret = wolfSSH_SendPacket(ssh);

    WLOG(WS_LOG_DEBUG, "Leaving SendNewKeys(), ret = %d", ret);
    return ret;
}


#ifndef WOLFSSH_NO_DH_GEX_SHA256
int SendKexDhGexRequest(WOLFSSH* ssh)
{
    byte* output;
    word32 idx = 0;
    word32 payloadSz;
    int ret = WS_SUCCESS;

    WLOG(WS_LOG_DEBUG, "Entering SendKexDhGexRequest()");
    if (ssh == NULL || ssh->handshake == NULL)
        ret = WS_BAD_ARGUMENT;

    if (ret == WS_SUCCESS) {
        payloadSz = MSG_ID_SZ + (UINT32_SZ * 3);
        ret = PreparePacket(ssh, payloadSz);
    }

    if (ret == WS_SUCCESS) {
        output = ssh->outputBuffer.buffer;
        idx = ssh->outputBuffer.length;

        output[idx++] = MSGID_KEXDH_GEX_REQUEST;

        WLOG(WS_LOG_INFO, "  min = %u, preferred = %u, max = %u",
                ssh->handshake->dhGexMinSz,
                ssh->handshake->dhGexPreferredSz,
                ssh->handshake->dhGexMaxSz);
        c32toa(ssh->handshake->dhGexMinSz, output + idx);
        idx += UINT32_SZ;
        c32toa(ssh->handshake->dhGexPreferredSz, output + idx);
        idx += UINT32_SZ;
        c32toa(ssh->handshake->dhGexMaxSz, output + idx);
        idx += UINT32_SZ;

        ssh->outputBuffer.length = idx;

        ret = BundlePacket(ssh);
    }

    if (ret == WS_SUCCESS)
        ret = wolfSSH_SendPacket(ssh);

    WLOG(WS_LOG_DEBUG, "Leaving SendKexDhGexRequest(), ret = %d", ret);
    return ret;
}


int SendKexDhGexGroup(WOLFSSH* ssh)
{
    byte* output;
    word32 idx = 0;
    word32 payloadSz;
    const byte* primeGroup = dhPrimeGroup14;
    word32 primeGroupSz = dhPrimeGroup14Sz;
    const byte* generator = dhGenerator;
    word32 generatorSz = dhGeneratorSz;
    byte primePad = 0;
    byte generatorPad = 0;
    int ret = WS_SUCCESS;

    WLOG(WS_LOG_DEBUG, "Entering SendKexDhGexGroup()");
    if (ssh == NULL)
        ret = WS_BAD_ARGUMENT;

    if (ret == WS_SUCCESS) {
        if (primeGroup[0] & 0x80)
            primePad = 1;

        if (generator[0] & 0x80)
            generatorPad = 1;

        payloadSz = MSG_ID_SZ + (LENGTH_SZ * 2) +
                    primeGroupSz + primePad +
                    generatorSz + generatorPad;
        ret = PreparePacket(ssh, payloadSz);
    }

    if (ret == WS_SUCCESS) {
        output = ssh->outputBuffer.buffer;
        idx = ssh->outputBuffer.length;

        output[idx++] = MSGID_KEXDH_GEX_GROUP;

        c32toa(primeGroupSz + primePad, output + idx);
        idx += LENGTH_SZ;

        if (primePad) {
            output[idx++] = 0;
        }

        WMEMCPY(output + idx, primeGroup, primeGroupSz);
        idx += primeGroupSz;

        c32toa(generatorSz + generatorPad, output + idx);
        idx += LENGTH_SZ;

        if (generatorPad) {
            output[idx++] = 0;
        }

        WMEMCPY(output + idx, generator, generatorSz);
        idx += generatorSz;

        ssh->outputBuffer.length = idx;

        ret = BundlePacket(ssh);
    }

    if (ret == WS_SUCCESS)
        ret = wolfSSH_SendPacket(ssh);

    WLOG(WS_LOG_DEBUG, "Leaving SendKexDhGexGroup(), ret = %d", ret);
    return ret;
}
#endif


int SendKexDhInit(WOLFSSH* ssh)
{
    byte* output;
    word32 idx = 0;
    word32 payloadSz;
#ifndef WOLFSSH_NO_DH
    const byte* primeGroup = NULL;
    word32 primeGroupSz = 0;
    const byte* generator = NULL;
    word32 generatorSz = 0;
#endif
    int ret = WS_SUCCESS;
    byte msgId = MSGID_KEXDH_INIT;
    byte e[MAX_KEX_KEY_SZ+1]; /* plus 1 in case of padding. */
    word32 eSz = (word32)sizeof(e);
    byte  ePad = 0;

    WLOG(WS_LOG_DEBUG, "Entering SendKexDhInit()");

    switch (ssh->handshake->kexId) {
#ifndef WOLFSSH_NO_DH_GROUP1_SHA1
        case ID_DH_GROUP1_SHA1:
            ssh->handshake->useDh = 1;
            primeGroup = dhPrimeGroup1;
            primeGroupSz = dhPrimeGroup1Sz;
            generator = dhGenerator;
            generatorSz = dhGeneratorSz;
            break;
#endif
#ifndef WOLFSSH_NO_DH_GROUP14_SHA1
        case ID_DH_GROUP14_SHA1:
            ssh->handshake->useDh = 1;
            primeGroup = dhPrimeGroup14;
            primeGroupSz = dhPrimeGroup14Sz;
            generator = dhGenerator;
            generatorSz = dhGeneratorSz;
            break;
#endif
#ifndef WOLFSSH_NO_DH_GROUP14_SHA256
        case ID_DH_GROUP14_SHA256:
            ssh->handshake->useDh = 1;
            primeGroup = dhPrimeGroup14;
            primeGroupSz = dhPrimeGroup14Sz;
            generator = dhGenerator;
            generatorSz = dhGeneratorSz;
            break;
#endif
#ifndef WOLFSSH_NO_DH_GEX_SHA256
        case ID_DH_GEX_SHA256:
            ssh->handshake->useDh = 1;
            primeGroup = ssh->handshake->primeGroup;
            primeGroupSz = ssh->handshake->primeGroupSz;
            generator = ssh->handshake->generator;
            generatorSz = ssh->handshake->generatorSz;
            msgId = MSGID_KEXDH_GEX_INIT;
            break;
#endif
#ifndef WOLFSSH_NO_ECDH_SHA2_NISTP256
        case ID_ECDH_SHA2_NISTP256:
            ssh->handshake->useEcc = 1;
            msgId = MSGID_KEXECDH_INIT;
            break;
#endif
#ifndef WOLFSSH_NO_ECDH_SHA2_NISTP384
        case ID_ECDH_SHA2_NISTP384:
            ssh->handshake->useEcc = 1;
            msgId = MSGID_KEXECDH_INIT;
            break;
#endif
#ifndef WOLFSSH_NO_ECDH_SHA2_NISTP521
        case ID_ECDH_SHA2_NISTP521:
            ssh->handshake->useEcc = 1;
            msgId = MSGID_KEXECDH_INIT;
            break;
#endif
#ifndef WOLFSSH_NO_CURVE25519_SHA256
        case ID_CURVE25519_SHA256:
            ssh->handshake->useCurve25519 = 1;
            msgId = MSGID_KEXECDH_INIT;
            break;
#endif
#ifndef WOLFSSH_NO_ECDH_NISTP256_KYBER_LEVEL1_SHA256
        case ID_ECDH_NISTP256_KYBER_LEVEL1_SHA256:
            /* Only support level 1 for now. */
            ssh->handshake->useEccKyber = 1;
            msgId = MSGID_KEXKEM_INIT;
            break;
#endif
        default:
            WLOG(WS_LOG_DEBUG, "Invalid algo: %u", ssh->handshake->kexId);
            ret = WS_INVALID_ALGO_ID;
    }


    if (ret == WS_SUCCESS) {
        if (!ssh->handshake->useEcc
#ifndef WOLFSSH_NO_ECDH_NISTP256_KYBER_LEVEL1_SHA256
            && !ssh->handshake->useEccKyber
#endif
#ifndef WOLFSSH_NO_CURVE25519_SHA256
            && !ssh->handshake->useCurve25519
#endif
) {
#ifndef WOLFSSH_NO_DH
            DhKey* privKey = &ssh->handshake->privKey.dh;

            ret = wc_InitDhKey(privKey);
            if (ret == 0)
                ret = wc_DhSetKey(privKey, primeGroup, primeGroupSz,
                                  generator, generatorSz);
            if (ret == 0)
                ret = wc_DhGenerateKeyPair(privKey, ssh->rng,
                                           ssh->handshake->x,
                                           &ssh->handshake->xSz,
                                           e, &eSz);
#endif
        }
#ifndef WOLFSSH_NO_CURVE25519_SHA256
        else if (ssh->handshake->useCurve25519) {
            curve25519_key* privKey = &ssh->handshake->privKey.curve25519;
            if (ret == 0)
                ret = wc_curve25519_init_ex(privKey, ssh->ctx->heap,
                                            INVALID_DEVID);
            if (ret == 0)
                ret = wc_curve25519_make_key(ssh->rng, CURVE25519_KEYSIZE,
                                             privKey);
            if (ret == 0) {
                PRIVATE_KEY_UNLOCK();
                ret = wc_curve25519_export_public_ex(privKey, e, &eSz,
                          EC25519_LITTLE_ENDIAN);
                PRIVATE_KEY_LOCK();
            }
        }
#endif /* ! WOLFSSH_NO_CURVE25519_SHA256 */
        else if (ssh->handshake->useEcc
#ifndef WOLFSSH_NO_ECDH_NISTP256_KYBER_LEVEL1_SHA256
                 || ssh->handshake->useEccKyber
#endif
                ) {
#if !defined(WOLFSSH_NO_ECDH)
            ecc_key* privKey = &ssh->handshake->privKey.ecc;
            int primeId = wcPrimeForId(ssh->handshake->kexId);

            if (primeId == ECC_CURVE_INVALID)
                ret = WS_INVALID_PRIME_CURVE;

            if (ret == 0)
                ret = wc_ecc_init_ex(privKey, ssh->ctx->heap,
                                     INVALID_DEVID);
#ifdef HAVE_WC_ECC_SET_RNG
            if (ret == 0)
                ret = wc_ecc_set_rng(privKey, ssh->rng);
#endif
            if (ret == 0)
                ret = wc_ecc_make_key_ex(ssh->rng,
                                     wc_ecc_get_curve_size_from_id(primeId),
                                     privKey, primeId);
            if (ret == 0) {
                PRIVATE_KEY_UNLOCK();
                ret = wc_ecc_export_x963(privKey, e, &eSz);
                PRIVATE_KEY_LOCK();
            }
#else
            ret = WS_INVALID_ALGO_ID;
#endif /* !defined(WOLFSSH_NO_ECDH) */
        }
        else {
            ret = WS_INVALID_ALGO_ID;
        }

#ifndef WOLFSSH_NO_ECDH_NISTP256_KYBER_LEVEL1_SHA256
        if (ssh->handshake->useEccKyber) {
            KyberKey kem = {0};
            word32 length_publickey = 0;
            word32 length_privatekey = 0;
            ret = 0;

            if (ret == 0) {
                ret = wc_KyberKey_Init(KYBER512, &kem, ssh->ctx->heap,
                                       INVALID_DEVID);
            }

            if (ret == 0) {
                ret = wc_KyberKey_MakeKey(&kem, ssh->rng);
            }

            if (ret == 0) {
                ret = wc_KyberKey_PublicKeySize(&kem, &length_publickey);
            }

            if (ret == 0) {
                ret = wc_KyberKey_PrivateKeySize(&kem, &length_privatekey);
            }

            if (ret == 0) {
                /* Move ecc to the back and put PQ Key in the front. Note that
                 * this assumes the PQ public key is bigger than the ECC public
                 * key. */
                XMEMCPY(e + length_publickey, e, eSz);
                ret = wc_KyberKey_EncodePublicKey(&kem, e, length_publickey);
                eSz += length_publickey;
            }

            if (ret == 0) {
                ret = wc_KyberKey_EncodePrivateKey(&kem, ssh->handshake->x,
                                                   length_privatekey);
                ssh->handshake->xSz = length_privatekey;
            }

            wc_KyberKey_Free(&kem);
        }
#endif /* ! WOLFSSH_NO_ECDH_NISTP256_KYBER_LEVEL1_SHA256 */
        if (ret == 0) {
            ret = WS_SUCCESS;
        }
    }

    if (ret == WS_SUCCESS
#ifndef WOLFSSH_NO_ECDH_NISTP256_KYBER_LEVEL1_SHA256
        && !ssh->handshake->useEccKyber
#endif
#ifndef WOLFSSH_NO_CURVE25519_SHA256
        && !ssh->handshake->useCurve25519
#endif

       ) {
        ret = CreateMpint(e, &eSz, &ePad);
    }

    if (ret == WS_SUCCESS) {
        if (ePad == 1) {
            ssh->handshake->e[0] = 0;
        }
        WMEMCPY(ssh->handshake->e + ePad, e, eSz);
        ssh->handshake->eSz = eSz + ePad;

        payloadSz = MSG_ID_SZ + LENGTH_SZ + eSz + ePad;
        ret = PreparePacket(ssh, payloadSz);
    }

    if (ret == WS_SUCCESS) {
        output = ssh->outputBuffer.buffer;
        idx = ssh->outputBuffer.length;

        output[idx++] = msgId;

        c32toa(eSz + ePad, output + idx);
        idx += LENGTH_SZ;

        if (ePad) {
            output[idx] = 0;
            idx++;
        }

        WMEMCPY(output + idx, e, eSz);
        idx += eSz;

        ssh->outputBuffer.length = idx;

        ret = BundlePacket(ssh);
    }

    if (ret == WS_SUCCESS)
        ret = wolfSSH_SendPacket(ssh);

    WLOG(WS_LOG_DEBUG, "Leaving SendKexDhInit(), ret = %d", ret);
    return ret;
}


int SendUnimplemented(WOLFSSH* ssh)
{
    byte* output;
    word32 idx = 0;
    int ret = WS_SUCCESS;

    if (ssh == NULL) {
        WLOG(WS_LOG_DEBUG, "Entering SendUnimplemented(), no parameter");
        ret = WS_BAD_ARGUMENT;
        WLOG(WS_LOG_DEBUG, "Leaving SendUnimplemented(), ret = %d", ret);
        return ret;
    }

    WLOG(WS_LOG_DEBUG,
         "Entering SendUnimplemented(), peerSeq = %u", ssh->peerSeq);

    if (ret == WS_SUCCESS)
        ret = PreparePacket(ssh, MSG_ID_SZ + LENGTH_SZ);

    if (ret == WS_SUCCESS) {
        output = ssh->outputBuffer.buffer;
        idx = ssh->outputBuffer.length;

        output[idx++] = MSGID_UNIMPLEMENTED;
        c32toa(ssh->peerSeq, output + idx);
        idx += UINT32_SZ;

        ssh->outputBuffer.length = idx;

        ret = BundlePacket(ssh);
    }

    if (ret == WS_SUCCESS)
        ret = wolfSSH_SendPacket(ssh);

    WLOG(WS_LOG_DEBUG, "Leaving SendUnimplemented(), ret = %d", ret);
    return ret;
}


int SendDisconnect(WOLFSSH* ssh, word32 reason)
{
    byte* output;
    word32 idx = 0;
    int ret = WS_SUCCESS;

    if (ssh == NULL)
        ret = WS_BAD_ARGUMENT;

    if (ret == WS_SUCCESS)
        ret = PreparePacket(ssh, MSG_ID_SZ + UINT32_SZ + (LENGTH_SZ * 2));

    if (ret == WS_SUCCESS) {
        output = ssh->outputBuffer.buffer;
        idx = ssh->outputBuffer.length;

        output[idx++] = MSGID_DISCONNECT;
        c32toa(reason, output + idx);
        idx += UINT32_SZ;
        c32toa(0, output + idx);
        idx += LENGTH_SZ;
        c32toa(0, output + idx);
        idx += LENGTH_SZ;

        ssh->outputBuffer.length = idx;

        ret = BundlePacket(ssh);
    }

    if (ret == WS_SUCCESS)
        ret = wolfSSH_SendPacket(ssh);

    return ret;
}


int SendIgnore(WOLFSSH* ssh, const unsigned char* data, word32 dataSz)
{
    byte* output;
    word32 idx = 0;
    int ret = WS_SUCCESS;

    if (ssh == NULL || (data == NULL && dataSz > 0))
        ret = WS_BAD_ARGUMENT;

    if (ret == WS_SUCCESS)
        ret = PreparePacket(ssh, MSG_ID_SZ + LENGTH_SZ + dataSz);

    if (ret == WS_SUCCESS) {
        output = ssh->outputBuffer.buffer;
        idx = ssh->outputBuffer.length;

        output[idx++] = MSGID_IGNORE;
        c32toa(dataSz, output + idx);
        idx += LENGTH_SZ;
        if (dataSz > 0) {
            WMEMCPY(output + idx, data, dataSz);
            idx += dataSz;
        }

        ssh->outputBuffer.length = idx;

        ret = BundlePacket(ssh);
    }

    if (ret == WS_SUCCESS)
        ret = wolfSSH_SendPacket(ssh);

    return ret;
}

int SendGlobalRequest(WOLFSSH* ssh, const unsigned char* data, word32 dataSz, int reply)
{
    byte* output;
    word32 idx = 0;
    int ret = WS_SUCCESS;

    if (ssh == NULL || (data == NULL && dataSz > 0))
        ret = WS_BAD_ARGUMENT;

    WLOG(WS_LOG_DEBUG, "Enter SendGlobalRequest");

    if (ret == WS_SUCCESS)
        ret = PreparePacket(ssh, MSG_ID_SZ + LENGTH_SZ + dataSz + BOOLEAN_SZ);
    WLOG(WS_LOG_DEBUG, "Done PreparePacket");

    if (ret == WS_SUCCESS)
    {
        output = ssh->outputBuffer.buffer;
        idx = ssh->outputBuffer.length;

        output[idx++] = MSGID_GLOBAL_REQUEST;
        c32toa(dataSz, output + idx);
        idx += LENGTH_SZ;
        if (dataSz > 0)
        {
            WMEMCPY(output + idx, data, dataSz);
            idx += dataSz;
        }

        output[idx++] = reply;

        ssh->outputBuffer.length = idx;

        ret = BundlePacket(ssh);
    }
    WLOG(WS_LOG_DEBUG, "Done BundlePacket");

    if (ret == WS_SUCCESS)
        ret = wolfSSH_SendPacket(ssh);

    WLOG(WS_LOG_DEBUG, "Leaving SendServiceRequest(), ret = %d", ret);

    return ret;
}

static const char cannedLangTag[] = "en-us";
static const word32 cannedLangTagSz = (word32)sizeof(cannedLangTag) - 1;


int SendDebug(WOLFSSH* ssh, byte alwaysDisplay, const char* msg)
{
    word32 msgSz;
    byte* output;
    word32 idx = 0;
    int ret = WS_SUCCESS;

    if (ssh == NULL)
        ret = WS_BAD_ARGUMENT;

    if (ret == WS_SUCCESS) {
        msgSz = (msg != NULL) ? (word32)WSTRLEN(msg) : 0;

        ret = PreparePacket(ssh,
                            MSG_ID_SZ + BOOLEAN_SZ + (LENGTH_SZ * 2) +
                            msgSz + cannedLangTagSz);
    }

    if (ret == WS_SUCCESS) {
        output = ssh->outputBuffer.buffer;
        idx = ssh->outputBuffer.length;

        output[idx++] = MSGID_DEBUG;
        output[idx++] = (alwaysDisplay != 0);
        c32toa(msgSz, output + idx);
        idx += LENGTH_SZ;
        if (msgSz > 0) {
            WMEMCPY(output + idx, msg, msgSz);
            idx += msgSz;
        }
        c32toa(cannedLangTagSz, output + idx);
        idx += LENGTH_SZ;
        WMEMCPY(output + idx, cannedLangTag, cannedLangTagSz);
        idx += cannedLangTagSz;

        ssh->outputBuffer.length = idx;

        ret = BundlePacket(ssh);
    }

    if (ret == WS_SUCCESS)
        ret = wolfSSH_SendPacket(ssh);

    return ret;
}


int SendServiceRequest(WOLFSSH* ssh, byte serviceId)
{
    const char* serviceName;
    word32 serviceNameSz;
    byte* output;
    word32 idx;
    int ret = WS_SUCCESS;

    WLOG(WS_LOG_DEBUG, "Entering SendServiceRequest()");

    if (ssh == NULL)
        ret = WS_BAD_ARGUMENT;

    if (ret == WS_SUCCESS) {
        serviceName = IdToName(serviceId);
        serviceNameSz = (word32)WSTRLEN(serviceName);

        ret = PreparePacket(ssh,
                            MSG_ID_SZ + LENGTH_SZ + serviceNameSz);
    }

    if (ret == WS_SUCCESS) {
        output = ssh->outputBuffer.buffer;
        idx = ssh->outputBuffer.length;

        output[idx++] = MSGID_SERVICE_REQUEST;
        c32toa(serviceNameSz, output + idx);
        idx += LENGTH_SZ;
        WMEMCPY(output + idx, serviceName, serviceNameSz);
        idx += serviceNameSz;

        ssh->outputBuffer.length = idx;
        ret = BundlePacket(ssh);
    }

    if (ret == WS_SUCCESS)
        ret = wolfSSH_SendPacket(ssh);

    WLOG(WS_LOG_DEBUG, "Leaving SendServiceRequest(), ret = %d", ret);
    return ret;
}


int SendServiceAccept(WOLFSSH* ssh, byte serviceId)
{
    const char* serviceName;
    word32 serviceNameSz;
    byte* output;
    word32 idx;
    int ret = WS_SUCCESS;

    if (ssh == NULL)
        ret = WS_BAD_ARGUMENT;

    if (ret == WS_SUCCESS) {
        serviceName = IdToName(serviceId);
        serviceNameSz = (word32)WSTRLEN(serviceName);
        ret = PreparePacket(ssh, MSG_ID_SZ + LENGTH_SZ + serviceNameSz);
    }

    if (ret == WS_SUCCESS) {
        output = ssh->outputBuffer.buffer;
        idx = ssh->outputBuffer.length;

        output[idx++] = MSGID_SERVICE_ACCEPT;
        c32toa(serviceNameSz, output + idx);
        idx += LENGTH_SZ;
        WMEMCPY(output + idx, serviceName, serviceNameSz);
        idx += serviceNameSz;

        ssh->outputBuffer.length = idx;

        ret = BundlePacket(ssh);
    }

    if (ret == WS_SUCCESS)
        ret = SendUserAuthBanner(ssh);

    return ret;
}


#define WS_EXTINFO_EXTENSION_COUNT 1
static const char serverSigAlgsName[] = "server-sig-algs";


int SendExtInfo(WOLFSSH* ssh)
{
    byte* output;
    word32 idx;
    word32 keyAlgoNamesSz = 0;
    word32 serverSigAlgsNameSz = 0;
    int ret = WS_SUCCESS;

    WLOG(WS_LOG_DEBUG, "Entering SendExtInfo()");

    if (ssh == NULL) {
        ret = WS_BAD_ARGUMENT;
    }

    if (ret == WS_SUCCESS) {
        keyAlgoNamesSz = AlgoListSz(ssh->algoListKeyAccepted);
        serverSigAlgsNameSz = AlgoListSz(serverSigAlgsName);
        ret = PreparePacket(ssh, MSG_ID_SZ + UINT32_SZ + (LENGTH_SZ * 2)
                + serverSigAlgsNameSz + keyAlgoNamesSz);
    }

    if (ret == WS_SUCCESS) {
        output = ssh->outputBuffer.buffer;
        idx = ssh->outputBuffer.length;

        output[idx++] = MSGID_EXT_INFO;
        c32toa(WS_EXTINFO_EXTENSION_COUNT, output + idx);
        idx += UINT32_SZ;

        c32toa(serverSigAlgsNameSz, output + idx);
        idx += LENGTH_SZ;
        WMEMCPY(output + idx, serverSigAlgsName, serverSigAlgsNameSz);
        idx += serverSigAlgsNameSz;

        c32toa(keyAlgoNamesSz, output + idx);
        idx += LENGTH_SZ;
        WMEMCPY(output + idx, ssh->algoListKeyAccepted, keyAlgoNamesSz);
        idx += keyAlgoNamesSz;

        ssh->outputBuffer.length = idx;

        ret = BundlePacket(ssh);
    }

    if (ret == WS_SUCCESS) {
        ret = wolfSSH_SendPacket(ssh);
    }

    WLOG(WS_LOG_DEBUG, "Leaving SendExtInfo(), ret = %d", ret);
    return ret;
}


/* Updates the payload size, and maybe loads keys. */
static int PrepareUserAuthRequestPassword(WOLFSSH* ssh, word32* payloadSz,
        const WS_UserAuthData* authData)
{
    int ret = WS_SUCCESS;

    if (ssh == NULL || payloadSz == NULL || authData == NULL)
        ret = WS_BAD_ARGUMENT;

    if (ret == WS_SUCCESS)
        *payloadSz += BOOLEAN_SZ + LENGTH_SZ +
                authData->sf.password.passwordSz;

    return ret;
}


static int BuildUserAuthRequestPassword(WOLFSSH* ssh,
        byte* output, word32* idx,
        const WS_UserAuthData* authData)
{
    int ret = WS_SUCCESS;
    word32 begin;

    if (ssh == NULL || output == NULL || idx == NULL || authData == NULL)
        ret = WS_BAD_ARGUMENT;

    if (ret == WS_SUCCESS) {
        begin = *idx;
        output[begin++] = 0; /* Boolean "FALSE" for password change */
        c32toa(authData->sf.password.passwordSz, output + begin);
        begin += LENGTH_SZ;
        WMEMCPY(output + begin, authData->sf.password.password,
                authData->sf.password.passwordSz);
        begin += authData->sf.password.passwordSz;
        *idx = begin;
    }

    return ret;
}


#ifndef WOLFSSH_NO_RSA
static int PrepareUserAuthRequestRsa(WOLFSSH* ssh, word32* payloadSz,
        const WS_UserAuthData* authData, WS_KeySignature* keySig)
{
    int ret = WS_SUCCESS;

    if (ssh == NULL || payloadSz == NULL || authData == NULL || keySig == NULL)
        ret = WS_BAD_ARGUMENT;

    if (ret == WS_SUCCESS)
        ret = wc_InitRsaKey(&keySig->ks.rsa.key, NULL);

    if (ret == WS_SUCCESS) {
        word32 idx = 0;
        #ifdef WOLFSSH_AGENT
        if (ssh->agentEnabled) {
            ret = wc_RsaPublicKeyDecode(authData->sf.publicKey.publicKey,
                    &idx, &keySig->ks.rsa.key,
                    authData->sf.publicKey.publicKeySz);
        }
        else
        #endif
        {
            ret = wc_RsaPrivateKeyDecode(authData->sf.publicKey.privateKey,
                    &idx, &keySig->ks.rsa.key,
                    authData->sf.publicKey.privateKeySz);
            if (ret != 0) {
                idx = 0;
                ret = GetOpenSshKey(keySig,
                        authData->sf.publicKey.privateKey,
                        authData->sf.publicKey.privateKeySz, &idx);
            }
        }
    }

    if (ret == WS_SUCCESS) {
        if (authData->sf.publicKey.hasSignature) {
            int sigSz = wc_RsaEncryptSize(&keySig->ks.rsa.key);

            if (sigSz >= 0) {
                *payloadSz += (LENGTH_SZ * 3) + (word32)sigSz +
                        authData->sf.publicKey.publicKeyTypeSz;
                keySig->sigSz = sigSz;
            }
            else
                ret = sigSz;
        }
    }

    return ret;
}


static int BuildUserAuthRequestRsa(WOLFSSH* ssh,
        byte* output, word32* idx,
        const WS_UserAuthData* authData,
        const byte* sigStart, word32 sigStartIdx,
        WS_KeySignature* keySig)
{
    wc_HashAlg hash;
    byte digest[WC_MAX_DIGEST_SIZE];
    word32 digestSz = 0;
    word32 begin;
    enum wc_HashType hashId = WC_HASH_TYPE_SHA;
    int ret = WS_SUCCESS;
    byte* checkData = NULL;
    word32 checkDataSz = 0;

    if (ssh == NULL || output == NULL || idx == NULL || authData == NULL ||
            sigStart == NULL || keySig == NULL) {
        ret = WS_BAD_ARGUMENT;
        return ret;
    }

    begin = *idx;

    if (ret == WS_SUCCESS) {
        hashId = HashForId(keySig->keySigId);
        if (hashId == WC_HASH_TYPE_NONE)
            ret = WS_INVALID_ALGO_ID;
    }
    if (ret == WS_SUCCESS) {
        int checkSz = wc_HashGetDigestSize(hashId);
        if (checkSz > 0)
            digestSz = (word32)checkSz;
        else
            ret = WS_INVALID_ALGO_ID;
    }
    if (ret == WS_SUCCESS) {
        checkDataSz = LENGTH_SZ + ssh->sessionIdSz + (begin - sigStartIdx);
        checkData = (byte*)WMALLOC(checkDataSz, ssh->ctx->heap, DYNTYPE_TEMP);
        if (checkData == NULL)
            ret = WS_MEMORY_E;
    }

    if (ret == WS_SUCCESS) {
        word32 i = 0;

        c32toa(ssh->sessionIdSz, checkData + i);
        i += LENGTH_SZ;
        WMEMCPY(checkData + i, ssh->sessionId, ssh->sessionIdSz);
        i += ssh->sessionIdSz;
        WMEMCPY(checkData + i, sigStart, begin - sigStartIdx);
    }

    #ifdef WOLFSSH_AGENT
    if (ssh->agentEnabled) {
        if (ret == WS_SUCCESS)
            ret = wolfSSH_AGENT_SignRequest(ssh, checkData, checkDataSz,
                    output + begin + LENGTH_SZ, &keySig->sigSz,
                    authData->sf.publicKey.publicKey,
                    authData->sf.publicKey.publicKeySz, 0);
        if (ret == WS_SUCCESS) {
            c32toa(keySig->sigSz, output + begin);
            begin += LENGTH_SZ + keySig->sigSz;
        }
    }
    else
    #endif
    {
        if (ret == WS_SUCCESS) {
            WMEMSET(digest, 0, sizeof(digest));
            ret = wc_HashInit(&hash, hashId);
            if (ret == WS_SUCCESS)
                ret = HashUpdate(&hash, hashId, checkData, checkDataSz);
            if (ret == WS_SUCCESS)
                ret = wc_HashFinal(&hash, hashId, digest);
        }

        if (ret == WS_SUCCESS) {
            const char* names;
            word32 namesSz;
            byte encDigest[MAX_ENCODED_SIG_SZ];
            int encDigestSz;

            switch (keySig->keySigId) {
                #ifndef WOLFSSH_NO_SSH_RSA_SHA1
                case ID_SSH_RSA:
                    names = cannedKeyAlgoSshRsaNames;
                    break;
                #endif
                #ifndef WOLFSSH_NO_RSA_SHA2_256
                case ID_RSA_SHA2_256:
                    names = cannedKeyAlgoRsaSha2_256Names;
                    break;
                #endif
                #ifndef WOLFSSH_NO_RSA_SHA2_512
                case ID_RSA_SHA2_512:
                    names = cannedKeyAlgoRsaSha2_512Names;
                    break;
                #endif
                default:
                    WLOG(WS_LOG_DEBUG, "SUAR: RSA invalid algo");
                    ret = WS_INVALID_ALGO_ID;
            }

            if (ret == WS_SUCCESS) {
                namesSz = (word32)WSTRLEN(names);
                c32toa(keySig->sigSz + namesSz + LENGTH_SZ * 2, output + begin);
                begin += LENGTH_SZ;
                c32toa(namesSz, output + begin);
                begin += LENGTH_SZ;

                WMEMCPY(output + begin, names, namesSz);
                begin += namesSz;
                c32toa(keySig->sigSz, output + begin);
                begin += LENGTH_SZ;
                encDigestSz = wc_EncodeSignature(encDigest, digest, digestSz,
                        wc_HashGetOID(hashId));
                if (encDigestSz <= 0) {
                    WLOG(WS_LOG_DEBUG, "SUAR: Bad Encode Sig");
                    ret = WS_CRYPTO_FAILED;
                }
                else {
                    int sigSz;
                    WLOG(WS_LOG_INFO, "Signing hash with RSA.");
                    sigSz = wc_RsaSSL_Sign(encDigest, encDigestSz,
                            output + begin, keySig->sigSz,
                            &keySig->ks.rsa.key, ssh->rng);
                    if (sigSz <= 0 || (word32)sigSz != keySig->sigSz) {
                        WLOG(WS_LOG_DEBUG, "SUAR: Bad RSA Sign");
                        ret = WS_RSA_E;
                    }
                    else {
                        ret = wolfSSH_RsaVerify(output + begin, keySig->sigSz,
                                encDigest, encDigestSz, &keySig->ks.rsa.key,
                                ssh->ctx->heap, "SUAR");
                    }
                }
            }

            if (ret == WS_SUCCESS)
                begin += keySig->sigSz;
        }
    }

    if (ret == WS_SUCCESS)
        *idx = begin;

    if (checkData != NULL) {
        ForceZero(checkData, checkDataSz);
        WFREE(checkData, ssh->ctx->heap, DYNTYPE_TEMP);
    }

    return ret;
}


#ifdef WOLFSSH_CERTS
static int PrepareUserAuthRequestRsaCert(WOLFSSH* ssh, word32* payloadSz,
        const WS_UserAuthData* authData, WS_KeySignature* keySig)
{
    int ret = WS_SUCCESS;

    WLOG(WS_LOG_DEBUG, "Entering PrepareUserAuthRequestRsaCert()");
    if (ssh == NULL || payloadSz == NULL || authData == NULL || keySig == NULL)
        ret = WS_BAD_ARGUMENT;

    if (ret == WS_SUCCESS)
        ret = wc_InitRsaKey(&keySig->ks.rsa.key, NULL);

    if (ret == WS_SUCCESS) {
        word32 idx = 0;
        #ifdef WOLFSSH_AGENT
        if (ssh->agentEnabled)
            ret = wc_RsaPublicKeyDecode(authData->sf.publicKey.publicKey,
                    &idx, &keySig->ks.rsa.key,
                    authData->sf.publicKey.publicKeySz);
        else
        #endif /* WOLFSSH_AGENT */
            ret = wc_RsaPrivateKeyDecode(authData->sf.publicKey.privateKey,
                    &idx, &keySig->ks.rsa.key,
                    authData->sf.publicKey.privateKeySz);
    }

    if (ret == WS_SUCCESS) {
        *payloadSz += (LENGTH_SZ + authData->sf.publicKey.publicKeyTypeSz) +
                (UINT32_SZ * 2); /* certificate and ocsp counts */

        if (authData->sf.publicKey.hasSignature) {
            int sigSz = wc_RsaEncryptSize(&keySig->ks.rsa.key);

            if (sigSz >= 0) {
                *payloadSz += (LENGTH_SZ * 3) + (word32)sigSz +
                        authData->sf.publicKey.publicKeyTypeSz;
                keySig->sigSz = sigSz;
            }
            else
                ret = sigSz;
        }
    }

    WLOG(WS_LOG_DEBUG, "Leaving PrepareUserAuthRequestRsaCert(), ret = %d",
            ret);
    return ret;
}


static int BuildUserAuthRequestRsaCert(WOLFSSH* ssh,
        byte* output, word32* idx,
        const WS_UserAuthData* authData,
        const byte* sigStart, word32 sigStartIdx,
        WS_KeySignature* keySig)
{
    wc_HashAlg hash;
    byte digest[WC_MAX_DIGEST_SIZE];
    word32 digestSz = 0;
    word32 begin;
    enum wc_HashType hashId = WC_HASH_TYPE_SHA;
    int ret = WS_SUCCESS;
    byte* checkData = NULL;
    word32 checkDataSz = 0;

    WLOG(WS_LOG_DEBUG, "Entering BuildUserAuthRequestRsaCert()");
    if (ssh == NULL || output == NULL || idx == NULL || authData == NULL ||
            sigStart == NULL || keySig == NULL) {
        ret = WS_BAD_ARGUMENT;
    }

    if (ret == WS_SUCCESS) {
        begin = *idx;
        hashId = HashForId(keySig->keySigId);
        if (hashId == WC_HASH_TYPE_NONE)
            ret = WS_INVALID_ALGO_ID;
        WLOG(WS_LOG_DEBUG, "HashForId = %d, ret = %d", hashId, ret);
    }
    if (ret == WS_SUCCESS) {
        int checkSz = wc_HashGetDigestSize(hashId);
        if (checkSz > 0)
            digestSz = (word32)checkSz;
        else
            ret = WS_INVALID_ALGO_ID;
        WLOG(WS_LOG_DEBUG, "HashGetDigestSz = %d, ret = %d", checkSz, ret);
    }
    if (ret == WS_SUCCESS) {
        checkDataSz = LENGTH_SZ + ssh->sessionIdSz + (begin - sigStartIdx);
        checkData = (byte*)WMALLOC(checkDataSz, ssh->ctx->heap, DYNTYPE_TEMP);
        if (checkData == NULL)
            ret = WS_MEMORY_E;
    }

    if (ret == WS_SUCCESS) {
        word32 i = 0;

        c32toa(ssh->sessionIdSz, checkData + i);
        i += LENGTH_SZ;
        WMEMCPY(checkData + i, ssh->sessionId, ssh->sessionIdSz);
        i += ssh->sessionIdSz;
        WMEMCPY(checkData + i, sigStart, begin - sigStartIdx);
    }

    if (ret == WS_SUCCESS) {
        #ifdef WOLFSSH_AGENT
        if (ssh->agentEnabled) {
            if (ret == WS_SUCCESS)
                ret = wolfSSH_AGENT_SignRequest(ssh, checkData, checkDataSz,
                        output + begin + LENGTH_SZ, &keySig->sigSz,
                        authData->sf.publicKey.publicKey,
                        authData->sf.publicKey.publicKeySz, 0);
            if (ret == WS_SUCCESS) {
                c32toa(keySig->sigSz, output + begin);
                begin += LENGTH_SZ + keySig->sigSz;
            }
        }
        else
        #endif /* WOLFSSH_AGENT */
        {
            byte encDigest[MAX_ENCODED_SIG_SZ];
            int encDigestSz;

            WMEMSET(digest, 0, sizeof(digest));
            ret = wc_HashInit(&hash, hashId);
            if (ret == WS_SUCCESS)
                ret = HashUpdate(&hash, hashId, checkData, checkDataSz);
            if (ret == WS_SUCCESS)
                ret = wc_HashFinal(&hash, hashId, digest);

            if (ret == WS_SUCCESS) {
                c32toa(keySig->sigSz + 7 + LENGTH_SZ * 2, output + begin);
                begin += LENGTH_SZ;
                c32toa(7, output + begin);
                begin += LENGTH_SZ;
                WMEMCPY(output + begin, "ssh-rsa", 7);
                begin += 7;
                c32toa(keySig->sigSz, output + begin);
                begin += LENGTH_SZ;
                encDigestSz = wc_EncodeSignature(encDigest, digest, digestSz,
                        wc_HashGetOID(hashId));
                if (encDigestSz <= 0) {
                    WLOG(WS_LOG_DEBUG, "SUAR: Bad Encode Sig");
                    ret = WS_CRYPTO_FAILED;
                }
            }
            if (ret == WS_SUCCESS) {
                int sigSz;
                WLOG(WS_LOG_INFO, "Signing hash with RSA.");
                sigSz = wc_RsaSSL_Sign(encDigest, encDigestSz,
                        output + begin, keySig->sigSz,
                        &keySig->ks.rsa.key, ssh->rng);
                if (sigSz <= 0 || (word32)sigSz != keySig->sigSz) {
                    WLOG(WS_LOG_DEBUG, "SUAR: Bad RSA Sign");
                    ret = WS_RSA_E;
                }
                else {
                    ret = wolfSSH_RsaVerify(output + begin, keySig->sigSz,
                            encDigest, encDigestSz, &keySig->ks.rsa.key,
                            ssh->ctx->heap, "SUAR");
                }
            }

            if (ret == WS_SUCCESS)
                begin += keySig->sigSz;
        }
    }

    if (ret == WS_SUCCESS)
        *idx = begin;

    if (checkData != NULL) {
        ForceZero(checkData, checkDataSz);
        WFREE(checkData, ssh->ctx->heap, DYNTYPE_TEMP);
    }

    WLOG(WS_LOG_DEBUG, "Leaving BuildUserAuthRequestRsaCert(), ret = %d",
            ret);
    return ret;
}
#endif /* WOLFSSH_CERTS */
#endif /* ! WOLFSSH_NO_RSA */


#ifndef WOLFSSH_NO_ECDSA
static int PrepareUserAuthRequestEcc(WOLFSSH* ssh, word32* payloadSz,
        const WS_UserAuthData* authData, WS_KeySignature* keySig)
{
    int ret = WS_SUCCESS;

    WLOG(WS_LOG_DEBUG, "Entering PrepareUserAuthRequestEcc()");
    if (ssh == NULL || payloadSz == NULL || authData == NULL || keySig == NULL)
        ret = WS_BAD_ARGUMENT;

    if (ret == WS_SUCCESS)
        ret = wc_ecc_init(&keySig->ks.ecc.key);

    if (ret == 0) {
        word32 idx = 0;
        #ifdef WOLFSSH_AGENT
        if (ssh->agentEnabled) {
            word32 sz;
            const byte* c = (const byte*)authData->sf.publicKey.publicKey;

            ato32(c + idx, &sz);
            idx += LENGTH_SZ + sz;
            ato32(c + idx, &sz);
            idx += LENGTH_SZ + sz;
            ato32(c + idx, &sz);
            idx += LENGTH_SZ;
            c += idx;
            idx = 0;

            ret = wc_ecc_import_x963(c, sz, &keySig->ks.ecc.key);
        }
        else
        #endif
        {
            ret = wc_EccPrivateKeyDecode(authData->sf.publicKey.privateKey,
                    &idx, &keySig->ks.ecc.key,
                    authData->sf.publicKey.privateKeySz);
            if (ret != 0) {
                idx = 0;
                ret = GetOpenSshKey(keySig,
                        authData->sf.publicKey.privateKey,
                        authData->sf.publicKey.privateKeySz, &idx);
            }
        }
    }

    if (ret == WS_SUCCESS) {
        if (authData->sf.publicKey.hasSignature) {
            int sigSz = wc_ecc_sig_size(&keySig->ks.ecc.key);

            if (sigSz >= 0) {
                *payloadSz += (LENGTH_SZ * 5) + (word32)sigSz +
                        authData->sf.publicKey.publicKeyTypeSz;
                keySig->sigSz = sigSz;
            }
            else
                ret = sigSz;
        }
    }

    WLOG(WS_LOG_DEBUG, "Leaving PrepareUserAuthRequestEcc(), ret = %d", ret);
    return ret;
}


static int BuildUserAuthRequestEcc(WOLFSSH* ssh,
        byte* output, word32* idx,
        const WS_UserAuthData* authData,
        const byte* sigStart, word32 sigStartIdx,
        WS_KeySignature* keySig)
{
    wc_HashAlg hash;
    byte digest[WC_MAX_DIGEST_SIZE];
    word32 digestSz;
    word32 begin;
    enum wc_HashType hashId = WC_HASH_TYPE_SHA;
    int ret = WS_SUCCESS;
    byte* r_ptr;
    byte* s_ptr;
    byte* sig_ptr;
    word32 rSz = ECC_MAX_SIG_SIZE / 2;
    word32 sSz = ECC_MAX_SIG_SIZE / 2;
    word32 sigSz = ECC_MAX_SIG_SIZE;
    byte* checkData = NULL;
    word32 checkDataSz = 0;

#ifdef WOLFSSH_SMALL_STACK
    r_ptr = (byte*)WMALLOC(rSz, ssh->ctx->heap, DYNTYPE_BUFFER);
    s_ptr = (byte*)WMALLOC(sSz, ssh->ctx->heap, DYNTYPE_BUFFER);
    sig_ptr = (byte*)WMALLOC(sigSz, ssh->ctx->heap, DYNTYPE_BUFFER);
    if (r_ptr == NULL || s_ptr == NULL || sig_ptr == NULL)
        ret = WS_MEMORY_E;
#else
    byte r_s[ECC_MAX_SIG_SIZE / 2];
    byte s_s[ECC_MAX_SIG_SIZE / 2];
    byte sig_s[ECC_MAX_SIG_SIZE];
    r_ptr = r_s;
    s_ptr = s_s;
    sig_ptr = sig_s;
#endif

    if (ssh == NULL || output == NULL || idx == NULL || authData == NULL ||
            sigStart == NULL || keySig == NULL) {
        ret = WS_BAD_ARGUMENT;
        return ret;
    }

    begin = *idx;

    if (ret == WS_SUCCESS) {
        hashId = HashForId(keySig->keySigId);
        WMEMSET(digest, 0, sizeof(digest));
        digestSz = wc_HashGetDigestSize(hashId);
        checkDataSz = LENGTH_SZ + ssh->sessionIdSz + (begin - sigStartIdx);
        checkData = (byte*)WMALLOC(checkDataSz, ssh->ctx->heap, DYNTYPE_TEMP);
        if (checkData == NULL)
            ret = WS_MEMORY_E;
    }

    if (ret == WS_SUCCESS) {
        word32 i = 0;

        c32toa(ssh->sessionIdSz, checkData + i);
        i += LENGTH_SZ;
        WMEMCPY(checkData + i, ssh->sessionId, ssh->sessionIdSz);
        i += ssh->sessionIdSz;
        WMEMCPY(checkData + i, sigStart, begin - sigStartIdx);
    }

    #ifdef WOLFSSH_AGENT
    if (ssh->agentEnabled) {
        if (ret == WS_SUCCESS)
            ret = wolfSSH_AGENT_SignRequest(ssh, checkData, checkDataSz,
                    sig_ptr, &sigSz,
                    authData->sf.publicKey.publicKey,
                    authData->sf.publicKey.publicKeySz, 0);
        if (ret == WS_SUCCESS) {
            c32toa(sigSz, output + begin);
            begin += LENGTH_SZ;
            XMEMCPY(output + begin, sig_ptr, sigSz);
            begin += sigSz;
        }
    }
    else
    #endif
    {
        if (ret == WS_SUCCESS) {
            WLOG(WS_LOG_INFO, "Signing hash with ECDSA.");
            ret = wc_HashInit(&hash, hashId);
            if (ret == WS_SUCCESS)
                ret = HashUpdate(&hash, hashId, checkData, checkDataSz);
            if (ret == WS_SUCCESS)
                ret = wc_HashFinal(&hash, hashId, digest);
            if (ret == WS_SUCCESS)
                ret = wc_ecc_sign_hash(digest, digestSz, sig_ptr, &sigSz,
                        ssh->rng, &keySig->ks.ecc.key);
            if (ret != WS_SUCCESS) {
                WLOG(WS_LOG_DEBUG, "SUAR: Bad ECC Sign");
                ret = WS_ECC_E;
            }
        }

        if (ret == WS_SUCCESS) {
            ret = wc_ecc_sig_to_rs(sig_ptr, sigSz, r_ptr, &rSz, s_ptr, &sSz);
        }

        if (ret == WS_SUCCESS) {
            const char* names;
            word32 namesSz;
            byte rPad;
            byte sPad;

            /* adds a byte of padding if needed to avoid negative values */
            rPad = (r_ptr[0] & 0x80) ? 1 : 0;
            sPad = (s_ptr[0] & 0x80) ? 1 : 0;

            switch (keySig->keySigId) {
                #ifndef WOLFSSH_NO_ECDSA_SHA2_NISTP256
                case ID_ECDSA_SHA2_NISTP256:
                    names = cannedKeyAlgoEcc256Names;
                    break;
                #endif
                #ifndef WOLFSSH_NO_ECDSA_SHA2_NISTP384
                case ID_ECDSA_SHA2_NISTP384:
                    names = cannedKeyAlgoEcc384Names;
                    break;
                #endif
                #ifndef WOLFSSH_NO_ECDSA_SHA2_NISTP521
                case ID_ECDSA_SHA2_NISTP521:
                    names = cannedKeyAlgoEcc521Names;
                    break;
                #endif
                default:
                    WLOG(WS_LOG_DEBUG, "SUAR: ECDSA invalid algo");
                    ret = WS_INVALID_ALGO_ID;
            }

            if (ret == WS_SUCCESS) {
                namesSz = (word32)WSTRLEN(names);

                c32toa(rSz + rPad + sSz + sPad + namesSz + LENGTH_SZ * 4,
                        output + begin);
                begin += LENGTH_SZ;

                c32toa(namesSz, output + begin);
                begin += LENGTH_SZ;

                WMEMCPY(output + begin, names, namesSz);
                begin += namesSz;

                c32toa(rSz + rPad + sSz + sPad + LENGTH_SZ * 2, output + begin);
                begin += LENGTH_SZ;

                c32toa(rSz + rPad, output + begin);
                begin += LENGTH_SZ;

                if (rPad)
                    output[begin++] = 0;

                WMEMCPY(output + begin, r_ptr, rSz);
                begin += rSz;

                c32toa(sSz + sPad, output + begin);
                begin += LENGTH_SZ;

                if (sPad)
                    output[begin++] = 0;

                WMEMCPY(output + begin, s_ptr, sSz);
                begin += sSz;
            }
        }
    }

    if (ret == WS_SUCCESS)
        *idx = begin;

    if (checkData != NULL) {
        ForceZero(checkData, checkDataSz);
        WFREE(checkData, ssh->ctx->heap, DYNTYPE_TEMP);
    }

#ifdef WOLFSSH_SMALL_STACK
    if (r_ptr)
        WFREE(r_ptr, ssh->ctx->heap, DYNTYPE_BUFFER);
    if (s_ptr)
        WFREE(s_ptr, ssh->ctx->heap, DYNTYPE_BUFFER);
    if (sig_ptr)
        WFREE(sig_ptr, ssh->ctx->heap, DYNTYPE_BUFFER);
#endif
    return ret;
}


#ifdef WOLFSSH_CERTS

static int PrepareUserAuthRequestEccCert(WOLFSSH* ssh, word32* payloadSz,
        const WS_UserAuthData* authData, WS_KeySignature* keySig)
{
    int ret = WS_SUCCESS;

    WLOG(WS_LOG_DEBUG, "Entering PrepareUserAuthRequestEccCert()");
    if (ssh == NULL || payloadSz == NULL || authData == NULL || keySig == NULL)
        ret = WS_BAD_ARGUMENT;

    if (ret == WS_SUCCESS)
        ret = wc_ecc_init(&keySig->ks.ecc.key);

    if (ret == WS_SUCCESS) {
        word32 idx = 0;
        #if 0
        #ifdef WOLFSSH_AGENT
        if (ssh->agentEnabled) {
            word32 sz;
            const byte* c = (const byte*)authData->sf.publicKey.publicKey;

            ato32(c + idx, &sz);
            idx += LENGTH_SZ + sz;
            ato32(c + idx, &sz);
            idx += LENGTH_SZ + sz;
            ato32(c + idx, &sz);
            idx += LENGTH_SZ;
            c += idx;
            idx = 0;

            ret = wc_ecc_import_x963(c, sz, &keySig->ks.ecc.key);
        }
        else
        #endif
        #endif
            ret = wc_EccPrivateKeyDecode(authData->sf.publicKey.privateKey,
                    &idx, &keySig->ks.ecc.key,
                    authData->sf.publicKey.privateKeySz);
    }

    if (ret == WS_SUCCESS) {
        *payloadSz += (LENGTH_SZ + authData->sf.publicKey.publicKeyTypeSz) +
                (UINT32_SZ * 2); /* certificate and ocsp counts */

        if (authData->sf.publicKey.hasSignature) {
            int sigSz = wc_ecc_sig_size(&keySig->ks.ecc.key);

            if (sigSz >= 0) {
                /* 5 lengths: sig(R), sig(S), sig, sig-type, sig-blob */
                *payloadSz += (LENGTH_SZ * 5) + (word32)sigSz +
                        authData->sf.publicKey.publicKeyTypeSz;
                keySig->sigSz = sigSz;
            }
            else
                ret = sigSz;
        }
    }

    WLOG(WS_LOG_DEBUG, "Leaving PrepareUserAuthRequestEccCert(), ret = %d",
            ret);
    return ret;
}


static int BuildUserAuthRequestEccCert(WOLFSSH* ssh,
        byte* output, word32* idx,
        const WS_UserAuthData* authData,
        const byte* sigStart, word32 sigStartIdx,
        WS_KeySignature* keySig)
{
    wc_HashAlg hash;
    byte digest[WC_MAX_DIGEST_SIZE];
    word32 digestSz;
    word32 begin;
    enum wc_HashType hashId = WC_HASH_TYPE_SHA;
    int ret = WS_SUCCESS;
    byte* r;
    byte* s;
    byte sig[139]; /* wc_ecc_sig_size() for a prime521 key. */
    byte rs[139];  /* wc_ecc_sig_size() for a prime521 key. */
    word32 sigSz = (word32)sizeof(sig), rSz, sSz;
    byte* checkData = NULL;
    word32 checkDataSz = 0;

    if (ssh == NULL || output == NULL || idx == NULL || authData == NULL ||
            sigStart == NULL || keySig == NULL) {
        ret = WS_BAD_ARGUMENT;
        return ret;
    }

    begin = *idx;

    if (ret == WS_SUCCESS) {
        hashId = HashForId(keySig->keySigId);
        WMEMSET(digest, 0, sizeof(digest));
        digestSz = wc_HashGetDigestSize(hashId);
        checkDataSz = LENGTH_SZ + ssh->sessionIdSz + (begin - sigStartIdx);
        checkData = (byte*)WMALLOC(checkDataSz, ssh->ctx->heap, DYNTYPE_TEMP);
        if (checkData == NULL)
            ret = WS_MEMORY_E;
    }

    if (ret == WS_SUCCESS) {
        word32 i = 0;

        c32toa(ssh->sessionIdSz, checkData + i);
        i += LENGTH_SZ;
        WMEMCPY(checkData + i, ssh->sessionId, ssh->sessionIdSz);
        i += ssh->sessionIdSz;
        WMEMCPY(checkData + i, sigStart, begin - sigStartIdx);
    }

    #if 0
    #ifdef WOLFSSH_AGENT
    if (ssh->agentEnabled) {
        if (ret == WS_SUCCESS)
            ret = wolfSSH_AGENT_SignRequest(ssh, checkData, checkDataSz,
                    sig, &sigSz,
                    authData->sf.publicKey.publicKey,
                    authData->sf.publicKey.publicKeySz, 0);
        if (ret == WS_SUCCESS) {
            c32toa(sigSz, output + begin);
            begin += LENGTH_SZ;
            XMEMCPY(output + begin, sig, sigSz);
            begin += sigSz;
        }
    }
    else
    #endif
    #endif
    {
        if (ret == WS_SUCCESS) {
            WLOG(WS_LOG_INFO, "Signing hash with ECDSA cert.");
            ret = wc_HashInit(&hash, hashId);
            if (ret == WS_SUCCESS)
                ret = HashUpdate(&hash, hashId, checkData, checkDataSz);
            if (ret == WS_SUCCESS)
                ret = wc_HashFinal(&hash, hashId, digest);
            if (ret == WS_SUCCESS)
                ret = wc_ecc_sign_hash(digest, digestSz, sig, &sigSz,
                        ssh->rng, &keySig->ks.ecc.key);
            if (ret != WS_SUCCESS) {
                WLOG(WS_LOG_DEBUG, "SUAR: Bad ECC Cert Sign");
                ret = WS_ECC_E;
            }
        }

        if (ret == WS_SUCCESS) {
            rSz = sSz = (word32)sizeof(rs) / 2;
            r = rs;
            s = rs + rSz;
            ret = wc_ecc_sig_to_rs(sig, sigSz, r, &rSz, s, &sSz);
        }

        if (ret == WS_SUCCESS) {
            const char* names;
            word32 namesSz;
            byte rPad;
            byte sPad;

            /* adds a byte of padding if needed to avoid negative values */
            rPad = (r[0] & 0x80) ? 1 : 0;
            sPad = (s[0] & 0x80) ? 1 : 0;

            switch (keySig->keySigId) {
                #ifndef WOLFSSH_NO_ECDSA_SHA2_NISTP256
                case ID_ECDSA_SHA2_NISTP256:
                    names = cannedKeyAlgoEcc256Names;
                    break;
                #endif
                #ifndef WOLFSSH_NO_ECDSA_SHA2_NISTP384
                case ID_ECDSA_SHA2_NISTP384:
                    names = cannedKeyAlgoEcc384Names;
                    break;
                #endif
                #ifndef WOLFSSH_NO_ECDSA_SHA2_NISTP521
                case ID_ECDSA_SHA2_NISTP521:
                    names = cannedKeyAlgoEcc521Names;
                    break;
                #endif
                #ifndef WOLFSSH_NO_ECDSA_SHA2_NISTP256
                case ID_X509V3_ECDSA_SHA2_NISTP256:
                    names = cannedKeyAlgoX509Ecc256Names;
                    break;
                #endif
                #ifndef WOLFSSH_NO_ECDSA_SHA2_NISTP384
                case ID_X509V3_ECDSA_SHA2_NISTP384:
                    names = cannedKeyAlgoX509Ecc384Names;
                    break;
                #endif
                #ifndef WOLFSSH_NO_ECDSA_SHA2_NISTP521
                case ID_X509V3_ECDSA_SHA2_NISTP521:
                    names = cannedKeyAlgoX509Ecc521Names;
                    break;
                #endif
                default:
                    WLOG(WS_LOG_DEBUG, "SUAR: ECDSA cert invalid algo");
                    ret = WS_INVALID_ALGO_ID;
            }

            if (ret == WS_SUCCESS) {
                namesSz = (word32)WSTRLEN(names);

                c32toa(rSz + rPad + sSz + sPad + namesSz+ LENGTH_SZ * 4,
                        output + begin);
                begin += LENGTH_SZ;

                c32toa(namesSz, output + begin);
                begin += LENGTH_SZ;

                WMEMCPY(output + begin, names, namesSz);
                begin += namesSz;

                c32toa(rSz + rPad + sSz + sPad + LENGTH_SZ * 2, output + begin);
                begin += LENGTH_SZ;

                c32toa(rSz + rPad, output + begin);
                begin += LENGTH_SZ;

                if (rPad)
                    output[begin++] = 0;

                WMEMCPY(output + begin, r, rSz);
                begin += rSz;

                c32toa(sSz + sPad, output + begin);
                begin += LENGTH_SZ;

                if (sPad)
                    output[begin++] = 0;

                WMEMCPY(output + begin, s, sSz);
                begin += sSz;
            }
        }
    }

    if (ret == WS_SUCCESS)
        *idx = begin;

    if (checkData != NULL) {
        ForceZero(checkData, checkDataSz);
        WFREE(checkData, ssh->ctx->heap, DYNTYPE_TEMP);
    }

    return ret;
}

#endif /* WOLFSSH_CERTS */

#endif /* WOLFSSH_NO_ECDSA */


#ifndef WOLFSSH_NO_ED25519

static int PrepareUserAuthRequestEd25519(WOLFSSH* ssh, word32* payloadSz,
        const WS_UserAuthData* authData, WS_KeySignature* keySig)
{
    int ret = WS_SUCCESS;

    WLOG(WS_LOG_DEBUG, "Entering PrepareUserAuthRequestEd25519()");
    if (ssh == NULL || payloadSz == NULL || authData == NULL || keySig == NULL)
        ret = WS_BAD_ARGUMENT;

    if (ret == WS_SUCCESS)
        ret = wc_ed25519_init_ex(&keySig->ks.ed25519.key,
                keySig->heap, INVALID_DEVID);

    if (ret == 0) {
        word32 idx = 0;
        #ifdef WOLFSSH_AGENT
        if (ssh->agentEnabled) {
            /* XXX: Pending */
        }
        else
        #endif
        {
            ret = GetOpenSshKey(keySig,
                    authData->sf.publicKey.privateKey,
                    authData->sf.publicKey.privateKeySz, &idx);
        }
    }

    if (ret == WS_SUCCESS) {
        if (authData->sf.publicKey.hasSignature) {
            int sigSz = wc_ed25519_sig_size(&keySig->ks.ed25519.key);

            if (sigSz >= 0) {
                *payloadSz += (LENGTH_SZ * 3) + (word32)sigSz +
                        authData->sf.publicKey.publicKeyTypeSz;
                keySig->sigSz = sigSz;
            }
            else
                ret = sigSz;
        }
    }

    WLOG(WS_LOG_DEBUG,
            "Leaving PrepareUserAuthRequestEd25519(), ret = %d", ret);
    return ret;
}


static int BuildUserAuthRequestEd25519(WOLFSSH* ssh,
        byte* output, word32* idx,
        const WS_UserAuthData* authData,
        const byte* sigStart, word32 sigStartIdx,
        WS_KeySignature* keySig)
{
    word32 begin;
    int ret = WS_SUCCESS;
    byte* sig;
    word32 sigSz = ED25519_SIG_SIZE;
    byte* checkData = NULL;
    word32 checkDataSz = 0;
#ifndef WOLFSSH_SMALL_STACK
    byte sig_s[ED25519_SIG_SIZE];
#endif

    WLOG(WS_LOG_DEBUG, "Entering BuildUserAuthRequestEd25519()");
    if (ssh == NULL || output == NULL || idx == NULL || authData == NULL ||
            sigStart == NULL || keySig == NULL) {
        ret = WS_BAD_ARGUMENT;
        return ret;
    }

#ifdef WOLFSSH_SMALL_STACK
    sig = (byte*)WMALLOC(sigSz, keySig->heap, DYNTYPE_BUFFER);
    if (sig == NULL)
        ret = WS_MEMORY_E;
#else
    sig = sig_s;
#endif

    begin = *idx;

    if (ret == WS_SUCCESS) {
        checkDataSz = LENGTH_SZ + ssh->sessionIdSz + (begin - sigStartIdx);
        checkData = (byte*)WMALLOC(checkDataSz, keySig->heap, DYNTYPE_TEMP);
        if (checkData == NULL)
            ret = WS_MEMORY_E;
    }

    if (ret == WS_SUCCESS) {
        word32 i = 0;

        c32toa(ssh->sessionIdSz, checkData + i);
        i += LENGTH_SZ;
        WMEMCPY(checkData + i, ssh->sessionId, ssh->sessionIdSz);
        i += ssh->sessionIdSz;
        WMEMCPY(checkData + i, sigStart, begin - sigStartIdx);
    }

    #ifdef WOLFSSH_AGENT
    if (ssh->agentEnabled) {
        /* XXX: Pending */
    }
    else
    #endif
    {
        if (ret == WS_SUCCESS) {
            WLOG(WS_LOG_INFO, "Signing with Ed25519.");
            ret = wc_ed25519_sign_msg(checkData, checkDataSz,
                    sig, &sigSz, &keySig->ks.ed25519.key);

            if (ret != WS_SUCCESS) {
                WLOG(WS_LOG_DEBUG, "SUAR: Bad ED25519 Sign");
                ret = WS_ED25519_E;
            }
        }

        if (ret == WS_SUCCESS) {
            const char* name = cannedKeyAlgoEd25519Name;
            word32 nameSz = (word32)WSTRLEN(name);

            c32toa(LENGTH_SZ * 2 + nameSz + sigSz, output + begin);
            begin += LENGTH_SZ;

            c32toa(nameSz, output + begin);
            begin += LENGTH_SZ;

            WMEMCPY(output + begin, name, nameSz);
            begin += nameSz;

            c32toa(sigSz, output + begin);
            begin += LENGTH_SZ;

            WMEMCPY(output + begin, sig, sigSz);
            begin += sigSz;
        }
    }

    if (ret == WS_SUCCESS)
        *idx = begin;

    if (checkData != NULL) {
        ForceZero(checkData, checkDataSz);
        WFREE(checkData, keySig->heap, DYNTYPE_TEMP);
    }

#ifdef WOLFSSH_SMALL_STACK
    if (sig)
        WFREE(sig, keySig->heap, DYNTYPE_BUFFER);
#endif

    WLOG(WS_LOG_DEBUG,
            "Leaving BuildUserAuthRequestEd25519(), ret = %d", ret);
    return ret;
}

#endif /* WOLFSSH_NO_ED25519 */


#if !defined(WOLFSSH_NO_RSA) || !defined(WOLFSSH_NO_ECDSA) \
    || !defined(WOLFSSH_NO_ED25519)
static int PrepareUserAuthRequestPublicKey(WOLFSSH* ssh, word32* payloadSz,
        const WS_UserAuthData* authData, WS_KeySignature* keySig)
{
    int ret = WS_SUCCESS;

    WLOG(WS_LOG_DEBUG, "Entering PrepareUserAuthRequestPublicKey()");

    if (ssh == NULL || payloadSz == NULL || authData == NULL || keySig == NULL) {
        ret = WS_BAD_ARGUMENT;
    }

    if (ret == WS_SUCCESS) {
        byte keyId, matchId, algoId[4];
        word32 algoIdSz = 0;

        keyId = NameToId(
                (const char*)authData->sf.publicKey.publicKeyType,
                authData->sf.publicKey.publicKeyTypeSz);
        if (keyId == ID_SSH_RSA) {
        #ifndef WOLFSSH_NO_RSA_SHA2_512
            algoId[algoIdSz++] = ID_RSA_SHA2_512;
        #endif
        #ifndef WOLFSSH_NO_RSA_SHA2_256
            algoId[algoIdSz++] = ID_RSA_SHA2_256;
        #endif
        #if !defined(WOLFSSH_NO_SSH_RSA_SHA1) \
            && defined(WOLFSSH_NO_SHA1_SOFT_DISABLE)
            algoId[algoIdSz++] = ID_SSH_RSA;
        #endif
        }
        else {
            algoId[algoIdSz++] = keyId;
        }

        /* Is that in the peerSigId list? */
        matchId = MatchIdLists(WOLFSSH_ENDPOINT_CLIENT, algoId, algoIdSz,
                ssh->peerSigId, ssh->peerSigIdSz);
        if (matchId == ID_UNKNOWN) {
            ret = WS_MATCH_KEY_ALGO_E;
        }
        keySig->keySigId = matchId;
        keySig->name = IdToName(matchId);
        keySig->nameSz = (word32)WSTRLEN(keySig->name);
    }

    if (ret == WS_SUCCESS) {
        /* Add the boolean size to the payload, and the lengths of
         * the public key algorithm name, and the public key length.
         * For the X509 types, this accounts for ONLY one certificate.*/
        *payloadSz += BOOLEAN_SZ + (LENGTH_SZ * 2) +
            keySig->nameSz + authData->sf.publicKey.publicKeySz;

        switch (keySig->keySigId) {
            #ifndef WOLFSSH_NO_RSA
            case ID_SSH_RSA:
            case ID_RSA_SHA2_256:
            case ID_RSA_SHA2_512:
                ret = PrepareUserAuthRequestRsa(ssh,
                        payloadSz, authData, keySig);
                break;
            #ifdef WOLFSSH_CERTS
            case ID_X509V3_SSH_RSA:
                ret = PrepareUserAuthRequestRsaCert(ssh,
                        payloadSz, authData, keySig);
                break;
            #endif
            #endif
            #ifndef WOLFSSH_NO_ECDSA
            case ID_ECDSA_SHA2_NISTP256:
            case ID_ECDSA_SHA2_NISTP384:
            case ID_ECDSA_SHA2_NISTP521:
                ret = PrepareUserAuthRequestEcc(ssh,
                        payloadSz, authData, keySig);
                break;
            #ifdef WOLFSSH_CERTS
            case ID_X509V3_ECDSA_SHA2_NISTP256:
            case ID_X509V3_ECDSA_SHA2_NISTP384:
            case ID_X509V3_ECDSA_SHA2_NISTP521:
                ret = PrepareUserAuthRequestEccCert(ssh,
                        payloadSz, authData, keySig);
                break;
            #endif
            #endif
            #ifndef WOLFSSH_NO_ED25519
            case ID_ED25519:
                ret = PrepareUserAuthRequestEd25519(ssh,
                        payloadSz, authData, keySig);
                break;
            #endif
            default:
                ret = WS_INVALID_ALGO_ID;
        }
    }

    WLOG(WS_LOG_DEBUG, "Leaving PrepareUserAuthRequestPublicKey(), ret = %d",
            ret);
    return ret;
}


static int BuildUserAuthRequestPublicKey(WOLFSSH* ssh,
        byte* output, word32* idx,
        const WS_UserAuthData* authData,
        const byte* sigStart, word32 sigStartIdx,
        WS_KeySignature* keySig)
{
    const WS_UserAuthData_PublicKey* pk;
    word32 begin;
    int ret = WS_SUCCESS;

    WLOG(WS_LOG_DEBUG, "Entering BuildUserAuthRequestPublicKey()");
    if (ssh == NULL || output == NULL || idx == NULL || authData == NULL ||
            sigStart == NULL || keySig == NULL)
        ret = WS_BAD_ARGUMENT;

    if (ret == WS_SUCCESS) {
        begin = *idx;
        pk = &authData->sf.publicKey;
        output[begin++] = pk->hasSignature;

        if (pk->hasSignature) {
            WLOG(WS_LOG_DEBUG, "User signature type: %s",
                    IdToName(keySig->keySigId));

            switch (keySig->keySigId) {
                #ifndef WOLFSSH_NO_RSA
                case ID_SSH_RSA:
                case ID_RSA_SHA2_256:
                case ID_RSA_SHA2_512:
                    c32toa(keySig->nameSz, output + begin);
                    begin += LENGTH_SZ;
                    WMEMCPY(output + begin, keySig->name, keySig->nameSz);
                    begin += keySig->nameSz;
                    c32toa(pk->publicKeySz, output + begin);
                    begin += LENGTH_SZ;
                    WMEMCPY(output + begin, pk->publicKey, pk->publicKeySz);
                    begin += pk->publicKeySz;
                    keySig->keySigId = ID_RSA_SHA2_256;
                    ret = BuildUserAuthRequestRsa(ssh, output, &begin,
                            authData, sigStart, sigStartIdx, keySig);
                    break;
                #ifdef WOLFSSH_CERTS
                case ID_X509V3_SSH_RSA:
                    /* public key type name */
                    c32toa(pk->publicKeyTypeSz, output + begin);
                    begin += LENGTH_SZ;
                    WMEMCPY(output + begin,
                            pk->publicKeyType, pk->publicKeyTypeSz);
                    begin += pk->publicKeyTypeSz;

                    ret = BuildRFC6187Info(ssh, keySig->keySigId,
                            pk->publicKey, pk->publicKeySz, NULL, 0,
                            output, &ssh->outputBuffer.bufferSz, &begin);
                    if (ret == WS_SUCCESS) {
                        ret = BuildUserAuthRequestRsaCert(ssh, output, &begin,
                            authData, sigStart, sigStartIdx, keySig);
                    }
                    break;
                #endif
                #endif
                #ifndef WOLFSSH_NO_ECDSA
                case ID_ECDSA_SHA2_NISTP256:
                case ID_ECDSA_SHA2_NISTP384:
                case ID_ECDSA_SHA2_NISTP521:
                    c32toa(pk->publicKeyTypeSz, output + begin);
                    begin += LENGTH_SZ;
                    WMEMCPY(output + begin,
                            pk->publicKeyType, pk->publicKeyTypeSz);
                    begin += pk->publicKeyTypeSz;
                    c32toa(pk->publicKeySz, output + begin);
                    begin += LENGTH_SZ;
                    WMEMCPY(output + begin, pk->publicKey, pk->publicKeySz);
                    begin += pk->publicKeySz;
                    ret = BuildUserAuthRequestEcc(ssh, output, &begin,
                            authData, sigStart, sigStartIdx, keySig);
                    break;
                #ifdef WOLFSSH_CERTS
                case ID_X509V3_ECDSA_SHA2_NISTP256:
                case ID_X509V3_ECDSA_SHA2_NISTP384:
                case ID_X509V3_ECDSA_SHA2_NISTP521:
                    /* public key type name */
                    c32toa(pk->publicKeyTypeSz, output + begin);
                    begin += LENGTH_SZ;
                    WMEMCPY(output + begin,
                            pk->publicKeyType, pk->publicKeyTypeSz);
                    begin += pk->publicKeyTypeSz;

                    /* build RFC6178 public key to send */
                    ret = BuildRFC6187Info(ssh, keySig->keySigId,
                            pk->publicKey, pk->publicKeySz, NULL, 0,
                            output, &ssh->outputBuffer.bufferSz, &begin);
                    if (ret == WS_SUCCESS) {
                        ret = BuildUserAuthRequestEccCert(ssh, output, &begin,
                            authData, sigStart, sigStartIdx, keySig);
                    }
                    break;
                #endif
                #endif
                #ifndef WOLFSSH_NO_ED25519
                case ID_ED25519:
                    c32toa(pk->publicKeyTypeSz, output + begin);
                    begin += LENGTH_SZ;
                    WMEMCPY(output + begin,
                            pk->publicKeyType, pk->publicKeyTypeSz);
                    begin += pk->publicKeyTypeSz;
                    c32toa(pk->publicKeySz, output + begin);
                    begin += LENGTH_SZ;
                    WMEMCPY(output + begin, pk->publicKey, pk->publicKeySz);
                    begin += pk->publicKeySz;
                    ret = BuildUserAuthRequestEd25519(ssh, output, &begin,
                        authData, sigStart, sigStartIdx, keySig);
                    break;
                #endif
                default:
                    ret = WS_INVALID_ALGO_ID;
            }
        }
        else {
            ret = WS_INVALID_ALGO_ID;
        }

        if (ret == WS_SUCCESS)
            *idx = begin;
    }

    WLOG(WS_LOG_DEBUG, "Leaving BuildUserAuthRequestPublicKey(), ret = %d",
            ret);
    return ret;
}


#endif


int SendUserAuthRequest(WOLFSSH* ssh, byte authType, int addSig)
{
    byte* output;
    word32 idx;
    const char* authName = NULL;
    word32 authNameSz = 0;
    const char* serviceName = NULL;
    word32 serviceNameSz = 0;
    word32 payloadSz = 0;
    int ret = WS_SUCCESS;
    WS_UserAuthData authData;
    WS_KeySignature *keySig_ptr = NULL;
    byte authId = ID_NONE;

    WOLFSSH_UNUSED(addSig);

    WLOG(WS_LOG_DEBUG, "Entering SendUserAuthRequest()");

    if (ssh == NULL)
        ret = WS_BAD_ARGUMENT;

    if (ret == WS_SUCCESS) {
        keySig_ptr = (WS_KeySignature*)WMALLOC(sizeof(WS_KeySignature),
                ssh->ctx->heap, DYNTYPE_BUFFER);
        if (!keySig_ptr)
            ret = WS_MEMORY_E;
    }

    if (ret == WS_SUCCESS) {
        WMEMSET(keySig_ptr, 0, sizeof(WS_KeySignature));
        keySig_ptr->keySigId = ID_NONE;
        keySig_ptr->heap = ssh->ctx->heap;

        if (ssh->ctx->userAuthCb != NULL) {
            WLOG(WS_LOG_DEBUG, "SUAR: Calling the userauth callback");

            WMEMSET(&authData, 0, sizeof(authData));
            authData.type = authType;
            authData.username = (const byte*)ssh->userName;
            authData.usernameSz = ssh->userNameSz;

            if (authType & WOLFSSH_USERAUTH_PASSWORD) {
                ret = ssh->ctx->userAuthCb(WOLFSSH_USERAUTH_PASSWORD,
                        &authData, ssh->userAuthCtx);
                if (ret != WOLFSSH_USERAUTH_SUCCESS) {
                    WLOG(WS_LOG_DEBUG, "SUAR: Couldn't get password");
                    ret = WS_FATAL_ERROR;
                    authType &= ~WOLFSSH_USERAUTH_PASSWORD;
                }
                else {
                    WLOG(WS_LOG_DEBUG, "SUAR: Callback successful password");
                    authId = ID_USERAUTH_PASSWORD;
                    authType = WOLFSSH_USERAUTH_PASSWORD;
                    authData.type = authType;
                }
            }
            /* fall into public key case if password case was not successful */
            if ((ret == WS_FATAL_ERROR ||
                !(authType & WOLFSSH_USERAUTH_PASSWORD)) &&
                (authType & WOLFSSH_USERAUTH_PUBLICKEY)) {
                ret = ssh->ctx->userAuthCb(WOLFSSH_USERAUTH_PUBLICKEY,
                        &authData, ssh->userAuthCtx);
                if (ret != WOLFSSH_USERAUTH_SUCCESS) {
                    WLOG(WS_LOG_DEBUG, "SUAR: Couldn't get key");
                    ret = WS_FATAL_ERROR;
                }
                else {
                    WLOG(WS_LOG_DEBUG, "SUAR: Callback successful public key");
                    authData.type = WOLFSSH_USERAUTH_PUBLICKEY;
                    authId = ID_USERAUTH_PUBLICKEY;
                }
            }

        }
        else {
            WLOG(WS_LOG_DEBUG, "SUAR: No user auth callback");
            ret = WS_FATAL_ERROR;
        }
    }

    if (ret == WS_SUCCESS) {
        serviceName = IdToName(ID_SERVICE_CONNECTION);
        serviceNameSz = (word32)WSTRLEN(serviceName);
        authName = IdToName(authId);
        authNameSz = (word32)WSTRLEN(authName);

        payloadSz = MSG_ID_SZ + (LENGTH_SZ * 3) +
                    ssh->userNameSz + serviceNameSz + authNameSz;

        if (authId == ID_USERAUTH_PASSWORD)
            ret = PrepareUserAuthRequestPassword(ssh, &payloadSz, &authData);
        else if (authId == ID_USERAUTH_PUBLICKEY && !ssh->userAuthPkDone) {
            authData.sf.publicKey.hasSignature = 1;
            ssh->userAuthPkDone = 1;
            ret = PrepareUserAuthRequestPublicKey(ssh, &payloadSz, &authData,
                    keySig_ptr);
        }
        else if (authId != ID_NONE && !ssh->userAuthPkDone)
            ret = WS_INVALID_ALGO_ID;
    }

    if (ret == WS_SUCCESS)
        ret = PreparePacket(ssh, payloadSz);

    if (ret == WS_SUCCESS) {
        byte* sigStart;
        word32 sigStartIdx;

        output = ssh->outputBuffer.buffer;
        idx = ssh->outputBuffer.length;

        sigStart = output + idx;
        sigStartIdx = idx;

        output[idx++] = MSGID_USERAUTH_REQUEST;
        c32toa(ssh->userNameSz, output + idx);
        idx += LENGTH_SZ;
        WMEMCPY(output + idx, ssh->userName, ssh->userNameSz);
        idx += ssh->userNameSz;

        c32toa(serviceNameSz, output + idx);
        idx += LENGTH_SZ;
        WMEMCPY(output + idx, serviceName, serviceNameSz);
        idx += serviceNameSz;

        c32toa(authNameSz, output + idx);
        idx += LENGTH_SZ;
        WMEMCPY(output + idx, authName, authNameSz);
        idx += authNameSz;

        if (authId == ID_USERAUTH_PASSWORD) {
            WOLFSSH_UNUSED(sigStart);
            WOLFSSH_UNUSED(sigStartIdx);

            ret = BuildUserAuthRequestPassword(ssh, output, &idx, &authData);
        }
        else if (authId == ID_USERAUTH_PUBLICKEY)
            ret = BuildUserAuthRequestPublicKey(ssh, output, &idx, &authData,
                    sigStart, sigStartIdx, keySig_ptr);

        if (ret == WS_SUCCESS) {
            ssh->outputBuffer.length = idx;
            ret = BundlePacket(ssh);
        }
    }

    if (authId == ID_USERAUTH_PUBLICKEY)
        wolfSSH_KEY_clean(keySig_ptr);

    if (ret == WS_SUCCESS) {
        ret = wolfSSH_SendPacket(ssh);
    }

    if (ret != WS_WANT_WRITE && ret != WS_SUCCESS)
        PurgePacket(ssh);

    ForceZero(&authData, sizeof(WS_UserAuthData));
    WLOG(WS_LOG_DEBUG, "Leaving SendUserAuthRequest(), ret = %d", ret);

    if (keySig_ptr)
        WFREE(keySig_ptr, ssh->ctx->heap, DYNTYPE_BUFFER);

    return ret;
}

#ifndef MAX_AUTH_STRING
    #define MAX_AUTH_STRING 80
#endif
static int GetAllowedAuth(WOLFSSH* ssh, char* authStr)
{
    int typeAllowed = 0;

    typeAllowed |= WOLFSSH_USERAUTH_PASSWORD;
#if !defined(WOLFSSH_NO_RSA) || !defined(WOLFSSH_NO_ECDSA)
    typeAllowed |= WOLFSSH_USERAUTH_PUBLICKEY;
#endif

    if (ssh == NULL || authStr == NULL)
        return WS_BAD_ARGUMENT;

    authStr[0] = '\0';
    if (ssh->ctx && ssh->ctx->userAuthTypesCb) {
        typeAllowed = ssh->ctx->userAuthTypesCb(ssh, ssh->userAuthCtx);
    }
    if (typeAllowed & WOLFSSH_USERAUTH_PUBLICKEY) {
        WSTRNCAT(authStr, "publickey,", MAX_AUTH_STRING-1);
    }

    if (typeAllowed & WOLFSSH_USERAUTH_PASSWORD) {
        WSTRNCAT(authStr, "password,", MAX_AUTH_STRING-1);
    }

    /* remove last comma from the list */
    return (int)XSTRLEN(authStr) - 1;
}

int SendUserAuthFailure(WOLFSSH* ssh, byte partialSuccess)
{
    byte* output;
    word32 idx;
    int ret = WS_SUCCESS;
    int   authSz = 0;
    char  authStr[MAX_AUTH_STRING];

    WLOG(WS_LOG_DEBUG, "Entering SendUserAuthFailure()");

    if (ssh == NULL)
        ret = WS_BAD_ARGUMENT;

    if (ret == WS_SUCCESS) {
        authSz = GetAllowedAuth(ssh, authStr);
        if (authSz < 0) {
            ret = authSz; /* propogate error value */
        }
    }

    if (ret == WS_SUCCESS)
        ret = PreparePacket(ssh,
                            MSG_ID_SZ + LENGTH_SZ +
                            authSz + BOOLEAN_SZ);

    if (ret == WS_SUCCESS) {
        output = ssh->outputBuffer.buffer;
        idx = ssh->outputBuffer.length;

        output[idx++] = MSGID_USERAUTH_FAILURE;
        c32toa(authSz, output + idx);
        idx += LENGTH_SZ;
        WMEMCPY(output + idx, authStr, authSz);
        idx += authSz;
        output[idx++] = (partialSuccess != 0);

        ssh->outputBuffer.length = idx;

        ret = BundlePacket(ssh);
    }

    if (ret == WS_SUCCESS)
        ret = wolfSSH_SendPacket(ssh);

    return ret;
}


int SendUserAuthSuccess(WOLFSSH* ssh)
{
    byte* output;
    word32 idx;
    int ret = WS_SUCCESS;

    if (ssh == NULL)
        ret = WS_BAD_ARGUMENT;

    if (ret == WS_SUCCESS)
        ret = PreparePacket(ssh, MSG_ID_SZ);

    if (ret == WS_SUCCESS) {
        output = ssh->outputBuffer.buffer;
        idx = ssh->outputBuffer.length;

        output[idx++] = MSGID_USERAUTH_SUCCESS;

        ssh->outputBuffer.length = idx;

        ret = BundlePacket(ssh);
    }

    if (ret == WS_SUCCESS)
        ret = wolfSSH_SendPacket(ssh);

    return ret;
}


int SendUserAuthPkOk(WOLFSSH* ssh,
                     const byte* algoName, word32 algoNameSz,
                     const byte* publicKey, word32 publicKeySz)
{
    byte* output;
    word32 idx;
    int ret = WS_SUCCESS;

    if (ssh == NULL ||
        algoName == NULL || algoNameSz == 0 ||
        publicKey == NULL || publicKeySz == 0) {

        ret = WS_BAD_ARGUMENT;
    }

    if (ret == WS_SUCCESS)
        ret = PreparePacket(ssh, MSG_ID_SZ + (LENGTH_SZ * 2) +
                                 algoNameSz + publicKeySz);

    if (ret == WS_SUCCESS) {
        output = ssh->outputBuffer.buffer;
        idx = ssh->outputBuffer.length;

        output[idx++] = MSGID_USERAUTH_PK_OK;
        c32toa(algoNameSz, output + idx);
        idx += LENGTH_SZ;
        WMEMCPY(output + idx, algoName, algoNameSz);
        idx += algoNameSz;
        c32toa(publicKeySz, output + idx);
        idx += LENGTH_SZ;
        WMEMCPY(output + idx, publicKey, publicKeySz);
        idx += publicKeySz;

        ssh->outputBuffer.length = idx;

        ret = BundlePacket(ssh);
    }

    if (ret == WS_SUCCESS)
        ret = wolfSSH_SendPacket(ssh);

    return ret;
}


int SendUserAuthBanner(WOLFSSH* ssh)
{
    byte* output;
    word32 idx;
    int ret = WS_SUCCESS;
    const char* banner = NULL;
    word32 bannerSz = 0;

    WLOG(WS_LOG_DEBUG, "Entering SendUserAuthBanner()");
    if (ssh == NULL)
        ret = WS_BAD_ARGUMENT;

    if (ret == WS_SUCCESS) {
        banner = ssh->ctx->banner;
        bannerSz = ssh->ctx->bannerSz;
    }

    if (banner != NULL && bannerSz > 0) {
        if (ret == WS_SUCCESS)
            ret = PreparePacket(ssh, MSG_ID_SZ + (LENGTH_SZ * 2) +
                                bannerSz + cannedLangTagSz);

        if (ret == WS_SUCCESS) {
            output = ssh->outputBuffer.buffer;
            idx = ssh->outputBuffer.length;

            output[idx++] = MSGID_USERAUTH_BANNER;
            c32toa(bannerSz, output + idx);
            idx += LENGTH_SZ;
            if (bannerSz > 0)
                WMEMCPY(output + idx, banner, bannerSz);
            idx += bannerSz;
            c32toa(cannedLangTagSz, output + idx);
            idx += LENGTH_SZ;
            WMEMCPY(output + idx, cannedLangTag, cannedLangTagSz);
            idx += cannedLangTagSz;

            ssh->outputBuffer.length = idx;

            ret = BundlePacket(ssh);
        }
    }

    if (ret == WS_SUCCESS)
        ret = wolfSSH_SendPacket(ssh);

    WLOG(WS_LOG_DEBUG, "Leaving SendUserAuthBanner()");
    return ret;
}


int SendRequestSuccess(WOLFSSH *ssh, int success)
{
    byte *output;
    word32 idx;
    int ret = WS_SUCCESS;

    WLOG(WS_LOG_DEBUG, "Entering SendRequestSuccess(), %s",
         success ? "Success" : "Failure");

    if (ssh == NULL)
        ret = WS_BAD_ARGUMENT;

    if (ret == WS_SUCCESS)
        ret = PreparePacket(ssh, MSG_ID_SZ);

    if (ret == WS_SUCCESS)
    {
        output = ssh->outputBuffer.buffer;
        idx = ssh->outputBuffer.length;

        output[idx++] = success ? MSGID_REQUEST_SUCCESS : MSGID_REQUEST_FAILURE;

        ssh->outputBuffer.length = idx;

        ret = BundlePacket(ssh);
    }

    if (ret == WS_SUCCESS)
        ret = wolfSSH_SendPacket(ssh);

    WLOG(WS_LOG_DEBUG, "Leaving SendRequestSuccess(), ret = %d", ret);
    return ret;
}


int SendGlobalRequestFwdSuccess(WOLFSSH* ssh, int success, word32 port)
{
    byte *output;
    word32 idx;
    int ret = WS_SUCCESS;

    WLOG(WS_LOG_DEBUG, "Entering SendGlobalRequestFwdSuccess(), %s",
         success ? "Success" : "Failure");

    if (ssh == NULL)
        ret = WS_BAD_ARGUMENT;

    if (ret == WS_SUCCESS)
        ret = PreparePacket(ssh, MSG_ID_SZ + (success ? UINT32_SZ : 0));

    if (ret == WS_SUCCESS)
    {
        output = ssh->outputBuffer.buffer;
        idx = ssh->outputBuffer.length;

        if (success) {
            output[idx++] = MSGID_REQUEST_SUCCESS;
            c32toa(port, output + idx);
            idx += UINT32_SZ;
        }
        else {
            output[idx++] = MSGID_REQUEST_FAILURE;
        }

        ssh->outputBuffer.length = idx;

        ret = BundlePacket(ssh);
    }

    if (ret == WS_SUCCESS)
        ret = wolfSSH_SendPacket(ssh);

    WLOG(WS_LOG_DEBUG, "Leaving SendGlobalRequestFwdSuccess(), ret = %d", ret);
    return ret;
}


static int SendChannelOpen(WOLFSSH* ssh, WOLFSSH_CHANNEL* channel,
        byte* channelData, word32 channelDataSz)
{
    byte* output;
    const char* channelType = NULL;
    word32 channelTypeSz = 0, idx;
    int ret = WS_SUCCESS;

    WLOG(WS_LOG_DEBUG, "Entering SendChannelOpen()");

    if (ssh == NULL || channel == NULL)
        ret = WS_BAD_ARGUMENT;
    if (channelDataSz > 0 && channelData == NULL)
        ret = WS_BAD_ARGUMENT;

    if (ret == WS_SUCCESS) {
        channelType = IdToName(channel->channelType);
        channelTypeSz = (word32)WSTRLEN(channelType);

        ret = PreparePacket(ssh, MSG_ID_SZ + LENGTH_SZ + channelTypeSz +
                                 (UINT32_SZ * 3) + channelDataSz);
    }

    if (ret == WS_SUCCESS) {
        output = ssh->outputBuffer.buffer;
        idx = ssh->outputBuffer.length;

        output[idx++] = MSGID_CHANNEL_OPEN;
        c32toa(channelTypeSz, output + idx);
        idx += LENGTH_SZ;
        WMEMCPY(output + idx, channelType, channelTypeSz);
        idx += channelTypeSz;
        c32toa(channel->channel, output + idx);
        idx += UINT32_SZ;
        c32toa(channel->windowSz, output + idx);
        idx += UINT32_SZ;
        c32toa(channel->maxPacketSz, output + idx);
        idx += UINT32_SZ;
        if (channelDataSz > 0)
            WMEMCPY(output + idx, channelData, channelDataSz);
        idx += channelDataSz;

        ssh->outputBuffer.length = idx;

        ret = BundlePacket(ssh);
    }

    if (ret == WS_SUCCESS)
        ret = wolfSSH_SendPacket(ssh);

    WLOG(WS_LOG_DEBUG, "Leaving SendChannelOpen(), ret = %d", ret);
    return ret;
}


int SendChannelOpenSession(WOLFSSH* ssh, WOLFSSH_CHANNEL* channel)
{
    int ret = WS_SUCCESS;

    WLOG(WS_LOG_DEBUG, "Entering SendChannelOpenSession()");

    ret = SendChannelOpen(ssh, channel, NULL, 0);

    WLOG(WS_LOG_DEBUG, "Leaving SendChannelOpenSession(), ret = %d", ret);
    return ret;
}


#ifdef WOLFSSH_FWD
int SendChannelOpenForward(WOLFSSH* ssh, WOLFSSH_CHANNEL* channel)
{
    int ret = WS_SUCCESS;
    byte* forwardData = NULL;
    word32 hostSz, originSz, forwardDataSz, idx;

    WLOG(WS_LOG_DEBUG, "Entering SendChannelOpenForward()");

    if (ssh == NULL || channel == NULL ||
            channel->host == NULL || channel->origin == NULL)
        ret = WS_BAD_ARGUMENT;

    if (ret == WS_SUCCESS) {
        hostSz = (word32)WSTRLEN(channel->host);
        originSz = (word32)WSTRLEN(channel->origin);
        forwardDataSz = UINT32_SZ * 2 + LENGTH_SZ * 2 + hostSz + originSz;
        forwardData = (byte*)WMALLOC(forwardDataSz,
                ssh->ctx->heap, DYNTYPE_TEMP);
        if (forwardData == NULL)
            ret = WS_MEMORY_E;
    }

    if (ret == WS_SUCCESS) {
        c32toa(hostSz, forwardData);
        idx = LENGTH_SZ;
        WMEMCPY(forwardData + idx, channel->host, hostSz);
        idx += hostSz;
        c32toa(channel->hostPort, forwardData + idx);
        idx += UINT32_SZ;
        c32toa(originSz, forwardData + idx);
        idx += LENGTH_SZ;
        WMEMCPY(forwardData + idx, channel->origin, originSz);
        idx += originSz;
        c32toa(channel->originPort, forwardData + idx);

        ret = SendChannelOpen(ssh, channel, forwardData, forwardDataSz);
    }

    if (forwardData)
        WFREE(forwardData, ssh->ctx->heap, DYNTYPE_TEMP);

    WLOG(WS_LOG_DEBUG, "Leaving SendChannelOpenForward(), ret = %d", ret);
    return ret;
}
#endif /* WOLFSSH_FWD */


int SendChannelOpenConf(WOLFSSH* ssh, WOLFSSH_CHANNEL* channel)
{
    byte* output;
    word32 idx;
    int ret = WS_SUCCESS;

    WLOG(WS_LOG_DEBUG, "Entering SendChannelOpenConf()");

    if (ssh == NULL)
        ret = WS_BAD_ARGUMENT;

    if (ret == WS_SUCCESS) {
        WLOG(WS_LOG_INFO, "  channelId = %u", channel->channel);
        WLOG(WS_LOG_INFO, "  peerChannelId = %u", channel->peerChannel);
        WLOG(WS_LOG_INFO, "  peerWindowSz = %u", channel->peerWindowSz);
        WLOG(WS_LOG_INFO, "  peerMaxPacketSz = %u", channel->peerMaxPacketSz);
    }

    if (ret == WS_SUCCESS)
        ret = PreparePacket(ssh, MSG_ID_SZ + (UINT32_SZ * 4));

    if (ret == WS_SUCCESS) {
        output = ssh->outputBuffer.buffer;
        idx = ssh->outputBuffer.length;

        output[idx++] = MSGID_CHANNEL_OPEN_CONF;
        c32toa(channel->peerChannel, output + idx);
        idx += UINT32_SZ;
        c32toa(channel->channel, output + idx);
        idx += UINT32_SZ;
        c32toa(channel->windowSz, output + idx);
        idx += UINT32_SZ;
        c32toa(channel->maxPacketSz, output + idx);
        idx += UINT32_SZ;

        ssh->outputBuffer.length = idx;

        ret = BundlePacket(ssh);
    }

    if (ret == WS_SUCCESS)
        ret = wolfSSH_SendPacket(ssh);

    WLOG(WS_LOG_DEBUG, "Leaving SendChannelOpenConf(), ret = %d", ret);
    return ret;
}

int SendChannelOpenFail(WOLFSSH* ssh, word32 channel, word32 reason,
        const char* description, const char* language)
{
    byte* output;
    word32 idx;
    word32 descriptionSz = (word32)WSTRLEN(description);
    word32 languageSz = (word32)WSTRLEN(language);
    int ret = WS_SUCCESS;

    WLOG(WS_LOG_DEBUG, "Entering SendChannelOpenFail()");

    if (ssh == NULL)
        ret = WS_BAD_ARGUMENT;

    if (ret == WS_SUCCESS) {
        WLOG(WS_LOG_INFO, "  channelId = %u", channel);
        WLOG(WS_LOG_INFO, "  reason = %u", reason);
        WLOG(WS_LOG_INFO, "  description = %s", description);
        WLOG(WS_LOG_INFO, "  language = %s", language);
    }

    if (ret == WS_SUCCESS) {
        ret = PreparePacket(ssh, MSG_ID_SZ + UINT32_SZ + UINT32_SZ
                + LENGTH_SZ + descriptionSz + LENGTH_SZ + languageSz);
    }

    if (ret == WS_SUCCESS) {
        output = ssh->outputBuffer.buffer;
        idx = ssh->outputBuffer.length;

        output[idx++] = MSGID_CHANNEL_OPEN_FAIL;
        c32toa(channel, output + idx);
        idx += UINT32_SZ;
        c32toa(reason, output + idx);
        idx += UINT32_SZ;
        c32toa(descriptionSz, output + idx);
        idx += LENGTH_SZ;
        WMEMCPY(output + idx, description, descriptionSz);
        idx += descriptionSz;
        c32toa(languageSz, output + idx);
        idx += LENGTH_SZ;
        WMEMCPY(output + idx, language, languageSz);
        idx += languageSz;

        ssh->outputBuffer.length = idx;

        ret = BundlePacket(ssh);
    }

    if (ret == WS_SUCCESS)
        ret = wolfSSH_SendPacket(ssh);

    WLOG(WS_LOG_DEBUG, "Leaving SendChannelOpenFail(), ret = %d", ret);
    return ret;
}

int SendChannelEof(WOLFSSH* ssh, word32 peerChannelId)
{
    byte* output;
    word32 idx;
    int ret = WS_SUCCESS;
    WOLFSSH_CHANNEL* channel = NULL;

    WLOG(WS_LOG_DEBUG, "Entering SendChannelEof()");

    if (ssh == NULL)
        ret = WS_BAD_ARGUMENT;

    if (ret == WS_SUCCESS) {
        channel = ChannelFind(ssh, peerChannelId, WS_CHANNEL_ID_PEER);
        if (channel == NULL)
            ret = WS_INVALID_CHANID;
    }

    if (ret == WS_SUCCESS) {
        if (channel->eofTxd) {
            WLOG(WS_LOG_DEBUG, "Already sent EOF");
            WLOG(WS_LOG_DEBUG, "Leaving SendChannelEof(), ret = %d", ret);
            return ret;
        }
    }

    if (ret == WS_SUCCESS)
        ret = PreparePacket(ssh, MSG_ID_SZ + UINT32_SZ);

    if (ret == WS_SUCCESS) {
        output = ssh->outputBuffer.buffer;
        idx = ssh->outputBuffer.length;

        output[idx++] = MSGID_CHANNEL_EOF;
        c32toa(channel->peerChannel, output + idx);
        idx += UINT32_SZ;

        ssh->outputBuffer.length = idx;

        ret = BundlePacket(ssh);
    }

    if (ret == WS_SUCCESS)
        ret = wolfSSH_SendPacket(ssh);

    if (ret == WS_SUCCESS)
        channel->eofTxd = 1;

    WLOG(WS_LOG_DEBUG, "Leaving SendChannelEof(), ret = %d", ret);
    return ret;
}


int SendChannelEow(WOLFSSH* ssh, word32 peerChannelId)
{
    byte* output;
    const char* str = "eow@openssh.com";
    word32 idx;
    word32 strSz = 0;
    int      ret = WS_SUCCESS;
    WOLFSSH_CHANNEL* channel = NULL;

    WLOG(WS_LOG_DEBUG, "Entering SendChannelEow()");

    if (ssh == NULL)
        ret = WS_BAD_ARGUMENT;

    if (ret == WS_SUCCESS && !ssh->clientOpenSSH) {
        WLOG(WS_LOG_DEBUG, "Leaving SendChannelEow(), not OpenSSH");
        return ret;
    }

    if (ret == WS_SUCCESS) {
        channel = ChannelFind(ssh, peerChannelId, WS_CHANNEL_ID_PEER);
        if (channel == NULL)
            ret = WS_INVALID_CHANID;
    }

    if (ret == WS_SUCCESS) {
        strSz = (word32)WSTRLEN(str);
        ret = PreparePacket(ssh, MSG_ID_SZ + UINT32_SZ + LENGTH_SZ + strSz +
                            BOOLEAN_SZ);
    }

    if (ret == WS_SUCCESS) {
        output = ssh->outputBuffer.buffer;
        idx = ssh->outputBuffer.length;

        output[idx++] = MSGID_CHANNEL_REQUEST;
        c32toa(channel->peerChannel, output + idx);
        idx += UINT32_SZ;
        c32toa(strSz, output + idx);
        idx += LENGTH_SZ;
        WMEMCPY(output + idx, str, strSz);
        idx += strSz;
        output[idx++] = 0;

        ssh->outputBuffer.length = idx;

        ret = BundlePacket(ssh);
    }

    if (ret == WS_SUCCESS)
        ret = wolfSSH_SendPacket(ssh);

    WLOG(WS_LOG_DEBUG, "Leaving SendChannelEow(), ret = %d", ret);
    return ret;
}


int SendChannelExit(WOLFSSH* ssh, word32 peerChannelId, int status)
{
    byte* output;
    const char* str = "exit-status";
    word32 idx;
    word32 strSz = 0;
    int      ret = WS_SUCCESS;
    WOLFSSH_CHANNEL* channel = NULL;

    WLOG(WS_LOG_DEBUG, "Entering SendChannelExit(), status = %d", status);

    if (ssh == NULL)
        ret = WS_BAD_ARGUMENT;

    if (ret == WS_SUCCESS) {
        channel = ChannelFind(ssh, peerChannelId, WS_CHANNEL_ID_PEER);
        if (channel == NULL)
            ret = WS_INVALID_CHANID;
    }

    if (ret == WS_SUCCESS) {
        strSz = (word32)WSTRLEN(str);
        ret = PreparePacket(ssh, MSG_ID_SZ + UINT32_SZ + LENGTH_SZ + strSz +
                            BOOLEAN_SZ + UINT32_SZ);
    }

    if (ret == WS_SUCCESS) {
        output = ssh->outputBuffer.buffer;
        idx = ssh->outputBuffer.length;

        output[idx++] = MSGID_CHANNEL_REQUEST;
        c32toa(channel->peerChannel, output + idx);
        idx += UINT32_SZ;
        c32toa(strSz, output + idx);
        idx += LENGTH_SZ;
        WMEMCPY(output + idx, str, strSz);
        idx += strSz;
        output[idx++] = 0;
        c32toa(status, output + idx);
        idx += UINT32_SZ;

        ssh->outputBuffer.length = idx;

        ret = BundlePacket(ssh);
    }

    if (ret == WS_SUCCESS)
        ret = wolfSSH_SendPacket(ssh);

    WLOG(WS_LOG_DEBUG, "Leaving SendChannelExit(), ret = %d", ret);
    return ret;
}


int SendChannelClose(WOLFSSH* ssh, word32 peerChannelId)
{
    byte* output;
    word32 idx;
    int ret = WS_SUCCESS;
    WOLFSSH_CHANNEL* channel = NULL;

    WLOG(WS_LOG_DEBUG, "Entering SendChannelClose()");

    if (ssh == NULL)
        ret = WS_BAD_ARGUMENT;

    if (ret == WS_SUCCESS) {
        channel = ChannelFind(ssh, peerChannelId, WS_CHANNEL_ID_PEER);
        if (channel == NULL)
            ret = WS_INVALID_CHANID;
        else if (channel->closeTxd) {
            WLOG(WS_LOG_DEBUG, "Leaving SendChannelClose(), already sent");
            return ret;
        }
    }

    if (ret == WS_SUCCESS)
        ret = PreparePacket(ssh, MSG_ID_SZ + UINT32_SZ);

    if (ret == WS_SUCCESS) {
        output = ssh->outputBuffer.buffer;
        idx = ssh->outputBuffer.length;

        output[idx++] = MSGID_CHANNEL_CLOSE;
        c32toa(channel->peerChannel, output + idx);
        idx += UINT32_SZ;

        ssh->outputBuffer.length = idx;

        ret = BundlePacket(ssh);
    }

    if (ret == WS_SUCCESS) {
        ret = wolfSSH_SendPacket(ssh);
        channel->closeTxd = 1;
    }

    WLOG(WS_LOG_DEBUG, "Leaving SendChannelClose(), ret = %d", ret);
    return ret;
}


int SendChannelData(WOLFSSH* ssh, word32 channelId,
                    byte* data, word32 dataSz)
{
    byte* output;
    word32 idx;
    int ret = WS_SUCCESS;
    WOLFSSH_CHANNEL* channel = NULL;

    WLOG(WS_LOG_DEBUG, "Entering SendChannelData()");

    if (ssh == NULL)
        ret = WS_BAD_ARGUMENT;

    if (ret == WS_SUCCESS) {
        if (ssh->isKeying)
            ret = WS_REKEYING;
    }

    /* if already having data pending try to flush it first and do not continue
     * to que more on fail */
    if (ret == WS_SUCCESS && ssh->outputBuffer.plainSz > 0) {
        WLOG(WS_LOG_DEBUG, "Flushing out want write data");
        ret = wolfSSH_SendPacket(ssh);
        if (ret != WS_SUCCESS) {
            WLOG(WS_LOG_DEBUG, "Leaving SendChannelData(), ret = %d", ret);
            return ret;
        }

    }

    if (ret == WS_SUCCESS) {
        if (ssh->outputBuffer.length != 0)
            ret = wolfSSH_SendPacket(ssh);
    }

    if (ret == WS_SUCCESS) {
        channel = ChannelFind(ssh, channelId, WS_CHANNEL_ID_SELF);
        if (channel == NULL) {
            WLOG(WS_LOG_DEBUG, "Invalid channel");
            ret = WS_INVALID_CHANID;
        }
    }

    if (ret == WS_SUCCESS) {
        if (channel->peerWindowSz == 0) {
            WLOG(WS_LOG_DEBUG, "channel window is full");
            ssh->error = WS_WINDOW_FULL;
            ret = WS_WINDOW_FULL;
        }
    }

    if (ret == WS_SUCCESS) {
        word32 bound = min(channel->peerWindowSz, channel->peerMaxPacketSz);
        bound = min(bound, channel->maxPacketSz);

        if (dataSz > bound) {
            WLOG(WS_LOG_DEBUG,
                 "Trying to send %u, client will only accept %u, limiting",
                 dataSz, bound);
            dataSz = bound;
        }

        ret = PreparePacket(ssh,
                MSG_ID_SZ + UINT32_SZ + LENGTH_SZ + dataSz);
    }

    if (ret == WS_SUCCESS) {
        output = ssh->outputBuffer.buffer;
        idx = ssh->outputBuffer.length;

        output[idx++] = MSGID_CHANNEL_DATA;
        c32toa(channel->peerChannel, output + idx);
        idx += UINT32_SZ;
        c32toa(dataSz, output + idx);
        idx += LENGTH_SZ;
        WMEMCPY(output + idx, data, dataSz);
        idx += dataSz;

        ssh->outputBuffer.length = idx;

        ret = BundlePacket(ssh);
    }

    if (ret == WS_SUCCESS) {
        WLOG(WS_LOG_INFO, "  dataSz = %u", dataSz);
        WLOG(WS_LOG_INFO, "  peerWindowSz = %u", channel->peerWindowSz);
        channel->peerWindowSz -= dataSz;
        WLOG(WS_LOG_INFO, "  update peerWindowSz = %u", channel->peerWindowSz);
    }

    /* at this point the data has been loaded into WOLFSSH structure and is
     * considered consumed */
    if (ret == WS_SUCCESS)
        ret = wolfSSH_SendPacket(ssh);

    if (ret == WS_SUCCESS || ret == WS_WANT_WRITE)
        ret = dataSz;

    if (ssh && ssh->error == WS_WANT_WRITE)
        ssh->outputBuffer.plainSz = dataSz;

    WLOG(WS_LOG_DEBUG, "Leaving SendChannelData(), ret = %d", ret);
    return ret;
}


int SendChannelExtendedData(WOLFSSH* ssh, word32 channelId,
                    byte* data, word32 dataSz)
{
    byte* output;
    word32 idx;
    int ret = WS_SUCCESS;
    WOLFSSH_CHANNEL* channel = NULL;

    WLOG(WS_LOG_DEBUG, "Entering SendChannelData()");

    if (ssh == NULL)
        ret = WS_BAD_ARGUMENT;

    if (ret == WS_SUCCESS) {
        if (ssh->isKeying)
            ret = WS_REKEYING;
    }

    /* if already having data pending try to flush it first and do not continue
     * to que more on fail */
    if (ret == WS_SUCCESS && ssh->outputBuffer.plainSz > 0) {
        WLOG(WS_LOG_DEBUG, "Flushing out want write data");
        ret = wolfSSH_SendPacket(ssh);
        if (ret != WS_SUCCESS) {
            WLOG(WS_LOG_DEBUG, "Leaving SendChannelData(), ret = %d", ret);
            return ret;
        }

    }

    if (ret == WS_SUCCESS) {
        if (ssh->outputBuffer.length != 0)
            ret = wolfSSH_SendPacket(ssh);
    }

    if (ret == WS_SUCCESS) {
        channel = ChannelFind(ssh, channelId, WS_CHANNEL_ID_SELF);
        if (channel == NULL) {
            WLOG(WS_LOG_DEBUG, "Invalid channel");
            ret = WS_INVALID_CHANID;
        }
    }

    if (ret == WS_SUCCESS) {
        if (channel->peerWindowSz == 0) {
            WLOG(WS_LOG_DEBUG, "channel window is full");
            ssh->error = WS_WINDOW_FULL;
            ret = WS_WINDOW_FULL;
        }
    }

    if (ret == WS_SUCCESS) {
        word32 bound = min(channel->peerWindowSz, channel->peerMaxPacketSz);
        bound = min(bound, channel->maxPacketSz);

        if (dataSz > bound) {
            WLOG(WS_LOG_DEBUG,
                 "Trying to send %u, client will only accept %u, limiting",
                 dataSz, bound);
            dataSz = bound;
        }

        ret = PreparePacket(ssh,
                MSG_ID_SZ + UINT32_SZ + UINT32_SZ + LENGTH_SZ + dataSz);
    }

    if (ret == WS_SUCCESS) {
        output = ssh->outputBuffer.buffer;
        idx = ssh->outputBuffer.length;


        output[idx++] = MSGID_CHANNEL_EXTENDED_DATA;
        c32toa(channel->peerChannel, output + idx);
        idx += UINT32_SZ;
        c32toa(CHANNEL_EXTENDED_DATA_STDERR, output + idx);
        idx += UINT32_SZ;
        c32toa(dataSz, output + idx);
        idx += LENGTH_SZ;
        WMEMCPY(output + idx, data, dataSz);
        idx += dataSz;

        ssh->outputBuffer.length = idx;

        ret = BundlePacket(ssh);
    }

    if (ret == WS_SUCCESS) {
        WLOG(WS_LOG_INFO, "  dataSz = %u", dataSz);
        WLOG(WS_LOG_INFO, "  peerWindowSz = %u", channel->peerWindowSz);
        channel->peerWindowSz -= dataSz;
        WLOG(WS_LOG_INFO, "  update peerWindowSz = %u", channel->peerWindowSz);
    }

    /* at this point the data has been loaded into WOLFSSH structure and is
     * considered consumed */
    if (ret == WS_SUCCESS)
        ret = wolfSSH_SendPacket(ssh);

    if (ret == WS_SUCCESS || ret == WS_WANT_WRITE)
        ret = dataSz;

    if (ssh && ssh->error == WS_WANT_WRITE)
        ssh->outputBuffer.plainSz = dataSz;

    WLOG(WS_LOG_DEBUG, "Leaving SendChannelExtendedData(), ret = %d", ret);
    return ret;
}


int SendChannelWindowAdjust(WOLFSSH* ssh, word32 channelId,
                            word32 bytesToAdd)
{
    byte* output;
    word32 idx;
    int ret = WS_SUCCESS;
    WOLFSSH_CHANNEL* channel;

    WLOG(WS_LOG_DEBUG, "Entering SendChannelWindowAdjust()");

    if (ssh == NULL)
        ret = WS_BAD_ARGUMENT;

    channel = ChannelFind(ssh, channelId, WS_CHANNEL_ID_SELF);
    if (channel == NULL) {
        WLOG(WS_LOG_DEBUG, "Invalid channel");
        ret = WS_INVALID_CHANID;
    }
    if (ret == WS_SUCCESS)
        ret = PreparePacket(ssh, MSG_ID_SZ + (UINT32_SZ * 2));

    if (ret == WS_SUCCESS) {
        output = ssh->outputBuffer.buffer;
        idx = ssh->outputBuffer.length;

        output[idx++] = MSGID_CHANNEL_WINDOW_ADJUST;
        c32toa(channel->peerChannel, output + idx);
        idx += UINT32_SZ;
        c32toa(bytesToAdd, output + idx);
        idx += UINT32_SZ;

        ssh->outputBuffer.length = idx;

        ret = BundlePacket(ssh);
    }

    if (ret == WS_SUCCESS)
        ret = wolfSSH_SendPacket(ssh);

    WLOG(WS_LOG_DEBUG, "Leaving SendChannelWindowAdjust(), ret = %d", ret);
    return ret;
}


static const char cannedShellName[] = "shell";
static const word32 cannedShellNameSz = (word32)sizeof(cannedShellName) - 1;

static const char cannedSubName[] = "subsystem";
static const word32 cannedSubNameSz = (word32)sizeof(cannedSubName) - 1;

static const char cannedExecName[] = "exec";
static const word32 cannedExecNameSz = (word32)sizeof(cannedExecName) - 1;


/* name : command for exec and name for subsystem channels */
int SendChannelRequest(WOLFSSH* ssh, byte* name, word32 nameSz)
{
    byte* output;
    word32 idx;
    int ret = WS_SUCCESS;
    WOLFSSH_CHANNEL* channel = NULL;
    const char* cType = NULL;
    word32 typeSz = 0;

    WLOG(WS_LOG_DEBUG, "Entering SendChannelRequest()");

    if (ssh == NULL)
        ret = WS_BAD_ARGUMENT;

    if (ret == WS_SUCCESS) {
        channel = ChannelFind(ssh,
                ssh->defaultPeerChannelId, WS_CHANNEL_ID_PEER);
        if (channel == NULL)
            ret = WS_INVALID_CHANID;
    }

    if (ret == WS_SUCCESS) {
        switch (ssh->connectChannelId) {
            case WOLFSSH_SESSION_SHELL:
                cType  = cannedShellName;
                typeSz = cannedShellNameSz;
                break;

            case WOLFSSH_SESSION_EXEC:
                cType  = cannedExecName;
                typeSz = cannedExecNameSz;
                break;

            case WOLFSSH_SESSION_SUBSYSTEM:
                cType  = cannedSubName;
                typeSz = cannedSubNameSz;
                break;

            default:
                WLOG(WS_LOG_DEBUG, "Unknown channel type");
                return WS_BAD_ARGUMENT;
        }
    }

    if (ret == WS_SUCCESS)
        ret = PreparePacket(ssh, MSG_ID_SZ + UINT32_SZ + LENGTH_SZ +
                                 typeSz + BOOLEAN_SZ +
                                 ((nameSz > 0)? UINT32_SZ : 0) + nameSz);

    if (ret == WS_SUCCESS) {
        output = ssh->outputBuffer.buffer;
        idx = ssh->outputBuffer.length;

        output[idx++] = MSGID_CHANNEL_REQUEST;
        c32toa(channel->peerChannel, output + idx);
        idx += UINT32_SZ;
        c32toa(typeSz, output + idx);
        idx += LENGTH_SZ;
        WMEMCPY(output + idx, cType, typeSz);
        idx += typeSz;
        output[idx++] = 1;

        if (nameSz > 0) {
            c32toa(nameSz, output + idx);
            idx += UINT32_SZ;
            WMEMCPY(output + idx, name, nameSz);
            idx += nameSz;
        }

        ssh->outputBuffer.length = idx;

        WLOG(WS_LOG_INFO, "Sending Channel Request: ");
        WLOG(WS_LOG_INFO, "  channelId = %u", channel->peerChannel);
        WLOG(WS_LOG_INFO, "  type = %s", cType);
        WLOG(WS_LOG_INFO, "  wantReply = %u", 1);

    #ifdef DEBUG_WOLFSSH
        /* only compile in code for checks on type if in debug mode */
        switch (ssh->connectChannelId) {
            case WOLFSSH_SESSION_EXEC:
                WLOG(WS_LOG_INFO, "  command = %s", name);
                break;

            case WOLFSSH_SESSION_SUBSYSTEM:
                WLOG(WS_LOG_INFO, "  subsystem = %s", name);
                break;

            default:
                break;
        }
    #endif

        ret = BundlePacket(ssh);
    }

    if (ret == WS_SUCCESS)
        ret = wolfSSH_SendPacket(ssh);

    WLOG(WS_LOG_DEBUG, "Leaving SendChannelRequest(), ret = %d", ret);
    return ret;
}


#if defined(WOLFSSH_TERM) && !defined(NO_FILESYSTEM)

static void TTYWordSet(word32 flag, int type, byte* out, word32* idx)
{
    out[*idx] = type; *idx += 1;
    c32toa(flag, out + *idx); *idx += UINT32_SZ;
}

#if !defined(USE_WINDOWS_API) && !defined(MICROCHIP_PIC32) && \
    !defined(NO_TERMIOS)

    /* sets terminal mode in buffer and advances idx */
    static void TTYSet(word32 isSet, int type, byte* out, word32* idx)
    {
        if (isSet) isSet = 1;
        out[*idx] = type; *idx += 1;
        c32toa(isSet, out + *idx); *idx += UINT32_SZ;
    }

    static void TTYCharSet(char flag, int type, byte* out, word32* idx)
    {
        TTYWordSet((flag & 0xFF), type, out, idx);
    }
#endif /* !USE_WINDOWS_API && !MICROCHIP_PIC32 && !NO_TERMIOS*/


/* create terminal mode string for pseudo-terminal request
 * returns size of buffer */
static int CreateMode(WOLFSSH* ssh, byte* mode)
{
    word32 idx = 0;

    #if !defined(USE_WINDOWS_API) && !defined(MICROCHIP_PIC32) && \
        !defined(NO_TERMIOS)
    {
        WOLFSSH_TERMIOS term;
        int baud;

        if (tcgetattr(STDIN_FILENO, &term) != 0) {
            printf("Couldn't get the original terminal settings.\n");
            return -1;
        }

        /* get baud rate */
        baud = (int)cfgetospeed(&term);
        TTYWordSet(baud, WOLFSSH_TTY_OP_ISPEED, mode, &idx);
        TTYWordSet(baud, WOLFSSH_TTY_OP_OSPEED, mode, &idx);

        /* char type */
        TTYCharSet(term.c_cc[VINTR], WOLFSSH_VINTR, mode, &idx);
        TTYCharSet(term.c_cc[VQUIT], WOLFSSH_VQUIT, mode, &idx);
        TTYCharSet(term.c_cc[VERASE], WOLFSSH_VERASE, mode, &idx);
        TTYCharSet(term.c_cc[VKILL], WOLFSSH_VKILL, mode, &idx);
        TTYCharSet(term.c_cc[VEOF], WOLFSSH_VEOF, mode, &idx);
        TTYCharSet(term.c_cc[VEOL], WOLFSSH_VEOL, mode, &idx);
        TTYCharSet(term.c_cc[VEOL2], WOLFSSH_VEOL2, mode, &idx);
        TTYCharSet(term.c_cc[VSTART], WOLFSSH_VSTART, mode, &idx);
        TTYCharSet(term.c_cc[VSTOP], WOLFSSH_VSTOP, mode, &idx);
        TTYCharSet(term.c_cc[VSUSP], WOLFSSH_VSUSP, mode, &idx);
        #ifdef VDSUSP
            TTYCharSet(term.c_cc[VDSUSP], WOLFSSH_VDSUSP, mode, &idx);
        #endif
        TTYCharSet(term.c_cc[VREPRINT], WOLFSSH_VREPRINT, mode, &idx);
        TTYCharSet(term.c_cc[VWERASE], WOLFSSH_VWERASE, mode, &idx);
        TTYCharSet(term.c_cc[VLNEXT], WOLFSSH_VLNEXT, mode, &idx);
        #ifdef VFLUSH
            TTYCharSet(term.c_cc[VFLUSH], WOLFSSH_VFLUSH, mode, &idx);
        #endif
        #ifdef VSWTCH
            TTYCharSet(term.c_cc[VSWTCH], WOLFSSH_VSWTCH, mode, &idx);
        #endif
        #ifdef VSTATUS
            TTYCharSet(term.c_cc[VSTATUS], WOLFSSH_VSTATUS, mode, &idx);
        #endif
        TTYCharSet(term.c_cc[VDISCARD], WOLFSSH_VDISCARD, mode, &idx);

        /* c_iflag for input modes */
        TTYSet((term.c_iflag & IGNPAR), WOLFSSH_IGNPAR, mode, &idx);
        TTYSet((term.c_iflag & PARMRK), WOLFSSH_PARMRK, mode, &idx);
        TTYSet((term.c_iflag & INPCK), WOLFSSH_INPCK, mode, &idx);
        TTYSet((term.c_iflag & ISTRIP), WOLFSSH_ISTRIP, mode, &idx);
        TTYSet((term.c_iflag & INLCR), WOLFSSH_INLCR, mode, &idx);
        TTYSet((term.c_iflag & IGNCR), WOLFSSH_IGNCR, mode, &idx);
        TTYSet((term.c_iflag & ICRNL), WOLFSSH_ICRNL, mode, &idx);
        #ifdef IUCLC
            TTYSet((term.c_iflag & IUCLC), WOLFSSH_IUCLC, mode, &idx);
        #endif
        TTYSet((term.c_iflag & IXON), WOLFSSH_IXON, mode, &idx);
        TTYSet((term.c_iflag & IXANY), WOLFSSH_IXANY, mode, &idx);
        TTYSet((term.c_iflag & IXOFF), WOLFSSH_IXOFF, mode, &idx);
        TTYSet((term.c_iflag & IMAXBEL), WOLFSSH_IMAXBEL, mode, &idx);
        #ifdef IUTF8
            TTYSet((term.c_iflag & IUTF8), WOLFSSH_IUTF8, mode, &idx);
        #endif

        /* c_lflag */
        TTYSet((term.c_lflag & ISIG), WOLFSSH_ISIG, mode, &idx);
        TTYSet((term.c_lflag &  ICANON), WOLFSSH_ICANON, mode, &idx);
        #ifdef XCASE
            TTYSet((term.c_lflag &  XCASE), WOLFSSH_XCASE, mode, &idx);
        #endif
        TTYSet((term.c_lflag &  ECHO), WOLFSSH_ECHO, mode, &idx);
        TTYSet((term.c_lflag &  ECHOE), WOLFSSH_ECHOE, mode, &idx);
        TTYSet((term.c_lflag &  ECHOK), WOLFSSH_ECHOK, mode, &idx);
        TTYSet((term.c_lflag &  ECHONL), WOLFSSH_ECHONL, mode, &idx);
        TTYSet((term.c_lflag &  NOFLSH), WOLFSSH_NOFLSH, mode, &idx);
        TTYSet((term.c_lflag &  TOSTOP), WOLFSSH_TOSTOP, mode, &idx);
        TTYSet((term.c_lflag &  IEXTEN), WOLFSSH_IEXTEN, mode, &idx);
        TTYSet((term.c_lflag &  ECHOCTL), WOLFSSH_ECHOCTL, mode, &idx);
        TTYSet((term.c_lflag &  ECHOKE), WOLFSSH_ECHOKE, mode, &idx);
        #ifdef PENDIN
            TTYSet((term.c_lflag &  PENDIN), WOLFSSH_PENDIN, mode, &idx);
        #endif

        /* c_oflag */
        TTYSet((term.c_oflag &  OPOST), WOLFSSH_OPOST, mode, &idx);
        #ifdef OLCUC
            TTYSet((term.c_oflag &  OLCUC), WOLFSSH_OLCUC, mode, &idx);
        #endif
        TTYSet((term.c_oflag &  ONLCR), WOLFSSH_ONLCR, mode, &idx);
        TTYSet((term.c_oflag &  OCRNL), WOLFSSH_OCRNL, mode, &idx);
        TTYSet((term.c_oflag &  ONOCR), WOLFSSH_ONOCR, mode, &idx);
        TTYSet((term.c_oflag &  ONLRET), WOLFSSH_ONLRET, mode, &idx);

        /* c_cflag */
        TTYSet((term.c_cflag &  CS7), WOLFSSH_CS7, mode, &idx);
        TTYSet((term.c_cflag &  CS8), WOLFSSH_CS8, mode, &idx);
        TTYSet((term.c_cflag &  PARENB), WOLFSSH_PARENB, mode, &idx);
        TTYSet((term.c_cflag &  PARODD), WOLFSSH_PARODD, mode, &idx);
    }
    #else
    {
        /* No termios. Just set the bitrate to 38400. */
        TTYWordSet(38400, WOLFSSH_TTY_OP_ISPEED, mode, &idx);
        TTYWordSet(38400, WOLFSSH_TTY_OP_OSPEED, mode, &idx);
    }
    #endif /* !USE_WINDOWS_API && !MICROCHIP_PIC32 && !NO_TERMIOS */

    WOLFSSH_UNUSED(ssh);
    mode[idx++] = WOLFSSH_TTY_OP_END;
    return idx;
}


int SendChannelTerminalResize(WOLFSSH* ssh, word32 columns, word32 rows,
    word32 widthPixels, word32 heightPixels)
{
    int ret = WS_SUCCESS;
    byte* output;
    word32 idx;
    WOLFSSH_CHANNEL* channel = NULL;
    const char* cType = "window-change";
    word32 typeSz = 0;

    if (ret == WS_SUCCESS) {
        channel = ChannelFind(ssh,
                ssh->defaultPeerChannelId, WS_CHANNEL_ID_PEER);
        if (channel == NULL)
            ret = WS_INVALID_CHANID;
    }

    if (ret == WS_SUCCESS) {
        typeSz = (word32)WSTRLEN(cType);
        ret = PreparePacket(ssh, MSG_ID_SZ + UINT32_SZ + LENGTH_SZ +
                                 typeSz + BOOLEAN_SZ + (4 * UINT32_SZ));
    }

    if (ret == WS_SUCCESS) {
        output = ssh->outputBuffer.buffer;
        idx = ssh->outputBuffer.length;

        output[idx++] = MSGID_CHANNEL_REQUEST;
        c32toa(channel->peerChannel, output + idx);
        idx += UINT32_SZ;
        c32toa(typeSz, output + idx);
        idx += LENGTH_SZ;
        WMEMCPY(output + idx, cType, typeSz);
        idx += typeSz;
        output[idx++] = 0;

        c32toa(columns, output + idx);
        idx += UINT32_SZ;
        c32toa(rows, output + idx);
        idx += UINT32_SZ;
        c32toa(widthPixels, output + idx);
        idx += UINT32_SZ;
        c32toa(heightPixels, output + idx);
        idx += UINT32_SZ;

        ssh->outputBuffer.length = idx;

        WLOG(WS_LOG_INFO, "Sending Channel Request: ");
        WLOG(WS_LOG_INFO, "  channelId = %u", channel->peerChannel);
        WLOG(WS_LOG_INFO, "  type = %s", cType);
        WLOG(WS_LOG_INFO, "  wantReply = %u", 0);

        ret = BundlePacket(ssh);
    }

    if (ret == WS_SUCCESS)
        ret = wolfSSH_SendPacket(ssh);

    return ret;
}


#ifdef HAVE_SYS_IOCTL_H
    #include <sys/ioctl.h>
#endif

static void GetTerminalInfo(word32* width, word32* height,
        word32* pixWidth, word32* pixHeight, const char** term)
{
#ifdef HAVE_SYS_IOCTL_H
    struct winsize windowSize = { 0,0,0,0 };

    ioctl(STDOUT_FILENO, TIOCGWINSZ, &windowSize);
    *width  = (word32)windowSize.ws_col;
    *height = (word32)windowSize.ws_row;
    *pixWidth = (word32)windowSize.ws_xpixel;
    *pixHeight = (word32)windowSize.ws_ypixel;
    *term = getenv("TERM");
#elif defined(_MSC_VER)
    CONSOLE_SCREEN_BUFFER_INFO cs;

    if (GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &cs) != 0) {
        *width  = cs.srWindow.Right - cs.srWindow.Left + 1;
        *height = cs.srWindow.Bottom - cs.srWindow.Top + 1;
    }
#else
    /* sane defaults for terminal size if not yet supported */
    *width  = 80;
    *height = 24;
#endif
}


/* sends request for pseudo-terminal (rfc 4254)
 * returns WS_SUCCESS on success */
int SendChannelTerminalRequest(WOLFSSH* ssh)
{
    byte* output;
    word32 idx;
    int ret = WS_SUCCESS;
    WOLFSSH_CHANNEL* channel;
    const char cType[] = "pty-req";
    const char* term = NULL;
    byte mode[4096];
    word32 termSz, typeSz, modeSz;
    word32 w = 0, h = 0, pxW = 0, pxH = 0;

    WLOG(WS_LOG_DEBUG, "Entering SendChannelTerminalRequest()");

    if (ssh == NULL)
        ret = WS_BAD_ARGUMENT;

    GetTerminalInfo(&w, &h, &pxW, &pxH, &term);
    if (term == NULL) {
        term = "xterm";
    }
    termSz  = (word32)WSTRLEN(term);
    typeSz = (word32)WSTRLEN(cType);
    modeSz = CreateMode(ssh, mode);

    if (ret == WS_SUCCESS) {
        channel = ChannelFind(ssh,
                ssh->defaultPeerChannelId, WS_CHANNEL_ID_PEER);
        if (channel == NULL)
            ret = WS_INVALID_CHANID;
    }

    /*     craft packet with the following structure
     *     byte      MSGID_CHANNEL_REQUEST
     *     word32    channel
     *     string    "pty-req"
     *     boolean   want_reply
     *     string    term environment variable
     *     word32    terminal width
     *     word32    terminal height
     *     word32    terminal width (pixels)
     *     word32    terminal height (pixels)
     *     string    encoded terminal modes
     */

    if (ret == WS_SUCCESS) {
        ret = PreparePacket(ssh, MSG_ID_SZ + UINT32_SZ + LENGTH_SZ + typeSz
                + BOOLEAN_SZ + LENGTH_SZ + termSz + UINT32_SZ * 4
                + LENGTH_SZ + modeSz);
    }

    if (ret == WS_SUCCESS) {
        output = ssh->outputBuffer.buffer;
        idx    = ssh->outputBuffer.length;

        output[idx++] = MSGID_CHANNEL_REQUEST;
        c32toa(channel->peerChannel, output + idx); idx += UINT32_SZ;
        c32toa(typeSz, output + idx);               idx += LENGTH_SZ;
        WMEMCPY(output + idx, cType, typeSz);       idx += typeSz;
        output[idx++] = 1; /* want reply */

        c32toa(termSz, output + idx);
        idx += UINT32_SZ;
        if (termSz > 0) {
            WMEMCPY(output + idx, term, termSz);
            idx += termSz;
        }

        c32toa(w, output + idx);   idx += UINT32_SZ;
        c32toa(h, output + idx);   idx += UINT32_SZ;
        c32toa(pxW, output + idx); idx += UINT32_SZ;
        c32toa(pxH, output + idx); idx += UINT32_SZ;

        if (modeSz > 0) {
            c32toa(modeSz, output + idx);          idx += UINT32_SZ;
            WMEMCPY(output + idx, mode, modeSz);   idx += modeSz;
        }

        ssh->outputBuffer.length = idx;

        WLOG(WS_LOG_INFO, "Sending Pseudo-Terminal Channel Request: ");
        WLOG(WS_LOG_INFO, "  channelId = %u", channel->peerChannel);
        WLOG(WS_LOG_INFO, "  type = %s", cType);
        WLOG(WS_LOG_INFO, "  wantReply = %u", 1);
        WLOG(WS_LOG_INFO, "  (width , height) = (%d , %d)", w, h);
        WLOG(WS_LOG_INFO, "  pixels (width , height) = (%d , %d)", pxW, pxH);
        WLOG(WS_LOG_INFO, "  term mode = %s", mode);


        ret = BundlePacket(ssh);
    }

    if (ret == WS_SUCCESS)
        ret = wolfSSH_SendPacket(ssh);

    WLOG(WS_LOG_DEBUG, "Leaving SendChannelTerminalRequest(), ret = %d", ret);
    return ret;
}
#endif /* WOLFSSH_TERM */


#ifdef WOLFSSH_AGENT

int SendChannelAgentRequest(WOLFSSH* ssh)
{
    byte* output;
    word32 idx;
    int ret = WS_SUCCESS;
    WOLFSSH_CHANNEL* channel;
    const char* cType = "auth-agent-req@openssh.com";
    word32 typeSz;

    WLOG(WS_LOG_DEBUG, "Entering SendChannelRequestAgent()");

    if (ssh == NULL)
        ret = WS_BAD_ARGUMENT;

    if (ret == WS_SUCCESS) {
        channel = ChannelFind(ssh,
                ssh->defaultPeerChannelId, WS_CHANNEL_ID_PEER);
        if (channel == NULL)
            ret = WS_INVALID_CHANID;
    }

    if (ret == WS_SUCCESS) {
        typeSz = (word32)WSTRLEN(cType);
        ret = PreparePacket(ssh, MSG_ID_SZ + UINT32_SZ + LENGTH_SZ +
                                 typeSz + BOOLEAN_SZ);
    }

    if (ret == WS_SUCCESS) {
        output = ssh->outputBuffer.buffer;
        idx = ssh->outputBuffer.length;

        output[idx++] = MSGID_CHANNEL_REQUEST;
        c32toa(channel->peerChannel, output + idx);
        idx += UINT32_SZ;
        c32toa(typeSz, output + idx);
        idx += LENGTH_SZ;
        WMEMCPY(output + idx, cType, typeSz);
        idx += typeSz;
        output[idx++] = 0;

        ssh->outputBuffer.length = idx;

        WLOG(WS_LOG_INFO, "Sending Channel Request: ");
        WLOG(WS_LOG_INFO, "  channelId = %u", channel->peerChannel);
        WLOG(WS_LOG_INFO, "  type = %s", cType);
        WLOG(WS_LOG_INFO, "  wantReply = %u", 0);

        ret = BundlePacket(ssh);
    }

    if (ret == WS_SUCCESS)
        ret = wolfSSH_SendPacket(ssh);

    WLOG(WS_LOG_DEBUG, "Leaving SendChannelRequestAgent(), ret = %d", ret);
    return ret;
}

#endif /* WOLFSSH_AGENT */


int SendChannelSuccess(WOLFSSH* ssh, word32 channelId, int success)
{
    byte* output;
    word32 idx;
    int ret = WS_SUCCESS;
    WOLFSSH_CHANNEL* channel = NULL;

    WLOG(WS_LOG_DEBUG, "Entering SendChannelSuccess(), %s",
         success ? "Success" : "Failure");

    if (ssh == NULL)
        ret = WS_BAD_ARGUMENT;

    if (ret == WS_SUCCESS) {
        channel = ChannelFind(ssh, channelId, WS_CHANNEL_ID_SELF);
        if (channel == NULL) {
            WLOG(WS_LOG_DEBUG, "Invalid channel");
            ret = WS_INVALID_CHANID;
        }
    }

    if (ret == WS_SUCCESS)
        ret = PreparePacket(ssh, MSG_ID_SZ + UINT32_SZ);

    if (ret == WS_SUCCESS) {
        output = ssh->outputBuffer.buffer;
        idx = ssh->outputBuffer.length;

        output[idx++] = success ?
                        MSGID_CHANNEL_SUCCESS : MSGID_CHANNEL_FAILURE;
        c32toa(channel->peerChannel, output + idx);
        idx += UINT32_SZ;

        ssh->outputBuffer.length = idx;

        ret = BundlePacket(ssh);
    }

    if (ret == WS_SUCCESS)
        ret = wolfSSH_SendPacket(ssh);

    WLOG(WS_LOG_DEBUG, "Leaving SendChannelSuccess(), ret = %d", ret);
    return ret;
}


#if (defined(WOLFSSH_SFTP) || defined(WOLFSSH_SCP)) && \
    !defined(NO_WOLFSSH_SERVER)
/* cleans up absolute path
 * returns size of new path on success (strlen sz) and negative values on fail*/
int wolfSSH_CleanPath(WOLFSSH* ssh, char* in)
{
    int  i;
    long sz;
    byte found;
    char *path;
    void *heap = NULL;

    if (in == NULL) {
        return WS_BAD_ARGUMENT;
    }

    if (ssh != NULL) {
        heap = ssh->ctx->heap;
    }

    sz   = (long)WSTRLEN(in);
    path = (char*)WMALLOC(sz+1, heap, DYNTYPE_PATH);
    if (path == NULL) {
        return WS_MEMORY_E;
    }
    WMEMCPY(path, in, sz);
    path[sz] = '\0';

#if defined(WOLFSSL_NUCLEUS) || defined(USE_WINDOWS_API)
    for (i = 0; i < sz; i++) {
        if (path[i] == '/') path[i] = '\\';
    }
#endif
    sz = (long)WSTRLEN(path);

    /* remove any /./ patterns, direcotries, exclude cases like ./ok./test */
    for (i = 1; i + 1 < sz; i++) {
        if (path[i] == '.' && path[i - 1] == WS_DELIM && path[i + 1] == WS_DELIM) {
            WMEMMOVE(path + (i-1), path + (i+1), sz - (i-1));
            sz -= 2; /* removed '/.' from string*/
            i--;
        }
    }

    /* remove any double '/' or '\' chars */
    for (i = 0; i < sz; i++) {
        if ((path[i] == WS_DELIM && path[i+1] == WS_DELIM)) {
            WMEMMOVE(path + i, path + i + 1, sz - i);
            sz -= 1;
            i--;
        }
    }

    if (path != NULL) {
        /* go through path until no cases are found */
        do {
            int prIdx = 0; /* begin of cut */
            int enIdx = 0; /* end of cut */
            sz = (long)WSTRLEN(path);

            found = 0;
            for (i = 1; i < sz; i++) {
                if (path[i] == WS_DELIM) {
                    int z;

                    /* if next two chars are .. then delete */
                    if (path[i+1] == '.' && path[i+2] == '.') {
                        enIdx = i + 3;

                        /* start at one char before / and retrace path */
                        for (z = i - 1; z > 0; z--) {
                            if (path[z] == WS_DELIM || path[z] == ':') {
                                prIdx = z;
                                break;
                            }
                        }

                        /* cut out .. and previous */
                        WMEMMOVE(path + prIdx, path + enIdx, sz - enIdx);
                        path[sz - (enIdx - prIdx)] = '\0';

                        if (enIdx == sz) {
                            path[prIdx] = '\0';
                        }

                        /* case of at / */
                        if (WSTRLEN(path) == 0) {
                           path[0] = '/';
                           path[1] = '\0';
                        }

                        found = 1;
                        break;
                    }
                }
            }
        } while (found);

#if defined(WOLFSSL_NUCLEUS) || defined(USE_WINDOWS_API)
        sz = (long)WSTRLEN(path);

        if (path[sz - 1] == ':') {
            path[sz] = WS_DELIM;
            path[sz + 1] = '\0';
            in[sz] = WS_DELIM;
            in[sz + 1] = '\0';
        }

        /* clean up any multiple drive listed i.e. A:/A: */
        {
            int i,j;
            sz = (long)WSTRLEN(path);
            for (i = 0, j = 0; i < sz; i++) {
                if (path[i] == ':') {
                    if (j == 0) j = i;
                    else {
                        /* @TODO only checking once */
                        WMEMMOVE(path, path + i - WS_DRIVE_SIZE,
                                sz - i + WS_DRIVE_SIZE);
                        path[sz - i + WS_DRIVE_SIZE] = '\0';
                        break;
                    }
                }
            }
        }

        /* remove leading '/' for nucleus. Preserve case of single "/" */
        sz = (long)WSTRLEN(path);
        while (sz > 2 && path[0] == WS_DELIM) {
            sz--;
            WMEMMOVE(path, path + 1, sz);
            path[sz] = '\0';
        }
#endif

#ifndef FREESCALE_MQX
        /* remove trailing delimiter */
        if (sz > 3 && path[sz - 1] == WS_DELIM) {
            path[sz - 1] = '\0';
        }
#endif

#ifdef FREESCALE_MQX
        /* remove trailing '.' */
        if (path[sz - 1] == '.') {
            path[sz - 1] = '\0';
        }
#endif
    }

    /* copy result back to 'in' buffer */
    if (WSTRLEN(in) < WSTRLEN(path)) {
        WLOG(WS_LOG_ERROR, "Fatal error cleaning path");
        WFREE(path, heap, DYNTYPE_PATH);
        return WS_BUFFER_E;
    }
    sz = (long)WSTRLEN(path);
    WMEMCPY(in, path, sz);
    in[sz] = '\0';
    WFREE(path, heap, DYNTYPE_PATH);
    return (int)sz;
}
#endif /* WOLFSSH_SFTP || WOLFSSH_SCP */



#define LINE_WIDTH 16
void DumpOctetString(const byte* input, word32 inputSz)
{
    int rows = inputSz / LINE_WIDTH;
    int remainder = inputSz % LINE_WIDTH;
    int i,j;
    char text[17];
    byte c;

    for (i = 0; i < rows; i++) {
        XMEMSET(text, 0, sizeof text);
        printf("%04X: ", i * LINE_WIDTH);
        for (j = 0; j < LINE_WIDTH; j++) {
            c = input[i * LINE_WIDTH + j];
            printf("%02X ", c);
            text[j] = isprint(c) ? (char)c : '.';
        }
        printf(" %s\n", text);
    }
    if (remainder) {
        XMEMSET(text, 0, sizeof text);
        printf("%04X: ", i * LINE_WIDTH);
        for (j = 0; j < remainder; j++) {
            c = input[i * LINE_WIDTH + j];
            printf("%02X ", c);
            text[j] = isprint(c) ? c : '.';
        }
        for (; j < LINE_WIDTH; j++) {
            printf("   ");
        }
        printf(" %s\n", text);
    }
}


#ifdef WOLFSSH_SFTP

/* converts the octal input to decimal. Input is in string format i.e. 0666
 * returns the decimal value on success or negative value on failure */
int wolfSSH_oct2dec(WOLFSSH* ssh, byte* oct, word32 octSz)
{
    int ret;
    word32 i;

    if (octSz > WOLFSSH_MAX_OCTET_LEN || ssh == NULL || oct == NULL) {
        return WS_BAD_ARGUMENT;
    }

    /* convert octal string to int without mp_read_radix() */
    ret = 0;

    for (i = 0; i < octSz; i++)
    {
        if (oct[i] < '0' || oct[0] > '7') {
            ret = WS_BAD_ARGUMENT;
            break;
        }
        ret <<= 3;
        ret |= (oct[i] - '0');
    }

    return ret;
}


/* addend1 += addend2 */
void AddAssign64(word32* addend1, word32 addend2)
{
    if (addend1[0] > (WOLFSSL_MAX_32BIT - addend2)) {
        addend1[1]++;

        /* -1 to account for roll over digit */
        addend1[0] = addend2 - (WOLFSSL_MAX_32BIT- addend1[0]) - 1;
    }
    else {
        addend1[0] += addend2;
    }
}

#endif /* WOLFSSH_SFTP */

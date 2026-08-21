/* wolfssh-options.c
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


/*
 * Build option probe for the test scripts. Prints each enabled build option,
 * one per line. Not installed; a build tree artifact only.
 *
 *     OPTIONS=$(./apps/wolfssh-options) || exit 1
 *     if ! echo "$OPTIONS" | grep -qx "FPKI"; then
 *         echo "built without FPKI, skipping"
 *         exit 77
 *     fi
 *
 * scripts/ runs from the build root and calls "./apps/wolfssh-options"; the
 * wolfSSHd tests source ./wolfssh_options.sh for it. Match whole lines, so one
 * option name cannot match another that has it as a prefix. A probe that will
 * not run is a build problem, not an option being off.
 *
 * Each option prints under the same guard the library uses, so the output is
 * the preprocessor's answer for this build. Covers every configure
 * --enable/--disable that sets a macro, plus a few facts from the wolfSSL
 * build; not --enable-examples, which defines nothing to test.
 *
 * To add an option, add a guard and a printf() below.
 */


#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif
#ifdef WOLFSSL_USER_SETTINGS
    #include <wolfssl/wolfcrypt/settings.h>
#else
    #include <wolfssl/options.h>
#endif
#include <wolfssh/ssh.h>
#include <wolfssh/internal.h>
#include <stdio.h>

/* internal.h derives the WOLFSSH_NO_* options from the wolfSSL build. */
#ifndef _WOLFSSH_INTERNAL_H_
    #error "wolfssh-options.c requires wolfssh/internal.h"
#endif


int main(void)
{
    /* Library features. NO_INLINE is shared with wolfSSL's --disable-inline,
     * so INLINE is the effective state, not wolfSSH's configure answer. */
#ifndef NO_INLINE
    printf("INLINE\n");
#endif
#ifndef NO_WOLFSSH_SERVER
    printf("SERVER\n");
#endif
#ifndef NO_WOLFSSH_CLIENT
    printf("CLIENT\n");
#endif
#ifdef WOLFSSH_KEYGEN
    printf("KEYGEN\n");
#endif
#ifdef WOLFSSH_KEYBOARD_INTERACTIVE
    printf("KEYBOARD_INTERACTIVE\n");
#endif
#ifdef WOLFSSH_SCP
    printf("SCP\n");
#endif
#ifdef WOLFSSH_SFTP
    printf("SFTP\n");
#endif
#if defined(WOLFSSH_SFTP) && !defined(WOLFSSH_NO_SFTP_BUFFER_ZERO)
    printf("SFTP_ZEROIZE\n");
#endif
#ifdef WOLFSSH_FWD
    printf("FWD\n");
#endif
#ifdef WOLFSSH_TERM
    printf("TERM\n");
#endif
#ifdef WOLFSSH_SHELL
    printf("SHELL\n");
#endif
#ifdef WOLFSSH_AGENT
    printf("AGENT\n");
#endif
#ifdef WOLFSSH_TPM
    printf("TPM\n");
#endif
#ifdef WOLFSSH_SMALL_STACK
    printf("SMALL_STACK\n");
#endif
#ifdef WOLFSSH_ALLOW_NONE_CIPHER
    printf("NONE_CIPHER\n");
#endif
    /* Same guard as WOLFSSHD_HOSTKEY_RELAX_PERMS in wolfsshd.c; keep the two in
     * step. The sshd tests use this to skip the host key negative cases. */
#if defined(WOLFSSH_NO_HOSTKEY_PERMS) && \
        (defined(__QNX__) || defined(__QNXNTO__))
    printf("HOSTKEY_RELAX_PERMS\n");
#endif
    /* Same guard as wIsSymlink in port.h. */
#if defined(WOLFSSH_HAVE_SYMLINK) && \
        (defined(WOLFSSH_SFTP) || defined(WOLFSSH_SCP))
    printf("SYMLINK_CHECK\n");
#endif

    /* Certificates. */
#ifdef WOLFSSH_CERTS
    printf("CERTS\n");
#endif
#ifdef WOLFSSH_OSSH_CERTS
    printf("OSSH_CERTS\n");
#endif
    /* Gates wolfSSHd's AuthorizedUPNDomains check, the same guard auth.c
     * uses, plus cert support, without which no cert reaches it. Not
     * WOLFSSH_NO_FPKI: that only turns off certman.c's profile enforcement,
     * which most CI workflows do. */
#if defined(WOLFSSL_FPKI) && defined(WOLFSSH_CERTS)
    printf("FPKI\n");
#endif

    /* PQC Options */
#ifndef WOLFSSH_NO_MLDSA
    printf("MLDSA\n");
#endif
    /* Same guard as cannedKeyAlgoNamesHostKey in src/internal.c: the
     * composite needs the ECDSA half too. */
#if !defined(WOLFSSH_NO_MLDSA87) && \
        !defined(WOLFSSH_NO_ECDSA_SHA2_NISTP384) && !defined(NO_SHA512)
    printf("MLDSA87_ES384\n");
#endif

    /* Applications. */
#ifdef WOLFSSH_SSHCLIENT
    printf("SSHCLIENT\n");
#endif
#ifdef WOLFSSH_SSHD
    printf("SSHD\n");
#endif

    /* wolfSSHd password check backends; with none, no password login. */
#ifdef WOLFSSH_USE_PAM
    printf("PAM\n");
#endif
#ifdef WOLFSSH_HAVE_LIBCRYPT
    printf("LIBCRYPT\n");
#endif
#ifdef WOLFSSH_HAVE_LIBLOGIN
    printf("LIBLOGIN\n");
#endif

    /* --enable-debug, so there is WLOG() output to inspect. */
#ifdef DEBUG_WOLFSSH
    printf("DEBUG\n");
#endif

    /* Fault injected non-blocking IO, so the examples need -N. */
#ifdef WOLFSSH_TEST_BLOCK
    printf("TEST_BLOCK\n");
#endif

    return 0;
}

/* sftpclient.c
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
#include <wolfssh/wolfsftp.h>
#include <wolfssh/test.h>
#include <wolfssh/port.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/coding.h>
#include "examples/sftpclient/sftpclient.h"
#include "examples/client/common.h"
#if !defined(USE_WINDOWS_API) && !defined(MICROCHIP_PIC32) && \
    !defined(WOLFSSH_ZEPHYR)
    #include <termios.h>
#endif

#ifdef WOLFSSH_CERTS
    #include <wolfssl/wolfcrypt/asn.h>
#endif

#if defined(WOLFSSH_SFTP) && !defined(NO_WOLFSSH_CLIENT)

/* static so that signal handler can access and interrupt get/put */
static WOLFSSH* ssh = NULL;
static char* workingDir;
#define fin stdin
#define fout stdout
#define MAX_CMD_SZ 7


#define AUTOPILOT_OFF 0
#define AUTOPILOT_GET 1
#define AUTOPILOT_PUT 2


#ifdef WOLFSSH_STATIC_MEMORY
    #include <wolfssl/wolfcrypt/memory.h>

    typedef WOLFSSL_HEAP_HINT SFTPC_HEAP_HINT;

     /* This static buffer is tuned for building with SFTP only. The static
      * buffer size is calulated by multiplying the pairs of sizeList items
      * and distList items and summing (32*50 + 128*100 + ...) and adding
      * the sum of the distList values times the sizeof wc_Memory (rounded up
      * to a word, 24). This total was 268kb plus change, rounded up to 269. */
    #ifndef SFTPC_STATIC_SIZES
        #define SFTPC_STATIC_SIZES 64,128,384,800,3120,8400,17552,33104,131072
    #endif
    #ifndef SFTPC_STATIC_DISTS
        #define SFTPC_STATIC_DISTS 60,100,4,6,5,2,1,2,1
    #endif
    #ifndef SFTPC_STATIC_LISTSZ
        #define SFTPC_STATIC_LISTSZ 9
    #endif
    #ifndef SFTPC_STATIC_BUFSZ
        #define SFTPC_STATIC_BUFSZ (269*1024)
    #endif
    static const word32 static_sizeList[] = {SFTPC_STATIC_SIZES};
    static const word32 static_distList[] = {SFTPC_STATIC_DISTS};
    static byte static_buffer[SFTPC_STATIC_BUFSZ];
#else /* WOLFSSH_STATIC_MEMORY */
    typedef void SFTPC_HEAP_HINT;
#endif /* WOLFSSH_STATIC_MEMORY */


static void err_msg(const char* s)
{
    printf("%s\n", s);
}


#ifndef WOLFSSH_NO_TIMESTAMP

    static char   currentFile[WOLFSSH_MAX_FILENAME + 1] = "";
    static word32 startTime;
    #define TIMEOUT_VALUE 120

    word32 current_time(int);
#ifdef USE_WINDOWS_API
    #include <time.h>
    #define WIN32_LEAN_AND_MEAN
    #include <windows.h>

    word32 current_time(int reset)
    {
        static int init = 0;
        static LARGE_INTEGER freq;

        LARGE_INTEGER count;

        (void)reset;

        if (!init) {
            QueryPerformanceFrequency(&freq);
            init = 1;
        }

        QueryPerformanceCounter(&count);

        return (word32)(count.QuadPart / freq.QuadPart);
    }
#else
    #include <sys/time.h>

    /* return number of seconds*/
    word32 current_time(int reset)
    {
        struct timeval tv;

        (void)reset;

        gettimeofday(&tv, 0);
        return (word32)tv.tv_sec;
    }
#endif /* USE_WINDOWS_API */
#endif /* !WOLFSSH_NO_TIMESTAMP */


static void myStatusCb(WOLFSSH* sshIn, word32* bytes, char* name)
{
    word32 currentTime;
    char buf[80];
    word64 longBytes = ((word64)bytes[1] << 32) | bytes[0];

#ifndef WOLFSSH_NO_TIMESTAMP
    if (WSTRNCMP(currentFile, name, WSTRLEN(name)) != 0) {
        startTime = current_time(1);
        WMEMSET(currentFile, 0, WOLFSSH_MAX_FILENAME);
        WSTRNCPY(currentFile, name, WOLFSSH_MAX_FILENAME);
    }
    currentTime = current_time(0) - startTime;
    WSNPRINTF(buf, sizeof(buf), "Processed %8llu\t bytes in %d seconds\r",
            (unsigned long long)longBytes, currentTime);
#ifndef WOLFSSH_NO_SFTP_TIMEOUT
    if (currentTime > TIMEOUT_VALUE) {
        WSNPRINTF(buf, sizeof(buf), "\nProcess timed out at %d seconds, "
                "stopping\r", currentTime);
        WMEMSET(currentFile, 0, WOLFSSH_MAX_FILENAME);
        wolfSSH_SFTP_Interrupt(ssh);
    }
#endif
#else
    WSNPRINTF(buf, sizeof(buf), "Processed %8llu\t bytes \r",
            (unsigned long long)longBytes);
    (void)currentTime;
#endif
    WFPUTS(buf, fout);
    (void)name;
    (void)sshIn;
}


static int NonBlockSSH_connect(void)
{
    int ret;
    int error;
    SOCKET_T sockfd;
    int select_ret = 0;

    ret = wolfSSH_SFTP_connect(ssh);
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
            select_ret == WS_SELECT_ERROR_READY ||
            error == WS_WANT_WRITE)
        {
            ret = wolfSSH_SFTP_connect(ssh);
            error = wolfSSH_get_error(ssh);
        }
        else if (select_ret == WS_SELECT_TIMEOUT)
            error = WS_WANT_READ;
        else
            error = WS_FATAL_ERROR;
    }

    return ret;
}


#ifndef WS_NO_SIGNAL
/* for command reget and reput to handle saving offset after interrupt during
 * get and put */
#include <signal.h>
static byte interrupt = 0;

static void sig_handler(const int sig)
{
    (void)sig;

    interrupt = 1;
    wolfSSH_SFTP_Interrupt(ssh);
}
#endif /* WS_NO_SIGNAL */

/* cleans up absolute path */
static void clean_path(char* path)
{
    int  i;
    long sz = (long)WSTRLEN(path);
    byte found;

    /* remove any double '/' chars */
    for (i = 0; i < sz; i++) {
        if (path[i] == '/' && path[i+1] == '/') {
            WMEMMOVE(path + i, path + i + 1, sz - i);
            sz -= 1;
            i--;
        }
    }

    /* remove any trailing '/' chars */
    sz = (long)WSTRLEN(path);
    for (i = (int)sz - 1; i > 0; i--) {
        if (path[i] == '/') {
            path[i] = '\0';
        }
        else {
            break;
        }
    }

    if (path != NULL) {
        /* go through path until no cases are found */
        do {
            int prIdx = 0; /* begin of cut */
            int enIdx = 0; /* end of cut */
            sz = (long)WSTRLEN(path);

            found = 0;
            for (i = 0; i < sz; i++) {
                if (path[i] == '/') {
                    int z;

                    /* if next two chars are .. then delete */
                    if (path[i+1] == '.' && path[i+2] == '.') {
                        enIdx = i + 3;

                        /* start at one char before / and retrace path */
                        for (z = i - 1; z > 0; z--) {
                            if (path[z] == '/') {
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
    }
}

#define WS_MAX_EXAMPLE_RW 1024

static void ShowCommands(void)
{
    printf("\n\nCommands :\n");
    printf("\tcd  <string>                      change directory\n");
    printf("\tchmod <mode> <path>               change mode\n");
    printf("\tget <remote file> <local file>    pulls file(s) from server\n");
    printf("\tls                                list current directory\n");
    printf("\tmkdir <dir name>                  creates new directory on server\n");
    printf("\tput <local file> <remote file>    push file(s) to server\n");
    printf("\tpwd                               list current path\n");
    printf("\tquit                              exit\n");
    printf("\trename <old> <new>                renames remote file\n");
    printf("\treget <remote file> <local file>  resume pulling file\n");
    printf("\treput <remote file> <local file>  resume pushing file\n");
    printf("\t<crtl + c>                        interrupt get/put cmd\n");

}

static void ShowUsage(void)
{
    printf("wolfsftp %s\n", LIBWOLFSSH_VERSION_STRING);
    printf(" -?            display this help and exit\n");
    printf(" -h <host>     host to connect to, default %s\n", wolfSshIp);
    printf(" -p <num>      port to connect on, default %d\n", wolfSshPort);
    printf(" -u <username> username to authenticate as (REQUIRED)\n");
    printf(" -P <password> password for username, prompted if omitted\n");
    printf(" -d <path>     set the default local path\n");
    printf(" -N            use non blocking sockets\n");
    printf(" -e            use ECC user authentication\n");
    /*printf(" -E            use ECC server authentication\n");*/
    printf(" -l <filename> local filename\n");
    printf(" -r <filename> remote filename\n");
    printf(" -g            put local filename as remote filename\n");
    printf(" -G            get remote filename as local filename\n");
    printf(" -i <filename> filename for the user's private key\n");
#ifdef WOLFSSH_CERTS
    printf(" -J <filename> filename for DER certificate to use\n");
    printf("               Certificate example : client -u orange \\\n");
    printf("               -J orange-cert.der -i orange-key.der\n");
    printf(" -A <filename> filename for DER CA certificate to verify host\n");
    printf(" -X            Ignore IP checks on peer vs peer certificate\n");
#endif

    ShowCommands();
}


/* returns 0 on success */
static INLINE int SFTP_FPUTS(func_args* args, const char* msg)
{
    int ret;

    if (args && args->sftp_cb)
        ret = args->sftp_cb(msg, NULL, 0);
    else
        ret = WFPUTS(msg, fout);

    return ret;
}


/* returns pointer on success, NULL on failure */
static INLINE char* SFTP_FGETS(func_args* args, char* msg, int msgSz)
{
    char* ret = NULL;

    WMEMSET(msg, 0, msgSz);
    if (args && args->sftp_cb) {
        if (args->sftp_cb(NULL, msg, msgSz) == 0)
            ret = msg;
    }
    else
        ret = WFGETS(msg, msgSz, fin);

    return ret;
}


/* main loop for handling commands */
static int doCmds(func_args* args)
{
    byte quit = 0;
    int ret = WS_SUCCESS, err;
    byte resume = 0;
    int i;

    do {
        char msg[WOLFSSH_MAX_FILENAME * 2];
        char* pt;

        if (wolfSSH_get_error(ssh) == WS_SOCKET_ERROR_E) {
            if (SFTP_FPUTS(args, "peer disconnected\n") < 0) {
                err_msg("fputs error");
                return -1;
            }
            return WS_SOCKET_ERROR_E;
        }

        if (SFTP_FPUTS(args, "wolfSSH sftp> ") < 0) {
            err_msg("fputs error");
            return -1;
        }
        WFFLUSH(stdout);

        WMEMSET(msg, 0, sizeof(msg));
        if (SFTP_FGETS(args, msg, sizeof(msg) - 1) == NULL) {
            err_msg("fgets error");
            return -1;
        }
        msg[WOLFSSH_MAX_FILENAME * 2 - 1] = '\0';

        if ((pt = WSTRNSTR(msg, "mkdir", sizeof(msg))) != NULL) {
            WS_SFTP_FILEATRB atrb;
            int sz;
            char* f = NULL;

            pt += sizeof("mkdir");
            sz = (int)WSTRLEN(pt);

            if (pt[sz - 1] == '\n') pt[sz - 1] = '\0';
            if (pt[0] != '/') {
                int maxSz = (int)WSTRLEN(workingDir) + sz + 2;
                f = (char*)WMALLOC(maxSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                if (f == NULL)
                    return WS_MEMORY_E;

                f[0] = '\0';
                WSTRNCAT(f, workingDir, maxSz);
                WSTRNCAT(f, "/", maxSz);
                WSTRNCAT(f, pt, maxSz);

                pt = f;
            }

            do {
                err = WS_SUCCESS;
                if ((ret = wolfSSH_SFTP_MKDIR(ssh, pt, &atrb)) != WS_SUCCESS) {
                    err = wolfSSH_get_error(ssh);
                    if (ret == WS_PERMISSIONS) {
                        if (SFTP_FPUTS(args, "Insufficient permissions\n") < 0) {
                            err_msg("fputs error");
                            return -1;
                        }
                    }
                    else if (err != WS_WANT_READ && err != WS_WANT_WRITE) {
                        if (SFTP_FPUTS(args, "Error writing directory\n") < 0) {
                            err_msg("fputs error");
                            return -1;
                        }
                    }
                }
            } while ((err == WS_WANT_READ || err == WS_WANT_WRITE)
                        && ret != WS_SUCCESS);
            WFREE(f, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            continue;
        }

        if (WSTRNSTR(msg, "reget", MAX_CMD_SZ) != NULL) {
            resume = 1;
        }

        if ((pt = WSTRNSTR(msg, "get", MAX_CMD_SZ)) != NULL) {
            int sz;
            char* f  = NULL;
            char* to = NULL;

            pt += sizeof("get");

            sz = (int)WSTRLEN(pt);
            if (pt[sz - 1] == '\n') pt[sz - 1] = '\0';

            /* search for space delimiter */
            to = pt;
            for (i = 0; i < sz; i++) {
                to++;
                if (pt[i] == ' ') {
                    pt[i] = '\0';
                    break;
                }
            }

            /* check if local file path listed */
            if (WSTRLEN(to) <= 0) {

                to = pt;
                /* if local path not listed follow path till at the tail */
                for (i = 0; i < sz; i++) {
                    if (pt[i] == '/') {
                        to = pt + i + 1;
                    }
                }
            }

            if (pt[0] != '/') {
                int maxSz = (int)(WSTRLEN(workingDir) + sz + 2);
                f = (char*)WMALLOC(maxSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                if (f == NULL) {
                    err_msg("Error malloc'ing");
                    return -1;
                }

                f[0] = '\0';
                WSTRNCAT(f, workingDir, maxSz);
                if (WSTRLEN(workingDir) > 1) {
                    WSTRNCAT(f, "/", maxSz);
                }
                WSTRNCAT(f, pt, maxSz);

                pt = f;
            }

            {
                char buf[WOLFSSH_MAX_FILENAME * 3];
                if (resume) {
                    WSNPRINTF(buf, sizeof(buf), "resuming %s to %s\n", pt, to);
                }
                else {
                    WSNPRINTF(buf, sizeof(buf), "fetching %s to %s\n", pt, to);
                }
                if (SFTP_FPUTS(args, buf) < 0) {
                    err_msg("fputs error");
                    return -1;
                }
            }

            do {
                while (ret == WS_REKEYING || ssh->error == WS_REKEYING) {
                    ret = wolfSSH_worker(ssh, NULL);
                    if (ret != WS_SUCCESS && ret == WS_FATAL_ERROR) {
                        ret = wolfSSH_get_error(ssh);
                    }
                }

                ret = wolfSSH_SFTP_Get(ssh, pt, to, resume, &myStatusCb);
                if (ret != WS_SUCCESS && ret == WS_FATAL_ERROR) {
                    ret = wolfSSH_get_error(ssh);
                }
            } while (ret == WS_WANT_READ || ret == WS_WANT_WRITE ||
                    ret == WS_CHAN_RXD || ret == WS_REKEYING);

#ifndef WOLFSSH_NO_TIMESTAMP
            WMEMSET(currentFile, 0, WOLFSSH_MAX_FILENAME);
#endif

            if (ret != WS_SUCCESS) {
                if (wolfSSH_get_error(ssh) == WS_SFTP_NOT_FILE_E) {
                    if (SFTP_FPUTS(args, "Not a regular file\n")  < 0) {
                         err_msg("fputs error");
                         return -1;
                    }
                }
                if (SFTP_FPUTS(args, "Error getting file\n")  < 0) {
                     err_msg("fputs error");
                     return -1;
                }
            }
            else {
                if (SFTP_FPUTS(args, "\n") < 0) { /* new line after status output */
                     err_msg("fputs error");
                     return -1;
                }
            }
            resume = 0;
            WFREE(f, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            continue;
        }


        if (WSTRNSTR(msg, "reput", MAX_CMD_SZ) != NULL) {
            resume = 1;
        }

        if ((pt = WSTRNSTR(msg, "put", MAX_CMD_SZ)) != NULL) {
            int sz;
            char* f  = NULL;
            char* to = NULL;

            pt += sizeof("put");
            sz = (int)WSTRLEN(pt);

            if (pt[sz - 1] == '\n') pt[sz - 1] = '\0';

            to = pt;
            for (i = 0; i < sz; i++) {
                to++;
                if (pt[i] == ' ') {
                    pt[i] = '\0';
                    break;
                }
            }

            /* check if local file path listed */
            if (WSTRLEN(to) <= 0) {

                to = pt;
                /* if local path not listed follow path till at the tail */
                for (i = 0; i < sz; i++) {
                    if (pt[i] == '/') {
                        to = pt + i + 1;
                    }
                }
            }

            if (to[0] != '/') {
                int maxSz = (int)WSTRLEN(workingDir) + sz + 2;
                f = (char*)WMALLOC(maxSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                if (f == NULL) {
                    err_msg("Error malloc'ing");
                    return -1;
                }

                f[0] = '\0';
                WSTRNCAT(f, workingDir, maxSz);
                if (WSTRLEN(workingDir) > 1) {
                    WSTRNCAT(f, "/", maxSz);
                }
                WSTRNCAT(f, to, maxSz);

                to = f;
            }

            {
                char buf[WOLFSSH_MAX_FILENAME * 3];
                if (resume) {
                    WSNPRINTF(buf, sizeof(buf), "resuming %s to %s\n", pt, to);
                }
                else {
                    WSNPRINTF(buf, sizeof(buf), "pushing %s to %s\n", pt, to);
                }
                if (SFTP_FPUTS(args, buf) < 0) {
                     err_msg("fputs error");
                     return -1;
                }

            }

            do {
                while (ret == WS_REKEYING || ssh->error == WS_REKEYING) {
                    ret = wolfSSH_worker(ssh, NULL);
                    if (ret != WS_SUCCESS && ret == WS_FATAL_ERROR) {
                        ret = wolfSSH_get_error(ssh);
                    }
                }

                ret = wolfSSH_SFTP_Put(ssh, pt, to, resume, &myStatusCb);
                if (ret != WS_SUCCESS && ret == WS_FATAL_ERROR) {
                    ret = wolfSSH_get_error(ssh);
                }
            } while (ret == WS_WANT_READ || ret == WS_WANT_WRITE ||
                    ret == WS_CHAN_RXD || ret == WS_REKEYING);

#ifndef WOLFSSH_NO_TIMESTAMP
            WMEMSET(currentFile, 0, WOLFSSH_MAX_FILENAME);
#endif

            if (ret != WS_SUCCESS) {
                if (wolfSSH_get_error(ssh) == WS_SFTP_NOT_FILE_E) {
                    if (SFTP_FPUTS(args, "Not a regular file\n")  < 0) {
                         err_msg("fputs error");
                         return -1;
                    }
                }
                if (SFTP_FPUTS(args, "Error pushing file\n") < 0) {
                    err_msg("fputs error");
                    return -1;
                }
            }
            else {
                if (SFTP_FPUTS(args, "\n") < 0) { /* new line after status output */
                    err_msg("fputs error");
                    return -1;
                }
            }
            resume = 0;
            WFREE(f, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            continue;
        }

        if ((pt = WSTRNSTR(msg, "cd", MAX_CMD_SZ)) != NULL) {
            WS_SFTP_FILEATRB atrb;
            int sz;
            char* f = NULL;

            pt += sizeof("cd");
            sz = (int)WSTRLEN(pt);

            if (pt[sz - 1] == '\n') pt[sz - 1] = '\0';
            if (pt[0] != '/') {
                int maxSz = (int)WSTRLEN(workingDir) + sz + 2;
                f = (char*)WMALLOC(maxSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                if (f == NULL) {
                    err_msg("Error malloc'ing");
                    return -1;
                }

                f[0] = '\0';
                WSTRNCAT(f, workingDir, maxSz);
                if (WSTRLEN(workingDir) > 1) {
                    WSTRNCAT(f, "/", maxSz);
                }
                WSTRNCAT(f, pt, maxSz);

                pt = f;
            }

            /* check directory is valid */
            do {
                ret = wolfSSH_SFTP_STAT(ssh, pt, &atrb);
                err = wolfSSH_get_error(ssh);
            } while ((err == WS_WANT_READ || err == WS_WANT_WRITE)
                        && ret != WS_SUCCESS);
            if (ret != WS_SUCCESS) {
                if (SFTP_FPUTS(args, "Error changing directory\n") < 0) {
                    err_msg("fputs error");
                    return -1;
                }
            }

            if (ret == WS_SUCCESS) {
                sz = (int)WSTRLEN(pt);
                WFREE(workingDir, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                workingDir = (char*)WMALLOC(sz + 1, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                if (workingDir == NULL) {
                    err_msg("Error malloc'ing");
                    return -1;
                }
                WMEMCPY(workingDir, pt, sz);
                workingDir[sz] = '\0';

                clean_path(workingDir);
            }
            WFREE(f, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            continue;
        }

        if ((pt = WSTRNSTR(msg, "chmod", MAX_CMD_SZ)) != NULL) {
            word32 sz, idx;
            char* f = NULL;
            char mode[WOLFSSH_MAX_OCTET_LEN];

            pt += sizeof("chmod");
            sz = (word32)WSTRLEN(pt);

            if (pt[sz - 1] == '\n') pt[sz - 1] = '\0';

            /* advance pointer to first location of non space character */
            for (idx = 0; idx < sz && pt[0] == ' '; idx++, pt++);
            sz = (word32)WSTRLEN(pt);

            /* get mode */
            sz = (sz < WOLFSSH_MAX_OCTET_LEN - 1)? sz :
                                                   WOLFSSH_MAX_OCTET_LEN -1;
            WMEMCPY(mode, pt, sz);
            mode[WOLFSSH_MAX_OCTET_LEN - 1] = '\0';
            for (idx = 0; idx < sz; idx++) {
                if (mode[idx] == ' ') {
                    mode[idx] = '\0';
                    break;
                }
            }
            if (idx == 0) {
                printf("error with getting mode\r\n");
                continue;
            }
            pt += (word32)WSTRLEN(mode);
            sz = (word32)WSTRLEN(pt);
            for (idx = 0; idx < sz && pt[0] == ' '; idx++, pt++);

            if (pt[0] != '/') {
                int maxSz = (int)WSTRLEN(workingDir) + sz + 2;
                f = (char*)WMALLOC(maxSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                if (f == NULL) {
                    err_msg("Error malloc'ing");
                    return -1;
                }

                f[0] = '\0';
                WSTRNCAT(f, workingDir, maxSz);
                if (WSTRLEN(workingDir) > 1) {
                    WSTRNCAT(f, "/", maxSz);
                }
                WSTRNCAT(f, pt, maxSz);

                pt = f;
            }

            /* update permissions */
            do {
                ret = wolfSSH_SFTP_CHMOD(ssh, pt, mode);
                err = wolfSSH_get_error(ssh);
            } while ((err == WS_WANT_READ || err == WS_WANT_WRITE)
                        && ret != WS_SUCCESS);
            if (ret != WS_SUCCESS) {
                if (SFTP_FPUTS(args, "Unable to change permissions of ") < 0) {
                    err_msg("fputs error");
                    return -1;
                }
                if (SFTP_FPUTS(args, pt) < 0) {
                    err_msg("fputs error");
                    return -1;
                }
                if (SFTP_FPUTS(args, "\n") < 0) {
                    err_msg("fputs error");
                    return -1;
                }
            }

            WFREE(f, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            continue;
        }

        if ((pt = WSTRNSTR(msg, "rmdir", MAX_CMD_SZ)) != NULL) {
            int sz;
            char* f = NULL;

            pt += sizeof("rmdir");
            sz = (int)WSTRLEN(pt);

            if (pt[sz - 1] == '\n') pt[sz - 1] = '\0';
            if (pt[0] != '/') {
                int maxSz = (int)WSTRLEN(workingDir) + sz + 2;
                f = (char*)WMALLOC(maxSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                if (f == NULL) {
                    err_msg("Error malloc'ing");
                    return -1;
                }

                f[0] = '\0';
                WSTRNCAT(f, workingDir, maxSz);
                if (WSTRLEN(workingDir) > 1) {
                    WSTRNCAT(f, "/", maxSz);
                }
                WSTRNCAT(f, pt, maxSz);

                pt = f;
            }

            do {
                ret = wolfSSH_SFTP_RMDIR(ssh, pt);
                err = wolfSSH_get_error(ssh);
            } while ((err == WS_WANT_READ || err == WS_WANT_WRITE)
                        && ret != WS_SUCCESS);
            if (ret != WS_SUCCESS) {
                if (ret == WS_PERMISSIONS) {
                    if (SFTP_FPUTS(args, "Insufficient permissions\n") < 0) {
                        err_msg("fputs error");
                        return -1;
                    }
                }
                else {
                    if (SFTP_FPUTS(args, "Error writing directory\n") < 0) {
                        err_msg("fputs error");
                        return -1;
                    }
                }
            }
            WFREE(f, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            continue;
        }


        if ((pt = WSTRNSTR(msg, "rm", MAX_CMD_SZ)) != NULL) {
            int sz;
            char* f = NULL;

            pt += sizeof("rm");
            sz = (int)WSTRLEN(pt);

            if (pt[sz - 1] == '\n') pt[sz - 1] = '\0';
            if (pt[0] != '/') {
                int maxSz = (int)WSTRLEN(workingDir) + sz + 2;
                f = (char*)WMALLOC(maxSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);

                f[0] = '\0';
                WSTRNCAT(f, workingDir, maxSz);
                if (WSTRLEN(workingDir) > 1) {
                    WSTRNCAT(f, "/", maxSz);
                }
                WSTRNCAT(f, pt, maxSz);

                pt = f;
            }

            do {
                ret = wolfSSH_SFTP_Remove(ssh, pt);
                err = wolfSSH_get_error(ssh);
            } while ((err == WS_WANT_READ || err == WS_WANT_WRITE)
                        && ret != WS_SUCCESS);
            if (ret != WS_SUCCESS) {
                if (ret == WS_PERMISSIONS) {
                    if (SFTP_FPUTS(args, "Insufficient permissions\n") < 0) {
                        err_msg("fputs error");
                        return -1;
                    }
                }
                else {
                    if (SFTP_FPUTS(args, "Error writing directory\n") < 0) {
                        err_msg("fputs error");
                        return -1;
                    }
                }
            }
            WFREE(f, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            continue;
        }

        if ((pt = WSTRNSTR(msg, "rename", MAX_CMD_SZ)) != NULL) {
            int sz;
            char* f   = NULL;
            char* fTo = NULL;
            char* to;
            int toSz;

            pt += sizeof("rename");
            sz = (int)WSTRLEN(pt);

            if (pt[sz - 1] == '\n') pt[sz - 1] = '\0';

            /* search for space delimiter */
            to = pt;
            for (i = 0; i < sz; i++) {
                to++;
                if (pt[i] == ' ') {
                    pt[i] = '\0';
                    break;
                }
            }
            if ((toSz = (int)WSTRLEN(to)) <= 0 || i == sz) {
                printf("bad usage, expected <old> <new> input\n");
                continue;
            }
            sz = (int)WSTRLEN(pt);

            if (pt[0] != '/') {
                int maxSz = (int)WSTRLEN(workingDir) + sz + 2;
                f = (char*)WMALLOC(maxSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                if (f == NULL) {
                    err_msg("Error malloc'ing");
                    return -1;
                }

                f[0] = '\0';
                WSTRNCAT(f, workingDir, maxSz);
                if (WSTRLEN(workingDir) > 1) {
                    WSTRNCAT(f, "/", maxSz);
                }
                WSTRNCAT(f, pt, maxSz);

                pt = f;
            }
            if (to[0] != '/') {
                int maxSz = (int)WSTRLEN(workingDir) + toSz + 2;
                fTo = (char*)WMALLOC(maxSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);

                fTo[0] = '\0';
                WSTRNCAT(fTo, workingDir, maxSz);
                if (WSTRLEN(workingDir) > 1) {
                    WSTRNCAT(fTo, "/", maxSz);
                }
                WSTRNCAT(fTo, to, maxSz);

                to = fTo;
            }

            do {
                while (ret == WS_REKEYING || ssh->error == WS_REKEYING) {
                    ret = wolfSSH_worker(ssh, NULL);
                    if (ret != WS_SUCCESS && ret == WS_FATAL_ERROR) {
                        ret = wolfSSH_get_error(ssh);
                    }
                }

                ret = wolfSSH_SFTP_Rename(ssh, pt, to);
                if (ret != WS_SUCCESS && ret == WS_FATAL_ERROR) {
                    ret = wolfSSH_get_error(ssh);
                }
            } while (ret == WS_WANT_READ || ret == WS_WANT_WRITE ||
                    ret == WS_CHAN_RXD || ret == WS_REKEYING);
            if (ret != WS_SUCCESS) {
                if (SFTP_FPUTS(args, "Error with rename\n") < 0) {
                    err_msg("fputs error");
                    return -1;
                }
            }
            WFREE(f, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            WFREE(fTo, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            continue;

        }

        if (WSTRNSTR(msg, "ls", MAX_CMD_SZ) != NULL) {
            WS_SFTPNAME* tmp;
            WS_SFTPNAME* current;

            do {
                while (ret == WS_REKEYING || ssh->error == WS_REKEYING) {
                    ret = wolfSSH_worker(ssh, NULL);
                    if (ret != WS_SUCCESS && ret == WS_FATAL_ERROR) {
                        ret = wolfSSH_get_error(ssh);
                    }
                }

                current = wolfSSH_SFTP_LS(ssh, workingDir);
                err = wolfSSH_get_error(ssh);
            } while ((err == WS_WANT_READ || err == WS_WANT_WRITE ||
                    err == WS_REKEYING) &&
                    (current == NULL && err != WS_SUCCESS));

            if (WSTRNSTR(msg, "-s", MAX_CMD_SZ) != NULL) {
                char tmpStr[WOLFSSH_MAX_FILENAME];
                XMEMSET(tmpStr, 0, WOLFSSH_MAX_FILENAME);
                XSNPRINTF(tmpStr, WOLFSSH_MAX_FILENAME, "size in bytes, file name\n");
                if (SFTP_FPUTS(args, tmpStr) < 0) {
                    err_msg("fputs error");
                    return -1;
                }
            }

            tmp = current;
            while (tmp != NULL) {
                if (WSTRNSTR(msg, "-s", MAX_CMD_SZ) != NULL) {
                    char tmpStr[WOLFSSH_MAX_FILENAME];
                    XSNPRINTF(tmpStr, WOLFSSH_MAX_FILENAME, "%lld, ",
                       (long long)(((long long)tmp->atrb.sz[1] << 32) | tmp->atrb.sz[0]));
                    if (SFTP_FPUTS(args, tmpStr) < 0) {
                        err_msg("fputs error");
                        return -1;
                    }
                }

                if (SFTP_FPUTS(args, tmp->fName) < 0) {
                    err_msg("fputs error");
                    return -1;
                }
                if (SFTP_FPUTS(args, "\n") < 0) {
                    err_msg("fputs error");
                    return -1;
                }
                tmp = tmp->next;
            }
            wolfSSH_SFTPNAME_list_free(current);
            continue;
        }

        /* display current working directory */
        if (WSTRNSTR(msg, "pwd", MAX_CMD_SZ) != NULL) {
            if (SFTP_FPUTS(args, workingDir) < 0 ||
                    SFTP_FPUTS(args, "\n") < 0) {
                err_msg("fputs error");
                return -1;
            }
            continue;
        }

        if (WSTRNSTR(msg, "help", MAX_CMD_SZ) != NULL) {
            ShowCommands();
            continue;
        }

        if (WSTRNSTR(msg, "quit", MAX_CMD_SZ) != NULL) {
            quit = 1;
            continue;
        }

        if (WSTRNSTR(msg, "exit", MAX_CMD_SZ) != NULL) {
            quit = 1;
            continue;
        }

        SFTP_FPUTS(args, "Unknown command\n");
    } while (!quit);

    return WS_SUCCESS;
}


/* alternate main loop for the autopilot get/receive */
static int doAutopilot(int cmd, char* local, char* remote)
{
    int err;
    int ret = WS_SUCCESS;
    char fullpath[128] = ".";
    WS_SFTPNAME* name  = NULL;
    byte remoteAbsPath = 0;

    /* check if is absolute path before making it one */
    if (remote != NULL && WSTRLEN(remote) > 2 && remote[1] == ':' &&
            remote[2] == '\\') {
        remoteAbsPath = 1;
    }
    else if (remote != NULL && WSTRLEN(remote) > 2 && remote[1] == ':' &&
            remote[2] == '/') {
        remoteAbsPath = 1;
    }
    else if (remote != NULL && remote[0] == '/') {
        remoteAbsPath = 1;
    }

    if (remoteAbsPath) {
       /* use remote absolute path if provided */
       WMEMSET(fullpath, 0, sizeof(fullpath));
       WSTRNCPY(fullpath, remote, sizeof(fullpath) - 1);
    }
    else {
        do {
            name = wolfSSH_SFTP_RealPath(ssh, fullpath);
            err = wolfSSH_get_error(ssh);
        } while ((err == WS_WANT_READ || err == WS_WANT_WRITE) &&
            ret != WS_SUCCESS);

        snprintf(fullpath, sizeof(fullpath), "%s/%s",
            name == NULL ? "." : name->fName,
            remote);
    }

    do {
        if (cmd == AUTOPILOT_PUT) {
            ret = wolfSSH_SFTP_Put(ssh, local, fullpath, 0, NULL);
        }
        else if (cmd == AUTOPILOT_GET) {
            ret = wolfSSH_SFTP_Get(ssh, fullpath, local, 0, NULL);
        }
        err = wolfSSH_get_error(ssh);
    } while ((err == WS_WANT_READ || err == WS_WANT_WRITE ||
                err == WS_CHAN_RXD) && ret == WS_FATAL_ERROR);

    if (ret != WS_SUCCESS) {
        if (cmd == AUTOPILOT_PUT) {
            fprintf(stderr, "Unable to copy local file %s to remote file %s\n",
                   local, fullpath);
        }
        else if (cmd == AUTOPILOT_GET) {
            fprintf(stderr, "Unable to copy remote file %s to local file %s\n",
                    fullpath, local);
        }
    }

    wolfSSH_SFTPNAME_list_free(name);
    return ret;
}


THREAD_RETURN WOLFSSH_THREAD sftpclient_test(void* args)
{
    WOLFSSH_CTX* ctx = NULL;
    SOCKET_T sockFd = WOLFSSH_SOCKET_INVALID;
    SOCKADDR_IN_T clientAddr;
    socklen_t clientAddrSz = sizeof(clientAddr);
    int ret;
    int ch;
    int userEcc = 0;
    /* int peerEcc = 0; */
    word16 port = wolfSshPort;
    char* host = (char*)wolfSshIp;
    const char* username = NULL;
    const char* password = NULL;
    const char* defaultSftpPath = NULL;
    const char* privKeyName = NULL;
    byte nonBlock = 0;
    int autopilot = AUTOPILOT_OFF;
    char* apLocal = NULL;
    char* apRemote = NULL;
    char* pubKeyName = NULL;
    char* certName = NULL;
    char* caCert   = NULL;
    SFTPC_HEAP_HINT* heap = NULL;

    int     argc = ((func_args*)args)->argc;
    char**  argv = ((func_args*)args)->argv;
    ((func_args*)args)->return_code = 0;

    while ((ch = mygetopt(argc, argv, "?d:gh:i:j:l:p:r:u:EGNP:J:A:X")) != -1) {
        switch (ch) {
            case 'd':
                defaultSftpPath = myoptarg;
                break;

            case 'E':
                /* peerEcc = 1; */
                err_sys("wolfSFTP ECC server authentication "
                        "not yet supported.");
                break;

            case 'h':
                host = myoptarg;
                break;

            case 'p':
                if (myoptarg == NULL)
                    err_sys("null argument found");
                port = (word16)atoi(myoptarg);
                #if !defined(NO_MAIN_DRIVER) || defined(USE_WINDOWS_API)
                    if (port == 0)
                        err_sys("port number cannot be 0");
                #endif
                break;

            case 'u':
                username = myoptarg;
                break;

            case 'l':
                apLocal = myoptarg;
                break;

            case 'r':
                apRemote = myoptarg;
                break;

            case 'g':
                autopilot = AUTOPILOT_PUT;
                break;

            case 'G':
                autopilot = AUTOPILOT_GET;
                break;

            case 'P':
                password = myoptarg;
                break;

            case 'N':
                nonBlock = 1;
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

            #if defined(OPENSSL_ALL) || defined(WOLFSSL_IP_ALT_NAME)
            case 'X':
                ClientIPOverride(1);
                break;
            #endif
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

    if ((pubKeyName == NULL && certName == NULL) && privKeyName != NULL) {
        err_sys("If setting priv key, need pub key.");
    }


#ifdef WOLFSSH_NO_RSA
    userEcc = 1;
    /* peerEcc = 1; */
#endif

    if (autopilot != AUTOPILOT_OFF) {
        if (apLocal == NULL || apRemote == NULL) {
            err_sys("Options -G and -g require both -l and -r.");
        }
    }

#ifdef WOLFSSH_TEST_BLOCK
    if (!nonBlock) {
        err_sys("Use -N when testing forced non blocking");
    }
#endif

#ifdef WOLFSSH_STATIC_MEMORY
    ret = wc_LoadStaticMemory_ex(&heap,
            SFTPC_STATIC_LISTSZ, static_sizeList, static_distList,
            static_buffer, sizeof(static_buffer),
            WOLFMEM_GENERAL, 0);
    if (ret != 0) {
        err_sys("Couldn't set up static memory pool.\n");
    }
#endif /* WOLFSSH_STATIC_MEMORY */

    ret = ClientSetPrivateKey(privKeyName, userEcc, heap);
    if (ret != 0) {
        err_sys("Error setting private key");
    }

#ifdef WOLFSSH_CERTS
    /* passed in certificate to use */
    if (certName) {
        ret = ClientUseCert(certName, heap);
    }
    else
#endif
    {
        ret = ClientUsePubKey(pubKeyName, 0, heap);
    }
    if (ret != 0) {
        err_sys("Error setting public key");
    }

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_CLIENT, heap);
    if (ctx == NULL)
        err_sys("Couldn't create wolfSSH client context.");

    if (((func_args*)args)->user_auth == NULL)
        wolfSSH_SetUserAuth(ctx, ClientUserAuth);
    else
        wolfSSH_SetUserAuth(ctx, ((func_args*)args)->user_auth);

#if !defined(WS_NO_SIGNAL) && !defined(USE_WINDOWS_API)
    /* handle interrupt with get and put */
    signal(SIGINT, sig_handler);
#endif

#ifdef WOLFSSH_CERTS
    ClientLoadCA(ctx, caCert);
#else
    (void)caCert;
#endif /* WOLFSSH_CERTS */

    wolfSSH_CTX_SetPublicKeyCheck(ctx, ClientPublicKeyCheck);

    ssh = wolfSSH_new(ctx);
    if (ssh == NULL)
        err_sys("Couldn't create wolfSSH session.");

    if (defaultSftpPath != NULL) {
        if (wolfSSH_SFTP_SetDefaultPath(ssh, defaultSftpPath)
                != WS_SUCCESS) {
            fprintf(stderr, "Couldn't store default sftp path.\n");
            exit(EXIT_FAILURE);
        }
    }

    if (password != NULL)
        wolfSSH_SetUserAuthCtx(ssh, (void*)password);

    wolfSSH_SetPublicKeyCheckCtx(ssh, (void*)host);

    ret = wolfSSH_SetUsername(ssh, username);
    if (ret != WS_SUCCESS)
        err_sys("Couldn't set the username.");

    build_addr(&clientAddr, host, port);
    tcp_socket(&sockFd, ((struct sockaddr_in *)&clientAddr)->sin_family);

    ret = connect(sockFd, (const struct sockaddr *)&clientAddr, clientAddrSz);
    if (ret != 0)
        err_sys("Couldn't connect to server.");

    if (nonBlock)
        tcp_set_nonblocking(&sockFd);

    ret = wolfSSH_set_fd(ssh, (int)sockFd);
    if (ret != WS_SUCCESS)
        err_sys("Couldn't set the session's socket.");

    if (!nonBlock)
        ret = wolfSSH_SFTP_connect(ssh);
    else
        ret = NonBlockSSH_connect();
    if (ret != WS_SUCCESS)
        err_sys("Couldn't connect SFTP");

    {
        /* get current working directory */
        WS_SFTPNAME* n = NULL;

        do {
            n = wolfSSH_SFTP_RealPath(ssh, (char*)".");
            ret = wolfSSH_get_error(ssh);
        } while (ret == WS_WANT_READ || ret == WS_WANT_WRITE);
        if (n == NULL) {
            err_sys("Unable to get real path for working directory");
        }

        workingDir = (char*)WMALLOC(n->fSz + 1, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (workingDir == NULL) {
            err_sys("Unable to create working directory");
        }
        WMEMCPY(workingDir, n->fName, n->fSz);
        workingDir[n->fSz] = '\0';

        /* free after done with names */
        wolfSSH_SFTPNAME_list_free(n);
        n = NULL;
    }

    if (autopilot == AUTOPILOT_OFF) {
        ret = doCmds((func_args*)args);
    }
    else {
        ret = doAutopilot(autopilot, apLocal, apRemote);
    }

    WFREE(workingDir, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (ret == WS_SUCCESS) {
        if (wolfSSH_shutdown(ssh) != WS_SUCCESS) {
            int rc;
            rc = wolfSSH_get_error(ssh);

            if (rc != WS_SOCKET_ERROR_E && rc != WS_EOF)
                printf("error with wolfSSH_shutdown()\n");
        }
    }
    WCLOSESOCKET(sockFd);
    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);
    if (ret != WS_SUCCESS) {
        printf("error %d encountered\n", ret);
        ((func_args*)args)->return_code = ret;
    }

    ClientFreeBuffers(pubKeyName, privKeyName, heap);
#if !defined(WOLFSSH_NO_ECC) && defined(FP_ECC) && defined(HAVE_THREAD_LS)
    wc_ecc_fp_free();  /* free per thread cache */
#endif

    WOLFSSL_RETURN_FROM_THREAD(0);
}

#else

THREAD_RETURN WOLFSSH_THREAD sftpclient_test(void* args)
{
#ifdef NO_WOLFSSH_CLIENT
    printf("NO_WOLFSSH_CLIENT macro was used. Can not have a client example\n");
#else
    printf("Not compiled in!\n"
           "Please recompile with WOLFSSH_SFTP or --enable-sftp\n");
#endif
    (void)args;
    WOLFSSL_RETURN_FROM_THREAD(0);
}
#endif /* WOLFSSH_SFTP */

#ifndef NO_MAIN_DRIVER

    int main(int argc, char** argv)
    {
        func_args args;

        args.argc = argc;
        args.argv = argv;
        args.return_code = 0;
        args.user_auth = NULL;
        #ifdef WOLFSSH_SFTP
            args.sftp_cb = NULL;
        #endif

        WSTARTTCP();

        #ifdef DEBUG_WOLFSSH
            wolfSSH_Debugging_ON();
        #endif

        wolfSSH_Init();

        ChangeToWolfSshRoot();
        sftpclient_test(&args);

        wolfSSH_Cleanup();

        #if defined(WOLFSSH_SFTP) && !defined(NO_WOLFSSH_CLIENT)
            return args.return_code;
        #else
            return -1; /* return error when not compiled in */
        #endif
    }

    int myoptind = 0;
    char* myoptarg = NULL;

#endif /* NO_MAIN_DRIVER */

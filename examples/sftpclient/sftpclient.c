/* sftpclient.c
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

#define WOLFSSH_TEST_CLIENT

#include <wolfssh/ssh.h>
#include <wolfssh/wolfsftp.h>
#include <wolfssh/test.h>
#include <wolfssh/port.h>
#include "examples/sftpclient/sftpclient.h"
#ifndef USE_WINDOWS_API
    #include <termios.h>
#endif

#ifdef WOLFSSH_SFTP

int doCmds(func_args* args);


/* static so that signal handler can access and interrupt get/put */
static WOLFSSH* ssh = NULL;
static char* workingDir;
#define fin stdin
#define fout stdout
#define MAX_CMD_SZ 7


static void err_msg(const char* s)
{
    printf("%s\n", s);
}

static void myStatusCb(WOLFSSH* sshIn, word32* bytes, char* name)
{
    char buf[80];
    word64 longBytes = ((word64)bytes[1] << 32) | bytes[0];
    WSNPRINTF(buf, sizeof(buf), "Processed %8ld\t bytes \r", longBytes);
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
static byte interupt = 0;

static void sig_handler(const int sig)
{
    (void)sig;

    interupt = 1;
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
            WMEMMOVE(path + i, path + i + 1, sz - i + 1);
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

const char sftpTestString[] = "Hello, wolfSSH!";

#define WS_MAX_EXAMPLE_RW 1024

static int SetEcho(int on)
{
#ifndef USE_WINDOWS_API
    static int echoInit = 0;
    static struct termios originalTerm;
    if (!echoInit) {
        if (tcgetattr(STDIN_FILENO, &originalTerm) != 0) {
            printf("Couldn't get the original terminal settings.\n");
            return -1;
        }
        echoInit = 1;
    }
    if (on) {
        if (tcsetattr(STDIN_FILENO, TCSANOW, &originalTerm) != 0) {
            printf("Couldn't restore the terminal settings.\n");
            return -1;
        }
    }
    else {
        struct termios newTerm;
        memcpy(&newTerm, &originalTerm, sizeof(struct termios));

        newTerm.c_lflag &= ~ECHO;
        newTerm.c_lflag |= (ICANON | ECHONL);

        if (tcsetattr(STDIN_FILENO, TCSANOW, &newTerm) != 0) {
            printf("Couldn't turn off echo.\n");
            return -1;
        }
    }
#else
    static int echoInit = 0;
    static DWORD originalTerm;
    HANDLE stdinHandle = GetStdHandle(STD_INPUT_HANDLE);
    if (!echoInit) {
        if (GetConsoleMode(stdinHandle, &originalTerm) == 0) {
            printf("Couldn't get the original terminal settings.\n");
            return -1;
        }
        echoInit = 1;
    }
    if (on) {
        if (SetConsoleMode(stdinHandle, originalTerm) == 0) {
            printf("Couldn't restore the terminal settings.\n");
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
    printf("client %s\n", LIBWOLFSSH_VERSION_STRING);
    printf(" -?            display this help and exit\n");
    printf(" -h <host>     host to connect to, default %s\n", wolfSshIp);
    printf(" -p <num>      port to connect on, default %d\n", wolfSshPort);
    printf(" -u <username> username to authenticate as (REQUIRED)\n");
    printf(" -P <password> password for username, prompted if omitted\n");
    printf(" -d <path>     set the default local path\n");
    printf(" -N            use non blocking sockets\n");

    ShowCommands();
}


byte userPassword[256];

static int wsUserAuth(byte authType,
                      WS_UserAuthData* authData,
                      void* ctx)
{
    const char* defaultPassword = (const char*)ctx;
    word32 passwordSz;
    int ret = WOLFSSH_USERAUTH_SUCCESS;

    (void)authType;
    if (defaultPassword != NULL) {
        passwordSz = (word32)strlen(defaultPassword);
        memcpy(userPassword, defaultPassword, passwordSz);
    }
    else {
        printf("Password: ");
        SetEcho(0);
        if (WFGETS((char*)userPassword, sizeof(userPassword), stdin) == NULL) {
            printf("Getting password failed.\n");
            ret = WOLFSSH_USERAUTH_FAILURE;
        }
        else {
            char* c = strpbrk((char*)userPassword, "\r\n");;
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

    return ret;
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
int doCmds(func_args* args)
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
                f = XMALLOC(maxSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
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
            XFREE(f, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            continue;
        }

        if ((pt = WSTRNSTR(msg, "reget", MAX_CMD_SZ)) != NULL) {
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
                f = XMALLOC(maxSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
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
                ret = wolfSSH_SFTP_Get(ssh, pt, to, resume, &myStatusCb);
                if (ret != WS_SUCCESS) {
                    ret = wolfSSH_get_error(ssh);
                }
            } while (ret == WS_WANT_READ || ret == WS_WANT_WRITE);

            if (ret != WS_SUCCESS) {
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
            XFREE(f, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            continue;
        }


        if ((pt = WSTRNSTR(msg, "reput", MAX_CMD_SZ)) != NULL) {
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
                f = XMALLOC(maxSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
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
                ret = wolfSSH_SFTP_Put(ssh, pt, to, resume, &myStatusCb);
                err = wolfSSH_get_error(ssh);
            } while ((err == WS_WANT_READ || err == WS_WANT_WRITE)
                        && ret != WS_SUCCESS);
            if (ret != WS_SUCCESS) {
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
            XFREE(f, NULL, DYNAMIC_TYPE_TMP_BUFFER);
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
                f = XMALLOC(maxSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
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
                XFREE(workingDir, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                workingDir = (char*)XMALLOC(sz + 1, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                if (workingDir == NULL) {
                    err_msg("Error malloc'ing");
                    return -1;
                }
                WMEMCPY(workingDir, pt, sz);
                workingDir[sz] = '\0';

                clean_path(workingDir);
            }
            XFREE(f, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            continue;
        }

        if ((pt = WSTRNSTR(msg, "chmod", MAX_CMD_SZ)) != NULL) {
            int sz;
            char* f = NULL;
            char mode[WOLFSSH_MAX_OCTET_LEN];

            pt += sizeof("chmod");
            sz = (int)WSTRLEN(pt);

            if (pt[sz - 1] == '\n') pt[sz - 1] = '\0';

            /* get mode */
            sz = (sz < WOLFSSH_MAX_OCTET_LEN - 1)? sz :
                                                   WOLFSSH_MAX_OCTET_LEN -1;
            WMEMCPY(mode, pt, sz);
            mode[WOLFSSH_MAX_OCTET_LEN - 1] = '\0';
            for (i = sz; i > 0; i--) {
                if (mode[i] == ' ') {
                    mode[i] = '\0';
                    break;
                }
            }
            if (i == 0) {
                printf("error with getting mode\r\n");
                continue;
            }
            pt += (int)WSTRLEN(mode);
            sz = (int)WSTRLEN(pt);
            for (i = 0; i < sz && pt[0] == ' '; i++, pt++);

            if (pt[0] != '/') {
                int maxSz = (int)WSTRLEN(workingDir) + sz + 2;
                f = XMALLOC(maxSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
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
                if (SFTP_FPUTS(args, "Unable to change path permissions\n") < 0) {
                    err_msg("fputs error");
                    return -1;
                }
            }

            XFREE(f, NULL, DYNAMIC_TYPE_TMP_BUFFER);
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
                f = XMALLOC(maxSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
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
            XFREE(f, NULL, DYNAMIC_TYPE_TMP_BUFFER);
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
                f = XMALLOC(maxSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);

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
            XFREE(f, NULL, DYNAMIC_TYPE_TMP_BUFFER);
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
                f = XMALLOC(maxSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
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
                fTo = XMALLOC(maxSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);

                fTo[0] = '\0';
                WSTRNCAT(fTo, workingDir, maxSz);
                if (WSTRLEN(workingDir) > 1) {
                    WSTRNCAT(fTo, "/", maxSz);
                }
                WSTRNCAT(fTo, to, maxSz);

                to = fTo;
            }

            do {
                ret = wolfSSH_SFTP_Rename(ssh, pt, to);
                err = wolfSSH_get_error(ssh);
            } while ((err == WS_WANT_READ || err == WS_WANT_WRITE)
                        && ret != WS_SUCCESS);
            if (ret != WS_SUCCESS) {
                if (SFTP_FPUTS(args, "Error with rename\n") < 0) {
                    err_msg("fputs error");
                    return -1;
                }
            }
            XFREE(f, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            XFREE(fTo, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            continue;

        }

        if ((pt = WSTRNSTR(msg, "ls", MAX_CMD_SZ)) != NULL) {
            WS_SFTPNAME* tmp;
            WS_SFTPNAME* current;

            do {
                current = wolfSSH_SFTP_LS(ssh, workingDir);
                err = wolfSSH_get_error(ssh);
            } while ((err == WS_WANT_READ || err == WS_WANT_WRITE)
                        && current == NULL && err != WS_SUCCESS);
            tmp = current;
            while (tmp != NULL) {
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
        if ((pt = WSTRNSTR(msg, "pwd", MAX_CMD_SZ)) != NULL) {
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


THREAD_RETURN WOLFSSH_THREAD sftpclient_test(void* args)
{
    WOLFSSH_CTX* ctx = NULL;
    SOCKET_T sockFd = WOLFSSH_SOCKET_INVALID;
    SOCKADDR_IN_T clientAddr;
    socklen_t clientAddrSz = sizeof(clientAddr);
    int ret;
    int ch;
    word16 port = wolfSshPort;
    char* host = (char*)wolfSshIp;
    const char* username = NULL;
    const char* password = NULL;
    const char* defaultSftpPath = NULL;
    byte nonBlock = 0;

    int     argc = ((func_args*)args)->argc;
    char**  argv = ((func_args*)args)->argv;
    ((func_args*)args)->return_code = 0;

    while ((ch = mygetopt(argc, argv, "?d:h:p:u:P:N")) != -1) {
        switch (ch) {
            case 'd':
                defaultSftpPath = myoptarg;
                break;

            case 'h':
                host = myoptarg;
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

            case 'N':
                nonBlock = 1;
                break;

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


#ifdef WOLFSSH_TEST_BLOCK
    if (!nonBlock) {
        err_sys("Use -N when testing forced non blocking");
    }
#endif

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_CLIENT, NULL);
    if (ctx == NULL)
        err_sys("Couldn't create wolfSSH client context.");

    if (((func_args*)args)->user_auth == NULL)
        wolfSSH_SetUserAuth(ctx, wsUserAuth);
    else
        wolfSSH_SetUserAuth(ctx, ((func_args*)args)->user_auth);

#ifndef WS_NO_SIGNAL
    /* handle interrupt with get and put */
    signal(SIGINT, sig_handler);
#endif

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

        workingDir = (char*)XMALLOC(n->fSz + 1, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (workingDir == NULL) {
            err_sys("Unable to create working directory");
        }
        WMEMCPY(workingDir, n->fName, n->fSz);
        workingDir[n->fSz] = '\0';

        /* free after done with names */
        wolfSSH_SFTPNAME_list_free(n);
        n = NULL;
    }

    ret = doCmds(args);
    XFREE(workingDir, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (ret == WS_SUCCESS)
        ret = wolfSSH_shutdown(ssh);
    WCLOSESOCKET(sockFd);
    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);
    if (ret != WS_SUCCESS) {
        printf("error %d encountered\n", ret);
        ((func_args*)args)->return_code = ret;
    }

    return 0;
}

#else

THREAD_RETURN WOLFSSH_THREAD sftpclient_test(void* args)
{
    printf("Not compiled in!\nPlease recompile with WOLFSSH_SFTP or --enable-sftp");
    (void)args;
    return 0;
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
        args.sftp_cb   = NULL;

        WSTARTTCP();

        #ifdef DEBUG_WOLFSSH
            wolfSSH_Debugging_ON();
        #endif

        wolfSSH_Init();

        ChangeToWolfSshRoot();
        sftpclient_test(&args);

        wolfSSH_Cleanup();

        return args.return_code;
    }

    int myoptind = 0;
    char* myoptarg = NULL;

#endif /* NO_MAIN_DRIVER */

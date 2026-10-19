/* sshd_fork_preload.c
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

/* LD_PRELOAD interposer for sshd_fork_fail_test.sh only. */
/* When WOLFSSHD_FAULT_FORK is set, the first fork() after the first accept()
 * returns EAGAIN, as it does at a process limit. Keyed on accept() so the two
 * forks made while daemonizing are left alone. One shot: every later fork,
 * including those in connection children, is forwarded. */

#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <dlfcn.h>

static int wsshd_accepted = 0;
static int wsshd_failed = 0;

int accept(int fd, struct sockaddr* addr, socklen_t* addrLen)
{
    int (*real)(int, struct sockaddr*, socklen_t*);
    int ret;

    real = (int (*)(int, struct sockaddr*, socklen_t*))
        dlsym(RTLD_NEXT, "accept");
    if (real == NULL) {
        errno = ENOSYS;
        return -1;
    }
    ret = real(fd, addr, addrLen);
    if (ret >= 0) {
        wsshd_accepted++;
    }
    return ret;
}

pid_t fork(void)
{
    pid_t (*real)(void);

    if (getenv("WOLFSSHD_FAULT_FORK") != NULL && wsshd_accepted == 1
            && !wsshd_failed) {
        wsshd_failed = 1;
        errno = EAGAIN;
        return -1;
    }
    real = (pid_t (*)(void))dlsym(RTLD_NEXT, "fork");
    if (real == NULL) {
        errno = ENOSYS;
        return -1;
    }
    return real();
}

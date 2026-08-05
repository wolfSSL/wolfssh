/* sshd_chroot_preload.c
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

/* LD_PRELOAD interposer for sshd_chroot_fail_test.sh only. Three environment
 * variables drive it, all unset by default, in which case every call is
 * forwarded untouched. */
/* WOLFSSHD_FAULT_CHDIR_PATH makes chdir() fail with EACCES for that one path,
 * so SetupChroot()'s chdir into the chroot target fails against a stock
 * wolfsshd. It matches on the argument on purpose: the daemon chdir()s in four
 * places, one of them a chdir("/") during daemonization, and a blanket fault
 * would stop the daemon before it ever listened. */
/* WOLFSSHD_FAULT_CHROOT_FAIL makes chroot() fail with EPERM, for the other half
 * of the guard: the chdir("/") that must not run after a failed chroot(). */
/* WOLFSSHD_FAULT_CHROOT_MARKER names a file this records into. Every chroot()
 * is recorded, and so is every chdir() made after one, which is what lets the
 * test see a step that ran when it should have been skipped. Recording the call
 * rather than its result keeps the assertions independent of whether the call
 * would have succeeded. chdir()s before the first chroot() are not recorded:
 * they are the daemon's ordinary ones and only the post-chroot sequence is
 * under test. The flag is per process and does not survive the exec() at the
 * end of the session setup, so a shell's own chdir()s stay out of the file. */

#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <dlfcn.h>

static int wsshd_sawChroot = 0;

static void wsshd_note(const char* call, const char* path)
{
    const char* marker;
    int fd;
    int savedErrno;

    marker = getenv("WOLFSSHD_FAULT_CHROOT_MARKER");
    if (marker == NULL) {
        return;
    }

    /* The caller is about to inspect errno from the real call, so leave it
     * exactly as it was found. */
    savedErrno = errno;

    /* The daemon is still root here and the marker sits outside the chroot
     * target, so a plain open is enough. */
    fd = open(marker, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd >= 0) {
        /* umask independent: the test user has to read this back. */
        (void)fchmod(fd, 0644);
        (void)write(fd, call, strlen(call));
        (void)write(fd, " ", 1);
        if (path != NULL) {
            (void)write(fd, path, strlen(path));
        }
        (void)write(fd, "\n", 1);
        (void)close(fd);
    }

    errno = savedErrno;
}

int chdir(const char* path)
{
    int (*real)(const char*);
    const char* fault;
    /* Through a local, not the parameter: glibc declares chdir()'s argument
     * nonnull, and comparing the parameter itself to NULL is a -Wnonnull-compare
     * error. An interposer does not get to assume its callers behaved. */
    const char* target = path;

    if (wsshd_sawChroot) {
        wsshd_note("chdir", target);
    }

    fault = getenv("WOLFSSHD_FAULT_CHDIR_PATH");
    if (fault != NULL && target != NULL && strcmp(fault, target) == 0) {
        errno = EACCES;
        return -1;
    }
    real = (int (*)(const char*))dlsym(RTLD_NEXT, "chdir");
    if (real == NULL) {
        errno = ENOSYS;
        return -1;
    }
    return real(path);
}

int chroot(const char* path)
{
    int (*real)(const char*);

    wsshd_note("chroot", path);
    /* Set before the fault below, so the chdir()s that a failed chroot() must
     * not be followed by are still recorded. */
    wsshd_sawChroot = 1;

    if (getenv("WOLFSSHD_FAULT_CHROOT_FAIL") != NULL) {
        errno = EPERM;
        return -1;
    }
    real = (int (*)(const char*))dlsym(RTLD_NEXT, "chroot");
    if (real == NULL) {
        errno = ENOSYS;
        return -1;
    }
    return real(path);
}

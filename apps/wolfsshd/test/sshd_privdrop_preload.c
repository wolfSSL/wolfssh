/* sshd_privdrop_preload.c
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

/* LD_PRELOAD interposer for sshd_privdrop_fail_test.sh only. */
/* When WOLFSSHD_FAULT_PRIVDROP is set, setregid()/setreuid() return EPERM so the
 * per-connection privilege drop in the stock wolfsshd fails. */
/* No other daemon call uses these; the real call is forwarded when unarmed. */

#define _GNU_SOURCE
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <dlfcn.h>

static int wsshd_fault_armed(void)
{
    return getenv("WOLFSSHD_FAULT_PRIVDROP") != NULL;
}

int setregid(gid_t rgid, gid_t egid)
{
    int (*real)(gid_t, gid_t);

    if (wsshd_fault_armed()) {
        errno = EPERM;
        return -1;
    }
    real = (int (*)(gid_t, gid_t))dlsym(RTLD_NEXT, "setregid");
    if (real == NULL) {
        errno = ENOSYS;
        return -1;
    }
    return real(rgid, egid);
}

int setreuid(uid_t ruid, uid_t euid)
{
    int (*real)(uid_t, uid_t);

    if (wsshd_fault_armed()) {
        errno = EPERM;
        return -1;
    }
    real = (int (*)(uid_t, uid_t))dlsym(RTLD_NEXT, "setreuid");
    if (real == NULL) {
        errno = ENOSYS;
        return -1;
    }
    return real(ruid, euid);
}

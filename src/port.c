/* port.c 
 *
 * Copyright (C) 2014-2016 wolfSSL Inc.
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
 * The port module wraps standard C library functions with macros to
 * cover portablility issues when building in environments that rename
 * those functions. This module also provides local versions of some
 * standard C library functions that are missing on some platforms.
 */


#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <stdio.h>
#include <wolfssh/port.h>


#ifndef NO_FILESYSTEM
int wfopen(WFILE** f, const char* filename, const char* mode)
{
#ifdef USE_WINDOWS_API
    return fopen_s(f, filename, mode) != 0;
#elif defined(WOLFSSL_NUCLEUS)
    int m = WOLFSSH_O_CREAT;

    if (WSTRSTR(mode, "r") && WSTRSTR(mode, "w")) {
        m |= WOLFSSH_O_RDWR;
    }
    else {
        if (WSTRSTR(mode, "r")) {
            m |= WOLFSSH_O_RDONLY;
        }
        if (WSTRSTR(mode, "w")) {
            m |= WOLFSSH_O_WRONLY;
        }
    }

    if (filename != NULL && f != NULL) {
        if ((**f = WOPEN(filename, m, 0)) < 0) {
            return **f;
        }

        /* fopen defaults to normal */
        if (NU_Set_Attributes(filename, 0) != NU_SUCCESS) {
            WCLOSE(**f);
            return 1;
        }
        return 0;
    }
    else {
        return 1;
    }
#else
    if (f != NULL) {
        *f = fopen(filename, mode);
        return *f == NULL;
    }
    return 1;
#endif
}
#endif /* !NO_FILESYSTEM */

#ifndef WSTRING_USER

char* wstrnstr(const char* s1, const char* s2, unsigned int n)
{
    unsigned int s2_len = (unsigned int)WSTRLEN(s2);

    if (s2_len == 0)
        return (char*)s1;

    while (n >= s2_len && s1[0]) {
        if (s1[0] == s2[0])
            if (WMEMCMP(s1, s2, s2_len) == 0)
                return (char*)s1;
        s1++;
        n--;
    }

    return NULL;
}

#endif /* WSTRING_USER */

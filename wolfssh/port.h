/* port.h
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


#pragma once

#include <wolfssh/settings.h>

#ifdef __cplusplus
extern "C" {
#endif


/* setup memory handling */
#ifndef WMALLOC_USER
    #include <wolfssh/memory.h>

    #define WMALLOC(s, h, t)    ((void)h, (void)t, wolfSSH_Malloc((s)))
    #define WFREE(p, h, t)      {void* xp = (p); if ((xp)) wolfSSH_Free((xp));}
    #define WREALLOC(p, n, h, t) wolfSSH_Realloc((p), (n))
#endif /* WMALLOC_USER */


/* setup string handling */
#ifndef WSTRING_USER
    #include <string.h>

    #define WFILE FILE

    WOLFSSH_API char* wstrnstr(const char*, const char*, unsigned int);
    WOLFSSH_API int wfopen(WFILE**, const char*, const char*);

    #define WMEMCPY(d,s,l)    memcpy((d),(s),(l))
    #define WMEMSET(b,c,l)    memset((b),(c),(l))
    #define WMEMCMP(s1,s2,n)  memcmp((s1),(s2),(n))
    #define WMEMMOVE(d,s,l)   memmove((d),(s),(l))

    #define WSTRLEN(s1)       strlen((s1))
    #define WSTRSTR(s1,s2)    strstr((s1),(s2))
    #define WSTRNSTR(s1,s2,n) wstrnstr((s1),(s2),(n))
    #define WSTRNCMP(s1,s2,n) strncmp((s1),(s2),(n))
    #define WSTRNCAT(s1,s2,n) strncat((s1),(s2),(n))
    #define WSTRSPN(s1,s2)    strspn((s1),(s2))
    #define WSTRCSPN(s1,s2)   strcspn((s1),(s2))
    #define WFOPEN(f,fn,m)    wfopen((f),(fn),(m))
    #define WFCLOSE(f)        fclose(f)

    #ifndef USE_WINDOWS_API
        #include <stdio.h>
        #define WSTRNCPY(s1,s2,n) strncpy((s1),(s2),(n))
        #define WSTRNCASECMP(s1,s2,n) strncasecmp((s1),(s2),(n))
        #define WSNPRINTF(s,n,f,...) snprintf((s),(n),(f),##__VA_ARGS__)
        #define WVSNPRINTF(s,n,f,...) vsnprintf((s),(n),(f),##__VA_ARGS__)
        #define WLOCALTIME(c,r) (localtime_r((c),(r))!=NULL)
    #else
        #define WSTRNCPY(s1,s2,n) strncpy_s((s1),(n),(s2),(n))
        #define WSTRNCASECMP(s1,s2,n) _strnicmp((s1),(s2),(n))
        #define WSNPRINTF(s,n,f,...) _snprintf_s((s),(n),(n),(f),##__VA_ARGS__)
        #define WVSNPRINTF(s,n,f,...) vsnprintf_s((s),(n),(n),(f),##__VA_ARGS__)
        #define WLOCALTIME(c,r) (localtime_s((r),(c))==0)
    #endif
#endif /* WSTRING_USER */


/* setup compiler inlining */
#ifndef INLINE
#ifndef NO_INLINE
    #ifdef _MSC_VER
        #define INLINE __inline
    #elif defined(__GNUC__)
        #define INLINE inline
    #elif defined(__IAR_SYSTEMS_ICC__)
        #define INLINE inline
    #elif defined(THREADX)
        #define INLINE _Inline
    #else
        #define INLINE
    #endif
#else
    #define INLINE
#endif
#endif /* INLINE */


/* GCC 7 has new switch() fall-through detection */
#if defined(__GNUC__)
    #if ((__GNUC__ > 7) || ((__GNUC__ == 7) && (__GNUC_MINOR__ >= 1)))
        #define FALL_THROUGH __attribute__ ((fallthrough));
    #endif
#endif
#ifndef FALL_THROUGH
    #define FALL_THROUGH
#endif


#ifdef __cplusplus
}
#endif


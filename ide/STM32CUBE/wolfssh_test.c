/* wolfssh_test.c
 *
 * Copyright (C) 2006-2023 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

#include "wolfssh_test.h"

#ifndef SINGLE_THREADED
    #include <cmsis_os.h>

    #ifdef WOLFSSL_DEBUG_MEMORY
        /* for memory debugging */
        #include <task.h>
    #endif
#endif

#include <stdio.h>
#include <string.h>


#ifdef CMSIS_OS2_H_
void wolfSSHTest(void* argument)
#else
void wolfSSHTest(const void* argument)
#endif
{
    int ret = 0;
#if 0
    wolfSSL_Debugging_ON();
    wolfSSH_Debugging_ON();
#endif

    printf("Running wolfSSH Tests...\n");

    if (wolfSSH_TestsuiteTest(0, NULL))
        ret = -1;
    if (wolfSSH_UnitTest(0, NULL))
        ret = -1;
    if (wolfSSH_ApiTest(0, NULL))
        ret = -1;

    printf("wolfSSH Test: Return code %d\n", ret);

}

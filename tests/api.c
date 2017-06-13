/* api.c
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


#include <wolfssh/ssh.h>
#include <tests/unit.h>


#define TEST_SUCCESS    (1)
#define TEST_FAIL       (0)

#define testingFmt "   %s:"
#define resultFmt  " %s\n"
static const char* passed = "passed";
static const char* failed = "failed";


static int test_wolfSSH_Init(void)
{
    int result;

    printf(testingFmt, "wolfSSH_Init()");
    result = wolfSSH_Init();
    printf(resultFmt, result == WS_SUCCESS ? passed : failed);

    return result;
}


static int test_wolfSSH_Cleanup(void)
{
    int result;

    printf(testingFmt, "wolfSSH_Cleanup()");
    result = wolfSSH_Cleanup();
    printf(resultFmt, result == WS_SUCCESS ? passed : failed);

    return result;
}


int ApiTest(void)
{
    printf(" Begin API Tests\n");
    AssertIntEQ(test_wolfSSH_Init(), WS_SUCCESS);
    AssertIntEQ(test_wolfSSH_Cleanup(), WS_SUCCESS);
    printf(" End API Tests\n");
    return 0;
}

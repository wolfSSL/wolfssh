/* wolfssh_test.h
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

#ifndef WOLFSSH_TEST_H_
#define WOLFSSH_TEST_H_

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssh/settings.h>

#include "../../tests/unit.h"
#include "../../tests/api.h"
#include "../../tests/testsuite.h"

#ifndef SINGLE_THREADED
#include <cmsis_os.h>
#endif

#ifdef CMSIS_OS2_H_
void wolfSSHTest(void* argument);
#else
void wolfSSHTest(void const * argument);
#endif

#endif /* WOLFSSH_TEST_H_ */

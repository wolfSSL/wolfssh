/* user_settings.h
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

#ifndef WOLFSSH_USER_SETTINGS_H
#define WOLFSSH_USER_SETTINGS_H


#ifdef __cplusplus
extern "C" {
#endif

#include <wolfssl/wolfcrypt/types.h>

#undef WOLFSSH_SCP
#define WOLFSSH_SCP

#undef NO_APITEST_MAIN_DRIVER
#define NO_APITEST_MAIN_DRIVER

#undef NO_TESTSUITE_MAIN_DRIVER
#define NO_TESTSUITE_MAIN_DRIVER

#undef NO_UNITTEST_MAIN_DRIVER
#define NO_UNITTEST_MAIN_DRIVER

#undef NO_MAIN_DRIVER
#define NO_MAIN_DRIVER

#undef WS_NO_SIGNAL
#define WS_NO_SIGNAL

#undef WS_USE_TEST_BUFFERS
#define WS_USE_TEST_BUFFERS

#undef NO_WOLFSSL_DIR
#define NO_WOLFSSL_DIR

#undef WOLFSSH_NO_NONBLOCKING
#define WOLFSSH_NO_NONBLOCKING

#define DEFAULT_WINDOW_SZ (128 * 128)
#define WOLFSSH_MAX_SFTP_RW 8192

#undef NO_FILESYSTEM
#define NO_FILESYSTEM

#ifdef __cplusplus
}
#endif

#endif

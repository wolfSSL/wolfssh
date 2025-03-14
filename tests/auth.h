/* auth.h
 *
 * Copyright (C) 2025 wolfSSL Inc.
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

#ifndef _WOLFSSH_TESTS_AUTH_H_
#define _WOLFSSH_TESTS_AUTH_H_

#include <wolfssh/test.h>

int wolfSSH_AuthTest(int argc, char** argv);

typedef struct thread_args {
    int return_code;
    tcp_ready* signal;
} thread_args;

#endif /* _WOLFSSH_TESTS_AUTH_H_ */

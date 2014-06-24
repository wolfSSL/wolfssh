/* error.c 
 *
 * Copyright (C) 2014 wolfSSL Inc.
 *
 * This file is part of wolfSSH.
 *
 * wolfSSH is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSH is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssh/ssh.h>
#include <wolfssh/log.h>
#include <wolfssh/error.h>


const char* wolfSSH_get_error(int err)
{
#ifdef NO_WOLFSSH_STRINGS
    return "No wolfSSH strings available";
#else
    switch (err) {
        case WS_SUCCESS:
            return "function success";

        case WS_FATAL_ERROR:
            return "general function failure";

        case WS_BAD_ARGUMENT:
            return "bad function argument";

        case WS_MEMORY_E:
            return "memory allocation failure";

        case WS_BUFFER_E:
            return "input/output buffer size error";

        case WS_PARSE_E:
            return "general parsing error";

        case WS_NOT_COMPILED:
            return "feature not compiled in";

        case WS_OVERFLOW_E:
            return "would overflow if continued failure";

        case WS_BAD_USAGE:
            return "bad example usage";

        case WS_CBIO_ERR_GENERAL:
            return "general I/O callback error";

        case WS_CBIO_ERR_WANT_READ:
            return "I/O callback would read block error";

        case WS_CBIO_ERR_WANT_WRITE:
            return "I/O callback would write block error";

        case WS_CBIO_ERR_CONN_RST:
            return "I/O callback connection reset error";

        case WS_CBIO_ERR_ISR:
            return "I/O callback interrupt error";

        case WS_CBIO_ERR_CONN_CLOSE:
            return "I/O callback connection closed error";

        case WS_CBIO_ERR_TIMEOUT:
            return "I/O callback timeout error";

        default:
            return "Unknown error code";
    }
#endif
}


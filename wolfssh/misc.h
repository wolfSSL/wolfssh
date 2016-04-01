/* misc.h
 *
 * Copyright (C) 2006-2016 wolfSSL Inc.
 *
 * This file is part of wolfSSH.
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

#pragma once

#ifndef WOLFSSH_MISC_H
#define WOLFSSH_MISC_H


#ifdef __cplusplus
    extern "C" {
#endif


#include <wolfssh/port.h>


#ifdef NO_INLINE


#ifndef min
WOLFSSH_LOCAL uint32_t min(uint32_t, uint32_t);
#endif /* min */

WOLFSSH_LOCAL void ato32(const uint8_t*, uint32_t*);
WOLFSSH_LOCAL void c32toa(uint32_t, uint8_t*);
WOLFSSH_LOCAL void ForceZero(const void*, uint32_t);
WOLFSSH_LOCAL int ConstantCompare(const uint8_t*, const uint8_t*, uint32_t);


#endif /* NO_INLINE */


#ifdef __cplusplus
    }   /* extern "C" */
#endif


#endif /* WOLFSSH_MISC_H */


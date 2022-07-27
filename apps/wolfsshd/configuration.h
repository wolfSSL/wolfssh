/* configuration.h
 *
 * Copyright (C) 2014-2021 wolfSSL Inc.
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

#ifndef WOLFSSHD_H
#define WOLFSSHD_H

typedef struct WOLFSSHD_CONFIG WOLFSSHD_CONFIG;

#include "auth.h"


#define WOLFSSHD_PRIV_SEPARAT 0
#define WOLFSSHD_PRIV_SANDBOX 1
#define WOLFSSHD_PRIV_OFF     2

WOLFSSHD_CONFIG* wolfSSHD_NewConfig(void* heap);
void wolfSSHD_ConfigFree(WOLFSSHD_CONFIG* conf);
int wolfSSHD_ConfigLoad(WOLFSSHD_CONFIG* conf, const char* filename);

char* wolfSSHD_ConfigGetBanner(const WOLFSSHD_CONFIG* conf);
char* wolfSSHD_ConfigGetHostKeyFile(const WOLFSSHD_CONFIG* conf);
int wolfSSHD_ConfigSetHostKeyFile(WOLFSSHD_CONFIG* conf, const char* file);
word16 wolfSSHD_ConfigGetPort(const WOLFSSHD_CONFIG* conf);
char* wolfSSHD_ConfigGetAuthKeysFile(const WOLFSSHD_CONFIG* conf);
int wolfSSHD_ConfigSetAuthKeysFile(WOLFSSHD_CONFIG* conf, const char* file);
byte wolfSSHD_ConfigGetPermitEmptyPw(const WOLFSSHD_CONFIG* conf);
long wolfSSHD_ConfigGetGraceTime(const WOLFSSHD_CONFIG* conf);

#endif /* WOLFSSHD_H */


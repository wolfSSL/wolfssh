/* wolfsshd.h
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
void wolfSSHD_FreeConfig(WOLFSSHD_CONFIG* conf);
int wolfSSHD_LoadSSHD(WOLFSSHD_CONFIG* conf, const char* filename);

char* wolfSSHD_GetBanner(WOLFSSHD_CONFIG* conf);
char* wolfSSHD_GetHostPrivateKey(WOLFSSHD_CONFIG* conf);
int wolfSSHD_SetHostPrivateKey(WOLFSSHD_CONFIG* conf, const char* hostKeyFile);
word16 wolfSSHD_GetPort(WOLFSSHD_CONFIG* conf);
char* wolfSSHD_GetAuthKeysFile(WOLFSSHD_CONFIG* conf);
int wolfSSHD_SetAuthKeysFile(WOLFSSHD_CONFIG* conf, const char* file);


/* on/off flag options to check */
#define WOLFSSHD_EMPTY_PASSWORD 1

int wolfSSHD_ConfigOptionEnabled(WOLFSSHD_CONFIG* conf, word32 opt);

#endif /* WOLFSSHD_H */


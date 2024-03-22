/* configuration.h
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

#ifndef WOLFSSHD_H
#define WOLFSSHD_H

typedef struct WOLFSSHD_CONFIG WOLFSSHD_CONFIG;

#include "auth.h"

/* 0 so that privilage seperation is default on after struct memset'd on init */
#define WOLFSSHD_PRIV_SEPARAT 0
#define WOLFSSHD_PRIV_SANDBOX 1
#define WOLFSSHD_PRIV_OFF     2

WOLFSSHD_CONFIG* wolfSSHD_ConfigNew(void* heap);
void wolfSSHD_ConfigFree(WOLFSSHD_CONFIG* conf);
int wolfSSHD_ConfigLoad(WOLFSSHD_CONFIG* conf, const char* filename);

char* wolfSSHD_ConfigGetForcedCmd(const WOLFSSHD_CONFIG* conf);
char* wolfSSHD_ConfigGetBanner(const WOLFSSHD_CONFIG* conf);
char* wolfSSHD_ConfigGetChroot(const WOLFSSHD_CONFIG* conf);
char* wolfSSHD_ConfigGetHostKeyFile(const WOLFSSHD_CONFIG* conf);
char* wolfSSHD_ConfigGetHostCertFile(const WOLFSSHD_CONFIG* conf);
char* wolfSSHD_ConfigGetUserCAKeysFile(const WOLFSSHD_CONFIG* conf);
int wolfSSHD_ConfigSetHostKeyFile(WOLFSSHD_CONFIG* conf, const char* file);
int wolfSSHD_ConfigSetHostCertFile(WOLFSSHD_CONFIG* conf, const char* file);
int wolfSSHD_ConfigSetUserCAKeysFile(WOLFSSHD_CONFIG* conf, const char* file);
word16 wolfSSHD_ConfigGetPort(const WOLFSSHD_CONFIG* conf);
char* wolfSSHD_ConfigGetAuthKeysFile(const WOLFSSHD_CONFIG* conf);
int wolfSSHD_ConfigGetAuthKeysFileSet(const WOLFSSHD_CONFIG* conf);
int wolfSSHD_ConfigSetAuthKeysFile(WOLFSSHD_CONFIG* conf, const char* file);
byte wolfSSHD_ConfigGetPermitEmptyPw(const WOLFSSHD_CONFIG* conf);
byte wolfSSHD_ConfigGetPermitRoot(const WOLFSSHD_CONFIG* conf);
byte wolfSSHD_ConfigGetPrivilegeSeparation(const WOLFSSHD_CONFIG* conf);
long wolfSSHD_ConfigGetGraceTime(const WOLFSSHD_CONFIG* conf);
byte wolfSSHD_ConfigGetPwAuth(const WOLFSSHD_CONFIG* conf);
WOLFSSHD_CONFIG* wolfSSHD_GetUserConf(const WOLFSSHD_CONFIG* conf,
        const char* usr, const char* grp, const char* host,
        const char* localAdr, word16* localPort, const char* RDomain,
        const char* adr);
void wolfSSHD_ConfigSavePID(const WOLFSSHD_CONFIG* conf);

#ifdef WOLFSSHD_UNIT_TEST
int ParseConfigLine(WOLFSSHD_CONFIG** conf, const char* l, int lSz);
#endif

#endif /* WOLFSSHD_H */


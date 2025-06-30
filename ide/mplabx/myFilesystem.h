/* myFilesystem.h
 *
 * Copyright (C) 2014-2025 wolfSSL Inc.
 *
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


/*
 * The port module wraps standard C library functions with macros to
 * cover portability issues when building in environments that rename
 * those functions. This module also provides local versions of some
 * standard C library functions that are missing on some platforms.
 */


#ifndef MY_FILESYSTEM_H
#define MY_FILESYSTEM_H

#include <wolfssh/settings.h>

#ifdef __cplusplus
extern "C" {
#endif

#include <stdlib.h>
#include <stdio.h>
#include "system/fs/sys_fs.h"

/*******************************************************************************
 mapping of file handles and modes
*******************************************************************************/
#define WDIR              SYS_FS_HANDLE
#define WSTAT_T           SYS_FS_FSTAT
#define WS_DELIM          '/'
#define WFFLUSH(s)        SYS_FS_FileSync((s))
#define WFILE             SYS_FS_HANDLE
#define WSEEK_END         SYS_FS_SEEK_END
#define WBADFILE          SYS_FS_HANDLE_INVALID
#define WOLFSSH_O_RDWR    SYS_FS_FILE_OPEN_READ_PLUS
#define WOLFSSH_O_RDONLY  SYS_FS_FILE_OPEN_READ
#define WOLFSSH_O_WRONLY  SYS_FS_FILE_OPEN_WRITE_PLUS
#define WOLFSSH_O_APPEND  SYS_FS_FILE_OPEN_APPEND
#define WOLFSSH_O_CREAT   SYS_FS_FILE_OPEN_WRITE_PLUS
#define WOLFSSH_O_TRUNC   0
#define WOLFSSH_O_EXCL    0
#define FLUSH_STD(a)

/*******************************************************************************
 function declerations for operations that do not have a user check
*******************************************************************************/
#define WFD SYS_FS_HANDLE
int wPread(WFD, unsigned char*, unsigned int, const unsigned int*);
char* wGetCwd(char *r, int rSz);
int wStat(const char* path, WSTAT_T* stat);
int wDirOpen(void* heap, WDIR* dir, const char* path);


/*******************************************************************************
 mapping "SAFE" operations, any user can do
*******************************************************************************/
#define WFOPEN(fs,f,fn,m)   wfopen(*(f),(fn),(m))
#define WFCLOSE(fs,f)       SYS_FS_FileClose(*(f))
#define WFREAD(fs,b,s,a,f)  SYS_FS_FileRead(*(f),(b),(s)*(a))
#define WFSEEK(fs,s,o,w)    SYS_FS_FileSeek(*(s),(o),(w))
#define WFTELL(fs,s)        SYS_FS_FileTell(*(s))
#define WREWIND(fs,s)       SYS_FS_FileSeek(*(s), 0, SYS_FS_SEEK_SET)
#define WCHDIR(fs,b)        SYS_FS_DirectryChange((b))
#define WOPENDIR(fs,h,c,d)  wDirOpen((h), (c),(d))
#define WCLOSEDIR(fs,d)     SYS_FS_DirClose(*(d))
#define WSTAT(fs,p,b)       wStat((p), (b))
#define WPREAD(fs,fd,b,s,o) wPread((fd),(b),(s),(o))
#define WGETCWD(fs,r,rSz)   wGetCwd(r,(rSz))


/*******************************************************************************
 function declerations for operations that have a user check before running
*******************************************************************************/
int wPwrite(void* fs, WFD, unsigned char*, unsigned int, const unsigned int*);
int wRename(void* fs, unsigned char* orig, unsigned char* newName);
int wRemove(void* fs, unsigned char* dir);
int wRmdir(void* fs, unsigned char* dir);
int wMkdir(void* fs, unsigned char* path);
int wChmod(void* fs, const char* path, int mode);
int wFwrite(void *fs, unsigned char* b, int s, int a, WFILE* f);
int wFread(void *fs, unsigned char* b, int s, int a, WFILE* f);


/*******************************************************************************
 mapping of operations that have a user check before running
*******************************************************************************/
#define WFWRITE(fs,b,s,a,f)  wFwrite((fs),(b),(s),(a),(f))
#define WCHMOD(fs,f,m)       wChmod((fs),(f),(m))
#define WMKDIR(fs,p,m)       wMkdir((fs),(p))
#define WRMDIR(fs,d)         wRmdir((fs),(d))
#define WREMOVE(fs,d)        wRemove((fs),(d))
#define WRENAME(fs,o,n)      wRename((fs),(o),(n))
#define WPWRITE(fs,fd,b,s,o) wPwrite((fs),(fd),(b),(s),(o))


/*******************************************************************************
 FPUTS/FGETS only used in SFTP client example
*******************************************************************************/
#undef  WFGETS
#define WFGETS(b,s,f)       SYS_FS_FileStringGet((f), (b), (s))
#undef  WFPUTS
#define WFPUTS(b,f)         SYS_FS_FileStringPut((f), (b))


/*******************************************************************************
 Operations that do not have a port for
*******************************************************************************/
#define WUTIMES(a,b)         (0)
#define WSETTIME(fs,f,a,m)   (0)
#define WFSETTIME(fs,fd,a,m) (0)
#define WFCHMOD(fs,fd,m)     (0)


/*******************************************************************************
 File attribute functions
*******************************************************************************/
int SFTP_GetAttributesStat(void* atr, void* stats);
int SFTP_GetAttributes_Handle(void* ssh, unsigned char* handle, int handleSz,
                char* name, void* atr);

#ifdef __cplusplus
}
#endif

#endif /* MY_FILESYSTEM_H */


/* dummy_filesystem.h
 *
 * Copyright (C) 2014-2020 wolfSSL Inc.
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


#ifndef DUMMY_FILESYSTEM_H
#define DUMMY_FILESYSTEM_H

#ifdef WOLFSSH_USER_FILESYSTEM
    typedef unsigned int off_t;
    typedef int mode_t; 
    #define WFILE int
    #define WFOPEN(f,n,m)    dummy_wfopen((f),(n),(m))
    #define WFCLOSE(f)        dummy_fclose(f)
    #define WFREAD(b,s,a,f)   dummy_fread((b),(s),(a),(f))
    #define WFWRITE(b,s,a,f)  dummy_fwrite((b),(s),(a),(f))
    #define WFSEEK(s,o,w)     dummy_fseek((s),(o),(w))
    #define WFTELL(s)         dummy_ftell((s))
    #define WREWIND(s)        dummy_rewind((s))
    #define WSEEK_END         SEEK_END
    #define WBADFILE          NULL
    #define WS_DELIM '/'

    #define WFD int
    typedef int FILE;

enum {
    WOLFSSH_O_RDWR, WOLFSSH_O_RDONLY, WOLFSSH_O_WRONLY, 
    WOLFSSH_O_APPEND, WOLFSSH_O_CREAT, WOLFSSH_O_TRUNC, WOLFSSH_O_EXCL
} ;

    #define WOPEN(p, m, f)      dummy_open(p, m, f)
    #define WCLOSE(f)           dummy_close(f)
    #define WPREAD(f, b, c, o)  dummy_pread(f, b, c, o) 
    #define WPWRITE(f, b, c, o) dummy_pwrite(f, b, c, o) 
    #define WGETCWD(f, b, l)    dummy_getcwd(b, l)
    #define WRMDIR(f, p)        dummy_rmdir(p)
    #define WMKDIR(f, p, m)     dummy_mkdir(p, m)

    #define WREMOVE(fs,d)     dummy_remove((d))
    #define WRENAME(fs,o,n)   dummy_rename((o),(n))

    #define  WSTAT_T  stat_t
    typedef  struct { int i; } stat_t;
    
    #define WSTAT(p,b)     dummy_stat((b),(p))
    #define WLSTAT(p,b)    dummy_lstat((b),(p))
    #define WCHMOD(fs,f,m) dummy_chmod((f),(m))

int    dummy_wfopen(FILE **f, const char *n, const char *m);
int    dummy_fclose(FILE *f);
size_t dummy_fread(void *b, size_t s, size_t n, FILE *f);
size_t dummy_fwrite(const void *b, size_t s, size_t n, FILE *f);
int    dummy_fseek(FILE *f, long int p, int m);
long   dummy_ftell(FILE *f);
void   dummy_rewind(FILE *f);

int    dummy_open (const char* n, int f, int m);
int    dummy_close(int f);
size_t dummy_pread (int f, void* b, size_t c, off_t *o);
size_t dummy_pwrite (int f, void* b, size_t c, off_t *o);
char  *dummy_getcwd(char *f, size_t l);
int    dummy_rmdir(const char *p);
int    dummy_mkdir(const char *p, mode_t m);
int    dummy_remove(const char *p);
int    dummy_rename(const char *p, const char *np);
int    dummy_stat(const char *p, stat_t *b);
int    dummy_lstat(const char *p, stat_t *b);

int    dummy_chmod(const char *p, mode_t  m);

#define WFD int
enum { O_RDWR, O_RDONLY, O_WRONLY, O_APPEND, O_CREAT, O_TRUNC, O_EXCL } ;

int SFTP_GetAttributes(void* fs, const char* fileName,
        void* atr, byte link, void* heap);
int SFTP_GetAttributes_Handle(void* ssh, byte* handle, int handleSz,
        void* atr);

#endif /*  WOLFSSH_USER_FILESYSTEM */

#endif
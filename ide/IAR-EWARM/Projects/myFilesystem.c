/* dummy_filesystem.c
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


#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/types.h>
#include <wolfssh/internal.h>
#include <wolfssh/ssh.h>

#ifdef WOLFSSH_USER_FILESYSTEM

#include "myFilesystem.h"

int    dummy_wfopen(FILE **f, const char *n, const char *m){
    (void) n; (void) m; (void)f;
    return NULL;
}

int      dummy_fclose(FILE *f) {
    (void) f;
    return 0;
}

size_t   dummy_fread(void *b, size_t s, size_t n, FILE *f) {
    (void) b; (void) s; (void) n; (void) f;
    return 0;
}
size_t   dummy_fwrite(const void *b, size_t s, size_t n, FILE *f) {
    (void) b; (void) s; (void) n; (void) f;
    return 0;
}

int      dummy_fseek(FILE *f, long int p, int m) {
    (void) f; (void) p; (void) m;
    return 0;
}
long int dummy_ftell(FILE *f) {
    (void) f;
    return 0;
}
void     dummy_rewind(FILE *f) {
    (void) f;
}

    #define WFD int

int dummy_open (const char* n, int f, int m) {
    (void) f; (void) n; (void) m;
    return 0;
}

int dummy_close(int f) {
    (void) f;
    return 0;
}

size_t dummy_pread (int f, void* b, size_t c,  off_t *o) {
    (void) f; (void) b; (void) c; (void)o;
    return 0;
}

size_t dummy_pwrite (int f, void* b, size_t c,  off_t *o) {
    (void) f; (void) b; (void) c; (void)o;
    return 0;
}

char *dummy_getcwd(char *f, size_t l){
    (void) f; (void) l;
    return 0;
}
int dummy_rmdir(const char *p){
    (void) p;
    return 0;
}

int dummy_mkdir(const char *p, mode_t m) {
    (void) p; (void) m;
    return 0;
}
int dummy_remove(const char *p){
    (void) p;
    return 0;
} 
int dummy_rename(const char *p, const char *np){
    (void) p; (void)np;
    return 0;
}

int    dummy_stat(const char *p, stat_t *b) {
    (void) p; (void)b;
    return 0;
}
int    dummy_lstat(const char *p, stat_t *b) {
    (void) p; (void)b;
    return 0;
}

int    dummy_chmod(const char *p, mode_t m) {
    (void) p; (void)m;
    return 0;
}

int SFTP_GetAttributes(void* fs, const char* fileName,
        void* atr, byte link, void* heap) {
    (void)fs; (void)fileName; (void)atr; (void)link; (void)heap;
    return 0;

}

int SFTP_GetAttributes_Handle(void* ssh, byte* handle, int handleSz,
        void* atr) {
            (void)ssh; (void)handle; (void)handleSz;

        return 0;
}

#endif

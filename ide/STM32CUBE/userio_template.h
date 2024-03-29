/* userio_template.h
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


#ifndef USERIO_TEMPLATE_H
#define USERIO_TEMPLATE_H

#ifdef WOLFSSH_USER_IO

#define SOCK_STREAM     1
#define SOCK_DGRAM      2
#define SOCK_RAW        3

#define SOL_SOCKET     0xfff
#define SO_REUSEADDR   0x0004

#define AF_INET         2
#define INADDR_ANY      ((uint32_t)0x00000000UL)

#define socklen_t uint32_t

typedef struct { int s_addr; } in_addr;

struct sockaddr { int i; };

typedef struct sockaddr sockaddr;

struct sockaddr_in{
    int sin_len;
    int sin_family;
    int sin_port;
    in_addr sin_addr;
};

typedef struct sockaddr_in sockaddr_in;

struct hostent{
    char *h_name;
    int  h_length;
    char **h_addr_list;
};

typedef struct hostent hostent;

static inline int inet_addr(const char* n){
    (void) n;
    return 0;
}

static inline int htons(unsigned int n){
    (void) n;
    return 0;
}

static inline int ntohs(unsigned int n){
    (void) n;
    return 0;
}

static inline int socket(int d, int t, int p) {
    (void) d; (void) t; (void) p;
    return 0;
}

static inline int setsockopt(int s, int l, int n, const void *o,
                             socklen_t len) {
    (void) s; (void) l; (void) n; (void) o; (void) len;
    return 0;
}

static inline int getsockname(int s, struct sockaddr *n, socklen_t* len) {
    (void) s; (void) n; (void) len;
    return 0;
}

static inline int bind(int s, const struct sockaddr *n, socklen_t l) {
    (void) s; (void) n; (void) l;
    return 0;
}

static inline int listen(int s, int b) {
    (void) s; (void) b;
    return 0;
}

static inline struct hostent* gethostbyname(const char* n) {
    (void) n;
    return NULL;
}

#endif /*  WOLFSSH_USER_IO */

#endif

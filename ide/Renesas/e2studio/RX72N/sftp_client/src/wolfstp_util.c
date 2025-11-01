/* wolfstp_util.c
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
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
#include <stdio.h>
#include <string.h>

#include "r_t4_itcpip.h"
#include "r_sys_time_rx_if.h"
#include "Pin.h"
#include "r_tsip_rx_if.h"
#define SIMPLE_TLSSEVER_IP       "192.168.11.9"
#define SIMPLE_TLSSERVER_PORT    "22222"

#define T4_WORK_SIZE (14800)
static UW tcpudp_work[(T4_WORK_SIZE / 4) + 1];

ER    t4_tcp_callback(ID cepid, FN fncd , VP p_parblk);
struct WOLFSSH;

static int getIPaddr(char *arg)
{
    int a1, a2, a3, a4;
    if(sscanf(arg, "%d.%d.%d.%d", &a1, &a2, &a3, &a4) == 4)
         return (a1 << 24) | (a2 << 16) | (a3 << 8) | a4;
    else return 0;
}

static int getPort(char *arg)
{
    int port;
    if(sscanf(arg, "%d", &port) == 1)
         return port;
    else return 0;
}

ID t4_connect()
{
    T_IPV4EP dst_addr;
    ID  cepid = 1;
    ER  ercd;
    static T_IPV4EP my_addr = { 0, 0 };
    
    if((dst_addr.ipaddr = getIPaddr(SIMPLE_TLSSEVER_IP)) == 0){
        printf("ERROR: IP address\n");
        goto out;
    }
    if((dst_addr.portno = getPort(SIMPLE_TLSSERVER_PORT)) == 0){
        printf("ERROR: Port number\n");
        goto out;
    }
    
    if((ercd = tcp_con_cep(cepid, &my_addr, &dst_addr, TMO_FEVR)) != E_OK) {
        printf("ERROR TCP Connect: %d\n", ercd);
        goto out;
    }
    
    return cepid;
out:
    tcp_sht_cep(cepid);
    tcp_cls_cep(cepid, TMO_FEVR);
    return 0;
}

int my_IORecv(struct WOLFSSH* ssh, void* buff, int sz, void* ctx)
{
    int ret;
    ID  cepid;
    (void)ssh;
    
    if(ctx != NULL)
        cepid = *(ID *)ctx;
    else
        return -1;

    ret = tcp_rcv_dat(cepid, (char*)buff, sz, TMO_FEVR);
    if(ret > 0)
        return ret;
    else
        return -1;
}

int my_IOSend(struct WOLFSSH* ssh, void* buff, int sz, void* ctx)
{
    int ret;
    ID  cepid;
    (void)ssh;
    
    if(ctx != NULL)
        cepid = *(ID *)ctx;
    else
        return -1;

    ret = tcp_snd_dat(cepid, (char*)buff, sz, TMO_FEVR);
    if(ret == sz)
        return ret;
    else
        return -1;
}

int Open_tcp( )
{
    ER  ercd;
    W   size;
    sys_time_err_t sys_ercd;
    char ver[128];
    /* initialize TSIP since t4 seems to call R_TSIP_RandomNumber */
    R_TSIP_Open(NULL,NULL);

    /* cast from uint8_t to char* */
    strcpy(ver, (char*)R_t4_version.library);

    sys_ercd = R_SYS_TIME_Open();
    if (sys_ercd != SYS_TIME_SUCCESS) {
        printf("ERROR : R_SYS_TIME_Open() failed\n");
        return -1;
    }
    R_Pins_Create();
    /* start LAN controller */
    ercd = lan_open();
    /* initialize TCP/IP */
    size = tcpudp_get_ramsize();
    if (size > (sizeof(tcpudp_work))) {
        printf("size > (sizeof(tcpudp_work))!\n");
        return -1;
    }
    ercd = tcpudp_open(tcpudp_work);
    if (ercd != E_OK) {
        printf("ERROR : tcpudp_open failed\n");
        return -1;
    }

    return 0;
}

void Close_tcp()
{
    /* end TCP/IP */
    tcpudp_close();
    lan_close();
    R_SYS_TIME_Close();
    R_TSIP_Close();
}

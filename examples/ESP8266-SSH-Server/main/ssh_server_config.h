#pragma once
#include "driver/gpio.h"

/* default is wireless unless USE_ENC28J60 is defined */
#undef USE_ENC28J60
// #define USE_ENC28J60    

/* wifi can be either STA or AP 
 *  #define WOLFSSH_SERVER_IS_AP
 *  #define WOLFSSH_SERVER_IS_STA
 **/

#define WOLFSSH_SERVER_IS_AP

/* SSH is usually on port 22, but for our example it lives at port 22222 */
#define SSH_UART_PORT 22222

#define SINGLE_THREADED
#define DEBUG_WOLFSSL
#define DEBUG_WOLFSSH


#define SSH_SERVER_BANNER "wolfSSH Example Server\n"
// static const char serverBanner[] = "wolfSSH Example Server\n";

#undef  SO_REUSEPORT

/* WOLFSSL_NONBLOCK is a value assigned to threadCtx->nonBlock
 * and should be a value 1 or 0
 */
#define WOLFSSL_NONBLOCK 1

/* set SSH_SERVER_ECHO to a value of 1 to echo UART
 * this is optional and typically not desired as the
 * UART target will typically echo its own characters.
 * Valid values are 0 and 1.
 */
#define SSH_SERVER_ECHO 0


#ifndef EXAMPLE_HIGHWATER_MARK
    #define EXAMPLE_HIGHWATER_MARK 0x3FFF8000 /* 1GB - 32kB */
#endif
#ifndef EXAMPLE_BUFFER_SZ
    #define EXAMPLE_BUFFER_SZ 4096
#endif
#define SCRATCH_BUFFER_SZ 1200


#ifdef WOLFSSL_NUCLEUS
    #define WFD_SET_TYPE FD_SET
    #define WFD_SET NU_FD_Set
    #define WFD_ZERO NU_FD_Init
    #define WFD_ISSET NU_FD_Check
#else
    #define WFD_SET_TYPE fd_set
    #define WFD_SET FD_SET
    #define WFD_ZERO FD_ZERO
    #define WFD_ISSET FD_ISSET
#endif

/**
 ******************************************************************************
 ******************************************************************************
 ** USER SETTINGS BEGIN
 ******************************************************************************
 ******************************************************************************
 **/

/* UART pins and config */
#include "uart_helper.h"
// static const int RX_BUF_SIZE = 1024;

#undef ULX3S
#undef M5STICKC
#define SSH_HUZZAH_ESP8266

#ifdef M5STICKC
    /* reminder GPIO 34 to 39 are input only */
    #define TXD_PIN (GPIO_NUM_26) /* orange */
    #define RXD_PIN (GPIO_NUM_36) /* yellow */
#elif defined (ULX3S)
    /* reminder GPIO 34 to 39 are input only */
    #define TXD_PIN (GPIO_NUM_32) /* orange */
    #define RXD_PIN (GPIO_NUM_33) /* yellow */
#elif defined (SSH_HUZZAH_ESP8266)
    #define EX_UART_NUM UART_NUM_0
#else
    /* this also works for Adafruit Feather HUZZAH ESP8266 */
    #define TXD_PIN (GPIO_Pin_15) /* orange */
    #define RXD_PIN (GPIO_Pin_13) /* yellow */
#endif

/* Edgerouter is 57600, others are typically 115200 */
#define BAUD_RATE (57600)

/* ESP8266 74880 */

// see https://tf.nist.gov/tf-cgi/servers.cgi



#define NTP_SERVER_LIST ( (char*[]) {        \
                                     "pool.ntp.org",         \
                                     "time.nist.gov",        \
                                     "utcnist.colorado.edu"  \
                                     }                       \
                        ) 

/* number of elements 
 * To determine the number of elements in the array, we can divide the total size of 
 * the array by the size of the array element 
 * See https://stackoverflow.com/questions/37538/how-do-i-determine-the-size-of-my-array-in-c
 **/
#define NELEMS(x)  ( (int)(sizeof(x) / sizeof((x)[0])) )
    
/* #define NTP_SERVER_COUNT  (int)(sizeof(NTP_SERVER_LIST) / sizeof(NTP_SERVER_LIST[0])) */
#define NTP_SERVER_COUNT NELEMS(NTP_SERVER_LIST)

// extern char* ntpServerList[NTP_SERVER_COUNT];
extern char* ntpServerList[NTP_SERVER_COUNT];

    
#define TIME_ZONE "PST-8"

/**
 ******************************************************************************
 ******************************************************************************
 ** USER SETTINGS END
 ******************************************************************************
 ******************************************************************************
 **/

#ifdef  WOLFSSH_SERVER_IS_AP
    #ifdef WOLFSSH_SERVER_IS_STA
        #error Concurrent WOLFSSH_SERVER_IS_AP and WOLFSSH_SERVER_IS_STA not supported. Pick one. Disable the other.
    #endif
#endif
  
void ssh_server_config_init();


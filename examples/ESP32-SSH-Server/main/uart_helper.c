#include <esp_task_wdt.h>
/* uart_hlper.c
 *
 * Copyright (C) 2014-2022 wolfSSL Inc.
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
 *
 */
#include "uart_helper.h"
#include "tx_rx_buffer.h"

#include "driver/uart.h"
#include "esp_log.h"
#include "string.h"
#include "ssh_server.h"

#define DEBUG_WOLFSSL
#define DEBUG_WOLFSSH
#include <wolfssl/wolfcrypt/logging.h>

/* portTICK_PERIOD_MS is ( ( TickType_t ) 1000 / configTICK_RATE_HZ )
 * configTICK_RATE_HZ is CONFIG_FREERTOS_HZ
 * CONFIG_FREERTOS_HZ is 100
 **/
#define UART_TICKS_TO_WAIT (20 / portTICK_RATE_MS)

/*
 * see examples: https://github.com/espressif/esp-idf/blob/master/examples/peripherals/uart/uart_echo/main/uart_echo_example_main.c
 */


/* we are going to use a real backspace instead of 0x7f observed */
const char* backspace = (char*)0x08;
static SemaphoreHandle_t xUART_Semaphore = NULL;


/*
 * startupMessage is the message before actually connecting to UART in server task thread.
 */
static char startupMessage[] =
      "\n"
      "Welcome to ESP32 SSH Server!"
      "\n\n"
      "Press [Enter]\n\n";

/*
 * welcome message
 */
void uart_send_welcome() {
    static const char *TX_TASK_TAG = "TX_TASK_WELCOME";
    sendData(TX_TASK_TAG, startupMessage);
}


/*
 *  send character string at char* data to UART
 */
int sendData(const char* logName, const char* data) {
    const int len = strlen(data);

    /* note we are always using UART_NUM_1 but the GPIO pins may vary */
    const int txBytes = uart_write_bytes(UART_NUM_1, data, len);

    ESP_LOGI(logName, "Wrote %d bytes", txBytes);

    return txBytes;
}

/*
 *  if the external Receive Buffer has data (e.g. from SSH client)
 *  then send that data to the UART (ExternalReceiveBufferSz bytes)
 */
void uart_tx_task(void *arg) {
    /*
     * when we receive chars from ssh, we'll send them out the UART
    */
    static const char *TX_TASK_TAG = "TX_TASK";
    esp_log_level_set(TX_TASK_TAG, ESP_LOG_INFO);

    /* this RTOS task will never exit */
    while (1) {
        if (ExternalReceiveBufferSz() > 0)
        {
            WOLFSSL_MSG("UART Send Data");

            /* we don't want to send 0x7f as a backspace, we want a real backspace
             * TODO: optional character mapping */
            // taskENTER_CRITICAL(NULL);
            //char thisChar = (byte)ExternalReceiveBuffer()[0];
            //int thisLength  = ExternalReceiveBufferSz();
            //bool isSingleBackspace = (thisChar == 0x7f) && (thisLength == 1);
            // taskEXIT_CRITICAL(NULL);

            if (ExternalReceiveBuffer_IsChar(0x7f)) {

            // if ((byte)ExternalReceiveBuffer() == 0x7f && ExternalReceiveBufferSz()  == 1) {
                sendData(TX_TASK_TAG, backspace);
            }
            else
            {
                sendData(TX_TASK_TAG, (char*)ExternalReceiveBuffer());
            }

            /* once we sent data, reset the pointer to zero to indicate empty queue */
            Set_ExternalReceiveBufferSz(0);
        }

        /* yield. let's not be greedy */
        taskYIELD();
    }
}

/*
 * reading and writing memory from different threads requires coordination.
 * we'll use exclusive mutex semaphores for this.
 */
void InitSemaphore()
{
    if (xUART_Semaphore == NULL) {
        xUART_Semaphore = xSemaphoreCreateMutex();
    }

#ifdef configUSE_RECURSIVE_MUTEXES
    /* this may be interesting; see semphr.h */
    WOLFSSL_MSG("InitSemaphore found UART configUSE_RECURSIVE_MUTEXES enabled");
#endif
}

/*
 * for any data received FROM the UART, put it in the External Transmit
 * buffer to SEND (typically out to the SSH client)
 */
void uart_rx_task(void *arg) {
    InitSemaphore();

    /* TODO do we really want malloc? probably not.
     * but in this thread, it only gets allocated once.
     **/
    uint8_t* data = (uint8_t*) malloc(RX_BUF_SIZE + 1);

    /*
     * when we receive chars from UART, we'll send them out SSH
     */
    static const char *RX_TASK_TAG = "RX_TASK";
    esp_log_level_set(RX_TASK_TAG, ESP_LOG_INFO);


    /* TODO this should be interrupt driven, rather than polling */
    while (1) {
        /* note some examples have UART_TICKS_TO_WAIT = 1000,
         * which results in very sluggish response.
         * a known good value is (20 / portTICK_RATE_MS) */
        const int rxBytes = uart_read_bytes(UART_NUM_1,
                                            data,
                                            RX_BUF_SIZE,
                                            UART_TICKS_TO_WAIT);

        if (rxBytes > 0) {
            WOLFSSL_MSG("UART Rx Data!");
            data[rxBytes] = 0;

            ESP_LOGI(RX_TASK_TAG, "Read %d bytes:", rxBytes);

            /* this can be helpful during debug, but causes a bit of
             * sluggish performance as it is not very RTOS friendly:

             ESP_LOGI(RX_TASK_TAG, "Read %d bytes: '%s'", rxBytes, data);
             ESP_LOG_BUFFER_HEXDUMP(RX_TASK_TAG, data, rxBytes, ESP_LOG_INFO);

              *
              */

            Set_ExternalTransmitBuffer(data, rxBytes);
        } /* (rxBytes > 0) */

        /* yield. let's not be greedy */
        taskYIELD();
    }

    /* we never actually get here */
    free(data);
}
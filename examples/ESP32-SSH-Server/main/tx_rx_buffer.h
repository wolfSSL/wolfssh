#pragma once

#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>

#include <wolfssl/wolfcrypt/logging.h>

/* TODO do these really need to be so big? probably not */
#define ExternalReceiveBufferMaxLength 2047
#define ExternalTransmitBufferMaxLength 2047


int  init_tx_rx_buffer(byte TxPin, byte RxPin);
int Get_ExternalTransmitBuffer(byte **ToData);

int Set_ExternalTransmitBuffer(byte *FromData, int sz);

int Set_ExternalReceiveBuffer(byte *FromData, int sz);

bool ExternalReceiveBuffer_IsChar(char charValue);


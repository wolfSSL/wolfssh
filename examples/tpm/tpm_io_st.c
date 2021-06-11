/* tpm_io_st.c
 *
 * Copyright (C) 2006-2021 wolfSSL Inc.
 *
 * This file is part of wolfTPM.
 *
 * wolfTPM is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfTPM is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

/* This example shows IO interfaces for STM32 CubeMX HAL */


#include <wolftpm/tpm2.h>
#include <wolftpm/tpm2_tis.h>
#include "tpm_io.h"

/******************************************************************************/
/* --- BEGIN IO Callback Logic -- */
/******************************************************************************/

/* Included via tpm_io.c if WOLFTPM_INCLUDE_IO_FILE is defined */
#ifdef WOLFTPM_INCLUDE_IO_FILE

#if ! (defined(WOLFTPM_LINUX_DEV) || \
       defined(WOLFTPM_SWTPM) ||     \
       defined(WOLFTPM_WINAPI) )

#if defined(WOLFSSL_STM32_CUBEMX)
    #ifdef WOLFTPM_I2C
    #define TPM2_I2C_ADDR 0x2e
    /* STM32 CubeMX HAL I2C */
    #define STM32_CUBEMX_I2C_TIMEOUT 250
    static int i2c_read(void* userCtx, word32 reg, byte* data, int len)
    {
        int rc;
        int i2cAddr = (TPM2_I2C_ADDR << 1) | 0x01; /* For I2C read LSB is 1 */
        byte buf[MAX_SPI_FRAMESIZE+1];
        I2C_HandleTypeDef* hi2c = (I2C_HandleTypeDef*)userCtx;

        /* TIS layer should never provide a buffer larger than this,
           but double check for good coding practice */
        if (len > MAX_SPI_FRAMESIZE)
            return BAD_FUNC_ARG;

        buf[0] = (reg & 0xFF);
        rc = HAL_I2C_Master_Receive(&hi2c, i2cAddr, data, len, STM32_CUBEMX_I2C_TIMEOUT);

        if (rc != -1) {
            XMEMCPY(data, buf+1, len);
            return TPM_RC_SUCCESS;
        }

        return TPM_RC_FAILURE;
    }

    static int i2c_write(void* userCtx, word32 reg, byte* data, int len)
    {
        int rc;
        int i2cAddr = (TPM2_I2C_ADDR << 1); /* I2C write operation, LSB is 0 */
        byte buf[MAX_SPI_FRAMESIZE+1];
        I2C_HandleTypeDef* hi2c = (I2C_HandleTypeDef*)userCtx;

        /* TIS layer should never provide a buffer larger than this,
           but double check for good coding practice */
        if (len > MAX_SPI_FRAMESIZE)
            return BAD_FUNC_ARG;

        buf[0] = (reg & 0xFF); /* TPM register address */
        XMEMCPY(buf + 1, data, len);
        rc = HAL_I2C_Master_Transmit(&hi2c, TPM2_I2C_ADDR << 1, buf, len);

        if (rc != -1) {
            return TPM_RC_SUCCESS;
        }

        return TPM_RC_FAILURE;
    }

    int TPM2_IoCb_STCubeMX_I2C(TPM2_CTX* ctx, int isRead, word32 addr,
        byte* buf, word16 size, void* userCtx)
    {
        int ret = TPM_RC_FAILURE;

        if (userCtx != NULL) {
            if (isRead)
                ret = i2c_read(userCtx, addr, buf, size);
            else
                ret = i2c_write(userCtx, addr, buf, size);
        }

        (void)ctx;

        return ret;
    }

    #else /* STM32 CubeMX Hal SPI */
    #define STM32_CUBEMX_SPI_TIMEOUT 250
    int TPM2_IoCb_STCubeMX_SPI(TPM2_CTX* ctx, const byte* txBuf, byte* rxBuf,
        word16 xferSz, void* userCtx)
    {
        int ret = TPM_RC_FAILURE;
        SPI_HandleTypeDef* hspi = (SPI_HandleTypeDef*)userCtx;
        HAL_StatusTypeDef status;
    #ifdef WOLFTPM_CHECK_WAIT_STATE
        int timeout = TPM_SPI_WAIT_RETRY;
    #endif

        __HAL_SPI_ENABLE(hspi);
    #ifndef USE_HW_SPI_CS
        HAL_GPIO_WritePin(GPIOA, GPIO_PIN_15, GPIO_PIN_RESET); /* active low */
    #endif

    #ifdef WOLFTPM_CHECK_WAIT_STATE
        /* Send Header */
        status = HAL_SPI_TransmitReceive(hspi, (byte*)txBuf, rxBuf,
            TPM_TIS_HEADER_SZ, STM32_CUBEMX_SPI_TIMEOUT);
        if (status != HAL_OK) {
        #ifndef USE_HW_SPI_CS
            HAL_GPIO_WritePin(GPIOA, GPIO_PIN_15, GPIO_PIN_SET);
        #endif
            __HAL_SPI_DISABLE(hspi);
            return TPM_RC_FAILURE;
        }

        /* Check for wait states */
        if ((rxBuf[TPM_TIS_HEADER_SZ-1] & TPM_TIS_READY_MASK) == 0) {
            do {
                /* Check for SPI ready */
                status = HAL_SPI_TransmitReceive(hspi, (byte*)txBuf, rxBuf, 1,
                    STM32_CUBEMX_SPI_TIMEOUT);
                if (rxBuf[0] & TPM_TIS_READY_MASK)
                    break;
            } while (status == HAL_OK && --timeout > 0);
        #ifdef WOLFTPM_DEBUG_TIMEOUT
            printf("SPI Ready Wait %d\n", TPM_SPI_WAIT_RETRY - timeout);
        #endif
            if (timeout <= 0) {
            #ifndef USE_HW_SPI_CS
                HAL_GPIO_WritePin(GPIOA, GPIO_PIN_15, GPIO_PIN_SET);
            #endif
                __HAL_SPI_DISABLE(hspi);
                return TPM_RC_FAILURE;
            }
        }

        /* Send remainder of payload */
        status = HAL_SPI_TransmitReceive(hspi,
            (byte*)&txBuf[TPM_TIS_HEADER_SZ],
            &rxBuf[TPM_TIS_HEADER_SZ],
            xferSz - TPM_TIS_HEADER_SZ, STM32_CUBEMX_SPI_TIMEOUT);
    #else
        /* Send Entire Message - no wait states */
        status = HAL_SPI_TransmitReceive(hspi, (byte*)txBuf, rxBuf, xferSz,
            STM32_CUBEMX_SPI_TIMEOUT);
    #endif /* WOLFTPM_CHECK_WAIT_STATE */

    #ifndef USE_HW_SPI_CS
        HAL_GPIO_WritePin(GPIOA, GPIO_PIN_15, GPIO_PIN_SET);
    #endif
        __HAL_SPI_DISABLE(hspi);

        if (status == HAL_OK)
            ret = TPM_RC_SUCCESS;

        (void)ctx;

        return ret;
    }
    #endif /* WOLFTPM_I2C */
#endif
#endif /* !(WOLFTPM_LINUX_DEV || WOLFTPM_SWTPM || WOLFTPM_WINAPI) */
#endif /* WOLFTPM_INCLUDE_IO_FILE */

/******************************************************************************/
/* --- END IO Callback Logic -- */
/******************************************************************************/

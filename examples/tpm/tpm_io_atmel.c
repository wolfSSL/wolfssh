/* tpm_io_atmel.c
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

/* This example shows IO interfaces for ATMEL microcontrollers using ASF */


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

/* Use the max speed by default - see tpm2_types.h for chip specific max values */
#ifndef TPM2_SPI_HZ
    #define TPM2_SPI_HZ TPM2_SPI_MAX_HZ
#endif

#if defined(WOLFSSL_ATMEL)
    #include "asf.h"

    /* Atmel ASF */
    #define SPI_BAUD_RATE_4M    21
    #define CS_SPI_TPM          2

    /* Atmel ATSAM3X8EA Chip Selects */
    static const byte Spi_CS[] =  {    0,    1,    2,    3 };
    static const byte Spi_PCS[] = { 0x0E, 0x0D, 0x0B, 0x07 };

    static inline byte GetSPI_PCS(byte pcs)
    {
        if (pcs < sizeof(Spi_PCS))
            return Spi_PCS[pcs];
        return 0;
    }

    static inline byte GetSPI_CS(byte cs)
    {
        if (cs < sizeof(Spi_CS))
            return Spi_CS[cs];
        return 0;
    }

    static byte InitSPI_TPM(byte cs, byte baudRate, byte delay1, byte delay2)
    {
        byte csIdx, pcs;

        /* Get CS/PCS */
        csIdx = GetSPI_CS(cs);
        pcs = GetSPI_PCS(cs);

        SPI0->SPI_CR = SPI_CR_SPIDIS;

        SPI0->SPI_CSR[csIdx] = SPI_CSR_DLYBCT(delay2) | SPI_CSR_DLYBS(delay1) |
            SPI_CSR_BITS_8_BIT | SPI_CSR_SCBR(baudRate) | SPI_CSR_CSAAT |
            SPI_CSR_NCPHA;
        SPI0->SPI_MR = SPI_MR_MSTR | SPI_MR_MODFDIS | SPI_MR_PCS(pcs);
        SPI0->SPI_CR = SPI_CR_SPIEN;

        return pcs;
    }

    static int XferSPI_TPM(byte pcs, const byte* pSendBuf, byte* pReadBuf, word16 wLen)
    {
        int ret = TPM_RC_SUCCESS;
        word16 i;

        for (i = 0; i < wLen; i++) {
            while ((SPI0->SPI_SR & SPI_SR_TXEMPTY) == 0);
                SPI0->SPI_TDR = (word16)pSendBuf[i] | (pcs << 16);
            while ((SPI0->SPI_SR & SPI_SR_TDRE) == 0);
            while ((SPI0->SPI_SR & SPI_SR_RDRF) == 0);
            pReadBuf[i] = SPI0->SPI_RDR & 0x00FF;
        }

        return ret;
    }

    int TPM2_IoCb_Atmel_SPI(TPM2_CTX* ctx, const byte* txBuf, byte* rxBuf,
        word16 xferSz, void* userCtx)
    {
        int ret;
        byte pcs;
    #ifdef WOLFTPM_CHECK_WAIT_STATE
        int timeout = TPM_SPI_WAIT_RETRY;
    #endif

        /* Setup SPI */
        pcs = InitSPI_TPM(CS_SPI_TPM, SPI_BAUD_RATE_4M, 0x02, 0x02);

    #ifdef WOLFTPM_CHECK_WAIT_STATE
        /* Send Header */
        ret = XferSPI_TPM(pcs, txBuf, rxBuf, TPM_TIS_HEADER_SZ);
        if (ret != TPM_RC_SUCCESS) {
            SPI0->SPI_CR = SPI_CR_SPIDIS;
            return ret;
        }

        /* Check for wait states */
        if ((rxBuf[TPM_TIS_HEADER_SZ-1] & TPM_TIS_READY_MASK) == 0) {
            do {
                /* Check for SPI ready */
                ret = XferSPI_TPM(pcs, txBuf, rxBuf, 1);
                if (rxBuf[0] & TPM_TIS_READY_MASK)
                    break;
            } while (ret == TPM_RC_SUCCESS && --timeout > 0);
        #ifdef WOLFTPM_DEBUG_TIMEOUT
            printf("SPI Ready Wait %d\n", TPM_SPI_WAIT_RETRY - timeout);
        #endif
            if (timeout <= 0) {
                SPI0->SPI_CR = SPI_CR_SPIDIS;
                return TPM_RC_FAILURE;
            }
        }

        /* Send remainder of payload */
        ret = XferSPI_TPM(pcs,
            &txBuf[TPM_TIS_HEADER_SZ],
            &rxBuf[TPM_TIS_HEADER_SZ],
            xferSz - TPM_TIS_HEADER_SZ);
    #else
        /* Send Entire Message - no wait states */
        ret = XferSPI_TPM(pcs, txBuf, rxBuf, xferSz);
    #endif /* WOLFTPM_CHECK_WAIT_STATE */

        /* Disable SPI */
        SPI0->SPI_CR = SPI_CR_SPIDIS;

        (void)ctx;
        (void)userCtx;

        return ret;
    }

#endif
#endif /* !(WOLFTPM_LINUX_DEV || WOLFTPM_SWTPM || WOLFTPM_WINAPI) */
#endif /* WOLFTPM_INCLUDE_IO_FILE */

/******************************************************************************/
/* --- END IO Callback Logic -- */
/******************************************************************************/

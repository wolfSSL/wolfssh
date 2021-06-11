/* tpm_io_barebox.c
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

/* This example shows IO interfaces for Barebox */


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

#if defined(__BAREBOX__)
    #include <spi/spi.h>
    #include <spi/spi_gpio.h>

    int TPM2_IoCb_Barebox_SPI(TPM2_CTX* ctx, const byte* txBuf,
        byte* rxBuf, word16 xferSz, void* userCtx)
    {
        int ret = TPM_RC_FAILURE;
        struct spi_device spi;
        int bus = 0;
        struct spi_transfer t;
        struct spi_message m;

    #ifdef WOLFTPM_CHECK_WAIT_STATE
        #error SPI check wait state logic not supported for BareBox
    #endif

        XMEMSET(&spi, 0, sizeof(spi));
        spi.master = spi_get_master(bus);   /* get bus 0 master */
        spi.max_speed_hz = 1 * 1000 * 1000; /* 1 MHz */
        spi.mode = 0;                       /* Mode 0 (CPOL=0, CPHA=0) */
        spi.bits_per_word = 8;              /* 8-bits */
        spi.chip_select = 0;                /* Use CS 0 */

        /* setup SPI master */
        ret = spi.master->setup(&spi);

        /* setup transfer */
        XMEMSET(&t, 0, sizeof(t));
        t.tx_buf = txBuf;
        t.rx_buf = rxBuf;
        t.len    = xferSz;
        spi_message_init(&m);
        spi_message_add_tail(&t, &m);
        ret = spi_sync(&spi, &m);
        if (ret == 0)
            ret = TPM_RC_SUCCESS;

        (void)userCtx;
        (void)ctx;

        return ret;
    }

#endif
#endif /* !(WOLFTPM_LINUX_DEV || WOLFTPM_SWTPM || WOLFTPM_WINAPI) */
#endif /* WOLFTPM_INCLUDE_IO_FILE */

/******************************************************************************/
/* --- END IO Callback Logic -- */
/******************************************************************************/

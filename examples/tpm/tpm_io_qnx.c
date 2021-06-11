/* tpm_io_qnx.c
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

/* This example shows IO interfaces for QNX */


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

#if defined(__QNX__) || defined(__QNXNTO__)
    /* QNX */
    #include "hw/spi-master.h"
    #ifndef TPM2_SPI_DEV
    #define TPM2_SPI_DEV "/dev/spi0"
    #endif

    /* customization to QNX SPI master to allow keeping
        CS asserted (low) till spi_close. See IDE/QNX for spi_master patch */
    #ifndef SPI_MODE_MAN_CS
    #define SPI_MODE_MAN_CS   (1 << 17) /* Manual Chip select */
    #endif
    #ifndef SPI_MODE_CLEAR_CS
    #define SPI_MODE_CLEAR_CS (1 << 18) /* Clear all chip selects (must be used with SPI_MODE_MAN_CS) */
    #endif

    int TPM2_IoCb_QNX_SPI(TPM2_CTX* ctx, const byte* txBuf,
        byte* rxBuf, word16 xferSz, void* userCtx)
    {
        int fd;
        int ret = TPM_RC_FAILURE;
        int status;
    #ifdef WOLFTPM_CHECK_WAIT_STATE
        int timeout = TPM_SPI_WAIT_RETRY;
    #endif
        spi_cfg_t cfg;

        /* open device */
        fd = spi_open(TPM2_SPI_DEV);
        if (fd == -1) {
            return TPM_RC_FAILURE;
        }
        XMEMSET(&cfg, 0, sizeof(cfg));
        cfg.mode = 8; /* 8-bits - CPOL=0/CPHA=0 */
    #ifdef WOLFTPM_CHECK_WAIT_STATE
        cfg.mode |= SPI_MODE_MAN_CS; /* manual chip select - leave asserted */
    #endif
        cfg.clock_rate = TPM2_SPI_HZ;
        status = spi_setcfg(fd, SPI_DEV_DEFAULT, &cfg);
        if (status != 0) {
            spi_close(fd);
            return TPM_RC_FAILURE;
        }

    #ifdef WOLFTPM_CHECK_WAIT_STATE
        /* Send Header */
        status = spi_xchange(fd, SPI_DEV_DEFAULT,
            (byte*)txBuf, rxBuf, TPM_TIS_HEADER_SZ);
        if (status == -1) {
            /* inform spi_master we are done... de-assert SPI */
            cfg.mode |= (SPI_MODE_MAN_CS | SPI_MODE_CLEAR_CS);
            (void)spi_setcfg(fd, SPI_DEV_DEFAULT, &cfg);
            spi_close(fd);
            return TPM_RC_FAILURE;
        }

        /* Check for wait states */
        if ((rxBuf[TPM_TIS_HEADER_SZ-1] & TPM_TIS_READY_MASK) == 0) {
            do {
                /* Check for SPI ready */
                status = spi_xchange(fd, SPI_DEV_DEFAULT,
                    (byte*)txBuf, rxBuf, 1);
                if (status != -1 && rxBuf[0] & TPM_TIS_READY_MASK)
                    break;
            } while (--timeout > 0);
        #ifdef WOLFTPM_DEBUG_TIMEOUT
            printf("SPI Ready Wait %d\n", TPM_SPI_WAIT_RETRY - timeout);
        #endif
            if (timeout <= 0) {
                /* inform spi_master we are done... de-assert SPI */
                cfg.mode |= (SPI_MODE_MAN_CS | SPI_MODE_CLEAR_CS);
                (void)spi_setcfg(fd, SPI_DEV_DEFAULT, &cfg);
                spi_close(fd);
                return TPM_RC_FAILURE;
            }
        }

        /* Send remainder of payload */
        status = spi_xchange(fd, SPI_DEV_DEFAULT,
            (byte*)&txBuf[TPM_TIS_HEADER_SZ],
            &rxBuf[TPM_TIS_HEADER_SZ],
            xferSz - TPM_TIS_HEADER_SZ);

        /* inform spi_master we are done... de-assert SPI */
        cfg.mode |= (SPI_MODE_MAN_CS | SPI_MODE_CLEAR_CS);
        (void)spi_setcfg(fd, SPI_DEV_DEFAULT, &cfg);
    #else
        /* Send Entire Message - no wait states */
        status = spi_xchange(fd, SPI_DEV_DEFAULT,
            (byte*)txBuf, rxBuf, xferSz);
    #endif /* WOLFTPM_CHECK_WAIT_STATE */
        if (status != -1) {
            ret = TPM_RC_SUCCESS;
        }

        spi_close(fd);

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

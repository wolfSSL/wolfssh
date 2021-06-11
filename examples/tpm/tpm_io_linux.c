/* tpm_io_linux.c
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

/* This example shows IO interfaces for Linux using the kernel spidev and i2c driver
 *
 * NB: To use /dev/tpm0, wolfTPM does not require an IO callback, just pass NULL
 *
 * */


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

#if defined(__linux__)
    #include <sys/ioctl.h>
    #ifdef WOLFTPM_I2C
        #include <linux/types.h>
        #include <linux/i2c.h>
        #include <linux/i2c-dev.h>
        #include <sys/ioctl.h>
        #include <sys/types.h>
        #include <sys/stat.h>
    #else
        #include <linux/spi/spidev.h>
    #endif
    #include <fcntl.h>
    #include <unistd.h>

    #ifdef WOLFTPM_I2C
        /* I2C - (Only tested with ST33HTPH I2C) */
        #define TPM2_I2C_ADDR 0x2e
        #define TPM2_I2C_DEV  "/dev/i2c-1"
        #define TPM2_I2C_HZ   400000 /* 400kHz */
    #else
        /* SPI */
        #ifdef WOLFTPM_MCHP
            /* Microchip ATTPM20 uses CE0 */
            #define TPM2_SPI_DEV_CS "0"
        #elif defined(WOLFTPM_ST33)
            /* STM ST33HTPH SPI uses CE0 */
            #define TPM2_SPI_DEV_CS "0"
        #elif defined(WOLFTPM_NUVOTON)
            /* Nuvoton NPCT75x uses CE0 */
            #define TPM2_SPI_DEV_CS "0"
        #else
            /* OPTIGA SLB9670 and LetsTrust TPM use CE1 */
            #define TPM2_SPI_DEV_CS "1"
        #endif

        #ifdef WOLFTPM_AUTODETECT
            #undef TPM2_SPI_DEV
            /* this will try incrementing spidev chip selects */
            static char TPM2_SPI_DEV[] = "/dev/spidev0.0";
            #define MAX_SPI_DEV_CS '4'
            static int foundSpiDev = 0;
        #else
            #define TPM2_SPI_DEV "/dev/spidev0."TPM2_SPI_DEV_CS
        #endif
    #endif
#endif


#if defined(__linux__)
#if defined(WOLFTPM_I2C)
    #define TPM_I2C_TRIES 10
    static int i2c_read(int fd, word32 reg, byte* data, int len)
    {
        int rc;
        struct i2c_rdwr_ioctl_data rdwr;
        struct i2c_msg msgs[2];
        unsigned char buf[2];
        int timeout = TPM_I2C_TRIES;

        rdwr.msgs = msgs;
        rdwr.nmsgs = 2;
        buf[0] = (reg & 0xFF); /* address */

        msgs[0].flags = 0;
        msgs[0].buf = buf;
        msgs[0].len = 1;
        msgs[0].addr = TPM2_I2C_ADDR;

        msgs[1].flags = I2C_M_RD;
        msgs[1].buf =  data;
        msgs[1].len =  len;
        msgs[1].addr = TPM2_I2C_ADDR;

        /* The I2C device may hold clock low to indicate busy, which results in
         * ioctl failure here. Typically the retry completes in 1-3 retries.
         * Its important to keep device open during these retries */
        do {
            rc = ioctl(fd, I2C_RDWR, &rdwr);
            if (rc != -1)
                break;
        } while (--timeout > 0);

        return (rc == -1) ? TPM_RC_FAILURE : TPM_RC_SUCCESS;
    }

    static int i2c_write(int fd, word32 reg, byte* data, int len)
    {
        int rc;
        struct i2c_rdwr_ioctl_data rdwr;
        struct i2c_msg msgs[1];
        byte buf[MAX_SPI_FRAMESIZE+1];
        int timeout = TPM_I2C_TRIES;

        /* TIS layer should never provide a buffer larger than this,
           but double check for good coding practice */
        if (len > MAX_SPI_FRAMESIZE)
            return BAD_FUNC_ARG;

        rdwr.msgs = msgs;
        rdwr.nmsgs = 1;
        buf[0] = (reg & 0xFF); /* address */
        XMEMCPY(buf + 1, data, len);

        msgs[0].flags = 0;
        msgs[0].buf = buf;
        msgs[0].len = len + 1;
        msgs[0].addr = TPM2_I2C_ADDR;

        /* The I2C device may hold clock low to indicate busy, which results in
         * ioctl failure here. Typically the retry completes in 1-3 retries.
         * Its important to keep device open during these retries */
        do {
            rc = ioctl(fd, I2C_RDWR, &rdwr);
            if (rc != -1)
                break;
        } while (--timeout > 0);

        return (rc == -1) ? TPM_RC_FAILURE : TPM_RC_SUCCESS;
    }

    /* Use Linux I2C */
    int TPM2_IoCb_Linux_I2C(TPM2_CTX* ctx, int isRead, word32 addr, byte* buf,
        word16 size, void* userCtx)
    {
        int ret = TPM_RC_FAILURE;
        int i2cDev = open(TPM2_I2C_DEV, O_RDWR);
        if (i2cDev >= 0) {
            if (isRead)
                ret = i2c_read(i2cDev, addr, buf, size);
            else
                ret = i2c_write(i2cDev, addr, buf, size);

            close(i2cDev);
        }

        (void)ctx;
        (void)userCtx;

        return ret;
    }

#else
    /* Use Linux SPI synchronous access */
    int TPM2_IoCb_Linux_SPI(TPM2_CTX* ctx, const byte* txBuf, byte* rxBuf,
        word16 xferSz, void* userCtx)
    {
        int ret = TPM_RC_FAILURE;
        int spiDev;
    #ifdef WOLFTPM_CHECK_WAIT_STATE
        int timeout = TPM_SPI_WAIT_RETRY;
    #endif

        /* Note: PI has issue with 5-10Mhz on packets sized over 130 bytes */
        unsigned int maxSpeed = TPM2_SPI_HZ;
        int mode = 0; /* Mode 0 (CPOL=0, CPHA=0) */
        int bits_per_word = 8; /* 8-bits */

    #ifdef WOLFTPM_AUTODETECT
    tryagain:
    #endif

        spiDev = open(TPM2_SPI_DEV, O_RDWR);
        if (spiDev >= 0) {
            struct spi_ioc_transfer spi;
            size_t size;

            ioctl(spiDev, SPI_IOC_WR_MODE, &mode);
            ioctl(spiDev, SPI_IOC_WR_MAX_SPEED_HZ, &maxSpeed);
            ioctl(spiDev, SPI_IOC_WR_BITS_PER_WORD, &bits_per_word);

            XMEMSET(&spi, 0, sizeof(spi));
            spi.cs_change = 1; /* strobe CS between transfers */

    #ifdef WOLFTPM_CHECK_WAIT_STATE
            /* Send Header */
            spi.tx_buf   = (unsigned long)txBuf;
            spi.rx_buf   = (unsigned long)rxBuf;
            spi.len      = TPM_TIS_HEADER_SZ;
            size = ioctl(spiDev, SPI_IOC_MESSAGE(1), &spi);
            if (size != TPM_TIS_HEADER_SZ) {
                close(spiDev);
                return TPM_RC_FAILURE;
            }

            /* Handle SPI wait states (ST33 typical wait is 2 bytes) */
            if ((rxBuf[TPM_TIS_HEADER_SZ-1] & TPM_TIS_READY_MASK) == 0) {
                do {
                    /* Check for SPI ready */
                    spi.len = 1;
                    size = ioctl(spiDev, SPI_IOC_MESSAGE(1), &spi);
                    if (rxBuf[0] & TPM_TIS_READY_MASK)
                        break;
                } while (size == 1 && --timeout > 0);
            #ifdef WOLFTPM_DEBUG_TIMEOUT
                printf("SPI Ready Timeout %d\n", TPM_SPI_WAIT_RETRY - timeout);
            #endif
                if (size == 1 && timeout > 0) {
                    ret = TPM_RC_SUCCESS;
                }
            }
            else {
                ret = TPM_RC_SUCCESS;
            }

            if (ret == TPM_RC_SUCCESS) {
                /* Remainder of message */
                spi.tx_buf   = (unsigned long)&txBuf[TPM_TIS_HEADER_SZ];
                spi.rx_buf   = (unsigned long)&rxBuf[TPM_TIS_HEADER_SZ];
                spi.len      = xferSz - TPM_TIS_HEADER_SZ;
                size = ioctl(spiDev, SPI_IOC_MESSAGE(1), &spi);

                if (size == (size_t)xferSz - TPM_TIS_HEADER_SZ)
                    ret = TPM_RC_SUCCESS;
            }
    #else
            /* Send Entire Message - no wait states */
            spi.tx_buf   = (unsigned long)txBuf;
            spi.rx_buf   = (unsigned long)rxBuf;
            spi.len      = xferSz;
            size = ioctl(spiDev, SPI_IOC_MESSAGE(1), &spi);
            if (size == (size_t)xferSz)
                ret = TPM_RC_SUCCESS;
    #endif /* WOLFTPM_CHECK_WAIT_STATE */

            close(spiDev);
        }

    #ifdef WOLFTPM_AUTODETECT
        /* if response is not 0xFF then we "found" something */
        if (!foundSpiDev) {
            if (ret == TPM_RC_SUCCESS && rxBuf[0] != 0xFF) {
        #ifdef DEBUG_WOLFTPM
                printf("Found TPM @ %s\n", TPM2_SPI_DEV);
        #endif
                foundSpiDev = 1;
            }
            else {
                int devLen = (int)XSTRLEN(TPM2_SPI_DEV);
                /* tries spidev0.[0-4] */
                if (TPM2_SPI_DEV[devLen-1] <= MAX_SPI_DEV_CS) {
                    TPM2_SPI_DEV[devLen-1]++;
                    goto tryagain;
                }
            }
        }
    #endif

        (void)ctx;
        (void)userCtx;

        return ret;
    }
#endif /* WOLFTPM_I2C */
#endif /* __linux__ */
#endif /* !(WOLFTPM_LINUX_DEV || WOLFTPM_SWTPM || WOLFTPM_WINAPI) */
#endif /* WOLFTPM_INCLUDE_IO_FILE */

/******************************************************************************/
/* --- END IO Callback Logic -- */
/******************************************************************************/

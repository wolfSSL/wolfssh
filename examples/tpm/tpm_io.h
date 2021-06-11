/* tpm_io.h
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

#ifndef _TPM_IO_H_
#define _TPM_IO_H_

#include <wolftpm/tpm2.h>

#ifdef __cplusplus
    extern "C" {
#endif

/* TPM2 IO Examples */

/** @defgroup TPM2_IO wolfTPM2 IO HAL Callbacks
 *
 * This module describes the available example TPM 2.0 IO HAL Callbacks in wolfTPM
 *
 * wolfTPM uses a single IO callback function.
 * This allows the TPM 2.0 stack to be highly portable.
 * These IO Callbacks are working examples for various embedded platforms and operating systems.
 *
 * Here is a non exhaustive list of the existing TPM 2.0 IO Callbacks
 * * ST Micro STM32, through STM32 CubeMX HAL
 * * Native Linux (/dev/tpm0)
 * * Linux through spidev without kernel driver thanks to wolfTPM own TIS layer
 * * Linux through i2c without kernel driver thanks to wolfTPM own TIS layer
 * * Native Windows
 * * Atmel MCUs
 * * Xilinx Zynq
 * * Barebox
 * * QNX
 *
 * Using custom IO Callback is always possible.
 *
 */

#if defined(WOLFTPM_LINUX_DEV) || defined(WOLFTPM_SWTPM) || defined(WOLFTPM_WINAPI)
#define TPM2_IoCb NULL
#else

#ifdef WOLFTPM_ADV_IO
int TPM2_IoCb(TPM2_CTX*, int isRead, word32 addr, byte* buf, word16 size,
    void* userCtx);
#else
int TPM2_IoCb(TPM2_CTX* ctx, const byte* txBuf, byte* rxBuf,
    word16 xferSz, void* userCtx);
#endif
#endif /* !(WOLFTPM_LINUX_DEV || WOLFTPM_SWTPM || WOLFTPM_WINAPI) */

/* Platform support, in alphabetical order */
#ifdef WOLFTPM_I2C
#if defined(__linux__)
int TPM2_IoCb_Linux_I2C(TPM2_CTX* ctx, int isRead, word32 addr, byte* buf,
    word16 size, void* userCtx);
#elif defined(WOLFSSL_STM32_CUBEMX)
int TPM2_IoCb_STCubeMX_I2C(TPM2_CTX* ctx, int isRead, word32 addr,
    byte* buf, word16 size, void* userCtx);
#endif /* __linux__ */
#else /* SPI */
#if defined(WOLFSSL_ATMEL)
int TPM2_IoCb_Atmel_SPI(TPM2_CTX* ctx, const byte* txBuf, byte* rxBuf,
    word16 xferSz, void* userCtx);
#elif defined(__BAREBOX__)
int TPM2_IoCb_Barebox_SPI(TPM2_CTX* ctx, const byte* txBuf,
    byte* rxBuf, word16 xferSz, void* userCtx);
#elif defined(__linux__)
int TPM2_IoCb_Linux_SPI(TPM2_CTX* ctx, const byte* txBuf, byte* rxBuf,
    word16 xferSz, void* userCtx);
#elif defined(WOLFSSL_STM32_CUBEMX)
int TPM2_IoCb_STCubeMX_SPI(TPM2_CTX* ctx, const byte* txBuf, byte* rxBuf,
    word16 xferSz, void* userCtx);
#elif defined(__QNX__) || defined(__QNXTO__)
int TPM2_IoCb_QNX_SPI(TPM2_CTX* ctx, const byte* txBuf,
    byte* rxBuf, word16 xferSz, void* userCtx);
#elif defined(__XILINX__)
int TPM2_IoCb_Xilinx_SPI(TPM2_CTX* ctx, const byte* txBuf,
    byte* rxBuf, word16 xferSz, void* userCtx);
#endif /* WOLFSSL_ATMEL */
#endif /* WOLFTPM_I2C */

#ifdef __cplusplus
    }  /* extern "C" */
#endif

#endif /* _TPM_IO_H_ */

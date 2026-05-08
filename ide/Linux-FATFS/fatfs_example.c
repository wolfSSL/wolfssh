/* sftpclient.c
 *
 * Copyright (C) 2014-2026 wolfSSL Inc.
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
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "ff.h"
#include "diskio.h"

#define STORAGE_FILE_PATH "fatfs_image.img"

static FILE *storage_file = NULL;

/* Initialize the storage file */
DSTATUS disk_initialize(BYTE pdrv) {
    if (pdrv != 0) return STA_NOINIT;  /* Only support one drive (0) */
    
    /* Open the storage file in read/write binary mode */
    storage_file = fopen(STORAGE_FILE_PATH, "r+b");
    if (!storage_file) {
        perror("Failed to open storage file");
        return STA_NODISK | STA_NOINIT;
    }
    
    return 0;  /* Initialization successful */
}

/* Get the status of the storage file */
DSTATUS disk_status(BYTE pdrv) {
    if (pdrv != 0) return STA_NOINIT;  /* Only support one drive (0) */
    if (!storage_file) return STA_NODISK;
    return 0;
}

/* Read sectors from the storage file */
DRESULT disk_read(BYTE pdrv, BYTE* buff, LBA_t sector, UINT count) {
    if (pdrv != 0) return RES_PARERR;  /* Only support one drive (0) */
    if (!storage_file) return RES_NOTRDY;
    
    off_t offset = sector * FF_MIN_SS;  /* Calculate the byte offset */
    if (fseek(storage_file, offset, SEEK_SET) != 0) {
        perror("Failed to seek in storage file");
        return RES_ERROR;
    }
    
    size_t bytes_read = fread(buff, FF_MIN_SS, count, storage_file);
    if (bytes_read != count) {
        perror("Failed to read from storage file");
        return RES_ERROR;
    }
    
    return RES_OK;
}

/* Write sectors to the storage file */
DRESULT disk_write(BYTE pdrv, const BYTE* buff, LBA_t sector, UINT count) {
    if (pdrv != 0) return RES_PARERR;  /* Only support one drive (0) */
    if (!storage_file) return RES_NOTRDY;
    
    off_t offset = sector * FF_MIN_SS;  /* Calculate the byte offset */
    if (fseek(storage_file, offset, SEEK_SET) != 0) {
        perror("Failed to seek in storage file");
        return RES_ERROR;
    }
    
    size_t bytes_written = fwrite(buff, FF_MIN_SS, count, storage_file);
    if (bytes_written != count) {
        perror("Failed to write to storage file");
        return RES_ERROR;
    }
    
    fflush(storage_file);  /* Ensure data is written to disk */
    return RES_OK;
}

/* Control the device */
DRESULT disk_ioctl(BYTE pdrv, BYTE cmd, void* buff) {
    if (pdrv != 0) return RES_PARERR;  /* Only support one drive (0) */
    
    switch (cmd) {
        case CTRL_SYNC:
            /* Ensure all data is written to disk */
            fflush(storage_file);
            break;
        
        case GET_SECTOR_SIZE:
            *(WORD*)buff = FF_MIN_SS;
            break;
        
        case GET_BLOCK_SIZE:
            *(DWORD*)buff = 1;  /* One sector per block (minimum) */
            break;
        
        default:
            return RES_PARERR;
    }
    
    return RES_OK;
}

/* Function to deinitialize the storage file */
DSTATUS disk_deinitialize(BYTE pdrv) {
    if (pdrv != 0) return STA_NOINIT;  /* Only support one drive (0) */
    
    if (storage_file) {
        fclose(storage_file);
        storage_file = NULL;
    }
    
    return 0;  /* Deinitialization successful */
}

/* FatFs disk I/O driver interface */
DSTATUS disk_status_(BYTE pdrv) { return disk_status(pdrv); }
DRESULT disk_read_(BYTE pdrv, BYTE* buff, LBA_t sector, UINT count) { return disk_read(pdrv, buff, sector, count); }
DRESULT disk_write_(BYTE pdrv, const BYTE* buff, LBA_t sector, UINT count) { return disk_write(pdrv, buff, sector, count); }
DRESULT disk_ioctl_(BYTE pdrv, BYTE cmd, void* buff) { return disk_ioctl(pdrv, cmd, buff); }

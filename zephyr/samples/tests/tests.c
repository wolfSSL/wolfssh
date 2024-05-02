/* tests.c
 *
 * Copyright (C) 2014-2024 wolfSSL Inc.
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

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif


#ifdef WOLFSSL_USER_SETTINGS
    #include <wolfssl/wolfcrypt/settings.h>
#else
    #include <wolfssl/options.h>
#endif

/* tests/unit.h collides with the wolfSSL header so use relative include */
#include "../../../tests/unit.h"
#include "../../../tests/testsuite.h"
#include "../../../tests/api.h"
#include "../../../tests/sftp.h"
#include <stdio.h>
#include <wolfssh/settings.h>
#include <wolfssh/ssh.h>

#ifndef NO_FILESYSTEM
#ifndef CONFIG_FAT_FILESYSTEM_ELM
#error "This test is designed for FAT FS"
#endif
#include <zephyr/fs/fs.h>
#include <zephyr/storage/disk_access.h>
#include <ff.h>
#endif

#define CHECK_TEST_RETURN(func) do {                \
    printf("\tRunning %s... ", #func);              \
    ret = (func);                                   \
    if (ret != 0) {                                 \
        printf("failed with %d\n", ret);            \
        goto exit_main;                             \
    }                                               \
    printf("ok\n");                                 \
} while(0)


int main(void)
{
    int ret = 0;
#ifndef NO_FILESYSTEM
    static FATFS fat_fs;
    static struct fs_mount_t mnt_point = {
        .type = FS_FATFS,
        .mnt_point = CONFIG_WOLFSSH_SFTP_DEFAULT_DIR,
        .fs_data = &fat_fs,
    };
    struct fs_file_t zfp;
    char file_contents[5];
    int i;
    char filename[50];

    WMEMSET(file_contents, 0xFE, sizeof(file_contents));

    /* +1 because the default dir mount point starts with a / and we want to
     * remove it when formatting */
    CHECK_TEST_RETURN(fs_mkfs(FS_FATFS,
            (uintptr_t)(CONFIG_WOLFSSH_SFTP_DEFAULT_DIR+1), NULL, 0));
    CHECK_TEST_RETURN(fs_mount(&mnt_point));
    /* Setup the necessary files for the sftp tests */
    fs_file_t_init(&zfp);
    snprintf(filename, sizeof(filename), "%s/%s",
            CONFIG_WOLFSSH_SFTP_DEFAULT_DIR, "configure.ac");
    CHECK_TEST_RETURN(fs_open(&zfp, filename, FS_O_WRITE|FS_O_CREATE));
    /* Write some random data to file */
    for (i = 0; i < 10; i++)
        CHECK_TEST_RETURN(fs_write(&zfp, file_contents, sizeof(file_contents))
                            < 0);

    CHECK_TEST_RETURN(fs_close(&zfp));
#endif

    CHECK_TEST_RETURN(wolfSSH_UnitTest(0, NULL));
    CHECK_TEST_RETURN(wolfSSH_TestsuiteTest(0, NULL));
    CHECK_TEST_RETURN(wolfSSH_ApiTest(0, NULL));
    printf("Zephyr wolfSSH tests passed\n");

exit_main:
    return ret;
}

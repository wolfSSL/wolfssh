# FATFS Linux Example

This is a FATFS example that uses a single file on the Linux filesystem as the
FATFS file system.

## Compiling Library

To compile the FATFS library simply run `make`.

## Setup filesystem

The single file used for FATFS should be generated using:

```sh
dd if=/dev/zero of=fatfs_image.img bs=1M count=32
mkdosfs fatfs_image.img
```

Note that this file will need to be local to wherever you execute anything using
the library.

## Compiling wolfSSH and wolfSSL

### wolfSSL

```sh
./configure --enable-wolfssh --enable-intelasm --disable-crl --disable-examples --disable-filesystem CFLAGS="-DNO_WOLFSSL_DIR"
```

### wolfSSH

```sh
export LD_LIBRARY_PATH=ide/Linux-FATFS
./configure --enable-sftp CFLAGS="-DWOLFSSH_FATFS -Iide/Linux-FATFS -DSTDIN_FILENO=0 -DPRINTF=printf -lfatfs"
```


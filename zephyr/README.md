Zephyr Project Port
===================

## Overview

This port is for the Zephyr RTOS Project, available [here](https://www.zephyrproject.org/).


It provides the following zephyr code.

- modules/lib/wolfssh
    - wolfSSH library code
- modules/lib/wolfssh/zephyr/
    - Configuration and CMake files for wolfSSH as a Zephyr module
- modules/lib/wolfssh/zephyr/samples/tests
    - wolfSSH tests

## How to setup as a Zephyr Module

Follow the [instructions](https://docs.zephyrproject.org/latest/develop/getting_started/index.html) to setup a zephyr project.

### Modify your project's west manifest

Add wolfSSH as a project to your west.yml:

```
manifest:
  remotes:
    # <your other remotes>
    - name: wolfssh
      url-base: https://github.com/wolfssl

  projects:
    # <your other projects>
    - name: wolfssh
      path: modules/lib/wolfssh
      revision: master
      remote: wolfssh
```

Update west's modules:

```bash
west update
```

Now west recognizes 'wolfssh' as a module, and will include it's Kconfig and
CMakeFiles.txt in the build system.

## Build and Run Samples

If you want to run build apps without running `west zephyr-export` then it is
possible by setting the `CMAKE_PREFIX_PATH` variable to the location of the
zephyr sdk and building from the `zephyr` directory. For example:

```
CMAKE_PREFIX_PATH=/path/to/zephyr-sdk-<VERSION> west build -p always -b qemu_x86 ../modules/lib/wolfssh/zephyr/samples/tests/
```

### Build and Run Tests

build and execute `tests`

```bash
cd [zephyrproject]
west build -p auto -b qemu_x86 modules/lib/wolfssh/zephyr/samples/tests
west build -t run
```


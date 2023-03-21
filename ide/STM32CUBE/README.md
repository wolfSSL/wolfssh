# wolfSSH for STM32 Cube IDE 

The wolfSSH Cube Pack can be found [here](https://www.wolfssl.com/files/ide/I-CUBE-wolfSSH.pack)

1. The first step is to setup the wolfCrypt library in your ST project following the guide here [https://github.com/wolfSSL/wolfssl/blob/master/IDE/STM32Cube/README.md](https://github.com/wolfSSL/wolfssl/blob/master/IDE/STM32Cube/README.md). To run the wolfSSH unit tests, name the entry function `wolfSSHTest` instead of `wolfCryptDemo`.

2. Then install the wolfSSH Cube Pack in the same manner as the wolfSSL pack with CUBEMX.

3. Open the project `.ioc` file and click the `Softare Packs` drop down menu and then `Select Components`. Expand the `wolfSSH` pack and check all the components. 

4. In the `Softare Packs` configuration category of the `.ioc` file, click on the wolfSSH pack and enable the library by checking the box.

5. Since LwIP is a dependency for the Cube Pack, enable LwIP in the `Middleware` configuration category of the project. Also enable the `LWIP_DNS` option in the LwIP configuration settings.

6. Save your changes and select yes to the prompt asking about generating code.

7. Build the project and run the unit tests.

## Notes
- Make sure to make [these changes](https://github.com/wolfSSL/wolfssl/tree/master/IDE/STM32Cube#stm32-printf) to redirect the printf's to the UART.

- If looking to enable filesystem support, the pack assumes the user has defined their own filesystem in `wolfssh/myFilesystem.h`. That file will originally contain a dummy filesystem. If going the FATFS route, make sure to replace `#define WOLFSSH_USER_FILESYSTEM` with `#define WOLFSSH_FATFS` in the `wolfSSL.I-CUBE-wolfSSH_conf.h` header file. The wolfSSL Cube Pack also defaults to disabling filesystem support so make sure to remove `#define NO_FILESYSTEM` from `wolfSSL.I-CUBE-wolfSSL_conf.h`.

wolfSSH simple sftp client application project for RX72N EnvisionKit board
======
## 1. Overview
-----

We provide a simple sftp client program for evaluating wolfSSH targeting the RX72N evaluation board, which has RX72 MCU on it. The sample program runs in a bare metal environment that does not use a real-time OS and uses e2 studio as an IDE. This document describes the procedure from build to execution of the sample program.

The sample provided is a single application that can evaluate the following functions:

- SFTP Client: A program that performs SFTP communication with the opposite SSH/SFTP server

Since the H/W settings and S/W settings for operating the evaluation board have already been prepared, the minimum settings are required to operate the sample application.

The following sections will walk you through the steps leading up to running the sample application.
## 2. Target H/W, components and libraries
-----

This sample program uses the following hardware and software libraries. If a new version of the software component is available at the time of use, please update it as appropriate.

|item|name & version|
|:--|:--|
|Board|RX72N EnvisionKit|
|Device|R5F572NNHxFB|
|IDE| Renesas e2Studio Version:2025-04.1 (25.4.1) |
|Emulator| E2 Emulator Lite |
|Toolchain|CCRX v3.06.00|

The project of this sample program has a configuration file that uses the following FIT components.
However, the FIT components themselves are not included in the distribution of this sample application. You need to download it by operating in the IDE. Some FIT components (TSIPs) cannot be downloaded directly from within the IDE and may need to be downloaded separately from the Renesas download site.


|FIT component|version|name|
|:--|:--|:--|
|Board Support Packages|7.53|r_bsp|
|CMT driver|5.71|r_cmt_rx|
|Ethernet Driver|1.21|r_ether_rx|
|Generic system timer for RX MCUs|1.01|r_sys_time_rx|
|Memory Driver Interface for Open Source FAT File System|2.61|r_tfat_driver_rx|
|Open Source FAT File System|4.14|r_tfat_rx|
|SD Mode SD Memory Card Driver|3.01|r_sdc_sdmem_rx|
|SD Mode SDHI Driver|2.12|r_sdhi_rx|
|TCP/IP protocol stack[M3S-T4-Tiny] - RX Ethernet Driver Interface|1.09|r_t4_driver_rx|
|TCP/IP protocol stack[M3S-T4-Tiny] for Renesas MCUs|2.10|r_t4_rx|
|TSIP(Trusted Secure IP) driver|1.22|r_tsip_rx|

## 3. Importing a simple sftp client application project into e2Studio
----

There is no need to create a new sample program. Since the project file is already prepared, please import the project from the IDE by following the steps below.

+ e2studio "File" menu> "Open project from file system ..."> "Directory (R) ..." Click the import source button and select the folder from which the project will be imported. Select the folder (Renesas/e2studio/{MCU}/{board-name-folder}/) where this README file exists.
+ Three projects that can be imported are listed, but check only the four projects "app_sftpclient", "wolfcrypt_test", "wolfssl_RX72N" and "wolfssh_RX72N" and click the "Finish" button.

## 4. FIT module download and smart configurator file generation
----

You will need to get the required FIT modules yourself. Follow the steps below to get them.

1. Open the test project in Project Explorer and double-click the **app_sftpclient.scfg** file to open the Smart Configurator Perspective.

2. Select the "Components" tab on the software component settings pane. Then click the "Add Component" button at the top right of the pane. The software component selection dialog will pop up. Click "Download the latest version of FIT driver and middleware" at the bottom of the dialog to get the modules. You can check the download destination folder by pressing "Basic settings...".

3. The latest version of the TSIP component may not be automatically obtained due to the delay in Renesas' support by the method in step 2 above. In that case, you can download it manually from the Renesas website. Unzip the downloaded component and store the files contained in the FIT Modules folder in the download destination folder of step 2.

4. Select the required FIT components shown from the list and press the "Finish" button. Repeat this operation until you have the required FIT components.

5. Select the Components tab on the Software Component Settings pane and select the r_t4_rx component. In the settings pane on the right, specify the IP address of this board as the value of the "# IP address for ch0, when DHCP disable." Property (e.g. 192.168.1.9).

6. Press the "Generate Code" button at the top right of the software component settings pane to have the smart configurator generate the source files. A src/smc_gen folder will be created under the smc project to store source files, libraries, etc.

## 5. SFTP Server and Port Settings for SFTP Client Test Application
----

The test project is a very simple sftp client application, which connects to echo server and gets `working directory` listing.
Before building the test application, set the SFTP server IP address and port number in the project properties.

- SFTP_SERVER_IP : IP address of the SFTP server
- SFTP_SERVER_PORT : Port number of the SFTP server (default: 22222)

Then build the test application.

## 6. Build and run the the application
-----

Now that the test application is ready to build.

1. Build the wolfssl and wolfssh projects on the project explorer, then the test project.

2. After a successful build, connect the target board to the emulator and supply external power.

3. Select "Run" menu> "Debug" to open the debug perspective.

4. The test application outputs the operating status to the standard output. Keep the "Renesas Debug Virtual Console" open for viewing this standard output.

5. Press the run button to run the test application.


## 8. Running sftp client application to echo server
You can see the following log output on the Renesas Debug Virtual Console when the sftp client application runs successfully and connects to the echo server.

`Server output example`
```
./examples/echoserver/echoserver
Keying Complete:
        WOLFSSH_TEXT_KEX_ALGO          : ECDH
        WOLFSSH_TEXT_KEX_CURVE         : nistp256
        WOLFSSH_TEXT_KEX_HASH          : SHA-256
        WOLFSSH_TEXT_CRYPTO_IN_CIPHER  : AES-256 GCM
        WOLFSSH_TEXT_CRYPTO_IN_MAC     : AES256 GCM (in ETM mode)
        WOLFSSH_TEXT_CRYPTO_OUT_CIPHER : AES-256 GCM
        WOLFSSH_TEXT_CRYPTO_OUT_MAC    : AES256 GCM (in ETM mode)
```

`Client output example`
```
config.status
.gitignore
sshd_config
apps
...
zephyr
libtool
Makefile.am
Makefile.in
src
aclocal.m4
sftp client completes 0
```

# 9. Support

For support inquiries and questions, please email support@wolfssl.com. Feel free to reach out to info@wolfssl.jp as well.

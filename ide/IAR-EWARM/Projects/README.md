# wolfSSH Example echoServer Setup Guide

wolfSSH exhoserver example works with wolfSSL and wolfSSH library.

## 1) Source file location

Put wolfSSL and wolfSSH files under a working directory in parallel
with the directory name of "wolfssl" and "wolfssh".

#### \<workDir\>/wolfssl
#### \<workDir\>/wolfssh

## 2) Open projects

Open wolfSSL workspace and add wolfSSH lib and echoserver project.

#### \<workDir\>/wolfssl/IDE/IAR-EWARM/Projects/wolfssl.eww
#### \<workDir\>/wolfssh/ide/IAR-EWARM/Projects/lib/wolfSSH-Lib.ewp
#### \<workDir\>/wolfssh/ide/IAR-EWARM/Projects/echoserver/echoserver.ewp

### 3) Test build of projects

Select project and Make of wolfSSL-Lib, wolfSSH-Lib and echoserver project respectively with default options.


### 4) Modify echoserver.c for your target platform

Configuration Openstions are in user_setings.h under each "Projects" directory 

#### \<workDir\>/wolfssl/IDE/IAR-EWARM/Projects/user_setings.h
#### \<workDir\>/wolfssh/ide/IAR-EWARM/Projects/user_setings.h

Put appropriate options and modify echoserve.c for your target environment. 

#### \<workDir\>/wolfssl/examples/echoserver/echoserver.c
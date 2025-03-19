This is example code for adding a wolfSSH echoserver to a MPLABX project.

For SAMV71:

1) Import the .mc3 settings. Create a new project for SAMV71, click on CM for content manager. Click "Load Manifest" and select the ide/mplabx/mcc-manifest-samv71.yml file and then click apply.
2) Open MCC then click "Import" and import ide/mplabx/wolfssh-sftp-server-samv71.mc3 and then click "Generate"
3) Adjust the "Preprocessor macros" to include WOLFSSH_IGNORE_FILE_WARN and WOLFSSL_USER_SETTINGS
4) Create a user_sttings.h file in config/sam_v71_xult_freertos that includes config.h i.e.

user_settings.h
```
  1 #ifndef USER_SETTINGS_H
  2 #define USER_SETTINGS_H
  3 #include "config.h"
  4 #endif
```

5) Remove the generated app.c from Source Files
6) Download wolfssh into src/third_party/wolfssh, for example:

```
cd src/third_party
git clone git@github.com:wolfssl/wolfssh
```

7) Right click on the project and add existing item. Select src/third_party/wolfssh/ide/mplabx/wolfssh.c
8) Right click on the project and add existing folder. Select src/third_party/wolfssh/src
9) Increase the heap size to 200,000 by right clicking on the project, selecting "Properties"->"x32-ld"
10) In "Header Files"/config/sam_v71_xult_freertos/configuration.h alter the configuration to support wolfSSH

```
// wolfSSH
#define WOLFSSL_WOLFSSH
#ifndef NO_FILESYSTEM
    #define WOLFSSH_SFTP
#endif
#define WOLFSSH_NO_HMAC_SHA2_512
#define DEFAULT_WINDOW_SZ 16384
```

If present remove NO_FILESYSTEM and NO_SIG_WRAPPER. Add NO_WOLFSSL_DIR.


Notes:

For the current project this was tested with the heap and stack set to 200,000 each. This was not trimed to see the minumum possible heap and stack usage yet. The TX buffer size used was set to 1024. The example was developed with wolfssh version 1.4.20. 

After building and flashing the board a wolfSSH echoserver will be open on port 22 which can be connected to by using the example client bundled with wolfSSH. ```./examples/client/client -u jill -P upthehill -h 192.168.1.120 -p 22```

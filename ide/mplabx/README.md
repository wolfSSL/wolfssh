# wolfSSH MPLABX

This is example project to create a wolfSSH library and example code for adding
a wolfSSH echoserver to a MPLABX project.

Tested on a ATSAMV71Q21B with MPLABX version 6.20.

### Building wolfSSH library

The library project is located at ide/mplabx/wolfssh.X

- First open wolfssh.X with MPLABX IDE then click on "CM" content manager and
import the ide/mplabx/wolfssh.X/mcc-manifest-generated-success.yml file.
- Click apply.
- Next click "MCC" and "generate".
- To build from the command line, do the following after the XC32 toolchain has
been installed.

```
cd ide/mplabx/wolfssh.X
make
```

- To build using the IDE open the project ide/mplabx/wolfssh.X and click build.


This will produce a wolfssh.X.a library in the directory
ide/mplabx/wolfssh.X/dist/default/production/wolfssh.X.a

The application and wolfSSL must be built with the same user_settings.h as the
wolfSSH library was built with! Differences in macro's defined for
configuration will cause undefined behavior and potential crashes.

### Building an example app

1) Adjust the "Preprocessor macros" to include WOLFSSL_USER_SETTINGS and add an
 include path to ide/mplabx/user_settings.h.
2) Remove the generated app.c from Source File
3) Link to the wolfssh.X.a library. Properties->Libraries->Add Library/Object
 File...
4) Right click on the project and add existing item. Select ide/mplabx/wolfssh.c
5) Increase the heap size to 200,000 by right clicking on the project, selecting
 "Properties"->"x32-ld"

Notes:

For the current project this was tested with the heap and stack set to 200,000
 each. This was not trimed to see the minumum possible heap and stack usage yet.
 The TX buffer size used was set to 1024. The example was developed with wolfssh
 version 1.4.20.

After building and flashing the board a wolfSSH echoserver will be open on port
 22 which can be connected to by using the example client bundled with wolfSSH.
 ```./examples/client/client -u jill -P upthehill -h 192.168.1.120 -p 22```

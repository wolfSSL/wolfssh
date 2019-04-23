This is example code for adding a wolfSSH echoserver to a MPLABX project.

The steps to use the code is as follows:
1) Add wolfssh.c source file to project build.
2) Make sure that current MPLABX project handles setting up TCP stack (see MPLABX examples for this /microchip/harmony/XXX/apps/examples/)
3) Add include path to wolfssh root directory.
4) Add preprocessor macro WOLFSSL_USER_SETTINGS (this is so wolfssl/wolfssh includes user_settings.h) to the project properties.
5) Add include path to user_settings.h to project properties.
6) Add APP_SSH_Tasks() and APP_SSH_Initialize() declarations to app.h header file.
7) Add call to APP_SSH_Initialize() to system_init.c
8) Add call to APP_SSH_Tasks() to system_tasks.c

For the current project this was tested with the heap and stack set to 200,000 each. This was not trimed to see the minumum possible heap and stack usage yet. The TX buffer size used was set to 1024. The example needs to use wolfssl versions that are later than 4/5/2018 (mid v3.14.0) for hardware acceleration and versions v3.14.0 and later for software only.

After building and flashing the board a wolfSSH echoserver will be open on port 22 which can be connected to by using the example client bundled with wolfSSH. ```./examples/client/client -u jill -P upthehill -h 192.168.1.120 -p 22```

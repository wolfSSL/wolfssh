# wolfSSH MPLABX

This is an example project demonstrating how to build the `wolfSSH` library and
 use it to add a SSH server to an MPLABX project.

Tested on an **ATSAMV71Q21B** using **MPLABX version 6.20**.

---

## Building the wolfSSH Library

The library project is located at:

```

ide/mplabx/wolfssh.X

```

### Using MPLABX IDE

1. Open the `wolfssh.X` project in MPLABX.
2. Click **CM (Content Manager)** and import the manifest:

```

ide/mplabx/wolfssh.X/mcc-manifest-generated-success.yml

````

3. Click **Apply**.
4. Click **MCC** and then **Generate**.
5. Build the project via the IDE (hammer icon or `Run → Build Project`).

### Using the Command Line

After installing the XC32 toolchain:

```sh
cd ide/mplabx/wolfssh.X
make
````

This produces:

```
ide/mplabx/wolfssh.X/dist/default/production/wolfssh.X.a
```

> **Important:** The application and wolfSSL must be built using the **same**
 `user_settings.h` as used for the wolfSSH library. Mismatched macros can result
 in undefined behavior or crashes.

---

## Building the Example Application

### Steps:

1. **Set Preprocessor Macros**:

   * Define `WOLFSSL_USER_SETTINGS`.
   * Add include path to `ide/mplabx/user_settings.h`.

2. **Remove** the generated `app.c` from Source Files.

3. **Link the wolfSSH Library**:

   * Go to **Project Properties → Libraries → Add Library/Object File**.
   * Select `wolfssh.X.a`.

4. **Add Source File**:

   * Right-click the project → **Add Existing Item**.
   * Select `ide/mplabx/wolfssh.c`.

5. **Increase Heap Size**:

   * Right-click the project → **Properties → XC32-ld**.
   * Set heap size to at least **200,000**.

### Notes

* Tested with heap and stack sizes of **200,000**.
* TX buffer size: **1024 bytes**.
* Tested with `wolfSSH version 1.4.20`.

After flashing the board, a wolfSSH server will be listening on port **22**.
You can connect using the provided client:

```sh
./examples/client/client -u jill -P upthehill -h 192.168.1.120 -p 22
```

---

## Overriding the File System for SFTP

This example shows how to override the SFTP file system interface and apply
 restrictions based on the logged-in user. It uses Microchip's file system but
 the approach is generic.

### Enabling a Custom File System

1. **Define `WOLFSSH_USER_FILESYSTEM`** in `user_settings.h`.

2. **Provide `myFilesystem.h`**:

   * Required when `WOLFSSH_USER_FILESYSTEM` is defined.
   * Ensure it's in your include path (e.g., move it to the wolfSSH `include/` directory).

3. **Add `myFilesystem.c`** to the wolfSSH project.

4. **Recompile** the library.

### Example File Operation Categories

* **Safe operations**: Navigation, file downloads.
* **Restricted operations**: Modifying or deleting files.

Set the custom file system handle as follows:

```c
wolfSSH_SetFilesystemHandle(ssh, (void*)ssh);
```

### Integration Example (in `wolfssh.c`)

```c
case APP_SSH_SFTP_START:
    SYS_CONSOLE_PRINT("Setting starting SFTP directory to [%s]\r\n", "/mnt/myDrive1");
    if (wolfSSH_SFTP_SetDefaultPath(ssh, "/mnt/myDrive1") != WS_SUCCESS) {
        SYS_CONSOLE_PRINT("Error setting starting directory\r\n");
        SYS_CONSOLE_PRINT("Error = %d\r\n", wolfSSH_get_error(ssh));
        appData.state = APP_SSH_CLEANUP;
    }
    wolfSSH_SetFilesystemHandle(ssh, (void*)ssh);
    appData.state = APP_SSH_SFTP;
    break;
```

### Privileged Access

Logging in as user `admin` with password `fetchapail` enables restricted operations.


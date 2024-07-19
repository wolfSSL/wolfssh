# wolfSSH v1.4.18 (July 22, 2024)

## New Features

- Add wolfSSL style static memory pool allocation support.
- Add Ed25519 public key support.
- Add Banner option to wolfSSHd configuration.
- Add non-blocking socket support to the example SCP client.

## Improvements

- Documentation updates.
- Update the Zephyr test action.
- Add a no-filesystem build to the Zephyr port.
- Update the macOS test action.
- Refactor certificate processing. Only verify certificates when a signature
  is present.
- Update the Kyber test action.
- Refactor the Curve25519 Key Agreement support.
- Update the STM32Cube Pack.
- Increase the memory that Zephyr uses for a heap for testing.
- Add a macro wrapper to replace the ReadDir function.
- Add callback hook for keying completion.
- Add function to return strings for the names of algorithms.
- Add asynchronous server side user authentication.
- Add ssh-rsa (SHA-1) to the default user auth algorithm list when
  sha1-soft-disable is disabled.
- Update Espressif examples using Managed Components.
- Add SCP test case.
- Refactor RSA sign and verify.
- Refresh the example echoserver with updates from wolfSSHd.
- Add callback hooks for most channel messages including open, close, success,
  fail, and requests.
- Reduce the number of memory allocations SCP makes.
- Improve wolfSSHd’s behavior on closing a connection. It closes channels and
  waits for the peer to close the channels.

## Fixes

- Refactor wolfSSHd service support for Windows to fix PowerShell
  Write-Progress.
- Fix partial success case with public key user authentication.
- Fix the build guards with respect to cannedKeyAlgoNames.
- Error if unable to open the local file when doing a SCP send.
- Fix some IPv6 related build issues.
- Add better checks for SCP error returns for closed channels.
- In the example SCP client, move the public key check context after the
  WOLFSSH object is created.
- Fix error reporting for wolfSSH_SFTP_STAT.
- In the example SCP client, fix error code checking on shutdown.
- Change return from wolfSSH_shutdown() to WS_CHANNEL_CLOSED.
- Fix SFTP symlink handling.
- Fix variable initialization warnings for Zephyr builds.
- Fix wolfSSHd case of non-console output handles.
- Fix testsuite for single threaded builds. Add single threaded test action.
- Fix wolfSSHd shutting down on fcntl() failure.
- Fix wolfSSHd on Windows handling virtual terminal sequences using exec
  commands.
- Fix possible null dereference when matching MAC algos during key exchange.

---

# wolfSSH v1.4.17 (March 25, 2024)

## Vulnerabilities

* Fixes a vulnerability where a properly crafted SSH client can bypass user
  authentication in the wolfSSH server code. The added fix filters the
  messages that are allowed during different operational states.

## Notes

* When building wolfSSL/wolfCrypt versions before v5.6.6 with CMake,
  wolfSSH may have a problem with RSA keys. This is due to wolfSSH not
  checking on the size of `___uint128_t`. wolfSSH sees the RSA structure
  as the wrong size. You will have to define `HAVE___UINT128_T` if you
  know you have it and are using it in wolfSSL. wolfSSL v5.6.6 exports that
  define in options.h when using CMake.
* The example server in directory examples/server/server.c has been removed.
  It was never kept up to date, the echoserver did its job as an example and
  test server.

## New Features

* Added functions to set algorithms lists for KEX at run-time, and some
  functions to inspect which algorithms are set or are available to use.
* In v1.4.15, we had disabled SHA-1 in the build by default. SHA-1 has been
  re-enabled in the build and is now "soft" disabled, where algorithms using
  it can be configured for KEX.
* Add Curve25519 KEX support for server/client key agreement.

## Improvements

* Clean up some issues when building for Nucleus.
* Clean up some issues when building for Windows.
* Clean up some issues when building for QNX.
* Added more wolfSSHd testing.
* Added more appropriate build option guard checking.
* General improvements for the ESP32 builds.
* Better terminal support in Windows.
* Better I/O pipes and return codes when running commands or scripts over an
  SSH connection.

## Fixes

* Fix shell terminal window resizing and it sets up the environment better.
* Fix some corner cases with the SFTP testing.
* Fix some corner cases with SFTP in general.
* Fix verifying RSA signatures.
* Add masking of file mode bits for Zephyr.
* Fix leak of terminal modes cache.

---

# wolfSSH v1.4.15 (December 22, 2023)

## Vulnerabilities

* Fixes a potential vulnerability described in the paper "Passive SSH Key
  Compromise via Lattices". While the misbehavior described hasn't
  been observed in wolfSSH, the fix is now implemented. The RSA signature
  is verified before sending to the peer.
  - Keegan Ryan, Kaiwen He, George Arnold Sullivan, and Nadia Heninger. 2023.
    Passive SSH Key Compromise via Lattices. Cryptology ePrint Archive,
    Report 2023/1711. https://eprint.iacr.org/2023/1711.

## Notes

* When building wolfSSL/wolfCrypt versions before v5.6.6 with CMake,
  wolfSSH may have a problem with RSA keys. This is due to wolfSSH not
  checking on the size of `___uint128_t`. wolfSSH sees the RSA structure
  as the wrong size. You will have to define `HAVE___UINT128_T` if you
  know you have it and are using it in wolfSSL. wolfSSL v5.6.6 exports that
  define in options.h when using CMake.

## New Features

* Added wolfSSH client application.
* Added support for OpenSSH-style private keys, like those made by ssh-keygen.
* Added support for the Zephyr RTOS.
* Added support for multiple authentication schemes in the userauth callback
  with the error response `WOLFSSH_USERAUTH_PARTIAL_SUCCESS`.

## Improvements

* Allow override of default sshd user name at build.
* Do not attempt to copy device files. The client won't ask, and the server
  won't do it.
* More wolfSSHd testing.
* Portability updates.
* Terminal updates for shell connections to wolfSSHd, including window size
  updates.
* QNX support updates.
* Windows file support updates for SFTP and SCP.
* Allow for longer command strings in wolfSSHd.
* Tweaked some select timeouts in the echoserver.
* Add some type size checks to configure.
* Update for changes in wolfSSL's threading wrappers.
* Updates for Espressif support and testing.
* Speed improvements for SFTP. (Fixed unnecessary waiting.)
* Windows wolfSSHd improvements.
* The functions `wolfSSH_ReadKey_file()` and `wolfSSH_ReadKey_buffer()`
  handle more encodings.
* Add function to supply new protocol ID string.
* Support larger RSA keys.
* MinGW support updates.
* Update file use W-macro wrappers with a filesystem parameter.

## Fixes

* When setting the file permissions for a file in Zephyr, use the correct
  permission constants.
* Fix buffer issue in `DoReceive()` on some edge failure conditions.
* Prevent wolfSSHd zombie processes.
* Fixed a few references to the heap variable for user supplied memory
  allocation functions.
* Fixed an index update when verifying the server's RSA signature during KEX.
* Fixed some of the guards around optional code.
* Fixed some would-block cases when using non-blocking sockets in the
  examples.
* Fixed some compile issues with liboqs.
* Fix for interop issue with OpenSSH when using AES-CTR.

---

# wolfSSH v1.4.14 (July 7, 2023)

## New Feature Additions and Improvements

- Add user authentication support for RSA signing with SHA2-256 and SHA2-512 (Following RFC 8332)
- Support for FATFS on Xilinx targets
- ecc_p256-kyber_level1 interop with OQS OpenSSH following the RFC https://www.ietf.org/id/draft-kampanakis-curdle-ssh-pq-ke-01.html
- Internal refactor of client apps to simplify them and added X509 support to scpclient
- wolfSSH_accept now returns WS_SCP_INIT and needs called again to complete the SCP operation
- Update to document Cube Pack dependencies
- Add carriage return for ‘enter’ key in the example client with shell connections to windows server
- Stack usage improvement to limit the scope of variables
- Echoserver example SFTP non blocking improvement for want read cases
- Increase SFTP performance with throughput

## Fixes

- Fix for calling chdir after chroot with wolfSSHd when jailing connections on unix environments
- Better handling on the server side for when the client’s window is filled up
- Fix for building the client project on windows when shell support is enabled
- Sanity check improvements for handling memory management with non blocking connections
- Fix for support with secondary groups with wolfSSHd
- Fixes for SFTP edge cases when used with LWiP

---

# wolfSSH v1.4.13 (Apr 3, 2023)

## New Feature Additions and Improvements

- Improvement to forking the wolfSSHd daemon.
- Added an STM32Cube Expansion pack. See the file _ide/STM32CUBE/README.md_
  for more information. (https://www.wolfssl.com/files/ide/I-CUBE-wolfSSH.pack)
- Improved test coverage for wolfSSHd.
- X.509 style private key support.

## Fixes

- Fixed shadow password checking in wolfSSHd.
- Building cleanups: warnings, types, 32-bit.
- SFTP fixes for large files.
- Testing and fixes with SFTP and LwIP.

## Vulnerabilities

- wolfSSHd would allow users without passwords to log in with any password.
  This is fixed as of this version. The return value of crypt() was not
  correctly checked. This issue was introduced in v1.4.11 and only affects
  wolfSSHd when using the default authentication callback provided with
  wolfSSHd. Anyone using wolfSSHd should upgrade to v1.4.13.

---

# wolfSSH v1.4.12 (Dec 28, 2022)

## New Feature Additions and Improvements
- Support for Green Hills Software's INTEGRITY
- wolfSSHd Release (https://github.com/wolfSSL/wolfssh/pull/453 rounds off testing and additions)
- Support for RFC 6187, using X.509 Certificates as public keys
- OCSP and CRL checking for X.509 Certificates (uses wolfSSL CertManager)
- Add callback to the server for reporting userauth result
- FPKI profile checking support
- chroot jailing for SFTP in wolfSSHd
- Permission level changes in wolfSSHd
- Add Hybrid ECDH-P256 Kyber-Level1
- Multiple server keys
- Makefile updates
- Remove dependency on wolfSSL being built with public math enabled

## Fixes
- Fixes for compiler complaints using GHS compiler
- Fixes for compiler complaints using GCC 4.0.2
- Fixes for the directory path cleanup function for SFTP
- Fixes for SFTP directory listing when on Windows
- Fixes for large file transfers with SFTP
- Fixes for port forwarding
- Fix for building with QNX
- Fix for the wolfSSHd grace time alarm
- Fixes for Yocto builds
- Fixes for issues found with fuzzing

## Vulnerabilities
- The vulnerability fixed in wolfSSH v1.4.8 finally issued CVE-2022-32073

---

# wolfSSH v1.4.11 (Aug 22, 2022)

## New Feature Additions and Improvements
- Alpha version of SSHD implementation (--enable-sshd)
- ECDSA key generation wrapper
- Espressif port and component install
- Improvements to detection of ECC RNG requirement

## Fixes
- Handle receiving extended data type with SCP connections
- Multiple non blocking fixes in SSH and SFTP use cases
- Fix for handling '.' character in file name with SFTP
- Windows build fix for SFTP with log timestamps enabled
- Fix to handle listing large directories with SFTP LS function
- Fix for checking path length when cleaning it (SFTP/SCP)

---

# wolfSSH v1.4.10 (May 13, 2022)

## New Feature Additions and Improvements
- Additional small stack optimizations to reduce stack used farther
- Update to Visual Studio paths for looking for wolfSSL library
- SFTP example, reset timeout value with get/put command
- Add support for flushing file IO using WOLFSCP_FLUSH
- Add preprocessor guards for RSA/ECC to agent and the example and test applications
- Initialization of variables to avoid warnings and use with ESP-IDF

## Fixes
- When scp receives a string in STDERR, print it out, rather than treating it as an error
- Window adjustment refactor and fix
- fix check on RSA import size
- Fix for building with older GCC versions (tested with 4.0.2)
- SFTP fix handling sent data sz when its size is greater than peer max packet size
- SFTP add error return code for a bad header when sending a packet
- KCAPI build fixes for macro guards needed
- SCP fix for handling small and empty message sizes
- SFTP update to handle WS_CHAN_RXD return values when reading
- Fix for IPv6 with scpclient
- Fixes for cross-compiling (don't force library path references)
- Fix for FIPS 140-3 on ECC private key use

# wolfSSH v1.4.8 (Nov 4, 2021)

## New Feature Additions and Improvements

- Add remote port forwarding
- Make loading user created keys into the examples easier
- Add --with-wolfssl and use --prefix to look for wolfSSL
- Updated the unsupported GlobalReq response


## Fixes

- Fix for RSA public key auth
- Fix an issue where the testsuite and echoserver a socket failure
- SFTP fix for getting attribute header
- Fix for possible null dereference in SendKexDhReply
- Remove reference to udp from test.h
- Fixes to local port forwarding

## Vulnerabilities
- When processing SFTP messages, wolfSSH isn't checking data lengths against the size of the message and is potentially under-allocating, over-reading, and over-writing buffers. Thank you to Michael Randrianantenaina, an independent security researcher, for the report.

---

# wolfSSH v1.4.7 (July 23, 2021)

## New Feature Additions and Improvements

- SCP improvements to run on embedded RTOS
- For SFTP messages, check both minimum bound and maximum bound of the length value
- Added option for --enable-small-stack
- Added SFTP support for FatFs
- Added 192 and 256 bit support for AES-CBC, AES-CTR, and AES-GCM
- Added options to disable algorithms. (ie WOLFSSH_NO_ECDSA, WOLFSSH_NO_AES_CBC, etc)
- Improved handling of builds without ECC


## Fixes
- When processing public key user auth, initialize the key earlier
- When processing public key user auth, use GetSize() instead of GetUint32()
- Fix for better handling rekey
- Fix for build with NO_WOLFSSH_CLIENT macro and --enable-all
- Fix configuration with WOLFSSH_NO_DH
- To add internal function to purge a packet in case building one fails
- Fix for cleanup in error case with SFTP read packet
- Fix initialization of DH Size values

--------------------------------

# wolfSSH v1.4.6 (February 3, 2021)

## New Feature Additions

- Added optional builds for not using RSA or ECC making the build more modular for resource constrained situations.
- MQX IDE build added
- Command line option added for Agent use with the example client



## Fixes

- Increase the ID list size for interop with some OpenSSH servers
- In the case of a network error add a close to any open files with SFTP connection
- Fix for potential memory leak with agent and a case with wolfSHS_SFTP_GetHandle
- Fuzzing fix for potential out of bounds read in the public key user auth messages
- MQX build fixes
- Sanity check that agent was set before setting the agent’s channel
- Fuzzing fix for bounds checking with DoKexDhReply internal function
- Fuzzing fix for clean up of base path with SCP use
- Fuzzing fix for sanity checks on setting the prime group and generator
- Fuzzing fix for return result of high water check
- Fuzzing fix for null terminator in internal ReceiveScpConfirmation function

## Improvements and Optimizations

- Example timeout added to SFTP example
- Update wolfSSH_ReadKey_buffer() to handle P-384 and P-521 when reading a key from a buffer
- Use internal version of strdup
- Use strncmp instead of memcmp for comparint session string type

--------------------------------

# wolfSSH v1.4.5 (August 31, 2020)

## New Feature Additions

- Added SSH-AGENT support to the echoserver and client
- For testing purposes, add ability to have named users with authentication
  type of "none"
- Added support for building for EWARM
- Echoserver can now spawn a shell and set up a pty with it
- Added example to the SCP callback for file transfers without a filesystem

## Fixes

- Fixes for clean connection shutdown in the example.
- Fixes for some issues with DH KEX discovered with fuzz testing
- Fix for an OOB read around the RSA signature
- Fix for building with wolfSSL v4.5.0 with respect to `wc_ecc_set_rng()`;
  configure will detect the function's presence and work around it absence;
  see note in internal.c regarding the flag `HAVE_WC_ECC_SET_RNG` if not
  using configure

## Improvements and Optimizations

- Improved interoperability with winSCP
- Improved interoperability with Dropbear
- Example client can now authenticate with public keys


--------------------------------

# wolfSSH v1.4.4 (04/28/2020)

## New Feature Additions

- Added wolfSCP client example
- Added support for building for VxWorks

## Fixes

- Fixes for some buffer issues discovered with fuzz testing
- Fixes for some SCP directory issues in Nucleus
- Fixed an issue where a buffer size went negative, cosmetic
- Fixed bug in ECDSA when using alt-ecc-size in wolfCrypt
- Fixed bug with AES-CTR and FIPSv2 build
- Fixed bug when using single precision
- Fix for SCP rename action

## Improvements and Optimizations

- Improved interoperability with FireZilla
- Example tool option clarification
- Better SFTP support in 32-bit environments
- SFTP and SCP aren't dependent on ioctl() anymore
- Add password rejection count
- Public key vs password authentication chosen by user auth callback
- MQX maintenance


--------------------------------

# wolfSSH v1.4.3 (10/31/2019)

- wolfSFTP port to MQX 4.2 (MQX/MFS/RTCS)
- Maintenance and bug fixes
- Improvements and additions to the test cases
- Fix some portablility between C compilers
- Fixed an issue in the echoserver example where it would error sometimes
  on shutdown
- Improvement to the global request processing
- Fixed bug in the new keys message handler where it reported the wrong size
  in the data buffer; invalid value was logged, not used
- Fixed bug in AES initialization that depended on build settings
- Improved interoperability with puTTY
- Added user auth callback error code for too many password failures
- Improvements to the Nucleus filesystem abstraction
- Added example for an "autopilot" file get and file put with the wolfSFTP
  example client


# wolfSSH v1.4.2 (08/06/2019)

- GCC 8 build warning fixes
- Fix for warning with enums used with SFTP and set socket type
- Added example server with Renesas CS+ port
- Fix for initializing UserAuthData to all zeros before use
- Fix for SFTP “LS” operation when setting the default window size to 2048
- Add structure size print out option -z to example client when the macro
  WOLFSSH_SHOW_SIZES is defined
- Additional automated tests of wolfSSH_CTX_UsePrivateKey_buffer and fix for
  call when key is already loaded
- Refactoring done to internal handling of packet assembly
- Add client side public key authentication support
- Support added for global requests
- Fix for NULL dereference warning, rPad/sPad initialization and SFTP check on
  want read. Thanks to GitHub user LinuxJedi for the reports
- Addition of WS_USER_AUTH_E error returned when user authentication callback
  returns WOLFSSH_USERAUTH_REJECTED
- Remove void cast on variable not compiled in with single threaded builds


# wolfSSH v1.4.0 (04/30/2019)

- SFTP support for time attributes
- TCP port forwarding feature added (--enable-fwd)
- Example tcp port forwarding added to /examples/portfwd/portfwd
- Fixes to SCP, including default direction set
- Fix to match ID during KEX init
- Add check for window adjustment packets when sending large transfers
- Fixes and maintenance to Nucleus port for file closing
- Add enable all option (--enable-all)
- Fix for --disable-inline build
- Fixes for GCC-7 warnings when falling through switch statements
- Additional sanity checks added from fuzz testing
- Refactor and fixes for use with non blocking
- Add extended data read for piping stderr
- Add client side pseudo terminal connection with ./examples/client/client -t
- Add some basic Windows terminal conversions with wolfSSH_ConvertConsole
- Add wolfSSH_stream_peek function to peek at incoming SSH data
- Change name of internal function SendBuffered() to avoid clash with wolfSSL
- Add support for SFTP on Windows
- Use int types for arguments in examples to fix Raspberry Pi build
- Fix for fail case with leading 0’s on MPINT
- Default window size (DEFAULT_WINDOW_SZ) lowered from ~ 1 MB to ~ 16 KB
- Disable examples option added to configure (--disable-examples)
- Callback function and example use added for checking public key sent
- AES CTR cipher support added
- Fix for free’ing ECC caches with examples
- Renamed example SFTP to be examples/sftpclient/wolfsftp


# wolfSSH v1.3.0 (08/15/2018)

- Accepted code submission from Stephen Casner for SCP support. Thanks Stephen!
- Added SCP server support.
- Added SFTP client and server support.
- Updated the autoconf scripts.
- Other bug fixes and enhancements.

# wolfSSH v1.2.0 (09/26/2017)

- Added ECDH Group Exchange with SHA2 hashing and curves nistp256,
  nistp384, and nistp521.
- Added ECDSA with SHA2 hashing and curves nistp256, nistp384, and nistp521.
- Added client support.
- Added an example client that talks to the echoserver.
- Changed the echoserver to allow only one connection, but multiple
  connections are allowed with a command line option.
- Added option to echoserver to offer an ECC public key.
- Added a Visual Studio solution to build the library, examples, and tests.
- Other bug fixes and enhancements.

# wolfSSH v1.1.0 (06/16/2017)

- Added DH Group Exchange with SHA-256 hashing to the key exchange.
- Removed the canned banner and provided a function to set a banner string.
  If no sting is provided, no banner is sent.
- Expanded the make checking to include an API test.
- Added a function that returns session statistics.
- When connecting to the echoserver, hitting Ctrl-E will give you some
  session statistics.
- Parse and reply to the Global Request message.
- Fixed a bug with client initiated rekeying.
- Fixed a bug with the GetString function.
- Other small bug fixes and enhancements.

# wolfSSH v1.0.0 (10/24/2016)

Initial release.

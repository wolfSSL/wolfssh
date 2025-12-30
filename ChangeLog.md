# wolfSSH v1.4.22 (December 31, 2025)

## Vulnerabilities

- [Critical] CVE-2025-14942. wolfSSH’s key exchange state machine can be
  manipulated to leak the client’s password in the clear, trick the client to
  send a bogus signature, or trick the client into skipping user
  authentication. This affects client applications with wolfSSH version 1.4.21
  and earlier. Users of wolfSSH must update or apply the fix patch and it’s
  recommended to update credentials used. This fix is also recommended for
  wolfSSH server applications. While there aren’t any specific attacks, the
  same defect is present. Thanks to Aina Toky Rasoamanana of Valeo and Olivier
  Levillain of Telecom SudParis for the report. (PR 855)
- [Medium] CVE-2025-15382. The function used to clean up a path string may read
  one byte off the end of the bounds of the string. The function is used by the
  SCP handling in wolfSSH. This affects server applications with wolfSSH
  versions 1.4.12 through 1.4.21, inclusive. Thanks to Luigino Camastra from
  Aisle Research for the report. (PR 859)

## New Features

- Added a complete SFTP client example for the Renesas RX72N platform. (PR
  847)
- Enabled TSIP support and provided cleaned-up configuration headers for the
  RX72N example. (PR 847)
- Added FIPS-enabled build configurations to the Visual Studio project files.
  (PR 851)
- Added documentation describing how to build and use the new FIPS Visual
  Studio configurations. (PR 851)
- Introduced regression tests covering SSH agent signing, including error
  paths and successful operation. (PR 856)
- Added regression tests that explicitly exercise WANT_READ / WANT_WRITE  paths
  to guard against deadlocks. (PR 856)

## Improvements

- Refactored SSH string parsing by unifying GetString() and GetStringAlloc()
  around GetStringRef(), simplifying maintenance and reducing duplication. (PR
  857)
- Enhanced SSH message-order validation by introducing explicit
  expected-message tracking and clearer message ID range macros. (PR 855)
- Improved server-side out-of-order message checking to align behavior with the
  stricter client implementation. (PR 855)
- Improved worker thread behavior under window backpressure by prioritizing
  receive handling, preventing stalls with small-window SFTP clients. (PR 856)
- Hardened SSH agent handling logic by validating response types, tracking
  message IDs, and enforcing strict buffer size limits. (PR 845)
- Improved SCP path handling by canonicalizing client-supplied base paths
  before filesystem access. (PR 845)
- Improved portability by replacing non-standard <sys/errno.h> includes with
  standard <errno.h>. (PR 852)
- Reduced logging overhead by defining WLOG as a no-op when debugging is
  disabled. (PR 839)
- Updated documentation to better reflect current features, examples, and build
  options. (PR 851)

## Fixes

- Fix off-by-1 read error when cleaning the file path for SCP. (PR  859)
- Fixed incorrect handling of zero-length SSH strings in packet parsing. (PR
  857)
- Fixed a worker-thread deadlock caused by blocked sends preventing
  window-adjust processing. (PR 856)
- Fixed a double-free crash and eliminated a socket-close spin loop under error
  conditions. (PR 855)
- Fixed uninitialized authentication data that could lead to undefined behavior
  during authentication. (PR 854)
- Fixed SFTP connection interoperability issues discovered through
  cross-implementation testing. SFTP fix for init to handle channel data which
  resolves a potential interoperability SFTP connection issue. (PR 846)
- Fixed SCP receive handling to reject traversal filenames containing path
  separators or “dot” components. (PR 845)
- Fixed missing declaration of wc_SSH_KDF that caused build failures under
  strict compiler warnings. (PR 848)
- Fixed SSH agent test setup so regression tests exercise the intended code
  paths. (PR 845)
- Excluded a standalone regression test from Zephyr builds where it was
  incompatible with the Zephyr test model. (PR 855)

---

# wolfSSH v1.4.21 (October 20, 2025)

## Vulnerabilities

- [Critical] CVE-2025-11625 The client's host verification can be bypassed by a malicious server, and client credentials leaked. This affects client applications with wolfSSH version 1.4.20 and earlier. Users of wolfSSH on the client side must update or apply the fix patch and it’s recommended to update credentials used. Fixed in PR (https://github.com/wolfSSL/wolfssh/pull/840)

- [Med] CVE-2025-11624 Potential for stack overflow write when reading the file handle provided by an SFTP client. After a SFTP connection was established there is the case where a SFTP client could craft a malicious read, write or set state SFTP packet which would cause the SFTP server code to write into stack. Thanks to Stanislav Fort of Aisle Research for the report. Fixed in PR (https://github.com/wolfSSL/wolfssh/pull/834)

## New Features

- Curve25519 interoperability with LibSSH. Update to treat curve25519-sha256@libssh.org as an alias for curve25519-sha256 (PR 789)
- Microchip example for ATSAMV71Q21B and harmony filesystem support (PR 790)
- Make Keyboard Interactive a compile time option, enabled using --enable-keyboard-interactive. Off by default. (PR 800)
- wolfSSH support for using TPM based key for authentication (PR 754)
- By default, soft disable AES-CBC. It isn't offered as a default encrypt algorithm, but may be set at runtime (PR 804)
- Add ED25519 key generation support. (PR 823)

## Improvements

- Add GitHub Action for testing wolfSSH server with Paramiko SFTP client (PR 788)
- Additional sanity checks on message types during rekey (PR 793)
- FATFS improvements, test and Linux example (PR 787)
- Adjust behavior when getting WOLFSSH_USERAUTH_REJECTED return from callback. It now will reject and not continue on with user auth attempts. (PR 837)
- Rename arguments and variables to idx instead of index to avoid shadowed variables. (PR 828)
- Move user filesystem override to the top of the ports check so that the override also overrides enabled ports. (PR 805)
- Remove keyboard auth callback and use a generic auth callback (PR 807)
- Update Espressif examples and add getting started info to Espressif README (PR 810, 771)
- Disable old threading functions when SINGLE_THREADED (PR 809)
- Replace Kyber 512 with ML-KEM 768. (PR 792)
- Update SFTP status callback to output once per second. (PR 779)
- Refactor to leverage wolfSSL FALLTHROUGH macro with switch statements. (PR 815)
- Autoconf and Automake Updates (PR 821)
- Simplify Test Build Flags (PR 818)
- Fixed typo and spelling edits (PR 797, 798)

## Fixes

- Fix SFTP data truncation by moving sentSzSave to state structure(PR 785)
- Fix SFTP Symlink Indication. (PR 791)
- Fix warning on FATFS builds (PR 796)
- Keyboard Interactive bug fixes (PR 801, 802)
- Fix double-free on `wolfSSH_SFTPNAME_readdir` (PR 806)
- Adjust the highwater check location to avoid masking the return value. (PR 795)
- DoAsn1Key now fails when WOLFSSH_NO_RSA is defined (PR 808)
- Avoid potential for overflow/underflow in comparison by rearranging evaluation of unsigned condition. (PR 814)
- Fixing a batch of warning from Coverity reports. (PR 817, 820, 822)
- Fix inet_addr accounting for '.' character (PR 816)
- Fix to only send ext info once after SSH_MSG_NEWKEYS. (PR 819)
- Fix "rejected" authentication in DoUserAuthRequestPublicKey() (PR 825)
- Rename struct Buffer to WOLFSSH_BUFFER in wolfSSH_ShowSizes to match the previous rename.(PR 830)
- Rename wolfssh test certs to avoid conflict with wolfssl test certs (PR 831)
- Do not treat the shell as interactive until pty-req message request is received. This fixes an interoperability issue with WinSCP (PR 832)

---

# wolfSSH v1.4.20 (Feburary 20, 2025)

## New Features

- Added DH Group 16 and HMAC-SHA2-512 support (PR 768)
- Added RFC-4256 keyboard-interactive authentication support (PR 763)

## Enhancements and Fixes

- Enhancement to pass dynamic memory heap hint to init RNG call (PR 749)
- Update SCP example to properly free memory upon failure (PR 750)
- Address memory management during socket timeouts in wolfSSHd (PR 752)
- Modify wolfSSHd to terminate child processes following SSH connection failures
 (PR 753)
- Fix for wolfSSHd handling of pipe's with forced commands (PR 776)
- Resolve SFTP compilation issues with WOLFSSH_FATFS (PR 756)
- Refactor and simplify autogen script (PR 758)
- Fix SCP hang issue in interop scenarios (PR 751)
- Fix for SCP server side handling of EAGAIN (PR 783)
- Reinstate support for P521 and P384 curves by default when compiled in (PR 762)
- Fix for wolfSSH client app handling of an empty hostname (PR 768)

---

# wolfSSH v1.4.19 (November 1, 2024)

## New Features

- Add DH Group 14 with SHA256 KEX support (PR 731)

## Improvements

- Use of the new SSH-KDF function in wolfCrypt (PR 729)
- Adds macro guards to the non-POSIX value checks and updates with TTY modes (PR 739)
- Add CI test against master and last two wolfSSL releases (PR 746)
- Show version of wolfSSL linked to when application help messages are printed out (PR 741)
- Purge OQS from wolfSSH and instead use Kyber implementation from wolfssl (PR 736)
- Adjust Espressif wolfssl_echoserver example timehelper (PR 730)

## Fixes

- Remove Inline for function HashForId() to resolve clash with WOLFSSH_LOCAL declaration (PR 738)
- Fix for wolfSSHd’s handling of re-key and window full when processing a command with lots of stdout text (PR 719)
- Fix for wolfSSH client app to gracefully clean up on failure and added more WLOG debug messages (PR 732)
- Minor static analysis report fixes (PR 740, 735)
- Fix for handling SFTP transfer to non-existent folder (PR 743)

---

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

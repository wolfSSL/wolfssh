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

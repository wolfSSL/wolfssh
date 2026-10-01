# wolfSSH v1.6.0 (October 6, 2026)

## Vulnerabilities

- [Critical] CVE-2026-16516. wolfSSH did not check that the ECDSA curve in a
  server's host key blob matched the negotiated algorithm, so a
  man-in-the-middle could substitute a key on another curve and pass
  verification with a private key of its own. Also requires a lax public key
  check callback. Affects through 1.5.0. Thanks to zhangph (GitHub afldl).
  Fixed in PR 1022, issue #1012
- [High] CVE-2026-83540. wolfSSHd on Windows shared one authentication
  context, and the logon token stored in it, across concurrent connections,
  so a user with a valid account could end up logged in as another, more
  privileged user. Password and public key logins both wrote the shared
  token. Non-Windows builds are unaffected. Affects 1.4.15 through 1.5.0.
  Found by internal wolfSSL testing. Fixed in PR 1163
- [Medium] CVE-2026-84897. A wolfSSH server accepted the DH group exchange
  messages only a server sends, `SSH_MSG_KEX_DH_GEX_GROUP` (31) and
  `SSH_MSG_KEX_DH_GEX_REPLY` (33), from an unauthenticated client. A client
  that negotiated `diffie-hellman-group-exchange-sha256` and sent message 31
  made the server run the client-side handler, which primality-tests an
  attacker-chosen group of up to 8192 bits, about half a second of CPU per
  1 KB packet for a 4096-bit prime, and then continue the key exchange in
  the client role. Affects 1.2.0 through 1.5.0; the primality cost applies
  from 1.5.0. Builds with `WOLFSSH_NO_DH_GEX_SHA256` are unaffected. Thanks
  to Abdullah Al Ishtiaq, Kai Tu, Matthew Carter, Xiaotian Zhou, Ananna
  Rahman, Yilu Dong, Tianwei Yu, Ali Ranjbar and Syed Rafiul Hussain. Fixed
  in PR 1221
- [Medium] CVE-2026-81535. With `--enable-fwd`, `forwarded-tcpip` channel
  opens were admitted without consulting the forwarding policy callback, and
  a client accepted them for forwards it never requested with
  `tcpip-forward`. A peer could make an endpoint allocate buffers for
  forwarding channels the application never authorized. Affects 1.4.8
  through 1.5.0. Thanks to zhangph (GitHub afldl). Fixed in PR 1059, 1148,
  1220
- [Medium] CVE-2026-83742. `wolfSSH_RealPath()` bounded each path component
  it appended by the space left in the output buffer rather than by the
  buffer's size, so once an accumulated path passed the halfway mark the
  unsigned length computation in `wstrncat()` wrapped and the copy became
  effectively unbounded. A crafted SFTP path could then write a single
  terminating NUL one byte past the end of a stack buffer, corrupting an
  adjacent value and crashing the process. Requires an authenticated
  session, and affects non-Windows builds. An application calling the public
  `wolfSSH_RealPath()` with an output buffer smaller than its input is
  further exposed to an unbounded copy. Affects 1.4.11 through 1.5.0. Thanks
  to Asif Nadaf. Fixed in PR 1084

## Notes

- wolfSSH now requires wolfSSL built with `--enable-wolfssh`
  (`WOLFSSL_WOLFSSH`); a build without it stops with an `#error`. (PR 938)
- `WOLFSSH_DEFAULT_GEXDH_MIN` is now a 2048-bit floor, so GEX fails with a
  1024-bit-only server. (PR 1056)
- An OpenSSH client now gets the 4096-bit group 16, at 5-8x the cost of
  group 14; `WOLFSSH_NO_DH_GROUP16_SHA512` keeps group 14. (PR 1056)
- Strict KEX is on by default; a non-KEX message in a strict first KEX ends
  the connection. Opt out with `wolfSSH_CTX_SetStrictKex()`. (PR 1271)
- RSA user authentication keys must now be at least 2048 bits
  (`WOLFSSH_RSA_MIN_KEY_BITS`); shorter keys must be regenerated. (PR 1101)
- A "none" cipher or MAC now requires `--enable-none-cipher`. (PR 1117)
- The `SetAlgoList*()` setters now validate input and can return
  `WS_INVALID_ALGO_ID`; most no longer accept NULL. (PR 1117)
- `wolfSSH_CTX_SetWindowPacketSize()` now returns `WS_BAD_ARGUMENT` for a
  window over 256 KB or a packet over `MAX_PACKET_SZ`. (PR 995)
- The server now disconnects after 6 failed authentication attempts; change
  it with `wolfSSH_CTX_SetMaxAuthAttempts()`. (PR 1117, 1127)
- A password-change user auth request is now refused without reaching
  `userAuthCb`. (PR 1049)
- A `WOLFSSH_USERAUTH_REJECTED` from keyboard-interactive setup now ends the
  session; `NO_FAILURE_ON_REJECTED` is gone. (PR 1202)
- Applications must now drain stderr. Ignoring `WS_EXTDATA` exhausts the
  channel window and deadlocks it. (PR 1054)
- `wolfSSH_stream_read()` now fails on extended data for any channel but the
  first; use `wolfSSH_ChannelIdReadExt()`. (PR 1054)
- `wolfSSH_extended_data_read()` now returns `WS_BAD_ARGUMENT` for a zero
  `outSz` or no open channel, never `WS_INVALID_EXTDATA`. (PR 1054)
- A peer's channel EOF is now reported as `WS_EOF`, not answered; send your
  own with `wolfSSH_ChannelSendEof()`. (PR 1195, 982)
- `wolfSSH_ChannelExit()` now keeps the channel, and the application's
  pointer, valid until `WS_CHANNEL_CLOSED`. (PR 1195)
- `wolfSSH_shutdown()` now returns `WS_WANT_WRITE` while output is still
  queued; call it again until it completes. (PR 1217, 1219, 1252)
- `wolfSSH_get_fd()` given a NULL session now returns -1, where non-Windows
  builds returned `WS_BAD_ARGUMENT`. (PR 1247)
- `WS_CallbackFwd` must now return the allocated port for a port-0
  `WOLFSSH_FWD_REMOTE_SETUP`, not `WS_FWD_SUCCESS`. (PR 1059)
- `forwarded-tcpip` channel opens now require a `fwdCb`, as `direct-tcpip`
  opens do; without one they are refused. (PR 1059)
- A client now refuses a `forwarded-tcpip` open matching no registered
  forward; opt out with `wolfSSH_SetFwdRemoteMatch()`. (PR 1148, 1220)
- A client now refuses `tcpip-forward` and `cancel-tcpip-forward` with
  `REQUEST_FAILURE`, even with a `fwdCb`. (PR 1214)
- A client now refuses a `session` channel open outright, per RFC 4254
  section 6.1, ahead of any `channelOpenCb`. (PR 1224)
- Each `WOLFSSH_FWD_LOCAL_SETUP` now gets a `WOLFSSH_FWD_LOCAL_CLEANUP`; a
  `fwdCb` must not free that state twice. (PR 1229)
- SFTP `SETSTAT` and `FSETSTAT` now apply the attributes or answer
  `SSH_FX_OP_UNSUPPORTED`, not always `SSH_FX_OK`. (PR 1197)
- On Windows, an SFTP open with `CREAT` but not `TRUNC` no longer truncates
  an existing file, and `EXCL` now fails on one. (PR 1173)
- The `wolfssh` client no longer accepts `-N`. It was parsed but never read,
  so it is now a usage error rather than silently ignored. (PR 1162)
- wolfSSHd enforces `StrictModes` by default and refuses unsafe host key or
  CA file modes; `StrictModes no` relaxes only authorized keys. (PR 1042)
- wolfSSHd refuses a `Match` keyed on anything but `User` or `Group`, and
  `Match User X Group Y` now requires both. (PR 1026, 1027)
- Without FPKI, wolfSSHd certificate auth now requires `AuthorizedKeysFile`;
  CA-only logins fail closed. (PR 1019)
- wolfSSHd's `LoginGraceTime` now defaults to 120 seconds, not unlimited.
  (PR 950)
- wolfSSHd now keeps a 022 umask (`WOLFSSHD_DEFAULT_UMASK`), so sessions no
  longer create world-writable files. (PR 1269)

## New Features

- Added strict key exchange, the Terrapin (CVE-2023-48795) mitigation, and
  `wolfSSH_GetStrictKexNegotiated()`. (PR 1271, 1295)
- Added ML-DSA-44, -65 and -87 host keys and user auth, with X.509 and
  composite variants. (PR 1048, 1109, 1259, 1266)
- Added OpenSSH certificate user authentication to wolfSSHd, behind
  `--enable-ossh-certs`. (PR 1060)
- Added TPM-resident host keys, including X.509 host certificates, with
  `wolfSSH_CTX_UseTpmHostKey()`. (PR 1033, 1081)
- Added host keys from the Windows certificate store, and wolfSSHd options
  to load keys and CAs from system stores. (PR 900)
- Added support for builds with neither RSA nor ECDSA, such as Ed25519
  only. (PR 1257, 1183)
- Added client-side remote port forwarding with `wolfSSH_FwdRemoteSetup()`
  and `wolfSSH_FwdRemoteCancel()`, and portfwd `-r`. (PR 1066)
- Added `wolfSSH_SetFwdRemoteMatch()` to match remote forwards on the port
  alone or not at all. (PR 1148)
- Added `wolfSSH_ReadCert_file()` and related certificate loaders that
  detect PEM or DER from the content. (PR 1140, 1150)
- Added SFTP session confinement with `wolfSSH_SFTP_SetConfinePath()`,
  separate from where a session starts; wolfSSHd sets none. (PR 1000, 1167)
- Added per-channel stderr buffering with window flow control, and the
  `wolfSSH_Channel*Ext()` read and send functions. (PR 1054)
- Added independent cipher and MAC negotiation for each direction. (PR 952)
- Added a packet-count rekey trigger and `wolfSSH_SetMsgHighwater()`.
  (PR 963)
- Added `wolfSSH_RekeyPending()`, which reports whether a key exchange is
  in flight. (PR 1260)
- Added wolfSSHd's `PubkeyAuthentication` directive. (PR 1011)
- Added `StrictModes` to wolfSSHd, on by default. (PR 1042)
- Added `prohibit-password` and `forced-commands-only` to wolfSSHd's
  `PermitRootLogin`. (PR 1111)
- Added `%u`, `%h` and `%%` expansion to `AuthorizedKeysFile`. (PR 1064)
- Added `make sbom` targets producing CycloneDX and SPDX output. (PR 1050)
- Added Zephyr 4.4.0 to the test sample and its CI, keeping 3.4.0.
  (PR 1065)
- Added `wolfssh-options`, a build option probe for test scripts. (PR 1180)
- Added an `-E` log file option to the `wolfssh` client, and built and
  tested the client app in CI. (PR 1168)
- Added CI for X.509 interop, coverage, Windows SFTP and SCP, MinGW, TPM,
  heapmath and Espressif. (PR 989, 1158, 1058, 1165, 1241, 1038, 1255)
- Added KEX and user auth tests for corrupted signatures, ed25519 keys, cert
  auth and the pre-auth gate. (PR 1051, 924, 968, 992, 1068, 923, 929, 925)
- Added tests for channel limits, forged SFTP handles, the AEAD IV counter
  and a forwarding rejection. (PR 1057, 943, 875, 1112, 1205)
- Added tests that secrets are zeroized on free and in DH KEX. (PR 980)
- Added wolfSSHd authentication tests for the privilege drop, password hash
  checks and authorized keys rejection. (PR 994, 1107, 914, 1100)
- Added tests for the protocol state machine's rejections. (PR 990)
- Added tests for the channel open response, close, exec and subsystem
  callbacks, and for the default algorithm lists. (PR 1227, 1269, 1273)
- Added `wolfSSH_ChannelSendEof()` and `wolfSSH_stream_send_eof()`,
  completing the RFC 4254 section 5.3 half-close. (PR 1195)
- Added `wolfSSH_ChannelIdPeek()`, which reports buffered channel data
  without consuming it. (PR 1270)
- Added application-driven channels: with `wolfSSH_CTX_SetAppChannels()`,
  the application grants each session request. (PR 1233, 1234, 1251, 1274)
- Added `wolfSSH_CTX_SetChannelReqAnyCb()` and
  `wolfSSH_CTX_SetGlobalReqAnyCb()`, consulted first. (PR 1236)
- Added `wolfSSH_ChannelGetSessionGranted()` and
  `wolfSSH_ChannelCommandIsScp()`. (PR 1237)
- Added `wolfSSH_AGENT_ChannelOpen()`, so an application driving its own
  channels can open the agent channel. (PR 1230)
- Added `wolfSSH_AGENT_RelayChannel()`, which relays whole agent messages
  across partial reads and writes. (PR 1262)
- Added `wolfSSH_SCP_accept()`, so an application that binds an `scp`
  command to a channel itself can run the transfer. (PR 1231)

## Improvements

- Validated peer DH and ECDH public keys before key agreement, rejecting
  degenerate and off-curve values. (PR 1049, 1077)
- Rejected packets with less than the minimum padding. (PR 1049)
- Reworked DH group exchange to honor the client's size window and enforce
  a 2048-bit floor. See Notes. (PR 1056)
- Bounded KEXINIT name-list parsing, closing a pre-auth CPU DoS. (PR 1062)
- Rejected inbound packets that are not cipher-block aligned. (PR 1189)
- Made the client refuse the key exchange messages only a client sends.
  (PR 1222, 1223)
- Capped failed auth attempts, validated the algorithm setters and version
  string, and zeroized transport buffers. (PR 1117)
- Reworked `wolfSSH_RsaVerify()` to compare blocks in constant time rather
  than parse the recovered padding. (PR 1203)
- Validated the ECC curve name in user auth, and documented the user auth
  and public key check callback contracts. (PR 1141)
- Sanitized control bytes in `wolfSSH_Log()`, closing log injection.
  (PR 1031)
- Hardened the SCP callbacks against symlinks, masked setuid and setgid mode
  bits, and bounded SCP depth. (PR 1015, 1034, 1037, 1032, 999, 991)
- Bounded peer-declared SFTP request and NAME response sizes before
  allocating. (PR 1025, 1036)
- Capped open SFTP handles per session. Thanks to @loganaden. (PR 1135)
- Tracked SFTP handles per session and validated them on use. (PR 875, 997)
- Zeroized secret buffers before free; `--disable-sftp-zeroize` opts out for
  SFTP file data. (PR 1099, 1053, 947, 1129, 1108, 1106)
- Hardened wolfSSHd's PID file and chroot. (PR 1074, 1088)
- Equalized the cost of a rejected wolfSSHd password, closing a user
  enumeration timing oracle. (PR 1116)
- Enforced shadow password and account aging in wolfSSHd. (PR 1184)
- Bound wolfSSHd certificate auth to the requested user, and added
  `AuthorizedUPNDomains` to restrict the UPN realm. (PR 1019, 1079)
- Required an end-entity leaf and CA intermediates in X.509 chains, and
  skipped OCSP with no responder URL. (PR 1075, 1021)
- Rejected unsanitized host names and key types before the `wolfssh` client
  writes `known_hosts`. (PR 1045)
- Replaced `atoi()` on peer-supplied fields with bounded parsers. (PR 1095)
- Refused a shell, exec or subsystem request wolfSSHd's build cannot serve,
  rather than accepting and then dropping it. (PR 1237)
- Warned on wolfSSHd options that are parsed but not enforced, such as
  `UsePAM` and `X11Forwarding`. (PR 1269)
- Added `WOLFSSH_NO_HOSTKEY_PERMS`, which skips wolfSSHd's host key owner
  and mode checks on QNX. (PR 1185)
- Sent a `DISCONNECT` with `PROTOCOL_ERROR` for a message the connection
  state disallows, rather than tearing down silently. (PR 1214)
- Shrank the `WOLFSSH` struct by about 4KB per connection. (PR 1104)
- Centralized the AES cipher lifecycle so a context is never keyed or freed
  uninitialized. (PR 1043)
- Advertised `ext-info-s` from the server. (PR 998)
- Made the client skip non-SSH banner lines before the version. (PR 959)
- Cleared all 378 clang-tidy findings. (PR 1002)
- Reworked the SFTP parsers onto the bounds-checked `Get*` helpers. (PR 961)
- Sanity checked the server's SFTP version, and reported a bad PEM as
  `WS_PARSE_E`. (PR 1133, 1151)
- Checked that a decoded private host key yields a public key. (PR 1121)
- Removed dead code in `wolfSSH_ProcessBuffer()` and the agent, and sized
  wolfSSHd's wide-character conversion exactly. (PR 1268, 1258, CID 653252)
- Refactored the echoserver's forwarding, agent and shell paths. (PR 962)
- Added `CONTRIBUTING.md`. (PR 1160)
- Converted permission constants to octal, made the sources 7-bit ASCII
  clean, and restored C89 compliance. (PR 1007, 987, 948, 1087)
- Moved the path to the end of an `auth.c` log message. (PR 1175)
- Removed `wolfSSH_CTX_SetFwdEnable()` and `wolfSSH_SetFwdEnable()`, which
  were declared but never defined. (PR 1210)
- Warned when a channel open arrives with no `channelOpenCb`. (PR 954)
- Improved MQX filesystem compatibility, and exported two Windows directory
  wrappers. (PR 941, 958)
- Terminated the `ES_ERROR()` messages with a newline. (PR 1208)
- Made the SFTP example client's autopilot report why a copy failed.
  (PR 1271)
- Registered the portfwd example's channel open response callbacks, which
  had no caller anywhere in the tree. (PR 1232)
- Took the authorized-keys type from the wire blob, and fixed ML-DSA
  small-stack use and composite gating. (PR 1159)
- Validated custom identification strings, including the CRLF terminator,
  when they are set. (PR 1218, 1239)
- Reworked the wolfSSHd test harness, which passed while silently skipping
  the last eleven tests. (PR 1174, 1024)
- Hardened `sftp.test`'s ready-file wait, and dropped the external test.
  (PR 1206)
- Let concurrent wolfSSHd suite runs share a host, widened the echoserver
  ready-file wait, and fixed two CI flakes. (PR 1256, 1225, 1249)
- Stopped skipped test binaries crashing with SIGILL on macOS. (PR 1226)
- Let the tests fall back when RSA or ECDSA is disabled. (PR 951)
- Matched the private-only ECC key test to wolfSSL's earlier scalar range
  check. (PR 1187)
- Made the `wolfSSH_RealPath()` tests fail on a mismatch, and cleared static
  analysis findings in the tests and dead code. (PR 935, 1110, 1154, 1134)
- Allowed SCP in a client-only build, and PTY requests from a client with
  no filesystem. (PR 1272)
- Updated CI actions, wolfSSL versions and timeouts, and the Windows SFTP
  client project. (PR 970, 984, 1046, 1114, 957)

## Fixes

- Fixed a wolfSSHd auth bypass under `WOLFSSH_ALLOW_USERAUTH_NONE`.
  (PR 940)
- Fixed public key auth failing for a key string with no trailing newline.
  Affects 1.4.21 through 1.5.0. (PR 1136)
- Fixed four fail-open wolfSSHd `Match` defects. (PR 1003, 1027, 1039, 1026)
- Fixed wolfSSHd `Match` blocks inheriting settings, dropping `Include`d
  blocks, and applying only one match. (PR 1153, 1186)
- Fixed `PermitRootLogin` covering only the name root, not every UID 0
  account. (PR 1073)
- Fixed wolfSSHd to fail closed when a privilege drop fails. (PR 1067)
- Fixed wolfSSHd skipping the supplementary group drop on BSD and macOS.
  (PR 1085)
- Fixed wolfSSHd rejecting empty passwords with `PermitEmptyPasswords yes`.
  (PR 986)
- Fixed a stack over-read in wolfSSHd's Windows pseudo-console resize.
  (PR 1005)
- Fixed a `pty-req` mode size wrap when stdin is not a terminal. (PR 1130)
- Fixed a heap over-read parsing an `SSH_FXP_HANDLE` reply, and a one-byte
  overflow in `LoadTpmSshKey()`. (PR 1083, 1164)
- Fixed out-of-bounds accesses in `wolfSSH_DoOSC()` and
  `wolfSSH_DoControlSeq()`. (PR 1035, 1076)
- Fixed a stack out-of-bounds write in the example client, and its missing
  RFC 6187 name length check. (PR 1004, 1052)
- Fixed TPM builds refusing password and keyboard-interactive user
  authentication. (PR 1081)
- Fixed keyboard-interactive in the example client without `WOLFSSH_TERM`.
  (PR 1065)
- Fixed six SFTP client request states dropping unsent bytes on a partial
  send. (PR 1008)
- Fixed SFTP and SCP transfers failing on a mid-flight rekey.
  (PR 1001, 1018)
- Fixed the client SFTP VERSION and DATA length reads, which could not
  recover from a short read. (PR 1138, 1181)
- Fixed `wolfSSH_SFTP_Put()` reporting success on a rejected write.
  (PR 1182)
- Fixed `wolfSSH_SFTP_Open()` ignoring its `atr` argument. (PR 999)
- Fixed a resumed SFTP put truncating the destination. (PR 1191)
- Fixed `wPread()` and `wPwrite()` dropping offsets past 4 GiB in the
  pread/pwrite, Harmony and Zephyr ports. (PR 1166, 1172)
- Fixed `WFSEEK()` return checks on Nucleus and Harmony. (PR 1145)
- Fixed an SFTP `readdir` double free, and FATFS end-of-directory, root
  attribute and timestamp defects. (PR 973, 978, 974, 977)
- Fixed wolfSSHd shell relay data loss on `EINTR`, stderr backlog, write
  back-pressure and stdin close. (PR 996, 1212, 1253, 1263)
- Fixed wolfSSHd spinning a core on an idle SFTP session. (PR 1207)
- Fixed the `wolfssh` client discarding the remote command. (PR 1162)
- Fixed `ssh://hostname` destinations with no explicit port. (PR 1006)
- Fixed agent RSA signing failing every key above 2048 bits, and a signing
  error becoming a huge signature length. (PR 1179, 1131)
- Fixed Ed25519 agent authentication sending no signature. (PR 1196)
- Fixed DH and DH-GEX key exchange and agent RSA signing failing against a
  FIPS wolfSSL. (PR 1297)
- Fixed agent forwarding in the `wolfssh` and example clients losing
  messages that did not arrive in one 512-byte read. (PR 1262)
- Fixed ECDSA and Ed25519 ASN.1 public keys being read as RSA. (PR 1137)
- Fixed an all-zero mpint not encoding as empty, per RFC 4251. (PR 939)
- Fixed name-list parsing of trailing, doubled and empty elements, and
  unchecked KEXINIT language lists. (PR 1055, 1132)
- Fixed a wrong `first_kex_packet_follows` guess not being discarded, on
  both sides. (PR 927, 956, 1056)
- Fixed the client accepting an unencrypted `CHANNEL_OPEN` pre-KEX.
  (PR 1147)
- Fixed service messages being accepted while keying. (PR 1200)
- Fixed the server accepting a `USERAUTH_REQUEST` for a service other than
  `ssh-connection`. (PR 953, 1201)
- Fixed two keyboard-interactive defects: a response-count mismatch
  dropping the connection, and unvalidated prompts. (PR 1070, 1199)
- Fixed the `USERAUTH_BANNER` and `REQUEST_*` parsers, and unknown channel
  requests not being rejected. (PR 937, 949, 942)
- Fixed the userauth username not being bound to the first request.
  (PR 1063)
- Fixed `wolfSSH_shutdown()` looking up the channel by the wrong ID, and
  the drivers and `DoPacket()` running past a disconnect. (PR 1190, 1211)
- Fixed `wolfSSH_shutdown()` dropping queued output other than a
  disconnect. (PR 1219)
- Fixed a non-blocking application stalling because `wolfSSH_worker()`
  never flushed a queued window adjust. (PR 1217)
- Fixed a refused session request still establishing the session or
  starting SFTP. (PR 1235)
- Fixed an exec of a command such as `scpbackup` reaching the built-in SCP
  server. (PR 1237)
- Fixed the server adding a bound-port field to a `tcpip-forward` success
  for an explicit port. Thanks to the tlspuffin team. (PR 1254, issue #1246)
- Fixed `WOLFSSH_FWD_LOCAL_CLEANUP` never being sent, leaking a peer-opened
  forward's setup state. (PR 1229)
- Fixed KEX failures aborting with no `SSH_MSG_DISCONNECT`. (PR 1091, 1171)
- Fixed packets sent in the same segment as the peer's version line being
  dropped. (PR 1271)
- Fixed the server accepting any transport message between the client's
  KEXINIT and its first KEX message. (PR 1271)
- Fixed a peer-initiated rekey failing after an earlier channel send filled
  the window. (PR 1278)
- Fixed an unsent KEXINIT leaving a rekey stuck, and a highwater callback
  starting a second one. (PR 1260)
- Fixed `wolfSSH_SetChannelType()` name checks, a channel packet-size bound
  and a terminal size wrap. (PR 1177)
- Fixed `wolfSSH_ChannelRead()` and `wolfSSH_stream_read()` returning the
  window-adjust result rather than the byte count. (PR 1192)
- Fixed four channel message defects, including a missing size check.
  (PR 982)
- Fixed SCP send repeating the file header when the send callback first
  returned 0 bytes. (PR 1128)
- Fixed a recursive SCP source aborting on a separator-less path, and an
  exact-fit `ScpBuffer` rejected. (PR 1020, 1161)
- Fixed the SCP rename check bounding the base path by the peer's command
  length. (PR 1049)
- Fixed an SCP base path leak, and wolfSSHd leaving privileges raised when
  shell setup failed. (PR 1125, 1126)
- Fixed wolfSSHd loading a PKCS#8 PEM host key, and PEM private keys
  without `WOLFSSH_CERTS`. (PR 1118, 1119)
- Fixed root CA bundles loading only their first certificate, and a replaced
  host certificate being appended instead. (PR 1149, 1152)
- Fixed `wolfSSHD_ConfigSetAuthKeysFile()` not marking `AuthorizedKeysFile`
  as set, so certificate logins skipped the authorized keys check. (PR 1044)
- Fixed `LoginGraceTime` never being armed on Windows. (PR 1028)
- Fixed wolfSSHd `Include` crashes and truncation, and config files without
  a trailing newline. (PR 1029, 1023, 1156)
- Fixed the SFTP example client's autopilot retry loop never iterating.
  (PR 993)
- Fixed the examples loading no public key under `WOLFSSH_NO_RSA`. (PR 1170)
- Fixed the portfwd example printing the SSH password. (PR 1198)
- Fixed portfwd cutting a transfer short when input ended mid-window.
  (PR 1228)
- Fixed three echoserver defects around agent sockets and rekeys. (PR 1209)
- Fixed the echoserver spinning in its SFTP loop on a blocked write.
  (PR 1250)
- Fixed the echoserver losing data a channel send did not take, and ending
  SFTP sessions on a partial packet. (PR 1261, 1271)
- Fixed eight issues from a security audit. (PR 1143)
- Fixed a dozen memory-safety and error-handling findings. (PR 1136)
- Fixed twenty-four agent, SFTP, terminal and FPKI findings. (PR 1103)
- Fixed ten integer underflow and bounds defects. (PR 1096)
- Fixed reported issues in `FindKeyId()`, locking, SCP size parsing and root
  CA loading. Thanks to Asif Nadaf. (PR 1084)
- Hardened `DoOpenSshKey()` parsing, and fixed `wc_InitDecodedCert()` given
  the wrong argument. Thanks to Asif Nadaf. (PR 1078, 1080)
- Fixed the remaining fuzz findings: negative mpints and RSA signature blob
  parsing. (PR 1022, issue #1013)
- Fixed wolfSSHd and echoserver leaks, a required `sshd` user, and the
  echoserver's key lookup. (PR 1071, 1038)
- Fixed a password overflow check and a large stack key struct. (PR 1122)
- Fixed missing `WMALLOC` checks in the SFTP client. (PR 1124)
- Fixed Windows resource cleanup in the shell subsystem and
  `wolfSSH_SFTP_RecvOpenDir()`. (PR 981)
- Fixed SFTP short writes reporting success. (PR 998)
- Fixed `wolfSSH_SFTP_SaveOfst()` accepting a name with no room for its
  terminator. (PR 1105)
- Fixed SFTP attributes promising extension records they did not carry.
  (PR 1269)
- Fixed the client writing `known_hosts` in text mode on Windows. (PR 1241)
- Fixed the Nucleus and Harmony SFTP builds referencing an out-of-scope
  `ssh->fs`. (PR 1082)
- Fixed `GetOpenSshPublicKey()` ignoring a failed key-type parse. (PR 1193)
- Fixed the test suites under `--disable-server`, `--disable-client` and
  `--enable-tpm`. (PR 1155, 1264, 1169)
- Fixed an `api.test` SFTP race under `make -j check` and two wolfSSHd test
  dependencies on the host. (PR 1142, 1115, 1040)
- Fixed the build against wolfSSL without `mlkem.h`. (PR 960)
- Fixed the Zephyr build on Zephyr 4.1 and newer, and against current
  wolfSSL. (PR 1267, 1265, 1144)
- Fixed the `wolfssh` client accepting a declined host key, an Ed25519
  verify failure, and an SFTP underflow. (PR 969)
- Static analysis fixes in the disconnect handlers, the client config, a
  Windows file-move leak and a wolfSSHd hash wipe. (PR 965, 988)
- Static analysis fixes in `DoProtoId()`, `DoNewKeys()`, `DoKexInit()` and
  the client buffers. (PR 983)
- Static analysis fixes in the GEX state and the key readers. (PR 976)
- Static analysis fixes for an uninitialized variable, a `word16` truncation
  and a Nucleus log variable. (PR 945, 946, 944)
- Static analysis fixes in `VerifyMac()`, `IdentifyAsn1Key()`, three SFTP
  handlers, config line parsing and OpenSSH key padding. (PR 967, 971, 972)
- Static analysis fixes in the user auth and SFTP paths. (PR 966, 979)
- Coverity fixes for unchecked SFTP returns and an uninitialized scalar.
  (PR 964, 1041)
- Coverity fixes in wolfscp, wolfsftp, the client app and wolfSSHd.
  (PR 1139)
- Fixed an uninitialized Windows file handle, and cleared cppcheck
  findings. (PR 1204)
- Fixed four `agent.c` functions never freeing their SHA-256 context.
  (PR 930)
- Fixed the Windows SFTP open flags, including TRUNC, EXCL and APPEND, and
  wolfSSHd's `-D` on Windows. (PR 1173)
- Fixed a resumed SFTP `get` truncating the local file on Windows, and
  trusting a stale saved offset. (PR 1216)
- Fixed recursive SCP send on Windows, which read end-of-directory as an
  enumeration failure and truncated every tree silently. (PR 1242)
- Fixed the Zephyr directory walk discarding every entry it read, so
  recursive SCP sent empty directories. (PR 1245)
- Fixed wolfSSHd on Windows refusing a first login by a user with no
  profile, and never unloading the profile hive. (PR 1243)
- Fixed an inbound `auth-agent@openssh.com` open being admitted without the
  client's request. (PR 1244)
- Fixed SFTP append offsets, Windows short writes, and wolfSSHd's Windows
  argv handling. (PR 1159)

---

# wolfSSH v1.5.0 (April 17, 2026)

## Vulnerabilities
- [Low] CVE-2026-0930. Potential read out of bounds case with wolfSSHd on
  Windows while handling a terminal resize request. An authenticated user could
  trigger the out of bounds read after establishing a connection which would
  leak the adjacent stack memory to the pseudo-console output. Thanks to Luigino
  Camastra and Pavel Kohout for the report. Fixed in PR 864

## New Features

- Added ML-KEM hybrid KEX algorithms `mlkem1024nistp384-sha384` and
  `mlkem768x25519-sha256` from draft-ietf-sshm-mlkem-hybrid-kex, with KEX tests
  driven by name and a GitHub action testing interop against OpenSSH. (PR 869)
- Allowed building wolfSSH against a wolfSSL FIPS build that has HashDRBG
  disabled. (PR 833)
- Added `lcd` and `lls` commands to the SFTP example client for changing and
  listing the local working directory within a session. (PR 909)
- Added a public accessor function for retrieving a channel's type. (PR 873)
- Added client-side support for `rsa-sha2-512` signatures, separating the
  key type from the signature type so `ssh-rsa` keys can be used with
  `ssh-rsa`, `rsa-sha2-256`, or `rsa-sha2-512` signatures. (PR 890)
- Added new CI workflows: codespell, multi-compiler builds (gcc 11/12/13 and
  clang 14/15/17), and sanitizer builds (ASan, UBSan, LeakSan). (PR 884)
- Added a GitHub action to run automated Coverity scans. (PR 872)
- Added SFTP contention testing that simulates network latency with `netem`
  to exercise the non-blocking SFTP server paths. (PR 877)
- Added integration tests for client public-key authentication covering
  valid RSA, valid ECC, and wrong-key rejection. (PR 913)
- Added a unit test for `VerifyMac` using a new internal-only test entry
  point that injects packets with corrupted MACs. (PR 912)
- Added a Windows wolfsshd to wolfsftp large-transfer test and an additional
  large SFTP transfer test with an enlarged SFTP read/write buffer. (PR 874)
- Added a forwarding regression test for the echoserver. (PR 874)

## Improvements

- Replaced `WMEMCMP` in `CheckAuthKeysLine` with a constant-time comparison
  to avoid leaking authorized-key material through timing. (PR 915)
- Switched SFTP `RecvOpen` to use the same `GetAndCleanPath()` helper that
  the other SFTP handlers use. (PR 867)
- Hardened `wolfSSH_CleanPath` used by SCP. (PR 865)
- Reworked `wolfSSH_SFTP_RecvOpen` to allocate the response buffer outside
  the success path and added a centralized cleanup phase so failure cases
  send a proper SFTP status packet. (PR 905)
- Reworked the SFTP example tests to use a table linking each command to
  its expected output, cleaned up working directories before each run, and
  fixed an argument-parsing underflow when commands receive empty args.
  (PR 911)
- Hardened `SendUserAuthKeyboardResponse` against null `ssh` and missing
  `userAuthCb`, validated `PreparePacket()` success, and added a regression
  test. (PR 910)
- Made SFTP send/read handling more robust around multi-byte passwords and
  cleaned up file mode and attribute reporting. (PR 882)
- Added rekey support to additional SFTP client commands, switched
  `wolfsftp.c` to use `NoticeError` consistently, and fixed forwarding and
  agent handling in the echoserver. (PR 874)
- Validated channel-accept request and reply payloads. (PR 902)
- Hardened `DoKexDhReply()` to reject the server's public key when no
  `PublicKeyCheck` callback is registered, with a regression test added.
  (PR 917)
- Hardened `DoGlobalRequestFwd()` to reject `tcpip-forward` global requests
  when no `fwdCb` is registered, and deferred `SSH_MSG_REQUEST_SUCCESS` until
  the policy callback approves. (PR 918)
- Hardened `DoChannelOpen()` to reject channel-open requests when the
  required callback is not registered, with a regression test added.
  (PR 919)
- Added validation of the server's DH group parameters in
  `DoKexDhGexGroup` so the prime `p` is verified to be safe (`p` prime and
  `(p-1)/2` prime), plus unit tests covering known safe and unsafe primes.
  (PR 922)
- Added preprocessor guards so the Curve25519 union member used by the
  hybrid Curve25519+ML-KEM paths is only required when one of those KEX
  modes is enabled. (PR 901)
- Reorganized SFTP function placement, prototypes, and build guards, and
  fixed mismatched guards around `SFTP_FreeHandles` in
  `wolfSSH_SFTP_free`. (PR 891)
- Cleaned up macOS threading by switching to named POSIX semaphores and
  consolidating semaphore use behind a single wrapper API. (PR 895,
  resolves issue #893)
- Improved `wolfSSH_ProcessBuffer` to validate the input type, handled
  non-`WOLFSSH_CERTS` builds in `SendKexDhReply`, allowed
  `DoUserAuthRequestRsa()` and `DoUserAuthRequestRsaCert()` to accept
  `ssh-rsa`, `rsa-sha2-256`, and `rsa-sha2-512`, and added the
  `test_wolfSSH_CTX_UsePrivateKey_buffer_pem` API test. (PR 906)
- Updated the FatFS test to cache the source archive and follow the same
  wolfSSL build pattern as the other workflows. (PR 878)
- Avoided setting the terminal size to 0x0 when running the echoserver in
  echo mode, which left vim and other tools mis-sized after tests. (PR 868)
- Fixed an `snprintf` format-truncation warning in the wolfsshd test
  harness and used `sizeof` to size command buffers. (PR 866)
- Misc cleanup: whitespace in the global request functions and split the
  echoserver portion of the testsuite into its own function. (PR 873)

## Fixes

- Fixed an SFTP server hang on `WS_WANT_WRITE` with non-blocking sockets:
  `wolfSSH_SFTP_buffer_send()` now flushes any pending output buffered from
  a previous `WS_WANT_WRITE` before queuing more data. (PR 876)
- Fixed a Coverity untrusted-divisor finding by reworking `ato32()` to mask
  and shift defensively. (PR 870, CID 572837)
- Simplified and fixed `AddAssign64` when `WOLFSSL_MAX_32BIT` is not
  defined. (PR 894)
- Added bounds checks in the FatFS-backed `ff_close`, `ff_pwrite`, and
  `ff_pread` SFTP helpers. (PR 904)
- Fixed `wolfSSH_AGENT_Relay()` to evaluate the size return rather than the
  status code. (PR 903)
- Fixed `wolfSSH_DoModes()` to update the requested output flags rather
  than overwriting the local mode flags. (PR 897)
- Added missing `wc_HashFree()` calls in the RSA/ECC `BuildUserAuthRequest`
  paths and added Ed25519 key cleanup in `FreePubKey()` with a
  `keyAllocated` flag tracked in `ParseEd25519PubKey()`. (PR 896)
- Fixed Windows authentication: `SetupUserTokenWin()` now uses
  `DomainName.Length` for `DomainName.MaximumLength`, and
  `CheckPasswordWIN()` now computes `usrWSz` as a wide-character length.
  (PR 898)
- Fixed several smaller findings: foreground-color mask in mode 30, an
  error-path guard around `findHandle`, bounds-checked `GetSkip()` use in
  `ParseRSAPubKey()` / `ParseECCPubKey()`, and a length-validation bug.
  (PR 899)
- Fixed compilation when `WOLFSSH_NO_NISTP256_MLKEM768_SHA256` is defined.
  (PR 887)
- Fixed a non-constant-time password-hash comparison and added missing
  bounds checks in `DoIgnore`, `DoUserAuthRequestPassword`,
  `DoServiceRequest`, and `PrepareUserAuthRequestEcc`, plus an unsigned-vs-
  zero comparison. (PR 892)
- Static-analysis fixes: uninitialized `mode` in FatFS `ff_open`, an
  operator-precedence bug, missing `wc_ecc_init()` before ECC key import,
  unchecked `wc_InitRsaKey` return, missing `break` between switch cases,
  and missing `ForceZero` on a plaintext password copy. (PR 883)
- Static-analysis fixes: missing null check on a duplicated string, bounds
  check on an addition using a peer value, null dereference after a failed
  channel lookup, wrong pointer checked for null, and a wrong bitwise
  operator when testing an attribute. (PR 881)
- Static-analysis fixes: logical operator in public-key type validation,
  buffer over-read in `wolfSSH_DoModes` terminal-mode parsing, two bugs in
  `PostRemoveId` agent identity removal, digest comparison in `FindKeyId`,
  octal validation loop index in `GetScpFileMode`, wrong variable checked
  in the `DoCheckUser` auth callback, and a NULL pointer dereference in
  `wolfSSH_SetTpmDev` / `wolfSSH_SetTpmKey`. (PR 880)
- Static-analysis fixes: an `oct2dec` typo, a linked-list leak, Nucleus
  month and hour handling, `DoDisconnect` now signals connection
  termination, `DoChannelOpen` returns a proper failure response (with a
  regression test), and the host-key signature algorithm name is now
  validated in `DoKexDhReply()`. (PR 908)
- Fixed `PostSignRequest` to pass the correct `digestSz` to
  `SignHashRsa()`. (PR 916)
- Fixed `DoChannelOpenConf()` to update `idx` with the consumed length for
  consistency and correctness. (PR 920)
- Fixed the server-side `DoKexDhReply()` to set `expectMsgId` to
  `MSGID_NEWKEYS` before sending its new keys message. (PR 921)

---

# wolfSSH v1.4.22 (January 5, 2026)

## Vulnerabilities

- [Critical] CVE-2025-14942. wolfSSH's key exchange state machine can be
  manipulated to leak the client's password in the clear, trick the client to
  send a bogus signature, or trick the client into skipping user
  authentication. This affects client applications with wolfSSH version 1.4.21
  and earlier. Users of wolfSSH must update or apply the fix patch and it's
  recommended to update credentials used. This fix is also recommended for
  wolfSSH server applications. While there aren't any specific attacks, the
  same defect is present. Thanks to Aina Toky Rasoamanana of Valeo and Olivier
  Levillain of Telecom SudParis for the report. (PR 855)
- [Medium] CVE-2025-15382. The function used to clean up a path string may read
  one byte off the end of the bounds of the string. The function is used by the
  SCP handling in wolfSSH. This affects server applications with wolfSSH
  versions 1.4.12 through 1.4.21, inclusive. Thanks to Luigino Camastra from
  Aisle Research for the report. (PR 859)

## New Features

- Added a complete SFTP client example for the Renesas RX72N platform.
  (PR 847)
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
  around GetStringRef(), simplifying maintenance and reducing duplication.
  (PR 857)
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

- Fix off-by-1 read error when cleaning the file path for SCP. (PR 859)
- Fixed incorrect handling of zero-length SSH strings in packet parsing.
  (PR 857)
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
  separators or "dot" components. (PR 845)
- Fixed missing declaration of wc_SSH_KDF that caused build failures under
  strict compiler warnings. (PR 848)
- Fixed SSH agent test setup so regression tests exercise the intended code
  paths. (PR 845)
- Excluded a standalone regression test from Zephyr builds where it was
  incompatible with the Zephyr test model. (PR 855)

---

# wolfSSH v1.4.21 (October 20, 2025)

## Vulnerabilities

- [Critical] CVE-2025-11625 The client's host verification can be bypassed
  by a malicious server, and client credentials leaked. This affects client
  applications with wolfSSH version 1.4.20 and earlier. Users of wolfSSH on
  the client side must update or apply the fix patch and it's recommended to
  update credentials used.
  Fixed in PR (https://github.com/wolfSSL/wolfssh/pull/840)

- [Med] CVE-2025-11624 Potential for stack overflow write when reading the
  file handle provided by an SFTP client. After a SFTP connection was
  established there is the case where a SFTP client could craft a malicious
  read, write or set state SFTP packet which would cause the SFTP server
  code to write into stack. Thanks to Stanislav Fort of Aisle Research for
  the report. Fixed in PR (https://github.com/wolfSSL/wolfssh/pull/834)

## New Features

- Curve25519 interoperability with LibSSH. Update to treat
  curve25519-sha256@libssh.org as an alias for curve25519-sha256 (PR 789)
- Microchip example for ATSAMV71Q21B and harmony filesystem support (PR 790)
- Make Keyboard Interactive a compile time option, enabled using
  --enable-keyboard-interactive. Off by default. (PR 800)
- wolfSSH support for using TPM based key for authentication (PR 754)
- By default, soft disable AES-CBC. It isn't offered as a default encrypt
  algorithm, but may be set at runtime (PR 804)
- Add ED25519 key generation support. (PR 823)

## Improvements

- Add GitHub Action for testing wolfSSH server with Paramiko SFTP client
  (PR 788)
- Additional sanity checks on message types during rekey (PR 793)
- FATFS improvements, test and Linux example (PR 787)
- Adjust behavior when getting WOLFSSH_USERAUTH_REJECTED return from
  callback. It now will reject and not continue on with user auth attempts.
  (PR 837)
- Rename arguments and variables to idx instead of index to avoid shadowed
  variables. (PR 828)
- Move user filesystem override to the top of the ports check so that the
  override also overrides enabled ports. (PR 805)
- Remove keyboard auth callback and use a generic auth callback (PR 807)
- Update Espressif examples and add getting started info to Espressif README
  (PR 810, 771)
- Disable old threading functions when SINGLE_THREADED (PR 809)
- Replace Kyber 512 with ML-KEM 768. (PR 792)
- Update SFTP status callback to output once per second. (PR 779)
- Refactor to leverage wolfSSL FALLTHROUGH macro with switch statements.
  (PR 815)
- Autoconf and Automake Updates (PR 821)
- Simplify Test Build Flags (PR 818)
- Fixed typo and spelling edits (PR 797, 798)

## Fixes

- Fix SFTP data truncation by moving sentSzSave to state structure(PR 785)
- Fix SFTP Symlink Indication. (PR 791)
- Fix warning on FATFS builds (PR 796)
- Keyboard Interactive bug fixes (PR 801, 802)
- Fix double-free on `wolfSSH_SFTPNAME_readdir` (PR 806)
- Adjust the highwater check location to avoid masking the return value.
  (PR 795)
- DoAsn1Key now fails when WOLFSSH_NO_RSA is defined (PR 808)
- Avoid potential for overflow/underflow in comparison by rearranging
  evaluation of unsigned condition. (PR 814)
- Fixing a batch of warning from Coverity reports. (PR 817, 820, 822)
- Fix inet_addr accounting for '.' character (PR 816)
- Fix to only send ext info once after SSH_MSG_NEWKEYS. (PR 819)
- Fix "rejected" authentication in DoUserAuthRequestPublicKey() (PR 825)
- Rename struct Buffer to WOLFSSH_BUFFER in wolfSSH_ShowSizes to match the
  previous rename.(PR 830)
- Rename wolfssh test certs to avoid conflict with wolfssl test certs (PR 831)
- Do not treat the shell as interactive until pty-req message request is
  received. This fixes an interoperability issue with WinSCP (PR 832)

---

# wolfSSH v1.4.20 (February 20, 2025)

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
- Reinstate support for P521 and P384 curves by default when compiled in
  (PR 762)
- Fix for wolfSSH client app handling of an empty hostname (PR 768)

---

# wolfSSH v1.4.19 (November 1, 2024)

## New Features

- Add DH Group 14 with SHA256 KEX support (PR 731)

## Improvements

- Use of the new SSH-KDF function in wolfCrypt (PR 729)
- Adds macro guards to the non-POSIX value checks and updates with TTY modes
  (PR 739)
- Add CI test against master and last two wolfSSL releases (PR 746)
- Show version of wolfSSL linked to when application help messages are
  printed out (PR 741)
- Purge OQS from wolfSSH and instead use Kyber implementation from wolfssl
  (PR 736)
- Adjust Espressif wolfssl_echoserver example timehelper (PR 730)

## Fixes

- Remove Inline for function HashForId() to resolve clash with WOLFSSH_LOCAL
  declaration (PR 738)
- Fix for wolfSSHd's handling of re-key and window full when processing a
  command with lots of stdout text (PR 719)
- Fix for wolfSSH client app to gracefully clean up on failure and added
  more WLOG debug messages (PR 732)
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
- Improve wolfSSHd's behavior on closing a connection. It closes channels and
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

- Add user authentication support for RSA signing with SHA2-256 and SHA2-512
  (Following RFC 8332)
- Support for FATFS on Xilinx targets
- ecc_p256-kyber_level1 interop with OQS OpenSSH following the RFC
  https://www.ietf.org/id/draft-kampanakis-curdle-ssh-pq-ke-01.html
- Internal refactor of client apps to simplify them and added X509 support
  to scpclient
- wolfSSH_accept now returns WS_SCP_INIT and needs called again to complete
  the SCP operation
- Update to document Cube Pack dependencies
- Add carriage return for 'enter' key in the example client with shell
  connections to windows server
- Stack usage improvement to limit the scope of variables
- Echoserver example SFTP non blocking improvement for want read cases
- Increase SFTP performance with throughput

## Fixes

- Fix for calling chdir after chroot with wolfSSHd when jailing connections
  on unix environments
- Better handling on the server side for when the client's window is filled up
- Fix for building the client project on windows when shell support is enabled
- Sanity check improvements for handling memory management with non blocking
  connections
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
- wolfSSHd Release (https://github.com/wolfSSL/wolfssh/pull/453 rounds off
  testing and additions)
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
- Add preprocessor guards for RSA/ECC to agent and the example and test
  applications
- Initialization of variables to avoid warnings and use with ESP-IDF

## Fixes
- When scp receives a string in STDERR, print it out, rather than treating
  it as an error
- Window adjustment refactor and fix
- fix check on RSA import size
- Fix for building with older GCC versions (tested with 4.0.2)
- SFTP fix handling sent data sz when its size is greater than peer max
  packet size
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
- When processing SFTP messages, wolfSSH isn't checking data lengths against
  the size of the message and is potentially under-allocating, over-reading,
  and over-writing buffers. Thank you to Michael Randrianantenaina, an
  independent security researcher, for the report.

---

# wolfSSH v1.4.7 (July 23, 2021)

## New Feature Additions and Improvements

- SCP improvements to run on embedded RTOS
- For SFTP messages, check both minimum bound and maximum bound of the
  length value
- Added option for --enable-small-stack
- Added SFTP support for FatFs
- Added 192 and 256 bit support for AES-CBC, AES-CTR, and AES-GCM
- Added options to disable algorithms. (ie WOLFSSH_NO_ECDSA,
  WOLFSSH_NO_AES_CBC, etc)
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

- Added optional builds for not using RSA or ECC making the build more
  modular for resource constrained situations.
- MQX IDE build added
- Command line option added for Agent use with the example client



## Fixes

- Increase the ID list size for interop with some OpenSSH servers
- In the case of a network error add a close to any open files with SFTP
  connection
- Fix for potential memory leak with agent and a case with
  wolfSHS_SFTP_GetHandle
- Fuzzing fix for potential out of bounds read in the public key user auth
  messages
- MQX build fixes
- Sanity check that agent was set before setting the agent's channel
- Fuzzing fix for bounds checking with DoKexDhReply internal function
- Fuzzing fix for clean up of base path with SCP use
- Fuzzing fix for sanity checks on setting the prime group and generator
- Fuzzing fix for return result of high water check
- Fuzzing fix for null terminator in internal ReceiveScpConfirmation function

## Improvements and Optimizations

- Example timeout added to SFTP example
- Update wolfSSH_ReadKey_buffer() to handle P-384 and P-521 when reading a
  key from a buffer
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
- Fix for SFTP "LS" operation when setting the default window size to 2048
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
- Fix for fail case with leading 0's on MPINT
- Default window size (DEFAULT_WINDOW_SZ) lowered from ~ 1 MB to ~ 16 KB
- Disable examples option added to configure (--disable-examples)
- Callback function and example use added for checking public key sent
- AES CTR cipher support added
- Fix for free'ing ECC caches with examples
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
  If no string is provided, no banner is sent.
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

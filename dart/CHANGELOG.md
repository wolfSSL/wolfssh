# Changelog

## 0.1.0

Initial release.

- FFI bindings for the wolfSSH client at v1.5.0-stable.
- `WolfSshContext` with mandatory `HostKeyVerifier` and `UserAuthStrategy`.
- Fail-closed host-key and user-auth callback trampolines.
- Password and public-key user-auth: the callback fills
  `WS_UserAuthData.sf.password` or `WS_UserAuthData.sf.publicKey` via
  the `wolfssh_dart_fill_password` / `wolfssh_dart_fill_pubkey` helpers
  in the C glue. Credential bytes are held in context-owned native
  buffers (managed by the internal `_NativeByteBuffer` helper) that
  are zeroed on dispose.
- `UserAuthStrategy.publicKey(username, PublicKeyCredential)` factory
  alongside the existing `UserAuthStrategy.password`.
- `WolfSshSession.connect`, `readOnce` / `writeOnce` / `writeAll`.
- `IoStatus` sum type for `WS_WANT_READ` / `WS_WANT_WRITE` / `EOF`.
- `example/posix_socket.dart` — Linux/macOS libc FFI helper that opens
  an IPv4 TCP socket and returns the raw fd, used by the connect demo
  (since `dart:io`'s `Socket` doesn't expose its fd).
- PoC exploit tests covering the binding's CVE mitigations:
  - `test/cve_host_key_bypass_test.dart` — exercises the host-key
    callback trampoline against the input shapes that would have to
    succeed to regress CVE-2025-11625 (NULL pointer, zero-length,
    oversize key, throwing verifier).
  - `test/cve_user_auth_bypass_test.dart` — pins every
    `UserAuthOutcome.code` to its `WOLFSSH_USERAUTH_*` native constant
    and asserts no two outcomes alias to `SUCCESS`.
  - `test/cve_ffi_buffer_overflow_test.dart` — exercises
    `checkBufferLen` at the word32 boundary so a Dart `int` overflow
    cannot silently truncate at the FFI edge.

See `SECURITY.md` for security-critical paths and host-key verification
guidance.

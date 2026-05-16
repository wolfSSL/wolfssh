# Changelog

## 0.1.1

Security hardening from internal review (`docs/security-review-log.md`):

- **`WolfSshLibrary.load` now enforces a minimum native wolfSSH
  version** (`>= 0x01005000` = 1.5.0). Calls `wolfssh_dart_version_hex`
  immediately after binding resolution and throws `StateError` if the
  loaded `.so/.dylib/.dll` was built against a pre-1.5.0 wolfSSH —
  closing a silent-downgrade path that could otherwise have loaded a
  binary missing the CVE-2025-11625 fix.
- **`checkBufferLen` now gates the user-auth fill path** (password +
  public-key) in addition to the existing stream-I/O call sites. The
  four `Uint8List.length` values passed through to
  `wolfssh_dart_fill_password` / `wolfssh_dart_fill_pubkey` are
  validated before crossing the FFI boundary, restoring full coverage
  of the SECURITY.md §4 policy.
- **`_NativeByteBuffer.writeAll` zeroes the tail** of the allocation
  when a write is smaller than current capacity. Prevents previous
  larger credentials (passwords, private keys) from lingering in heap
  pages until the next grow or `dispose`.
- **`WolfSshSession` refuses to operate against a disposed
  `WolfSshContext`**. New `context.isDisposed` getter; both
  `WolfSshSession.connect` and `_ensureOpen` check it and throw
  `StateError` instead of dereferencing a freed `WOLFSSH_CTX*`.
- **NUL-byte validation on `username`** in `WolfSshSession.connect`.
  Previously an embedded NUL would have been silently truncated by
  `wolfSSH_SetUsername`'s strlen-semantics, letting a caller bug
  authenticate as a prefix of the intended username. Now throws
  `ArgumentError`.
- Documentation:
  - `library.dart` per-isolate vs per-process semantics for
    `wolfSSH_Init` clarified.
  - `error.dart` "constant-time-ish" comment removed (buffer lengths
    are not secret).
  - `UserAuthFill.password` / `.publicKey` factories note the
    `assert(credential is X)` is debug-only; runtime enforcement is
    in `_userAuthTrampoline`.
- New test: `test/library_version_test.dart` — PoCs the
  anti-downgrade gate.

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

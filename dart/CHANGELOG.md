# Changelog

## 0.1.0

Initial release.

- FFI bindings for the wolfSSH client at v1.5.0-stable.
- `WolfSshContext` with mandatory `HostKeyVerifier` and `UserAuthStrategy`.
- Fail-closed host-key and user-auth callback trampolines.
- `WolfSshSession.connect`, `readOnce` / `writeOnce` / `writeAll`.
- `IoStatus` sum type for `WS_WANT_READ` / `WS_WANT_WRITE` / `EOF`.
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

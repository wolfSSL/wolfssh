# Changelog

## 0.1.0

Initial release.

- FFI bindings for the wolfSSH client at v1.5.0-stable.
- `WolfSshContext` with mandatory `HostKeyVerifier` and `UserAuthStrategy`.
- Fail-closed host-key and user-auth callback trampolines.
- `WolfSshSession.connect`, `readOnce` / `writeOnce` / `writeAll`.
- `IoStatus` sum type for `WS_WANT_READ` / `WS_WANT_WRITE` / `EOF`.

See `SECURITY.md` for security-critical paths and host-key verification
guidance.

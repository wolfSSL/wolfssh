# Critical security paths — wolfSSH Dart FFI

> **Unofficial.** This package is an independent, community-maintained
> Dart FFI wrapper around wolfSSH and is **not affiliated with, endorsed
> by, or supported by wolfSSL Inc.** Vulnerabilities **in this binding**
> (the Dart wrapper, the FFI trampolines, the CMake glue) should be
> reported to this repository's issue tracker. Vulnerabilities in
> wolfSSH or wolfSSL **upstream** should be reported to wolfSSL Inc.
> directly (https://www.wolfssl.com/, `licensing@wolfssl.com`).

This binding wraps wolfSSH **v1.5.0-stable** (April 17, 2026). Older
versions are out of scope and **must not** be used: CVE-2025-11625 (a
critical client host-verification bypass) was fixed in 1.4.21+. The
CMakeLists.txt also pins a tested wolfSSL release; mismatched wolfSSL
can defeat the protocol-hardening intent of upgrading wolfSSH.

## CVE regression tests

The `test/` directory contains PoC tests that drive the binding with
the input shapes a regression of each documented CVE class would have
to accept. Each is pure-Dart and runs in CI without the native lib:

  * `test/cve_host_key_bypass_test.dart` — CVE-2025-11625 (host-key
    bypass) mitigations at the trampoline layer. Exercises NULL key
    pointer, zero-length, oversize (> 64 KiB), and a throwing
    verifier; asserts each is rejected (return code 1) regardless of
    the registered verifier's policy.
  * `test/cve_user_auth_bypass_test.dart` — auth-callback bypass
    class (e.g. CVE-2018-10933 in libssh). Pins every
    `UserAuthOutcome.code` to the native `WOLFSSH_USERAUTH_*`
    constant, asserts no non-success outcome aliases to SUCCESS, and
    asserts `UserAuthFill.decline()` defaults to FAILURE never SUCCESS.
  * `test/cve_ffi_buffer_overflow_test.dart` — integer-truncation
    class at the Dart `int` ↔ wolfSSH `word32` boundary. Asserts
    `checkBufferLen` allows 0 and 0xFFFFFFFF, rejects 0x100000000,
    INT64-large, and any negative length.

A red light on any of these tests is a security regression, not a
flake. Investigate before merging.

This document inventories every place where the FFI boundary touches a
security-sensitive path. The numbering matches `lib/src/auth/` and
`lib/src/context.dart` so reviewers can map docs ↔ code.

## 1. Host-key verification (highest priority)

**Hazard.** wolfSSH's `WS_CallbackPublicKeyCheck` is a soft default: if
no callback is registered, the server's offered host key is accepted
silently with a debug log line ("DKDR: no public key check callback,
accepted"). That is a textbook MITM hole. CVE-2025-11625 was a related
bypass against client host verification.

**Defence.** [`WolfSshContext`](lib/src/context.dart) takes a **required,
non-null** `HostKeyVerifier`. There is no default. The constructor wires
the native callback unconditionally and routes it through the trampoline
in `lib/src/auth/host_key.dart`. The trampoline:

  * rejects when `keyPtr == nullptr` or `keySz == 0`;
  * rejects when `keySz > 64 KiB` (defence-in-depth — host keys are at
    most a few KB; an oversize blob means the parser is in an
    unexpected state);
  * **fail-closed on exception**: any throw from the verifier is caught
    and translated to "reject", and the `NativeCallable` is constructed
    with `exceptionalReturn: 1` so even an out-of-Dart panic rejects.

Built-in verifier strategies, in order of preference:

| Verifier | Use when | Surface area |
|---|---|---|
| `HostKeyVerifier.fingerprintPin([sha256])` | You can pin keys out-of-band (CI, infra automation). | Pure SHA-256 compare, no I/O. |
| `HostKeyVerifier.knownHosts(file, hostnameAndPort:)` | Interactive use mirroring OpenSSH semantics. | Reads a file; `trustOnFirstUse: true` opt-in. |
| `HostKeyVerifier.acceptAnyDangerous()` | **Lab only.** | The constructor name is intentionally awkward to surface in code review. |

Reviewers should `grep -rn 'acceptAnyDangerous\|trustOnFirstUse: true'`
on every audit.

## 2. User-auth callback fail-closed

**Hazard.** wolfSSH's `WS_CallbackUserAuth` returns an int. Returning
`WOLFSSH_USERAUTH_SUCCESS` (= 0) by accident — including from an
uncaught exception — passes auth.

**Defence.** The trampoline in `lib/src/context.dart`:

  * coerces only from the typed `UserAuthOutcome` enum, never raw ints;
  * registers the `NativeCallable` with
    `exceptionalReturn: WOLFSSH_USERAUTH_FAILURE` so any uncaught Dart
    exception fails the auth attempt;
  * wraps every strategy invocation in `try / catch` and returns
    `WOLFSSH_USERAUTH_FAILURE` on any throw.

Note: the password-flow native fill path (writing the credential into
`WS_UserAuthData.sf.password`) is not yet implemented in this skeleton —
see the comment in `_userAuthTrampoline`. Until that lands the binding
is suitable for handshake/host-key verification testing but cannot
complete a full password authentication. This is tracked as a known
limitation, not a security regression.

## 3. Memory ownership

| Native API | Owner | Wrapper |
|---|---|---|
| `wolfSSH_CTX_new` → `WOLFSSH_CTX*` | caller frees | `WolfSshContext.dispose()` (manual; see below) |
| `wolfSSH_new` → `WOLFSSH*` | caller frees | `WolfSshSession.dispose()` (manual) |
| `wolfSSH_GetUsername` → `const char*` | wolfSSH-owned (do not free) | not exposed; if added, must `.toDartString()` to copy |
| `wolfSSH_ReadKey_buffer` output `byte**` | caller frees | not exposed in this iteration |

The `NativeCallable`s for the auth and host-key trampolines are owned
by `WolfSshContext` and closed in `dispose()`. Forgetting to `dispose`
leaks them but does not corrupt: the Dart side holds them as fields and
GC reclaims memory once unreachable.

This iteration does **not** attach a `NativeFinalizer` for `WOLFSSH_CTX*`
or `WOLFSSH*`. Doing so requires a `Pointer<NativeFinalizerFunction>`
to `wolfSSH_CTX_free` / `wolfSSH_free`, which is per-library-instance
and not available until after `WolfSshLibrary.load`. The callers must
therefore call `dispose()` deterministically (use `try / finally`).
Forgetting to dispose leaks native memory but does not violate any
security invariant. A follow-up may wire finalizers via a process-wide
singleton library.

## 4. Buffer/length validation at the FFI boundary

Every `(byte*, word32)` API is gated by `checkBufferLen` in
`lib/src/error.dart`, which rejects any length outside `[0, 0xFFFFFFFF]`
before crossing the FFI boundary. Affected calls in this iteration:
`wolfSSH_stream_read`, `wolfSSH_stream_send`. When extending bindings,
always route new buffer lengths through `checkBufferLen` so a 64-bit
`int` from Dart cannot silently truncate to a 32-bit `word32` and
under-flow the destination buffer.

## 5. Stream return-code semantics

`wolfSSH_stream_read` and `wolfSSH_stream_send` may return a positive
byte count, `WS_WANT_READ`, `WS_WANT_WRITE`, `WS_EOF`,
`WS_CHANNEL_CLOSED`, or a negative hard error. The wrapper exposes this
as the sealed `IoStatus` type (`IoCompleted` / `IoWantRead` /
`IoWantWrite` / `IoEof`); hard errors are turned into
`WolfSshException` via `wolfSSH_get_error` so the caller sees the real
classification rather than the immediate return value.

## 6. RNG / entropy

wolfSSH delegates RNG to wolfCrypt. The CMake build:

  * pins `wolfssl v5.7.6-stable` via `FetchContent`, with default seed
    sources (POSIX `/dev/urandom`, Windows `BCryptGenRandom`,
    macOS/iOS `arc4random_buf`);
  * never enables `WOLFSSL_GENSEED_FORTEST`;
  * passes through `HAVE_HASHDRBG`-compatible defaults.

If a downstream consumer overrides wolfSSL build flags they are on the
hook for entropy. Document any override in your project's threat model.

## 7. Sensitive parsers (advisory)

The Dart binding does not invoke these directly, but a misconfigured
wolfCrypt build can defeat their hardening. After every wolfSSH or
wolfSSL bump, re-audit:

  * `DoUserAuthRequestPublicKey` in `src/internal.c` — public-key auth
    parsing (multiple OOB fixes through 1.4.x).
  * `DoKexDhReply` — DH KEX bounds + prime/generator sanity checks.
  * `ReceiveScpConfirmation` — out of scope (build flags disable SCP
    server) but worth checking.

## 8. Context void-pointer usage

Both `wolfSSH_SetUserAuthCtx` and `wolfSSH_SetPublicKeyCheckCtx` accept
a `void*`. We pass the **context's own native pointer**, not a Dart
heap address (which the GC could move). The trampoline uses
`lookupContextByAddress(ctxArg.address)` to recover the strongly-typed
`WolfSshContext` from a registry keyed on that pointer, gated to the
Dart isolate's main thread.

## 9. Notable CVEs absorbed by the v1.4.6 → v1.5.0 upgrade

From `ChangeLog.md`:

  * **CVE-2025-11625** [Critical] — client host verification bypass (≤1.4.20).
  * **CVE-2025-14942** [Critical] — KEX state-machine manipulation that
    could leak the client password in cleartext.
  * **CVE-2025-15382** [Medium] — path-string OOB read.
  * **CVE-2025-11624** [Med] — SFTP stack overflow (out of scope here,
    but build flags disable SFTP server symbols anyway).
  * **CVE-2026-0930** [Low] — wolfSSHd Windows server-side OOB (out of
    scope).
  * **CVE-2022-32073** [historical] — context for v1.4.8.

## Reviewer's grep checklist

Run before approving any change to this package:

```sh
grep -rn 'acceptAnyDangerous'             dart/
grep -rn 'trustOnFirstUse: true'          dart/
grep -rn 'NativeCallable<'                dart/lib/    # every callback must set exceptionalReturn
grep -rn 'exceptionalReturn'              dart/lib/    # ... and to a *failure* value
grep -rn 'malloc\b'                       dart/lib/    # confirm matched malloc.free
grep -rn 'WOLFSSH_USERAUTH_SUCCESS'       dart/lib/    # ensure not returned from a default arm
grep -rn 'asTypedList'                    dart/lib/    # no aliasing across an FFI free
```

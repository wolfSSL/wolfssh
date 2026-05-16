# Security review log — Dart FFI binding to wolfSSH

A per-section walkthrough of security-sensitive code in `dart/lib/` and
`dart/native/`. Each entry captures honest findings: what's a real
defense, what's hygiene, and what's a found gap. Pinned to commit
`9e923177a66b38baf562e1a96d4eefedc40ecd06` on branch
`claude/dart-ffi-wolfssh-security-DjdXd`.

For the user-facing "what defenses exist and why" document, see
[`SECURITY.md`](../SECURITY.md). This log is the auditor's view.

Calibration legend used in tables:

  * **Real defense** — removing it enables a concrete attack or
    correctness failure that an attacker could trigger.
  * **Real hygiene** — removing it would weaken credential or memory
    handling but no realistic attacker gains anything directly.
  * **Modest defense** — defensive coding for cases unreachable in
    normal operation; cheap, keep, but don't oversell.
  * **Found gap** — a real shortcoming. Severity noted inline.
  * **Design question** — judgement call worth flagging in review.

---

## Entry 01 — Host-key trampoline (`lib/src/auth/host_key.dart`)

**Threat model.** wolfSSH's `WS_CallbackPublicKeyCheck` defaults to
"accept any key with a debug log warning" — exactly the class of bug
behind CVE-2025-11625. If our binding ever invokes wolfSSH without a
working callback, every connection is silently MITM-able.

**Defense shape.** The file defines the `HostKeyVerifier` policy
interface, three built-in verifiers, and the trampoline that converts
the C `(byte*, word32)` call into a Dart `bool verify(Uint8List)` call.
Three layers of fail-closed (try/catch in inner trampoline,
try/catch in outer trampoline at `context.dart:181`, `exceptionalReturn:
1` on the NativeCallable).

### Calibrated table

| Item | Weight | Local ref | Permalink |
|---|---|---|---|
| `verify()` declared as `bool` (not `int`) — prevents `WS_SUCCESS==0` confusion | Real defense | `host_key.dart:33` | [L33](https://github.com/j4qfrost/wolfssh/blob/9e923177a66b38baf562e1a96d4eefedc40ecd06/dart/lib/src/auth/host_key.dart#L33) |
| `acceptAnyDangerous` factory name (grep target for reviewers) | Soft defense | `host_key.dart:54` | [L54](https://github.com/j4qfrost/wolfssh/blob/9e923177a66b38baf562e1a96d4eefedc40ecd06/dart/lib/src/auth/host_key.dart#L54) |
| Empty fingerprint pin list throws `ArgumentError` | Real defense (UX: surface intent instead of silent reject-all) | `host_key.dart:60-62` | [L60-L62](https://github.com/j4qfrost/wolfssh/blob/9e923177a66b38baf562e1a96d4eefedc40ecd06/dart/lib/src/auth/host_key.dart#L60-L62) |
| `_normalize` preserves base64 case | Real defense — lowercasing would weaken comparison | `host_key.dart:73-84` | [L73-L84](https://github.com/j4qfrost/wolfssh/blob/9e923177a66b38baf562e1a96d4eefedc40ecd06/dart/lib/src/auth/host_key.dart#L73-L84) |
| `trustOnFirstUse = false` default | Real defense — flipping enables first-contact MITM | `host_key.dart:91` | [L91](https://github.com/j4qfrost/wolfssh/blob/9e923177a66b38baf562e1a96d4eefedc40ecd06/dart/lib/src/auth/host_key.dart#L91) |
| Mismatched-key path doesn't auto-update known_hosts | Real defense — strict known_hosts invariant | `host_key.dart:111-122` | [L111-L122](https://github.com/j4qfrost/wolfssh/blob/9e923177a66b38baf562e1a96d4eefedc40ecd06/dart/lib/src/auth/host_key.dart#L111-L122) |
| Trampoline `try {`...`catch (_) { return 1; }` envelope | Real defense — fail-closed on verifier throw | `host_key.dart:235, 246-249` | [L235-L249](https://github.com/j4qfrost/wolfssh/blob/9e923177a66b38baf562e1a96d4eefedc40ecd06/dart/lib/src/auth/host_key.dart#L235-L249) |
| `return verifier.verify(bytes) ? 0 : 1` direction | Real defense — swap inverts the policy | `host_key.dart:245` | [L245](https://github.com/j4qfrost/wolfssh/blob/9e923177a66b38baf562e1a96d4eefedc40ecd06/dart/lib/src/auth/host_key.dart#L245) |
| NULL keyPtr / zero keySz guard | Modest defense — unreachable from non-buggy wolfSSH | `host_key.dart:236-238` | [L236-L238](https://github.com/j4qfrost/wolfssh/blob/9e923177a66b38baf562e1a96d4eefedc40ecd06/dart/lib/src/auth/host_key.dart#L236-L238) |
| 64 KiB oversize guard | Modest defense — sanity check; SHA-256 on 64 KiB is microseconds, not a DoS bound | `host_key.dart:239-243` | [L239-L243](https://github.com/j4qfrost/wolfssh/blob/9e923177a66b38baf562e1a96d4eefedc40ecd06/dart/lib/src/auth/host_key.dart#L239-L243) |
| `Uint8List.fromList(...)` copy of native bytes | Real hygiene — protects user-supplied verifiers that retain the buffer; in-tree verifiers hash synchronously and don't need it | `host_key.dart:244` | [L244](https://github.com/j4qfrost/wolfssh/blob/9e923177a66b38baf562e1a96d4eefedc40ecd06/dart/lib/src/auth/host_key.dart#L244) |

### Found gaps / followups for entry 01

None blocking. Two soft notes:

1. `_KnownHostsVerifier` does no file locking — concurrent connects could
   interleave appends. Tolerable for single-process use; flag if we
   add multi-isolate support.
2. `_KnownHostsVerifier` stores plaintext hostnames where OpenSSH's
   `HashKnownHosts yes` mode stores salted hashes. Not a wire-attacker
   concern; privacy gap if the file is exfiltrated. Worth a follow-up
   if we ship to mobile.

### Self-correction from first pass

Earlier draft of this entry over-sold three items:

  * The 64 KiB oversize cap and NULL/zero guard were framed as
    "defense" against the network attacker. They're not — wolfSSH
    won't reach the callback with NULL/oversize in normal operation.
    They're sanity checks; keep them, but they aren't load-bearing.
  * The `catch (_)` underscore was described as a logging-oracle
    mitigation. That was wrong: the SSH server can't read our logs;
    `_` is just Dart idiom for an unused binding.
  * The `Uint8List.fromList` copy was labelled "critical." For the
    in-tree verifiers it's unnecessary; it's defense-in-depth against
    user-supplied verifiers that retain the buffer.

Recorded so future reviewers don't re-inflate the same claims.

---

## Entry 02 — Context wiring & user-auth trampoline (`lib/src/context.dart`)

**Threat model.** Two failure classes: (a) a `WolfSshContext`
constructed without a verifier or strategy (would expose the wolfSSH
"accept any key" default and "any user-auth callback return = success"
default), and (b) a callback invocation that escapes Dart with no
return value (Dart panic, OOM) — wolfSSH would receive an undefined
return.

**Defense shape.** API-level: both verifier and strategy are
`required` non-nullable. Wiring: factory unconditionally registers
both callbacks before returning. Runtime: outer + inner try/catch on
both trampolines, plus `exceptionalReturn` on the NativeCallable as
final backstop.

### Calibrated table

| Item | Weight | Local ref | Permalink |
|---|---|---|---|
| `required` non-null `hostKeyVerifier` + `userAuthStrategy` | Real defense — compile-time enforcement of "no default accept" | `context.dart:30-31` | [L30-L31](https://github.com/j4qfrost/wolfssh/blob/9e923177a66b38baf562e1a96d4eefedc40ecd06/dart/lib/src/context.dart#L30-L31) |
| `exceptionalReturn: 1` on host-key NativeCallable | Real defense — third layer of fail-closed | `context.dart:45` | [L45](https://github.com/j4qfrost/wolfssh/blob/9e923177a66b38baf562e1a96d4eefedc40ecd06/dart/lib/src/context.dart#L45) |
| `exceptionalReturn: WOLFSSH_USERAUTH_FAILURE` on auth NativeCallable | Real defense | `context.dart:53` | [L53](https://github.com/j4qfrost/wolfssh/blob/9e923177a66b38baf562e1a96d4eefedc40ecd06/dart/lib/src/context.dart#L53) |
| `ctxSetPublicKeyCheck` + `setUserAuth` unconditional in factory | Real defense — no path returns a ctx without both wired | `context.dart:47, 55` | [L47](https://github.com/j4qfrost/wolfssh/blob/9e923177a66b38baf562e1a96d4eefedc40ecd06/dart/lib/src/context.dart#L47), [L55](https://github.com/j4qfrost/wolfssh/blob/9e923177a66b38baf562e1a96d4eefedc40ecd06/dart/lib/src/context.dart#L55) |
| `_unregisterContext` before `ctxFree` in `dispose` | Real defense — closes address-reuse race window | `context.dart:90, 93` | [L87-L101](https://github.com/j4qfrost/wolfssh/blob/9e923177a66b38baf562e1a96d4eefedc40ecd06/dart/lib/src/context.dart#L87-L101) |
| `_callable.close()` before `ctxFree` | Real hygiene — prevents new invocations into a half-freed ctx | `context.dart:91-92` | [L91-L92](https://github.com/j4qfrost/wolfssh/blob/9e923177a66b38baf562e1a96d4eefedc40ecd06/dart/lib/src/context.dart#L91-L92) |
| `disposeAndZero` on credential buffers | Real hygiene — scrubs secrets at end of life | `context.dart:97-100` | [L97-L100](https://github.com/j4qfrost/wolfssh/blob/9e923177a66b38baf562e1a96d4eefedc40ecd06/dart/lib/src/context.dart#L97-L100) |
| `_NativeByteBuffer.ensure` zero-on-grow | Real hygiene | `context.dart:129` | [L129](https://github.com/j4qfrost/wolfssh/blob/9e923177a66b38baf562e1a96d4eefedc40ecd06/dart/lib/src/context.dart#L129) |
| Outer try/catch in `_hostKeyTrampoline` | Modest defense — mostly insures the lookup line | `context.dart:183, 187-189` | [L181-L190](https://github.com/j4qfrost/wolfssh/blob/9e923177a66b38baf562e1a96d4eefedc40ecd06/dart/lib/src/context.dart#L181-L190) |
| `ctx == null` reject in both trampolines | Real defense — closes dispose-race window | `context.dart:185, 196` | [L185](https://github.com/j4qfrost/wolfssh/blob/9e923177a66b38baf562e1a96d4eefedc40ecd06/dart/lib/src/context.dart#L185), [L196](https://github.com/j4qfrost/wolfssh/blob/9e923177a66b38baf562e1a96d4eefedc40ecd06/dart/lib/src/context.dart#L196) |
| `if (rc != WS_SUCCESS) return FAILURE` in both auth fill branches | Real defense — honors C-helper rejection | `context.dart:211, 233` | [L211](https://github.com/j4qfrost/wolfssh/blob/9e923177a66b38baf562e1a96d4eefedc40ecd06/dart/lib/src/context.dart#L211), [L233](https://github.com/j4qfrost/wolfssh/blob/9e923177a66b38baf562e1a96d4eefedc40ecd06/dart/lib/src/context.dart#L233) |
| Catch-all in `_userAuthTrampoline` | Real defense — final fail-closed for any strategy/helper throw | `context.dart:239-241` | [L239-L241](https://github.com/j4qfrost/wolfssh/blob/9e923177a66b38baf562e1a96d4eefedc40ecd06/dart/lib/src/context.dart#L239-L241) |

### Found gaps / followups for entry 02

1. **Stale-tail in `_NativeByteBuffer.writeAll`** — *Found gap, modest
   severity.* When a write is smaller than current capacity, `ensure`
   short-circuits and `setAll` only overwrites bytes `[0, src.length)`.
   Bytes `[src.length, _capacity)` retain previous credential data
   until next grow or `dispose`. Not exposed over the network
   (wolfSSH gets `(ptr, size)` and copies exactly `size`), but applies
   to `_pwBuf` and `_pkPrivBuf` (secret material). One-line fix in
   `writeAll`: zero `[src.length, _capacity)` after `setAll`.
   Local ref: `context.dart:142-148` —
   [permalink](https://github.com/j4qfrost/wolfssh/blob/9e923177a66b38baf562e1a96d4eefedc40ecd06/dart/lib/src/context.dart#L142-L148).

2. **Type-mismatch silent-drop in `_userAuthTrampoline`** — *Design
   question.* If a strategy returns a `PublicKeyCredential` when
   wolfSSH asked for `PASSWORD` (or vice versa), control falls through
   to `context.dart:238` and returns `fill.outcome.code` without
   filling any credential. wolfSSH would proceed with an empty/default
   credential field. Honest behaviour depends on wolfSSH internals;
   safer-by-default would be an explicit `return FAILURE` for the
   mismatch case. Leaning: leave the code, add a one-line comment so
   the intent is documented. Local ref: `context.dart:201-202,
   216-217, 238` —
   [permalink](https://github.com/j4qfrost/wolfssh/blob/9e923177a66b38baf562e1a96d4eefedc40ecd06/dart/lib/src/context.dart#L201-L238).

3. **No `NativeFinalizer` on `WOLFSSH_CTX*`** — already documented in
   SECURITY.md §3 as a memory leak (not a security regression) if
   callers forget `dispose()`. Recording here for completeness.

---

## Entry 03 — User-auth types (`lib/src/auth/user_auth.dart`)

**Threat model.** This file defines the typed API that callers use to
return auth results. The danger class is well-known
(CVE-2018-10933 in libssh: a misplaced `MSG_USERAUTH_SUCCESS` from
server logic into client-success logic). Our wrapper's defense is
**typed enum mediation**: callers cannot return raw ints, only
`UserAuthOutcome` enum values whose `.code` fields are bound to the
wolfSSH constants. The trampoline then coerces `enum → int` rather
than letting Dart code return arbitrary integers.

### Calibrated table

| Item | Weight | Local ref | Permalink |
|---|---|---|---|
| `UserCredential` is a `sealed` class | Real defense — limits the credential type set the trampoline must dispatch on; new types must be added intentionally | `user_auth.dart:7` | [L7](https://github.com/j4qfrost/wolfssh/blob/9e923177a66b38baf562e1a96d4eefedc40ecd06/dart/lib/src/auth/user_auth.dart#L7) |
| `PasswordCredential` field is `Uint8List` (not `String`) at the wire level | Real hygiene — Strings are immutable and can't be zeroed; bytes can | `user_auth.dart:13-20` | [L13-L20](https://github.com/j4qfrost/wolfssh/blob/9e923177a66b38baf562e1a96d4eefedc40ecd06/dart/lib/src/auth/user_auth.dart#L13-L20) |
| `UserAuthOutcome` enum binds Dart values to `WOLFSSH_USERAUTH_*` constants | **Real defense — the load-bearing defense for this file.** Mediates int-return; pinned by `test/cve_user_auth_bypass_test.dart`. | `user_auth.dart:66-75` | [L66-L75](https://github.com/j4qfrost/wolfssh/blob/9e923177a66b38baf562e1a96d4eefedc40ecd06/dart/lib/src/auth/user_auth.dart#L66-L75) |
| Abstract `fill(int authType) → UserAuthFill` (non-nullable return) | Real defense — strategy cannot return null | `user_auth.dart:89` | [L89](https://github.com/j4qfrost/wolfssh/blob/9e923177a66b38baf562e1a96d4eefedc40ecd06/dart/lib/src/auth/user_auth.dart#L89) |
| `UserAuthFill.decline({outcome = UserAuthOutcome.failure})` — **default is failure** | Real defense — pinned by `test/cve_user_auth_bypass_test.dart`. A decline never accidentally succeeds. | `user_auth.dart:118-119` | [L118-L119](https://github.com/j4qfrost/wolfssh/blob/9e923177a66b38baf562e1a96d4eefedc40ecd06/dart/lib/src/auth/user_auth.dart#L118-L119) |
| `UserAuthFill.password` defaults `outcome = success` | Real correctness — supplying a credential indicates intent to authenticate | `user_auth.dart:106` | [L106](https://github.com/j4qfrost/wolfssh/blob/9e923177a66b38baf562e1a96d4eefedc40ecd06/dart/lib/src/auth/user_auth.dart#L106) |
| `assert(credential is PasswordCredential)` in `UserAuthFill.password` | **Documentation only** — `assert` is a no-op in release. Real enforcement is the `is` check at `context.dart:202`. | `user_auth.dart:107, 114` | [L107](https://github.com/j4qfrost/wolfssh/blob/9e923177a66b38baf562e1a96d4eefedc40ecd06/dart/lib/src/auth/user_auth.dart#L107) |
| Built-in strategies decline unknown auth types | Real defense — `_PasswordStrategy` and `_PublicKeyStrategy` only fill on the matching `authType`; everything else routes through `decline()` whose default is failure | `user_auth.dart:132-138, 147-153` | [L125-L154](https://github.com/j4qfrost/wolfssh/blob/9e923177a66b38baf562e1a96d4eefedc40ecd06/dart/lib/src/auth/user_auth.dart#L125-L154) |
| `keyTypeBytes` memoization | Correctness — no security weight | `user_auth.dart:55-57` | [L55-L57](https://github.com/j4qfrost/wolfssh/blob/9e923177a66b38baf562e1a96d4eefedc40ecd06/dart/lib/src/auth/user_auth.dart#L55-L57) |

### Found gaps / followups for entry 03

1. **`assert` is debug-only.** The `UserAuthFill.password` and
   `.publicKey` factories use `assert(credential is X)` to enforce
   credential-type ↔ factory consistency. This is a no-op in
   `--release` Dart. It's *not* a vulnerability — the real check is
   the `is` test at the trampoline (`context.dart:202`, `:217`) — but
   a reviewer skimming this file shouldn't mistake the assert for
   runtime enforcement. Suggested: add a comment on the assert
   noting "debug-only; runtime enforcement is at context.dart:202".

2. **`PasswordCredential.fromString` retains String input by
   construction.** The caller-supplied `String password` is encoded to
   `Uint8List` but the original `String` remains in the caller's
   scope and the Dart string-interning pool (where applicable),
   neither of which we can scrub. Existing doc at `user_auth.dart:11-12`
   already advises against long-lived String storage. *Not a bug*,
   but worth one extra sentence in the doc.

3. **Strategy objects hold credentials for their full lifetime.**
   `_PasswordStrategy._password` and `_PublicKeyStrategy._key` are
   never zeroed because Dart objects can't be deterministically
   scrubbed. Same intrinsic-limitation note as (2). The mitigation is
   already in place: the *native* buffers (in `_NativeByteBuffer`)
   are zeroed at dispose. The Dart-side `Uint8List` lives until GC.

4. **`username` field on built-in strategies is dead in `fill()`.**
   Both `_PasswordStrategy.username` and `_PublicKeyStrategy.username`
   are set but never read by `fill()`. The actual SSH username goes
   through `WolfSshSession.setUsername`. Not a security issue, but the
   redundant field is misleading — a caller might assume changing it
   changes the wire username. Consider either: (a) document that it's
   advisory for caller bookkeeping, or (b) remove it and have callers
   pass username directly to the session. Out of scope for this
   review; recording.

### Cross-reference: C-glue helpers (`dart/native/wolfssh_dart_glue.c`)

Relevant to entries 02 + 03:

| Item | Weight | Local ref | Permalink |
|---|---|---|---|
| `wolfssh_dart_fill_password` NULL guard | Real defense — `WS_BAD_ARGUMENT` if `data` or `password` is NULL | `wolfssh_dart_glue.c:75-77` | [L75-L77](https://github.com/j4qfrost/wolfssh/blob/9e923177a66b38baf562e1a96d4eefedc40ecd06/dart/native/wolfssh_dart_glue.c#L75-L77) |
| `wolfssh_dart_fill_pubkey` NULL guard on all four pointers | Real defense | `wolfssh_dart_glue.c:100-103` | [L100-L103](https://github.com/j4qfrost/wolfssh/blob/9e923177a66b38baf562e1a96d4eefedc40ecd06/dart/native/wolfssh_dart_glue.c#L100-L103) |
| `const`-cast on `data->sf.password.password = (unsigned char*)password` | Documented — wolfSSH ABI is non-const but read-only; rationale at L78-79 | `wolfssh_dart_glue.c:78-80` | [L78-L80](https://github.com/j4qfrost/wolfssh/blob/9e923177a66b38baf562e1a96d4eefedc40ecd06/dart/native/wolfssh_dart_glue.c#L78-L80) |
| `hasSignature = 0` in `fill_pubkey` | Real correctness — wolfSSH must compute the signature itself | `wolfssh_dart_glue.c:114` | [L114](https://github.com/j4qfrost/wolfssh/blob/9e923177a66b38baf562e1a96d4eefedc40ecd06/dart/native/wolfssh_dart_glue.c#L114) |
| `passwordSz` NOT validated in C glue | **By design** — comment at L68-70 notes this is the Dart-side `checkBufferLen` helper's responsibility. Audit on every binding extension to confirm `checkBufferLen` is called before reaching this C function. | `wolfssh_dart_glue.c:68-70` | [L68-L70](https://github.com/j4qfrost/wolfssh/blob/9e923177a66b38baf562e1a96d4eefedc40ecd06/dart/native/wolfssh_dart_glue.c#L68-L70) |

### Open question for entry 03

The `assert` items in (1) above — do we want to **upgrade them to
runtime checks** (throw on type mismatch from the factory itself)?
Arguments for: deterministic behaviour in release builds; failure at
the construction site, not three frames deep in the trampoline.
Arguments against: redundant with `is`-check at the trampoline; would
make `UserAuthFill.password(somethingDynamic)` throw at construction
where today it just fails at fill time.

---

## Entry 04 — Error types & FFI buffer-length boundary (`lib/src/error.dart`)

**Threat model.** Two distinct hazards in one file:

  1. **Integer truncation at the Dart `int` ↔ wolfSSH `word32`
     boundary.** Dart `int` is 64-bit signed; wolfSSH's API uses
     `word32` (uint32). A length of `0x100000000` from Dart truncates
     to `0` on the C side, so `wolfSSH_stream_send(ssh, data, 0)`
     returns success without sending anything, and the caller thinks
     `4 GiB+1` bytes were processed. A negative `int` cast to `word32`
     becomes a huge positive value (e.g. `-1` → `0xFFFFFFFF`).
  2. **I/O return-code confusion.** wolfSSH's stream I/O can return a
     positive byte count, `WS_WANT_READ`/`WS_WANT_WRITE`, `WS_EOF`,
     `WS_CHANNEL_CLOSED`, or a hard error. A caller that treats the
     `WS_WANT_READ` constant as a negative byte count or "any negative
     is an error" gets data-loss or hangs.

**Defense shape.** `checkBufferLen` for (1); `IoStatus` sealed
hierarchy + `interpretIoReturn` for (2); `WolfSshException` +
`throwWolfSshError` for hard errors.

### Calibrated table

| Item | Weight | Local ref | Permalink |
|---|---|---|---|
| `checkBufferLen` rejects `len < 0` and `len > 0xFFFFFFFF` | **Real defense** — pinned by `test/cve_ffi_buffer_overflow_test.dart`. Prevents the truncation class at the FFI boundary. | `error.dart:71-80` | [L71-L80](https://github.com/j4qfrost/wolfssh/blob/9e923177a66b38baf562e1a96d4eefedc40ecd06/dart/lib/src/error.dart#L71-L80) |
| `checkBufferLen` returns the validated value (not just throws) | Real correctness — encourages `final len = checkBufferLen(...)` idiom so the validated value is what gets passed to the C call | `error.dart:79` | [L79](https://github.com/j4qfrost/wolfssh/blob/9e923177a66b38baf562e1a96d4eefedc40ecd06/dart/lib/src/error.dart#L79) |
| `IoStatus` is `sealed` (forces exhaustive switch at callers) | Real defense — prevents the "negative byte count" confusion class for `WS_WANT_READ` | `error.dart:43-66` | [L43-L66](https://github.com/j4qfrost/wolfssh/blob/9e923177a66b38baf562e1a96d4eefedc40ecd06/dart/lib/src/error.dart#L43-L66) |
| `interpretIoReturn` default case `throw StateError` for unknown codes | Real defense — fail-loud on unknown wolfSSH return codes (e.g. after a wolfSSH bump that adds a new code) | `error.dart:96-98` | [L96-L98](https://github.com/j4qfrost/wolfssh/blob/9e923177a66b38baf562e1a96d4eefedc40ecd06/dart/lib/src/error.dart#L96-L98) |
| `throwWolfSshError` NULL-checks `errorToName` return before `.toDartString()` | Real correctness — wolfSSH's `wolfSSH_ErrorToName` returns NULL on unknown codes; without the check, `nullptr.cast<Utf8>().toDartString()` crashes | `error.dart:38` | [L38](https://github.com/j4qfrost/wolfssh/blob/9e923177a66b38baf562e1a96d4eefedc40ecd06/dart/lib/src/error.dart#L38) |
| `throwWolfSshError` returns `Never` | Correctness — compiler refuses code after the throw | `error.dart:36` | [L36](https://github.com/j4qfrost/wolfssh/blob/9e923177a66b38baf562e1a96d4eefedc40ecd06/dart/lib/src/error.dart#L36) |
| `WolfSshException.toString` includes code, name, optional context | Diagnostic. No security weight. `name` is a wolfSSH string-literal table return, not attacker-controlled. | `error.dart:26-30` | [L26-L30](https://github.com/j4qfrost/wolfssh/blob/9e923177a66b38baf562e1a96d4eefedc40ecd06/dart/lib/src/error.dart#L26-L30) |
| `interpretIoReturn` maps `WS_EOF` and `WS_CHANNEL_CLOSED` both to `IoEof` | Real correctness — callers don't need to distinguish "peer closed channel" vs "peer hung up at TCP layer" for the EOF semantic | `error.dart:93-95` | [L93-L95](https://github.com/j4qfrost/wolfssh/blob/9e923177a66b38baf562e1a96d4eefedc40ecd06/dart/lib/src/error.dart#L93-L95) |

### Found gaps / followups for entry 04

1. **Found gap (medium severity, policy violation): `checkBufferLen`
   is not routed at the user-auth fill helpers.** SECURITY.md §4
   policy says "every `(byte*, word32)` API is gated by
   `checkBufferLen`". The two streaming callsites comply
   (`session.dart:79, 98`). The four user-auth fill callsites do
   not:

     * `context.dart:208` — `final size = cred.password.length;` passed
       to `dartFillPassword` as `Uint32`
     * `context.dart:229-231` — `keyTypeBytes.length`,
       `cred.publicKey.length`, `cred.privateKey.length` all passed to
       `dartFillPubkey` as `Uint32`

   Permalinks:
   [context.dart:208-210](https://github.com/j4qfrost/wolfssh/blob/9e923177a66b38baf562e1a96d4eefedc40ecd06/dart/lib/src/context.dart#L208-L210),
   [context.dart:227-232](https://github.com/j4qfrost/wolfssh/blob/9e923177a66b38baf562e1a96d4eefedc40ecd06/dart/lib/src/context.dart#L227-L232).

   Real-world exploitability is low — a Uint8List with > 4 GiB of
   password/key bytes is implausible — but the policy is the policy
   and the fix is one line per length. Until fixed, the cve test at
   `test/cve_ffi_buffer_overflow_test.dart` is **incomplete coverage**
   for §4: it pins the helper but doesn't exercise the auth path.

   **Recommended fix.** Wrap each `.length` with `checkBufferLen`:
   ```dart
   final size = checkBufferLen(cred.password.length,
                               where: 'PasswordCredential.password.length');
   ```
   and similarly for the three pubkey lengths.

2. **Misleading comment: "constant-time-ish" at `error.dart:68`.**
   Buffer lengths aren't secrets; constant-time isn't a property this
   function needs to maintain. The "ish" is honestly conceding that
   Dart's int representation isn't strictly constant-time, but the
   framing invites a future reviewer to ask whether timing
   side-channels matter. They don't. Suggest renaming the comment to
   just "Length validator at the FFI boundary".
   [L68](https://github.com/j4qfrost/wolfssh/blob/9e923177a66b38baf562e1a96d4eefedc40ecd06/dart/lib/src/error.dart#L68)

3. **`setFd` (`session.dart:54`) passes a Dart `int` file descriptor
   to a C `int` parameter without `checkBufferLen`.** This is *not* a
   word32 boundary (it's `int`, typically 32-bit signed on POSIX),
   and file descriptors are OS-bounded to well below INT_MAX. Calling
   it out so future reviewers don't think it's an oversight: it's
   intentionally not gated because the truncation class doesn't apply
   to fd values. If we ever support APIs that take Dart `int` ↔ C
   `int` for *non*-fd values where truncation matters, consider a
   separate `checkIntArg` helper.

### Action items from entry 04

  * **[planned]** Route the four auth-fill length args through
    `checkBufferLen`. One commit, four lines.
  * **[planned]** Extend `test/cve_ffi_buffer_overflow_test.dart` to
    cover the auth path so §4 coverage is genuine.
  * **[optional]** Reword the "constant-time-ish" comment.

---

## Entry 05 — Session lifecycle & stream I/O (`lib/src/session.dart`)

**Threat model.** Three failure classes:

  1. **Use-after-free of `WOLFSSH*`** — calling `writeOnce` /
     `readOnce` / `writeAll` after `dispose`, or after the parent
     context has been disposed. Without a guard, this dereferences a
     freed pointer.
  2. **Memory leak on partial-connect failure** — `connect` allocates
     the `WOLFSSH*` and a Utf8-encoded username buffer; any throw
     between those allocations and the successful return must free
     both.
  3. **Out-of-bounds write into caller's read destination** — if
     `readOnce` copied `maxBytes` instead of `bytes actually read`,
     the tail of an under-filled buffer would leak uninitialized
     `malloc` bytes into the caller's `Uint8List`.

Stream I/O on top of `WolfSshSession` is also where most of the
`IoStatus`-class confusion (entry 04) is actually consumed; the
classifier here intentionally diverges from `interpretIoReturn` to
call `wolfSSH_get_error` on hard errors.

### Calibrated table

| Item | Weight | Local ref | Permalink |
|---|---|---|---|
| `connect` requires non-null context/fd/username and NULL-checks `sshNew` | Real defense (API) + real correctness | `session.dart:25-34` | [L25-L34](https://github.com/j4qfrost/wolfssh/blob/9e923177a66b38baf562e1a96d4eefedc40ecd06/dart/lib/src/session.dart#L25-L34) |
| Passes `context.nativeHandle` (not session ptr) as the callback userdata | Real defense — matches the trampolines' `lookupContextByAddress`; documented in SECURITY.md §8 | `session.dart:39-41` | [L39-L41](https://github.com/j4qfrost/wolfssh/blob/9e923177a66b38baf562e1a96d4eefedc40ecd06/dart/lib/src/session.dart#L39-L41) |
| `setUserAuthCtx` + `setPublicKeyCheckCtx` called before any handshake step | Real defense — without these the trampolines would be invoked with NULL userdata, lookup would miss, callbacks fail-closed (still safe, but every session would fail) | `session.dart:40-41` | [L40-L41](https://github.com/j4qfrost/wolfssh/blob/9e923177a66b38baf562e1a96d4eefedc40ecd06/dart/lib/src/session.dart#L40-L41) |
| `try/finally` around `usernameC` so the Utf8 buffer is freed even on `setUsername` failure | Real correctness — no memory leak on failed-handshake throw paths | `session.dart:43-52` | [L43-L52](https://github.com/j4qfrost/wolfssh/blob/9e923177a66b38baf562e1a96d4eefedc40ecd06/dart/lib/src/session.dart#L43-L52) |
| Every error branch in `connect` calls `sshFree(ssh)` before throwing | Real correctness — no `WOLFSSH*` leak | `session.dart:47, 56, 63` | [L47](https://github.com/j4qfrost/wolfssh/blob/9e923177a66b38baf562e1a96d4eefedc40ecd06/dart/lib/src/session.dart#L47), [L56](https://github.com/j4qfrost/wolfssh/blob/9e923177a66b38baf562e1a96d4eefedc40ecd06/dart/lib/src/session.dart#L56), [L63](https://github.com/j4qfrost/wolfssh/blob/9e923177a66b38baf562e1a96d4eefedc40ecd06/dart/lib/src/session.dart#L63) |
| `connect` failure path calls `getError(ssh)` for the real wolfSSH error code (not the bare `rc`) | Real correctness — wolfSSH's outer return is often `WS_FATAL_ERROR`; the real reason is inside `getError` | `session.dart:62` | [L62](https://github.com/j4qfrost/wolfssh/blob/9e923177a66b38baf562e1a96d4eefedc40ecd06/dart/lib/src/session.dart#L62) |
| `WolfSshSession.context` field holds the parent context by strong reference | Real defense — keeps the context wrapper (and its NativeCallables) alive at least as long as the session | `session.dart:70` | [L70](https://github.com/j4qfrost/wolfssh/blob/9e923177a66b38baf562e1a96d4eefedc40ecd06/dart/lib/src/session.dart#L70) |
| `_ensureOpen` rejects use after dispose / NULL `_ssh` | Real defense — prevents UAF on session methods | `session.dart:155-159` | [L155-L159](https://github.com/j4qfrost/wolfssh/blob/9e923177a66b38baf562e1a96d4eefedc40ecd06/dart/lib/src/session.dart#L155-L159) |
| `_ssh = nullptr` after `sshFree` in `dispose` | Real defense — `_ensureOpen`'s NULL check actually fires | `session.dart:170` | [L170](https://github.com/j4qfrost/wolfssh/blob/9e923177a66b38baf562e1a96d4eefedc40ecd06/dart/lib/src/session.dart#L170) |
| `writeOnce` malloc + memcpy of caller's `Uint8List` (instead of passing Dart-backed pointer) | Real defense — pinned native allocation can't be moved by Dart GC during the FFI call | `session.dart:80-87` | [L80-L87](https://github.com/j4qfrost/wolfssh/blob/9e923177a66b38baf562e1a96d4eefedc40ecd06/dart/lib/src/session.dart#L80-L87) |
| `readOnce` pre-checks `into.length >= maxBytes` | Real defense — without this, `into.setRange(0, bytes, ...)` could OOB-write | `session.dart:94-97` | [L94-L97](https://github.com/j4qfrost/wolfssh/blob/9e923177a66b38baf562e1a96d4eefedc40ecd06/dart/lib/src/session.dart#L94-L97) |
| `readOnce` copies `status.bytes` (actual), not `maxBytes` (requested), back to `into` | **Real defense — uninitialized-byte leak prevention.** If wolfSSH reports `bytes < maxBytes`, the tail of `buf` is uninitialized `malloc` memory; copying `maxBytes` would expose process memory to the caller. | `session.dart:103-104` | [L103-L104](https://github.com/j4qfrost/wolfssh/blob/9e923177a66b38baf562e1a96d4eefedc40ecd06/dart/lib/src/session.dart#L103-L104) |
| `readOnce` `try/finally` frees `buf` even on classification throw | Real correctness | `session.dart:99-109` | [L99-L109](https://github.com/j4qfrost/wolfssh/blob/9e923177a66b38baf562e1a96d4eefedc40ecd06/dart/lib/src/session.dart#L99-L109) |
| `writeAll` throws on mid-stream `IoEof` instead of silently returning short | Real correctness — caller learns about partial flush | `session.dart:132-134` | [L132-L134](https://github.com/j4qfrost/wolfssh/blob/9e923177a66b38baf562e1a96d4eefedc40ecd06/dart/lib/src/session.dart#L132-L134) |
| `_classify` calls `getError(_ssh)` on hard-error default | Real correctness — surfaces wolfSSH's real reason, not the wrapper rc | `session.dart:149-152` | [L149-L152](https://github.com/j4qfrost/wolfssh/blob/9e923177a66b38baf562e1a96d4eefedc40ecd06/dart/lib/src/session.dart#L149-L152) |
| `dispose` is idempotent (`if (_disposed) return`) | Real correctness — caller `try/finally` patterns can double-dispose without UB | `session.dart:163` | [L163](https://github.com/j4qfrost/wolfssh/blob/9e923177a66b38baf562e1a96d4eefedc40ecd06/dart/lib/src/session.dart#L163) |
| `dispose` calls `shutdown` before `sshFree` | Real hygiene — clean SSH disconnect; comment notes return is ignored | `session.dart:168-169` | [L168-L169](https://github.com/j4qfrost/wolfssh/blob/9e923177a66b38baf562e1a96d4eefedc40ecd06/dart/lib/src/session.dart#L168-L169) |

### Found gaps / followups for entry 05

1. **No protection against `context.dispose()` while a session is
   alive.** *Found gap, robustness.* The session holds the context by
   strong Dart reference (`session.dart:70`), so the wrapper object
   stays alive — but the *native* `WOLFSSH_CTX*` is freed as soon as
   the user calls `context.dispose()`. Subsequent session I/O
   dereferences a freed CTX. This is documented in SECURITY.md §3
   ("do not dispose the context while sessions are open") but not
   enforced. Two options:
     * (a) Track open sessions in `WolfSshContext` and refuse
       `dispose()` (or sessions decrement a count on their own
       `dispose()`).
     * (b) Leave the contract; loud doc + a `StateError` from a
       sentinel inside session methods if `context._disposed`.

   Not network-exploitable. Recording.
   [context.dart:87-101](https://github.com/j4qfrost/wolfssh/blob/9e923177a66b38baf562e1a96d4eefedc40ecd06/dart/lib/src/context.dart#L87-L101),
   [session.dart:70](https://github.com/j4qfrost/wolfssh/blob/9e923177a66b38baf562e1a96d4eefedc40ecd06/dart/lib/src/session.dart#L70).

2. **NUL byte in `username` String is silently truncated.** *Found
   gap, low.* `username.toNativeUtf8()` (`session.dart:43`) encodes
   the String to UTF-8 + final NUL. If the caller passes
   `"alice\x00sudo"`, the buffer has the NUL in the middle, and
   `wolfSSH_SetUsername` uses `strlen`-semantics → treats the
   username as `"alice"`. Not network-exploitable (we don't accept
   usernames from the network), but a Dart-side caller bug becomes a
   silent semantic change. Suggested: validate
   `!username.codeUnits.contains(0)` before encoding, throw
   `ArgumentError` if it does.
   [session.dart:43](https://github.com/j4qfrost/wolfssh/blob/9e923177a66b38baf562e1a96d4eefedc40ecd06/dart/lib/src/session.dart#L43).

3. **`writeAll` busy-spins on `WS_WANT_WRITE` / `WS_WANT_READ`.**
   *Performance, not security.* The doc-comment at
   `session.dart:114-115` already concedes production callers should
   integrate with their selector. Recording for the follow-up
   "high-level stream wrapper" work.
   [session.dart:116-137](https://github.com/j4qfrost/wolfssh/blob/9e923177a66b38baf562e1a96d4eefedc40ecd06/dart/lib/src/session.dart#L116-L137).

4. **`_classify` (`session.dart:139-153`) vs `interpretIoReturn`
   (`error.dart:84-100`) overlap.** *Code smell, not a bug.* The two
   differ intentionally: `_classify` calls `getError` and throws a
   `WolfSshException` on hard errors; `interpretIoReturn` throws
   `StateError` on unknown codes. Worth one-line comment noting the
   divergence so a future refactor doesn't accidentally collapse
   them. No security weight.

5. **No `NativeFinalizer`** for `WOLFSSH*`. Already covered in
   SECURITY.md §3 — same reason as `WOLFSSH_CTX*`. Recording for
   audit completeness.

### Action items from entry 05

  * **[planned]** Decide between (a) refcount sessions in context vs
    (b) cross-check `context._disposed` flag at session-method
    entry. (b) is one line and cheap; suggest it.
  * **[planned]** NUL-byte validation in `username`.
  * **[optional]** Cross-reference comment between `_classify` and
    `interpretIoReturn`.

---

## Pending entries

Sections not yet reviewed:

  * Entry 06 — Library loading (`lib/src/library.dart`): version-check
    against `wolfssh_dart_version_hex`, `.so`/`.dylib`/`.dll` search
    path.
  * Entry 07 — CVE regression tests (`test/cve_*`): assert they
    actually trip the conditions they claim.

---

## Process notes

  * Each entry has a calibration legend applied. If a future reviewer
    upgrades a "Modest defense" item to "Real defense" they should
    record the threat model that makes it load-bearing — otherwise
    the table inflates again.
  * Entry 01's self-correction section is precedent: when a draft
    over-claims, leave the correction in the log rather than rewriting
    silently, so the calibration discipline is visible.

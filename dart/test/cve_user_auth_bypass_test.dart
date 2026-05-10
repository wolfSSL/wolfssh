// PoC tests for user-auth fail-closed semantics.
//
// There is no public CVE specific to this binding's user-auth wiring
// at the time of writing, but the class of bug is well-documented in
// SSH server/client history (e.g. CVE-2018-15473 username-enumeration,
// CVE-2018-10933 libssh server auth bypass). Both share a common
// failure mode: a callback returning the wrong integer constant so
// that a *failed* auth attempt is reported as a *success* by mistake.
//
// The Dart binding defends against this by:
//
//   * Sealing every callback return through the [UserAuthOutcome]
//     enum, whose .code values are pinned to the wolfSSH
//     WOLFSSH_USERAUTH_* native constants.
//   * Wrapping the native callback in a fail-closed trampoline
//     (lib/src/context.dart::_userAuthTrampoline) whose
//     `exceptionalReturn` is WOLFSSH_USERAUTH_FAILURE — so an
//     uncaught Dart exception becomes "auth failed" not "auth ok".
//
// The tests below exercise the enum contract directly so any
// renumbering or aliasing in either layer triggers a red light before
// it can ship.

import 'package:test/test.dart';
import 'package:wolfssh/src/auth/user_auth.dart';
import 'package:wolfssh/src/bindings/wolfssh.g.dart' as raw;
import 'package:wolfssh/wolfssh.dart';

void main() {
  group('user-auth: UserAuthOutcome ↔ wolfSSH native constants', () {
    // The most catastrophic regression class: a non-success outcome
    // accidentally mapped to WOLFSSH_USERAUTH_SUCCESS. Each negative
    // outcome below is asserted to be DIFFERENT from SUCCESS.

    test('PoC: UserAuthOutcome.success maps to WOLFSSH_USERAUTH_SUCCESS', () {
      expect(UserAuthOutcome.success.code, raw.WOLFSSH_USERAUTH_SUCCESS);
    });

    test('PoC: failure outcome is NOT aliased to success', () {
      expect(UserAuthOutcome.failure.code,
          isNot(equals(raw.WOLFSSH_USERAUTH_SUCCESS)),
          reason: 'failure must be distinct from success — aliasing here is '
              'a silent auth-bypass regression');
      expect(UserAuthOutcome.failure.code, raw.WOLFSSH_USERAUTH_FAILURE);
    });

    test('PoC: rejected outcome is NOT aliased to success', () {
      expect(UserAuthOutcome.rejected.code,
          isNot(equals(raw.WOLFSSH_USERAUTH_SUCCESS)));
      expect(UserAuthOutcome.rejected.code, raw.WOLFSSH_USERAUTH_REJECTED);
    });

    test('PoC: invalidUser outcome is NOT aliased to success', () {
      expect(UserAuthOutcome.invalidUser.code,
          isNot(equals(raw.WOLFSSH_USERAUTH_SUCCESS)));
      expect(UserAuthOutcome.invalidUser.code,
          raw.WOLFSSH_USERAUTH_INVALID_USER);
    });

    test('PoC: invalidPassword outcome is NOT aliased to success', () {
      expect(UserAuthOutcome.invalidPassword.code,
          isNot(equals(raw.WOLFSSH_USERAUTH_SUCCESS)));
      expect(UserAuthOutcome.invalidPassword.code,
          raw.WOLFSSH_USERAUTH_INVALID_PASSWORD);
    });

    test('PoC: every enum variant is distinct (no two outcomes share a code)',
        () {
      // Defence-in-depth: even if a constant changed value upstream
      // and we forgot to bump the binding, *two* outcomes pointing at
      // the same int would still be a red flag (one strategy result
      // would silently impersonate another).
      final codes = UserAuthOutcome.values.map((v) => v.code).toList();
      final unique = codes.toSet();
      expect(unique.length, codes.length,
          reason: 'duplicate codes across UserAuthOutcome variants: $codes');
    });
  });

  group('user-auth: UserAuthFill defaults', () {
    test('PoC: decline() defaults to failure (never to success)', () {
      // A future contributor refactoring UserAuthFill.decline could
      // mistakenly default to UserAuthOutcome.success. That would
      // silently turn "I don't know how to answer this prompt" into
      // "auth ok".
      final fill = UserAuthFill.decline();
      expect(fill.outcome.code,
          isNot(equals(raw.WOLFSSH_USERAUTH_SUCCESS)),
          reason: 'declining a prompt must never report success');
      expect(fill.credential, isNull);
    });

    test('PoC: password fill outcome defaults to success', () {
      // Negative control: when the strategy DOES supply a password,
      // the default outcome should be success — otherwise legitimate
      // logins fail closed in a different (unintended) way.
      final fill = UserAuthFill.password(PasswordCredential.fromString('x'));
      expect(fill.outcome.code, raw.WOLFSSH_USERAUTH_SUCCESS);
    });
  });

  group('user-auth: UserAuthStrategy.password', () {
    test('PoC: returns password fill ONLY for WOLFSSH_USERAUTH_PASSWORD', () {
      final strategy = UserAuthStrategy.password('alice', 'hunter2');

      final passFill = strategy.fill(raw.WOLFSSH_USERAUTH_PASSWORD);
      expect(passFill.credential, isA<PasswordCredential>(),
          reason: 'password prompt must receive a credential');
      expect(passFill.outcome.code, raw.WOLFSSH_USERAUTH_SUCCESS);
    });

    test('PoC: declines unknown auth types — does NOT impersonate success',
        () {
      final strategy = UserAuthStrategy.password('alice', 'hunter2');

      // Pretend the server requested keyboard-interactive (a constant
      // the password strategy cannot satisfy). It must decline, never
      // accidentally claim success with a null credential.
      final unknownAuthType = raw.WOLFSSH_USERAUTH_PASSWORD + 999;
      final fill = strategy.fill(unknownAuthType);
      expect(fill.credential, isNull);
      expect(fill.outcome.code,
          isNot(equals(raw.WOLFSSH_USERAUTH_SUCCESS)),
          reason: 'unknown auth type must not be answered with success');
    });
  });
}

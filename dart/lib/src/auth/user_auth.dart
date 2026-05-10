import 'dart:convert';
import 'dart:typed_data';

import '../bindings/wolfssh.g.dart' as raw;

/// Credential the client offers when the server requests user-auth.
sealed class UserCredential {
  const UserCredential();
}

/// Plain-password authentication. Avoid storing the password in long-
/// lived strings; pass a fresh [Uint8List] when possible.
class PasswordCredential extends UserCredential {
  PasswordCredential(this.password);

  PasswordCredential.fromString(String password)
      : password = Uint8List.fromList(utf8.encode(password));

  final Uint8List password;
}

/// Public-key authentication.
///
/// [keyType] is the SSH algorithm name, e.g. `ssh-rsa`, `ssh-ed25519`,
/// `ecdsa-sha2-nistp256`. wolfSSH uses it to label the USERAUTH_REQUEST
/// and to pick the matching signature algorithm.
///
/// [publicKey] and [privateKey] are the raw key bytes in the format
/// wolfSSH expects (PEM, DER, or OpenSSH wire format depending on how
/// the calling configuration was built — match what
/// `wolfSSH_ReadKey_buffer` would accept).
///
/// SECURITY: the binding holds these bytes in long-lived native buffers
/// for the lifetime of the [WolfSshContext] and zeroes them on dispose.
/// Callers should still keep the Dart `Uint8List`s out of long-lived
/// scopes — the canonical pattern is `read → construct credential →
/// pass to context → discard local references → dispose context`.
class PublicKeyCredential extends UserCredential {
  PublicKeyCredential({
    required this.keyType,
    required this.publicKey,
    required this.privateKey,
  });

  /// SSH algorithm identifier, e.g. `ssh-rsa`, `ssh-ed25519`.
  final String keyType;

  /// Public key blob, in the format wolfSSH was built to accept.
  final Uint8List publicKey;

  /// Private key blob, in the format wolfSSH was built to accept.
  final Uint8List privateKey;

  /// UTF-8 encoding of [keyType], cached for the binding.
  Uint8List get keyTypeBytes =>
      _keyTypeBytes ??= Uint8List.fromList(utf8.encode(keyType));
  Uint8List? _keyTypeBytes;
}

/// Result of a single user-auth callback invocation.
///
/// SECURITY: the integer values here mirror the wolfSSH `WS_UserAuthResults`
/// enum exactly. Returning the wrong code from the native callback can
/// silently turn a failed auth into a success, so the wrapper coerces
/// from this sealed type rather than letting callers return raw ints.
enum UserAuthOutcome {
  success(raw.WOLFSSH_USERAUTH_SUCCESS),
  failure(raw.WOLFSSH_USERAUTH_FAILURE),
  invalidUser(raw.WOLFSSH_USERAUTH_INVALID_USER),
  invalidPassword(raw.WOLFSSH_USERAUTH_INVALID_PASSWORD),
  rejected(raw.WOLFSSH_USERAUTH_REJECTED);

  const UserAuthOutcome(this.code);
  final int code;
}

/// Strategy for satisfying user-auth requests from the server.
///
/// The simple constructor [UserAuthStrategy.password] covers the common
/// case. Callers needing per-prompt logic can implement [UserAuthStrategy]
/// directly.
abstract class UserAuthStrategy {
  const UserAuthStrategy();

  /// Called by the binding for each user-auth attempt. [authType] is one
  /// of the `WOLFSSH_USERAUTH_*` constants from
  /// [raw.WOLFSSH_USERAUTH_PASSWORD] etc. Returning anything other than
  /// [UserAuthOutcome.success] aborts authentication.
  UserAuthFill fill(int authType);

  factory UserAuthStrategy.password(String username, String password) =
      _PasswordStrategy;

  /// A strategy that always offers the same public-key credential.
  factory UserAuthStrategy.publicKey(
    String username,
    PublicKeyCredential credential,
  ) = _PublicKeyStrategy;
}

/// What the strategy wants the binding to do for one prompt.
class UserAuthFill {
  /// Provide a password credential to wolfSSH and return [outcome] from
  /// the callback. The default outcome is `success` because for the
  /// password flow the strategy supplying a password indicates intent.
  UserAuthFill.password(this.credential, {this.outcome = UserAuthOutcome.success})
      : assert(credential is PasswordCredential);

  /// Provide a public-key credential to wolfSSH. Same outcome semantics
  /// as [UserAuthFill.password] — defaulting to `success` indicates
  /// the strategy is committing to this key.
  UserAuthFill.publicKey(this.credential,
      {this.outcome = UserAuthOutcome.success})
      : assert(credential is PublicKeyCredential);

  /// Decline the prompt without filling any credential. Use this when
  /// the server requests an auth type the strategy doesn't support.
  UserAuthFill.decline({this.outcome = UserAuthOutcome.failure})
      : credential = null;

  final UserCredential? credential;
  final UserAuthOutcome outcome;
}

class _PasswordStrategy extends UserAuthStrategy {
  _PasswordStrategy(this.username, String password)
      : _password = PasswordCredential.fromString(password);

  final String username;
  final PasswordCredential _password;

  @override
  UserAuthFill fill(int authType) {
    if (authType == raw.WOLFSSH_USERAUTH_PASSWORD) {
      return UserAuthFill.password(_password);
    }
    return UserAuthFill.decline();
  }
}

class _PublicKeyStrategy extends UserAuthStrategy {
  _PublicKeyStrategy(this.username, this._key);

  final String username;
  final PublicKeyCredential _key;

  @override
  UserAuthFill fill(int authType) {
    if (authType == raw.WOLFSSH_USERAUTH_PUBLICKEY) {
      return UserAuthFill.publicKey(_key);
    }
    return UserAuthFill.decline();
  }
}

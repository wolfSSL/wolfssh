/// Dart FFI bindings for the wolfSSH client.
///
/// Top-level entry points:
///   * [WolfSshLibrary] - process-wide library handle (call [WolfSshLibrary.load]
///     once before use).
///   * [HostKeyVerifier] - SECURITY-CRITICAL: required server-key check.
///   * [UserAuthStrategy] - credential supplier for user auth.
///   * [WolfSshContext] - configuration container; one per fleet of
///     connections sharing the same crypto + auth settings.
///   * [WolfSshSession] - one live SSH connection.
library wolfssh;

export 'src/library.dart' show WolfSshLibrary;
export 'src/error.dart'
    show
        WolfSshException,
        IoStatus,
        IoCompleted,
        IoWantRead,
        IoWantWrite,
        IoEof;
export 'src/auth/host_key.dart' show HostKeyVerifier;
export 'src/auth/user_auth.dart'
    show UserAuthStrategy, UserCredential, PasswordCredential, UserAuthOutcome;
export 'src/context.dart' show WolfSshContext;
export 'src/session.dart' show WolfSshSession;

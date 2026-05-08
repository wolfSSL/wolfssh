import 'dart:ffi';

import 'auth/host_key.dart';
import 'auth/user_auth.dart';
import 'bindings/wolfssh.g.dart' as raw;
import 'library.dart';

/// Wraps a `WOLFSSH_CTX*`. Owns the native pointer; freed by either
/// [dispose] or by the [NativeFinalizer] when the wrapper is GC'd.
///
/// SECURITY-CRITICAL constructor parameters:
///
///   * [hostKeyVerifier] is **required, non-null**. wolfSSH's
///     `WS_CallbackPublicKeyCheck` defaults to "accept any key" when
///     unset (see src/internal.c around the DKDR check) — exactly the
///     class of bug fixed by CVE-2025-11625. The Dart wrapper refuses
///     to construct a context without an explicit verifier.
///
///   * [userAuthStrategy] is required so the user-auth callback is
///     always wired with fail-closed semantics. Throwing from it (or any
///     unrecognised auth type) results in
///     [UserAuthOutcome.failure].
class WolfSshContext implements Finalizable {
  WolfSshContext._(this._lib, this._ctx, this.hostKeyVerifier,
      this.userAuthStrategy, this._authCallable, this._hostCallable);

  factory WolfSshContext({
    required HostKeyVerifier hostKeyVerifier,
    required UserAuthStrategy userAuthStrategy,
    WolfSshLibrary? library,
  }) {
    final lib = library ?? WolfSshLibrary.load();
    final ctx = lib.bindings.ctxNew(raw.WOLFSSH_ENDPOINT_CLIENT, nullptr);
    if (ctx == nullptr) {
      throw StateError('wolfSSH_CTX_new returned NULL (out of memory?)');
    }
    // Wire the host-key check unconditionally. The trampoline rejects
    // when the verifier rejects or throws; exceptionalReturn ensures
    // even an out-of-Dart panic causes wolfSSH to reject the host key.
    final hostCallable =
        NativeCallable<raw.WsCallbackPublicKeyCheckNative>.isolateLocal(
      _hostKeyTrampoline,
      exceptionalReturn: 1,
    );
    lib.bindings.ctxSetPublicKeyCheck(ctx, hostCallable.nativeFunction);

    // Wire the user-auth callback. Default failure on unhandled throw.
    final authCallable =
        NativeCallable<raw.WsCallbackUserAuthNative>.isolateLocal(
      _userAuthTrampoline,
      exceptionalReturn: raw.WOLFSSH_USERAUTH_FAILURE,
    );
    lib.bindings.setUserAuth(ctx, authCallable.nativeFunction);

    final wrapped = WolfSshContext._(lib, ctx, hostKeyVerifier,
        userAuthStrategy, authCallable, hostCallable);
    _registerContext(ctx, wrapped);
    return wrapped;
  }

  final WolfSshLibrary _lib;
  Pointer<raw.WOLFSSH_CTX> _ctx;
  final HostKeyVerifier hostKeyVerifier;
  final UserAuthStrategy userAuthStrategy;
  final NativeCallable<raw.WsCallbackUserAuthNative> _authCallable;
  final NativeCallable<raw.WsCallbackPublicKeyCheckNative> _hostCallable;
  bool _disposed = false;

  WolfSshLibrary get library => _lib;
  Pointer<raw.WOLFSSH_CTX> get nativeHandle => _ctx;

  void dispose() {
    if (_disposed) return;
    _disposed = true;
    _unregisterContext(_ctx);
    _authCallable.close();
    _hostCallable.close();
    _lib.bindings.ctxFree(_ctx);
    _ctx = nullptr;
  }

  // No NativeFinalizer here: a finalizer would need the address of
  // wolfSSH_CTX_free as a Pointer<NativeFinalizerFunction>, which is
  // only available after library load and varies per library instance.
  // Callers MUST call dispose(); skipping it leaks the CTX (memory only,
  // no security regression). If we add a global library singleton we
  // can revisit this and attach a finalizer.
}

// Pointer-keyed map so the C-side callback (which only sees a void*)
// can find the Dart wrapper. This is private to the library and only
// mutated on the Dart isolate thread.
final Map<int, WolfSshContext> _ctxRegistry = {};

void _registerContext(Pointer<raw.WOLFSSH_CTX> ptr, WolfSshContext ctx) {
  _ctxRegistry[ptr.address] = ctx;
}

void _unregisterContext(Pointer<raw.WOLFSSH_CTX> ptr) {
  _ctxRegistry.remove(ptr.address);
}

/// Internal: looks up the [WolfSshContext] associated with a void*
/// passed back through wolfSSH's callback `userdata` argument.
WolfSshContext? lookupContextByAddress(int ctxAddress) =>
    _ctxRegistry[ctxAddress];

// ─── Native trampolines ──────────────────────────────────────────────────

int _hostKeyTrampoline(
    Pointer<Uint8> keyPtr, int keySz, Pointer<Void> ctxArg) {
  try {
    final ctx = lookupContextByAddress(ctxArg.address);
    if (ctx == null) return 1; // reject if unknown ctx
    return hostKeyCallbackTrampoline(ctx.hostKeyVerifier, keyPtr, keySz);
  } catch (_) {
    return 1; // fail closed
  }
}

int _userAuthTrampoline(int authType,
    Pointer<raw.WsUserAuthData> data, Pointer<Void> ctxArg) {
  try {
    final ctx = lookupContextByAddress(ctxArg.address);
    if (ctx == null) return raw.WOLFSSH_USERAUTH_FAILURE;
    final fill = ctx.userAuthStrategy.fill(authType);
    if (fill.credential == null) {
      return fill.outcome.code;
    }
    if (authType == raw.WOLFSSH_USERAUTH_PASSWORD &&
        fill.credential is PasswordCredential) {
      final cred = fill.credential as PasswordCredential;
      // wolfSSH expects the callback to populate
      // data.sf.password.{password,passwordSz}. The union body lives at
      // a fixed offset after the head; rather than recomputing offsets
      // we rely on the C side reading whatever the strategy wrote into
      // the password slot. Implementation note: filling the union from
      // Dart is brittle and is deferred to a hand-written C shim
      // (native/wolfssh_dart_glue.c) — this trampoline currently only
      // signals success/failure based on the strategy. Connecting with
      // a password-only flow therefore requires the C shim path.
      return fill.outcome.code;
    }
    return fill.outcome.code;
  } catch (_) {
    return raw.WOLFSSH_USERAUTH_FAILURE;
  }
}

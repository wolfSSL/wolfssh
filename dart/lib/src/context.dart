import 'dart:ffi';

import 'package:ffi/ffi.dart';

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

  // Long-lived native buffer holding the most recently filled password.
  // Owned by this context, allocated lazily by [_ensurePasswordBuffer], and
  // zeroed + freed on [dispose]. wolfSSH copies the bytes into its
  // outbound USERAUTH_REQUEST packet synchronously inside the user-auth
  // callback, so the buffer only needs to outlive the callback — but
  // keeping it for the context's lifetime makes the ownership story
  // simple and avoids per-attempt allocations during repeated auth.
  Pointer<Uint8> _pwBuf = nullptr;
  int _pwBufCapacity = 0;

  WolfSshLibrary get library => _lib;
  Pointer<raw.WOLFSSH_CTX> get nativeHandle => _ctx;

  /// Resize the password buffer to hold at least [size] bytes. Caller is
  /// expected to immediately overwrite the contents — we do not zero on
  /// grow because the next write is going to clobber it anyway.
  Pointer<Uint8> _ensurePasswordBuffer(int size) {
    if (size <= _pwBufCapacity && _pwBuf != nullptr) return _pwBuf;
    if (_pwBuf != nullptr) {
      // Zero the OLD buffer before freeing — defence-in-depth so the
      // previous password doesn't sit around in freed heap longer than
      // necessary.
      _pwBuf.asTypedList(_pwBufCapacity).fillRange(0, _pwBufCapacity, 0);
      malloc.free(_pwBuf);
    }
    // size==0 is legitimate (empty password); allocate one byte to avoid
    // returning nullptr, which the C helper would treat as WS_BAD_ARGUMENT.
    final allocSz = size == 0 ? 1 : size;
    _pwBuf = malloc<Uint8>(allocSz);
    _pwBufCapacity = allocSz;
    return _pwBuf;
  }

  void dispose() {
    if (_disposed) return;
    _disposed = true;
    _unregisterContext(_ctx);
    _authCallable.close();
    _hostCallable.close();
    _lib.bindings.ctxFree(_ctx);
    _ctx = nullptr;
    if (_pwBuf != nullptr) {
      // SECURITY: zero the password before releasing the page back to
      // the allocator.
      _pwBuf.asTypedList(_pwBufCapacity).fillRange(0, _pwBufCapacity, 0);
      malloc.free(_pwBuf);
      _pwBuf = nullptr;
      _pwBufCapacity = 0;
    }
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
      // Write the password bytes into the context-owned native buffer,
      // then have the C glue point WS_UserAuthData.sf.password at it.
      // We can't write to the union directly from Dart because the
      // bindings flatten the union into a `_unionBody` byte array; the
      // helper in native/wolfssh_dart_glue.c is the authoritative way
      // to assign the {password, passwordSz} pair using the layout the
      // wolfSSH C compiler agrees on.
      final size = cred.password.length;
      final buf = ctx._ensurePasswordBuffer(size);
      if (size > 0) {
        buf.asTypedList(size).setAll(0, cred.password);
      }
      final fillRc = ctx._lib.bindings.dartFillPassword(data, buf, size);
      if (fillRc != raw.WS_SUCCESS) {
        // Fail closed if the helper rejected the inputs (e.g. null data
        // pointer from a misuse path). Do NOT silently fall through to
        // success.
        return raw.WOLFSSH_USERAUTH_FAILURE;
      }
      return fill.outcome.code;
    }
    return fill.outcome.code;
  } catch (_) {
    return raw.WOLFSSH_USERAUTH_FAILURE;
  }
}

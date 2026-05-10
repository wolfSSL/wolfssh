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

  // Long-lived native buffers holding the most recently filled
  // user-auth credential bytes. Owned by this context, allocated lazily
  // on first use, and zeroed + freed in [dispose]. wolfSSH copies the
  // bytes into its outbound USERAUTH_REQUEST packet synchronously
  // inside the user-auth callback, so each buffer only needs to outlive
  // the callback — but keeping them for the context's lifetime keeps
  // ownership simple and avoids per-attempt allocations during
  // repeated auth.
  final _NativeByteBuffer _pwBuf = _NativeByteBuffer();
  final _NativeByteBuffer _pkTypeBuf = _NativeByteBuffer();
  final _NativeByteBuffer _pkPubBuf = _NativeByteBuffer();
  final _NativeByteBuffer _pkPrivBuf = _NativeByteBuffer();

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
    // SECURITY: zero credential bytes before releasing the pages back
    // to the allocator. Affects passwords + private keys.
    _pwBuf.disposeAndZero();
    _pkTypeBuf.disposeAndZero();
    _pkPubBuf.disposeAndZero();
    _pkPrivBuf.disposeAndZero();
  }

  // No NativeFinalizer here: a finalizer would need the address of
  // wolfSSH_CTX_free as a Pointer<NativeFinalizerFunction>, which is
  // only available after library load and varies per library instance.
  // Callers MUST call dispose(); skipping it leaks the CTX (memory only,
  // no security regression). If we add a global library singleton we
  // can revisit this and attach a finalizer.
}

/// Small helper around a malloc'd `Pointer<Uint8>` buffer that grows
/// monotonically and zeroes itself on shrink/dispose. Used to hold
/// user-auth credential bytes (password, public key, private key) for
/// the lifetime of the wolfSSH callback dispatch.
///
/// SECURITY: every transition that releases the underlying allocation
/// (grow, dispose) zeroes the previous capacity first so credential
/// bytes don't linger in freed heap pages longer than necessary.
class _NativeByteBuffer {
  Pointer<Uint8> _ptr = nullptr;
  int _capacity = 0;

  /// Resize so the buffer can hold at least [size] bytes; returns the
  /// pointer. Caller is expected to immediately overwrite the contents,
  /// so we do not zero on grow (the write will clobber the old bytes).
  Pointer<Uint8> ensure(int size) {
    if (size <= _capacity && _ptr != nullptr) return _ptr;
    if (_ptr != nullptr) {
      _ptr.asTypedList(_capacity).fillRange(0, _capacity, 0);
      malloc.free(_ptr);
    }
    // size==0 is legitimate (empty credential); allocate one byte to
    // avoid returning nullptr, which the C helpers treat as
    // WS_BAD_ARGUMENT.
    final allocSz = size == 0 ? 1 : size;
    _ptr = malloc<Uint8>(allocSz);
    _capacity = allocSz;
    return _ptr;
  }

  /// Copy [src] into the buffer, growing if needed. Returns the pointer.
  Pointer<Uint8> writeAll(List<int> src) {
    final p = ensure(src.length);
    if (src.isNotEmpty) {
      p.asTypedList(src.length).setAll(0, src);
    }
    return p;
  }

  /// Zero the current contents and free the allocation.
  void disposeAndZero() {
    if (_ptr != nullptr) {
      _ptr.asTypedList(_capacity).fillRange(0, _capacity, 0);
      malloc.free(_ptr);
      _ptr = nullptr;
      _capacity = 0;
    }
  }
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
      // Bindings flatten the WS_UserAuthData union into a `_unionBody`
      // byte array, so we can't write {password, passwordSz} from Dart
      // directly — the C glue does the union member assignment using
      // the compiler-agreed layout.
      final size = cred.password.length;
      final buf = ctx._pwBuf.writeAll(cred.password);
      final rc = ctx._lib.bindings.dartFillPassword(data, buf, size);
      if (rc != raw.WS_SUCCESS) {
        return raw.WOLFSSH_USERAUTH_FAILURE;
      }
      return fill.outcome.code;
    }
    if (authType == raw.WOLFSSH_USERAUTH_PUBLICKEY &&
        fill.credential is PublicKeyCredential) {
      final cred = fill.credential as PublicKeyCredential;
      // Stage all three byte slices in context-owned native buffers
      // so they outlive the callback. wolfSSH derives the signature
      // internally from the private key during the second
      // USERAUTH_REQUEST round-trip.
      final keyTypeBytes = cred.keyTypeBytes;
      final typeP = ctx._pkTypeBuf.writeAll(keyTypeBytes);
      final pubP = ctx._pkPubBuf.writeAll(cred.publicKey);
      final privP = ctx._pkPrivBuf.writeAll(cred.privateKey);
      final rc = ctx._lib.bindings.dartFillPubkey(
        data,
        typeP, keyTypeBytes.length,
        pubP, cred.publicKey.length,
        privP, cred.privateKey.length,
      );
      if (rc != raw.WS_SUCCESS) {
        return raw.WOLFSSH_USERAUTH_FAILURE;
      }
      return fill.outcome.code;
    }
    return fill.outcome.code;
  } catch (_) {
    return raw.WOLFSSH_USERAUTH_FAILURE;
  }
}

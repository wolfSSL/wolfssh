import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import 'bindings/wolfssh.g.dart' as raw;
import 'context.dart';
import 'error.dart';

/// A live wolfSSH session. Created by [WolfSshSession.connect].
///
/// Memory:
///   * Owns a `WOLFSSH*`; freed by [dispose] or via [NativeFinalizer].
///   * The session holds a reference to its parent [WolfSshContext]; do
///     not dispose the context while sessions are open.
class WolfSshSession implements Finalizable {
  WolfSshSession._(this.context, this._ssh);

  /// Establishes a session by performing the SSH handshake on an
  /// already-connected socket [fileDescriptor].
  ///
  /// On Linux/macOS/Android this is the integer fd from
  /// `Socket.getSocketOption(SocketOption.fd)` (or platform-specific).
  /// On Windows it's the SOCKET handle cast to int.
  static WolfSshSession connect({
    required WolfSshContext context,
    required int fileDescriptor,
    required String username,
  }) {
    final lib = context.library;
    final ssh = lib.bindings.sshNew(context.nativeHandle);
    if (ssh == nullptr) {
      throw StateError('wolfSSH_new returned NULL');
    }

    // Tie this session to its context so the user-auth and host-key
    // trampolines can recover the Dart-side strategy via the void*
    // userdata pointer wolfSSH passes through.
    final ctxPtr = context.nativeHandle.cast<Void>();
    lib.bindings.setUserAuthCtx(ssh, ctxPtr);
    lib.bindings.setPublicKeyCheckCtx(ssh, ctxPtr);

    final usernameC = username.toNativeUtf8();
    try {
      final rcUser = lib.bindings.setUsername(ssh, usernameC.cast<Char>());
      if (rcUser != raw.WS_SUCCESS) {
        lib.bindings.sshFree(ssh);
        throwWolfSshError(lib, rcUser, context: 'wolfSSH_SetUsername');
      }
    } finally {
      malloc.free(usernameC);
    }

    final rcFd = lib.bindings.setFd(ssh, fileDescriptor);
    if (rcFd != raw.WS_SUCCESS) {
      lib.bindings.sshFree(ssh);
      throwWolfSshError(lib, rcFd, context: 'wolfSSH_set_fd');
    }

    final rcConnect = lib.bindings.connect(ssh);
    if (rcConnect != raw.WS_SUCCESS) {
      final detail = lib.bindings.getError(ssh);
      lib.bindings.sshFree(ssh);
      throwWolfSshError(lib, detail, context: 'wolfSSH_connect');
    }

    return WolfSshSession._(context, ssh);
  }

  final WolfSshContext context;
  Pointer<raw.WOLFSSH> _ssh;
  bool _disposed = false;

  /// Sends [data] over the active channel. Loops on `WS_WANT_WRITE` is
  /// the caller's responsibility — see [writeAll] for a high-level
  /// helper.
  IoStatus writeOnce(Uint8List data) {
    _ensureOpen();
    final len = checkBufferLen(data.length, where: 'data.length');
    final buf = malloc<Uint8>(len);
    try {
      buf.asTypedList(len).setAll(0, data);
      final rc = context.library.bindings.streamSend(_ssh, buf, len);
      return _classify(rc);
    } finally {
      malloc.free(buf);
    }
  }

  /// Reads up to [maxBytes] bytes; returns [IoCompleted] with the slice
  /// of bytes read, or [IoWantRead] / [IoEof].
  IoStatus readOnce(int maxBytes, Uint8List into) {
    _ensureOpen();
    if (into.length < maxBytes) {
      throw ArgumentError(
          'destination buffer too small ($maxBytes requested, ${into.length} available)');
    }
    final len = checkBufferLen(maxBytes, where: 'maxBytes');
    final buf = malloc<Uint8>(len);
    try {
      final rc = context.library.bindings.streamRead(_ssh, buf, len);
      final status = _classify(rc);
      if (status is IoCompleted && status.bytes > 0) {
        into.setRange(0, status.bytes, buf.asTypedList(status.bytes));
      }
      return status;
    } finally {
      malloc.free(buf);
    }
  }

  /// Convenience: blocking write that loops until all of [data] has been
  /// flushed or a hard error occurs. Treats `WS_WANT_WRITE` as a busy
  /// signal and retries; production code driving its own selector should
  /// prefer [writeOnce] and integrate with the platform's poll/epoll.
  void writeAll(Uint8List data) {
    var offset = 0;
    while (offset < data.length) {
      final slice = data.sublist(offset);
      final status = writeOnce(slice);
      switch (status) {
        case IoCompleted(:final bytes):
          if (bytes == 0) {
            // wolfSSH returned zero bytes sent without WS_WANT_WRITE;
            // treat as a soft retry but break out if it persists.
            return;
          }
          offset += bytes;
        case IoWantWrite():
        case IoWantRead():
          continue;
        case IoEof():
          throw WolfSshException(
              raw.WS_EOF, 'WS_EOF', 'writeAll mid-stream EOF');
      }
    }
  }

  IoStatus _classify(int rc) {
    if (rc >= 0) return IoCompleted(rc);
    switch (rc) {
      case raw.WS_WANT_READ:
        return const IoWantRead();
      case raw.WS_WANT_WRITE:
        return const IoWantWrite();
      case raw.WS_EOF:
      case raw.WS_CHANNEL_CLOSED:
        return const IoEof();
      default:
        final detail = context.library.bindings.getError(_ssh);
        throwWolfSshError(context.library, detail);
    }
  }

  void _ensureOpen() {
    if (_disposed || _ssh == nullptr) {
      throw StateError('WolfSshSession used after dispose()');
    }
  }

  /// Initiates a clean SSH shutdown and frees the native session.
  void dispose() {
    if (_disposed) return;
    _disposed = true;
    if (_ssh != nullptr) {
      // Best-effort shutdown; ignore non-zero return — we still need to
      // free the structure.
      context.library.bindings.shutdown(_ssh);
      context.library.bindings.sshFree(_ssh);
      _ssh = nullptr;
    }
  }
}

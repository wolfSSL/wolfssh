import 'dart:ffi';

import 'package:ffi/ffi.dart';

import 'bindings/wolfssh.g.dart' as raw;
import 'library.dart';

/// Exception type raised when a wolfSSH call returns a hard error.
///
/// `WS_WANT_READ` and `WS_WANT_WRITE` are *not* turned into exceptions;
/// they surface as `IoStatus` values from the streaming methods so that
/// callers driving their own event loop don't pay the cost of a throw on
/// every short read.
class WolfSshException implements Exception {
  WolfSshException(this.code, this.name, [this.context]);

  /// Numeric WS_* error code.
  final int code;

  /// Human-readable name from `wolfSSH_ErrorToName`, or a fallback.
  final String name;

  /// Optional context hint (e.g. which API call returned the error).
  final String? context;

  @override
  String toString() {
    final ctx = context != null ? ' [$context]' : '';
    return 'WolfSshException(code=$code, $name)$ctx';
  }
}

/// Convert a wolfSSH return value (or `wolfSSH_get_error()` result) into
/// a thrown [WolfSshException]. The caller must have already checked that
/// `code < 0` and that it is not `WS_WANT_READ` / `WS_WANT_WRITE`.
Never throwWolfSshError(WolfSshLibrary lib, int code, {String? context}) {
  final namePtr = lib.bindings.errorToName(code);
  final name = namePtr == nullptr ? 'WS_UNKNOWN' : namePtr.cast<Utf8>().toDartString();
  throw WolfSshException(code, name, context);
}

/// Result of a non-blocking I/O attempt.
sealed class IoStatus {
  const IoStatus();
}

/// `n` bytes were transferred (0 ≤ n ≤ requested).
class IoCompleted extends IoStatus {
  const IoCompleted(this.bytes);
  final int bytes;
}

/// The peer is not ready; retry once data is available.
class IoWantRead extends IoStatus {
  const IoWantRead();
}

/// The send buffer is full; retry the same data.
class IoWantWrite extends IoStatus {
  const IoWantWrite();
}

/// Channel was closed cleanly by the peer.
class IoEof extends IoStatus {
  const IoEof();
}

/// Constant-time-ish length validator for buffer/length pairs at the FFI
/// boundary. wolfSSH takes `word32` (uint32) sizes; Dart `List.length` is
/// a 64-bit int. Reject anything that would silently truncate.
int checkBufferLen(int len, {String? where}) {
  if (len < 0 || len > 0xFFFFFFFF) {
    throw ArgumentError.value(
      len,
      where ?? 'length',
      'must fit in word32 (0..0xFFFFFFFF)',
    );
  }
  return len;
}

/// Translate a positive int return (bytes transferred) or specific
/// negative wolfSSH codes into an [IoStatus].
IoStatus interpretIoReturn(int rc) {
  if (rc >= 0) {
    return IoCompleted(rc);
  }
  switch (rc) {
    case raw.WS_WANT_READ:
      return const IoWantRead();
    case raw.WS_WANT_WRITE:
      return const IoWantWrite();
    case raw.WS_EOF:
    case raw.WS_CHANNEL_CLOSED:
      return const IoEof();
    default:
      // Caller should have classified hard errors via throwWolfSshError.
      throw StateError('unexpected wolfSSH I/O code $rc');
  }
}

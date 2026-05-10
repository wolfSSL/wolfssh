// Minimal POSIX socket helpers for the example, used to obtain a raw
// integer fd that wolfSSH_set_fd accepts. Linux + macOS only — Windows
// requires WSAStartup/WSASocket and is out of scope for this demo.
//
// dart:io's Socket does not surface its underlying fd publicly (this is
// by design: dart:io owns lifecycle on most platforms). Rather than
// reach into _NativeSocket private state we open the socket ourselves
// via libc, which is also closer to what production embedders of an
// SSH client do — they often want to control socket options (TCP_NODELAY,
// SO_KEEPALIVE, etc.) that dart:io does not expose.

import 'dart:ffi';
import 'dart:io';

import 'package:ffi/ffi.dart';

const int _AF_INET = 2;
const int _SOCK_STREAM = 1;
// IPPROTO_TCP differs across platforms; 0 lets the kernel pick the
// default for SOCK_STREAM, which is TCP. That's what we want.
const int _IPPROTO_DEFAULT = 0;

// The libc symbols are statically linked into the Dart VM on the
// standard Linux/macOS runtimes, so process() resolves them.
final DynamicLibrary _libc = DynamicLibrary.process();

typedef _SocketC = Int Function(Int, Int, Int);
typedef _SocketDart = int Function(int, int, int);
final _SocketDart _socket =
    _libc.lookupFunction<_SocketC, _SocketDart>('socket');

typedef _ConnectC = Int Function(Int, Pointer<Uint8>, Uint32);
typedef _ConnectDart = int Function(int, Pointer<Uint8>, int);
final _ConnectDart _connect =
    _libc.lookupFunction<_ConnectC, _ConnectDart>('connect');

typedef _CloseC = Int Function(Int);
typedef _CloseDart = int Function(int);
final _CloseDart _close =
    _libc.lookupFunction<_CloseC, _CloseDart>('close');

typedef _InetPtonC = Int Function(Int, Pointer<Utf8>, Pointer<Uint8>);
typedef _InetPtonDart = int Function(int, Pointer<Utf8>, Pointer<Uint8>);
final _InetPtonDart _inetPton =
    _libc.lookupFunction<_InetPtonC, _InetPtonDart>('inet_pton');

/// Connects to an IPv4 [host]:[port] and returns the resulting fd.
///
/// Caller is responsible for [closeFd] when done. On error throws
/// [OSError].
///
/// Limitations:
///   * IPv4 only — for IPv6 use a wider sockaddr_in6 layout. Many SSH
///     servers still default to IPv4-only listeners, which is fine for
///     a demo.
///   * Synchronous blocking connect — production code should set
///     SOCK_NONBLOCK and integrate with wolfSSH's WS_WANT_READ/WRITE
///     loop.
///   * Resolves only literal IPv4 dotted-quads. Hostname resolution
///     should be done up-front by the caller (e.g. via
///     `InternetAddress.lookup`).
int connectIpv4Tcp(String dottedQuad, int port) {
  if (!Platform.isLinux && !Platform.isMacOS) {
    throw UnsupportedError(
        'connectIpv4Tcp() supports Linux/macOS only; on Windows use '
        'WSASocket via your own helper');
  }

  final fd = _socket(_AF_INET, _SOCK_STREAM, _IPPROTO_DEFAULT);
  if (fd < 0) {
    throw OSError('socket() failed', fd);
  }

  // sockaddr_in layout (Linux + macOS, 16 bytes):
  //   [0..1]   sa_family   (uint16, host byte order — _AF_INET)
  //   [2..3]   sin_port    (uint16, network byte order)
  //   [4..7]   sin_addr    (uint32, set via inet_pton)
  //   [8..15]  sin_zero    (8 bytes, must be zero — calloc zero-fills)
  final addr = calloc<Uint8>(16);
  try {
    addr.cast<Uint16>().value = _AF_INET; // host byte order on both BSD and Linux
    // Port is big-endian on the wire (htons).
    addr[2] = (port >> 8) & 0xff;
    addr[3] = port & 0xff;

    final hostC = dottedQuad.toNativeUtf8();
    try {
      final addrField = Pointer<Uint8>.fromAddress(addr.address + 4);
      final ptonRc = _inetPton(_AF_INET, hostC, addrField);
      if (ptonRc != 1) {
        throw OSError(
            'inet_pton() failed for "$dottedQuad" (rc=$ptonRc; not a valid '
            'IPv4 dotted-quad — resolve hostnames before calling)',
            ptonRc);
      }
    } finally {
      malloc.free(hostC);
    }

    final connectRc = _connect(fd, addr, 16);
    if (connectRc != 0) {
      _close(fd);
      throw OSError('connect() failed', connectRc);
    }
    return fd;
  } finally {
    calloc.free(addr);
  }
}

/// Closes a file descriptor obtained from [connectIpv4Tcp]. Always
/// safe to call (a -1 fd is silently ignored).
void closeFd(int fd) {
  if (fd < 0) return;
  _close(fd);
}

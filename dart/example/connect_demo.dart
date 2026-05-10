// Minimal connection demo. Requires a running SSH server with a known
// host-key fingerprint. NOT a copy-paste recipe for production:
// HostKeyVerifier.acceptAnyDangerous() exists for sandboxed lab use only.

import 'dart:io';
import 'dart:typed_data';

import 'package:wolfssh/wolfssh.dart';

import 'posix_socket.dart';

Future<void> main(List<String> args) async {
  if (args.length < 3) {
    stderr.writeln(
        'usage: connect_demo <ipv4-host> <port> <user> [pinFingerprint]');
    stderr.writeln('  <ipv4-host> must be a dotted quad like 127.0.0.1.');
    stderr.writeln('  Resolve hostnames externally; this demo skips DNS.');
    exit(64);
  }
  final host = args[0];
  final port = int.parse(args[1]);
  final user = args[2];
  final pin = args.length > 3 ? args[3] : null;

  final verifier = pin != null
      ? HostKeyVerifier.fingerprintPin([pin])
      : HostKeyVerifier.acceptAnyDangerous();

  final ctx = WolfSshContext(
    hostKeyVerifier: verifier,
    userAuthStrategy: UserAuthStrategy.password(user, _readPassword()),
  );

  // Open the socket via libc so we get a raw fd that wolfSSH_set_fd
  // can drive directly. dart:io's Socket does not surface its
  // underlying fd; see example/posix_socket.dart for the rationale.
  final fd = connectIpv4Tcp(host, port);

  try {
    final session = WolfSshSession.connect(
      context: ctx,
      fileDescriptor: fd,
      username: user,
    );
    try {
      session.writeAll(Uint8List.fromList('uptime\n'.codeUnits));
      final buf = Uint8List(4096);
      final status = session.readOnce(buf.length, buf);
      switch (status) {
        case IoCompleted(:final bytes):
          stdout.add(buf.sublist(0, bytes));
        case IoWantRead():
        case IoWantWrite():
          stderr.writeln('I/O not ready; integrate with select()/epoll.');
        case IoEof():
          stderr.writeln('peer closed channel');
      }
    } finally {
      session.dispose();
    }
  } finally {
    closeFd(fd);
    ctx.dispose();
  }
}

String _readPassword() {
  stdout.write('Password: ');
  stdin.echoMode = false;
  try {
    return stdin.readLineSync() ?? '';
  } finally {
    stdin.echoMode = true;
    stdout.writeln();
  }
}

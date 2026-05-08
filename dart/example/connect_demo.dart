// Minimal connection demo. Requires a running SSH server with a known
// host-key fingerprint. NOT a copy-paste recipe for production:
// HostKeyVerifier.acceptAnyDangerous() exists for sandboxed lab use only.

import 'dart:io';
import 'dart:typed_data';

import 'package:wolfssh/wolfssh.dart';

Future<void> main(List<String> args) async {
  if (args.length < 3) {
    stderr.writeln('usage: connect_demo <host> <port> <user> [pinFingerprint]');
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

  final socket = await Socket.connect(host, port);
  // Platform note: extracting the underlying fd from a dart:io Socket
  // is platform-sensitive. On Dart 3.4+ this requires
  // `socket.address` plus a syscall, or a tiny platform channel on
  // Android/iOS. Demo elides this for brevity.
  final fd = -1;
  if (fd < 0) {
    stderr.writeln('TODO: extract fd from Socket on this platform.');
    await socket.close();
    ctx.dispose();
    return;
  }

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
    ctx.dispose();
    await socket.close();
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

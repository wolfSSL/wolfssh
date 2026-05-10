# wolfssh (Dart FFI)

> **Unofficial.** This package is an independent, community-maintained
> Dart FFI wrapper around wolfSSH. It is **not affiliated with, endorsed
> by, or supported by wolfSSL Inc.** For official wolfSSH support,
> commercial licensing, or security advisories, contact wolfSSL Inc.
> directly (`licensing@wolfssl.com`, https://www.wolfssl.com).
> Bugs in *this binding* should be reported to this repository's
> issue tracker — not to wolfSSL.

Dart FFI bindings for the [wolfSSH](https://www.wolfssl.com/products/wolfssh/)
client, vendored at v1.5.0-stable. Targets desktop (Linux, macOS,
Windows) and mobile (Android, iOS) via CMake-driven native builds.

> **Read [SECURITY.md](SECURITY.md) before using.** Host-key
> verification is mandatory and is the most common place to introduce
> a man-in-the-middle vulnerability.

## Status

Skeleton, work-in-progress. Implemented:

  * Library loader, `wolfSSH_Init`/`Cleanup` lifecycle.
  * `WolfSshContext` with required `HostKeyVerifier` + `UserAuthStrategy`.
  * Fail-closed host-key trampoline (rejects on null/oversize/throw).
  * Fail-closed user-auth trampoline (returns
    `WOLFSSH_USERAUTH_FAILURE` on throw).
  * Password and public-key user-auth: the callback fills
    `WS_UserAuthData.sf.password` or `WS_UserAuthData.sf.publicKey`
    via the `wolfssh_dart_fill_password` / `wolfssh_dart_fill_pubkey`
    helpers in the C glue. Credential bytes live in context-owned
    native buffers that are zeroed on dispose.
  * `WolfSshSession.connect`, `readOnce` / `writeOnce` / `writeAll`.
  * `IoStatus` sum type for `WS_WANT_READ` / `WS_WANT_WRITE` / `EOF`.
  * `example/posix_socket.dart` — small libc FFI helper that opens an
    IPv4 TCP socket and returns the raw fd, since `dart:io`'s `Socket`
    does not expose its underlying fd. Linux/macOS only.

Not yet implemented:

  * Channel API beyond the default stream channel.
  * SFTP, SCP, agent forwarding, server-side accept.
  * Windows socket helper for the example (needs WSASocket).
  * Hostname resolution in the example (consumers should call
    `InternetAddress.lookup` and pass a literal IPv4 dotted-quad).

## Build

```sh
# From inside dart/
cmake -B build -DWOLFSSH_DART_FETCH_WOLFSSL=ON
cmake --build build -j
# Result: dart/build/libwolfssh_dart.{so,dylib,dll}
```

To use a system-installed wolfSSL instead:

```sh
cmake -B build -DWOLFSSH_DART_FETCH_WOLFSSL=OFF   # requires libwolfssl-dev
```

## Usage

```dart
import 'dart:io';
import 'dart:typed_data';
import 'package:wolfssh/wolfssh.dart';

Future<void> main() async {
  // 1. Pin the host key out-of-band. NEVER ship acceptAnyDangerous
  //    in production.
  final verifier = HostKeyVerifier.fingerprintPin([
    'SHA256:abcd1234...your-server-key-fingerprint',
  ]);

  // 2. Provide credentials.
  final auth = UserAuthStrategy.password('alice', 'hunter2');

  // 3. Build a context and a session.
  final ctx = WolfSshContext(
    hostKeyVerifier: verifier,
    userAuthStrategy: auth,
  );
  try {
    final socket = await Socket.connect('example.com', 22);
    // Platform-specific: get the raw fd from the socket. On Dart >=3.4
    // this is exposed via SocketControl.fileDescriptor; on older
    // SDKs you'll need a small platform plugin.
    final fd = await _socketFd(socket);

    final session = WolfSshSession.connect(
      context: ctx,
      fileDescriptor: fd,
      username: 'alice',
    );
    try {
      session.writeAll(Uint8List.fromList('uname -a\n'.codeUnits));
      // ... readOnce loop ...
    } finally {
      session.dispose();
      await socket.close();
    }
  } finally {
    ctx.dispose();
  }
}

Future<int> _socketFd(Socket socket) async {
  // Placeholder; real code uses dart:io's RawSocket fd accessor or a
  // platform plugin on systems that don't expose it directly.
  throw UnimplementedError();
}
```

## Layout

```
dart/
├── pubspec.yaml
├── ffigen.yaml          # for regenerating raw bindings (optional)
├── CMakeLists.txt       # native build (vendors ../src + wolfssl)
├── native/              # tiny C glue
├── lib/
│   ├── wolfssh.dart     # public barrel
│   └── src/
│       ├── bindings/    # hand-curated raw FFI
│       ├── auth/        # HostKeyVerifier, UserAuthStrategy
│       ├── library.dart
│       ├── error.dart
│       ├── context.dart
│       └── session.dart
├── example/
├── test/
├── README.md
└── SECURITY.md          # critical security paths — REQUIRED READING
```

## License

Inherits from wolfSSH (GPLv3 or commercial). See [LICENSE](LICENSE) for the
full GPLv3 text. For a commercial license, contact wolfSSL Inc. directly
(see disclaimer at the top of this README).

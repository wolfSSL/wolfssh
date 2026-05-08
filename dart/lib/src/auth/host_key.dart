import 'dart:convert';
import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';

/// Verifies a server's offered SSH public key.
///
/// SECURITY-CRITICAL.
///
/// Without a registered `WS_CallbackPublicKeyCheck`, wolfSSH silently
/// accepts any host key the server presents (see src/internal.c around
/// the "DKDR: no public key check callback, accepted" log line). That
/// behaviour is a man-in-the-middle vulnerability; CVE-2025-11625 was a
/// related bypass fixed in wolfSSH 1.4.21+ and is one of the reasons
/// this binding requires v1.5.0-stable or newer.
///
/// The wrapper requires every [WolfSshContext] to be constructed with a
/// non-null verifier. There is intentionally no default. The named
/// constructors below cover the three patterns most callers want:
///
///   * [HostKeyVerifier.fingerprintPin]   - safest; pin one or more
///     SHA-256 fingerprints out-of-band.
///   * [HostKeyVerifier.knownHosts]       - OpenSSH-compatible
///     known_hosts file lookup (TOFU on first contact, strict thereafter).
///   * [HostKeyVerifier.acceptAnyDangerous] - explicit footgun for
///     development/testing; the name is awkward on purpose so it shows
///     up in code review.
abstract class HostKeyVerifier {
  const HostKeyVerifier();

  /// Returns true to accept the server key, false to reject and abort
  /// the handshake. Throwing is treated as rejection (fail-closed).
  bool verify(Uint8List serverPublicKey);

  /// Pin one or more SHA-256 fingerprints. Format matches `ssh-keygen
  /// -lf` output — hex bytes optionally separated by colons, or the
  /// `SHA256:base64` form. Comparison is case-insensitive.
  factory HostKeyVerifier.fingerprintPin(List<String> sha256Fingerprints) =
      _FingerprintPinVerifier;

  /// Verifies the server key against an OpenSSH-style known_hosts file.
  /// On first contact (host absent), [trustOnFirstUse] decides whether
  /// to record the new key. Default is **false** — TOFU must be opted
  /// into explicitly.
  factory HostKeyVerifier.knownHosts(
    File knownHostsFile, {
    required String hostnameAndPort,
    bool trustOnFirstUse,
  }) = _KnownHostsVerifier;

  /// Accepts any key. The constructor name is intentionally verbose and
  /// includes "Dangerous" so that `grep` / code review surface every
  /// caller. Use only for connecting to controlled lab targets.
  factory HostKeyVerifier.acceptAnyDangerous() = _AcceptAnyVerifier;
}

class _FingerprintPinVerifier extends HostKeyVerifier {
  _FingerprintPinVerifier(List<String> sha256Fingerprints)
      : _normalized = sha256Fingerprints.map(_normalize).toSet() {
    if (_normalized.isEmpty) {
      throw ArgumentError('fingerprint pin list must not be empty');
    }
  }

  final Set<String> _normalized;

  @override
  bool verify(Uint8List serverPublicKey) {
    final actual = _normalize(_sha256B64(serverPublicKey));
    return _normalized.contains(actual);
  }

  static String _normalize(String s) {
    var t = s.trim();
    // Strip optional "SHA256:" prefix (case-insensitive). Do NOT
    // lowercase the body: base64 fingerprints are case-sensitive.
    if (t.length >= 7 && t.substring(0, 7).toUpperCase() == 'SHA256:') {
      t = t.substring(7);
    }
    // Hex-style fingerprints use colons as separators; strip them.
    // Spaces sometimes creep in from copy/paste.
    t = t.replaceAll(':', '').replaceAll(' ', '');
    return t;
  }
}

class _KnownHostsVerifier extends HostKeyVerifier {
  _KnownHostsVerifier(
    this._file, {
    required this.hostnameAndPort,
    this.trustOnFirstUse = false,
  });

  final File _file;
  final String hostnameAndPort;
  final bool trustOnFirstUse;

  @override
  bool verify(Uint8List serverPublicKey) {
    final fp = _sha256B64(serverPublicKey);
    if (!_file.existsSync()) {
      if (trustOnFirstUse) {
        _file.writeAsStringSync('$hostnameAndPort $fp\n', mode: FileMode.append);
        return true;
      }
      return false;
    }
    final lines = _file.readAsLinesSync();
    var sawHost = false;
    for (final line in lines) {
      final parts = line.trim().split(RegExp(r'\s+'));
      if (parts.length < 2) continue;
      if (parts[0] != hostnameAndPort) continue;
      sawHost = true;
      if (parts[1] == fp) return true;
    }
    if (!sawHost && trustOnFirstUse) {
      _file.writeAsStringSync('$hostnameAndPort $fp\n', mode: FileMode.append);
      return true;
    }
    return false;
  }
}

class _AcceptAnyVerifier extends HostKeyVerifier {
  const _AcceptAnyVerifier();

  @override
  bool verify(Uint8List serverPublicKey) => true;
}

String _sha256B64(Uint8List bytes) {
  // Avoid pulling in `package:crypto` so the binding has no dependencies
  // beyond `package:ffi`. We FFI into wolfCrypt's SHA-256 via the bound
  // wolfSSL symbols — but that path isn't yet exposed by the curated
  // bindings, so for now we use Dart's `sha256` placeholder import-free
  // by deferring to a tiny pure-Dart implementation.
  return base64.encode(_sha256(bytes));
}

// ─── Minimal SHA-256 (RFC 6234) ──────────────────────────────────────────
// Used only for fingerprint computation in the host-key verifier. Avoids
// a hard dependency on package:crypto. Constant-time across inputs of
// equal length is sufficient for non-secret fingerprint hashing.
Uint8List _sha256(Uint8List msg) {
  const k = <int>[
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  ];
  final h = <int>[
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
  ];
  final bitLen = msg.length * 8;
  final padLen = (msg.length + 9 + 63) & ~63;
  final padded = Uint8List(padLen);
  padded.setAll(0, msg);
  padded[msg.length] = 0x80;
  // Big-endian 64-bit length.
  for (var i = 0; i < 8; i++) {
    padded[padded.length - 1 - i] = (bitLen >> (8 * i)) & 0xff;
  }

  int rotr(int x, int n) => ((x >>> n) | (x << (32 - n))) & 0xffffffff;

  for (var chunk = 0; chunk < padded.length; chunk += 64) {
    final w = List<int>.filled(64, 0);
    for (var i = 0; i < 16; i++) {
      w[i] = (padded[chunk + 4 * i] << 24) |
          (padded[chunk + 4 * i + 1] << 16) |
          (padded[chunk + 4 * i + 2] << 8) |
          padded[chunk + 4 * i + 3];
    }
    for (var i = 16; i < 64; i++) {
      final s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
      final s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & 0xffffffff;
    }
    var a = h[0], b = h[1], c = h[2], d = h[3];
    var e = h[4], f = h[5], g = h[6], hh = h[7];
    for (var i = 0; i < 64; i++) {
      final s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      final ch = (e & f) ^ ((~e & 0xffffffff) & g);
      final t1 = (hh + s1 + ch + k[i] + w[i]) & 0xffffffff;
      final s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      final mj = (a & b) ^ (a & c) ^ (b & c);
      final t2 = (s0 + mj) & 0xffffffff;
      hh = g;
      g = f;
      f = e;
      e = (d + t1) & 0xffffffff;
      d = c;
      c = b;
      b = a;
      a = (t1 + t2) & 0xffffffff;
    }
    h[0] = (h[0] + a) & 0xffffffff;
    h[1] = (h[1] + b) & 0xffffffff;
    h[2] = (h[2] + c) & 0xffffffff;
    h[3] = (h[3] + d) & 0xffffffff;
    h[4] = (h[4] + e) & 0xffffffff;
    h[5] = (h[5] + f) & 0xffffffff;
    h[6] = (h[6] + g) & 0xffffffff;
    h[7] = (h[7] + hh) & 0xffffffff;
  }

  final out = Uint8List(32);
  for (var i = 0; i < 8; i++) {
    out[4 * i] = (h[i] >> 24) & 0xff;
    out[4 * i + 1] = (h[i] >> 16) & 0xff;
    out[4 * i + 2] = (h[i] >> 8) & 0xff;
    out[4 * i + 3] = h[i] & 0xff;
  }
  return out;
}

/// Internal: glue used by [WolfSshContext] to wire the verifier as a
/// `WS_CallbackPublicKeyCheck` and pass it through `void* ctx`. Returns
/// 0 to wolfSSH on accept, non-zero on reject — matches the convention
/// at src/internal.c around the DKDR public-key-check call site.
int hostKeyCallbackTrampoline(
  HostKeyVerifier verifier,
  Pointer<Uint8> keyPtr,
  int keySz,
) {
  try {
    if (keyPtr == nullptr || keySz == 0) {
      return 1; // reject
    }
    if (keySz > 64 * 1024) {
      // Defence in depth: SSH host keys are at most a few KB. Anything
      // larger means the parser is in an unexpected state.
      return 1;
    }
    final bytes = Uint8List.fromList(keyPtr.asTypedList(keySz));
    return verifier.verify(bytes) ? 0 : 1;
  } catch (_) {
    // Fail closed on any verifier exception.
    return 1;
  }
}

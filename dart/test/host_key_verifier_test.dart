// Tests for the HostKeyVerifier strategies. These are pure-Dart tests
// and do not touch the native library, so they run without
// libwolfssh_dart being built.

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:wolfssh/wolfssh.dart';

void main() {
  group('fingerprintPin', () {
    final demoKey = Uint8List.fromList(utf8.encode('demo public key blob'));
    // SHA-256 of the bytes above:
    final demoFp = base64.encode(_sha256Bytes(demoKey));

    test('accepts matching fingerprint', () {
      final v = HostKeyVerifier.fingerprintPin([demoFp]);
      expect(v.verify(demoKey), isTrue);
    });

    test('rejects non-matching fingerprint', () {
      final v = HostKeyVerifier.fingerprintPin(['notarealfingerprint']);
      expect(v.verify(demoKey), isFalse);
    });

    test('SHA256: prefix and colons are normalised', () {
      final v = HostKeyVerifier.fingerprintPin(['SHA256:$demoFp']);
      expect(v.verify(demoKey), isTrue);
    });

    test('empty pin list is rejected at construction', () {
      expect(() => HostKeyVerifier.fingerprintPin([]),
          throwsA(isA<ArgumentError>()));
    });
  });

  group('knownHosts', () {
    late File tmp;
    setUp(() {
      tmp = File('${Directory.systemTemp.path}/wolfssh_test_${DateTime.now().microsecondsSinceEpoch}');
    });
    tearDown(() {
      if (tmp.existsSync()) tmp.deleteSync();
    });

    test('rejects when file missing and TOFU disabled', () {
      final v = HostKeyVerifier.knownHosts(tmp,
          hostnameAndPort: 'example.com:22');
      expect(v.verify(Uint8List.fromList([1, 2, 3])), isFalse);
    });

    test('records first key when TOFU enabled', () {
      final v = HostKeyVerifier.knownHosts(tmp,
          hostnameAndPort: 'example.com:22', trustOnFirstUse: true);
      final key = Uint8List.fromList([4, 5, 6]);
      expect(v.verify(key), isTrue);
      expect(tmp.readAsStringSync(), contains('example.com:22'));
    });

    test('rejects mismatched key on subsequent connect', () {
      final v = HostKeyVerifier.knownHosts(tmp,
          hostnameAndPort: 'example.com:22', trustOnFirstUse: true);
      v.verify(Uint8List.fromList([7, 8, 9]));
      // Different key for same host: must reject (not auto-update).
      expect(v.verify(Uint8List.fromList([1, 1, 1])), isFalse);
    });
  });

  group('acceptAnyDangerous', () {
    test('always accepts; the grep target lives in this test', () {
      final v = HostKeyVerifier.acceptAnyDangerous();
      expect(v.verify(Uint8List.fromList([0])), isTrue);
    });
  });
}

// Local SHA-256 used to compute expected fingerprints in tests; matches
// the implementation in lib/src/auth/host_key.dart.
Uint8List _sha256Bytes(Uint8List msg) {
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
      hh = g; g = f; f = e; e = (d + t1) & 0xffffffff;
      d = c; c = b; b = a; a = (t1 + t2) & 0xffffffff;
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

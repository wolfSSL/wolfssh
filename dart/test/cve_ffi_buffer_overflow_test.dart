// PoC tests for FFI buffer-length boundary at the Dart ↔ wolfSSH edge.
//
// wolfSSH's stream/channel APIs take `(byte*, word32)` pairs. Dart's
// List.length is a 64-bit int. Any path that lets a large Dart length
// flow into a `word32` without an explicit check is an integer-truncation
// hazard that has been the root cause of multiple SSH/TLS CVEs over the
// years (CVE-2002-0083 / CVE-2007-2243 / CVE-2018-1000301 in unrelated
// SSH stacks all share this shape: caller passes N bytes, library reads
// N & 0xffffffff bytes, attacker confuses bookkeeping).
//
// The binding's defence is a single helper [checkBufferLen] (see
// lib/src/error.dart) that all length-bearing FFI call sites must funnel
// through. Tests here exercise:
//
//   * the boundary values 0, 0xFFFFFFFF (legitimate)
//   * 0xFFFFFFFF + 1, INT64_MAX (must throw, not truncate)
//   * negative lengths (must throw — interpreting a negative Dart int
//     as an unsigned word32 is the classic underflow attack)
//
// Tests are pure-Dart; no native library required.

import 'package:test/test.dart';
import 'package:wolfssh/src/error.dart';

void main() {
  group('checkBufferLen — integer-truncation guard', () {
    test('zero is allowed (legitimate empty read/write)', () {
      expect(checkBufferLen(0), 0);
    });

    test('1 byte is allowed', () {
      expect(checkBufferLen(1), 1);
    });

    test('PoC: word32 boundary 0xFFFFFFFF is allowed', () {
      // The maximum value that fits in a uint32. Anything larger
      // would be truncated by the C side; the helper must allow this
      // exact value through unchanged.
      expect(checkBufferLen(0xFFFFFFFF), 0xFFFFFFFF);
    });

    test('PoC: 0x100000000 (one past word32 max) is rejected', () {
      // Without this guard, the high 32 bits would be silently
      // discarded and wolfSSH would read/write buf.length & 0xffffffff
      // bytes — i.e. *zero* — while the Dart caller believes 4 GiB
      // were processed. That mismatch is the bug class.
      expect(
          () => checkBufferLen(0x100000000),
          throwsA(isA<ArgumentError>().having(
              (e) => e.message.toString(),
              'message',
              contains('word32'))),
          reason: '4 GiB + 1 byte must throw, not silently truncate to 0');
    });

    test('PoC: very large length is rejected', () {
      // A pathological caller passing a near-INT64_MAX length should
      // not reach the FFI boundary at all.
      const big = 1 << 53; // 9 PiB; well past word32
      expect(() => checkBufferLen(big), throwsA(isA<ArgumentError>()));
    });

    test('PoC: negative length is rejected', () {
      // -1 reinterpreted as uint32 is 0xFFFFFFFF (4 GiB). A future
      // refactor that subtracts past zero (e.g. remaining = total -
      // sent on a buggy progress accumulator) must not silently turn
      // into a 4 GiB read.
      expect(() => checkBufferLen(-1), throwsA(isA<ArgumentError>()));
    });

    test('PoC: -2147483648 (INT32_MIN) is rejected', () {
      // Same shape as -1 but covers a separate code path on platforms
      // where the helper might do a smallint optimisation.
      expect(() => checkBufferLen(-2147483648),
          throwsA(isA<ArgumentError>()));
    });

    test('error message identifies the offending field name when supplied',
        () {
      // Aids debugging in production: a thrown ArgumentError should
      // say *which* length parameter was bad, not just "length".
      try {
        checkBufferLen(-1, where: 'channel_send.bufSz');
        fail('expected throw');
      } on ArgumentError catch (e) {
        expect(e.name, 'channel_send.bufSz');
      }
    });
  });
}

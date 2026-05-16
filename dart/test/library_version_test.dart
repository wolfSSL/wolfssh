// Pure-Dart tests for the anti-downgrade gate in WolfSshLibrary.
//
// SECURITY: this is the binding's defence against loading a stale
// `libwolfssh_dart.so` that was built against a pre-1.5.0 wolfSSH —
// pre-1.5.0 is missing at least one of the CVE fixes documented in
// SECURITY.md §9 (most importantly CVE-2025-11625 host-key bypass).
//
// The check itself runs inside `WolfSshLibrary.load`, which needs the
// native library. To keep these tests runnable in CI without the .so,
// the comparison logic is factored into the static
// `WolfSshLibrary.validateNativeVersion(int)` method, which these
// tests drive directly.

import 'package:test/test.dart';
import 'package:wolfssh/src/library.dart';

void main() {
  group('WolfSshLibrary.validateNativeVersion', () {
    test('accepts the minimum version exactly (0x01005000 == 1.5.0)', () {
      expect(() => WolfSshLibrary.validateNativeVersion(0x01005000),
          returnsNormally);
    });

    test('accepts versions above the minimum', () {
      expect(() => WolfSshLibrary.validateNativeVersion(0x01005001),
          returnsNormally);
      expect(() => WolfSshLibrary.validateNativeVersion(0x02000000),
          returnsNormally);
    });

    test('PoC: rejects 0 (uninitialised / missing symbol fallback)', () {
      expect(
          () => WolfSshLibrary.validateNativeVersion(0),
          throwsA(isA<StateError>().having(
              (e) => e.message, 'message', contains('too old'))));
    });

    test('PoC: rejects the value just below 1.5.0', () {
      expect(
          () => WolfSshLibrary.validateNativeVersion(0x01004FFF),
          throwsA(isA<StateError>().having(
              (e) => e.message, 'message', contains('1.5.0'))));
    });

    test('PoC: rejects a 1.4.x-shaped version (CVE-2025-11625 absent)', () {
      // wolfSSH 1.4.20 encodes as 0x01004020. CVE-2025-11625 was fixed
      // in 1.4.21+; even 1.4.21 is below our minimum because we want
      // the additional fixes that landed in 1.5.0 (CVE-2025-14942,
      // CVE-2025-15382). Asserting the binding refuses 1.4.x outright.
      expect(() => WolfSshLibrary.validateNativeVersion(0x01004020),
          throwsA(isA<StateError>()));
      expect(() => WolfSshLibrary.validateNativeVersion(0x01004021),
          throwsA(isA<StateError>()));
    });

    test('error message identifies the actual version (aids debugging)', () {
      try {
        WolfSshLibrary.validateNativeVersion(0x01004006);
        fail('expected throw');
      } on StateError catch (e) {
        expect(e.message, contains('0x01004006'));
        expect(e.message, contains('0x01005000'));
      }
    });

    test('minWolfSshVersionHex is at 1.5.0 (post CVE-2025-11625 fix)', () {
      expect(WolfSshLibrary.minWolfSshVersionHex, 0x01005000);
    });
  });
}

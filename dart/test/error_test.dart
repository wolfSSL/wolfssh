// Pure-Dart tests for the error mapping helpers. No native lib needed.

import 'package:test/test.dart';
import 'package:wolfssh/wolfssh.dart';

void main() {
  group('IoStatus pattern matching', () {
    test('positive byte count is IoCompleted', () {
      const status = IoCompleted(42);
      expect(status, isA<IoCompleted>());
      expect(status.bytes, 42);
    });

    test('IoEof is recognised in switch', () {
      const status = IoEof();
      var matched = false;
      switch (status) {
        case IoEof():
          matched = true;
        case IoCompleted():
        case IoWantRead():
        case IoWantWrite():
          break;
      }
      expect(matched, isTrue);
    });
  });

  test('WolfSshException toString includes context', () {
    final e = WolfSshException(-1066, 'WS_PUBKEY_REJECTED_E', 'connect');
    expect(e.toString(), contains('-1066'));
    expect(e.toString(), contains('WS_PUBKEY_REJECTED_E'));
    expect(e.toString(), contains('connect'));
  });
}

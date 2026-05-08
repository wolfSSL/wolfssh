import 'dart:ffi';
import 'dart:io';

import 'bindings/wolfssh.g.dart';

/// Resolves and loads the native wolfssh_dart shared library for the
/// current platform.
///
/// Lookup order:
///   1. Path supplied to [WolfSshLibrary.load].
///   2. WOLFSSH_DART_LIB environment variable (debug helper).
///   3. Platform-default library name (libwolfssh_dart.so / .dylib /
///      wolfssh_dart.dll). On iOS the symbols are statically linked into
///      the host binary, so we use [DynamicLibrary.process()].
class WolfSshLibrary {
  WolfSshLibrary._(this.bindings);

  final WolfSshBindings bindings;

  static WolfSshLibrary? _instance;

  /// Returns a process-wide singleton. wolfSSH's `wolfSSH_Init` must run
  /// exactly once per process, which the singleton enforces.
  static WolfSshLibrary load({String? overridePath}) {
    final cached = _instance;
    if (cached != null) {
      return cached;
    }
    final lib = _open(overridePath);
    final bindings = WolfSshBindings(lib);
    final initRc = bindings.init();
    if (initRc != 0) {
      throw StateError('wolfSSH_Init failed (rc=$initRc)');
    }
    final created = WolfSshLibrary._(bindings);
    _instance = created;
    return created;
  }

  static DynamicLibrary _open(String? overridePath) {
    final envPath = Platform.environment['WOLFSSH_DART_LIB'];
    final explicit = overridePath ?? envPath;
    if (explicit != null && explicit.isNotEmpty) {
      return DynamicLibrary.open(explicit);
    }
    if (Platform.isIOS) {
      return DynamicLibrary.process();
    }
    if (Platform.isMacOS) {
      return DynamicLibrary.open('libwolfssh_dart.dylib');
    }
    if (Platform.isWindows) {
      return DynamicLibrary.open('wolfssh_dart.dll');
    }
    // Linux + Android.
    return DynamicLibrary.open('libwolfssh_dart.so');
  }
}

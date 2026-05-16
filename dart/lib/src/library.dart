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

  /// Minimum wolfSSH version this binding will load against. wolfSSH
  /// encodes its version as `0xMMmmmppp` where 1.5.0 == `0x01005000`.
  /// Set to the first release that contains the CVE-2025-11625 fix.
  static const int minWolfSshVersionHex = 0x01005000;

  /// Returns a singleton per Dart isolate. wolfSSH's `wolfSSH_Init` must
  /// run exactly once per process, but the Dart static field below is
  /// isolate-local. Production code that spawns multiple isolates and
  /// loads the binding in each must arrange for the bindings to be
  /// shared (e.g. via `Isolate.exit`), or accept that `wolfSSH_Init`
  /// will be called once per isolate. See SECURITY.md for the
  /// multi-isolate caveat.
  static WolfSshLibrary load({String? overridePath}) {
    final cached = _instance;
    if (cached != null) {
      return cached;
    }
    final lib = _open(overridePath);
    final bindings = WolfSshBindings(lib);
    validateNativeVersion(bindings.dartVersionHex());
    final initRc = bindings.init();
    if (initRc != 0) {
      throw StateError('wolfSSH_Init failed (rc=$initRc)');
    }
    final created = WolfSshLibrary._(bindings);
    _instance = created;
    return created;
  }

  /// Throws [StateError] if [hex] (the value returned by
  /// `wolfssh_dart_version_hex`) is older than [minWolfSshVersionHex].
  ///
  /// SECURITY: this is the binding's anti-downgrade gate. The native
  /// library exports a numeric version baked in at C compile time via
  /// `LIBWOLFSSH_VERSION_HEX`. If a stale `.so` from a pre-1.5.0 build
  /// is on the dynamic-linker search path, this check refuses to use
  /// it — every wolfSSH release before 1.5.0 is missing at least one
  /// of the host-key / KEX-state / pubkey-parser CVE fixes documented
  /// in SECURITY.md §9.
  static void validateNativeVersion(int hex) {
    if (hex < minWolfSshVersionHex) {
      throw StateError(
          'wolfSSH native library is too old: '
          '0x${hex.toRadixString(16).padLeft(8, '0')} '
          '< required 0x${minWolfSshVersionHex.toRadixString(16).padLeft(8, '0')}. '
          'Rebuild against wolfSSH v1.5.0-stable or newer (this binding '
          'refuses to load older binaries — see SECURITY.md).');
    }
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

// Hand-curated raw FFI bindings for the wolfSSH client subset.
//
// This file is committed (not auto-generated at install). To widen the
// surface, run `dart run ffigen --config ../../../ffigen.yaml`, but be aware
// that ffigen will produce the entire WOLFSSH_API surface (~157 functions);
// we keep this file intentionally small to limit the security audit area.
//
// Cross-references back to wolfSSH headers use file:line citations against
// wolfSSH v1.5.0-stable.

// ignore_for_file: non_constant_identifier_names, camel_case_types

import 'dart:ffi' as ffi;

// ─── Opaque handles ──────────────────────────────────────────────────────
final class WOLFSSH_CTX extends ffi.Opaque {}

final class WOLFSSH extends ffi.Opaque {}

// ─── Endpoint type (wolfssh/ssh.h:454-456) ───────────────────────────────
const int WOLFSSH_ENDPOINT_SERVER = 0;
const int WOLFSSH_ENDPOINT_CLIENT = 1;

// ─── User-auth message types (wolfssh/ssh.h:469-473, bitmask in API) ─────
const int WOLFSSH_USERAUTH_PASSWORD = 0x01;
const int WOLFSSH_USERAUTH_PUBLICKEY = 0x02;
const int WOLFSSH_USERAUTH_KEYBOARD = 0x04;
const int WOLFSSH_USERAUTH_NONE = 0x08;

// ─── User-auth result codes (wolfssh/ssh.h:476-485) ──────────────────────
// SECURITY: returning the wrong code from the user-auth callback is the
// most direct way to introduce an auth bypass. Always use the named
// constants here, never raw integers.
const int WOLFSSH_USERAUTH_SUCCESS = 0;
const int WOLFSSH_USERAUTH_FAILURE = 1;
const int WOLFSSH_USERAUTH_INVALID_AUTHTYPE = 2;
const int WOLFSSH_USERAUTH_INVALID_USER = 3;
const int WOLFSSH_USERAUTH_INVALID_PASSWORD = 4;
const int WOLFSSH_USERAUTH_REJECTED = 5;
const int WOLFSSH_USERAUTH_INVALID_PUBLICKEY = 6;
const int WOLFSSH_USERAUTH_PARTIAL_SUCCESS = 7;

// ─── Selected error codes (wolfssh/error.h) ──────────────────────────────
const int WS_SUCCESS = 0;
const int WS_FATAL_ERROR = -1001;
const int WS_BAD_ARGUMENT = -1002;
const int WS_MEMORY_E = -1003;
const int WS_BUFFER_E = -1004;
const int WS_WANT_READ = -1010;
const int WS_WANT_WRITE = -1011;
const int WS_EOF = -1031;
const int WS_REKEYING = -1035;
const int WS_CHANNEL_CLOSED = -1036;
const int WS_PUBKEY_REJECTED_E = -1066;

// ─── Format types (wolfssh/ssh.h:459-465) ────────────────────────────────
const int WOLFSSH_FORMAT_ASN1 = 0;
const int WOLFSSH_FORMAT_PEM = 1;
const int WOLFSSH_FORMAT_RAW = 2;
const int WOLFSSH_FORMAT_SSH = 3;
const int WOLFSSH_FORMAT_OPENSSH = 4;

// ─── WS_UserAuthData (wolfssh/ssh.h:307-365) ─────────────────────────────
//
// Represented field-by-field rather than nested unions to keep Dart-side
// code straightforward. Caller selects which sub-struct is valid via the
// `type` field.
final class WsUserAuthDataPassword extends ffi.Struct {
  external ffi.Pointer<ffi.Uint8> password;
  @ffi.Uint32()
  external int passwordSz;
  @ffi.Uint8()
  external int hasNewPassword;
  external ffi.Pointer<ffi.Uint8> newPassword;
  @ffi.Uint32()
  external int newPasswordSz;
}

final class WsUserAuthDataPublicKey extends ffi.Struct {
  external ffi.Pointer<ffi.Uint8> dataToSign;
  external ffi.Pointer<ffi.Uint8> publicKeyType;
  @ffi.Uint32()
  external int publicKeyTypeSz;
  external ffi.Pointer<ffi.Uint8> publicKey;
  @ffi.Uint32()
  external int publicKeySz;
  external ffi.Pointer<ffi.Uint8> privateKey;
  @ffi.Uint32()
  external int privateKeySz;
  @ffi.Uint8()
  external int hasSignature;
  external ffi.Pointer<ffi.Uint8> signature;
  @ffi.Uint32()
  external int signatureSz;
  @ffi.Uint8()
  external int isCertBitfield;
}

// Layout matches the C union { password; publicKey; }; we expose the raw
// bytes and let the wrapper inspect `type` before reading either view.
final class WsUserAuthData extends ffi.Struct {
  @ffi.Uint8()
  external int type;
  external ffi.Pointer<ffi.Uint8> username;
  @ffi.Uint32()
  external int usernameSz;
  external ffi.Pointer<ffi.Uint8> serviceName;
  @ffi.Uint32()
  external int serviceNameSz;
  external ffi.Pointer<ffi.Uint8> authName;
  @ffi.Uint32()
  external int authNameSz;
  // Union body: large enough for the bigger of the two variants. Read via
  // an explicit cast in the wrapper after checking `type`.
  @ffi.Array(112)
  external ffi.Array<ffi.Uint8> _unionBody;
}

// ─── Native function typedefs ────────────────────────────────────────────
typedef _WolfSshInitC = ffi.Int Function();
typedef WolfSshInitDart = int Function();

typedef _WolfSshCleanupC = ffi.Int Function();
typedef WolfSshCleanupDart = int Function();

typedef _WolfSshCtxNewC = ffi.Pointer<WOLFSSH_CTX> Function(
    ffi.Uint8 endpoint, ffi.Pointer<ffi.Void> heap);
typedef WolfSshCtxNewDart = ffi.Pointer<WOLFSSH_CTX> Function(
    int endpoint, ffi.Pointer<ffi.Void> heap);

typedef _WolfSshCtxFreeC = ffi.Void Function(ffi.Pointer<WOLFSSH_CTX>);
typedef WolfSshCtxFreeDart = void Function(ffi.Pointer<WOLFSSH_CTX>);

typedef _WolfSshNewC = ffi.Pointer<WOLFSSH> Function(ffi.Pointer<WOLFSSH_CTX>);
typedef WolfSshNewDart = ffi.Pointer<WOLFSSH> Function(
    ffi.Pointer<WOLFSSH_CTX>);

typedef _WolfSshFreeC = ffi.Void Function(ffi.Pointer<WOLFSSH>);
typedef WolfSshFreeDart = void Function(ffi.Pointer<WOLFSSH>);

typedef _WolfSshSetFdC = ffi.Int Function(ffi.Pointer<WOLFSSH>, ffi.Int);
typedef WolfSshSetFdDart = int Function(ffi.Pointer<WOLFSSH>, int);

typedef _WolfSshSetUsernameC = ffi.Int Function(
    ffi.Pointer<WOLFSSH>, ffi.Pointer<ffi.Char>);
typedef WolfSshSetUsernameDart = int Function(
    ffi.Pointer<WOLFSSH>, ffi.Pointer<ffi.Char>);

typedef _WolfSshConnectC = ffi.Int Function(ffi.Pointer<WOLFSSH>);
typedef WolfSshConnectDart = int Function(ffi.Pointer<WOLFSSH>);

typedef _WolfSshShutdownC = ffi.Int Function(ffi.Pointer<WOLFSSH>);
typedef WolfSshShutdownDart = int Function(ffi.Pointer<WOLFSSH>);

typedef _WolfSshStreamReadC = ffi.Int Function(
    ffi.Pointer<WOLFSSH>, ffi.Pointer<ffi.Uint8>, ffi.Uint32);
typedef WolfSshStreamReadDart = int Function(
    ffi.Pointer<WOLFSSH>, ffi.Pointer<ffi.Uint8>, int);

typedef _WolfSshStreamSendC = ffi.Int Function(
    ffi.Pointer<WOLFSSH>, ffi.Pointer<ffi.Uint8>, ffi.Uint32);
typedef WolfSshStreamSendDart = int Function(
    ffi.Pointer<WOLFSSH>, ffi.Pointer<ffi.Uint8>, int);

typedef _WolfSshGetErrorC = ffi.Int Function(ffi.Pointer<WOLFSSH>);
typedef WolfSshGetErrorDart = int Function(ffi.Pointer<WOLFSSH>);

typedef _WolfSshErrorToNameC = ffi.Pointer<ffi.Char> Function(ffi.Int);
typedef WolfSshErrorToNameDart = ffi.Pointer<ffi.Char> Function(int);

// User-auth callback: int (*)(byte type, WS_UserAuthData* data, void* ctx)
typedef WsCallbackUserAuthNative = ffi.Int Function(
    ffi.Uint8, ffi.Pointer<WsUserAuthData>, ffi.Pointer<ffi.Void>);

typedef _WolfSshSetUserAuthC = ffi.Void Function(
    ffi.Pointer<WOLFSSH_CTX>,
    ffi.Pointer<ffi.NativeFunction<WsCallbackUserAuthNative>>);
typedef WolfSshSetUserAuthDart = void Function(
    ffi.Pointer<WOLFSSH_CTX>,
    ffi.Pointer<ffi.NativeFunction<WsCallbackUserAuthNative>>);

typedef _WolfSshSetUserAuthCtxC = ffi.Void Function(
    ffi.Pointer<WOLFSSH>, ffi.Pointer<ffi.Void>);
typedef WolfSshSetUserAuthCtxDart = void Function(
    ffi.Pointer<WOLFSSH>, ffi.Pointer<ffi.Void>);

// Public-key check callback: int (*)(const byte* pubKey, word32 pubKeySz, void* ctx)
typedef WsCallbackPublicKeyCheckNative = ffi.Int Function(
    ffi.Pointer<ffi.Uint8>, ffi.Uint32, ffi.Pointer<ffi.Void>);

typedef _WolfSshCtxSetPublicKeyCheckC = ffi.Void Function(
    ffi.Pointer<WOLFSSH_CTX>,
    ffi.Pointer<ffi.NativeFunction<WsCallbackPublicKeyCheckNative>>);
typedef WolfSshCtxSetPublicKeyCheckDart = void Function(
    ffi.Pointer<WOLFSSH_CTX>,
    ffi.Pointer<ffi.NativeFunction<WsCallbackPublicKeyCheckNative>>);

typedef _WolfSshSetPublicKeyCheckCtxC = ffi.Void Function(
    ffi.Pointer<WOLFSSH>, ffi.Pointer<ffi.Void>);
typedef WolfSshSetPublicKeyCheckCtxDart = void Function(
    ffi.Pointer<WOLFSSH>, ffi.Pointer<ffi.Void>);

// Glue helpers from native/wolfssh_dart_glue.c
typedef _WolfSshDartVersionC = ffi.Pointer<ffi.Char> Function();
typedef WolfSshDartVersionDart = ffi.Pointer<ffi.Char> Function();

/// Lookup table for the symbols. The wrapper resolves each symbol once at
/// startup and reuses the resulting Dart function.
final class WolfSshBindings {
  WolfSshBindings(ffi.DynamicLibrary lib)
      : init = lib.lookupFunction<_WolfSshInitC, WolfSshInitDart>(
            'wolfSSH_Init'),
        cleanup = lib.lookupFunction<_WolfSshCleanupC, WolfSshCleanupDart>(
            'wolfSSH_Cleanup'),
        ctxNew = lib.lookupFunction<_WolfSshCtxNewC, WolfSshCtxNewDart>(
            'wolfSSH_CTX_new'),
        ctxFree = lib.lookupFunction<_WolfSshCtxFreeC, WolfSshCtxFreeDart>(
            'wolfSSH_CTX_free'),
        sshNew = lib.lookupFunction<_WolfSshNewC, WolfSshNewDart>(
            'wolfSSH_new'),
        sshFree = lib.lookupFunction<_WolfSshFreeC, WolfSshFreeDart>(
            'wolfSSH_free'),
        setFd = lib.lookupFunction<_WolfSshSetFdC, WolfSshSetFdDart>(
            'wolfSSH_set_fd'),
        setUsername =
            lib.lookupFunction<_WolfSshSetUsernameC, WolfSshSetUsernameDart>(
                'wolfSSH_SetUsername'),
        connect = lib.lookupFunction<_WolfSshConnectC, WolfSshConnectDart>(
            'wolfSSH_connect'),
        shutdown = lib.lookupFunction<_WolfSshShutdownC, WolfSshShutdownDart>(
            'wolfSSH_shutdown'),
        streamRead =
            lib.lookupFunction<_WolfSshStreamReadC, WolfSshStreamReadDart>(
                'wolfSSH_stream_read'),
        streamSend =
            lib.lookupFunction<_WolfSshStreamSendC, WolfSshStreamSendDart>(
                'wolfSSH_stream_send'),
        getError = lib.lookupFunction<_WolfSshGetErrorC, WolfSshGetErrorDart>(
            'wolfSSH_get_error'),
        errorToName =
            lib.lookupFunction<_WolfSshErrorToNameC, WolfSshErrorToNameDart>(
                'wolfSSH_ErrorToName'),
        setUserAuth =
            lib.lookupFunction<_WolfSshSetUserAuthC, WolfSshSetUserAuthDart>(
                'wolfSSH_SetUserAuth'),
        setUserAuthCtx = lib.lookupFunction<_WolfSshSetUserAuthCtxC,
            WolfSshSetUserAuthCtxDart>('wolfSSH_SetUserAuthCtx'),
        ctxSetPublicKeyCheck = lib.lookupFunction<
            _WolfSshCtxSetPublicKeyCheckC,
            WolfSshCtxSetPublicKeyCheckDart>('wolfSSH_CTX_SetPublicKeyCheck'),
        setPublicKeyCheckCtx = lib.lookupFunction<
            _WolfSshSetPublicKeyCheckCtxC,
            WolfSshSetPublicKeyCheckCtxDart>('wolfSSH_SetPublicKeyCheckCtx'),
        dartVersion = lib.lookupFunction<_WolfSshDartVersionC,
            WolfSshDartVersionDart>('wolfssh_dart_version');

  final WolfSshInitDart init;
  final WolfSshCleanupDart cleanup;
  final WolfSshCtxNewDart ctxNew;
  final WolfSshCtxFreeDart ctxFree;
  final WolfSshNewDart sshNew;
  final WolfSshFreeDart sshFree;
  final WolfSshSetFdDart setFd;
  final WolfSshSetUsernameDart setUsername;
  final WolfSshConnectDart connect;
  final WolfSshShutdownDart shutdown;
  final WolfSshStreamReadDart streamRead;
  final WolfSshStreamSendDart streamSend;
  final WolfSshGetErrorDart getError;
  final WolfSshErrorToNameDart errorToName;
  final WolfSshSetUserAuthDart setUserAuth;
  final WolfSshSetUserAuthCtxDart setUserAuthCtx;
  final WolfSshCtxSetPublicKeyCheckDart ctxSetPublicKeyCheck;
  final WolfSshSetPublicKeyCheckCtxDart setPublicKeyCheckCtx;
  final WolfSshDartVersionDart dartVersion;
}

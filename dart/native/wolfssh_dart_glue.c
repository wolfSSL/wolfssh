/* Minimal C-side glue for the Dart FFI binding.
 *
 * Most of the wolfSSH API can be called directly from Dart. This file only
 * holds helpers where Dart's FFI cannot easily express what's needed:
 *
 *   1. wolfssh_dart_set_default_io  - registers wolfSSH's built-in
 *      libc-socket I/O callbacks on a context. The Dart side passes a
 *      bare fd via wolfSSH_set_fd; on platforms where dart:io's Socket
 *      surfaces a numeric fd we let wolfSSH drive recv()/send() itself.
 *
 *   2. wolfssh_dart_version - compile-time version string for the loaded
 *      library, so the Dart side can refuse to run against an older binary
 *      (defence-in-depth against accidental ABI mismatch).
 *
 *   3. wolfssh_dart_fill_password - assigns the password pointer + size
 *      into the WS_UserAuthData union member. Dart cannot easily express
 *      a write into a tagged union member from inside an FFI struct, so
 *      this helper does the field assignment from C where the union
 *      layout is statically known to the compiler.
 */

#include <wolfssh/ssh.h>
#include <wolfssh/error.h>
#include <wolfssh/version.h>

#ifdef _WIN32
#  define WSD_EXPORT __declspec(dllexport)
#else
#  define WSD_EXPORT __attribute__((visibility("default")))
#endif

WSD_EXPORT const char* wolfssh_dart_version(void) {
    return LIBWOLFSSH_VERSION_STRING;
}

WSD_EXPORT unsigned int wolfssh_dart_version_hex(void) {
    return (unsigned int)LIBWOLFSSH_VERSION_HEX;
}

/* Returns 0 on success, or a negative WS_* error code.
 *
 * wolfSSH provides default recv/send wrappers internally that operate on
 * the fd set via wolfSSH_set_fd. This helper exists so the Dart side
 * doesn't need to FFI the WS_CallbackIORecv/Send typedefs at all for the
 * common case. */
WSD_EXPORT int wolfssh_dart_use_default_io(WOLFSSH_CTX* ctx) {
    if (ctx == NULL) {
        return WS_BAD_ARGUMENT;
    }
    /* No-op on current wolfSSH: the default I/O callbacks are wired by
     * wolfSSH_CTX_new. This stub exists so a future change can opt the
     * binding out of the default without breaking the Dart API. */
    (void)ctx;
    return WS_SUCCESS;
}

/* Fill the password slot of a WS_UserAuthData from the user-auth callback.
 *
 * SECURITY: caller (the Dart trampoline) is responsible for keeping
 * `password` alive at least until wolfSSH_connect returns. The Dart side
 * holds the buffer in a long-lived allocation owned by WolfSshContext and
 * zeroes it on dispose. wolfSSH copies the bytes into its outbound
 * USERAUTH_REQUEST packet synchronously inside the callback dispatcher,
 * but a future upstream change could in principle defer the copy; if you
 * are reading this comment because of a use-after-free, audit the buffer
 * lifetime in lib/src/context.dart::_ensurePasswordBuffer.
 *
 * Returns 0 on success, WS_BAD_ARGUMENT on null inputs. The function
 * does NOT validate `passwordSz` against the protocol limit; that is the
 * Dart-side checkBufferLen helper's job. */
WSD_EXPORT int wolfssh_dart_fill_password(
        WS_UserAuthData* data,
        const unsigned char* password,
        unsigned int passwordSz) {
    if (data == NULL || password == NULL) {
        return WS_BAD_ARGUMENT;
    }
    /* `data->sf.password.password` is `byte*` not `const byte*` in the
     * wolfSSH ABI; the cast is safe because wolfSSH only reads from it. */
    data->sf.password.password = (unsigned char*)password;
    data->sf.password.passwordSz = passwordSz;
    return WS_SUCCESS;
}


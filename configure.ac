# wolfssh
# Copyright (C) 2014-2019 wolfSSL Inc.
# All right reserved.

AC_COPYRIGHT([Copyright (C) 2014-2019 wolfSSL Inc.])
AC_INIT([wolfssh],[1.4.2],[support@wolfssl.com],[wolfssh],[https://www.wolfssl.com])
AC_PREREQ([2.63])
AC_CONFIG_AUX_DIR([build-aux])

: ${CFLAGS=""}
# Test ar for the "U" option. Should be checked before the libtool macros.
xxx_ar_flags=$(ar --help 2>&1)
AS_CASE([$xxx_ar_flags],[*'use actual timestamps and uids/gids'*],[: ${AR_FLAGS="Ucru"}])

AC_CANONICAL_HOST

AM_INIT_AUTOMAKE([1.11 -Wall -Werror -Wno-portability foreign tar-ustar subdir-objects no-define color-tests])

AC_ARG_PROGRAM
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS([src/config.h])

WOLFSSH_LIBRARY_VERSION=9:0:0
#                       | | |
#                +------+ | +---+
#                |        |     |
#               current:revision:age
#                |        |     |
#                |        |     +- increment if interfaces have been added
#                |        |        set to zero if interfaces have been removed
#                |        |        or changed
#                |        +- increment if source code has changed
#                |           set to zero if current is incremented
#                +- increment if interfaces have been added, removed or changed
AC_SUBST([WOLFSSH_LIBRARY_VERSION])

LT_PREREQ([2.2])
LT_INIT([disable-static win32-dll])

gl_VISIBILITY
AS_IF([test -n "$CFLAG_VISIBILITY"],[AM_CFLAGS="$AM_CFLAGS $CFLAG_VISIBILITY"])

# silent
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

# Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_INSTALL

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_SIZEOF([long long])
AC_CHECK_SIZEOF([long])

# Check headers/libs
AC_CHECK_FUNCS([gethostbyname getaddrinfo gettimeofday inet_ntoa memset socket])
AC_CHECK_LIB([network],[socket])
AC_CHECK_LIB([wolfssl],[wolfCrypt_Init],,[AC_MSG_ERROR([libwolfssl is required for ${PACKAGE}. It can be obtained from https://www.wolfssl.com/download.html/ .])])

# DEBUG
DEBUG_CFLAGS="-g -O0"
DEBUG_CPPFLAGS="-DDEBUG -DDEBUG_WOLFSSH"

AX_DEBUG
AS_IF([test "x$ax_enable_debug" = "xyes"],
      [AM_CFLAGS="$DEBUG_CFLAGS $AM_CFLAGS"
       AM_CPPFLAGS="$DEBUG_CPPFLAGS $AM_CPPFLAGS"],
      [AM_CFLAGS="$AM_CFLAGS -O2"
       AM_CPPFLAGS="-DNDEBUG $AM_CPPFLAGS"])

AX_PTHREAD([
    # If AX_PTHREAD is adding -Qunused-arguments, need to prepend with
    # -Xcompiler libtool will use it. Newer versions of clang don't need
    # the -Q flag when using pthreads.
    AS_CASE([$PTHREAD_CFLAGS],[-Qunused-arguments*],[PTHREAD_CFLAGS="-Xcompiler $PTHREAD_CFLAGS"])
    AM_CFLAGS="$AM_CFLAGS $PTHREAD_CFLAGS"])

# Inline Build
AC_ARG_ENABLE([inline],
    [AS_HELP_STRING([--disable-inline],[Disable inline functions (default: enabled)])],
    [ENABLED_INLINE=$enableval],[ENABLED_INLINE=yes])

# Examples Build
AC_ARG_ENABLE([examples],
    [AS_HELP_STRING([--disable-examples],[Disable examples (default: enabled)])],
    [ENABLED_EXAMPLES=$enableval],[ENABLED_EXAMPLES=yes])

# Key Generation
AC_ARG_ENABLE([keygen],
    [AS_HELP_STRING([--enable-keygen],[Enable key generation (default: disabled)])],
    [ENABLED_KEYGEN=$enableval],[ENABLED_KEYGEN=no])

# SCP
AC_ARG_ENABLE([scp],
    [AS_HELP_STRING([--enable-scp],[Enable scp support (default: disabled)])],
    [ENABLED_SCP=$enableval],[ENABLED_SCP=no])

# SFTP
AC_ARG_ENABLE([sftp],
    [AS_HELP_STRING([--enable-sftp],[Enable SFTP support (default: disabled)])],
    [ENABLED_SFTP=$enableval],[ENABLED_SFTP=no])

# TCP/IP Forwarding
AC_ARG_ENABLE([fwd],
    [AS_HELP_STRING([--enable-fwd],[Enable TCP/IP Forwarding support (default: disabled)])],
    [ENABLED_FWD=$enableval],[ENABLED_FWD=no])

# pseudo-terminal
AC_ARG_ENABLE([term],
    [AS_HELP_STRING([--enable-term],[Enable pseudo-terminal support (default: enabled)])],
    [ENABLED_PTERM=$enableval],[ENABLED_PTERM=yes])

# Enable All
AC_ARG_ENABLE([all],
    [AS_HELP_STRING([--enable-all],[Enable all wolfSSH features (default: disabled)])],
    [ENABLED_ALL=$enableval],[ENABLED_ALL=no])

# Distro build
AC_ARG_ENABLE([distro],
    [AS_HELP_STRING([--enable-distro],[Enable wolfSSH distro build (default: disabled)])],
    [ENABLED_DISTRO=$enableval],[ENABLED_DISTRO=no])

AS_IF([test "x$ENABLED_DISTRO" = "xyes"],
      [ENABLED_ALL=yes; enable_shared=yes; enable_static=yes])
AS_IF([test "x$ENABLED_ALL" = "xyes"],
      [ENABLED_KEYGEN=yes; ENABLED_SCP=yes; ENABLED_SFTP=yes; ENABLED_FWD=yes])
AS_IF([test "x$ENABLED_INLINE" = "xno"],
      [AM_CPPFLAGS="$AM_CPPFLAGS -DNO_INLINE"])
AS_IF([test "x$ENABLED_KEYGEN" = "xyes"],
      [AM_CPPFLAGS="$AM_CPPFLAGS -DWOLFSSH_KEYGEN"])
AS_IF([test "x$ENABLED_SCP" = "xyes"],
      [AM_CPPFLAGS="$AM_CPPFLAGS -DWOLFSSH_SCP"])
AS_IF([test "x$ENABLED_SFTP" = "xyes"],
      [AM_CPPFLAGS="$AM_CPPFLAGS -DWOLFSSH_SFTP"])
AS_IF([test "x$ENABLED_FWD" = "xyes"],
      [AM_CPPFLAGS="$AM_CPPFLAGS -DWOLFSSH_FWD"])
AS_IF([test "x$ENABLED_PTERM" = "xyes"],
      [AM_CPPFLAGS="$AM_CPPFLAGS -DWOLFSSH_TERM"])

AM_CONDITIONAL([BUILD_EXAMPLE_SERVERS],[test "x$ENABLED_EXAMPLES" = "xyes"])
AM_CONDITIONAL([BUILD_EXAMPLE_CLIENTS],[test "x$ENABLED_EXAMPLES" = "xyes"])
AM_CONDITIONAL([BUILD_INLINE],[test "x$ENABLED_INLINE" = "xyes"])
AM_CONDITIONAL([BUILD_KEYGEN],[test "x$ENABLED_KEYGEN" = "xyes"])
AM_CONDITIONAL([BUILD_SCP],[test "x$ENABLED_SCP" = "xyes"])
AM_CONDITIONAL([BUILD_SFTP],[test "x$ENABLED_SFTP" = "xyes"])
AM_CONDITIONAL([BUILD_FWD],[test "x$ENABLED_FWD" = "xyes"])
AM_CONDITIONAL([BUILD_TERM],[test "x$ENABLED_TERM" = "xyes"])

# Checks for typedefs, structures, and compiler characteristics.
if test "$ac_cv_sizeof_long" = "8"; then
    AM_CPPFLAGS="$AM_CPPFLAGS -DSIZEOF_LONG=8"
else
    if test "$ac_cv_sizeof_long_long" = "8"; then
        AM_CPPFLAGS="$AM_CPPFLAGS -DSIZEOF_LONG_LONG=8"
    fi
fi

# HARDEN FLAGS
AX_HARDEN_CC_COMPILER_FLAGS

CREATE_HEX_VERSION
AC_SUBST([AM_CPPFLAGS])
AC_SUBST([AM_CFLAGS])
AC_SUBST([AM_LDFLAGS])

# FINAL
AC_CONFIG_FILES([Makefile wolfssh/version.h])

AX_CREATE_GENERIC_CONFIG
AX_AM_JOBSERVER([yes])

AC_OUTPUT

# force make clean
echo "---"
echo "Running make clean..."
make clean >/dev/null 2>&1

# output config summary
echo "---"
echo "Configuration summary for $PACKAGE_NAME version $VERSION"
echo ""
echo "   * Installation prefix:       $prefix"
echo "   * System type:               $host_vendor-$host_os"
echo "   * Host CPU:                  $host_cpu"
echo "   * C Compiler:                $CC"
echo "   * C Flags:                   $CFLAGS"
echo "   * CPP Flags:                 $CPPFLAGS"
echo "   * Linker Flags:              $LDFLAGS"
echo
echo "   Features"
echo "   * Inline Code:               $ENABLED_INLINE"
echo "   * keygen:                    $ENABLED_KEYGEN"
echo "   * psuedo-terminal:           $ENABLED_PTERM"
echo "   * scp:                       $ENABLED_SCP"
echo "   * sftp:                      $ENABLED_SFTP"
echo "   * TCP/IP Forwarding:         $ENABLED_FWD"
echo "   * Examples:                  $ENABLED_EXAMPLES"

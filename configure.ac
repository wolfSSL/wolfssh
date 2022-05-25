# wolfssh
# Copyright (C) 2014-2020 wolfSSL Inc.
# All right reserved.

AC_COPYRIGHT([Copyright (C) 2014-2020 wolfSSL Inc.])
AC_INIT([wolfssh],[1.4.10],[support@wolfssl.com],[wolfssh],[https://www.wolfssl.com])
AC_PREREQ([2.63])
AC_CONFIG_AUX_DIR([build-aux])

: ${CFLAGS=""}

AC_CANONICAL_HOST
AC_CANONICAL_TARGET

AM_INIT_AUTOMAKE([1.11 -Wall -Werror -Wno-portability foreign tar-ustar subdir-objects no-define color-tests])

AC_ARG_PROGRAM
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS([config.h])

WOLFSSH_LIBRARY_VERSION=12:4:4
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

# Checks for type sizes.
AC_CHECK_SIZEOF([long long])
AC_CHECK_SIZEOF([long])
AC_CHECK_SIZEOF([off_t])

# Check headers/libs
AC_CHECK_HEADERS([sys/select.h sys/time.h pty.h util.h termios.h])
AC_CHECK_LIB([network],[socket])
AC_CHECK_LIB([util],[forkpty])

# liboqs
ENABLED_LIBOQS="no"
tryliboqsdir=""
AC_ARG_WITH([liboqs],
    [AS_HELP_STRING([--with-liboqs=PATH],[Path to liboqs install (default /usr/local) EXPERIMENTAL!])],
    [
        AC_MSG_CHECKING([for liboqs])
        CPPFLAGS="$CPPFLAGS -DWOLFSSH_HAVE_LIBOQS"
        LIBS="$LIBS -loqs"

        AC_LINK_IFELSE([AC_LANG_PROGRAM([[#include <oqs/common.h>]], [[ OQS_init(); ]])], [ liboqs_linked=yes ],[ liboqs_linked=no ])

        if test "x$liboqs_linked" = "xno" ; then
            if test "x$withval" != "xno" ; then
                tryliboqsdir=$withval
            fi
            if test "x$withval" = "xyes" ; then
                tryliboqsdir="/usr/local"
            fi

            LDFLAGS="$AM_LDFLAGS $LDFLAGS -L$tryliboqsdir/lib"
            CPPFLAGS="$CPPFLAGS -I$tryliboqsdir/include"

            AC_LINK_IFELSE([AC_LANG_PROGRAM([[#include <oqs/common.h>]], [[ OQS_init(); ]])], [ liboqs_linked=yes ],[ liboqs_linked=no ])

            if test "x$liboqs_linked" = "xno" ; then
                AC_MSG_ERROR([liboqs isn't found.
                If it's already installed, specify its path using --with-liboqs=/dir/])
            fi
            AC_MSG_RESULT([yes])
            AM_LDFLAGS="$AM_LDFLAGS -L$tryliboqsdir/lib"
        else
            AC_MSG_RESULT([yes])
        fi

        AM_CFLAGS="$AM_CFLAGS -DWOLFSSH_HAVE_LIBOQS"
        ENABLED_LIBOQS="yes"
    ]
)

#wolfssl
AC_MSG_CHECKING([for wolfSSL])
if test "x$prefix" = "xNONE"
then
    wcpath=$ac_default_prefix
else
    wcpath=$prefix
fi
AC_MSG_NOTICE([prefix ${prefix}])
WOLFSSL_URL="http://www.wolfssl.com/download.html"
AC_ARG_WITH(wolfssl,
  [AS_HELP_STRING([--with-wolfssl=PATH], [PATH to wolfssl install (default /usr/local)])],
  [
    if test "x$withval" != "xno" ; then
      if test -d "${withval}/lib" && test -d "${withval}/include"; then
        wcpath=${withval}

        LDFLAGS="-L${wcpath}/lib $LDFLAGS"
        CPPFLAGS="-I${wcpath}/include $CPPFLAGS"
      else
        AC_MSG_ERROR([wolfSSL path error (${withval}): missing lib and include])
      fi
    fi
  ]
)

AC_CHECK_LIB([wolfssl],[wolfCrypt_Init],,[AC_MSG_ERROR([libwolfssl is required for ${PACKAGE}. It can be obtained from https://www.wolfssl.com/download.html/ .])])
AC_CHECK_FUNCS([gethostbyname getaddrinfo gettimeofday inet_ntoa memset socket wc_ecc_set_rng])
AC_CHECK_DECLS([[pread],[pwrite]],,[unistd.h])

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

AX_AM_JOBSERVER([yes])

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

# SSHD
AC_ARG_ENABLE([sshd],
    [AS_HELP_STRING([--enable-sshd],[Enable SSHD support (default: disabled)])],
    [ENABLED_SSHD=$enableval],[ENABLED_SSHD=no])

# TCP/IP Forwarding
AC_ARG_ENABLE([fwd],
    [AS_HELP_STRING([--enable-fwd],[Enable TCP/IP Forwarding support (default: disabled)])],
    [ENABLED_FWD=$enableval],[ENABLED_FWD=no])

# pseudo-terminal
AC_ARG_ENABLE([term],
    [AS_HELP_STRING([--disable-term],[Disable pseudo-terminal support (default: enabled)])],
    [ENABLED_PTERM=$enableval],[ENABLED_PTERM=yes])

# shell support
AC_ARG_ENABLE([shell],
    [AS_HELP_STRING([--enable-shell],[Enable echoserver shell support (default: disabled)])],
    [ENABLED_SHELL=$enableval],[ENABLED_SHELL=no])

# ssh-agent
AC_ARG_ENABLE([agent],
    [AS_HELP_STRING([--enable-agent],[Enable ssh-agent support (default: disabled)])],
    [ENABLED_AGENT=$enableval],[ENABLED_AGENT=no])

# smallstack
AC_ARG_ENABLE([smallstack],
    [AS_HELP_STRING([--enable-smallstack],[Enable small stack (default: disabled)])],
    [ENABLED_SMALLSTACK=$enableval],[ENABLED_SMALLSTACK=no])

# Enable All
AC_ARG_ENABLE([all],
    [AS_HELP_STRING([--enable-all],[Enable all wolfSSH features (default: disabled)])],
    [ENABLED_ALL=$enableval],[ENABLED_ALL=no])

# Distro build
AC_ARG_ENABLE([distro],
    [AS_HELP_STRING([--enable-distro],[Enable wolfSSH distro build (default: disabled)])],
    [ENABLED_DISTRO=$enableval],[ENABLED_DISTRO=no])

# Update the ENABLED flags for options that affect other options.
AS_IF([test "x$ENABLED_DISTRO" = "xyes"],
      [ENABLED_ALL=yes; enable_shared=yes; enable_static=yes])
AS_IF([test "x$ENABLED_ALL" = "xyes"],
      [ENABLED_KEYGEN=yes; ENABLED_SCP=yes; ENABLED_SFTP=yes; ENABLED_FWD=yes; ENABLED_SHELL=yes; ENABLED_AGENT=yes])

# Set the defined flags for the code.
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
AS_IF([test "x$ENABLED_SHELL" = "xyes"],
      [AM_CPPFLAGS="$AM_CPPFLAGS -DWOLFSSH_SHELL"])
AS_IF([test "x$ENABLED_AGENT" = "xyes"],[AM_CPPFLAGS="$AM_CPPFLAGS -DWOLFSSH_AGENT"])
AS_IF([test "x$ENABLED_SMALLSTACK" = "xyes"],
       [AM_CPPFLAGS="$AM_CPPFLAGS -DWOLFSSH_SMALL_STACK"])
AS_IF([test "x$ENABLED_SSHD" = "xyes"],
       [AM_CPPFLAGS="$AM_CPPFLAGS -DWOLFSSH_SSHD"])

# Set the automake conditionals.
AM_CONDITIONAL([BUILD_EXAMPLE_SERVERS],[test "x$ENABLED_EXAMPLES" = "xyes"])
AM_CONDITIONAL([BUILD_EXAMPLE_CLIENTS],[test "x$ENABLED_EXAMPLES" = "xyes"])
AM_CONDITIONAL([BUILD_INLINE],[test "x$ENABLED_INLINE" = "xyes"])
AM_CONDITIONAL([BUILD_KEYGEN],[test "x$ENABLED_KEYGEN" = "xyes"])
AM_CONDITIONAL([BUILD_SCP],[test "x$ENABLED_SCP" = "xyes"])
AM_CONDITIONAL([BUILD_SFTP],[test "x$ENABLED_SFTP" = "xyes"])
AM_CONDITIONAL([BUILD_FWD],[test "x$ENABLED_FWD" = "xyes"])
AM_CONDITIONAL([BUILD_TERM],[test "x$ENABLED_TERM" = "xyes"])
AM_CONDITIONAL([BUILD_SHELL],[test "x$ENABLED_SHELL" = "xyes"])
AM_CONDITIONAL([BUILD_AGENT],[test "x$ENABLED_AGENT" = "xyes"])
AM_CONDITIONAL([BUILD_SSHD],[test "x$ENABLED_SSHD" = "xyes"])

AX_HARDEN_CC_COMPILER_FLAGS

CREATE_HEX_VERSION
AC_SUBST([AM_CPPFLAGS])
AC_SUBST([AM_CFLAGS])
AC_SUBST([AM_LDFLAGS])

# FINAL
AC_CONFIG_FILES([Makefile wolfssh/version.h])

AX_CREATE_GENERIC_CONFIG

AC_OUTPUT

# force make clean
AS_ECHO(["---"])
AS_ECHO(["Running make clean..."])
make clean >/dev/null 2>&1

# output config summary
AS_ECHO(["---"])
AS_ECHO(["Configuration summary for $PACKAGE_NAME version $VERSION"])
AS_ECHO
AS_ECHO(["   * Installation prefix:       $prefix"])
AS_ECHO(["   * System type:               $host_vendor-$host_os"])
AS_ECHO(["   * Host CPU:                  $host_cpu"])
AS_ECHO(["   * C Compiler:                $CC"])
AS_ECHO(["   * C Flags:                   $CFLAGS"])
AS_ECHO(["   * CPP Flags:                 $CPPFLAGS"])
AS_ECHO(["   * Linker Flags:              $LDFLAGS"])
AS_ECHO
AS_ECHO(["   Features"])
AS_ECHO(["   * Inline Code:               $ENABLED_INLINE"])
AS_ECHO(["   * Small stack:               $ENABLED_SMALLSTACK"])
AS_ECHO(["   * keygen:                    $ENABLED_KEYGEN"])
AS_ECHO(["   * psuedo-terminal:           $ENABLED_PTERM"])
AS_ECHO(["   * echoserver shell support:  $ENABLED_SHELL"])
AS_ECHO(["   * scp:                       $ENABLED_SCP"])
AS_ECHO(["   * sftp:                      $ENABLED_SFTP"])
AS_ECHO(["   * sshd:                      $ENABLED_SSHD"])
AS_ECHO(["   * agent:                     $ENABLED_AGENT"])
AS_ECHO(["   * TCP/IP Forwarding:         $ENABLED_FWD"])
AS_ECHO(["   * Examples:                  $ENABLED_EXAMPLES"])
AS_ECHO(["   * liboqs Integration:        $ENABLED_LIBOQS"])

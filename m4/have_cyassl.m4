
#--------------------------------------------------------------------
# Check for libcyassl
#--------------------------------------------------------------------


AC_DEFUN([_TAO_SEARCH_LIBCYASSL],[
  AC_REQUIRE([AC_LIB_PREFIX])

  LIBS="$LIBS -lcyassl"

  AC_LIB_HAVE_LINKFLAGS([cyassl], ,
  [
    #include <cyassl/ssl.h>
  ],[
    CyaSSL_Init();
  ]) 

  AM_CONDITIONAL(HAVE_LIBCYASSL, [test "x${ac_cv_libcyassl}" = "xyes"])

  AS_IF([test "x${ac_cv_libcyassl}" = "xyes"],[
    save_LIBS="${LIBS}"
    LIBS="${LIBS} ${LTLIBCYASSL}"
    AC_CHECK_FUNCS(CyaSSL_Cleanup)
    LIBS="$save_LIBS"
  ])
])

AC_DEFUN([_TAO_HAVE_LIBCYASSL],[

  AC_ARG_ENABLE([libcyassl],
    [AS_HELP_STRING([--disable-libcyassl],
      [Build with libcyassl support @<:@default=on@:>@])],
    [ac_enable_libcyassl="$enableval"],
    [ac_enable_libcyassl="yes"])

  _TAO_SEARCH_LIBCYASSL
])


AC_DEFUN([TAO_HAVE_LIBCYASSL],[
  AC_REQUIRE([_TAO_HAVE_LIBCYASSL])
])

AC_DEFUN([_TAO_REQUIRE_LIBCYASSL],[
  ac_enable_libcyassl="yes"
  _TAO_SEARCH_LIBCYASSL

  AS_IF([test x$ac_cv_libcyassl = xno],[
    AC_MSG_ERROR([libcyassl is required for ${PACKAGE}. It can be obtained from http://www.wolfssl.com/download.html/])
  ])
])

AC_DEFUN([TAO_REQUIRE_LIBCYASSL],[
  AC_REQUIRE([_TAO_REQUIRE_LIBCYASSL])
])

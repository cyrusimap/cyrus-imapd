dnl libwrap.m4 --- do we have libwrap, the access control library?

AC_DEFUN(CMU_LIBWRAP, [
  AC_ARG_WITH(libwrap, 
              [  --with-libwrap=DIR      use libwrap (rooted in DIR) [yes] ],
              with_libwrap=$withval, with_libwrap=yes)
  if test "$with_libwrap" != no; then
    if test -d "$with_libwrap"; then
      CPPFLAGS="$CPPFLAGS -I${with_libwrap}/include"
      LDFLAGS="$LDFLAGS -L${with_libwrap}/lib"
    fi
    cmu_save_LIBS="$LIBS"
    AC_CHECK_LIB(wrap, request_init,
		 AC_CHECK_HEADER(tcpd.h,, with_libwrap=no),
		 with_libwrap=no)
    LIBS="$cmu_save_LIBS"
  fi
  AC_MSG_CHECKING(libwrap support)
  AC_MSG_RESULT($with_libwrap)
  LIB_WRAP=""
  if test "$with_libwrap" != no; then
    AC_DEFINE(HAVE_LIBWRAP)
    LIB_WRAP="-lwrap"
  fi
  AC_SUBST(LIB_WRAP)
])

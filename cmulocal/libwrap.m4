dnl libwrap.m4 --- do we have libwrap, the access control library?
dnl $Id: libwrap.m4,v 1.10 2005/04/26 19:14:08 shadow Exp $

AC_DEFUN([CMU_LIBWRAP], [
AC_REQUIRE([CMU_FIND_LIB_SUBDIR])
  AC_REQUIRE([CMU_SOCKETS])
  AC_ARG_WITH(libwrap, 
              [  --with-libwrap=DIR      use libwrap (rooted in DIR) [yes] ],
              with_libwrap=$withval, with_libwrap=yes)
  if test "$with_libwrap" != no; then
    if test -d "$with_libwrap"; then
      CPPFLAGS="$CPPFLAGS -I${with_libwrap}/include"
      LDFLAGS="$LDFLAGS -L${with_libwrap}/$CMU_LIB_SUBDIR"
    fi
    cmu_save_LIBS="$LIBS"
    AC_CHECK_LIB(wrap, request_init, [
		 AC_CHECK_HEADER(tcpd.h,, with_libwrap=no)],
		 with_libwrap=no, ${LIB_SOCKET})
    LIBS="$cmu_save_LIBS"
  fi
  AC_MSG_CHECKING(libwrap support)
  AC_MSG_RESULT($with_libwrap)
  LIB_WRAP=""
  if test "$with_libwrap" != no; then
    AC_DEFINE(HAVE_LIBWRAP,[],[Do we have TCP wrappers?])
    LIB_WRAP="-lwrap"
    AC_CHECK_LIB(nsl, yp_get_default_domain, LIB_WRAP="${LIB_WRAP} -lnsl")
  fi
  AC_SUBST(LIB_WRAP)
])

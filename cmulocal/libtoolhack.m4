dnl libtoolhack.m4--hack to make libtool behave better
dnl Rob Earhart
dnl $Id: libtoolhack.m4,v 1.3 2002/05/25 19:57:42 leg Exp $

dnl Libtool tries to compile an empty file to see whether it can build
dnl shared libraries, and treats *any* warning as a problem.
dnl Solaris's and HP's cc complains about the empty file.  So we hack
dnl the CFLAGS to make cc not complain.

AC_DEFUN(CMU_PROG_LIBTOOL, [
AC_REQUIRE([AC_PROG_CC])
if test "$ac_cv_prog_gcc" = no; then
  case "$host_os" in
    solaris2*)
      save_cflags="${CFLAGS}"
      CFLAGS="-erroff=E_EMPTY_TRANSLATION_UNIT ${CFLAGS}"
      ;;
    hpux*)
      save_cflags="${CFLAGS}"
      CFLAGS="-w"
      ;;
  esac
fi

AM_PROG_LIBTOOL

if test "$ac_cv_prog_gcc" = no; then
  case "$host_os" in
    solaris2*|hpux*)
      CFLAGS="${save_cflags}"
  esac
fi
])

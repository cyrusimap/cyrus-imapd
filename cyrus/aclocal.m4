dnl aclocal.m4 generated automatically by aclocal 1.4

dnl Copyright (C) 1994, 1995-8, 1999 Free Software Foundation, Inc.
dnl This file is free software; the Free Software Foundation
dnl gives unlimited permission to copy and/or distribute it,
dnl with or without modifications, as long as this notice is preserved.

dnl This program is distributed in the hope that it will be useful,
dnl but WITHOUT ANY WARRANTY, to the extent permitted by law; without
dnl even the implied warranty of MERCHANTABILITY or FITNESS FOR A
dnl PARTICULAR PURPOSE.

dnl
dnl Additional macros for configure.in packaged up for easier theft.
dnl tjs@andrew.cmu.edu 6-may-1998
dnl

dnl It would be good if ANDREW_ADD_LIBPATH could detect if something was
dnl already there and not redundantly add it if it is.

dnl add -L(arg), and possibly (runpath switch)(arg), to LDFLAGS
dnl (so the runpath for shared libraries is set).
AC_DEFUN(CMU_ADD_LIBPATH, [
  # this is CMU ADD LIBPATH
  if test "$andrew_runpath_switch" = "none" ; then
	LDFLAGS="-L$1 ${LDFLAGS}"
  else
	LDFLAGS="-L$1 $andrew_runpath_switch$1 ${LDFLAGS}"
  fi
])

dnl add -L(1st arg), and possibly (runpath switch)(1st arg), to (2nd arg)
dnl (so the runpath for shared libraries is set).
AC_DEFUN(CMU_ADD_LIBPATH_TO, [
  # this is CMU ADD LIBPATH TO
  if test "$andrew_runpath_switch" = "none" ; then
	$2="-L$1 ${$2}"
  else
	$2="-L$1 ${$2} $andrew_runpath_switch$1"
  fi
])

dnl runpath initialization
AC_DEFUN(CMU_GUESS_RUNPATH_SWITCH, [
   # CMU GUESS RUNPATH SWITCH
  AC_CACHE_CHECK(for runpath switch, andrew_runpath_switch, [
    # first, try -R
    SAVE_LDFLAGS="${LDFLAGS}"
    LDFLAGS="-R /usr/lib"
    AC_TRY_LINK([],[],[andrew_runpath_switch="-R"], [
  	LDFLAGS="-Wl,-rpath,/usr/lib"
    AC_TRY_LINK([],[],[andrew_runpath_switch="-Wl,-rpath,"],
    [andrew_runpath_switch="none"])
    ])
  LDFLAGS="${SAVE_LDFLAGS}"
  ])])

dnl sasl.m4--sasl libraries and includes
dnl Derrick Brashear
dnl from KTH sasl and Arla

AC_DEFUN(CMU_SASL_INC_WHERE1, [
AC_REQUIRE([AC_PROG_CC_GNU])
saved_CPPFLAGS=$CPPFLAGS
CPPFLAGS="$saved_CPPFLAGS -I$1"
CMU_CHECK_HEADER_NOCACHE(sasl.h,
ac_cv_found_sasl_inc=yes,
ac_cv_found_sasl_inc=no)
CPPFLAGS=$saved_CPPFLAGS
])

AC_DEFUN(CMU_SASL_INC_WHERE, [
   for i in $1; do
      CMU_SASL_INC_WHERE1($i)
      CMU_TEST_INCPATH($i, sasl)
      if test "$ac_cv_found_sasl_inc" = "yes"; then
        ac_cv_sasl_where_inc=$i
        break
      fi
    done
])

AC_DEFUN(CMU_SASL_LIB_WHERE1, [
AC_REQUIRE([AC_PROG_CC_GNU])
saved_LIBS=$LIBS
LIBS="$saved_LIBS -L$1 -lsasl"
AC_TRY_LINK(,
[sasl_getprop();],
[ac_cv_found_sasl_lib=yes],
ac_cv_found_sasl_lib=no)
LIBS=$saved_LIBS
])

AC_DEFUN(CMU_SASL_LIB_WHERE, [
   for i in $1; do
      CMU_SASL_LIB_WHERE1($i)
      dnl deal with false positives from implicit link paths
      CMU_TEST_LIBPATH($i, sasl)
      if test "$ac_cv_found_sasl_lib" = "yes" ; then
        ac_cv_sasl_where_lib=$i
        break
      fi
    done
])

AC_DEFUN(CMU_SASL, [
AC_ARG_WITH(sasl,
            [  --with-sasl=DIR        Compile with libsasl in <DIR>],
	    with_sasl="$withval",
            with_sasl="yes")

	SASLFLAGS=""
	LIB_SASL=""

	cmu_saved_CPPFLAGS=$CPPFLAGS
	cmu_saved_LDFLAGS=$LDFLAGS
	cmu_saved_LIBS=$LIBS
	if test -d ${with_sasl}; then
          ac_cv_sasl_where_lib=${with_sasl}/lib
          ac_cv_sasl_where_inc=${with_sasl}/include

	  SASLFLAGS="-I$ac_cv_sasl_where_inc"
	  LIB_SASL="-L$ac_cv_sasl_where_lib"
	  CPPFLAGS="${cmu_saved_CPPFLAGS} -I${ac_cv_sasl_where_inc}"
	  LDFLAGS="${cmu_saved_LDFLAGS} -L${ac_cv_sasl_where_lib}"
	fi

	AC_CHECK_HEADER(sasl.h,
	  AC_CHECK_LIB(sasl, sasl_getprop, 
                       ac_cv_found_sasl=yes,
		       ac_cv_found_sasl=no), ac_cv_found_sasl=no)

	LIBS="$cmu_saved_LIBS"
	LDFLAGS="$cmu_saved_LDFLAGS"
	CPPFLAGS="$cmu_saved_CPPFLAGS"
	if test "$ac_cv_found_sasl" = yes; then
	  LIB_SASL="$LIB_SASL -lsasl"
	else
	  LIB_SASL=""
	  SASLFLAGS=""
	fi
	AC_SUBST(LIB_SASL)
	AC_SUBST(SASLFLAGS)
	])

AC_DEFUN(CMU_SASL_REQUIRED,
[AC_REQUIRE([CMU_SASL])
if test "$ac_cv_found_sasl" != "yes"; then
        AC_ERROR([Cannot continue without libsasl.
Get it from ftp://ftp.andrew.cmu.edu:/pub/cyrus-mail/.])
fi])

AC_DEFUN(CMU_TEST_LIBPATH, [
changequote(<<, >>)
define(<<CMU_AC_CV_FOUND>>, translit(ac_cv_found_$2_lib, [ *], [_p]))
changequote([, ])
if test "$CMU_AC_CV_FOUND" = "yes"; then
  if test \! -f "$1/lib$2.a" -a \! -f "$i/lib$2.so" -a \! -f "$i/lib$2.sl"; then
    CMU_AC_CV_FOUND=no
  fi
fi
])

AC_DEFUN(CMU_TEST_INCPATH, [
changequote(<<, >>)
define(<<CMU_AC_CV_FOUND>>, translit(ac_cv_found_$2_inc, [ *], [_p]))
changequote([, ])
if test "$CMU_AC_CV_FOUND" = "yes"; then
  if test \! -f "$1/$2.h"; then
    CMU_AC_CV_FOUND=no
  fi
fi
])

dnl CMU_CHECK_HEADER_NOCACHE(HEADER-FILE, [ACTION-IF-FOUND [, ACTION-IF-NOT-FOUND]])
AC_DEFUN(CMU_CHECK_HEADER_NOCACHE,
[dnl Do the transliteration at runtime so arg 1 can be a shell variable.
ac_safe=`echo "$1" | sed 'y%./+-%__p_%'`
AC_MSG_CHECKING([for $1])
AC_TRY_CPP([#include <$1>], eval "ac_cv_header_$ac_safe=yes",
  eval "ac_cv_header_$ac_safe=no")
if eval "test \"`echo '$ac_cv_header_'$ac_safe`\" = yes"; then
  AC_MSG_RESULT(yes)
  ifelse([$2], , :, [$2])
else
  AC_MSG_RESULT(no)
ifelse([$3], , , [$3
])dnl
fi
])

dnl bsd_sockets.m4--which socket libraries do we need? 
dnl Derrick Brashear
dnl from Zephyr

dnl Hacked on by Rob Earhart to not just toss stuff in LIBS
dnl It now puts everything required for sockets into LIB_SOCKET

AC_DEFUN(CMU_SOCKETS, [
	LIB_SOCKET=""
	AC_CHECK_FUNC(connect, :,
		AC_CHECK_LIB(nsl, gethostbyname,
			     LIB_SOCKET="-lnsl $LIB_SOCKET")
		AC_CHECK_LIB(socket, connect,
			     LIB_SOCKET="-lsocket $LIB_SOCKET")
	)
	AC_SUBST(LIB_SOCKET)
	])

dnl libwrap.m4 --- do we have libwrap, the access control library?

AC_DEFUN(CMU_LIBWRAP, [
  AC_REQUIRE([CMU_SOCKETS])
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
		 with_libwrap=no, ${LIB_SOCKET})
    LIBS="$cmu_save_LIBS"
  fi
  AC_MSG_CHECKING(libwrap support)
  AC_MSG_RESULT($with_libwrap)
  LIB_WRAP=""
  if test "$with_libwrap" != no; then
    AC_DEFINE(HAVE_LIBWRAP)
    LIB_WRAP="-lwrap"
    AC_CHECK_LIB(nsl, yp_get_default_domain, LIB_WRAP="${LIB_WRAP} -lnsl")
  fi
  AC_SUBST(LIB_WRAP)
])

dnl look for the ucdsnmp libraries

AC_DEFUN(CMU_UCDSNMP, [
  AC_REQUIRE([CMU_SOCKETS])
  AC_ARG_WITH(ucdsnmp, 
              [  --with-ucdsnmp=DIR      use ucd snmp (rooted in DIR) [yes] ],
              with_ucdsnmp=$withval, with_ucdsnmp=yes)
  if test "$with_ucdsnmp" != no; then
    if test -d "$with_ucdsnmp"; then
      CPPFLAGS="$CPPFLAGS -I${with_ucdsnmp}/include"
      LDFLAGS="$LDFLAGS -L${with_ucdsnmp}/lib"
    fi
    cmu_save_LIBS="$LIBS"
    AC_CHECK_LIB(snmp, sprint_objid,
		 AC_CHECK_HEADER(ucd-snmp/version.h,, with_ucdsnmp=no),
		 with_ucdsnmp=no, ${LIB_SOCKET})
    LIBS="$cmu_save_LIBS"
  fi
  AC_MSG_CHECKING(UCD SNMP libraries)
  AC_MSG_RESULT($with_ucdsnmp)
  LIB_UCDSNMP=""
  if test "$with_ucdsnmp" != no; then
    AC_DEFINE(HAVE_UCDSNMP)
    LIB_UCDSNMP="-lucdagent -lucdmibs -lsnmp"
  fi
  AC_SUBST(LIB_UCDSNMP)
])


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

dnl agentx.m4--detect agentx libraries
dnl copied from x-unixrc
dnl Tim Martin

AC_DEFUN(CMU_AGENTX, [

	dnl
	dnl CMU AgentX
	dnl
	AC_MSG_CHECKING([for AgentX])
	AC_ARG_WITH(agentx, [  --with-agentx              CMU AgentX libraries located in (val)], AGENTX_DIR="$withval", AGENTX_DIR=no)

	found_agentx="no"

	if test "${AGENTX_DIR}" != "no" &&
	   test -f $AGENTX_DIR/lib${ABILIBDIR}/libagentx.a &&
	   test -f $AGENTX_DIR/include/agentx.h; then
	     AGENTX_DIR="$AGENTX_DIR"
	     found_agentx="yes"
	elif test -d /usr/local &&
	   test -f /usr/local/lib${ABILIBDIR}/libagentx.a &&
	   test -f /usr/local/include/agentx.h; then
	     AGENTX_DIR="/usr/local"
	     found_agentx="yes"

	elif test -d /usr/ng &&
	   test -f /usr/ng/lib${ABILIBDIR}/libagentx.a &&
	   test -f /usr/ng/include/agentx.h; then
	     AGENTX_DIR="/usr/ng"
	     found_agentx="yes"
	fi

	if test "$found_agentx" = "no"; then
	  AC_MSG_WARN([Could not locate AgentX Libraries! http://www.net.cmu.edu/groups/netdev/agentx/])
	else
	  LIB_AGENTX="-L$AGENTX_DIR/lib${ABILIBDIR} -lagentx"
  	  AC_SUBST(LIB_AGENTX)
	  AGENTXFLAGS="-I$AGENTX_DIR/include"
          AC_SUBST(AGENTXFLAGS)   
	  AC_MSG_RESULT([found $AGENTX_DIR/lib${ABILIBDIR}/libagentx.a])	
	fi



])
dnl pthreads.m4--pthreads setup macro
dnl Rob Earhart

AC_DEFUN(CMU_PTHREADS, [
   AC_REQUIRE([AC_CANONICAL_HOST])
   cmu_save_LIBS="$LIBS"
   AC_CHECK_LIB(pthread, pthread_create,LIB_PTHREAD="-lpthread",
     AC_CHECK_LIB(c_r, pthread_create,LIB_PTHREAD="-lc_r",
       AC_ERROR([Can't compile without pthreads])))
  LIBS="$cmu_save_LIBS"
   AC_SUBST(LIB_PTHREAD)
   AC_DEFINE(_REENTRANT)
   case "$host_os" in
   solaris2*)
 	AC_DEFINE(_POSIX_PTHREAD_SEMANTICS)
 	AC_DEFINE(__EXTENSIONS__)
 	;;
   irix6*)
 	AC_DEFINE(_SGI_REENTRANT_FUNCTIONS)
 	;;
   esac
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


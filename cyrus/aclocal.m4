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
dnl $Id: aclocal.m4,v 1.32 2000/04/25 04:42:11 leg Exp $
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

dnl sasl.m4--sasl detection macro
dnl Rob Earhart
dnl $Id: aclocal.m4,v 1.32 2000/04/25 04:42:11 leg Exp $

AC_DEFUN(CMU_SASL, [
  AC_ARG_WITH(sasldir,[  --with-sasldir=PATH     PATH where the sasl library is installed], sasldir="$withval")

  cmu_need_sasl=no
  if test -z "$sasldir"; then
    # look for it ourselves
    AC_CHECK_HEADER(sasl.h,
      cmu_save_LIBS="$LIBS"
      AC_CHECK_LIB(sasl, sasl_getprop,,cmu_need_sasl=yes)
      LIBS="$cmu_save_LIBS"
     ,cmu_need_sasl=yes)
    if test "$cmu_need_sasl" = yes; then
    AC_ERROR([Can't compile without libsasl
              (Get it from <url:ftp://ftp.andrew.cmu.edu:/pub/cyrus-mail/>).])
    fi
    LIB_SASL="-lsasl"
    AC_SUBST(LIB_SASL)
    SASLFLAGS=""
    AC_SUBST(SASLFLAGS)
  else
    # try the user-specified path --- too lazy to test for it right now
    LIB_SASL="-L$sasldir/lib -lsasl"
    AC_SUBST(LIB_SASL)
    SASLFLAGS="-I$sasldir/include"
    AC_SUBST(SASLFLAGS)    
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


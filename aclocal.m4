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
dnl $Id: aclocal.m4,v 1.21 2000/01/28 22:09:39 leg Exp $
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
dnl $Id: aclocal.m4,v 1.21 2000/01/28 22:09:39 leg Exp $

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


dnl util.m4--robutil macro
dnl Rob Earhart
dnl $Id: util.m4,v 1.10 2003/10/08 20:35:26 rjs3 Exp $

dnl robutil is a collection of stuff I (Rob Earhart) have found useful
dnl to have around when writing code; it's the stuff I wind up rewriting
dnl every time I start a project.  This does the autoconf setup
dnl necessary for it.

dnl This is a helper macro, here because there're times when I
dnl want to know if a type exists or not, but don't want to define
dnl it to something else (the way AC_CHECK_TYPE does).

AC_DEFUN([CMU_CHECK_TYPE_EXISTS], [
changequote(<<, >>)
define(<<CMU_TYPE_NAME>>, translit(CMU_HAVE_$1, [a-z *], [A-Z_P]))
define(<<CMU_CV_NAME>>, translit(cmu_cv_type_$1, [ *], [_p]))
changequote([, ])
  AC_REQUIRE([AC_HEADER_STDC])
  AC_MSG_CHECKING(for $1)
  AC_CACHE_VAL(CMU_CV_NAME, [
    AC_EGREP_CPP([$1[[^a-zA-Z_0-9]]], [
#include <sys/types.h>
#if STDC_HEADERS
#include <stdlib.h>
#include <stddef.h>
#endif
], CMU_CV_NAME=yes, CMU_CV_NAME=no)])
  AC_MSG_RESULT($CMU_CV_NAME)
  if test $CMU_CV_NAME = yes; then
    AC_DEFINE(CMU_TYPE_NAME)
  fi
])

AC_DEFUN([CMU_UTIL], [
  AC_REQUIRE([AC_PROG_CC])
  AC_REQUIRE([AM_PROG_CC_STDC])
  AC_REQUIRE([AC_PROG_RANLIB])
  AC_REQUIRE([CMU_NANA])
  AC_REQUIRE([CMU_COMERR])
  AC_REQUIRE([AC_HEADER_STDC])
  AC_REQUIRE([AC_TYPE_MODE_T])
  AC_REQUIRE([AC_C_CONST])
  AC_CHECK_HEADERS(sys/sysmacros.h)
  AC_CHECK_HEADER(inttypes.h, AC_DEFINE(HAVE_INTTYPES_H),
		  CMU_CHECK_TYPE_EXISTS(int8_t)
		  CMU_CHECK_TYPE_EXISTS(uint8_t)
		  CMU_CHECK_TYPE_EXISTS(u_int8_t)
		  CMU_CHECK_TYPE_EXISTS(int16_t)
		  CMU_CHECK_TYPE_EXISTS(uint16_t)
		  CMU_CHECK_TYPE_EXISTS(u_int16_t)
		  CMU_CHECK_TYPE_EXISTS(int32_t)
		  CMU_CHECK_TYPE_EXISTS(uint32_t)
		  CMU_CHECK_TYPE_EXISTS(u_int32_t)
  )
  dnl I'm not sure why autoconf gets so annoyed when these
  dnl are embedded as part of the inttypes check, but, whatever,
  dnl this works.
  if test "$ac_cv_header_inttypes_h" = no; then
    AC_CHECK_SIZEOF(short)
    AC_CHECK_SIZEOF(int)
    AC_CHECK_SIZEOF(long)
  fi

  AC_CHECK_TYPE(ssize_t, signed)
  THREADED_UTIL_OBJECTS=""
  AC_SUBST(THREADED_UTIL_OBJECTS)
])

AC_DEFUN([CMU_THREAD_UTIL], [
  AC_REQUIRE([CMU_UTIL])
  THREADED_UTIL_OBJECTS="refcache.o rselock.o"
])

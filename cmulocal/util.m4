dnl util.m4--robutil macro
dnl Rob Earhart
dnl $Id: util.m4,v 1.5 1998/10/25 00:57:29 rob Exp $

dnl robutil is a collection of stuff I (Rob Earhart) have found useful
dnl to have around when writing code; it's the stuff I wind up rewriting
dnl every time I start a project.  This macro does the autoconf setup
dnl necessary for it.

AC_DEFUN(CMU_UTIL, [
  AC_REQUIRE([AC_PROG_CC])
  AC_REQUIRE([AM_PROG_CC_STDC])
  AC_REQUIRE([AC_PROG_RANLIB])
  AC_REQUIRE([CMU_NANA])
  AC_REQUIRE([CMU_COMERR])
  AC_REQUIRE([AC_HEADER_STDC])
  AC_REQUIRE([AC_TYPE_MODE_T])
  AC_REQUIRE([AC_C_CONST])
  AC_CHECK_HEADERS(inttypes.h sys/sysmacros.h)
  AC_CHECK_TYPE(ssize_t, signed)
  AC_CHECK_TYPE(int32_t, signed)
  AC_CHECK_TYPE(uint32_t, unsigned)
  THREADED_UTIL_OBJECTS=""
  AC_SUBST(THREADED_UTIL_OBJECTS)
])

AC_DEFUN(CMU_THREAD_UTIL, [
  AC_REQUIRE([CMU_UTIL])
  THREADED_UTIL_OBJECTS="refcache.o rselock.o"
])

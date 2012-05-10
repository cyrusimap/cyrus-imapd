dnl pthreads.m4--pthreads setup macro
dnl Rob Earhart
dnl $Id: pthreads.m4,v 1.11 2003/10/08 20:35:25 rjs3 Exp $

AC_DEFUN([CMU_PTHREADS], [
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

dnl $Id: arx.m4,v 1.6 2005/04/26 19:14:07 shadow Exp $

AC_DEFUN([CMU_ARX_INC_WHERE1], [
saved_CPPFLAGS=$CPPFLAGS
CPPFLAGS="$saved_CPPFLAGS -I$1"
AC_TRY_COMPILE([#include <arx.h>],
[arx_context *foo;],
ac_cv_found_arx_inc=yes,
ac_cv_found_arx_inc=no)
CPPFLAGS=$saved_CPPFLAGS
])

AC_DEFUN([CMU_ARX_INC_WHERE], [
   for i in $1; do
      AC_MSG_CHECKING(for arx headers in $i)
      CMU_ARX_INC_WHERE1($i)
      CMU_TEST_INCPATH($i, arx)
      if test "$ac_cv_found_arx_inc" = "yes"; then
        ac_cv_arx_where_inc=$i
        AC_MSG_RESULT(found)
        break
      else
        AC_MSG_RESULT(not found)
      fi
    done
])

#
# Test for lib files
#

AC_DEFUN([CMU_ARX_LIB_WHERE1], [
AC_REQUIRE([CMU_AFS])
AC_REQUIRE([CMU_KRB4])
saved_LIBS=$LIBS
LIBS="$saved_LIBS -L$1 -larx $AFS_LIB_FLAGS $AFS_CLIENT_LIBS $KRB_LIB_FLAGS $LIB_SOCKET"
AC_TRY_LINK(,
[arx_Init();],
[ac_cv_found_arx_lib=yes],
ac_cv_found_arx_lib=no)
LIBS=$saved_LIBS
])

AC_DEFUN([CMU_ARX_LIB_WHERE], [
   for i in $1; do
      AC_MSG_CHECKING(for arx libraries in $i)
      CMU_ARX_LIB_WHERE1($i)
      CMU_TEST_LIBPATH($i, arx)
      if test "$ac_cv_found_arx_lib" = "yes" ; then
        ac_cv_arx_where_lib=$i
        AC_MSG_RESULT(found)
        break
      else
        AC_MSG_RESULT(not found)
      fi
    done
])

AC_DEFUN([CMU_USE_ARX], [
AC_REQUIRE([CMU_FIND_LIB_SUBDIR])
AC_ARG_WITH(arx,
	[  --with-arx=PREFIX      Compile with arx support],
	[if test "X$with_arx" = "X"; then
		with_arx=yes
	fi])
AC_ARG_WITH(arx-lib,
	[  --with-arx-lib=dir     use arx libraries in dir],
	[if test "$withval" = "yes" -o "$withval" = "no"; then
		AC_MSG_ERROR([No argument for --with-arx-lib])
	fi])
AC_ARG_WITH(arx-include,
	[  --with-arx-include=dir use arx headers in dir],
	[if test "$withval" = "yes" -o "$withval" = "no"; then
		AC_MSG_ERROR([No argument for --with-arx-include])
	fi])

	if test "X$with_arx" != "X"; then
	  if test "$with_arx" != "yes"; then
	    ac_cv_arx_where_lib=$with_arx/${CMU_LIB_SUBDIR}
	    ac_cv_arx_where_inc=$with_arx/include
	  fi
	fi

	if test "X$with_arx_lib" != "X"; then
	  ac_cv_arx_where_lib=$with_arx_lib
	fi
	if test "X$ac_cv_arx_where_lib" = "X"; then
	  CMU_ARX_LIB_WHERE(/usr/athena/${CMU_LIB_SUBDIR} /usr/local/${CMU_LIB_SUBDIR} /usr/${CMU_LIB_SUBDIR})
	fi

	if test "X$with_arx_include" != "X"; then
	  ac_cv_arx_where_inc=$with_arx_include
	fi
	if test "X$ac_cv_arx_where_inc" = "X"; then
	  CMU_ARX_INC_WHERE(/usr/athena/include /usr/local/include)
	fi

	AC_MSG_CHECKING(whether to include arx)
	if test "X$ac_cv_arx_where_lib" = "X" -o "X$ac_cv_arx_where_inc" = "X"; then
	  ac_cv_found_arx=no
	  AC_MSG_RESULT(no)
	else
	  ac_cv_found_arx=yes
	  AC_MSG_RESULT(yes)
	  ARX_INC_DIR=$ac_cv_arx_where_inc
	  ARX_LIB_DIR=$ac_cv_arx_where_lib
	  ARX_INC_FLAGS="-I${ARX_INC_DIR}"
	  ARX_LIB_FLAGS="-L${ARX_LIB_DIR} -larx"
	  ARX_LD_FLAGS="-L${ARX_LIB_DIR}"
          dnl Do not force configure.in to put these in CFLAGS and LIBS unconditionally
          dnl Allow makefile substitutions....
          AC_SUBST(ARX_INC_FLAGS)
          AC_SUBST(ARX_LIB_FLAGS)
          AC_SUBST(ARX_LD_FLAGS)
	  if test "X$RPATH" = "X"; then
		RPATH=""
	  fi
	  case "${host}" in
	    *-*-linux*)
	      if test "X$RPATH" = "X"; then
	        RPATH="-Wl,-rpath,${ARX_LIB_DIR}"
	      else 
		RPATH="${RPATH}:${ARX_LIB_DIR}"
	      fi
	      ;;
	    *-*-hpux*)
	      if test "X$RPATH" = "X"; then
	        RPATH="-Wl,+b${ARX_LIB_DIR}"
	      else 
		RPATH="${RPATH}:${ARX_LIB_DIR}"
	      fi
	      ;;
	    *-*-irix*)
	      if test "X$RPATH" = "X"; then
	        RPATH="-Wl,-rpath,${ARX_LIB_DIR}"
	      else 
		RPATH="${RPATH}:${ARX_LIB_DIR}"
	      fi
	      ;;
	    *-*-solaris2*)
	      if test "$ac_cv_prog_gcc" = yes; then
		if test "X$RPATH" = "X"; then
		  RPATH="-Wl,-R${ARX_LIB_DIR}"
		else 
		  RPATH="${RPATH}:${ARX_LIB_DIR}"
		fi
	      else
	        RPATH="${RPATH} -R${ARX_LIB_DIR}"
	      fi
	      ;;
	  esac
	  AC_SUBST(RPATH)
	fi
	])


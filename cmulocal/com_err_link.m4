dnl damnit, i don't want to figure out if I need to build an integral com_err
dnl library with the collection, I just want to know where it's installed,
dnl so don't bitch, Rob...
dnl Derrick Brashear
dnl $Id: com_err_link.m4,v 1.6 2002/12/21 18:44:24 cg2v Exp $


AC_DEFUN(CMU_COMERR_INC_WHERE1, [
saved_CPPFLAGS=$CPPFLAGS
CPPFLAGS="$saved_CPPFLAGS -I$1"
AC_TRY_COMPILE([#include <com_err.h>],
[int foo;],
ac_cv_found_com_err_inc=yes,
ac_cv_found_com_err_inc=no)
CPPFLAGS=$saved_CPPFLAGS
])

AC_DEFUN(CMU_COMERR_INC_WHERE, [
   for i in $1; do
      AC_MSG_CHECKING(for com_err headers in $i)
      CMU_COMERR_INC_WHERE1($i)
      CMU_TEST_INCPATH($i, com_err)
      if test "$ac_cv_found_com_err_inc" = "yes"; then
        ac_cv_comerr_where_inc=$i
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

AC_DEFUN(CMU_COMERR_LIB_WHERE1, [
saved_LIBS=$LIBS
LIBS="$saved_LIBS -L$1 -lcom_err"
AC_TRY_LINK(,
[com_err();],
[ac_cv_found_com_err_lib=yes],
ac_cv_found_com_err_lib=no)
LIBS=$saved_LIBS
])

AC_DEFUN(CMU_COMERR_LIB_WHERE, [
   for i in $1; do
      AC_MSG_CHECKING(for com_err libraries in $i)
      CMU_COMERR_LIB_WHERE1($i)
      CMU_TEST_LIBPATH($i, com_err)
      if test "$ac_cv_found_com_err_lib" = "yes" ; then
        ac_cv_comerr_where_lib=$i
        AC_MSG_RESULT(found)
        break
      else
        AC_MSG_RESULT(not found)
      fi
    done
])

AC_DEFUN(CMU_USE_COMERR, [
AC_ARG_WITH(comerr,
	[  --with-comerr=PREFIX      Compile with com_err support],
	[if test "X$with_comerr" = "X"; then
		with_comerr=yes
	fi])
AC_ARG_WITH(comerr-lib,
	[  --with-comerr-lib=dir     use com_err libraries in dir],
	[if test "$withval" = "yes" -o "$withval" = "no"; then
		AC_MSG_ERROR([No argument for --with-comerr-lib])
	fi])
AC_ARG_WITH(comerr-include,
	[  --with-comerr-include=dir use com_err headers in dir],
	[if test "$withval" = "yes" -o "$withval" = "no"; then
		AC_MSG_ERROR([No argument for --with-comerr-include])
	fi])

	if test "X$with_comerr" != "X"; then
	  if test "$with_comerr" != "yes"; then
	    ac_cv_comerr_where_lib=$with_comerr/lib
	    ac_cv_comerr_where_inc=$with_comerr/include
	  fi
	fi

	if test "X$with_comerr_lib" != "X"; then
	  ac_cv_comerr_where_lib=$with_comerr_lib
	fi
	if test "X$ac_cv_comerr_where_lib" = "X"; then
	  CMU_COMERR_LIB_WHERE(/usr/athena/lib /usr/lib /usr/local/lib)
	fi

	if test "X$with_comerr_include" != "X"; then
	  ac_cv_comerr_where_inc=$with_comerr_include
	fi
	if test "X$ac_cv_comerr_where_inc" = "X"; then
	  CMU_COMERR_INC_WHERE(/usr/athena/include /usr/local/include)
	fi

	AC_MSG_CHECKING(whether to include com_err)
	if test "X$ac_cv_comerr_where_lib" = "X" -a "X$ac_cv_comerr_where_inc" = "X"; then
	  ac_cv_found_com_err=no
	  AC_MSG_RESULT(no)
	else
	  ac_cv_found_com_err=yes
	  AC_MSG_RESULT(yes)
	  COMERR_INC_DIR=$ac_cv_comerr_where_inc
	  COMERR_LIB_DIR=$ac_cv_comerr_where_lib
	  COMERR_INC_FLAGS="-I${COMERR_INC_DIR}"
	  COMERR_LIB_FLAGS="-L${COMERR_LIB_DIR} -lcom_err"
          dnl Do not force configure.in to put these in CFLAGS and LIBS unconditionally
          dnl Allow makefile substitutions....
          AC_SUBST(COMERR_INC_FLAGS)
          AC_SUBST(COMERR_LIB_FLAGS)
	  if test "X$RPATH" = "X"; then
		RPATH=""
	  fi
	  case "${host}" in
	    *-*-linux*)
	      if test "X$RPATH" = "X"; then
	        RPATH="-Wl,-rpath,${COMERR_LIB_DIR}"
	      else 
		RPATH="${RPATH}:${COMERR_LIB_DIR}"
	      fi
	      ;;
	    *-*-hpux*)
	      if test "X$RPATH" = "X"; then
	        RPATH="-Wl,+b${COMERR_LIB_DIR}"
	      else 
		RPATH="${RPATH}:${COMERR_LIB_DIR}"
	      fi
	      ;;
	    *-*-irix*)
	      if test "X$RPATH" = "X"; then
	        RPATH="-Wl,-rpath,${COMERR_LIB_DIR}"
	      else 
		RPATH="${RPATH}:${COMERR_LIB_DIR}"
	      fi
	      ;;
	    *-*-solaris2*)
	      if test "$ac_cv_prog_gcc" = yes; then
		if test "X$RPATH" = "X"; then
		  RPATH="-Wl,-R${COMERR_LIB_DIR}"
		else 
		  RPATH="${RPATH}:${COMERR_LIB_DIR}"
		fi
	      else
	        RPATH="${RPATH} -R${COMERR_LIB_DIR}"
	      fi
	      ;;
	  esac
	  AC_SUBST(RPATH)
	fi
	])


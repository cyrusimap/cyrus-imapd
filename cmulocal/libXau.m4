dnl $Id: libXau.m4,v 1.2 2002/05/25 19:57:42 leg Exp $

AC_DEFUN(CMU_XAU_INC_WHERE1, [
AC_REQUIRE([AC_PROG_CC_GNU])
saved_CPPFLAGS=$CPPFLAGS
CPPFLAGS="$saved_CPPFLAGS -I$1"
AC_TRY_COMPILE([
#include <X11/Xauth.h>
],
[Xauth foo;],
ac_cv_found_Xau_inc=yes,
ac_cv_found_Xau_inc=no)
CPPFLAGS=$saved_CPPFLAGS
])

AC_DEFUN(CMU_XAU_INC_WHERE, [
   for i in $1; do
      AC_MSG_CHECKING(for Xau headers in $i)
      CMU_XAU_INC_WHERE1($i)
      CMU_TEST_INCPATH($i, X11/Xauth)
      if test "$ac_cv_found_Xau_inc" = "yes"; then
        ac_cv_Xau_where_inc=$i
        AC_MSG_RESULT(found)
        break
      else
        AC_MSG_RESULT(not found)
      fi
    done
])

AC_DEFUN(CMU_XAU_LIB_WHERE1, [
AC_REQUIRE([AC_PROG_CC_GNU])
saved_LIBS=$LIBS
LIBS="$saved_LIBS -L$1 -lXau $LIB_SOCKET"
AC_TRY_LINK(,
[XauDisposeAuth();],
[ac_cv_found_Xau_lib=yes],
ac_cv_found_Xau_lib=no)
LIBS=$saved_LIBS
])

AC_DEFUN(CMU_XAU_LIB_WHERE, [
   for i in $1; do
      AC_MSG_CHECKING(for Xau libraries in $i)
      CMU_XAU_LIB_WHERE1($i)
      dnl deal with false positives from implicit link paths
      CMU_TEST_LIBPATH($i, Xau)
      if test "$ac_cv_found_Xau_lib" = "yes" ; then
        ac_cv_Xau_where_lib=$i
        AC_MSG_RESULT(found)
        break
      else
        AC_MSG_RESULT(not found)
      fi
    done
])

AC_DEFUN(CMU_XAU, [
AC_REQUIRE([CMU_SOCKETS])
AC_ARG_WITH(Xau,
	[  --with-Xau=PREFIX      Compile with Xau support],
	[if test "X$with_Xau" = "X"; then
		with_Xau=yes
	fi])
AC_ARG_WITH(Xau-lib,
	[  --with-Xau-lib=dir     use Xau libraries in dir],
	[if test "$withval" = "yes" -o "$withval" = "no"; then
		AC_MSG_ERROR([No argument for --with-Xau-lib])
	fi])
AC_ARG_WITH(Xau-include,
	[  --with-Xau-include=dir use Xau headers in dir],
	[if test "$withval" = "yes" -o "$withval" = "no"; then
		AC_MSG_ERROR([No argument for --with-Xau-include])
	fi])

	if test "X$with_Xau" != "X"; then
	  if test "$with_Xau" != "yes"; then
	    ac_cv_Xau_where_lib=$with_Xau/lib
	    ac_cv_Xau_where_inc=$with_Xau/include
	  fi
	fi

	if test "X$with_Xau_lib" != "X"; then
	  ac_cv_Xau_where_lib=$with_Xau_lib
	fi
	if test "X$ac_cv_Xau_where_lib" = "X"; then
	  CMU_XAU_LIB_WHERE(/usr/X11R6/lib /usr/local/lib /usr/openwin/lib)
	fi

	if test "X$with_Xau_include" != "X"; then
	  ac_cv_Xau_where_inc=$with_Xau_include
	fi
	if test "X$ac_cv_Xau_where_inc" = "X"; then
	  CMU_XAU_INC_WHERE(/usr/X11R6/include /usr/local/include /usr/openwin/include)
	fi

	AC_MSG_CHECKING(whether to include Xau)
	if test "X$ac_cv_Xau_where_lib" = "X" -a "X$ac_cv_Xau_where_inc" = "X"; then
	  ac_cv_found_Xau=no
	  AC_MSG_RESULT(no)
	else
	  ac_cv_found_Xau=yes
	  AC_MSG_RESULT(yes)
	  XAU_INC_DIR=$ac_cv_Xau_where_inc
	  XAU_LIB_DIR=$ac_cv_Xau_where_lib
	  XAU_INC_FLAGS="-I${XAU_INC_DIR}"
	  XAU_LIB_FLAGS="-L${XAU_LIB_DIR} -lXau"
	  if test "X$RPATH" = "X"; then
		RPATH=""
	  fi
	  case "${host}" in
	    *-*-linux*)
	      if test "X$RPATH" = "X"; then
	        RPATH="-Wl,-rpath,${XAU_LIB_DIR}"
	      else 
		RPATH="${RPATH}:${XAU_LIB_DIR}"
	      fi
	      ;;
	    *-*-hpux*)
	      if test "X$RPATH" = "X"; then
	        RPATH="-Wl,+b${XAU_LIB_DIR}"
	      else 
		RPATH="${RPATH}:${XAU_LIB_DIR}"
	      fi
	      ;;
	    *-*-irix*)
	      if test "X$RPATH" = "X"; then
	        RPATH="-Wl,-rpath,${XAU_LIB_DIR}"
	      else 
		RPATH="${RPATH}:${XAU_LIB_DIR}"
	      fi
	      ;;
	    *-*-solaris2*)
	      if test "$ac_cv_prog_gcc" = yes; then
		if test "X$RPATH" = "X"; then
		  RPATH="-Wl,-R${XAU_LIB_DIR}"
		else 
		  RPATH="${RPATH}:${XAU_LIB_DIR}"
		fi
	      else
	        RPATH="${RPATH} -R${XAU_LIB_DIR}"
	      fi
	      ;;
	  esac
	  AC_SUBST(RPATH)
	fi
	])


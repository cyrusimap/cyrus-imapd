dnl sasl.m4--sasl libraries and includes
dnl Derrick Brashear
dnl from KTH sasl and Arla

AC_DEFUN(CMU_SASL_INC_WHERE1, [
AC_REQUIRE([AC_PROG_CC_GNU])
saved_CPPFLAGS=$CPPFLAGS
CPPFLAGS="$saved_CPPFLAGS -I$1"
AC_TRY_COMPILE([
#include <sasl.h>
],
[sasl_secret_t foo;],
ac_cv_found_sasl_inc=yes,
ac_cv_found_sasl_inc=no)
if test "$ac_cv_found_sasl_inc" = "no"; then
  CPPFLAGS="$saved_CPPFLAGS -I$1 -I$1/sasl"
  AC_TRY_COMPILE([
#include <sasl.h>
],
  [sasl_secret_t foo;],
  [ac_cv_found_sasl_inc=yes],
  ac_cv_found_sasl_inc=no)
fi
CPPFLAGS=$saved_CPPFLAGS
])

AC_DEFUN(CMU_SASL_INC_WHERE, [
   for i in $1; do
      AC_MSG_CHECKING(for sasl headers in $i)
      CMU_SASL_INC_WHERE1($i)
      CMU_TEST_INCPATH($i, sasl)
      if test "$ac_cv_found_sasl_inc" = "yes"; then
        ac_cv_sasl_where_inc=$i
        AC_MSG_RESULT(found)
        break
      else
        AC_MSG_RESULT(not found)
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
      AC_MSG_CHECKING(for sasl libraries in $i)
      CMU_SASL_LIB_WHERE1($i)
      dnl deal with false positives from implicit link paths
      CMU_TEST_LIBPATH($i, sasl)
      if test "$ac_cv_found_sasl_lib" = "yes" ; then
        ac_cv_sasl_where_lib=$i
        AC_MSG_RESULT(found)
        break
      else
        AC_MSG_RESULT(not found)
      fi
    done
])

AC_DEFUN(CMU_SASL, [
AC_REQUIRE([CMU_SOCKETS])
AC_REQUIRE([CMU_KRB4])
AC_ARG_WITH(sasl,
	[  --with-sasl=PREFIX      Compile with Sasl support],
	[if test "X$with_sasl" = "X"; then
		with_sasl=yes
	fi])
AC_ARG_WITH(sasl-lib,
	[  --with-sasl-lib=dir     use sasl libraries in dir],
	[if test "$withval" = "yes" -o "$withval" = "no"; then
		AC_MSG_ERROR([No argument for --with-sasl-lib])
	fi])
AC_ARG_WITH(sasl-include,
	[  --with-sasl-include=dir use sasl headers in dir],
	[if test "$withval" = "yes" -o "$withval" = "no"; then
		AC_MSG_ERROR([No argument for --with-sasl-include])
	fi])

	if test "X$with_sasl" != "X"; then
	  if test "$with_sasl" != "yes" -a "$with_sasl" != no; then
	    ac_cv_sasl_where_lib=$with_sasl/lib
	    ac_cv_sasl_where_inc=$with_sasl/include
	  fi
	fi

	if test "$with_sasl" != "no"; then 
	  if test "X$with_sasl_lib" != "X"; then
	    ac_cv_sasl_where_lib=$with_sasl_lib
	  fi
	  if test "X$ac_cv_sasl_where_lib" = "X"; then
	    CMU_SASL_LIB_WHERE(/usr/sasl/lib /usr/local/lib /usr/lib)
	  fi

	  if test "X$with_sasl_include" != "X"; then
	    ac_cv_sasl_where_inc=$with_sasl_include
	  fi
	  if test "X$ac_cv_sasl_where_inc" = "X"; then
	    CMU_SASL_INC_WHERE(/usr/sasl/include /usr/include/sasl /usr/local/include /usr/include)
	  fi
	fi

	AC_MSG_CHECKING(whether to include sasl)
	if test "X$ac_cv_sasl_where_lib" = "X" -a "X$ac_cv_sasl_where_inc" = "X"; then
	  ac_cv_found_sasl=no
	  AC_MSG_RESULT(no)
	else
	  ac_cv_found_sasl=yes
	  AC_MSG_RESULT(yes)
	  SASL_INC_DIR=$ac_cv_sasl_where_inc
	  SASL_LIB_DIR=$ac_cv_sasl_where_lib
	  SASL_INC_FLAGS="-I${SASL_INC_DIR}"
	  SASL_LIB_FLAGS="-L${SASL_LIB_DIR} -lsasl"
	  LIB_SASL="-L${SASL_LIB_DIR} -lsasl" 
 	  SASLFLAGS="-I${SASL_INC_DIR}"
	  AC_SUBST(LIB_SASL)
	  AC_SUBST(SASLFLAGS)    
	  if test "X$RPATH" = "X"; then
		RPATH=""
	  fi
	  case "${host}" in
	    *-*-linux*)
	      if test "X$RPATH" = "X"; then
	        RPATH="-Wl,-rpath,${SASL_LIB_DIR}"
	      else 
		RPATH="${RPATH}:${SASL_LIB_DIR}"
	      fi
	      ;;
	    *-*-hpux*)
	      if test "X$RPATH" = "X"; then
	        RPATH="-Wl,+b${SASL_LIB_DIR}"
	      else 
		RPATH="${RPATH}:${SASL_LIB_DIR}"
	      fi
	      ;;
	    *-*-irix*)
	      if test "X$RPATH" = "X"; then
	        RPATH="-Wl,-rpath,${SASL_LIB_DIR}"
	      else 
		RPATH="${RPATH}:${SASL_LIB_DIR}"
	      fi
	      ;;
	    *-*-solaris2*)
	      if test "$ac_cv_prog_gcc" = yes; then
		if test "X$RPATH" = "X"; then
		  RPATH="-Wl,-R${SASL_LIB_DIR}"
		else 
		  RPATH="${RPATH}:${SASL_LIB_DIR}"
		fi
	      else
	        RPATH="${RPATH} -R${SASL_LIB_DIR}"
	      fi
	      ;;
	  esac
	  AC_SUBST(RPATH)
	fi
	AC_SUBST(SASL_INC_DIR)
	AC_SUBST(SASL_INC_FLAGS)
	AC_SUBST(SASL_LIB_DIR)
	AC_SUBST(SASL_LIB_FLAGS)
	])

AC_DEFUN(CMU_NEEDS_SASL,
[AC_REQUIRE([CMU_SASL])
if test "$ac_cv_found_sasl" != "yes"; then
        AC_ERROR([Cannot continue without sasl (Get it from <url:ftp://ftp.andrew.cmu.edu:/pub/cyrus-mail/>).])
fi])

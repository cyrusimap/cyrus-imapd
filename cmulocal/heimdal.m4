dnl kerberos_v5.m4--Kerberos 5 libraries and includes
dnl Derrick Brashear
dnl from KTH krb and Arla

AC_DEFUN(CMU_LIBHEIMDAL_INC_WHERE1, [
AC_REQUIRE([AC_PROG_CC_GNU])
saved_CPPFLAGS=$CPPFLAGS
CPPFLAGS="$saved_CPPFLAGS -I$1"
AC_TRY_COMPILE([#include <krb5.h>],
[krb5_keyblock foo;],
ac_cv_found_libheimdal_inc=yes,
ac_cv_found_libheimdal_inc=no)
CPPFLAGS=$saved_CPPFLAGS
])

AC_DEFUN(CMU_LIBHEIMDAL_INC_WHERE, [
   for i in $1; do
      AC_MSG_CHECKING(for heimdal headers in $i)
      CMU_LIBHEIMDAL_INC_WHERE1($i)
      CMU_TEST_INCPATH($i, krb5)
      if test "$ac_cv_found_libheimdal_inc" = "yes"; then
        ac_cv_libheimdal_where_inc=$i
        AC_MSG_RESULT(found)
        break
      else
        AC_MSG_RESULT(not found)
      fi
    done
])

#
# Test for kerberos lib files
#

AC_DEFUN(CMU_LIBHEIMDAL_LIB_WHERE1, [
AC_REQUIRE([AC_PROG_CC_GNU])
saved_LIBS=$LIBS
LIBS="$saved_LIBS -L$1 -lkadm5clnt -lkrb5 -lasn1 -lkadm5clnt -ldes -lroken -lresolv"
AC_TRY_LINK(,
[krb5_get_in_tkt();],
[ac_cv_found_libheimdal_lib=yes],
ac_cv_found_libheimdal_lib=no)
LIBS=$saved_LIBS
])

AC_DEFUN(CMU_LIBHEIMDAL_LIB_WHERE, [
   for i in $1; do
      AC_MSG_CHECKING(for heimdal libraries in $i)
      CMU_LIBHEIMDAL_LIB_WHERE1($i)
      CMU_TEST_LIBPATH($i, krb5)
      if test "$ac_cv_found_libheimdal_lib" = "yes" ; then
        ac_cv_libheimdal_where_lib=$i
        AC_MSG_RESULT(found)
        break
      else
        AC_MSG_RESULT(not found)
      fi
    done
])

AC_DEFUN(CMU_LIBHEIMDAL, [
AC_REQUIRE([CMU_SOCKETS])
AC_REQUIRE([CMU_USE_COMERR])
AC_ARG_WITH(LIBHEIMDAL,
	[  --with-libheimdal=PREFIX      Compile with Heimdal support],
	[if test "X$with_libheimdal" = "X"; then
		with_libheimdal=yes
	fi])
AC_ARG_WITH(libheimdal-lib,
	[  --with-libheimdal-lib=dir     use heimdal libraries in dir],
	[if test "$withval" = "yes" -o "$withval" = "no"; then
		AC_MSG_ERROR([No argument for --with-libheimdal-lib])
	fi])
AC_ARG_WITH(libheimdal-include,
	[  --with-libheimdal-include=dir use heimdal headers in dir],
	[if test "$withval" = "yes" -o "$withval" = "no"; then
		AC_MSG_ERROR([No argument for --with-libheimdal-include])
	fi])

	if test "X$with_libheimdal" != "X"; then
	  if test "$with_libheimdal" != "yes" -a "$with_libheimdal" != "no"; then
	    ac_cv_libheimdal_where_lib=$with_libheimdal/lib
	    ac_cv_libheimdal_where_inc=$with_libheimdal/include
	  fi
	fi

	if test "$with_libheimdal" != "no"; then
	  if test "X$with_libheimdal_lib" != "X"; then
	    ac_cv_libheimdal_where_lib=$with_libheimdal_lib
	  fi
	  if test "X$ac_cv_libheimdal_where_lib" = "X"; then
	    CMU_LIBHEIMDAL_LIB_WHERE(/usr/athena/lib /usr/lib /usr/heimdal/lib /usr/local/lib)
	  fi

	  if test "X$with_libheimdal_include" != "X"; then
	    ac_cv_libheimdal_where_inc=$with_libheimdal_include
	  fi
	  if test "X$ac_cv_libheimdal_where_inc" = "X"; then
	    CMU_LIBHEIMDAL_INC_WHERE(/usr/athena/include /usr/heimdal/include /usr/local/include)
	  fi
	fi

	AC_MSG_CHECKING(whether to include heimdal)
	if test "X$ac_cv_libheimdal_where_lib" = "X" -a "X$ac_cv_libheimdal_where_inc" = "X"; then
	  ac_cv_found_libheimdal=no
	  AC_MSG_RESULT(no)
	else
	  ac_cv_found_libheimdal=yes
	  AC_MSG_RESULT(yes)
	  LIBHEIMDAL_INC_DIR=$ac_cv_libheimdal_where_inc
	  LIBHEIMDAL_LIB_DIR=$ac_cv_libheimdal_where_lib
	  LIBHEIMDAL_INC_FLAGS="-I${LIBHEIMDAL_INC_DIR}"
	  LIBHEIMDAL_LIB_FLAGS="-L${LIBHEIMDAL_LIB_DIR} -lkadm5clnt -lkrb5 -lasn1 -ldes -lroken -lresolv"
	  AC_SUBST(LIBHEIMDAL_INC_FLAGS)
	  AC_SUBST(LIBHEIMDAL_LIB_FLAGS)
	  if test "X$RPATH" = "X"; then
		RPATH=""
	  fi
	  case "${host}" in
	    *-*-linux*)
	      if test "X$RPATH" = "X"; then
	        RPATH="-Wl,-rpath,${LIBHEIMDAL_LIB_DIR}"
	      else 
		RPATH="${RPATH}:${LIBHEIMDAL_LIB_DIR}"
	      fi
	      ;;
	    *-*-hpux*)
	      if test "X$RPATH" = "X"; then
	        RPATH="-Wl,+b${LIBHEIMDAL_LIB_DIR}"
	      else 
		RPATH="${RPATH}:${LIBHEIMDAL_LIB_DIR}"
	      fi
	      ;;
	    *-*-irix*)
	      if test "X$RPATH" = "X"; then
	        RPATH="-Wl,-rpath,${LIBHEIMDAL_LIB_DIR}"
	      else 
		RPATH="${RPATH}:${LIBHEIMDAL_LIB_DIR}"
	      fi
	      ;;
	    *-*-solaris2*)
	      if test "$ac_cv_prog_gcc" = yes; then
		if test "X$RPATH" = "X"; then
		  RPATH="-Wl,-R${LIBHEIMDAL_LIB_DIR}"
		else 
		  RPATH="${RPATH}:${LIBHEIMDAL_LIB_DIR}"
		fi
	      else
	        RPATH="${RPATH} -R${LIBHEIMDAL_LIB_DIR}"
	      fi
	      ;;
	  esac
	  AC_SUBST(RPATH)
	fi
	])


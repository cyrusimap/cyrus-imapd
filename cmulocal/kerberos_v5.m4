dnl kerberos_v5.m4--Kerberos 5 libraries and includes
dnl Derrick Brashear
dnl from KTH krb and Arla
dnl $Id: kerberos_v5.m4,v 1.5.4.1 2003/02/14 16:14:48 ken3 Exp $

AC_DEFUN(CMU_KRB5_INC_WHERE1, [
saved_CPPFLAGS=$CPPFLAGS
CPPFLAGS="$saved_CPPFLAGS -I$1"
AC_TRY_COMPILE([#include <krb5.h>],
[krb5_keyblock foo;],
ac_cv_found_krb5_inc=yes,
ac_cv_found_krb5_inc=no)
CPPFLAGS=$saved_CPPFLAGS
])

AC_DEFUN(CMU_KRB5_INC_WHERE, [
   for i in $1; do
      AC_MSG_CHECKING(for krb5 headers in $i)
      CMU_KRB5_INC_WHERE1($i)
      CMU_TEST_INCPATH($i, krb5)
      if test "$ac_cv_found_krb5_inc" = "yes"; then
        ac_cv_krb5_where_inc=$i
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

AC_DEFUN(CMU_KRB5_LIB_WHERE1, [
saved_LIBS=$LIBS
LIBS="$saved_LIBS -L$1 -lkrb5 -lk5crypto"
AC_TRY_LINK(,
[krb5_get_in_tkt();],
[ac_cv_found_krb5_lib=yes],
ac_cv_found_krb5_lib=no)
LIBS=$saved_LIBS
])

AC_DEFUN(CMU_KRB5_HLIB_WHERE1, [
saved_LIBS=$LIBS
LIBS="$saved_LIBS -L$1 -lkrb5 -ldes -lasn1"
AC_TRY_LINK(,
[krb5_get_in_tkt();],
[ac_cv_found_krb5_lib=yes],
ac_cv_found_krb5_lib=no)
LIBS=$saved_LIBS
])

AC_DEFUN(CMU_KRB5_LIB_WHERE, [
   for i in $1; do
      AC_MSG_CHECKING(for krb5 libraries in $i)
      CMU_KRB5_LIB_WHERE1($i)
      CMU_TEST_LIBPATH($i, krb5)
      if test "$ac_cv_found_krb5_lib" = "yes" ; then
        ac_cv_krb5_where_lib=$i
        AC_MSG_RESULT(found)
        break
      else
        AC_MSG_RESULT(not found)
      fi
    done
])

AC_DEFUN(CMU_KRB5_HLIB_WHERE, [
   for i in $1; do
      AC_MSG_CHECKING(for heimdal krb5 libraries in $i)
      CMU_KRB5_HLIB_WHERE1($i)
      CMU_TEST_LIBPATH($i, krb5)
      if test "$ac_cv_found_krb5_lib" = "yes" ; then
        ac_cv_krb5_where_hlib=$i
        AC_MSG_RESULT(found)
        break
      else
        AC_MSG_RESULT(not found)
      fi
    done
])

AC_DEFUN(CMU_KRB5, [
AC_REQUIRE([CMU_SOCKETS])
AC_REQUIRE([CMU_USE_COMERR])
AC_ARG_WITH(krb5,
	[  --with-krb5=PREFIX      Compile with Kerberos 5 support],
	[if test "X$with_krb5" = "X"; then
		with_krb5=yes
	fi])
AC_ARG_WITH(krb5-lib,
	[  --with-krb5-lib=dir     use kerberos 5 libraries in dir],
	[if test "$withval" = "yes" -o "$withval" = "no"; then
		AC_MSG_ERROR([No argument for --with-krb5-lib])
	fi])
AC_ARG_WITH(krb5-include,
	[  --with-krb5-include=dir use kerberos 5 headers in dir],
	[if test "$withval" = "yes" -o "$withval" = "no"; then
		AC_MSG_ERROR([No argument for --with-krb5-include])
	fi])

	if test "X$with_krb5" != "X"; then
	  if test "$with_krb5" != "yes" -a "$with_krb5" != "no"; then
	    ac_cv_krb5_where_lib=$with_krb5/lib
	    ac_cv_krb5_where_inc=$with_krb5/include
	  fi
	fi

	if test "$with_krb5" != "no"; then
	  if test "X$with_krb5_lib" != "X"; then
	    ac_cv_krb5_where_lib=$with_krb5_lib
	  fi
	  if test "X$ac_cv_krb5_where_lib" = "X"; then
	    CMU_KRB5_LIB_WHERE(/usr/athena/lib /usr/lib /usr/local/lib)
	  fi
	  if test "X$ac_cv_krb5_where_lib" = "X"; then
	    CMU_KRB5_HLIB_WHERE(/usr/athena/lib /usr/lib /usr/local/lib)
	  fi

	  if test "X$with_krb5_include" != "X"; then
	    ac_cv_krb5_where_inc=$with_krb5_include
	  fi
	  if test "X$ac_cv_krb5_where_inc" = "X"; then
	    CMU_KRB5_INC_WHERE(/usr/athena/include /usr/include/kerberos /usr/local/include /usr/include)
	  fi
	fi

	AC_MSG_CHECKING(whether to include kerberos 5)
	if test "X$ac_cv_krb5_where_lib" = "X" -a "X$ac_cv_krb5_where_hlib" = "X" -o "X$ac_cv_krb5_where_inc" = "X"; then
	  ac_cv_found_krb5=no
	  AC_MSG_RESULT(no)
	else
	  ac_cv_found_krb5=yes
	  AC_MSG_RESULT(yes)
	  KRB5_INC_DIR=$ac_cv_krb5_where_inc
	  if test "X$ac_cv_krb5_where_hlib" = "X"; then
  	    KRB5_LIB_DIR=$ac_cv_krb5_where_lib
	    KRB5_LIB_FLAGS="-L${KRB5_LIB_DIR} -lkrb5 -lk5crypto"
          else
	    KRB5_LIB_DIR=$ac_cv_krb5_where_hlib
     	    KRB5_LIB_FLAGS="-L${KRB5_LIB_DIR} -lkrb5 -ldes -lasn1"
	    AC_DEFINE(HEIMDAL,,[we found heimdal krb5 and not MIT krb5])
          fi
	  KRB5_INC_FLAGS="-I${KRB5_INC_DIR}"
          AC_SUBST(KRB5_INC_FLAGS)
          AC_SUBST(KRB5_LIB_FLAGS)
	  AC_DEFINE(KRB5,,[Use Kerberos 5. (maybe find what needs this and nuke it)])
	  if test "X$RPATH" = "X"; then
		RPATH=""
	  fi
	  case "${host}" in
	    *-*-linux*)
	      if test "X$RPATH" = "X"; then
	        RPATH="-Wl,-rpath,${KRB5_LIB_DIR}"
	      else 
		RPATH="${RPATH}:${KRB5_LIB_DIR}"
	      fi
	      ;;
	    *-*-hpux*)
	      if test "X$RPATH" = "X"; then
	        RPATH="-Wl,+b${KRB5_LIB_DIR}"
	      else 
		RPATH="${RPATH}:${KRB5_LIB_DIR}"
	      fi
	      ;;
	    *-*-irix*)
	      if test "X$RPATH" = "X"; then
	        RPATH="-Wl,-rpath,${KRB5_LIB_DIR}"
	      else 
		RPATH="${RPATH}:${KRB5_LIB_DIR}"
	      fi
	      ;;
	    *-*-solaris2*)
	      if test "$ac_cv_prog_gcc" = yes; then
		if test "X$RPATH" = "X"; then
		  RPATH="-Wl,-R${KRB5_LIB_DIR}"
		else 
		  RPATH="${RPATH}:${KRB5_LIB_DIR}"
		fi
	      else
	        RPATH="${RPATH} -R${KRB5_LIB_DIR}"
	      fi
	      ;;
	  esac
	  AC_SUBST(RPATH)
	fi
	])


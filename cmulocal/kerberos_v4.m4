dnl kerberos_v4.m4--Kerberos 4 libraries and includes
dnl Derrick Brashear
dnl from KTH krb and Arla

AC_DEFUN(CMU_KRB_INC_WHERE1, [
AC_REQUIRE([AC_PROG_CC_GNU])
saved_CPPFLAGS=$CPPFLAGS
if test "$ac_cv_prog_gcc" = "yes" ; then
  CPPFLAGS="$saved_CPPFLAGS -nostdinc -I$1 -I/usr/include"
else
  CPPFLAGS="$saved_CPPFLAGS -I$1"
fi
AC_TRY_COMPILE([#include <krb.h>],
[struct ktext foo;],
ac_cv_found_krb_inc=yes,
ac_cv_found_krb_inc=no)
if test "$ac_cv_found_krb_inc" = "no"; then
  if test "$ac_cv_prog_gcc" = "yes" ; then
    CPPFLAGS="$saved_CPPFLAGS -nostdinc -I$1 -I$1/kerberosIV -I/usr/include"
  else
    CPPFLAGS="$saved_CPPFLAGS -I$1 -I$1/kerberosIV"
  fi
  AC_TRY_COMPILE([#include <krb.h>],
  [struct ktext foo;],
  [ac_cv_found_krb_inc=yes],
  ac_cv_found_krb_inc=no)
fi
CPPFLAGS=$saved_CPPFLAGS
])

AC_DEFUN(CMU_KRB_INC_WHERE, [
   for i in $1; do
      AC_MSG_CHECKING(for kerberos headers in $i)
      CMU_KRB_INC_WHERE1($i)
      if test "$ac_cv_found_krb_inc" = "yes"; then
        ac_cv_krb_where_inc=$i
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

AC_DEFUN(CMU_KRB_LIB_WHERE1, [
AC_REQUIRE([AC_PROG_CC_GNU])
saved_LIBS=$LIBS
LIBS="$saved_LIBS -L$1 -lkrb -ldes"
AC_TRY_LINK(,
[dest_tkt();des_ecb_encrypt();],
[ac_cv_found_krb_lib=yes],
ac_cv_found_krb_lib=no)
LIBS=$saved_LIBS
])

AC_DEFUN(CMU_KRB_LIB_WHERE, [
   for i in $1; do
      AC_MSG_CHECKING(for kerberos libraries in $i)
      CMU_KRB_LIB_WHERE1($i)
      dnl deal with false positives from implicit link paths
      CMU_TEST_LIBPATH($i, krb)
      if test "$ac_cv_found_krb_lib" = "yes" ; then
        ac_cv_krb_where_lib=$i
        AC_MSG_RESULT(found)
        break
      else
        AC_MSG_RESULT(not found)
      fi
    done
])

AC_DEFUN(CMU_KRB4, [
AC_REQUIRE([CMU_SOCKETS])
AC_ARG_WITH(krb4,
	[  --with-krb4=PREFIX      Compile with Kerberos 4 support],
	[if test "X$with_krb4" = "X"; then
		with_krb4=yes
	fi])
AC_ARG_WITH(krb4-lib,
	[  --with-krb4-lib=dir     use kerberos 4 libraries in dir],
	[if test "$withval" = "yes" -o "$withval" = "no"; then
		AC_MSG_ERROR([No argument for --with-krb4-lib])
	fi])
AC_ARG_WITH(krb4-include,
	[  --with-krb4-include=dir use kerberos 4 headers in dir],
	[if test "$withval" = "yes" -o "$withval" = "no"; then
		AC_MSG_ERROR([No argument for --with-krb4-include])
	fi])

	if test "X$with_krb4" != "X"; then
	  if test "$with_krb4" != "yes"; then
	    ac_cv_krb_where_lib=$with_krb4/lib
	    ac_cv_krb_where_inc=$with_krb4/include
	  fi
	fi

	if test "X$with_krb4_lib" != "X"; then
	  ac_cv_krb_where_lib=$with_krb4_lib
	fi
	if test "X$ac_cv_krb_where_lib" = "X"; then
	  CMU_KRB_LIB_WHERE(/usr/athena/lib /usr/local/lib /usr/lib)
	fi

	if test "X$with_krb4_include" != "X"; then
	  ac_cv_krb_where_inc=$with_krb4_include
	fi
	if test "X$ac_cv_krb_where_inc" = "X"; then
	  CMU_KRB_INC_WHERE(/usr/athena/include /usr/include/kerberosIV /usr/local/include /usr/include/kerberos)
	fi

	AC_MSG_CHECKING(whether to include kerberos 4)
	if test "X$ac_cv_krb_where_lib" = "X" -a "X$ac_cv_krb_where_inc" = "X"; then
	  ac_cv_found_krb=no
	  AC_MSG_RESULT(no)
	else
	  ac_cv_found_krb=yes
	  AC_MSG_RESULT(yes)
	  KRB_INC_DIR=$ac_cv_krb_where_inc
	  KRB_LIB_DIR=$ac_cv_krb_where_lib
	  KRB_INC_FLAGS="-I${KRB_INC_DIR}"
	  KRB_LIB_FLAGS="-L${KRB_LIB_DIR} -lkrb -ldes"
	  cmu_save_LIBS="$LIBS"
	  LIBS="${LIBS} ${KRB_LIB_FLAGS}"
	  AC_CHECK_LIB(resolv, dns_lookup, KRB_LIB_FLAGS="${KRB_LIB_FLAGS} -lresolv",,"${KRB_LIB_FLAGS}")
	  AC_CHECK_FUNCS(krb_get_int krb_life_to_time)
	  LIBS="${cmu_save_LIBS} ${KRB_LIB_FLAGS}"
	  AC_DEFINE(KERBEROS)
	  if test "X$RPATH" = "X"; then
		RPATH=""
	  fi
	  case "${host}" in
	    *-*-linux*)
	      if test "X$RPATH" = "X"; then
	        RPATH="-Wl,-rpath,${KRB_LIB_DIR}"
	      else 
		RPATH="${RPATH}:${KRB_LIB_DIR}"
	      fi
	      ;;
	    *-*-hpux*)
	      if test "X$RPATH" = "X"; then
	        RPATH="-Wl,+b${KRB_LIB_DIR}"
	      else 
		RPATH="${RPATH}:${KRB_LIB_DIR}"
	      fi
	      ;;
	    *-*-irix*)
	      if test "X$RPATH" = "X"; then
	        RPATH="-Wl,-rpath,${KRB_LIB_DIR}"
	      else 
		RPATH="${RPATH}:${KRB_LIB_DIR}"
	      fi
	      ;;
	    *-*-solaris2*)
	      if test "$ac_cv_prog_gcc" = yes; then
		if test "X$RPATH" = "X"; then
		  RPATH="-Wl,-R${KRB_LIB_DIR}"
		else 
		  RPATH="${RPATH}:${KRB_LIB_DIR}"
		fi
	      else
	        RPATH="${RPATH} -R${KRB_LIB_DIR}"
	      fi
	      ;;
	  esac
	  AC_SUBST(RPATH)
	fi
	])


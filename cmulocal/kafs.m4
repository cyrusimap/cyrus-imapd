dnl kerberos_v4.m4--Kafs libraries and includes
dnl Derrick Brashear
dnl from KTH kafs and Arla
dnl $Id: kafs.m4,v 1.4.4.1 2003/02/14 16:14:48 ken3 Exp $

AC_DEFUN(CMU_KAFS_INC_WHERE1, [
saved_CPPFLAGS=$CPPFLAGS
CPPFLAGS="$saved_CPPFLAGS -I$1"
AC_TRY_COMPILE([
#include <krb.h>
#include <sys/ioctl.h>
#include <kafs.h>
],
[struct ClearToken foo;],
ac_cv_found_kafs_inc=yes,
ac_cv_found_kafs_inc=no)
if test "$ac_cv_found_kafs_inc" = "no"; then
  CPPFLAGS="$saved_CPPFLAGS -I$1 -I$1/kerberosIV"
  AC_TRY_COMPILE([
#include <krb.h>
#include <sys/ioctl.h>
#include <kafs.h>
],
  [struct ClearToken foo;],
  [ac_cv_found_kafs_inc=yes],
  ac_cv_found_kafs_inc=no)
fi
CPPFLAGS=$saved_CPPFLAGS
])

AC_DEFUN(CMU_KAFS_INC_WHERE, [
   for i in $1; do
      AC_MSG_CHECKING(for kafs headers in $i)
      CMU_KAFS_INC_WHERE1($i)
      CMU_TEST_INCPATH($i, kafs)
      if test "$ac_cv_found_kafs_inc" = "yes"; then
        ac_cv_kafs_where_inc=$i
        AC_MSG_RESULT(found)
        break
      else
        AC_MSG_RESULT(not found)
      fi
    done
])

AC_DEFUN(CMU_KAFS_LIB_WHERE1, [
saved_LIBS=$LIBS
LIBS="$saved_LIBS -L$1 -lkafs $KRB_LIB_FLAGS $KRB5_LIB_FLAGS"
AC_TRY_LINK(,
[krb_afslog();],
[ac_cv_found_kafs_lib=yes],
ac_cv_found_kafs_lib=no)
LIBS=$saved_LIBS
])

AC_DEFUN(CMU_KAFS_LIB_WHERE, [
   for i in $1; do
      AC_MSG_CHECKING(for kafs libraries in $i)
      CMU_KAFS_LIB_WHERE1($i)
      dnl deal with false positives from implicit link paths
      CMU_TEST_LIBPATH($i, kafs)
      if test "$ac_cv_found_kafs_lib" = "yes" ; then
        ac_cv_kafs_where_lib=$i
        AC_MSG_RESULT(found)
        break
      else
        AC_MSG_RESULT(not found)
      fi
    done
])

AC_DEFUN(CMU_KAFS, [
AC_REQUIRE([CMU_SOCKETS])
AC_REQUIRE([CMU_KRB4])
AC_REQUIRE([CMU_KRB5])
AC_ARG_WITH(kafs,
	[  --with-kafs=PREFIX      Compile with Kafs support],
	[if test "X$with_kafs" = "X"; then
		with_kafs=yes
	fi])
AC_ARG_WITH(kafs-lib,
	[  --with-kafs-lib=dir     use kafs libraries in dir],
	[if test "$withval" = "yes" -o "$withval" = "no"; then
		AC_MSG_ERROR([No argument for --with-kafs-lib])
	fi])
AC_ARG_WITH(kafs-include,
	[  --with-kafs-include=dir use kafs headers in dir],
	[if test "$withval" = "yes" -o "$withval" = "no"; then
		AC_MSG_ERROR([No argument for --with-kafs-include])
	fi])

	if test "X$with_kafs" != "X"; then
	  if test "$with_kafs" != "yes" -a "$with_kafs" != no; then
	    ac_cv_kafs_where_lib=$with_kafs/lib
	    ac_cv_kafs_where_inc=$with_kafs/include
	  fi
	fi

	if test "$with_kafs" != "no"; then 
	  if test "X$with_kafs_lib" != "X"; then
	    ac_cv_kafs_where_lib=$with_kafs_lib
	  fi
	  if test "X$ac_cv_kafs_where_lib" = "X"; then
	    CMU_KAFS_LIB_WHERE(/usr/athena/lib /usr/local/lib /usr/lib)
	  fi

	  if test "X$with_kafs_include" != "X"; then
	    ac_cv_kafs_where_inc=$with_kafs_include
	  fi
	  if test "X$ac_cv_kafs_where_inc" = "X"; then
	    CMU_KAFS_INC_WHERE(/usr/athena/include /usr/include/kerberosIV /usr/local/include /usr/include/kerberos)
	  fi
	fi

	AC_MSG_CHECKING(whether to include kafs)
	if test "X$ac_cv_kafs_where_lib" = "X" -a "X$ac_cv_kafs_where_inc" = "X"; then
	  ac_cv_found_kafs=no
	  AC_MSG_RESULT(no)
	else
	  ac_cv_found_kafs=yes
	  AC_MSG_RESULT(yes)
	  KAFS_INC_DIR=$ac_cv_kafs_where_inc
	  KAFS_LIB_DIR=$ac_cv_kafs_where_lib
	  KAFS_INC_FLAGS="-I${KAFS_INC_DIR}"
	  KAFS_LIB_FLAGS="-L${KAFS_LIB_DIR} -lkafs"
	  if test "X$RPATH" = "X"; then
		RPATH=""
	  fi
	  case "${host}" in
	    *-*-linux*)
	      if test "X$RPATH" = "X"; then
	        RPATH="-Wl,-rpath,${KAFS_LIB_DIR}"
	      else 
		RPATH="${RPATH}:${KAFS_LIB_DIR}"
	      fi
	      ;;
	    *-*-hpux*)
	      if test "X$RPATH" = "X"; then
	        RPATH="-Wl,+b${KAFS_LIB_DIR}"
	      else 
		RPATH="${RPATH}:${KAFS_LIB_DIR}"
	      fi
	      ;;
	    *-*-irix*)
	      if test "X$RPATH" = "X"; then
	        RPATH="-Wl,-rpath,${KAFS_LIB_DIR}"
	      else 
		RPATH="${RPATH}:${KAFS_LIB_DIR}"
	      fi
	      ;;
	    *-*-solaris2*)
	      if test "$ac_cv_prog_gcc" = yes; then
		if test "X$RPATH" = "X"; then
		  RPATH="-Wl,-R${KAFS_LIB_DIR}"
		else 
		  RPATH="${RPATH}:${KAFS_LIB_DIR}"
		fi
	      else
	        RPATH="${RPATH} -R${KAFS_LIB_DIR}"
	      fi
	      ;;
	  esac
	  AC_SUBST(RPATH)
	fi
	])


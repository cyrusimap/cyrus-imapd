dnl libssl.m4--Ssl libraries and includes
dnl Derrick Brashear
dnl from KTH kafs and Arla
dnl $Id: libssl.m4,v 1.8 2002/12/21 18:44:25 cg2v Exp $

AC_DEFUN(CMU_LIBSSL_INC_WHERE1, [
saved_CPPFLAGS=$CPPFLAGS
CPPFLAGS="$saved_CPPFLAGS -I$1"
CMU_CHECK_HEADER_NOCACHE(openssl/ssl.h,
ac_cv_found_libssl_inc=yes,
ac_cv_found_libssl_inc=no)
CPPFLAGS=$saved_CPPFLAGS
])

AC_DEFUN(CMU_LIBSSL_INC_WHERE, [
   for i in $1; do
      AC_MSG_CHECKING(for libssl headers in $i)
      CMU_LIBSSL_INC_WHERE1($i)
      CMU_TEST_INCPATH($i, ssl)
      if test "$ac_cv_found_libssl_inc" = "yes"; then
        ac_cv_libssl_where_inc=$i
        AC_MSG_RESULT(found)
        break
      else
        AC_MSG_RESULT(not found)
      fi
    done
])

AC_DEFUN(CMU_LIBSSL_LIB_WHERE1, [
saved_LIBS=$LIBS
LIBS="$saved_LIBS -L$1 -lssl -lcrypto $LIB_SOCKET"
AC_TRY_LINK(,
[SSL_write();],
[ac_cv_found_ssl_lib=yes],
ac_cv_found_ssl_lib=no)
LIBS=$saved_LIBS
])

AC_DEFUN(CMU_LIBSSL_LIB_WHERE, [
   for i in $1; do
      AC_MSG_CHECKING(for libssl libraries in $i)
      CMU_LIBSSL_LIB_WHERE1($i)
      dnl deal with false positives from implicit link paths
      CMU_TEST_LIBPATH($i, ssl)
      if test "$ac_cv_found_ssl_lib" = "yes" ; then
        ac_cv_libssl_where_lib=$i
        AC_MSG_RESULT(found)
        break
      else
        AC_MSG_RESULT(not found)
      fi
    done
])

AC_DEFUN(CMU_LIBSSL, [
AC_REQUIRE([CMU_SOCKETS])
AC_ARG_WITH(libssl,
	[  --with-libssl=PREFIX      Compile with Libssl support],
	[if test "X$with_libssl" = "X"; then
		with_libssl=yes
	fi])
AC_ARG_WITH(libssl-lib,
	[  --with-libssl-lib=dir     use libssl libraries in dir],
	[if test "$withval" = "yes" -o "$withval" = "no"; then
		AC_MSG_ERROR([No argument for --with-libssl-lib])
	fi])
AC_ARG_WITH(libssl-include,
	[  --with-libssl-include=dir use libssl headers in dir],
	[if test "$withval" = "yes" -o "$withval" = "no"; then
		AC_MSG_ERROR([No argument for --with-libssl-include])
	fi])

	if test "X$with_libssl" != "X"; then
	  if test "$with_libssl" != "yes" -a "$with_libssl" != no; then
	    ac_cv_libssl_where_lib=$with_libssl/lib
	    ac_cv_libssl_where_inc=$with_libssl/include
	  fi
	fi

	if test "$with_libssl" != "no"; then 
	  if test "X$with_libssl_lib" != "X"; then
	    ac_cv_libssl_where_lib=$with_libssl_lib
	  fi
	  if test "X$ac_cv_libssl_where_lib" = "X"; then
	    CMU_LIBSSL_LIB_WHERE(/usr/local/lib/openssl /usr/lib/openssl /usr/local/lib /usr/lib)
	  fi

	  if test "X$with_libssl_include" != "X"; then
	    ac_cv_libssl_where_inc=$with_libssl_include
	  fi
	  if test "X$ac_cv_libssl_where_inc" = "X"; then
	    CMU_LIBSSL_INC_WHERE(/usr/local/include /usr/include)
	  fi
	fi

	AC_MSG_CHECKING(whether to include libssl)
	if test "X$ac_cv_libssl_where_lib" = "X" -a "X$ac_cv_libssl_where_inc" = "X"; then
	  ac_cv_found_libssl=no
	  AC_MSG_RESULT(no)
	else
	  ac_cv_found_libssl=yes
	  AC_MSG_RESULT(yes)
	  LIBSSL_INC_DIR=$ac_cv_libssl_where_inc
	  LIBSSL_LIB_DIR=$ac_cv_libssl_where_lib
	  LIBSSL_INC_FLAGS="-I${LIBSSL_INC_DIR}"
	  LIBSSL_LIB_FLAGS="-L${LIBSSL_LIB_DIR} -lssl -lcrypto"
	  if test "X$RPATH" = "X"; then
		RPATH=""
	  fi
	  case "${host}" in
	    *-*-linux*)
	      if test "X$RPATH" = "X"; then
	        RPATH="-Wl,-rpath,${LIBSSL_LIB_DIR}"
	      else 
 		RPATH="${RPATH}:${LIBSSL_LIB_DIR}"
	      fi
	      ;;
	    *-*-hpux*)
	      if test "X$RPATH" = "X"; then
	        RPATH="-Wl,+b${LIBSSL_LIB_DIR}"
	      else 
		RPATH="${RPATH}:${LIBSSL_LIB_DIR}"
	      fi
	      ;;
	    *-*-irix*)
	      if test "X$RPATH" = "X"; then
	        RPATH="-Wl,-rpath,${LIBSSL_LIB_DIR}"
	      else 
		RPATH="${RPATH}:${LIBSSL_LIB_DIR}"
	      fi
	      ;;
	    *-*-solaris2*)
	      if test "$ac_cv_prog_gcc" = yes; then
		if test "X$RPATH" = "X"; then
		  RPATH="-Wl,-R${LIBSSL_LIB_DIR}"
		else 
		  RPATH="${RPATH}:${LIBSSL_LIB_DIR}"
		fi
	      else
	        RPATH="${RPATH} -R${LIBSSL_LIB_DIR}"
	      fi
	      ;;
	  esac
	  AC_SUBST(RPATH)
	fi
	AC_SUBST(LIBSSL_INC_DIR)
	AC_SUBST(LIBSSL_LIB_DIR)
	AC_SUBST(LIBSSL_INC_FLAGS)
	AC_SUBST(LIBSSL_LIB_FLAGS)
	])


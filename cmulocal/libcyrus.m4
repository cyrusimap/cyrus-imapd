dnl libcyrus.m4--Cyrus libraries and includes
dnl Derrick Brashear
dnl from KTH kafs and Arla

AC_DEFUN(CMU_LIBCYRUS_INC_WHERE1, [
AC_REQUIRE([AC_PROG_CC_GNU])
saved_CPPFLAGS=$CPPFLAGS
CPPFLAGS="$saved_CPPFLAGS -I$1 $SASLFLAGS"
CMU_CHECK_HEADER_NOCACHE(imclient.h,
ac_cv_found_cyrus_inc=yes,
ac_cv_found_cyrus_inc=no)
CPPFLAGS=$saved_CPPFLAGS
])

AC_DEFUN(CMU_LIBCYRUS_INC_WHERE, [
   for i in $1; do
      AC_MSG_CHECKING(for libcyrus headers in $i)
      CMU_LIBCYRUS_INC_WHERE1($i)
      CMU_TEST_INCPATH($i, imclient)
      if test "$ac_cv_found_cyrus_inc" = "yes"; then
        ac_cv_cyrus_where_inc=$i
        AC_MSG_RESULT(found)
        break
      else
        AC_MSG_RESULT(not found)
      fi
    done
])

AC_DEFUN(CMU_LIBCYRUS_LIB_WHERE1, [
AC_REQUIRE([AC_PROG_CC_GNU])
saved_LIBS=$LIBS
LIBS="$saved_LIBS -L$1 -lcyrus ${LIB_SASL} ${LIBSSL_LIB_FLAGS} ${LIB_SOCKET}"
AC_TRY_LINK([void fatal(){}],
[imclient_authenticate();],
[ac_cv_found_cyrus_lib=yes],
ac_cv_found_cyrus_lib=no)
LIBS=$saved_LIBS
])

AC_DEFUN(CMU_LIBCYRUS_LIB_WHERE, [
   for i in $1; do
      AC_MSG_CHECKING(for libcyrus libraries in $i)
      CMU_LIBCYRUS_LIB_WHERE1($i)
      dnl deal with false positives from implicit link paths
      CMU_TEST_LIBPATH($i, cyrus)
      if test "$ac_cv_found_cyrus_lib" = "yes" ; then
        ac_cv_cyrus_where_lib=$i
        AC_MSG_RESULT(found)
        break
      else
        AC_MSG_RESULT(not found)
      fi
    done
])

AC_DEFUN(CMU_LIBCYRUS, [
AC_REQUIRE([CMU_SOCKETS])
AC_REQUIRE([CMU_SASL])
AC_REQUIRE([CMU_LIBSSL])
AC_ARG_WITH(libcyrus,
	[  --with-libcyrus=PREFIX      Compile with Libcyrus support],
	[if test "X$with_libcyrus" = "X"; then
		with_libcyrus=yes
	fi])
AC_ARG_WITH(libcyrus-lib,
	[  --with-libcyrus-lib=dir     use libcyrus libraries in dir],
	[if test "$withval" = "yes" -o "$withval" = "no"; then
		AC_MSG_ERROR([No argument for --with-libcyrus-lib])
	fi])
AC_ARG_WITH(libcyrus-include,
	[  --with-libcyrus-include=dir use libcyrus headers in dir],
	[if test "$withval" = "yes" -o "$withval" = "no"; then
		AC_MSG_ERROR([No argument for --with-libcyrus-include])
	fi])

	if test "X$with_libcyrus" != "X"; then
	  if test "$with_libcyrus" != "yes" -a "$with_libcyrus" != no; then
	    ac_cv_cyrus_where_lib=$with_libcyrus/lib
	    ac_cv_cyrus_where_inc=$with_libcyrus/include
	  fi
	fi

	if test "$with_libcyrus" != "no"; then 
	  if test "X$with_libcyrus_lib" != "X"; then
	    ac_cv_cyrus_where_lib=$with_libcyrus_lib
	  fi
	  if test "X$ac_cv_cyrus_where_lib" = "X"; then
	    CMU_LIBCYRUS_LIB_WHERE(/usr/cyrus/lib /usr/local/lib /usr/lib)
	  fi

	  if test "X$with_libcyrus_include" != "X"; then
	    ac_cv_cyrus_where_inc=$with_libcyrus_include
	  fi
	  if test "X$ac_cv_cyrus_where_inc" = "X"; then
	    CMU_LIBCYRUS_INC_WHERE(/usr/cyrus/include /usr/local/include /usr/local/include/cyrus /usr/include/cyrus)
	  fi
	fi

	AC_MSG_CHECKING(whether to include libcyrus)
	if test "X$ac_cv_cyrus_where_lib" = "X" -o "X$ac_cv_cyrus_where_inc" = "X"; then
	  ac_cv_found_cyrus=no
	  AC_MSG_RESULT(no)
	else
	  ac_cv_found_cyrus=yes
	  AC_MSG_RESULT(yes)
	  LIBCYRUS_INC_DIR=$ac_cv_cyrus_where_inc
	  LIBCYRUS_LIB_DIR=$ac_cv_cyrus_where_lib
	  LIBCYRUS_INC_FLAGS="-I${LIBCYRUS_INC_DIR}"
	  LIBCYRUS_LIB_FLAGS="-L${LIBCYRUS_LIB_DIR} -lcyrus"
	  if test "X$RPATH" = "X"; then
		RPATH=""
	  fi
	  case "${host}" in
	    *-*-linux*)
	      if test "X$RPATH" = "X"; then
	        RPATH="-Wl,-rpath,${LIBCYRUS_LIB_DIR}"
	      else 
		RPATH="${RPATH}:${LIBCYRUS_LIB_DIR}"
	      fi
	      ;;
	    *-*-hpux*)
	      if test "X$RPATH" = "X"; then
	        RPATH="-Wl,+b${LIBCYRUS_LIB_DIR}"
	      else 
		RPATH="${RPATH}:${LIBCYRUS_LIB_DIR}"
	      fi
	      ;;
	    *-*-irix*)
	      if test "X$RPATH" = "X"; then
	        RPATH="-Wl,-rpath,${LIBCYRUS_LIB_DIR}"
	      else 
		RPATH="${RPATH}:${LIBCYRUS_LIB_DIR}"
	      fi
	      ;;
	    *-*-solaris2*)
	      if test "$ac_cv_prog_gcc" = yes; then
		if test "X$RPATH" = "X"; then
		  RPATH="-Wl,-R${LIBCYRUS_LIB_DIR}"
		else 
		  RPATH="${RPATH}:${LIBCYRUS_LIB_DIR}"
		fi
	      else
	        RPATH="${RPATH} -R${LIBCYRUS_LIB_DIR}"
	      fi
	      ;;
	  esac
	  AC_SUBST(RPATH)
	fi
	AC_SUBST(LIBCYRUS_INC_DIR)
	AC_SUBST(LIBCYRUS_LIB_DIR)
	AC_SUBST(LIBCYRUS_INC_FLAGS)
	AC_SUBST(LIBCYRUS_LIB_FLAGS)
	])


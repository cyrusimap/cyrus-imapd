dnl libloguse.m4--LOGUSE libraries and includes
dnl Derrick Brashear
dnl from KTH krb and Arla
dnl $Id: libloguse.m4,v 1.4 2002/12/21 18:44:24 cg2v Exp $

AC_DEFUN(CMU_LOGUSE_LIB_WHERE1, [
saved_LIBS=$LIBS
LIBS="$saved_LIBS -L$1 -lloguse"
AC_TRY_LINK(,
[loguse("","","");],
[ac_cv_found_loguse_lib=yes],
ac_cv_found_loguse_lib=no)
LIBS=$saved_LIBS
])

AC_DEFUN(CMU_LOGUSE_LIB_WHERE, [
   for i in $1; do
      AC_MSG_CHECKING(for loguse library in $i)
      CMU_LOGUSE_LIB_WHERE1($i)
      CMU_TEST_LIBPATH($i, loguse)
      if test "$ac_cv_found_loguse_lib" = "yes" ; then
        ac_cv_loguse_where_lib=$i
        AC_MSG_RESULT(found)
        break
      else
        AC_MSG_RESULT(no found)
      fi
    done
])

AC_DEFUN(CMU_LOGUSE, [
AC_REQUIRE([CMU_SOCKETS])
AC_ARG_WITH(loguse,
	[  --with-loguse=PREFIX      Compile with LOGUSE support],
	[if test "X$with_loguse" = "X"; then
		with_loguse=yes
	fi])

	if test "X$with_loguse" != "X"; then
	  if test "$with_loguse" != "yes"; then
	    ac_cv_loguse_where_lib=$with_loguse/lib
	  fi
	fi

	if test "X$with_loguse_lib" != "X"; then
	  ac_cv_loguse_where_lib=$with_loguse_lib
	fi
	if test "X$ac_cv_loguse_where_lib" = "X"; then
	  CMU_LOGUSE_LIB_WHERE(/usr/lib /usr/local/lib)
	fi

	AC_MSG_CHECKING(whether to include loguse)
	if test "X$ac_cv_loguse_where_lib" = "X"; then
	  ac_cv_found_loguse=no
	  AC_MSG_RESULT(no)
	else
	  ac_cv_found_loguse=yes
	  AC_DEFINE(HAVE_LOGUSE)
	  AC_MSG_RESULT(yes)
	  LOGUSE_LIB_DIR=$ac_cv_loguse_where_lib
	  LOGUSE_LIB_FLAGS="-L${LOGUSE_LIB_DIR} -lloguse"
	  if test "X$RPATH" = "X"; then
		RPATH=""
	  fi
	  case "${host}" in
	    *-*-linux*)
	      if test "X$RPATH" = "X"; then
	        RPATH="-Wl,-rpath,${LOGUSE_LIB_DIR}"
	      else 
		RPATH="${RPATH}:${LOGUSE_LIB_DIR}"
	      fi
	      ;;
	    *-*-hpux*)
	      if test "X$RPATH" = "X"; then
	        RPATH="-Wl,+b${LOGUSE_LIB_DIR}"
	      else 
		RPATH="${RPATH}:${LOGUSE_LIB_DIR}"
	      fi
	      ;;
	    *-*-irix*)
	      if test "X$RPATH" = "X"; then
	        RPATH="-Wl,-rpath,${LOGUSE_LIB_DIR}"
	      else 
		RPATH="${RPATH}:${LOGUSE_LIB_DIR}"
	      fi
	      ;;
	    *-*-solaris2*)
	      if test "$ac_cv_prog_gcc" = yes; then
		if test "X$RPATH" = "X"; then
		  RPATH="-Wl,-R${LOGUSE_LIB_DIR}"
		else 
		  RPATH="${RPATH}:${LOGUSE_LIB_DIR}"
		fi
	      else
	        RPATH="${RPATH} -R${LOGUSE_LIB_DIR}"
	      fi
	      ;;
	  esac
	  AC_SUBST(RPATH)
	fi
	])


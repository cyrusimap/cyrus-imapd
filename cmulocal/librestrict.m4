dnl librestrict.m4--restrict libraries and includes
dnl Derrick Brashear
dnl from KTH krb and Arla
dnl $Id: librestrict.m4,v 1.6 2006/02/25 18:26:22 cg2v Exp $

AC_DEFUN([CMU_RESTRICT_LIB_WHERE1], [
saved_LIBS=$LIBS
LIBS="$saved_LIBS -L$1 -lrestrict"
AC_TRY_LINK(,
[ConsoleInUse();],
[ac_cv_found_restrict_lib=yes],
ac_cv_found_restrict_lib=no)
LIBS=$saved_LIBS
])

AC_DEFUN([CMU_RESTRICT_LIB_WHERE], [
   for i in $1; do
      AC_MSG_CHECKING(for restrict library in $i)
      CMU_RESTRICT_LIB_WHERE1($i)
      CMU_TEST_LIBPATH($i, restrict)
      if test "$ac_cv_found_restrict_lib" = "yes" ; then
        ac_cv_restrict_where_lib=$i
        AC_MSG_RESULT(found)
        break
      else
        AC_MSG_RESULT(no found)
      fi
    done
])

AC_DEFUN([CMU_RESTRICT], [
AC_REQUIRE([CMU_FIND_LIB_SUBDIR])
AC_ARG_WITH(restrict,
	[  --with-restrict=PREFIX      Compile with RESTRICT support],
	[if test "X$with_restrict" = "X"; then
		with_restrict=yes
	fi])

	if test "X$with_restrict" != "X"; then
	  if test "$with_restrict" != "yes"; then
	    ac_cv_restrict_where_lib=$with_restrict/$CMU_LIB_SUBDIR
	  fi
	fi

	if test "X$with_restrict_lib" != "X"; then
	  ac_cv_restrict_where_lib=$with_restrict_lib
	fi
	if test "X$ac_cv_restrict_where_lib" = "X"; then
	  CMU_RESTRICT_LIB_WHERE(/usr/$CMU_LIB_SUBDIR /usr/local/$CMU_LIB_SUBDIR)
	fi

	AC_MSG_CHECKING(whether to include restrict)
	if test "X$ac_cv_restrict_where_lib" = "X"; then
	  ac_cv_found_restrict=no
	  AC_MSG_RESULT(no)
	else
	  ac_cv_found_restrict=yes
	  AC_DEFINE(HAVE_RESTRICT,, [Use librestrict])
	  AC_MSG_RESULT(yes)
	  RESTRICT_LIB_DIR=$ac_cv_restrict_where_lib
	  RESTRICT_LIB_FLAGS="-L${RESTRICT_LIB_DIR} -lrestrict"
	  if test "X$RPATH" = "X"; then
		RPATH=""
	  fi
	  case "${host}" in
	    *-*-linux*)
	      if test "X$RPATH" = "X"; then
	        RPATH="-Wl,-rpath,${RESTRICT_LIB_DIR}"
	      else 
		RPATH="${RPATH}:${RESTRICT_LIB_DIR}"
	      fi
	      ;;
	    *-*-hpux*)
	      if test "X$RPATH" = "X"; then
	        RPATH="-Wl,+b${RESTRICT_LIB_DIR}"
	      else 
		RPATH="${RPATH}:${RESTRICT_LIB_DIR}"
	      fi
	      ;;
	    *-*-irix*)
	      if test "X$RPATH" = "X"; then
	        RPATH="-Wl,-rpath,${RESTRICT_LIB_DIR}"
	      else 
		RPATH="${RPATH}:${RESTRICT_LIB_DIR}"
	      fi
	      ;;
	    *-*-solaris2*)
	      if test "$ac_cv_prog_gcc" = yes; then
		if test "X$RPATH" = "X"; then
		  RPATH="-Wl,-R${RESTRICT_LIB_DIR}"
		else 
		  RPATH="${RPATH}:${RESTRICT_LIB_DIR}"
		fi
	      else
	        RPATH="${RPATH} -R${RESTRICT_LIB_DIR}"
	      fi
	      ;;
	  esac
	  AC_SUBST(RPATH)
	fi
	])


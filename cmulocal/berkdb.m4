

AC_DEFUN(CMU_DB_INC_WHERE1, [
AC_REQUIRE([AC_PROG_CC_GNU])
saved_CPPFLAGS=$CPPFLAGS
CPPFLAGS="$saved_CPPFLAGS -I$1"
AC_TRY_COMPILE([#include <db.h>],
[DB *db;
db_create(&db, NULL, 0);
db->open(db, "foo.db", NULL, DB_UNKNOWN, DB_RDONLY, 0644);],
ac_cv_found_db_inc=yes,
ac_cv_found_db_inc=no)
CPPFLAGS=$saved_CPPFLAGS
])

AC_DEFUN(CMU_DB_INC_WHERE, [
   for i in $1; do
      AC_MSG_CHECKING(for db headers in $i)
      CMU_DB_INC_WHERE1($i)
      CMU_TEST_INCPATH($i, db)
      if test "$ac_cv_found_db_inc" = "yes"; then
        ac_cv_db_where_inc=$i
        AC_MSG_RESULT(found)
        break
      else
        AC_MSG_RESULT(not found)
      fi
    done
])

#
# Test for lib files
#

AC_DEFUN(CMU_DB_LIB_WHERE1, [
AC_REQUIRE([AC_PROG_CC_GNU])
AC_REQUIRE([CMU_AFS])
AC_REQUIRE([CMU_KRB4])
saved_LIBS=$LIBS
if test "$enable_db4" = "yes"; then
  LIBS="$saved_LIBS -L$1 -ldb-4"
else
  LIBS="$saved_LIBS -L$1 -ldb-3"
fi
AC_TRY_LINK(,
[db_env_create();],
[ac_cv_found_db_lib=yes],
ac_cv_found_db_lib=no)
LIBS=$saved_LIBS
])

AC_DEFUN(CMU_DB_LIB_WHERE, [
   for i in $1; do
      AC_MSG_CHECKING(for db libraries in $i)
      CMU_DB_LIB_WHERE1($i)
      CMU_TEST_LIBPATH($i, db)
      if test "$ac_cv_found_db_lib" = "yes" ; then
        ac_cv_db_where_lib=$i
        AC_MSG_RESULT(found)
        break
      else
        AC_MSG_RESULT(not found)
      fi
    done
])

AC_DEFUN(CMU_USE_DB, [
AC_ARG_WITH(db,
	[  --with-db=PREFIX      Compile with db support],
	[if test "X$with_db" = "X"; then
		with_db=yes
	fi])
AC_ARG_WITH(db-lib,
	[  --with-db-lib=dir     use db libraries in dir],
	[if test "$withval" = "yes" -o "$withval" = "no"; then
		AC_MSG_ERROR([No argument for --with-db-lib])
	fi])
AC_ARG_WITH(db-include,
	[  --with-db-include=dir use db headers in dir],
	[if test "$withval" = "yes" -o "$withval" = "no"; then
		AC_MSG_ERROR([No argument for --with-db-include])
	fi])
AC_ARG_ENABLE(db4,
	[  --enable-db4          use db 4.x libraries])
	
	if test "X$with_db" != "X"; then
	  if test "$with_db" != "yes"; then
	    ac_cv_db_where_lib=$with_db/lib
	    ac_cv_db_where_inc=$with_db/include
	  fi
	fi

	if test "X$with_db_lib" != "X"; then
	  ac_cv_db_where_lib=$with_db_lib
	fi
	if test "X$ac_cv_db_where_lib" = "X"; then
	  CMU_DB_LIB_WHERE(/usr/athena/lib /usr/lib /usr/local/lib)
	fi

	if test "X$with_db_include" != "X"; then
	  ac_cv_db_where_inc=$with_db_include
	fi
	if test "X$ac_cv_db_where_inc" = "X"; then
	  CMU_DB_INC_WHERE(/usr/athena/include /usr/local/include)
	fi

	AC_MSG_CHECKING(whether to include db)
	if test "X$ac_cv_db_where_lib" = "X" -o "X$ac_cv_db_where_inc" = "X"; then
	  ac_cv_found_db=no
	  AC_MSG_RESULT(no)
	else
	  ac_cv_found_db=yes
	  AC_MSG_RESULT(yes)
	  DB_INC_DIR=$ac_cv_db_where_inc
	  DB_LIB_DIR=$ac_cv_db_where_lib
	  DB_INC_FLAGS="-I${DB_INC_DIR}"
          if test "$enable_db4" = "yes"; then
	     DB_LIB_FLAGS="-L${DB_LIB_DIR} -ldb-4"
          else
	     DB_LIB_FLAGS="-L${DB_LIB_DIR} -ldb-3"
          fi
          dnl Do not force configure.in to put these in CFLAGS and LIBS unconditionally
          dnl Allow makefile substitutions....
          AC_SUBST(DB_INC_FLAGS)
          AC_SUBST(DB_LIB_FLAGS)
	  if test "X$RPATH" = "X"; then
		RPATH=""
	  fi
	  case "${host}" in
	    *-*-linux*)
	      if test "X$RPATH" = "X"; then
	        RPATH="-Wl,-rpath,${DB_LIB_DIR}"
	      else 
		RPATH="${RPATH}:${DB_LIB_DIR}"
	      fi
	      ;;
	    *-*-hpux*)
	      if test "X$RPATH" = "X"; then
	        RPATH="-Wl,+b${DB_LIB_DIR}"
	      else 
		RPATH="${RPATH}:${DB_LIB_DIR}"
	      fi
	      ;;
	    *-*-irix*)
	      if test "X$RPATH" = "X"; then
	        RPATH="-Wl,-rpath,${DB_LIB_DIR}"
	      else 
		RPATH="${RPATH}:${DB_LIB_DIR}"
	      fi
	      ;;
	    *-*-solaris2*)
	      if test "$ac_cv_prog_gcc" = yes; then
		if test "X$RPATH" = "X"; then
		  RPATH="-Wl,-R${DB_LIB_DIR}"
		else 
		  RPATH="${RPATH}:${DB_LIB_DIR}"
		fi
	      else
	        RPATH="${RPATH} -R${DB_LIB_DIR}"
	      fi
	      ;;
	  esac
	  AC_SUBST(RPATH)
	fi
	])


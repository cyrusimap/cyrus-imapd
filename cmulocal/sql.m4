dnl $Id: sql.m4,v 1.2 2010/01/06 17:01:28 murch Exp $

dnl These are the Cyrus MySQL macros.

dnl They are here so that they can be shared between Cyrus IMAPd
dnl and Cyrus SASL with relative ease.

dnl When we're done, there will be a MYSQL_LIBADD and a MYSQL_INCADD which
dnl should dnl be used when necessary. 
dnl We should probably be smarter about our RPATH dnl handling.

dnl Call these with CYRUS_MYSQL_CHK.

dnl We will also set $mysqllib to "yes" if we are successful, "no" otherwise.

AC_DEFUN([CYRUS_MYSQL_CHK_LIB],
[
	MYSQL_SAVE_LDFLAGS=$LDFLAGS

	if test -d $with_mysql_lib; then
	    CMU_ADD_LIBPATH_TO($with_mysql_lib, LDFLAGS)
	    CMU_ADD_LIBPATH_TO($with_mysql_lib, MYSQL_LIBADD)
	else
	    MYSQL_LIBADD=""
	fi

	saved_LIBS=$LIBS
        for libname in ${with_mysql} mysqlclient
          do
	    LIBS="$saved_LIBS -l$libname"
	    AC_TRY_LINK([#include <stdio.h>
#include <mysql.h>],
	    [mysql_select_db(NULL, NULL);],
	    MYSQL_LIBADD="$MYSQL_LIBADD -l$libname"; mysqllib="yes",
            mysqllib="no")
	    if test "$mysqllib" = "yes"; then break; fi
          done
	LIBS=$saved_LIBS

	LDFLAGS=$MYSQL_SAVE_LDFLAGS
])

AC_DEFUN([CYRUS_MYSQL_OPTS],
[
AC_ARG_WITH(mysql-libdir,
	[  --with-mysql-libdir=DIR   MySQL lib files are in DIR],
	with_mysql_lib=$withval,
	[ test "${with_mysql_lib+set}" = set || with_mysql_lib=none])
AC_ARG_WITH(mysql-incdir,
	[  --with-mysql-incdir=DIR   MySQL include files are in DIR],
	with_mysql_inc=$withval,
	[ test "${with_mysql_inc+set}" = set || with_mysql_inc=none ])
])

AC_DEFUN([CYRUS_MYSQL_CHK],
[
	AC_REQUIRE([CYRUS_MYSQL_OPTS])

	cmu_save_CPPFLAGS=$CPPFLAGS

	if test -d $with_mysql_inc; then
	    CPPFLAGS="$CPPFLAGS -I$with_mysql_inc"
	    MYSQL_INCADD="-I$with_mysql_inc"
	else
	    MYSQL_INCADD=""
	fi

        AC_CHECK_HEADER(mysql.h,
                        [CYRUS_MYSQL_CHK_LIB()],
                        mysqllib="no")

	CPPFLAGS=$cmu_save_CPPFLAGS
])



dnl These are the Cyrus PgSQL macros.

dnl They are here so that they can be shared between Cyrus IMAPd
dnl and Cyrus SASL with relative ease.

dnl When we're done, there will be a PGSQL_LIBADD and a PGSQL_INCADD which
dnl should dnl be used when necessary. 
dnl We should probably be smarter about our RPATH dnl handling.

dnl Call these with CYRUS_PGSQL_CHK.

dnl We will also set $pgsqllib to "yes" if we are successful, "no" otherwise.

AC_DEFUN([CYRUS_PGSQL_CHK_LIB],
[
	PGSQL_SAVE_LDFLAGS=$LDFLAGS

	if test -d $with_pgsql_lib; then
	    CMU_ADD_LIBPATH_TO($with_pgsql_lib, LDFLAGS)
	    CMU_ADD_LIBPATH_TO($with_pgsql_lib, PGSQL_LIBADD)
	else
	    PGSQL_LIBADD=""
	fi

	saved_LIBS=$LIBS
        for libname in ${with_pgsql} pq
          do
	    LIBS="$saved_LIBS -l$libname"
	    AC_TRY_LINK([#include <stdio.h>
#include <libpq-fe.h>],
	    [PQconnectdb(NULL);],
	    PGSQL_LIBADD="$PGSQL_LIBADD -l$libname"; pgsqllib="yes",
            pgsqllib="no")
	    if test "$pgsqllib" = "yes"; then break; fi
          done
	LIBS=$saved_LIBS

	LDFLAGS=$PGSQL_SAVE_LDFLAGS
])

AC_DEFUN([CYRUS_PGSQL_OPTS],
[
AC_ARG_WITH(pgsql-libdir,
	[  --with-pgsql-libdir=DIR   Pgsql lib files are in DIR],
	with_pgsql_lib=$withval,
	[ test "${with_pgsql_lib+set}" = set || with_pgsql_lib=none])
AC_ARG_WITH(pgsql-incdir,
	[  --with-pgsql-incdir=DIR   Pgsql include files are in DIR],
	with_pgsql_inc=$withval,
	[ test "${with_pgsql_inc+set}" = set || with_pgsql_inc=none ])
])

AC_DEFUN([CYRUS_PGSQL_CHK],
[
	AC_REQUIRE([CYRUS_PGSQL_OPTS])

	cmu_save_CPPFLAGS=$CPPFLAGS

	if test -d $with_pgsql_inc; then
	    CPPFLAGS="$CPPFLAGS -I$with_pgsql_inc"
	    PGSQL_INCADD="-I$with_pgsql_inc"
	else
	    PGSQL_INCADD=""
	fi

        AC_CHECK_HEADER(libpq-fe.h,
                        [CYRUS_PGSQL_CHK_LIB()],
                        pgsqllib="no")

	CPPFLAGS=$cmu_save_CPPFLAGS
])



dnl These are the Cyrus SQLite macros.

dnl They are here so that they can be shared between Cyrus IMAPd
dnl and Cyrus SASL with relative ease.

dnl When we're done, there will be a SQLITE_LIBADD and a SQLITE_INCADD which
dnl should dnl be used when necessary. 
dnl We should probably be smarter about our RPATH dnl handling.

dnl Call these with CYRUS_SQLITE_CHK.

dnl We will also set $sqlitelib to "yes" if we are successful, "no" otherwise.

AC_DEFUN([CYRUS_SQLITE_CHK_LIB],
[
	SQLITE_SAVE_LDFLAGS=$LDFLAGS

	if test -d $with_sqlite_lib; then
	    CMU_ADD_LIBPATH_TO($with_sqlite_lib, LDFLAGS)
	    CMU_ADD_LIBPATH_TO($with_sqlite_lib, SQLITE_LIBADD)
	else
	    SQLITE_LIBADD=""
	fi

	saved_LIBS=$LIBS
        for libname in ${with_sqlite} sqlite3
          do
	    LIBS="$saved_LIBS -l$libname"
	    AC_TRY_LINK([#include <stdio.h>
#include <sqlite3.h>],
	    [sqlite3_open(NULL, NULL);],
	    SQLITE_LIBADD="$SQLITE_LIBADD -l$libname"; sqlitelib="yes",
            sqlitelib="no")
	    if test "$sqlitelib" = "yes"; then break; fi
          done
	LIBS=$saved_LIBS

	LDFLAGS=$SQLITE_SAVE_LDFLAGS
])

AC_DEFUN([CYRUS_SQLITE_OPTS],
[
AC_ARG_WITH(sqlite-libdir,
	[  --with-sqlite-libdir=DIR   SQLite lib files are in DIR],
	with_sqlite_lib=$withval,
	[ test "${with_sqlite_lib+set}" = set || with_sqlite_lib=none])
AC_ARG_WITH(sqlite-incdir,
	[  --with-sqlite-incdir=DIR   SQLite include files are in DIR],
	with_sqlite_inc=$withval,
	[ test "${with_sqlite_inc+set}" = set || with_sqlite_inc=none ])
])

AC_DEFUN([CYRUS_SQLITE_CHK],
[
	AC_REQUIRE([CYRUS_SQLITE_OPTS])

	cmu_save_CPPFLAGS=$CPPFLAGS

	if test -d $with_sqlite_inc; then
	    CPPFLAGS="$CPPFLAGS -I$with_sqlite_inc"
	    SQLITE_INCADD="-I$with_sqlite_inc"
	else
	    SQLITE_INCADD=""
	fi

        AC_CHECK_HEADER(sqlite3.h,
                        [CYRUS_SQLITE_CHK_LIB()],
                        sqlitelib="no")

	CPPFLAGS=$cmu_save_CPPFLAGS
])

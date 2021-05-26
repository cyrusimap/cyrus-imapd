dnl Process this file with autoconf to produce a configure script.

dnl
dnl Copyright (c) 1994-2008 Carnegie Mellon University.  All rights reserved.
dnl
dnl Redistribution and use in source and binary forms, with or without
dnl modification, are permitted provided that the following conditions
dnl are met:
dnl
dnl 1. Redistributions of source code must retain the above copyright
dnl    notice, this list of conditions and the following disclaimer.
dnl
dnl 2. Redistributions in binary form must reproduce the above copyright
dnl    notice, this list of conditions and the following disclaimer in
dnl    the documentation and/or other materials provided with the
dnl    distribution.
dnl
dnl 3. The name "Carnegie Mellon University" must not be used to
dnl    endorse or promote products derived from this software without
dnl    prior written permission. For permission or any legal
dnl    details, please contact
dnl      Carnegie Mellon University
dnl      Center for Technology Transfer and Enterprise Creation
dnl      4615 Forbes Avenue
dnl      Suite 302
dnl      Pittsburgh, PA  15213
dnl      (412) 268-7393, fax: (412) 268-7395
dnl      innovation@andrew.cmu.edu
dnl
dnl 4. Redistributions of any form whatsoever must retain the following
dnl    acknowledgment:
dnl    "This product includes software developed by Computing Services
dnl     at Carnegie Mellon University (http://www.cmu.edu/computing/)."
dnl
dnl CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
dnl THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
dnl AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
dnl FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
dnl WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
dnl AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
dnl OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
dnl
dnl configure.ac for the Cyrus imapd
dnl


AC_INIT([cyrus-imapd],
        m4_esyscmd(printf '%s' $(tools/git-version.sh)),
        [https://github.com/cyrusimap/cyrus-imapd/issues],
        ,
        [https://www.cyrusimap.org])
AC_PREREQ([2.63])
AC_CONFIG_SRCDIR([imap/imapd.c])
AC_CONFIG_HEADERS(config.h)
AC_CONFIG_MACRO_DIR([cmulocal])
AC_CANONICAL_SYSTEM

dnl shared or static
ENABLE_SHARED="$enable_shared"
AC_SUBST(ENABLE_SHARED)

ENABLE_STATIC="$enable_static"
AC_SUBST(ENABLE_STATIC)

dnl carve the version string (defined in AC_INIT above) into useful chunks
dnl e.g. for version 3.0.0-beta:
dnl   CYRUS_IMAPD_SERIES   => 3.0
dnl   CYRUS_IMAPD_REVISION => 0
dnl   CYRUS_IMAPD_PATCH    => beta2
CYRUS_IMAPD_SERIES=`echo AC_PACKAGE_VERSION | cut -d- -f1 | cut -d. -f1-2`
CYRUS_IMAPD_REVISION=`echo AC_PACKAGE_VERSION | cut -d- -f1 | cut -d. -f3`
CYRUS_IMAPD_PATCH=`echo AC_PACKAGE_VERSION | cut -d- -f2-`
AC_SUBST([CYRUS_IMAPD_SERIES])
AC_SUBST([CYRUS_IMAPD_REVISION])
AC_SUBST([CYRUS_IMAPD_PATCH])

dnl in case the first use of PKG_CHECK_MODULES is inside a conditional
PKG_PROG_PKG_CONFIG

AM_INIT_AUTOMAKE([-Wall -Werror -Wno-portability foreign dist-bzip2
                  no-installinfo subdir-objects silent-rules tar-ustar])
AC_CONFIG_LIBOBJ_DIR([lib])

dnl Useful hook for distributions
AC_ARG_WITH(extraident,
        [AS_HELP_STRING([--with-extraident=STRING],[use STRING as extra version information])],
        [AC_DEFINE_UNQUOTED(EXTRA_IDENT,"$withval", [Extra version information for imap/version.h])])

AM_MAINTAINER_MODE

dnl Coverage (disabled by default)
GCOV_CFLAGS=
GCOV_CXXFLAGS=
GCOV_LDFLAGS=
GCOV_LIBS=

AC_ARG_ENABLE(coverage,
    AS_HELP_STRING([--enable-coverage],[enable C test coverage])
)

AS_IF([test "x$enable_coverage" = "xyes"], [
    GCOV_CFLAGS="--coverage"
    GCOV_CXXFLAGS="--coverage"
    GCOV_LDFLAGS="--coverage"
    GCOV_LIBS="-lgcov"
])
AM_CONDITIONAL([HAVE_COVERAGE], [test "x$enable_coverage" = "xyes"])

AC_SUBST(GCOV_CFLAGS)
AC_SUBST(GCOV_CXXFLAGS)
AC_SUBST(GCOV_LDFLAGS)
AC_SUBST(GCOV_LIBS)

AC_ARG_WITH(login,,AC_MSG_ERROR([--with-login is no longer supported.
Configure SASL appropriately instead.]))

AC_ARG_WITH(cyrus-user,
        [AS_HELP_STRING([--with-cyrus-user=USERID], [use USERID cyrus userid])],
        cyrus_user="$withval",cyrus_user="cyrus")
AC_SUBST(cyrus_user)
AC_DEFINE_UNQUOTED(CYRUS_USER, "$cyrus_user",[What user will we run as?])

dnl allow users to override $sysconfdir, but retain old default (/etc)
dnl if not specified
if test $sysconfdir = '${prefix}/etc'; then
  sysconfdir="/etc"
fi

dnl for some reason AC_PROG_CXX can succeed even though c++ compiler is missing
dnl if it is invoked after AC_PROG_CC, so instead invoke it first
dnl ref: https://lists.gnu.org/archive/html/bug-autoconf/2010-05/msg00001.html
AC_PROG_CXX
AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_PROG_INSTALL
AC_USE_SYSTEM_EXTENSIONS
AC_ISC_POSIX
AC_PROG_AWK
AC_SYS_LONG_FILE_NAMES
if test $ac_cv_sys_long_file_names = no; then
        AC_MSG_ERROR(The Cyrus IMAPD requires support for long file names)
fi
AC_C_INLINE

gl_VISIBILITY
AH_BOTTOM([#if HAVE_VISIBILITY
#define EXPORTED __attribute__((__visibility__("default")))
#define HIDDEN   __attribute__((__visibility__("hidden")))
#else
#define EXPORTED
#define HIDDEN
#endif])

AH_BOTTOM([#if defined __GNUC__ &&  __GNUC__ > 6
    #define GCC_FALLTHROUGH __attribute__((fallthrough));
#else
    #define GCC_FALLTHROUGH /* fall through */
#endif
])

LT_PREREQ([2.2.6])
LT_INIT([disable-static])
AC_SUBST([LIBTOOL_DEPS])

dnl Check the size of various types
AC_CHECK_SIZEOF(int)
AC_CHECK_SIZEOF(long)
AC_CHECK_SIZEOF(size_t)
AC_CHECK_SIZEOF(off_t)
AC_CHECK_SIZEOF(time_t)

dnl Warn if time_t is only 32 bits
AS_IF([test "$ac_cv_sizeof_time_t" -lt 8],
      [AC_MSG_WARN([Your platform's time_t is less than 64 bits])
])

dnl Check that `long long int' is available
AC_CHECK_SIZEOF(long long int)
AC_CHECK_SIZEOF(unsigned long long int)
if test "$ac_cv_sizeof_long_long_int" -eq 8 -a \
        "$ac_cv_sizeof_unsigned_long_long_int" -eq 8; then
  AC_C_BIGENDIAN
else
  AC_MSG_ERROR(The Cyrus IMAPD requires support for long long int)
fi

dnl Check the required alignment for various types
AC_CHECK_ALIGNOF(uint32_t)

dnl check for -R, etc. switch
CMU_GUESS_RUNPATH_SWITCH

AC_CHECK_HEADERS(unistd.h sys/select.h sys/param.h stdarg.h)
AC_REPLACE_FUNCS(memmove strcasecmp ftruncate strerror posix_fadvise strsep memmem memrchr)
AC_CHECK_FUNCS(strlcat strlcpy strnchr getgrouplist fmemopen pselect futimens futimes)
AC_HEADER_DIRENT

dnl check whether to use getpassphrase or getpass
AC_CHECK_HEADERS(stdlib.h)
AC_CHECK_FUNCS(getpassphrase)


# backwards compat with older pkg-config
m4_ifndef([PKG_CHECK_VAR], [
AC_DEFUN([PKG_CHECK_VAR],
        [AC_REQUIRE([PKG_PROG_PKG_CONFIG])dnl
        AC_ARG_VAR([$1], [value of $3 for $2, overriding pkg-config])dnl
        _PKG_CONFIG([$1], [variable="][$3]["], [$2])
        AS_VAR_COPY([$1], [pkg_cv_][$1])
        AS_VAR_IF([$1], [""], [$5], [$4])dnl
        ])
        ])

dnl do this before Berkeley DB/IPv6 detection
CMU_SOCKETS
LIBS="$LIBS ${LIB_SOCKET}"

dnl check for IPv6 functions (fall back to sasl's if we don't have them)
cyrus_cv_getaddrinfo=yes
IPv6_CHECK_FUNC(getaddrinfo, [IPv6_CHECK_FUNC(gai_strerror,
        AC_DEFINE(HAVE_GETADDRINFO,[],[Do we have a getaddrinfo?]),
        cyrus_cv_getaddrinfo=no)], cyrus_cv_getaddrinfo=no)

cyrus_cv_getnameinfo=yes
IPv6_CHECK_FUNC(getnameinfo,
        AC_DEFINE(HAVE_GETNAMEINFO,[],[Do we have a getnameinfo?]),
        cyrus_cv_getnameinfo=no)

AM_CONDITIONAL([IPV6_noGETADDRINFO], [test $cyrus_cv_getaddrinfo = no])
AM_CONDITIONAL([IPV6_noGETNAMEINFO], [test $cyrus_cv_getnameinfo = no])
IPv6_CHECK_SS_FAMILY()
IPv6_CHECK_SA_LEN()

dnl this is to check for time things
AC_CHECK_HEADERS(sys/time.h)
AC_HEADER_TIME
AC_STRUCT_TM
AC_STRUCT_TIMEZONE
AC_CHECK_FUNCS(timegm)

AC_SUBST(CPPFLAGS)
AC_SUBST(LOCALDEFS)
AC_FUNC_VPRINTF

CYR_INTTYPE([time_t], [#include <time.h>])
AC_DEFINE_UNQUOTED([TIME_T_FMT], ["$cyr_cv_format_time_t"],
                   [printf formatter for time_t])
AC_DEFINE_UNQUOTED([strtotimet(a,b,c)], [$cyr_cv_parse_time_t(a,b,c)],
                   [strtol-like parse function for time_t])

CYR_INTTYPE([size_t], [#include <stdlib.h>])
AC_DEFINE_UNQUOTED([SIZE_T_FMT], ["$cyr_cv_format_size_t"],
                   [printf formatter for size_t])
AC_DEFINE_UNQUOTED([strtosizet(a,b,c)], [$cyr_cv_parse_size_t(a,b,c)],
                   [strtol-like parse function for size_t])

CYR_INTTYPE([off_t], [#include <sys/types.h>])
AC_DEFINE_UNQUOTED([OFF_T_FMT], ["$cyr_cv_format_off_t"],
                   [printf formatter for off_t])
AC_DEFINE_UNQUOTED([strtoofft(a,b,c)], [$cyr_cv_parse_off_t(a,b,c)],
                   [strtol-like parse function for off_t])

CYR_INTTYPE([rlim_t], [#include <sys/resource.h>])
AC_DEFINE_UNQUOTED([RLIM_T_FMT], ["$cyr_cv_format_rlim_t"],
                   [printf formatter for rlim_t])
AC_DEFINE_UNQUOTED([strtorlimt(a,b,c)], [$cyr_cv_parse_rlim_t(a,b,c)],
                   [strtol-like parse function for rlim_t])

dnl function for doing each of the database backends
dnl parameters: backend name, variable to set, withval

dnl SQL DB Detection

HAVE_CYRUSDB_SQL=0

dnl MySQL Detection

dnl legacy options --with-mysql-libdir and --with-mysql-incdir
CYRUS_MYSQL_OPTS
if test "$with_mysql_lib" != none ; then
    AC_MSG_NOTICE([Legacy option --with-mysql-libdir=DIR detected.]
                  [You may wish to change to --with-mysql which works now.])
    withval="$with_mysql_lib/.."
else
    withval="no"
fi

AC_MSG_CHECKING([whether to use MySQL])
AC_ARG_WITH(mysql,
        [AS_HELP_STRING([--with-mysql=DIR], [use MySQL (in DIR) [no]])])
with_mysql=$withval

case "$with_mysql" in
  no)
        # Explicitly disable MySQL
        ;;
  yes)
        # Find mysql_config in $PATH
        AC_PATH_PROG(mysql_config, mysql_config, [])
        AS_IF([test -z "$mysql_config"],
            AC_MSG_ERROR([The mysql_config program was not found]))
        ;;
  *)
        # Find mysql_config in the specified directory
        mysql_config="$with_mysql/bin/mysql_config"
        if test ! -x "$mysql_config" ; then
            AC_MSG_ERROR([The mysql_config program was not found]
                         [in $with_mysql/bin, disabling MySQL support])
            with_mysql="no"
        fi
        ;;
esac

if test "$with_mysql" != "no"; then
    MYSQL_LIBADD=`$mysql_config --libs`
    MYSQL_INCADD=`$mysql_config --cflags`
    HAVE_CYRUSDB_SQL=1
    LIBS="${LIBS} ${MYSQL_LIBADD}"
    CPPFLAGS="${MYSQL_INCADD} ${CPPFLAGS}"
    AC_DEFINE(HAVE_MYSQL,[],[Build in MySQL support?])
    AC_SUBST(MYSQL_LIBADD)
fi
AC_MSG_RESULT($with_mysql)

dnl End MySQL Detection


dnl PgSQL Detection
AC_ARG_WITH(pgsql,
        [AS_HELP_STRING([--with-pgsql=DIR], [use PostgreSQL (in DIR) [no]])],
        with_pgsql=$withval, with_pgsql="no")

case "$with_pgsql" in
  no)
        use_pgsql="no"
        ;;
  yes)
        use_pgsql="yes"
        with_pgsql_lib=none
        with_pgsql_inc=none
        ;;
  *)
        use_pgsql="yes"
        with_pgsql_lib="$with_pgsql/lib"
        with_pgsql_inc="$with_pgsql/include"
        ;;
esac

if test "$use_pgsql" != "no"; then
  CYRUS_PGSQL_CHK()

  if test "$pgsqllib" = "no"; then
    AC_MSG_ERROR([PgSQL was not found.  You may need to supply the
    --with-pgsql-libdir or --with-pgsql-incdir configure options.])
  else
    HAVE_CYRUSDB_SQL=1
  fi

  if test "$with_pgsql_lib" != "none"; then
    CMU_ADD_LIBPATH($with_pgsql_lib)
  fi

  LIBS="${LIBS} ${PGSQL_LIBADD}"
  CPPFLAGS="${PGSQL_INCADD} ${CPPFLAGS}"

  AC_DEFINE(HAVE_PGSQL,[],[Build in PgSQL support?])
  AC_SUBST(PGSQL_LIBADD)
fi

dnl End PgSQL Detection


dnl SQLite Detection
dnl XXX this is a bit gross... the same option for specifying WHERE sqlite is
dnl (--with-sqlite) is also the option for enabling it as a cyrusdb backend,
dnl which means if your sqlite is in a non-default location and you need httpd
dnl or object storage etc, you're suddenly also supporting it as a cyrusdb
dnl backend, possibly unexpectedly.
AC_ARG_WITH(sqlite,
        [AS_HELP_STRING([--with-sqlite=DIR], [use SQLite (in DIR) (check)])],
        with_sqlite=$withval, with_sqlite=check)

case "$with_sqlite" in
  no)
        use_sqlite="no"
        ;;
  yes)
        use_sqlite="yes"
        with_sqlite_lib=none
        with_sqlite_inc=none
        ;;
  check)
        use_sqlite="check"
        with_sqlite_lib=none
        with_sqlite_inc=none
        ;;
  *)
        use_sqlite="yes"
        with_sqlite_lib="$with_sqlite/lib"
        with_sqlite_inc="$with_sqlite/include"
        ;;
esac

if test "$use_sqlite" != "no"; then
  CYRUS_SQLITE_CHK()

  if test "$use_sqlite" = "yes"; then
    dnl sqlite specifically requested: not found is a failure
    if test "$sqlitelib" = "no"; then
        AC_MSG_ERROR([Sqlite was not found.  You may need to supply the
        --with-sqlite-libdir or --with-sqlite-incdir configure options.])
    else
        HAVE_CYRUSDB_SQL=1
        HAVE_SQLITE=1
    fi
  else
    dnl sqlite not specifically requested: not found isn't a failure (yet)
    use_sqlite="no"
    if test "$sqlitelib" = "no"; then
        AC_MSG_NOTICE([sqlite was not found, will try to build without it])
    else
        HAVE_SQLITE=1
    fi
  fi

  dnl other modules might yet need to link against sqlite.
  dnl we will update LIBS/CPPFLAGS etc later, once their checks have run.
  dnl for now:
  dnl   * $use_sqlite = "yes" if we definitely need it
  dnl   * $HAVE_SQLITE = 1 if we have it available
fi

dnl End SQLite Detection

if test "x$HAVE_CYRUSDB_SQL" = x1; then
    AC_DEFINE([USE_CYRUSDB_SQL],[],[Build in cyrusdb_sql support?])
fi
AM_CONDITIONAL([USE_CYRUSDB_SQL], [test $HAVE_CYRUSDB_SQL = 1])
dnl End SQL DB Detection

dnl
dnl Object Store support
dnl

dnl Caringo object store backend
AC_MSG_CHECKING([whether to use Caringo])
AC_ARG_WITH(caringo,
        [AS_HELP_STRING([--with-caringo], [use Caringo ("yes" or "no")])],,with_caringo="no")
case "$with_caringo" in
  yes)
	LDFLAGS="$LDFLAGS -lCastorSDK"
  ;;
esac
AC_MSG_RESULT([$with_caringo])

dnl OpenIO object store backend
dnl deps: metautils gridclient oiosds curl
AC_MSG_CHECKING([whether to use OpenIO])
AC_ARG_WITH(openio,
        [AS_HELP_STRING([--with-openio=yes|no], [use OpenIO ("yes" or "no")])],
        with_openio=$withval, with_openio="no")

case "$with_openio" in
  no)
	use_openio="no"
	;;
  yes)
	use_openio="yes"
	with_openio_lib=none
	with_openio_inc=none
	AC_DEFINE([WITH_OPENIO],[1],[Enable support for OpenIO object storage.])
	;;
  *)
	use_openio="yes"
	with_openio_lib="$with_openio/lib64"
	with_openio_inc="$with_openio/include"
	AC_DEFINE([WITH_OPENIO],[1],[Enable support for OpenIO object storage.])
	;;
esac

AC_ARG_WITH(openio-libdir,
        [AS_HELP_STRING([--with-openio-libdir=DIR], [OpenIO lib files are in DIR])],
        with_openio_lib=$withval,
        [ test "${with_openio_lib+set}" = set || with_openio_lib=none])
AC_ARG_WITH(openio-incdir,
        [AS_HELP_STRING([--with-openio-incdir=DIR], [OpenIO include files are in DIR])],
        with_openio_inc=$withval,
        [ test "${with_openio_inc+set}" = set || with_openio_inc=none ])

if test "$use_openio" = "yes"; then
	if test ! -d "$with_openio_lib"; then
		AC_MSG_ERROR([OpenIO library directory '$with_openio_lib' does not exist.])
	fi
	if test ! -d "$with_openio_inc"; then
		AC_MSG_ERROR([OpenIO include directory '$with_openio_inc' does not exist.])
	fi

	LDFLAGS="$LDFLAGS -L$with_openio_lib"
	CFLAGS="$CFLAGS -I$with_openio_inc"
	openio_headers="oio_sds.h core/oiourl.h"
	for h in $openio_headers; do
		AC_CHECK_HEADER($h,[],[
			AC_MSG_ERROR([Header $h is missing.])
		])
	done
	AC_CHECK_LIB([oiosds],[oio_error_free],[],[AC_MSG_ERROR([Library oiosds not found.])])
	AC_CHECK_LIB([oiocore],[oio_url_empty],[],[AC_MSG_ERROR([Library oiocore not found.])])
	AC_CHECK_LIB([curl],[curl_version],[],[AC_MSG_ERROR([Library curl not found.])])
	AC_CHECK_LIB([json-c],[json_tokener_parse_ex],[],[AC_MSG_ERROR([Library json-c not found.])])

	LDFLAGS="$LDFLAGS -L$with_openio_lib -loiosds -loiocore -lcurl -ljson-c"
fi
AC_MSG_RESULT([$use_openio])

dnl enable object store
AC_MSG_CHECKING([whether to enable object store])
AC_ARG_ENABLE(objectstore,
    [AS_HELP_STRING([--enable-objectstore],
        [enable IMAP objectstore support. Use --with-caringo or --with-openio to choose a backend])],
    [],
    [enable_objectstore=no])

with_objectstore_dummy=no
if test "x$enable_objectstore" != xno ; then
    dnl we need sqlite for the objectstore database
    if test "x$HAVE_SQLITE" != x1; then
        AC_MSG_ERROR([Need sqlite3 for objectstore])
    else
        use_sqlite="yes"
    fi

    dnl arbitrarily prioritise OpenIO over Caringo if both are requested
    AS_IF(
        [test "x$with_openio" != xno -a "x$with_caringo" != xno],
            [AC_MSG_WARN([both --with-openio and --with-caringo requested: using OpenIO])
             enable_objectstore="openio"
             with_caringo = "no"],
        [test "x$with_openio" != xno],
            [enable_objectstore="openio"],
        [test "x$with_caringo" != xno],
            [enable_objectstore="caringo"],
        [enable_objectstore="dummy"
         with_objectstore_dummy="yes"])
    AC_DEFINE([ENABLE_OBJECTSTORE],[],[Build with Object Store support])
fi
AC_MSG_RESULT([$enable_objectstore])
AM_CONDITIONAL([OBJECTSTORE], [test "x$enable_objectstore" != xno])
AM_CONDITIONAL([WITH_CARINGO], [test "x$with_caringo" != xno])
AM_CONDITIONAL([WITH_OPENIO], [test "x$use_openio" != xno])
AM_CONDITIONAL([WITH_OBJSTR_DUMMY], [test "x$with_objectstore_dummy" != xno])

dnl
dnl Search engines - SQUAT
dnl

AC_ARG_ENABLE(squat,
    [AS_HELP_STRING([--disable-squat], [disable Squat support])],,[enable_squat="yes";])

if test "$enable_squat" != "no"; then
    AC_DEFINE(USE_SQUAT,[],[Build in Squat support?])
fi

AM_CONDITIONAL([USE_SQUAT], [test "${enable_squat}" != "no"])

dnl
dnl Search engines - Xapian
dnl

xapian_cjk_tokens=none
AC_ARG_ENABLE(xapian,
        [AS_HELP_STRING([--enable-xapian], [enable Xapian support])],,
        [enable_xapian=no])
if test "x$enable_xapian" != xno ; then
    AC_ARG_VAR(RSYNC_BIN, [Location of rsync])
    AC_PATH_PROG(RSYNC_BIN, [rsync], [])
    AS_IF([test -z "$RSYNC_BIN"],[
        AC_MSG_ERROR([Can't find the 'rsync' binary])
    ])
    AC_DEFINE_UNQUOTED([RSYNC_BIN], ["$RSYNC_BIN"], [Path to 'rsync' binary])

    AC_ARG_VAR(XAPIAN_CONFIG, [Location of xapian-config])
    AC_PATH_PROGS(XAPIAN_CONFIG, [xapian-config-1.5 xapian-config], [])
    if test -z "$XAPIAN_CONFIG"; then
        AC_MSG_ERROR([Can't find Xapian library])
    else
        AC_MSG_CHECKING([$XAPIAN_CONFIG works])
        dnl check for --ltlibs but not --libs as xapian-config --libs will
        dnl fail if xapian isn't installed...

        dnl run with exec to avoid leaking output on "real" bourne shells
        if (exec >&5 2>&5 ; $XAPIAN_CONFIG --ltlibs --cxxflags; exit $?) then
            AC_MSG_RESULT(yes)
        else
            AC_MSG_ERROR([\`$XAPIAN_CONFIG --ltlibs --cxxflags' doesn't work, aborting])
        fi

        dnl Xapian requires CXX11
        AX_CXX_COMPILE_STDCXX_11([noext], [mandatory])

        dnl If AC_PROG_LIBTOOL (or the deprecated older version AM_PROG_LIBTOOL)
        dnl has already been expanded, enable libtool support now, otherwise add
        dnl hooks to the end of AC_PROG_LIBTOOL and AM_PROG_LIBTOOL to enable it
        dnl if either is expanded later.
        XAPIAN_VERSION="`$XAPIAN_CONFIG --version|sed 's/.* //'`"
        AS_VERSION_COMPARE([$XAPIAN_VERSION], [1.4], AC_MSG_ERROR([need at least Xapian 1.4]), [], [])
        XAPIAN_CXXFLAGS="`$XAPIAN_CONFIG --cxxflags`"
        AC_PROVIDE_IFELSE([AC_PROG_LIBTOOL],
            [XAPIAN_LIBS="`$XAPIAN_CONFIG --ltlibs`"],
            [AC_PROVIDE_IFELSE([AM_PROG_LIBTOOL],
                [XAPIAN_LIBS="`$XAPIAN_CONFIG --ltlibs`"],
                dnl Pass magic option so xapian-config knows we called it (so it
                dnl can choose a more appropriate error message if asked to link
                dnl with an uninstalled libxapian). Also pass ac_top_srcdir
                dnl so the error message can correctly say "configure.ac" or
                dnl "configure.in" according to which is in use.
                [XAPIAN_LIBS="`ac_top_srcdir=\"$ac_top_srcdir\" $XAPIAN_CONFIG --from-xo-lib-xapian --libs`"
                define([AC_PROG_LIBTOOL], defn([AC_PROG_LIBTOOL])
                       [XAPIAN_LIBS="`$XAPIAN_CONFIG --ltlibs`"])
                define([AM_PROG_LIBTOOL], defn([AM_PROG_LIBTOOL])
                       [XAPIAN_LIBS="`$XAPIAN_CONFIG --ltlibs`"])])])
        AC_DEFINE(USE_XAPIAN,[],[Build in Xapian support?])

        dnl check if Xapian supports Cyruslibs extensions
        AC_LANG_PUSH([C++])
        ORIG_LDFLAGS=$LDFLAGS
        ORIG_CXXFLAGS=$CXXFLAGS
        LDFLAGS="$LDFLAGS $XAPIAN_LIBS"
        CXXFLAGS="$CXXFLAGS $XAPIAN_CXXFLAGS"
        AC_MSG_CHECKING([for Xapian cjk word tokenization])
        AC_LINK_IFELSE(
            [AC_LANG_PROGRAM(
                [[#include <xapian.h>]],
                [[unsigned cjk_flags = Xapian::TermGenerator::FLAG_CJK_WORDS | Xapian::QueryParser::FLAG_CJK_WORDS | Xapian::MSet::SNIPPET_CJK_WORDS; (void) cjk_flags; ]])],
            [xapian_cjkwords="yes"],
            [xapian_cjkwords="no"])
        AC_MSG_RESULT($xapian_cjkwords)
        if test $xapian_cjkwords = yes; then
            AC_DEFINE([USE_XAPIAN_CJK_WORDS], [], [Use Xapian CJK word tokenizer, rather than n-grams?])
            xapian_cjk_tokens=words
        else
            AC_MSG_NOTICE([Your Xapian does not support CJK word tokenization. CJK ngram tokenization will be used instead.])
            xapian_cjk_tokens=ngrams
        fi
        LDFLAGS=$ORIG_LDFLAGS
        CXXFLAGS=$ORIG_CXXFLAGS
        AC_LANG_POP([C++])
    fi
    AC_SUBST(XAPIAN_CXXFLAGS)
    AC_SUBST(XAPIAN_LIBS)
    AC_SUBST(XAPIAN_VERSION)
fi
AM_CONDITIONAL([USE_XAPIAN], [test "${enable_xapian}" != "no"])
AC_DEFINE_UNQUOTED([XAPIAN_CJK_TOKENS], ["$xapian_cjk_tokens"], [Which Xapian CJK tokenzation are we using?])

dnl
dnl Search - Squatter
dnl
if test "${enable_squat}" != "no" -o "${enable_xapian}" != "no"; then
    AC_CHECK_FUNC(getopt_long, [], [AC_MSG_ERROR([squatter executable requires getopt_long])])
fi
AM_CONDITIONAL([SQUATTER],
    [test "${enable_squat}" != "no" -o "${enable_xapian}" != "no" ])

AC_ARG_ENABLE(sieve,
        [AS_HELP_STRING([--disable-sieve], [disable Sieve support])],,[enable_sieve="yes";])
AC_ARG_ENABLE(pcre,
        [AS_HELP_STRING([--disable-pcre], [disable PCRE library])],[cyrus_cv_pcre_utf8="$enableval"])

if test "$enable_sieve" != "no"; then
        AC_DEFINE(USE_SIEVE,[],[Build in Sieve support?])

        dnl Sieve configure stuff
        AC_PROG_YACC
        AM_PROG_LEX

        if test -z "$ac_cv_prog_YACC"; then
            AC_MSG_ERROR([Sieve requires bison/byacc/yacc, but none is installed])
        fi

        if test -z "$ac_cv_prog_LEX"; then
            AC_MSG_ERROR([Sieve requires flex/lex, but none is installed])
        fi
fi

AM_CONDITIONAL([SIEVE], [test "${enable_sieve}" != "no"])

if test "$enable_pcre" != "no"; then
        AC_CHECK_HEADER(pcreposix.h)
        if test "$ac_cv_header_pcreposix_h" = "yes"; then
            AC_MSG_CHECKING(for utf8 enabled pcre)
            AC_CACHE_VAL(cyrus_cv_pcre_utf8, AC_TRY_CPP([#include <pcreposix.h>
#ifndef REG_UTF8
#include </nonexistent>
#endif],cyrus_cv_pcre_utf8=yes,cyrus_cv_pcre_utf8=no))
            AC_MSG_RESULT($cyrus_cv_pcre_utf8)
        else
            cyrus_cv_pcre_utf8="no"
        fi
fi

LIB_REGEX=
if test "$cyrus_cv_pcre_utf8" = "yes"; then
        LIB_REGEX="-lpcre -lpcreposix";
        AC_DEFINE(ENABLE_REGEX, [], [Do we have a regex library?])
        AC_DEFINE(HAVE_PCREPOSIX_H, [], [Do we have usable pcre library?])
else
        AC_CHECK_HEADERS(rxposix.h)
        if test "$ac_cv_header_rxposix_h" = "yes"; then
            LIB_REGEX="-lrx"
            AC_DEFINE(ENABLE_REGEX, [], [Do we have a regex library?])
        else
            AC_SEARCH_LIBS(regcomp, regex,
                           AC_DEFINE(ENABLE_REGEX, [], [Do we have a regex library?]), [])
        fi
fi
AC_SUBST(LIB_REGEX)
LIBS="$LIBS $LIB_REGEX"

dnl
dnl see if we're compiling with SRS
dnl
AC_MSG_CHECKING([whether to use SRS])
AC_ARG_ENABLE(srs,
    [AS_HELP_STRING([--enable-srs], [enable Sender Rewriting Scheme support])],,
    [enable_srs=no])
AC_MSG_RESULT($enable_srs)
AM_CONDITIONAL([USE_SRS], [test "${enable_srs}" != "no"])
if test "x$enable_srs" != xno; then
    AC_CHECK_HEADER([srs2.h],,
        [AC_MSG_ERROR([cannot find SRS headers])])
    AC_CHECK_LIB(srs2, srs_forward,,
        [AC_MSG_ERROR([cannot find SRS lib])])
    LIBS="$LIBS -lsrs2"
    AC_DEFINE(USE_SRS,[],[Build with srs functionality])
else
    AC_MSG_NOTICE([Outgoing messages will not support the Sender Rewriting Scheme.  Consider installing libsrs2 and --enable-srs])
fi

dnl look for an option to disable sign-comparison warnings (needed for
dnl flex-generated sieve sources when building with -Werror)
saved_CFLAGS="$CFLAGS"
NOWARN_SIGN_COMPARE="-Wno-sign-compare"
CFLAGS="$NOWARN_SIGN_COMPARE"
AC_MSG_CHECKING([whether the C compiler supports -Wno-sign-compare])
AC_COMPILE_IFELSE(
    [AC_LANG_PROGRAM([], [])],
    [AC_MSG_RESULT([yes])],
    [NOWARN_SIGN_COMPARE=]
    [AC_MSG_RESULT([no])]
)
CFLAGS="$saved_CFLAGS"
AC_SUBST([NOWARN_SIGN_COMPARE])

dnl for et routines
AC_FUNC_CHECK(strerror,AC_DEFINE(HAS_STRERROR,[],[Do we have strerror()?]),
              AC_DEFINE(NEED_SYS_ERRLIST,[],[Do we have a sys_errlist?]))

dnl for master fd limits
AC_CHECK_HEADERS(sys/resource.h)
AC_CHECK_FUNCS(setrlimit)
AC_CHECK_FUNCS(getrlimit)

dnl for detaching terminal
AC_CHECK_FUNCS(daemon setsid)

dnl for turning off sockets
AC_CHECK_FUNCS(shutdown)

AC_EGREP_HEADER(socklen_t, sys/socket.h, AC_DEFINE(HAVE_SOCKLEN_T,[],[Do we have a socklen_t?]))
AC_EGREP_HEADER(sockaddr_storage, sys/socket.h,
                AC_DEFINE(HAVE_STRUCT_SOCKADDR_STORAGE,[],[Do we have a sockaddr_storage?]))
AC_EGREP_HEADER(rlim_t, sys/resource.h, AC_DEFINE(HAVE_RLIM_T,[],[Do we have an rlim_t?]))

dnl Bunch of setproctitle stuff
spt_type=""
AC_CHECK_FUNC(setproctitle,spt_type=SPT_BUILTIN)
if test "$spt_type" = ""; then
        dnl BSD/OS and FreeBSD put it in -lutil
        AC_CHECK_LIB(util,setproctitle,spt_type=SPT_BUILTIN
                        LIBS="${LIBS} -lutil")
fi
if test "$spt_type" = ""; then
        AC_CHECK_HEADER(sys/pstat.h,spt_type=SPT_PSTAT)
fi
if test "$spt_type" = ""; then
        AC_CHECK_HEADER(sys/sysnews.h,spt_type=SPT_SYSMIPS)
fi
if test "$spt_type" = ""; then
        AC_MSG_CHECKING(for PS_STRINGS)
        AC_CACHE_VAL(cyrus_cv_sys_psstrings, AC_COMPILE_IFELSE([AC_LANG_SOURCE([
#include <machine/vmparam.h>
#include <sys/exec.h>
void *p = PS_STRINGS;
])],cyrus_cv_sys_psstrings=yes,cyrus_cv_sys_psstrings=no))
         if test $cyrus_cv_sys_psstrings = yes; then
                 spt_type=SPT_PSSTRINGS
         fi
         AC_MSG_RESULT($cyrus_cv_sys_psstrings)
fi
if test "$spt_type" = ""; then
        AC_MSG_CHECKING(for SCO)
        AC_CACHE_VAL(cyrus_cv_sys_sco, AC_TRY_CPP([
#ifndef _SCO_unix_
#include </nonexistent>
#endif],cyrus_cv_sys_sco=yes,cyrus_cv_sys_sco=no))
        if test $cyrus_cv_sys_sco = yes; then
                spt_type=SPT_SCO
        fi
        AC_MSG_RESULT($cyrus_cv_sys_sco)
fi
if test "$spt_type" = ""; then
        AC_MSG_CHECKING(for setproctitle usability)
        AC_CACHE_VAL(cyrus_cv_sys_setproctitle, AC_TRY_CPP([
#if defined(DGUX) || defined(_SEQUENT_) || defined(apollo)
#include </nonexistent>
#endif],cyrus_cv_sys_setproctitle=yes,cyrus_cv_sys_setproctitle=no))
        if test $cyrus_cv_sys_setproctitle = no; then
                spt_type=SPT_NONE
        fi
        AC_MSG_RESULT($cyrus_cv_sys_setproctitle)
fi
if test "$spt_type" != ""; then
        AC_DEFINE_UNQUOTED(SPT_TYPE,$spt_type,[Do we already have setproctitle?])
fi

AC_MSG_CHECKING(nonblocking method)
AC_CACHE_VAL(cyrus_cv_sys_nonblock,AC_TRY_LINK([#include <sys/types.h>
#include <sys/file.h>
#include <fcntl.h>
#ifndef FNDELAY
#define FNDELAY         O_NDELAY
#endif],[fcntl(0, F_GETFL, 0)&FNDELAY],
cyrus_cv_sys_nonblock=fcntl,cyrus_cv_sys_nonblock=ioctl))
AM_CONDITIONAL([NONBLOCK_FCNTL], [test "$cyrus_cv_sys_nonblock" = "fcntl"])
AC_MSG_RESULT($cyrus_cv_sys_nonblock)

AC_MSG_CHECKING(timezone GMT offset method)
AC_CACHE_VAL(cyrus_cv_struct_sys_gmtoff,AC_TRY_COMPILE([
#include <time.h>],[struct tm tm;
tm.tm_gmtoff = 0;
],cyrus_cv_struct_sys_gmtoff=tm,cyrus_cv_struct_sys_gmtoff=gmtime))
AM_CONDITIONAL([GMTOFF_TM], [test "$cyrus_cv_struct_sys_gmtoff" = "tm"])
AC_MSG_RESULT($cyrus_cv_struct_sys_gmtoff)
AC_MSG_CHECKING(for shared mmap)
AC_CACHE_VAL(cyrus_cv_func_mmap_shared,AC_TRY_RUN([
#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>
int main() {
    char *base;
    int mmapflags = MAP_SHARED;
    int fd = open("conftestmmap", O_RDWR|O_CREAT|O_TRUNC, 0666);
    if (fd == -1) return 1;
    if (write(fd, "test", 4) != 4) return 1;
    fsync(fd);
#ifdef MAP_FILE
    mmapflags |= MAP_FILE;
#endif
#ifdef MAP_VARIABLE
    mmapflags |= MAP_VARIABLE;
#endif
    base = mmap((caddr_t)0, 100, PROT_READ, mmapflags, fd, 0L);
    if (base == (caddr_t)-1) return 1;
    if (memcmp(base, "test", 4) != 0) return 1;
    if (write(fd, "test", 4) != 4) return 1;
    fsync(fd);
    if (memcmp(base+4, "test", 4) != 0) return 1;
    return 0;
}
],cyrus_cv_func_mmap_shared=yes,cyrus_cv_func_mmap_shared=no,
cyrus_cv_func_mmap_shared=no))
AC_MSG_RESULT($cyrus_cv_func_mmap_shared)
if test $cyrus_cv_func_mmap_shared = yes; then
        found_map="shared"
else
AC_MSG_CHECKING(for stupid shared mmap)
AC_CACHE_VAL(cyrus_cv_func_mmap_stupidshared,AC_TRY_RUN([
#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>
int main() {
    char *base;
    int fd = open("conftestmmap", O_RDWR|O_CREAT|O_TRUNC, 0666);
    int mmapflags = MAP_SHARED;
    if (fd == -1) return 1;
    if (write(fd, "test", 4) != 4) return 1;
    fsync(fd);
#ifdef MAP_FILE
    mmapflags |= MAP_FILE;
#endif
#ifdef MAP_VARIABLE
    mmapflags |= MAP_VARIABLE;
#endif
    base = mmap((caddr_t)0, 4, PROT_READ, mmapflags, fd, 0L);
    if (base == (caddr_t)-1) return 1;
    if (memcmp(base, "test", 4) != 0) return 1;
    lseek(fd, 0L, 0);
    if (write(fd, "xyzz", 4) != 4) return 1;
    fsync(fd);
    if (memcmp(base, "xyzz", 4) != 0) return 1;
    return 0;
}
],cyrus_cv_func_mmap_stupidshared=yes,cyrus_cv_func_mmap_stupidshared=no,
cyrus_cv_func_mmap_stupidshared=no))
AC_MSG_RESULT($cyrus_cv_func_mmap_stupidshared)
if test $cyrus_cv_func_mmap_stupidshared = yes; then
        found_map="stupidshared"
else
        AC_MSG_WARN([*** This system does not have a working mmap()])
        AC_MSG_WARN(*** Expect a considerable performance penalty)
        found_map=nommap
fi
fi

AC_ARG_WITH(mmap,
        [AS_HELP_STRING([--with-mmap=TYPE], [force shared/stupidshared/nommap - JUST FOR TESTING])],
        WITH_MAP="$withval",WITH_MAP="$found_map")
AM_CONDITIONAL([MAP_SHARED], [test "$WITH_MAP" = "shared"])
AM_CONDITIONAL([MAP_STUPIDSHARED], [test "$WITH_MAP" = "stupidshared"])

AC_ARG_WITH(lock,
  [AS_HELP_STRING([--with-lock=METHOD], [force use of METHOD for locking (flock or fcntl)])],
  WITH_LOCK="$withval", [
  AC_CHECK_FUNC(fcntl,WITH_LOCK="fcntl",[
                AC_CHECK_FUNC(flock,WITH_LOCK="flock",[
                                AC_MSG_ERROR(unable to detect locking method)
                              ])
                ])
  ])
AM_CONDITIONAL([LOCK_FCNTL], [test $WITH_LOCK = "fcntl"])

dnl check for fdatasync (used by cyrusdb_skiplist)
AC_SEARCH_LIBS([fdatasync], [rt], [
    AC_DEFINE(HAVE_FDATASYNC,[],[Do we have fdatasync()?])
], [])

dnl check for clock_gettime
AC_SEARCH_LIBS([clock_gettime], [rt], [], [
    AC_MSG_ERROR([unable to find the clock_gettime() function])
])

dnl check for libuuid (used when generating mailbox uniqueids)
LIB_UUID=
AC_CHECK_LIB(uuid, uuid_generate,[
    LIB_UUID="-luuid"
    AC_DEFINE(HAVE_LIBUUID,[],[Do we have the uuid library])
])

dnl for AFS.
cant_find_sigvec=no
AC_CACHE_VAL(cyrus_cv_sigveclib,[
 dnl bsd classic flavor
 AC_CHECK_FUNC(sigvec, [
        cyrus_cv_sigveclib=""
  ], [
  dnl hp flavor
  AC_CHECK_LIB(BSD, sigvec, cyrus_cv_sigveclib="-lBSD", [
    dnl not hp flavor
    SAVE_LDFLAGS="$LDFLAGS"
    dnl solaris flavor
    LDFLAGS="-L/usr/ucblib -R/usr/ucblib $LDFLAGS"
    AC_CHECK_LIB(ucb, sigvec, [
      dnl more solaris flavor
      cyrus_cv_sigveclib="-lc -L/usr/ucblib -R/usr/ucblib -lucb"],
      [ cant_find_sigvec=yes ])
    LDFLAGS="$SAVE_LDFLAGS"])
  ])
])
AC_SUBST(cyrus_cv_sigveclib)

# ok, we still look for this stuff because of checking groups, but
# all authentication goes through SASL
AC_ARG_ENABLE([afs],
        [AS_HELP_STRING([--enable-afs], [Enable AFS with ptloader])])

AC_ARG_WITH(afs-libdir,
        [AS_HELP_STRING([--with-afs-libdir=DIR], [use AFS libraries from DIR [/usr/lib]])],
        afs_libdir="${withval}", afs_libdir="/usr/lib")

AC_ARG_WITH(afs-incdir,
        [AS_HELP_STRING([--with-afs-incdir=DIR], [use AFS headers from DIR [/usr/include]])],
        afs_incdir="${withval}", afs_incdir="/usr/include")

AC_ARG_WITH(ldap,
        [AS_HELP_STRING([--with-ldap=DIR], [use LDAP (in DIR) (experimental) [/usr/local]])],
        with_ldap="${withval}", with_ldap="no")

dnl select mode of afspts
AC_ARG_ENABLE(krb5afspts,
        [AS_HELP_STRING([--enable-krb5afspts], [compile afskrb PTS module with krb5 support])])

if test "x$enable_afs" = "xyes"; then
# krb5afspts is only valid if AFS is enabled, so check inside here.
    AS_IF([test "x$enable_krb5afspts" = "xyes"], [SASL_SET_GSSAPI_LIBS
      AC_DEFINE(AFSPTS_USE_KRB5,[],[Should the AFS PTS plugin use krb5?])
    ])

    SAVE_CFLAGS="$CFLAGS"
    CFLAGS="${CFLAGS} -I${with_afs_incdir}"
    AFS_LIBS="${with_afs_libdir}/afs/libkauth.a ${with_afs_libdir}/afs/libprot.a  ${with_afs_libdir}/afs/libauth.a ${with_afs_libdir}/afs/libsys.a ${with_afs_libdir}/librxkad.a ${with_afs_libdir}/librx.a ${with_afs_libdir}/afs/libsys.a ${with_afs_libdir}/libubik.a ${with_afs_libdir}/afs/util.a ${with_afs_libdir}/afs/libafscom_err.a -lresolv"
    if test -f ${with_afs_libdir}/afs/liblwp.a; then
      AFS_LIBS="$AFS_LIBS ${with_afs_libdir}/afs/liblwp.a"
    elif test -f ${with_afs_libdir}/liblwp.a; then
      AFS_LIBS="$AFS_LIBS ${with_afs_libdir}/liblwp.a"
    fi
    if test -f ${with_afs_libdir}/afs/libaudit.a; then
      AFS_LIBS="$AFS_LIBS ${with_afs_libdir}/afs/libaudit.a"
    fi
    if test -f /usr/ucblib/libucb.a; then
      CMU_ADD_LIBPATH_TO(/usr/ucblib, AFS_LDFLAGS)
      AFS_LIBS="$AFS_LIBS -lc -lucb"
    fi
    if test -f ${with_afs_libdir}/afs/libdes.a; then
      AFS_LIBS="$AFS_LIBS ${with_afs_libdir}/afs/libdes.a"
    else
      AFS_LIBS="$AFS_LIBS -ldes"
    fi

    AC_CACHE_VAL(cyrus_cv_afs_sigvec,[
        SAVE_LIBS="$LIBS"
        LIBS="${with_afs_libdir}/liblwp.a"
        AC_MSG_CHECKING(if AFS libraries need sigvec)
        dnl Does AFS need sigvec?  We have to link against lwp and see
        dnl if IOMGR_Initialize wants it
        AC_TRY_LINK([IOMGR_Initialize();],
                [IOMGR_Initialize()],
                [
                        dnl it linked; don't need it
                        AC_MSG_RESULT(no)
                        cyrus_cv_afs_sigvec="no"
                ], [
                        dnl didn't link; pick up sigvec
                        AC_MSG_RESULT(yes)
                        cyrus_cv_afs_sigvec="yes"
                ])
        ])
    if test "$cyrus_cv_afs_sigvec" = yes; then
      if test "$cant_find_sigvec" = yes; then
        AC_MSG_WARN([Can not find a sigvec for AFS libraries which seem to need one.])
      else
        AFS_LIBS="${AFS_LIBS} $cyrus_cv_sigveclib"
        AC_DEFINE(HAVE_AFSKRB,[],[Should we build afskrb pts module?])
      fi
    else
      AFS_LIBS="${AFS_LIBS}"
      AC_DEFINE(HAVE_AFSKRB,[],[Should we build afskrb pts module?])
    fi
    LIBS="$SAVE_LIBS"
    CFLAGS="$SAVE_CFLAGS"
    AC_SUBST(AFS_LDFLAGS)
    AC_SUBST(AFS_LIBS)
fi
AM_CONDITIONAL([USE_AFSKRB], [grep HAVE_AFSKRB confdefs.h >/dev/null])

have_ldap=no
LDAP_CPPFLAGS=
LDAP_LDFLAGS=
LDAP_LIBS=

case "x$with_ldap" in
xno)
    # default args or --without-ldap
    # do not try to enable
    ;;
xyes)
    # --with-ldap
    # try to enable, search in default system directories
    ldap_cppflags=
    ldap_ldflags=
    ;;
*)
    # --with-ldap=DIR
    # try to enable, search in given install directory
    if test "x$with_ldap" != "x" -a -d "$with_ldap"; then
        ldap_cppflags="-I${with_ldap}/include"
        ldap_ldflags="-L${with_ldap}/lib"
        with_ldap=yes
    else
        AC_WARN([Disabling LDAP - no include files found])
        with_ldap=no
    fi
esac

if test $with_ldap = yes; then
    save_CPPFLAGS="$CPPFLAGS"
    save_LDFLAGS="$LDFLAGS"
    CPPFLAGS="$CPPFLAGS $ldap_cppflags"
    LDFLAGS="$LDFLAGS $ldap_ldflags"

    AC_CHECK_LIB(ldap, ldap_initialize, [
        AC_DEFINE(HAVE_LDAP,[],[Should we build the LDAP pts module?])
        LDAP_CPPFLAGS="$ldap_cppflags"
        LDAP_LDFLAGS="$ldap_ldflags"
        LDAP_LIBS="-lldap -llber"
        have_ldap=yes
    ],,-llber)

    CPPFLAGS="$save_CPPFLAGS"
    LDFLAGS="$save_LDFLAGS"
fi
AC_SUBST(LDAP_CPPFLAGS)
AC_SUBST(LDAP_LDFLAGS)
AC_SUBST(LDAP_LIBS)
AM_CONDITIONAL([HAVE_LDAP], [test "$have_ldap" = "yes"])

AM_CONDITIONAL([PTCLIENT], [test "x$enable_afs" = "xyes" -o "$have_ldap" = "yes"])

AC_ARG_WITH([clamav],
	AS_HELP_STRING([--without-clamav], [ignore presence of ClamAV and disable it]))
AS_IF([test "x$with_clamav" != "xno"],
	[ PKG_CHECK_MODULES([CLAMAV], [libclamav],
		[ AC_DEFINE(HAVE_CLAMAV, [], [Do we have ClamAV?])
		  with_clamav=yes ],
		with_clamav=no)])

AC_ARG_ENABLE(server,
        [AS_HELP_STRING([--disable-server], [disable compiling servers])])
AM_CONDITIONAL([SERVER], [test "$enable_server" != "no"])
# We always output a server makefile (just because we can)

dnl this is the new simple check for kerberos; since the person had to
dnl compile SASL, we might as well use the same checks.
AC_ARG_WITH(krb,
        [AS_HELP_STRING([--with-krb=DIR], [use Kerberos from DIR])],
        with_krb="$withval", with_krb="no")

AC_ARG_WITH(krbimpl,
        [AS_HELP_STRING([--with-krbimpl=kth|mit], [assume Kerberos 4 from KTH or MIT])],
        with_krbimpl="$withval", with_krbimpl="kth")

AC_ARG_ENABLE(statickrb,
        [AS_HELP_STRING([--enable-statickrb], [link Kerberos statically])],
        with_statickrb="yes", with_statickrb="no")

AC_ARG_WITH(krb5-config,
        [AS_HELP_STRING([--with-krb5-config=PATH], [use krb5-config from PATH])],
        with_krb5config="$withval", with_krb5config="no")

if test "$with_krb5config" != "no"; then
    AC_MSG_CHECKING([$with_krb5config works])

    dnl run with exec to avoid leaking output on "real" bourne shells
    if (exec >&5 2>&5 ; $with_krb5config --libs --cflags; exit $?) then
        AC_MSG_RESULT(yes)
    else
        AC_MSG_ERROR([\`$with_krb5config --libs --cflags' doesn't work, aborting])
    fi

    KRB5_CFLAGS="`$with_krb5config --cflags`"
    KRB5_LDFLAGS="`$with_krb5config --libs`"

    LDFLAGS="$KRB5_LDFLAGS $LDFLAGS"
    CFLAGS="$KRB5_CFLAGS $CFLAGS"
fi

dnl In order to compile kerberos4, we need libkrb and libdes.

dnl we might need -lresolv for kerberos
AC_CHECK_LIB(resolv,res_search)

if test "$with_statickrb" = "yes" -a ! -d "$with_krb"; then
      AC_MSG_ERROR([--enable-statickrb specified but --with-krb did not specify a valid directory])
fi

if test "$with_krb" != "no"; then
dnl Do we need DES for kerberos?
AC_ARG_WITH(krbdes,
        [AS_HELP_STRING([--without-krbdes], [disable Kerberos DES implementation])],, with_krbdes="yes")
if test "$with_krbdes" = "yes"; then
  AC_CHECK_LIB(des,des_ecb_encrypt,
      if test "$with_statickrb" = "yes"; then
          KRB_LIBS="$with_krb/lib/libdes.a"
      else
          KRB_LIBS="-ldes"
      fi,
  AC_MSG_ERROR([The Kerberos DES library is required for Kerberos support.]))
fi
fi

dnl if we were ambitious, we'd look more aggressively for the
dnl krb4 install
if test -d ${with_krb}; then
   AC_CACHE_CHECK(for Kerberos includes, cyrus_cv_krbinclude, [
     for krbhloc in include/kerberosIV include
     do
       if test -f ${with_krb}/${krbhloc}/krb.h ; then
         cyrus_cv_krbinclude=${with_krb}/${krbhloc}
         break
       fi
     done
     ])

   if test -n "${cyrus_cv_krbinclude}"; then
     CPPFLAGS="$CPPFLAGS -I${cyrus_cv_krbinclude}"
   fi
   CMU_ADD_LIBPATH(${with_krb}/lib)
fi

if test "$with_krbimpl" != "kth"; then
  KRBLIB="krb4"
else
  KRBLIB="krb"
fi

if test "$with_des" != no; then
  AC_CHECK_HEADER(krb.h,
    AC_CHECK_LIB(${KRBLIB}, krb_mk_priv,
      if test "$with_statickrb" = "yes"; then
          KRB_LIBS="$KRB_LIBS $with_krb/lib/lib${KRBLIB}.a"
      else
          KRB_LIBS="$KRB_LIBS -l${KRBLIB}"
      fi,
                 AC_WARN(No Kerberos V4 found); krb4=no,
           $KRB_LIBS),
    krb4=no)
else
  AC_WARN(No DES library found for Kerberos V4 support)
  krb4=no
fi

if test "${krb4}" != no; then
  AC_DEFINE(HAVE_KRB,[],[Support for Kerberos?])
fi

LIBS="$KRB_LIBS $LIBS"

SASL_SET_GSSAPI_LIBS

dnl
dnl Test for OpenSSL
dnl
AC_ARG_WITH(openssl,
        [AS_HELP_STRING([--with-openssl=DIR], [use OpenSSL from DIR])],
        with_ssl="${withval}")

SSL_CPPFLAGS=
SSL_LIBS=

case "x$with_ssl" in
xno)
    # --without-openssl
    # do not try to enable
    ;;
x|xyes)
    # default args or --with-openssl
    #
    # Try pkg-config - OpenSSL >= 0.9.6 has openssl.pc
    PKG_CHECK_MODULES(OPENSSL, openssl, [with_ssl=yes])
    ssl_cppflags="$OPENSSL_CFLAGS"
    ssl_ldflags="$OPENSSL_LIBS"
    #
    # If pkg-config doesn't work, search in default system directories
    ;;
*)
    # --with-openssl=DIR
    # try to enable, search in given install directory
    if test -d "$with_ssl"; then
        ssl_cppflags="-I${with_ssl}/include"
        ssl_ldflags=
        if test -d "${with_ssl}/lib64"; then
            CMU_ADD_LIBPATH_TO(${with_ssl}/lib64, ssl_ldflags)
        else
            CMU_ADD_LIBPATH_TO(${with_ssl}/lib, ssl_ldflags)
        fi
        with_ssl=yes
    else
        AC_WARN([Disabling OpenSSL - no include files found])
        with_ssl=no
    fi
esac

if test "$with_ssl" != "no"; then
    save_CPPFLAGS="$CPPFLAGS"
    save_LDFLAGS="$LDFLAGS"
    CPPFLAGS="$CPPFLAGS $ssl_cppflags"
    LDFLAGS="$LDFLAGS $ssl_ldflags"

    AC_CHECK_HEADER(openssl/evp.h, [
        with_ssl=yes
    ],[
        with_ssl=no
    ])

    dnl if openssl has been compiled with the rsaref2 libraries,
    dnl we need to include the rsaref libraries in the crypto check
    ssl_libs=
    AC_CHECK_LIB(rsaref, RSAPublicEncrypt,[
       ssl_libs="-lRSAglue -lrsaref"
    ],[
       # whatever, we do not care
       :
    ])
    AC_CHECK_LIB(crypto, BIO_accept,[
        ssl_libs="-lcrypto $ssl_libs"
    ],[
        with_ssl=no
    ], $ssl_libs)
    AC_CHECK_LIB(ssl, SSL_CTX_new, [
        ssl_libs="-lssl $ssl_libs"
    ],[
        with_ssl=no
    ], $ssl_libs)

    if test "$with_ssl" = "no"; then
        AC_WARN([Disabling SSL - no library files found])
    fi
    CPPFLAGS="$save_CPPFLAGS"
    LDFLAGS="$save_LDFLAGS"
fi

AC_MSG_CHECKING(for ssl)
AC_MSG_RESULT($with_ssl)

if test "$with_ssl" != "no"; then
    SSL_CPPFLAGS="$ssl_cppflags"
    SSL_LIBS="$ssl_ldflags $ssl_libs"
    AC_DEFINE(HAVE_SSL,[],[Build with SSL support?])
    if test "${krb4}" != no; then
       AC_DEFINE(OPENSSL_ENABLE_OLD_DES_SUPPORT,[],[Configure OpenSSL to provide legacy des apis])
       AC_DEFINE(OPENSSL_DES_LIBDES_COMPATIBILITY,[],[Configure OpenSSL to provide krb4-compatible legacy des apis])
    fi

    AC_CHECK_LIB(ssl, SSL_CTX_set_alpn_select_cb,
       AC_DEFINE(HAVE_TLS_ALPN,[], [Do we have support for TLS ALPN extension?]))
fi
AM_CONDITIONAL([HAVE_SSL], [test "$with_ssl" != "no"])
AC_SUBST(SSL_CPPFLAGS)
AC_SUBST(SSL_LIBS)

dnl
dnl Allow for setting EGD socket file on systems without /dev/*random.
dnl
AC_ARG_WITH(egd-socket,
      [AC_HELP_STRING([--with-egd-socket=FILE], [Entropy Gathering Daemon socket pathname for systems without /dev/urandom])],
              [ EGD_SOCKET="$withval" ]
      )
if test -n "$EGD_SOCKET" ; then
      AC_DEFINE_UNQUOTED(EGD_SOCKET, "$EGD_SOCKET", [Alternative to /dev/urandom?])
fi

dnl
dnl Test for zlib
dnl
AC_ARG_WITH(zlib, [AS_HELP_STRING([--with-zlib=DIR],[use zlib from DIR])],
    with_zlib=$withval, with_zlib="yes")

save_CPPFLAGS=$CPPFLAGS
save_LDFLAGS=$LDFLAGS

if test -d $with_zlib; then
    CPPFLAGS="${CPPFLAGS} -I${with_lib}/include"
    CMU_ADD_LIBPATH(${with_zlib}/$CMU_LIB_SUBDIR)
fi

ZLIB=""
case "$with_zlib" in
    no)
      with_zlib="no";;
    *)
    AC_CHECK_HEADER(zlib.h, [
        AC_CHECK_LIB(z, deflate,
                LIBS="${LIBS} -lz"; with_zlib="yes",
                with_zlib="no",)],
        with_zlib=no)
    ;;
esac

if test "$with_zlib" != "no"; then
    AC_DEFINE(HAVE_ZLIB,[],[Do we have zlib?])
    ZLIB="-lz"
    HAVE_ZLIB=1

    AC_CHECK_LIB(z, deflatePending,
            AC_DEFINE(HAVE_DEFLATE_PENDING,[], [Do we have deflatePending()?]))
else
    CPPFLAGS=$save_CPPFLAGS
    LDFLAGS=$save_LDFLAGS
    HAVE_ZLIB=0
fi

AC_MSG_CHECKING(for zlib)
AC_MSG_RESULT($with_zlib)
AC_SUBST(ZLIB)

dnl
dnl Test for Zephyr
dnl
AC_ARG_WITH(zephyr,
        [AS_HELP_STRING([--with-zephyr=DIR], [enable Zephyr notification (installed on DIR)])],
        with_zephyr="${withval}")
if test -z "$with_zephyr"; then
     if test -f /usr/local/lib/libzephyr.a; then
        with_zephyr="/usr/local"
     elif test -f /usr/lib/libzephyr.a; then
        with_zephyr="/usr"
     fi
fi
ZEPHYR_LIBS=""
case "$with_zephyr" in
        no) true;;
        ""|yes) AC_CHECK_LIB(zephyr,ZInitialize,ZEPHYR_LIBS="-lzephyr",
                with_zephyr="no",);;
       *) ZEPHYR_LIBS="-lzephyr";;
esac
AC_SUBST(ZEPHYR_LIBS)
if test "$with_zephyr" != "no"; then
        AC_DEFINE(HAVE_ZEPHYR,[],[Build with Zephyr support?])
fi
AM_CONDITIONAL([ZEPHYR], [test "$with_zephyr" != "no"])


dnl
dnl Test for libcap (POSIX.1e - security API) on Linux systems
dnl
AC_ARG_WITH([libcap],
        AS_HELP_STRING([--with-libcap], [Enable libcap system capabilities handling (Linux systems only)]),
        with_libcap="${withval}")

have_libcap=no
LIBCAP_LIBS=""
case $host_os in
linux*)
        if test "x$with_libcap" = "xyes"; then
                AC_CHECK_LIB([cap], [cap_get_proc], have_libcap=yes, have_libcap=no)
                AC_CHECK_HEADERS([sys/capability.h sys/prctl.h], , have_libcap=no)
                if test "$have_libcap" = "yes"; then
                        AC_DEFINE(HAVE_LIBCAP, [], [Do we have libcap system capabilities handling (Linux systems only)?])
                        LIBCAP_LIBS="-lcap"
                fi
        fi
        ;;
*)
        ;;
esac
AC_SUBST(LIBCAP_LIBS)

AC_MSG_CHECKING(for libcap)
AC_MSG_RESULT($have_libcap)

dnl
dnl Check for jansson library, needed for JSON support
dnl
PKG_CHECK_MODULES([JANSSON], [jansson >= 2.3],
                  [ AC_DEFINE(HAVE_JANSSON, [], [Do we have Jansson?])
                    with_jansson=yes ],
                  AC_MSG_ERROR([libjansson is required]))
dnl call AC_SUBST macro to support pkg-config version older than 0.24
AC_SUBST([JANSSON_LIBS])
AC_SUBST([JANSSON_CFLAGS])
AM_CONDITIONAL([USE_JANSSON], [test "x$with_jansson" = xyes])

save_CFLAGS="$CFLAGS"
CFLAGS="$CFLAGS $JANSSON_CFLAGS $JANSSON_LIBS"
AC_CHECK_LIB([jansson], [json_dumpb],
             [],
             [ AC_DEFINE(NEED_JANSSON_JSON_DUMPB, [1],
                         [Do we need to provide our own json_dumpb()?])
               AC_MSG_NOTICE([jansson does not provide json_dumpb(), using ours instead])
             ])
CFLAGS="$save_CFLAGS"

dnl
dnl Check for ICU library, needed for charset conversions and non-gregorian
dnl rscale conversions
dnl
with_icu4c=no
PKG_CHECK_MODULES([ICU], [icu-i18n >= 55 icu-uc >= 55], [
                    AC_DEFINE(HAVE_ICU, [], [Build with ICU support])
                    with_icu4c=yes
                  ],
                  [AC_MSG_ERROR([Need ICU4C])])
AC_SUBST([ICU_LIBS])
AC_SUBST([ICU_CFLAGS])

dnl
dnl Check for zeroskip library, needed for zeroskip support
dnl
AC_ARG_WITH([zeroskip],
	[AS_HELP_STRING([--without-zeroskip], [ignore presence of Zeroskip and disable it])],
    [],
    [with_zeroskip=yes])
AS_IF([test "x$with_zeroskip" = "xyes"],
	[ PKG_CHECK_MODULES([ZEROSKIP], [libzeroskip],
		[ AC_DEFINE(HAVE_ZEROSKIP, [], [Do we have Zeroskip?])
		  with_zeroskip=yes ],
		with_zeroskip=no)])
AC_SUBST([ZEROSKIP_LIBS])
AC_SUBST([ZEROSKIP_CFLAGS])
AM_CONDITIONAL([USE_ZEROSKIP], [test "x$with_zeroskip" = xyes])

dnl
dnl Check for chardet library, needed for charset detection support
dnl
AC_ARG_WITH([chardet],
	[AS_HELP_STRING([--without-chardet], [ignore presence of chardet library and disable it])],
    [],
    [with_chardet=yes])
AS_IF([test "x$with_chardet" = "xyes"],
	[ PKG_CHECK_MODULES([LIBCHARDET], [chardet],
		[ AC_DEFINE(HAVE_LIBCHARDET, [], [Build with chardet library support])
		  with_chardet=yes ],
		with_chardet=no)])
AS_IF([test "x$with_chardet" != "xyes"],
      [AC_MSG_NOTICE([JMAP will not have character set detection support.  Consider installing chardet])])
AC_SUBST([LIBCHARDET_LIBS])
AC_SUBST([LIBCHARDET_CFLAGS])
AM_CONDITIONAL([USE_LIBCHARDET], [test "x$with_chardet" = xyes])

dnl
dnl Check for cld2 library
dnl
AC_ARG_WITH([cld2],
	[AS_HELP_STRING([--without-cld2], [ignore presence of cld2 library and disable it])],
    [],
    [with_cld2=yes])
AS_IF([test "x$with_cld2" = "xyes"],
	[ PKG_CHECK_MODULES([CLD2], [cld2],
		[ AC_DEFINE(HAVE_CLD2, [], [Build with cld2 library support])
		  with_cld2=yes ],
          with_cld2=no)])
AC_SUBST([CLD2_LIBS])
AC_SUBST([CLD2_CFLAGS])
AM_CONDITIONAL([HAVE_CLD2], [test "x$with_cld2" = xyes])

dnl
dnl Set pidfile location
dnl
AC_ARG_WITH(pidfile,
        [AS_HELP_STRING([--with-pidfile=DIR], [pidfile in DIR [/var/run/cyrus-master.pid]])],
        [MASTERPIDFILE="$withval"],
        [MASTERPIDFILE="/var/run/cyrus-master.pid"])
MASTERPIDFILE="\"$MASTERPIDFILE\""
AC_DEFINE_UNQUOTED(MASTER_PIDFILE, $MASTERPIDFILE,[Name of the pidfile for master])

dnl
dnl see if we're compiling with autocreate support
dnl
AC_ARG_ENABLE(autocreate,
        [AS_HELP_STRING([--enable-autocreate], [enable autocreate support])],,[enable_autocreate="no";])
AM_CONDITIONAL([AUTOCREATE], [test "$enable_autocreate" != "no"])
if test "x$enable_autocreate" = "xyes"; then
        AC_DEFINE(USE_AUTOCREATE,[],[Build with autocreate functionality])
fi
dnl
dnl see if we're compiling with IMAP idled support
dnl
AC_ARG_ENABLE(idled,
        [AS_HELP_STRING([--enable-idled], [enable IMAP idled support])],,[enable_idled="no";])
AM_CONDITIONAL([IDLED], [test "$enable_idled" != "no"])
if test "x$enable_idled" = "xyes"; then
        AC_DEFINE(USE_IDLED,[],[Build with idled functionality])
fi
dnl
dnl see if we're compiling with NNTP support
dnl
AC_ARG_ENABLE(nntp,
        [AS_HELP_STRING([--enable-nntp], [enable NNTP support])],,[enable_nntp="no";])
AM_CONDITIONAL([NNTPD], [test "$enable_nntp" != "no"])
if test "x$enable_nntp" = "xyes"; then
        AC_DEFINE(USE_NNTPD,[],[Build with nntpd functionality])
fi

dnl
dnl see if we're compiling the Murder support programs
dnl
AC_ARG_ENABLE(murder,
        [AS_HELP_STRING([--enable-murder], [enable IMAP Murder support])],, [enable_murder="no";])
AM_CONDITIONAL([MURDER], [test "$enable_murder" != "no"])
if test "$enable_murder" != no; then
        # for master/slave auto-selection
        AC_CHECK_HEADERS(sys/sockio.h)
fi
if test "x$enable_murder" = "xyes"; then
        AC_DEFINE(USE_MURDER,[],[Build with Murder functionality])
fi

dnl
dnl see if we're compiling with HTTP support
dnl
AC_ARG_ENABLE(http,
        [AS_HELP_STRING([--enable-http], [enable HTTP support])],, [enable_http="no";])
AM_CONDITIONAL([HTTPD], [test "$enable_http" != "no"])

HTTP_CPPFLAGS=
HTTP_LIBS=
if test "$enable_http" != no; then
dnl
dnl make sure all the modules we need are present
dnl
        if test "x$HAVE_SQLITE" != x1; then
            AC_MSG_ERROR([Need sqlite3 for http])
        else
            use_sqlite="yes"
            AC_DEFINE(WITH_DAV,[],[Build *DAV support into httpd?])
        fi

        PKG_CHECK_MODULES([XML2], [libxml-2.0], [
                AC_DEFINE(HAVE_XML2, [], [Build with libxml support])
                LIBS="$LIBS ${XML2_LIBS}"
                with_xml2=yes
                ],
                AC_MSG_ERROR([Need libxml-2.0 for http]))

        AC_CHECK_LIB(xml2, xmlFirstElementChild, [
                AC_DEFINE(HAVE_XML_FIRSTCHILD,[],
                        [Do we have support for xmlFirstElementChild()?])

                AC_CHECK_LIB(xml2, xmlBufferDetach,
                        AC_DEFINE(HAVE_XML_BUFFERDETACH,[],
                                [Do we have support for xmlBufferDetach()?]))
                ])

        PKG_CHECK_MODULES([ICAL], [libical >= 3.0.0], [
                AC_DEFINE(HAVE_ICAL,[],[Build CalDAV support into httpd?])
                LIBS="$LIBS ${ICAL_LIBS}"
                with_ical=yes
                ],
                AC_MSG_ERROR([Need libical 3.0.0 for http]))

        dnl icalproperty_new_color was overlooked, and eventually added in 3.0.5
        AC_CHECK_LIB(ical, icalproperty_new_color,
                AC_DEFINE(HAVE_RFC7986_COLOR,[],
                        [Do we have built-in support for RFC7986 color prop?]))

        dnl libical may have been built without RSCALE support
        AC_CHECK_LIB(ical, icalrecurrencetype_rscale_is_supported,
                [AC_DEFINE(HAVE_RSCALE,[], [Build RSCALE support into httpd?])],
                [AC_MSG_NOTICE([Your version of libical can not support non-gregorian recurrences])])

        dnl icalcomponent_clone will be new in libical 3.1.0
        AC_CHECK_LIB(ical, icalcomponent_clone,
                AC_DEFINE(HAVE_NEW_CLONE_API,[],
                        [Do we have support for new clone API?]))

dnl  Don't bother checking for DKIM until iSchedule gains traction
dnl        PKG_CHECK_MODULES([DKIM], [opendkim >= 2.7.0],
dnl                AC_EGREP_HEADER(DKIM_CANON_ISCHEDULE, dkim.h,
dnl                        AC_DEFINE(WITH_DKIM,[],
dnl                                [Build DKIM support into iSchedule?]),
dnl                        AC_MSG_WARN([Your version of OpenDKIM can not support iSchedule.  Consider patching OpenDKIM with contrib/dkim_canon_ischedule.patch])),
dnl                AC_MSG_WARN([Your version of OpenDKIM can not support iSchedule.  Consider upgrading to OpenDKIM >= 2.7.0]))

        AC_ARG_WITH(nghttp2, [AS_HELP_STRING([--without-nghttp2], [disable HTTP/2 support (check)])],,[with_nghttp2="check"])
        if test "x$with_nghttp2" = "xyes" -o "x$with_nghttp2" = "xcheck"; then
                PKG_CHECK_MODULES([NGHTTP2], [libnghttp2 >= 1.34.0], [
                        AC_DEFINE(HAVE_NGHTTP2,[],
                                [Build HTTP/2 support into httpd?])
                        with_nghttp2=yes
                ], [
                        if test "x$with_nghttp2" = "xyes"; then
                                AC_MSG_ERROR([HTTP/2 explicitly requested, but libnghttp2 was not found])
                        fi
                        AC_MSG_NOTICE([httpd will not have support for HTTP/2.  Consider installing libnghttp2 >= 1.5])
                        with_nghttp2=no
                ])
        fi


        AC_ARG_WITH(wslay, [AS_HELP_STRING([--without-wslay], [disable WebSockets support (check)])],,[with_wslay="check"])
        if test "x$with_wslay" = "xyes" -o "x$with_wslay" = "xcheck"; then
                PKG_CHECK_MODULES([WSLAY], [libwslay >= 1.1.1], [
                        AC_DEFINE(HAVE_WSLAY,[],
                                [Build WebSockets support into httpd?])
                        with_wslay=yes
                ], [
                        if test "x$with_wslay" = "xyes"; then
                                AC_MSG_ERROR([WebSockets explicitly requested, but libwslay was not found])
                        fi
                        AC_MSG_NOTICE([httpd will not have support for WebSockets.  Consider installing libwslay])
                        with_wslay=no
                ])
        fi

        AC_ARG_WITH(brotli, [AS_HELP_STRING([--without-brotli], [disable brotli compression (check)])])
        if test "x$with_brotli" = xyes -o "${with_brotli+x}" != x; then
                PKG_CHECK_MODULES([BROTLI], [libbrotlienc], [
                        AC_DEFINE(HAVE_BROTLI,[],
                                [Build Brotli compression support into httpd?])
                        with_brotli=yes
                ], [
                        if test "x$with_brotli" = xyes; then
                                AC_MSG_ERROR([brotli compression explicitly requested, but libbrotlienc was not found])
                        fi
                        with_brotli="no (libbrotlienc not found)"
                ])
        fi

        AC_ARG_WITH(zstd, [AS_HELP_STRING([--without-zstd], [disable Zstandard compression (check)])])
        if test "x$with_zstd" = xyes -o "${with_zstd+x}" != x; then
                PKG_CHECK_MODULES([ZSTD], [libzstd >= 1.4.0], [
                        AC_DEFINE(HAVE_ZSTD,[],
                                [Build Zstandard compression support into httpd?])
                        with_zstd=yes
                ], [
                        if test "x$with_zstd" = xyes; then
                                AC_MSG_ERROR([Zstandard compression explicitly requested, but libzstd was not found])
                        fi
                        with_zstd="no (libzstd >= 1.4.0 not found)"
               ])
        fi

        dnl httpd needs libmath in a few places
        dnl XXX really should check for this properly but AC_SEARCH_LIBS/AC_CHECK_LIB
        dnl XXX break under -Werror(!)
        LIB_MATH="-lm"

        PKG_CHECK_MODULES([SHAPELIB], [shapelib >= 1.3.0],[
                AC_DEFINE(HAVE_SHAPELIB,[],
                        [Build geographic support into tzdist?])
                AC_DEFINE(SHAPELIB_VERSION, ["1.3.0"], [ShapeLib Version])
                with_shapelib=yes
                ],
                AC_MSG_NOTICE([tzdist will not have geolocation support.  Consider installing shapelib]))

        HTTP_CPPFLAGS="${XML2_CFLAGS} ${SQLITE3_CFLAGS} ${ICAL_CFLAGS} ${GLIB_CFLAGS} ${JANSSON_CFLAGS} ${NGHTTP2_CFLAGS} ${WSLAY_CFLAGS} ${BROTLI_CFLAGS} ${ZSTD_CFLAGS} ${SHAPELIB_CFLAGS}"
        HTTP_LIBS="${XML2_LIBS} ${SQLITE3_LIBS} ${ICAL_LIBS} ${GLIB_LIBS} ${JANSSON_LIBS} ${NGHTTP2_LIBS} ${WSLAY_LIBS} ${BROTLI_LIBS} ${ZSTD_LIBS} ${SHAPELIB_LIBS} ${LIB_MATH}"
else
        with_nghttp2="no (httpd is not built)"
        with_wslay="no (httpd is not built)"
        with_brotli="no (httpd is not built)"
        with_zstd="no (httpd is not built)"
        with_xml2="no (httpd is not built)"
        with_ical="no (httpd is not built)"
        with_shapelib="no (httpd is not built)"
fi
AC_SUBST(HTTP_CPPFLAGS)
AC_SUBST(HTTP_LIBS)
if test "x$enable_http" = "xyes"; then
        AC_DEFINE(USE_HTTPD,[],[Build with HTTP functionality])
fi

dnl
dnl see if we're compiling with calendar alarm support
dnl
AC_ARG_ENABLE(calalarmd,
        [AS_HELP_STRING([--enable-calalarmd], [enable CalDAV alarm support])],,[enable_calalarmd="no";])
if test "x$enable_calalarmd" = "xyes"; then
    if test "x$enable_http" = "xyes"; then
	AC_DEFINE(USE_CALALARMD,[],[Build with calendar alarm functionality])
    else
	AC_MSG_ERROR([--enable-calalarmd requires --enable-http])
    fi
fi
AM_CONDITIONAL([CALALARMD], [test "$enable_calalarmd" != "no"])

dnl
dnl see if we're compiling with JMAP support
dnl
AC_ARG_ENABLE(jmap,
        [AS_HELP_STRING([--enable-jmap], [enable JMAP support])],, [enable_jmap="no";])
if test "x$enable_jmap" = "xyes" ; then
    if test "x$enable_xapian" = "xno" ; then
        AC_MSG_ERROR([--enable-jmap requires --enable-xapian])
    fi
    if test "x$enable_http" = "xno" ; then
        AC_MSG_ERROR([--enable-jmap requires --enable-http])
    fi
    AC_DEFINE(WITH_JMAP,[],[Build with JMAP support])
fi
AM_CONDITIONAL([JMAP], [test "${enable_jmap}" != "no"])

dnl
dnl see if we're compiling replication support programs
dnl
AC_ARG_ENABLE(replication,
        [AS_HELP_STRING([--enable-replication], [enable replication support (experimental)])],,[enable_replication="no";])
AM_CONDITIONAL([REPLICATION], [test "$enable_replication" != no])
if test "x$enable_replication" = "xyes"; then
        AC_DEFINE(USE_REPLICATION,[],[Build with replication functionality])
fi

dnl
dnl see if we're compiling backup support programs
dnl
AC_ARG_ENABLE(backup,
        [AS_HELP_STRING([--enable-backup], [enable backup support (experimental)])],,[enable_backup="no";])
AM_CONDITIONAL([BACKUP], [test "$enable_backup" != no])

if test "x$enable_backup" != xno; then
    if test "x$HAVE_SQLITE" != x1; then
        AC_MSG_ERROR([Need sqlite3 for backups])
    else
        use_sqlite="yes"
    fi
    if test "x$HAVE_ZLIB" != x1; then
        AC_MSG_ERROR([Need zlib for backups])
    fi

    AC_DEFINE([ENABLE_BACKUP],[],[Build with backup support])
fi

dnl
dnl Try and find a system version of com_err.
dnl If we see something that looks a little wacky, ignore it (there are many
dnl deficient installs of com_err, unfortunately, which leave out compile_et)
dnl There is also a broken re-implementation of compile_et, apparently derived
dnl from the Kerberos project, being shipped in /usr/bin on MacOS X, see Bug #3711.
dnl
AC_ARG_WITH(com_err,
        [AS_HELP_STRING([--with-com_err=DIR], [use com_err from path -- includes in DIR/include, libs in DIR/lib, and compile_et in DIR/bin])])
if test -z "$with_com_err"; then
        # no value supplied
        AC_CHECK_LIB(com_err, com_err, [
                # com_err is already in library path
                # guess we're okay
                # can use system com_err
                with_com_err=""
                AC_CHECK_HEADER(et/com_err.h,
                  [AC_DEFINE(HAVE_ET_COM_ERR_H,[],[We need et/com_err.h])],
                  [AC_CHECK_HEADER(com_err.h,[],[AC_MSG_ERROR([cannot locate com_err.h])])])
                AC_PATH_PROG(COMPILE_ET, compile_et, [no compile et])
        ], [
        if test -f /usr/local/include/com_err.h -o -f /usr/local/include/et/com_err.h; then
                with_com_err="/usr/local"
                AC_PATH_PROG(COMPILE_ET, /usr/local/bin/compile_et, [no compile et])
        elif test -f /usr/include/com_err.h -o -f /usr/include/et/com_err.h; then
                with_com_err="/usr"
                AC_PATH_PROG(COMPILE_ET, /usr/bin/compile_et, [no compile et])
        else
                # use ours
                with_com_err=yes
        fi
        ])

        if test "${with_com_err}" = "no"; then
          AC_MSG_WARN([com_err is required; included version will be used.])
          with_com_err="yes"
        fi
        if test "${COMPILE_ET}" = "no compile et" -o "${COMPILE_ET}" = ""; then
          AC_MSG_NOTICE([Parts of com_err distribution were found, but not compile_et.])
          AC_MSG_NOTICE([Will build com_err from included sources.])
          with_com_err="yes" # build it ourselves
        fi
fi

dnl Set up $COMPILE_ET first, we need to test it
case "$with_com_err" in
    # built-in et
    yes) # use the com_err we're gonna build
        COMPILE_ET="\${abs_top_builddir}/com_err/et/compile_et"
        ;;
    "") # no problem, we already have it in the paths
        # we do nothing to pick it up
        ;;
    *)  # use whatever they told us, or whatever we found
        COMPILE_ET="${with_com_err}/bin/compile_et"
        ;;
esac

if test "$with_com_err" != yes ; then
    dnl Test that the specified compile_et produces correct output
    dnl See bug #3711 for why this is necessary
    TEST1=".cyrus-configure-test-$$"
    /bin/rm -f $TEST1.et $TEST1.h $TEST1.c
    echo "error_table imap" >> $TEST1.et
    echo "ec IMAP_TESTING," >> $TEST1.et
    echo "   \"Testing\"" >> $TEST1.et
    echo "end" >> $TEST1.et
    "${COMPILE_ET}" $TEST1.et > /dev/null
    compile_et_ok=no
    if test -f $TEST1.h ; then
        dnl Broken compile_et produces (2390157824L)
        if test `awk '/IMAP_TESTING/{print $3}' $TEST1.h 2>/dev/null` = "(-1904809472L)" ; then
            dnl We need a version that exposes et_[foo]_error_table
            if grep -q '^extern const struct error_table et_imap_error_table;' $TEST1.h; then
                compile_et_ok=yes
            fi
        fi
    fi
    /bin/rm -f $TEST1.et $TEST1.h $TEST1.c
    if test "$compile_et_ok" = no ; then
        # revert to the built-in compile_et
        AC_MSG_WARN([It seems $COMPILE_ET is buggy, building our own])
        with_com_err=yes
        COMPILE_ET="\${abs_top_builddir}/com_err/et/compile_et"
    fi
fi

case "$with_com_err" in
  # built-in et
  yes) # use the com_err we're gonna build
          COM_ERR_LIBS="com_err/et/libcyrus_com_err.la"
          COM_ERR_CPPFLAGS="-I\${abs_top_srcdir}/com_err/et"
          ;;
  "")   # no problem, we already have it in the paths
        # we do nothing to pick it up
        COM_ERR_LIBS="-lcom_err" # hope it's not shared
        # we already set COMPILE_ET, or we didn't get here
        COM_ERR_CPPFLAGS=""
      ;;
  *) # use whatever they told us, or whatever we found
     COM_ERR_LIBS="${with_com_err}/lib/libcom_err.a"
     COM_ERR_CPPFLAGS="-I${with_com_err}/include"
     # Ever get the feeling people hide this stuff on purpose?
     if test -d "${with_com_err}/include/et" ; then
       COM_ERR_CPPFLAGS="-I${with_com_err}/include/et"
     fi
esac
AM_CONDITIONAL([COM_ERR], [test "$with_com_err" = "yes"])
if test "$with_com_err" = "yes"; then
  PKG_CONFIG_COM_ERR_LIB="-lcyrus_com_err"
fi
AC_SUBST(PKG_CONFIG_COM_ERR_LIB)
AC_SUBST(COMPILE_ET)
AC_SUBST(COM_ERR_LIBS)
AC_SUBST(COM_ERR_CPPFLAGS)

if test "$USE_MAINTAINER_MODE" = "yes" ; then
    AC_CHECK_PROG(GPERF,gperf,yes,no)
    if test "$GPERF" != "yes"; then
        AC_MSG_ERROR([gperf is not installed on this system, but is required for maintainer mode build rules])
    fi
fi

AC_MSG_CHECKING(for modern syslog)
AC_CACHE_VAL(cyrus_cv_lib_syslog, AC_TRY_CPP([#include <syslog.h>
#ifndef LOG_LOCAL6
#include </nonexistent>
#endif],cyrus_cv_lib_syslog=yes,cyrus_cv_lib_syslog=no))
AC_MSG_RESULT($cyrus_cv_lib_syslog)

AC_MSG_CHECKING(which syslog facility to use)
SYSLOG_FACILITY=LOG_LOCAL6
AC_ARG_WITH(syslogfacility,
        [AS_HELP_STRING([--with-syslogfacility=FACILITY], [set the syslog facility to use (default LOCAL6)])],
               [ if test "$withval" != "yes" -a "$withval" != "no" ; then
                       SYSLOG_FACILITY=LOG_$withval
               fi; ])
AC_DEFINE_UNQUOTED(SYSLOG_FACILITY, $SYSLOG_FACILITY, [Syslog facility to use.])
AC_MSG_RESULT($SYSLOG_FACILITY)

dnl Have to check getdtablesize after adding ossup, as some ossups define it
AC_REPLACE_FUNCS(getdtablesize)
AC_ARG_ENABLE(cmulocal,
        [AS_HELP_STRING([--enable-cmulocal], [enable CMU-specific local support])])
AM_CONDITIONAL([CMULOCAL], [test "$enable_cmulocal" = "yes"])
AC_MSG_CHECKING(to use old sieve service name)
AC_ARG_ENABLE(oldsievename,
        [AS_HELP_STRING([--enable-oldsievename], [enable the use of 'imap' as the sieve service name])],
        if test "$enableval" = yes; then
                AC_MSG_RESULT(yes)
                AC_DEFINE(OLD_SIEVE_SERVICE_NAME,[],[Use "imap" as sieve service name?])
        else
                AC_MSG_RESULT(no)
        fi,
        AC_MSG_RESULT(no))

CMU_SASL2_REQUIRE_VER(2,1,7)
CMU_SASL2_CHECKAPOP_REQUIRED

AC_ARG_WITH(perl,
        [AS_HELP_STRING([--with-perl=PERL], [use PERL for perl])],
        with_perl="$withval", with_perl="perl")

if test "${with_perl}" = yes; then
    with_perl="perl"
fi
if test "${with_perl}" != no; then
    if test ${using_static_sasl} = "staticonly"; then
        AC_MSG_WARN([Cannot compile perl utilities using static libsasl])
        with_perl="no"
    else
        AC_CHECK_PROGS(PERL, ${with_perl} perl, with_perl=notfound)
    fi
fi
AM_CONDITIONAL([PERL], [test "$with_perl" != "no" -a "$with_perl" != "notfound"])
srctoolsdir=`cd ${srcdir};pwd`/tools
if test "$with_perl" = "notfound"; then
    AC_MSG_WARN(Perl not found: Administrative tools will not be available)
elif test "${with_perl}" != "no"; then
dnl compile perl stuff and perl/cyradm
    PERL="${with_perl}"

dnl Make sure perl modules are in the build directory (which isn't necessarily
dnl the source directory)
    AC_CONFIG_LINKS([perl/sieve/managesieve/managesieve.pm:perl/sieve/managesieve/managesieve.pm])
    AC_CONFIG_FILES([perl/sieve/managesieve/MANIFEST])
    AC_CONFIG_LINKS([perl/imap/Cyrus/HeaderFile.pm:perl/imap/Cyrus/HeaderFile.pm])
    AC_CONFIG_LINKS([perl/imap/Cyrus/CacheFile.pm:perl/imap/Cyrus/CacheFile.pm])
    AC_CONFIG_LINKS([perl/imap/Cyrus/IndexFile.pm:perl/imap/Cyrus/IndexFile.pm])
    AC_CONFIG_LINKS([perl/imap/Cyrus/DList.pm:perl/imap/Cyrus/DList.pm])
    AC_CONFIG_LINKS([perl/imap/Cyrus/ImapClone.pm:perl/imap/Cyrus/ImapClone.pm])
    AC_CONFIG_LINKS([perl/imap/Cyrus/SyncProto.pm:perl/imap/Cyrus/SyncProto.pm])
    AC_CONFIG_LINKS([perl/imap/IMAP/Shell.pm:perl/imap/IMAP/Shell.pm])
    AC_CONFIG_LINKS([perl/imap/IMAP/IMSP.pm:perl/imap/IMAP/IMSP.pm])
    AC_CONFIG_LINKS([perl/imap/IMAP/Admin.pm:perl/imap/IMAP/Admin.pm])
    AC_CONFIG_LINKS([perl/imap/IMAP.pm:perl/imap/IMAP.pm])
    AC_CONFIG_FILES([perl/imap/MANIFEST])
    AC_CONFIG_LINKS([perl/annotator/Message.pm:perl/annotator/Message.pm])
    AC_CONFIG_LINKS([perl/annotator/AnnotateInlinedCIDs.pm:perl/annotator/AnnotateInlinedCIDs.pm])
    AC_CONFIG_LINKS([perl/annotator/Daemon.pm:perl/annotator/Daemon.pm])
    AC_CONFIG_FILES([perl/annotator/MANIFEST])

dnl add perl cccdlflags when building libraries -- this ensures that the
dnl libraries will be compiled as PIC if perl requires PIC objects
dnl -- this is needed on NetBSD and Linux, but seems to cause problems on atleast Solaris --
    case "${target_os}" in
        linux*|netbsd*|freebsd*|dragonfly*|openbsd*)
            AC_MSG_CHECKING(for perl cccdlflags needed on "${target_os}")
            eval `${PERL} -V:cccdlflags`
            PERL_CCCDLFLAGS="$cccdlflags"
            AC_SUBST(PERL_CCCDLFLAGS)
            AC_MSG_RESULT($PERL_CCCDLFLAGS)
            ;;
        *)
            AC_MSG_WARN(skipping check for perl cccdlflags on "${target_os}")
    esac

    PERL_PREINSTALL="${PERL} ${srctoolsdir}/fixsearchpath.pl ${prefix} ${bindir}"
    AC_SUBST(PERL_PREINSTALL)
fi

CMU_LIBWRAP

# Figure out what directories we're linking against.
# Lots of fun for the whole family.
# This probably chokes on anything with spaces in it.
# All we want is the list of -L directories, and -L may or may not be
# followed by a space.
isdir=no
libpath=""
#echo "debug ldflags: << ${ldflags} >>"
#echo "debug default_ldflags: << ${default_ldflags} >>"
for flag in ${ldflags} ${default_ldflags}; do
  case $flag in
    -L)
      # it's a split -L option, we'll mark the next option as a dir.
      isdir=yes
      ;;

    -L*)
      # attached -L option: split off the directory
      larg=`echo $flag | sed -e 's:-L\(..*\):\1:'`
      libpath="${libpath} ${larg}"
      ;;

    *)
      if test $isdir = yes ; then
        libpath="${libpath} ${flag}"
        isdir=no
      fi
  esac
done

AC_SUBST(LIB_SASL)
AC_SUBST(LIB_UUID)
AC_SUBST(PERL)

dnl
dnl Enable/disable unit tests.  These are disabled by default, as
dnl they require an additional library (the CUnit library).
dnl
AC_ARG_ENABLE(unit-tests,
        [AS_HELP_STRING([--enable-unit-tests], [enable CUnit-based unit regression tests])])

dnl Unit tests need the CUnit library, so check if we
dnl have both the header and the library.
dnl
dnl XXX cunit.pl is not compatible with vpath build, so auto-enabling
dnl XXX unit tests breaks make distcheck.  Shutting it up for now by not
dnl XXX auto-enabling them, because validating the rest of the distribution
dnl XXX with distcheck is more important than having it automatically run
dnl XXX the unit tests.  Once cunit.pl can handle vpath builds, make this
dnl XXX automatic again!
if test "x$enable_unit_tests" = xyes ; then
    AC_CHECK_LIB(cunit,CU_initialize_registry,found_lib=yes,found_lib=no)
    AC_CHECK_HEADER([CUnit/CUnit.h],found_hdr=yes,found_hdr=no)
    if test "$found_lib$found_hdr" != "yesyes" ; then
        if test "x$enable_unit_tests" = xyes; then
            AC_MSG_ERROR([Unit tests explicitly requested, but CUnit library is not installed])
        fi
        AC_MSG_NOTICE([Disabling unit tests because the required CUnit library is not installed])
        enable_unit_tests=no
    else
        enable_unit_tests=yes
    fi
    AC_CHECK_HEADER([CUnit/Basic.h],
        AC_CHECK_TYPE([CU_SetUpFunc],AC_DEFINE(HAVE_CU_SETUPFUNC,[],[Do we have CU_SetUpFunc?]),,
            [#include <CUnit/Basic.h>])
        ,)
fi
if test "$enable_unit_tests" = "yes" ; then
    dnl Valgrind is an amazingly useful tool for running tests.  It doesn't
    dnl need the program under test to be modified in any way, but it we can
    dnl optionally use some magic in it's header file to compensate for some
    dnl of the shortcomings of a C development environment by giving error
    dnl messages with backtraces.  This is so enormously useful for the unit
    dnl tests that want to enable it if possible, but we can struggle on
    dnl without it.  Besides, on many platforms the header file is in a
    dnl different package to the main valgrind binary, and so might not be
    dnl installed.
    AC_CHECK_HEADERS([valgrind/valgrind.h])

    dnl We depend on some data files, which exist in the source directory,
    dnl but need to be found at runtime by the built unit tests.
    dnl Under VPATH builds the source and build directories are not the same,
    dnl so the built unit tests can't easily find their data files.
    dnl Solution: just link them into the build directory at the same path.
    AC_CONFIG_LINKS([cunit/cacert.pem:cunit/cacert.pem])
    AC_CONFIG_LINKS([cunit/cert.pem:cunit/cert.pem])
    AC_CONFIG_LINKS([cunit/key.pem:cunit/key.pem])

    USE_MAINTAINER_MODE=yes
fi

AM_CONDITIONAL([CUNIT], [test "$enable_unit_tests" = "yes"])

dnl
dnl Enable/disable cyrusdb benchmarks.
dnl
AC_ARG_ENABLE(cyrusdb-benchmarks,
        [AS_HELP_STRING([--enable-cyrusdb-benchmarks], [enable cyrdb benchmarks])])

if test "$enable_cyrusbd_benchmarks" = "yes" ; then
    USE_MAINTAINER_MODE=yes
fi

AM_CONDITIONAL([BENCH], [test "$enable_cyrusdb_benchmarks" = "yes"])

dnl Finally, now that we've checked everything else, we can see whether to link
dnl in SQLite or not.
dnl
if test "x$use_sqlite" = xyes; then
  if test "x$HAVE_SQLITE" = x1; then
    if test "x$with_sqlite_lib" != xnone; then
        CMU_ADD_LIBPATH($with_sqlite_lib)
    fi

    LIBS="${LIBS} ${SQLITE_LIBADD}"
    CPPFLAGS="${SQLITE_INCADD} ${CPPFLAGS}"
    AC_DEFINE(HAVE_SQLITE,[],[Build in SQLite support?])
    AC_SUBST(SQLITE_LIBADD)
  else
    AC_MSG_ERROR([SQLite required but not found])
  fi
fi
AM_CONDITIONAL([USE_SQLITE], [test "x$use_sqlite" = xyes])

dnl compiler feature checking
AC_MSG_CHECKING(for function nesting)
AC_CACHE_VAL(cyrus_cv_function_nesting, AC_TRY_COMPILE([
#include <stdlib.h>
void func(void *data, size_t nmemb, size_t size,
          int (*compar)(const void *, const void *, void *),
          void *thunk)
{
    int compar_func(const void *a, const void *b)
    {
        return compar(a, b, thunk);
    }
    qsort(data, nmemb, size, compar_func);
}
int cval(const void *a, const void *b, void *prev)
{
  char **ref = (char **)prev;
  char *ac = (char *)a;
  char *bc = (char *)b;
  if (*ac < *bc) return -1;
  if (*ac == *bc) return 0;
  *ref = bc;
  return 1;
}
],[
    char *dest;
    func("abc", 3, 1, cval, &dest);
],cyrus_cv_function_nesting=yes, cyrus_cv_function_nesting=no))
AC_MSG_RESULT($cyrus_cv_function_nesting)
if test "$cyrus_cv_function_nesting" = "yes"; then
  AC_DEFINE(HAVE_FUNCTION_NESTING,[],[Do we have function nesting support?])
fi

AC_CACHE_CHECK(
    [for optimisation support],
    [cyrus_cv_declare_optimize],
    [
        AC_LANG_PUSH([C])
        saved_CFLAGS="$CFLAGS"
        CFLAGS="$CFLAGS -Werror"
        AC_COMPILE_IFELSE(
            [AC_LANG_PROGRAM(
                [
                    #include <stdlib.h>
                    static inline int numcmp(int n1, int n2)
                        __attribute__((pure, always_inline, optimize("-O3")));
                    static int numcmp(int n1, int n2) { return n1 - n2; }
                ],
                [ if (numcmp(1, 2)) exit(1); ])
            ],
            [cyrus_cv_declare_optimize=yes],
            [cyrus_cv_declare_optimize=no])
        CFLAGS="$saved_CFLAGS"
        AC_LANG_POP([C])
    ])
AS_IF(
    [test "x$cyrus_cv_declare_optimize" = "xyes"],
    [AC_DEFINE(HAVE_DECLARE_OPTIMIZE,[],
        [Do we have support for optimize __attribute__?])]
)

dnl documentation generation (sphinx, perl2rst, gitpython)
AC_ARG_VAR(SPHINX_BUILD, [Location of sphinx-build])
AC_ARG_WITH([sphinx-build],
            AS_HELP_STRING([--with-sphinx-build=(yes|no|PATH)], [Look for sphinx-build in PATH]),
            [with_sphinx_build=$withval],
            [with_sphinx_build=yes])
AS_CASE([$with_sphinx_build],
        [yes],  [AC_PATH_PROG(SPHINX_BUILD, sphinx-build)],
        [no],   [SPHINX_BUILD=''],
        [*],    [AC_PATH_PROG(SPHINX_BUILD, sphinx-build, [], [$with_sphinx_build])])
AS_IF([test -z "$SPHINX_BUILD"],
      [AC_MSG_WARN([No sphinx-build, won't be able to regenerate docs])])
AC_SUBST([SPHINX_BUILD])

AX_PROG_PERL_MODULES([Pod::POM::View::Restructured],
                     [have_ppvr=yes],
                     [AC_MSG_WARN([No Pod::POM::View::Restructured, won't be able to regenerate docs])
                       have_ppvr=no
                     ])

AX_PYTHON_MODULE([git], [], [python])
AS_CASE([$HAVE_PYMOD_GIT],
        [yes],  [],
        [*],    [AC_MSG_WARN([GitPython not found, won't be able to regenerate docs])])

AM_CONDITIONAL([HAVE_SPHINX_BUILD],
    [ test -n "$SPHINX_BUILD" -a x"$have_ppvr" = xyes -a x"$HAVE_PYMOD_GIT" = xyes])

AH_TOP([
/*
 * Copyright (c) 1994-2015 Carnegie Mellon University.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The name "Carnegie Mellon University" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For permission or any legal
 *    details, please contact
 *      Carnegie Mellon University
 *      Center for Technology Transfer and Enterprise Creation
 *      4615 Forbes Avenue
 *      Suite 302
 *      Pittsburgh, PA  15213
 *      (412) 268-7393, fax: (412) 268-7395
 *      innovation@andrew.cmu.edu
 *
 * 4. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by Computing Services
 *     at Carnegie Mellon University (http://www.cmu.edu/computing/)."
 *
 * CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
 * FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef _CYRUS_IMAPD_CONFIG_H_
#define _CYRUS_IMAPD_CONFIG_H_
])

AH_BOTTOM([
/* time.h */
#if TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif

/* com_err.h, as needed */
#ifndef IN_COM_ERR
#ifdef HAVE_ET_COM_ERR_H
#include <et/com_err.h>
#else
#include <com_err.h>
#endif /* HAVE_ET_COM_ERR_H */
#endif /* IN_COM_ERR */

/* This allows us to work even when we don't have an fdatasync */
#ifndef HAVE_FDATASYNC
#define fdatasync(fd) fsync(fd)
#endif

/* A similar setup for not having O_DSYNC */
#include <fcntl.h>

#ifndef O_DSYNC
#  ifdef O_SYNC
#    define O_DSYNC     O_SYNC          /* POSIX */
#  else
#    define O_DSYNC     O_FSYNC         /* BSD */
#  endif
#endif

#ifndef HAVE_SOCKLEN_T
typedef unsigned int socklen_t;
#endif

#ifndef HAVE_RLIM_T
typedef int rlim_t;
#endif

/* some potentially memory saving tradeoffs,
   preconfigured in memory-saving mode */

/* save the cmdlines for the ID command */
#undef ID_SAVE_CMDLINE

/* IPv6 things */
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#ifndef HAVE_STRUCT_SOCKADDR_STORAGE
#define _SS_MAXSIZE     128     /* Implementation specific max size */
#define _SS_PADSIZE     (_SS_MAXSIZE - sizeof (struct sockaddr))

struct sockaddr_storage {
        struct  sockaddr ss_sa;
        char            __ss_pad2[_SS_PADSIZE];
};
# define ss_family ss_sa.sa_family
# define HAVE_SS_FAMILY
#endif /* !HAVE_STRUCT_SOCKADDR_STORAGE */

#ifndef AF_INET6
/* Define it to something that should never appear */
#define AF_INET6        AF_MAX
#endif

#if !defined(HAVE_GETADDRINFO) || !defined(HAVE_GETNAMEINFO)
#include "lib/gai.h"
#endif

/* End IPv6 things */

#ifdef OLD_SIEVE_SERVICE_NAME
#define SIEVE_SERVICE_NAME "imap"
#else
#define SIEVE_SERVICE_NAME "sieve"
#endif

/* filenames */
#define FNAME_DBDIR "/db"
#define FNAME_USERDIR "/user/"
#define FNAME_DOMAINDIR "/domain/"
#define FNAME_LOGDIR "/log/"
#define FNAME_PTSDB "/ptclient/ptscache.db"
#define CONFIG_FILENAME (SYSCONF_DIR "/imapd.conf")
#define DEFAULT_MASTER_CONFIG_FILENAME (SYSCONF_DIR "/cyrus.conf")

#ifndef HAVE_SHUTDOWN
#define shutdown(fd, mode) 0
#endif

#ifndef HAVE_POSIX_FADVISE
#define POSIX_FADV_WILLNEED 0
extern int posix_fadvise(int fd, off_t offset, off_t len, int advice);
#endif

#ifndef HAVE_STRSEP
extern char *strsep(char **, const char *);
#endif

#ifndef HAVE_MEMMEM
extern void *memmem(const void *, size_t, const void *, size_t);
#endif

#ifndef HAVE_MEMRCHR
extern void *memrchr(const void *, int, size_t);
#endif

/* compile time options; think carefully before modifying */
enum {
    /* should we send an UNAVAILABLE message to master when
     * a service is exiting (master is already going to be
     * informed of the exit by the SIGCHLD signal anyway) ? */
    MESSAGE_MASTER_ON_EXIT = 0,

    /* should a hierarchical rename stop on error? */
    RENAME_STOP_ON_ERROR = 1,

    /* should we call fsync() to maybe help with softupdates? (it should) */
    APPEND_ULTRA_PARANOID = 1,

    /* should we log extra information at the DEBUG level for DB stuff?
     * 0 -> nothing; 1 -> some; higher -> even more */
    CONFIG_DB_VERBOSE = 1,

    /* log timing information to LOG_DEBUG */
    CONFIG_TIMING_VERBOSE = 0,

    /* should we be pedantic about namespace or sleezy? */
    SLEEZY_NAMESPACE = 1,

    /* should we do a fast TLS session shutdown? */
    TLS_FAST_SHUTDOWN = 1,

    /* should we have long LMTP error messages? */
    LMTP_LONG_ERROR_MSGS = 1
};

#endif /* _CYRUS_IMAPD_CONFIG_H_ */
])

dnl We need to link with stdc++ when building static cyrus libs and binaries.
dnl libstdc++ is required because we link with libxapian, which is written in C++.
if test "X$enable_shared" = "Xno"
then
        LIBS="$LIBS -lstdc++";
fi

dnl make sure that Makefile is the last thing output
AC_CONFIG_FILES([
    libcyrus_imap.pc
    libcyrus_min.pc
    libcyrus.pc
    libcyrus_sieve.pc
    Makefile
])

if test "$with_perl" != "no" -a "$with_perl" != "notfound" ; then
CMU_PERL_MAKEMAKER(perl/annotator)
CMU_PERL_MAKEMAKER(perl/imap)
CMU_PERL_MAKEMAKER(perl/sieve/managesieve)
fi

AC_OUTPUT
echo "
Cyrus Server configured components

   gssapi:             $gssapi
   autocreate:         $enable_autocreate
   idled:              $enable_idled
   httpd:              $enable_http
   kerberos V4:        $krb4
   murder:             $enable_murder
   nntpd:              $enable_nntp
   replication:        $enable_replication
   sieve:              $enable_sieve
   srs:                $enable_srs
   calalarmd:          $enable_calalarmd
   jmap:               $enable_jmap
   objectstore:        $enable_objectstore
   backup:             $enable_backup
   com_err:            $with_com_err

External dependencies:
   ldap:               $have_ldap
   openssl:            $with_ssl
   zlib:               $with_zlib
   jansson:            $with_jansson
   pcre:               $cyrus_cv_pcre_utf8
   clamav:             $with_clamav
   -----------------------
   caringo:            $with_caringo
   openio:             $with_openio
   -----------------------
   nghttp2:            $with_nghttp2
   wslay:              $with_wslay
   brotli:             $with_brotli
   zstd:               $with_zstd
   xml2:               $with_xml2
   ical:               $with_ical
   shapelib:           $with_shapelib
   icu4c:              $with_icu4c
   chardet:            $with_chardet
   cld2:               $with_cld2

Database support:
   mysql:              $with_mysql
   postgresql:         $use_pgsql
   sqlite:             $use_sqlite
   zeroskip:           $with_zeroskip

Search engine:
   squat:              $enable_squat
   xapian:             $enable_xapian
   xapian_cjk_tokens:  $xapian_cjk_tokens

Documentation dependencies:
   sphinx-build:       $SPHINX_BUILD
   Pod::POM::View::Restructured:  $have_ppvr
   GitPython:          $HAVE_PYMOD_GIT

Installation directories:
   prefix:             $prefix
   sysconfdir:         $sysconfdir

Build info:
   shared:             $enable_shared
   static:             $enable_static
   cflags:             $CFLAGS
   cxxflags:           $CXXFLAGS
   libs:               $LIBS
   ldflags:            $LDFLAGS
   unit tests (cunit): $enable_unit_tests
"

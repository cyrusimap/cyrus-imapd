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

dnl in case the first use of PKG_CHECK_MODULES is inside a conditional
PKG_PROG_PKG_CONFIG

AM_INIT_AUTOMAKE([-Wall -Werror -Wno-portability foreign dist-bzip2 no-installinfo subdir-objects])
AC_CONFIG_LIBOBJ_DIR([lib])

dnl Useful hook for distributions
AC_ARG_WITH(extraident,
        [AS_HELP_STRING([--with-extraident=STRING],[use STRING as extra version information])],
	[AC_DEFINE_UNQUOTED(EXTRA_IDENT,"$withval", [Extra version information for imap/version.h])])

AM_MAINTAINER_MODE

dnl Coverage (disabled by default)
COV_CFLAGS=
COV_LDFLAGS=

AC_ARG_ENABLE(coverage,
    AS_HELP_STRING([--enable-coverage],[enable C test coverage])
)

AS_IF([test "x$enable_coverage" = "xyes"], [
    COV_CFLAGS="--coverage"
    COV_LDFLAGS="--coverage"
])

AC_SUBST(COV_CFLAGS)
AC_SUBST(COV_LDFLAGS)

AC_ARG_WITH(login,,AC_MSG_ERROR([--with-login is no longer supported.
Configure SASL appropriately instead.]))

dnl We need to derive default values for --with-cyrus-prefix and
dnl --with-service-path based on $prefix, but $prefix may currently
dnl be set to "NONE" for autoconf reasons, so work around that.
if test "x$prefix" = "xNONE"; then
    myprefix="$ac_default_prefix"
else
    myprefix="$prefix"
fi

AC_ARG_WITH(cyrus-prefix,
	[AS_HELP_STRING([--with-cyrus-prefix=DIR], [use DIR as cyrus server install directory [PREFIX/cyrus]])],
	cyrus_prefix="$withval",cyrus_prefix="$myprefix/cyrus")
AC_DEFINE_UNQUOTED(CYRUS_PATH,"$cyrus_prefix",[Where will we be installed?])
AC_ARG_WITH(service-path,
	[AS_HELP_STRING([--with-service-path=DIR], [use DIR as service install directory [CYRUSPREFIX/bin]])],
	servicedir="$withval",servicedir="$cyrus_prefix/bin")
userdir=$servicedir
AC_SUBST(userdir)
AC_SUBST(servicedir)
AC_DEFINE_UNQUOTED(SERVICE_DIR,"$servicedir",[Directory to use for service binaries])
AC_ARG_WITH(cyrus-user,
	[AS_HELP_STRING([--with-cyrus-user=USERID], [use USERID cyrus userid])],
	cyrus_user="$withval",cyrus_user="cyrus")
AC_SUBST(cyrus_user)
AC_DEFINE_UNQUOTED(CYRUS_USER, "$cyrus_user",[What user will we run as?])
AC_ARG_WITH(cyrus-group,
	[AS_HELP_STRING([--with-cyrus-group=GROUPID], [use GROUPID cyrus group])],
	cyrus_group="$withval",cyrus_group="mail")
AC_SUBST(cyrus_group)

dnl allow users to override $sysconfdir, but retain old default (/etc)
dnl if not specified
if test $sysconfdir = '${prefix}/etc'; then
  sysconfdir="/etc"
fi
AC_DEFINE_UNQUOTED(SYSCONFDIR,"$sysconfdir",[Config File Location])

AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_PROG_INSTALL
AC_USE_SYSTEM_EXTENSIONS
AC_ISC_POSIX
AC_PROG_AWK
AC_C_CONST
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

LT_PREREQ([2.2.6])
LT_INIT([disable-static])
AC_SUBST([LIBTOOL_DEPS])

dnl Check the size of various types
AC_CHECK_SIZEOF(int)
AC_CHECK_SIZEOF(long)
AC_CHECK_SIZEOF(size_t)
AC_CHECK_SIZEOF(off_t)

dnl Check that `long long int' is available
AC_CHECK_SIZEOF(long long int)
AC_CHECK_SIZEOF(unsigned long long int)
if test "$ac_cv_sizeof_long_long_int" -eq 8 -a \
        "$ac_cv_sizeof_unsigned_long_long_int" -eq 8; then
  AC_C_BIGENDIAN
else
  AC_MSG_ERROR(The Cyrus IMAPD requires support for long long int)
fi

CMU_C_FPIC

dnl check for -R, etc. switch
CMU_GUESS_RUNPATH_SWITCH

AC_CHECK_HEADERS(unistd.h sys/select.h sys/param.h stdarg.h)
AC_REPLACE_FUNCS(memmove strcasecmp ftruncate strerror posix_fadvise strsep memmem)
AC_CHECK_FUNCS(strlcat strlcpy getgrouplist fmemopen pselect getline)
AC_HEADER_DIRENT

dnl check whether to use getpassphrase or getpass
AC_CHECK_HEADERS(stdlib.h)
AC_CHECK_FUNCS(getpassphrase)

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

dnl function for doing each of the database backends
dnl parameters: backend name, variable to set, withval

dnl Berkeley DB Detection

AC_ARG_WITH(bdb,
	[AS_HELP_STRING([--with-bdb=DIR], [use Berkeley DB (in DIR) [yes]])],
	with_bdb=$withval, with_bdb="yes")

dnl support old-style
AC_ARG_WITH(dbdir,, with_bdb=$withval)

case "$with_bdb" in
  no)
	use_berkeley="no"
	;;
  yes)
	use_berkeley="yes"
	with_bdb_lib=none
	with_bdb_inc=none
	;;
  *)
	use_berkeley="yes"
	with_bdb_lib="$with_bdb/lib"
	with_bdb_inc="$with_bdb/include"
	;;
esac

if test "$use_berkeley" != "no"; then
  CYRUS_BERKELEY_DB_CHK()

  if test "$dblib" = "no"; then
    AC_MSG_ERROR([Berkeley DB 3.x or later was not found.  You may need to 
    supply the --with-bdb-libdir or --with-bdb-incdir configure options.])
  fi

  if test "$with_bdb_lib" != "none"; then
    CMU_ADD_LIBPATH($with_bdb_lib)
  fi

  BDB_INC=${BDB_INCADD}
  BDB_LIB=${BDB_LIBADD}
  AC_SUBST(BDB_INC)
  AC_SUBST(BDB_LIB)

  LIBS="${LIBS} ${BDB_LIBADD}"
  CPPFLAGS="${BDB_INCADD} ${CPPFLAGS}"
  AC_DEFINE(HAVE_BDB,[],[Build in Berkeley DB support?])
fi
AM_CONDITIONAL([USE_BERKELEY], [test "$use_berkeley" != "no"])

dnl End Berkeley DB Detection


dnl SQL DB Detection

HAVE_SQL=0

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
    HAVE_SQL=1
    LIBS="${LIBS} ${MYSQL_LIBADD}"
    CPPFLAGS="${MYSQL_INCADD} ${CPPFLAGS}"
    AC_DEFINE(HAVE_MYSQL,[],[Build in MySQL support?])
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
    HAVE_SQL=1
  fi

  if test "$with_pgsql_lib" != "none"; then
    CMU_ADD_LIBPATH($with_pgsql_lib)
  fi

  LIBS="${LIBS} ${PGSQL_LIBADD}"
  CPPFLAGS="${PGSQL_INCADD} ${CPPFLAGS}"

  AC_DEFINE(HAVE_PGSQL,[],[Build in PgSQL support?])
fi

dnl End PgSQL Detection


dnl SQLite Detection
AC_ARG_WITH(sqlite,
	[AS_HELP_STRING([--with-sqlite=DIR], [use SQLite (in DIR) [no]])],
	with_sqlite=$withval, with_sqlite=no)

case "$with_sqlite" in
  no)
	use_sqlite="no"
	;;
  yes)
	use_sqlite="yes"
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

  if test "$sqlitelib" = "no"; then
    AC_MSG_ERROR([Sqlite was not found.  You may need to supply the
    --with-sqlite-libdir or --with-sqlite-incdir configure options.])
  else
    HAVE_SQL=1
  fi

  if test "$with_sqlite_lib" != "none"; then
    CMU_ADD_LIBPATH($with_sqlite_lib)
  fi

  LIBS="${LIBS} ${SQLITE_LIBADD}"
  CPPFLAGS="${SQLITE_INCADD} ${CPPFLAGS}"

  AC_DEFINE(HAVE_SQLITE,[],[Build in SQLite support?])
fi

dnl End SQLite Detection

AM_CONDITIONAL([USE_SQL], [test $HAVE_SQL = 1])
dnl End SQL DB Detection

AC_ARG_ENABLE(sieve,
        [AS_HELP_STRING([--disable-sieve], [disable Sieve support])],,[enable_sieve="yes";])
AC_ARG_ENABLE(pcre,
	[AS_HELP_STRING([--disable-pcre], [disable PCRE library])])

if test "$enable_sieve" != "no"; then
	AC_DEFINE(USE_SIEVE,[],[Build in Sieve support?])

	dnl Sieve configure stuff
	AC_PROG_YACC
	AM_PROG_LEX

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

	if test "$cyrus_cv_pcre_utf8" = "yes"; then
		LIBS="$LIBS -lpcre -lpcreposix";
		AC_DEFINE(ENABLE_REGEX, [], [Do we have a regex library?])
		AC_DEFINE(HAVE_PCREPOSIX_H, [], [Do we have usable pcre library?])
	else
		AC_CHECK_HEADERS(rxposix.h)
		if test "$ac_cv_header_rxposix_h" = "yes"; then
			LIBS="$LIBS -lrx"
			AC_DEFINE(ENABLE_REGEX, [],
				  [Do we have a regex library?])
		else
			AC_SEARCH_LIBS(regcomp, regex,
					AC_DEFINE(ENABLE_REGEX, [],
					[Do we have a regex library?]), [])
		fi
	fi
fi

AM_CONDITIONAL([SIEVE], [test "${enable_sieve}" != "no"])

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
#ifndef	FNDELAY
#define FNDELAY		O_NDELAY
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

    CFLAGS="${CFLAGS} -I${with_afs_incdir}"
    AFS_LIBS="${with_afs_libdir}/afs/libkauth.a ${with_afs_libdir}/afs/libprot.a  ${with_afs_libdir}/afs/libauth.a ${with_afs_libdir}/afs/libsys.a ${with_afs_libdir}/librxkad.a ${with_afs_libdir}/librx.a ${with_afs_libdir}/afs/libsys.a ${with_afs_libdir}/libubik.a  ${with_afs_libdir}/afs/liblwp.a ${with_afs_libdir}/afs/util.a ${with_afs_libdir}/afs/libafscom_err.a -lresolv"
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
AM_CONDITIONAL([HAVE_CLAMAV], [test "x$with_clamav" != "xno"])

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

dnl In order to compile kerberos4, we need libkrb and libdes.

dnl we might need -lresolv for kerberos
AC_CHECK_LIB(resolv,res_search)

if test "$with_statickrb" = "yes" -a ! -d "$with_krb"; then
      AC_MSG_ERROR([--enable-statickrb specified but --with-krb did not specify a valid directory])
fi 

if test "$with_krb" != "no"; then
dnl Do we need DES for kerberos?
AC_ARG_WITH(krbdes,
	[AS_HELP_STRING([--with-krbdes], [use Kerberos DES implementation [yes]])],
	with_krbdes="$withval", with_krbdes="yes")
if test "$with_krbdes" = "yes"; then
  AC_CHECK_LIB(des,des_ecb_encrypt,
      if test "$with_statickrb" = "yes"; then
          KRB_LIBS="$with_krb/lib/libdes.a"
      else
          KRB_LIBS="-ldes"
      fi,
  AC_MSG_ERROR([The Kerberos DES library is required for Kerberos support.  You might want --with-auth=unix.]))
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
CMU_HAVE_ZLIB
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
case $host_os in
linux*)
	if test "x$with_libcap" = "xyes"; then
		AC_CHECK_LIB([cap], [cap_get_proc], have_libcap=yes, have_libcap=no)
		AC_CHECK_HEADERS([sys/capability.h sys/prctl.h], , have_libcap=no)
		if test "$have_libcap" = "yes"; then
			AC_DEFINE(HAVE_LIBCAP, [], [Do we have libcap system capabilities handling (Linux systems only)?])
			LIBS="$LIBS -lcap"
		fi
	fi
	;;
*)
	;;
esac

AC_MSG_CHECKING(for libcap)
AC_MSG_RESULT($have_libcap)


dnl
dnl Test for mailbox event notification
dnl enable requires the installation of jansson library
dnl
AC_ARG_ENABLE(event-notification,
        [AS_HELP_STRING([--disable-event-notification], [disable compiling of mailbox event notification (that needs jansson library)])],,
        [enable_event_notification="yes";])

if test "$enable_event_notification" != "no"; then
    PKG_CHECK_MODULES([JANSSON], [jansson >= 2.0],
	[check_jansson=true] 
	  dnl call AC_SUBST macro to support pkg-config version older that 0.24 without any bad consequence for recent version
	  [AC_SUBST([JANSSON_LIBS])]
	  [AC_SUBST([JANSSON_CFLAGS])]
	  [AC_DEFINE(ENABLE_MBOXEVENT,[],[Build with support of mailbox event notification])],
	[check_jansson=false]
	  [AC_MSG_WARN([jansson 2.0 or later was not found, but is required to enable mailbox event notification])]
	  enable_event_notification="no")
fi
AM_CONDITIONAL(JANSSON, test x$check_jansson = xtrue)

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
dnl
dnl see if we're compiling with NNTP support
dnl
AC_ARG_ENABLE(nntp,
        [AS_HELP_STRING([--enable-nntp], [enable NNTP support])],,[enable_nntp="no";])
AM_CONDITIONAL([NNTPD], [test "$enable_nntp" != "no"])

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

dnl
dnl see if we're compiling with HTTP support
dnl
ENABLE_HTTP=no
AC_ARG_ENABLE(http,
        [AS_HELP_STRING([--enable-http], [enable HTTP support])],, [enable_http="no";])
AM_CONDITIONAL([HTTPD], [test "$enable_http" != "no"])

HTTP_CPPFLAGS=
HTTP_LIBS=
if test "$enable_http" != no; then
dnl
dnl make sure all the modules we need are present
dnl
	ENABLE_RSS=yes
	ENABLE_DAV=yes
	PKG_CHECK_MODULES([XML2], [libxml-2.0],,AC_MSG_ERROR([Need libxml-2.0 for http]))
	PKG_CHECK_MODULES([ICAL], [libical],,AC_MSG_ERROR([Need libical for http]))
	PKG_CHECK_MODULES([SQLITE3], [sqlite3],,AC_MSG_ERROR([Need sqlite3 for http]))
	PKG_CHECK_MODULES([JSON], [jansson],,AC_MSG_ERROR([Need jansson for http]))

	HTTP_LIBS="${XML2_LIBS} ${ICAL_LIBS} ${SQLITE3_LIBS} ${JSON_LIBS}"
	HTTP_CPPFLAGS="${JSON_CFLAGS} ${SQLITE3_CFLAGS} ${ICAL_CFLAGS} ${XML2_CFLAGS}"

	saved_LIBS=${LIBS}
	saved_CPPFLAGS="${CPPFLAGS}"
	LIBS="${LIBS} ${HTTP_LIBS}"
	CPPFLAGS="${CPPFLAGS} ${HTTP_CPPFLAGS}"

	AC_DEFINE(HAVE_XML2,[],[Build in libxml support?])
	AC_DEFINE(HAVE_ICAL,[],[Build in ical support?])
	AC_DEFINE(HAVE_SQLITE3,[],[Build in SQLite support?])

	AC_DEFINE(WITH_DAV,[],[Build DAV support into httpd?])
	AC_DEFINE(WITH_JSON,[],[Build jCal/jCard/TZdist support into httpd?])

	AC_CHECK_LIB(ical, icaltimezone_set_builtin_tzdata,
		AC_DEFINE(HAVE_TZ_BY_REF,[],
			[Build TZ by ref support into httpd?]))

	AC_EGREP_HEADER(ICAL_TZUNTIL_PROPERTY, [libical/ical.h],
		AC_DEFINE(HAVE_TZDIST_PROPS,[],
			[Do we have built-in support for TZdist props?]))

	CYRUS_OPENDKIM_CHK()
	if test "$opendkimlib" = "yes"; then
	    AC_SUBST(DKIM_CFLAGS)
	    AC_SUBST(DKIM_LIBS)
	    AC_DEFINE(WITH_DKIM,[],[Build DKIM support into iSchedule?]) 
	fi

	AC_EGREP_HEADER(ICAL_IANA_PARAMETER, [libical/ical.h],
		AC_DEFINE(HAVE_IANA_PARAMS,[],
			[Do we have support for IANA params?]),
		AC_MSG_WARN([Your version of libical can not support scheduling or managed attachments.  Consider upgrading to libical >= 0.48]))

	AC_EGREP_HEADER(ICAL_SCHEDULESTATUS_PARAMETER, [libical/ical.h],
		AC_DEFINE(HAVE_SCHEDULING_PARAMS,[],
			[Do we have built-in support for scheduling params?]))

	AC_EGREP_HEADER(ICAL_VAVAILABILITY_COMPONENT, [libical/ical.h],
		AC_DEFINE(HAVE_VAVAILABILITY,[],
			[Build VAVAILABILITY support into httpd?]))

	AC_EGREP_HEADER(ICAL_VPOLL_COMPONENT, [libical/ical.h],
		AC_DEFINE(HAVE_VPOLL,[],
			[Build VPOLL support into httpd?]))

	ENABLE_RSCALE=yes
	PKG_CHECK_MODULES([ICU], [icu-i18n],, ENABLE_RSCALE=no)
	if test "$ENABLE_RSCALE" != no; then
	     AC_SUBST(ICU_CFLAGS)
	     AC_SUBST(ICU_LIBS)
	     AC_CHECK_LIB(ical, icalrecurrencetype_rscale_is_supported,
		    AC_DEFINE(HAVE_RSCALE,[], [Build RSCALE support into httpd?]))
	fi

	LIBS="${saved_LIBS}"
	CPPFLAGS="${saved_CPPFLAGS}"
fi
AC_SUBST(HTTP_CPPFLAGS)
AC_SUBST(HTTP_LIBS)

dnl
dnl see if we're compiling replication support programs
dnl
AC_ARG_ENABLE(replication,
        [AS_HELP_STRING([--enable-replication], [enable replication support (experimental)])],,[enable_replication="no";])
AM_CONDITIONAL([REPLICATION], [test "$enable_replication" != no])

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
	  AC_MSG_WARN([Parts of com_err distribuion were found, but not compile_et.])
	  AC_MSG_WARN([Will build com_err from included sources.])
	  with_com_err="yes" # build it ourselves
	fi
fi

dnl Set up $COMPILE_ET first, we need to test it
case "$with_com_err" in
    # built-in et
    yes) # use the com_err we're gonna build
	COMPILE_ET="\${abs_top_builddir}/com_err/et/compile_et"
	;;
    "")	# no problem, we already have it in the paths
	# we do nothing to pick it up
	;;
    *)	# use whatever they told us, or whatever we found
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
	if test `awk '/IMAP_TESTING/{print $3}' $TEST1.h 2>/dev/null` = "(-1904809472L)" ; then
	    compile_et_ok=yes
	fi
	dnl Broken compile_et produces (2390157824L)
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
	  COM_ERR_CPPFLAGS="-I\${top_srcdir}/com_err/et"
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

dnl Have to check getdtabalesize after adding ossup, as some ossups define it
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

AC_ARG_ENABLE(netscapehack,
	[AS_HELP_STRING([--enable-netscapehack], [enable Netscape hack for the menu option in Communicator to Administrate Mail])],
	if test "$enableval" = yes; then
		AC_DEFINE(ENABLE_X_NETSCAPE_HACK,[],[Enable Netscape Menu Option Hack?])
	fi)

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
dnl add perl cccdlflags when building libraries -- this ensures that the
dnl libraries will be compiled as PIC if perl requires PIC objects
dnl -- this is needed on NetBSD and Linux, but seems to cause problems on atleast Solaris --
    case "${target_os}" in
        linux*|netbsd*|freebsd*|dragonfly*)
            AC_MSG_CHECKING(for perl cccdlflags needed on "${target_os}")
            eval `${PERL} -V:cccdlflags`
            PERL_CCCDLFLAGS="$cccdlflags"
            AC_SUBST(PERL_CCCDLFLAGS)
            AC_MSG_RESULT($PERL_CCCDLFLAGS)
            ;;
        *)
            AC_MSG_WARN(skipping check for perl cccdlflags on "${target_os}")
    esac

    PERL_PREINSTALL="${PERL} ${srctoolsdir}/fixsearchpath.pl ${cyrus_prefix} ${bindir}"
    AC_SUBST(PERL_PREINSTALL)
fi

CMU_LIBWRAP
CMU_UCDSNMP

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
if test "$enable_unit_tests" = "yes" ; then
    AC_CHECK_LIB(cunit,CU_initialize_registry,found_lib=yes,found_lib=no)
    AC_CHECK_HEADER([CUnit/CUnit.h],found_hdr=yes,found_hdr=no)
    if test "$found_lib$found_hdr" != "yesyes" ; then
	AC_MSG_NOTICE([Disabling unit tests because the required CUnit library is not installed])
	enable_unit_tests=no
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

    USE_MAINTAINER_MODE=yes
fi

AM_CONDITIONAL([CUNIT], [test "$enable_unit_tests" = "yes"])

AH_TOP([
/*
 * Copyright (c) 1994-2012 Carnegie Mellon University.  All rights reserved.
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
#define	_SS_MAXSIZE	128	/* Implementation specific max size */
#define	_SS_PADSIZE	(_SS_MAXSIZE - sizeof (struct sockaddr))

struct sockaddr_storage {
	struct	sockaddr ss_sa;
	char		__ss_pad2[_SS_PADSIZE];
};
# define ss_family ss_sa.sa_family
# define HAVE_SS_FAMILY
#endif /* !HAVE_STRUCT_SOCKADDR_STORAGE */

#ifndef AF_INET6
/* Define it to something that should never appear */
#define	AF_INET6	AF_MAX
#endif

#if !defined(HAVE_GETADDRINFO) || !defined(HAVE_GETNAMEINFO)
#include "gai.h"
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
#define CONFIG_FILENAME (SYSCONFDIR "/imapd.conf")
#define DEFAULT_MASTER_CONFIG_FILENAME (SYSCONFDIR "/cyrus.conf")

#ifndef HAVE_SHUTDOWN
#define shutdown(fd, mode) 0
#endif

/* *printf() macros */
#if (SIZEOF_SIZE_T == SIZEOF_INT)
#define SIZE_T_FMT "%u"
#elif (SIZEOF_SIZE_T == SIZEOF_LONG)
#define SIZE_T_FMT "%lu"
#elif (SIZEOF_SIZE_T == SIZEOF_LONG_LONG_INT)
#define SIZE_T_FMT "%llu"
#else
#error dont know what to use for SIZE_T_FMT
#endif

#if (SIZEOF_OFF_T == SIZEOF_LONG)
#define OFF_T_FMT "%ld"
#define strtoofft(nptr, endptr, base) strtol(nptr, endptr, base)
#elif (SIZEOF_OFF_T == SIZEOF_LONG_LONG_INT)
#define OFF_T_FMT "%lld"
#define strtoofft(nptr, endptr, base) strtoll(nptr, endptr, base)
#else
#error dont know what to use for OFF_T_FMT
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

    /* should we use the SQUAT engine to accelerate SEARCH? */
    SQUAT_ENGINE = 1,

    /* should we have long LMTP error messages? */
    LMTP_LONG_ERROR_MSGS = 1
};

#endif /* _CYRUS_IMAPD_CONFIG_H_ */
])

dnl make sure that Makefile is the last thing output
AC_CONFIG_FILES([
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
Cyrus Imapd configured components

   event notification: $enable_event_notification
   gssapi:             $gssapi
   autocreate:         $enable_autocreate
   idled:              $enable_idled
   http:               $enable_http
   kerberos V4:        $krb4
   murder:             $enable_murder
   nntpd:              $enable_nntp
   replication:        $enable_replication
   sieve:              $enable_sieve

External dependencies:
   ldap:               $have_ldap
   openssl:            $with_ssl
   pcre:               $cyrus_cv_pcre_utf8
   clamav:             $with_clamav

Database support:
   bdb:                $use_berkeley
   mysql:              $with_mysql
   postgresql:         $use_pgsql
   sqlite:             $use_sqlite
"

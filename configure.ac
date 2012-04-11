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
dnl $Id: configure.ac,v 1.316 2010/01/06 17:01:26 murch Exp $
dnl
dnl configure.ac for the Cyrus imapd
dnl


AC_INIT([cyrus-imapd], [2.5], [http://bugzilla.cyrusimap.org],,[http://www.cyrusimap.org])
AC_PREREQ([2.68])
AC_CONFIG_SRCDIR([imap/imapd.c])
AC_CONFIG_HEADERS(config.h)
AC_CANONICAL_SYSTEM

AM_INIT_AUTOMAKE([-Wall -Werror -Wno-portability foreign dist-bzip2 no-installinfo subdir-objects])
dnl 
AM_SILENT_RULES([yes])
AC_CONFIG_LIBOBJ_DIR([lib])
dnl Useful hook for distributions
AC_ARG_WITH(extraident,
        [AS_HELP_STRING([--with-extraident=STRING],[use STRING as extra version information])],
	[AC_DEFINE_UNQUOTED(EXTRA_IDENT,"$withval", [Extra version information for imap/version.h])])

srctoolsdir=`cd ${srcdir};pwd`/tools
AC_CHECK_PROG(MAKEDEPEND,makedepend,makedepend,[${srctoolsdir}/not-mkdep])
if test "$MAKEDEPEND" != "makedepend"; then
        AC_MSG_WARN([Makedepend is not installed on this system.  You should compile and install the version from the makedepend subdirectory.])
fi

dnl If we were using Automake, this would be AM_MAINTAINER_MODE
CMU_MAINTAINER_MODE

AC_ARG_WITH(login,,AC_ERROR([--with-login is no longer supported.
Configure SASL appropriately instead.]))

AC_ARG_WITH(cyrus-prefix,
	[AS_HELP_STRING([--with-cyrus-prefix=DIR], [use DIR as cyrus server install directory [PREFIX/cyrus]])],
	cyrus_prefix="$withval",cyrus_prefix="$prefix/cyrus")
AC_DEFINE_UNQUOTED(CYRUS_PATH,"$cyrus_prefix",[Where will we be installed?])
AC_ARG_WITH(service-path,
	[AS_HELP_STRING([--with-service-path=DIR], [use DIR as service install directory [PREFIX/cyrus/bin]])],
	servicedir="$withval",servicedir="$cyrus_prefix/bin")
AC_SUBST(servicedir)
AC_DEFINE_UNQUOTED(SERVICE_PATH,"$servicedir",[Directory to use for service binaries])
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
AC_PROG_RANLIB
AC_PROG_MAKE_SET
AC_PROG_INSTALL
AC_AIX
AC_ISC_POSIX
AC_PROG_AWK
AC_C_CONST
AC_SYS_LONG_FILE_NAMES
if test $ac_cv_sys_long_file_names = no; then
	AC_MSG_ERROR(The Cyrus IMAPD requires support for long file names)
fi
AC_C_INLINE

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

CMU_C___ATTRIBUTE__
CMU_C_FPIC

dnl check for -R, etc. switch
CMU_GUESS_RUNPATH_SWITCH

AC_CHECK_HEADERS(unistd.h sys/select.h sys/param.h stdarg.h)
AC_REPLACE_FUNCS(memmove strcasecmp ftruncate strerror)
AC_CHECK_FUNCS(strlcat strlcpy getgrouplist fmemopen pselect)
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
AC_SUBST(DEPLIBS)
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
    AC_ERROR([Berkeley DB 3.x or later was not found.  You may need to 
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
AC_ARG_WITH(mysql,
	[AS_HELP_STRING([--with-mysql=DIR], [use MySQL (in DIR) [no]])],
	with_mysql=$withval, with_mysql="no")

case "$with_mysql" in
  no)
	use_mysql="no"
	;;
  yes)
	use_mysql="yes"
	with_mysql_lib=none
	with_mysql_inc=none
	;;
  *)
	use_mysql="yes"
	with_mysql_lib="$with_mysql/lib"
	with_mysql_inc="$with_mysql/include"
	;;
esac

if test "$use_mysql" != "no"; then
  CYRUS_MYSQL_CHK()

  if test "$mysqllib" = "no"; then
    AC_ERROR([MySQL was not found.  You may need to supply the
    --with-mysql-libdir or --with-mysql-incdir configure options.])
  else
    HAVE_SQL=1
  fi

  if test "$with_mysql_lib" != "none"; then
    CMU_ADD_LIBPATH($with_mysql_lib)
  fi

  LIBS="${LIBS} ${MYSQL_LIBADD}"
  CPPFLAGS="${MYSQL_INCADD} ${CPPFLAGS}"

  AC_DEFINE(HAVE_MYSQL,[],[Build in MySQL support?])
fi

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
    AC_ERROR([PgSQL was not found.  You may need to supply the
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
    AC_ERROR([Sqlite was not found.  You may need to supply the
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
        [AS_HELP_STRING([--disable-sieve], [disable Sieve support])])
testpcre="yes"
AC_ARG_ENABLE(pcre,
	[AS_HELP_STRING([--disable-pcre], [disable PCRE library])],
	if test "$enableval" = no; then
		testpcre="no"
	fi)

if test "$enable_sieve" != "no"; then
	SIEVE_OBJS="lmtp_sieve.o smtpclient.o"
	AC_SUBST(SIEVE_OBJS)
	SIEVE_LIBS="../sieve/libsieve.a"
	AC_SUBST(SIEVE_LIBS)
	SIEVE_TESTSOURCES="sieve.c"
	AC_SUBST(SIEVE_TESTSOURCES)
	AC_DEFINE(USE_SIEVE,[],[Build in Sieve support?])

	dnl Sieve configure stuff
	AC_PROG_YACC
	AM_PROG_LEX

	if test "$testpcre" != "no"; then
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
	AC_CACHE_VAL(cyrus_cv_sys_psstrings, AC_TRY_CPP([
#include <machine/vmparam.h>
#include <sys/exec.h>
#ifndef PS_STRINGS
#include </nonexistent>
#endif],cyrus_cv_sys_psstrings=yes,cyrus_cv_sys_psstrings=no))
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
#include <sys/types.h>
#include <sys/mman.h>
#include <fcntl.h>
main() {
char *base;
int fd = open("conftestmmap", O_RDWR|O_CREAT|O_TRUNC, 0666);
if (fd == -1) exit(1);
if (write(fd, "test", 4) != 4) exit(1);
fsync(fd);
base = mmap((caddr_t)0, 100, PROT_READ, MAP_SHARED
#ifdef MAP_FILE
| MAP_FILE
#endif
#ifdef MAP_VARIABLE
| MAP_VARIABLE
#endif
, fd, 0L);
if (base == (caddr_t)-1) exit(1);
if (strncmp(base, "test", 4) != 0) exit(1);
if (write(fd, "test", 4) != 4) exit(1);
fsync(fd);
if (strncmp(base+4, "test", 4) != 0) exit(1);
exit(0);}
],cyrus_cv_func_mmap_shared=yes,cyrus_cv_func_mmap_shared=no,
cyrus_cv_func_mmap_shared=no))
AC_MSG_RESULT($cyrus_cv_func_mmap_shared)
if test $cyrus_cv_func_mmap_shared = yes; then
	found_map="shared"
else
AC_MSG_CHECKING(for stupid shared mmap)
AC_CACHE_VAL(cyrus_cv_func_mmap_stupidshared,AC_TRY_RUN([
#include <sys/types.h>
#include <sys/mman.h>
#include <fcntl.h>
main() {
char *base;
int fd = open("conftestmmap", O_RDWR|O_CREAT|O_TRUNC, 0666);
if (fd == -1) exit(1);
if (write(fd, "test", 4) != 4) exit(1);
fsync(fd);
base = mmap((caddr_t)0, 4, PROT_READ, MAP_SHARED
#ifdef MAP_FILE
| MAP_FILE
#endif
#ifdef MAP_VARIABLE
| MAP_VARIABLE
#endif
, fd, 0L);
if (base == (caddr_t)-1) exit(1);
if (strncmp(base, "test", 4) != 0) exit(1);
lseek(fd, 0L, 0);	
if (write(fd, "xyzz", 4) != 4) exit(1);
fsync(fd);
if (strncmp(base, "xyzz", 4) != 0) exit(1);
exit(0);}
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
				AC_ERROR(unable to detect locking method)
			      ])
		])
  ])
AM_CONDITIONAL([LOCK_FCNTL], [test $WITH_LOCK = "fcntl"])

dnl check for fdatasync (used by cyrusdb_skiplist)
LIB_RT=""
AC_CHECK_FUNC(fdatasync, AC_DEFINE(HAVE_FDATASYNC,[],[Do we have fdatasync()?]), [
  AC_CHECK_LIB(rt, fdatasync, [
	LIB_RT="-lrt"
	AC_DEFINE(HAVE_FDATASYNC,[],[Do we have fdatasync()?])
  ])
])

dnl check for libuuid (used when generating mailbox uniqueids)
LIB_UUID=
AC_CHECK_LIB(uuid, uuid_generate,[
    LIB_UUID="-luuid"
    AC_DEFINE(HAVE_LIBUUID,[],[Do we have the uuid library])
])

dnl for makedepend and AFS.
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

    CFLAGS="${CFLAGS} -I${with_afs_incdir}/include"
    AFS_LIBS="${with_afs_libdir}/afs/libkauth.a ${with_afs_libdir}/afs/libprot.a  ${with_afs_libdir}/afs/libauth.a ${with_afs_libdir}/afs/libsys.a ${with_afs_libdir}/librxkad.a ${with_afs_libdir}/librx.a ${with_afs_libdir}/afs/libsys.a ${with_afs_libdir}/libubik.a  ${with_afs_libdir}/liblwp.a ${with_afs_libdir}/afs/util.a ${with_afs_libdir}/afs/libcom_err.a"
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
        AC_MSG_WARN([Can't find a sigvec for AFS libraries which seem to need one.])
      else
        AFS_LIBS="${AFS_LIBS} $cyrus_cv_sigveclib"
        AC_SUBST(AFS_LIBS)
        AC_SUBST(AFS_LDFLAGS)
        AC_DEFINE(HAVE_AFSKRB,[],[Should we build afskrb pts module?])
      fi
    else
      AFS_LIBS="${AFS_LIBS}"
      AC_SUBST(AFS_LIBS)
      AC_SUBST(AFS_LDFLAGS)
      AC_DEFINE(HAVE_AFSKRB,[],[Should we build afskrb pts module?])
    fi
    LIBS="$SAVE_LIBS"
fi

LDAP_CPPFLAGS=""
LDAP_LDFLAGS=""
LDAP_LIBS=""

if test "x$with_ldap" != "xno"; then
    if test ! -d $with_ldap; then
        with_ldap=/usr/local
    fi

    LDAP_CPPFLAGS="$CPPFLAGS -I${with_ldap}/include"
    LDAP_LDFLAGS="$LDFLAGS -L${with_ldap}/lib"
    LDAP_LIBS=""

    save_CPPFLAGS=$CPPFLAGS
    save_LDFLAGS=$LDFLAGS
    CPPFLAGS=$LDAP_CPPFLAGS
    LDFLAGS=$LDAP_LDFLAGS

    AC_CHECK_LIB(ldap, ldap_initialize, 
        [ AC_DEFINE(HAVE_LDAP,[],[Should we build ldap pts module?])
          AC_SUBST(LDAP_CPPFLAGS)
          AC_SUBST(LDAP_LDFLAGS)
          AC_SUBST(LDAP_LIBS) 
          LDAP_LIBS="-lldap -llber" ],,-llber)

    CPPFLAGS=$save_CPPFLAGS
    LDFLAGS=$LDAP_LDFLAGS

    AC_CHECK_LIB(ldap, ldap_initialize, 
        [ AC_DEFINE(HAVE_LDAP,[],[Should we build ldap pts module?])
          AC_SUBST(LDAP_CPPFLAGS)
          AC_SUBST(LDAP_LDFLAGS)
          AC_SUBST(LDAP_LIBS) 
          LDAP_LIBS="-lldap -llber" ],,-llber)

    CPPFLAGS=$save_CPPFLAGS
    LDFLAGS=$save_LDFLAGS
fi
 
AM_CONDITIONAL([PTCLIENT], [test "x$enable_afs" = "xyes" -o "x$with_ldap" != "xno"])



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
    AC_WARN(No Kerberos V4 found); krb4=no)
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
IMAP_PROGS=""
AC_ARG_WITH(openssl,
	[AS_HELP_STRING([--with-openssl=DIR], [use OpenSSL from DIR])],
	with_openssl="${withval}")

OPENSSL_INC=
OPENSSL_LIB=
case "$with_openssl" in
	no) with_openssl="no";;
	""|yes) 
	  dnl if openssl has been compiled with the rsaref2 libraries,
	  dnl we need to include the rsaref libraries in the crypto check
                LIB_RSAREF=""
	        AC_CHECK_LIB(rsaref, RSAPublicEncrypt,
		       LIB_RSAREF="-lRSAglue -lrsaref"; cmu_have_rsaref=yes,
		       cmu_have_rsaref=no)

		with_openssl="yes"
		AC_CHECK_LIB(crypto,BIO_accept,
                                    LIBS="-lcrypto $LIB_RSAREF ${LIBS}",
		                    with_openssl="no", $LIB_RSAREF)
		AC_CHECK_LIB(ssl, SSL_CTX_new, LIBS="-lssl ${LIBS}",
		             with_openssl="no", -lcrypto $LIB_RSAREF)
		
		;;
	*)  OPENSSL_INC="-I${with_openssl}/include"
	    OPENSSL_LIBPATH="${with_openssl}/lib"
	    OPENSSL_LIB="-L${OPENSSL_LIBPATH}"
	    CPPFLAGS="${CPPFLAGS} ${OPENSSL_INC}"
	    CMU_ADD_LIBPATH(${OPENSSL_LIBPATH})
	    CMU_ADD_LIBPATH_TO(${OPENSSL_LIBPATH}, OPENSSL_LIB)
	    LIBS="${LIBS} -lssl -lcrypto";;
esac

AC_MSG_CHECKING(for openssl)
AC_MSG_RESULT($with_openssl)

if test "$with_openssl" != "no"; then
	AC_DEFINE(HAVE_SSL,[],[Build with SSL support?])
	IMAP_PROGS="$IMAP_PROGS tls_prune"
        if test "${krb4}" != no; then
           AC_DEFINE(OPENSSL_ENABLE_OLD_DES_SUPPORT,[],[Configure OpenSSL to provide legacy des apis])
           AC_DEFINE(OPENSSL_DES_LIBDES_COMPATIBILITY,[],[Configure OpenSSL to provide krb4-compatible legacy des apis])
        fi
fi
AC_SUBST(OPENSSL_INC)
AC_SUBST(OPENSSL_LIB)

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
ZEPHYR_CPPFLAGS=""
case "$with_zephyr" in
	no) true;;
	""|yes) AC_CHECK_LIB(zephyr,ZInitialize,ZEPHYR_LIBS="-lzephyr",
		with_zephyr="no",);;
       *)  if test -d ${with_zephyr}/include/zephyr; then
               ZEPHYR_CPPFLAGS="-I${with_zephyr}/include/zephyr"
           else
               ZEPHYR_CPPFLAGS="-I${with_zephyr}/include"
           fi
           ZEPHYR_LIBS="-lzephyr";;
esac
AC_SUBST(ZEPHYR_LIBS)
AC_SUBST(ZEPHYR_CPPFLAGS)
if test "$with_zephyr" != "no"; then
	AC_DEFINE(HAVE_ZEPHYR,[],[Build with Zephyr support?])
fi

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
dnl see if we're compiling with IMAP idled support
dnl
AC_ARG_ENABLE(idled,
        [AS_HELP_STRING([--enable-idled], [enable IMAP idled support])],
        if test "$enable_val" != no; then
	  IMAP_PROGS="$IMAP_PROGS idled"
        fi) 

dnl
dnl see if we're compiling with NNTP support
dnl
ENABLE_NNTP=no
AC_ARG_ENABLE(nntp,
        [AS_HELP_STRING([--enable-nntp], [enable NNTP support])],
	ENABLE_NNTP=$enableval
        if test "$ENABLE_NNTP" != no; then
	  IMAP_PROGS="$IMAP_PROGS nntpd fetchnews"
        fi) 

dnl
dnl see if we're compiling the Murder support programs
dnl
ENABLE_MURDER=no
AC_ARG_ENABLE(murder,
        [AS_HELP_STRING([--enable-murder], [enable IMAP Murder support])],
	ENABLE_MURDER=$enableval)

if test "$ENABLE_MURDER" != no; then
	IMAP_PROGS="$IMAP_PROGS mupdate"
	# for master/slave auto-selection
	AC_CHECK_HEADERS(sys/sockio.h)
fi

dnl
dnl see if we're compiling replication support programs
dnl
ENABLE_REPLICATION=no
AC_ARG_ENABLE(replication,
        [AS_HELP_STRING([--enable-replication], [enable replication support (experimental)])],
	ENABLE_REPLICATION=$enableval
        if test "$ENABLE_REPLICATION" != no; then
	  IMAP_PROGS="$IMAP_PROGS sync_client sync_server sync_reset"
        fi) 

AC_SUBST(IMAP_PROGS)

dnl
dnl Try and find a system version of com_err.
dnl If we see something that looks a little wacky, ignore it (there are many
dnl deficient installs of com_err, unfortunately, which leave out compile_et)
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
		  [AC_CHECK_HEADER(com_err.h,[],[AC_ERROR([cannot locate com_err.h])])])
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

case "$with_com_err" in
  # built-in et
  yes) # use the com_err we're gonna build
	  COM_ERR_LIBS="com_err/et/libcom_err.a"
	  COMPILE_ET="com_err/et/compile_et"
	  COM_ERR_CPPFLAGS="-I\${top_srcdir}/com_err/et"
	  ;;
  "")   # no problem, we already have it in the paths
	# we do nothing to pick it up
	COM_ERR_LIBS="-lcom_err" # hope it's not shared
	# we already set COMPILE_ET, or we didn't get here
	COM_ERR_CPPFLAGS=""
      ;;
  *) # use whatever they told us, or whatever we found
     COMPILE_ET="${with_com_err}/bin/compile_et"
     COM_ERR_LIBS="${with_com_err}/lib/libcom_err.a"
     COM_ERR_CPPFLAGS="-I${with_com_err}/include"
     # Ever get the feeling people hide this stuff on purpose?
     if test -d "${with_com_err}/include/et" ; then
       COM_ERR_CPPFLAGS="-I${with_com_err}/include/et"
     fi
dnl     CMU_ADD_LIBPATH_TO(${with_com_err}/lib, COM_ERR_LDFLAGS)
     COMPILE_ET="${with_com_err}/bin/compile_et"
esac
AM_CONDITIONAL([COM_ERR], [test "$with_com_err" = "yes"])
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
if test $cyrus_cv_lib_syslog = no; then
	DEPLIBS="${DEPLIBS} ../syslog/libsyslog.a"
	CPPFLAGS="$CPPFLAGS -I\$(srcdir)/../syslog"
fi
AM_CONDITIONAL([SYSLOG], [test "$cyrus_cv_lib_syslog" = "no"])
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

AC_CHECK_FUNC(dlopen,,[AC_CHECK_LIB(dl, dlopen)])
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
if test "$with_perl" = "notfound"; then
    AC_MSG_WARN(Perl not found: Administrative tools will not be available)
elif test "${with_perl}" != "no"; then
dnl compile perl stuff and perl/cyradm
    PERL_SUBDIRS="imap"
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

dnl for timsieved
if test "$enable_sieve" != "no"; then
	PERL_SUBDIRS="${PERL_SUBDIRS} sieve"
	PERL_DEPSUBDIRS="sieve"
else
	PERL_DEPSUBDIRS="none"
fi

dnl for the Cyrus annotator daemon class
PERL_SUBDIRS="${PERL_SUBDIRS} annotator"

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

IMAP_LIBS="${LIB_SASL} ${LIBS}"

AC_SUBST(LIB_RT)
AC_SUBST(LIB_UUID)
AC_SUBST(IMAP_LIBS)

dnl AC_OUTPUT_COMMANDS([
dnl   if test "$with_perl" != "no"; then
dnl     (cd perl/sieve/managesieve; $perl Makefile.PL PREFIX=$prefix)
dnl     (cd perl/imap; $perl Makefile.PL PREFIX=$prefix)
dnl   fi
dnl ], perl=$PERL; with_perl=$with_perl; prefix=$prefix; SASL_LIB="$LIB_SASL"; SASL_INC="$SASLFLAGS"; export SASL_LIB SASL_INC)
AC_SUBST(PERL_SUBDIRS)
AC_SUBST(PERL_DEPSUBDIRS)
AC_SUBST(PERL)

dnl
dnl Enable/disable unit tests.  These are disabled by default, as
dnl they require an additional library (the CUnit library).
dnl
AC_ARG_ENABLE(unit-tests,
        [AS_HELP_STRING([--enable-unit-tests], [enable CUnit-based unit regression tests])])

dnl Unit tests need the CUnit library, so check if we
dnl have both the header and the library.
if test "$enable_unit_tests" != "no" ; then
    AC_CHECK_LIB(cunit,CU_initialize_registry,found_lib=yes,found_lib=no)
    AC_CHECK_HEADER([CUnit/CUnit.h],found_hdr=yes,found_hdr=no)
    if test "$found_lib$found_hdr" != "yesyes" ; then
	AC_MSG_NOTICE([Disabling unit tests because the required CUnit library is not installed])
	enable_unit_tests=no
    fi
fi
if test "$enable_unit_tests" != "no" ; then
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
fi

AM_CONDITIONAL([CUNIT], [test "$enable_unit_tests" != "no"])

AH_TOP([
/*
 * Copyright (c) 1994-2008 Carnegie Mellon University.  All rights reserved.
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
 *
 * $Id: configure.ac,v 1.316 2010/01/06 17:01:26 murch Exp $
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

#ifndef HAVE___ATTRIBUTE__
/* Can't use attributes... */
#define __attribute__(foo)
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

#ifndef HAVE_SS_FAMILY
#define ss_family	__ss_family
#endif

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
AC_CONFIG_FILES([cunit/Makefile depot/Makefile imap/Makefile imtest/Makefile notifyd/Makefile perl/Makefile perl/sieve/Makefile ptclient/Makefile syslog/Makefile timsieved/Makefile Makefile])
AC_OUTPUT

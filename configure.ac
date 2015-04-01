#######################################################################
# And so it begins...
#######################################################################

AC_INIT([cyrus-imapd], [3.0], [https://git.cyrus.foundation/maniphest/task/create/],,[http://www.cyrus.foundation/])
AC_PREREQ([2.69])
PACKAGE_COPYRIGHT='Copyright (c) 1994-2008 Carnegie Mellon University.  All rights reserved.'
AC_COPYRIGHT([$PACKAGE_COPYRIGHT])

AS_ECHO()
AS_ECHO("$PACKAGE_STRING")
AS_ECHO("$PACKAGE_COPYRIGHT")
AS_ECHO()

dnl AC_PREFIX_DEFAULT([/usr/local/cyrus])

dnl
dnl AC_INIT sets ac_default_prefix=value and prefix=NONE. --prefix will
dnl set prefix, but the default is not applied until AC_OUTPUT.  So we
dnl need a working copy for AC_DEFINE and any other uses between here
dnl and AC_OUTPUT
dnl
AS_IF([test "$prefix" = 'NONE'],[
	prefix_copy="$ac_default_prefix"
],[
	prefix_copy="$prefix"
])
AC_SUBST(prefix_copy)

AC_CONFIG_SRCDIR([imap/imapd.c])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_LIBOBJ_DIR([lib])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_FILES([
	libcyrus.pc
	libcyrus_min.pc
	libcyrus_sieve.pc
	Makefile
])
AC_CANONICAL_TARGET

AM_INIT_AUTOMAKE([-Wall -Werror -Wno-portability foreign dist-bzip2 no-define no-installinfo subdir-objects])

#######################################################################
# Check build environemnt.
#######################################################################

dnl Want the generic OS name without version info.
AC_MSG_CHECKING([Platform])
AS_CASE([$target_os],
[netbsd*],[
	dnl Installed packages found under /usr/pkg.
	CPPFLAGS="-I/usr/pkg/include $CPPFLAGS"
	LDFLAGS="-L/usr/pkg/lib $LDFLAGS"
],[
	dnl Generic assumption about extra local software.
	CPPFLAGS="-I/usr/local/include $CPPFLAGS"
	LDFLAGS="-L/usr/local/lib $LDFLAGS"
])
AC_MSG_RESULT([$target_os "$CPPFLAGS" "$LDFLAGS"])

#######################################################################
# Package configuration.  All are required for standard build.
#######################################################################

SNERT_OPTION_ENABLE_DEBUG
AC_ARG_ENABLE(cyrus-user,[AS_HELP_STRING([--with-cyrus-user=USERID],[use USERID cyrus userid])],[],[enable_cyrus_user="cyrus"])
AC_ARG_ENABLE(cyrus-group,[AS_HELP_STRING([--with-cyrus-group=GROUPID],[use GROUPID cyrus group])],[],[enable_cyrus_group="mail"])
AC_ARG_ENABLE(afs,[AS_HELP_STRING([--disable-afs],[disable AFS with ptloader])],[],[enable_afs="yes"])
AC_ARG_ENABLE(krb5afspts,[AS_HELP_STRING([--disable-krb5afspts],[disable afskrb PTS module with krb5 support])],[],[enable_krb5afspts="yes"])
AC_ARG_ENABLE(event-notification,[AS_HELP_STRING([--disable-event-notification], [disable compiling of mailbox event notification (needs jansson library)])],[],[enable_event_notification="yes"])
CYRUS_OPTION_ENABLE_GSSAPI
AC_ARG_ENABLE(http,[AS_HELP_STRING([--disable-http],[disable HTTP support])],[],[enable_http="yes"])
AC_ARG_ENABLE(lock,[AS_HELP_STRING([--enable-lock=METHOD],[force use of METHOD for locking (flock or fcntl)])],,[enable_lock='fcntl'])
AC_ARG_ENABLE(mmap,[AS_HELP_STRING([--enable-mmap=TYPE],[force shared / stupidshared / nommap; JUST FOR TESTING])],,[enable_mmap='auto'])
AC_ARG_ENABLE(syslog-facility,[AS_HELP_STRING([--enable-syslog-facility=FACILITY], [the syslog facility to use (default LOCAL6)])],[],[enable_syslog_facility="LOG_LOCAL6"])

dnl AC_ARG_ENABLE(murder,[AS_HELP_STRING([--disable-murder], [disable IMAP Murder support])],[],[enable_murder="yes";])
dnl AC_ARG_ENABLE(nntp,[AS_HELP_STRING([--disable-nntp],[disable NNTP support])],[],[enable_nntp="yes"])
dnl AC_ARG_ENABLE(replication,[AS_HELP_STRING([--disable-replication], [disable replication support])],[],[enable_replication="yes";])
dnl AC_ARG_ENABLE(server,[AS_HELP_STRING([--disable-server], [disable compiling servers])],[],[enable_server="yes"])
dnl AC_ARG_ENABLE(sieve,[AS_HELP_STRING([--disable-sieve],[disable Sieve support])],[],[enable_sieve="yes"])
dnl AC_ARG_ENABLE(pcre, [AS_HELP_STRING([--disable-pcre],[disable PCRE library])])

#######################################################################
# Optional third party packages.
#######################################################################

CYRUS_OPTION_WITH_CLAMAV
AC_ARG_WITH(libcap,[AS_HELP_STRING([--with-libcap],[Enable libcap system capabilities handling (Linux systems only)])])
CYRUS_OPTION_WITH_COM_ERR
CYRUS_OPTION_WITH_CUNIT
AC_ARG_WITH(egd-socket,[AC_HELP_STRING([--with-egd-socket=FILE], [Entropy Gathering Daemon socket pathname for systems without /dev/urandom])],[
	AC_DEFINE_UNQUOTED(EGD_SOCKET, "$with_egd_socket", [Alternative to /dev/urandom?])
])

CYRUS_OPTION_WITH_GSSAPI

AC_ARG_WITH(ldap,[AS_HELP_STRING([--with-ldap=DIR],[LDAP support])],,[with_ldap='yes'])

CYRUS_OPTION_WITH_JANSSON
CYRUS_OPTION_WITH_KERBEROS
CYRUS_OPTION_WITH_OPENAFS
CYRUS_OPTION_WITH_OPENLDAP
CYRUS_OPTION_WITH_OPENDKIM
SNERT_OPTION_WITH_OPENSSL

AC_ARG_WITH([perl],[AS_HELP_STRING([--with-perl=PROG],[absolute program path for perl])],[
	dnl Override detected system perl.
	PERL="$with_perl"
],[
	with_perl='yes'
])
AC_ARG_WITH(pid-file,[AS_HELP_STRING([--with-pid-file=DIR],[pidfile in DIR [/var/run/cyrus-master.pid]])],[],[with_pid_file="$withval"])

SNERT_OPTION_WITH_SASL2
SNERT_OPTION_WITH_SQLITE3
CYRUS_OPTION_WITH_ZEPHYR
SNERT_OPTION_WITH_ZLIB

#######################################################################
# Compiler and common headers.
#######################################################################

AS_ECHO()
AS_ECHO("Checking C compiler and common headers...")
AS_ECHO()
SNERT_CC_INFO

dnl AC_HEADER_ASSERT
AC_C_CONST
AC_C_INLINE
AC_ISC_POSIX

AC_SYS_LONG_FILE_NAMES
AS_IF([test "$HAVE_LONG_FILE_NAMES" = 'no'],[
	AC_MSG_ERROR(The Cyrus IMAPD requires support for long file names)
])

dnl Check the size of various types
AC_CHECK_SIZEOF(int)
AC_CHECK_SIZEOF(long)
AC_CHECK_SIZEOF(size_t)
AC_CHECK_SIZEOF(off_t)

dnl Check that `long long int' is available
AC_CHECK_SIZEOF(long long int)
AC_CHECK_SIZEOF(unsigned long long int)
AS_IF([test "$ac_cv_sizeof_long_long_int" -eq 8 -a "$ac_cv_sizeof_unsigned_long_long_int" -eq 8],[
	AC_C_BIGENDIAN
],[
	AC_MSG_ERROR(The Cyrus IMAPD requires support for long long int)
])

dnl AC_CHECK_TYPES([mode_t, off_t, pid_t, uid_t, gid_t, size_t, ssize_t, time_t, intptr_t, uintptr_t])

gl_VISIBILITY
AH_BOTTOM([
#if HAVE_VISIBILITY
# define EXPORTED __attribute__((__visibility__("default")))
# define HIDDEN   __attribute__((__visibility__("hidden")))
#else
# define EXPORTED
# define HIDDEN
#endif
])

#######################################################################
# Check for programs.
#######################################################################

AS_ECHO()
AS_ECHO("Checking for assorted tools...")
AS_ECHO()
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_PROG_INSTALL
AC_PROG_YACC
AC_PROG_LEX
AC_PATH_PROGS([MD5SUM],[md5sum md5])

AC_PATH_PROGS([BASH],[bash],[false])
AS_IF([test "$BASH" != '/bin/bash'],[
	AC_MSG_WARN([Some shell scripts assume [#]!/bin/bash.])
])

AS_IF([test "$with_perl" = 'yes'],[
	AC_PATH_PROGS([PERL],[perl],[false])
	dnl Update the option to reflect the found Perl.
	AS_IF([test "$PERL" = 'false'],[
		with_perl='no'
	],[
		with_perl="$PERL"
	])
	AS_IF([test "$PERL" != '/usr/bin/perl'],[
		AC_MSG_WARN([The Perl administration scripts assume [#]!/usr/bin/perl.])
	])
])

LT_PREREQ([2.2.6])
LT_INIT([disable-static])
AC_SUBST([LIBTOOL_DEPS])

#######################################################################
# API tests, headers, libraries, and functions.
#######################################################################

dnl
dnl Standard library functions generate HAVE_function=1.  Some,
dnl networking, may generate CPPFLAGS_name, LDFLAGS_name, and LIBS_name
dnl on some systems, like Solaris, that use separate libraries for some
dnl facilities.  See acsite.m4.
dnl
SNERT_ANSI_STRING
SNERT_EXTRA_STRING
SNERT_ANSI_TIME
SNERT_SYS
SNERT_POSIX_IO
SNERT_FILE_LOCKS
CYRUS_MMAP
SNERT_NETWORK
SNERT_PROCESS
CYRUS_SIGVEC

dnl
dnl Packages generate CPPFLAGS_name, LDFLAGS_name, and LIBS_name;
dnl they accept --with-NAME, --with-NAME-inc, and --with-NAME-lib.
dnl See acsite.m4.
dnl
CYRUS_CAP
CYRUS_CLAMAV
CYRUS_COM_ERR
CYRUS_CUNIT
CYRUS_GSSAPI
CYRUS_ICAL
CYRUS_ICU
CYRUS_JANSSON
CYRUS_KERBEROS
CYRUS_XML2
CYRUS_OPENAFS
CYRUS_OPENDKIM
CYRUS_OPENLDAP
SNERT_OPENSSL
SNERT_PCRE
SNERT_REGEX
SNERT_SASL2
SNERT_SQLITE3
CYRUS_ZEPHYR
SNERT_ZLIB

AS_ECHO()
AS_ECHO('Checking for other stuff...')
AS_ECHO()

AC_CHECK_HEADERS(sys/sockio.h)
AC_REPLACE_FUNCS([memmove strcasecmp ftruncate strerror posix_fadvise strsep memmem])
AC_CHECK_FUNCS([getgrouplist fmemopen pselect getpassphrase])

dnl check for fdatasync (used by cyrusdb_skiplist)
AC_SEARCH_LIBS([fdatasync],[rt],[
	AS_IF([expr "$ac_cv_search_fdatasync" : '-l' >/dev/null],[
		LIB_RT="$ac_cv_search_fdatasync"
		AC_SUBST(LIB_RT)
	])
])

dnl check for libuuid (used when generating mailbox uniqueids)
AC_SEARCH_LIBS([uuid_generate],[uuid],[
	AS_IF([expr "$ac_cv_search_uuid_generate" : '-l' >/dev/null],[
		LIB_UUID="$ac_cv_search_uuid_generate"
		AC_SUBST(LIB_UUID)
	])
])

AC_CHECK_FUNC([setproctitle],[
	spt_type=SPT_BUILTIN
],[
	AC_CHECK_LIB([util],[setproctitle],[
		spt_type=SPT_BUILTIN
		LIBS="$LIBS -lutil"
	],[
		AC_CHECK_HEADERS([sys/pstat.h],[spt_type=SPT_PSTAT])
		AC_CHECK_HEADERS([sys/sysnews.h],[spt_type=SPT_SYSMIPS])
	])
])
AC_DEFINE_UNQUOTED(SPT_TYPE,$spt_type,[Do we already have setproctitle?])

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

#######################################################################
# Apply --enable and --with configuration options.
#######################################################################

AS_IF([test "$with_openssl" = 'no'],[
	AC_MSG_ERROR([OpenSSL is required for correct functionality.])
])
AC_DEFINE([HAVE_SSL],[1],[Build with SSL support?])

AS_IF([test "$with_krb" != 'no'],[
	AC_DEFINE(OPENSSL_ENABLE_OLD_DES_SUPPORT,[],[Configure OpenSSL to provide legacy des apis])
	AC_DEFINE(OPENSSL_DES_LIBDES_COMPATIBILITY,[],[Configure OpenSSL to provide krb4-compatible legacy des apis])
])

AS_IF([test "$with_sqlite3" = 'no'],[
	AC_MSG_ERROR([SQLite is a required package.])
])

AS_IF([test -e "$PERL"],[
	dnl Add perl cccdlflags when building libraries.  This ensures
	dnl that the libraries will be compiled as PIC, if perl requires
	dnl PIC objects.  This is needed on *BSD and Linux, but seems to
	dnl cause problems on at least Solaris.
	dnl
	dnl PERL_CCCDLFLAGS will be undefined or empty, if no cccdlflags.
	AC_MSG_CHECKING([for Perl cccdlflags needed on "${target_os}"])
	eval `${PERL} -V:cccdlflags`
	PERL_CCCDLFLAGS="$cccdlflags"
	AC_SUBST(PERL_CCCDLFLAGS)
	AC_MSG_RESULT($PERL_CCCDLFLAGS)

	dnl This is not the ideal way to make the substitution in
	dnl perl/imap/Makefile.PL.in.
	here=`pwd`
	PERL_PREINSTALL="${PERL} ${here}/tools/fixsearchpath.pl ${prefix_copy} ${bindir}"
	AC_SUBST(PERL_PREINSTALL)
],[
	AC_MSG_WARN(Perl not found, administrative tools will not be available.)
])
AC_SUBST(PERL)

dnl AS_IF([test "$enable_sieve" != "no"],[
	AC_DEFINE(USE_SIEVE,[],[Build in Sieve support?])

	dnl Tools needed to build Sieve.
	dnl AC_PROG_YACC
	AM_PROG_LEX

	dnl Yet another Regex API.
	AC_CHECK_HEADERS([rxposix.h],[
		AC_SEARCH_LIBS([regcomp],[rx])
		AC_CHECK_FUNCS([regcomp regexec regerror regfree])
	])

	AS_IF([test "$ac_cv_search_regcomp" != 'no'],[
		AC_DEFINE(ENABLE_REGEX, [], [Do we have a regex library?])
	],[
		AC_MSG_ERROR([No POSIX API compatible regular expression library for Sieve.])
	])
dnl ])

AS_IF([test "$enable_afs" != 'no' -a "$snert_find_file_afs_libkauth" != 'no'],[
	AS_IF([test "$enable_krb5afspts" = "yes"], [
		AC_DEFINE(AFSPTS_USE_KRB5,[],[Should the AFS PTS plugin use krb5?])
		AC_CHECK_LIB([krb5],[krb5_init_context])
	])

	dnl Does AFS need sigvec?  We have to link against lwp and see
	dnl if IOMGR_Initialize wants it.
	AC_CACHE_VAL([cyrus_cv_afs_sigvec],[
		save_LIBS="$LIBS"
		AS_IF([test "$snert_find_file_libafslwp_a" != 'no'],[
			LIBS="$snert_find_file_libafslwp_a $LIBS"
		])
		AS_IF([test "$snert_find_file_liblwp_a" != 'no'],[
			LIBS="$snert_find_file_liblwp_a $LIBS"
		])
		AC_CHECK_FUNCS([IOMGR_Initialize],[
			dnl it linked; don't need it
			cyrus_cv_afs_sigvec="no"
		],[
			dnl didn't link; pick up sigvec
			cyrus_cv_afs_sigvec="yes"
		])
		LIBS="$save_LIBS"
	])
	AC_MSG_CHECKING(if AFS libraries need sigvec)
	AC_MSG_RESULT($cyrus_cv_afs_sigvec)

	AS_IF([test "$cyrus_cv_afs_sigvec" = 'yes'],[
		AS_IF([test "$ac_cv_search_sigvec" = 'no'],[
			AC_MSG_WARN([Can not find a sigvec for AFS libraries, which seem to need one.])
		],[
			LIBS_AFS="${LIBS_AFS} $ac_cv_search_sigvec"
			AC_DEFINE(HAVE_AFSKRB,[],[Should we build afskrb pts module?])
		])
	],[
		AC_DEFINE(HAVE_AFSKRB,[],[Should we build afskrb pts module?])
	])

	AC_SUBST(AFS_LIBS, $LIBS_AFS)
])

AS_IF([test "$ac_cv_func_cl_init" != "no"],[
	AC_DEFINE(HAVE_CLAMAV,[],[Do we have ClamAV?])
	AC_SUBST(LIB_CLAMAV, LIBS_CLAMAV)
])

AS_IF([test "${with_com_err}" = "no"],[
	AC_MSG_WARN([com_err is required, included version will be used.])
	with_com_err="yes"
])
AS_IF([test "${COMPILE_ET}" = "false"],[
	AC_MSG_WARN([Parts of com_err distribuion were found, but not compile_et.])
	AC_MSG_WARN([Will build com_err from included sources.])
	dnl build it ourselves
	with_com_err="yes"
])
dnl Set up $COMPILE_ET first, we need to test it
AS_CASE(["$with_com_err"],
[yes],[
	dnl built-in et
	dnl use the com_err we're gonna build
	CPPFLAGS_COM_ERR="-I\${top_srcdir}/com_err/et"
	LDFLAGS_COM_ERR=''
	LIBS_COM_ERR="com_err/et/libcyrus_com_err.la"
	COMPILE_ET="\${abs_top_builddir}/com_err/et/compile_et"
],[
	dnl We already have it in the paths. Hope its not shared.
])
AS_IF([test "$with_com_err" != 'yes'],[
	AC_MSG_CHECKING([if compile_et produces correct code])

	dnl Test that the specified compile_et produces correct output
	dnl See bug #3711 for why this is necessary
	TEST1="compile_et-test"
	/bin/rm -f $TEST1.et $TEST1.h $TEST1.c
	echo "error_table imap" >> $TEST1.et
	echo "ec IMAP_TESTING," >> $TEST1.et
	echo "   \"Testing\"" >> $TEST1.et
	echo "end" >> $TEST1.et
	"${COMPILE_ET}" $TEST1.et > /dev/null

	compile_et_ok='no'
	AS_IF([test -f $TEST1.h],[
		AS_IF([test `awk '/IMAP_TESTING/{print $3}' $TEST1.h 2>/dev/null` = "-1904809472"],[
			compile_et_ok=yes
		])
		dnl Broken compile_et produces (2390157824L)
	])
	/bin/rm -f $TEST1.et $TEST1.h $TEST1.c
	AC_MSG_RESULT($compile_et_ok)

	AS_IF([test "$compile_et_ok" = 'no'],[
		dnl revert to the built-in compile_et
		AC_MSG_WARN([It seems $COMPILE_ET is buggy, building our own])
		CPPFLAGS_COM_ERR="-I\${top_srcdir}/com_err/et"
		LDFLAGS_COM_ERR=''
		LIBS_COM_ERR="com_err/et/libcyrus_com_err.la"
		COMPILE_ET="\${abs_top_builddir}/com_err/et/compile_et"
		with_com_err='yes'
	])
])

AS_IF([test "$ac_cv_header_jansson_h" = 'yes'],[
	AC_MSG_CHECKING([jansson version])
	HDR_DIR=`echo "$CPPFLAGS_JANSSON" | sed -e's/-I//'`
	JANSSON_MAJOR=`sed -n -e's/#define JANSSON_MAJOR_VERSION.*\([0-9][0-9]*\)/\1/p' $HDR_DIR/jansson.h`
	JANSSON_MINOR=`sed -n -e's/#define JANSSON_MINOR_VERSION.*\([0-9][0-9]*\)/\1/p' $HDR_DIR/jansson.h`
	JANSSON_MICRO=`sed -n -e's/#define JANSSON_MICRO_VERSION.*\([0-9][0-9]*\)/\1/p' $HDR_DIR/jansson.h`
	AC_MSG_RESULT([${JANSSON_MAJOR}.${JANSSON_MINOR}.${JANSSON_MICRO}])

	AS_IF([test "$JANSSON_MAJOR" -ge 2 -a "$JANSSON_MINOR" -ge 0],[
		AC_DEFINE([ENABLE_MBOXEVENT],[1],[Build with support of mailbox event notification])
	],[
		AC_MSG_WARN([jansson 2.0 or later was not found, but is required to enable mailbox event notification])
		enable_event_notification="no"
	])
])

AS_IF([test "$enable_http" = 'yes'],[
	AS_IF([test X"$LIBS_ICAL" = X],[
		AC_MSG_ERROR([libical required for HTTP support.])
	])
	AS_IF([test X"$LIBS_XML2" = X],[
		AC_MSG_ERROR([libxml2 required for HTTP support.])
	])
	AS_IF([test X"$LIBS_JANSSON" = X],[
		AC_MSG_ERROR([Janssson library required for HTTP support.])
	])
	AS_IF([test X"$LIBS_SQLITE3" = X],[
		AC_MSG_ERROR([SQLite3 required for HTTP support.])
	])

	SNERT_JOIN_UNIQ([HTTP_LIBS],[$LIBS_XML2 $LIBS_ICAL $LIBS_SQLITE3 $LIBS_JANSSON])
	SNERT_JOIN_UNIQ([HTTP_LDFLAGS],[$LDFLAGS_XML2 $LDFLAGS_ICAL $LDFLAGS_SQLITE3 $LDFLAGS_JANSSON])
	SNERT_JOIN_UNIQ([HTTP_CPPFLAGS],[$CPPFLAGS_XML2 $CPPFLAGS_ICAL $CPPFLAGS_SQLITE3 $CPPFLAGS_JANSSON])

	AC_DEFINE(HAVE_XML2,[1],[Build in libxml support?])
	AC_DEFINE(HAVE_ICAL,[1],[Build in ical support?])
	AC_DEFINE(HAVE_SQLITE3,[1],[Build in SQLite support?])

	AC_DEFINE(WITH_DAV,[1],[Build DAV support into httpd?])
	AC_DEFINE(WITH_JSON,[1],[Build jCal/jCard/TZdist support into httpd?])

	AC_CHECK_LIB([ical],[icaltimezone_set_builtin_tzdata],[
		AC_DEFINE(HAVE_TZ_BY_REF,[1],[Build TZ by ref support into httpd?])
	])
	AC_EGREP_HEADER(ICAL_TZUNTIL_PROPERTY, ical.h,[
		AC_DEFINE(HAVE_TZDIST_PROPS,[1],[Do we have built-in support for TZdist props?])
	])
	AC_EGREP_HEADER(ICAL_SCHEDULESTATUS_PARAMETER, ical.h,[
		AC_DEFINE(HAVE_SCHEDULING_PARAMS,[1],[Do we have built-in support for scheduling params?])
	])
	AC_EGREP_HEADER(ICAL_VAVAILABILITY_COMPONENT, ical.h,[
		AC_DEFINE(HAVE_VAVAILABILITY,[1], [Build VAVAILABILITY support into httpd?])
	])
	AC_EGREP_HEADER(ICAL_VPOLL_COMPONENT, ical.h,[
		AC_DEFINE(HAVE_VPOLL,[], [Build VPOLL support into httpd?])
	])
	AC_CHECK_LIB(ical, icalrecur_rscale_token_handling_is_supported,[
		AS_IF([test X"$LIBS_ICU" != X],[
			AC_DEFINE(HAVE_RSCALE,[1], [Build RSCALE support into httpd?])
		])
	])
	AS_IF([test X"$LIBS_DKIM" != X],[
		AC_DEFINE(WITH_DKIM,[1],[Build DKIM support into iSchedule?])
	])

	AC_SUBST(HTTP_CPPFLAGS)
	AC_SUBST(HTTP_LDFLAGS)
	AC_SUBST(HTTP_LIBS)
])

AS_IF([test "$enable_mmap" = 'auto' -a "$cyrus_cv_func_mmap_stupidshared" = 'yes'],[
	enable_mmap='stupidshared'
],[
	AC_MSG_WARN([*** This system does not have a working mmap().])
	AC_MSG_WARN([*** Expect a considerable performance penalty])
	enable_mmap='nomap'
])

HAVE_SQL='no'
AC_MSG_CHECKING([for at least one supported SQL package])
AS_IF([test -n "$LIBS_MYSQL" -o -n "$LIBS_PGSQL" -o -n "$LIBS_SQLITE3"],[
	AC_DEFINE(HAVE_SQL,[1],[Enable SQL support with one of the supported libraries.])
	HAVE_SQL='yes'
])
AC_MSG_RESULT($HAVE_SQL)

AC_DEFINE_UNQUOTED(CYRUS_USER, "$enable_cyrus_user",[What user will we run as?])
AC_DEFINE_UNQUOTED(CYRUS_GROUP, "$enable_cyrus_group",[What group will we run as?])
AC_SUBST(enable_cyrus_user)
AC_SUBST(enable_cyrus_group)

AC_SUBST(CPPFLAGS)
AC_SUBST(LOCALDEFS)

#######################################################################
# Mapping new variables to old configure.
#######################################################################

AC_DEFINE_UNQUOTED(CYRUS_PATH,"$prefix_copy",[Where will we be installed?])
AS_IF([test -n "$HAVE_STRERROR"],[AC_DEFINE_UNQUOTED(HAS_STRERROR, $HAVE_STRERROR, [Do we have strerror()?])])
AS_IF([test -n "$LIBS_CLAMAV"],[AC_DEFINE_UNQUOTED(HAVE_CLAMAV,"$LIBS_CLAMAV",[Do we have ClamAV?])])
AS_IF([test -n "$LIBS_LDAP"],[AC_DEFINE_UNQUOTED(HAVE_LDAP,"$LIBS_LDAP",[Should we build the LDAP pts module?])])
AS_IF([test -n "$LIBS_MYSQL"],[AC_DEFINE_UNQUOTED(HAVE_MYSQL,"$LIBS_MYSQL",[Build in MySQL support?])])
AS_IF([test -n "$LIBS_PGSQL"],[AC_DEFINE_UNQUOTED(HAVE_PGSQL,"$LIBS_PGSQL",[Build in PgSQL support?])])
AS_IF([test -n "$LIBS_SQLITE3"],[AC_DEFINE_UNQUOTED(HAVE_SQLITE,"$LIBS_SQLITE3",[Build in SQLite support?])])
AS_IF([test -n "$LIBS_ZEPHYR"],[AC_DEFINE_UNQUOTED(HAVE_ZEPHYR,"$LIBS_ZEPHYR",[Build with Zephyr support?])])
AS_IF([test -n "$LIBS_ZLIB"],[AC_DEFINE_UNQUOTED(HAVE_ZLIB, "$LIBS_ZLIB",[Do we have zlib?])])
AS_IF([test -n "$HAVE_SYS_ERRLIST"],[AC_DEFINE_UNQUOTED(NEED_SYS_ERRLIST, $HAVE_SYS_ERRLIST, [Do we have a sys_errlist?])])
AC_DEFINE_UNQUOTED(MASTER_PIDFILE, "$with_pid_file",[File path of the PID file for master])
AC_DEFINE_UNQUOTED(SERVICE_DIR,"$libexecdir",[Directory to use for service binaries])
AC_DEFINE_UNQUOTED(SYSCONFDIR, "$sysconfdir",[Config File Location])
AC_DEFINE_UNQUOTED(SYSLOG_FACILITY, $enable_syslog_facility, [Syslog facility to use.])

AC_SUBST(userdir,[$bindir])
AC_SUBST(servicedir,[$SERVICE_DIR])

dnl
dnl Berkeley DB has been dropped, but some substitions references
dnl haven't been removed and don't get replaced properly unless,
dnl declared leaving spurious at-signs (@).
dnl
AC_SUBST(BDB_INC)
AC_SUBST(BDB_LIB)

dnl --coverage has been dropped, but need the substitions to work.
AC_SUBST(COV_CFLAGS)
AC_SUBST(COV_LDFLAGS)

AC_SUBST(AFS_CFLAGS, $CPPFLAGS_AFS)
AC_SUBST(AFS_LDFLAGS, $LDFLAGS_AFS)
AC_SUBST(AFS_LIBS, $LIBS_AFS)

AC_SUBST(LIB_CLAMAV, $LIBS_CLAMAV)

AC_SUBST(COM_ERR_CFLAGS, $CPPFLAGS_COM_ERR)
AC_SUBST(COM_ERR_LDFLAGS, $LDFLAGS_COM_ERR)
AC_SUBST(COM_ERR_LIBS, $LIBS_COM_ERR)
AC_SUBST(PKG_CONFIG_COM_ERR_LIB, $LIBS_COM_ERR)

AC_SUBST(DKIM_CFLAGS, $CPPFLAGS_DKIM)
AC_SUBST(DKIM_LDFLAGS, $LDFLAGS_DKIM)
AC_SUBST(DKIM_LIBS, $LIBS_DKIM)

AC_SUBST(ICU_CFLAGS, $CPPFLAGS_ICU)
AC_SUBST(ICU_LDFLAGSS, $LDFLAGS_ICU)
AC_SUBST(ICU_LIBS, $LIBS_ICU)

AC_SUBST(LDAP_CFLAGS, $CPPFLAGS_LDAP)
AC_SUBST(LDAP_LDFLAGS, $LDFLAGS_LDAP)
AC_SUBST(LDAP_LIBS, $LIBS_LIBLDAP)

AC_SUBST([JANSSON_LIBS], $LIBS_JANSSON)
AC_SUBST([JANSSON_LDFLAGS], $LDFLAGS_JANSSON)
AC_SUBST([JANSSON_CFLAGS], $CPPFLAGS_JANSSON)

AC_SUBST(HAVE_KRB, $LIBS_KRB)

AC_SUBST(SASLFLAGS, $CPPFLAGS_SASL2)
AC_SUBST(LIB_SASL, $LIBS_SASL2)
AC_SUBST(LIB_DYN_SASL, $LIBS_SASL2)
AC_SUBST(DYNSASLFLAGS, $CPPFLAGS_SASL2)

AC_SUBST(SSL_CPPFLAGS, $CPPFLAGS_SSL)
AC_SUBST(SSL_LDFLAGS, $LDFLAGS_SSL)
AC_SUBST(SSL_LIBS, $LIBS_SSL)

AC_SUBST(ZEPHYR_LIBS, $LIBS_ZEPHYR)

AC_SUBST(ZLIB, $LIBS_ZLIB)

#######################################################################
# automake conditionals
#######################################################################

AM_CONDITIONAL([CMULOCAL],[false]) 	dnl replaced by acsite.m4
AM_CONDITIONAL([USE_BERKELEY],[false])	dnl Berkeley DB support removed.

dnl Always built in, controlled by imapd.conf or cyrus.conf.
AM_CONDITIONAL([AUTOCREATE], [true])
AM_CONDITIONAL([IDLED], [true])
AM_CONDITIONAL([MURDER],[true])
AM_CONDITIONAL([NNTPD],[true])
AM_CONDITIONAL([REPLICATION],[true])
AM_CONDITIONAL([SERVER],[true])
AM_CONDITIONAL([SIEVE],[true])

AM_CONDITIONAL([IPV6_noGETADDRINFO],[test "$ac_cv_func_getaddrinfo" = 'no'])
AM_CONDITIONAL([IPV6_noGETNAMEINFO],[test "$ac_cv_func_getnameinfo" = 'no'])
AM_CONDITIONAL([USE_SQL], [test "$HAVE_SQL" = 'yes'])
AM_CONDITIONAL([USE_AFSKRB], [test -n "$LIBS_AFS"])
AM_CONDITIONAL([HAVE_CLAMAV], [test "$ac_cv_func_cl_init" = "yes"])
AM_CONDITIONAL([COM_ERR], [test "$with_com_err" = "yes"])
AM_CONDITIONAL([CUNIT],[test "$with_cunit" != "no"])
AM_CONDITIONAL([GMTOFF_TM], [test "$ac_cv_member_struct_tm_tm_gmtoff" = 'yes'])
AM_CONDITIONAL([HTTPD], [test "$enable_http" != "no" -a "$ac_cv_header_jansson_h" = 'yes'])
AM_CONDITIONAL([JANSSON], [test "$enable_event_notification" != 'no' -a "$ac_cv_header_jansson_h" = 'yes'])
AM_CONDITIONAL([HAVE_LDAP], [test "$HAVE_LIBLDAP" = "yes"])
AM_CONDITIONAL([PTCLIENT], [test "$HAVE_LIBLDAP" = "yes" -a -n "$LIBS_AFS"])
AM_CONDITIONAL([LOCK_FCNTL], [test "$enable_lock" = "fcntl"])
AM_CONDITIONAL([NONBLOCK_FCNTL], [test "$ac_cv_define_FNDELAY" != "no"])
AM_CONDITIONAL([MAP_SHARED], [test "$with_map" = "shared"])
AM_CONDITIONAL([MAP_STUPIDSHARED], [test "$with_map" = "stupidshared"])
dnl AM_CONDITIONAL([MURDER], [test "$enable_murder" != "no"])
dnl AM_CONDITIONAL([NNTPD], [test "$enable_nntp" != "no"])
AM_CONDITIONAL([PERL], [test "$PERL" != 'false'])
dnl AM_CONDITIONAL([REPLICATION], [test "$enable_replication" != 'no'])
dnl AM_CONDITIONAL([SERVER], [test "$enable_server" != "no"])
dnl AM_CONDITIONAL([SIEVE], [test "$enable_sieve" != "no"])
AM_CONDITIONAL([HAVE_SSL], [test "$with_openssl" != "no"])
AM_CONDITIONAL([ZEPHYR], [test "$ac_cv_func_ZInitialize" != "no"])

#######################################################################
# Finally generate headers and makefiles.
#######################################################################

AH_TOP([
#ifndef _CYRUS_IMAPD_CONFIG_H_
#define _CYRUS_IMAPD_CONFIG_H_
])

AH_BOTTOM([
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

AS_ECHO()
AS_ECHO("Generating files...")
AS_ECHO()

CMU_PERL_MAKEMAKER(perl/annotator)
CMU_PERL_MAKEMAKER(perl/imap)
CMU_PERL_MAKEMAKER(perl/sieve/managesieve)

AC_OUTPUT()

AS_ECHO()
AS_ECHO("$PACKAGE_STRING")
AS_ECHO("$PACKAGE_COPYRIGHT")
AS_ECHO()
AC_MSG_RESULT([Install Locations])
AC_MSG_RESULT([  Platform............: $target_os $CC ${GCC_MAJOR} ${GCC_MINOR} ${GCC_PATCH}])
AC_MSG_RESULT([  prefix..............: $prefix])
AC_MSG_RESULT([  exec_prefix.........: $exec_prefix])
AC_MSG_RESULT([  bindir..............: $bindir])
AC_MSG_RESULT([  sbindir.............: $sbindir])
AC_MSG_RESULT([  libexecdir..........: $libexecdir])
AC_MSG_RESULT([  sysconfdir..........: $sysconfdir])
AC_MSG_RESULT([  localstatedir.......: $localstatedir])
AS_ECHO()
AC_MSG_RESULT([Configuration])
AC_MSG_RESULT([  CUnit...............: $with_cunit])
AC_MSG_RESULT([  User & Group........: $enable_cyrus_user:$enable_cyrus_group])
AC_MSG_RESULT([  Event notification..: $enable_event_notification])
AC_MSG_RESULT([  GSSAPI impl.........: $enable_gssapi])
AC_MSG_RESULT([  Http................: $enable_http])
AC_MSG_RESULT([  Kerberos 4 impl.....: $with_krb with DES $with_krb_des])
AC_MSG_RESULT([  Lock................: $enable_lock])
AC_MSG_RESULT([  Mmap................: $enable_mmap])
AC_MSG_RESULT([  pid file............: $with_pid_file])
dnl AC_MSG_RESULT([  Murder..............: $enable_murder])
dnl AC_MSG_RESULT([  Nntpd...............: $enable_nntp])
dnl AC_MSG_RESULT([  Replication.........: $enable_replication])
dnl AC_MSG_RESULT([  Sieve...............: $enable_sieve])
AC_MSG_RESULT([  syslog facility.....: $enable_syslog_facility])
AC_MSG_RESULT([  CFLAGS..............: $CFLAGS])
AC_MSG_RESULT([  CPPFLAGS............: $CPPFLAGS])
AC_MSG_RESULT([  LDFLAGS.............: $LDFLAGS])
AC_MSG_RESULT([  LIBS................: $LIBS])
AC_MSG_RESULT([  NETWORK_LIBS........: $NETWORK_LIBS])
AS_ECHO()
AC_MSG_RESULT([External Packages])
AC_MSG_RESULT([  ClamAV..............: "$CPPFLAGS_CLAMAV" "$LDFLAGS_CLAMAV" "$LIBS_CLAMAV"])
AC_MSG_RESULT([  com_err.............: "$CPPFLAGS_COM_ERR" "$LDFLAGS_COM_ERR" "$LIBS_COM_ERR" "$COMPILE_ET"])
AC_MSG_RESULT([  CUnit...............: "$CPPFLAGS_CUNIT" "$LDFLAGS_CUNIT" "$LIBS_CUNIT"])
AC_MSG_RESULT([  GSSAPI..............: "$CPPFLAGS_GSSAPI" "$LDFLAGS_GSSAPI" "$LIBS_GSSAPI"])
AC_MSG_RESULT([  Jansson.............: "$CPPFLAGS_JANSSON" "$LDFLAGS_JANSSON" "$LIBS_JANSSON"])
AC_MSG_RESULT([  Kerberos 4..........: "$CPPFLAGS_KRB" "$LDFLAGS_KRB" "$LIBS_KRB"])
AC_MSG_RESULT([  libical.............: "$CPPFLAGS_ICAL" "$LDFLAGS_ICAL" "$LIBS_ICAL"])
AC_MSG_RESULT([  libicu..............: "$CPPFLAGS_ICU" "$LDFLAGS_ICU" "$LIBS_ICU"])
AC_MSG_RESULT([  libxml2.............: "$CPPFLAGS_XML2" "$LDFLAGS_XML2" "$LIBS_XML2"])
AC_MSG_RESULT([  OpenAFS.............: "$CPPFLAGS_AFS" "$LDFLAGS_AFS" "$LIBS_AFS"])
AC_MSG_RESULT([  OpenDKIM............: "$CPPFLAGS_DKIM" "$LDFLAGS_DKIM" "$LIBS_DKIM"])
AC_MSG_RESULT([  OpenLDAP............: "$CPPFLAGS_LDAP" "$LDFLAGS_LDAP" "$LIBS_LDAP"])
AC_MSG_RESULT([  OpenSSL.............: "$CPPFLAGS_SSL" "$LDFLAGS_SSL" "$LIBS_SSL"])
AC_MSG_RESULT([  Perl................: "$with_perl"])
AC_MSG_RESULT([  SASL2...............: "$CPPFLAGS_SASL2" "$LDFLAGS_SASL2" "$LIBS_SASL2"])
AC_MSG_RESULT([  SQLite3.............: "$CPPFLAGS_SQLITE3" "$LDFLAGS_SQLITE3" "$LIBS_SQLITE3"])
AC_MSG_RESULT([  Zephyr..............: "$CPPFLAGS_ZEPHYR" "$LDFLAGS_ZEPHYR" "$LIBS_ZEPHYR"])
AC_MSG_RESULT([  zlib................: "$CPPFLAGS_ZLIB" "$LDFLAGS_ZLIB" "$LIBS_ZLIB"])
AS_ECHO()

#######################################################################
# -END-
#######################################################################

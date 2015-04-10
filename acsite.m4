#######################################################################
# autoconf support macros
#######################################################################

dnl
dnl SNERT_JOIN_UNIQ(var, word_list,[head|tail])
dnl
AC_DEFUN([SNERT_JOIN_UNIQ],[
	list=`eval echo \$$1`
	for w in $2; do
		dnl Look for the whole word in the list.
		AS_IF([expr " $list " : ".* $w " >/dev/null],[
			:
		],[
			AS_IF([test "$3" = 'head'],[
				list="$w${list:+ $list}"
			],[
				list="${list:+$list }$w"
			])
		])
	done
	eval $1="\"$list\""
])

dnl
dnl SNERT_CHECK_DEFINE(symbol[, header_file])
dnl
dnl Without a header_file, check for a predefined macro.
dnl
AC_DEFUN([SNERT_CHECK_DEFINE],[
	AC_LANG_PUSH([C])
	AC_CACHE_CHECK([for $1],ac_cv_define_$1,[
		AS_IF([test -z "$2"],[
			AC_RUN_IFELSE([
				AC_LANG_SOURCE([[
int main()
{
#ifdef $1
	return 0;
#else
	return 1;
#endif
}
				]])
			],[
				ac_cv_define_$1=yes
			],[
				ac_cv_define_$1=no
			])
		],[
			AC_RUN_IFELSE([
				AC_LANG_SOURCE([[
#include <$2>
int main()
{
#ifdef $1
	return 0;
#else
	return 1;
#endif
}
				]])
			],[
				ac_cv_define_$1=yes
			],[
				ac_cv_define_$1=no
			])
		])
	])
	AC_LANG_POP([C])
	AS_IF([test $ac_cv_define_$1 = 'yes'],[
		AC_DEFINE_UNQUOTED([HAVE_MACRO_]translit($1, [a-z], [A-Z]))
		AH_TEMPLATE([HAVE_MACRO_]translit($1, [a-z], [A-Z]))
	])
])

dnl
dnl SNERT_CHECK_PREDEFINE(symbol)
dnl
AC_DEFUN(SNERT_CHECK_PREDEFINE,[
	SNERT_CHECK_DEFINE($1)
])

dnl
dnl SNERT_IF_SYSTEM_DIR(word, if-system, not-system)
dnl
m4_define([SNERT_IF_SYSTEM_DIR],[
	AS_CASE([$1],[/usr/include|/usr/lib64|/usr/lib/x86_64-linux-gnu|/usr/lib|/lib64|/lib/x86_64-linux-gnu|/lib],[$2],[$3])
])

dnl
dnl SNERT_FIND_FILE(wild_file, directories, if-found, not-found)
dnl if-found can reference the found $dir_val
dnl
AC_DEFUN([SNERT_FIND_FILE],[
	AS_VAR_PUSHDEF([snert_dir], [snert_find_file_$1])
	AS_VAR_SET([snert_dir],'no')
	AC_MSG_CHECKING([for location of $1])

	dnl File to find specifies an extension?
	AS_IF([expr "$1" : '.*\.[[0-9a-zA-Z]]' >/dev/null],[
		dnl Has an extension.
		pattern="$1"
	],[
		dnl No extension, so look for any extension (.a and .so variants).
		dnl Without the dot (.) to mark the end of the name prefix
		dnl we can inadvertantly match libraries with similar prefixes,
		dnl ie. libz and libzephyr
		pattern="$1.*"
	])
	for d in $2; do
		AS_IF([ls -1 $d/$pattern >/dev/null 2>&1],[
			AS_VAR_SET([snert_dir],[$d])
			break
		])
	done

	AS_VAR_COPY([dir_val],[snert_dir])
dnl	AS_IF([test "$dir_val" = 'no'],AC_MSG_RESULT(no),AC_MSG_RESULT(yes))
	AC_MSG_RESULT($dir_val)
	AS_VAR_IF([snert_dir],[no],[$4],[$3])
	AS_VAR_POPDEF([snert_dir])
])

dnl
dnl SNERT_CHECK_PACKAGE_HEADER(header, if-found, not-found[, extra_dirs])
dnl
AC_DEFUN([SNERT_CHECK_PACKAGE_HEADER],[
	SNERT_FIND_FILE([$1],[$4 /usr/pkg/include /usr/local/include /usr/include],[$2],[$3])
])

dnl
dnl SNERT_CHECK_PACKAGE_LIB(library, if-found, not-found[, extra_dirs])
dnl
AC_DEFUN([SNERT_CHECK_PACKAGE_LIB],[
	SNERT_FIND_FILE([$1],[$4 /usr/pkg/lib /usr/local/lib /usr/lib64 /usr/lib/x86_64-linux-gnu /usr/lib /lib64 /lib/x86_64-linux-gnu /lib],[$2],[$3])
])

dnl
dnl SNERT_DEFINE(name[, value])
dnl
AC_DEFUN([SNERT_DEFINE],[
	name=AS_TR_CPP($1)
	AS_IF([test -n "$2"],[value="$2"],[eval value="\$$name"])
	AC_DEFINE_UNQUOTED($name,["$value"])
])

dnl
dnl SNERT_CHECK_PACKAGE(
dnl	name, headers, libs, [funcs],
dnl	with_base, with_inc, with_lib,
dnl	[extra_includes], [define_and_subst=true]
dnl )
dnl
AC_DEFUN([SNERT_CHECK_PACKAGE],[
	AS_ECHO()
	AS_ECHO("Checking for $1 package...")
	AS_ECHO()

	dnl Watch out for leading and trailing whitespace with m4 macros;
	dnl everything delimited by open/close paren and/or commas is
	dnl part of the argument, so pretty formatting for readability
	dnl can screw with string compares.  Use echo to trim whitespace.
	with_base=`AS_ECHO([$5])`

AS_IF([test "$with_base" != 'no'],[
	dnl Careful with --with options as they can be specified,
	dnl without a base directory path, in which case ignore it.
	AS_IF([test "$with_base" = 'yes'],[
		with_base=''
	])

	for f in $2; do
		cache_id=AS_TR_SH(ac_cv_header_$f)
		SNERT_CHECK_PACKAGE_HEADER([$f],[
			dnl Remember the location we found the header
			dnl even if its a system directory.
			have=AS_TR_CPP(HAVE_$f)
			AC_DEFINE_UNQUOTED($have,["$dir_val/$f"])
			AC_CACHE_VAL($cache_id,[eval $cache_id="\"$dir_val/$f\""])

			SNERT_IF_SYSTEM_DIR([$dir_val],[
				dnl Ignore system directories.
				SNERT_JOIN_UNIQ([CPPFLAGS_$1])
			],[
				SNERT_JOIN_UNIQ([CPPFLAGS_$1],["-I$dir_val"],[head])
			])
		],[
			AC_CACHE_VAL($cache_id,[eval $cache_id='no'])
		],[${with_base:+$with_base/include} $6])
	done

	for f in $3; do
		SNERT_CHECK_PACKAGE_LIB([$f],[
			have=AS_TR_CPP(HAVE_$f)
			AC_DEFINE_UNQUOTED($have,["$dir_val"])
			SNERT_IF_SYSTEM_DIR([$dir_val],[
				lib=`basename -- $f | sed -e's/^lib//'`
				SNERT_JOIN_UNIQ([LIBS_$1],["-l$lib"],[tail])
			],[
				dnl Add only one -Ldir instance.
				SNERT_JOIN_UNIQ([LDFLAGS_$1],["-L$dir_val"])
				AS_IF([expr "$f" : '.*\.a$' >/dev/null],[
					dnl Explicit static library.
					SNERT_JOIN_UNIQ([LIBS_$1],["$dir_val/$f"],[tail])
				],[
					lib=`basename -- $f | sed -e's/^lib//'`
					SNERT_JOIN_UNIQ([LIBS_$1],["-l$lib"],[tail])
				])
			])
		],[],[${with_base:+$with_base/lib} $7])
	done

	define_and_subst=`AS_ECHO([$9])`
	AS_CASE([$define_and_subst],
	[false|no|0],[
		dnl Caller wants to take care of this, possibly
		dnl to append extra flags before committing the
		dnl defines and substutions.
		:
	],[
		dnl Default.
		SNERT_DEFINE(CPPFLAGS_[$1])
		SNERT_DEFINE(LDFLAGS_[$1])
		SNERT_DEFINE(LIBS_[$1])
		AC_SUBST(CPPFLAGS_[$1])
		AC_SUBST(LDFLAGS_[$1])
		AC_SUBST(LIBS_[$1])
	])

	AS_IF([test -n "$4"],[
		save_LIBS="$LIBS"
		save_LDFLAGS="$LDFLAGS"
		save_CPPFLAGS="$CPPFLAGS"

		eval LIBS=\"\$LIBS_$1 $LIBS\"
		eval LDFLAGS=\"\$LDFLAGS_$1 $LDFLAGS\"
		eval CPPFLAGS=\"\$CPPFLAGS_$1 $CPPFLAGS\"

		AC_CHECK_FUNCS([$4],[],[],[$8])

		CPPFLAGS="$save_CPPFLAGS"
		LDFLAGS="$save_LDFLAGS"
		LIBS="$save_LIBS"
	])
],[
	AC_MSG_NOTICE([Package $1 has been explicitly disabled.])
])
])

dnl
dnl SNERT_OPTION_ENABLE_DEBUG
dnl
AC_DEFUN(SNERT_OPTION_ENABLE_DEBUG,[
	dnl Assert that CFLAGS is defined. When AC_PROC_CC is called to
	dnl check the compiler and CC == gcc is found and CFLAGS is
	dnl undefined, then it gets assigned "-g -O2", which is just
	dnl annoying when you want the default to no debugging.
	CPPFLAGS="${CPPFLAGS}"
	CFLAGS="${CFLAGS}"

	AC_ARG_ENABLE(debug,[AC_HELP_STRING([--enable-debug],[enable compiler debug option])],[
	],[
		AC_DEFINE(NDEBUG,[1],[Disable debug code])
	])
])

AC_DEFUN([SNERT_CC_INFO],[
	AC_REQUIRE([AC_PROG_CC])
	AC_USE_SYSTEM_EXTENSIONS
	AC_LANG([C])

	AS_IF([test "$GCC" = 'yes'],[
		GCC_MAJOR=`$CC -dM -E -xc /dev/null | sed -n -e 's/.*__GNUC__ \(.*\)/\1/p'`
		GCC_MINOR=`$CC -dM -E -xc /dev/null | sed -n -e 's/.*__GNUC_MINOR__ \(.*\)/\1/p'`
		GCC_PATCH=`$CC -dM -E -xc /dev/null | sed -n -e 's/.*__GNUC_PATCHLEVEL__ \(.*\)/\1/p'`
		dnl Nothing wrong using a char for a subscript.
		AS_IF([test $GCC_MAJOR -ge 3],[CFLAGS="-Wno-char-subscripts $CFLAGS"])
		dnl Option to ignore extra support functions.
		AS_IF([test $GCC_MAJOR -ge 4 -a $GCC_MINOR -ge 3 ],[CFLAGS="-Wno-unused-function $CFLAGS"])
		dnl Option to silience Valgrind and ProtoThread macro warnings.
		AS_IF([test $GCC_MAJOR -ge 4 -a $GCC_MINOR -ge 6 ],[CFLAGS="-Wno-unused-but-set-variable $CFLAGS"])
		CFLAGS="-Wall $CFLAGS"
	])
	AS_IF([test ${enable_debug:-no} = 'no'],[
		CFLAGS="-O2 ${CFLAGS}"
		LDFLAGS="${LDFLAGS}"
	],[
		CFLAGS="-O0 -g ${CFLAGS}"
	])

	dnl Tradional cc options.
	dnl NOTE SunOS as(1) _wants_ a space between -o and its argument.
	CC_E='-o'
	CC_E_NAME='-o $@'
	CC_O='-o'
	CC_O_NAME='-o $''*$O'
	LD=$CC

	AC_SUBST(CC_E)
	AC_SUBST(CC_E_NAME)
	AC_SUBST(CC_O)
	AC_SUBST(CC_O_NAME)

	dnl Check for recent ANSI C additions that HAVE_HEADER_STDC check
	dnl doesn't distinguish between C89 and C99.
	AC_CHECK_HEADERS([stdarg.h])
	SNERT_CHECK_DEFINE([va_copy], [stdarg.h])
])

AC_DEFUN([SNERT_TAR_SETTINGS],[
	AC_MSG_CHECKING(for tar file list option to use)
	AS_IF([tar --version 2>&1 | grep '(GNU tar)' >/dev/null],[
		TAR_I='-T'
	],[
		TAR_I='-I'
	])
	AC_SUBST(TAR_I)
	AC_MSG_RESULT($TAR_I)
])

#######################################################################
# API Families
#######################################################################

dnl
dnl SNERT_ANSI_STRING
dnl
AC_DEFUN(SNERT_ANSI_STRING,[
	AS_ECHO()
	AS_ECHO("Check for ANSI string functions...")
	AS_ECHO()
	AC_CHECK_FUNCS([ dnl
		memchr memcmp memcpy memmove memset dnl
		strcat strncat strcpy strncpy strcmp strncmp strxfrm dnl
		strchr strcspn strerror strlen strpbrk strrchr strspn strstr strtok dnl
		sys_errlist dnl
	])
	AC_FUNC_STRCOLL
	AC_FUNC_STRERROR_R
])

dnl
dnl SNERT_EXTRA_STRING
dnl
AC_DEFUN(SNERT_EXTRA_STRING,[
	AS_ECHO()
	AS_ECHO("Check for supplemental string support...")
	AS_ECHO()
	AC_CHECK_FUNCS([ dnl
		strdup strtol strlcpy strlcat strcasecmp strncasecmp dnl
		snprintf vsnprintf setproctitle dnl
	])
])

AC_DEFUN(SNERT_FILE_LOCKS,[
	AS_ECHO()
	AS_ECHO("Check for file locking...")
	AS_ECHO()
	AC_CHECK_HEADERS([fcntl.h],[
		AC_CHECK_FUNCS(flock fcntl lockf locking)
		SNERT_CHECK_DEFINE(O_BINARY, fcntl.h)
		SNERT_CHECK_DEFINE(LOCK_SH, fcntl.h)

		dnl Discontinue used of old flags, switch to O_NONBLOCK.
		SNERT_CHECK_DEFINE(O_NDELAY, fcntl.h)
		SNERT_CHECK_DEFINE(FNDELAY, fcntl.h)
	])
	AH_VERBATIM(HAVE_LOCK_SH,[
#undef HAVE_MACRO_LOCK_SH

/*
 * Define the flock() constants separately, since some systems
 * have flock(), but fail to define the constants in a header.
 * These values were taken from FreeBSD.
 */
#ifndef HAVE_MACRO_LOCK_SH
# define LOCK_SH	0x01		/* shared file lock */
# define LOCK_EX	0x02		/* exclusive file lock */
# define LOCK_NB	0x04		/* don't block when locking */
# define LOCK_UN	0x08		/* unlock file */
#endif
	])
])

dnl
dnl SNERT_POSIX_IO
dnl
AC_DEFUN(SNERT_POSIX_IO,[
	AS_ECHO()
	AS_ECHO("Check for POSIX File & Directory I/O support...")
	AS_ECHO()
	AC_HEADER_DIRENT
dnl autoconf says the following should be included:
dnl
dnl #if HAVE_DIRENT_H
dnl # include <dirent.h>
dnl # define NAMLEN(dirent) strlen((dirent)->d_name)
dnl #else
dnl # define dirent direct
dnl # define NAMLEN(dirent) (dirent)->d_namlen
dnl # if HAVE_SYS_NDIR_H
dnl #  include <sys/ndir.h>
dnl # endif
dnl # if HAVE_SYS_DIR_H
dnl #  include <sys/dir.h>
dnl # endif
dnl # if HAVE_NDIR_H
dnl #  include <ndir.h>
dnl # endif
dnl #endif

	AC_CHECK_HEADERS([unistd.h fcntl.h sys/stat.h utime.h])
	AC_CHECK_FUNCS([ dnl
		chdir getcwd mkdir rmdir closedir opendir readdir dnl
		chmod chown chroot fchmod stat fstat link rename symlink unlink umask utime dnl
		close creat dup dup2 ftruncate chsize truncate lseek open pipe read write dnl
		isatty getdtablesize dnl
	])
	AC_FUNC_CHOWN
])

dnl
dnl SNERT_SYS
dnl
AC_DEFUN([SNERT_SYS],[
	AS_ECHO()
	AS_ECHO("Check for system kernel support...")
	AS_ECHO()
	dnl Linux
	AC_CHECK_HEADERS([sys/prctl.h],[
		AC_CHECK_FUNCS(prctl)
	])
	AC_CHECK_HEADERS([sys/sysinfo.h],[
		AC_CHECK_FUNCS(get_nprocs_conf get_nprocs)
	])
	dnl *BSD
	AC_CHECK_HEADERS([sys/param.h sys/sysctl.h],[
		AC_CHECK_FUNCS(sysctl)
	])
	AC_CHECK_HEADERS([stdlib.h],[
		AC_CHECK_FUNCS(getloadavg)
	])
	dnl POSIX / generic
	AC_CHECK_HEADERS([unistd.h],[
		AC_CHECK_FUNCS(fpathconf pathconf sysconf)
	])
])

dnl
dnl SNERT_PROCESS
dnl
AC_DEFUN(SNERT_PROCESS,[
	AS_ECHO()
	AS_ECHO("Check for process support...")
	AS_ECHO()
	AC_CHECK_HEADER([unistd.h],[
		AC_DEFINE_UNQUOTED(HAVE_UNISTD_H)
		AC_CHECK_FUNCS([ dnl
			getopt getuid getgid setuid setgid dnl
			geteuid getegid seteuid setegid getpgid setpgid dnl
			getresuid getresgid setresuid setresgid dnl
			setreuid getgroups setgroups initgroups dnl
			_exit exit daemon fork execl execle execlp execv execve execvp setsid dnl
		])
	])
	AC_CHECK_HEADER([sys/wait.h],[
		AC_DEFINE(HAVE_SYS_WAIT_H,[],[Process Support])
		AC_CHECK_FUNCS([wait wait3 wait4 waitpid])
	])

	AC_CHECK_HEADER([sys/resource.h],[
		AC_DEFINE(HAVE_SYS_RESOURCE_H,[],[Process Resources])
		AC_CHECK_TYPES([struct rlimit, rlim_t],[],[],[
#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif
#ifdef TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# ifdef HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif
#include <sys/resource.h>
		])
		AC_CHECK_FUNCS([getrlimit setrlimit])
	])
	AC_CHECK_HEADERS([limits.h sysexits.h syslog.h])
])

dnl
dnl SNERT_NETWORK
dnl
AC_DEFUN(SNERT_NETWORK,[
	AS_ECHO()
	AS_ECHO("Check for Network services...")
	AS_ECHO()
	SNERT_CHECK_PREDEFINE(__WIN32__)
	SNERT_CHECK_PREDEFINE(__CYGWIN__)

	AS_IF([test "$ac_cv_define___WIN32__" = 'no'],[
		AC_SEARCH_LIBS([socket], [socket nsl])
		AC_SEARCH_LIBS([inet_aton], [socket nsl resolv])

		AC_CHECK_HEADERS([ dnl
			sys/socket.h netinet/in.h netinet/in6.h netinet6/in6.h dnl
			netinet/tcp.h poll.h sys/poll.h sys/select.h sys/un.h dnl
			arpa/inet.h dnl
		])

dnl When using poll() use this block.
dnl
dnl #ifdef HAVE_POLL_H
dnl # include <poll.h>
dnl # ifndef INFTIM
dnl #  define INFTIM	(-1)
dnl # endif
dnl #endif

dnl When using kqueue() use this block.
dnl
dnl #ifdef HAVE_SYS_EVENT_H
dnl # include <sys/types.h>
dnl # include <sys/event.h>
dnl # include <sys/time.h>
dnl # ifndef INFTIM
dnl #  define INFTIM	(-1)
dnl # endif
dnl #endif

		AC_CHECK_FUNCS([ dnl
			inet_pton inet_aton inet_addr inet_ntoa inet_ntop dnl
			accept bind connect listen poll select shutdown socket dnl
			getpeereid getpeername getsockname getsockopt setsockopt dnl
			recv recvfrom recvmsg send sendmsg sendto dnl
			htonl htons ntohl ntohs dnl
		])

		AC_CHECK_HEADERS([sys/event.h],[AC_CHECK_FUNCS([kqueue kevent])])
		AC_CHECK_HEADERS([sys/epoll.h],[AC_CHECK_FUNCS([epoll_create epoll_ctl epoll_wait epoll_pwait])])

		AC_CHECK_HEADERS([netdb.h],[
			AC_CHECK_FUNCS([ dnl
				getaddrinfo freeaddrinfo getnameinfo dnl
				gethostname gethostbyname gethostbyname2 gethostbyaddr dnl
				gethostbyname_r gethostbyname2_r gethostbyaddr_r dnl
				gethostent sethostent endhostent hstrerror herror dnl
				getservent getservbyport getservbyname setservent endservent dnl
				getprotoent getprotobynumber getprotobyname setprotoent endprotoent dnl
			])
		])

		AC_CHECK_HEADERS([ifaddrs.h],[
			AC_CHECK_FUNCS([getifaddrs freeifaddrs])
		])
		AC_CHECK_HEADERS([net/if.h],[
			AC_CHECK_FUNCS([if_nameindex if_freenameindex if_nametoindex if_indextoname])
		])
	],[
		AC_CHECK_HEADERS(windows.h)
		AC_CHECK_HEADER(winsock2.h,[
			AC_DEFINE_UNQUOTED(AS_TR_CPP([HAVE_]winsock2.h),[],[Windows BSD Socket API])
		],[],[
#if defined(__WIN32__)
# if defined(HAVE_WINDOWS_H)
#  include  <windows.h>
# endif
#endif
		])
		AC_CHECK_HEADER(ws2tcpip.h,[
			AC_SUBST(HAVE_LIB_WS2_32, '-lws2_32')
			AC_DEFINE(AS_TR_CPP([HAVE_]ws2tcpip.h),[],[Windows TCP/IP API])
		],[],[
#if defined(__WIN32__)
# if defined(HAVE_WINDOWS_H)
#  include  <windows.h>
# endif
# if defined(HAVE_WINSOCK2_H)
#  include  <winsock2.h>
# endif
#endif
		])
		AC_CHECK_HEADER(Iphlpapi.h,[
			AC_SUBST(HAVE_LIB_IPHLPAPI, '-lIphlpapi')
			AC_DEFINE(AS_TR_CPP([HAVE_]Iphlpapi.h),[],[Windows IP Helper library])
		],[],[
#if defined(__WIN32__)
# if defined(HAVE_WINDOWS_H)
#  include  <windows.h>
# endif
#endif
		])

		for i in \
			accept \
			bind \
			closesocket \
			connect \
			endservent \
			getpeername \
			getprotobyname \
			getprotobynumber \
			getservbyname \
			getservbyport \
			getservent \
			getsockname \
			getsockopt \
			htonl \
			htons \
			inet_addr \
			inet_ntoa \
			listen \
			ntohl \
			ntohs \
			recv \
			recvfrom \
			select \
			send \
			sendto \
			setservent \
			setsockopt \
			shutdown \
			socket \
			getaddrinfo freeaddrinfo getnameinfo \
			gethostname gethostbyname gethostbyaddr
		do
			AC_MSG_CHECKING([for $i])
			AC_DEFINE(AS_TR_CPP([HAVE_]$i),[],[function $1])
			AC_MSG_RESULT([assumed in winsock2.h & ws2tcpip.h])
		done
	])

	AS_IF([test ${ac_cv_define___CYGWIN__:-no} != 'no' -o ${ac_cv_define___WIN32__:-no} != 'no'],[
		NETWORK_LIBS="-lws2_32 -lIphlpapi $NETWORK_LIBS"
		AC_SUBST(NETWORK_LIBS, ${NETWORK_LIBS})
	])

	AC_CHECK_TYPES([struct sockaddr_in6, struct in6_addr, struct sockaddr_un, socklen_t, struct sockaddr_storage],[],[],[
#if defined(__WIN32__)
# define WINVER	0x0501
# if defined(HAVE_WINDOWS_H)
#  include  <windows.h>
# endif
# if defined(HAVE_WINSOCK2_H)
#  include  <winsock2.h>
# endif
# if defined(HAVE_WS2TCPIP_H)
#  include <ws2tcpip.h>
# endif
#else
# ifdef HAVE_SYS_TYPES_H
#  include <sys/types.h>
# endif
# ifdef HAVE_SYS_SOCKET_H
#  include <sys/socket.h>
# endif
# ifdef HAVE_SYS_UN_H
#  include <sys/un.h>
# endif
# ifdef HAVE_NETINET_IN_H
#  include <netinet/in.h>
# endif
# ifdef HAVE_NETINET_IN6_H
#  include <netinet/in6.h>
# endif
# ifdef HAVE_NETINET6_IN6_H
#  include <netinet6/in6.h>
# endif
#endif
	])
	AC_CHECK_MEMBERS([struct sockaddr.sa_len, struct sockaddr_in.sin_len, struct sockaddr_in6.sin6_len, struct sockaddr_un.sun_len],[],[],[
#if defined(__WIN32__)
# define WINVER	0x0501
# if defined(HAVE_WINDOWS_H)
#  include  <windows.h>
# endif
# if defined(HAVE_WINSOCK2_H)
#  include  <winsock2.h>
# endif
# if defined(HAVE_WS2TCPIP_H)
#  include <ws2tcpip.h>
# endif
#else
# ifdef HAVE_SYS_TYPES_H
#  include <sys/types.h>
# endif
# ifdef HAVE_SYS_SOCKET_H
#  include <sys/socket.h>
# endif
# ifdef HAVE_SYS_UN_H
#  include <sys/un.h>
# endif
# ifdef HAVE_NETINET_IN_H
#  include <netinet/in.h>
# endif
# ifdef HAVE_NETINET_IN6_H
#  include <netinet/in6.h>
# endif
# ifdef HAVE_NETINET6_IN6_H
#  include <netinet6/in6.h>
# endif
#endif
	])
])

dnl
dnl SNERT_ANSI_TIME
dnl
AC_DEFUN(SNERT_ANSI_TIME,[
	AS_ECHO()
	AS_ECHO("Check for ANSI & supplemental time support...")
	AS_ECHO()

dnl	saved_libs=$LIBS

	AC_CHECK_HEADERS(time.h sys/time.h)
	AC_HEADER_TIME
dnl autoconf says the following should be included:
dnl
dnl #ifdef TIME_WITH_SYS_TIME
dnl # include <sys/time.h>
dnl # include <time.h>
dnl #else
dnl # ifdef HAVE_SYS_TIME_H
dnl #  include <sys/time.h>
dnl # else
dnl #  include <time.h>
dnl # endif
dnl #endif
	AC_SEARCH_LIBS([clock_gettime],[rt])
	AS_IF([expr "$ac_cv_search_clock_gettime" : '-l' >/dev/null],[
		LIBS_RT="$ac_cv_search_clock_gettime"
		AC_DEFINE_UNQUOTED(LIBS_RT,"$LIBS_RT",[Realtime library])
		AC_SUBST(LIBS_RT)
	])
	AC_CHECK_FUNCS([ dnl
		clock difftime mktime time asctime ctime gmtime localtime tzset sleep usleep nanosleep dnl
		asctime_r ctime_r gmtime_r localtime_r clock_gettime gettimeofday dnl
		alarm getitimer setitimer dnl
	])
	dnl These are typically macros:  timerclear timerisset timercmp timersub timeradd
	AC_FUNC_STRFTIME
	AC_CHECK_TYPES([struct timespec, struct timeval],[],[],[
#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif
#ifdef TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# ifdef HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif
	])

	AC_STRUCT_TM
	AC_CHECK_MEMBERS([struct tm.tm_gmtoff],[],[],[
#ifdef TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# ifdef HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif
	])
	AC_STRUCT_TIMEZONE
	AC_CHECK_FUNCS(timegm)

dnl	LIBS=$saved_libs
])

dnl
dnl SNERT_REGEX
dnl
AC_DEFUN([SNERT_REGEX],[
	AS_ECHO()
	AS_ECHO("Check for regex...")
	AS_ECHO()
	AC_CHECK_HEADERS([regex.h],[
		AC_SEARCH_LIBS([regcomp], [regex])
		dnl Redo function tests; see SNERT_PCRE.
		AS_UNSET(ac_cv_func_regcomp)
		AS_UNSET(ac_cv_func_regexec)
		AS_UNSET(ac_cv_func_regerror)
		AS_UNSET(ac_cv_func_regfree)
		AC_CHECK_FUNCS(regcomp regexec regerror regfree)
	])
])

AC_DEFUN(CYRUS_SIGVEC,[
	AS_ECHO()
	AS_ECHO("Check for sigvec...")
	AS_ECHO()
	AC_SEARCH_LIBS([sigvec],[BSD],[
		AS_IF([test "$ac_cv_search_sigvec" = 'none required'],[
			ac_cv_search_sigvec=''
		])
	],[
		SAVE_LDFLAGS="$LDFLAGS"
		dnl solaris flavor
		LDFLAGS="-L/usr/ucblib -R/usr/ucblib $LDFLAGS"
		AS_UNSET([ac_cv_search_sigvec])
		AC_SEARCH_LIBS([sigvec],[ucb],[
			dnl more solaris flavor
			ac_cv_search_sigvec="-L/usr/ucblib -R/usr/ucblib -lucb"
		])
		LDFLAGS="$SAVE_LDFLAGS"
	])
	AC_SUBST(cyrus_cv_sigveclib, $ac_cv_search_sigvec)
])

dnl
dnl CYRUS_MMAP
dnl
AC_DEFUN(CYRUS_MMAP,[
	AS_ECHO()
	AS_ECHO("Check MMAP...")
	AS_ECHO()
	AC_CHECK_HEADERS([sys/mman.h],[
		AC_CHECK_FUNCS([madvise mlock mmap mprotect msync munmap])
	])

	AC_CACHE_CHECK([for shared mmap],[cyrus_cv_func_mmap_shared],[
		AC_RUN_IFELSE([
			AC_LANG_SOURCE([[
#include <string.h>
#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif
#ifdef HAVE_FCNTL_H
# include <fcntl.h>
#endif
#ifdef HAVE_MMAN_H
# include <sys/mman.h>
#endif
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif

int
main(int argc, char **argv)
{
	char *base;
	int fd, mmapflags = MAP_SHARED;

	/* Create a file. */
	if ((fd = open("conftestmmap", O_RDWR|O_CREAT|O_TRUNC, 0666)) < 0)
		return 1;
	(void) unlink("conftestmmap");
	if (write(fd, "test", 4) != 4)
		return 2;
	(void) fsync(fd);
	/* Map file into memory. */
#ifdef MAP_FILE
	mmapflags |= MAP_FILE;
#endif
#ifdef MAP_VARIABLE
	mmapflags |= MAP_VARIABLE;
#endif
	base = mmap((caddr_t)0, 100, PROT_READ, mmapflags, fd, 0L);
	if (base == (caddr_t)-1)
		return 3;
	/* Verify memory matches what was originally written. */
	if (memcmp(base, "test", 4) != 0)
		return 4;
	/* Write / append to the file. */
	if (write(fd, "more", 4) != 4)
		return 5;
	(void) fsync(fd);
	/* Check if file write is seen by the memory map. */
	if (memcmp(base+4, "more", 4) != 0)
		return 6;
	(void) close(fd);

	return 0;
}
			]])
		],[
			cyrus_cv_func_mmap_shared='yes'
		],[
			cyrus_cv_func_mmap_shared='no'
		])
	])

	AC_CACHE_CHECK([for stupid shared mmap],[cyrus_cv_func_mmap_stupidshared],[
		AC_RUN_IFELSE([
			AC_LANG_SOURCE([[
#include <string.h>
#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif
#ifdef HAVE_FCNTL_H
# include <fcntl.h>
#endif
#ifdef HAVE_MMAN_H
# include <sys/mman.h>
#endif
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif

int
main(int argc, char **argv)
{
	char *base;
	int fd, mmapflags = MAP_SHARED;

	/* Create a file. */
	if ((fd = open("conftestmmap", O_RDWR|O_CREAT|O_TRUNC, 0666)) < 0)
		return 1;
	(void) unlink("conftestmmap");
	if (write(fd, "test", 4) != 4)
		return 2;
	(void) fsync(fd);
	/* Map file into memory. */
#ifdef MAP_FILE
	mmapflags |= MAP_FILE;
#endif
#ifdef MAP_VARIABLE
	mmapflags |= MAP_VARIABLE;
#endif
	base = mmap((caddr_t)0, 100, PROT_READ, mmapflags, fd, 0L);
	if (base == (caddr_t)-1)
		return 3;
	/* Verify memory matches what was originally written. */
	if (memcmp(base, "test", 4) != 0)
		return 4;
	/* Rewind to start of file. */
	(void) lseek(fd, 0L, 0);
	/* Overwrite start of file. */
	if (write(fd, "over", 4) != 4)
		return 5;
	(void) fsync(fd);
	/* Check if file seek and overwrite is seen by the memory map. */
	if (memcmp(base, "over", 4) != 0)
		return 6;
	(void) close(fd);

	return 0;
}
			]])
		],[
			cyrus_cv_func_mmap_stupidshared='yes'
		],[
			cyrus_cv_func_mmap_stupidshared='no'
		])
	])
])

#######################################################################
# Packages
#######################################################################

dnl
dnl SNERT_SQLITE3
dnl
AC_DEFUN(SNERT_OPTION_WITH_SQLITE3,[
	AC_ARG_WITH([sqlite3],[AS_HELP_STRING([--with-sqlite3=DIR],[SQLite3 package, optional base directory])])
	AC_ARG_WITH([sqlite3-inc],[AS_HELP_STRING([--with-sqlite3-inc=DIR],[...specific SQLite3 include directory])])
	AC_ARG_WITH([sqlite3-lib],[AS_HELP_STRING([--with-sqlite3-lib=DIR],[...specific SQLite3 library directory])])
])
AC_DEFUN(SNERT_SQLITE3,[
	SNERT_CHECK_PACKAGE([SQLITE3],[sqlite3.h],[libsqlite3],[sqlite3_open], dnl
		[$with_sqlite3],[$with_sqlite3_inc],[$with_sqlite3_lib] dnl
	)
dnl 	AC_SUBST(LIBS_SQLITE3)
dnl 	AC_SUBST(CPPFLAGS_SQLITE3)
dnl 	AC_SUBST(LDFLAGS_SQLITE3)
	AH_VERBATIM(LIBS_SQLITE3,[
#undef HAVE_LIBSQLITE3
#undef HAVE_SQLITE3_H
#undef HAVE_SQLITE3_OPEN
#undef CPPFLAGS_SQLITE3
#undef LDFLAGS_SQLITE3
#undef LIBS_SQLITE3
	])
])

AC_DEFUN(SNERT_OPTION_WITH_MYSQL,[
	AC_ARG_WITH([mysql],[AS_HELP_STRING([--with-mysql=DIR],[MySQL package, optional base directory])])
	AC_ARG_WITH([mysql-inc],[AS_HELP_STRING([--with-mysql-inc=DIR],[...specific MySQL include directory])])
	AC_ARG_WITH([mysql-lib],[AS_HELP_STRING([--with-mysql-lib=DIR],[...specific MySQL library directory])])
])
AC_DEFUN(SNERT_MYSQL,[
	SNERT_CHECK_PACKAGE([MYSQL],[mysql.h mysql/mysql.h],[libmysqlclient mysql/libmysqlclient ],[mysql_select_db], dnl
		[$with_mysql],[$with_mysql_inc],[$with_mysql_lib],[],[no]dnl
	)

	AC_PATH_PROG([MYSQL_CONFIG],[mysql_config],[false])
	AS_IF([test "$MYSQL_CONFIG" = 'false'],[
		with_mysql='no'
		AS_UNSET([LIBS_MYSQL])
		AS_UNSET([LDFLAGS_MYSQL])
		AS_UNSET([CPPFLAGS_MYSQL])
		AC_MSG_WARN([mysql_config not found, disabling MySQL support.])
	],[
		dnl Override found flags with those supplied by tool.
		CPPFLAGS_MYSQL=`$MYSQL_CONFIG --include`
		LIBS_MYSQL=`$MYSQL_CONFIG --libs`
	])

	SNERT_DEFINE([LIBS_MYSQL])
	SNERT_DEFINE([LDFLAGS_MYSQL])
	SNERT_DEFINE([CPPFLAGS_MYSQL])

 	AC_SUBST(LIBS_MYSQL)
 	AC_SUBST(LDFLAGS_MYSQL)
 	AC_SUBST(CPPFLAGS_MYSQL)

	AH_VERBATIM(LIBS_MYSQL,[
#undef HAVE_MYSQL_LIBMYSQLCLIENT
#undef HAVE_LIBMYSQLCLIENT
#undef HAVE_MYSQL_MYSQL_H
#undef HAVE_MYSQL_H
#undef HAVE_MYSQL_SELECT_DB
#undef CPPFLAGS_MYSQL
#undef LDFLAGS_MYSQL
#undef LIBS_MYSQL
	])
])

AC_DEFUN(SNERT_OPTION_WITH_PGSQL,[
	AC_ARG_WITH([pgsql],[AS_HELP_STRING([--with-pgsql=DIR],[PostgreSQL package, optional base directory])])
	AC_ARG_WITH([pgsql-inc],[AS_HELP_STRING([--with-pgsql-inc=DIR],[...specific PostgreSQL include directory])])
	AC_ARG_WITH([pgsql-lib],[AS_HELP_STRING([--with-pgsql-lib=DIR],[...specific PostgreSQL library directory])])
])
AC_DEFUN(SNERT_PGSQL,[
	SNERT_CHECK_PACKAGE([PGSQL],[libpq-fe.h],[libpq],[PQconnectdb],dnl
		[$with_pgsql],[$with_pgsql_inc],[$with_pgsql_lib]dnl
	)
dnl 	AC_SUBST(LIBS_PGSQL)
dnl 	AC_SUBST(CPPFLAGS_PGSQL)
dnl 	AC_SUBST(LDFLAGS_PGSQL)
	AH_VERBATIM(LIBS_PGSQL,[
#undef HAVE_LIBPQ
#undef HAVE_LIBPQ_FE_H
#undef HAVE_PQCONNECTDB
#undef CPPFLAGS_PGSQL
#undef LDFLAGS_PGSQL
#undef LIBS_PGSQL
	])
])

AC_DEFUN([SNERT_OPTION_WITH_SASL2],[
	AC_ARG_WITH([sasl2],[AS_HELP_STRING([--with-sasl2=DIR],[SASL2 package, optional base directory])])
	AC_ARG_WITH([sasl2-inc],[AS_HELP_STRING([--with-sasl2-inc=DIR],[...specific SASL2 include directory])])
	AC_ARG_WITH([sasl2-lib],[AS_HELP_STRING([--with-sasl2-lib=DIR],[...specific SASL2 library directory])])
])
AC_DEFUN([SNERT_SASL2],[
	AC_REQUIRE([SNERT_NETWORK])
	SNERT_CHECK_PACKAGE([SASL2], dnl
		[sasl/sasl.h sasl/saslutil.h],[libsasl2],[prop_get sasl_checkapop], dnl
		[$with_sasl2],[$with_sasl2_inc],[$with_sasl2_lib] dnl
	)
dnl 	AC_SUBST(LIBS_SASL2)
dnl 	AC_SUBST(CPPFLAGS_SASL2)
dnl 	AC_SUBST(LDFLAGS_SASL2)
	AH_VERBATIM(LIBS_SASL2,[
#undef HAVE_LIBSASL2
#undef HAVE_SASL_SASL_H
#undef HAVE_SASL_SASLUTIL_H
#undef HAVE_SASL_CHECKAPOP
#undef HAVE_PROP_GET
#undef CPPFLAGS_SASL2
#undef LDFLAGS_SASL2
#undef LIBS_SASL2
	])
])

AC_DEFUN([CYRUS_OPTION_WITH_KRB4],[
	AC_ARG_WITH([krb4],[AS_HELP_STRING([--with-krb4=DIR],[Kerberos 4 package, optional base directory])])
	AC_ARG_WITH([krb4-inc],[AS_HELP_STRING([--with-krb4-inc=DIR],[...specific Kerberos 4 include directory])])
	AC_ARG_WITH([krb4-lib],[AS_HELP_STRING([--with-krb4-lib=DIR],[...specific Kerberos 4 library directory])])
	AC_ARG_WITH([krb4-des],[AS_HELP_STRING([--with-krb4-des],[use Kerberos DES implementation])],[],[with_krb_des='yes'])
])
AC_DEFUN([CYRUS_KRB4],[
	AC_REQUIRE([SNERT_NETWORK])
	AC_REQUIRE([CYRUS_COM_ERR])
	SNERT_CHECK_PACKAGE([KRB4], dnl
		[kerberosIV/krb.h krb.h], dnl
		[libkrb4 libkrb libdes], dnl
		[krb_mk_priv des_ecb_encrypt], dnl
		[$with_krb4],[$with_krb4_inc],[$with_krb4_lib] dnl
	)

	AS_IF([test "$enable_krb_des" = 'yes' -a "$snert_find_file_libdes" = 'no'],[
		AC_MSG_ERROR([The Kerberos DES library is required for Kerberos support.])
	])

dnl 	AC_SUBST(LIBS_KRB4)
dnl 	AC_SUBST(CPPFLAGS_KRB4)
dnl 	AC_SUBST(LDFLAGS_KRB4)
	AH_VERBATIM(LIBS_KRB4,[
#undef HAVE_LIBKRB4
#undef HAVE_LIBKRB
#undef HAVE_LIBDES
#undef HAVE_KRB_H
#undef HAVE_KERBEROSIV_KRB_H
#undef HAVE_KRB_MK_PRIV
#undef HAVE_DES_ECB_ENCRYPT
#undef CPPFLAGS_KRB4
#undef LDFLAGS_KRB4
#undef LIBS_KRB4
	])
])

AC_DEFUN([CYRUS_OPTION_WITH_KRB5],[
	AC_ARG_WITH([krb5],[AS_HELP_STRING([--with-krb5=DIR],[Kerberos 5 package, optional base directory])])
	AC_ARG_WITH([krb5-inc],[AS_HELP_STRING([--with-krb5-inc=DIR],[...specific Kerberos 5 include directory])])
	AC_ARG_WITH([krb5-lib],[AS_HELP_STRING([--with-krb5-lib=DIR],[...specific Kerberos 5 library directory])])
])
AC_DEFUN([CYRUS_KRB5],[
	AC_REQUIRE([SNERT_NETWORK])
	SNERT_CHECK_PACKAGE([KRB5],[krb5.h krb5/krb5.h],[libkrb5],dnl
		[krb5_init_context krb5_mk_priv], dnl
		[$with_krb5],[$with_krb5_inc],[$with_krb5_lib] dnl
	)
dnl 	AC_SUBST(LIBS_KRB5)
dnl 	AC_SUBST(CPPFLAGS_KRB5)
dnl 	AC_SUBST(LDFLAGS_KRB5)
	AH_VERBATIM(LIBS_KRB5,[
#undef HAVE_LIBKRB5
#undef HAVE_KRB5_H
#undef HAVE_KRB5_KRB5_H
#undef HAVE_KRB5_MK_PRIV
#undef CPPFLAGS_KRB5
#undef LDFLAGS_KRB5
#undef LIBS_KRB5
	])
])

dnl
dnl We need to find out which gssapi implementation we are
dnl using. Supported alternatives are:
dnl
dnl 	Heimdal Kerberos 5 (http://www.pdc.kth.se/heimdal)
dnl 	MIT Kerberos 5
dnl 	CyberSafe Kerberos 5 (http://www.cybersafe.com/)
dnl 	Sun SEAM (http://wwws.sun.com/software/security/kerberos/)
dnl
dnl The choice is reflected in GSSAPIBASE_LIBS
dnl
AC_DEFUN([CYRUS_OPTION_ENABLE_GSSAPI],[
	AC_ARG_ENABLE([gssapi],[AS_HELP_STRING([--enable-gssapi=IMPL],[GSSAPI implementation: auto, heimdal, mit, cybersafe, or seam])],[
		AS_IF([test "$enable_gssapi" = 'yes'],[
			enable_gssapi='auto'
		])
	],[
		enable_gssapi='auto'
	])
])
AC_DEFUN([CYRUS_OPTION_WITH_GSSAPI],[
	AC_ARG_WITH([gssapi],[AS_HELP_STRING([--with-gssapi=DIR],[GSSAPI package, optional base directory])])
	AC_ARG_WITH([gssapi-inc],[AS_HELP_STRING([--with-gssapi-inc=DIR],[...specific GSSAPI include directory])])
	AC_ARG_WITH([gssapi-lib],[AS_HELP_STRING([--with-gssapi-lib=DIR],[...specific GSSAPI library directory])])
])
AC_DEFUN([CYRUS_GSSAPI],[
	AC_REQUIRE([CYRUS_KRB5])
	AC_REQUIRE([CYRUS_COM_ERR])
	SNERT_CHECK_PACKAGE([GSSAPI], dnl
		[gssapi/gssapi.h gssapi/gssapi_ext.h gssapi.h appsec-sdk/include/gssapi.h], dnl
		[libgssapi libgssapi_krb5 libkrb5support appsec-rt/lib/libgss], dnl
		[gss_unwrap krb5int_getspecific csf_gss_acq_user], dnl
		[$with_gssapi],[$with_gssapi_inc],[$with_gssapi_lib],[],[no]dnl
	)

	save_LIBS="$LIBS"
	save_LDFLAGS="$LDFLAGS"
	save_CPPFLAGS="$CPPFLAGS"

	LIBS="$LIBS_GSSAPI $LIBS"
	LDFLAGS="$LDFLAGS_GSSAPI $LDFLAGS"
	CPPFLAGS="$CPPFLAGS_GSSAPI $CPPFLAGS"

	AC_SEARCH_LIBS([res_search],[resolv])

	dnl We'll test for all supported implementations.
	AS_UNSET([ac_cv_lib_gssapi_gss_unwrap])
	AC_CHECK_LIB([gssapi],[gss_unwrap],[
		AS_IF([test "$enable_gssapi" = 'auto' -o "$enable_gssapi" = 'heimdal'],[
			SNERT_JOIN_UNIQ([LIBS_GSSAPI],[$LIBS_KRB5 $LIBS_COM_ERR $NETWORK_LIBS])
			SNERT_JOIN_UNIQ([CPPFLAGS_GSSAPI],[$CPPFLAGS_KRB5 $CPPFLAGS_COM_ERR])
			SNERT_JOIN_UNIQ([LDFLAGS_GSSAPI],[$LDFLAGS_KRB5 $LDFLAGS_COM_ERR])
			enable_gssapi='heimdal'
		])
	],[],[$LIBS_KRB5 $LIBS_COM_ERR $NETWORK_LIBS])

	AS_UNSET([ac_cv_lib_gssapi_gss_unwrap])
	AC_CHECK_LIB([gssapi_krb5],[gss_unwrap],[
		AS_IF([test "$enable_gssapi" = 'auto' -o "$enable_gssapi" = 'mit'],[
			SNERT_JOIN_UNIQ([LIBS_GSSAPI],[$LIBS_KRB5 -lk5crypto $LIBS_COM_ERR $NETWORK_LIBS])
			SNERT_JOIN_UNIQ([CPPFLAGS_GSSAPI],[$CPPFLAGS_KRB5 $CPPFLAGS_COM_ERR])
			SNERT_JOIN_UNIQ([LDFLAGS_GSSAPI],[$LDFLAGS_KRB5 $LDFLAGS_COM_ERR])
			enable_gssapi="mit"
		])
	],[],[$LIBS_KRB5 -lk5crypto $LIBS_COM_ERR $NETWORK_LIBS])

	AS_UNSET([ac_cv_lib_gss_csf_gss_acq_user])
	AC_CHECK_LIB([gss],[csf_gss_acq_user],[
		AS_IF([test "$enable_gssapi" = 'auto' -o "$enable_gssapi" = 'cybersafe'],[
			SNERT_JOIN_UNIQ([LIBS_GSSAPI],[-lgss -lcstbk5 $NETWORK_LIBS])
			enable_gssapi="cybersafe03"
		])
	],[],[-lcstbk5])
	AS_UNSET([ac_cv_lib_gss_csf_gss_acq_user])
	AC_CHECK_LIB([gss],[csf_gss_acq_user],[
		AS_IF([test "$enable_gssapi" = 'auto' -o "$enable_gssapi" = 'cybersafe'],[
			SNERT_JOIN_UNIQ([LIBS_GSSAPI],[-lgss $NETWORK_LIBS])
			enable_gssapi="cybersafe"
		])
	])

	AS_UNSET([ac_cv_lib_gssapi_gss_unwrap])
	AC_CHECK_LIB([gss],[gss_unwrap],[
		AS_IF([test "$enable_gssapi" = 'auto' -o "$enable_gssapi" = 'seam'],[
			SNERT_JOIN_UNIQ([LIBS_GSSAPI],[-lgss $NETWORK_LIBS])
			enable_gssapi="seam"
		])
	])

	AC_MSG_CHECKING([for GSSAPI implementation])
	AC_MSG_RESULT([$enable_gssapi])

	CPPFLAGS="$save_CPPFLAGS"
	LDFLAGS="$save_LDFLAGS"
	LIBS="$save_LIBS"

	SNERT_DEFINE([LIBS_GSSAPI])
	SNERT_DEFINE([LDFLAGS_GSSAPI])
	SNERT_DEFINE([CPPFLAGS_GSSAPI])

 	AC_SUBST(LIBS_GSSAPI)
 	AC_SUBST(LDFLAGS_GSSAPI)
 	AC_SUBST(CPPFLAGS_GSSAPI)

	AH_VERBATIM(LIBS_GSSAPI,[
#undef HAVE_LIBGSS
#undef HAVE_LIBGSSAPI
#undef HAVE_LIBASN1
#undef HAVE_LIBROKEN
#undef HAVE_LIBGSSAPI_KRB5
#undef HAVE_LIBKRB5SUPPORT
#undef HAVE_APPSEC_RT_LIB_LIBGSS
#undef HAVE_GSSAPI_H
#undef HAVE_GSSAPI_GSSAPI_H
#undef HAVE_GSSAPI_GSSAPI_EXT_H
#undef HAVE_GSS_UNWRAP
#undef HAVE_KRB5INT_GETSPECIFIC
#undef HAVE_CSF_GSS_ACQ_USER
#undef CPPFLAGS_GSSAPI
#undef LDFLAGS_GSSAPI
#undef LIBS_GSSAPI
	])
])

AC_DEFUN([SNERT_OPTION_WITH_OPENSSL],[
	AC_ARG_WITH([openssl],[AS_HELP_STRING([--with-openssl=DIR],[OpenSSL package, optional base directory])])
	AC_ARG_WITH([openssl-inc],[AS_HELP_STRING([--with-openssl-inc=DIR],[...specific OpenSSL include directory])])
	AC_ARG_WITH([openssl-lib],[AS_HELP_STRING([--with-openssl-lib=DIR],[...specific OpenSSL library directory])])
])
AC_DEFUN([SNERT_OPENSSL],[
	AC_REQUIRE([SNERT_NETWORK])
	SNERT_CHECK_PACKAGE([SSL], dnl
		[openssl/ssl.h openssl/bio.h openssl/err.h openssl/crypto.h], dnl
		[libssl libcrypto],[SSL_library_init EVP_cleanup] dnl
		[$with_openssl],[$with_openssl_inc],[$with_openssl_lib] dnl
	)
	SNERT_CHECK_DEFINE(OpenSSL_add_all_algorithms, openssl/evp.h)
dnl 	AC_SUBST(LIBS_SSL)
dnl 	AC_SUBST(CPPFLAGS_SSL)
dnl 	AC_SUBST(LDFLAGS_SSL)
	AH_VERBATIM(LIBS_SSL,[
#undef HAVE_LIBSSL
#undef HAVE_LIBCRYPTO
#undef HAVE_OPENSSL_SSL_H
#undef HAVE_OPENSSL_BIO_H
#undef HAVE_OPENSSL_ERR_H
#undef HAVE_OPENSSL_CRYPTO_H
#undef HAVE_EVP_CLEANUP
#undef HAVE_SSL_LIBRARY_INIT
#undef HAVE_MACRO_OPENSSL_ADD_ALL_ALGORITHMS
#undef CPPFLAGS_SSL
#undef LDFLAGS_SSL
#undef LIBS_SSL
	])
])

AC_DEFUN(CYRUS_OPTION_WITH_OPENLDAP,[
	AC_ARG_WITH([openldap],[AS_HELP_STRING([--with-openldap=DIR],[OpenLDAP package, optional base directory])])
	AC_ARG_WITH([openldap-inc],[AS_HELP_STRING([--with-openldap-inc=DIR],[...specific OpenLDAP include directory])])
	AC_ARG_WITH([openldap-lib],[AS_HELP_STRING([--with-openldap-lib=DIR],[...specific OpenLDAP library directory])])
])
AC_DEFUN(CYRUS_OPENLDAP,[
	SNERT_CHECK_PACKAGE([LDAP], dnl
		[lber.h lber_types.h ldap.h ldap_cdefs.h ldap_features.h ldap_schema.h ldap_utf8.h ldif.h slapi-plugin.h], dnl
		[libldap],[ldap_initialize], dnl
		[$with_openldap],[$with_openldap_inc],[$with_openldap_lib] dnl
	)
dnl 	AC_SUBST(LIBS_LDAP)
dnl 	AC_SUBST(CPPFLAGS_LDAP)
dnl 	AC_SUBST(LDFLAGS_LDAP)
	AH_VERBATIM(LIBS_LDAP,[
#undef HAVE_LIBLDAP
#undef HAVE_LBER_H
#undef HAVE_LBER_TYPES_H
#undef HAVE_LDAP_H
#undef HAVE_LDAP_CDEFS_H
#undef HAVE_LDAP_FEATURES_H
#undef HAVE_LDAP_SCHEMA_H
#undef HAVE_LDAP_UTF8_H
#undef HAVE_LDIF_H
#undef HAVE_SLAPI_PLUGIN_H
#undef HAVE_LDAP_INITIALIZE
#undef CPPFLAGS_LDAP
#undef LDFLAGS_LDAP
#undef LIBS_LDAP
	])
])

AC_DEFUN(CYRUS_OPTION_WITH_OPENAFS,[
	AC_ARG_WITH([openafs],[AS_HELP_STRING([--with-openafs=DIR],[OpenAFS package, optional base directory])])
	AC_ARG_WITH([openafs-inc],[AS_HELP_STRING([--with-openafs-inc=DIR],[...specific OpenAFS include directory])])
	AC_ARG_WITH([openafs-lib],[AS_HELP_STRING([--with-openafs-lib=DIR],[...specific OpenAFS library directory])])
])
AC_DEFUN(CYRUS_OPENAFS,[
	AC_REQUIRE([CYRUS_KRB5])
	SNERT_CHECK_PACKAGE([AFS], dnl
		[afs/afs.h afs/afsutil.h afs/auth.h afs/cellconfig.h afs/com_err.h afs/ptserver.h afs/pterror.h], dnl
		[afs/libkauth.a afs/libafscom_err afs/libauth afs/libprot afs/libsys dnl
		 afs/libafsutil afs/util.a libafslwp liblwp librxkad librx libubik],[], dnl
		[$with_openafs],[$with_openafs_inc],[$with_openafs_lib],[],[no]dnl
	)

	dnl Do we have BOTH libafsutil and util.a, which are the same library? Remove the latter.
	AS_IF([test "$HAVE_AFS_LIBAFSUTIL" != 'no' -a "$HAVE_AFS_UTIL_A" != 'no'],[
		LIBS_AFS=`echo $LIBS_AFS | sed -e's, [[^ ]][[^ ]]*afs/util\.a,,'`
	])

	AS_IF([test "$HAVE_AFS_LIBAFSUTIL" != 'no' -o "$HAVE_AFS_UTIL_A" != 'no'],[
		dnl libafsutil references krb5_* functions.
		SNERT_JOIN_UNIQ([LIBS_AFS],[$LIBS_KRB5])
		SNERT_JOIN_UNIQ([LDFLAGS_AFS],[$LDFLAGS_KRB5])
		SNERT_JOIN_UNIQ([CPPFLAGS_AFS],[$CPPFLAGS_KRB5])
	])

	AC_PATH_PROG([AFS_COMPILE_ET],[afs_compile_et],[false])
	AC_DEFINE_UNQUOTED([HAVE_AFS_COMPILE_ET],[$AFS_COMPILE_ET],[OpenAFS supplies a compile_et.])
	AC_SUBST([AFS_COMPILE_ET])

 	SNERT_DEFINE(LIBS_AFS)
 	SNERT_DEFINE(LDFLAGS_AFS)
 	SNERT_DEFINE(CPPFLAGS_AFS)

 	AC_SUBST(LIBS_AFS)
 	AC_SUBST(LDFLAGS_AFS)
 	AC_SUBST(CPPFLAGS_AFS)

	dnl Note libafsutil.a same as util.a.
 	AH_VERBATIM(CPPFLAGS_AFS,[
#undef HAVE_AFS_AFS_H
#undef HAVE_AFS_AUTH_H
#undef HAVE_AFS_AFSUTIL_H
#undef HAVE_AFS_CELLCONFIG_H
#undef HAVE_AFS_COM_ERR_H
#undef HAVE_AFS_COMPILE_ET
#undef HAVE_AFS_PTSERVER_H
#undef HAVE_AFS_PTERROR_H
#undef HAVE_AFS_LIBKAUTH_A
#undef HAVE_AFS_LIBAFSCOM_ERR
#undef HAVE_AFS_LIBAUTH
#undef HAVE_AFS_LIBPROT
#undef HAVE_AFS_LIBSYS
#undef HAVE_AFS_LIBAFSUTIL
#undef HAVE_AFS_UTIL_A
#undef HAVE_LIBAFSLWP
#undef HAVE_LIBLWP
#undef HAVE_LIBRXKAD
#undef HAVE_LIBRX
#undef HAVE_LIBUBIK
#undef CPPFLAGS_AFS
#undef LDFLAGS_AFS
#undef LIBS_AFS
	])
])

AC_DEFUN(CYRUS_OPTION_WITH_OPENDKIM,[
	AC_ARG_WITH([opendkim],[AS_HELP_STRING([--with-opendkim=DIR],[OpenDKIM package, optional base directory])])
	AC_ARG_WITH([opendkim-inc],[AS_HELP_STRING([--with-opendkim-inc=DIR],[...specific OpenDKIM include directory])])
	AC_ARG_WITH([opendkim-lib],[AS_HELP_STRING([--with-opendkim-lib=DIR],[...specific OpenDKIM library directory])])
])
AC_DEFUN(CYRUS_OPENDKIM,[
	SNERT_CHECK_PACKAGE([DKIM],[opendkim/dkim.h dkim.h],[libopendkim],[dkim_init], dnl
		[$with_opendkim],[$with_opendkim_inc],[$with_opendkim_lib] dnl
	)
dnl 	AC_SUBST(LIBS_DKIM)
dnl 	AC_SUBST(CPPFLAGS_DKIM)
dnl 	AC_SUBST(LDFLAGS_DKIM)
	AH_VERBATIM(LIBS_DKIM,[
#undef HAVE_LIBOPENDKIM
#undef HAVE_OPENDKIM_DKIM_H
#undef HAVE_DKIM_H
#undef HAVE_DKIM_INIT
#undef CPPFLAGS_DKIM
#undef LDFLAGS_DKIM
#undef LIBS_DKIM
	])
])

AC_DEFUN([CYRUS_OPTION_WITH_CLAMAV],[
	AC_ARG_WITH([clamav],[AS_HELP_STRING([--with-clamav=DIR],[ClamAV package, optional base directory])])
	AC_ARG_WITH([clamav-inc],[AS_HELP_STRING([--with-clamav-inc=DIR],[...specific ClamAV include directory])])
	AC_ARG_WITH([clamav-lib],[AS_HELP_STRING([--with-clamav-lib=DIR],[...specific ClamAV library directory])])
])
AC_DEFUN([CYRUS_CLAMAV],[
	SNERT_CHECK_PACKAGE([CLAMAV],[clamav.h],[libclamav],[cl_init cl_engine_new], dnl
		[$with_clamav],[$with_clamav_inc],[$with_clamav_lib] dnl
	)
dnl 	AC_SUBST(LIBS_CLAMAV)
dnl 	AC_SUBST(CPPFLAGS_CLAMAV)
dnl 	AC_SUBST(LDFLAGS_CLAMAV)
	AH_VERBATIM(LIBS_CLAMAV,[
#undef HAVE_CLAMAV_H
#undef HAVE_CL_INIT
#undef HAVE_CL_ENGINE_NEW
#undef CPPFLAGS_CLAMAV
#undef LDFLAGS_CLAMAV
#undef LIBS_CLAMAV
	])
])

AC_DEFUN([CYRUS_OPTION_WITH_ZEPHYR],[
	AC_ARG_WITH([zephyr],[AS_HELP_STRING([--with-zephyr=DIR],[Zephyr notification package, optional base directory])])
	AC_ARG_WITH([zephyr-inc],[AS_HELP_STRING([--with-zephyr-inc=DIR],[...specific Zephyr include directory])])
	AC_ARG_WITH([zephyr-lib],[AS_HELP_STRING([--with-zephyr-lib=DIR],[...specific Zephyr library directory])])
])
AC_DEFUN([CYRUS_ZEPHYR],[
	AC_REQUIRE([CYRUS_KRB4])
	save_zephyr_LIBS="$LIBS"
	LIBS="$LIBS_KRB4 $LIBS"
	SNERT_CHECK_PACKAGE([ZEPHYR],[zephyr/zephyr.h],[libzephyr],[ZInitialize], dnl
		[$with_zephyr],[$with_zephyr_inc],[$with_zephyr_lib],[],[no] dnl
	)
	LIBS="$save_zephyr_LIBS"

	AS_IF([test "$ac_cv_func_ZInitialize" = 'yes'],[
		SNERT_JOIN_UNIQ([CPPFLAGS_ZEPHYR],[$CPPFLAGS_KRB4])
		SNERT_JOIN_UNIQ([LDFLAGS_ZEPHYR],[$LDFLAGS_KRB4])
		SNERT_JOIN_UNIQ([LIBS_ZEPHYR],[$LIBS_KRB4])
	])

 	SNERT_DEFINE(LIBS_ZEPHYR)
 	SNERT_DEFINE(LDFLAGS_ZEPHYR)
 	SNERT_DEFINE(CPPFLAGS_ZEPHYR)

 	AC_SUBST(LIBS_ZEPHYR)
 	AC_SUBST(LDFLAGS_ZEPHYR)
 	AC_SUBST(CPPFLAGS_ZEPHYR)

	AH_VERBATIM(LIBS_ZEPHYR,[
#undef HAVE_ZEPHYR_ZEPHYR_H
#undef HAVE_ZINITIALIZE
#undef CPPFLAGS_ZEPHYR
#undef LDFLAGS_ZEPHYR
#undef LIBS_ZEPHYR
	])
])

AC_DEFUN([CYRUS_OPTION_WITH_JANSSON],[
	AC_ARG_WITH([jansson],[AS_HELP_STRING([--with-jansson=dir],[Jansson package, optional base directory])])
	AC_ARG_WITH([jansson-inc],[AS_HELP_STRING([--with-jansson-inc=dir],[...specific Jansson include directory])])
	AC_ARG_WITH([jansson-lib],[AS_HELP_STRING([--with-jansson-lib=dir],[...specific Jansson library directory])])
])
AC_DEFUN([CYRUS_JANSSON],[
	SNERT_CHECK_PACKAGE([JANSSON],[jansson.h],[libjansson],[json_object json_string], dnl
		[$with_jansson],[$with_jansson_inc],[$with_jansson_lib] dnl
	)
dnl 	AC_SUBST(LIBS_JANSSON)
dnl 	AC_SUBST(CPPFLAGS_JANSSON)
dnl 	AC_SUBST(LDFLAGS_JANSSON)
	AH_VERBATIM(LIBS_JANSSON,[
#undef HAVE_JANSSON_H
#undef HAVE_JSON_OBJECT
#undef HAVE_JSON_STRING
#undef CPPFLAGS_JANSSON
#undef LDFLAGS_JANSSON
#undef LIBS_JANSSON
	])
])

AC_DEFUN([CYRUS_OPTION_WITH_COM_ERR],[
	AC_ARG_WITH([com_err],[AS_HELP_STRING([--with-com_err=dir],[com_err API, optional base directory])])
	AC_ARG_WITH([com_err-bin],[AS_HELP_STRING([--with-com_err-bin=dir],[...specific com_err binary directory])])
	AC_ARG_WITH([com_err-inc],[AS_HELP_STRING([--with-com_err-inc=dir],[...specific com_err include directory])])
	AC_ARG_WITH([com_err-lib],[AS_HELP_STRING([--with-com_err-lib=dir],[...specific com_err library directory])])
])
AC_DEFUN([CYRUS_COM_ERR],[
	dnl
	dnl Try and find a system version of com_err.
	dnl If we see something that looks a little wacky, ignore it (there are many
	dnl deficient installs of com_err, unfortunately, which leave out compile_et)
	dnl There is also a broken re-implementation of compile_et, apparently derived
	dnl from the Kerberos project, being shipped in /usr/bin on MacOS X, see Bug #3711.
	dnl
	SNERT_CHECK_PACKAGE([COM_ERR], dnl
		[et/com_err.h krb5/com_err.h com_err.h],[libcom_err],[com_err], dnl
		[$with_com_err],[$with_com_err_inc],[$with_com_err_lib],[[
#ifdef __NetBSD__
/* NetBSD /usr/include/krb5/com_err.h requires these extras. */
#include <stdlib.h>
#include <stdarg.h>
#endif
	]],[no])

	dnl Search for compile_et(1), but if not found fall back to false(1),
	dnl force the use of the builtin version.
	AC_PATH_PROG([COMPILE_ET],[compile_et],[false],[${with_com_err_bin:+$with_com_err_bin$PATH_SEPARATOR}$PATH])
	AS_IF([test "$COMPILE_ET" = '/usr/pkg/bin/compile_et'],[
		dnl NetBSD: Part of kth-krb4 required by Zephyr.  Suspect?
		dnl What of OpenAFS com_err library and its tool?
		dnl
		dnl Discard any found flags in favour of built-in.
		AS_UNSET([LIBS_COM_ERR])
		AS_UNSET([LDFLAGS_COM_ERR])
		AS_UNSET([CPPFLAGS_COM_ERR])
		COMPILE_ET='false'
	])

	SNERT_DEFINE([COMPILE_ET])
	SNERT_DEFINE([LIBS_COM_ERR])
	SNERT_DEFINE([LDFLAGS_COM_ERR])
	SNERT_DEFINE([CPPFLAGS_COM_ERR])

	AC_SUBST(COMPILE_ET)
 	AC_SUBST(LIBS_COM_ERR)
 	AC_SUBST(LDFLAGS_COM_ERR)
 	AC_SUBST(CPPFLAGS_COM_ERR)

	AH_VERBATIM(LIBS_COM_ERR,[
#undef HAVE_ET_COM_ERR_H
#undef HAVE_KRB5_COM_ERR_H
#undef HAVE_COM_ERR_H
#undef HAVE_COM_ERR
#undef COMPILE_ET
#undef CPPFLAGS_COM_ERR
#undef LDFLAGS_COM_ERR
#undef LIBS_COM_ERR
	])
])

dnl
dnl SNERT_PCRE
dnl
AC_DEFUN(SNERT_PCRE,[
	dnl Redo function tests; see SNERT_REGEX.
	AS_UNSET(ac_cv_func_regcomp)
	AS_UNSET(ac_cv_func_regexec)
	AS_UNSET(ac_cv_func_regerror)
	AS_UNSET(ac_cv_func_regfree)
	SNERT_CHECK_PACKAGE([PCRE], dnl
		[pcre.h pcreposix.h],[libpcre libpcreposix], dnl
		[pcre_compile pcre_exec pcre_free regcomp regexec regerror regfree] dnl
		[$with_pcre],[$with_pcre_inc],[$with_pcre_lib] dnl
	)
dnl 	AC_SUBST(LIBS_PCRE)
dnl 	AC_SUBST(CPPFLAGS_PCRE)
dnl 	AC_SUBST(LDFLAGS_PCRE)
	AH_VERBATIM(LIBS_PCRE,[
#undef HAVE_PCRE_H
#undef HAVE_PCREPOSIX_H
#undef HAVE_LIBPCRE
#undef HAVE_LIBPCREPOSIX
#undef HAVE_PCRE_COMPILE
#undef HAVE_PCRE_EXEC
#undef HAVE_PCRE_FREE
#undef HAVE_REGCOMP
#undef HAVE_REGEXEC
#undef HAVE_REGERROR
#undef HAVE_REGFREE
#undef CPPFLAGS_PCRE
#undef LDFLAGS_PCRE
#undef LIBS_PCRE
	])
])

AC_DEFUN([SNERT_OPTION_WITH_ZLIB],[
	AC_ARG_WITH([zlib],[AS_HELP_STRING([--with-zlib=dir],[zlib package, optional base directory])])
	AC_ARG_WITH([zlib-inc],[AS_HELP_STRING([--with-zlib-inc=dir],[...specific zlib include directory])])
	AC_ARG_WITH([zlib-lib],[AS_HELP_STRING([--with-zlib-lib=dir],[...specific zlib library directory])])
])
AC_DEFUN([SNERT_ZLIB],[
	SNERT_CHECK_PACKAGE([ZLIB],[zlib.h],[libz],[deflate], dnl
		[$with_zlib],[$with_zlib_inc],[$with_zlib_lib] dnl
	)
dnl 	AC_SUBST(LIBS_ZLIB)
dnl 	AC_SUBST(CPPFLAGS_ZLIB)
dnl 	AC_SUBST(LDFLAGS_ZLIB)
	AH_VERBATIM(LIBS_ZLIB,[
#undef HAVE_ZLIB_H
#undef HAVE_LIBZ
#undef HAVE_DEFLATE
#undef CPPFLAGS_ZLIB
#undef LDFLAGS_ZLIB
#undef LIBS_ZLIB
	])
])

AC_DEFUN([CYRUS_UUID],[
	SNERT_CHECK_PACKAGE([UUID],[uuid/uuid.h uuid.h],[libuuid],[uuid_generate], dnl
		[$with_uuid],[$with_uuid_inc],[$with_uuid_lib],[],[no] dnl
	)

	dnl NetBSD comes with a stock libuuid with a different API
	dnl from the Linux version, which is a 3rd party package.
	AS_IF([test "$ac_cv_func_uuid_generate" = 'no'],[
		AS_UNSET([LIBS_UUID])
		AS_UNSET([LDFLAGS_UUID])
		AS_UNSET([CPPFLAGS_UUID])
		AC_MSG_WARN([Did not find Linux libuuid API.])
	])

	SNERT_DEFINE([LIBS_UUID])
	SNERT_DEFINE([LDFLAGS_UUID])
	SNERT_DEFINE([CPPFLAGS_UUID])

	AC_SUBST(LIBS_UUID)
 	AC_SUBST(CPPFLAGS_UUID)
 	AC_SUBST(LDFLAGS_UUID)

	AH_VERBATIM(LIBS_UUID,[
#undef HAVE_UUID_H
#undef HAVE_UUID_UUID_H
#undef HAVE_LIBUUID
#undef HAVE_UUID_GENERATE
#undef CPPFLAGS_UUID
#undef LDFLAGS_UUID
#undef LIBS_UUID
	])
])

AC_DEFUN([CYRUS_ICAL],[
	SNERT_CHECK_PACKAGE([ICAL],[libical/ical.h ical.h],[libical],[icalcomponent_new], dnl
		[$with_ical],[$with_ical_inc],[$with_ical_lib] dnl
	)
dnl 	AC_SUBST(LIBS_ICAL)
dnl 	AC_SUBST(CPPFLAGS_ICAL)
dnl 	AC_SUBST(LDFLAGS_ICAL)
	AH_VERBATIM(LIBS_ICAL,[
#undef HAVE_ICAL_H
#undef HAVE_LIBICAL_ICAL_H
#undef HAVE_LIBICAL
#undef HAVE_ICALCOMPONENT_NEW
#undef CPPFLAGS_ICAL
#undef LDFLAGS_ICAL
#undef LIBS_ICAL
	])
])

AC_DEFUN([CYRUS_XML2],[
	dnl Some odd reason we have two directory levels for the package,
	dnl but refer to in package source as #include <libxml/tree.h>.
	dnl The package's own headers reference themselves by
	dnl #include <libxml/SOME_HEADER>, so we need an explicit -I
	dnl include directory.
	AS_CASE([$target_os],
	[netbsd*],[
		with_xml2_inc='/usr/pkg/include/libxml2'
	],[
		dnl Assuming Linux layout.
		with_xml2_inc='/usr/include/libxml2'
	])

	SNERT_CHECK_PACKAGE([XML2],[libxml/tree.h],[libxml2],[xmlNewParserCtxt], dnl
		[$with_xml2],[$with_xml2_inc],[$with_xml2_lib] dnl
	)
dnl 	AC_SUBST(LIBS_XML2)
dnl 	AC_SUBST(CPPFLAGS_XML2)
dnl 	AC_SUBST(LDFLAGS_XML2)

	AH_VERBATIM(LIBS_XML2,[
#undef HAVE_LIBXML_TREE_H
#undef HAVE_LIBXML2
#undef HAVE_XMLNEWPARSERCTXT
#undef CPPFLAGS_XML2
#undef LDFLAGS_XML2
#undef LIBS_XML2
	])
])

AC_DEFUN([CYRUS_ICU],[
	SNERT_CHECK_PACKAGE([ICU],[unicode/ucal.h],[libicui18n],[ucal_open], dnl
		[$with_icu],[$with_icu_inc],[$with_icu_lib] dnl
	)
dnl 	AC_SUBST(LIBS_ICU)
dnl 	AC_SUBST(CPPFLAGS_ICU)
dnl 	AC_SUBST(LDFLAGS_ICU)
	AH_VERBATIM(LIBS_ICU,[
#undef HAVE_UNICODE_UCAL_H
#undef HAVE_LIBICUI18N
#undef HAVE_UCAL_OPEN
#undef CPPFLAGS_ICU
#undef LDFLAGS_ICU
#undef LIBS_ICU
	])
])

AC_DEFUN([CYRUS_CAP],[
	dnl Linux specific library.
	SNERT_CHECK_PACKAGE([CAP],[sys/capability.h sys/prctl.h],[libcap],dnl
		[cap_free cap_from_name cap_from_text cap_get_pid cap_get_proc dnl
		 cap_set_proc cap_to_name cap_to_text],dnl
		[$with_libcap]
	)
dnl 	AC_SUBST(LIBS_CAP)
dnl 	AC_SUBST(CPPFLAGS_CAP)
dnl 	AC_SUBST(LDFLAGS_CAP)
	AH_VERBATIM(LIBS_CAP,[
#undef HAVE_SYS_CAPABILITY_H
#undef HAVE_SYS_PRCTL_H
#undef HAVE_LIBCAP
#undef HAVE_CAP_FREE
#undef HAVE_CAP_FROM_NAME
#undef HAVE_CAP_FROM_TEXT
#undef HAVE_CAP_GET_PID
#undef HAVE_CAP_GET_PROC
#undef HAVE_CAP_SET_PROC
#undef HAVE_CAP_TO_NAME
#undef HAVE_CAP_TO_TEXT
#undef CPPFLAGS_CAP
#undef LDFLAGS_CAP
#undef LIBS_CAP
	])
])

AC_DEFUN([CYRUS_OPTION_WITH_CUNIT],[
	AC_ARG_WITH([cunit],[AS_HELP_STRING([--with-cunit=dir],[CUnit package, optional base directory])])
	AC_ARG_WITH([cunit-inc],[AS_HELP_STRING([--with-cunit-inc=dir],[...specific CUnit include directory])])
	AC_ARG_WITH([cunit-lib],[AS_HELP_STRING([--with-cunit-lib=dir],[...specific CUnit library directory])])
])
AC_DEFUN([CYRUS_CUNIT],[
	SNERT_CHECK_PACKAGE([CUNIT], dnl
		[CUnit/CUnit.h CUnit/Basic.h], dnl
		[libcunit],[], dnl
		[$with_cunit],[$with_cunit_inc],[$with_cunit_lib] dnl
	)

	save_LIBS="$LIBS"
	save_LDFLAGS="$LDFLAGS"
	save_CPPFLAGS="$CPPFLAGS"

	LIBS="$LIBS_CUNIT $LIBS"
	LDFLAGS="$LDFLAGS_CUNIT $LDFLAGS"
	CPPFLAGS="$CPPFLAGS_CUNIT $CPPFLAGS"

	AC_CHECK_HEADER([CUnit/Basic.h],[
		AC_CHECK_TYPES([CU_SetUpFunc],[],[],[
#include <CUnit/Basic.h>
		])
	])

	CPPFLAGS="$save_CPPFLAGS"
	LDFLAGS="$save_LDFLAGS"
	LIBS="$save_LIBS"

dnl 	AC_SUBST(LIBS_CUNIT)
dnl 	AC_SUBST(CPPFLAGS_CUNIT)
dnl 	AC_SUBST(LDFLAGS_CUNIT)
	AH_VERBATIM(LIBS_CUNIT,[
#undef HAVE_CUNIT_CUNIT_H
#undef HAVE_CUNIT_BASIC_H
#undef HAVE_LIBCUNIT
#undef CPPFLAGS_CUNIT
#undef LDFLAGS_CUNIT
#undef LIBS_CUNIT
	])
])

# visibility.m4 serial 5 (gettext-0.18.2)
dnl Copyright (C) 2005, 2008, 2010-2012 Free Software Foundation, Inc.
dnl This file is free software; the Free Software Foundation
dnl gives unlimited permission to copy and/or distribute it,
dnl with or without modifications, as long as this notice is preserved.

dnl From Bruno Haible.

dnl Tests whether the compiler supports the command-line option
dnl -fvisibility=hidden and the function and variable attributes
dnl __attribute__((__visibility__("hidden"))) and
dnl __attribute__((__visibility__("default"))).
dnl Does *not* test for __visibility__("protected") - which has tricky
dnl semantics (see the 'vismain' test in glibc) and does not exist e.g. on
dnl Mac OS X.
dnl Does *not* test for __visibility__("internal") - which has processor
dnl dependent semantics.
dnl Does *not* test for #pragma GCC visibility push(hidden) - which is
dnl "really only recommended for legacy code".
dnl Set the variable CFLAG_VISIBILITY.
dnl Defines and sets the variable HAVE_VISIBILITY.

AC_DEFUN([gl_VISIBILITY],
[
  AC_REQUIRE([AC_PROG_CC])
  CFLAG_VISIBILITY=
  HAVE_VISIBILITY=0
  if test -n "$GCC"; then
    dnl First, check whether -Werror can be added to the command line, or
    dnl whether it leads to an error because of some other option that the
    dnl user has put into $CC $CFLAGS $CPPFLAGS.
    AC_MSG_CHECKING([whether the -Werror option is usable])
    AC_CACHE_VAL([gl_cv_cc_vis_werror], [
      gl_save_CFLAGS="$CFLAGS"
      CFLAGS="$CFLAGS -Werror"
      AC_COMPILE_IFELSE(
        [AC_LANG_PROGRAM([[]], [[]])],
        [gl_cv_cc_vis_werror=yes],
        [gl_cv_cc_vis_werror=no])
      CFLAGS="$gl_save_CFLAGS"])
    AC_MSG_RESULT([$gl_cv_cc_vis_werror])
    dnl Now check whether visibility declarations are supported.
    AC_MSG_CHECKING([for simple visibility declarations])
    AC_CACHE_VAL([gl_cv_cc_visibility], [
      gl_save_CFLAGS="$CFLAGS"
      CFLAGS="$CFLAGS -fvisibility=hidden"
      dnl We use the option -Werror and a function dummyfunc, because on some
      dnl platforms (Cygwin 1.7) the use of -fvisibility triggers a warning
      dnl "visibility attribute not supported in this configuration; ignored"
      dnl at the first function definition in every compilation unit, and we
      dnl don't want to use the option in this case.
      if test $gl_cv_cc_vis_werror = yes; then
        CFLAGS="$CFLAGS -Werror"
      fi
      AC_COMPILE_IFELSE(
        [AC_LANG_PROGRAM(
           [[extern __attribute__((__visibility__("hidden"))) int hiddenvar;
             extern __attribute__((__visibility__("default"))) int exportedvar;
             extern __attribute__((__visibility__("hidden"))) int hiddenfunc (void);
             extern __attribute__((__visibility__("default"))) int exportedfunc (void);
             void dummyfunc (void) {}
           ]],
           [[]])],
        [gl_cv_cc_visibility=yes],
        [gl_cv_cc_visibility=no])
      CFLAGS="$gl_save_CFLAGS"])
    AC_MSG_RESULT([$gl_cv_cc_visibility])
    if test $gl_cv_cc_visibility = yes; then
      CFLAG_VISIBILITY="-fvisibility=hidden"
      HAVE_VISIBILITY=1
    fi
  fi
  AC_SUBST([CFLAG_VISIBILITY])
  AC_SUBST([HAVE_VISIBILITY])
  AC_DEFINE_UNQUOTED([HAVE_VISIBILITY], [$HAVE_VISIBILITY],
    [Define to 1 or 0, depending whether the compiler supports simple visibility declarations.])
])

dnl
dnl CMU_PERL_MAKEMAKER(perl_pkg)
dnl
AC_DEFUN([CMU_PERL_MAKEMAKER],[
	AS_IF([test -e "$PERL"],[
		AS_ECHO("Preparing $1 ...")
		AC_CONFIG_FILES([$1/Makefile.PL])
		AC_CONFIG_COMMANDS($1/Makefile,[
			( cd $1; $PERL Makefile.PL $MAKE_MAKER_ARGS )
		],[
			PERL="${PERL}"
			MAKE_MAKER_ARGS="PREFIX=${prefix}"
		])
	])
])

AC_DEFUN(CYRUS_OPTION_WITH_XAPIAN,[
	AC_ARG_WITH([xapian],[AS_HELP_STRING([--with-xapian=DIR],[Xapian package, optional base directory])])
	AC_ARG_WITH([xapian-inc],[AS_HELP_STRING([--with-xapian-inc=dir],[...specific Xapian include directory])])
	AC_ARG_WITH([xapian-lib],[AS_HELP_STRING([--with-xapian-lib=dir],[...specific Xapian library directory])])
])
AC_DEFUN(CYRUS_XAPIAN,[
	SNERT_CHECK_PACKAGE([XAPIAN],[xapian.h],[libxapian],[], dnl
		[$with_xapian],[$with_xapian_inc],[$with_xapian_lib],[],[no]dnl
	)

	AC_ARG_VAR([XAPIAN_CONFIG],[Location of xapian-config])
	AC_PATH_PROG([XAPIAN_CONFIG],[xapian-config],[false])
	AS_IF([test "$XAPIAN_CONFIG" = 'false'],[
		with_xapian='no'
		AS_UNSET([LIBS_XAPIAN])
		AS_UNSET([LDFLAGS_XAPIAN])
		AS_UNSET([CPPFLAGS_XAPIAN])
		AC_MSG_WARN([xapian-config not found, disabling.])
	],[
		dnl Override found flags with those supplied by tool.
		CXXFLAGS_XAPIAN=`$XAPIAN_CONFIG --cxxflags`
		CPPFLAGS_XAPIAN="$CXXFLAGS_XAPIAN"

		dnl Pass magic option so xapian-config knows we called it (so it
		dnl can choose a more appropriate error message if asked to link
		dnl with an uninstalled libxapian). Also pass ac_top_srcdir
		dnl so the error message can correctly say "configure.ac" or
		dnl "configure.in" according to which is in use.
		LIBS_XAPIAN=`ac_top_srcdir="$ac_top_srcdir" $XAPIAN_CONFIG --from-xo-lib-xapian --libs`
	])

	SNERT_DEFINE([LIBS_XAPIAN])
	SNERT_DEFINE([LDFLAGS_XAPIAN])
	SNERT_DEFINE([CPPFLAGS_XAPIAN])
	SNERT_DEFINE([CXXFLAGS_XAPIAN])

 	AC_SUBST(LIBS_XAPIAN)
 	AC_SUBST(LDFLAGS_XAPIAN)
 	AC_SUBST(CPPFLAGS_XAPIAN)
 	AC_SUBST(CXXFLAGS_XAPIAN)

	AH_VERBATIM(LIBS_XAPIAN,[
#undef HAVE_LIBXAPIAN
#undef HAVE_XAPIAN_H
#undef CXXFLAGS_XAPIAN
#undef CPPFLAGS_XAPIAN
#undef LDFLAGS_XAPIAN
#undef LIBS_XAPIAN
	])
])


dnl telnet.m4--telnet special macros
dnl Derrick Brashear
dnl $Id: telnet.m4,v 1.13 2006/02/25 18:36:36 cg2v Exp $

AC_DEFUN([CMU_TELNET_WHICH_TERM], [
AC_CHECK_LIB(termlib, setupterm, [
AC_DEFINE(HAVE_SETUPTERM,, [Define to 1 if you have the `setupterm' function.]) 
AC_CHECK_LIB(c, setupterm, TCLIB="/usr/ccs/lib/libtermlib.a",TCLIB="-ltermlib","/usr/ccs/lib/libtermlib.a")
],  TCLIB="-ltermcap")
])

AC_DEFUN([CMU_TELNET_CC_T], 
[
AC_MSG_CHECKING(for cc_t definition)
AC_CACHE_VAL(cmu_cv_cc_t_definition, [
AC_TRY_COMPILE(
[
#ifdef HAVE_SYS_TERMIOS_H
#include <sys/termios.h>
#else
#ifdef HAVE_SYS_TERMIO_H
#include <sys/termio.h>
#endif
#endif
],
[cc_t ffoo;],
cmu_cv_cc_t_definition=yes,
cmu_cv_cc_t_definition=no)
])
if test "$cmu_cv_cc_t_definition" = "no"; then
        AC_DEFINE(NO_CC_T,, [The type `cc_t' is not available])
fi
AC_MSG_RESULT($cmu_cv_cc_t_definition)
])

AC_DEFUN([CMU_STREAMS], [
if test "$ac_cv_header_sys_stropts_h" = "yes" -o "$ac_cv_header_stropts_h" = "yes"; then 
	AC_DEFINE(HAVE_STREAMS,, [STREAMS are available])dnl
fi
])

AC_DEFUN([CMU_TERMIO_MODEL], [
if test "$ac_cv_header_sys_termio_h" = "yes" -o "$ac_cv_header_sys_termios_h" = "yes"; then 
	AC_DEFINE(USE_TERMIO,, [Use termios for tty configuration])dnl
	if test "$ac_cv_header_sys_termios_h" = "no"; then
		AC_DEFINE(SYSV_TERMIO,, [Use SysV termios])dnl
	fi
fi
])

AC_DEFUN([CMU_TELNET_DES_STRING_TO_KEY_PROTO], [
AC_MSG_CHECKING(for des_string_to_key prototype)
AC_CACHE_VAL(cmu_cv_des_string_to_key_proto, [
AC_TRY_COMPILE(
[#include <des.h>
typedef unsigned char Block[8];
int  des_string_to_key(char *, Block);],
[int foo = des_string_to_key(NULL, NULL);],
cmu_cv_des_string_to_key_proto=no,
cmu_cv_des_string_to_key_proto=yes)
])
if test "$cmu_cv_des_string_to_key_proto" = yes; then
        AC_DEFINE(HAVE_DES_STRING_TO_KEY_PROTO,, [define to 1 if `des_string_to_key' has a prototype])dnl
fi
AC_MSG_RESULT($cmu_cv_des_string_to_key_proto)
])

AC_DEFUN([CMU_TELNET_DES_KEY_SCHED_PROTO], [
AC_MSG_CHECKING(for des_key_sched prototype)
AC_CACHE_VAL(cmu_cv_des_key_sched_proto, [
AC_TRY_COMPILE(
[
#include <des.h>
char des_key_sched(int foo, int bar);
],
[des_key_sched(NULL, NULL);],
cmu_cv_des_key_sched_proto=no,
cmu_cv_des_key_sched_proto=yes)
])
if test "$cmu_cv_des_key_sched_proto" = yes; then
        AC_DEFINE(HAVE_DES_KEY_SCHED_PROTO,, [define to 1 if `des_key_sched' has a prototype])dnl
fi
AC_MSG_RESULT($cmu_cv_des_key_sched_proto)
])

AC_DEFUN([CMU_TELNET_DES_SET_RANDOM_GENERATOR_SEED_PROTO], [
AC_MSG_CHECKING(for des_set_random_generator_seed prototype)
AC_CACHE_VAL(cmu_cv_des_set_random_generator_seed_proto, [
AC_TRY_COMPILE(
[
#include <des.h>
char des_set_random_generator_seed(int foo, int bar);
],
[des_set_random_generator_seed(NULL, NULL);],
cmu_cv_des_set_random_generator_seed_proto=no,
cmu_cv_des_set_random_generator_seed_proto=yes)
])
if test "$cmu_cv_des_set_random_generator_seed_proto" = yes; then
        AC_DEFINE(HAVE_DES_SET_RANDOM_GENERATOR_SEED_PROTO,, [define to 1 if `des_set_random_generator_seed' has a prototype])dnl
fi
AC_MSG_RESULT($cmu_cv_des_set_random_generator_seed_proto)
])

AC_DEFUN([CMU_TELNET_DES_NEW_RANDOM_KEY_PROTO], [
AC_MSG_CHECKING(for des_new_random_key prototype)
AC_CACHE_VAL(cmu_cv_des_new_random_key_proto, [
AC_TRY_COMPILE(
[
#include <des.h>
char des_new_random_key(int foo, int bar);
],
[des_new_random_key(NULL, NULL);],
cmu_cv_des_new_random_key_proto=no,
cmu_cv_des_new_random_key_proto=yes)
])
if test "$cmu_cv_des_new_random_key_proto" = yes; then
        AC_DEFINE(HAVE_DES_NEW_RANDOM_KEY_PROTO,, [define to 1 if `des_new_random_key' has a prototype])dnl
fi
AC_MSG_RESULT($cmu_cv_des_new_random_key_proto)
])

AC_DEFUN([CMU_TELNET_DES_ECB_ENCRYPT_PROTO], [
AC_MSG_CHECKING(for des_ecb_encrypt prototype)
AC_CACHE_VAL(cmu_cv_des_ecb_encrypt_proto, [
AC_TRY_COMPILE(
[#include <des.h>
typedef unsigned char Block[8];
typedef struct { Block _; } Schedule[16];
void des_ecb_encrypt(Block, Block, Schedule, int);],
[int foo = des_ecb_encrypt(NULL, NULL, NULL, 0);],
cmu_cv_des_ecb_encrypt_proto=no,
cmu_cv_des_ecb_encrypt_proto=yes)
])
if test "$cmu_cv_des_ecb_encrypt_proto" = yes; then
        AC_DEFINE(HAVE_DES_ECB_ENCRYPT_PROTO,, [define to 1 if `des_ecb_encrypt' has a prototype])dnl
fi
AC_MSG_RESULT($cmu_cv_des_ecb_encrypt_proto)
])

AC_DEFUN([CMU_TELNET_GETTYTAB], [
	 if test -f "/etc/gettytab"; then
		AC_CHECK_FUNCS(getent getstr)
	        if test "X$ac_cv_func_getent" != "Xyes"; then
			AC_DEFINE(HAVE_GETTYTAB,, [gettytab support is present])
			if test "X$ac_cv_func_getstr" = "Xyes"; then
				CFLAGS="$CFLAGS -Dgetstr=ggetstr"
			fi
		fi
	 else
		AC_CHECK_FUNCS(cgetent)
	 fi
	 ])

AC_DEFUN([CMU_TELNET_ISSUE], [
	 if test -f "/etc/issue.net"; then
		AC_DEFINE(ISSUE_FILE, "/etc/issue.net", [path of issue file to use])
	 else
		if test -f "/etc/issue"; then
			AC_DEFINE(ISSUE_FILE, "/etc/issue", [path of issue file to use])
		fi
	 fi
	 ])

AC_DEFUN([CMU_TELNET_PTYDIR], [

	 if test -d /dev/pts -o -d /dev/pty; then
	  	case "${host}" in
		  *-*-irix*)
		    ;;
		  *-*-linux*)
		    AC_DEFINE(PTYDIR,, [Has /dev/ptX and pty allocation funcs])
		    ;;
		  *)
		    AC_DEFINE(PTYDIR,, [Has /dev/ptX and pty allocation funcs])
		    AC_DEFINE(STREAMSPTY,, [ptys are streams devices])
		    ;;
		esac
	 fi
	 ])


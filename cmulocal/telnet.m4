dnl telnet.m4--telnet special macros
dnl Derrick Brashear

AC_DEFUN(CMU_TELNET_CC_T, [
AC_MSG_CHECKING(for cc_t definition)
AC_CACHE_VAL(ac_cv_cc_t_definition, [
AC_TRY_COMPILE(
[
#ifdef HAVE_SYS_TERMIO_H
#include <sys/termio.h>
#else
#ifdef HAVE_SYS_TERMIOS_H
#include <sys/termios.h>
#endif
#endif
],
[cc_t foo;],
ac_cv_cc_t_definition=no,
ac_cv_cc_t_definition=yes)
])
if test "$ac_cv_cc_t_definition" = yes; then
        AC_DEFINE(NO_CC_T)dnl
fi
AC_MSG_RESULT($ac_cv_cc_t_definition)
])

AC_DEFUN(CMU_TELNET_DES_STRING_TO_KEY_PROTO, [
AC_MSG_CHECKING(for des_string_to_key prototype)
AC_CACHE_VAL(ac_cv_des_string_to_key_proto, [
AC_TRY_COMPILE(
[#include <des.h>
typedef unsigned char Block[8];
int  des_string_to_key(char *, Block);],
[int foo = des_string_to_key(NULL, NULL);],
ac_cv_des_string_to_key_proto=no,
ac_cv_des_string_to_key_proto=yes)
])
if test "$ac_cv_des_string_to_key_proto" = yes; then
        AC_DEFINE(HAVE_DES_STRING_TO_KEY_PROTO)dnl
fi
AC_MSG_RESULT($ac_cv_des_string_to_key_proto)
])

AC_DEFUN(CMU_TELNET_DES_ECB_ENCRYPT_PROTO, [
AC_MSG_CHECKING(for des_ecb_encrypt prototype)
AC_CACHE_VAL(ac_cv_des_ecb_encrypt_proto, [
AC_TRY_COMPILE(
[#include <des.h>
typedef unsigned char Block[8];
typedef struct { Block _; } Schedule[16];
void des_ecb_encrypt(Block, Block, Schedule, int);],
[int foo = des_ecb_encrypt(NULL, NULL, NULL, 0);],
ac_cv_des_ecb_encrypt_proto=no,
ac_cv_des_ecb_encrypt_proto=yes)
])
if test "$ac_cv_des_ecb_encrypt_proto" = yes; then
        AC_DEFINE(HAVE_DES_ECB_ENCRYPT_PROTO)dnl
fi
AC_MSG_RESULT($ac_cv_des_ecb_encrypt_proto)
])

AC_DEFUN(CMU_TELNET_NEWDES, [
	 if test "$with_des" = yes; then
		AC_CHECK_FUNCS(des_new_random_key)
		if test "$ac_cv_func_des_new_random_key" = yes; then
			AC_DEFINE(NEWDESLIB)
		fi
	 fi
	 ])

AC_DEFUN(CMU_TELNET_PTYDIR, [
	 if test -d "/dev/pts" -o -d "/dev/pty"; then
		AC_DEFINE(PTYDIR)
	 fi
	 ])


dnl init_automake.m4--cmulocal automake setup macro
dnl Rob Earhart

AC_DEFUN(CMU_INIT_AUTOMAKE, [
	AC_REQUIRE([AM_INIT_AUTOMAKE])
	ACLOCAL="$ACLOCAL -I \$(top_srcdir)/cmulocal"
	])

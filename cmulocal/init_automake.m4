dnl init_automake.m4--cmulocal automake setup macro
dnl Rob Earhart
dnl $Id: init_automake.m4,v 1.3 2002/05/25 19:57:42 leg Exp $

AC_DEFUN(CMU_INIT_AUTOMAKE, [
	AC_REQUIRE([AM_INIT_AUTOMAKE])
	ACLOCAL="$ACLOCAL -I \$(top_srcdir)/cmulocal"
	])

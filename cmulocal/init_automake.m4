dnl init_automake.m4--cmulocal automake setup macro
dnl Rob Earhart
dnl $Id: init_automake.m4,v 1.1 1998/10/02 21:35:59 rob Exp $

AC_DEFUN(CMU_INIT_AUTOMAKE, [
	AC_REQUIRE([AM_INIT_AUTOMAKE])
	ACLOCAL="$ACLOCAL -I \$(top_srcdir)/cmulocal"
	])

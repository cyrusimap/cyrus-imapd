dnl com_err.m4--com_err detection macro
dnl Rob Earhart
dnl $Id: com_err.m4,v 1.6 2003/10/08 20:35:24 rjs3 Exp $

AC_DEFUN([CMU_COMERR], [
	 cmu_need_compile_et=no
	 AC_CHECK_PROGS(COMPILE_ET, compile_et, no)
	 if test "$COMPILE_ET" = no; then
	    COMPILE_ET="\$(top_builddir)/com_err/compile_et"
	    cmu_need_to_compile_com_err=yes
	 fi
	 AC_CHECK_HEADER(com_err.h,,CPPFLAGS="$CPPFLAGS -I\$(top_srcdir)/com_err")
	 cmu_save_LIBS="$LIBS"
	 AC_CHECK_LIB(com_err, com_err,
		      LIB_COMERR="-lcom_err",
		      LDFLAGS="$LDFLAGS -L`pwd`/com_err"
			LIB_COMERR="\$(top_builddir)/com_err/libcom_err.la"
		      cmu_need_to_compile_com_err=yes)
	 AC_SUBST(LIB_COMERR)
	 LIBS="$cmu_save_LIBS"
	 AC_MSG_CHECKING(whether we need to compile com_err)
	 if test "$cmu_need_to_compile_com_err" = yes; then
	   AC_MSG_RESULT(yes)
	   AC_CONFIG_SUBDIRS(com_err)
	 else
	   AC_MSG_RESULT(no)
	 fi
	 ])

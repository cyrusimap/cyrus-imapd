dnl com_err.m4--com_err detection macro
dnl Rob Earhart
dnl $Id: com_err.m4,v 1.1 1998/10/02 21:35:59 rob Exp $

AC_DEFUN(CMU_COMERR, [
	 cmu_need_compile_et=no;
	 AC_CHECK_PROGS(COMPILE_ET, compile_et, no)
	 if test "$COMPILE_ET" = no; then
	    COMPILE_ET=`pwd`/compile_et
	    cmu_need_to_compile_com_err=yes
	 fi
	 AC_CHECK_HEADER(com_err.h,,CPPFLAGS="$CPPFLAGS -I${srcdir}/com_err")
	 cmu_save_LIBS="$LIBS"
	 AC_CHECK_LIB(com_err, com_err,,
		      LDFLAGS="$LDFLAGS -L`pwd`/com_err";
		      LIBCOMERR="-lcom_err"
		      cmu_need_to_compile_com_err=yes)
	 LIBS="$cmu_save_LIBS"
	 AC_MSG_CHECKING(whether we need to compile com_err)
	 if test "$cmu_need_to_compile_com_err" = yes; then
	   AC_MSG_RESULT(yes)
	   AC_CONFIG_SUBDIRS(com_err)
	 else
	   AC_MSG_RESULT(no)
	 fi
	 ])

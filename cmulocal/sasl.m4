dnl sasl.m4--sasl detection macro
dnl Rob Earhart
dnl $Id: sasl.m4,v 1.3 1998/11/18 01:22:21 rob Exp $

AC_DEFUN(CMU_SASL, [
	cmu_need_sasl=no
	AC_CHECK_HEADER(sasl.h,
	  cmu_save_LIBS="$LIBS"
	  AC_CHECK_LIB(sasl, sasl_getprop,,cmu_need_sasl=yes)
	  LIBS="$cmu_save_LIBS"
	,cmu_need_sasl=yes)
	if test "$cmu_need_sasl" = yes; then
	  AC_ERROR([Can't compile without libsasl
                  (Get it from <url:ftp://ftp.andrew.cmu.edu:/pub/cyrus-mail/>).])
	fi
	LIB_SASL="-lsasl"
	AC_SUBST(LIB_SASL)
])

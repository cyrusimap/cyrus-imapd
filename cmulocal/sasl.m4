dnl sasl.m4--sasl detection macro
dnl Rob Earhart
dnl $Id: sasl.m4,v 1.1 1998/10/13 13:21:59 rob Exp $

AC_DEFUN(CMU_SASL, [
	cmu_need_sasl=no
	AC_CHECK_HEADER(sasl.h,
	  cmu_save_LIBS="$LIBS"
	  AC_CHECK_LIB(dl, dlopen,cmu_dl_lib=" -ldl",cmu_dl_lib="")
	  AC_CHECK_LIB(sasl, sasl_getprop,,cmu_need_sasl=yes)
	  LIBS="$cmu_save_LIBS"
	,cmu_need_sasl=yes)
	if test "$cmu_need_sasl" = yes; then
	  AC_ERROR([Can't compile without libsasl
                  (Get it from <ftp://ftp.andrew.cmu.edu:/pub/cyrus-mail/>).])
	fi
	LIB_SASL="-lsasl${cmu_dl_lib}"
	AC_SUBST(LIB_SASL)
])

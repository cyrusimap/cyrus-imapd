dnl sasl.m4--sasl detection macro
dnl Rob Earhart
dnl $Id: sasl.m4,v 1.6 2000/01/28 22:09:40 leg Exp $

AC_DEFUN(CMU_SASL, [
  AC_ARG_WITH(sasldir,[  --with-sasldir=PATH     PATH where the sasl library is installed], sasldir="$withval")

  cmu_need_sasl=no
  if test -z "$sasldir"; then
    # look for it ourselves
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
    SASLFLAGS=""
    AC_SUBST(SASLFLAGS)
  else
    # try the user-specified path --- too lazy to test for it right now
    LIB_SASL="-L$sasldir/lib -lsasl"
    AC_SUBST(LIB_SASL)
    SASLFLAGS="-I$sasldir/include"
    AC_SUBST(SASLFLAGS)    
  fi
])

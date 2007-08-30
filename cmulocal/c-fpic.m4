dnl
dnl $Id: c-fpic.m4,v 1.3 2007/08/30 16:57:55 murch Exp $
dnl

dnl
dnl Test for -fPIC
dnl

AC_DEFUN([CMU_C_FPIC], [
AC_MSG_CHECKING(if compiler supports -fPIC)
AC_CACHE_VAL(ac_cv_fpic, [
save_CFLAGS=$CFLAGS
CFLAGS="${CFLAGS} -fPIC"
AC_TRY_COMPILE([
#include <stdlib.h>
static void
foo(void)
{
  exit(1);
}
],
[
],
ac_cv_fpic=yes,
ac_cv_fpic=no)
CFLAGS=$save_CFLAGS
])
if test "$ac_cv_fpic" = "yes"; then
    FPIC_CFLAGS="-fPIC"
else
    FPIC_CFLAGS=""
fi
AC_MSG_RESULT($ac_cv_fpic)
])


dnl $Id: broken.m4,v 1.3 1999/02/11 17:45:19 shadow Exp $
dnl
dnl
dnl Same as AC _REPLACE_FUNCS, just define HAVE_func if found in normal
dnl libraries 

define(upcase,`echo $1 | tr abcdefghijklmnopqrstuvwxyz ABCDEFGHIJKLMNOPQRSTUVWXYZ`)dnl

AC_DEFUN(CMU_BROKEN,
[for cmu_func in $1
do
AC_CHECK_FUNC($cmu_func, [
cmu_tr_func=HAVE_[]upcase($cmu_func)
AC_DEFINE_UNQUOTED($cmu_tr_func)],[LIBOBJS[]="$LIBOBJS ${cmu_func}.o"])
dnl autoheader tricks *sigh*
: << END
@@@funcs="$funcs $1"@@@
END
done
AC_SUBST(LIBOBJS)dnl
])

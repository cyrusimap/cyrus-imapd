dnl $Id: broken.m4,v 1.2 1999/02/10 17:16:40 shadow Exp $
dnl
dnl
dnl Same as AC _REPLACE_FUNCS, just define HAVE_func if found in normal
dnl libraries 

define(upcase,`echo $1 | tr abcdefghijklmnopqrstuvwxyz ABCDEFGHIJKLMNOPQRSTUVWXYZ`)dnl

AC_DEFUN(AC_BROKEN,
[for ac_func in $1
do
AC_CHECK_FUNC($ac_func, [
ac_tr_func=HAVE_[]upcase($ac_func)
AC_DEFINE_UNQUOTED($ac_tr_func)],[LIBOBJS[]="$LIBOBJS ${ac_func}.o"])
dnl autoheader tricks *sigh*
: << END
@@@funcs="$funcs $1"@@@
END
done
AC_SUBST(LIBOBJS)dnl
])

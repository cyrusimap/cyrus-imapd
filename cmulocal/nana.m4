dnl nana.m4--nana macro
dnl Rob Earhart
dnl $Id: nana.m4,v 1.3.4.1 2002/08/15 22:35:19 ken3 Exp $

AC_DEFUN(CMU_NANA, [
  AC_REQUIRE([AC_PROG_CC])
  AC_ARG_WITH(nana, [[  --with-nana             use NANA [yes] ]],,with_nana=yes)
  if test "$GCC" != yes; then
    with_nana=no
  elif test "$with_nana" = yes; then
    AC_CHECK_PROGS(NANA, nana, :)
    if test "$NANA" = ":"; then
      with_nana=no
    else
      AC_CHECK_HEADER(nana.h,
		      AC_CHECK_LIB(nana, nana_error,,with_nana=no),
		      with_nana=no)
    fi
  else
    with_nana=no
  fi
  AC_MSG_CHECKING([whether to use NANA])
  AC_MSG_RESULT($with_nana)
  if test "$with_nana" != yes; then
    AC_DEFINE(WITHOUT_NANA)
  fi
])

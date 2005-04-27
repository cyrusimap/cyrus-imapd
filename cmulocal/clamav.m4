dnl
dnl macros for configure.in to detect clamav library
dnl $Id: clamav.m4,v 1.1 2005/04/27 00:39:11 shadow Exp $
dnl

AC_DEFUN([CMU_CLAMAV], [
AC_REQUIRE([CMU_FIND_LIB_SUBDIR])
AC_ARG_WITH(clamav,[  --with-clamav=DIR	use ClamAV from PATH (yes)],
	with_clamav=$withval, with_clamav=yes)
  if test "$with_clamav" != no; then
	if test -d $with_clamav; then
		save_CPPFLAGS="$CPPFLAGS"
		save_LDFLAGS="$LDFLAGS"
		save_LIBS="$LIBS"

		CPPFLAGS="${CPPFLAGS} -I${with_clamav}/include"
		LDFLAGS="$LDFLAGS -L${with_clamav}/$CMU_LIB_SUBDIR"
		AC_CHECK_LIB(wrap, request_init, [
			AC_CHECK_HEADER(clamav.h,, with_clamav=no)],
			with_clamav=no, )

		CPPFLAGS="$save_CPPFLAGS"
		LDFLAGS="$save_LDFLAGS"
		LIBS="$save_LIBS"
        fi
   fi

   AC_MSG_CHECKING(ClamAV support)
   AC_MSG_RESULT($with_clamav)
   LIB_CLAMAV=""
   if test "$with_clamav" != "no"; then
	AC_DEFINE(HAVE_CLAMAV,[],[Do we have ClamAV?])
	if test -d "$with_clamav"; then
		CPPFLAGS="${CPPFLAGS} -I${with_clamav}/include"
		LIB_CLAMAV="-L${with_clamav}/$CMU_LIB_SUBDIR -lclamav"
	else
		LIB_CLAMAV="-lclamav"
	fi
  fi
  AC_SUBST(LIB_CLAMAV)
])

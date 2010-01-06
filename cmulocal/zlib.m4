dnl
dnl macros for configure.in to detect zlib
dnl $Id: zlib.m4,v 1.4 2010/01/06 17:01:28 murch Exp $
dnl

AC_DEFUN([CMU_HAVE_ZLIB], [
AC_REQUIRE([CMU_FIND_LIB_SUBDIR])
AC_ARG_WITH(zlib,[  --with-zlib=PATH        use zlib from PATH],
	with_zlib=$withval, with_zlib="yes")

	save_CPPFLAGS=$CPPFLAGS
	save_LDFLAGS=$LDFLAGS

	if test -d $with_zlib; then
	  CPPFLAGS="${CPPFLAGS} -I${with_lib}/include"
	  CMU_ADD_LIBPATH(${with_zlib}/$CMU_LIB_SUBDIR)
	fi

ZLIB=""
case "$with_zlib" in
	no)
	  with_zlib="no";;
	*) 
	AC_CHECK_HEADER(zlib.h, [
		AC_CHECK_LIB(z, deflate,
				LIBS="${LIBS} -lz"; with_zlib="yes",
				with_zlib="no",)],
		with_zlib=no)
	;;
esac

	if test "$with_zlib" != "no"; then
		AC_DEFINE(HAVE_ZLIB,[],[Do we have zlib?])
		ZLIB="-lz"
	else
		CPPFLAGS=$save_CPPFLAGS
		LDFLAGS=$save_LDFLAGS
	fi
])

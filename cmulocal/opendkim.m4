dnl These are the Cyrus OpenDKIM macros.

dnl They are here so that they can be shared between Cyrus IMAPd
dnl and Cyrus SASL with relative ease.

dnl When we're done, there will be a DKIM_CFLAGS and a DKIM_LIBS which
dnl should be used when necessary. 
dnl We should probably be smarter about our RPATH dnl handling.

dnl Call these with CYRUS_SQLITE_CHK.

dnl We will also set $opendkimlib to "yes" if we are successful, "no" otherwise.

AC_DEFUN([CYRUS_OPENDKIM_CHK_LIB],
[
	OPENDKIM_SAVE_LDFLAGS=$LDFLAGS

	if test -d $with_opendkim_lib; then
	    CMU_ADD_LIBPATH_TO($with_opendkim_lib, LDFLAGS)
	    CMU_ADD_LIBPATH_TO($with_opendkim_lib, OPENDKIM_LIBADD)
	else
	    DKIM_LIBS=""
	fi

	saved_LIBS=$LIBS
        for libname in ${with_opendkim} opendkim
          do
	    LIBS="$saved_LIBS -l$libname"
	    AC_TRY_LINK([#include <stdio.h>
#include <dkim.h>],
	    [dkim_init(NULL, NULL);],
	    DKIM_LIBS="$DKIM_LIBS -l$libname"; opendkimlib="yes",
            opendkimlib="no")
	    if test "$opendkimlib" = "yes"; then break; fi
          done
	LIBS=$saved_LIBS

	LDFLAGS=$OPENDKIM_SAVE_LDFLAGS
])

AC_DEFUN([CYRUS_OPENDKIM_OPTS],
[
AC_ARG_WITH(opendkim-libdir,
	[  --with-opendkim-libdir=DIR   Opendkim lib files are in DIR],
	with_opendkim_lib=$withval,
	[ test "${with_opendkim_lib+set}" = set || with_opendkim_lib=none])
AC_ARG_WITH(opendkim-incdir,
	[  --with-opendkim-incdir=DIR   Opendkim include files are in DIR],
	with_opendkim_inc=$withval,
	[ test "${with_opendkim_inc+set}" = set || with_opendkim_inc=none ])
])

AC_DEFUN([CYRUS_OPENDKIM_CHK],
[
	AC_REQUIRE([CYRUS_OPENDKIM_OPTS])

	cmu_save_CPPFLAGS=$CPPFLAGS

	if test -d $with_opendkim_inc; then
	    CPPFLAGS="$CPPFLAGS -I$with_opendkim_inc"
	    DKIM_CFLAGS="-I$with_opendkim_inc"
	else
	    DKIM_CFLAGS=""
	fi

        AC_CHECK_HEADER(dkim.h,
                        [CYRUS_OPENDKIM_CHK_LIB()],
                        opendkimlib="no")

	CPPFLAGS=$cmu_save_CPPFLAGS
])

dnl sasl.m4--sasl libraries and includes
dnl Derrick Brashear
dnl from KTH sasl and Arla

AC_DEFUN(CMU_SASL_INC_WHERE1, [
AC_REQUIRE([AC_PROG_CC_GNU])
saved_CPPFLAGS=$CPPFLAGS
CPPFLAGS="$saved_CPPFLAGS -I$1"
CMU_CHECK_HEADER_NOCACHE(sasl.h,
ac_cv_found_sasl_inc=yes,
ac_cv_found_sasl_inc=no)
CPPFLAGS=$saved_CPPFLAGS
])

AC_DEFUN(CMU_SASL_INC_WHERE, [
   for i in $1; do
      CMU_SASL_INC_WHERE1($i)
      CMU_TEST_INCPATH($i, sasl)
      if test "$ac_cv_found_sasl_inc" = "yes"; then
        ac_cv_sasl_where_inc=$i
        break
      fi
    done
])

AC_DEFUN(CMU_SASL_LIB_WHERE1, [
AC_REQUIRE([AC_PROG_CC_GNU])
saved_LIBS=$LIBS
LIBS="$saved_LIBS -L$1 -lsasl"
AC_TRY_LINK(,
[sasl_getprop();],
[ac_cv_found_sasl_lib=yes],
ac_cv_found_sasl_lib=no)
LIBS=$saved_LIBS
])

AC_DEFUN(CMU_SASL_LIB_WHERE, [
   for i in $1; do
      CMU_SASL_LIB_WHERE1($i)
      dnl deal with false positives from implicit link paths
      CMU_TEST_LIBPATH($i, sasl)
      if test "$ac_cv_found_sasl_lib" = "yes" ; then
        ac_cv_sasl_where_lib=$i
        break
      fi
    done
])

AC_DEFUN(CMU_SASL, [
AC_ARG_WITH(sasl,
            [  --with-sasl=DIR        Compile with libsasl in <DIR>],
	    with_sasl="$withval",
            with_sasl="yes")

	SASLFLAGS=""
	LIB_SASL=""

	cmu_saved_CPPFLAGS=$CPPFLAGS
	cmu_saved_LDFLAGS=$LDFLAGS
	cmu_saved_LIBS=$LIBS
	if test -d ${with_sasl}; then
          ac_cv_sasl_where_lib=${with_sasl}/lib
          ac_cv_sasl_where_inc=${with_sasl}/include

	  SASLFLAGS="-I$ac_cv_sasl_where_inc"
	  LIB_SASL="-L$ac_cv_sasl_where_lib"
	  CPPFLAGS="${cmu_saved_CPPFLAGS} -I${ac_cv_sasl_where_inc}"
	  LDFLAGS="${cmu_saved_LDFLAGS} -L${ac_cv_sasl_where_lib}"
	fi

	AC_CHECK_HEADER(sasl.h,
	  AC_CHECK_LIB(sasl, sasl_getprop, 
                       ac_cv_found_sasl=yes,
		       ac_cv_found_sasl=no), ac_cv_found_sasl=no)

	LIBS="$cmu_saved_LIBS"
	LDFLAGS="$cmu_saved_LDFLAGS"
	CPPFLAGS="$cmu_saved_CPPFLAGS"
	if test "$ac_cv_found_sasl" = yes; then
	  LIB_SASL="$LIB_SASL -lsasl"
	else
	  LIB_SASL=""
	  SASLFLAGS=""
	fi
	AC_SUBST(LIB_SASL)
	AC_SUBST(SASLFLAGS)
	])

AC_DEFUN(CMU_SASL_REQUIRED,
[AC_REQUIRE([CMU_SASL])
if test "$ac_cv_found_sasl" != "yes"; then
        AC_ERROR([Cannot continue without libsasl.
Get it from ftp://ftp.andrew.cmu.edu:/pub/cyrus-mail/.])
fi])

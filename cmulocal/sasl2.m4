dnl sasl2.m4--sasl2 libraries and includes
dnl Rob Siemborski
dnl $Id: sasl2.m4,v 1.17 2002/05/25 19:57:42 leg Exp $

AC_DEFUN(SASL_GSSAPI_CHK,[
 AC_ARG_ENABLE(gssapi, [  --enable-gssapi=<DIR>   enable GSSAPI authentication [yes] ],
    gssapi=$enableval,
    gssapi=yes)

 if test "$gssapi" != no; then
    if test -d ${gssapi}; then
       CPPFLAGS="$CPPFLAGS -I$gssapi/include"
       LDFLAGS="$LDFLAGS -L$gssapi/lib"
    fi
    AC_CHECK_HEADER(gssapi.h, AC_DEFINE(HAVE_GSSAPI_H),
      AC_CHECK_HEADER(gssapi/gssapi.h,, AC_WARN(Disabling GSSAPI); gssapi=no))
 fi

 if test "$gssapi" != no; then
  dnl We need to find out which gssapi implementation we are
  dnl using. Supported alternatives are: MIT Kerberos 5 and
  dnl Heimdal Kerberos 5 (http://www.pdc.kth.se/heimdal)
  dnl
  dnl The choice is reflected in GSSAPIBASE_LIBS
  dnl we might need libdb
  AC_CHECK_LIB(db, db_open)

  gss_impl="mit";
  AC_CHECK_LIB(resolv,res_search)
  if test -d ${gssapi}; then 
     CPPFLAGS="$CPPFLAGS -I$gssapi/include"
     LDFLAGS="$LDFLAGS -L$gssapi/lib"
  fi

  if test -d ${gssapi}; then
     gssapi_dir="${gssapi}/lib"
     GSSAPIBASE_LIBS="-L$gssapi_dir"
     GSSAPIBASE_STATIC_LIBS="-L$gssapi_dir"
  else
     dnl FIXME: This is only used for building cyrus, and then only as
     dnl a real hack.  it needs to be fixed.
     gssapi_dir="/usr/local/lib"
  fi

  # Check a full link against the heimdal libraries.  If this fails, assume
  # MIT.
  AC_CHECK_LIB(gssapi,gss_unwrap,gss_impl="heimdal",,$GSSAPIBASE_LIBS -lgssapi -lkrb5 -ldes -lasn1 -lroken ${LIB_CRYPT} -lcom_err)

  if test "$gss_impl" = "mit"; then
     GSSAPIBASE_LIBS="$GSSAPIBASE_LIBS -lgssapi_krb5 -lkrb5 -lk5crypto -lcom_err"
     GSSAPIBASE_STATIC_LIBS="$GSSAPIBASE_LIBS $gssapi_dir/libgssapi_krb5.a $gssapi_dir/libkrb5.a $gssapi_dir/libk5crypto.a $gssapi_dir/libcom_err.a"
  elif test "$gss_impl" = "heimdal"; then
     GSSAPIBASE_LIBS="$GSSAPIBASE_LIBS -lgssapi -lkrb5 -ldes -lasn1 -lroken ${LIB_CRYPT} -lcom_err"
     GSSAPIBASE_STATIC_LIBS="$GSSAPIBASE_STATIC_LIBS $gssapi_dir/libgssapi.a $gssapi_dir/libkrb5.a $gssapi_dir/libdes.a $gssapi_dir/libasn1.a $gssapi_dir/libroken.a $gssapi_dir/libcom_err.a ${LIB_CRYPT}"
  else
     gssapi="no"
     AC_WARN(Disabling GSSAPI)
  fi
 fi

 if test "$ac_cv_header_gssapi_h" = "yes"; then
  AC_EGREP_HEADER(GSS_C_NT_HOSTBASED_SERVICE, gssapi.h,
    AC_DEFINE(HAVE_GSS_C_NT_HOSTBASED_SERVICE))
 elif test "$ac_cv_header_gssapi_gssapi_h"; then
  AC_EGREP_HEADER(GSS_C_NT_HOSTBASED_SERVICE, gssapi/gssapi.h,
    AC_DEFINE(HAVE_GSS_C_NT_HOSTBASED_SERVICE))
 fi

 GSSAPI_LIBS=""
 AC_MSG_CHECKING(GSSAPI)
 if test "$gssapi" != no; then
  AC_MSG_RESULT(with implementation ${gss_impl})
  AC_CHECK_LIB(ndbm,dbm_open,GSSAPIBASE_LIBS="$GSSAPIBASE_LIBS -lndbm")
  AC_CHECK_LIB(resolv,res_search,GSSAPIBASE_LIBS="$GSSAPIBASE_LIBS -lresolv")
  SASL_MECHS="$SASL_MECHS libgssapiv2.la"
  SASL_STATIC_OBJS="$SASL_STATIC_OBJS ../plugins/gssapi.o"

  cmu_save_LIBS="$LIBS"
  LIBS="$LIBS $GSSAPIBASE_LIBS"
  AC_CHECK_FUNCS(gsskrb5_register_acceptor_identity)
  LIBS="$cmu_save_LIBS"
else
  AC_MSG_RESULT(disabled)
fi
AC_SUBST(GSSAPI_LIBS)
AC_SUBST(GSSAPIBASE_LIBS)
])

dnl What we want to do here is setup LIB_SASL with what one would
dnl generally want to have (e.g. if static is requested, make it that,
dnl otherwise make it dynamic.

dnl We also want to creat LIB_DYN_SASL and DYNSASLFLAGS.

dnl Also sets using_static_sasl to "no" "static" or "staticonly"

AC_DEFUN(CMU_SASL2, [
AC_ARG_WITH(sasl,
            [  --with-sasl=DIR         Compile with libsasl2 in <DIR>],
	    with_sasl="$withval",
            with_sasl="yes")

AC_ARG_WITH(staticsasl,
	    [  --with-staticsasl=DIR   Compile with staticly linked libsasl2 in <DIR>],
	    with_staticsasl="$withval";
	    if test $with_staticsasl != "no"; then
		using_static_sasl="static"
	    fi,
	    with_staticsasl="no"; using_static_sasl="no")

	SASLFLAGS=""
	LIB_SASL=""

	cmu_saved_CPPFLAGS=$CPPFLAGS
	cmu_saved_LDFLAGS=$LDFLAGS
	cmu_saved_LIBS=$LIBS

	if test ${with_staticsasl} != "no"; then
	  if test -d ${with_staticsasl}; then
	    ac_cv_sasl_where_lib=${with_staticsasl}/lib
	    ac_cv_sasl_where_inc=${with_staticsasl}/include

	    SASLFLAGS="-I$ac_cv_sasl_where_inc"
	    LIB_SASL="-L$ac_cv_sasl_where_lib"
	    CPPFLAGS="${cmu_saved_CPPFLAGS} -I${ac_cv_sasl_where_inc}"
	    LDFLAGS="${cmu_saved_LDFLAGS} -L${ac_cv_sasl_where_lib}"
	  else
	    with_staticsasl="/usr"
	  fi

	  AC_CHECK_HEADER(sasl/sasl.h,
	    AC_CHECK_HEADER(sasl/saslutil.h,
	     if test -r ${with_staticsasl}/lib/libsasl2.a; then
		ac_cv_found_sasl=yes
		AC_MSG_CHECKING(for static libsasl)
		LIB_SASL="$LIB_SASL ${with_staticsasl}/lib/libsasl2.a"
	     else
	        AC_MSG_CHECKING(for static libsasl)
		AC_ERROR([Could not find ${with_staticsasl}/lib/libsasl2.a])
	     fi
	    ))

	  AC_MSG_RESULT(found)

	  SASL_GSSAPI_CHK

	  LIB_SASL="$LIB_SASL $GSSAPIBASE_STATIC_LIBS"
	fi

	if test -d ${with_sasl}; then
            ac_cv_sasl_where_lib=${with_sasl}/lib
            ac_cv_sasl_where_inc=${with_sasl}/include

	    DYNSASLFLAGS="-I$ac_cv_sasl_where_inc"
	    if test "$ac_cv_sasl_where_lib" != ""; then
		CMU_ADD_LIBPATH_TO($ac_cv_sasl_where_lib, LIB_DYN_SASL)
	    fi
	    LIB_DYN_SASL="$LIB_DYN_SASL -lsasl2"
	    CPPFLAGS="${cmu_saved_CPPFLAGS} -I${ac_cv_sasl_where_inc}"
	    LDFLAGS="${cmu_saved_LDFLAGS} -L${ac_cv_sasl_where_lib}"
	fi

	dnl be sure to check for a SASLv2 specific function
	AC_CHECK_HEADER(sasl/sasl.h,
	    AC_CHECK_HEADER(sasl/saslutil.h,
	      AC_CHECK_LIB(sasl2, prop_get, 
                           ac_cv_found_sasl=yes,
		           ac_cv_found_sasl=no),
	                   ac_cv_found_sasl=no), ac_cv_found_sasl=no)

	if test "$ac_cv_found_sasl" = "yes"; then
	    if test "$ac_cv_sasl_where_lib" != ""; then
	        CMU_ADD_LIBPATH_TO($ac_cv_sasl_where_lib, DYNLIB_SASL)
	    fi
	    DYNLIB_SASL="$DYNLIB_SASL -lsasl2"
	    if test "$using_static_sasl" != "static"; then
		LIB_SASL=$DYNLIB_SASL
		SASLFLAGS=$DYNSASLFLAGS
	    fi
	else
	    DYNLIB_SASL=""
	    DYNSASLFLAGS=""
	    using_static_sasl="staticonly"
	fi

	LIBS="$cmu_saved_LIBS"
	LDFLAGS="$cmu_saved_LDFLAGS"
	CPPFLAGS="$cmu_saved_CPPFLAGS"

	AC_SUBST(LIB_DYN_SASL)
	AC_SUBST(DYNSASLFLAGS)
	AC_SUBST(LIB_SASL)
	AC_SUBST(SASLFLAGS)
	])

AC_DEFUN(CMU_SASL2_REQUIRED,
[AC_REQUIRE([CMU_SASL2])
if test "$ac_cv_found_sasl" != "yes"; then
        AC_ERROR([Cannot continue without libsasl2.
Get it from ftp://ftp.andrew.cmu.edu/pub/cyrus-mail/.])
fi])

AC_DEFUN(CMU_SASL2_CHECKAPOP_REQUIRED, [
	AC_REQUIRE([CMU_SASL2_REQUIRED])

	cmu_saved_LDFLAGS=$LDFLAGS

	LDFLAGS="$LIB_SASL $LDFLAGS"

	AC_CHECK_LIB(sasl2, sasl_checkapop, AC_DEFINE(HAVE_APOP),
		AC_MSG_ERROR([libsasl2 without working sasl_checkapop.  Cannot continue.]))

	LDFLAGS=$cmu_saved_LDFLAGS
])

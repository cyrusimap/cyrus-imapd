dnl sasl2.m4--sasl2 libraries and includes
dnl Rob Siemborski

AC_DEFUN(SASL_GSSAPI_CHK,[
 AC_ARG_ENABLE(gssapi, [  --with-gssapi=<DIR>	  enable GSSAPI authentication (for staticsasl only) [yes] ],
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

  # the base64_decode check fails because libroken has dependencies
  # FIXME: this is probabally non-optimal as well
  AC_CHECK_LIB(krb5,krb5_vlog,gss_impl="heimdal",,)
  #  AC_CHECK_LIB(roken,base64_decode,gss_impl="heimdal",, $LIB_CRYPT)

  if test -d ${gssapi}; then
     GSSAPIBASE_LIBS="-L$gssapi/lib"
  fi

  if test "$gss_impl" = mit; then
     GSSAPIBASE_LIBS="$GSSAPIBASE_LIBS -lgssapi_krb5 -lkrb5 -lk5crypto -lcom_err"
  elif test "$gss_impl" = "heimdal"; then
     GSSAPIBASE_LIBS="$GSSAPIBASE_LIBS -lgssapi -lkrb5 -ldes -lasn1 -lroken ${LIB_CRYPT} -lcom_err"
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

AC_DEFUN(CMU_SASL2, [
AC_ARG_WITH(sasl,
            [  --with-sasl=DIR         Compile with libsasl2 in <DIR>],
	    with_sasl="$withval",
            with_sasl="yes")

AC_ARG_WITH(staticsasl,
	    [  --with-staticsasl=DIR  Compile with staticly linked libsasl2 in <DIR>],
	    with_staticsasl="$withval";
	    if test $with_staticsasl != "no"; then
		with_sasl="static"
	    fi,
	    with_staticsasl="no")

	SASLFLAGS=""
	LIB_SASL=""

	cmu_saved_CPPFLAGS=$CPPFLAGS
	cmu_saved_LDFLAGS=$LDFLAGS
	cmu_saved_LIBS=$LIBS

	if test ${with_sasl} = "static"; then
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

	  LIB_SASL="$LIB_SASL $GSSAPIBASE_LIBS"

	else
	  if test -d ${with_sasl}; then
            ac_cv_sasl_where_lib=${with_sasl}/lib
            ac_cv_sasl_where_inc=${with_sasl}/include

	    SASLFLAGS="-I$ac_cv_sasl_where_inc"
	    LIB_SASL="-L$ac_cv_sasl_where_lib"
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

	  if test "$ac_cv_found_sasl" = yes; then
	    LIB_SASL="$LIB_SASL -lsasl2"
	  else
	    LIB_SASL=""
	    SASLFLAGS=""
	  fi
	fi

	LIBS="$cmu_saved_LIBS"
	LDFLAGS="$cmu_saved_LDFLAGS"
	CPPFLAGS="$cmu_saved_CPPFLAGS"

	AC_SUBST(LIB_SASL)
	AC_SUBST(SASLFLAGS)
	])

AC_DEFUN(CMU_SASL2_REQUIRED,
[AC_REQUIRE([CMU_SASL2])
if test "$ac_cv_found_sasl" != "yes"; then
        AC_ERROR([Cannot continue without libsasl2.
Get it from ftp://ftp.andrew.cmu.edu/pub/cyrus-mail/.])
fi])

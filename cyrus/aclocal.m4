dnl aclocal.m4 generated automatically by aclocal 1.4

dnl Copyright (C) 1994, 1995-8, 1999 Free Software Foundation, Inc.
dnl This file is free software; the Free Software Foundation
dnl gives unlimited permission to copy and/or distribute it,
dnl with or without modifications, as long as this notice is preserved.

dnl This program is distributed in the hope that it will be useful,
dnl but WITHOUT ANY WARRANTY, to the extent permitted by law; without
dnl even the implied warranty of MERCHANTABILITY or FITNESS FOR A
dnl PARTICULAR PURPOSE.

#serial 1
# This test replaces the one in autoconf.
# Currently this macro should have the same name as the autoconf macro
# because gettext's gettext.m4 (distributed in the automake package)
# still uses it.  Otherwise, the use in gettext.m4 makes autoheader
# give these diagnostics:
#   configure.in:556: AC_TRY_COMPILE was called before AC_ISC_POSIX
#   configure.in:556: AC_TRY_RUN was called before AC_ISC_POSIX

undefine([AC_ISC_POSIX])

AC_DEFUN([AC_ISC_POSIX],
  [
    dnl This test replaces the obsolescent AC_ISC_POSIX kludge.
    AC_CHECK_LIB(cposix, strerror, [LIBS="$LIBS -lcposix"])
  ]
)

dnl
dnl Additional macros for configure.in packaged up for easier theft.
dnl tjs@andrew.cmu.edu 6-may-1998
dnl

dnl It would be good if ANDREW_ADD_LIBPATH could detect if something was
dnl already there and not redundantly add it if it is.

dnl add -L(arg), and possibly (runpath switch)(arg), to LDFLAGS
dnl (so the runpath for shared libraries is set).
AC_DEFUN(CMU_ADD_LIBPATH, [
  # this is CMU ADD LIBPATH
  if test "$andrew_runpath_switch" = "none" ; then
	LDFLAGS="-L$1 ${LDFLAGS}"
  else
	LDFLAGS="-L$1 $andrew_runpath_switch$1 ${LDFLAGS}"
  fi
])

dnl add -L(1st arg), and possibly (runpath switch)(1st arg), to (2nd arg)
dnl (so the runpath for shared libraries is set).
AC_DEFUN(CMU_ADD_LIBPATH_TO, [
  # this is CMU ADD LIBPATH TO
  if test "$andrew_runpath_switch" = "none" ; then
	$2="-L$1 ${$2}"
  else
	$2="-L$1 ${$2} $andrew_runpath_switch$1"
  fi
])

dnl runpath initialization
AC_DEFUN(CMU_GUESS_RUNPATH_SWITCH, [
   # CMU GUESS RUNPATH SWITCH
  AC_CACHE_CHECK(for runpath switch, andrew_runpath_switch, [
    # first, try -R
    SAVE_LDFLAGS="${LDFLAGS}"
    LDFLAGS="-R /usr/lib"
    AC_TRY_LINK([],[],[andrew_runpath_switch="-R"], [
  	LDFLAGS="-Wl,-rpath,/usr/lib"
    AC_TRY_LINK([],[],[andrew_runpath_switch="-Wl,-rpath,"],
    [andrew_runpath_switch="none"])
    ])
  LDFLAGS="${SAVE_LDFLAGS}"
  ])])

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

  if test "$gss_impl" = "mit"; then
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
	    [  --with-staticsasl=DIR  Compile with staticly linked libsasl2 in <DIR>],
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

	  LIB_SASL="$LIB_SASL $GSSAPIBASE_LIBS"
	fi

	if test -d ${with_sasl}; then
            ac_cv_sasl_where_lib=${with_sasl}/lib
            ac_cv_sasl_where_inc=${with_sasl}/include

	    DYNSASLFLAGS="-I$ac_cv_sasl_where_inc"
	    LIB_DYN_SASL="-L$ac_cv_sasl_where_lib"
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
	    DYNLIB_SASL="$LIB_SASL -lsasl2"
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

dnl bsd_sockets.m4--which socket libraries do we need? 
dnl Derrick Brashear
dnl from Zephyr

dnl Hacked on by Rob Earhart to not just toss stuff in LIBS
dnl It now puts everything required for sockets into LIB_SOCKET

AC_DEFUN(CMU_SOCKETS, [
	save_LIBS="$LIBS"
	LIB_SOCKET=""
	AC_CHECK_FUNC(connect, :,
		AC_CHECK_LIB(nsl, gethostbyname,
			     LIB_SOCKET="-lnsl $LIB_SOCKET")
		AC_CHECK_LIB(socket, connect,
			     LIB_SOCKET="-lsocket $LIB_SOCKET")
	)
	LIBS="$LIB_SOCKET $save_LIBS"
	AC_CHECK_FUNC(res_search, :,
                AC_CHECK_LIB(resolv, res_search,
                              LIB_SOCKET="-lresolv $LIB_SOCKET") 
        )
	LIBS="$LIB_SOCKET $save_LIBS"
	AC_CHECK_FUNCS(dn_expand dns_lookup)
	LIBS="$save_LIBS"
	AC_SUBST(LIB_SOCKET)
	])

dnl libwrap.m4 --- do we have libwrap, the access control library?

AC_DEFUN(CMU_LIBWRAP, [
  AC_REQUIRE([CMU_SOCKETS])
  AC_ARG_WITH(libwrap, 
              [  --with-libwrap=DIR      use libwrap (rooted in DIR) [yes] ],
              with_libwrap=$withval, with_libwrap=yes)
  if test "$with_libwrap" != no; then
    if test -d "$with_libwrap"; then
      CPPFLAGS="$CPPFLAGS -I${with_libwrap}/include"
      LDFLAGS="$LDFLAGS -L${with_libwrap}/lib"
    fi
    cmu_save_LIBS="$LIBS"
    AC_CHECK_LIB(wrap, request_init,
		 AC_CHECK_HEADER(tcpd.h,, with_libwrap=no),
		 with_libwrap=no, ${LIB_SOCKET})
    LIBS="$cmu_save_LIBS"
  fi
  AC_MSG_CHECKING(libwrap support)
  AC_MSG_RESULT($with_libwrap)
  LIB_WRAP=""
  if test "$with_libwrap" != no; then
    AC_DEFINE(HAVE_LIBWRAP)
    LIB_WRAP="-lwrap"
    AC_CHECK_LIB(nsl, yp_get_default_domain, LIB_WRAP="${LIB_WRAP} -lnsl")
  fi
  AC_SUBST(LIB_WRAP)
])

dnl look for the ucdsnmp libraries

AC_DEFUN(CMU_UCDSNMP, [
  AC_REQUIRE([CMU_SOCKETS])
  AC_ARG_WITH(ucdsnmp, 
              [  --with-ucdsnmp=DIR      use ucd snmp (rooted in DIR) [yes] ],
              with_ucdsnmp=$withval, with_ucdsnmp=yes)
  if test "$with_ucdsnmp" != no; then
    if test -d "$with_ucdsnmp"; then
      CPPFLAGS="$CPPFLAGS -I${with_ucdsnmp}/include"
      LDFLAGS="$LDFLAGS -L${with_ucdsnmp}/lib"
    fi
    cmu_save_LIBS="$LIBS"
    AC_CHECK_LIB(snmp, sprint_objid,
		 AC_CHECK_HEADER(ucd-snmp/version.h,, with_ucdsnmp=no),
		 with_ucdsnmp=no, ${LIB_SOCKET})
    LIBS="$cmu_save_LIBS"
  fi
  AC_MSG_CHECKING(UCD SNMP libraries)
  AC_MSG_RESULT($with_ucdsnmp)
  LIB_UCDSNMP=""
  if test "$with_ucdsnmp" != no; then
    AC_DEFINE(HAVE_UCDSNMP)
    LIB_UCDSNMP="-lucdagent -lucdmibs -lsnmp"
    AC_CHECK_LIB(rpm, rpmdbOpen,
		 LIB_UCDSNMP="${LIB_UCDSNMP} -lrpm -lpopt",,-lpopt)
  fi
  AC_SUBST(LIB_UCDSNMP)
])


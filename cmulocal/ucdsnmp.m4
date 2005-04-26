dnl look for the (ucd|net)snmp libraries
dnl $Id: ucdsnmp.m4,v 1.11 2005/04/26 19:14:08 shadow Exp $

AC_DEFUN([CMU_UCDSNMP], [
AC_REQUIRE([CMU_FIND_LIB_SUBDIR])
  AC_REQUIRE([CMU_SOCKETS])
  AC_ARG_WITH(snmp, 
              [  --with-snmp=DIR         use ucd|net snmp (rooted in DIR) [yes] ],
              with_snmp=$withval, with_snmp=yes)

  dnl
  dnl Maintain backwards compatibility with old --with-ucdsnmp option
  dnl
  AC_ARG_WITH(ucdsnmp,, with_snmp=$withval,)

if test "$with_snmp" != "no"; then

  dnl
  dnl Try net-snmp first
  dnl
  if test "$with_snmp" = "yes"; then
    AC_PATH_PROG(SNMP_CONFIG,net-snmp-config,,[/usr/local/bin:$PATH])
  else
    SNMP_CONFIG="$with_snmp/bin/net-snmp-config"
  fi

  if test -x "$SNMP_CONFIG"; then
    AC_MSG_CHECKING(NET SNMP libraries)

    SNMP_LIBS=`$SNMP_CONFIG --agent-libs`
    SNMP_PREFIX=`$SNMP_CONFIG --prefix`

    if test -n "$SNMP_LIBS" && test -n "$SNMP_PREFIX"; then
      CPPFLAGS="$CPPFLAGS -I${SNMP_PREFIX}/include"
      LIB_UCDSNMP=$SNMP_LIBS
      AC_DEFINE(HAVE_NETSNMP,1,[Do we have Net-SNMP support?])
      AC_SUBST(LIB_UCDSNMP)
      AC_MSG_RESULT(yes)
    else
      AC_MSG_RESULT(no)
      AC_MSG_WARN([Could not find the required paths. Please check your net-snmp installation.])
    fi
  else
    dnl
    dnl Try ucd-snmp if net-snmp test failed
    dnl
    if test "$with_snmp" != no; then
      if test -d "$with_snmp"; then
        CPPFLAGS="$CPPFLAGS -I${with_snmp}/include"
        LDFLAGS="$LDFLAGS -L${with_snmp}/$CMU_LIB_SUBDIR"
      fi
      cmu_save_LIBS="$LIBS"
      AC_CHECK_LIB(snmp, sprint_objid, [
  		 AC_CHECK_HEADER(ucd-snmp/version.h,, with_snmp=no)],
  		 with_snmp=no, ${LIB_SOCKET})
      LIBS="$cmu_save_LIBS"
    fi
    AC_MSG_CHECKING(UCD SNMP libraries)
    AC_MSG_RESULT($with_snmp)
    LIB_UCDSNMP=""
    if test "$with_snmp" != no; then
      AC_DEFINE(HAVE_UCDSNMP,1,[Do we have UCD-SNMP support?])
      LIB_UCDSNMP="-lucdagent -lucdmibs -lsnmp"
      AC_CHECK_LIB(rpm, rpmdbOpen,
		 LIB_UCDSNMP="${LIB_UCDSNMP} -lrpm -lpopt",,-lpopt)
    fi
    AC_SUBST(LIB_UCDSNMP)
  fi
fi

])

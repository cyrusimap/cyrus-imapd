dnl look for the ucdsnmp libraries
dnl $Id: ucdsnmp.m4,v 1.5 2002/08/21 15:03:19 rjs3 Exp $

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
    AC_CHECK_LIB(snmp, sprint_objid, [
		 AC_CHECK_HEADER(ucd-snmp/version.h,, with_ucdsnmp=no)],
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

dnl aclocal.m4 generated automatically by aclocal 1.4

dnl Copyright (C) 1994, 1995-8, 1999 Free Software Foundation, Inc.
dnl This file is free software; the Free Software Foundation
dnl gives unlimited permission to copy and/or distribute it,
dnl with or without modifications, as long as this notice is preserved.

dnl This program is distributed in the hope that it will be useful,
dnl but WITHOUT ANY WARRANTY, to the extent permitted by law; without
dnl even the implied warranty of MERCHANTABILITY or FITNESS FOR A
dnl PARTICULAR PURPOSE.

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
      AC_MSG_CHECKING(for sasl headers in $i)
      CMU_SASL_INC_WHERE1($i)
      CMU_TEST_INCPATH($i, sasl)
      if test "$ac_cv_found_sasl_inc" = "yes"; then
        ac_cv_sasl_where_inc=$i
        AC_MSG_RESULT(found)
        break
      else
        AC_MSG_RESULT(not found)
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
      AC_MSG_CHECKING(for sasl libraries in $i)
      CMU_SASL_LIB_WHERE1($i)
      dnl deal with false positives from implicit link paths
      CMU_TEST_LIBPATH($i, sasl)
      if test "$ac_cv_found_sasl_lib" = "yes" ; then
        ac_cv_sasl_where_lib=$i
        AC_MSG_RESULT(found)
        break
      else
        AC_MSG_RESULT(not found)
      fi
    done
])

AC_DEFUN(CMU_SASL, [
AC_REQUIRE([CMU_SOCKETS])
AC_REQUIRE([CMU_KRB4])
AC_ARG_WITH(sasl,
	[  --with-sasl=PREFIX      Compile with Sasl support],
	[if test "X$with_sasl" = "X"; then
		with_sasl=yes
	fi])
AC_ARG_WITH(sasl-lib,
	[  --with-sasl-lib=dir     use sasl libraries in dir],
	[if test "$withval" = "yes" -o "$withval" = "no"; then
		AC_MSG_ERROR([No argument for --with-sasl-lib])
	fi])
AC_ARG_WITH(sasl-include,
	[  --with-sasl-include=dir use sasl headers in dir],
	[if test "$withval" = "yes" -o "$withval" = "no"; then
		AC_MSG_ERROR([No argument for --with-sasl-include])
	fi])

	if test "X$with_sasl" != "X"; then
	  if test "$with_sasl" != "yes" -a "$with_sasl" != no; then
	    ac_cv_sasl_where_lib=$with_sasl/lib
	    ac_cv_sasl_where_inc=$with_sasl/include
	  fi
	fi

	if test "$with_sasl" != "no"; then 
	  if test "X$with_sasl_lib" != "X"; then
	    ac_cv_sasl_where_lib=$with_sasl_lib
	  fi
	  if test "X$ac_cv_sasl_where_lib" = "X"; then
	    CMU_SASL_LIB_WHERE(/usr/sasl/lib /usr/local/lib /usr/lib)
	  fi

	  if test "X$with_sasl_include" != "X"; then
	    ac_cv_sasl_where_inc=$with_sasl_include
	  fi
	  if test "X$ac_cv_sasl_where_inc" = "X"; then
	    CMU_SASL_INC_WHERE(/usr/sasl/include /usr/include/sasl /usr/local/include /usr/include)
	  fi
	fi

	AC_MSG_CHECKING(whether to include sasl)
	if test "X$ac_cv_sasl_where_lib" = "X" -a "X$ac_cv_sasl_where_inc" = "X"; then
	  ac_cv_found_sasl=no
	  AC_MSG_RESULT(no)
	else
	  ac_cv_found_sasl=yes
	  AC_MSG_RESULT(yes)
	  SASL_INC_DIR=$ac_cv_sasl_where_inc
	  SASL_LIB_DIR=$ac_cv_sasl_where_lib
	  SASL_INC_FLAGS="-I${SASL_INC_DIR}"
	  SASL_LIB_FLAGS="-L${SASL_LIB_DIR} -lsasl"
	  LIB_SASL="-L${SASL_LIB_DIR} -lsasl" 
 	  SASLFLAGS="-I${SASL_INC_DIR}"
	  AC_SUBST(LIB_SASL)
	  AC_SUBST(SASLFLAGS)    
	  if test "X$RPATH" = "X"; then
		RPATH=""
	  fi
	  case "${host}" in
	    *-*-linux*)
	      if test "X$RPATH" = "X"; then
	        RPATH="-Wl,-rpath,${SASL_LIB_DIR}"
	      else 
		RPATH="${RPATH}:${SASL_LIB_DIR}"
	      fi
	      ;;
	    *-*-hpux*)
	      if test "X$RPATH" = "X"; then
	        RPATH="-Wl,+b${SASL_LIB_DIR}"
	      else 
		RPATH="${RPATH}:${SASL_LIB_DIR}"
	      fi
	      ;;
	    *-*-irix*)
	      if test "X$RPATH" = "X"; then
	        RPATH="-Wl,-rpath,${SASL_LIB_DIR}"
	      else 
		RPATH="${RPATH}:${SASL_LIB_DIR}"
	      fi
	      ;;
	    *-*-solaris2*)
	      if test "$ac_cv_prog_gcc" = yes; then
		if test "X$RPATH" = "X"; then
		  RPATH="-Wl,-R${SASL_LIB_DIR}"
		else 
		  RPATH="${RPATH}:${SASL_LIB_DIR}"
		fi
	      else
	        RPATH="${RPATH} -R${SASL_LIB_DIR}"
	      fi
	      ;;
	  esac
	  AC_SUBST(RPATH)
	fi
	AC_SUBST(SASL_INC_DIR)
	AC_SUBST(SASL_INC_FLAGS)
	AC_SUBST(SASL_LIB_DIR)
	AC_SUBST(SASL_LIB_FLAGS)
	])

AC_DEFUN(CMU_NEEDS_SASL,
[AC_REQUIRE([CMU_SASL])
if test "$ac_cv_found_sasl" != "yes"; then
        AC_ERROR([Cannot continue without sasl (Get it from <url:ftp://ftp.andrew.cmu.edu:/pub/cyrus-mail/>).])
fi])

AC_DEFUN(CMU_TEST_LIBPATH, [
changequote(<<, >>)
define(<<CMU_AC_CV_FOUND>>, translit(ac_cv_found_$2_lib, [ *], [_p]))
changequote([, ])
if test "$CMU_AC_CV_FOUND" = "yes"; then
  if test \! -f "$1/lib$2.a" -a \! -f "$i/lib$2.so" -a \! -f "$i/lib$2.sl"; then
    CMU_AC_CV_FOUND=no
  fi
fi
])

AC_DEFUN(CMU_TEST_INCPATH, [
changequote(<<, >>)
define(<<CMU_AC_CV_FOUND>>, translit(ac_cv_found_$2_inc, [ *], [_p]))
changequote([, ])
if test "$CMU_AC_CV_FOUND" = "yes"; then
  if test \! -f "$1/$2.h"; then
    CMU_AC_CV_FOUND=no
  fi
fi
])

dnl CMU_CHECK_HEADER_NOCACHE(HEADER-FILE, [ACTION-IF-FOUND [, ACTION-IF-NOT-FOUND]])
AC_DEFUN(CMU_CHECK_HEADER_NOCACHE,
[dnl Do the transliteration at runtime so arg 1 can be a shell variable.
ac_safe=`echo "$1" | sed 'y%./+-%__p_%'`
AC_MSG_CHECKING([for $1])
AC_TRY_CPP([#include <$1>], eval "ac_cv_header_$ac_safe=yes",
  eval "ac_cv_header_$ac_safe=no")
if eval "test \"`echo '$ac_cv_header_'$ac_safe`\" = yes"; then
  AC_MSG_RESULT(yes)
  ifelse([$2], , :, [$2])
else
  AC_MSG_RESULT(no)
ifelse([$3], , , [$3
])dnl
fi
])

dnl bsd_sockets.m4--which socket libraries do we need? 
dnl Derrick Brashear
dnl from Zephyr

dnl Hacked on by Rob Earhart to not just toss stuff in LIBS
dnl It now puts everything required for sockets into LIB_SOCKET

AC_DEFUN(CMU_SOCKETS, [
	LIB_SOCKET=""
	AC_CHECK_FUNC(connect, :,
		AC_CHECK_LIB(nsl, gethostbyname,
			     LIB_SOCKET="-lnsl $LIB_SOCKET")
		AC_CHECK_LIB(socket, connect,
			     LIB_SOCKET="-lsocket $LIB_SOCKET")
	)
	AC_SUBST(LIB_SOCKET)
	])

dnl kerberos_v4.m4--Kerberos 4 libraries and includes
dnl Derrick Brashear
dnl from KTH krb and Arla

AC_DEFUN(CMU_KRB_SET_KEY_PROTO, [
AC_MSG_CHECKING(for krb_set_key prototype)
AC_CACHE_VAL(ac_cv_krb_set_key_proto, [
cmu_save_CPPFLAGS="$CPPFLAGS"
CPPFLAGS="${CPPFLAGS} ${KRB_INC_FLAGS}"
AC_TRY_COMPILE(
[#include <krb.h>
int krb_set_key(char *key, int cvt);],
[int foo = krb_set_key(0, 0);],
ac_cv_krb_set_key_proto=no,
ac_cv_krb_set_key_proto=yes)
])
CPPFLAGS="${cmu_save_CPPFLAGS}"
if test "$ac_cv_krb_set_key_proto" = yes; then
	AC_DEFINE(HAVE_KRB_SET_KEY_PROTO)dnl
fi
AC_MSG_RESULT($ac_cv_krb_set_key_proto)
])

AC_DEFUN(CMU_KRB_RD_REQ_PROTO, [
AC_MSG_CHECKING(for krb_rd_req prototype)
AC_CACHE_VAL(ac_cv_krb_rd_req_proto, [
cmu_save_CPPFLAGS="$CPPFLAGS"
CPPFLAGS="${CPPFLAGS} ${KRB_INC_FLAGS}"
AC_TRY_COMPILE(
[#include <krb.h>
int krb_rd_req(KTEXT authent, char *service, char *instance,
unsigned KRB_INT32 from_addr, AUTH_DAT *ad, char *fn);],
[int foo = krb_rd_req(NULL, NULL, NULL, 0, NULL, NULL);],
ac_cv_krb_rd_req_proto=no,
ac_cv_krb_rd_req_proto=yes)
])
CPPFLAGS="${cmu_save_CPPFLAGS}"
if test "$ac_cv_krb_rd_req_proto" = yes; then
	AC_DEFINE(HAVE_KRB_RD_REQ_PROTO)dnl
fi
AC_MSG_RESULT($ac_cv_krb_rd_req_proto)
])

AC_DEFUN(CMU_KRB_INC_WHERE1, [
AC_REQUIRE([AC_PROG_CC_GNU])
saved_CPPFLAGS=$CPPFLAGS
CPPFLAGS="$saved_CPPFLAGS -I$1"
AC_TRY_COMPILE([#include <krb.h>],
[struct ktext foo;],
ac_cv_found_krb_inc=yes,
ac_cv_found_krb_inc=no)
if test "$ac_cv_found_krb_inc" = "no"; then
  CPPFLAGS="$saved_CPPFLAGS -I$1 -I$1/kerberosIV"
  AC_TRY_COMPILE([#include <krb.h>],
  [struct ktext foo;],
  [ac_cv_found_krb_inc=yes],
  ac_cv_found_krb_inc=no)
fi
CPPFLAGS=$saved_CPPFLAGS
])

AC_DEFUN(CMU_KRB_INC_WHERE, [
   for i in $1; do
      AC_MSG_CHECKING(for kerberos headers in $i)
      CMU_KRB_INC_WHERE1($i)
      CMU_TEST_INCPATH($i, krb)
      if test "$ac_cv_found_krb_inc" = "yes"; then
        ac_cv_krb_where_inc=$i
        AC_MSG_RESULT(found)
        break
      else
        AC_MSG_RESULT(not found)
      fi
    done
])

#
# Test for kerberos lib files
#

AC_DEFUN(CMU_KRB_LIB_WHERE1, [
AC_REQUIRE([AC_PROG_CC_GNU])
saved_LIBS=$LIBS
LIBS="$saved_LIBS -L$1 -lkrb -ldes"
AC_TRY_LINK(,
[dest_tkt();des_ecb_encrypt();],
[ac_cv_found_krb_lib=yes],
ac_cv_found_krb_lib=no)
LIBS=$saved_LIBS
])

AC_DEFUN(CMU_KRB_LIB_WHERE, [
   for i in $1; do
      AC_MSG_CHECKING(for kerberos libraries in $i)
      CMU_KRB_LIB_WHERE1($i)
      dnl deal with false positives from implicit link paths
      CMU_TEST_LIBPATH($i, krb)
      if test "$ac_cv_found_krb_lib" = "yes" ; then
        ac_cv_krb_where_lib=$i
        AC_MSG_RESULT(found)
        break
      else
        AC_MSG_RESULT(not found)
      fi
    done
])

AC_DEFUN(CMU_KRB4, [
AC_REQUIRE([CMU_SOCKETS])
AC_ARG_WITH(krb4,
	[  --with-krb4=PREFIX      Compile with Kerberos 4 support],
	[if test "X$with_krb4" = "X"; then
		with_krb4=yes
	fi])
AC_ARG_WITH(krb4-lib,
	[  --with-krb4-lib=dir     use kerberos 4 libraries in dir],
	[if test "$withval" = "yes" -o "$withval" = "no"; then
		AC_MSG_ERROR([No argument for --with-krb4-lib])
	fi])
AC_ARG_WITH(krb4-include,
	[  --with-krb4-include=dir use kerberos 4 headers in dir],
	[if test "$withval" = "yes" -o "$withval" = "no"; then
		AC_MSG_ERROR([No argument for --with-krb4-include])
	fi])

	if test "X$with_krb4" != "X"; then
	  if test "$with_krb4" != "yes" -a "$with_krb4" != "no"; then
	    ac_cv_krb_where_lib=$with_krb4/lib
	    ac_cv_krb_where_inc=$with_krb4/include
	  fi
	fi

	if test "$with_krb4" != "no"; then
	  if test "X$with_krb4_lib" != "X"; then
	    ac_cv_krb_where_lib=$with_krb4_lib
	  fi
	  if test "X$ac_cv_krb_where_lib" = "X"; then
	    CMU_KRB_LIB_WHERE(/usr/athena/lib /usr/local/lib /usr/lib)
	  fi

	  if test "X$with_krb4_include" != "X"; then
	    ac_cv_krb_where_inc=$with_krb4_include
	  fi
	  if test "X$ac_cv_krb_where_inc" = "X"; then
	    CMU_KRB_INC_WHERE(/usr/athena/include /usr/include/kerberosIV /usr/local/include /usr/include/kerberos)
	  fi
	fi

	AC_MSG_CHECKING(whether to include kerberos 4)
	if test "X$ac_cv_krb_where_lib" = "X" -a "X$ac_cv_krb_where_inc" = "X"; then
	  ac_cv_found_krb=no
	  AC_MSG_RESULT(no)
	else
	  ac_cv_found_krb=yes
	  AC_MSG_RESULT(yes)
	  KRB_INC_DIR=$ac_cv_krb_where_inc
	  KRB_LIB_DIR=$ac_cv_krb_where_lib
	  KRB_INC_FLAGS="-I${KRB_INC_DIR}"
	  KRB_LIB_FLAGS="-L${KRB_LIB_DIR} -lkrb -ldes"
	  cmu_save_LIBS="$LIBS"
	  LIBS="${LIBS} ${KRB_LIB_FLAGS}"
	  AC_CHECK_LIB(resolv, dns_lookup, KRB_LIB_FLAGS="${KRB_LIB_FLAGS} -lresolv",,"${KRB_LIB_FLAGS}")
	  AC_CHECK_LIB(crypt, crypt, KRB_LIB_FLAGS="${KRB_LIB_FLAGS} -lcrypt",,"${KRB_LIB_FLAGS}")
	  AC_CHECK_FUNCS(krb_get_int krb_life_to_time)
          AC_SUBST(KRB_INC_FLAGS)
          AC_SUBST(KRB_LIB_FLAGS)
	  LIBS="${cmu_save_LIBS}"
	  AC_DEFINE(KERBEROS)
	  if test "X$RPATH" = "X"; then
		RPATH=""
	  fi
	  case "${host}" in
	    *-*-linux*)
	      if test "X$RPATH" = "X"; then
	        RPATH="-Wl,-rpath,${KRB_LIB_DIR}"
	      else 
		RPATH="${RPATH}:${KRB_LIB_DIR}"
	      fi
	      ;;
	    *-*-hpux*)
	      if test "X$RPATH" = "X"; then
	        RPATH="-Wl,+b${KRB_LIB_DIR}"
	      else 
		RPATH="${RPATH}:${KRB_LIB_DIR}"
	      fi
	      ;;
	    *-*-irix*)
	      if test "X$RPATH" = "X"; then
	        RPATH="-Wl,-rpath,${KRB_LIB_DIR}"
	      else 
		RPATH="${RPATH}:${KRB_LIB_DIR}"
	      fi
	      ;;
	    *-*-solaris2*)
	      if test "$ac_cv_prog_gcc" = yes; then
		if test "X$RPATH" = "X"; then
		  RPATH="-Wl,-R${KRB_LIB_DIR}"
		else 
		  RPATH="${RPATH}:${KRB_LIB_DIR}"
		fi
	      else
	        RPATH="${RPATH} -R${KRB_LIB_DIR}"
	      fi
	      ;;
	  esac
	  AC_SUBST(RPATH)
	fi
	])


dnl agentx.m4--detect agentx libraries
dnl copied from x-unixrc
dnl Tim Martin

AC_DEFUN(CMU_AGENTX, [

	dnl
	dnl CMU AgentX
	dnl
	AC_MSG_CHECKING([for AgentX])
	AC_ARG_WITH(agentx, [  --with-agentx              CMU AgentX libraries located in (val)], AGENTX_DIR="$withval", AGENTX_DIR=no)

	found_agentx="no"

	if test "${AGENTX_DIR}" != "no" &&
	   test -f $AGENTX_DIR/lib${ABILIBDIR}/libagentx.a &&
	   test -f $AGENTX_DIR/include/agentx.h; then
	     AGENTX_DIR="$AGENTX_DIR"
	     found_agentx="yes"
	elif test -d /usr/local &&
	   test -f /usr/local/lib${ABILIBDIR}/libagentx.a &&
	   test -f /usr/local/include/agentx.h; then
	     AGENTX_DIR="/usr/local"
	     found_agentx="yes"

	elif test -d /usr/ng &&
	   test -f /usr/ng/lib${ABILIBDIR}/libagentx.a &&
	   test -f /usr/ng/include/agentx.h; then
	     AGENTX_DIR="/usr/ng"
	     found_agentx="yes"
	fi

	if test "$found_agentx" = "no"; then
	  AC_MSG_WARN([Could not locate AgentX Libraries! http://www.net.cmu.edu/groups/netdev/agentx/])
	else
	  LIB_AGENTX="-L$AGENTX_DIR/lib${ABILIBDIR} -lagentx"
  	  AC_SUBST(LIB_AGENTX)
	  AGENTXFLAGS="-I$AGENTX_DIR/include"
          AC_SUBST(AGENTXFLAGS)   
	  AC_MSG_RESULT([found $AGENTX_DIR/lib${ABILIBDIR}/libagentx.a])	
	fi



])
dnl pthreads.m4--pthreads setup macro
dnl Rob Earhart

AC_DEFUN(CMU_PTHREADS, [
   AC_REQUIRE([AC_CANONICAL_HOST])
   cmu_save_LIBS="$LIBS"
   AC_CHECK_LIB(pthread, pthread_create,LIB_PTHREAD="-lpthread",
     AC_CHECK_LIB(c_r, pthread_create,LIB_PTHREAD="-lc_r",
       AC_ERROR([Can't compile without pthreads])))
  LIBS="$cmu_save_LIBS"
   AC_SUBST(LIB_PTHREAD)
   AC_DEFINE(_REENTRANT)
   case "$host_os" in
   solaris2*)
 	AC_DEFINE(_POSIX_PTHREAD_SEMANTICS)
 	AC_DEFINE(__EXTENSIONS__)
 	;;
   irix6*)
 	AC_DEFINE(_SGI_REENTRANT_FUNCTIONS)
 	;;
   esac
])


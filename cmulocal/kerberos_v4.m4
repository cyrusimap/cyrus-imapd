dnl kerberos_v4.m4--Kerberos 4 libraries and includes
dnl Derrick Brashear
dnl from KTH krb and Arla
dnl $Id: kerberos_v4.m4,v 1.23 2002/07/22 20:26:02 shadow Exp $

AC_DEFUN(CMU_KRB_SENDAUTH_PROTO, [
AC_MSG_CHECKING(for krb_sendauth prototype)
AC_TRY_COMPILE(
[#include <krb.h>
int krb_sendauth (long options, int fd, KTEXT ktext, char *service,
                  char *inst, char *realm, u_long checksum,
                  MSG_DAT *msg_data, CREDENTIALS *cred,
                  Key_schedule schedule, struct sockaddr_in *laddr,
                  struct sockaddr_in *faddr, char *version);],
[int foo = krb_sendauth(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0); ],
ac_cv_krb_sendauth_proto=no,
ac_cv_krb_sendauth_proto=yes)
AC_MSG_RESULT($ac_cv_krb_sendauth_proto)
if test "$ac_cv_krb_sendauth_proto" = yes; then
        AC_DEFINE(HAVE_KRB_SENDAUTH_PROTO)dnl
fi
AC_MSG_RESULT($ac_cv_krb_sendauth_proto)
])

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

AC_DEFUN(CMU_KRB4_32_DEFN, [
AC_MSG_CHECKING(for KRB4_32 definition)
AC_CACHE_VAL(ac_cv_krb4_32_defn, [
cmu_save_CPPFLAGS="$CPPFLAGS"
CPPFLAGS="${CPPFLAGS} ${KRB_INC_FLAGS}"
AC_TRY_COMPILE(
[#include <krb.h>
],
[KRB4_32 foo = 1;],
ac_cv_krb4_32_defn=yes,
ac_cv_krb4_32_defn=no)
])
CPPFLAGS="${cmu_save_CPPFLAGS}"
if test "$ac_cv_krb4_32_defn" = yes; then
	AC_DEFINE(HAVE_KRB4_32_DEFINE)dnl
fi
AC_MSG_RESULT($ac_cv_krb4_32_defn)
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
[int foo = krb_rd_req(0,0,0,0,0,0);],
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
LIBS="$saved_LIBS -L$1 -lkrb"
AC_TRY_LINK(,
[dest_tkt();],
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
AC_REQUIRE([CMU_LIBSSL])
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

          AC_MSG_CHECKING([if libdes is needed])
          AC_TRY_LINK([],[des_quad_cksum();],AFS_DES_LIB="",AFS_DES_LIB="maybe")
          if test "X$KRB_DES_LIB" != "X"; then
              LIBS="$cmu_save_LIBS -ldes"
              AC_TRY_LINK([], [des_quad_cksum();],KRB_DES_LIB="yes")
              if test "X$KRB_DES_LIB" = "Xyes"; then
                  AC_MSG_RESULT([yes])
                  KRB_LIBDES="-ldes"
                  KRB_LIBDESA="${KRB_LIB_DIR}/libdes.a"
              else
                  LIBS="$cmu_save_LIBS $LIBSSL_LIB_FLAGS"
                  AC_TRY_LINK([],
                  [des_quad_cksum();],KRB_DES_LIB="libcrypto")
                  if test "X$KRB_DES_LIB" = "Xlibcrypto"; then
                      AC_MSG_RESULT([libcrypto])
                      KRB_LIBDES="$LIBSSL_LIB_FLAGS"
                      KRB_LIBDESA="$LIBSSL_LIB_FLAGS"
                  else
                      AC_MSG_RESULT([unknown])
                      AC_MSG_ERROR([Could not use -ldes])
                  fi 
              fi 
          else
             AC_MSG_RESULT([no])
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
	  KRB_LIB_FLAGS="-L${KRB_LIB_DIR} -lkrb ${KRB_LIBDES}"
	  cmu_save_LIBS="$LIBS"
	  LIBS="${LIBS} ${KRB_LIB_FLAGS}"
	  AC_CHECK_LIB(resolv, dns_lookup, KRB_LIB_FLAGS="${KRB_LIB_FLAGS} -lresolv",,"${KRB_LIB_FLAGS}")
	  AC_CHECK_LIB(crypt, crypt, KRB_LIB_FLAGS="${KRB_LIB_FLAGS} -lcrypt",,"${KRB_LIB_FLAGS}")
	  AC_CHECK_FUNCS(krb_get_int krb_life_to_time)
          AC_SUBST(KRB_INC_FLAGS)
          AC_SUBST(KRB_LIB_FLAGS)
	  LIBS="${cmu_save_LIBS}"
	  AC_DEFINE(KERBEROS,,[Use kerberos 4. find out what needs this symbol])
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


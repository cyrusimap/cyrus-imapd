dnl afs.m4--AFS libraries, includes, and dependencies
dnl $Id: afs.m4,v 1.25 2003/05/09 03:51:17 cg2v Exp $
dnl Chaskiel Grundman
dnl based on kerberos_v4.m4
dnl Derrick Brashear
dnl from KTH krb and Arla

AC_DEFUN(CMU_AFS_INC_WHERE1, [
cmu_save_CPPFLAGS=$CPPFLAGS
CPPFLAGS="$cmu_save_CPPFLAGS -I$1"
AC_TRY_COMPILE([#include <afs/param.h>],
[#ifndef SYS_NAME
choke me
#endif
int foo;],
ac_cv_found_afs_inc=yes,
ac_cv_found_afs_inc=no)
CPPFLAGS=$cmu_save_CPPFLAGS
])

AC_DEFUN(CMU_AFS_LIB_WHERE1, [
save_LIBS="$LIBS"
save_LDFLAGS="$LDFLAGS"

LIBS="-lauth $1/afs/util.a $LIB_SOCKET $LIBS"
LDFLAGS="-L$1 -L$1/afs $LDFLAGS"
dnl suppress caching
AC_TRY_LINK([],[afsconf_Open();], ac_cv_found_afs_lib=yes, ac_cv_found_afs_lib=no)
LIBS="$save_LIBS"
LDFLAGS="$save_LDFLAGS"
])

AC_DEFUN(CMU_AFS_WHERE, [
   for i in $1; do
      AC_MSG_CHECKING(for AFS in $i)
      CMU_AFS_INC_WHERE1("$i/include")
      ac_cv_found_lwp_inc=$ac_cv_found_afs_inc
      CMU_TEST_INCPATH($i/include, lwp) 
      ac_cv_found_afs_inc=$ac_cv_found_lwp_inc
      if test "$ac_cv_found_afs_inc" = "yes"; then
        CMU_AFS_LIB_WHERE1("$i/lib")
        if test "$ac_cv_found_afs_lib" = "yes"; then
          ac_cv_afs_where=$i
          AC_MSG_RESULT(found)
          break
        else
          AC_MSG_RESULT(not found)
        fi
      else
        AC_MSG_RESULT(not found)
      fi
    done
])

AC_DEFUN(CMU_AFS, [
AC_REQUIRE([CMU_SOCKETS])
AC_REQUIRE([CMU_LIBSSL])
AC_ARG_WITH(AFS,
	[  --with-afs=PREFIX      Compile with AFS support],
	[if test "X$with_AFS" = "X"; then
		with_AFS=yes
	fi])

	if test "X$with_AFS" != "X"; then
	  ac_cv_afs_where=$with_AFS
	fi
	if test "X$ac_cv_afs_where" = "X"; then
	  CMU_AFS_WHERE(/usr/afsws /usr/local /usr/athena)
	fi

	AC_MSG_CHECKING(whether to include AFS)
	if test "X$ac_cv_afs_where" = "Xno" -o "X$ac_cv_afs_where" = "X"; then
	  ac_cv_found_afs=no
	  AC_MSG_RESULT(no)
	else
	  ac_cv_found_afs=yes
	  AC_MSG_RESULT(yes)
	  AFS_INC_DIR="$ac_cv_afs_where/include"
	  AFS_LIB_DIR="$ac_cv_afs_where/lib"
	  AFS_TOP_DIR="$ac_cv_afs_where"
	  AFS_INC_FLAGS="-I${AFS_INC_DIR}"
          AFS_LIB_FLAGS="-L${AFS_LIB_DIR} -L${AFS_LIB_DIR}/afs"
          cmu_save_LIBS="$LIBS"
          cmu_save_CPPFLAGS="$CPPFLAGS"
          CPPFLAGS="$CPPFLAGS ${AFS_INC_FLAGS}"
	  cmu_save_LDFLAGS="$LDFLAGS"
 	  LDFLAGS="$cmu_save_LDFLAGS ${AFS_LIB_FLAGS}"
                        
          AC_CHECK_HEADERS(afs/stds.h)

          AC_MSG_CHECKING([if libdes is needed])
          AC_TRY_LINK([],[des_quad_cksum();],AFS_DES_LIB="",AFS_DES_LIB="maybe")
          if test "X$AFS_DES_LIB" != "X"; then
              LIBS="$cmu_save_LIBS -ldes"
              AC_TRY_LINK([], [des_quad_cksum();],AFS_DES_LIB="yes")
              if test "X$AFS_DES_LIB" = "Xyes"; then
                  AC_MSG_RESULT([yes])
    	          AFS_LIBDES="-ldes"
    	          AFS_LIBDESA="${AFS_LIB_DIR}/libdes.a"
    	      else
   	          LIBS="$cmu_save_LIBS $LIBSSL_LIB_FLAGS"
 	          AC_TRY_LINK([],
	          [des_quad_cksum();],AFS_DES_LIB="libcrypto")
	          if test "X$AFS_DES_LIB" = "Xlibcrypto"; then
	              AC_MSG_RESULT([libcrypto])
		      AFS_LIBDES="$LIBSSL_LIB_FLAGS"
	              AFS_LIBDESA="$LIBSSL_LIB_FLAGS"
	          else
         	      AC_MSG_RESULT([unknown])
	              AC_MSG_ERROR([Could not use -ldes])
	          fi 
	      fi 
	  else
             AC_MSG_RESULT([no])
          fi


	  AFS_CLIENT_LIBS_STATIC="${AFS_LIB_DIR}/afs/libvolser.a ${AFS_LIB_DIR}/afs/libvldb.a ${AFS_LIB_DIR}/afs/libkauth.a ${AFS_LIB_DIR}/afs/libprot.a ${AFS_LIB_DIR}/libubik.a ${AFS_LIB_DIR}/afs/libauth.a ${AFS_LIB_DIR}/librxkad.a ${AFS_LIB_DIR}/librx.a ${AFS_LIB_DIR}/afs/libsys.a ${AFS_LIB_DIR}/librx.a ${AFS_LIB_DIR}/liblwp.a ${AFS_LIBDESA} ${AFS_LIB_DIR}/afs/libcmd.a ${AFS_LIB_DIR}/afs/libcom_err.a ${AFS_LIB_DIR}/afs/util.a"
          AFS_KTC_LIBS_STATIC="${AFS_LIB_DIR}/afs/libauth.a ${AFS_LIB_DIR}/afs/libsys.a ${AFS_LIB_DIR}/librx.a ${AFS_LIB_DIR}/liblwp.a ${AFS_LIBDESA} ${AFS_LIB_DIR}/afs/libcom_err.a ${AFS_LIB_DIR}/afs/util.a"
	  AFS_CLIENT_LIBS="-lvolser -lvldb -lkauth -lprot -lubik -lauth -lrxkad -lrx ${AFS_LIB_DIR}/afs/libsys.a -lrx -llwp ${AFS_LIBDES} -lcmd -lcom_err ${AFS_LIB_DIR}/afs/util.a"
	  AFS_RX_LIBS="-lauth -lrxkad -lrx ${AFS_LIB_DIR}/afs/libsys.a -lrx -llwp ${AFS_LIBDES} -lcmd -lcom_err ${AFS_LIB_DIR}/afs/util.a"
          AFS_KTC_LIBS="-lauth ${AFS_LIB_DIR}/afs/libsys.a -lrx -llwp ${AFS_LIBDES} -lcom_err ${AFS_LIB_DIR}/afs/util.a"
          LIBS="$cmu_save_LIBS"
          AC_CHECK_FUNC(flock)
          LIBS="$cmu_save_LIBS ${AFS_CLIENT_LIBS} ${LIB_SOCKET}"
          if test "X$ac_cv_func_flock" != "Xyes"; then
             AC_MSG_CHECKING([if AFS needs flock])
             AC_TRY_LINK([#include <afs/param.h>
#ifdef HAVE_AFS_STDS_H
#include <afs/stds.h>
#endif
#include <ubik.h>
#include <afs/cellconfig.h>
#include <afs/auth.h>
#include <afs/volser.h>
struct ubik_client * cstruct;
int sigvec() {return 0;}
extern int UV_SetSecurity();],
             [vsu_ClientInit(1,"","",0,
                             &cstruct,UV_SetSecurity)],
             AFS_FLOCK=no,AFS_FLOCK=yes)
             if test $AFS_FLOCK = "no"; then
                AC_MSG_RESULT([no])
             else
               AC_MSG_RESULT([yes])
               LDFLAGS="$LDFLAGS -L/usr/ucblib"
               AC_CHECK_LIB(ucb, flock,:, [AC_CHECK_LIB(BSD, flock)])
             fi
          fi
          LIBS="$cmu_save_LIBS"
          AC_CHECK_FUNC(sigvec)
          LIBS="$cmu_save_LIBS ${AFS_CLIENT_LIBS} ${LIB_SOCKET}"
          if test "X$ac_cv_func_sigvec" != "Xyes"; then
             AC_MSG_CHECKING([if AFS needs sigvec])
             AC_TRY_LINK([#include <afs/param.h>
#ifdef HAVE_AFS_STDS_H
#include <afs/stds.h>
#endif
#include <ubik.h>
#include <afs/cellconfig.h>
#include <afs/auth.h>
#include <afs/volser.h>
struct ubik_client * cstruct;
int flock() {return 0;}
extern int UV_SetSecurity();],
             [vsu_ClientInit(1,"","",0,
                             &cstruct,UV_SetSecurity)],
             AFS_SIGVEC=no,AFS_SIGVEC=yes)
             if test $AFS_SIGVEC = "no"; then
                AC_MSG_RESULT([no])
             else
               AC_MSG_RESULT([yes])
               LDFLAGS="$LDFLAGS -L/usr/ucblib"
               AC_CHECK_LIB(ucb, sigvec,:,[AC_CHECK_LIB(BSD, sigvec)])
             fi
          fi
          if test "$ac_cv_lib_ucb_flock" = "yes" -o "$ac_cv_lib_ucb_sigvec" = "yes"; then
             AFS_LIB_FLAGS="${AFS_LIB_FLAGS} -L/usr/ucblib -R/usr/ucblib"
          fi
          if test "$ac_cv_lib_ucb_flock" = "yes" -o "$ac_cv_lib_ucb_sigvec" = "yes"; then
             AFS_BSD_LIB="-lucb"
          elif test "$ac_cv_lib_BSD_flock" = "yes" -o "$ac_cv_lib_BSD_sigvec" = "yes"; then
             AFS_BSD_LIB="-lBSD"
          fi
          if test "X$AFS_BSD_LIB" != "X" ; then
                AFS_CLIENT_LIBS_STATIC="$AFS_CLIENT_LIBS_STATIC $AFS_BSD_LIB"
                AFS_KTC_LIBS_STATIC="$AFS_KTC_LIBS_STATIC $AFS_BSD_LIB"
                AFS_CLIENT_LIBS="$AFS_CLIENT_LIBS $AFS_BSD_LIB"
                AFS_RX_LIBS="$AFS_CLIENT_LIBS $AFS_BSD_LIB"
                AFS_KTC_LIBS="$AFS_KTC_LIBS $AFS_BSD_LIB"
          fi
          LIBS="$cmu_save_LIBS $AFS_CLIENT_LIBS ${LIB_SOCKET}"
          AC_CHECK_FUNC(des_pcbc_init)
          if test "X$ac_cv_func_des_pcbc_init" != "Xyes"; then
           AC_CHECK_LIB(descompat, des_pcbc_init, AFS_DESCOMPAT_LIB="-ldescompat")
           if test "X$AFS_DESCOMPAT_LIB" != "X" ; then
                AFS_CLIENT_LIBS_STATIC="$AFS_CLIENT_LIBS_STATIC $AFS_DESCOMPAT_LIB"
                AFS_KTC_LIBS_STATIC="$AFS_KTC_LIBS_STATIC $AFS_DESCOMPAT_LIB"
                AFS_CLIENT_LIBS="$AFS_CLIENT_LIBS $AFS_DESCOMPAT_LIB"
                AFS_KTC_LIBS="$AFS_KTC_LIBS $AFS_DESCOMPAT_LIB"
           else

           AC_MSG_CHECKING([if rxkad needs des_pcbc_init])
           AC_TRY_LINK(,[tkt_DecodeTicket();],RXKAD_PROBLEM=no,RXKAD_PROBLEM=maybe)
            if test "$RXKAD_PROBLEM" = "maybe"; then
              AC_TRY_LINK([int des_pcbc_init() { return 0;}],
              [tkt_DecodeTicket();],RXKAD_PROBLEM=yes,RXKAD_PROBLEM=error)
              if test "$RXKAD_PROBLEM" = "yes"; then
                    AC_MSG_RESULT([yes])
                    AC_MSG_ERROR([cannot use rxkad])
              else
                    AC_MSG_RESULT([unknown])        
                    AC_MSG_ERROR([Unknown error testing rxkad])
              fi
            else
              AC_MSG_RESULT([no])
            fi
           fi
          fi

          AC_MSG_CHECKING([if libaudit is needed])
	  AFS_LIBAUDIT=""
          LIBS="$cmu_save_LIBS $AFS_CLIENT_LIBS ${LIB_SOCKET}"
          AC_TRY_LINK([#include <afs/param.h>
#ifdef HAVE_AFS_STDS_H
#include <afs/stds.h>
#endif
#include <afs/cellconfig.h>
#include <afs/auth.h>],
          [afsconf_SuperUser();],AFS_AUDIT_LIB="",AFS_AUDIT_LIB="maybe")
          if test "X$AFS_AUDIT_LIB" != "X"; then
          LIBS="$cmu_save_LIBS -lvolser -lvldb -lkauth -lprot -lubik -lauth -laudit -lrxkad -lrx ${AFS_LIB_DIR}/afs/libsys.a -lrx -llwp ${AFS_LIBDES} -lcmd -lcom_err ${AFS_LIB_DIR}/afs/util.a $AFS_BSD_LIB $AFS_DESCOMPAT_LIB $LIB_SOCKET"
             AC_TRY_LINK([#include <afs/param.h>
#ifdef HAVE_AFS_STDS_H
#include <afs/stds.h>
#endif
#include <afs/cellconfig.h>
#include <afs/auth.h>],
             [afsconf_SuperUser();],AFS_AUDIT_LIB="yes")
             if test "X$AFS_AUDIT_LIB" = "Xyes"; then
                 AC_MSG_RESULT([yes])
	         AFS_LIBAUDIT="-laudit"
	         AFS_CLIENT_LIBS_STATIC="${AFS_LIB_DIR}/afs/libvolser.a ${AFS_LIB_DIR}/afs/libvldb.a ${AFS_LIB_DIR}/afs/libkauth.a ${AFS_LIB_DIR}/afs/libprot.a ${AFS_LIB_DIR}/libubik.a ${AFS_LIB_DIR}/afs/libauth.a ${AFS_LIB_DIR}/afs/libaudit.a ${AFS_LIB_DIR}/librxkad.a ${AFS_LIB_DIR}/librx.a ${AFS_LIB_DIR}/afs/libsys.a ${AFS_LIB_DIR}/librx.a ${AFS_LIB_DIR}/liblwp.a ${AFS_LIBDESA} ${AFS_LIB_DIR}/afs/libcmd.a ${AFS_LIB_DIR}/afs/libcom_err.a ${AFS_LIB_DIR}/afs/util.a"
                 AFS_CLIENT_LIBS="-lvolser -lvldb -lkauth -lprot -lubik -lauth -laudit -lrxkad -lrx ${AFS_LIB_DIR}/afs/libsys.a -lrx -llwp ${AFS_LIBDES} -lcmd -lcom_err ${AFS_LIB_DIR}/afs/util.a $AFS_BSD_LIB $AFS_DESCOMPAT_LIB"
                 AFS_RX_LIBS="-lauth -laudit -lrxkad -lrx ${AFS_LIB_DIR}/afs/libsys.a -lrx -llwp ${AFS_LIBDES} -lcmd -lcom_err ${AFS_LIB_DIR}/afs/util.a $AFS_BSD_LIB $AFS_DESCOMPAT_LIB"
             else
                 AC_MSG_RESULT([unknown])
                 AC_MSG_ERROR([Could not use -lauth while testing for -laudit])
             fi 
          else
             AC_MSG_RESULT([no])
          fi

	  AC_CHECK_FUNCS(VL_ProbeServer)
          AC_MSG_CHECKING([if new-style afs_ integer types are defined])
          AC_CACHE_VAL(ac_cv_afs_int32,
dnl The next few lines contain a quoted argument to egrep
dnl It is critical that there be no leading or trailing whitespace
dnl or newlines
[AC_EGREP_CPP(dnl
changequote(<<,>>)dnl
<<(^|[^a-zA-Z_0-9])afs_int32[^a-zA-Z_0-9]>>dnl
changequote([,]), [#include <afs/param.h>
#ifdef HAVE_AFS_STDS_H
#include <afs/stds.h>
#endif],
ac_cv_afs_int32=yes, ac_cv_afs_int32=no)])
          AC_MSG_RESULT($ac_cv_afs_int32)
          if test $ac_cv_afs_int32 = yes ; then
            AC_DEFINE(HAVE_AFS_INT32,, [AFS provides new "unambiguous" type names])
          else
            AC_DEFINE(afs_int16, int16, [it's a type definition])
            AC_DEFINE(afs_int32, int32, [it's a type definition])
            AC_DEFINE(afs_uint16, u_int16, [it's a type definition])
            AC_DEFINE(afs_uint32, u_int32, [it's a type definition])
          fi

          CPPFLAGS="${cmu_save_CPPFLAGS}"
          LDFLAGS="${cmu_save_LDFLAGS}"
          LIBS="${cmu_save_LIBS}"
	  AC_DEFINE(AFS_ENV,, [Use AFS. (find what needs this and nuke it)])
          AC_DEFINE(AFS,, [Use AFS. (find what needs this and nuke it)])
          AC_SUBST(AFS_CLIENT_LIBS_STATIC)
          AC_SUBST(AFS_KTC_LIBS_STATIC)
          AC_SUBST(AFS_CLIENT_LIBS)
          AC_SUBST(AFS_RX_LIBS)
          AC_SUBST(AFS_KTC_LIBS)
          AC_SUBST(AFS_INC_FLAGS)
          AC_SUBST(AFS_LIB_FLAGS)
	  AC_SUBST(AFS_TOP_DIR)
	  AC_SUBST(AFS_LIBAUDIT)
	  AC_SUBST(AFS_LIBDES)
          AC_SUBST(AFS_LIBDESA)
       	fi
	])

AC_DEFUN(CMU_NEEDS_AFS,
[AC_REQUIRE([CMU_AFS])
if test "$ac_cv_found_afs" != "yes"; then
        AC_ERROR([Cannot continue without AFS])
fi])

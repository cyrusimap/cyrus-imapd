dnl afs.m4--AFS libraries, includes, and dependencies
dnl Chaskiel Grundman
dnl based on kerberos_v4.m4
dnl Derrick Brashear
dnl from KTH krb and Arla

AC_DEFUN(CMU_AFS_INC_WHERE1, [
AC_REQUIRE([AC_PROG_CC_GNU])
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
AC_ARG_WITH(AFS,
	[  --with-afs=PREFIX      Compile with AFS support],
	[if test "X$with_afs" = "X"; then
		with_afs=yes
	fi])

	if test "X$with_afs" != "X"; then
	  ac_cv_afs_where=$with_afs
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
                        
          AC_CHECK_HEADER(afs/stds.h)
	  AFS_CLIENT_LIBS="-lvolser -lvldb -lkauth -lprot -lubik -lauth -lrxkad -lrx ${AFS_LIB_DIR}/afs/libsys.a -lrx -llwp -ldes -lcmd -lcom_err ${AFS_LIB_DIR}/afs/util.a"
	  AFS_RX_LIBS="-lauth -lrxkad -lrx ${AFS_LIB_DIR}/afs/libsys.a -lrx -llwp -ldes -lcmd -lcom_err ${AFS_LIB_DIR}/afs/util.a"
          AFS_KTC_LIBS="-lauth ${AFS_LIB_DIR}/afs/libsys.a -lrx -llwp -ldes -lcom_err ${AFS_LIB_DIR}/afs/util.a"
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
                AFS_CLIENT_LIBS="$AFS_CLIENT_LIBS $AFS_BSD_LIB"
                AFS_RX_LIBS="$AFS_CLIENT_LIBS $AFS_BSD_LIB"
                AFS_KTC_LIBS="$AFS_KTC_LIBS $AFS_BSD_LIB"
          fi
          LIBS="$cmu_save_LIBS $AFS_CLIENT_LIBS ${LIB_SOCKET}"
          AC_CHECK_FUNC(des_pcbc_init)
          if test "X$ac_cv_func_des_pcbc_init" != "Xyes"; then
           AC_CHECK_LIB(descompat, des_pcbc_init, AFS_DESCOMPAT_LIB="-ldescompat")
           if test "X$AFS_DESCOMPAT_LIB" != "X" ; then
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
          LIBS="$cmu_save_LIBS $AFS_CLIENT_LIBS ${LIB_SOCKET}"
          AC_TRY_LINK([#include <afs/param.h>
#ifdef HAVE_AFS_STDS_H
#include <afs/stds.h>
#endif
#include <afs/cellconfig.h>
#include <afs/auth.h>],
          [afsconf_SuperUser();],AFS_AUDIT_LIB="",AFS_AUDIT_LIB="maybe")
          if test "X$AFS_AUDIT_LIB" != "X"; then
          LIBS="$cmu_save_LIBS -lvolser -lvldb -lkauth -lprot -lubik -lauth -laudit -lrxkad -lrx ${AFS_LIB_DIR}/afs/libsys.a -lrx -llwp -ldes -lcmd -lcom_err ${AFS_LIB_DIR}/afs/util.a $AFS_BSD_LIB $AFS_DESCOMPAT_LIB $LIB_SOCKET"
             AC_TRY_LINK([#include <afs/param.h>
#ifdef HAVE_AFS_STDS_H
#include <afs/stds.h>
#endif
#include <afs/cellconfig.h>
#include <afs/auth.h>],
             [afsconf_SuperUser();],AFS_AUDIT_LIB="yes")
             if test "X$AFS_AUDIT_LIB" = "Xyes"; then
                 AC_MSG_RESULT([yes])
                 AFS_CLIENT_LIBS="-lvolser -lvldb -lkauth -lprot -lubik -lauth -laudit -lrxkad -lrx ${AFS_LIB_DIR}/afs/libsys.a -lrx -llwp -ldes -lcmd -lcom_err ${AFS_LIB_DIR}/afs/util.a $AFS_BSD_LIB $AFS_DESCOMPAT_LIB"
                 AFS_RX_LIBS="-lauth -laudit -lrxkad -lrx ${AFS_LIB_DIR}/afs/libsys.a -lrx -llwp -ldes -lcmd -lcom_err ${AFS_LIB_DIR}/afs/util.a $AFS_BSD_LIB $AFS_DESCOMPAT_LIB"
             else
                 AC_MSG_RESULT([unknown])
                 AC_MSG_ERROR([Could not use -lauth while testing for -laudit])
             fi 
          else
             AC_MSG_RESULT([no])
          fi

          CPPFLAGS="${cmu_save_CPPFLAGS}"
          LDFLAGS="${cmu_save_LDFLAGS}"
          LIBS="${cmu_save_LIBS}"
	  AC_DEFINE(AFS_ENV)
          AC_DEFINE(AFS)
          AC_SUBST(AFS_CLIENT_LIBS)
          AC_SUBST(AFS_RX_LIBS)
          AC_SUBST(AFS_KTC_LIBS)
          AC_SUBST(AFS_INC_FLAGS)
          AC_SUBST(AFS_LIB_FLAGS)
	  AC_SUBST(AFS_TOP_DIR)
       	fi
	])

AC_DEFUN(CMU_NEEDS_AFS,
[AC_REQUIRE([CMU_AFS])
if test "$ac_cv_found_afs" != "yes"; then
        AC_ERROR([Cannot continue without AFS])
fi])

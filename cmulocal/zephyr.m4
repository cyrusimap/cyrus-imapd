dnl zephyr.m4--Zephyr libraries and includes
dnl based on kafs.m4, by
dnl Derrick Brashear
dnl from KTH kafs and Arla
dnl $Id: zephyr.m4,v 1.2 2005/04/26 19:14:08 shadow Exp $

AC_DEFUN([CMU_ZEPHYR_INC_WHERE1], [
saved_CPPFLAGS=$CPPFLAGS
CPPFLAGS="$saved_CPPFLAGS -I$1"
AC_TRY_COMPILE(
[#include <zephyr/zephyr.h>],
[ZNotice_t foo;],
ac_cv_found_zephyr_inc=yes,
ac_cv_found_zephyr_inc=no)
CPPFLAGS=$saved_CPPFLAGS
])

AC_DEFUN([CMU_ZEPHYR_INC_WHERE], [
   for i in $1; do
      AC_MSG_CHECKING(for zephyr headers in $i)
      CMU_ZEPHYR_INC_WHERE1($i)
      CMU_TEST_INCPATH($i, zephyr/zephyr)
      if test "$ac_cv_found_zephyr_inc" = "yes"; then
        ac_cv_zephyr_where_inc=$i
        AC_MSG_RESULT(found)
        break
      else
        AC_MSG_RESULT(not found)
      fi
    done
])

AC_DEFUN([CMU_ZEPHYR_LIB_WHERE1], [
saved_LIBS=$LIBS
LIBS="$saved_LIBS -L$1 -lzephyr $KRB_LIB_FLAGS"
AC_TRY_LINK(,
[ZInitialize();],
[ac_cv_found_zephyr_lib=yes],
ac_cv_found_zephyr_lib=no)
LIBS=$saved_LIBS
])

AC_DEFUN([CMU_ZEPHYR_LIB_WHERE], [
   for i in $1; do
      AC_MSG_CHECKING(for zephyr libraries in $i)
      CMU_ZEPHYR_LIB_WHERE1($i)
      dnl deal with false positives from implicit link paths
      CMU_TEST_LIBPATH($i, zephyr)
      if test "$ac_cv_found_zephyr_lib" = "yes" ; then
        ac_cv_zephyr_where_lib=$i
        AC_MSG_RESULT(found)
        break
      else
        AC_MSG_RESULT(not found)
      fi
    done
])

AC_DEFUN([CMU_ZEPHYR], [
AC_REQUIRE([CMU_FIND_LIB_SUBDIR])
AC_REQUIRE([CMU_SOCKETS])
AC_REQUIRE([CMU_KRB4])
AC_ARG_WITH(zephyr,
        [  --with-zephyr=PREFIX      Compile with Zephyr support],
        [if test "X$with_zephyr" = "X"; then
                with_zephyr=yes
        fi])
AC_ARG_WITH(zephyr-lib,
        [  --with-zephyr-lib=dir     use zephyr libraries in dir],
        [if test "$withval" = "yes" -o "$withval" = "no"; then
                AC_MSG_ERROR([No argument for --with-zephyr-lib])
        fi])
AC_ARG_WITH(zephyr-include,
        [  --with-zephyr-include=dir use zephyr headers in dir],
        [if test "$withval" = "yes" -o "$withval" = "no"; then
                AC_MSG_ERROR([No argument for --with-zephyr-include])
        fi])

        if test "X$with_zephyr" != "X"; then
          if test "$with_zephyr" != "yes" -a "$with_zephyr" != no; then
            ac_cv_zephyr_where_lib=$with_zephyr/$CMU_LIB_SUBDIR
            ac_cv_zephyr_where_inc=$with_zephyr/include
          fi
        fi

        if test "$with_zephyr" != "no"; then 
          if test "X$with_zephyr_lib" != "X"; then
            ac_cv_zephyr_where_lib=$with_zephyr_lib
          fi
          if test "X$ac_cv_zephyr_where_lib" = "X"; then
            CMU_ZEPHYR_LIB_WHERE(/usr/athena/$CMU_LIB_SUBDIR /usr/local/$CMU_LIB_SUBDIR /usr/$CMU_LIB_SUBDIR)
          fi

          if test "X$with_zephyr_include" != "X"; then
            ac_cv_zephyr_where_inc=$with_zephyr_include
          fi
          if test "X$ac_cv_zephyr_where_inc" = "X"; then
            CMU_ZEPHYR_INC_WHERE(/usr/athena/include /usr/local/include /usr/include)
          fi
        fi

        AC_MSG_CHECKING(whether to include zephyr)
        if test "X$ac_cv_zephyr_where_lib" = "X" -a "X$ac_cv_zephyr_where_inc" = "X"; then
          ac_cv_found_zephyr=no
          AC_MSG_RESULT(no)
        else
          ac_cv_found_zephyr=yes
          AC_MSG_RESULT(yes)
          ZEPHYR_INC_DIR=$ac_cv_zephyr_where_inc
          ZEPHYR_LIB_DIR=$ac_cv_zephyr_where_lib
          ZEPHYR_INC_FLAGS="-I${ZEPHYR_INC_DIR}"
          ZEPHYR_LIB_FLAGS="-L${ZEPHYR_LIB_DIR} -lzephyr"
	  AC_SUBST(ZEPHYT_INC_FLAGS)
	  AC_SUBST(ZEPHYR_LIB_FLAGS)
          if test "X$RPATH" = "X"; then
                RPATH=""
          fi
          case "${host}" in
            *-*-linux*)
              if test "X$RPATH" = "X"; then
                RPATH="-Wl,-rpath,${ZEPHYR_LIB_DIR}"
              else 
                RPATH="${RPATH}:${ZEPHYR_LIB_DIR}"
              fi
              ;;
            *-*-hpux*)
              if test "X$RPATH" = "X"; then
                RPATH="-Wl,+b${ZEPHYR_LIB_DIR}"
              else 
                RPATH="${RPATH}:${ZEPHYR_LIB_DIR}"
              fi
              ;;
            *-*-irix*)
              if test "X$RPATH" = "X"; then
                RPATH="-Wl,-rpath,${ZEPHYR_LIB_DIR}"
              else 
                RPATH="${RPATH}:${ZEPHYR_LIB_DIR}"
              fi
              ;;
            *-*-solaris2*)
              if test "$ac_cv_prog_gcc" = yes; then
                if test "X$RPATH" = "X"; then
                  RPATH="-Wl,-R${ZEPHYR_LIB_DIR}"
                else 
                  RPATH="${RPATH}:${ZEPHYR_LIB_DIR}"
                fi
              else
                RPATH="${RPATH} -R${ZEPHYR_LIB_DIR}"
              fi
              ;;
          esac
          AC_SUBST(RPATH)
        fi
        ])


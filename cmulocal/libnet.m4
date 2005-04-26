dnl libnet.m4--libnet and includes
dnl Derrick Brashear
dnl from KTH krb and Arla
dnl $Id: libnet.m4,v 1.8 2005/04/26 19:14:08 shadow Exp $

AC_DEFUN([CMU_LIBNET_CFG_WHERE1], [
ac_cv_found_libnet_bin=no
if test -f "$1/libnet-config" ; then
  ac_cv_found_libnet_cfg=yes
fi
])

AC_DEFUN([CMU_LIBNET_CFG_WHERE], [
   for i in $1; do
      AC_MSG_CHECKING(for libnet config in $i)
      CMU_LIBNET_CFG_WHERE1($i)
      if test "$ac_cv_found_libnet_cfg" = "yes"; then
        ac_cv_libnet_where_cfg=$i
        AC_MSG_RESULT(found)
        break
      else
        AC_MSG_RESULT(not found)
      fi
    done
])

AC_DEFUN([CMU_LIBNET_INC_WHERE1], [
ac_cv_found_libnet_inc=no
if test -f "$1/libnet.h" ; then
  ac_cv_found_libnet_inc=yes
fi
])

AC_DEFUN([CMU_LIBNET_INC_WHERE], [
   for i in $1; do
      AC_MSG_CHECKING(for libnet header in $i)
      CMU_LIBNET_INC_WHERE1($i)
      if test "$ac_cv_found_libnet_inc" = "yes"; then
        ac_cv_libnet_where_inc=$i
        AC_MSG_RESULT(found)
        break
      else
        AC_MSG_RESULT(not found)
      fi
    done
])

AC_DEFUN([CMU_LIBNET_LIB_WHERE1], [
saved_LIBS=$LIBS
LIBS="$saved_LIBS -L$1 -lnet"
AC_TRY_LINK(,
[open_link_interface("","");],
[ac_cv_found_libnet_lib=yes],
AC_TRY_LINK(,
[libnet_open_link_interface("","");],
[
CMU_LIBNET_CFLAGS_ADD="-DNEW_LIBNET_INTERFACE"
ac_cv_found_libnet_lib=yes
],
ac_cv_found_libnet_lib=no)
)
LIBS=$saved_LIBS
])

AC_DEFUN([CMU_LIBNET_LIB_WHERE], [
   for i in $1; do
      AC_MSG_CHECKING(for libnet library in $i)
      CMU_LIBNET_LIB_WHERE1($i)
      CMU_TEST_LIBPATH($i, net)
      if test "$ac_cv_found_libnet_lib" = "yes" ; then
        ac_cv_libnet_where_lib=$i
        AC_MSG_RESULT(found)
        break
      else
        AC_MSG_RESULT(not found)
      fi
    done
])

AC_DEFUN([CMU_LIBNET], [
AC_REQUIRE([CMU_FIND_LIB_SUBDIR])
AC_ARG_WITH(libnet,
	[  --with-libnet=PREFIX      Compile with LIBNET support],
	[if test "X$with_libnet" = "X"; then
		with_libnet=yes
	fi])
AC_ARG_WITH(libnet-config,
	[  --with-libnet-config=dir  use libnet config program in dir],
	[if test "$withval" = "yes" -o "$withval" = "no"; then
		AC_MSG_ERROR([No argument for --with-libnet-config])
	fi])
AC_ARG_WITH(libnet-lib,
	[  --with-libnet-lib=dir     use libnet libraries in dir],
	[if test "$withval" = "yes" -o "$withval" = "no"; then
		AC_MSG_ERROR([No argument for --with-libnet-lib])
	fi])
AC_ARG_WITH(libnet-include,
	[  --with-libnet-include=dir use libnet headers in dir],
	[if test "$withval" = "yes" -o "$withval" = "no"; then
		AC_MSG_ERROR([No argument for --with-libnet-include])
	fi])

	if test "X$with_libnet" != "X"; then
	  if test "$with_libnet" != "yes"; then
            if test -f "$with_libnet/libnet-config"; then
	      ac_cv_libnet_where_cfg=$with_libnet
            else
	      ac_cv_libnet_where_cfg=$with_libnet/bin
            fi
	    ac_cv_libnet_where_lib=$with_libnet/$CMU_LIB_SUBDIR
	    ac_cv_libnet_where_inc=$with_libnet/include
	  fi
	fi

	if test "X$with_libnet_cfg" != "X"; then
	  ac_cv_libnet_where_cfg=$with_libnet_cfg
	fi
	if test "X$ac_cv_libnet_where_cfg" = "X"; then
	  CMU_LIBNET_CFG_WHERE(/usr/ng/bin /usr/bin /usr/local/bin)
	fi

	if test "X$with_libnet_lib" != "X"; then
	  ac_cv_libnet_where_lib=$with_libnet_lib
	fi
	if test "X$ac_cv_libnet_where_lib" = "X"; then
	  CMU_LIBNET_LIB_WHERE(/usr/ng/$CMU_LIB_SUBDIR /usr/$CMU_LIB_SUBDIR /usr/local/$CMU_LIB_SUBDIR)
	fi

	if test "X$with_libnet_include" != "X"; then
	  ac_cv_libnet_where_inc=$with_libnet_include
	fi
	if test "X$ac_cv_libnet_where_inc" = "X"; then
	  CMU_LIBNET_INC_WHERE(/usr/ng/include /usr/include /usr/local/include)
	fi

	AC_MSG_CHECKING(whether to include libnet)
	if test "X$ac_cv_libnet_where_lib" = "X" -o "X$ac_cv_libnet_where_inc" = "X" -o "X$ac_cv_libnet_where_cfg" = "X"; then
	  ac_cv_found_libnet=no
	  AC_MSG_RESULT(no)
	else
	  ac_cv_found_libnet=yes
	  AC_MSG_RESULT(yes)
	  LIBNET_CONFIG=$ac_cv_libnet_where_cfg/libnet-config
	  LIBNET_INC_DIR=$ac_cv_libnet_where_inc
	  LIBNET_LIB_DIR=$ac_cv_libnet_where_lib

	  LIBNET_CFLAGS="`$LIBNET_CONFIG --cflags` ${CMU_LIBNET_CFLAGS_ADD}"
	  LIBNET_DEF_FLAGS="`$LIBNET_CONFIG --defines`"
	  LIBNET_INC_FLAGS="-I${LIBNET_INC_DIR}"
	  LIBNET_LIB_FLAGS="-L${LIBNET_LIB_DIR} `${LIBNET_CONFIG} --libs`"

	  if test "X$RPATH" = "X"; then
		RPATH=""
	  fi
	  case "${host}" in
	    *-*-linux*)
	      if test "X$RPATH" = "X"; then
	        RPATH="-Wl,-rpath,${LIBNET_LIB_DIR}"
	      else 
		RPATH="${RPATH}:${LIBNET_LIB_DIR}"
	      fi
	      ;;
	    *-*-hpux*)
	      if test "X$RPATH" = "X"; then
	        RPATH="-Wl,+b${LIBNET_LIB_DIR}"
	      else 
		RPATH="${RPATH}:${LIBNET_LIB_DIR}"
	      fi
	      ;;
	    *-*-irix*)
	      if test "X$RPATH" = "X"; then
	        RPATH="-Wl,-rpath,${LIBNET_LIB_DIR}"
	      else 
		RPATH="${RPATH}:${LIBNET_LIB_DIR}"
	      fi
	      ;;
	    *-*-solaris2*)
	      if test "$ac_cv_prog_gcc" = yes; then
		if test "X$RPATH" = "X"; then
		  RPATH="-Wl,-R${LIBNET_LIB_DIR}"
		else 
		  RPATH="${RPATH}:${LIBNET_LIB_DIR}"
		fi
	      else
	        RPATH="${RPATH} -R${LIBNET_LIB_DIR}"
	      fi
	      ;;
	  esac
	  AC_SUBST(RPATH)
	fi
	])


dnl libpcap.m4--PCAP libraries and includes
dnl Derrick Brashear
dnl from KTH krb and Arla

AC_DEFUN(CMU_PCAP_INC_WHERE1, [
AC_REQUIRE([AC_PROG_CC_GNU])
saved_CPPFLAGS=$CPPFLAGS
if test "$ac_cv_prog_gcc" = "yes" ; then
  CPPFLAGS="$saved_CPPFLAGS -nostdinc -I$1 -I/usr/include"
else
  CPPFLAGS="$saved_CPPFLAGS -I$1"
fi
AC_TRY_COMPILE([#include <pcap.h>],
[struct pcap_file_header foo;],
ac_cv_found_pcap_inc=yes,
ac_cv_found_pcap_inc=no)
CPPFLAGS=$saved_CPPFLAGS
])

AC_DEFUN(CMU_PCAP_INC_WHERE, [
   for i in $1; do
      AC_MSG_CHECKING(for pcap header in $i)
      CMU_PCAP_INC_WHERE1($i)
      if test "$ac_cv_found_pcap_inc" = "yes"; then
        ac_cv_pcap_where_inc=$i
        AC_MSG_RESULT(found)
        break
      else
        AC_MSG_RESULT(no found)
      fi
    done
])

AC_DEFUN(CMU_PCAP_LIB_WHERE1, [
AC_REQUIRE([AC_PROG_CC_GNU])
saved_LIBS=$LIBS
LIBS="$saved_LIBS -L$1 -lpcap"
AC_TRY_LINK(,
[pcap_lookupdev("");],
[ac_cv_found_pcap_lib=yes],
ac_cv_found_pcap_lib=no)
LIBS=$saved_LIBS
])

AC_DEFUN(CMU_PCAP_LIB_WHERE, [
   for i in $1; do
      AC_MSG_CHECKING(for pcap library in $i)
      CMU_PCAP_LIB_WHERE1($i)
      if test "$ac_cv_found_pcap_lib" = "yes" ; then
        ac_cv_pcap_where_lib=$i
        AC_MSG_RESULT(found)
        break
      else
        AC_MSG_RESULT(no found)
      fi
    done
])

AC_DEFUN(CMU_PCAP, [
AC_ARG_WITH(pcap,
	[  --with-pcap=PREFIX      Compile with PCAP support],
	[if test "X$with_pcap" = "X"; then
		with_pcap=yes
	fi])
AC_ARG_WITH(pcap-lib,
	[  --with-pcap-lib=dir     use pcap libraries in dir],
	[if test "$withval" = "yes" -o "$withval" = "no"; then
		AC_MSG_ERROR([No argument for --with-pcap-lib])
	fi])
AC_ARG_WITH(pcap-include,
	[  --with-pcap-include=dir use pcap headers in dir],
	[if test "$withval" = "yes" -o "$withval" = "no"; then
		AC_MSG_ERROR([No argument for --with-pcap-include])
	fi])

	if test "X$with_pcap" != "X"; then
	  if test "$with_pcap" != "yes"; then
	    ac_cv_pcap_where_lib=$with_pcap/lib
	    ac_cv_pcap_where_inc=$with_pcap/include
	  fi
	fi

	if test "X$with_pcap_lib" != "X"; then
	  ac_cv_pcap_where_lib=$with_pcap_lib
	fi
	if test "X$ac_cv_pcap_where_lib" = "X"; then
	  CMU_PCAP_LIB_WHERE(/usr/ng/lib /usr/lib /usr/local/lib)
	fi

	if test "X$with_pcap_include" != "X"; then
	  ac_cv_pcap_where_inc=$with_pcap_include
	fi
	if test "X$ac_cv_pcap_where_inc" = "X"; then
	  CMU_PCAP_INC_WHERE(/usr/ng/include /usr/include /usr/local/include)
	fi

	AC_MSG_CHECKING(whether to include pcap)
	if test "X$ac_cv_pcap_where_lib" = "X" -a "X$ac_cv_pcap_where_inc" = "X"; then
	  ac_cv_found_pcap=no
	  AC_MSG_RESULT(no)
	else
	  ac_cv_found_pcap=yes
	  AC_MSG_RESULT(yes)
	  PCAP_INC_DIR=$ac_cv_pcap_where_inc
	  PCAP_LIB_DIR=$ac_cv_pcap_where_lib
	  PCAP_INC_FLAGS="-I${PCAP_INC_DIR}"
	  PCAP_LIB_FLAGS="-L${PCAP_LIB_DIR} -lpcap -ldes"
	  if test "X$RPATH" = "X"; then
		RPATH=""
	  fi
	  case "${host}" in
	    *-*-linux*)
	      if test "X$RPATH" = "X"; then
	        RPATH="-Wl,-rpath,/usr/local/lib"
	      else 
		RPATH="${RPATH}:/usr/local/lib"
	      fi
	      ;;
	    *-*-hpux*)
	      if test "X$RPATH" = "X"; then
	        RPATH="-Wl,+b/usr/local/lib"
	      else 
		RPATH="${RPATH}:/usr/local/lib"
	      fi
	      ;;
	    *-*-irix*)
	      if test "X$RPATH" = "X"; then
	        RPATH="-Wl,-rpath,/usr/local/lib"
	      else 
		RPATH="${RPATH}:/usr/local/lib"
	      fi
	      ;;
	    *-*-solaris2*)
	      if test "$ac_cv_prog_gcc" = yes; then
		if test "X$RPATH" = "X"; then
		  RPATH="-Wl,-R/usr/local/lib"
		else 
		  RPATH="${RPATH}:/usr/local/lib"
		fi
	      else
	        RPATH="${RPATH} -R/usr/local/lib"
	      fi
	      ;;
	  esac
	  AC_SUBST(RPATH)
	fi
	])


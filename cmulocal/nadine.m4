dnl nadine.m4--The nadine event library
dnl Derrick Brashear
dnl from KTH kafs and Arla

AC_DEFUN(CMU_NADINE_INC_WHERE1, [
AC_REQUIRE([AC_PROG_CC_GNU])
saved_CPPFLAGS=$CPPFLAGS
CPPFLAGS="$saved_CPPFLAGS -I$1"
CMU_CHECK_HEADER_NOCACHE(libevent/libevent.h,
ac_cv_found_event_inc=yes,
ac_cv_found_event_inc=no)
CPPFLAGS=$saved_CPPFLAGS
])

AC_DEFUN(CMU_NADINE_INC_WHERE, [
   for i in $1; do
      AC_MSG_CHECKING(for nadine headers in $i)
      CMU_NADINE_INC_WHERE1($i)
dnl      CMU_TEST_INCPATH($i, ssl)
dnl   CMU_TEST_INCPATH isn't very versatile
      if test "$ac_cv_found_event_inc" = "yes"; then
        if test \! -f $i/libevent/libevent.h ; then
          ac_cv_found_event_inc=no
        fi
      fi
      if test "$ac_cv_found_event_inc" = "yes"; then
        ac_cv_event_where_inc=$i
        AC_MSG_RESULT(found)
        break
      else
        AC_MSG_RESULT(not found)
      fi
    done
])

AC_DEFUN(CMU_NADINE_LIB_WHERE1, [
AC_REQUIRE([AC_PROG_CC_GNU])
saved_LIBS=$LIBS
LIBS="$saved_LIBS -L$1 -levent"
AC_TRY_LINK(,
[libevent_Initialize();],
[ac_cv_found_event_lib=yes],
ac_cv_found_event_lib=no)
LIBS=$saved_LIBS
])

AC_DEFUN(CMU_NADINE_LIB_WHERE, [
   for i in $1; do
      AC_MSG_CHECKING(for event libraries in $i)
      CMU_NADINE_LIB_WHERE1($i)
      dnl deal with false positives from implicit link paths
      CMU_TEST_LIBPATH($i, event)
      if test "$ac_cv_found_event_lib" = "yes" ; then
        ac_cv_event_where_lib=$i
        AC_MSG_RESULT(found)
        break
      else
        AC_MSG_RESULT(not found)
      fi
    done
])

AC_DEFUN(CMU_NADINE, [
AC_REQUIRE([CMU_SOCKETS])
AC_ARG_WITH(nadine,
	[  --with-nadine=PREFIX      Compile with nadine libevent support],
	[if test "X$with_nadine" = "X"; then
		with_nadine=yes
	fi])
AC_ARG_WITH(nadine-lib,
	[  --with-nadine-lib=dir     use nadine libraries in dir],
	[if test "$withval" = "yes" -o "$withval" = "no"; then
		AC_MSG_ERROR([No argument for --with-nadine-lib])
	fi])
AC_ARG_WITH(nadine-include,
	[  --with-nadine-include=dir use nadine headers in dir],
	[if test "$withval" = "yes" -o "$withval" = "no"; then
		AC_MSG_ERROR([No argument for --with-nadine-include])
	fi])

        if test "$with_ucdsnmp" = "no" ; then
             AC_MSG_WARN([Nadine requires UCD SNMP. Disabling Nadine support])
             with_nadine=no
             with_nadine_lib=no
             with_nadine_include=no
        fi
	if test "X$with_nadine" != "X"; then
	  if test "$with_nadine" != "yes" -a "$with_nadine" != no; then
	    ac_cv_event_where_lib=$with_nadine/lib
	    ac_cv_event_where_inc=$with_nadine/include
	  fi
	fi

	if test "$with_nadine" != "no"; then 
	  if test "X$with_nadine_lib" != "X"; then
	    ac_cv_event_where_lib=$with_nadine_lib
	  fi
	  if test "X$ac_cv_event_where_lib" = "X"; then
	    CMU_NADINE_LIB_WHERE(/usr/local/lib /usr/ng/lib /usr/lib)
	  fi

	  if test "X$with_nadine_include" != "X"; then
	    ac_cv_event_where_inc=$with_nadine_include
	  fi
	  if test "X$ac_cv_event_where_inc" = "X"; then
	    CMU_NADINE_INC_WHERE(/usr/local/include /usr/ng/include /usr/include)
	  fi
	fi

	AC_MSG_CHECKING(whether to include nadine)
	if test "X$ac_cv_event_where_lib" = "X" -a "X$ac_cv_event_where_inc" = "X"; then
	  ac_cv_found_event=no
	  AC_MSG_RESULT(no)
	else
	  ac_cv_found_event=yes
	  AC_MSG_RESULT(yes)
	  NADINE_INC_DIR=$ac_cv_event_where_inc
	  NADINE_LIB_DIR=$ac_cv_event_where_lib
	  NADINE_INC_FLAGS="-I${NADINE_INC_DIR}"
	  NADINE_LIB_FLAGS="-L${NADINE_LIB_DIR} -levent"
	  if test "X$RPATH" = "X"; then
		RPATH=""
	  fi
	  case "${host}" in
	    *-*-linux*)
	      if test "X$RPATH" = "X"; then
	        RPATH="-Wl,-rpath,${NADINE_LIB_DIR}"
	      else 
 		RPATH="${RPATH}:${NADINE_LIB_DIR}"
	      fi
	      ;;
	    *-*-hpux*)
	      if test "X$RPATH" = "X"; then
	        RPATH="-Wl,+b${NADINE_LIB_DIR}"
	      else 
		RPATH="${RPATH}:${NADINE_LIB_DIR}"
	      fi
	      ;;
	    *-*-irix*)
	      if test "X$RPATH" = "X"; then
	        RPATH="-Wl,-rpath,${NADINE_LIB_DIR}"
	      else 
		RPATH="${RPATH}:${NADINE_LIB_DIR}"
	      fi
	      ;;
	    *-*-solaris2*)
	      if test "$ac_cv_prog_gcc" = yes; then
		if test "X$RPATH" = "X"; then
		  RPATH="-Wl,-R${NADINE_LIB_DIR}"
		else 
		  RPATH="${RPATH}:${NADINE_LIB_DIR}"
		fi
	      else
	        RPATH="${RPATH} -R${NADINE_LIB_DIR}"
	      fi
	      ;;
	  esac
	  AC_SUBST(RPATH)
	fi
	AC_SUBST(NADINE_INC_DIR)
	AC_SUBST(NADINE_LIB_DIR)
	AC_SUBST(NADINE_INC_FLAGS)
	AC_SUBST(NADINE_LIB_FLAGS)
	])


dnl
dnl

AC_DEFUN(ANDREW_ADD_LIBPATH, [
  # this is ANDREW ADD LIBPATH
  if test "$andrew_runpath" = "none" ; then
	LDFLAGS="-L$1 ${LDFLAGS}"
  else
	LDFLAGS="-L$1 ${LDFLAGS} $andrew_runpath_switch$1"
  fi
])

AC_DEFUN(ANDREW_ADD_LIBPATH_TO, [
  # this is ANDREW ADD LIBPATH TO
  if test "$andrew_runpath" = "none" ; then
	$2="-L$1 ${$2}"
  else
	$2="-L$1 ${$2} $andrew_runpath_switch$1"
  fi
])

dnl runpath initialization
AC_DEFUN(ANDREW_GUESS_RUNPATH_SWITCH, [
AC_MSG_CHECKING(for runpath switch)
AC_CACHE_VAL(andrew_runpath_switch, [
# first, try and see if -R works
  SAVE_LDFLAGS="${LDFLAGS}"
  LDFLAGS="-R /usr/lib"
  AC_TRY_LINK([],[],[andrew_runpath_switch="-R"], [
    LDFLAGS="-Wl,-rpath,/usr/lib"
    AC_TRY_LINK([],[],[andrew_runpath_switch="-Wl,-rpath,"],
		[andrew_runpath_switch="none"])
    ])
  LDFLAGS="${SAVE_LDFLAGS}"
])
AC_MSG_RESULT($andrew_runpath_switch)
])

dnl FIRST PASS AFTER STEALING THIS FROM CYRUS!
dnl USE AT YOUR OWN PERIL!
dnl I MEAN IT!
dnl
dnl tcl.m4: an autoconf Tcl locator
dnl $Id: tcl.m4,v 1.3 2002/05/25 19:57:42 leg Exp $
dnl
dnl This is rob's Tcl macro, fixed by tjs.  It may need occasional tweaking,
dnl but until the next impediment to compilation, it's fill-in-the-blank,
dnl and it should be able to do reasonable things with user input.
dnl
dnl This will probably just work on Andrew systems, but given the variety
dnl and apparent creativity of people who compile Tcl elsewhere, I don't know
dnl what it will do.  I have yet to see an autoconf Tcl test that users were
dnl happy with.
dnl
dnl BUGS
dnl   The command-line arguments are overcomplicated.
dnl   There are doubtlessly others...

dnl To use this macro, just do CMU_TCL.  It outputs
dnl TCL_LIBS, TCL_CPPFLAGS, and TCL_DEFS and SUBSTs them.  
dnl If successful, these have stuff in them.  If not, they're empty.
dnl If not successful, with_tcl has the value "no".

AC_DEFUN(CMU_TCL, [
# --- BEGIN CMU_TCL ---
dnl To link against Tcl, configure does several things to make my life
dnl "easier".
dnl
dnl * maybe ask the user where they think Tcl lives, and try to find it
dnl * maybe ask the user what "tclsh" is called this week (i.e., "tclsh8.0")
dnl * run tclsh, ask it for a path, then run that path through sed
dnl * sanity check its result (many installs are a little broken)
dnl * try to figure out where Tcl is based on this result
dnl * try to guess where the Tcl include files are
dnl
dnl Notes from previous incarnations:
dnl > XXX MUST CHECK FOR TCL BEFORE KERBEROS V4 XXX
dnl > This is because some genius at MIT named one of the Kerberos v4
dnl > library functions log().  This of course conflicts with the
dnl > logarithm function in the standard math library, used by Tcl.
dnl
dnl > Checking for Tcl first puts -lm before -lkrb on the library list.
dnl

dnl Check for some information from the user on what the world looks like
AC_ARG_WITH(tclconfig,[  --with-tclconfig=PATH   use tclConfig.sh from PATH
                          (configure gets Tcl configuration from here)],
        dnl trim tclConfig.sh off the end so we can add it back on later.
	TclLibBase=`echo ${withval} | sed s/tclConfig.sh\$//`)
AC_ARG_WITH(tcl,      [  --with-tcl=PATH         use Tcl from PATH],
	TclLibBase="${withval}/lib")
AC_ARG_WITH(tclsh,    [  --with-tclsh=TCLSH      use TCLSH as the tclsh program
                          (let configure find Tcl using this program)],
	TCLSH="${withval}")

if test "$TCLSH" = "no" -o "$with_tclconfig" = "no" ; then
  AC_MSG_WARN([Tcl disabled because tclsh or tclconfig specified as "no"])
  with_tcl=no
fi

if test "$with_tcl" != "no"; then
  if test \! -z "$with_tclconfig" -a \! -d "$with_tclconfig" ; then
    AC_MSG_ERROR([--with-tclconfig requires a directory argument.])
  fi

  if test \! -z "$TCLSH" -a \! -x "$TCLSH" ; then
    AC_MSG_ERROR([--with-tclsh must specify an executable file.])
  fi

  if test -z "$TclLibBase"; then # do we already know?
    # No? Run tclsh and ask it where it lives.

    # Do we know where a tclsh lives?
    if test -z "$TCLSH"; then
      # Try and find tclsh.  Any tclsh.
      # If a new version of tcl comes out and unfortunately adds another
      # filename, it should be safe to add it (to the front of the line --
      # somef vendors have older, badly installed tclshs that we want to avoid
      # if we can)
      AC_PATH_PROGS(TCLSH, [tclsh8.1 tclsh8.0 tclsh], "unknown")
    fi

    # Do we know where to get a tclsh?
    if test "${TCLSH}" != "unknown"; then
      AC_MSG_CHECKING([where Tcl says it lives])
      TclLibBase=`echo puts \\\$tcl_library | ${TCLSH} | sed -e 's,[^/]*$,,'`
      AC_MSG_RESULT($TclLibBase)
    fi
  fi

  if test -z "$TclLibBase" ; then
    AC_MSG_RESULT([can't find tclsh])
    AC_MSG_WARN([can't find Tcl installtion; use of Tcl disabled.])
    with_tcl=no
  else
    AC_MSG_CHECKING([for tclConfig.sh])
    # Check a list of places where the tclConfig.sh file might be.
    for tcldir in "${TclLibBase}" \
                  "${TclLibBase}/.." \
		  "${TclLibBase}"`echo ${TCLSH} | sed s/sh//` ; do
      if test -f "${tcldir}/tclConfig.sh"; then
        TclLibBase="${tcldir}"
        break
      fi
    done

    if test -z "${TclLibBase}" ; then
      AC_MSG_RESULT("unknown")
      AC_MSG_WARN([can't find Tcl configuration; use of Tcl disabled.])
      with_tcl=no
    else
      AC_MSG_RESULT(${TclLibBase}/)
    fi

    if test "${with_tcl}" != no ; then
      AC_MSG_CHECKING([Tcl configuration on what Tcl needs to compile])
      . ${TclLibBase}/tclConfig.sh
      AC_MSG_RESULT(ok)
      dnl no TK stuff for us.
      dnl . ${TclLibBase}/tkConfig.sh
    fi

    if test "${with_tcl}" != no ; then
      dnl Now, hunt for the Tcl include files, since we don't strictly
      dnl know where they are; some folks put them (properly) in the 
      dnl default include path, or maybe in /usr/local; the *BSD folks
      dnl put them in other places.
      AC_MSG_CHECKING([where Tcl includes are])
      for tclinclude in "${TCL_PREFIX}/include/tcl${TCL_VERSION}" \
                        "${TCL_PREFIX}/include/tcl" \
                        "${TCL_PREFIX}/include" ; do
        if test -r "${tclinclude}/tcl.h" ; then
          TCL_CPPFLAGS="-I${tclinclude}"
          break
        fi
      done
      if test -z "${TCL_CPPFLAGS}" ; then
        AC_MSG_WARN(can't find Tcl includes; use of Tcl disabled.)
        with_tcl=no
      fi
      AC_MSG_RESULT(${TCL_CPPFLAGS})
    fi
    
    # Finally, pick up the Tcl configuration if we haven't found an
    # excuse not to.
    if test "${with_tcl}" != no; then
      dnl TCL_LIBS="${TK_LIB_SPEC} ${TK_XLIBSW} ${TCL_LD_SEARCH_FLAGS} ${TCL_LIB_SPEC}"
      TCL_LIBS="${TCL_LD_SEARCH_FLAGS} ${TCL_LIB_SPEC} ${TCL_LIBS}"
    fi
  fi
fi

AC_SUBST(TCL_DEFS)
AC_SUBST(TCL_LIBS)
AC_SUBST(TCL_CPPFLAGS)

# --- END CMU_TCL ---
]) dnl CMU_TCL

dnl agentx.m4--detect agentx libraries
dnl copied from x-unixrc
dnl Tim Martin
dnl $Id: agentx.m4,v 1.4 2002/05/25 19:57:41 leg Exp $

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

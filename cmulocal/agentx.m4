dnl agentx.m4--detect agentx libraries
dnl copied from x-unixrc
dnl Tim Martin

AC_DEFUN(CMU_AGENTX, [

	dnl
	dnl CMU AgentX
	dnl
	AC_MSG_CHECKING([for AgentX])
	AC_ARG_WITH(agentx, [  --with-agentx              CMU AgentX libraries located in (val)], AGENTX_DIR="$withval", AGENTX_DIR=no)

	if test "${AGENTX_DIR}" != "no" &&
	   test -f $AGENTX_DIR/lib${ABILIBDIR}/libagentx.a &&
	   test -f $AGENTX_DIR/include/agentx.h; then
	     AGENTX_DIR="$AGENTX_DIR"
	elif test -d /usr/local &&
	   test -f /usr/local/lib${ABILIBDIR}/libagentx.a &&
	   test -f /usr/local/include/agentx.h; then
	     AGENTX_DIR="/usr/local"

	elif test -d /usr/ng &&
	   test -f /usr/ng/lib${ABILIBDIR}/libagentx.a &&
	   test -f /usr/ng/include/agentx.h; then
	     AGENTX_DIR="/usr/ng"

	else
	  AC_MSG_WARN([Could not locate AgentX Libraries! http://www.net.cmu.edu/groups/netdev/agentx/])
	fi

	LIB_AGENTX="-L$AGENTX_DIR/lib${ABILIBDIR} -lagentx"
	AC_SUBST(LIB_AGENTX)
	AGENTXFLAGS="-I$AGENTX_DIR/include"
        AC_SUBST(AGENTXFLAGS)   
	AC_MSG_RESULT([found $AGENTX_DIR/lib${ABILIBDIR}/libagentx.a])

])
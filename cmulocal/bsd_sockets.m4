dnl bsd_sockets.m4--which socket libraries do we need? 
dnl Derrick Brashear
dnl from Zephyr
dnl $Id: bsd_sockets.m4,v 1.1 1998/10/05 16:02:16 shadow Exp $

AC_DEFUN(CMU_SOCKETS, [
	AC_MSG_CHECKING(finding socket libraries)
	AC_FUNC_CHECK(connect, :, [AC_CHECK_LIB(socket, socket)
		AC_CHECK_LIB(nsl, gethostbyname)])
	])

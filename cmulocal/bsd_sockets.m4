dnl bsd_sockets.m4--which socket libraries do we need? 
dnl Derrick Brashear
dnl from Zephyr
dnl $Id: bsd_sockets.m4,v 1.2 1998/10/08 22:01:32 rob Exp $

AC_DEFUN(CMU_SOCKETS, [
	AC_FUNC_CHECK(connect, :, [AC_CHECK_LIB(socket, socket)
		AC_CHECK_LIB(nsl, gethostbyname)])
	])

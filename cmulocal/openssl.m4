dnl
dnl macros for configure.in to detect openssl
dnl $Id: openssl.m4,v 1.6.2.1 2003/02/14 16:14:51 ken3 Exp $
dnl

AC_DEFUN(CMU_HAVE_OPENSSL, [
AC_ARG_WITH(openssl,[  --with-openssl=PATH     use OpenSSL from PATH],
	with_openssl=$withval, with_openssl="yes")

	save_CPPFLAGS=$CPPFLAGS
	save_LDFLAGS=$LDFLAGS

	if test -d $with_openssl; then
	  CPPFLAGS="${CPPFLAGS} -I${with_openssl}/include"
	  LDFLAGS="${LDFLAGS} -L${with_openssl}/lib"
	fi

case "$with_openssl" in
	no)
	  with_openssl="no";;
	*) 
	  dnl if openssl has been compiled with the rsaref2 libraries,
	  dnl we need to include the rsaref libraries in the crypto check
                LIB_RSAREF=""
	        AC_CHECK_LIB(rsaref, RSAPublicEncrypt,
		       LIB_RSAREF="-lRSAglue -lrsaref"; cmu_have_rsaref=yes,
		       cmu_have_rsaref=no)

		AC_CHECK_HEADER(openssl/evp.h, [
			AC_CHECK_LIB(crypto, EVP_DigestInit,
					with_openssl="yes",
					with_openssl="no", $LIB_RSAREF)],
			with_openssl=no)
		;;
esac

	if test "$with_openssl" != "no"; then
		AC_DEFINE(HAVE_OPENSSL)
	else
		CPPFLAGS=$save_CPPFLAGS
		LDFLAGS=$save_LDFLAGS
	fi
])
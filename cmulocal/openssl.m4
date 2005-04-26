dnl
dnl macros for configure.in to detect openssl
dnl $Id: openssl.m4,v 1.10 2005/04/26 19:14:08 shadow Exp $
dnl

AC_DEFUN([CMU_HAVE_OPENSSL], [
AC_REQUIRE([CMU_FIND_LIB_SUBDIR])
AC_ARG_WITH(openssl,[  --with-openssl=PATH     use OpenSSL from PATH],
	with_openssl=$withval, with_openssl="yes")

	save_CPPFLAGS=$CPPFLAGS
	save_LDFLAGS=$LDFLAGS

	if test -d $with_openssl; then
	  CPPFLAGS="${CPPFLAGS} -I${with_openssl}/include"
	  CMU_ADD_LIBPATH(${with_openssl}/$CMU_LIB_SUBDIR)
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
		AC_DEFINE(HAVE_OPENSSL,[],[Do we have OpenSSL?])
	else
		CPPFLAGS=$save_CPPFLAGS
		LDFLAGS=$save_LDFLAGS
	fi
])

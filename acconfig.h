/* $Id: acconfig.h,v 1.3 2000/04/06 18:31:21 leg Exp $ */

@TOP@

/* where are we going to be installed? */
#define CYRUS_PATH "/usr/cyrus"

/* what user are we going to run as? */
#define CYRUS_USER "cyrus"

/* do we have strerror()? */
#undef HAS_STRERROR

/* do we have kerberos? */
#undef HAVE_KRB

/* do we already have sys_errlist? */
#undef NEED_SYS_ERRLIST

/* how should we setproctitle? */
#undef SPT_TYPE

/* do we have the AFS symbol pr_End? */
#undef HAVE_PR_END

/* do we have an acceptable regex library? */
#undef ENABLE_REGEX

/* do we support XNETSCAPE */
#undef ENABLE_X_NETSCAPE_HACK

/* we better have berkeley db 3.x */
#undef HAVE_LIBDB

/* the AFS RX (RPC) package */
#undef HAVE_RX

/* do we have OpenSSL? */
#undef HAVE_SSL

/* where should we put state information? */
#undef STATEDIR

/* is Sieve enabled? */
#undef USE_SIEVE

/* _POSIX_PTHREAD_SEMANTICS needed? */
#undef _POSIX_PTHREAD_SEMANTICS

/* _REENTRANT needed? */
#undef _REENTRANT

/* _SGI_REENTRANT_FUNCTIONS needed? */
#undef _SGI_REENTRANT_FUNCTIONS

/* This seems to be required to make Solaris happy. */
#undef __EXTENSIONS__

@BOTTOM@

#ifndef __GNUC__
#define __attribute__(foo)
#endif

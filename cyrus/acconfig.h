/* $Id: acconfig.h,v 1.1 2000/02/10 21:25:22 leg Exp $ */

@TOP@

/* where are we going to be installed? */
#define CYRUS_PATH "/usr/cyrus"

/* what user are we going to run as? */
#define CYRUS_USER "cyrus"

/* should we enable experimental features? */
#undef ENABLE_EXPERIMENT

/* should we support the NETSCAPE command? */
#undef ENABLE_X_NETSCAPE_HACK

/* do we have strerror()? */
#undef HAS_STRERROR

/* do we have kerberos? */
#undef HAVE_KRB

/* we better have berkeley db 3.x */
#undef HAVE_LIBDB

/* do we have OpenSSL? */
#undef HAVE_SSL

/* do we already have sys_errlist? */
#undef NEED_SYS_ERRLIST

/* how should we setproctitle? */
#undef SPT_TYPE

/* where should we look for pts database? */
#undef STATEDIR

/* should we support Sieve, the mail filtering language? */
#undef USE_SIEVE

/* do we have the AFS symbol pr_End? */
#undef HAVE_PR_END

@BOTTOM@

#ifndef __GNUC__
#define __attribute__(foo)
#endif

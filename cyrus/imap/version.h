/* version.h: the version number
 *
 * $Id: version.h,v 1.79 2000/01/04 19:42:23 leg Exp $
 */

#define _CYRUS_VERSION "v1.6.22"

/* EXTRA_IDENT is a hack to add some version information for which compile
 * was used to build this version (at CMU, but we don't care what you do with
 * it).
 */

#ifdef EXTRA_IDENT
#define CYRUS_VERSION _CYRUS_VERSION "-" EXTRA_IDENT
#else
#define CYRUS_VERSION _CYRUS_VERSION
#endif

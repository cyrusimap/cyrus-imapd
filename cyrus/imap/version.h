/* version.h: the version number
 *
 * $Id: version.h,v 1.79.2.1 2000/05/16 14:50:43 ken3 Exp $
 */

#define _CYRUS_VERSION "v1.6.23-BETA"

/* EXTRA_IDENT is a hack to add some version information for which compile
 * was used to build this version (at CMU, but we don't care what you do with
 * it).
 */

#ifdef EXTRA_IDENT
#define CYRUS_VERSION _CYRUS_VERSION "-" EXTRA_IDENT
#else
#define CYRUS_VERSION _CYRUS_VERSION
#endif

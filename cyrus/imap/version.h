/* version.h: the version number
 *
 * $Id: version.h,v 1.84 2000/04/11 03:37:30 leg Exp $
 */

#define _CYRUS_VERSION "v2.0.0"

/* EXTRA_IDENT is a hack to add some version information for which compile
 * was used to build this version (at CMU, but we don't care what you do with
 * it).
 */

#ifdef EXTRA_IDENT
#define CYRUS_VERSION _CYRUS_VERSION "-" EXTRA_IDENT
#else
#define CYRUS_VERSION _CYRUS_VERSION
#endif

/* CAPABILITIES are now defined here, not including sasl ones */
#define CAPABILITY_STRING "IMAP4 IMAP4rev1 ACL QUOTA LITERAL+ NAMESPACE " \
	"UIDPLUS NO_ATOMIC_RENAME UNSELECT MULTIAPPEND"

/* version.h: the version number
 *
 * $Id: version.h,v 1.81 2000/01/28 22:09:52 leg Exp $
 */

#define _CYRUS_VERSION "v1.6.23-DB"

/* EXTRA_IDENT is a hack to add some version information for which compile
 * was used to build this version (at CMU, but we don't care what you do with
 * it).
 */

#ifdef EXTRA_IDENT
#define CYRUS_VERSION _CYRUS_VERSION "-" EXTRA_IDENT
#else
#define CYRUS_VERSION _CYRUS_VERSION
#endif

/* CAPABILITIES are now defined here, no including sasl ones */
#define CAPABILITY_STRING "IMAP4 IMAP4rev1 ACL QUOTA LITERAL+ NAMESPACE " \
	"UIDPLUS X-NON-HIERARCHICAL-RENAME NO_ATOMIC_RENAME UNSELECT"

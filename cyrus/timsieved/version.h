/* version.h: the version number
 *
 * $Id: version.h,v 1.2 2000/01/28 22:09:57 leg Exp $
 */

#define _SIEVED_VERSION "v1.0.0"

#ifdef EXTRA_IDENT
#define SIEVED_VERSION _SIEVED_VERSION "-" EXTRA_IDENT
#else
#define SIEVED_VERSION _SIEVED_VERSION
#endif

#define SIEVED_IDENT "Cyrus timsieved"

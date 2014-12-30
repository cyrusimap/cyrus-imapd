/*
 * variables.c
 *
 *  Created on: Dec 26, 2014
 *      Author: James Cassell
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "variables.h"
#include "bytecode.h"
#include "xmalloc.h"

#include <string.h>

EXPORTED char *variables_modify_string (const char *string, int modifiers) {
    int len;
    char * result;
    len = strlen(string);
    /* Consider the string '\\\'
     * length will be doubled with :quotewildcard
     * length will then be tripled with :encodeurl
     * so we allocate a buffer to encode the worst
     * case final string of 2 * 3 = 6 times the length
     * of the original string
     */
    result = xzmalloc(2 * 3 * len + 1);

    /*
     * +--------------------------------+
     * | Precedence     Modifier        |
     * +--------------------------------+
     * |     40         :lower          |
     * |                :upper          |
     * +--------------------------------+
     * |     30         :lowerfirst     |
     * |                :upperfirst     |
     * +--------------------------------+
     * |     20         :quotewildcard  |
     * +--------------------------------+
     * |     15         :encodeurl      |
     * +--------------------------------+
     * |     10         :length         |
     * +--------------------------------+
     */
    /* Precedence 40 */
    switch ((BFV_LOWER | BFV_UPPER) & modifiers) {
    case BFV_LOWER:

	break;
    case BFV_UPPER:

	break;
    }
    /* Precedence 30 */
    switch ((BFV_LOWERFIRST | BFV_UPPERFIRST) & modifiers) {
    case BFV_LOWERFIRST:

	break;
    case BFV_UPPERFIRST:

	break;
    }
    /* Precedence 20 */
    if (BFV_QUOTEWILDCARD & modifiers) {

    }
    /*
     *
     * 2.1. Percent-Encoding

   A percent-encoding mechanism is used to represent a data octet in a
   component when that octet's corresponding character is outside the
   allowed set or is being used as a delimiter of, or within, the
   component.  A percent-encoded octet is encoded as a character
   triplet, consisting of the percent character "%" followed by the two
   hexadecimal digits representing that octet's numeric value.  For
   example, "%20" is the percent-encoding for the binary octet
   "00100000" (ABNF: %x20), which in US-ASCII corresponds to the space
   character (SP).  Section 2.4 describes when percent-encoding and
   decoding is applied.

      pct-encoded = "%" HEXDIG HEXDIG

   The uppercase hexadecimal digits 'A' through 'F' are equivalent to
   the lowercase digits 'a' through 'f', respectively.  If two URIs
   differ only in the case of hexadecimal digits used in percent-encoded
   octets, they are equivalent.  For consistency, URI producers and
   normalizers should use uppercase hexadecimal digits for all percent-
   encodings.
     *
     * 2.3. Unreserved Characters

   Characters that are allowed in a URI but do not have a reserved
   purpose are called unreserved.  These include uppercase and lowercase
   letters, decimal digits, hyphen, period, underscore, and tilde.

      unreserved  = ALPHA / DIGIT / "-" / "." / "_" / "~"

   URIs that differ in the replacement of an unreserved character with
   its corresponding percent-encoded US-ASCII octet are equivalent: they
   identify the same resource.  However, URI comparison implementations
   do not always perform normalization prior to comparison (see Section
   6).  For consistency, percent-encoded octets in the ranges of ALPHA
   (%41-%5A and %61-%7A), DIGIT (%30-%39), hyphen (%2D), period (%2E),
   underscore (%5F), or tilde (%7E) should not be created by URI
   producers and, when found in a URI, should be decoded to their
   corresponding unreserved characters by URI normalizers.

     */
    /* Precedence 15 */
    if (BFV_ENCODEURL & modifiers) {

    }
    /* Precedence 10 */
    if (BFV_LENGTH & modifiers) {

    }
}

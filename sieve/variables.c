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
#include <ctype.h>

EXPORTED char *variables_modify_string (const char *string, int modifiers) {
    int len, i, j;
    char *result;
    char *working_buffer;
    len = strlen(string);
    if (!len) {
	return (BFV_LENGTH & modifiers) ? xstrdup("0") : xstrdup("");
    }
    /* Consider the string '\\\'
     * length will be doubled with :quotewildcard
     * length will then be tripled with :encodeurl
     * so we allocate a buffer to encode the worst
     * case final string of 2 * 3 = 6 times the length
     * of the original string
     */
    result = xstrdup(string);
    working_buffer = xstrdup(string);
    result = xrealloc(result, 2 * 3 * len + 1);
    working_buffer = xrealloc(working_buffer, 2 * 3 * len + 1);

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
	for (i = 0; i < len; i++) {
	    result[i] = tolower(result[i]);
	}
	break;
    case BFV_UPPER:
	for (i = 0; i < len; i++) {
	    result[i] = tolower(result[i]);
	}
	break;
    }
    /* Precedence 30 */
    switch ((BFV_LOWERFIRST | BFV_UPPERFIRST) & modifiers) {
    case BFV_LOWERFIRST:
	result[0] = tolower(result[0]);
	break;
    case BFV_UPPERFIRST:
	result[0] = toupper(result[0]);
	break;
    }
    /*
     * 4.1.2.  Modifier ":quotewildcard"

   This modifier adds the necessary quoting to ensure that the expanded
   text will only match a literal occurrence if used as a parameter to
   :matches.  Every character with special meaning ("*", "?",  and "\")
   is prefixed with "\" in the expansion.
     *
     */
    /* Precedence 20 */
    if (BFV_QUOTEWILDCARD & modifiers) {
	char *original, *quoted;
	original = result;
	quoted = working_buffer;
	while (*original) {
	    switch (*original) {
	    case '*':
	    case '?':
	    case '\\':
		*quoted = '\\';
		quoted++;
		break;
	    }
	    *quoted = *original;
	    quoted++;
	    original++;
	}
	*quoted = '\0';
	{
	    char *temp;
	    temp = result;
	    result = working_buffer;
	    working_buffer = temp;
	}
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
	char *original, *quoted;
	original = result;
	quoted = working_buffer;

	while (*original) {
	    switch (*original) {
	    case 'a' ... 'z':
	    case 'A' ... 'Z':
	    case '0' ... '9':
		*quoted = *original;
		quoted ++;
		break;
	    default:
		snprintf(quoted, 4, "%%%02X", *original);
		quoted += 3;
		break;
	    }
	    original++;
	}
	*quoted = '\0';
	{
	    char *temp;
	    temp = result;
	    result = working_buffer;
	    working_buffer = temp;
	}
    }
    /* Precedence 10 */
    if (BFV_LENGTH & modifiers) {
	snprintf(working_buffer, strlen(result), "%zu", strlen(result));
	{
	    char *temp;
	    temp = result;
	    result = working_buffer;
	    working_buffer = temp;
	}
    }
    free(working_buffer);
    return result;
}

/*
 * variables.c
 *
 *  Created on: Dec 26, 2014
 *      Author: James Cassell
 *
 *  Rewritten by Ken Murchison 4/7/17 to use 'struct buf'
 */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include "variables.h"
#include "bytecode.h"
#include "util.h"

#include <ctype.h>

#define buf_swap(b1, b2)                                                       \
    {                                                                          \
        struct buf *temp = b1;                                                 \
        b1 = b2;                                                               \
        b2 = temp;                                                             \
    }

EXPORTED char *variables_modify_string(const char *string, int modifiers)
{
    struct buf buf1 = BUF_INITIALIZER, buf2 = BUF_INITIALIZER;
    struct buf *result = &buf1, *working_buffer = &buf2;

    buf_init_ro_cstr(result, string);

    if (!buf_len(result)) {
        if (BFV_LENGTH & modifiers) {
            buf_printf(result, "%zu", (size_t) 0);
        }
        return buf_release(result);
    }

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
     * |                :quoteregex     |
     * +--------------------------------+
     * |     15         :encodeurl      |
     * +--------------------------------+
     * |     10         :length         |
     * +--------------------------------+
     */

    /* Precedence 40 */
    switch ((BFV_LOWER | BFV_UPPER) & modifiers) {
    case BFV_LOWER:
        buf_lcase(result);
        break;

    case BFV_UPPER:
        buf_ucase(result);
        break;
    }

    /* Precedence 30 */
    if ((BFV_LOWERFIRST | BFV_UPPERFIRST) & modifiers) {
        string = buf_cstring(result);

        buf_reset(working_buffer);
        buf_printf(working_buffer,
                   "%c%s",
                   (BFV_LOWERFIRST & modifiers) ? tolower(string[0])
                                                : toupper(string[0]),
                   string + 1);
        buf_swap(result, working_buffer);
    }

    /* Precedence 20 */
    if ((BFV_QUOTEWILDCARD | BFV_QUOTEREGEX) & modifiers) {
        /*
          These modifiers add the necessary quoting to ensure that the expanded
          text will only match a literal occurrence if used as a parameter to
          :matches or :regex respectively.  Every character with special meaning
          ("*", "?", "\", etc) is prefixed with "\" in the expansion.
        */
        buf_reset(working_buffer);

        for (string = buf_cstring(result); *string; string++) {
            switch (*string) {
                /* :regex-ONLY special characters */
            case '.':
            case '^':
            case '$':
            case '+':
            case '(':
            case ')':
            case '[':
            case '{':
            case '|':
                if (!(BFV_QUOTEREGEX & modifiers)) {
                    break;
                }
                GCC_FALLTHROUGH
                /* :matches AND :regex special characters */
            case '*':
            case '?':
            case '\\':
                buf_putc(working_buffer, '\\');
                break;
            }

            buf_putc(working_buffer, *string);
        }

        buf_swap(result, working_buffer);
    }

    /* Precedence 15 */
    if (BFV_ENCODEURL & modifiers) {
        /*
          2.1. Percent-Encoding

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

          2.3. Unreserved Characters

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
        buf_reset(working_buffer);

        for (string = buf_cstring(result); *string; string++) {
            switch (*string) {
            case 'A' ... 'Z':
            case 'a' ... 'z':
            case '0' ... '9':
            case '-':
            case '.':
            case '_':
            case '~':
                buf_putc(working_buffer, *string);
                break;

            default:
                buf_printf(working_buffer, "%%%02X", *string);
                break;
            }
        }

        buf_swap(result, working_buffer);
    }

    /* Precedence 10 */
    if (BFV_LENGTH & modifiers) {
        buf_reset(working_buffer);
        buf_printf(working_buffer, "%zu", buf_len(result));
        buf_swap(result, working_buffer);
    }

    buf_free(working_buffer);

    return buf_release(result);
}

/* ANSI-C code produced by gperf version 3.1 */
/* Command-line: gperf --ignore-case --initializer-suffix=,0 -p -j1 -i 1 -g -o -t -H mailbox_header_cache_hash -N mailbox_header_cache_lookup -k'1,3,$' imap/mailbox_header_cache.gperf  */

#if !(                                                                         \
    (' ' == 32) && ('!' == 33) && ('"' == 34) && ('#' == 35) && ('%' == 37)    \
    && ('&' == 38) && ('\'' == 39) && ('(' == 40) && (')' == 41)               \
    && ('*' == 42) && ('+' == 43) && (',' == 44) && ('-' == 45) && ('.' == 46) \
    && ('/' == 47) && ('0' == 48) && ('1' == 49) && ('2' == 50) && ('3' == 51) \
    && ('4' == 52) && ('5' == 53) && ('6' == 54) && ('7' == 55) && ('8' == 56) \
    && ('9' == 57) && (':' == 58) && (';' == 59) && ('<' == 60) && ('=' == 61) \
    && ('>' == 62) && ('?' == 63) && ('A' == 65) && ('B' == 66) && ('C' == 67) \
    && ('D' == 68) && ('E' == 69) && ('F' == 70) && ('G' == 71) && ('H' == 72) \
    && ('I' == 73) && ('J' == 74) && ('K' == 75) && ('L' == 76) && ('M' == 77) \
    && ('N' == 78) && ('O' == 79) && ('P' == 80) && ('Q' == 81) && ('R' == 82) \
    && ('S' == 83) && ('T' == 84) && ('U' == 85) && ('V' == 86) && ('W' == 87) \
    && ('X' == 88) && ('Y' == 89) && ('Z' == 90) && ('[' == 91)                \
    && ('\\' == 92) && (']' == 93) && ('^' == 94) && ('_' == 95)               \
    && ('a' == 97) && ('b' == 98) && ('c' == 99) && ('d' == 100)               \
    && ('e' == 101) && ('f' == 102) && ('g' == 103) && ('h' == 104)            \
    && ('i' == 105) && ('j' == 106) && ('k' == 107) && ('l' == 108)            \
    && ('m' == 109) && ('n' == 110) && ('o' == 111) && ('p' == 112)            \
    && ('q' == 113) && ('r' == 114) && ('s' == 115) && ('t' == 116)            \
    && ('u' == 117) && ('v' == 118) && ('w' == 119) && ('x' == 120)            \
    && ('y' == 121) && ('z' == 122) && ('{' == 123) && ('|' == 124)            \
    && ('}' == 125) && ('~' == 126))
/* The character set is not based on ISO-646.  */
# error                                                                        \
     "gperf generated tables don't work with this execution character set. Please report a bug to <bug-gperf@gnu.org>."
#endif

#line 1 "imap/mailbox_header_cache.gperf"

/* mailbox_header_cache.h -- Lookup functions for mailbox headers we cache in
                             the cyrus.cache file
 *
 * Copyright (c) 1994-2017 Carnegie Mellon University.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The name "Carnegie Mellon University" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For permission or any legal
 *    details, please contact
 *      Carnegie Mellon University
 *      Center for Technology Transfer and Enterprise Creation
 *      4615 Forbes Avenue
 *      Suite 302
 *      Pittsburgh, PA  15213
 *      (412) 268-7393, fax: (412) 268-7395
 *      innovation@andrew.cmu.edu
 *
 * 4. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by Computing Services
 *     at Carnegie Mellon University (http://www.cmu.edu/computing/)."
 *
 * CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
 * FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
/* Command-line: gperf --ignore-case -p -j1 -i 1 -g -o -t -H mailbox_header_cache_hash -N mailbox_header_cache_lookup -k1,3,$ mailbox_header_cache.gperf */
#include "util.h"
#line 47 "imap/mailbox_header_cache.gperf"
struct mailbox_header_cache
{
    const char *name;
    bit32 min_cache_version;
};

#define TOTAL_KEYWORDS 49
#define MIN_WORD_LENGTH 2
#define MAX_WORD_LENGTH 31
#define MIN_HASH_VALUE 4
#define MAX_HASH_VALUE 65
/* maximum key range = 62, duplicates = 0 */

#ifndef GPERF_DOWNCASE
# define GPERF_DOWNCASE 1
static unsigned char gperf_downcase[256] = {
    0,   1,   2,   3,   4,   5,   6,   7,   8,   9,   10,  11,  12,  13,  14,
    15,  16,  17,  18,  19,  20,  21,  22,  23,  24,  25,  26,  27,  28,  29,
    30,  31,  32,  33,  34,  35,  36,  37,  38,  39,  40,  41,  42,  43,  44,
    45,  46,  47,  48,  49,  50,  51,  52,  53,  54,  55,  56,  57,  58,  59,
    60,  61,  62,  63,  64,  97,  98,  99,  100, 101, 102, 103, 104, 105, 106,
    107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121,
    122, 91,  92,  93,  94,  95,  96,  97,  98,  99,  100, 101, 102, 103, 104,
    105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119,
    120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134,
    135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149,
    150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164,
    165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179,
    180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194,
    195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209,
    210, 211, 212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224,
    225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239,
    240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254,
    255
};
#endif

#ifndef GPERF_CASE_STRCMP
# define GPERF_CASE_STRCMP 1
static int gperf_case_strcmp(register const char *s1, register const char *s2)
{
    for (;;) {
        unsigned char c1 = gperf_downcase[(unsigned char) *s1++];
        unsigned char c2 = gperf_downcase[(unsigned char) *s2++];
        if (c1 != 0 && c1 == c2) {
            continue;
        }
        return (int) c1 - (int) c2;
    }
}
#endif

#ifdef __GNUC__
__inline
#else
# ifdef __cplusplus
inline
# endif
#endif
    static unsigned int mailbox_header_cache_hash(register const char *str,
                                                  register size_t len)
{
    static unsigned char asso_values[] = {
        66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66,
        66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66,
        66, 66, 66, 66, 66, 66, 66, 66, 66, 3,  66, 66, 66, 66, 66, 66, 66, 66,
        66, 66, 66, 35, 66, 66, 66, 66, 66, 66, 66, 1,  2,  1,  2,  1,  26, 2,
        15, 23, 66, 66, 10, 1,  27, 17, 12, 66, 7,  2,  18, 16, 21, 8,  1,  13,
        66, 66, 66, 66, 66, 66, 66, 1,  2,  1,  2,  1,  26, 2,  15, 23, 66, 66,
        10, 1,  27, 17, 12, 66, 7,  2,  18, 16, 21, 8,  1,  13, 66, 66, 66, 66,
        66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66,
        66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66,
        66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66,
        66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66,
        66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66,
        66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66,
        66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66,
        66, 66, 66, 66
    };
    register unsigned int hval = len;

    switch (hval) {
    default:
        hval += asso_values[(unsigned char) str[2]];
    /*FALLTHROUGH*/
    case 2:
    case 1:
        hval += asso_values[(unsigned char) str[0]];
        break;
    }
    return hval + asso_values[(unsigned char) str[len - 1]];
}

struct mailbox_header_cache *mailbox_header_cache_lookup(
    register const char *str,
    register size_t len)
{
    static struct mailbox_header_cache wordlist[] = {
        { "",                                0         },
        { "",                                0         },
        { "",                                0         },
        { "",                                0         },
#line 71 "imap/mailbox_header_cache.gperf"
        { "cc",                              BIT32_MAX },
        { "",                                0         },
        { "",                                0         },
#line 70 "imap/mailbox_header_cache.gperf"
        { "bcc",                             BIT32_MAX },
        { "",                                0         },
        { "",                                0         },
        { "",                                0         },
        { "",                                0         },
        { "",                                0         },
#line 62 "imap/mailbox_header_cache.gperf"
        { "x-msoesrec",                      2         },
#line 66 "imap/mailbox_header_cache.gperf"
        { "x-mail-from",                     3         },
#line 87 "imap/mailbox_header_cache.gperf"
        { "message-id",                      BIT32_MAX },
#line 63 "imap/mailbox_header_cache.gperf"
        { "x-spam-score",                    3         },
#line 57 "imap/mailbox_header_cache.gperf"
        { "x-mailer",                        1         },
#line 79 "imap/mailbox_header_cache.gperf"
        { "received",                        BIT32_MAX },
#line 68 "imap/mailbox_header_cache.gperf"
        { "x-me-message-id",                 4         },
#line 92 "imap/mailbox_header_cache.gperf"
        { "arc-seal",                        BIT32_MAX },
#line 54 "imap/mailbox_header_cache.gperf"
        { "resent-from",                     0         },
#line 69 "imap/mailbox_header_cache.gperf"
        { "x-cyrus-session-id",              4         },
#line 85 "imap/mailbox_header_cache.gperf"
        { "domainkey-signature",             BIT32_MAX },
#line 93 "imap/mailbox_header_cache.gperf"
        { "arc-message-signature",           BIT32_MAX },
#line 72 "imap/mailbox_header_cache.gperf"
        { "date",                            BIT32_MAX },
#line 73 "imap/mailbox_header_cache.gperf"
        { "delivery-date",                   BIT32_MAX },
#line 58 "imap/mailbox_header_cache.gperf"
        { "x-trace",                         1         },
#line 90 "imap/mailbox_header_cache.gperf"
        { "x-apple-base-url",                6         },
#line 82 "imap/mailbox_header_cache.gperf"
        { "subject",                         BIT32_MAX },
#line 94 "imap/mailbox_header_cache.gperf"
        { "arc-authentication-results",      BIT32_MAX },
#line 97 "imap/mailbox_header_cache.gperf"
        { "archived-at",                     BIT32_MAX },
#line 61 "imap/mailbox_header_cache.gperf"
        { "x-msmail-priority",               2         },
#line 98 "imap/mailbox_header_cache.gperf"
        { "listbox-message-date",            BIT32_MAX },
#line 65 "imap/mailbox_header_cache.gperf"
        { "x-delivered-to",                  3         },
#line 91 "imap/mailbox_header_cache.gperf"
        { "x-apple-mail-remote-attachments", 6         },
#line 60 "imap/mailbox_header_cache.gperf"
        { "x-priority",                      2         },
#line 83 "imap/mailbox_header_cache.gperf"
        { "to",                              BIT32_MAX },
#line 64 "imap/mailbox_header_cache.gperf"
        { "x-resolved-to",                   3         },
#line 59 "imap/mailbox_header_cache.gperf"
        { "x-ref",                           2         },
#line 84 "imap/mailbox_header_cache.gperf"
        { "dkim-signature",                  BIT32_MAX },
#line 77 "imap/mailbox_header_cache.gperf"
        { "mime-version",                    BIT32_MAX },
#line 81 "imap/mailbox_header_cache.gperf"
        { "sender",                          7         },
#line 95 "imap/mailbox_header_cache.gperf"
        { "authentication-results",          BIT32_MAX },
#line 78 "imap/mailbox_header_cache.gperf"
        { "reply-to",                        7         },
#line 53 "imap/mailbox_header_cache.gperf"
        { "references",                      0         },
#line 96 "imap/mailbox_header_cache.gperf"
        { "received-spf",                    BIT32_MAX },
#line 55 "imap/mailbox_header_cache.gperf"
        { "newsgroups",                      0         },
#line 75 "imap/mailbox_header_cache.gperf"
        { "from",                            BIT32_MAX },
#line 89 "imap/mailbox_header_cache.gperf"
        { "x-uniform-type-identifier",       6         },
#line 74 "imap/mailbox_header_cache.gperf"
        { "envelope-to",                     BIT32_MAX },
#line 80 "imap/mailbox_header_cache.gperf"
        { "return-path",                     BIT32_MAX },
#line 86 "imap/mailbox_header_cache.gperf"
        { "domainkey-x509",                  BIT32_MAX },
#line 99 "imap/mailbox_header_cache.gperf"
        { "topicbox-message-uuid",           BIT32_MAX },
#line 76 "imap/mailbox_header_cache.gperf"
        { "in-reply-to",                     BIT32_MAX },
#line 88 "imap/mailbox_header_cache.gperf"
        { "x-universally-unique-identifier", 6         },
#line 52 "imap/mailbox_header_cache.gperf"
        { "priority",                        0         },
#line 100 "imap/mailbox_header_cache.gperf"
        { "topicbox-policy-reasoning",       BIT32_MAX },
        { "",                                0         },
        { "",                                0         },
        { "",                                0         },
        { "",                                0         },
        { "",                                0         },
        { "",                                0         },
#line 56 "imap/mailbox_header_cache.gperf"
        { "followup-to",                     0         },
#line 67 "imap/mailbox_header_cache.gperf"
        { "x-truedomain-domain",             3         }
    };

    if (len <= MAX_WORD_LENGTH && len >= MIN_WORD_LENGTH) {
        register unsigned int key = mailbox_header_cache_hash(str, len);

        if (key <= MAX_HASH_VALUE) {
            register const char *s = wordlist[key].name;

            if ((((unsigned char) *str ^ (unsigned char) *s) & ~32) == 0
                && !gperf_case_strcmp(str, s))
            {
                return &wordlist[key];
            }
        }
    }
    return 0;
}

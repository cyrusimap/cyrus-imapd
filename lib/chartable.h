/* Definitions internal to charset.c and chartable.c */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

struct charmap {
    unsigned int c;
    unsigned char next;
};

struct charset {
    const char *name;
    const struct charmap (*table)[256];
};

struct charset_alias {
    const char *name;
    const char *canon_name;
};

/* unicode canon translations */
extern const int chartables_translation_multichar[];
extern const unsigned char chartables_translation_block16[256];
extern const unsigned char chartables_translation_block8[][256];
extern const int chartables_translation[][256];

/* named character sets */
extern const struct charset chartables_charset_table[];
extern const int chartables_num_charsets;
extern const struct charset_alias charset_aliases[];

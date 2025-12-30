/* ANSI-C code produced by gperf version 3.2.1 */
/* Command-line: gperf imap/jmap_blob_props.gperf  */
/* Computed positions: -k'$' */

#if !((' ' == 32) && ('!' == 33) && ('"' == 34) && ('#' == 35) \
      && ('%' == 37) && ('&' == 38) && ('\'' == 39) && ('(' == 40) \
      && (')' == 41) && ('*' == 42) && ('+' == 43) && (',' == 44) \
      && ('-' == 45) && ('.' == 46) && ('/' == 47) && ('0' == 48) \
      && ('1' == 49) && ('2' == 50) && ('3' == 51) && ('4' == 52) \
      && ('5' == 53) && ('6' == 54) && ('7' == 55) && ('8' == 56) \
      && ('9' == 57) && (':' == 58) && (';' == 59) && ('<' == 60) \
      && ('=' == 61) && ('>' == 62) && ('?' == 63) && ('A' == 65) \
      && ('B' == 66) && ('C' == 67) && ('D' == 68) && ('E' == 69) \
      && ('F' == 70) && ('G' == 71) && ('H' == 72) && ('I' == 73) \
      && ('J' == 74) && ('K' == 75) && ('L' == 76) && ('M' == 77) \
      && ('N' == 78) && ('O' == 79) && ('P' == 80) && ('Q' == 81) \
      && ('R' == 82) && ('S' == 83) && ('T' == 84) && ('U' == 85) \
      && ('V' == 86) && ('W' == 87) && ('X' == 88) && ('Y' == 89) \
      && ('Z' == 90) && ('[' == 91) && ('\\' == 92) && (']' == 93) \
      && ('^' == 94) && ('_' == 95) && ('a' == 97) && ('b' == 98) \
      && ('c' == 99) && ('d' == 100) && ('e' == 101) && ('f' == 102) \
      && ('g' == 103) && ('h' == 104) && ('i' == 105) && ('j' == 106) \
      && ('k' == 107) && ('l' == 108) && ('m' == 109) && ('n' == 110) \
      && ('o' == 111) && ('p' == 112) && ('q' == 113) && ('r' == 114) \
      && ('s' == 115) && ('t' == 116) && ('u' == 117) && ('v' == 118) \
      && ('w' == 119) && ('x' == 120) && ('y' == 121) && ('z' == 122) \
      && ('{' == 123) && ('|' == 124) && ('}' == 125) && ('~' == 126))
/* The character set is not based on ISO-646.  */
#error "gperf generated tables don't work with this execution character set. Please report a bug to <bug-gperf@gnu.org>."
#endif

#line 1 "imap/jmap_blob_props.gperf"

/* jmap_blob_props.h -- Lookup functions for JMAP Blob properties */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

enum
  {
    BLOB_PROP_TOTAL_KEYWORDS = 7,
    BLOB_PROP_MIN_WORD_LENGTH = 4,
    BLOB_PROP_MAX_WORD_LENGTH = 14,
    BLOB_PROP_MIN_HASH_VALUE = 4,
    BLOB_PROP_MAX_HASH_VALUE = 15
  };

/* maximum key range = 12, duplicates = 0 */

#ifdef __GNUC__
__inline
#else
#ifdef __cplusplus
inline
#endif
#endif
static unsigned int
blob_prop_hash (register const char *str, register size_t len)
{
  static const unsigned char asso_values[] =
    {
      16, 16, 16, 16, 16, 16, 16, 16, 16, 16,
      16, 16, 16, 16, 16, 16, 16, 16, 16, 16,
      16, 16, 16, 16, 16, 16, 16, 16, 16, 16,
      16, 16, 16, 16, 16, 16, 16, 16, 16, 16,
      16, 16, 16, 16, 16, 16, 16, 16, 16, 16,
      16, 16,  0,  5,  0, 16, 16, 16, 16, 16,
      16, 16, 16, 16, 16, 16, 16, 16, 16, 16,
      16, 16, 16, 16, 16, 16, 16, 16, 16, 16,
      16, 16, 16, 16, 16, 16, 16, 16, 16, 16,
      16, 16, 16, 16, 16, 16, 16,  0, 16, 16,
      16,  5, 16, 16, 16, 16, 16, 16, 16, 16,
      16, 16, 16, 16, 16, 16,  0, 16, 16, 16,
      16, 16, 16, 16, 16, 16, 16, 16, 16, 16,
      16, 16, 16, 16, 16, 16, 16, 16, 16, 16,
      16, 16, 16, 16, 16, 16, 16, 16, 16, 16,
      16, 16, 16, 16, 16, 16, 16, 16, 16, 16,
      16, 16, 16, 16, 16, 16, 16, 16, 16, 16,
      16, 16, 16, 16, 16, 16, 16, 16, 16, 16,
      16, 16, 16, 16, 16, 16, 16, 16, 16, 16,
      16, 16, 16, 16, 16, 16, 16, 16, 16, 16,
      16, 16, 16, 16, 16, 16, 16, 16, 16, 16,
      16, 16, 16, 16, 16, 16, 16, 16, 16, 16,
      16, 16, 16, 16, 16, 16, 16, 16, 16, 16,
      16, 16, 16, 16, 16, 16, 16, 16, 16, 16,
      16, 16, 16, 16, 16, 16, 16, 16, 16, 16,
      16, 16, 16, 16, 16, 16
    };
  return len + asso_values[(unsigned char)str[len - 1]];
}

static const unsigned char blob_prop_lengths[] =
  {
     0,  0,  0,  0,  4,  0,  0,  0,  0,  4, 10, 11,  0, 13,
    14, 10
  };

static const jmap_property_t blob_prop_array[] =
  {
    {(char*)0,NULL,0}, {(char*)0,NULL,0}, {(char*)0,NULL,0},
    {(char*)0,NULL,0},
#line 27 "imap/jmap_blob_props.gperf"
    {"data",           NULL, JMAP_PROP_SERVER_SET | JMAP_PROP_IMMUTABLE},
    {(char*)0,NULL,0}, {(char*)0,NULL,0}, {(char*)0,NULL,0},
    {(char*)0,NULL,0},
#line 33 "imap/jmap_blob_props.gperf"
    {"size",           NULL, JMAP_PROP_SERVER_SET | JMAP_PROP_IMMUTABLE},
#line 31 "imap/jmap_blob_props.gperf"
    {"digest:sha",     NULL, JMAP_PROP_SERVER_SET | JMAP_PROP_IMMUTABLE | JMAP_PROP_SKIP_GET},
#line 29 "imap/jmap_blob_props.gperf"
    {"data:asText",    NULL, JMAP_PROP_SERVER_SET | JMAP_PROP_IMMUTABLE | JMAP_PROP_SKIP_GET},
    {(char*)0,NULL,0},
#line 28 "imap/jmap_blob_props.gperf"
    {"data:asBase64",  NULL, JMAP_PROP_SERVER_SET | JMAP_PROP_IMMUTABLE | JMAP_PROP_SKIP_GET},
#line 32 "imap/jmap_blob_props.gperf"
    {"digest:sha-256", NULL, JMAP_PROP_SERVER_SET | JMAP_PROP_IMMUTABLE | JMAP_PROP_SKIP_GET},
#line 30 "imap/jmap_blob_props.gperf"
    {"digest:md5",     NULL, JMAP_PROP_SERVER_SET | JMAP_PROP_IMMUTABLE | JMAP_PROP_SKIP_GET}
  };

const jmap_property_t *
blob_prop_lookup (register const char *str, register size_t len)
{
  if (len <= BLOB_PROP_MAX_WORD_LENGTH && len >= BLOB_PROP_MIN_WORD_LENGTH)
    {
      register unsigned int key = blob_prop_hash (str, len);

      if (key <= BLOB_PROP_MAX_HASH_VALUE)
        if (len == blob_prop_lengths[key])
          {
            register const char *s = blob_prop_array[key].name;

            if (s && *str == *s && !memcmp (str + 1, s + 1, len - 1))
              return &blob_prop_array[key];
          }
    }
  return (jmap_property_t *) 0;
}
#line 34 "imap/jmap_blob_props.gperf"


static const jmap_prop_hash_table_t jmap_blob_props_map = {
    blob_prop_array,
    BLOB_PROP_TOTAL_KEYWORDS,
    BLOB_PROP_MIN_HASH_VALUE,
    BLOB_PROP_MAX_HASH_VALUE,
    &blob_prop_lookup
};

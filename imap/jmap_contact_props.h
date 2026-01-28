/* ANSI-C code produced by gperf version 3.2.1 */
/* Command-line: gperf imap/jmap_contact_props.gperf  */
/* Computed positions: -k'1-2' */

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

#line 1 "imap/jmap_contact_props.gperf"

/* jmap_contact_props.h -- Lookup functions for JMAP Contact properties */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

enum
  {
    CONTACT_PROP_TOTAL_KEYWORDS = 28,
    CONTACT_PROP_MIN_WORD_LENGTH = 2,
    CONTACT_PROP_MAX_WORD_LENGTH = 13,
    CONTACT_PROP_MIN_HASH_VALUE = 3,
    CONTACT_PROP_MAX_HASH_VALUE = 51
  };

/* maximum key range = 49, duplicates = 0 */

#ifdef __GNUC__
__inline
#else
#ifdef __cplusplus
inline
#endif
#endif
static unsigned int
contact_prop_hash (register const char *str, register size_t len)
{
  static const unsigned char asso_values[] =
    {
      52, 52, 52, 52, 52, 52, 52, 52, 52, 52,
      52, 52, 52, 52, 52, 52, 52, 52, 52, 52,
      52, 52, 52, 52, 52, 52, 52, 52, 52, 52,
      52, 52, 52, 52, 52, 52, 52, 52, 52, 52,
      52, 52, 52, 52, 52, 20, 52, 52, 52, 52,
      52, 52, 52, 52, 52, 52, 52, 52, 52, 52,
      52, 52, 52, 52, 52, 52, 52,  0, 52, 52,
      52, 52, 52, 52, 52, 52, 52, 52, 52, 52,
      52, 52, 52, 52, 52, 52, 52, 52, 52, 52,
      52, 52, 52, 52, 52, 52, 52,  0, 30,  0,
       5, 20, 20, 52, 25,  0,  0, 52,  0,  5,
       5, 15, 20, 52, 20, 15, 52,  0,  0, 52,
      15, 52, 52, 52, 52, 52, 52, 52, 52, 52,
      52, 52, 52, 52, 52, 52, 52, 52, 52, 52,
      52, 52, 52, 52, 52, 52, 52, 52, 52, 52,
      52, 52, 52, 52, 52, 52, 52, 52, 52, 52,
      52, 52, 52, 52, 52, 52, 52, 52, 52, 52,
      52, 52, 52, 52, 52, 52, 52, 52, 52, 52,
      52, 52, 52, 52, 52, 52, 52, 52, 52, 52,
      52, 52, 52, 52, 52, 52, 52, 52, 52, 52,
      52, 52, 52, 52, 52, 52, 52, 52, 52, 52,
      52, 52, 52, 52, 52, 52, 52, 52, 52, 52,
      52, 52, 52, 52, 52, 52, 52, 52, 52, 52,
      52, 52, 52, 52, 52, 52, 52, 52, 52, 52,
      52, 52, 52, 52, 52, 52, 52, 52, 52, 52,
      52, 52, 52, 52, 52, 52
    };
  return len + asso_values[(unsigned char)str[1]] + asso_values[(unsigned char)str[0]];
}

static const unsigned char contact_prop_lengths[] =
  {
     0,  0,  0,  3,  0,  0,  6,  2,  8,  9, 10, 11,  0,  8,
     9, 10, 11,  0, 13,  4,  0,  6,  7,  8,  9,  5,  6,  0,
     0,  9,  0,  6,  0,  0,  0, 10,  6,  0,  8,  0,  0,  6,
     0,  0,  0, 10,  6,  0,  0,  0,  0,  6
  };

static const jmap_property_t contact_prop_array[] =
  {
    {(char*)0,NULL,0}, {(char*)0,NULL,0}, {(char*)0,NULL,0},
#line 28 "imap/jmap_contact_props.gperf"
    {"uid",         NULL, JMAP_PROP_IMMUTABLE},
    {(char*)0,NULL,0}, {(char*)0,NULL,0},
#line 30 "imap/jmap_contact_props.gperf"
    {"avatar",      NULL, 0},
#line 27 "imap/jmap_contact_props.gperf"
    {"id",          NULL, JMAP_PROP_SERVER_SET | JMAP_PROP_IMMUTABLE | JMAP_PROP_ALWAYS_GET},
#line 33 "imap/jmap_contact_props.gperf"
    {"lastName",    NULL, 0},
#line 49 "imap/jmap_contact_props.gperf"
    {"vCardName",   NULL, JMAP_PROP_REJECT_GET | JMAP_PROP_REJECT_SET | JMAP_PROP_SKIP_GET},
#line 48 "imap/jmap_contact_props.gperf"
    {"vCardProps",  NULL, JMAP_PROP_REJECT_GET | JMAP_PROP_REJECT_SET | JMAP_PROP_SKIP_GET},
#line 50 "imap/jmap_contact_props.gperf"
    {"vCardParams", NULL, JMAP_PROP_REJECT_GET | JMAP_PROP_REJECT_SET | JMAP_PROP_SKIP_GET},
    {(char*)0,NULL,0},
#line 35 "imap/jmap_contact_props.gperf"
    {"nickname",    NULL, 0},
#line 44 "imap/jmap_contact_props.gperf"
    {"addresses",   NULL, 0},
#line 59 "imap/jmap_contact_props.gperf"
    {"importance",    JMAP_CONTACTS_EXTENSION, 0},
#line 37 "imap/jmap_contact_props.gperf"
    {"anniversary", NULL, 0},
    {(char*)0,NULL,0},
#line 53 "imap/jmap_contact_props.gperf"
    {"addressbookId", JMAP_CONTACTS_EXTENSION, 0},
#line 61 "imap/jmap_contact_props.gperf"
    {"size",          JMAP_CONTACTS_EXTENSION, JMAP_PROP_SERVER_SET},
    {(char*)0,NULL,0},
#line 34 "imap/jmap_contact_props.gperf"
    {"suffix",      NULL, 0},
#line 38 "imap/jmap_contact_props.gperf"
    {"company",     NULL, 0},
#line 40 "imap/jmap_contact_props.gperf"
    {"jobTitle",    NULL, 0},
#line 29 "imap/jmap_contact_props.gperf"
    {"isFlagged",   NULL, 0},
#line 45 "imap/jmap_contact_props.gperf"
    {"notes",       NULL, 0},
#line 43 "imap/jmap_contact_props.gperf"
    {"online",      NULL, 0},
    {(char*)0,NULL,0}, {(char*)0,NULL,0},
#line 32 "imap/jmap_contact_props.gperf"
    {"firstName",   NULL, 0},
    {(char*)0,NULL,0},
#line 41 "imap/jmap_contact_props.gperf"
    {"emails",      NULL, 0},
    {(char*)0,NULL,0}, {(char*)0,NULL,0}, {(char*)0,NULL,0},
#line 39 "imap/jmap_contact_props.gperf"
    {"department",  NULL, 0},
#line 60 "imap/jmap_contact_props.gperf"
    {"blobId",        JMAP_CONTACTS_EXTENSION, JMAP_PROP_SERVER_SET},
    {(char*)0,NULL,0},
#line 36 "imap/jmap_contact_props.gperf"
    {"birthday",    NULL, 0},
    {(char*)0,NULL,0}, {(char*)0,NULL,0},
#line 55 "imap/jmap_contact_props.gperf"
    {"x-href",        JMAP_CONTACTS_EXTENSION, JMAP_PROP_SERVER_SET | JMAP_PROP_IMMUTABLE},
    {(char*)0,NULL,0}, {(char*)0,NULL,0}, {(char*)0,NULL,0},
#line 57 "imap/jmap_contact_props.gperf"
    {"x-hasPhoto",    JMAP_CONTACTS_EXTENSION, JMAP_PROP_SERVER_SET},
#line 31 "imap/jmap_contact_props.gperf"
    {"prefix",      NULL, 0},
    {(char*)0,NULL,0}, {(char*)0,NULL,0}, {(char*)0,NULL,0},
    {(char*)0,NULL,0},
#line 42 "imap/jmap_contact_props.gperf"
    {"phones",      NULL, 0}
  };

const jmap_property_t *
contact_prop_lookup (register const char *str, register size_t len)
{
  if (len <= CONTACT_PROP_MAX_WORD_LENGTH && len >= CONTACT_PROP_MIN_WORD_LENGTH)
    {
      register unsigned int key = contact_prop_hash (str, len);

      if (key <= CONTACT_PROP_MAX_HASH_VALUE)
        if (len == contact_prop_lengths[key])
          {
            register const char *s = contact_prop_array[key].name;

            if (s && *str == *s && !memcmp (str + 1, s + 1, len - 1))
              return &contact_prop_array[key];
          }
    }
  return (jmap_property_t *) 0;
}
#line 62 "imap/jmap_contact_props.gperf"


static const jmap_prop_hash_table_t jmap_contact_props_map = {
    contact_prop_array,
    CONTACT_PROP_TOTAL_KEYWORDS,
    CONTACT_PROP_MIN_HASH_VALUE,
    CONTACT_PROP_MAX_HASH_VALUE,
    &contact_prop_lookup
};

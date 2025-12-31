/* ANSI-C code produced by gperf version 3.2.1 */
/* Command-line: gperf imap/jmap_contact_card_props.gperf  */
/* Computed positions: -k'2,$' */

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

#line 1 "imap/jmap_contact_card_props.gperf"

/* jmap_contact_card_props.h --
   Lookup functions for JMAP ContactCard properties */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

enum
  {
    CARD_PROP_TOTAL_KEYWORDS = 41,
    CARD_PROP_MIN_WORD_LENGTH = 1,
    CARD_PROP_MAX_WORD_LENGTH = 24,
    CARD_PROP_MIN_HASH_VALUE = 1,
    CARD_PROP_MAX_HASH_VALUE = 64
  };

/* maximum key range = 64, duplicates = 0 */

#ifdef __GNUC__
__inline
#else
#ifdef __cplusplus
inline
#endif
#endif
static unsigned int
card_prop_hash (register const char *str, register size_t len)
{
  static const unsigned char asso_values[] =
    {
      65, 65, 65, 65, 65, 65, 65, 65, 65, 65,
      65, 65, 65, 65, 65, 65, 65, 65, 65, 65,
      65, 65, 65, 65, 65, 65, 65, 65, 65, 65,
      65, 65, 65, 65, 65, 65, 65, 65, 65, 65,
      65, 65,  0, 65, 65, 65, 65, 65, 65, 65,
      65, 65, 65, 65, 65, 65, 65, 65, 65, 65,
      65, 65, 65, 65, 65, 65, 65,  5, 65, 65,
      65, 65, 65, 65, 65, 65, 65, 65, 65, 65,
      65, 65, 65, 65, 65, 65, 65, 65, 65, 65,
      65, 65, 65, 65, 65, 65, 65, 50, 65, 45,
       0,  0,  5, 65,  5, 15, 65, 65, 65,  0,
      20, 35, 30, 65, 25,  0,  0, 65, 65, 65,
      65,  5, 65, 65, 65, 65, 65, 65, 65, 65,
      65, 65, 65, 65, 65, 65, 65, 65, 65, 65,
      65, 65, 65, 65, 65, 65, 65, 65, 65, 65,
      65, 65, 65, 65, 65, 65, 65, 65, 65, 65,
      65, 65, 65, 65, 65, 65, 65, 65, 65, 65,
      65, 65, 65, 65, 65, 65, 65, 65, 65, 65,
      65, 65, 65, 65, 65, 65, 65, 65, 65, 65,
      65, 65, 65, 65, 65, 65, 65, 65, 65, 65,
      65, 65, 65, 65, 65, 65, 65, 65, 65, 65,
      65, 65, 65, 65, 65, 65, 65, 65, 65, 65,
      65, 65, 65, 65, 65, 65, 65, 65, 65, 65,
      65, 65, 65, 65, 65, 65, 65, 65, 65, 65,
      65, 65, 65, 65, 65, 65, 65, 65, 65, 65,
      65, 65, 65, 65, 65, 65
    };
  register unsigned int hval = len;

  switch (hval)
    {
      default:
        hval += asso_values[(unsigned char)str[1]];
#if (defined __cplusplus && (__cplusplus >= 201703L || (__cplusplus >= 201103L && defined __clang__ && __clang_major__ + (__clang_minor__ >= 9) > 3))) || (defined __STDC_VERSION__ && __STDC_VERSION__ >= 202000L && ((defined __GNUC__ && __GNUC__ >= 10) || (defined __clang__ && __clang_major__ >= 9)))
      [[fallthrough]];
#elif (defined __GNUC__ && __GNUC__ >= 7) || (defined __clang__ && __clang_major__ >= 10)
      __attribute__ ((__fallthrough__));
#endif
      /*FALLTHROUGH*/
      case 1:
        break;
    }
  return hval + asso_values[(unsigned char)str[len - 1]];
}

static const unsigned char card_prop_lengths[] =
  {
     0,  1,  2,  0,  0,  5,  6,  7,  8,  9, 10,  6,  0,  0,
    14, 10,  0,  0,  3,  4,  5,  6,  0, 18,  9, 20, 11,  7,
    18, 24,  0,  6,  7, 13, 14, 10,  0,  7, 13,  9,  5,  0,
     0, 18,  9,  0,  0, 12, 13,  9,  0,  0,  0,  0,  4,  5,
     0,  0,  8,  9,  0,  0,  0,  0, 19
  };

static const jmap_property_t card_prop_array[] =
  {
    {(char*)0,NULL,0},
#line 72 "imap/jmap_contact_card_props.gperf"
    {"*", NULL, 0},
#line 28 "imap/jmap_contact_card_props.gperf"
    {"id",                  NULL, JMAP_PROP_SERVER_SET | JMAP_PROP_IMMUTABLE | JMAP_PROP_ALWAYS_GET},
    {(char*)0,NULL,0}, {(char*)0,NULL,0},
#line 30 "imap/jmap_contact_card_props.gperf"
    {"@type",               NULL, JMAP_PROP_MANDATORY},
#line 46 "imap/jmap_contact_card_props.gperf"
    {"emails",              NULL, 0},
#line 35 "imap/jmap_contact_card_props.gperf"
    {"members",             NULL, 0},
#line 60 "imap/jmap_contact_card_props.gperf"
    {"keywords",            NULL, 0},
#line 53 "imap/jmap_contact_card_props.gperf"
    {"addresses",           NULL, 0},
#line 45 "imap/jmap_contact_card_props.gperf"
    {"department",          NULL, 0},
#line 48 "imap/jmap_contact_card_props.gperf"
    {"phones",              NULL, 0},
    {(char*)0,NULL,0}, {(char*)0,NULL,0},
#line 29 "imap/jmap_contact_card_props.gperf"
    {"addressBookIds",      NULL, 0},
#line 63 "imap/jmap_contact_card_props.gperf"
    {"vCardProps",          NULL, 0},
    {(char*)0,NULL,0}, {(char*)0,NULL,0},
#line 38 "imap/jmap_contact_card_props.gperf"
    {"uid",                 NULL, JMAP_PROP_IMMUTABLE},
#line 33 "imap/jmap_contact_card_props.gperf"
    {"kind",                NULL, 0},
#line 56 "imap/jmap_contact_card_props.gperf"
    {"links",               NULL, 0},
#line 44 "imap/jmap_contact_card_props.gperf"
    {"titles",              NULL, 0},
    {(char*)0,NULL,0},
#line 68 "imap/jmap_contact_card_props.gperf"
    {"cyrusimap.org:size",       JMAP_CONTACTS_EXTENSION, JMAP_PROP_SERVER_SET},
#line 41 "imap/jmap_contact_card_props.gperf"
    {"nicknames",           NULL, 0},
#line 67 "imap/jmap_contact_card_props.gperf"
    {"cyrusimap.org:blobId",     JMAP_CONTACTS_EXTENSION, JMAP_PROP_SERVER_SET},
#line 55 "imap/jmap_contact_card_props.gperf"
    {"directories",         NULL, 0},
#line 31 "imap/jmap_contact_card_props.gperf"
    {"version",             NULL, JMAP_PROP_MANDATORY},
#line 69 "imap/jmap_contact_card_props.gperf"
    {"cyrusimap.org:href",       JMAP_CONTACTS_EXTENSION, JMAP_PROP_SERVER_SET | JMAP_PROP_IMMUTABLE},
#line 66 "imap/jmap_contact_card_props.gperf"
    {"cyrusimap.org:importance", JMAP_CONTACTS_EXTENSION, 0},
    {(char*)0,NULL,0},
#line 36 "imap/jmap_contact_card_props.gperf"
    {"prodId",              NULL, 0},
#line 32 "imap/jmap_contact_card_props.gperf"
    {"created",             NULL, 0},
#line 59 "imap/jmap_contact_card_props.gperf"
    {"anniversaries",       NULL, 0},
#line 47 "imap/jmap_contact_card_props.gperf"
    {"onlineServices",      NULL, 0},
#line 54 "imap/jmap_contact_card_props.gperf"
    {"cryptoKeys",          NULL, 0},
    {(char*)0,NULL,0},
#line 39 "imap/jmap_contact_card_props.gperf"
    {"updated",             NULL, 0},
#line 42 "imap/jmap_contact_card_props.gperf"
    {"organizations",       NULL, 0},
#line 43 "imap/jmap_contact_card_props.gperf"
    {"speakToAs",           NULL, 0},
#line 61 "imap/jmap_contact_card_props.gperf"
    {"notes",               NULL, 0},
    {(char*)0,NULL,0}, {(char*)0,NULL,0},
#line 50 "imap/jmap_contact_card_props.gperf"
    {"preferredLanguages",  NULL, 0},
#line 37 "imap/jmap_contact_card_props.gperf"
    {"relatedTo",           NULL, 0},
    {(char*)0,NULL,0}, {(char*)0,NULL,0},
#line 62 "imap/jmap_contact_card_props.gperf"
    {"personalInfo",        NULL, 0},
#line 58 "imap/jmap_contact_card_props.gperf"
    {"localizations",       NULL, 0},
#line 49 "imap/jmap_contact_card_props.gperf"
    {"contactBy",           NULL, 0},
    {(char*)0,NULL,0}, {(char*)0,NULL,0}, {(char*)0,NULL,0},
    {(char*)0,NULL,0},
#line 40 "imap/jmap_contact_card_props.gperf"
    {"name",                NULL, 0},
#line 57 "imap/jmap_contact_card_props.gperf"
    {"media",               NULL, 0},
    {(char*)0,NULL,0}, {(char*)0,NULL,0},
#line 34 "imap/jmap_contact_card_props.gperf"
    {"language",            NULL, 0},
#line 51 "imap/jmap_contact_card_props.gperf"
    {"calendars",           NULL, 0},
    {(char*)0,NULL,0}, {(char*)0,NULL,0}, {(char*)0,NULL,0},
    {(char*)0,NULL,0},
#line 52 "imap/jmap_contact_card_props.gperf"
    {"schedulingAddresses", NULL, 0}
  };

const jmap_property_t *
card_prop_lookup (register const char *str, register size_t len)
{
  if (len <= CARD_PROP_MAX_WORD_LENGTH && len >= CARD_PROP_MIN_WORD_LENGTH)
    {
      register unsigned int key = card_prop_hash (str, len);

      if (key <= CARD_PROP_MAX_HASH_VALUE)
        if (len == card_prop_lengths[key])
          {
            register const char *s = card_prop_array[key].name;

            if (s && *str == *s && !memcmp (str + 1, s + 1, len - 1))
              return &card_prop_array[key];
          }
    }
  return (jmap_property_t *) 0;
}
#line 73 "imap/jmap_contact_card_props.gperf"


static const jmap_prop_hash_table_t jmap_card_props_map = {
    card_prop_array,
    CARD_PROP_TOTAL_KEYWORDS,
    CARD_PROP_MIN_HASH_VALUE,
    CARD_PROP_MAX_HASH_VALUE,
    &card_prop_lookup
};

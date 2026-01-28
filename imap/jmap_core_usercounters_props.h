/* ANSI-C code produced by gperf version 3.2.1 */
/* Command-line: gperf imap/jmap_core_usercounters_props.gperf  */
/* Computed positions: -k'3,5,12' */

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

#line 1 "imap/jmap_core_usercounters_props.gperf"

/* jmap_core_usercounters_props.h -- Lookup functions for JMAP Core properties */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

enum
  {
    USERCOUNTERS_PROP_TOTAL_KEYWORDS = 29,
    USERCOUNTERS_PROP_MIN_WORD_LENGTH = 2,
    USERCOUNTERS_PROP_MAX_WORD_LENGTH = 31,
    USERCOUNTERS_PROP_MIN_HASH_VALUE = 2,
    USERCOUNTERS_PROP_MAX_HASH_VALUE = 73
  };

/* maximum key range = 72, duplicates = 0 */

#ifdef __GNUC__
__inline
#else
#ifdef __cplusplus
inline
#endif
#endif
static unsigned int
usercounters_prop_hash (register const char *str, register size_t len)
{
  static const unsigned char asso_values[] =
    {
      74, 74, 74, 74, 74, 74, 74, 74, 74, 74,
      74, 74, 74, 74, 74, 74, 74, 74, 74, 74,
      74, 74, 74, 74, 74, 74, 74, 74, 74, 74,
      74, 74, 74, 74, 74, 74, 74, 74, 74, 74,
      74, 74, 74, 74, 74, 74, 74, 74, 74, 74,
      74, 74, 74, 74, 74, 74, 74, 74, 74, 74,
      74, 74, 74, 74, 74, 74, 74, 74,  5, 74,
       0, 74, 74, 74, 74, 74, 74,  0, 74, 74,
      74, 74, 74,  5, 74, 74, 74, 74, 74, 74,
      74, 74, 74, 74, 74, 74, 74,  5,  0,  0,
      20,  0, 74,  0, 74,  5, 74, 74, 10, 74,
      15,  5, 74, 74, 74,  0,  0, 74, 74, 74,
      74, 74, 74, 74, 74, 74, 74, 74, 74, 74,
      74, 74, 74, 74, 74, 74, 74, 74, 74, 74,
      74, 74, 74, 74, 74, 74, 74, 74, 74, 74,
      74, 74, 74, 74, 74, 74, 74, 74, 74, 74,
      74, 74, 74, 74, 74, 74, 74, 74, 74, 74,
      74, 74, 74, 74, 74, 74, 74, 74, 74, 74,
      74, 74, 74, 74, 74, 74, 74, 74, 74, 74,
      74, 74, 74, 74, 74, 74, 74, 74, 74, 74,
      74, 74, 74, 74, 74, 74, 74, 74, 74, 74,
      74, 74, 74, 74, 74, 74, 74, 74, 74, 74,
      74, 74, 74, 74, 74, 74, 74, 74, 74, 74,
      74, 74, 74, 74, 74, 74, 74, 74, 74, 74,
      74, 74, 74, 74, 74, 74, 74, 74, 74, 74,
      74, 74, 74, 74, 74, 74
    };
  register unsigned int hval = len;

  switch (hval)
    {
      default:
        hval += asso_values[(unsigned char)str[11]];
#if (defined __cplusplus && (__cplusplus >= 201703L || (__cplusplus >= 201103L && defined __clang__ && __clang_major__ + (__clang_minor__ >= 9) > 3))) || (defined __STDC_VERSION__ && __STDC_VERSION__ >= 202000L && ((defined __GNUC__ && __GNUC__ >= 10) || (defined __clang__ && __clang_major__ >= 9)))
      [[fallthrough]];
#elif (defined __GNUC__ && __GNUC__ >= 7) || (defined __clang__ && __clang_major__ >= 10)
      __attribute__ ((__fallthrough__));
#endif
      /*FALLTHROUGH*/
      case 11:
      case 10:
      case 9:
      case 8:
      case 7:
      case 6:
      case 5:
        hval += asso_values[(unsigned char)str[4]];
#if (defined __cplusplus && (__cplusplus >= 201703L || (__cplusplus >= 201103L && defined __clang__ && __clang_major__ + (__clang_minor__ >= 9) > 3))) || (defined __STDC_VERSION__ && __STDC_VERSION__ >= 202000L && ((defined __GNUC__ && __GNUC__ >= 10) || (defined __clang__ && __clang_major__ >= 9)))
      [[fallthrough]];
#elif (defined __GNUC__ && __GNUC__ >= 7) || (defined __clang__ && __clang_major__ >= 10)
      __attribute__ ((__fallthrough__));
#endif
      /*FALLTHROUGH*/
      case 4:
      case 3:
        hval += asso_values[(unsigned char)str[2]];
#if (defined __cplusplus && (__cplusplus >= 201703L || (__cplusplus >= 201103L && defined __clang__ && __clang_major__ + (__clang_minor__ >= 9) > 3))) || (defined __STDC_VERSION__ && __STDC_VERSION__ >= 202000L && ((defined __GNUC__ && __GNUC__ >= 10) || (defined __clang__ && __clang_major__ >= 9)))
      [[fallthrough]];
#elif (defined __GNUC__ && __GNUC__ >= 7) || (defined __clang__ && __clang_major__ >= 10)
      __attribute__ ((__fallthrough__));
#endif
      /*FALLTHROUGH*/
      case 2:
        break;
    }
  return hval;
}

static const unsigned char usercounters_prop_lengths[] =
  {
     0,  0,  2,  0,  0,  0,  0,  0,  0,  0, 10, 11,  0, 13,
     0, 10,  0, 17, 18,  0,  0, 11, 17,  0, 24, 25, 16, 17,
    23, 24,  0, 31,  0, 23, 24,  0, 11,  0, 18, 14, 30, 21,
     0,  0, 14,  0, 21,  0,  0,  0,  0,  0,  0,  0,  0,  0,
     0,  0,  0,  0,  0, 21,  0,  0,  0,  0, 21,  0, 28,  0,
     0,  0,  0, 28
  };

static const jmap_property_t usercounters_prop_array[] =
  {
    {(char*)0,NULL,0}, {(char*)0,NULL,0},
#line 27 "imap/jmap_core_usercounters_props.gperf"
    {"id",                              NULL, JMAP_PROP_SERVER_SET | JMAP_PROP_IMMUTABLE | JMAP_PROP_ALWAYS_GET},
    {(char*)0,NULL,0}, {(char*)0,NULL,0}, {(char*)0,NULL,0},
    {(char*)0,NULL,0}, {(char*)0,NULL,0}, {(char*)0,NULL,0},
    {(char*)0,NULL,0},
#line 54 "imap/jmap_core_usercounters_props.gperf"
    {"raclModSeq",                      NULL, JMAP_PROP_SERVER_SET},
#line 32 "imap/jmap_core_usercounters_props.gperf"
    {"notesModSeq",                     NULL, JMAP_PROP_SERVER_SET},
    {(char*)0,NULL,0},
#line 28 "imap/jmap_core_usercounters_props.gperf"
    {"highestModSeq",                   NULL, JMAP_PROP_SERVER_SET},
    {(char*)0,NULL,0},
#line 29 "imap/jmap_core_usercounters_props.gperf"
    {"mailModSeq",                      NULL, JMAP_PROP_SERVER_SET},
    {(char*)0,NULL,0},
#line 34 "imap/jmap_core_usercounters_props.gperf"
    {"sieveScriptModSeq",               NULL, JMAP_PROP_SERVER_SET},
#line 44 "imap/jmap_core_usercounters_props.gperf"
    {"notesFoldersModSeq",              NULL, JMAP_PROP_SERVER_SET},
    {(char*)0,NULL,0}, {(char*)0,NULL,0},
#line 53 "imap/jmap_core_usercounters_props.gperf"
    {"quotaModSeq",                     NULL, JMAP_PROP_SERVER_SET},
#line 41 "imap/jmap_core_usercounters_props.gperf"
    {"mailFoldersModSeq",               NULL, JMAP_PROP_SERVER_SET},
    {(char*)0,NULL,0},
#line 46 "imap/jmap_core_usercounters_props.gperf"
    {"sieveScriptFoldersModSeq",        NULL, JMAP_PROP_SERVER_SET},
#line 50 "imap/jmap_core_usercounters_props.gperf"
    {"notesFoldersDeletedModSeq",       NULL, JMAP_PROP_SERVER_SET},
#line 33 "imap/jmap_core_usercounters_props.gperf"
    {"submissionModSeq",                NULL, JMAP_PROP_SERVER_SET},
#line 35 "imap/jmap_core_usercounters_props.gperf"
    {"mailDeletedModSeq",               NULL, JMAP_PROP_SERVER_SET},
#line 39 "imap/jmap_core_usercounters_props.gperf"
    {"submissionDeletedModSeq",         NULL, JMAP_PROP_SERVER_SET},
#line 40 "imap/jmap_core_usercounters_props.gperf"
    {"sieveScriptDeletedModSeq",        NULL, JMAP_PROP_SERVER_SET},
    {(char*)0,NULL,0},
#line 52 "imap/jmap_core_usercounters_props.gperf"
    {"sieveScriptFoldersDeletedModSeq", NULL, JMAP_PROP_SERVER_SET},
    {(char*)0,NULL,0},
#line 45 "imap/jmap_core_usercounters_props.gperf"
    {"submissionFoldersModSeq",         NULL, JMAP_PROP_SERVER_SET},
#line 47 "imap/jmap_core_usercounters_props.gperf"
    {"mailFoldersDeletedModSeq",        NULL, JMAP_PROP_SERVER_SET},
    {(char*)0,NULL,0},
#line 55 "imap/jmap_core_usercounters_props.gperf"
    {"uidValidity",                     NULL, JMAP_PROP_SERVER_SET},
    {(char*)0,NULL,0},
#line 38 "imap/jmap_core_usercounters_props.gperf"
    {"notesDeletedModSeq",              NULL, JMAP_PROP_SERVER_SET},
#line 31 "imap/jmap_core_usercounters_props.gperf"
    {"contactsModSeq",                  NULL, JMAP_PROP_SERVER_SET},
#line 51 "imap/jmap_core_usercounters_props.gperf"
    {"submissionFoldersDeletedModSeq",  NULL, JMAP_PROP_SERVER_SET},
#line 37 "imap/jmap_core_usercounters_props.gperf"
    {"contactsDeletedModSeq",           NULL, JMAP_PROP_SERVER_SET},
    {(char*)0,NULL,0}, {(char*)0,NULL,0},
#line 30 "imap/jmap_core_usercounters_props.gperf"
    {"calendarModSeq",                  NULL, JMAP_PROP_SERVER_SET},
    {(char*)0,NULL,0},
#line 36 "imap/jmap_core_usercounters_props.gperf"
    {"calendarDeletedModSeq",           NULL, JMAP_PROP_SERVER_SET},
    {(char*)0,NULL,0}, {(char*)0,NULL,0}, {(char*)0,NULL,0},
    {(char*)0,NULL,0}, {(char*)0,NULL,0}, {(char*)0,NULL,0},
    {(char*)0,NULL,0}, {(char*)0,NULL,0}, {(char*)0,NULL,0},
    {(char*)0,NULL,0}, {(char*)0,NULL,0}, {(char*)0,NULL,0},
    {(char*)0,NULL,0}, {(char*)0,NULL,0},
#line 43 "imap/jmap_core_usercounters_props.gperf"
    {"contactsFoldersModSeq",           NULL, JMAP_PROP_SERVER_SET},
    {(char*)0,NULL,0}, {(char*)0,NULL,0}, {(char*)0,NULL,0},
    {(char*)0,NULL,0},
#line 42 "imap/jmap_core_usercounters_props.gperf"
    {"calendarFoldersModSeq",           NULL, JMAP_PROP_SERVER_SET},
    {(char*)0,NULL,0},
#line 49 "imap/jmap_core_usercounters_props.gperf"
    {"contactsFoldersDeletedModSeq",    NULL, JMAP_PROP_SERVER_SET},
    {(char*)0,NULL,0}, {(char*)0,NULL,0}, {(char*)0,NULL,0},
    {(char*)0,NULL,0},
#line 48 "imap/jmap_core_usercounters_props.gperf"
    {"calendarFoldersDeletedModSeq",    NULL, JMAP_PROP_SERVER_SET}
  };

const jmap_property_t *
usercounters_prop_lookup (register const char *str, register size_t len)
{
  if (len <= USERCOUNTERS_PROP_MAX_WORD_LENGTH && len >= USERCOUNTERS_PROP_MIN_WORD_LENGTH)
    {
      register unsigned int key = usercounters_prop_hash (str, len);

      if (key <= USERCOUNTERS_PROP_MAX_HASH_VALUE)
        if (len == usercounters_prop_lengths[key])
          {
            register const char *s = usercounters_prop_array[key].name;

            if (s && *str == *s && !memcmp (str + 1, s + 1, len - 1))
              return &usercounters_prop_array[key];
          }
    }
  return (jmap_property_t *) 0;
}
#line 56 "imap/jmap_core_usercounters_props.gperf"


static const jmap_prop_hash_table_t jmap_usercounters_props_map = {
    usercounters_prop_array,
    USERCOUNTERS_PROP_TOTAL_KEYWORDS,
    USERCOUNTERS_PROP_MIN_HASH_VALUE,
    USERCOUNTERS_PROP_MAX_HASH_VALUE,
    &usercounters_prop_lookup
};

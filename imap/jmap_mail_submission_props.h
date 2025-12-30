/* ANSI-C code produced by gperf version 3.2.1 */
/* Command-line: gperf imap/jmap_mail_submission_props.gperf  */
/* Computed positions: -k'1' */

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

#line 1 "imap/jmap_mail_submission_props.gperf"

/* jmap_mail_submission_props.h --
   Lookup functions for JMAP Email Submission properties */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

enum
  {
    SUBMISSION_PROP_TOTAL_KEYWORDS = 12,
    SUBMISSION_PROP_MIN_WORD_LENGTH = 2,
    SUBMISSION_PROP_MAX_WORD_LENGTH = 14,
    SUBMISSION_PROP_MIN_HASH_VALUE = 2,
    SUBMISSION_PROP_MAX_HASH_VALUE = 25
  };

/* maximum key range = 24, duplicates = 0 */

#ifdef __GNUC__
__inline
#else
#ifdef __cplusplus
inline
#endif
#endif
static unsigned int
submission_prop_hash (register const char *str, register size_t len)
{
  static const unsigned char asso_values[] =
    {
      26, 26, 26, 26, 26, 26, 26, 26, 26, 26,
      26, 26, 26, 26, 26, 26, 26, 26, 26, 26,
      26, 26, 26, 26, 26, 26, 26, 26, 26, 26,
      26, 26, 26, 26, 26, 26, 26, 26, 26, 26,
      26, 26, 26, 26, 26, 26, 26, 26, 26, 26,
      26, 26, 26, 26, 26, 26, 26, 26, 26, 26,
      26, 26, 26, 26, 26, 26, 26, 26, 26, 26,
      26, 26, 26, 26, 26, 26, 26, 26, 26, 26,
      26, 26, 26, 26, 26, 26, 26, 26, 26, 26,
      26, 26, 26, 26, 26, 26, 26, 26, 26,  5,
       5,  0, 26, 26, 26,  0, 26, 26, 26, 15,
      26,  5, 26, 26, 26,  0,  5, 10, 26, 26,
      26, 26, 26, 26, 26, 26, 26, 26, 26, 26,
      26, 26, 26, 26, 26, 26, 26, 26, 26, 26,
      26, 26, 26, 26, 26, 26, 26, 26, 26, 26,
      26, 26, 26, 26, 26, 26, 26, 26, 26, 26,
      26, 26, 26, 26, 26, 26, 26, 26, 26, 26,
      26, 26, 26, 26, 26, 26, 26, 26, 26, 26,
      26, 26, 26, 26, 26, 26, 26, 26, 26, 26,
      26, 26, 26, 26, 26, 26, 26, 26, 26, 26,
      26, 26, 26, 26, 26, 26, 26, 26, 26, 26,
      26, 26, 26, 26, 26, 26, 26, 26, 26, 26,
      26, 26, 26, 26, 26, 26, 26, 26, 26, 26,
      26, 26, 26, 26, 26, 26, 26, 26, 26, 26,
      26, 26, 26, 26, 26, 26, 26, 26, 26, 26,
      26, 26, 26, 26, 26, 26
    };
  return len + asso_values[(unsigned char)str[0]];
}

static const unsigned char submission_prop_lengths[] =
  {
     0,  0,  2,  0,  0,  0,  6,  7,  8,  0, 10,  6,  7,  8,
     0, 10,  0,  0,  0, 14, 10,  0,  0,  0,  0, 10
  };

static const jmap_property_t submission_prop_array[] =
  {
    {(char*)0,NULL,0}, {(char*)0,NULL,0},
#line 28 "imap/jmap_mail_submission_props.gperf"
    {"id",             NULL, JMAP_PROP_SERVER_SET | JMAP_PROP_IMMUTABLE | JMAP_PROP_ALWAYS_GET},
    {(char*)0,NULL,0}, {(char*)0,NULL,0}, {(char*)0,NULL,0},
#line 33 "imap/jmap_mail_submission_props.gperf"
    {"sendAt",         NULL, JMAP_PROP_SERVER_SET | JMAP_PROP_IMMUTABLE},
#line 30 "imap/jmap_mail_submission_props.gperf"
    {"emailId",        NULL, JMAP_PROP_IMMUTABLE},
#line 32 "imap/jmap_mail_submission_props.gperf"
    {"envelope",       NULL, JMAP_PROP_IMMUTABLE},
    {(char*)0,NULL,0},
#line 29 "imap/jmap_mail_submission_props.gperf"
    {"identityId",     NULL, JMAP_PROP_IMMUTABLE},
#line 40 "imap/jmap_mail_submission_props.gperf"
    {"onSend",  JMAP_MAIL_EXTENSION, JMAP_PROP_IMMUTABLE},
#line 41 "imap/jmap_mail_submission_props.gperf"
    {"created", JMAP_MAIL_EXTENSION, JMAP_PROP_SERVER_SET | JMAP_PROP_IMMUTABLE},
#line 31 "imap/jmap_mail_submission_props.gperf"
    {"threadId",       NULL, JMAP_PROP_SERVER_SET | JMAP_PROP_IMMUTABLE},
    {(char*)0,NULL,0},
#line 36 "imap/jmap_mail_submission_props.gperf"
    {"dsnBlobIds",     NULL, JMAP_PROP_SERVER_SET},
    {(char*)0,NULL,0}, {(char*)0,NULL,0}, {(char*)0,NULL,0},
#line 35 "imap/jmap_mail_submission_props.gperf"
    {"deliveryStatus", NULL, JMAP_PROP_SERVER_SET},
#line 34 "imap/jmap_mail_submission_props.gperf"
    {"undoStatus",     NULL, JMAP_PROP_SERVER_SET},
    {(char*)0,NULL,0}, {(char*)0,NULL,0}, {(char*)0,NULL,0},
    {(char*)0,NULL,0},
#line 37 "imap/jmap_mail_submission_props.gperf"
    {"mdnBlobIds",     NULL, JMAP_PROP_SERVER_SET}
  };

const jmap_property_t *
submission_prop_lookup (register const char *str, register size_t len)
{
  if (len <= SUBMISSION_PROP_MAX_WORD_LENGTH && len >= SUBMISSION_PROP_MIN_WORD_LENGTH)
    {
      register unsigned int key = submission_prop_hash (str, len);

      if (key <= SUBMISSION_PROP_MAX_HASH_VALUE)
        if (len == submission_prop_lengths[key])
          {
            register const char *s = submission_prop_array[key].name;

            if (s && *str == *s && !memcmp (str + 1, s + 1, len - 1))
              return &submission_prop_array[key];
          }
    }
  return (jmap_property_t *) 0;
}
#line 42 "imap/jmap_mail_submission_props.gperf"


static const jmap_prop_hash_table_t jmap_submission_props_map = {
    submission_prop_array,
    SUBMISSION_PROP_TOTAL_KEYWORDS,
    SUBMISSION_PROP_MIN_HASH_VALUE,
    SUBMISSION_PROP_MAX_HASH_VALUE,
    &submission_prop_lookup
};

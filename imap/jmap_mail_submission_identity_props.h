/* ANSI-C code produced by gperf version 3.2.1 */
/* Command-line: gperf imap/jmap_mail_submission_identity_props.gperf  */
/* Computed positions: -k'2,5' */

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

#line 1 "imap/jmap_mail_submission_identity_props.gperf"

/* jmap_mail_submission_identity_props.h --
   Lookup functions for JMAP Email Submission Identity properties */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

enum
  {
    IDENTITY_PROP_TOTAL_KEYWORDS = 22,
    IDENTITY_PROP_MIN_WORD_LENGTH = 2,
    IDENTITY_PROP_MAX_WORD_LENGTH = 19,
    IDENTITY_PROP_MIN_HASH_VALUE = 2,
    IDENTITY_PROP_MAX_HASH_VALUE = 28
  };

/* maximum key range = 27, duplicates = 0 */

#ifdef __GNUC__
__inline
#else
#ifdef __cplusplus
inline
#endif
#endif
static unsigned int
identity_prop_hash (register const char *str, register size_t len)
{
  static const unsigned char asso_values[] =
    {
      29, 29, 29, 29, 29, 29, 29, 29, 29, 29,
      29, 29, 29, 29, 29, 29, 29, 29, 29, 29,
      29, 29, 29, 29, 29, 29, 29, 29, 29, 29,
      29, 29, 29, 29, 29, 29, 29, 29, 29, 29,
      29, 29, 29, 29, 29, 29, 29, 29, 29, 29,
      29, 29, 29, 29, 29, 29, 29, 29, 29, 29,
      29, 29, 29, 29, 29, 29, 29, 29, 29, 29,
      29, 29, 29, 29, 29, 29, 29, 29, 29, 10,
      15, 29,  5,  0, 29,  0, 29, 29, 29, 29,
      29, 29, 29, 29, 29, 29, 29,  0, 29,  0,
       0,  5, 29, 29, 29,  0, 29, 29,  0,  0,
      10,  0, 29, 29, 29,  0,  0, 29, 29, 29,
      29,  5, 29, 29, 29, 29, 29, 29, 29, 29,
      29, 29, 29, 29, 29, 29, 29, 29, 29, 29,
      29, 29, 29, 29, 29, 29, 29, 29, 29, 29,
      29, 29, 29, 29, 29, 29, 29, 29, 29, 29,
      29, 29, 29, 29, 29, 29, 29, 29, 29, 29,
      29, 29, 29, 29, 29, 29, 29, 29, 29, 29,
      29, 29, 29, 29, 29, 29, 29, 29, 29, 29,
      29, 29, 29, 29, 29, 29, 29, 29, 29, 29,
      29, 29, 29, 29, 29, 29, 29, 29, 29, 29,
      29, 29, 29, 29, 29, 29, 29, 29, 29, 29,
      29, 29, 29, 29, 29, 29, 29, 29, 29, 29,
      29, 29, 29, 29, 29, 29, 29, 29, 29, 29,
      29, 29, 29, 29, 29, 29, 29, 29, 29, 29,
      29, 29, 29, 29, 29, 29
    };
  register unsigned int hval = len;

  switch (hval)
    {
      default:
        hval += asso_values[(unsigned char)str[4]];
#if (defined __cplusplus && (__cplusplus >= 201703L || (__cplusplus >= 201103L && defined __clang__ && __clang_major__ + (__clang_minor__ >= 9) > 3))) || (defined __STDC_VERSION__ && __STDC_VERSION__ >= 202000L && ((defined __GNUC__ && __GNUC__ >= 10) || (defined __clang__ && __clang_major__ >= 9)))
      [[fallthrough]];
#elif (defined __GNUC__ && __GNUC__ >= 7) || (defined __clang__ && __clang_major__ >= 10)
      __attribute__ ((__fallthrough__));
#endif
      /*FALLTHROUGH*/
      case 4:
      case 3:
      case 2:
        hval += asso_values[(unsigned char)str[1]];
        break;
    }
  return hval;
}

static const unsigned char identity_prop_lengths[] =
  {
     0,  0,  2,  3,  4,  5,  0,  7,  8,  9, 10, 11, 12, 13,
     9, 15, 16,  7, 13, 19, 10,  0, 17,  8,  0,  0,  0, 12,
    18
  };

static const jmap_property_t identity_prop_array[] =
  {
    {(char*)0,NULL,0}, {(char*)0,NULL,0},
#line 28 "imap/jmap_mail_submission_identity_props.gperf"
    {"id",            NULL, JMAP_PROP_SERVER_SET | JMAP_PROP_IMMUTABLE | JMAP_PROP_ALWAYS_GET},
#line 32 "imap/jmap_mail_submission_identity_props.gperf"
    {"bcc",           NULL, 0},
#line 29 "imap/jmap_mail_submission_identity_props.gperf"
    {"name",          NULL, 0},
#line 30 "imap/jmap_mail_submission_identity_props.gperf"
    {"email",         NULL, JMAP_PROP_IMMUTABLE},
    {(char*)0,NULL,0},
#line 47 "imap/jmap_mail_submission_identity_props.gperf"
    {"smtpSSL",             JMAP_MAIL_EXTENSION, 0},
#line 48 "imap/jmap_mail_submission_identity_props.gperf"
    {"smtpUser",            JMAP_MAIL_EXTENSION, 0},
#line 51 "imap/jmap_mail_submission_identity_props.gperf"
    {"popLinkId",           JMAP_MAIL_EXTENSION, 0},
#line 45 "imap/jmap_mail_submission_identity_props.gperf"
    {"smtpServer",          JMAP_MAIL_EXTENSION, 0},
#line 38 "imap/jmap_mail_submission_identity_props.gperf"
    {"displayName",         JMAP_MAIL_EXTENSION, 0},
#line 39 "imap/jmap_mail_submission_identity_props.gperf"
    {"addBccOnSMTP",        JMAP_MAIL_EXTENSION, 0},
#line 34 "imap/jmap_mail_submission_identity_props.gperf"
    {"htmlSignature", NULL, 0},
#line 35 "imap/jmap_mail_submission_identity_props.gperf"
    {"mayDelete",     NULL, JMAP_PROP_SERVER_SET},
#line 42 "imap/jmap_mail_submission_identity_props.gperf"
    {"useForAutoReply",     JMAP_MAIL_EXTENSION, 0},
#line 43 "imap/jmap_mail_submission_identity_props.gperf"
    {"isAutoConfigured",    JMAP_MAIL_EXTENSION, 0},
#line 31 "imap/jmap_mail_submission_identity_props.gperf"
    {"replyTo",       NULL, 0},
#line 33 "imap/jmap_mail_submission_identity_props.gperf"
    {"textSignature", NULL, 0},
#line 40 "imap/jmap_mail_submission_identity_props.gperf"
    {"saveSentToMailboxId", JMAP_MAIL_EXTENSION, 0},
#line 41 "imap/jmap_mail_submission_identity_props.gperf"
    {"saveOnSMTP",          JMAP_MAIL_EXTENSION, 0},
    {(char*)0,NULL,0},
#line 50 "imap/jmap_mail_submission_identity_props.gperf"
    {"smtpRemoteService",   JMAP_MAIL_EXTENSION, 0},
#line 46 "imap/jmap_mail_submission_identity_props.gperf"
    {"smtpPort",            JMAP_MAIL_EXTENSION, 0},
    {(char*)0,NULL,0}, {(char*)0,NULL,0}, {(char*)0,NULL,0},
#line 49 "imap/jmap_mail_submission_identity_props.gperf"
    {"smtpPassword",        JMAP_MAIL_EXTENSION, 0},
#line 44 "imap/jmap_mail_submission_identity_props.gperf"
    {"enableExternalSMTP",  JMAP_MAIL_EXTENSION, 0}
  };

const jmap_property_t *
identity_prop_lookup (register const char *str, register size_t len)
{
  if (len <= IDENTITY_PROP_MAX_WORD_LENGTH && len >= IDENTITY_PROP_MIN_WORD_LENGTH)
    {
      register unsigned int key = identity_prop_hash (str, len);

      if (key <= IDENTITY_PROP_MAX_HASH_VALUE)
        if (len == identity_prop_lengths[key])
          {
            register const char *s = identity_prop_array[key].name;

            if (s && *str == *s && !memcmp (str + 1, s + 1, len - 1))
              return &identity_prop_array[key];
          }
    }
  return (jmap_property_t *) 0;
}
#line 52 "imap/jmap_mail_submission_identity_props.gperf"


static const jmap_prop_hash_table_t jmap_identity_props_map = {
    identity_prop_array,
    IDENTITY_PROP_TOTAL_KEYWORDS,
    IDENTITY_PROP_MIN_HASH_VALUE,
    IDENTITY_PROP_MAX_HASH_VALUE,
    &identity_prop_lookup
};

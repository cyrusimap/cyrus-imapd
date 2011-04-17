/* Test the getxstring() function */
#include "config.h"
#include "cunit/cunit.h"
#include "xmalloc.h"
#include "prot.h"
#include "global.h"

/*
 * Here's the ABNF describing the various types of string from RF3501.
 * This is included for amusement mainly, as the getxstring() code takes
 * many liberties with it, being at times more liberal and at times more
 * conservative than the strict interpretation of the ABNF.  As these
 * behaviours have been in the field a long time and clients may well
 * depend on them, we test for the existing behaviour rather than strict
 * RFC compliance.
 *
 * astring         = 1*ASTRING-CHAR / string
 *
 * ASTRING-CHAR   = ATOM-CHAR / resp-specials
 *
 * ATOM-CHAR       = <any CHAR except atom-specials>
 *
 * atom-specials   = "(" / ")" / "{" / SP / CTL / list-wildcards /
 *                   quoted-specials / resp-specials
 *
 * string          = quoted / literal
 *
 * list-wildcards  = "%" / "*"
 *
 * literal         = "{" number "}" CRLF *CHAR8
 *                     ; Number represents the number of CHAR8s
 *
 * nil             = "NIL"
 *
 * nstring         = string / nil
 *
 * quoted          = DQUOTE *QUOTED-CHAR DQUOTE
 *
 * QUOTED-CHAR     = <any TEXT-CHAR except quoted-specials> /
 *                   "\" quoted-specials
 *
 * quoted-specials = DQUOTE / "\"
 *
 * resp-specials   = "]"
 *
 * string          = quoted / literal
 */

/*
 * Run a single testcase.
 *
 * Note: prot_setisclient() turns off off literal synchronising so
 * we don't have to futz around with testing that.
 */
#define _TESTCASE_PRE(fut, input, retval) \
    do { \
	struct buf b = BUF_INITIALIZER; \
	struct protstream *p; \
	int c; \
	p = prot_readmap(input, sizeof(input)-1); \
	CU_ASSERT_PTR_NOT_NULL(p); \
	prot_setisclient(p, 1); \
	c = fut(p, NULL, &b); \
	CU_ASSERT_EQUAL(c, retval); \
	if (c != EOF) {
#define _TESTCASE_POST() \
	} \
	prot_free(p); \
	buf_free(&b); \
    } while (0)
#define TESTCASE(fut, input, retval, output) \
    do { \
	int outputlen = sizeof(output)-1; \
	_TESTCASE_PRE(fut, input, retval); \
	CU_ASSERT_EQUAL(b.len, outputlen); \
	CU_ASSERT(!memcmp(b.s, output, outputlen)); \
	_TESTCASE_POST(); \
    } while(0)
#define TESTCASE_NULL(fut, input, retval) \
    do { \
	_TESTCASE_PRE(fut, input, retval); \
	CU_ASSERT_EQUAL(b.len, 0); \
	CU_ASSERT_PTR_NULL(b.s); \
	_TESTCASE_POST(); \
    } while(0)

/*
 * getastring() parses something vaguely like an astring, with a few differences.
 */
static void test_getastring(void)
{
    /* Simple sequences of ascii alphanumerics characters are atoms */
    TESTCASE(getastring, "hydrogen helium", ' ', "hydrogen");
    TESTCASE(getastring, "258 uranium", ' ', "258");
    TESTCASE(getastring, "uranium258 plutonium", ' ', "uranium258");

    /* The character sequence NIL is not special, it's parsed as an atom */
    TESTCASE(getastring, "NIL by mouth", ' ', "NIL");
    TESTCASE(getastring, "NELLY the lamb", ' ', "NELLY");

    /*
     * List wildcards aren't part of an atom, but Cyrus accepts them
     * in order to implement the "mailbox" and "list-mailbox" rules,
     * which are like astrings but also allow unquoted wildcards,
     * as astrings.
     */
    TESTCASE(getastring, "foo*bar baz", ' ', "foo*bar");
    TESTCASE(getastring, "baz%quux foo", ' ', "baz%quux");

    /*
     * Various special characters are not part of atoms.
     *
     * Again the server code is very liberal in accepting all kinds of
     * things which aren't in the ABNF, so we test for the liberal
     * interpretation and note the conservative one in a comment.
     */
    TESTCASE(getastring, "foo(bar baz", '(', "foo");
    TESTCASE(getastring, "foo)bar baz", ')', "foo");
    TESTCASE(getastring, "foo{bar baz", ' ', "foo{bar"); /* should be: '{', "foo" */
    TESTCASE(getastring, "foo\"bar baz", '"', "foo");
    TESTCASE(getastring, "foo\\bar baz", ' ', "foo\\bar"); /* should be: '\\', "foo" */
    TESTCASE(getastring, "foo]bar baz", ' ', "foo]bar"); /* should be ']', "foo" */

    /*
     * Quoted strings are astrings
     */
    TESTCASE(getastring, "\"foo\" bar", ' ', "foo");
    TESTCASE(getastring, "\"foo bar\" baz", ' ', "foo bar");
    TESTCASE(getastring, "\"foo bar", EOF, "");
    TESTCASE(getastring, "\"foo\\\"bar\" baz", ' ', "foo\"bar");
    TESTCASE(getastring, "\"foo\\\\bar\" baz", ' ', "foo\\bar");
    /* Any non-special char can be escaped with \ */
    TESTCASE(getastring, "\"foo\\bar\" baz", ' ', "foobar");
    /* \n and \r can be escaped with \ */
    TESTCASE(getastring, "\"foo\\\nbar\" baz", ' ', "foo\nbar");
    TESTCASE(getastring, "\"foo\\\rbar\" baz", ' ', "foo\rbar");
    /* Non-escaped \n and \r.  The server is actually more
     * conversative than the ABNF and rejects these. */
    TESTCASE(getastring, "\"foo\nbar\" baz", EOF, ""); /* should be ' ', "foo\nbar" */
    TESTCASE(getastring, "\"foo\rbar\" baz", EOF, ""); /* should be ' ', "foo\rbar" */

    /*
     * Literals are astrings
     */
    /* boring literal */
    TESTCASE(getastring, "{3}\r\nfoo ", ' ', "foo");
    /* literals with embedded space */
    TESTCASE(getastring, "{7}\r\nfoo bar ", ' ', "foo bar");
    /* literals with embedded \n or \r */
    TESTCASE(getastring, "{7}\r\nfoo\nbar ", ' ', "foo\nbar");
    TESTCASE(getastring, "{7}\r\nfoo\rbar ", ' ', "foo\rbar");
    /* literals with 8-bit chars */
    TESTCASE(getastring, "{7}\r\nfoo\277bar ", ' ', "foo\277bar");
    /* literals with embedded NUL - getastring() rejects these */
    TESTCASE(getastring, "{7}\r\nfoo\0bar ", EOF, ""); /* should be ' ', "foo\0bar" */
}

/*
 * getbastring() is just the same as getastring() but allows embedded
 * NULs in literals.
 */
static void test_getbastring(void)
{
    /* Simple sequences of ascii alphanumerics characters are atoms */
    TESTCASE(getbastring, "hydrogen helium", ' ', "hydrogen");
    TESTCASE(getbastring, "258 uranium", ' ', "258");
    TESTCASE(getbastring, "uranium258 plutonium", ' ', "uranium258");

    /* The character sequence NIL is not special, it's parsed as an atom */
    TESTCASE(getbastring, "NIL by mouth", ' ', "NIL");
    TESTCASE(getbastring, "NELLY the lamb", ' ', "NELLY");

    /*
     * List wildcards aren't part of an atom, but Cyrus accepts them
     * in order to implement the "mailbox" and "list-mailbox" rules,
     * which are like astrings but also allow unquoted wildcards,
     * as astrings.  This is probably sheer laziness on Cyrus' part
     * but it's a liberal-server interpretation which has been in the
     * field a while now, so we ought to preserve it.
     */
    TESTCASE(getbastring, "foo*bar baz", ' ', "foo*bar");
    TESTCASE(getbastring, "baz%quux foo", ' ', "baz%quux");

    /*
     * Various special characters are not part of atoms.
     *
     * Again the server code is very liberal in accepting all kinds of
     * things which aren't in the ABNF, so we test for the liberal
     * interpretation and note the conservative one in a comment.
     */
    TESTCASE(getbastring, "foo(bar baz", '(', "foo");
    TESTCASE(getbastring, "foo)bar baz", ')', "foo");
    TESTCASE(getbastring, "foo{bar baz", ' ', "foo{bar"); /* should be: '{', "foo" */
    TESTCASE(getbastring, "foo\"bar baz", '"', "foo");
    TESTCASE(getbastring, "foo\\bar baz", ' ', "foo\\bar"); /* should be: '\\', "foo" */
    TESTCASE(getbastring, "foo]bar baz", ' ', "foo]bar"); /* should be ']', "foo" */

    /*
     * Quoted strings are astrings
     */
    TESTCASE(getbastring, "\"foo\" bar", ' ', "foo");
    TESTCASE(getbastring, "\"foo bar\" baz", ' ', "foo bar");
    TESTCASE(getbastring, "\"foo bar", EOF, "");
    TESTCASE(getbastring, "\"foo\\\"bar\" baz", ' ', "foo\"bar");
    TESTCASE(getbastring, "\"foo\\\\bar\" baz", ' ', "foo\\bar");
    /* Any non-special char can be escaped with \ */
    TESTCASE(getbastring, "\"foo\\bar\" baz", ' ', "foobar");
    /* \n and \r can be escaped with \ */
    TESTCASE(getbastring, "\"foo\\\nbar\" baz", ' ', "foo\nbar");
    TESTCASE(getbastring, "\"foo\\\rbar\" baz", ' ', "foo\rbar");
    /* Non-escaped \n and \r.  The server is actually more
     * conversative than the ABNF and rejects these. */
    TESTCASE(getbastring, "\"foo\nbar\" baz", EOF, ""); /* should be ' ', "foo\nbar" */
    TESTCASE(getbastring, "\"foo\rbar\" baz", EOF, ""); /* should be ' ', "foo\rbar" */

    /*
     * Literals are astrings
     */
    /* boring literal */
    TESTCASE(getbastring, "{3}\r\nfoo ", ' ', "foo");
    /* literals with embedded space */
    TESTCASE(getbastring, "{7}\r\nfoo bar ", ' ', "foo bar");
    /* literals with embedded \n or \r */
    TESTCASE(getbastring, "{7}\r\nfoo\nbar ", ' ', "foo\nbar");
    TESTCASE(getbastring, "{7}\r\nfoo\rbar ", ' ', "foo\rbar");
    /* literals with 8-bit chars */
    TESTCASE(getbastring, "{7}\r\nfoo\277bar ", ' ', "foo\277bar");
    /* literals with embedded NUL - getbastring() allows these */
    TESTCASE(getbastring, "{7}\r\nfoo\0bar ", ' ', "foo\0bar");
}

/*
 * getstring() parses something very like a 'string' in the ABNF.
 */
static void test_getstring(void)
{
    /* Simple sequences of ascii alphanumerics characters are atoms
     * which are not strings */
    TESTCASE(getstring, "hydrogen helium", EOF, "");
    TESTCASE(getstring, "258 uranium", EOF, "");
    TESTCASE(getstring, "uranium258 plutonium", EOF, "");

    /* The character sequence NIL is not special, it's parsed as an atom */
    TESTCASE(getstring, "NIL by mouth", EOF, "");
    TESTCASE(getstring, "NELLY the lamb", EOF, "");

    /*
     * List wildcards aren't part of an atom, but Cyrus accepts them
     * in order to implement the "mailbox" and "list-mailbox" rules,
     * which are like astrings but also allow unquoted wildcards,
     * as astrings.  This is probably sheer laziness on Cyrus' part
     * but it's a liberal-server interpretation which has been in the
     * field a while now, so we ought to preserve it.
     */
    TESTCASE(getstring, "foo*bar baz", EOF, "");
    TESTCASE(getstring, "baz%quux foo", EOF, "");

    /*
     * Various special characters are not part of atoms.
     *
     * Again the server code is very liberal in accepting all kinds of
     * things which aren't in the ABNF, so we test for the liberal
     * interpretation and note the conservative one in a comment.
     */
    TESTCASE(getstring, "foo(bar baz", EOF, "");
    TESTCASE(getstring, "foo)bar baz", EOF, "");
    TESTCASE(getstring, "foo{bar baz", EOF, "");
    TESTCASE(getstring, "foo\"bar baz", EOF, "");
    TESTCASE(getstring, "foo\\bar baz", EOF, "");
    TESTCASE(getstring, "foo]bar baz", EOF, "");

    /*
     * Quoted strings are strings
     */
    TESTCASE(getstring, "\"foo\" bar", ' ', "foo");
    TESTCASE(getstring, "\"foo bar\" baz", ' ', "foo bar");
    TESTCASE(getstring, "\"foo bar", EOF, "");
    TESTCASE(getstring, "\"foo\\\"bar\" baz", ' ', "foo\"bar");
    TESTCASE(getstring, "\"foo\\\\bar\" baz", ' ', "foo\\bar");
    /* Any non-special char can be escaped with \ */
    TESTCASE(getstring, "\"foo\\bar\" baz", ' ', "foobar");
    /* \n and \r can be escaped with \ */
    TESTCASE(getstring, "\"foo\\\nbar\" baz", ' ', "foo\nbar");
    TESTCASE(getstring, "\"foo\\\rbar\" baz", ' ', "foo\rbar");
    /* Non-escaped \n and \r.  The server is actually more
     * conversative than the ABNF and rejects these. */
    TESTCASE(getstring, "\"foo\nbar\" baz", EOF, ""); /* should be ' ', "foo\nbar" */
    TESTCASE(getstring, "\"foo\rbar\" baz", EOF, ""); /* should be ' ', "foo\rbar" */

    /*
     * Literals are strings
     */
    /* boring literal */
    TESTCASE(getstring, "{3}\r\nfoo ", ' ', "foo");
    /* literals with embedded space */
    TESTCASE(getstring, "{7}\r\nfoo bar ", ' ', "foo bar");
    /* literals with embedded \n or \r */
    TESTCASE(getstring, "{7}\r\nfoo\nbar ", ' ', "foo\nbar");
    TESTCASE(getstring, "{7}\r\nfoo\rbar ", ' ', "foo\rbar");
    /* literals with 8-bit chars */
    TESTCASE(getstring, "{7}\r\nfoo\277bar ", ' ', "foo\277bar");
    /* literals with embedded NUL - getstring() rejects these */
    TESTCASE(getqstring, "{7}\r\nfoo\0bar ", EOF, ""); /* should be ' ', "foo\0bar" */
}


/*
 * getqstring() accepts something very like the qstring in the ABNF.
 * Atoms, NIL and literals all fail.
 */
static void test_getqstring(void)
{
    /* Simple sequences of ascii alphanumerics characters are atoms
     * which are not qstrings */
    TESTCASE(getqstring, "hydrogen helium", EOF, "");
    TESTCASE(getqstring, "258 uranium", EOF, "");
    TESTCASE(getqstring, "uranium258 plutonium", EOF, "");

    /* The character sequence NIL is not special, it's parsed as an atom */
    TESTCASE(getqstring, "NIL by mouth", EOF, "");
    TESTCASE(getqstring, "NELLY the lamb", EOF, "");

    /*
     * List wildcards aren't part of an atom, but Cyrus accepts them
     * in order to implement the "mailbox" and "list-mailbox" rules,
     * which are like astrings but also allow unquoted wildcards,
     * as astrings.  This is probably sheer laziness on Cyrus' part
     * but it's a liberal-server interpretation which has been in the
     * field a while now, so we ought to preserve it.
     */
    TESTCASE(getqstring, "foo*bar baz", EOF, "");
    TESTCASE(getqstring, "baz%quux foo", EOF, "");

    /*
     * Various special characters are not part of atoms.
     *
     * Again the server code is very liberal in accepting all kinds of
     * things which aren't in the ABNF, so we test for the liberal
     * interpretation and note the conservative one in a comment.
     */
    TESTCASE(getqstring, "foo(bar baz", EOF, "");
    TESTCASE(getqstring, "foo)bar baz", EOF, "");
    TESTCASE(getqstring, "foo{bar baz", EOF, "");
    TESTCASE(getqstring, "foo\"bar baz", EOF, "");
    TESTCASE(getqstring, "foo\\bar baz", EOF, "");
    TESTCASE(getqstring, "foo]bar baz", EOF, "");

    /*
     * Quoted strings
     */
    TESTCASE(getqstring, "\"foo\" bar", ' ', "foo");
    TESTCASE(getqstring, "\"foo bar\" baz", ' ', "foo bar");
    TESTCASE(getqstring, "\"foo bar", EOF, "");
    TESTCASE(getqstring, "\"foo\\\"bar\" baz", ' ', "foo\"bar");
    TESTCASE(getqstring, "\"foo\\\\bar\" baz", ' ', "foo\\bar");
    /* Any non-special char can be escaped with \ */
    TESTCASE(getqstring, "\"foo\\bar\" baz", ' ', "foobar");
    /* \n and \r can be escaped with \ */
    TESTCASE(getqstring, "\"foo\\\nbar\" baz", ' ', "foo\nbar");
    TESTCASE(getqstring, "\"foo\\\rbar\" baz", ' ', "foo\rbar");
    /* Non-escaped \n and \r.  The server is actually more
     * conversative than the ABNF and rejects these. */
    TESTCASE(getqstring, "\"foo\nbar\" baz", EOF, ""); /* should be ' ', "foo\nbar" */
    TESTCASE(getqstring, "\"foo\rbar\" baz", EOF, ""); /* should be ' ', "foo\rbar" */

    /*
     * Literals are not qstrings
     */
    /* boring literal */
    TESTCASE(getqstring, "{3}\r\nfoo ", EOF, "");
    /* literals with embedded space */
    TESTCASE(getqstring, "{7}\r\nfoo bar ", EOF, "");
    /* literals with embedded \n or \r */
    TESTCASE(getqstring, "{7}\r\nfoo\nbar ", EOF, "");
    TESTCASE(getqstring, "{7}\r\nfoo\rbar ", EOF, "");
    /* literals with 8-bit chars */
    TESTCASE(getqstring, "{7}\r\nfoo\277bar ", EOF, "");
    /* literals with embedded NUL */
    TESTCASE(getqstring, "{7}\r\nfoo\0bar ", EOF, "");
}

/*
 * getnstring() parses something vaguely like an nstring, with a few differences.
 */
static void test_getnstring(void)
{
    /* Simple sequences of ascii alphanumerics characters are atoms */
    TESTCASE(getnstring, "hydrogen helium", EOF, "");
    TESTCASE(getnstring, "258 uranium", EOF, "");
    TESTCASE(getnstring, "uranium258 plutonium", EOF, "");

    /* The character sequence NIL is special for nstrings only */
    TESTCASE_NULL(getnstring, "NIL by mouth", ' ');
    TESTCASE(getnstring, "NELLY ", EOF, "");

    /*
     * List wildcards aren't part of an atom, but Cyrus accepts them
     * in order to implement the "mailbox" and "list-mailbox" rules,
     * which are like astrings but also allow unquoted wildcards,
     * as astrings.
     */
    TESTCASE(getnstring, "foo*bar baz", EOF, "");
    TESTCASE(getnstring, "baz%quux foo", EOF, "");

    /*
     * Various special characters are not part of atoms.
     *
     * Again the server code is very liberal in accepting all kinds of
     * things which aren't in the ABNF, so we test for the liberal
     * interpretation and note the conservative one in a comment.
     */
    TESTCASE(getnstring, "foo(bar baz", EOF, "");
    TESTCASE(getnstring, "foo)bar baz", EOF, "");
    TESTCASE(getnstring, "foo{bar baz", EOF, "");
    TESTCASE(getnstring, "foo\"bar baz", EOF, "");
    TESTCASE(getnstring, "foo\\bar baz", EOF, "");
    TESTCASE(getnstring, "foo]bar baz", EOF, "");

    /*
     * Quoted strings are nstrings
     */
    TESTCASE(getnstring, "\"foo\" bar", ' ', "foo");
    TESTCASE(getnstring, "\"foo bar\" baz", ' ', "foo bar");
    TESTCASE(getnstring, "\"foo bar", EOF, "");
    TESTCASE(getnstring, "\"foo\\\"bar\" baz", ' ', "foo\"bar");
    TESTCASE(getnstring, "\"foo\\\\bar\" baz", ' ', "foo\\bar");
    /* Any non-special char can be escaped with \ */
    TESTCASE(getnstring, "\"foo\\bar\" baz", ' ', "foobar");
    /* \n and \r can be escaped with \ */
    TESTCASE(getnstring, "\"foo\\\nbar\" baz", ' ', "foo\nbar");
    TESTCASE(getnstring, "\"foo\\\rbar\" baz", ' ', "foo\rbar");
    /* Non-escaped \n and \r.  The server is actually more
     * conversative than the ABNF and rejects these. */
    TESTCASE(getnstring, "\"foo\nbar\" baz", EOF, ""); /* should be ' ', "foo\nbar" */
    TESTCASE(getnstring, "\"foo\rbar\" baz", EOF, ""); /* should be ' ', "foo\rbar" */

    /*
     * Literals are nstrings
     */
    /* boring literal */
    TESTCASE(getnstring, "{3}\r\nfoo ", ' ', "foo");
    /* literals with embedded space */
    TESTCASE(getnstring, "{7}\r\nfoo bar ", ' ', "foo bar");
    /* literals with embedded \n or \r */
    TESTCASE(getnstring, "{7}\r\nfoo\nbar ", ' ', "foo\nbar");
    TESTCASE(getnstring, "{7}\r\nfoo\rbar ", ' ', "foo\rbar");
    /* literals with 8-bit chars */
    TESTCASE(getnstring, "{7}\r\nfoo\277bar ", ' ', "foo\277bar");
    /* literals with embedded NUL - getnstring() rejects these */
    TESTCASE(getnstring, "{7}\r\nfoo\0bar ", EOF, ""); /* should be ' ', "foo\0bar" */
}

/*
 * getbnstring() is just like getnstring() but allows embedded NULs in
 * literals.
 */
static void test_getbnstring(void)
{
    /* Simple sequences of ascii alphanumerics characters are atoms */
    TESTCASE(getbnstring, "hydrogen helium", EOF, "");
    TESTCASE(getbnstring, "258 uranium", EOF, "");
    TESTCASE(getbnstring, "uranium258 plutonium", EOF, "");

    /* The character sequence NIL is special for nstrings only */
    TESTCASE_NULL(getbnstring, "NIL by mouth", ' ');
    TESTCASE(getbnstring, "NELLY ", EOF, "");

    /*
     * List wildcards aren't part of an atom, but Cyrus accepts them
     * in order to implement the "mailbox" and "list-mailbox" rules,
     * which are like astrings but also allow unquoted wildcards,
     * as astrings.
     */
    TESTCASE(getnstring, "foo*bar baz", EOF, "");
    TESTCASE(getbnstring, "baz%quux foo", EOF, "");

    /*
     * Various special characters are not part of atoms.
     *
     * Again the server code is very liberal in accepting all kinds of
     * things which aren't in the ABNF, so we test for the liberal
     * interpretation and note the conservative one in a comment.
     */
    TESTCASE(getbnstring, "foo(bar baz", EOF, "");
    TESTCASE(getbnstring, "foo)bar baz", EOF, "");
    TESTCASE(getbnstring, "foo{bar baz", EOF, "");
    TESTCASE(getbnstring, "foo\"bar baz", EOF, "");
    TESTCASE(getbnstring, "foo\\bar baz", EOF, "");
    TESTCASE(getbnstring, "foo]bar baz", EOF, "");

    /*
     * Quoted strings are nstrings
     */
    TESTCASE(getbnstring, "\"foo\" bar", ' ', "foo");
    TESTCASE(getbnstring, "\"foo bar\" baz", ' ', "foo bar");
    TESTCASE(getbnstring, "\"foo bar", EOF, "");
    TESTCASE(getbnstring, "\"foo\\\"bar\" baz", ' ', "foo\"bar");
    TESTCASE(getbnstring, "\"foo\\\\bar\" baz", ' ', "foo\\bar");
    /* Any non-special char can be escaped with \ */
    TESTCASE(getbnstring, "\"foo\\bar\" baz", ' ', "foobar");
    /* \n and \r can be escaped with \ */
    TESTCASE(getbnstring, "\"foo\\\nbar\" baz", ' ', "foo\nbar");
    TESTCASE(getbnstring, "\"foo\\\rbar\" baz", ' ', "foo\rbar");
    /* Non-escaped \n and \r.  The server is actually more
     * conversative than the ABNF and rejects these. */
    TESTCASE(getbnstring, "\"foo\nbar\" baz", EOF, ""); /* should be ' ', "foo\nbar" */
    TESTCASE(getbnstring, "\"foo\rbar\" baz", EOF, ""); /* should be ' ', "foo\rbar" */

    /*
     * Literals are nstrings
     */
    /* boring literal */
    TESTCASE(getbnstring, "{3}\r\nfoo ", ' ', "foo");
    /* literals with embedded space */
    TESTCASE(getbnstring, "{7}\r\nfoo bar ", ' ', "foo bar");
    /* literals with embedded \n or \r */
    TESTCASE(getbnstring, "{7}\r\nfoo\nbar ", ' ', "foo\nbar");
    TESTCASE(getbnstring, "{7}\r\nfoo\rbar ", ' ', "foo\rbar");
    /* literals with 8-bit chars */
    TESTCASE(getbnstring, "{7}\r\nfoo\277bar ", ' ', "foo\277bar");
    /* literals with embedded NUL - getbnstring() allows these */
    TESTCASE(getbnstring, "{7}\r\nfoo\0bar ", ' ', "foo\0bar");
}


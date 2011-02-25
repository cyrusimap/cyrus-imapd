#include <malloc.h>
#include "cunit/cunit.h"
#include "parseaddr.h"

static void test_single(void)
{
    struct address *a;

    a = NULL;
    parseaddr_list("Fred Bloggs <fbloggs@fastmail.fm>", &a);
    CU_ASSERT_PTR_NOT_NULL_FATAL(a);
    CU_ASSERT_STRING_EQUAL(a->name, "Fred Bloggs");
    CU_ASSERT_STRING_EQUAL(a->mailbox, "fbloggs");
    CU_ASSERT_STRING_EQUAL(a->domain, "fastmail.fm");
    CU_ASSERT_PTR_NULL(a->next);

    parseaddr_free(a);
}

static void test_single_append(void)
{
    struct address *a;
    struct address *origa;

    a = NULL;
    parseaddr_list("Fred Bloggs <fbloggs@fastmail.fm>", &a);
    CU_ASSERT_PTR_NOT_NULL_FATAL(a);
    CU_ASSERT_STRING_EQUAL(a->name, "Fred Bloggs");
    CU_ASSERT_STRING_EQUAL(a->mailbox, "fbloggs");
    CU_ASSERT_STRING_EQUAL(a->domain, "fastmail.fm");
    CU_ASSERT_PTR_NULL(a->next);
    origa = a;

    parseaddr_list("Sarah Jane Smith <sjsmith@gmail.com>", &a);
    CU_ASSERT_PTR_EQUAL_FATAL(a, origa);
    CU_ASSERT_STRING_EQUAL(a->name, "Fred Bloggs");
    CU_ASSERT_STRING_EQUAL(a->mailbox, "fbloggs");
    CU_ASSERT_STRING_EQUAL(a->domain, "fastmail.fm");
    CU_ASSERT_PTR_NOT_NULL_FATAL(a->next);
    CU_ASSERT_STRING_EQUAL(a->next->name, "Sarah Jane Smith");
    CU_ASSERT_STRING_EQUAL(a->next->mailbox, "sjsmith");
    CU_ASSERT_STRING_EQUAL(a->next->domain, "gmail.com");
    CU_ASSERT_PTR_NULL(a->next->next);

    parseaddr_free(a);
}

static void test_multiple(void)
{
    struct address *a;

    a = NULL;
    parseaddr_list("Fred Bloggs <fbloggs@fastmail.fm>, Sarah Jane Smith <sjsmith@gmail.com>", &a);
    CU_ASSERT_PTR_NOT_NULL_FATAL(a);
    CU_ASSERT_STRING_EQUAL(a->name, "Fred Bloggs");
    CU_ASSERT_STRING_EQUAL(a->mailbox, "fbloggs");
    CU_ASSERT_STRING_EQUAL(a->domain, "fastmail.fm");
    CU_ASSERT_PTR_NOT_NULL_FATAL(a->next);
    CU_ASSERT_STRING_EQUAL(a->next->name, "Sarah Jane Smith");
    CU_ASSERT_STRING_EQUAL(a->next->mailbox, "sjsmith");
    CU_ASSERT_STRING_EQUAL(a->next->domain, "gmail.com");
    CU_ASSERT_PTR_NULL(a->next->next);

    parseaddr_free(a);
}

static void test_quoted_name(void)
{
    struct address *a;

    a = NULL;
    parseaddr_list("\"Fred Bloggs\" <fbloggs@fastmail.fm>", &a);
    CU_ASSERT_PTR_NOT_NULL_FATAL(a);
    CU_ASSERT_STRING_EQUAL(a->name, "Fred Bloggs");
    CU_ASSERT_STRING_EQUAL(a->mailbox, "fbloggs");
    CU_ASSERT_STRING_EQUAL(a->domain, "fastmail.fm");
    CU_ASSERT_PTR_NULL(a->next);

    parseaddr_free(a);
}

static void test_quoted_name_comma(void)
{
    struct address *a;

    a = NULL;
    parseaddr_list("\"Bloggs, Fred\" <fbloggs@fastmail.fm>", &a);
    CU_ASSERT_PTR_NOT_NULL_FATAL(a);
    CU_ASSERT_STRING_EQUAL(a->name, "Bloggs, Fred");
    CU_ASSERT_STRING_EQUAL(a->mailbox, "fbloggs");
    CU_ASSERT_STRING_EQUAL(a->domain, "fastmail.fm");
    CU_ASSERT_PTR_NULL(a->next);

    parseaddr_free(a);
}

static void test_comment_name(void)
{
    struct address *a;

    a = NULL;
    parseaddr_list("fbloggs@fastmail.fm (Fred Bloggs)", &a);
    CU_ASSERT_PTR_NOT_NULL_FATAL(a);
    CU_ASSERT_STRING_EQUAL(a->name, "Fred Bloggs");
    CU_ASSERT_STRING_EQUAL(a->mailbox, "fbloggs");
    CU_ASSERT_STRING_EQUAL(a->domain, "fastmail.fm");
    CU_ASSERT_PTR_NULL(a->next);

    parseaddr_free(a);
}

static void test_quoted_mailbox(void)
{
    struct address *a;

    a = NULL;
    parseaddr_list("Fred Bloggs <\"fred bloggs\"@fastmail.fm>", &a);
    CU_ASSERT_PTR_NOT_NULL_FATAL(a);
    CU_ASSERT_STRING_EQUAL(a->name, "Fred Bloggs");
    CU_ASSERT_STRING_EQUAL(a->mailbox, "fred bloggs");
    CU_ASSERT_STRING_EQUAL(a->domain, "fastmail.fm");
    CU_ASSERT_PTR_NULL(a->next);

    parseaddr_free(a);
}

static void test_mailbox_comment(void)
{
    struct address *a;

    /* This example is from the RFC822 text */
    a = NULL;
    parseaddr_list("Wilt . (the Stilt) Chamberlain@NBA.US", &a);
    CU_ASSERT_PTR_NOT_NULL_FATAL(a);
    CU_ASSERT_PTR_NULL(a->name);
//     CU_ASSERT_STRING_EQUAL(a->mailbox, "Wilt.Chamberlain");
    CU_ASSERT_STRING_EQUAL(a->domain, "NBA.US");
    CU_ASSERT_PTR_NULL(a->next);

    parseaddr_free(a);
}

static void test_domain_literal(void)
{
    struct address *a;

    a = NULL;
    parseaddr_list("Fred Bloggs <fbloggs@[192.168.0.1]>", &a);
    CU_ASSERT_PTR_NOT_NULL_FATAL(a);
    CU_ASSERT_STRING_EQUAL(a->name, "Fred Bloggs");
    CU_ASSERT_STRING_EQUAL(a->mailbox, "fbloggs");
    CU_ASSERT_STRING_EQUAL(a->domain, "[192.168.0.1]");
    CU_ASSERT_PTR_NULL(a->next);

    parseaddr_free(a);
}

static void test_dotted_mailbox(void)
{
    struct address *a;

    a = NULL;
    parseaddr_list("Fred Bloggs <Fred.Bloggs@fastmail.fm>", &a);
    CU_ASSERT_PTR_NOT_NULL_FATAL(a);
    CU_ASSERT_STRING_EQUAL(a->name, "Fred Bloggs");
    CU_ASSERT_STRING_EQUAL(a->mailbox, "Fred.Bloggs");
    CU_ASSERT_STRING_EQUAL(a->domain, "fastmail.fm");
    CU_ASSERT_PTR_NULL(a->next);

    parseaddr_free(a);
}

static void test_long_domain(void)
{
    struct address *a;

    a = NULL;
    parseaddr_list("Fred Bloggs <fbloggs@a.really.quite.surprisingly.long.domain.name.com>", &a);
    CU_ASSERT_PTR_NOT_NULL_FATAL(a);
    CU_ASSERT_STRING_EQUAL(a->name, "Fred Bloggs");
    CU_ASSERT_STRING_EQUAL(a->mailbox, "fbloggs");
    CU_ASSERT_STRING_EQUAL(a->domain, "a.really.quite.surprisingly.long.domain.name.com");
    CU_ASSERT_PTR_NULL(a->next);

    parseaddr_free(a);
}

static void test_group(void)
{
    struct address *a;

    a = NULL;
    parseaddr_list("Buddies: Fred Bloggs <fbloggs@fastmail.fm>, Sarah Jane Smith <sjsmith@gmail.com>;", &a);

    CU_ASSERT_PTR_NOT_NULL_FATAL(a);
    CU_ASSERT_PTR_NULL(a->name);
    CU_ASSERT_STRING_EQUAL(a->mailbox, "Buddies");
    CU_ASSERT_PTR_NULL(a->domain);

    CU_ASSERT_PTR_NOT_NULL_FATAL(a->next);
    CU_ASSERT_STRING_EQUAL(a->next->name, "Fred Bloggs");
    CU_ASSERT_STRING_EQUAL(a->next->mailbox, "fbloggs");
    CU_ASSERT_STRING_EQUAL(a->next->domain, "fastmail.fm");

    CU_ASSERT_PTR_NOT_NULL_FATAL(a->next->next);
    CU_ASSERT_STRING_EQUAL(a->next->next->name, "Sarah Jane Smith");
    CU_ASSERT_STRING_EQUAL(a->next->next->mailbox, "sjsmith");
    CU_ASSERT_STRING_EQUAL(a->next->next->domain, "gmail.com");

    CU_ASSERT_PTR_NOT_NULL_FATAL(a->next->next->next);
    CU_ASSERT_PTR_NULL(a->next->next->next->name);
    CU_ASSERT_PTR_NULL(a->next->next->next->mailbox);
    CU_ASSERT_PTR_NULL(a->next->next->next->domain);

    CU_ASSERT_PTR_NULL(a->next->next->next->next);

    parseaddr_free(a);
}

/* TODO: test the source routing feature */

/* Test the iterator interface */
static void test_iterator(void)
{
    struct address_itr ai;
    const struct address *a;

    address_itr_init(&ai, "");
    a = address_itr_next(&ai);
    CU_ASSERT_PTR_NULL(a);
    address_itr_fini(&ai);

    address_itr_init(&ai, "Fred Bloggs <fbloggs@fastmail.fm>, Sarah Jane Smith <sjsmith@gmail.com>");
    a = address_itr_next(&ai);
    CU_ASSERT_PTR_NOT_NULL_FATAL(a);
    CU_ASSERT_STRING_EQUAL(a->name, "Fred Bloggs");
    CU_ASSERT_STRING_EQUAL(a->mailbox, "fbloggs");
    CU_ASSERT_STRING_EQUAL(a->domain, "fastmail.fm");
    a = address_itr_next(&ai);
    CU_ASSERT_PTR_NOT_NULL_FATAL(a);
    CU_ASSERT_STRING_EQUAL(a->name, "Sarah Jane Smith");
    CU_ASSERT_STRING_EQUAL(a->mailbox, "sjsmith");
    CU_ASSERT_STRING_EQUAL(a->domain, "gmail.com");
    CU_ASSERT_PTR_NULL(a->next);
    address_itr_fini(&ai);
}

static void test_canonicalise(void)
{
    char *addr;

    addr = address_canonicalise("Fred Bloggs <F.Bloggs@FastMAIL.fm>");
    CU_ASSERT_STRING_EQUAL(addr, "F.Bloggs@fastmail.fm");
    free(addr);
}

/*
 * Test getting parts of a fully featured address
 */
static void test_getparts(void)
{
    struct address *a;
    char *s;

    a = NULL;
    parseaddr_list("Fred Bloggs <fbloggs+foo@FastMAIL.fm>", &a);
    CU_ASSERT_PTR_NOT_NULL_FATAL(a);

    s = address_get_all(a, 0);
    CU_ASSERT_STRING_EQUAL(s, "fbloggs+foo@FastMAIL.fm");
    free(s);

    s = address_get_all(a, 1);
    CU_ASSERT_STRING_EQUAL(s, "fbloggs+foo@fastmail.fm");
    free(s);

    s = address_get_localpart(a);
    CU_ASSERT_STRING_EQUAL(s, "fbloggs+foo");
    free(s);

    s = address_get_domain(a, 0);
    CU_ASSERT_STRING_EQUAL(s, "FastMAIL.fm");
    free(s);

    s = address_get_domain(a, 1);
    CU_ASSERT_STRING_EQUAL(s, "fastmail.fm");
    free(s);

    s = address_get_user(a);
    CU_ASSERT_STRING_EQUAL(s, "fbloggs");
    free(s);

    s = address_get_detail(a);
    CU_ASSERT_STRING_EQUAL(s, "foo");
    free(s);

    parseaddr_free(a);
}

/*
 * Test getting parts of an address with no detail part
 */
static void test_getparts_nodetail(void)
{
    struct address *a;
    char *s;

    a = NULL;
    parseaddr_list("Fred Bloggs <fbloggs@FastMAIL.fm>", &a);
    CU_ASSERT_PTR_NOT_NULL_FATAL(a);

    s = address_get_all(a, 0);
    CU_ASSERT_STRING_EQUAL(s, "fbloggs@FastMAIL.fm");
    free(s);

    s = address_get_all(a, 1);
    CU_ASSERT_STRING_EQUAL(s, "fbloggs@fastmail.fm");
    free(s);

    s = address_get_localpart(a);
    CU_ASSERT_STRING_EQUAL(s, "fbloggs");
    free(s);

    s = address_get_domain(a, 0);
    CU_ASSERT_STRING_EQUAL(s, "FastMAIL.fm");
    free(s);

    s = address_get_domain(a, 1);
    CU_ASSERT_STRING_EQUAL(s, "fastmail.fm");
    free(s);

    s = address_get_user(a);
    CU_ASSERT_STRING_EQUAL(s, "fbloggs");
    free(s);

    s = address_get_detail(a);
    CU_ASSERT_PTR_NULL(s);

    parseaddr_free(a);
}

/*
 * Test getting parts of an address with no domain part
 */
static void test_getparts_nodomain(void)
{
    struct address *a;
    char *s;

    a = NULL;
    parseaddr_list("Fred Bloggs <fbloggs>", &a);
    CU_ASSERT_PTR_NOT_NULL_FATAL(a);

    s = address_get_all(a, 0);
    CU_ASSERT_STRING_EQUAL(s, "fbloggs@unspecified-domain");
    free(s);

    s = address_get_all(a, 1);
    CU_ASSERT_STRING_EQUAL(s, "fbloggs@unspecified-domain");
    free(s);

    s = address_get_localpart(a);
    CU_ASSERT_STRING_EQUAL(s, "fbloggs");
    free(s);

    s = address_get_domain(a, 0);
    CU_ASSERT_STRING_EQUAL(s, "unspecified-domain");
    free(s);

    s = address_get_domain(a, 1);
    CU_ASSERT_STRING_EQUAL(s, "unspecified-domain");
    free(s);

    s = address_get_user(a);
    CU_ASSERT_STRING_EQUAL(s, "fbloggs");
    free(s);

    s = address_get_detail(a);
    CU_ASSERT_PTR_NULL(s);

    parseaddr_free(a);
}


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
    CU_ASSERT_STRING_EQUAL(a->mailbox, "Wilt.Chamberlain");
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

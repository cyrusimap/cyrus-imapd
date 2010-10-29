#if HAVE_CONFIG_H
#include <config.h>
#endif
#include "cunit/cunit.h"
#include "parseaddr.h"
#include "imap/message.h"

static void test_parse_trivial(void)
{
    static const char msg[] =
"From: Fred Bloggs <fbloggs@fastmail.fm>\r\n"
"To: Sarah Jane Smith <sjsmith@gmail.com>\r\n"
"Date: Wed, 27 Oct 2010 18:37:26 +1100\r\n"
"Subject: Trivial testing email\r\n"
"Message-ID: <fake800@fastmail.fm>\r\n"
"\r\n"
"Hello, World\n";
    int r;
    struct body body;

    memset(&body, 0x45, sizeof(body));
    r = message_parse_mapped(msg, sizeof(msg)-1, &body);

    CU_ASSERT_EQUAL(r, 0);

    /* From: Fred Bloggs <fbloggs@fastmail.fm> */
    CU_ASSERT_PTR_NOT_NULL_FATAL(body.from);
    CU_ASSERT_STRING_EQUAL(body.from->name, "Fred Bloggs");
    CU_ASSERT_STRING_EQUAL(body.from->mailbox, "fbloggs");
    CU_ASSERT_STRING_EQUAL(body.from->domain, "fastmail.fm");
    CU_ASSERT_PTR_NULL(body.from->next);

    CU_ASSERT_PTR_NULL(body.reply_to);

    /* To: Sarah Jane Smith <sjsmith@gmail.com> */
    CU_ASSERT_PTR_NOT_NULL_FATAL(body.to);
    CU_ASSERT_STRING_EQUAL(body.to->name, "Sarah Jane Smith");
    CU_ASSERT_STRING_EQUAL(body.to->mailbox, "sjsmith");
    CU_ASSERT_STRING_EQUAL(body.to->domain, "gmail.com");
    CU_ASSERT_PTR_NULL(body.to->next);

    CU_ASSERT_PTR_NULL(body.cc);

    CU_ASSERT_PTR_NULL(body.bcc);

    /* Date: Wed, 27 Oct 2010 18:37:26 +1100 */
    CU_ASSERT_STRING_EQUAL(body.date, "Wed, 27 Oct 2010 18:37:26 +1100");

    /* Subject: Trivial testing email */
    CU_ASSERT_STRING_EQUAL(body.subject, "Trivial testing email");

    /* Content-Type not specified, this is the default */
    CU_ASSERT_STRING_EQUAL(body.type, "TEXT");
    CU_ASSERT_STRING_EQUAL(body.subtype, "PLAIN");
    CU_ASSERT_PTR_NOT_NULL(body.params);
    CU_ASSERT_STRING_EQUAL(body.params->attribute, "CHARSET");
    CU_ASSERT_STRING_EQUAL(body.params->value, "us-ascii");
    CU_ASSERT_PTR_NULL(body.params->next);

    CU_ASSERT_PTR_NULL(body.language);

    /* Message-ID: <fake800@fastmail.fm> */
    CU_ASSERT_STRING_EQUAL(body.message_id, "<fake800@fastmail.fm>");

    CU_ASSERT_PTR_NULL(body.in_reply_to);

    CU_ASSERT_PTR_NULL(body.received_date);

    /* simple body */
    CU_ASSERT_EQUAL(body.numparts, 0);
    CU_ASSERT_PTR_NULL(body.subpart);

    message_free_body(&body);
}


static void test_parse_simple(void)
{
    static const char msg[] =
"From: Fred Bloggs <fbloggs@fastmail.fm>\r\n"
"Reply-To: <bounce.me.harder@fastmail.fm>\r\n"
"To: Sarah Jane Smith <sjsmith@gmail.com>\r\n"
"Cc: Al Capone <al@speakeasy.com>\r\n"
"Bcc: Bugsy Moran <bugsy@garage.com>\r\n"
"Date: Thu, 28 Oct 2010 18:37:26 +1100\r\n"
"Subject: Simple testing email\r\n"
"Content-Type: text/plain; charset=\"utf-8\"\r\n"
"Content-Language: en\r\n"
"Message-ID: <fake1000@fastmail.fm>\r\n"
"In-Reply-To: <fake999@gmail.com>\r\n"
"Received: from foo.fastmail.fm (foo.fastmail.fm [10.0.0.1])\r\n"
"\tby bar.gmail.com (Software); Thu, 28 Oct 2010 18:55:54 +1100\r\n"
"\r\n"
"Hello, World\n";
    int r;
    struct body body;

    memset(&body, 0x45, sizeof(body));
    r = message_parse_mapped(msg, sizeof(msg)-1, &body);

    CU_ASSERT_EQUAL(r, 0);

    /* From: Fred Bloggs <fbloggs@fastmail.fm> */
    CU_ASSERT_PTR_NOT_NULL_FATAL(body.from);
    CU_ASSERT_STRING_EQUAL(body.from->name, "Fred Bloggs");
    CU_ASSERT_STRING_EQUAL(body.from->mailbox, "fbloggs");
    CU_ASSERT_STRING_EQUAL(body.from->domain, "fastmail.fm");
    CU_ASSERT_PTR_NULL(body.from->next);

    /* Reply-To: <bounce.me.harder@fastmail.fm> */
    CU_ASSERT_PTR_NOT_NULL_FATAL(body.reply_to);
    CU_ASSERT_PTR_NULL(body.reply_to->name);
    CU_ASSERT_STRING_EQUAL(body.reply_to->mailbox, "bounce.me.harder");
    CU_ASSERT_STRING_EQUAL(body.reply_to->domain, "fastmail.fm");
    CU_ASSERT_PTR_NULL(body.reply_to->next);

    /* To: Sarah Jane Smith <sjsmith@gmail.com> */
    CU_ASSERT_PTR_NOT_NULL_FATAL(body.to);
    CU_ASSERT_STRING_EQUAL(body.to->name, "Sarah Jane Smith");
    CU_ASSERT_STRING_EQUAL(body.to->mailbox, "sjsmith");
    CU_ASSERT_STRING_EQUAL(body.to->domain, "gmail.com");
    CU_ASSERT_PTR_NULL(body.to->next);

    /* Cc: Al Capone <al@speakeasy.com> */
    CU_ASSERT_PTR_NOT_NULL_FATAL(body.cc);
    CU_ASSERT_STRING_EQUAL(body.cc->name, "Al Capone");
    CU_ASSERT_STRING_EQUAL(body.cc->mailbox, "al");
    CU_ASSERT_STRING_EQUAL(body.cc->domain, "speakeasy.com");
    CU_ASSERT_PTR_NULL(body.cc->next);

    /* Bcc: Bugsy Moran <bugsy@garage.com> */
    CU_ASSERT_PTR_NOT_NULL_FATAL(body.bcc);
    CU_ASSERT_STRING_EQUAL(body.bcc->name, "Bugsy Moran");
    CU_ASSERT_STRING_EQUAL(body.bcc->mailbox, "bugsy");
    CU_ASSERT_STRING_EQUAL(body.bcc->domain, "garage.com");
    CU_ASSERT_PTR_NULL(body.bcc->next);

    /* Date: Thu, 28 Oct 2010 18:37:26 +1100 */
    CU_ASSERT_STRING_EQUAL(body.date, "Thu, 28 Oct 2010 18:37:26 +1100");

    /* Subject: Simple testing email */
    CU_ASSERT_STRING_EQUAL(body.subject, "Simple testing email");

    /* Content-Type: text/plain; charset="utf-8" */
    CU_ASSERT_STRING_EQUAL(body.type, "TEXT");
    CU_ASSERT_STRING_EQUAL(body.subtype, "PLAIN");
    CU_ASSERT_PTR_NOT_NULL(body.params);
    CU_ASSERT_STRING_EQUAL(body.params->attribute, "CHARSET");
    CU_ASSERT_STRING_EQUAL(body.params->value, "utf-8");
    CU_ASSERT_PTR_NULL(body.params->next);

    /* Content-Language: en */
    CU_ASSERT_PTR_NOT_NULL(body.language);
    CU_ASSERT_PTR_NULL(body.language->attribute);
    CU_ASSERT_STRING_EQUAL(body.language->value, "EN");
    CU_ASSERT_PTR_NULL(body.language->next);

    /* Message-ID: <fake1000@fastmail.fm> */
    CU_ASSERT_STRING_EQUAL(body.message_id, "<fake1000@fastmail.fm>");

    /* In-Reply-To: <fake999@gmail.com> */
    CU_ASSERT_STRING_EQUAL(body.in_reply_to, "<fake999@gmail.com>");

    /* Received: from foo.fastmail.fm (foo.fastmail.fm [10.0.0.1]) ... */
    CU_ASSERT_STRING_EQUAL(body.received_date, "Thu, 28 Oct 2010 18:55:54 +1100");

    /* simple body */
    CU_ASSERT_EQUAL(body.numparts, 0);
    CU_ASSERT_PTR_NULL(body.subpart);

    message_free_body(&body);
}


/*
 * There are two different headers from which we can extract
 * the body.received_date field.  Test that the rules for
 * choosing which date are correctly applied.
 */
static void test_parse_rxdate(void)
{
#define DELIVERED   "Fri, 29 Oct 2010 13:07:07 +1100"
#define FIRST_RX    "Fri, 29 Oct 2010 13:05:01 +1100"
#define SECOND_RX   "Fri, 29 Oct 2010 13:03:03 +1100"
#define THIRD_RX    "Fri, 29 Oct 2010 13:01:01 +1100"
#define SENT	    "Thu, 28 Oct 2010 18:37:26 +1100"

    /* Message has neither Received: nor X-DeliveredInternalDate headers. */
    static const char msg_neither[] =
"From: Fred Bloggs <fbloggs@fastmail.fm>\r\n"
"To: Sarah Jane Smith <sjsmith@gmail.com>\r\n"
"Date: " SENT "\r\n"
"Subject: Simple testing email\r\n"
"Message-ID: <fake1000@fastmail.fm>\r\n"
"\r\n"
"Hello, World\n";

    /* Message has only Received: headers. */
    static const char msg_only_received[] =
"From: Fred Bloggs <fbloggs@fastmail.fm>\r\n"
"To: Sarah Jane Smith <sjsmith@gmail.com>\r\n"
"Date: " SENT "\r\n"
"Subject: Simple testing email\r\n"
"Message-ID: <fake1000@fastmail.fm>\r\n"
"Received: from mail.quux.com (mail.quux.com [10.0.0.1])\r\n"
"\tby mail.gmail.com (Software); " FIRST_RX "\r\n"
"Received: from mail.bar.com (mail.bar.com [10.0.0.1])\r\n"
"\tby mail.quux.com (Software); " SECOND_RX "\r\n"
"Received: from mail.fastmail.fm (mail.fastmail.fm [10.0.0.1])\r\n"
"\tby mail.bar.com (Software); " THIRD_RX "\r\n"
"\r\n"
"Hello, World\n";

    /* Message has only X-DeliveredInternalDate (weird!) */
    static const char msg_only_xdid[] =
"From: Fred Bloggs <fbloggs@fastmail.fm>\r\n"
"To: Sarah Jane Smith <sjsmith@gmail.com>\r\n"
"Date: " SENT "\r\n"
"Subject: Simple testing email\r\n"
"Message-ID: <fake1000@fastmail.fm>\r\n"
"X-Deliveredinternaldate: " DELIVERED "\r\n"
"\r\n"
"Hello, World\n";

    /* Message has both Received and X-DeliveredInternalDate in that order */
    static const char msg_received_then_xdid[] =
"From: Fred Bloggs <fbloggs@fastmail.fm>\r\n"
"To: Sarah Jane Smith <sjsmith@gmail.com>\r\n"
"Date: " SENT "\r\n"
"Subject: Simple testing email\r\n"
"Message-ID: <fake1000@fastmail.fm>\r\n"
"Received: from mail.quux.com (mail.quux.com [10.0.0.1])\r\n"
"\tby mail.gmail.com (Software); " FIRST_RX "\r\n"
"Received: from mail.bar.com (mail.bar.com [10.0.0.1])\r\n"
"\tby mail.quux.com (Software); " SECOND_RX "\r\n"
"Received: from mail.fastmail.fm (mail.fastmail.fm [10.0.0.1])\r\n"
"\tby mail.bar.com (Software); " THIRD_RX "\r\n"
"X-Deliveredinternaldate: " DELIVERED "\r\n"
"\r\n"
"Hello, World\n";

    /* Message has both X-DeliveredInternalDate and Received in that order */
    static const char msg_xdid_then_received[] =
"From: Fred Bloggs <fbloggs@fastmail.fm>\r\n"
"To: Sarah Jane Smith <sjsmith@gmail.com>\r\n"
"Date: " SENT "\r\n"
"Subject: Simple testing email\r\n"
"Message-ID: <fake1000@fastmail.fm>\r\n"
"X-Deliveredinternaldate: " DELIVERED "\r\n"
"Received: from mail.quux.com (mail.quux.com [10.0.0.1])\r\n"
"\tby mail.gmail.com (Software); " FIRST_RX "\r\n"
"Received: from mail.bar.com (mail.bar.com [10.0.0.1])\r\n"
"\tby mail.quux.com (Software); " SECOND_RX "\r\n"
"Received: from mail.fastmail.fm (mail.fastmail.fm [10.0.0.1])\r\n"
"\tby mail.bar.com (Software); " THIRD_RX "\r\n"
"\r\n"
"Hello, World\n";

    int r;
    struct body body;

    /* Neither: no received_date */
    memset(&body, 0x45, sizeof(body));
    r = message_parse_mapped(msg_neither, sizeof(msg_neither)-1, &body);
    CU_ASSERT_EQUAL(r, 0);
    CU_ASSERT_PTR_NULL(body.received_date);
    message_free_body(&body);

    /* Received only: first seen Received */
    memset(&body, 0x45, sizeof(body));
    r = message_parse_mapped(msg_only_received,
			     sizeof(msg_only_received)-1, &body);
    CU_ASSERT_EQUAL(r, 0);
    CU_ASSERT_STRING_EQUAL(body.received_date, FIRST_RX);
    message_free_body(&body);

    /* X-DeliveredInternalDate only: use that */
    memset(&body, 0x45, sizeof(body));
    r = message_parse_mapped(msg_only_xdid,
			     sizeof(msg_only_xdid)-1, &body);
    CU_ASSERT_EQUAL(r, 0);
    CU_ASSERT_STRING_EQUAL(body.received_date, DELIVERED);
    message_free_body(&body);

    /* both, Received first: use X-DeliveredInternalDate */
    memset(&body, 0x45, sizeof(body));
    r = message_parse_mapped(msg_received_then_xdid,
			     sizeof(msg_received_then_xdid)-1, &body);
    CU_ASSERT_EQUAL(r, 0);
    CU_ASSERT_STRING_EQUAL(body.received_date, DELIVERED);
    message_free_body(&body);

    /* both, X-DeliveredInternalDate first: use X-DeliveredInternalDate */
    memset(&body, 0x45, sizeof(body));
    r = message_parse_mapped(msg_xdid_then_received,
			     sizeof(msg_xdid_then_received)-1, &body);
    CU_ASSERT_EQUAL(r, 0);
    CU_ASSERT_STRING_EQUAL(body.received_date, DELIVERED);
    message_free_body(&body);
}


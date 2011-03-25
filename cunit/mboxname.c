#if HAVE_CONFIG_H
#include <config.h>
#endif
#include "cunit/cunit.h"
#include "libconfig.h"
#include "mboxname.h"
#include "mailbox.h"
#include "global.h"

static void test_to_parts(void)
{
    static const char FRED_DRAFTS[] = "user.fred.Drafts";
    static const char JANEAT_SENT[] = "bloggs.com!user.jane.Sent";
    static const char SHARED[] = "shared.Gossip";
    static const char SHAREDAT[] = "foonly.com!shared.Tattle";
    struct mboxname_parts parts;
    int r;

    r = mboxname_to_parts(FRED_DRAFTS, &parts);
    CU_ASSERT_EQUAL(r, 0);
    CU_ASSERT_PTR_NULL(parts.domain);
    CU_ASSERT_STRING_EQUAL(parts.userid, "fred");
    CU_ASSERT_STRING_EQUAL(parts.box, "Drafts");
    mboxname_free_parts(&parts);

    r = mboxname_to_parts(JANEAT_SENT, &parts);
    CU_ASSERT_EQUAL(r, 0);
    CU_ASSERT_STRING_EQUAL(parts.domain, "bloggs.com");
    CU_ASSERT_STRING_EQUAL(parts.userid, "jane");
    CU_ASSERT_STRING_EQUAL(parts.box, "Sent");
    mboxname_free_parts(&parts);

    r = mboxname_to_parts(SHARED, &parts);
    CU_ASSERT_EQUAL(r, 0);
    CU_ASSERT_PTR_NULL(parts.domain);
    CU_ASSERT_PTR_NULL(parts.userid);
    CU_ASSERT_STRING_EQUAL(parts.box, "shared.Gossip");
    mboxname_free_parts(&parts);

    r = mboxname_to_parts(SHAREDAT, &parts);
    CU_ASSERT_EQUAL(r, 0);
    CU_ASSERT_STRING_EQUAL(parts.domain, "foonly.com");
    CU_ASSERT_PTR_NULL(parts.userid);
    CU_ASSERT_STRING_EQUAL(parts.box, "shared.Tattle");
    mboxname_free_parts(&parts);
}

static void test_to_userid(void)
{
    static const char SAM_DRAFTS[] = "user.sam.Drafts";
    static const char BETTYAT_SENT[] = "boop.com!user.betty.Sent";
    static const char SHARED[] = "shared.Gossip";
    static const char SHAREDAT[] = "foonly.com!shared.Tattle";
    const char *r;

    r = mboxname_to_userid(SAM_DRAFTS);
    CU_ASSERT_STRING_EQUAL(r, "sam");

    r = mboxname_to_userid(BETTYAT_SENT);
    CU_ASSERT_STRING_EQUAL(r, "betty@boop.com");

    r = mboxname_to_userid(SHARED);
    CU_ASSERT_PTR_NULL(r);

    r = mboxname_to_userid(SHAREDAT);
    CU_ASSERT_PTR_NULL(r);
}

static void test_to_inbox(void)
{
    const char *r;

    r = mboxname_user_inbox("sam");
    CU_ASSERT_STRING_EQUAL(r, "user.sam");

    r = mboxname_user_inbox("betty@boop.com");
    CU_ASSERT_STRING_EQUAL(r, "boop.com!user.betty");

    r = mboxname_user_inbox(NULL);
    CU_ASSERT_PTR_NULL(r);
}


static void test_same_userid(void)
{
    static const char FRED_DRAFTS[] = "user.fred.Drafts";
    static const char FRED_SENT[] = "user.fred.Sent";
    static const char JANE_SENT[] = "user.jane.Sent";

    CU_ASSERT_EQUAL(mboxname_same_userid(FRED_DRAFTS, FRED_SENT), 1);
    CU_ASSERT_EQUAL(mboxname_same_userid(JANE_SENT, FRED_SENT), 0);
}

static void test_same_userid_domain(void)
{
    static const char FREDAT_DRAFTS[] = "bloggs.com!user.fred.Drafts";
    static const char FREDAT_SENT[] = "bloggs.com!user.fred.Sent";
    static const char JANEAT_SENT[] = "bloggs.com!user.jane.Sent";
    static const char JANE_SENT[] = "user.jane.Sent";

    CU_ASSERT_EQUAL(mboxname_same_userid(FREDAT_DRAFTS, FREDAT_SENT), 1);
    CU_ASSERT_EQUAL(mboxname_same_userid(JANEAT_SENT, FREDAT_SENT), 0);
    CU_ASSERT_EQUAL(mboxname_same_userid(JANE_SENT, FREDAT_SENT), 0);
    CU_ASSERT_EQUAL(mboxname_same_userid(JANE_SENT, JANEAT_SENT), 0);
}

static void test_contains(void)
{
    static const char FOO[] = "bloggs.com!user.foo";
    static const char FOOBAR[] = "bloggs.com!user.foobar";
    static const char FOODRAFT[] = "bloggs.com!user.foo.Drafts";
    static const char FOONET[] = "bloggs.net!user.foo";
    static const char FOONONE[] = "user.foo";

    CU_ASSERT_EQUAL(mboxname_is_prefix(FOO, FOOBAR), 0);
    CU_ASSERT_EQUAL(mboxname_is_prefix(FOOBAR, FOO), 0);
    CU_ASSERT_EQUAL(mboxname_is_prefix(FOO, FOODRAFT), 0);
    CU_ASSERT_EQUAL(mboxname_is_prefix(FOODRAFT, FOO), 1);
    CU_ASSERT_EQUAL(mboxname_is_prefix(FOOBAR, FOOBAR), 1);
    CU_ASSERT_EQUAL(mboxname_is_prefix(FOO, FOONET), 0);
    CU_ASSERT_EQUAL(mboxname_is_prefix(FOONET, FOO), 0);
    CU_ASSERT_EQUAL(mboxname_is_prefix(FOONONE, FOO), 0);
    CU_ASSERT_EQUAL(mboxname_is_prefix(FOO, FOONONE), 0);
}

static void test_parts_same_userid(void)
{
    static const char FRED_DRAFTS[] = "user.fred.Drafts";
    static const char FRED_SENT[] = "user.fred.Sent";
    static const char JANE_SENT[] = "user.jane.Sent";
    struct mboxname_parts parts1, parts2;
    int r;

    r = mboxname_to_parts(FRED_DRAFTS, &parts1);
    CU_ASSERT_EQUAL(r, 0);
    r = mboxname_to_parts(FRED_SENT, &parts2);
    CU_ASSERT_EQUAL(r, 0);
    CU_ASSERT_EQUAL(mboxname_parts_same_userid(&parts1, &parts2), 1);
    mboxname_free_parts(&parts1);
    mboxname_free_parts(&parts2);

    r = mboxname_to_parts(JANE_SENT, &parts1);
    CU_ASSERT_EQUAL(r, 0);
    r = mboxname_to_parts(FRED_SENT, &parts2);
    CU_ASSERT_EQUAL(r, 0);
    CU_ASSERT_EQUAL(mboxname_parts_same_userid(&parts1, &parts2), 0);
    mboxname_free_parts(&parts1);
    mboxname_free_parts(&parts2);
}

static void test_parts_same_userid_domain(void)
{
    static const char FREDAT_DRAFTS[] = "bloggs.com!user.fred.Drafts";
    static const char FREDAT_SENT[] = "bloggs.com!user.fred.Sent";
    static const char JANEAT_SENT[] = "bloggs.com!user.jane.Sent";
    static const char JANE_SENT[] = "user.jane.Sent";
    struct mboxname_parts parts1, parts2;
    int r;

    r = mboxname_to_parts(FREDAT_DRAFTS, &parts1);
    CU_ASSERT_EQUAL(r, 0);
    r = mboxname_to_parts(FREDAT_SENT, &parts2);
    CU_ASSERT_EQUAL(r, 0);
    CU_ASSERT_EQUAL(mboxname_parts_same_userid(&parts1, &parts2), 1);
    mboxname_free_parts(&parts1);
    mboxname_free_parts(&parts2);

    r = mboxname_to_parts(JANEAT_SENT, &parts1);
    CU_ASSERT_EQUAL(r, 0);
    r = mboxname_to_parts(FREDAT_SENT, &parts2);
    CU_ASSERT_EQUAL(r, 0);
    CU_ASSERT_EQUAL(mboxname_parts_same_userid(&parts1, &parts2), 0);
    mboxname_free_parts(&parts1);
    mboxname_free_parts(&parts2);

    r = mboxname_to_parts(JANE_SENT, &parts1);
    CU_ASSERT_EQUAL(r, 0);
    r = mboxname_to_parts(FREDAT_SENT, &parts2);
    CU_ASSERT_EQUAL(r, 0);
    CU_ASSERT_EQUAL(mboxname_parts_same_userid(&parts1, &parts2), 0);
    mboxname_free_parts(&parts1);
    mboxname_free_parts(&parts2);

    r = mboxname_to_parts(JANE_SENT, &parts1);
    CU_ASSERT_EQUAL(r, 0);
    r = mboxname_to_parts(JANEAT_SENT, &parts2);
    CU_ASSERT_EQUAL(r, 0);
    CU_ASSERT_EQUAL(mboxname_parts_same_userid(&parts1, &parts2), 0);
    mboxname_free_parts(&parts1);
    mboxname_free_parts(&parts2);
}

/* This structure encapsulates all the variables which affect
 * namespace translation in one place */
static struct
{
    const char *userid;
    int isadmin;
    int altnamespace;
    int virtdomains;
    const char *defdomain;
    const char *userprefix;
    const char *sharedprefix;
    int unixhierarchysep;
} conf;

static void toexternal_helper(const char *intname,
			      const char *extname_expected)
{
    struct namespace ns;
    char extname[MAX_MAILBOX_NAME];
    int r;

    config_virtdomains = conf.virtdomains;
    config_defdomain = conf.defdomain;
    imapopts[IMAPOPT_UNIXHIERARCHYSEP].val.b = conf.unixhierarchysep;
    imapopts[IMAPOPT_ALTNAMESPACE].val.b = conf.altnamespace;
    imapopts[IMAPOPT_USERPREFIX].val.s = conf.userprefix;
    imapopts[IMAPOPT_SHAREDPREFIX].val.s = conf.sharedprefix;

    r = mboxname_init_namespace(&ns, conf.isadmin);
    CU_ASSERT_EQUAL_FATAL(r, 0);

    memset(extname, 0x45, sizeof(extname));
    r = ns.mboxname_toexternal(&ns, intname, conf.userid, extname);
    CU_ASSERT_EQUAL_FATAL(r, 0);
    CU_ASSERT_STRING_EQUAL(extname, extname_expected);
}

static void test_toexternal_simple(void)
{
    memset(&conf, 0, sizeof(conf));
    conf.virtdomains = 0;
    conf.userid = "fred";

    toexternal_helper("user.fred", "INBOX");
    toexternal_helper("user.fred.foo", "INBOX.foo");
    toexternal_helper("user.fred.foo.barracuda", "INBOX.foo.barracuda");
    toexternal_helper("user.jane", "user.jane");
    toexternal_helper("user.jane.baz", "user.jane.baz");
    toexternal_helper("shared.quux", "shared.quux");
}

static void test_toexternal_domains(void)
{
    memset(&conf, 0, sizeof(conf));
    conf.virtdomains = 1;
    conf.userid = "fred@bloggs.com";

    toexternal_helper("bloggs.com!user.fred", "INBOX");
    toexternal_helper("bloggs.com!user.fred.foo", "INBOX.foo");
    toexternal_helper("bloggs.com!user.fred.foo.barracuda", "INBOX.foo.barracuda");
    toexternal_helper("bloggs.com!user.jane", "user.jane");
    toexternal_helper("bloggs.com!user.jane.baz", "user.jane.baz");
    toexternal_helper("boop.com!user.betty", "user.betty@boop.com");
    toexternal_helper("bloggs.com!shared.quux", "shared.quux");
    toexternal_helper("boop.com!shared.quux", "shared.quux@boop.com");
}

static void test_toexternal_unixhier(void)
{
    memset(&conf, 0, sizeof(conf));
    conf.unixhierarchysep = 1;
    conf.userid = "fred";

    toexternal_helper("user.fred", "INBOX");
    toexternal_helper("user.fred.foo", "INBOX/foo");
    toexternal_helper("user.fred.foo.barracuda", "INBOX/foo/barracuda");
    toexternal_helper("user.jane", "user/jane");
    toexternal_helper("user.jane.baz", "user/jane/baz");
    toexternal_helper("shared.quux", "shared/quux");
}

static void test_toexternal_alt(void)
{
    memset(&conf, 0, sizeof(conf));
    conf.altnamespace = 1;
    conf.userprefix = "Uvvers";
    conf.sharedprefix = "Chaired";
    conf.userid = "fred";

    toexternal_helper("user.fred", "INBOX");
    toexternal_helper("user.fred.foo", "foo");
    toexternal_helper("user.fred.foo.barracuda", "foo.barracuda");
    toexternal_helper("user.jane", "Uvvers.jane");
    toexternal_helper("user.jane.baz", "Uvvers.jane.baz");
    toexternal_helper("shared.quux", "Chaired.shared.quux");
}

static enum enum_value old_config_virtdomains;

static int set_up(void)
{
    /*
     * TODO: this is pretty hacky.  There should be some
     * cleaner way of pushing aside the config for a moment
     * and temporarily setting up a particular set of config
     * options for testing.
     */
    old_config_virtdomains = config_virtdomains;
    config_virtdomains = IMAP_ENUM_VIRTDOMAINS_ON;
    return 0;
}

static int tear_down(void)
{
    config_virtdomains = old_config_virtdomains;
    return 0;
}


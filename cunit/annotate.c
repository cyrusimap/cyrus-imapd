#if HAVE_CONFIG_H
#include <config.h>
#endif
#include "cunit/cunit.h"
#include "xmalloc.h"
#include "retry.h"
#include "global.h"
#include "libcyr_cfg.h"
#include "annotate.h"
#include "mboxlist.h"
#include "imap_err.h"

#define DBDIR		"test-dbdir"
#define MBOXNAME1_INT   "user.smurf"
#define MBOXNAME1_EXT   "INBOX"
#define MBOXNAME2_INT   "user.smurfette"
#define MBOXNAME2_EXT   "user.smurfette"
#define PARTITION	"default"
#define COMMENT		"/comment"
#define EXENTRY		"/vendor/example.com/a-non-default-entry"
#define VALUE_SHARED	"value.shared"
#define SIZE_SHARED	"size.shared"
#define VALUE0		"Hello World"
#define LENGTH0		"11"
#define VALUE1		"lorem ipsum"
#define VALUE2		"dolor sit amet"
#define ACL		"anyone\tlrswipkxtecdan\t"

static struct namespace namespace;
static int isadmin;
static const char *userid;
static struct auth_state *auth_state;
static const char *old_annotation_definitions = NULL;

static void config_read_string(const char *s)
{
    char *fname = xstrdup("/tmp/cyrus-cunit-configXXXXXX");
    int fd = mkstemp(fname);
    retry_write(fd, s, strlen(s));
    config_reset();
    config_read(fname);
    unlink(fname);
    free(fname);
    close(fd);
}

static void set_annotation_definitions(const char *s)
{
    static const char *fname = DBDIR"/conf/annotations.def";
    int fd;

    fd = open(fname, O_WRONLY|O_CREAT|O_TRUNC, 0666);
    assert(fd >= 0);
    retry_write(fd, s, strlen(s));
    close(fd);

    imapopts[IMAPOPT_ANNOTATION_DEFINITIONS].val.s = fname;
}

static int fexists(const char *fname)
{
    struct stat sb;
    int r;

    r = stat(fname, &sb);
    if (r < 0)
	r = -errno;
    return r;
}


static void fetch_cb(const char *mboxname, uint32_t uid,
		     const char *entry, struct attvaluelist *avlist,
		     void *rock)
{
    strarray_t *results = (strarray_t *)rock;
    struct buf buf = BUF_INITIALIZER;

    buf_printf(&buf, "mboxname=\"%s\" uid=%u entry=\"%s\"",
	       mboxname, uid, entry);

    for ( ; avlist ; avlist = avlist->next) {
	buf_printf(&buf, " %s=", avlist->attrib);
	if (avlist->value.s)
	    buf_printf(&buf, "\"%s\"", buf_cstring(&avlist->value));
	else
	    buf_printf(&buf, "NIL");
    }

    strarray_appendm(results, buf_release(&buf));
}

static void test_begin_without_open(void)
{
    int r;

    annotatemore_init(NULL, NULL);

    /* no call to annotatemore_open() here */

    r = annotatemore_begin();
    CU_ASSERT_EQUAL(r, IMAP_INTERNAL);

    r = annotatemore_commit();
    CU_ASSERT_EQUAL(r, IMAP_INTERNAL);
}

static void test_commit_without_begin(void)
{
    int r;

    annotatemore_init(NULL, NULL);

    annotatemore_open();

    r = annotatemore_commit();
    CU_ASSERT_EQUAL(r, IMAP_INTERNAL);

    r = annotatemore_begin();
    CU_ASSERT_EQUAL(r, 0);

    r = annotatemore_commit();
    CU_ASSERT_EQUAL(r, 0);

    annotatemore_close();
}

static void test_store_without_begin(void)
{
    int r;
    annotate_scope_t scope;
    strarray_t entries = STRARRAY_INITIALIZER;
    strarray_t attribs = STRARRAY_INITIALIZER;
    struct entryattlist *ealist = NULL;
    struct buf val = BUF_INITIALIZER;
    struct buf val2 = BUF_INITIALIZER;

    annotatemore_init(NULL, NULL);

    annotatemore_open();

    annotate_scope_init_server(&scope);

    strarray_append(&entries, COMMENT);
    strarray_append(&attribs, VALUE_SHARED);

    /* store should fail as we're not in a txn */

    buf_appendcstr(&val, VALUE0);
    setentryatt(&ealist, COMMENT, VALUE_SHARED, &val);
    isadmin = 1;	/* pretend to be admin */
    r = annotatemore_store(&scope, ealist,
		           &namespace, isadmin, userid, auth_state);
    isadmin = 0;
    CU_ASSERT_EQUAL(r, IMAP_INTERNAL);

    /* commit should fail as we're not in a txn */
    r = annotatemore_commit();
    CU_ASSERT_EQUAL(r, IMAP_INTERNAL);

    /* check that the failed _store did not store */
    r = annotatemore_lookup(/*mboxname*/"", COMMENT, /*userid*/"", &val2);
    CU_ASSERT_EQUAL_FATAL(r, 0);
    CU_ASSERT_PTR_NULL(val2.s);

    annotatemore_close();

    strarray_fini(&entries);
    strarray_fini(&attribs);
    buf_free(&val);
    buf_free(&val2);
    freeentryatts(ealist);
}

static void test_getset_server_shared(void)
{
    int r;
    annotate_scope_t scope;
    strarray_t entries = STRARRAY_INITIALIZER;
    strarray_t attribs = STRARRAY_INITIALIZER;
    strarray_t results = STRARRAY_INITIALIZER;
    struct entryattlist *ealist = NULL;
    struct buf val = BUF_INITIALIZER;
    struct buf val2 = BUF_INITIALIZER;

    annotatemore_init(NULL, NULL);

    annotatemore_open();

    annotate_scope_init_server(&scope);

    strarray_append(&entries, COMMENT);
    strarray_append(&attribs, VALUE_SHARED);

    /* check that there is no value initially */

    r = annotatemore_fetch(&scope,
		           &entries, &attribs,
		           &namespace, isadmin, userid, auth_state,
		           fetch_cb, &results,
		           NULL);
    CU_ASSERT_EQUAL(r, 0);
    CU_ASSERT_EQUAL_FATAL(results.count, 1);
#define EXPECTED \
	   "mboxname=\"\" " \
	   "uid=0 " \
	   "entry=\"" COMMENT "\" " \
	   VALUE_SHARED "=NIL"
    CU_ASSERT_STRING_EQUAL(results.data[0], EXPECTED);
#undef EXPECTED
    strarray_truncate(&results, 0);

    r = annotatemore_lookup(/*mboxname*/"", COMMENT, /*userid*/"", &val);
    CU_ASSERT_EQUAL(r, 0);
    CU_ASSERT_PTR_NULL(val.s);

    r = annotatemore_begin();
    CU_ASSERT_EQUAL(r, 0);

    /* set a value */

    buf_appendcstr(&val, VALUE0);
    setentryatt(&ealist, COMMENT, VALUE_SHARED, &val);
    isadmin = 1;	/* pretend to be admin */
    r = annotatemore_store(&scope, ealist,
		           &namespace, isadmin, userid, auth_state);
    isadmin = 0;
    CU_ASSERT_EQUAL(r, 0);
    freeentryatts(ealist);
    ealist = NULL;

    /* check that we can fetch the value back in the same txn */
    r = annotatemore_fetch(&scope,
		           &entries, &attribs,
		           &namespace, isadmin, userid, auth_state,
		           fetch_cb, &results,
		           NULL);
    CU_ASSERT_EQUAL(r, 0);
    CU_ASSERT_EQUAL_FATAL(results.count, 1);
#define EXPECTED \
	   "mboxname=\"\" " \
	   "uid=0 " \
	   "entry=\"" COMMENT "\" " \
	   VALUE_SHARED "=\"" VALUE0 "\""
    CU_ASSERT_STRING_EQUAL(results.data[0], EXPECTED);
#undef EXPECTED
    strarray_truncate(&results, 0);

    r = annotatemore_lookup(/*mboxname*/"", COMMENT, /*userid*/"", &val2);
    CU_ASSERT_EQUAL_FATAL(r, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(val2.s);
    CU_ASSERT_STRING_EQUAL(buf_cstring(&val2), VALUE0);
    buf_free(&val2);

    r = annotatemore_commit();
    CU_ASSERT_EQUAL(r, 0);

    /* check that we can fetch the value back in a new txn */
    r = annotatemore_fetch(&scope,
		           &entries, &attribs,
		           &namespace, isadmin, userid, auth_state,
		           fetch_cb, &results,
		           NULL);
    CU_ASSERT_EQUAL(r, 0);
    CU_ASSERT_EQUAL_FATAL(results.count, 1);
#define EXPECTED \
	   "mboxname=\"\" " \
	   "uid=0 " \
	   "entry=\"" COMMENT "\" " \
	   VALUE_SHARED "=\"" VALUE0 "\""
    CU_ASSERT_STRING_EQUAL(results.data[0], EXPECTED);
#undef EXPECTED
    strarray_truncate(&results, 0);

    r = annotatemore_lookup(/*mboxname*/"", COMMENT, /*userid*/"", &val2);
    CU_ASSERT_EQUAL_FATAL(r, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(val2.s);
    CU_ASSERT_STRING_EQUAL(buf_cstring(&val2), VALUE0);
    buf_free(&val2);

    annotatemore_close();

    /* check that we can fetch the value back after close and re-open */

    annotatemore_open();

    r = annotatemore_fetch(&scope,
		           &entries, &attribs,
		           &namespace, isadmin, userid, auth_state,
		           fetch_cb, &results,
		           NULL);
    CU_ASSERT_EQUAL(r, 0);
    CU_ASSERT_EQUAL_FATAL(results.count, 1);
#define EXPECTED \
	   "mboxname=\"\" " \
	   "uid=0 " \
	   "entry=\"" COMMENT "\" " \
	   VALUE_SHARED "=\"" VALUE0 "\""
    CU_ASSERT_STRING_EQUAL(results.data[0], EXPECTED);
#undef EXPECTED
    strarray_truncate(&results, 0);

    r = annotatemore_lookup(/*mboxname*/"", COMMENT, /*userid*/"", &val2);
    CU_ASSERT_EQUAL_FATAL(r, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(val2.s);
    CU_ASSERT_STRING_EQUAL(buf_cstring(&val2), VALUE0);
    buf_free(&val2);

    /* delete the value */

    r = annotatemore_begin();
    CU_ASSERT_EQUAL(r, 0);

    buf_free(&val);
    setentryatt(&ealist, COMMENT, VALUE_SHARED, &val);
    isadmin = 1;	/* pretend to be admin */
    r = annotatemore_store(&scope, ealist,
		           &namespace, isadmin, userid, auth_state);
    isadmin = 0;
    CU_ASSERT_EQUAL(r, 0);
    freeentryatts(ealist);
    ealist = NULL;

    r = annotatemore_commit();
    CU_ASSERT_EQUAL(r, 0);

    /* check that there is no value any more */

    r = annotatemore_fetch(&scope,
		           &entries, &attribs,
		           &namespace, isadmin, userid, auth_state,
		           fetch_cb, &results,
		           NULL);
    CU_ASSERT_EQUAL(r, 0);
    CU_ASSERT_EQUAL_FATAL(results.count, 1);
#define EXPECTED \
	   "mboxname=\"\" " \
	   "uid=0 " \
	   "entry=\"" COMMENT "\" " \
	   VALUE_SHARED "=NIL"
    CU_ASSERT_STRING_EQUAL(results.data[0], EXPECTED);
#undef EXPECTED
    strarray_truncate(&results, 0);

    r = annotatemore_lookup(/*mboxname*/"", COMMENT, /*userid*/"", &val);
    CU_ASSERT_EQUAL(r, 0);
    CU_ASSERT_PTR_NULL(val.s);


    annotatemore_close();

    strarray_fini(&entries);
    strarray_fini(&attribs);
    strarray_fini(&results);
    buf_free(&val);
}


static void test_getset_mailbox_shared(void)
{
    int r;
    annotate_scope_t scope;
    strarray_t entries = STRARRAY_INITIALIZER;
    strarray_t attribs = STRARRAY_INITIALIZER;
    strarray_t results = STRARRAY_INITIALIZER;
    struct entryattlist *ealist = NULL;
    struct buf val = BUF_INITIALIZER;
    struct buf val2 = BUF_INITIALIZER;

    annotatemore_init(NULL, NULL);

    annotatemore_open();

    annotate_scope_init_mailbox(&scope, MBOXNAME1_INT);

    strarray_append(&entries, COMMENT);
    strarray_append(&attribs, VALUE_SHARED);

    /* check that there is no value initially */

    r = annotatemore_fetch(&scope,
		           &entries, &attribs,
		           &namespace, isadmin, userid, auth_state,
		           fetch_cb, &results,
		           NULL);
    CU_ASSERT_EQUAL(r, 0);
    CU_ASSERT_EQUAL_FATAL(results.count, 1);
#define EXPECTED \
	   "mboxname=\"" MBOXNAME1_EXT "\" " \
	   "uid=0 " \
	   "entry=\"" COMMENT "\" " \
	   VALUE_SHARED "=NIL"
    CU_ASSERT_STRING_EQUAL(results.data[0], EXPECTED);
#undef EXPECTED
    strarray_truncate(&results, 0);

    r = annotatemore_lookup(MBOXNAME1_INT, COMMENT, /*userid*/"", &val);
    CU_ASSERT_EQUAL(r, 0);
    CU_ASSERT_PTR_NULL(val.s);

    r = annotatemore_begin();
    CU_ASSERT_EQUAL(r, 0);

    /* set a value */

    buf_appendcstr(&val, VALUE0);
    setentryatt(&ealist, COMMENT, VALUE_SHARED, &val);
    r = annotatemore_store(&scope, ealist,
		           &namespace, isadmin, userid, auth_state);
    CU_ASSERT_EQUAL(r, 0);
    freeentryatts(ealist);
    ealist = NULL;

    /* check that we can fetch the value back in the same txn */
    r = annotatemore_fetch(&scope,
		           &entries, &attribs,
		           &namespace, isadmin, userid, auth_state,
		           fetch_cb, &results,
		           NULL);
    CU_ASSERT_EQUAL(r, 0);
    CU_ASSERT_EQUAL_FATAL(results.count, 1);
#define EXPECTED \
	   "mboxname=\"" MBOXNAME1_EXT "\" " \
	   "uid=0 " \
	   "entry=\"" COMMENT "\" " \
	   VALUE_SHARED "=\"" VALUE0 "\""
    CU_ASSERT_STRING_EQUAL(results.data[0], EXPECTED);
#undef EXPECTED
    strarray_truncate(&results, 0);

    r = annotatemore_lookup(MBOXNAME1_INT, COMMENT, /*userid*/"", &val2);
    CU_ASSERT_EQUAL_FATAL(r, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(val2.s);
    CU_ASSERT_STRING_EQUAL(buf_cstring(&val2), VALUE0);
    buf_free(&val2);

    r = annotatemore_commit();
    CU_ASSERT_EQUAL(r, 0);

    /* check that we can fetch the value back in a new txn */
    r = annotatemore_fetch(&scope,
		           &entries, &attribs,
		           &namespace, isadmin, userid, auth_state,
		           fetch_cb, &results,
		           NULL);
    CU_ASSERT_EQUAL(r, 0);
    CU_ASSERT_EQUAL_FATAL(results.count, 1);
#define EXPECTED \
	   "mboxname=\"" MBOXNAME1_EXT "\" " \
	   "uid=0 " \
	   "entry=\"" COMMENT "\" " \
	   VALUE_SHARED "=\"" VALUE0 "\""
    CU_ASSERT_STRING_EQUAL(results.data[0], EXPECTED);
#undef EXPECTED
    strarray_truncate(&results, 0);

    r = annotatemore_lookup(MBOXNAME1_INT, COMMENT, /*userid*/"", &val2);
    CU_ASSERT_EQUAL_FATAL(r, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(val2.s);
    CU_ASSERT_STRING_EQUAL(buf_cstring(&val2), VALUE0);
    buf_free(&val2);

    annotatemore_close();

    /* check that we can fetch the value back after close and re-open */

    annotatemore_open();

    r = annotatemore_fetch(&scope,
		           &entries, &attribs,
		           &namespace, isadmin, userid, auth_state,
		           fetch_cb, &results,
		           NULL);
    CU_ASSERT_EQUAL(r, 0);
    CU_ASSERT_EQUAL_FATAL(results.count, 1);
#define EXPECTED \
	   "mboxname=\"" MBOXNAME1_EXT "\" " \
	   "uid=0 " \
	   "entry=\"" COMMENT "\" " \
	   VALUE_SHARED "=\"" VALUE0 "\""
    CU_ASSERT_STRING_EQUAL(results.data[0], EXPECTED);
#undef EXPECTED
    strarray_truncate(&results, 0);

    r = annotatemore_lookup(MBOXNAME1_INT, COMMENT, /*userid*/"", &val2);
    CU_ASSERT_EQUAL_FATAL(r, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(val2.s);
    CU_ASSERT_STRING_EQUAL(buf_cstring(&val2), VALUE0);
    buf_free(&val2);

    /* delete the value */

    r = annotatemore_begin();
    CU_ASSERT_EQUAL(r, 0);

    buf_free(&val);
    setentryatt(&ealist, COMMENT, VALUE_SHARED, &val);
    r = annotatemore_store(&scope, ealist,
		           &namespace, isadmin, userid, auth_state);
    CU_ASSERT_EQUAL(r, 0);
    freeentryatts(ealist);
    ealist = NULL;

    r = annotatemore_commit();
    CU_ASSERT_EQUAL(r, 0);

    /* check that there is no value any more */

    r = annotatemore_fetch(&scope,
		           &entries, &attribs,
		           &namespace, isadmin, userid, auth_state,
		           fetch_cb, &results,
		           NULL);
    CU_ASSERT_EQUAL(r, 0);
    CU_ASSERT_EQUAL_FATAL(results.count, 1);
#define EXPECTED \
	   "mboxname=\"" MBOXNAME1_EXT "\" " \
	   "uid=0 " \
	   "entry=\"" COMMENT "\" " \
	   VALUE_SHARED "=NIL"
    CU_ASSERT_STRING_EQUAL(results.data[0], EXPECTED);
#undef EXPECTED
    strarray_truncate(&results, 0);

    buf_free(&val);
    r = annotatemore_lookup(MBOXNAME1_INT, COMMENT, /*userid*/"", &val);
    CU_ASSERT_EQUAL(r, 0);
    CU_ASSERT_PTR_NULL(val.s);

    annotatemore_close();

    strarray_fini(&entries);
    strarray_fini(&attribs);
    strarray_fini(&results);
    buf_free(&val);
}


static void test_getset_message_shared(void)
{
    int r;
    annotate_scope_t scope;
    struct mailbox mailbox;
    strarray_t entries = STRARRAY_INITIALIZER;
    strarray_t attribs = STRARRAY_INITIALIZER;
    strarray_t results = STRARRAY_INITIALIZER;
    struct entryattlist *ealist = NULL;
    struct buf val = BUF_INITIALIZER;
    struct buf val2 = BUF_INITIALIZER;

    annotatemore_init(NULL, NULL);

    annotatemore_open();

    memset(&mailbox, 0, sizeof(mailbox));
    mailbox.name = MBOXNAME1_INT;
    mailbox.acl = ACL;
    annotate_scope_init_message(&scope, &mailbox, 42);

    strarray_append(&entries, COMMENT);
    strarray_append(&attribs, VALUE_SHARED);

    /* check that there is no value initially */

    r = annotatemore_fetch(&scope,
		           &entries, &attribs,
		           &namespace, isadmin, userid, auth_state,
		           fetch_cb, &results,
		           NULL);
    CU_ASSERT_EQUAL(r, 0);
    CU_ASSERT_EQUAL_FATAL(results.count, 1);
#define EXPECTED \
	   "mboxname=\"" MBOXNAME1_EXT "\" " \
	   "uid=42 " \
	   "entry=\"" COMMENT "\" " \
	   VALUE_SHARED "=NIL"
    CU_ASSERT_STRING_EQUAL(results.data[0], EXPECTED);
#undef EXPECTED
    strarray_truncate(&results, 0);

    r = annotatemore_msg_lookup(MBOXNAME1_INT, 42, COMMENT, /*userid*/"", &val);
    CU_ASSERT_EQUAL(r, 0);
    CU_ASSERT_PTR_NULL(val.s);

    r = annotatemore_begin();
    CU_ASSERT_EQUAL(r, 0);

    /* set a value */

    buf_appendcstr(&val, VALUE0);
    setentryatt(&ealist, COMMENT, VALUE_SHARED, &val);
    r = annotatemore_store(&scope, ealist,
		           &namespace, isadmin, userid, auth_state);
    CU_ASSERT_EQUAL(r, 0);
    freeentryatts(ealist);
    ealist = NULL;

    /* check that we can fetch the value back in the same txn */
    r = annotatemore_fetch(&scope,
		           &entries, &attribs,
		           &namespace, isadmin, userid, auth_state,
		           fetch_cb, &results,
		           NULL);
    CU_ASSERT_EQUAL(r, 0);
    CU_ASSERT_EQUAL_FATAL(results.count, 1);
#define EXPECTED \
	   "mboxname=\"" MBOXNAME1_EXT "\" " \
	   "uid=42 " \
	   "entry=\"" COMMENT "\" " \
	   VALUE_SHARED "=\"" VALUE0 "\""
    CU_ASSERT_STRING_EQUAL(results.data[0], EXPECTED);
#undef EXPECTED
    strarray_truncate(&results, 0);

    r = annotatemore_msg_lookup(MBOXNAME1_INT, 42, COMMENT, /*userid*/"", &val2);
    CU_ASSERT_EQUAL_FATAL(r, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(val2.s);
    CU_ASSERT_STRING_EQUAL(buf_cstring(&val2), VALUE0);
    buf_free(&val2);

    r = annotatemore_commit();
    CU_ASSERT_EQUAL(r, 0);

    /* check that we can fetch the value back in a new txn */
    r = annotatemore_fetch(&scope,
		           &entries, &attribs,
		           &namespace, isadmin, userid, auth_state,
		           fetch_cb, &results,
		           NULL);
    CU_ASSERT_EQUAL(r, 0);
    CU_ASSERT_EQUAL_FATAL(results.count, 1);
#define EXPECTED \
	   "mboxname=\"" MBOXNAME1_EXT "\" " \
	   "uid=42 " \
	   "entry=\"" COMMENT "\" " \
	   VALUE_SHARED "=\"" VALUE0 "\""
    CU_ASSERT_STRING_EQUAL(results.data[0], EXPECTED);
#undef EXPECTED
    strarray_truncate(&results, 0);

    r = annotatemore_msg_lookup(MBOXNAME1_INT, 42, COMMENT, /*userid*/"", &val2);
    CU_ASSERT_EQUAL_FATAL(r, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(val2.s);
    CU_ASSERT_STRING_EQUAL(buf_cstring(&val2), VALUE0);
    buf_free(&val2);

    annotatemore_close();

    /* check that we can fetch the value back after close and re-open */

    annotatemore_open();

    r = annotatemore_fetch(&scope,
		           &entries, &attribs,
		           &namespace, isadmin, userid, auth_state,
		           fetch_cb, &results,
		           NULL);
    CU_ASSERT_EQUAL(r, 0);
    CU_ASSERT_EQUAL_FATAL(results.count, 1);
#define EXPECTED \
	   "mboxname=\"" MBOXNAME1_EXT "\" " \
	   "uid=42 " \
	   "entry=\"" COMMENT "\" " \
	   VALUE_SHARED "=\"" VALUE0 "\""
    CU_ASSERT_STRING_EQUAL(results.data[0], EXPECTED);
#undef EXPECTED
    strarray_truncate(&results, 0);

    r = annotatemore_msg_lookup(MBOXNAME1_INT, 42, COMMENT, /*userid*/"", &val2);
    CU_ASSERT_EQUAL_FATAL(r, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(val2.s);
    CU_ASSERT_STRING_EQUAL(buf_cstring(&val2), VALUE0);
    buf_free(&val2);

    /* delete the value */

    r = annotatemore_begin();
    CU_ASSERT_EQUAL(r, 0);

    buf_free(&val);
    setentryatt(&ealist, COMMENT, VALUE_SHARED, &val);
    r = annotatemore_store(&scope, ealist,
		           &namespace, isadmin, userid, auth_state);
    CU_ASSERT_EQUAL(r, 0);
    freeentryatts(ealist);
    ealist = NULL;

    r = annotatemore_commit();
    CU_ASSERT_EQUAL(r, 0);

    /* check that there is no value any more */

    r = annotatemore_fetch(&scope,
		           &entries, &attribs,
		           &namespace, isadmin, userid, auth_state,
		           fetch_cb, &results,
		           NULL);
    CU_ASSERT_EQUAL(r, 0);
    CU_ASSERT_EQUAL_FATAL(results.count, 1);
#define EXPECTED \
	   "mboxname=\"" MBOXNAME1_EXT "\" " \
	   "uid=42 " \
	   "entry=\"" COMMENT "\" " \
	   VALUE_SHARED "=NIL"
    CU_ASSERT_STRING_EQUAL(results.data[0], EXPECTED);
#undef EXPECTED
    strarray_truncate(&results, 0);

    buf_free(&val);
    r = annotatemore_msg_lookup(MBOXNAME1_INT, 42, COMMENT, /*userid*/"", &val);
    CU_ASSERT_EQUAL(r, 0);
    CU_ASSERT_PTR_NULL(val.s);


    annotatemore_close();

    strarray_fini(&entries);
    strarray_fini(&attribs);
    strarray_fini(&results);
    buf_free(&val);
}


static void test_delete(void)
{
    int r;
    annotate_scope_t scope;
    struct mailbox mailbox;
    strarray_t entries = STRARRAY_INITIALIZER;
    strarray_t attribs = STRARRAY_INITIALIZER;
    struct entryattlist *ealist = NULL;
    struct buf val = BUF_INITIALIZER;
    struct buf val2 = BUF_INITIALIZER;

    CU_ASSERT_EQUAL(fexists(DBDIR"/data/user/smurf/annotations.db"), -ENOENT);

    annotatemore_init(NULL, NULL);

    annotatemore_open();

    memset(&mailbox, 0, sizeof(mailbox));
    mailbox.name = MBOXNAME1_INT;
    mailbox.acl = ACL;

    strarray_append(&entries, COMMENT);
    strarray_append(&attribs, VALUE_SHARED);

    r = annotatemore_begin();
    CU_ASSERT_EQUAL(r, 0);

    /* set some values */

    buf_appendcstr(&val, VALUE0);
    setentryatt(&ealist, COMMENT, VALUE_SHARED, &val);
    annotate_scope_init_mailbox(&scope, MBOXNAME1_INT);
    r = annotatemore_store(&scope, ealist,
		           &namespace, isadmin, userid, auth_state);
    CU_ASSERT_EQUAL(r, 0);
    freeentryatts(ealist);
    ealist = NULL;

    buf_reset(&val);
    buf_appendcstr(&val, VALUE1);
    setentryatt(&ealist, COMMENT, VALUE_SHARED, &val);
    annotate_scope_init_message(&scope, &mailbox, 42);
    r = annotatemore_store(&scope, ealist,
		           &namespace, isadmin, userid, auth_state);
    CU_ASSERT_EQUAL(r, 0);
    freeentryatts(ealist);
    ealist = NULL;

    buf_reset(&val);
    buf_appendcstr(&val, VALUE2);
    setentryatt(&ealist, COMMENT, VALUE_SHARED, &val);
    annotate_scope_init_message(&scope, &mailbox, 127);
    r = annotatemore_store(&scope, ealist,
		           &namespace, isadmin, userid, auth_state);
    CU_ASSERT_EQUAL(r, 0);
    freeentryatts(ealist);
    ealist = NULL;

    r = annotatemore_commit();
    CU_ASSERT_EQUAL(r, 0);

    /* check that we can fetch the values back */

    r = annotatemore_msg_lookup(MBOXNAME1_INT, 0, COMMENT, /*userid*/"", &val2);
    CU_ASSERT_EQUAL_FATAL(r, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(val2.s);
    CU_ASSERT_STRING_EQUAL(buf_cstring(&val2), VALUE0);
    buf_free(&val2);

    r = annotatemore_msg_lookup(MBOXNAME1_INT, 42, COMMENT, /*userid*/"", &val2);
    CU_ASSERT_EQUAL_FATAL(r, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(val2.s);
    CU_ASSERT_STRING_EQUAL(buf_cstring(&val2), VALUE1);
    buf_free(&val2);

    r = annotatemore_msg_lookup(MBOXNAME1_INT, 127, COMMENT, /*userid*/"", &val2);
    CU_ASSERT_EQUAL_FATAL(r, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(val2.s);
    CU_ASSERT_STRING_EQUAL(buf_cstring(&val2), VALUE2);
    buf_free(&val2);

    CU_ASSERT_EQUAL(fexists(DBDIR"/data/user/smurf/annotations.db"), 0);

    /* delete all the entries associated with the mailbox */

    r = annotatemore_delete(MBOXNAME1_INT);
    CU_ASSERT_EQUAL(r, 0);

    CU_ASSERT_EQUAL(fexists(DBDIR"/data/user/smurf/annotations.db"), -ENOENT);

    /* check that the values are gone */

    r = annotatemore_msg_lookup(MBOXNAME1_INT, 0, COMMENT, /*userid*/"", &val2);
    CU_ASSERT_EQUAL_FATAL(r, 0);
    CU_ASSERT_PTR_NULL_FATAL(val2.s);
    buf_free(&val2);

    r = annotatemore_msg_lookup(MBOXNAME1_INT, 42, COMMENT, /*userid*/"", &val2);
    CU_ASSERT_EQUAL_FATAL(r, 0);
    CU_ASSERT_PTR_NULL_FATAL(val2.s);
    buf_free(&val2);

    r = annotatemore_msg_lookup(MBOXNAME1_INT, 127, COMMENT, /*userid*/"", &val2);
    CU_ASSERT_EQUAL_FATAL(r, 0);
    CU_ASSERT_PTR_NULL_FATAL(val2.s);
    buf_free(&val2);

    annotatemore_close();

    CU_ASSERT_EQUAL(fexists(DBDIR"/data/user/smurf/annotations.db"), -ENOENT);

    strarray_fini(&entries);
    strarray_fini(&attribs);
    buf_free(&val);
}

static void test_rename(void)
{
    int r;
    annotate_scope_t scope;
    struct mailbox mailbox;
    strarray_t entries = STRARRAY_INITIALIZER;
    strarray_t attribs = STRARRAY_INITIALIZER;
    struct entryattlist *ealist = NULL;
    struct buf val = BUF_INITIALIZER;
    struct buf val2 = BUF_INITIALIZER;

    annotatemore_init(NULL, NULL);

    annotatemore_open();

    CU_ASSERT_EQUAL(fexists(DBDIR"/data/user/smurf/annotations.db"), -ENOENT);
    CU_ASSERT_EQUAL(fexists(DBDIR"/data/user/smurfette/annotations.db"), -ENOENT);

    memset(&mailbox, 0, sizeof(mailbox));
    mailbox.name = MBOXNAME1_INT;
    mailbox.acl = ACL;

    strarray_append(&entries, COMMENT);
    strarray_append(&attribs, VALUE_SHARED);

    r = annotatemore_begin();
    CU_ASSERT_EQUAL(r, 0);

    /* set some values */

    buf_appendcstr(&val, VALUE0);
    setentryatt(&ealist, COMMENT, VALUE_SHARED, &val);
    annotate_scope_init_mailbox(&scope, MBOXNAME1_INT);
    r = annotatemore_store(&scope, ealist,
		           &namespace, isadmin, userid, auth_state);
    CU_ASSERT_EQUAL(r, 0);
    freeentryatts(ealist);
    ealist = NULL;

    buf_reset(&val);
    buf_appendcstr(&val, VALUE1);
    setentryatt(&ealist, COMMENT, VALUE_SHARED, &val);
    annotate_scope_init_message(&scope, &mailbox, 42);
    r = annotatemore_store(&scope, ealist,
		           &namespace, isadmin, userid, auth_state);
    CU_ASSERT_EQUAL(r, 0);
    freeentryatts(ealist);
    ealist = NULL;

    buf_reset(&val);
    buf_appendcstr(&val, VALUE2);
    setentryatt(&ealist, COMMENT, VALUE_SHARED, &val);
    annotate_scope_init_message(&scope, &mailbox, 127);
    r = annotatemore_store(&scope, ealist,
		           &namespace, isadmin, userid, auth_state);
    CU_ASSERT_EQUAL(r, 0);
    freeentryatts(ealist);
    ealist = NULL;

    r = annotatemore_commit();
    CU_ASSERT_EQUAL(r, 0);

    /* check that we can fetch the values back */

    r = annotatemore_msg_lookup(MBOXNAME1_INT, 0, COMMENT, /*userid*/"", &val2);
    CU_ASSERT_EQUAL_FATAL(r, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(val2.s);
    CU_ASSERT_STRING_EQUAL(buf_cstring(&val2), VALUE0);
    buf_free(&val2);

    r = annotatemore_msg_lookup(MBOXNAME1_INT, 42, COMMENT, /*userid*/"", &val2);
    CU_ASSERT_EQUAL_FATAL(r, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(val2.s);
    CU_ASSERT_STRING_EQUAL(buf_cstring(&val2), VALUE1);
    buf_free(&val2);

    r = annotatemore_msg_lookup(MBOXNAME1_INT, 127, COMMENT, /*userid*/"", &val2);
    CU_ASSERT_EQUAL_FATAL(r, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(val2.s);
    CU_ASSERT_STRING_EQUAL(buf_cstring(&val2), VALUE2);
    buf_free(&val2);

    CU_ASSERT_EQUAL(fexists(DBDIR"/data/user/smurf/annotations.db"), 0);
    CU_ASSERT_EQUAL(fexists(DBDIR"/data/user/smurfette/annotations.db"), -ENOENT);

    /* rename MBOXNAME1 -> MBOXNAME2 */

    r = annotatemore_rename(MBOXNAME1_INT, MBOXNAME2_INT,
			    "smurf", "smurfette");
    CU_ASSERT_EQUAL(r, 0);

    CU_ASSERT_EQUAL(fexists(DBDIR"/data/user/smurf/annotations.db"), -ENOENT);
    CU_ASSERT_EQUAL(fexists(DBDIR"/data/user/smurfette/annotations.db"), 0);

    /* check that the values are gone under the old name */

    r = annotatemore_msg_lookup(MBOXNAME1_INT, 0, COMMENT, /*userid*/"", &val2);
    CU_ASSERT_EQUAL_FATAL(r, 0);
    CU_ASSERT_PTR_NULL_FATAL(val2.s);
    buf_free(&val2);

    r = annotatemore_msg_lookup(MBOXNAME1_INT, 42, COMMENT, /*userid*/"", &val2);
    CU_ASSERT_EQUAL_FATAL(r, 0);
    CU_ASSERT_PTR_NULL_FATAL(val2.s);
    buf_free(&val2);

    r = annotatemore_msg_lookup(MBOXNAME1_INT, 127, COMMENT, /*userid*/"", &val2);
    CU_ASSERT_EQUAL_FATAL(r, 0);
    CU_ASSERT_PTR_NULL_FATAL(val2.s);
    buf_free(&val2);

    /* check that the values are present under the new name */

    r = annotatemore_msg_lookup(MBOXNAME2_INT, 0, COMMENT, /*userid*/"", &val2);
    CU_ASSERT_EQUAL_FATAL(r, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(val2.s);
    CU_ASSERT_STRING_EQUAL(buf_cstring(&val2), VALUE0);
    buf_free(&val2);

    r = annotatemore_msg_lookup(MBOXNAME2_INT, 42, COMMENT, /*userid*/"", &val2);
    CU_ASSERT_EQUAL_FATAL(r, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(val2.s);
    CU_ASSERT_STRING_EQUAL(buf_cstring(&val2), VALUE1);
    buf_free(&val2);

    r = annotatemore_msg_lookup(MBOXNAME2_INT, 127, COMMENT, /*userid*/"", &val2);
    CU_ASSERT_EQUAL_FATAL(r, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(val2.s);
    CU_ASSERT_STRING_EQUAL(buf_cstring(&val2), VALUE2);
    buf_free(&val2);

    CU_ASSERT_EQUAL(fexists(DBDIR"/data/user/smurf/annotations.db"), -ENOENT);
    CU_ASSERT_EQUAL(fexists(DBDIR"/data/user/smurfette/annotations.db"), 0);

    annotatemore_close();

    strarray_fini(&entries);
    strarray_fini(&attribs);
    buf_free(&val);
}

static void test_abort(void)
{
    int r;
    annotate_scope_t scope;
    struct mailbox mailbox;
    strarray_t entries = STRARRAY_INITIALIZER;
    strarray_t attribs = STRARRAY_INITIALIZER;
    struct entryattlist *ealist = NULL;
    struct buf val = BUF_INITIALIZER;
    struct buf val2 = BUF_INITIALIZER;

    annotatemore_init(NULL, NULL);

    annotatemore_open();

    memset(&mailbox, 0, sizeof(mailbox));
    mailbox.name = MBOXNAME1_INT;
    mailbox.acl = ACL;

    strarray_append(&entries, COMMENT);
    strarray_append(&attribs, VALUE_SHARED);

    /* check that the values we'll be setting are not already present */

    buf_free(&val2);
    r = annotatemore_msg_lookup("", 0, COMMENT, /*userid*/"", &val2);
    CU_ASSERT_EQUAL_FATAL(r, 0);
    CU_ASSERT_PTR_NULL_FATAL(val2.s);

    buf_free(&val2);
    r = annotatemore_msg_lookup(MBOXNAME1_INT, 0, COMMENT, /*userid*/"", &val2);
    CU_ASSERT_EQUAL_FATAL(r, 0);
    CU_ASSERT_PTR_NULL_FATAL(val2.s);

    buf_free(&val2);
    r = annotatemore_msg_lookup(MBOXNAME1_INT, 42, COMMENT, /*userid*/"", &val2);
    CU_ASSERT_EQUAL_FATAL(r, 0);
    CU_ASSERT_PTR_NULL_FATAL(val2.s);

    /* set some values */

    r = annotatemore_begin();
    CU_ASSERT_EQUAL(r, 0);

    buf_appendcstr(&val, VALUE0);
    setentryatt(&ealist, COMMENT, VALUE_SHARED, &val);
    annotate_scope_init_server(&scope);
    isadmin = 1;
    r = annotatemore_store(&scope, ealist,
		           &namespace, isadmin, userid, auth_state);
    isadmin = 0;
    CU_ASSERT_EQUAL(r, 0);
    freeentryatts(ealist);
    ealist = NULL;

    buf_appendcstr(&val, VALUE0);
    setentryatt(&ealist, COMMENT, VALUE_SHARED, &val);
    annotate_scope_init_mailbox(&scope, MBOXNAME1_INT);
    r = annotatemore_store(&scope, ealist,
		           &namespace, isadmin, userid, auth_state);
    CU_ASSERT_EQUAL(r, 0);
    freeentryatts(ealist);
    ealist = NULL;

    buf_reset(&val);
    buf_appendcstr(&val, VALUE1);
    setentryatt(&ealist, COMMENT, VALUE_SHARED, &val);
    annotate_scope_init_message(&scope, &mailbox, 42);
    r = annotatemore_store(&scope, ealist,
		           &namespace, isadmin, userid, auth_state);
    CU_ASSERT_EQUAL(r, 0);
    freeentryatts(ealist);
    ealist = NULL;

    /* abort the txn */

    annotatemore_abort();

    /* check that the values are still not present */

    buf_free(&val2);
    r = annotatemore_msg_lookup("", 0, COMMENT, /*userid*/"", &val2);
    CU_ASSERT_EQUAL_FATAL(r, 0);
    CU_ASSERT_PTR_NULL_FATAL(val2.s);

    buf_free(&val2);
    r = annotatemore_msg_lookup(MBOXNAME1_INT, 0, COMMENT, /*userid*/"", &val2);
    CU_ASSERT_EQUAL_FATAL(r, 0);
    CU_ASSERT_PTR_NULL_FATAL(val2.s);

    buf_free(&val2);
    r = annotatemore_msg_lookup(MBOXNAME1_INT, 42, COMMENT, /*userid*/"", &val2);
    CU_ASSERT_EQUAL_FATAL(r, 0);
    CU_ASSERT_PTR_NULL_FATAL(val2.s);

    annotatemore_close();

    strarray_fini(&entries);
    strarray_fini(&attribs);
    buf_free(&val);
    buf_free(&val2);
}


static void test_msg_copy(void)
{
    int r;
    annotate_scope_t scope;
    struct mailbox mailbox;
    strarray_t entries = STRARRAY_INITIALIZER;
    strarray_t attribs = STRARRAY_INITIALIZER;
    struct entryattlist *ealist = NULL;
    struct buf val = BUF_INITIALIZER;
    struct buf val2 = BUF_INITIALIZER;

    annotatemore_init(NULL, NULL);

    annotatemore_open();

    CU_ASSERT_EQUAL(fexists(DBDIR"/data/user/smurf/annotations.db"), -ENOENT);
    CU_ASSERT_EQUAL(fexists(DBDIR"/data/user/smurfette/annotations.db"), -ENOENT);

    memset(&mailbox, 0, sizeof(mailbox));
    mailbox.name = MBOXNAME1_INT;
    mailbox.acl = ACL;

    strarray_append(&entries, COMMENT);
    strarray_append(&attribs, VALUE_SHARED);

    r = annotatemore_begin();
    CU_ASSERT_EQUAL(r, 0);

    /* set some values */

    buf_appendcstr(&val, VALUE0);
    setentryatt(&ealist, COMMENT, VALUE_SHARED, &val);
    annotate_scope_init_message(&scope, &mailbox, 17);
    r = annotatemore_store(&scope, ealist,
		           &namespace, isadmin, userid, auth_state);
    CU_ASSERT_EQUAL(r, 0);
    freeentryatts(ealist);
    ealist = NULL;

    buf_reset(&val);
    buf_appendcstr(&val, VALUE1);
    setentryatt(&ealist, COMMENT, VALUE_SHARED, &val);
    annotate_scope_init_message(&scope, &mailbox, 42);
    r = annotatemore_store(&scope, ealist,
		           &namespace, isadmin, userid, auth_state);
    CU_ASSERT_EQUAL(r, 0);
    freeentryatts(ealist);
    ealist = NULL;

    buf_reset(&val);
    buf_appendcstr(&val, VALUE2);
    setentryatt(&ealist, COMMENT, VALUE_SHARED, &val);
    annotate_scope_init_message(&scope, &mailbox, 127);
    r = annotatemore_store(&scope, ealist,
		           &namespace, isadmin, userid, auth_state);
    CU_ASSERT_EQUAL(r, 0);
    freeentryatts(ealist);
    ealist = NULL;

    r = annotatemore_commit();
    CU_ASSERT_EQUAL(r, 0);

    /* check that we can fetch the values back */

    buf_free(&val2);
    r = annotatemore_msg_lookup(MBOXNAME1_INT, 17, COMMENT, /*userid*/"", &val2);
    CU_ASSERT_EQUAL_FATAL(r, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(val2.s);
    CU_ASSERT_STRING_EQUAL(buf_cstring(&val2), VALUE0);

    buf_free(&val2);
    r = annotatemore_msg_lookup(MBOXNAME1_INT, 42, COMMENT, /*userid*/"", &val2);
    CU_ASSERT_EQUAL_FATAL(r, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(val2.s);
    CU_ASSERT_STRING_EQUAL(buf_cstring(&val2), VALUE1);

    buf_free(&val2);
    r = annotatemore_msg_lookup(MBOXNAME1_INT, 127, COMMENT, /*userid*/"", &val2);
    CU_ASSERT_EQUAL_FATAL(r, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(val2.s);
    CU_ASSERT_STRING_EQUAL(buf_cstring(&val2), VALUE2);

    buf_free(&val2);
    r = annotatemore_msg_lookup(MBOXNAME2_INT, 35, COMMENT, /*userid*/"", &val2);
    CU_ASSERT_EQUAL_FATAL(r, 0);
    CU_ASSERT_PTR_NULL_FATAL(val2.s);

    CU_ASSERT_EQUAL(fexists(DBDIR"/data/user/smurf/annotations.db"), 0);
    CU_ASSERT_EQUAL(fexists(DBDIR"/data/user/smurfette/annotations.db"), -ENOENT);

    /* copy MBOXNAME1,17 -> MBOXNAME2,35 */

    r = annotatemore_begin();
    CU_ASSERT_EQUAL(r, 0);

    r = annotate_msg_copy(MBOXNAME1_INT, 17, MBOXNAME2_INT, 35, "smurf");
    CU_ASSERT_EQUAL(r, 0);

    r = annotatemore_commit();
    CU_ASSERT_EQUAL(r, 0);

    CU_ASSERT_EQUAL(fexists(DBDIR"/data/user/smurf/annotations.db"), 0);
    CU_ASSERT_EQUAL(fexists(DBDIR"/data/user/smurfette/annotations.db"), 0);

    /* check that the values copied are present for both mailboxes */

    buf_free(&val2);
    r = annotatemore_msg_lookup(MBOXNAME1_INT, 17, COMMENT, /*userid*/"", &val2);
    CU_ASSERT_EQUAL_FATAL(r, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(val2.s);
    CU_ASSERT_STRING_EQUAL(buf_cstring(&val2), VALUE0);

    buf_free(&val2);
    r = annotatemore_msg_lookup(MBOXNAME2_INT, 35, COMMENT, /*userid*/"", &val2);
    CU_ASSERT_EQUAL_FATAL(r, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(val2.s);
    CU_ASSERT_STRING_EQUAL(buf_cstring(&val2), VALUE0);

    /* check that the values not copied are only present in the source
     * mailbox */

    buf_free(&val2);
    r = annotatemore_msg_lookup(MBOXNAME1_INT, 42, COMMENT, /*userid*/"", &val2);
    CU_ASSERT_EQUAL_FATAL(r, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(val2.s);
    CU_ASSERT_STRING_EQUAL(buf_cstring(&val2), VALUE1);

    buf_free(&val2);
    r = annotatemore_msg_lookup(MBOXNAME1_INT, 127, COMMENT, /*userid*/"", &val2);
    CU_ASSERT_EQUAL_FATAL(r, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(val2.s);
    CU_ASSERT_STRING_EQUAL(buf_cstring(&val2), VALUE2);

    buf_free(&val2);
    r = annotatemore_msg_lookup(MBOXNAME2_INT, 42, COMMENT, /*userid*/"", &val2);
    CU_ASSERT_EQUAL_FATAL(r, 0);
    CU_ASSERT_PTR_NULL(val2.s);

    buf_free(&val2);
    r = annotatemore_msg_lookup(MBOXNAME2_INT, 127, COMMENT, /*userid*/"", &val2);
    CU_ASSERT_EQUAL_FATAL(r, 0);
    CU_ASSERT_PTR_NULL(val2.s);

    CU_ASSERT_EQUAL(fexists(DBDIR"/data/user/smurf/annotations.db"), 0);
    CU_ASSERT_EQUAL(fexists(DBDIR"/data/user/smurfette/annotations.db"), 0);

    annotatemore_close();

    strarray_fini(&entries);
    strarray_fini(&attribs);
    buf_free(&val);
    buf_free(&val2);
}

// static void test_missing_definitions_file(void)
// {
//     char *old;
// 
//     old = imapopts[IMAPOPT_ANNOTATION_DEFINITIONS].val.s;
//     imapopts[IMAPOPT_ANNOTATION_DEFINITIONS].val.s = "/no/such/file";
// 
//     annotatemore_init(NULL, NULL);
//     imapopts[IMAPOPT_ANNOTATION_DEFINITIONS].val.s = old;
// }

static void test_getset_server_undefined(void)
{
    int r;
    annotate_scope_t scope;
    strarray_t entries = STRARRAY_INITIALIZER;
    strarray_t attribs = STRARRAY_INITIALIZER;
    strarray_t results = STRARRAY_INITIALIZER;
    struct entryattlist *ealist = NULL;
    struct buf val = BUF_INITIALIZER;
    struct buf val2 = BUF_INITIALIZER;

    annotatemore_init(NULL, NULL);

    annotatemore_open();

    annotate_scope_init_server(&scope);

    strarray_append(&entries, EXENTRY);
    strarray_append(&attribs, VALUE_SHARED);

    /* check that there is no value initially */

    r = annotatemore_fetch(&scope,
		           &entries, &attribs,
		           &namespace, isadmin, userid, auth_state,
		           fetch_cb, &results,
		           NULL);
    CU_ASSERT_EQUAL(r, 0);
    CU_ASSERT_EQUAL_FATAL(results.count, 1);
#define EXPECTED \
	   "mboxname=\"\" " \
	   "uid=0 " \
	   "entry=\"" EXENTRY "\" " \
	   VALUE_SHARED "=NIL"
    CU_ASSERT_STRING_EQUAL(results.data[0], EXPECTED);
#undef EXPECTED
    strarray_truncate(&results, 0);

    r = annotatemore_lookup(/*mboxname*/"", EXENTRY, /*userid*/"", &val);
    CU_ASSERT_EQUAL(r, 0);
    CU_ASSERT_PTR_NULL(val.s);

    r = annotatemore_begin();
    CU_ASSERT_EQUAL(r, 0);

    /* setting a value should fail */

    buf_appendcstr(&val, VALUE0);
    setentryatt(&ealist, EXENTRY, VALUE_SHARED, &val);
    isadmin = 1;	/* pretend to be admin */
    r = annotatemore_store(&scope, ealist,
		           &namespace, isadmin, userid, auth_state);
    isadmin = 0;
    CU_ASSERT_EQUAL(r, IMAP_PERMISSION_DENIED);
    freeentryatts(ealist);
    ealist = NULL;

    r = annotatemore_commit();
    CU_ASSERT_EQUAL(r, 0);

    /* check that there is no value */

    r = annotatemore_fetch(&scope,
		           &entries, &attribs,
		           &namespace, isadmin, userid, auth_state,
		           fetch_cb, &results,
		           NULL);
    CU_ASSERT_EQUAL(r, 0);
    CU_ASSERT_EQUAL_FATAL(results.count, 1);
#define EXPECTED \
	   "mboxname=\"\" " \
	   "uid=0 " \
	   "entry=\"" EXENTRY "\" " \
	   VALUE_SHARED "=NIL"
    CU_ASSERT_STRING_EQUAL(results.data[0], EXPECTED);
#undef EXPECTED
    strarray_truncate(&results, 0);

    buf_free(&val);
    r = annotatemore_lookup(/*mboxname*/"", EXENTRY, /*userid*/"", &val);
    CU_ASSERT_EQUAL(r, 0);
    CU_ASSERT_PTR_NULL(val.s);

    annotatemore_close();

    strarray_fini(&entries);
    strarray_fini(&attribs);
    strarray_fini(&results);
    buf_free(&val);
    buf_free(&val2);
}


static void test_getset_server_defined(void)
{
    int r;
    annotate_scope_t scope;
    strarray_t entries = STRARRAY_INITIALIZER;
    strarray_t attribs = STRARRAY_INITIALIZER;
    strarray_t results = STRARRAY_INITIALIZER;
    struct entryattlist *ealist = NULL;
    struct buf val = BUF_INITIALIZER;
    struct buf val2 = BUF_INITIALIZER;

    set_annotation_definitions(
	EXENTRY",server,string,backend,value.shared,\n");
    annotatemore_init(NULL, NULL);

    annotatemore_open();

    annotate_scope_init_server(&scope);

    strarray_append(&entries, EXENTRY);
    strarray_append(&attribs, VALUE_SHARED);
    strarray_append(&attribs, SIZE_SHARED);

    /* check that there is no value initially */

    r = annotatemore_fetch(&scope,
		           &entries, &attribs,
		           &namespace, isadmin, userid, auth_state,
		           fetch_cb, &results,
		           NULL);
    CU_ASSERT_EQUAL(r, 0);
    CU_ASSERT_EQUAL_FATAL(results.count, 1);
#define EXPECTED \
	   "mboxname=\"\" " \
	   "uid=0 " \
	   "entry=\"" EXENTRY "\" " \
	   VALUE_SHARED "=NIL " \
	   SIZE_SHARED "=\"0\""
    CU_ASSERT_STRING_EQUAL(results.data[0], EXPECTED);
#undef EXPECTED
    strarray_truncate(&results, 0);

    r = annotatemore_lookup(/*mboxname*/"", EXENTRY, /*userid*/"", &val);
    CU_ASSERT_EQUAL(r, 0);
    CU_ASSERT_PTR_NULL(val.s);

    r = annotatemore_begin();
    CU_ASSERT_EQUAL(r, 0);

    /* set a value */

    buf_appendcstr(&val, VALUE0);
    setentryatt(&ealist, EXENTRY, VALUE_SHARED, &val);
    isadmin = 1;	/* pretend to be admin */
    r = annotatemore_store(&scope, ealist,
		           &namespace, isadmin, userid, auth_state);
    isadmin = 0;
    CU_ASSERT_EQUAL(r, 0);
    freeentryatts(ealist);
    ealist = NULL;

    /* check that we can fetch the value back in the same txn */
    r = annotatemore_fetch(&scope,
		           &entries, &attribs,
		           &namespace, isadmin, userid, auth_state,
		           fetch_cb, &results,
		           NULL);
    CU_ASSERT_EQUAL(r, 0);
    CU_ASSERT_EQUAL_FATAL(results.count, 1);
#define EXPECTED \
	   "mboxname=\"\" " \
	   "uid=0 " \
	   "entry=\"" EXENTRY "\" " \
	   VALUE_SHARED "=\"" VALUE0 "\" " \
	   SIZE_SHARED "=\"" LENGTH0 "\""
    CU_ASSERT_STRING_EQUAL(results.data[0], EXPECTED);
#undef EXPECTED
    strarray_truncate(&results, 0);

    r = annotatemore_lookup(/*mboxname*/"", EXENTRY, /*userid*/"", &val2);
    CU_ASSERT_EQUAL_FATAL(r, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(val2.s);
    CU_ASSERT_STRING_EQUAL(buf_cstring(&val2), VALUE0);
    buf_free(&val2);

    r = annotatemore_commit();
    CU_ASSERT_EQUAL(r, 0);

    /* check that we can fetch the value back in a new txn */
    r = annotatemore_fetch(&scope,
		           &entries, &attribs,
		           &namespace, isadmin, userid, auth_state,
		           fetch_cb, &results,
		           NULL);
    CU_ASSERT_EQUAL(r, 0);
    CU_ASSERT_EQUAL_FATAL(results.count, 1);
#define EXPECTED \
	   "mboxname=\"\" " \
	   "uid=0 " \
	   "entry=\"" EXENTRY "\" " \
	   VALUE_SHARED "=\"" VALUE0 "\" " \
	   SIZE_SHARED "=\"" LENGTH0 "\""
    CU_ASSERT_STRING_EQUAL(results.data[0], EXPECTED);
#undef EXPECTED
    strarray_truncate(&results, 0);

    r = annotatemore_lookup(/*mboxname*/"", EXENTRY, /*userid*/"", &val2);
    CU_ASSERT_EQUAL_FATAL(r, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(val2.s);
    CU_ASSERT_STRING_EQUAL(buf_cstring(&val2), VALUE0);
    buf_free(&val2);

    annotatemore_close();

    /* check that we can fetch the value back after close and re-open */

    annotatemore_open();

    r = annotatemore_fetch(&scope,
		           &entries, &attribs,
		           &namespace, isadmin, userid, auth_state,
		           fetch_cb, &results,
		           NULL);
    CU_ASSERT_EQUAL(r, 0);
    CU_ASSERT_EQUAL_FATAL(results.count, 1);
#define EXPECTED \
	   "mboxname=\"\" " \
	   "uid=0 " \
	   "entry=\"" EXENTRY "\" " \
	   VALUE_SHARED "=\"" VALUE0 "\" " \
	   SIZE_SHARED "=\"" LENGTH0 "\""
    CU_ASSERT_STRING_EQUAL(results.data[0], EXPECTED);
#undef EXPECTED
    strarray_truncate(&results, 0);

    r = annotatemore_lookup(/*mboxname*/"", EXENTRY, /*userid*/"", &val2);
    CU_ASSERT_EQUAL_FATAL(r, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(val2.s);
    CU_ASSERT_STRING_EQUAL(buf_cstring(&val2), VALUE0);
    buf_free(&val2);

    /* delete the value */

    r = annotatemore_begin();
    CU_ASSERT_EQUAL(r, 0);

    buf_free(&val);
    setentryatt(&ealist, EXENTRY, VALUE_SHARED, &val);
    isadmin = 1;	/* pretend to be admin */
    r = annotatemore_store(&scope, ealist,
		           &namespace, isadmin, userid, auth_state);
    isadmin = 0;
    CU_ASSERT_EQUAL(r, 0);
    freeentryatts(ealist);
    ealist = NULL;

    r = annotatemore_commit();
    CU_ASSERT_EQUAL(r, 0);

    /* check that there is no value any more */

    r = annotatemore_fetch(&scope,
		           &entries, &attribs,
		           &namespace, isadmin, userid, auth_state,
		           fetch_cb, &results,
		           NULL);
    CU_ASSERT_EQUAL(r, 0);
    CU_ASSERT_EQUAL_FATAL(results.count, 1);
#define EXPECTED \
	   "mboxname=\"\" " \
	   "uid=0 " \
	   "entry=\"" EXENTRY "\" " \
	   VALUE_SHARED "=NIL " \
	   SIZE_SHARED "=\"0\""
    CU_ASSERT_STRING_EQUAL(results.data[0], EXPECTED);
#undef EXPECTED
    strarray_truncate(&results, 0);

    r = annotatemore_lookup(/*mboxname*/"", EXENTRY, /*userid*/"", &val);
    CU_ASSERT_EQUAL(r, 0);
    CU_ASSERT_PTR_NULL(val.s);


    annotatemore_close();

    strarray_fini(&entries);
    strarray_fini(&attribs);
    strarray_fini(&results);
    buf_free(&val);
}



static int set_up(void)
{
    int r;
    struct mboxlist_entry mbentry;
    const char * const *d;
    static const char * const dirs[] = {
	DBDIR,
	DBDIR"/db",
	DBDIR"/conf",
	DBDIR"/data",
	DBDIR"/data/user",
	DBDIR"/data/user/smurf",
	DBDIR"/data/user/smurfette",
	NULL
    };

    r = system("rm -rf " DBDIR);
    if (r)
	return r;
    r = fexists(DBDIR);
    if (r != -ENOENT)
	return ENOTDIR;

    for (d = dirs ; *d ; d++) {
	r = mkdir(*d, 0777);
	if (r < 0) {
	    int e = errno;
	    perror(*d);
	    return e;
	}
    }

    libcyrus_config_setstring(CYRUSOPT_CONFIG_DIR, DBDIR);
    config_read_string(
	"configdirectory: "DBDIR"/conf\n"
	"defaultpartition: "PARTITION"\n"
	"partition-"PARTITION": "DBDIR"/data\n"
    );

    cyrusdb_init();
    config_mboxlist_db = cyrusdb_fromname("skiplist");
    config_annotation_db = cyrusdb_fromname("skiplist");

    userid = "smurf";
    isadmin = 0;
    auth_state = auth_newstate(userid);
    mboxname_init_namespace(&namespace, isadmin);

    mboxlist_init(0);
    mboxlist_open(NULL);

    memset(&mbentry, 0, sizeof(mbentry));
    mbentry.name = MBOXNAME1_INT;
    mbentry.mbtype = 0;
    mbentry.partition = PARTITION;
    mbentry.acl = ACL;
    r = mboxlist_update(&mbentry, /*localonly*/1);

    memset(&mbentry, 0, sizeof(mbentry));
    mbentry.name = MBOXNAME2_INT;
    mbentry.mbtype = 0;
    mbentry.partition = PARTITION;
    mbentry.acl = ACL;
    r = mboxlist_update(&mbentry, /*localonly*/1);

    old_annotation_definitions =
	imapopts[IMAPOPT_ANNOTATION_DEFINITIONS].val.s;

    return 0;
}

static int tear_down(void)
{
    int r;

    mboxlist_close();
    mboxlist_done();

    annotatemore_done();

    imapopts[IMAPOPT_ANNOTATION_DEFINITIONS].val.s =
	old_annotation_definitions;

    auth_freestate(auth_state);

    cyrusdb_done();
    config_mboxlist_db = NULL;
    config_annotation_db = NULL;

    r = system("rm -rf " DBDIR);
    /* I'm ignoring you */

    return 0;
}

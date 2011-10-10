#include "config.h"
#include "cunit/cunit.h"
#include "xmalloc.h"
#include "global.h"
#include "retry.h"
#include "cyrusdb.h"
#include "libcyr_cfg.h"
#include "util.h"
#include "hash.h"

#define DBDIR	    "test-mb-dbdir"

struct binary_result
{
    struct binary_result *next;
    char *key;
    size_t keylen;
    char *data;
    size_t datalen;
};

static char *backend = CUNIT_PARAM("skiplist,flat,berkeley");
static struct cyrusdb_backend *DB;
static char *filename;
static char *filename2;

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

static int fexists(const char *fname)
{
    struct stat sb;
    int r;

    r = stat(fname, &sb);
    if (r < 0)
	r = -errno;
    return r;
}

static char *make_basedir(const char * const *reldirs)
{
    int r;
    int unique = 0;
    const char *tmpdir;
    char *basedir;
    char path[PATH_MAX];
    const char * const *d;

    tmpdir = getenv("TMPDIR");
    if (!tmpdir)
	tmpdir = "/tmp";

    for (;;) {
	if (unique)
	    snprintf(path, sizeof(path), "%s/cunit-db-test.%d.%d", tmpdir, getpid(), unique);
	else
	    snprintf(path, sizeof(path), "%s/cunit-db-test.%d", tmpdir, getpid());

	r = mkdir(path, 0700);
	if (!r)
	    break;	/* success! */
	if (errno != EEXIST) {
	    perror(path);
	    return NULL;
	}
	unique++;
    }
    basedir = xstrdup(path);

    for (d = reldirs ; *d ; d++) {
	snprintf(path, sizeof(path), "%s/%s", basedir, *d);
	r = mkdir(path, 0700);
	if (r < 0) {
	    perror(path);
	    free(basedir);
	    return NULL;
	}
    }

    return basedir;
}

#define CANSTORE(key, keylen, data, datalen) \
    r = DB->store(db, key, keylen, data, datalen, &txn); \
    CU_ASSERT_EQUAL(r, CYRUSDB_OK); \
    CU_ASSERT_PTR_NOT_NULL(txn);

#define CANNOTSTORE(key, keylen, data, datalen) \
    r = DB->store(db, key, keylen, data, datalen, &txn); \
    CU_ASSERT_EQUAL(r, CYRUSDB_BADPARAM); \
    CU_ASSERT_PTR_NOT_NULL(txn);

#define BADDATA		((const char *)0xdeadbeef)
#define BADLEN		((int)0xcafebabe)

#define CANFETCH(key, keylen, expdata, expdatalen) \
{ \
    const char *_data = BADDATA; \
    size_t _datalen = BADLEN; \
    r = DB->fetch(db, key, keylen, &_data, &_datalen, &txn); \
    CU_ASSERT_EQUAL(r, CYRUSDB_OK); \
    CU_ASSERT_PTR_NOT_NULL(txn); \
    CU_ASSERT_PTR_NOT_NULL(_data); \
    CU_ASSERT_PTR_NOT_EQUAL(_data, BADDATA); \
    CU_ASSERT_PTR_NOT_EQUAL(_data, expdata); \
    CU_ASSERT_NOT_EQUAL(_datalen, BADLEN); \
    CU_ASSERT_EQUAL(_datalen, expdatalen); \
    CU_ASSERT(!memcmp(_data, expdata, _datalen)); \
}

#define CANNOTFETCH(key, keylen, experror) \
{ \
    const char *_data = BADDATA; \
    size_t _datalen = BADLEN; \
    r = DB->fetch(db, key, keylen, &_data, &_datalen, &txn); \
    CU_ASSERT_EQUAL(r, experror); \
    CU_ASSERT_PTR_NOT_NULL(txn); \
    CU_ASSERT_PTR_NULL(_data); \
    CU_ASSERT_PTR_NOT_EQUAL(_data, BADDATA); \
    CU_ASSERT_EQUAL(_datalen, 0); \
    CU_ASSERT_NOT_EQUAL(_datalen, BADLEN); \
}

#define CANCOMMIT() \
    r = DB->commit(db, txn); \
    CU_ASSERT_EQUAL(r, CYRUSDB_OK); \
    txn = NULL;

#define CANREOPEN() \
    r = DB->close(db); \
    db = NULL; \
    CU_ASSERT_EQUAL(r, CYRUSDB_OK); \
    r = DB->open(filename, 0, &db); \
    CU_ASSERT_EQUAL(r, CYRUSDB_OK); \
    CU_ASSERT_PTR_NOT_NULL(db);

#define GOTRESULT(expkey, expkeylen, expdata, expdatalen) \
{ \
    const char *_key = (expkey); \
    size_t _keylen = (expkeylen); \
    const char *_data = (expdata); \
    size_t _datalen = (expdatalen); \
    struct binary_result *actual = results; \
    CU_ASSERT_PTR_NOT_NULL_FATAL(results); \
    results = results->next; \
    CU_ASSERT_EQUAL(_keylen, actual->keylen); \
    CU_ASSERT_EQUAL(0, memcmp(_data, actual->data, _datalen)); \
    CU_ASSERT_EQUAL(_datalen, actual->datalen); \
    CU_ASSERT_EQUAL(0, memcmp(_key, actual->key, _keylen)); \
    free(actual->key); \
    free(actual->data); \
    free(actual); \
}

static void test_openclose(void)
{
    struct db *db = NULL;
    int r;

    CU_ASSERT_EQUAL(fexists(filename), -ENOENT);

    /* open() without _CREATE fails with NOTFOUND
     * and doesn't create the db */
    r = DB->open(filename, 0, &db);
    CU_ASSERT(r == CYRUSDB_NOTFOUND || r == CYRUSDB_IOERROR);
    CU_ASSERT_PTR_NULL(db);
    CU_ASSERT_EQUAL(fexists(filename), -ENOENT);

    /* open() with _CREATE succeeds and creates the db */
    r = DB->open(filename, CYRUSDB_CREATE, &db);
    CU_ASSERT_EQUAL(r, CYRUSDB_OK);
    CU_ASSERT_PTR_NOT_NULL(db);
    CU_ASSERT_EQUAL(fexists(filename), 0);

    /* closing succeeds and leaves the file in place */
    r = DB->close(db);
    CU_ASSERT_EQUAL(r, CYRUSDB_OK);
    CU_ASSERT_EQUAL(fexists(filename), 0);
}

static void test_multiopen(void)
{
    struct db *db1 = NULL;
    struct db *db = NULL;
    struct txn *txn = NULL;
    int r;
    /* data courtesy hipsteripsum.me */
    static const char KEY1[] = "mustache";
    static const char DATA1[] = "blog lomo";
    static const char KEY2[] = "cred";
    static const char DATA2[] = "beard ethical";
    static const char KEY3[] = "leggings";
    static const char DATA3[] = "tumblr salvia";

    CU_ASSERT_EQUAL(fexists(filename), -ENOENT);

    /* open() with _CREATE succeeds and creates the db */
    r = DB->open(filename, CYRUSDB_CREATE, &db);
    CU_ASSERT_EQUAL(r, CYRUSDB_OK);
    CU_ASSERT_PTR_NOT_NULL(db);
    CU_ASSERT_EQUAL(fexists(filename), 0);

    /* 1st txn starts */
    CANSTORE(KEY1, strlen(KEY1), DATA1, strlen(DATA1));
    CANCOMMIT();
    /* 1st txn ends */

    /*
     * Note: the transaction started on the first db reference is
     * carefully *not* left open when starting a transaction on the
     * second db reference.  Supported nested transactions is actually
     * quite a challenge for some backends, and is NOT part of the Cyrus
     * DB semantics.  All we're testing here is that both db references
     * work fine as long as the transactions do not overlap.
     */

    db1 = db;
    {
	struct db *db = NULL;
	struct txn *txn = NULL;

	/* a second open() with the same filename returns
	 * another reference to the same db */
	r = DB->open(filename, 0, &db);
	CU_ASSERT_EQUAL(r, CYRUSDB_OK);
	CU_ASSERT_PTR_NOT_NULL(db);
	if (strcmp(backend, "berkeley")) {
	    CU_ASSERT_PTR_EQUAL_FATAL(db, db1);
	}

	/* 2nd txn starts */
	CANSTORE(KEY2, strlen(KEY2), DATA2, strlen(DATA2));
	CANCOMMIT();
	/* 2nd txn ends */

	/* closing succeeds and leaves the file in place */
	r = DB->close(db);
	CU_ASSERT_EQUAL(r, CYRUSDB_OK);
	CU_ASSERT_EQUAL(fexists(filename), 0);
    }

    /* the 1st db ref still works */
    /* 3rd txn starts */
    CANSTORE(KEY3, strlen(KEY3), DATA3, strlen(DATA3));
    CANCOMMIT();
    /* 3rd txn ends */

    /* closing the other reference succeeds and leaves the file in place */
    r = DB->close(db);
    CU_ASSERT_EQUAL(r, CYRUSDB_OK);
    CU_ASSERT_EQUAL(fexists(filename), 0);

    /* re-opening works */
    r = DB->open(filename, 0, &db);
    CU_ASSERT_EQUAL(r, CYRUSDB_OK);
    CU_ASSERT_PTR_NOT_NULL(db);
    CU_ASSERT_EQUAL(fexists(filename), 0);

    /* all the records are present in the file */
    /* 4th txn starts */
    CANFETCH(KEY1, strlen(KEY1), DATA1, strlen(DATA1));
    CANFETCH(KEY2, strlen(KEY2), DATA2, strlen(DATA2));
    CANFETCH(KEY3, strlen(KEY3), DATA3, strlen(DATA3));
    CANCOMMIT();
    /* 4th txn ends */

    r = DB->close(db);
    CU_ASSERT_EQUAL(r, CYRUSDB_OK);
    CU_ASSERT_EQUAL(fexists(filename), 0);
}

static void test_opentwo(void)
{
    struct db *db1 = NULL;
    struct db *db2 = NULL;
    int r;

    CU_ASSERT_EQUAL(fexists(filename), -ENOENT);
    CU_ASSERT_EQUAL(fexists(filename2), -ENOENT);

    /* open() with _CREATE succeeds and creates the db */
    r = DB->open(filename, CYRUSDB_CREATE, &db1);
    CU_ASSERT_EQUAL(r, CYRUSDB_OK);
    CU_ASSERT_PTR_NOT_NULL(db1);
    CU_ASSERT_EQUAL(fexists(filename), 0);
    CU_ASSERT_EQUAL(fexists(filename2), -ENOENT);

    /* open() of the 2nd filename with _CREATE
     * succeeds and creates another separate db */
    r = DB->open(filename2, CYRUSDB_CREATE, &db2);
    CU_ASSERT_EQUAL(r, CYRUSDB_OK);
    CU_ASSERT_PTR_NOT_NULL(db2);
    CU_ASSERT_EQUAL(fexists(filename), 0);
    CU_ASSERT_EQUAL(fexists(filename2), 0);
    CU_ASSERT_PTR_NOT_EQUAL(db1, db2);

    /* closing succeeds and leaves the file in place */
    r = DB->close(db1);
    CU_ASSERT_EQUAL(r, CYRUSDB_OK);

    /* closing the other reference succeeds and leaves the file in place */
    r = DB->close(db2);
    CU_ASSERT_EQUAL(r, CYRUSDB_OK);

    CU_ASSERT_EQUAL(fexists(filename), 0);
    CU_ASSERT_EQUAL(fexists(filename2), 0);
}

static void test_readwrite(void)
{
    struct db *db = NULL;
    struct txn *txn = NULL;
    static const char KEY[] = "skeleton";
    static const char DATA[] = "dem bones dem bones dem thighbones";
    int r;

    r = DB->open(filename, CYRUSDB_CREATE, &db);
    CU_ASSERT_EQUAL(r, CYRUSDB_OK);
    CU_ASSERT_PTR_NOT_NULL(db);

    /* the database is initially empty, so fetch will fail */
    CANNOTFETCH(KEY, strlen(KEY), CYRUSDB_NOTFOUND);

    /* store()ing a record succeeds */
    CANSTORE(KEY, strlen(KEY), DATA, strlen(DATA));

    /* the record can be fetched back */
    CANFETCH(KEY, strlen(KEY), DATA, strlen(DATA));

    /* commit succeeds */
    CANCOMMIT();

    /* data can be read back in a new transaction */
    CANFETCH(KEY, strlen(KEY), DATA, strlen(DATA));

    /* close the txn - it doesn't matter here if we commit or abort */
    CANCOMMIT();

    /* close and re-open the database */
    CANREOPEN();

    /* data can still be read back */
    CANFETCH(KEY, strlen(KEY), DATA, strlen(DATA));

    /* close the txn - it doesn't matter here if we commit or abort */
    CANCOMMIT();

    /* closing succeeds */
    r = DB->close(db);
    CU_ASSERT_EQUAL(r, CYRUSDB_OK);
}

static void test_multirw(void)
{
    struct db *db = NULL;
    struct txn *txn = NULL;
    static const char KEY[] = "skeleton";
    static const char DATA1[] = "dem bones";
    static const char DATA2[] = "Dem KneeBones";
    int r;

    r = DB->open(filename, CYRUSDB_CREATE, &db);
    CU_ASSERT_EQUAL(r, CYRUSDB_OK);
    CU_ASSERT_PTR_NOT_NULL(db);

    /* the database is initially empty, so fetch will fail */
    CANNOTFETCH(KEY, strlen(KEY), CYRUSDB_NOTFOUND);

    /* store()ing a record succeeds */
    CANSTORE(KEY, strlen(KEY), DATA1, strlen(DATA1));

    /* the record can be fetched back */
    CANFETCH(KEY, strlen(KEY), DATA1, strlen(DATA1));

    /* store()ing the record again, in the same txn, succeeds */
    CANSTORE(KEY, strlen(KEY), DATA2, strlen(DATA2));

    /* fetching again gets the new data */
    CANFETCH(KEY, strlen(KEY), DATA2, strlen(DATA2));

    /* commit succeeds */
    CANCOMMIT();

    /* new data can be read back in a new transaction */
    CANFETCH(KEY, strlen(KEY), DATA2, strlen(DATA2));

    /* close the txn - it doesn't matter here if we commit or abort */
    CANCOMMIT();

    /* close and re-open the database */
    CANREOPEN();

    /* new data can still be read back */
    CANFETCH(KEY, strlen(KEY), DATA2, strlen(DATA2));

    /* close the txn - it doesn't matter here if we commit or abort */
    CANCOMMIT();

    /* closing succeeds */
    r = DB->close(db);
    CU_ASSERT_EQUAL(r, CYRUSDB_OK);
}

/* read-write of a non-NULL zero length datum */
static void test_readwrite_zerolen(void)
{
    struct db *db = NULL;
    struct txn *txn = NULL;
    /* test data thanks to hipsteripsum.me */
    static const char KEY[] = "keffiyeh";
    static const char DATA[] = "";
    int r;

    r = DB->open(filename, CYRUSDB_CREATE, &db);
    CU_ASSERT_EQUAL(r, CYRUSDB_OK);
    CU_ASSERT_PTR_NOT_NULL(db);

    /* the database is initially empty, so fetch will fail */
    CANNOTFETCH(KEY, strlen(KEY), CYRUSDB_NOTFOUND);

    /* store()ing a record succeeds */
    CANSTORE(KEY, strlen(KEY), DATA, 0);

    /* the records can be fetched back; we get non-NULL
     * zero-length data */
    CANFETCH(KEY, strlen(KEY), DATA, 0);

    /* commit succeeds */
    CANCOMMIT();

    /* data can be read back in a new transaction */
    CANFETCH(KEY, strlen(KEY), DATA, 0);

    /* close the txn - it doesn't matter here if we commit or abort */
    CANCOMMIT();

    /* close and re-open the database */
    CANREOPEN();

    /* data can still be read back */
    CANFETCH(KEY, strlen(KEY), DATA, 0);

    /* close the txn - it doesn't matter here if we commit or abort */
    CANCOMMIT();

    /* closing succeeds */
    r = DB->close(db);
    CU_ASSERT_EQUAL(r, CYRUSDB_OK);
}

/* read-write of a NULL zero length datum */
static void test_readwrite_null(void)
{
    struct db *db = NULL;
    struct txn *txn = NULL;
    /* test data thanks to hipsteripsum.me */
    static const char KEY[] = "skateboard";
    static const char EMPTY[] = "";
    int r;

    r = DB->open(filename, CYRUSDB_CREATE, &db);
    CU_ASSERT_EQUAL(r, CYRUSDB_OK);
    CU_ASSERT_PTR_NOT_NULL(db);

    /* the database is initially empty, so fetch will fail */
    CANNOTFETCH(KEY, strlen(KEY), CYRUSDB_NOTFOUND);

    /* store()ing a record succeeds */
    CANSTORE(KEY, strlen(KEY), NULL, 0);

    /* the records can be fetched back; we get non-NULL
     * zero-length data */
    CANFETCH(KEY, strlen(KEY), EMPTY, 0);

    /* commit succeeds */
    CANCOMMIT();

    /* data can be read back in a new transaction */
    CANFETCH(KEY, strlen(KEY), EMPTY, 0);

    /* close the txn - it doesn't matter here if we commit or abort */
    CANCOMMIT();

    /* close and re-open the database */
    CANREOPEN();

    /* data can still be read back */
    CANFETCH(KEY, strlen(KEY), EMPTY, 0);

    /* close the txn - it doesn't matter here if we commit or abort */
    CANCOMMIT();

    /* closing succeeds */
    r = DB->close(db);
    CU_ASSERT_EQUAL(r, CYRUSDB_OK);
}

/* read-write of a NULL datum with non-zero length (which is
 * really bad parameters passed to the store() call) */
static void test_readwrite_null_nonzerolen(void)
{
    struct db *db = NULL;
    struct txn *txn = NULL;
    /* test data thanks to hipsteripsum.me */
    static const char KEY[] = "viral";
    int r;

    r = DB->open(filename, CYRUSDB_CREATE, &db);
    CU_ASSERT_EQUAL(r, CYRUSDB_OK);
    CU_ASSERT_PTR_NOT_NULL(db);

    /* the database is initially empty, so fetch will fail */
    CANNOTFETCH(KEY, strlen(KEY), CYRUSDB_NOTFOUND);

    /* store()ing a record fails due to the length */
    CANNOTSTORE(KEY, strlen(KEY), NULL, 23);

    /* abort succeeds */
    r = DB->abort(db, txn);
    CU_ASSERT_EQUAL(r, CYRUSDB_OK);
    txn = NULL;

    /* closing succeeds */
    r = DB->close(db);
    CU_ASSERT_EQUAL(r, CYRUSDB_OK);
}

static void test_abort(void)
{
    struct db *db = NULL;
    struct txn *txn = NULL;
    static const char KEY[] = "yale";
    static const char DATA[] = "standford mit harvard";
    int r;

    r = DB->open(filename, CYRUSDB_CREATE, &db);
    CU_ASSERT_EQUAL(r, CYRUSDB_OK);
    CU_ASSERT_PTR_NOT_NULL(db);

    /* the database is initially empty, so fetch will fail */
    CANNOTFETCH(KEY, strlen(KEY), CYRUSDB_NOTFOUND);

    /* store()ing a record succeeds */
    CANSTORE(KEY, strlen(KEY), DATA, strlen(DATA));

    /* the record can be fetched back */
    CANFETCH(KEY, strlen(KEY), DATA, strlen(DATA));

    /* abort succeeds */
    r = DB->abort(db, txn);
    CU_ASSERT_EQUAL(r, CYRUSDB_OK);
    txn = NULL;

    /* data is not present in a new transaction */
    CANNOTFETCH(KEY, strlen(KEY), CYRUSDB_NOTFOUND);

    /* close the new txn - it doesn't matter here if we commit or abort */
    CANCOMMIT();

    /* close and re-open the database */
    CANREOPEN();

    /* data is still not present after close/reopen */
    CANNOTFETCH(KEY, strlen(KEY), CYRUSDB_NOTFOUND);

    /* close the txn - it doesn't matter here if we commit or abort */
    CANCOMMIT();

    /* closing succeeds */
    r = DB->close(db);
    CU_ASSERT_EQUAL(r, CYRUSDB_OK);
}


static void test_delete(void)
{
    struct db *db = NULL;
    struct txn *txn = NULL;
    /* random word generator to the rescue! */
    static const char KEY1[] = "buzzes";
    static const char DATA1[] = "afro timur funky cents hewitt";
    static const char KEY2[] = "galas";
    static const char DATA2[] = "assad goering flemish brynner heshvan";
    static const char KEY3[] = "bathes";
    static const char DATA3[] = "flax corm naipaul enable herrera fating";
    int r;

    r = DB->open(filename, CYRUSDB_CREATE, &db);
    CU_ASSERT_EQUAL(r, CYRUSDB_OK);
    CU_ASSERT_PTR_NOT_NULL(db);

    /* store() some records */
    CANSTORE(KEY1, strlen(KEY1), DATA1, strlen(DATA1));
    CANSTORE(KEY2, strlen(KEY2), DATA2, strlen(DATA2));
    CANSTORE(KEY3, strlen(KEY3), DATA3, strlen(DATA3));

    /* commit succeeds */
    CANCOMMIT();

    /* all records can be fetched back */
    CANFETCH(KEY1, strlen(KEY1), DATA1, strlen(DATA1));
    CANFETCH(KEY2, strlen(KEY2), DATA2, strlen(DATA2));
    CANFETCH(KEY3, strlen(KEY3), DATA3, strlen(DATA3));

    /* one of the records can be deleted */
    r = DB->delete(db, KEY2, strlen(KEY2), &txn, 1);
    CU_ASSERT_EQUAL(r, CYRUSDB_OK);
    CU_ASSERT_PTR_NOT_NULL(txn);

    /* deleted record cannot be fetch()ed now */
    CANNOTFETCH(KEY2, strlen(KEY2), CYRUSDB_NOTFOUND);
    /* but others can */
    CANFETCH(KEY1, strlen(KEY1), DATA1, strlen(DATA1));
    CANFETCH(KEY3, strlen(KEY3), DATA3, strlen(DATA3));

    /* commit succeeds */
    CANCOMMIT();

    /* deleted record still cannot be fetch()ed in a new txn */
    CANNOTFETCH(KEY2, strlen(KEY2), CYRUSDB_NOTFOUND);
    /* but others can */
    CANFETCH(KEY1, strlen(KEY1), DATA1, strlen(DATA1));
    CANFETCH(KEY3, strlen(KEY3), DATA3, strlen(DATA3));

    /* close the txn - it doesn't matter here if we commit or abort */
    CANCOMMIT();

    /* close and re-open the database */
    CANREOPEN();

    /* deleted record still cannot be fetch()ed and re-open */
    CANNOTFETCH(KEY2, strlen(KEY2), CYRUSDB_NOTFOUND);
    /* but others can */
    CANFETCH(KEY1, strlen(KEY1), DATA1, strlen(DATA1));
    CANFETCH(KEY3, strlen(KEY3), DATA3, strlen(DATA3));

    /* close the txn - it doesn't matter here if we commit or abort */
    CANCOMMIT();

    /* closing succeeds */
    r = DB->close(db);
    CU_ASSERT_EQUAL(r, CYRUSDB_OK);
}

static int foreacher(void *rock,
		     const char *key, size_t keylen,
		     const char *data, size_t datalen)
{
    struct binary_result **head = (struct binary_result **)rock;
    struct binary_result **tail;
    struct binary_result *res;

    /* check that key and data are correct */
    CU_ASSERT_PTR_NOT_NULL(key);
    CU_ASSERT(keylen > 0);

    CU_ASSERT_PTR_NOT_NULL(data);
    CU_ASSERT(datalen > 0);

    /* remember them for later perusal */
    res = xzmalloc(sizeof(*res));
    res->key = xmemdup(key, keylen);
    res->keylen = keylen;
    res->data = xmemdup(data, datalen);
    res->datalen = datalen;
    /* append to the list.  yes, it's inefficient. */
    for (tail = head ; *tail ; tail = &(*tail)->next)
	;
    *tail = res;

    return 0;
}

static void test_foreach(void)
{
    struct db *db = NULL;
    struct txn *txn = NULL;
    struct binary_result *results = NULL;
    /* random word generator to the rescue! */
    static const char KEY1[] = "carib";
    static const char DATA1[] = "delays maj bullish packard ronald";
    static const char KEY2[] = "cubist";
    static const char DATA2[] = "bobby tswana cu albumin created";
    static const char KEY3[] = "eulogy";
    static const char DATA3[] = "aleut stoic muscovy adonis moe docent";
    int r;

    r = DB->open(filename, CYRUSDB_CREATE, &db);
    CU_ASSERT_EQUAL(r, CYRUSDB_OK);
    CU_ASSERT_PTR_NOT_NULL(db);

    /* store() some records */
    CANSTORE(KEY1, strlen(KEY1), DATA1, strlen(DATA1));
    CANSTORE(KEY2, strlen(KEY2), DATA2, strlen(DATA2));
    CANSTORE(KEY3, strlen(KEY3), DATA3, strlen(DATA3));

    /* commit succeeds */
    CANCOMMIT();

    /* all records can be fetched back */
    CANFETCH(KEY1, strlen(KEY1), DATA1, strlen(DATA1));
    CANFETCH(KEY2, strlen(KEY2), DATA2, strlen(DATA2));
    CANFETCH(KEY3, strlen(KEY3), DATA3, strlen(DATA3));

    /* commit succeeds */
    CANCOMMIT();

    /* foreach succeeds */
    r = DB->foreach(db, NULL, 0, NULL, foreacher, &results, &txn);
    CU_ASSERT_EQUAL(r, CYRUSDB_OK);

    /* got the expected keys in the expected order */
    GOTRESULT(KEY1, strlen(KEY1), DATA1, strlen(DATA1));
    GOTRESULT(KEY2, strlen(KEY2), DATA2, strlen(DATA2));
    GOTRESULT(KEY3, strlen(KEY3), DATA3, strlen(DATA3));
    /* foreach iterated over exactly all the keys */
    CU_ASSERT_PTR_NULL(results);

    /* close the txn - it doesn't matter here if we commit or abort */
    CANCOMMIT();

    /* closing succeeds */
    r = DB->close(db);
    CU_ASSERT_EQUAL(r, CYRUSDB_OK);
}

static void test_binary_keys(void)
{
    struct db *db = NULL;
    struct txn *txn = NULL;
    /* data from hipsteripsum.me */
    static const char KEY1[] = "master\0cleanse";
    static const char DATA1[] = "ethical";
    static const char KEY2[] = "cardigan\tdreamcatcher";
    static const char DATA2[] = "shoreditch";
    static const char KEY3[] = "pitchfork\rcarles";
    static const char DATA3[] = "tumble";
    static const char KEY4[] = "seitan\nraw\ndenim";
    static const char DATA4[] = "fap";
    static const char KEY5[] = { 0x01, 0x02, 0x04, 0x08,
			         0x10, 0x20, 0x40, 0x80,
				 0x00/*unused*/};
    static const char DATA5[] = "farm-to-table";
    struct binary_result *results = NULL;
    int r;

    r = DB->open(filename, CYRUSDB_CREATE, &db);
    CU_ASSERT_EQUAL(r, CYRUSDB_OK);
    CU_ASSERT_PTR_NOT_NULL(db);

    /* the database is initially empty, so fetch will fail */
    CANNOTFETCH(KEY1, sizeof(KEY1)-1, CYRUSDB_NOTFOUND);
    CANNOTFETCH(KEY2, sizeof(KEY2)-1, CYRUSDB_NOTFOUND);
    CANNOTFETCH(KEY3, sizeof(KEY3)-1, CYRUSDB_NOTFOUND);
    CANNOTFETCH(KEY4, sizeof(KEY4)-1, CYRUSDB_NOTFOUND);
    CANNOTFETCH(KEY5, sizeof(KEY5)-1, CYRUSDB_NOTFOUND);

    /* store()ing a record succeeds */
    CANSTORE(KEY1, sizeof(KEY1)-1, DATA1, sizeof(DATA1)-1);
    CANSTORE(KEY2, sizeof(KEY2)-1, DATA2, sizeof(DATA2)-1);
    CANSTORE(KEY3, sizeof(KEY3)-1, DATA3, sizeof(DATA3)-1);
    CANSTORE(KEY4, sizeof(KEY4)-1, DATA4, sizeof(DATA4)-1);
    CANSTORE(KEY5, sizeof(KEY5)-1, DATA5, sizeof(DATA5)-1);

    /* the record can be fetched back */
    CANFETCH(KEY1, sizeof(KEY1)-1, DATA1, sizeof(DATA1)-1);
    CANFETCH(KEY2, sizeof(KEY2)-1, DATA2, sizeof(DATA2)-1);
    CANFETCH(KEY3, sizeof(KEY3)-1, DATA3, sizeof(DATA3)-1);
    CANFETCH(KEY4, sizeof(KEY4)-1, DATA4, sizeof(DATA4)-1);
    CANFETCH(KEY5, sizeof(KEY5)-1, DATA5, sizeof(DATA5)-1);

    /* commit succeeds */
    CANCOMMIT();

    /* data can be read back in a new transaction */
    CANFETCH(KEY1, sizeof(KEY1)-1, DATA1, sizeof(DATA1)-1);
    CANFETCH(KEY2, sizeof(KEY2)-1, DATA2, sizeof(DATA2)-1);
    CANFETCH(KEY3, sizeof(KEY3)-1, DATA3, sizeof(DATA3)-1);
    CANFETCH(KEY4, sizeof(KEY4)-1, DATA4, sizeof(DATA4)-1);
    CANFETCH(KEY5, sizeof(KEY5)-1, DATA5, sizeof(DATA5)-1);

    /* close the txn - it doesn't matter here if we commit or abort */
    CANCOMMIT();

    /* foreach succeeds */
    r = DB->foreach(db, NULL, 0, NULL, foreacher, &results, &txn);
    CU_ASSERT_EQUAL(r, CYRUSDB_OK);

    /* got the expected keys in the expected order */
    GOTRESULT(KEY5, sizeof(KEY5)-1, DATA5, sizeof(DATA5)-1);
    GOTRESULT(KEY2, sizeof(KEY2)-1, DATA2, sizeof(DATA2)-1);
    GOTRESULT(KEY1, sizeof(KEY1)-1, DATA1, sizeof(DATA1)-1);
    GOTRESULT(KEY3, sizeof(KEY3)-1, DATA3, sizeof(DATA3)-1);
    GOTRESULT(KEY4, sizeof(KEY4)-1, DATA4, sizeof(DATA4)-1);
    /* foreach iterated over exactly all the keys */
    CU_ASSERT_PTR_NULL(results);

    /* close the txn - it doesn't matter here if we commit or abort */
    CANCOMMIT();

    /* close and re-open the database */
    CANREOPEN();

    /* data can still be read back */
    CANFETCH(KEY1, sizeof(KEY1)-1, DATA1, sizeof(DATA1)-1);
    CANFETCH(KEY2, sizeof(KEY2)-1, DATA2, sizeof(DATA2)-1);
    CANFETCH(KEY3, sizeof(KEY3)-1, DATA3, sizeof(DATA3)-1);
    CANFETCH(KEY4, sizeof(KEY4)-1, DATA4, sizeof(DATA4)-1);
    CANFETCH(KEY5, sizeof(KEY5)-1, DATA5, sizeof(DATA5)-1);

    /* foreach still succeeds */
    r = DB->foreach(db, NULL, 0, NULL, foreacher, &results, &txn);
    CU_ASSERT_EQUAL(r, CYRUSDB_OK);

    /* got the expected keys in the expected order */
    GOTRESULT(KEY5, sizeof(KEY5)-1, DATA5, sizeof(DATA5)-1);
    GOTRESULT(KEY2, sizeof(KEY2)-1, DATA2, sizeof(DATA2)-1);
    GOTRESULT(KEY1, sizeof(KEY1)-1, DATA1, sizeof(DATA1)-1);
    GOTRESULT(KEY3, sizeof(KEY3)-1, DATA3, sizeof(DATA3)-1);
    GOTRESULT(KEY4, sizeof(KEY4)-1, DATA4, sizeof(DATA4)-1);
    /* foreach iterated over exactly all the keys */
    CU_ASSERT_PTR_NULL(results);

    /* close the txn - it doesn't matter here if we commit or abort */
    CANCOMMIT();

    /* closing succeeds */
    r = DB->close(db);
    CU_ASSERT_EQUAL(r, CYRUSDB_OK);
}


static void test_binary_data(void)
{
    struct db *db = NULL;
    struct txn *txn = NULL;
    /* data from hipsteripsum.me */
    static const char KEY1[] = "vinyl";
    static const char DATA1[] = "cosby\0sweater";
    static const char KEY2[] = "blog";
    static const char DATA2[] = "next\tlevel";
    static const char KEY3[] = "chambray";
    static const char DATA3[] = "mcsweeneys\rletterpress";
    static const char KEY4[] = "synth";
    static const char DATA4[] = "readymade\ncliche\nterry\nrichardson";
    static const char KEY5[] = "fixie";
    static const char DATA5[] = { 0x01, 0x02, 0x04, 0x08,
			          0x10, 0x20, 0x40, 0x80,
				  0x00/*unused*/};
    struct binary_result *results = NULL;
    int r;

    r = DB->open(filename, CYRUSDB_CREATE, &db);
    CU_ASSERT_EQUAL(r, CYRUSDB_OK);
    CU_ASSERT_PTR_NOT_NULL(db);

    /* the database is initially empty, so fetch will fail */
    CANNOTFETCH(KEY1, sizeof(KEY1)-1, CYRUSDB_NOTFOUND);
    CANNOTFETCH(KEY2, sizeof(KEY2)-1, CYRUSDB_NOTFOUND);
    CANNOTFETCH(KEY3, sizeof(KEY3)-1, CYRUSDB_NOTFOUND);
    CANNOTFETCH(KEY4, sizeof(KEY4)-1, CYRUSDB_NOTFOUND);
    CANNOTFETCH(KEY5, sizeof(KEY5)-1, CYRUSDB_NOTFOUND);

    /* store()ing a record succeeds */
    CANSTORE(KEY1, sizeof(KEY1)-1, DATA1, sizeof(DATA1)-1);
    CANSTORE(KEY2, sizeof(KEY2)-1, DATA2, sizeof(DATA2)-1);
    CANSTORE(KEY3, sizeof(KEY3)-1, DATA3, sizeof(DATA3)-1);
    CANSTORE(KEY4, sizeof(KEY4)-1, DATA4, sizeof(DATA4)-1);
    CANSTORE(KEY5, sizeof(KEY5)-1, DATA5, sizeof(DATA5)-1);

    /* the record can be fetched back */
    CANFETCH(KEY1, sizeof(KEY1)-1, DATA1, sizeof(DATA1)-1);
    CANFETCH(KEY2, sizeof(KEY2)-1, DATA2, sizeof(DATA2)-1);
    CANFETCH(KEY3, sizeof(KEY3)-1, DATA3, sizeof(DATA3)-1);
    CANFETCH(KEY4, sizeof(KEY4)-1, DATA4, sizeof(DATA4)-1);
    CANFETCH(KEY5, sizeof(KEY5)-1, DATA5, sizeof(DATA5)-1);

    /* commit succeeds */
    CANCOMMIT();

    /* data can be read back in a new transaction */
    CANFETCH(KEY1, sizeof(KEY1)-1, DATA1, sizeof(DATA1)-1);
    CANFETCH(KEY2, sizeof(KEY2)-1, DATA2, sizeof(DATA2)-1);
    CANFETCH(KEY3, sizeof(KEY3)-1, DATA3, sizeof(DATA3)-1);
    CANFETCH(KEY4, sizeof(KEY4)-1, DATA4, sizeof(DATA4)-1);
    CANFETCH(KEY5, sizeof(KEY5)-1, DATA5, sizeof(DATA5)-1);

    /* close the txn - it doesn't matter here if we commit or abort */
    CANCOMMIT();

    /* foreach succeeds */
    r = DB->foreach(db, NULL, 0, NULL, foreacher, &results, &txn);
    CU_ASSERT_EQUAL(r, CYRUSDB_OK);

    /* got the expected keys in the expected order */
    GOTRESULT(KEY2, sizeof(KEY2)-1, DATA2, sizeof(DATA2)-1);
    GOTRESULT(KEY3, sizeof(KEY3)-1, DATA3, sizeof(DATA3)-1);
    GOTRESULT(KEY5, sizeof(KEY5)-1, DATA5, sizeof(DATA5)-1);
    GOTRESULT(KEY4, sizeof(KEY4)-1, DATA4, sizeof(DATA4)-1);
    GOTRESULT(KEY1, sizeof(KEY1)-1, DATA1, sizeof(DATA1)-1);
    /* foreach iterated over exactly all the keys */
    CU_ASSERT_PTR_NULL(results);

    /* close the txn - it doesn't matter here if we commit or abort */
    CANCOMMIT();

    /* close and re-open the database */
    CANREOPEN();

    /* data can still be read back */
    CANFETCH(KEY1, sizeof(KEY1)-1, DATA1, sizeof(DATA1)-1);
    CANFETCH(KEY2, sizeof(KEY2)-1, DATA2, sizeof(DATA2)-1);
    CANFETCH(KEY3, sizeof(KEY3)-1, DATA3, sizeof(DATA3)-1);
    CANFETCH(KEY4, sizeof(KEY4)-1, DATA4, sizeof(DATA4)-1);
    CANFETCH(KEY5, sizeof(KEY5)-1, DATA5, sizeof(DATA5)-1);

    /* foreach still succeeds */
    r = DB->foreach(db, NULL, 0, NULL, foreacher, &results, &txn);
    CU_ASSERT_EQUAL(r, CYRUSDB_OK);

    /* got the expected keys in the expected order */
    GOTRESULT(KEY2, sizeof(KEY2)-1, DATA2, sizeof(DATA2)-1);
    GOTRESULT(KEY3, sizeof(KEY3)-1, DATA3, sizeof(DATA3)-1);
    GOTRESULT(KEY5, sizeof(KEY5)-1, DATA5, sizeof(DATA5)-1);
    GOTRESULT(KEY4, sizeof(KEY4)-1, DATA4, sizeof(DATA4)-1);
    GOTRESULT(KEY1, sizeof(KEY1)-1, DATA1, sizeof(DATA1)-1);
    /* foreach iterated over exactly all the keys */
    CU_ASSERT_PTR_NULL(results);

    /* close the txn - it doesn't matter here if we commit or abort */
    CANCOMMIT();

    /* closing succeeds */
    r = DB->close(db);
    CU_ASSERT_EQUAL(r, CYRUSDB_OK);
}


const char *nth_compound(unsigned int n,
			 const char * const * words /*[37]*/,
			 const char *sep,
			 struct buf *res)
{
    buf_reset(res);

    if ((n / 1000) % 10) {
	buf_appendcstr(res, words[28 + (n / 1000) % 10]);
    }

    if ((n / 100) % 10) {
	if (res->len && sep)
	    buf_appendcstr(res, sep);
	buf_appendcstr(res, words[19 + (n / 100) % 10]);
    }

    if ((n / 10) % 10) {
	if (res->len && sep)
	    buf_appendcstr(res, sep);
	buf_appendcstr(res, words[10 + (n / 10) % 10]);
    }

    if (res->len && sep)
	buf_appendcstr(res, sep);
    buf_appendcstr(res, words[n % 10]);

    return buf_cstring(res);
}

static const char *nth_key(unsigned int n)
{
    static const char * const words[37] = {
	"dray", "bite", "cue", "ado", "felt",
	"firm", "sal", "ahab", "cab", "lord",
	"blob", "be", "coil", "hay",
	"bled", "got", "leta", "sept", "deft",
	"ibm", "kama", "bean", "ado",
	"cord", "firm", "ben", "fore", "huck",
	"haas", "jack", "aden", "nerf",
	"gash", "stu", "nona", "gel", "ale"
    };
    static struct buf buf = BUF_INITIALIZER;
    return nth_compound(n, words, ".", &buf);
}

static const char *nth_data(unsigned int n)
{
    static const char * const words[37] = {
	"abettor", "afresh", "aisling", "arthur", "ascots",
	"belled", "berserk", "border", "bourbon", "brawny",
	"carpels", "cavils", "coating", "cologne",
	"concern", "consul", "crater", "crocks", "deirdre",
	"dewier", "disdain", "dowdier", "duncan",
	"eighth", "enigma", "evelyn", "fennel", "flowery",
	"flukier", "forums", "gametes", "gamins",
	"gavels", "gibbers", "gulags", "gunther", "gunwale"
    };
    static struct buf buf = BUF_INITIALIZER;
    return nth_compound(n, words, " ", &buf);
}

static int finder(void *rock,
		  const char *key, size_t keylen,
		  const char *data, size_t datalen)
{
    hash_table *exphash = (hash_table *)rock;
    char *expected;
    struct buf kbuf = BUF_INITIALIZER;

    /* check that key and data are correct */
    CU_ASSERT_PTR_NOT_NULL(key);
    CU_ASSERT(keylen > 0);

    CU_ASSERT_PTR_NOT_NULL(data);
    CU_ASSERT(datalen > 0);

    buf_appendmap(&kbuf, key, keylen);
    buf_cstring(&kbuf);

    expected = hash_lookup(kbuf.s, exphash);
    CU_ASSERT_EQUAL(datalen, strlen(expected));
    CU_ASSERT_EQUAL(0, memcmp(data, expected, datalen));
    hash_del(kbuf.s, exphash);
    free(expected);
    buf_free(&kbuf);

    return 0;
}

static void count_cb(const char *key __attribute__((unused)),
		     void *data __attribute__((unused)),
		     void *rock)
{
    unsigned int *np = (unsigned int *)rock;
    (*np)++;
}

static unsigned int hash_count(hash_table *ht)
{
    unsigned int n = 0;
    hash_enumerate(ht, count_cb, &n);
    return n;
}

#define FOREACH_PRECONDITION(condition, expcount) \
{ \
    unsigned int nsubset = 0; \
    unsigned int i; \
    for (i = 0 ; i <= MAXN ; i++) { \
	const char *key = nth_key(i); \
	const char *data = nth_data(i); \
	if ((condition)) { \
	    hash_insert(key, (void *)xstrdup(data), &exphash); \
	    nsubset++; \
	} \
    } \
    CU_ASSERT_EQUAL(nsubset, expcount); \
    CU_ASSERT_EQUAL(hash_count(&exphash), nsubset); \
}

#define FOREACH_POSTCONDITION() \
    CU_ASSERT_EQUAL(r, CYRUSDB_OK); \
    CU_ASSERT_EQUAL(hash_count(&exphash), 0);

#define FOREACH_TEST(prefix, prefixlen, good, condition, expcount) \
    FOREACH_PRECONDITION(condition, expcount); \
    r = DB->foreach(db, prefix, prefixlen, good, finder, &exphash, &txn); \
    FOREACH_POSTCONDITION()

static void test_many(void)
{
    struct db *db = NULL;
    struct txn *txn = NULL;
    hash_table exphash = HASH_TABLE_INITIALIZER;
#define MAXN	4095
    unsigned int n;
    int r;

    construct_hash_table(&exphash, (MAXN+1)*4, 0);

    r = DB->open(filename, CYRUSDB_CREATE, &db);
    CU_ASSERT_EQUAL(r, CYRUSDB_OK);
    CU_ASSERT_PTR_NOT_NULL(db);

    /* store() some records */
    for (n = 0 ; n <= MAXN ; n++) {
	const char *key = nth_key(n);
	const char *data = nth_data(n);
	CANSTORE(key, strlen(key), data, strlen(data));
    }

    /* commit succeeds */
    CANCOMMIT();

    /* check the records all made it */
    for (n = 0 ; n <= MAXN ; n++)
    {
	const char *key = nth_key(n);
	const char *data = nth_data(n);
	CANFETCH(key, strlen(key), data, strlen(data));
    }

    /* prefix=NULL: iterate all the records */
    FOREACH_TEST(/*prefix*/NULL, /*prefixlen*/0,
	         /*good*/NULL, /*condition*/1, MAXN+1);

    /* prefix="": iterate all the records */
    FOREACH_TEST(/*prefix*/"", /*prefixlen*/0,
	         /*good*/NULL, /*condition*/1, MAXN+1);

    /* prefix=an uncommon prefix: iterate some of the records */
    FOREACH_TEST(/*prefix*/"jack.", /*prefixlen*/5,
		 /*good*/NULL, /*condition*/i / 1000 == 1, 1000);

    /* delete records one by one, checking that foreach
     * walks over the expected number from time to time */
    for (n = 0 ; n <= MAXN ; n++) {
	const char *key = nth_key(n);
	r = DB->delete(db, key, strlen(key), &txn, 1);
	CU_ASSERT_EQUAL(r, CYRUSDB_OK);
	CU_ASSERT_PTR_NOT_NULL(txn);
	if (n && n % 301 == 0) {
	    FOREACH_TEST(/*prefix*/NULL, /*prefixlen*/0,
			 /*good*/NULL, /*condition*/i > n, MAXN-n);
	}
    }

    /* close the txn - it doesn't matter here if we commit or abort */
    CANCOMMIT();

    /* closing succeeds */
    r = DB->close(db);
    CU_ASSERT_EQUAL(r, CYRUSDB_OK);

    free_hash_table(&exphash, free);
#undef MAXN
}

static char *basedir;

static int set_up(void)
{
    char buf[PATH_MAX];
    static const char * const reldirs[] = {
	"db",
	"conf",
	"conf/lock/",
	"conf/lock/user",
	"stuff",
	NULL
    };

    basedir = make_basedir(reldirs);
    if (!basedir)
	return -1;

    libcyrus_config_setstring(CYRUSOPT_CONFIG_DIR, basedir);
    snprintf(buf, sizeof(buf), "configdirectory: %s/conf\n", basedir);
    config_read_string(buf);

    cyrusdb_init();
    DB = cyrusdb_fromname(backend);

    filename = strconcat(basedir, "/stuff/cyrus.", backend, "-test", (char *)NULL);
    filename2 = strconcat(basedir, "/stuff/cyrus.", backend, "-testB", (char *)NULL);

    return 0;
}

static int tear_down(void)
{
    int r;

    cyrusdb_done();

    if (basedir) {
	char buf[PATH_MAX];
	snprintf(buf, sizeof(buf), "rm -rf \"%s\"", basedir);
	r = system(buf);
	/* I'm ignoring you */
    }

    free(filename);
    filename = NULL;
    free(filename2);
    filename2 = NULL;
    free(basedir);
    basedir = NULL;

    return 0;
}


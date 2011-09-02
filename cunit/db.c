#include "config.h"
#include "cunit/cunit.h"
#include "xmalloc.h"
#include "global.h"
#include "retry.h"
#include "cyrusdb.h"
#include "libcyr_cfg.h"
#include "util.h"
#include "strarray.h"
#include "hash.h"

#define BACKEND	    "skiplist"
#define DBDIR	    "test-mb-dbdir"
#define FNAME	    DBDIR"/cyrus."BACKEND"-test"
#define FNAME2	    DBDIR"/cyrus."BACKEND"-testB"

static struct cyrusdb_backend *DB;

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

#define CANSTORE(key, keylen, data, datalen) \
    r = DB->store(db, key, keylen, data, datalen, &txn); \
    CU_ASSERT_EQUAL(r, CYRUSDB_OK); \
    CU_ASSERT_PTR_NOT_NULL(txn);

#define CANFETCH(key, keylen, expdata, expdatalen) \
{ \
    const char *_data = NULL; \
    int _datalen = 0; \
    r = DB->fetch(db, key, keylen, &_data, &_datalen, &txn); \
    CU_ASSERT_EQUAL(r, CYRUSDB_OK); \
    CU_ASSERT_PTR_NOT_NULL(txn); \
    CU_ASSERT_PTR_NOT_NULL(_data); \
    CU_ASSERT_PTR_NOT_EQUAL((void *)_data, (void *)expdata); \
    CU_ASSERT_EQUAL(_datalen, expdatalen); \
    CU_ASSERT(!memcmp(_data, expdata, _datalen)); \
    CU_ASSERT(_data[_datalen] == '\0'); \
}

#define CANNOTFETCH(key, keylen, experror) \
{ \
    const char *_data = NULL; \
    int _datalen = 0; \
    r = DB->fetch(db, key, keylen, &_data, &_datalen, &txn); \
    CU_ASSERT_EQUAL(r, experror); \
    CU_ASSERT_PTR_NOT_NULL(txn); \
    CU_ASSERT_PTR_NULL(_data); \
    CU_ASSERT_EQUAL(_datalen, 0); \
}

#define CANCOMMIT() \
    r = DB->commit(db, txn); \
    CU_ASSERT_EQUAL(r, CYRUSDB_OK); \
    txn = NULL;

#define CANREOPEN() \
    r = DB->close(db); \
    db = NULL; \
    CU_ASSERT_EQUAL(r, CYRUSDB_OK); \
    r = DB->open(FNAME, 0, &db); \
    CU_ASSERT_EQUAL(r, CYRUSDB_OK); \
    CU_ASSERT_PTR_NOT_NULL(db);

static void test_openclose(void)
{
    struct db *db = NULL;
    int r;

    CU_ASSERT_EQUAL(fexists(FNAME), -ENOENT);

    /* open() without _CREATE fails with NOTFOUND
     * and doesn't create the db */
    r = DB->open(FNAME, 0, &db);
    CU_ASSERT_EQUAL(r, CYRUSDB_NOTFOUND);
    CU_ASSERT_PTR_NULL(db);
    CU_ASSERT_EQUAL(fexists(FNAME), -ENOENT);

    /* open() with _CREATE succeeds and creates the db */
    r = DB->open(FNAME, CYRUSDB_CREATE, &db);
    CU_ASSERT_EQUAL(r, CYRUSDB_OK);
    CU_ASSERT_PTR_NOT_NULL(db);
    CU_ASSERT_EQUAL(fexists(FNAME), 0);

    /* closing succeeds and leaves the file in place */
    r = DB->close(db);
    CU_ASSERT_EQUAL(r, CYRUSDB_OK);
    CU_ASSERT_EQUAL(fexists(FNAME), 0);
}

static void test_multiopen(void)
{
    struct db *db1 = NULL;
    struct db *db2 = NULL;
    int r;

    CU_ASSERT_EQUAL(fexists(FNAME), -ENOENT);

    /* open() with _CREATE succeeds and creates the db */
    r = DB->open(FNAME, CYRUSDB_CREATE, &db1);
    CU_ASSERT_EQUAL(r, CYRUSDB_OK);
    CU_ASSERT_PTR_NOT_NULL(db1);
    CU_ASSERT_EQUAL(fexists(FNAME), 0);

    /* a second open() with the same filename returns
     * another reference to the same db */
    r = DB->open(FNAME, 0, &db2);
    CU_ASSERT_EQUAL(r, CYRUSDB_OK);
    CU_ASSERT_PTR_NOT_NULL(db2);
    CU_ASSERT_PTR_EQUAL(db1, db2);

    /* closing succeeds and leaves the file in place */
    r = DB->close(db1);
    CU_ASSERT_EQUAL(r, CYRUSDB_OK);
    CU_ASSERT_EQUAL(fexists(FNAME), 0);

    /* closing the other reference succeeds and leaves the file in place */
    r = DB->close(db2);
    CU_ASSERT_EQUAL(r, CYRUSDB_OK);
    CU_ASSERT_EQUAL(fexists(FNAME), 0);
}

static void test_opentwo(void)
{
    struct db *db1 = NULL;
    struct db *db2 = NULL;
    int r;

    CU_ASSERT_EQUAL(fexists(FNAME), -ENOENT);
    CU_ASSERT_EQUAL(fexists(FNAME2), -ENOENT);

    /* open() with _CREATE succeeds and creates the db */
    r = DB->open(FNAME, CYRUSDB_CREATE, &db1);
    CU_ASSERT_EQUAL(r, CYRUSDB_OK);
    CU_ASSERT_PTR_NOT_NULL(db1);
    CU_ASSERT_EQUAL(fexists(FNAME), 0);
    CU_ASSERT_EQUAL(fexists(FNAME2), -ENOENT);

    /* open() of the 2nd filename with _CREATE
     * succeeds and creates another separate db */
    r = DB->open(FNAME2, CYRUSDB_CREATE, &db2);
    CU_ASSERT_EQUAL(r, CYRUSDB_OK);
    CU_ASSERT_PTR_NOT_NULL(db2);
    CU_ASSERT_EQUAL(fexists(FNAME), 0);
    CU_ASSERT_EQUAL(fexists(FNAME2), 0);
    CU_ASSERT_PTR_NOT_EQUAL(db1, db2);

    /* closing succeeds and leaves the file in place */
    r = DB->close(db1);
    CU_ASSERT_EQUAL(r, CYRUSDB_OK);

    /* closing the other reference succeeds and leaves the file in place */
    r = DB->close(db2);
    CU_ASSERT_EQUAL(r, CYRUSDB_OK);

    CU_ASSERT_EQUAL(fexists(FNAME), 0);
    CU_ASSERT_EQUAL(fexists(FNAME2), 0);
}

static void test_readwrite(void)
{
    struct db *db = NULL;
    struct txn *txn = NULL;
    static const char KEY[] = "skeleton";
    static const char DATA[] = "dem bones dem bones dem thighbones";
    int r;

    r = DB->open(FNAME, CYRUSDB_CREATE, &db);
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

    r = DB->open(FNAME, CYRUSDB_CREATE, &db);
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

static void test_abort(void)
{
    struct db *db = NULL;
    struct txn *txn = NULL;
    static const char KEY[] = "yale";
    static const char DATA[] = "standford mit harvard";
    int r;

    r = DB->open(FNAME, CYRUSDB_CREATE, &db);
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

    r = DB->open(FNAME, CYRUSDB_CREATE, &db);
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
		     const char *key, int keylen,
		     const char *data, int datalen)
{
    strarray_t *resultsp = (strarray_t *)rock;

    /* check that key and data are correct and NUL-terminated */
    CU_ASSERT_PTR_NOT_NULL(key);
    CU_ASSERT(keylen > 0);
    CU_ASSERT(key[keylen] == '\0');
    CU_ASSERT_EQUAL(keylen, strlen(key));

    CU_ASSERT_PTR_NOT_NULL(data);
    CU_ASSERT(datalen > 0);
    CU_ASSERT(data[datalen] == '\0');
    CU_ASSERT_EQUAL(datalen, strlen(data));

    /* remember them for later perusal */
    strarray_append(resultsp, key);
    strarray_append(resultsp, data);

    return 0;
}

static void test_foreach(void)
{
    struct db *db = NULL;
    struct txn *txn = NULL;
    strarray_t results = STRARRAY_INITIALIZER;
    /* random word generator to the rescue! */
    static const char KEY1[] = "carib";
    static const char DATA1[] = "delays maj bullish packard ronald";
    static const char KEY2[] = "cubist";
    static const char DATA2[] = "bobby tswana cu albumin created";
    static const char KEY3[] = "eulogy";
    static const char DATA3[] = "aleut stoic muscovy adonis moe docent";
    int r;

    r = DB->open(FNAME, CYRUSDB_CREATE, &db);
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

    /* foreach iterated over exactly all the keys */
    CU_ASSERT_EQUAL(results.count, 6);

    r = strarray_find(&results, KEY1, 0);
    CU_ASSERT(r >= 0 && r < 6 && r % 2 == 0);
    CU_ASSERT_STRING_EQUAL(results.data[r+1], DATA1);

    r = strarray_find(&results, KEY2, 0);
    CU_ASSERT(r >= 0 && r < 6 && r % 2 == 0);
    CU_ASSERT_STRING_EQUAL(results.data[r+1], DATA2);

    r = strarray_find(&results, KEY3, 0);
    CU_ASSERT(r >= 0 && r < 6 && r % 2 == 0);
    CU_ASSERT_STRING_EQUAL(results.data[r+1], DATA3);

    /* close the txn - it doesn't matter here if we commit or abort */
    CANCOMMIT();

    /* closing succeeds */
    r = DB->close(db);
    CU_ASSERT_EQUAL(r, CYRUSDB_OK);

    strarray_fini(&results);
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
		  const char *key, int keylen,
		  const char *data, int datalen)
{
    hash_table *exphash = (hash_table *)rock;
    char *expected;

    /* check that key and data are correct and NUL-terminated */
    CU_ASSERT_PTR_NOT_NULL(key);
    CU_ASSERT(keylen > 0);
    CU_ASSERT(key[keylen] == '\0');
    CU_ASSERT_EQUAL(keylen, strlen(key));

    CU_ASSERT_PTR_NOT_NULL(data);
    CU_ASSERT(datalen > 0);
    CU_ASSERT(data[datalen] == '\0');
    CU_ASSERT_EQUAL(datalen, strlen(data));

    expected = hash_lookup(key, exphash);
    CU_ASSERT_STRING_EQUAL(data, expected);
    hash_del(key, exphash);
    free(expected);

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

    r = DB->open(FNAME, CYRUSDB_CREATE, &db);
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




static int set_up(void)
{
    int r;
    const char * const *d;
    static const char * const dirs[] = {
	DBDIR,
	DBDIR"/db",
	DBDIR"/conf",
	DBDIR"/conf/lock/",
	DBDIR"/conf/lock/user",
	NULL
    };

    r = system("rm -rf " DBDIR);
    if (r)
	return r;

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
    );

    cyrusdb_init();
    DB = cyrusdb_fromname(BACKEND);
    if (!DB)
	return -1;

    return 0;
}

static int tear_down(void)
{
    int r;

    cyrusdb_done();

    r = system("rm -rf " DBDIR);
    /* I'm ignoring you */

    return 0;
}

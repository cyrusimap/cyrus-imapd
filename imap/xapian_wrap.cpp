#include <errno.h>
#include <config.h>
#include <string.h>
#include <sys/types.h>
#include <syslog.h>

#include <fstream>
#include <sstream>
#include <algorithm>
#include <memory>

extern "C" {
#include <assert.h>
#include "libconfig.h"
#include "util.h"
#include "search_engines.h"
#include "search_part.h"
#include "xmalloc.h"
#include "xapian_wrap.h"
#include "charset.h"
#include "ptrarray.h"


/* generated headers are not necessarily in current directory */
#include "imap/imap_err.h"
};

#include <unicode/unistr.h>
#include <unicode/locid.h>

#include <xapian.h>

// from global.h
extern int charset_flags;

#define SLOT_CYRUSID        0

/* ====================================================================== */

static void make_cyrusid(struct buf *dst, const struct message_guid *guid, char doctype)
{
    buf_reset(dst);
    buf_putc(dst, '*');
    buf_putc(dst, doctype);
    buf_putc(dst, '*');
    buf_appendcstr(dst, message_guid_encode(guid));
}

/* ====================================================================== */

// Process-scoped, thread-unsafe cache of stoppers by ISO 639-1 code.
static std::map<std::string, std::unique_ptr<Xapian::Stopper>> stoppers;

static const Xapian::Stopper* get_stopper(const std::string& iso)
{
    // Lookup cached entry.
    try {
        return stoppers.at(iso).get();
    } catch (const std::out_of_range&) {};

    // Lookup language name by ISO code.
    std::string lang_name;
    icu::Locale loc(iso.c_str());
    if (loc.isBogus()) return NULL;
    icu::UnicodeString ulang_name;
    loc.getDisplayLanguage(icu::Locale("en"), ulang_name);
    ulang_name.toLower();
    ulang_name.toUTF8String(lang_name);

    // Read stopper file and add to cache.
    const char *swpath = config_getstring(IMAPOPT_SEARCH_STOPWORD_PATH);
    if (!swpath) return NULL;

    // Open stopword file
    // XXX doesn't play nice with WIN32 paths
    std::string fname(std::string(swpath) + "/" + lang_name + ".txt");
    errno = 0;
    std::ifstream inFile (fname);
    if (inFile.fail()) {
        syslog(LOG_DEBUG, "Xapian: could not open stopword file %s: %s",
                fname.c_str(), errno ? strerror(errno) : "unknown error");
        return NULL;
    }

    // Create and store the Xapian stopper
    stoppers[iso].reset(new Xapian::SimpleStopper(
                std::istream_iterator<std::string>(inFile),
                std::istream_iterator<std::string>()));
    return stoppers[iso].get();
}

/* ====================================================================== */

class CyrusSearchStemmer : public Xapian::StemImplementation
{
    charset_t utf8 {charset_lookupname("utf-8")};
    std::map<const std::string, std::string> cache;
    Xapian::Stem stem {"en"};

    public:
    virtual ~CyrusSearchStemmer() { charset_free(&utf8); }

    virtual std::string operator() (const std::string &word) override {
        // Is this word already in the cache?
        try {
            return cache.at(word);
        } catch (const std::out_of_range&) {}

        // Convert the word to search form
        std::unique_ptr<char, decltype(std::free)*> q {charset_convert(word.c_str(), utf8, charset_flags), std::free};
        if (!q) {
            return stem(word);
        }

        // Store the normalized word in the cache
        return cache[word] = stem(Xapian::Unicode::tolower(q.get()));
    }

    virtual std::string get_description () const override {
        return "Cyrus";
    }
};

/* ====================================================================== */

/*
 * A brief history of Xapian db versions:
 * Version 0: uses STEM_ALL for all terms, term prefixes don't start with 'X'
 * Version 1: term prefixes start with 'X'
 * Version 2: uses STEM_SOME for some terms
 * Version 3: removes all use of STEM_ALL
 * Version 4: indexes headers and bodies in separate documents
 * Version 5: indexes headers and bodies together and stems by language
 */
#define XAPIAN_DB_CURRENT_VERSION 5
#define XAPIAN_DB_MIN_SUPPORTED_VERSION 2

static std::set<int> get_db_versions(const Xapian::Database &database)
{
    std::set<int> versions;

    // db_version is a comma-separated list of version numbers
    std::string val = database.get_metadata("cyrus.db_version");
    if (!val.empty()) {
        strarray_t *vstr = strarray_split(val.c_str(), ",", 0);
        for (int i = 0; i < strarray_size(vstr); i++) {
            int version = std::atoi(strarray_nth(vstr, i));
            if (version) versions.insert(version);
        }
        strarray_free(vstr);
    }
    // Up to version 3 this was named stem version.
    val = database.get_metadata("cyrus.stem-version");
    if (!val.empty()) {
        versions.insert(std::stoi(val));
    }

    return versions;
}

static void set_db_versions(Xapian::WritableDatabase &database, std::set<int> &versions)
{
    std::ostringstream val;
    for (std::set<int>::iterator it = versions.begin(); it != versions.end(); ++it) {
        if (it != versions.begin()) val << ",";
        val << *it;
    }
    database.set_metadata("cyrus.db_version", val.str());
    database.set_metadata("cyrus.stem-version", "");
}

/* ====================================================================== */

EXPORTED int xapian_compact_dbs(const char *dest, const char **sources)
{
    int r = 0;
    Xapian::Database db;
    const char *thispath = "(unknown path)";
    std::set<int> db_versions;

    try {
        while (*sources) {
            thispath = *sources;
            Xapian::Database subdb(*sources++);
            db.add_database(subdb);

            // Aggregate db versions.
            std::set<int> subdb_versions = get_db_versions(subdb);
            db_versions.insert(subdb_versions.begin(), subdb_versions.end());
        }
        thispath = "(unknown path)";

        /* FULLER because we never write to compression targets again */
        db.compact(dest, Xapian::Compactor::FULLER | Xapian::DBCOMPACT_MULTIPASS);

        Xapian::WritableDatabase newdb(dest);
        set_db_versions(newdb, db_versions);
    }
    catch (const Xapian::Error &err) {
        syslog(LOG_ERR, "IOERROR: Xapian: caught exception compact_dbs: %s: %s (%s)",
                err.get_context().c_str(), err.get_description().c_str(), thispath);
        r = IMAP_IOERROR;
    }

    return r;
}

/* ====================================================================== */

static const char *get_term_prefix(int db_version, int partnum)
{
    /*
     * We use term prefixes to store terms per search part.
     * In addition, each Xapian document contains a special
     * prefix to indicate its document type, e.g. 'G' for
     * a message, or 'P' for a MIME part. This allow to query
     * search results by both search part queries and filter
     * by document type.
     *
     * The prefix "XE" is reserved for the document type and
     * MUST not be used for any search part.
     *
     * The prefix "XI" is reserved for future use.
     *
     */
    static const char * const term_prefixes[SEARCH_NUM_PARTS] = {
        NULL,
        "XF",                /* FROM */
        "XT",                /* TO */
        "XC",                /* CC */
        "XB",                /* BCC */
        "XS",                /* SUBJECT */
        "XL",                /* LISTID */
        "XY",                /* TYPE */
        "XH",                /* HEADERS */
        "",                  /* BODY */
        "XO",                /* LOCATION */
        "XA",                /* ATTACHMENTNAME */
        "XAB"                /* ATTACHMENTBODY */
    };

    static const char * const term_prefixes_v0[SEARCH_NUM_PARTS] = {
        NULL,
        "F",                /* FROM */
        "T",                /* TO */
        "C",                /* CC */
        "B",                /* BCC */
        "S",                /* SUBJECT */
        "L",                /* LISTID */
        "Y",                /* TYPE */
        "H",                /* HEADERS */
        "D",                /* BODY */
        "O",                /* LOCATION */
        "A",                /* ATTACHMENTNAME */
        "AB"                /* ATTACHMENTBODY */
    };

    return db_version > 0 ? term_prefixes[partnum] : term_prefixes_v0[partnum];
}

static Xapian::TermGenerator::stem_strategy get_stem_strategy(int db_version, int partnum)
{
    static Xapian::TermGenerator::stem_strategy stem_strategy[SEARCH_NUM_PARTS] = {
        // Version 2 and higher
        Xapian::TermGenerator::STEM_NONE,
        Xapian::TermGenerator::STEM_NONE,  /* FROM */
        Xapian::TermGenerator::STEM_NONE,  /* TO */
        Xapian::TermGenerator::STEM_NONE,  /* CC */
        Xapian::TermGenerator::STEM_NONE,  /* BCC */
        Xapian::TermGenerator::STEM_SOME,  /* SUBJECT */
        Xapian::TermGenerator::STEM_NONE,  /* LISTID */
        Xapian::TermGenerator::STEM_NONE,  /* TYPE */
        Xapian::TermGenerator::STEM_NONE,  /* HEADERS */
        Xapian::TermGenerator::STEM_SOME,  /* BODY */
        Xapian::TermGenerator::STEM_SOME,  /* LOCATION */
        Xapian::TermGenerator::STEM_NONE,  /* ATTACHMENTNAME */
        Xapian::TermGenerator::STEM_SOME   /* ATTACHMENTBODY */
    };

    static Xapian::TermGenerator::stem_strategy stem_strategy_v1[SEARCH_NUM_PARTS] = {
        // Version 1: Stem bodies using STEM_SOME with stopwords
        Xapian::TermGenerator::STEM_NONE,
        Xapian::TermGenerator::STEM_ALL,   /* FROM */
        Xapian::TermGenerator::STEM_ALL,   /* TO */
        Xapian::TermGenerator::STEM_ALL,   /* CC */
        Xapian::TermGenerator::STEM_ALL,   /* BCC */
        Xapian::TermGenerator::STEM_ALL,   /* SUBJECT */
        Xapian::TermGenerator::STEM_ALL,   /* LISTID */
        Xapian::TermGenerator::STEM_ALL,   /* TYPE */
        Xapian::TermGenerator::STEM_ALL,   /* HEADERS */
        Xapian::TermGenerator::STEM_SOME,  /* BODY */
        Xapian::TermGenerator::STEM_SOME,  /* LOCATION */
        Xapian::TermGenerator::STEM_NONE,  /* ATTACHMENTNAME */
        Xapian::TermGenerator::STEM_SOME   /* ATTACHMENTBODY */
    };

    static Xapian::TermGenerator::stem_strategy stem_strategy_v0[SEARCH_NUM_PARTS] = {
        // Version 0: Initial version
        Xapian::TermGenerator::STEM_NONE,
        Xapian::TermGenerator::STEM_ALL,   /* FROM */
        Xapian::TermGenerator::STEM_ALL,   /* TO */
        Xapian::TermGenerator::STEM_ALL,   /* CC */
        Xapian::TermGenerator::STEM_ALL,   /* BCC */
        Xapian::TermGenerator::STEM_ALL,   /* SUBJECT */
        Xapian::TermGenerator::STEM_ALL,   /* LISTID */
        Xapian::TermGenerator::STEM_ALL,   /* TYPE */
        Xapian::TermGenerator::STEM_ALL,   /* HEADERS */
        Xapian::TermGenerator::STEM_ALL,   /* BODY */
        Xapian::TermGenerator::STEM_ALL,   /* LOCATION */
        Xapian::TermGenerator::STEM_ALL,   /* ATTACHMENTNAME */
        Xapian::TermGenerator::STEM_ALL    /* ATTACHMENTBODY */
    };

    switch (db_version) {
        case 0:
            return stem_strategy_v0[partnum];
        case 1:
            return stem_strategy_v1[partnum];
        default:
            return stem_strategy[partnum];
    }
}

/* For all db paths in sources that are not using the latest database
 * version or not readable, report their paths in toreindex */
EXPORTED void xapian_check_if_needs_reindex(const strarray_t *sources, strarray_t *toreindex, int always_upgrade)
{
    // Check the version of all dbs in sources
    for (int i = 0; i < sources->count; i++) {
        const char *thispath = strarray_nth(sources, i);
        try {
            for (const int& it: get_db_versions(Xapian::Database{thispath})) {
                if (it < XAPIAN_DB_MIN_SUPPORTED_VERSION ||
                        (always_upgrade && (it != XAPIAN_DB_CURRENT_VERSION))) {
                    strarray_add(toreindex, thispath);
                }
            }
        }
        catch (const Xapian::Error &err) {
            strarray_add(toreindex, thispath);
        }
    }
}

/* ====================================================================== */

struct xapian_dbw
{
    Xapian::WritableDatabase *database;
    Xapian::Stem *stemmer;
    Xapian::TermGenerator *term_generator;
    Xapian::Document *document;
    char doctype;
    Xapian::Stopper *stopper;
    ptrarray_t otherdbs;
    char *cyrusid;
    Xapian::Stem *default_stemmer;
    const Xapian::Stopper* default_stopper;
    bool is_inmemory;
};


static int xapian_dbw_init(xapian_dbw_t *dbw)
{
    dbw->default_stemmer = new Xapian::Stem(new CyrusSearchStemmer);
    dbw->default_stopper = get_stopper("en");
    dbw->term_generator = new Xapian::TermGenerator;
    /* Always enable CJK word tokenization */
#ifdef USE_XAPIAN_CJK_WORDS
    dbw->term_generator->set_flags(Xapian::TermGenerator::FLAG_CJK_WORDS,
            ~Xapian::TermGenerator::FLAG_CJK_WORDS);
#else
    dbw->term_generator->set_flags(Xapian::TermGenerator::FLAG_CJK_NGRAM,
            ~Xapian::TermGenerator::FLAG_CJK_NGRAM);
#endif
    dbw->term_generator->set_stopper(dbw->stopper);
    return 0;
}

EXPORTED int xapian_dbw_open(const char **paths, xapian_dbw_t **dbwp, int mode)
{
    xapian_dbw_t *dbw = (xapian_dbw_t *)xzmalloc(sizeof(xapian_dbw_t));
    int r = 0;
    const char *thispath = *paths++;

    std::set<int> db_versions;
    try {
        /* Determine the sterm version of an existing database, or create a
         * new one with the latest one. Never implicitly upgrade. */
        try {
            dbw->database = new Xapian::WritableDatabase{thispath, Xapian::DB_OPEN};
            db_versions = get_db_versions(*dbw->database);
        } catch (Xapian::DatabaseOpeningError &e) {
            /* It's OK not to atomically create or open, since we can assume
             * the xapianactive file items to be locked. */
            dbw->database = new Xapian::WritableDatabase{thispath, Xapian::DB_CREATE|Xapian::DB_BACKEND_GLASS};
        }

        if (db_versions.find(XAPIAN_DB_CURRENT_VERSION) == db_versions.end()) {
            // Always index using latest database version.
            db_versions.insert(XAPIAN_DB_CURRENT_VERSION);
            set_db_versions(*dbw->database, db_versions);
        }

        r = xapian_dbw_init(dbw);

    }
    catch (const Xapian::DatabaseLockError &err) {
        /* somebody else is already indexing this user.  They may be doing a different
         * mailbox, so we need to re-insert this mailbox into the queue! */
        r = IMAP_MAILBOX_LOCKED;
    }
    catch (const Xapian::Error &err) {
        syslog(LOG_ERR, "IOERROR: Xapian: caught exception dbw_open: %s: %s (%s)",
                    err.get_context().c_str(), err.get_description().c_str(), thispath);
        r = IMAP_IOERROR;
    }

    if (r) {
        xapian_dbw_close(dbw);
        return r;
    }

    /* open the read-only databases */
    if (mode == XAPIAN_DBW_XAPINDEXED) {
        while (*paths) {
            try {
                thispath = *paths;
                ptrarray_append(&dbw->otherdbs, new Xapian::Database{*paths++});
            }
            catch (const Xapian::Error &err) {
                syslog(LOG_ERR, "IOERROR: Xapian: caught exception dbw_open read: %s: %s (%s)",
                            err.get_context().c_str(), err.get_description().c_str(), thispath);
            }
        }
    }

    *dbwp = dbw;

    return 0;
}

EXPORTED int xapian_dbw_openmem(struct xapian_dbw **dbwp)
{
    xapian_dbw_t *dbw = (xapian_dbw_t *)xzmalloc(sizeof(xapian_dbw_t));
    dbw->is_inmemory = true;

    dbw->database = new Xapian::WritableDatabase{"", Xapian::DB_BACKEND_INMEMORY};
    std::set<int> db_versions {XAPIAN_DB_CURRENT_VERSION};
    set_db_versions(*dbw->database, db_versions);

    int r = xapian_dbw_init(dbw);
    if (r) {
        xapian_dbw_close(dbw);
        dbw = NULL;
    }

    *dbwp = dbw;
    return r;
}

EXPORTED void xapian_dbw_close(xapian_dbw_t *dbw)
{
    if (!dbw) return;
    try {
        delete dbw->database;
        delete dbw->term_generator;
        delete dbw->stemmer;
        delete dbw->stopper;
        delete dbw->document;
        delete dbw->default_stemmer;
        for (int i = 0; i < dbw->otherdbs.count; i++) {
            delete (Xapian::Database *)ptrarray_nth(&dbw->otherdbs, i);
        }
        ptrarray_fini(&dbw->otherdbs);
        if (dbw->cyrusid) free(dbw->cyrusid);
        free(dbw);
    }
    catch (const Xapian::Error &err) {
        syslog(LOG_ERR, "IOERROR: Xapian: caught exception dbw_close: %s: %s",
                    err.get_context().c_str(), err.get_description().c_str());
    }
}

EXPORTED int xapian_dbw_begin_txn(xapian_dbw_t *dbw)
{
    int r = 0;
    try {
        dbw->database->begin_transaction();
    }
    catch (const Xapian::Error &err) {
        syslog(LOG_ERR, "IOERROR: Xapian: caught exception begin_txn: %s: %s",
                    err.get_context().c_str(), err.get_description().c_str());
        r = IMAP_IOERROR;
    }
    return r;
}

EXPORTED int xapian_dbw_commit_txn(xapian_dbw_t *dbw)
{
    int r = 0;
    try {
        dbw->database->commit_transaction();
    }
    catch (const Xapian::Error &err) {
        syslog(LOG_ERR, "IOERROR: Xapian: caught exception commit_txn: %s: %s",
                    err.get_context().c_str(), err.get_description().c_str());
        r = IMAP_IOERROR;
    }
    return r;
}

EXPORTED int xapian_dbw_cancel_txn(xapian_dbw_t *dbw)
{
    int r = 0;
    try {
        dbw->database->cancel_transaction();
    }
    catch (const Xapian::Error &err) {
        syslog(LOG_ERR, "IOERROR: Xapian: caught exception cancel_txn: %s: %s",
                    err.get_context().c_str(), err.get_description().c_str());
        r = IMAP_IOERROR;
    }
    return r;
}

EXPORTED int xapian_dbw_begin_doc(xapian_dbw_t *dbw, const struct message_guid *guid, char doctype)
{
    int r = 0;

    try {
        delete dbw->document;
        dbw->document = new Xapian::Document;
        dbw->doctype = doctype;
        /* Set document id and type */
        struct buf buf = BUF_INITIALIZER;
        make_cyrusid(&buf, guid, doctype);
        dbw->document->add_value(SLOT_CYRUSID, buf_cstring(&buf));
        dbw->cyrusid = buf_release(&buf);
        dbw->document->add_boolean_term(std::string("XE") + doctype);
        /* Initialize term generator */
        dbw->term_generator->set_document(*dbw->document);
        dbw->term_generator->set_termpos(1);
    }
    catch (const Xapian::Error &err) {
        syslog(LOG_ERR, "IOERROR: Xapian: caught exception begin_doc: %s: %s",
                    err.get_context().c_str(), err.get_description().c_str());
        r = IMAP_IOERROR;
    }
    return r;
}

EXPORTED int xapian_dbw_doc_part(xapian_dbw_t *dbw, const struct buf *part, int num_part)
{
    int r = 0;

    const char *prefix = get_term_prefix(XAPIAN_DB_CURRENT_VERSION, num_part);
    if (!prefix) {
        syslog(LOG_ERR, "xapian_wrapper: no prefix for num_part %d", num_part);
        return IMAP_INTERNAL;
    }

    try {
        Xapian::TermGenerator::stem_strategy stem_strategy =
            get_stem_strategy(XAPIAN_DB_CURRENT_VERSION, num_part);
        dbw->term_generator->set_stemming_strategy(stem_strategy);

        // Index text.
        if (stem_strategy != Xapian::TermGenerator::STEM_NONE) {
            // Index with default stemmer.
            dbw->term_generator->set_stemmer(*dbw->default_stemmer);
            dbw->term_generator->set_stopper(dbw->default_stopper);
        } else {
            // Index with no stemming.
            dbw->term_generator->set_stemmer(Xapian::Stem());
            dbw->term_generator->set_stopper(NULL);
        }
        dbw->term_generator->index_text(Xapian::Utf8Iterator(part->s, part->len), 1, prefix);

        // Finalize index.
        dbw->term_generator->increase_termpos();
    }
    catch (const Xapian::Error &err) {
        syslog(LOG_ERR, "IOERROR: Xapian: caught exception doc_part: %s: %s",
                    err.get_context().c_str(), err.get_description().c_str());
        r = IMAP_IOERROR;
    }
    return r;
}

EXPORTED int xapian_dbw_end_doc(xapian_dbw_t *dbw)
{
    int r = 0;
    try {
        dbw->database->add_document(*dbw->document);
        dbw->database->set_metadata("cyrusid." + std::string(dbw->cyrusid), "1");
        delete dbw->document;
        dbw->document = 0;
        dbw->doctype = 0;
        if (dbw->cyrusid) free(dbw->cyrusid);
        dbw->cyrusid = NULL;
    }
    catch (const Xapian::Error &err) {
        syslog(LOG_ERR, "IOERROR: Xapian: caught exception end_doc: %s: %s",
                    err.get_context().c_str(), err.get_description().c_str());
        r = IMAP_IOERROR;
    }
    return r;
}

EXPORTED int xapian_dbw_is_indexed(xapian_dbw_t *dbw, const struct message_guid *guid, char doctype)
{
    struct buf buf = BUF_INITIALIZER;
    make_cyrusid(&buf, guid, doctype);
    std::string key = "cyrusid." + std::string(buf_cstring(&buf));
    buf_free(&buf);

    /* indexed in the current DB? */
    if (!dbw->database->get_metadata(key).empty())
        return 1;

    /* indexed in other DBs? */
    for (int i = 0; i < dbw->otherdbs.count; i++) {
        Xapian::Database *database = (Xapian::Database *)ptrarray_nth(&dbw->otherdbs, i);
        if (!database->get_metadata(key).empty()) return 1;
    }

    /* nup */
    return 0;
}

/* ====================================================================== */

struct xapian_db
{
    std::string *paths;
    Xapian::Database *database; // all but version 4 databases
    Xapian::Database *legacydbv4; // version 4 databases
    std::vector<Xapian::Database> *shards; // all database shards
    Xapian::Stem *default_stemmer;
    const Xapian::Stopper* default_stopper;
    Xapian::QueryParser *parser;
    std::set<int> *db_versions;
    xapian_dbw_t *dbw;
};

static int xapian_db_init(xapian_db_t *db)
{
    int r = 0;

    try {
        db->parser = new Xapian::QueryParser;
        db->parser->set_default_op(Xapian::Query::OP_AND);
        db->parser->set_database(db->database ? *db->database : *db->legacydbv4);
        db->default_stemmer = new Xapian::Stem(new CyrusSearchStemmer);
        db->default_stopper = get_stopper("en");
    }
    catch (const Xapian::Error &err) {
        syslog(LOG_ERR, "IOERROR: Xapian: caught exception db_open: %s: %s",
                "<inmemory>", err.get_description().c_str());
        r = IMAP_IOERROR;
    }

    return r;
}

EXPORTED int xapian_db_open(const char **paths, xapian_db_t **dbp)
{
    xapian_db_t *db = (xapian_db_t *)xzmalloc(sizeof(xapian_db_t));
    const char *thispath = "(unknown)";
    int r = 0;

    try {
        db->paths = new std::string;
        while (paths && *paths) {
            thispath = *paths++;
            Xapian::Database subdb {thispath};
            std::set<int> db_versions = get_db_versions(subdb);
            if (db_versions.empty()) {
                syslog(LOG_ERR, "xapian_wrapper: invalid db version in %s", thispath);
                r = IMAP_INTERNAL;
                goto done;
            }
            if (!db->db_versions)
                db->db_versions = new std::set<int>;
            db->db_versions->insert(db_versions.begin(), db_versions.end());
            // Databases with version 4 split indexing by doctype.
            if (db_versions.find(4) != db_versions.end()) {
                if (!db->legacydbv4) db->legacydbv4 = new Xapian::Database;
                db->legacydbv4->add_database(subdb);
            }
            // Databases with any but version 4 are regular dbs.
            if (db_versions.size() > 1 || db_versions.find(4) == db_versions.end()) {
                if (!db->database) db->database = new Xapian::Database;
                db->database->add_database(subdb);
            }

            // Xapian database has no API to access shards.
            if (!db->shards) db->shards = new std::vector<Xapian::Database>;
            db->shards->push_back(subdb);

            db->paths->append(thispath).push_back(' ');
        }
        thispath = "(unknown)";

        if (!db->database && !db->legacydbv4) {
            r = IMAP_NOTFOUND;
            goto done;
        }

        r = xapian_db_init(db);
        if (r) goto done;
    }
    catch (const Xapian::Error &err) {
        syslog(LOG_ERR, "IOERROR: Xapian: caught exception db_open: %s: %s",
                    thispath, err.get_description().c_str());
        r = IMAP_IOERROR;
    }

done:
    if (r)
        xapian_db_close(db);
    else
        *dbp = db;

    return r;
}

EXPORTED int xapian_db_opendbw(struct xapian_dbw *dbw, xapian_db_t **dbp)
{
    xapian_db_t *db = (xapian_db_t *)xzmalloc(sizeof(xapian_db_t));

    db->dbw = dbw;
    db->database = dbw->database;
    db->db_versions = new std::set<int>();
    std::set<int> dbw_versions = get_db_versions(*dbw->database);
    db->db_versions->insert(dbw_versions.begin(), dbw_versions.end());
    db->shards = new std::vector<Xapian::Database>;
    db->shards->push_back(*dbw->database);

    int r = xapian_db_init(db);
    if (r) {
        xapian_db_close(db);
        db = NULL;
    }

    *dbp = db;
    return r;
}

EXPORTED void xapian_db_close(xapian_db_t *db)
{
    if (!db) return;
    try {
        if (!db->dbw) delete db->database;
        delete db->legacydbv4;
        delete db->parser;
        delete db->paths;
        delete db->db_versions;
        delete db->default_stemmer;
        delete db->shards;
        free(db);
    }
    catch (const Xapian::Error &err) {
        /* XXX - memory leak? */
        syslog(LOG_ERR, "IOERROR: Xapian: caught exception db_close: %s: %s",
                    err.get_context().c_str(), err.get_description().c_str());
    }
}

EXPORTED int xapian_db_has_otherthan_v4_index(const xapian_db_t *db)
{
    return db->database != NULL;
}

EXPORTED int xapian_db_has_legacy_v4_index(const xapian_db_t *db)
{
    return db->legacydbv4 != NULL;
}

static Xapian::Query *make_stem_match_query(const xapian_db_t *db,
                                            const char *match,
                                            const char *prefix,
                                            Xapian::TermGenerator::stem_strategy tg_stem_strategy)
{
    unsigned flags = Xapian::QueryParser::FLAG_PHRASE |
                     Xapian::QueryParser::FLAG_LOVEHATE |
                     Xapian::QueryParser::FLAG_WILDCARD;

    if (tg_stem_strategy != Xapian::TermGenerator::STEM_NONE) {

        // STEM_SOME doesn't work for terms starting with upper case,
        // which will break for languages such as German. We also can't use
        // STEM_ALL_Z, as this would force-stem phrase queries. Best guess
        // is to lower case the query and risk stemming proper nouns.
        std::string lmatch(match);
        std::transform(lmatch.begin(), lmatch.end(), lmatch.begin(), ::tolower);

        // Query without any stemmer.
        db->parser->set_stemmer(Xapian::Stem());
        db->parser->set_stopper(NULL);
        db->parser->set_stemming_strategy(Xapian::QueryParser::STEM_NONE);
        Xapian::Query q = db->parser->parse_query(lmatch, flags, prefix);

        // Query with default stemmer. But don't stem stopwords.
        if (!db->default_stopper || !(*db->default_stopper)(lmatch)) {
            db->parser->set_stemmer(*db->default_stemmer);
            db->parser->set_stopper(db->default_stopper);
            db->parser->set_stemming_strategy(Xapian::QueryParser::STEM_SOME);
            q |= db->parser->parse_query(lmatch, flags, prefix);
        }

        return new Xapian::Query(q);
    }
    else {
        db->parser->set_stemmer(Xapian::Stem());
        db->parser->set_stopper(NULL);
        db->parser->set_stemming_strategy(Xapian::QueryParser::STEM_NONE);
        return new Xapian::Query {db->parser->parse_query(match, flags, prefix)};
    }
}

EXPORTED xapian_query_t *
xapian_query_new_match(const xapian_db_t *db, int partnum, const char *str)
{
    if (db->shards->empty()) {
        // no database to query
        return NULL;
    }
    const char *prefix = get_term_prefix(XAPIAN_DB_CURRENT_VERSION, partnum);
    if (!prefix) {
        // Legacy prefix handling code, this is not an error
        return NULL;
    }

    try {
        int min_version = *db->db_versions->begin();
        if (min_version < XAPIAN_DB_MIN_SUPPORTED_VERSION) {
            syslog(LOG_ERR, "Xapian: db versions < %d are deprecated. Reindex your dbs.",
                    XAPIAN_DB_MIN_SUPPORTED_VERSION);
        }

        // Don't stem queries for Thaana codepage (0780) or higher.
        for (const unsigned char *p = (const unsigned char *)str; *p; p++) {
            if (*p > 221) //has highbit
                return (xapian_query_t *) new Xapian::Query {db->parser->parse_query(
                    str,
#ifdef USE_XAPIAN_CJK_WORDS
                    Xapian::QueryParser::FLAG_CJK_WORDS,
#else
                    Xapian::QueryParser::FLAG_CJK_NGRAM,
#endif
                    prefix)};
        }

        // Regular codepage.
        Xapian::TermGenerator::stem_strategy stem_strategy =
            get_stem_strategy(XAPIAN_DB_CURRENT_VERSION, partnum);
        return (xapian_query_t *) make_stem_match_query(db, str, prefix, stem_strategy);

    } catch (const Xapian::Error &err) {
        syslog(LOG_ERR, "IOERROR: Xapian: caught exception match_internal: %s: %s",
                err.get_context().c_str(), err.get_description().c_str());
        return 0;
    }
}

EXPORTED xapian_query_t *xapian_query_new_compound(const xapian_db_t *db __attribute__((unused)),
                                          int is_or, xapian_query_t **children, int n)
{
    try {
        // I want to use std::initializer_list<Xapian::Query*> here
        // but that requires "experimental" gcc C++0x support :(
        // 'compound' owns a refcount on each child.  We need to
        // drop the one we got when we allocated the children
        Xapian::Query* compound = new Xapian::Query;
        if (is_or)
            for (int i = 0 ; i < n ; i++) {
                *compound |= *(Xapian::Query*)children[i];
                delete (Xapian::Query*)children[i];
            }
        else
            for (int i = 0 ; i < n ; i++) {
                if (compound->empty())
                    *compound = *(Xapian::Query*)children[i];
                else
                    *compound &= *(Xapian::Query*)children[i];
                delete (Xapian::Query*)children[i];
            }
        return (xapian_query_t *)compound;
    }
    catch (const Xapian::Error &err) {
        syslog(LOG_ERR, "IOERROR: Xapian: caught exception new_compound: %s: %s",
                    err.get_context().c_str(), err.get_description().c_str());
        return 0;
    }
}

/* Xapian does not have an OP_NOT.  WTF?  We fake it with
 * OP_AND_NOT where the left child is MatchAll */
EXPORTED xapian_query_t *xapian_query_new_not(const xapian_db_t *db __attribute__((unused)),
                                     xapian_query_t *child)
{
    try {
        Xapian::Query *qq = new Xapian::Query(
                                        Xapian::Query::OP_AND_NOT,
                                        Xapian::Query::MatchAll,
                                        *(Xapian::Query *)child);
        // 'compound' owns a refcount on each child.  We need to
        // drop the one we got when we allocated the children
        delete (Xapian::Query *)child;
        return (xapian_query_t *)qq;
    }
    catch (const Xapian::Error &err) {
        syslog(LOG_ERR, "IOERROR: Xapian: caught exception new_not: %s: %s",
                    err.get_context().c_str(), err.get_description().c_str());
        return 0;
    }
}

EXPORTED xapian_query_t *xapian_query_new_matchall(const xapian_db_t *db __attribute__((unused)))
{
    return (xapian_query_t *) new Xapian::Query(Xapian::Query::MatchAll);
}

EXPORTED xapian_query_t *xapian_query_new_has_doctype(const xapian_db_t *db __attribute__((unused)),
                                             char doctype, xapian_query_t *child)
{
    try {
        Xapian::Query *qq = new Xapian::Query(
                                        Xapian::Query::OP_FILTER,
                                        child ? *(Xapian::Query *)child : Xapian::Query::MatchAll,
                                        std::string("XE") + doctype);
        // 'compound' owns a refcount on each child.  We need to
        // drop the one we got when we allocated the children
        delete (Xapian::Query *)child;
        return (xapian_query_t *)qq;
    }
    catch (const Xapian::Error &err) {
        syslog(LOG_ERR, "IOERROR: Xapian: caught exception new_filter_doctype: %s: %s",
                    err.get_context().c_str(), err.get_description().c_str());
        return 0;
    }
}

EXPORTED void xapian_query_free(xapian_query_t *qq)
{
    try {
        delete (Xapian::Query *)qq;
    }
    catch (const Xapian::Error &err) {
        syslog(LOG_ERR, "IOERROR: Xapian: caught exception query_free: %s: %s",
                    err.get_context().c_str(), err.get_description().c_str());
    }
}

EXPORTED int xapian_query_run(const xapian_db_t *db, const xapian_query_t *qq, int is_legacy,
                     int (*cb)(void *data, size_t n, void *rock), void *rock)
{
    const Xapian::Query *query = (const Xapian::Query *)qq;
    void *data = NULL;
    size_t n = 0;

    if ((is_legacy && !db->legacydbv4) || (!is_legacy && !db->database)) return 0;

    try {
        Xapian::Database *database = is_legacy ? db->legacydbv4 : db->database;
        Xapian::Enquire enquire(*database);
        enquire.set_query(*query);
        enquire.set_sort_by_value(0, false); // sort by cyrusid ascending
        Xapian::MSet matches = enquire.get_mset(0, database->get_doccount());
        size_t size = matches.size();
        if (size) data = xzmalloc(size * 41);
        for (Xapian::MSetIterator i = matches.begin() ; i != matches.end() ; ++i) {
            const Xapian::Document& d = i.get_document();
            const std::string& cyrusid = d.get_value(SLOT_CYRUSID);

            /* ignore documents with no cyrusid.  Shouldn't happen, but has been seen */
            if (cyrusid.length() != 43) {
                syslog(LOG_ERR, "IOERROR: Xapian: zero length cyrusid for document id %u in index files %s",
                                d.get_docid(), db->paths->c_str());
                continue;
            }
            const char *cstr = cyrusid.c_str();
            if (cstr[0] != '*' || !isalpha(cstr[1]) || cstr[2] != '*') {
                syslog(LOG_ERR, "IOERROR: Xapian: invalid cyrusid %s for document id %u in index files %s",
                                cstr, d.get_docid(), db->paths->c_str());
                continue;
            }
            if (n >= size) throw Xapian::DatabaseError("Too many records in MSet");
            char *entry = (char *) data + (41*n);
            memcpy(entry, cstr+3, 40);
            entry[40] = '\0';
            ++n;
        }
    }
    catch (const Xapian::Error &err) {
        syslog(LOG_ERR, "IOERROR: Xapian: caught exception query_run: %s: %s",
                    err.get_context().c_str(), err.get_description().c_str());
        free(data);
        return IMAP_IOERROR;
    }

    if (!n) {
        free(data);
        return 0;
    }

    int r = cb(data, n, rock);
    free(data);
    return r;
}

/* ====================================================================== */

struct xapian_snipgen
{
    Xapian::Stem *default_stemmer;
    xapian_db_t *db;
    Xapian::Database *memdb;
    std::vector<std::string> *loose_terms;
    std::vector<std::string> *queries;
    char *cyrusid;
    struct buf *buf;
    const char *hi_start;
    const char *hi_end;
    const char *omit;
    size_t max_len;
};

EXPORTED xapian_snipgen_t *xapian_snipgen_new(xapian_db_t *db,
                                     const char *hi_start,
                                     const char *hi_end,
                                     const char *omit)
{
    xapian_snipgen_t *snipgen = (xapian_snipgen_t *)xzmalloc(sizeof(xapian_snipgen_t));
    snipgen->default_stemmer = new Xapian::Stem(new CyrusSearchStemmer);
    snipgen->db = db;
    snipgen->memdb = new Xapian::WritableDatabase(std::string(), Xapian::DB_BACKEND_INMEMORY);
    snipgen->buf = buf_new();
    snipgen->hi_start = hi_start;
    snipgen->hi_end = hi_end;
    snipgen->omit = omit;
    snipgen->max_len = (size_t) config_getint(IMAPOPT_SEARCH_SNIPPET_LENGTH);

    return snipgen;
}

EXPORTED void xapian_snipgen_free(xapian_snipgen_t *snipgen)
{
    delete snipgen->default_stemmer;
    delete snipgen->loose_terms;
    delete snipgen->queries;
    delete snipgen->memdb;
    free(snipgen->cyrusid);
    buf_destroy(snipgen->buf);
    free(snipgen);
}

static Xapian::Query xapian_snipgen_build_query(xapian_snipgen_t *snipgen, Xapian::Stem& stemmer)
{
    Xapian::TermGenerator term_generator;
    Xapian::Query q;

    if (snipgen->loose_terms) {
        /* Add loose query terms */
        term_generator.set_stemmer(stemmer);
#ifdef USE_XAPIAN_CJK_WORDS
        term_generator.set_flags(Xapian::TermGenerator::FLAG_CJK_WORDS,
                ~Xapian::TermGenerator::FLAG_CJK_WORDS);
#else
        term_generator.set_flags(Xapian::TermGenerator::FLAG_CJK_NGRAM,
                ~Xapian::TermGenerator::FLAG_CJK_NGRAM);
#endif

        for(size_t i = 0; i < snipgen->loose_terms->size(); ++i)
        {
            term_generator.index_text(Xapian::Utf8Iterator((*snipgen->loose_terms)[i]));
        }

        const Xapian::Document& doc = term_generator.get_document();
        q = Xapian::Query(Xapian::Query::OP_OR, doc.termlist_begin(), doc.termlist_end());
    }

    if (snipgen->queries) {
        /* Add phrase queries */
        unsigned flags = Xapian::QueryParser::FLAG_PHRASE|
                         Xapian::QueryParser::FLAG_WILDCARD|
#ifdef USE_XAPIAN_CJK_WORDS
                         Xapian::QueryParser::FLAG_CJK_WORDS;
#else
                         Xapian::QueryParser::FLAG_CJK_NGRAM;
#endif
        Xapian::QueryParser queryparser;
        queryparser.set_stemmer(stemmer);
        for(size_t i = 0; i < snipgen->queries->size(); ++i) {
            q |= queryparser.parse_query((*snipgen->queries)[i], flags);;
        }
    }

    return q;
}

EXPORTED int xapian_snipgen_add_match(xapian_snipgen_t *snipgen, const char *match)
{
    size_t len = strlen(match);
    bool is_query = len > 1 && ((match[0] == '"' && match[len-1] == '"') ||
                                (strchr(match, '*') != NULL));

    if (is_query) {
        if (!snipgen->queries) {
            snipgen->queries = new std::vector<std::string>;
        }
        snipgen->queries->push_back(match);
    } else {
        if (!snipgen->loose_terms) {
            snipgen->loose_terms = new std::vector<std::string>;
        }
        snipgen->loose_terms->push_back(match);
    }

    return 0;
}

EXPORTED int xapian_snipgen_begin_doc(xapian_snipgen_t *snipgen,
                             const struct message_guid *guid, char doctype)
{
    struct buf buf = BUF_INITIALIZER;
    make_cyrusid(&buf, guid, doctype);
    snipgen->cyrusid = buf_release(&buf);
    buf_free(&buf);

    buf_reset(snipgen->buf);
    return 0;
}

EXPORTED int xapian_snipgen_make_snippet(xapian_snipgen_t *snipgen,
                                const struct buf *part,
                                Xapian::Stem* stemmer)
{
    int r = 0;
    try {
        std::string text {buf_base(part), buf_len(part)};
        Xapian::Enquire enquire(*snipgen->memdb);
        enquire.set_query(xapian_snipgen_build_query(snipgen, *stemmer));

        unsigned flags = Xapian::MSet::SNIPPET_EXHAUSTIVE |
                         Xapian::MSet::SNIPPET_EMPTY_WITHOUT_MATCH;
#ifdef USE_XAPIAN_CJK_WORDS
        flags |= Xapian::MSet::SNIPPET_CJK_WORDS;
#endif

        const std::string snippet = enquire.get_mset(0, 0).snippet(text,
                snipgen->max_len - buf_len(snipgen->buf),
                *stemmer, flags,
                snipgen->hi_start,
                snipgen->hi_end,
                snipgen->omit);
        if (!snippet.empty()) {
            if (buf_len(snipgen->buf)) {
                buf_appendoverlap(snipgen->buf, snipgen->omit);
            }
            buf_appendcstr(snipgen->buf, snippet.c_str());
        }
    } catch (const Xapian::Error &err) {
        syslog(LOG_ERR, "IOERROR: Xapian: caught exception doc_part: %s: %s",
                err.get_context().c_str(), err.get_description().c_str());
        r = IMAP_IOERROR;
    }
    return r;
}

EXPORTED int xapian_snipgen_doc_part(xapian_snipgen_t *snipgen, const struct buf *part,
		                    int partnum __attribute__((unused)))
{
    // Ignore empty queries.
    if (!snipgen->loose_terms && !snipgen->queries) return 0;

    // Don't exceed allowed snippet length.
    if (buf_len(snipgen->buf) >= snipgen->max_len) return 0;

    return xapian_snipgen_make_snippet(snipgen, part, snipgen->default_stemmer);
}

EXPORTED int xapian_snipgen_end_doc(xapian_snipgen_t *snipgen, struct buf *buf)
{
    buf_reset(buf);
    buf_copy(buf, snipgen->buf);
    buf_cstring(buf);
    buf_reset(snipgen->buf);

    delete snipgen->loose_terms;
    snipgen->loose_terms = NULL;

    delete snipgen->queries;
    snipgen->queries = NULL;

    free(snipgen->cyrusid);
    snipgen->cyrusid = NULL;

    return 0;
}

/* cb returns true if document should be copied, false if not */
EXPORTED int xapian_filter(const char *dest, const char **sources,
                  int (*cb)(const char *cyrusid, void *rock),
                  void *rock)
{
    int r = 0;
    const char *thispath = "(unknown path)";
    std::set<int> db_versions;

    try {
        /* create a destination database */
        Xapian::WritableDatabase destdb {dest, Xapian::DB_CREATE|Xapian::DB_BACKEND_GLASS};

        /* With multiple databases as above, the docids are interleaved, so it
         * might be worth trying to open each source and copy its documents to
         * destdb in turn for better locality of reference, and so better cache
         * use. -- Olly on the mailing list */
        while (*sources) {
            thispath = *sources++;
            const Xapian::Database srcdb {thispath};

            // Aggregate db versions.
            std::set<int> srcdb_versions = get_db_versions(srcdb);
            db_versions.insert(srcdb_versions.begin(), srcdb_versions.end());

            /* copy all matching documents to the new DB */
            for (Xapian::ValueIterator it = srcdb.valuestream_begin(SLOT_CYRUSID);
                                       it != srcdb.valuestream_end(SLOT_CYRUSID); ++it) {
                const char *cyrusid = (*it).c_str();
                if (cb(cyrusid, rock)) {
                    /* is it already indexed? */
                    std::string key {"cyrusid." + *it};
                    if (destdb.get_metadata(key).empty()) {
                        destdb.add_document(srcdb.get_document(it.get_docid()));
                        destdb.set_metadata(key, "1");
                    }
                }
            }
        }

        thispath = "(unknown path)";

        // set the versions to match the source databases
        set_db_versions(destdb, db_versions);

        /* commit all changes explicitly */
        destdb.commit();
    }
    catch (const Xapian::Error &err) {
        syslog(LOG_ERR, "IOERROR: Xapian: caught exception filter: %s (%s)",
               err.get_description().c_str(), thispath);
        r = IMAP_IOERROR;
    }

    return r;
}

EXPORTED const char *xapian_version_string()
{
    return Xapian::version_string();
}

struct xapian_doc {
    Xapian::TermGenerator *termgen;
    Xapian::Document *doc;
};

EXPORTED xapian_doc_t *xapian_doc_new(void)
{
    xapian_doc_t *doc = (xapian_doc_t *) xzmalloc(sizeof(struct xapian_doc));
    doc->doc = new Xapian::Document;
    doc->termgen = new Xapian::TermGenerator;
    doc->termgen->set_document(*doc->doc);
    return doc;
}

EXPORTED void xapian_doc_index_text(xapian_doc_t *doc, const char *text, size_t len)
{
    doc->termgen->index_text(Xapian::Utf8Iterator(text, len));
}

EXPORTED size_t xapian_doc_termcount(xapian_doc_t *doc)
{
    return doc->doc->termlist_count();
}

EXPORTED int xapian_doc_foreach_term(xapian_doc_t *doc, int(*cb)(const char*, void*), void *rock)
{
    for (Xapian::TermIterator ti = doc->doc->termlist_begin();
            ti != doc->doc->termlist_end(); ++ti) {
        int r = cb((*ti).c_str(), rock);
        if (r) return r;
    }
    return 0;
}

EXPORTED void xapian_doc_reset(xapian_doc_t *doc)
{
    doc->doc->clear_values();
}
extern void xapian_doc_close(xapian_doc_t *termgen);

EXPORTED void xapian_doc_close(xapian_doc_t *doc)
{
    delete doc->termgen;
    delete doc->doc;
    free(doc);
}

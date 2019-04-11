
#include <errno.h>
#include <config.h>
#include <string.h>
#include <sys/types.h>
#include <syslog.h>

#include <fstream>
#include <sstream>

extern "C" {
#include <assert.h>
#include "libconfig.h"
#include "util.h"
#include "search_part.h"
#include "xmalloc.h"
#include "xapian_wrap.h"
#include "charset.h"
#include "ptrarray.h"


/* generated headers are not necessarily in current directory */
#include "imap/imap_err.h"
};

#include <xapian.h>

// from global.h
extern int charset_flags;

#define SLOT_CYRUSID        0

/* ====================================================================== */

static const char *make_cyrusid(struct buf *buf, const struct message_guid *guid, char doctype)
{
    buf_reset(buf);
    buf_putc(buf, '*');
    buf_putc(buf, doctype);
    buf_putc(buf, '*');
    buf_appendcstr(buf, message_guid_encode(guid));
    return buf_cstring(buf);
}

/* ====================================================================== */

static Xapian::Stopper *get_stopper()
{
    Xapian::Stopper *stopper = NULL;

    const char *swpath = config_getstring(IMAPOPT_SEARCH_STOPWORD_PATH);
    if (swpath) {
        // Set path to stopword file
        struct buf buf = BUF_INITIALIZER;
        buf_setcstr(&buf, swpath);
        // XXX doesn't play nice with WIN32 paths
        buf_appendcstr(&buf, "/english.list");

        // Open the stopword file
        errno = 0;
        std::ifstream inFile (buf_cstring(&buf));
        if (inFile.fail()) {
            syslog(LOG_ERR, "Xapian: could not open stopword file %s: %s",
                   buf_cstring(&buf), errno ? strerror(errno) : "unknown error");
            exit(1);
        }

        // Create the Xapian stopper
        stopper = new Xapian::SimpleStopper(
                std::istream_iterator<std::string>(inFile),
                std::istream_iterator<std::string>());

        // Clean up
        buf_free(&buf);
    }
    return stopper;
}

/* ====================================================================== */

int xapian_compact_dbs(const char *dest, const char **sources)
{
    int r = 0;
    Xapian::Database db;
    const char *thispath = "(unknown path)";

    try {
        while (*sources) {
            thispath = *sources;
            Xapian::Database subdb(*sources++);
            db.add_database(subdb);
        }
        thispath = "(unknown path)";

        /* FULLER because we never write to compression targets again */
        db.compact(dest, Xapian::Compactor::FULLER | Xapian::DBCOMPACT_MULTIPASS);
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

#define XAPIAN_DB_CURRENT_VERSION 4

static int get_db_version(Xapian::Database *database)
{
    std::string val = database->get_metadata("cyrus.db_version");
    if (val.empty()) {
        // Up to version 3 this was named stem version.
        val = database->get_metadata("cyrus.stem-version");
        if (val.empty()) {
            // Absence of the key indicates version 0
            return 0;
        }
    }
    char *err = NULL;
    long version = strtol(val.c_str(), &err, 10);
    if ((err && *err) || version < 0 || version > INT_MAX) {
        // That's just bogus data
        return -1;
    }
    return version;
}

static void set_db_version(Xapian::WritableDatabase *database, int version)
{
    std::ostringstream convert;
    convert << version;
    database->set_metadata("cyrus.db_version", convert.str());
}

/* For all db paths in sources that are not using the latest database
 * version or not readable, report their paths in toreindex */
void xapian_check_if_needs_reindex(const strarray_t *sources, strarray_t *toreindex)
{
    int i;

    // Check the version of all dbs in sources
    for (i = 0; i < sources->count; i++) {
        const char *thispath = strarray_nth(sources, i);
        try {
            Xapian::Database database = Xapian::Database(thispath);
            int db_version = get_db_version(&database);
            if (db_version != XAPIAN_DB_CURRENT_VERSION) {
                strarray_add(toreindex, thispath);
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
    Xapian::Stopper *stopper;
    ptrarray_t otherdbs;
    int db_version;
    char *cyrusid;
};

int xapian_dbw_open(const char **paths, xapian_dbw_t **dbwp, int mode)
{
    xapian_dbw_t *dbw = (xapian_dbw_t *)xzmalloc(sizeof(xapian_dbw_t));
    int r = 0;
    const char *thispath = "(unknown path)";

    const char *path = *paths++;
    try {
        /* Determine the sterm version of an existing database, or create a
         * new one with the latest one. Never implicitly upgrade. */
        thispath = path;
        try {
            dbw->database = new Xapian::WritableDatabase(path, Xapian::DB_OPEN);
            dbw->db_version = get_db_version(dbw->database);
            if (dbw->db_version < 0) {
                syslog(LOG_ERR, "xapian_wrapper: Invalid database version %d in %s",
                        dbw->db_version, path);
                r = IMAP_IOERROR;
            }
        } catch (Xapian::DatabaseOpeningError &e) {
            /* It's OK not to atomically create or open, since we can assume
             * the xapianactive file items to be locked. */
            dbw->database = new Xapian::WritableDatabase(path, Xapian::DB_CREATE|Xapian::DB_BACKEND_GLASS);
            dbw->db_version = XAPIAN_DB_CURRENT_VERSION;
            set_db_version(dbw->database, dbw->db_version);
        }

        dbw->term_generator = new Xapian::TermGenerator();
        dbw->stemmer = new Xapian::Stem("en");
        dbw->stopper = get_stopper();
        dbw->term_generator->set_stemmer(*dbw->stemmer);
        /* Always enable CJK word tokenization */
#ifdef USE_XAPIAN_CJK_WORDS
        dbw->term_generator->set_flags(Xapian::TermGenerator::FLAG_CJK_WORDS,
                ~Xapian::TermGenerator::FLAG_CJK_WORDS);
#else
        dbw->term_generator->set_flags(Xapian::TermGenerator::FLAG_CJK_NGRAM,
                ~Xapian::TermGenerator::FLAG_CJK_NGRAM);
#endif
        dbw->term_generator->set_stopper(dbw->stopper);
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
                Xapian::Database *database = new Xapian::Database(*paths++);
                ptrarray_append(&dbw->otherdbs, database);
            }
            catch (const Xapian::Error &err) {
                syslog(LOG_ERR, "IOERROR: Xapian: caught exception dbw_open read: %s: %s (%s)",
                            err.get_context().c_str(), err.get_description().c_str(), thispath);
            }
        }
    }

    *dbwp = dbw;

    return r;
}

void xapian_dbw_close(xapian_dbw_t *dbw)
{
    if (!dbw) return;
    try {
        delete dbw->database;
        delete dbw->term_generator;
        delete dbw->stemmer;
        delete dbw->stopper;
        delete dbw->document;
        for (int i = 0; i < dbw->otherdbs.count; i++) {
            Xapian::Database *database = (Xapian::Database *)ptrarray_nth(&dbw->otherdbs, i);
            delete database;
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

int xapian_dbw_is_legacy(const xapian_dbw_t *dbw)
{
    return dbw->db_version < XAPIAN_DB_CURRENT_VERSION;
}

int xapian_dbw_begin_txn(xapian_dbw_t *dbw)
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

int xapian_dbw_commit_txn(xapian_dbw_t *dbw)
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

int xapian_dbw_cancel_txn(xapian_dbw_t *dbw)
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

int xapian_dbw_begin_doc(xapian_dbw_t *dbw, const struct message_guid *guid, char doctype)
{
    int r = 0;

    try {
        if (dbw->document) {
            delete dbw->document;
            dbw->document = 0;
        }
        dbw->document = new Xapian::Document();
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

int xapian_dbw_doc_part(xapian_dbw_t *dbw, const struct buf *part, int num_part)
{
    int r = 0;

    const char *prefix = get_term_prefix(dbw->db_version, num_part);
    if (!prefix) {
        syslog(LOG_ERR, "xapian_wrapper: no prefix for num_part %d", num_part);
        return IMAP_INTERNAL;
    }

    try {
        Xapian::TermGenerator::stem_strategy stem_strategy = get_stem_strategy(dbw->db_version, num_part);
        dbw->term_generator->set_stemming_strategy(stem_strategy);
        dbw->term_generator->index_text(Xapian::Utf8Iterator(part->s, part->len), 1, prefix);
        dbw->term_generator->increase_termpos();
    }
    catch (const Xapian::Error &err) {
        syslog(LOG_ERR, "IOERROR: Xapian: caught exception doc_part: %s: %s",
                    err.get_context().c_str(), err.get_description().c_str());
        r = IMAP_IOERROR;
    }
    return r;
}

int xapian_dbw_end_doc(xapian_dbw_t *dbw)
{
    int r = 0;
    try {
        dbw->database->add_document(*dbw->document);
        dbw->database->set_metadata("cyrusid." + std::string(dbw->cyrusid), "1");
        delete dbw->document;
        dbw->document = 0;
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

int xapian_dbw_is_indexed(xapian_dbw_t *dbw, const struct message_guid *guid, char doctype)
{
    struct buf buf = BUF_INITIALIZER;
    std::string key = "cyrusid." + std::string(make_cyrusid(&buf, guid, doctype));
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
    Xapian::Database *database; // version > 3: supports indexing by doctype
    Xapian::Database *legacydb; // implicitly indexes by doctype 'G'
    Xapian::Stem *stemmer;
    Xapian::QueryParser *parser;
    Xapian::Stopper *stopper;
    std::set<int> *db_versions;
};

int xapian_db_open(const char **paths, xapian_db_t **dbp)
{
    xapian_db_t *db = (xapian_db_t *)xzmalloc(sizeof(xapian_db_t));
    const char *thispath = "(unknown)";
    int r = 0;

    try {
        db->paths = new std::string();
        while (*paths) {
            thispath = *paths++;
            Xapian::Database database = Xapian::Database(thispath);
            int db_version = get_db_version(&database);
            if (db_version < 0) {
                syslog(LOG_ERR, "xapian_wrapper: Invalid db version %d in %s",
                        db_version, thispath);
                r = IMAP_INTERNAL;
                goto done;
            }
            if (!db->db_versions)
                db->db_versions = new std::set<int>();
            db->db_versions->insert(db_version);
            /* XXX This code smell is on purpose. We should throw away
             * legacy dbs before adding new features which require us
             * to juggle any more legacy db versions. */
            if (db_version >= 4) {
                if (!db->database) db->database = new Xapian::Database();
                db->database->add_database(database);
            }
            else {
                if (!db->legacydb) db->legacydb = new Xapian::Database();
                db->legacydb->add_database(database);
            }
            db->paths->append(thispath);
            db->paths->append(" ");
            thispath = "(unknown)";
        }

        if (!db->database && !db->legacydb) {
            r = IMAP_NOTFOUND;
            goto done;
        }

        db->stemmer = new Xapian::Stem("en");
        db->parser = new Xapian::QueryParser;
        db->stopper = get_stopper();
        db->parser->set_stemmer(*db->stemmer);
        db->parser->set_default_op(Xapian::Query::OP_AND);
        db->parser->set_database(db->database ? *db->database : *db->legacydb);
        db->parser->set_stopper(db->stopper);
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

void xapian_db_close(xapian_db_t *db)
{
    try {
        delete db->database;
        delete db->legacydb;
        delete db->stemmer;
        delete db->parser;
        delete db->stopper;
        delete db->paths;
        delete db->db_versions;
        free(db);
    }
    catch (const Xapian::Error &err) {
        /* XXX - memory leak? */
        syslog(LOG_ERR, "IOERROR: Xapian: caught exception db_close: %s: %s",
                    err.get_context().c_str(), err.get_description().c_str());
    }
}

int xapian_db_supports_current_version(const xapian_db_t *db)
{
    return db->database != 0;
}

int xapian_db_supports_legacy_version(const xapian_db_t *db)
{
    return db->legacydb != 0;
}

static xapian_query_t *
xapian_query_new_match_internal(const xapian_db_t *db, int db_version,
                                int num_part, const char *str)
{
    try {
        // We don't use FLAG_BOOLEAN because Cyrus is doing boolean for us
        // TODO: FLAG_AUTO_SYNONYMS
        int has_highbit = 0;
        const unsigned char *p;
        const char *prefix = get_term_prefix(db_version, num_part);

        if (!prefix) {
            // Imitating the legacy prefix handling code, this is not an error
            return NULL;
        }

        for (p = (const unsigned char *)str; *p; p++)
            if (*p > 205) has_highbit = 1;

        if (has_highbit) {
            // anything from greek (codepage from 0380) isn't english parsable
            // so don't try stemming it!
            db->parser->set_stemming_strategy(Xapian::QueryParser::STEM_NONE);
            std::string sstr = std::string("") + str;
            Xapian::Query query = db->parser->parse_query(
                                    sstr,
#ifdef USE_XAPIAN_CJK_WORDS
                                    Xapian::QueryParser::FLAG_CJK_WORDS,
#else
                                    Xapian::QueryParser::FLAG_CJK_NGRAM,
#endif
                                    std::string(prefix));
            return (xapian_query_t *)new Xapian::Query(query);
        }

        // Determine the stem strategy for this prefix and message part
        Xapian::TermGenerator::stem_strategy tg_stem_strategy =
            get_stem_strategy(db_version, num_part);
        Xapian::QueryParser::stem_strategy stem_strategy;
        switch (tg_stem_strategy) {
            case Xapian::TermGenerator::STEM_NONE:
                stem_strategy = Xapian::QueryParser::STEM_NONE;
                break;
            case Xapian::TermGenerator::STEM_ALL:
                stem_strategy = Xapian::QueryParser::STEM_ALL;
                break;
            default:
                stem_strategy = Xapian::QueryParser::STEM_SOME;
        }
        db->parser->set_stemming_strategy(stem_strategy);

        // Prepare the search term
        std::string search;
        switch (stem_strategy) {
            case Xapian::QueryParser::STEM_ALL:
                // quote the query for phrase management. This is for
                // backward compatibility, but shouldn't hurt anyways.
                search = std::string("\"") + str + "\"";
                break;
            case Xapian::QueryParser::STEM_SOME:
                // Cyrus canonical search form is all upper case, but STEM_SOME
                // doesn't work for terms starting with upper case. Best guess
                // is to lower case and risk stemming proper nouns
                search = Xapian::Unicode::tolower(str);
                break;
            default:
                search = std::string(str);
        }

        // Finally, run the query
        Xapian::Query query = db->parser->parse_query(
                search,
                (Xapian::QueryParser::FLAG_PHRASE |
                 Xapian::QueryParser::FLAG_LOVEHATE |
                 Xapian::QueryParser::FLAG_WILDCARD),
                std::string(prefix));
        return (xapian_query_t *)new Xapian::Query(query);
    }
    catch (const Xapian::Error &err) {
        syslog(LOG_ERR, "IOERROR: Xapian: caught exception match_internal: %s: %s",
                    err.get_context().c_str(), err.get_description().c_str());
        return 0;
    }
}

xapian_query_t *
xapian_query_new_match(const xapian_db_t *db, int num_part,const char *str)
{
    std::set<int> *versions = db->db_versions;

    // at least one database must be open
    assert(versions);
    assert(versions->size());

    if (versions->size() == 1) {
        // All database are using the same stemming scheme. Great!
        int version = *(versions->begin());

        if (!get_term_prefix(version, num_part))
            return NULL;

        return (xapian_query_t *)
            xapian_query_new_match_internal(db, version, num_part, str);
    }

    // At least two prefix schemes are used in the open databases. Since db
    // fans out to n databases, let's OR queries for each stem version
    std::vector<Xapian::Query*> v;
    // No 'auto' before C++0x... :(
    for (std::set<int>::iterator it = versions->begin(); it != versions->end(); ++it) {
        if (get_term_prefix(*it, num_part)) {
            v.push_back((Xapian::Query *)
                    xapian_query_new_match_internal(db, *it, num_part, str));
        }
    }
    if (v.empty()) {
        return NULL;
    }

    Xapian::Query *compound =
        new Xapian::Query(Xapian::Query::OP_OR, v.begin(), v.end());

    // 'compound' owns a refcount on each child.  We need to
    // drop the one we got when we allocated the children
    for (std::vector<Xapian::Query*>::iterator it = v.begin(); it != v.end(); ++it) {
        delete *(it);
    }

    return (xapian_query_t *)compound;
}


xapian_query_t *xapian_query_new_compound(const xapian_db_t *db __attribute__((unused)),
                                          int is_or, xapian_query_t **children, int n)
{
    try {
        // I want to use std::initializer_list<Xapian::Query*> here
        // but that requires "experimental" gcc C++0x support :(
        std::vector<Xapian::Query*> v;
        for (int i = 0 ; i < n ; i++)
            v.push_back((Xapian::Query *)children[i]);
        Xapian::Query *compound = new Xapian::Query(
                                    is_or ?  Xapian::Query::OP_OR : Xapian::Query::OP_AND,
                                    v.begin(), v.end());
        // 'compound' owns a refcount on each child.  We need to
        // drop the one we got when we allocated the children
        for (int i = 0 ; i < n ; i++)
            delete (Xapian::Query *)children[i];
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
xapian_query_t *xapian_query_new_not(const xapian_db_t *db __attribute__((unused)),
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

xapian_query_t *xapian_query_new_filter_doctype(const xapian_db_t *db __attribute__((unused)),
                                                char doctype, xapian_query_t *child)
{
    try {
        Xapian::Query *qq = new Xapian::Query(
                                        Xapian::Query::OP_FILTER,
                                        *(Xapian::Query *)child,
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

void xapian_query_free(xapian_query_t *qq)
{
    try {
        Xapian::Query *query = (Xapian::Query *)qq;
        delete query;
    }
    catch (const Xapian::Error &err) {
        syslog(LOG_ERR, "IOERROR: Xapian: caught exception query_free: %s: %s",
                    err.get_context().c_str(), err.get_description().c_str());
    }
}

int bincmp21(const void *a, const void *b)
{
    return memcmp(a, b, 21);
}

int xapian_query_run(const xapian_db_t *db, const xapian_query_t *qq, int is_legacy,
                     int (*cb)(void *data, size_t n, void *rock), void *rock)
{
    const Xapian::Query *query = (const Xapian::Query *)qq;
    void *data = NULL;
    size_t n = 0;

    if ((is_legacy && !db->legacydb) || (!is_legacy && !db->database)) return 0;

    try {
        Xapian::Database *database = is_legacy ? db->legacydb : db->database;
        Xapian::Enquire enquire(*database);
        enquire.set_query(*query);
        Xapian::MSet matches = enquire.get_mset(0, database->get_doccount());
        data = xzmalloc(matches.size() * 21);
        for (Xapian::MSetIterator i = matches.begin() ; i != matches.end() ; ++i) {
            Xapian::Document d = i.get_document();
            std::string cyrusid = d.get_value(SLOT_CYRUSID);

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
            char *entry = (char *) data + (21*n);
            entry[0] = cstr[1];
            hex_to_bin(cstr+3, 40, (uint8_t *)entry + 1);
            n++;
        }
    }
    catch (const Xapian::Error &err) {
        syslog(LOG_ERR, "IOERROR: Xapian: caught exception query_run: %s: %s",
                    err.get_context().c_str(), err.get_description().c_str());
        free(data);
        return IMAP_IOERROR;
    }

    // XXX why sort guids? shouldn't xapian return unique doc ids?
    if (n) qsort(data, n, 21, bincmp21);

    return cb(data, n, rock);
}

struct xapian_snipgen
{
    Xapian::Stem *stemmer;
    Xapian::Database *db;
    std::vector<std::string> *loose_terms;
    std::vector<std::string> *queries;
    struct buf *buf;
    const char *hi_start;
    const char *hi_end;
    const char *omit;
    int partnum;
};

class CharsetStemmer : public Xapian::StemImplementation
{
    charset_t utf8;
    std::map<const std::string, std::string> cache;
    Xapian::Stem stem;

    public:
    CharsetStemmer(Xapian::Stem s) : utf8(charset_lookupname("utf-8")),
                                     stem(s) { }

    virtual ~CharsetStemmer() { charset_free(&utf8); }

    virtual std::string operator() (const std::string &word) {
        char *q;
        std::string res;

        // Is this word already in the cache?
        std::map<const std::string, std::string>::iterator it = cache.find(word);
        if (it != cache.end()) {
            return it->second;
        }

        // Convert the word to search form
        q = charset_convert(word.c_str(), utf8, charset_flags);
        if (!q) {
            return stem(word);
        }

        // Store the normalized word in the cache
        res = stem(Xapian::Unicode::tolower(q));
        cache[word] = res;
        free(q);
        return res;
    }

    virtual std::string get_description () const {
        return "Cyrus search form";
    }
};

xapian_snipgen_t *xapian_snipgen_new(const char *hi_start, const char *hi_end,
                                     const char *omit)
{
    xapian_snipgen_t *snipgen = NULL;
    CharsetStemmer *stem = new CharsetStemmer(Xapian::Stem("en"));

    snipgen = (xapian_snipgen_t *)xzmalloc(sizeof(xapian_snipgen_t));
    snipgen->stemmer = new Xapian::Stem(stem);
    snipgen->db = new Xapian::WritableDatabase(std::string(), Xapian::DB_BACKEND_INMEMORY);
    snipgen->buf = buf_new();
    snipgen->hi_start = hi_start;
    snipgen->hi_end = hi_end;
    snipgen->omit = omit;
    snipgen->partnum = -1;

    return snipgen;
}

void xapian_snipgen_free(xapian_snipgen_t *snipgen)
{
    snipgen->db->close();
    delete snipgen->stemmer;
    delete snipgen->loose_terms;
    delete snipgen->queries;
    delete snipgen->db;
    buf_destroy(snipgen->buf);
    free(snipgen);
}

Xapian::Query xapian_snipgen_build_query(xapian_snipgen_t *snipgen)
{
    std::vector<std::string> terms;
    Xapian::TermGenerator term_generator;
    std::vector<Xapian::Query> v;

    if (snipgen->loose_terms) {
        /* Add loose query terms */
        term_generator.set_stemmer(*snipgen->stemmer);
#ifdef USE_XAPIAN_CJK_WORDS
        term_generator.set_flags(Xapian::TermGenerator::FLAG_CJK_WORDS,
                ~Xapian::TermGenerator::FLAG_CJK_WORDS);
#else
        term_generator.set_flags(Xapian::TermGenerator::FLAG_CJK_NGRAM,
                ~Xapian::TermGenerator::FLAG_CJK_NGRAM);
#endif

        for(size_t i = 0; i < snipgen->loose_terms->size(); ++i)
        {
            std::string match = snipgen->loose_terms->at(i);
            term_generator.index_text(Xapian::Utf8Iterator(match.c_str()));
        }

        const Xapian::Document & doc = term_generator.get_document();
        Xapian::TermIterator it = doc.termlist_begin();
        while (it != doc.termlist_end()) {
            terms.push_back(*it);
            it++;
        }

        for(size_t i = 0; i < terms.size(); ++i)
        {
            v.push_back(Xapian::Query(terms[i]));
        }
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
        queryparser.set_stemmer(*snipgen->stemmer);
        for(size_t i = 0; i < snipgen->queries->size(); ++i) {
            std::string phrase = snipgen->queries->at(i);
            v.push_back(queryparser.parse_query(phrase, flags));
        }
    }

    return Xapian::Query(Xapian::Query::OP_OR, v.begin(), v.end());
}

int xapian_snipgen_add_match(xapian_snipgen_t *snipgen, const char *match)
{
    int r = 0;

    size_t len = strlen(match);
    int is_query = len > 1 && ((match[0] == '"' && match[len-1] == '"') ||
                               (strchr(match, '*') != NULL));

    if (is_query) {
        if (!snipgen->queries) {
            snipgen->queries = new std::vector<std::string>();
        }
        snipgen->queries->push_back(std::string(match));
    } else {
        if (!snipgen->loose_terms) {
            snipgen->loose_terms = new std::vector<std::string>();
        }
        snipgen->loose_terms->push_back(std::string(match));
    }

    return r;
}

int xapian_snipgen_begin_doc(xapian_snipgen_t *snipgen,
                             unsigned int context_length __attribute__((unused)))
{
    buf_reset(snipgen->buf);
    return 0;
}

int xapian_snipgen_doc_part(xapian_snipgen_t *snipgen, const struct buf *part,
		            int partnum)
{
    if (buf_len(snipgen->buf)) {
        // XXX hackish: the original snippet generator passed down
        // boundaries using termpos++. But now it's all text, so encode
        // part gaps using the 'omit' signifier
        buf_appendcstr(snipgen->buf, snipgen->omit);
    }
    buf_append(snipgen->buf, part);
    snipgen->partnum = partnum;
    return 0;
}

int xapian_snipgen_end_doc(xapian_snipgen_t *snipgen, struct buf *buf)
{
    int r = 0;

    if (!snipgen->loose_terms && !snipgen->queries) {
        buf_reset(snipgen->buf);
        buf_reset(buf);
        buf_cstring(buf);
        return 0;
    }

    try {
        std::string snippet;
        std::string text = std::string(buf_base(snipgen->buf), buf_len(snipgen->buf));
        Xapian::Enquire enquire(*snipgen->db);
        enquire.set_query(xapian_snipgen_build_query(snipgen));

        unsigned flags = Xapian::MSet::SNIPPET_EXHAUSTIVE |
                         Xapian::MSet::SNIPPET_EMPTY_WITHOUT_MATCH;

        snippet = enquire.get_mset(0, 0).snippet(text,
                config_getint(IMAPOPT_SEARCH_SNIPPET_LENGTH),
                *snipgen->stemmer,
                flags,
                snipgen->hi_start,
                snipgen->hi_end,
                snipgen->omit
#ifdef USE_XAPIAN_CYRUS_EXTENSIONS
                , Xapian::TermGenerator::FLAG_CJK_WORDS
#endif
        );

        buf_setcstr(buf, snippet.c_str());
        buf_cstring(buf);

        delete snipgen->loose_terms;
        snipgen->loose_terms = NULL;

        delete snipgen->queries;
        snipgen->queries = NULL;

    } catch (const Xapian::Error &err) {
        syslog(LOG_ERR, "IOERROR: Xapian: caught exception end_doc: %s: %s",
                err.get_context().c_str(), err.get_description().c_str());
        r = IMAP_IOERROR;
    }

    buf_reset(snipgen->buf);
    snipgen->partnum = -1;
    return r;
}

/* cb returns true if document should be copied, false if not */
int xapian_filter(const char *dest, const char **sources,
                  int (*cb)(const char *cyrusid, void *rock),
                  void *rock)
{
    int r = 0;
    const char *thispath = "(unknown path)";

    try {
        /* create a destination database */
        Xapian::WritableDatabase destdb = Xapian::WritableDatabase(dest, Xapian::DB_CREATE|Xapian::DB_BACKEND_GLASS);

        /* With multiple databases as above, the docids are interleaved, so it
         * might be worth trying to open each source and copy its documents to
         * destdb in turn for better locality of reference, and so better cache
         * use. -- Olly on the mailing list */
        while (*sources) {
            thispath = *sources;
            Xapian::Database srcdb = Xapian::Database(*sources++);

            /* copy all matching documents to the new DB */
            for (Xapian::ValueIterator it = srcdb.valuestream_begin(SLOT_CYRUSID);
                                       it != srcdb.valuestream_end(SLOT_CYRUSID); it++) {
                if (cb((*it).c_str(), rock)) {
                    destdb.add_document(srcdb.get_document(it.get_docid()));
                }
            }
        }

        thispath = "(unknown path)";

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


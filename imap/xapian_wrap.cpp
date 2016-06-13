
#include <config.h>
#include <sys/types.h>
#include <syslog.h>

extern "C" {
#include "xmalloc.h"
#include "xapian_wrap.h"

/* generated headers are not necessarily in current directory */
#include "imap/imap_err.h"
};

#include <xapian.h>

#define SLOT_CYRUSID        0

/* ====================================================================== */

void xapian_init(void)
{
    /* do nothing */
}

/* ====================================================================== */

int xapian_compact_dbs(const char *dest, const char **sources)
{
    int r = 0;

    try {
        Xapian::Compactor *c = new Xapian::Compactor;

        while (*sources) {
            c->add_source(*sources++);
        }

        c->set_destdir(dest);

        /* we never write to compresion targets again */
        c->set_compaction_level(Xapian::Compactor::FULLER);

        c->set_multipass(true);

        c->compact();
    }
    catch (const Xapian::Error &err) {
        syslog(LOG_ERR, "IOERROR: Xapian: caught exception: %s: %s",
                    err.get_context().c_str(), err.get_description().c_str());
        r = IMAP_IOERROR;
    }

    return r;
}

/* ====================================================================== */

struct xapian_dbw
{
    Xapian::WritableDatabase *database;
    Xapian::Stem *stemmer;
    Xapian::TermGenerator *term_generator;
    Xapian::Document *document;
};

int xapian_dbw_open(const char *path, xapian_dbw_t **dbwp)
{
    xapian_dbw_t *dbw = (xapian_dbw_t *)xzmalloc(sizeof(xapian_dbw_t));
    int r = 0;

    try {
        int action = Xapian::DB_CREATE_OR_OPEN;
        dbw->database = new Xapian::WritableDatabase(path, action);
        dbw->term_generator = new Xapian::TermGenerator();
        dbw->stemmer = new Xapian::Stem("en");
        dbw->term_generator->set_stemmer(*dbw->stemmer);
        dbw->term_generator->set_stemming_strategy(Xapian::TermGenerator::STEM_ALL);
        /* Always enable CJK word tokenization */
        dbw->term_generator->set_flags(Xapian::TermGenerator::FLAG_CJK_NGRAM,
                ~Xapian::TermGenerator::FLAG_CJK_NGRAM);
    }
    catch (const Xapian::DatabaseLockError &err) {
        /* somebody else is already indexing this user.  They may be doing a different
         * mailbox, so we need to re-insert this mailbox into the queue! */
        r = IMAP_MAILBOX_LOCKED;
    }
    catch (const Xapian::Error &err) {
        syslog(LOG_ERR, "IOERROR: Xapian: caught exception: %s: %s",
                    err.get_context().c_str(), err.get_description().c_str());
        r = IMAP_IOERROR;
    }

    if (r)
        xapian_dbw_close(dbw);
    else
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
        delete dbw->document;
        free(dbw);
    }
    catch (const Xapian::Error &err) {
        syslog(LOG_ERR, "IOERROR: Xapian: caught exception: %s: %s",
                    err.get_context().c_str(), err.get_description().c_str());
    }
}


int xapian_dbw_begin_txn(xapian_dbw_t *dbw)
{
    int r = 0;
    try {
        dbw->database->begin_transaction();
    }
    catch (const Xapian::Error &err) {
        syslog(LOG_ERR, "IOERROR: Xapian: caught exception: %s: %s",
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
        syslog(LOG_ERR, "IOERROR: Xapian: caught exception: %s: %s",
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
        syslog(LOG_ERR, "IOERROR: Xapian: caught exception: %s: %s",
                    err.get_context().c_str(), err.get_description().c_str());
        r = IMAP_IOERROR;
    }
    return r;
}

int xapian_dbw_begin_doc(xapian_dbw_t *dbw, const char *cyrusid)
{
    int r = 0;
    try {
        if (dbw->document) {
            delete dbw->document;
            dbw->document = 0;
        }
        dbw->document = new Xapian::Document();
        dbw->document->add_value(SLOT_CYRUSID, cyrusid);
        dbw->term_generator->set_document(*dbw->document);
        dbw->term_generator->set_termpos(1);
    }
    catch (const Xapian::Error &err) {
        syslog(LOG_ERR, "IOERROR: Xapian: caught exception: %s: %s",
                    err.get_context().c_str(), err.get_description().c_str());
        r = IMAP_IOERROR;
    }
    return r;
}

int xapian_dbw_doc_part(xapian_dbw_t *dbw, const struct buf *part, const char *prefix)
{
    int r = 0;
    try {
        dbw->term_generator->index_text(Xapian::Utf8Iterator(part->s, part->len), 1, prefix);
        dbw->term_generator->increase_termpos();
    }
    catch (const Xapian::Error &err) {
        syslog(LOG_ERR, "IOERROR: Xapian: caught exception: %s: %s",
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
        delete dbw->document;
        dbw->document = 0;
    }
    catch (const Xapian::Error &err) {
        syslog(LOG_ERR, "IOERROR: Xapian: caught exception: %s: %s",
                    err.get_context().c_str(), err.get_description().c_str());
        r = IMAP_IOERROR;
    }
    return r;
}

/* ====================================================================== */

struct xapian_db
{
    std::string *paths;
    Xapian::Database *database;
    Xapian::Stem *stemmer;
    Xapian::QueryParser *parser;
};

int xapian_db_open(const char **paths, xapian_db_t **dbp)
{
    xapian_db_t *db = (xapian_db_t *)xzmalloc(sizeof(xapian_db_t));
    const char *thispath = "(unknown)";
    int r = 0;

    try {
        db->paths = new std::string();
        db->database = new Xapian::Database();
        while (*paths) {
            thispath = *paths++;
            db->database->add_database(Xapian::Database(thispath));
            db->paths->append(thispath);
            db->paths->append(" ");
            thispath = "(unknown)";
        }
        db->stemmer = new Xapian::Stem("en");
        db->parser = new Xapian::QueryParser;
        db->parser->set_stemmer(*db->stemmer);
        db->parser->set_default_op(Xapian::Query::OP_AND);
        db->parser->set_database(*db->database);
    }
    catch (const Xapian::Error &err) {
        syslog(LOG_ERR, "IOERROR: Xapian: caught exception: %s: %s",
                    thispath, err.get_description().c_str());
        r = IMAP_IOERROR;
    }

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
        delete db->stemmer;
        delete db->parser;
        delete db->paths;
        free(db);
    }
    catch (const Xapian::Error &err) {
        /* XXX - memory leak? */
        syslog(LOG_ERR, "IOERROR: Xapian: caught exception: %s: %s",
                    err.get_context().c_str(), err.get_description().c_str());
    }
}

xapian_query_t *xapian_query_new_match(const xapian_db_t *db, const char *prefix, const char *str)
{
    try {
        // We don't use FLAG_BOOLEAN because Cyrus is doing boolean for us
        // TODO: FLAG_AUTO_SYNONYMS
        int has_highbit = 0;
        const unsigned char *p;
        for (p = (const unsigned char *)str; *p; p++)
            if (*p > 205) has_highbit = 1;

        if (has_highbit) {
            // anything from greek (codepage from 0380) isn't english parsable
            // so don't try stemming it!
            db->parser->set_stemming_strategy(Xapian::QueryParser::STEM_NONE);
            std::string sstr = std::string("") + str;
            Xapian::Query query = db->parser->parse_query(
                                    sstr,
                                    Xapian::QueryParser::FLAG_CJK_NGRAM,
                                    std::string(prefix));
            return (xapian_query_t *)new Xapian::Query(query);
        }
        else {
            // quote the query for phrase management
            std::string quoted = std::string("\"") + str + "\"";
            db->parser->set_stemming_strategy(Xapian::QueryParser::STEM_ALL);
            Xapian::Query query = db->parser->parse_query(
                                    quoted,
                                    (Xapian::QueryParser::FLAG_PHRASE |
                                     Xapian::QueryParser::FLAG_LOVEHATE |
                                     Xapian::QueryParser::FLAG_WILDCARD),
                                    std::string(prefix));
            return (xapian_query_t *)new Xapian::Query(query);
        }
    }
    catch (const Xapian::Error &err) {
        syslog(LOG_ERR, "IOERROR: Xapian: caught exception: %s: %s",
                    err.get_context().c_str(), err.get_description().c_str());
        return 0;
    }
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
        syslog(LOG_ERR, "IOERROR: Xapian: caught exception: %s: %s",
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
        syslog(LOG_ERR, "IOERROR: Xapian: caught exception: %s: %s",
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
        syslog(LOG_ERR, "IOERROR: Xapian: caught exception: %s: %s",
                    err.get_context().c_str(), err.get_description().c_str());
    }
}

int xapian_query_run(const xapian_db_t *db, const xapian_query_t *qq,
                     int (*cb)(const char *cyrusid, void *rock), void *rock)
{
    const Xapian::Query *query = (const Xapian::Query *)qq;
    int r = 0;

    try {
        Xapian::Enquire enquire(*db->database);
        enquire.set_query(*query);
        Xapian::MSet matches = enquire.get_mset(0, db->database->get_doccount());
        for (Xapian::MSetIterator i = matches.begin() ; i != matches.end() ; ++i) {
            Xapian::Document d = i.get_document();
            std::string cyrusid = d.get_value(SLOT_CYRUSID);
            /* ignore documents with no cyrusid.  Shouldn't happen, but has been seen */
            if (cyrusid.length() == 0) {
                syslog(LOG_ERR, "IOERROR: Xapian: zero length cyrusid for document id %u in index files %s",
                                d.get_docid(), db->paths->c_str());
                continue;
            }
            r = cb(cyrusid.c_str(), rock);
            if (r) break;
        }
    }
    catch (const Xapian::Error &err) {
        syslog(LOG_ERR, "IOERROR: Xapian: caught exception: %s: %s",
                    err.get_context().c_str(), err.get_description().c_str());
        r = IMAP_IOERROR;
    }

    return r;
}

struct xapian_snipgen
{
    Xapian::Stem *stemmer;
    Xapian::SnippetGenerator *snippet_generator;
};

xapian_snipgen_t *xapian_snipgen_new(void)
{
    xapian_snipgen_t *snipgen = NULL;

    try {
        snipgen = (xapian_snipgen_t *)xzmalloc(sizeof(xapian_snipgen_t));

        snipgen->stemmer = new Xapian::Stem("en");
        snipgen->snippet_generator = new Xapian::SnippetGenerator;
        snipgen->snippet_generator->set_stemmer(*snipgen->stemmer);
    }
    catch (const Xapian::Error &err) {
        syslog(LOG_ERR, "IOERROR: Xapian: caught exception: %s: %s",
                    err.get_context().c_str(), err.get_description().c_str());
    }

    return snipgen;
}

void xapian_snipgen_free(xapian_snipgen_t *snipgen)
{
    try {
        delete snipgen->snippet_generator;
        delete snipgen->stemmer;
        free(snipgen);
    }
    catch (const Xapian::Error &err) {
        syslog(LOG_ERR, "IOERROR: Xapian: caught exception: %s: %s",
                    err.get_context().c_str(), err.get_description().c_str());
    }
}

int xapian_snipgen_add_match(xapian_snipgen_t *snipgen, const char *match)
{
    int r = 0;

    try {
        snipgen->snippet_generator->add_match(match);
    }
    catch (const Xapian::Error &err) {
        syslog(LOG_ERR, "IOERROR: Xapian: caught exception: %s: %s",
                    err.get_context().c_str(), err.get_description().c_str());
        r = IMAP_IOERROR;
    }

    return r;
}

int xapian_snipgen_begin_doc(xapian_snipgen_t *snipgen, unsigned int context_length)
{
    int r = 0;

    try {
        snipgen->snippet_generator->reset();
        snipgen->snippet_generator->set_context_length(context_length);
    }
    catch (const Xapian::Error &err) {
        syslog(LOG_ERR, "IOERROR: Xapian: caught exception: %s: %s",
                    err.get_context().c_str(), err.get_description().c_str());
        r = IMAP_IOERROR;
    }

    return r;
}

int xapian_snipgen_doc_part(xapian_snipgen_t *snipgen, const struct buf *part)
{
    int r = 0;

    try {
        snipgen->snippet_generator->accept_text(Xapian::Utf8Iterator(part->s, part->len));
        snipgen->snippet_generator->increase_termpos();
    }
    catch (const Xapian::Error &err) {
        syslog(LOG_ERR, "IOERROR: Xapian: caught exception: %s: %s",
                    err.get_context().c_str(), err.get_description().c_str());
        r = IMAP_IOERROR;
    }

    return r;
}

int xapian_snipgen_end_doc(xapian_snipgen_t *snipgen, struct buf *buf)
{
    int r = 0;

    try {
        buf_reset(buf);
        buf_appendcstr(buf, snipgen->snippet_generator->get_snippets().c_str());
        buf_cstring(buf);
    }
    catch (const Xapian::Error &err) {
        syslog(LOG_ERR, "IOERROR: Xapian: caught exception: %s: %s",
                    err.get_context().c_str(), err.get_description().c_str());
        r = IMAP_IOERROR;
    }

    return r;
}

/* cb returns true if document should be copied, false if not */
int xapian_filter(const char *dest, const char **sources,
                  int (*cb)(const char *cyrusid, void *rock),
                  void *rock)
{
    int r = 0;
    int count = 0;

    try {
        /* create a destination database */
        Xapian::WritableDatabase destdb = Xapian::WritableDatabase(dest, Xapian::DB_CREATE);

        /* With multiple databases as above, the docids are interleaved, so it
         * might be worth trying to open each source and copy its documents to
         * destdb in turn for better locality of reference, and so better cache
         * use. -- Olly on the mailing list */
        while (*sources) {
            Xapian::Database srcdb = Xapian::Database(*sources++);

            /* copy all matching documents to the new DB */
            for (Xapian::ValueIterator it = srcdb.valuestream_begin(SLOT_CYRUSID);
                                       it != srcdb.valuestream_end(SLOT_CYRUSID); it++) {
                if (cb((*it).c_str(), rock)) {
                    destdb.add_document(srcdb.get_document(it.get_docid()));
                }
            }
        }

        /* commit all changes explicitly */
        destdb.commit();
    }
    catch (const Xapian::Error &err) {
        syslog(LOG_ERR, "IOERROR: Xapian: caught exception: %s",
               err.get_description().c_str());
        r = IMAP_IOERROR;
    }

    return r;
}


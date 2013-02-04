
#include <config.h>
#include <sys/types.h>
#include <syslog.h>

extern "C" {
#include "imap_err.h"
#include "xmalloc.h"
#include "xapian_wrap.h"
};

#include <xapian.h>

#define SLOT_CYRUSID	    0

/* ====================================================================== */

void xapian_init(void)
{
    static int init = 0;
    static /* NOT const */ char enable_ngrams[] = "XAPIAN_CJK_NGRAM=1";

    if (!init) {
	putenv(enable_ngrams);
	init = 1;
    }
}

/* ====================================================================== */

struct xapian_dbw
{
    Xapian::WritableDatabase *database;
    Xapian::Stem *stemmer;
    Xapian::TermGenerator *term_generator;
    Xapian::Document *document;
};

xapian_dbw_t *xapian_dbw_open(const char *path, int incremental)
{
    xapian_dbw_t *dbw = 0;
    try {
	dbw = (xapian_dbw_t *)xzmalloc(sizeof(xapian_dbw_t));
	int action = (incremental ? Xapian::DB_CREATE_OR_OPEN : Xapian::DB_CREATE_OR_OVERWRITE);
	dbw->database = new Xapian::WritableDatabase(path, action);
	dbw->term_generator = new Xapian::TermGenerator();
	dbw->stemmer = new Xapian::Stem("en");
	dbw->term_generator->set_stemmer(*dbw->stemmer);
	dbw->term_generator->set_stemming_strategy(Xapian::TermGenerator::STEM_ALL);
    }
    catch (const Xapian::Error &err) {
	syslog(LOG_ERR, "IOERROR: Xapian: caught exception: %s: %s",
		    err.get_context().c_str(), err.get_description().c_str());
	free(dbw);
	dbw = 0;
    }
    return dbw;
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
    Xapian::Database *database;
    Xapian::Stem *stemmer;
    Xapian::QueryParser *parser;
};

// there is no struct xapian_query, we just typedef
// to it in order to hide Xapian::Query

xapian_db_t *xapian_db_open(const char *path)
{
    xapian_db_t *db = NULL;
    try {
	db = (xapian_db_t *)xzmalloc(sizeof(xapian_db_t));
	db->database = new Xapian::Database(path);
	db->stemmer = new Xapian::Stem("en");
	db->parser = new Xapian::QueryParser;
	db->parser->set_stemming_strategy(Xapian::QueryParser::STEM_ALL);
	db->parser->set_stemmer(*db->stemmer);
	db->parser->set_default_op(Xapian::Query::OP_AND);
	db->parser->set_database(*db->database);
    }
    catch (const Xapian::Error &err) {
	syslog(LOG_ERR, "IOERROR: Xapian: caught exception: %s: %s",
		    path, err.get_description().c_str());
	db = NULL;
    }
    return db;
}

void xapian_db_close(xapian_db_t *db)
{
    try {
	delete db->database;
	delete db->stemmer;
	delete db->parser;
	free(db);
    }
    catch (const Xapian::Error &err) {
	syslog(LOG_ERR, "IOERROR: Xapian: caught exception: %s: %s",
		    err.get_context().c_str(), err.get_description().c_str());
    }
}

xapian_query_t *xapian_query_new_match(const xapian_db_t *db, const char *prefix, const char *str)
{
    try {
	// We don't use FLAG_BOOLEAN because Cyrus is doing boolean for us
	// TODO: FLAG_AUTO_SYNONYMS
	Xapian::Query query = db->parser->parse_query(
				    std::string(str),
				    (Xapian::QueryParser::FLAG_PHRASE |
				     Xapian::QueryParser::FLAG_LOVEHATE |
				     Xapian::QueryParser::FLAG_WILDCARD),
				    std::string(prefix));
	return (xapian_query_t *)new Xapian::Query(query);
    }
    catch (const Xapian::Error &err) {
	syslog(LOG_ERR, "IOERROR: Xapian: caught exception: %s: %s",
		    err.get_context().c_str(), err.get_description().c_str());
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
	return (xapian_query_t *)new Xapian::Query(
					Xapian::Query::OP_AND_NOT,
					Xapian::Query::MatchAll,
					*(Xapian::Query *)child);
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
	    std::string cyrusid = i.get_document().get_value(SLOT_CYRUSID);
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



#include <config.h>
#include <sys/types.h>
#include <syslog.h>

extern "C" {
#include "imap_err.h"
#include "xmalloc.h"
#include "xapian_wrap.h"
};

#include <xapian.h>

struct xapian_dbw
{
    Xapian::WritableDatabase *database;
    Xapian::Stem *stemmer;
    Xapian::TermGenerator *term_generator;
    Xapian::Document *document;
};

xapian_dbw_t *xapian_dbw_open(const char *path)
{
    xapian_dbw_t *dbw = 0;
    try {
	dbw = (xapian_dbw_t *)xzmalloc(sizeof(xapian_dbw_t));
	dbw->database = new Xapian::WritableDatabase(path, Xapian::DB_CREATE_OR_OPEN);
	dbw->term_generator = new Xapian::TermGenerator();
	dbw->stemmer = new Xapian::Stem("en");
	dbw->term_generator->set_stemmer(*dbw->stemmer);
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
	dbw->document->add_value(0, cyrusid);
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

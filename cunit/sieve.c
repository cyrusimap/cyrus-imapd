/* Unit test for sieve */
/* Heavily based on the old sieve/test.c which bore this message:
 *
 * - * test.c -- tester for libsieve
 * - * Larry Greenfield
 *
 */
#include "cunit/cunit.h"
#include <malloc.h>
#include "sieve_interface.h"
#include "bytecode.h"
#include "prot.h"
#include "retry.h"
#include "comparator.h"
#include "spool.h"
#include "map.h"
#include "message.h"
#include "xstrlcat.h"
#include "xstrlcpy.h"

typedef struct {
    sieve_interp_t *interp;
    sieve_execute_t *exe;
    struct {
	unsigned int actions;
	unsigned int errors;
	unsigned int redirects;
	unsigned int discards;
	unsigned int rejects;
	unsigned int fileintos;
	unsigned int keeps;
	unsigned int notifies;
	unsigned int vaction_responses;
    } stats;
    char *redirected_to;
    char *reject_message;
    char *filed_mailbox;
    char *filed_flags;
    char *notify_method;
    char *notify_priority;
    char *notify_options;
    char *vacation_message;
    char *vacation_subject;
    char *vacation_to;
    char *vacation_from;
    strarray_t *compile_errors;
    strarray_t *run_errors;
} sieve_test_context_t;

typedef struct {
    const char *text;
    int length;
    struct message_content content;
    hdrcache_t headers;
    char *filename;
} sieve_test_message_t;


extern int verbose;

#define TESTCASE(_comp, _mode, _pat, _text, _result)		\
    comprock = NULL;						\
    c = lookup_comp(_comp, _mode, -1, &comprock);		\
    CU_ASSERT_PTR_NOT_NULL(c);					\
    if (c) {							\
	res = c(_text, strlen(_text), _pat, comprock);		\
	CU_ASSERT_EQUAL(res, _result);				\
    }

static void test_comparator(void)
{
    void *comprock;
    comparator_t *c;
    int res;

    TESTCASE( B_OCTET, B_IS, "", "", 1 );
    TESTCASE( B_OCTET, B_IS, "a", "", 0 );
    TESTCASE( B_OCTET, B_IS, "", "a", 0 );
    TESTCASE( B_OCTET, B_IS, "a", "a", 1 );
    TESTCASE( B_OCTET, B_IS, "a", "A", 0 );

    TESTCASE( B_ASCIICASEMAP, B_IS, "", "", 1 );
    TESTCASE( B_ASCIICASEMAP, B_IS, "a", "", 0 );
    TESTCASE( B_ASCIICASEMAP, B_IS, "", "a", 0 );
    TESTCASE( B_ASCIICASEMAP, B_IS, "a", "a", 1 );
    TESTCASE( B_ASCIICASEMAP, B_IS, "a", "A", 1 );

    TESTCASE( B_ASCIINUMERIC, B_IS, "123", "123", 1 );
    TESTCASE( B_ASCIINUMERIC, B_IS, "123", "-123", 0 );
    TESTCASE( B_ASCIINUMERIC, B_IS, "abc", "123", 0 );
    TESTCASE( B_ASCIINUMERIC, B_IS, "abc", "abc", 1 );
    TESTCASE( B_ASCIINUMERIC, B_IS, "12345678900", "3755744308", 0 );    /* test for 32bit overflow */
    TESTCASE( B_ASCIINUMERIC, B_IS, "1567", "1567pounds", 1 );
    TESTCASE( B_ASCIINUMERIC, B_IS, "", "", 1 );
    TESTCASE( B_ASCIINUMERIC, B_IS, "123456789", "567", 0 );
    TESTCASE( B_ASCIINUMERIC, B_IS, "567", "123456789", 0 );
    TESTCASE( B_ASCIINUMERIC, B_IS, "123456789", "00000123456789", 1 );
    TESTCASE( B_ASCIINUMERIC, B_IS, "102", "1024", 0 );
    TESTCASE( B_ASCIINUMERIC, B_IS, "1567M", "1567 arg", 1 );

    TESTCASE( B_OCTET, B_CONTAINS, "", "", 1 );
    TESTCASE( B_OCTET, B_CONTAINS, "", "a", 1 );
    TESTCASE( B_OCTET, B_CONTAINS, "a", "", 0 );
    TESTCASE( B_OCTET, B_CONTAINS, "a", "a", 1 );
    TESTCASE( B_OCTET, B_CONTAINS, "a", "ab", 1 );
    TESTCASE( B_OCTET, B_CONTAINS, "a", "ba", 1 );
    TESTCASE( B_OCTET, B_CONTAINS, "a", "aba", 1 );
    TESTCASE( B_OCTET, B_CONTAINS, "a", "bab", 1 );
    TESTCASE( B_OCTET, B_CONTAINS, "a", "bb", 0 );
    TESTCASE( B_OCTET, B_CONTAINS, "a", "bbb", 0 );

    TESTCASE( B_OCTET, B_MATCHES, "", "", 1 );
    TESTCASE( B_OCTET, B_MATCHES, "", "a", 0 );
    TESTCASE( B_OCTET, B_MATCHES, "a", "", 0 );
    TESTCASE( B_OCTET, B_MATCHES, "a", "a", 1 );
    TESTCASE( B_OCTET, B_MATCHES, "a", "ab", 0 );
    TESTCASE( B_OCTET, B_MATCHES, "a", "ba", 0 );
    TESTCASE( B_OCTET, B_MATCHES, "a", "aba", 0 );
    TESTCASE( B_OCTET, B_MATCHES, "a", "bab", 0 );
    TESTCASE( B_OCTET, B_MATCHES, "a", "bb", 0 );
    TESTCASE( B_OCTET, B_MATCHES, "a", "bbb", 0 );

    TESTCASE( B_OCTET, B_MATCHES, "*", "", 1 );
    TESTCASE( B_OCTET, B_MATCHES, "*", "a", 1 );
    TESTCASE( B_OCTET, B_MATCHES, "*a*", "", 0 );
    TESTCASE( B_OCTET, B_MATCHES, "*a*", "a", 1 );
    TESTCASE( B_OCTET, B_MATCHES, "*a*", "ab", 1 );
    TESTCASE( B_OCTET, B_MATCHES, "*a*", "ba", 1 );
    TESTCASE( B_OCTET, B_MATCHES, "*a*", "aba", 1 );
    TESTCASE( B_OCTET, B_MATCHES, "*a*", "bab", 1 );
    TESTCASE( B_OCTET, B_MATCHES, "*a*", "bb", 0 );
    TESTCASE( B_OCTET, B_MATCHES, "*a*", "bbb", 0 );

    TESTCASE( B_OCTET, B_MATCHES, "*a", "", 0 );
    TESTCASE( B_OCTET, B_MATCHES, "*a", "a", 1 );
    TESTCASE( B_OCTET, B_MATCHES, "*a", "ab", 0 );
    TESTCASE( B_OCTET, B_MATCHES, "*a", "ba", 1 );
    TESTCASE( B_OCTET, B_MATCHES, "*a", "aba", 1 );
    TESTCASE( B_OCTET, B_MATCHES, "*a", "bab", 0 );
    TESTCASE( B_OCTET, B_MATCHES, "*a", "bb", 0 );
    TESTCASE( B_OCTET, B_MATCHES, "*a", "bbb", 0 );

    TESTCASE( B_OCTET, B_MATCHES, "a*", "", 0 );
    TESTCASE( B_OCTET, B_MATCHES, "a*", "a", 1 );
    TESTCASE( B_OCTET, B_MATCHES, "a*", "ab", 1 );
    TESTCASE( B_OCTET, B_MATCHES, "a*", "ba", 0 );
    TESTCASE( B_OCTET, B_MATCHES, "a*", "aba", 1 );
    TESTCASE( B_OCTET, B_MATCHES, "a*", "bab", 0 );
    TESTCASE( B_OCTET, B_MATCHES, "a*", "bb", 0 );
    TESTCASE( B_OCTET, B_MATCHES, "a*", "bbb", 0 );

    TESTCASE( B_OCTET, B_MATCHES, "a*b", "", 0 );
    TESTCASE( B_OCTET, B_MATCHES, "a*b", "a", 0 );
    TESTCASE( B_OCTET, B_MATCHES, "a*b", "ab", 1 );
    TESTCASE( B_OCTET, B_MATCHES, "a*b", "ba", 0 );
    TESTCASE( B_OCTET, B_MATCHES, "a*b", "aba", 0 );
    TESTCASE( B_OCTET, B_MATCHES, "a*b", "bab", 0 );
    TESTCASE( B_OCTET, B_MATCHES, "a*b", "bb", 0 );
    TESTCASE( B_OCTET, B_MATCHES, "a*b", "bbb", 0 );
    TESTCASE( B_OCTET, B_MATCHES, "a*b", "abbb", 1 );
    TESTCASE( B_OCTET, B_MATCHES, "a*b", "acb", 1 );
    TESTCASE( B_OCTET, B_MATCHES, "a*b", "acbc", 0 );

    TESTCASE( B_OCTET, B_MATCHES, "a?b", "", 0 );
    TESTCASE( B_OCTET, B_MATCHES, "a?b", "a", 0 );
    TESTCASE( B_OCTET, B_MATCHES, "a?b", "ab", 0 );
    TESTCASE( B_OCTET, B_MATCHES, "a?b", "ba", 0 );
    TESTCASE( B_OCTET, B_MATCHES, "a?b", "aba", 0 );
    TESTCASE( B_OCTET, B_MATCHES, "a?b", "bab", 0 );
    TESTCASE( B_OCTET, B_MATCHES, "a?b", "bb", 0 );
    TESTCASE( B_OCTET, B_MATCHES, "a?b", "bbb", 0 );
    TESTCASE( B_OCTET, B_MATCHES, "a?b", "abbb", 0 );
    TESTCASE( B_OCTET, B_MATCHES, "a?b", "acb", 1 );
    TESTCASE( B_OCTET, B_MATCHES, "a?b", "acbc", 0 );

    TESTCASE( B_OCTET, B_MATCHES, "a*?b", "", 0 );
    TESTCASE( B_OCTET, B_MATCHES, "a*?b", "a", 0 );
    TESTCASE( B_OCTET, B_MATCHES, "a*?b", "ab", 0 );
    TESTCASE( B_OCTET, B_MATCHES, "a*?b", "ba", 0 );
    TESTCASE( B_OCTET, B_MATCHES, "a*?b", "aba", 0 );
    TESTCASE( B_OCTET, B_MATCHES, "a*?b", "bab", 0 );
    TESTCASE( B_OCTET, B_MATCHES, "a*?b", "bb", 0 );
    TESTCASE( B_OCTET, B_MATCHES, "a*?b", "bbb", 0 );
    TESTCASE( B_OCTET, B_MATCHES, "a*?b", "abbb", 1 );
    TESTCASE( B_OCTET, B_MATCHES, "a*?b", "acb", 1 );
    TESTCASE( B_OCTET, B_MATCHES, "a*?b", "acbc", 0 );

    TESTCASE( B_OCTET, B_MATCHES, "a?*b", "", 0 );
    TESTCASE( B_OCTET, B_MATCHES, "a?*b", "a", 0 );
    TESTCASE( B_OCTET, B_MATCHES, "a?*b", "ab", 0 );
    TESTCASE( B_OCTET, B_MATCHES, "a?*b", "ba", 0 );
    TESTCASE( B_OCTET, B_MATCHES, "a?*b", "aba", 0 );
    TESTCASE( B_OCTET, B_MATCHES, "a?*b", "bab", 0 );
    TESTCASE( B_OCTET, B_MATCHES, "a?*b", "bb", 0 );
    TESTCASE( B_OCTET, B_MATCHES, "a?*b", "bbb", 0 );
    TESTCASE( B_OCTET, B_MATCHES, "a?*b", "abbb", 1 );
    TESTCASE( B_OCTET, B_MATCHES, "a?*b", "acb", 1 );
    TESTCASE( B_OCTET, B_MATCHES, "a?*b", "acbc", 0 );

    TESTCASE( B_OCTET, B_MATCHES, "a*?*b", "", 0 );
    TESTCASE( B_OCTET, B_MATCHES, "a*?*b", "a", 0 );
    TESTCASE( B_OCTET, B_MATCHES, "a*?*b", "ab", 0 );
    TESTCASE( B_OCTET, B_MATCHES, "a*?*b", "ba", 0 );
    TESTCASE( B_OCTET, B_MATCHES, "a*?*b", "aba", 0 );
    TESTCASE( B_OCTET, B_MATCHES, "a*?*b", "bab", 0 );
    TESTCASE( B_OCTET, B_MATCHES, "a*?*b", "bb", 0 );
    TESTCASE( B_OCTET, B_MATCHES, "a*?*b", "bbb", 0 );
    TESTCASE( B_OCTET, B_MATCHES, "a*?*b", "abbb", 1 );
    TESTCASE( B_OCTET, B_MATCHES, "a*?*b", "acb", 1 );
    TESTCASE( B_OCTET, B_MATCHES, "a*?*b?", "acbc", 1 );

    TESTCASE( B_ASCIICASEMAP, B_MATCHES, "a*b", "", 0 );
    TESTCASE( B_ASCIICASEMAP, B_MATCHES, "a*b", "a", 0 );
    TESTCASE( B_ASCIICASEMAP, B_MATCHES, "a*b", "ab", 1 );
    TESTCASE( B_ASCIICASEMAP, B_MATCHES, "a*b", "ba", 0 );
    TESTCASE( B_ASCIICASEMAP, B_MATCHES, "a*b", "aba", 0 );
    TESTCASE( B_ASCIICASEMAP, B_MATCHES, "a*b", "bab", 0 );
    TESTCASE( B_ASCIICASEMAP, B_MATCHES, "a*b", "bb", 0 );
    TESTCASE( B_ASCIICASEMAP, B_MATCHES, "a*b", "bbb", 0 );
    TESTCASE( B_ASCIICASEMAP, B_MATCHES, "a*b", "abbb", 1 );
    TESTCASE( B_ASCIICASEMAP, B_MATCHES, "a*b", "acb", 1 );
    TESTCASE( B_ASCIICASEMAP, B_MATCHES, "a*b", "acbc", 0 );

    TESTCASE( B_ASCIICASEMAP, B_MATCHES, "a*b", "", 0 );
    TESTCASE( B_ASCIICASEMAP, B_MATCHES, "a*b", "A", 0 );
    TESTCASE( B_ASCIICASEMAP, B_MATCHES, "a*b", "Ab", 1 );
    TESTCASE( B_ASCIICASEMAP, B_MATCHES, "a*b", "BA", 0 );
    TESTCASE( B_ASCIICASEMAP, B_MATCHES, "a*b", "ABA", 0 );
    TESTCASE( B_ASCIICASEMAP, B_MATCHES, "a*b", "BAb", 0 );
    TESTCASE( B_ASCIICASEMAP, B_MATCHES, "a*b", "BB", 0 );
    TESTCASE( B_ASCIICASEMAP, B_MATCHES, "a*b", "BBB", 0 );
    TESTCASE( B_ASCIICASEMAP, B_MATCHES, "a*b", "aBBB", 1 );
    TESTCASE( B_ASCIICASEMAP, B_MATCHES, "a*b", "ACB", 1 );
    TESTCASE( B_ASCIICASEMAP, B_MATCHES, "a*b", "ACBC", 0 );
}


/* gets the header "head" from msg. */
static int getheader(void *mc, const char *name, const char ***body)
{
    sieve_test_message_t *msg = (sieve_test_message_t *)mc;

    *body = spool_getheader(msg->headers, name);
    if (!*body)
	return SIEVE_FAIL;
    return SIEVE_OK;
}

static int getsize(void *mc, int *size)
{
    sieve_test_message_t *msg = (sieve_test_message_t *)mc;

    *size = msg->length;
    return SIEVE_OK;
}

static int getbody(void *mc, const char **content_types, sieve_bodypart_t ***parts)
{
    sieve_test_message_t *msg = (sieve_test_message_t *)mc;
    int r = 0;

    if (!msg->content.body) {
	/* parse the message body if we haven't already */
	FILE *fp = fopen(msg->filename, "r");
	CU_ASSERT_PTR_NOT_NULL(fp);
	r = message_parse_file(fp,
			       &msg->content.base,
			       &msg->content.len,
			       &msg->content.body);
	CU_ASSERT_EQUAL(r, 0);
	fclose(fp);
    }

    /* XXX currently struct bodypart as defined in message.h is the same as
       sieve_bodypart_t as defined in sieve_interface.h, so we can typecast */
    if (!r)
	message_fetch_part(&msg->content, content_types,
			   (struct bodypart ***) parts);

    if (r)
	return SIEVE_FAIL;
    return SIEVE_OK;
}

static int getinclude(void *sc __attribute__((unused)),
		      const char *script,
		      int isglobal __attribute__((unused)),
		      char *fpath, size_t size)
{
    strlcpy(fpath, script, size);
    strlcat(fpath, ".bc", size);
    return SIEVE_OK;
}

static int redirect(void *ac, void *ic, void *sc __attribute__((unused)),
		    void *mc __attribute__((unused)),
		    const char **errmsg __attribute__((unused)))
{
    sieve_redirect_context_t *rc = (sieve_redirect_context_t *)ac;
    sieve_test_context_t *ctx = (sieve_test_context_t *)ic;

    ctx->stats.actions++;
    ctx->stats.redirects++;
    free(ctx->redirected_to);
    ctx->redirected_to = xstrdup(rc->addr);

    /* TODO: test returning SIEVE_FAIL */
    return SIEVE_OK;
}

static int discard(void *ac __attribute__((unused)),
		   void *ic, void *sc __attribute__((unused)),
		   void *mc __attribute__((unused)),
		   const char **errmsg __attribute__((unused)))
{
    sieve_test_context_t *ctx = (sieve_test_context_t *)ic;

    ctx->stats.actions++;
    ctx->stats.discards++;

    /* TODO: test returning SIEVE_FAIL */
    return SIEVE_OK;
}

static int reject(void *ac, void *ic, void *sc __attribute__((unused)),
	          void *mc __attribute__((unused)),
		  const char **errmsg __attribute__((unused)))
{
    sieve_reject_context_t *rc = (sieve_reject_context_t *)ac;
    sieve_test_context_t *ctx = (sieve_test_context_t *)ic;

    ctx->stats.actions++;
    ctx->stats.rejects++;
    free(ctx->reject_message);
    ctx->reject_message = xstrdup(rc->msg);

    /* TODO: test returning SIEVE_FAIL */
    return SIEVE_OK;
}

static int fileinto(void *ac, void *ic, void *sc __attribute__((unused)),
		    void *mc __attribute__((unused)),
		    const char **errmsg __attribute__((unused)))
{
    sieve_fileinto_context_t *fc = (sieve_fileinto_context_t *)ac;
    sieve_test_context_t *ctx = (sieve_test_context_t *)ic;

    ctx->stats.actions++;
    ctx->stats.fileintos++;
    free(ctx->filed_mailbox);
    ctx->filed_mailbox = xstrdup(fc->mailbox);
    free(ctx->filed_flags);
    ctx->filed_flags = strarray_join(fc->imapflags, " ");

    /* TODO: test returning SIEVE_FAIL */
    return SIEVE_OK;
}

static int keep(void *ac, void *ic, void *sc __attribute__((unused)),
	        void *mc __attribute__((unused)),
		const char **errmsg __attribute__((unused)))
{
    sieve_keep_context_t *kc = (sieve_keep_context_t *)ac;
    sieve_test_context_t *ctx = (sieve_test_context_t *)ic;

    ctx->stats.actions++;
    ctx->stats.keeps++;
    free(ctx->filed_flags);
    ctx->filed_flags = strarray_join(kc->imapflags, " ");

    /* TODO: test returning SIEVE_FAIL */
    return SIEVE_OK;
}

static int notify(void *ac, void *ic, void *sc __attribute__((unused)),
	          void *mc __attribute__((unused)),
	          const char **errmsg __attribute__((unused)))
{
    sieve_notify_context_t *nc = (sieve_notify_context_t *)ac;
    sieve_test_context_t *ctx = (sieve_test_context_t *)ic;
    struct buf opts = BUF_INITIALIZER;
    const char **p;

    for (p = nc->options ; *p ; p++) {
	if (opts.len)
	    buf_putc(&opts, ' ');
	buf_appendcstr(&opts, *p);
    }

    ctx->stats.actions++;
    ctx->stats.notifies++;
    free(ctx->notify_options);
    ctx->notify_options = buf_release(&opts);
    free(ctx->notify_method);
    ctx->notify_method = xstrdup(nc->method);
    free(ctx->notify_priority);
    ctx->notify_method = xstrdup(nc->priority);

    /* TODO: test returning SIEVE_FAIL */
    return SIEVE_OK;
}

static int mysieve_error(int lineno, const char *msg,
			 void *ic __attribute__((unused)),
		         void *sc __attribute__((unused)))
{
    sieve_test_context_t *ctx = (sieve_test_context_t *)ic;
    struct buf buf = BUF_INITIALIZER;

    ctx->stats.errors++;
    buf_printf(&buf, "line %d: %s", lineno, msg);
    strarray_appendm(ctx->compile_errors, buf_release(&buf));

    return SIEVE_OK;
}

static int mysieve_execute_error(const char *msg,
				 void *ic __attribute__((unused)),
			         void *sc __attribute__((unused)),
			         void *mc __attribute__((unused)))
{
    sieve_test_context_t *ctx = (sieve_test_context_t *)ic;

    ctx->stats.errors++;
    strarray_append(ctx->run_errors, msg);

    return SIEVE_OK;
}

static int autorespond(void *ac, void *ic,
		       void *sc __attribute__((unused)),
		       void *mc __attribute__((unused)),
		       const char **errmsg __attribute__((unused)))
{
//     sieve_autorespond_context_t *arc = (sieve_autorespond_context_t *)ac;
//     sieve_test_context_t *ctx = (sieve_test_context_t *)ic;
//     char yn;
//     int i;
// 
//     printf("Have I already responded to '");
//     for (i = 0; i < SIEVE_HASHLEN; i++) {
// 	printf("%x", arc->hash[i]);
//     }
//     printf("' in %d days? ", arc->days);
//     scanf(" %c", &yn);
// 
//     if (TOLOWER(yn) == 'y') return SIEVE_DONE;
//     if (TOLOWER(yn) == 'n') return SIEVE_OK;

    return SIEVE_FAIL;
}

static int send_response(void *ac, void *ic, void *sc __attribute__((unused)),
			 void *mc __attribute__((unused)),
			 const char **errmsg __attribute__((unused)))
{
    sieve_send_response_context_t *src = (sieve_send_response_context_t *)ac;
    sieve_test_context_t *ctx = (sieve_test_context_t *)ic;

    ctx->stats.actions++;
    ctx->stats.vaction_responses++;
    free(ctx->vacation_message);
    ctx->vacation_message = xstrdup(src->msg);
    free(ctx->vacation_subject);
    ctx->vacation_subject = xstrdup(src->subj);
    free(ctx->vacation_to);
    ctx->vacation_to = xstrdup(src->addr);
    free(ctx->vacation_from);
    ctx->vacation_from = xstrdup(src->fromaddr);

    /* TODO: test returning SIEVE_FAIL */
    return SIEVE_OK;
}

#ifndef HAVE_FMEMOPEN
static FILE *fmemopen(const void *buf, size_t len, const char *mode)
{
    FILE *fp;

    fp = fopen("/dev/null", mode);
    if (!fp)
	return NULL;
    setbuffer(fp, buf, len);
    return fp;
}
#endif

static void context_setup(sieve_test_context_t *ctx,
			  const char *script)
{
    int r;
    static strarray_t mark = STRARRAY_INITIALIZER;
    static sieve_vacation_t vacation = {
	0,			/* min response */
	0,			/* max response */
	&autorespond,		/* autorespond() */
	&send_response		/* send_response() */
    };
    int len = strlen(script);
    int fd;
    FILE *fp;
    sieve_script_t *scr = NULL;
    bytecode_info_t *bytecode = NULL;
    char tempfile[32];

    memset(ctx, 0, sizeof(*ctx));
    if (!mark.count)
	strarray_append(&mark, "\\flagged");

    ctx->compile_errors = strarray_new();
    ctx->run_errors = strarray_new();

    r = sieve_interp_alloc(&ctx->interp, ctx);
    CU_ASSERT_EQUAL(r, SIEVE_OK);
    r = sieve_register_redirect(ctx->interp, redirect);
    CU_ASSERT_EQUAL(r, SIEVE_OK);
    r = sieve_register_discard(ctx->interp, discard);
    CU_ASSERT_EQUAL(r, SIEVE_OK);
    r = sieve_register_reject(ctx->interp, reject);
    CU_ASSERT_EQUAL(r, SIEVE_OK);
    r = sieve_register_fileinto(ctx->interp, fileinto);
    CU_ASSERT_EQUAL(r, SIEVE_OK);
    r = sieve_register_keep(ctx->interp, keep);
    CU_ASSERT_EQUAL(r, SIEVE_OK);
    r = sieve_register_size(ctx->interp, getsize);
    CU_ASSERT_EQUAL(r, SIEVE_OK);
    r = sieve_register_header(ctx->interp, getheader);
    CU_ASSERT_EQUAL(r, SIEVE_OK);
    r = sieve_register_envelope(ctx->interp, getheader);
    CU_ASSERT_EQUAL(r, SIEVE_OK);
    r = sieve_register_body(ctx->interp, getbody);
    CU_ASSERT_EQUAL(r, SIEVE_OK);
    r = sieve_register_include(ctx->interp, getinclude);
    CU_ASSERT_EQUAL(r, SIEVE_OK);
    r = sieve_register_vacation(ctx->interp, &vacation);
    CU_ASSERT_EQUAL(r, SIEVE_OK);
    r = sieve_register_imapflags(ctx->interp, &mark);
    CU_ASSERT_EQUAL(r, SIEVE_OK);
    r = sieve_register_notify(ctx->interp, notify);
    CU_ASSERT_EQUAL(r, SIEVE_OK);
    r = sieve_register_parse_error(ctx->interp, mysieve_error);
    CU_ASSERT_EQUAL(r, SIEVE_OK);
    r = sieve_register_execute_error(ctx->interp, mysieve_execute_error);
    CU_ASSERT_EQUAL(r, SIEVE_OK);

    /* Here we pretend to be the sieve compiler, and generate
     * a file of compiled bytecode from the script string */
    fp = fmemopen((void *)script, len, "r");
    r = sieve_script_parse(ctx->interp, fp, ctx, &scr);
    CU_ASSERT_EQUAL(r, SIEVE_OK);
    fclose(fp);

    r = sieve_generate_bytecode(&bytecode, scr);
    CU_ASSERT(r > 0);
    strcpy(tempfile, "/tmp/sievetest-BC-XXXXXX");
    fd = mkstemp(tempfile);
    CU_ASSERT(fd >= 0);
    r = sieve_emit_bytecode(fd, bytecode);
    CU_ASSERT(r > 0);
    sieve_free_bytecode(&bytecode);
    sieve_script_free(&scr);

    /* Now load the compiled bytecode */
    r = sieve_script_load(tempfile, &ctx->exe);
    CU_ASSERT_EQUAL(r, SIEVE_OK);
    unlink(tempfile);
}

static void context_cleanup(sieve_test_context_t *ctx)
{
    int r;

    if (verbose > 1) {
	int i;

	fprintf(stderr, "sieve test context\n");
	fprintf(stderr, "    actions: %u\n", ctx->stats.actions);
	fprintf(stderr, "    errors: %u\n", ctx->stats.errors);
	fprintf(stderr, "    redirects: %u\n", ctx->stats.redirects);
	fprintf(stderr, "    discards: %u\n", ctx->stats.discards);
	fprintf(stderr, "    rejects: %u\n", ctx->stats.rejects);
	fprintf(stderr, "    fileintos: %u\n", ctx->stats.fileintos);
	fprintf(stderr, "    keeps: %u\n", ctx->stats.keeps);
	fprintf(stderr, "    notifies: %u\n", ctx->stats.notifies);
	fprintf(stderr, "    vaction_responses: %u\n", ctx->stats.vaction_responses);
	if (ctx->redirected_to)
	    fprintf(stderr, "    redirected_to: %s\n", ctx->redirected_to);
	if (ctx->reject_message)
	    fprintf(stderr, "    reject_message: %s\n", ctx->reject_message);
	if (ctx->filed_mailbox)
	    fprintf(stderr, "    filed_mailbox: %s\n", ctx->filed_mailbox);
	if (ctx->filed_flags)
	    fprintf(stderr, "    filed_flags: %s\n", ctx->filed_flags);
	if (ctx->notify_method)
	    fprintf(stderr, "    notify_method: %s\n", ctx->notify_method);
	if (ctx->notify_priority)
	    fprintf(stderr, "    notify_priority: %s\n", ctx->notify_priority);
	if (ctx->notify_options)
	    fprintf(stderr, "    notify_options: %s\n", ctx->notify_options);
	if (ctx->vacation_message)
	    fprintf(stderr, "    vacation_message: %s\n", ctx->vacation_message);
	if (ctx->vacation_subject)
	    fprintf(stderr, "    vacation_subject: %s\n", ctx->vacation_subject);
	if (ctx->vacation_to)
	    fprintf(stderr, "    vacation_to: %s\n", ctx->vacation_to);
	if (ctx->vacation_from)
	    fprintf(stderr, "    vacation_from: %s\n", ctx->vacation_from);
	if (ctx->compile_errors->count) {
	    fprintf(stderr, "    compile_errors:\n");
	    for (i = 0 ; i < ctx->compile_errors->count ; i++)
		fprintf(stderr, "\t[%d] %s\n", i, ctx->compile_errors->data[i]);
	}
	if (ctx->run_errors->count) {
	    fprintf(stderr, "    run_errors:\n");
	    for (i = 0 ; i < ctx->run_errors->count ; i++)
		fprintf(stderr, "\t[%d] %s\n", i, ctx->run_errors->data[i]);
	}
    }

    /*used to be sieve_script_free*/
    r = sieve_script_unload(&ctx->exe);
    CU_ASSERT_EQUAL(r, SIEVE_OK);
    CU_ASSERT_PTR_NULL(ctx->exe);

    r = sieve_interp_free(&ctx->interp);
    CU_ASSERT_EQUAL(r, SIEVE_OK);

    free(ctx->redirected_to);
    free(ctx->reject_message);
    free(ctx->filed_mailbox);
    free(ctx->filed_flags);
    free(ctx->notify_method);
    free(ctx->notify_priority);
    free(ctx->notify_options);
    free(ctx->vacation_message);
    free(ctx->vacation_subject);
    free(ctx->vacation_to);
    free(ctx->vacation_from);
    strarray_free(ctx->compile_errors);
    strarray_free(ctx->run_errors);
}


static sieve_test_message_t *message_new(const char *text, int len)
{
    sieve_test_message_t *msg;
    struct protstream *pin;
    FILE *fout;
    int fd;
    int r;
    char tempfile[32];

    msg = xzmalloc(sizeof(sieve_test_message_t));
    msg->text = text;
    msg->length = len;
    msg->headers = spool_new_hdrcache();

    strcpy(tempfile, "/tmp/sievetest-MS-XXXXXX");
    fd = mkstemp(tempfile);
    CU_ASSERT(fd >= 0);
    msg->filename = xstrdup(tempfile);
    r = retry_write(fd, text, len);
    CU_ASSERT_EQUAL(r, len);
    lseek(fd, SEEK_SET, 0);

    pin = prot_new(fd, /*read*/0);
    CU_ASSERT_PTR_NOT_NULL(pin);

    fout = fopen("/dev/null", "w");
    CU_ASSERT_PTR_NOT_NULL(fout);

    r = spool_fill_hdrcache(pin, fout, msg->headers, NULL);
    CU_ASSERT_EQUAL(r, 0);

    fclose(fout);
    prot_free(pin);

    return msg;
}

static void message_free(sieve_test_message_t *msg)
{
    spool_free_hdrcache(msg->headers);
    if (msg->content.body)
	message_free_body(msg->content.body);
    if (msg->content.base)
	map_free(&msg->content.base, &msg->content.len);
    unlink(msg->filename);
    free(msg->filename);
    free(msg);
}


static void run_message(sieve_test_context_t *ctx,
		        const char *text)
{
    sieve_test_message_t *msg;
    int r;

    msg = message_new(text, strlen(text));
    CU_ASSERT_PTR_NOT_NULL(msg);

    r = sieve_execute_bytecode(ctx->exe, ctx->interp, ctx, msg);
    CU_ASSERT_EQUAL(r, SIEVE_OK);

    message_free(msg);
}

static void test_address_all(void)
{
    static const char SCRIPT_IS[] =
    "if address :all :is \"from\" \"zme@true.com\"\n"
    "{redirect \"me@blah.com\";}\n"
    ;
    static const char SCRIPT_CONTAINS[] =
    "if address :all :contains \"from\" \"true.com\"\n"
    "{redirect \"me@blah.com\";}\n"
    ;
    static const char SCRIPT_MATCHES[] =
    "if address :all :matches \"from\" \"*true.com\"\n"
    "{redirect \"me@blah.com\";}\n"
    ;

    static const char MSG_TRUE[] =
    "Date: Mon, 25 Jan 2003 08:51:06 -0500\r\n"
    "From: zme@true.com\r\n"
    "To: you\r\n"
    "Subject: simple address test\r\n"
    "\r\n"
    "blah\n"
    ;
    static const char MSG_FALSE[] =
    "Date: Mon, 25 Jan 2003 08:51:06 -0500\r\n"
    "From: zme@false.com\r\n"
    "To: you\r\n"
    "Subject: simple address test\r\n"
    "\r\n"
    "blah\n"
    ;
    sieve_test_context_t ctx;

    /* Test :is */
    context_setup(&ctx, SCRIPT_IS);
    CU_ASSERT_EQUAL(ctx.stats.errors, 0);

    run_message(&ctx, MSG_TRUE);
    CU_ASSERT_EQUAL(ctx.stats.errors, 0);
    CU_ASSERT_EQUAL(ctx.stats.actions, 1);
    CU_ASSERT_EQUAL(ctx.stats.redirects, 1);
    CU_ASSERT_EQUAL(ctx.stats.keeps, 0);
    CU_ASSERT_STRING_EQUAL(ctx.redirected_to, "me@blah.com");

    run_message(&ctx, MSG_FALSE);
    CU_ASSERT_EQUAL(ctx.stats.errors, 0);
    CU_ASSERT_EQUAL(ctx.stats.actions, 2);
    CU_ASSERT_EQUAL(ctx.stats.redirects, 1);
    CU_ASSERT_EQUAL(ctx.stats.keeps, 1);
    CU_ASSERT_STRING_EQUAL(ctx.redirected_to, "me@blah.com");

    context_cleanup(&ctx);

    /* Test :contains */
    context_setup(&ctx, SCRIPT_CONTAINS);
    CU_ASSERT_EQUAL(ctx.stats.errors, 0);

    run_message(&ctx, MSG_TRUE);
    CU_ASSERT_EQUAL(ctx.stats.errors, 0);
    CU_ASSERT_EQUAL(ctx.stats.actions, 1);
    CU_ASSERT_EQUAL(ctx.stats.redirects, 1);
    CU_ASSERT_EQUAL(ctx.stats.keeps, 0);
    CU_ASSERT_STRING_EQUAL(ctx.redirected_to, "me@blah.com");

    run_message(&ctx, MSG_FALSE);
    CU_ASSERT_EQUAL(ctx.stats.errors, 0);
    CU_ASSERT_EQUAL(ctx.stats.actions, 2);
    CU_ASSERT_EQUAL(ctx.stats.redirects, 1);
    CU_ASSERT_EQUAL(ctx.stats.keeps, 1);
    CU_ASSERT_STRING_EQUAL(ctx.redirected_to, "me@blah.com");

    context_cleanup(&ctx);

    /* Test :matches */
    context_setup(&ctx, SCRIPT_MATCHES);
    CU_ASSERT_EQUAL(ctx.stats.errors, 0);

    run_message(&ctx, MSG_TRUE);
    CU_ASSERT_EQUAL(ctx.stats.errors, 0);
    CU_ASSERT_EQUAL(ctx.stats.actions, 1);
    CU_ASSERT_EQUAL(ctx.stats.redirects, 1);
    CU_ASSERT_EQUAL(ctx.stats.keeps, 0);
    CU_ASSERT_STRING_EQUAL(ctx.redirected_to, "me@blah.com");

    run_message(&ctx, MSG_FALSE);
    CU_ASSERT_EQUAL(ctx.stats.errors, 0);
    CU_ASSERT_EQUAL(ctx.stats.actions, 2);
    CU_ASSERT_EQUAL(ctx.stats.redirects, 1);
    CU_ASSERT_EQUAL(ctx.stats.keeps, 1);
    CU_ASSERT_STRING_EQUAL(ctx.redirected_to, "me@blah.com");

    context_cleanup(&ctx);
}

static void test_exists(void)
{
    static const char SCRIPT[] =
    "if exists \"flooglewart\"\n"
    "{redirect \"me@blah.com\";}\n"
    ;
    static const char MSG_TRUE[] =
    "Date: Mon, 25 Jan 2003 08:51:06 -0500\r\n"
    "From: zme@true.com\r\n"
    "To: you\r\n"
    "Subject: simple address test\r\n"
    "Flooglewart: fnarp fmeh oogedyboogedy\r\n"
    "\r\n"
    "blah\n"
    ;
    static const char MSG_FALSE[] =
    "Date: Mon, 25 Jan 2003 08:51:06 -0500\r\n"
    "From: yme@false.com\r\n"
    "To: you\r\n"
    "Subject: simple address test\r\n"
    "\r\n"
    "blah\n"
    ;
    sieve_test_context_t ctx;

    context_setup(&ctx, SCRIPT);
    CU_ASSERT_EQUAL(ctx.stats.errors, 0);

    run_message(&ctx, MSG_TRUE);
    CU_ASSERT_EQUAL(ctx.stats.errors, 0);
    CU_ASSERT_EQUAL(ctx.stats.actions, 1);
    CU_ASSERT_EQUAL(ctx.stats.redirects, 1);
    CU_ASSERT_EQUAL(ctx.stats.keeps, 0);
    CU_ASSERT_STRING_EQUAL(ctx.redirected_to, "me@blah.com");

    run_message(&ctx, MSG_FALSE);
    CU_ASSERT_EQUAL(ctx.stats.errors, 0);
    CU_ASSERT_EQUAL(ctx.stats.actions, 2);
    CU_ASSERT_EQUAL(ctx.stats.redirects, 1);
    CU_ASSERT_EQUAL(ctx.stats.keeps, 1);
    CU_ASSERT_STRING_EQUAL(ctx.redirected_to, "me@blah.com");

    context_cleanup(&ctx);
}

static void test_address_domain(void)
{
    static const char SCRIPT[] =
    "if address :domain :is \"from\" \"true.com\"\n"
    "{redirect \"me@blah.com\";}\n"
    ;
    static const char MSG_TRUE[] =
    "Date: Mon, 25 Jan 2003 08:51:06 -0500\r\n"
    "From: zme@true.com\r\n"
    "To: you\r\n"
    "Subject: simple address test\r\n"
    "\r\n"
    "blah\n"
    ;
    static const char MSG_FALSE[] =
    "Date: Mon, 25 Jan 2003 08:51:06 -0500\r\n"
    "From: zme@false.com\r\n"
    "To: you\r\n"
    "Subject: simple address test\r\n"
    "\r\n"
    "blah\n"
    ;
    sieve_test_context_t ctx;

    context_setup(&ctx, SCRIPT);
    CU_ASSERT_EQUAL(ctx.stats.errors, 0);

    run_message(&ctx, MSG_TRUE);
    CU_ASSERT_EQUAL(ctx.stats.errors, 0);
    CU_ASSERT_EQUAL(ctx.stats.actions, 1);
    CU_ASSERT_EQUAL(ctx.stats.redirects, 1);
    CU_ASSERT_EQUAL(ctx.stats.keeps, 0);
    CU_ASSERT_STRING_EQUAL(ctx.redirected_to, "me@blah.com");

    run_message(&ctx, MSG_FALSE);
    CU_ASSERT_EQUAL(ctx.stats.errors, 0);
    CU_ASSERT_EQUAL(ctx.stats.actions, 2);
    CU_ASSERT_EQUAL(ctx.stats.redirects, 1);
    CU_ASSERT_EQUAL(ctx.stats.keeps, 1);
    CU_ASSERT_STRING_EQUAL(ctx.redirected_to, "me@blah.com");

    context_cleanup(&ctx);
}

static void test_address_localpart(void)
{
    static const char SCRIPT[] =
    "if address :localpart :is \"from\" \"zme\"\n"
    "{redirect \"me@blah.com\";}\n"
    ;
    static const char MSG_TRUE[] =
    "Date: Mon, 25 Jan 2003 08:51:06 -0500\r\n"
    "From: zme@true.com\r\n"
    "To: you\r\n"
    "Subject: simple address test\r\n"
    "\r\n"
    "blah\n"
    ;
    static const char MSG_FALSE[] =
    "Date: Mon, 25 Jan 2003 08:51:06 -0500\r\n"
    "From: yme@false.com\r\n"
    "To: you\r\n"
    "Subject: simple address test\r\n"
    "\r\n"
    "blah\n"
    ;
    sieve_test_context_t ctx;

    context_setup(&ctx, SCRIPT);
    CU_ASSERT_EQUAL(ctx.stats.errors, 0);

    run_message(&ctx, MSG_TRUE);
    CU_ASSERT_EQUAL(ctx.stats.errors, 0);
    CU_ASSERT_EQUAL(ctx.stats.actions, 1);
    CU_ASSERT_EQUAL(ctx.stats.redirects, 1);
    CU_ASSERT_EQUAL(ctx.stats.keeps, 0);
    CU_ASSERT_STRING_EQUAL(ctx.redirected_to, "me@blah.com");

    run_message(&ctx, MSG_FALSE);
    CU_ASSERT_EQUAL(ctx.stats.errors, 0);
    CU_ASSERT_EQUAL(ctx.stats.actions, 2);
    CU_ASSERT_EQUAL(ctx.stats.redirects, 1);
    CU_ASSERT_EQUAL(ctx.stats.keeps, 1);
    CU_ASSERT_STRING_EQUAL(ctx.redirected_to, "me@blah.com");

    context_cleanup(&ctx);
}

// TODO: test
// if size :over 10K { redirect "me@blah.com"; }
// TODO: test
// if true {...}
//
// if false {...}
//
// if not false {...}
//
// if true {...} else {...}
//
// if false {...} elsif true {...} else {...}
//
// if false {...} elsif false {...} else {...}
//
// if false {} else {...}
//
// if true { if true { if true { ... } } }
//
// if allof(false, false) {...} else {...}
//
// if allof(false,true) {...} else {...}
//
// if allof(true,false) {...} else {...}
//
// if allof(true,true) {...} else {...}
//
// if anyof(false, false) {...} else {...}
//
// if anyof(false,true) {...} else {...}
//
// if anyof(true,false) {...} else {...}
//
// if anyof(true,true) {...} else {...}

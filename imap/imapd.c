/*
 * Copyright (c) 1994-2008 Carnegie Mellon University.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The name "Carnegie Mellon University" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For permission or any legal
 *    details, please contact
 *      Carnegie Mellon University
 *      Center for Technology Transfer and Enterprise Creation
 *      4615 Forbes Avenue
 *      Suite 302
 *      Pittsburgh, PA  15213
 *      (412) 268-7393, fax: (412) 268-7395
 *      innovation@andrew.cmu.edu
 *
 * 4. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by Computing Services
 *     at Carnegie Mellon University (http://www.cmu.edu/computing/)."
 *
 * CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
 * FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * $Id: imapd.c,v 1.545 2008/04/10 17:30:18 murch Exp $
 */

#include <config.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <syslog.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <sasl/sasl.h>

#ifdef HAVE_SSL
#include <openssl/hmac.h>
#include <openssl/rand.h>
#endif /* HAVE_SSL */

#include "acl.h"
#include "annotate.h"
#include "append.h"
#include "auth.h"
#include "backend.h"
#include "charset.h"
#include "exitcodes.h"
#include "idle.h"
#include "global.h"
#include "hash.h"
#include "imap_err.h"
#include "proxy.h"
#include "imap_proxy.h"
#include "imapd.h"
#include "imapurl.h"
#include "imparse.h"
#include "index.h"
#include "iptostring.h"
#include "mailbox.h"
#include "message.h"
#include "mboxkey.h"
#include "mboxlist.h"
#include "mboxname.h"
#include "mbdump.h"
#include "mkgmtime.h"
#include "mupdate-client.h"
#include "quota.h"
#include "statuscache.h"
#include "sync_log.h"
#include "telemetry.h"
#include "tls.h"
#include "user.h"
#include "util.h"
#include "version.h"
#include "xmalloc.h"
#include "xstrlcat.h"
#include "xstrlcpy.h"

#include "pushstats.h"		/* SNMP interface */

extern void seen_done(void);

extern int optind;
extern char *optarg;

/* global state */
const int config_need_data = CONFIG_NEED_PARTITION_DATA;

static char shutdownfilename[1024];
static int imaps = 0;
static sasl_ssf_t extprops_ssf = 0;

/* PROXY STUFF */
/* we want a list of our outgoing connections here and which one we're
   currently piping */

static const int ultraparanoid = 1; /* should we kick after every operation? */
unsigned int proxy_cmdcnt;

static int referral_kick = 0; /* kick after next command recieved, for
				 referrals that are likely to change the
				 mailbox list */

/* all subscription commands go to the backend server containing the
   user's inbox */
struct backend *backend_inbox = NULL;

/* the current server most commands go to */
struct backend *backend_current = NULL;

/* our cached connections */
struct backend **backend_cached = NULL;

/* are we doing virtdomains with multiple IPs? */
static int disable_referrals;

/* has the client issued an RLIST, RLSUB, or LIST (REMOTE)? */
static int supports_referrals;

/* end PROXY STUFF */

/* per-user/session state */
int imapd_timeout;
struct protstream *imapd_out = NULL;
struct protstream *imapd_in = NULL;
struct protgroup *protin = NULL;
static char imapd_clienthost[NI_MAXHOST*2+1] = "[local]";
static int imapd_logfd = -1;
char *imapd_userid = NULL, *proxy_userid = NULL;
static char *imapd_magicplus = NULL;
struct auth_state *imapd_authstate = 0;
static int imapd_userisadmin = 0;
static int imapd_userisproxyadmin = 0;
int imapd_condstore_client = 0;
static sasl_conn_t *imapd_saslconn; /* the sasl connection context */
static int imapd_starttls_done = 0; /* have we done a successful starttls? */
const char *plaintextloginalert = NULL;
#ifdef HAVE_SSL
/* our tls connection, if any */
static SSL *tls_conn = NULL;
#endif /* HAVE_SSL */

/* stage(s) for APPEND */
struct appendstage {
    struct stagemsg *stage;
    FILE *f;
    char **flag;
    int nflags, flagalloc;
    time_t internaldate;
    int binary;
} **stage = NULL;
unsigned long numstage = 0;

/* the sasl proxy policy context */
static struct proxy_context imapd_proxyctx = {
    1, 1, &imapd_authstate, &imapd_userisadmin, &imapd_userisproxyadmin
};

/* current sub-user state */
static struct mailbox mboxstruct;
static struct mailbox *imapd_mailbox;
int imapd_exists = -1;

/* current namespace */
struct namespace imapd_namespace;

static const char *monthname[] = {
    "jan", "feb", "mar", "apr", "may", "jun",
    "jul", "aug", "sep", "oct", "nov", "dec"
};

static const int max_monthdays[] = {
    31, 29, 31, 30, 31, 30,
    31, 31, 30, 31, 30, 31
};

void motd_file(int fd);
void shut_down(int code);
void fatal(const char *s, int code);

void cmdloop(void);
void cmd_login(char *tag, char *user);
void cmd_authenticate(char *tag, char *authtype, char *resp);
void cmd_noop(char *tag, char *cmd);
void capa_response(int flags);
void cmd_capability(char *tag);
void cmd_append(char *tag, char *name, const char *cur_name);
void cmd_select(char *tag, char *cmd, char *name);
void cmd_close(char *tag);
void cmd_fetch(char *tag, char *sequence, int usinguid);
void cmd_partial(const char *tag, const char *msgno, char *data,
		 const char *start, const char *count);
void cmd_store(char *tag, char *sequence, int usinguid);
void cmd_search(char *tag, int usinguid);
void cmd_sort(char *tag, int usinguid);
void cmd_thread(char *tag, int usinguid);
void cmd_copy(char *tag, char *sequence, char *name, int usinguid);
void cmd_expunge(char *tag, char *sequence);
void cmd_create(char *tag, char *name, char *partition, int localonly);
void cmd_delete(char *tag, char *name, int localonly, int force);
void cmd_dump(char *tag, char *name, int uid_start);
void cmd_undump(char *tag, char *name);
void cmd_xfer(char *tag, char *name, char *toserver, char *topart);
void cmd_rename(char *tag, char *oldname, char *newname, char *partition);
void cmd_reconstruct(const char *tag, const char *name, int recursive);
void cmd_find(char *tag, char *namespace, char *pattern);
void cmd_list(char *tag, struct listargs *listargs);
void cmd_changesub(char *tag, char *namespace, char *name, int add);
void cmd_getacl(const char *tag, const char *name);
void cmd_listrights(char *tag, char *name, char *identifier);
void cmd_myrights(const char *tag, const char *name);
void cmd_setacl(char *tag, const char *name,
		const char *identifier, const char *rights);
void cmd_getquota(const char *tag, const char *name);
void cmd_getquotaroot(const char *tag, const char *name);
void cmd_setquota(const char *tag, const char *quotaroot);
void cmd_status(char *tag, char *name);
void cmd_unselect(char* tag);
void cmd_namespace(char* tag);
void cmd_mupdatepush(char *tag, char *name);
void cmd_id(char* tag);
extern void id_getcmdline(int argc, char **argv);
extern void id_response(struct protstream *pout);

void cmd_idle(char* tag);
void idle_update(idle_flags_t flags);

void cmd_starttls(char *tag, int imaps);

#ifdef HAVE_SSL
void cmd_urlfetch(char *tag);
void cmd_genurlauth(char *tag);
void cmd_resetkey(char *tag, char *mailbox, char *mechanism);
#endif

#ifdef ENABLE_X_NETSCAPE_HACK
void cmd_netscrape(char* tag);
#endif

void cmd_getannotation(char* tag, char *mboxpat);
void cmd_setannotation(char* tag, char *mboxpat);

int getannotatefetchdata(char *tag,
			 struct strlist **entries, struct strlist **attribs);
int getannotatestoredata(char *tag, struct entryattlist **entryatts);

void annotate_response(struct entryattlist *l);

#ifdef ENABLE_LISTEXT
int getlistopts(char *tag, unsigned *listopts);
#endif

int getsearchprogram(char *tag, struct searchargs *searchargs,
			int *charset, int parsecharset);
int getsearchcriteria(char *tag, struct searchargs *searchargs,
			 int *charset, int parsecharset);
int getsearchdate(time_t *start, time_t *end);
int getsortcriteria(char *tag, struct sortcrit **sortcrit);
int getdatetime(time_t *date);

void printstring(const char *s);
void printastring(const char *s);

void appendfieldlist(struct fieldlist **l, char *section,
		     struct strlist *fields, char *trail,
		     void *d, size_t size);
void freefieldlist(struct fieldlist *l);
void freestrlist(struct strlist *l);
void appendsearchargs(struct searchargs *s, struct searchargs *s1,
			 struct searchargs *s2);
void freesearchargs(struct searchargs *s);
static void freesortcrit(struct sortcrit *s);

static int mailboxdata(char *name, int matchlen, int maycreate, void *rock);
static int listdata(char *name, int matchlen, int maycreate, void *rock);
static void mstringdata(char *cmd, char *name, int matchlen, int maycreate,
			unsigned listopts);

extern void setproctitle_init(int argc, char **argv, char **envp);
extern int proc_register(const char *progname, const char *clienthost, 
			 const char *userid, const char *mailbox);
extern void proc_cleanup(void);

extern int saslserver(sasl_conn_t *conn, const char *mech,
		      const char *init_resp, const char *resp_prefix,
		      const char *continuation, const char *empty_resp,
		      struct protstream *pin, struct protstream *pout,
		      int *sasl_result, char **success_data);

/* Enable the resetting of a sasl_conn_t */
static int reset_saslconn(sasl_conn_t **conn);

static struct 
{
    char *ipremoteport;
    char *iplocalport;
    sasl_ssf_t ssf;
    char *authid;
} saslprops = {NULL,NULL,0,NULL};

static int imapd_canon_user(sasl_conn_t *conn, void *context,
			    const char *user, unsigned ulen,
			    unsigned flags, const char *user_realm,
			    char *out, unsigned out_max, unsigned *out_ulen)
{
    char userbuf[MAX_MAILBOX_NAME+1], *p;
    size_t n;
    int r;

    if (!ulen) ulen = strlen(user);

    if (config_getswitch(IMAPOPT_IMAPMAGICPLUS)) {
	/* make a working copy of the auth[z]id */
	if (ulen > MAX_MAILBOX_NAME) {
	    sasl_seterror(conn, 0, "buffer overflow while canonicalizing");
	    return SASL_BUFOVER;
	}
	memcpy(userbuf, user, ulen);
	userbuf[ulen] = '\0';
	user = userbuf;

	/* See if we're using the magic plus
	   (currently we don't support anything after '+') */
	if ((p = strchr(userbuf, '+')) && 
	    (n = config_virtdomains ? strcspn(p, "@") : strlen(p)) == 1) {

	    if (flags & SASL_CU_AUTHZID) {
		/* make a copy of the magic plus */
		if (imapd_magicplus) free(imapd_magicplus);
		imapd_magicplus = xstrndup(p, n);
	    }

	    /* strip the magic plus from the auth[z]id */
	    memmove(p, p+n, strlen(p+n)+1);
	    ulen -= n;
	}
    }

    r = mysasl_canon_user(conn, context, user, ulen, flags, user_realm,
			  out, out_max, out_ulen);

    if (!r && imapd_magicplus && flags == SASL_CU_AUTHZID) {
	/* If we're only doing the authzid, put back the magic plus
	   in case its used in the challenge/response calculation */
	n = strlen(imapd_magicplus);
	if (*out_ulen + n > out_max) {
	    sasl_seterror(conn, 0, "buffer overflow while canonicalizing");
	    r = SASL_BUFOVER;
	}
	else {
	    p = (config_virtdomains && (p = strchr(out, '@'))) ?
		p : out + *out_ulen;
	    memmove(p+n, p, strlen(p)+1);
	    memcpy(p, imapd_magicplus, n);
	    *out_ulen += n;
	}
    }

    return r;
}

static int imapd_proxy_policy(sasl_conn_t *conn,
			      void *context,
			      const char *requested_user, unsigned rlen,
			      const char *auth_identity, unsigned alen,
			      const char *def_realm,
			      unsigned urlen,
			      struct propctx *propctx)
{
    if (config_getswitch(IMAPOPT_IMAPMAGICPLUS)) {
	char userbuf[MAX_MAILBOX_NAME+1], *p;
	size_t n;

	/* make a working copy of the authzid */
	if (!rlen) rlen = strlen(requested_user);
	if (rlen > MAX_MAILBOX_NAME) {
	    sasl_seterror(conn, 0, "buffer overflow while proxying");
	    return SASL_BUFOVER;
	}
	memcpy(userbuf, requested_user, rlen);
	userbuf[rlen] = '\0';
	requested_user = userbuf;

	/* See if we're using the magic plus */
	if ((p = strchr(userbuf, '+'))) {
	    n = config_virtdomains ? strcspn(p, "@") : strlen(p);

	    /* strip the magic plus from the authzid */
	    memmove(p, p+n, strlen(p+n)+1);
	    rlen -= n;
	}
    }

    return mysasl_proxy_policy(conn, context, requested_user, rlen,
			       auth_identity, alen, def_realm, urlen, propctx);
}

static const struct sasl_callback mysasl_cb[] = {
    { SASL_CB_GETOPT, &mysasl_config, NULL },
    { SASL_CB_PROXY_POLICY, &imapd_proxy_policy, (void*) &imapd_proxyctx },
    { SASL_CB_CANON_USER, &imapd_canon_user, (void*) &disable_referrals },
    { SASL_CB_LIST_END, NULL, NULL }
};

/* imapd_refer() issues a referral to the client. */
static void imapd_refer(const char *tag,
			const char *server,
			const char *mailbox)
{
    struct imapurl imapurl;
    char url[MAX_MAILBOX_PATH+1];

    memset(&imapurl, 0, sizeof(struct imapurl));
    imapurl.server = server;
    imapurl.mailbox = mailbox;
    imapurl.auth = !strcmp(imapd_userid, "anonymous") ? "anonymous" : "*";

    imapurl_toURL(url, &imapurl);
    
    prot_printf(imapd_out, "%s NO [REFERRAL %s] Remote mailbox.\r\n", 
		tag, url);
}

/* wrapper for mboxlist_lookup that will force a referral if we are remote
 * returns IMAP_SERVER_UNAVAILABLE if we don't have a place to send the client
 * (that'd be a bug).
 * returns IMAP_MAILBOX_MOVED if we referred the client */
/* ext_name is the external name of the mailbox */
/* you can avoid referring the client by setting tag or ext_name to NULL. */
int mlookup(const char *tag, const char *ext_name,
	    const char *name, int *flags, char **pathp, char **mpathp,
	    char **partp, char **aclp, struct txn **tid) 
{
    int r, mbtype;
    char *remote, *acl;

    r = mboxlist_detail(name, &mbtype, pathp, mpathp, &remote, &acl, tid);
    if ((r == IMAP_MAILBOX_NONEXISTENT || (mbtype & MBTYPE_RESERVE)) &&
	config_mupdate_server) {
	/* It is not currently active, make sure we have the most recent
	 * copy of the database */
	kick_mupdate();
	r = mboxlist_detail(name, &mbtype, pathp, mpathp, &remote, &acl, tid);
    }

    if(partp) *partp = remote;
    if(aclp) *aclp = acl;
    if(flags) *flags = mbtype;
    if(r) return r;

    if(mbtype & MBTYPE_RESERVE) return IMAP_MAILBOX_RESERVED;
    
    if(mbtype & MBTYPE_MOVING) {
	/* do we have rights on the mailbox? */
	if(!imapd_userisadmin &&
	   (!acl || !(cyrus_acl_myrights(imapd_authstate,acl) & ACL_LOOKUP))) {
	    r = IMAP_MAILBOX_NONEXISTENT;
	} else if(tag && ext_name && remote && *remote) {
	    char *c = NULL;
	    
	    c = strchr(remote, '!');
	    if(c) *c = '\0';
	    imapd_refer(tag, remote, ext_name);
	    r = IMAP_MAILBOX_MOVED;
	} else if(config_mupdate_server) {
	    r = IMAP_SERVER_UNAVAILABLE;
	} else {
	    r = IMAP_MAILBOX_NOTSUPPORTED;
	}
    }
    else if (mbtype & MBTYPE_REMOTE) {
	/* xxx hide the fact that we are storing partitions */
	if(remote && *remote) {
	    char *c;
	    c = strchr(remote, '!');
	    if(c) *c = '\0';
	}
    }
    
    return r;
}

static void imapd_reset(void)
{
    int i;
    
    proc_cleanup();

    /* close backend connections */
    i = 0;
    while (backend_cached && backend_cached[i]) {
	proxy_downserver(backend_cached[i]);
	if (backend_cached[i]->last_result.s) {
	    free(backend_cached[i]->last_result.s);
	}
	free(backend_cached[i]);
	i++;
    }
    if (backend_cached) free(backend_cached);
    backend_cached = NULL;
    backend_inbox = backend_current = NULL;
    proxy_cmdcnt = 0;
    disable_referrals = 0;
    supports_referrals = 0;

    if (imapd_mailbox) {
	index_closemailbox(imapd_mailbox);
	mailbox_close(imapd_mailbox);
	imapd_mailbox = 0;
    }

    if (imapd_in) {
	/* Flush the incoming buffer */
	prot_NONBLOCK(imapd_in);
	prot_fill(imapd_in);

	prot_free(imapd_in);
    }

    if (imapd_out) {
	/* Flush the outgoing buffer */
	prot_flush(imapd_out);

	prot_free(imapd_out);
    }
    
    imapd_in = imapd_out = NULL;

    if (protin) protgroup_reset(protin);

#ifdef HAVE_SSL
    if (tls_conn) {
	if (tls_reset_servertls(&tls_conn) == -1) {
	    fatal("tls_reset() failed", EC_TEMPFAIL);
	}
	tls_conn = NULL;
    }
#endif

    cyrus_reset_stdio();

    strcpy(imapd_clienthost, "[local]");
    if (imapd_logfd != -1) {
	close(imapd_logfd);
	imapd_logfd = -1;
    }
    if (imapd_userid != NULL) {
	free(imapd_userid);
	imapd_userid = NULL;
    }
    if (proxy_userid != NULL) {
	free(proxy_userid);
	proxy_userid = NULL;
    }
    if (imapd_magicplus != NULL) {
	free(imapd_magicplus);
	imapd_magicplus = NULL;
    }
    if (imapd_authstate) {
	auth_freestate(imapd_authstate);
	imapd_authstate = NULL;
    }
    imapd_userisadmin = 0;
    imapd_userisproxyadmin = 0;
    imapd_condstore_client = 0;
    if (imapd_saslconn) {
	sasl_dispose(&imapd_saslconn);
	free(imapd_saslconn);
	imapd_saslconn = NULL;
    }
    imapd_starttls_done = 0;
    plaintextloginalert = NULL;

    if(saslprops.iplocalport) {
	free(saslprops.iplocalport);
	saslprops.iplocalport = NULL;
    }
    if(saslprops.ipremoteport) {
	free(saslprops.ipremoteport);
	saslprops.ipremoteport = NULL;
    }
    if(saslprops.authid) {
	free(saslprops.authid);
	saslprops.authid = NULL;
    }
    saslprops.ssf = 0;

    imapd_exists = -1;
}

/*
 * run once when process is forked;
 * MUST NOT exit directly; must return with non-zero error code
 */
int service_init(int argc, char **argv, char **envp)
{
    int ret;
    int opt;
    
    if (geteuid() == 0) fatal("must run as the Cyrus user", EC_USAGE);
    setproctitle_init(argc, argv, envp);

    /* set signal handlers */
    signals_set_shutdown(&shut_down);
    signal(SIGPIPE, SIG_IGN);

    /* load the SASL plugins */
    global_sasl_init(1, 1, mysasl_cb);

    ret = snprintf(shutdownfilename, sizeof(shutdownfilename),
		   "%s/msg/shutdown", config_dir);
    
    if(ret < 0 || ret >= (int) sizeof(shutdownfilename)) {
       fatal("shutdownfilename buffer too small (configdirectory too long)",
	     EC_CONFIG);
    }

    /* open the mboxlist, we'll need it for real work */
    mboxlist_init(0);
    mboxlist_open(NULL);
    mailbox_initialize();

    /* open the quota db, we'll need it for real work */
    quotadb_init(0);
    quotadb_open(NULL);

    /* setup for sending IMAP IDLE notifications */
    idle_enabled();

    /* create connection to the SNMP listener, if available. */
    snmp_connect(); /* ignore return code */
    snmp_set_str(SERVER_NAME_VERSION,CYRUS_VERSION);

    while ((opt = getopt(argc, argv, "sp:")) != EOF) {
	switch (opt) {
	case 's': /* imaps (do starttls right away) */
	    imaps = 1;
	    if (!tls_enabled()) {
		syslog(LOG_ERR, "imaps: required OpenSSL options not present");
		fatal("imaps: required OpenSSL options not present",
		      EC_CONFIG);
	    }
	    break;
	case 'p': /* external protection */
	    extprops_ssf = atoi(optarg);
	    break;
	default:
	    break;
	}
    }

    /* Initialize the annotatemore extention */
    if (config_mupdate_server)
	annotatemore_init(0, annotate_fetch_proxy, annotate_store_proxy);
    else
	annotatemore_init(0, NULL, NULL);
    annotatemore_open(NULL);

    if (config_getswitch(IMAPOPT_STATUSCACHE)) {
	statuscache_open(NULL);
    }

    /* Create a protgroup for input from the client and selected backend */
    protin = protgroup_new(2);

    return 0;
}

/*
 * run for each accepted connection
 */
#ifdef ID_SAVE_CMDLINE
int service_main(int argc, char **argv, char **envp __attribute__((unused)))
#else
int service_main(int argc __attribute__((unused)),
		 char **argv __attribute__((unused)),
		 char **envp __attribute__((unused)))
#endif
{
    socklen_t salen;
    sasl_security_properties_t *secprops = NULL;
    struct sockaddr_storage imapd_localaddr, imapd_remoteaddr;
    char localip[60], remoteip[60];
    char hbuf[NI_MAXHOST];
    int niflags;
    int imapd_haveaddr = 0;

    signals_poll();

#ifdef ID_SAVE_CMDLINE
    /* get command line args for use in ID before getopt mangles them */
    id_getcmdline(argc, argv);
#endif

    sync_log_init();

    imapd_in = prot_new(0, 0);
    imapd_out = prot_new(1, 1);
    protgroup_insert(protin, imapd_in);

    /* Find out name of client host */
    salen = sizeof(imapd_remoteaddr);
    if (getpeername(0, (struct sockaddr *)&imapd_remoteaddr, &salen) == 0 &&
	(imapd_remoteaddr.ss_family == AF_INET ||
	 imapd_remoteaddr.ss_family == AF_INET6)) {
	if (getnameinfo((struct sockaddr *)&imapd_remoteaddr, salen,
			hbuf, sizeof(hbuf), NULL, 0, NI_NAMEREQD) == 0) {
	    strncpy(imapd_clienthost, hbuf, sizeof(hbuf));
	    strlcat(imapd_clienthost, " ", sizeof(imapd_clienthost));
	    imapd_clienthost[sizeof(imapd_clienthost)-30] = '\0';
	} else {
	    imapd_clienthost[0] = '\0';
	}
	niflags = NI_NUMERICHOST;
#ifdef NI_WITHSCOPEID
	if (((struct sockaddr *)&imapd_remoteaddr)->sa_family == AF_INET6)
	    niflags |= NI_WITHSCOPEID;
#endif
	if (getnameinfo((struct sockaddr *)&imapd_remoteaddr, salen, hbuf,
			sizeof(hbuf), NULL, 0, niflags) != 0)
	    strlcpy(hbuf, "unknown", sizeof(hbuf));
	strlcat(imapd_clienthost, "[", sizeof(imapd_clienthost));
	strlcat(imapd_clienthost, hbuf, sizeof(imapd_clienthost));
	strlcat(imapd_clienthost, "]", sizeof(imapd_clienthost));
	salen = sizeof(imapd_localaddr);
	if (getsockname(0, (struct sockaddr *)&imapd_localaddr, &salen) == 0) {
	    if(iptostring((struct sockaddr *)&imapd_remoteaddr, salen,
			  remoteip, sizeof(remoteip)) == 0
	       && iptostring((struct sockaddr *)&imapd_localaddr, salen,
			     localip, sizeof(localip)) == 0) {
		imapd_haveaddr = 1;
	    }
	}
    }

    /* create the SASL connection */
    if (sasl_server_new("imap", config_servername, 
			NULL, NULL, NULL, NULL, 0, 
			&imapd_saslconn) != SASL_OK) {
	fatal("SASL failed initializing: sasl_server_new()", EC_TEMPFAIL);
    }

    secprops = mysasl_secprops(0);
    sasl_setprop(imapd_saslconn, SASL_SEC_PROPS, secprops);
    sasl_setprop(imapd_saslconn, SASL_SSF_EXTERNAL, &extprops_ssf);

    if (imapd_haveaddr) {
	sasl_setprop(imapd_saslconn, SASL_IPREMOTEPORT, remoteip);
	saslprops.ipremoteport = xstrdup(remoteip);
	sasl_setprop(imapd_saslconn, SASL_IPLOCALPORT, localip);
	saslprops.iplocalport = xstrdup(localip);
    }

    proc_register("imapd", imapd_clienthost, NULL, NULL);

    /* Set inactivity timer */
    imapd_timeout = config_getint(IMAPOPT_TIMEOUT);
    if (imapd_timeout < 30) imapd_timeout = 30;
    imapd_timeout *= 60;
    prot_settimeout(imapd_in, imapd_timeout);
    prot_setflushonread(imapd_in, imapd_out);

    /* we were connected on imaps port so we should do 
       TLS negotiation immediately */
    if (imaps == 1) cmd_starttls(NULL, 1);

    snmp_increment(TOTAL_CONNECTIONS, 1);
    snmp_increment(ACTIVE_CONNECTIONS, 1);

    cmdloop();

    /* LOGOUT executed */
    prot_flush(imapd_out);
    snmp_increment(ACTIVE_CONNECTIONS, -1);

    /* cleanup */
    imapd_reset();

    return 0;
}

/* Called by service API to shut down the service */
void service_abort(int error)
{
    shut_down(error);
}

/*
 * found a motd file; spit out message and return
 */
void motd_file(fd)
int fd;
{
    struct protstream *motd_in;
    char buf[1024];
    char *p;

    motd_in = prot_new(fd, 0);

    prot_fgets(buf, sizeof(buf), motd_in);
    if ((p = strchr(buf, '\r'))!=NULL) *p = 0;
    if ((p = strchr(buf, '\n'))!=NULL) *p = 0;

    for(p = buf; *p == '['; p++); /* can't have [ be first char, sigh */
    prot_printf(imapd_out, "* OK [ALERT] %s\r\n", p);
}

/*
 * Cleanly shut down and exit
 */
void shut_down(int code) __attribute__((noreturn));
void shut_down(int code)
{
    int i;

    proc_cleanup();

    i = 0;
    while (backend_cached && backend_cached[i]) {
	proxy_downserver(backend_cached[i]);
	if (backend_cached[i]->last_result.s) {
	    free(backend_cached[i]->last_result.s);
	}
	free(backend_cached[i]);
	i++;
    }
    if (backend_cached) free(backend_cached);

    if (imapd_mailbox) {
	index_closemailbox(imapd_mailbox);
	mailbox_close(imapd_mailbox);
    }
    seen_done();
    mboxkey_done();
    mboxlist_close();
    mboxlist_done();

    quotadb_close();
    quotadb_done();

    annotatemore_close();
    annotatemore_done();

    if (config_getswitch(IMAPOPT_STATUSCACHE)) {
	statuscache_close();
	statuscache_done();
    }

    if (imapd_in) {
	/* Flush the incoming buffer */
	prot_NONBLOCK(imapd_in);
	prot_fill(imapd_in);
	
	prot_free(imapd_in);
    }
    
    if (imapd_out) {
	/* Flush the outgoing buffer */
	prot_flush(imapd_out);
	prot_free(imapd_out);
	
	/* one less active connection */
	snmp_increment(ACTIVE_CONNECTIONS, -1);
    }

    if (protin) protgroup_free(protin);

#ifdef HAVE_SSL
    tls_shutdown_serverengine();
#endif

    cyrus_done();

    exit(code);
}

void fatal(const char *s, int code)
{
    static int recurse_code = 0;

    if (recurse_code) {
	/* We were called recursively. Just give up */
	proc_cleanup();
	snmp_increment(ACTIVE_CONNECTIONS, -1);
	exit(recurse_code);
    }
    recurse_code = code;
    if (imapd_out) {
	prot_printf(imapd_out, "* BYE Fatal error: %s\r\n", s);
	prot_flush(imapd_out);
    }
    if (stage) {
	/* Cleanup the stage(s) */
	while (numstage) {
	    struct appendstage *curstage = stage[--numstage];

	    if (curstage->f != NULL) fclose(curstage->f);
	    append_removestage(curstage->stage);
	    while (curstage->nflags--) {
		free(curstage->flag[curstage->nflags]);
	    }
	    if (curstage->flag) free((char *) curstage->flag);
	    free(curstage);
	}
	free(stage);
    }

    syslog(LOG_ERR, "Fatal error: %s", s);
    shut_down(code);
}

/*
 * Check the currently selected mailbox for updates.
 *
 * 'be' is the backend (if any) that we just proxied a command to.
 */
static void imapd_check(struct backend *be, int usinguid, int checkseen)
{
    if (backend_current && backend_current != be) {
	/* remote mailbox */
	char mytag[128];

	proxy_gentag(mytag, sizeof(mytag));
	    
	prot_printf(backend_current->out, "%s Noop\r\n", mytag);
	pipe_until_tag(backend_current, mytag, 0);
    }
    else if (imapd_mailbox) {
	/* local mailbox */
	index_check(imapd_mailbox, usinguid, checkseen);
    }
}

/*
 * Top-level command loop parsing
 */
void cmdloop()
{
    int fd;
    char motdfilename[1024];
    int c;
    int ret;
    int usinguid, havepartition, havenamespace, recursive;
    static struct buf tag, cmd, arg1, arg2, arg3, arg4;
    char *p, shut[1024];
    const char *err;

    prot_printf(imapd_out, "* OK [CAPABILITY ");
    capa_response(CAPA_PREAUTH);
    prot_printf(imapd_out, "] %s Cyrus IMAP4 %s%s server ready\r\n",
		config_servername,
		config_mupdate_server ? "(Murder) " : "", CYRUS_VERSION);

    ret = snprintf(motdfilename, sizeof(motdfilename), "%s/msg/motd",
		   config_dir);
    
    if(ret < 0 || ret >= (int) sizeof(motdfilename)) {
       fatal("motdfilename buffer too small (configdirectory too long)",
	     EC_CONFIG);
    }
    
    if ((fd = open(motdfilename, O_RDONLY, 0)) != -1) {
	motd_file(fd);
	close(fd);
    }

    for (;;) {
	/* Flush any buffered output */
	prot_flush(imapd_out);
	if (backend_current) prot_flush(backend_current->out);

	/* Check for shutdown file */
	if ( !imapd_userisadmin && imapd_userid
	     && shutdown_file(shut, sizeof(shut))) {
	    for (p = shut; *p == '['; p++); /* can't have [ be first char */
	    prot_printf(imapd_out, "* BYE [ALERT] %s\r\n", p);
	    shut_down(0);
	}

	signals_poll();

	if (!proxy_check_input(protin, imapd_in, imapd_out,
			       backend_current ? backend_current->in : NULL,
			       NULL, 0)) {
	    /* No input from client */
	    continue;
	}

	/* Parse tag */
	c = getword(imapd_in, &tag);
	if (c == EOF) {
	    if ((err = prot_error(imapd_in))!=NULL
		&& strcmp(err, PROT_EOF_STRING)) {
		syslog(LOG_WARNING, "%s, closing connection", err);
		prot_printf(imapd_out, "* BYE %s\r\n", err);
	    }
	    return;
	}
	if (c != ' ' || !imparse_isatom(tag.s) || (tag.s[0] == '*' && !tag.s[1])) {
	    prot_printf(imapd_out, "* BAD Invalid tag\r\n");
	    eatline(imapd_in, c);
	    continue;
	}

	/* Parse command name */
	c = getword(imapd_in, &cmd);
	if (!cmd.s[0]) {
	    prot_printf(imapd_out, "%s BAD Null command\r\n", tag.s);
	    eatline(imapd_in, c);
	    continue;
	}
	if (islower((unsigned char) cmd.s[0])) 
	    cmd.s[0] = toupper((unsigned char) cmd.s[0]);
	for (p = &cmd.s[1]; *p; p++) {
	    if (isupper((unsigned char) *p)) *p = tolower((unsigned char) *p);
	}

	/* if we need to force a kick, do so */
	if (referral_kick) {
	    kick_mupdate();
	    referral_kick = 0;
	}
	
	if (plaintextloginalert) {
	    prot_printf(imapd_out, "* OK [ALERT] %s\r\n",
			plaintextloginalert);
	    plaintextloginalert = NULL;
	}

 	/* Only Authenticate/Login/Logout/Noop/Capability/Id/Starttls
	   allowed when not logged in */
	if (!imapd_userid && !strchr("ALNCIS", cmd.s[0])) goto nologin;
    
	/* note that about half the commands (the common ones that don't
	   hit the mailboxes file) now close the mailboxes file just in
	   case it was open. */
	switch (cmd.s[0]) {
	case 'A':
	    if (!strcmp(cmd.s, "Authenticate")) {
		int haveinitresp = 0;

		if (c != ' ') goto missingargs;
		c = getword(imapd_in, &arg1);
		if (!imparse_isatom(arg1.s)) {
		    prot_printf(imapd_out, "%s BAD Invalid authenticate mechanism\r\n", tag.s);
		    eatline(imapd_in, c);
		    continue;
		}
		if (c == ' ') {
		    haveinitresp = 1;
		    c = getword(imapd_in, &arg2);
		    if (c == EOF) goto missingargs;
		}
		if (c == '\r') c = prot_getc(imapd_in);
		if (c != '\n') goto extraargs;
		
		if (imapd_userid) {
		    prot_printf(imapd_out, "%s BAD Already authenticated\r\n", tag.s);
		    continue;
		}
		cmd_authenticate(tag.s, arg1.s, haveinitresp ? arg2.s : NULL);

		snmp_increment(AUTHENTICATE_COUNT, 1);
	    }
	    else if (!imapd_userid) goto nologin;
	    else if (!strcmp(cmd.s, "Append")) {
		if (c != ' ') goto missingargs;
		c = getastring(imapd_in, imapd_out, &arg1);
		if (c != ' ') goto missingargs;

		cmd_append(tag.s, arg1.s, NULL);

		snmp_increment(APPEND_COUNT, 1);
	    }
	    else goto badcmd;
	    break;

	case 'B':
	    if (!strcmp(cmd.s, "Bboard")) {
		if (c != ' ') goto missingargs;
		c = getastring(imapd_in, imapd_out, &arg1);
		if (c == EOF) goto missingargs;
		prot_ungetc(c, imapd_in);

		cmd_select(tag.s, cmd.s, arg1.s);

		snmp_increment(BBOARD_COUNT, 1);
	    }
	    else goto badcmd;
	    break;

	case 'C':
	    if (!strcmp(cmd.s, "Capability")) {
		if (c == '\r') c = prot_getc(imapd_in);
		if (c != '\n') goto extraargs;
		cmd_capability(tag.s);

		snmp_increment(CAPABILITY_COUNT, 1);
	    }
	    else if (!imapd_userid) goto nologin;
	    else if (!strcmp(cmd.s, "Check")) {
		if (!imapd_mailbox && !backend_current) goto nomailbox;
		if (c == '\r') c = prot_getc(imapd_in);
		if (c != '\n') goto extraargs;

		cmd_noop(tag.s, cmd.s);

		snmp_increment(CHECK_COUNT, 1);
	    }
	    else if (!strcmp(cmd.s, "Copy")) {
		if (!imapd_mailbox && !backend_current) goto nomailbox;
		usinguid = 0;
		if (c != ' ') goto missingargs;
	    copy:
		c = getword(imapd_in, &arg1);
		if (c == '\r') goto missingargs;
		if (c != ' ' || !imparse_issequence(arg1.s)) goto badsequence;
		c = getastring(imapd_in, imapd_out, &arg2);
		if (c == EOF) goto missingargs;
		if (c == '\r') c = prot_getc(imapd_in);
		if (c != '\n') goto extraargs;

		cmd_copy(tag.s, arg1.s, arg2.s, usinguid);

		snmp_increment(COPY_COUNT, 1);
	    }
	    else if (!strcmp(cmd.s, "Create")) {
		havepartition = 0;
		if (c != ' ') goto missingargs;
		c = getastring(imapd_in, imapd_out, &arg1);
		if (c == EOF) goto missingargs;
		if (c == ' ') {
		    havepartition = 1;
		    c = getword(imapd_in, &arg2);
		    if (!imparse_isatom(arg2.s)) goto badpartition;
		}
		if (c == '\r') c = prot_getc(imapd_in);
		if (c != '\n') goto extraargs;
		cmd_create(tag.s, arg1.s, havepartition ? arg2.s : 0, 0);

		snmp_increment(CREATE_COUNT, 1);
	    }
	    else if (!strcmp(cmd.s, "Close")) {
		if (!imapd_mailbox && !backend_current) goto nomailbox;
		if (c == '\r') c = prot_getc(imapd_in);
		if (c != '\n') goto extraargs;

		cmd_close(tag.s);

		snmp_increment(CLOSE_COUNT, 1);
	    }
	    else goto badcmd;
	    break;

	case 'D':
	    if (!strcmp(cmd.s, "Delete")) {
		if (c != ' ') goto missingargs;
		c = getastring(imapd_in, imapd_out, &arg1);
		if (c == EOF) goto missingargs;
		if (c == '\r') c = prot_getc(imapd_in);
		if (c != '\n') goto extraargs;
		cmd_delete(tag.s, arg1.s, 0, 0);

		snmp_increment(DELETE_COUNT, 1);
	    }
	    else if (!strcmp(cmd.s, "Deleteacl")) {
		if (c != ' ') goto missingargs;
		c = getastring(imapd_in, imapd_out, &arg1);
		if (c != ' ') goto missingargs;
		c = getastring(imapd_in, imapd_out, &arg2);
		if (c == EOF) goto missingargs;
		if (c == '\r') c = prot_getc(imapd_in);
		if (c != '\n') goto extraargs;
		cmd_setacl(tag.s, arg1.s, arg2.s, NULL);

		snmp_increment(DELETEACL_COUNT, 1);
	    }
	    else if (!strcmp(cmd.s, "Dump")) {
		int uid_start = 0;
		
		if(c != ' ') goto missingargs;
		c = getastring(imapd_in, imapd_out, &arg1);
		if(c == ' ') {
		    c = getastring(imapd_in, imapd_out, &arg2);
		    if(!imparse_isnumber(arg2.s)) goto extraargs;
		    uid_start = atoi(arg2.s);
		}
		
		if(c == '\r') c = prot_getc(imapd_in);
		if(c != '\n') goto extraargs;
		
		cmd_dump(tag.s, arg1.s, uid_start);
	    /*	snmp_increment(DUMP_COUNT, 1);*/
	    }
	    else goto badcmd;
	    break;

	case 'E':
	    if (!strcmp(cmd.s, "Expunge")) {
		if (!imapd_mailbox && !backend_current) goto nomailbox;
		if (c == '\r') c = prot_getc(imapd_in);
		if (c != '\n') goto extraargs;

		cmd_expunge(tag.s, 0);

		snmp_increment(EXPUNGE_COUNT, 1);
	    }
	    else if (!strcmp(cmd.s, "Examine")) {
		if (c != ' ') goto missingargs;
		c = getastring(imapd_in, imapd_out, &arg1);
		if (c == EOF) goto missingargs;
		prot_ungetc(c, imapd_in);

		cmd_select(tag.s, cmd.s, arg1.s);

		snmp_increment(EXAMINE_COUNT, 1);
	    }
	    else goto badcmd;
	    break;

	case 'F':
	    if (!strcmp(cmd.s, "Fetch")) {
		if (!imapd_mailbox && !backend_current) goto nomailbox;
		usinguid = 0;
		if (c != ' ') goto missingargs;
	    fetch:
		c = getword(imapd_in, &arg1);
		if (c == '\r') goto missingargs;
		if (c != ' ' || !imparse_issequence(arg1.s)) goto badsequence;

		cmd_fetch(tag.s, arg1.s, usinguid);

		snmp_increment(FETCH_COUNT, 1);
	    }
	    else if (!strcmp(cmd.s, "Find")) {
		c = getword(imapd_in, &arg1);
		if (c != ' ') goto missingargs;
		c = getastring(imapd_in, imapd_out, &arg2);
		if (c == EOF) goto missingargs;
		if (c == '\r') c = prot_getc(imapd_in);
		if (c != '\n') goto extraargs;
		cmd_find(tag.s, arg1.s, arg2.s);

		snmp_increment(FIND_COUNT, 1);
	    }
	    else goto badcmd;
	    break;

	case 'G':
	    if (!strcmp(cmd.s, "Getacl")) {
		if (c != ' ') goto missingargs;
		c = getastring(imapd_in, imapd_out, &arg1);
		if (c == EOF) goto missingargs;
		if (c == '\r') c = prot_getc(imapd_in);
		if (c != '\n') goto extraargs;
		cmd_getacl(tag.s, arg1.s);

		snmp_increment(GETACL_COUNT, 1);
	    }
	    else if (!strcmp(cmd.s, "Getannotation")) {
		if (c != ' ') goto missingargs;
		c = getastring(imapd_in, imapd_out, &arg1);
		if (c != ' ') goto missingargs;

		cmd_getannotation(tag.s, arg1.s);

		snmp_increment(GETANNOTATION_COUNT, 1);
	    }
	    else if (!strcmp(cmd.s, "Getquota")) {
		if (c != ' ') goto missingargs;
		c = getastring(imapd_in, imapd_out, &arg1);
		if (c == EOF) goto missingargs;
		if (c == '\r') c = prot_getc(imapd_in);
		if (c != '\n') goto extraargs;
		cmd_getquota(tag.s, arg1.s);

		snmp_increment(GETQUOTA_COUNT, 1);
	    }
	    else if (!strcmp(cmd.s, "Getquotaroot")) {
		if (c != ' ') goto missingargs;
		c = getastring(imapd_in, imapd_out, &arg1);
		if (c == EOF) goto missingargs;
		if (c == '\r') c = prot_getc(imapd_in);
		if (c != '\n') goto extraargs;
		cmd_getquotaroot(tag.s, arg1.s);

		snmp_increment(GETQUOTAROOT_COUNT, 1);
	    }
#ifdef HAVE_SSL
	    else if (!strcmp(cmd.s, "Genurlauth")) {
		if (c != ' ') goto missingargs;
		
		cmd_genurlauth(tag.s);
	    /*	snmp_increment(GENURLAUTH_COUNT, 1);*/
	    }
#endif
	    else goto badcmd;
	    break;

	case 'I':
	    if (!strcmp(cmd.s, "Id")) {
		if (c != ' ') goto missingargs;
		cmd_id(tag.s);

		snmp_increment(ID_COUNT, 1);
	    }
	    else if (!imapd_userid) goto nologin;
	    else if (!strcmp(cmd.s, "Idle") && idle_enabled()) {
		if (c == '\r') c = prot_getc(imapd_in);
		if (c != '\n') goto extraargs;
		cmd_idle(tag.s);

		snmp_increment(IDLE_COUNT, 1);
	    }
	    else goto badcmd;
	    break;

	case 'L':
	    if (!strcmp(cmd.s, "Login")) {
		if (c != ' ') goto missingargs;
		c = getastring(imapd_in, imapd_out, &arg1);
		if(c != ' ') goto missingargs;

		cmd_login(tag.s, arg1.s);

		snmp_increment(LOGIN_COUNT, 1);
	    }
	    else if (!strcmp(cmd.s, "Logout")) {
		if (c == '\r') c = prot_getc(imapd_in);
		if (c != '\n') goto extraargs;

		snmp_increment(LOGOUT_COUNT, 1);		

		/* force any responses from our selected backend */
		if (backend_current) imapd_check(NULL, 0, 0);

		prot_printf(imapd_out, "* BYE %s\r\n", 
			    error_message(IMAP_BYE_LOGOUT));
		prot_printf(imapd_out, "%s OK %s\r\n", tag.s, 
			    error_message(IMAP_OK_COMPLETED));
		return;
	    }
	    else if (!imapd_userid) goto nologin;
	    else if (!strcmp(cmd.s, "List")) {
		struct listargs listargs;

		memset(&listargs, 0, sizeof(struct listargs));
		listargs.opts = LIST_CHILDREN;
#ifdef ENABLE_LISTEXT
		/* Check for and parse LISTEXT options */
		c = prot_getc(imapd_in);
		if (c == '(') {
		    c = getlistopts(tag.s, &listargs.opts);
		    if (c == EOF) {
			eatline(imapd_in, c);
			continue;
		    }
		}
		else
		    prot_ungetc(c, imapd_in);
#endif /* ENABLE_LISTEXT */
		if (imapd_magicplus) listargs.opts += LIST_SUBSCRIBED;

		c = getastring(imapd_in, imapd_out, &arg1);
		if (c != ' ') goto missingargs;
		c = getastring(imapd_in, imapd_out, &arg2);
		if (c == '\r') c = prot_getc(imapd_in);
		if (c != '\n') goto extraargs;

		listargs.ref = arg1.s;
		listargs.pat = arg2.s;
		cmd_list(tag.s, &listargs);

		snmp_increment(LIST_COUNT, 1);
	    }
	    else if (!strcmp(cmd.s, "Lsub")) {
		struct listargs listargs;

		c = getastring(imapd_in, imapd_out, &arg1);
		if (c != ' ') goto missingargs;
		c = getastring(imapd_in, imapd_out, &arg2);
		if (c == '\r') c = prot_getc(imapd_in);
		if (c != '\n') goto extraargs;

		memset(&listargs, 0, sizeof(struct listargs));
		listargs.opts = LIST_LSUB | LIST_CHILDREN;
		listargs.ref = arg1.s;
		listargs.pat = arg2.s;
		cmd_list(tag.s, &listargs);

		snmp_increment(LSUB_COUNT, 1);
	    }
	    else if (!strcmp(cmd.s, "Listrights")) {
		c = getastring(imapd_in, imapd_out, &arg1);
		if (c != ' ') goto missingargs;
		c = getastring(imapd_in, imapd_out, &arg2);
		if (c == '\r') c = prot_getc(imapd_in);
		if (c != '\n') goto extraargs;
		cmd_listrights(tag.s, arg1.s, arg2.s);

		snmp_increment(LISTRIGHTS_COUNT, 1);
	    }
	    else if (!strcmp(cmd.s, "Localappend")) {
		/* create a local-only mailbox */
		if (c != ' ') goto missingargs;
		c = getastring(imapd_in, imapd_out, &arg1);
		if (c != ' ') goto missingargs;
		c = getastring(imapd_in, imapd_out, &arg2);
		if (c != ' ') goto missingargs;

		cmd_append(tag.s, arg1.s, *arg2.s ? arg2.s : NULL);

		snmp_increment(APPEND_COUNT, 1);
	    }
	    else if (!strcmp(cmd.s, "Localcreate")) {
		/* create a local-only mailbox */
		havepartition = 0;
		if (c != ' ') goto missingargs;
		c = getastring(imapd_in, imapd_out, &arg1);
		if (c == EOF) goto missingargs;
		if (c == ' ') {
		    havepartition = 1;
		    c = getword(imapd_in, &arg2);
		    if (!imparse_isatom(arg2.s)) goto badpartition;
		}
		if (c == '\r') c = prot_getc(imapd_in);
		if (c != '\n') goto extraargs;
		cmd_create(tag.s, arg1.s, havepartition ? arg2.s : NULL, 1);

		/* xxxx snmp_increment(CREATE_COUNT, 1); */
	    }
	    else if (!strcmp(cmd.s, "Localdelete")) {
		/* delete a mailbox locally only */
		if (c != ' ') goto missingargs;
		c = getastring(imapd_in, imapd_out, &arg1);
		if (c == EOF) goto missingargs;
		if (c == '\r') c = prot_getc(imapd_in);
		if (c != '\n') goto extraargs;
		cmd_delete(tag.s, arg1.s, 1, 1);

		/* xxxx snmp_increment(DELETE_COUNT, 1); */
	    }
	    else goto badcmd;
	    break;

	case 'M':
	    if (!strcmp(cmd.s, "Myrights")) {
		if (c != ' ') goto missingargs;
		c = getastring(imapd_in, imapd_out, &arg1);
		if (c == EOF) goto missingargs;
		if (c == '\r') c = prot_getc(imapd_in);
		if (c != '\n') goto extraargs;
		cmd_myrights(tag.s, arg1.s);

		/* xxxx snmp_increment(MYRIGHTS_COUNT, 1); */
	    }
	    else if (!strcmp(cmd.s, "Mupdatepush")) {
		if (c != ' ') goto missingargs;
		c = getastring(imapd_in, imapd_out, &arg1);
		if(c == EOF) goto missingargs;
		if(c == '\r') c = prot_getc(imapd_in);
		if(c != '\n') goto extraargs;
		cmd_mupdatepush(tag.s, arg1.s);
		
		/* xxxx snmp_increment(MUPDATEPUSH_COUNT, 1); */
	    } else goto badcmd;
	    break;

	case 'N':
	    if (!strcmp(cmd.s, "Noop")) {
		if (c == '\r') c = prot_getc(imapd_in);
		if (c != '\n') goto extraargs;

		cmd_noop(tag.s, cmd.s);

		/* xxxx snmp_increment(NOOP_COUNT, 1); */
	    }
#ifdef ENABLE_X_NETSCAPE_HACK
	    else if (!strcmp(cmd.s, "Netscape")) {
		if (c == '\r') c = prot_getc(imapd_in);
		if (c != '\n') goto extraargs;
		cmd_netscrape(tag.s);
	    }
#endif
	    else if (!imapd_userid) goto nologin;
	    else if (!strcmp(cmd.s, "Namespace")) {
		if (c == '\r') c = prot_getc(imapd_in);
		if (c != '\n') goto extraargs;
		cmd_namespace(tag.s);

		/* xxxx snmp_increment(NAMESPACE_COUNT, 1); */
	    }
	    else goto badcmd;
	    break;

	case 'P':
	    if (!strcmp(cmd.s, "Partial")) {
		if (!imapd_mailbox && !backend_current) goto nomailbox;
		if (c != ' ') goto missingargs;
		c = getword(imapd_in, &arg1);
		if (c != ' ') goto missingargs;
		c = getword(imapd_in, &arg2);
		if (c != ' ') goto missingargs;
		c = getword(imapd_in, &arg3);
		if (c != ' ') goto missingargs;
		c = getword(imapd_in, &arg4);
		if (c == '\r') c = prot_getc(imapd_in);
		if (c != '\n') goto extraargs;

		cmd_partial(tag.s, arg1.s, arg2.s, arg3.s, arg4.s);

		/* xxxx snmp_increment(PARTIAL_COUNT, 1); */
	    }
	    else goto badcmd;
	    break;

	case 'R':
	    if (!strcmp(cmd.s, "Rename")) {
		havepartition = 0;
		if (c != ' ') goto missingargs;
		c = getastring(imapd_in, imapd_out, &arg1);
		if (c != ' ') goto missingargs;
		c = getastring(imapd_in, imapd_out, &arg2);
		if (c == EOF) goto missingargs;
		if (c == ' ') {
		    havepartition = 1;
		    c = getword(imapd_in, &arg3);
		    if (!imparse_isatom(arg3.s)) goto badpartition;
		}
		if (c == '\r') c = prot_getc(imapd_in);
		if (c != '\n') goto extraargs;
		cmd_rename(tag.s, arg1.s, arg2.s, havepartition ? arg3.s : 0);

		/* xxxx snmp_increment(RENAME_COUNT, 1); */
	    } else if(!strcmp(cmd.s, "Reconstruct")) {
		recursive = 0;
		if (c != ' ') goto missingargs;
		c = getastring(imapd_in, imapd_out, &arg1);
		if(c == ' ') {
		    /* Optional RECURSEIVE argument */
		    c = getword(imapd_in, &arg2);
		    if(!imparse_isatom(arg2.s))
			goto extraargs;
		    else if(!strcasecmp(arg2.s, "RECURSIVE"))
			recursive = 1;
		    else
			goto extraargs;
		}
		if(c == '\r') c = prot_getc(imapd_in);
		if(c != '\n') goto extraargs;
		cmd_reconstruct(tag.s, arg1.s, recursive);

		/* snmp_increment(RECONSTRUCT_COUNT, 1); */
	    } 
	    else if (!strcmp(cmd.s, "Rlist")) {
		struct listargs listargs;

		c = getastring(imapd_in, imapd_out, &arg1);
		if (c != ' ') goto missingargs;
		c = getastring(imapd_in, imapd_out, &arg2);
		if (c == '\r') c = prot_getc(imapd_in);
		if (c != '\n') goto extraargs;

		memset(&listargs, 0, sizeof(struct listargs));
		listargs.opts = LIST_CHILDREN | LIST_REMOTE;
		listargs.ref = arg1.s;
		listargs.pat = arg2.s;
		cmd_list(tag.s, &listargs);

/* 		snmp_increment(LIST_COUNT, 1); */
	    }
	    else if (!strcmp(cmd.s, "Rlsub")) {
		struct listargs listargs;

		c = getastring(imapd_in, imapd_out, &arg1);
		if (c != ' ') goto missingargs;
		c = getastring(imapd_in, imapd_out, &arg2);
		if (c == '\r') c = prot_getc(imapd_in);
		if (c != '\n') goto extraargs;

		memset(&listargs, 0, sizeof(struct listargs));
		listargs.opts = LIST_LSUB | LIST_CHILDREN | LIST_REMOTE;
		listargs.ref = arg1.s;
		listargs.pat = arg2.s;
		cmd_list(tag.s, &listargs);

/* 		snmp_increment(LSUB_COUNT, 1); */
	    }
#ifdef HAVE_SSL
	    else if (!strcmp(cmd.s, "Resetkey")) {
		int have_mbox = 0, have_mech = 0;

		if (c == ' ') {
		    have_mbox = 1;
		    c = getastring(imapd_in, imapd_out, &arg1);
		    if (c == EOF) goto missingargs;
		    if (c == ' ') {
			have_mech = 1;
			c = getword(imapd_in, &arg2);
		    }
		}
		
		if (c == '\r') c = prot_getc(imapd_in);
		if (c != '\n') goto extraargs;
		cmd_resetkey(tag.s, have_mbox ? arg1.s : 0,
			     have_mech ? arg2.s : 0);
	    /*	snmp_increment(RESETKEY_COUNT, 1);*/
	    }
#endif
	    else goto badcmd;
	    break;
	    
	case 'S':
	    if (!strcmp(cmd.s, "Starttls")) {
		if (!tls_enabled()) {
		    /* we don't support starttls */
		    goto badcmd;
		}

		if (c == '\r') c = prot_getc(imapd_in);
		if (c != '\n') goto extraargs;

		/* if we've already done SASL fail */
		if (imapd_userid != NULL) {
		    prot_printf(imapd_out, 
	       "%s BAD Can't Starttls after authentication\r\n", tag.s);
		    continue;
		}
		
		/* check if already did a successful tls */
		if (imapd_starttls_done == 1) {
		    prot_printf(imapd_out, 
				"%s BAD Already did a successful Starttls\r\n",
				tag.s);
		    continue;
		}
		cmd_starttls(tag.s, 0);	

		snmp_increment(STARTTLS_COUNT, 1);      
		continue;
	    }
	    if (!imapd_userid) {
		goto nologin;
	    } else if (!strcmp(cmd.s, "Store")) {
		if (!imapd_mailbox && !backend_current) goto nomailbox;
		usinguid = 0;
		if (c != ' ') goto missingargs;
	    store:
		c = getword(imapd_in, &arg1);
		if (c != ' ' || !imparse_issequence(arg1.s)) goto badsequence;

		cmd_store(tag.s, arg1.s, usinguid);

		snmp_increment(STORE_COUNT, 1);
	    }
	    else if (!strcmp(cmd.s, "Select")) {
		if (c != ' ') goto missingargs;
		c = getastring(imapd_in, imapd_out, &arg1);
		if (c == EOF) goto missingargs;
		prot_ungetc(c, imapd_in);

		cmd_select(tag.s, cmd.s, arg1.s);

		snmp_increment(SELECT_COUNT, 1);
	    }
	    else if (!strcmp(cmd.s, "Search")) {
		if (!imapd_mailbox && !backend_current) goto nomailbox;
		usinguid = 0;
		if (c != ' ') goto missingargs;
	    search:

		cmd_search(tag.s, usinguid);

		snmp_increment(SEARCH_COUNT, 1);
	    }
	    else if (!strcmp(cmd.s, "Subscribe")) {
		if (c != ' ') goto missingargs;
		havenamespace = 0;
		c = getastring(imapd_in, imapd_out, &arg1);
		if (c == ' ') {
		    havenamespace = 1;
		    c = getastring(imapd_in, imapd_out, &arg2);
		}
		if (c == EOF) goto missingargs;
		if (c == '\r') c = prot_getc(imapd_in);
		if (c != '\n') goto extraargs;
		if (havenamespace) {
		    cmd_changesub(tag.s, arg1.s, arg2.s, 1);
		}
		else {
		    cmd_changesub(tag.s, (char *)0, arg1.s, 1);
		}
		snmp_increment(SUBSCRIBE_COUNT, 1);
	    }		
	    else if (!strcmp(cmd.s, "Setacl")) {
		if (c != ' ') goto missingargs;
		c = getastring(imapd_in, imapd_out, &arg1);
		if (c != ' ') goto missingargs;
		c = getastring(imapd_in, imapd_out, &arg2);
		if (c != ' ') goto missingargs;
		c = getastring(imapd_in, imapd_out, &arg3);
		if (c == EOF) goto missingargs;
		if (c == '\r') c = prot_getc(imapd_in);
		if (c != '\n') goto extraargs;
		cmd_setacl(tag.s, arg1.s, arg2.s, arg3.s);

		snmp_increment(SETACL_COUNT, 1);
	    }
	    else if (!strcmp(cmd.s, "Setannotation")) {
		if (c != ' ') goto missingargs;
		c = getastring(imapd_in, imapd_out, &arg1);
		if (c != ' ') goto missingargs;

		cmd_setannotation(tag.s, arg1.s);

		snmp_increment(SETANNOTATION_COUNT, 1);
	    }
	    else if (!strcmp(cmd.s, "Setquota")) {
		if (c != ' ') goto missingargs;
		c = getastring(imapd_in, imapd_out, &arg1);
		if (c != ' ') goto missingargs;
		cmd_setquota(tag.s, arg1.s);

		snmp_increment(SETQUOTA_COUNT, 1);
	    }
	    else if (!strcmp(cmd.s, "Sort")) {
		if (!imapd_mailbox && !backend_current) goto nomailbox;
		usinguid = 0;
		if (c != ' ') goto missingargs;
	    sort:
		cmd_sort(tag.s, usinguid);

		snmp_increment(SORT_COUNT, 1);
	    }
	    else if (!strcmp(cmd.s, "Status")) {
		if (c != ' ') goto missingargs;
		c = getastring(imapd_in, imapd_out, &arg1);
		if (c != ' ') goto missingargs;
		cmd_status(tag.s, arg1.s);

		snmp_increment(STATUS_COUNT, 1);
	    }
	    else if (!strcmp(cmd.s, "Scan")) {
		struct listargs listargs;

		c = getastring(imapd_in, imapd_out, &arg1);
		if (c != ' ') goto missingargs;
		c = getastring(imapd_in, imapd_out, &arg2);
		if (c != ' ') goto missingargs;
		c = getastring(imapd_in, imapd_out, &arg3);
		if (c == '\r') c = prot_getc(imapd_in);
		if (c != '\n') goto extraargs;

		memset(&listargs, 0, sizeof(struct listargs));
		listargs.ref = arg1.s;
		listargs.pat = arg2.s;
		listargs.scan = arg3.s;
		cmd_list(tag.s, &listargs);

		snmp_increment(SCAN_COUNT, 1);
	    }
	    else goto badcmd;
	    break;

	case 'T':
	    if (!strcmp(cmd.s, "Thread")) {
		if (!imapd_mailbox && !backend_current) goto nomailbox;
		usinguid = 0;
		if (c != ' ') goto missingargs;
	    thread:
		cmd_thread(tag.s, usinguid);

		snmp_increment(THREAD_COUNT, 1);
	    }
	    else goto badcmd;
	    break;

	case 'U':
	    if (!strcmp(cmd.s, "Uid")) {
		if (!imapd_mailbox && !backend_current) goto nomailbox;
		usinguid = 1;
		if (c != ' ') goto missingargs;
		c = getword(imapd_in, &arg1);
		if (c != ' ') goto missingargs;
		lcase(arg1.s);
		if (!strcmp(arg1.s, "fetch")) {
		    goto fetch;
		}
		else if (!strcmp(arg1.s, "store")) {
		    goto store;
		}
		else if (!strcmp(arg1.s, "search")) {
		    goto search;
		}
		else if (!strcmp(arg1.s, "sort")) {
		    goto sort;
		}
		else if (!strcmp(arg1.s, "thread")) {
		    goto thread;
		}
		else if (!strcmp(arg1.s, "copy")) {
		    goto copy;
		}
		else if (!strcmp(arg1.s, "expunge")) {
		    c = getword(imapd_in, &arg1);
		    if (!imparse_issequence(arg1.s)) goto badsequence;
		    if (c == '\r') c = prot_getc(imapd_in);
		    if (c != '\n') goto extraargs;
		    cmd_expunge(tag.s, arg1.s);

		    snmp_increment(EXPUNGE_COUNT, 1);
		}
		else {
		    prot_printf(imapd_out, "%s BAD Unrecognized UID subcommand\r\n", tag.s);
		    eatline(imapd_in, c);
		}
	    }
	    else if (!strcmp(cmd.s, "Unsubscribe")) {
		if (c != ' ') goto missingargs;
		havenamespace = 0;
		c = getastring(imapd_in, imapd_out, &arg1);
		if (c == ' ') {
		    havenamespace = 1;
		    c = getastring(imapd_in, imapd_out, &arg2);
		}
		if (c == EOF) goto missingargs;
		if (c == '\r') c = prot_getc(imapd_in);
		if (c != '\n') goto extraargs;
		if (havenamespace) {
		    cmd_changesub(tag.s, arg1.s, arg2.s, 0);
		}
		else {
		    cmd_changesub(tag.s, (char *)0, arg1.s, 0);
		}

		snmp_increment(UNSUBSCRIBE_COUNT, 1);
	    }		
	    else if (!strcmp(cmd.s, "Unselect")) {
		if (!imapd_mailbox && !backend_current) goto nomailbox;
		if (c == '\r') c = prot_getc(imapd_in);
		if (c != '\n') goto extraargs;
		cmd_unselect(tag.s);

		snmp_increment(UNSELECT_COUNT, 1);
	    }
	    else if (!strcmp(cmd.s, "Undump")) {
		if(c != ' ') goto missingargs;
		c = getastring(imapd_in, imapd_out, &arg1);

		/* we want to get a list at this point */
		if(c != ' ') goto missingargs;
		
		cmd_undump(tag.s, arg1.s);
	    /*	snmp_increment(UNDUMP_COUNT, 1);*/
	    }
#ifdef HAVE_SSL
	    else if (!strcmp(cmd.s, "Urlfetch")) {
		if (c != ' ') goto missingargs;
		
		cmd_urlfetch(tag.s);
	    /*	snmp_increment(URLFETCH_COUNT, 1);*/
	    }
#endif
	    else goto badcmd;
	    break;

	case 'X':
	    if (!strcmp(cmd.s, "Xfer")) {
		int havepartition = 0;
		
		/* Mailbox */
		if(c != ' ') goto missingargs;
		c = getastring(imapd_in, imapd_out, &arg1);

		/* Dest Server */
		if(c != ' ') goto missingargs;
		c = getastring(imapd_in, imapd_out, &arg2);

		if(c == ' ') {
		    /* Dest Partition */
		    c = getastring(imapd_in, imapd_out, &arg3);
		    if (!imparse_isatom(arg3.s)) goto badpartition;
		    havepartition = 1;
		}
		
		if (c == '\r') c = prot_getc(imapd_in);
		if (c != '\n') goto extraargs;

		cmd_xfer(tag.s, arg1.s, arg2.s,
			 (havepartition ? arg3.s : NULL));
	    /*	snmp_increment(XFER_COUNT, 1);*/
	    }
	    else goto badcmd;
	    break;

	default:
	badcmd:
	    prot_printf(imapd_out, "%s BAD Unrecognized command\r\n", tag.s);
	    eatline(imapd_in, c);
	}

	continue;

    nologin:
	prot_printf(imapd_out, "%s BAD Please login first\r\n", tag.s);
	eatline(imapd_in, c);
	continue;

    nomailbox:
	prot_printf(imapd_out, "%s BAD Please select a mailbox first\r\n", tag.s);
	eatline(imapd_in, c);
	continue;

    missingargs:
	prot_printf(imapd_out, "%s BAD Missing required argument to %s\r\n", tag.s, cmd.s);
	eatline(imapd_in, c);
	continue;

    extraargs:
	prot_printf(imapd_out, "%s BAD Unexpected extra arguments to %s\r\n", tag.s, cmd.s);
	eatline(imapd_in, c);
	continue;

    badsequence:
	prot_printf(imapd_out, "%s BAD Invalid sequence in %s\r\n", tag.s, cmd.s);
	eatline(imapd_in, c);
	continue;

    badpartition:
	prot_printf(imapd_out, "%s BAD Invalid partition name in %s\r\n",
	       tag.s, cmd.s);
	eatline(imapd_in, c);
	continue;
    }
}

/*
 * Perform a LOGIN command
 */
void cmd_login(char *tag, char *user)
{
    char userbuf[MAX_MAILBOX_NAME+1];
    unsigned userlen;
    const char *canon_user = userbuf;
    const void *val;
    char c;
    struct buf passwdbuf;
    char *passwd;
    const char *reply = NULL;
    int r;
    
    if (imapd_userid) {
	eatline(imapd_in, ' ');
	prot_printf(imapd_out, "%s BAD Already logged in\r\n", tag);
	return;
    }

    r = imapd_canon_user(imapd_saslconn, NULL, user, 0,
			 SASL_CU_AUTHID | SASL_CU_AUTHZID, NULL,
			 userbuf, sizeof(userbuf), &userlen);

    if (r) {
	eatline(imapd_in, ' ');
	syslog(LOG_NOTICE, "badlogin: %s plaintext %s invalid user",
	       imapd_clienthost, beautify_string(user));
	prot_printf(imapd_out, "%s NO %s\r\n", tag, 
		    error_message(IMAP_INVALID_USER));
	return;
    }

    /* possibly disallow login */
    if (!imapd_starttls_done && (extprops_ssf < 2) &&
	!config_getswitch(IMAPOPT_ALLOWPLAINTEXT) &&
	!is_userid_anonymous(canon_user)) {
	eatline(imapd_in, ' ');
	prot_printf(imapd_out, "%s NO Login only available under a layer\r\n",
		    tag);
	return;
    }

    memset(&passwdbuf,0,sizeof(struct buf));
    c = getastring(imapd_in, imapd_out, &passwdbuf);

    if(c == '\r') c = prot_getc(imapd_in);
    if (c != '\n') {
	freebuf(&passwdbuf);
	prot_printf(imapd_out,
		    "%s BAD Unexpected extra arguments to LOGIN\r\n",
		    tag);
	eatline(imapd_in, c);
	return;
    }

    passwd = passwdbuf.s;

    if (is_userid_anonymous(canon_user)) {
	if (config_getswitch(IMAPOPT_ALLOWANONYMOUSLOGIN)) {
	    passwd = beautify_string(passwd);
	    if (strlen(passwd) > 500) passwd[500] = '\0';
	    syslog(LOG_NOTICE, "login: %s anonymous %s",
		   imapd_clienthost, passwd);
	    reply = "Anonymous access granted";
	    imapd_userid = xstrdup("anonymous");
	}
	else {
	    syslog(LOG_NOTICE, "badlogin: %s anonymous login refused",
		   imapd_clienthost);
	    prot_printf(imapd_out, "%s NO %s\r\n", tag,
		   error_message(IMAP_ANONYMOUS_NOT_PERMITTED));
	    freebuf(&passwdbuf);
	    return;
	}
    }
    else if ((r = sasl_checkpass(imapd_saslconn,
				 canon_user,
				 strlen(canon_user),
				 passwd,
				 strlen(passwd))) != SASL_OK) {
	syslog(LOG_NOTICE, "badlogin: %s plaintext %s %s",
	       imapd_clienthost, canon_user, sasl_errdetail(imapd_saslconn));

	sleep(3);

	/* Don't allow user probing */
	if (r == SASL_NOUSER) r = SASL_BADAUTH;

	if ((reply = sasl_errstring(r, NULL, NULL)) != NULL) {
	    prot_printf(imapd_out, "%s NO Login failed: %s\r\n", tag, reply);
	} else {
	    prot_printf(imapd_out, "%s NO Login failed: %d\r\n", tag, r);
	}

	snmp_increment_args(AUTHENTICATION_NO, 1,
			    VARIABLE_AUTH, 0 /* hash_simple("LOGIN") */,
			    VARIABLE_LISTEND);
    	freebuf(&passwdbuf);
	return;
    }
    else {
	r = sasl_getprop(imapd_saslconn, SASL_USERNAME, &val);

	if(r != SASL_OK) {
	    if ((reply = sasl_errstring(r, NULL, NULL)) != NULL) {
		prot_printf(imapd_out, "%s NO Login failed: %s\r\n",
			    tag, reply);
	    } else {
		prot_printf(imapd_out, "%s NO Login failed: %d\r\n", tag, r);
	    }

	    snmp_increment_args(AUTHENTICATION_NO, 1,
				VARIABLE_AUTH, 0 /* hash_simple("LOGIN") */,
				VARIABLE_LISTEND);
	    freebuf(&passwdbuf);
	    return;
	}

	reply = "User logged in";
	imapd_userid = xstrdup((const char *) val);
	snmp_increment_args(AUTHENTICATION_YES, 1,
			    VARIABLE_AUTH, 0 /*hash_simple("LOGIN") */, 
			    VARIABLE_LISTEND);
	syslog(LOG_NOTICE, "login: %s %s%s plaintext%s %s", imapd_clienthost,
	       imapd_userid, imapd_magicplus ? imapd_magicplus : "",
	       imapd_starttls_done ? "+TLS" : "", 
	       reply ? reply : "");

	/* Apply penalty only if not under layer */
	if (!imapd_starttls_done) {
	    int plaintextloginpause = config_getint(IMAPOPT_PLAINTEXTLOGINPAUSE);
	    if (plaintextloginpause) {
		sleep(plaintextloginpause);
	    }

	    /* Fetch plaintext login nag message */
	    plaintextloginalert = config_getstring(IMAPOPT_PLAINTEXTLOGINALERT);
	}
    }
    
    /* authstate already created by mysasl_proxy_policy() */
    imapd_userisadmin = global_authisa(imapd_authstate, IMAPOPT_ADMINS);

    prot_printf(imapd_out, "%s OK [CAPABILITY ", tag);
    capa_response(CAPA_PREAUTH|CAPA_POSTAUTH);
    prot_printf(imapd_out, "] %s\r\n", reply);

    /* Create telemetry log */
    imapd_logfd = telemetry_log(imapd_userid, imapd_in, imapd_out, 0);

    /* Set namespace */
    if ((r = mboxname_init_namespace(&imapd_namespace,
				     imapd_userisadmin || imapd_userisproxyadmin)) != 0) {
	syslog(LOG_ERR, error_message(r));
	fatal(error_message(r), EC_CONFIG);
    }

    /* Make a copy of the external userid for use in proxying */
    proxy_userid = xstrdup(imapd_userid);

    /* Translate any separators in userid */
    mboxname_hiersep_tointernal(&imapd_namespace, imapd_userid,
				config_virtdomains ?
				strcspn(imapd_userid, "@") : 0);

    freebuf(&passwdbuf);
    return;
}

/*
 * Perform an AUTHENTICATE command
 */
void
cmd_authenticate(char *tag, char *authtype, char *resp)
{
    int sasl_result;

    const void *val;
    sasl_ssf_t ssf;
    char *ssfmsg=NULL;

    const char *canon_user;

    int r;

    r = saslserver(imapd_saslconn, authtype, resp, "", "+ ", "",
		   imapd_in, imapd_out, &sasl_result, NULL);

    if (r) {
	const char *errorstring = NULL;

	switch (r) {
	case IMAP_SASL_CANCEL:
	    prot_printf(imapd_out,
			"%s BAD Client canceled authentication\r\n", tag);
	    break;
	case IMAP_SASL_PROTERR:
	    errorstring = prot_error(imapd_in);

	    prot_printf(imapd_out,
			"%s NO Error reading client response: %s\r\n",
			tag, errorstring ? errorstring : "");
	    break;
	default: 
	    /* failed authentication */
	    syslog(LOG_NOTICE, "badlogin: %s %s [%s]",
		   imapd_clienthost, authtype, sasl_errdetail(imapd_saslconn));

	    snmp_increment_args(AUTHENTICATION_NO, 1,
				VARIABLE_AUTH, 0, /* hash_simple(authtype) */ 
				VARIABLE_LISTEND);
	    sleep(3);

	    /* Don't allow user probing */
	    if (sasl_result == SASL_NOUSER) sasl_result = SASL_BADAUTH;

	    errorstring = sasl_errstring(sasl_result, NULL, NULL);
	    if (errorstring) {
		prot_printf(imapd_out, "%s NO %s\r\n", tag, errorstring);
	    } else {
		prot_printf(imapd_out, "%s NO Error authenticating\r\n", tag);
	    }
	}

	reset_saslconn(&imapd_saslconn);
	return;
    }

    /* successful authentication */

    /* get the userid from SASL --- already canonicalized from
     * mysasl_proxy_policy()
     */
    sasl_result = sasl_getprop(imapd_saslconn, SASL_USERNAME, &val);
    if (sasl_result != SASL_OK) {
	prot_printf(imapd_out, "%s NO weird SASL error %d SASL_USERNAME\r\n", 
		    tag, sasl_result);
	syslog(LOG_ERR, "weird SASL error %d getting SASL_USERNAME", 
	       sasl_result);
	reset_saslconn(&imapd_saslconn);
	return;
    }
    canon_user = (const char *) val;

    /* If we're proxying, the authzid may contain a magic plus,
       so re-canonify it */
    if (config_getswitch(IMAPOPT_IMAPMAGICPLUS) && strchr(canon_user, '+')) {
	char userbuf[MAX_MAILBOX_NAME+1];
	unsigned userlen;

	sasl_result = imapd_canon_user(imapd_saslconn, NULL, canon_user, 0,
				       SASL_CU_AUTHID | SASL_CU_AUTHZID,
				       NULL, userbuf, sizeof(userbuf), &userlen);
	if (sasl_result != SASL_OK) {
	    prot_printf(imapd_out, 
			"%s NO SASL canonification error %d\r\n", 
			tag, sasl_result);
	    reset_saslconn(&imapd_saslconn);
	    return;
	}

	imapd_userid = xstrdup(userbuf);
    } else {
	imapd_userid = xstrdup(canon_user);
    }

    proc_register("imapd", imapd_clienthost, imapd_userid, (char *)0);

    syslog(LOG_NOTICE, "login: %s %s%s %s%s %s", imapd_clienthost,
	   imapd_userid, imapd_magicplus ? imapd_magicplus : "",
	   authtype, imapd_starttls_done ? "+TLS" : "", "User logged in");

    sasl_getprop(imapd_saslconn, SASL_SSF, &val);
    ssf = *((sasl_ssf_t *) val);

    /* really, we should be doing a sasl_getprop on SASL_SSF_EXTERNAL,
       but the current libsasl doesn't allow that. */
    if (imapd_starttls_done) {
	switch(ssf) {
	case 0: ssfmsg = "tls protection"; break;
	case 1: ssfmsg = "tls plus integrity protection"; break;
	default: ssfmsg = "tls plus privacy protection"; break;
	}
    } else {
	switch(ssf) {
	case 0: ssfmsg = "no protection"; break;
	case 1: ssfmsg = "integrity protection"; break;
	default: ssfmsg = "privacy protection"; break;
	}
    }

    snmp_increment_args(AUTHENTICATION_YES, 1,
			VARIABLE_AUTH, 0, /* hash_simple(authtype) */
			VARIABLE_LISTEND);

    if (!ssf) {
	prot_printf(imapd_out, "%s OK [CAPABILITY ", tag);
	capa_response(CAPA_PREAUTH|CAPA_POSTAUTH);
	prot_printf(imapd_out, "] Success (%s)\r\n", ssfmsg);
    } else {
	prot_printf(imapd_out, "%s OK Success (%s)\r\n", tag, ssfmsg);
    }

    prot_setsasl(imapd_in,  imapd_saslconn);
    prot_setsasl(imapd_out, imapd_saslconn);

    /* Create telemetry log */
    imapd_logfd = telemetry_log(imapd_userid, imapd_in, imapd_out, 0);

    /* Set namespace */
    if ((r = mboxname_init_namespace(&imapd_namespace,
				     imapd_userisadmin || imapd_userisproxyadmin)) != 0) {
	syslog(LOG_ERR, error_message(r));
	fatal(error_message(r), EC_CONFIG);
    }

    /* Make a copy of the external userid for use in proxying */
    proxy_userid = xstrdup(imapd_userid);

    /* Translate any separators in userid */
    mboxname_hiersep_tointernal(&imapd_namespace, imapd_userid,
				config_virtdomains ?
				strcspn(imapd_userid, "@") : 0);

    return;
}

/*
 * Perform a NOOP command
 */
void cmd_noop(char *tag, char *cmd)
{
    if (backend_current) {
	/* remote mailbox */
	prot_printf(backend_current->out, "%s %s\r\n", tag, cmd);
	pipe_including_tag(backend_current, tag, 0);

	return;
    }

    if (imapd_mailbox) {
	index_check(imapd_mailbox, 0, 1);
    }
    prot_printf(imapd_out, "%s OK %s\r\n", tag,
		error_message(IMAP_OK_COMPLETED));
}

/*
 * Parse and perform an ID command.
 *
 * the command has been parsed up to the parameter list.
 *
 * we only allow one ID in non-authenticated state from a given client.
 * we only allow MAXIDFAILED consecutive failed IDs from a given client.
 * we only record MAXIDLOG ID responses from a given client.
 */
void cmd_id(char *tag)
{
    static int did_id = 0;
    static int failed_id = 0;
    static int logged_id = 0;
    int error = 0;
    int c = EOF, npair = 0;
    static struct buf arg, field;
    struct attvaluelist *params = 0;

    /* check if we've already had an ID in non-authenticated state */
    if (!imapd_userid && did_id) {
	prot_printf(imapd_out,
		    "%s NO Only one Id allowed in non-authenticated state\r\n",
		    tag);
	eatline(imapd_in, c);
	return;
    }

    /* check if we've had too many failed IDs in a row */
    if (failed_id >= MAXIDFAILED) {
	prot_printf(imapd_out, "%s NO Too many (%u) invalid Id commands\r\n",
		    tag, failed_id);
	eatline(imapd_in, c);
	return;
    }

    /* ok, accept parameter list */
    c = getword(imapd_in, &arg);
    /* check for "NIL" or start of parameter list */
    if (strcasecmp(arg.s, "NIL") && c != '(') {
	prot_printf(imapd_out, "%s BAD Invalid parameter list in Id\r\n", tag);
	eatline(imapd_in, c);
	failed_id++;
	return;
    }

    /* parse parameter list */
    if (c == '(') {
	for (;;) {
	    if (c == ')') {
		/* end of string/value pairs */
		break;
	    }

	    /* get field name */
	    c = getstring(imapd_in, imapd_out, &field);
	    if (c != ' ') {
		prot_printf(imapd_out,
			    "%s BAD Invalid/missing field name in Id\r\n",
			    tag);
		error = 1;
		break;
	    }

	    /* get field value */
	    c = getnstring(imapd_in, imapd_out, &arg);
	    if (c != ' ' && c != ')') {
		prot_printf(imapd_out,
			    "%s BAD Invalid/missing value in Id\r\n",
			    tag);
		error = 1;
		break;
	    }

	    /* ok, we're anal, but we'll still process the ID command */
	    if (strlen(field.s) > MAXIDFIELDLEN) {
		prot_printf(imapd_out, 
			    "%s BAD field longer than %u octets in Id\r\n",
			    tag, MAXIDFIELDLEN);
		error = 1;
		break;
	    }
	    if (strlen(arg.s) > MAXIDVALUELEN) {
		prot_printf(imapd_out,
			    "%s BAD value longer than %u octets in Id\r\n",
			    tag, MAXIDVALUELEN);
		error = 1;
		break;
	    }
	    if (++npair > MAXIDPAIRS) {
		prot_printf(imapd_out,
			    "%s BAD too many (%u) field-value pairs in ID\r\n",
			    tag, MAXIDPAIRS);
		error = 1;
		break;
	    }
	    
	    /* ok, we're happy enough */
	    appendattvalue(&params, field.s, arg.s);
	}

	if (error || c != ')') {
	    /* erp! */
	    eatline(imapd_in, c);
	    freeattvalues(params);
	    failed_id++;
	    return;
	}
	c = prot_getc(imapd_in);
    }

    /* check for CRLF */
    if (c == '\r') c = prot_getc(imapd_in);
    if (c != '\n') {
	prot_printf(imapd_out,
		    "%s BAD Unexpected extra arguments to Id\r\n", tag);
	eatline(imapd_in, c);
	freeattvalues(params);
	failed_id++;
	return;
    }

    /* log the client's ID string.
       eventually this should be a callback or something. */
    if (npair && logged_id < MAXIDLOG) {
	char logbuf[MAXIDLOGLEN + 1] = "";
	struct attvaluelist *pptr;

	for (pptr = params; pptr; pptr = pptr->next) {
	    /* should we check for and format literals here ??? */
	    snprintf(logbuf + strlen(logbuf), MAXIDLOGLEN - strlen(logbuf),
		     " \"%s\" ", pptr->attrib);
	    if (!strcmp(pptr->value, "NIL"))
		snprintf(logbuf + strlen(logbuf), MAXIDLOGLEN - strlen(logbuf),
			 "NIL");
	    else
		snprintf(logbuf + strlen(logbuf), MAXIDLOGLEN - strlen(logbuf),
			"\"%s\"", pptr->value);
	}

	syslog(LOG_INFO, "client id:%s", logbuf);

	logged_id++;
    }

    freeattvalues(params);

    /* spit out our ID string.
       eventually this might be configurable. */
    if (config_getswitch(IMAPOPT_IMAPIDRESPONSE)) {
	id_response(imapd_out);
	prot_printf(imapd_out, ")\r\n");
    }
    else
	prot_printf(imapd_out, "* ID NIL\r\n");

    imapd_check(NULL, 0, 0);

    prot_printf(imapd_out, "%s OK %s\r\n", tag,
		error_message(IMAP_OK_COMPLETED));

    failed_id = 0;
    did_id = 1;
}

/*
 * Perform an IDLE command
 */
void cmd_idle(char *tag)
{
    int c = EOF;
    static struct buf arg;
    static int idle_period = -1;

    if (!backend_current) {  /* Local mailbox */
	/* Setup for doing mailbox updates */
	if (!idle_init(idle_update)) {
	    prot_printf(imapd_out, 
			"%s NO cannot start idling\r\n", tag);
	    return;
	}

	/* Tell client we are idling and waiting for end of command */
	prot_printf(imapd_out, "+ idling\r\n");
	prot_flush(imapd_out);

	/* Start doing mailbox updates */
	if (imapd_mailbox) index_check(imapd_mailbox, 0, 1);
	idle_start(imapd_mailbox ? imapd_mailbox->name : NULL);

	/* Get continuation data */
	c = getword(imapd_in, &arg);

	/* Stop updates and do any necessary cleanup */
	idle_done(imapd_mailbox ? imapd_mailbox->name : NULL);
    }
    else {  /* Remote mailbox */
	int done = 0, shutdown = 0;
	char buf[2048];

	/* get polling period */
	if (idle_period == -1) {
	    idle_period = config_getint(IMAPOPT_IMAPIDLEPOLL);
	}

	if (CAPA(backend_current, CAPA_IDLE)) {
	    /* Start IDLE on backend */
	    prot_printf(backend_current->out, "%s IDLE\r\n", tag);
	    if (!prot_fgets(buf, sizeof(buf), backend_current->in)) {

		/* If we received nothing from the backend, fail */
		prot_printf(imapd_out, "%s NO %s\r\n", tag, 
			    error_message(IMAP_SERVER_UNAVAILABLE));
		return;
	    }
	    if (buf[0] != '+') {
		/* If we received anything but a continuation response,
		   spit out what we received and quit */
		prot_write(imapd_out, buf, strlen(buf));
		return;
	    }
	}

	/* Tell client we are idling and waiting for end of command */
	prot_printf(imapd_out, "+ idling\r\n");
	prot_flush(imapd_out);

	/* Pipe updates to client while waiting for end of command */
	while (!done) {
	    /* Flush any buffered output */
	    prot_flush(imapd_out);

	    /* Check for shutdown file */
	    if (!imapd_userisadmin && shutdown_file(buf, sizeof(buf))) {
		shutdown = done = 1;
		goto done;
	    }

	    done = proxy_check_input(protin, imapd_in, imapd_out,
				     backend_current->in, NULL, idle_period);

	    /* If not running IDLE on backend, poll the mailbox for updates */
	    if (!CAPA(backend_current, CAPA_IDLE)) {
		imapd_check(NULL, 0, 1);
	    }
	}

	/* Get continuation data */
	c = getword(imapd_in, &arg);

      done:
	if (CAPA(backend_current, CAPA_IDLE)) {
	    /* Either the client timed out, or ended the command.
	       In either case we're done, so terminate IDLE on backend */
	    prot_printf(backend_current->out, "Done\r\n");
	    pipe_until_tag(backend_current, tag, 0);
	}

	if (shutdown) {
	    char *p;

	    for (p = buf; *p == '['; p++); /* can't have [ be first char */
	    prot_printf(imapd_out, "* BYE [ALERT] %s\r\n", p);
	    shut_down(0);
	}
    }

    imapd_check(NULL, 0, 1);

    if (c != EOF) {
	if (!strcasecmp(arg.s, "Done") &&
	    (c = (c == '\r') ? prot_getc(imapd_in) : c) == '\n') {
	    prot_printf(imapd_out, "%s OK %s\r\n", tag,
			error_message(IMAP_OK_COMPLETED));
	}
	else {
	    prot_printf(imapd_out, 
			"%s BAD Invalid Idle continuation\r\n", tag);
	    eatline(imapd_in, c);
	}
    }
}

/* Send unsolicited untagged responses to the client */
void idle_update(idle_flags_t flags)
{
    if ((flags & IDLE_MAILBOX) && imapd_mailbox)
	index_check(imapd_mailbox, 0, 1);

    if (flags & IDLE_ALERT) {
	char shut[1024];
	if (! imapd_userisadmin && shutdown_file(shut, sizeof(shut))) {
	    char *p;
	    for (p = shut; *p == '['; p++); /* can't have [ be first char */
	    prot_printf(imapd_out, "* BYE [ALERT] %s\r\n", p);
	    shut_down(0);
	}
    }

    prot_flush(imapd_out);
}

void capa_response(int flags)
{
    const char *sasllist; /* the list of SASL mechanisms */
    int mechcount;

    prot_printf(imapd_out, CAPA_PREAUTH_STRING);

    if(config_mupdate_server) {
	prot_printf(imapd_out, " MUPDATE=mupdate://%s/", config_mupdate_server);
    }

    if (tls_enabled() && !imapd_starttls_done && !imapd_authstate) {
	prot_printf(imapd_out, " STARTTLS");
    }
    if (imapd_authstate ||
	(!imapd_starttls_done && (extprops_ssf < 2) &&
	 !config_getswitch(IMAPOPT_ALLOWPLAINTEXT))) {
	prot_printf(imapd_out, " LOGINDISABLED");
    }

    /* add the SASL mechs */
    if (!imapd_authstate &&
	sasl_listmech(imapd_saslconn, NULL, 
		      "AUTH=", " AUTH=", " SASL-IR",
		      &sasllist,
		      NULL, &mechcount) == SASL_OK && mechcount > 0) {
	prot_printf(imapd_out, " %s", sasllist);      
    } else {
	/* else don't show anything */
    }

    if (!(flags & CAPA_POSTAUTH)) return;

    prot_printf(imapd_out, CAPA_POSTAUTH_STRING);

    if (idle_enabled()) {
	prot_printf(imapd_out, " IDLE");
    }

#ifdef ENABLE_LISTEXT
    prot_printf(imapd_out, " LISTEXT LIST-SUBSCRIBED");
#endif /* ENABLE_LISTEXT */

#ifdef ENABLE_X_NETSCAPE_HACK
    prot_printf(imapd_out, " X-NETSCAPE");
#endif

#ifdef HAVE_SSL
    prot_printf(imapd_out, " URLAUTH");
#endif
}

/*
 * Perform a CAPABILITY command
 */
void cmd_capability(char *tag)
{
    imapd_check(NULL, 0, 0);

    prot_printf(imapd_out, "* CAPABILITY ");

    capa_response(CAPA_PREAUTH|CAPA_POSTAUTH);

    prot_printf(imapd_out, "\r\n%s OK %s\r\n", tag,
		error_message(IMAP_OK_COMPLETED));
}

/*
 * Parse and perform an APPEND command.
 * The command has been parsed up to and including
 * the mailbox name.
 */
static int isokflag(char *s, int *isseen)
{
    if (s[0] == '\\') {
	lcase(s);
	if (!strcmp(s, "\\seen")) {
	    *isseen = 1;
	    return 1;
	}
	if (!strcmp(s, "\\answered")) return 1;
	if (!strcmp(s, "\\flagged")) return 1;
	if (!strcmp(s, "\\draft")) return 1;
	if (!strcmp(s, "\\deleted")) return 1;
	
	/* uh oh, system flag i don't recognize */
	return 0;
    } else {
	/* valid user flag? */
	return imparse_isatom(s);
    }
}

static int getliteralsize(char *p, int c,
			  unsigned *size, int *binary, const char **parseerr)

{
    int sawdigit = 0;
    int isnowait = 0;

    /* Check for literal8 */
    if (*p == '~') {
	p++;

	*binary = 1;
    }
    if (*p != '{') {
	*parseerr = "Missing required argument to Append command";
	return IMAP_PROTOCOL_ERROR;
    }
	
    /* Read size from literal */
    isnowait = 0;
    *size = 0;
    for (++p; *p && isdigit((int) *p); p++) {
	sawdigit++;
	if (*size > (UINT_MAX - (*p - '0')) / 10)
	    return IMAP_MESSAGE_TOO_LARGE;
	*size = (*size)*10 + *p - '0';
#if 0
	if (*size < 0) {
	    lose();
	}
#endif
    }
    if (*p == '+') {
	isnowait++;
	p++;
    }
	
    if (c == '\r') {
	c = prot_getc(imapd_in);
    }
    else {
	prot_ungetc(c, imapd_in);
	c = ' ';		/* Force a syntax error */
    }
	
    if (*p != '}' || p[1] || c != '\n' || !sawdigit) {
	*parseerr = "Invalid literal in Append command";
	return IMAP_PROTOCOL_ERROR;
    }

    if (!isnowait) {
	/* Tell client to send the message */
	prot_printf(imapd_out, "+ go ahead\r\n");
	prot_flush(imapd_out);
    }

    return 0;
}

static int catenate_text(FILE *f, unsigned *totalsize, int *binary,
			 const char **parseerr)
{
    int c;
    static struct buf arg;
    unsigned size = 0;
    char buf[4096+1];
    unsigned n;
    int r;

    c = getword(imapd_in, &arg);

    /* Read size from literal */
    r = getliteralsize(arg.s, c, &size, binary, parseerr);
    if (r) return r;

    if (*totalsize > UINT_MAX - size) r = IMAP_MESSAGE_TOO_LARGE;

    /* Catenate message part to stage */
    while (size) {
	n = prot_read(imapd_in, buf, size > 4096 ? 4096 : size);
	if (!n) {
	    syslog(LOG_ERR,
		   "IOERROR: reading message: unexpected end of file");
	    return IMAP_IOERROR;
	}

	buf[n] = '\0';
	if (!*binary && (n != strlen(buf))) r = IMAP_MESSAGE_CONTAINSNULL;

	size -= n;
	if (r) continue;

	/* XXX  do we want to try and validate the message like
	   we do in message_copy_strict()? */

	if (f) fwrite(buf, n, 1, f);
    }

    *totalsize += size;

    return r;
}

static int catenate_url(const char *s, const char *cur_name, FILE *f,
			unsigned *totalsize, const char **parseerr)
{
    struct imapurl url;
    char mailboxname[MAX_MAILBOX_NAME+1];
    struct mailbox mboxstruct, *mailbox;
    unsigned msgno;
    int r = 0, doclose = 0;
    unsigned long size = 0;

    r = imapurl_fromURL(&url, s);

    if (r) {
	*parseerr = "Improperly specified URL";
	r = IMAP_BADURL;
    } else if (url.server) {
	*parseerr = "Only relative URLs are supported";
	r = IMAP_BADURL;
#if 0
    } else if (url.server && strcmp(url.server, config_servername)) {
	*parseerr = "Can not catenate messages from another server";
	r = IMAP_BADURL;
#endif
    } else if (!url.mailbox && !imapd_mailbox && !cur_name) {
	*parseerr = "No mailbox is selected or specified";
	r = IMAP_BADURL;
    } else if (url.mailbox || (url.mailbox = cur_name)) {
	r = (*imapd_namespace.mboxname_tointernal)(&imapd_namespace,
						   url.mailbox,
						   imapd_userid, mailboxname);
	if (!r) {
	    if (!imapd_mailbox || strcmp(imapd_mailbox->name, mailboxname)) {
		/* not the currently selected mailbox, so try to open it */
		int mbtype;
		char *newserver;

		/* lookup the location of the mailbox */
		r = mlookup(NULL, NULL, mailboxname, &mbtype, NULL, NULL,
			    &newserver, NULL, NULL);

		if (!r && (mbtype & MBTYPE_REMOTE)) {
		    /* remote mailbox */
		    struct backend *be;

		    be = proxy_findserver(newserver, &imap_protocol,
					 proxy_userid, &backend_cached,
					 &backend_current, &backend_inbox, imapd_in);
		    if (!s) {
			r = IMAP_SERVER_UNAVAILABLE;
		    } else {
			r = proxy_catenate_url(be, &url, f, &size, parseerr);
			if (*totalsize > UINT_MAX - size)
			    r = IMAP_MESSAGE_TOO_LARGE;
			else
			    *totalsize += size;
		    }

		    free(url.freeme);

		    return r;
		}

		/* local mailbox */
		if (!r) {
		    r = mailbox_open_header(mailboxname, imapd_authstate,
					    &mboxstruct);
		}

		if (!r) {
		    doclose = 1;
		    r = mailbox_open_index(&mboxstruct);
		}

		if (!r && !(mboxstruct.myrights & ACL_READ)) {
		    r = (imapd_userisadmin || (mboxstruct.myrights & ACL_LOOKUP)) ?
			IMAP_PERMISSION_DENIED : IMAP_MAILBOX_NONEXISTENT;
		}

		if (!r) {
		    mailbox = &mboxstruct;
		    index_operatemailbox(mailbox);
		}
	    } else {
		mailbox = imapd_mailbox;
	    }
	}

	if (r) {
	    *parseerr = error_message(r);
	    r = IMAP_BADURL;
	}
    } else {
	mailbox = imapd_mailbox;
    }

    if (r) {
	/* nothing to do, handled up top */
    } else if (url.uidvalidity &&
	       (mailbox->uidvalidity != url.uidvalidity)) {
	*parseerr = "Uidvalidity of mailbox has changed";
	r = IMAP_BADURL;
    } else if (!url.uid || !(msgno = index_finduid(url.uid)) ||
	       (index_getuid(msgno) != url.uid)) {
	*parseerr = "No such message in mailbox";
	r = IMAP_BADURL;
    } else {
	/* Catenate message part to stage */
	struct protstream *s = prot_new(fileno(f), 1);

	r = index_urlfetch(mailbox, msgno, url.section,
			   url.start_octet, url.octet_count, s, &size);
	if (r == IMAP_BADURL)
	    *parseerr = "No such message part";
	else if (!r) {
	    if (*totalsize > UINT_MAX - size)
		r = IMAP_MESSAGE_TOO_LARGE;
	    else
		*totalsize += size;
	}

	prot_flush(s);
	prot_free(s);

	/* XXX  do we want to try and validate the message like
	   we do in message_copy_strict()? */
    }

    free(url.freeme);

    if (doclose) {
	mailbox_close(&mboxstruct);
	if (imapd_mailbox) index_operatemailbox(imapd_mailbox);
    }

    return r;
}

static int append_catenate(FILE *f, const char *cur_name, unsigned *totalsize,
			   int *binary, const char **parseerr, const char **url)
{
    int c, r = 0;
    static struct buf arg;

    do {
	c = getword(imapd_in, &arg);
	if (c != ' ') {
	    *parseerr = "Missing message part data in Append command";
	    return IMAP_PROTOCOL_ERROR;
	}

	if (!strcasecmp(arg.s, "TEXT")) {
	    int r1 = catenate_text(!r ? f : NULL, totalsize, binary, parseerr);
	    if (r1) return r1;

	    /* if we see a SP, we're trying to catenate more than one part */

	    /* Parse newline terminating command */
	    c = prot_getc(imapd_in);
	}
	else if (!strcasecmp(arg.s, "URL")) {
	    c = getastring(imapd_in, imapd_out, &arg);
	    if (c != ' ' && c != ')') {
		*parseerr = "Missing URL in Append command";
		return IMAP_PROTOCOL_ERROR;
	    }

	    if (!r) {
		r = catenate_url(arg.s, cur_name, f, totalsize, parseerr);
		if (r) *url = arg.s;
	    }
	}
	else {
	    *parseerr = "Invalid message part type in Append command";
	    return IMAP_PROTOCOL_ERROR;
	}

	fflush(f);
    } while (c == ' ');

    if (c != ')') {
	*parseerr = "Missing space or ) after catenate list in Append command";
	return IMAP_PROTOCOL_ERROR;
    }

    if (ferror(f) || fsync(fileno(f))) {
	syslog(LOG_ERR, "IOERROR: writing message: %m");
	return IMAP_IOERROR;
    }

    return r;
}

/* If an APPEND is proxied from another server,
 * 'cur_name' is the name of the currently selected mailbox (if any) 
 * in case we have to resolve relative URLs
 */
#define FLAGGROW 10
void cmd_append(char *tag, char *name, const char *cur_name)
{
    int c;
    static struct buf arg;
    time_t now = time(NULL);
    unsigned size, totalsize = 0;
    int sync_seen = 0;
    int r;
    unsigned i;
    char mailboxname[MAX_MAILBOX_NAME+1];
    struct appendstate mailbox;
    unsigned long uidvalidity;
    unsigned long firstuid, num;
    long doappenduid = 0;
    const char *parseerr = NULL, *url = NULL;
    int mbtype;
    char *newserver;
    unsigned numalloc = 5;
    struct appendstage *curstage;

    /* See if we can append */
    r = (*imapd_namespace.mboxname_tointernal)(&imapd_namespace, name,
					       imapd_userid, mailboxname);
    if (!r) {
	r = mlookup(tag, name, mailboxname, &mbtype, NULL, NULL,
		    &newserver, NULL, NULL);
    }

    if (!r && (mbtype & MBTYPE_REMOTE)) {
	/* remote mailbox */
	struct backend *s = NULL;

	if (supports_referrals) { 
	    imapd_refer(tag, newserver, name);
	    /* Eat the argument */
	    eatline(imapd_in, prot_getc(imapd_in));
	    return;
	}

	s = proxy_findserver(newserver, &imap_protocol,
			     proxy_userid, &backend_cached,
			     &backend_current, &backend_inbox, imapd_in);
	if (!s) r = IMAP_SERVER_UNAVAILABLE;

	imapd_check(s, 0, 0);

	if (!r) {
	    int is_active = 1;
	    s->context = (void*) &is_active;
	    if (imapd_mailbox) {
		prot_printf(s->out, "%s Localappend {%d+}\r\n%s {%d+}\r\n%s ",
			    tag, strlen(name), name,
			    strlen(imapd_mailbox->name), imapd_mailbox->name);
	    } else {
		prot_printf(s->out, "%s Localappend {%d+}\r\n%s {%d+}\r\n%s ",
			    tag, strlen(name), name, 0, "");
	    }
	    if (!(r = pipe_command(s, 16384))) {
		pipe_including_tag(s, tag, 0);
	    }
	    s->context = NULL;
	} else {
	    eatline(imapd_in, prot_getc(imapd_in));
	}

	if (r) {
	    prot_printf(imapd_out, "%s NO %s\r\n", tag,
			prot_error(imapd_in) ? prot_error(imapd_in) :
			error_message(r));
	}

	return;
    }

    /* local mailbox */
    if (!r) {
	r = append_check(mailboxname, MAILBOX_FORMAT_NORMAL,
			 imapd_authstate, ACL_INSERT, totalsize);
    }
    if (r) {
	eatline(imapd_in, ' ');
	prot_printf(imapd_out, "%s NO %s%s\r\n",
		    tag,
		    (r == IMAP_MAILBOX_NONEXISTENT &&
		     mboxlist_createmailboxcheck(mailboxname, 0, 0,
						 imapd_userisadmin,
						 imapd_userid, imapd_authstate,
						 NULL, NULL, 0) == 0)
		    ? "[TRYCREATE] " : "", error_message(r));
	return;
    }

    stage = xmalloc(numalloc * sizeof(struct appendstage *));

    c = ' '; /* just parsed a space */
    /* we loop, to support MULTIAPPEND */
    while (!r && c == ' ') {
	/* Grow the stage array, if necessary */
	if (numstage == numalloc) {
	    /* Avoid integer wrap as arg to xrealloc */
	    if (numalloc > INT_MAX/(2*sizeof(struct appendstage *)))
		goto done;
	    numalloc *= 2;
	    stage = xrealloc(stage, numalloc * sizeof(struct appendstage *));
	}
	curstage = stage[numstage] = xzmalloc(sizeof(struct appendstage));
	numstage++;
	/* Parse flags */
	c = getword(imapd_in, &arg);
	if  (c == '(' && !arg.s[0]) {
	    curstage->nflags = 0;
	    do {
		c = getword(imapd_in, &arg);
		if (!curstage->nflags && !arg.s[0] && c == ')') break; /* empty list */
		if (!isokflag(arg.s, &sync_seen)) {
		    parseerr = "Invalid flag in Append command";
		    r = IMAP_PROTOCOL_ERROR;
		    goto done;
		}
		if (curstage->nflags == curstage->flagalloc) {
		    curstage->flagalloc += FLAGGROW;
		    curstage->flag =
			(char **) xrealloc((char *) curstage->flag, 
					   curstage->flagalloc * sizeof(char *));
		}
		curstage->flag[curstage->nflags] = xstrdup(arg.s);
		curstage->nflags++;
	    } while (c == ' ');
	    if (c != ')') {
		parseerr = 
		    "Missing space or ) after flag name in Append command";
		r = IMAP_PROTOCOL_ERROR;
		goto done;
	    }
	    c = prot_getc(imapd_in);
	    if (c != ' ') {
		parseerr = "Missing space after flag list in Append command";
		r = IMAP_PROTOCOL_ERROR;
		goto done;
	    }
	    c = getword(imapd_in, &arg);
	}

	/* Parse internaldate */
	if (c == '\"' && !arg.s[0]) {
	    prot_ungetc(c, imapd_in);
	    c = getdatetime(&(curstage->internaldate));
	    if (c != ' ') {
		parseerr = "Invalid date-time in Append command";
		r = IMAP_PROTOCOL_ERROR;
		goto done;
	    }
	    c = getword(imapd_in, &arg);
	} else {
	    curstage->internaldate = now;
	}

	/* Stage the message */
	curstage->f = append_newstage(mailboxname, now, numstage, &(curstage->stage));
	if (!curstage->f) {
	    r = IMAP_IOERROR;
	    goto done;
	}

	if (!strcasecmp(arg.s, "CATENATE")) {
	    if (c != ' ' || (c = prot_getc(imapd_in) != '(')) {
		parseerr = "Missing message part(s) in Append command";
		r = IMAP_PROTOCOL_ERROR;
		goto done;
	    }

	    /* Catenate the message part(s) to stage */
	    size = 0;
	    r = append_catenate(curstage->f, cur_name, &size,
				&(curstage->binary), &parseerr, &url);
	    if (r) goto done;
	}
	else {
	    /* Read size from literal */
	    r = getliteralsize(arg.s, c, &size, &(curstage->binary), &parseerr);
	    if (r) goto done;

	    /* Copy message to stage */
	    r = message_copy_strict(imapd_in, curstage->f, size, curstage->binary);
	}
	totalsize += size;
	/* If this is a non-BINARY message, close the stage file.
	 * Otherwise, leave it open so we can encode the binary parts.
	 *
	 * XXX  For BINARY MULTIAPPEND, we may have to close the stage files
	 * anyways to avoid too many open files.
	 */
	if (!curstage->binary) {
	    fclose(curstage->f);
	    curstage->f = NULL;
	}

	/* if we see a SP, we're trying to append more than one message */

	/* Parse newline terminating command */
	c = prot_getc(imapd_in);
    }

 done:
    if (r) {
	eatline(imapd_in, c);
    } else {
	/* we should be looking at the end of the line */
	if (c == '\r') c = prot_getc(imapd_in);
	if (c != '\n') {
	    parseerr = "junk after literal";
	    r = IMAP_PROTOCOL_ERROR;
	    eatline(imapd_in, c);
	}
    }

    /* Append from the stage(s) */
    if (!r) {
	r = append_setup(&mailbox, mailboxname, MAILBOX_FORMAT_NORMAL,
			 imapd_userid, imapd_authstate, ACL_INSERT, totalsize);
    }
    if (!r) {
	struct body *body = NULL;

	doappenduid = (mailbox.m.myrights & ACL_READ);

	for (i = 0; !r && i < numstage; i++) {
	    if (stage[i]->binary) {
		r = message_parse_binary_file(stage[i]->f, &body);
		fclose(stage[i]->f);
		stage[i]->f = NULL;
	    }
	    if (!r) {
		r = append_fromstage(&mailbox, &body, stage[i]->stage,
				     stage[i]->internaldate, 
				     (const char **) stage[i]->flag,
				     stage[i]->nflags, 0);
	    }
	    if (body) message_free_body(body);
	}
	if (body) free(body);

	if (!r) {
	    int sharedseen = (mailbox.m.options & OPT_IMAP_SHAREDSEEN);

	    r = append_commit(&mailbox, totalsize, &uidvalidity, &firstuid, &num);
            if (!r) {
		sync_log_append(mailboxname);
		if (sync_seen) {
		    sync_log_seen(sharedseen ? "anyone" : imapd_userid,
				  mailboxname);
		}
	    }
	} else {
	    append_abort(&mailbox);
	}
    }

    /* Cleanup the stage(s) */
    while (numstage) {
	curstage = stage[--numstage];

	if (curstage->f != NULL) fclose(curstage->f);
	append_removestage(curstage->stage);
	while (curstage->nflags--) {
	    free(curstage->flag[curstage->nflags]);
	}
	if (curstage->flag) free((char *) curstage->flag);
	free(curstage);
    }
    if (stage) free(stage);
    stage = NULL;

    imapd_check(NULL, 0, 0);

    if (r == IMAP_PROTOCOL_ERROR && parseerr) {
	prot_printf(imapd_out, "%s BAD %s\r\n", tag, parseerr);
    } else if (r == IMAP_BADURL) {
	prot_printf(imapd_out, "%s NO [BADURL \"%s\"] %s\r\n",
		    tag, url, parseerr);
    } else if (r) {
	prot_printf(imapd_out, "%s NO %s%s\r\n",
		    tag,
		    (r == IMAP_MAILBOX_NONEXISTENT &&
		     mboxlist_createmailboxcheck(mailboxname, 0, 0,
						 imapd_userisadmin,
						 imapd_userid, imapd_authstate,
						 NULL, NULL, 0) == 0)
		    ? "[TRYCREATE] " : r == IMAP_MESSAGE_TOO_LARGE
		    ? "[TOOBIG]" : "", error_message(r));
    } else if (doappenduid) {
	/* is this a space seperated list or sequence list? */
	prot_printf(imapd_out, "%s OK [APPENDUID %lu", tag, uidvalidity);
	if (num == 1) {
	    prot_printf(imapd_out, " %lu", firstuid);
	} else {
	    prot_printf(imapd_out, " %lu:%lu", firstuid, firstuid + num - 1);
	}
	prot_printf(imapd_out, "] %s\r\n", error_message(IMAP_OK_COMPLETED));
    } else {
	prot_printf(imapd_out, "%s OK %s\r\n", tag,
		    error_message(IMAP_OK_COMPLETED));
    }
}

/*
 * Perform a SELECT/EXAMINE/BBOARD command
 */
void cmd_select(char *tag, char *cmd, char *name)
{
    int c;
    struct mailbox mailbox;
    char mailboxname[MAX_MAILBOX_NAME+1];
    int r = 0;
    double usage;
    int doclose = 0;
    int mbtype;
    char *newserver;
    struct backend *backend_next = NULL;
    static char lastqr[MAX_MAILBOX_PATH+1] = "";
    static time_t nextalert = 0;

    c = prot_getc(imapd_in);
    if (cmd[0] != 'B' && c == ' ') {
	static struct buf arg;

	c = prot_getc(imapd_in);
	if (c != '(') goto badlist;

	c = getword(imapd_in, &arg);
	if (arg.s[0] == '\0') goto badlist;
	for (;;) {
	    ucase(arg.s);
	    if (!strcmp(arg.s, "CONDSTORE")) {
		imapd_condstore_client = 1;
	    }
	    else {
		prot_printf(imapd_out, "%s BAD Invalid %s modifier %s\r\n",
			    tag, cmd, arg.s);
		eatline(imapd_in, c);
		return;
	    }
	    
	    if (c == ' ') c = getword(imapd_in, &arg);
	    else break;
	}

	if (c != ')') {
	    prot_printf(imapd_out,
			"%s BAD Missing close parenthesis in %s\r\n", tag, cmd);
	    eatline(imapd_in, c);
	    return;
	}

	c = prot_getc(imapd_in);
    }
    if (c == '\r') c = prot_getc(imapd_in);
    if (c != '\n') {
	prot_printf(imapd_out,
		    "%s BAD Unexpected extra arguments to %s\r\n", tag, cmd);
	eatline(imapd_in, c);
	return;
    }

    if (imapd_mailbox) {
	index_closemailbox(imapd_mailbox);
	mailbox_close(imapd_mailbox);
	imapd_mailbox = 0;
    }
    if (backend_current) {
	/* remove backend_current from the protgroup */
	protgroup_delete(protin, backend_current->in);
    }

    if (cmd[0] == 'B') {
	/* BBoard namespace is empty */
	r = IMAP_MAILBOX_NONEXISTENT;
    }
    else {
	r = (*imapd_namespace.mboxname_tointernal)(&imapd_namespace, name,
						   imapd_userid, mailboxname);
    }

    if (!r) {
	r = mlookup(tag, name, mailboxname, &mbtype, NULL, NULL,
		    &newserver, NULL, NULL);
    }
    if (r == IMAP_MAILBOX_MOVED) return;

    if (!r && (mbtype & MBTYPE_REMOTE)) {
	if (supports_referrals) {
	    imapd_refer(tag, newserver, name);
	    return;
	}

	backend_next = proxy_findserver(newserver, &imap_protocol,
					proxy_userid, &backend_cached,
					&backend_current, &backend_inbox,
					imapd_in);
	if (!backend_next) r = IMAP_SERVER_UNAVAILABLE;

	if (backend_current && backend_current != backend_next) {
	    char mytag[128];

	    /* switching servers; flush old server output */
	    proxy_gentag(mytag, sizeof(mytag));
	    prot_printf(backend_current->out, "%s Unselect\r\n", mytag);
	    /* do not fatal() here, because we don't really care about this
	     * server anymore anyway */
	    pipe_until_tag(backend_current, mytag, 1);
	}
	backend_current = backend_next;

	if (r) {
	    prot_printf(imapd_out, "%s NO %s\r\n", tag, error_message(r));
	    return;
	}

	prot_printf(backend_current->out, "%s %s {%d+}\r\n%s%s\r\n", tag, cmd, 
		    strlen(name), name,
		    imapd_condstore_client ? " (CONDSTORE)" : "");
	switch (pipe_including_tag(backend_current, tag, 0)) {
	case PROXY_OK:
	    proc_register("imapd", imapd_clienthost, imapd_userid, mailboxname);
	    syslog(LOG_DEBUG, "open: user %s opened %s on %s",
		   imapd_userid, name, newserver);

	    /* add backend_current to the protgroup */
	    protgroup_insert(protin, backend_current->in);
	    break;
	default:
	    syslog(LOG_DEBUG, "open: user %s failed to open %s", imapd_userid,
		   name);
	    /* not successfully selected */
	    backend_current = NULL;
	    break;
	}

	return;
    }

    /* local mailbox */
    if (backend_current) {
      char mytag[128];

      /* switching servers; flush old server output */
      proxy_gentag(mytag, sizeof(mytag));
      prot_printf(backend_current->out, "%s Unselect\r\n", mytag);
      /* do not fatal() here, because we don't really care about this
       * server anymore anyway */
      pipe_until_tag(backend_current, mytag, 1);
    }
    backend_current = NULL;

    if (!r) {
	r = mailbox_open_header(mailboxname, imapd_authstate, &mailbox);
    }

    if (!r) {
	doclose = 1;
	r = mailbox_open_index(&mailbox);
    }
    if (!r && !(mailbox.myrights & ACL_READ)) {
	r = (imapd_userisadmin || (mailbox.myrights & ACL_LOOKUP)) ?
	  IMAP_PERMISSION_DENIED : IMAP_MAILBOX_NONEXISTENT;
    }

    if (r) {
	prot_printf(imapd_out, "%s NO %s\r\n", tag, error_message(r));
	if (doclose) mailbox_close(&mailbox);
	return;
    }

    mboxstruct = mailbox;
    imapd_mailbox = &mboxstruct;

    index_newmailbox(imapd_mailbox, cmd[0] == 'E');

    /* Examine command puts mailbox in read-only mode */
    if (cmd[0] == 'E') {
	imapd_mailbox->myrights &= ~ACL_READ_WRITE;
    }

    if (imapd_mailbox->myrights & ACL_EXPUNGE) {
	time_t now = time(NULL);

	/* Warn if mailbox is close to or over quota */
	r = quota_read(&imapd_mailbox->quota, NULL, 0);
	if (!r && imapd_mailbox->quota.limit > 0 &&
	    (strcmp(imapd_mailbox->quota.root, lastqr) || now > nextalert)) {
 	    /* Warn if the following possibilities occur:
 	     * - quotawarnkb not set + quotawarn hit
	     * - quotawarnkb set larger than mailbox + quotawarn hit
 	     * - quotawarnkb set + hit + quotawarn hit
 	     */
 	    int warnsize = config_getint(IMAPOPT_QUOTAWARNKB);
 	    if (warnsize <= 0 || warnsize >= imapd_mailbox->quota.limit ||
 	        ((uquota_t) (imapd_mailbox->quota.limit - warnsize)) * QUOTA_UNITS < 
		imapd_mailbox->quota.used) {
		usage = ((double) imapd_mailbox->quota.used * 100.0) / (double)
		    ((uquota_t) imapd_mailbox->quota.limit * QUOTA_UNITS);
		if (usage >= 100.0) {
		    prot_printf(imapd_out, "* NO [ALERT] %s\r\n",
				error_message(IMAP_NO_OVERQUOTA));
		}
		else if (usage > config_getint(IMAPOPT_QUOTAWARN)) {
		    int usageint = (int) usage;
		    prot_printf(imapd_out, "* NO [ALERT] ");
		    prot_printf(imapd_out, error_message(IMAP_NO_CLOSEQUOTA),
				usageint);
		    prot_printf(imapd_out, "\r\n");
		}
	    }
	    strlcpy(lastqr, imapd_mailbox->quota.root, sizeof(lastqr));
	    nextalert = now + 600; /* ALERT every 10 min regardless */
	}
    }

    prot_printf(imapd_out, "* OK [URLMECH INTERNAL]\r\n");
    prot_printf(imapd_out, "%s OK [READ-%s] %s\r\n", tag,
		(imapd_mailbox->myrights & ACL_READ_WRITE) ?
		"WRITE" : "ONLY", error_message(IMAP_OK_COMPLETED));

    proc_register("imapd", imapd_clienthost, imapd_userid, mailboxname);
    syslog(LOG_DEBUG, "open: user %s opened %s", imapd_userid, name);
    return;

 badlist:
    prot_printf(imapd_out, "%s BAD Invalid modifier list in %s\r\n", tag, cmd);
    eatline(imapd_in, c);
}
	  
/*
 * Perform a CLOSE command
 */
void cmd_close(char *tag)
{
    int r;

    if (backend_current) {
	/* remote mailbox */
	prot_printf(backend_current->out, "%s Close\r\n", tag);
	/* xxx do we want this to say OK if the connection is gone?
	 * saying NO is clearly wrong, hense the fatal request. */
	pipe_including_tag(backend_current, tag, 0);

	/* remove backend_current from the protgroup */
	protgroup_delete(protin, backend_current->in);

	backend_current = NULL;
	return;
    }

    /* local mailbox */
    if (!(imapd_mailbox->myrights & ACL_EXPUNGE)) r = 0;
    else {
	r = mailbox_expunge(imapd_mailbox, NULL, NULL, 0);
	if (!r) sync_log_mailbox(imapd_mailbox->name);
    }

    index_closemailbox(imapd_mailbox);
    mailbox_close(imapd_mailbox);
    imapd_mailbox = 0;

    if (r) {
	prot_printf(imapd_out, "%s NO %s\r\n", tag, error_message(r));
    }
    else {
	prot_printf(imapd_out, "%s OK %s\r\n", tag,
		    error_message(IMAP_OK_COMPLETED));
    }
}    

/*
 * Perform an UNSELECT command -- for some support of IMAP proxy.
 * Just like close except no expunge.
 */
void cmd_unselect(char *tag)
{
    if (backend_current) {
	/* remote mailbox */
	prot_printf(backend_current->out, "%s Unselect\r\n", tag);
	/* xxx do we want this to say OK if the connection is gone?
	 * saying NO is clearly wrong, hense the fatal request. */
	pipe_including_tag(backend_current, tag, 0);

	/* remove backend_current from the protgroup */
	protgroup_delete(protin, backend_current->in);

	backend_current = NULL;
	return;
    }

    /* local mailbox */
    index_closemailbox(imapd_mailbox);
    mailbox_close(imapd_mailbox);
    imapd_mailbox = 0;

    prot_printf(imapd_out, "%s OK %s\r\n", tag,
		error_message(IMAP_OK_COMPLETED));
}

/*
 * Parse the syntax for a partial fetch:
 *   "<" number "." nz-number ">"
 */
#define PARSE_PARTIAL(start_octet, octet_count)			        \
    (start_octet) = (octet_count) = 0;                                  \
    if (*p == '<' && isdigit((int) p[1])) {				\
	(start_octet) = p[1] - '0';				\
	p += 2;								\
	while (isdigit((int) *p)) {					\
	    (start_octet) =					\
		(start_octet) * 10 + *p++ - '0';		\
	}								\
									\
	if (*p == '.' && p[1] >= '1' && p[1] <= '9') {			\
	    (octet_count) = p[1] - '0';				\
	    p[0] = '>'; p[1] = '\0'; /* clip off the octet count 	\
					(its not used in the reply) */	\
	    p += 2;							\
	    while (isdigit((int) *p)) {					\
		(octet_count) =					\
		    (octet_count) * 10 + *p++ - '0';		\
	    }								\
	}								\
	else p--;							\
									\
	if (*p != '>') {						\
	    prot_printf(imapd_out,					\
			"%s BAD Invalid body partial\r\n", tag);	\
	    eatline(imapd_in, c);					\
	    goto freeargs;						\
	}								\
	p++;								\
    }

/*
 * Parse and perform a FETCH/UID FETCH command
 * The command has been parsed up to and including
 * the sequence
 */
void cmd_fetch(char *tag, char *sequence, int usinguid)
{
    const char *cmd = usinguid ? "UID Fetch" : "Fetch";
    static struct buf fetchatt, fieldname;
    int c;
    int inlist = 0;
    int fetchitems = 0;
    struct fetchargs fetchargs;
    struct octetinfo oi;
    struct strlist *newfields = 0;
    char *p, *section;
    int fetchedsomething, r;
    clock_t start = clock();
    char mytime[100];

    if (backend_current) {
	/* remote mailbox */
	prot_printf(backend_current->out, "%s %s %s ", tag, cmd, sequence);
	if (!pipe_command(backend_current, 65536)) {
	    pipe_including_tag(backend_current, tag, 0);
	}
	return;
    }

    /* local mailbox */
    memset(&fetchargs, 0, sizeof(struct fetchargs));

    c = getword(imapd_in, &fetchatt);
    if (c == '(' && !fetchatt.s[0]) {
	inlist = 1;
	c = getword(imapd_in, &fetchatt);
    }
    for (;;) {
	ucase(fetchatt.s);
	switch (fetchatt.s[0]) {
	case 'A':
	    if (!inlist && !strcmp(fetchatt.s, "ALL")) {
		fetchitems |= FETCH_ALL;
	    }
	    else goto badatt;
	    break;

	case 'B':
	    if (!strncmp(fetchatt.s, "BINARY[", 7) ||
		!strncmp(fetchatt.s, "BINARY.PEEK[", 12) ||
		!strncmp(fetchatt.s, "BINARY.SIZE[", 12)) {
		int binsize = 0;

		p = section = fetchatt.s + 7;
		if (!strncmp(p, "PEEK[", 5)) {
		    p = section += 5;
		}
		else if (!strncmp(p, "SIZE[", 5)) {
		    p = section += 5;
		    binsize = 1;
		}
		else {
		    fetchitems |= FETCH_SETSEEN;
		}
		while (isdigit((int) *p) || *p == '.') {
		    if (*p == '.' && !isdigit((int) p[-1])) break;
		    /* Part number can not begin with '0' */
		    if (*p == '0' && !isdigit((int) p[-1])) break;
		    p++;
		}

		if (*p != ']') {
		    prot_printf(imapd_out, "%s BAD Invalid binary section\r\n", tag);
		    eatline(imapd_in, c);
		    goto freeargs;
		}
		p++;

		if (!binsize) PARSE_PARTIAL(oi.start_octet, oi.octet_count);

		if (*p) {
		    prot_printf(imapd_out, "%s BAD Junk after binary section\r\n", tag);
		    eatline(imapd_in, c);
		    goto freeargs;
		}
		if (binsize)
		    appendstrlist_withdata(&fetchargs.sizesections, section, &oi, sizeof(oi));
		else
		    appendstrlist_withdata(&fetchargs.binsections, section, &oi, sizeof(oi));
	    }
	    else if (!strcmp(fetchatt.s, "BODY")) {
		fetchitems |= FETCH_BODY;
	    }
	    else if (!strcmp(fetchatt.s, "BODYSTRUCTURE")) {
		fetchitems |= FETCH_BODYSTRUCTURE;
	    }
	    else if (!strncmp(fetchatt.s, "BODY[", 5) ||
		     !strncmp(fetchatt.s, "BODY.PEEK[", 10)) {
		p = section = fetchatt.s + 5;
		if (!strncmp(p, "PEEK[", 5)) {
		    p = section += 5;
		}
		else {
		    fetchitems |= FETCH_SETSEEN;
		}
		while (isdigit((int) *p) || *p == '.') {
		    if (*p == '.' && !isdigit((int) p[-1])) break;
		    /* Obsolete section 0 can only occur before close brace */
		    if (*p == '0' && !isdigit((int) p[-1]) && p[1] != ']') break;
		    p++;
		}

		if (*p == 'H' && !strncmp(p, "HEADER.FIELDS", 13) &&
		    (p == section || p[-1] == '.') &&
		    (p[13] == '\0' || !strcmp(p+13, ".NOT"))) {

		    /*
		     * If not top-level or a HEADER.FIELDS.NOT, can't pull
		     * the headers out of the cache.
		     */
		    if (p != section || p[13] != '\0') {
			fetchargs.cache_atleast = BIT32_MAX;
		    }

		    if (c != ' ') {
			prot_printf(imapd_out,
				    "%s BAD Missing required argument to %s %s\r\n",
				    tag, cmd, fetchatt.s);
			eatline(imapd_in, c);
			goto freeargs;
		    }
		    c = prot_getc(imapd_in);
		    if (c != '(') {
			prot_printf(imapd_out, "%s BAD Missing required open parenthesis in %s %s\r\n",
				    tag, cmd, fetchatt.s);
			eatline(imapd_in, c);
			goto freeargs;
		    }
		    do {
			c = getastring(imapd_in, imapd_out, &fieldname);
			for (p = fieldname.s; *p; p++) {
			    if (*p <= ' ' || *p & 0x80 || *p == ':') break;
			}
			if (*p || !*fieldname.s) {
			    prot_printf(imapd_out, "%s BAD Invalid field-name in %s %s\r\n",
					tag, cmd, fetchatt.s);
			    eatline(imapd_in, c);
			    goto freeargs;
			}
			appendstrlist(&newfields, fieldname.s);
			if (fetchargs.cache_atleast < BIT32_MAX) {
			    bit32 this_ver =
				mailbox_cached_header(fieldname.s);
			    if(this_ver > fetchargs.cache_atleast)
				fetchargs.cache_atleast = this_ver;
			}
		    } while (c == ' ');
		    if (c != ')') {
			prot_printf(imapd_out, "%s BAD Missing required close parenthesis in %s %s\r\n",
				    tag, cmd, fetchatt.s);
			eatline(imapd_in, c);
			goto freeargs;
		    }

		    /* Grab/parse the ]<x.y> part */
		    c = getword(imapd_in, &fieldname);
		    p = fieldname.s;
		    if (*p++ != ']') {
			prot_printf(imapd_out, "%s BAD Missing required close bracket after %s %s\r\n",
				    tag, cmd, fetchatt.s);
			eatline(imapd_in, c);
			goto freeargs;
		    }

		    PARSE_PARTIAL(oi.start_octet, oi.octet_count);

		    if (*p) {
			prot_printf(imapd_out, "%s BAD Junk after body section\r\n", tag);
			eatline(imapd_in, c);
			goto freeargs;
		    }
		    appendfieldlist(&fetchargs.fsections,
				    section, newfields, fieldname.s,
				    &oi, sizeof(oi));
		    newfields = 0;
		    break;
		}

		switch (*p) {
		case 'H':
		    if (p != section && p[-1] != '.') break;
		    if (!strncmp(p, "HEADER]", 7)) p += 6;
		    break;

		case 'M':
		    if (!strncmp(p-1, ".MIME]", 6)) p += 4;
		    break;

		case 'T':
		    if (p != section && p[-1] != '.') break;
		    if (!strncmp(p, "TEXT]", 5)) p += 4;
		    break;
		}

		if (*p != ']') {
		    prot_printf(imapd_out, "%s BAD Invalid body section\r\n", tag);
		    eatline(imapd_in, c);
		    goto freeargs;
		}
		p++;

		PARSE_PARTIAL(oi.start_octet, oi.octet_count);

		if (*p) {
		    prot_printf(imapd_out, "%s BAD Junk after body section\r\n", tag);
		    eatline(imapd_in, c);
		    goto freeargs;
		}
		appendstrlist_withdata(&fetchargs.bodysections, section,
				       &oi, sizeof(oi));
	    }
	    else goto badatt;
	    break;

	case 'E':
	    if (!strcmp(fetchatt.s, "ENVELOPE")) {
		fetchitems |= FETCH_ENVELOPE;
	    }
	    else goto badatt;
	    break;

	case 'F':
	    if (!inlist && !strcmp(fetchatt.s, "FAST")) {
		fetchitems |= FETCH_FAST;
	    }
	    else if (!inlist && !strcmp(fetchatt.s, "FULL")) {
		fetchitems |= FETCH_FULL;
	    }
	    else if (!strcmp(fetchatt.s, "FLAGS")) {
		fetchitems |= FETCH_FLAGS;
	    }
	    else goto badatt;
	    break;

	case 'I':
	    if (!strcmp(fetchatt.s, "INTERNALDATE")) {
		fetchitems |= FETCH_INTERNALDATE;
	    }
	    else goto badatt;
	    break;

	case 'M':
	    if ((imapd_mailbox->options & OPT_IMAP_CONDSTORE) &&
		!strcmp(fetchatt.s, "MODSEQ")) {
		fetchitems |= FETCH_MODSEQ;
	    }
	    else goto badatt;
	    break;
	case 'R':
	    if (!strcmp(fetchatt.s, "RFC822")) {
		fetchitems |= FETCH_RFC822|FETCH_SETSEEN;
	    }
	    else if (!strcmp(fetchatt.s, "RFC822.HEADER")) {
		fetchitems |= FETCH_HEADER;
	    }
	    else if (!strcmp(fetchatt.s, "RFC822.PEEK")) {
		fetchitems |= FETCH_RFC822;
	    }
	    else if (!strcmp(fetchatt.s, "RFC822.SIZE")) {
		fetchitems |= FETCH_SIZE;
	    }
	    else if (!strcmp(fetchatt.s, "RFC822.TEXT")) {
		fetchitems |= FETCH_TEXT|FETCH_SETSEEN;
	    }
	    else if (!strcmp(fetchatt.s, "RFC822.TEXT.PEEK")) {
		fetchitems |= FETCH_TEXT;
	    }
	    else if (!strcmp(fetchatt.s, "RFC822.HEADER.LINES") ||
		     !strcmp(fetchatt.s, "RFC822.HEADER.LINES.NOT")) {
		if (c != ' ') {
		    prot_printf(imapd_out, "%s BAD Missing required argument to %s %s\r\n",
			   tag, cmd, fetchatt.s);
		    eatline(imapd_in, c);
		    goto freeargs;
		}
		c = prot_getc(imapd_in);
		if (c != '(') {
		    prot_printf(imapd_out, "%s BAD Missing required open parenthesis in %s %s\r\n",
			   tag, cmd, fetchatt.s);
		    eatline(imapd_in, c);
		    goto freeargs;
		}
		do {
		    c = getastring(imapd_in, imapd_out, &fieldname);
		    for (p = fieldname.s; *p; p++) {
			if (*p <= ' ' || *p & 0x80 || *p == ':') break;
		    }
		    if (*p || !*fieldname.s) {
			prot_printf(imapd_out, "%s BAD Invalid field-name in %s %s\r\n",
			       tag, cmd, fetchatt.s);
			eatline(imapd_in, c);
			goto freeargs;
		    }
		    lcase(fieldname.s);;
		    /* 19 is magic number -- length of 
		     * "RFC822.HEADERS.NOT" */
		    appendstrlist(strlen(fetchatt.s) == 19 ?
				  &fetchargs.headers : &fetchargs.headers_not,
				  fieldname.s);
		    if (strlen(fetchatt.s) != 19) {
			fetchargs.cache_atleast = BIT32_MAX;
		    }
		    if (fetchargs.cache_atleast < BIT32_MAX) {
			bit32 this_ver =
			    mailbox_cached_header(fieldname.s);
			if(this_ver > fetchargs.cache_atleast)
			    fetchargs.cache_atleast = this_ver;
		   }
		} while (c == ' ');
		if (c != ')') {
		    prot_printf(imapd_out, "%s BAD Missing required close parenthesis in %s %s\r\n",
			   tag, cmd, fetchatt.s);
		    eatline(imapd_in, c);
		    goto freeargs;
		}
		c = prot_getc(imapd_in);
	    }
	    else goto badatt;
	    break;

	case 'U':
	    if (!strcmp(fetchatt.s, "UID")) {
		fetchitems |= FETCH_UID;
	    }
	    else goto badatt;
	    break;

	default:
	badatt:
	    prot_printf(imapd_out, "%s BAD Invalid %s attribute %s\r\n", tag, cmd, fetchatt.s);
	    eatline(imapd_in, c);
	    goto freeargs;
	}

	if (inlist && c == ' ') c = getword(imapd_in, &fetchatt);
	else break;
    }
    
    if (inlist && c == ')') {
	inlist = 0;
	c = prot_getc(imapd_in);
    }
    if (inlist) {
	prot_printf(imapd_out, "%s BAD Missing close parenthesis in %s\r\n",
		    tag, cmd);
	eatline(imapd_in, c);
	goto freeargs;
    }

    if (c == ' ') {
	/* Grab/parse the modifier(s) */
	c = prot_getc(imapd_in);
	if (c != '(') {
	    prot_printf(imapd_out,
			"%s BAD Missing required open parenthesis in %s modifiers\r\n",
			tag, cmd);
	    eatline(imapd_in, c);
	    goto freeargs;
	}
	do {
	    c = getword(imapd_in, &fetchatt);
	    ucase(fetchatt.s);
	    if ((imapd_mailbox->options & OPT_IMAP_CONDSTORE) &&
		!strcmp(fetchatt.s, "CHANGEDSINCE")) {
		if (c != ' ') {
		    prot_printf(imapd_out,
				"%s BAD Missing required argument to %s %s\r\n",
				tag, cmd, fetchatt.s);
		    eatline(imapd_in, c);
		    goto freeargs;
		}
		c = getastring(imapd_in, imapd_out, &fieldname);
		fetchargs.changedsince = strtoul(fieldname.s, &p, 10);
		if (*p || fetchargs.changedsince == ULONG_MAX) {
		    prot_printf(imapd_out,
				"%s BAD Invalid argument to %s %s\r\n",
				tag, cmd, fetchatt.s);
		    eatline(imapd_in, c);
		    goto freeargs;
		}
		fetchitems |= FETCH_MODSEQ;
	    }
	    else {
		prot_printf(imapd_out, "%s BAD Invalid %s modifier %s\r\n",
			    tag, cmd, fetchatt.s);
		eatline(imapd_in, c);
		goto freeargs;
	    }
	} while (c == ' ');
	if (c != ')') {
	    prot_printf(imapd_out, "%s BAD Missing close parenthesis in %s\r\n",
			tag, cmd);
	    eatline(imapd_in, c);
	    goto freeargs;
	}
	c = prot_getc(imapd_in);
    }

    if (c == '\r') c = prot_getc(imapd_in);
    if (c != '\n') {
	prot_printf(imapd_out, "%s BAD Unexpected extra arguments to %s\r\n", tag, cmd);
	eatline(imapd_in, c);
	goto freeargs;
    }

    if (!fetchitems && !fetchargs.bodysections && !fetchargs.fsections &&
	!fetchargs.binsections && !fetchargs.sizesections &&
	!fetchargs.headers && !fetchargs.headers_not) {
	prot_printf(imapd_out, "%s BAD Missing required argument to %s\r\n", tag, cmd);
	goto freeargs;
    }

    if (fetchitems & FETCH_MODSEQ) {
	if (!imapd_condstore_client++)
	    prot_printf(imapd_out, "* OK [HIGHESTMODSEQ " MODSEQ_FMT "]  \r\n",
			imapd_mailbox->highestmodseq);
    }

    /* EXPUNGE responses allowed for UID FETCH */
    if (usinguid) {
	fetchitems |= FETCH_UID;
	index_check(imapd_mailbox, 1, 0);
    }

    fetchargs.fetchitems = fetchitems;
    r = index_fetch(imapd_mailbox, sequence, usinguid, &fetchargs,
		&fetchedsomething);

    if (config_getswitch(IMAPOPT_FLUSHSEENSTATE)) {
        /* Flush \Seen state to disk immediately (but only if anything
           changed) and check for updates by other processes */
        index_check_existing(imapd_mailbox, usinguid, 1);  
    }

    snprintf(mytime, sizeof(mytime), "%2.3f", 
	     (clock() - start) / (double) CLOCKS_PER_SEC);

    if (r) {
	prot_printf(imapd_out, "%s NO %s (%s sec)\r\n", tag,
		    error_message(r), mytime);
    } else if (fetchedsomething || usinguid) {
	prot_printf(imapd_out, "%s OK %s (%s sec)\r\n", tag,
		    error_message(IMAP_OK_COMPLETED), mytime);
    } else {
	/* normal FETCH, nothing came back */
	prot_printf(imapd_out, "%s NO %s (%s sec)\r\n", tag,
		    error_message(IMAP_NO_NOSUCHMSG), mytime);
    }

 freeargs:
    freestrlist(newfields);
    freestrlist(fetchargs.bodysections);
    freefieldlist(fetchargs.fsections);
    freestrlist(fetchargs.headers);
    freestrlist(fetchargs.headers_not);
}

#undef PARSE_PARTIAL /* cleanup */

/*
 * Perform a PARTIAL command
 */
void cmd_partial(const char *tag, const char *msgno, char *data,
		 const char *start, const char *count)
{
    const char *pc;
    char *p;
    struct fetchargs fetchargs;
    char *section;
    int prev;
    int fetchedsomething;

    if (backend_current) {
	/* remote mailbox */
	prot_printf(backend_current->out, "%s Partial %s %s %s %s\r\n",
		    tag, msgno, data, start, count);
	pipe_including_tag(backend_current, tag, 0);
	return;
    }

    /* local mailbox */
    memset(&fetchargs, 0, sizeof(struct fetchargs));

    for (pc = msgno; *pc; pc++) {
	if (!isdigit((int) *pc)) break;
    }
    if (*pc || !*msgno) {
	prot_printf(imapd_out, "%s BAD Invalid message number\r\n", tag);
	return;
    }

    lcase(data);
    if (!strcmp(data, "rfc822")) {
	fetchargs.fetchitems = FETCH_RFC822|FETCH_SETSEEN;
    }
    else if (!strcmp(data, "rfc822.header")) {
	fetchargs.fetchitems = FETCH_HEADER;
    }
    else if (!strcmp(data, "rfc822.peek")) {
	fetchargs.fetchitems = FETCH_RFC822;
    }
    else if (!strcmp(data, "rfc822.text")) {
	fetchargs.fetchitems = FETCH_TEXT|FETCH_SETSEEN;
    }
    else if (!strcmp(data, "rfc822.text.peek")) {
	fetchargs.fetchitems = FETCH_TEXT;
    }
    else if (!strncmp(data, "body[", 5) ||
	     !strncmp(data, "body.peek[", 10)) {
	p = section = data + 5;
	if (!strncmp(p, "peek[", 5)) {
	    p = section += 5;
	}
	else {
	    fetchargs.fetchitems = FETCH_SETSEEN;
	}
	while (isdigit((int) *p) || *p == '.') {
	    if (*p == '.' && (p == section || !isdigit((int) p[1]))) break;
	    p++;
	}
	if (p == section || *p != ']' || p[1]) {
	    prot_printf(imapd_out, "%s BAD Invalid body section\r\n", tag);
	    freestrlist(fetchargs.bodysections);
	    return;
	}
	*(p+1) = '\0'; /* Keep the closing bracket in place */
	appendstrlist(&fetchargs.bodysections, section);
    }
    else {
	prot_printf(imapd_out, "%s BAD Invalid Partial item\r\n", tag);
	freestrlist(fetchargs.bodysections);
	return;
    }

    for (pc = start; *pc; pc++) {
	if (!isdigit((int) *pc)) break;
	prev = fetchargs.start_octet;
	fetchargs.start_octet = fetchargs.start_octet*10 + *pc - '0';
	if(fetchargs.start_octet < prev) {
	    fetchargs.start_octet = 0;
	    break;
	}
    }
    if (*pc || !fetchargs.start_octet) {
	prot_printf(imapd_out, "%s BAD Invalid starting octet\r\n", tag);
	freestrlist(fetchargs.bodysections);
	return;
    }
    fetchargs.start_octet--;	/* Normalize to be 0-based */
    
    prev = fetchargs.octet_count;
    for (pc = count; *pc; pc++) {
	if (!isdigit((int) *pc)) break;
	prev = fetchargs.octet_count;
	fetchargs.octet_count = fetchargs.octet_count*10 + *pc - '0';
	if(fetchargs.octet_count < prev) {
	    prev = -1;
	    break;
	}
    }
    if (*pc || !*count || prev == -1) {
	prot_printf(imapd_out, "%s BAD Invalid octet count\r\n", tag);
	freestrlist(fetchargs.bodysections);
	return;
    }

    fetchargs.fetchitems |= FETCH_IS_PARTIAL;

    index_fetch(imapd_mailbox, msgno, 0, &fetchargs, &fetchedsomething);

    if (config_getswitch(IMAPOPT_FLUSHSEENSTATE)) {
        /* Flush \Seen state to disk immediately (but only if anything
           changed) and check for updates by other processes */
        index_check_existing(imapd_mailbox, 0, 1);
    }

    if (fetchedsomething) {
	prot_printf(imapd_out, "%s OK %s\r\n", tag,
		    error_message(IMAP_OK_COMPLETED));
    } else {
	prot_printf(imapd_out,
		    "%s BAD Invalid sequence in PARTIAL command\r\n",
		    tag);
    }

    freestrlist(fetchargs.bodysections);
}

/*
 * Parse and perform a STORE/UID STORE command
 * The command has been parsed up to and including
 * the sequence
 */
void cmd_store(char *tag, char *sequence, int usinguid)
{
    const char *cmd = usinguid ? "UID Store" : "Store";
    struct storeargs storeargs;
    static struct buf operation, flagname;
    int len, c;
    char **flag = 0;
    int nflags = 0, flagalloc = 0;
    int flagsparsed = 0, inlist = 0;
    int r;

    if (backend_current) {
	/* remote mailbox */
	prot_printf(backend_current->out, "%s %s %s ",
		    tag, cmd, sequence);
	if (!pipe_command(backend_current, 65536)) {
	    pipe_including_tag(backend_current, tag, 0);
	}
	return;
    }

    /* local mailbox */
    memset(&storeargs, 0, sizeof storeargs);
    storeargs.unchangedsince = ULONG_MAX;

    c = prot_getc(imapd_in);
    if (c == '(') {
	/* Grab/parse the modifier(s) */
	static struct buf storemod, modvalue;
	char *p;

	do {
	    c = getword(imapd_in, &storemod);
	    ucase(storemod.s);
	    if ((imapd_mailbox->options & OPT_IMAP_CONDSTORE) &&
		!strcmp(storemod.s, "UNCHANGEDSINCE")) {
		if (c != ' ') {
		    prot_printf(imapd_out,
				"%s BAD Missing required argument to %s %s\r\n",
				tag, cmd, storemod.s);
		    eatline(imapd_in, c);
		    return;
		}
		c = getastring(imapd_in, imapd_out, &modvalue);
		storeargs.unchangedsince = strtoul(modvalue.s, &p, 10);
		if (*p || storeargs.unchangedsince == ULONG_MAX) {
		    prot_printf(imapd_out,
				"%s BAD Invalid argument to %s %s\r\n",
				tag, cmd, storemod.s);
		    eatline(imapd_in, c);
		    return;
		}
	    }
	    else {
		prot_printf(imapd_out, "%s BAD Invalid %s modifier %s\r\n",
			    tag, cmd, storemod.s);
		eatline(imapd_in, c);
		return;
	    }
	} while (c == ' ');
	if (c != ')') {
	    prot_printf(imapd_out,
			"%s BAD Missing close paren in store modifier entry \r\n",
			tag);
	    eatline(imapd_in, c);
	    return;
	}
	c = prot_getc(imapd_in);
	if (c != ' ') {
	    prot_printf(imapd_out,
			"%s BAD Missing required argument to %s\r\n",
			tag, cmd);
	    eatline(imapd_in, c);
	    return;
	}
    }
    else
	prot_ungetc(c, imapd_in);

    c = getword(imapd_in, &operation);
    if (c != ' ') {
	prot_printf(imapd_out,
		    "%s BAD Missing required argument to %s\r\n", tag, cmd);
	eatline(imapd_in, c);
	return;
    }
    lcase(operation.s);

    len = strlen(operation.s);
    if (len > 7 && !strcmp(operation.s+len-7, ".silent")) {
	storeargs.silent = 1;
	operation.s[len-7] = '\0';
    }
    
    if (!strcmp(operation.s, "+flags")) {
	storeargs.operation = STORE_ADD;
    }
    else if (!strcmp(operation.s, "-flags")) {
	storeargs.operation = STORE_REMOVE;
    }
    else if (!strcmp(operation.s, "flags")) {
	storeargs.operation = STORE_REPLACE;
    }
    else {
	prot_printf(imapd_out, "%s BAD Invalid %s attribute\r\n", tag, cmd);
	eatline(imapd_in, ' ');
	return;
    }

    for (;;) {
	c = getword(imapd_in, &flagname);
	if (c == '(' && !flagname.s[0] && !flagsparsed && !inlist) {
	    inlist = 1;
	    continue;
	}

	if (!flagname.s[0]) break;

	if (flagname.s[0] == '\\') {
	    lcase(flagname.s);
	    if (!strcmp(flagname.s, "\\seen")) {
		storeargs.seen = 1;
	    }
	    else if (!strcmp(flagname.s, "\\answered")) {
		storeargs.system_flags |= FLAG_ANSWERED;
	    }
	    else if (!strcmp(flagname.s, "\\flagged")) {
		storeargs.system_flags |= FLAG_FLAGGED;
	    }
	    else if (!strcmp(flagname.s, "\\deleted")) {
		storeargs.system_flags |= FLAG_DELETED;
	    }
	    else if (!strcmp(flagname.s, "\\draft")) {
		storeargs.system_flags |= FLAG_DRAFT;
	    }
	    else {
		prot_printf(imapd_out, "%s BAD Invalid system flag in %s command\r\n",
		       tag, cmd);
		eatline(imapd_in, c);
		goto freeflags;
	    }
	}
	else if (!imparse_isatom(flagname.s)) {
	    prot_printf(imapd_out, "%s BAD Invalid flag name %s in %s command\r\n",
		   tag, flagname.s, cmd);
	    eatline(imapd_in, c);
	    goto freeflags;
	}
	else {
	    if (nflags == flagalloc) {
		flagalloc += FLAGGROW;
		flag = (char **)xrealloc((char *)flag,
					 flagalloc*sizeof(char *));
	    }
	    flag[nflags] = xstrdup(flagname.s);
	    nflags++;
	}

	flagsparsed++;
	if (c != ' ') break;
    }

    if (!inlist && !flagsparsed) {
	prot_printf(imapd_out, "%s BAD Missing required argument to %s\r\n", tag, cmd);
	eatline(imapd_in, c);
	return;
    }
    if (inlist && c == ')') {
	inlist = 0;
	c = prot_getc(imapd_in);
    }
    if (inlist) {
	prot_printf(imapd_out, "%s BAD Missing close parenthesis in %s\r\n", tag, cmd);
	eatline(imapd_in, c);
	goto freeflags;
    }
    if (c == '\r') c = prot_getc(imapd_in);
    if (c != '\n') {
	prot_printf(imapd_out, "%s BAD Unexpected extra arguments to %s\r\n", tag, cmd);
	eatline(imapd_in, c);
	goto freeflags;
    }

    if ((storeargs.unchangedsince != ULONG_MAX) && !imapd_condstore_client++) {
	prot_printf(imapd_out, "* OK [HIGHESTMODSEQ " MODSEQ_FMT "]  \r\n",
		    imapd_mailbox->highestmodseq);
    }

    r = index_store(imapd_mailbox, sequence, usinguid, &storeargs,
		    flag, nflags);

    if (usinguid) {
	index_check(imapd_mailbox, 1, 1);   /* Check \Seen too */
    } else if (config_getswitch(IMAPOPT_FLUSHSEENSTATE)) {
        /* Flush \Seen state to disk immediately (but only if anything
           changed) and check for updates by other processes */
        index_check_existing(imapd_mailbox, 0, 1);
    }

    if (r) {
	prot_printf(imapd_out, "%s NO %s\r\n", tag, error_message(r));
    }
    else {
	prot_printf(imapd_out, "%s OK %s\r\n", tag,
		    error_message(IMAP_OK_COMPLETED));

	/* We only need to log a MAILBOX event if we've changed
	   a flag other than \Seen */
	if (storeargs.system_flags || nflags ||
	    storeargs.operation == STORE_REPLACE) {
	    sync_log_mailbox(imapd_mailbox->name);
	}
    }

 freeflags:
    while (nflags--) {
	free(flag[nflags]);
    }
    if (flag) free((char *)flag);
}

void cmd_search(char *tag, int usinguid)
{
    int c;
    int charset = 0;
    struct searchargs *searchargs;
    clock_t start = clock();
    char mytime[100];
    int n;

    if (backend_current) {
	/* remote mailbox */
	const char *cmd = usinguid ? "UID Search" : "Search";

	prot_printf(backend_current->out, "%s %s ", tag, cmd);
	if (!pipe_command(backend_current, 65536)) {
	    pipe_including_tag(backend_current, tag, 0);
	}
	return;
    }

    /* local mailbox */
    searchargs = (struct searchargs *)xzmalloc(sizeof(struct searchargs));

    c = getsearchprogram(tag, searchargs, &charset, 1);
    if (c == EOF) {
	eatline(imapd_in, ' ');
	freesearchargs(searchargs);
	return;
    }

    if (c == '\r') c = prot_getc(imapd_in);
    if (c != '\n') {
	prot_printf(imapd_out, "%s BAD Unexpected extra arguments to Search\r\n", tag);
	eatline(imapd_in, c);
	freesearchargs(searchargs);
	return;
    }

    index_check(imapd_mailbox, 1, 0);

    if (charset == -1) {
	prot_printf(imapd_out, "%s NO %s\r\n", tag,
	       error_message(IMAP_UNRECOGNIZED_CHARSET));
    }
    else {
	n = index_search(imapd_mailbox, searchargs, usinguid);
	snprintf(mytime, sizeof(mytime), "%2.3f", 
		 (clock() - start) / (double) CLOCKS_PER_SEC);
	prot_printf(imapd_out, "%s OK %s (%d msgs in %s secs)\r\n", tag,
		    error_message(IMAP_OK_COMPLETED), n, mytime);
    }

    freesearchargs(searchargs);
}

/*
 * Perform a SORT/UID SORT command
 */    
void cmd_sort(char *tag, int usinguid)
{
    int c;
    struct sortcrit *sortcrit = NULL;
    static struct buf arg;
    int charset = 0;
    struct searchargs *searchargs;
    clock_t start = clock();
    char mytime[100];
    int n;

    if (backend_current) {
	/* remote mailbox */
	char *cmd = usinguid ? "UID Sort" : "Sort";

	prot_printf(backend_current->out, "%s %s ", tag, cmd);
	if (!pipe_command(backend_current, 65536)) {
	    pipe_including_tag(backend_current, tag, 0);
	}
	return;
    }

    /* local mailbox */
    c = getsortcriteria(tag, &sortcrit);
    if (c == EOF) {
	eatline(imapd_in, ' ');
	freesortcrit(sortcrit);
	return;
    }

    /* get charset */
    if (c != ' ') {
	prot_printf(imapd_out, "%s BAD Missing charset in Sort\r\n",
		    tag);
	eatline(imapd_in, c);
	freesortcrit(sortcrit);
	return;
    }

    c = getword(imapd_in, &arg);
    if (c != ' ') {
	prot_printf(imapd_out, "%s BAD Missing search criteria in Sort\r\n",
		    tag);
	eatline(imapd_in, c);
	freesortcrit(sortcrit);
	return;
    }
    lcase(arg.s);
    charset = charset_lookupname(arg.s);

    if (charset == -1) {
	prot_printf(imapd_out, "%s NO %s\r\n", tag,
	       error_message(IMAP_UNRECOGNIZED_CHARSET));
	eatline(imapd_in, c);
	freesortcrit(sortcrit);
	return;
    }

    searchargs = (struct searchargs *)xzmalloc(sizeof(struct searchargs));

    c = getsearchprogram(tag, searchargs, &charset, 0);
    if (c == EOF) {
	eatline(imapd_in, ' ');
	freesearchargs(searchargs);
	freesortcrit(sortcrit);
	return;
    }

    if (c == '\r') c = prot_getc(imapd_in);
    if (c != '\n') {
	prot_printf(imapd_out, 
		    "%s BAD Unexpected extra arguments to Sort\r\n", tag);
	eatline(imapd_in, c);
	freesearchargs(searchargs);
	freesortcrit(sortcrit);
	return;
    }

    index_check(imapd_mailbox, 1, 0);

    n = index_sort(imapd_mailbox, sortcrit, searchargs, usinguid);
    snprintf(mytime, sizeof(mytime), "%2.3f",
	     (clock() - start) / (double) CLOCKS_PER_SEC);
    prot_printf(imapd_out, "%s OK %s (%d msgs in %s secs)\r\n", tag,
		error_message(IMAP_OK_COMPLETED), n, mytime);

    freesortcrit(sortcrit);
    freesearchargs(searchargs);
    return;
}

/*
 * Perform a THREAD/UID THREAD command
 */    
void cmd_thread(char *tag, int usinguid)
{
    static struct buf arg;
    int c;
    int charset = 0;
    int alg;
    struct searchargs *searchargs;
    clock_t start = clock();
    char mytime[100];
    int n;

    if (backend_current) {
	/* remote mailbox */
	const char *cmd = usinguid ? "UID Thread" : "Thread";

	prot_printf(backend_current->out, "%s %s ", tag, cmd);
	if (!pipe_command(backend_current, 65536)) {
	    pipe_including_tag(backend_current, tag, 0);
	}
	return;
    }

    /* local mailbox */
    /* get algorithm */
    c = getword(imapd_in, &arg);
    if (c != ' ') {
	prot_printf(imapd_out, "%s BAD Missing algorithm in Thread\r\n", tag);
	eatline(imapd_in, c);
	return;
    }

    if ((alg = find_thread_algorithm(arg.s)) == -1) {
	prot_printf(imapd_out, "%s BAD Invalid Thread algorithm %s\r\n",
		    tag, arg.s);
	eatline(imapd_in, c);
	return;
    }

    /* get charset */
    c = getword(imapd_in, &arg);
    if (c != ' ') {
	prot_printf(imapd_out, "%s BAD Missing charset in Thread\r\n",
		    tag);
	eatline(imapd_in, c);
	return;
    }
    lcase(arg.s);
    charset = charset_lookupname(arg.s);

    if (charset == -1) {
	prot_printf(imapd_out, "%s NO %s\r\n", tag,
	       error_message(IMAP_UNRECOGNIZED_CHARSET));
	eatline(imapd_in, c);
	return;
    }

    searchargs = (struct searchargs *)xzmalloc(sizeof(struct searchargs));

    c = getsearchprogram(tag, searchargs, &charset, 0);
    if (c == EOF) {
	eatline(imapd_in, ' ');
	freesearchargs(searchargs);
	return;
    }

    if (c == '\r') c = prot_getc(imapd_in);
    if (c != '\n') {
	prot_printf(imapd_out, 
		    "%s BAD Unexpected extra arguments to Thread\r\n", tag);
	eatline(imapd_in, c);
	freesearchargs(searchargs);
	return;
    }

    index_check(imapd_mailbox, 1, 0);

    n = index_thread(imapd_mailbox, alg, searchargs, usinguid);
    snprintf(mytime, sizeof(mytime), "%2.3f", 
	     (clock() - start) / (double) CLOCKS_PER_SEC);
    prot_printf(imapd_out, "%s OK %s (%d msgs in %s secs)\r\n", tag,
		error_message(IMAP_OK_COMPLETED), n, mytime);

    freesearchargs(searchargs);
    return;
}

/*
 * Perform a COPY/UID COPY command
 */    
void cmd_copy(char *tag, char *sequence, char *name, int usinguid)
{
    int r, myrights;
    char mailboxname[MAX_MAILBOX_NAME+1];
    int mbtype;
    char *server, *acl;
    char *copyuid;

    r = (*imapd_namespace.mboxname_tointernal)(&imapd_namespace, name,
					       imapd_userid, mailboxname);

    if (!r) {
	r = mlookup(NULL, NULL, mailboxname, &mbtype, NULL, NULL,
		    &server, &acl, NULL);
    }

    if (!r) myrights = cyrus_acl_myrights(imapd_authstate, acl);

    if (!r && backend_current) {
	/* remote mailbox -> local or remote mailbox */

	/* xxx  start of separate proxy-only code
	   (remove when we move to a unified environment) */
	struct backend *s = NULL;

	s = proxy_findserver(server, &imap_protocol,
			     proxy_userid, &backend_cached,
			     &backend_current, &backend_inbox, imapd_in);
	if (!s) {
	    r = IMAP_SERVER_UNAVAILABLE;
	    goto done;
	}

	if (s != backend_current) {
	    /* this is the hard case; we have to fetch the messages and append
	       them to the other mailbox */

	    proxy_copy(tag, sequence, name, myrights, usinguid, s);
	    return;
	}
	/* xxx  end of separate proxy-only code */

	/* simply send the COPY to the backend */
	prot_printf(backend_current->out, "%s %s %s {%d+}\r\n%s\r\n",
		    tag, usinguid ? "UID Copy" : "Copy",
		    sequence, strlen(name), name);
	pipe_including_tag(backend_current, tag, 0);

	return;
    }
    else if (!r && (mbtype & MBTYPE_REMOTE)) {
	/* local mailbox -> remote mailbox
	 *
	 * fetch the messages and APPEND them to the backend
	 *
	 * xxx  completely untested
	 */
	struct backend *s = NULL;
	int res;

	index_check(imapd_mailbox, usinguid, 0);

	s = proxy_findserver(server, &imap_protocol,
			     proxy_userid, &backend_cached,
			     &backend_current, &backend_inbox, imapd_in);
	if (!s) r = IMAP_SERVER_UNAVAILABLE;
	else if (!CAPA(s, CAPA_MULTIAPPEND)) {
	    /* we need MULTIAPPEND for atomicity */
	    r = IMAP_REMOTE_NO_MULTIAPPEND;
	}

	if (r) goto done;

	/* start the append */
	prot_printf(s->out, "%s Append {%d+}\r\n%s", tag, strlen(name), name);

	/* append the messages */
	r = index_copy_remote(imapd_mailbox, sequence, usinguid, s->out);

	if (!r) {
	    /* ok, finish the append; we need the UIDVALIDITY and UIDs
	       to return as part of our COPYUID response code */
	    char *appenduid, *b;

	    prot_printf(s->out, "\r\n");

	    res = pipe_until_tag(s, tag, 0);

	    if (res == PROXY_OK) {
		if (myrights & ACL_READ) {
		    appenduid = strchr(s->last_result.s, '[');
		    /* skip over APPENDUID */
		    appenduid += strlen("[appenduid ");
		    b = strchr(appenduid, ']');
		    *b = '\0';
		    prot_printf(imapd_out, "%s OK [COPYUID %s] %s\r\n", tag,
				appenduid, error_message(IMAP_OK_COMPLETED));
		} else {
		    prot_printf(imapd_out, "%s OK %s\r\n", tag,
				error_message(IMAP_OK_COMPLETED));
		}
	    } else {
		prot_printf(imapd_out, "%s %s", tag, s->last_result.s);
	    }
	} else {
	    /* abort the append */
	    prot_printf(s->out, " {0}\r\n");
	    pipe_until_tag(s, tag, 0);
	    
	    /* report failure */
	    prot_printf(imapd_out, "%s NO inter-server COPY failed\r\n", tag);
	}

	return;
    }

    /* local mailbox -> local mailbox */
    if (!r) {
	r = index_copy(imapd_mailbox, sequence, usinguid, mailboxname,
		       &copyuid, !config_getswitch(IMAPOPT_SINGLEINSTANCESTORE));
    }

    imapd_check(NULL, usinguid, 0);

  done:
    if (r && !(usinguid && r == IMAP_NO_NOSUCHMSG)) {
	prot_printf(imapd_out, "%s NO %s%s\r\n", tag,
		    (r == IMAP_MAILBOX_NONEXISTENT &&
		     mboxlist_createmailboxcheck(mailboxname, 0, 0,
						 imapd_userisadmin,
						 imapd_userid, imapd_authstate,
						 NULL, NULL, 0) == 0)
		    ? "[TRYCREATE] " : "", error_message(r));
    }
    else if (copyuid) {
	    prot_printf(imapd_out, "%s OK [COPYUID %s] %s\r\n", tag,
			copyuid, error_message(IMAP_OK_COMPLETED));
	    free(copyuid);
    }
    else {
	prot_printf(imapd_out, "%s OK %s\r\n", tag,
		    error_message(IMAP_OK_COMPLETED));
    }
}    

/*
 * Perform an EXPUNGE command
 * sequence == NULL if this isn't a UID EXPUNGE
 */
void cmd_expunge(char *tag, char *sequence)
{
    int r;

    if (backend_current) {
	/* remote mailbox */
	if (sequence) {
	    prot_printf(backend_current->out, "%s UID Expunge %s\r\n", tag,
			sequence);
	} else {
	    prot_printf(backend_current->out, "%s Expunge\r\n", tag);
	}
	pipe_including_tag(backend_current, tag, 0);
	return;
    }

    /* local mailbox */
    if (!(imapd_mailbox->myrights & ACL_EXPUNGE)) r = IMAP_PERMISSION_DENIED;
    else if (sequence) {
	struct seq_set *seq_set = index_parse_sequence(sequence, 1, NULL);

	r = mailbox_expunge(imapd_mailbox, index_expungeuidlist, seq_set, 0);
	freesequencelist(seq_set);
    }
    else {
	r = mailbox_expunge(imapd_mailbox, (mailbox_decideproc_t *)0,
			    (void *)0, 0);
    }

    index_check(imapd_mailbox, 0, 0);

    if (r) {
	prot_printf(imapd_out, "%s NO %s\r\n", tag, error_message(r));
    }
    else {
	prot_printf(imapd_out, "%s OK %s\r\n", tag,
		    error_message(IMAP_OK_COMPLETED));
        sync_log_mailbox(imapd_mailbox->name);
    }
}    

/*
 * Perform a CREATE command
 */
void cmd_create(char *tag, char *name, char *partition, int localonly)
{
    int r = 0;
    char mailboxname[MAX_MAILBOX_NAME+1];
    int autocreatequota;

    if (partition && !imapd_userisadmin) {
	r = IMAP_PERMISSION_DENIED;
    }

    if (name[0] && name[strlen(name)-1] == imapd_namespace.hier_sep) {
	/* We don't care about trailing hierarchy delimiters. */
	name[strlen(name)-1] = '\0';
    }

    if (!r) {
	r = (*imapd_namespace.mboxname_tointernal)(&imapd_namespace, name,
						   imapd_userid, mailboxname);
    }

    if (!r && !localonly && config_mupdate_server) {
	int guessedpart = 0;

	/* determine if we're creating locally or remotely */
	if (!partition) {
	    guessedpart = 1;
	    r = mboxlist_createmailboxcheck(mailboxname, 0, 0,
					    imapd_userisadmin,
					    imapd_userid, imapd_authstate,
					    NULL, &partition, 0);
	}

	if (!r && !config_partitiondir(partition)) {
	    /* invalid partition, assume its a server (remote mailbox) */
	    char *server;
	    struct backend *s = NULL;
	    int res;
 
	    /* check for a remote partition */
	    server = partition;
	    partition = strchr(server, '!');
	    if (partition) *partition++ = '\0';
	    if (guessedpart) partition = NULL;

	    s = proxy_findserver(server, &imap_protocol,
				 proxy_userid, &backend_cached,
				 &backend_current, &backend_inbox, imapd_in);
	    if (!s) r = IMAP_SERVER_UNAVAILABLE;

	    if (!r && imapd_userisadmin && supports_referrals) {
		/* They aren't an admin remotely, so let's refer them */
		imapd_refer(tag, server, name);
		referral_kick = 1;
		return;
	    }

	    if (!r) {
		if (!CAPA(s, CAPA_MUPDATE)) {
		    /* reserve mailbox on MUPDATE */
		}
	    }

	    if (!r) {
		/* ok, send the create to that server */
		if (partition) {
		    /* Send partition as an atom, since its all we accept */
		    prot_printf(s->out,
				"%s CREATE {%d+}\r\n%s %s\r\n", 
				tag, strlen(name), name, partition);
		}
		else
		    prot_printf(s->out, "%s CREATE {%d+}\r\n%s\r\n", 
				tag, strlen(name), name);
		res = pipe_until_tag(s, tag, 0);
	
		if (!CAPA(s, CAPA_MUPDATE)) {
		    /* do MUPDATE create operations */
		}
		/* make sure we've seen the update */
		if (ultraparanoid && res == PROXY_OK) kick_mupdate();
	    }
    
	    imapd_check(s, 0, 0);

	    if (r) {
		prot_printf(imapd_out, "%s NO %s\r\n", tag, error_message(r));
	    } else {
		/* we're allowed to reference last_result since the noop, if
		   sent, went to a different server */
		prot_printf(imapd_out, "%s %s", tag, s->last_result.s);
	    }

	    return;
	}
	else if (!r &&
		 (config_mupdate_config == IMAP_ENUM_MUPDATE_CONFIG_STANDARD) &&
		 !config_getstring(IMAPOPT_PROXYSERVERS)) {
	    /* can't create maiilboxes on proxy-only servers */
	    r = IMAP_PERMISSION_DENIED;
	}

	/* local mailbox -- fall through */
	if (guessedpart) partition = NULL;
    }

    /* local mailbox */
    if (!r) {
	/* xxx we do forced user creates on LOCALCREATE to facilitate
	 * mailbox moves */
	r = mboxlist_createmailbox(mailboxname, 0, partition,
				   imapd_userisadmin, 
				   imapd_userid, imapd_authstate,
				   localonly, localonly, 0);

	if (r == IMAP_PERMISSION_DENIED && !strcasecmp(name, "INBOX") &&
	    (autocreatequota = config_getint(IMAPOPT_AUTOCREATEQUOTA))) {

	    /* Auto create */
	    r = mboxlist_createmailbox(mailboxname, 0,
				       partition, 1, imapd_userid,
				       imapd_authstate, 0, 0, 0);
	    
	    if (!r && autocreatequota > 0) {
		(void) mboxlist_setquota(mailboxname, autocreatequota, 0);
	    }
	}
    }

    imapd_check(NULL, 0, 0);

    if (r) {
	prot_printf(imapd_out, "%s NO %s\r\n", tag, error_message(r));
    }
    else {
	if (config_mupdate_server &&
	    (config_mupdate_config != IMAP_ENUM_MUPDATE_CONFIG_STANDARD)) {
	    kick_mupdate();
	}

	prot_printf(imapd_out, "%s OK %s\r\n", tag,
		    error_message(IMAP_OK_COMPLETED));

	if ( !localonly ) {
	    if (mboxname_isusermailbox(mailboxname, 1))
		sync_log_user(mboxname_inbox_touserid(mailboxname));
	    else
		sync_log_mailbox(mailboxname);
	}
    }
}	

/* Callback for use by cmd_delete */
static int delmbox(char *name,
		   int matchlen __attribute__((unused)),
		   int maycreate __attribute__((unused)),
		   void *rock __attribute__((unused)))
{
    int r;

    if (!mboxlist_delayed_delete_isenabled()) {
        r = mboxlist_deletemailbox(name, imapd_userisadmin,
                                   imapd_userid, imapd_authstate,
                                   0, 0, 0);
    } else if (imapd_userisadmin && mboxname_isdeletedmailbox(name)) {
        r = mboxlist_deletemailbox(name, imapd_userisadmin,
                                   imapd_userid, imapd_authstate,
                                   0, 0, 0);
    } else {
        r = mboxlist_delayed_deletemailbox(name, imapd_userisadmin,
                                           imapd_userid, imapd_authstate,
                                           0, 0, 0);
    }
    
    if (!r) sync_log_mailbox(name);

    if(r) {
	prot_printf(imapd_out, "* NO delete %s: %s\r\n",
		    name, error_message(r));
    }
    
    return 0;
}

/*
 * Perform a DELETE command
 */
void cmd_delete(char *tag, char *name, int localonly, int force)
{
    int r;
    char mailboxname[MAX_MAILBOX_NAME+1];
    int mbtype;
    char *server;
    char *p;
    size_t domainlen = 0;

    r = (*imapd_namespace.mboxname_tointernal)(&imapd_namespace, name,
					       imapd_userid, mailboxname);

    if (!r) {
	r = mlookup(NULL, NULL, mailboxname, &mbtype, NULL, NULL,
		    &server, NULL, NULL);
    }

    if (!r && (mbtype & MBTYPE_REMOTE)) {
	/* remote mailbox */
	struct backend *s = NULL;
	int res;

	if (supports_referrals) { 
	    imapd_refer(tag, server, name);
	    referral_kick = 1;
	    return;
	}

	s = proxy_findserver(server, &imap_protocol,
			     proxy_userid, &backend_cached,
			     &backend_current, &backend_inbox, imapd_in);
	if (!s) r = IMAP_SERVER_UNAVAILABLE;

	if (!r) {
	    prot_printf(s->out, "%s DELETE {%d+}\r\n%s\r\n", 
			tag, strlen(name), name);
	    res = pipe_until_tag(s, tag, 0);

	    if (!CAPA(s, CAPA_MUPDATE) && res == PROXY_OK) {
		/* do MUPDATE delete operations */
	    }

	    /* make sure we've seen the update */
	    if (ultraparanoid && res == PROXY_OK) kick_mupdate();
	}

	imapd_check(s, 0, 0);

	if (r) {
	    prot_printf(imapd_out, "%s NO %s\r\n", tag, error_message(r));
	} else {
	    /* we're allowed to reference last_result since the noop, if
	       sent, went to a different server */
	    prot_printf(imapd_out, "%s %s", tag, s->last_result.s);
	}

	return;
    }

    /* local mailbox */
    if (!r) {
	if (config_virtdomains && (p = strchr(mailboxname, '!')))
	    domainlen = p - mailboxname + 1;

        if (localonly || !mboxlist_delayed_delete_isenabled()) {
            r = mboxlist_deletemailbox(mailboxname, imapd_userisadmin,
                                       imapd_userid, imapd_authstate, 
                                       1-force, localonly, 0);
        } else if (imapd_userisadmin &&
                   mboxname_isdeletedmailbox(mailboxname)) {
            r = mboxlist_deletemailbox(mailboxname, imapd_userisadmin,
                                       imapd_userid, imapd_authstate,
                                       0 /* checkacl */, localonly, 0);
        } else {
            r = mboxlist_delayed_deletemailbox(mailboxname, imapd_userisadmin,
                                               imapd_userid, imapd_authstate,
                                               1-force, localonly, 0);
        }
    }

    /* was it a top-level user mailbox? */
    /* localonly deletes are only per-mailbox */
    if (!r && !localonly &&
	!strncmp(mailboxname+domainlen, "user.", 5) &&
	!strchr(mailboxname+domainlen+5, '.')) {
 	size_t mailboxname_len = strlen(mailboxname);

 	/* If we aren't too close to MAX_MAILBOX_NAME, append .* */
 	p = mailboxname + mailboxname_len; /* end of mailboxname */
 	if (mailboxname_len < sizeof(mailboxname) - 3) {
 	    strcpy(p, ".*");
 	}
	
	/* build a list of mailboxes - we're using internal names here */
	mboxlist_findall(NULL, mailboxname, imapd_userisadmin, imapd_userid,
			 imapd_authstate, delmbox, NULL);

	/* take care of deleting ACLs, subscriptions, seen state and quotas */
	*p = '\0'; /* clip off pattern */
	if ((!domainlen) || 
	    (domainlen+1 < (sizeof(mailboxname) - mailboxname_len))) {
	    if (domainlen) {
		/* fully qualify the userid */
               snprintf(p, (sizeof(mailboxname) - mailboxname_len), "@%.*s", 
                        domainlen-1, mailboxname);
	    }
	    user_deletedata(mailboxname+domainlen+5, imapd_userid,
			    imapd_authstate, 1);

	    sync_log_user(mailboxname+domainlen+5);

	    *p = '\0'; /* clip off domain */
        }
    }

    imapd_check(NULL, 0, 0);

    if (r) {
	prot_printf(imapd_out, "%s NO %s\r\n", tag, error_message(r));
    }
    else {
	if (config_mupdate_server &&
	    (config_mupdate_config != IMAP_ENUM_MUPDATE_CONFIG_STANDARD)) {
	    kick_mupdate();
	}

	prot_printf(imapd_out, "%s OK %s\r\n", tag,
		    error_message(IMAP_OK_COMPLETED));

	sync_log_mailbox(mailboxname);
    }
}	

struct renrock 
{
    int ol;
    int nl;
    int rename_user;
    char *olduser, *newuser;
    char *acl_olduser, *acl_newuser;
    char *newmailboxname;
    char *partition;
};

/* Callback for use by cmd_rename */
static int renmbox(char *name,
		   int matchlen __attribute__((unused)),
		   int maycreate __attribute__((unused)),
		   void *rock)
{
    char oldextname[MAX_MAILBOX_NAME+1];
    char newextname[MAX_MAILBOX_NAME+1];
    struct renrock *text = (struct renrock *)rock;
    int r;

    if((text->nl + strlen(name + text->ol)) > MAX_MAILBOX_NAME)
	return 0;

    strcpy(text->newmailboxname + text->nl, name + text->ol);

    r = mboxlist_renamemailbox(name, text->newmailboxname,
			       text->partition,
			       1, imapd_userid, imapd_authstate, 0);
    
    (*imapd_namespace.mboxname_toexternal)(&imapd_namespace,
					   name,
					   imapd_userid, oldextname);
    (*imapd_namespace.mboxname_toexternal)(&imapd_namespace,
					   text->newmailboxname,
					   imapd_userid, newextname);

    if(r) {
	prot_printf(imapd_out, "* NO rename %s %s: %s\r\n",
		    oldextname, newextname, error_message(r));
	if (RENAME_STOP_ON_ERROR) return r;
    } else {
	/* If we're renaming a user, change quotaroot and ACL */
	if (text->rename_user) {
	    user_copyquotaroot(name, text->newmailboxname);
	    user_renameacl(text->newmailboxname,
			   text->acl_olduser, text->acl_newuser);
	}

	/* Rename mailbox annotations */
	annotatemore_rename(name, text->newmailboxname,
			    text->rename_user ? text->olduser : NULL,
			    text->newuser);
	
	prot_printf(imapd_out, "* OK rename %s %s\r\n",
		    oldextname, newextname);

        sync_log_mailbox_double(name, text->newmailboxname);
    }

    prot_flush(imapd_out);

    return 0;
}

/*
 * Perform a RENAME command
 */
void cmd_rename(char *tag, char *oldname, char *newname, char *partition)
{
    int r = 0;
    char oldmailboxname[MAX_MAILBOX_NAME+3];
    char newmailboxname[MAX_MAILBOX_NAME+2];
    char oldmailboxname2[MAX_MAILBOX_NAME+1];
    char newmailboxname2[MAX_MAILBOX_NAME+1];
    char oldextname[MAX_MAILBOX_NAME+1];
    char newextname[MAX_MAILBOX_NAME+1];
    int omlen, nmlen;
    int recursive_rename = 1;
    int rename_user = 0;
    char olduser[128], newuser[128];
    char acl_olduser[128], acl_newuser[128];
    int mbtype;
    char *server;

    if (partition && !imapd_userisadmin) {
	r = IMAP_PERMISSION_DENIED;
    }

    /* canonicalize names */
    r = (*imapd_namespace.mboxname_tointernal)(&imapd_namespace, oldname,
					       imapd_userid, oldmailboxname);
    if (!r)
	r = (*imapd_namespace.mboxname_tointernal)(&imapd_namespace, newname,
						   imapd_userid, newmailboxname);

    /* Keep temporary copy: master is trashed */
    strcpy(oldmailboxname2, oldmailboxname);
    strcpy(newmailboxname2, newmailboxname);

    if (!r) {
	r = mlookup(NULL, NULL, oldmailboxname, &mbtype, NULL, NULL,
		    &server, NULL, NULL);
    }

    if (!r && (mbtype & MBTYPE_REMOTE)) {
	/* remote mailbox */
	struct backend *s = NULL;
	int res;

	s = proxy_findserver(server, &imap_protocol,
			     proxy_userid, &backend_cached,
			     &backend_current, &backend_inbox, imapd_in);
	if (!s) r = IMAP_SERVER_UNAVAILABLE;

	/* xxx  start of separate proxy-only code
	   (remove when we move to a unified environment) */

	/* Cross Server Rename */
	if (!r && partition) {
	    char *destpart;
	
	    if (strcmp(oldname, newname)) {
		prot_printf(imapd_out,
			    "%s NO Cross-server or cross-partition move w/rename not supported\r\n",
			    tag);
		return;
	    }

	    /* dest partition? */

	    destpart = strchr(partition,'!');
	    if (destpart) {
		char newserver[MAX_MAILBOX_NAME+1];	    
		if (strlen(partition) >= sizeof(newserver)) {
		    prot_printf(imapd_out,
				"%s NO Partition name too long\r\n", tag);
		    return;
		}
		strcpy(newserver,partition);
		newserver[destpart-partition]='\0';
		destpart++;

		if (!strcmp(server, newserver)) {
		    /* Same Server, different partition */
		    /* xxx this would require administrative access to the
		     * backend, which we won't get */
		    prot_printf(imapd_out,
				"%s NO Can't move across partitions via a proxy\r\n",
				tag);
		    return;
		} else {
		    /* Cross Server */
		    /* <tag> XFER <name> <dest server> <dest partition> */
		    prot_printf(s->out,
				"%s XFER {%d+}\r\n%s {%d+}\r\n%s {%d+}\r\n%s\r\n", 
				tag, strlen(oldname), oldname,
				strlen(newserver), newserver,
				strlen(destpart), destpart);
		}
	    
	    } else {
		/* <tag> XFER <name> <dest server> */
		prot_printf(s->out, "%s XFER {%d+}\r\n%s {%d+}\r\n%s\r\n", 
			    tag, strlen(oldname), oldname,
			    strlen(partition), partition);
	    }

	    res = pipe_including_tag(s, tag, 0);

	    /* make sure we've seen the update */
	    if (ultraparanoid && res == PROXY_OK) kick_mupdate();

	    return;
	}
	/* xxx  end of separate proxy-only code */

	if (!r) {
	    if (!CAPA(s, CAPA_MUPDATE)) {
		/* do MUPDATE create operations for new mailbox */
	    }

	    prot_printf(s->out, "%s RENAME {%d+}\r\n%s {%d+}\r\n%s\r\n", 
			tag, strlen(oldname), oldname,
			strlen(newname), newname);
	    res = pipe_until_tag(s, tag, 0);
	
	    if (!CAPA(s, CAPA_MUPDATE)) {
		/* Activate/abort new mailbox in MUPDATE*/
		/* delete old mailbox from MUPDATE */
	    }

	    /* make sure we've seen the update */
	    if (res == PROXY_OK) kick_mupdate();
	}

	imapd_check(s, 0, 0);

	if (r) {
	    prot_printf(imapd_out, "%s NO %s\r\n", tag, error_message(r));
	} else {
	    /* we're allowed to reference last_result since the noop, if
	       sent, went to a different server */
	    prot_printf(imapd_out, "%s %s", tag, s->last_result.s);
	}

	return;
    }

    /* local mailbox */

    if (!r && partition && !config_partitiondir(partition)) {
	/* invalid partition, assume its a server (remote destination) */
	char *server;
 
	if (strcmp(oldname, newname)) {
	    prot_printf(imapd_out,
			"%s NO Cross-server or cross-partition move w/rename not supported\r\n",
			tag);
	    return;
	}

	/* dest partition? */
	server = partition;
	partition = strchr(server, '!');
	if (partition) *partition++ = '\0';

	cmd_xfer(tag, oldname, server, partition);

	return;
    }

    /* local destination */

    /* if this is my inbox, don't do recursive renames */
    if (!strcasecmp(oldname, "inbox")) {
	recursive_rename = 0;
    }
    /* check if we're an admin renaming a user */
    else if (config_getswitch(IMAPOPT_ALLOWUSERMOVES) &&
	     mboxname_isusermailbox(oldmailboxname, 1) &&
	     mboxname_isusermailbox(newmailboxname, 1) &&
	     strcmp(oldmailboxname, newmailboxname) && /* different user */
	     imapd_userisadmin) {
	rename_user = 1;
    }

    /* if we're renaming something inside of something else, 
       don't recursively rename stuff */
    omlen = strlen(oldmailboxname);
    nmlen = strlen(newmailboxname);
    if (omlen < nmlen) {
	if (!strncmp(oldmailboxname, newmailboxname, omlen) &&
	    newmailboxname[omlen] == '.') {
	    recursive_rename = 0;
	}
    } else {
	if (!strncmp(oldmailboxname, newmailboxname, nmlen) &&
	    oldmailboxname[nmlen] == '.') {
	    recursive_rename = 0;
	}
    }

    /* attempt to rename the base mailbox */
    if (!r) {
	r = mboxlist_renamemailbox(oldmailboxname, newmailboxname, partition,
				   imapd_userisadmin, 
				   imapd_userid, imapd_authstate, 0);
    }

    /* If we're renaming a user, take care of changing quotaroot, ACL,
       seen state, subscriptions and sieve scripts */
    if (!r && rename_user) {
	char *domain;

	/* create canonified userids */

	domain = strchr(oldmailboxname, '!');
	strcpy(olduser, domain ? domain+6 : oldmailboxname+5);
	if (domain)
	    sprintf(olduser+strlen(olduser), "@%.*s",
		    domain - oldmailboxname, oldmailboxname);
	strcpy(acl_olduser, olduser);

	/* Translate any separators in source old userid (for ACLs) */
	mboxname_hiersep_toexternal(&imapd_namespace, acl_olduser,
				    config_virtdomains ?
				    strcspn(acl_olduser, "@") : 0);

	domain = strchr(newmailboxname, '!');
	strcpy(newuser, domain ? domain+6 : newmailboxname+5);
	if (domain)
	    sprintf(newuser+strlen(newuser), "@%.*s",
		    domain - newmailboxname, newmailboxname);
	strcpy(acl_newuser, newuser);

	/* Translate any separators in destination new userid (for ACLs) */
	mboxname_hiersep_toexternal(&imapd_namespace, acl_newuser,
				    config_virtdomains ?
				    strcspn(acl_newuser, "@") : 0);

	user_copyquotaroot(oldmailboxname, newmailboxname);
	user_renameacl(newmailboxname, acl_olduser, acl_newuser);
	user_renamedata(olduser, newuser, imapd_userid, imapd_authstate);

	/* XXX report status/progress of meta-data */
    }

    if (!r) {
	/* Rename mailbox annotations */
	annotatemore_rename(oldmailboxname, newmailboxname,
			    rename_user ? olduser : NULL,
			    newuser);
    }

    /* rename all mailboxes matching this */
    if (!r && recursive_rename) {
	struct renrock rock;
	int ol = omlen + 1;
	int nl = nmlen + 1;

	(*imapd_namespace.mboxname_toexternal)(&imapd_namespace,
					       oldmailboxname,
					       imapd_userid, oldextname);
	(*imapd_namespace.mboxname_toexternal)(&imapd_namespace,
					       newmailboxname,
					       imapd_userid, newextname);

	prot_printf(imapd_out, "* OK rename %s %s\r\n",
		    oldextname, newextname);
	prot_flush(imapd_out);

	strcat(oldmailboxname, ".*");
	strcat(newmailboxname, ".");

	/* setup the rock */
	rock.newmailboxname = newmailboxname;
	rock.ol = ol;
	rock.nl = nl;
	rock.olduser = olduser;
	rock.newuser = newuser;
	rock.acl_olduser = acl_olduser;
	rock.acl_newuser = acl_newuser;
	rock.partition = partition;
	rock.rename_user = rename_user;
	
	/* add submailboxes; we pretend we're an admin since we successfully
	   renamed the parent - we're using internal names here */
	r = mboxlist_findall(NULL, oldmailboxname, 1, imapd_userid,
			     imapd_authstate, renmbox, &rock);
    }

    /* take care of deleting old ACLs, subscriptions, seen state and quotas */
    if (!r && rename_user)
	user_deletedata(olduser, imapd_userid, imapd_authstate, 1);

    imapd_check(NULL, 0, 0);

    if (r) {
	prot_printf(imapd_out, "%s NO %s\r\n", tag, error_message(r));
    } else {
	if (config_mupdate_server &&
	    (config_mupdate_config != IMAP_ENUM_MUPDATE_CONFIG_STANDARD)) {
	    kick_mupdate();
	}

	prot_printf(imapd_out, "%s OK %s\r\n", tag,
		    error_message(IMAP_OK_COMPLETED));
        sync_log_mailbox_double(oldmailboxname2, newmailboxname2);

	/* if user is renaming inbox, sync seen state on new mailbox */
	if (!strcasecmp(oldname, "inbox")) {
	    /* XXX  Need to check for sharedseen somehow */
	    sync_log_seen(imapd_userid, newmailboxname2);
	}
    }
}	

/*
 * Perform a RECONSTRUCT command
 */
void cmd_reconstruct(const char *tag, const char *name, int recursive)
{
    int r = 0;
    char mailboxname[MAX_MAILBOX_NAME+1];
    char quotaroot[MAX_MAILBOX_NAME+1];
    int mbtype;
    char *server;
    struct mailbox mailbox;

    /* administrators only please */
    if (!imapd_userisadmin) {
	r = IMAP_PERMISSION_DENIED;
    }

    if (!r) {
	r = (*imapd_namespace.mboxname_tointernal)(&imapd_namespace, name,
						   imapd_userid, mailboxname);
    }
    
    if (!r) {
	r = mlookup(tag, name, mailboxname, &mbtype, NULL, NULL,
		    &server, NULL, NULL);
    }
    if (r == IMAP_MAILBOX_MOVED) return;

    if (!r && (mbtype & MBTYPE_REMOTE)) {
	/* remote mailbox */
	imapd_refer(tag, server, name);
	return;
    }

    /* local mailbox */
    if (!r) {
	int pid;
	    
	/* Reconstruct it */

	pid = fork();
	if(pid == -1) {
	    r = IMAP_SYS_ERROR;
	} else if(pid == 0) {
	    char buf[4096];
	    int ret;
	    
	    /* Child - exec reconstruct*/	    
	    syslog(LOG_NOTICE, "Reconstructing '%s' (%s) for user '%s'",
		   mailboxname, recursive ? "recursive" : "not recursive",
		   imapd_userid);

	    fclose(stdin);
	    fclose(stdout);
	    fclose(stderr);

	    ret = snprintf(buf, sizeof(buf), "%s/reconstruct", SERVICE_PATH);
	    if(ret < 0 || ret >= (int) sizeof(buf)) {
		/* in child, so fatailing won't disconnect our user */ 
	        fatal("reconstruct buffer not sufficiently big", EC_CONFIG);
	    }

	    if(recursive) {
		execl(buf, buf, "-C", config_filename, "-r", "-f",
		      mailboxname, NULL);
	    } else {
		execl(buf, buf, "-C", config_filename, mailboxname, NULL);
	    }
	    
	    /* if we are here, we have a problem */
	    exit(-1);
	} else {
	    int status;

	    /* Parent, wait on child */
	    if(waitpid(pid, &status, 0) < 0) r = IMAP_SYS_ERROR;

	    /* Did we fail? */
	    if(WEXITSTATUS(status) != 0) r = IMAP_SYS_ERROR;
	}
    }

    /* Still in parent, need to re-quota the mailbox*/

    /* Find its quota root */
    if (!r) {
	r = mailbox_open_header(mailboxname, imapd_authstate, &mailbox);
    }

    if(!r) {
	if(mailbox.quota.root) {
	    strcpy(quotaroot, mailbox.quota.root);
	} else {
	    strcpy(quotaroot, mailboxname);
	}
	mailbox_close(&mailbox);
    }
    
    /* Run quota -f */
    if (!r) {
	int pid;

	pid = fork();
	if(pid == -1) {
	    r = IMAP_SYS_ERROR;
	} else if(pid == 0) {
	    char buf[4096];
	    int ret;
	    
	    /* Child - exec reconstruct*/	    
	    syslog(LOG_NOTICE,
		   "Regenerating quota roots starting with '%s' for user '%s'",
		   mailboxname, imapd_userid);

	    fclose(stdin);
	    fclose(stdout);
	    fclose(stderr);

	    ret = snprintf(buf, sizeof(buf), "%s/quota", SERVICE_PATH);
	    if(ret < 0 || ret >= (int) sizeof(buf)) {
		/* in child, so fatailing won't disconnect our user */ 
	        fatal("quota buffer not sufficiently big", EC_CONFIG);
	    }

	    execl(buf, buf, "-C", config_filename, "-f", quotaroot, NULL);
	    
	    /* if we are here, we have a problem */
	    exit(-1);
	} else {
	    int status;

	    /* Parent, wait on child */
	    if(waitpid(pid, &status, 0) < 0) r = IMAP_SYS_ERROR;

	    /* Did we fail? */
	    if(WEXITSTATUS(status) != 0) r = IMAP_SYS_ERROR;
	}
    }

    if (r) {
	prot_printf(imapd_out, "%s NO %s\r\n", tag, error_message(r));
    } else {
	prot_printf(imapd_out, "%s OK %s\r\n", tag,
		    error_message(IMAP_OK_COMPLETED));
        sync_log_mailbox(mailboxname);
    }
}	

/*
 * Perform a FIND command
 */
void cmd_find(char *tag, char *namespace, char *pattern)
{
    char *p;
    lcase(namespace);

    for (p = pattern; *p; p++) {
	if (*p == '%') *p = '?';
    }

    if (!strcasecmp(namespace, "mailboxes")) {
	if (backend_inbox || (backend_inbox = proxy_findinboxserver())) {
	    /* remote INBOX */
	    prot_printf(backend_inbox->out, 
			"%s Lsub \"\" {%d+}\r\n%s\r\n",
			tag, strlen(pattern), pattern);
	    pipe_lsub(backend_inbox, tag, 0, "MAILBOX");
	} else {
	    /* local INBOX */
	    int force = config_getswitch(IMAPOPT_ALLOWALLSUBSCRIBE);

	    /* Translate any separators in pattern */
	    mboxname_hiersep_tointernal(&imapd_namespace, pattern,
					config_virtdomains ?
					strcspn(pattern, "@") : 0);

	    (*imapd_namespace.mboxlist_findsub)(&imapd_namespace, pattern,
						imapd_userisadmin, imapd_userid,
						imapd_authstate, mailboxdata,
						NULL, force);
	}
    }
    else if (!strcasecmp(namespace, "all.mailboxes")) {
	/* Translate any separators in pattern */
	mboxname_hiersep_tointernal(&imapd_namespace, pattern,
				    config_virtdomains ?
				    strcspn(pattern, "@") : 0);

	(*imapd_namespace.mboxlist_findall)(&imapd_namespace, pattern,
					    imapd_userisadmin, imapd_userid,
					    imapd_authstate, mailboxdata, NULL);
    }
    else if (!strcasecmp(namespace, "bboards")
	     || !strcasecmp(namespace, "all.bboards")) {
	;
    }
    else {
	prot_printf(imapd_out, "%s BAD Invalid FIND subcommand\r\n", tag);
	return;
    }

    imapd_check(backend_inbox, 0, 0);

    prot_printf(imapd_out, "%s OK %s\r\n", tag,
		error_message(IMAP_OK_COMPLETED));
}

static int mstringdatacalls;

/*
 * Perform a LIST or LSUB command
 */
void cmd_list(char *tag, struct listargs *listargs)
{
    static int ignorereference = 0;
    clock_t start = clock();
    char mytime[100];
    int (*findall)(struct namespace *namespace,
		   const char *pattern, int isadmin, char *userid, 
		   struct auth_state *auth_state, int (*proc)(),
		   void *rock);
    int (*findsub)(struct namespace *namespace,
		   const char *pattern, int isadmin, char *userid, 
		   struct auth_state *auth_state, int (*proc)(),
		   void *rock, int force);

    if (listargs->opts & LIST_REMOTE) {
	if (!config_getswitch(IMAPOPT_PROXYD_DISABLE_MAILBOX_REFERRALS)) {
	    supports_referrals = !disable_referrals;
	}
    }

    /* Ignore the reference argument?
       (the behavior in 1.5.10 & older) */
    if (ignorereference == 0) {
	ignorereference = config_getswitch(IMAPOPT_IGNOREREFERENCE);
    }

    /* Reset state in mstringdata */
    mstringdata(NULL, NULL, 0, 0, 0);

    if (!listargs->pat[0] && !(listargs->opts & LIST_LSUB)) {
	/* Special case: query top-level hierarchy separator */
	prot_printf(imapd_out, "* LIST (\\Noselect) \"%c\" \"\"\r\n",
		    imapd_namespace.hier_sep);
    } else if ((listargs->opts & (LIST_LSUB | LIST_SUBSCRIBED)) &&
	       (backend_inbox || (backend_inbox = proxy_findinboxserver()))) {
	/* remote INBOX */
	if ((listargs->opts & LIST_SUBSCRIBED) && (listargs->opts & LIST_EXT) &&
	    CAPA(backend_inbox, CAPA_LISTSUBSCRIBED)) {
	    prot_printf(backend_inbox->out, "%s List (subscribed", tag);
	    if (listargs->opts & LIST_CHILDREN)
		prot_printf(backend_inbox->out, " children");
	    if (listargs->opts & LIST_REMOTE)
		prot_printf(backend_inbox->out, " remote");
	    prot_printf(backend_inbox->out, ") ");
	} else {
	    prot_printf(backend_inbox->out, "%s Lsub ", tag);
	}
	prot_printf(backend_inbox->out, 
		    "{%d+}\r\n%s {%d+}\r\n%s\r\n",
		    strlen(listargs->ref), listargs->ref,
		    strlen(listargs->pat), listargs->pat);
	pipe_lsub(backend_inbox, tag, 0,
		  (listargs->opts & LIST_LSUB) ? "LSUB" : "LIST");
    } else {
	char *pattern = NULL;

	/* Do we need to concatenate fields? */
	if (!ignorereference || listargs->pat[0] == imapd_namespace.hier_sep) {
	    /* Either
	     * - name begins with dot
	     * - we're configured to honor the reference argument */

	    /* Allocate a buffer, figure out how to stick the arguments
	       together, do it, then do that instead of using pattern. */
	    int patlen = strlen(listargs->pat);
	    int reflen = strlen(listargs->ref);
	    
	    pattern = xmalloc(patlen + reflen + 1);
	    pattern[0] = '\0';

	    if (*listargs->ref) {
		strcpy(pattern, listargs->ref);
		/* check for LIST A. .B, change to LIST "" A.B */
		if (listargs->ref[reflen-1] == imapd_namespace.hier_sep &&
		    listargs->pat[0] == imapd_namespace.hier_sep) {
		    pattern[--reflen] = '\0';
		}
	    }
	    strcat(pattern, listargs->pat);
	} else {
	    pattern = xstrdup(listargs->pat);
	}

	/* Translate any separators in pattern */
	mboxname_hiersep_tointernal(&imapd_namespace, pattern,
				    config_virtdomains ?
				    strcspn(pattern, "@") : 0);

	/* Check to see if we should only list the personal namespace */
	if (!strcmp(pattern, "*")
	    && config_getswitch(IMAPOPT_FOOLSTUPIDCLIENTS)) {
	    if (pattern) free(pattern);
	    pattern = xstrdup("INBOX*");
	    findsub = mboxlist_findsub;
	    findall = mboxlist_findall;
	}
	else {
	    findsub = imapd_namespace.mboxlist_findsub;
	    findall = imapd_namespace.mboxlist_findall;
	}

	if (listargs->opts & (LIST_LSUB | LIST_SUBSCRIBED)) {
	    int force = config_getswitch(IMAPOPT_ALLOWALLSUBSCRIBE);

	    (*findsub)(&imapd_namespace, pattern,
		       imapd_userisadmin, imapd_userid, imapd_authstate,
		       listdata, listargs, force);
	}
	else {
	    if (listargs->scan) {
		construct_hash_table(&listargs->server_table, 10, 1);
	    }

	    (*findall)(&imapd_namespace, pattern,
		       imapd_userisadmin, imapd_userid, imapd_authstate,
		       listdata, listargs);

	    free_hash_table(&listargs->server_table, NULL);
	}

	listdata((char *)0, 0, 0, listargs);

	if (pattern) free(pattern);
    }

    if (listargs->scan && imapd_mailbox) {
	/* SCAN will mess with the globals in index.c,
	   so reset them for our currently mailbox */
	index_operatemailbox(imapd_mailbox);
    }

    imapd_check(!(listargs->opts & (LIST_LSUB | LIST_SUBSCRIBED)) ?
		backend_inbox : NULL, 0, 0);

    snprintf(mytime, sizeof(mytime), "%2.3f",
	     (clock() - start) / (double) CLOCKS_PER_SEC);
    prot_printf(imapd_out, "%s OK %s (%s secs %d calls)\r\n", tag,
		error_message(IMAP_OK_COMPLETED), mytime, mstringdatacalls);
}
  
/*
 * Perform a SUBSCRIBE (add is nonzero) or
 * UNSUBSCRIBE (add is zero) command
 */
void cmd_changesub(char *tag, char *namespace, char *name, int add)
{
    const char *cmd = add ? "Subscribe" : "Unsubscribe";
    int r = 0;
    char mailboxname[MAX_MAILBOX_NAME+1];
    int force = config_getswitch(IMAPOPT_ALLOWALLSUBSCRIBE);

    if (backend_inbox || (backend_inbox = proxy_findinboxserver())) {
	/* remote INBOX */
	if (add) {
	    r = (*imapd_namespace.mboxname_tointernal)(&imapd_namespace,
						       name, imapd_userid,
						       mailboxname);
	    if (!r) r = mlookup(NULL, NULL, mailboxname,
				NULL, NULL, NULL, NULL, NULL, NULL);

	    /* Doesn't exist on murder */
	}

	imapd_check(backend_inbox, 0, 0);

	if (!r) {
	    if (namespace) {
		prot_printf(backend_inbox->out, 
			    "%s %s {%d+}\r\n%s {%d+}\r\n%s\r\n", 
			    tag, cmd, 
			    strlen(namespace), namespace,
			    strlen(name), name);
	    } else {
		prot_printf(backend_inbox->out, "%s %s {%d+}\r\n%s\r\n", 
			    tag, cmd, 
			    strlen(name), name);
	    }
	    pipe_including_tag(backend_inbox, tag, 0);
	}
	else {
	    prot_printf(imapd_out, "%s NO %s\r\n", tag, error_message(r));
	}

	return;
    }

    /* local INBOX */
    if (namespace) lcase(namespace);
    if (!namespace || !strcmp(namespace, "mailbox")) {
	size_t len = strlen(name);
	if (force && imapd_namespace.isalt &&
	    (((len == strlen(imapd_namespace.prefix[NAMESPACE_USER]) - 1) &&
	      !strncmp(name, imapd_namespace.prefix[NAMESPACE_USER], len)) ||
	     ((len == strlen(imapd_namespace.prefix[NAMESPACE_SHARED]) - 1) &&
	      !strncmp(name, imapd_namespace.prefix[NAMESPACE_SHARED], len)))) {
	    r = 0;
	}
	else {
	    r = (*imapd_namespace.mboxname_tointernal)(&imapd_namespace, name,
						       imapd_userid, mailboxname);
	    if (!r) {
		r = mboxlist_changesub(mailboxname, imapd_userid, 
				       imapd_authstate, add, force);
	    }
	}
    }
    else if (!strcmp(namespace, "bboard")) {
	r = add ? IMAP_MAILBOX_NONEXISTENT : 0;
    }
    else {
	prot_printf(imapd_out, "%s BAD Invalid %s subcommand\r\n", tag, cmd);
	return;
    }

    imapd_check(NULL, 0, 0);

    if (r) {
	prot_printf(imapd_out, "%s NO %s: %s\r\n", tag, cmd, error_message(r));
    }
    else {
	prot_printf(imapd_out, "%s OK %s\r\n", tag,
		    error_message(IMAP_OK_COMPLETED));
        sync_log_subscribe(imapd_userid, mailboxname, add);
    }
}

/*
 * Perform a GETACL command
 */
void cmd_getacl(const char *tag, const char *name)
{
    char mailboxname[MAX_MAILBOX_NAME+1];
    int r, access;
    char *acl;
    char *rights, *nextid;

    r = (*imapd_namespace.mboxname_tointernal)(&imapd_namespace, name,
					       imapd_userid, mailboxname);

    if (!r) {
	r = mlookup(tag, name, mailboxname, NULL, NULL, NULL, NULL, &acl, NULL);
    }
    if (r == IMAP_MAILBOX_MOVED) return;

    if (!r) {
	access = cyrus_acl_myrights(imapd_authstate, acl);

	if (!(access & ACL_ADMIN) &&
	    !imapd_userisadmin &&
	    !mboxname_userownsmailbox(imapd_userid, mailboxname)) {
	    r = (access&ACL_LOOKUP) ?
	      IMAP_PERMISSION_DENIED : IMAP_MAILBOX_NONEXISTENT;
	}
    }

    imapd_check(NULL, 0, 0);

    if (r) {
	prot_printf(imapd_out, "%s NO %s\r\n", tag, error_message(r));
	return;
    }
    
    prot_printf(imapd_out, "* ACL ");
    printastring(name);
    
    while (acl) {
	rights = strchr(acl, '\t');
	if (!rights) break;
	*rights++ = '\0';
	
	nextid = strchr(rights, '\t');
	if (!nextid) break;
	*nextid++ = '\0';
	
	prot_printf(imapd_out, " ");
	printastring(acl);
	prot_printf(imapd_out, " ");
	printastring(rights);
	acl = nextid;
    }
    prot_printf(imapd_out, "\r\n");
    prot_printf(imapd_out, "%s OK %s\r\n", tag,
		error_message(IMAP_OK_COMPLETED));
}

/*
 * Perform a LISTRIGHTS command
 */
void
cmd_listrights(tag, name, identifier)
char *tag;
char *name;
char *identifier;
{
    char mailboxname[MAX_MAILBOX_NAME+1];
    int r, rights;
    char *acl;

    r = (*imapd_namespace.mboxname_tointernal)(&imapd_namespace, name,
					       imapd_userid, mailboxname);

    if (!r) {
	r = mlookup(tag, name, mailboxname, NULL, NULL, NULL, NULL, &acl, NULL);
    }
    if (r == IMAP_MAILBOX_MOVED) return;

    if (!r) {
	rights = cyrus_acl_myrights(imapd_authstate, acl);

	if (!rights && !imapd_userisadmin &&
	    !mboxname_userownsmailbox(imapd_userid, mailboxname)) {
	    r = IMAP_MAILBOX_NONEXISTENT;
	}
    }

    imapd_check(NULL, 0, 0);

    if (!r) {
	struct auth_state *authstate = auth_newstate(identifier);
	char *canon_identifier;
	int canonidlen = 0;
	int implicit;
	char rightsdesc[100], optional[33];

	if (global_authisa(authstate, IMAPOPT_ADMINS))
	    canon_identifier = identifier; /* don't canonify global admins */
	else
	    canon_identifier = canonify_userid(identifier, imapd_userid, NULL);
	auth_freestate(authstate);

	if (canon_identifier) canonidlen = strlen(canon_identifier);

	if (!canon_identifier) {
	    implicit = 0;
	}
	else if (mboxname_userownsmailbox(canon_identifier, mailboxname)) {
	    /* identifier's personal mailbox */
	    implicit = config_implicitrights;
	}
	else if (mboxname_isusermailbox(mailboxname, 1)) {
	    /* anyone can post to an INBOX */
	    implicit = ACL_POST;
	}
	else {
	    implicit = 0;
	}

	/* calculate optional rights */
	cyrus_acl_masktostr(implicit ^ (canon_identifier ? ACL_FULL : 0),
			    optional);

	/* build the rights string */
	if (implicit) {
	    cyrus_acl_masktostr(implicit, rightsdesc);
	}
	else {
	    strcpy(rightsdesc, "\"\"");
	}

	if (*optional) {
	    int i, n = strlen(optional);
	    char *p = rightsdesc + strlen(rightsdesc);

	    for (i = 0; i < n; i++) {
		*p++ = ' ';
		*p++ = optional[i];
	    }
	    *p = '\0';
	}

	prot_printf(imapd_out, "* LISTRIGHTS ");
	printastring(name);
	prot_putc(' ', imapd_out);
	printastring(identifier);
	prot_printf(imapd_out, " %s", rightsdesc);

	prot_printf(imapd_out, "\r\n%s OK %s\r\n", tag,
		    error_message(IMAP_OK_COMPLETED));
	return;
    }

    prot_printf(imapd_out, "%s NO %s\r\n", tag, error_message(r));
}

/*
 * Perform a MYRIGHTS command
 */
void cmd_myrights(const char *tag, const char *name)
{
    char mailboxname[MAX_MAILBOX_NAME+1];
    int r, rights = 0;
    char *acl;
    char str[ACL_MAXSTR];

    r = (*imapd_namespace.mboxname_tointernal)(&imapd_namespace, name,
					       imapd_userid, mailboxname);

    if (!r) {
	r = mlookup(tag, name, mailboxname, NULL, NULL, NULL, NULL, &acl, NULL);
    }
    if (r == IMAP_MAILBOX_MOVED) return;

    if (!r) {
	rights = cyrus_acl_myrights(imapd_authstate, acl);

	/* Add in implicit rights */
	if (imapd_userisadmin) {
	    rights |= ACL_LOOKUP|ACL_ADMIN;
	}
	else if (mboxname_userownsmailbox(imapd_userid, mailboxname)) {
	    rights |= config_implicitrights;
	}

	if (!(rights & (ACL_LOOKUP|ACL_READ|ACL_INSERT|ACL_CREATE|ACL_DELETEMBOX|ACL_ADMIN))) {
	    r = IMAP_MAILBOX_NONEXISTENT;
	}
    }

    imapd_check(NULL, 0, 0);

    if (r) {
	prot_printf(imapd_out, "%s NO %s\r\n", tag, error_message(r));
	return;
    }
    
    prot_printf(imapd_out, "* MYRIGHTS ");
    printastring(name);
    prot_printf(imapd_out, " ");
    printastring(cyrus_acl_masktostr(rights, str));
    prot_printf(imapd_out, "\r\n%s OK %s\r\n", tag,
		error_message(IMAP_OK_COMPLETED));
}

/*
 * Perform a SETACL command
 */
void cmd_setacl(char *tag, const char *name,
		const char *identifier, const char *rights)
{
    int r;
    char mailboxname[MAX_MAILBOX_NAME+1];
    char *server;
    int mbtype;

    r = (*imapd_namespace.mboxname_tointernal)(&imapd_namespace, name,
					       imapd_userid, mailboxname);

    /* is it remote? */
    if (!r) {
	r = mlookup(tag, name, mailboxname, &mbtype, NULL, NULL,
		    &server, NULL, NULL);
    }
    if (r == IMAP_MAILBOX_MOVED) return;

    if (!r && (mbtype & MBTYPE_REMOTE)) {
	/* remote mailbox */
	struct backend *s = NULL;
	int res;

	s = proxy_findserver(server, &imap_protocol,
			     proxy_userid, &backend_cached,
			     &backend_current, &backend_inbox, imapd_in);
	if (!s) r = IMAP_SERVER_UNAVAILABLE;

	if (!r && imapd_userisadmin && supports_referrals) {
	    /* They aren't an admin remotely, so let's refer them */
	    imapd_refer(tag, server, name);
	    referral_kick = 1;
	    return;
	} else if (!r) {
	    if (rights) {
		prot_printf(s->out, 
			    "%s Setacl {%d+}\r\n%s {%d+}\r\n%s {%d+}\r\n%s\r\n",
			    tag, strlen(name), name,
			    strlen(identifier), identifier,
			    strlen(rights), rights);
	    } else {
		prot_printf(s->out, 
			    "%s Deleteacl {%d+}\r\n%s {%d+}\r\n%s\r\n",
			    tag, strlen(name), name,
			    strlen(identifier), identifier);
	    }
	    res = pipe_until_tag(s, tag, 0);

	    if (!CAPA(s, CAPA_MUPDATE) && res == PROXY_OK) {
		/* setup new ACL in MUPDATE */
	    }
	    /* make sure we've seen the update */
	    if (ultraparanoid && res == PROXY_OK) kick_mupdate();
	}

	imapd_check(s, 0, 0);

	if (r) {
	    prot_printf(imapd_out, "%s NO %s\r\n", tag, error_message(r));
	} else {
	    /* we're allowed to reference last_result since the noop, if
	       sent, went to a different server */
	    prot_printf(imapd_out, "%s %s", tag, s->last_result.s);
	}

	return;
    }

    /* local mailbox */
    if (!r) {
	r = mboxlist_setacl(mailboxname, identifier, rights,
			    imapd_userisadmin, imapd_userid, imapd_authstate);
    }

    imapd_check(NULL, 0, 0);

    if (r) {
	prot_printf(imapd_out, "%s NO %s\r\n", tag, error_message(r));
    } else {
	if (config_mupdate_server &&
	    (config_mupdate_config != IMAP_ENUM_MUPDATE_CONFIG_STANDARD)) {
	    kick_mupdate();
	}

	prot_printf(imapd_out, "%s OK %s\r\n", tag,
		    error_message(IMAP_OK_COMPLETED));
	sync_log_acl(mailboxname);
    }
}

/*
 * Callback for (get|set)quota, to ensure that all of the
 * submailboxes are on the same server.
 */
static int quota_cb(char *name, int matchlen __attribute__((unused)),
		    int maycreate __attribute__((unused)), void *rock) 
{
    int r;
    char *this_server;
    const char *servername = (const char *)rock;
    
    r = mlookup(NULL, NULL, name, NULL, NULL, NULL, &this_server, NULL, NULL);
    if(r) return r;

    if(strcmp(servername, this_server)) {
	/* Not on same server as the root */
	return IMAP_NOT_SINGULAR_ROOT;
    } else {
	return PROXY_OK;
    }
}

/*
 * Perform a GETQUOTA command
 */
void cmd_getquota(const char *tag, const char *name)
{
    int r;
    struct quota quota;
    char quotarootbuf[MAX_MAILBOX_PATH+3];
    char mailboxname[MAX_MAILBOX_NAME+1];
    int mbtype;
    char *server_rock = NULL, *server_rock_tmp = NULL;

    imapd_check(NULL, 0, 0);

    if (!imapd_userisadmin) r = IMAP_PERMISSION_DENIED;
    else {
	r = (*imapd_namespace.mboxname_tointernal)(&imapd_namespace, name,
						   imapd_userid, mailboxname);
    }

    if (!r) {
    	r = mlookup(NULL, NULL, mailboxname, &mbtype, NULL, NULL,
		    &server_rock_tmp, NULL, NULL);
    }

    if (!r && (mbtype & MBTYPE_REMOTE)) {
	/* remote mailbox */
	server_rock = xstrdup(server_rock_tmp);

	snprintf(quotarootbuf, sizeof(quotarootbuf), "%s.*", mailboxname);

	r = mboxlist_findall(&imapd_namespace, quotarootbuf,
			     imapd_userisadmin, imapd_userid,
			     imapd_authstate, quota_cb, server_rock);

	if (!r) {
	    /* Do the referral */
	    imapd_refer(tag, server_rock, name);
	    free(server_rock);
	} else {
	    if(server_rock) free(server_rock);
	    prot_printf(imapd_out, "%s NO %s\r\n", tag, error_message(r));
	}

	return;
    }

    /* local mailbox */
    if (!r) {
	quota.root = mailboxname;
	r = quota_read(&quota, NULL, 0);
    }
    
    if (!r) {
	prot_printf(imapd_out, "* QUOTA ");
	printastring(name);
	prot_printf(imapd_out, " (");
	if (quota.limit >= 0) {
	    prot_printf(imapd_out, "STORAGE " UQUOTA_T_FMT " %d",
			quota.used/QUOTA_UNITS, quota.limit);
	}
	prot_printf(imapd_out, ")\r\n");
    }

    if (r) {
	prot_printf(imapd_out, "%s NO %s\r\n", tag, error_message(r));
	return;
    }
    
    prot_printf(imapd_out, "%s OK %s\r\n", tag,
		error_message(IMAP_OK_COMPLETED));
}

/*
 * Perform a GETQUOTAROOT command
 */
void cmd_getquotaroot(const char *tag, const char *name)
{
    char mailboxname[MAX_MAILBOX_NAME+1];
    char *server;
    int mbtype;
    struct mailbox mailbox;
    int r;
    int doclose = 0;

    r = (*imapd_namespace.mboxname_tointernal)(&imapd_namespace, name,
					       imapd_userid, mailboxname);

    if (!r) {
	r = mlookup(tag, name, mailboxname, &mbtype, NULL, NULL,
		    &server, NULL, NULL);
    }
    if (r == IMAP_MAILBOX_MOVED) return;

    if (!r && (mbtype & MBTYPE_REMOTE)) {
	/* remote mailbox */

	if (imapd_userisadmin) {
	    /* If they are an admin, they won't retain that privledge if we
	     * proxy for them, so we need to refer them -- even if they haven't
	     * told us they're able to handle it. */
	    imapd_refer(tag, server, name);
	} else {
	    struct backend *s;

	    s = proxy_findserver(server, &imap_protocol,
				 proxy_userid, &backend_cached,
				 &backend_current, &backend_inbox, imapd_in);
	    if (!s) r = IMAP_SERVER_UNAVAILABLE;

	    imapd_check(s, 0, 0);

	    if (!r) {
		prot_printf(s->out, "%s Getquotaroot {%d+}\r\n%s\r\n",
			    tag, strlen(name), name);
		pipe_including_tag(s, tag, 0);
	    } else {
		prot_printf(imapd_out, "%s NO %s\r\n", tag, error_message(r));
	    }
	}

	return;
    }

    /* local mailbox */
    if (!r) {
	r = mailbox_open_header(mailboxname, imapd_authstate, &mailbox);
    }

    if (!r) {
	doclose = 1;
	if (!imapd_userisadmin && !(mailbox.myrights & ACL_READ)) {
	    r = (mailbox.myrights & ACL_LOOKUP) ?
	      IMAP_PERMISSION_DENIED : IMAP_MAILBOX_NONEXISTENT;
	}
    }

    if (!r) {
	prot_printf(imapd_out, "* QUOTAROOT ");
	printastring(name);
	if (mailbox.quota.root) {
	    (*imapd_namespace.mboxname_toexternal)(&imapd_namespace,
						   mailbox.quota.root,
						   imapd_userid, mailboxname);
	    prot_printf(imapd_out, " ");
	    printastring(mailboxname);
	    r = quota_read(&mailbox.quota, NULL, 0);
	    if (!r) {
		prot_printf(imapd_out, "\r\n* QUOTA ");
		printastring(mailboxname);
		prot_printf(imapd_out, " (");
		if (mailbox.quota.limit >= 0) {
		    prot_printf(imapd_out, "STORAGE " UQUOTA_T_FMT " %d",
				mailbox.quota.used/QUOTA_UNITS,
				mailbox.quota.limit);
		}
		prot_putc(')', imapd_out);
	    }
	}
	prot_printf(imapd_out, "\r\n");
    }

    if (doclose) mailbox_close(&mailbox);

    imapd_check(NULL, 0, 0);

    if (r) {
	prot_printf(imapd_out, "%s NO %s\r\n", tag, error_message(r));
	return;
    }
    
    prot_printf(imapd_out, "%s OK %s\r\n", tag,
		error_message(IMAP_OK_COMPLETED));
}

/*
 * Parse and perform a SETQUOTA command
 * The command has been parsed up to the resource list
 */
void cmd_setquota(const char *tag, const char *quotaroot)
{
    int newquota = -1;
    int badresource = 0;
    int c;
    int force = 0;
    static struct buf arg;
    char *p;
    int r;
    char mailboxname[MAX_MAILBOX_NAME+1];
    int mbtype;
    char *server_rock_tmp = NULL;

    c = prot_getc(imapd_in);
    if (c != '(') goto badlist;

    c = getword(imapd_in, &arg);
    if (c != ')' || arg.s[0] != '\0') {
	for (;;) {
	    if (c != ' ') goto badlist;
	    if (strcasecmp(arg.s, "storage") != 0) badresource = 1;
	    c = getword(imapd_in, &arg);
	    if (c != ' ' && c != ')') goto badlist;
	    if (arg.s[0] == '\0') goto badlist;
	    newquota = 0;
	    for (p = arg.s; *p; p++) {
		if (!isdigit((int) *p)) goto badlist;
		newquota = newquota * 10 + *p - '0';
                if (newquota < 0) goto badlist; /* overflow */
	    }
	    if (c == ')') break;
	}
    }
    c = prot_getc(imapd_in);
    if (c == '\r') c = prot_getc(imapd_in);
    if (c != '\n') {
	prot_printf(imapd_out, "%s BAD Unexpected extra arguments to SETQUOTA\r\n", tag);
	eatline(imapd_in, c);
	return;
    }

    if (badresource) r = IMAP_UNSUPPORTED_QUOTA;
    else if (!imapd_userisadmin && !imapd_userisproxyadmin) {
	/* need to allow proxies so that mailbox moves can set initial quota
	 * roots */
	r = IMAP_PERMISSION_DENIED;
    } else {
	/* are we forcing the creation of a quotaroot by having a leading +? */
	if (quotaroot[0] == '+') {
	    force = 1;
	    quotaroot++;
	}
	
	r = (*imapd_namespace.mboxname_tointernal)(&imapd_namespace, quotaroot,
						   imapd_userid, mailboxname);
    }

    if (!r) {
    	r = mlookup(NULL, NULL, mailboxname, &mbtype, NULL, NULL,
		    &server_rock_tmp, NULL, NULL);
    }

    if (!r && (mbtype & MBTYPE_REMOTE)) {
	/* remote mailbox */
	char quotarootbuf[MAX_MAILBOX_NAME + 3];
	char *server_rock = xstrdup(server_rock_tmp);

	snprintf(quotarootbuf, sizeof(quotarootbuf), "%s.*", mailboxname);

	r = mboxlist_findall(&imapd_namespace, quotarootbuf,
			     imapd_userisadmin, imapd_userid,
			     imapd_authstate, quota_cb, server_rock);

	imapd_check(NULL, 0, 0);

	if (!r) {
	    /* Do the referral */
	    imapd_refer(tag, server_rock, quotaroot);
	    free(server_rock);
	} else {
	    if (server_rock) free(server_rock);
	    prot_printf(imapd_out, "%s NO %s\r\n", tag, error_message(r));
	}

	return;
    }

    /* local mailbox */
    if (!r || (r == IMAP_MAILBOX_NONEXISTENT)) {
	r = mboxlist_setquota(mailboxname, newquota, force);
    }

    imapd_check(NULL, 0, 0);

    if (r) {
	prot_printf(imapd_out, "%s NO %s\r\n", tag, error_message(r));
	return;
    }
    
    prot_printf(imapd_out, "%s OK %s\r\n", tag,
		error_message(IMAP_OK_COMPLETED));
    sync_log_quota(mailboxname);
    return;

 badlist:
    prot_printf(imapd_out, "%s BAD Invalid quota list in Setquota\r\n", tag);
    eatline(imapd_in, c);
}

#ifdef HAVE_SSL
/*
 * this implements the STARTTLS command, as described in RFC 2595.
 * one caveat: it assumes that no external layer is currently present.
 * if a client executes this command, information about the external
 * layer that was passed on the command line is disgarded. this should
 * be fixed.
 */
/* imaps - whether this is an imaps transaction or not */
void cmd_starttls(char *tag, int imaps)
{
    int result;
    int *layerp;

    char *auth_id;
    sasl_ssf_t ssf;

    /* SASL and openssl have different ideas about whether ssf is signed */
    layerp = (int *) &ssf;

    if (imapd_starttls_done == 1)
    {
	prot_printf(imapd_out, "%s NO TLS already active\r\n", tag);
	return;
    }

    result=tls_init_serverengine("imap",
				 5,        /* depth to verify */
				 !imaps,   /* can client auth? */
				 !imaps);  /* TLS only? */

    if (result == -1) {

	syslog(LOG_ERR, "error initializing TLS");

	if (imaps == 0) {
	    prot_printf(imapd_out, "%s NO Error initializing TLS\r\n", tag);
 	} else {
	    fatal("tls_init() failed", EC_CONFIG);
	}

	return;
    }

    if (imaps == 0)
    {
	prot_printf(imapd_out, "%s OK Begin TLS negotiation now\r\n", tag);
	/* must flush our buffers before starting tls */
	prot_flush(imapd_out);
    }
  
    result=tls_start_servertls(0, /* read */
			       1, /* write */
			       imaps ? 180 : imapd_timeout,
			       layerp,
			       &auth_id,
			       &tls_conn);

    /* if error */
    if (result==-1) {
	if (imaps == 0)	{
	    prot_printf(imapd_out, "%s NO Starttls negotiation failed\r\n", 
			tag);
	    syslog(LOG_NOTICE, "STARTTLS negotiation failed: %s", 
		   imapd_clienthost);
	    return;
	} else {
	    syslog(LOG_NOTICE, "imaps TLS negotiation failed: %s", 
		   imapd_clienthost);
	    fatal("tls_start_servertls() failed", EC_TEMPFAIL);
	    return;
	}
    }

    /* tell SASL about the negotiated layer */
    result = sasl_setprop(imapd_saslconn, SASL_SSF_EXTERNAL, &ssf);
    if (result != SASL_OK) {
	fatal("sasl_setprop() failed: cmd_starttls()", EC_TEMPFAIL);
    }
    saslprops.ssf = ssf;

    result = sasl_setprop(imapd_saslconn, SASL_AUTH_EXTERNAL, auth_id);
    if (result != SASL_OK) {
	fatal("sasl_setprop() failed: cmd_starttls()", EC_TEMPFAIL);
    }
    if(saslprops.authid) {
	free(saslprops.authid);
	saslprops.authid = NULL;
    }
    if(auth_id)
        saslprops.authid = xstrdup(auth_id);

    /* tell the prot layer about our new layers */
    prot_settls(imapd_in, tls_conn);
    prot_settls(imapd_out, tls_conn);

    imapd_starttls_done = 1;
}
#else
void cmd_starttls(char *tag, int imaps)
{
    fatal("cmd_starttls() executed, but starttls isn't implemented!",
	  EC_SOFTWARE);
}
#endif /* HAVE_SSL */

/*
 * Parse and perform a STATUS command
 * The command has been parsed up to the attribute list
 */
void cmd_status(char *tag, char *name)
{
    int c;
    unsigned statusitems = 0;
    static struct buf arg;
    char mailboxname[MAX_MAILBOX_NAME+1];
    int mbtype;
    char *server, *acl;
    int r = 0;

    r = (*imapd_namespace.mboxname_tointernal)(&imapd_namespace, name,
					       imapd_userid, mailboxname);

    if (!r) {
	r = mlookup(tag, name, mailboxname, &mbtype, NULL, NULL,
		    &server, &acl, NULL);
    }
    if (r == IMAP_MAILBOX_MOVED) {
	/* Eat the argument */
	eatline(imapd_in, prot_getc(imapd_in));
	return;
    }

    if (!r && (mbtype & MBTYPE_REMOTE)) {
	/* remote mailbox */

	if (supports_referrals
	    && config_getswitch(IMAPOPT_PROXYD_ALLOW_STATUS_REFERRAL)) { 
	    imapd_refer(tag, server, name);
	    /* Eat the argument */
	    eatline(imapd_in, prot_getc(imapd_in));
	}
	else {
	    struct backend *s;

	    s = proxy_findserver(server, &imap_protocol,
				 proxy_userid, &backend_cached,
				 &backend_current, &backend_inbox, imapd_in);
	    if (!s) r = IMAP_SERVER_UNAVAILABLE;

	    imapd_check(s, 0, 0);

	    if (!r) {
		prot_printf(s->out, "%s Status {%d+}\r\n%s ", tag,
			    strlen(name), name);
		if (!pipe_command(s, 65536)) {
		    pipe_including_tag(s, tag, 0);
		}
	    } else {
		eatline(imapd_in, prot_getc(imapd_in));
		prot_printf(imapd_out, "%s NO %s\r\n", tag, error_message(r));
	    }
	}

	return;
    }

    /* local mailbox */

    /*
     * Perform a full checkpoint of any open mailbox, in case we're
     * doing a STATUS check of the current mailbox.
     */
    imapd_check(NULL, 0, 1);

    c = prot_getc(imapd_in);
    if (c != '(') goto badlist;

    c = getword(imapd_in, &arg);
    if (arg.s[0] == '\0') goto badlist;
    for (;;) {
	lcase(arg.s);
	if (!strcmp(arg.s, "messages")) {
	    statusitems |= STATUS_MESSAGES;
	}
	else if (!strcmp(arg.s, "recent")) {
	    statusitems |= STATUS_RECENT;
	}
	else if (!strcmp(arg.s, "uidnext")) {
	    statusitems |= STATUS_UIDNEXT;
	}
	else if (!strcmp(arg.s, "uidvalidity")) {
	    statusitems |= STATUS_UIDVALIDITY;
	}
	else if (!strcmp(arg.s, "unseen")) {
	    statusitems |= STATUS_UNSEEN;
	}
	else if (!strcmp(arg.s, "highestmodseq")) {
	    statusitems |= STATUS_HIGHESTMODSEQ;
	}
	else {
	    prot_printf(imapd_out, "%s BAD Invalid Status attribute %s\r\n",
			tag, arg.s);
	    eatline(imapd_in, c);
	    return;
	}
	    
	if (c == ' ') c = getword(imapd_in, &arg);
	else break;
    }

    if (c != ')') {
	prot_printf(imapd_out,
		    "%s BAD Missing close parenthesis in Status\r\n", tag);
	eatline(imapd_in, c);
	return;
    }

    c = prot_getc(imapd_in);
    if (c == '\r') c = prot_getc(imapd_in);
    if (c != '\n') {
	prot_printf(imapd_out,
		    "%s BAD Unexpected extra arguments to Status\r\n", tag);
	eatline(imapd_in, c);
	return;
    }

    if (!r) {
	int myrights = cyrus_acl_myrights(imapd_authstate, acl);

	if (!(myrights & ACL_READ)) {
	    r = (imapd_userisadmin || (myrights & ACL_LOOKUP)) ?
		IMAP_PERMISSION_DENIED : IMAP_MAILBOX_NONEXISTENT;
	}
    }

    if (!r) {
	r = index_status(mailboxname, name, statusitems);
    }

    if (r) {
	prot_printf(imapd_out, "%s NO %s\r\n", tag, error_message(r));
	return;
    }
    
    prot_printf(imapd_out, "%s OK %s\r\n", tag,
		error_message(IMAP_OK_COMPLETED));
    return;

 badlist:
    prot_printf(imapd_out, "%s BAD Invalid status list in Status\r\n", tag);
    eatline(imapd_in, c);
}

#ifdef ENABLE_X_NETSCAPE_HACK
/*
 * Reply to Netscape's crock with a crock of my own
 */
void cmd_netscrape(char *tag)
{
    const char *url;

    url = config_getstring(IMAPOPT_NETSCAPEURL);

    /* I only know of three things to reply with: */
    prot_printf(imapd_out,
		"* OK [NETSCAPE] Carnegie Mellon Cyrus IMAP\r\n"
		"* VERSION %s\r\n",
		CYRUS_VERSION);
    if (url) prot_printf(imapd_out, "* ACCOUNT-URL %s\r\n", url);
    prot_printf(imapd_out, "%s OK %s\r\n",
		tag, error_message(IMAP_OK_COMPLETED));
}
#endif /* ENABLE_X_NETSCAPE_HACK */

/* Callback for cmd_namespace to be passed to mboxlist_findall.
 * For each top-level mailbox found, print a bit of the response
 * if it is a shared namespace.  The rock is used as an integer in
 * order to ensure the namespace response is correct on a server with
 * no shared namespace.
 */
static int namespacedata(char *name,
			 int matchlen __attribute__((unused)),
			 int maycreate __attribute__((unused)),
			 void *rock)
{
    int* sawone = (int*) rock;

    if (!name) {
	return 0;
    }
    
    if ((!strncasecmp(name, "INBOX", 5) && (!name[5] || name[5] == '.'))) {
	/* The user has a "personal" namespace. */
	sawone[NAMESPACE_INBOX] = 1;
    } else if (mboxname_isusermailbox(name, 0)) {
	/* The user can see the "other users" namespace. */
	sawone[NAMESPACE_USER] = 1;
    } else {
	/* The user can see the "shared" namespace. */
	sawone[NAMESPACE_SHARED] = 1;
    }

    return 0;
}

/*
 * Print out a response to the NAMESPACE command defined by
 * RFC 2342.
 */
void cmd_namespace(tag)
    char* tag;
{
    int sawone[3] = {0, 0, 0};
    char* pattern;

    if (SLEEZY_NAMESPACE) {
	char inboxname[MAX_MAILBOX_NAME+1];

	if (strlen(imapd_userid) + 5 > MAX_MAILBOX_NAME)
	    sawone[NAMESPACE_INBOX] = 0;
	else {
	    (*imapd_namespace.mboxname_tointernal)(&imapd_namespace, "INBOX",
						   imapd_userid, inboxname);
	    sawone[NAMESPACE_INBOX] = 
		!mboxlist_lookup(inboxname, NULL, NULL);
	}
	sawone[NAMESPACE_USER] = 1;
	sawone[NAMESPACE_SHARED] = 1;
    } else {
	pattern = xstrdup("%");
	/* now find all the exciting toplevel namespaces -
	 * we're using internal names here
	 */
	mboxlist_findall(NULL, pattern, imapd_userisadmin, imapd_userid,
			 imapd_authstate, namespacedata, (void*) sawone);
	free(pattern);
    }

    prot_printf(imapd_out, "* NAMESPACE");
    if (sawone[NAMESPACE_INBOX]) {
	prot_printf(imapd_out, " ((\"%s\" \"%c\"))",
		    imapd_namespace.prefix[NAMESPACE_INBOX],
		    imapd_namespace.hier_sep);
    } else {
	prot_printf(imapd_out, " NIL");
    }
    if (sawone[NAMESPACE_USER]) {
	prot_printf(imapd_out, " ((\"%s\" \"%c\"))",
		    imapd_namespace.prefix[NAMESPACE_USER],
		    imapd_namespace.hier_sep);
    } else {
	prot_printf(imapd_out, " NIL");
    }
    if (sawone[NAMESPACE_SHARED]) {
	prot_printf(imapd_out, " ((\"%s\" \"%c\"))",
		    imapd_namespace.prefix[NAMESPACE_SHARED],
		    imapd_namespace.hier_sep);
    } else {
	prot_printf(imapd_out, " NIL");
    }
    prot_printf(imapd_out, "\r\n");

    imapd_check(NULL, 0, 0);

    prot_printf(imapd_out, "%s OK %s\r\n", tag,
		error_message(IMAP_OK_COMPLETED));
}

/*
 * Parse annotate fetch data.
 *
 * This is a generic routine which parses just the annotation data.
 * Any surrounding command text must be parsed elsewhere, ie,
 * GETANNOTATION, FETCH.
 */

int getannotatefetchdata(char *tag,
			 struct strlist **entries, struct strlist **attribs)
{
    int c;
    static struct buf arg;

    *entries = *attribs = NULL;

    c = prot_getc(imapd_in);
    if (c == EOF) {
	prot_printf(imapd_out,
		    "%s BAD Missing annotation entry\r\n", tag);
	goto baddata;
    }
    else if (c == '(') {
	/* entry list */
	do {
	    c = getqstring(imapd_in, imapd_out, &arg);
	    if (c == EOF) {
		prot_printf(imapd_out,
			    "%s BAD Missing annotation entry\r\n", tag);
		goto baddata;
	    }

	    /* add the entry to the list */
	    appendstrlist(entries, arg.s);

	} while (c == ' ');

	if (c != ')') {
	    prot_printf(imapd_out,
			"%s BAD Missing close paren in annotation entry list \r\n",
			tag);
	    goto baddata;
	}

	c = prot_getc(imapd_in);
    }
    else {
	/* single entry -- add it to the list */
	prot_ungetc(c, imapd_in);
	c = getqstring(imapd_in, imapd_out, &arg);
	if (c == EOF) {
	    prot_printf(imapd_out,
			"%s BAD Missing annotation entry\r\n", tag);
	    goto baddata;
	}

	appendstrlist(entries, arg.s);
    }

    if (c != ' ' || (c = prot_getc(imapd_in)) == EOF) {
	prot_printf(imapd_out,
		    "%s BAD Missing annotation attribute(s)\r\n", tag);
	goto baddata;
    }

    if (c == '(') {
	/* attrib list */
	do {
	    c = getnstring(imapd_in, imapd_out, &arg);
	    if (c == EOF) {
		prot_printf(imapd_out,
			    "%s BAD Missing annotation attribute(s)\r\n", tag);
		goto baddata;
	    }

	    /* add the attrib to the list */
	    appendstrlist(attribs, arg.s);

	} while (c == ' ');

	if (c != ')') {
	    prot_printf(imapd_out,
			"%s BAD Missing close paren in "
			"annotation attribute list\r\n", tag);
	    goto baddata;
	}

	c = prot_getc(imapd_in);
    }
    else {
	/* single attrib */
	prot_ungetc(c, imapd_in);
	c = getqstring(imapd_in, imapd_out, &arg);
	    if (c == EOF) {
		prot_printf(imapd_out,
			    "%s BAD Missing annotation attribute\r\n", tag);
		goto baddata;
	    }

	appendstrlist(attribs, arg.s);
   }

    return c;

  baddata:
    if (c != EOF) prot_ungetc(c, imapd_in);
    return EOF;
}

/*
 * Parse annotate store data.
 *
 * This is a generic routine which parses just the annotation data.
 * Any surrounding command text must be parsed elsewhere, ie,
 * SETANNOTATION, STORE, APPEND.
 */

int getannotatestoredata(char *tag, struct entryattlist **entryatts)
{
    int c, islist = 0;
    static struct buf entry, attrib, value;
    struct attvaluelist *attvalues = NULL;

    *entryatts = NULL;

    c = prot_getc(imapd_in);
    if (c == EOF) {
	prot_printf(imapd_out,
		    "%s BAD Missing annotation entry\r\n", tag);
	goto baddata;
    }
    else if (c == '(') {
	/* entry list */
	islist = 1;
    }
    else {
	/* single entry -- put the char back */
	prot_ungetc(c, imapd_in);
    }

    do {
	/* get entry */
	c = getqstring(imapd_in, imapd_out, &entry);
	if (c == EOF) {
	    prot_printf(imapd_out,
			"%s BAD Missing annotation entry\r\n", tag);
	    goto baddata;
	}

	/* parse att-value list */
	if (c != ' ' || (c = prot_getc(imapd_in)) != '(') {
	    prot_printf(imapd_out,
			"%s BAD Missing annotation attribute-values list\r\n",
			tag);
	    goto baddata;
	}

	do {
	    /* get attrib */
	    c = getqstring(imapd_in, imapd_out, &attrib);
	    if (c == EOF) {
		prot_printf(imapd_out,
			    "%s BAD Missing annotation attribute\r\n", tag);
		goto baddata;
	    }

	    /* get value */
	    if (c != ' ' ||
		(c = getnstring(imapd_in, imapd_out, &value)) == EOF) {
		prot_printf(imapd_out,
			    "%s BAD Missing annotation value\r\n", tag);
		goto baddata;
	    }

	    /* add the attrib-value pair to the list */
	    appendattvalue(&attvalues, attrib.s, value.s);

	} while (c == ' ');

	if (c != ')') {
	    prot_printf(imapd_out,
			"%s BAD Missing close paren in annotation "
			"attribute-values list\r\n", tag);
	    goto baddata;
	}

	/* add the entry to the list */
	appendentryatt(entryatts, entry.s, attvalues);
	attvalues = NULL;

	c = prot_getc(imapd_in);

    } while (c == ' ');

    if (islist) {
	if (c != ')') {
	    prot_printf(imapd_out,
			"%s BAD Missing close paren in annotation entry list \r\n",
			tag);
	    goto baddata;
	}

	c = prot_getc(imapd_in);
    }

    return c;

  baddata:
    if (attvalues) freeattvalues(attvalues);
    if (c != EOF) prot_ungetc(c, imapd_in);
    return EOF;
}

/*
 * Output an entry/attribute-value list response.
 *
 * This is a generic routine which outputs just the annotation data.
 * Any surrounding response text must be output elsewhere, ie,
 * GETANNOTATION, FETCH. 
 */
void annotate_response(struct entryattlist *l)
{
    int islist; /* do we have more than one entry? */

    if (!l) return;

    islist = (l->next != NULL);

    if (islist) prot_printf(imapd_out, "(");

    while (l) {
	prot_printf(imapd_out, "\"%s\"", l->entry);

	/* do we have attributes?  solicited vs. unsolicited */
	if (l->attvalues) {
	    struct attvaluelist *av = l->attvalues;

	    prot_printf(imapd_out, " (");
	    while (av) {
		prot_printf(imapd_out, "\"%s\" ", av->attrib);
		if (!strcasecmp(av->value, "NIL"))
		    prot_printf(imapd_out, "NIL");
		else
		    prot_printf(imapd_out, "\"%s\"", av->value);

		if ((av = av->next) == NULL)
		    prot_printf(imapd_out, ")");
		else
		    prot_printf(imapd_out, " ");
	    }
	}

	if ((l = l->next) != NULL)
	    prot_printf(imapd_out, " ");
    }

    if (islist) prot_printf(imapd_out, ")");
}

/*
 * Perform a GETANNOTATION command
 *
 * The command has been parsed up to the entries
 */    
void cmd_getannotation(char *tag, char *mboxpat)
{
    int c, r = 0;
    struct strlist *entries = NULL, *attribs = NULL;

    c = getannotatefetchdata(tag, &entries, &attribs);
    if (c == EOF) {
	eatline(imapd_in, c);
	return;
    }

    /* check for CRLF */
    if (c == '\r') c = prot_getc(imapd_in);
    if (c != '\n') {
	prot_printf(imapd_out,
		    "%s BAD Unexpected extra arguments to Getannotation\r\n",
		    tag);
	eatline(imapd_in, c);
	goto freeargs;
    }

    r = annotatemore_fetch(mboxpat, entries, attribs, &imapd_namespace,
			   imapd_userisadmin || imapd_userisproxyadmin,
			   imapd_userid, imapd_authstate, imapd_out);

    imapd_check(NULL, 0, 0);

    if (r) {
	prot_printf(imapd_out, "%s NO %s\r\n", tag, error_message(r));
    } else {
	prot_printf(imapd_out, "%s OK %s\r\n",
		    tag, error_message(IMAP_OK_COMPLETED));
    }

  freeargs:
    if (entries) freestrlist(entries);
    if (attribs) freestrlist(attribs);

    return;
}

/*
 * Perform a SETANNOTATION command
 *
 * The command has been parsed up to the entry-att list
 */    
void cmd_setannotation(char *tag, char *mboxpat)
{
    int c, r = 0;
    struct entryattlist *entryatts = NULL;

    c = getannotatestoredata(tag, &entryatts);
    if (c == EOF) {
	eatline(imapd_in, c);
	return;
    }

    /* check for CRLF */
    if (c == '\r') c = prot_getc(imapd_in);
    if (c != '\n') {
	prot_printf(imapd_out,
		    "%s BAD Unexpected extra arguments to Setannotation\r\n",
		    tag);
	eatline(imapd_in, c);
	goto freeargs;
    }

    r = annotatemore_store(mboxpat,
			   entryatts, &imapd_namespace, imapd_userisadmin,
			   imapd_userid, imapd_authstate);

    imapd_check(NULL, 0, 0);

    if (r) {
	prot_printf(imapd_out, "%s NO %s\r\n", tag, error_message(r));
    } else {
	prot_printf(imapd_out, "%s OK %s\r\n", tag,
		    error_message(IMAP_OK_COMPLETED));
    }

  freeargs:
    if (entryatts) freeentryatts(entryatts);
    return;
}

/*
 * Parse a search program
 */
int getsearchprogram(tag, searchargs, charset, parsecharset)
char *tag;
struct searchargs *searchargs;
int *charset;
int parsecharset;
{
    int c;

    do {
	c = getsearchcriteria(tag, searchargs, charset, parsecharset);
	parsecharset = 0;
    } while (c == ' ');
    return c;
}

/*
 * Parse a search criteria
 */
int getsearchcriteria(tag, searchargs, charset, parsecharset)
char *tag;
struct searchargs *searchargs;
int *charset;
int parsecharset;
{
    static struct buf criteria, arg;
    struct searchargs *sub1, *sub2;
    char *p, *str;
    int c, flag;
    unsigned size;
    time_t start, end;

    c = getword(imapd_in, &criteria);
    lcase(criteria.s);
    switch (criteria.s[0]) {
    case '\0':
	if (c != '(') goto badcri;
	c = getsearchprogram(tag, searchargs, charset, 0);
	if (c == EOF) return EOF;
	if (c != ')') {
	    prot_printf(imapd_out, "%s BAD Missing required close paren in Search command\r\n",
		   tag);
	    if (c != EOF) prot_ungetc(c, imapd_in);
	    return EOF;
	}
	c = prot_getc(imapd_in);
	break;

    case '0': case '1': case '2': case '3': case '4':
    case '5': case '6': case '7': case '8': case '9':
    case '*':
	if (imparse_issequence(criteria.s)) {
	    appendsequencelist(&searchargs->sequence, criteria.s, 0);
	}
	else goto badcri;
	break;

    case 'a':
	if (!strcmp(criteria.s, "answered")) {
	    searchargs->system_flags_set |= FLAG_ANSWERED;
	}
	else if (!strcmp(criteria.s, "all")) {
	    break;
	}
	else goto badcri;
	break;

    case 'b':
	if (!strcmp(criteria.s, "before")) {
	    if (c != ' ') goto missingarg;		
	    c = getsearchdate(&start, &end);
	    if (c == EOF) goto baddate;
	    if (!searchargs->before || searchargs->before > start) {
		searchargs->before = start;
	    }
	}
	else if (!strcmp(criteria.s, "bcc")) {
	    if (c != ' ') goto missingarg;		
	    c = getastring(imapd_in, imapd_out, &arg);
	    if (c == EOF) goto missingarg;
	    str = charset_convert(arg.s, *charset, NULL, 0);
	    if (strchr(str, EMPTY)) {
		/* Force failure */
		searchargs->flags = (SEARCH_RECENT_SET|SEARCH_RECENT_UNSET);
	    }
	    else {
		appendstrlistpat(&searchargs->bcc, str);
	    }
	}
	else if (!strcmp(criteria.s, "body")) {
	    if (c != ' ') goto missingarg;		
	    c = getastring(imapd_in, imapd_out, &arg);
	    if (c == EOF) goto missingarg;
	    str = charset_convert(arg.s, *charset, NULL, 0);
	    if (strchr(str, EMPTY)) {
		/* Force failure */
		searchargs->flags = (SEARCH_RECENT_SET|SEARCH_RECENT_UNSET);
	    }
	    else {
		appendstrlistpat(&searchargs->body, str);
	    }
	}
	else goto badcri;
	break;

    case 'c':
	if (!strcmp(criteria.s, "cc")) {
	    if (c != ' ') goto missingarg;		
	    c = getastring(imapd_in, imapd_out, &arg);
	    if (c == EOF) goto missingarg;
	    str = charset_convert(arg.s, *charset, NULL, 0);
	    if (strchr(str, EMPTY)) {
		/* Force failure */
		searchargs->flags = (SEARCH_RECENT_SET|SEARCH_RECENT_UNSET);
	    }
	    else {
		appendstrlistpat(&searchargs->cc, str);
	    }
	}
	else if (parsecharset && !strcmp(criteria.s, "charset")) {
	    if (c != ' ') goto missingarg;		
	    c = getastring(imapd_in, imapd_out, &arg);
	    if (c != ' ') goto missingarg;
	    lcase(arg.s);
	    *charset = charset_lookupname(arg.s);
	}
	else goto badcri;
	break;

    case 'd':
	if (!strcmp(criteria.s, "deleted")) {
	    searchargs->system_flags_set |= FLAG_DELETED;
	}
	else if (!strcmp(criteria.s, "draft")) {
	    searchargs->system_flags_set |= FLAG_DRAFT;
	}
	else goto badcri;
	break;

    case 'f':
	if (!strcmp(criteria.s, "flagged")) {
	    searchargs->system_flags_set |= FLAG_FLAGGED;
	}
	else if (!strcmp(criteria.s, "from")) {
	    if (c != ' ') goto missingarg;		
	    c = getastring(imapd_in, imapd_out, &arg);
	    if (c == EOF) goto missingarg;
	    str = charset_convert(arg.s, *charset, NULL, 0);
	    if (strchr(str, EMPTY)) {
		/* Force failure */
		searchargs->flags = (SEARCH_RECENT_SET|SEARCH_RECENT_UNSET);
	    }
	    else {
		appendstrlistpat(&searchargs->from, str);
	    }
	}
	else goto badcri;
	break;

    case 'h':
	if (!strcmp(criteria.s, "header")) {
	    struct strlist **patlist;

	    if (c != ' ') goto missingarg;		
	    c = getastring(imapd_in, imapd_out, &arg);
	    if (c != ' ') goto missingarg;
	    lcase(arg.s);

	    /* some headers can be reduced to search terms */
            if (!strcmp(arg.s, "bcc")) {
                patlist = &searchargs->bcc;
            }
            else if (!strcmp(arg.s, "cc")) {
		patlist = &searchargs->cc;
            }
	    else if (!strcmp(arg.s, "to")) {
		patlist = &searchargs->to;
            }
	    else if (!strcmp(arg.s, "from")) {
		patlist = &searchargs->from;
            }
	    else if (!strcmp(arg.s, "subject")) {
		patlist = &searchargs->subject;
            }

	    /* we look message-id up in the envelope */
	    else if (!strcmp(arg.s, "message-id")) {
		patlist = &searchargs->messageid;
	    }

	    /* all other headers we handle normally */
	    else {
		if (searchargs->cache_atleast < BIT32_MAX) {
		    bit32 this_ver =
			mailbox_cached_header(arg.s);
		    if(this_ver > searchargs->cache_atleast)
			searchargs->cache_atleast = this_ver;
		}
		appendstrlist(&searchargs->header_name, arg.s);
		patlist = &searchargs->header;
	    }

	    c = getastring(imapd_in, imapd_out, &arg);
	    if (c == EOF) goto missingarg;
	    str = charset_convert(arg.s, *charset, NULL, 0);
	    if (strchr(str, EMPTY)) {
		/* Force failure */
		searchargs->flags = (SEARCH_RECENT_SET|SEARCH_RECENT_UNSET);
	    }
	    else {
		appendstrlistpat(patlist, str);
	    }
	}
	else goto badcri;
	break;

    case 'k':
	if (!strcmp(criteria.s, "keyword")) {
	    if (c != ' ') goto missingarg;		
	    c = getword(imapd_in, &arg);
	    if (!imparse_isatom(arg.s)) goto badflag;
	    lcase(arg.s);
	    for (flag=0; flag < MAX_USER_FLAGS; flag++) {
		if (imapd_mailbox->flagname[flag] &&
		    !strcasecmp(imapd_mailbox->flagname[flag], arg.s)) break;
	    }
	    if (flag == MAX_USER_FLAGS) {
		/* Force failure */
		searchargs->flags = (SEARCH_RECENT_SET|SEARCH_RECENT_UNSET);
		break;
	    }
	    searchargs->user_flags_set[flag/32] |= 1<<(flag&31);
	}
	else goto badcri;
	break;

    case 'l':
	if (!strcmp(criteria.s, "larger")) {
	    if (c != ' ') goto missingarg;		
	    c = getword(imapd_in, &arg);
	    size = 0;
	    for (p = arg.s; *p && isdigit((int) *p); p++) {
		size = size * 10 + *p - '0';
                /* if (size < 0) goto badnumber; */
	    }
	    if (!arg.s || *p) goto badnumber;
	    if (size > searchargs->larger) searchargs->larger = size;
	}
	else goto badcri;
	break;

    case 'm':
	if ((imapd_mailbox->options & OPT_IMAP_CONDSTORE) &&
	    !strcmp(criteria.s, "modseq")) {
	    if (c != ' ') goto missingarg;		
	    c = getword(imapd_in, &arg);
	    for (p = arg.s; *p && isdigit((int) *p); p++) {
		searchargs->modseq = searchargs->modseq * 10 + *p - '0';
	    }
	    if (!arg.s || *p) goto badnumber;
	}
	else goto badcri;
	break;

    case 'n':
	if (!strcmp(criteria.s, "not")) {
	    if (c != ' ') goto missingarg;		
	    sub1 = (struct searchargs *)xzmalloc(sizeof(struct searchargs));
	    c = getsearchcriteria(tag, sub1, charset, 0);
	    if (c == EOF) {
		freesearchargs(sub1);
		return EOF;
	    }

	    appendsearchargs(searchargs, sub1, (struct searchargs *)0);
	}
	else if (!strcmp(criteria.s, "new")) {
	    searchargs->flags |= (SEARCH_SEEN_UNSET|SEARCH_RECENT_SET);
	}
	else goto badcri;
	break;

    case 'o':
	if (!strcmp(criteria.s, "or")) {
	    if (c != ' ') goto missingarg;		
	    sub1 = (struct searchargs *)xzmalloc(sizeof(struct searchargs));
	    c = getsearchcriteria(tag, sub1, charset, 0);
	    if (c == EOF) {
		freesearchargs(sub1);
		return EOF;
	    }
	    if (c != ' ') goto missingarg;		
	    sub2 = (struct searchargs *)xzmalloc(sizeof(struct searchargs));
	    c = getsearchcriteria(tag, sub2, charset, 0);
	    if (c == EOF) {
		freesearchargs(sub1);
		freesearchargs(sub2);
		return EOF;
	    }
	    appendsearchargs(searchargs, sub1, sub2);
	}
	else if (!strcmp(criteria.s, "old")) {
	    searchargs->flags |= SEARCH_RECENT_UNSET;
	}
	else if (!strcmp(criteria.s, "on")) {
	    if (c != ' ') goto missingarg;		
	    c = getsearchdate(&start, &end);
	    if (c == EOF) goto baddate;
	    if (!searchargs->before || searchargs->before > end) {
		searchargs->before = end;
	    }
	    if (!searchargs->after || searchargs->after < start) {
		searchargs->after = start;
	    }
	}
	else goto badcri;
	break;

    case 'r':
	if (!strcmp(criteria.s, "recent")) {
	    searchargs->flags |= SEARCH_RECENT_SET;
	}
	else goto badcri;
	break;

    case 's':
	if (!strcmp(criteria.s, "seen")) {
	    searchargs->flags |= SEARCH_SEEN_SET;
	}
	else if (!strcmp(criteria.s, "sentbefore")) {
	    if (c != ' ') goto missingarg;		
	    c = getsearchdate(&start, &end);
	    if (c == EOF) goto baddate;
	    if (!searchargs->sentbefore || searchargs->sentbefore > start) {
		searchargs->sentbefore = start;
	    }
	}
	else if (!strcmp(criteria.s, "senton")) {
	    if (c != ' ') goto missingarg;		
	    c = getsearchdate(&start, &end);
	    if (c == EOF) goto baddate;
	    if (!searchargs->sentbefore || searchargs->sentbefore > end) {
		searchargs->sentbefore = end;
	    }
	    if (!searchargs->sentafter || searchargs->sentafter < start) {
		searchargs->sentafter = start;
	    }
	}
	else if (!strcmp(criteria.s, "sentsince")) {
	    if (c != ' ') goto missingarg;		
	    c = getsearchdate(&start, &end);
	    if (c == EOF) goto baddate;
	    if (!searchargs->sentafter || searchargs->sentafter < start) {
		searchargs->sentafter = start;
	    }
	}
	else if (!strcmp(criteria.s, "since")) {
	    if (c != ' ') goto missingarg;		
	    c = getsearchdate(&start, &end);
	    if (c == EOF) goto baddate;
	    if (!searchargs->after || searchargs->after < start) {
		searchargs->after = start;
	    }
	}
	else if (!strcmp(criteria.s, "smaller")) {
	    if (c != ' ') goto missingarg;		
	    c = getword(imapd_in, &arg);
	    size = 0;
	    for (p = arg.s; *p && isdigit((int) *p); p++) {
		size = size * 10 + *p - '0';
                /* if (size < 0) goto badnumber; */
	    }
	    if (!arg.s || *p) goto badnumber;
	    if (size == 0) size = 1;
	    if (!searchargs->smaller || size < searchargs->smaller)
	      searchargs->smaller = size;
	}
	else if (!strcmp(criteria.s, "subject")) {
	    if (c != ' ') goto missingarg;		
	    c = getastring(imapd_in, imapd_out, &arg);
	    if (c == EOF) goto missingarg;
	    str = charset_convert(arg.s, *charset, NULL, 0);
	    if (strchr(str, EMPTY)) {
		/* Force failure */
		searchargs->flags = (SEARCH_RECENT_SET|SEARCH_RECENT_UNSET);
	    }
	    else {
		appendstrlistpat(&searchargs->subject, str);
	    }
	}
	else goto badcri;
	break;

    case 't':
	if (!strcmp(criteria.s, "to")) {
	    if (c != ' ') goto missingarg;		
	    c = getastring(imapd_in, imapd_out, &arg);
	    if (c == EOF) goto missingarg;
	    str = charset_convert(arg.s, *charset, NULL, 0);
	    if (strchr(str, EMPTY)) {
		/* Force failure */
		searchargs->flags = (SEARCH_RECENT_SET|SEARCH_RECENT_UNSET);
	    }
	    else {
		appendstrlistpat(&searchargs->to, str);
	    }
	}
	else if (!strcmp(criteria.s, "text")) {
	    if (c != ' ') goto missingarg;		
	    c = getastring(imapd_in, imapd_out, &arg);
	    if (c == EOF) goto missingarg;
	    str = charset_convert(arg.s, *charset, NULL, 0);
	    if (strchr(str, EMPTY)) {
		/* Force failure */
		searchargs->flags = (SEARCH_RECENT_SET|SEARCH_RECENT_UNSET);
	    }
	    else {
		appendstrlistpat(&searchargs->text, str);
	    }
	}
	else goto badcri;
	break;

    case 'u':
	if (!strcmp(criteria.s, "uid")) {
	    if (c != ' ') goto missingarg;
	    c = getword(imapd_in, &arg);
	    if (!imparse_issequence(arg.s)) goto badcri;
	    appendsequencelist(&searchargs->uidsequence, arg.s, 1);
	}
	else if (!strcmp(criteria.s, "unseen")) {
	    searchargs->flags |= SEARCH_SEEN_UNSET;
	}
	else if (!strcmp(criteria.s, "unanswered")) {
	    searchargs->system_flags_unset |= FLAG_ANSWERED;
	}
	else if (!strcmp(criteria.s, "undeleted")) {
	    searchargs->system_flags_unset |= FLAG_DELETED;
	}
	else if (!strcmp(criteria.s, "undraft")) {
	    searchargs->system_flags_unset |= FLAG_DRAFT;
	}
	else if (!strcmp(criteria.s, "unflagged")) {
	    searchargs->system_flags_unset |= FLAG_FLAGGED;
	}
	else if (!strcmp(criteria.s, "unkeyword")) {
	    if (c != ' ') goto missingarg;		
	    c = getword(imapd_in, &arg);
	    if (!imparse_isatom(arg.s)) goto badflag;
	    lcase(arg.s);
	    for (flag=0; flag < MAX_USER_FLAGS; flag++) {
		if (imapd_mailbox->flagname[flag] &&
		    !strcasecmp(imapd_mailbox->flagname[flag], arg.s)) break;
	    }
	    if (flag != MAX_USER_FLAGS) {
		searchargs->user_flags_unset[flag/32] |= 1<<(flag&31);
	    }
	}
	else goto badcri;
	break;

    default:
    badcri:
	prot_printf(imapd_out, "%s BAD Invalid Search criteria\r\n", tag);
	if (c != EOF) prot_ungetc(c, imapd_in);
	return EOF;
    }

    return c;

 missingarg:
    prot_printf(imapd_out, "%s BAD Missing required argument to Search %s\r\n",
	   tag, criteria.s);
    if (c != EOF) prot_ungetc(c, imapd_in);
    return EOF;

 badflag:
    prot_printf(imapd_out, "%s BAD Invalid flag name %s in Search command\r\n",
	   tag, arg.s);
    if (c != EOF) prot_ungetc(c, imapd_in);
    return EOF;

 baddate:
    prot_printf(imapd_out, "%s BAD Invalid date in Search command\r\n", tag);
    if (c != EOF) prot_ungetc(c, imapd_in);
    return EOF;

 badnumber:
    prot_printf(imapd_out, "%s BAD Invalid number in Search command\r\n", tag);
    if (c != EOF) prot_ungetc(c, imapd_in);
    return EOF;
}

void cmd_dump(char *tag, char *name, int uid_start) 
{
    int r = 0;
    char mailboxname[MAX_MAILBOX_NAME+1];
    char *path, *mpath, *acl;

    /* administrators only please */
    if (!imapd_userisadmin) {
	r = IMAP_PERMISSION_DENIED;
    }

    if (!r) {
	r = (*imapd_namespace.mboxname_tointernal)(&imapd_namespace, name,
						   imapd_userid, mailboxname);
    }
    
    if (!r) {
	r = mlookup(tag, name, mailboxname, NULL, &path, &mpath,
		    NULL, &acl, NULL);
    }
    if (r == IMAP_MAILBOX_MOVED) return;

    if(!r) {
	r = dump_mailbox(tag, mailboxname, path, mpath, acl, uid_start,
			 imapd_in, imapd_out, imapd_authstate);
    }

    if (r) {
	prot_printf(imapd_out, "%s NO %s\r\n", tag, error_message(r));
    } else {
	prot_printf(imapd_out, "%s OK %s\r\n", tag,
		    error_message(IMAP_OK_COMPLETED));
    }
}

void cmd_undump(char *tag, char *name) 
{
    int r = 0;
    char mailboxname[MAX_MAILBOX_NAME+1];
    char *path, *mpath, *acl;

    /* administrators only please */
    if (!imapd_userisadmin) {
	r = IMAP_PERMISSION_DENIED;
    }

    if (!r) {
	r = (*imapd_namespace.mboxname_tointernal)(&imapd_namespace, name,
						   imapd_userid, mailboxname);
    }
    
    if (!r) {
	r = mlookup(tag, name, mailboxname, NULL, &path, &mpath,
		    NULL, &acl, NULL);
    }
    if (r == IMAP_MAILBOX_MOVED) return;

    if(!r) {
	/* save this stuff from additional mlookups */
	char *safe_path = xstrdup(path);
	char *safe_mpath = mpath ? xstrdup(mpath) : NULL;
	char *safe_acl = xstrdup(acl);
	r = undump_mailbox(mailboxname, safe_path, safe_mpath, safe_acl,
			   imapd_in, imapd_out, imapd_authstate);
	free(safe_path);
	if (safe_mpath) free(safe_mpath);
	free(safe_acl);
    }

    if (r) {
	prot_printf(imapd_out, "%s NO %s%s\r\n",
		    tag,
		    (r == IMAP_MAILBOX_NONEXISTENT &&
		     mboxlist_createmailboxcheck(mailboxname, 0, 0,
						 imapd_userisadmin,
						 imapd_userid, imapd_authstate,
						 NULL, NULL, 0) == 0)
		    ? "[TRYCREATE] " : "", error_message(r));
    } else {
	prot_printf(imapd_out, "%s OK %s\r\n", tag,
		    error_message(IMAP_OK_COMPLETED));
	if (mboxname_isusermailbox(mailboxname, 1))
	    sync_log_user(mboxname_inbox_touserid(mailboxname));
	else
	    sync_log_mailbox(mailboxname);
    }
}

static int getresult(struct protstream *p, char *tag) 
{
    char buf[4096];
    char *str = (char *) buf;
    
    while(1) {
	if (!prot_fgets(str, sizeof(buf), p)) {
	    return IMAP_SERVER_UNAVAILABLE;
	}
	if (!strncmp(str, tag, strlen(tag))) {
	    str += strlen(tag);
	    if(!*str) {
		/* We got a tag, but no response */
		return IMAP_SERVER_UNAVAILABLE;
	    }
	    str++;
	    if (!strncasecmp(str, "OK ", 3)) { return 0; }
	    if (!strncasecmp(str, "NO ", 3)) { return IMAP_REMOTE_DENIED; }
	    return IMAP_SERVER_UNAVAILABLE; /* huh? */
	}
	/* skip this line, we don't really care */
    }
}

/* given 2 protstreams and a mailbox, gets the acl and then wipes it */
static int trashacl(struct protstream *pin, struct protstream *pout,
		    char *mailbox) 
{
    int i=0, j=0;
    char tagbuf[128];
    int c;		/* getword() returns an int */
    struct buf tag, cmd, tmp, user;
    int r = 0;

    memset(&tag, 0, sizeof(struct buf));
    memset(&cmd, 0, sizeof(struct buf));
    memset(&tmp, 0, sizeof(struct buf));
    memset(&user, 0, sizeof(struct buf));

    prot_printf(pout, "ACL0 GETACL {%d+}\r\n%s\r\n",
		strlen(mailbox), mailbox);

    while(1) {
	c = getword(pin, &tag);
	if (c == EOF) {
	    r = IMAP_SERVER_UNAVAILABLE;
	    break;
	}

	c = getword(pin, &cmd);
	if (c == EOF) {
	    r = IMAP_SERVER_UNAVAILABLE;
	    break;
	}
	
	if(c == '\r') {
	    c = prot_getc(pin);
	    if(c != '\n') {
		r = IMAP_SERVER_UNAVAILABLE;
		goto cleanup;
	    }
	}
	if(c == '\n') goto cleanup;	

	if (tag.s[0] == '*' && !strncmp(cmd.s, "ACL", 3)) {
	    while(c != '\n') {
		/* An ACL response, we should send a DELETEACL command */
		c = getastring(pin, pout, &tmp);
		if (c == EOF) {
		    r = IMAP_SERVER_UNAVAILABLE;
		    goto cleanup;
		}

		if(c == '\r') {
		    c = prot_getc(pin);
		    if(c != '\n') {
			r = IMAP_SERVER_UNAVAILABLE;
			goto cleanup;
		    }
		}
		if(c == '\n') goto cleanup;
		
		c = getastring(pin, pout, &user);
		if (c == EOF) {
		    r = IMAP_SERVER_UNAVAILABLE;
		    goto cleanup;
		}

		snprintf(tagbuf, sizeof(tagbuf), "ACL%d", ++i);
		
		prot_printf(pout, "%s DELETEACL {%d+}\r\n%s {%d+}\r\n%s\r\n",
			    tagbuf, strlen(mailbox), mailbox,
			    strlen(user.s), user.s);
		if(c == '\r') {
		    c = prot_getc(pin);
		    if(c != '\n') {
			r = IMAP_SERVER_UNAVAILABLE;
			goto cleanup;
		    }
		}
		/* if the next character is \n, we'll exit the loop */
	    }
	    continue;
	} else if (!strncmp(tag.s, "ACL0", 4)) {
	    /* end of this command */
	    if (!strcasecmp(cmd.s, "OK")) { break; }
	    if (!strcasecmp(cmd.s, "NO")) { r = IMAP_REMOTE_DENIED; break; }
	    r = IMAP_SERVER_UNAVAILABLE;
	    break;
	}
    }

    cleanup:

    /* Now cleanup after all the DELETEACL commands */
    if(!r) {
	while(j < i) {
	    c = getword(pin, &tag);
	    if (c == EOF) {
		r = IMAP_SERVER_UNAVAILABLE;
		break;
	    }
	    
	    eatline(pin, c);
	    
	    if(!strncmp("ACL", tag.s, 3)) {
		j++;
	    }
	}
    }

    if(r) eatline(pin, c);

    freebuf(&user);
    freebuf(&tmp);
    freebuf(&cmd);
    freebuf(&tag);

    return r;
}

static int dumpacl(struct protstream *pin, struct protstream *pout,
		   char *mailbox, char *acl_in) 
{
    int r = 0;
    int c;		/* getword() returns an int */
    char tag[128];
    int tagnum = 1;
    char *rights, *nextid;
    int mailboxlen = strlen(mailbox);
    char *acl_safe = acl_in ? xstrdup(acl_in) : NULL;
    char *acl = acl_safe;
    struct buf inbuf;
    
    memset(&inbuf, 0, sizeof(struct buf));

    while (acl) {
	rights = strchr(acl, '\t');
	if (!rights) break;
	*rights++ = '\0';
	
	nextid = strchr(rights, '\t');
	if (!nextid) break;
	*nextid++ = '\0';

	snprintf(tag, sizeof(tag), "SACL%d", tagnum++);
	
	prot_printf(pout, "%s SETACL {%d+}\r\n%s {%d+}\r\n%s {%d+}\r\n%s\r\n",
		    tag,
		    mailboxlen, mailbox,
		    strlen(acl), acl,
		    strlen(rights), rights);

	while(1) {
	    c = getword(pin, &inbuf);
	    if (c == EOF) {
		r = IMAP_SERVER_UNAVAILABLE;
		break;
	    }
	    if(strncmp(tag, inbuf.s, strlen(tag))) {
		eatline(pin, c);
		continue;
	    } else {
		/* this is our line */
		break;
	    }
	}

	/* Are we OK? */

	c = getword(pin, &inbuf);
	if (c == EOF) {
	    r = IMAP_SERVER_UNAVAILABLE;
	    break;
	}

	if(strncmp("OK", inbuf.s, 2)) {
	    r = IMAP_REMOTE_DENIED;
	    break;
	}

	/* Eat the line and get the next one */
	eatline(pin, c);
	acl = nextid;
    }

    freebuf(&inbuf);
    if(acl_safe) free(acl_safe);

    return r;
}

static int do_xfer_single(char *toserver, char *topart,
			  char *name, char *mailboxname,
			  int mbflags, 
			  char *path, char *mpath, char *part, char *acl,
			  int prereserved,
			  mupdate_handle *h_in,
			  struct backend *be_in) 
{
    int r = 0, rerr = 0;
    char buf[MAX_PARTITION_LEN+HOSTNAME_SIZE+2];
    struct backend *be = NULL;
    mupdate_handle *mupdate_h = NULL;
    int backout_mupdate = 0;
    int backout_remotebox = 0;
    int backout_remoteflag = 0;

    /* Make sure we're given a sane value */
    if(topart && !imparse_isatom(topart)) {
	return IMAP_PARTITION_UNKNOWN;
    }

    if(!strcmp(toserver, config_servername)) {
	return IMAP_BAD_SERVER;
    }
    
    /* Okay, we have the mailbox, now the order of steps is:
     *
     * 1) Connect to remote server.
     * 2) LOCALCREATE on remote server
     * 2.5) Set mailbox as REMOTE on local server
     * 3) mupdate.DEACTIVATE(mailbox, remoteserver) xxx what partition?
     * 4) undump mailbox from local to remote
     * 5) Sync remote acl
     * 6) mupdate.ACTIVATE(mailbox, remoteserver)
     * ** MAILBOX NOW LIVING ON REMOTE SERVER
     * 6.5) force remote server to push the final mupdate entry to ensure
     *      that the state of the world is correct (required if we do not
     *      know the remote partition, but worst case it will be caught
     *      when they next sync)
     * 7) local delete of mailbox
     * 8) remove local remote mailbox entry??????
     */

    /* Step 1: Connect to remote server */
    if(!r && !be_in) {
	/* Just authorize as the IMAP server, so pass "" as our authzid */
	be = backend_connect(NULL, toserver, &imap_protocol,
			     "", NULL, NULL);
	if(!be) r = IMAP_SERVER_UNAVAILABLE;
	if(r) syslog(LOG_ERR,
		     "Could not move mailbox: %s, Backend connect failed",
		     mailboxname);
    } else if(!r) {
	be = be_in;
    }

    /* Step 1a: Connect to mupdate (as needed) */
    if(h_in) {
	mupdate_h = h_in;
    } else if (config_mupdate_server) {
	r = mupdate_connect(config_mupdate_server, NULL, &mupdate_h, NULL);
	if(r) {
	    syslog(LOG_ERR,
		   "Could not move mailbox: %s, MUPDATE connect failed",
		   mailboxname);
	    goto done;
	}

    }

    /* Step 2: LOCALCREATE on remote server */
    if(!r) {
	if(topart) {
	    /* need to send partition as an atom */
	    prot_printf(be->out, "LC1 LOCALCREATE {%d+}\r\n%s %s\r\n",
			strlen(name), name, topart);
	} else {
	    prot_printf(be->out, "LC1 LOCALCREATE {%d+}\r\n%s\r\n",
			strlen(name), name);
	}
	r = getresult(be->in, "LC1");
	if(r) syslog(LOG_ERR, "Could not move mailbox: %s, LOCALCREATE failed",
		     mailboxname);
	else backout_remotebox = 1;
    }

    /* Step 2.5: Set mailbox as REMOTE on local server */
    if(!r) {
	snprintf(buf, sizeof(buf), "%s!%s", toserver, part);
	r = mboxlist_update(mailboxname, mbflags|MBTYPE_MOVING, buf, acl, 1);
	if(r) syslog(LOG_ERR, "Could not move mailbox: %s, " \
		     "mboxlist_update failed", mailboxname);
    }

    /* Step 3: mupdate.DEACTIVATE(mailbox, newserver) */
    /* (only if mailbox has not been already deactivated by our caller) */
    if(!r && mupdate_h && !prereserved) {
	backout_remoteflag = 1;

	/* Note we are making the reservation on OUR host so that recovery
	 * make sense */
	snprintf(buf, sizeof(buf), "%s!%s", config_servername, part);
	r = mupdate_deactivate(mupdate_h, mailboxname, buf);
	if(r) syslog(LOG_ERR,
		     "Could not move mailbox: %s, MUPDATE DEACTIVATE failed",
		     mailboxname);
    }

    /* Step 4: Dump local -> remote */
    if(!r) {
	backout_mupdate = 1;

	prot_printf(be->out, "D01 UNDUMP {%d+}\r\n%s ", strlen(name), name);

	r = dump_mailbox(NULL, mailboxname, path, mpath, acl,
			 0, be->in, be->out, imapd_authstate);

	if(r)
	    syslog(LOG_ERR,
		   "Could not move mailbox: %s, dump_mailbox() failed",
		   mailboxname);
    }

    if(!r) {
	r = getresult(be->in, "D01");
	if(r) syslog(LOG_ERR, "Could not move mailbox: %s, UNDUMP failed",
		     mailboxname);
    }
    
    /* Step 5: Set ACL on remote */
    if(!r) {
	r = trashacl(be->in, be->out, name);
	if(r) syslog(LOG_ERR, "Could not clear remote acl on %s",
		     mailboxname);
    }
    if(!r) {
	r = dumpacl(be->in, be->out, name, acl);
	if(r) syslog(LOG_ERR, "Could not set remote acl on %s",
		     mailboxname);
    }

    /* Step 6: mupdate.activate(mailbox, remote) */
    /* We do this from the local server first so that recovery is easier */
    if(!r && mupdate_h) {
	/* Note the flag that we don't have a valid partiton at the moment */
	snprintf(buf, sizeof(buf), "%s!MOVED", toserver);
	r = mupdate_activate(mupdate_h, mailboxname, buf, acl);
    }
    
    /* MAILBOX NOW LIVES ON REMOTE */
    if(!r) {
	backout_remotebox = 0;
	backout_mupdate = 0;
	backout_remoteflag = 0;

	/* 6.5) Kick remote server to correct mupdate entry */
	/* Note that we don't really care if this succeeds or not */
	if (mupdate_h) {
	    prot_printf(be->out, "MP1 MUPDATEPUSH {%d+}\r\n%s\r\n",
			strlen(name), name);
	    rerr = getresult(be->in, "MP1");
	    if(rerr) {
		syslog(LOG_ERR,
		       "Could not trigger remote push to mupdate server" \
		       "during move of %s",
		       mailboxname);
	    }
	}
    }

    /* 7) local delete of mailbox
     * & remove local "remote" mailboxlist entry */
    if(!r) {
	if (config_mupdate_config != IMAP_ENUM_MUPDATE_CONFIG_UNIFIED) {
	    /* Note that we do not check the ACL, and we don't update MUPDATE */
	    /* note also that we need to remember to let proxyadmins do this */
	    r = mboxlist_deletemailbox(mailboxname,
				       imapd_userisadmin || imapd_userisproxyadmin,
				       imapd_userid, imapd_authstate, 0, 1, 0);
	    if(r) syslog(LOG_ERR,
			 "Could not delete local mailbox during move of %s",
			 mailboxname);
	} else {
	    /* Can't trust local mailboxes database with unified config */
	    struct mailbox mailbox;

	    r = mailbox_open_locked(mailboxname, path, mpath,
				    acl, 0, &mailbox, 0);
	    if(r) syslog(LOG_ERR,
			 "Could not open local mailbox during move of %s",
			 mailboxname);
	    if(!r) {
		/* Delete mailbox and quota root */
		r = mailbox_delete(&mailbox, 0);
		if(r) syslog(LOG_ERR,
			     "Could not delete local mailbox during move of %s",
			     mailboxname);
	    }
	}

	if (!r) {
	    /* Delete mailbox annotations */
	    annotatemore_delete(mailboxname);
	    sync_log_mailbox(mailboxname);
	}
     }

done:
    if(r && mupdate_h && backout_mupdate) {
	rerr = 0;
	/* xxx if the mupdate server is what failed, then this won't
	   help any! */
	snprintf(buf, sizeof(buf), "%s!%s", config_servername, part);
	rerr = mupdate_activate(mupdate_h, mailboxname, buf, acl);
	if(rerr) {
	    syslog(LOG_ERR,
		   "Could not back out mupdate during move of %s (%s)",
		   mailboxname, error_message(rerr));
	}
    }
    if(r && backout_remotebox) {
	rerr = 0;
	prot_printf(be->out, "LD1 LOCALDELETE {%d+}\r\n%s\r\n",
		    strlen(name), name);
	rerr = getresult(be->in, "LD1");
 	if(rerr) {
	    syslog(LOG_ERR,
		   "Could not back out remote mailbox during move of %s (%s)",
		   name, error_message(rerr));
	}   
    }
    if(r && backout_remoteflag) {
	rerr = 0;

	rerr = mboxlist_update(mailboxname, mbflags, part, acl, 1);
	if(rerr) syslog(LOG_ERR, "Could not unset remote flag on mailbox: %s",
			mailboxname);
    }

    /* release the handles we got locally if necessary */
    if(mupdate_h && !h_in)
	mupdate_disconnect(&mupdate_h);
    if(be && !be_in)
	backend_disconnect(be);

    return r;
}

struct xfer_user_rock 
{
    char *toserver;
    char *topart;
    mupdate_handle *h;
    struct backend *be;
};

static int xfer_user_cb(char *name,
			int matchlen __attribute__((unused)),
			int maycreate __attribute__((unused)),
			void *rock) 
{
    mupdate_handle *mupdate_h = ((struct xfer_user_rock *)rock)->h;
    char *toserver = ((struct xfer_user_rock *)rock)->toserver;
    char *topart = ((struct xfer_user_rock *)rock)->topart;
    struct backend *be = ((struct xfer_user_rock *)rock)->be;
    char externalname[MAX_MAILBOX_NAME+1];
    int mbflags;
    int r = 0;
    char *inpath, *inmpath, *inpart, *inacl;
    char *path = NULL, *mpath = NULL, *part = NULL, *acl = NULL;

    if (!r) {
	/* NOTE: NOT mlookup() because we don't want to issue a referral */
	r = mboxlist_detail(name, &mbflags,
			    &inpath, &inmpath, &inpart, &inacl, NULL);
    }
    
    if (!r && (mbflags & MBTYPE_REMOTE)) {
	/* Skip remote mailbox */
	return 0;
    }

    if (!r) {
	path = xstrdup(inpath);
	if (inmpath) mpath = xstrdup(inmpath);
	part = xstrdup(inpart);
	acl = xstrdup(inacl);
    }

    if (!r) {
	r = (*imapd_namespace.mboxname_toexternal)(&imapd_namespace,
						   name,
						   imapd_userid,
						   externalname);
    }

    if(!r) {
	r = do_xfer_single(toserver, topart, externalname, name, mbflags,
			   path, mpath, part, acl, 0, mupdate_h, be);
    }

    if(path) free(path);
    if(mpath) free(mpath);
    if(part) free(part);
    if(acl) free(acl);

    return r;
}


void cmd_xfer(char *tag, char *name, char *toserver, char *topart)
{
    int r = 0;
    char buf[MAX_PARTITION_LEN+HOSTNAME_SIZE+2];
    char mailboxname[MAX_MAILBOX_NAME+1];
    int mbflags;
    int moving_user = 0;
    int backout_mupdate = 0;
    mupdate_handle *mupdate_h = NULL;
    char *inpath, *inmpath, *inpart, *inacl;
    char *path = NULL, *mpath = NULL, *part = NULL, *acl = NULL;
    char *p, *mbox = mailboxname;
    
    /* administrators only please */
    /* however, proxys can do this, if their authzid is an admin */
    if (!imapd_userisadmin && !imapd_userisproxyadmin) {
	r = IMAP_PERMISSION_DENIED;
    }

    if (!r) {
	r = (*imapd_namespace.mboxname_tointernal)(&imapd_namespace,
						   name,
						   imapd_userid,
						   mailboxname);
    }

    /* NOTE: Since XFER can only be used by an admin, and we always connect
     * to the destination backend as an admin, we take advantage of the fact
     * that admins *always* use a consistent mailbox naming scheme.
     * So, 'name' should be used in any command we send to a backend, and
     * 'mailboxname' is the internal name to be used for mupdate and findall.
     */

    if (config_virtdomains && (p = strchr(mailboxname, '!'))) {
	/* pointer to mailbox w/o domain prefix */
	mbox = p + 1;
    }

    if(!strncmp(mbox, "user.", 5) && !strchr(mbox+5, '.')) {
	if ((strlen(mbox+5) == (strlen(imapd_userid) - (mbox - mailboxname))) &&
	    !strncmp(mbox+5, imapd_userid, strlen(mbox+5))) {
	    /* don't move your own inbox, that could be troublesome */
	    r = IMAP_MAILBOX_NOTSUPPORTED;
	} else if (!config_getswitch(IMAPOPT_ALLOWUSERMOVES)) {
	    /* not configured to allow user moves */
	    r = IMAP_MAILBOX_NOTSUPPORTED;
	} else {
	    moving_user = 1;
	}
    }
    
    if (!r) {
	r = mlookup(tag, name, mailboxname, &mbflags,
		    &inpath, &inmpath, &inpart, &inacl, NULL);
    }
    if (r == IMAP_MAILBOX_MOVED) return;
    
    if (!r) {
	path = xstrdup(inpath);
	if (inmpath) mpath = xstrdup(inmpath);
	part = xstrdup(inpart);
	acl = xstrdup(inacl);
    }

    /* if we are not moving a user, just move the one mailbox */
    if(!r && !moving_user) {
	r = do_xfer_single(toserver, topart, name, mailboxname, mbflags,
			   path, mpath, part, acl, 0, NULL, NULL);
    } else if (!r) {
	struct backend *be = NULL;
	
	/* we need to reserve the users inbox - connect to mupdate */
	if(!r && config_mupdate_server) {
	    r = mupdate_connect(config_mupdate_server, NULL, &mupdate_h, NULL);
	    if(r) {
		syslog(LOG_ERR,
		       "Could not move mailbox: %s, MUPDATE connect failed",
		       mailboxname);
		goto done;
	    }
	}

	/* Get a single connection to the remote backend */
	be = backend_connect(NULL, toserver, &imap_protocol,
			     "", NULL, NULL);
	if(!be) {
	    r = IMAP_SERVER_UNAVAILABLE;
	    syslog(LOG_ERR,
		   "Could not move mailbox: %s, " \
		   "Initial backend connect failed",
		   mailboxname);
	}

	/* deactivate their inbox */
	if(!r && mupdate_h) {
	    /* Note we are making the reservation on OUR host so that recovery
	     * make sense */
	    snprintf(buf, sizeof(buf), "%s!%s", config_servername, part);
	    r = mupdate_deactivate(mupdate_h, mailboxname, buf);
	    if(r) syslog(LOG_ERR,
			 "Could not deactivate mailbox: %s, during move (%s)",
			 mailboxname, error_message(r));
	    else backout_mupdate = 1;
	}

	/* If needed, set an uppermost quota root */
	if(!r) {
	    struct quota quota;
	    
	    quota.root = mailboxname;
	    r = quota_read(&quota, NULL, 0);
	    
	    if(!r) {
		/* note use of + to force the setting of a nonexistant
		 * quotaroot */
		prot_printf(be->out, "Q01 SETQUOTA {%d+}\r\n" \
			    "+%s (STORAGE %d)\r\n",
			    strlen(name)+1, name, quota.limit);
		r = getresult(be->in, "Q01");
		if(r) syslog(LOG_ERR,
			     "Could not move mailbox: %s, " \
			     "failed setting initial quota root\r\n",
			     mailboxname);
	    }
	    else if (r == IMAP_QUOTAROOT_NONEXISTENT) r = 0;
	}


	/* recursively move all sub-mailboxes, using internal names */
	if(!r) {
	    struct xfer_user_rock rock;

	    rock.toserver = toserver;
	    rock.topart = topart;
	    rock.h = mupdate_h;
	    rock.be = be;

	    snprintf(buf, sizeof(buf), "%s.*", mailboxname);
	    r = mboxlist_findall(NULL, buf, 1, imapd_userid,
				 imapd_authstate, xfer_user_cb,
				 &rock);
	}

	/* xxx how do you back out if one of the above moves fails? */
	    
	/* move this mailbox */
	/* ...and seen file, and subs file, and sieve scripts... */
	if(!r) {
	    r = do_xfer_single(toserver, topart, name, mailboxname, mbflags,
			       path, mpath, part, acl, 1, mupdate_h, be);
	}

	if(be) {
	    backend_disconnect(be);
	    free(be);
	}

	if(r && mupdate_h && backout_mupdate) {
	    int rerr = 0;
	    /* xxx if the mupdate server is what failed, then this won't
	       help any! */
	    snprintf(buf, sizeof(buf), "%s!%s", config_servername, part);
	    rerr = mupdate_activate(mupdate_h, mailboxname, buf, acl);
	    if(rerr) {
		syslog(LOG_ERR,
		       "Could not back out mupdate during move of %s (%s)",
		       mailboxname, error_message(rerr));
	    }
	} else if(!r) {
	    /* this was a successful user delete, and we need to delete
	       certain user meta-data (but not seen state!) */
	    user_deletedata(mailboxname+5, imapd_userid, imapd_authstate, 0);
	    sync_log_user(mboxname_inbox_touserid(mailboxname));
	}
	
	if(!r && mupdate_h) {
	    mupdate_disconnect(&mupdate_h);
	}
    }

 done:
    if(part) free(part);
    if(path) free(path);
    if(mpath) free(mpath);
    if(acl) free(acl);

    imapd_check(NULL, 0, 0);

    if (r) {
	prot_printf(imapd_out, "%s NO %s\r\n",
		    tag,
		    error_message(r));
    } else {
	prot_printf(imapd_out, "%s OK %s\r\n", tag,
		    error_message(IMAP_OK_COMPLETED));
    }

    return;
}

/*
 * Parse a "date", for SEARCH criteria
 * The time_t's pointed to by 'start' and 'end' are set to the
 * times of the start and end of the parsed date.
 */
int getsearchdate(start, end)
time_t *start, *end;
{
    int c;
    struct tm tm;
    int quoted = 0;
    char month[4];

    memset(&tm, 0, sizeof tm);

    c = prot_getc(imapd_in);
    if (c == '\"') {
	quoted++;
	c = prot_getc(imapd_in);
    }

    /* Day of month */
    if (!isdigit(c)) goto baddate;
    tm.tm_mday = c - '0';
    c = prot_getc(imapd_in);
    if (isdigit(c)) {
	tm.tm_mday = tm.tm_mday * 10 + c - '0';
	c = prot_getc(imapd_in);
    }
    
    if (c != '-') goto baddate;
    c = prot_getc(imapd_in);

    /* Month name */
    if (!isalpha(c)) goto baddate;
    month[0] = c;
    c = prot_getc(imapd_in);
    if (!isalpha(c)) goto baddate;
    month[1] = c;
    c = prot_getc(imapd_in);
    if (!isalpha(c)) goto baddate;
    month[2] = c;
    c = prot_getc(imapd_in);
    month[3] = '\0';
    lcase(month);

    for (tm.tm_mon = 0; tm.tm_mon < 12; tm.tm_mon++) {
	if (!strcmp(month, monthname[tm.tm_mon])) break;
    }
    if (tm.tm_mon == 12) goto baddate;

    if (c != '-') goto baddate;
    c = prot_getc(imapd_in);

    /* Year */
    if (!isdigit(c)) goto baddate;
    tm.tm_year = c - '0';
    c = prot_getc(imapd_in);
    if (!isdigit(c)) goto baddate;
    tm.tm_year = tm.tm_year * 10 + c - '0';
    c = prot_getc(imapd_in);
    if (isdigit(c)) {
	if (tm.tm_year < 19) goto baddate;
	tm.tm_year -= 19;
	tm.tm_year = tm.tm_year * 10 + c - '0';
	c = prot_getc(imapd_in);
	if (!isdigit(c)) goto baddate;
	tm.tm_year = tm.tm_year * 10 + c - '0';
	c = prot_getc(imapd_in);
    }

    if (quoted) {
	if (c != '\"') goto baddate;
	c = prot_getc(imapd_in);
    }

    tm.tm_isdst = -1;
    *start = mktime(&tm);

    tm.tm_hour = 24;
    tm.tm_isdst = -1;
    *end = mktime(&tm);

    return c;

 baddate:
    prot_ungetc(c, imapd_in);
    return EOF;
}

#define SORTGROWSIZE	10

/*
 * Parse sort criteria
 */
int getsortcriteria(char *tag, struct sortcrit **sortcrit)
{
    int c;
    static struct buf criteria;
    int nsort, n;

    *sortcrit = NULL;

    c = prot_getc(imapd_in);
    if (c != '(') goto missingcrit;

    c = getword(imapd_in, &criteria);
    if (criteria.s[0] == '\0') goto missingcrit;

    nsort = 0;
    n = 0;
    for (;;) {
	if (n >= nsort - 1) {	/* leave room for implicit criterion */
	    /* (Re)allocate an array for sort criteria */
	    nsort += SORTGROWSIZE;
	    *sortcrit =
		(struct sortcrit *) xrealloc(*sortcrit,
					     nsort * sizeof(struct sortcrit));
	    /* Zero out the newly added sortcrit */
	    memset((*sortcrit)+n, 0, SORTGROWSIZE * sizeof(struct sortcrit));
	}

	lcase(criteria.s);
	if (!strcmp(criteria.s, "reverse")) {
	    (*sortcrit)[n].flags |= SORT_REVERSE;
	    goto nextcrit;
	}
	else if (!strcmp(criteria.s, "arrival"))
	    (*sortcrit)[n].key = SORT_ARRIVAL;
	else if (!strcmp(criteria.s, "cc"))
	    (*sortcrit)[n].key = SORT_CC;
	else if (!strcmp(criteria.s, "date"))
	    (*sortcrit)[n].key = SORT_DATE;
	else if (!strcmp(criteria.s, "from"))
	    (*sortcrit)[n].key = SORT_FROM;
	else if (!strcmp(criteria.s, "size"))
	    (*sortcrit)[n].key = SORT_SIZE;
	else if (!strcmp(criteria.s, "subject"))
	    (*sortcrit)[n].key = SORT_SUBJECT;
	else if (!strcmp(criteria.s, "to"))
	    (*sortcrit)[n].key = SORT_TO;
#if 0
	else if (!strcmp(criteria.s, "annotation")) {
	    (*sortcrit)[n].key = SORT_ANNOTATION;
	    if (c != ' ') goto missingarg;
	    c = getstring(imapd_in, &arg);
	    if (c != ' ') goto missingarg;
	    (*sortcrit)[n].args.annot.entry = xstrdup(arg.s);
	    c = getstring(imapd_in, &arg);
	    if (c == EOF) goto missingarg;
	    (*sortcrit)[n].args.annot.attrib = xstrdup(arg.s);
	}
#endif
	else if ((imapd_mailbox->options & OPT_IMAP_CONDSTORE) &&
		 !strcmp(criteria.s, "modseq"))
	    (*sortcrit)[n].key = SORT_MODSEQ;
	else {
	    prot_printf(imapd_out, "%s BAD Invalid Sort criterion %s\r\n",
			tag, criteria.s);
	    if (c != EOF) prot_ungetc(c, imapd_in);
	    return EOF;
	}

	n++;

 nextcrit:
	if (c == ' ') c = getword(imapd_in, &criteria);
	else break;
    }

    if ((*sortcrit)[n].flags & SORT_REVERSE  && !(*sortcrit)[n].key) {
	prot_printf(imapd_out,
		    "%s BAD Missing Sort criterion to reverse\r\n", tag);
	if (c != EOF) prot_ungetc(c, imapd_in);
	return EOF;
    }

    if (c != ')') {
	prot_printf(imapd_out,
		    "%s BAD Missing close parenthesis in Sort\r\n", tag);
	if (c != EOF) prot_ungetc(c, imapd_in);
	return EOF;
    }

    /* Terminate the list with the implicit sort criterion */
    (*sortcrit)[n++].key = SORT_SEQUENCE;

    c = prot_getc(imapd_in);

    return c;

 missingcrit:
    prot_printf(imapd_out, "%s BAD Missing Sort criteria\r\n", tag);
    if (c != EOF) prot_ungetc(c, imapd_in);
    return EOF;
#if 0 /* For annotations stuff above */
 missingarg:
    prot_printf(imapd_out, "%s BAD Missing argument to Sort criterion %s\r\n",
		tag, criteria.s);
    if (c != EOF) prot_ungetc(c, imapd_in);
    return EOF;
#endif
}

#ifdef ENABLE_LISTEXT
/*
 * Parse LIST options.
 * The command has been parsed up to and including the opening '('.
 */
int getlistopts(char *tag, unsigned *listopts)
{
    int c;
    static struct buf arg;

    *listopts = LIST_EXT;

    for (;;) {
	c = getword(imapd_in, &arg);
	if (!arg.s[0]) break;

	lcase(arg.s);
	if (!strcmp(arg.s, "subscribed")) {
	    *listopts |= LIST_SUBSCRIBED;
	}
	else if (!strcmp(arg.s, "children")) {
	    *listopts |= LIST_CHILDREN;
	}
	else if (!strcmp(arg.s, "remote")) {
	    *listopts |= LIST_REMOTE;
	}
	else {
	    prot_printf(imapd_out, "%s BAD Invalid List option %s\r\n",
			tag, arg.s);
	    return EOF;
	}

	if (c != ' ') break;
    }

    if (c != ')') {
	prot_printf(imapd_out,
		    "%s BAD Missing close parenthesis in List\r\n", tag);
	return EOF;
    }

    c = prot_getc(imapd_in);

    return c;
}
#endif /* ENABLE_LISTEXT */

/*
 * Parse a date_time, for the APPEND command
 */
int getdatetime(date)
time_t *date;
{
    int c;
    struct tm tm;
    int old_format = 0;
    char month[4], zone[4], *p;
    time_t tmp_gmtime;
    int zone_off;

    memset(&tm, 0, sizeof tm);

    c = prot_getc(imapd_in);
    if (c != '\"') goto baddate;
    
    /* Day of month */
    c = prot_getc(imapd_in);
    if (c == ' ') c = '0';
    if (!isdigit(c)) goto baddate;
    tm.tm_mday = c - '0';
    c = prot_getc(imapd_in);
    if (isdigit(c)) {
	tm.tm_mday = tm.tm_mday * 10 + c - '0';
	c = prot_getc(imapd_in);
	if(tm.tm_mday <= 0 || tm.tm_mday > 31)
	    goto baddate;
    }
    
    if (c != '-') goto baddate;
    c = prot_getc(imapd_in);

    /* Month name */
    if (!isalpha(c)) goto baddate;
    month[0] = c;
    c = prot_getc(imapd_in);
    if (!isalpha(c)) goto baddate;
    month[1] = c;
    c = prot_getc(imapd_in);
    if (!isalpha(c)) goto baddate;
    month[2] = c;
    c = prot_getc(imapd_in);
    month[3] = '\0';
    lcase(month);

    for (tm.tm_mon = 0; tm.tm_mon < 12; tm.tm_mon++) {
	if (!strcmp(month, monthname[tm.tm_mon])) break;
    }
    if (tm.tm_mon == 12) goto baddate;
    /* xxx this doesn't quite work in leap years */
    if (tm.tm_mday > max_monthdays[tm.tm_mon]) goto baddate;

    if (c != '-') goto baddate;
    c = prot_getc(imapd_in);

    /* Year */
    if (!isdigit(c)) goto baddate;
    tm.tm_year = c - '0';
    c = prot_getc(imapd_in);
    if (!isdigit(c)) goto baddate;
    tm.tm_year = tm.tm_year * 10 + c - '0';
    c = prot_getc(imapd_in);
    if (isdigit(c)) {
	if (tm.tm_year < 19) goto baddate;
	tm.tm_year -= 19;
	tm.tm_year = tm.tm_year * 10 + c - '0';
	c = prot_getc(imapd_in);
	if (!isdigit(c)) goto baddate;
	tm.tm_year = tm.tm_year * 10 + c - '0';
	c = prot_getc(imapd_in);
    }
    else old_format++;

    /* Hour */
    if (c != ' ') goto baddate;
    c = prot_getc(imapd_in);
    if (!isdigit(c)) goto baddate;
    tm.tm_hour = c - '0';
    c = prot_getc(imapd_in);
    if (!isdigit(c)) goto baddate;
    tm.tm_hour = tm.tm_hour * 10 + c - '0';
    c = prot_getc(imapd_in);
    if (tm.tm_hour > 23) goto baddate;

    /* Minute */
    if (c != ':') goto baddate;
    c = prot_getc(imapd_in);
    if (!isdigit(c)) goto baddate;
    tm.tm_min = c - '0';
    c = prot_getc(imapd_in);
    if (!isdigit(c)) goto baddate;
    tm.tm_min = tm.tm_min * 10 + c - '0';
    c = prot_getc(imapd_in);
    if (tm.tm_min > 59) goto baddate;

    /* Second */
    if (c != ':') goto baddate;
    c = prot_getc(imapd_in);
    if (!isdigit(c)) goto baddate;
    tm.tm_sec = c - '0';
    c = prot_getc(imapd_in);
    if (!isdigit(c)) goto baddate;
    tm.tm_sec = tm.tm_sec * 10 + c - '0';
    c = prot_getc(imapd_in);
    if (tm.tm_min > 60) goto baddate;

    /* Time zone */
    if (old_format) {
	if (c != '-') goto baddate;
	c = prot_getc(imapd_in);

	if (!isalpha(c)) goto baddate;
	zone[0] = c;
	c = prot_getc(imapd_in);

	if (c == '\"') {
	    /* Military (single-char) zones */
	    zone[1] = '\0';
	    lcase(zone);
	    if (zone[0] <= 'm') {
		zone_off = (zone[0] - 'a' + 1)*60;
	    }
	    else if (zone[0] < 'z') {
		zone_off = ('m' - zone[0])*60;
	    }
	    else zone_off = 0;
	}
	else {
	    /* UT (universal time) */
	    zone[1] = c;
	    c = prot_getc(imapd_in);
	    if (c == '\"') {
		zone[2] = '\0';
		lcase(zone);
		if (!strcmp(zone, "ut")) goto baddate;
		zone_off = 0;
	    }
	    else {
		/* 3-char time zone */
		zone[2] = c;
		c = prot_getc(imapd_in);
		if (c != '\"') goto baddate;
		zone[3] = '\0';
		lcase(zone);
		p = strchr("aecmpyhb", zone[0]);
		if (c != '\"' || zone[2] != 't' || !p) goto baddate;
		zone_off = (strlen(p) - 12)*60;
		if (zone[1] == 'd') zone_off -= 60;
		else if (zone[1] != 's') goto baddate;
	    }
	}
    }
    else {
	if (c != ' ') goto baddate;
	c = prot_getc(imapd_in);

	if (c != '+' && c != '-') goto baddate;
	zone[0] = c;

	c = prot_getc(imapd_in);
	if (!isdigit(c)) goto baddate;
	zone_off = c - '0';
	c = prot_getc(imapd_in);
	if (!isdigit(c)) goto baddate;
	zone_off = zone_off * 10 + c - '0';
	c = prot_getc(imapd_in);
	if (!isdigit(c)) goto baddate;
	zone_off = zone_off * 6 + c - '0';
	c = prot_getc(imapd_in);
	if (!isdigit(c)) goto baddate;
	zone_off = zone_off * 10 + c - '0';

	if (zone[0] == '-') zone_off = -zone_off;

	c = prot_getc(imapd_in);
	if (c != '\"') goto baddate;

    }

    c = prot_getc(imapd_in);

    tm.tm_isdst = -1;

    tmp_gmtime = mkgmtime(&tm);
    if(tmp_gmtime == -1) goto baddate;

    *date = tmp_gmtime - zone_off*60;

    return c;

 baddate:
    prot_ungetc(c, imapd_in);
    return EOF;
}

/*
 * Print 's' as a quoted-string or literal (but not an atom)
 */
void
printstring(s)
const char *s;
{
    const char *p;
    int len = 0;

    /* Look for any non-QCHAR characters */
    for (p = s; *p && len < 1024; p++) {
	len++;
	if (*p & 0x80 || *p == '\r' || *p == '\n'
	    || *p == '\"' || *p == '%' || *p == '\\') break;
    }

    /* if it's too long, literal it */
    if (*p || len >= 1024) {
	prot_printf(imapd_out, "{%u}\r\n%s", strlen(s), s);
    } else {
	prot_printf(imapd_out, "\"%s\"", s);
    }
}

/*
 * Print 's' as an atom, quoted-string, or literal
 */
void
printastring(s)
const char *s;
{
    const char *p;
    int len = 0;

    if (imparse_isatom(s)) {
	prot_printf(imapd_out, "%s", s);
	return;
    }

    /* Look for any non-QCHAR characters */
    for (p = s; *p && len < 1024; p++) {
	len++;
	if (*p & 0x80 || *p == '\r' || *p == '\n'
	    || *p == '\"' || *p == '%' || *p == '\\') break;
    }

    /* if it's too long, literal it */
    if (*p || len >= 1024) {
	prot_printf(imapd_out, "{%u}\r\n%s", strlen(s), s);
    } else {
	prot_printf(imapd_out, "\"%s\"", s);
    }
}

/*
 * Append 'section', 'fields', 'trail' to the fieldlist 'l'.
 */
void
appendfieldlist(struct fieldlist **l, char *section,
		struct strlist *fields, char *trail,
		void *d, size_t size)
{
    struct fieldlist **tail = l;

    while (*tail) tail = &(*tail)->next;

    *tail = (struct fieldlist *)xmalloc(sizeof(struct fieldlist));
    (*tail)->section = xstrdup(section);
    (*tail)->fields = fields;
    (*tail)->trail = xstrdup(trail);
    if(d && size) {
	(*tail)->rock = xmalloc(size);
	memcpy((*tail)->rock, d, size);
    } else {
	(*tail)->rock = NULL;
    }
    (*tail)->next = 0;
}


/*
 * Free the fieldlist 'l'
 */
void freefieldlist(struct fieldlist *l)
{
    struct fieldlist *n;

    while (l) {
	n = l->next;
	free(l->section);
	freestrlist(l->fields);
	free(l->trail);
	if (l->rock) free(l->rock);
	free((char *)l);
	l = n;
    }
}

/*
 * Append the searchargs 's1' and 's2' to the sublist of 's'
 */
void
appendsearchargs(s, s1, s2)
struct searchargs *s, *s1, *s2;
{
    struct searchsub **tail = &s->sublist;

    while (*tail) tail = &(*tail)->next;

    *tail = (struct searchsub *)xmalloc(sizeof(struct searchsub));
    (*tail)->sub1 = s1;
    (*tail)->sub2 = s2;
    (*tail)->next = 0;
}


/*
 * Free the searchargs 's'
 */
void
freesearchargs(s)
struct searchargs *s;
{
    struct searchsub *sub, *n;

    if (!s) return;

    freesequencelist(s->sequence);
    freesequencelist(s->uidsequence);
    freestrlist(s->from);
    freestrlist(s->to);
    freestrlist(s->cc);
    freestrlist(s->bcc);
    freestrlist(s->subject);
    freestrlist(s->body);
    freestrlist(s->text);
    freestrlist(s->header_name);
    freestrlist(s->header);

    for (sub = s->sublist; sub; sub = n) {
	n = sub->next;
	freesearchargs(sub->sub1);
	freesearchargs(sub->sub2);
	free(sub);
    }
    free(s);
}

/*
 * Free an array of sortcrit
 */
static void freesortcrit(struct sortcrit *s)
{
    int i = 0;

    if (!s) return;
    do {
	switch (s[i].key) {
	case SORT_ANNOTATION:
	    free(s[i].args.annot.entry);
	    free(s[i].args.annot.attrib);
	    break;
	}
	i++;
    } while (s[i].key != SORT_SEQUENCE);
    free(s);
}

/*
 * Issue a MAILBOX untagged response
 */
static int mailboxdata(char *name,
		       int matchlen __attribute__((unused)),
		       int maycreate __attribute__((unused)),
		       void *rock __attribute__((unused)))
{
    char mboxname[MAX_MAILBOX_PATH+1];

    (*imapd_namespace.mboxname_toexternal)(&imapd_namespace, name,
					   imapd_userid, mboxname);
    prot_printf(imapd_out, "* MAILBOX %s\r\n", mboxname);
    return 0;
}

/*
 * Issue a LIST or LSUB untagged response
 */
static void mstringdata(char *cmd, char *name, int matchlen, int maycreate,
			unsigned listopts)
{
    static char lastname[MAX_MAILBOX_PATH+1];
    static int lastnamedelayed = 0;
    static int lastnamenoinferiors = 0;
    static int nonexistent = 0;
    static int sawuser = 0;
    int lastnamehassub = 0;
    int c, mbtype;
    char mboxname[MAX_MAILBOX_PATH+1];

    /* We have to reset the sawuser flag before each list command.
     * Handle it as a dirty hack.
     */
    if (cmd == NULL) {
	sawuser = 0;
	mstringdatacalls = 0;
	return;
    }
    mstringdatacalls++;

    if (lastnamedelayed) {
	/* Check if lastname has children */
	if (name && strncmp(lastname, name, strlen(lastname)) == 0 &&
	    name[strlen(lastname)] == '.') {
	    lastnamehassub = 1;
	}
	prot_printf(imapd_out, "* %s (", cmd);
	if (nonexistent == IMAP_MAILBOX_RESERVED) {
	    /* LISTEXT wants \\PlaceHolder instead of \\Noselect */
	    if (listopts & LIST_EXT)
		prot_printf(imapd_out, "\\PlaceHolder");
	    else
		prot_printf(imapd_out, "\\Noselect");
	} else if (nonexistent) {
	    prot_printf(imapd_out, "\\NonExistent");
	}
	if (lastnamenoinferiors) {
	    prot_printf(imapd_out, "%s\\Noinferiors", nonexistent ? " " : "");
	}
	else if ((listopts & LIST_CHILDREN) &&
		 /* we can't determine \HasNoChildren for subscriptions */
		 (lastnamehassub ||
		  !(listopts & (LIST_LSUB | LIST_SUBSCRIBED)))) {
	    prot_printf(imapd_out, "%s%s", nonexistent ? " " : "",
			lastnamehassub ? "\\HasChildren" : "\\HasNoChildren");
	}
	prot_printf(imapd_out, ") \"%c\" ", imapd_namespace.hier_sep);
		    
	(*imapd_namespace.mboxname_toexternal)(&imapd_namespace, lastname,
					       imapd_userid, mboxname);
	printstring(mboxname);
	prot_printf(imapd_out, "\r\n");
	lastnamedelayed = lastnamenoinferiors = nonexistent = 0;
    }

    /* Special-case to flush any final state */
    if (!name) {
	lastname[0] = '\0';
	return;
    }

    /* Suppress any output of a partial match */
    if ((name[matchlen]
	 && strncmp(lastname, name, matchlen) == 0
	 && (lastname[matchlen] == '\0' || lastname[matchlen] == '.'))) {
	return;
    }
	
    /*
     * We can get a partial match for "user" multiple times with
     * other matches inbetween.  Handle it as a special case
     */
    if (matchlen == 4 && strncasecmp(name, "user", 4) == 0) {
	if (sawuser) return;
	sawuser = 1;
    }

    strlcpy(lastname, name, sizeof(lastname));
    lastname[matchlen] = '\0';
    nonexistent = 0;

    /* Now we need to see if this mailbox exists */
    /* first convert "INBOX" to "user.<userid>" */
    if (!strncasecmp(lastname, "inbox", 5)) {
	(*imapd_namespace.mboxname_tointernal)(&imapd_namespace, "INBOX",
					       imapd_userid, mboxname);
	strlcat(mboxname, lastname+5, sizeof(mboxname));
    }
    else
	strlcpy(mboxname, lastname, sizeof(mboxname));

    /* Look it up */
    nonexistent = mboxlist_detail(mboxname, &mbtype,
				  NULL, NULL, NULL, NULL, NULL);
    if(!nonexistent && (mbtype & MBTYPE_RESERVE))
	nonexistent = IMAP_MAILBOX_RESERVED;

    if (!name[matchlen]) {
	lastnamedelayed = 1;
	if (!maycreate) lastnamenoinferiors = 1;
	return;
    }

    c = name[matchlen];
    if (c) name[matchlen] = '\0';
    prot_printf(imapd_out, "* %s (", cmd);
    if (c) {
	/* Handle namespace prefix as a special case */ 
	if (!strcmp(name, "user") ||
	    !strcmp(name, imapd_namespace.prefix[NAMESPACE_SHARED])) {
	    prot_printf(imapd_out, "\\Noselect");
	    if (listopts & LIST_EXT)
		prot_printf(imapd_out, " \\PlaceHolder");
	}
	else {
	    if (nonexistent)
		prot_printf(imapd_out, "\\NonExistent");
	    /* LISTEXT uses \PlaceHolder instead of \Noselect */
	    if (listopts & LIST_EXT)
		prot_printf(imapd_out, "%s\\PlaceHolder", nonexistent ? " " : "");
	    else
		prot_printf(imapd_out, "%s\\Noselect", nonexistent ? " " : "");
	}
	if (listopts & LIST_CHILDREN)
	    prot_printf(imapd_out, " \\HasChildren");
    }
    prot_printf(imapd_out, ") \"%c\" ", imapd_namespace.hier_sep);

    (*imapd_namespace.mboxname_toexternal)(&imapd_namespace, name,
					   imapd_userid, mboxname);
    printstring(mboxname);
    prot_printf(imapd_out, "\r\n");
    if (c) name[matchlen] = c;
    return;
}

/*
 * Issue a LIST untagged response
 */
static int listdata(char *name, int matchlen, int maycreate, void *rock)
{
    struct listargs *listargs = (struct listargs *) rock;

    if (name && listargs->scan) {
	/* SCAN mailbox for content */
	char mailboxname[MAX_MAILBOX_NAME+1];
	int r = 0;
	int mbtype;
	char *server;
	static struct mailbox mailbox;

	/* Convert "INBOX" to "user.<userid>" */
	if (!strncasecmp(name, "inbox", 5)) {
	    (*imapd_namespace.mboxname_tointernal)(&imapd_namespace, "INBOX",
						   imapd_userid, mailboxname);
	    strlcat(mailboxname, name+5, sizeof(mailboxname));
	}
	else
	    strlcpy(mailboxname, name, sizeof(mailboxname));

	if (!r) r = mlookup(NULL, NULL, mailboxname, &mbtype, NULL, NULL,
			    &server, NULL, NULL);

	if (!r && (mbtype & MBTYPE_REMOTE) &&
	    !hash_lookup(server, &listargs->server_table)) {
	    /* remote mailbox that we haven't proxied to yet */
	    struct backend *s;

	    hash_insert(server,  (void *)0xDEADBEEF, &listargs->server_table);
	    s = proxy_findserver(server, &imap_protocol,
				 proxy_userid, &backend_cached,
				 &backend_current, &backend_inbox, imapd_in);
	    if (!s) r = IMAP_SERVER_UNAVAILABLE;

	    if (!r) {
		char mytag[128];
		proxy_gentag(mytag, sizeof(mytag));

		prot_printf(s->out,
			    "%s Scan {%d+}\r\n%s {%d+}\r\n%s {%d+}\r\n%s\r\n",
			    mytag,
			    strlen(listargs->ref), listargs->ref,
			    strlen(listargs->pat), listargs->pat,
			    strlen(listargs->scan), listargs->scan);

		r = pipe_until_tag(s, mytag, 0);
	    }

	    return 0;
	}
	else if (!r) {
	    /* local mailbox */
	    int doclose = 0;

	    r = mailbox_open_header(mailboxname, imapd_authstate, &mailbox);

	    if (!r) {
		doclose = 1;
		r = mailbox_open_index(&mailbox);
	    }

	    if (!r && !(mailbox.myrights & ACL_READ)) {
		r = (imapd_userisadmin || (mailbox.myrights & ACL_LOOKUP)) ?
		    IMAP_PERMISSION_DENIED : IMAP_MAILBOX_NONEXISTENT;
	    }

	    if (!r) {
		/* Set the globals in index.c for this mailbox.
		   The globals are used by the search_engines.c */
		index_operatemailbox(&mailbox);
		if (index_scan(&mailbox, listargs->scan) > 0) {
		    mstringdata("LIST", name, matchlen, maycreate, 0);
		}
	    }

	    if (doclose) mailbox_close(&mailbox);

	    return 0;
	}
    }

    mstringdata(((listargs->opts & LIST_LSUB) ? "LSUB" : "LIST"),
	name, matchlen, maycreate, listargs->opts);

    return 0;
}

/* Reset the given sasl_conn_t to a sane state */
static int reset_saslconn(sasl_conn_t **conn) 
{
    int ret;
    sasl_security_properties_t *secprops = NULL;

    sasl_dispose(conn);
    /* do initialization typical of service_main */
    ret = sasl_server_new("imap", config_servername,
		          NULL, NULL, NULL,
			  NULL, 0, conn);
    if(ret != SASL_OK) return ret;

    if(saslprops.ipremoteport)
	ret = sasl_setprop(*conn, SASL_IPREMOTEPORT,
			   saslprops.ipremoteport);
    if(ret != SASL_OK) return ret;
    
    if(saslprops.iplocalport)
	ret = sasl_setprop(*conn, SASL_IPLOCALPORT,
			   saslprops.iplocalport);
    if(ret != SASL_OK) return ret;
    
    secprops = mysasl_secprops(0);
    ret = sasl_setprop(*conn, SASL_SEC_PROPS, secprops);
    if(ret != SASL_OK) return ret;
    /* end of service_main initialization excepting SSF */

    /* If we have TLS/SSL info, set it */
    if(saslprops.ssf) {
	ret = sasl_setprop(*conn, SASL_SSF_EXTERNAL, &saslprops.ssf);
    } else {
	ret = sasl_setprop(*conn, SASL_SSF_EXTERNAL, &extprops_ssf);
    }
    if(ret != SASL_OK) return ret;

    if(saslprops.authid) {
	ret = sasl_setprop(*conn, SASL_AUTH_EXTERNAL, saslprops.authid);
	if(ret != SASL_OK) return ret;
    }
    /* End TLS/SSL Info */

    return SASL_OK;
}

void cmd_mupdatepush(char *tag, char *name)
{
    int r = 0;
    char mailboxname[MAX_MAILBOX_NAME+1];
    char *part, *acl;
    mupdate_handle *mupdate_h = NULL;
    char buf[MAX_PARTITION_LEN + HOSTNAME_SIZE + 2];

    if (!imapd_userisadmin) {
	r = IMAP_PERMISSION_DENIED;
    }
    if (!config_mupdate_server) {
	r = IMAP_SERVER_UNAVAILABLE;
    }

    if (!r) {
	r = (*imapd_namespace.mboxname_tointernal)(&imapd_namespace, name,
						   imapd_userid, mailboxname);
    }

    if (!r) {
	r = mlookup(tag, name, mailboxname, NULL, NULL, NULL,
		    &part, &acl, NULL);
    }
    if (r == IMAP_MAILBOX_MOVED) return;

    /* Push mailbox to mupdate server */
    if (!r) {
	r = mupdate_connect(config_mupdate_server, NULL, &mupdate_h, NULL);
    }

    if (!r) {
	snprintf(buf, sizeof(buf), "%s!%s", config_servername, part);

	r = mupdate_activate(mupdate_h, mailboxname, buf, acl);
    }

    if(mupdate_h) {
	mupdate_disconnect(&mupdate_h);
    }

    if (r) {
	prot_printf(imapd_out, "%s NO %s\r\n", tag, error_message(r));
    }
    else {
	prot_printf(imapd_out, "%s OK %s\r\n", tag,
		    error_message(IMAP_OK_COMPLETED));
    }
}

#ifdef HAVE_SSL
/* Convert the ASCII hex into binary data
 *
 * 'bin' MUST be able to accomodate at least strlen(hex)/2 bytes
 */
void hex2bin(const char *hex, unsigned char *bin, unsigned int *binlen)
{
    int i;
    const char *c;
    unsigned char msn, lsn;

    for (c = hex, i = 0; *c && isxdigit((int) *c); c++) {
	msn = (*c > '9') ? tolower((int) *c) - 'a' + 10 : *c - '0';
	c++;
	lsn = (*c > '9') ? tolower((int) *c) - 'a' + 10 : *c - '0';
	
	bin[i++] = (unsigned char) (msn << 4) | lsn;
    }
    *binlen = i;
}

enum {
    URLAUTH_ALG_HMAC_SHA1 =	0 /* HMAC-SHA1 */
};

void cmd_urlfetch(char *tag)
{
    struct mboxkey *mboxkey_db;
    int c, r, doclose;
    static struct buf arg;
    struct imapurl url;
    char mailboxname[MAX_MAILBOX_NAME+1];
    struct mailbox mboxstruct, *mailbox = NULL;
    unsigned msgno;
    unsigned int token_len;
    int mbtype;
    char *newserver;
    time_t now = time(NULL);

    prot_printf(imapd_out, "* URLFETCH");

    do {
	c = getastring(imapd_in, imapd_out, &arg);
	prot_putc(' ', imapd_out);
	printstring(arg.s);
	prot_putc(' ', imapd_out);

	doclose = 0;
	r = imapurl_fromURL(&url, arg.s);

	/* validate the URL */
	if (r || !url.user || !url.server || !url.mailbox || !url.uid ||
	    (url.section && !*url.section) ||
	    (url.urlauth.access && !(url.urlauth.mech && url.urlauth.token))) {
	    /* missing info */
	    r = IMAP_BADURL;
	} else if (strcmp(url.server, config_servername)) {
	    /* wrong server */
	    r = IMAP_BADURL;
	} else if (url.urlauth.expire &&
		   url.urlauth.expire < mktime(gmtime(&now))) {
	    /* expired */
	    r = IMAP_BADURL;
	} else if (url.urlauth.access) {
	    /* check mechanism & authorization */
	    int authorized = 0;

	    if (!strcasecmp(url.urlauth.mech, "INTERNAL")) {
		if (!strncasecmp(url.urlauth.access, "submit+", 7) &&
		    global_authisa(imapd_authstate, IMAPOPT_SUBMITSERVERS)) {
		    /* authorized submit server */
		    authorized = 1;
		} else if (!strncasecmp(url.urlauth.access, "user+", 5) &&
			   !strcmp(url.urlauth.access+5, imapd_userid)) {
		    /* currently authorized user */
		    authorized = 1;
		} else if (!strcasecmp(url.urlauth.access, "authuser") &&
			   strcmp(imapd_userid, "anonymous")) {
		    /* any non-anonymous authorized user */
		    authorized = 1;
		} else if (!strcasecmp(url.urlauth.access, "anonymous")) {
		    /* anyone */
		    authorized = 1;
		}
	    }

	    if (!authorized) r = IMAP_BADURL;
	}
		
	if (!r) {
	    r = (*imapd_namespace.mboxname_tointernal)(&imapd_namespace,
						       url.mailbox,
						       url.user, mailboxname);
	}
	if (!r) {
	    r = mlookup(NULL, NULL, mailboxname, &mbtype, NULL, NULL,
			&newserver, NULL, NULL);
	}

	if (!r && (mbtype & MBTYPE_REMOTE)) {
	    /* remote mailbox */
	    struct backend *be;

	    be = proxy_findserver(newserver, &imap_protocol,
				  proxy_userid, &backend_cached,
				  &backend_current, &backend_inbox, imapd_in);
	    if (!be) {
		r = IMAP_SERVER_UNAVAILABLE;
	    } else {
		/* XXX  proxy command to backend */
	    }
	    
	    free(url.freeme);

	    continue;
	}

	/* local mailbox */
	if (!r) {
	    if (url.urlauth.token) {
		/* validate the URLAUTH token */
		hex2bin(url.urlauth.token,
			(unsigned char *) url.urlauth.token, &token_len);

		/* first byte is the algorithm used to create token */
		switch (url.urlauth.token[0]) {
		case URLAUTH_ALG_HMAC_SHA1: {
		    const char *key;
		    size_t keylen;
		    unsigned char vtoken[EVP_MAX_MD_SIZE];
		    unsigned int vtoken_len;

		    r = mboxkey_open(url.user, 0, &mboxkey_db);
		    if (r) break;

		    r = mboxkey_read(mboxkey_db, mailboxname, &key, &keylen);
		    if (r) break;

		    HMAC(EVP_sha1(), key, keylen, (unsigned char *) arg.s,
			 url.urlauth.rump_len, vtoken, &vtoken_len);
		    mboxkey_close(mboxkey_db);

		    if (memcmp(vtoken, url.urlauth.token+1, vtoken_len)) {
			r = IMAP_BADURL;
		    }

		    break;
		}
		default:
		    r = IMAP_BADURL;
		    break;
		}
	    }

	    if (!r) {
		if (!imapd_mailbox || strcmp(imapd_mailbox->name, mailboxname)) {
		    /* not the currently selected mailbox, so try to open it */

		    r = mailbox_open_header(mailboxname, imapd_authstate,
					    &mboxstruct);

		    if (!r) {
			doclose = 1;
			r = mailbox_open_index(&mboxstruct);
		    }

		    if (!r && !url.urlauth.access &&
			!(mboxstruct.myrights & ACL_READ)) {
			r = (imapd_userisadmin ||
			     (mboxstruct.myrights & ACL_LOOKUP)) ?
			    IMAP_PERMISSION_DENIED : IMAP_MAILBOX_NONEXISTENT;
		    }

		    if (!r) {
			mailbox = &mboxstruct;
			index_operatemailbox(mailbox);
		    }
		} else {
		    mailbox = imapd_mailbox;
		}
	    }

	    if (r) {
		/* nothing to do, handled up top */
	    } else if (url.uidvalidity &&
		       (mailbox->uidvalidity != url.uidvalidity)) {
		r = IMAP_BADURL;
	    } else if (!url.uid || !(msgno = index_finduid(url.uid)) ||
		       (index_getuid(msgno) != url.uid)) {
		r = IMAP_BADURL;
	    } else {
		r = index_urlfetch(mailbox, msgno, url.section,
				   url.start_octet, url.octet_count,
				   imapd_out, NULL);
	    }

	    free(url.freeme);

	    if (doclose) {
		mailbox_close(&mboxstruct);
		if (imapd_mailbox) index_operatemailbox(imapd_mailbox);
	    }
	}

	if (r) prot_printf(imapd_out, "NIL");

    } while (c == ' ');

    prot_printf(imapd_out, "\r\n");

    if (c == '\r') c = prot_getc(imapd_in);
    if (c != '\n') {
	prot_printf(imapd_out,
		    "%s BAD Unexpected extra arguments to URLFETCH\r\n", tag);
	eatline(imapd_in, c);
    }
    else {
	prot_printf(imapd_out, "%s OK %s\r\n", tag,
		    error_message(IMAP_OK_COMPLETED));
    }
}

/* Convert the binary data into ASCII hex
 *
 * 'hex' MUST be able to accomodate at least 2*binlen+1 bytes
 */
void bin2hex(unsigned char *bin, int binlen, char *hex)
{
    int i;
    unsigned char c;
    
    for (i = 0; i < binlen; i++) {
	c = (bin[i] >> 4) & 0xf;
	hex[i*2] = (c > 9) ? ('a' + c - 10) : ('0' + c);
	c = bin[i] & 0xf;
	hex[i*2+1] = (c > 9) ? ('a' + c - 10) : ('0' + c);
    }
    hex[i*2] = '\0';
}

#define MBOX_KEY_LEN 16		  /* 128 bits */

void cmd_genurlauth(char *tag)
{
    struct mboxkey *mboxkey_db;
    int first = 1;
    int c, r;
    static struct buf arg1, arg2;
    struct imapurl url;
    char mailboxname[MAX_MAILBOX_NAME+1], *urlauth = NULL;
    char newkey[MBOX_KEY_LEN];
    const char *key;
    size_t keylen;
    unsigned char token[EVP_MAX_MD_SIZE+1]; /* +1 for algorithm */
    unsigned int token_len;
    int mbtype;
    char *newserver;
    time_t now = time(NULL);

    r = mboxkey_open(imapd_userid, MBOXKEY_CREATE, &mboxkey_db);
    if (r) {
	prot_printf(imapd_out,
		   "%s NO Can not open mailbox key db for %s: %s\r\n",
		   tag, imapd_userid, error_message(r));
	return;
    }

    do {
	c = getastring(imapd_in, imapd_out, &arg1);
	if (c != ' ') {
	    prot_printf(imapd_out,
			"%s BAD Missing required argument to Genurlauth\r\n",
			tag);
	    eatline(imapd_in, c);
	    return;
	}
	c = getword(imapd_in, &arg2);
	if (strcasecmp(arg2.s, "INTERNAL")) {
	    prot_printf(imapd_out,
			"%s BAD Unknown auth mechanism to Genurlauth %s\r\n",
			tag, arg2.s);
	    eatline(imapd_in, c);
	    return;
	}

	r = imapurl_fromURL(&url, arg1.s);

	/* validate the URL */
	if (r || !url.user || !url.server || !url.mailbox || !url.uid ||
	    (url.section && !*url.section) || !url.urlauth.access) {
	    r = IMAP_BADURL;
	} else if (strcmp(url.user, imapd_userid)) {
	    /* not using currently authorized user's namespace */
	    r = IMAP_BADURL;
	} else if (strcmp(url.server, config_servername)) {
	    /* wrong server */
	    r = IMAP_BADURL;
	} else if (url.urlauth.expire &&
		   url.urlauth.expire < mktime(gmtime(&now))) {
	    /* already expired */
	    r = IMAP_BADURL;
	}

	if (!r) {
	    r = (*imapd_namespace.mboxname_tointernal)(&imapd_namespace,
						       url.mailbox,
						       imapd_userid, mailboxname);
	}
	if (!r) {
	    r = mlookup(NULL, NULL, mailboxname, &mbtype, NULL, NULL,
			&newserver, NULL, NULL);
	}
	if (r) {
	    prot_printf(imapd_out,
			"%s BAD Poorly specified URL to Genurlauth %s\r\n",
			tag, arg1.s);
	    eatline(imapd_in, c);
	    return;
	}

	if (mbtype & MBTYPE_REMOTE) {
	    /* XXX  proxy to backend */
	    continue;
	}

	/* lookup key */
	r = mboxkey_read(mboxkey_db, mailboxname, &key, &keylen);
	if (r) {
	    syslog(LOG_ERR, "DBERROR: error fetching mboxkey: %s",
		   cyrusdb_strerror(r));
	}
	else if (!key) {
	    /* create a new key */
	    RAND_bytes((unsigned char *) newkey, MBOX_KEY_LEN);
	    key = newkey;
	    keylen = MBOX_KEY_LEN;
	    r = mboxkey_write(mboxkey_db, mailboxname, key, keylen);
	    if (r) {
		syslog(LOG_ERR, "DBERROR: error writing new mboxkey: %s",
		       cyrusdb_strerror(r));
	    }
	}

	if (r) {
	    eatline(imapd_in, c);
	    prot_printf(imapd_out,
			"%s NO Error authorizing %s: %s\r\n",
			tag, arg1.s, cyrusdb_strerror(r));
	    return;
	}

	/* first byte is the algorithm used to create token */
	token[0] = URLAUTH_ALG_HMAC_SHA1;
	HMAC(EVP_sha1(), key, keylen, (unsigned char *) arg1.s, strlen(arg1.s),
	     token+1, &token_len);
	token_len++;

	urlauth = xrealloc(urlauth, strlen(arg1.s) + 10 +
			   2 * (EVP_MAX_MD_SIZE+1) + 1);
	strcpy(urlauth, arg1.s);
	strcat(urlauth, ":internal:");
	bin2hex(token, token_len, urlauth+strlen(urlauth));

	if (first) {
	    prot_printf(imapd_out, "* GENURLAUTH");
	    first = 0;
	}
	prot_putc(' ', imapd_out);
	printstring(urlauth);
    } while (c == ' ');

    if (!first) prot_printf(imapd_out, "\r\n");
 
    if (c == '\r') c = prot_getc(imapd_in);
    if (c != '\n') {
	prot_printf(imapd_out,
		    "%s BAD Unexpected extra arguments to GENURLAUTH\r\n", tag);
	eatline(imapd_in, c);
    }
    else {
	prot_printf(imapd_out, "%s OK %s\r\n", tag,
		    error_message(IMAP_OK_COMPLETED));
    }

    mboxkey_close(mboxkey_db);
}

void cmd_resetkey(char *tag, char *mailbox,
		  char *mechanism __attribute__((unused)))
/* XXX we don't support any external mechanisms, so we ignore it */
{
    int r;

    if (mailbox) {
	/* delete key for specified mailbox */
	char mailboxname[MAX_MAILBOX_NAME+1], *newserver;
	int mbtype;
	struct mboxkey *mboxkey_db;

	r = (*imapd_namespace.mboxname_tointernal)(&imapd_namespace,
						   mailbox,
						   imapd_userid, mailboxname);
	if (!r) {
	    r = mlookup(NULL, NULL, mailboxname, &mbtype, NULL, NULL,
			&newserver, NULL, NULL);
	}
	if (r) {
	    prot_printf(imapd_out, "%s NO Error removing key: %s\r\n",
			tag, error_message(r));
	    return;
	}

	if (mbtype & MBTYPE_REMOTE) {
	    /* XXX  proxy to backend */
	    return;
	}

	r = mboxkey_open(imapd_userid, MBOXKEY_CREATE, &mboxkey_db);
	if (!r) {
	    r = mboxkey_write(mboxkey_db, mailboxname, NULL, 0);
	    mboxkey_close(mboxkey_db);
	}

	if (r) {
	    prot_printf(imapd_out, "%s NO Error removing key: %s\r\n",
			tag, cyrusdb_strerror(r));
	} else {
	    prot_printf(imapd_out,
			"%s OK [URLMECH INTERNAL] key removed\r\n", tag);
	}
    }
    else {
	/* delete ALL keys */
	/* XXX  what do we do about multiple backends? */
	r = mboxkey_delete_user(imapd_userid);
	if (r) {
	    prot_printf(imapd_out, "%s NO Error removing keys: %s\r\n",
			tag, cyrusdb_strerror(r));
	} else {
	    prot_printf(imapd_out, "%s OK All keys removed\r\n", tag);
	}
    }
}
#endif /* HAVE_SSL */

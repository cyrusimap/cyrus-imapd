/* deliver.c -- Program to deliver mail to a mailbox
 * Copyright 1999 Carnegie Mellon University
 * $Id: deliver.c,v 1.123.2.11 2000/09/13 18:13:11 ken3 Exp $
 * 
 * No warranties, either expressed or implied, are made regarding the
 * operation, use, or results of the software.
 *
 * Permission to use, copy, modify and distribute this software and its
 * documentation is hereby granted for non-commercial purposes only
 * provided that this copyright notice appears in all copies and in
 * supporting documentation.
 *
 * Permission is also granted to Internet Service Providers and others
 * entities to use the software for internal purposes.
 *
 * The distribution, modification or sale of a product which uses or is
 * based on the software, in whole or in part, for commercial purposes or
 * benefits requires specific, additional permission from:
 *
 *  Office of Technology Transfer
 *  Carnegie Mellon University
 *  5000 Forbes Avenue
 *  Pittsburgh, PA  15213-3890
 *  (412) 268-4387, fax: (412) 268-7395
 *  tech-transfer@andrew.cmu.edu
 *
 */

static char _rcsid[] = "$Id: deliver.c,v 1.123.2.11 2000/09/13 18:13:11 ken3 Exp $";

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <syslog.h>
#include <com_err.h>
#include <errno.h>
#ifdef HAVE_LIBDB
#ifdef HAVE_DB_185_H
#include <db_185.h>
#else
#include <db.h>
#endif
#else
#include <ndbm.h>
#endif

#ifdef USE_SIEVE
#include <sieve_interface.h>

#define HEADERCACHESIZE 4009

#ifdef TM_IN_SYS_TIME
#include <sys/time.h>
#else
#include <time.h>
#endif

#include <pwd.h>
#include <sys/types.h>
#include <sys/wait.h>
#endif

#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sasl.h>

#include "acl.h"
#include "util.h"
#include "auth.h"
#include "prot.h"
#include "imparse.h"
#include "lock.h"
#include "config.h"
#include "exitcodes.h"
#include "imap_err.h"
#include "mailbox.h"
#include "xmalloc.h"
#include "version.h"

struct protstream *deliver_out, *deliver_in;

extern int optind;
extern char *optarg;

extern int errno;

typedef struct deliver_opts {
    int quotaoverride;		/* should i override quota? */
    char *authuser;		/* authenticated user submitting mail */
    struct auth_state *authstate;
} deliver_opts_t;

#ifdef USE_SIEVE
/* data per message */
typedef struct Header {
    char *name;
    int ncontents;
    char *contents[1];
} header_t;
#endif

typedef struct address_data {
    char *mailbox;
    char *detail;
    char *all;
} address_data_t;

typedef struct message_data {
    struct protstream *data;	/* message in temp file */
    struct stagemsg *stage;	/* staging location for single instance
				   store */

    FILE *f;
    char *notifyheader;
    char *id;			/* message id */
    int size;			/* size of message */

    /* msg envelope */
    char *return_path;		/* where to return message */
    address_data_t **rcpt;	/* to receipients of this message */
    char *temp[2];		/* used to avoid extra indirection in
				   getenvelope() */
    int rcpt_num;
#ifdef USE_SIEVE
    /* sieve related data */
    header_t *cache[HEADERCACHESIZE];
#endif
} message_data_t;

/* data per script */
typedef struct script_data {
    char *username;
    char *mailboxname;
    struct auth_state *authstate;
} script_data_t;

int deliver(deliver_opts_t *delopts, message_data_t *msgdata,
	    char **flag, int nflags,
	    char *user, char *mailboxname);

int dupelim = 0;
int logdebug = 0;
int singleinstance = 1;

void savemsg();
char *convert_lmtp();
void clean822space();

static time_t checkdelivered();
static void markdelivered(char *, int, char *, int, time_t);

static char *_get_db_name();
static int _lock_delivered_db();
static void logdupelem();
static void usage();
static void setup_sieve();

int msg_new(message_data_t **m);
void msg_free(message_data_t *m);

#ifdef USE_SIEVE
static sieve_interp_t *sieve_interp;
static int sieve_usehomedir = 0;
static const char *sieve_dir = NULL;
#endif

struct sockaddr_in deliver_localaddr, deliver_remoteaddr;

static sasl_security_properties_t *make_secprops(int min, int max)
{
    sasl_security_properties_t *ret = (sasl_security_properties_t *) 
	xmalloc(sizeof(sasl_security_properties_t));

    ret->maxbufsize = 4000;
    ret->min_ssf = min;		/* minimum allowable security strength */
    ret->max_ssf = max;		/* maximum allowable security strength */

    ret->security_flags = 0;
    if (!config_getswitch("allowplaintext", 1)) {
	ret->security_flags |= SASL_SEC_NOPLAINTEXT;
    }
    ret->security_flags |= SASL_SEC_NOANONYMOUS;

    ret->property_names = NULL;
    ret->property_values = NULL;
    
    return ret;
}

/* this is a wrapper to call the cyrus configuration from SASL */
static int mysasl_config(void *context __attribute__((unused)), 
			 const char *plugin_name,
			 const char *option,
			 const char **result,
			 unsigned *len)
{
    char opt[1024];

    if (strcmp(option, "srvtab")) { /* we don't transform srvtab! */
	int sl = 5 + (plugin_name ? strlen(plugin_name) + 1 : 0);

	strncpy(opt, "sasl_", 1024);
	if (plugin_name) {
	    strncat(opt, plugin_name, 1019);
	    strncat(opt, "_", 1024 - sl);
	}
 	strncat(opt, option, 1024 - sl - 1);
	opt[1023] = '\0';
    } else {
	strncpy(opt, option, 1024);
    }

    *result = config_getstring(opt, NULL);
    if (*result != NULL) {
	if (len) { *len = strlen(*result); }
	return SASL_OK;
    }
   
    return SASL_FAIL;
}

/* returns true if imapd_authstate is in "item";
   expected: item = admins or proxyservers */
static int authisa(char *authname, const char *item)
{
    const char *val = config_getstring(item, "");
    char buf[MAX_MAILBOX_PATH];

    while (*val) {
	char *p;
	
	for (p = (char *) val; *p && !isspace(*p); p++);
	strncpy(buf, val, p-val);
	buf[p-val] = 0;

	if (strcasecmp(authname, buf)==0) {
	    return 1;
	}
	val = p;
	while (*val && isspace(*val)) val++;
    }
    return 0;
}


/* should we allow users to proxy?  return SASL_OK if yes,
   SASL_BADAUTH otherwise */
static mysasl_authproc(void *context __attribute__((unused)),
		       const char *auth_identity,
		       const char *requested_user,
		       const char **user,
		       const char **errstr)
{
    char *p;
    const char *val;
    char *canon_authuser, *canon_requser;
    char *username=NULL, *realm;
    char buf[MAX_MAILBOX_PATH];
    static char replybuf[100];
    int allowed=0;

    canon_authuser = auth_canonifyid(auth_identity);
    if (!canon_authuser) {
	*errstr = "bad userid authenticated";
	return SASL_BADAUTH;
    }
    canon_authuser = xstrdup(canon_authuser);

    canon_requser = auth_canonifyid(requested_user);
    if (!canon_requser) {
	*errstr = "bad userid requested";
	return SASL_BADAUTH;
    }
    canon_requser = xstrdup(canon_requser);

    /* check if remote realm */
    if (realm = strchr(canon_authuser, '@')) {
	realm++;
	val = config_getstring("loginrealms", "");
	while (*val) {
	    if (!strncasecmp(val, realm, strlen(realm)) &&
		(!val[strlen(realm)] || isspace(val[strlen(realm)]))) {
		break;
	    }
	    /* not this realm, try next one */
	    while (*val && !isspace(*val)) val++;
	    while (*val && isspace(*val)) val++;
	}
	if (!*val) {
	    snprintf(replybuf, 100, "cross-realm login %s denied", 
		     canon_authuser);
	    *errstr = replybuf;
	    return SASL_BADAUTH;
	}
    }

    /* ok, is auth_identity an admin? */
    allowed = authisa(canon_authuser, "lmtpadmins");

    if (allowed==0)
    {
      return SASL_BADAUTH;
    }

    free(canon_authuser);
    *user = canon_requser;
    *errstr = NULL;
    return SASL_OK;
}


static struct sasl_callback mysasl_cb[] = {
    { SASL_CB_GETOPT, &mysasl_config, NULL },
    { SASL_CB_PROXY_POLICY, &mysasl_authproc, NULL },
    { SASL_CB_LIST_END, NULL, NULL }
};


int
main(argc, argv)
int argc;
char **argv;
{
    int opt;
    int r;
    int exitval = 0;
    int lmtpflag = 0;
    char *mailboxname = 0;
    char **flag = 0;
    int nflags = 0;
    char *authuser = 0;
    deliver_opts_t *delopts =
	(deliver_opts_t *) xmalloc(sizeof(deliver_opts_t));
    message_data_t *msgdata;

    deliver_in = prot_new(0, 0);
    deliver_out = prot_new(1, 1);
    prot_setflushonread(deliver_in, deliver_out);
    prot_settimeout(deliver_in, 300);

    config_init("deliver");

#ifdef USE_SIEVE
    sieve_usehomedir = config_getswitch("sieveusehomedir", 0);
    if (!sieve_usehomedir) {
	sieve_dir = config_getstring("sievedir", "/usr/sieve");
    } else {
	sieve_dir = NULL;
    }
#endif USE_SIEVE

    singleinstance = config_getswitch("singleinstancestore", 1);

    msg_new(&msgdata);
    memset((void *) delopts, 0, sizeof(deliver_opts_t));

    /* Can't be EC_USAGE; sendmail thinks that EX_USAGE implies
     * a permenant failure.
     */
    if (geteuid() == 0) {
	fatal("must run as the Cyrus user", EC_TEMPFAIL);
    }

    while ((opt = getopt(argc, argv, "df:r:m:a:F:eE:lqD")) != EOF) {
	switch(opt) {
	case 'd':
	    /* Ignore -- /bin/mail compatibility flags */
	    break;

        case 'D':
	    logdebug = 1;
	    break;

	case 'r':
	case 'f':
	    msgdata->return_path = xstrdup(optarg);
	    break;

	case 'm':
	    if (mailboxname) {
		fprintf(stderr, "deliver: multiple -m options\n");
		usage();
	    }
	    if (*optarg) mailboxname = optarg;
	    break;

	case 'a':
	    if (authuser) {
		fprintf(stderr, "deliver: multiple -a options\n");
		usage();
	    }
	    authuser = optarg;
	    break;

	case 'F':
	    if (!isvalidflag(optarg)) break;
	    nflags++;
	    flag = 
		(char **)xrealloc((char *)flag, nflags*sizeof(char *));
	    flag[nflags-1] = optarg;
	    break;

	case 'e':
	    dupelim = 1;
	    break;

	case 'E':
	    exit(prunedelivered(atoi(optarg)));

	case 'l':
	    lmtpflag = 1;
	    break;

	case 'q':
	    delopts->quotaoverride = 1;
	    break;

	default:
	    usage();
	}
    }

#ifdef USE_SIEVE
    /* setup sieve support */
    setup_sieve(delopts, lmtpflag);
#endif

    if (lmtpflag) {
	lmtpmode(delopts);
	exit(0);
    }

    if (authuser) {
	delopts->authuser = auth_canonifyid(authuser);
	if (authuser) {
	    delopts->authstate = auth_newstate(delopts->authuser, (char *)0);
	} else {
	    delopts->authstate = 0;
	}
    }

    /* Copy message to temp file */
    savemsg(msgdata, 0);

    if (optind == argc) {
	/* deliver to global mailbox */
	r = deliver(delopts, msgdata, flag, nflags,
		    (char *)0, mailboxname);
	
	if (r) {
	    com_err(mailboxname, r,
		    (r == IMAP_IOERROR) ? error_message(errno) : NULL);
	}

	exitval = convert_sysexit(r);
    }
    while (optind < argc) {
	/* deliver to users */
	r = deliver(delopts, msgdata, flag, nflags,
		    argv[optind], mailboxname);

	if (r) {
	    com_err(argv[optind], r,
		    (r == IMAP_IOERROR) ? error_message(errno) : NULL);
	}

	if (r && exitval != EC_TEMPFAIL) exitval = convert_sysexit(r);

	optind++;
    }

    msg_free(msgdata);

    exit(exitval);
}

#ifdef USE_SIEVE

static char *make_sieve_db(char *user)
{
    static char buf[MAX_MAILBOX_PATH];

    buf[0] = '.';
    buf[1] = '\0';
    strcat(buf, user);
    strcat(buf, ".sieve.");

    return buf;
}

static int hashheader(char *header)
{
    int x = 0;
    /* any CHAR except ' ', :, or a ctrl char */
    for (; !iscntrl(*header) && (*header != ' ') && (*header != ':'); 
	 header++) {
	x *= 256;
	x += *header;
	x %= HEADERCACHESIZE;
    }
    return x;
}

/* take a list of headers, pull the first one out and return it in
   name and contents.

   copies fin to fout, massaging 

   returns 0 on success, negative on failure */
typedef enum {
    NAME_START,
    NAME,
    COLON,
    BODY_START,
    BODY
} state;

#define NAMEINC 128
#define BODYINC 1024

/* we don't have to worry about dotstuffing here, since it's illegal
   for a header to begin with a dot! */
static int parseheader(struct protstream *fin, FILE *fout, 
		       int lmtpmode, char **headname, char **contents) {
    int c;
    static char *name = NULL, *body = NULL;
    static int namelen = 0, bodylen = 0;
    int off = 0;
    state s = NAME_START;

    if (namelen == 0) {
	namelen += NAMEINC;
	name = (char *) xrealloc(name, namelen * sizeof(char));
    }
    if (bodylen == 0) {
	bodylen += BODYINC;
	body = (char *) xrealloc(body, bodylen * sizeof(char));
    }

    /* there are two ways out of this loop, both via gotos:
       either we successfully read a character (got_header)
       or we hit an error (ph_error) */
    while ((c = prot_getc(fin)) != EOF) { /* examine each character */
	switch (s) {
	case NAME_START:
	    if (c == '\r' || c == '\n') {
		/* no header here! */
		goto ph_error;
	    }
	    if (!isalpha(c)) {
		/* invalid header name */
		goto ph_error;
	    }
	    name[0] = tolower(c);
	    off = 1;
	    s = NAME;
	    break;

	case NAME:
	    if (c == ' ' || c == '\t' || c == ':') {
		name[off] = '\0';
		s = (c == ':' ? BODY_START : COLON);
		break;
	    }
	    if (iscntrl(c)) {
		goto ph_error;
	    }
	    name[off++] = tolower(c);
	    if (off >= namelen - 3) {
		namelen += NAMEINC;
		name = (char *) xrealloc(name, namelen);
	    }
	    break;
	
	case COLON:
	    if (c == ':') {
		s = BODY_START;
	    } else if (c != ' ' && c != '\t') {
		/* i want to avoid confusing dot-stuffing later */
		while (c == '.') {
		    fputc(c, fout);
		    c = prot_getc(fin);
		}
		goto ph_error;
	    }
	    break;

	case BODY_START:
	    if (c == ' ' || c == '\t') /* eat the whitespace */
		break;
	    off = 0;
	    s = BODY;
	    /* falls through! */
	case BODY:
	    /* now we want to convert all newlines into \r\n */
	    if (c == '\r' || c == '\n') {
		int peek;

		peek = prot_getc(fin);
		
		fputc('\r', fout);
		fputc('\n', fout);
		/* we should peek ahead to see if it's folded whitespace */
		if (c == '\r' && peek == '\n') {
		    c = prot_getc(fin);
		} else {
		    c = peek; /* single newline seperator */
		}
		if (c != ' ' && c != '\t') {
		    /* this is the end of the header */
		    body[off] = '\0';
		    prot_ungetc(c, fin);
		    goto got_header;
		}
		/* ignore this whitespace, but we'll copy all the rest in */
		break;
	    } else {
		/* just an ordinary character */
		body[off++] = c;
		if (off >= bodylen - 3) {
		    bodylen += BODYINC;
		    body = (char *) xrealloc(body, bodylen);
		}
	    }
	}

	/* copy this to the output */
	fputc(c, fout);
    }

    /* if we fall off the end of the loop, we hit some sort of error
       condition */

 ph_error:
    /* put the last character back; we'll copy it later */
    prot_ungetc(c, fin);

    /* and we didn't get a header */
    if (headname != NULL) *headname = NULL;
    if (contents != NULL) *contents = NULL;
    return -1;

 got_header:
    if (headname != NULL) *headname = xstrdup(name);
    if (contents != NULL) *contents = xstrdup(body);

    return 0;
}

/* copies the message from fin to fout, massaging accordingly: mostly
 * newlines are fiddled. in lmtpmode, "." terminates; otherwise, EOF
 * does it.  */
static void copy_msg(struct protstream *fin, FILE *fout, 
		     int lmtpmode)
{
    char buf[8192], *p;

    while (prot_fgets(buf, sizeof(buf)-1, fin)) {
	p = buf + strlen(buf) - 1;
	if (p == buf || p[-1] != '\r') {
	    p[0] = '\r';
	    p[1] = '\n';
	    p[2] = '\0';
	} else if (*p == '\r') {
	    if (buf[0] == '\r' && buf[1] == '\0') {
		/* The message contained \r\0, and fgets is confusing us.
		   XXX ignored
		   */
	    } else {
		/*
		 * We were unlucky enough to get a CR just before we ran
		 * out of buffer--put it back.
		 */
		prot_ungetc('\r', fin);
		*p = '\0';
	    }
	}
	/* Remove any lone CR characters */
	while ((p = strchr(buf, '\r')) && p[1] != '\n') {
	    strcpy(p, p+1);
	}
	
	if (lmtpmode && buf[0] == '.') {
	    if (buf[1] == '\r' && buf[2] == '\n') {
		/* End of message */
		goto lmtpdot;
	    }
	    /* Remove the dot-stuffing */
	    fputs(buf+1, fout);
	} else {
	    fputs(buf, fout);
	}
    }

    if (lmtpmode) {
	/* wow, serious error---got a premature EOF */
	exit(EC_TEMPFAIL);
    }

lmtpdot:
    return;
}

static void fill_cache(struct protstream *fin, FILE *fout, 
		       int lmtpmode, message_data_t *m)
{
    /* let's fill that header cache */
    for (;;) {
	char *name, *body;
	int cl, clinit;

	if (parseheader(fin, fout, lmtpmode, &name, &body) < 0) {
	    break;
	}

	/* put it in the hash table */
	clinit = cl = hashheader(name);
	while (m->cache[cl] != NULL && strcmp(name, m->cache[cl]->name)) {
	    cl++;		/* resolve collisions linearly */
	    cl %= HEADERCACHESIZE;
	    if (cl == clinit) break; /* gone all the way around, so bail */
	}

	/* found where to put it, so insert it into a list */
	if (m->cache[cl]) {
	    /* add this body on */
	    m->cache[cl]->contents[m->cache[cl]->ncontents++] = body;

	    /* whoops, won't have room for the null at the end! */
	    if (!(m->cache[cl]->ncontents % 8)) {
		/* increase the size */
		m->cache[cl] = (header_t *)
		    xrealloc(m->cache[cl],sizeof(header_t) +
			     ((8 + m->cache[cl]->ncontents) * sizeof(char *)));
	    }

	    /* have no need of this */
	    free(name);
	} else {
	    /* create a new entry in the hash table */
	    m->cache[cl] = (header_t *) xmalloc(sizeof(header_t) + 
						8 * sizeof(char*));
	    m->cache[cl]->name = name;
	    m->cache[cl]->contents[0] = body;
	    m->cache[cl]->ncontents = 1;
	}

	/* we always want a NULL at the end */
	m->cache[cl]->contents[m->cache[cl]->ncontents] = NULL;
    }

    copy_msg(fin, fout, lmtpmode);
}

/* gets the header "head" from msg. */
static int getheader(void *v, const char *phead, const char ***body)
{
    message_data_t *m = (message_data_t *) v;
    int cl, clinit;
    char *h;
    char *head;

    *body = NULL;

    /* copy header parameter so we can mangle it */
    head = malloc(strlen(phead)+1);
    if (!head) return SIEVE_FAIL;
    strcpy(head, phead);

    h = head;
    while (*h != '\0') {
	if (isupper((int) *h))
	    *h = tolower((int) *h);
	h++;
    }

    /* check the cache */
    clinit = cl = hashheader(head);
    while (m->cache[cl] != NULL) {
	if (!strcmp(head, m->cache[cl]->name)) {
	    *body = (const char **) m->cache[cl]->contents;
	    break;
	}
	cl++; /* try next hash bin */
	cl %= HEADERCACHESIZE;
	if (cl == clinit) break; /* gone all the way around */
    }

    free(head);

    if (*body) {
	return SIEVE_OK;
    } else {
	return SIEVE_FAIL;
    }
}

static int getsize(void *mc, int *size)
{
    message_data_t *m = (message_data_t *) mc;

    *size = m->size;
    return SIEVE_OK;
}

/* we use the temp field in message_data to avoid having to malloc memory
   to return, and we also can't expose our the receipients to the message */
int getenvelope(void *mc, const char *field, const char ***contents)
{
    message_data_t *m = (message_data_t *) mc;

    if (!strcasecmp(field, "from")) {
	*contents = (const char **) m->temp;
	m->temp[0] = m->return_path;
	m->temp[1] = NULL;
	return SIEVE_OK;
    } else if (!strcasecmp(field, "to")) {
	m->temp[0] = m->rcpt[m->rcpt_num]->all;
	m->temp[1] = NULL;
	*contents = (const char **) m->temp;
	return SIEVE_OK;
    } else {
	*contents = NULL;
	return SIEVE_FAIL;
    }
}

#define DEFAULT_SENDMAIL "/usr/lib/sendmail"
#define DEFAULT_POSTMASTER "postmaster"

#define SENDMAIL (config_getstring("sendmail", DEFAULT_SENDMAIL))
#define POSTMASTER (config_getstring("postmaster", DEFAULT_POSTMASTER))

static char *month[] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun",
                         "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

static char *wday[] = { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };

static int global_outgoing_count = 0;

int open_sendmail(char *argv[], FILE **sm)
{
    int fds[2];
    FILE *ret;
    pid_t p;

    pipe(fds);
    if ((p = fork()) == 0) {
	/* i'm the child! run sendmail! */
	close(fds[1]);
	/* make the pipe be stdin */
	dup2(fds[0], 0);
	execv(SENDMAIL, argv);

	/* if we're here we suck */
	printf("451 deliver: didn't exec?!?\r\n");
	fatal("couldn't exec", EC_TEMPFAIL);
    }
    /* i'm the parent */
    close(fds[0]);
    ret = fdopen(fds[1], "w");
    *sm = ret;

    return p;
}

/* sendmail_errstr.  create a descriptive message given 'sm_stat': 
   the exit code from wait() from sendmail.

   not thread safe, but probably ok */
static char *sendmail_errstr(int sm_stat)
{
    static char errstr[200];

    if (WIFEXITED(sm_stat)) {
	snprintf(errstr, sizeof errstr,
		 "Sendmail process terminated normally, exit status %d\n",
		 WEXITSTATUS(sm_stat));
    } else if (WIFSIGNALED(sm_stat)) {
	snprintf(errstr, sizeof errstr,
		 "Sendmail process terminated abnormally, signal = %d %s\n",
		 WTERMSIG(sm_stat), 
		 WCOREDUMP(sm_stat) ? " -- core file generated" : "");
    } else if (WIFSTOPPED(sm_stat)) {
	snprintf(errstr, sizeof errstr,
		 "Sendmail process stopped, signal = %d\n",
		 WTERMSIG(sm_stat));
    } else {
	return NULL;
    }

    return errstr;
}

int send_rejection(char *origid,
		   char *rejto,
		   char *origreceip, 
		   char *mailreceip, 
		   char *reason, 
		   struct protstream *file)
{
    FILE *sm;
    char *smbuf[6];
    char hostname[1024], buf[8192], *namebuf;
    int i, sm_stat;
    struct tm *tm;
    int tz;
    time_t t;
    pid_t sm_pid, p;

    smbuf[0] = "sendmail";
    smbuf[1] = "-f";
    smbuf[2] = "<>";
    smbuf[3] = "--";
    smbuf[4] = rejto;
    smbuf[5] = NULL;
    sm_pid = open_sendmail(smbuf, &sm);
    if (sm == NULL) {
	return -1;
    }

    gethostname(hostname, 1024);
    t = time(NULL);
    p = getpid();
    snprintf(buf, sizeof(buf), "<cmu-sieve-%d-%d-%d@%s>", p, t, 
	     global_outgoing_count++, hostname);
    
    namebuf = make_sieve_db(mailreceip);
    markdelivered(buf, strlen(buf), namebuf, strlen(namebuf), t);
    fprintf(sm, "Message-ID: %s\r\n", buf);

    tm = localtime(&t);
#ifdef HAVE_TM_ZONE
    tz = tm->tm_gmtoff / 60;
#else
    tz = timezone / 60;
#endif
    fprintf(sm, "Date: %s, %02d %s %4d %02d:%02d:%02d %c%02d%02d\r\n",
	    wday[tm->tm_wday], 
	    tm->tm_mday, month[tm->tm_mon], tm->tm_year + 1900,
	    tm->tm_hour, tm->tm_min, tm->tm_sec,
            tz > 0 ? '-' : '+', tz / 60, tz % 60);

    fprintf(sm, "X-Sieve: %s\r\n", sieve_version);
    fprintf(sm, "From: Mail Sieve Subsystem <%s>\r\n", POSTMASTER);
    fprintf(sm, "To: <%s>\r\n", rejto);
    fprintf(sm, "MIME-Version: 1.0\r\n");
    fprintf(sm, "Content-Type: "
	    "multipart/report; report-type=disposition-notification;"
	    "\r\n\tboundary=\"%d/%s\"\r\n", p, hostname);
    fprintf(sm, "Subject: Automatically rejected mail\r\n");
    fprintf(sm, "Auto-Submitted: auto-replied (rejected)\r\n");
    fprintf(sm, "\r\nThis is a MIME-encapsulated message\r\n\r\n");

    /* this is the human readable status report */
    fprintf(sm, "--%d/%s\r\n\r\n", p, hostname);
    fprintf(sm, "Your message was automatically rejected by Sieve, a mail\r\n"
	    "filtering language.\r\n\r\n");
    fprintf(sm, "The following reason was given:\r\n%s\r\n\r\n", reason);

    /* this is the MDN status report */
    fprintf(sm, "--%d/%s\r\n"
	    "Content-Type: message/disposition-notification\r\n\r\n",
	    p, hostname);
    fprintf(sm, "Reporting-UA: %s; Cyrus %s/%s\r\n",
	    hostname, CYRUS_VERSION, sieve_version);
    if (origreceip)
	fprintf(sm, "Original-Recipient: rfc822; %s\r\n", origreceip);
    fprintf(sm, "Final-Recipient: rfc822; %s\r\n", mailreceip);
    fprintf(sm, "Original-Message-ID: %s\r\n", origid);
    fprintf(sm, "Disposition: "
	    "automatic-action/MDN-sent-automatically; deleted\r\n");
    fprintf(sm, "\r\n");

    /* this is the original message */
    fprintf(sm, "--%d/%s\r\nContent-Type: message/rfc822\r\n\r\n",
	    p, hostname);
    prot_rewind(file);
    while ((i = prot_read(file, buf, sizeof(buf))) > 0) {
	fwrite(buf, i, 1, sm);
    }
    fprintf(sm, "\r\n\r\n");
    fprintf(sm, "--%d/%s--\r\n", p, hostname);

    fclose(sm);
    while (waitpid(sm_pid, &sm_stat, 0) < 0);

    return sm_stat;	/* sendmail exit value */
}

int send_forward(char *forwardto, char *return_path, struct protstream *file)
{
    FILE *sm;
    char *smbuf[6];
    int i, sm_stat;
    char buf[1024];
    pid_t sm_pid;

    smbuf[0] = "sendmail";
    if (return_path != NULL) {
	smbuf[1] = "-f";
	smbuf[2] = return_path;
    } else {
	smbuf[1] = "-f";
	smbuf[2] = "<>";
    }
    smbuf[3] = "--";
    smbuf[4] = forwardto;
    smbuf[5] = NULL;
    sm_pid = open_sendmail(smbuf, &sm);
	
    if (sm == NULL) {
	return -1;
    }

    prot_rewind(file);

    while ((i = prot_read(file, buf, sizeof(buf))) > 0) {
	fwrite(buf, i, 1, sm);
    }

    fclose(sm);
    while (waitpid(sm_pid, &sm_stat, 0) < 0);

    return sm_stat;	/* sendmail exit value */
}

static
int sieve_redirect(void *ac, void *ic, void *sc, void *mc, const char **errmsg)
{
    sieve_redirect_context_t *rc = (sieve_redirect_context_t *) ac;
    script_data_t *sd = (script_data_t *) sc;
    message_data_t *m = (message_data_t *) mc;
    int res;

    if ((res = send_forward(rc->addr, m->return_path, m->data)) == 0) {
	return SIEVE_OK;
    } else {
	if (res == -1)
	    *errmsg = "Could not spawn sendmail process";
	else
	    *errmsg = sendmail_errstr(res);
	return SIEVE_FAIL;
    }
}

static
int sieve_discard(void *ac, void *ic, void *sc, void *mc, const char **errmsg)
{
    script_data_t *sd = (script_data_t *) sc;
    message_data_t *m = (message_data_t *) mc;

    /* ok, we won't file it */
    return SIEVE_OK;
}

static
int sieve_reject(void *ac, void *ic, void *sc, void *mc, const char **errmsg)
{
    sieve_reject_context_t *rc = (sieve_reject_context_t *) ac;
    script_data_t *sd = (script_data_t *) sc;
    message_data_t *m = (message_data_t *) mc;
    char buf[8192];
    const char **body;
    char *origreceip;
    int res;

    if (m->return_path == NULL) {
	/* return message to who?!? */
	*errmsg = "No return-path for reply";
	return SIEVE_FAIL;
    }
    
    if (strcpy(buf, "original-recipient"),
	getheader((void *) m, buf, &body) == SIEVE_OK) {
	origreceip = xstrdup(body[0]);
    } else {
	origreceip = NULL;		/* no original-recipient */
    }

    if ((res = send_rejection(m->id, m->return_path, origreceip, sd->username,
			      rc->msg, m->data)) == 0) {
	return SIEVE_OK;
    } else {
	if (res == -1)
	    *errmsg = "Could not spawn sendmail process";
	else
	    *errmsg = sendmail_errstr(res);
	return SIEVE_FAIL;
    }
}

static
int sieve_fileinto(void *ac, void *ic, void *sc, void *mc, const char **errmsg)
{
    sieve_fileinto_context_t *fc = (sieve_fileinto_context_t *) ac;
    deliver_opts_t *dop = (deliver_opts_t *) ic;
    script_data_t *sd = (script_data_t *) sc;
    message_data_t *md = (message_data_t *) mc;
    int ret;

    /* we're now the user who owns the script */
    if (!sd->authstate)
	return SIEVE_FAIL;

    ret = deliver_mailbox(md->data, &md->stage, md->size,
			  fc->imapflags->flag, fc->imapflags->nflags,
			  sd->username, sd->authstate, md->id,
			  sd->username, md->notifyheader,
			  fc->mailbox, dop->quotaoverride, 0);

    if (ret == 0) {
	return SIEVE_OK;
    } else {
	*errmsg = error_message(ret);
	return SIEVE_FAIL;
    }
}

static
int sieve_keep(void *ac, void *ic, void *sc, void *mc, const char **errmsg)
{
    sieve_keep_context_t *kc = (sieve_keep_context_t *) ac;
    deliver_opts_t *dop = (deliver_opts_t *) ic;
    script_data_t *sd = (script_data_t *) sc;
    message_data_t *md = (message_data_t *) mc;
    char namebuf[MAX_MAILBOX_PATH];
    int ret = 1;

    if (sd->mailboxname) {
	strcpy(namebuf, "INBOX.");
	strcat(namebuf, sd->mailboxname);

	ret = deliver_mailbox(md->data, &md->stage, md->size,
			      kc->imapflags->flag, kc->imapflags->nflags,
			      dop->authuser, dop->authstate, md->id,
			      sd->username, md->notifyheader,
			      namebuf, dop->quotaoverride, 0);
    }
    if (ret) {
	/* we're now the user who owns the script */
	if (!sd->authstate)
	    return SIEVE_FAIL;

	ret = deliver_mailbox(md->data, &md->stage, md->size,
			      kc->imapflags->flag, kc->imapflags->nflags,
			      sd->username, sd->authstate, md->id,
			      sd->username, md->notifyheader,
			      "INBOX", dop->quotaoverride, 1);
    }

    if (ret == 0) {
	return SIEVE_OK;
    } else {
	*errmsg = error_message(ret);
	return SIEVE_FAIL;
    }
}

static int sieve_notify(void *ac,
  			void *interp_context, 
  			void *script_context,
  			void *mc,
			const char **errmsg)
{
    sieve_notify_context_t *nc = (sieve_notify_context_t *) ac;
    script_data_t *sd = (script_data_t *) script_context;

    notify("SIEVE",
 	   nc->priority,
  	   sd->username,
  	   NULL,
 	   nc->message);

    return SIEVE_OK;
}
   
int autorespond(void *ac, void *ic, void *sc, void *mc, const char **errmsg)
{
    sieve_autorespond_context_t *arc = (sieve_autorespond_context_t *) ac;
    script_data_t *sd = (script_data_t *) sc;
    time_t t, now;
    int ret;

    now = time(NULL);

    /* ok, let's see if we've responded before */
    if (t = checkdelivered(arc->hash, arc->len, sd->username, strlen(sd->username))) {
	if (now >= t) {
	    /* yay, we can respond again! */
	    ret = SIEVE_OK;
	} else {
	    ret = SIEVE_DONE;
	}
    } else {
	/* never responded before */
	ret = SIEVE_OK;
    }

    if (ret == SIEVE_OK) {
	markdelivered((char *) arc->hash, arc->len, 
		      sd->username, strlen(sd->username), 
		      now + arc->days * (24 * 60 * 60));
    }

    return ret;
}

int send_response(void *ac, void *ic, void *sc, void *mc, const char **errmsg)
{
    FILE *sm;
    char *smbuf[6];
    char hostname[1024], outmsgid[8192], *sievedb;
    int i, sl, sm_stat;
    struct tm *tm;
    int tz;
    time_t t;
    pid_t sm_pid, p;
    sieve_send_response_context_t *src = (sieve_send_response_context_t *) ac;
    message_data_t *m = (message_data_t *) mc;
    script_data_t *sdata = (script_data_t *) sc;

    smbuf[0] = "sendmail";
    smbuf[1] = "-f";
    smbuf[2] = "<>";
    smbuf[3] = "--";
    smbuf[4] = src->addr;
    smbuf[5] = NULL;
    sm_pid = open_sendmail(smbuf, &sm);
    if (sm == NULL) {
	*errmsg = "Could not spawn sendmail process";
	return -1;
    }

    gethostname(hostname, 1024);
    t = time(NULL);
    p = getpid();
    snprintf(outmsgid, sizeof(outmsgid), "<cmu-sieve-%d-%d-%d@%s>", p, t, 
	     global_outgoing_count++, hostname);
    
    fprintf(sm, "Message-ID: %s\r\n", outmsgid);

    tm = localtime(&t);
#ifdef HAVE_TM_ZONE
    tz = tm->tm_gmtoff / 60;
#else
    tz = timezone / 60;
#endif
    fprintf(sm, "Date: %s, %02d %s %4d %02d:%02d:%02d %c%02d%02d\r\n",
	    wday[tm->tm_wday], 
	    tm->tm_mday, month[tm->tm_mon], tm->tm_year + 1900,
	    tm->tm_hour, tm->tm_min, tm->tm_sec,
            tz > 0 ? '-' : '+', tz / 60, tz % 60);
    
    fprintf(sm, "X-Sieve: %s\r\n", sieve_version);
    fprintf(sm, "From: <%s>\r\n", src->fromaddr);
    fprintf(sm, "To: <%s>\r\n", src->addr);
    /* check that subject is sane */
    sl = strlen(src->subj);
    for (i = 0; i < sl; i++)
	if (iscntrl(src->subj[i])) {
	    src->subj[i] = '\0';
	    break;
	}
    fprintf(sm, "Subject: %s\r\n", src->subj);
    fprintf(sm, "In-Reply-To: %s\r\n", m->id);
    fprintf(sm, "Auto-Submitted: auto-replied (vacation)\r\n");
    if (src->mime) {
	fprintf(sm, "MIME-Version: 1.0\r\n");
	fprintf(sm, "Content-Type: multipart/mixed;"
		"\r\n\tboundary=\"%d/%s\"\r\n", p, hostname);
	fprintf(sm, "\r\nThis is a MIME-encapsulated message\r\n\r\n");
	fprintf(sm, "--%d/%s\r\n", p, hostname);
    } else {
	fprintf(sm, "\r\n");
    }

    fprintf(sm, "%s\r\n", src->msg);

    if (src->mime) {
	fprintf(sm, "\r\n--%d/%s--\r\n", p, hostname);
    }
    fclose(sm);
    while (waitpid(sm_pid, &sm_stat, 0) < 0);

    if (sm_stat == 0) { /* sendmail exit value */
	sievedb = make_sieve_db(sdata->username);

	markdelivered(outmsgid, strlen(outmsgid), sievedb, strlen(sievedb), t);
	return SIEVE_OK;
    } else {
	*errmsg = sendmail_errstr(sm_stat);
	return SIEVE_FAIL;
    }
}

/* vacation support */
sieve_vacation_t vacation = {
    1,				/* min response */
    31,				/* max response */
    &autorespond,		/* autorespond() */
    &send_response,		/* send_response() */
};

/* imapflags support */
static char *markflags[] = { "\\flagged" };
static sieve_imapflags_t mark = { markflags, 1 };

int mysieve_parse_error(int lineno, char *msg, void *ic, void *sc)
{
    script_data_t *sd = (script_data_t *) sc;

    syslog(LOG_INFO, "sieve parse error for %s: line %d: %s",
	   sd->username, lineno, msg);

    return SIEVE_OK;
}
int mysieve_execute_error(char *msg, void *ic, void *sc, void *mc)
{
    script_data_t *sd = (script_data_t *) sc;
    message_data_t *md = (message_data_t *) mc;

    syslog(LOG_INFO, "sieve runtime error for %s id %s: %s",
	   sd->username, md->id ? md->id : "(null)", msg);

    return SIEVE_OK;
}

static void
setup_sieve(deliver_opts_t *delopts, int lmtpmode)
{
    int res;

    res = sieve_interp_alloc(&sieve_interp, (void *) delopts);
    if (res != SIEVE_OK) {
	syslog(LOG_ERR, "sieve_interp_alloc() returns %d\n", res);
	fatal("sieve_interp_alloc()", EC_TEMPFAIL);
    }

    res = sieve_register_redirect(sieve_interp, &sieve_redirect);
    if (res != SIEVE_OK) {
	syslog(LOG_ERR, "sieve_register_redirect() returns %d\n", res);
	fatal("sieve_register_redirect()", EC_TEMPFAIL);
    }
    res = sieve_register_discard(sieve_interp, &sieve_discard);
    if (res != SIEVE_OK) {
	syslog(LOG_ERR, "sieve_register_discard() returns %d\n", res);
	fatal("sieve_register_discard()", EC_TEMPFAIL);
    }
    res = sieve_register_reject(sieve_interp, &sieve_reject);
    if (res != SIEVE_OK) {
	syslog(LOG_ERR, "sieve_register_reject() returns %d\n", res);
	fatal("sieve_register_reject()", EC_TEMPFAIL);
    }
    res = sieve_register_fileinto(sieve_interp, &sieve_fileinto);
    if (res != SIEVE_OK) {
	syslog(LOG_ERR, "sieve_register_fileinto() returns %d\n", res);
	fatal("sieve_register_fileinto()", EC_TEMPFAIL);
    }
    res = sieve_register_keep(sieve_interp, &sieve_keep);
    if (res != SIEVE_OK) {
	syslog(LOG_ERR, "sieve_register_keep() returns %d\n", res);
	fatal("sieve_register_keep()", EC_TEMPFAIL);
    }
    res = sieve_register_imapflags(sieve_interp, &mark);
    if (res != SIEVE_OK) {
	syslog(LOG_ERR, "sieve_register_imapflags() returns %d\n", res);
	fatal("sieve_register_imapflags()", EC_TEMPFAIL);
    }
    res = sieve_register_notify(sieve_interp, &sieve_notify);
    if (res != SIEVE_OK) {
	syslog(LOG_ERR, "sieve_register_notify() returns %d\n", res);
	fatal("sieve_register_notify()", EC_TEMPFAIL);
    }
    res = sieve_register_size(sieve_interp, &getsize);
    if (res != SIEVE_OK) {
	syslog(LOG_ERR, "sieve_register_size() returns %d\n", res);
	fatal("sieve_register_size()", EC_TEMPFAIL);
    }
    res = sieve_register_header(sieve_interp, &getheader);
    if (res != SIEVE_OK) {
	syslog(LOG_ERR, "sieve_register_header() returns %d\n", res);
	fatal("sieve_register_header()", EC_TEMPFAIL);
    }

    if (lmtpmode) {
	res = sieve_register_envelope(sieve_interp, &getenvelope);
	if (res != SIEVE_OK) {
	    syslog(LOG_ERR,"sieve_register_envelope() returns %d\n", res);
	    fatal("sieve_register_envelope()", EC_TEMPFAIL);
	}

	res = sieve_register_vacation(sieve_interp, &vacation);
	if (res != SIEVE_OK) {
	    syslog(LOG_ERR, "sieve_register_vacation() returns %d\n", res);
	    fatal("sieve_register_vacation()", EC_TEMPFAIL);
	}
    }

    res = sieve_register_parse_error(sieve_interp, &mysieve_parse_error);
    if (res != SIEVE_OK) {
	syslog(LOG_ERR, "sieve_register_parse_error() returns %d\n", res);
	fatal("sieve_register_parse_error()", EC_TEMPFAIL);
    }

    res = sieve_register_execute_error(sieve_interp, &mysieve_execute_error);
    if (res != SIEVE_OK) {
	syslog(LOG_ERR, "sieve_register_execute_error() returns %d\n", res);
	fatal("sieve_register_execute_error()", EC_TEMPFAIL);
    }
}

#endif

static void
usage()
{
    fprintf(stderr, 
"421-4.3.0 usage: deliver [-m mailbox] [-a auth] [-i] [-F flag]... [user]...\r\n");
    fprintf(stderr, "421 4.3.0        deliver -E age\n");
    fprintf(stderr, "421 4.3.0 %s\n", CYRUS_VERSION);
    exit(EC_USAGE);
}

char *parseaddr(s)
char *s;
{
    char *p;
    int len;

    p = s;

    if (*p++ != '<') return 0;

    /* at-domain-list */
    while (*p == '@') {
	p++;
	if (*p == '[') {
	    p++;
	    while (isdigit(*p) || *p == '.') p++;
	    if (*p++ != ']') return 0;
	}
	else {
	    while (isalnum(*p) || *p == '.' || *p == '-') p++;
	}
	if (*p == ',' && p[1] == '@') p++;
	else if (*p == ':' && p[1] != '@') p++;
	else return 0;
    }
    
    /* local-part */
    if (*p == '\"') {
	p++;
	while (*p && *p != '\"') {
	    if (*p == '\\') {
		if (!*++p) return 0;
	    }
	    p++;
	}
	if (!*p++) return 0;
    }
    else {
	while (*p && *p != '@' && *p != '>') {
	    if (*p == '\\') {
		if (!*++p) return 0;
	    }
	    else {
		if (*p <= ' ' || (*p & 128) ||
		    strchr("<>()[]\\,;:\"", *p)) return 0;
	    }
	    p++;
	}
    }

    /* @domain */
    if (*p == '@') {
	p++;
	if (*p == '[') {
	    p++;
	    while (isdigit(*p) || *p == '.') p++;
	    if (*p++ != ']') return 0;
	}
	else {
	    while (isalnum(*p) || *p == '.' || *p == '-') p++;
	}
    }
    
    if (*p++ != '>') return 0;
    if (*p && *p != ' ') return 0;
    len = p - s;

    s = xstrdup(s);
    s[len] = '\0';
    return s;
}

char *process_recipient(addr, ad)
char *addr;
address_data_t **ad;
{
    char *dest = addr;
    char *user = addr;
    char *plus, *dot;
    char buf[1024];
    int r, sl;
    address_data_t *ret = (address_data_t *) malloc(sizeof(address_data_t));

    if (ret == NULL) {
	fatal("out of memory", EC_TEMPFAIL);
    }

    if (*addr == '<') addr++;

    ret->all = xstrdup(addr);
    sl = strlen(ret->all);
    if (ret->all[sl-1] == '>')
	ret->all[sl-1] = '\0';
    
    /* Skip at-domain-list */
    if (*addr == '@') {
	addr = strchr(addr, ':');
	if (!addr) return "501 5.5.4 Syntax error in parameters";
	addr++;
    }
    
    if (*addr == '\"') {
	addr++;
	while (*addr && *addr != '\"') {
	    if (*addr == '\\') addr++;
	    *dest++ = *addr++;
	}
    }
    else {
	while (*addr != '@' && *addr != '>') {
	    if (*addr == '\\') addr++;
	    *dest++ = *addr++;
	}
    }
    *dest = 0;
	
    dot = strchr(user, '.');
    plus = strchr (user, '+');
    if (plus && (!dot || plus < dot)) dot = plus;

    if (dot) *dot = '\0';
    if (*user) {
	if (strlen(user) > sizeof(buf)-10) {
	    return convert_lmtp(IMAP_MAILBOX_NONEXISTENT);
	}
	strcpy(buf, "user.");
	strcat(buf, user);
	r = mboxlist_lookup(buf, (char **)0, (char **)0);
    }
    else {
	r = mboxlist_lookup(user+1, (char **)0, (char **)0);
    }
    if (r) {
	return convert_lmtp(r);
    }
    if (dot) *dot++ = '\0';
    ret->mailbox = user;
    ret->detail = dot;

    *ad = ret;

    return 0;
}    

/* returns non-zero on failure */
int msg_new(message_data_t **m)
{
    message_data_t *ret = (message_data_t *)malloc(sizeof(message_data_t));
    int i;

    if (!ret) {
	return -1;
    }
    ret->data = NULL;
    ret->stage = NULL;
    ret->f = NULL;
    ret->notifyheader = ret->id = NULL;
    ret->size = 0;
    ret->return_path = NULL;
    ret->rcpt = NULL;
    ret->rcpt_num = 0;

#ifdef USE_SIEVE
    for (i = 0; i < HEADERCACHESIZE; i++)
	ret->cache[i] = NULL;
#endif

    *m = ret;
    return 0;
}

void msg_free(message_data_t *m)
{
    int i;

    if (m->data) {
	prot_free(m->data);
    }
    if (m->f) {
	fclose(m->f);
    }
    if (m->stage) {
	append_removestage(m->stage);
    }
    if (m->notifyheader) {
	free(m->notifyheader);
    }
    if (m->id) {
	free(m->id);
    }

    if (m->return_path) {
	free(m->return_path);
    }
    if (m->rcpt) {
	for (i = 0; i < m->rcpt_num; i++) {
	    if (m->rcpt[i]->all) free(m->rcpt[i]->all);
	    if (m->rcpt[i]->mailbox) free(m->rcpt[i]->mailbox);
	    free(m->rcpt[i]);
	}
	free(m->rcpt);
    }

#ifdef USE_SIEVE
    for (i = 0; i < HEADERCACHESIZE; i++)
	if (m->cache[i]) {
	    int j;

	    free(m->cache[i]->name);
	    for (j = 0; j < m->cache[i]->ncontents; j++) {
		free(m->cache[i]->contents[j]);
	    }

	    free(m->cache[i]);
	}
#endif

    free(m);
}

#define RCPT_GROW 5 /* XXX 30 */

lmtpmode(delopts)
deliver_opts_t *delopts;
{
    message_data_t *msg;
    char buf[4096];
    char *p;
    char *authuser = 0;
    char myhostname[1024];
    int r;
    char *err;
    int i;
    unsigned int mechcount = 0;
    int salen;
    struct stat sbuf;

    sasl_conn_t *conn;
    sasl_security_properties_t *secprops = NULL;
    sasl_external_properties_t *extprops = NULL;

    delopts->authuser = 0;
    delopts->authstate = 0;

    signal(SIGPIPE, SIG_IGN);

    gethostname(myhostname, sizeof(myhostname)-1);
    r = msg_new(&msg);
    if (r) {
	/* damn */
	fatal("out of memory", EC_TEMPFAIL);
    }

    if (sasl_server_init(mysasl_cb, "Cyrus") != SASL_OK) {
	fatal("SASL failed initializing: sasl_server_init()", EC_TEMPFAIL);
    }

    if (sasl_server_new("lmtp", NULL, NULL, NULL, 0, &conn) != SASL_OK) {
	fatal("SASL failed initializing: sasl_server_new()", EC_TEMPFAIL);
    }

    secprops = make_secprops(0, 10000);
    sasl_setprop(conn, SASL_SEC_PROPS, secprops);

    fstat(0, &sbuf);


    salen = sizeof(deliver_remoteaddr);
    r = getpeername(0, (struct sockaddr *)&deliver_remoteaddr, &salen);
    switch (r) {
    case 0:
	salen = sizeof(deliver_localaddr);
	if (getsockname(0, (struct sockaddr *)&deliver_localaddr, &salen) 
	    == 0) {
	    /* set the ip addresses here */
	    sasl_setprop(conn, SASL_IP_REMOTE, &deliver_remoteaddr);  
	    sasl_setprop(conn, SASL_IP_LOCAL,  &deliver_localaddr );
	    
	    syslog(LOG_DEBUG, "connection from [%s]", 
		   inet_ntoa(deliver_remoteaddr.sin_addr));
	} else {
	    syslog(LOG_ERR, "can't get local addr\n");
	}

	break;

    default:
	/* we're not connected to a internet socket! */
	extprops = (sasl_external_properties_t *) 
	    xmalloc(sizeof(sasl_external_properties_t));
	extprops->ssf = 2;
	extprops->auth_id = "postman";
	sasl_setprop(conn, SASL_SSF_EXTERNAL, extprops);

	syslog(LOG_DEBUG, "lmtp connection preauth'd as postman");

	break;
    }

    prot_printf(deliver_out,"220 %s LMTP ready\r\n", myhostname);

    for (;;) {
      if (!prot_fgets(buf, sizeof(buf)-1, deliver_in)) {
	  msg_free(msg);
	  exit(0);
      }
      p = buf + strlen(buf) - 1;
      if (p >= buf && *p == '\n') *p-- = '\0';
      if (p >= buf && *p == '\r') *p-- = '\0';

      switch (buf[0]) {
      case 'a':
      case 'A':
	    if (!strncasecmp(buf, "auth ", 5)) {
		char *mech;
		char *data;
		char *in, *out;
		unsigned int inlen, outlen;
		const char *errstr;
		
		if (delopts->authuser) {
		    prot_printf(deliver_out,"503 5.5.0 already authenticated\r\n");
		    continue;
		}
		if (msg->rcpt_num != 0) {
		    prot_printf(deliver_out,"503 5.5.0 AUTH not permitted now\r\n");
		    continue;
		}

		/* ok, what mechanism ? */
		mech = buf + 5;
		p=mech;
		while ((*p != ' ') && (*p != '\0')) {
		    p++;
		}
		if (*p == ' ') {
		  *p = '\0';
		  p++;
		} else {
		  p = NULL;
		}

		if (p != NULL) {
		    in = xmalloc(strlen(p));
		    r = sasl_decode64(p, strlen(p), in, &inlen);
		    if (r != SASL_OK) {
			prot_printf(deliver_out,
				    "501 5.5.4 cannot base64 decode\r\n");
			if (in) { free(in); }
			continue;
		    }
		} else {
		    in = NULL;
		    inlen = 0;
		}

		r = sasl_server_start(conn,
				      mech,
				      in,
				      inlen,
				      &out,
				      &outlen,
				      &errstr);
		
		if (in) { free(in); }

		while (r == SASL_CONTINUE) {
		    char inbase64[4096];

		    r = sasl_encode64(out, outlen, 
				      inbase64, sizeof(inbase64), NULL);
		    
		    if (r != SASL_OK) {
			 break;
		     }

		     /* send out */
		     prot_printf(deliver_out,"334 %s\r\n", inbase64);

		     /* read a line */
		     if (!prot_fgets(buf, sizeof(buf)-1, deliver_in)) {
			 msg_free(msg);
			 exit(0);
		     }
		     p = buf + strlen(buf) - 1;
		     if (p >= buf && *p == '\n') *p-- = '\0';
		     if (p >= buf && *p == '\r') *p-- = '\0';

		     in = xmalloc(strlen(buf));
		     r = sasl_decode64(buf, strlen(buf), in, &inlen);
		     if (r != SASL_OK) {
			 prot_printf(deliver_out,
				     "501 5.5.4 cannot base64 decode\r\n");
			 if (in) { free(in); }
			 continue; /* xxx */
		     }

		     r = sasl_server_step(conn,
					  in,
					  inlen,
					  &out,
					  &outlen,
					  &errstr);

		 }

		 if ((r != SASL_OK) && (r != SASL_CONTINUE)) {
		     prot_printf(deliver_out, "501 5.5.4 %s\n",
				 sasl_errstring(r, NULL, NULL));
		     continue;
		 }

		 /* authenticated successfully! */
		 prot_printf(deliver_out, "250 Authenticated!\r\n");

		 /* set protection layers */
		 prot_setsasl(deliver_in,  conn);
		 prot_setsasl(deliver_out, conn);
		 continue;
	    }
	    goto syntaxerr;

	case 'd':
	case 'D':
	    if (!strcasecmp(buf, "data")) {
		if (!msg->rcpt_num) {
		    prot_printf(deliver_out,"503 5.5.1 No recipients\r\n");
		    continue;
		}
		savemsg(msg, msg->rcpt_num);
		if (!msg->data) continue;

		i = msg->rcpt_num;
		for (msg->rcpt_num = 0; msg->rcpt_num < i; msg->rcpt_num++) {
		    int cur = msg->rcpt_num;

		    r = deliver(delopts, msg, 0, 0,
				msg->rcpt[cur]->mailbox[0] ? 
				msg->rcpt[cur]->mailbox : (char *)0, 
				msg->rcpt[cur]->detail);

		    prot_printf(deliver_out,"%s\r\n", convert_lmtp(r));
		}
		goto rset;
	    }
	    goto syntaxerr;

	case 'l':
	case 'L':
	    if (!strncasecmp(buf, "lhlo ", 5)) {
		char *mechs;

		prot_printf(deliver_out,"250-%s\r\n250-8BITMIME\r\n"
			    "250-ENHANCEDSTATUSCODES\r\n",
			    myhostname);
		if (sasl_listmech(conn, NULL, "AUTH ", " ", "", &mechs, 
				  NULL, &mechcount) == SASL_OK && 
		    mechcount > 0) {
		  prot_printf(deliver_out,"250-%s\r\n", mechs);
		  free(mechs);
		}
		prot_printf(deliver_out, "250 PIPELINING\r\n");

		continue;
	    }
	    goto syntaxerr;

	case 'm':
	case 'M':
	    if (!strncasecmp(buf, "mail ", 5)) {
		if (msg->return_path) {
		    prot_printf(deliver_out, "503 5.5.1 Nested MAIL command\r\n");
		    continue;
		}
		if (strncasecmp(buf+5, "from:", 5) != 0 ||
		    !(msg->return_path = parseaddr(buf+10))) {
		    prot_printf(deliver_out, "501 5.5.4 Syntax error in parameters\r\n");
		    continue;
		}
		prot_printf(deliver_out, "250 2.1.0 ok\r\n");
		continue;
	    }
	    goto syntaxerr;

	case 'n':
	case 'N':
	    if (!strcasecmp(buf, "noop")) {
		prot_printf(deliver_out,"250 2.0.0 ok\r\n");
		continue;
	    }
	    goto syntaxerr;

	case 'q':
	case 'Q':
	    if (!strcasecmp(buf, "quit")) {
		prot_printf(deliver_out,"221 2.0.0 bye\r\n");
		prot_flush(deliver_out);
		msg_free(msg);
		exit(0);
	    }
	    goto syntaxerr;
	    
	case 'r':
	case 'R':
	    if (!strncasecmp(buf, "rcpt ", 5)) {
		char *rcpt;

		if (!msg->return_path) {
		    prot_printf(deliver_out, "503 5.5.1 Need MAIL command\r\n");
		    continue;
		}
		if (!(msg->rcpt_num % RCPT_GROW)) { /* time to alloc more */
		    msg->rcpt = (address_data_t **)
			xrealloc(msg->rcpt, (msg->rcpt_num + RCPT_GROW + 1) * 
				 sizeof(address_data_t *));
		}
		if (strncasecmp(buf+5, "to:", 3) != 0 ||
		    !(rcpt = parseaddr(buf+8))) {
		    prot_printf(deliver_out, "501 5.5.4 Syntax error in parameters\r\n");
		    continue;
		}
		if (err = process_recipient(rcpt, 
					    &msg->rcpt[msg->rcpt_num])) {
		    prot_printf(deliver_out, "%s\r\n", err);
		    continue;
		}
		msg->rcpt_num++;
		msg->rcpt[msg->rcpt_num] = NULL;
		prot_printf(deliver_out, "250 2.1.5 ok\r\n");
		continue;
	    }
	    else if (!strcasecmp(buf, "rset")) {
		prot_printf(deliver_out, "250 2.0.0 ok\r\n");

	      rset:
		msg_free(msg);
		if (msg_new(&msg)) {
		    fatal("out of memory", EC_TEMPFAIL);
		}
		continue;
	    }
	    goto syntaxerr;
	    
	case 'v':
	case 'V':
	    if (!strncasecmp(buf, "vrfy ", 5)) {
		prot_printf(deliver_out, "252 2.3.3 try RCPT to attempt delivery\r\n");
		continue;
	    }
	    goto syntaxerr;

	default:
	syntaxerr:
	    prot_printf(deliver_out, "500 5.5.2 Syntax error\r\n");
	    continue;
	}
    }
}

void clean_retpath(char *rpath)
{
    char buf[8192];
    int i, sl;

    /* Remove any angle brackets around return path */
    if (*rpath == '<') {
	sl = strlen(rpath);
	for (i = 0; i < sl; i++) {
	    rpath[i] = rpath[i+1];
	}
	sl--; /* string is one shorter now */
	if (rpath[sl-1] == '>') {
	    rpath[sl-1] = '\0';
	}
    }
}

void
savemsg(message_data_t *m, int lmtpmode)
{
    FILE *f;
    char *hostname = 0;
#ifndef USE_SIEVE
    int scanheader = 1;
    int sawidhdr = 0, sawresentidhdr = 0;
    int sawnotifyheader = 0;
    int sawretpathhdr = 0;
#endif
    char buf[8192], *p;
    int retpathclean = 0;
    struct stat sbuf;
    const char **body, **frombody, **subjbody, **tobody;
    int sl, i;

    /* Copy to temp file */
    f = tmpfile();
    if (!f) {
	if (lmtpmode) {
	    prot_printf(deliver_out,
			"451 4.3.%c cannot create temporary file: %s\r\n",
		   (
#ifdef EDQUOT
		    errno == EDQUOT ||
#endif
		    errno == ENOSPC) ? '1' : '2',
		   error_message(errno));
	    return;
	}
	exit(EC_TEMPFAIL);
    }

    if (lmtpmode) {
	prot_printf(deliver_out,"354 go ahead\r\n");
    }

    if (m->return_path) { /* add the return path */
	char *rpath = m->return_path;

	clean_retpath(rpath);
	retpathclean = 1;

	/* Append our hostname if there's no domain in address */
	if (!strchr(rpath, '@')) {
	    gethostname(buf, sizeof(buf)-1);
	    hostname = buf;
	}

	fprintf(f, "Return-Path: <%s%s%s>\r\n",
		rpath, hostname ? "@" : "", hostname ? hostname : "");
    }

#ifdef USE_SIEVE
    /* add the Sieve header */
    fprintf(f, "X-Sieve: %s\r\n", sieve_version);

    /* fill the cache */
    fill_cache(deliver_in, f, lmtpmode, m);

    /* now, using our header cache, fill in the data that we want */

    /* first check resent-message-id */
    if (strcpy(buf, "resent-message-id"),
	getheader((void *) m, buf, &body) == SIEVE_OK) {
	m->id = xstrdup(body[0]);
    } else if (strcpy(buf, "message-id"), 
	       getheader((void *) m, buf, &body) == SIEVE_OK) {
	m->id = xstrdup(body[0]);
    } else {
	m->id = NULL;		/* no message-id */
    }

    /* figure out notifyheader */
    strcpy(buf, "from"), getheader((void *) m, buf, &frombody);
    strcpy(buf, "subject"), getheader((void *) m, buf, &subjbody);
    strcpy(buf, "to"), getheader((void *) m, buf, &tobody);

    sl = 0;
    if (frombody) for (i = 0; frombody[i] != NULL; i++) {
	sl += strlen(frombody[i]) + 10;
    }
    if (subjbody) for (i = 0; subjbody[i] != NULL; i++) {
	sl += strlen(subjbody[i]) + 13;
    }
    if (tobody) for (i = 0; tobody[i] != NULL; i++) {
	sl += strlen(tobody[i]) + 8;
    }
    m->notifyheader = (char *) malloc(sizeof(char) * (sl + 50));
    m->notifyheader[0] = '\0';
    if (frombody) for (i = 0; frombody[i] != NULL; i++) {
	strcat(m->notifyheader, "From: ");
	strcat(m->notifyheader, frombody[i]);
	strcat(m->notifyheader, "\n");
    }
    if (subjbody) for (i = 0; subjbody[i] != NULL; i++) {
	strcat(m->notifyheader, "Subject: ");
	strcat(m->notifyheader, subjbody[i]);
	strcat(m->notifyheader, "\n");
    }
    if (tobody) for (i = 0; tobody[i] != NULL; i++) {
	strcat(m->notifyheader, "To: ");
	strcat(m->notifyheader, tobody[i]);
	strcat(m->notifyheader, "\n");
    }

    if (!m->return_path &&
	(strcpy(buf, "return-path"),
	 getheader((void *) m, buf, &body) == SIEVE_OK)) {
	/* let's grab return_path */
	m->return_path = xstrdup(body[0]);
	clean822space(m->return_path);
	clean_retpath(m->return_path);
    }

#else
    while (prot_fgets(buf, sizeof(buf)-1, deliver_in)) {
	p = buf + strlen(buf) - 1;
	if (*p == '\n') {
	    if (p == buf || p[-1] != '\r') {
		p[0] = '\r';
		p[1] = '\n';
		p[2] = '\0';
	    }
	}
	else if (*p == '\r') {
	    if (buf[0] == '\r' && buf[1] == '\0') {
		/* The message contained \r\0, and fgets is confusing us.
		   XXX ignored
		 */
	    } else {
		/*
		 * We were unlucky enough to get a CR just before we ran
		 * out of buffer--put it back.
		 */
		prot_ungetc('\r', deliver_in);
		*p = '\0';
	    }
	}
	/* Remove any lone CR characters */
	while ((p = strchr(buf, '\r')) && p[1] != '\n') {
	    strcpy(p, p+1);
	}

	if (lmtpmode && buf[0] == '.') {
	    if (buf[1] == '\r' && buf[2] == '\n') {
		/* End of message */
		goto lmtpdot;
	    }
	    /* Remove the dot-stuffing */
	    fputs(buf+1, f);
	}
	else {
	    fputs(buf, f);
	}

	/* Look for message-id or resent-message-id headers */
	if (scanheader) {
	    p = 0;
	    if (*buf == '\r') scanheader = 0;
	    if (sawnotifyheader) {
		if (*buf == ' ' || *buf == '\t') {
		    m->notifyheader =
			xrealloc(m->notifyheader,
				 strlen(m->notifyheader) + strlen(buf) + 1);
		    strcat(m->notifyheader, buf);
		}
		else sawnotifyheader = 0;
	    }
	    if (sawretpathhdr) {
		if (*buf == ' ' || *buf == '\t') {
		    m->return_path =
			xrealloc(m->return_path,
				 strlen(m->return_path) + strlen(buf) + 1);
		    strcat(m->return_path, buf);
		}
		else sawretpathhdr = 0;
	    }
	    if (sawidhdr || sawresentidhdr) {
		if (*buf == ' ' || *buf == '\t') p = buf+1;
		else sawidhdr = sawresentidhdr = 0;
	    }

	    if (!m->id && !strncasecmp(buf, "message-id:", 11)) {
		sawidhdr = 1;
		p = buf + 11;
	    }
	    else if (!strncasecmp(buf, "resent-message-id:", 18)) {
		sawresentidhdr = 1;
		p = buf + 18;
	    }
	    else if (!strncasecmp(buf, "from:", 5) ||
		      !strncasecmp(buf, "subject:", 8) ||
		      !strncasecmp(buf, "to:", 3)) {
		if (!m->notifyheader) m->notifyheader = xstrdup(buf);
		else {
		    m->notifyheader =
			xrealloc(m->notifyheader,
				 strlen(m->notifyheader) + strlen(buf) + 1);
		    strcat(m->notifyheader, buf);
		}
		sawnotifyheader = 1;
	    }
	    else if (!m->return_path && 
		     !strncasecmp(buf, "return-path:", 12)) {
		sawretpathhdr = 1;
		m->return_path = xstrdup(buf + 12);
	    }

	    if (p) {
		clean822space(p);
		if (*p) {
		    m->id = xstrdup(p);
		    /*
		     * If we got a resent-message-id header,
		     * we're done looking for *message-id headers.
		     */
		    if (sawresentidhdr) m->id = 0;
		    sawresentidhdr = sawidhdr = 0;
		}
	    }
	}

    }

    if (m->return_path && !retpathclean) {
	clean822space(m->return_path);
	clean_retpath(m->return_path);
    }

    if (lmtpmode) {
	/* Got a premature EOF -- toss message and exit */
	exit(0);
    }

  lmtpdot:

#endif /* USE_SIEVE */

    fflush(f);
    if (ferror(f)) {
	if (!lmtpmode) {
	    perror("deliver: copying message");
	    exit(EC_TEMPFAIL);
	}
	while (lmtpmode--) {
	    prot_printf(deliver_out,
	       "451 4.3.%c cannot copy message to temporary file: %s\r\n",
		   (
#ifdef EDQUOT
		    errno == EDQUOT ||
#endif
		    errno == ENOSPC) ? '1' : '2',
		   error_message(errno));
	}
	fclose(f);
	return;
    }

    if (fstat(fileno(f), &sbuf) == -1) {
	if (!lmtpmode) {
	    perror("deliver: stating message");
	    exit(EC_TEMPFAIL);
	}
	while (lmtpmode--) {
	    prot_printf(deliver_out,
			"451 4.3.2 cannot stat message temporary file: %s\r\n",
			error_message(errno));
	}
	fclose(f);
	return;
    }
    m->size = sbuf.st_size;
    m->f = f;
    m->data = prot_new(fileno(f), 0);
}


/*"*/
/* places msg in mailbox mailboxname.  
 * if you wish to use single instance store, pass stage as non-NULL
 * if you want to deliver message regardless of duplicates, pass id as NULL
 * if you want to notify, pass user
 * if you want to force delivery (to force delivery to INBOX, for instance)
 * pass acloverride
 */
deliver_mailbox(struct protstream *msg,
		struct stagemsg **stage,
		unsigned size,
		char **flag,
		int nflags,
		char *authuser,
		struct auth_state *authstate,
		char *id,
		char *user,
		char *notifyheader,
		char *mailboxname,
		int quotaoverride,
		int acloverride)
{
    int r;
    struct mailbox mailbox;
    char namebuf[MAX_MAILBOX_PATH];
    time_t now = time(NULL);

    if (user && !strncasecmp(mailboxname, "INBOX", 5)) {
	/* canonicalize mailbox */
	if (strchr(user, '.') ||
	    strlen(user) + 30 > MAX_MAILBOX_PATH) {
	    return IMAP_MAILBOX_NONEXISTENT;
	}
	strcpy(namebuf, "user.");
	strcat(namebuf, user);
	strcat(namebuf, mailboxname + 5);
    } else {
	strcpy(namebuf, mailboxname);
    }

    if (dupelim && id && 
	checkdelivered(id, strlen(id), namebuf, strlen(namebuf))) {
	/* duplicate message */
	logdupelem(id, namebuf);
	return 0;
    }
    r = append_setup(&mailbox, namebuf, MAILBOX_FORMAT_NORMAL,
		     authstate, acloverride ? 0 : ACL_POST, 
		     quotaoverride ? -1 : 0);

    if (!r) {
	prot_rewind(msg);
	if (singleinstance && stage) {
	    r = append_fromstage(&mailbox, msg, size, now, flag, nflags,
				 user, stage);
	} else {
	    r = append_fromstream(&mailbox, msg, size, now, flag, nflags,
				  user);
	}
	mailbox_close(&mailbox);
    }

    if (!r && user) {
	/* do we want to replace user.XXX with INBOX? */

	notify(user, mailboxname, notifyheader ? notifyheader : "");
    }

    if (!r && dupelim && id) markdelivered(id, strlen(id), 
					   namebuf, strlen(namebuf),
					   now);

    return r;
}

#ifdef USE_SIEVE
/* returns true if user has a sieve file in afs */
FILE *sieve_find_script(char *user)
{
    char buf[1024];

    if (strlen(user) > 900) {
	return NULL;
    }
    
    if (!dupelim) {
	/* duplicate delivery suppression is needed for sieve */
	return NULL;
    }

    if (sieve_usehomedir) { /* look in homedir */
	struct passwd *pent = getpwnam(user);

	if (pent == NULL) {
	    return NULL;
	}

	/* check ~USERNAME/.sieve */
	snprintf(buf, sizeof(buf), "%s/%s", pent->pw_dir, ".sieve");
    } else { /* look in sieve_dir */
	char hash;

	hash = (char) tolower((int) *user);
	if (!islower(hash)) { hash = 'q'; }

	snprintf(buf, sizeof(buf), "%s/%c/%s/default", sieve_dir, hash, user);
    }
	
    return (fopen(buf, "r"));
}
#endif

int deliver(deliver_opts_t *delopts, message_data_t *msgdata,
	    char **flag, int nflags, char *user, char *mailboxname)
{
    int r;
    struct mailbox mailbox;
    char namebuf[MAX_MAILBOX_PATH];
    char notifybuf[MAX_MAILBOX_PATH];
    char *submailbox = 0;
    FILE *f;

    if (user) {
	if (strchr(user, '.') ||
	    strlen(user) + 30 > MAX_MAILBOX_PATH) {
	    return IMAP_MAILBOX_NONEXISTENT;
	}
#ifdef USE_SIEVE
	f = sieve_find_script(user);
	if (f != NULL) {
	    script_data_t *sdata = NULL;
	    sieve_script_t *s = NULL;

	    sdata = (script_data_t *) xmalloc(sizeof(script_data_t));

	    sdata->username = user;
	    sdata->mailboxname = mailboxname;
	    sdata->authstate = auth_newstate(user, (char *)0);
	    
	    /* slap the mailboxname back on so we hash the envelope & id
	       when we figure out whether or not to keep the message */
	    strcpy(namebuf, user);
	    if (mailboxname) {
		strcat(namebuf, "+");
		strcat(namebuf, mailboxname);
	    }

	    /* is this the first time we've sieved the message? */
	    if (msgdata->id) {
		char *sdb = make_sieve_db(namebuf);
		
		if (checkdelivered(msgdata->id, strlen(msgdata->id),
				   sdb, strlen(sdb))) {
		    logdupelem(msgdata->id, sdb);
		    /* done it before ! */
		    return 0;
		}
	    } else {
		/* ah, screw it, we'll sieve it ! */
	    }

	    r = sieve_script_parse(sieve_interp, f, (void *) sdata, &s);
	    fclose(f);
	    if (r == SIEVE_OK)
		r = sieve_execute_script(s, (void *) msgdata);

	    if ((r == SIEVE_OK) && (msgdata->id)) {
		/* ok, we've run the script */
		char *sdb = make_sieve_db(namebuf);

		markdelivered(msgdata->id, strlen(msgdata->id), 
			      sdb, strlen(sdb), time(NULL));
	    }

	    /* free everything */
	    if (sdata->authstate) auth_freestate(sdata->authstate);
	    if (sdata) free(sdata);
	    sieve_script_free(&s);

	    /* if there was an error, r is non-zero and do normal delivery */
	} else {
	    /* no sieve script */
	    r = 1; /* do normal delivery actions */
	}
#else
	r = 1;
#endif
	if (r) {		/* normal delivery */
	    if (!mailboxname ||
		strlen(user) + strlen(mailboxname) + 30 > MAX_MAILBOX_PATH) {
		r = IMAP_MAILBOX_NONEXISTENT;
	    } else {
		strcpy(namebuf, "INBOX.");
		strcat(namebuf, mailboxname);
		
		r = deliver_mailbox(msgdata->data, 
				    &msgdata->stage, 
				    msgdata->size, 
				    flag, nflags, 
				    delopts->authuser, delopts->authstate,
				    msgdata->id, user, msgdata->notifyheader,
				    namebuf, delopts->quotaoverride, 0);
	    }
	    if (r) {
		strcpy(namebuf, "INBOX");
		
		/* ignore ACL's trying to deliver to INBOX */
		r = deliver_mailbox(msgdata->data, 
				    &msgdata->stage,
				    msgdata->size, 
				    flag, nflags, 
				    delopts->authuser, delopts->authstate,
				    msgdata->id, user, msgdata->notifyheader,
				    namebuf, delopts->quotaoverride, 1);
	    }
	}
    }
    else if (mailboxname) {
	r = deliver_mailbox(msgdata->data, 
			    &msgdata->stage,
			    msgdata->size, 
			    flag, nflags, 
			    delopts->authuser, delopts->authstate,
			    msgdata->id, user, msgdata->notifyheader,
			    mailboxname, delopts->quotaoverride, 0);
    }
    else {
	fprintf(stderr, "deliver: either -m or user required\n");
	usage();
    }

    return r;
}

/*
 */
static void
logdupelem(msgid, name)
char *msgid;
char *name;
{
    if (strlen(msgid) < 80) {
	syslog(LOG_INFO, "dupelim: eliminated duplicate message to %s id %s",
	       name, msgid);
    }
    else {
	syslog(LOG_INFO, "dupelim: eliminated duplicate message to %s",
	       name);
    }	
}

int 
convert_sysexit(r)
     int r;
{
    switch (r) {
    case 0:
	return 0;
	
    case IMAP_IOERROR:
	return EC_IOERR;

    case IMAP_PERMISSION_DENIED:
	return EC_NOPERM;

    case IMAP_MAILBOX_BADFORMAT:
    case IMAP_MAILBOX_NOTSUPPORTED:
    case IMAP_QUOTA_EXCEEDED:
	return EC_TEMPFAIL;

    case IMAP_MESSAGE_CONTAINSNULL:
    case IMAP_MESSAGE_CONTAINSNL:
    case IMAP_MESSAGE_CONTAINS8BIT:
    case IMAP_MESSAGE_BADHEADER:
    case IMAP_MESSAGE_NOBLANKLINE:
	return EC_DATAERR;

    case IMAP_MAILBOX_NONEXISTENT:
	/* XXX Might have been moved to other server */
	return EC_NOUSER;
    }
	
    /* Some error we're not expecting. */
    return EC_SOFTWARE;
}	

char 
*convert_lmtp(r)
     int r;
{
    switch (r) {
    case 0:
	return "250 2.1.5 Ok";
	
    case IMAP_IOERROR:
	return "451 4.3.0 System I/O error";
	
    case IMAP_PERMISSION_DENIED:
	return "550 5.7.1 Permission denied";

    case IMAP_QUOTA_EXCEEDED:
	return "452 4.2.2 Over quota";

    case IMAP_MAILBOX_BADFORMAT:
    case IMAP_MAILBOX_NOTSUPPORTED:
	return "451 4.2.0 Mailbox has an invalid format";

    case IMAP_MESSAGE_CONTAINSNULL:
	return "554 5.6.0 Message contains NUL characters";
	
    case IMAP_MESSAGE_CONTAINSNL:
	return "554 5.6.0 Message contains bare newlines";

    case IMAP_MESSAGE_CONTAINS8BIT:
	return "554 5.6.0 Message contains non-ASCII characters in headers";

    case IMAP_MESSAGE_BADHEADER:
	return "554 5.6.0 Message contains invalid header";

    case IMAP_MESSAGE_NOBLANKLINE:
	return "554 5.6.0 Message has no header/body separator";

    case IMAP_MAILBOX_NONEXISTENT:
	/* XXX Might have been moved to other server */
	return "550 5.1.1 User unknown";
    }
	
    /* Some error we're not expecting. */
    return "554 5.0.0 Unexpected internal error";
}

void fatal(const char* s, int code)
{
    prot_printf(deliver_out,"421 4.3.0 deliver: %s\r\n", s);
    prot_flush(deliver_out);
    exit(code);
}

int isvalidflag(f)
char *f;
{
    if (f[0] == '\\') {
	lcase(f);
	if (strcmp(f, "\\seen") && strcmp(f, "\\answered") &&
	    strcmp(f, "\\flagged") && strcmp(f, "\\draft") &&
	    strcmp(f, "\\deleted")) {
	    return 0;
	}
	return 1;
    }
    if (!imparse_isatom(f)) return 0;
    return 1;
}

/*
 * Destructively remove any whitespace and 822 comments
 * from string pointed to by 'buf'.  Does not handle continuation header
 * lines.
 */
void
clean822space(buf)
char *buf;
{
    char *from=buf, *to=buf;
    int c;
    int commentlevel = 0;

    while (c = *from++) {
	switch (c) {
	case '\r':
	case '\n':
	case '\0':
	    *to = '\0';
	    return;

	case ' ':
	case '\t':
	    continue;

	case '(':
	    commentlevel++;
	    break;

	case ')':
	    if (commentlevel) commentlevel--;
	    break;

	case '\\':
	    if (commentlevel && *from) from++;
	    /* FALL THROUGH */

	default:
	    if (!commentlevel) *to++ = c;
	    break;
	}
    }
}

#ifdef HAVE_LIBDB
static DB	*DeliveredDBptr;
#else
static DBM	*DeliveredDBptr;
#endif



/* too many processes are contending for single locks on delivered.db 
 * so we use this function to generate a specific delivered.db for a mailbox
 * First pass will be to just have 26 db files based on the first letter of 
 * the mailbox name. As distribution goes, this really blows but, hey, what do 
 * you expect from something quick and dirty?
 */
static char *
_get_db_name (mbox) 
     char *mbox;
{
  static char buf[MAX_MAILBOX_PATH];
  char *idx;
  char c;
  
  idx = strchr(mbox,'.');   /* skip past user. */
  if (idx == NULL) {         /* no '.' so just use mbox */
      idx = mbox;
  } else {
      idx++;                   /* skip past '.' */
  }
  c = (char) tolower((int) *idx);
  if (!islower(c)) {
      c = 'q';
  }

  sprintf(buf, "%s/deliverdb/deliver-%c", config_dir, c);

  return buf;
}


static int
_lock_delivered_db(to, write_lock) 
     char *to;
     int write_lock;
{
  char buf[MAX_MAILBOX_PATH];
  int lockfd;

  (void)strcpy(buf, _get_db_name(to));
  (void)strcat(buf, ".lock");
  lockfd = open(buf, O_RDWR|O_CREAT, 0666);
  if (lockfd < 0) {
    syslog(LOG_ERR, "Unable to open lock file: %s: %m", buf);
    return -1;
  }
  if (write_lock) {
    if (lock_blocking(lockfd)) {
      syslog(LOG_ERR, "Unable to write lock lock file: %s: %m", buf);
      close(lockfd);
      return -1;
    }
  } else {
    if (lock_shared(lockfd)) {
      syslog(LOG_ERR, "Unable to read lock lock file: %s: %m", buf);
      close(lockfd);
      return -1;
    }
  }
  
  return lockfd;
}

/* id: message id
 * to: name of mailbox
 * returns: 0 if not there
 *          time of delivery if there
 */
static time_t
checkdelivered(id, idlen, to, tolen)
char *id, *to;
int idlen, tolen;
{
#ifdef HAVE_LIBDB
    char buf[MAX_MAILBOX_PATH];
    char fname[MAX_MAILBOX_PATH];
    DBT date, delivery;
    HASHINFO info;
    int i, lockfd;
    time_t mark;

    (void)memset(&info, 0, sizeof(info));
    (void)memset(&date, 0, sizeof(date));
    (void)memset(&delivery, 0, sizeof(delivery));

    (void)strcpy(fname, _get_db_name(to));
    (void)strcat(fname, ".db");

    memcpy(buf, id, idlen);
    buf[idlen] = '\0';
    memcpy(buf + idlen + 1, to, tolen);
    buf[idlen + tolen + 1] = '\0';
    delivery.data = buf;
    delivery.size = idlen + tolen + 2;
          /* +2 b/c 1 for the center null; +1 for the terminating null */

    if ((lockfd = _lock_delivered_db(to, 0)) < 0) {
      return 0;
    }

    DeliveredDBptr = dbopen(fname, O_RDONLY, 0666, DB_HASH, &info);
    if (!DeliveredDBptr) {
      close(lockfd);
      syslog(LOG_ERR,"checkdelivered: Unable to open delivered db: %s: %m", 
	     fname);
      return 0;
    }

    if ((i = DeliveredDBptr->get(DeliveredDBptr, &delivery, &date, 0)) < 0) {
      syslog(LOG_ERR, "checkdelivered: error looking up %s/%d: %m", id, to);
    }

    if (logdebug) {
      syslog(LOG_DEBUG, "checkdelivered: checking %s %s - result = %d", id, to, i);
    }

    if (i == 0) {
	/* found the record */
	memcpy(&mark, date.data, sizeof(time_t));
    } else {
	mark = 0;
    }

    if (DeliveredDBptr->close(DeliveredDBptr) < 0) {
      syslog(LOG_ERR, "checkdelivered: error closing db: %m");
    }
    close(lockfd);

    return mark;
#else /* HAVE_LIBDB */
    static int initialized = 0;
    char buf[MAX_MAILBOX_PATH];
    datum date, delivery;
    int lockfd;
    time_t mark;

    /* The whole locking situation with dbm should be examined in some
     * more detail (but since we are using db and not dbm I'm just going
     * to leave this comment).
     * The right thing to do (with db too) is to keep the write lock 
     * active unless a duplicate is found. If a duplicate is found, then
     * the lock can be released. Otherwise, the lock should probably be
     * held until markdelivered() finishes updating the db.
     * The performance impact of holding the lock for that length of
     * time needs to also be examined.
     */

    if ((lockfd = _lock_delivered_db(to, 1)) <0)
      return 0;
	
    if (!initialized) {
      initialized++;

      (void)strcpy(buf, _get_db_name(to));
      (void)strcat(buf, ".db");

      DeliveredDBptr = dbm_open(buf, O_RDWR|O_CREAT, 0666);
      if (!DeliveredDBptr) {
	syslog(LOG_ERR, "checkdelivered: error opening delivered database: %s: %m",
	       buf);
	close(lockfd);
	return 0;
      }
    }
    if (!DeliveredDBptr) {
      close(lockfd);
      return 0;
    }

    sprintf(buf, "%s%c%s", id, '\0', to);
    delivery.dptr = buf;
    delivery.dsize = strlen(id) + strlen(to) + 2;
    date = dbm_fetch(DeliveredDBptr, delivery);
    if (date.dptr == NULL) {
	/* syslog(LOG_INFO, "unable to fetch entry for %s/%s: %m", id, to); */
	close(lockfd);
	return 0;
    }
    close(lockfd);
    memcpy(&mark, date.dptr, sizeof(time_t));
    dbm_close(DeliveredDBptr);

    return mark;
#endif /* HAVE_LIBDB */
}

static void
markdelivered(char *id, int idlen, char *to, int tolen, time_t mark)
{
  char buf[MAX_MAILBOX_PATH];
  char fname[MAX_MAILBOX_PATH];
  int lockfd;
#ifdef HAVE_LIBDB
  DBT date, delivery;
  HASHINFO info;
#else /* HAVE_LIBDB */
  datum date, delivery;
#endif

  memcpy(buf, id, idlen);
  buf[idlen] = '\0';
  memcpy(buf + idlen + 1, to, tolen);
  buf[idlen + tolen + 1] = '\0';
  if (mark == 0) { mark = time(0); }
    
#ifdef HAVE_LIBDB
  (void)memset(&info, 0, sizeof(info));
  (void)memset(&date, 0, sizeof(date));
  (void)memset(&delivery, 0, sizeof(delivery));

  delivery.data = buf;
  delivery.size = idlen + tolen + 2;
          /* +2 b/c 1 for the center null; +1 for the terminating null */

  date.data = &mark;
  date.size = sizeof(mark);

  (void)strcpy(fname, _get_db_name(to));
  (void)strcat(fname, ".db");

  if ((lockfd = _lock_delivered_db(to, 1)) < 0)
    return;
    
  DeliveredDBptr = dbopen(fname, O_RDWR|O_CREAT, 0666, DB_HASH, &info);
  if (!DeliveredDBptr) {
    syslog(LOG_ERR, "markdelivered: error opening delivered.db: %s: %m", buf);
    close(lockfd);
    return;
  }

  if (DeliveredDBptr->put(DeliveredDBptr, &delivery, &date, 0) < 0) {
    syslog(LOG_ERR, "markdelivered: error storing data: %m");
  }
  if (DeliveredDBptr->close(DeliveredDBptr) < 0) {
    syslog(LOG_ERR, "markdelivered: closing database :m");
  }
  close(lockfd);
#else /* don't HAVE_LIBDB */

  delivery.dptr = buf;
  delivery.dsize = idlen + tolen + 2;

  date.dptr = &mark;
  date.dsize = sizeof(mark);

  /* dbm_open is called in checkdelivered. This assumes that checkdelivered
     * gets called first */

  if ((lockfd = _lock_delivered_db(to, 1)) < 0)
    return;

  if (dbm_store(DeliveredDBptr, delivery, date, DBM_REPLACE) < 0) {
    syslog(LOG_ERR, "markdelivered: dbm_store: %m");
  }
  close(lockfd);
#endif /* HAVE_LIBDB */

  if (logdebug)
    syslog(LOG_DEBUG, "deliver: delivered %s to %s at %d", id, to, mark);
}

static int
_prune_actual_db(fname, mark) 
     char *fname;
     time_t mark;
{
  int rcode = 0;
  int count = 1;

#ifdef HAVE_LIBDB
  int rc, mode;
  DBT date, delivery;
  DBT *deletions = 0;
  HASHINFO info;
  int num_deletions = 0, alloc_deletions = 0;
#else /* HAVE_LIBDB */
  datum date, delivery;
#endif


#ifdef HAVE_LIBDB
  (void)memset(&info, 0, sizeof(info));
  (void)memset(&date, 0, sizeof(date));
  (void)memset(&delivery, 0, sizeof(delivery));

  (void)memset(&info, 0, sizeof(info));
  DeliveredDBptr = dbopen(fname, O_RDWR|O_CREAT, 0666, DB_HASH, &info);
  if (!DeliveredDBptr) {
    syslog(LOG_ERR,  "prunedelivered: error opening %s: %m");
    return -1;
  }
    
  mode = R_FIRST;
  while ((rc = DeliveredDBptr->seq(DeliveredDBptr, &delivery, &date, mode)) == 0) {
    mode = R_NEXT;
    count++;
    if ((date.size > 0) && ((*(time_t *)date.data) < mark)) {
      if (num_deletions >= alloc_deletions) {
	alloc_deletions += 1000;
	deletions = (DBT *) xrealloc((char *)deletions,
				     alloc_deletions * sizeof(DBT));
      }
      deletions[num_deletions].size = delivery.size;
      deletions[num_deletions].data = xmalloc(delivery.size);
      (void)memcpy(deletions[num_deletions].data, delivery.data, delivery.size);
      num_deletions++;
      if (logdebug) {
	/* delivery.data should be a string the form of  "<msgid>\0<to>\0" 
	 * but <msgid> and <to> may now be binary & contain nulls!!!
	 * eh, you asked for debugging
	 */
	char *ptr;
	      
	ptr = ((char *)delivery.data + (strlen(delivery.data) + 1)); 
	syslog(LOG_NOTICE, "prunedelivered: marking %s/%s at %d for deletion\n",
	       delivery.data, ptr, *(time_t *)date.data);
      }
    }
  }
  if (rc < 0) {
    syslog(LOG_ERR, "prunedelivered: error detected looking up %d entry: %m", count);
    syslog(LOG_ERR, "prunedelivered: will try to purge %d entries", num_deletions);
  }
  if (logdebug)
    syslog(LOG_DEBUG, "prunedelivered: will try to purge %d entries", num_deletions);
      
  while (num_deletions--) {
    if (DeliveredDBptr->del(DeliveredDBptr, &deletions[num_deletions], 0) < 0) {
      syslog(LOG_ERR, "prunedelivered: error deleting entry %d", num_deletions);
    }
  }

  if (DeliveredDBptr->close(DeliveredDBptr) < 0) {
    syslog(LOG_ERR, "prunedelivered: error closing database: %m");
  }
#else /* HAVE_LIBDB */

  /* initialize database */
  checkdelivered("", 0, "", 0);

  if (!DeliveredDBptr) return 1;

  for (delivery = dbm_firstkey(DeliveredDBptr); delivery.dptr;
						delivery = dbm_nextkey(DeliveredDBptr)) {
    date = dbm_fetch(DeliveredDBptr, delivery);
    if (!date.dptr) continue;
    if ((date.dsize > 0) && ((*(time_t *)date.dptr) < mark)) {
      if (dbm_delete(DeliveredDBptr, delivery)) {
	rcode = 1;
      }
    }
  }
  dbm_close(DeliveredDBptr);

#endif /* HAVE_LIBDB */

  return rcode;
}


int
prunedelivered(age)
int age;
{
  char c[2];
  int lockfd;
  int rc;
  char fname[MAX_MAILBOX_PATH];
  time_t mark;

  /* we allow age == 0 to nuke all current entries */
  if (age < 0)
    fatal("must specify positive number of days", EC_USAGE);

  mark = time(0) - (age*60*60*24);
  syslog(LOG_NOTICE, "prunedelivered: pruning back %d days", age);
  c[1] = '\0';
  for (c[0] = 'a' ; c[0] <= 'z'; c[0]++) {
      (void)strcpy(fname, _get_db_name(c));
      (void)strcat(fname, ".db");
      
      if (logdebug) {
	  syslog(LOG_DEBUG, "prunedelivered: pruning %s", fname);
      }
      
      if ((lockfd = _lock_delivered_db(c, 1)) < 0) {
	  return -1;
      }
      rc = _prune_actual_db(fname, mark);
      close(lockfd);
      if (rc < 0) {
	  syslog(LOG_ERR, "prunedelivered: error exit", age);
	  return(rc);
      }
  }
  syslog(LOG_NOTICE, "prunedelivered: done");
  return 0;
}

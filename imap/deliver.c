/*
 * deliver shell - this just calls lmtpd
 *
 * 
 *
 *
 *
 */

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

extern int optind;
extern char *optarg;

int lmtpdsock;

struct protstream *deliver_out, *deliver_in;

struct protstream *lmtpd_out, *lmtpd_in;

int logdebug = 0;

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
} message_data_t;

/* forward declarations */

void clean_retpath(char *rpath);

static void
usage()
{
    fprintf(stderr, 
	    "421-4.3.0 usage: deliver [-m mailbox] [-a auth] [-i]... [user]...\r\n");
    fprintf(stderr, "421 4.3.0        deliver -E age\n");
    fprintf(stderr, "421 4.3.0 %s\n", CYRUS_VERSION);
    exit(EC_USAGE);
}

void fatal(const char* s, int code)
{
    prot_printf(deliver_out,"421 4.3.0 deliver: %s\r\n", s);
    prot_flush(deliver_out);
    exit(code);
}

/*
 * Destructively remove any whitespace and 822 comments
 * from string pointed to by 'buf'.  Does not handle continuation header
 * lines.
 */
void
clean822space(char *buf)
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

int main(int argc, char **argv)
{
    int opt;
    char *mailboxname = NULL;
    char *authuser = NULL;
    message_data_t *msgdata;
    int r;

    deliver_in = prot_new(0, 0);
    deliver_out = prot_new(1, 1);
    prot_setflushonread(deliver_in, deliver_out);
    prot_settimeout(deliver_in, 300);

    msg_new(&msgdata);

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
	    msgdata->return_path = optarg;
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

	case 'F': /* set IMAP flag. we no longer support this */
	    fprintf(stderr,"deliver: 'F' option no longer supported\n");
	    usage();
	    break;

	case 'e':
	    /* duplicate delivery. ignore */
	    break;

	case 'E':
	    fprintf(stderr,"deliver: 'E' option no longer supported\n");
	    usage();
	    break;

	case 'l':
	    /* we always do lmtp. ignore */
	    break;

	case 'q':
	    /* lmtpd will handle quota issues. ignore */
	    break;

	default:
	    usage();
	}
    }

    /* Copy message to temp file */
    savemsg(msgdata);

    if (optind == argc) {
	/* deliver to global mailbox */
	r = deliver_msg(msgdata, NULL, mailboxname);
	
	if (r) {
	    com_err(mailboxname, r,
		    (r == IMAP_IOERROR) ? error_message(errno) : NULL);
	}

	/*	exitval = convert_sysexit(r); */
    }
    while (optind < argc) {
	/* deliver to users */
	r = deliver_msg(msgdata, argv[optind], mailboxname);

	if (r) {
	    com_err(argv[optind], r,
		    (r == IMAP_IOERROR) ? error_message(errno) : NULL);
	}

	/*	if (r && exitval != EC_TEMPFAIL) exitval = convert_sysexit(r); */

	optind++;
    }

}

/* initialize the network */
int init_net(char *serverFQDN, int port)
{
  struct sockaddr_in addr;
  struct hostent *hp;

  if ((hp = gethostbyname(serverFQDN)) == NULL) {
    perror("gethostbyname");
    return 0;
  }

  if ((lmtpdsock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    perror("socket");
    return 0;	
  }

  addr.sin_family = AF_INET;
  memcpy(&addr.sin_addr, hp->h_addr, hp->h_length);
  addr.sin_port = htons(port);

  if (connect(lmtpdsock, (struct sockaddr *) &addr, sizeof (addr)) < 0) {
    perror("connect");
    return 0;
  }

  return 1;
}

/* Return the response code for this line
   -1 if it doesn't seem to have one
*/
static int ask_code(char *str)
{
    int ret = 0;
    
    if (str==NULL) return -1;

    if (strlen(str) < 3) return -1;

    /* check to make sure 0-2 are digits */
    if ((isdigit(str[0])==0) ||
	(isdigit(str[1])==0) ||
	(isdigit(str[2])==0))
    {
	return -1;
    }


    ret = ((str[0]-'0')*100)+
	  ((str[1]-'0')*10)+
	  (str[2]-'0');
    
    return ret;
}

int read_initial(void)
{
    char buf[4096];

    do {

	prot_fgets(buf, sizeof(buf)-1, lmtpd_in);

	printf("buf = %s\n",buf);
    
    } while ((ask_code(buf)==220) && (buf[3]=='-'));

    if (ask_code(buf)!=220) return 0;

    return 1;
}

void say_hello(void)
{
    char buf[4096];

    prot_printf(lmtpd_out,"LHLO cmu.edu\r\n"); /* xxx */

    do {

	prot_fgets(buf, sizeof(buf)-1, lmtpd_in);

	printf("buf = %s\n",buf);
    
    } while ((ask_code(buf)==250) && (buf[3]=='-'));
}

int say_whofrom(void)
{
    char buf[4096];

    prot_printf(lmtpd_out,"MAIL FROM:<tmartin@andrew.cmu.edu>\r\n"); /* xxx */

    prot_fgets(buf, sizeof(buf)-1, lmtpd_in);

    printf("buf = %s\n",buf);
    
    if (ask_code(buf)!=250) return 0;

    return 1;
}

int say_rcpt(char *user, char *mailbox)
{
    int lup;
    char buf[4096];

    if ((user == NULL) && (mailbox==NULL))
    {
	return 0;
    }

    /* deliver to bboard */
    if (user == NULL)
    {
	prot_printf(lmtpd_out,"RCPT TO:<bb+%s>\r\n",mailbox);
    } else if (mailbox == NULL) {
	prot_printf(lmtpd_out,"RCPT TO:<%s>\r\n",user);
    } else {
	prot_printf(lmtpd_out,"RCPT TO:<%s+%s>\r\n",user,mailbox);
    }
    
    prot_fgets(buf, sizeof(buf)-1, lmtpd_in);    

    printf("buf = %s\n",buf);
    
    if (ask_code(buf)!=250) return 0;

    return 1;
}

int dot_stuff(char *in, int inlen, char **out)
{
    if (in[0]=='.')
    {
	*out = in-1;
	out[0]='.';
	return inlen+1;
    }

    *out = in;
    return inlen;
}

int pump_data(struct protstream *f)
{
    char buf[4096];
    char *tosend;
    int len;

    prot_printf(lmtpd_out, "DATA\r\n");

    prot_fgets(buf, sizeof(buf)-1, lmtpd_in);

    printf("%s\n",buf);
    
    if (ask_code(buf)!=354) return 0; 

    while ((len = prot_fgets(buf+1, sizeof(buf)-1, f))>0)
    {
	len = dot_stuff(buf, len, &tosend);
	
	prot_write(lmtpd_out, tosend, len);
    }

    prot_printf(lmtpd_out, "\r\n.\r\n");

    prot_fgets(buf, sizeof(buf)-1, lmtpd_in);

    printf("%s\n",buf);
    
    if (ask_code(buf)!=250) return 0; 

    return 1;
}
 
void deliver_msg(message_data_t *m, char *user, char *mailbox)
{
    printf("init network\n");
    /* connect */
    if (!init_net("cyrus-dev.andrew.cmu.edu",2003)) /* xxx */
    {
	printf("network init failed\n");
	/* xxx */
    }

    lmtpd_in = prot_new(lmtpdsock, 0);
    lmtpd_out = prot_new(lmtpdsock, 1);
    prot_setflushonread(lmtpd_in, lmtpd_out);
    prot_settimeout(lmtpd_in, 300);

    /* read initial */
    read_initial();

    /* lhlo */
    say_hello();
    
    /* mail from */
    say_whofrom();
    
    /* rcpt to */
    say_rcpt(user, mailbox);

    /* data */
    pump_data(m->data);

}


void savemsg(message_data_t *m)
{
    FILE *f;
    char *hostname = 0;
    int scanheader = 1;
    int sawidhdr = 0, sawresentidhdr = 0;
    int sawnotifyheader = 0;
    int sawretpathhdr = 0;
    char buf[8192], *p;
    int retpathclean = 0;
    struct stat sbuf;
    char **body, **frombody, **subjbody, **tobody;
    int sl, i;

    /* Copy to temp file */
    f = tmpfile();
    if (!f) {
	exit(EC_TEMPFAIL);
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

	fputs(buf, f);

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



    fflush(f);
    if (ferror(f)) {
	perror("deliver: copying message");
	exit(EC_TEMPFAIL);
    }

    if (fstat(fileno(f), &sbuf) == -1) {
	perror("deliver: stating message");
	exit(EC_TEMPFAIL);
    }
    m->size = sbuf.st_size;
    m->f = f;
    m->data = prot_new(fileno(f), 0);
}

/* returns non-zero on failure */
int msg_new(message_data_t **m)
{
    message_data_t *ret = (message_data_t *)malloc(sizeof(message_data_t));

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

    *m = ret;
    return 0;
}


void clean_retpath(char *rpath)
{
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

/*
 * deliver shell - this just calls lmtpd
 *
 * 
 *
 *
 *
 */

/* issues:
   -l flag
   buffer up whole message
   doesn't deal w/ multiple responses from DATA
   doesn't correctly exit based on response code
   MAIL FROM:<> isn't filled in with the sender
*/

#include <config.h>
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

#define DEFAULT_PORT 2003

extern int optind;
extern char *optarg;

int lmtpdsock;

struct protstream *deliver_out, *deliver_in;

struct protstream *lmtpd_out, *lmtpd_in;

int logdebug = 0;
int exitcode = 0;

/* forward declarations */

void pushmsg(struct protstream *out);
void deliver_msg(char *return_path, char *authuser, char **users, int numusers, char *mailbox, int portnum);
static int init_net(char *serverFQDN, int port);

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

static int push(int in, int out)
{
    char buf[4096];
    int len;
    int cnt;
    int amnt = 0;
    len = read(in, buf, sizeof(buf)-1);
    
    if (len == -1)
    {
	/* xxx what to do here? */
	exit (EC_IOERR);
    }
    if (len == 0)
    {
	exit(0);
    }

    /* keep writing until we have written the whole thing xxx can cause deadlock??? */
    do {
	cnt = write(out, buf+amnt,len-amnt);
    
	if (cnt == -1)
	{
	    /* xxx what to do here? */
	    exit (EC_IOERR);
	}
	amnt+=cnt;
    } while (amnt<len);

    return 0;
}

/*
 * Here we're just an intermediatory piping stdin to lmtp socket
 * and lmtp socket to stdout
 */
void pipe_through(int lmtp_in, int lmtp_out, int local_in, int local_out)
{
    int nfound;
    int highest = 3;
    fd_set read_set, rset;
    fd_set write_set, wset;


    FD_ZERO(&read_set);
    FD_SET(lmtp_in, &read_set);
    if (lmtp_in >= highest) highest = lmtp_in+1;
    FD_SET(local_in, &read_set);

    FD_ZERO(&write_set);
    FD_SET(lmtp_out, &write_set);
    if (lmtp_out >= highest) highest = lmtp_out+1;
    FD_SET(local_out, &write_set);

    while (1)
    {
	rset = read_set;
	wset = write_set;
	nfound = select(highest, &rset, &wset, NULL, NULL);
	if (nfound < 0) {
	    printf("xxx select err\n");
	}

	if ((FD_ISSET(lmtp_in,&rset))  && (FD_ISSET(local_out,&wset)))
	{
	    push(lmtp_in, local_out);
	} else if ((FD_ISSET(local_in,&rset)) && (FD_ISSET(lmtp_out,&wset))) {
	    push(local_in, lmtp_out);
	} else {
	    usleep(1000);
	}
    }
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

    while ((c = *from++)!=NULL) {
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
    int lmtpflag = 0;
    char *mailboxname = NULL;
    char *authuser = NULL;
    char *return_path = NULL;
    struct servent *serv;
    char *port = "lmtp";
    int portnum;

    /* map port -> num */
    serv = getservbyname(port, "tcp");
    if (serv == NULL) {
	portnum = DEFAULT_PORT;
    } else {
	portnum = ntohs(serv->s_port);
    }

    deliver_in = prot_new(0, 0);
    deliver_out = prot_new(1, 1);
    prot_setflushonread(deliver_in, deliver_out);
    prot_settimeout(deliver_in, 300);

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
	    return_path = optarg;
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
	    lmtpflag = 1;
	    break;

	case 'q':
	    /* lmtpd will handle quota issues. ignore */
	    break;

	default:
	    usage();
	}
    }

    if (lmtpflag == 1)
    {
	int s = init_net("localhost",portnum);

	pipe_through(s,s,0,1);
    }

    /* deliver to users or global mailbox */
    deliver_msg(return_path,authuser, argv+optind, argc - optind, mailboxname, portnum);
    
    /* if we got here there were no errors */
    exit(exitcode);
}

void just_exit(const char *msg)
{
    com_err(msg, 0, error_message(errno));

    fatal(msg,0);
}

/* initialize the network */
static int init_net(char *serverFQDN, int port)
{
  struct sockaddr_in addr;
  struct hostent *hp;

  if ((hp = gethostbyname(serverFQDN)) == NULL) {
      just_exit("gethostbyname failed");
  }

  if ((lmtpdsock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
      just_exit("socket failed");
  }

  addr.sin_family = AF_INET;
  memcpy(&addr.sin_addr, hp->h_addr, hp->h_length);
  addr.sin_port = htons(port);

  if (connect(lmtpdsock, (struct sockaddr *) &addr, sizeof (addr)) < 0) {
      just_exit("connect failed");
  }

  return lmtpdsock;
}

static void close_net(void)
{
    prot_printf(lmtpd_out,"QUIT\r\n");
    prot_flush(lmtpd_out);

    close(lmtpdsock);    
}

/*
 * Close the connection and exit with the desired error code
 */

void close_and_exit(int code, const char *msg)
{    

    
    com_err(msg, code,
	    (code == EC_IOERR) ? error_message(errno) : NULL);

    /* issue quit and close connection */
    close_net();

    fatal(msg, code);
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
    if ((isdigit((int) str[0])==0) ||
	(isdigit((int) str[1])==0) ||
	(isdigit((int) str[2])==0))
    {
	return -1;
    }


    ret = ((str[0]-'0')*100)+
	  ((str[1]-'0')*10)+
	  (str[2]-'0');
    
    return ret;
}

static void read_initial(void)
{
    char buf[4096];

    do {

	if (prot_fgets(buf, sizeof(buf)-1, lmtpd_in) == NULL)
	    close_and_exit (EC_IOERR, "Error reading initial");

    } while ((ask_code(buf)==220) && (buf[3]=='-'));


    switch (ask_code(buf))
	{
	case 421:
	    close_and_exit(EC_TEMPFAIL,"Service shutting down");
	    break;
	case 220: /* good */
	    break;
	default:
	    close_and_exit (EC_TEMPFAIL, "Received wrong initial code");	    
	    break;
	}
}

static void say_hello(void)
{
    char buf[4096];
    int r;

    r = prot_printf(lmtpd_out,"LHLO localhost\r\n");
    if (r) close_and_exit(EC_IOERR, "Error writing LHLO");

    do {

	if (prot_fgets(buf, sizeof(buf)-1, lmtpd_in) == NULL)
	    close_and_exit (EC_IOERR, "Error reading LHLO response");

    } while ((ask_code(buf)==250) && (buf[3]=='-'));

    switch (ask_code(buf))
	{
	case 250: break;
	case 421: close_and_exit (EC_TEMPFAIL, "Temporarily unavailable"); break;
	default: close_and_exit (EC_SOFTWARE, "Got 5xx response from LHLO"); break;	    
	}

}

static void say_whofrom(char *from, char *authuser)
{
    char buf[4096];
    int r;
    int code;        
    char *who = ""; /* leave blank so we don't get any bounces */
    if (from) who = from;

    if (authuser)
	r = prot_printf(lmtpd_out,"MAIL FROM:<%s> AUTH=%s\r\n",who,authuser);
    } else {
	r = prot_printf(lmtpd_out,"MAIL FROM:<%s>\r\n",who);
    }

    if (r) close_and_exit(EC_IOERR, "Error writing mail from");

    if (prot_fgets(buf, sizeof(buf)-1, lmtpd_in) == NULL)
	close_and_exit(EC_IOERR, "Error reading mail from response");

    
    code = ask_code(buf);

    if (code/100 == 4)
	close_and_exit (EC_TEMPFAIL, "Temporary failure from MAIL FROM command");

    if (code/100 == 5)
	close_and_exit (EC_SOFTWARE, "MAIL FROM command rejected");

    
}

static void handle_rcpt_code(char *buf, int *rcpts)
{
    switch (ask_code(buf))
	{
	case 251:
	case 250:
	    (*rcpts)++;
	    break;
	case 551: /* xxx user not local. how do we handle? */
	case 550: /* 550 5.1.1 User unknown */
	    exitcode = EC_NOUSER;
	    break;
	case 421:
	    close_and_exit(EC_TEMPFAIL,"Service shutting down");
	    break;
	default:
	    close_and_exit(EC_SOFTWARE, "Bad rcpt to response");	    
	    break;
	}
}

/*
** returns the number of rcpt's
*/

static int say_rcpt(char **users, int numusers, char *mailbox)
{
    char buf[4096];
    int r;
    int rcpts = 0;

    if ((numusers == 0) && (mailbox==NULL))
    {
	close_and_exit(EC_TEMPFAIL,"No mailbox or users specified");
    }

    /* deliver to bboard */
    if (numusers == 0)
    {
	r = prot_printf(lmtpd_out,"RCPT TO:<bb+%s>\r\n",mailbox);
	if (r) close_and_exit(EC_IOERR, "Error writing rcpt to");

	if (prot_fgets(buf, sizeof(buf)-1, lmtpd_in) == NULL)
	    close_and_exit(EC_IOERR, "Error reading rcpt to response");
	
	handle_rcpt_code(buf, &rcpts);

    } else {
	int lup;

	for (lup=0;lup<numusers;lup++)
	{
	    if (mailbox == NULL) {
		r = prot_printf(lmtpd_out,"RCPT TO:<%s>\r\n",users[lup]);		
	    } else {
		r = prot_printf(lmtpd_out,"RCPT TO:<%s+%s>\r\n",users[lup],mailbox);		
	    }

	    if (r) close_and_exit(EC_IOERR, "Error writing rcpt to");


	    if (prot_fgets(buf, sizeof(buf)-1, lmtpd_in) == NULL)
		close_and_exit(EC_IOERR, "Error reading rcpt to response");

	    handle_rcpt_code(buf, &rcpts);

	}
    } 

    return rcpts;
}

static void pump_data(int rcpts)
{
    char buf[4096];
    int lup;
    int r;

    r = prot_printf(lmtpd_out, "DATA\r\n");
    if (r) close_and_exit(EC_IOERR, "Error writing DATA");
    
    if (prot_fgets(buf, sizeof(buf)-1, lmtpd_in) == NULL)
	close_and_exit(EC_IOERR, "Error reading after DATA");

    switch (ask_code(buf))
	{
	case 354: /* good */ break;
	case 421: close_and_exit(EC_TEMPFAIL, "Service unavailable"); break;
	default:
	    close_and_exit(EC_SOFTWARE, "Service unavailable");	 break;	    
	}

    pushmsg(lmtpd_out);

    /* should receive one response for each sucessful rcpt to */
    for (lup=0;lup<rcpts;lup++)
    {
	if (prot_fgets(buf, sizeof(buf)-1, lmtpd_in) == NULL)
	    close_and_exit(EC_IOERR, "Error reading after message data");
	
	switch ((ask_code(buf))
		{
		case 552:
		case 452: /* quota issue */
		    exitcode = EC_TEMPFAIL; break;

		case 250: /* good */
		    break;
		    
		case 421:
		case 451:
		case 554: /* transaction failed */
		default:
		    close_and_exit(EC_SOFTWARE, "Error reading after message data"); 
		    break;
		}
    }
}
 
void deliver_msg(char *return_path, char *authuser, char **users, int numusers, char *mailbox, int portnum)
{
    int rcpts;

    /* connect */
    init_net("localhost",portnum);

    lmtpd_in = prot_new(lmtpdsock, 0);
    lmtpd_out = prot_new(lmtpdsock, 1);
    prot_setflushonread(lmtpd_in, lmtpd_out);
    prot_settimeout(lmtpd_in, 300);

    /* read initial */
    read_initial();

    /* lhlo */
    say_hello();
    
    /* mail from */
    say_whofrom(return_path, authuser);
    
    /* rcpt to */
    rcpts = say_rcpt(users,numusers, mailbox);

    if (rcpts > 0)
    {
	/* data */
	pump_data(rcpts);
    }

    close_net();
}


void pushmsg(struct protstream *out)
{
    int r;
    char *hostname = 0;
    char buf[8192], *p;
    int retpathclean = 0;
    int lastline_hadendline = 1;

    while (prot_fgets(buf, sizeof(buf)-1, deliver_in)) {

	/* dot stuff */
	if (lastline_hadendline == 1)
	    if (buf[0]=='.') {
		r = prot_write(out,".",1);
		if (r) close_and_exit(EC_IOERR, "Error writing message data");
	    }

	p = buf + strlen(buf) - 1;
	if (*p == '\n') {
	    if (p == buf || p[-1] != '\r') {
		p[0] = '\r';
		p[1] = '\n';
		p[2] = '\0';
	    }
	    lastline_hadendline = 1;
	}
	else if (*p == '\r') {
	    if (buf[0] == '\r' && buf[1] == '\0') {
		/* The message contained \r\0, and fgets is confusing us.
		   XXX ignored
		 */
		lastline_hadendline = 1;
	    } else {
		/*
		 * We were unlucky enough to get a CR just before we ran
		 * out of buffer--put it back.
		 */
		prot_ungetc('\r', deliver_in);
		*p = '\0';
		lastline_hadendline = 0;
	    }
	} else {
	    lastline_hadendline = 0;
	}

	/* Remove any lone CR characters */
	while ((p = strchr(buf, '\r')) && p[1] != '\n') {
	    strcpy(p, p+1);
	}

	r = prot_write(out, buf, strlen(buf));
	if (r) close_and_exit(EC_IOERR, "Error writing message data");
    }

    /* signify end of message */
    r = prot_printf(out, "\r\n.\r\n");
    if (r) close_and_exit(EC_IOERR, "Error writing message data");

    r = prot_flush(out);
    if (r) close_and_exit(EC_IOERR, "Error writing message data");
}


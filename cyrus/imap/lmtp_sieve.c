/* lmtp_sieve.c -- Sieve implementation for lmtpd
 *
 * $Id: lmtp_sieve.c,v 1.1.2.10 2004/06/24 15:16:27 ken3 Exp $
 * Copyright (c) 1998-2003 Carnegie Mellon University.  All rights reserved.
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
 *    prior written permission. For permission or any other legal
 *    details, please contact  
 *      Office of Technology Transfer
 *      Carnegie Mellon University
 *      5000 Forbes Avenue
 *      Pittsburgh, PA  15213-3890
 *      (412) 268-4387, fax: (412) 268-7395
 *      tech-transfer@andrew.cmu.edu
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
 *
 */

#include <config.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <pwd.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "append.h"
#include "auth.h"
#include "duplicate.h"
#include "exitcodes.h"
#include "global.h"
#include "imap_err.h"
#include "lmtp_sieve.h"
#include "lmtpengine.h"
#include "lmtpstats.h"
#include "notify.h"
#include "prot.h"
#include "rfc822date.h"
#include "sieve_interface.h"
#include "smtpclient.h"
#include "util.h"
#include "version.h"
#include "xmalloc.h"

static int sieve_usehomedir = 0;
static const char *sieve_dir = NULL;

/* data per script */
typedef struct script_data {
    const char *username;
    const char *mailboxname;
    struct auth_state *authstate;
} script_data_t;

/* forward declarations */
extern int deliver_mailbox(FILE *f,
			   struct message_content *content,
			   struct stagemsg *stage,
			   unsigned size,
			   char **flag,
			   int nflags,
			   char *authuser,
			   struct auth_state *authstate,
			   char *id,
			   const char *user,
			   char *notifyheader,
			   const char *mailboxname,
			   int quotaoverride,
			   int acloverride);

extern int fuzzy_match(char *mboxname);

static char *make_sieve_db(const char *user)
{
    static char buf[MAX_MAILBOX_PATH+1];

    buf[0] = '.';
    buf[1] = '\0';
    strlcat(buf, user, sizeof(buf));
    strlcat(buf, ".sieve.", sizeof(buf));

    return buf;
}

/* gets the header "head" from msg. */
static int getheader(void *v, const char *phead, const char ***body)
{
    message_data_t *m = ((sieve_msgdata_t *) v)->m;

    if (phead==NULL) return SIEVE_FAIL;
    *body = msg_getheader(m, phead);

    if (*body) {
	return SIEVE_OK;
    } else {
	return SIEVE_FAIL;
    }
}

static int getsize(void *mc, int *size)
{
    message_data_t *m = ((sieve_msgdata_t *) mc)->m;

    *size = msg_getsize(m);
    return SIEVE_OK;
}

/* we use the temp field in message_data to avoid having to malloc memory
   to return, and we also can't expose our the receipients to the message */
static int getenvelope(void *mc, const char *field, const char ***contents)
{
    sieve_msgdata_t *mydata = (sieve_msgdata_t *) mc;
    message_data_t *m = mydata->m;

    if (!strcasecmp(field, "from")) {
	*contents = mydata->temp;
	mydata->temp[0] = m->return_path;
	mydata->temp[1] = NULL;
	return SIEVE_OK;
    } else if (!strcasecmp(field, "to")) {
	*contents = mydata->temp;
	mydata->temp[0] = msg_getrcptall(m, mydata->cur_rcpt);
	mydata->temp[1] = NULL;
	return SIEVE_OK;
    } else if (!strcasecmp(field, "auth") && mydata->authuser) {
	*contents = mydata->temp;
	mydata->temp[0] = mydata->authuser;
	mydata->temp[1] = NULL;
	return SIEVE_OK;
    } else {
	*contents = NULL;
	return SIEVE_FAIL;
    }
}

static int getbody(void *mc, const char **content_types,
		   sieve_bodypart_t ***parts)
{
    sieve_msgdata_t *mydata = (sieve_msgdata_t *) mc;
    message_data_t *m = mydata->m;
    int r = 0;

    if (!mydata->content->body) {
	/* parse the message body if we haven't already */
	r = message_parse_file(m->f, &mydata->content->base,
			       &mydata->content->len, &mydata->content->body);
    }

    /* XXX currently struct bodypart as defined in message.h is the same as
       sieve_bodypart_t as defined in sieve_interface.h, so we can typecast */
    if (!r) message_fetch_part(mydata->content, content_types,
			       (struct bodypart ***) parts);
    return (!r ? SIEVE_OK : SIEVE_FAIL);
}


static int global_outgoing_count = 0;

static int send_rejection(const char *origid,
			  const char *rejto,
			  const char *origreceip, 
			  const char *mailreceip, 
			  const char *reason, 
			  struct protstream *file)
{
    FILE *sm;
    const char *smbuf[10];
    char buf[8192], *namebuf;
    int i, sm_stat;
    time_t t;
    char datestr[80];
    pid_t sm_pid, p;

    smbuf[0] = "sendmail";
    smbuf[1] = "-i";		/* ignore dots */
    smbuf[2] = "-f";
    smbuf[3] = "<>";
    smbuf[4] = "--";
    smbuf[5] = rejto;
    smbuf[6] = NULL;
    sm_pid = open_sendmail(smbuf, &sm);
    if (sm == NULL) {
	return -1;
    }

    t = time(NULL);
    p = getpid();
    snprintf(buf, sizeof(buf), "<cmu-sieve-%d-%d-%d@%s>", (int) p, (int) t, 
	     global_outgoing_count++, config_servername);
    
    namebuf = make_sieve_db(mailreceip);
    duplicate_mark(buf, strlen(buf), namebuf, strlen(namebuf), t, 0);
    fprintf(sm, "Message-ID: %s\r\n", buf);

    rfc822date_gen(datestr, sizeof(datestr), t);
    fprintf(sm, "Date: %s\r\n", datestr);

    fprintf(sm, "X-Sieve: %s\r\n", SIEVE_VERSION);
    fprintf(sm, "From: Mail Sieve Subsystem <%s>\r\n",
	    config_getstring(IMAPOPT_POSTMASTER));
    fprintf(sm, "To: <%s>\r\n", rejto);
    fprintf(sm, "MIME-Version: 1.0\r\n");
    fprintf(sm, "Content-Type: "
	    "multipart/report; report-type=disposition-notification;"
	    "\r\n\tboundary=\"%d/%s\"\r\n", (int) p, config_servername);
    fprintf(sm, "Subject: Automatically rejected mail\r\n");
    fprintf(sm, "Auto-Submitted: auto-replied (rejected)\r\n");
    fprintf(sm, "\r\nThis is a MIME-encapsulated message\r\n\r\n");

    /* this is the human readable status report */
    fprintf(sm, "--%d/%s\r\n", (int) p, config_servername);
    fprintf(sm, "Content-Type: text/plain; charset=utf-8\r\n");
    fprintf(sm, "Content-Disposition: inline\r\n");
    fprintf(sm, "Content-Transfer-Encoding: 8bit\r\n\r\n");

    fprintf(sm, "Your message was automatically rejected by Sieve, a mail\r\n"
	    "filtering language.\r\n\r\n");
    fprintf(sm, "The following reason was given:\r\n%s\r\n\r\n", reason);

    /* this is the MDN status report */
    fprintf(sm, "--%d/%s\r\n"
	    "Content-Type: message/disposition-notification\r\n\r\n",
	    (int) p, config_servername);
    fprintf(sm, "Reporting-UA: %s; Cyrus %s/%s\r\n",
	    config_servername, CYRUS_VERSION, SIEVE_VERSION);
    if (origreceip)
	fprintf(sm, "Original-Recipient: rfc822; %s\r\n", origreceip);
    fprintf(sm, "Final-Recipient: rfc822; %s\r\n", mailreceip);
    if (origid)
	fprintf(sm, "Original-Message-ID: %s\r\n", origid);
    fprintf(sm, "Disposition: "
	    "automatic-action/MDN-sent-automatically; deleted\r\n");
    fprintf(sm, "\r\n");

    /* this is the original message */
    fprintf(sm, "--%d/%s\r\nContent-Type: message/rfc822\r\n\r\n",
	    (int) p, config_servername);
    prot_rewind(file);
    while ((i = prot_read(file, buf, sizeof(buf))) > 0) {
	fwrite(buf, i, 1, sm);
    }
    fprintf(sm, "\r\n\r\n");
    fprintf(sm, "--%d/%s--\r\n", (int) p, config_servername);

    fclose(sm);
    while (waitpid(sm_pid, &sm_stat, 0) < 0);

    return sm_stat;	/* sendmail exit value */
}

static int send_forward(const char *forwardto,
			char *return_path,
			struct protstream *file)
{
    FILE *sm;
    const char *smbuf[10];
    int sm_stat;
    char buf[1024];
    pid_t sm_pid;
    int body = 0, skip;

    smbuf[0] = "sendmail";
    smbuf[1] = "-i";		/* ignore dots */
    if (return_path && *return_path) {
	smbuf[2] = "-f";
	smbuf[3] = return_path;
    } else {
	smbuf[2] = "-f";
	smbuf[3] = "<>";
    }
    smbuf[4] = "--";
    smbuf[5] = forwardto;
    smbuf[6] = NULL;
    sm_pid = open_sendmail(smbuf, &sm);
	
    if (sm == NULL) {
	return -1;
    }

    prot_rewind(file);
    while (prot_fgets(buf, sizeof(buf), file)) {
	if (!body && buf[0] == '\r' && buf[1] == '\n') {
	    /* blank line between header and body */
	    body = 1;
	}

	skip = 0;
	if (!body) {
	    if (!strncasecmp(buf, "Return-Path:", 12)) {
		/* strip the Return-Path */
		skip = 1;
	    }
	}

	do {
	    if (!skip) fwrite(buf, strlen(buf), 1, sm);
	} while (buf[strlen(buf)-1] != '\n' &&
		 prot_fgets(buf, sizeof(buf), file));
    }

    fclose(sm);
    while (waitpid(sm_pid, &sm_stat, 0) < 0);

    return sm_stat;	/* sendmail exit value */
}


static int sieve_redirect(void *ac, 
			  void *ic __attribute__((unused)), 
			  void *sc, void *mc, const char **errmsg)
{
    sieve_redirect_context_t *rc = (sieve_redirect_context_t *) ac;
    script_data_t *sd = (script_data_t *) sc;
    message_data_t *m = ((sieve_msgdata_t *) mc)->m;
    char buf[8192], *sievedb = NULL;
    int res;

    /* if we have a msgid, we can track our redirects */
    if (m->id) {
	snprintf(buf, sizeof(buf), "%s-%s", m->id, rc->addr);
	sievedb = make_sieve_db(sd->username);

	/* ok, let's see if we've redirected this message before */
	if (duplicate_check(buf, strlen(buf), sievedb, strlen(sievedb))) {
	    duplicate_log(m->id, sd->username, "redirect");
	    return SIEVE_OK;
	}
    }

    if ((res = send_forward(rc->addr, m->return_path, m->data)) == 0) {
	/* mark this message as redirected */
	if (sievedb) duplicate_mark(buf, strlen(buf), 
				    sievedb, strlen(sievedb), time(NULL), 0);

	snmp_increment(SIEVE_REDIRECT, 1);
	return SIEVE_OK;
    } else {
	if (res == -1) {
	    *errmsg = "Could not spawn sendmail process";
	} else {
	    *errmsg = sendmail_errstr(res);
	}
	return SIEVE_FAIL;
    }
}

static int sieve_discard(void *ac __attribute__((unused)), 
			 void *ic __attribute__((unused)), 
			 void *sc, void *mc, 
			 const char **errmsg __attribute__((unused)))
{
    script_data_t *sd = (script_data_t *) sc;
    message_data_t *md = ((sieve_msgdata_t *) mc)->m;

    snmp_increment(SIEVE_DISCARD, 1);

    /* ok, we won't file it, but log it */
    if (md->id && strlen(md->id) < 80) {
	char pretty[160];

	beautify_copy(pretty, md->id);
	syslog(LOG_INFO, "sieve: discarded message to %s id %s",
	       sd->username, pretty);
    }
    else {
	syslog(LOG_INFO, "sieve: discarded message to %s",
	       sd->username);
    }	

    return SIEVE_OK;
}

static int sieve_reject(void *ac, 
			void *ic __attribute__((unused)), 
			void *sc, void *mc, const char **errmsg)
{
    sieve_reject_context_t *rc = (sieve_reject_context_t *) ac;
    script_data_t *sd = (script_data_t *) sc;
    message_data_t *md = ((sieve_msgdata_t *) mc)->m;
    const char **body;
    const char *origreceip;
    int res;

    if (md->return_path == NULL) {
	/* return message to who?!? */
	*errmsg = "No return-path for reply";
	return SIEVE_FAIL;
    }

    if (strlen(md->return_path) == 0) {
	syslog(LOG_INFO, "sieve: discarded reject to <> for %s id %s",
	       sd->username, md->id);
        return SIEVE_OK;
    }

    body = msg_getheader(md, "original-recipient");
    origreceip = body ? body[0] : NULL;
    if ((res = send_rejection(md->id, md->return_path, 
			      origreceip, sd->username,
			      rc->msg, md->data)) == 0) {
	snmp_increment(SIEVE_REJECT, 1);
	return SIEVE_OK;
    } else {
	if (res == -1) {
	    *errmsg = "Could not spawn sendmail process";
	} else {
	    *errmsg = sendmail_errstr(res);
	}
	return SIEVE_FAIL;
    }
}

static int sieve_fileinto(void *ac, 
			  void *ic __attribute__((unused)),
			  void *sc, 
			  void *mc __attribute__((unused)), 
			  const char **errmsg __attribute__((unused)))
{
    sieve_fileinto_context_t *fc = (sieve_fileinto_context_t *) ac;
    script_data_t *sd = (script_data_t *) sc;
    sieve_msgdata_t *mdata = (sieve_msgdata_t *) mc;
    message_data_t *md = mdata->m;
    int quotaoverride = msg_getrcpt_ignorequota(md, mdata->cur_rcpt);
    char namebuf[MAX_MAILBOX_NAME+1];
    int ret;

    /* we're now the user who owns the script */
    if (!sd->authstate) return SIEVE_FAIL;

    ret = (*mdata->namespace->mboxname_tointernal)(mdata->namespace,
						   fc->mailbox,
						   sd->username, namebuf);
    if (!ret) {
	ret = deliver_mailbox(md->f, mdata->content, mdata->stage, md->size,
			      fc->imapflags->flag, fc->imapflags->nflags,
			      (char *) sd->username, sd->authstate, md->id,
			      sd->username, mdata->notifyheader,
			      namebuf, quotaoverride, 0);
    }

    if (!ret) {
	snmp_increment(SIEVE_FILEINTO, 1);
	return SIEVE_OK;
    } else {
	*errmsg = error_message(ret);
	return SIEVE_FAIL;
    }
}

static int sieve_keep(void *ac, 
		      void *ic __attribute__((unused)),
		      void *sc, void *mc, const char **errmsg)
{
    sieve_keep_context_t *kc = (sieve_keep_context_t *) ac;
    script_data_t *sd = (script_data_t *) sc;
    sieve_msgdata_t *mydata = (sieve_msgdata_t *) mc;
    message_data_t *md = mydata->m;
    int quotaoverride = msg_getrcpt_ignorequota(md, mydata->cur_rcpt);
    char namebuf[MAX_MAILBOX_NAME+1], *tail;
    int ret;

    ret = (*mydata->namespace->mboxname_tointernal)(mydata->namespace,
						    "INBOX",
						    sd->username, namebuf);

    if (!ret) {
	int ret2 = 1;

	tail = namebuf + strlen(namebuf);
	if (sd->mailboxname) {
	    strlcat(namebuf, ".", sizeof(namebuf));
	    strlcat(namebuf, sd->mailboxname, sizeof(namebuf));

	    ret2 = deliver_mailbox(md->f, mydata->content, mydata->stage, md->size,
				   kc->imapflags->flag, kc->imapflags->nflags,
				   mydata->authuser, mydata->authstate, md->id,
				   sd->username, mydata->notifyheader,
				   namebuf, quotaoverride, 0);
	}
	if (ret2 == IMAP_MAILBOX_NONEXISTENT && sd->mailboxname &&
	    config_getswitch(IMAPOPT_LMTP_FUZZY_MAILBOX_MATCH) &&
	    fuzzy_match(namebuf)) {
	    /* try delivery to a fuzzy matched mailbox */
	    ret2 = deliver_mailbox(md->f, mydata->content, mydata->stage, md->size,
				   kc->imapflags->flag, kc->imapflags->nflags,
				   mydata->authuser, mydata->authstate, md->id,
				   sd->username, mydata->notifyheader,
				   namebuf, quotaoverride, 0);
	}
	if (ret2) {
	    /* we're now the user who owns the script */
	    if (!sd->authstate) return SIEVE_FAIL;

	    /* normal delivery to INBOX */
	    *tail = '\0';

	    ret = deliver_mailbox(md->f, mydata->content, mydata->stage, md->size,
				  kc->imapflags->flag, kc->imapflags->nflags,
				  (char *) sd->username, sd->authstate, md->id,
				  sd->username, mydata->notifyheader,
				  namebuf, quotaoverride, 1);
	}
    }

    if (!ret) {
	snmp_increment(SIEVE_KEEP, 1);
	return SIEVE_OK;
    } else {
	*errmsg = error_message(ret);
	return SIEVE_FAIL;
    }
}

static int sieve_notify(void *ac,
			void *interp_context __attribute__((unused)), 
			void *script_context,
			void *mc __attribute__((unused)),
			const char **errmsg __attribute__((unused)))
{
    const char *notifier = config_getstring(IMAPOPT_SIEVENOTIFIER);

    if (notifier) {
	sieve_notify_context_t *nc = (sieve_notify_context_t *) ac;
	script_data_t *sd = (script_data_t *) script_context;
	int nopt = 0;

	snmp_increment(SIEVE_NOTIFY, 1);

	/* count options */
	while (nc->options[nopt]) nopt++;

	/* "default" is a magic value that implies the default */
	notify(!strcmp("default",nc->method) ? notifier : nc->method,
	       "SIEVE", nc->priority, sd->username, NULL,
	       nopt, nc->options, nc->message);
    }
    
    return SIEVE_OK;
}

static int autorespond(void *ac, 
		       void *ic __attribute__((unused)), 
		       void *sc,
		       void *mc __attribute__((unused)),
		       const char **errmsg __attribute__((unused)))
{
    sieve_autorespond_context_t *arc = (sieve_autorespond_context_t *) ac;
    script_data_t *sd = (script_data_t *) sc;
    time_t t, now;
    int ret;

    snmp_increment(SIEVE_VACATION_TOTAL, 1);

    now = time(NULL);

    /* ok, let's see if we've responded before */
    t = duplicate_check(arc->hash, arc->len, 
			sd->username, strlen(sd->username));
    if (t) {
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
	duplicate_mark((char *) arc->hash, arc->len, 
		       sd->username, strlen(sd->username), 
		       now + arc->days * (24 * 60 * 60), 0);
    }

    return ret;
}

static int send_response(void *ac, 
			 void *ic __attribute__((unused)), 
			 void *sc, void *mc, const char **errmsg)
{
    FILE *sm;
    const char *smbuf[10];
    char outmsgid[8192], *sievedb;
    int i, sl, sm_stat;
    time_t t;
    char datestr[80];
    pid_t sm_pid, p;
    sieve_send_response_context_t *src = (sieve_send_response_context_t *) ac;
    message_data_t *md = ((sieve_msgdata_t *) mc)->m;
    script_data_t *sdata = (script_data_t *) sc;

    smbuf[0] = "sendmail";
    smbuf[1] = "-i";		/* ignore dots */
    smbuf[2] = "-f";
    smbuf[3] = "<>";
    smbuf[4] = "--";
    smbuf[5] = src->addr;
    smbuf[6] = NULL;
    sm_pid = open_sendmail(smbuf, &sm);
    if (sm == NULL) {
	*errmsg = "Could not spawn sendmail process";
	return -1;
    }

    t = time(NULL);
    p = getpid();
    snprintf(outmsgid, sizeof(outmsgid), "<cmu-sieve-%d-%d-%d@%s>", 
	     (int) p, (int) t, global_outgoing_count++, config_servername);
    
    fprintf(sm, "Message-ID: %s\r\n", outmsgid);

    rfc822date_gen(datestr, sizeof(datestr), t);
    fprintf(sm, "Date: %s\r\n", datestr);
    
    fprintf(sm, "X-Sieve: %s\r\n", SIEVE_VERSION);
    fprintf(sm, "From: <%s>\r\n", src->fromaddr);
    fprintf(sm, "To: <%s>\r\n", src->addr);
    /* check that subject is sane */
    sl = strlen(src->subj);
    for (i = 0; i < sl; i++)
	if (iscntrl((int) src->subj[i])) {
	    src->subj[i] = '\0';
	    break;
	}
    fprintf(sm, "Subject: %s\r\n", src->subj);
    if (md->id) fprintf(sm, "In-Reply-To: %s\r\n", md->id);
    fprintf(sm, "Auto-Submitted: auto-replied (vacation)\r\n");
    fprintf(sm, "MIME-Version: 1.0\r\n");
    if (src->mime) {
	fprintf(sm, "Content-Type: multipart/mixed;"
		"\r\n\tboundary=\"%d/%s\"\r\n", (int) p, config_servername);
	fprintf(sm, "\r\nThis is a MIME-encapsulated message\r\n\r\n");
	fprintf(sm, "--%d/%s\r\n", (int) p, config_servername);
    } else {
	fprintf(sm, "Content-Type: text/plain; charset=utf-8\r\n");
	fprintf(sm, "Content-Transfer-Encoding: 8bit\r\n");
	fprintf(sm, "\r\n");
    }

    fprintf(sm, "%s\r\n", src->msg);

    if (src->mime) {
	fprintf(sm, "\r\n--%d/%s--\r\n", (int) p, config_servername);
    }
    fclose(sm);
    while (waitpid(sm_pid, &sm_stat, 0) < 0);

    if (sm_stat == 0) { /* sendmail exit value */
	sievedb = make_sieve_db(sdata->username);

	duplicate_mark(outmsgid, strlen(outmsgid), 
		       sievedb, strlen(sievedb), t, 0);

	snmp_increment(SIEVE_VACATION_REPLIED, 1);

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

static int sieve_parse_error_handler(int lineno, const char *msg, 
				     void *ic __attribute__((unused)),
				     void *sc)
{
    script_data_t *sd = (script_data_t *) sc;
    
    syslog(LOG_INFO, "sieve parse error for %s: line %d: %s",
	   sd->username, lineno, msg);
    
    return SIEVE_OK;
}

static int sieve_execute_error_handler(const char *msg, 
				       void *ic  __attribute__((unused)), 
				       void *sc, void *mc)
{
    script_data_t *sd = (script_data_t *) sc;
    message_data_t *md = ((sieve_msgdata_t *) mc)->m;
    
    syslog(LOG_INFO, "sieve runtime error for %s id %s: %s",
	   sd->username, md->id ? md->id : "(null)", msg);
    
    return SIEVE_OK;
}
 
sieve_interp_t *setup_sieve(void)
{
    sieve_interp_t *interp = NULL;
    int res;

    sieve_usehomedir = config_getswitch(IMAPOPT_SIEVEUSEHOMEDIR);
    if (!sieve_usehomedir) {
	sieve_dir = config_getstring(IMAPOPT_SIEVEDIR);
    } else {
	sieve_dir = NULL;
    }

    res = sieve_interp_alloc(&interp, NULL);
    if (res != SIEVE_OK) {
	syslog(LOG_ERR, "sieve_interp_alloc() returns %d\n", res);
	fatal("sieve_interp_alloc()", EC_SOFTWARE);
    }

    res = sieve_register_redirect(interp, &sieve_redirect);
    if (res != SIEVE_OK) {
	syslog(LOG_ERR, "sieve_register_redirect() returns %d\n", res);
	fatal("sieve_register_redirect()", EC_SOFTWARE);
    }
    res = sieve_register_discard(interp, &sieve_discard);
    if (res != SIEVE_OK) {
	syslog(LOG_ERR, "sieve_register_discard() returns %d\n", res);
	fatal("sieve_register_discard()", EC_SOFTWARE);
    }
    res = sieve_register_reject(interp, &sieve_reject);
    if (res != SIEVE_OK) {
	syslog(LOG_ERR, "sieve_register_reject() returns %d\n", res);
	fatal("sieve_register_reject()", EC_SOFTWARE);
    }
    res = sieve_register_fileinto(interp, &sieve_fileinto);
    if (res != SIEVE_OK) {
	syslog(LOG_ERR, "sieve_register_fileinto() returns %d\n", res);
	fatal("sieve_register_fileinto()", EC_SOFTWARE);
    }
    res = sieve_register_keep(interp, &sieve_keep);
    if (res != SIEVE_OK) {
	syslog(LOG_ERR, "sieve_register_keep() returns %d\n", res);
	fatal("sieve_register_keep()", EC_SOFTWARE);
    }
    res = sieve_register_imapflags(interp, &mark);
    if (res != SIEVE_OK) {
	syslog(LOG_ERR, "sieve_register_imapflags() returns %d\n", res);
	fatal("sieve_register_imapflags()", EC_SOFTWARE);
    }
    res = sieve_register_notify(interp, &sieve_notify);
    if (res != SIEVE_OK) {
	syslog(LOG_ERR, "sieve_register_notify() returns %d\n", res);
	fatal("sieve_register_notify()", EC_SOFTWARE);
    }
    res = sieve_register_size(interp, &getsize);
    if (res != SIEVE_OK) {
	syslog(LOG_ERR, "sieve_register_size() returns %d\n", res);
	fatal("sieve_register_size()", EC_SOFTWARE);
    }
    res = sieve_register_header(interp, &getheader);
    if (res != SIEVE_OK) {
	syslog(LOG_ERR, "sieve_register_header() returns %d\n", res);
	fatal("sieve_register_header()", EC_SOFTWARE);
    }

    res = sieve_register_envelope(interp, &getenvelope);
    if (res != SIEVE_OK) {
	syslog(LOG_ERR,"sieve_register_envelope() returns %d\n", res);
	fatal("sieve_register_envelope()", EC_SOFTWARE);
    }
    
    res = sieve_register_body(interp, &getbody);
    if (res != SIEVE_OK) {
	syslog(LOG_ERR,"sieve_register_body() returns %d\n", res);
	fatal("sieve_register_body()", EC_SOFTWARE);
    }
    
    res = sieve_register_vacation(interp, &vacation);
    if (res != SIEVE_OK) {
	syslog(LOG_ERR, "sieve_register_vacation() returns %d\n", res);
	fatal("sieve_register_vacation()", EC_SOFTWARE);
    }

    res = sieve_register_parse_error(interp, &sieve_parse_error_handler);
    if (res != SIEVE_OK) {
	syslog(LOG_ERR, "sieve_register_parse_error() returns %d\n", res);
	fatal("sieve_register_parse_error()", EC_SOFTWARE);
    }
 
    res = sieve_register_execute_error(interp, 
				       &sieve_execute_error_handler);
    if (res != SIEVE_OK) {
	syslog(LOG_ERR, "sieve_register_execute_error() returns %d\n", res);
	fatal("sieve_register_execute_error()", EC_SOFTWARE);
    }

    return interp;
}

static int sieve_find_script(const char *user, const char *domain,
			     char *fname, size_t size)
{
    if (strlen(user) > 900) {
	return -1;
    }
    
    if (sieve_usehomedir) { /* look in homedir */
	struct passwd *pent = getpwnam(user);

	if (pent == NULL) {
	    return -1;
	}

	/* check ~USERNAME/.sieve */
	snprintf(fname, size, "%s/%s", pent->pw_dir, ".sieve");
    } else { /* look in sieve_dir */
	char hash = (char) dir_hash_c(user);

	if (domain) {
	    char dhash = (char) dir_hash_c(domain);
	    snprintf(fname, size, "%s%s%c/%s/%c/%s/defaultbc",
		     sieve_dir, FNAME_DOMAINDIR, dhash, domain, hash, user);
	} else {
	    snprintf(fname, size, "%s/%c/%s/defaultbc", sieve_dir, hash, user);
	}
    }
	
    return 0;
}

int run_sieve(const char *user, const char *domain, const char *mailbox,
	      sieve_interp_t *interp, sieve_msgdata_t *msgdata)
{
    char fname[MAX_MAILBOX_PATH+1];
    int r = 0;

    if (sieve_find_script(user, domain, fname, sizeof(fname)) != -1) {
	script_data_t *sdata = NULL;
	sieve_bytecode_t *bc = NULL;
	char userbuf[MAX_MAILBOX_NAME+1];
	char authuserbuf[MAX_MAILBOX_NAME+1];

	sdata = (script_data_t *) xmalloc(sizeof(script_data_t));

	strlcpy(userbuf, user, sizeof(userbuf));
	if (domain) {
	    strlcat(userbuf, "@", sizeof(userbuf));
	    strlcat(userbuf, domain, sizeof(userbuf));
	}
	strlcpy(authuserbuf, userbuf, sizeof(authuserbuf));
	if (config_getswitch(IMAPOPT_UNIXHIERARCHYSEP)) {
	    mboxname_hiersep_toexternal(msgdata->namespace, authuserbuf,
					domain ? strcspn(authuserbuf, "@") : 0);
	}
	sdata->username = userbuf;
	sdata->mailboxname = mailbox;
	sdata->authstate = auth_newstate(authuserbuf);

	r = sieve_script_load(fname, &bc);
	if (r == SIEVE_OK) {
	    r = sieve_execute_bytecode(bc, interp,
				       (void *) sdata, (void *) msgdata);
	}
	if ((r == SIEVE_OK) && (msgdata->m->id)) {
	    /* ok, we've run the script */
	    char namebuf[MAX_MAILBOX_NAME+1];
	    char *sdb;
		    
	    /* slap the mailbox back on so we hash the envelope & id
	       when we figure out whether or not to keep the message */
	    snprintf(namebuf, sizeof(namebuf), "%s+%s@%s",
		     user, mailbox ? mailbox : "", domain ? domain : "");
	    sdb = make_sieve_db(namebuf);
		
	    duplicate_mark(msgdata->m->id, strlen(msgdata->m->id), 
			   sdb, strlen(sdb), time(NULL), 0);
	}
		
	/* free everything */
	if (sdata->authstate) auth_freestate(sdata->authstate);
	if (sdata) free(sdata);
	sieve_script_unload(&bc);
		
	/* if there was an error, r is non-zero and 
	   we'll do normal delivery */
    } else {
	/* no sieve script */
	r = 1; /* do normal delivery actions */
    }

    return r;
}

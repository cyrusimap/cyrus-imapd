/* imap_proxy.c - IMAP proxy support functions
 *
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
 */

#include <config.h>

#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <sysexits.h>
#include <syslog.h>
#include <sys/un.h>

#include "assert.h"
#include "acl.h"
#include "annotate.h"
#include "backend.h"
#include "global.h"
#include "imap_proxy.h"
#include "proxy.h"
#include "mboxname.h"
#include "mupdate-client.h"
#include "partlist.h"
#include "prot.h"
#include "util.h"
#include "xmalloc.h"

/* generated headers are not necessarily in current directory */
#include "imap/imap_err.h"

extern unsigned int proxy_cmdcnt;
extern struct protstream *imapd_in, *imapd_out;
extern struct backend *backend_inbox, *backend_current;
extern ptrarray_t backend_cached;
extern char *imapd_userid, *proxy_userid;
extern struct namespace imapd_namespace;

static partlist_t *server_parts = NULL;

static void proxy_part_filldata(partlist_t *part_list, int idx);

static void imap_postcapability(struct backend *s)
{
    if (CAPA(s, CAPA_SASL_IR)) {
        /* server supports initial response in AUTHENTICATE command */
        s->prot->u.std.sasl_cmd.maxlen = USHRT_MAX;
    }
}

struct protocol_t imap_protocol =
{ "imap", "imap", TYPE_STD,
  { { { 1, NULL },
      { "C01 CAPABILITY", NULL, "C01 ", imap_postcapability,
        CAPAF_MANY_PER_LINE,
        { { "AUTH", CAPA_AUTH },
          { "STARTTLS", CAPA_STARTTLS },
          { "COMPRESS=DEFLATE", CAPA_COMPRESS },
          { "IDLE", CAPA_IDLE },
          { "MUPDATE", CAPA_MUPDATE },
          { "MULTIAPPEND", CAPA_MULTIAPPEND },
          { "METADATA", CAPA_METADATA },
          { "RIGHTS=kxte", CAPA_ACLRIGHTS },
          { "LIST-EXTENDED", CAPA_LISTEXTENDED },
          { "SASL-IR", CAPA_SASL_IR },
          { "X-REPLICATION", CAPA_REPLICATION },
          { "X-SIEVE-MAILBOX", CAPA_SIEVE_MAILBOX },
          { "X-REPLICATION-ARCHIVE", CAPA_REPLICATION_ARCHIVE },
          /* Need to bump MAX_CAPA in protocol.h if this array is extended */
          { NULL, 0 } } },
      { "S01 STARTTLS", "S01 OK", "S01 NO", 0 },
      { "A01 AUTHENTICATE", 0, 0, "A01 OK", "A01 NO", "+ ", "*",
        NULL, AUTO_CAPA_AUTH_OK },
      { "Z01 COMPRESS DEFLATE", "* ", "Z01 OK" },
      { "N01 NOOP", "* ", "N01 OK" },
      { "Q01 LOGOUT", "* ", "Q01 " } } }
};

void proxy_gentag(char *tag, size_t len)
{
    snprintf(tag, len, "PROXY%d", proxy_cmdcnt++);
}

struct backend *proxy_findinboxserver(const char *userid)
{
    mbentry_t *mbentry = NULL;
    struct backend *s = NULL;

    char *inbox = mboxname_user_mbox(userid, NULL);
    int r = mboxlist_lookup(inbox, &mbentry, NULL);
    free(inbox);

    if (r) return NULL;

    if (mbentry->mbtype & MBTYPE_REMOTE) {
        s = proxy_findserver(mbentry->server, &imap_protocol,
                             proxy_userid, &backend_cached,
                             &backend_current, &backend_inbox, imapd_in);
    }

    mboxlist_entry_free(&mbentry);

    return s;
}

/* pipe_response() reads from 's->in' until either the tagged response
   starting with 'tag' appears, or if 'tag' is NULL, to the end of the
   current line.  If 'include_last' is set, the last/tagged line is included
   in the output, otherwise the last/tagged line is stored in 's->last_result'.
   In either case, the result of the tagged command is returned.

   's->last_result' assumes that tagged responses don't contain literals.
   Unfortunately, the IMAP grammar allows them

   force_notfatal says to not fatal() if we lose connection to backend_current
   even though it is in 95% of the cases, a good idea...
*/
static int pipe_response(struct backend *s, const char *tag, int include_last,
                         int force_notfatal)
{
    char buf[2048];
    char eol[128];
    unsigned sl;
    int cont = 0, last = !tag, r = PROXY_OK;
    size_t taglen = 0;

    s->timeout->mark = time(NULL) + IDLE_TIMEOUT;

    if (tag) {
        taglen = strlen(tag);
        if(taglen >= sizeof(buf) + 1) {
            fatal("tag too large",EX_TEMPFAIL);
        }
    }

    buf_reset(&s->last_result);

    /* the only complication here are literals */
    do {
        /* if 'cont' is set, we're looking at the continuation to a very
           long line.
           if 'last' is set, we've seen the tag we're looking for, we're
           just reading the end of the line. */
        if (!cont) eol[0] = '\0';

        if (!prot_fgets(buf, sizeof(buf), s->in)) {
            /* uh oh */
            if(s == backend_current && !force_notfatal)
                fatal("Lost connection to selected backend", EX_UNAVAILABLE);
            proxy_downserver(s);
            return PROXY_NOCONNECTION;
        }

        sl = strlen(buf);

        if (tag) {
            /* Check for the tagged line */
            if (!cont && buf[taglen] == ' ' && !strncmp(tag, buf, taglen)) {

                switch (buf[taglen + 1]) {
                case 'O': case 'o':
                    r = PROXY_OK;
                    break;
                case 'N': case 'n':
                    r = PROXY_NO;
                    break;
                case 'B': case 'b':
                    r = PROXY_BAD;
                    break;
                default: /* huh? no result? */
                    if(s == backend_current && !force_notfatal)
                        fatal("Lost connection to selected backend",
                              EX_UNAVAILABLE);
                    proxy_downserver(s);
                    r = PROXY_NOCONNECTION;
                    break;
                }

                last = 1;
            }

            if (last && !include_last) {
                /* Store the tagged line */
                buf_appendcstr(&s->last_result, buf+taglen+1);
                buf_cstring(&s->last_result);
            }
        }

        if (sl == (sizeof(buf) - 1) && buf[sl-1] != '\n') {
            /* only got part of a line */
            /* we save the last 64 characters in case it has important
               literal information */
            strcpy(eol, buf + sl - 64);

            /* write out this part, but we have to keep reading until we
               hit the end of the line */
            if (!last || include_last) prot_write(imapd_out, buf, sl);
            cont = 1;
            continue;
        } else {                /* we got the end of the line */
            int i;
            int litlen = 0, islit = 0;

            if (!last || include_last) prot_write(imapd_out, buf, sl);

            /* now we have to see if this line ends with a literal */
            if (sl < 64) {
                strcat(eol, buf);
            } else {
                strcat(eol, buf + sl - 63);
            }

            /* eol now contains the last characters from the line; we want
               to see if we've hit a literal */
            i = strlen(eol);
            if (i >= 4 &&
                eol[i-1] == '\n' && eol[i-2] == '\r' && eol[i-3] == '}') {
                /* possible literal */
                i -= 4;
                while (i > 0 && eol[i] != '{' && Uisdigit(eol[i])) {
                    i--;
                }
                if (eol[i] == '{') {
                    islit = 1;
                    litlen = atoi(eol + i + 1);
                }
            }

            /* copy the literal over */
            if (islit) {
                while (litlen > 0) {
                    int j = (litlen > (int) sizeof(buf) ?
                             (int) sizeof(buf) : litlen);

                    j = prot_read(s->in, buf, j);
                    if(!j) {
                        /* EOF or other error */
                        return -1;
                    }
                    if (!last || include_last) prot_write(imapd_out, buf, j);
                    litlen -= j;
                }

                /* none of our saved information has any relevance now */
                eol[0] = '\0';

                /* have to keep going for the end of the line */
                cont = 1;
                continue;
            }
        }

        /* ok, let's read another line */
        cont = 0;

    } while (!last || cont);

    return r;
}

int pipe_until_tag(struct backend *s, const char *tag, int force_notfatal)
{
    return pipe_response(s, tag, 0, force_notfatal);
}

int pipe_including_tag(struct backend *s, const char *tag, int force_notfatal)
{
    int r;

    r = pipe_response(s, tag, 1, force_notfatal);
    if (r == PROXY_NOCONNECTION) {
        /* don't have to worry about downing the server, since
         * pipe_until_tag does that for us */
        prot_printf(imapd_out, "%s NO %s\r\n", tag,
                    error_message(IMAP_SERVER_UNAVAILABLE));
    }
    return r;
}

static int pipe_to_end_of_response(struct backend *s, int force_notfatal)
{
    return pipe_response(s, NULL, 1, force_notfatal);
}

/* copy our current input to 's' until we hit a true EOL.

   'optimistic_literal' is how happy we should be about assuming
   that a command will go through by converting synchronizing literals of
   size less than optimistic_literal to nonsync

   returns 0 on success, <0 on big failure, >0 on full command not sent */
int pipe_command(struct backend *s, int optimistic_literal)
{
    char buf[2048];
    char eol[128];
    int sl;

    s->timeout->mark = time(NULL) + IDLE_TIMEOUT;

    eol[0] = '\0';

    /* again, the complication here are literals */
    for (;;) {
        if (!prot_fgets(buf, sizeof(buf), imapd_in)) {
            /* uh oh */
            return -1;
        }

        sl = strlen(buf);

        if (sl == (sizeof(buf) - 1) && buf[sl-1] != '\n') {
            /* only got part of a line */
            strcpy(eol, buf + sl - 64);

            /* and write this out, except for what we've saved */
            prot_write(s->out, buf, sl - 64);
            continue;
        } else {
            int i, nonsynch = 0, islit = 0, litlen = 0;

            if (sl < 64) {
                strcat(eol, buf);
            } else {
                /* write out what we have, and copy the last 64 characters
                   to eol */
                prot_printf(s->out, "%s", eol);
                prot_write(s->out, buf, sl - 64);
                strcpy(eol, buf + sl - 64);
            }

            /* now determine if eol has a literal in it */
            i = strlen(eol);
            if (i >= 4 &&
                eol[i-1] == '\n' && eol[i-2] == '\r' && eol[i-3] == '}') {
                /* possible literal */
                i -= 4;
                if (eol[i] == '+') {
                    nonsynch = 1;
                    i--;
                }
                while (i > 0 && eol[i] != '{' && Uisdigit(eol[i])) {
                    i--;
                }
                if (eol[i] == '{') {
                    islit = 1;
                    litlen = atoi(eol + i + 1);
                }
            }

            if (islit) {
                if (nonsynch) {
                    prot_write(s->out, eol, strlen(eol));
                } else if (!nonsynch && (litlen <= optimistic_literal)) {
                    prot_printf(imapd_out, "+ i am an optimist\r\n");
                    prot_write(s->out, eol, strlen(eol) - 3);
                    /* need to insert a + to turn it into a nonsynch */
                    prot_printf(s->out, "+}\r\n");
                } else {
                    /* we do a standard synchronizing literal */
                    prot_write(s->out, eol, strlen(eol));
                    /* but here the game gets tricky... */
                    prot_fgets(buf, sizeof(buf), s->in);
                    /* but for now we cheat */
                    prot_write(imapd_out, buf, strlen(buf));
                    if (buf[0] != '+' && buf[1] != ' ') {
                        /* char *p = strchr(buf, ' '); */
                        /* strncpy(s->last_result, p + 1, LAST_RESULT_LEN);*/

                        /* stop sending command now */
                        return 1;
                    }
                }

                /* gobble literal and sent it onward */
                while (litlen > 0) {
                    int j = (litlen > (int) sizeof(buf) ?
                             (int) sizeof(buf) : litlen);

                    j = prot_read(imapd_in, buf, j);
                    if(!j) {
                        /* EOF or other error */
                        return -1;
                    }
                    prot_write(s->out, buf, j);
                    litlen -= j;
                }

                eol[0] = '\0';

                /* have to keep going for the send of the command */
                continue;
            } else {
                /* no literal, so we're done! */
                prot_write(s->out, eol, strlen(eol));

                return 0;
            }
        }
    }
}

void print_listresponse(unsigned cmd, const char *extname, char hier_sep,
                        uint32_t attributes, struct buf *extraflags)
{
    const struct mbox_name_attribute *attr;
    const char *resp, *sep;

    switch (cmd) {
    case LIST_CMD_LSUB:
        resp = "LSUB";
        break;
    case LIST_CMD_XLIST:
        resp = "XLIST";
        break;
    default:
        resp = "LIST";
        break;
    }

    prot_printf(imapd_out, "* %s (", resp);

    for (sep = "", attr = mbox_name_attributes; attr->id; attr++) {
        if (attributes & attr->flag) {
            prot_printf(imapd_out, "%s%s", sep, attr->id);
            sep = " ";
        }
    }

    if (extraflags && buf_len(extraflags)) {
        prot_printf(imapd_out, "%s%s", sep, buf_cstring(extraflags));
    }

    prot_printf(imapd_out, ") \"%c\" ", hier_sep);

    prot_printastring(imapd_out, extname);

    if (attributes & MBOX_ATTRIBUTE_CHILDINFO_SUBSCRIBED) {
        prot_puts(imapd_out, " (CHILDINFO (");
        /* RFC 5258:
         *     ; Note 2: The selection options are always returned
         *     ; quoted, unlike their specification in
         *     ; the extended LIST command.
         */
        if (attributes & MBOX_ATTRIBUTE_CHILDINFO_SUBSCRIBED)
            prot_puts(imapd_out, "\"SUBSCRIBED\"");
        prot_puts(imapd_out, "))");
    }

    prot_puts(imapd_out, "\r\n");
}

/* add subscription flags or filter out non-subscribed mailboxes */
static int check_subs(mbentry_t *mbentry, strarray_t *subs,
                      struct listargs *listargs, uint32_t *flags)
{
    int i, namelen = strlen(mbentry->name);

    for (i = 0; i < subs->count; i++) {
        const char *name = strarray_nth(subs, i);

        if (strncmp(mbentry->name, name, namelen)) continue;
        else if (!name[namelen]) { /* exact match */
            *flags |= MBOX_ATTRIBUTE_SUBSCRIBED;
            break;
        }
        else if (name[namelen] == '.' &&
                 (listargs->sel & LIST_SEL_RECURSIVEMATCH)) {
            *flags |= MBOX_ATTRIBUTE_CHILDINFO_SUBSCRIBED;
            break;
        }
    }

    /* check if we need to filter out this mailbox */
    return (!(listargs->sel & LIST_SEL_SUBSCRIBED) ||
            (*flags & (MBOX_ATTRIBUTE_SUBSCRIBED |
                       MBOX_ATTRIBUTE_CHILDINFO_SUBSCRIBED)));
}

/* add subscribed mailbox or ancestor of subscribed mailbox to our list */
static void add_sub(strarray_t *subs, mbentry_t *mbentry, uint32_t attributes)
{
    if (attributes & MBOX_ATTRIBUTE_SUBSCRIBED) {
        /* mailbox is subscribed */
        strarray_append(subs, mbentry->name);
    }
    else {
        /* a descendent of mailbox is subscribed */
        struct buf child = BUF_INITIALIZER;

        buf_printf(&child, "%s.", mbentry->name);
        strarray_appendm(subs, buf_release(&child));
    }
}

static int is_extended_resp(const char *cmd, struct listargs *listargs)
{
    if (!(listargs->ret &
          (LIST_RET_STATUS | LIST_RET_MYRIGHTS | LIST_RET_METADATA))) {
        /* backend won't be sending extended response data */
        return 0;
    }
    else if ((listargs->ret & LIST_RET_STATUS) &&
             !strncasecmp("STATUS", cmd, 6)) {
        return 1;
    }
    else if ((listargs->ret & LIST_RET_MYRIGHTS) &&
             !strncasecmp("MYRIGHTS", cmd, 8)) {
        return 1;
    }
    else if ((listargs->ret & LIST_RET_METADATA) &&
             !strncasecmp("METADATA", cmd, 8)) {
        return 1;
    }

    return 0;
}

/* This handles piping of the LSUB command, because we have to figure out
 * what mailboxes actually exist before passing them to the end user.
 *
 * It is also needed if we are doing a LIST-EXTENDED, to capture subscriptions
 * and/or return data that can only be obtained from the backends.
 */
int pipe_lsub(struct backend *s, const char *userid, const char *tag,
              int force_notfatal, struct listargs *listargs, strarray_t *subs)
{
    int taglen = strlen(tag);
    int c;
    int r = PROXY_OK;
    int exist_r;
    static struct buf tagb, cmd, sep, name, ext;
    struct buf extraflags = BUF_INITIALIZER;
    int build_list_only = subs && !(listargs->ret & LIST_RET_SUBSCRIBED);
    int suppress_resp = 0;

    assert(s);
    assert(s->timeout);

    s->timeout->mark = time(NULL) + IDLE_TIMEOUT;

    while(1) {
        c = getword(s->in, &tagb);

        if(c == EOF) {
            if(s == backend_current && !force_notfatal)
                fatal("Lost connection to selected backend", EX_UNAVAILABLE);
            proxy_downserver(s);
            r = PROXY_NOCONNECTION;
            goto out;
        }

        if(!strncmp(tag, tagb.s, taglen)) {
            char buf[2048];
            if(!prot_fgets(buf, sizeof(buf), s->in)) {
                if(s == backend_current && !force_notfatal)
                    fatal("Lost connection to selected backend",
                          EX_UNAVAILABLE);
                proxy_downserver(s);
                r = PROXY_NOCONNECTION;
                goto out;
            }
            /* Got the end of the response */
            buf_appendcstr(&s->last_result, buf);
            buf_cstring(&s->last_result);

            switch (buf[0]) {
            case 'O': case 'o':
                r = PROXY_OK;
                break;
            case 'N': case 'n':
                r = PROXY_NO;
                break;
            case 'B': case 'b':
                r = PROXY_BAD;
                break;
            default: /* huh? no result? */
                if(s == backend_current && !force_notfatal)
                    fatal("Lost connection to selected backend",
                          EX_UNAVAILABLE);
                proxy_downserver(s);
                r = PROXY_NOCONNECTION;
                break;
            }
            break; /* we're done */
        }

        c = getword(s->in, &cmd);

        if(c == EOF) {
            if(s == backend_current && !force_notfatal)
                fatal("Lost connection to selected backend", EX_UNAVAILABLE);
            proxy_downserver(s);
            r = PROXY_NOCONNECTION;
            goto out;
        }

        if(strncasecmp("LSUB", cmd.s, 4) && strncasecmp("LIST", cmd.s, 4)) {
            if (suppress_resp && is_extended_resp(cmd.s, listargs)) {
                /* suppress extended return data for this mailbox */
                eatline(s->in, c);
            }
            else {
                prot_printf(imapd_out, "%s %s ", tagb.s, cmd.s);
                r = pipe_to_end_of_response(s, force_notfatal);
                if (r != PROXY_OK)
                    goto out;
            }
        } else {
            /* build up the response bit by bit */
            const struct mbox_name_attribute *attr;
            uint32_t attributes = 0;

            /* Get flags */
            buf_reset(&extraflags);
            c = prot_getc(s->in);
            if (c == '(') {
                do {
                    c = getword(s->in, &name);
                    for (attr = mbox_name_attributes;
                         attr->id && strcasecmp(name.s, attr->id); attr++);

                    if (attr->id) attributes |= attr->flag;
                    else {
                        if (buf_len(&extraflags)) buf_putc(&extraflags, ' ');
                        buf_appendcstr(&extraflags, name.s);
                    }
                } while (c == ' ');

                if (c == ')') {
                    /* end of flags - get the next character */
                    c = prot_getc(s->in);
                }
            }

            if(c != ' ') {
                if(s == backend_current && !force_notfatal)
                    fatal("Bad LSUB response from selected backend",
                          EX_UNAVAILABLE);
                proxy_downserver(s);
                r = PROXY_NOCONNECTION;
                goto out;
            }

            /* Get separator */
            c = getastring(s->in, s->out, &sep);

            if(c != ' ') {
                if(s == backend_current && !force_notfatal)
                    fatal("Bad LSUB response from selected backend",
                          EX_UNAVAILABLE);
                proxy_downserver(s);
                r = PROXY_NOCONNECTION;
                goto out;
            }

            /* Get name */
            c = getastring(s->in, s->out, &name);

            /* Get extension(s) */
            buf_reset(&ext);
            if (c == ' ') {
                do {
                    buf_putc(&ext, c);
                    c = prot_getc(s->in);
                } while (c != '\r' && c != '\n' && c != EOF);

                /* XXX  Currently there are no other documented extensions */
                attributes |= MBOX_ATTRIBUTE_CHILDINFO_SUBSCRIBED;
            }
            buf_cstring(&ext);

            if(c == '\r') c = prot_getc(s->in);
            if(c != '\n') {
                if(s == backend_current && !force_notfatal)
                    fatal("Bad LSUB response from selected backend",
                          EX_UNAVAILABLE);
                proxy_downserver(s);
                r = PROXY_NOCONNECTION;
                goto out;
            }

            /* lookup name */
            exist_r = 1;
            char *intname =
                mboxname_from_external(name.s, &imapd_namespace, userid);
            mbentry_t *mbentry = NULL;
            exist_r = mboxlist_lookup(intname, &mbentry, NULL);
            free(intname);
            if(!exist_r && (mbentry->mbtype & MBTYPE_RESERVE))
                exist_r = IMAP_MAILBOX_RESERVED;

            /* suppress responses to client if we're just building subs list */
            suppress_resp = build_list_only;

            if (!exist_r) {
                /* we need to remove \Noselect if it's in our mailboxes.db */
                attributes &=
                    ~(MBOX_ATTRIBUTE_NOSELECT | MBOX_ATTRIBUTE_NONEXISTENT);

                if (subs) {
                    /* process subscriptions */
                    if (s != backend_inbox) {
                        /* backend server won't have subs info -
                           add sub flags or filter out non-sub mailboxes */
                        if (!check_subs(mbentry, subs, listargs, &attributes)) {
                            /* unsubscribed and we only want subscriptions */
                            suppress_resp = 1;
                        }
                    }
                    else if (listargs->sel & LIST_SEL_SUBSCRIBED) {
                        /* If we're just building subs list,
                           we want ALL subscriptions added to list.
                           Otherwise just add those NOT on Inbox server. */
                        if (build_list_only ||
                            strcmp(mbentry->server, backend_inbox->hostname)) {
                            add_sub(subs, mbentry, attributes);
                            /* suppress the response - those NOT added to the
                               list are sent to client in subsequent requests */
                            suppress_resp = 1;
                        }
                    }
                }
            }

            if (!suppress_resp) {
                /* send response to the client */
                print_listresponse(listargs->cmd, name.s, sep.s[0],
                                   attributes, &extraflags);

                /* send any PROXY_ONLY metadata items */
                for (c = 0; c < listargs->metaitems.count; c++) {
                    const char *entry = strarray_nth(&listargs->metaitems, c);

                    if (mbentry &&
                        !strcmp(entry, "/shared" IMAP_ANNOT_NS "server")) {
                        prot_puts(imapd_out, "* METADATA ");
                        prot_printastring(imapd_out, name.s);
                        prot_puts(imapd_out, " (");
                        prot_printstring(imapd_out, entry);
                        prot_puts(imapd_out, " ");
                        prot_printstring(imapd_out, mbentry->server);
                        prot_puts(imapd_out, ")\r\n");
                    }
                }
            }

            mboxlist_entry_free(&mbentry);
        }
    } /* while(1) */

out:
    buf_free(&extraflags);
    return r;
}

/* xxx  start of separate proxy-only code
   (remove when we move to a unified environment) */
static int chomp(struct protstream *p, const char *s)
{
    int c = prot_getc(p);

    while (*s) {
        if (tolower(c) != tolower(*s)) { break; }
        s++;
        c = prot_getc(p);
    }
    if (*s) {
        if (c != EOF) prot_ungetc(c, p);
        c = EOF;
    }
    return c;
}

#define BUFGROWSIZE 100

/* read characters from 'p' until 'end' is seen */
static char *grab(struct protstream *p, char end)
{
    int alloc = BUFGROWSIZE, cur = 0;
    int c = -1;
    char *ret = (char *) xmalloc(alloc);

    ret[0] = '\0';
    while ((c = prot_getc(p)) != end) {
        if (c == EOF) break;
        if (cur == alloc - 1) {
            alloc += BUFGROWSIZE;
            ret = xrealloc(ret, alloc);

        }
        ret[cur++] = c;
    }
    if (cur) ret[cur] = '\0';

    return ret;
}

/* remove \Recent from the flags */
static char *editflags(char *flags)
{
    char *p;

    p = flags;
    while ((p = strchr(p, '\\')) != NULL) {
        if (!strncasecmp(p + 1, "recent", 6)) {
            if (p[7] == ' ') {
                /* shift everything over so that \recent vanishes */
                char *q;

                q = p + 8;
                while (*q) {
                    *p++ = *q++;
                }
                *p = '\0';
            } else if (p[7] == '\0') {
                /* last flag in line */
                *p = '\0';
            } else {
                /* not really \recent, i guess */
                p++;
            }
        } else {
            p++;
        }
    }

    return flags;
}

void proxy_copy(const char *tag, char *sequence, char *name, int myrights,
                int usinguid, struct backend *s)
{
    char mytag[128];
    struct d {
        char *idate;
        char *flags;
        unsigned int seqno, uid;
        struct d *next;
    } *head, *p, *q;
    int c;

    /* find out what the flags & internaldate for this message are */
    proxy_gentag(mytag, sizeof(mytag));
    prot_printf(backend_current->out,
                "%s %s %s (Flags Internaldate)\r\n",
                tag, usinguid ? "Uid Fetch" : "Fetch", sequence);
    head = (struct d *) xmalloc(sizeof(struct d));
    head->flags = NULL; head->idate = NULL;
    head->seqno = head->uid = 0;
    head->next = NULL;
    p = head;
    /* read all the responses into the linked list */
    for (/* each FETCH response */;;) {
        unsigned int seqno = 0, uidno = 0;
        char *flags = NULL, *idate = NULL;

        /* read a line */
        c = prot_getc(backend_current->in);
        if (c != '*') break;
        c = prot_getc(backend_current->in);
        if (c != ' ') { /* protocol error */ c = EOF; break; }

        /* check for OK/NO/BAD/BYE response */
        if (!isdigit(c = prot_getc(backend_current->in))) {
            prot_printf(imapd_out, "* %c", c);
            pipe_to_end_of_response(backend_current, 0);
            continue;
        }

        /* read seqno */
        prot_ungetc(c, backend_current->in);
        c = getuint32(backend_current->in, &seqno);
        if (seqno == 0 || c != ' ') {
            /* we suck and won't handle this case */
            c = EOF; break;
        }
        c = chomp(backend_current->in, "fetch (");
        if (c == EOF) {
            c = chomp(backend_current->in, "exists\r");
            if (c == '\n') { /* got EXISTS response */
                prot_printf(imapd_out, "* %d EXISTS\r\n", seqno);
                continue;
            }
        }
        if (c == EOF) {
            /* XXX  the "exists" check above will eat "ex" */
            c = chomp(backend_current->in, "punge\r");
            if (c == '\n') { /* got EXPUNGE response */
                prot_printf(imapd_out, "* %d EXPUNGE\r\n", seqno);
                continue;
            }
        }
        if (c == EOF) {
            c = chomp(backend_current->in, "recent\r");
            if (c == '\n') { /* got RECENT response */
                prot_printf(imapd_out, "* %d RECENT\r\n", seqno);
                continue;
            }
        }
        /* huh, don't get this response */
        if (c == EOF) break;
        for (/* each fetch item */;;) {
            /* looking at the first character in an item */
            switch (c) {
            case 'f': case 'F': /* flags? */
                c = chomp(backend_current->in, "lags");
                if (c != ' ') { c = EOF; }
                else c = prot_getc(backend_current->in);
                if (c != '(') { c = EOF; }
                else {
                    flags = grab(backend_current->in, ')');
                    c = prot_getc(backend_current->in);
                }
                break;
            case 'i': case 'I': /* internaldate? */
                c = chomp(backend_current->in, "nternaldate");
                if (c != ' ') { c = EOF; }
                else c = prot_getc(backend_current->in);
                if (c != '"') { c = EOF; }
                else {
                    idate = grab(backend_current->in, '"');
                    c = prot_getc(backend_current->in);
                }
                break;
            case 'u': case 'U': /* uid */
                c = chomp(backend_current->in, "id");
                if (c != ' ') { c = EOF; }
                else c = getuint32(backend_current->in, &uidno);
                break;
            default: /* hmm, don't like the smell of it */
                c = EOF;
                break;
            }
            /* looking at either SP separating items or a RPAREN */
            if (c == ' ') { c = prot_getc(backend_current->in); }
            else if (c == ')') break;
            else { c = EOF; break; }
        }
        /* if c == EOF we have either a protocol error or a situation
           we can't handle, and we should die. */
        if (c == ')') c = prot_getc(backend_current->in);
        if (c == '\r') c = prot_getc(backend_current->in);
        if (c != '\n') {
            c = EOF;
            free(flags);
            free(idate);
            break;
        }

        /* if we're missing something, we should echo */
        if (!flags || !idate) {
            char sep = '(';
            prot_printf(imapd_out, "* %d FETCH ", seqno);
            if (uidno) {
                prot_printf(imapd_out, "%cUID %d", sep, uidno);
                sep = ' ';
            }
            if (flags) {
                prot_printf(imapd_out, "%cFLAGS %s", sep, flags);
                sep = ' ';
            }
            if (idate) {
                prot_printf(imapd_out, "%cINTERNALDATE %s", sep, idate);
                sep = ' ';
            }
            prot_printf(imapd_out, ")\r\n");
            if (flags) free(flags);
            if (idate) free(idate);
            continue;
        }

        /* add to p->next */
        p->next = xmalloc(sizeof(struct d));
        p = p->next;
        p->idate = idate;
        p->flags = editflags(flags);
        p->uid = uidno;
        p->seqno = seqno;
        p->next = NULL;
    }
    if (c != EOF) {
        prot_ungetc(c, backend_current->in);

        /* we should be looking at the tag now */
        pipe_until_tag(backend_current, tag, 0);
    }
    if (c == EOF) {
        /* uh oh, we're not happy */
        fatal("Lost connection to selected backend", EX_UNAVAILABLE);
    }

    /* start the append */
    prot_printf(s->out, "%s Append {" SIZE_T_FMT "+}\r\n%s",
                tag, strlen(name), name);
    prot_printf(backend_current->out, "%s %s %s (Rfc822.peek)\r\n",
                mytag, usinguid ? "Uid Fetch" : "Fetch", sequence);
    for (/* each FETCH response */;;) {
        unsigned int seqno = 0, uidno = 0;

        /* read a line */
        c = prot_getc(backend_current->in);
        if (c != '*') break;
        c = prot_getc(backend_current->in);
        if (c != ' ') { /* protocol error */ c = EOF; break; }

        /* check for OK/NO/BAD/BYE response */
        if (!isdigit(c = prot_getc(backend_current->in))) {
            prot_printf(imapd_out, "* %c", c);
            pipe_to_end_of_response(backend_current, 0);
            continue;
        }

        /* read seqno */
        prot_ungetc(c, backend_current->in);
        c = getuint32(backend_current->in, &seqno);
        if (seqno == 0 || c != ' ') {
            /* we suck and won't handle this case */
            c = EOF; break;
        }
        c = chomp(backend_current->in, "fetch (");
        if (c == EOF) { /* not a fetch response */
            c = chomp(backend_current->in, "exists\r");
            if (c == '\n') { /* got EXISTS response */
                prot_printf(imapd_out, "* %d EXISTS\r\n", seqno);
                continue;
            }
        }
        if (c == EOF) { /* not an exists response */
            /* XXX  the "exists" check above will eat "ex" */
            c = chomp(backend_current->in, "punge\r");
            if (c == '\n') { /* got EXPUNGE response */
                prot_printf(imapd_out, "* %d EXPUNGE\r\n", seqno);
                continue;
            }
        }
        if (c == EOF) { /* not an exists response */
            c = chomp(backend_current->in, "recent\r");
            if (c == '\n') { /* got RECENT response */
                prot_printf(imapd_out, "* %d RECENT\r\n", seqno);
                continue;
            }
        }
        if (c == EOF) {
            /* huh, don't get this response */
            break;
        }
        /* find seqno in the list */
        p = head;
        while (p->next && seqno != p->next->seqno) p = p->next;
        if (!p->next) break;
        q = p->next;
        p->next = q->next;
        for (/* each fetch item */;;) {
            int sz = 0;

            switch (c) {
            case 'u': case 'U':
                c = chomp(backend_current->in, "id");
                if (c != ' ') { c = EOF; }
                else c = getuint32(backend_current->in, &uidno);
                break;

            case 'r': case 'R':
                c = chomp(backend_current->in, "fc822");
                if (c == ' ') c = prot_getc(backend_current->in);
                if (c != '{') {
                    /* NIL? */
                    eatline(backend_current->in, c);
                    c = EOF;
                }
                else c = getint32(backend_current->in, &sz);
                if (c == '}') c = prot_getc(backend_current->in);
                if (c == '\r') c = prot_getc(backend_current->in);
                if (c != '\n') c = EOF;

                if (c != EOF) {
                    /* append p to s->out */
                    prot_printf(s->out, " (%s) \"%s\" {%d+}\r\n",
                                q->flags, q->idate, sz);
                    while (sz) {
                        char buf[2048];
                        int j = (sz > (int) sizeof(buf) ?
                                 (int) sizeof(buf) : sz);

                        j = prot_read(backend_current->in, buf, j);
                        if(!j) break;
                        prot_write(s->out, buf, j);
                        sz -= j;
                    }
                    c = prot_getc(backend_current->in);
                }

                break; /* end of case */
            default:
                c = EOF;
                break;
            }
            /* looking at either SP separating items or a RPAREN */
            if (c == ' ') { c = prot_getc(backend_current->in); }
            else if (c == ')') break;
            else { c = EOF; break; }
        }

        /* if c == EOF we have either a protocol error or a situation
           we can't handle, and we should die. */
        if (c == ')') c = prot_getc(backend_current->in);
        if (c == '\r') c = prot_getc(backend_current->in);
        if (c != '\n') { c = EOF; break; }

        /* free q */
        free(q->idate);
        free(q->flags);
        free(q);
    }
    if (c != EOF) {
        char *appenduid, *b;
        int res;

        /* pushback the first character of the tag we're looking at */
        prot_ungetc(c, backend_current->in);

        /* nothing should be left in the linked list */
        assert(head->next == NULL);

        /* ok, finish the append; we need the UIDVALIDITY and UIDs
           to return as part of our COPYUID response code */
        prot_printf(s->out, "\r\n");

        /* should be looking at 'mytag' on 'backend_current',
           'tag' on 's' */
        pipe_until_tag(backend_current, mytag, 0);
        res = pipe_until_tag(s, tag, 0);

        if (res == PROXY_OK) {
            if (myrights & ACL_READ) {
                appenduid = strchr(s->last_result.s, '[');
                /* skip over APPENDUID */
                if (appenduid) {
                    appenduid += strlen("[appenduid ");
                    b = strchr(appenduid, ']');
                    if (b) *b = '\0';
                    prot_printf(imapd_out, "%s OK [COPYUID %s] %s\r\n", tag,
                                appenduid, error_message(IMAP_OK_COMPLETED));
                }
                else
                    prot_printf(imapd_out, "%s OK %s\r\n", tag, s->last_result.s);
            }
            else {
                prot_printf(imapd_out, "%s OK %s\r\n", tag,
                            error_message(IMAP_OK_COMPLETED));
            }
        } else {
            prot_printf(imapd_out, "%s %s", tag, s->last_result.s);
        }
    } else {
        /* abort the append */
        prot_printf(s->out, " {0+}\r\n\r\n");
        pipe_until_tag(backend_current, mytag, 0);
        pipe_until_tag(s, tag, 0);

        /* report failure */
        prot_printf(imapd_out, "%s NO inter-server COPY failed\r\n", tag);
    }

    /* free dynamic memory */
    while (head) {
        p = head;
        head = head->next;
        if (p->idate) free(p->idate);
        if (p->flags) free(p->flags);
        free(p);
    }
}
/* xxx  end of separate proxy-only code */

int proxy_catenate_url(struct backend *s, struct imapurl *url, FILE *f,
                       size_t maxsize, unsigned long *size, const char **parseerr)
{
    char mytag[128];
    int c, r = 0, found = 0;
    unsigned int uidvalidity = 0;

    *size = 0;
    *parseerr = NULL;

    /* select the mailbox (read-only) */
    proxy_gentag(mytag, sizeof(mytag));
    prot_printf(s->out, "%s Examine {" SIZE_T_FMT "+}\r\n%s\r\n",
                mytag, strlen(url->mailbox), url->mailbox);
    for (/* each examine response */;;) {
        /* read a line */
        c = prot_getc(s->in);
        if (c != '*') break;
        c = prot_getc(s->in);
        if (c != ' ') { /* protocol error */ c = EOF; break; }

        c = chomp(s->in, "ok [uidvalidity");
        if (c == EOF) {
            /* we don't care about this response */
            eatline(s->in, c);
            continue;
        }

        /* read uidvalidity */
        c = getuint32(s->in, &uidvalidity);
        if (c != ']') { c = EOF; break; }
        eatline(s->in, c); /* we don't care about the rest of the line */
    }
    if (c != EOF) {
        prot_ungetc(c, s->in);

        /* we should be looking at the tag now */
        eatline(s->in, c);
    }
    if (c == EOF) {
        /* uh oh, we're not happy */
        fatal("Lost connection to backend", EX_UNAVAILABLE);
    }

    if (url->uidvalidity && (uidvalidity != url->uidvalidity)) {
        *parseerr = "Uidvalidity of mailbox has changed";
        r = IMAP_BADURL;
        goto unselect;
    }

    /* fetch the bodypart */
    proxy_gentag(mytag, sizeof(mytag));
    prot_printf(s->out, "%s Uid Fetch %lu Body.Peek[%s]\r\n",
                mytag, url->uid, url->section ? url->section : "");
    for (/* each fetch response */;;) {
        unsigned int seqno;

      next_resp:
        /* read a line */
        c = prot_getc(s->in);
        if (c != '*') break;
        c = prot_getc(s->in);
        if (c != ' ') { /* protocol error */ c = EOF; break; }

        /* read seqno */
        c = getuint32(s->in, &seqno);
        if (seqno == 0 || c != ' ') {
            /* we suck and won't handle this case */
            c = EOF; break;
        }
        c = chomp(s->in, "fetch (");
        if (c == EOF) { /* not a fetch response */
            eatline(s->in, c);
            continue;
        }

        for (/* each fetch item */;;) {
            unsigned uid, sz = 0;

            switch (c) {
            case 'u': case 'U':
                c = chomp(s->in, "id");
                if (c != ' ') { c = EOF; }
                else {
                    c = getuint32(s->in, &uid);
                    if (uid != url->uid) {
                        /* not our response */
                        eatline(s->in, c);
                        goto next_resp;
                    }
                }
                break;

            case 'b': case 'B':
                c = chomp(s->in, "ody[");
                while (c != ']') c = prot_getc(s->in);
                if (c == ']') c = prot_getc(s->in);
                if (c == ' ') c = prot_getc(s->in);
                if (c == '{') {
                    c = getuint32(s->in, &sz);
                    if (c == '}') c = prot_getc(s->in);
                    if (c == '\r') c = prot_getc(s->in);
                    if (c != '\n') c = EOF;
                    if (sz > maxsize) {
                        r = IMAP_MESSAGE_TOO_LARGE;
                        eatline(s->in, c);
                        goto next_resp;
                    }
                }
                else if (c == 'n' || c == 'N') {
                    c = chomp(s->in, "il");
                    r = IMAP_BADURL;
                    *parseerr = "No such message part";
                }

                if (c != EOF) {
                    /* catenate to f */
                    found = 1;
                    *size = sz;

                    while (sz) {
                        char buf[2048];
                        int j = (sz > sizeof(buf) ? sizeof(buf) : sz);

                        j = prot_read(s->in, buf, j);
                        if(!j) break;
                        fwrite(buf, j, 1, f);
                        sz -= j;
                    }
                    c = prot_getc(s->in);
                }

                break; /* end of case */
            default:
                /* probably a FLAGS item */
                eatline(s->in, c);
                goto next_resp;
            }
            /* looking at either SP separating items or a RPAREN */
            if (c == ' ') { c = prot_getc(s->in); }
            else if (c == ')') break;
            else { c = EOF; break; }
        }

        /* if c == EOF we have either a protocol error or a situation
           we can't handle, and we should die. */
        if (c == ')') c = prot_getc(s->in);
        if (c == '\r') c = prot_getc(s->in);
        if (c != '\n') { c = EOF; break; }
    }
    if (c != EOF) {
        prot_ungetc(c, s->in);

        /* we should be looking at the tag now */
        eatline(s->in, c);
    }
    if (c == EOF) {
        /* uh oh, we're not happy */
        fatal("Lost connection to backend", EX_UNAVAILABLE);
    }

  unselect:
    /* unselect the mailbox */
    proxy_gentag(mytag, sizeof(mytag));
    prot_printf(s->out, "%s Unselect\r\n", mytag);
    for (/* each unselect response */;;) {
        /* read a line */
        c = prot_getc(s->in);
        if (c != '*') break;
        c = prot_getc(s->in);
        if (c != ' ') { /* protocol error */ c = EOF; break; }

        /* we don't care about this response */
        eatline(s->in, c);
    }
    if (c != EOF) {
        prot_ungetc(c, s->in);

        /* we should be looking at the tag now */
        eatline(s->in, c);
    }
    if (c == EOF) {
        /* uh oh, we're not happy */
        fatal("Lost connection to backend", EX_UNAVAILABLE);
    }

    if (!r && !found) {
        r = IMAP_BADURL;
        *parseerr = "No such message in mailbox";
    }

    return r;
}

/* Proxy GETMETADATA commands to backend */
int annotate_fetch_proxy(const char *server, const char *mbox_pat,
                         const strarray_t *entry_pat,
                         const strarray_t *attribute_pat)
{
    struct backend *be;
    int i, j;
    char mytag[128];

    assert(server && mbox_pat && entry_pat && attribute_pat);

    be = proxy_findserver(server, &imap_protocol,
                          proxy_userid, &backend_cached,
                          &backend_current, &backend_inbox, imapd_in);
    if (!be) return IMAP_SERVER_UNAVAILABLE;

    /* Send command to remote */
    proxy_gentag(mytag, sizeof(mytag));
    prot_printf(be->out, "%s GETANNOTATION \"%s\" (", mytag, mbox_pat);
    for (i = 0; i < entry_pat->count; i++) {
        const char *entry = strarray_nth(entry_pat, i);

        for (j = 0; j < attribute_pat->count; j++) {
            const char *scope, *attr = strarray_nth(attribute_pat, j);
            if (!strcmp(attr, "value.shared")) {
                scope = "/shared";
            }
            else if (!strcmp(attr, "value.priv")) {
                scope = "/private";
            }
            else {
                syslog(LOG_ERR, "won't get deprecated annotation attribute %s", attr);
                continue;
            }
            prot_printf(be->out, "%s%s%s", i ? " " : "", scope, entry);
        }
    }
    prot_printf(be->out, ")\r\n");
    prot_flush(be->out);

    /* Pipe the results.  Note that backend-current may also pipe us other
       messages. */
    pipe_until_tag(be, mytag, 0);

    return 0;
}

/* Proxy SETMETADATA commands to backend */
int annotate_store_proxy(const char *server, const char *mbox_pat,
                         struct entryattlist *entryatts)
{
    struct backend *be;
    struct entryattlist *e;
    struct attvaluelist *av;
    char mytag[128];
    struct buf entrybuf = BUF_INITIALIZER;


    assert(server && mbox_pat && entryatts);

    be = proxy_findserver(server, &imap_protocol,
                          proxy_userid, &backend_cached,
                          &backend_current, &backend_inbox, imapd_in);
    if (!be) return IMAP_SERVER_UNAVAILABLE;

    /* Send command to remote */
    proxy_gentag(mytag, sizeof(mytag));
    prot_printf(be->out, "%s SETMETADATA \"%s\" (", mytag, mbox_pat);
    for (e = entryatts; e; e = e->next) {
        for (av = e->attvalues; av; av = av->next) {
            assert(av->attrib);
            if (!strcmp(av->attrib, "value.shared")) {
                buf_setcstr(&entrybuf, "/shared");
            }
            else if (!strcmp(av->attrib, "value.priv")) {
                buf_setcstr(&entrybuf, "/private");
            }
            else {
                syslog(LOG_ERR,
                       "won't proxy annotation with deprecated attribute %s",
                       av->attrib);
                buf_free(&entrybuf);
                return IMAP_INTERNAL;
            }

            buf_appendcstr(&entrybuf, e->entry);

            /* Print the entry-value pair */
            prot_printamap(be->out, entrybuf.s, entrybuf.len);
            prot_putc(' ', be->out);
            prot_printamap(be->out, av->value.s, av->value.len);

            if (av->next) prot_putc(' ', be->out);
        }
        if (e->next) prot_putc(' ', be->out);
    }
    prot_printf(be->out, ")\r\n");
    prot_flush(be->out);

    /* Pipe the results.  Note that backend-current may also pipe us other
       messages. */
    pipe_until_tag(be, mytag, 0);

    buf_free(&entrybuf);

    return 0;
}


char *find_free_server(void)
{
    const char *servers = config_getstring(IMAPOPT_SERVERLIST);
    char *server = NULL;

    if (servers) {
        if (!server_parts) {
            server_parts = xzmalloc(sizeof(partlist_t));

            partlist_initialize(
                    server_parts,
                    proxy_part_filldata,
                    NULL,
                    servers,
                    NULL,
                    partlist_getmode(config_getstring(IMAPOPT_SERVERLIST_SELECT_MODE)),
                    config_getint(IMAPOPT_SERVERLIST_SELECT_SOFT_USAGE_LIMIT),
                    config_getint(IMAPOPT_SERVERLIST_SELECT_USAGE_REINIT)
                );

        }

        server = (char *)partlist_select_value(server_parts);
    }

    return server;
}


static void proxy_part_filldata(partlist_t *part_list, int idx)
{
    char mytag[128];
    struct backend *be;
    partitem_t *item = &part_list->items[idx];

    item->id = 0;
    item->available = 0;
    item->total = 0;
    item->quota = 0.;

    syslog(LOG_DEBUG, "checking free space on server '%s'", item->value);

    /* connect to server */
    be = proxy_findserver(item->value, &imap_protocol,
            proxy_userid, &backend_cached,
            &backend_current, &backend_inbox, imapd_in);

    if (be) {
        uint64_t server_available = 0;
        uint64_t server_total = 0;
        const char *annot =
            (part_list->mode == PART_SELECT_MODE_FREESPACE_MOST) ?
            "freespace/total" : "freespace/percent/most";
        struct buf cmd = BUF_INITIALIZER;
        int c;

        /* fetch annotation from remote */
        proxy_gentag(mytag, sizeof(mytag));
        if (CAPA(be, CAPA_METADATA)) {
            buf_printf(&cmd, "METADATA \"\" (\"/shared" IMAP_ANNOT_NS "%s\"",
                       annot);
        }
        else {
            buf_printf(&cmd, "ANNOTATION \"\" \"" IMAP_ANNOT_NS "%s\" "
                       "(\"value.shared\"", annot);
        }
        prot_printf(be->out, "%s GET%s)\r\n", mytag, buf_cstring(&cmd));
        prot_flush(be->out);

        for (/* each annotation response */;;) {
            /* read a line */
            c = prot_getc(be->in);
            if (c != '*') break;
            c = prot_getc(be->in);
            if (c != ' ') { /* protocol error */ c = EOF; break; }

            c = chomp(be->in, buf_cstring(&cmd));
            if (c == ' ') c = prot_getc(be->in);
            if ((c == EOF) || (c != '\"')) {
                /* we don't care about this response */
                eatline(be->in, c);
                continue;
            }

            /* read available */
            c = getuint64(be->in, &server_available);
            if (c != ';') { c = EOF; break; }

            /* read total */
            c = getuint64(be->in, &server_total);
            if (c != '\"') { c = EOF; break; }
            eatline(be->in, c); /* we don't care about the rest of the line */
        }
        buf_free(&cmd);
        if (c != EOF) {
            prot_ungetc(c, be->in);

            /* we should be looking at the tag now */
            eatline(be->in, c);
        }
        if (c == EOF) {
            /* uh oh, we're not happy */
            fatal("Lost connection to backend", EX_UNAVAILABLE);
        }

        /* unique id */
        item->id = idx;
        item->available = server_available;
        item->total = server_total;
    }
}

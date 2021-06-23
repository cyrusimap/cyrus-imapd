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
 */

#include <config.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sysexits.h>
#include <syslog.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <stdbool.h>
#include <errno.h>

#include <sasl/sasl.h>

#ifdef HAVE_SSL
#include <openssl/hmac.h>
#include <openssl/rand.h>
#endif /* HAVE_SSL */

#include "acl.h"
#include "annotate.h"
#include "append.h"
#include "auth.h"
#ifdef USE_AUTOCREATE
#include "autocreate.h"
#endif // USE_AUTOCREATE
#include "assert.h"
#include "backend.h"
#include "bsearch.h"
#include "bufarray.h"
#include "charset.h"
#include "dlist.h"
#include "idle.h"
#include "global.h"
#include "times.h"
#include "proxy.h"
#include "imap_proxy.h"
#include "imapd.h"
#include "imapurl.h"
#include "imparse.h"
#include "index.h"
#include "mailbox.h"
#include "message.h"
#include "mboxevent.h"
#include "mboxkey.h"
#include "mboxlist.h"
#include "mboxname.h"
#include "mbdump.h"
#include "mupdate-client.h"
#include "partlist.h"
#include "proc.h"
#include "prometheus.h"
#include "quota.h"
#include "seen.h"
#include "statuscache.h"
#include "sync_log.h"
#include "sync_support.h"
#include "telemetry.h"
#include "tls.h"
#include "user.h"
#include "userdeny.h"
#include "util.h"
#include "version.h"
#include "xmalloc.h"
#include "xstrlcat.h"
#include "xstrlcpy.h"
#include "ptrarray.h"
#include "xstats.h"

/* generated headers are not necessarily in current directory */
#include "imap/imap_err.h"

#include "iostat.h"

extern int optind;
extern char *optarg;

/* global state */
const int config_need_data = CONFIG_NEED_PARTITION_DATA;

static int imaps = 0;
static sasl_ssf_t extprops_ssf = 0;
static int nosaslpasswdcheck = 0;
static int apns_enabled = 0;
static size_t maxsize = 0;

/* PROXY STUFF */
/* we want a list of our outgoing connections here and which one we're
   currently piping */

static const int ultraparanoid = 1; /* should we kick after every operation? */
unsigned int proxy_cmdcnt;

static int referral_kick = 0; /* kick after next command received, for
                                 referrals that are likely to change the
                                 mailbox list */

/* global conversations database holder to avoid re-opening during
 * status command or list responses */
struct conversations_state *global_conversations = NULL;

/* all subscription commands go to the backend server containing the
   user's inbox */
struct backend *backend_inbox = NULL;

/* the current server most commands go to */
struct backend *backend_current = NULL;

/* our cached connections */
struct backend **backend_cached = NULL;

/* cached connection to mupdate master (for multiple XFER and MUPDATEPUSH) */
static mupdate_handle *mupdate_h = NULL;

/* are we doing virtdomains with multiple IPs? */
static int disable_referrals;

/* has the client issued an RLIST, RLSUB, or LIST (REMOTE)? */
static int supports_referrals;

/* end PROXY STUFF */

/* per-user/session state */
static int imapd_timeout;
struct protstream *imapd_out = NULL;
struct protstream *imapd_in = NULL;
static struct protgroup *protin = NULL;
static const char *imapd_clienthost = "[local]";
static int imapd_logfd = -1;
char *imapd_userid = NULL, *proxy_userid = NULL;
static char *imapd_magicplus = NULL;
struct auth_state *imapd_authstate = 0;
static int imapd_userisadmin = 0;
static int imapd_userisproxyadmin = 0;
static sasl_conn_t *imapd_saslconn; /* the sasl connection context */
static int imapd_starttls_done = 0; /* have we done a successful starttls? */
static int imapd_tls_required = 0; /* is tls required? */
static void *imapd_tls_comp = NULL; /* TLS compression method, if any */
static int imapd_compress_done = 0; /* have we done a successful compress? */
static const char *plaintextloginalert = NULL;
static int ignorequota = 0;

#define QUIRK_SEARCHFUZZY (1<<0)
static struct id_data {
    struct attvaluelist *params;
    int did_id;
    int quirks;
} imapd_id;

#ifdef HAVE_SSL
/* our tls connection, if any */
static SSL *tls_conn = NULL;
#endif /* HAVE_SSL */

/* stage(s) for APPEND */
struct appendstage {
    struct stagemsg *stage;
    FILE *f;
    strarray_t flags;
    time_t internaldate;
    int binary;
    struct entryattlist *annotations;
};
static ptrarray_t stages = PTRARRAY_INITIALIZER;

/* the sasl proxy policy context */
static struct proxy_context imapd_proxyctx = {
    1, 1, &imapd_authstate, &imapd_userisadmin, &imapd_userisproxyadmin
};

/* current sub-user state */
static struct index_state *imapd_index;

/* current namespace */
struct namespace imapd_namespace;

/* track if we're idling */
static int idling = 0;

const struct mbox_name_attribute mbox_name_attributes[] = {
    /* from RFC 3501 */
    { MBOX_ATTRIBUTE_NOINFERIORS,   "\\Noinferiors"   },
    { MBOX_ATTRIBUTE_NOSELECT,      "\\Noselect"      },
    { MBOX_ATTRIBUTE_MARKED,        "\\Marked"        },
    { MBOX_ATTRIBUTE_UNMARKED,      "\\Unmarked"      },

    /* from RFC 5258 */
    { MBOX_ATTRIBUTE_NONEXISTENT,   "\\NonExistent"   },
    { MBOX_ATTRIBUTE_SUBSCRIBED,    "\\Subscribed"    },
    { MBOX_ATTRIBUTE_REMOTE,        "\\Remote"        },
    { MBOX_ATTRIBUTE_HASCHILDREN,   "\\HasChildren"   },
    { MBOX_ATTRIBUTE_HASNOCHILDREN, "\\HasNoChildren" },

    { 0, NULL }
};

/*
 * These bitmasks define how List selection options can be combined:
 * list_select_mod_opts may only be used if at least one list_select_base_opt
 * is also present.
 * For example, (RECURSIVEMATCH) and (RECURSIVEMATCH REMOTE) are invalid, but
 * (RECURSIVEMATCH SUBSCRIBED) is ok.
 */
static const int list_select_base_opts = LIST_SEL_SUBSCRIBED;
static const int list_select_mod_opts  = LIST_SEL_RECURSIVEMATCH;

/* structure that list_data passes its callbacks */
struct list_rock {
    struct listargs *listargs;
    strarray_t *subs;
    char *last_name;
    mbentry_t *last_mbentry;
    uint32_t last_attributes;
    int last_category;
    hash_table server_table;    /* for proxying */
};

/* Information about one mailbox name that LIST returns */
struct list_entry {
    char *extname;
    mbentry_t *mbentry;
    uint32_t attributes; /* bitmap of MBOX_ATTRIBUTE_* */
};

/* structure that list_data_recursivematch passes its callbacks */
struct list_rock_recursivematch {
    struct listargs *listargs;
    struct hash_table table;  /* maps mailbox names to list_entries */
    int count;                /* # of entries in table */
    struct list_entry *array;
};

/* CAPABILITIES are defined here, not including TLS/SASL ones,
   and those that are configurable */

enum {
    CAPA_PREAUTH = 0x1,
    CAPA_POSTAUTH = 0x2
};

struct capa_struct {
    const char *str;
    int mask;
};

static struct capa_struct base_capabilities[] = {
/* pre-auth capabilities */
    { "IMAP4rev1",             3 },
    { "LITERAL+",              3 }, /* This is in RFC 7888, but likely the implementation is for RFC 2088 */
    /* LITERAL- (RFC 7888) sent instead of LITERAL+ when literalminus=yes */
    { "ID",                    3 }, /* RFC 2971 */
    { "ENABLE",                3 }, /* RFC 5161 */
/* post-auth capabilities
 * this is kept sorted, so that it can be easily compared to https://www.iana.org/assignments/imap-capabilities/imap-capabilities.xhtml */
    { "ACL",                   2 }, /* RFC 4314 */
    { "ANNOTATE-EXPERIMENT-1", 2 }, /* RFC 5257 */
    /* APPENDLIMIT=     RFC 7889 is announced in capa_response() */
    /* AUTH=            RFC 3501 is announced conditionally in capa_response() */
    { "BINARY",                2 }, /* RFC 3516 */
    { "CATENATE",              2 }, /* RFC 4469 */
    { "CHILDREN",              2 }, /* RFC 3348 */
    /* COMPRESS=DEFLATE RFC 4498 is announced conditionally in capa_response() */
    { "CONDSTORE",             2 }, /* RFC 7162, but the implementation is likely from RFC 4551 */
    /* CONTEXT=SEARCH   RFC 5267 is not implemented.  From that RFC only ESORT is ready */
    /* CONTEXT=SORT     RFC 5267 is not implemented.  From that RFC only ESORT is ready */
    /* CONVERT          RFC 5259 is not implemented */
    { "CREATE-SPECIAL-USE",    2 }, /* RFC 6154 */
    { "ESEARCH",               2 }, /* RFC 4731 */
    { "ESORT",                 2 }, /* RFC 5267 */
    /* FILTERS          RFC 5466 is not implemented */
    /* I18NLEVEL=1      RFC 5255 is not implemented */
    /* I18NLEVEL=2      RFC 5255 is not implemented */
    /* IDLE             RFC 2177 is announced conditionally in capa_response() */
    /* IMAPSIEVE=       RFC 6785 is not implemented */
    /* LANGUAGE         RFC 5255 is not implemented */
    { "LIST-EXTENDED",         2 }, /* RFC 5258 */
    { "LIST-MYRIGHTS",         2 }, /* RFC 8440 */
    { "LIST-STATUS",           2 }, /* RFC 5819 */
    /* LOGIN-REFERRALS  RFC 2221 is not implemented */
    /* LOGINDISABLED    RFC 2595/RFC 3591 is announced conditionally in capa_response() */
    { "MAILBOX-REFERRALS",     2 }, /* RFC 2193 */
    { "METADATA",              2 }, /* RFC 5464 */
    /*METADATA-SERVER   RFC 5464.  Sending METADATA implies METADATA-SERVER */
    { "MOVE",                  2 }, /* RFC 6851 */
    { "MULTIAPPEND",           2 }, /* RFC 3502 */
    /* MULTISEARCH      RFC 7377 is not implemented */
    { "NAMESPACE",             2 }, /* RFC 2342 */
    /* NOTIFY           RFC 5465 is not implemented */
    { "OBJECTID",              2 }, /* RFC 8474 */
    { "PREVIEW",               2 }, /* RFC 8970 */
    { "QRESYNC",               2 }, /* RFC 7162, but the implementation is likely from RFC 4551 and RFC 5162 */
    { "QUOTA",                 2 }, /* RFC 2087 */
    /* REPLACE          RFC 8508 is not implemented */
    { "RIGHTS=kxten",          2 }, /* RFC 4314 */
    /* SASL-IR          RFC 4959 is announced in capa_response() */
    { "SAVEDATE",              2 }, /* RFC 8514 */
    { "SEARCH=FUZZY",          2 }, /* RFC 6203 */
    /* SEARCHRES        RFC 5182 is not implemented */
    { "SORT",                  2 }, /* RFC 5256 */
    { "SORT=DISPLAY",          2 }, /* RFC 5957 */
    { "SPECIAL-USE",           2 }, /* RFC 6154 */
    /* STARTTLS         RFC 2595, RFC 3501 is announced in capa_response() */
    { "STATUS=SIZE",           2 }, /* RFC 8438 */
    { "THREAD=ORDEREDSUBJECT", 2 }, /* RFC 5256 */
    { "THREAD=REFERENCES",     2 }, /* RFC 5256 */
    { "UIDPLUS",               2 }, /* RFC 4315 */
    /* UNAUTHENTICATE   RFC 8437 is implemented */
    { "UNSELECT",              2 }, /* RFC 3691 */
    /* URL-PARTIAL      RFC 5550 is not implemented */
#ifdef HAVE_SSL
    { "URLAUTH",               2 }, /* RFC 4467 */
    { "URLAUTH=BINARY",        2 }, /* RFC 5524 */
#endif
    /* UTF8=ACCEPT      RFC 6855 is not implemented */
    /* UTF8=ONLY        RFC 6855 is not implemented */
    { "WITHIN",                2 }, /* RFC 5032 */
    /* drafts, non-standard */
    { "ANNOTATEMORE",          2 }, /* legacy SETANNOTATION/GETANNOTATION commands */
    { "DIGEST=SHA1",           2 }, /* Cyrus custom */
    { "LIST-METADATA",         2 }, /* not standard */
    { "NO_ATOMIC_RENAME",      2 },
    { "SCAN",                  2 },
    { "SORT=MODSEQ",           2 },
    { "SORT=UID",              2 }, /* not standard */
    { "THREAD=REFS",           2 }, /* draft-ietf-morg-inthread */
    { "X-CREATEDMODSEQ",       2 }, /* Cyrus custom */
    { "X-REPLICATION",         2 }, /* Cyrus custom */
    { "XLIST",                 2 }, /* not standard */
    { "XMOVE",                 2 }, /* not standard */

/* keep this to mark the end of the list */
    { 0,                       0 }
};


static void motd_file(void);
void shut_down(int code);
void fatal(const char *s, int code);

static void cmdloop(void);
static void cmd_login(char *tag, char *user);
static void cmd_authenticate(char *tag, char *authtype, char *resp);
static void cmd_unauthenticate(char *tag);
static void cmd_noop(char *tag, char *cmd);
static void capa_response(int flags);
static void cmd_capability(char *tag);
static void cmd_append(char *tag, char *name, const char *cur_name);
static void cmd_select(char *tag, char *cmd, char *name);
static void cmd_close(char *tag, char *cmd);
static int parse_fetch_args(const char *tag, const char *cmd,
                            int allow_vanished,
                            struct fetchargs *fa);
static void cmd_fetch(char *tag, char *sequence, int usinguid);
static void cmd_store(char *tag, char *sequence, int usinguid);
static void cmd_search(char *tag, int usinguid);
static void cmd_sort(char *tag, int usinguid);
static void cmd_thread(char *tag, int usinguid);
static void cmd_copy(char *tag, char *sequence, char *name, int usinguid, int ismove);
static void cmd_expunge(char *tag, char *sequence);
static void cmd_create(char *tag, char *name, struct dlist *extargs, int localonly);
static void cmd_delete(char *tag, char *name, int localonly, int force);
static void cmd_dump(char *tag, char *name, int uid_start);
static void cmd_undump(char *tag, char *name);
static void cmd_xfer(const char *tag, const char *name,
                     const char *toserver, const char *topart);
static void cmd_rename(char *tag, char *oldname, char *newname, char *partition);
static void cmd_reconstruct(const char *tag, const char *name, int recursive);
static void getlistargs(char *tag, struct listargs *listargs);
static void cmd_list(char *tag, struct listargs *listargs);
static void cmd_changesub(char *tag, char *namespace, char *name, int add);
static void cmd_getacl(const char *tag, const char *name);
static void cmd_listrights(char *tag, char *name, char *identifier);
static void cmd_myrights(const char *tag, const char *name);
static void cmd_setacl(char *tag, const char *name,
                const char *identifier, const char *rights);
static void cmd_getquota(const char *tag, const char *name);
static void cmd_getquotaroot(const char *tag, const char *name);
static void cmd_setquota(const char *tag, const char *quotaroot);
static void cmd_status(char *tag, char *name);
static void cmd_namespace(char* tag);
static void cmd_mupdatepush(char *tag, char *name);
static void cmd_id(char* tag);

static void cmd_idle(char* tag);

static void cmd_starttls(char *tag, int imaps);

static void cmd_xconvsort(char *tag, int updates);
static void cmd_xconvmultisort(char *tag);
static void cmd_xconvmeta(const char *tag);
static void cmd_xconvfetch(const char *tag);
static int do_xconvfetch(struct dlist *cidlist,
                         modseq_t ifchangedsince,
                         struct fetchargs *fetchargs);
static void cmd_xsnippets(char *tag);
static void cmd_xstats(char *tag);

static void cmd_xapplepushservice(const char *tag,
                                  struct applepushserviceargs *applepushserviceargs);
static void cmd_xbackup(const char *tag, const char *mailbox,
                        const char *channel);

#ifdef HAVE_SSL
static void cmd_urlfetch(char *tag);
static void cmd_genurlauth(char *tag);
static void cmd_resetkey(char *tag, char *mailbox, char *mechanism);
#endif

#ifdef HAVE_ZLIB
static void cmd_compress(char *tag, char *alg);
#endif

static void cmd_getannotation(const char* tag, char *mboxpat);
static void cmd_getmetadata(const char* tag);
static void cmd_setannotation(const char* tag, char *mboxpat);
static void cmd_setmetadata(const char* tag, char *mboxpat);
static void cmd_xrunannotator(const char *tag, const char *sequence,
                              int usinguid);
static void cmd_xwarmup(const char *tag);

static void cmd_enable(char* tag);

static void cmd_syncget(const char *tag, struct dlist *kl);
static void cmd_syncapply(const char *tag, struct dlist *kl,
                      struct sync_reserve_list *reserve_list);
static void cmd_syncrestart(const char *tag, struct sync_reserve_list **reserve_listp,
                       int realloc);
static void cmd_syncrestore(const char *tag, struct dlist *kin,
                            struct sync_reserve_list *reserve_list);
static void cmd_xkillmy(const char *tag, const char *cmdname);
static void cmd_xforever(const char *tag);
static void cmd_xmeid(const char *tag, const char *id);

static int parsecreateargs(struct dlist **extargs);

static int parse_annotate_fetch_data(const char *tag,
                                     int permessage_flag,
                                     strarray_t *entries,
                                     strarray_t *attribs);
static int parse_metadata_string_or_list(const char *tag,
                                         strarray_t *sa,
                                         int *is_list);
static int parse_annotate_store_data(const char *tag,
                                     int permessage_flag,
                                     struct entryattlist **entryatts);
static int parse_metadata_store_data(const char *tag,
                                     struct entryattlist **entryatts);

static int getlistselopts(char *tag, struct listargs *args);
static int getlistretopts(char *tag, struct listargs *args);

static int get_snippetargs(struct snippetargs **sap);
static void free_snippetargs(struct snippetargs **sap);
static int getsortcriteria(char *tag, struct sortcrit **sortcrit);
static int getdatetime(time_t *date);
static int parse_windowargs(const char *tag, struct windowargs **, int);
static void free_windowargs(struct windowargs *wa);

static void appendfieldlist(struct fieldlist **l, char *section,
                     strarray_t *fields, char *trail,
                     void *d, size_t size);
static void freefieldlist(struct fieldlist *l);
void freestrlist(struct strlist *l);

static int set_haschildren(const mbentry_t *entry, void *rock);
static char *canonical_list_pattern(const char *reference,
                                    const char *pattern);
static void canonical_list_patterns(const char *reference,
                                    strarray_t *patterns);
static int list_cb(struct findall_data *data, void *rock);
static int subscribed_cb(struct findall_data *data, void *rock);
static void list_data(struct listargs *listargs);
static int list_data_remote(struct backend *be, char *tag,
                            struct listargs *listargs, strarray_t *subs);

static void clear_id();

extern int saslserver(sasl_conn_t *conn, const char *mech,
                      const char *init_resp, const char *resp_prefix,
                      const char *continuation, const char *empty_resp,
                      struct protstream *pin, struct protstream *pout,
                      int *sasl_result, char **success_data);

/* Enable the resetting of a sasl_conn_t */
static int reset_saslconn(sasl_conn_t **conn);

static struct saslprops_t saslprops = SASLPROPS_INITIALIZER;

static int imapd_canon_user(sasl_conn_t *conn, void *context,
                            const char *user, unsigned ulen,
                            unsigned flags, const char *user_realm,
                            char *out, unsigned out_max, unsigned *out_ulen)
{
    char userbuf[MAX_MAILBOX_BUFFER], *p;
    size_t n;
    int r;

    if (!ulen) ulen = strlen(user);

    if (config_getswitch(IMAPOPT_IMAPMAGICPLUS)) {
        /* make a working copy of the auth[z]id */
        if (ulen >= MAX_MAILBOX_BUFFER) {
            sasl_seterror(conn, 0, "buffer overflow while canonicalizing");
            return SASL_BUFOVER;
        }
        memcpy(userbuf, user, ulen);
        userbuf[ulen] = '\0';
        user = userbuf;

        /* See if we're using the magic plus */
        if ((p = strchr(userbuf, '+'))) {
            n = config_virtdomains ? strcspn(p, "@") : strlen(p);

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
    char userbuf[MAX_MAILBOX_BUFFER];

    if (config_getswitch(IMAPOPT_IMAPMAGICPLUS)) {
        size_t n;
        char *p;

        /* make a working copy of the authzid */
        if (!rlen) rlen = strlen(requested_user);
        if (rlen >= MAX_MAILBOX_BUFFER) {
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

static int imapd_sasl_log(void *context __attribute__((unused)),
                          int level, const char *message)
{
    int syslog_level = LOG_INFO;

    switch (level) {
    case SASL_LOG_ERR:
    case SASL_LOG_FAIL:
        syslog_level = LOG_ERR;
        break;
    case SASL_LOG_WARN:
        syslog_level = LOG_WARNING;
        break;
    case SASL_LOG_DEBUG:
    case SASL_LOG_TRACE:
    case SASL_LOG_PASS:
        syslog_level = LOG_DEBUG;
        break;
    }

    syslog(syslog_level, "SASL %s", message);
    return SASL_OK;
}

static const struct sasl_callback mysasl_cb[] = {
    { SASL_CB_GETOPT, (mysasl_cb_ft *) &mysasl_config, NULL },
    { SASL_CB_PROXY_POLICY, (mysasl_cb_ft *) &imapd_proxy_policy, (void*) &imapd_proxyctx },
    { SASL_CB_CANON_USER, (mysasl_cb_ft *) &imapd_canon_user, (void*) &disable_referrals },
    { SASL_CB_LOG, (mysasl_cb_ft *) &imapd_sasl_log, NULL },
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

    free(imapurl.freeme);
}

/* wrapper for mboxlist_lookup that will force a referral if we are remote
 * returns IMAP_SERVER_UNAVAILABLE if we don't have a place to send the client
 * (that'd be a bug).
 * returns IMAP_MAILBOX_MOVED if we referred the client */
/* ext_name is the external name of the mailbox */
/* you can avoid referring the client by setting tag or ext_name to NULL. */
struct mbox_refer_rock {
    const char *tag;
    const char *ext_name;
};

static int mbox_refer_proc(mbentry_t *mbentry, void *rock)
{
    struct mbox_refer_rock *mrock = (struct mbox_refer_rock *) rock;
    int r;

    /* do we have rights on the mailbox? */
    if (!imapd_userisadmin &&
        (!mbentry->acl ||
         !(cyrus_acl_myrights(imapd_authstate, mbentry->acl) & ACL_LOOKUP))) {
        r = IMAP_MAILBOX_NONEXISTENT;
    } else if (mrock->tag && mrock->ext_name && mbentry->server) {
        imapd_refer(mrock->tag, mbentry->server, mrock->ext_name);
        r = IMAP_MAILBOX_MOVED;
    } else if (config_mupdate_server) {
        r = IMAP_SERVER_UNAVAILABLE;
    } else {
        r = IMAP_MAILBOX_NOTSUPPORTED;
    }

    return r;
}

static int mlookup(const char *tag, const char *ext_name,
                   const char *name, mbentry_t **mbentryp)
{
    mbentry_t *mbentry = NULL;
    struct mbox_refer_rock rock = { tag, ext_name };
    struct mbox_refer refer = { &mbox_refer_proc, &rock };

    int r = proxy_mlookup(name, &mbentry, NULL, &refer);

    if (!r && mbentryp) *mbentryp = mbentry;
    else mboxlist_entry_free(&mbentry); /* we don't actually want it! */

    return r;
}

static void imapd_reset(void)
{
    int i;
    int bytes_in = 0;
    int bytes_out = 0;

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
    if (mupdate_h) mupdate_disconnect(&mupdate_h);
    mupdate_h = NULL;
    proxy_cmdcnt = 0;
    disable_referrals = 0;
    supports_referrals = 0;

    index_text_extractor_destroy();

    if (imapd_index) {
        if (config_getswitch(IMAPOPT_AUTOEXPUNGE) && index_hasrights(imapd_index, ACL_EXPUNGE))
            index_expunge(imapd_index, NULL, 1);
        index_close(&imapd_index);
    }

    if (imapd_in) {
        /* Flush the incoming buffer */
        prot_NONBLOCK(imapd_in);
        prot_fill(imapd_in);
        bytes_in = prot_bytes_in(imapd_in);
        prot_free(imapd_in);
    }

    if (imapd_out) {
        /* Flush the outgoing buffer */
        prot_flush(imapd_out);
        bytes_out = prot_bytes_out(imapd_out);
        prot_free(imapd_out);
    }

    if (config_auditlog)
        syslog(LOG_NOTICE, "auditlog: traffic sessionid=<%s> bytes_in=<%d> bytes_out=<%d>",
                           session_id(), bytes_in, bytes_out);

    imapd_in = imapd_out = NULL;

    if (protin) protgroup_reset(protin);

#ifdef HAVE_SSL
    if (tls_conn) {
        if (tls_reset_servertls(&tls_conn) == -1) {
            fatal("tls_reset() failed", EX_TEMPFAIL);
        }
        tls_conn = NULL;
    }
#endif

    cyrus_reset_stdio();

    imapd_clienthost = "[local]";
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
    client_capa = 0;
    if (imapd_saslconn) {
        sasl_dispose(&imapd_saslconn);
        free(imapd_saslconn);
        imapd_saslconn = NULL;
    }
    imapd_compress_done = 0;
    imapd_tls_comp = NULL;
    imapd_starttls_done = 0;
    plaintextloginalert = NULL;

    saslprops_reset(&saslprops);

    clear_id();
}

/*
 * run once when process is forked;
 * MUST NOT exit directly; must return with non-zero error code
 */
int service_init(int argc, char **argv, char **envp)
{
    int opt, events;

    if (geteuid() == 0) fatal("must run as the Cyrus user", EX_USAGE);
    setproctitle_init(argc, argv, envp);

    /* set signal handlers */
    signals_set_shutdown(&shut_down);
    signal(SIGPIPE, SIG_IGN);

    /* load the SASL plugins */
    global_sasl_init(1, 1, mysasl_cb);

    /* setup for sending IMAP IDLE notifications */
    idle_init();

    /* setup for mailbox event notifications */
    events = mboxevent_init();
    apns_enabled =
      (events & EVENT_APPLEPUSHSERVICE) && config_getstring(IMAPOPT_APS_TOPIC);

    while ((opt = getopt(argc, argv, "Np:sq")) != EOF) {
        switch (opt) {
        case 's': /* imaps (do starttls right away) */
            imaps = 1;
            if (!tls_enabled()) {
                syslog(LOG_ERR, "imaps: required OpenSSL options not present");
                fatal("imaps: required OpenSSL options not present",
                      EX_CONFIG);
            }
            break;
        case 'p': /* external protection */
            extprops_ssf = atoi(optarg);
            break;
        case 'N': /* bypass SASL password check.  Not recommended unless
                   * you know what you're doing! */
            nosaslpasswdcheck = 1;
            break;
        case 'q': /* don't enforce quotas */
            ignorequota = 1;
            break;
        default:
            break;
        }
    }

    /* Initialize the annotatemore extension */
    if (config_mupdate_server)
        annotate_init(annotate_fetch_proxy, annotate_store_proxy);
    else
        annotate_init(NULL, NULL);
    annotatemore_open();

    /* Create a protgroup for input from the client and selected backend */
    protin = protgroup_new(2);

    prometheus_increment(CYRUS_IMAP_READY_LISTENERS);

    maxsize = config_getint(IMAPOPT_MAXMESSAGESIZE) * 1024;
    if (!maxsize) maxsize = UINT32_MAX;

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
    sasl_security_properties_t *secprops = NULL;
    const char *localip, *remoteip;
    struct mboxevent *mboxevent = NULL;
    struct io_count *io_count_start = NULL;
    struct io_count *io_count_stop = NULL;

    /* fatal/shut_down will adjust these, so we need to set them early */
    prometheus_decrement(CYRUS_IMAP_READY_LISTENERS);
    prometheus_increment(CYRUS_IMAP_ACTIVE_CONNECTIONS);

    if (config_iolog) {
        io_count_start = xmalloc (sizeof (struct io_count));
        io_count_stop = xmalloc (sizeof (struct io_count));
        read_io_count(io_count_start);
    }

    session_new_id();

    signals_poll();

#ifdef ID_SAVE_CMDLINE
    /* get command line args for use in ID before getopt mangles them */
    id_getcmdline(argc, argv);
#endif

    imapd_in = prot_new(0, 0);
    imapd_out = prot_new(1, 1);
    protgroup_insert(protin, imapd_in);

    /* Find out name of client host */
    imapd_clienthost = get_clienthost(0, &localip, &remoteip);

    if (localip && remoteip) {
        buf_setcstr(&saslprops.ipremoteport, remoteip);
        buf_setcstr(&saslprops.iplocalport, localip);
    }

    /* create the SASL connection */
    if (sasl_server_new("imap", config_servername, NULL,
                        buf_cstringnull_ifempty(&saslprops.iplocalport),
                        buf_cstringnull_ifempty(&saslprops.ipremoteport),
                        NULL, 0, &imapd_saslconn) != SASL_OK) {
        fatal("SASL failed initializing: sasl_server_new()", EX_TEMPFAIL);
    }

    secprops = mysasl_secprops(0);
    if (sasl_setprop(imapd_saslconn, SASL_SEC_PROPS, secprops) != SASL_OK)
        fatal("Failed to set SASL property", EX_TEMPFAIL);
    if (sasl_setprop(imapd_saslconn, SASL_SSF_EXTERNAL, &extprops_ssf) != SASL_OK)
        fatal("Failed to set SASL property", EX_TEMPFAIL);

    imapd_tls_required = config_getswitch(IMAPOPT_TLS_REQUIRED);

    proc_register(config_ident, imapd_clienthost, NULL, NULL, NULL);

    /* Set inactivity timer */
    imapd_timeout = config_getduration(IMAPOPT_TIMEOUT, 'm');
    if (imapd_timeout < 30 * 60) imapd_timeout = 30 * 60;
    prot_settimeout(imapd_in, imapd_timeout);
    prot_setflushonread(imapd_in, imapd_out);

    /* we were connected on imaps port so we should do
       TLS negotiation immediately */
    if (imaps == 1) cmd_starttls(NULL, 1);

    /* count the connection, now that it's established */
    prometheus_increment(CYRUS_IMAP_CONNECTIONS_TOTAL);

    /* Setup a default namespace until replaced after authentication. */
    mboxname_init_namespace(&imapd_namespace, /*isadmin*/1);
    mboxevent_setnamespace(&imapd_namespace);

    index_text_extractor_init(imapd_in);

    cmdloop();

    /* LOGOUT executed */
    prot_flush(imapd_out);
    prometheus_decrement(CYRUS_IMAP_ACTIVE_CONNECTIONS);

    /* send a Logout event notification */
    if ((mboxevent = mboxevent_new(EVENT_LOGOUT))) {
        mboxevent_set_access(mboxevent,
                             buf_cstringnull_ifempty(&saslprops.iplocalport),
                             buf_cstringnull_ifempty(&saslprops.ipremoteport),
                             imapd_userid, NULL, 1);

        mboxevent_notify(&mboxevent);
        mboxevent_free(&mboxevent);
    }

    /* cleanup */
    imapd_reset();

    if (config_iolog) {
        read_io_count(io_count_stop);
        syslog(LOG_INFO,
               "IMAP session stats : I/O read : %d bytes : I/O write : %d bytes",
                io_count_stop->io_read_count - io_count_start->io_read_count,
                io_count_stop->io_write_count - io_count_start->io_write_count);
        free (io_count_start);
        free (io_count_stop);
    }

    prometheus_increment(CYRUS_IMAP_READY_LISTENERS);
    return 0;
}

/* Called by service API to shut down the service */
void service_abort(int error)
{
    shut_down(error);
}

/*
 * Try to find a motd file; if found spit out message as an [ALERT]
 */
static void motd_file(void)
{
    char *filename = NULL;
    int fd = -1;
    struct protstream *motd_in = NULL;
    char buf[MAX_MAILBOX_PATH+1];
    char *p;

    filename = strconcat(config_dir, "/msg/motd", (char *)NULL);
    fd = open(filename, O_RDONLY, 0);
    if (fd < 0)
        goto out;

    motd_in = prot_new(fd, 0);

    prot_fgets(buf, sizeof(buf), motd_in);
    if ((p = strchr(buf, '\r'))!=NULL) *p = 0;
    if ((p = strchr(buf, '\n'))!=NULL) *p = 0;

    for (p = buf; *p == '['; p++); /* can't have [ be first char, sigh */
    prot_printf(imapd_out, "* OK [ALERT] %s\r\n", p);

out:
    if (motd_in)
        prot_free(motd_in);
    if (fd >= 0)
        close(fd);
    free(filename);
}

/*
 * Cleanly shut down and exit
 */
void shut_down(int code) __attribute__((noreturn));
void shut_down(int code)
{
    int i;
    int bytes_in = 0;
    int bytes_out = 0;

    in_shutdown = 1;

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
    if (mupdate_h) mupdate_disconnect(&mupdate_h);

    index_text_extractor_destroy();

    if (idling)
        idle_stop(index_mboxname(imapd_index));

    if (imapd_index) {
        if (config_getswitch(IMAPOPT_AUTOEXPUNGE) && index_hasrights(imapd_index, ACL_EXPUNGE))
            index_expunge(imapd_index, NULL, 1);
        index_close(&imapd_index);
    }

    seen_done();
    mboxkey_done();

    annotatemore_close();
    annotate_done();

    idle_done();

    partlist_local_done();

    if (imapd_in) {
        /* Flush the incoming buffer */
        prot_NONBLOCK(imapd_in);
        prot_fill(imapd_in);
        bytes_in = prot_bytes_in(imapd_in);
        prot_free(imapd_in);
    }

    if (imapd_out) {
        /* Flush the outgoing buffer */
        prot_flush(imapd_out);
        bytes_out = prot_bytes_out(imapd_out);
        prot_free(imapd_out);

        /* one less active connection */
        prometheus_decrement(CYRUS_IMAP_ACTIVE_CONNECTIONS);
    }
    else {
        /* one less ready listener */
        prometheus_decrement(CYRUS_IMAP_READY_LISTENERS);
    }

    prometheus_increment(code ? CYRUS_IMAP_SHUTDOWN_TOTAL_STATUS_ERROR
                              : CYRUS_IMAP_SHUTDOWN_TOTAL_STATUS_OK);

    if (config_auditlog)
        syslog(LOG_NOTICE, "auditlog: traffic sessionid=<%s> bytes_in=<%d> bytes_out=<%d>",
                           session_id(), bytes_in, bytes_out);

    if (protin) protgroup_free(protin);

#ifdef HAVE_SSL
    tls_shutdown_serverengine();
#endif

    saslprops_free(&saslprops);

    cyrus_done();

    exit(code);
}

EXPORTED void fatal(const char *s, int code)
{
    static int recurse_code = 0;

    if (recurse_code) {
        /* We were called recursively. Just give up */
        proc_cleanup();
        if (imapd_out) {
            /* one less active connection */
            prometheus_decrement(CYRUS_IMAP_ACTIVE_CONNECTIONS);
        }
        else {
            /* one less ready listener */
            prometheus_decrement(CYRUS_IMAP_READY_LISTENERS);
        }
        prometheus_increment(CYRUS_IMAP_SHUTDOWN_TOTAL_STATUS_ERROR);
        exit(recurse_code);
    }
    recurse_code = code;
    if (imapd_out) {
        prot_printf(imapd_out, "* BYE Fatal error: %s\r\n", s);
        prot_flush(imapd_out);
    }
    if (stages.count) {
        /* Cleanup the stage(s) */
        struct appendstage *curstage;
        while ((curstage = ptrarray_pop(&stages))) {
            if (curstage->f != NULL) fclose(curstage->f);
            append_removestage(curstage->stage);
            strarray_fini(&curstage->flags);
            freeentryatts(curstage->annotations);
            free(curstage);
        }
        ptrarray_fini(&stages);
    }

    syslog(LOG_ERR, "Fatal error: %s", s);
    shut_down(code);
}

/*
 * Check the currently selected mailbox for updates.
 *
 * 'be' is the backend (if any) that we just proxied a command to.
 */
static void imapd_check(struct backend *be, int usinguid)
{
    if (backend_current && backend_current != be) {
        /* remote mailbox */
        char mytag[128];

        proxy_gentag(mytag, sizeof(mytag));

        prot_printf(backend_current->out, "%s Noop\r\n", mytag);
        pipe_until_tag(backend_current, mytag, 0);
    }
    else {
        /* local mailbox */
        index_check(imapd_index, usinguid, 0);
    }
}

#define IS_EOL(c, pin) ((c = (c == '\r') ? prot_getc(pin) : c) == '\n')

/*
 * Top-level command loop parsing
 */
static void cmdloop(void)
{
    int c;
    int usinguid, havepartition, havenamespace, recursive;
    static struct buf tag, cmd, arg1, arg2, arg3;
    char *p, shut[MAX_MAILBOX_PATH+1], cmdname[100];
    const char *err;
    const char * commandmintimer;
    double commandmintimerd = 0.0;
    struct sync_reserve_list *reserve_list =
        sync_reserve_list_create(SYNC_MESSAGE_LIST_HASH_SIZE);
    struct applepushserviceargs applepushserviceargs;
    int readonly = config_getswitch(IMAPOPT_READONLY);

    prot_printf(imapd_out, "* OK [CAPABILITY ");
    capa_response(CAPA_PREAUTH);
    prot_printf(imapd_out, "]");
    if (config_serverinfo) prot_printf(imapd_out, " %s", config_servername);
    if (config_serverinfo == IMAP_ENUM_SERVERINFO_ON) {
        prot_printf(imapd_out, " Cyrus IMAP %s", CYRUS_VERSION);
    }
    prot_printf(imapd_out, " server ready\r\n");

    /* clear cancelled flag if present before the next command */
    cmd_cancelled(/*insearch*/0);

    motd_file();

    /* Get command timer logging paramater. This string
     * is a time in seconds. Any command that takes >=
     * this time to execute is logged */
    commandmintimer = config_getstring(IMAPOPT_COMMANDMINTIMER);
    cmdtime_settimer(commandmintimer ? 1 : 0);
    if (commandmintimer) {
      commandmintimerd = atof(commandmintimer);
    }

    for (;;) {
        /* Release any held index */
        index_release(imapd_index);

        /* ensure we didn't leak anything! */
        assert(!open_mailboxes_exist());
        assert(!open_mboxlocks_exist());

        sync_log_reset();

        /* Flush any buffered output */
        prot_flush(imapd_out);
        if (backend_current) prot_flush(backend_current->out);

        /* command no longer running */
        proc_register(config_ident, imapd_clienthost, imapd_userid, index_mboxname(imapd_index), NULL);

        /* Check for shutdown file */
        if ( !imapd_userisadmin && imapd_userid &&
             (shutdown_file(shut, sizeof(shut)) ||
              userdeny(imapd_userid, config_ident, shut, sizeof(shut)))) {
            for (p = shut; *p == '['; p++); /* can't have [ be first char */
            prot_printf(imapd_out, "* BYE [ALERT] %s\r\n", p);
            telemetry_rusage(imapd_userid);
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
            goto done;
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
        lcase(cmd.s);
        xstrncpy(cmdname, cmd.s, 99);
        cmd.s[0] = toupper((unsigned char) cmd.s[0]);

        if (config_getswitch(IMAPOPT_CHATTY))
            syslog(LOG_NOTICE, "command: %s %s", tag.s, cmd.s);

        proc_register(config_ident, imapd_clienthost, imapd_userid, index_mboxname(imapd_index), cmd.s);

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

        /* Only Authenticate/Enable/Login/Logout/Noop/Capability/Id/Starttls
           allowed when not logged in */
        if (!imapd_userid && !strchr("AELNCIS", cmd.s[0])) goto nologin;

        /* Start command timer */
        cmdtime_starttimer();

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
                if (!IS_EOL(c, imapd_in)) goto extraargs;

                if (imapd_userid) {
                    prot_printf(imapd_out, "%s BAD Already authenticated\r\n", tag.s);
                    continue;
                }
                cmd_authenticate(tag.s, arg1.s, haveinitresp ? arg2.s : NULL);

                /* prometheus stat is counted by cmd_authenticate based on success/failure */
            }
            else if (!imapd_userid) goto nologin;
            else if (!strcmp(cmd.s, "Append")) {
                if (readonly) goto noreadonly;
                if (c != ' ') goto missingargs;
                c = getastring(imapd_in, imapd_out, &arg1);
                if (c != ' ') goto missingargs;

                cmd_append(tag.s, arg1.s, NULL);

                prometheus_increment(CYRUS_IMAP_APPEND_TOTAL);
            }
            else goto badcmd;
            break;

        case 'C':
            if (!strcmp(cmd.s, "Capability")) {
                if (!IS_EOL(c, imapd_in)) goto extraargs;
                cmd_capability(tag.s);

                prometheus_increment(CYRUS_IMAP_CAPABILITY_TOTAL);
            }
            else if (!imapd_userid) goto nologin;
#ifdef HAVE_ZLIB
            else if (!strcmp(cmd.s, "Compress")) {
                if (c != ' ') goto missingargs;
                c = getword(imapd_in, &arg1);
                if (c == EOF) goto missingargs;
                if (!IS_EOL(c, imapd_in)) goto extraargs;

                cmd_compress(tag.s, arg1.s);

                prometheus_increment(CYRUS_IMAP_COMPRESS_TOTAL);
            }
#endif /* HAVE_ZLIB */
            else if (!strcmp(cmd.s, "Check")) {
                if (!imapd_index && !backend_current) goto nomailbox;
                if (!IS_EOL(c, imapd_in)) goto extraargs;

                cmd_noop(tag.s, cmd.s);

                prometheus_increment(CYRUS_IMAP_CHECK_TOTAL);
            }
            else if (!strcmp(cmd.s, "Copy")) {
                if (readonly) goto noreadonly;
                if (!imapd_index && !backend_current) goto nomailbox;
                usinguid = 0;
                if (c != ' ') goto missingargs;
            copy:
                c = getword(imapd_in, &arg1);
                if (c == '\r') goto missingargs;
                if (c != ' ' || !imparse_issequence(arg1.s)) goto badsequence;
                c = getastring(imapd_in, imapd_out, &arg2);
                if (c == EOF) goto missingargs;
                if (!IS_EOL(c, imapd_in)) goto extraargs;

                cmd_copy(tag.s, arg1.s, arg2.s, usinguid, /*ismove*/0);

                prometheus_increment(CYRUS_IMAP_COPY_TOTAL);
            }
            else if (!strcmp(cmd.s, "Create")) {
                if (readonly) goto noreadonly;
                struct dlist *extargs = NULL;

                if (c != ' ') goto missingargs;
                c = getastring(imapd_in, imapd_out, &arg1);
                if (c == EOF) goto missingargs;
                if (c == ' ') {
                    c = parsecreateargs(&extargs);
                    if (c == EOF) goto badpartition;
                }
                if (!IS_EOL(c, imapd_in)) goto extraargs;
                cmd_create(tag.s, arg1.s, extargs, 0);
                dlist_free(&extargs);

                prometheus_increment(CYRUS_IMAP_CREATE_TOTAL);
            }
            else if (!strcmp(cmd.s, "Close")) {
                if (!imapd_index && !backend_current) goto nomailbox;
                if (!IS_EOL(c, imapd_in)) goto extraargs;

                cmd_close(tag.s, cmd.s);

                prometheus_increment(CYRUS_IMAP_CLOSE_TOTAL);
            }
            else goto badcmd;
            break;

        case 'D':
            if (!strcmp(cmd.s, "Delete")) {
                if (readonly) goto noreadonly;
                if (c != ' ') goto missingargs;
                c = getastring(imapd_in, imapd_out, &arg1);
                if (c == EOF) goto missingargs;
                if (!IS_EOL(c, imapd_in)) goto extraargs;
                cmd_delete(tag.s, arg1.s, 0, 0);

                prometheus_increment(CYRUS_IMAP_DELETE_TOTAL);
            }
            else if (!strcmp(cmd.s, "Deleteacl")) {
                if (readonly) goto noreadonly;
                if (c != ' ') goto missingargs;
                c = getastring(imapd_in, imapd_out, &arg1);
                if (c != ' ') goto missingargs;
                c = getastring(imapd_in, imapd_out, &arg2);
                if (c == EOF) goto missingargs;
                if (!IS_EOL(c, imapd_in)) goto extraargs;
                cmd_setacl(tag.s, arg1.s, arg2.s, NULL);

                prometheus_increment(CYRUS_IMAP_DELETEACL_TOTAL);
            }
            else if (!strcmp(cmd.s, "Dump")) {
                if (readonly) goto noreadonly;
                int uid_start = 0;

                if(c != ' ') goto missingargs;
                c = getastring(imapd_in, imapd_out, &arg1);
                if(c == ' ') {
                    c = getastring(imapd_in, imapd_out, &arg2);
                    if(!imparse_isnumber(arg2.s)) goto extraargs;
                    uid_start = atoi(arg2.s);
                }

                if (!IS_EOL(c, imapd_in)) goto extraargs;

                cmd_dump(tag.s, arg1.s, uid_start);
                prometheus_increment(CYRUS_IMAP_DUMP_TOTAL);
            }
            else goto badcmd;
            break;

        case 'E':
            if (!imapd_userid) goto nologin;
            else if (!strcmp(cmd.s, "Enable")) {
                if (c != ' ') goto missingargs;

                cmd_enable(tag.s);
            }
            else if (!strcmp(cmd.s, "Expunge")) {
                if (readonly) goto noreadonly;
                if (!imapd_index && !backend_current) goto nomailbox;
                if (!IS_EOL(c, imapd_in)) goto extraargs;

                cmd_expunge(tag.s, 0);

                prometheus_increment(CYRUS_IMAP_EXPUNGE_TOTAL);
            }
            else if (!strcmp(cmd.s, "Examine")) {
                if (c != ' ') goto missingargs;
                c = getastring(imapd_in, imapd_out, &arg1);
                if (c == EOF) goto missingargs;
                prot_ungetc(c, imapd_in);

                cmd_select(tag.s, cmd.s, arg1.s);

                prometheus_increment(CYRUS_IMAP_EXAMINE_TOTAL);
            }
            else goto badcmd;
            break;

        case 'F':
            if (!strcmp(cmd.s, "Fetch")) {
                if (!imapd_index && !backend_current) goto nomailbox;
                usinguid = 0;
                if (c != ' ') goto missingargs;
            fetch:
                c = getword(imapd_in, &arg1);
                if (c == '\r') goto missingargs;
                if (c != ' ' || !imparse_issequence(arg1.s)) goto badsequence;

                cmd_fetch(tag.s, arg1.s, usinguid);

                prometheus_increment(CYRUS_IMAP_FETCH_TOTAL);
            }
            else goto badcmd;
            break;

        case 'G':
            if (!strcmp(cmd.s, "Getacl")) {
                if (c != ' ') goto missingargs;
                c = getastring(imapd_in, imapd_out, &arg1);
                if (c == EOF) goto missingargs;
                if (!IS_EOL(c, imapd_in)) goto extraargs;
                cmd_getacl(tag.s, arg1.s);

                prometheus_increment(CYRUS_IMAP_GETACL_TOTAL);
            }
            else if (!strcmp(cmd.s, "Getannotation")) {
                if (c != ' ') goto missingargs;
                c = getastring(imapd_in, imapd_out, &arg1);
                if (c != ' ') goto missingargs;

                cmd_getannotation(tag.s, arg1.s);

                prometheus_increment(CYRUS_IMAP_GETANNOTATION_TOTAL);
            }
            else if (!strcmp(cmd.s, "Getmetadata")) {
                if (c != ' ') goto missingargs;

                cmd_getmetadata(tag.s);

                prometheus_increment(CYRUS_IMAP_GETMETADATA_TOTAL);
            }
            else if (!strcmp(cmd.s, "Getquota")) {
                if (c != ' ') goto missingargs;
                c = getastring(imapd_in, imapd_out, &arg1);
                if (c == EOF) goto missingargs;
                if (!IS_EOL(c, imapd_in)) goto extraargs;
                cmd_getquota(tag.s, arg1.s);

                prometheus_increment(CYRUS_IMAP_GETQUOTA_TOTAL);
            }
            else if (!strcmp(cmd.s, "Getquotaroot")) {
                if (c != ' ') goto missingargs;
                c = getastring(imapd_in, imapd_out, &arg1);
                if (c == EOF) goto missingargs;
                if (!IS_EOL(c, imapd_in)) goto extraargs;
                cmd_getquotaroot(tag.s, arg1.s);

                prometheus_increment(CYRUS_IMAP_GETQUOTAROOT_TOTAL);
            }
#ifdef HAVE_SSL
            else if (!strcmp(cmd.s, "Genurlauth")) {
                if (c != ' ') goto missingargs;

                cmd_genurlauth(tag.s);
                prometheus_increment(CYRUS_IMAP_GENURLAUTH_TOTAL);
            }
#endif
            else goto badcmd;
            break;

        case 'I':
            if (!strcmp(cmd.s, "Id")) {
                if (c != ' ') goto missingargs;
                cmd_id(tag.s);

                prometheus_increment(CYRUS_IMAP_ID_TOTAL);
            }
            else if (!imapd_userid) goto nologin;
            else if (!strcmp(cmd.s, "Idle") && idle_enabled()) {
                if (!IS_EOL(c, imapd_in)) goto extraargs;
                cmd_idle(tag.s);

                prometheus_increment(CYRUS_IMAP_IDLE_TOTAL);
            }
            else goto badcmd;
            break;

        case 'L':
            if (!strcmp(cmd.s, "Login")) {
                if (c != ' ') goto missingargs;
                c = getastring(imapd_in, imapd_out, &arg1);
                if(c != ' ') goto missingargs;

                cmd_login(tag.s, arg1.s);

                /* prometheus stat is counted by cmd_login based on success/failure */
            }
            else if (!strcmp(cmd.s, "Logout")) {
                if (!IS_EOL(c, imapd_in)) goto extraargs;

                prometheus_increment(CYRUS_IMAP_LOGOUT_TOTAL);

                /* force any responses from our selected backend */
                if (backend_current) imapd_check(NULL, 0);

                prot_printf(imapd_out, "* BYE %s\r\n",
                            error_message(IMAP_BYE_LOGOUT));
                prot_printf(imapd_out, "%s OK %s\r\n", tag.s,
                            error_message(IMAP_OK_COMPLETED));

                if (imapd_userid && *imapd_userid) {
                    telemetry_rusage(imapd_userid);
                }

                goto done;
            }
            else if (!imapd_userid) goto nologin;
            else if (!strcmp(cmd.s, "List")) {
                struct listargs listargs;

                if (c != ' ') goto missingargs;

                memset(&listargs, 0, sizeof(struct listargs));
                listargs.ret = LIST_RET_CHILDREN;
                getlistargs(tag.s, &listargs);
                if (listargs.pat.count) cmd_list(tag.s, &listargs);

                prometheus_increment(CYRUS_IMAP_LIST_TOTAL);
            }
            else if (!strcmp(cmd.s, "Lsub")) {
                struct listargs listargs;

                c = getastring(imapd_in, imapd_out, &arg1);
                if (c != ' ') goto missingargs;
                c = getastring(imapd_in, imapd_out, &arg2);
                if (!IS_EOL(c, imapd_in)) goto extraargs;

                memset(&listargs, 0, sizeof(struct listargs));
                listargs.cmd = LIST_CMD_LSUB;
                listargs.sel = LIST_SEL_SUBSCRIBED;
                if (!strcasecmpsafe(imapd_magicplus, "+dav"))
                    listargs.sel |= LIST_SEL_DAV;
                listargs.ref = arg1.s;
                strarray_append(&listargs.pat, arg2.s);

                cmd_list(tag.s, &listargs);

                prometheus_increment(CYRUS_IMAP_LSUB_TOTAL);
            }
            else if (!strcmp(cmd.s, "Listrights")) {
                c = getastring(imapd_in, imapd_out, &arg1);
                if (c != ' ') goto missingargs;
                c = getastring(imapd_in, imapd_out, &arg2);
                if (!IS_EOL(c, imapd_in)) goto extraargs;
                cmd_listrights(tag.s, arg1.s, arg2.s);

                prometheus_increment(CYRUS_IMAP_LISTRIGHTS_TOTAL);
            }
            else if (!strcmp(cmd.s, "Localappend")) {
                if (readonly) goto noreadonly;
                /* create a local-only mailbox */
                if (c != ' ') goto missingargs;
                c = getastring(imapd_in, imapd_out, &arg1);
                if (c != ' ') goto missingargs;
                c = getastring(imapd_in, imapd_out, &arg2);
                if (c != ' ') goto missingargs;

                cmd_append(tag.s, arg1.s, *arg2.s ? arg2.s : NULL);

                prometheus_increment(CYRUS_IMAP_APPEND_TOTAL);
            }
            else if (!strcmp(cmd.s, "Localcreate")) {
                if (readonly) goto noreadonly;
                /* create a local-only mailbox */
                struct dlist *extargs = NULL;

                if (c != ' ') goto missingargs;
                c = getastring(imapd_in, imapd_out, &arg1);
                if (c == EOF) goto missingargs;
                if (c == ' ') {
                    c = parsecreateargs(&extargs);
                    if (c == EOF) goto badpartition;
                }
                if (!IS_EOL(c, imapd_in)) goto extraargs;
                cmd_create(tag.s, arg1.s, extargs, 1);
                dlist_free(&extargs);

                /* XXX prometheus_increment(CYRUS_IMAP_CREATE_TOTAL); */
            }
            else if (!strcmp(cmd.s, "Localdelete")) {
                if (readonly) goto noreadonly;
                /* delete a mailbox locally only */
                if (c != ' ') goto missingargs;
                c = getastring(imapd_in, imapd_out, &arg1);
                if (c == EOF) goto missingargs;
                if (!IS_EOL(c, imapd_in)) goto extraargs;
                cmd_delete(tag.s, arg1.s, 1, 1);

                /* XXX prometheus_increment(CYRUS_IMAP_DELETE_TOTAL); */
            }
            else goto badcmd;
            break;

        case 'M':
            if (!strcmp(cmd.s, "Myrights")) {
                if (c != ' ') goto missingargs;
                c = getastring(imapd_in, imapd_out, &arg1);
                if (c == EOF) goto missingargs;
                if (!IS_EOL(c, imapd_in)) goto extraargs;
                cmd_myrights(tag.s, arg1.s);

                prometheus_increment(CYRUS_IMAP_MYRIGHTS_TOTAL);
            }
            else if (!strcmp(cmd.s, "Mupdatepush")) {
                if (readonly) goto noreadonly;
                if (c != ' ') goto missingargs;
                c = getastring(imapd_in, imapd_out, &arg1);
                if(c == EOF) goto missingargs;
                if (!IS_EOL(c, imapd_in)) goto extraargs;
                cmd_mupdatepush(tag.s, arg1.s);

                prometheus_increment(CYRUS_IMAP_MUPDATEPUSH_TOTAL);
            }
            else if (!strcmp(cmd.s, "Move")) {
                if (readonly) goto noreadonly;
                if (!imapd_index && !backend_current) goto nomailbox;
                usinguid = 0;
                if (c != ' ') goto missingargs;
            move:
                c = getword(imapd_in, &arg1);
                if (c == '\r') goto missingargs;
                if (c != ' ' || !imparse_issequence(arg1.s)) goto badsequence;
                c = getastring(imapd_in, imapd_out, &arg2);
                if (c == EOF) goto missingargs;
                if (!IS_EOL(c, imapd_in)) goto extraargs;

                cmd_copy(tag.s, arg1.s, arg2.s, usinguid, /*ismove*/1);

                prometheus_increment(CYRUS_IMAP_COPY_TOTAL);
            } else goto badcmd;
            break;

        case 'N':
            if (!strcmp(cmd.s, "Noop")) {
                if (!IS_EOL(c, imapd_in)) goto extraargs;

                cmd_noop(tag.s, cmd.s);

                /* XXX prometheus_increment(CYRUS_IMAP_NOOP_TOTAL); */
            }
            else if (!imapd_userid) goto nologin;
            else if (!strcmp(cmd.s, "Namespace")) {
                if (!IS_EOL(c, imapd_in)) goto extraargs;
                cmd_namespace(tag.s);

                /* XXX prometheus_increment(CYRUS_IMAP_NAMESPACE_TOTAL); */
            }
            else goto badcmd;
            break;

        case 'R':
            if (!strcmp(cmd.s, "Rename")) {
                if (readonly) goto noreadonly;
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
                if (!IS_EOL(c, imapd_in)) goto extraargs;
                cmd_rename(tag.s, arg1.s, arg2.s, havepartition ? arg3.s : 0);

                /* XXX prometheus_increment(CYRUS_IMAP_RENAME_TOTAL); */
            } else if(!strcmp(cmd.s, "Reconstruct")) {
                if (readonly) goto noreadonly;
                recursive = 0;
                if (c != ' ') goto missingargs;
                c = getastring(imapd_in, imapd_out, &arg1);
                if(c == ' ') {
                    /* Optional RECURSIVE argument */
                    c = getword(imapd_in, &arg2);
                    if(!imparse_isatom(arg2.s))
                        goto extraargs;
                    else if(!strcasecmp(arg2.s, "RECURSIVE"))
                        recursive = 1;
                    else
                        goto extraargs;
                }
                if (!IS_EOL(c, imapd_in)) goto extraargs;
                cmd_reconstruct(tag.s, arg1.s, recursive);

                /* XXX prometheus_increment(CYRUS_IMAP_RECONSTRUCT_TOTAL); */
            }
            else if (!strcmp(cmd.s, "Rlist")) {
                struct listargs listargs;

                c = getastring(imapd_in, imapd_out, &arg1);
                if (c != ' ') goto missingargs;
                c = getastring(imapd_in, imapd_out, &arg2);
                if (!IS_EOL(c, imapd_in)) goto extraargs;

                memset(&listargs, 0, sizeof(struct listargs));
                listargs.sel = LIST_SEL_REMOTE;
                listargs.ret = LIST_RET_CHILDREN;
                listargs.ref = arg1.s;
                strarray_append(&listargs.pat, arg2.s);

                cmd_list(tag.s, &listargs);

                /* XXX prometheus_increment(prom_handle, CYRUS_IMAP_LIST_TOTAL); */
            }
            else if (!strcmp(cmd.s, "Rlsub")) {
                struct listargs listargs;

                c = getastring(imapd_in, imapd_out, &arg1);
                if (c != ' ') goto missingargs;
                c = getastring(imapd_in, imapd_out, &arg2);
                if (!IS_EOL(c, imapd_in)) goto extraargs;

                memset(&listargs, 0, sizeof(struct listargs));
                listargs.cmd = LIST_CMD_LSUB;
                listargs.sel = LIST_SEL_REMOTE | LIST_SEL_SUBSCRIBED;
                listargs.ref = arg1.s;
                strarray_append(&listargs.pat, arg2.s);

                cmd_list(tag.s, &listargs);

                /* XXX prometheus_increment(prom_handle, CYRUS_IMAP_LSUB_TOTAL); */
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

                if (!IS_EOL(c, imapd_in)) goto extraargs;
                cmd_resetkey(tag.s, have_mbox ? arg1.s : 0,
                             have_mech ? arg2.s : 0);
                /* XXX prometheus_increment(CYRUS_IMAP_RESETKEY_TOTAL); */
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

                if (!IS_EOL(c, imapd_in)) goto extraargs;

                /* XXX  discard any input pipelined after STARTTLS */
                prot_flush(imapd_in);

                /* if we've already done SASL fail */
                if (imapd_userid != NULL) {
                    prot_printf(imapd_out,
               "%s BAD Can't Starttls after authentication\r\n", tag.s);
                    continue;
                }

                /* if we've already done COMPRESS fail */
                if (imapd_compress_done == 1) {
                    prot_printf(imapd_out,
               "%s BAD Can't Starttls after Compress\r\n", tag.s);
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

                prometheus_increment(CYRUS_IMAP_STARTTLS_TOTAL);
                continue;
            }
            if (!imapd_userid) {
                goto nologin;
            } else if (!strcmp(cmd.s, "Store")) {
                if (readonly) goto noreadonly;
                if (!imapd_index && !backend_current) goto nomailbox;
                usinguid = 0;
                if (c != ' ') goto missingargs;
            store:
                c = getword(imapd_in, &arg1);
                if (c != ' ' || !imparse_issequence(arg1.s)) goto badsequence;

                cmd_store(tag.s, arg1.s, usinguid);

                prometheus_increment(CYRUS_IMAP_STORE_TOTAL);
            }
            else if (!strcmp(cmd.s, "Select")) {
                if (c != ' ') goto missingargs;
                c = getastring(imapd_in, imapd_out, &arg1);
                if (c == EOF) goto missingargs;
                prot_ungetc(c, imapd_in);

                cmd_select(tag.s, cmd.s, arg1.s);

                prometheus_increment(CYRUS_IMAP_SELECT_TOTAL);
            }
            else if (!strcmp(cmd.s, "Search")) {
                if (!imapd_index && !backend_current) goto nomailbox;
                usinguid = 0;
                if (c != ' ') goto missingargs;
            search:

                cmd_search(tag.s, usinguid);

                prometheus_increment(CYRUS_IMAP_SEARCH_TOTAL);
            }
            else if (!strcmp(cmd.s, "Subscribe")) {
                if (readonly) goto noreadonly;
                if (c != ' ') goto missingargs;
                havenamespace = 0;
                c = getastring(imapd_in, imapd_out, &arg1);
                if (c == ' ') {
                    havenamespace = 1;
                    c = getastring(imapd_in, imapd_out, &arg2);
                }
                if (c == EOF) goto missingargs;
                if (!IS_EOL(c, imapd_in)) goto extraargs;
                if (havenamespace) {
                    cmd_changesub(tag.s, arg1.s, arg2.s, 1);
                }
                else {
                    cmd_changesub(tag.s, (char *)0, arg1.s, 1);
                }
                prometheus_increment(CYRUS_IMAP_SUBSCRIBE_TOTAL);
            }
            else if (!strcmp(cmd.s, "Setacl")) {
                if (readonly) goto noreadonly;
                if (c != ' ') goto missingargs;
                c = getastring(imapd_in, imapd_out, &arg1);
                if (c != ' ') goto missingargs;
                c = getastring(imapd_in, imapd_out, &arg2);
                if (c != ' ') goto missingargs;
                c = getastring(imapd_in, imapd_out, &arg3);
                if (c == EOF) goto missingargs;
                if (!IS_EOL(c, imapd_in)) goto extraargs;
                cmd_setacl(tag.s, arg1.s, arg2.s, arg3.s);

                prometheus_increment(CYRUS_IMAP_SETACL_TOTAL);
            }
            else if (!strcmp(cmd.s, "Setannotation")) {
                if (readonly) goto noreadonly;
                if (c != ' ') goto missingargs;
                c = getastring(imapd_in, imapd_out, &arg1);
                if (c != ' ') goto missingargs;

                cmd_setannotation(tag.s, arg1.s);

                prometheus_increment(CYRUS_IMAP_SETANNOTATION_TOTAL);
            }
            else if (!strcmp(cmd.s, "Setmetadata")) {
                if (readonly) goto noreadonly;
                if (c != ' ') goto missingargs;
                c = getastring(imapd_in, imapd_out, &arg1);
                if (c != ' ') goto missingargs;

                cmd_setmetadata(tag.s, arg1.s);

                prometheus_increment(CYRUS_IMAP_SETMETADATA_TOTAL);
            }
            else if (!strcmp(cmd.s, "Setquota")) {
                if (readonly) goto noreadonly;
                if (c != ' ') goto missingargs;
                c = getastring(imapd_in, imapd_out, &arg1);
                if (c != ' ') goto missingargs;
                cmd_setquota(tag.s, arg1.s);

                prometheus_increment(CYRUS_IMAP_SETQUOTA_TOTAL);
            }
            else if (!strcmp(cmd.s, "Sort")) {
                if (!imapd_index && !backend_current) goto nomailbox;
                usinguid = 0;
                if (c != ' ') goto missingargs;
            sort:
                cmd_sort(tag.s, usinguid);

                prometheus_increment(CYRUS_IMAP_SORT_TOTAL);
            }
            else if (!strcmp(cmd.s, "Status")) {
                if (c != ' ') goto missingargs;
                c = getastring(imapd_in, imapd_out, &arg1);
                if (c != ' ') goto missingargs;
                cmd_status(tag.s, arg1.s);

                prometheus_increment(CYRUS_IMAP_STATUS_TOTAL);
            }
            else if (!strcmp(cmd.s, "Scan")) {
                struct listargs listargs;

                c = getastring(imapd_in, imapd_out, &arg1);
                if (c != ' ') goto missingargs;
                c = getastring(imapd_in, imapd_out, &arg2);
                if (c != ' ') goto missingargs;
                c = getastring(imapd_in, imapd_out, &arg3);
                if (!IS_EOL(c, imapd_in)) goto extraargs;

                memset(&listargs, 0, sizeof(struct listargs));
                listargs.ref = arg1.s;
                strarray_append(&listargs.pat, arg2.s);
                listargs.scan = arg3.s;

                cmd_list(tag.s, &listargs);

                prometheus_increment(CYRUS_IMAP_SCAN_TOTAL);
            }
            else if (!strcmp(cmd.s, "Syncapply")) {
                if (!imapd_userisadmin) goto badcmd;

                struct dlist *kl = sync_parseline(imapd_in);

                if (kl) {
                    cmd_syncapply(tag.s, kl, reserve_list);
                    dlist_free(&kl);
                }
                else goto badrepl;
            }
            else if (!strcmp(cmd.s, "Syncget")) {
                if (!imapd_userisadmin) goto badcmd;

                struct dlist *kl = sync_parseline(imapd_in);

                if (kl) {
                    cmd_syncget(tag.s, kl);
                    dlist_free(&kl);
                }
                else goto badrepl;
            }
            else if (!strcmp(cmd.s, "Syncrestart")) {
                if (!imapd_userisadmin) goto badcmd;

                if (!IS_EOL(c, imapd_in)) goto extraargs;

                /* just clear the GUID cache */
                cmd_syncrestart(tag.s, &reserve_list, 1);
            }
            else if (!strcmp(cmd.s, "Syncrestore")) {
                if (!imapd_userisadmin) goto badcmd;

                struct dlist *kl = sync_parseline(imapd_in);

                if (kl) {
                    cmd_syncrestore(tag.s, kl, reserve_list);
                    dlist_free(&kl);
                }
                else goto badrepl;
            }
            else goto badcmd;
            break;

        case 'T':
            if (!strcmp(cmd.s, "Thread")) {
                if (!imapd_index && !backend_current) goto nomailbox;
                usinguid = 0;
                if (c != ' ') goto missingargs;
            thread:
                cmd_thread(tag.s, usinguid);

                prometheus_increment(CYRUS_IMAP_THREAD_TOTAL);
            }
            else goto badcmd;
            break;

        case 'U':
            if (!strcmp(cmd.s, "Uid")) {
                if (!imapd_index && !backend_current) goto nomailbox;
                usinguid = 1;
                if (c != ' ') goto missingargs;
                c = getword(imapd_in, &arg1);
                if (c != ' ') goto missingargs;
                lcase(arg1.s);
                xstrncpy(cmdname, arg1.s, 99);
                if (!strcmp(arg1.s, "fetch")) {
                    goto fetch;
                }
                else if (!strcmp(arg1.s, "store")) {
                    if (readonly) goto noreadonly;
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
                    if (readonly) goto noreadonly;
                    goto copy;
                }
                else if (!strcmp(arg1.s, "move")) {
                    if (readonly) goto noreadonly;
                    goto move;
                }
                else if (!strcmp(arg1.s, "xmove")) {
                    if (readonly) goto noreadonly;
                    goto move;
                }
                else if (!strcmp(arg1.s, "expunge")) {
                    if (readonly) goto noreadonly;
                    c = getword(imapd_in, &arg1);
                    if (!imparse_issequence(arg1.s)) goto badsequence;
                    if (!IS_EOL(c, imapd_in)) goto extraargs;
                    cmd_expunge(tag.s, arg1.s);

                    prometheus_increment(CYRUS_IMAP_EXPUNGE_TOTAL);
                }
                else if (!strcmp(arg1.s, "xrunannotator")) {
                    if (readonly) goto noreadonly;
                    goto xrunannotator;
                }
                else {
                    prot_printf(imapd_out, "%s BAD Unrecognized UID subcommand\r\n", tag.s);
                    eatline(imapd_in, c);
                }
            }
            else if (!strcmp(cmd.s, "Unauthenticate")) {
                if (!imapd_userisadmin) goto badcmd;

                if (!IS_EOL(c, imapd_in)) goto extraargs;

                cmd_unauthenticate(tag.s);

                prometheus_increment(CYRUS_IMAP_UNAUTHENTICATE_TOTAL);
            }
            else if (!strcmp(cmd.s, "Unsubscribe")) {
                if (readonly) goto noreadonly;
                if (c != ' ') goto missingargs;
                havenamespace = 0;
                c = getastring(imapd_in, imapd_out, &arg1);
                if (c == ' ') {
                    havenamespace = 1;
                    c = getastring(imapd_in, imapd_out, &arg2);
                }
                if (c == EOF) goto missingargs;
                if (!IS_EOL(c, imapd_in)) goto extraargs;
                if (havenamespace) {
                    cmd_changesub(tag.s, arg1.s, arg2.s, 0);
                }
                else {
                    cmd_changesub(tag.s, (char *)0, arg1.s, 0);
                }

                prometheus_increment(CYRUS_IMAP_UNSUBSCRIBE_TOTAL);
            }
            else if (!strcmp(cmd.s, "Unselect")) {
                if (!imapd_index && !backend_current) goto nomailbox;
                if (!IS_EOL(c, imapd_in)) goto extraargs;

                cmd_close(tag.s, cmd.s);

                prometheus_increment(CYRUS_IMAP_UNSELECT_TOTAL);
            }
            else if (!strcmp(cmd.s, "Undump")) {
                if (readonly) goto noreadonly;
                if(c != ' ') goto missingargs;
                c = getastring(imapd_in, imapd_out, &arg1);

                /* we want to get a list at this point */
                if(c != ' ') goto missingargs;

                cmd_undump(tag.s, arg1.s);
                /* XXX prometheus_increment(CYRUS_IMAP_UNDUMP_TOTAL); */
            }
#ifdef HAVE_SSL
            else if (!strcmp(cmd.s, "Urlfetch")) {
                if (c != ' ') goto missingargs;

                cmd_urlfetch(tag.s);
                /* XXX prometheus_increment(CYRUS_IMAP_URLFETCH_TOTAL); */
            }
#endif
            else goto badcmd;
            break;

        case 'X':
            if (!strcmp(cmd.s, "Xbackup")) {
                if (readonly) goto noreadonly;
                int havechannel = 0;

                if (!config_getswitch(IMAPOPT_XBACKUP_ENABLED))
                    goto badcmd;

                /* user */
                if (c != ' ') goto missingargs;
                c = getastring(imapd_in, imapd_out, &arg1);

                /* channel */
                if (c == ' ') {
                    havechannel = 1;
                    c = getword(imapd_in, &arg2);
                    if (c == EOF) goto missingargs;
                }

                if (!IS_EOL(c, imapd_in)) goto extraargs;

                cmd_xbackup(tag.s, arg1.s, havechannel ? arg2.s : NULL);

                prometheus_increment(CYRUS_IMAP_XBACKUP_TOTAL);
            }
            else if (!strcmp(cmd.s, "Xconvfetch")) {
                cmd_xconvfetch(tag.s);

                /* XXX prometheus_increment(CYRUS_IMAP_XCONVFETCH_TOTAL); */
            }
            else if (!strcmp(cmd.s, "Xconvmultisort")) {
                if (c != ' ') goto missingargs;
                if (!imapd_index && !backend_current) goto nomailbox;
                cmd_xconvmultisort(tag.s);

                /* XXX prometheus_increment(CYRUS_IMAP_XCONVMULTISORT_TOTAL); */
            }
            else if (!strcmp(cmd.s, "Xconvsort")) {
                if (c != ' ') goto missingargs;
                if (!imapd_index && !backend_current) goto nomailbox;
                cmd_xconvsort(tag.s, 0);

                /* XXX prometheus_increment(CYRUS_IMAP_XCONVSORT_TOTAL); */
            }
            else if (!strcmp(cmd.s, "Xconvupdates")) {
                if (c != ' ') goto missingargs;
                if (!imapd_index && !backend_current) goto nomailbox;
                cmd_xconvsort(tag.s, 1);

                /* XXX prometheus_increment(CYRUS_IMAP_XCONVUPDATES_TOTAL); */
            }
            else if (!strcmp(cmd.s, "Xfer")) {
                if (readonly) goto noreadonly;
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

                if (!IS_EOL(c, imapd_in)) goto extraargs;

                cmd_xfer(tag.s, arg1.s, arg2.s,
                         (havepartition ? arg3.s : NULL));
                /* XXX prometheus_increment(CYRUS_IMAP_XFER_TOTAL); */
            }
            else if (!strcmp(cmd.s, "Xconvmeta")) {
                cmd_xconvmeta(tag.s);
            }
            else if (!strcmp(cmd.s, "Xlist")) {
                struct listargs listargs;

                if (c != ' ') goto missingargs;

                memset(&listargs, 0, sizeof(struct listargs));
                listargs.cmd = LIST_CMD_XLIST;
                listargs.ret = LIST_RET_CHILDREN | LIST_RET_SPECIALUSE;
                getlistargs(tag.s, &listargs);
                if (listargs.pat.count) cmd_list(tag.s, &listargs);

                prometheus_increment(CYRUS_IMAP_LIST_TOTAL);
            }
            else if (!strcmp(cmd.s, "Xmove")) {
                if (readonly) goto noreadonly;
                if (!imapd_index && !backend_current) goto nomailbox;
                usinguid = 0;
                if (c != ' ') goto missingargs;
                goto move;
            }
            else if (!strcmp(cmd.s, "Xrunannotator")) {
                if (readonly) goto noreadonly;
                if (!imapd_index && !backend_current) goto nomailbox;
                usinguid = 0;
                if (c != ' ') goto missingargs;
            xrunannotator:
                c = getword(imapd_in, &arg1);
                if (!arg1.len || !imparse_issequence(arg1.s)) goto badsequence;
                if (!IS_EOL(c, imapd_in)) goto extraargs;
                cmd_xrunannotator(tag.s, arg1.s, usinguid);
                /* XXX prometheus_increment(CYRUS_IMAP_XRUNANNOTATOR_TOTAL); */
            }
            else if (!strcmp(cmd.s, "Xsnippets")) {
                if (c != ' ') goto missingargs;
                if (!imapd_index && !backend_current) goto nomailbox;
                cmd_xsnippets(tag.s);

                /* XXX prometheus_increment(CYRUS_IMAP_XSNIPPETS_TOTAL); */
            }
            else if (!strcmp(cmd.s, "Xstats")) {
                if (!IS_EOL(c, imapd_in)) goto extraargs;
                cmd_xstats(tag.s);
            }
            else if (!strcmp(cmd.s, "Xwarmup")) {
                /* XWARMUP doesn't need a mailbox to be selected */
                if (c != ' ') goto missingargs;
                cmd_xwarmup(tag.s);
                /* XXX prometheus_increment(CYRUS_IMAP_XWARMUP_TOTAL); */
            }
            else if (!strcmp(cmd.s, "Xkillmy")) {
                if (c != ' ') goto missingargs;
                c = getastring(imapd_in, imapd_out, &arg1);
                if (c == EOF) goto missingargs;
                if (!IS_EOL(c, imapd_in)) goto extraargs;
                cmd_xkillmy(tag.s, arg1.s);
            }
            else if (!strcmp(cmd.s, "Xforever")) {
                if (!IS_EOL(c, imapd_in)) goto extraargs;
                cmd_xforever(tag.s);
            }
            else if (!strcmp(cmd.s, "Xmeid")) {
                if (c != ' ') goto missingargs;
                c = getastring(imapd_in, imapd_out, &arg1);
                if (c == EOF) goto missingargs;
                if (!IS_EOL(c, imapd_in)) goto extraargs;
                cmd_xmeid(tag.s, arg1.s);
            }

            else if (apns_enabled && !strcmp(cmd.s, "Xapplepushservice")) {
                if (c != ' ') goto missingargs;

                memset(&applepushserviceargs, 0, sizeof(struct applepushserviceargs));

                do {
                    c = getastring(imapd_in, imapd_out, &arg1);
                    if (c == EOF) goto aps_missingargs;

                    if (!strcmp(arg1.s, "mailboxes")) {
                        c = prot_getc(imapd_in);
                        if (c != '(')
                            goto aps_missingargs;

                        c = prot_getc(imapd_in);
                        if (c != ')') {
                            prot_ungetc(c, imapd_in);
                            do {
                                c = getastring(imapd_in, imapd_out, &arg2);
                                if (c == EOF) break;
                                strarray_push(&applepushserviceargs.mailboxes, arg2.s);
                            } while (c == ' ');
                        }

                        if (c != ')')
                            goto aps_missingargs;
                        c = prot_getc(imapd_in);
                    }

                    else {
                        c = getastring(imapd_in, imapd_out, &arg2);

                        // regular key/value
                        if (!strcmp(arg1.s, "aps-version")) {
                            if (!imparse_isnumber(arg2.s)) goto aps_extraargs;
                            applepushserviceargs.aps_version = atoi(arg2.s);
                        }
                        else if (!strcmp(arg1.s, "aps-account-id"))
                            buf_copy(&applepushserviceargs.aps_account_id, &arg2);
                        else if (!strcmp(arg1.s, "aps-device-token"))
                            buf_copy(&applepushserviceargs.aps_device_token, &arg2);
                        else if (!strcmp(arg1.s, "aps-subtopic"))
                            buf_copy(&applepushserviceargs.aps_subtopic, &arg2);
                        else
                            goto aps_extraargs;
                    }
                } while (c == ' ');

                if (!IS_EOL(c, imapd_in)) goto aps_extraargs;

                cmd_xapplepushservice(tag.s, &applepushserviceargs);
            }

            else goto badcmd;
            break;

        default:
        badcmd:
            prot_printf(imapd_out, "%s BAD Unrecognized command\r\n", tag.s);
            eatline(imapd_in, c);
        }

        /* End command timer - don't log "idle" commands */
        if (commandmintimer && strcmp("idle", cmdname)) {
            double cmdtime, nettime;
            const char *mboxname = index_mboxname(imapd_index);
            if (!mboxname) mboxname = "<none>";
            cmdtime_endtimer(&cmdtime, &nettime);
            if (cmdtime >= commandmintimerd) {
                syslog(LOG_NOTICE, "cmdtimer: '%s' '%s' '%s' '%f' '%f' '%f'",
                    imapd_userid ? imapd_userid : "<none>", cmdname, mboxname,
                    cmdtime, nettime, cmdtime + nettime);
            }
        }
        continue;

    nologin:
        prot_printf(imapd_out, "%s BAD Please login first\r\n", tag.s);
        eatline(imapd_in, c);
        continue;

    nomailbox:
        prot_printf(imapd_out,
                    "%s BAD Please select a mailbox first\r\n", tag.s);
        eatline(imapd_in, c);
        continue;

    noreadonly:
        prot_printf(imapd_out, "%s NO %s\r\n", tag.s,
                    error_message(IMAP_CONNECTION_READONLY));
        eatline(imapd_in, c);
        continue;

    aps_missingargs:
        buf_free(&applepushserviceargs.aps_account_id);
        buf_free(&applepushserviceargs.aps_device_token);
        buf_free(&applepushserviceargs.aps_subtopic);
        strarray_fini(&applepushserviceargs.mailboxes);

    missingargs:
        prot_printf(imapd_out,
                    "%s BAD Missing required argument to %s\r\n", tag.s, cmd.s);
        eatline(imapd_in, c);
        continue;

    aps_extraargs:
        buf_free(&applepushserviceargs.aps_account_id);
        buf_free(&applepushserviceargs.aps_device_token);
        buf_free(&applepushserviceargs.aps_subtopic);
        strarray_fini(&applepushserviceargs.mailboxes);

    extraargs:
        prot_printf(imapd_out,
                    "%s BAD Unexpected extra arguments to %s\r\n", tag.s, cmd.s);
        eatline(imapd_in, c);
        continue;

    badsequence:
        prot_printf(imapd_out,
                    "%s BAD Invalid sequence in %s\r\n", tag.s, cmd.s);
        eatline(imapd_in, c);
        continue;

    badpartition:
        prot_printf(imapd_out,
                    "%s BAD Invalid partition name in %s\r\n", tag.s, cmd.s);
        eatline(imapd_in, c);
        continue;

    badrepl:
        prot_printf(imapd_out,
                    "%s BAD Replication parse failure in %s\r\n", tag.s, cmd.s);
        /* n.b. sync_parseline already ate the bad line */
        continue;
    }

done:
    cmd_syncrestart(NULL, &reserve_list, 0);
}

#ifdef USE_AUTOCREATE
/*
 * Autocreate Inbox and subfolders upon login
 */
static void autocreate_inbox(void)
{
    if (imapd_userisadmin) return;
    if (imapd_userisproxyadmin) return;

    if (config_getint(IMAPOPT_AUTOCREATE_QUOTA) >= 0) {
        char *inboxname = mboxname_user_mbox(imapd_userid, NULL);
        int r = mboxlist_lookup(inboxname, NULL, NULL);
        free(inboxname);
        if (r != IMAP_MAILBOX_NONEXISTENT) return;
        autocreate_user(&imapd_namespace, imapd_userid);
    }
}
#endif // USE_AUTOCREATE

static void authentication_success(void)
{
    int r;
    struct mboxevent *mboxevent;

    /* authstate already created by mysasl_proxy_policy() */
    imapd_userisadmin = global_authisa(imapd_authstate, IMAPOPT_ADMINS);

    /* Create telemetry log */
    imapd_logfd = telemetry_log(imapd_userid, imapd_in, imapd_out, 0);

    /* Set namespace */
    r = mboxname_init_namespace(&imapd_namespace,
                                imapd_userisadmin || imapd_userisproxyadmin);

    mboxevent_setnamespace(&imapd_namespace);

    if (r) {
        syslog(LOG_ERR, "%s", error_message(r));
        fatal(error_message(r), EX_CONFIG);
    }

    /* Make a copy of the external userid for use in proxying */
    proxy_userid = xstrdup(imapd_userid);

    /* send a Login event notification */
    if ((mboxevent = mboxevent_new(EVENT_LOGIN))) {
        mboxevent_set_access(mboxevent,
                             buf_cstringnull_ifempty(&saslprops.iplocalport),
                             buf_cstringnull_ifempty(&saslprops.ipremoteport),
                             imapd_userid, NULL, 1);

        mboxevent_notify(&mboxevent);
        mboxevent_free(&mboxevent);
    }

#ifdef USE_AUTOCREATE
    autocreate_inbox();
#endif // USE_AUTOCREATE
}

static int checklimits(const char *tag)
{
    struct proc_limits limits;

    limits.procname = "imapd";
    limits.clienthost = imapd_clienthost;
    limits.userid = imapd_userid;

    if (proc_checklimits(&limits)) {
        const char *sep = "";
        char part1[1024] = "";
        char part2[1024] = "";
        prot_printf(imapd_out, "%s NO Too many open connections (", tag);
        if (limits.maxhost) {
            prot_printf(imapd_out, "%s%d of %d from %s", sep,
                        limits.host, limits.maxhost, imapd_clienthost);
            snprintf(part1, sizeof(part1), "%s%d of %d from %s", sep,
                        limits.host, limits.maxhost, imapd_clienthost);
            sep = ", ";
        }
        if (limits.maxuser) {
            prot_printf(imapd_out, "%s%d of %d for %s", sep,
                        limits.user, limits.maxuser, imapd_userid);
            snprintf(part2, sizeof(part2), "%s%d of %d for %s", sep,
                        limits.user, limits.maxuser, imapd_userid);
        }
        prot_printf(imapd_out, ")\r\n");
        syslog(LOG_ERR, "Too many open connections (%s%s)", part1, part2);
        free(imapd_userid);
        imapd_userid = NULL;
        auth_freestate(imapd_authstate);
        imapd_authstate = NULL;
        return 1;
    }
    return 0;
}

/*
 * Perform a LOGIN command
 */
static void cmd_login(char *tag, char *user)
{
    char userbuf[MAX_MAILBOX_BUFFER];
    char replybuf[MAX_MAILBOX_BUFFER];
    unsigned userlen;
    const char *canon_user = userbuf;
    const void *val;
    int c;
    struct buf passwdbuf;
    char *passwd;
    const char *reply = NULL;
    int r;
    int failedloginpause;

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
        syslog(LOG_NOTICE, "badlogin: %s plaintext (%s) invalid user",
               imapd_clienthost, beautify_string(user));
        prot_printf(imapd_out, "%s NO %s\r\n", tag,
                    error_message(IMAP_INVALID_USER));
        return;
    }

    /* possibly disallow login */
    if (imapd_tls_required ||
        (!imapd_starttls_done && (extprops_ssf < 2) &&
         !config_getswitch(IMAPOPT_ALLOWPLAINTEXT) &&
         !is_userid_anonymous(canon_user))) {
        eatline(imapd_in, ' ');
        prot_printf(imapd_out, "%s NO Login only available under a layer\r\n",
                    tag);
        return;
    }

    memset(&passwdbuf,0,sizeof(struct buf));
    c = getastring(imapd_in, imapd_out, &passwdbuf);

    if (!IS_EOL(c, imapd_in)) {
        buf_free(&passwdbuf);
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
            buf_free(&passwdbuf);
            return;
        }
    }
    else if ( nosaslpasswdcheck ) {
        snprintf(replybuf, sizeof(replybuf),
            "User logged in SESSIONID=<%s>", session_id());
        reply = replybuf;
        imapd_userid = xstrdup(canon_user);
        imapd_authstate = auth_newstate(canon_user);
        syslog(LOG_NOTICE, "login: %s %s%s nopassword%s %s", imapd_clienthost,
               imapd_userid, imapd_magicplus ? imapd_magicplus : "",
               imapd_starttls_done ? "+TLS" : "", reply);
    }
    else if ((r = sasl_checkpass(imapd_saslconn,
                                 canon_user,
                                 strlen(canon_user),
                                 passwd,
                                 strlen(passwd))) != SASL_OK) {
        syslog(LOG_NOTICE, "badlogin: %s plaintext (%s) [%s]",
               imapd_clienthost, canon_user, sasl_errdetail(imapd_saslconn));

        failedloginpause = config_getduration(IMAPOPT_FAILEDLOGINPAUSE, 's');
        if (failedloginpause != 0) {
            sleep(failedloginpause);
        }

        /* Don't allow user probing */
        if (r == SASL_NOUSER) r = SASL_BADAUTH;

        if ((reply = sasl_errstring(r, NULL, NULL)) != NULL) {
            prot_printf(imapd_out, "%s NO Login failed: %s\r\n", tag, reply);
        } else {
            prot_printf(imapd_out, "%s NO Login failed: %d\r\n", tag, r);
        }

        prometheus_increment(CYRUS_IMAP_AUTHENTICATE_TOTAL_RESULT_NO);
        buf_free(&passwdbuf);
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

            prometheus_increment(CYRUS_IMAP_AUTHENTICATE_TOTAL_RESULT_NO);
            buf_free(&passwdbuf);
            return;
        }

        snprintf(replybuf, sizeof(replybuf),
            "User logged in SESSIONID=<%s>", session_id());
        reply = replybuf;
        imapd_userid = xstrdup((const char *) val);
        prometheus_increment(CYRUS_IMAP_AUTHENTICATE_TOTAL_RESULT_YES);
        syslog(LOG_NOTICE, "login: %s %s%s plaintext%s %s", imapd_clienthost,
               imapd_userid, imapd_magicplus ? imapd_magicplus : "",
               imapd_starttls_done ? "+TLS" : "",
               reply ? reply : "");

        /* Apply penalty only if not under layer */
        if (!imapd_starttls_done) {
            int plaintextloginpause = config_getduration(IMAPOPT_PLAINTEXTLOGINPAUSE, 's');
            if (plaintextloginpause) {
                sleep(plaintextloginpause);
            }

            /* Fetch plaintext login nag message */
            plaintextloginalert = config_getstring(IMAPOPT_PLAINTEXTLOGINALERT);
        }
    }

    buf_free(&passwdbuf);

    if (checklimits(tag)) return;

    prot_printf(imapd_out, "%s OK [CAPABILITY ", tag);
    capa_response(CAPA_PREAUTH|CAPA_POSTAUTH);
    prot_printf(imapd_out, "] %s\r\n", reply);

    authentication_success();
}

/*
 * Perform an AUTHENTICATE command
 */
static void cmd_authenticate(char *tag, char *authtype, char *resp)
{
    int sasl_result;

    const void *val;
    const char *ssfmsg = NULL;

    const char *canon_user;

    int r;
    int failedloginpause;

    if (imapd_tls_required) {
        prot_printf(imapd_out,
                    "%s NO Authenticate only available under a layer\r\n", tag);
        return;
    }

    r = saslserver(imapd_saslconn, authtype, resp, "", "+ ", "",
                   imapd_in, imapd_out, &sasl_result, NULL);

    if (r) {
        const char *errorstring = NULL;
        const char *userid = "-notset-";

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
            if (sasl_result != SASL_NOUSER)
                sasl_getprop(imapd_saslconn, SASL_USERNAME, (const void **) &userid);

            syslog(LOG_NOTICE, "badlogin: %s %s (%s) [%s]",
                   imapd_clienthost, authtype, userid, sasl_errdetail(imapd_saslconn));

            prometheus_increment(CYRUS_IMAP_AUTHENTICATE_TOTAL_RESULT_NO);
            failedloginpause = config_getduration(IMAPOPT_FAILEDLOGINPAUSE, 's');
            if (failedloginpause != 0) {
                sleep(failedloginpause);
            }

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
        char userbuf[MAX_MAILBOX_BUFFER];
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

    syslog(LOG_NOTICE, "login: %s %s%s %s%s User logged in SESSIONID=<%s>", imapd_clienthost,
           imapd_userid, imapd_magicplus ? imapd_magicplus : "",
           authtype, imapd_starttls_done ? "+TLS" : "", session_id());

    sasl_getprop(imapd_saslconn, SASL_SSF, &val);
    saslprops.ssf = *((sasl_ssf_t *) val);

    /* really, we should be doing a sasl_getprop on SASL_SSF_EXTERNAL,
       but the current libsasl doesn't allow that. */
    if (imapd_starttls_done) {
        switch(saslprops.ssf) {
        case 0: ssfmsg = "tls protection"; break;
        case 1: ssfmsg = "tls plus integrity protection"; break;
        default: ssfmsg = "tls plus privacy protection"; break;
        }
    } else {
        switch(saslprops.ssf) {
        case 0: ssfmsg = "no protection"; break;
        case 1: ssfmsg = "integrity protection"; break;
        default: ssfmsg = "privacy protection"; break;
        }
    }

    prometheus_increment(CYRUS_IMAP_AUTHENTICATE_TOTAL_RESULT_YES);

    if (checklimits(tag)) {
        reset_saslconn(&imapd_saslconn);
        return;
    }

    if (!saslprops.ssf) {
        prot_printf(imapd_out, "%s OK [CAPABILITY ", tag);
        capa_response(CAPA_PREAUTH|CAPA_POSTAUTH);
        prot_printf(imapd_out, "] Success (%s) SESSIONID=<%s>\r\n",
                    ssfmsg, session_id());
    } else {
        prot_printf(imapd_out, "%s OK Success (%s) SESSIONID=<%s>\r\n",
                    tag, ssfmsg, session_id());
    }

    prot_setsasl(imapd_in,  imapd_saslconn);
    prot_setsasl(imapd_out, imapd_saslconn);

    authentication_success();
}

/*
 * Perform an UNAUTHENTICATE command
 */
static void cmd_unauthenticate(char *tag)
{
    /* Unselect any open mailbox */
    if (backend_current) {
        /* remote mailbox */
        char mytag[128];

        proxy_gentag(mytag, sizeof(mytag));
        prot_printf(backend_current->out, "%s Unselect\r\n", mytag);
        /* do not fatal() here, because we don't really care about this
         * server anymore anyway */
        pipe_until_tag(backend_current, mytag, 1);

        /* remove backend_current from the protgroup */
        protgroup_delete(protin, backend_current->in);

        backend_current = NULL;
    }
    else if (imapd_index) {
        if (config_getswitch(IMAPOPT_AUTOEXPUNGE) && index_hasrights(imapd_index, ACL_EXPUNGE))
            index_expunge(imapd_index, NULL, 1);
        index_close(&imapd_index);
    }

    /* Reset authentication state */
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
    plaintextloginalert = NULL;
    saslprops_reset(&saslprops);
    clear_id();

    /* Reset client-enabled extensions */
    client_capa = 0;

    /* Send response
       (MUST be done with current SASL and/or commpression layer still active) */
    prot_printf(imapd_out, "%s OK [CAPABILITY ", tag);
    capa_response(CAPA_PREAUTH);
    prot_printf(imapd_out, "] %s\r\n", error_message(IMAP_OK_COMPLETED));
    prot_flush(imapd_out);

    /* Reset connection state (other than TLS) */
#ifdef HAVE_ZLIB
    if (imapd_compress_done) {
        /* disable (de)compression on the prot layer */
        prot_unsetcompress(imapd_in);
        prot_unsetcompress(imapd_out);

        imapd_compress_done = 0;
    }
#endif
    if (imapd_saslconn) {
        /* disable SASL on the prot layer */
        prot_unsetsasl(imapd_out);
        prot_unsetsasl(imapd_in);

        reset_saslconn(&imapd_saslconn);
    }
}

/*
 * Perform a NOOP command
 */
static void cmd_noop(char *tag, char *cmd)
{
    if (backend_current) {
        /* remote mailbox */
        prot_printf(backend_current->out, "%s %s\r\n", tag, cmd);
        pipe_including_tag(backend_current, tag, 0);

        return;
    }

    index_check(imapd_index, 1, 0);

    prot_printf(imapd_out, "%s OK %s\r\n", tag,
                error_message(IMAP_OK_COMPLETED));
}

static void clear_id() {
    if (imapd_id.params) {
        freeattvalues(imapd_id.params);
    }
    memset(&imapd_id, 0, sizeof(struct id_data));
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
static void cmd_id(char *tag)
{
    int c = EOF, npair = 0;
    static struct buf arg, field;

    /* check if we've already had an ID in non-authenticated state */
    if (!imapd_userid && imapd_id.did_id) {
        prot_printf(imapd_out, "%s OK NIL\r\n", tag);
        eatline(imapd_in, c);
        return;
    }

    clear_id();

    /* ok, accept parameter list */
    c = getword(imapd_in, &arg);
    /* check for "NIL" or start of parameter list */
    if (strcasecmp(arg.s, "NIL") && c != '(') {
        prot_printf(imapd_out, "%s BAD Invalid parameter list in Id\r\n", tag);
        eatline(imapd_in, c);
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
                eatline(imapd_in, c);
                return;
            }

            /* get field value */
            c = getnstring(imapd_in, imapd_out, &arg);
            if (c != ' ' && c != ')') {
                prot_printf(imapd_out,
                            "%s BAD Invalid/missing value in Id\r\n",
                            tag);
                eatline(imapd_in, c);
                return;
            }

            /* ok, we're anal, but we'll still process the ID command */
            if (strlen(field.s) > MAXIDFIELDLEN) {
                prot_printf(imapd_out,
                            "%s BAD field longer than %u octets in Id\r\n",
                            tag, MAXIDFIELDLEN);
                eatline(imapd_in, c);
                return;
            }
            if (arg.len > MAXIDVALUELEN) {
                prot_printf(imapd_out,
                            "%s BAD value longer than %u octets in Id\r\n",
                            tag, MAXIDVALUELEN);
                eatline(imapd_in, c);
                return;
            }
            if (++npair > MAXIDPAIRS) {
                prot_printf(imapd_out,
                            "%s BAD too many (%u) field-value pairs in ID\r\n",
                            tag, MAXIDPAIRS);
                eatline(imapd_in, c);
                return;
            }

            if (!strcmp(field.s, "os") && !strcmp(arg.s, "iOS")) {
                imapd_id.quirks |= QUIRK_SEARCHFUZZY;
            }

            /* ok, we're happy enough */
            appendattvalue(&imapd_id.params, field.s, &arg);
        }

        if (c != ')') {
            /* erp! */
            prot_printf(imapd_out, "%s BAD trailing junk\r\n", tag);
            eatline(imapd_in, c);
            return;
        }
        c = prot_getc(imapd_in);
    }

    /* check for CRLF */
    if (!IS_EOL(c, imapd_in)) {
        prot_printf(imapd_out, "%s BAD Unexpected extra arguments to Id\r\n", tag);
        eatline(imapd_in, c);
        return;
    }

    /* log the client's ID string.
       eventually this should be a callback or something. */
    if (npair) {
        struct buf logbuf = BUF_INITIALIZER;
        struct attvaluelist *pptr;

        for (pptr = imapd_id.params; pptr; pptr = pptr->next) {
            const char *val = buf_cstring(&pptr->value);

            /* should we check for and format literals here ??? */
            buf_printf(&logbuf, " \"%s\" ", pptr->attrib);
            if (!val || !strcmp(val, "NIL"))
                buf_printf(&logbuf, "NIL");
            else
                buf_printf(&logbuf, "\"%s\"", val);
        }

        syslog(LOG_INFO, "client id sessionid=<%s>:%s", session_id(), buf_cstring(&logbuf));
        buf_free(&logbuf);
    }

    /* spit out our ID string.
       eventually this might be configurable. */
    if (config_getswitch(IMAPOPT_IMAPIDRESPONSE) &&
        (imapd_authstate || (config_serverinfo == IMAP_ENUM_SERVERINFO_ON))) {
        id_response(imapd_out);
        prot_printf(imapd_out, ")\r\n");
    }
    else if (config_serverinfo) {
        prot_printf(imapd_out, "* ID (");
        prot_printf(imapd_out, "\"name\" \"Cyrus IMAPD\"");
        if (config_serverinfo == IMAP_ENUM_SERVERINFO_ON) {
            prot_printf(imapd_out, " \"version\" \"%s\"", CYRUS_VERSION);
        }
        prot_printf(imapd_out, " \"vendor\" \"Project Cyrus\"");
        prot_printf(imapd_out, " \"support-url\" \"https://www.cyrusimap.org\"");
        prot_printf(imapd_out, ")\r\n");
    }
    else {
        prot_printf(imapd_out, "* ID NIL\r\n");
    }

    imapd_check(NULL, 0);

    prot_printf(imapd_out, "%s OK %s\r\n", tag,
                error_message(IMAP_OK_COMPLETED));

    imapd_id.did_id = 1;
}

static bool deadline_exceeded(const struct timespec *d)
{
    struct timespec now;

    if (d->tv_sec <= 0) {
        /* No deadline configured */
        return false;
    }

    errno = 0;
    if (clock_gettime(CLOCK_MONOTONIC, &now) == -1) {
        syslog(LOG_ERR, "clock_gettime (%d %m): error reading clock", errno);
        return false;
    }

    return now.tv_sec > d->tv_sec ||
           (now.tv_sec == d->tv_sec && now.tv_nsec > d->tv_nsec);
}

/*
 * Perform an IDLE command
 */
static void cmd_idle(char *tag)
{
    int c = EOF;
    int flags;
    static struct buf arg;
    static int idle_period = -1;
    static time_t idle_timeout = -1;
    struct timespec deadline = { 0, 0 };

    if (idle_timeout == -1) {
        idle_timeout = config_getduration(IMAPOPT_IMAPIDLETIMEOUT, 'm');
        if (idle_timeout <= 0) {
            idle_timeout = config_getduration(IMAPOPT_TIMEOUT, 'm');
        }
    }

    if (idle_timeout > 0) {
        errno = 0;
        if (clock_gettime(CLOCK_MONOTONIC, &deadline) == -1) {
            syslog(LOG_ERR, "clock_gettime (%d %m): error reading clock",
                   errno);
        } else {
            deadline.tv_sec += idle_timeout;
        }
    }

    if (!backend_current) {  /* Local mailbox */

        /* Tell client we are idling and waiting for end of command */
        prot_printf(imapd_out, "+ idling\r\n");
        prot_flush(imapd_out);

        /* Start doing mailbox updates */
        index_check(imapd_index, 1, 0);
        idle_start(index_mboxname(imapd_index));
        /* use this flag so if getc causes a shutdown due to
         * connection abort we tell idled about it */
        idling = 1;

        index_release(imapd_index);
        while ((flags = idle_wait(imapd_in->fd))) {
            if (deadline_exceeded(&deadline)) {
                syslog(LOG_DEBUG, "timeout for user '%s' while idling",
                       imapd_userid);
                shut_down(0);
                break;
            }

            if (flags & IDLE_INPUT) {
                /* Get continuation data */
                c = getword(imapd_in, &arg);
                break;
            }

            /* Send unsolicited untagged responses to the client */
            if (flags & IDLE_MAILBOX)
                index_check(imapd_index, 1, 0);

            if (flags & IDLE_ALERT) {
                char shut[MAX_MAILBOX_PATH+1];
                if (! imapd_userisadmin &&
                    (shutdown_file(shut, sizeof(shut)) ||
                     (imapd_userid &&
                      userdeny(imapd_userid, config_ident, shut, sizeof(shut))))) {
                    char *p;
                    for (p = shut; *p == '['; p++); /* can't have [ be first char */
                    prot_printf(imapd_out, "* BYE [ALERT] %s\r\n", p);
                    shut_down(0);
                }
            }

            index_release(imapd_index);
            prot_flush(imapd_out);
        }

        /* Stop updates and do any necessary cleanup */
        idling = 0;
        idle_stop(index_mboxname(imapd_index));
    }
    else {  /* Remote mailbox */
        int done = 0;
        enum { shutdown_skip, shutdown_bye, shutdown_silent } shutdown = shutdown_skip;
        char buf[2048];

        /* get polling period */
        if (idle_period == -1) {
            idle_period = config_getduration(IMAPOPT_IMAPIDLEPOLL, 's');
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
            if (deadline_exceeded(&deadline)) {
                syslog(LOG_DEBUG,
                       "timeout for user '%s' while idling on remote mailbox",
                       imapd_userid);
                shutdown = shutdown_silent;
                goto done;
            }

            /* Flush any buffered output */
            prot_flush(imapd_out);

            /* Check for shutdown file */
            if (!imapd_userisadmin &&
                (shutdown_file(buf, sizeof(buf)) ||
                 (imapd_userid &&
                  userdeny(imapd_userid, config_ident, buf, sizeof(buf))))) {
                done = 1;
                shutdown = shutdown_bye;
                goto done;
            }

            done = proxy_check_input(protin, imapd_in, imapd_out,
                                     backend_current->in, NULL, idle_period);

            /* If not running IDLE on backend, poll the mailbox for updates */
            if (!CAPA(backend_current, CAPA_IDLE)) {
                imapd_check(NULL, 0);
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

        switch (shutdown) {
        case shutdown_bye:
            ;
            char *p;

            for (p = buf; *p == '['; p++); /* can't have [ be first char */
            prot_printf(imapd_out, "* BYE [ALERT] %s\r\n", p);
            /* fallthrough */
            GCC_FALLTHROUGH

        case shutdown_silent:
            shut_down(0);
            break;
        case shutdown_skip:
        default:
            break;
        }
    }

    imapd_check(NULL, 1);

    if (c != EOF) {
        if (!strcasecmp(arg.s, "Done") && IS_EOL(c, imapd_in)) {
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


static void capa_response(int flags)
{
    const char *sasllist; /* the list of SASL mechanisms */
    int mechcount;
    int need_space = 0;
    int i;

    int lminus = config_getswitch(IMAPOPT_LITERALMINUS);

    for (i = 0; base_capabilities[i].str; i++) {
        const char *capa = base_capabilities[i].str;
        /* Filter capabilities if requested */
        if (capa_is_disabled(capa))
            continue;
        /* Don't show "MAILBOX-REFERRALS" if disabled by config */
        if (config_getswitch(IMAPOPT_PROXYD_DISABLE_MAILBOX_REFERRALS) &&
            !strcmp(capa, "MAILBOX-REFERRALS"))
            continue;
        /* Don't show "ANNOTATEMORE" if not enabled by config */
        if (!config_getswitch(IMAPOPT_ANNOTATION_ENABLE_LEGACY_COMMANDS) &&
            !strcmp(capa, "ANNOTATEMORE"))
            continue;
        /* Don't show if they're not shown at this level of login */
        if (!(base_capabilities[i].mask & flags))
            continue;
        /* cheap and nasty version of LITERAL- (RFC 7888) support - just say so */
        if (lminus && !strcmp(capa, "LITERAL+"))
            capa = "LITERAL-";
        /* print the capability */
        if (need_space) prot_putc(' ', imapd_out);
        else need_space = 1;
        prot_printf(imapd_out, "%s", base_capabilities[i].str);
    }

    if (config_mupdate_server) {
        prot_printf(imapd_out, " MUPDATE=mupdate://%s/", config_mupdate_server);
    }

    if (apns_enabled) {
        prot_printf(imapd_out, " XAPPLEPUSHSERVICE");
    }

    if (tls_enabled() && !imapd_starttls_done && !imapd_authstate) {
        prot_printf(imapd_out, " STARTTLS");
    }
    if (imapd_tls_required || imapd_authstate ||
        (!imapd_starttls_done && (extprops_ssf < 2) &&
         !config_getswitch(IMAPOPT_ALLOWPLAINTEXT))) {
        prot_printf(imapd_out, " LOGINDISABLED");
    }

    /* add the SASL mechs */
    if (!imapd_tls_required && (!imapd_authstate || saslprops.ssf) &&
        sasl_listmech(imapd_saslconn, NULL,
                      "AUTH=", " AUTH=",
                      !imapd_authstate ? " SASL-IR" : "", &sasllist,
                      NULL, &mechcount) == SASL_OK && mechcount > 0) {
        prot_printf(imapd_out, " %s", sasllist);
    } else {
        /* else don't show anything */
    }

    if (!(flags & CAPA_POSTAUTH)) return;

    if (imapd_authstate && imapd_userisadmin) {
        prot_printf(imapd_out, " UNAUTHENTICATE");
    }

    if (config_getswitch(IMAPOPT_CONVERSATIONS))
        prot_printf(imapd_out, " XCONVERSATIONS");

#ifdef HAVE_ZLIB
    if (!imapd_compress_done && !imapd_tls_comp) {
        prot_printf(imapd_out, " COMPRESS=DEFLATE");
    }
#endif // HAVE_ZLIB

    for (i = 0 ; i < QUOTA_NUMRESOURCES ; i++)
        prot_printf(imapd_out, " X-QUOTA=%s", quota_names[i]);

    if (idle_enabled()) {
        prot_printf(imapd_out, " IDLE");
    }

    prot_printf(imapd_out, " APPENDLIMIT=%zu", maxsize);
}

/*
 * Perform a CAPABILITY command
 */
static void cmd_capability(char *tag)
{
    imapd_check(NULL, 0);

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

static int getliteralsize(const char *p, int c, size_t maxsize,
                          unsigned *size, int *binary, const char **parseerr)

{
    int isnowait = 0;
    uint32_t num;

    /* Check for literal8 */
    if (*p == '~') {
        p++;
        *binary = 1;
    }

    /* check for start of literal */
    if (*p != '{') {
        *parseerr = "Missing required argument to Append command";
        return IMAP_PROTOCOL_ERROR;
    }

    /* Read size from literal */
    if (parseuint32(p+1, &p, &num)) {
        *parseerr = "Literal size not a number";
        return IMAP_PROTOCOL_ERROR;
    }

    if (*p == '+') {
        isnowait++;
        p++;
    }

    if (c == '\r') {
        c = prot_getc(imapd_in);
    }

    if (*p != '}' || p[1] || c != '\n') {
        *parseerr = "Invalid literal in Append command";
        return IMAP_PROTOCOL_ERROR;
    }

    if (num > maxsize)
        return IMAP_MESSAGE_TOO_LARGE;

    if (!isnowait) {
        /* Tell client to send the message */
        prot_printf(imapd_out, "+ go ahead\r\n");
        prot_flush(imapd_out);
    }

    *size = num;

    return 0;
}

static int catenate_text(FILE *f, size_t maxsize, unsigned *totalsize, int *binary,
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
    r = getliteralsize(arg.s, c, maxsize - *totalsize, &size, binary, parseerr);
    if (r) return r;

    /* Catenate message part to stage */
    while (size) {
        n = prot_read(imapd_in, buf, size > 4096 ? 4096 : size);
        if (!n) {
            syslog(LOG_ERR,
                   "DISCONNECT: client disconnected during upload of literal");
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
                        size_t maxsize, unsigned *totalsize, const char **parseerr)
{
    struct imapurl url;
    struct index_state *state;
    uint32_t msgno;
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
        *parseerr = "Cannot catenate messages from another server";
        r = IMAP_BADURL;
#endif
    } else if (!url.mailbox && !imapd_index && !cur_name) {
        *parseerr = "No mailbox is selected or specified";
        r = IMAP_BADURL;
    } else if (url.mailbox || (url.mailbox = cur_name)) {
        mbentry_t *mbentry = NULL;

        /* lookup the location of the mailbox */
        char *intname = mboxname_from_external(url.mailbox, &imapd_namespace, imapd_userid);
        r = mlookup(NULL, NULL, intname, &mbentry);

        if (!r && (mbentry->mbtype & MBTYPE_REMOTE)) {
            /* remote mailbox */
            struct backend *be;

            be = proxy_findserver(mbentry->server, &imap_protocol,
                                 proxy_userid, &backend_cached,
                                 &backend_current, &backend_inbox, imapd_in);
            if (be) {
                r = proxy_catenate_url(be, &url, f, maxsize - *totalsize, &size, parseerr);
                *totalsize += size;
            }
            else
                r = IMAP_SERVER_UNAVAILABLE;

            free(url.freeme);
            mboxlist_entry_free(&mbentry);
            free(intname);

            return r;
        }

        mboxlist_entry_free(&mbentry);

        /* local mailbox */
        if (!r) {
            struct index_init init;
            memset(&init, 0, sizeof(init));
            init.userid = imapd_userid;
            init.authstate = imapd_authstate;
            init.out = imapd_out;
            r = index_open(intname, &init, &state);
            if (init.vanishedlist) seqset_free(init.vanishedlist);
        }
        if (!r) doclose = 1;

        if (!r && !(state->myrights & ACL_READ))
            r = (imapd_userisadmin || (state->myrights & ACL_LOOKUP)) ?
                IMAP_PERMISSION_DENIED : IMAP_MAILBOX_NONEXISTENT;

        if (r) {
            *parseerr = error_message(r);
            r = IMAP_BADURL;
        }

        free(intname);
    } else {
        state = imapd_index;
    }

    if (r) {
        /* nothing to do, handled up top */
    } else if (url.uidvalidity &&
               (state->mailbox->i.uidvalidity != url.uidvalidity)) {
        *parseerr = "Uidvalidity of mailbox has changed";
        r = IMAP_BADURL;
    } else if (!url.uid || !(msgno = index_finduid(state, url.uid)) ||
               (index_getuid(state, msgno) != url.uid)) {
        *parseerr = "No such message in mailbox";
        r = IMAP_BADURL;
    } else {
        /* Catenate message part to stage */
        struct protstream *s = prot_new(fileno(f), 1);

        r = index_urlfetch(state, msgno, 0, url.section,
                           url.start_octet, url.octet_count, s,
                           maxsize - *totalsize, &size);
        if (r == IMAP_BADURL)
            *parseerr = "No such message part";
        else if (!r) {
            *totalsize += size;
        }

        prot_flush(s);
        prot_free(s);

        /* XXX  do we want to try and validate the message like
           we do in message_copy_strict()? */
    }

    free(url.freeme);

    if (doclose) index_close(&state);

    return r;
}

static int append_catenate(FILE *f, const char *cur_name, size_t maxsize, unsigned *totalsize,
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
            int r1 = catenate_text(f, maxsize, totalsize, binary, parseerr);
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
                r = catenate_url(arg.s, cur_name, f, maxsize, totalsize, parseerr);
                if (r) {
                    *url = arg.s;
                    return r;
                }
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
static void cmd_append(char *tag, char *name, const char *cur_name)
{
    int c;
    static struct buf arg;
    time_t now = time(NULL);
    quota_t qdiffs[QUOTA_NUMRESOURCES] = QUOTA_DIFFS_DONTCARE_INITIALIZER;
    unsigned size;
    int sync_seen = 0;
    int r;
    int i;
    struct appendstate appendstate;
    unsigned long uidvalidity = 0;
    long doappenduid = 0;
    const char *parseerr = NULL, *url = NULL;
    struct appendstage *curstage;
    mbentry_t *mbentry = NULL;

    memset(&appendstate, 0, sizeof(struct appendstate));

    /* See if we can append */
    char *intname = mboxname_from_external(name, &imapd_namespace, imapd_userid);
    r = mlookup(tag, name, intname, &mbentry);

    if (!r && (mbentry->mbtype & MBTYPE_REMOTE)) {
        /* remote mailbox */
        struct backend *s = NULL;

        if (supports_referrals) {
            imapd_refer(tag, mbentry->server, name);
            /* Eat the argument */
            eatline(imapd_in, prot_getc(imapd_in));
            mboxlist_entry_free(&mbentry);
            free(intname);
            return;
        }

        s = proxy_findserver(mbentry->server, &imap_protocol,
                             proxy_userid, &backend_cached,
                             &backend_current, &backend_inbox, imapd_in);
        if (!s) r = IMAP_SERVER_UNAVAILABLE;

        mboxlist_entry_free(&mbentry);

        imapd_check(s, 0);

        if (!r) {
            int is_active = 1;
            s->context = (void*) &is_active;
            if (imapd_index) {
                const char *mboxname = index_mboxname(imapd_index);
                prot_printf(s->out, "%s Localappend {" SIZE_T_FMT "+}\r\n%s"
                            " {" SIZE_T_FMT "+}\r\n%s ",
                            tag, strlen(name), name,
                            strlen(mboxname), mboxname);
            } else {
                prot_printf(s->out, "%s Localappend {" SIZE_T_FMT "+}\r\n%s"
                            " \"\" ", tag, strlen(name), name);
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
        free(intname);

        return;
    }

    mboxlist_entry_free(&mbentry);

    /* local mailbox */
    if (!r) {
        qdiffs[QUOTA_ANNOTSTORAGE] = 0;
        qdiffs[QUOTA_STORAGE] = 0;
        qdiffs[QUOTA_MESSAGE] = 1;
        r = append_check(intname, imapd_authstate, ACL_INSERT, ignorequota ? NULL : qdiffs);
    }
    if (r) {
        eatline(imapd_in, ' ');
        prot_printf(imapd_out, "%s NO %s%s\r\n",
                    tag,
                    (r == IMAP_MAILBOX_NONEXISTENT &&
                     mboxlist_createmailboxcheck(intname, 0, 0,
                                                 imapd_userisadmin,
                                                 imapd_userid, imapd_authstate,
                                                 NULL, NULL, 0) == 0)
                    ? "[TRYCREATE] " : "", error_message(r));
        free(intname);
        return;
    }

    c = ' '; /* just parsed a space */
    /* we loop, to support MULTIAPPEND */
    while (!r && c == ' ') {
        curstage = xzmalloc(sizeof(*curstage));
        ptrarray_push(&stages, curstage);

        /* now parsing "append-opts" in the ABNF */

        /* Parse flags */
        c = getword(imapd_in, &arg);
        if  (c == '(' && !arg.s[0]) {
            strarray_init(&curstage->flags);
            do {
                c = getword(imapd_in, &arg);
                if (!curstage->flags.count && !arg.s[0] && c == ')') break; /* empty list */
                if (!isokflag(arg.s, &sync_seen)) {
                    parseerr = "Invalid flag in Append command";
                    r = IMAP_PROTOCOL_ERROR;
                    goto done;
                }
                strarray_append(&curstage->flags, arg.s);
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
        }

        /* try to parse a sequence of "append-ext" */
        for (;;) {
            if (!strcasecmp(arg.s, "ANNOTATION")) {
                /* RFC 5257 */
                if (c != ' ') {
                    parseerr = "Missing annotation data in Append command";
                    r = IMAP_PROTOCOL_ERROR;
                    goto done;
                }
                c = parse_annotate_store_data(tag,
                                              /*permessage_flag*/1,
                                              &curstage->annotations);
                if (c == EOF) {
                    eatline(imapd_in, c);
                    goto cleanup;
                }
                qdiffs[QUOTA_ANNOTSTORAGE] += sizeentryatts(curstage->annotations);
                c = getword(imapd_in, &arg);
            }
            else
                break;  /* not a known extension keyword */
        }

        /* Stage the message */
        curstage->f = append_newstage(intname, now, stages.count, &(curstage->stage));
        if (!curstage->f) {
            r = IMAP_IOERROR;
            goto done;
        }

        /* now parsing "append-data" in the ABNF */

        if (!strcasecmp(arg.s, "CATENATE")) {
            if (c != ' ' || (c = prot_getc(imapd_in) != '(')) {
                parseerr = "Missing message part(s) in Append command";
                r = IMAP_PROTOCOL_ERROR;
                goto done;
            }

            /* Catenate the message part(s) to stage */
            size = 0;
            r = append_catenate(curstage->f, cur_name, maxsize, &size,
                                &(curstage->binary), &parseerr, &url);
            if (r) goto done;
        }
        else {
            /* Read size from literal */
            r = getliteralsize(arg.s, c, maxsize, &size, &(curstage->binary), &parseerr);
            if (!r && size == 0) r = IMAP_ZERO_LENGTH_LITERAL;
            if (r) goto done;

            /* Copy message to stage */
            r = message_copy_strict(imapd_in, curstage->f, size, curstage->binary);
        }
        qdiffs[QUOTA_STORAGE] += size;
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
        if (!IS_EOL(c, imapd_in)) {
            parseerr = "junk after literal";
            r = IMAP_PROTOCOL_ERROR;
            eatline(imapd_in, c);
        }
    }

    /* Append from the stage(s) */
    if (!r) {
        qdiffs[QUOTA_MESSAGE] = stages.count;
        r = append_setup(&appendstate, intname,
                         imapd_userid, imapd_authstate, ACL_INSERT,
                         ignorequota ? NULL : qdiffs, &imapd_namespace,
                         (imapd_userisadmin || imapd_userisproxyadmin),
                         EVENT_MESSAGE_APPEND);
    }
    if (!r) {
        /* make sure appending to this mailbox is allowed */
        r = insert_into_mailbox_allowed(appendstate.mailbox);
    }
    if (!r) {
        struct body *body;

        doappenduid = (appendstate.myrights & ACL_READ);
        uidvalidity = append_uidvalidity(&appendstate);

        for (i = 0; !r && i < stages.count ; i++) {
            curstage = stages.data[i];
            body = NULL;
            if (curstage->binary) {
                /* XXX we might have fname here, but it's hidden inside opaque
                 * curstage->stage field */
                r = message_parse_binary_file(curstage->f, &body, NULL);
                fclose(curstage->f);
                curstage->f = NULL;
            }
            if (!r) {
                r = append_fromstage(&appendstate, &body, curstage->stage,
                                     curstage->internaldate, /*createdmodseq*/0,
                                     &curstage->flags, 0,
                                     &curstage->annotations);
            }
            if (body) {
                /* Note: either the calls to message_parse_binary_file()
                 * or append_fromstage() above, may create a body.  */
                message_free_body(body);
                free(body);
                body = NULL;
            }
        }
    }
    if (!r) {
        r = append_commit(&appendstate);
    } else {
        append_abort(&appendstate);
    }

    imapd_check(NULL, 1);

    if (r == IMAP_PROTOCOL_ERROR && parseerr) {
        prot_printf(imapd_out, "%s BAD %s\r\n", tag, parseerr);
    } else if (r == IMAP_BADURL) {
        prot_printf(imapd_out, "%s NO [BADURL \"%s\"] %s\r\n",
                    tag, url, parseerr);
    } else if (r) {
        const char *respcode = "";
        if (r == IMAP_MAILBOX_NOTSUPPORTED) {
            respcode = "[CANNOT] ";
        }
        else if (r == IMAP_MESSAGE_TOO_LARGE) {
            respcode = "[TOOBIG] ";
        }
        else if (r == IMAP_MAILBOX_NONEXISTENT &&
                 mboxlist_createmailboxcheck(intname, 0, 0,
                                             imapd_userisadmin,
                                             imapd_userid, imapd_authstate,
                                             NULL, NULL, 0) == 0) {
            respcode = "[TRYCREATE] ";
        }
        prot_printf(imapd_out, "%s NO %s%s\r\n",
                    tag, respcode, error_message(r));
    } else if (doappenduid) {
        /* is this a space separated list or sequence list? */
        prot_printf(imapd_out, "%s OK [APPENDUID %lu ", tag, uidvalidity);
        if (appendstate.nummsg == 1) {
            prot_printf(imapd_out, "%u", appendstate.baseuid);
        } else {
            prot_printf(imapd_out, "%u:%u", appendstate.baseuid,
                        appendstate.baseuid + appendstate.nummsg - 1);
        }
        prot_printf(imapd_out, "] %s\r\n", error_message(IMAP_OK_COMPLETED));
    } else {
        index_release(imapd_index);
        sync_checkpoint(imapd_in);

        prot_printf(imapd_out, "%s OK %s\r\n", tag,
                    error_message(IMAP_OK_COMPLETED));
    }

cleanup:
    /* Cleanup the stage(s) */
    while ((curstage = ptrarray_pop(&stages))) {
        if (curstage->f != NULL) fclose(curstage->f);
        append_removestage(curstage->stage);
        strarray_fini(&curstage->flags);
        freeentryatts(curstage->annotations);
        free(curstage);
    }
    free(intname);
    ptrarray_fini(&stages);
}

/*
 * Warn if mailbox is close to or over any quota resource.
 *
 * Warn if the following possibilities occur:
 * - quotawarnkb not set + quotawarn hit
 * - quotawarnkb set larger than mailbox + quotawarn hit
 * - quotawarnkb set + hit + quotawarn hit
 * - quotawarnmsg not set + quotawarn hit
 * - quotawarnmsg set larger than mailbox + quotawarn hit
 * - quotawarnmsg set + hit + quotawarn hit
 */
static void warn_about_quota(const char *quotaroot)
{
    time_t now = time(NULL);
    struct quota q;
    int res;
    int r;
    int thresholds[QUOTA_NUMRESOURCES];
    int pc_threshold = config_getint(IMAPOPT_QUOTAWARN);
    int pc_usage;
    struct buf msg = BUF_INITIALIZER;
    static char lastqr[MAX_MAILBOX_PATH+1] = "";
    static time_t nextalert = 0;

    if (!quotaroot || !*quotaroot)
        return;     /* no quota, nothing to do */

    /* rate limit checks and warnings to every 10 min */
    if (!strcmp(quotaroot, lastqr) && now < nextalert)
        return;
    strlcpy(lastqr, quotaroot, sizeof(lastqr));
    nextalert = now + 600;

    quota_init(&q, quotaroot);
    r = quota_read_withconversations(&q);
    if (r)
        goto out;           /* failed to read */

    memset(thresholds, 0, sizeof(thresholds));
    thresholds[QUOTA_STORAGE] = config_getint(IMAPOPT_QUOTAWARNKB);
    thresholds[QUOTA_MESSAGE] = config_getint(IMAPOPT_QUOTAWARNMSG);
    thresholds[QUOTA_ANNOTSTORAGE] = config_getint(IMAPOPT_QUOTAWARNKB);

    for (res = 0 ; res < QUOTA_NUMRESOURCES ; res++) {
        if (q.limits[res] < 0)
            continue;       /* this resource is unlimited */
        buf_reset(&msg);

        if (thresholds[res] <= 0 ||
            thresholds[res] >= q.limits[res] ||
            q.useds[res] > ((quota_t) (q.limits[res] - thresholds[res])) * quota_units[res]) {

            pc_usage = (int)(((double) q.useds[res] * 100.0) /
                             (double) ((quota_t) q.limits[res] * quota_units[res]));

            if (q.useds[res] > (quota_t) q.limits[res] * quota_units[res])
                buf_printf(&msg, error_message(IMAP_NO_OVERQUOTA),
                           quota_names[res]);
            else if (pc_usage > pc_threshold)
                buf_printf(&msg, error_message(IMAP_NO_CLOSEQUOTA),
                           pc_usage, quota_names[res]);
        }

        if (msg.len)
            prot_printf(imapd_out, "* NO [ALERT] %s\r\n", buf_cstring(&msg));
    }

    buf_reset(&msg);
out:
    quota_free(&q);
}


/*
 * Perform a SELECT/EXAMINE/BBOARD command
 */
static void cmd_select(char *tag, char *cmd, char *name)
{
    int c;
    int r = 0;
    int doclose = 0;
    mbentry_t *mbentry = NULL;
    struct backend *backend_next = NULL;
    struct index_init init;
    int wasopen = 0;
    int allowdeleted = config_getswitch(IMAPOPT_ALLOWDELETED);
    struct vanished_params *v = &init.vanished;

    memset(&init, 0, sizeof(struct index_init));

    c = prot_getc(imapd_in);
    if (c == ' ') {
        static struct buf arg, parm1, parm2;

        c = prot_getc(imapd_in);
        if (c != '(') goto badlist;

        c = getword(imapd_in, &arg);
        if (arg.s[0] == '\0') goto badlist;
        for (;;) {
            ucase(arg.s);
            if (!strcmp(arg.s, "CONDSTORE")) {
                client_capa |= CAPA_CONDSTORE;
            }
            else if ((client_capa & CAPA_QRESYNC) &&
                     !strcmp(arg.s, "QRESYNC")) {
                char *p;

                if (c != ' ') goto badqresync;
                c = prot_getc(imapd_in);
                if (c != '(') goto badqresync;
                c = getastring(imapd_in, imapd_out, &arg);
                v->uidvalidity = strtoul(arg.s, &p, 10);
                if (*p || !v->uidvalidity || v->uidvalidity == ULONG_MAX) goto badqresync;
                if (c != ' ') goto badqresync;
                c = getmodseq(imapd_in, &v->modseq);
                if (c == EOF) goto badqresync;
                if (c == ' ') {
                    c = prot_getc(imapd_in);
                    if (c != '(') {
                        /* optional UID sequence */
                        prot_ungetc(c, imapd_in);
                        c = getword(imapd_in, &arg);
                        if (!imparse_issequence(arg.s)) goto badqresync;
                        v->sequence = arg.s;
                        if (c == ' ') {
                            c = prot_getc(imapd_in);
                            if (c != '(') goto badqresync;
                        }
                    }
                    if (c == '(') {
                        /* optional sequence match data */
                        c = getword(imapd_in, &parm1);
                        if (!imparse_issequence(parm1.s)) goto badqresync;
                        v->match_seq = parm1.s;
                        if (c != ' ') goto badqresync;
                        c = getword(imapd_in, &parm2);
                        if (!imparse_issequence(parm2.s)) goto badqresync;
                        v->match_uid = parm2.s;
                        if (c != ')') goto badqresync;
                        c = prot_getc(imapd_in);
                    }
                }
                if (c != ')') goto badqresync;
                c = prot_getc(imapd_in);
            }
            else if (!strcmp(arg.s, "ANNOTATE")) {
                /*
                 * RFC 5257 requires us to parse this keyword, which
                 * indicates that the client wants unsolicited
                 * ANNOTATION responses in this session, but we don't
                 * actually have to do anything with it, so we won't.
                 */
                ;
            }
            else if (allowdeleted && !strcmp(arg.s, "VENDOR.CMU-INCLUDE-EXPUNGED")) {
                init.want_expunged = 1;
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
    if (!IS_EOL(c, imapd_in)) {
        prot_printf(imapd_out,
                    "%s BAD Unexpected extra arguments to %s\r\n", tag, cmd);
        eatline(imapd_in, c);
        return;
    }

    if (imapd_index) {
        if (config_getswitch(IMAPOPT_AUTOEXPUNGE) && index_hasrights(imapd_index, ACL_EXPUNGE))
            index_expunge(imapd_index, NULL, 1);
        index_close(&imapd_index);
        wasopen = 1;
    }

    if (backend_current) {
        /* remove backend_current from the protgroup */
        protgroup_delete(protin, backend_current->in);
        wasopen = 1;
    }

    char *intname = mboxname_from_external(name, &imapd_namespace, imapd_userid);
    r = mlookup(tag, name, intname, &mbentry);
    if (r == IMAP_MAILBOX_MOVED) {
        free(intname);
        return;
    }

    if (!r && (mbentry->mbtype & MBTYPE_REMOTE)) {
        char mytag[128];

        if (supports_referrals) {
            imapd_refer(tag, mbentry->server, name);
            mboxlist_entry_free(&mbentry);
            free(intname);
            return;
        }

        backend_next = proxy_findserver(mbentry->server, &imap_protocol,
                                        proxy_userid, &backend_cached,
                                        &backend_current, &backend_inbox,
                                        imapd_in);
        if (!backend_next) r = IMAP_SERVER_UNAVAILABLE;

        if (backend_current && backend_current != backend_next) {
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
            mboxlist_entry_free(&mbentry);
            free(intname);
            return;
        }

        if (client_capa) {
            /* Enable client capabilities on new backend */
            proxy_gentag(mytag, sizeof(mytag));
            prot_printf(backend_current->out, "%s Enable", mytag);
            if (client_capa & CAPA_QRESYNC)
                prot_printf(backend_current->out, " Qresync");
            else if (client_capa & CAPA_CONDSTORE)
                prot_printf(backend_current->out, " Condstore");
            prot_printf(backend_current->out, "\r\n");
            pipe_until_tag(backend_current, mytag, 0);
        }

        /* Send SELECT command to backend */
        prot_printf(backend_current->out, "%s %s {" SIZE_T_FMT "+}\r\n%s",
                    tag, cmd, strlen(name), name);
        if (v->uidvalidity) {
            prot_printf(backend_current->out, " (QRESYNC (%lu " MODSEQ_FMT,
                        v->uidvalidity, v->modseq);
            if (v->sequence) {
                prot_printf(backend_current->out, " %s", v->sequence);
            }
            if (v->match_seq && v->match_uid) {
                prot_printf(backend_current->out, " (%s %s)",
                            v->match_seq, v->match_uid);
            }
            prot_printf(backend_current->out, "))");
        }
        prot_printf(backend_current->out, "\r\n");

        switch (pipe_including_tag(backend_current, tag, 0)) {
        case PROXY_OK:
            syslog(LOG_DEBUG, "open: user %s opened %s on %s",
                   imapd_userid, name, mbentry->server);

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

        mboxlist_entry_free(&mbentry);
        free(intname);

        return;
    }

    mboxlist_entry_free(&mbentry);

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

    if (wasopen) prot_printf(imapd_out, "* OK [CLOSED] Ok\r\n");

    init.userid = imapd_userid;
    init.authstate = imapd_authstate;
    init.out = imapd_out;
    init.examine_mode = (cmd[0] == 'E') || config_getswitch(IMAPOPT_READONLY);
    init.select = 1;
    if (!strcasecmpsafe(imapd_magicplus, "+dav")) init.want_dav = 1;

    if (!imapd_userisadmin && !allowdeleted && mboxname_isdeletedmailbox(intname, NULL))
        r = IMAP_MAILBOX_NONEXISTENT;
    else
        r = index_open(intname, &init, &imapd_index);
    if (!r) doclose = 1;

    if (!r && !index_hasrights(imapd_index, ACL_READ)) {
        r = (imapd_userisadmin || index_hasrights(imapd_index, ACL_LOOKUP)) ?
          IMAP_PERMISSION_DENIED : IMAP_MAILBOX_NONEXISTENT;
    }

    if (r) {
        prot_printf(imapd_out, "%s NO %s\r\n", tag, error_message(r));
        if (init.vanishedlist) seqset_free(init.vanishedlist);
        init.vanishedlist = NULL;
        if (doclose) index_close(&imapd_index);
        free(intname);
        return;
    }

    if (index_hasrights(imapd_index, ACL_EXPUNGE))
        warn_about_quota(imapd_index->mailbox->quotaroot);

    index_select(imapd_index, &init);

    if (init.vanishedlist) seqset_free(init.vanishedlist);
    init.vanishedlist = NULL;

    prot_printf(imapd_out, "%s OK [READ-%s] %s\r\n", tag,
                index_hasrights(imapd_index, ACL_READ_WRITE) ?
                "WRITE" : "ONLY", error_message(IMAP_OK_COMPLETED));

    syslog(LOG_DEBUG, "open: user %s opened %s", imapd_userid, name);
    free(intname);
    return;

 badlist:
    prot_printf(imapd_out, "%s BAD Invalid modifier list in %s\r\n", tag, cmd);
    eatline(imapd_in, c);
    return;

 badqresync:
    prot_printf(imapd_out, "%s BAD Invalid QRESYNC parameter list in %s\r\n",
                tag, cmd);
    eatline(imapd_in, c);
    return;
}

/*
 * Perform a CLOSE/UNSELECT command
 */
static void cmd_close(char *tag, char *cmd)
{
    if (backend_current) {
        /* remote mailbox */
        prot_printf(backend_current->out, "%s %s\r\n", tag, cmd);
        /* xxx do we want this to say OK if the connection is gone?
         * saying NO is clearly wrong, hense the fatal request. */
        pipe_including_tag(backend_current, tag, 0);

        /* remove backend_current from the protgroup */
        protgroup_delete(protin, backend_current->in);

        backend_current = NULL;
        return;
    }

    /* local mailbox */
    if ((cmd[0] == 'C' || config_getswitch(IMAPOPT_AUTOEXPUNGE)) && index_hasrights(imapd_index, ACL_EXPUNGE)) {
        index_expunge(imapd_index, NULL, 1);
        /* don't tell changes here */
    }

    index_close(&imapd_index);

    /* http://www.rfc-editor.org/errata_search.php?rfc=5162
     * Errata ID: 1808 - don't send HIGHESTMODSEQ to a close
     * command, because it can lose synchronisation */
    prot_printf(imapd_out, "%s OK %s\r\n",
                tag, error_message(IMAP_OK_COMPLETED));
}


/*
 * Append to the section list.
 */
static void section_list_append(struct section **l,
                                const char *name,
                                const struct octetinfo *oi)
{
    struct section **tail = l;

    while (*tail) tail = &(*tail)->next;

    *tail = xzmalloc(sizeof(struct section));
    (*tail)->name = xstrdup(name);
    (*tail)->octetinfo = *oi;
    (*tail)->next = NULL;
}

static void section_list_free(struct section *l)
{
    struct section *n;

    while (l) {
        n = l->next;
        free(l->name);
        free(l);
        l = n;
    }
}

/*
 * Parse the syntax for a partial fetch:
 *   "<" number "." nz-number ">"
 */
#define PARSE_PARTIAL(start_octet, octet_count) do {                    \
    (start_octet) = (octet_count) = 0;                                  \
    if (*p == '<' && Uisdigit(p[1])) {                                  \
        (start_octet) = p[1] - '0';                                     \
        p += 2;                                                         \
        while (Uisdigit((int) *p)) {                                    \
            (start_octet) =                                     \
                (start_octet) * 10 + *p++ - '0';                \
        }                                                               \
                                                                        \
        if (*p == '.' && p[1] >= '1' && p[1] <= '9') {                  \
            (octet_count) = p[1] - '0';                         \
            p[0] = '>'; p[1] = '\0'; /* clip off the octet count        \
                                        (its not used in the reply) */  \
            p += 2;                                                     \
            while (Uisdigit(*p)) {                                      \
                (octet_count) =                                 \
                    (octet_count) * 10 + *p++ - '0';            \
            }                                                           \
        }                                                               \
        else p--;                                                       \
                                                                        \
        if (*p != '>') {                                                \
            prot_printf(imapd_out,                                      \
                        "%s BAD Invalid body partial\r\n", tag);        \
            eatline(imapd_in, c);                                       \
            goto freeargs;                                              \
        }                                                               \
        p++;                                                            \
    }                                                                   \
} while(0)

static int parse_fetch_args(const char *tag, const char *cmd,
                            int allow_vanished,
                            struct fetchargs *fa)
{
    static struct buf fetchatt, fieldname;
    int c;
    int inlist = 0;
    char *p, *section;
    struct octetinfo oi;
    strarray_t *newfields = strarray_new();

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
                fa->fetchitems |= FETCH_ALL;
            }
            else if (!strcmp(fetchatt.s, "ANNOTATION")) {
                fa->fetchitems |= FETCH_ANNOTATION;
                if (c != ' ')
                    goto badannotation;
                c = prot_getc(imapd_in);
                if (c != '(')
                    goto badannotation;
                c = parse_annotate_fetch_data(tag,
                                              /*permessage_flag*/1,
                                              &fa->entries,
                                              &fa->attribs);
                if (c == EOF) {
                    eatline(imapd_in, c);
                    goto freeargs;
                }
                if (c != ')') {
badannotation:
                    prot_printf(imapd_out, "%s BAD invalid Annotation\r\n", tag);
                    eatline(imapd_in, c);
                    goto freeargs;
                }
                c = prot_getc(imapd_in);
            }
            else goto badatt;
            break;

        case 'B':
            if (!strcmp(fetchatt.s, "BASECID") &&
                config_getswitch(IMAPOPT_CONVERSATIONS)) {
                fa->fetchitems |= FETCH_BASECID;
            }
            else if (!strncmp(fetchatt.s, "BINARY[", 7) ||
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
                    fa->fetchitems |= FETCH_SETSEEN;
                }
                while (Uisdigit(*p) || *p == '.') {
                    if (*p == '.' && !Uisdigit(p[-1])) break;
                    /* Part number cannot begin with '0' */
                    if (*p == '0' && !Uisdigit(p[-1])) break;
                    p++;
                }

                if (*p != ']') {
                    prot_printf(imapd_out, "%s BAD Invalid binary section\r\n", tag);
                    eatline(imapd_in, c);
                    goto freeargs;
                }
                p++;

                if (!binsize) {
                    PARSE_PARTIAL(oi.start_octet, oi.octet_count);
                }

                if (*p) {
                    prot_printf(imapd_out, "%s BAD Junk after binary section\r\n", tag);
                    eatline(imapd_in, c);
                    goto freeargs;
                }
                if (binsize)
                    section_list_append(&fa->sizesections, section, &oi);
                else
                    section_list_append(&fa->binsections, section, &oi);
            }
            else if (!strcmp(fetchatt.s, "BODY")) {
                fa->fetchitems |= FETCH_BODY;
            }
            else if (!strcmp(fetchatt.s, "BODYSTRUCTURE")) {
                fa->fetchitems |= FETCH_BODYSTRUCTURE;
            }
            else if (!strncmp(fetchatt.s, "BODY[", 5) ||
                     !strncmp(fetchatt.s, "BODY.PEEK[", 10)) {
                p = section = fetchatt.s + 5;
                if (!strncmp(p, "PEEK[", 5)) {
                    p = section += 5;
                }
                else {
                    fa->fetchitems |= FETCH_SETSEEN;
                }
                while (Uisdigit(*p) || *p == '.') {
                    if (*p == '.' && !Uisdigit(p[-1])) break;
                    /* Obsolete section 0 can only occur before close brace */
                    if (*p == '0' && !Uisdigit(p[-1]) && p[1] != ']') break;
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
                        fa->cache_atleast = BIT32_MAX;
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
                        strarray_append(newfields, fieldname.s);
                        if (fa->cache_atleast < BIT32_MAX) {
                            bit32 this_ver =
                                mailbox_cached_header(fieldname.s);
                            if(this_ver > fa->cache_atleast)
                                fa->cache_atleast = this_ver;
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
                    appendfieldlist(&fa->fsections,
                                    section, newfields, fieldname.s,
                                    &oi, sizeof(oi));
                    /* old 'newfields' is managed by the fieldlist now */
                    newfields = strarray_new();
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
                section_list_append(&fa->bodysections, section, &oi);
            }
            else goto badatt;
            break;

        case 'C':
            if (!strcmp(fetchatt.s, "CID") &&
                config_getswitch(IMAPOPT_CONVERSATIONS)) {
                fa->fetchitems |= FETCH_CID;
            }
            else if (!strcmp(fetchatt.s, "CREATEDMODSEQ")) {
                fa->fetchitems |= FETCH_CREATEDMODSEQ;
            }
            else goto badatt;
            break;

        case 'D':
            if (!strcmp(fetchatt.s, "DIGEST.SHA1")) {
                fa->fetchitems |= FETCH_GUID;
            }
            else goto badatt;
            break;

        case 'E':
            if (!strcmp(fetchatt.s, "ENVELOPE")) {
                fa->fetchitems |= FETCH_ENVELOPE;
            }
            else if (!strcmp(fetchatt.s, "EMAILID")) {   /* RFC 8474 */
                fa->fetchitems |= FETCH_EMAILID;
            }
            else goto badatt;
            break;

        case 'F':
            if (!inlist && !strcmp(fetchatt.s, "FAST")) {
                fa->fetchitems |= FETCH_FAST;
            }
            else if (!inlist && !strcmp(fetchatt.s, "FULL")) {
                fa->fetchitems |= FETCH_FULL;
            }
            else if (!strcmp(fetchatt.s, "FLAGS")) {
                fa->fetchitems |= FETCH_FLAGS;
            }
            else if (!strcmp(fetchatt.s, "FOLDER")) {
                fa->fetchitems |= FETCH_FOLDER;
            }
            else goto badatt;
            break;

        case 'I':
            if (!strcmp(fetchatt.s, "INTERNALDATE")) {
                fa->fetchitems |= FETCH_INTERNALDATE;
            }
            else goto badatt;
            break;

        case 'L':
            if (!strcmp(fetchatt.s, "LASTUPDATED")) {
                fa->fetchitems |= FETCH_LASTUPDATED;
            }
            else goto badatt;
            break;

        case 'M':
            if (config_getswitch(IMAPOPT_CONVERSATIONS)
                && !strcmp(fetchatt.s, "MAILBOXES")) {
                fa->fetchitems |= FETCH_MAILBOXES;
            }
            else if (config_getswitch(IMAPOPT_CONVERSATIONS)
                && !strcmp(fetchatt.s, "MAILBOXIDS")) {
                fa->fetchitems |= FETCH_MAILBOXIDS;
            }
            else if (!strcmp(fetchatt.s, "MODSEQ")) {
                fa->fetchitems |= FETCH_MODSEQ;
            }
            else goto badatt;
            break;

        case 'P':
            if (!strcmp(fetchatt.s, "PREVIEW")) {
                fa->fetchitems |= FETCH_PREVIEW;
                if (c == ' ') {
                    c = prot_getc(imapd_in);
                    if (c == '(') {
                        c = ' ';
                        while (c == ' ') {
                            c = getword(imapd_in, &fieldname);
                            if (strcasecmp(fieldname.s, "LAZY")) {
                                prot_printf(imapd_out, "%s BAD FETCH contains invalid preview modifier (%s)\r\n", tag, fieldname.s);
                                eatline(imapd_in, c);
                                goto freeargs;
                            }
                        }
                        if (c == ')') c = prot_getc(imapd_in);
                        else {
                            prot_printf(imapd_out, "%s BAD PREVIEW list not finished.\r\n", tag);
                            eatline(imapd_in, c);
                            goto freeargs;
                        }
                    }
                    else {
                        prot_ungetc(c, imapd_in);
                        c = ' ';
                    }
                }
            }
            else goto badatt;
            break;

        case 'R':
            if (!strcmp(fetchatt.s, "RFC822")) {
                fa->fetchitems |= FETCH_RFC822|FETCH_SETSEEN;
            }
            else if (!strcmp(fetchatt.s, "RFC822.HEADER")) {
                fa->fetchitems |= FETCH_HEADER;
            }
            else if (!strcmp(fetchatt.s, "RFC822.PEEK")) {
                fa->fetchitems |= FETCH_RFC822;
            }
            else if (!strcmp(fetchatt.s, "RFC822.SIZE")) {
                fa->fetchitems |= FETCH_SIZE;
            }
            else if (!strcmp(fetchatt.s, "RFC822.TEXT")) {
                fa->fetchitems |= FETCH_TEXT|FETCH_SETSEEN;
            }
            else if (!strcmp(fetchatt.s, "RFC822.SHA1")) {
                fa->fetchitems |= FETCH_SHA1;
            }
            else if (!strcmp(fetchatt.s, "RFC822.FILESIZE")) {
                fa->fetchitems |= FETCH_FILESIZE;
            }
            else if (!strcmp(fetchatt.s, "RFC822.TEXT.PEEK")) {
                fa->fetchitems |= FETCH_TEXT;
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
                    strarray_append(strlen(fetchatt.s) == 19 ?
                                  &fa->headers : &fa->headers_not,
                                  fieldname.s);
                    if (strlen(fetchatt.s) != 19) {
                        fa->cache_atleast = BIT32_MAX;
                    }
                    if (fa->cache_atleast < BIT32_MAX) {
                        bit32 this_ver =
                            mailbox_cached_header(fieldname.s);
                        if(this_ver > fa->cache_atleast)
                            fa->cache_atleast = this_ver;
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

        case 'S':
            if (!strcmp(fetchatt.s, "SAVEDATE")) {
                fa->fetchitems |= FETCH_SAVEDATE;
            }
            else goto badatt;
            break;

        case 'T':
            if (!strcmp(fetchatt.s, "THREADID")) {   /* RFC 8474 */
                fa->fetchitems |= FETCH_THREADID;
            }
            else goto badatt;
            break;

        case 'U':
            if (!strcmp(fetchatt.s, "UID")) {
                fa->fetchitems |= FETCH_UID;
            }
            else if (!strcmp(fetchatt.s, "UIDVALIDITY")) {
                fa->fetchitems |= FETCH_UIDVALIDITY;
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
            if (!strcmp(fetchatt.s, "CHANGEDSINCE")) {
                if (c != ' ') {
                    prot_printf(imapd_out,
                                "%s BAD Missing required argument to %s %s\r\n",
                                tag, cmd, fetchatt.s);
                    eatline(imapd_in, c);
                    goto freeargs;
                }
                c = getmodseq(imapd_in, &fa->changedsince);
                if (c == EOF) {
                    prot_printf(imapd_out,
                                "%s BAD Invalid argument to %s %s\r\n",
                                tag, cmd, fetchatt.s);
                    eatline(imapd_in, c);
                    goto freeargs;
                }
                fa->fetchitems |= FETCH_MODSEQ;
            }
            else if (allow_vanished &&
                     !strcmp(fetchatt.s, "VANISHED")) {
                fa->vanished = 1;
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

    if (!IS_EOL(c, imapd_in)) {
        prot_printf(imapd_out, "%s BAD Unexpected extra arguments to %s\r\n", tag, cmd);
        eatline(imapd_in, c);
        goto freeargs;
    }

    if (!fa->fetchitems && !fa->bodysections && !fa->fsections &&
        !fa->binsections && !fa->sizesections &&
        !fa->headers.count && !fa->headers_not.count) {
        prot_printf(imapd_out, "%s BAD Missing required argument to %s\r\n", tag, cmd);
        goto freeargs;
    }

    if (fa->vanished && !fa->changedsince) {
        prot_printf(imapd_out, "%s BAD Missing required argument to %s\r\n", tag, cmd);
        goto freeargs;
    }

    if (fa->fetchitems & FETCH_MODSEQ) {
        if (!(client_capa & CAPA_CONDSTORE)) {
            client_capa |= CAPA_CONDSTORE;
            if (imapd_index)
                prot_printf(imapd_out, "* OK [HIGHESTMODSEQ " MODSEQ_FMT "] CONDSTORE enabled by MODSEQ fetch\r\n",
                        index_highestmodseq(imapd_index));
        }
    }

    if (fa->fetchitems & (FETCH_ANNOTATION|FETCH_FOLDER|FETCH_MAILBOXES)) {
        fa->namespace = &imapd_namespace;
        fa->userid = imapd_userid;
    }
    if (fa->fetchitems & FETCH_ANNOTATION) {
        fa->isadmin = imapd_userisadmin || imapd_userisproxyadmin;
        fa->authstate = imapd_authstate;
    }
    if (config_getswitch(IMAPOPT_CONVERSATIONS)
        && (fa->fetchitems & (FETCH_MAILBOXIDS|FETCH_MAILBOXES))) {
        // annoyingly, this codepath COULD be called from xconv* commands, but it never is,
        // in reality, so it's safe leaving this as shared
        int r = conversations_open_user(imapd_userid, 0/*shared*/, &fa->convstate);
        if (r) {
            syslog(LOG_WARNING, "error opening conversations for %s: %s",
                                imapd_userid,
                                error_message(r));
        }
    }

    strarray_free(newfields);
    return 0;

freeargs:
    strarray_free(newfields);
    return IMAP_PROTOCOL_BAD_PARAMETERS;
}

static void fetchargs_fini (struct fetchargs *fa)
{
    section_list_free(fa->binsections);
    section_list_free(fa->sizesections);
    section_list_free(fa->bodysections);
    freefieldlist(fa->fsections);
    strarray_fini(&fa->headers);
    strarray_fini(&fa->headers_not);
    strarray_fini(&fa->entries);
    strarray_fini(&fa->attribs);
    conversations_commit(&fa->convstate);

    memset(fa, 0, sizeof(struct fetchargs));
}

/*
 * Parse and perform a FETCH/UID FETCH command
 * The command has been parsed up to and including
 * the sequence
 */
static void cmd_fetch(char *tag, char *sequence, int usinguid)
{
    const char *cmd = usinguid ? "UID Fetch" : "Fetch";
    struct fetchargs fetchargs;
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

    r = parse_fetch_args(tag, cmd,
                         (usinguid && (client_capa & CAPA_QRESYNC)),
                         &fetchargs);
    if (r)
        goto freeargs;

    if (usinguid)
        fetchargs.fetchitems |= FETCH_UID;

    r = index_fetch(imapd_index, sequence, usinguid, &fetchargs,
                &fetchedsomething);

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
    fetchargs_fini(&fetchargs);
}

static void do_one_xconvmeta(struct conversations_state *state,
                             conversation_id_t cid,
                             conversation_t *conv,
                             struct dlist *itemlist)
{
    struct dlist *item = dlist_newpklist(NULL, "");
    struct dlist *fl;

    assert(conv);
    assert(itemlist);

    for (fl = itemlist->head; fl; fl = fl->next) {
        const char *key = dlist_cstring(fl);

        /* xxx - parse to a fetchitems? */
        if (!strcasecmp(key, "MODSEQ"))
            dlist_setnum64(item, "MODSEQ", conv->modseq);
        else if (!strcasecmp(key, "EXISTS"))
            dlist_setnum32(item, "EXISTS", conv->exists);
        else if (!strcasecmp(key, "UNSEEN"))
            dlist_setnum32(item, "UNSEEN", conv->unseen);
        else if (!strcasecmp(key, "SIZE"))
            dlist_setnum32(item, "SIZE", conv->size);
        else if (!strcasecmp(key, "COUNT")) {
            struct dlist *flist = dlist_newlist(item, "COUNT");
            fl = fl->next;
            if (dlist_isatomlist(fl)) {
                struct dlist *tmp;
                for (tmp = fl->head; tmp; tmp = tmp->next) {
                    const char *lookup = dlist_cstring(tmp);
                    int i = strarray_find_case(state->counted_flags, lookup, 0);
                    if (i >= 0) {
                        dlist_setflag(flist, "FLAG", lookup);
                        dlist_setnum32(flist, "COUNT", conv->counts[i]);
                    }
                }
            }
        }
        else if (!strcasecmp(key, "SENDERS")) {
            conv_sender_t *sender;
            struct dlist *slist = dlist_newlist(item, "SENDERS");
            for (sender = conv->senders; sender; sender = sender->next) {
                struct dlist *sli = dlist_newlist(slist, "");
                dlist_setatom(sli, "NAME", sender->name);
                dlist_setatom(sli, "ROUTE", sender->route);
                dlist_setatom(sli, "MAILBOX", sender->mailbox);
                dlist_setatom(sli, "DOMAIN", sender->domain);
            }
        }
        /* XXX - maybe rename FOLDERCOUNTS or something? */
        else if (!strcasecmp(key, "FOLDEREXISTS")) {
            struct dlist *flist = dlist_newlist(item, "FOLDEREXISTS");
            conv_folder_t *folder;
            fl = fl->next;
            if (dlist_isatomlist(fl)) {
                struct dlist *tmp;
                for (tmp = fl->head; tmp; tmp = tmp->next) {
                    const char *extname = dlist_cstring(tmp);
                    char *intname = mboxname_from_external(extname, &imapd_namespace, imapd_userid);
                    folder = conversation_find_folder(state, conv, intname);
                    free(intname);
                    dlist_setatom(flist, "MBOXNAME", extname);
                    /* ok if it's not there */
                    dlist_setnum32(flist, "EXISTS", folder ? folder->exists : 0);
                }
            }
        }
        else if (!strcasecmp(key, "FOLDERUNSEEN")) {
            struct dlist *flist = dlist_newlist(item, "FOLDERUNSEEN");
            conv_folder_t *folder;
            fl = fl->next;
            if (dlist_isatomlist(fl)) {
                struct dlist *tmp;
                for (tmp = fl->head; tmp; tmp = tmp->next) {
                    const char *extname = dlist_cstring(tmp);
                    char *intname = mboxname_from_external(extname, &imapd_namespace, imapd_userid);
                    folder = conversation_find_folder(state, conv, intname);
                    free(intname);
                    dlist_setatom(flist, "MBOXNAME", extname);
                    /* ok if it's not there */
                    dlist_setnum32(flist, "UNSEEN", folder ? folder->unseen : 0);
                }
            }
        }
        else {
            dlist_setatom(item, key, NULL); /* add a NIL response */
        }
    }

    prot_printf(imapd_out, "* XCONVMETA %s ", conversation_id_encode(cid));
    dlist_print(item, 0, imapd_out);
    prot_printf(imapd_out, "\r\n");

    dlist_free(&item);
}

static void do_xconvmeta(const char *tag,
                         struct conversations_state *state,
                         struct dlist *cidlist,
                         struct dlist *itemlist)
{
    conversation_id_t cid;
    struct dlist *dl;
    int r;

    for (dl = cidlist->head; dl; dl = dl->next) {
        const char *cidstr = dlist_cstring(dl);
        conversation_t *conv = NULL;

        if (!conversation_id_decode(&cid, cidstr) || !cid) {
            prot_printf(imapd_out, "%s BAD Invalid CID %s\r\n", tag, cidstr);
            return;
        }

        r = conversation_load(state, cid, &conv);
        if (r) {
            prot_printf(imapd_out, "%s BAD Failed to read %s\r\n", tag, cidstr);
            conversation_free(conv);
            return;
        }

        if (conv && conv->exists)
            do_one_xconvmeta(state, cid, conv, itemlist);

        conversation_free(conv);
    }

    prot_printf(imapd_out, "%s OK Completed\r\n", tag);
}

static int do_xbackup(const char *channel,
                      const ptrarray_t *list)
{
    int partial_success = 0;
    int mbox_count = 0;
    int i, r = 0;
    struct sync_client_state sync_cs = SYNC_CLIENT_STATE_INITIALIZER;

    sync_cs.servername = sync_get_config(channel, "sync_host");
    sync_cs.channel = channel;

    syslog(LOG_INFO, "XBACKUP: connecting to server '%s' for channel '%s'",
                     sync_cs.servername, channel);

    r = sync_connect(&sync_cs);
    if (r) {
        syslog(LOG_ERR, "XBACKUP: failed to connect to server '%s' for channel '%s'",
                        sync_cs.servername, channel);
        return r;
    }

    for (i = 0; i < list->count; i++) {
        const mbname_t *mbname = ptrarray_nth(list, i);
        if (!mbname) continue;
        const char *userid = mbname_userid(mbname);
        const char *intname = mbname_intname(mbname);
        const char *extname = mbname_extname(mbname, &imapd_namespace, NULL);

        if (userid) {
            syslog(LOG_INFO, "XBACKUP: replicating user %s", userid);

            r = sync_do_user(&sync_cs, userid, NULL);
        }
        else {
            struct sync_name_list *mboxname_list = sync_name_list_create();

            syslog(LOG_INFO, "XBACKUP: replicating mailbox %s", intname);
            sync_name_list_add(mboxname_list, intname);

            r = sync_do_mailboxes(&sync_cs, mboxname_list, NULL, sync_cs.flags);
            mbox_count++;
            sync_name_list_free(&mboxname_list);
        }

        if (r) {
            prot_printf(imapd_out, "* NO %s %s (%s)\r\n",
                        userid ? "USER" : "MAILBOX",
                        userid ? userid : extname,
                        error_message(r));
        }
        else {
            partial_success++;
            prot_printf(imapd_out, "* OK %s %s\r\n",
                        userid ? "USER" : "MAILBOX",
                        userid ? userid : extname);
        }
        prot_flush(imapd_out);

        /* send RESTART after each user, or 1000 mailboxes */
        if (!r && i < list->count - 1 && (userid || mbox_count >= 1000)) {
            mbox_count = 0;

            r = sync_do_restart(&sync_cs);
            if (r) goto done;
        }
    }

    /* send a final RESTART */
    sync_do_restart(&sync_cs);

    if (partial_success) r = 0;

done:
    sync_disconnect(&sync_cs);
    free(sync_cs.backend);

    return r;
}

static int xbackup_addmbox(struct findall_data *data, void *rock)
{
    if (!data) return 0;
    if (!data->is_exactmatch) return 0;
    ptrarray_t *list = (ptrarray_t *) rock;

    /* Only add shared mailboxes or user INBOXes */
    if (!mbname_localpart(data->mbname) ||
        (!mbname_isdeleted(data->mbname) &&
         !strarray_size(mbname_boxes(data->mbname)))) {

        ptrarray_append(list, mbname_dup(data->mbname));
    }

    return 0;
}

/* Parse and perform an XBACKUP command. */
void cmd_xbackup(const char *tag,
                 const char *mailbox,
                 const char *channel)
{
    ptrarray_t list = PTRARRAY_INITIALIZER;
    int i, r;

    /* admins only please */
    if (!imapd_userisadmin && !imapd_userisproxyadmin) {
        r = IMAP_PERMISSION_DENIED;
        goto done;
    }

    if (!config_getswitch(IMAPOPT_XBACKUP_ENABLED)) {
        /* shouldn't get here, but just in case */
        r = IMAP_PERMISSION_DENIED;
        goto done;
    }

    mboxlist_findall(NULL, mailbox, 1, NULL, NULL, xbackup_addmbox, &list);

    if (list.count) {
        r = do_xbackup(channel, &list);

        for (i = 0; i < list.count; i++) {
            mbname_t *mbname = ptrarray_nth(&list, i);
            if (mbname)
                mbname_free(&mbname);
        }
        ptrarray_fini(&list);
    }
    else {
        r = IMAP_MAILBOX_NONEXISTENT;
    }

done:
    imapd_check(NULL, 0);

    if (r) {
        prot_printf(imapd_out, "%s NO %s\r\n", tag, error_message(r));
    } else {
        prot_printf(imapd_out, "%s OK %s\r\n", tag,
                    error_message(IMAP_OK_COMPLETED));
    }
}

/*
 * Parse and perform a XCONVMETA command.
 */
void cmd_xconvmeta(const char *tag)
{
    int r;
    int c = ' ';
    struct conversations_state *state = NULL;
    struct dlist *cidlist = NULL;
    struct dlist *itemlist = NULL;

    if (backend_current) {
        /* remote mailbox */
        prot_printf(backend_current->out, "%s XCONVMETA ", tag);
        if (!pipe_command(backend_current, 65536)) {
            pipe_including_tag(backend_current, tag, 0);
        }
        return;
    }

    if (!config_getswitch(IMAPOPT_CONVERSATIONS)) {
        prot_printf(imapd_out, "%s BAD Unrecognized command\r\n", tag);
        eatline(imapd_in, c);
        goto done;
    }

    c = dlist_parse_asatomlist(&cidlist, 0, imapd_in);
    if (c != ' ') {
        prot_printf(imapd_out, "%s BAD Failed to parse CID list\r\n", tag);
        eatline(imapd_in, c);
        goto done;
    }

    c = dlist_parse_asatomlist(&itemlist, 0, imapd_in);
    if (!IS_EOL(c, imapd_in)) {
        prot_printf(imapd_out, "%s BAD Failed to parse item list\r\n", tag);
        eatline(imapd_in, c);
        goto done;
    }

    // this one is OK, xconvmeta doesn't do an expunge
    r = conversations_open_user(imapd_userid, 1/*shared*/, &state);
    if (r) {
        prot_printf(imapd_out, "%s BAD failed to open db: %s\r\n",
                    tag, error_message(r));
        goto done;
    }

    do_xconvmeta(tag, state, cidlist, itemlist);

 done:

    dlist_free(&itemlist);
    dlist_free(&cidlist);
    conversations_commit(&state);
}

/*
 * Parse and perform a XCONVFETCH command.
 */
void cmd_xconvfetch(const char *tag)
{
    int c = ' ';
    struct fetchargs fetchargs;
    int r;
    clock_t start = clock();
    modseq_t ifchangedsince = 0;
    char mytime[100];
    struct dlist *cidlist = NULL;
    struct dlist *item;

    if (backend_current) {
        /* remote mailbox */
        prot_printf(backend_current->out, "%s XCONVFETCH ", tag);
        if (!pipe_command(backend_current, 65536)) {
            pipe_including_tag(backend_current, tag, 0);
        }
        return;
    }

    if (!config_getswitch(IMAPOPT_CONVERSATIONS)) {
        prot_printf(imapd_out, "%s BAD Unrecognized command\r\n", tag);
        eatline(imapd_in, c);
        return;
    }

    /* local mailbox */
    memset(&fetchargs, 0, sizeof(struct fetchargs));

    c = dlist_parse_asatomlist(&cidlist, 0, imapd_in);
    if (c != ' ')
        goto syntax_error;

    /* check CIDs */
    for (item = cidlist->head; item; item = item->next) {
        if (!dlist_ishex64(item)) {
            prot_printf(imapd_out, "%s BAD Invalid CID\r\n", tag);
            eatline(imapd_in, c);
            goto freeargs;
        }
    }

    c = getmodseq(imapd_in, &ifchangedsince);
    if (c != ' ')
        goto syntax_error;

    r = parse_fetch_args(tag, "Xconvfetch", 0, &fetchargs);
    if (r)
        goto freeargs;
    fetchargs.fetchitems |= (FETCH_UIDVALIDITY|FETCH_FOLDER);
    fetchargs.namespace = &imapd_namespace;
    fetchargs.userid = imapd_userid;

    r = do_xconvfetch(cidlist, ifchangedsince, &fetchargs);

    snprintf(mytime, sizeof(mytime), "%2.3f",
             (clock() - start) / (double) CLOCKS_PER_SEC);

    if (r) {
        prot_printf(imapd_out, "%s NO %s (%s sec)\r\n", tag,
                    error_message(r), mytime);
    } else {
        prot_printf(imapd_out, "%s OK Completed (%s sec)\r\n",
                    tag, mytime);
    }

freeargs:
    dlist_free(&cidlist);
    fetchargs_fini(&fetchargs);
    return;

syntax_error:
    prot_printf(imapd_out, "%s BAD Syntax error\r\n", tag);
    eatline(imapd_in, c);
    dlist_free(&cidlist);
    fetchargs_fini(&fetchargs);
}

static int xconvfetch_lookup(struct conversations_state *statep,
                             conversation_id_t cid,
                             modseq_t ifchangedsince,
                             hash_table *wanted_cids,
                             strarray_t *folder_list)
{
    const char *key = conversation_id_encode(cid);
    conversation_t *conv = NULL;
    conv_folder_t *folder;
    int r;

    r = conversation_load(statep, cid, &conv);
    if (r) return r;

    if (!conv)
        goto out;

    if (!conv->exists)
        goto out;

    /* output the metadata for this conversation */
    {
        struct dlist *dl = dlist_newlist(NULL, "");
        dlist_setatom(dl, "", "MODSEQ");
        do_one_xconvmeta(statep, cid, conv, dl);
        dlist_free(&dl);
    }

    if (ifchangedsince >= conv->modseq)
        goto out;

    hash_insert(key, (void *)1, wanted_cids);

    for (folder = conv->folders; folder; folder = folder->next) {
        /* no contents */
        if (!folder->exists)
            continue;

        /* finally, something worth looking at */
        strarray_add(folder_list, strarray_nth(statep->folders, folder->number));
    }

out:
    conversation_free(conv);
    return 0;
}

static int do_xconvfetch(struct dlist *cidlist,
                         modseq_t ifchangedsince,
                         struct fetchargs *fetchargs)
{
    struct conversations_state *state = NULL;
    int r = 0;
    struct index_state *index_state = NULL;
    struct dlist *dl;
    hash_table wanted_cids = HASH_TABLE_INITIALIZER;
    strarray_t folder_list = STRARRAY_INITIALIZER;
    struct index_init init;
    int i;

    // this one expunges each mailbox it enters, so we need to lock exclusively
    r = conversations_open_user(imapd_userid, 0/*shared*/, &state);
    if (r) goto out;

    construct_hash_table(&wanted_cids, 1024, 0);

    for (dl = cidlist->head; dl; dl = dl->next) {
        r = xconvfetch_lookup(state, dlist_num(dl), ifchangedsince,
                              &wanted_cids, &folder_list);
        if (r) goto out;
    }

    /* unchanged, woot */
    if (!folder_list.count)
        goto out;

    fetchargs->cidhash = &wanted_cids;

    memset(&init, 0, sizeof(struct index_init));
    init.userid = imapd_userid;
    init.authstate = imapd_authstate;
    init.out = imapd_out;

    for (i = 0; i < folder_list.count; i++) {
        const char *mboxname;
        mbentry_t *mbentry = NULL;

        if (state->folders_byname) mboxname = folder_list.data[i];
        else {
            mboxlist_lookup_by_uniqueid(folder_list.data[i], &mbentry, NULL);
            if (!mbentry) continue;
            mboxname = mbentry->name;
        }

        r = index_open(mboxname, &init, &index_state);
        mboxlist_entry_free(&mbentry);
        if (r == IMAP_MAILBOX_NONEXISTENT)
            continue;
        if (r)
            goto out;

        index_checkflags(index_state, 0, 0);

        /* make sure \Deleted messages are expunged.  Will also lock the
         * mailbox state and read any new information */
        r = index_expunge(index_state, NULL, 1);

        if (!r)
            index_fetchresponses(index_state, NULL, /*usinguid*/1,
                                 fetchargs, NULL);

        index_close(&index_state);

        if (r) goto out;
    }

    r = 0;

out:
    index_close(&index_state);
    conversations_commit(&state);
    free_hash_table(&wanted_cids, NULL);
    strarray_fini(&folder_list);
    return r;
}

#undef PARSE_PARTIAL /* cleanup */

/*
 * Parse and perform a STORE/UID STORE command
 * The command has been parsed up to and including
 * the sequence
 */
static void cmd_store(char *tag, char *sequence, int usinguid)
{
    const char *cmd = usinguid ? "UID Store" : "Store";
    struct storeargs storeargs;
    static struct buf operation, flagname;
    int len, c;
    int flagsparsed = 0, inlist = 0;
    char *modified = NULL;
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
    storeargs.unchangedsince = ~0ULL;
    storeargs.usinguid = usinguid;
    strarray_init(&storeargs.flags);

    c = prot_getc(imapd_in);
    if (c == '(') {
        /* Grab/parse the modifier(s) */
        static struct buf storemod;

        do {
            c = getword(imapd_in, &storemod);
            ucase(storemod.s);
            if (!strcmp(storemod.s, "UNCHANGEDSINCE")) {
                if (c != ' ') {
                    prot_printf(imapd_out,
                                "%s BAD Missing required argument to %s %s\r\n",
                                tag, cmd, storemod.s);
                    eatline(imapd_in, c);
                    return;
                }
                c = getmodseq(imapd_in, &storeargs.unchangedsince);
                if (c == EOF) {
                    prot_printf(imapd_out,
                                "%s BAD Invalid argument to %s UNCHANGEDSINCE\r\n",
                                tag, cmd);
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
        storeargs.operation = STORE_ADD_FLAGS;
    }
    else if (!strcmp(operation.s, "-flags")) {
        storeargs.operation = STORE_REMOVE_FLAGS;
    }
    else if (!strcmp(operation.s, "flags")) {
        storeargs.operation = STORE_REPLACE_FLAGS;
    }
    else if (!strcmp(operation.s, "annotation")) {
        storeargs.operation = STORE_ANNOTATION;
        /* ANNOTATION has implicit .SILENT behaviour */
        storeargs.silent = 1;

        c = parse_annotate_store_data(tag, /*permessage_flag*/1,
                                      &storeargs.entryatts);
        if (c == EOF) {
            eatline(imapd_in, c);
            goto freeflags;
        }
        storeargs.namespace = &imapd_namespace;
        storeargs.isadmin = imapd_userisadmin;
        storeargs.userid = imapd_userid;
        storeargs.authstate = imapd_authstate;
        goto notflagsdammit;
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
        else
            strarray_append(&storeargs.flags, flagname.s);

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
notflagsdammit:
    if (!IS_EOL(c, imapd_in)) {
        prot_printf(imapd_out, "%s BAD Unexpected extra arguments to %s\r\n", tag, cmd);
        eatline(imapd_in, c);
        goto freeflags;
    }

    if ((storeargs.unchangedsince != ULONG_MAX) &&
        !(client_capa & CAPA_CONDSTORE)) {
        client_capa |= CAPA_CONDSTORE;
        prot_printf(imapd_out, "* OK [HIGHESTMODSEQ " MODSEQ_FMT "] CONDSTORE enabled by UNCHANGEDSINCE\r\n",
                    index_highestmodseq(imapd_index));
    }

    r = index_store(imapd_index, sequence, &storeargs);

    /* format the MODIFIED response code */
    if (storeargs.modified) {
        char *seqstr = seqset_cstring(storeargs.modified);
        assert(seqstr);
        modified = strconcat("[MODIFIED ", seqstr, "] ", (char *)NULL);
        free(seqstr);
    }
    else {
        modified = xstrdup("");
    }

    if (r) {
        prot_printf(imapd_out, "%s NO %s%s\r\n",
                    tag, modified, error_message(r));
    }
    else {
        index_release(imapd_index);
        sync_checkpoint(imapd_in);

        prot_printf(imapd_out, "%s OK %s%s\r\n",
                    tag, modified, error_message(IMAP_OK_COMPLETED));
    }

 freeflags:
    strarray_fini(&storeargs.flags);
    freeentryatts(storeargs.entryatts);
    seqset_free(storeargs.modified);
    free(modified);
}

static void cmd_search(char *tag, int usinguid)
{
    int c;
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
    searchargs = new_searchargs(tag, GETSEARCH_CHARSET_KEYWORD|GETSEARCH_RETURN,
                                &imapd_namespace, imapd_userid, imapd_authstate,
                                imapd_userisadmin || imapd_userisproxyadmin);

    /* Set FUZZY search according to config and quirks */
    static const char *annot = IMAP_ANNOT_NS "search-fuzzy-always";
    char *inbox = mboxname_user_mbox(imapd_userid, NULL);
    struct buf val = BUF_INITIALIZER;
    if (imapd_id.quirks & QUIRK_SEARCHFUZZY) {
        /* Quirks overrule anything */
        searchargs->fuzzy_depth++;
    }
    else if (!annotatemore_lookupmask(inbox, annot, imapd_userid, &val) && val.len) {
        /* User may override global config */
        int b = config_parse_switch(buf_cstring(&val));
        if (b > 0 || (b < 0 && config_getswitch(IMAPOPT_SEARCH_FUZZY_ALWAYS))) {
            searchargs->fuzzy_depth++;
        }
    }
    else if (config_getswitch(IMAPOPT_SEARCH_FUZZY_ALWAYS)) {
        /* Use global config */
        searchargs->fuzzy_depth++;
    }
    buf_free(&val);
    free(inbox);

    c = get_search_program(imapd_in, imapd_out, searchargs);
    if (c == EOF) {
        eatline(imapd_in, ' ');
        freesearchargs(searchargs);
        return;
    }

    if (!IS_EOL(c, imapd_in)) {
        prot_printf(imapd_out, "%s BAD Unexpected extra arguments to Search\r\n", tag);
        eatline(imapd_in, c);
        freesearchargs(searchargs);
        return;
    }

    if (searchargs->charset == CHARSET_UNKNOWN_CHARSET) {
        prot_printf(imapd_out, "%s NO %s\r\n", tag,
               error_message(IMAP_UNRECOGNIZED_CHARSET));
    }
    else {
        n = index_search(imapd_index, searchargs, usinguid);
        int r = cmd_cancelled(/*insearch*/1);
        if (!r) {
            snprintf(mytime, sizeof(mytime), "%2.3f",
                    (clock() - start) / (double) CLOCKS_PER_SEC);
            prot_printf(imapd_out, "%s OK %s (%d msgs in %s secs)\r\n", tag,
                        error_message(IMAP_OK_COMPLETED), n, mytime);
        }
        else {
            prot_printf(imapd_out, "%s NO %s\r\n", tag, error_message(r));
        }
    }

    freesearchargs(searchargs);
}

/*
 * Perform a SORT/UID SORT command
 */
static void cmd_sort(char *tag, int usinguid)
{
    int c;
    struct buf arg = BUF_INITIALIZER;
    struct sortcrit *sortcrit = NULL;
    struct searchargs *searchargs = NULL;
    clock_t start = clock();
    char mytime[100];
    int n;

    if (backend_current) {
        /* remote mailbox */
        const char *cmd = usinguid ? "UID Sort" : "Sort";

        prot_printf(backend_current->out, "%s %s ", tag, cmd);
        if (!pipe_command(backend_current, 65536)) {
            pipe_including_tag(backend_current, tag, 0);
        }
        return;
    }

    /* local mailbox */
    searchargs = new_searchargs(tag, GETSEARCH_CHARSET_FIRST,
                                &imapd_namespace, imapd_userid, imapd_authstate,
                                imapd_userisadmin || imapd_userisproxyadmin);
    if (imapd_id.quirks & QUIRK_SEARCHFUZZY)
        searchargs->fuzzy_depth++;

    /* See if its ESORT */
    c = getword(imapd_in, &arg);
    if (c == EOF) goto error;
    else if (c == ' ' && !strcasecmp(arg.s, "return")) {   /* RFC 5267 */
        c = get_search_return_opts(imapd_in, imapd_out, searchargs);
        if (c != ' ') goto error;
    }
    else prot_ungetc(c, imapd_in);

    c = getsortcriteria(tag, &sortcrit);
    if (c == EOF) goto error;

    c = get_search_program(imapd_in, imapd_out, searchargs);
    if (c == EOF) goto error;

    if (!IS_EOL(c, imapd_in)) {
        prot_printf(imapd_out,
                    "%s BAD Unexpected extra arguments to Sort\r\n", tag);
        goto error;
    }

    n = index_sort(imapd_index, sortcrit, searchargs, usinguid);
    snprintf(mytime, sizeof(mytime), "%2.3f",
             (clock() - start) / (double) CLOCKS_PER_SEC);
    if (CONFIG_TIMING_VERBOSE) {
        char *s = sortcrit_as_string(sortcrit);
        syslog(LOG_DEBUG, "SORT (%s) processing time: %d msg in %s sec",
               s, n, mytime);
        free(s);
    }
    prot_printf(imapd_out, "%s OK %s (%d msgs in %s secs)\r\n", tag,
                error_message(IMAP_OK_COMPLETED), n, mytime);

    buf_free(&arg);
    freesortcrit(sortcrit);
    freesearchargs(searchargs);
    return;

error:
    eatline(imapd_in, (c == EOF ? ' ' : c));
    buf_free(&arg);
    freesortcrit(sortcrit);
    freesearchargs(searchargs);
}

/*
 * Perform a XCONVSORT or XCONVUPDATES command
 */
void cmd_xconvsort(char *tag, int updates)
{
    int c;
    struct sortcrit *sortcrit = NULL;
    struct searchargs *searchargs = NULL;
    struct windowargs *windowargs = NULL;
    struct index_init init;
    struct index_state *oldstate = NULL;
    struct conversations_state *cstate = NULL;
    clock_t start = clock();
    char mytime[100];
    int r;

    if (backend_current) {
        /* remote mailbox */
        const char *cmd = "Xconvsort";

        prot_printf(backend_current->out, "%s %s ", tag, cmd);
        if (!pipe_command(backend_current, 65536)) {
            pipe_including_tag(backend_current, tag, 0);
        }
        return;
    }
    assert(imapd_index);

    if (!config_getswitch(IMAPOPT_CONVERSATIONS)) {
        prot_printf(imapd_out, "%s BAD Unrecognized command\r\n", tag);
        eatline(imapd_in, ' ');
        return;
    }

    c = getsortcriteria(tag, &sortcrit);
    if (c == EOF) goto error;

    if (c != ' ') {
        prot_printf(imapd_out, "%s BAD Missing window args in XConvSort\r\n",
                    tag);
        goto error;
    }

    c = parse_windowargs(tag, &windowargs, updates);
    if (c != ' ')
        goto error;

    /* open the conversations state first - we don't care if it fails,
     * because that probably just means it's already open */
    // this codepath might expunge, so we can't open shared
    conversations_open_mbox(index_mboxname(imapd_index), 0/*shared*/, &cstate);

    if (updates) {
        /* in XCONVUPDATES, need to force a re-read from scratch into
         * a new index, because we ask for deleted messages */

        oldstate = imapd_index;
        imapd_index = NULL;

        memset(&init, 0, sizeof(struct index_init));
        init.userid = imapd_userid;
        init.authstate = imapd_authstate;
        init.out = imapd_out;
        init.want_expunged = 1;

        r = index_open(index_mboxname(oldstate), &init, &imapd_index);
        if (r) {
            prot_printf(imapd_out, "%s NO %s\r\n", tag,
                        error_message(r));
            goto error;
        }

        index_checkflags(imapd_index, 0, 0);
    }

    /* need index loaded to even parse searchargs! */
    searchargs = new_searchargs(tag, GETSEARCH_CHARSET_FIRST,
                                &imapd_namespace, imapd_userid, imapd_authstate,
                                imapd_userisadmin || imapd_userisproxyadmin);
    c = get_search_program(imapd_in, imapd_out, searchargs);
    if (c == EOF) goto error;

    if (!IS_EOL(c, imapd_in)) {
        prot_printf(imapd_out,
                    "%s BAD Unexpected extra arguments to Xconvsort\r\n", tag);
        goto error;
    }

    if (updates)
        r = index_convupdates(imapd_index, sortcrit, searchargs, windowargs);
    else
        r = index_convsort(imapd_index, sortcrit, searchargs, windowargs);

    if (oldstate) {
        index_close(&imapd_index);
        imapd_index = oldstate;
    }

    if (r < 0) {
        prot_printf(imapd_out, "%s NO %s\r\n", tag,
                    error_message(r));
        goto error;
    }

    snprintf(mytime, sizeof(mytime), "%2.3f",
             (clock() - start) / (double) CLOCKS_PER_SEC);
    if (CONFIG_TIMING_VERBOSE) {
        char *s = sortcrit_as_string(sortcrit);
        syslog(LOG_DEBUG, "XCONVSORT (%s) processing time %s sec",
               s, mytime);
        free(s);
    }
    prot_printf(imapd_out, "%s OK %s (in %s secs)\r\n", tag,
                error_message(IMAP_OK_COMPLETED), mytime);

out:
    if (cstate) conversations_commit(&cstate);
    freesortcrit(sortcrit);
    freesearchargs(searchargs);
    free_windowargs(windowargs);
    return;

error:
    if (cstate) conversations_commit(&cstate);
    if (oldstate) {
        if (imapd_index) index_close(&imapd_index);
        imapd_index = oldstate;
    }
    eatline(imapd_in, (c == EOF ? ' ' : c));
    goto out;
}

/*
 * Perform a XCONVMULTISORT command.  This is like XCONVSORT but returns
 * search results from multiple folders.  It still requires a selected
 * mailbox, for two reasons:
 *
 * a) it's a useful shorthand for choosing what the current
 * conversations scope is, and
 *
 * b) the code to parse a search program currently relies on a selected
 * mailbox.
 *
 * Unlike ESEARCH it doesn't take folder names for scope, instead the
 * search scope is implicitly the current conversation scope.  This is
 * implemented more or less by accident because both the Sphinx index
 * and the conversations database are hardcoded to be per-user.
 */
static void cmd_xconvmultisort(char *tag)
{
    int c;
    struct sortcrit *sortcrit = NULL;
    struct searchargs *searchargs = NULL;
    struct windowargs *windowargs = NULL;
    struct conversations_state *cstate = NULL;
    clock_t start = clock();
    char mytime[100];
    int r;

    if (backend_current) {
        /* remote mailbox */
        const char *cmd = "Xconvmultisort";

        prot_printf(backend_current->out, "%s %s ", tag, cmd);
        if (!pipe_command(backend_current, 65536)) {
            pipe_including_tag(backend_current, tag, 0);
        }
        return;
    }
    assert(imapd_index);

    if (!config_getswitch(IMAPOPT_CONVERSATIONS)) {
        prot_printf(imapd_out, "%s BAD Unrecognized command\r\n", tag);
        eatline(imapd_in, ' ');
        return;
    }

    c = getsortcriteria(tag, &sortcrit);
    if (c == EOF) goto error;

    if (c != ' ') {
        prot_printf(imapd_out, "%s BAD Missing window args in XConvMultiSort\r\n",
                    tag);
        goto error;
    }

    c = parse_windowargs(tag, &windowargs, /*updates*/0);
    if (c != ' ')
        goto error;

    /* open the conversations state first - we don't care if it fails,
     * because that probably just means it's already open */
    // this codepath might expunge, so we can't open shared
    conversations_open_mbox(index_mboxname(imapd_index), 0/*shared*/, &cstate);

    /* need index loaded to even parse searchargs! */
    searchargs = new_searchargs(tag, GETSEARCH_CHARSET_FIRST,
                                &imapd_namespace, imapd_userid, imapd_authstate,
                                imapd_userisadmin || imapd_userisproxyadmin);
    c = get_search_program(imapd_in, imapd_out, searchargs);
    if (c == EOF) goto error;

    if (!IS_EOL(c, imapd_in)) {
        prot_printf(imapd_out,
                    "%s BAD Unexpected extra arguments to XconvMultiSort\r\n", tag);
        goto error;
    }

    r = index_convmultisort(imapd_index, sortcrit, searchargs, windowargs);

    if (r < 0) {
        prot_printf(imapd_out, "%s NO %s\r\n", tag,
                    error_message(r));
        goto error;
    }

    snprintf(mytime, sizeof(mytime), "%2.3f",
             (clock() - start) / (double) CLOCKS_PER_SEC);
    if (CONFIG_TIMING_VERBOSE) {
        char *s = sortcrit_as_string(sortcrit);
        syslog(LOG_DEBUG, "XCONVMULTISORT (%s) processing time %s sec",
               s, mytime);
        free(s);
    }
    prot_printf(imapd_out, "%s OK %s (in %s secs)\r\n", tag,
                error_message(IMAP_OK_COMPLETED), mytime);

out:
    if (cstate) conversations_commit(&cstate);
    freesortcrit(sortcrit);
    freesearchargs(searchargs);
    free_windowargs(windowargs);
    return;

error:
    if (cstate) conversations_commit(&cstate);
    eatline(imapd_in, (c == EOF ? ' ' : c));
    goto out;
}

static void cmd_xsnippets(char *tag)
{
    int c;
    struct searchargs *searchargs = NULL;
    struct snippetargs *snippetargs = NULL;
    clock_t start = clock();
    char mytime[100];
    int r;

    if (backend_current) {
        /* remote mailbox */
        const char *cmd = "Xsnippets";

        prot_printf(backend_current->out, "%s %s ", tag, cmd);
        if (!pipe_command(backend_current, 65536)) {
            pipe_including_tag(backend_current, tag, 0);
        }
        return;
    }
    assert(imapd_index);

    c = get_snippetargs(&snippetargs);
    if (c == EOF) {
        prot_printf(imapd_out, "%s BAD Syntax error in snippet arguments\r\n", tag);
        goto error;
    }
    if (c != ' ') {
        prot_printf(imapd_out,
                    "%s BAD Unexpected arguments in Xsnippets\r\n", tag);
        goto error;
    }

    /* need index loaded to even parse searchargs! */
    searchargs = new_searchargs(tag, GETSEARCH_CHARSET_FIRST,
                                &imapd_namespace, imapd_userid, imapd_authstate,
                                imapd_userisadmin || imapd_userisproxyadmin);
    c = get_search_program(imapd_in, imapd_out, searchargs);
    if (c == EOF) goto error;

    if (!IS_EOL(c, imapd_in)) {
        prot_printf(imapd_out,
                    "%s BAD Unexpected extra arguments to Xsnippets\r\n", tag);
        goto error;
    }

    r = index_snippets(imapd_index, snippetargs, searchargs);

    if (r < 0) {
        prot_printf(imapd_out, "%s NO %s\r\n", tag,
                    error_message(r));
        goto error;
    }

    snprintf(mytime, sizeof(mytime), "%2.3f",
             (clock() - start) / (double) CLOCKS_PER_SEC);
    prot_printf(imapd_out, "%s OK %s (in %s secs)\r\n", tag,
                error_message(IMAP_OK_COMPLETED), mytime);

out:
    freesearchargs(searchargs);
    free_snippetargs(&snippetargs);
    return;

error:
    eatline(imapd_in, (c == EOF ? ' ' : c));
    goto out;
}

static void cmd_xstats(char *tag)
{
    int metric;

    if (backend_current) {
        /* remote mailbox */
        const char *cmd = "Xstats";

        prot_printf(backend_current->out, "%s %s ", tag, cmd);
        if (!pipe_command(backend_current, 65536)) {
            pipe_including_tag(backend_current, tag, 0);
        }
        return;
    }

    prot_printf(imapd_out, "* XSTATS");
    for (metric = 0 ; metric < XSTATS_NUM_METRICS ; metric++)
        prot_printf(imapd_out, " %s %u", xstats_names[metric], xstats[metric]);
    prot_printf(imapd_out, "\r\n");

    prot_printf(imapd_out, "%s OK %s\r\n", tag,
                error_message(IMAP_OK_COMPLETED));
    return;
}

/*
 * Perform a THREAD/UID THREAD command
 */
static void cmd_thread(char *tag, int usinguid)
{
    static struct buf arg;
    int c;
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

    searchargs = new_searchargs(tag, GETSEARCH_CHARSET_FIRST,
                                &imapd_namespace, imapd_userid, imapd_authstate,
                                imapd_userisadmin || imapd_userisproxyadmin);
    c = get_search_program(imapd_in, imapd_out, searchargs);
    if (c == EOF) {
        eatline(imapd_in, ' ');
        freesearchargs(searchargs);
        return;
    }

    if (!IS_EOL(c, imapd_in)) {
        prot_printf(imapd_out,
                    "%s BAD Unexpected extra arguments to Thread\r\n", tag);
        eatline(imapd_in, c);
        freesearchargs(searchargs);
        return;
    }

    n = index_thread(imapd_index, alg, searchargs, usinguid);
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
static void cmd_copy(char *tag, char *sequence, char *name, int usinguid, int ismove)
{
    int r, myrights = 0;
    char *copyuid = NULL;
    mbentry_t *mbentry = NULL;

    char *intname = mboxname_from_external(name, &imapd_namespace, imapd_userid);
    r = mlookup(NULL, NULL, intname, &mbentry);

    if (!r) myrights = cyrus_acl_myrights(imapd_authstate, mbentry->acl);

    if (!r && backend_current) {
        /* remote mailbox -> local or remote mailbox */

        /* xxx  start of separate proxy-only code
           (remove when we move to a unified environment) */
        struct backend *s = NULL;

        s = proxy_findserver(mbentry->server, &imap_protocol,
                             proxy_userid, &backend_cached,
                             &backend_current, &backend_inbox, imapd_in);
        mboxlist_entry_free(&mbentry);
        if (!s) {
            r = IMAP_SERVER_UNAVAILABLE;
            goto done;
        }

        if (s != backend_current) {
            /* this is the hard case; we have to fetch the messages and append
               them to the other mailbox */

            proxy_copy(tag, sequence, name, myrights, usinguid, s);
            goto cleanup;
        }
        /* xxx  end of separate proxy-only code */

        /* simply send the COPY to the backend */
        prot_printf(
                backend_current->out,
                "%s %s %s {" SIZE_T_FMT "+}\r\n%s\r\n",
                tag,
                usinguid ? (ismove ? "UID Move" : "UID Copy") : (ismove ? "Move" : "Copy"),
                sequence,
                strlen(name),
                name
            );

        pipe_including_tag(backend_current, tag, 0);

        goto cleanup;
    }
    else if (!r && (mbentry->mbtype & MBTYPE_REMOTE)) {
        /* local mailbox -> remote mailbox
         *
         * fetch the messages and APPEND them to the backend
         *
         * xxx  completely untested
         */
        struct backend *s = NULL;
        int res;

        s = proxy_findserver(mbentry->server, &imap_protocol,
                             proxy_userid, &backend_cached,
                             &backend_current, &backend_inbox, imapd_in);
        mboxlist_entry_free(&mbentry);
        if (!s) r = IMAP_SERVER_UNAVAILABLE;
        else if (!CAPA(s, CAPA_MULTIAPPEND)) {
            /* we need MULTIAPPEND for atomicity */
            r = IMAP_REMOTE_NO_MULTIAPPEND;
        }

        if (r) goto done;

        assert(!ismove); /* XXX - support proxying moves */

        /* start the append */
        prot_printf(s->out, "%s Append {" SIZE_T_FMT "+}\r\n%s",
                    tag, strlen(name), name);

        /* append the messages */
        r = index_copy_remote(imapd_index, sequence, usinguid, s->out);

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
                    if (appenduid) {
                        appenduid += strlen("[appenduid ");
                        b = strchr(appenduid, ']');
                        if (b) *b = '\0';
                        prot_printf(imapd_out, "%s OK [COPYUID %s] %s\r\n", tag,
                                    appenduid, error_message(IMAP_OK_COMPLETED));
                    } else
                        prot_printf(imapd_out, "%s OK %s\r\n", tag,
                                    error_message(IMAP_OK_COMPLETED));
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

        goto cleanup;
    }

    /* need permission to delete from source if it's a move */
    if (!r && ismove && !(imapd_index->myrights & ACL_EXPUNGE))
        r = IMAP_PERMISSION_DENIED;

    /* local mailbox -> local mailbox */
    if (!r) {
        r = index_copy(imapd_index, sequence, usinguid, intname,
                       &copyuid, !config_getswitch(IMAPOPT_SINGLEINSTANCESTORE),
                       &imapd_namespace,
                       (imapd_userisadmin || imapd_userisproxyadmin), ismove,
                       ignorequota);
    }

    if (ismove && copyuid && !r) {
        prot_printf(imapd_out, "* OK [COPYUID %s] %s\r\n",
                    copyuid, error_message(IMAP_OK_COMPLETED));
        free(copyuid);
        copyuid = NULL;
    }

    imapd_check(NULL, ismove || usinguid);

  done:

    if (r && !(usinguid && r == IMAP_NO_NOSUCHMSG)) {
        const char *respcode = "";
        if (r == IMAP_MAILBOX_NOTSUPPORTED) {
            respcode = "[CANNOT] ";
        }
        else if (r == IMAP_MAILBOX_NONEXISTENT &&
                 mboxlist_createmailboxcheck(intname, 0, 0,
                                             imapd_userisadmin,
                                             imapd_userid, imapd_authstate,
                                             NULL, NULL, 0) == 0) {
            respcode = "[TRYCREATE] ";
        }
        prot_printf(imapd_out, "%s NO %s%s\r\n", tag,
                    respcode, error_message(r));
    }
    else if (copyuid) {
            prot_printf(imapd_out, "%s OK [COPYUID %s] %s\r\n", tag,
                        copyuid, error_message(IMAP_OK_COMPLETED));
            free(copyuid);
    }
    else {
        index_release(imapd_index);
        sync_checkpoint(imapd_in);

        prot_printf(imapd_out, "%s OK %s\r\n", tag,
                    error_message(IMAP_OK_COMPLETED));
    }

cleanup:
    mboxlist_entry_free(&mbentry);
    free(intname);
}

/*
 * Perform an EXPUNGE command
 * sequence == NULL if this isn't a UID EXPUNGE
 */
static void cmd_expunge(char *tag, char *sequence)
{
    modseq_t old;
    modseq_t new;
    int r = 0;

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
    if (!index_hasrights(imapd_index, ACL_EXPUNGE))
        r = IMAP_PERMISSION_DENIED;

    old = index_highestmodseq(imapd_index);

    if (!r) r = index_expunge(imapd_index, sequence, 1);
    /* tell expunges */
    if (!r) index_tellchanges(imapd_index, 1, sequence ? 1 : 0, 0);

    if (r) {
        prot_printf(imapd_out, "%s NO %s\r\n", tag, error_message(r));
        return;
    }

    new = index_highestmodseq(imapd_index);

    index_release(imapd_index);
    sync_checkpoint(imapd_in);

    prot_printf(imapd_out, "%s OK ", tag);
    if (new > old)
        prot_printf(imapd_out, "[HIGHESTMODSEQ " MODSEQ_FMT "] ", new);
    prot_printf(imapd_out, "%s\r\n", error_message(IMAP_OK_COMPLETED));
}

/*
 * Perform a CREATE command
 */
static void cmd_create(char *tag, char *name, struct dlist *extargs, int localonly)
{
    int r = 0;
    int mbtype = MBTYPE_EMAIL;
    int options = 0;
    const char *partition = NULL;
    const char *server = NULL;
    const char *uniqueid = NULL;
    struct buf specialuse = BUF_INITIALIZER;
    struct dlist *use;
    struct mailbox *mailbox = NULL;
    char *mailboxid = NULL;
    mbentry_t *parent = NULL;

    /* We don't care about trailing hierarchy delimiters. */
    if (name[0] && name[strlen(name)-1] == imapd_namespace.hier_sep) {
        name[strlen(name)-1] = '\0';
    }

    mbname_t *mbname = mbname_from_extname(name, &imapd_namespace, imapd_userid);

    struct mboxlock *namespacelock = mboxname_usernamespacelock(mbname_intname(mbname));

    const char *type = NULL;

    dlist_getatom(extargs, "PARTITION", &partition);
    dlist_getatom(extargs, "SERVER", &server);
    dlist_getatom(extargs, "MAILBOXID", &uniqueid);
    if (dlist_getatom(extargs, "TYPE", &type)) {
        if (!strcasecmp(type, "CALENDAR")) mbtype = MBTYPE_CALENDAR;
        else if (!strcasecmp(type, "COLLECTION")) mbtype = MBTYPE_COLLECTION;
        else if (!strcasecmp(type, "ADDRESSBOOK")) mbtype = MBTYPE_ADDRESSBOOK;
        else {
            r = IMAP_MAILBOX_BADTYPE;
            goto err;
        }
    }
    use = dlist_getchild(extargs, "USE");
    if (use) {
        /* only user mailboxes can have specialuse, and they must be user toplevel folders */
        if (!mbname_userid(mbname) || strarray_size(mbname_boxes(mbname)) != 1) {
            r = IMAP_MAILBOX_SPECIALUSE;
            goto err;
        }
        /* I would much prefer to create the specialuse annotation FIRST
         * and do the sanity check on the values, so we can return the
         * correct error.  Sadly, that's a pain - so we compromise by
         * "normalising" first */
        struct dlist *item;
        char *raw;
        strarray_t *su = strarray_new();
        for (item = use->head; item; item = item->next) {
            strarray_append(su, dlist_cstring(item));
        }
        raw = strarray_join(su, " ");
        strarray_free(su);
        r = specialuse_validate(NULL, imapd_userid, raw, &specialuse, 0);
        free(raw);
        if (r) {
            prot_printf(imapd_out, "%s NO [USEATTR] %s\r\n", tag, error_message(r));
            goto done;
        }

        if (strstr(buf_cstring(&specialuse), "\\Snoozed"))
            options |= OPT_IMAP_HAS_ALARMS;
    }

    // A non-admin is not allowed to specify the server nor partition on which
    // to create the mailbox.
    //
    // However, this only applies to frontends. If we're a backend, a frontend will
    // proxy the partition it wishes to create the mailbox on.
    if ((server || partition || uniqueid) && !imapd_userisadmin) {
        if (config_mupdate_config == IMAP_ENUM_MUPDATE_CONFIG_STANDARD ||
            config_mupdate_config == IMAP_ENUM_MUPDATE_CONFIG_UNIFIED) {

            if (!config_getstring(IMAPOPT_PROXYSERVERS)) {
                r = IMAP_PERMISSION_DENIED;
                goto err;
            }
        }
    }

    /* check for INBOX.INBOX creation by broken Apple clients */
    const strarray_t *boxes = mbname_boxes(mbname);
    if (strarray_size(boxes) > 1
        && !strcasecmp(strarray_nth(boxes, 0), "INBOX")
        && !strcasecmp(strarray_nth(boxes, 1), "INBOX"))
        r = IMAP_MAILBOX_BADNAME;

    if (r) {
    err:
        prot_printf(imapd_out, "%s NO %s\r\n", tag, error_message(r));
        goto done;
    }

    // If the create command does not mandate the mailbox must be created
    // locally, let's go and find the most appropriate location.
    if (!localonly) {

        // If we're running in a Murder, things get more complicated.
        if (config_mupdate_server) {

            // Consider your actions on a per type of topology basis.
            //
            // First up: Standard / discrete murder topology, with dedicated
            // imap frontends, or unified -- both allow the IMAP server to either
            // need to proxy through, or create locally.
            if (
                    config_mupdate_config == IMAP_ENUM_MUPDATE_CONFIG_STANDARD ||
                    config_mupdate_config == IMAP_ENUM_MUPDATE_CONFIG_UNIFIED
                ) {

                // The way that we detect whether we're a frontend is by testing
                // for the proxy servers setting ... :/
                if (!config_getstring(IMAPOPT_PROXYSERVERS)) {
                    // Find the parent mailbox, if any.
                    // mboxlist_findparent either supplies the parent
                    // or has a return code of IMAP_MAILBOX_NONEXISTENT.
                    r = mboxlist_findparent(mbname_intname(mbname), &parent);

                    if (r) {
                        if (r != IMAP_MAILBOX_NONEXISTENT) {
                            prot_printf(imapd_out, "%s NO %s (%s:%d)\r\n", tag, error_message(r), __FILE__, __LINE__);
                            goto done;
                        }
                    }

                    if (!server && !partition) {
                        if (!parent) {
                            server = find_free_server();

                            if (!server) {
                                prot_printf(imapd_out, "%s NO %s\r\n", tag, error_message(IMAP_SERVER_UNAVAILABLE));
                                goto done;
                            }

                        } else {
                            server = parent->server;
                            /* DO NOT set the partition:
                               only admins are allowed to do this
                               and the backend will use the partition
                               of the parent by default anyways.

                            partition = parent->partition;
                            */
                        }
                    }

                    struct backend *s_conn = NULL;

                    s_conn = proxy_findserver(
                            server,
                            &imap_protocol,
                            proxy_userid,
                            &backend_cached,
                            &backend_current,
                            &backend_inbox,
                            imapd_in
                        );

                    if (!s_conn) {
                        prot_printf(imapd_out, "%s NO %s\r\n", tag, error_message(IMAP_SERVER_UNAVAILABLE));
                        goto done;
                    }

                    // Huh?
                    if (imapd_userisadmin && supports_referrals) {
                        // "They are not an admin remotely, so let's refer them" --
                        //  - Who is they?
                        //  - How did imapd_userisadmin get set all of a sudden?
                        imapd_refer(tag, server, name);
                        referral_kick = 1;
                        return;
                    }

                    if (!CAPA(s_conn, CAPA_MUPDATE)) {
                        // Huh?
                        // "reserve mailbox on MUPDATE"
                        syslog(LOG_WARNING, "backend %s is not advertising any MUPDATE capability (%s:%d)", server, __FILE__, __LINE__);
                    }

                    // why not send a LOCALCREATE to the backend?
                    prot_printf(s_conn->out, "%s CREATE ", tag);
                    prot_printastring(s_conn->out, name);

                    // special use needs extended support, so pass through extargs
                    if (specialuse.len || uniqueid) {
                        prot_printf(s_conn->out, " (");
                        int printsp = 0;
                        if (specialuse.len) {
                            if (printsp) prot_putc(' ', s_conn->out);
                            printsp = 1;
                            prot_printf(s_conn->out, "USE (%s)", buf_cstring(&specialuse));
                        }

                        if (partition) {
                            if (printsp) prot_putc(' ', s_conn->out);
                            printsp = 1;
                            prot_printf(s_conn->out, "PARTITION ");
                            prot_printastring(s_conn->out, partition);
                        }

                        if (uniqueid) {
                            if (printsp) prot_putc(' ', s_conn->out);
                            printsp = 1;
                            prot_printf(s_conn->out, "MAILBOXID ");
                            prot_printastring(s_conn->out, uniqueid);
                        }

                        prot_putc(')', s_conn->out);
                    }

                    // Send partition as an atom, since its supported by older servers
                    else if (partition) {
                        prot_putc(' ', s_conn->out);
                        prot_printastring(s_conn->out, partition);
                    }

                    prot_printf(s_conn->out, "\r\n");

                    int res = pipe_until_tag(s_conn, tag, 0);

                    if (!CAPA(s_conn, CAPA_MUPDATE)) {
                        // Huh?
                        // "do MUPDATE create operations"
                        syslog(LOG_WARNING, "backend %s is not advertising any MUPDATE capability (%s:%d)", server, __FILE__, __LINE__);
                    }

                    /* make sure we've seen the update */
                    if (ultraparanoid && res == PROXY_OK) kick_mupdate();

                    imapd_check(s_conn, 0);

                    prot_printf(imapd_out, "%s %s", tag, s_conn->last_result.s);

                    goto done;

                } else { // (!config_getstring(IMAPOPT_PROXYSERVERS))
                    // I have a standard murder config but also proxy servers configured; I'm a backend!
                    goto localcreate;

                } // (!config_getstring(IMAPOPT_PROXYSERVERS))

            } // (config_mupdate_config == IMAP_ENUM_MUPDATE_CONFIG_STANDARD)

            else if (config_mupdate_config == IMAP_ENUM_MUPDATE_CONFIG_REPLICATED) {
                // Everything is local
                goto localcreate;
            } // (config_mupdate_config == IMAP_ENUM_MUPDATE_CONFIG_REPLICATED)

            else {
                syslog(LOG_ERR, "murder configuration I cannot deal with");
                prot_printf(imapd_out, "%s NO %s\r\n", tag, error_message(IMAP_SERVER_UNAVAILABLE));
                goto done;
            }

        } else { // (config_mupdate_server)
            // I'm no part of a Murder, *everything* is localcreate
            goto localcreate;
        } // (config_mupdate_server)

    } else { // (!localonly)
        goto localcreate;
    }

localcreate:
    // XXX  Do we want a config option for this?
    // find the nearest ancestor to see if we have to fill out the branch
    r = mboxlist_findparent(mbname_intname(mbname), &parent);
    if (r == IMAP_MAILBOX_NONEXISTENT) r = 0;

    if (!r && (parent || !mbname_userid(mbname))) {
        mbname_t *ancestor = mbname_from_intname(parent ? parent->name : NULL);
        int oldest = strarray_size(mbname_boxes(ancestor));
        int youngest = strarray_size(boxes) - 1;

        // any missing ancestors?
        if (youngest > oldest) {
            // verify that we can create the requested mailbox
            // before creating its ancestors
            r = mboxlist_createmailboxcheck(mbname_intname(mbname),
                                            mbtype, partition,
                                            imapd_userisadmin
                                            || imapd_userisproxyadmin,
                                            imapd_userid, imapd_authstate,
                                            NULL, NULL, 0);

            int i;
            for (i = oldest; !r && i < youngest; i++) {
                // create the ancestors
                mbname_push_boxes(ancestor, strarray_nth(boxes, i));

                /* Don't create any magic user.foo.INBOX mailboxes */
                if (mbname_userid(ancestor) != NULL &&
                    strarray_size(mbname_boxes(ancestor)) == 1 &&
                    !strcmp(strarray_nth(mbname_boxes(ancestor), 0), "INBOX")) {
                    continue;
                }

                r = mboxlist_createmailbox(mbname_intname(ancestor),
                                           mbtype, partition,
                                           imapd_userisadmin
                                           || imapd_userisproxyadmin,
                                           imapd_userid, imapd_authstate,
                                           localonly, localonly, 0, 1, NULL);
                if (r) {
                    // XXX  should we delete the ancestors we just created?
                    break;
                }
            }
        }

        mbname_free(&ancestor);
    }
    if (r) {
        prot_printf(imapd_out, "%s NO %s\r\n", tag, error_message(r));
        goto done;
    }


    // now create the requested mailbox
    r = mboxlist_createmailbox_opts(
            mbname_intname(mbname),                             // const char *name
            mbtype,                                             // int mbtype
            partition,                                          // const char *partition
            imapd_userisadmin || imapd_userisproxyadmin,        // int isadmin
            imapd_userid,                                       // const char *userid
            imapd_authstate,                                    // struct auth_state *auth_state
            options,                                            // options
            localonly,                                          // int localonly
            localonly,                                          // int forceuser
            0,                                                  // int dbonly
            1,                                                  // int notify
            uniqueid,                                           // const char *uniqueid
            &mailbox                                            // struct mailbox **mailboxptr
        );

#ifdef USE_AUTOCREATE
    // Clausing autocreate for the INBOX
    if (r == IMAP_PERMISSION_DENIED) {
        if (!strarray_size(mbname_boxes(mbname)) && !strcmpsafe(imapd_userid, mbname_userid(mbname))) {
            int autocreatequotastorage = config_getint(IMAPOPT_AUTOCREATE_QUOTA);

            if (autocreatequotastorage > 0) {
                r = mboxlist_createmailbox(
                        mbname_intname(mbname),
                        0,
                        partition,
                        1,
                        imapd_userid,
                        imapd_authstate,
                        0,
                        0,
                        0,
                        1,
                        &mailbox
                    );

                if (r) {
                    prot_printf(imapd_out, "%s NO %s\r\n", tag, error_message(r));
                    goto done;
                }

                int autocreatequotamessage = config_getint(IMAPOPT_AUTOCREATE_QUOTA_MESSAGES);

                if ((autocreatequotastorage > 0) || (autocreatequotamessage > 0)) {
                    quota_t newquotas[QUOTA_NUMRESOURCES];
                    int res;

                    for (res = 0; res < QUOTA_NUMRESOURCES; res++) {
                        newquotas[res] = QUOTA_UNLIMITED;
                    }

                    newquotas[QUOTA_STORAGE] = autocreatequotastorage;
                    newquotas[QUOTA_MESSAGE] = autocreatequotamessage;

                    (void) mboxlist_setquotas(mbname_intname(mbname), newquotas, 0, 0);
                }
            }
        }
    }
#endif

    if (r) {
        prot_printf(imapd_out, "%s NO %s\r\n", tag, error_message(r));
        goto done;
    }

    /* Close newly created mailbox before writing annotations */
    mailboxid = xstrdup(mailbox->uniqueid);
    mailbox_close(&mailbox);

    if (specialuse.len) {
        r = annotatemore_write(mbname_intname(mbname), "/specialuse", mbname_userid(mbname), &specialuse);
        if (r) {
            /* XXX - failure here SHOULD cause a cleanup of the created mailbox */
            syslog(
                    LOG_ERR,
                    "IOERROR: failed to write specialuse for %s on %s (%s) (%s:%d)",
                    imapd_userid,
                    mbname_intname(mbname),
                    buf_cstring(&specialuse),
                    __FILE__,
                    __LINE__
                );

            prot_printf(imapd_out, "%s NO %s (%s:%d)\r\n", tag, error_message(r), __FILE__, __LINE__);
            goto done;
        }
    }

    index_release(imapd_index);
    sync_checkpoint(imapd_in);

    prot_printf(imapd_out, "%s OK [MAILBOXID (%s)] Completed\r\n", tag, mailboxid);

    imapd_check(NULL, 0);

done:
    mboxname_release(&namespacelock);
    mailbox_close(&mailbox);
    mboxlist_entry_free(&parent);
    buf_free(&specialuse);
    mbname_free(&mbname);
    free(mailboxid);
}

/* Callback for use by cmd_delete */
static int delmbox(const mbentry_t *mbentry, void *rock __attribute__((unused)))
{
    int r;

    if (!mboxlist_delayed_delete_isenabled()) {
        r = mboxlist_deletemailbox(mbentry->name,
                                   imapd_userisadmin || imapd_userisproxyadmin,
                                   imapd_userid, imapd_authstate, NULL,
                                   MBOXLIST_DELETE_KEEP_INTERMEDIARIES);
    } else if ((imapd_userisadmin || imapd_userisproxyadmin) &&
               mboxname_isdeletedmailbox(mbentry->name, NULL)) {
        r = mboxlist_deletemailbox(mbentry->name,
                                   imapd_userisadmin || imapd_userisproxyadmin,
                                   imapd_userid, imapd_authstate, NULL,
                                   MBOXLIST_DELETE_KEEP_INTERMEDIARIES);
    } else {
        r = mboxlist_delayed_deletemailbox(mbentry->name,
                                           imapd_userisadmin || imapd_userisproxyadmin,
                                           imapd_userid, imapd_authstate, NULL,
                                           MBOXLIST_DELETE_KEEP_INTERMEDIARIES);
    }

    if (r) {
        prot_printf(imapd_out, "* NO delete %s: %s\r\n",
                    mbentry->name, error_message(r));
    }

    return 0;
}

/*
 * Perform a DELETE command
 */
static void cmd_delete(char *tag, char *name, int localonly, int force)
{
    int r;
    mbentry_t *mbentry = NULL;
    struct mboxevent *mboxevent = NULL;
    mbname_t *mbname = mbname_from_extname(name, &imapd_namespace, imapd_userid);
    int delete_user = 0;

    r = mlookup(NULL, NULL, mbname_intname(mbname), &mbentry);

    if (!r && (mbentry->mbtype & MBTYPE_REMOTE)) {
        /* remote mailbox */
        struct backend *s = NULL;
        int res;

        if (supports_referrals) {
            imapd_refer(tag, mbentry->server, name);
            referral_kick = 1;
            mboxlist_entry_free(&mbentry);
            mbname_free(&mbname);
            return;
        }

        s = proxy_findserver(mbentry->server, &imap_protocol,
                             proxy_userid, &backend_cached,
                             &backend_current, &backend_inbox, imapd_in);
        mboxlist_entry_free(&mbentry);
        if (!s) r = IMAP_SERVER_UNAVAILABLE;

        if (!r) {
            prot_printf(s->out, "%s DELETE {" SIZE_T_FMT "+}\r\n%s\r\n",
                        tag, strlen(name), name);
            res = pipe_until_tag(s, tag, 0);

            if (!CAPA(s, CAPA_MUPDATE) && res == PROXY_OK) {
                /* do MUPDATE delete operations */
            }

            /* make sure we've seen the update */
            if (ultraparanoid && res == PROXY_OK) kick_mupdate();
        }

        imapd_check(s, 0);

        if (r) {
            prot_printf(imapd_out, "%s NO %s\r\n", tag, error_message(r));
        } else {
            /* we're allowed to reference last_result since the noop, if
               sent, went to a different server */
            prot_printf(imapd_out, "%s %s", tag, s->last_result.s);
        }

        mbname_free(&mbname);
        return;
    }
    mboxlist_entry_free(&mbentry);

    struct mboxlock *namespacelock = mboxname_usernamespacelock(mbname_intname(mbname));

    mboxevent = mboxevent_new(EVENT_MAILBOX_DELETE);

    /* local mailbox */
    if (!r) {
        int isadmin = imapd_userisadmin || imapd_userisproxyadmin;

        if (mbname_isdeleted(mbname)) {
            r = mboxlist_deletemailbox(mbname_intname(mbname),
                                       isadmin, imapd_userid,
                                       imapd_authstate, mboxevent,
                                       MBOXLIST_DELETE_LOCALONLY);
        }
        else {
            delete_user = mboxname_isusermailbox(mbname_intname(mbname), 1);
            int delflags = (1-force) ? MBOXLIST_DELETE_CHECKACL : 0;

            if (!delete_user && mboxlist_haschildren(mbname_intname(mbname))) {
                r = IMAP_MAILBOX_HASCHILDREN;
            }
            else if (localonly || !mboxlist_delayed_delete_isenabled()) {
                r = mboxlist_deletemailbox(mbname_intname(mbname),
                                           isadmin, imapd_userid,
                                           imapd_authstate, mboxevent,
                                           delflags|MBOXLIST_DELETE_LOCALONLY);
            }
            else {
                r = mboxlist_delayed_deletemailbox(mbname_intname(mbname),
                                                   isadmin, imapd_userid,
                                                   imapd_authstate, mboxevent,
                                                   delflags);
            }
        }
    }

    /* send a MailboxDelete event notification */
    if (!r)
        mboxevent_notify(&mboxevent);
    mboxevent_free(&mboxevent);

    /* was it a top-level user mailbox? */
    /* localonly deletes are only per-mailbox */
    if (!r && !localonly && delete_user) {
        const char *userid = mbname_userid(mbname);
        if (userid) {
            r = mboxlist_usermboxtree(userid, NULL, delmbox, NULL, MBOXTREE_INTERMEDIATES);
            if (!r) r = user_deletedata(userid, 1);
        }
    }

    mboxname_release(&namespacelock);

    if (!r && config_getswitch(IMAPOPT_DELETE_UNSUBSCRIBE)) {
        mboxlist_changesub(mbname_intname(mbname), imapd_userid, imapd_authstate,
                           /* add */ 0, /* force */ 0, /* notify? */ 1);
    }

    imapd_check(NULL, 0);

    if (r) {
        prot_printf(imapd_out, "%s NO %s\r\n", tag, error_message(r));
    }
    else {
        if (config_mupdate_server)
            kick_mupdate();

        index_release(imapd_index);
        sync_checkpoint(imapd_in);

        prot_printf(imapd_out, "%s OK %s\r\n", tag,
                    error_message(IMAP_OK_COMPLETED));
    }
    mbname_free(&mbname);
}

struct renrock
{
    const struct namespace *namespace;
    int ol;
    int nl;
    int rename_user;
    const char *olduser, *newuser;
    char *newmailboxname;
    const char *partition;
    int found;
};

/* Callback for use by cmd_rename */
static int checkmboxname(const mbentry_t *mbentry, void *rock)
{
    struct renrock *text = (struct renrock *)rock;
    int r;

    text->found++;

    if((text->nl + strlen(mbentry->name + text->ol)) >= MAX_MAILBOX_BUFFER)
        return IMAP_MAILBOX_BADNAME;

    strcpy(text->newmailboxname + text->nl, mbentry->name + text->ol);

    /* force create, but don't ignore policy.  This is a filthy hack that
       will go away when we refactor this code */
    r = mboxlist_createmailboxcheck(text->newmailboxname, 0, text->partition, 1,
                                    imapd_userid, imapd_authstate, NULL, NULL, 2);
    return r;
}

/* Callback for use by cmd_rename */
static int renmbox(const mbentry_t *mbentry, void *rock)
{
    struct renrock *text = (struct renrock *)rock;
    char *oldextname = NULL, *newextname = NULL;
    int r = 0;
    uint32_t uidvalidity = mbentry->uidvalidity;

    if((text->nl + strlen(mbentry->name + text->ol)) >= MAX_MAILBOX_BUFFER)
        goto done;

    strcpy(text->newmailboxname + text->nl, mbentry->name + text->ol);

    /* check if a previous deleted mailbox existed */
    mbentry_t *newmbentry = NULL;
    r = mboxlist_lookup_allow_all(text->newmailboxname, &newmbentry, NULL);
    /* XXX - otherwise we should probably reject now, but meh, save it for
     * a real cleanup */
    if (!r && (newmbentry->mbtype & MBTYPE_DELETED)) {
        /* changing the unique id since last time? */
        if (strcmpsafe(mbentry->uniqueid, newmbentry->uniqueid)) {
            /* then the UIDVALIDITY must be higher than before */
            if (uidvalidity <= newmbentry->uidvalidity)
                uidvalidity = newmbentry->uidvalidity+1;
        }
    }
    mboxlist_entry_free(&newmbentry);


    /* don't notify implied rename in mailbox hierarchy */
    r = mboxlist_renamemailbox(mbentry, text->newmailboxname,
                               text->partition, uidvalidity,
                               1, imapd_userid, imapd_authstate, NULL, 0, 0,
                               text->rename_user, /*keep_intermediaries*/1, 0, 0);

    if (!r && config_getswitch(IMAPOPT_DELETE_UNSUBSCRIBE)) {
        mboxlist_changesub(mbentry->name, imapd_userid, imapd_authstate,
                           /* add */ 0, /* force */ 0, /* notify? */ 0);
    }

    oldextname =
        mboxname_to_external(mbentry->name, &imapd_namespace, imapd_userid);
    newextname =
        mboxname_to_external(text->newmailboxname, &imapd_namespace, imapd_userid);

    if(r) {
        prot_printf(imapd_out, "* NO rename %s %s: %s\r\n",
                    oldextname, newextname, error_message(r));
        if (!RENAME_STOP_ON_ERROR) r = 0;
    } else {
        /* If we're renaming a user, change quotaroot and ACL */
        if (text->rename_user) {
            user_copyquotaroot(mbentry->name, text->newmailboxname);
            user_renameacl(text->namespace, text->newmailboxname,
                           text->olduser, text->newuser);
        }

        // non-standard output item, but it helps give progress
        prot_printf(imapd_out, "* OK rename %s %s\r\n",
                    oldextname, newextname);
    }

done:
    prot_flush(imapd_out);
    free(oldextname);
    free(newextname);

    return r;
}

/* Callback for use by cmd_rename */
static int checkrenmacl(const mbentry_t *mbentry, void *rock)
{
    const struct auth_state *auth_state = (struct auth_state *) rock;
    long myrights = cyrus_acl_myrights(auth_state, mbentry->acl);

    if (myrights & ACL_DELETEMBOX) return IMAP_OK_COMPLETED;

    return (myrights & ACL_LOOKUP) ?
        IMAP_PERMISSION_DENIED : IMAP_MAILBOX_NONEXISTENT;
}

/*
 * Perform a RENAME command
 */
static void cmd_rename(char *tag, char *oldname, char *newname, char *location)
{
    int r = 0;
    char *c;
    char oldmailboxname[MAX_MAILBOX_BUFFER];
    char newmailboxname[MAX_MAILBOX_BUFFER];
    char oldmailboxname2[MAX_MAILBOX_BUFFER];
    char newmailboxname2[MAX_MAILBOX_BUFFER];
    char *oldextname = NULL;
    char *newextname = NULL;
    char *oldintname = NULL;
    char *newintname = NULL;
    char *olduser = NULL;
    char *newuser = NULL;
    int omlen, nmlen;
    int subcount = 0; /* number of sub-folders found */
    int recursive_rename = 1;
    int rename_user = 0;
    int mbtype = 0;
    mbentry_t *mbentry = NULL;
    struct renrock rock;

    if (location && !imapd_userisadmin) {
        prot_printf(imapd_out, "%s NO %s\r\n", tag, error_message(IMAP_PERMISSION_DENIED));
        return;
    }

    if (location && strcmp(oldname, newname)) {
        /* XXX It would be nice to not complain here iff the location
         * XXX is actually the mailbox's current partition, but we
         * XXX don't have that info until much later!
         */
        prot_printf(imapd_out,
                    "%s NO Cross-server or cross-partition move w/rename not supported\r\n",
                    tag);
        return;
    }

    oldintname = mboxname_from_external(oldname, &imapd_namespace, imapd_userid);
    xstrncpy(oldmailboxname, oldintname, MAX_MAILBOX_NAME);
    free(oldintname);

    newintname = mboxname_from_external(newname, &imapd_namespace, imapd_userid);
    xstrncpy(newmailboxname, newintname, MAX_MAILBOX_NAME);
    free(newintname);

    olduser = mboxname_to_userid(oldmailboxname);
    newuser = mboxname_to_userid(newmailboxname);

    struct mboxlock *oldnamespacelock = NULL;
    struct mboxlock *newnamespacelock = NULL;

    if (strcmpsafe(oldmailboxname, newmailboxname) < 0) {
        oldnamespacelock = mboxname_usernamespacelock(oldmailboxname);
        newnamespacelock = mboxname_usernamespacelock(newmailboxname);
    }
    else {
        newnamespacelock = mboxname_usernamespacelock(newmailboxname);
        oldnamespacelock = mboxname_usernamespacelock(oldmailboxname);
    }

    /* Keep temporary copy: master is trashed */
    strcpy(oldmailboxname2, oldmailboxname);
    strcpy(newmailboxname2, newmailboxname);

    r = mlookup(NULL, NULL, oldmailboxname, &mbentry);
    if (r == IMAP_MAILBOX_NONEXISTENT) {
        /* Check if the base mailbox is an intermediate */
        r = mboxlist_lookup_allow_all(oldmailboxname, &mbentry, 0);

        if (!r) {
            if (mbentry->mbtype & (MBTYPE_RESERVE | MBTYPE_DELETED)) {
                r = IMAP_MAILBOX_NONEXISTENT;
            }
            else if (!imapd_userisadmin &&
                     (mbentry->mbtype & MBTYPE_INTERMEDIATE)) {
                /* Make sure we can rename the first child */
                r = mboxlist_allmbox(oldmailboxname,
                                     checkrenmacl, imapd_authstate, 0);
                if (r == IMAP_OK_COMPLETED) r = 0;
            }
        }
    }
    if (r) {
        prot_printf(imapd_out, "%s NO %s\r\n", tag, error_message(r));
        goto done;
    }

    mbtype = mbentry->mbtype;

    if (!r && mbentry->mbtype & MBTYPE_REMOTE) {
        /* remote mailbox */
        struct backend *s = NULL;
        int res;

        s = proxy_findserver(mbentry->server, &imap_protocol,
                             proxy_userid, &backend_cached,
                             &backend_current, &backend_inbox, imapd_in);

        if (!s) {
            prot_printf(imapd_out, "%s NO %s\r\n", tag, error_message(IMAP_SERVER_UNAVAILABLE));
            goto done;
        }

        // Server or partition is going to change
        if (location) {
            char *destserver = NULL;
            char *destpart = NULL;

            c = strchr(location, '!');
            if (c) {
                destserver = xstrndup(location, c - location);
                destpart = xstrdup(c + 1);
            } else {
                destpart = xstrdup(location);
            }

            if (*destpart == '\0') {
                free(destpart);
                destpart = NULL;
            }

            if (!destserver || !strcmp(destserver, mbentry->server)) {
                /* same server: proxy a rename */
                prot_printf(s->out,
                        "%s RENAME \"%s\" \"%s\" %s\r\n",
                        tag,
                        oldname,
                        newname,
                        location);
            } else {
                /* different server: proxy an xfer */
                prot_printf(s->out,
                        "%s XFER \"%s\" %s%s%s\r\n",
                        tag,
                        oldname,
                        destserver,
                        destpart ? " " : "",
                        destpart ? destpart : "");
            }

            if (destserver) free(destserver);
            if (destpart) free(destpart);

            res = pipe_until_tag(s, tag, 0);

            /* make sure we've seen the update */
            if (ultraparanoid && res == PROXY_OK) kick_mupdate();

        } else { // (location)
            // a simple rename, old name and new name must not be the same
            if (!strcmp(oldname, newname)) {
                prot_printf(imapd_out, "%s NO %s\r\n", tag, error_message(IMAP_SERVER_UNAVAILABLE));
                goto done;
            }

            prot_printf(s->out,
                    "%s RENAME \"%s\" \"%s\"\r\n",
                    tag,
                    oldname,
                    newname
                );

            res = pipe_until_tag(s, tag, 0);

            /* make sure we've seen the update */
            if (ultraparanoid && res == PROXY_OK) kick_mupdate();
        }

        imapd_check(s, 0);

        if (r) {
            prot_printf(imapd_out, "%s NO %s\r\n", tag, error_message(r));
        } else {
            /* we're allowed to reference last_result since the noop, if
               sent, went to a different server */
            prot_printf(imapd_out, "%s %s", tag, s->last_result.s);
        }

        goto done;
    }

    /* local mailbox */

    if (location && !config_partitiondir(location)) {
        /* invalid partition, assume its a server (remote destination) */
        char *server;
        char *partition;

        /* dest partition? */
        server = location;
        partition = strchr(location, '!');
        if (partition) *partition++ = '\0';

        cmd_xfer(tag, oldname, server, partition);

        goto done;
    }

    /* local rename: it's OK if the mailbox doesn't exist, we'll check
     * if sub mailboxes can be renamed */
    if (r == IMAP_MAILBOX_NONEXISTENT)
        r = 0;

    if (r) {
        prot_printf(imapd_out, "%s NO %s\r\n", tag, error_message(r));
        goto done;
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

    oldextname = mboxname_to_external(oldmailboxname, &imapd_namespace, imapd_userid);
    newextname = mboxname_to_external(newmailboxname, &imapd_namespace, imapd_userid);

    /* rename all mailboxes matching this */
    if (recursive_rename && strcmp(oldmailboxname, newmailboxname)) {
        int ol = omlen + 1;
        int nl = nmlen + 1;
        char ombn[MAX_MAILBOX_BUFFER];
        char nmbn[MAX_MAILBOX_BUFFER];

        strcpy(ombn, oldmailboxname);
        strcpy(nmbn, newmailboxname);
        strcat(ombn, ".");
        strcat(nmbn, ".");

        /* setup the rock */
        rock.namespace = &imapd_namespace;
        rock.found = 0;
        rock.newmailboxname = nmbn;
        rock.ol = ol;
        rock.nl = nl;
        rock.olduser = olduser;
        rock.newuser = newuser;
        rock.partition = location;
        rock.rename_user = rename_user;

        /* Check mboxnames to ensure we can write them all BEFORE we start */
        r = mboxlist_allmbox(ombn, checkmboxname, &rock, 0);

        subcount = rock.found;
    }

    /* attempt to rename the base mailbox */
    if (!r) {
        struct mboxevent *mboxevent = NULL;
        uint32_t uidvalidity = mbentry ? mbentry->uidvalidity : 0;

        /* don't send rename notification if we only change the partition */
        if (strcmp(oldmailboxname, newmailboxname))
            mboxevent = mboxevent_new(EVENT_MAILBOX_RENAME);

        /* check if a previous deleted mailbox existed */
        mbentry_t *newmbentry = NULL;
        r = mboxlist_lookup_allow_all(newmailboxname, &newmbentry, NULL);
        /* XXX - otherwise we should probably reject now, but meh, save it for
         * a real cleanup */
        if (!r && (newmbentry->mbtype & MBTYPE_DELETED)) {
            /* changing the unique id since last time? */
            if (!mbentry || strcmpsafe(mbentry->uniqueid, newmbentry->uniqueid)) {
                /* then the UIDVALIDITY must be higher than before */
                if (uidvalidity <= newmbentry->uidvalidity)
                    uidvalidity = newmbentry->uidvalidity+1;
            }
        }
        mboxlist_entry_free(&newmbentry);

        r = mboxlist_renamemailbox(mbentry, newmailboxname,
                                   location ? location : mbentry->partition,
                                   0 /* uidvalidity */, imapd_userisadmin,
                                   imapd_userid, imapd_authstate, mboxevent,
                                   0, 0, rename_user, /*keep_intermediaries*/1, 0, 0);

        /* it's OK to not exist if there are subfolders */
        if (r == IMAP_MAILBOX_NONEXISTENT && subcount && !rename_user &&
           mboxname_userownsmailbox(imapd_userid, oldmailboxname) &&
           mboxname_userownsmailbox(imapd_userid, newmailboxname)) {

            mboxevent_free(&mboxevent);

            goto submboxes;
        }

        /* send a MailboxRename event notification if enabled */
        if (!r)
            mboxevent_notify(&mboxevent);
        mboxevent_free(&mboxevent);

        if (!r && config_getswitch(IMAPOPT_DELETE_UNSUBSCRIBE)) {
            mboxlist_changesub(oldmailboxname, imapd_userid, imapd_authstate,
                               /* add */ 0, /* force */ 0, /* notify? */ 1);
        }
    }

    /* If we're renaming a user, take care of changing quotaroot and ACL */
    if (!r && rename_user) {
        user_copyquotaroot(oldmailboxname, newmailboxname);
        user_renameacl(&imapd_namespace, newmailboxname, olduser, newuser);

        /* XXX report status/progress of meta-data */
    }

    /* rename all mailboxes matching this */
    if (!r && recursive_rename) {
        prot_printf(imapd_out, "* OK rename %s %s\r\n",
                    oldextname, newextname);
        prot_flush(imapd_out);

submboxes:
        strcat(oldmailboxname, ".");
        strcat(newmailboxname, ".");

        /* setup the rock */
        rock.namespace = &imapd_namespace;
        rock.newmailboxname = newmailboxname;
        rock.ol = omlen + 1;
        rock.nl = nmlen + 1;
        rock.olduser = olduser;
        rock.newuser = newuser;
        rock.partition = location;
        rock.rename_user = rename_user;

        /* add submailboxes; we pretend we're an admin since we successfully
           renamed the parent - we're using internal names here */
        r = mboxlist_allmbox(oldmailboxname, renmbox, &rock, MBOXTREE_INTERMEDIATES);
    }

    /* take care of intermediaries */
    mboxlist_update_intermediaries(oldmailboxname, mbtype, 0);
    mboxlist_update_intermediaries(newmailboxname, mbtype, 0);

    imapd_check(NULL, 0);

    if (r) {
        prot_printf(imapd_out, "%s NO %s\r\n", tag, error_message(r));
    } else {
        if (config_mupdate_server)
            kick_mupdate();

        if (rename_user)
            sync_log_user(newuser);

        index_release(imapd_index);
        sync_checkpoint(imapd_in);

        prot_printf(imapd_out, "%s OK %s\r\n", tag,
                    error_message(IMAP_OK_COMPLETED));
    }

done:
    mboxname_release(&oldnamespacelock);
    mboxname_release(&newnamespacelock);
    mboxlist_entry_free(&mbentry);
    free(oldextname);
    free(newextname);
    free(olduser);
    free(newuser);
}

/*
 * Perform a RECONSTRUCT command
 */
static void cmd_reconstruct(const char *tag, const char *name, int recursive)
{
    int r = 0;
    char quotaroot[MAX_MAILBOX_BUFFER];
    mbentry_t *mbentry = NULL;
    struct mailbox *mailbox = NULL;

    /* administrators only please */
    if (!imapd_userisadmin)
        r = IMAP_PERMISSION_DENIED;

    char *intname = mboxname_from_external(name, &imapd_namespace, imapd_userid);

    if (!r && !strcmpsafe(intname, index_mboxname(imapd_index)))
        r = IMAP_MAILBOX_LOCKED;

    if (!r) {
        r = mlookup(tag, name, intname, &mbentry);
    }
    if (r == IMAP_MAILBOX_MOVED) {
        free(intname);
        return;
    }

    if (!r && (mbentry->mbtype & MBTYPE_REMOTE)) {
        /* remote mailbox */
        imapd_refer(tag, mbentry->server, name);
        mboxlist_entry_free(&mbentry);
        free(intname);
        return;
    }

    mboxlist_entry_free(&mbentry);

    /* local mailbox */
    if (!r) {
        int pid;

        /* Reconstruct it */

        pid = fork();
        if (pid == -1) {
            r = IMAP_SYS_ERROR;
        } else if (pid == 0) {
            char buf[4096];
            int ret;

            /* Child - exec reconstruct*/
            syslog(LOG_NOTICE, "Reconstructing '%s' (%s) for user '%s'",
                   intname, recursive ? "recursive" : "not recursive",
                   imapd_userid);

            fclose(stdin);
            fclose(stdout);
            fclose(stderr);

            ret = snprintf(buf, sizeof(buf), "%s/reconstruct", SBIN_DIR);
            if(ret < 0 || ret >= (int) sizeof(buf)) {
                /* in child, so fatailing won't disconnect our user */
                fatal("reconstruct buffer not sufficiently big", EX_CONFIG);
            }

            if(recursive) {
                execl(buf, buf, "-C", config_filename, "-r", "-f",
                      intname, NULL);
            } else {
                execl(buf, buf, "-C", config_filename, intname, NULL);
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
    if (!r)
        r = mailbox_open_irl(intname, &mailbox);

    if(!r) {
        if(mailbox->quotaroot) {
            strcpy(quotaroot, mailbox->quotaroot);
        } else {
            strcpy(quotaroot, intname);
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
                   intname, imapd_userid);

            fclose(stdin);
            fclose(stdout);
            fclose(stderr);

            ret = snprintf(buf, sizeof(buf), "%s/quota", SBIN_DIR);
            if(ret < 0 || ret >= (int) sizeof(buf)) {
                /* in child, so fatailing won't disconnect our user */
                fatal("quota buffer not sufficiently big", EX_CONFIG);
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
    }

    free(intname);
}

/* number of times the callbacks for findall/findsub have been called */
static int list_callback_calls;

/*
 * Parse LIST command arguments.
 */
static void getlistargs(char *tag, struct listargs *listargs)
{
    static struct buf reference, buf;
    int c;

    /* Check for and parse LIST-EXTENDED selection options */
    c = prot_getc(imapd_in);
    if (c == '(') {
        listargs->cmd = LIST_CMD_EXTENDED;
        c = getlistselopts(tag, listargs);
        if (c == EOF) {
            eatline(imapd_in, c);
            return;
        }
    }
    else
        prot_ungetc(c, imapd_in);

    if (!strcmpsafe(imapd_magicplus, "+")) listargs->sel |= LIST_SEL_SUBSCRIBED;
    else if (!strcasecmpsafe(imapd_magicplus, "+dav")) listargs->sel |= LIST_SEL_DAV;

    /* Read in reference name */
    c = getastring(imapd_in, imapd_out, &reference);
    if (c == EOF && !*reference.s) {
        prot_printf(imapd_out,
                    "%s BAD Missing required argument to List: reference name\r\n",
                    tag);
        eatline(imapd_in, c);
        return;
    }
    listargs->ref = reference.s;

    if (c != ' ') {
        prot_printf(imapd_out,
                    "%s BAD Missing required argument to List: mailbox pattern\r\n", tag);
        eatline(imapd_in, c);
        return;
    }

    /* Read in mailbox pattern(s) */
    c = prot_getc(imapd_in);
    if (c == '(') {
        listargs->cmd = LIST_CMD_EXTENDED;
        for (;;) {
            c = getastring(imapd_in, imapd_out, &buf);
            if (*buf.s)
                strarray_append(&listargs->pat, buf.s);
            if (c != ' ') break;
        }
        if (c != ')') {
            prot_printf(imapd_out,
                        "%s BAD Invalid syntax in List command\r\n", tag);
            eatline(imapd_in, c);
            goto freeargs;
        }
        c = prot_getc(imapd_in);
    }
    else {
        prot_ungetc(c, imapd_in);
        c = getastring(imapd_in, imapd_out, &buf);
        if (c == EOF) {
            prot_printf(imapd_out,
                        "%s BAD Missing required argument to List: mailbox pattern\r\n",
                        tag);
            eatline(imapd_in, c);
            goto freeargs;
        }
        strarray_append(&listargs->pat, buf.s);
    }

    /* Check for and parse LIST-EXTENDED return options */
    if (c == ' ') {
        listargs->cmd = LIST_CMD_EXTENDED;
        c = getlistretopts(tag, listargs);
        if (c == EOF) {
            eatline(imapd_in, c);
            goto freeargs;
        }
    }

    /* check for CRLF */
    if (!IS_EOL(c, imapd_in)) {
        prot_printf(imapd_out,
                    "%s BAD Unexpected extra arguments to List\r\n", tag);
        eatline(imapd_in, c);
        goto freeargs;
    }

#ifdef USE_AUTOCREATE
    autocreate_inbox();
#endif // USE_AUTOCREATE

    return;

  freeargs:
    strarray_fini(&listargs->pat);
    strarray_fini(&listargs->metaitems);
    return;
}

/*
 * Perform a LIST, LSUB, RLIST or RLSUB command
 */
static void cmd_list(char *tag, struct listargs *listargs)
{
    clock_t start = clock();
    char mytime[100];

    if (listargs->sel & LIST_SEL_REMOTE) {
        if (!config_getswitch(IMAPOPT_PROXYD_DISABLE_MAILBOX_REFERRALS)) {
            supports_referrals = !disable_referrals;
        }
    }

    list_callback_calls = 0;

    if (listargs->pat.count && !*(listargs->pat.data[0]) && (listargs->cmd == LIST_CMD_LIST)) {
        /* special case: query top-level hierarchy separator */
        prot_printf(imapd_out, "* LIST (\\Noselect) \"%c\" \"\"\r\n",
                    imapd_namespace.hier_sep);
    } else if (listargs->pat.count && !*(listargs->pat.data[0]) && (listargs->cmd == LIST_CMD_XLIST)) {
        /* special case: query top-level hierarchy separator */
        prot_printf(imapd_out, "* XLIST (\\Noselect) \"%c\" \"\"\r\n",
                    imapd_namespace.hier_sep);
    } else if ((listargs->cmd == LIST_CMD_LSUB) &&
               (backend_inbox || (backend_inbox = proxy_findinboxserver(imapd_userid)))) {
        /* remote inbox */
        if (list_data_remote(backend_inbox, tag, listargs, NULL))
            return;
    } else {
        list_data(listargs);
    }

    if (global_conversations) {
        conversations_abort(&global_conversations);
        global_conversations = NULL;
    }

    strarray_fini(&listargs->pat);
    strarray_fini(&listargs->metaitems);

    imapd_check((listargs->sel & LIST_SEL_SUBSCRIBED) ?  NULL : backend_inbox, 0);

    snprintf(mytime, sizeof(mytime), "%2.3f",
             (clock() - start) / (double) CLOCKS_PER_SEC);
    if ((listargs->sel & LIST_SEL_METADATA) && listargs->metaopts.maxsize &&
        listargs->metaopts.biggest > listargs->metaopts.maxsize) {
        prot_printf(imapd_out, "%s OK [METADATA LONGENTRIES %u] %s\r\n", tag,
                    (unsigned)listargs->metaopts.biggest, error_message(IMAP_OK_COMPLETED));
    }
    else {
        prot_printf(imapd_out, "%s OK %s (%s secs", tag,
                    error_message(IMAP_OK_COMPLETED), mytime);
        if (list_callback_calls)
            prot_printf(imapd_out, " %u calls", list_callback_calls);
        prot_printf(imapd_out, ")\r\n");
    }
}

/*
 * Perform a SUBSCRIBE (add is nonzero) or
 * UNSUBSCRIBE (add is zero) command
 */
static void cmd_changesub(char *tag, char *namespace, char *name, int add)
{
    const char *cmd = add ? "Subscribe" : "Unsubscribe";
    int r = 0;
    int force = config_getswitch(IMAPOPT_ALLOWALLSUBSCRIBE);

    if (backend_inbox || (backend_inbox = proxy_findinboxserver(imapd_userid))) {
        /* remote INBOX */
        if (add) {
            char *intname = mboxname_from_external(name, &imapd_namespace, imapd_userid);
            r = mlookup(NULL, NULL, intname, NULL);
            free(intname);

            /* Doesn't exist on murder */
        }

        imapd_check(backend_inbox, 0);

        if (!r) {
            if (namespace) {
                prot_printf(backend_inbox->out,
                            "%s %s {" SIZE_T_FMT "+}\r\n%s"
                            " {" SIZE_T_FMT "+}\r\n%s\r\n",
                            tag, cmd,
                            strlen(namespace), namespace,
                            strlen(name), name);
            } else {
                prot_printf(backend_inbox->out, "%s %s {" SIZE_T_FMT "+}\r\n%s\r\n",
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
            char *intname = mboxname_from_external(name, &imapd_namespace, imapd_userid);
            r = mboxlist_changesub(intname, imapd_userid, imapd_authstate, add, force, 1);
            free(intname);
        }
    }
    else if (!strcmp(namespace, "bboard")) {
        r = add ? IMAP_MAILBOX_NONEXISTENT : 0;
    }
    else {
        prot_printf(imapd_out, "%s BAD Invalid %s subcommand\r\n", tag, cmd);
        return;
    }

    imapd_check(NULL, 0);

    if (r) {
        prot_printf(imapd_out, "%s NO %s: %s\r\n", tag, cmd, error_message(r));
    }
    else {
        index_release(imapd_index);
        sync_checkpoint(imapd_in);

        prot_printf(imapd_out, "%s OK %s\r\n", tag,
                    error_message(IMAP_OK_COMPLETED));
    }
}

/*
 * Perform a GETACL command
 */
static void cmd_getacl(const char *tag, const char *name)
{
    int r, access;
    char *acl;
    char *rights, *nextid;
    char *freeme = NULL;
    mbentry_t *mbentry = NULL;

    char *intname = mboxname_from_external(name, &imapd_namespace, imapd_userid);

    r = mlookup(tag, name, intname, &mbentry);
    if (r == IMAP_MAILBOX_MOVED) return;

    if (!r) {
        access = cyrus_acl_myrights(imapd_authstate, mbentry->acl);

        if (!(access & ACL_ADMIN) &&
            !imapd_userisadmin &&
            !mboxname_userownsmailbox(imapd_userid, intname)) {
            r = (access & ACL_LOOKUP) ?
              IMAP_PERMISSION_DENIED : IMAP_MAILBOX_NONEXISTENT;
        }
    }

    imapd_check(NULL, 0);

    if (r) {
        prot_printf(imapd_out, "%s NO %s\r\n", tag, error_message(r));
        mboxlist_entry_free(&mbentry);
        free(intname);
        return;
    }

    prot_printf(imapd_out, "* ACL ");
    prot_printastring(imapd_out, name);

    freeme = acl = xstrdupnull(mbentry->acl);

    while (acl) {
        rights = strchr(acl, '\t');
        if (!rights) break;
        *rights++ = '\0';

        nextid = strchr(rights, '\t');
        if (!nextid) break;
        *nextid++ = '\0';

        prot_printf(imapd_out, " ");
        prot_printastring(imapd_out, acl);
        prot_printf(imapd_out, " ");
        prot_printastring(imapd_out, rights);
        acl = nextid;
    }
    prot_printf(imapd_out, "\r\n");
    prot_printf(imapd_out, "%s OK %s\r\n", tag,
                error_message(IMAP_OK_COMPLETED));
    free(freeme);
    mboxlist_entry_free(&mbentry);
    free(intname);
}

/*
 * Perform a LISTRIGHTS command
 */
static void cmd_listrights(char *tag, char *name, char *identifier)
{
    int r, rights;
    mbentry_t *mbentry = NULL;
    struct auth_state *authstate;
    const char *canon_identifier;
    int implicit;
    char rightsdesc[100], optional[33];

    char *intname = mboxname_from_external(name, &imapd_namespace, imapd_userid);
    r = mlookup(tag, name, intname, &mbentry);
    if (r == IMAP_MAILBOX_MOVED) return;

    if (!r) {
        rights = cyrus_acl_myrights(imapd_authstate, mbentry->acl);

        if (!rights && !imapd_userisadmin &&
            !mboxname_userownsmailbox(imapd_userid, intname)) {
            r = IMAP_MAILBOX_NONEXISTENT;
        }
    }

    mboxlist_entry_free(&mbentry);

    imapd_check(NULL, 0);

    if (r) {
        prot_printf(imapd_out, "%s NO %s\r\n", tag, error_message(r));
        return;
    }

    authstate = auth_newstate(identifier);
    if (global_authisa(authstate, IMAPOPT_ADMINS))
        canon_identifier = identifier; /* don't canonify global admins */
    else
        canon_identifier = canonify_userid(identifier, imapd_userid, NULL);
    auth_freestate(authstate);

    if (!canon_identifier) {
        implicit = 0;
    }
    else if (mboxname_userownsmailbox(canon_identifier, intname)) {
        /* identifier's personal mailbox */
        implicit = config_implicitrights;
    }
    else if (mboxname_isusermailbox(intname, 1)) {
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
    prot_printastring(imapd_out, name);
    (void)prot_putc(' ', imapd_out);
    prot_printastring(imapd_out, identifier);
    prot_printf(imapd_out, " %s", rightsdesc);

    prot_printf(imapd_out, "\r\n%s OK %s\r\n", tag,
                error_message(IMAP_OK_COMPLETED));
    free(intname);
}

static int printmyrights(const char *extname, const mbentry_t *mbentry)
{
    int rights = 0;
    char str[ACL_MAXSTR];

    rights = cyrus_acl_myrights(imapd_authstate, mbentry->acl);

    /* Add in implicit rights */
    if (imapd_userisadmin) {
        rights |= ACL_LOOKUP|ACL_ADMIN;
    }
    else if (mboxname_userownsmailbox(imapd_userid, mbentry->name)) {
        rights |= config_implicitrights;
    }

    if (!(rights & (ACL_LOOKUP|ACL_READ|ACL_INSERT|ACL_CREATE|ACL_DELETEMBOX|ACL_ADMIN))) {
        return IMAP_MAILBOX_NONEXISTENT;
    }

    prot_printf(imapd_out, "* MYRIGHTS ");
    prot_printastring(imapd_out, extname);
    prot_printf(imapd_out, " ");
    prot_printastring(imapd_out, cyrus_acl_masktostr(rights, str));
    prot_printf(imapd_out, "\r\n");

    return 0;
}

/*
 * Perform a MYRIGHTS command
 */
static void cmd_myrights(const char *tag, const char *name)
{
    mbentry_t *mbentry = NULL;
    int r;
    char *intname = mboxname_from_external(name, &imapd_namespace, imapd_userid);

    r = mlookup(tag, name, intname, &mbentry);
    free(intname);
    if (r == IMAP_MAILBOX_MOVED) return;

    if (!r) r = printmyrights(name, mbentry);

    mboxlist_entry_free(&mbentry);

    imapd_check(NULL, 0);

    if (r) {
        prot_printf(imapd_out, "%s NO %s\r\n", tag, error_message(r));
        return;
    }

    prot_printf(imapd_out, "%s OK %s\r\n", tag,
                error_message(IMAP_OK_COMPLETED));
}

/*
 * Perform a SETACL command
 */
static void cmd_setacl(char *tag, const char *name,
                const char *identifier, const char *rights)
{
    int r;
    mbentry_t *mbentry = NULL;

    char *intname = mboxname_from_external(name, &imapd_namespace, imapd_userid);

    /* is it remote? */
    r = mlookup(tag, name, intname, &mbentry);
    if (r == IMAP_MAILBOX_MOVED) goto done;

    if (!config_getswitch(IMAPOPT_ALLOWSETACL))
        r = IMAP_DISABLED;

    if (!r && (mbentry->mbtype & MBTYPE_REMOTE)) {
        /* remote mailbox */
        struct backend *s = NULL;
        int res;

        s = proxy_findserver(mbentry->server, &imap_protocol,
                             proxy_userid, &backend_cached,
                             &backend_current, &backend_inbox, imapd_in);
        if (!s) r = IMAP_SERVER_UNAVAILABLE;

        if (!r && imapd_userisadmin && supports_referrals) {
            /* They aren't an admin remotely, so let's refer them */
            imapd_refer(tag, mbentry->server, name);
            referral_kick = 1;
            goto done;
        }

        if (!r) {
            if (rights) {
                prot_printf(s->out,
                            "%s Setacl {" SIZE_T_FMT "+}\r\n%s"
                            " {" SIZE_T_FMT "+}\r\n%s {" SIZE_T_FMT "+}\r\n%s\r\n",
                            tag, strlen(name), name,
                            strlen(identifier), identifier,
                            strlen(rights), rights);
            } else {
                prot_printf(s->out,
                            "%s Deleteacl {" SIZE_T_FMT "+}\r\n%s"
                            " {" SIZE_T_FMT "+}\r\n%s\r\n",
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

        imapd_check(s, 0);

        if (r) {
            prot_printf(imapd_out, "%s NO %s\r\n", tag, error_message(r));
        } else {
            /* we're allowed to reference last_result since the noop, if
               sent, went to a different server */
            prot_printf(imapd_out, "%s %s", tag, s->last_result.s);
        }

        goto done;
    }

    /* local mailbox */
    if (!r) {
        char *err;

        /* send BAD response if rights string contains unrecognised chars */
        if (rights && *rights) {
            r = cyrus_acl_checkstr(rights, &err);
            if (r) {
                prot_printf(imapd_out, "%s BAD %s\r\n", tag, err);
                free(err);
                goto done;
            }
        }

        r = mboxlist_setacl(&imapd_namespace, intname, identifier, rights,
                            imapd_userisadmin || imapd_userisproxyadmin,
                            proxy_userid, imapd_authstate);
    }

    imapd_check(NULL, 0);

    if (r) {
        prot_printf(imapd_out, "%s NO %s\r\n", tag, error_message(r));
    } else {
        if (config_mupdate_server)
            kick_mupdate();

        index_release(imapd_index);
        sync_checkpoint(imapd_in);

        prot_printf(imapd_out, "%s OK %s\r\n", tag,
                    error_message(IMAP_OK_COMPLETED));
    }

done:
    free(intname);
    mboxlist_entry_free(&mbentry);
}

static void print_quota_used(struct protstream *o, const struct quota *q)
{
    int res;
    const char *sep = "";

    prot_putc('(', o);
    for (res = 0 ; res < QUOTA_NUMRESOURCES ; res++) {
        if (q->limits[res] >= 0) {
            prot_printf(o, "%s%s " QUOTA_T_FMT " " QUOTA_T_FMT,
                        sep, quota_names[res],
                        q->useds[res]/quota_units[res],
                        q->limits[res]);
            sep = " ";
        }
    }
    prot_putc(')', o);
}

static void print_quota_limits(struct protstream *o, const struct quota *q)
{
    int res;
    const char *sep = "";

    prot_putc('(', o);
    for (res = 0 ; res < QUOTA_NUMRESOURCES ; res++) {
        if (q->limits[res] >= 0) {
            prot_printf(o, "%s%s " QUOTA_T_FMT,
                        sep, quota_names[res],
                        q->limits[res]);
            sep = " ";
        }
    }
    prot_putc(')', o);
}

/*
 * Callback for (get|set)quota, to ensure that all of the
 * submailboxes are on the same server.
 */
static int quota_cb(const mbentry_t *mbentry, void *rock)
{
    const char *servername = (const char *)rock;
    int r;

    if (strcmp(servername, mbentry->server)) {
        /* Not on same server as the root */
        r = IMAP_NOT_SINGULAR_ROOT;
    } else {
        r = PROXY_OK;
    }

    return r;
}


/*
 * Perform a GETQUOTA command
 */
static void cmd_getquota(const char *tag, const char *name)
{
    int r;
    char quotarootbuf[MAX_MAILBOX_BUFFER];
    mbentry_t *mbentry = NULL;
    struct quota q;
    char *intname = mboxname_from_external(name, &imapd_namespace, imapd_userid);

    quota_init(&q, intname);

    imapd_check(NULL, 0);

    if (!imapd_userisadmin && !imapd_userisproxyadmin) {
        r = IMAP_PERMISSION_DENIED;
        goto done;
    }

    r = mlookup(NULL, NULL, intname, &mbentry);
    if (!r && (mbentry->mbtype & MBTYPE_REMOTE)) {
        /* remote mailbox */

        snprintf(quotarootbuf, sizeof(quotarootbuf), "%s.", intname);

        r = mboxlist_allmbox(quotarootbuf, quota_cb, (void *)mbentry->server, 0);
        if (r) goto done;

        struct backend *s;
        s = proxy_findserver(mbentry->server, &imap_protocol,
                             proxy_userid, &backend_cached,
                             &backend_current, &backend_inbox, imapd_in);
        if (!s) {
            r = IMAP_SERVER_UNAVAILABLE;
            goto done;
        }

        imapd_check(s, 0);

        prot_printf(s->out, "%s Getquota {" SIZE_T_FMT "+}\r\n%s\r\n",
                    tag, strlen(name), name);
        pipe_including_tag(s, tag, 0);

        goto done;
    }

    /* local mailbox */

    r = quota_read_withconversations(&q);
    if (r) goto done;

    prot_printf(imapd_out, "* QUOTA ");
    prot_printastring(imapd_out, name);
    prot_printf(imapd_out, " ");
    print_quota_used(imapd_out, &q);
    prot_printf(imapd_out, "\r\n");

    prot_printf(imapd_out, "%s OK %s\r\n", tag,
                error_message(IMAP_OK_COMPLETED));

 done:
    if (r) prot_printf(imapd_out, "%s NO %s\r\n", tag, error_message(r));
    mboxlist_entry_free(&mbentry);
    quota_free(&q);
    free(intname);
}

/*
 * Perform a GETQUOTAROOT command
 */
static void cmd_getquotaroot(const char *tag, const char *name)
{
    mbentry_t *mbentry = NULL;
    struct mailbox *mailbox = NULL;
    int myrights = 0;
    int r, doclose = 0;

    char *intname = mboxname_from_external(name, &imapd_namespace, imapd_userid);
    r = mlookup(tag, name, intname, &mbentry);
    if (r == IMAP_MAILBOX_MOVED) {
        free(intname);
        return;
    }

    if (!r && (mbentry->mbtype & MBTYPE_REMOTE)) {
        /* remote mailbox */
        struct backend *s;

        s = proxy_findserver(mbentry->server, &imap_protocol,
                             proxy_userid, &backend_cached,
                             &backend_current, &backend_inbox, imapd_in);
        if (!s) r = IMAP_SERVER_UNAVAILABLE;

        imapd_check(s, 0);

        if (!r) {
            prot_printf(s->out, "%s Getquotaroot {" SIZE_T_FMT "+}\r\n%s\r\n",
                        tag, strlen(name), name);
            pipe_including_tag(s, tag, 0);
        } else {
            prot_printf(imapd_out, "%s NO %s\r\n", tag, error_message(r));
        }

        mboxlist_entry_free(&mbentry);
        free(intname);

        return;
    }

    mboxlist_entry_free(&mbentry);

    /* local mailbox */
    if (!r) {
        r = mailbox_open_irl(intname, &mailbox);
        if (!r) {
            doclose = 1;
            myrights = cyrus_acl_myrights(imapd_authstate, mailbox->acl);
        }
    }

    if (!r) {
        if (!imapd_userisadmin && !(myrights & ACL_READ)) {
            r = (myrights & ACL_LOOKUP) ?
              IMAP_PERMISSION_DENIED : IMAP_MAILBOX_NONEXISTENT;
        }
    }

    if (!r) {
        prot_printf(imapd_out, "* QUOTAROOT ");
        prot_printastring(imapd_out, name);
        if (mailbox->quotaroot) {
            struct quota q;
            char *extname = mboxname_to_external(mailbox->quotaroot, &imapd_namespace, imapd_userid);
            prot_printf(imapd_out, " ");
            prot_printastring(imapd_out, extname);
            quota_init(&q, mailbox->quotaroot);
            r = quota_read_withconversations(&q);
            if (!r) {
                prot_printf(imapd_out, "\r\n* QUOTA ");
                prot_printastring(imapd_out, extname);
                prot_putc(' ', imapd_out);
                print_quota_used(imapd_out, &q);
            }
            quota_free(&q);
            free(extname);
        }
        prot_printf(imapd_out, "\r\n");
    }

    if (doclose) mailbox_close(&mailbox);

    free(intname);

    if (r) {
        prot_printf(imapd_out, "%s NO %s\r\n", tag, error_message(r));
        return;
    }

    imapd_check(NULL, 0);

    prot_printf(imapd_out, "%s OK %s\r\n", tag,
                error_message(IMAP_OK_COMPLETED));
}

/*
 * Parse and perform a SETQUOTA command
 * The command has been parsed up to the resource list
 */
void cmd_setquota(const char *tag, const char *quotaroot)
{
    quota_t newquotas[QUOTA_NUMRESOURCES];
    int res;
    int c;
    int force = 0;
    static struct buf arg;
    int r;
    mbentry_t *mbentry = NULL;
    char *intname = NULL;

    if (!imapd_userisadmin && !imapd_userisproxyadmin) {
        /* need to allow proxies so that mailbox moves can set initial quota
         * roots */
        r = IMAP_PERMISSION_DENIED;
        goto out;
    }

    /* are we forcing the creation of a quotaroot by having a leading +? */
    if (quotaroot[0] == '+') {
        force = 1;
        quotaroot++;
    }

    intname = mboxname_from_external(quotaroot, &imapd_namespace, imapd_userid);

    r = mlookup(NULL, NULL, intname, &mbentry);
    if (r == IMAP_MAILBOX_NONEXISTENT)
        r = 0;      /* will create a quotaroot anyway */
    if (r)
        goto out;

    if (mbentry && (mbentry->mbtype & MBTYPE_REMOTE)) {
        /* remote mailbox */
        struct backend *s;
        char quotarootbuf[MAX_MAILBOX_BUFFER];

        snprintf(quotarootbuf, sizeof(quotarootbuf), "%s.", intname);

        r = mboxlist_allmbox(quotarootbuf, quota_cb, (void *)mbentry->server, 0);
        if (r)
            goto out;

        imapd_check(NULL, 0);

        s = proxy_findserver(mbentry->server, &imap_protocol,
                             proxy_userid, &backend_cached,
                             &backend_current, &backend_inbox, imapd_in);
        if (!s) {
            r = IMAP_SERVER_UNAVAILABLE;
            goto out;
        }

        imapd_check(s, 0);

        prot_printf(s->out, "%s Setquota ", tag);
        prot_printstring(s->out, quotaroot);
        prot_putc(' ', s->out);
        pipe_command(s, 0);
        pipe_including_tag(s, tag, 0);

        free(intname);
        return;

    }
    mboxlist_entry_free(&mbentry);

    /* local mailbox */

    /* Now parse the arguments as a setquota_list */
    c = prot_getc(imapd_in);
    if (c != '(') goto badlist;

    for (res = 0 ; res < QUOTA_NUMRESOURCES ; res++)
        newquotas[res] = QUOTA_UNLIMITED;

    for (;;) {
        /* XXX - limit is actually stored in an int value */
        int32_t limit = 0;

        c = getword(imapd_in, &arg);
        if ((c == ')') && !arg.s[0]) break;
        if (c != ' ') goto badlist;
        res = quota_name_to_resource(arg.s);
        if (res < 0) {
            r = IMAP_UNSUPPORTED_QUOTA;
            goto out;
        }

        c = getsint32(imapd_in, &limit);
        /* note: we accept >= 0 according to RFC 2087,
         * and also -1 to fix Bug #3559 */
        if (limit < -1) goto badlist;
        newquotas[res] = limit;
        if (c == ')') break;
        else if (c != ' ') goto badlist;
    }
    c = prot_getc(imapd_in);
    if (!IS_EOL(c, imapd_in)) {
        prot_printf(imapd_out, "%s BAD Unexpected extra arguments to SETQUOTA\r\n", tag);
        eatline(imapd_in, c);
        return;
    }

    r = mboxlist_setquotas(intname, newquotas, 0, force);

    imapd_check(NULL, 0);
out:
    mboxlist_entry_free(&mbentry);
    free(intname);

    if (r) {
        prot_printf(imapd_out, "%s NO %s\r\n", tag, error_message(r));
        return;
    }

    index_release(imapd_index);
    sync_checkpoint(imapd_in);

    prot_printf(imapd_out, "%s OK %s\r\n", tag,
                error_message(IMAP_OK_COMPLETED));
    return;

 badlist:
    prot_printf(imapd_out, "%s BAD Invalid quota list in Setquota\r\n", tag);
    eatline(imapd_in, c);
    free(intname);
}

#ifdef HAVE_SSL
/*
 * this implements the STARTTLS command, as described in RFC 2595.
 * one caveat: it assumes that no external layer is currently present.
 * if a client executes this command, information about the external
 * layer that was passed on the command line is discarded. this should
 * be fixed.
 */
/* imaps - whether this is an imaps transaction or not */
static void cmd_starttls(char *tag, int imaps)
{
    int result;
    char *localip, *remoteip;

    if (imapd_starttls_done == 1)
    {
        prot_printf(imapd_out, "%s NO TLS already active\r\n", tag);
        return;
    }

    result=tls_init_serverengine("imap",
                                 5,        /* depth to verify */
                                 !imaps,   /* can client auth? */
                                 NULL);

    if (result == -1) {

        syslog(LOG_ERR, "error initializing TLS");

        if (imaps == 0) {
            prot_printf(imapd_out, "%s NO Error initializing TLS\r\n", tag);
        } else {
            shut_down(0);
        }

        return;
    }

    if (imaps == 0)
    {
        prot_printf(imapd_out, "%s OK Begin TLS negotiation now\r\n", tag);
        /* must flush our buffers before starting tls */
        prot_flush(imapd_out);
    }

    /* tls_start_servertls is going to reset saslprops, discarding the
     * iplocalport and ipremoteport fields.  Preserve them, then put them back
     * after the call.
     */
    localip = buf_release(&saslprops.iplocalport);
    remoteip = buf_release(&saslprops.ipremoteport);

    result=tls_start_servertls(0, /* read */
                               1, /* write */
                               imaps ? 180 : imapd_timeout,
                               &saslprops,
                               &tls_conn);

    /* put the iplocalport and ipremoteport back */
    if (localip)  buf_initm(&saslprops.iplocalport, localip, strlen(localip));
    if (remoteip) buf_initm(&saslprops.ipremoteport, remoteip, strlen(remoteip));

    /* if error */
    if (result==-1) {
        if (imaps == 0) {
            prot_printf(imapd_out, "%s NO Starttls negotiation failed\r\n", tag);
            syslog(LOG_NOTICE, "STARTTLS negotiation failed: %s", imapd_clienthost);
            return;
        } else {
            syslog(LOG_NOTICE, "imaps TLS negotiation failed: %s", imapd_clienthost);
            shut_down(0);
        }
    }

    /* tell SASL about the negotiated layer */
    result = saslprops_set_tls(&saslprops, imapd_saslconn);

    if (result != SASL_OK) {
        syslog(LOG_NOTICE, "saslprops_set_tls() failed: cmd_starttls()");
        if (imaps == 0) {
            fatal("saslprops_set_tls() failed: cmd_starttls()", EX_TEMPFAIL);
        } else {
            shut_down(0);
        }
    }

    /* tell the prot layer about our new layers */
    prot_settls(imapd_in, tls_conn);
    prot_settls(imapd_out, tls_conn);

    imapd_starttls_done = 1;
    imapd_tls_required = 0;

#if (OPENSSL_VERSION_NUMBER >= 0x0090800fL)
    imapd_tls_comp = (void *) SSL_get_current_compression(tls_conn);
#endif
}
#else
void cmd_starttls(char *tag __attribute__((unused)),
                  int imaps __attribute__((unused)))
{
    fatal("cmd_starttls() executed, but starttls isn't implemented!",
          EX_SOFTWARE);
}
#endif // (OPENSSL_VERSION_NUMBER >= 0x0090800fL)

static int parse_statusitems(unsigned *statusitemsp, const char **errstr)
{
    static struct buf arg;
    unsigned statusitems = 0;
    int c;
    int hasconv = config_getswitch(IMAPOPT_CONVERSATIONS);

    c = prot_getc(imapd_in);
    if (c != '(') goto bad;

    c = getword(imapd_in, &arg);
    if (arg.s[0] == '\0') goto bad;
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
        else if (!strcmp(arg.s, "mailboxid")) {
            statusitems |= STATUS_MAILBOXID;
        }
        else if (!strcmp(arg.s, "unseen")) {
            statusitems |= STATUS_UNSEEN;
        }
        else if (!strcmp(arg.s, "size")) {
            statusitems |= STATUS_SIZE;
        }
        else if (!strcmp(arg.s, "highestmodseq")) {
            statusitems |= STATUS_HIGHESTMODSEQ;
        }
        else if (!strcmp(arg.s, "createdmodseq")) {
            statusitems |= STATUS_CREATEDMODSEQ;
        }
        else if (hasconv && !strcmp(arg.s, "xconvexists")) {
            statusitems |= STATUS_XCONVEXISTS;
        }
        else if (hasconv && !strcmp(arg.s, "xconvunseen")) {
            statusitems |= STATUS_XCONVUNSEEN;
        }
        else if (hasconv && !strcmp(arg.s, "xconvmodseq")) {
            statusitems |= STATUS_XCONVMODSEQ;
        }
        else {
            static char buf[200];
            snprintf(buf, 200, "Invalid Status attributes %s", arg.s);
            *errstr = buf;
            goto bad;
        }

        if (c == ' ') c = getword(imapd_in, &arg);
        else break;
    }

    if (c != ')') {
        *errstr = "Missing close parenthesis in Status";
        goto bad;
    }
    c = prot_getc(imapd_in);

    /* success */
    *statusitemsp = statusitems;
    return c;

bad:
    if (c != EOF) prot_ungetc(c, imapd_in);
    return EOF;
}

static int print_statusline(const char *extname, unsigned statusitems,
                            struct statusdata *sd)
{
    int sepchar;

    prot_printf(imapd_out, "* STATUS ");
    prot_printastring(imapd_out, extname);
    prot_printf(imapd_out, " ");
    sepchar = '(';

    if (statusitems & STATUS_MESSAGES) {
        prot_printf(imapd_out, "%cMESSAGES %u", sepchar, sd->messages);
        sepchar = ' ';
    }
    if (statusitems & STATUS_RECENT) {
        prot_printf(imapd_out, "%cRECENT %u", sepchar, sd->recent);
        sepchar = ' ';
    }
    if (statusitems & STATUS_UIDNEXT) {
        prot_printf(imapd_out, "%cUIDNEXT %u", sepchar, sd->uidnext);
        sepchar = ' ';
    }
    if (statusitems & STATUS_UIDVALIDITY) {
        prot_printf(imapd_out, "%cUIDVALIDITY %u", sepchar, sd->uidvalidity);
        sepchar = ' ';
    }
    if (statusitems & STATUS_MAILBOXID) {
        prot_printf(imapd_out, "%cMAILBOXID (%s)", sepchar, sd->mailboxid);
        sepchar = ' ';
    }
    if (statusitems & STATUS_UNSEEN) {
        prot_printf(imapd_out, "%cUNSEEN %u", sepchar, sd->unseen);
        sepchar = ' ';
    }
    if (statusitems & STATUS_SIZE) {
        prot_printf(imapd_out, "%cSIZE %llu", sepchar, sd->size);
        sepchar = ' ';
    }
    if (statusitems & STATUS_CREATEDMODSEQ) {
        prot_printf(imapd_out, "%cCREATEDMODSEQ " MODSEQ_FMT,
                    sepchar, sd->createdmodseq);
        sepchar = ' ';
    }
    if (statusitems & STATUS_HIGHESTMODSEQ) {
        prot_printf(imapd_out, "%cHIGHESTMODSEQ " MODSEQ_FMT,
                    sepchar, sd->highestmodseq);
        sepchar = ' ';
    }
    if (statusitems & STATUS_XCONVEXISTS) {
        prot_printf(imapd_out, "%cXCONVEXISTS %u", sepchar, sd->xconv.threadexists);
        sepchar = ' ';
    }
    if (statusitems & STATUS_XCONVUNSEEN) {
        prot_printf(imapd_out, "%cXCONVUNSEEN %u", sepchar, sd->xconv.threadunseen);
        sepchar = ' ';
    }
    if (statusitems & STATUS_XCONVMODSEQ) {
        prot_printf(imapd_out, "%cXCONVMODSEQ " MODSEQ_FMT, sepchar, sd->xconv.threadmodseq);
        sepchar = ' ';
    }

    prot_printf(imapd_out, ")\r\n");

    return 0;
}

static int imapd_statusdata(const mbentry_t *mbentry, unsigned statusitems,
                            struct statusdata *sd)
{
    int r;
    struct conversations_state *state = NULL;

    if (!(statusitems & STATUS_CONVITEMS)) goto nonconv;
    statusitems &= ~STATUS_CONVITEMS; /* strip them for the regular lookup */

    /* use the existing state if possible */
    state = conversations_get_mbox(mbentry->name);

    /* otherwise fetch a new one! */
    if (!state) {
        if (global_conversations) {
            conversations_abort(&global_conversations);
            global_conversations = NULL;
        }
        // we never write anything in STATUS calls, so shared is fine
        r = conversations_open_mbox(mbentry->name, 1/*shared*/, &state);
        if (r) {
            /* maybe the mailbox doesn't even have conversations - just ignore */
            goto nonconv;
        }
        global_conversations = state;
    }

    r = conversation_getstatus(state,
                               CONV_FOLDER_KEY_MBE(state, mbentry), &sd->xconv);
    if (r) return r;

nonconv:
    /* use the index status if we can so we get the 'alive' Recent count */
    if (!strcmpsafe(mbentry->name, index_mboxname(imapd_index)) && imapd_index->mailbox)
        return index_status(imapd_index, sd);

    /* fall back to generic lookup */
    return status_lookup_mbentry(mbentry, imapd_userid, statusitems, sd);
}

/*
 * Parse and perform a STATUS command
 * The command has been parsed up to the attribute list
 */
static void cmd_status(char *tag, char *name)
{
    int c;
    unsigned statusitems = 0;
    const char *errstr = "Bad status string";
    mbentry_t *mbentry = NULL;
    struct statusdata sdata = STATUSDATA_INIT;
    int r = 0;

    char *intname = mboxname_from_external(name, &imapd_namespace, imapd_userid);
    r = mlookup(tag, name, intname, &mbentry);
    if (r == IMAP_MAILBOX_MOVED) {
        /* Eat the argument */
        eatline(imapd_in, prot_getc(imapd_in));
        free(intname);
        return;
    }

    if (!r && (mbentry->mbtype & MBTYPE_REMOTE)) {
        /* remote mailbox */

        if (supports_referrals
            && config_getswitch(IMAPOPT_PROXYD_ALLOW_STATUS_REFERRAL)) {
            imapd_refer(tag, mbentry->server, name);
            /* Eat the argument */
            eatline(imapd_in, prot_getc(imapd_in));
        }
        else {
            struct backend *s;

            s = proxy_findserver(mbentry->server, &imap_protocol,
                                 proxy_userid, &backend_cached,
                                 &backend_current, &backend_inbox, imapd_in);
            if (!s) r = IMAP_SERVER_UNAVAILABLE;

            imapd_check(s, 0);

            if (!r) {
                prot_printf(s->out, "%s Status {" SIZE_T_FMT "+}\r\n%s ", tag,
                            strlen(name), name);
                if (!pipe_command(s, 65536)) {
                    pipe_including_tag(s, tag, 0);
                }
            } else {
                eatline(imapd_in, prot_getc(imapd_in));
                prot_printf(imapd_out, "%s NO %s\r\n", tag, error_message(r));
            }
        }

        goto done;
    }

    /* local mailbox */

    imapd_check(NULL, 0);

    c = parse_statusitems(&statusitems, &errstr);
    if (c == EOF) {
        prot_printf(imapd_out, "%s BAD %s\r\n", tag, errstr);
        eatline(imapd_in, c);
        goto done;
    }

    if (!IS_EOL(c, imapd_in)) {
        prot_printf(imapd_out,
                    "%s BAD Unexpected extra arguments to Status\r\n", tag);
        eatline(imapd_in, c);
        goto done;
    }

    /* check permissions */
    if (!r) {
        int myrights = cyrus_acl_myrights(imapd_authstate, mbentry->acl);

        if (!(myrights & ACL_READ)) {
            r = (imapd_userisadmin || (myrights & ACL_LOOKUP)) ?
                IMAP_PERMISSION_DENIED : IMAP_MAILBOX_NONEXISTENT;
        }
    }

    if (!r) r = imapd_statusdata(mbentry, statusitems, &sdata);

    if (r) {
        prot_printf(imapd_out, "%s NO %s\r\n", tag,
                    error_message(r));
    }
    else {
        print_statusline(name, statusitems, &sdata);
        prot_printf(imapd_out, "%s OK %s\r\n", tag,
                    error_message(IMAP_OK_COMPLETED));
    }

 done:
    if (global_conversations) {
        conversations_abort(&global_conversations);
        global_conversations = NULL;
    }
    mboxlist_entry_free(&mbentry);
    free(intname);
    return;
}

/* Callback for cmd_namespace to be passed to mboxlist_findall.
 * For each top-level mailbox found, print a bit of the response
 * if it is a shared namespace.  The rock is used as an integer in
 * order to ensure the namespace response is correct on a server with
 * no shared namespace.
 */
static int namespacedata(struct findall_data *data, void *rock)
{
    if (!data) return 0;
    int* sawone = (int*) rock;

    switch (data->mb_category) {
    case MBNAME_INBOX:
    case MBNAME_ALTINBOX:
    case MBNAME_ALTPREFIX:
        sawone[NAMESPACE_INBOX] = 1;
        break;

    case MBNAME_OTHERUSER:
        sawone[NAMESPACE_USER] = 1;
        break;

    case MBNAME_SHARED:
        sawone[NAMESPACE_SHARED] = 1;
        break;
    }

    return 0;
}

/*
 * Print out a response to the NAMESPACE command defined by
 * RFC 2342.
 */
static void cmd_namespace(char* tag)
{
    int sawone[3] = {0, 0, 0};
    char* pattern;

    if (SLEEZY_NAMESPACE) {
        if (strlen(imapd_userid) + 5 >= MAX_MAILBOX_BUFFER)
            sawone[NAMESPACE_INBOX] = 0;
        else {
            char *inbox = mboxname_user_mbox(imapd_userid, NULL);
            sawone[NAMESPACE_INBOX] =
                !mboxlist_lookup(inbox, NULL, NULL);
            free(inbox);
        }
        sawone[NAMESPACE_USER] = imapd_userisadmin ? 1 : imapd_namespace.accessible[NAMESPACE_USER];
        sawone[NAMESPACE_SHARED] = imapd_userisadmin ? 1 : imapd_namespace.accessible[NAMESPACE_SHARED];
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

    imapd_check(NULL, 0);

    prot_printf(imapd_out, "%s OK %s\r\n", tag,
                error_message(IMAP_OK_COMPLETED));
}

static int parsecreateargs(struct dlist **extargs)
{
    int c;
    static struct buf arg, val;
    struct dlist *res;
    struct dlist *sub;
    char *p;
    const char *name;

    res = dlist_newkvlist(NULL, "CREATE");

    c = prot_getc(imapd_in);
    if (c == '(') {
        /* new style RFC 4466 arguments */
        do {
            c = getword(imapd_in, &arg);
            name = ucase(arg.s);
            if (c != ' ') goto fail;
            c = prot_getc(imapd_in);
            if (c == '(') {
                /* fun - more lists! */
                sub = dlist_newlist(res, name);
                do {
                    c = getword(imapd_in, &val);
                    dlist_setatom(sub, name, val.s);
                } while (c == ' ');
                if (c != ')') goto fail;
                c = prot_getc(imapd_in);
            }
            else {
                prot_ungetc(c, imapd_in);
                c = getword(imapd_in, &val);
                dlist_setatom(res, name, val.s);
            }
        } while (c == ' ');
        if (c != ')') goto fail;
        c = prot_getc(imapd_in);
    }
    else {
        prot_ungetc(c, imapd_in);
        c = getword(imapd_in, &arg);
        if (c == EOF) goto fail;
        p = strchr(arg.s, '!');
        if (p) {
            /* with a server */
            *p = '\0';
            dlist_setatom(res, "SERVER", arg.s);
            dlist_setatom(res, "PARTITION", p+1);
        }
        else {
            dlist_setatom(res, "PARTITION", arg.s);
        }
    }

    *extargs = res;
    return c;

 fail:
    dlist_free(&res);
    if (c != EOF) prot_ungetc(c, imapd_in);
    return EOF;
}

/*
 * Parse annotate fetch data.
 *
 * This is a generic routine which parses just the annotation data.
 * Any surrounding command text must be parsed elsewhere, ie,
 * GETANNOTATION, FETCH.
 */

static int parse_annotate_fetch_data(const char *tag,
                                     int permessage_flag,
                                     strarray_t *entries,
                                     strarray_t *attribs)
{
    int c;
    static struct buf arg;

    c = prot_getc(imapd_in);
    if (c == EOF) {
        prot_printf(imapd_out,
                    "%s BAD Missing annotation entry\r\n", tag);
        goto baddata;
    }
    else if (c == '(') {
        /* entry list */
        do {
            if (permessage_flag)
                c = getastring(imapd_in, imapd_out, &arg);
            else
                c = getqstring(imapd_in, imapd_out, &arg);
            if (c == EOF) {
                prot_printf(imapd_out,
                            "%s BAD Missing annotation entry\r\n", tag);
                goto baddata;
            }

            /* add the entry to the list */
            strarray_append(entries, arg.s);

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
        if (permessage_flag)
            c = getastring(imapd_in, imapd_out, &arg);
        else
            c = getqstring(imapd_in, imapd_out, &arg);
        if (c == EOF) {
            prot_printf(imapd_out,
                        "%s BAD Missing annotation entry\r\n", tag);
            goto baddata;
        }

        strarray_append(entries, arg.s);
    }

    if (c != ' ' || (c = prot_getc(imapd_in)) == EOF) {
        prot_printf(imapd_out,
                    "%s BAD Missing annotation attribute(s)\r\n", tag);
        goto baddata;
    }

    if (c == '(') {
        /* attrib list */
        do {
            if (permessage_flag)
                c = getastring(imapd_in, imapd_out, &arg);
            else
                c = getqstring(imapd_in, imapd_out, &arg);
            if (c == EOF) {
                prot_printf(imapd_out,
                            "%s BAD Missing annotation attribute(s)\r\n", tag);
                goto baddata;
            }

            /* add the attrib to the list */
            strarray_append(attribs, arg.s);

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
        if (permessage_flag)
            c = getastring(imapd_in, imapd_out, &arg);
        else
            c = getqstring(imapd_in, imapd_out, &arg);
        if (c == EOF) {
            prot_printf(imapd_out,
                        "%s BAD Missing annotation attribute\r\n", tag);
            goto baddata;
        }

        strarray_append(attribs, arg.s);
   }

    return c;

  baddata:
    if (c != EOF) prot_ungetc(c, imapd_in);
    return EOF;
}

/*
 * Parse either a single string or a (bracketed) list of strings.
 * This is used up to three times in the GETMETADATA command.
 */
static int parse_metadata_string_or_list(const char *tag,
                                         strarray_t *entries,
                                         int *is_list)
{
    int c;
    static struct buf arg;

    // Assume by default the arguments are a list of entries,
    // until proven otherwise.
    if (is_list) *is_list = 1;

    c = prot_getc(imapd_in);
    if (c == EOF) {
        prot_printf(imapd_out,
                    "%s BAD Missing metadata entry\r\n", tag);
        goto baddata;
    }
    else if (c == '\r') {
        return c;
    }
    else if (c == '(') {
        /* entry list */
        do {
            c = getastring(imapd_in, imapd_out, &arg);
            if (c == EOF) {
                prot_printf(imapd_out,
                            "%s BAD Missing metadata entry\r\n", tag);
                goto baddata;
            }

            /* add the entry to the list */
            strarray_append(entries, arg.s);

        } while (c == ' ');

        if (c != ')') {
            prot_printf(imapd_out,
                        "%s BAD Missing close paren in metadata entry list \r\n",
                        tag);
            goto baddata;
        }

        if (is_list) *is_list = 0;

        c = prot_getc(imapd_in);
    }
    else {
        /* single entry -- add it to the list */
        prot_ungetc(c, imapd_in);
        c = getastring(imapd_in, imapd_out, &arg);
        if (c == EOF) {
            prot_printf(imapd_out,
                        "%s BAD Missing metadata entry\r\n", tag);
            goto baddata;
        }

        strarray_append(entries, arg.s);

        // It is only not a list if there are no wildcards
        if (!strchr(arg.s, '*') && !strchr(arg.s, '%')) {
            // Not a list
            if (is_list) *is_list = 0;
        }
    }

    if (c == ' ' || c == '\r' || c == ')') return c;

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
 *
 * Also parse RFC 5257 per-message annotation store data, which
 * is almost identical but differs in that entry names and attrib
 * names are astrings rather than strings, and that the whole set
 * of data *must* be enclosed in parentheses.
 */

static int parse_annotate_store_data(const char *tag,
                                     int permessage_flag,
                                     struct entryattlist **entryatts)
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
    else if (permessage_flag) {
        prot_printf(imapd_out,
                    "%s BAD Missing paren for annotation entry\r\n", tag);
        goto baddata;
    }
    else {
        /* single entry -- put the char back */
        prot_ungetc(c, imapd_in);
    }

    do {
        /* get entry */
        if (permessage_flag)
            c = getastring(imapd_in, imapd_out, &entry);
        else
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
            if (permessage_flag)
                c = getastring(imapd_in, imapd_out, &attrib);
            else
                c = getqstring(imapd_in, imapd_out, &attrib);
            if (c == EOF) {
                prot_printf(imapd_out,
                            "%s BAD Missing annotation attribute\r\n", tag);
                goto baddata;
            }

            /* get value */
            if (c != ' ') {
                prot_printf(imapd_out,
                            "%s BAD Missing annotation value\r\n", tag);
                goto baddata;
            }
            c = getbnstring(imapd_in, imapd_out, &value);
            if (c == EOF) {
                prot_printf(imapd_out,
                            "%s BAD Missing annotation value\r\n", tag);
                goto baddata;
            }

            /* add the attrib-value pair to the list */
            appendattvalue(&attvalues, attrib.s, &value);

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
 * Parse metadata store data.
 *
 * This is a generic routine which parses just the annotation data.
 * Any surrounding command text must be parsed elsewhere, ie,
 * SETANNOTATION, STORE, APPEND.
 */
static int parse_metadata_store_data(const char *tag,
                                     struct entryattlist **entryatts)
{
    int c;
    const char *name;
    const char *att;
    static struct buf entry, value;
    struct attvaluelist *attvalues = NULL;
    struct entryattlist *entryp;
    int need_add;

    *entryatts = NULL;

    c = prot_getc(imapd_in);
    if (c != '(') {
        prot_printf(imapd_out,
                    "%s BAD Missing metadata entry list\r\n", tag);
        goto baddata;
    }

    do {
        /* get entry */
        c = getastring(imapd_in, imapd_out, &entry);
        if (c != ' ') {
            prot_printf(imapd_out,
                        "%s BAD Missing metadata entry\r\n", tag);
            goto baddata;
        }
        /* DAV code uses case significant metadata entries, so if you log in with +dav,
         * we make the metadata commands case significant! */
        if (strcasecmpsafe(imapd_magicplus, "+dav"))
            lcase(entry.s);

        /* get value */
        c = getbnstring(imapd_in, imapd_out, &value);
        if (c == EOF) {
            prot_printf(imapd_out,
                        "%s BAD Missing metadata value\r\n", tag);
            goto baddata;
        }

        if (!strncmp(entry.s, "/private", 8) &&
            (entry.s[8] == '\0' || entry.s[8] == '/')) {
            att = "value.priv";
            name = entry.s + 8;
        }
        else if (!strncmp(entry.s, "/shared", 7) &&
                 (entry.s[7] == '\0' || entry.s[7] == '/')) {
            att = "value.shared";
            name = entry.s + 7;
        }
        else {
            prot_printf(imapd_out,
                        "%s BAD entry must begin with /shared or /private\r\n",
                        tag);
            goto baddata;
        }

        need_add = 1;
        for (entryp = *entryatts; entryp; entryp = entryp->next) {
            if (strcmp(entryp->entry, name)) continue;
            /* it's a match, have to append! */
            appendattvalue(&entryp->attvalues, att, &value);
            need_add = 0;
            break;
        }
        if (need_add) {
            appendattvalue(&attvalues, att, &value);
            appendentryatt(entryatts, name, attvalues);
            attvalues = NULL;
        }
    } while (c == ' ');

    if (c != ')') {
        prot_printf(imapd_out,
                    "%s BAD Missing close paren in annotation entry list \r\n",
                    tag);
        goto baddata;
    }

    c = prot_getc(imapd_in);

    return c;

  baddata:
    if (attvalues) freeattvalues(attvalues);
    if (c != EOF) prot_ungetc(c, imapd_in);
    return EOF;
}

static void getannotation_response(const char *mboxname,
                                   uint32_t uid
                                        __attribute__((unused)),
                                   const char *entry,
                                   struct attvaluelist *attvalues,
                                   void *rock __attribute__((unused)))
{
    int sep = '(';
    struct attvaluelist *l;
    char *extname = *mboxname ?
        mboxname_to_external(mboxname, &imapd_namespace, imapd_userid) :
        xstrdup("");  /* server annotation */

    prot_printf(imapd_out, "* ANNOTATION ");
    prot_printastring(imapd_out, extname);
    prot_putc(' ', imapd_out);
    prot_printstring(imapd_out, entry);
    prot_putc(' ', imapd_out);
    for (l = attvalues ; l ; l = l->next) {
        prot_putc(sep, imapd_out);
        sep = ' ';
        prot_printstring(imapd_out, l->attrib);
        prot_putc(' ',  imapd_out);
        prot_printmap(imapd_out, l->value.s, l->value.len);
    }
    prot_printf(imapd_out, ")\r\n");
    free(extname);
}

struct annot_fetch_rock
{
    strarray_t *entries;
    strarray_t *attribs;
    annotate_fetch_cb_t callback;
    void *cbrock;
};

static int annot_fetch_cb(annotate_state_t *astate, void *rock)
{
    struct annot_fetch_rock *arock = rock;
    return annotate_state_fetch(astate, arock->entries, arock->attribs,
                                arock->callback, arock->cbrock);
}

struct annot_store_rock
{
    struct entryattlist *entryatts;
};

static int annot_store_cb(annotate_state_t *astate, void *rock)
{
    struct annot_store_rock *arock = rock;
    return annotate_state_store(astate, arock->entryatts);
}

/*
 * Common code used to apply a function to every mailbox which matches
 * a mailbox pattern, with an annotate_state_t* set up to point to the
 * mailbox.
 */

struct apply_rock {
    annotate_state_t *state;
    int (*proc)(annotate_state_t *, void *data);
    void *data;
    char lastname[MAX_MAILBOX_PATH+1];
    unsigned int nseen;
};

static int apply_cb(struct findall_data *data, void* rock)
{
    if (!data) return 0;
    if (!data->is_exactmatch) return 0;

    struct apply_rock *arock = (struct apply_rock *)rock;
    annotate_state_t *state = arock->state;
    int r;

    strlcpy(arock->lastname, mbname_intname(data->mbname), sizeof(arock->lastname));

    // malloc extra-long to have room for pattern shenanigans later
    /* NOTE: this is a fricking horrible abuse of layers.  We'll be passing the
     * extname less horribly one day */
    const char *extname = mbname_extname(data->mbname, &imapd_namespace, imapd_userid);
    mbentry_t *backdoor = (mbentry_t *)data->mbentry;
    backdoor->ext_name = xmalloc(strlen(extname)+1);
    strcpy(backdoor->ext_name, extname);

    r = annotate_state_set_mailbox_mbe(state, data->mbentry);
    if (r) return r;

    r = arock->proc(state, arock->data);
    arock->nseen++;

    return r;
}

static int apply_mailbox_pattern(annotate_state_t *state,
                                 const char *pattern,
                                 int (*proc)(annotate_state_t *, void *),
                                 void *data)
{
    struct apply_rock arock;
    int r = 0;

    memset(&arock, 0, sizeof(arock));
    arock.state = state;
    arock.proc = proc;
    arock.data = data;

    r = mboxlist_findall(&imapd_namespace,
                         pattern,
                         imapd_userisadmin || imapd_userisproxyadmin,
                         imapd_userid,
                         imapd_authstate,
                         apply_cb, &arock);

    if (!r && !arock.nseen)
        r = IMAP_MAILBOX_NONEXISTENT;

    return r;
}

static int apply_mailbox_array(annotate_state_t *state,
                               const strarray_t *mboxes,
                               int (*proc)(annotate_state_t *, void *),
                               void *rock)
{
    int i;
    mbentry_t *mbentry = NULL;
    char *intname = NULL;
    int r = 0;

    for (i = 0 ; i < mboxes->count ; i++) {
        const char *extname = strarray_nth(mboxes, i);
        intname = mboxname_from_external(extname, &imapd_namespace, imapd_userid);

        r = mboxlist_lookup(intname, &mbentry, NULL);
        if (r)
            break;

        mbentry->ext_name = xstrdup(extname);

        r = annotate_state_set_mailbox_mbe(state, mbentry);
        if (r)
            break;

        r = proc(state, rock);
        if (r)
            break;

        mboxlist_entry_free(&mbentry);
        free(intname);
        intname = NULL;
    }

    mboxlist_entry_free(&mbentry);
    free(intname);

    return r;
}


/*
 * Perform a GETANNOTATION command
 *
 * The command has been parsed up to the entries
 */
static void cmd_getannotation(const char *tag, char *mboxpat)
{
    int c, r = 0;
    strarray_t entries = STRARRAY_INITIALIZER;
    strarray_t attribs = STRARRAY_INITIALIZER;
    annotate_state_t *astate = NULL;

    c = parse_annotate_fetch_data(tag, /*permessage_flag*/0, &entries, &attribs);
    if (c == EOF) {
        eatline(imapd_in, c);
        goto freeargs;
    }

    /* check for CRLF */
    if (!IS_EOL(c, imapd_in)) {
        prot_printf(imapd_out,
                    "%s BAD Unexpected extra arguments to Getannotation\r\n",
                    tag);
        eatline(imapd_in, c);
        goto freeargs;
    }

    if (config_getswitch(IMAPOPT_ANNOTATION_ENABLE_LEGACY_COMMANDS)) {
        astate = annotate_state_new();
        annotate_state_set_auth(astate,
                                imapd_userisadmin || imapd_userisproxyadmin,
                                imapd_userid, imapd_authstate);
        if (!*mboxpat) {
            r = annotate_state_set_server(astate);
            if (!r)
                r = annotate_state_fetch(astate, &entries, &attribs,
                                        getannotation_response, NULL);
        }
        else {
            struct annot_fetch_rock arock;
            arock.entries = &entries;
            arock.attribs = &attribs;
            arock.callback = getannotation_response;
            arock.cbrock = NULL;
            r = apply_mailbox_pattern(astate, mboxpat, annot_fetch_cb, &arock);
        }
        /* we didn't write anything */
        annotate_state_abort(&astate);
    }
    else {
        /* nope, sorry */
        r = IMAP_PERMISSION_DENIED;
    }

    imapd_check(NULL, 0);

    if (r) {
        prot_printf(imapd_out, "%s NO %s\r\n", tag, error_message(r));
    } else {
        prot_printf(imapd_out, "%s OK %s\r\n",
                    tag, error_message(IMAP_OK_COMPLETED));
    }

 freeargs:
    strarray_fini(&entries);
    strarray_fini(&attribs);
}

static void getmetadata_response(const char *mboxname,
                                 uint32_t uid __attribute__((unused)),
                                 const char *entry,
                                 struct attvaluelist *attvalues,
                                 void *rock)
{
    struct getmetadata_options *opts = (struct getmetadata_options *)rock;

    if (strcmpsafe(mboxname, opts->lastname) || !entry) {
        if (opts->items.count) {
            char *extname = NULL;
            size_t i;
            if (opts->lastname)
                extname = mboxname_to_external(opts->lastname, &imapd_namespace, imapd_userid);
            else
                extname = xstrdup("");
            prot_printf(imapd_out, "* METADATA ");
            prot_printastring(imapd_out, extname);
            prot_putc(' ', imapd_out);
            for (i = 0; i + 1 < opts->items.count; i+=2) {
                prot_putc(i ? ' ' : '(', imapd_out);
                const struct buf *key = bufarray_nth(&opts->items, i);
                prot_printmap(imapd_out, key->s, key->len);
                prot_putc(' ', imapd_out);
                const struct buf *val = bufarray_nth(&opts->items, i+1);
                prot_printmap(imapd_out, val->s, val->len);
            }
            prot_printf(imapd_out, ")\r\n");
            free(extname);
        }
        free(opts->lastname);
        opts->lastname = xstrdupnull(mboxname);
        bufarray_fini(&opts->items);
    }

    struct attvaluelist *l;
    struct buf buf = BUF_INITIALIZER;

    for (l = attvalues ; l ; l = l->next) {
        /* size check */
        if (opts->maxsize && l->value.len >= opts->maxsize) {
            if (l->value.len > opts->biggest) opts->biggest = l->value.len;
            continue;
        }
        /* check if it's a value we print... */
        buf_reset(&buf);
        if (!strcmp(l->attrib, "value.shared"))
            buf_appendcstr(&buf, "/shared");
        else if (!strcmp(l->attrib, "value.priv"))
            buf_appendcstr(&buf, "/private");
        else
            continue;
        buf_appendcstr(&buf, entry);

        bufarray_append(&opts->items, &buf);
        bufarray_append(&opts->items, &l->value);
    }
    buf_free(&buf);
}

static int parse_getmetadata_options(const strarray_t *sa,
                                     struct getmetadata_options *opts)
{
    int i;
    int n = 0;
    struct getmetadata_options dummy = OPTS_INITIALIZER;

    if (!opts) opts = &dummy;

    for (i = 0 ; i < sa->count ; i+=2) {
        const char *option = sa->data[i];
        const char *value = sa->data[i+1];
        if (!value)
            return -1;
        if (!strcasecmp(option, "MAXSIZE")) {
            char *end = NULL;
            /* we add one so that it's "less than" maxsize
             * and zero works but is still true */
            opts->maxsize = strtoul(value, &end, 10) + 1;
            if (!end || *end || end == value)
                return -1;
            n++;
        }
        else if (!strcasecmp(option, "DEPTH")) {
            if (!strcmp(value, "0"))
                opts->depth = 0;
            else if (!strcmp(value, "1"))
                opts->depth = 1;
            else if (!strcasecmp(value, "infinity"))
                opts->depth = -1;
            else
                return -1;
            n++;
        }
        else {
            return 0;
        }
    }

    return n;
}

static int _metadata_to_annotate(const strarray_t *entries,
                                 strarray_t *newa, strarray_t *newe,
                                 const char *tag, int depth)
{
    int i;
    int have_shared = 0;
    int have_private = 0;

    /* we need to rewrite the entries and attribs to match the way that
     * the old annotation system works. */
    for (i = 0 ; i < entries->count ; i++) {
        char *ent = entries->data[i];
        char entry[MAX_MAILBOX_NAME+1];

        lcase(ent);
        /* there's no way to perfect this - unfortunately - the old style
         * syntax doesn't support everything.  XXX - will be nice to get
         * rid of this... */
        if (!strncmp(ent, "/private", 8) &&
            (ent[8] == '\0' || ent[8] == '/')) {
            xstrncpy(entry, ent + 8, MAX_MAILBOX_NAME);
            have_private = 1;
        }
        else if (!strncmp(ent, "/shared", 7) &&
                 (ent[7] == '\0' || ent[7] == '/')) {
            xstrncpy(entry, ent + 7, MAX_MAILBOX_NAME);
            have_shared = 1;
        }
        else {
            if (tag)
                prot_printf(imapd_out,
                            "%s BAD entry must begin with /shared or /private\r\n",
                            tag);
            return IMAP_NO_NOSUCHMSG;
        }
        strarray_append(newe, entry);
        if (depth == 1) {
            strncat(entry, "/%", MAX_MAILBOX_NAME);
            strarray_append(newe, entry);
        }
        else if (depth == -1) {
            strncat(entry, "/*", MAX_MAILBOX_NAME);
            strarray_append(newe, entry);
        }
    }

    if (have_private) strarray_append(newa, "value.priv");
    if (have_shared) strarray_append(newa, "value.shared");

    return 0;
}

/*
 * Perform a GETMETADATA command
 *
 * The command has been parsed up to the mailbox
 */
static void cmd_getmetadata(const char *tag)
{
    int c, r = 0;
    strarray_t lists[3] = { STRARRAY_INITIALIZER,
                            STRARRAY_INITIALIZER,
                            STRARRAY_INITIALIZER };
    int is_list[3] = { 1, 1, 1 };
    int nlists = 0;
    strarray_t *options = NULL;
    strarray_t *mboxes = NULL;
    strarray_t *entries = NULL;
    strarray_t newe = STRARRAY_INITIALIZER;
    strarray_t newa = STRARRAY_INITIALIZER;
    struct buf arg1 = BUF_INITIALIZER;
    int mbox_is_pattern = 0;
    struct getmetadata_options opts = OPTS_INITIALIZER;
    annotate_state_t *astate = NULL;

    while (nlists < 3)
    {
        c = parse_metadata_string_or_list(tag, &lists[nlists], &is_list[nlists]);
        nlists++;
        if (c == '\r' || c == EOF)
            break;
    }

    /* check for CRLF */
    if (c == '\r') {

        c = prot_getc(imapd_in);

        if (c != '\n') {
            prot_printf(imapd_out,
                        "%s BAD Unexpected extra arguments to Getannotation\r\n",
                        tag);
            eatline(imapd_in, c);
            goto freeargs;
        }
    } else {
        // Make sure this line is gone
        eatline(imapd_in, c);
    }

    /*
     * We have three strings or lists of strings.  Now to figure out
     * what's what.  We have two complicating factors.  First, due to
     * a erratum in RFC 5464 and our earlier misreading of the document,
     * we historically supported specifying the options *after* the
     * mailbox name.  Second, we have for a few months now supported
     * a non-standard extension where a list of mailbox names could
     * be supplied instead of just a single one.  So we have to apply
     * some rules.  We support the following syntaxes:
     *
     * --- no options
     * mailbox entry
     * mailbox (entries)
     * (mailboxes) entry
     * (mailboxes) (entries)
     *
     * --- options in the correct place (per the ABNF in RFC 5464)
     * (options) mailbox entry
     * (options) mailbox (entries)
     * (options) (mailboxes) entry
     * (options) (mailboxes) (entries)
     *
     * --- options in the wrong place (per the examples in RFC 5464)
     * mailbox (options) entry
     * mailbox (options) (entries)
     * (mailboxes) (options) entry
     * (mailboxes) (options) (entries)
     */
    if (nlists < 2)
        goto missingargs;
    entries = &lists[nlists-1];     /* entries always last */
    if (nlists == 2) {
        /* no options */
        mboxes = &lists[0];
        mbox_is_pattern = is_list[0];
    }
    if (nlists == 3) {
        /* options, either before or after */
        int r0 = (parse_getmetadata_options(&lists[0], NULL) > 0);
        int r1 = (parse_getmetadata_options(&lists[1], NULL) > 0);
        switch ((r1<<1)|r0) {
        case 0:
            /* neither are valid options */
            goto missingargs;
        case 1:
            /* (options) (mailboxes) */
            options = &lists[0];
            mboxes = &lists[1];
            mbox_is_pattern = is_list[1];
            break;
        case 2:
            /* (mailboxes) (options) */
            mboxes = &lists[0];
            mbox_is_pattern = is_list[0];
            options = &lists[1];
            break;
        case 3:
            /* both appear like valid options */
            prot_printf(imapd_out,
                        "%s BAD Too many option lists for Getmetadata\r\n",
                        tag);
            eatline(imapd_in, c);
            goto freeargs;
        }
    }

    if (options) parse_getmetadata_options(options, &opts);

    if (_metadata_to_annotate(entries, &newa, &newe, tag, opts.depth))
        goto freeargs;

    astate = annotate_state_new();
    annotate_state_set_auth(astate,
                            imapd_userisadmin || imapd_userisproxyadmin,
                            imapd_userid, imapd_authstate);
    if (!mboxes->count || !strcmpsafe(mboxes->data[0], NULL)) {
        r = annotate_state_set_server(astate);
        if (!r)
            r = annotate_state_fetch(astate, &newe, &newa,
                                     getmetadata_response, &opts);
    }
    else {
        struct annot_fetch_rock arock;
        arock.entries = &newe;
        arock.attribs = &newa;
        arock.callback = getmetadata_response;
        arock.cbrock = &opts;
        if (mbox_is_pattern)
            r = apply_mailbox_pattern(astate, mboxes->data[0], annot_fetch_cb, &arock);
        else
            r = apply_mailbox_array(astate, mboxes, annot_fetch_cb, &arock);
    }
    /* we didn't write anything */
    annotate_state_abort(&astate);

    getmetadata_response(NULL, 0, NULL, NULL, &opts);

    imapd_check(NULL, 0);

    if (r) {
        prot_printf(imapd_out, "%s NO %s\r\n", tag, error_message(r));
    } else if (opts.maxsize && opts.biggest > opts.maxsize) {
        prot_printf(imapd_out, "%s OK [METADATA LONGENTRIES %u] %s\r\n",
                    tag, (unsigned)opts.biggest, error_message(IMAP_OK_COMPLETED));
    } else {
        prot_printf(imapd_out, "%s OK %s\r\n",
                    tag, error_message(IMAP_OK_COMPLETED));
    }

freeargs:
    strarray_fini(&lists[0]);
    strarray_fini(&lists[1]);
    strarray_fini(&lists[2]);
    strarray_fini(&newe);
    strarray_fini(&newa);
    buf_free(&arg1);
    return;

missingargs:
    prot_printf(imapd_out, "%s BAD Missing arguments to Getmetadata\r\n", tag);
    eatline(imapd_in, c);
    goto freeargs;
}

/*
 * Perform a SETANNOTATION command
 *
 * The command has been parsed up to the entry-att list
 */
static void cmd_setannotation(const char *tag, char *mboxpat)
{
    int c, r = 0;
    struct entryattlist *entryatts = NULL;
    annotate_state_t *astate = NULL;

    c = parse_annotate_store_data(tag, 0, &entryatts);
    if (c == EOF) {
        eatline(imapd_in, c);
        goto freeargs;
    }

    /* check for CRLF */
    if (!IS_EOL(c, imapd_in)) {
        prot_printf(imapd_out,
                    "%s BAD Unexpected extra arguments to Setannotation\r\n",
                    tag);
        eatline(imapd_in, c);
        goto freeargs;
    }

    if (config_getswitch(IMAPOPT_ANNOTATION_ENABLE_LEGACY_COMMANDS)) {
        astate = annotate_state_new();
        annotate_state_set_auth(astate, imapd_userisadmin,
                                imapd_userid, imapd_authstate);
        if (!r) {
            if (!*mboxpat) {
                r = annotate_state_set_server(astate);
                if (!r)
                    r = annotate_state_store(astate, entryatts);
            }
            else {
                struct annot_store_rock arock;
                arock.entryatts = entryatts;
                r = apply_mailbox_pattern(astate, mboxpat, annot_store_cb, &arock);
            }
        }
        if (!r)
            annotate_state_commit(&astate);
        else
            annotate_state_abort(&astate);
    }
    else {
        /* nope, sorry */
        r = IMAP_PERMISSION_DENIED;
    }

    imapd_check(NULL, 0);

    if (r) {
        prot_printf(imapd_out, "%s NO %s\r\n", tag, error_message(r));
    } else {
        index_release(imapd_index);
        sync_checkpoint(imapd_in);

        prot_printf(imapd_out, "%s OK %s\r\n", tag,
                    error_message(IMAP_OK_COMPLETED));
    }

  freeargs:
    if (entryatts) freeentryatts(entryatts);
}

/*
 * Perform a SETMETADATA command
 *
 * The command has been parsed up to the entry-att list
 */
static void cmd_setmetadata(const char *tag, char *mboxpat)
{
    int c, r = 0;
    struct entryattlist *entryatts = NULL;
    annotate_state_t *astate = NULL;

    c = parse_metadata_store_data(tag, &entryatts);
    if (c == EOF) {
        eatline(imapd_in, c);
        goto freeargs;
    }

    /* check for CRLF */
    if (!IS_EOL(c, imapd_in)) {
        prot_printf(imapd_out,
                    "%s BAD Unexpected extra arguments to Setmetadata\r\n",
                    tag);
        eatline(imapd_in, c);
        goto freeargs;
    }

    astate = annotate_state_new();
    annotate_state_set_auth(astate, imapd_userisadmin,
                            imapd_userid, imapd_authstate);
    if (!r) {
        if (!*mboxpat) {
            r = annotate_state_set_server(astate);
            if (!r)
                r = annotate_state_store(astate, entryatts);
        }
        else {
            struct annot_store_rock arock;
            arock.entryatts = entryatts;
            r = apply_mailbox_pattern(astate, mboxpat, annot_store_cb, &arock);
        }
    }
    if (!r)
        r = annotate_state_commit(&astate);
    else
        annotate_state_abort(&astate);

    imapd_check(NULL, 0);

    if (r) {
        prot_printf(imapd_out, "%s NO %s\r\n", tag, error_message(r));
    } else {
        index_release(imapd_index);
        sync_checkpoint(imapd_in);

        prot_printf(imapd_out, "%s OK %s\r\n", tag,
                    error_message(IMAP_OK_COMPLETED));
    }

  freeargs:
    if (entryatts) freeentryatts(entryatts);
    return;
}


static void cmd_xrunannotator(const char *tag, const char *sequence,
                              int usinguid)
{
    const char *cmd = usinguid ? "UID Xrunannotator" : "Xrunannotator";
    clock_t start = clock();
    char mytime[100];
    int r = 0;

    if (backend_current) {
        /* remote mailbox */
        prot_printf(backend_current->out, "%s %s %s ", tag, cmd, sequence);
        if (!pipe_command(backend_current, 65536)) {
            pipe_including_tag(backend_current, tag, 0);
        }
        return;
    }

    /* local mailbox */

    r = index_run_annotator(imapd_index, sequence, usinguid,
                            &imapd_namespace, imapd_userisadmin);

    index_release(imapd_index);
    sync_checkpoint(imapd_in);

    snprintf(mytime, sizeof(mytime), "%2.3f",
             (clock() - start) / (double) CLOCKS_PER_SEC);

    if (r)
        prot_printf(imapd_out, "%s NO %s (%s sec)\r\n", tag,
                    error_message(r), mytime);
    else
        prot_printf(imapd_out, "%s OK %s (%s sec)\r\n", tag,
                    error_message(IMAP_OK_COMPLETED), mytime);
}


static void cmd_xwarmup(const char *tag)
{
    const char *cmd = "Xwarmup";
    clock_t start = clock();
    char mytime[100];
    struct buf arg = BUF_INITIALIZER;
    int warmup_flags = 0;
    struct seqset *uids = NULL;
    /* We deal with the mboxlist API instead of the index_state API or
     * mailbox API to avoid the overhead of index_open(), which will
     * block while reading all the cyrus.index...we want to be
     * non-blocking */
    struct mboxlist_entry *mbentry = NULL;
    int myrights;
    int c, r = 0;
    char *intname = NULL;

    /* parse arguments: expect <mboxname> '('<warmup-items>')' */

    c = getastring(imapd_in, imapd_out, &arg);
    if (c != ' ') {
syntax_error:
        prot_printf(imapd_out, "%s BAD syntax error in %s\r\n", tag, cmd);
        eatline(imapd_in, c);
        goto out_noprint;
    }

    intname = mboxname_from_external(arg.s, &imapd_namespace, imapd_userid);
    r = mboxlist_lookup(intname, &mbentry, NULL);
    if (r) goto out;

    /* Do a permissions check to avoid server DoS opportunity.  But we
     * only need read permission to warmup a mailbox.  Also, be careful
     * to avoid telling the client about the existence of mailboxes to
     * which he doesn't have LOOKUP rights. */
    r = IMAP_PERMISSION_DENIED;
    myrights = (mbentry->acl ? cyrus_acl_myrights(imapd_authstate, mbentry->acl) : 0);
    if (imapd_userisadmin)
        r = 0;
    else if (!(myrights & ACL_LOOKUP))
        r = IMAP_MAILBOX_NONEXISTENT;
    else if (myrights & ACL_READ)
        r = 0;
    if (r) goto out;

    if (mbentry->mbtype & MBTYPE_REMOTE) {
        /* remote mailbox */
        struct backend *be;

        be = proxy_findserver(mbentry->server, &imap_protocol,
                              proxy_userid, &backend_cached,
                              &backend_current, &backend_inbox, imapd_in);
        if (!be) {
            r = IMAP_SERVER_UNAVAILABLE;
            goto out;
        }

        prot_printf(be->out, "%s %s %s ", tag, cmd, arg.s);
        if (!pipe_command(backend_current, 65536)) {
            pipe_including_tag(backend_current, tag, 0);
        }
        goto out;
    }
    /* local mailbox */

    /* parse the arguments after the mailbox */

    c = prot_getc(imapd_in);
    if (c != '(') goto syntax_error;

    for (;;) {
        c = getword(imapd_in, &arg);
        if (arg.len) {
            if (!strcasecmp(arg.s, "index"))
                warmup_flags |= WARMUP_INDEX;
            else if (!strcasecmp(arg.s, "conversations"))
                warmup_flags |= WARMUP_CONVERSATIONS;
            else if (!strcasecmp(arg.s, "annotations"))
                warmup_flags |= WARMUP_ANNOTATIONS;
            else if (!strcasecmp(arg.s, "search"))
                warmup_flags |= WARMUP_SEARCH;
            else if (!strcasecmp(arg.s, "uids")) {
                if (c != ' ') goto syntax_error;
                c = getword(imapd_in, &arg);
                if (c == EOF) goto syntax_error;
                if (!imparse_issequence(arg.s)) goto syntax_error;
                uids = seqset_parse(arg.s, NULL, /*maxval*/0);
                if (!uids) goto syntax_error;
            }
            else if (!strcasecmp(arg.s, "all"))
                warmup_flags |= WARMUP_ALL;
            else
                goto syntax_error;
        }
        if (c == ')')
            break;
        if (c != ' ') goto syntax_error;
    }

    /* we're expecting no more arguments */
    c = prot_getc(imapd_in);
    if (!IS_EOL(c, imapd_in)) goto syntax_error;

    r = index_warmup(mbentry, warmup_flags, uids);

out:
    snprintf(mytime, sizeof(mytime), "%2.3f",
             (clock() - start) / (double) CLOCKS_PER_SEC);

    if (r)
        prot_printf(imapd_out, "%s NO %s (%s sec)\r\n", tag,
                    error_message(r), mytime);
    else
        prot_printf(imapd_out, "%s OK %s (%s sec)\r\n", tag,
                    error_message(IMAP_OK_COMPLETED), mytime);

out_noprint:
    mboxlist_entry_free(&mbentry);
    free(intname);
    buf_free(&arg);
    if (uids) seqset_free(uids);
}

static void free_snippetargs(struct snippetargs **sap)
{
    while (*sap) {
        struct snippetargs *sa = *sap;
        *sap = sa->next;
        free(sa->mboxname);
        free(sa->uids.data);
        free(sa);
    }
}

static int get_snippetargs(struct snippetargs **sap)
{
    int c;
    struct snippetargs **prevp = sap;
    struct snippetargs *sa = NULL;
    struct buf arg = BUF_INITIALIZER;
    uint32_t uid;
    char *intname = NULL;

    c = prot_getc(imapd_in);
    if (c != '(') goto syntax_error;

    for (;;) {
        c = prot_getc(imapd_in);
        if (c == ')') break;
        if (c != '(') goto syntax_error;

        c = getastring(imapd_in, imapd_out, &arg);
        if (c != ' ') goto syntax_error;

        intname = mboxname_from_external(buf_cstring(&arg), &imapd_namespace, imapd_userid);

        /* allocate a new snippetargs */
        sa = xzmalloc(sizeof(struct snippetargs));
        sa->mboxname = xstrdup(intname);
        /* append to the list */
        *prevp = sa;
        prevp = &sa->next;

        c = getuint32(imapd_in, &sa->uidvalidity);
        if (c != ' ') goto syntax_error;

        c = prot_getc(imapd_in);
        if (c != '(') break;
        for (;;) {
            c = getuint32(imapd_in, &uid);
            if (c != ' ' && c != ')') goto syntax_error;
            if (sa->uids.count + 1 > sa->uids.alloc) {
                sa->uids.alloc += 64;
                sa->uids.data = xrealloc(sa->uids.data,
                                         sizeof(uint32_t) * sa->uids.alloc);
            }
            sa->uids.data[sa->uids.count++] = uid;
            if (c == ')') break;
        }

        c = prot_getc(imapd_in);
        if (c != ')') goto syntax_error;
    }

    c = prot_getc(imapd_in);
    if (c != ' ') goto syntax_error;

out:
    free(intname);
    buf_free(&arg);
    return c;

syntax_error:
    free_snippetargs(sap);
    c = EOF;
    goto out;
}

static void cmd_dump(char *tag, char *name, int uid_start)
{
    int r = 0;
    struct mailbox *mailbox = NULL;

    /* administrators only please */
    if (!imapd_userisadmin)
        r = IMAP_PERMISSION_DENIED;

    char *intname = mboxname_from_external(name, &imapd_namespace, imapd_userid);

    if (!r) r = mailbox_open_irl(intname, &mailbox);

    if (!r) r = dump_mailbox(tag, mailbox, uid_start, MAILBOX_MINOR_VERSION,
                             imapd_in, imapd_out, imapd_authstate);

    if (r) {
        prot_printf(imapd_out, "%s NO %s\r\n", tag, error_message(r));
    } else {
        prot_printf(imapd_out, "%s OK %s\r\n", tag,
                    error_message(IMAP_OK_COMPLETED));
    }

    if (mailbox) mailbox_close(&mailbox);
    free(intname);
}

static void cmd_undump(char *tag, char *name)
{
    int r = 0;
    mbname_t *mbname = mbname_from_extname(name, &imapd_namespace, imapd_userid);

    /* administrators only please */
    if (!imapd_userisadmin)
        r = IMAP_PERMISSION_DENIED;

    struct mboxlock *namespacelock = mboxname_usernamespacelock(mbname_intname(mbname));

    if (!r) r = mlookup(tag, name, mbname_intname(mbname), NULL);

    if (!r) r = undump_mailbox(mbname_intname(mbname), imapd_in, imapd_out, imapd_authstate);

    mboxname_release(&namespacelock);

    if (r) {
        prot_printf(imapd_out, "%s NO %s%s\r\n",
                    tag,
                    (r == IMAP_MAILBOX_NONEXISTENT &&
                     mboxlist_createmailboxcheck(mbname_intname(mbname), 0, 0,
                                                 imapd_userisadmin,
                                                 imapd_userid, imapd_authstate,
                                                 NULL, NULL, 0) == 0)
                    ? "[TRYCREATE] " : "", error_message(r));
    } else {
        prot_printf(imapd_out, "%s OK %s\r\n", tag,
                    error_message(IMAP_OK_COMPLETED));
    }
    mbname_free(&mbname);
}

static int getresult(struct protstream *p, const char *tag)
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
    int c;              /* getword() returns an int */
    struct buf cmd, tmp, user;
    int r = 0;

    memset(&cmd, 0, sizeof(struct buf));
    memset(&tmp, 0, sizeof(struct buf));
    memset(&user, 0, sizeof(struct buf));

    prot_printf(pout, "ACL0 GETACL {" SIZE_T_FMT "+}\r\n%s\r\n",
                strlen(mailbox), mailbox);

    while(1) {
        c = prot_getc(pin);
        if (c != '*') {
            prot_ungetc(c, pin);
            r = getresult(pin, "ACL0");
            break;
        }

        c = prot_getc(pin);  /* skip SP */
        c = getword(pin, &cmd);
        if (c == EOF) {
            r = IMAP_SERVER_UNAVAILABLE;
            break;
        }

        if (!strncmp(cmd.s, "ACL", 3)) {
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
                if(c == '\n') break;  /* end of * ACL */

                c = getastring(pin, pout, &user);
                if (c == EOF) {
                    r = IMAP_SERVER_UNAVAILABLE;
                    goto cleanup;
                }

                snprintf(tagbuf, sizeof(tagbuf), "ACL%d", ++i);

                prot_printf(pout, "%s DELETEACL {" SIZE_T_FMT "+}\r\n%s"
                            " {" SIZE_T_FMT "+}\r\n%s\r\n",
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
        }
        else {
            /* skip this line, we don't really care */
            eatline(pin, c);
        }
    }

    cleanup:

    /* Now cleanup after all the DELETEACL commands */
    if(!r) {
        while(j < i) {
            snprintf(tagbuf, sizeof(tagbuf), "ACL%d", ++j);
            r = getresult(pin, tagbuf);
            if (r) break;
        }
    }

    if(r) eatline(pin, c);

    buf_free(&user);
    buf_free(&tmp);
    buf_free(&cmd);

    return r;
}

static int dumpacl(struct protstream *pin, struct protstream *pout,
                   const char *mboxname, const char *acl_in)
{
    int r = 0;
    char tag[128];
    int tagnum = 1;
    char *rights, *nextid;
    char *acl_safe = acl_in ? xstrdup(acl_in) : NULL;
    char *acl = acl_safe;

    while (acl) {
        rights = strchr(acl, '\t');
        if (!rights) break;
        *rights++ = '\0';

        nextid = strchr(rights, '\t');
        if (!nextid) break;
        *nextid++ = '\0';

        snprintf(tag, sizeof(tag), "SACL%d", tagnum++);

        prot_printf(pout, "%s SETACL {" SIZE_T_FMT "+}\r\n%s"
                    " {" SIZE_T_FMT "+}\r\n%s {" SIZE_T_FMT "+}\r\n%s\r\n",
                    tag,
                    strlen(mboxname), mboxname,
                    strlen(acl), acl,
                    strlen(rights), rights);

        r = getresult(pin, tag);
        if (r) break;

        acl = nextid;
    }

    if(acl_safe) free(acl_safe);

    return r;
}

enum {
    XFER_MOVING_USER = -1,
    XFER_DEACTIVATED = 1,
    XFER_REMOTE_CREATED,
    XFER_LOCAL_MOVING,
    XFER_UNDUMPED,
};

struct xfer_item {
    mbentry_t *mbentry;
    char extname[MAX_MAILBOX_NAME];
    struct mailbox *mailbox;
    int state;
    struct xfer_item *next;
};

struct xfer_header {
    struct sync_client_state sync_cs;
    int remoteversion;
    unsigned long use_replication;
    char *userid;
    char *toserver;
    char *topart;
    struct seen *seendb;
    struct xfer_item *items;
};

static int xfer_mupdate(int isactivate,
                        const char *mboxname, const char *part,
                        const char *servername, const char *acl)
{
    char buf[MAX_PARTITION_LEN+HOSTNAME_SIZE+2];
    int retry = 0;
    int r = 0;

    /* no mupdate handle */
    if (!mupdate_h) return 0;

    snprintf(buf, sizeof(buf), "%s!%s", servername, part);

retry:
    /* make the change */
    if (isactivate)
        r = mupdate_activate(mupdate_h, mboxname, buf, acl);
    else
        r = mupdate_deactivate(mupdate_h, mboxname, buf);

    if (r && !retry) {
        syslog(LOG_INFO, "MUPDATE: lost connection, retrying");
        mupdate_disconnect(&mupdate_h);
        r = mupdate_connect(config_mupdate_server, NULL, &mupdate_h, NULL);
        if (r) {
            syslog(LOG_INFO, "Failed to connect to mupdate '%s'",
                   config_mupdate_server);
        }
        else {
            retry = 1;
            goto retry;
        }
    }

    return r;
}

/* nothing you can do about failures, just try to clean up */
static void xfer_cleanup(struct xfer_header *xfer)
{
    struct xfer_item *item, *next;

    /* remove items */
    item = xfer->items;
    while (item) {
        next = item->next;
        mboxlist_entry_free(&item->mbentry);
        free(item);
        item = next;
    }
    xfer->items = NULL;

    free(xfer->topart);
    free(xfer->userid);
    xfer->topart = xfer->userid = NULL;

    seen_close(&xfer->seendb);
    xfer->seendb = NULL;
}

static void xfer_done(struct xfer_header **xferptr)
{
    struct xfer_header *xfer = *xferptr;

    syslog(LOG_INFO, "XFER: disconnecting from servers");

    /* The sync_cs.backend connection is in backend_cached[],
       so it will be disconnected and freed in imapd_reset() */
    buf_free(&xfer->sync_cs.tagbuf);

    free(xfer->toserver);

    xfer_cleanup(xfer);

    free(xfer);

    *xferptr = NULL;
}

static int xfer_init(const char *toserver, struct xfer_header **xferptr)
{
    struct xfer_header *xfer = xzmalloc(sizeof(struct xfer_header));
    int r;

    syslog(LOG_INFO, "XFER: connecting to server '%s'", toserver);

    xfer->sync_cs.servername = toserver;
    xfer->sync_cs.flags = SYNC_FLAG_LOGGING | SYNC_FLAG_LOCALONLY;

    /* Get a connection to the remote backend */
    xfer->sync_cs.backend = proxy_findserver(toserver, &imap_protocol, "", &backend_cached,
                                             NULL, NULL, imapd_in);
    if (!xfer->sync_cs.backend) {
        syslog(LOG_ERR, "Failed to connect to server '%s'", toserver);
        r = IMAP_SERVER_UNAVAILABLE;
        goto fail;
    }

    struct backend *be = xfer->sync_cs.backend;
    xfer->sync_cs.clientin = be->in;
    xfer->remoteversion = backend_version(be);
    if (be->capability & CAPA_REPLICATION) {
        syslog(LOG_INFO, "XFER: destination supports replication");
        xfer->use_replication = 1;
        be->in->userdata = be->out->userdata = &xfer->sync_cs.tagbuf;
    }

    xfer->toserver = xstrdup(toserver);
    xfer->topart = NULL;
    xfer->seendb = NULL;

    /* connect to mupdate server if configured */
    if (config_mupdate_server && !mupdate_h) {
        syslog(LOG_INFO, "XFER: connecting to mupdate '%s'",
               config_mupdate_server);

        r = mupdate_connect(config_mupdate_server, NULL, &mupdate_h, NULL);
        if (r) {
            syslog(LOG_INFO, "Failed to connect to mupdate '%s'",
                   config_mupdate_server);
            goto fail;
        }
    }

    *xferptr = xfer;
    return 0;

fail:
    xfer_done(&xfer);
    return r;
}

static int xfer_localcreate(struct xfer_header *xfer)
{
    struct xfer_item *item;
    int r;

    syslog(LOG_INFO, "XFER: creating mailboxes on destination");

    for (item = xfer->items; item; item = item->next) {
        struct backend *be = xfer->sync_cs.backend;
        if (xfer->topart) {
            /* need to send partition as an atom */
            prot_printf(be->out, "LC1 LOCALCREATE {" SIZE_T_FMT "+}\r\n%s %s\r\n",
                        strlen(item->extname), item->extname, xfer->topart);
        } else {
            prot_printf(be->out, "LC1 LOCALCREATE {" SIZE_T_FMT "+}\r\n%s\r\n",
                        strlen(item->extname), item->extname);
        }
        r = getresult(be->in, "LC1");
        if (r) {
            syslog(LOG_ERR, "Could not move mailbox: %s, LOCALCREATE failed",
                   item->mbentry->name);
            return r;
        }

        item->state = XFER_REMOTE_CREATED;
    }

    return 0;
}

static int xfer_backport_seen_item(struct xfer_item *item,
                                   struct seen *seendb)
{
    struct mailbox *mailbox = item->mailbox;
    struct seqset *outlist = NULL;
    struct seendata sd = SEENDATA_INITIALIZER;
    int r;

    outlist = seqset_init(mailbox->i.last_uid, SEQ_MERGE);

    struct mailbox_iter *iter = mailbox_iter_init(mailbox, 0, ITER_SKIP_EXPUNGED);

    const message_t *msg;
    while ((msg = mailbox_iter_step(iter))) {
        const struct index_record *record = msg_record(msg);
        if (record->system_flags & FLAG_SEEN)
            seqset_add(outlist, record->uid, 1);
        else
            seqset_add(outlist, record->uid, 0);
    }

    mailbox_iter_done(&iter);

    sd.lastread = mailbox->i.recenttime;
    sd.lastuid = mailbox->i.recentuid;
    sd.lastchange = mailbox->i.last_appenddate;
    sd.seenuids = seqset_cstring(outlist);
    if (!sd.seenuids) sd.seenuids = xstrdup("");

    r = seen_write(seendb, mailbox->uniqueid, &sd);

    seen_freedata(&sd);
    seqset_free(outlist);

    return r;
}

static int xfer_deactivate(struct xfer_header *xfer)
{
    struct xfer_item *item;
    int r;

    syslog(LOG_INFO, "XFER: deactivating mailboxes");

    /* Step 3: mupdate.DEACTIVATE(mailbox, newserver) */
    for (item = xfer->items; item; item = item->next) {
        r = xfer_mupdate(0, item->mbentry->name, item->mbentry->partition,
                         config_servername, item->mbentry->acl);
        if (r) {
            syslog(LOG_ERR,
                   "Could not move mailbox: %s, MUPDATE DEACTIVATE failed",
                   item->mbentry->name);
            return r;
        }

        item->state = XFER_DEACTIVATED;
    }

    return 0;
}

static int xfer_undump(struct xfer_header *xfer)
{
    struct xfer_item *item;
    int r;
    mbentry_t *newentry;
    struct mailbox *mailbox = NULL;

    syslog(LOG_INFO, "XFER: dumping mailboxes to destination");

    for (item = xfer->items; item; item = item->next) {
        r = mailbox_open_irl(item->mbentry->name, &mailbox);
        if (r) {
            syslog(LOG_ERR,
                   "Failed to open mailbox %s for dump_mailbox() %s",
                   item->mbentry->name, error_message(r));
            return r;
        }

        /* Step 3.5: Set mailbox as MOVING on local server */
        /* XXX - this code is awful... need a sane way to manage mbentries */
        newentry = mboxlist_entry_create();
        newentry->name = xstrdupnull(item->mbentry->name);
        newentry->acl = xstrdupnull(item->mbentry->acl);
        newentry->server = xstrdupnull(xfer->toserver);
        newentry->partition = xstrdupnull(xfer->topart);
        newentry->mbtype = item->mbentry->mbtype|MBTYPE_MOVING;
        r = mboxlist_update(newentry, 1);
        mboxlist_entry_free(&newentry);

        if (r) {
            syslog(LOG_ERR,
                   "Could not move mailbox: %s, mboxlist_update() failed %s",
                   item->mbentry->name, error_message(r));
        }
        else item->state = XFER_LOCAL_MOVING;

        if (!r && xfer->seendb) {
            /* Backport the user's seendb on-the-fly */
            item->mailbox = mailbox;
            r = xfer_backport_seen_item(item, xfer->seendb);
            if (r) syslog(LOG_WARNING,
                          "Failed to backport seen state for mailbox '%s'",
                          item->mbentry->name);

            /* Need to close seendb before dumping Inbox (last item) */
            if (!item->next) seen_close(&xfer->seendb);
        }

        /* Step 4: Dump local -> remote */
        if (!r) {
            struct backend *be = xfer->sync_cs.backend;
            prot_printf(be->out, "D01 UNDUMP {" SIZE_T_FMT "+}\r\n%s ",
                        strlen(item->extname), item->extname);

            r = dump_mailbox(NULL, mailbox, 0, xfer->remoteversion,
                             be->in, be->out, imapd_authstate);
            if (r) {
                syslog(LOG_ERR,
                       "Could not move mailbox: %s, dump_mailbox() failed %s",
                       item->mbentry->name, error_message(r));
            }
        }

        mailbox_close(&mailbox);

        if (r) return r;

        struct backend *be = xfer->sync_cs.backend;
        r = getresult(be->in, "D01");
        if (r) {
            syslog(LOG_ERR, "Could not move mailbox: %s, UNDUMP failed %s",
                   item->mbentry->name, error_message(r));
            return r;
        }

        /* Step 5: Set ACL on remote */
        r = trashacl(be->in, be->out, item->extname);
        if (r) {
            syslog(LOG_ERR, "Could not clear remote acl on %s",
                   item->mbentry->name);
            return r;
        }

        r = dumpacl(be->in, be->out, item->extname, item->mbentry->acl);
        if (r) {
            syslog(LOG_ERR, "Could not set remote acl on %s",
                   item->mbentry->name);
            return r;
        }

        item->state = XFER_UNDUMPED;
    }

    return 0;
}

static int xfer_addusermbox(const mbentry_t *mbentry, void *rock)
{
    struct xfer_header *xfer = (struct xfer_header *)rock;

    /* Skip remote mailbox */
    if (mbentry->mbtype & MBTYPE_REMOTE)
        return 0;

    struct xfer_item *item = xzmalloc(sizeof(struct xfer_item));

    item->mbentry = mboxlist_entry_copy(mbentry);

    char *extname = mboxname_to_external(item->mbentry->name, &imapd_namespace, imapd_userid);
    xstrncpy(item->extname, extname, sizeof(item->extname));
    free(extname);
    item->mailbox = NULL;
    item->state = 0;

    /* and link on to the list (reverse order) */
    item->next = xfer->items;
    xfer->items = item;

    return 0;
}

static int xfer_initialsync(struct xfer_header *xfer)
{
    int r;

    if (xfer->userid) {
        struct xfer_item *item, *next;

        syslog(LOG_INFO, "XFER: initial sync of user %s", xfer->userid);

        r = sync_do_user(&xfer->sync_cs, xfer->userid, xfer->topart);
        if (r) return r;

        /* User moves may take a while, do another non-blocking sync */
        syslog(LOG_INFO, "XFER: second sync of user %s", xfer->userid);

        r = sync_do_user(&xfer->sync_cs, xfer->userid, xfer->topart);
        if (r) return r;

        /* User may have renamed/deleted a mailbox while syncing,
           recreate the submailboxes list */
        for (item = xfer->items; item; item = next) {
            next = item->next;
            mboxlist_entry_free(&item->mbentry);
            free(item);
        }
        xfer->items = NULL;

        r = mboxlist_usermboxtree(xfer->userid, NULL, xfer_addusermbox,
                                  xfer, MBOXTREE_DELETED);
    }
    else {
        struct sync_name_list *mboxname_list = sync_name_list_create();

        syslog(LOG_INFO, "XFER: initial sync of mailbox %s",
               xfer->items->mbentry->name);

        sync_name_list_add(mboxname_list, xfer->items->mbentry->name);
        r = sync_do_mailboxes(&xfer->sync_cs, mboxname_list, xfer->topart, xfer->sync_cs.flags);
        sync_name_list_free(&mboxname_list);
    }

    return r;
}

/*
 * This is similar to do_folders() from sync_support, but for a single mailbox.
 * It is needed for xfer_finalsync(), which needs to hold a single exclusive
 * lock on the mailbox for the duration of this operation.
 */
static int sync_mailbox(struct xfer_header *xfer,
                        struct mailbox *mailbox,
                        struct sync_folder_list *replica_folders,
                        const char *topart)
{
    int r = 0;
    struct sync_folder_list *master_folders = NULL;
    struct sync_reserve_list *reserve_guids = NULL;
    struct sync_msgid_list *part_list;
    struct sync_reserve *reserve;
    struct sync_folder *mfolder, *rfolder;
    struct sync_annot_list *annots = NULL;
    modseq_t xconvmodseq = 0;
    modseq_t raclmodseq = 0;

    if (!topart) topart = mailbox->part;
    reserve_guids = sync_reserve_list_create(SYNC_MSGID_LIST_HASH_SIZE);
    part_list = sync_reserve_partlist(reserve_guids, topart);

    /* always send mailbox annotations */
    r = read_annotations(mailbox, NULL, &annots, /*since_modseq*/0, /*flags*/0);
    if (r) {
        syslog(LOG_ERR, "sync_mailbox(): read annotations failed: %s '%s'",
               mailbox_name(mailbox), error_message(r));
        goto cleanup;
    }

    /* xconvmodseq */
    if (mailbox_has_conversations(mailbox)) {
        r = mailbox_get_xconvmodseq(mailbox, &xconvmodseq);
        if (r) {
            syslog(LOG_ERR, "sync_mailbox(): mailbox get xconvmodseq failed: %s '%s'",
                mailbox_name(mailbox), error_message(r));
            goto cleanup;
        }
    }
    /* raclmodseq */
    if (config_getswitch(IMAPOPT_REVERSEACLS)) {
        raclmodseq = mboxname_readraclmodseq(mailbox_name(mailbox));
    }

    master_folders = sync_folder_list_create();
    sync_folder_list_add(master_folders,
                         mailbox->uniqueid, mailbox_name(mailbox),
                         mailbox->mbtype,
                         mailbox->part,
                         mailbox->acl,
                         mailbox->i.options,
                         mailbox->i.uidvalidity,
                         mailbox->i.last_uid,
                         mailbox->i.highestmodseq,
                         mailbox->i.synccrcs,
                         mailbox->i.recentuid,
                         mailbox->i.recenttime,
                         mailbox->i.pop3_last_login,
                         mailbox->i.pop3_show_after,
                         annots,
                         xconvmodseq,
                         raclmodseq,
                         mailbox->foldermodseq,
                         /* ispartial */0);
    annots = NULL; /* list took ownership */

    mfolder = master_folders->head;
    /* when mfolder->mailbox is set, sync_update_mailbox will use it rather
     * than obtaining its own (short-lived) locks */
    mfolder->mailbox = mailbox;

    uint32_t fromuid = 0;
    rfolder = sync_folder_lookup(replica_folders, mfolder->uniqueid);
    if (rfolder) {
        rfolder->mark = 1;

        /* does it need a rename? */
        if (strcmp(mfolder->name, rfolder->name) ||
            strcmp(topart, rfolder->part)) {
            /* bail and retry */
            syslog(LOG_NOTICE,
                   "XFER: rename %s!%s -> %s!%s during final sync"
                   " - must try XFER again",
                   mfolder->name, mfolder->part, rfolder->name, rfolder->part);
            r = IMAP_AGAIN;
            goto cleanup;
        }
        fromuid = rfolder->last_uid;
    }
    sync_find_reserve_messages(mailbox, fromuid, mailbox->i.last_uid, part_list);

    reserve = reserve_guids->head;
    r = sync_reserve_partition(&xfer->sync_cs, reserve->part,
                               replica_folders, reserve->list);
    if (r) {
        syslog(LOG_ERR, "sync_mailbox(): reserve partition failed: %s '%s'",
               mfolder->name, error_message(r));
        goto cleanup;
    }

    r = sync_do_update_mailbox(&xfer->sync_cs, mfolder, rfolder, topart, reserve_guids);
    if (r) {
        syslog(LOG_ERR, "sync_mailbox(): update failed: %s '%s'",
                mfolder->name, error_message(r));
    }

  cleanup:
    sync_reserve_list_free(&reserve_guids);
    sync_folder_list_free(&master_folders);
    sync_annot_list_free(&annots);

    return r;
}

static int xfer_finalsync(struct xfer_header *xfer)
{
    struct sync_name_list *master_quotaroots = sync_name_list_create();
    struct sync_folder_list *replica_folders = sync_folder_list_create();
    struct sync_folder *rfolder;
    struct sync_name_list *replica_subs = NULL;
    struct sync_sieve_list *replica_sieve = NULL;
    struct sync_seen_list *replica_seen = NULL;
    struct sync_quota_list *replica_quota = sync_quota_list_create();
    const char *cmd;
    struct dlist *kl = NULL;
    struct xfer_item *item;
    struct mailbox *mailbox = NULL;
    int r;

    if (xfer->userid) {
        syslog(LOG_INFO, "XFER: final sync of user %s", xfer->userid);

        replica_subs = sync_name_list_create();
        replica_sieve = sync_sieve_list_create();
        replica_seen = sync_seen_list_create();

        cmd = "USER";
        kl = dlist_setatom(NULL, cmd, xfer->userid);
    }
    else {
        syslog(LOG_INFO, "XFER: final sync of mailbox %s",
               xfer->items->mbentry->name);

        cmd = "MAILBOXES";
        kl = dlist_newlist(NULL, cmd);
        dlist_setatom(kl, "MBOXNAME", xfer->items->mbentry->name);
    }

    sync_send_lookup(kl, xfer->sync_cs.backend->out);
    dlist_free(&kl);

    r = sync_response_parse(&xfer->sync_cs, cmd, replica_folders, replica_subs,
                            replica_sieve, replica_seen, replica_quota);

    if (r) goto done;

    for (item = xfer->items; item; item = item->next) {
        r = mailbox_open_iwl(item->mbentry->name, &mailbox);
        if (!r) r = sync_mailbox_version_check(&mailbox);
        if (r) {
            syslog(LOG_ERR,
                   "Failed to open mailbox %s for xfer_final_sync() %s",
                   item->mbentry->name, error_message(r));
            goto done;
        }

        /* Open cyrus.annotations before we set mailbox to MOVING and
           change its location to destination server and partition */
        r = mailbox_get_annotate_state(mailbox, ANNOTATE_ANY_UID, NULL);
        if (r) {
            syslog(LOG_ERR,
                   "Failed to get annotate state for mailbox %s"
                   " for xfer_final_sync() %s",
                   mailbox_name(mailbox), error_message(r));
            mailbox_close(&mailbox);
            goto done;
        }

        /* Step 3.5: Set mailbox as MOVING on local server */
        /* XXX - this code is awful... need a sane way to manage mbentries */
        mbentry_t *newmbentry = mboxlist_entry_create();
        newmbentry->name = xstrdupnull(item->mbentry->name);
        newmbentry->acl = xstrdupnull(item->mbentry->acl);
        newmbentry->uniqueid = xstrdupnull(item->mbentry->uniqueid);
        newmbentry->uidvalidity = item->mbentry->uidvalidity;
        newmbentry->mbtype = item->mbentry->mbtype|MBTYPE_MOVING;
        newmbentry->server = xstrdupnull(xfer->toserver);
        newmbentry->partition = xstrdupnull(xfer->topart);
        r = mboxlist_update(newmbentry, 1);
        mboxlist_entry_free(&newmbentry);

        if (r) {
            syslog(LOG_ERR,
                   "Could not move mailbox: %s, mboxlist_update() failed %s",
                   item->mbentry->name, error_message(r));
        }
        else item->state = XFER_LOCAL_MOVING;

        /* Step 4: Sync local -> remote */
        if (!r) {
            r = sync_mailbox(xfer, mailbox, replica_folders, xfer->topart);
            if (r) {
                syslog(LOG_ERR,
                       "Could not move mailbox: %s, sync_mailbox() failed %s",
                       item->mbentry->name, error_message(r));
            }
            else {
                if (mailbox->quotaroot)
                    sync_name_list_add(master_quotaroots, mailbox->quotaroot);

                r = sync_do_annotation(&xfer->sync_cs, mailbox_name(mailbox));
                if (r) {
                    syslog(LOG_ERR, "Could not move mailbox: %s,"
                           " sync_do_annotation() failed %s",
                           item->mbentry->name, error_message(r));
                }
            }
        }

        mailbox_close(&mailbox);

        if (r) goto done;

        item->state = XFER_UNDUMPED;
    }

    /* Delete folders on replica which no longer exist on master */
    for (rfolder = replica_folders->head; rfolder; rfolder = rfolder->next) {
        if (rfolder->mark) continue;

        r = sync_do_folder_delete(&xfer->sync_cs, rfolder->name);
        if (r) {
            syslog(LOG_ERR, "sync_folder_delete(): failed: %s '%s'",
                   rfolder->name, error_message(r));
            goto done;
        }
    }

    /* Handle any mailbox/user metadata */
    r = sync_do_user_quota(&xfer->sync_cs, master_quotaroots, replica_quota);
    if (!r && xfer->userid) {
        r = sync_do_user_seen(&xfer->sync_cs, xfer->userid, replica_seen);
        if (!r) r = sync_do_user_sub(&xfer->sync_cs, xfer->userid, replica_subs);
        if (!r) r = sync_do_user_sieve(&xfer->sync_cs, xfer->userid, replica_sieve);
    }

  done:
    sync_name_list_free(&master_quotaroots);
    sync_folder_list_free(&replica_folders);
    if (replica_subs) sync_name_list_free(&replica_subs);
    if (replica_sieve) sync_sieve_list_free(&replica_sieve);
    if (replica_seen) sync_seen_list_free(&replica_seen);
    if (replica_quota) sync_quota_list_free(&replica_quota);

    return r;
}

static int xfer_reactivate(struct xfer_header *xfer)
{
    struct xfer_item *item;
    int r;

    syslog(LOG_INFO, "XFER: reactivating mailboxes");

    if (!mupdate_h) return 0;

    /* 6.5) Kick remote server to correct mupdate entry */
    for (item = xfer->items; item; item = item->next) {
        struct backend *be = xfer->sync_cs.backend;
        prot_printf(be->out, "MP1 MUPDATEPUSH {" SIZE_T_FMT "+}\r\n%s\r\n",
                    strlen(item->extname), item->extname);
        r = getresult(be->in, "MP1");
        if (r) {
            syslog(LOG_ERR, "MUPDATE: can't activate mailbox entry '%s': %s",
                   item->mbentry->name, error_message(r));
        }
    }

    return 0;
}

static int xfer_delete(struct xfer_header *xfer)
{
    mbentry_t *newentry = NULL;
    struct xfer_item *item;
    int r;

    syslog(LOG_INFO, "XFER: deleting mailboxes on source");

    /* 7) local delete of mailbox
     * & remove local "remote" mailboxlist entry */
    for (item = xfer->items; item; item = item->next) {
        /* Set mailbox as DELETED on local server
           (need to also reset to local partition,
           otherwise mailbox can not be opened for deletion) */
        /* XXX - this code is awful... need a sane way to manage mbentries */
        newentry = mboxlist_entry_create();
        newentry->name = xstrdupnull(item->mbentry->name);
        newentry->uniqueid = xstrdupnull(item->mbentry->uniqueid);
        newentry->acl = xstrdupnull(item->mbentry->acl);
        newentry->server = xstrdupnull(item->mbentry->server);
        newentry->partition = xstrdupnull(item->mbentry->partition);
        newentry->mbtype |= MBTYPE_DELETED;
        r = mboxlist_update(newentry, 1);
        mboxlist_entry_free(&newentry);

        if (r) {
            syslog(LOG_ERR,
                   "Could not move mailbox: %s, mboxlist_update failed (%s)",
                   item->mbentry->name, error_message(r));
        }

        /* Note that we do not check the ACL, and we don't update MUPDATE */
        /* note also that we need to remember to let proxyadmins do this */
        /* On a unified system, the subsequent MUPDATE PUSH on the remote
           should repopulate the local mboxlist entry */
        r = mboxlist_deletemailboxlock(item->mbentry->name,
                                   imapd_userisadmin || imapd_userisproxyadmin,
                                   imapd_userid, imapd_authstate, NULL,
                                   MBOXLIST_DELETE_LOCALONLY);
        if (r) {
            syslog(LOG_ERR,
                   "Could not delete local mailbox during move of %s",
                   item->mbentry->name);
            /* can't abort now! */
        }
    }

    return 0;
}

static void xfer_recover(struct xfer_header *xfer)
{
    struct xfer_item *item;
    int r;

    syslog(LOG_INFO, "XFER: recovering");

    /* Backout any changes - we stop on first untouched mailbox */
    for (item = xfer->items; item && item->state; item = item->next) {
        switch (item->state) {
        case XFER_UNDUMPED:
        case XFER_LOCAL_MOVING:
            /* Unset mailbox as MOVING on local server */
            r = mboxlist_update(item->mbentry, 1);

            if (r) {
                syslog(LOG_ERR,
                       "Could not back out MOVING flag during move of %s (%s)",
                       item->mbentry->name, error_message(r));
            }
            GCC_FALLTHROUGH

        case XFER_REMOTE_CREATED:
            if (!xfer->use_replication) {
                /* Delete remote mailbox */
                prot_printf(xfer->sync_cs.backend->out,
                            "LD1 LOCALDELETE {" SIZE_T_FMT "+}\r\n%s\r\n",
                            strlen(item->extname), item->extname);
                r = getresult(xfer->sync_cs.backend->in, "LD1");
                if (r) {
                    syslog(LOG_ERR,
                        "Could not back out remote mailbox during move of %s (%s)",
                        item->mbentry->name, error_message(r));
                }
            }
            GCC_FALLTHROUGH

        case XFER_DEACTIVATED:
            /* Tell murder it's back here and active */
            r = xfer_mupdate(1, item->mbentry->name, item->mbentry->partition,
                             config_servername, item->mbentry->acl);
            if (r) {
                syslog(LOG_ERR,
                       "Could not back out mupdate during move of %s (%s)",
                       item->mbentry->name, error_message(r));
            }
        }
    }
}

static int do_xfer(struct xfer_header *xfer)
{
    int r = 0;

    if (xfer->use_replication) {
        /* Initial non-blocking sync */
        r = xfer_initialsync(xfer);
        if (r) return r;
    }

    r = xfer_deactivate(xfer);

    if (!r) {
        if (xfer->use_replication) {
            /* Final sync with write locks on mailboxes */
            r = xfer_finalsync(xfer);
        }
        else {
            r = xfer_localcreate(xfer);
            if (!r) r = xfer_undump(xfer);
        }
    }

    if (r) {
        /* Something failed, revert back to local server */
        xfer_recover(xfer);
        return r;
    }

    /* Successful dump of all mailboxes to remote server.
     * Remove them locally and activate them on remote.
     * Note - we don't report errors if this fails! */
    xfer_delete(xfer);
    xfer_reactivate(xfer);

    return 0;
}

static int xfer_setquotaroot(struct xfer_header *xfer, const char *mboxname)
{
    struct quota q;
    int r;

    syslog(LOG_INFO, "XFER: setting quota root %s", mboxname);

    quota_init(&q, mboxname);
    r = quota_read(&q, NULL, 0);
    if (r == IMAP_QUOTAROOT_NONEXISTENT) return 0;
    if (r) return r;

    /* note use of + to force the setting of a nonexistent
     * quotaroot */
    char *extname = mboxname_to_external(mboxname, &imapd_namespace, imapd_userid);
    prot_printf(xfer->sync_cs.backend->out, "Q01 SETQUOTA {" SIZE_T_FMT "+}\r\n+%s ",
                strlen(extname)+1, extname);
    free(extname);
    print_quota_limits(xfer->sync_cs.backend->out, &q);
    prot_printf(xfer->sync_cs.backend->out, "\r\n");
    quota_free(&q);

    r = getresult(xfer->sync_cs.backend->in, "Q01");
    if (r) syslog(LOG_ERR,
                  "Could not move mailbox: %s, " \
                  "failed setting initial quota root",
                  mboxname);
    return r;
}

struct xfer_list {
    const struct namespace *ns;
    const char *userid;
    const char *part;
    short allow_usersubs;
    struct xfer_item *mboxes;
};

static int xfer_addmbox(struct findall_data *data, void *rock)
{
    if (!data) return 0;
    if (!data->is_exactmatch) return 0;
    struct xfer_list *list = (struct xfer_list *) rock;

    if (list->part && strcmp(data->mbentry->partition, list->part)) {
        /* Not on specified partition */
        return 0;
    }

    /* Only add shared mailboxes, targeted user submailboxes, or user INBOXes */
    if (!mbname_localpart(data->mbname) || list->allow_usersubs ||
        (!mbname_isdeleted(data->mbname) && !strarray_size(mbname_boxes(data->mbname)))) {
        const char *extname = mbname_extname(data->mbname, list->ns, list->userid);
        struct xfer_item *mbox = xzmalloc(sizeof(struct xfer_item));

        mbox->mbentry = mboxlist_entry_copy(data->mbentry);
        xstrncpy(mbox->extname, extname, sizeof(mbox->extname));
        if (mbname_localpart(data->mbname) && !list->allow_usersubs) {
            /* User INBOX */
            mbox->state = XFER_MOVING_USER;
        }

        /* Add link on to the list (reverse order) */
        mbox->next = list->mboxes;
        list->mboxes = mbox;
    }

    return 0;
}

static void cmd_xfer(const char *tag, const char *name,
                     const char *toserver, const char *topart)
{
    int r = 0, partial_success = 0, mbox_count = 0;
    struct xfer_header *xfer = NULL;
    struct xfer_list list = { &imapd_namespace, imapd_userid, NULL, 0, NULL };
    struct xfer_item *item, *next;
    mbname_t *mbname = mbname_from_extname(name, &imapd_namespace, imapd_userid);

    /* administrators only please */
    /* however, proxys can do this, if their authzid is an admin */
    if (!imapd_userisadmin && !imapd_userisproxyadmin) {
        r = IMAP_PERMISSION_DENIED;
        goto done;
    }

    if (!strcmp(toserver, config_servername)) {
        r = IMAP_BAD_SERVER;
        goto done;
    }

    /* Build list of users/mailboxes to transfer */
    if (config_partitiondir(name)) {
        /* entire partition */
        list.part = name;
        mboxlist_findall(NULL, "*", 1, NULL, NULL, xfer_addmbox, &list);
    } else {
        /* mailbox pattern */
        if (mbname_localpart(mbname) &&
            (mbname_isdeleted(mbname) || strarray_size(mbname_boxes(mbname)))) {
            /* targeted a user submailbox */
            list.allow_usersubs = 1;
        }

        mboxlist_findall(NULL, mbname_intname(mbname), 1, NULL, NULL, xfer_addmbox, &list);
    }

    r = xfer_init(toserver, &xfer);
    if (r) goto done;

    for (item = list.mboxes; item; item = next) {
        mbentry_t *mbentry = item->mbentry;

        /* NOTE: Since XFER can only be used by an admin, and we always connect
         * to the destination backend as an admin, we take advantage of the fact
         * that admins *always* use a consistent mailbox naming scheme.
         * So, 'name' should be used in any command we send to a backend, and
         * 'mbentry->name' is the internal name to be used for mupdate and findall.
         */

        r = 0;
        xfer->topart = xstrdup(topart ? topart : mbentry->partition);

        /* if we are not moving a user, just move the one mailbox */
        if (item->state != XFER_MOVING_USER) {

            syslog(LOG_INFO, "XFER: mailbox '%s' -> %s!%s",
                   mbentry->name, xfer->toserver, xfer->topart);

            /* is the selected mailbox the one we're moving? */
            if (!strcmpsafe(mbentry->name, index_mboxname(imapd_index))) {
                r = IMAP_MAILBOX_LOCKED;
                goto next;
            }

            /* we're moving this mailbox */
            xfer_addusermbox(mbentry, xfer);
            mbox_count++;

            r = do_xfer(xfer);
        } else {
            xfer->userid = xstrdupnull(mbname_userid(mbname));

            syslog(LOG_INFO, "XFER: user '%s' -> %s!%s",
                   xfer->userid, xfer->toserver, xfer->topart);

            if (!config_getswitch(IMAPOPT_ALLOWUSERMOVES)) {
                /* not configured to allow user moves */
                r = IMAP_MAILBOX_NOTSUPPORTED;
            } else if (!strcmp(xfer->userid, imapd_userid)) {
                /* don't move your own inbox, that could be troublesome */
                r = IMAP_MAILBOX_NOTSUPPORTED;
            } else if (!strncmpsafe(mbentry->name, index_mboxname(imapd_index),
                             strlen(mbentry->name))) {
                /* selected mailbox is in the namespace we're moving */
                r = IMAP_MAILBOX_LOCKED;
            }
            if (r) goto next;

            struct mboxlock *namespacelock = user_namespacelock(xfer->userid);

            if (!xfer->use_replication) {
                /* set the quotaroot if needed */
                r = xfer_setquotaroot(xfer, mbentry->name);
                if (r) goto next;

                /* backport the seen file if needed */
                if (xfer->remoteversion < 12) {
                    r = seen_open(xfer->userid, SEEN_CREATE, &xfer->seendb);
                    if (r) goto next;
                }
            }

            r = mboxlist_usermboxtree(xfer->userid, NULL, xfer_addusermbox,
                                      xfer, MBOXTREE_DELETED);

            /* NOTE: mailboxes were added in reverse, so the inbox is
             * done last */
            r = do_xfer(xfer);

            if (!r) {
                /* this was a successful user move, and we need to delete
                   certain user meta-data (but not seen state!) */
                syslog(LOG_INFO, "XFER: deleting user metadata");
                user_deletedata(xfer->userid, 0);
            }
            mboxname_release(&namespacelock);
        }

      next:
        if (r) {
            if (xfer->userid)
                prot_printf(imapd_out, "* NO USER %s (%s)\r\n",
                            xfer->userid, error_message(r));
            else
                prot_printf(imapd_out, "* NO MAILBOX \"%s\" (%s)\r\n",
                            item->extname, error_message(r));
        } else {
            partial_success = 1;

            if (xfer->userid)
                prot_printf(imapd_out, "* OK USER %s\r\n", xfer->userid);
            else
                prot_printf(imapd_out, "* OK MAILBOX \"%s\"\r\n", item->extname);
        }
        prot_flush(imapd_out);

        mboxlist_entry_free(&mbentry);
        next = item->next;
        free(item);

        if (xfer->userid || mbox_count > 1000) {
            /* RESTART after each user or after every 1000 mailboxes */
            mbox_count = 0;

            r = sync_do_restart(&xfer->sync_cs);
            if (r) goto done;
        }

        xfer_cleanup(xfer);

        if (partial_success) r = 0;
    }

done:
    mbname_free(&mbname);
    if (xfer) xfer_done(&xfer);

    imapd_check(NULL, 0);

    if (r) {
        prot_printf(imapd_out, "%s NO %s\r\n", tag,
                    error_message(r));
    } else {
        prot_printf(imapd_out, "%s OK %s\r\n", tag,
                    error_message(IMAP_OK_COMPLETED));
    }

    return;
}

#define SORTGROWSIZE    10

/*
 * Parse sort criteria
 */
static int getsortcriteria(char *tag, struct sortcrit **sortcrit)
{
    int c;
    static struct buf criteria;
    int nsort, n;
    int hasconv = config_getswitch(IMAPOPT_CONVERSATIONS);

    *sortcrit = NULL;

    c = prot_getc(imapd_in);
    if (c != '(') goto missingcrit;

    c = getword(imapd_in, &criteria);
    if (criteria.s[0] == '\0') goto missingcrit;

    nsort = 0;
    n = 0;
    for (;;) {
        if (n >= nsort - 1) {   /* leave room for implicit criterion */
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
        else if (!strcmp(criteria.s, "displayfrom"))
            (*sortcrit)[n].key = SORT_DISPLAYFROM;
        else if (!strcmp(criteria.s, "displayto"))
            (*sortcrit)[n].key = SORT_DISPLAYTO;
        else if (!strcmp(criteria.s, "from"))
            (*sortcrit)[n].key = SORT_FROM;
        else if (!strcmp(criteria.s, "size"))
            (*sortcrit)[n].key = SORT_SIZE;
        else if (!strcmp(criteria.s, "subject"))
            (*sortcrit)[n].key = SORT_SUBJECT;
        else if (!strcmp(criteria.s, "to"))
            (*sortcrit)[n].key = SORT_TO;
        else if (!strcmp(criteria.s, "annotation")) {
            const char *userid = NULL;

            (*sortcrit)[n].key = SORT_ANNOTATION;
            if (c != ' ') goto missingarg;
            c = getastring(imapd_in, imapd_out, &criteria);
            if (c != ' ') goto missingarg;
            (*sortcrit)[n].args.annot.entry = xstrdup(criteria.s);
            c = getastring(imapd_in, imapd_out, &criteria);
            if (c == EOF) goto missingarg;
            if (!strcmp(criteria.s, "value.shared"))
                userid = "";
            else if (!strcmp(criteria.s, "value.priv"))
                userid = imapd_userid;
            else
                goto missingarg;
            (*sortcrit)[n].args.annot.userid = xstrdup(userid);
        }
        else if (!strcmp(criteria.s, "modseq"))
            (*sortcrit)[n].key = SORT_MODSEQ;
        else if (!strcmp(criteria.s, "uid"))
            (*sortcrit)[n].key = SORT_UID;
        else if (!strcmp(criteria.s, "hasflag")) {
            (*sortcrit)[n].key = SORT_HASFLAG;
            if (c != ' ') goto missingarg;
            c = getastring(imapd_in, imapd_out, &criteria);
            if (c == EOF) goto missingarg;
            (*sortcrit)[n].args.flag.name = xstrdup(criteria.s);
        }
        else if (hasconv && !strcmp(criteria.s, "convmodseq"))
            (*sortcrit)[n].key = SORT_CONVMODSEQ;
        else if (hasconv && !strcmp(criteria.s, "convexists"))
            (*sortcrit)[n].key = SORT_CONVEXISTS;
        else if (hasconv && !strcmp(criteria.s, "convsize"))
            (*sortcrit)[n].key = SORT_CONVSIZE;
        else if (hasconv && !strcmp(criteria.s, "hasconvflag")) {
            (*sortcrit)[n].key = SORT_HASCONVFLAG;
            if (c != ' ') goto missingarg;
            c = getastring(imapd_in, imapd_out, &criteria);
            if (c == EOF) goto missingarg;
            (*sortcrit)[n].args.flag.name = xstrdup(criteria.s);
        }
        else if (!strcmp(criteria.s, "folder"))
            (*sortcrit)[n].key = SORT_FOLDER;
        else if (!strcmp(criteria.s, "relevancy"))
            (*sortcrit)[n].key = SORT_RELEVANCY;
        else if (!strcmp(criteria.s, "spamscore"))
            (*sortcrit)[n].key = SORT_SPAMSCORE;
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
 missingarg:
    prot_printf(imapd_out, "%s BAD Missing argument to Sort criterion %s\r\n",
                tag, criteria.s);
    if (c != EOF) prot_ungetc(c, imapd_in);
    return EOF;
}

static int parse_windowargs(const char *tag,
                            struct windowargs **wa,
                            int updates)
{
    struct windowargs windowargs;
    struct buf arg = BUF_INITIALIZER;
    struct buf ext_folder = BUF_INITIALIZER;
    int c;

    memset(&windowargs, 0, sizeof(windowargs));

    c = prot_getc(imapd_in);
    if (c == EOF)
        goto out;
    if (c != '(') {
        /* no window args at all */
        prot_ungetc(c, imapd_in);
        goto out;
    }

    for (;;)
    {
        c = prot_getc(imapd_in);
        if (c == EOF)
            goto out;
        if (c == ')')
            break;  /* end of window args */

        prot_ungetc(c, imapd_in);
        c = getword(imapd_in, &arg);
        if (!arg.len)
            goto syntax_error;

        if (!strcasecmp(arg.s, "CONVERSATIONS"))
            windowargs.conversations = 1;
        else if (!strcasecmp(arg.s, "POSITION")) {
            if (updates)
                goto syntax_error;
            if (c != ' ')
                goto syntax_error;
            c = prot_getc(imapd_in);
            if (c != '(')
                goto syntax_error;
            c = getuint32(imapd_in, &windowargs.position);
            if (c != ' ')
                goto syntax_error;
            c = getuint32(imapd_in, &windowargs.limit);
            if (c != ')')
                goto syntax_error;
            c = prot_getc(imapd_in);
            if (windowargs.position == 0)
                goto syntax_error;
        }
        else if (!strcasecmp(arg.s, "ANCHOR")) {
            if (updates)
                goto syntax_error;
            if (c != ' ')
                goto syntax_error;
            c = prot_getc(imapd_in);
            if (c != '(')
                goto syntax_error;
            c = getuint32(imapd_in, &windowargs.anchor);
            if (c != ' ')
                goto syntax_error;
            c = getuint32(imapd_in, &windowargs.offset);
            if (c != ' ')
                goto syntax_error;
            c = getuint32(imapd_in, &windowargs.limit);
            if (c != ')')
                goto syntax_error;
            c = prot_getc(imapd_in);
            if (windowargs.anchor == 0)
                goto syntax_error;
        }
        else if (!strcasecmp(arg.s, "MULTIANCHOR")) {
            if (updates)
                goto syntax_error;
            if (c != ' ')
                goto syntax_error;
            c = prot_getc(imapd_in);
            if (c != '(')
                goto syntax_error;
            c = getuint32(imapd_in, &windowargs.anchor);
            if (c != ' ')
                goto syntax_error;
            c = getastring(imapd_in, imapd_out, &ext_folder);
            if (c != ' ')
                goto syntax_error;
            c = getuint32(imapd_in, &windowargs.offset);
            if (c != ' ')
                goto syntax_error;
            c = getuint32(imapd_in, &windowargs.limit);
            if (c != ')')
                goto syntax_error;
            c = prot_getc(imapd_in);
            if (windowargs.anchor == 0)
                goto syntax_error;
        }
        else if (!strcasecmp(arg.s, "CHANGEDSINCE")) {
            if (!updates)
                goto syntax_error;
            windowargs.changedsince = 1;
            if (c != ' ')
                goto syntax_error;
            c = prot_getc(imapd_in);
            if (c != '(')
                goto syntax_error;
            c = getmodseq(imapd_in, &windowargs.modseq);
            if (c != ' ')
                goto syntax_error;
            c = getuint32(imapd_in, &windowargs.uidnext);
            if (c != ')')
                goto syntax_error;
            c = prot_getc(imapd_in);
        } else if (!strcasecmp(arg.s, "UPTO")) {
            if (!updates)
                goto syntax_error;
            if (c != ' ')
                goto syntax_error;
            c = prot_getc(imapd_in);
            if (c != '(')
                goto syntax_error;
            c = getuint32(imapd_in, &windowargs.upto);
            if (c != ')')
                goto syntax_error;
            c = prot_getc(imapd_in);

            if (windowargs.upto == 0)
                goto syntax_error;
        }
        else
            goto syntax_error;

        if (c == ')')
            break;
        if (c != ' ')
            goto syntax_error;
    }

    c = prot_getc(imapd_in);
    if (c != ' ')
        goto syntax_error;

out:
    /* these two are mutually exclusive */
    if (windowargs.anchor && windowargs.position)
        goto syntax_error;
    /* changedsince is mandatory for XCONVUPDATES
     * and illegal for XCONVSORT */
    if (!!updates != windowargs.changedsince)
        goto syntax_error;

    if (ext_folder.len) {
        windowargs.anchorfolder = mboxname_from_external(buf_cstring(&ext_folder),
                                                         &imapd_namespace,
                                                         imapd_userid);
    }

    *wa = xmemdup(&windowargs, sizeof(windowargs));
    buf_free(&ext_folder);
    buf_free(&arg);
    return c;

syntax_error:
    free(windowargs.anchorfolder);
    buf_free(&ext_folder);
    prot_printf(imapd_out, "%s BAD Syntax error in window arguments\r\n", tag);
    if (c != EOF) prot_ungetc(c, imapd_in);
    return EOF;
}

static void free_windowargs(struct windowargs *wa)
{
    if (!wa)
        return;
    free(wa->anchorfolder);
    free(wa);
}

/*
 * Parse LIST selection options.
 * The command has been parsed up to and including the opening '('.
 */
static int getlistselopts(char *tag, struct listargs *args)
{
    int c;
    static struct buf buf;
    int allowdeleted = config_getswitch(IMAPOPT_ALLOWDELETED);

    if ( (c = prot_getc(imapd_in)) == ')')
        return prot_getc(imapd_in);
    else
        prot_ungetc(c, imapd_in);

    for (;;) {
        c = getword(imapd_in, &buf);

        if (!*buf.s) {
            prot_printf(imapd_out,
                        "%s BAD Invalid syntax in List command\r\n",
                        tag);
            goto bad;
        }

        lcase(buf.s);

        if (!strcmp(buf.s, "subscribed")) {
            args->sel |= LIST_SEL_SUBSCRIBED;
            args->ret |= LIST_RET_SUBSCRIBED;
        } else if (!strcmp(buf.s, "vendor.cmu-dav")) {
            args->sel |= LIST_SEL_DAV;
        } else if (!strcmp(buf.s, "vendor.cmu-include-deleted") && allowdeleted) {
            args->sel |= LIST_SEL_DELETED;
        } else if (!strcmp(buf.s, "vendor.fm-include-nonexistent")) {
            args->sel |= LIST_SEL_INTERMEDIATES;
        } else if (!strcmp(buf.s, "remote")) {
            args->sel |= LIST_SEL_REMOTE;
        } else if (!strcmp(buf.s, "recursivematch")) {
            args->sel |= LIST_SEL_RECURSIVEMATCH;
        } else if (!strcmp(buf.s, "special-use")) {
            args->sel |= LIST_SEL_SPECIALUSE;
            args->ret |= LIST_RET_SPECIALUSE;
        } else if (!strcmp(buf.s, "metadata")) {
            struct getmetadata_options opts = OPTS_INITIALIZER;
            args->sel |= LIST_SEL_METADATA;
            args->ret |= LIST_RET_METADATA;

            strarray_t options = STRARRAY_INITIALIZER;
            c = parse_metadata_string_or_list(tag, &options, NULL);
            parse_getmetadata_options(&options, &opts);
            args->metaopts = opts;
            strarray_fini(&options);
            if (c == EOF) return EOF;
        } else {
            prot_printf(imapd_out,
                        "%s BAD Invalid List selection option \"%s\"\r\n",
                        tag, buf.s);
            goto bad;
        }

        if (c != ' ') break;
    }

    if (c != ')') {
        prot_printf(imapd_out,
                    "%s BAD Missing close parenthesis for List selection options\r\n", tag);
        goto bad;
    }

    if (args->sel & list_select_mod_opts
            && ! (args->sel & list_select_base_opts)) {
        prot_printf(imapd_out,
                    "%s BAD Invalid combination of selection options\r\n",
                    tag);
        goto bad;
    }

    return prot_getc(imapd_in);

bad:
    if (c != EOF) prot_ungetc(c, imapd_in);
    return EOF;
}

/*
 * Parse LIST return options.
 * The command has been parsed up to and including the ' ' before RETURN.
 */
static int getlistretopts(char *tag, struct listargs *args)
{
    static struct buf buf;
    int c;

    c = getword(imapd_in, &buf);
    if (!*buf.s) {
        prot_printf(imapd_out,
                    "%s BAD Invalid syntax in List command\r\n", tag);
        goto bad;
    }
    lcase(buf.s);
    if (strcasecmp(buf.s, "return")) {
        prot_printf(imapd_out,
                    "%s BAD Unexpected extra argument to List: \"%s\"\r\n",
                    tag, buf.s);
        goto bad;
    }

    if (c != ' ' || (c = prot_getc(imapd_in)) != '(') {
        prot_printf(imapd_out,
                    "%s BAD Missing return argument list\r\n", tag);
        goto bad;
    }

    if ( (c = prot_getc(imapd_in)) == ')')
        return prot_getc(imapd_in);
    else
        prot_ungetc(c, imapd_in);

    for (;;) {
        c = getword(imapd_in, &buf);

        if (!*buf.s) {
            prot_printf(imapd_out,
                        "%s BAD Invalid syntax in List command\r\n", tag);
            goto bad;
        }

        lcase(buf.s);

        if (!strcmp(buf.s, "subscribed"))
            args->ret |= LIST_RET_SUBSCRIBED;
        else if (!strcmp(buf.s, "children"))
            args->ret |= LIST_RET_CHILDREN;
        else if (!strcmp(buf.s, "myrights"))
            args->ret |= LIST_RET_MYRIGHTS;
        else if (!strcmp(buf.s, "special-use"))
            args->ret |= LIST_RET_SPECIALUSE;
        else if (!strcmp(buf.s, "status")) {
            const char *errstr = "Bad status string";
            args->ret |= LIST_RET_STATUS;
            c = parse_statusitems(&args->statusitems, &errstr);
            if (c == EOF) {
                prot_printf(imapd_out, "%s BAD %s\r\n", tag, errstr);
                return EOF;
            }
        }
        else if (!strcmp(buf.s, "metadata")) {
            args->ret |= LIST_RET_METADATA;
            /* outputs the error for us */
            c = parse_metadata_string_or_list(tag, &args->metaitems, NULL);
            if (c == EOF) return EOF;
        }
        else {
            prot_printf(imapd_out,
                        "%s BAD Invalid List return option \"%s\"\r\n",
                        tag, buf.s);
            goto bad;
        }

        if (c != ' ') break;
    }

    if (c != ')') {
        prot_printf(imapd_out,
                    "%s BAD Missing close parenthesis for List return options\r\n", tag);
        goto bad;
    }

    return prot_getc(imapd_in);

bad:
    if (c != EOF) prot_ungetc(c, imapd_in);
    return EOF;
}

/*
 * Parse a string in IMAP date-time format (and some more
 * obscure legacy formats too) to a time_t.  Parses both
 * date and time parts.  See cyrus_parsetime() for formats.
 *
 * Returns: the next character read from imapd_in, or
 *          or EOF on error.
 */
static int getdatetime(time_t *date)
{
    int c;
    int r;
    int i = 0;
    char buf[RFC3501_DATETIME_MAX+1];

    c = prot_getc(imapd_in);
    if (c != '\"')
        goto baddate;
    while ((c = prot_getc(imapd_in)) != '\"') {
        if (i >= RFC3501_DATETIME_MAX)
            goto baddate;
        buf[i++] = c;
    }
    buf[i] = '\0';

    r = time_from_rfc5322(buf, date, DATETIME_FULL);
    if (r < 0)
        goto baddate;

    c = prot_getc(imapd_in);
    return c;

 baddate:
    if (c != EOF) prot_ungetc(c, imapd_in);
    return EOF;
}

/*
 * Append 'section', 'fields', 'trail' to the fieldlist 'l'.
 */
static void appendfieldlist(struct fieldlist **l, char *section,
                     strarray_t *fields, char *trail,
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
static void freefieldlist(struct fieldlist *l)
{
    struct fieldlist *n;

    while (l) {
        n = l->next;
        free(l->section);
        strarray_free(l->fields);
        free(l->trail);
        if (l->rock) free(l->rock);
        free((char *)l);
        l = n;
    }
}

static int set_haschildren(const mbentry_t *mbentry __attribute__((unused)),
                           void *rock)
{
    uint32_t *attributes = (uint32_t *)rock;
    list_callback_calls++;
    *attributes |= MBOX_ATTRIBUTE_HASCHILDREN;
    return CYRUSDB_DONE;
}

static void specialuse_flags(const mbentry_t *mbentry, struct buf *attrib,
                             int isxlist)
{
    if (!mbentry) return;

    char *inbox = mboxname_user_mbox(imapd_userid, NULL);
    int inboxlen = strlen(inbox);

    /* doesn't match inbox, not xlistable */
    if (strncmp(mbentry->name, inbox, inboxlen)) {
        free(inbox);
        return;
    }

    /* inbox - only print if command is XLIST */
    if (mbentry->name[inboxlen] == '\0') {
        if (isxlist) buf_init_ro_cstr(attrib, "\\Inbox");
    }
    /* subdir */
    else if (mbentry->name[inboxlen] == '.') {
        /* check if there's a special use flag set */
        annotatemore_lookup(mbentry->name, "/specialuse", imapd_userid, attrib);
    }
    free(inbox);
    /* otherwise it's actually another user who matches for
     * the substr.  Ok to just print nothing */
}

static void printmetadata(const mbentry_t *mbentry,
                          const strarray_t *entries,
                          struct getmetadata_options *opts)
{
    annotate_state_t *astate = annotate_state_new();
    strarray_t newa = STRARRAY_INITIALIZER;
    strarray_t newe = STRARRAY_INITIALIZER;
    annotate_state_set_auth(astate,
                            imapd_userisadmin || imapd_userisproxyadmin,
                            imapd_userid, imapd_authstate);
    int r = annotate_state_set_mailbox_mbe(astate, mbentry);
    if (r) goto done;
    r = _metadata_to_annotate(entries, &newa, &newe, NULL, opts->depth);
    if (r) goto done;

    annotate_state_fetch(astate, &newe, &newa, getmetadata_response, opts);
    getmetadata_response(NULL, 0, NULL, NULL, opts);

done:
    annotate_state_abort(&astate);
}

/* Print LIST or LSUB untagged response */
static void list_response(const char *extname, const mbentry_t *mbentry,
                          uint32_t attributes, struct listargs *listargs)
{
    int r;
    struct statusdata sdata = STATUSDATA_INIT;
    struct buf specialuse = BUF_INITIALIZER;

    /* Intermediates don't actually exist */
    if (mbentry && (mbentry->mbtype & MBTYPE_INTERMEDIATE)) {
        attributes |= MBOX_ATTRIBUTE_NONEXISTENT;
    }

    if ((attributes & MBOX_ATTRIBUTE_NONEXISTENT)) {
        if (!(listargs->cmd == LIST_CMD_EXTENDED)) {
            attributes |= MBOX_ATTRIBUTE_NOSELECT;
            attributes &= ~MBOX_ATTRIBUTE_NONEXISTENT;
        }
    }

    else if (listargs->scan) {
        /* SCAN mailbox for content */

        if (!strcmpsafe(mbentry->name, index_mboxname(imapd_index))) {
            /* currently selected mailbox */
            if (!index_scan(imapd_index, listargs->scan))
                return; /* no matching messages */
        }
        else {
            /* other local mailbox */
            struct index_state *state;
            struct index_init init;
            int doclose = 0;

            memset(&init, 0, sizeof(struct index_init));
            init.userid = imapd_userid;
            init.authstate = imapd_authstate;
            init.out = imapd_out;

            r = index_open(mbentry->name, &init, &state);

            if (!r)
                doclose = 1;

            if (!r && index_hasrights(state, ACL_READ)) {
                r = (imapd_userisadmin || index_hasrights(state, ACL_LOOKUP)) ?
                    IMAP_PERMISSION_DENIED : IMAP_MAILBOX_NONEXISTENT;
            }

            if (!r) {
                if (!index_scan(state, listargs->scan)) {
                    r = -1;  /* no matching messages */
                }
            }

            if (doclose) index_close(&state);

            if (r) return;
        }
    }

    /* figure out \Has(No)Children if necessary
       This is mainly used for LIST (SUBSCRIBED) RETURN (CHILDREN)
    */
    uint32_t have_childinfo =
        MBOX_ATTRIBUTE_HASCHILDREN | MBOX_ATTRIBUTE_HASNOCHILDREN;
    if ((listargs->ret & LIST_RET_CHILDREN) && !(attributes & have_childinfo)) {
        if (imapd_namespace.isalt && !strcmp(extname, "INBOX")) {
            /* don't look inside INBOX under altnamespace, its children aren't children */
        }
        else {
            char *intname = NULL, *freeme = NULL;

            /* if we got here via subscribed_cb, mbentry isn't set */
            if (mbentry)
                intname = mbentry->name;
            else
                intname = freeme = mboxname_from_external(extname, &imapd_namespace, imapd_userid);

            mboxlist_mboxtree(intname, set_haschildren, &attributes, MBOXTREE_SKIP_ROOT);
            if (freeme) free(freeme);
        }

        if (!(attributes & MBOX_ATTRIBUTE_HASCHILDREN))
            attributes |= MBOX_ATTRIBUTE_HASNOCHILDREN;
    }

    if (attributes & (MBOX_ATTRIBUTE_NONEXISTENT | MBOX_ATTRIBUTE_NOSELECT)) {
        int keep = 0;
        /* extended get told everything */
        if (listargs->cmd == LIST_CMD_EXTENDED) {
            keep = 1;
        }
        /* we have to mention this, it has children */
        if (listargs->cmd == LIST_CMD_LSUB) {
            /* subscribed children need a mention */
            if (attributes & MBOX_ATTRIBUTE_CHILDINFO_SUBSCRIBED)
                keep = 1;
            /* if mupdate is configured we can't drop out, we might
             * be a backend and need to report folders that don't
             * exist on this backend - this is awful and complex
             * and brittle and should be changed */
            if (config_mupdate_server)
                keep = 1;
        }
        else if (attributes & MBOX_ATTRIBUTE_HASCHILDREN)
            keep = 1;

        if (!keep) return;
    }

    if (listargs->cmd == LIST_CMD_LSUB) {
        /* \Noselect has a special second meaning with (R)LSUB */
        if ( !(attributes & MBOX_ATTRIBUTE_SUBSCRIBED)
             && attributes & MBOX_ATTRIBUTE_CHILDINFO_SUBSCRIBED)
            attributes |= MBOX_ATTRIBUTE_NOSELECT | MBOX_ATTRIBUTE_HASCHILDREN;
        attributes &= ~MBOX_ATTRIBUTE_SUBSCRIBED;
    }

    /* As CHILDINFO extended data item is not allowed if the
     * RECURSIVEMATCH selection option is not specified */
    if (!(listargs->sel & LIST_SEL_RECURSIVEMATCH)) {
        attributes &= ~MBOX_ATTRIBUTE_CHILDINFO_SUBSCRIBED;
    }

    /* no inferiors means no children (this basically means the INBOX
     * in alt namespace mode */
    if (attributes & MBOX_ATTRIBUTE_NOINFERIORS)
        attributes &= ~MBOX_ATTRIBUTE_HASCHILDREN;

    /* you can't have both!  If it's had children, it has children */
    if (attributes & MBOX_ATTRIBUTE_HASCHILDREN)
        attributes &= ~MBOX_ATTRIBUTE_HASNOCHILDREN;

    /* remove redundant flags */
    if (listargs->cmd == LIST_CMD_EXTENDED) {
        /* \NoInferiors implies \HasNoChildren */
        if (attributes & MBOX_ATTRIBUTE_NOINFERIORS)
            attributes &= ~MBOX_ATTRIBUTE_HASNOCHILDREN;
        /* \NonExistent implies \Noselect */
        if (attributes & MBOX_ATTRIBUTE_NONEXISTENT)
            attributes &= ~MBOX_ATTRIBUTE_NOSELECT;
    }

    if (config_getswitch(IMAPOPT_SPECIALUSEALWAYS) ||
        listargs->cmd == LIST_CMD_XLIST ||
        listargs->ret & LIST_RET_SPECIALUSE) {
        specialuse_flags(mbentry, &specialuse, listargs->cmd == LIST_CMD_XLIST);
    }

    if (listargs->sel & LIST_SEL_SPECIALUSE) {
        /* check that this IS a specialuse folder */
        if (!buf_len(&specialuse)) return;
    }

    /* can we read the status data ? */
    if ((listargs->ret & LIST_RET_STATUS) && mbentry) {
        r = imapd_statusdata(mbentry, listargs->statusitems, &sdata);
        if (r) {
            /* RFC 5819: the STATUS response MUST NOT be returned and the
             * LIST response MUST include the \NoSelect attribute. */
            attributes |= MBOX_ATTRIBUTE_NOSELECT;
        }
    }

    print_listresponse(listargs->cmd, extname,
                       imapd_namespace.hier_sep, attributes, &specialuse);
    buf_free(&specialuse);

    if ((listargs->ret & LIST_RET_STATUS) &&
        !(attributes & MBOX_ATTRIBUTE_NOSELECT)) {
        /* output the status line now, per RFC 5819 */
        if (mbentry) print_statusline(extname, listargs->statusitems, &sdata);
    }

    if ((listargs->ret & LIST_RET_MYRIGHTS) &&
        !(attributes & MBOX_ATTRIBUTE_NOSELECT)) {
        if (mbentry) printmyrights(extname, mbentry);
    }

    if ((listargs->ret & LIST_RET_METADATA) &&
        !(attributes & MBOX_ATTRIBUTE_NOSELECT)) {
        if (mbentry)
            printmetadata(mbentry, &listargs->metaitems, &listargs->metaopts);
    }
}

static void _addsubs(struct list_rock *rock)
{
    if (!rock->subs) return;
    if (!rock->last_mbentry) return;
    int i;
    const char *last_name = rock->last_mbentry->name;
    int namelen = strlen(last_name);
    for (i = 0; i < rock->subs->count; i++) {
        const char *name = strarray_nth(rock->subs, i);
        if (strncmp(last_name, name, namelen))
            continue;
        else if (!name[namelen]) {
            if ((rock->last_attributes & MBOX_ATTRIBUTE_NONEXISTENT))
                rock->last_attributes |= MBOX_ATTRIBUTE_CHILDINFO_SUBSCRIBED;
            else
                rock->last_attributes |= MBOX_ATTRIBUTE_SUBSCRIBED;
        }
        else if (name[namelen] == '.')
            rock->last_attributes |= MBOX_ATTRIBUTE_CHILDINFO_SUBSCRIBED;
    }
}

static int perform_output(const char *extname, const mbentry_t *mbentry, struct list_rock *rock)
{
    /* skip non-responsive mailboxes early, so they don't break sub folder detection */
    if (!imapd_userisadmin) {
        int mbtype = mbentry ? mbentry->mbtype : 0;

        if (mbtype_isa(mbtype) == MBTYPE_NETNEWS) return 0;
        if ((mbtype & MBTYPE_INTERMEDIATE) &&
            !(rock->listargs->sel & LIST_SEL_INTERMEDIATES)) return 0;
        if (!(rock->listargs->sel & LIST_SEL_DAV)) {
            char *intname = NULL, *freeme = NULL;
            int skip = 0;

            /* if we got here via subscribed_cb, mbentry isn't set */
            if (mbentry) intname = mbentry->name;
            else {
                intname = freeme = mboxname_from_external(extname,
                                                          &imapd_namespace,
                                                          imapd_userid);
            }
            if (mboxname_isnonimapmailbox(intname, mbtype))
                skip = 1;
            free(freeme);

            if (skip) return 0;
        }
    }

    if (mbentry && (mbentry->mbtype & MBTYPE_REMOTE)) {
        struct listargs *listargs = rock->listargs;

        if (hash_lookup(mbentry->server, &rock->server_table)) {
            /* already proxied to this backend server */
            return 0;
        }
        if (listargs->scan ||
            (listargs->ret &
             (LIST_RET_SPECIALUSE | LIST_RET_STATUS | LIST_RET_METADATA))) {
            /* remote mailbox that we need to fetch metadata from */
            struct backend *s;

            hash_insert(mbentry->server,
                        (void *)0xDEADBEEF, &rock->server_table);
            s = proxy_findserver(mbentry->server, &imap_protocol,
                                 proxy_userid, &backend_cached,
                                 &backend_current, &backend_inbox, imapd_in);
            if (s) {
                char mytag[128];

                proxy_gentag(mytag, sizeof(mytag));

                if (listargs->scan) {
                    /* Send SCAN command to backend */
                    prot_printf(s->out, "%s Scan {%tu+}\r\n%s {%tu+}\r\n%s"
                                " {%tu+}\r\n%s\r\n",
                                mytag, strlen(listargs->ref), listargs->ref,
                                strlen(listargs->pat.data[0]),
                                listargs->pat.data[0],
                                strlen(listargs->scan), listargs->scan);

                    pipe_until_tag(s, mytag, 0);
                }
                else {
                    /* Send LIST command to backend */
                    list_data_remote(s, mytag, listargs, rock->subs);
                }
            }

            return 0;
        }
    }

    if (rock->last_name) {
        if (extname) {
            /* same again */
            if (!strcmp(rock->last_name, extname)) return 0;
            size_t extlen = strlen(extname);
            if (extlen < strlen(rock->last_name)
             && rock->last_name[extlen] == imapd_namespace.hier_sep
             && !strncmp(rock->last_name, extname, extlen))
                return 0; /* skip duplicate or reversed calls */
        }
        _addsubs(rock);
        /* check if we need to filter out this mailbox */
        if (!(rock->listargs->sel & LIST_SEL_SUBSCRIBED) ||
            (rock->last_attributes &
             (MBOX_ATTRIBUTE_SUBSCRIBED | MBOX_ATTRIBUTE_CHILDINFO_SUBSCRIBED))) {
            list_response(rock->last_name, rock->last_mbentry,
                          rock->last_attributes, rock->listargs);
        }
        free(rock->last_name);
        rock->last_name = NULL;
        mboxlist_entry_free(&rock->last_mbentry);
    }

    if (extname) {
        rock->last_name = xstrdup(extname);
        if (mbentry) rock->last_mbentry = mboxlist_entry_copy(mbentry);
    }

    rock->last_attributes = 0;
    rock->last_category = 0;

    return 1;
}

static void add_intermediates(const char *extname, struct list_rock *lrock)
{
    mbname_t *mbname = mbname_from_extname(extname,
                                           &imapd_namespace, imapd_userid);
    strarray_t inter = STRARRAY_INITIALIZER;

    /* build a list of "missing" ancestors (youngest to oldest) */
    while (strarray_size(mbname_boxes(mbname))) {
        free(mbname_pop_boxes(mbname));

        extname = mbname_extname(mbname, &imapd_namespace, imapd_userid);
        if (!extname) break;  /* root of hierarchy */

        if (lrock->last_name &&
            mboxname_is_prefix(lrock->last_name, extname)) break;

        strarray_push(&inter, extname);
    }
    mbname_free(&mbname);

    /* output the ancestors (oldest to youngest) */
    char *ancestor;
    while ((ancestor = strarray_pop(&inter))) {
        mbentry_t *mbentry = NULL;

        if (!mboxlist_lookup_allow_all(ancestor, &mbentry, NULL)) {
            mbentry->mbtype |= MBTYPE_INTERMEDIATE;  /* force \NonExistent */
            perform_output(ancestor, mbentry, lrock);
        }

        mboxlist_entry_free(&mbentry);
        free(ancestor);
    }
    strarray_fini(&inter);
}

/* callback for mboxlist_findall
 * used when the SUBSCRIBED selection option is NOT given */
static int list_cb(struct findall_data *data, void *rockp)
{
    struct list_rock *rock = (struct list_rock *)rockp;

    // skip anything DELETED unless explicitly asked for
    if (data && !imapd_userisadmin
             && (!(rock->listargs->sel & LIST_SEL_DELETED) || !config_getswitch(IMAPOPT_ALLOWDELETED))
             && mbname_isdeleted(data->mbname))
        return 0;

    if (!data) {
        if (!(rock->last_attributes & MBOX_ATTRIBUTE_HASCHILDREN))
            rock->last_attributes |= MBOX_ATTRIBUTE_HASNOCHILDREN;
        perform_output(NULL, NULL, rock);
        return 0;
    }
    size_t last_len = (rock->last_name ? strlen(rock->last_name) : 0);
    const char *extname = data->extname;
    int last_name_is_ancestor =
        rock->last_name
        && strlen(extname) >= last_len
        && extname[last_len] == imapd_namespace.hier_sep
        && !memcmp(rock->last_name, extname, last_len);

    list_callback_calls++;

    /* list_response will calculate haschildren/hasnochildren flags later
     * if they're required but not yet set, but it's a little cheaper to
     * precalculate them now while we're iterating the mailboxes anyway.
     */
    if (last_name_is_ancestor || (rock->last_name && !data->is_exactmatch && !strcmp(rock->last_name, extname)))
        rock->last_attributes |= MBOX_ATTRIBUTE_HASCHILDREN;

    else if (!(rock->last_attributes & MBOX_ATTRIBUTE_HASCHILDREN))
        rock->last_attributes |= MBOX_ATTRIBUTE_HASNOCHILDREN;

    /* do we need to add "missing" intermediates? */
    if ((rock->listargs->sel & LIST_SEL_INTERMEDIATES) &&
        ((rock->listargs->sel & LIST_SEL_DAV) ||
         !mbtypes_dav(data->mbentry->mbtype)) &&
        !mboxname_contains_parent(data->extname, rock->last_name)) {

        add_intermediates(data->extname, rock);
    }

    if (!perform_output(data->extname, data->mbentry, rock))
        return 0;

    if (!data->is_exactmatch)
        rock->last_attributes |= MBOX_ATTRIBUTE_HASCHILDREN | MBOX_ATTRIBUTE_NONEXISTENT;

    else if (data->mb_category == MBNAME_ALTINBOX)
        rock->last_attributes |= MBOX_ATTRIBUTE_NOINFERIORS;

    return 0;
}

/* callback for mboxlist_findsub
 * used when SUBSCRIBED but not RECURSIVEMATCH is given */
static int subscribed_cb(struct findall_data *data, void *rockp)
{
    struct list_rock *rock = (struct list_rock *)rockp;
    if (!data) {
        perform_output(NULL, NULL, rock);
        return 0;
    }
    size_t last_len = (rock->last_name ? strlen(rock->last_name) : 0);
    const char *extname = data->extname;
    int last_name_is_ancestor =
        rock->last_name
        && strlen(extname) >= last_len
        && extname[last_len] == imapd_namespace.hier_sep
        && !memcmp(rock->last_name, extname, last_len);

    list_callback_calls++;

    if (last_name_is_ancestor ||
        (rock->last_name && !data->is_exactmatch && !strcmp(rock->last_name, extname)))
        rock->last_attributes |= MBOX_ATTRIBUTE_HASCHILDREN;

    if (data->is_exactmatch) {
        mbentry_t *mbentry = NULL;
        mboxlist_lookup(mbname_intname(data->mbname), &mbentry, NULL);
        perform_output(extname, mbentry, rock);
        mboxlist_entry_free(&mbentry);

        rock->last_attributes |= MBOX_ATTRIBUTE_SUBSCRIBED;
        if (mboxlist_lookup(mbname_intname(data->mbname), NULL, NULL))
            rock->last_attributes |= MBOX_ATTRIBUTE_NONEXISTENT;
        if (data->mb_category == MBNAME_ALTINBOX)
            rock->last_attributes |= MBOX_ATTRIBUTE_NOINFERIORS;
    }
    else if (rock->listargs->cmd == LIST_CMD_LSUB) {
        /* special case: for LSUB,
         * mailbox names that match the pattern but aren't subscribed
         * must also be returned if they have a child mailbox that is
         * subscribed */
        perform_output(extname, data->mbentry, rock);
        rock->last_attributes |= MBOX_ATTRIBUTE_CHILDINFO_SUBSCRIBED;
    }

    return 0;
}

/*
 * Takes the "reference name" and "mailbox name" arguments of the LIST command
 * and returns a "canonical LIST pattern". The caller is responsible for
 * free()ing the returned string.
 */
static char *canonical_list_pattern(const char *reference, const char *pattern)
{
    int patlen = strlen(pattern);
    int reflen = strlen(reference);

    char *buf = xmalloc(patlen + reflen + 1);
    buf[0] = '\0';

    if (*reference) {
        if (reference[reflen-1] == imapd_namespace.hier_sep &&
                pattern[0] == imapd_namespace.hier_sep)
            --reflen;
        memcpy(buf, reference, reflen);
        buf[reflen] = '\0';
    }
    strcat(buf, pattern);

    return buf;
}

/*
 * Turns the strings in patterns into "canonical LIST pattern"s. Also
 * translates any hierarchy separators.
 */
static void canonical_list_patterns(const char *reference,
                                    strarray_t *patterns)
{
    static int ignorereference = 0;
    int i;

    /* Ignore the reference argument?
       (the behavior in 1.5.10 & older) */
    if (ignorereference == 0)
        ignorereference = config_getswitch(IMAPOPT_IGNOREREFERENCE);

    for (i = 0 ; i < patterns->count ; i++) {
        char *p = patterns->data[i];
        if (!ignorereference || p[0] == imapd_namespace.hier_sep) {
            strarray_setm(patterns, i,
                          canonical_list_pattern(reference, p));
            p = patterns->data[i];
        }
    }
}

static void list_data_remotesubscriptions(struct listargs *listargs)
{
    /* Need to fetch subscription list from backend_inbox */
    struct list_rock rock;
    char mytag[128];

    memset(&rock, 0, sizeof(struct list_rock));
    rock.listargs = listargs;
    rock.subs = strarray_new();
    construct_hash_table(&rock.server_table, 10, 1);

    proxy_gentag(mytag, sizeof(mytag));

    if ((listargs->sel & LIST_SEL_SUBSCRIBED) &&
        !(listargs->sel & (LIST_SEL_SPECIALUSE | LIST_SEL_METADATA))) {
        /* Subscriptions are the only selection criteria.

           Send client request as-is to backend_inbox.
           Responses will be piped to the client as we build subs list.
        */
        list_data_remote(backend_inbox, mytag, listargs, rock.subs);

        /* Don't proxy to backend_inbox again */
        hash_insert(backend_inbox->hostname,
                    (void *)0xDEADBEEF, &rock.server_table);
    }
    else {
        /* Multiple selection criteria or need to return subscription info.

           Just fetch subscriptions without piping responses to the client.
           If we send entire client request, subscribed mailboxes on
           non-Inbox servers might be filtered out due to lack of metadata
           to meet the selection criteria.

           Note that we end up sending two requests to backend_inbox,
           but there doesn't appear to be any way around this.
        */
        struct listargs myargs;

        memcpy(&myargs, listargs, sizeof(struct listargs));
        myargs.sel = LIST_SEL_SUBSCRIBED;
        myargs.ret = 0;

        list_data_remote(backend_inbox, mytag, &myargs, rock.subs);
    }

    /* find */
    mboxlist_findallmulti(&imapd_namespace, &listargs->pat,
                          imapd_userisadmin, imapd_userid,
                          imapd_authstate, list_cb, &rock);

    strarray_free(rock.subs);
    free_hash_table(&rock.server_table, NULL);
    if (rock.last_name) free(rock.last_name);
}

/* callback for mboxlist_findsub
 * used by list_data_recursivematch */
static int recursivematch_cb(struct findall_data *data, void *rockp)
{
    if (!data) return 0;

    struct list_rock_recursivematch *rock = (struct list_rock_recursivematch *)rockp;
    list_callback_calls++;

    const char *extname = data->extname;

    /* skip non-responsive mailboxes early, so they don't break sub folder detection */
    if (!(imapd_userisadmin || (rock->listargs->sel & LIST_SEL_DAV))) {
        mbname_t *mbname = (mbname_t *) data->mbname;
        const char *intname;
        int r;

        if (!mbname) {
            mbname = mbname_from_extname(extname, &imapd_namespace, imapd_userid);
        }

        if (mbname) {
            intname = mbname_intname(mbname);
            r = mboxname_iscalendarmailbox(intname, 0) ||
                mboxname_isaddressbookmailbox(intname, 0) ||
                mboxname_isdavdrivemailbox(intname, 0) ||
                mboxname_isdavnotificationsmailbox(intname, 0);

            if (!data->mbname) mbname_free(&mbname);

            if (r) return 0;
        }
    }

    struct list_entry *entry = hash_lookup(extname, &rock->table);
    if (!entry) {
        entry = xzmalloc(sizeof(struct list_entry));
        entry->extname = xstrdupsafe(extname);
        entry->attributes |= MBOX_ATTRIBUTE_NONEXISTENT;

        hash_insert(extname, entry, &rock->table);
        rock->count++;
    }


    if (data->is_exactmatch) {
        entry->attributes |= MBOX_ATTRIBUTE_SUBSCRIBED;
        if (!data->mbentry) {
            mboxlist_lookup(mbname_intname(data->mbname), &entry->mbentry, NULL);
            if (entry->mbentry) entry->attributes &= ~MBOX_ATTRIBUTE_NONEXISTENT;
        }
    }
    else {
        entry->attributes |= MBOX_ATTRIBUTE_CHILDINFO_SUBSCRIBED | MBOX_ATTRIBUTE_HASCHILDREN;
    }

    return 0;
}

/* callback for hash_enumerate */
static void copy_to_array(const char *key __attribute__((unused)), void *data, void *void_rock)
{
    struct list_entry *entry = (struct list_entry *)data;
    struct list_rock_recursivematch *rock =
        (struct list_rock_recursivematch *)void_rock;
    assert(rock->count > 0);
    rock->array[--rock->count] = *entry;
}

/* Comparator for sorting an array of struct list_entry by mboxname. */
static int list_entry_comparator(const void *p1, const void *p2) {
    const struct list_entry *e1 = (struct list_entry *)p1;
    const struct list_entry *e2 = (struct list_entry *)p2;

    return strcmp(e1->extname, e2->extname);
}

static void free_list_entry(void *rock)
{
    struct list_entry *entry = (struct list_entry *)rock;
    mboxlist_entry_free(&entry->mbentry);
    free(entry->extname);
    free(entry);
}

static void list_data_recursivematch(struct listargs *listargs)
{
    struct list_rock_recursivematch rock;

    rock.count = 0;
    rock.listargs = listargs;
    construct_hash_table(&rock.table, 100, 1);

    /* find */
    mboxlist_findsubmulti(&imapd_namespace, &listargs->pat, imapd_userisadmin, imapd_userid,
                          imapd_authstate, recursivematch_cb, &rock, 1);

    if (rock.count) {
        int i;
        int entries = rock.count;

        /* sort */
        rock.array = xmalloc(entries * (sizeof(struct list_entry)));
        hash_enumerate(&rock.table, copy_to_array, &rock);
        qsort(rock.array, entries, sizeof(struct list_entry),
              list_entry_comparator);
        assert(rock.count == 0);

        /* print */
        for (i = 0; i < entries; i++) {
            if (!rock.array[i].extname) continue;
            list_response(rock.array[i].extname,
                          rock.array[i].mbentry,
                          rock.array[i].attributes,
                          rock.listargs);
        }

        free(rock.array);
    }

    free_hash_table(&rock.table, free_list_entry);
}

/* Retrieves the data and prints the untagged responses for a LIST command. */
static void list_data(struct listargs *listargs)
{
    canonical_list_patterns(listargs->ref, &listargs->pat);

    /* Check to see if we should only list the personal namespace */
    if (!(listargs->cmd == LIST_CMD_EXTENDED)
            && !strcmp(listargs->pat.data[0], "*")
            && config_getswitch(IMAPOPT_FOOLSTUPIDCLIENTS)) {
        strarray_set(&listargs->pat, 0, "INBOX*");
    }

    if ((listargs->ret & LIST_RET_SUBSCRIBED) &&
        (backend_inbox || (backend_inbox = proxy_findinboxserver(imapd_userid)))) {
        list_data_remotesubscriptions(listargs);
    }
    else if (listargs->sel & LIST_SEL_RECURSIVEMATCH) {
        list_data_recursivematch(listargs);
    }
    else {
        struct list_rock rock;
        memset(&rock, 0, sizeof(struct list_rock));
        rock.listargs = listargs;

        if (listargs->sel & LIST_SEL_SUBSCRIBED) {
            mboxlist_findsubmulti(&imapd_namespace, &listargs->pat,
                                  imapd_userisadmin, imapd_userid,
                                  imapd_authstate, subscribed_cb, &rock, 1);
        }
        else {
            if (config_mupdate_server) {
                /* In case we proxy to backends due to select/return criteria */
                construct_hash_table(&rock.server_table, 10, 1);
            }

            /* XXX: is there a cheaper way to figure out \Subscribed? */
            if (listargs->ret & LIST_RET_SUBSCRIBED) {
                rock.subs = mboxlist_sublist(imapd_userid);
            }

            mboxlist_findallmulti(&imapd_namespace, &listargs->pat,
                                  imapd_userisadmin, imapd_userid,
                                  imapd_authstate, list_cb, &rock);

            if (rock.subs) strarray_free(rock.subs);
            if (rock.server_table.size)
                free_hash_table(&rock.server_table, NULL);
        }

        if (rock.last_name) free(rock.last_name);
    }
}

/*
 * Retrieves the data and prints the untagged responses for a LIST command in
 * the case of a remote inbox.
 */
static int list_data_remote(struct backend *be, char *tag,
                            struct listargs *listargs, strarray_t *subs)
{
    if ((listargs->cmd == LIST_CMD_EXTENDED) &&
        !CAPA(be, CAPA_LISTEXTENDED)) {
        /* client wants to use extended list command but backend doesn't
         * support it */
        prot_printf(imapd_out,
                    "%s NO Backend server does not support LIST-EXTENDED\r\n",
                    tag);
        return IMAP_MAILBOX_NOTSUPPORTED;
    }

    /* print tag, command and list selection options */
    if (listargs->cmd == LIST_CMD_LSUB) {
        prot_printf(be->out, "%s Lsub ", tag);
    } else if (listargs->cmd == LIST_CMD_XLIST) {
        prot_printf(be->out, "%s Xlist ", tag);
    } else {
        prot_printf(be->out, "%s List ", tag);

        uint32_t select_mask = listargs->sel;

        if (be != backend_inbox) {
            /* don't send subscribed selection options to non-Inbox backend */
            select_mask &= ~(LIST_SEL_SUBSCRIBED | LIST_SEL_RECURSIVEMATCH);
        }

        /* print list selection options */
        if (select_mask) {
            const char *select_opts[] = {
                /* XXX  MUST be in same order as LIST_SEL_* bitmask */
                "subscribed", "remote", "recursivematch",
                "special-use", "vendor.cmu-dav", "metadata", NULL
            };
            char c = '(';
            int i;

            for (i = 0; select_opts[i]; i++) {
                unsigned opt = (1 << i);

                if (!(select_mask & opt)) continue;

                prot_printf(be->out, "%c%s", c, select_opts[i]);
                c = ' ';

                if (opt == LIST_SEL_METADATA) {
                    /* print metadata options */
                    prot_puts(be->out, " (depth ");
                    if (listargs->metaopts.depth < 0) {
                        prot_puts(be->out, "infinity");
                    }
                    else {
                        prot_printf(be->out, "%d",
                                    listargs->metaopts.depth);
                    }
                    if (listargs->metaopts.maxsize) {
                        prot_printf(be->out, " maxsize %zu",
                                    listargs->metaopts.maxsize);
                    }
                    (void)prot_putc(')', be->out);
                }
            }
            prot_puts(be->out, ") ");
        }
    }

    /* print reference argument */
    prot_printf(be->out,
                "{%tu+}\r\n%s ", strlen(listargs->ref), listargs->ref);

    /* print mailbox pattern(s) */
    if (listargs->pat.count > 1) {
        char **p;
        char c = '(';

        for (p = listargs->pat.data ; *p ; p++) {
            prot_printf(be->out,
                        "%c{%tu+}\r\n%s", c, strlen(*p), *p);
            c = ' ';
        }
        (void)prot_putc(')', be->out);
    } else {
        prot_printf(be->out, "{%tu+}\r\n%s",
                    strlen(listargs->pat.data[0]), listargs->pat.data[0]);
    }

    /* print list return options */
    if (listargs->ret && listargs->cmd == LIST_CMD_EXTENDED) {
        const char *return_opts[] = {
            /* XXX  MUST be in same order as LIST_RET_* bitmask */
            "subscribed", "children", "special-use",
            "status ", "myrights", "metadata ", NULL
        };
        char c = '(';
        int i, j;

        prot_puts(be->out, " return ");
        for (i = 0; return_opts[i]; i++) {
            unsigned opt = (1 << i);

            if (!(listargs->ret & opt)) continue;

            prot_printf(be->out, "%c%s", c, return_opts[i]);
            c = ' ';

            if (opt == LIST_RET_STATUS) {
                /* print status items */
                const char *status_items[] = {
                    /* XXX  MUST be in same order as STATUS_* bitmask */
                    "messages", "recent", "uidnext", "uidvalidity",
                    "unseen", "uniqueid", "size", "highestmodseq",
                    "xconvexists", "xconvunseen", "xconvmodseq",
                    "createdmodseq", "sharedseen", NULL
                };

                c = '(';
                for (j = 0; status_items[j]; j++) {
                    if (!(listargs->statusitems & (1 << j))) continue;

                    prot_printf(be->out, "%c%s", c, status_items[j]);
                    c = ' ';
                }
                (void)prot_putc(')', be->out);
            }
            else if (opt == LIST_RET_METADATA) {
                /* print metadata items */
                int n = strarray_size(&listargs->metaitems);

                c = '(';
                for (j = 0; j < n; j++) {
                    prot_printf(be->out, "%c\"%s\"", c,
                                strarray_nth(&listargs->metaitems, j));
                    c = ' ';
                }
                (void)prot_putc(')', be->out);
            }
        }
        (void)prot_putc(')', be->out);
    }

    prot_printf(be->out, "\r\n");
    pipe_lsub(be, imapd_userid, tag, 0, listargs, subs);

    return 0;
}

/* Reset the given sasl_conn_t to a sane state */
static int reset_saslconn(sasl_conn_t **conn)
{
    int ret;
    sasl_security_properties_t *secprops = NULL;

    sasl_dispose(conn);
    /* do initialization typical of service_main */
    ret = sasl_server_new("imap", config_servername, NULL,
                          buf_cstringnull_ifempty(&saslprops.iplocalport),
                          buf_cstringnull_ifempty(&saslprops.ipremoteport),
                          NULL, 0, conn);
    if(ret != SASL_OK) return ret;

    secprops = mysasl_secprops(0);
    ret = sasl_setprop(*conn, SASL_SEC_PROPS, secprops);
    if(ret != SASL_OK) return ret;
    /* end of service_main initialization excepting SSF */

    /* If we have TLS/SSL info, set it */
    if(saslprops.ssf) {
        ret = saslprops_set_tls(&saslprops, *conn);
    } else {
        ret = sasl_setprop(*conn, SASL_SSF_EXTERNAL, &extprops_ssf);
    }
    if(ret != SASL_OK) return ret;
    /* End TLS/SSL Info */

    return SASL_OK;
}

static void cmd_mupdatepush(char *tag, char *name)
{
    int r = 0, retry = 0;
    mbentry_t *mbentry = NULL;
    char buf[MAX_PARTITION_LEN + HOSTNAME_SIZE + 2];
    char *intname = mboxname_from_external(name, &imapd_namespace, imapd_userid);

    if (!imapd_userisadmin) {
        r = IMAP_PERMISSION_DENIED;
        goto done;
    }
    if (!config_mupdate_server) {
        r = IMAP_SERVER_UNAVAILABLE;
        goto done;
    }

    r = mlookup(tag, name, intname, &mbentry);
    if (r) goto done;

    /* Push mailbox to mupdate server */
    if (!mupdate_h) {
        syslog(LOG_INFO, "XFER: connecting to mupdate '%s'",
               config_mupdate_server);

        r = mupdate_connect(config_mupdate_server, NULL, &mupdate_h, NULL);
        retry = 1;
        if (r) {
            syslog(LOG_INFO, "Failed to connect to mupdate '%s'",
                   config_mupdate_server);
            goto done;
        }
    }

    snprintf(buf, sizeof(buf), "%s!%s",
             config_servername, mbentry->partition);

  retry:
    r = mupdate_activate(mupdate_h, intname, buf, mbentry->acl);

    if (r && !retry) {
        syslog(LOG_INFO, "MUPDATE: lost connection, retrying");
        mupdate_disconnect(&mupdate_h);
        r = mupdate_connect(config_mupdate_server, NULL, &mupdate_h, NULL);
        if (r) {
            syslog(LOG_INFO, "Failed to connect to mupdate '%s'",
                   config_mupdate_server);
        }
        else {
            retry = 1;
            goto retry;
        }
    }

done:
    mboxlist_entry_free(&mbentry);
    free(intname);
    if (r) {
        prot_printf(imapd_out, "%s NO %s\r\n", tag, error_message(r));
    }
    else {
        prot_printf(imapd_out, "%s OK %s\r\n", tag,
                    error_message(IMAP_OK_COMPLETED));
    }
}

#ifdef HAVE_SSL
enum {
    URLAUTH_ALG_HMAC_SHA1 =     0 /* HMAC-SHA1 */
};

static void cmd_urlfetch(char *tag)
{
    struct mboxkey *mboxkey_db;
    int c, r, doclose;
    static struct buf arg, param;
    struct imapurl url;
    struct index_state *state;
    uint32_t msgno;
    mbentry_t *mbentry = NULL;
    time_t now = time(NULL);
    unsigned extended, params;

    prot_printf(imapd_out, "* URLFETCH");

    do {
        char *intname = NULL;
        extended = params = 0;

        /* See if its an extended URLFETCH */
        c = prot_getc(imapd_in);
        if (c == '(') extended = 1;
        else prot_ungetc(c, imapd_in);

        c = getastring(imapd_in, imapd_out, &arg);
        (void)prot_putc(' ', imapd_out);
        prot_printstring(imapd_out, arg.s);

        if (extended) {
            while (c == ' ') {
                c = getword(imapd_in, &param);

                ucase(param.s);
                if (!strcmp(param.s, "BODY")) {
                    if (params & (URLFETCH_BODY | URLFETCH_BINARY)) goto badext;
                    params |= URLFETCH_BODY;
                } else if (!strcmp(param.s, "BINARY")) {
                    if (params & (URLFETCH_BODY | URLFETCH_BINARY)) goto badext;
                    params |= URLFETCH_BINARY;
                } else if (!strcmp(param.s, "BODYPARTSTRUCTURE")) {
                    if (params & URLFETCH_BODYPARTSTRUCTURE) goto badext;
                    params |= URLFETCH_BODYPARTSTRUCTURE;
                } else {
                    goto badext;
                }
            }

            if (c != ')') goto badext;
            c = prot_getc(imapd_in);
        }

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

        if (r) goto err;

        intname = mboxname_from_external(url.mailbox, &imapd_namespace, url.user);
        r = mlookup(NULL, NULL, intname, &mbentry);
        if (r) goto err;

        if ((mbentry->mbtype & MBTYPE_REMOTE)) {
            /* remote mailbox */
            struct backend *be;

            be = proxy_findserver(mbentry->server, &imap_protocol,
                                  proxy_userid, &backend_cached,
                                  &backend_current, &backend_inbox, imapd_in);
            if (!be) {
                r = IMAP_SERVER_UNAVAILABLE;
            } else {
                /* XXX  proxy command to backend */
            }

            free(url.freeme);

            mboxlist_entry_free(&mbentry);
            free(intname);

            continue;
        }

        mboxlist_entry_free(&mbentry);

        /* local mailbox */
        if (url.urlauth.token) {
            /* validate the URLAUTH token */

            /* yes, this is evil, in-place conversion from hex
             * to binary */
            if (hex_to_bin(url.urlauth.token, 0,
                (unsigned char *) url.urlauth.token) < 1) {
                r = IMAP_BADURL;
                break;
            }

            /* first byte is the algorithm used to create token */
            switch (url.urlauth.token[0]) {
            case URLAUTH_ALG_HMAC_SHA1: {
                const char *key;
                size_t keylen;
                unsigned char vtoken[EVP_MAX_MD_SIZE];
                unsigned int vtoken_len;

                r = mboxkey_open(url.user, 0, &mboxkey_db);
                if (r) break;

                r = mboxkey_read(mboxkey_db, intname, &key, &keylen);
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
        if (r) goto err;

        if (!strcmpnull(index_mboxname(imapd_index), intname)) {
            state = imapd_index;
        }
        else {
            /* not the currently selected mailbox, so try to open it */

            r = index_open(intname, NULL, &state);
            if (!r)
                doclose = 1;

            if (!r && !url.urlauth.access &&
                !(state->myrights & ACL_READ)) {
                r = (imapd_userisadmin ||
                     (state->myrights & ACL_LOOKUP)) ?
                    IMAP_PERMISSION_DENIED : IMAP_MAILBOX_NONEXISTENT;
            }
        }
        if (r) goto err;

        if (url.uidvalidity &&
           (state->mailbox->i.uidvalidity != url.uidvalidity)) {
            r = IMAP_BADURL;
        } else if (!url.uid || !(msgno = index_finduid(state, url.uid)) ||
                   (index_getuid(state, msgno) != url.uid)) {
            r = IMAP_BADURL;
        } else {
            r = index_urlfetch(state, msgno, params, url.section,
                               url.start_octet, url.octet_count,
                               imapd_out, UINT32_MAX, NULL);
        }

    err:
        if (doclose)
            index_close(&state);

        free(url.freeme);

        if (r) prot_printf(imapd_out, " NIL");
        free(intname);

    } while (c == ' ');

    prot_printf(imapd_out, "\r\n");

    if (!IS_EOL(c, imapd_in)) {
        prot_printf(imapd_out,
                    "%s BAD Unexpected extra arguments to URLFETCH\r\n", tag);
        eatline(imapd_in, c);
    }
    else {
        prot_printf(imapd_out, "%s OK %s\r\n", tag,
                    error_message(IMAP_OK_COMPLETED));
    }
    return;

  badext:
    prot_printf(imapd_out, " NIL\r\n");
    prot_printf(imapd_out,
                "%s BAD Invalid extended URLFETCH parameters\r\n", tag);
    eatline(imapd_in, c);
}

#define MBOX_KEY_LEN 16           /* 128 bits */

static void cmd_genurlauth(char *tag)
{
    struct mboxkey *mboxkey_db;
    int first = 1;
    int c, r;
    static struct buf arg1, arg2;
    struct imapurl url;
    char newkey[MBOX_KEY_LEN];
    char *urlauth = NULL;
    const char *key;
    size_t keylen;
    unsigned char token[EVP_MAX_MD_SIZE+1]; /* +1 for algorithm */
    unsigned int token_len;
    mbentry_t *mbentry = NULL;
    time_t now = time(NULL);

    r = mboxkey_open(imapd_userid, MBOXKEY_CREATE, &mboxkey_db);
    if (r) {
        prot_printf(imapd_out,
                   "%s NO Cannot open mailbox key db for %s: %s\r\n",
                   tag, imapd_userid, error_message(r));
        return;
    }

    do {
        char *intname = NULL;

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
        if (r) goto err;

        intname = mboxname_from_external(url.mailbox, &imapd_namespace, imapd_userid);
        r = mlookup(NULL, NULL, intname, &mbentry);

        if (r) {
            prot_printf(imapd_out,
                        "%s BAD Poorly specified URL to Genurlauth %s\r\n",
                        tag, arg1.s);
            eatline(imapd_in, c);
            free(url.freeme);
            free(intname);
            return;
        }

        if (mbentry->mbtype & MBTYPE_REMOTE) {
            /* XXX  proxy to backend */
            mboxlist_entry_free(&mbentry);
            free(url.freeme);
            free(intname);
            continue;
        }

        mboxlist_entry_free(&mbentry);

        /* lookup key */
        r = mboxkey_read(mboxkey_db, intname, &key, &keylen);
        if (r) {
            syslog(LOG_ERR, "DBERROR: error fetching mboxkey: %s",
                   cyrusdb_strerror(r));
        }
        else if (!key) {
            /* create a new key */
            RAND_bytes((unsigned char *) newkey, MBOX_KEY_LEN);
            key = newkey;
            keylen = MBOX_KEY_LEN;
            r = mboxkey_write(mboxkey_db, intname, key, keylen);
            if (r) {
                syslog(LOG_ERR, "DBERROR: error writing new mboxkey: %s",
                       cyrusdb_strerror(r));
            }
        }

        if (r) {
        err:
            eatline(imapd_in, c);
            prot_printf(imapd_out,
                        "%s NO Error authorizing %s: %s\r\n",
                        tag, arg1.s, cyrusdb_strerror(r));
            free(url.freeme);
            free(intname);
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
        bin_to_hex(token, token_len, urlauth+strlen(urlauth), BH_LOWER);

        if (first) {
            prot_printf(imapd_out, "* GENURLAUTH");
            first = 0;
        }
        (void)prot_putc(' ', imapd_out);
        prot_printstring(imapd_out, urlauth);
        free(intname);
        free(url.freeme);
    } while (c == ' ');

    if (!first) prot_printf(imapd_out, "\r\n");

    if (!IS_EOL(c, imapd_in)) {
        prot_printf(imapd_out,
                    "%s BAD Unexpected extra arguments to GENURLAUTH\r\n", tag);
        eatline(imapd_in, c);
    }
    else {
        prot_printf(imapd_out, "%s OK %s\r\n", tag,
                    error_message(IMAP_OK_COMPLETED));
    }

    free(urlauth);

    mboxkey_close(mboxkey_db);
}

static void cmd_resetkey(char *tag, char *name,
                  char *mechanism __attribute__((unused)))
/* XXX we don't support any external mechanisms, so we ignore it */
{
    int r;

    if (name) {
        /* delete key for specified mailbox */
        struct mboxkey *mboxkey_db;
        mbentry_t *mbentry = NULL;

        char *intname = mboxname_from_external(name, &imapd_namespace, imapd_userid);
        r = mlookup(NULL, NULL, intname, &mbentry);
        if (r) {
            prot_printf(imapd_out, "%s NO Error removing key: %s\r\n",
                        tag, error_message(r));
            free(intname);
            return;
        }

        if (mbentry->mbtype & MBTYPE_REMOTE) {
            /* XXX  proxy to backend */
            mboxlist_entry_free(&mbentry);
            free(intname);
            return;
        }

        mboxlist_entry_free(&mbentry);

        r = mboxkey_open(imapd_userid, MBOXKEY_CREATE, &mboxkey_db);
        if (!r) {
            r = mboxkey_write(mboxkey_db, intname, NULL, 0);
            mboxkey_close(mboxkey_db);
        }

        if (r) {
            prot_printf(imapd_out, "%s NO Error removing key: %s\r\n",
                        tag, cyrusdb_strerror(r));
        } else {
            prot_printf(imapd_out,
                        "%s OK [URLMECH INTERNAL] key removed\r\n", tag);
        }
        free(intname);
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

#ifdef HAVE_ZLIB
static void cmd_compress(char *tag, char *alg)
{
    if (imapd_compress_done) {
        prot_printf(imapd_out,
                    "%s BAD [COMPRESSIONACTIVE] DEFLATE active via COMPRESS\r\n",
                    tag);
    }
#if defined(HAVE_SSL) && (OPENSSL_VERSION_NUMBER >= 0x0090800fL)
    else if (imapd_tls_comp) {
        prot_printf(imapd_out,
                    "%s NO [COMPRESSIONACTIVE] %s active via TLS\r\n",
                    tag, SSL_COMP_get_name(imapd_tls_comp));
    }
#endif // defined(HAVE_SSL) && (OPENSSL_VERSION_NUMBER >= 0x0090800fL)
    else if (strcasecmp(alg, "DEFLATE")) {
        prot_printf(imapd_out,
                    "%s NO Unknown COMPRESS algorithm: %s\r\n", tag, alg);
    }
    else if (ZLIB_VERSION[0] != zlibVersion()[0]) {
        prot_printf(imapd_out,
                    "%s NO Error initializing %s (incompatible zlib version)\r\n",
                    tag, alg);
    }
    else {
        prot_printf(imapd_out,
                    "%s OK %s active\r\n", tag, alg);

        /* enable (de)compression for the prot layer */
        prot_setcompress(imapd_in);
        prot_setcompress(imapd_out);

        imapd_compress_done = 1;
    }
}
#endif /* HAVE_ZLIB */

static void cmd_enable(char *tag)
{
    static struct buf arg;
    int c;
    unsigned new_capa = 0;

    /* RFC 5161 says that enable while selected is actually bogus,
     * but it's no skin off our nose to support it, so don't
     * bother checking */

    do {
        c = getword(imapd_in, &arg);
        if (!arg.s[0]) {
            prot_printf(imapd_out,
                        "\r\n%s BAD Missing required argument to Enable\r\n",
                        tag);
            eatline(imapd_in, c);
            return;
        }
        if (!strcasecmp(arg.s, "condstore"))
            new_capa |= CAPA_CONDSTORE;
        else if (!strcasecmp(arg.s, "qresync"))
            new_capa |= CAPA_QRESYNC | CAPA_CONDSTORE;
    } while (c == ' ');

    /* check for CRLF */
    if (!IS_EOL(c, imapd_in)) {
        prot_printf(imapd_out,
                    "%s BAD Unexpected extra arguments to Enable\r\n", tag);
        eatline(imapd_in, c);
        return;
    }

    int started = 0;
    if (!(client_capa & CAPA_CONDSTORE) &&
         (new_capa & CAPA_CONDSTORE)) {
        if (!started) prot_printf(imapd_out, "* ENABLED");
        started = 1;
        prot_printf(imapd_out, " CONDSTORE");
    }
    if (!(client_capa & CAPA_QRESYNC) &&
         (new_capa & CAPA_QRESYNC)) {
        if (!started) prot_printf(imapd_out, "* ENABLED");
        started = 1;
        prot_printf(imapd_out, " QRESYNC");
    }
    if (started) prot_printf(imapd_out, "\r\n");

    /* track the new capabilities */
    client_capa |= new_capa;

    prot_printf(imapd_out, "%s OK %s\r\n", tag,
                error_message(IMAP_OK_COMPLETED));
}

static void cmd_xkillmy(const char *tag, const char *cmdname)
{
    char *cmd = xstrdup(cmdname);
    char *p;

    /* normalise to imapd conventions */
    if (Uislower(cmd[0]))
        cmd[0] = toupper((unsigned char) cmd[0]);
    for (p = cmd+1; *p; p++) {
        if (Uisupper(*p)) *p = tolower((unsigned char) *p);
    }

    proc_killusercmd(imapd_userid, cmd, SIGUSR2);

    free(cmd);

    prot_printf(imapd_out, "%s OK %s\r\n", tag,
                error_message(IMAP_OK_COMPLETED));
}

static void cmd_xforever(const char *tag)
{
    unsigned n = 1;
    int r = 0;

    while (!r) {
        sleep(1);
        prot_printf(imapd_out, "* FOREVER %u\r\n", n++);
        prot_flush(imapd_out);
        r = cmd_cancelled(/*insearch*/0);
    }

    prot_printf(imapd_out, "%s OK %s\r\n", tag, error_message(r));
}

static void cmd_xmeid(const char *tag, const char *id)
{
    mboxevent_set_client_id(id);

    prot_printf(imapd_out, "%s OK %s\r\n", tag,
                error_message(IMAP_OK_COMPLETED));
}

/*****************************  server-side sync  *****************************/

static void cmd_syncapply(const char *tag, struct dlist *kin, struct sync_reserve_list *reserve_list)
{
    struct sync_state sync_state = {
        imapd_userid,
        imapd_userisadmin || imapd_userisproxyadmin,
        imapd_authstate,
        &imapd_namespace,
        imapd_out,
        0 /* local_only */
    };

    /* administrators only please */
    if (!imapd_userisadmin) {
        syslog(LOG_ERR, "SYNCERROR: invalid user %s trying to sync", imapd_userid);
        prot_printf(imapd_out, "%s NO only administrators may use sync commands\r\n", tag);
        return;
    }

    const char *resp = sync_apply(kin, reserve_list, &sync_state);

    // chaining!
    index_release(imapd_index);
    sync_checkpoint(imapd_in);

    prot_printf(imapd_out, "%s %s\r\n", tag, resp);

    /* Reset inactivity timer in case we spent a long time processing data */
    prot_resettimeout(imapd_in);
}

static void cmd_syncget(const char *tag, struct dlist *kin)
{
    struct sync_state sync_state = {
        imapd_userid,
        imapd_userisadmin || imapd_userisproxyadmin,
        imapd_authstate,
        &imapd_namespace,
        imapd_out,
        0 /* local_only */
    };

    /* administrators only please */
    if (!imapd_userisadmin) {
        syslog(LOG_ERR, "SYNCERROR: invalid user %s trying to sync", imapd_userid);
        prot_printf(imapd_out, "%s NO only administrators may use sync commands\r\n", tag);
        return;
    }

    const char *resp = sync_get(kin, &sync_state);
    prot_printf(imapd_out, "%s %s\r\n", tag, resp);

    /* Reset inactivity timer in case we spent a long time processing data */
    prot_resettimeout(imapd_in);
}

/* partition_list is simple linked list of names used by cmd_syncrestart */

struct partition_list {
    struct partition_list *next;
    char *name;
};

static struct partition_list *
partition_list_add(char *name, struct partition_list *pl)
{
    struct partition_list *p;

    /* Is name already on list? */
    for (p=pl; p; p = p->next) {
        if (!strcmp(p->name, name))
            return(pl);
    }

    /* Add entry to start of list and return new list */
    p = xzmalloc(sizeof(struct partition_list));
    p->next = pl;
    p->name = xstrdup(name);

    return(p);
}

static void
partition_list_free(struct partition_list *current)
{
    while (current) {
        struct partition_list *next = current->next;

        free(current->name);
        free(current);

        current = next;
    }
}

static void cmd_syncrestart(const char *tag, struct sync_reserve_list **reserve_listp, int re_alloc)
{
    struct sync_reserve *res;
    struct sync_reserve_list *l = *reserve_listp;
    struct sync_msgid *msg;
    int hash_size = l->hash_size;
    struct partition_list *p, *pl = NULL;

    for (res = l->head; res; res = res->next) {
        for (msg = res->list->head; msg; msg = msg->next) {
            if (!msg->fname) continue;
            pl = partition_list_add(res->part, pl);

            unlink(msg->fname);
        }
    }
    sync_reserve_list_free(reserve_listp);

    /* Remove all <partition>/sync./<pid> directories referred to above */
    for (p=pl; p ; p = p->next) {
        static char buf[MAX_MAILBOX_PATH];

        snprintf(buf, MAX_MAILBOX_PATH, "%s/sync./%lu",
                 config_partitiondir(p->name), (unsigned long)getpid());
        rmdir(buf);

        if (config_getswitch(IMAPOPT_ARCHIVE_ENABLED)) {
            /* and the archive partition too */
            snprintf(buf, MAX_MAILBOX_PATH, "%s/sync./%lu",
                    config_archivepartitiondir(p->name), (unsigned long)getpid());
            rmdir(buf);
        }
    }
    partition_list_free(pl);

    if (re_alloc) {
        *reserve_listp = sync_reserve_list_create(hash_size);
        prot_printf(imapd_out, "%s OK Restarting\r\n", tag);
    }
    else
        *reserve_listp = NULL;
}

static void cmd_syncrestore(const char *tag, struct dlist *kin,
                            struct sync_reserve_list *reserve_list)
{
    struct sync_state sync_state = {
        imapd_userid,
        imapd_userisadmin || imapd_userisproxyadmin,
        imapd_authstate,
        &imapd_namespace,
        imapd_out,
        0 /* local_only */
    };

    /* administrators only please */
    if (!imapd_userisadmin) {
        syslog(LOG_ERR, "SYNCERROR: invalid user %s trying to sync", imapd_userid);
        prot_printf(imapd_out, "%s NO only administrators may use sync commands\r\n", tag);
        return;
    }

    const char *resp = sync_restore(kin, reserve_list, &sync_state);
    index_release(imapd_index);
    sync_checkpoint(imapd_in);
    prot_printf(imapd_out, "%s %s\r\n", tag, resp);

    /* Reset inactivity timer in case we spent a long time processing data */
    prot_resettimeout(imapd_in);
}

static void cmd_xapplepushservice(const char *tag,
                                  struct applepushserviceargs *applepushserviceargs)
{
    int r = 0;
    strarray_t notif_mailboxes = STRARRAY_INITIALIZER;
    int i;
    mbentry_t *mbentry = NULL;

    const char *aps_topic = config_getstring(IMAPOPT_APS_TOPIC);
    if (!aps_topic) {
        syslog(LOG_ERR,
               "aps_topic not configured, can't complete XAPPLEPUSHSERVICE response");
        prot_printf(imapd_out, "%s NO Server configuration error\r\n", tag);
        return;
    }

    if (!buf_len(&applepushserviceargs->aps_account_id)) {
        prot_printf(imapd_out, "%s NO Missing APNS account ID\r\n", tag);
        return;
    }
    if (!buf_len(&applepushserviceargs->aps_device_token)) {
        prot_printf(imapd_out, "%s NO Missing APNS device token\r\n", tag);
        return;
    }
    if (!buf_len(&applepushserviceargs->aps_subtopic)) {
        prot_printf(imapd_out, "%s NO Missing APNS sub-topic\r\n", tag);
        return;
    }

    // v1 is inbox-only, so override the mailbox list
    if (applepushserviceargs->aps_version == 1) {
        strarray_truncate(&applepushserviceargs->mailboxes, 0);
        strarray_push(&applepushserviceargs->mailboxes, "INBOX");
        applepushserviceargs->aps_version = 1;
    }
    else {
        // 2 is the most we support
        applepushserviceargs->aps_version = 2;
    }

    for (i = 0; i < strarray_size(&applepushserviceargs->mailboxes); i++) {
        const char *name = strarray_nth(&applepushserviceargs->mailboxes, i);
        char *intname =
            mboxname_from_external(name, &imapd_namespace, imapd_userid);
        r = mlookup(tag, name, intname, &mbentry);
        if (!r && mbtype_isa(mbentry->mbtype) == MBTYPE_EMAIL) {
            strarray_push(&notif_mailboxes, name);
            if (applepushserviceargs->aps_version >= 2) {
                prot_puts(imapd_out, "* XAPPLEPUSHSERVICE \"mailbox\" ");
                prot_printstring(imapd_out, name);
                prot_puts(imapd_out, "\r\n");
            }
        }
        mboxlist_entry_free(&mbentry);
        free(intname);
    }

    prot_printf(imapd_out,
                "* XAPPLEPUSHSERVICE \"aps-version\" \"%d\" \"aps-topic\" \"%s\"\r\n",
                applepushserviceargs->aps_version, aps_topic);
    prot_printf(imapd_out, "%s OK XAPPLEPUSHSERVICE completed.\r\n", tag);

    struct mboxevent *mboxevent = mboxevent_new(EVENT_APPLEPUSHSERVICE);
    mboxevent_set_applepushservice(mboxevent, applepushserviceargs,
                                   &notif_mailboxes, imapd_userid);
    mboxevent_notify(&mboxevent);
    mboxevent_free(&mboxevent);

    buf_release(&applepushserviceargs->aps_account_id);
    buf_release(&applepushserviceargs->aps_device_token);
    buf_release(&applepushserviceargs->aps_subtopic);
    strarray_fini(&applepushserviceargs->mailboxes);
    strarray_fini(&notif_mailboxes);
}

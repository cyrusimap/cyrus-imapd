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
#include "slowio.h"
#include "statuscache.h"
#include "sync_log.h"
#include "sync_support.h"
#include "telemetry.h"
#include "attachextract.h"
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
#include "xunlink.h"

/* generated headers are not necessarily in current directory */
#include "imap/imap_err.h"

#include "master/service.h"

#include "iostat.h"

extern int optind;
extern char *optarg;

/* global state */
const int config_need_data = CONFIG_NEED_PARTITION_DATA;
static struct proc_handle *proc_handle = NULL;

static int imaps = 0;
static struct saslprops_t saslprops = SASLPROPS_INITIALIZER;
static int auth_is_mboxgroups = 0;
static sasl_ssf_t extprops_ssf = 0;
static int nosaslpasswdcheck = 0;
static int apns_enabled = 0;
static int64_t maxmsgsize = 0;
static int64_t maxargssize = 0;
static uint64_t maxargssize_mark = 0;

static uint32_t client_behavior_mask = 0;

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
static struct conversations_state *global_conversations = NULL;

/* all subscription commands go to the backend server containing the
   user's inbox */
struct backend *backend_inbox = NULL;

/* the current server most commands go to */
struct backend *backend_current = NULL;

/* our cached connections */
ptrarray_t backend_cached = PTRARRAY_INITIALIZER;

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
static int imapd_idle_enabled = 0;
static int imapd_notify_enabled = 0;
static int imapd_login_disabled = 0;
static int imapd_compress_allowed = 0;
static int imapd_utf8_allowed = 0;
static int imapd_starttls_allowed = 0;
static int imapd_starttls_done = 0; /* have we done a successful starttls? */
static int imapd_tls_required = 0; /* is tls required? */
static void *imapd_tls_comp = NULL; /* TLS compression method, if any */
static int imapd_compress_done = 0; /* have we done a successful compress? */
static const char *plaintextloginalert = NULL;
static const char *imapd_jmapaccess_url = NULL;
static int imapd_jmapaccess_enabled = 0;
static int imapd_preview_enabled = 0;
static int ignorequota = 0;
static int sync_sieve_mailbox_enabled = 0;
static int sync_archive_enabled = 0;
static int idle_sock = PROT_NO_FD;

static struct event_groups {
    mailbox_filter_t filters;
    struct {
        unsigned long events;
        unsigned delayed : 1;
        struct fetchargs fetchargs;
    } selected;
    unsigned long inboxes_events;
    unsigned long personal_events;
    unsigned long subscribed_events;
    struct {
        unsigned long events;
        strarray_t mboxes;
    } subtree;
    struct {
        unsigned long events;
        strarray_t mboxes;
    } mailboxes;

} *notify_event_groups = NULL;

#define QUIRK_SEARCHFUZZY (1<<0)
static struct id_data {
    hash_table params;
    int did_id;
    int quirks;
} imapd_id = { HASH_TABLE_INITIALIZER, 0, 0 };

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

    /* from RFC 5465 */
    { MBOX_ATTRIBUTE_NOACCESS,      "\\NoAccess"      },

    { 0, NULL }
};

const struct mbox_name_attribute mbox_name_childinfo[] = {
    /* from RFC 5258 */
    { MBOX_ATTRIBUTE_CHILDINFO_SUBSCRIBED, "SUBSCRIBED" },

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
    strarray_t *special_nochildren;
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

/* CAPABILITIES are defined here */

enum {
    CAPA_PREAUTH     = (1<<0),   /* advertised pre-authentication             */
    CAPA_POSTAUTH    = (1<<1),   /* advertised post-authentication            */
    CAPA_REQD        = (1<<2),   /* required (can't be suppressed)            */
    CAPA_STATE       = (1<<3),   /* depends on a server state variable        */
    CAPA_CONFIG      = (1<<4),   /* depends on an imapd.conf config switch    */
    CAPA_REVERSE     = (1<<5),   /* reverse state/switch logic                */
    CAPA_COMPLEX     = (1<<6),   /* function to print "complex" capability    */
    CAPA_VALUE       = (1<<7),   /* has a formatted value based on config opt */
    CAPA_MULTI       = (1<<8),   /* has multiple string values                */
};

#define CAPA_OMNIAUTH  (CAPA_PREAUTH|CAPA_POSTAUTH)
#define CAPA_REVCONFIG (CAPA_CONFIG|CAPA_REVERSE)

struct capa_struct {
    const char *str;            /* capability name                            */
    int mask;                   /* mask of CAPA_* flags                       */

    /* availability/value(s) optionally based on one of the following:        */
    union {
        int *statep;            /* CAPA_STATE:   ptr to server state variable */
        enum imapopt config;    /* CAPA_CONFIG:  config switch option name    */
        void (*complex)(void);  /* CAPA_COMPLEX: function to print capablity  */

        struct {                /* CAPA_VALUE: prot_printf(fmt, *strp, *i64p) */
            const char *fmt;    /*   format using "%1$s" and/or "%2$" PRIi64  */
            const char **strp;  /*   arg1: optional ptr to string config var
                                     (*strp == NULL means capa is disabled)   */
            int64_t *i64p;      /*   arg2: optional ptr to int64 config var   */
        } value;

        struct {                /* CAPA_MULTI:                                */
            const char **val;   /*   array of string values                   */
            int num;            /*   number of values                         */
        } multi;
    } u;
};

static void capa_auth(void)
{
    const char *sasllist; /* the list of SASL mechanisms */
    int mechcount;

    if (!imapd_tls_required && (!imapd_authstate || saslprops.ssf) &&
        sasl_listmech(imapd_saslconn, NULL, " AUTH=", " AUTH=", "",
                      &sasllist, NULL, &mechcount) == SASL_OK &&
        mechcount > 0) {

        prot_puts(imapd_out, sasllist);
    }
}

static struct capa_struct base_capabilities[] = {
/* required capabilities */
    { "IMAP4rev1",             CAPA_OMNIAUTH|CAPA_REQD, { 0 } }, /* RFC 3501 */
    { "IMAP4rev2",             CAPA_OMNIAUTH|CAPA_REQD, { 0 } }, /* RFC 9051 */

/* this is kept sorted, so that it can be easily compared to
   https://www.iana.org/assignments/imap-capabilities/imap-capabilities.xhtml */
    { "ACL",                   CAPA_POSTAUTH,           { 0 } }, /* RFC 4314 */
    { "ANNOTATE-EXPERIMENT-1", CAPA_POSTAUTH,           { 0 } }, /* RFC 5257 */
    { "APPENDLIMIT=",          CAPA_POSTAUTH|CAPA_VALUE,         /* RFC 7889 */
      { .value = { "%1$s%2$" PRIi64, .i64p = &maxmsgsize } }  },
    { "AUTH=",                 CAPA_OMNIAUTH|CAPA_COMPLEX,       /* RFC 9051 */
      { .complex = &capa_auth }                               },
    { "BINARY",                CAPA_POSTAUTH,           { 0 } }, /* RFC 3516 */
    { "CATENATE",              CAPA_POSTAUTH,           { 0 } }, /* RFC 4469 */
    { "CHILDREN",              CAPA_POSTAUTH,           { 0 } }, /* RFC 3348 */
    { "COMPRESS=DEFLATE",      CAPA_POSTAUTH|CAPA_STATE,         /* RFC 4978 */
      { .statep = &imapd_compress_allowed }                   },
    { "CONDSTORE",             CAPA_POSTAUTH,           { 0 } }, /* RFC 7162 */
    { "CONTEXT=SEARCH",        0, /* not implemented */ { 0 } }, /* RFC 5267 */
    { "CONTEXT=SORT",          0, /* not implemented */ { 0 } }, /* RFC 5267 */
    { "CONVERT",               0, /* not implemented */ { 0 } }, /* RFC 5259 */
    { "CREATE-SPECIAL-USE",    CAPA_POSTAUTH,           { 0 } }, /* RFC 6154 */
    { "ENABLE",                CAPA_OMNIAUTH,           { 0 } }, /* RFC 5161 */
    { "ESEARCH",               CAPA_POSTAUTH,           { 0 } }, /* RFC 4731 */
    { "ESORT",                 CAPA_POSTAUTH,           { 0 } }, /* RFC 5267 */
    { "FILTERS",               0, /* not implemented */ { 0 } }, /* RFC 5466 */
    { "I18NLEVEL=1",           0, /* not implemented */ { 0 } }, /* RFC 5255 */
    { "I18NLEVEL=2",           0, /* not implemented */ { 0 } }, /* RFC 5255 */
    { "ID",                    CAPA_OMNIAUTH,           { 0 } }, /* RFC 2971 */
    { "IDLE",                  CAPA_POSTAUTH|CAPA_STATE,         /* RFC 2177 */
      { .statep = &imapd_idle_enabled }                       },
    { "IMAPSIEVE=",            0, /* not implemented */ { 0 } }, /* RFC 6785 */
    { "INPROGRESS",            CAPA_POSTAUTH,           { 0 } }, /* RFC 9585 */
    { "JMAPACCESS",            CAPA_POSTAUTH|CAPA_STATE,         /* RFC 9698 */
      { .statep = &imapd_jmapaccess_enabled }                 },
    { "LANGUAGE",              0, /* not implemented */ { 0 } }, /* RFC 5255 */
    { "LIST-EXTENDED",         CAPA_POSTAUTH,           { 0 } }, /* RFC 5258 */
    { "LIST-METADATA",         CAPA_POSTAUTH,           { 0 } }, /* RFC 9590 */
    { "LIST-MYRIGHTS",         CAPA_POSTAUTH,           { 0 } }, /* RFC 8440 */
    { "LIST-STATUS",           CAPA_POSTAUTH,           { 0 } }, /* RFC 5819 */
    { "LITERAL+",              CAPA_OMNIAUTH|CAPA_REVCONFIG,     /* RFC 7888 */
      { .config = IMAPOPT_LITERALMINUS }                      },
    { "LITERAL-",              CAPA_OMNIAUTH|CAPA_CONFIG,        /* RFC 7888 */
      { .config = IMAPOPT_LITERALMINUS }                      },
    { "LOGIN-REFERRALS",       0, /* not implemented */ { 0 } }, /* RFC 2221 */
    { "LOGINDISABLED",         CAPA_OMNIAUTH|CAPA_STATE,         /* RFC 9051 */
      { .statep = &imapd_login_disabled }                     },
    { "MAILBOX-REFERRALS",     CAPA_POSTAUTH|CAPA_REVCONFIG,     /* RFC 2193 */
      { .config = IMAPOPT_PROXYD_DISABLE_MAILBOX_REFERRALS }  },
    { "MESSAGELIMIT=",         0, /* not implemented */ { 0 } }, /* RFC 9738 */
    { "METADATA",              CAPA_POSTAUTH,           { 0 } }, /* RFC 5464 */
    { "METADATA-SERVER",       0,/*implied by METADATA*/{ 0 } }, /* RFC 5464 */
    { "MOVE",                  CAPA_POSTAUTH,           { 0 } }, /* RFC 6851 */
    { "MULTIAPPEND",           CAPA_POSTAUTH,           { 0 } }, /* RFC 3502 */
    { "MULTISEARCH",           CAPA_POSTAUTH,           { 0 } }, /* RFC 7377 */
    { "NAMESPACE",             CAPA_POSTAUTH,           { 0 } }, /* RFC 2342 */
    { "NOTIFY",                CAPA_POSTAUTH|CAPA_STATE,         /* RFC 5465 */
      { .statep = &imapd_notify_enabled }                     },
    { "OBJECTID",              CAPA_POSTAUTH,           { 0 } }, /* RFC 8474 */
    { "PARTIAL",               CAPA_POSTAUTH,           { 0 } }, /* RFC 9394 */
    { "PREVIEW",               CAPA_POSTAUTH|CAPA_STATE,         /* RFC 8970 */
      { .statep = &imapd_preview_enabled }                    },
    { "QRESYNC",               CAPA_POSTAUTH,           { 0 } }, /* RFC 7162 */
    { "QUOTA",                 CAPA_POSTAUTH,           { 0 } }, /* RFC 9208 */
    { "QUOTA=RES-",            CAPA_POSTAUTH|CAPA_MULTI,         /* RFC 9208 */
      { .multi = { (const char **) quota_names, QUOTA_NUMRESOURCES } } },
    { "QUOTASET",              CAPA_POSTAUTH,           { 0 } }, /* RFC 9208 */
    { "REPLACE",               CAPA_POSTAUTH,           { 0 } }, /* RFC 8508 */
    { "RIGHTS=kxten",          CAPA_POSTAUTH,           { 0 } }, /* RFC 4314 */
    { "SASL_IR",               CAPA_PREAUTH,            { 0 } }, /* RFC 4959 */
    { "SAVEDATE",              CAPA_POSTAUTH,           { 0 } }, /* RFC 8514 */
    { "SAVELIMIT=",            0, /* not implemented */ { 0 } }, /* RFC 9738 */
    { "SEARCH=FUZZY",          CAPA_POSTAUTH,           { 0 } }, /* RFC 6203 */
    { "SEARCHRES",             CAPA_POSTAUTH,           { 0 } }, /* RFC 5182 */
    { "SORT",                  CAPA_POSTAUTH,           { 0 } }, /* RFC 5256 */
    { "SORT=DISPLAY",          CAPA_POSTAUTH,           { 0 } }, /* RFC 5957 */
    { "SPECIAL-USE",           CAPA_POSTAUTH,           { 0 } }, /* RFC 6154 */
    { "STARTTLS",              CAPA_PREAUTH|CAPA_STATE,          /* RFC 9051 */
      { .statep = &imapd_starttls_allowed }                        },
    { "STATUS=SIZE",           CAPA_POSTAUTH,           { 0 } }, /* RFC 8438 */
    { "THREAD=ORDEREDSUBJECT", CAPA_POSTAUTH,           { 0 } }, /* RFC 5256 */
    { "THREAD=REFERENCES",     CAPA_POSTAUTH,           { 0 } }, /* RFC 5256 */
    { "UIDBATCHES",            CAPA_POSTAUTH,           { 0 } }, /* draft-ietf-mailmaint-imap-uidbatches */
    { "UIDONLY",               CAPA_POSTAUTH,           { 0 } }, /* RFC 9586 */
    { "UIDPLUS",               CAPA_POSTAUTH,           { 0 } }, /* RFC 4315 */
    { "UNAUTHENTICATE",        CAPA_POSTAUTH|CAPA_STATE,         /* RFC 8437 */
      { .statep = &imapd_userisadmin }                        },
    { "UNSELECT",              CAPA_POSTAUTH,           { 0 } }, /* RFC 3691 */
    { "URL-PARTIAL",           CAPA_POSTAUTH,           { 0 } }, /* RFC 5550 */
#ifdef HAVE_SSL
    { "URLAUTH",               CAPA_POSTAUTH,           { 0 } }, /* RFC 4467 */
    { "URLAUTH=BINARY",        CAPA_POSTAUTH,           { 0 } }, /* RFC 5524 */
#endif
    { "UTF8=ACCEPT",           CAPA_POSTAUTH|CAPA_STATE,         /* RFC 6855 */
      { .statep = &imapd_utf8_allowed }                       },
    { "UTF8=ONLY",             0,/*precluded by ACCEPT*/{ 0 } }, /* RFC 6855 */
    { "WITHIN",                CAPA_POSTAUTH,           { 0 } }, /* RFC 5032 */

/* drafts, non-standard (NS), Cyrus custom (CY) */
    { "ANNOTATEMORE",          CAPA_POSTAUTH|CAPA_CONFIG,        /* draft-daboo-imap-annotatemore-08 */
      { .config = IMAPOPT_ANNOTATION_ENABLE_LEGACY_COMMANDS } },
    { "DIGEST=SHA1",           CAPA_POSTAUTH,           { 0 } }, /* CY */
    { "MUPDATE=",              CAPA_OMNIAUTH|CAPA_VALUE,         /* CY */
      { .value = { "mupdate://%1$s/", .strp = &config_mupdate_server } } },
    { "NO_ATOMIC_RENAME",      CAPA_POSTAUTH,           { 0 } }, /* CY */
    { "SORT=MODSEQ",           CAPA_POSTAUTH,           { 0 } }, /* NS */
    { "SORT=UID",              CAPA_POSTAUTH,           { 0 } }, /* NS */
    { "THREAD=REFS",           CAPA_POSTAUTH,           { 0 } }, /* draft-ietf-morg-inthread */
    { "X-CREATEDMODSEQ",       CAPA_POSTAUTH,           { 0 } }, /* CY */
    { "X-REPLICATION",         CAPA_POSTAUTH,           { 0 } }, /* CY */
    { "X-REPLICATION-ARCHIVE", CAPA_POSTAUTH,           { 0 } }, /* CY */
    { "X-SIEVE-MAILBOX",       CAPA_POSTAUTH,           { 0 } }, /* CY */
    { "XAPPLEPUSHSERVICE",     CAPA_OMNIAUTH|CAPA_STATE,         /* NS */
      { .statep = &apns_enabled }                             },
    { "XLIST",                 CAPA_POSTAUTH,           { 0 } }, /* NS */
    { "XUSERGROUPS",           CAPA_POSTAUTH|CAPA_STATE,
      { .statep = &auth_is_mboxgroups }                       }, /* CY */

/* keep this to mark the end of the list */
    { 0,                       0,                       { 0 } }
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
static int  cmd_append(char *tag, char *name, const char *cur_name, int isreplace);
static void cmd_select(char *tag, char *cmd, char *name);
static void cmd_close(char *tag, char *cmd);
static int parse_fetch_args(const char *tag, const char *cmd,
                            unsigned flags,
                            struct fetchargs *fa);
static void fetchargs_fini (struct fetchargs *fa);
static void cmd_fetch(char *tag, char *sequence, int usinguid);
static void cmd_store(char *tag, char *sequence, int usinguid);
static void cmd_search(const char *tag, const char *cmd);
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
static void cmd_rename(char *tag, char *oldname, char *newname, char *partition, int noisy);
static void cmd_raclmodseq(const char *tag, const char *userid);
static void cmd_reconstruct(const char *tag, const char *name, int recursive);
static void getlistargs(char *tag, struct listargs *listargs);
static void cmd_list(char *tag, struct listargs *listargs);
static void cmd_changesub(char *tag, char *namespace, char *name, int add);
static void cmd_changeusergroup(char *tag, char *name, char *group, int add);
static void cmd_getacl(const char *tag, const char *name);
static void cmd_getusergroup(const char *tag, const char *group);
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

static void cmd_xstats(char *tag);

static void cmd_xapplepushservice(const char *tag,
                                  struct applepushserviceargs *applepushserviceargs);

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
static void cmd_replace(char *tag, char *seqno, char *name, int usinguid);
static void cmd_notify(char *tag, int set);
static void push_updates(int idling);

static void cmd_getjmapaccess(char* tag);
static void cmd_uidbatches(char *tag, uint32_t size,
                           uint32_t low, uint32_t high);

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

static int getsortcriteria(char *tag, struct sortcrit **sortcrit);
static int getdatetime(time_t *date);

static void appendfieldlist(struct fieldlist **l, char *section,
                     strarray_t *fields, char *trail,
                     void *d, size_t size);
static void freefieldlist(struct fieldlist *l);

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

void shut_down(int code) __attribute__((noreturn));

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
    { SASL_CB_GETOPT, SASL_CB_PROC_PTR &mysasl_config, NULL },
    { SASL_CB_PROXY_POLICY, SASL_CB_PROC_PTR &imapd_proxy_policy, (void*) &imapd_proxyctx },
    { SASL_CB_CANON_USER, SASL_CB_PROC_PTR &imapd_canon_user, (void*) &disable_referrals },
    { SASL_CB_LOG, SASL_CB_PROC_PTR &imapd_sasl_log, NULL },
    { SASL_CB_LIST_END, NULL, NULL }
};

/* imapd_refer() issues a referral to the client. */
static void imapd_refer(const char *tag,
                        const char *server,
                        const char *mailbox)
{
    struct imapurl imapurl;
    struct buf url = BUF_INITIALIZER;

    memset(&imapurl, 0, sizeof(struct imapurl));
    imapurl.server = server;
    imapurl.mailbox = mailbox;
    imapurl.auth = !strcmp(imapd_userid, "anonymous") ? "anonymous" : "*";

    imapurl_toURL(&url, &imapurl);

    prot_printf(imapd_out, "%s NO [REFERRAL %s] Remote mailbox.\r\n",
                tag, buf_cstring(&url));

    free(imapurl.freeme);
    buf_free(&url);
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

static void event_groups_free(struct event_groups **groups)
{
    if (!groups || !*groups) return;

    fetchargs_fini(&(*groups)->selected.fetchargs);
    strarray_fini(&(*groups)->subtree.mboxes);
    strarray_fini(&(*groups)->mailboxes.mboxes);
    xzfree(*groups);
}

/* Registry of exhibited client behaviors */
static const struct client_behavior {
    uint32_t flag;
    const char *name;
} client_behavior_registry[] = {
    { CB_ANNOTATE,    "annotate"    },
    { CB_BINARY,      "binary"      },
    { CB_CATENATE,    "catenate"    },
    { CB_COMPRESS,    "compress"    },
    { CB_CONDSTORE,   "condstore"   },
    { CB_IDLE,        "idle"        },
    { CB_IMAP4REV2,   "imap4rev2"   },
    { CB_METADATA,    "metadata"    },
    { CB_MOVE,        "move"        },
    { CB_MULTISEARCH, "multisearch" },
    { CB_NOTIFY,      "notify"      },
    { CB_OBJECTID,    "objectid"    },
    { CB_PARTIAL,     "partial"     },
    { CB_PREVIEW,     "preview"     },
    { CB_QRESYNC,     "qresync"     },
    { CB_REPLACE,     "replace"     },
    { CB_SAVEDATE,    "savedate"    },
    { CB_SEARCHRES,   "searchres"   },
    { CB_UIDBATCHES,  "uidbatches"  },
    { CB_UIDONLY,     "uidonly"     },
    { CB_UNSELECT,    "unselect"    },
    { CB_UTF8ACCEPT,  "utf8_accept" },
    { CB_XLIST,       "xlist"       },
    { 0,              NULL          }
};

static void imapd_log_client_behavior(void)
{
    static struct buf buf  = BUF_INITIALIZER;
    const char *id_name    = hash_lookup("name", &imapd_id.params);
    const char *id_vendor  = hash_lookup("vendor", &imapd_id.params);
    const char *id_version = hash_lookup("version", &imapd_id.params);

    /* log the client behaviors
     *
     * We only log the hits, not the misses, which should mean that the logs 
     * are a bit easier to skim and a bit smaller.
     */
    const struct client_behavior *cb;
    for (cb = client_behavior_registry; cb->flag; cb++) {
        if (client_behavior_mask & cb->flag) {
            buf_printf(&buf, " %s=<1>", cb->name);
        }
    }

    xsyslog(LOG_NOTICE, "session ended",
                        "sessionid=<%s> userid=<%s>"
                        " id.vendor=<%s> id.name=<%s> id.version=<%s>"
                        "%s",

                        session_id(),
                        imapd_userid ? imapd_userid : "",
                        id_vendor    ? id_vendor    : "",
                        id_name      ? id_name      : "",
                        id_version   ? id_version   : "",
                        buf_cstring(&buf));
    buf_reset(&buf);
}

static void maybe_autoexpunge(void)
{
    if (config_getswitch(IMAPOPT_REPLICAONLY)) return;
    if (!config_getswitch(IMAPOPT_AUTOEXPUNGE)) return;
    if (!index_hasrights(imapd_index, ACL_EXPUNGE)) return;
    index_expunge(imapd_index, NULL, 1);
}

static void imapd_reset(void)
{
    int i;
    uint64_t bytes_in = 0;
    uint64_t bytes_out = 0;

    /* run delayed commands first before closing anything */
    libcyrus_run_delayed();

    /* log the client behaviors */
    imapd_log_client_behavior();
    client_behavior_mask = 0;

    proc_cleanup(&proc_handle);

    /* close backend connections */
    for (i = 0; i < ptrarray_size(&backend_cached); i++) {
        struct backend *be = ptrarray_nth(&backend_cached, i);
        proxy_downserver(be);
        if (be->last_result.s) {
            free(be->last_result.s);
        }
        mboxlist_entry_free((mbentry_t **) &be->context);
        free(be);
    }
    ptrarray_fini(&backend_cached);
    backend_inbox = backend_current = NULL;
    if (mupdate_h) mupdate_disconnect(&mupdate_h);
    mupdate_h = NULL;
    proxy_cmdcnt = 0;
    disable_referrals = 0;
    supports_referrals = 0;

    attachextract_destroy();

    event_groups_free(&notify_event_groups);
    if (idle_sock != PROT_NO_FD)
        idle_stop(FILTER_NONE);

    if (imapd_index) {
        maybe_autoexpunge();
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
        syslog(LOG_NOTICE, "auditlog: traffic sessionid=<%s>"
               " bytes_in=<%" PRIu64 "> bytes_out=<%" PRIu64 ">",
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
    imapd_starttls_allowed = tls_starttls_enabled();
#ifdef HAVE_ZLIB
    imapd_compress_allowed = 1;
#endif
    plaintextloginalert = NULL;

    saslprops_reset(&saslprops);

    clear_id();

    slowio_reset();
}

/*
 * run once when process is forked;
 * MUST NOT exit directly; must return with non-zero error code
 */
int service_init(int argc, char **argv, char **envp)
{
    int opt, events;

    if (geteuid() == 0) fatal("must run as the Cyrus user", EX_USAGE);
    proc_settitle_init(argc, argv, envp);

    /* set signal handlers */
    signals_set_shutdown(&shut_down);
    signal(SIGPIPE, SIG_IGN);

    /* load the SASL plugins */
    global_sasl_init(1, 1, mysasl_cb);

    imapd_starttls_allowed = tls_starttls_enabled();
#ifdef HAVE_ZLIB
    imapd_compress_allowed = 1;
#endif

    imapd_jmapaccess_url = config_getstring(IMAPOPT_JMAPACCESS_URL);
    imapd_jmapaccess_enabled = !!imapd_jmapaccess_url;

    const char *annot = config_getstring(IMAPOPT_JMAP_PREVIEW_ANNOT);
    imapd_preview_enabled = !strncmpsafe(annot, "/shared/", 8);

    /* setup for sending IMAP IDLE/NOTIFY notifications */
    if ((imapd_idle_enabled = idle_enabled())) {
        idle_sock = idle_init();
        if (idle_sock != PROT_NO_FD) imapd_notify_enabled = 1;
    }

    /* setup for mailbox event notifications */
    events = mboxevent_init();
    apns_enabled =
      (events & EVENT_APPLEPUSHSERVICE) && config_getstring(IMAPOPT_APS_TOPIC);
    auth_is_mboxgroups = !strcmp(config_getstring(IMAPOPT_AUTH_MECH), "mboxgroups");

    while ((opt = getopt(argc, argv, "HNp:sq")) != EOF) {
        switch (opt) {
        case 'H': /* expect HAProxy protocol header */
            haproxy_protocol = 1;
            break;
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

    maxmsgsize = config_getbytesize(IMAPOPT_MAXMESSAGESIZE, 'B');
    if (maxmsgsize <= 0) maxmsgsize = BYTESIZE_UNLIMITED;

    maxargssize = config_getbytesize(IMAPOPT_MAXARGSSIZE, 'B');
    if (maxargssize <= 0) maxargssize = BYTESIZE_UNLIMITED;

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
    int r;

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

    /* Allow LITERAL+ */
    prot_setisclient(imapd_in, 1);

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

    imapd_utf8_allowed = !(config_getswitch(IMAPOPT_REJECT8BIT) ||
                           config_getswitch(IMAPOPT_MUNGE8BIT));

    imapd_tls_required = config_getswitch(IMAPOPT_TLS_REQUIRED);
    imapd_login_disabled = imapd_tls_required ||
        ((extprops_ssf < 2) && !config_getswitch(IMAPOPT_ALLOWPLAINTEXT));

    r = proc_register(&proc_handle, 0,
                      config_ident, imapd_clienthost, NULL, NULL, NULL);
    if (r) fatal("unable to register process", EX_IOERR);
    proc_settitle(config_ident, imapd_clienthost, NULL, NULL, NULL);

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
    mboxname_init_namespace(&imapd_namespace, NAMESPACE_OPTION_ADMIN);
    mboxevent_setnamespace(&imapd_namespace);

    attachextract_init(imapd_in);

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
void shut_down(int code)
{
    int i;
    uint64_t bytes_in = 0;
    uint64_t bytes_out = 0;

    in_shutdown = 1;

    /* run delayed commands before we take away all the environment */
    libcyrus_run_delayed();

    proc_cleanup(&proc_handle);

    for (i = 0; i < ptrarray_size(&backend_cached); i++) {
        struct backend *be = ptrarray_nth(&backend_cached, i);
        proxy_downserver(be);
        if (be->last_result.s) {
            free(be->last_result.s);
        }
        mboxlist_entry_free((mbentry_t **) &be->context);
        free(be);
    }
    ptrarray_fini(&backend_cached);
    if (mupdate_h) mupdate_disconnect(&mupdate_h);

    attachextract_destroy();

    event_groups_free(&notify_event_groups);
    if (idle_sock != PROT_NO_FD)
        idle_stop(FILTER_NONE);

    if (imapd_index) {
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
        syslog(LOG_NOTICE, "auditlog: traffic sessionid=<%s>"
               " bytes_in=<%" PRIu64 "> bytes_out=<%" PRIu64 ">",
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
        proc_cleanup(&proc_handle);
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
        prot_printf(imapd_out, "* BYE %s%s\r\n",
                    *s == '[' /* resp-text-code */ ? "" : "Fatal error: ", s);
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

    if (code != EX_PROTOCOL && config_fatals_abort) abort();

    shut_down(code);
}

/*
 * Check the currently selected mailbox for updates.
 *
 * 'be' is the backend (if any) that we just proxied a command to.
 */
static void imapd_check(struct backend *be, unsigned tell_flags)
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
        if (notify_event_groups &&
            !(notify_event_groups->selected.events & IMAP_NOTIFY_FLAG_CHANGE))
            tell_flags |= TELL_SILENT;

        index_check(imapd_index, tell_flags);
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
    int syntax_errors = 0;
    const int syntax_errors_limit = 10; /* XXX make this configurable? */
    unsigned command_count = 0;

    prot_printf(imapd_out, "* OK [CAPABILITY");
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
        int r;

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
        r = proc_register(&proc_handle, 0,
                          config_ident, imapd_clienthost, imapd_userid,
                          index_mboxname(imapd_index), NULL);
        if (r) fatal("unable to register process", EX_IOERR);
        proc_settitle(config_ident, imapd_clienthost, imapd_userid,
                      index_mboxname(imapd_index), NULL);

        /* run any delayed cleanup while a user isn't waiting on a reply */
        libcyrus_run_delayed();

        /* Check for shutdown file */
        if ( !imapd_userisadmin && imapd_userid &&
             (shutdown_file(shut, sizeof(shut)) ||
              userdeny(imapd_userid, config_ident, shut, sizeof(shut)))) {
            for (p = shut; *p == '['; p++); /* can't have [ be first char */
            prot_printf(imapd_out, "* BYE [ALERT] %s\r\n", p);
            telemetry_rusage(imapd_userid);
            shut_down(0);
        }

        /* ensure group information is fresh */
        auth_refresh(imapd_authstate);

        signals_poll();

        if (!prot_error(imapd_in)) {
            int r, idle_fd = PROT_NO_FD, idle_fd_flag = 0;

            if ((notify_event_groups && notify_event_groups->filters) ||
                (!notify_event_groups && (client_capa & CAPA_IMAP4REV2))) {
                idle_fd = idle_sock;
            }

            r = proxy_check_input(protin, imapd_in, imapd_out,
                                  backend_current ? backend_current->in : NULL,
                                  NULL, idle_fd, &idle_fd_flag, 0);

            if (idle_fd_flag) {
                push_updates(0);
            }

            if (!r) {
                /* No input from client */
                continue;
            }
        }

        /* too many consecutive syntax errors? probably not speaking IMAP, see
         * ya! reduces surface area for cross-protocol attacks such as ALPACA
         */
        if (syntax_errors >= syntax_errors_limit) {
            prot_printf(imapd_out, "* BYE This is an IMAP server\r\n");
            goto done;
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
        if (c != ' ' || !imparse_istag(tag.s, command_count)) {
            if (command_count) {
                syntax_errors ++;
                prot_printf(imapd_out, "* BAD Invalid tag\r\n");
                eatline(imapd_in, c);
                continue;
            }
            else {
                /* bad tag on very first command? probably not speaking IMAP */
                prot_printf(imapd_out, "* BYE This is an IMAP server\r\n");
                goto done;
            }
        }

        /* Parse command name */
        c = getword(imapd_in, &cmd);
        if (!cmd.s[0]) {
            syntax_errors ++;
            prot_printf(imapd_out, "%s BAD Null command\r\n", tag.s);
            eatline(imapd_in, c);
            continue;
        }
        lcase(cmd.s);
        xstrncpy(cmdname, cmd.s, 99);
        cmd.s[0] = toupper((unsigned char) cmd.s[0]);

        /* that looks like a command, count it (but saturate, not overflow) */
        if (command_count != UINT_MAX)
            command_count ++;

        if (config_getswitch(IMAPOPT_CHATTY))
            syslog(LOG_NOTICE, "command: %s %s", tag.s, cmd.s);

        r = proc_register(&proc_handle, 0,
                          config_ident, imapd_clienthost, imapd_userid,
                          index_mboxname(imapd_index), cmd.s);
        if (r) fatal("unable to register process", EX_IOERR);
        proc_settitle(config_ident, imapd_clienthost, imapd_userid,
                      index_mboxname(imapd_index), cmd.s);

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

        /* Set limit on the total number of bytes allowed for arguments */
        maxargssize_mark = prot_bytes_in(imapd_in) + maxargssize;

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

                cmd_append(tag.s, arg1.s, NULL, 0/*isreplace*/);

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
                if (client_capa & CAPA_UIDONLY) goto uidonly;
                usinguid = 0;
                if (c != ' ') goto missingargs;
            copy:
                c = getword(imapd_in, &arg1);
                if (c == '\r') goto missingargs;
                /* Allow RFC 5182 search result variable or explicit sequence */
                if (c != ' ' || (strcmp("$", arg1.s) && !imparse_issequence(arg1.s)))
                    goto badsequence;
                c = getastring(imapd_in, imapd_out, &arg2);
                if (c <= EOF) goto missingargs;
                if (!IS_EOL(c, imapd_in)) goto extraargs;

                cmd_copy(tag.s, arg1.s, arg2.s, usinguid, /*ismove*/0);

                prometheus_increment(CYRUS_IMAP_COPY_TOTAL);
            }
            else if (!strcmp(cmd.s, "Create")) {
                if (readonly) goto noreadonly;
                struct dlist *extargs = NULL;

                if (c != ' ') goto missingargs;
                c = getastring(imapd_in, imapd_out, &arg1);
                if (c <= EOF) goto missingargs;
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
                if (c <= EOF) goto missingargs;
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
                if (c <= EOF) goto missingargs;
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
            else if (!strcmp(cmd.s, "Esearch")) {
                if (c != ' ') goto missingargs;

                cmd_search(tag.s, cmd.s);

                prometheus_increment(CYRUS_IMAP_ESEARCH_TOTAL);
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
                if (c <= EOF) goto missingargs;
                prot_ungetc(c, imapd_in);

                cmd_select(tag.s, cmd.s, arg1.s);

                prometheus_increment(CYRUS_IMAP_EXAMINE_TOTAL);
            }
            else goto badcmd;
            break;

        case 'F':
            if (!strcmp(cmd.s, "Fetch")) {
                if (!imapd_index && !backend_current) goto nomailbox;
                if (client_capa & CAPA_UIDONLY) goto uidonly;
                usinguid = 0;
                if (c != ' ') goto missingargs;
            fetch:
                c = getword(imapd_in, &arg1);
                if (c == '\r') goto missingargs;
                /* Allow RFC 5182 search result variable or explicit sequence */
                if (c != ' ' || (strcmp("$", arg1.s) && !imparse_issequence(arg1.s)))
                    goto badsequence;

                cmd_fetch(tag.s, arg1.s, usinguid);

                prometheus_increment(CYRUS_IMAP_FETCH_TOTAL);
            }
            else goto badcmd;
            break;

        case 'G':
            if (!strcmp(cmd.s, "Getacl")) {
                if (c != ' ') goto missingargs;
                c = getastring(imapd_in, imapd_out, &arg1);
                if (c <= EOF) goto missingargs;
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
            else if (imapd_jmapaccess_enabled && !strcmp(cmd.s, "Getjmapaccess")) {
                if (!IS_EOL(c, imapd_in)) goto extraargs;
                cmd_getjmapaccess(tag.s);

                prometheus_increment(CYRUS_IMAP_GETJMAPACCESS_TOTAL);
            }
            else if (!strcmp(cmd.s, "Getmetadata")) {
                if (c != ' ') goto missingargs;

                cmd_getmetadata(tag.s);

                prometheus_increment(CYRUS_IMAP_GETMETADATA_TOTAL);
            }
            else if (!strcmp(cmd.s, "Getquota")) {
                if (c != ' ') goto missingargs;
                c = getastring(imapd_in, imapd_out, &arg1);
                if (c <= EOF) goto missingargs;
                if (!IS_EOL(c, imapd_in)) goto extraargs;
                cmd_getquota(tag.s, arg1.s);

                prometheus_increment(CYRUS_IMAP_GETQUOTA_TOTAL);
            }
            else if (!strcmp(cmd.s, "Getusergroup")) {
                if (!imapd_userisadmin) goto adminsonly;
                if (c != ' ') goto missingargs;
                c = getastring(imapd_in, imapd_out, &arg1);
                if (c == EOF) goto missingargs;
                if (!IS_EOL(c, imapd_in)) goto extraargs;
                cmd_getusergroup(tag.s, arg1.s);
            }
            else if (!strcmp(cmd.s, "Getquotaroot")) {
                if (c != ' ') goto missingargs;
                c = getastring(imapd_in, imapd_out, &arg1);
                if (c <= EOF) goto missingargs;
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
            else if (!strcmp(cmd.s, "Idle") && imapd_idle_enabled) {
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

                cmd_append(tag.s, arg1.s, *arg2.s ? arg2.s : NULL, 0/*isreplace*/);

                prometheus_increment(CYRUS_IMAP_APPEND_TOTAL);
            }
            else if (!strcmp(cmd.s, "Localcreate")) {
                if (readonly) goto noreadonly;
                /* create a local-only mailbox */
                struct dlist *extargs = NULL;

                if (c != ' ') goto missingargs;
                c = getastring(imapd_in, imapd_out, &arg1);
                if (c <= EOF) goto missingargs;
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
                if (c <= EOF) goto missingargs;
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
                if (c <= EOF) goto missingargs;
                if (!IS_EOL(c, imapd_in)) goto extraargs;
                cmd_myrights(tag.s, arg1.s);

                prometheus_increment(CYRUS_IMAP_MYRIGHTS_TOTAL);
            }
            else if (!strcmp(cmd.s, "Mupdatepush")) {
                if (readonly) goto noreadonly;
                if (c != ' ') goto missingargs;
                c = getastring(imapd_in, imapd_out, &arg1);
                if(c <= EOF) goto missingargs;
                if (!IS_EOL(c, imapd_in)) goto extraargs;
                cmd_mupdatepush(tag.s, arg1.s);

                prometheus_increment(CYRUS_IMAP_MUPDATEPUSH_TOTAL);
            }
            else if (!strcmp(cmd.s, "Move")) {
                if (readonly) goto noreadonly;
                if (!imapd_index && !backend_current) goto nomailbox;
                if (client_capa & CAPA_UIDONLY) goto uidonly;
                usinguid = 0;
                if (c != ' ') goto missingargs;
            move:
                c = getword(imapd_in, &arg1);
                if (c == '\r') goto missingargs;
                /* Allow RFC 5182 search result variable or explicit sequence */
                if (c != ' ' || (strcmp("$", arg1.s) && !imparse_issequence(arg1.s)))
                    goto badsequence;
                c = getastring(imapd_in, imapd_out, &arg2);
                if (c <= EOF) goto missingargs;
                if (!IS_EOL(c, imapd_in)) goto extraargs;

                cmd_copy(tag.s, arg1.s, arg2.s, usinguid, /*ismove*/1);

                prometheus_increment(CYRUS_IMAP_MOVE_TOTAL);
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
            else if (!strcmp(cmd.s, "Notify")) {
                int set = 0;

                if (c != ' ') goto missingargs;
                c = getword(imapd_in, &arg1);
                if (c == EOF) goto missingargs;
                if (!strcasecmp(arg1.s, "NONE")) {
                    if (!IS_EOL(c, imapd_in)) goto extraargs;
                }
                else if (!strcasecmp(arg1.s, "SET")) {
                    if (c != ' ') goto missingargs;
                    set = 1;
                }
                else {
                    prot_printf(imapd_out,
                                "%s BAD Unrecognized NOTIFY action\r\n", tag.s);
                    eatline(imapd_in, c);
                    continue;
                }

                cmd_notify(tag.s, set);

                /* XXX prometheus_increment(CYRUS_IMAP_NOTIFY_TOTAL); */
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
                if (c <= EOF) goto missingargs;
                if (c == ' ') {
                    havepartition = 1;
                    c = getword(imapd_in, &arg3);
                    if (!imparse_isatom(arg3.s)) goto badpartition;
                }
                if (!IS_EOL(c, imapd_in)) goto extraargs;
                cmd_rename(tag.s, arg1.s, arg2.s, havepartition ? arg3.s : 0, /*noisy*/0);

                /* XXX prometheus_increment(CYRUS_IMAP_RENAME_TOTAL); */
            } else if(!strcmp(cmd.s, "Raclmodseq")) {
                if (readonly) goto noreadonly;
                if (c != ' ') goto missingargs;
                c = getastring(imapd_in, imapd_out, &arg1);
                if (!IS_EOL(c, imapd_in)) goto extraargs;
                cmd_raclmodseq(tag.s, arg1.s);

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
            else if (!strcmp(cmd.s, "Replace")) {
                if (readonly) goto noreadonly;
                if (!imapd_index && !backend_current) goto nomailbox;
                usinguid = 0;
                if (c != ' ') goto missingargs;
            replace:
                c = getword(imapd_in, &arg1);
                if (c == '\r') goto missingargs;
                if (c != ' ' || !imparse_isnumber(arg1.s))
                    goto badsequence;
                c = getastring(imapd_in, imapd_out, &arg2);
                if (c != ' ') goto missingargs;

                cmd_replace(tag.s, arg1.s, arg2.s, usinguid);

                prometheus_increment(CYRUS_IMAP_REPLACE_TOTAL);
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
                    if (c <= EOF) goto missingargs;
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
                if (!imapd_starttls_allowed) {
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

                /* reset command count, the real imap session starts here */
                command_count = 0;

                prometheus_increment(CYRUS_IMAP_STARTTLS_TOTAL);
                continue;
            }
            if (!imapd_userid) {
                goto nologin;
            } else if (!strcmp(cmd.s, "Store")) {
                if (readonly) goto noreadonly;
                if (!imapd_index && !backend_current) goto nomailbox;
                if (client_capa & CAPA_UIDONLY) goto uidonly;
                usinguid = 0;
                if (c != ' ') goto missingargs;
            store:
                c = getword(imapd_in, &arg1);
                /* Allow RFC 5182 search result variable or explicit sequence */
                if (c != ' ' || (strcmp("$", arg1.s) && !imparse_issequence(arg1.s)))
                    goto badsequence;

                cmd_store(tag.s, arg1.s, usinguid);

                prometheus_increment(CYRUS_IMAP_STORE_TOTAL);
            }
            else if (!strcmp(cmd.s, "Select")) {
                if (c != ' ') goto missingargs;
                c = getastring(imapd_in, imapd_out, &arg1);
                if (c <= EOF) goto missingargs;
                prot_ungetc(c, imapd_in);

                cmd_select(tag.s, cmd.s, arg1.s);

                prometheus_increment(CYRUS_IMAP_SELECT_TOTAL);
            }
            else if (!strcmp(cmd.s, "Search")) {
                if (!imapd_index && !backend_current) goto nomailbox;
                if (client_capa & CAPA_UIDONLY) goto uidonly;
                if (c != ' ') goto missingargs;
            search:

                cmd_search(tag.s, cmd.s);

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
                if (c <= EOF) goto missingargs;
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
                if (c <= EOF) goto missingargs;
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
            else if (!strcmp(cmd.s, "Setusergroup")) {
                if (!imapd_userisadmin) goto adminsonly;
                if (readonly) goto noreadonly;
                if (c != ' ') goto missingargs;
                c = getastring(imapd_in, imapd_out, &arg1);
                if (c != ' ') goto missingargs;
                c = getastring(imapd_in, imapd_out, &arg2);
                if (!IS_EOL(c, imapd_in)) goto extraargs;

                cmd_changeusergroup(tag.s, arg1.s, arg2.s, 1);
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
                if (client_capa & CAPA_UIDONLY) goto uidonly;
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
            else if (!strcmp(cmd.s, "Syncapply")) {
                if (!imapd_userisadmin) goto adminsonly;

                struct dlist *kl = sync_parseline(imapd_in, sync_archive_enabled);

                if (kl) {
                    cmd_syncapply(tag.s, kl, reserve_list);
                    dlist_free(&kl);
                }
                else goto badrepl;
            }
            else if (!strcmp(cmd.s, "Syncget")) {
                if (!imapd_userisadmin) goto adminsonly;

                struct dlist *kl = sync_parseline(imapd_in, sync_archive_enabled);

                if (kl) {
                    cmd_syncget(tag.s, kl);
                    dlist_free(&kl);
                }
                else goto badrepl;
            }
            else if (!strcmp(cmd.s, "Syncrestart")) {
                if (!imapd_userisadmin) goto adminsonly;

                if (!IS_EOL(c, imapd_in)) goto extraargs;

                /* just clear the GUID cache */
                cmd_syncrestart(tag.s, &reserve_list, 1);
            }
            else if (!strcmp(cmd.s, "Syncrestore")) {
                if (!imapd_userisadmin) goto adminsonly;

                struct dlist *kl = sync_parseline(imapd_in, sync_archive_enabled);

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
                if (client_capa & CAPA_UIDONLY) goto uidonly;
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
                else if (!strcmp(arg1.s, "replace")) {
                    if (readonly) goto noreadonly;
                    goto replace;
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
            else if (!strcmp(cmd.s, "Uidbatches")) {
                uint32_t size, low = 1, high = UINT32_MAX;

                if (!imapd_index && !backend_current) goto nomailbox;

                if (c != ' ') goto missingargs;
                c = getuint32(imapd_in, &size);
                if (c <= EOF) goto missingargs;
                if (c == ' ' &&
                    /* Per Section 3.1.5:
                     * Servers MUST reject batch ranges that are in the wrong
                     * order with BAD and response code CLIENTBUG.
                     */
                    ((c = getuint32(imapd_in, &low)) != ':' ||
                     (c = getuint32(imapd_in, &high)) <= EOF ||
                     low > high)) {
                    prot_printf(imapd_out,
                                "%s BAD [CLIENTBUG] Invalid batch range\r\n",
                                tag.s);
                    eatline(imapd_in, c);
                    continue;
                }
                if (!IS_EOL(c, imapd_in)) goto extraargs;

                cmd_uidbatches(tag.s, size, low, high);

                prometheus_increment(CYRUS_IMAP_UIDBATCHES_TOTAL);
            }
            else if (!strcmp(cmd.s, "Unauthenticate")) {
                if (!imapd_userisadmin) goto adminsonly;

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
                if (c <= EOF) goto missingargs;
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
            else if (!strcmp(cmd.s, "Unsetusergroup")) {
                if (!imapd_userisadmin) goto adminsonly;
                if (readonly) goto noreadonly;
                if (c != ' ') goto missingargs;
                c = getastring(imapd_in, imapd_out, &arg1);
                if (c != ' ') goto missingargs;
                c = getastring(imapd_in, imapd_out, &arg2);
                if (!IS_EOL(c, imapd_in)) goto extraargs;

                cmd_changeusergroup(tag.s, arg1.s, arg2.s, 0);
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
            if (!strcmp(cmd.s, "Xfer")) {
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
            else if (!strcmp(cmd.s, "Xrename")) {
                if (readonly) goto noreadonly;
                havepartition = 0;
                if (c != ' ') goto missingargs;
                c = getastring(imapd_in, imapd_out, &arg1);
                if (c != ' ') goto missingargs;
                c = getastring(imapd_in, imapd_out, &arg2);
                if (c <= EOF) goto missingargs;
                if (c == ' ') {
                    havepartition = 1;
                    c = getword(imapd_in, &arg3);
                    if (!imparse_isatom(arg3.s)) goto badpartition;
                }
                if (!IS_EOL(c, imapd_in)) goto extraargs;
                cmd_rename(tag.s, arg1.s, arg2.s, havepartition ? arg3.s : 0, /*noisy*/1);
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
                if (c <= EOF) goto missingargs;
                if (!IS_EOL(c, imapd_in)) goto extraargs;
                cmd_xmeid(tag.s, arg1.s);
            }

            else if (apns_enabled && !strcmp(cmd.s, "Xapplepushservice")) {
                if (c != ' ') goto missingargs;

                memset(&applepushserviceargs, 0, sizeof(struct applepushserviceargs));

                do {
                    c = getastring(imapd_in, imapd_out, &arg1);
                    if (c <= EOF) goto aps_missingargs;

                    if (!strcmp(arg1.s, "mailboxes")) {
                        c = prot_getc(imapd_in);
                        if (c != '(')
                            goto aps_missingargs;

                        c = prot_getc(imapd_in);
                        if (c != ')') {
                            prot_ungetc(c, imapd_in);
                            do {
                                c = getastring(imapd_in, imapd_out, &arg2);
                                if (c <= EOF) break;
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
            syntax_errors ++;
            prot_printf(imapd_out, "%s BAD Unrecognized command\r\n", tag.s);
            eatline(imapd_in, c);
            continue;
        }

        /* End command timer - don't log "idle" commands */
        if (commandmintimer && strcmp("idle", cmdname)) {
            double cmdtime, nettime;
            const char *mboxname = index_mboxname(imapd_index);
            cmdtime_endtimer(&cmdtime, &nettime);
            if (cmdtime >= commandmintimerd) {
                xsyslog(LOG_NOTICE, "cmdtimer",
                                    "sessionid=<%s> userid=<%s> command=<%s>"
                                    " mailbox=<%s> cmdtime=<%f> nettime=<%f>"
                                    " total=<%f>",
                                    session_id(),
                                    imapd_userid ? imapd_userid : "",
                                    cmdname,
                                    mboxname ? mboxname : "",
                                    cmdtime, nettime, cmdtime + nettime);
            }
        }

        /* basic syntax validated okay, reset consecutive error counter */
        syntax_errors = 0;
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
        if (c == IMAP_LITERAL_TOO_LARGE) goto maxliteral;

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
        if (c == IMAP_LITERAL_TOO_LARGE) goto maxliteral;

        prot_printf(imapd_out,
                    "%s BAD Unexpected extra arguments to %s\r\n", tag.s, cmd.s);
        eatline(imapd_in, c);
        continue;

    maxliteral:
        prot_printf(imapd_out, "%s NO %s in %s\r\n",
                    tag.s, error_message(IMAP_LITERAL_TOO_LARGE), cmd.s);
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

    uidonly:
        prot_printf(imapd_out,
                    "%s BAD [UIDREQUIRED] Message numbers are not allowed in %s"
                    " after UIDONLY is enabled\r\n", tag.s, cmd.s);
        eatline(imapd_in, c);
        continue;

    adminsonly:
        /* administrators only please */
        syslog(LOG_ERR, "Unauthorized user %s trying to use %s command",
               imapd_userid, cmd.s);
        prot_printf(imapd_out,
                    "%s NO only administrators may use %s command\r\n",
                    tag.s, cmd.s);
        eatline(imapd_in, c);
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

    if (config_getbytesize(IMAPOPT_AUTOCREATE_QUOTA, 'K') >= 0) {
        char *inboxname = mboxname_user_mbox(imapd_userid, NULL);
        int r = mboxlist_lookup(inboxname, NULL, NULL);
        free(inboxname);
        if (r != IMAP_MAILBOX_NONEXISTENT) return;
        autocreate_user(&imapd_namespace, imapd_userid);
    }
}
#endif // USE_AUTOCREATE

static void authentication_success(const char *tag, int ssf, const char *reply)
{
    int r;
    struct mboxevent *mboxevent;

    imapd_login_disabled = 1;

    /* authstate already created by mysasl_proxy_policy() */
    imapd_userisadmin = global_authisa(imapd_authstate, IMAPOPT_ADMINS);

    prot_printf(imapd_out, "%s OK", tag);
    if (!ssf) {
        prot_puts(imapd_out, " [CAPABILITY");
        capa_response(CAPA_PREAUTH|CAPA_POSTAUTH);
        prot_puts(imapd_out, "]");
    }
    prot_printf(imapd_out, " %s\r\n", reply);

    /* Create telemetry log */
    imapd_logfd = telemetry_log(imapd_userid, imapd_in, imapd_out, 0);

    /* Set namespace */
    unsigned options =
        (imapd_userisadmin || imapd_userisproxyadmin) ? NAMESPACE_OPTION_ADMIN : 0;
    r = mboxname_init_namespace(&imapd_namespace, options);

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

    limits.servicename = config_ident;
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
        if (c == IMAP_LITERAL_TOO_LARGE) {
            prot_printf(imapd_out, "%s NO %s in LOGIN\r\n", tag, error_message(c));
        } else {
            prot_printf(imapd_out,
                        "%s BAD Unexpected extra arguments to LOGIN\r\n",
                        tag);
            eatline(imapd_in, c);
        }
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

    authentication_success(tag, 0, replybuf);
}

/*
 * Perform an AUTHENTICATE command
 */
static void cmd_authenticate(char *tag, char *authtype, char *resp)
{
    char replybuf[MAX_MAILBOX_BUFFER];
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

    prot_setsasl(imapd_in,  imapd_saslconn);
    prot_setsasl(imapd_out, imapd_saslconn);

    snprintf(replybuf, sizeof(replybuf),
             "Success (%s) SESSIONID=<%s>", ssfmsg, session_id());

    authentication_success(tag, saslprops.ssf, replybuf);
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
        maybe_autoexpunge();
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
    sync_sieve_mailbox_enabled = 0;
    sync_archive_enabled = 0;

    /* Send response
       (MUST be done with current SASL and/or commpression layer still active) */
    prot_printf(imapd_out, "%s OK [CAPABILITY", tag);
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

    imapd_check(NULL, TELL_EXPUNGED);

    prot_printf(imapd_out, "%s OK %s\r\n", tag,
                error_message(IMAP_OK_COMPLETED));
}

static void clear_id() {
    free_hash_table(&imapd_id.params, &free);
    memset(&imapd_id, 0, sizeof(struct id_data));
    construct_hash_table(&imapd_id.params, 32, 1);
}

static void log_id_param(const char *key, void *data, void *rock)
{
    struct buf *logbuf = (struct buf *) rock;
    const char *val = (const char *) data;

    /* should we check for and format literals here ??? */
    buf_printf(logbuf, " \"%s\" ", key);
    if (!val || !strcmp(val, "NIL"))
        buf_printf(logbuf, "NIL");
    else
        buf_printf(logbuf, "\"%s\"", val);
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
            if (c != ' ' ||
                /* get field value */
                (c = getnstring(imapd_in, imapd_out, &arg)) == EOF ||
                (c != ' ' && c != ')')) {
                if (c == IMAP_LITERAL_TOO_LARGE) {
                    prot_printf(imapd_out, "%s NO %s in Id\r\n",
                                tag, error_message(c));
                }
                else {
                    prot_printf(imapd_out,
                                "%s BAD Invalid field-value pair in Id\r\n",
                                tag);
                    eatline(imapd_in, c);
                }
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
            hash_insert(field.s, xstrdup(buf_cstring(&arg)), &imapd_id.params);
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

        hash_enumerate(&imapd_id.params, &log_id_param, &logbuf);

        syslog(LOG_INFO, "client id sessionid=<%s> userid=<%s>:%s",
                         session_id(),
                         imapd_userid ? imapd_userid : "",
                         buf_cstring(&logbuf));
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

/*
 * Perform an IDLE command
 */
static void cmd_idle(char *tag)
{
    int c = EOF;
    static struct buf arg;
    static int idle_period = -1;
    static time_t idle_timeout = -1;
    int done, shutdown = 0;
    char buf[2048];
    const char *msg = NULL;
    struct protstream *be_in = NULL;
    int extra_fd = idle_sock;

    client_behavior_mask |= CB_IDLE;

    /* get idle timeout */
    if (idle_timeout == -1) {
        idle_timeout = config_getduration(IMAPOPT_IMAPIDLETIMEOUT, 'm');
        if (idle_timeout <= 0) {
            idle_timeout = config_getduration(IMAPOPT_TIMEOUT, 'm');
        }
    }

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

        be_in = backend_current->in;
        extra_fd = PROT_NO_FD;
    }
    else if (!notify_event_groups && imapd_index && idle_sock != PROT_NO_FD) {
        /* If NOTIFY has NOT already been enabled,
           tell idled to start sending message updates */
        const char *mboxid = index_mboxid(imapd_index);
        strarray_t key = { 1, 0, (char **) &mboxid }; // avoid memory alloc

        idle_start(IMAP_NOTIFY_MESSAGE, time(NULL) + idle_timeout,
                   FILTER_SELECTED, &key);
    }

    /* Tell client we are idling and waiting for end of command */
    prot_printf(imapd_out, "+ idling\r\n");

    if (idle_timeout > 0) {
        errno = 0;
        prot_settimeout(imapd_in, idle_timeout);
    }

    do {
        /* If not using NOTIFY,
           and not using idled or running IDLE on backend, poll for updates */
        if (!notify_event_groups &&
            (idle_sock == PROT_NO_FD || !CAPA(backend_current, CAPA_IDLE))) {
            imapd_check(NULL, TELL_EXPUNGED);
        }

        /* Release any held index */
        index_release(imapd_index);

        /* Flush any buffered output */
        prot_flush(imapd_out);

        /* Check for shutdown file */
        if (!imapd_userisadmin &&
            (shutdown_file(buf, sizeof(buf)) ||
             userdeny(imapd_userid, config_ident, buf, sizeof(buf)))) {
            for (msg = buf; *msg == '['; msg++); // can't have [ be first char

            done = shutdown = 1;
        }
        else {
            int extra_fd_flag = 0;

            done = proxy_check_input(protin, imapd_in, imapd_out, be_in, NULL,
                                     extra_fd, &extra_fd_flag, idle_period);

            if (extra_fd_flag) {
                /* Message from idled */
                push_updates(1);
            }
        }
    } while (!done);

    /* Either the client timed out, ended the command, or received shutdown. */
    if (CAPA(backend_current, CAPA_IDLE)) {
        /* Terminate IDLE on backend */
        prot_printf(backend_current->out, "Done\r\n");
        pipe_until_tag(backend_current, tag, 0);
    }
    else if (!notify_event_groups && idle_sock != PROT_NO_FD) {
        /* If NOTIFY had NOT already been enabled,
           tell idled to stop sending message updates */
        idle_stop(FILTER_SELECTED);
    }

    if (shutdown) {
        prot_printf(imapd_out, "* BYE [ALERT] %s\r\n", msg);
        telemetry_rusage(imapd_userid);
        shut_down(0);
    }

    /* Get continuation data */
    c = getword(imapd_in, &arg);

    if (c != EOF) {
        prot_settimeout(imapd_in, imapd_timeout);

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
    const char *capa;
    int i;

    for (i = 0; (capa = base_capabilities[i].str); i++) {
        int mask = base_capabilities[i].mask;

        /* Filter capabilities if requested */
        if (!(mask & CAPA_REQD) && capa_is_disabled(capa))
            continue;

        /* Don't show if they're not shown at this level of login */
        if (!(mask & flags) || (imapd_authstate && !(mask & CAPA_POSTAUTH)))
            continue;

        /* Don't show if they're disabled by config switch */
        if (mask & CAPA_CONFIG) {
            enum imapopt config = base_capabilities[i].u.config;
            if (!config_getswitch(config) == !(mask & CAPA_REVERSE))
                continue;
        }

        /* Don't show if they're disallowed by server state */
        if (mask & CAPA_STATE) {
            int state = *base_capabilities[i].u.statep;
            if (!state == !(mask & CAPA_REVERSE))
                continue;
        }

        if (mask & CAPA_COMPLEX) {
            /* Complex capability */
            base_capabilities[i].u.complex();
        }
        else {
            /* Print the capability */
            const char **strp = NULL, *s = "", *valfmt = "";
            int64_t *i64p = NULL, i64 = INT64_MIN;
            int num = 1, n = 0;

            if (mask & CAPA_VALUE) {
                /* Capability with formatted value */
                strp = base_capabilities[i].u.value.strp;
                i64p = base_capabilities[i].u.value.i64p;

                if (strp) s = *strp;
                if (i64p) i64 = *i64p;

                /* Don't show if disabled by a NULL string argument */
                if (!s) continue;

                valfmt = base_capabilities[i].u.value.fmt;
            }
            else if (mask & CAPA_MULTI) {
                num = base_capabilities[i].u.multi.num;
                strp = (const char **) base_capabilities[i].u.multi.val;
                s = *strp;
                valfmt = "%1$s";
            }

            do {
                prot_putc(' ', imapd_out);
                prot_puts(imapd_out, capa);
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
                /* format string and args chosen carefully */
                prot_printf(imapd_out, valfmt, s, i64);
#pragma GCC diagnostic pop
            } while ((mask & CAPA_MULTI) && (++n < num) && (s = *(++strp)));
        }
    }
}

/*
 * Perform a CAPABILITY command
 */
static void cmd_capability(char *tag)
{
    imapd_check(NULL, 0);

    prot_printf(imapd_out, "* CAPABILITY");

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

static int getliteralsize(const char *tag, const char *p, int c, size_t maxsize,
                          unsigned *size, int *binary, const char **parseerr)

{
    int isnowait = 0;
    uint32_t num;
    static int lminus = -1;

    if (lminus == -1) lminus = config_getswitch(IMAPOPT_LITERALMINUS);

    /* Check for literal8 */
    if (*p == '~') {
        p++;
        *binary = client_behavior_mask |= CB_BINARY;
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
        /* LITERAL- says maximum size is 4096! */
        if (lminus && num > 4096) {
            /* Fail per RFC 7888, Section 4, choice 2 */
            prot_printf(imapd_out, "%s NO %s\r\n", tag,
                        error_message(IMAP_LITERAL_MINUS_TOO_LARGE));
            fatal(error_message(IMAP_LITERAL_MINUS_TOO_LARGE), EX_PROTOCOL);
        }
        if (num > maxsize) {
            /* Fail per RFC 7888, Section 4, choice 2 */
            prot_printf(imapd_out, "%s NO %s\r\n", tag,
                        error_message(IMAP_MESSAGE_TOOBIG));
            fatal(error_message(IMAP_MESSAGE_TOOBIG), EX_PROTOCOL);
        }
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

static int catenate_text(const char *tag, FILE *f, size_t maxsize,
                         unsigned *totalsize, int *binary, const char **parseerr)
{
    int c;
    static struct buf arg;
    unsigned size = 0;
    char buf[4096+1];
    unsigned n;
    int r;

    c = getword(imapd_in, &arg);

    /* Read size from literal */
    r = getliteralsize(tag, arg.s, c, maxsize - *totalsize,
                       &size, binary, parseerr);
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
    struct index_state *state = NULL;
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
            seqset_free(&init.vanishedlist);
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
    } else if (!url.uid || !(msgno = index_finduid(state, url.uid, FIND_EQ))) {
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

static int append_catenate(const char *tag, FILE *f, const char *cur_name,
                           size_t maxsize, unsigned *totalsize,
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
            int r1 = catenate_text(tag, f, maxsize, totalsize, binary, parseerr);
            if (r1) return r1;

            /* if we see a SP, we're trying to catenate more than one part */

            /* Parse newline terminating command */
            c = prot_getc(imapd_in);
        }
        else if ((client_capa & CAPA_UTF8_ACCEPT) && !strcasecmp(arg.s, "UTF8")) {
            int r1;

            if (c != ' ' || (c = prot_getc(imapd_in) != '(')) {
                *parseerr = "Missing UTF8 message part in Append command";
                return IMAP_PROTOCOL_ERROR;
            }

            r1 = catenate_text(tag, f, maxsize, totalsize, binary, parseerr);
            if (r1) return r1;

            if ((c = prot_getc(imapd_in) != ')')) {
                *parseerr =
                    "Missing ')' after UTF8 message part in Append command";
                return IMAP_PROTOCOL_ERROR;
            }

            /* if we see a SP, we're trying to catenate more than one part */

            /* Parse newline terminating command */
            c = prot_getc(imapd_in);
        }
        else if (!strcasecmp(arg.s, "URL")) {
            c = getastring(imapd_in, imapd_out, &arg);
            if (c == IMAP_LITERAL_TOO_LARGE) return c;
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

static char *normalize_mboxname(char *name, struct listargs *listargs)
{
    char *nfc_name = charset_utf8_normalize(name);

    if (strcmp(nfc_name, name)) {
        if (listargs) {
            /* Setup to emit LIST response with OLDNAME */
            strarray_append(&listargs->pat, nfc_name);
            listargs->denormalized = name;
        }
        return nfc_name;
    }

    free(nfc_name);

    return name;
}

/* If an APPEND is proxied from another server,
 * 'cur_name' is the name of the currently selected mailbox (if any)
 * in case we have to resolve relative URLs
 */
static int cmd_append(char *tag, char *name, const char *cur_name, int isreplace)
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
    const char *origname = name;
    struct listargs listargs = {
        LIST_CMD_EXTENDED, 0, LIST_RET_CHILDREN | LIST_RET_SPECIALUSE,
        "", STRARRAY_INITIALIZER, 0, {0}, STRARRAY_INITIALIZER, NULL
    };

    if (client_capa & CAPA_IMAP4REV2) {
        name = normalize_mboxname(name, &listargs);
    }
    else if (client_capa & CAPA_UTF8_ACCEPT) {
        name = normalize_mboxname(name, NULL);
    }

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
            r = IMAP_OK_COMPLETED;
            goto cleanup;
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
                            tag, strlen(origname), origname,
                            strlen(mboxname), mboxname);
            } else {
                prot_printf(s->out, "%s Localappend {" SIZE_T_FMT "+}\r\n%s"
                            " \"\" ", tag, strlen(origname), origname);
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

        goto cleanup;
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

        const char *respcode = "";
        if (r == IMAP_QUOTA_EXCEEDED) {
            respcode = "[OVERQUOTA] ";
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
        free(intname);
        return r;
    }

    c = ' '; /* just parsed a space */
    /* we loop, to support MULTIAPPEND */
    while (!r && c == ' ') {
        curstage = xzmalloc(sizeof(*curstage));
        ptrarray_push(&stages, curstage);

        /* Set limit on the total number of bytes allowed for mailbox+append-opts */
        maxargssize_mark = prot_bytes_in(imapd_in) + (maxargssize - strlen(name));

        /* now parsing "append-opts" in the ABNF */

        /* Parse flags */
        c = getword(imapd_in, &arg);
        if  (c == '(' && !arg.s[0]) {
            strarray_init(&curstage->flags);
            do {
                c = getword(imapd_in, &arg);
                if (prot_bytes_in(imapd_in) > maxargssize_mark)
                    fatal(error_message(IMAP_ARGS_TOO_LARGE), EX_PROTOCOL);
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
                if (c <= EOF) {
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
            client_behavior_mask |= CB_CATENATE;

            if (c != ' ' || (c = prot_getc(imapd_in) != '(')) {
                parseerr = "Missing message part(s) in Append command";
                r = IMAP_PROTOCOL_ERROR;
                goto done;
            }

            /* Catenate the message part(s) to stage */
            size = 0;
            r = append_catenate(tag, curstage->f, cur_name, maxmsgsize, &size,
                                &(curstage->binary), &parseerr, &url);
            if (r) goto done;
        }
        else {
            int is_utf8 = 0;

            if (!strcasecmp(arg.s, "UTF8")) {
                if (!(client_capa & CAPA_UTF8_ACCEPT)) {
                    parseerr = "Invalid argument in Append command";
                    r = IMAP_PROTOCOL_ERROR;
                    goto done;
                }

                is_utf8 = 1;

                if (c != ' ' || (c = prot_getc(imapd_in) != '(')) {
                    parseerr = "Missing UTF8 message part in Append command";
                    r = IMAP_PROTOCOL_ERROR;
                    goto done;
                }

                c = getword(imapd_in, &arg);
            }

            /* Read size from literal */
            r = getliteralsize(tag, arg.s, c, maxmsgsize,
                               &size, &(curstage->binary), &parseerr);
            if (!r && size == 0) r = IMAP_ZERO_LENGTH_LITERAL;
            if (r) goto done;

            /* Copy message to stage */
            r = message_copy_strict(imapd_in, curstage->f, size, curstage->binary);

            if (is_utf8 && (c = prot_getc(imapd_in) != ')')) {
                parseerr =
                    "Missing ')' after UTF8 message part in Append command";
                r = IMAP_PROTOCOL_ERROR;
                goto done;
            }
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

        /* REPLACE doesn't support MULTIAPPEND */
        if (isreplace) break;
    }

 done:
    switch (r) {
    case IMAP_ZERO_LENGTH_LITERAL:
    case IMAP_MESSAGE_TOO_LARGE:
        break;

    case 0:
        /* we should be looking at the end of the line */
        if (IS_EOL(c, imapd_in)) break;

        parseerr = "junk after literal";
        r = IMAP_PROTOCOL_ERROR;

        GCC_FALLTHROUGH

    default:
        eatline(imapd_in, c);
        break;
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
                /* free this up again - that way we re-parse the fixed up file */
                message_free_body(body);
                free(body);
                body = NULL;
            }
            if (!r) {
                r = append_fromstage(&appendstate, &body, curstage->stage,
                                     curstage->internaldate, /*createdmodseq*/0,
                                     &curstage->flags, 0,
                                     &curstage->annotations);
            }
            if (body) {
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

    if (isreplace && doappenduid && !r) {
        prot_printf(imapd_out, "* OK [APPENDUID %lu %u] %s\r\n",
                    uidvalidity, appendstate.baseuid,
                    error_message(IMAP_OK_COMPLETED));
        doappenduid = 0;
    }

    imapd_check(NULL, TELL_EXPUNGED);

    if (!r && strarray_size(&listargs.pat)) {
        /* Emit LIST response with OLDNAME */
        list_data(&listargs);
    }

    if (r == IMAP_PROTOCOL_ERROR && parseerr) {
        prot_printf(imapd_out, "%s BAD %s\r\n", tag, parseerr);
    } else if (r == IMAP_LITERAL_TOO_LARGE) {
        prot_printf(imapd_out, "%s NO %s\r\n", tag, error_message(r));
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
        else if (r == IMAP_USERFLAG_EXHAUSTED ||
                 r == IMAP_CONVERSATION_GUIDLIMIT) {
            respcode = "[LIMIT] ";
        }
        else if (r == IMAP_QUOTA_EXCEEDED) {
            respcode = "[OVERQUOTA] ";
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
    } else if (!isreplace) {
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
    strarray_fini(&listargs.pat);
    if (name != origname) free(name);

    return r;
}

/*
 * Warn if mailbox is close to or over any quota resource.
 *
 * Warn if the following possibilities occur:
 * - quotawarnsize not set + quotawarnpercent hit
 * - quotawarnsize set larger than mailbox + quotawarnpercent hit
 * - quotawarnsize set + hit + quotawarnpercent hit
 * - quotawarnmsg not set + quotawarnpercent hit
 * - quotawarnmsg set larger than mailbox + quotawarnpercent hit
 * - quotawarnmsg set + hit + quotawarnpercent hit
 */
static void warn_about_quota(const char *quotaroot)
{
    time_t now = time(NULL);
    struct quota q;
    int res;
    int r;
    int thresholds[QUOTA_NUMRESOURCES];
    int pc_threshold = config_getint(IMAPOPT_QUOTAWARNPERCENT);
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
    thresholds[QUOTA_STORAGE] = config_getbytesize(IMAPOPT_QUOTAWARNSIZE, 'K') / 1024;
    thresholds[QUOTA_MESSAGE] = config_getint(IMAPOPT_QUOTAWARNMSG);
    thresholds[QUOTA_ANNOTSTORAGE] = config_getbytesize(IMAPOPT_QUOTAWARNSIZE, 'K') / 1024;

    for (res = 0 ; res < QUOTA_NUMRESOURCES ; res++) {
        if (q.limits[res] < 0)
            continue;       /* this resource is unlimited */
        buf_reset(&msg);

        if (thresholds[res] <= 0 ||
            thresholds[res] >= q.limits[res] ||
            q.useds[res] > ((quota_t) (q.limits[res] - thresholds[res])) * quota_units[res]) {

            pc_usage = (int)(((double) q.useds[res] * 100.0) /
                             (double) ((quota_t) q.limits[res] * quota_units[res]));

            if (q.useds[res] > (quota_t) q.limits[res] * quota_units[res]) {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
                /* format string from imap_err.et */
                buf_printf(&msg, error_message(IMAP_NO_OVERQUOTA),
                           quota_names[res]);
#pragma GCC diagnostic pop
            }
            else if (pc_usage > pc_threshold) {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
                /* format string from imap_err.et */
                buf_printf(&msg, error_message(IMAP_NO_CLOSEQUOTA),
                           pc_usage, quota_names[res]);
#pragma GCC diagnostic pop
            }
        }

        if (msg.len)
            prot_printf(imapd_out, "* NO [ALERT] %s\r\n", buf_cstring(&msg));
    }

    buf_reset(&msg);
out:
    quota_free(&q);
}

static void prot_print_client_capa(struct protstream *pout, unsigned capa)
{
    if (capa & CAPA_IMAP4REV2) {
        prot_puts(pout, " IMAP4rev2");
    }
    if (capa & CAPA_CONDSTORE) {
        prot_puts(pout, " CONDSTORE");
    }
    if (capa & CAPA_QRESYNC) {
        prot_puts(pout, " QRESYNC");
    }
    if (capa & CAPA_UIDONLY) {
        prot_puts(pout, " UIDONLY");
    }
    if (capa & CAPA_UTF8_ACCEPT) {
        prot_puts(pout, " UTF8=ACCEPT");
    }
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
    const char *origname = name;
    struct listargs listargs = {
        LIST_CMD_EXTENDED, 0, LIST_RET_CHILDREN | LIST_RET_SPECIALUSE,
        "", STRARRAY_INITIALIZER, 0, {0}, STRARRAY_INITIALIZER, NULL
    };

    memset(&init, 0, sizeof(struct index_init));

    c = prot_getc(imapd_in);
    if (c == ' ') {
        static struct buf arg, parm1, parm2;

        c = prot_getc(imapd_in);
        if (c != '(') goto badlist;

        c = getword(imapd_in, &arg);
        if (arg.s[0] == '\0') goto badlist;
        for (;;) {
            if (prot_bytes_in(imapd_in) > maxargssize_mark)
                fatal(error_message(IMAP_ARGS_TOO_LARGE), EX_PROTOCOL);

            ucase(arg.s);
            if (!strcmp(arg.s, "CONDSTORE")) {
                client_capa |= CAPA_CONDSTORE;
                client_behavior_mask |= CB_CONDSTORE;
            }
            else if ((client_capa & CAPA_QRESYNC) &&
                     !strcmp(arg.s, "QRESYNC")) {
                client_behavior_mask |= CB_QRESYNC;

                if (c != ' ') goto badqresync;
                c = prot_getc(imapd_in);
                if (c != '(') goto badqresync;
                c = getuint32(imapd_in, &v->uidvalidity);
                if (c != ' ' || !v->uidvalidity) goto badqresync;
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
                    if (c == '(' && !(client_capa & CAPA_UIDONLY)) {
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
        maybe_autoexpunge();
        index_close(&imapd_index);
        wasopen = 1;

        if (notify_event_groups && notify_event_groups->selected.events) {
            /* Tell idled to stop sending message updates */
            idle_stop(FILTER_SELECTED);
        }
    }

    if (backend_current) {
        /* remove backend_current from the protgroup */
        protgroup_delete(protin, backend_current->in);
        wasopen = 1;
    }

    if (client_capa & CAPA_IMAP4REV2) {
        name = normalize_mboxname(name, &listargs);
        if (name == origname) {
            /* Always want LIST response even if name was in normal form */
            strarray_append(&listargs.pat, name);
        }
    }
    else if (client_capa & CAPA_UTF8_ACCEPT) {
        name = normalize_mboxname(name, NULL);
    }

    char *intname = mboxname_from_external(name, &imapd_namespace, imapd_userid);
    r = mlookup(tag, name, intname, &mbentry);
    if (r == IMAP_MAILBOX_MOVED) {
        goto done;
    }

    if (!r && (mbentry->mbtype & MBTYPE_REMOTE)) {
        char mytag[128];

        if (supports_referrals) {
            imapd_refer(tag, mbentry->server, name);
            mboxlist_entry_free(&mbentry);
            goto done;
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
            mboxlist_entry_free((mbentry_t **) &backend_current->context);
        }
        backend_current = backend_next;

        if (r) {
            prot_printf(imapd_out, "%s NO %s\r\n", tag, error_message(r));
            mboxlist_entry_free(&mbentry);
            goto done;
        }

        if (client_capa) {
            /* Enable client capabilities on new backend */
            proxy_gentag(mytag, sizeof(mytag));
            prot_printf(backend_current->out, "%s Enable", mytag);
            prot_print_client_capa(backend_current->out, client_capa);
            prot_puts(backend_current->out, "\r\n");
            pipe_until_tag(backend_current, mytag, 0);
        }

        /* Send SELECT command to backend */
        prot_printf(backend_current->out, "%s %s {" SIZE_T_FMT "+}\r\n%s",
                    tag, cmd, strlen(origname), origname);
        if (v->uidvalidity) {
            prot_printf(backend_current->out, " (QRESYNC (%u " MODSEQ_FMT,
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

            backend_current->context = mbentry;

            /* add backend_current to the protgroup */
            protgroup_insert(protin, backend_current->in);
            break;
        default:
            syslog(LOG_DEBUG, "open: user %s failed to open %s", imapd_userid,
                   name);
            /* not successfully selected */
            mboxlist_entry_free(&mbentry);
            backend_current = NULL;
            break;
        }

        goto done;
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
      mboxlist_entry_free((mbentry_t **) &backend_current->context);
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
        seqset_free(&init.vanishedlist);
        if (doclose) index_close(&imapd_index);
        goto done;
    }

    if (index_hasrights(imapd_index, ACL_EXPUNGE))
        warn_about_quota(mailbox_quotaroot(imapd_index->mailbox));

    index_select(imapd_index, &init);

    seqset_free(&init.vanishedlist);

    if (strarray_size(&listargs.pat)) {
        /* Emit LIST response, optionally with OLDNAME */
        list_data(&listargs);
    }

    if (notify_event_groups && notify_event_groups->selected.events) {
        /* Tell idled to start sending message updates */
        const char *mboxid = index_mboxid(imapd_index);
        strarray_t key = { 1, 0, (char **) &mboxid }; // avoid memory alloc

        idle_start(notify_event_groups->selected.events, 0, FILTER_SELECTED, &key);
    }

    prot_printf(imapd_out, "%s OK [READ-%s] %s\r\n", tag,
                index_hasrights(imapd_index, ACL_READ_WRITE) ?
                "WRITE" : "ONLY", error_message(IMAP_OK_COMPLETED));

    /* n.b. this debug log line is now load-bearing -- the cassandane test
     * Simple.toggleable_debug_logging looks for it
     */
    syslog(LOG_DEBUG, "open: user %s opened %s", imapd_userid, name);
    goto done;

 badlist:
    prot_printf(imapd_out, "%s BAD Invalid modifier list in %s\r\n", tag, cmd);
    eatline(imapd_in, c);
    return;

 badqresync:
    prot_printf(imapd_out, "%s BAD Invalid QRESYNC parameter list in %s\r\n",
                tag, cmd);
    eatline(imapd_in, c);
    return;

 done:
    strarray_fini(&listargs.pat);
    if (name != origname) free(name);
    free(intname);
}

/*
 * Perform a CLOSE/UNSELECT command
 */
static void cmd_close(char *tag, char *cmd)
{
    if (cmd[0] == 'U') client_behavior_mask |= CB_UNSELECT;

    if (backend_current) {
        /* remote mailbox */
        prot_printf(backend_current->out, "%s %s\r\n", tag, cmd);
        /* XXX do we want this to say OK if the connection is gone?
         * saying NO is clearly wrong, hense the fatal request. */
        pipe_including_tag(backend_current, tag, 0);

        /* remove backend_current from the protgroup */
        protgroup_delete(protin, backend_current->in);

        backend_current = NULL;
        return;
    }

    /* local mailbox */
    if (index_hasrights(imapd_index, ACL_EXPUNGE)) {
        if (cmd[0] == 'C') {
            // always expunge for close (as opposed to unselect)
            index_expunge(imapd_index, NULL, 1);
        }
        else {
            maybe_autoexpunge();
        }
    }

    index_close(&imapd_index);

    if (notify_event_groups && notify_event_groups->selected.events) {
        /* Tell idled to stop sending message updates */
        idle_stop(FILTER_SELECTED);
    }

    /* RFC 7162, Section 3.2.8 - don't send HIGHESTMODSEQ to a close
     * command, because it can cause client to lose synchronization */
    prot_printf(imapd_out, "%s OK %s\r\n",
                tag, error_message(IMAP_OK_COMPLETED));
}

static void condstore_enabled(const char *cmd)
{
    if (!(client_capa & CAPA_CONDSTORE)) {
        client_capa |= CAPA_CONDSTORE;
        if (imapd_index) {
            prot_printf(imapd_out, "* OK [HIGHESTMODSEQ " MODSEQ_FMT "]"
                        " CONDSTORE enabled by %s\r\n",
                        index_highestmodseq(imapd_index), cmd);
        }
    }
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

#define FETCH_ALLOW_VANISHED  (1<<0)
#define FETCH_ALLOW_MODIFIERS (1<<1)

static int parse_fetch_args(const char *tag, const char *cmd,
                            unsigned flags,
                            struct fetchargs *fa)
{
    static struct buf fetchatt, fieldname;
    int c;
    int inlist = 0;
    char *p, *section;
    struct octetinfo oi;
    strarray_t *newfields = strarray_new();

    fa->partial.high = UINT32_MAX;

    c = getword(imapd_in, &fetchatt);
    if (c == '(' && !fetchatt.s[0]) {
        inlist = 1;
        c = getword(imapd_in, &fetchatt);
    }
    for (;;) {
        if (prot_bytes_in(imapd_in) > maxargssize_mark)
            fatal(error_message(IMAP_ARGS_TOO_LARGE), EX_PROTOCOL);

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
                if (c <= EOF) {
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
                        if (prot_bytes_in(imapd_in) > maxargssize_mark)
                            fatal(error_message(IMAP_ARGS_TOO_LARGE), EX_PROTOCOL);
                        if (c == IMAP_LITERAL_TOO_LARGE) {
                            prot_printf(imapd_out, "%s NO %s in %s %s\r\n",
                                        tag, error_message(c), cmd, fetchatt.s);
                            goto freeargs;
                        }
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
            if (imapd_preview_enabled && !strcmp(fetchatt.s, "PREVIEW")) {
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
                    if (c == IMAP_LITERAL_TOO_LARGE) {
                        prot_printf(imapd_out, "%s NO %s in %s %s\r\n",
                                    tag, error_message(c), cmd, fetchatt.s);
                        goto freeargs;
                    }
                    for (p = fieldname.s; *p; p++) {
                        if (*p <= ' ' || *p & 0x80 || *p == ':') break;
                    }
                    if (*p || !*fieldname.s) {
                        prot_printf(imapd_out, "%s BAD Invalid field-name in %s %s\r\n",
                               tag, cmd, fetchatt.s);
                        eatline(imapd_in, c);
                        goto freeargs;
                    }
                    lcase(fieldname.s);
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

    if (inlist) {
        if (c != ')') {
            prot_printf(imapd_out, "%s BAD Missing close parenthesis in %s\r\n",
                        tag, cmd);
            eatline(imapd_in, c);
            goto freeargs;
        }
        if (flags & FETCH_ALLOW_MODIFIERS)
            c = prot_getc(imapd_in);
        else
            goto validate;
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
            if (prot_bytes_in(imapd_in) > maxargssize_mark)
                fatal(error_message(IMAP_ARGS_TOO_LARGE), EX_PROTOCOL);

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
            else if ((flags & FETCH_ALLOW_VANISHED) &&
                     !strcmp(fetchatt.s, "VANISHED")) {
                fa->vanished = 1;
            }
            else if (!strcmp(fetchatt.s, "PARTIAL")) {   /* RFC 9394 */
                int r = -1;

                if (c == ' ') {
                    c = getword(imapd_in, &fieldname);
                    r = imparse_range(fieldname.s, &fa->partial);
                }
                if (r) {
                    prot_printf(imapd_out, "%s BAD Invalid range in %s\r\n",
                                tag, cmd);
                    goto freeargs;
                }
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

  validate:
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
        condstore_enabled(fa->changedsince ? "FETCH CHANGEDSINCE" : "FETCH MODSEQ");
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
    unsigned flags = FETCH_ALLOW_MODIFIERS;

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

    if (usinguid) {
        if (client_capa & CAPA_QRESYNC)
            flags |= FETCH_ALLOW_VANISHED;

        if (!(client_capa & CAPA_UIDONLY))
            fetchargs.fetchitems |= FETCH_UID;
    }

    r = parse_fetch_args(tag, cmd, flags, &fetchargs);
    if (r)
        goto freeargs;

    if (fetchargs.fetchitems & FETCH_ANNOTATION)
        client_behavior_mask |= CB_ANNOTATE;

    if (fetchargs.fetchitems & (FETCH_EMAILID | FETCH_THREADID))
        client_behavior_mask |= CB_OBJECTID;

    if (fetchargs.fetchitems & FETCH_PREVIEW)
        client_behavior_mask |= CB_PREVIEW;

    if (fetchargs.fetchitems & FETCH_SAVEDATE)
        client_behavior_mask |= CB_SAVEDATE;

    if (fetchargs.binsections || fetchargs.sizesections)
        client_behavior_mask |= CB_BINARY;

    if (fetchargs.partial.low)
        client_behavior_mask |= CB_PARTIAL;

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
            if (prot_bytes_in(imapd_in) > maxargssize_mark)
                fatal(error_message(IMAP_ARGS_TOO_LARGE), EX_PROTOCOL);

            ucase(storemod.s);
            if (!strcmp(storemod.s, "UNCHANGEDSINCE")) {
                client_behavior_mask |= CB_CONDSTORE;

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
        if (c <= EOF) {
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
        if (prot_bytes_in(imapd_in) > maxargssize_mark)
            fatal(error_message(IMAP_ARGS_TOO_LARGE), EX_PROTOCOL);
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

    if (storeargs.unchangedsince != ULONG_MAX) {
        condstore_enabled("STORE UNCHANGEDSINCE");
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
    seqset_free(&storeargs.modified);
    free(modified);
}

static void progress_cb(unsigned count, unsigned total, void *rock)
{
    struct progress_rock *prock = (struct progress_rock *) rock;
    static time_t interval = -1;
    time_t now;

    if (interval == -1) {
        interval = config_getduration(IMAPOPT_IMAP_INPROGRESS_INTERVAL, 's');
        if (interval < 0) interval = 0;
    }

    now = time(0);
    if (interval && now - prock->last_resp > interval) {
        prock->last_resp = now;

        prot_printf(imapd_out, "* OK [INPROGRESS (\"%s\" ", prock->tag);
        if (prock->no_count)
            prot_puts(imapd_out, "NIL NIL");
        else {
            prot_printf(imapd_out, "%u ", count);
            prot_printf(imapd_out, total ? "%u" : "NIL", total);
        }
        prot_puts(imapd_out, ")] Still processing...\r\n");
        prot_flush(imapd_out);
    }
}

struct multisearch_rock {
    struct searchargs *args;
    search_expr_t *expr;  // pristine copy
    hash_table mailboxes; // for duplicate suppression
    unsigned filter;
    int root_depth;       // for subtree-one
    int *n;
    struct index_init init;
    struct progress_rock prock;
};

static int multisearch_cb(const mbentry_t *mbentry, void *rock)
{
    struct multisearch_rock *mrock = (struct multisearch_rock *) rock;
    struct index_state *state = NULL;
    int r;

    /* Skip non-email mailboxes and avoid duplicates */
    if (mbtype_isa(mbentry->mbtype) != MBTYPE_EMAIL ||
        hash_lookup(mbentry->name, &mrock->mailboxes))
        return 0;

    switch (mrock->filter) {
    case SEARCH_SOURCE_INBOXES:
        /* Only allow user's INBOX or those postable by anonymous */
        if (!mboxname_isusermailbox(mbentry->name, /*isinbox*/1) &&
            !(cyrus_acl_myrights(NULL, mbentry->acl) & ACL_POST))
            return 0;
        break;

    case SEARCH_SOURCE_SUBTREE_ONE: {
        /* Only allow parent and children - no other ancestors */
        mbname_t *mbname = mbname_from_intname(mbentry->name);
        int depth = strarray_size(mbname_boxes(mbname));
        mbname_free(&mbname);

        if (depth > mrock->root_depth + 1) return 0;
        break;
    }
    }

    if ((r = index_open(mbentry->name, &mrock->init, &state))) {
        return r;
    }

    /* Use a fresh search_expr_t for each mailbox */
    if (mrock->args->root) search_expr_free(mrock->args->root);
    mrock->args->root = search_expr_duplicate(mrock->expr);

    *mrock->n += index_search(state, mrock->args, /*usinguid*/1, &mrock->prock);
    index_close(&state);

    /* Reset inprogress timer after ESEARCH response */
    mrock->prock.last_resp =  time(0);

    /* Keep track of each mailbox we search */
    hash_insert(mbentry->name, (void *) 1, &mrock->mailboxes);

    return 0;
}

static void cmd_search(const char *tag, const char *cmd)
{
    int c;
    struct searchargs *searchargs;
    clock_t start = clock();
    char mytime[100];
    int usinguid = 0, n = 0;
    int state = GETSEARCH_RETURN;

    if (backend_current) {
        /* remote mailbox */
        if (cmd[0] == 'U') cmd = "UID Search";

        prot_printf(backend_current->out, "%s %s ", tag, cmd);
        if (!pipe_command(backend_current, 65536)) {
            pipe_including_tag(backend_current, tag, 0);
        }
        return;
    }

    switch (cmd[0]) {
    case 'E':  // Esearch (multisearch)
        client_behavior_mask |= CB_MULTISEARCH;
        state |= GETSEARCH_SOURCE;

        GCC_FALLTHROUGH

    case 'U':  // Uid Search
        usinguid = 1;
        break;
    }

    /* RFC 9855, Section 3: MUST reject SEARCH with a charset specification */ 
    if (!(client_capa & CAPA_UTF8_ACCEPT)) {
        state |= GETSEARCH_CHARSET_KEYWORD;
    }

    /* local mailbox */
    searchargs = new_searchargs(tag, state,
                                &imapd_namespace, imapd_userid, imapd_authstate,
                                imapd_userisadmin || imapd_userisproxyadmin);

    searchargs->maxargssize_mark = maxargssize_mark;

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
        goto done;
    }

    if (c == IMAP_LITERAL_TOO_LARGE) {
        prot_printf(imapd_out, "%s NO %s in Search\r\n", tag, error_message(c));
        goto done;
    }

    if (!IS_EOL(c, imapd_in)) {
        prot_printf(imapd_out,
                    "%s BAD Unexpected extra arguments to Search\r\n", tag);
        eatline(imapd_in, c);
        goto done;
    }

    if (searchargs->charset == CHARSET_UNKNOWN_CHARSET) {
        prot_printf(imapd_out, "%s NO %s\r\n", tag,
                    error_message(IMAP_UNRECOGNIZED_CHARSET));
        goto done;
    }

    if (searchargs->returnopts & SEARCH_RETURN_SAVE)
        client_behavior_mask |= CB_SEARCHRES;

    if (searchargs->returnopts & SEARCH_RETURN_PARTIAL)
        client_behavior_mask |= CB_PARTIAL;

    if (searchargs->did_objectid)
        client_behavior_mask |= CB_OBJECTID;

    // this refreshes the index, we may be looking at it in our search
    imapd_check(NULL, 0);

    if (searchargs->multi.filter) {
        /* Multisearch */
        if ((searchargs->multi.filter & SEARCH_SOURCE_SELECTED) && !imapd_index) {
            /* RFC 7377: 2.2
             * If the source options include (or default to) "selected", the IMAP
             * session MUST be in "selected" state.
             */
            prot_printf(imapd_out,
                        "%s BAD Please select a mailbox first\r\n", tag);
            goto done;
        }
        if (searchargs->multi.filter & ~SEARCH_SOURCE_SELECTED) {
            if (searchargs->returnopts & SEARCH_RETURN_SAVE) {
                /* RFC 7377: 2.2
                 * If the server supports the SEARCHRES [RFC5182] extension,
                 * then the "SAVE" result option is valid only if "selected"
                 * is specified or defaulted to as the sole mailbox to be
                 * searched.
                 * If any source option other than "selected" is specified,
                 * the ESEARCH command MUST return a "BAD" result.
                 */
                prot_printf(imapd_out,
                            "%s BAD Search results requested for unselected mailbox(es)\r\n",
                            tag);
                goto done;
            }
            if (searchargs->returnopts & SEARCH_RETURN_PARTIAL) {
                prot_printf(imapd_out,
                            "%s NO [CANNOT] Unsupported Search criteria\r\n",
                            tag);
                goto done;
            }
        }

        struct multisearch_rock mrock = {
            searchargs, search_expr_duplicate(searchargs->root),
            HASH_TABLE_INITIALIZER, 0, 0, &n,
            { .userid       = imapd_userid,
              .authstate    = imapd_authstate,
              .out          = imapd_out,
              .examine_mode = 1
            },
            { &progress_cb, tag, time(0),
              searchargs->multi.filter != SEARCH_SOURCE_SELECTED }
        };

        construct_hash_table(&mrock.mailboxes, 100, 0);  // arbitrary size

        if (!searchargs->returnopts) {
            /* RFC 7377: 2.1
             * Presence of a source option in the absence of a result option
             * implies the "ALL" result option.
             */
            searchargs->returnopts = SEARCH_RETURN_ALL;
        }

        /* Cycle through each of the possible source filters */
        for (mrock.filter = SEARCH_SOURCE_SELECTED;
             mrock.filter <= SEARCH_SOURCE_MAILBOXES; mrock.filter <<= 1) {

            if (!(searchargs->multi.filter & mrock.filter)) continue;

            switch (mrock.filter) {
            case SEARCH_SOURCE_SELECTED:
                if (!index_check(imapd_index, 0)) {  /* update the index */
                    n += index_search(imapd_index, searchargs, /* usinguid */1,
                                      &mrock.prock);

                    /* Reset inprogress timer after ESEARCH response */
                    mrock.prock.last_resp = time(0);

                    hash_insert(index_mboxname(imapd_index),
                                (void *) 1, &mrock.mailboxes);
                }
                break;

            case SEARCH_SOURCE_PERSONAL:
            case SEARCH_SOURCE_INBOXES:
                mboxlist_usermboxtree(searchargs->userid, searchargs->authstate,
                                      multisearch_cb, &mrock, 0);
                break;

            case SEARCH_SOURCE_SUBSCRIBED:
                mboxlist_usersubs(searchargs->userid, multisearch_cb, &mrock, 0);
                break;

            default: {
                strarray_t *mailboxes = NULL;
                unsigned flags = 0;
                int i;

                switch (mrock.filter) {
                case SEARCH_SOURCE_SUBTREE:
                    mailboxes = &searchargs->multi.subtree;
                    break;

                case SEARCH_SOURCE_SUBTREE_ONE:
                    mailboxes = &searchargs->multi.subtree_one;
                    break;

                case SEARCH_SOURCE_MAILBOXES:
                    /* Just the mailbox - no children */
                    flags = MBOXTREE_SKIP_CHILDREN;
                    mailboxes = &searchargs->multi.mailboxes;
                    break;
                }
                
                /* Cycle through each mailbox [tree] */
                for (i = 0; i < strarray_size(mailboxes); i++) {
                    const char *intname = strarray_nth(mailboxes, i);

                    if (mrock.filter == SEARCH_SOURCE_SUBTREE_ONE) {
                        /* Calculate the depth of the "root" mailbox */
                        mbname_t *mbname = mbname_from_intname(intname);
                        mrock.root_depth = strarray_size(mbname_boxes(mbname));
                        mbname_free(&mbname);
                    }

                    mboxlist_mboxtree(intname, multisearch_cb, &mrock, flags);
                }
                break;
            }
            }
        }

        search_expr_free(mrock.expr);
        free_hash_table(&mrock.mailboxes, NULL);
    }
    else {
        struct progress_rock prock = { &progress_cb, tag, time(0), 0 };

        if ((client_capa & CAPA_IMAP4REV2) && !searchargs->returnopts) {
            /* RFC 9051: Appendix E.4
             * SEARCH command now requires to return the ESEARCH response
             * (SEARCH response is now deprecated).
             */
            searchargs->returnopts = SEARCH_RETURN_ALL;
        }

        n = index_search(imapd_index, searchargs, usinguid, &prock);
    }

    if (searchargs->state & GETSEARCH_MODSEQ)
        condstore_enabled("SEARCH MODSEQ");

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

  done:
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

    searchargs->maxargssize_mark = maxargssize_mark;

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

    struct progress_rock prock = { &progress_cb, tag, time(0), 0 };

    n = index_sort(imapd_index, sortcrit, searchargs, usinguid, &prock);

    if (searchargs->state & GETSEARCH_MODSEQ)
        condstore_enabled("SORT MODSEQ");

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

    searchargs->maxargssize_mark = maxargssize_mark;

    c = get_search_program(imapd_in, imapd_out, searchargs);
    if (c == EOF) {
        eatline(imapd_in, ' ');
        goto done;
    }

    if (c == IMAP_LITERAL_TOO_LARGE) {
        prot_printf(imapd_out, "%s NO %s in Thread\r\n", tag, error_message(c));
        goto done;
    }

    if (!IS_EOL(c, imapd_in)) {
        prot_printf(imapd_out,
                    "%s BAD Unexpected extra arguments to Thread\r\n", tag);
        eatline(imapd_in, c);
        goto done;
    }

    struct progress_rock prock = { &progress_cb, tag, time(0), 0 };

    n = index_thread(imapd_index, alg, searchargs, usinguid, &prock);

    if (searchargs->state & GETSEARCH_MODSEQ)
        condstore_enabled("THREAD MODSEQ");

    snprintf(mytime, sizeof(mytime), "%2.3f",
             (clock() - start) / (double) CLOCKS_PER_SEC);
    prot_printf(imapd_out, "%s OK %s (%d msgs in %s secs)\r\n", tag,
                error_message(IMAP_OK_COMPLETED), n, mytime);

  done:
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

    if (ismove) client_behavior_mask |= CB_MOVE;

    char *intname = mboxname_from_external(name, &imapd_namespace, imapd_userid);
    r = mlookup(NULL, NULL, intname, &mbentry);

    if (!r) myrights = cyrus_acl_myrights(imapd_authstate, mbentry->acl);

    if (!r && backend_current) {
        /* remote mailbox -> local or remote mailbox */

        /* XXX  start of separate proxy-only code
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
        /* XXX  end of separate proxy-only code */

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
         * XXX  completely untested
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

    /* don't allow copying into \Scheduled mailbox */
    else if (mboxname_isscheduledmailbox(intname, 0))
        r = IMAP_PERMISSION_DENIED;

    /* local mailbox -> local mailbox */
    if (!r) {
        struct progress_rock prock = { &progress_cb, tag, time(0), 0 };

        r = index_copy(imapd_index, sequence, usinguid, intname,
                       &copyuid, !config_getswitch(IMAPOPT_SINGLEINSTANCESTORE),
                       &imapd_namespace,
                       (imapd_userisadmin || imapd_userisproxyadmin), ismove,
                       ignorequota, &prock);
    }

    if (ismove && copyuid && !r) {
        prot_printf(imapd_out, "* OK [COPYUID %s] %s\r\n",
                    copyuid, error_message(IMAP_OK_COMPLETED));
        free(copyuid);
        copyuid = NULL;
    }

    imapd_check(NULL, (ismove || usinguid) ? TELL_EXPUNGED : 0);

  done:

    if (r && !(usinguid && r == IMAP_NO_NOSUCHMSG)) {
        const char *respcode = "";
        if (r == IMAP_MAILBOX_NOTSUPPORTED) {
            respcode = "[CANNOT] ";
        }
        else if (r == IMAP_QUOTA_EXCEEDED) {
            respcode = "[OVERQUOTA] ";
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
    if (!r) index_tellchanges(imapd_index,
                              TELL_EXPUNGED | (sequence ? TELL_UID : 0));

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
    unsigned flags = MBOXLIST_CREATE_NOTIFY;
    const char *partition = NULL;
    const char *server = NULL;
    const char *uniqueid = NULL;
    uint32_t minor_version = 0;
    struct buf specialuse = BUF_INITIALIZER;
    struct dlist *use;
    struct mailbox *mailbox = NULL;
    char *mailboxid = NULL;
    mbentry_t *parent = NULL;
    const char *origname = name;
    struct listargs listargs = {
        LIST_CMD_EXTENDED, 0, LIST_RET_CHILDREN | LIST_RET_SPECIALUSE,
        "", STRARRAY_INITIALIZER, 0, {0}, STRARRAY_INITIALIZER, NULL
    };

    /* We don't care about trailing hierarchy delimiters. */
    if (name[0] && name[strlen(name)-1] == imapd_namespace.hier_sep) {
        name[strlen(name)-1] = '\0';
    }

    if (client_capa & CAPA_IMAP4REV2) {
        name = normalize_mboxname(name, &listargs);
    }
    else if (client_capa & CAPA_UTF8_ACCEPT) {
        name = normalize_mboxname(name, NULL);
    }

    mbname_t *mbname = mbname_from_extname(name, &imapd_namespace, imapd_userid);

    struct mboxlock *namespacelock = mboxname_usernamespacelock(mbname_intname(mbname));

    const char *type = NULL;

    dlist_getatom(extargs, "PARTITION", &partition);
    dlist_getatom(extargs, "SERVER", &server);
    dlist_getatom(extargs, "MAILBOXID", &uniqueid);
    dlist_getnum32(extargs, "VERSION", &minor_version);
    if (dlist_getatom(extargs, "TYPE", &type)) {
        if (!strcasecmp(type, "CALENDAR")) mbtype = MBTYPE_CALENDAR;
        else if (!strcasecmp(type, "COLLECTION")) mbtype = MBTYPE_COLLECTION;
        else if (!strcasecmp(type, "ADDRESSBOOK")) mbtype = MBTYPE_ADDRESSBOOK;
        else if (!strcasecmp(type, "SIEVE")) mbtype = MBTYPE_SIEVE;
        else {
            r = IMAP_MAILBOX_BADTYPE;
            goto err;
        }
    }
    use = dlist_getchild(extargs, "USE");
    if (use) {
        /* only user mailboxes can have specialuse, and if allowspecialusesubfolders is not enabled they must be user toplevel folders */
        if (!mbname_userid(mbname) || (!config_getswitch(IMAPOPT_ALLOWSPECIALUSESUBFOLDER ) && strarray_size(mbname_boxes(mbname)) != 1)) {
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
        else if (strstr(buf_cstring(&specialuse), "\\Scheduled"))
            flags |= MBOXLIST_CREATE_SETFLAGS_ONLY;
    }

    // A non-admin is not allowed to specify the server nor partition on which
    // to create the mailbox.
    //
    // However, this only applies to frontends. If we're a backend, a frontend will
    // proxy the partition it wishes to create the mailbox on.
    if (!imapd_userisadmin &&
        (server || partition || uniqueid || minor_version)) {
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

                    // don't hold the lock locally, we're proxying
                    mboxname_release(&namespacelock);

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
                    prot_printastring(s_conn->out, origname);

                    // special use needs extended support, so pass through extargs
                    if (specialuse.len || uniqueid) {
                        const char *sep = "";

                        prot_printf(s_conn->out, " (");

                        if (specialuse.len) {
                            prot_printf(s_conn->out, "USE (%s)", buf_cstring(&specialuse));
                            sep = " ";
                        }

                        if (partition) {
                            prot_printf(s_conn->out, "%sPARTITION ", sep);
                            prot_printastring(s_conn->out, partition);
                            sep = " ";
                        }

                        if (uniqueid) {
                            prot_printf(s_conn->out, "%sMAILBOXID ", sep);
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

    mbentry_t mbentry = MBENTRY_INITIALIZER;
    if (localonly) flags |= MBOXLIST_CREATE_LOCALONLY | MBOXLIST_CREATE_FORCEUSER;

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

                mbentry.name = (char *) mbname_intname(ancestor);
                mbentry.partition = (char *) partition;
                mbentry.mbtype = mbtype;
                r = mboxlist_createmailbox_version(&mbentry, minor_version,
                                                   0/*options*/, 0/*highestmodseq*/,
                                                   imapd_userisadmin || imapd_userisproxyadmin,
                                                   imapd_userid, imapd_authstate,
                                                   flags, NULL/*mailboxptr*/);
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
    mbentry.name = (char *) mbname_intname(mbname);
    mbentry.partition = (char *) partition;
    mbentry.uniqueid = (char *) uniqueid;
    mbentry.mbtype = mbtype;

    r = mboxlist_createmailbox_version(&mbentry, minor_version,
                                       options, 0/*highestmodseq*/,
                                       imapd_userisadmin || imapd_userisproxyadmin,
                                       imapd_userid, imapd_authstate,
                                       flags, &mailbox);

#ifdef USE_AUTOCREATE
    // Clausing autocreate for the INBOX
    if (r == IMAP_PERMISSION_DENIED) {
        if (!strarray_size(mbname_boxes(mbname)) && !strcmpsafe(imapd_userid, mbname_userid(mbname))) {
            int64_t autocreatequotastorage =
                config_getbytesize(IMAPOPT_AUTOCREATE_QUOTA, 'K');

            if (autocreatequotastorage > 0) {
                mbentry.uniqueid = NULL;
                r = mboxlist_createmailbox_version(&mbentry, minor_version,
                                                   0/*options*/, 0/*highestmodseq*/,
                                                   1/*isadmin*/, imapd_userid, imapd_authstate,
                                                   MBOXLIST_CREATE_NOTIFY, &mailbox);

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

                    if (autocreatequotastorage > 0)
                        newquotas[QUOTA_STORAGE] = autocreatequotastorage / 1024;
                    if (autocreatequotamessage > 0)
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
    mailboxid = xstrdup(mailbox_uniqueid(mailbox));
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

    /* Attempt to inherit the color of parent mailbox,
       as long as the parent is NOT a top-level user mailbox */
    if (parent &&
        !(imapd_namespace.isalt && mboxname_isusermailbox(parent->name, 1))) {
        static const char *annot = IMAP_ANNOT_NS "color";
        struct buf buf = BUF_INITIALIZER;

        annotatemore_lookupmask(parent->name, annot, imapd_userid, &buf);
        if (buf.len) {
            int r1 = annotatemore_writemask(mbentry.name, annot, imapd_userid, &buf);
            if (r1) {
                syslog(LOG_NOTICE,
                       "failed to write annotation %s on mailbox %s: %s",
                       annot, mbentry.name, error_message(r1));
            }
        }

        buf_free(&buf);
    }

    index_release(imapd_index);
    sync_checkpoint(imapd_in);

    if (strarray_size(&listargs.pat)) {
        /* Emit LIST response with OLDNAME */
        list_data(&listargs);
    }

    prot_printf(imapd_out, "%s OK [MAILBOXID (%s)] Completed\r\n", tag, mailboxid);

    imapd_check(NULL, 0);

done:
    mailbox_close(&mailbox);
    mboxname_release(&namespacelock);
    mboxlist_entry_free(&parent);
    buf_free(&specialuse);
    mbname_free(&mbname);
    free(mailboxid);
    strarray_fini(&listargs.pat);
    if (name != origname) free(name);
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
    int delete_user = 0;
    const char *origname = name;

    if (client_capa & (CAPA_IMAP4REV2 | CAPA_UTF8_ACCEPT)) {
        name = normalize_mboxname(name, NULL);
    }

    mbname_t *mbname = mbname_from_extname(name, &imapd_namespace, imapd_userid);
    struct mboxlock *namespacelock = mboxname_usernamespacelock(mbname_intname(mbname));

    r = mlookup(NULL, NULL, mbname_intname(mbname), &mbentry);

    if (!r && (mbentry->mbtype & MBTYPE_REMOTE)) {
        /* remote mailbox */
        struct backend *s = NULL;
        int res;

        // don't hold the lock locally, we're proxying
        mboxname_release(&namespacelock);

        if (supports_referrals) {
            imapd_refer(tag, mbentry->server, name);
            referral_kick = 1;
            goto done;
        }

        s = proxy_findserver(mbentry->server, &imap_protocol,
                             proxy_userid, &backend_cached,
                             &backend_current, &backend_inbox, imapd_in);
        if (!s) r = IMAP_SERVER_UNAVAILABLE;

        if (!r) {
            prot_printf(s->out, "%s DELETE {" SIZE_T_FMT "+}\r\n%s\r\n",
                        tag, strlen(origname), origname);
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

        goto done;
    }

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
        else if (!isadmin && mbname_issystem(mbname)) {
            r = IMAP_PERMISSION_DENIED;
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
            if (!r) r = user_deletedata(mbentry, 1);
        }
    }

    if (!r && config_getswitch(IMAPOPT_DELETE_UNSUBSCRIBE)) {
        mboxlist_changesub(mbname_intname(mbname), imapd_userid, imapd_authstate,
                           /* add */ 0, /* force */ 1, /* notify? */ 0, /*silent*/1);
    }

    mboxname_release(&namespacelock);

    imapd_check(NULL, 0);

    if (r) {
        prot_printf(imapd_out, "%s NO %s\r\n", tag, error_message(r));
    }
    else {
        if (config_mupdate_server)
            kick_mupdate();

        index_release(imapd_index);
        sync_checkpoint(imapd_in);

        if (name != origname && (client_capa & CAPA_IMAP4REV2)) {
            /* Emit LIST response for name with OLDNAME */
            print_listresponse(LIST_CMD_EXTENDED, name, origname,
                               imapd_namespace.hier_sep,
                               MBOX_ATTRIBUTE_NONEXISTENT, NULL);
        }

        prot_printf(imapd_out, "%s OK %s\r\n", tag,
                    error_message(IMAP_OK_COMPLETED));
    }

  done:
    if (name != origname) free(name);
    mboxlist_entry_free(&mbentry);
    mbname_free(&mbname);
}

struct renrock
{
    const char *tag;
    const struct namespace *namespace;
    int ol;
    int nl;
    int rename_user;
    const char *olduser, *newuser;
    char *newmailboxname;
    const char *partition;
    int found;
    int noisy;
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
                               text->rename_user, /*keep_intermediaries*/1,
                               0, /*silent*/text->rename_user);

    if (!r && config_getswitch(IMAPOPT_DELETE_UNSUBSCRIBE)) {
        mboxlist_changesub(mbentry->name, imapd_userid, imapd_authstate,
                           /* add */ 0, /* force */ 1, /* notify? */ 0, /*silent*/1);
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
        if (text->noisy) {
            prot_printf(imapd_out,
                        "* OK [INPROGRESS (\"%s\" NIL NIL)] rename %s %s\r\n",
                        text->tag, oldextname, newextname);
            prot_flush(imapd_out);
        }
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
static void cmd_rename(char *tag, char *oldname, char *newname, char *location, int noisy)
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
    mbentry_t *olddestmbentry = NULL;
    mbentry_t *newdestmbentry = NULL;
    struct renrock rock = {0};
    const char *orig_oldname = oldname;
    const char *orig_newname = newname;
    struct listargs listargs = {
        LIST_CMD_EXTENDED, 0, LIST_RET_CHILDREN | LIST_RET_SPECIALUSE,
        "", STRARRAY_INITIALIZER, 0, {0}, STRARRAY_INITIALIZER, NULL
    };

    if (location && !imapd_userisadmin) {
        prot_printf(imapd_out, "%s NO %s\r\n", tag, error_message(IMAP_PERMISSION_DENIED));
        return;
    }

    if (client_capa & CAPA_IMAP4REV2) {
        oldname = normalize_mboxname(oldname, NULL);
        newname = normalize_mboxname(newname, &listargs);
    }
    else if (client_capa & CAPA_UTF8_ACCEPT) {
        oldname = normalize_mboxname(oldname, NULL);
        newname = normalize_mboxname(newname, NULL);
    }

    if (location && strcmp(oldname, newname)) {
        /* XXX It would be nice to not complain here iff the location
         * XXX is actually the mailbox's current partition, but we
         * XXX don't have that info until much later!
         */
        prot_printf(imapd_out,
                    "%s NO Cross-server or cross-partition move w/rename not supported\r\n",
                    tag);
        if (oldname != orig_oldname) free(oldname);
        if (newname != orig_newname) free(newname);
        strarray_fini(&listargs.pat);
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

        // don't hold the locks locally, we're proxying
        mboxname_release(&oldnamespacelock);
        mboxname_release(&newnamespacelock);

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
                        orig_oldname,
                        orig_newname,
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
                    orig_oldname,
                    orig_newname
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
        /* create the destination mailbox first - if it exists, then that's a reason to error */
        mbentry_t newmbentry = MBENTRY_INITIALIZER;
        newmbentry.name = (char *) newmailboxname;
        newmbentry.partition = mbentry->partition;
        newmbentry.mbtype = mbentry->mbtype;

        unsigned flags = MBOXLIST_CREATE_NOTIFY;
        r = mboxlist_createmailbox(&newmbentry, 0/*options*/, 0/*highestmodseq*/,
                                   imapd_userisadmin || imapd_userisproxyadmin,
                                   imapd_userid, imapd_authstate,
                                   flags, NULL/*mailboxptr*/);

        if (r) goto respond;

        /* existing imapd index, or open one to copy from */
        struct index_state *state = NULL;
        if (!strcmpnull(index_mboxname(imapd_index), oldmailboxname)) {
            state = imapd_index;
        }
        else {
            struct index_init init = {
                .out = imapd_out,
                .userid = imapd_userid,
                .authstate = imapd_authstate
            };
            r = index_open(oldmailboxname, &init, &state);
            seqset_free(&init.vanishedlist);
        }

        /* move all the emails to the new folder */
        char *copyuid = NULL;
        if (!r) {
            struct progress_rock prock = { &progress_cb, tag, time(0), 0 };

            r = index_copy(state, "1:*", 1 /*usinguid*/, newmailboxname,
                           &copyuid, !config_getswitch(IMAPOPT_SINGLEINSTANCESTORE),
                           &imapd_namespace,
                           (imapd_userisadmin || imapd_userisproxyadmin), 1/*ismove*/,
                           1/*ignorequota*/, &prock);
        }
        free(copyuid); // we don't care, but the API requires it

        if (state != imapd_index)
            index_close(&state);

        goto respond;
    }
    /* check if we're an admin renaming a user */
    else if (config_getswitch(IMAPOPT_ALLOWUSERMOVES) &&
             mboxname_isusermailbox(oldmailboxname, 1) &&
             mboxname_isusermailbox(newmailboxname, 1) &&
             strcmp(oldmailboxname, newmailboxname) && /* different user */
             imapd_userisadmin) {

        rename_user = 1;

        // we can't rename users if the new inbox already exists!
        r = mboxlist_lookup_allow_all(newmailboxname, &olddestmbentry, NULL);
        if (r == IMAP_MAILBOX_NONEXISTENT) {
            // all good, there's nothing here
        } else if (r) {
            // any other error, abort - something bad with mailboxesdb
            goto respond;
        } else if (olddestmbentry->mbtype & MBTYPE_DELETED) {
            // this is OK, we're replacing a tombstone - hold on to the old entry in case we need to recreate it
        }
        else {
            // can't rename over an existing mailbox - abort
            mboxlist_entry_free(&olddestmbentry);
            r = IMAP_MAILBOX_EXISTS;
            goto respond;
        }

        /* we need to create a reference for the uniqueid so we find the right
         * conversations DB */
        newdestmbentry = mboxlist_entry_copy(mbentry);
        free(newdestmbentry->name);
        newdestmbentry->name = xstrdup(newmailboxname);
        newdestmbentry->mbtype |= MBTYPE_DELETED;
        r = mboxlist_update_full(newdestmbentry, /*localonly*/1, /*silent*/1);
        if (r) goto respond;
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
        rock.tag = tag;
        rock.namespace = &imapd_namespace;
        rock.found = 0;
        rock.newmailboxname = nmbn;
        rock.ol = ol;
        rock.nl = nl;
        rock.olduser = olduser;
        rock.newuser = newuser;
        rock.partition = location;
        rock.rename_user = rename_user;
            rock.noisy = noisy;

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
                                   0, 0, rename_user, /*keep_intermediaries*/1,
                                   0, /*silent*/rename_user);

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
                               /* add */ 0, /* force */ 1, /* notify? */ 0, /*silent*/1);
        }
    }

    /* If we're renaming a user, take care of changing quotaroot and ACL */
    if (!r && rename_user) {
        user_copyquotaroot(oldmailboxname, newmailboxname);
        user_renameacl(&imapd_namespace, newmailboxname, olduser, newuser);
        if (mbtype & MBTYPE_LEGACY_DIRS) {
            /* Change seen state, subscriptions and sieve scripts */
            user_renamedata(olduser, newuser);
        }

        /* XXX report status/progress of meta-data */
    }

    /* rename all mailboxes matching this */
    if (!r && recursive_rename) {
            if (noisy) {
            prot_printf(imapd_out,
                        "* OK [INPROGRESS (\"%s\" NIL NIL)] rename %s %s\r\n",
                        tag, oldextname, newextname);
            prot_flush(imapd_out);
            }

submboxes:
        strcat(oldmailboxname, ".");
        strcat(newmailboxname, ".");

        /* setup the rock */
        rock.tag = tag;
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


    /* take care of deleting old quotas */
    if (!r && rename_user) {
        user_deletequotaroots(olduser);
        sync_log_unuser(olduser);
    }

    /* take care of intermediaries */
    mboxlist_update_intermediaries(oldmailboxname, mbtype, 0);
    mboxlist_update_intermediaries(newmailboxname, mbtype, 0);

respond:

    imapd_check(NULL, 0);

    if (r) {
        prot_printf(imapd_out, "%s NO %s\r\n", tag, error_message(r));
        xsyslog(LOG_NOTICE, "rename failed",
                "oldmboxname=<%s> newmboxname=<%s> error=<%s>",
                oldmailboxname, newmailboxname, error_message(r));
        // ensure the mboxlist entry gets fixed up or removed
        if (olddestmbentry) {
            int r2 = mboxlist_update_full(olddestmbentry, /*localonly*/1, /*silent*/1);
            if (r2)
                xsyslog(LOG_ERR, "IOERROR: replacing old destination tombstone after rename error",
                        "mboxname=<%s> error=<%s>", olddestmbentry->name, error_message(r2));
        } else if (newdestmbentry) {
            int r2 = mboxlist_delete(newdestmbentry);
            if (r2)
                xsyslog(LOG_ERR, "IOERROR: removing temporary uniqueid tombstone after rename error",
                        "mboxname=<%s> error=<%s>", newdestmbentry->name, error_message(r2));
        }
    } else {
        if (config_mupdate_server)
            kick_mupdate();

        if (rename_user)
            sync_log_user(newuser);

        index_release(imapd_index);
        sync_checkpoint(imapd_in);

        if (client_capa & CAPA_IMAP4REV2) {
            if (oldname != orig_oldname) {
                /* Emit LIST response for oldname with OLDNAME */
                print_listresponse(listargs.cmd, oldname, orig_oldname,
                                   imapd_namespace.hier_sep,
                                   MBOX_ATTRIBUTE_NONEXISTENT, NULL);
            }
            if (strarray_size(&listargs.pat)) {
                /* Emit LIST response for newname with OLDNAME */
                list_data(&listargs);
            }
        }

        prot_printf(imapd_out, "%s OK %s\r\n", tag,
                    error_message(IMAP_OK_COMPLETED));
    }

done:
    mboxname_release(&oldnamespacelock);
    mboxname_release(&newnamespacelock);
    // rename acls after the lock is dropped
    if (!r && rename_user)
        user_sharee_renameacls(&imapd_namespace, olduser, newuser);
    mboxlist_entry_free(&mbentry);
    mboxlist_entry_free(&olddestmbentry);
    mboxlist_entry_free(&newdestmbentry);
    if (oldname != orig_oldname) free(oldname);
    if (newname != orig_newname) free(newname);
    strarray_fini(&listargs.pat);
    free(oldextname);
    free(newextname);
    free(olduser);
    free(newuser);
}

static void cmd_raclmodseq(const char *tag, const char *userid)
{
    int r = 0;

    /* administrators only please */
    if (!imapd_userisadmin)
        r = IMAP_PERMISSION_DENIED;

    /* touch the modseq */
    if (!r) r = mboxlist_update_raclmodseq(userid);

    if (r) {
        prot_printf(imapd_out, "%s NO %s\r\n", tag, error_message(r));
    } else {
        prot_printf(imapd_out, "%s OK %s\r\n", tag,
                    error_message(IMAP_OK_COMPLETED));
    }
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
        if (mailbox_quotaroot(mailbox)) {
            strcpy(quotaroot, mailbox_quotaroot(mailbox));
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
        if (c <= EOF) {
            return;
        }
    }
    else
        prot_ungetc(c, imapd_in);

    if (!strcmpsafe(imapd_magicplus, "+")) listargs->sel |= LIST_SEL_SUBSCRIBED;
    else if (!strcasecmpsafe(imapd_magicplus, "+dav")) listargs->sel |= LIST_SEL_DAV;

    /* Read in reference name */
    c = getastring(imapd_in, imapd_out, &reference);
    if (c == IMAP_LITERAL_TOO_LARGE) goto maxliteral;
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
            if (prot_bytes_in(imapd_in) > maxargssize_mark)
                fatal(error_message(IMAP_ARGS_TOO_LARGE), EX_PROTOCOL);
            if (c == IMAP_LITERAL_TOO_LARGE) goto maxliteral;
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
        if (c == IMAP_LITERAL_TOO_LARGE) goto maxliteral;
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
        if (c <= EOF) {
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

  maxliteral:
    prot_printf(imapd_out, "%s NO %s in List\r\n",
                tag, error_message(IMAP_LITERAL_TOO_LARGE));

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

    if (listargs->cmd == LIST_CMD_XLIST)
        client_behavior_mask |= CB_XLIST;

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
 * Change a usergroup membership - either add (if non-zero) or remove (if add is
 * zero).  userid must NOT start with 'group:' and group must.
 */
static void cmd_changeusergroup(char *tag, char *userid, char *group, int add)
{
    const char *cmd = add ? "Setusergroup" : "Unsetusergroup";
    int r = 0;

    if (backend_inbox || (backend_inbox = proxy_findinboxserver(imapd_userid))) {
        imapd_check(backend_inbox, 0);

        if (!r) {
            prot_printf(backend_inbox->out,
                        "%s %s {" SIZE_T_FMT "+}\r\n%s"
                        " {" SIZE_T_FMT "+}\r\n%s\r\n",
                        tag, cmd,
                        strlen(userid), userid,
                        strlen(group), group);
            pipe_including_tag(backend_inbox, tag, 0);
        }
        else {
            prot_printf(imapd_out, "%s NO %s\r\n", tag, error_message(r));
        }

        return;
    }

    const char *canon_id = canonify_userid(userid, imapd_userid, NULL);
    if (canon_id && !strncmp(group, "group:", 6))
        r = mboxlist_set_usergroup(canon_id, group, add, /*silent*/0);
    else r = IMAP_MAILBOX_BADNAME;

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
            r = mboxlist_changesub(intname, imapd_userid, imapd_authstate, add, force, 1, 0);
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
 * Perform a GETUSERGROUP command
 */
static void cmd_getusergroup(const char *tag, const char *group)
{
    strarray_t groups = STRARRAY_INITIALIZER;
    int r = mboxlist_lookup_usergroups(group, &groups);
    int i;

    if (r) {
        prot_printf(imapd_out, "%s NO %s\r\n", tag, error_message(r));
        return;
    }

    prot_printf(imapd_out, "* USERGROUP ");
    prot_printastring(imapd_out, group);
    prot_printf(imapd_out, " (");
    for (i = 0; i < strarray_size(&groups); i++) {
        if (i) prot_putc(' ', imapd_out);
        prot_printastring(imapd_out, strarray_nth(&groups, i));
    }

    prot_printf(imapd_out, ")\r\n");

    prot_printf(imapd_out, "%s OK %s\r\n", tag,
                error_message(IMAP_OK_COMPLETED));

    strarray_fini(&groups);
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
    struct mboxlock *namespacelock = mboxname_usernamespacelock(intname);

    /* is it remote? */
    r = mlookup(tag, name, intname, &mbentry);
    if (r == IMAP_MAILBOX_MOVED) goto done;

    if (!config_getswitch(IMAPOPT_ALLOWSETACL))
        r = IMAP_DISABLED;

    if (!r && (mbentry->mbtype & MBTYPE_REMOTE)) {
        /* remote mailbox */
        struct backend *s = NULL;
        int res;

        // don't hold the lock locally, we're calling remote
        mboxname_release(&namespacelock);

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
    mboxname_release(&namespacelock);
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
            myrights = cyrus_acl_myrights(imapd_authstate, mailbox_acl(mailbox));
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
        const char *quotaroot = mailbox_quotaroot(mailbox);
        if (quotaroot) {
            struct quota q;
            char *extname = mboxname_to_external(quotaroot, &imapd_namespace, imapd_userid);
            prot_printf(imapd_out, " ");
            prot_printastring(imapd_out, extname);
            quota_init(&q, quotaroot);
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

    /* Parse the arguments as a setquota_list */
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
        /* note: we accept >= 0 according to RFC 9208,
         * and also -1 to fix Bug #3559 */
        if (limit < -1) goto badlist;
        newquotas[res] = limit;
        if (c == ')') break;
        else if (c != ' ') goto badlist;

        if (prot_bytes_in(imapd_in) > maxargssize_mark)
            fatal(error_message(IMAP_ARGS_TOO_LARGE), EX_PROTOCOL);
    }
    c = prot_getc(imapd_in);
    if (!IS_EOL(c, imapd_in)) {
        prot_printf(imapd_out, "%s BAD Unexpected extra arguments to SETQUOTA\r\n", tag);
        eatline(imapd_in, c);
        return;
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
        const char * const *qnames;
        char sep = '(';

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

        qnames = CAPA(s, CAPA_QUOTASET) ? quota_names : legacy_quota_names;

        prot_printf(s->out, "%s Setquota ", tag);
        prot_printstring(s->out, quotaroot);
        prot_putc(' ', s->out);
        for (res = 0; res < QUOTA_NUMRESOURCES; res++) {
            prot_printf(s->out, "%c%s " QUOTA_T_FMT,
                        sep, qnames[res], newquotas[res]);
            sep = ' ';
        }
        prot_puts(s->out, ")\r\n");
        pipe_including_tag(s, tag, 0);

        free(intname);
        return;

    }
    mboxlist_entry_free(&mbentry);

    /* local mailbox */
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
static const struct tls_alpn_t imap_alpn_map[] = {
    { "imap", NULL, NULL },
    { "",     NULL, NULL }
};

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

    SSL_CTX *ctx = NULL;
    result=tls_init_serverengine("imap",
                                 5,        /* depth to verify */
                                 !imaps,   /* can client auth? */
                                 &ctx);

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

    result = tls_start_servertls(0, /* read */
                                 1, /* write */
                                 imaps ? 180 : imapd_timeout,
                                 &saslprops,
                                 imap_alpn_map,
                                 &tls_conn);

    /* put the iplocalport and ipremoteport back */
    if (localip)  buf_initm(&saslprops.iplocalport, localip, strlen(localip));
    if (remoteip) buf_initm(&saslprops.ipremoteport, remoteip, strlen(remoteip));

    /* if error */
    if (result==-1) {
        syslog(LOG_NOTICE, "TLS negotiation failed: %s", imapd_clienthost);
        shut_down(EX_PROTOCOL);
    }

    /* tell SASL about the negotiated layer */
    result = saslprops_set_tls(&saslprops, imapd_saslconn);

    if (result != SASL_OK) {
        syslog(LOG_NOTICE, "saslprops_set_tls() failed: cmd_starttls()");
        shut_down(EX_TEMPFAIL);
    }

    /* tell the prot layer about our new layers */
    prot_settls(imapd_in, tls_conn);
    prot_settls(imapd_out, tls_conn);

    imapd_starttls_done = 1;
    imapd_login_disabled = imapd_starttls_allowed = imapd_tls_required = 0;

    imapd_tls_comp = (void *) SSL_get_current_compression(tls_conn);
    if (imapd_tls_comp) imapd_compress_allowed = 0;
}
#else
void cmd_starttls(char *tag __attribute__((unused)),
                  int imaps __attribute__((unused)))
{
    fatal("cmd_starttls() executed, but starttls isn't implemented!",
          EX_SOFTWARE);
}
#endif // HAVE_SSL

static int parse_statusitems(unsigned *statusitemsp, const char **errstr)
{
    static struct buf arg;
    unsigned statusitems = 0;
    int c;

    c = prot_getc(imapd_in);
    if (c != '(') goto bad;

    c = getword(imapd_in, &arg);
    if (arg.s[0] == '\0') goto bad;
    for (;;) {
        if (prot_bytes_in(imapd_in) > maxargssize_mark)
            fatal(error_message(IMAP_ARGS_TOO_LARGE), EX_PROTOCOL);

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
        else if (!strcmp(arg.s, "highestmodseq")) {    /* RFC 7162 */
            statusitems |= STATUS_HIGHESTMODSEQ;
        }
        else if (!strcmp(arg.s, "appendlimit")) {      /* RFC 7889 */
            statusitems |= STATUS_APPENDLIMIT;
        }
        else if (!strcmp(arg.s, "size")) {             /* RFC 8438 */
            statusitems |= STATUS_SIZE;
        }
        else if (!strcmp(arg.s, "mailboxid")) {        /* RFC 8474 */
            statusitems |= STATUS_MAILBOXID;
        }
        else if (!strcmp(arg.s, "deleted")) {          /* RFC 9051 */
            statusitems |= STATUS_DELETED;
        }
        else if (!strcmp(arg.s, "deleted-storage")) {  /* RFC 9208 */
            statusitems |= STATUS_DELETED_STORAGE;
        }
        else if (!strcmp(arg.s, "createdmodseq")) {    /* Non-standard */
            statusitems |= STATUS_CREATEDMODSEQ;
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
    if (statusitems & STATUS_UNSEEN) {
        prot_printf(imapd_out, "%cUNSEEN %u", sepchar, sd->unseen);
        sepchar = ' ';
    }
    if (statusitems & STATUS_HIGHESTMODSEQ) {    /* RFC 7162 */
        prot_printf(imapd_out, "%cHIGHESTMODSEQ " MODSEQ_FMT,
                    sepchar, sd->highestmodseq);
        sepchar = ' ';
    }
    if (statusitems & STATUS_APPENDLIMIT) {      /* RFC 7889 */
        prot_printf(imapd_out, "%cAPPENDLIMIT %" PRIi64, sepchar, maxmsgsize);
        sepchar = ' ';
    }
    if (statusitems & STATUS_SIZE) {             /* RFC 8438 */
        prot_printf(imapd_out, "%cSIZE " QUOTA_T_FMT, sepchar, sd->size);
        sepchar = ' ';
    }
    if (statusitems & STATUS_MAILBOXID) {        /* RFC 8474 */
        prot_printf(imapd_out, "%cMAILBOXID (%s)", sepchar, sd->mailboxid);
        sepchar = ' ';
    }
    if (statusitems & STATUS_DELETED) {          /* RFC 9051 */
        prot_printf(imapd_out, "%cDELETED %u", sepchar, sd->deleted);
        sepchar = ' ';
    }
    if (statusitems & STATUS_DELETED_STORAGE) {  /* RFC 9208 */
        prot_printf(imapd_out, "%cDELETED-STORAGE " QUOTA_T_FMT,
                    sepchar, sd->deleted_storage);
        sepchar = ' ';
    }
    if (statusitems & STATUS_CREATEDMODSEQ) {    /* Non-standard */
        prot_printf(imapd_out, "%cCREATEDMODSEQ " MODSEQ_FMT,
                    sepchar, sd->createdmodseq);
        sepchar = ' ';
    }

    prot_printf(imapd_out, ")\r\n");

    return 0;
}

static int imapd_statusdata(const mbentry_t *mbentry, unsigned statusitems,
                            struct statusdata *sd)
{
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

            imapd_check(s, TELL_EXPUNGED);

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

    if (statusitems & STATUS_HIGHESTMODSEQ)
        condstore_enabled("STATUS (HIGHESTMODSEQ)");

    if (statusitems & STATUS_MAILBOXID)
        client_behavior_mask |= CB_OBJECTID;

    /* check permissions */
    if (!r) {
        int myrights = cyrus_acl_myrights(imapd_authstate, mbentry->acl);

        if (!(myrights & ACL_READ)) {
            r = (imapd_userisadmin || (myrights & ACL_LOOKUP)) ?
                IMAP_PERMISSION_DENIED : IMAP_MAILBOX_NONEXISTENT;
        }
    }

    // status of selected mailbox, we need to refresh
    if (!r && !strcmpsafe(mbentry->name, index_mboxname(imapd_index)))
        imapd_check(NULL, TELL_EXPUNGED);

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
            if (prot_bytes_in(imapd_in) > maxargssize_mark)
                fatal(error_message(IMAP_ARGS_TOO_LARGE), EX_PROTOCOL);

            name = ucase(arg.s);
            if (c != ' ') goto fail;
            c = prot_getc(imapd_in);
            if (c == '(') {
                /* fun - more lists! */
                sub = dlist_newlist(res, name);
                do {
                    c = getword(imapd_in, &val);
                    if (prot_bytes_in(imapd_in) > maxargssize_mark)
                        fatal(error_message(IMAP_ARGS_TOO_LARGE), EX_PROTOCOL);

                    dlist_setatom(sub, name, val.s);
                } while (c == ' ');
                if (c != ')') goto fail;
                c = prot_getc(imapd_in);
            }
            else {
                prot_ungetc(c, imapd_in);
                if (!strcmp(name, "VERSION")) {
                    uint32_t ver = 0;
                    c = getuint32(imapd_in, &ver);
                    dlist_setnum32(res, name, ver);
                }
                else {
                    c = getword(imapd_in, &val);
                    dlist_setatom(res, name, val.s);
                }
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
            if (prot_bytes_in(imapd_in) > maxargssize_mark)
                fatal(error_message(IMAP_ARGS_TOO_LARGE), EX_PROTOCOL);
            if (c == IMAP_LITERAL_TOO_LARGE) goto maxliteral;
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
        if (c == IMAP_LITERAL_TOO_LARGE) goto maxliteral;
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
            if (prot_bytes_in(imapd_in) > maxargssize_mark)
                fatal(error_message(IMAP_ARGS_TOO_LARGE), EX_PROTOCOL);
            if (c == IMAP_LITERAL_TOO_LARGE) goto maxliteral;
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
        if (c == IMAP_LITERAL_TOO_LARGE) goto maxliteral;
        if (c == EOF) {
            prot_printf(imapd_out,
                        "%s BAD Missing annotation attribute\r\n", tag);
            goto baddata;
        }

        strarray_append(attribs, arg.s);
   }

    return c;

  baddata:
    eatline(imapd_in, c);
    return EOF;

  maxliteral:
    prot_printf(imapd_out, "%s NO %s in annotation entry\r\n",
                tag, error_message(IMAP_LITERAL_TOO_LARGE));
    return IMAP_LITERAL_TOO_LARGE;
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
            if (prot_bytes_in(imapd_in) > maxargssize_mark)
                fatal(error_message(IMAP_ARGS_TOO_LARGE), EX_PROTOCOL);
            if (c == IMAP_LITERAL_TOO_LARGE) goto maxliteral;
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
        if (c == IMAP_LITERAL_TOO_LARGE)  goto maxliteral;
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
    eatline(imapd_in, c);
    return EOF;

  maxliteral:
    prot_printf(imapd_out, "%s NO %s in metadata entry\r\n",
                tag, error_message(IMAP_LITERAL_TOO_LARGE));
    return IMAP_LITERAL_TOO_LARGE;
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
        if (prot_bytes_in(imapd_in) > maxargssize_mark)
            fatal(error_message(IMAP_ARGS_TOO_LARGE), EX_PROTOCOL);
        if (c == IMAP_LITERAL_TOO_LARGE) goto maxliteral;
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
            if (c == IMAP_LITERAL_TOO_LARGE) goto maxliteral;
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
            if (c == IMAP_LITERAL_TOO_LARGE) goto maxliteral;
            if (c == EOF) {
                prot_printf(imapd_out,
                            "%s BAD Missing annotation value\r\n", tag);
                goto baddata;
            }

            if (prot_bytes_in(imapd_in) > maxargssize_mark)
                fatal(error_message(IMAP_ARGS_TOO_LARGE), EX_PROTOCOL);

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
    eatline(imapd_in, c);
    return EOF;

  maxliteral:
    if (attvalues) freeattvalues(attvalues);
    prot_printf(imapd_out, "%s NO %s in annotation entry\r\n",
                tag, error_message(IMAP_LITERAL_TOO_LARGE));
    return IMAP_LITERAL_TOO_LARGE;
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
        if (prot_bytes_in(imapd_in) > maxargssize_mark)
            fatal(error_message(IMAP_ARGS_TOO_LARGE), EX_PROTOCOL);
        if (c == IMAP_LITERAL_TOO_LARGE) goto maxliteral;
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
        if (prot_bytes_in(imapd_in) > maxargssize_mark)
            fatal(error_message(IMAP_ARGS_TOO_LARGE), EX_PROTOCOL);
        if (c == IMAP_LITERAL_TOO_LARGE) goto maxliteral;
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
                    "%s BAD Missing close paren in metadata entry list \r\n",
                    tag);
        goto baddata;
    }

    c = prot_getc(imapd_in);

    return c;

  baddata:
    if (attvalues) freeattvalues(attvalues);
    eatline(imapd_in, c);
    return EOF;

  maxliteral:
    if (attvalues) freeattvalues(attvalues);
    prot_printf(imapd_out, "%s NO %s in metadata entry\r\n",
                tag, error_message(IMAP_LITERAL_TOO_LARGE));
    return IMAP_LITERAL_TOO_LARGE;
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
    unsigned want_dav : 1;
};

static int apply_cb(struct findall_data *data, void* rock)
{
    if (!data) return 0;
    if (!data->is_exactmatch) return 0;

    struct apply_rock *arock = (struct apply_rock *)rock;
    annotate_state_t *state = arock->state;
    int r;

    if (!arock->want_dav && mbtype_isa(data->mbentry->mbtype) != MBTYPE_EMAIL) {
        return 0;
    }

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
    arock.want_dav = !strcasecmpsafe(imapd_magicplus, "+dav");

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

    client_behavior_mask |= CB_ANNOTATE;

    c = parse_annotate_fetch_data(tag, /*permessage_flag*/0, &entries, &attribs);
    if (c <= EOF) {
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
    int c = 0, r = 0;
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

    client_behavior_mask |= CB_METADATA;

    while (nlists < 3)
    {
        c = parse_metadata_string_or_list(tag, &lists[nlists], &is_list[nlists]);
        if (c <= EOF) goto freeargs;

        nlists++;
        if (c == '\r')
            break;
    }

    /* check for CRLF */
    if (c == '\r') {

        c = prot_getc(imapd_in);

        if (c != '\n') {
            prot_printf(imapd_out,
                        "%s BAD Unexpected extra arguments to Getmetadata\r\n",
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

    client_behavior_mask |= CB_ANNOTATE;

    c = parse_annotate_store_data(tag, 0, &entryatts);
    if (c <= EOF) {
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

    client_behavior_mask |= CB_METADATA;

    c = parse_metadata_store_data(tag, &entryatts);
    if (c <= EOF) {
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
    seqset_t *uids = NULL;
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
    if (c == IMAP_LITERAL_TOO_LARGE) {
        prot_printf(imapd_out, "%s NO %s in Xwarmup\r\n", tag, error_message(c));
        goto out_noprint;
    }
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
    seqset_free(&uids);
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
    struct mboxlock *namespacelock = mboxname_usernamespacelock(mbname_intname(mbname));

    /* administrators only please */
    if (!imapd_userisadmin)
        r = IMAP_PERMISSION_DENIED;

    if (!r) r = mlookup(tag, name, mbname_intname(mbname), NULL);

    if (!r) r = undump_mailbox(mbname_intname(mbname), imapd_in, imapd_out, imapd_authstate);

    if (r) {
        prot_printf(imapd_out, "%s NO %s%s\r\n",
                    tag,
                    (r == IMAP_MAILBOX_NONEXISTENT &&
                     mboxlist_createmailboxcheck(mbname_intname(mbname), 0, 0,
                                                 imapd_userisadmin,
                                                 imapd_userid, imapd_authstate,
                                                 NULL, NULL, 0) == 0)
                    ? "[TRYCREATE] " : "", error_message(r));
    }
    else {
        prot_printf(imapd_out, "%s OK %s\r\n", tag,
                    error_message(IMAP_OK_COMPLETED));
    }

    mboxname_release(&namespacelock);
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

enum mupdate_op {
    MUPDATE_ACTIVATE,
    MUPDATE_DEACTIVATE,
    MUPDATE_DELETE
};

static int xfer_mupdate(enum mupdate_op op,
                        const char *mboxname, const char *part,
                        const char *servername, const char *acl)
{
    char buf[MAX_PARTITION_LEN+HOSTNAME_SIZE+2];
    int retry = 0;
    int r = 0;

    /* no mupdate handle */
    if (!mupdate_h) return 0;

    if (servername && part)
        snprintf(buf, sizeof(buf), "%s!%s", servername, part);

retry:
    /* make the change */
    if (op == MUPDATE_DELETE)
        r = mupdate_delete(mupdate_h, mboxname);
    else if (op == MUPDATE_ACTIVATE)
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
    if (CAPA(be, CAPA_REPLICATION)) {
        syslog(LOG_INFO, "XFER: destination supports replication");
        xfer->use_replication = 1;
        be->in->userdata = be->out->userdata = &xfer->sync_cs.tagbuf;

        if (CAPA(be, CAPA_SIEVE_MAILBOX)) {
            syslog(LOG_INFO, "XFER: destination supports #sieve mailbox");
            sync_do_enable(&xfer->sync_cs, CAPA_SIEVE_MAILBOX);
        }
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
    seqset_t *outlist = NULL;
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

    r = seen_write(seendb, mailbox_uniqueid(mailbox), &sd);

    seen_freedata(&sd);
    seqset_free(&outlist);

    return r;
}

static int xfer_deactivate(struct xfer_header *xfer)
{
    struct xfer_item *item;
    int r;

    syslog(LOG_INFO, "XFER: deactivating mailboxes");

    /* Step 3: mupdate.DEACTIVATE(mailbox, newserver) */
    for (item = xfer->items; item; item = item->next) {
        r = xfer_mupdate(MUPDATE_DEACTIVATE, item->mbentry->name,
                         item->mbentry->partition, config_servername, NULL);
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
        r = mboxlist_updatelock(newentry, 1);
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

    if (!topart) topart = mailbox_partition(mailbox);
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
                         mailbox_uniqueid(mailbox), mailbox_name(mailbox),
                         mailbox_mbtype(mailbox),
                         mailbox_partition(mailbox),
                         mailbox_acl(mailbox),
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
                         mailbox_foldermodseq(mailbox),
                         /* groups */ NULL,
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
        if (mbtype_isa(item->mbentry->mbtype) == MBTYPE_SIEVE &&
            !(xfer->sync_cs.flags & SYNC_FLAG_SIEVE_MAILBOX)) {
            /* Ignore #sieve mailbox - replicated via *SIEVE* commands */
            continue;
        }

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
                const char *quotaroot = mailbox_quotaroot(mailbox);
                if (quotaroot)
                    sync_name_list_add(master_quotaroots, quotaroot);

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
        if (!r && !(xfer->sync_cs.flags & SYNC_FLAG_SIEVE_MAILBOX)) {
            r = sync_do_user_sieve(&xfer->sync_cs, xfer->userid, replica_sieve);
        }
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
        if (mbtype_isa(item->mbentry->mbtype) == MBTYPE_SIEVE &&
            !(xfer->sync_cs.flags & SYNC_FLAG_SIEVE_MAILBOX)) {
            /* Don't activate #sieve on remote, remove it from mupdate */
            r = xfer_mupdate(MUPDATE_DELETE, item->mbentry->name,
                             NULL, NULL, NULL);
            if (r) {
                syslog(LOG_ERR, "MUPDATE: can't delete mailbox entry '%s': %s",
                           item->mbentry->name, error_message(r));
            }
            continue;
        }

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
    struct xfer_item *item;
    int r;

    syslog(LOG_INFO, "XFER: deleting mailboxes on source");

    /* 7) local delete of mailbox
     * & remove local "remote" mailboxlist entry */
    for (item = xfer->items; item; item = item->next) {
        /* Note that we do not check the ACL, and we don't update MUPDATE */
        /* note also that we need to remember to let proxyadmins do this */
        /* On a unified system, the subsequent MUPDATE PUSH on the remote
           should repopulate the local mboxlist entry */
        r = mboxlist_deletemailboxlock(item->mbentry->name,
                                   imapd_userisadmin || imapd_userisproxyadmin,
                                   imapd_userid, imapd_authstate, NULL,
                                   MBOXLIST_DELETE_LOCALONLY|MBOXLIST_DELETE_FORCE);
        if (r) {
            syslog(LOG_ERR,
                   "Could not delete local mailbox during move of %s: %s",
                   item->mbentry->name, error_message(r));
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
            r = mboxlist_updatelock(item->mbentry, 1);

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
            r = xfer_mupdate(MUPDATE_ACTIVATE, item->mbentry->name,
                             item->mbentry->partition,
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

    /* Only add shared mailboxes or user INBOXes */
    if (!mbname_localpart(data->mbname) ||
        (!mbname_isdeleted(data->mbname) && !strarray_size(mbname_boxes(data->mbname)))) {
        const char *extname = mbname_extname(data->mbname, list->ns, list->userid);
        struct xfer_item *mbox = xzmalloc(sizeof(struct xfer_item));

        mbox->mbentry = mboxlist_entry_copy(data->mbentry);
        xstrncpy(mbox->extname, extname, sizeof(mbox->extname));
        if (mbname_localpart(data->mbname)) {
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
    struct xfer_list list = { &imapd_namespace, imapd_userid, NULL, NULL };
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
            r = IMAP_MAILBOX_NOTSUPPORTED;
            goto done;
        }

        /* admin namespace, use original name */
        mboxlist_findall(NULL, name, 1, NULL, NULL, xfer_addmbox, &list);
    }

    /* bail out if we didn't find anything to do */
    if (!list.mboxes) {
        r = IMAP_MAILBOX_NONEXISTENT;
        goto done;
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

        if (mbtype_isa(mbentry->mbtype) == MBTYPE_SIEVE &&
            !(xfer->use_replication & SYNC_FLAG_SIEVE_MAILBOX)) {
            /* Ignore #sieve mailbox - replicated via *SIEVE* commands */
            mboxlist_entry_free(&mbentry);
            next = item->next;
            free(item);
            continue;
        }

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
                if (r) {
                    mboxname_release(&namespacelock);
                    goto next;
                }

                /* backport the seen file if needed */
                if (xfer->remoteversion < 12) {
                    r = seen_open(xfer->userid, SEEN_CREATE, &xfer->seendb);
                    if (r) {
                        mboxname_release(&namespacelock);
                        goto next;
                    }
                }
            }
            mbentry_t *inbox_mbentry = NULL;
            char *inbox = mboxname_user_mbox(xfer->userid, 0);
            r = mboxlist_lookup_allow_all(inbox, &inbox_mbentry, NULL);
            free(inbox);
            if (r) {
                mboxname_release(&namespacelock);
                mboxlist_entry_free(&inbox_mbentry);
                goto next;
            }

            r = mboxlist_usermboxtree(xfer->userid, NULL, xfer_addusermbox,
                                      xfer, MBOXTREE_DELETED);

            /* NOTE: mailboxes were added in reverse, so the inbox is
             * done last */
            if (!r) r = do_xfer(xfer);

            if (!r) {
                /* this was a successful user move, and we need to delete
                   certain user meta-data (but not seen state!) */
                syslog(LOG_INFO, "XFER: deleting user metadata");
                user_deletedata(inbox_mbentry, 0);
            }
            mboxname_release(&namespacelock);
            mboxlist_entry_free(&inbox_mbentry);
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

        if (xfer->use_replication && (xfer->userid || mbox_count > 1000)) {
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
        if (prot_bytes_in(imapd_in) > maxargssize_mark)
            fatal(error_message(IMAP_ARGS_TOO_LARGE), EX_PROTOCOL);

        if (n >= nsort - 1) {   /* leave room for implicit criterion */
            /* (Re)allocate an array for sort criteria */
            int new_size = nsort + SORTGROWSIZE;
            *sortcrit = xzrealloc(*sortcrit,
                                  nsort * sizeof(struct sortcrit),
                                  new_size * sizeof(struct sortcrit));
            nsort = new_size;
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
            if (c == IMAP_LITERAL_TOO_LARGE) return c;
            if (c != ' ') goto missingarg;
            (*sortcrit)[n].args.annot.entry = xstrdup(criteria.s);
            c = getastring(imapd_in, imapd_out, &criteria);
            if (c == IMAP_LITERAL_TOO_LARGE) return c;
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
            if (c == IMAP_LITERAL_TOO_LARGE) return c;
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
            if (c == IMAP_LITERAL_TOO_LARGE) return c;
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

        if (prot_bytes_in(imapd_in) > maxargssize_mark)
            fatal(error_message(IMAP_ARGS_TOO_LARGE), EX_PROTOCOL);
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
            if (c <= EOF) return c;
            parse_getmetadata_options(&options, &opts);
            args->metaopts = opts;
            strarray_fini(&options);
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
    eatline(imapd_in, c);
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

        if (prot_bytes_in(imapd_in) > maxargssize_mark)
            fatal(error_message(IMAP_ARGS_TOO_LARGE), EX_PROTOCOL);
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
            if (c <= EOF) return c;
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
    eatline(imapd_in, c);
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

    /* Do we need to add the OLDNAME extended data item? */
    char *oldname = NULL;
    if (listargs->denormalized) {
        /* IMAP4rev2 client used a denormalized mailbox name */
        oldname = xstrdup(listargs->denormalized);
    }
    else if (client_capa & CAPA_IMAP4REV2) {
        /* Has this mailbox been renamed?
           XXX  We store the name history in the I record. */
        mbentry_t *id_mbe = NULL;
        mboxlist_lookup_by_uniqueid(mbentry->uniqueid, &id_mbe, NULL);
        if (id_mbe && ptrarray_size(&id_mbe->name_history)) {
            former_name_t *histitem = ptrarray_nth(&id_mbe->name_history, 0);
            oldname = mboxname_to_external(histitem->name,
                                           &imapd_namespace, imapd_userid);
        }
        mboxlist_entry_free(&id_mbe);
    }

    print_listresponse(listargs->cmd, extname, oldname,
                       imapd_namespace.hier_sep, attributes, &specialuse);
    buf_free(&specialuse);
    free(oldname);

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
        if (listargs->ret &
            (LIST_RET_SPECIALUSE | LIST_RET_STATUS | LIST_RET_METADATA)) {
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

                /* Send LIST command to backend */
                list_data_remote(s, mytag, listargs, rock->subs);
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

static int is_noinferiors(struct findall_data *data, struct list_rock *rock)
{
    int r = 0;

    if (data->mb_category == MBNAME_ALTINBOX)
        return 1;

    if (strarray_size(rock->special_nochildren)) {
        struct buf attrib = BUF_INITIALIZER;

        annotatemore_lookup(mbname_intname(data->mbname), "/specialuse",
                            mbname_userid(data->mbname), &attrib);
        if (buf_len(&attrib)) {
            strarray_t *uses = strarray_split(buf_cstring(&attrib), NULL, 0);

            if (strarray_intersect(uses, rock->special_nochildren)) {
                r = 1;
            }
            strarray_free(uses);
        }
        buf_free(&attrib);
    }

    return r;
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

    else if (is_noinferiors(data, rock))
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
        if (is_noinferiors(data, rock))
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
                mboxname_isdavnotificationsmailbox(intname, 0) ||
                mboxname_issievemailbox(intname, 0);

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

        rock.special_nochildren =
            strarray_split(config_getstring(IMAPOPT_SPECIALUSE_NOCHILDREN),
                           NULL, STRARRAY_TRIM);

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
        strarray_free(rock.special_nochildren);
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
                "special-use", "", "", "", "", "", "", "", "",
                "vendor.cmu-dav", "metadata", "vendor.fm-include-nonexistent",
                "vendor.cmu-include-deleted", NULL
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
                    "messages", "recent", "uidnext", "uidvalidity", "unseen",
                    "highestmodseq", "appendlimit", "size", "mailboxid",
                    "deleted", "deleted-storage",
                    "", "", "",  // placeholders for unused bits
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
        if (c == IMAP_LITERAL_TOO_LARGE) {
            prot_printf(imapd_out, "%s NO %s in Urlfetch\r\n",
                        tag, error_message(c));
            return;
        }
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
        } else if (!url.uid || !(msgno = index_finduid(state, url.uid, FIND_EQ))) {
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
        if (c == IMAP_LITERAL_TOO_LARGE) {
            prot_printf(imapd_out, "%s NO %s in Genurlauth\r\n",
                        tag, error_message(c));
            return;
        }
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
                        tag, arg1.s,
                        r == IMAP_BADURL ? error_message(r) : cyrusdb_strerror(r));
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
    client_behavior_mask |= CB_COMPRESS;

    if (imapd_compress_done) {
        prot_printf(imapd_out,
                    "%s BAD [COMPRESSIONACTIVE] DEFLATE active via COMPRESS\r\n",
                    tag);
    }
    else if (imapd_tls_comp) {
        prot_printf(imapd_out,
                    "%s NO [COMPRESSIONACTIVE] %s active via TLS\r\n",
                    tag, SSL_COMP_get_name(imapd_tls_comp));
    }
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

        xsyslog(LOG_INFO, "compression enabled",
                          "sessionid=<%s> userid=<%s> algorithm=<%s>",
                          session_id(),
                          imapd_userid ? imapd_userid : "",
                          alg);

        /* enable (de)compression for the prot layer */
        prot_setcompress(imapd_in);
        prot_setcompress(imapd_out);

        imapd_compress_done = 1;
        imapd_compress_allowed = 0;
    }
}
#endif /* HAVE_ZLIB */

static void cmd_enable(char *tag)
{
    static struct buf arg;
    int c;
    unsigned new_capa = 0;

    /* RFC 5161/9051 say that enable while selected is actually bogus,
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
        if (!strcasecmp(arg.s, "condstore")) {
            client_behavior_mask |= CB_CONDSTORE;
            new_capa |= CAPA_CONDSTORE;
        }
        else if (!strcasecmp(arg.s, "qresync")) {
            client_behavior_mask |= CB_QRESYNC;
            new_capa |= CAPA_QRESYNC | CAPA_CONDSTORE;
        }
        else if (!strcasecmp(arg.s, "imap4rev2")) {
            client_behavior_mask |= CB_IMAP4REV2;
            new_capa |= CAPA_IMAP4REV2;
        }
        else if (!strcasecmp(arg.s, "uidonly")) {
            client_behavior_mask |= CB_UIDONLY;
            new_capa |= CAPA_UIDONLY;
        }
        else if (imapd_utf8_allowed && !strcasecmp(arg.s, "utf8=accept")) {
            client_behavior_mask |= CB_UTF8ACCEPT;
            new_capa |= CAPA_UTF8_ACCEPT;
        }
    } while (c == ' ');

    /* check for CRLF */
    if (!IS_EOL(c, imapd_in)) {
        prot_printf(imapd_out,
                    "%s BAD Unexpected extra arguments to Enable\r\n", tag);
        eatline(imapd_in, c);
        return;
    }

    /* filter out already enabled extensions */
    new_capa ^= client_capa;

    if (new_capa & (CAPA_UTF8_ACCEPT | CAPA_IMAP4REV2)) {
        imapd_namespace.isutf8 = 1;

        if (new_capa & CAPA_IMAP4REV2) {
            /* Tell idled to start sending mailbox updates */
            strarray_t key = { 1, 0, &imapd_userid }; // avoid memory alloc

            idle_start(IMAP_NOTIFY_MAILBOX, 0, FILTER_PERSONAL, &key);
        }
    }

    if (ptrarray_size(&backend_cached)) {
        /* ENABLE on all remote mailboxes */
        for (int i = 0; i < ptrarray_size(&backend_cached); i++) {
            struct backend *be = ptrarray_nth(&backend_cached, i);

            prot_printf(be->out, "%s ENABLE", tag);
            prot_print_client_capa(be->out, new_capa);
            prot_puts(be->out, "\r\n");
            pipe_until_tag(be, tag, 0);
        }
    }
    else {
        /* RFC 9051, 6.3.1:
         * The ENABLED response is sent even if no extensions were enabled. */
        prot_puts(imapd_out, "* ENABLED");
        prot_print_client_capa(imapd_out, new_capa);
        prot_puts(imapd_out, "\r\n");
    }

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
        0 /* flags */
    };

    if (sync_sieve_mailbox_enabled) {
        sync_state.flags |= SYNC_FLAG_SIEVE_MAILBOX;
    }
    if (sync_archive_enabled) {
        sync_state.flags |= SYNC_FLAG_ARCHIVE;
    }

    const char *resp = sync_apply(kin, reserve_list, &sync_state);

    if (sync_state.flags & SYNC_FLAG_SIEVE_MAILBOX) {
        sync_sieve_mailbox_enabled = 1;
    }
    if (sync_state.flags & SYNC_FLAG_ARCHIVE) {
        sync_archive_enabled = 1;
    }

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
        0 /* flags */
    };

    if (sync_sieve_mailbox_enabled) {
        sync_state.flags |= SYNC_FLAG_SIEVE_MAILBOX;
    }
    if (sync_archive_enabled) {
        sync_state.flags |= SYNC_FLAG_ARCHIVE;
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

            xunlink(msg->fname);
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
        0 /* flags */
    };

    if (sync_sieve_mailbox_enabled) {
        sync_state.flags |= SYNC_FLAG_SIEVE_MAILBOX;
    }
    if (sync_archive_enabled) {
        sync_state.flags |= SYNC_FLAG_ARCHIVE;
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

    buf_free(&applepushserviceargs->aps_account_id);
    buf_free(&applepushserviceargs->aps_device_token);
    buf_free(&applepushserviceargs->aps_subtopic);
    strarray_fini(&applepushserviceargs->mailboxes);
    strarray_fini(&notif_mailboxes);
}

static void uid_cb(uint32_t seqno __attribute__((unused)),
                   unsigned item, void *datap, void *rock)
{
    uint32_t *uid = (uint32_t *) rock;

    if (item == FETCH_UID) {
        *uid = *((uint32_t *) datap);
    }
}

static void cmd_replace(char *tag, char *seqno, char *name, int usinguid)
{
    struct buf buf = BUF_INITIALIZER;
    mbentry_t *mbentry = NULL;
    const char *uidseq = NULL;
    uint32_t uid = 0, msgno;
    char *intname = NULL;
    int r = 0;

    client_behavior_mask |= CB_REPLACE;

    /* Need permission to delete message and seqno must be valid */
    if (backend_current) {
        static const int needrights = ACL_DELETEMSG|ACL_EXPUNGE;
        int myrights =
            cyrus_acl_myrights(imapd_authstate,
                               ((mbentry_t *) backend_current->context)->acl);

        if ((myrights & needrights) != needrights) {
            eatline(imapd_in, prot_getc(imapd_in));
            r = IMAP_PERMISSION_DENIED;
        }
        else if (!strtoul(seqno, NULL, 10)) {
            r = IMAP_NO_NOSUCHMSG;
        }
        /* validate seqno and get UID */
        else if (proxy_fetch(seqno, usinguid,
                             FETCH_UID, &uid_cb, &uid) != PROXY_OK) {
        }
        else if (!uid) {
            r = IMAP_NO_NOSUCHMSG;
        }
        else {
            buf_printf(&buf, "%u", uid);
            uidseq = buf_cstring(&buf);
        }
    }
    else if (!index_hasrights(imapd_index, ACL_EXPUNGE)) {
        r = IMAP_PERMISSION_DENIED;
    }
    else if (usinguid) {
        uid = strtoul(seqno, NULL, 10);
        if (!uid || !(msgno = index_finduid(imapd_index, uid, FIND_EQ))) {
            r = IMAP_NO_NOSUCHMSG;
        }
        else {
            uidseq = seqno;
        }
    }
    else if (!(msgno = strtoul(seqno, NULL, 10)) ||
             msgno > imapd_index->exists) {
        r = IMAP_NO_NOSUCHMSG;
    }
    else {
        buf_printf(&buf, "%u", index_getuid(imapd_index, msgno));
        uidseq = buf_cstring(&buf);
    }

    if (!r) {
        /* Check location of destination mailbox */
        intname = mboxname_from_external(name, &imapd_namespace, imapd_userid);
        r = mlookup(NULL, NULL, intname, &mbentry);
    }

    if (r) goto done;

    if (mbentry->mbtype & MBTYPE_REMOTE) {
        /* Remote destination mailbox */
        struct backend *s = NULL;

        s = proxy_findserver(mbentry->server, &imap_protocol,
                             proxy_userid, &backend_cached,
                             &backend_current, &backend_inbox, imapd_in);
        if (!s) {
            eatline(imapd_in, prot_getc(imapd_in));
            r = IMAP_SERVER_UNAVAILABLE;
        }
        else {
            imapd_check(s, 0);

            if (s == backend_current) {
                /* Simply send the REPLACE to the backend */
                prot_printf(s->out, "%s Replace %s {" SIZE_T_FMT "+}\r\n%s ",
                            tag, seqno, strlen(name), name);
                if (!(r = pipe_command(s, 16384))) {
                    pipe_including_tag(s, tag, 0);
                    goto cleanup;
                }
            }
            else {
                /* APPEND the new message to destination */
                const char *cur_name = backend_current ? 
                    ((mbentry_t *) backend_current->context)->name :
                    index_mboxname(imapd_index);

                prot_printf(s->out, "%s Localappend {" SIZE_T_FMT "+}\r\n%s"
                            " {" SIZE_T_FMT "+}\r\n%s ",
                            tag, strlen(name), name,
                            strlen(cur_name), cur_name);

                if (!(r = pipe_command(s, 16384))) {
                    r = pipe_until_tag(s, tag, 0);
                    if (r != PROXY_OK) {
                        prot_printf(imapd_out, "%s %s",
                                    tag, buf_cstring(&s->last_result));
                        goto cleanup;
                    }
                    else if (!strncmp(buf_cstring(&s->last_result),
                                      "OK [APPENDUID ", 14)) {
                        prot_printf(imapd_out, "* %s",
                                    buf_cstring(&s->last_result));
                    }
                }
            }
        }

        if (r) goto done;
    }
    else {
        /* Append the new message to local destination mailbox */
        r = cmd_append(tag, name, index_mboxname(imapd_index), 1/*isreplace*/);
        if (r) goto cleanup;  // APPEND-specific error responses already sent
    }

    /* EXPUNGE specified message from selected mailbox */
    if (backend_current) {
        /* First, mark the remote message as \Deleted */
        char mytag[128];

        proxy_gentag(mytag, sizeof(mytag));
        prot_printf(backend_current->out,
                    "%s UID STORE %s +FLAGS.SILENT (\\Deleted)\r\n",
                    mytag, uidseq);
        r = pipe_until_tag(backend_current, mytag, 0);

        if (r == PROXY_OK) {
            /* Now expunge it */
            proxy_gentag(mytag, sizeof(mytag));
            prot_printf(backend_current->out,
                        "%s UID EXPUNGE %s\r\n", mytag, uidseq);
            r = pipe_until_tag(backend_current, mytag, 0);
        }

        prot_printf(imapd_out, "%s %s",
                    tag, buf_cstring(&backend_current->last_result));
        goto cleanup;
    }
    else {
        /* Local mailbox */
        r = index_expunge(imapd_index, (char *) uidseq, 0);
        if (!r) index_tellchanges(imapd_index,
                                  TELL_EXPUNGED | (usinguid ? TELL_UID : 0));
    }

  done:
    if (r) {
        prot_printf(imapd_out, "%s NO %s\r\n", tag, prot_error(imapd_in) ?
                    prot_error(imapd_in) : error_message(r));
    }
    else {
        modseq_t highestmodseq = index_highestmodseq(imapd_index);

        index_release(imapd_index);
        sync_checkpoint(imapd_in);

        prot_printf(imapd_out, "%s OK [HIGHESTMODSEQ " MODSEQ_FMT "] %s\r\n",
                    tag, highestmodseq, error_message(IMAP_OK_COMPLETED));
    }

  cleanup:
    mboxlist_entry_free(&mbentry);
    buf_free(&buf);
    free(intname);
}

struct notify_event {
    const char *name;
    unsigned long events;
    unsigned selected : 1;
};

static const struct notify_event notify_events[] = {
    { "MessageNew",            IMAP_NOTIFY_MESSAGE_NEW,             1 },
    { "MessageExpunge",        IMAP_NOTIFY_MESSAGE_EXPUNGE,         1 },
    { "FlagChange",            IMAP_NOTIFY_FLAG_CHANGE,             1 },
//    { "AnnotationChange",      IMAP_NOTIFY_ANNOTATION_CHANGE,       1 },
    { "MailboxName",           IMAP_NOTIFY_MAILBOX_NAME,            0 },
    { "SubscriptionChange",    IMAP_NOTIFY_SUBSCRIPTION_CHANGE,     0 },
//    { "MailboxMetadataChange", IMAP_NOTIFY_MAILBOX_METADATA_CHANGE, 0 },
//    { "ServerMetadataChange",  IMAP_NOTIFY_SERVER_METADATA_CHANGE,  0 },
    { NULL,                    0,                                   0 }
};

struct notify_set_rock {
    mailbox_filter_t filter;
    unsigned long events;
    hash_table *mboxnames;
};

static int notify_set_status(const mbentry_t *mbentry, void *rock)
{
    struct notify_set_rock *srock = (struct notify_set_rock *) rock;
    struct statusdata sdata = STATUSDATA_INIT;
    unsigned statusitems = 0;
    int rights;

    if (hash_lookup(mbentry->name, srock->mboxnames)) return 0;

    if (mboxname_isnonimapmailbox(mbentry->name, mbentry->mbtype)) return 0;

    /* check permissions */
    switch (srock->filter) {
    case FILTER_SELECTED:
        break;

    case FILTER_INBOXES:
        rights = cyrus_acl_myrights(NULL, mbentry->acl);
        if (!(rights & ACL_POST)) return 0;
        break;

    default:
        rights = cyrus_acl_myrights(imapd_authstate, mbentry->acl);
        if ((rights & (ACL_LOOKUP | ACL_READ)) != (ACL_LOOKUP | ACL_READ)) return 0;
        break;
    }

    hash_insert(mbentry->name, (void *) 1, srock->mboxnames);
        
    if (srock->events & IMAP_NOTIFY_MESSAGE_NEW)
        statusitems |= (STATUS_MESSAGES | STATUS_UIDNEXT | STATUS_UIDVALIDITY);

    if (srock->events & IMAP_NOTIFY_MESSAGE_EXPUNGE)
        statusitems |= STATUS_MESSAGES;

    if (srock->events & (IMAP_NOTIFY_FLAG_CHANGE | IMAP_NOTIFY_ANNOTATION_CHANGE)) {
        statusitems |= (STATUS_UIDVALIDITY | STATUS_HIGHESTMODSEQ);
    }

    if (statusitems && !imapd_statusdata(mbentry, statusitems, &sdata)) {
        char *extname = mboxname_to_external(mbentry->name,
                                             &imapd_namespace, imapd_userid);
        print_statusline(extname, statusitems, &sdata);
        free(extname);
    }

    return 0;
}

static void cmd_notify(char *tag, int set)
{
    struct event_groups *new_egroups = xzmalloc(sizeof(struct event_groups));
    struct buf arg = BUF_INITIALIZER;
    char *filter_name = NULL;
    int c = EOF, do_status = 0;

    client_behavior_mask |= CB_NOTIFY;

    if (set) {
        /* Parse optional status-indicator */
        c = getword(imapd_in, &arg);
        if (!arg.s[0]) {
            prot_ungetc(c, imapd_in);
        }
        else if (c != ' ') {
            goto missingarg;
        }
        else if (strcasecmp(arg.s, "STATUS")) {
            goto badarg;
        }
        else {
            do_status = 1;
        }

        /* Parse event-groups */
        do {
            mailbox_filter_t filter = 0;
            unsigned long *events = NULL;
            strarray_t *mboxes = NULL;

            c = prot_getc(imapd_in);
            if (c != '(') {
                goto missingopen;
            }

            /* Parse filter-mailboxes */
            c = getword(imapd_in, &arg);
            lcase(arg.s);

            if (!strcmp(arg.s, "selected")) {
                filter = FILTER_SELECTED;
                events = &new_egroups->selected.events;
            }
            else if (!strcmp(arg.s, "selected-delayed")) {
                filter = FILTER_SELECTED;
                events = &new_egroups->selected.events;
                new_egroups->selected.delayed = 1;
            }
            else if (!strcmp(arg.s, "inboxes")) {
                filter = FILTER_INBOXES;
                events = &new_egroups->inboxes_events;
            }
            else if (!strcmp(arg.s, "personal")) {
                filter = FILTER_PERSONAL;
                events = &new_egroups->personal_events;
            }
            else if (!strcmp(arg.s, "subscribed")) {
                filter = FILTER_SUBSCRIBED;
                events = &new_egroups->subscribed_events;
            }
            else if (!strcmp(arg.s, "subtree")) {
                filter = FILTER_SUBTREE;
                events = &new_egroups->subtree.events;
                mboxes = &new_egroups->subtree.mboxes;
            }
            else if (!strcmp(arg.s, "mailboxes")) {
                filter = FILTER_MAILBOXES;
                events = &new_egroups->mailboxes.events;
                mboxes = &new_egroups->mailboxes.mboxes;
            }
            else {
                goto badarg;
            }

            if (new_egroups->filters & filter) {
                prot_printf(imapd_out,
                            "%s BAD Duplicate filter in Notify %s\r\n",
                            tag, arg.s);
                goto cleanup;
            }

            new_egroups->filters |= filter;
            filter_name = buf_release(&arg);

            if (mboxes) {
                int inlist = 0;

                /* Parse one-or-more-mailbox */
                if (prot_peek(imapd_in) == '(') {
                    prot_getc(imapd_in);
                    inlist = 1;
                }

                do {
                    char *mboxname = NULL;
                    mbentry_t *mbentry = NULL;

                    c = getastring(imapd_in, imapd_out, &arg);
                    if (prot_bytes_in(imapd_in) > maxargssize_mark)
                        fatal(error_message(IMAP_ARGS_TOO_LARGE), EX_PROTOCOL);
                    if (c == IMAP_LITERAL_TOO_LARGE) {
                        prot_printf(imapd_out, "%s NO %s in Notify\r\n",
                                    tag, error_message(c));
                        goto cleanup;
                    }
                    if (c == EOF) goto missingarg;

                    mboxname = mboxname_from_external(arg.s, &imapd_namespace,
                                                      imapd_userid);

                    if (!mboxlist_lookup(mboxname, &mbentry, NULL)) {
                        int myrights =
                            cyrus_acl_myrights(imapd_authstate, mbentry->acl);

                        if (myrights & ACL_LOOKUP) {
                            if (myrights & ACL_READ) {
                                strarray_add(mboxes, mbentry->name);
                            }
                            else {
                                print_listresponse(LIST_CMD_EXTENDED,
                                                   arg.s, NULL,
                                                   imapd_namespace.hier_sep,
                                                   MBOX_ATTRIBUTE_NOACCESS,
                                                   NULL);
                            }
                        }
                    }

                    mboxlist_entry_free(&mbentry);
                    free(mboxname);

                } while (inlist && c == ' ');

                if (inlist) {
                    if (c != ')') {
                        goto missingclose;
                    }

                    c = prot_getc(imapd_in);
                }
            }

            if (c != ' ') {
                goto missingarg;
            }

            /* Parse events */
            c = getword(imapd_in, &arg);

            if (!arg.s[0]) {
                if (c != '(') {
                    goto missingopen;
                }

                do {
                    const struct notify_event *nevent;

                    c = getword(imapd_in, &arg);
                    if (prot_bytes_in(imapd_in) > maxargssize_mark)
                        fatal(error_message(IMAP_ARGS_TOO_LARGE), EX_PROTOCOL);

                    for (nevent = notify_events; nevent->name; nevent++) {
                        if (strcasecmp(arg.s, nevent->name)) continue;

                        if (filter == FILTER_SELECTED) {
                            if (!nevent->selected) continue;

                            if (nevent->events == IMAP_NOTIFY_MESSAGE_NEW &&
                                c == ' ' && prot_peek(imapd_in) == '(') {
                                struct fetchargs *fetchargs =
                                    &new_egroups->selected.fetchargs;
                                unsigned flags = 0;

                                if (client_capa & CAPA_QRESYNC)
                                    flags |= FETCH_ALLOW_VANISHED;

                                if (parse_fetch_args(tag, "Notify",
                                                     flags, fetchargs)) {
                                    goto cleanup;
                                }

                                c = prot_getc(imapd_in);
                            }
                        }

                        *events |= nevent->events;

                        break;
                    }

                    if (!nevent->name) {
                        goto badevent;
                    }

                } while (c == ' ');

                if (c != ')') {
                    goto missingclose;
                }

                c = prot_getc(imapd_in);
            }
            else if (strcasecmp(arg.s, "NONE")) {
                goto badarg;
            }

            if (c != ')') {
                goto missingclose;
            }

            /* Sanity check events.  Per RFC 5465, Section 5:

               If the FlagChange and/or AnnotationChange events are specified,
               MessageNew and MessageExpunge MUST also be specified by the client.
               Otherwise, the server MUST respond with the tagged BAD response.

               If one of MessageNew or MessageExpunge is specified, then both events
               MUST be specified.  Otherwise, the server MUST respond with the
               tagged BAD response.
            */
            if (((*events & (IMAP_NOTIFY_FLAG_CHANGE|IMAP_NOTIFY_ANNOTATION_CHANGE))
                 && !(*events & IMAP_NOTIFY_MESSAGE_NEW))
                || (!!(*events & IMAP_NOTIFY_MESSAGE_NEW) !=
                    !!(*events & IMAP_NOTIFY_MESSAGE_EXPUNGE))) {
                prot_printf(imapd_out,
                            "%s BAD Missing %s event for '%s' filter in Notify\r\n",
                            tag,
                            (*events & IMAP_NOTIFY_MESSAGE_NEW) ?
                            "MessageExpunge" : "MessageNew",
                            filter_name);
                goto cleanup;
            }

            xzfree(filter_name);

            c = prot_getc(imapd_in);

            if (prot_bytes_in(imapd_in) > maxargssize_mark)
                fatal(error_message(IMAP_ARGS_TOO_LARGE), EX_PROTOCOL);

        } while (c == ' ');

        /* check for CRLF */
        if (!IS_EOL(c, imapd_in)) {
            prot_printf(imapd_out,
                        "%s BAD Unexpected extra arguments to Notify\r\n", tag);
            goto cleanup;
        }
    }

    /* Stop idled listening for old events */
    idle_stop(FILTER_NONE);

    /* Cancel all registered notification events */
    event_groups_free(&notify_event_groups);

    if (new_egroups->filters) {
        /* Start idled listening for our events and optionally send STATUS */
        strarray_t key = { 1, 0, NULL };  // avoid memory alloc
        struct notify_set_rock srock = { FILTER_NONE, 0, NULL };
        hash_table mboxnames = HASH_TABLE_INITIALIZER;
        strarray_t *mboxes;
        int i;

        if (new_egroups->filters & ~FILTER_SELECTED) {
            srock.mboxnames = construct_hash_table(&mboxnames, 100, 0);
        }

        if (new_egroups->selected.events && imapd_index) {
            const char *mboxid = index_mboxid(imapd_index);

            key.data = (char **) &mboxid;
            idle_start(new_egroups->selected.events, 0, FILTER_SELECTED, &key);

            imapd_check(NULL, TELL_EXPUNGED | TELL_UID);

            if (srock.mboxnames) {
                hash_insert(index_mboxname(imapd_index),
                            (void *) 1, srock.mboxnames);
            }
        }
        if (new_egroups->inboxes_events) {
            key.data = &imapd_userid;
            idle_start(new_egroups->inboxes_events, 0, FILTER_INBOXES, &key);

            if (do_status && (new_egroups->inboxes_events & IMAP_NOTIFY_MESSAGE)) {
                srock.filter = FILTER_INBOXES;
                srock.events = new_egroups->inboxes_events;
                mboxlist_usermboxtree(imapd_userid, imapd_authstate,
                                      &notify_set_status, &srock, 0);
            }
        }
        if (new_egroups->personal_events) {
            key.data = &imapd_userid;
            idle_start(new_egroups->personal_events, 0, FILTER_PERSONAL, &key);

            if (do_status && (new_egroups->personal_events & IMAP_NOTIFY_MESSAGE)) {
                srock.filter = FILTER_PERSONAL;
                srock.events = new_egroups->personal_events;
                mboxlist_usermboxtree(imapd_userid, imapd_authstate,
                                      &notify_set_status, &srock, 0);
            }
        }
        if (new_egroups->subscribed_events) {
            key.data = &imapd_userid;
            idle_start(new_egroups->subscribed_events, 0, FILTER_SUBSCRIBED, &key);

            if (do_status && (new_egroups->subscribed_events & IMAP_NOTIFY_MESSAGE)) {
                srock.filter = FILTER_SUBSCRIBED;
                srock.events = new_egroups->subscribed_events;
                mboxlist_usersubs(imapd_userid, &notify_set_status, &srock, 0);
            }
        }
        if (new_egroups->subtree.events) {
            idle_start(new_egroups->subtree.events, 0, FILTER_SUBTREE,
                       &new_egroups->subtree.mboxes);

            if (do_status && (new_egroups->subtree.events & IMAP_NOTIFY_MESSAGE)) {

                srock.filter = FILTER_SUBTREE;
                srock.events = new_egroups->subtree.events;
                mboxes = &new_egroups->subtree.mboxes;
                for (i = 0; i < strarray_size(mboxes); i++) {
                    mboxlist_mboxtree(strarray_nth(mboxes, i),
                                      &notify_set_status, &srock, 0);
                }
            }
        }
        if (new_egroups->mailboxes.events) {
            idle_start(new_egroups->mailboxes.events, 0, FILTER_MAILBOXES,
                       &new_egroups->mailboxes.mboxes);

            if (do_status && (new_egroups->mailboxes.events & IMAP_NOTIFY_MESSAGE)) {
                srock.filter = FILTER_MAILBOXES;
                srock.events = new_egroups->mailboxes.events;
                mboxes = &new_egroups->mailboxes.mboxes;
                for (i = 0; i < strarray_size(mboxes); i++) {
                    mboxlist_mboxtree(strarray_nth(mboxes, i),
                                      &notify_set_status, &srock,
                                      MBOXTREE_SKIP_CHILDREN);
                }
            }
        }

        free_hash_table(&mboxnames, NULL);
    }

    notify_event_groups = new_egroups;
    buf_free(&arg);

    prot_printf(imapd_out,
                "%s OK %s\r\n", tag, error_message(IMAP_OK_COMPLETED));
    return;

  badarg:
    prot_printf(imapd_out,
                "%s BAD Invalid argument in Notify '%s'\r\n", tag, arg.s);
    goto cleanup;

  badevent:
    prot_printf(imapd_out, "%s NO [BADEVENT ", tag);
    {
        const struct notify_event *nevent;
        char sep = '(';

        for (nevent = notify_events; nevent->name; nevent++) {
            prot_printf(imapd_out, "%c%s", sep, nevent->name);
            sep = ' ';
        }
    }
    prot_printf(imapd_out, ")] Unsupported event in Notify '%s'\r\n", arg.s);
    goto cleanup;

  missingarg:
    prot_printf(imapd_out,
                "%s BAD Missing argument in Notify\r\n", tag);
    goto cleanup;

  missingopen:
    prot_printf(imapd_out,
                "%s BAD Missing open parenthesis in Notify\r\n", tag);
    goto cleanup;

  missingclose:
    prot_printf(imapd_out,
                "%s BAD Missing close parenthesis in Notify\r\n", tag);
    goto cleanup;

  cleanup:
    event_groups_free(&new_egroups);
    free(filter_name);
    buf_free(&arg);
    eatline(imapd_in, c);
}

static void push_updates(int idling)
{
    json_t *msg;
    const char *mtype, *mboxid, *event;
    mbentry_t *mbentry = NULL;
    enum event_type etype;
    int r;

    msg = idle_get_message();

    while (msg) {
        json_t *nextmsg = NULL;

        mtype = json_string_value(json_object_get(msg, "@type"));

        if (!strcmp(mtype, "alert")) {
            if (notify_event_groups) {
                prot_puts(imapd_out,
                          "* OK [NOTIFICATIONOVERFLOW] Lost connection to idled\r\n");
            }
            idle_sock = PROT_NO_FD;
            imapd_notify_enabled = 0;
            goto done;
        }

        mboxid = json_string_value(json_object_get(msg, "mailboxID"));
        if (!mboxid) goto done;

        event = json_string_value(json_object_get(msg, "event"));
        etype = name_to_mboxevent(event);

        if (!etype || !mboxid) goto done;

        if (imapd_index && !strcmp(mboxid, index_mboxid(imapd_index))) {
            /* Notification for currently selected mailbox */
            if ((etype & IMAP_NOTIFY_MESSAGE_NEW) &&
                notify_event_groups &&
                notify_event_groups->selected.fetchargs.fetchitems) {
                const char *uidset =
                    json_string_value(json_object_get(msg, "uidset"));

                index_fetch(imapd_index, uidset ? uidset : "*", 1,
                            &notify_event_groups->selected.fetchargs, NULL);
            }
            else if (!(etype & IMAP_NOTIFY_MESSAGE_EXPUNGE) ||
                     idling || !notify_event_groups->selected.delayed) {
                imapd_check(NULL, TELL_EXPUNGED | TELL_UID);
            }

            goto done;
        }

        /* Notification for non-selected mailbox */
        mboxlist_lookup_by_uniqueid(mboxid, &mbentry, NULL);
        if (!mbentry) {
            /* mailbox doesn't exist */
            goto done;
        }

        int myrights = cyrus_acl_myrights(imapd_authstate, mbentry->acl);
        if ((myrights & (ACL_LOOKUP|ACL_READ)) != (ACL_LOOKUP|ACL_READ)) {
            /* RFC 5465, Secion 5:
             * All event types described in this document require the
             * 'l' and 'r' rights (see [RFC4314]) on all observed mailboxes.
             */
            goto done;
        }

        if (!mbentry->ext_name) {
            mbentry->ext_name =
                mboxname_to_external(mbentry->name,
                                     &imapd_namespace, imapd_userid);
        }

        if (etype & IMAP_NOTIFY_MESSAGE) {
            struct statusdata sdata = STATUSDATA_INIT;
            unsigned statusitems = STATUS_UIDVALIDITY;

            if (etype & (IMAP_NOTIFY_MESSAGE_NEW | IMAP_NOTIFY_MESSAGE_EXPUNGE))
                statusitems |= (STATUS_MESSAGES | STATUS_UIDNEXT);
            else if (etype & IMAP_NOTIFY_FLAG_CHANGE)
                statusitems |= STATUS_UNSEEN;

            if (client_capa & CAPA_CONDSTORE)
                statusitems |= STATUS_HIGHESTMODSEQ;

            r = imapd_statusdata(mbentry, statusitems, &sdata);
            if (!r) {
                print_statusline(mbentry->ext_name, statusitems, &sdata);
            }
        }
        else if (etype & IMAP_NOTIFY_MAILBOX) {
            const char *extname = mbentry->ext_name;
            struct buf specialuse = BUF_INITIALIZER;
            former_name_t *lastname = ptrarray_nth(&mbentry->name_history, 0);
            char *oldname = NULL, *freeme = NULL;
            uint32_t attribs = 0;
            struct timeval timeout = { 1, 0 };
            fd_set rset;

            switch (etype) {
            case EVENT_MAILBOX_CREATE:
                specialuse_flags(mbentry, &specialuse, 0);

                GCC_FALLTHROUGH

            case EVENT_MAILBOX_RENAME:
                if (lastname) {
                    oldname = mboxname_to_external(lastname->name,
                                                   &imapd_namespace, imapd_userid);
                }

                /* Thunderbird auto-subscribes on CREATE/RENAME, so
                 * wait 1 second for a SubscriptionChange message for this mailbox
                 * and consolidate it with the MailboxCreate/MailboxRename */
                FD_ZERO(&rset);
                FD_SET(idle_sock, &rset);
                r = signals_select(idle_sock+1, &rset, NULL, NULL, &timeout);

                if (r > 0 &&
                    FD_ISSET(idle_sock, &rset) && (nextmsg = idle_get_message())) {
                    mtype = json_string_value(json_object_get(nextmsg, "@type"));

                    if (!strcmpnull(mtype, "notify")) {
                        mboxid = json_string_value(json_object_get(nextmsg,
                                                                   "mailboxID"));
                        event = json_string_value(json_object_get(nextmsg,
                                                                  "event"));
                        etype = name_to_mboxevent(event);

                        if ((etype & IMAP_NOTIFY_SUBSCRIPTION_CHANGE) &&
                            !strcmpnull(mboxid, mbentry->uniqueid)) {
                            /* Discard next message */
                            json_decref(nextmsg);
                            nextmsg = NULL;

                            if (etype == EVENT_MAILBOX_SUBSCRIBE)
                                attribs |= MBOX_ATTRIBUTE_SUBSCRIBED;
                        }
                    }
                }
                break;

            case EVENT_MAILBOX_DELETE:
                if (mboxname_isdeletedmailbox(mbentry->name, NULL)) {
                    extname = freeme = mboxname_to_external(lastname->name,
                                                            &imapd_namespace,
                                                            imapd_userid);
                }

                attribs |= MBOX_ATTRIBUTE_NONEXISTENT;
                break;

            case EVENT_ACL_CHANGE:
                /* XXX  TODO */
                break;

            case EVENT_MAILBOX_SUBSCRIBE:
                attribs |= MBOX_ATTRIBUTE_SUBSCRIBED;
                break;

            default:
                break;
            }

            print_listresponse(LIST_CMD_EXTENDED, extname, oldname,
                               imapd_namespace.hier_sep, attribs, &specialuse);

            free(oldname);
            free(freeme);
        }

      done:
        mboxlist_entry_free(&mbentry);
        json_decref(msg);
        msg = nextmsg;
    }
}

static void cmd_getjmapaccess(char *tag)
{
    if (!imapd_jmapaccess_url) {
        prot_printf(imapd_out, "%s BAD %s\r\n", tag,
                    "This server is not accessible via JMAP\r\n");
        return;
    }

    prot_printf(imapd_out, "* JMAPACCESS \"%s\"\r\n", imapd_jmapaccess_url);
    prot_printf(imapd_out, "%s OK %s\r\n", tag,
                "This server is also accessible via JMAP, see RFC8620");
}

static void cmd_uidbatches(char *tag, uint32_t size, uint32_t low, uint32_t high)
{
    static int min_size = -1;
    static int max_msgs = -1;

    if (min_size == -1) {
        /* Per Section 3.1.3:
         * The server MUST support batch sizes of 500 messages or larger.
         *
         * Additionally, we require batch sizes 10 messages or larger.
         */
        min_size = MIN(500,
                       MAX(10, config_getint(IMAPOPT_UIDBATCHES_MIN_BATCH)));

        /* Per Secion 3.1.7:
         * The server MUST at least support returning UID ranges
         * spanning 100,000 messages.
         */
        max_msgs = MAX(100000, config_getint(IMAPOPT_UIDBATCHES_MAX_MESSAGES));
    }

    client_behavior_mask |= CB_UIDBATCHES;

    if (size < (uint32_t) min_size) {
        prot_printf(imapd_out, "%s NO [TOOSMALL] Minimum batch size is %d\r\n",
                    tag, min_size);
        return;
    }

    quota_t num_msg =
        (high == UINT32_MAX) ? imapd_index->exists : size * (high - low + 1);
    if (num_msg > max_msgs) {
        prot_printf(imapd_out,
                    "%s NO [LIMIT] UID ranges span more than %d messages\r\n",
                    tag, max_msgs);
        return;
    }

    if (backend_current) {
        /* remote mailbox */
        prot_printf(backend_current->out, "%s UIDBATCHES %u", tag, size);
        if (low > 1 || high < UINT32_MAX) {
            prot_printf(backend_current->out, " %u:%u", low, high);
        }
        prot_puts(backend_current->out, "\r\n");
        pipe_including_tag(backend_current, tag, 0);
        return;
    }

    /* Per Section 3.1.2:
     * The server MUST reply with a UIDBATCHES response,
     * even if no ranges are returned
     */
    prot_printf(imapd_out, "* UIDBATCHES (TAG \"%s\")", tag);

    /* Per Section 3.1:
       Batches are arranged by descending UID order,
       with the first batch containing the highest UIDs.
    */
    if (low <= (imapd_index->exists + size - 1) / size) {
        int64_t msgno = imapd_index->exists - ((low - 1) * size);
        uint32_t batch = low;
        char sep = ' ';

        /* Per Section 3.1.2:
         * The UID ranges in the response MUST be ordered in descending sequence,
         * from the highest to the lowest UIDs.
         */
        for (; msgno > 0 && batch <= high; batch++) {
            uint32_t first = index_getuid(imapd_index, msgno);
            /* Per Section 3.1.4:
             * Servers SHOULD end the last UID batch in the mailbox with UID 1
             * even if this UID does not exist on the server.
             */
            uint32_t last =
                (msgno -= size) > 0 ? index_getuid(imapd_index, msgno + 1) : 1;

            prot_printf(imapd_out, "%c%u:%u", sep, first, last);
            sep = ',';
        }
    }
    prot_puts(imapd_out, "\r\n");
    prot_printf(imapd_out, "%s OK %s\r\n",
                tag, error_message(IMAP_OK_COMPLETED));
}

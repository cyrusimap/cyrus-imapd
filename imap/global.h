/* global.h - Header for global/shared variables & functions. */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef INCLUDED_GLOBAL_H
#define INCLUDED_GLOBAL_H

#include <sasl/sasl.h>
#include "libconfig.h"
#include "auth.h"
#include "prot.h"
#include "mboxname.h"
#include "sessionid.h" /* XXX remove from here once it's auto-logged */
#include "signals.h"
#include "imapparse.h"
#include "libcyr_cfg.h"
#include "util.h"

#include <openssl/evp.h>
#define MAX_FINISHED_LEN EVP_MAX_MD_SIZE

/* Flags for cyrus_init() */
enum {
    CYRUSINIT_NODB =    (1<<0),
    CYRUSINIT_PERROR =  (1<<1)
};

/* Startup the configuration subsystem */
/* Note that cyrus_init is pretty much the wholesale startup function
 * for any libimap/libcyrus process, and should be called fairly early
 * (and needs an associated cyrus_done call) */
extern int cyrus_init(const char *alt_config, const char *ident,
                      unsigned flags, int config_need_data);
extern void global_sasl_init(int client, int server,
                             const sasl_callback_t *callbacks);

/* Register a module callback. This callback will be called
 * during cyrus_done, passing callback data rock */
extern void cyrus_modules_add(void (*done)(void*), void *rock);

/* Shutdown a cyrus process */
extern void cyrus_done(void);

/* sasl configuration */
extern int mysasl_config(void *context,
                         const char *plugin_name,
                         const char *option,
                         const char **result,
                         unsigned *len);
extern sasl_security_properties_t *mysasl_secprops(int flags);

#define SASL_CB_PROC_PTR  (int (*)())

/* user canonification */
extern const char *canonify_userid(char *user, const char *loginid,
                                   int *domain_from_ip);

extern int is_userid_anonymous(const char *user);

extern int mysasl_canon_user(sasl_conn_t *conn,
                             void *context,
                             const char *user, unsigned ulen,
                             unsigned flags,
                             const char *user_realm,
                             char *out_user,
                             unsigned out_max, unsigned *out_ulen);

extern int mysasl_proxy_policy(sasl_conn_t *conn,
                               void *context,
                               const char *requested_user, unsigned rlen,
                               const char *auth_identity, unsigned alen,
                               const char *def_realm __attribute__((unused)),
                               unsigned urlen __attribute__((unused)),
                               struct propctx *propctx __attribute__((unused)));

/* check if `authstate' is a valid member of class */
extern int global_authisa(struct auth_state *authstate,
                          enum imapopt opt);

/* useful types */
struct protstream;

struct proxy_context {
    int use_acl;
    int proxy_servers;
    struct auth_state **authstate;
    int *userisadmin;
    int *userisproxyadmin;
};

struct saslprops_t {
    struct buf iplocalport;
    struct buf ipremoteport;
    sasl_ssf_t ssf;
    struct buf authid;
    sasl_channel_binding_t cbinding;
    unsigned char tls_finished[MAX_FINISHED_LEN];
};
#define SASLPROPS_INITIALIZER \
    { BUF_INITIALIZER, BUF_INITIALIZER, 0, BUF_INITIALIZER, \
      { NULL, 0, 0, NULL }, { 0 } }

/* Misc utils */
extern int shutdown_file(char *buf, int size);
#define UNIX_SOCKET "[unix socket]"
extern const char *get_clienthost(int s,
                                  const char **localip, const char **remoteip);
extern void saslprops_reset(struct saslprops_t *saslprops);
extern void saslprops_free(struct saslprops_t *saslprops);
extern int saslprops_set_tls(struct saslprops_t *saslprops,
                             sasl_conn_t *saslconn);

/* Misc globals */
extern volatile sig_atomic_t in_shutdown;
extern int config_fulldirhash;
extern int config_implicitrights;
extern uint64_t config_metapartition_files;
extern const char *config_mboxlist_db;
extern const char *config_quota_db;
extern const char *config_subscription_db;
extern const char *config_annotation_db;
extern const char *config_seenstate_db;
extern const char *config_mboxkey_db;
extern const char *config_duplicate_db;
extern const char *config_tls_sessions_db;
extern const char *config_ptscache_db;
extern const char *config_statuscache_db;
extern const char *config_userdeny_db;
extern const char *config_zoneinfo_db;
extern const char *config_conversations_db;
extern int config_take_globallock;
extern char *config_skip_userlock;
extern int config_httpprettytelemetry;
extern int charset_flags;
extern int charset_snippet_flags;
extern size_t config_search_maxsize;
extern int haproxy_protocol;
extern int imaply_strict;

/* Capability suppression */
extern int capa_is_disabled(const char *str);

extern int cmd_cancelled(int insearch);

#endif /* INCLUDED_GLOBAL_H */

/* afskrb.c - AFS PTS Group (Kerberos Canonicalization) Backend to ptloader */
/*
 * Copyright (c) 1996-2000 Carnegie Mellon University.  All rights reserved.
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
 */

static char rcsid[] __attribute__((unused)) = 
      "$Id: afskrb.c,v 1.1.2.1 2002/12/13 17:10:37 rjs3 Exp $";

#include <config.h>

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/param.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <com_err.h>
#include <krb.h>

#include "auth_pts.h"
#include "exitcodes.h"
#include "hash.h"
#include "xmalloc.h"

/* AFS stuff */
#include <des.h> /* for int32, necessary for the AFS includes below */
#include <afs/ptserver.h>
#include <afs/cellconfig.h>
#include <rx/rxkad.h>
#include <afs/auth.h>

/* blame transarc i've been told */
#ifndef AFSCONF_CLIENTNAME
#include <afs/dirpath.h>
#define AFSCONF_CLIENTNAME AFSDIR_CLIENT_ETC_DIRPATH
#endif

/* Sanity Check */
#if PTS_DB_KEYSIZE < PR_MAXNAMELEN
#error PTS_DB_KEYSIZE is smaller than PR_MAXNAMELEN
#endif
#if PTS_DB_KEYSIZE < MAX_K_NAME_SZ
#error PTS_DB_KEYSIZE is smallr than MAX_K_NAME_SZ
#endif

/* where is krb.equiv? */
#ifndef KRB_MAPNAME
#define KRB_MAPNAME "/etc/krb.equiv"
#endif

/*
 * Parse a line 'src' from an /etc/krb.equiv file.
 * Sets the buffer pointed to by 'principal' to be the kerberos
 * identity and sets the buffer pointed to by 'localuser' to
 * be the local user.  Both buffers must be of size one larger than
 * MAX_K_NAME_SZ.  Returns 1 on success, 0 on failure.
 */
static int parse_krbequiv_line(const char *src, 
			       char *principal, 
			       char *localuser)
{
    int i;
    
    while (isspace(*src)) src++;
    if (!*src) return 0;

    for (i = 0; *src && !isspace(*src); i++) {
        if (i >= MAX_K_NAME_SZ) return 0;
        *principal++ = *src++;
    }
    *principal = 0;
    
    if (!isspace(*src)) return 0; /* Need at least one separator */
    while (isspace(*src)) src++;
    if (!*src) return 0;
  
    for (i = 0; *src && !isspace(*src); i++) {
        if (i >= MAX_K_NAME_SZ) return 0;
        *localuser++ = *src++;
    }
    *localuser = 0;
    return 1;
}

/*
 * Map a remote kerberos principal to a local username.  If a mapping
 * is found, a pointer to the local username is returned.  Otherwise,
 * a NULL pointer is returned.
 * Eventually, this may be more sophisticated than a simple file scan.
 */
static char *auth_map_krbid(const char *real_aname,
			    const char *real_inst,
			    const char *real_realm)
{
    static char localuser[MAX_K_NAME_SZ + 1];
    char principal[MAX_K_NAME_SZ + 1];
    char aname[ANAME_SZ];
    char inst[INST_SZ];
    char realm[REALM_SZ];
    char lrealm[REALM_SZ];
    char krbhst[MAX_HSTNM];
    char *p;
    char buf[1024];
    FILE *mapfile;

    if (!(mapfile = fopen(KRB_MAPNAME, "r"))) {
        /* If the file can't be opened, don't do mappings */
        return 0;
    }
    
    for (;;) {
        if (!fgets(buf, sizeof(buf), mapfile)) break;
        if (parse_krbequiv_line(buf, principal, localuser) == 0 ||
            kname_parse(aname, inst, realm, principal) != 0) {
            /* Ignore badly formed lines */
            continue;
        }
        if (!strcmp(aname, real_aname) && !strcmp(inst, real_inst) &&
            !strcmp(realm, real_realm)) {
            fclose(mapfile);
            
            aname[0] = inst[0] = realm[0] = '\0';
            if (kname_parse(aname, inst, realm, localuser) != 0) {
                return 0;
            }
            
            /* Upcase realm name */
            for (p = realm; *p; p++) {
                if (islower(*p)) *p = toupper(*p);
            }
            
            if (*realm) {
                if (krb_get_lrealm(lrealm,1) == 0 &&
		    strcmp(lrealm, realm) == 0) {
                    *realm = 0;
                }
                else if (krb_get_krbhst(krbhst, realm, 1)) {
                    return 0;           /* Unknown realm */
                }
            }
            
            strcpy(localuser, aname);
            if (*inst) {
                strcat(localuser, ".");
                strcat(localuser, inst);
            }
            if (*realm) {
                strcat(localuser, "@");
                strcat(localuser, realm);
            }
            
            return localuser;
        }
    }

    fclose(mapfile);
    return 0;
}

/*
 * Convert 'identifier' into canonical form.
 * Returns a pointer to a static buffer containing the canonical form
 * or NULL if 'identifier' is invalid.
 */
static char *afspts_canonifyid(const char *identifier, size_t len)
{
    static char retbuf[MAX_K_NAME_SZ+1];
    char aname[ANAME_SZ];
    char inst[INST_SZ];
    char realm[REALM_SZ];
    char lrealm[REALM_SZ];
    char krbhst[MAX_HSTNM];
    char *canon_buf;
    char *p;

    if(!len) len = strlen(identifier);

    canon_buf = xmalloc(len + 1);
    memcpy(canon_buf, identifier, len);
    canon_buf[len] = '\0';
   
    aname[0] = inst[0] = realm[0] = '\0';
    if (kname_parse(aname, inst, realm, canon_buf) != 0) {
	free(canon_buf);
        return 0;
    }

    free(canon_buf);
    
    /* Upcase realm name */
    for (p = realm; *p; p++) {
        if (islower(*p)) *p = toupper(*p);
    }
    
    if (*realm) {
        if (krb_get_lrealm(lrealm,1) == 0 &&
	    strcmp(lrealm, realm) == 0) {
            *realm = 0;
        }
        else if (krb_get_krbhst(krbhst, realm, 1)) {
            return 0;           /* Unknown realm */
        }
    }
    

    /* Check for krb.equiv remappings. */
    p = auth_map_krbid(aname, inst, realm);
    if (p) {
        strcpy(retbuf, p);
        return retbuf;
    }
    
    strcpy(retbuf, aname);
    if (*inst) {
        strcat(retbuf, ".");
        strcat(retbuf, inst);
    }
    if (*realm) {
        strcat(retbuf, "@");
        strcat(retbuf, realm);
    }
    
    return retbuf;
}

/* API */
const char *ptsmodule_name = "afskrb";

void ptsmodule_init(void) 
{
    int r = pr_Initialize (1L, AFSCONF_CLIENTNAME, 0);
    if (r) {
	syslog(LOG_DEBUG, "pr_Initialize failed: %d", r);
	fatal("pr_initialize failed", EC_TEMPFAIL);
    }
    return;
}

struct auth_state *ptsmodule_make_authstate(const char *identifier,
					    size_t size,
					    const char **reply, int *dsize) 
{
    const char *canon_id = afspts_canonifyid(identifier, size);
    namelist groups;
    int i, rc;
    struct auth_state *newstate;

    *reply = NULL;
    size = strlen(canon_id);

    memset(&groups, 0, sizeof(groups));
    groups.namelist_len = 0;
    groups.namelist_val = NULL;
    
    if ((rc = pr_ListMembers(canon_id, &groups))) {
	/* Failure may indicate that we need new tokens */
	pr_End();
	rc = pr_Initialize (1L, AFSCONF_CLIENTNAME, 0);
        if (rc) {
	    syslog(LOG_DEBUG, "pr_Initialize failed: %d", rc);
	    fatal("pr_Initialize failed", EC_TEMPFAIL);
        }
	/* Okay, rerun it now */
	rc = pr_ListMembers(canon_id, &groups);
    }

    if(rc) 
    {
        syslog(LOG_ERR, "pr_ListMembers %s: %s", canon_id, error_message(rc));
        *reply = error_message(rc);
	return NULL;
    }

    /* fill in our new state structure */
    *dsize = sizeof(struct auth_state) + 
	(groups.namelist_len * sizeof(struct auth_ident));
    newstate = (struct auth_state *) xmalloc(*dsize);

    strcpy(newstate->userid.id, canon_id);
    newstate->userid.hash = hash(canon_id);

    newstate->mark = time(0);
    newstate->ngroups = groups.namelist_len;
    /* store group list in contiguous array for easy storage in the database */
    memset(newstate->groups, 0, newstate->ngroups * sizeof(struct auth_ident));
    for (i = 0; i < newstate->ngroups; i++) {
        strcpy(newstate->groups[i].id, groups.namelist_val[i]);
	newstate->groups[i].hash = hash(groups.namelist_val[i]);
	/* don't free groups.namelist_val[i]. Something else currently
	 * takes care of that data. 
	 */
    }
    if (groups.namelist_val != NULL) {
	free(groups.namelist_val);
    }

    return newstate;
}

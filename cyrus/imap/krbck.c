/* krbck.c -- Test KERBEROS_V4 server configuration
 * $Id: krbck.c,v 1.12.16.1 2002/07/25 17:21:42 ken3 Exp $
 
 * Copyright (c) 1998-2000 Carnegie Mellon University.  All rights reserved.
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
#include <config.h>

#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <netdb.h>
#include <netinet/in.h>
#include <krb.h>
#include <des.h>
#include <netinet/in.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "xmalloc.h"

#define EXIT_CHOKE (int) 10

#define CONFIG_FILENAME "/etc/imapd.conf"
#define MAX_FILENAME_LEN 255

int errno;

static int  evalcheck(char*, int, char*);
static void evalerrorno(int);
extern char* strerror (int);

void fatal(const char* string, int choke)
{
    fprintf(stderr,"\tfatal: %s", string);
    exit(choke);
}

/* arguments:
 * m: message to print announcing test
 * c: a test that should be true
 * f: a message to print if it's not 
 */

int evalcheck(m, c, f)
char *m;
int c;
char *f;
{
    printf("Test: %s ... ",m);
    if (c) {
	printf("Ok.\n");
    } else {
	printf("\n\tfailed: %s\n", f);
    }
    return !c;
}

/* Print message vased on ern (errno passed to fn).
 */
void evalerrno(ern)
int ern;
{
    char *s = NULL;

    s = strerror((int) ern);
    printf("errno: %s\n", s);
}

int main(argc, argv)
int argc;
char **argv;
{
    struct stat statbuf;
    struct servent *servent = NULL;
    
    char realm[REALM_SZ];
    char hostname[REALM_SZ];
    char *phost, *pc;

    char tktstring[MAX_FILENAME_LEN];

    /* for reading /etc/imapd.conf */
    FILE *infile;
    int lineno = 0;
    int alloced = 0;
    char buf[4096];
    char tempbuf[4096];
    char *p, *key, *srvtab = NULL;
    char *configdirectory = NULL;

    struct hostent *local;
   
    int err;

    KTEXT_ST authent;
    AUTH_DAT ad;

    /* getservbyname("kerberos", "udp") returns port 750
     * if fails, tell them to add "kerberos 750/udp" to /etc/services
     */
    servent = getservbyname("kerberos", "udp");
    
    if (evalcheck("getservbyname(\"kerberos\", \"udp\")",
		  servent->s_port == htons(750),
		  "Add \"kerberos 750/udp\" to /etc/services.")) {
	exit(EXIT_CHOKE);
    }
    
    /* Files /etc/krb.conf and /etc/krb.realms exist
     */
    if (evalcheck("looking for /etc/krb.conf",
		  !stat("/etc/krb.conf", &statbuf),
		  "stat of /etc/krb.conf failed.")) {
	evalerrno(errno);
	exit(EXIT_CHOKE);
    }
    if (evalcheck("looking for /etc/krb.realms",
		  !stat("/etc/krb.realms", &statbuf),
		  "stat of /etc/krb.realms failed.")) {
	evalerrno(errno);
	exit(EXIT_CHOKE);
    }
    
    /* Can call krb_get_lrealm(realm, 0)
     */
    krb_get_lrealm(realm, 0);
    if (evalcheck("krb_get_lrealm(realm, 0)",
		  *realm != '\0',
		  "local realm is not set in /etc/krb.conf")) {
	printf("\tkrb_get_lrealm returned \"\"\n");
    } else {
	printf("\t[realm == %s]\n", realm);
    }

    /* krb_realmofhost(gethostname()) is equal to krb_get_lrealm()
     */
    if (gethostname(hostname, REALM_SZ)) {
	printf("gethostname() failed!\n");
	evalerrno(errno);
	exit(EXIT_CHOKE);
    }

    if (evalcheck("krb_realmofhost(gethostname()) == krb_get_lrealm() above",
		  !strcmp(krb_realmofhost(hostname), realm),
		  "/etc/krb.realms does not agree with /etc/krb.conf\n")) {
	printf("\thostname=%s krb_realmofhost(hostname)=%s\n",
	       hostname, krb_realmofhost(hostname));
	exit(EXIT_CHOKE);
    }

    /* srvtab option is set in /etc/imapd.conf
     */
    /* This code is stolen directly from Cyrus and simplified (we only
     * need two options).*/
    infile = fopen(CONFIG_FILENAME, "r");
    if (!infile) {
        snprintf(buf, sizeof(buf), "can't open configuration file %s: %s",
		CONFIG_FILENAME, strerror(errno));
        fatal(buf, EXIT_CHOKE);
    }
    
    while (fgets(buf, sizeof(buf), infile)) {
        lineno++;
	
        if (buf[strlen(buf)-1] == '\n') buf[strlen(buf)-1] = '\0';
        for (p = buf; *p && isspace(*p); p++);
        if (!*p || *p == '#') continue;
	
        key = p;
        while (*p && (isalnum((unsigned char) *p) || *p == '-')) {
            if (isupper((unsigned char) *p)) 
		*p = tolower((unsigned char) *p);
            p++;
        }
        if (*p != ':') {
            snprintf(buf, sizeof(buf),
                    "invalid option name on line %d of configuration file",
                    lineno);
            fatal(buf, EXIT_CHOKE);
        }
        *p++ = '\0';
	
        while (*p && isspace(*p)) p++;
        
        if (!*p) {
            snprintf(buf, sizeof(buf),
		    "empty option value on line %d of configuration file",
                    lineno);
            fatal(buf, EXIT_CHOKE);
        }
	
	if (!strcmp(key, "srvtab")) {
	    /* "right thing" is in p */
	    srvtab = xstrdup(p);
	}
	if (!strcmp(key, "configdirectory")) {
	    /* "right thing" is in p */
	    configdirectory = xstrdup(p);
	}
	
    }

    fclose(infile);


    snprintf(tempbuf, sizeof(tempbuf),
	     "configdirectory option not set in %s", CONFIG_FILENAME);
    if (evalcheck("looking up configdirectory option", (configdirectory != NULL), tempbuf)) {
	exit(EXIT_CHOKE);
    } else {
	printf("\tconfigdirectory is set to \"%s\"\n", configdirectory);
    }
	
    /* configdirectory exists and is readable
     */
    if (evalcheck("looking for configdirectory",
		  !stat(configdirectory, &statbuf),
		  "stat of configdirectory failed")) {
	evalerrno(errno);
	exit(EXIT_CHOKE);
    }

    /* running as cyrus? */
    if (evalcheck("running as cyrus user",
		  (getuid() == statbuf.st_uid),
		  "Run this program as the cyrus user.")) {
	exit(EXIT_CHOKE);
    }
    
    snprintf(tempbuf, sizeof(tempbuf),
	     "srvtab option not set in %s", CONFIG_FILENAME);
    if (evalcheck("looking up srvtab option", (srvtab != NULL), tempbuf)) {
	exit(EXIT_CHOKE);
    } else {
	printf("\tsrvtab file set to \"%s\"\n", srvtab);
    }

    /* srvtab file exists and is readable
     */
    if (evalcheck("looking for srvtab file",
		  !stat(srvtab, &statbuf),
		  "stat of srvtab file failed")) {
	evalerrno(errno);
	exit(EXIT_CHOKE);
    }

    if (evalcheck("checking cyrus' read rights on srvtab",
		  (statbuf.st_mode & 256 /*4 + 32 + 256*/),
		  /* either group or owner or everyone, I guess */
		  "can't read srvtab file")) {
	printf("\trights -- %d\n", statbuf.st_mode);
	exit(EXIT_CHOKE);
    }
    if (evalcheck("checking everyone else's read rights on srvtab",
		  !((statbuf.st_mode) & 4),
		  "srvtab should not be world readable")) {
	printf("\trights -- %d\n", statbuf.st_mode);
	exit(EXIT_CHOKE);
    }
    if (evalcheck("checking if cyrus owns srvtab file",
		  (getuid() == statbuf.st_uid),
		  "cyrus should own the srvtab file")) {
	exit(EXIT_CHOKE);
    }
    /* srvtab file has imap.host entry in it (there's some kerberos
     * lib call to fetch this)
     */
    /* Derrick says code below does that */
    /* sprintf(tktstring, "/tmp/tkt_pid_%d", getpid());
     * krb_set_tkt_string(tktstring);
     * krb_get_svc_in_tkt("imap", phost, realm, "krbtgt", realm, 127,
     * srvtab) succeeds
     * * If fails, use error message to diagnose:
     * * no such user --> imap.host entry is not in krb database
     * * bad passwd --> imap.host passwd in srvtab doesn't
     * *   match krb database
     */
    /* XXX phost is just mach name, right? */
    phost = xstrdup(hostname);
    
    pc = strchr(phost, '.');

    if (pc!=NULL) {
	*pc = '\0';
    }

    printf("\tserver's Kerberos identity: imap.%s@%s\n", phost, realm);

    snprintf(tktstring, sizeof(tktstring), "/tmp/tkt_pid_%d", getpid());
    krb_set_tkt_string(tktstring);
    if (evalcheck("attempting to get tickets (krb_get_svc_in_tkt)",
		  (err = krb_get_svc_in_tkt("imap", phost, realm,
					   "krbtgt", realm, 127,
					   srvtab)) == INTK_OK ,
	     "couldn't get tickets!")) {

	switch (err) {
	case INTK_PROT:
	    printf("\terror code indicates wrong protocol version (INTK_PROT)\n.");
	    break;
#ifdef INTK_PW_NULL
	case INTK_PW_NULL:
	    printf("\terror code indicates password was NULL\n");
	    break;
#endif
	case INTK_BADPW:
	    printf("\terror code indicates bad password -- imap.%s@%s passwd in srvtab doesn't match kerberos database (INTK_BADPW)\n",
		   phost, realm);
	    break;
	case INTK_ERR:
	    printf("\tticket is for the wrong server or ticket store can't be initialized (INTK_ERR)\n");
	    break;
	case KDC_PR_UNKNOWN:
	    printf("\terror code indicates imap.%s@%s is not in the Kerberos server database\n", phost, realm);
	    break;
	default:
	    printf("\tReason unknown (error = %d)\n", err);
	}
	exit(EXIT_CHOKE);
    }

    /* krb_mk_req(buf, "imap", phost, realm, 0)
     * use error message to diagnose
     * clock skew between us and kerberos server
     */
    
    if (evalcheck("krb_mk_request(&authent,\"imap\", phost, realm, 0)",
		  !(err=krb_mk_req(&authent, "imap", phost, realm, 0)),
		  "returned nonzero")) {
	printf("\terror is: %s\n", error_message(err));
    }

    /* krb_rd_req(...)
       int krb_rd_req(authent,service,instance,from_addr,ad,fn)
       KTEXT authent;
       char *service;
       char *instance;
       u_long from_addr;
       AUTH_DAT *ad;
       char *fn;
     */

    if (evalcheck("krb_rd_req(&authent, \"imap\", phost, 0L, &ad, srvtab)",
		  !(err=krb_rd_req(&authent, "imap", phost, 
				 0L /* XXX why? */, &ad, srvtab)),
		  "returned nonzero")) {
	printf("\terror is: %s\n", error_message(err));
	exit(EXIT_CHOKE);
    }
				 
    printf("Done.\n");

    free(phost);

    return 0;
}

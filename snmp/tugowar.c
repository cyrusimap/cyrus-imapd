/* tugowar.c -- Listens on unix domain udp socket and keeps track of oids
 * $Id: tugowar.c,v 1.8 2003/01/08 16:34:23 rjs3 Exp $
 *
 * Copyright (c) 2000 Carnegie Mellon University.  All rights reserved.
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


#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <agentx.h>
#include <agentx/hash.h>

#ifndef DEFAULT_TIMEOUT
#define DEFAULT_TIMEOUT 30
#endif

#define SOCK_PATH "/tmp/.snmp_door"

static int debugmode = 0;


typedef struct oid_trie_s {

    int value;

    agentx_oid_t *oid;
    agentx_vardata_t vardata;
    agentx_vartype_t type;

    int numchildren;
    int numchildren_alloc;

    struct oid_trie_s *parent;
    struct oid_trie_s **children;

} oid_trie_t;

oid_trie_t *trie_top;
int           agentx_session; /* agentx session id */

#define err(error_class, routine, call) \
    printf("%s error in tugowar.c: %s; %s\n", (error_class), (routine), (call))

#define IMAPMIB_NPARMS 11
u_int IMAPCommandsMIB [IMAPMIB_NPARMS]  = { 1, 3, 6, 1, 4, 1, 3, 2, 2, 3 };

agentx_errortype_t
mib_general_get  ( int Nsubid, u_int *subids, agentx_varbind_t *binding, int map );
int mib_general_getn ( agentx_oid_t *name, int baselen, int map_handle );

oid_trie_t *new_leaf(int value, oid_trie_t *parent, agentx_vartype_t type)
{
    oid_trie_t *ret = (oid_trie_t *) malloc(sizeof(oid_trie_t));

    if(!ret) {
	err("Critical","mib_general_getn","memory allocation error");
	exit(1);
    }

    ret->value = value;
    ret->type = type;
    
    ret->parent = parent;
    ret->oid = NULL;
    ret->numchildren=0;

    memset(&ret->vardata, '\0', sizeof(agentx_vardata_t));
    
    ret->numchildren_alloc = 10;
    ret->children = (oid_trie_t **)malloc(sizeof(oid_trie_t *)*ret->numchildren_alloc);

    if(!ret->children) {
	err("Critical","mib_general_getn,children","memory allocation error");
	exit(1);
    }
    
    return ret;
}

/* returns new child */
oid_trie_t* add_leaf_to_branch(oid_trie_t *branch, oid_trie_t *leaf)
{
    int lup, lup2;

    /* do we need to make the trie bigger? */
    if (branch->numchildren >= branch->numchildren_alloc - 1)
    {
	branch->numchildren_alloc+=10;
	branch->children = 
	    (oid_trie_t **)realloc(branch->children,
				   sizeof(oid_trie_t *)
				          * branch->numchildren_alloc);

	if(!branch->children) {
	    err("Critical","add_leaf_to_branch","memory allocation error");
	    exit(1);
	}
    }

    /* we want the invariant that this list is always sorted so place in the right place */
    
    for (lup=0; lup < branch->numchildren; lup++)
	if (leaf->value < branch->children[lup]->value)
	    break;

    /* we're inserting in middle. move end ones back */
    if (lup < branch->numchildren)
    { 	
	for (lup2 = branch->numchildren - 1; lup2 >= lup; lup2--)
	    branch->children[lup2+1]=branch->children[lup2];
    }
    
    branch->children[lup]=leaf;
    branch->numchildren++;

    return leaf;
}

oid_trie_t *find_oid_str(oid_trie_t *branch, char *str, agentx_vartype_t type)
{
    int num;
    int lup;
    int numchildren;

    num = strtol(str, NULL, 10);

    while (isdigit((int) *str))
    {
	str++;
    }

    numchildren = branch->numchildren;
    /* look for it in trie */
    for (lup=0;lup<numchildren;lup++)
    {
	if (branch->children[lup]->value == num)
	{
	    branch=branch->children[lup];
	    break;
	}
    }
    /* didn't find. let's add */
    if (lup == numchildren)
    {
	branch = add_leaf_to_branch(branch, new_leaf(num, branch, type));
    }
    

    if (*str == '.') {
	str++;
	return find_oid_str(branch, str, type);
    } else {
	return branch;
    }
}

oid_trie_t *find_oid_nums(oid_trie_t *branch, int Nsubid, u_int *subids)
{
    int lup;
    int numchildren;

    if (Nsubid==0) return branch;

    /* look for it in trie */
    numchildren = branch->numchildren;
    for (lup=0;lup<numchildren;lup++)
    {
	if (branch->children[lup]->value == subids[0])
	{
	    branch=branch->children[lup];
	    break;
	}
    }

    if (lup == numchildren)
    {
	printf("not found!\n");
	return NULL;
    }

    return find_oid_nums(branch, Nsubid-1, subids+1);
}

int go_down(oid_trie_t *branch, int Nsubid, u_int *subids, oid_trie_t **dest)
{
    int lup;
    int numchildren;

    if (Nsubid<=0)
    {
	*dest = branch;
	return 0;
    }

    printf("go_down()    looking for: %d\n",subids[0]);

    /* look for it in trie */
    numchildren = branch->numchildren;
    for (lup=0;lup<numchildren;lup++)
    {
	if (branch->children[lup]->value == subids[0])
	{
	    branch=branch->children[lup];
	    break;
	}
    }

    if (lup == numchildren)
    {
	printf("not found! in go_down()\n");
	*dest = branch;
	return Nsubid;
    }

    return go_down(branch, Nsubid-1, subids+1, dest);    
}

oid_trie_t *find_after(oid_trie_t *t, long next)
{
    if (t->numchildren > 0)
    {
	int lup;
	int found = 0;

	for (lup = 0;lup<t->numchildren;lup++)
	{
	    if (t->children[lup]->value > next)
	    {
		found = 1;
		break;
	    }
	}

	/* if we found something */
	if (found == 1)
	{
	    return find_after(t->children[lup], -2);
	} else {
	    if (t->parent == NULL) return NULL;
	    /* go to parent */
	    return find_after(t->parent, t->value);
	}
    } else {
	if (next == -2)
	{
	    int lup;

	    return t;
	}

	if (t->parent == NULL) return NULL;
	return find_after(t->parent, t->value);
    }

    return NULL;
}

void print_oid(agentx_oid_t *oid)
{
    int lup;
    printf("size = %d\n",oid->Nsubid);
    for (lup=0;lup<oid->Nsubid;lup++)
	printf("%d.",oid->subids[lup]);
    
    printf("\n");

}

int find_next(oid_trie_t *t, int len, u_int  *data, int baselen)
{
    int lup;
    int left;
    int diff;
    oid_trie_t *cur;

    printf("len = %d baselen = %d\n",len,baselen);
    /* go down as far as we can */
    left = go_down(t, len-baselen, data+baselen, &cur);
    
    if (left != 0)
	cur = find_after(cur, data[len-left]);
    else
	cur = find_after(cur, -1);

    if (cur == NULL) return -1;
    if (cur->oid == NULL) return -1;

    /* check to make sure oid matches up to baselen */
    for (lup=0;lup<baselen;lup++)
	if (cur->oid->subids[lup]!=data[lup])
	    return -1;

    diff = cur->oid->Nsubid - baselen;
    
    for (lup = baselen ; lup<cur->oid->Nsubid;lup++)
	data[lup]=cur->oid->subids[lup];
	
    return diff;
}

agentx_oid_t *makeoid(char *str)
{
    agentx_oid_t *ret = (agentx_oid_t *) malloc(sizeof(agentx_oid_t));
    int num;
    int lup;
    
    if(!ret) {
	err("Critical","makeoid","memory allocation error");
	exit(1);
    }
  
    ret->Nsubid = 0;
    ret->subids = (u_int *) malloc(sizeof(u_int *)*50); /* xxx max oid size? */

    if(!ret->subids) {
	err("Critical","makeoid,subids","memory allocation error");
	exit(1);
    }

    str--;

    do {
	str++;
	num = strtol(str, NULL, 10);

	ret->subids[ret->Nsubid]=num;
	ret->Nsubid++;
	if (ret->Nsubid == 50) /* xxx */
	{
	    printf("xxx\n");
	    exit(1);
	}

	while (isdigit((int) *str))
	{
	    str++;
	}
	
    } while (*str=='.');

    return ret;
}

agentx_oid_t **registeredlist;
int *registrationmaplist;
int registeredsize = 0;
int registeredalloc = 0;

static int mib_register(char *str)
{
    int reg_imap;
    agentx_oid_t *oid = makeoid(str);
    int lup;

    /* make sure we haven't already registered this oid */
    for (lup=0;lup<registeredsize;lup++)
	if (agentx_oidcmp (registeredlist[lup]->Nsubid, registeredlist[lup]->subids,
			   oid->Nsubid, oid->subids) == 0)
	{
	    free(oid);
	    return 0;
	}

    printf("registering %s\n",str);

    /* add to registered list */
    if (registeredsize >= registeredalloc)
    {
	registeredalloc+=100;
	registeredlist = realloc(registeredlist, sizeof(agentx_oid_t *) * registeredalloc);
	registrationmaplist = realloc(registrationmaplist, sizeof(int) * registeredalloc);

	if(!registeredlist || !registrationmaplist) {
	    err("Critical","mib_register",
		"registeredlists memory allocation error");
	    exit(1);
	}
    }

    registeredlist[registeredsize] = oid;
    registeredsize++;

    reg_imap  = agentx_register( agentx_session, 0, 0, 127, oid->Nsubid,
				 oid->subids);

    if (reg_imap < 0)
    {
	err("Internal","mib_register","");
	exit(1);
    }
    
    registrationmaplist[registeredsize-1] = agentx_mapget( reg_imap, 0, NULL, &mib_general_get, &mib_general_getn );

    if (registrationmaplist[registeredsize-1] < 0)
    {
	exit(1);
    }

    return 0;
}

oid_trie_t *find(char *str, char **tmp, agentx_vartype_t type)
{
    oid_trie_t *tree;

    tree = find_oid_str(trie_top,str, type);

    if (tree==NULL)
    {
	err("Internal","find","find_oid_str");
	exit(1);
    }
    
    if (tree->oid==NULL)
    {
	tree->oid = makeoid(str);
    }
    
    /* find space */
    *tmp = strchr(str,' ');
    if (*tmp==NULL) {
	err("Internal","find","no space found");
	exit(1);
    }
    tmp++;

    return tree;
}

/*
 * Log a command. The format of the string should be:
 *
 * <type> <oid in string format> [optional arguements]\n
 *
 * ex: C 1.3.6.1.4.6.3 1\n
 */

void log_cmd(char *str)
{
    oid_trie_t *tree;
    char *tmp;

    printf("received [%s]\n",str);

    if(strlen(str) < 2) {
	printf("Not Understood");
	return;
    }
    
    switch(str[0])
	{
	case 'C': /* counter32 */
	    tree = find(str+2, &tmp, agentx_Counter32);
	    if (!tree) break;

	    tree->vardata.int_data += atoi(tmp);
	    break;
	case 'I':
	    tree = find(str+2, &tmp, agentx_Integer);
	    if (!tree) break;
	    
	    tree->vardata.int_data = atoi(tmp);
	    break;
	case 'S':
	    tree = find(str+2, &tmp, agentx_OctetString);
	    if (!tree) break;

	    tree->vardata.ostr_data.len = strlen(tmp);
	    tree->vardata.ostr_data.data = strdup(tmp);
	    if(!tree->vardata.ostr_data.data) {
		err("Critical","logcmd(\"S\")", "memory allocation error");
		exit(1);
	    }
	    
	    break;

	case 'T': /* time. we're given time. someone will request the time interval of us */
	    tree = find(str+2, &tmp, agentx_TimeTicks);
	    if (!tree) break;

	    tree->vardata.int_data = atoi(tmp); /* xxx can we store a time_t here? */
	    break;

	case 'R':
	    mib_register(str+2);
	    break;
	default:
	    printf("Not understood\n");
	    break;
	}
}

agentx_errortype_t
mib_general_get  ( int Nsubid, u_int *subids, agentx_varbind_t *binding, int map )
{
    oid_trie_t *oidt;
    agentx_vardata_t vardata;
    int lup;
    agentx_oid_t *base;

    /* find the base xxx this is inefficient */
    for (lup=0;lup<registeredsize;lup++)
	if (map == registrationmaplist[lup])
	    base = registeredlist[lup];
	    

    oidt = find_oid_nums(trie_top, base->Nsubid, base->subids);
    if (oidt==NULL){ printf("unable to find any imap\n"); return agentx_genErr; }

    oidt = find_oid_nums(oidt, Nsubid, subids);

    if (oidt==NULL){
	err("Internal","mib_general_get","unable to find specific");
	return agentx_genErr;
    }

    if (oidt->oid==NULL) { 
	err("Internal","mib_general_get","");
	return agentx_genErr;
    }
           
    binding->type = oidt->type;

    if (oidt->type == agentx_TimeTicks)
    {
	binding->data.int_data = time(NULL) - oidt->vardata.int_data;
    } else {
	binding->data = oidt->vardata;
    }

    return agentx_noError;     
}

int mib_general_getn ( agentx_oid_t *name, int baselen, int map_handle )
{
    int lup;
    oid_trie_t *cur, *next;
    int newlen;

    cur = find_oid_nums(trie_top, baselen, name->subids);
    if (cur == NULL) { printf("not found base\n"); return agentx_genErr; }
        
    newlen = find_next(cur, name->Nsubid, name->subids, baselen);

    if (newlen == -1) { printf("not found in getn\n"); return AGENTX_NOTFOUND; }

    name->Nsubid = newlen+baselen;

    return AGENTX_OK;
}

int main(int argc, char **argv)
{
    int s, len;
    struct sockaddr_un local;
    char str[100];
    int lup;
    struct sockaddr_un from;
    int fromlen;
    agentx_oid_t  session_oid;
    mode_t oldumask;
    pid_t pid;
    int opt;

    while ((opt = getopt(argc, argv, "d")) != EOF) {
	switch (opt) {
	case 'd': /* don't fork. debugging mode */
	    debugmode = 1;
	    break;
	default:
	    fprintf(stderr, "invalid argument\n");
	    exit(1);
	    break;
	}
    }

    /* fork unless we were given the -d option */
    
    if (debugmode == 0) {
	pid = fork();
	
	if (pid == -1) {
	    perror("fork");
	    exit(1);
	}
	
	if (pid != 0) { /* parent */
	    exit(0);
	}
    }
    /* child */
    
    /* start up agentx */
    if ( !agentx_init( NULL ) ) {
	printf("Error starting AgentX\n");
	exit(1);
    }

    session_oid.Nsubid  = IMAPMIB_NPARMS;
    session_oid.include = 0;
    session_oid.subids  = IMAPCommandsMIB;
    agentx_session      = agentx_open( DEFAULT_TIMEOUT, &session_oid,
				       "CMU IMAP Commands MIB");
    if (agentx_session == AGENTX_NOTRUNNING)
    {
	fprintf(stderr, "AgentX not running\n");
	exit (1);
    }

    /* create socket we are going to use */
    if ((s = socket(AF_UNIX, SOCK_DGRAM, 0)) == -1) {
	perror("socket");
	exit(1);
    }

    /* bind it to a local file */
    local.sun_family = AF_UNIX;
    strcpy(local.sun_path, SOCK_PATH);
    unlink(local.sun_path);
    len = strlen(local.sun_path) + sizeof(local.sun_family);

    oldumask = umask((mode_t) 0); /* for Linux */

    if (bind(s, (struct sockaddr *)&local, len) == -1) {
	perror("bind");
	exit(1);
    }
    umask(oldumask); /* for Linux */
    chmod(SOCK_PATH, 0777); /* for DUX */

    trie_top = new_leaf(1, NULL, agentx_Null);

    registeredalloc = 100;
    registeredlist = (agentx_oid_t **) malloc(sizeof(agentx_oid_t *)*registeredalloc);
    registrationmaplist = (int *) malloc(sizeof(int) * registeredalloc);

    if(!registeredlist || !registrationmaplist) {
	err("Critical","main","registeredlists memory allocation error");
	exit(1);
    }

    /*
     * All we do is:
     * -listen for an UDP packet
     * -log it
     * -repeat
     */

    printf ("listening\n");

    for(;;) {
	int n;

	fromlen = sizeof(from);
	
	n = recvfrom(s, str, (int)sizeof(str)-1, 0,
		     (struct sockaddr *)&from, &fromlen);
	if(n<0) {
	    err("Network","main","recvfrom");
	    exit(1);
	}
	str[n]  = '\0';

	printf("read %d bytes\n",n);

	if (n>0)
	    log_cmd(str);

	/* ignore errors */
	
    }

    /* never gets here */      
    return 0;
}

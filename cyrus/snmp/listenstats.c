/* listenstats.c -- Listens on unix domain udp socket and keeps track of cmd counts
 *
 * Copyright 1998 Carnegie Mellon University
 * 
 * No warranties, either expressed or implied, are made regarding the
 * operation, use, or results of the software.
 *
 * Permission to use, copy, modify and distribute this software and its
 * documentation is hereby granted for non-commercial purposes only
 * provided that this copyright notice appears in all copies and in
 * supporting documentation.
 *
 * Permission is also granted to Internet Service Providers and others
 * entities to use the software for internal purposes.
 *
 * The distribution, modification or sale of a product which uses or is
 * based on the software, in whole or in part, for commercial purposes or
 * benefits requires specific, additional permission from:
 *
 *  Office of Technology Transfer
 *  Carnegie Mellon University
 *  5000 Forbes Avenue
 *  Pittsburgh, PA  15213-3890
 *  (412) 268-4387, fax: (412) 268-7395
 *  tech-transfer@andrew.cmu.edu
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

typedef struct oid_trie_s {

    int value;

    agentx_oid_t *oid;
    agentx_vardata_t vardata;

    int numchildren;
    int numchildren_alloc;

    struct oid_trie_s *parent;
    struct oid_trie_s **children;

} oid_trie_t;

oid_trie_t *trie_top;

#define IMAPMIB_NPARMS 11
u_int IMAPCommandsMIB [IMAPMIB_NPARMS]  = { 1, 3, 6, 1, 4, 1, 3, 2, 2, 2, 6 };

oid_trie_t *new_leaf(int value, oid_trie_t *parent)
{
    oid_trie_t *ret = (oid_trie_t *) malloc(sizeof(oid_trie_t));
    ret->value = value;

    ret->parent = parent;
    ret->oid = NULL;
    ret->numchildren=0;

    memset(&ret->vardata, '\0', sizeof(agentx_vardata_t));
    
    ret->numchildren_alloc = 10;
    ret->children = (oid_trie_t **)malloc(sizeof(oid_trie_t *)*ret->numchildren_alloc);
    
    return ret;
}

/* returns new child */
oid_trie_t* add_leaf_to_branch(oid_trie_t *branch, oid_trie_t *leaf)
{
    int lup;

    /* do we need to make the trie bigger? */
    if (branch->numchildren >= branch->numchildren_alloc)
    {
	branch->numchildren_alloc+=10;
	branch->children = (oid_trie_t **)realloc(branch->children,
					      sizeof(oid_trie_t *)*branch->numchildren_alloc);
    }

    /* we want the invariant that this list is always sorted so place in the right place */
    
    for (lup=0;lup<branch->numchildren;lup++)
	if (leaf->value < branch->value)
	    break;

    if (lup < branch->numchildren)
    { 	
	memcpy( branch->children+lup+1, branch->children, (branch->numchildren - lup)*sizeof(oid_trie_t *));	
    } 
    
    branch->children[lup]=leaf;
    branch->numchildren++;

    return leaf;
}

oid_trie_t *find_oid_str(oid_trie_t *branch, char *str)
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
	branch = add_leaf_to_branch(branch, new_leaf(num, branch));
    }
    

    if (*str == '.') {
	str++;
	return find_oid_str(branch, str);
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

    if (Nsubid==0)
    {
	*dest = branch;
	return 0;
    }

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
	    return find_after(t->parent, t->value+1);
	}
    } else {
	if (next == -2)
	{
	    int lup;

	    return t;
	}

	if (t->parent == NULL) return NULL;
	printf("parent %d\n", t->value+1);	
	return find_after(t->parent, t->value+1);
    }

    return NULL;
}

int find_next(oid_trie_t *t, int len, u_int  *data, int baselen)
{
    int lup;
    int left;
    int diff;
    oid_trie_t *cur;

    /* go down as far as we can */
    left = go_down(t, len-baselen, data+len, &cur);
    
    if (left != 0)
	cur = find_after(cur, data[len-left]);
    else
	cur = find_after(cur, -1);

    if (cur == NULL) return -1;
    if (cur->oid == NULL) return -1;

    diff = cur->oid->Nsubid - baselen;
    
    for (lup = baselen ; lup<cur->oid->Nsubid;lup++)
	data[lup]=cur->oid->subids[lup];
	
    return diff;

    /*    if (t->numchildren == 0)
	return NULL;

    for (lup=0;lup<t->numchildren;lup++)
	data[lup]=lup;

	return t->numchildren; */
}

agentx_oid_t *makeoid(char *str)
{
    agentx_oid_t *ret = (agentx_oid_t *) malloc(sizeof(agentx_oid_t));
    int num;
    int lup;
    
    ret->Nsubid = 0;
    ret->subids = (u_int *) malloc(sizeof(u_int *)*50);

    str--;

    do {
	str++;
	num = strtol(str, NULL, 10);

	ret->subids[ret->Nsubid]=num;
	ret->Nsubid++;
	if (ret->Nsubid == 50)
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
/*
 * Log a command. The format of the string should be:
 *
 * <oid in string format>[optional arguements]\n
 *
 * ex: 1.3.6.1.4.6.3\n
 */

void log_cmd(char *str)
{
    oid_trie_t *tree;

    tree = find_oid_str(trie_top,str);

    if (tree==NULL)
    {
	printf("xxx\n");
	exit(1);
    }

    if (tree->oid==NULL)
    {
	tree->oid = makeoid(str);
    }

    tree->vardata.int_data++;
}

agentx_errortype_t
mib_general_get  ( int Nsubid, u_int *subids, agentx_varbind_t *binding, int map )
{
    oid_trie_t *oidt;
    agentx_vardata_t vardata;

    oidt = find_oid_nums(trie_top, IMAPMIB_NPARMS, IMAPCommandsMIB);
    if (oidt==NULL){ printf("unable to find any imap\n"); return agentx_genErr; }

    oidt = find_oid_nums(oidt, Nsubid, subids);

    if (oidt==NULL){ printf("unable to find specific\n"); return agentx_genErr; }
    if (oidt->oid==NULL) { printf("blah\n"); return agentx_genErr; }
           
    binding->type = agentx_Counter32;

    binding->data = oidt->vardata;

    return agentx_noError;     
}

int mib_general_getn ( agentx_oid_t *name, int baselen, int map_handle )
{
    int lup;
    oid_trie_t *cur, *next;
    int newlen;

    cur = find_oid_nums(trie_top, baselen, name->subids);
    if (cur == NULL) { printf("not found\n"); return agentx_genErr; }
    
    

    newlen = find_next(cur, name->Nsubid, name->subids, baselen);

    if (newlen == -1) return AGENTX_NOTFOUND;

    name->Nsubid = newlen+baselen;

    return AGENTX_OK;
}

int main(void)
{
    int s, len;
    struct sockaddr_un local;
    char str[100];
    int lup;
    struct sockaddr_un from;
    int fromlen;
    int           session; /* agentx session id */
    agentx_oid_t  session_oid;
    int reg_imap;
    int map_imap;
    mode_t oldumask;

    /* start up agentx */
    if ( !agentx_init( NULL ) ) {
	printf("Error starting AgentX\n");
	exit(1);
    }

    session_oid.Nsubid  = IMAPMIB_NPARMS;
    session_oid.include = 0;
    session_oid.subids  = IMAPCommandsMIB;
    session             = agentx_open( DEFAULT_TIMEOUT, &session_oid,
				       "CMU IMAP Commands MIB" );
    if (session == AGENTX_NOTRUNNING)
    {
	printf("AgentX not running\n");
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

    trie_top = new_leaf(1, NULL);

    reg_imap  = agentx_register( session, 0, 0, 127, IMAPMIB_NPARMS,
				 IMAPCommandsMIB );

    if (reg_imap < 0)
	{
	    printf("error here\n");
	    exit(1);
	}
    
    map_imap  = agentx_mapget( reg_imap, 0, NULL, mib_general_get, mib_general_getn );

    if (map_imap < 0)
	{
	    exit(1);
	}

    /*
     * All we do is:
     * -listen for an UDP packet
     * -log it
     * -repeat
     */

    for(;;) {
	int n;

	fromlen = sizeof(from);

	printf ("listening\n",n);

	n = recvfrom(s, str, 100, 0, (struct sockaddr *) &from, &fromlen);

	printf ("received %d\n",n);

	if (n>0)
	    log_cmd(str);

	/* ignore errors */
	
    }

    /* never gets here */      
    return 0;
}

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

#include <config.h>

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

#include "pushstats.h"

#define SOCK_PATH "/tmp/imapd_log_socket"

#define LOG_FILE "/var/imap/cmdstats"

/* stats */

int cmd_cnt[PUSHSTATS_MAXCMDS];

int since_last = 0;
#define LOG_EVERY 100

FILE *logstream;

void output_logentry(void)
{
    int lup;

    for (lup=0;lup<PUSHSTATS_MAXCMDS;lup++)
	if (strlen(pushstats_getname(lup))>0)
	    fprintf(logstream, "%s     \t\t%d\n",pushstats_getname(lup), cmd_cnt[lup]);
}


void log_cmd(char *str)
{
    int cmd;

    memcpy(&cmd, str, sizeof(cmd));

    if ((cmd <0) || (cmd>=PUSHSTATS_MAXCMDS))
    {
	/* invalid cmd; ignore */
	return;
    }

    cmd_cnt[cmd]++;

    since_last++;
    
    if (since_last >= LOG_EVERY)
    {
	output_logentry();
	since_last = 0;
    }
}

int main(void)
{
    int s, len;
    struct sockaddr_un local;
    char str[100];
    int lup;
    struct sockaddr_un from;
    int fromlen;

    if ((s = socket(AF_UNIX, SOCK_DGRAM, 0)) == -1) {
	perror("socket");
	exit(1);
    }

    local.sun_family = AF_UNIX;
    strcpy(local.sun_path, SOCK_PATH);
    unlink(local.sun_path);
    len = strlen(local.sun_path) + sizeof(local.sun_family);
    if (bind(s, (struct sockaddr *)&local, len) == -1) {
	perror("bind");
	exit(1);
    }

    /* open log file */
    logstream = fopen(LOG_FILE,"a+");
    if (logstream == NULL)
    {
	printf("Unable to open logfile %s\n",LOG_FILE);
	exit(1);
    }
    
    /* zero out stats */
    for (lup=0;lup<PUSHSTATS_MAXCMDS;lup++)
	cmd_cnt[lup] = 0;

    for(;;) {
	int n;

	fromlen = sizeof(from);

	n = recvfrom(s, str, 100, 0, (struct sockaddr *) &from, &fromlen);

	log_cmd(str);
	
    }

    /* never gets here */      
    return 0;
}

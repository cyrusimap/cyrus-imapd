/* 
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
 */

/* $Id: idle_poll.c,v 1.1 2000/12/14 19:26:48 ken3 Exp $ */

#include <time.h>
#include <unistd.h>
#include <signal.h>

#include "idle.h"
#include "imapconf.h"

/* function to report mailbox updates to the client */
static idle_updateproc_t *idle_update = NULL;

/* how often to poll the mailbox */
static time_t idle_period = -1;


int idle_enabled(void)
{
    /* get polling period */
    if (idle_period == -1) {
      idle_period = config_getint("imapidlepoll", 60);
      if (idle_period < 0) idle_period = 0;
    }

    /* a period of zero disables IDLE */
    return idle_period;
}

void idle_poll(int sig)
{
    idle_update(IDLE_MAILBOX|IDLE_ALERT);

    alarm(idle_period);
}

int idle_init(struct mailbox *mailbox, idle_updateproc_t *proc)
{
    idle_update = proc;

    /* Setup the mailbox polling function to be called at 'idle_period'
       seconds from now */
    signal(SIGALRM, idle_poll);
    alarm(idle_period);

    return 1;
}

void idle_done(struct mailbox *mailbox)
{
    /* Remove the polling function */
    signal(SIGALRM, SIG_DFL);
}

/* message.h
 * Larry Greenfield
 * $Id: message.h,v 1.4 2000/01/28 22:09:55 leg Exp $
 */
/***********************************************************
        Copyright 1999 by Carnegie Mellon University

                      All Rights Reserved

Permission to use, copy, modify, and distribute this software and its
documentation for any purpose and without fee is hereby granted,
provided that the above copyright notice appear in all copies and that
both that copyright notice and this permission notice appear in
supporting documentation, and that the name of Carnegie Mellon
University not be used in advertising or publicity pertaining to
distribution of the software without specific, written prior
permission.

CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND
FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE FOR
ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
******************************************************************/

#ifndef MESSAGE_H
#define MESSAGE_H

typedef struct Action action_list_t;

typedef enum {
    ACTION_NONE,
    ACTION_REJECT,
    ACTION_FILEINTO,
    ACTION_KEEP,
    ACTION_REDIRECT,
    ACTION_DISCARD,
    ACTION_VACATION,
    ACTION_SETFLAG,
    ACTION_ADDFLAG,
    ACTION_REMOVEFLAG,
    ACTION_MARK,
    ACTION_UNMARK,
    ACTION_NOTIFY,
    ACTION_DENOTIFY
} action_t;

/* information */
action_list_t *new_action_list(void);
void free_action_list(action_list_t *actions);

/* invariant: always have a dummy element when free_action_list, param
   and vac_subj are freed.  none of the others are automatically freed.

   the do_action() functions should copy param */
struct Action {
    action_t a;
    union {
	struct {
	    char *msg;
	} rej;
	struct {
	    char *mbox;
	} fil;
	struct {
	    char *addr;
	} red;
	struct {
	    char *addr;		/* freed! */
	    char *fromaddr;     /* freed! */
	    char *subj;		/* freed! */
	    char *msg;
	    int days;
	    int mime;
	} vac;
	struct {
	    char *flag;
	} fla;
	struct {
	    char *priority;
	    char *method;
	    char *message;
	    char **headers;
	} not;
    } u;
    char *param;		/* freed! */
    struct Action *next;
    char *vac_subj;		/* freed! */
    char *vac_msg;
    int vac_days;
};

/* header parsing */
typedef enum {
    ADDRESS_ALL,
    ADDRESS_LOCALPART,
    ADDRESS_DOMAIN
} address_part_t;

int parse_address(char *header, void **data, void **marker);
char *get_address(address_part_t addrpart, void **data, void **marker);
int free_address(void **data, void **marker);

/* actions; return negative on failure.
 * these don't actually perform the actions, they just add it to the
 * action list */
int do_reject(action_list_t *m, char *msg);
int do_fileinto(action_list_t *m, char *mbox);
int do_forward(action_list_t *m, char *addr);
int do_keep(action_list_t *m);
int do_discard(action_list_t *m);
int do_vacation(action_list_t *m, char *addr, char *fromaddr,
		char *subj, char *msg, 
		int days, int mime);
int do_setflag(action_list_t *m, char *flag);
int do_addflag(action_list_t *m, char *flag);
int do_removeflag(action_list_t *m, char *flag);
int do_mark(action_list_t *m);
int do_unmark(action_list_t *m);


#endif

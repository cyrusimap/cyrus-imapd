#ifndef ACAPMBOX_H_
#define ACAPMBOX_H_

/* all functions return IMAP error codes */

int acapmbox_init(void);

#define global_dataset "/mb"

typedef enum {
    ACAPMBOX_UNKNOWN,
    ACAPMBOX_RESERVED,
    ACAPMBOX_COMMITTED
} acapmbox_status;

typedef struct acapmbox_data_s {
    char *name;			/* name of the mailbox */
    unsigned int uidvalidity;

    acapmbox_status status;	/* reserved | committed */
    char *post;			/* where a post to this mailbox should go */
    int haschildren;		/* yes | no */
    char *url;			/* where mailbox is located */
    char *acl;			/* acl */

    unsigned int answered;      /* number of messages with attribute */
    unsigned int flagged;       /* etc */
    unsigned int deleted;
    unsigned int total;
} acapmbox_data_t;

/* helper functions to create an acapmbox_data_t */
char *acapmbox_get_url(char *mbox);
char *acapmbox_get_postaddr(char *mbox);

typedef struct acapmbox_handle_s acapmbox_handle_t;

/*
 * get a handle.  all returns (including NULL) are valid!
 * may be a noop for non-acap-enabled installs.
 */
acapmbox_handle_t *acapmbox_get_handle(void);

void acapmbox_release_handle(acapmbox_handle_t *handle);

/*
 * Create a new entry for mailbox_name
 * 
 * mboxdata is initial value for it (may be NULL)
 *
 * sets the status of the entry on success to reserved
 */
int acapmbox_create(acapmbox_handle_t *AC,
		    acapmbox_data_t *mboxdata);

/* likewise, but you can mark it active immediately; use with caution */
int acapmbox_store(acapmbox_handle_t *AC,
		   acapmbox_data_t *mboxdata,
		   int commit);

/*
 * Commit the entry 
 */
int acapmbox_markactive(acapmbox_handle_t *AC,
			acapmbox_data_t *mboxdata);

/*
 * Remove an entry
 */
int acapmbox_delete(acapmbox_handle_t *AC,
		    char *mailbox_name);


/*
 * Delete all entries (the whole dataset)
 */
int acapmbox_deleteall(acapmbox_handle_t *AC);

/* 
 * does a mailbox exist? 
 * return ACAP_OK if it does; ACAP_FAIL if it doesn't
 */
int acapmbox_entryexists(acapmbox_handle_t *AC,
			 char *mailbox_name);

typedef enum {
    ACAPMBOX_ANSWERED,
    ACAPMBOX_FLAGGED,
    ACAPMBOX_DELETED,
    ACAPMBOX_TOTAL,
    ACAPMBOX_UIDVALIDITY
} acapmbox_property_t;

/*
 * properties are hints that the ACAP server stores about various mailboxes
 * used to provide a master update service
 */
int acapmbox_setproperty_acl(acapmbox_handle_t *AC,
			     char *mailbox_name,
			     char *newvalue);

int acapmbox_setproperty(acapmbox_handle_t *AC,
			 char *mailbox_name,
			 acapmbox_property_t prop,
			 int value);

acapmbox_status mboxdata_convert_status(acap_value_t *v);

/**************** proxy use *****************/
#define FNAME_TARGET_SOCK "/cyrus/target"

#endif /* ACAP_MBOX_H_ */

/***********************************************************
 The following copyright message holds for most of the information
 in this header file:

		Copyright IBM Corporation 1987

                      All Rights Reserved

Permission to use, copy, modify, and distribute this software and its 
documentation for any purpose and without fee is hereby granted, 
provided that the above copyright notice appear in all copies and that
both that copyright notice and this permission notice appear in 
supporting documentation, and that the name of IBM not be
used in advertising or publicity pertaining to distribution of the
software without specific, written prior permission.  

IBM DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING
ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO EVENT SHALL
IBM BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR
ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
SOFTWARE.
******************************************************************/

/*************************************************
 * the following information concerns the .MS_MsgDir file 
 *************************************************/

#define AMS_DATESIZE 7		/* Fixed size of compacted date */
#define AMS_CAPTIONSIZE 89	/* Fixed size of caption line */
#define AMS_CHAINSIZE 4		/* Fixed size of chain number */
#define AMS_MIDHASHSIZE 4	/* Fixed size of message id hash */
#define	AMS_REPLYHASHSIZE 4	/* Fixed size of in-reply-to or references hash */
#define AMS_ATTRIBUTESIZE 21	/* Fixed size of msg attributes */
#define AMS_IDSIZE 19		/* Fixed size of unique ID name */

#define AMS_SNAPSHOTSIZE (AMS_DATESIZE + AMS_CAPTIONSIZE + AMS_CHAINSIZE + AMS_MIDHASHSIZE + AMS_REPLYHASHSIZE + AMS_ATTRIBUTESIZE + AMS_IDSIZE)  /* 148 */

#define AMS_DATEOFFSET 0
#define AMS_DATE(s) ((char *) s)
#define AMS_CAPTIONOFFSET AMS_DATEOFFSET + AMS_DATESIZE
#define AMS_CAPTION(s) (((char *) s) + AMS_CAPTIONOFFSET)
#define AMS_CHAINOFFSET (AMS_CAPTIONOFFSET + AMS_CAPTIONSIZE)
#define AMS_CHAIN(s) (((char *) s) + AMS_CHAINOFFSET)
#define AMS_MIDHASHOFFSET (AMS_CHAINOFFSET + AMS_CHAINSIZE)
#define AMS_MIDHASH(s) (((char *) s) + AMS_MIDHASHOFFSET)
#define AMS_REPLYHASHOFFSET (AMS_MIDHASHOFFSET + AMS_MIDHASHSIZE)
#define AMS_REPLYHASH(s) (((char *) s) + AMS_REPLYHASHOFFSET)
#define AMS_ATTRIBUTEOFFSET (AMS_REPLYHASHOFFSET + AMS_REPLYHASHSIZE)
#define AMS_ATTRIBUTES(s) (((char *) s) + AMS_ATTRIBUTEOFFSET)
#define AMS_IDOFFSET (AMS_ATTRIBUTEOFFSET + AMS_ATTRIBUTESIZE)
#define AMS_ID(s) (((char *) s) + AMS_IDOFFSET)

/* The following define the meaning of the attributes field.
	The numbers are to be interpreted as bits in the successive
	bytes in the attributes field; they are best accessed through
	the AMS_GET_ATTRIBUTE, AMS_SET_ATTRIBUTE, and AMS_UNSET_ATTRIBUTE
	macros defined below. */

#define AMS_GET_ATTRIBUTE(s, a) (AMS_ATTRIBUTES(s)[(a)/8] & 1<<((a) % 8))
#define AMS_SET_ATTRIBUTE(s, a) (AMS_ATTRIBUTES(s)[(a)/8] |= 1<<((a) % 8))
#define AMS_UNSET_ATTRIBUTE(s, a) (AMS_ATTRIBUTES(s)[(a)/8] &= ~(1<<((a) % 8)))

#define AMS_ATT_RRR 0  		/* Return Receipt Requested */
#define AMS_ATT_ENCLOSURE 1		/* Parcel Post */
#define AMS_ATT_DELETED 2	/* Marked for deletion */
#define AMS_ATT_NEWDIR 3	/* Announcing a new message subdirectory */
#define AMS_ATT_FORMATTED 4	/* Multimedia format file */
#define AMS_ATT_MAYMODIFY 5	/* Message this user may alter */
#define AMS_ATT_UNSEEN 6	/* Message is marked as "unseen" */
#define AMS_ATT_UNAUTH 7	/* Message sender is unauthenticated */
#define AMS_ATT_FROMNET 8	/* Message sender is from remote machine */
#define AMS_ATT_VOTE 9		/* Message calls for a vote */
#define AMS_ATT_URGENT 10	/* User marked this message as Urgent */
#define AMS_ATT_CLOSED 11	/* User marked this message as Closed */
#define	AMS_ATT_REPLIEDTO 12	/* Message has been replied to */

/* The current configuration of UATTRs (user attributes) means that the
    last predefined attribute would be number 135.  */

#define AMS_ATT_LAST_UATTR ((21 * 8) - 1)
#define AMS_ATT_UATTR(a) (AMS_ATT_LAST_UATTR - (a))
#define AMS_NUM_UATTRS 32
#define AMS_ATTRNAMEMAX 16

#define	MS_DB_VERSION	4
#define AMS_DIRECTORY_PREFIX_STRING "\003\004\033\277BINARY FILE -- DO NOT EDIT!!!  \n`The mail transport mechanism is trivial.' --Jim Morris\n\n\003\033\277"
#define AMS_PREFIX_LEN 96
#define AMS_PADSIZE 10
#define ATTNAMESLEN (AMS_NUM_UATTRS * AMS_ATTRNAMEMAX)
#define AMS_DIRHEADSIZE (ATTNAMESLEN + (1024 - ATTNAMESLEN) + AMS_SNAPSHOTSIZE)

/****************************************
 * filenames used by AMS
 ****************************************/

#define AMS_SUBSCRIPTIONMAPFILE ".SubscriptionMap"
#define AMS_EXPLANATIONFILE ".MS_intro.txt"
#define MS_TREEROOT ".MESSAGES" /* matches .MESSAGES* */
#define MS_DIRNAME ".MS_MsgDir"
#define AMS_SUBSPROFFILE "~/.AMS.prof"
#define MS_MASTERDIR ".MS.Master"
#define MS_MASTERHINT "HINT_"
#define MS_MASTERUPDATE ".MS.Master/Update"
#define	AMS_MAILBOX_NAME "Mailbox"
#define AMS_DEFAULTMAILDIR "mail"
#define AMS_DIRECTPOST ".MS.DirectPost"
#define AMS_ALIASFILE "~/.AMS_aliases"

/********************************************
 * the following definitions are for the .AMS.prof file
 ********************************************/

#define AMS_UNSUBSCRIBED 0
#define AMS_ASKSUBSCRIBED 1
#define AMS_ALWAYSSUBSCRIBED 2
#define AMS_SHOWALLSUBSCRIBED 3
#define AMS_PRINTSUBSCRIBED 4

/********************************************
 * the following concerns Nifty Mail Validation
 ********************************************/

#define	NMV_POSTMASTER1	422
#define	NMV_POSTMASTER2	657

#define	NMV_VALID   0
#define	NMV_NETWORK 1
#define	NMV_NOBODY  2
#define	NMV_TOSELF  3
#define	NMV_OWNER   4
#define	NMV_FORGED  5

#define NMV_NETMAIL "0;andrew.cmu.edu;Network-Mail"

/*********************************
 * version flag for niftymail
 *********************************/
#define	NM_AMS_VERSION	4

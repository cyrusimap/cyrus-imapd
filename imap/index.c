#include <stdio.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <sys/mman.h>

#include "mailbox.h"
#include "imapd.h"
#include "message.h"
#include "imap_err.h"
#include "xmalloc.h"

static char *index_base;
static long index_len;
static char *cache_base;
static long cache_len;

static time_t index_ino;
static int start_offset;
static int record_size;

static int recentuid;
static int lastnotrecent;

static time_t *flagreport;
static char *seenflag;
static int flagalloced;

#define INDEX_OFFSET(msgno) (index_base+start_offset+(((msgno)-1)*record_size))
#define UID(msgno) ntohl(*((bit32 *)(INDEX_OFFSET(msgno))))
#define INTERNALDATE(msgno) ntohl(*((bit32 *)(INDEX_OFFSET(msgno)+4)))
#define SIZE(msgno) ntohl(*((bit32 *)(INDEX_OFFSET(msgno)+8)))
#define HEADER_SIZE(msgno) ntohl(*((bit32 *)(INDEX_OFFSET(msgno)+12)))
#define CONTENT_OFFSET(msgno) ntohl(*((bit32 *)(INDEX_OFFSET(msgno)+16)))
#define CACHE_OFFSET(msgno) ntohl(*((bit32 *)(INDEX_OFFSET(msgno)+20)))
#define LAST_UPDATED(msgno) ntohl(*((bit32 *)(INDEX_OFFSET(msgno)+24)))
#define SYSTEM_FLAGS(msgno) ntohl(*((bit32 *)(INDEX_OFFSET(msgno)+28)))
#define USER_FLAGS(msgno,i) ntohl(*((bit32 *)(INDEX_OFFSET(msgno)+32+((i)*4))))

#define CACHE_ITEM_DATA(ptr) ((ptr)+4)
#define CACHE_ITEM_LEN(ptr) (ntohl(*((bit32 *)(ptr))))
#define CACHE_ITEM_NEXT(ptr) ((ptr)+4+((3+CACHE_ITEM_LEN(ptr))&~3))

index_newmailbox(mailbox)
struct mailbox *mailbox;
{
    if (index_len) {
	munmap(index_base, index_len);
	munmap(cache_base, cache_len);
	index_len = cache_len = 0;
    }
    imapd_exists = -1;

    return index_check(mailbox);
}

#define SLOP 10 /* XXX 200 */
#define CACHESLOP 100 /* XXX 16*1024 */

index_check(mailbox)
struct mailbox *mailbox;
{
    struct stat sbuf;
    int newexists, i;

#if 0
    if (index_len && mailbox_new_index_header(mailbox)) {
	/* XXX send EXPUNGE */
	imapd_exists = -1;
    }
    index_ino = mailbox->index_ino;
#else
    fstat(fileno(mailbox->index), &sbuf);
    mailbox->index_size = sbuf.st_size;
#endif

    start_offset = mailbox->start_offset;
    record_size = mailbox->record_size;

    if (mailbox->index_size > index_len) {
	if (index_len) munmap(index_base, index_len);
	index_len =  mailbox->index_size + (SLOP*record_size);
	index_base = (char *)mmap((caddr_t)0, index_len, PROT_READ,
				  MAP_SHARED, fileno(mailbox->index), 0L);
    
	if (index_base == (char *)-1) {
	    index_len = 0;
	    return IMAP_IOERROR;
	}
    }

    if (fstat(fileno(mailbox->cache), &sbuf) == -1) {
	return IMAP_IOERROR;
    }

    if (cache_len <= sbuf.st_size) {
	if (cache_len) munmap(cache_base, cache_len);
	cache_len = sbuf.st_size + CACHESLOP;
	cache_base = (char *)mmap((caddr_t)0, cache_len, PROT_READ,
				  MAP_SHARED, fileno(mailbox->cache), 0L);

	if (cache_base == (char *)-1) {
	    cache_len = 0;
	    return IMAP_IOERROR;
	}
    }

    newexists = (mailbox->index_size - start_offset) / record_size;

    if (imapd_exists == -1) {
	imapd_exists = newexists;
	lastnotrecent = index_finduid(recentuid);
	if (lastnotrecent && UID(lastnotrecent) == recentuid) lastnotrecent--;
	imapd_exists = -1;
    }
    
    /* XXX check Flags */

    if (newexists != imapd_exists) {
	if (newexists > flagalloced) {
	    flagalloced = newexists + SLOP;
	    flagreport = (time_t *)
	      xrealloc((char *)flagreport, (flagalloced+1) * sizeof(time_t));
	    seenflag = xrealloc(seenflag, flagalloced+1);
	    
	    for (i = imapd_exists+1; i <= newexists; i++) {
		flagreport[i] = 0;
		seenflag[i] = 0;
	    }
	}
	imapd_exists = newexists;
	printf("* %d EXISTS\r\n* %d RECENT\r\n", imapd_exists, imapd_exists-lastnotrecent);
    }

    return 0;
}

static int
index_fetchreply(mailbox, msgno, rock)
struct mailbox *mailbox;
int msgno;
char *rock;
{
    struct fetchargs *fetchargs = (struct fetchargs *)rock;    
    int fetchitems = fetchargs->fetchitems;
    FILE *msgfile = 0;
    int sepchar = '(';
    char *cacheitem;

    /* Open the message file if we're going to need it */
    if ((fetchitems & (FETCH_HEADER|FETCH_TEXT|FETCH_RFC822)) ||
	fetchargs->bodyparts || fetchargs->headers || fetchargs->headers_not) {
	msgfile = fopen(message_fname(mailbox, UID(msgno)), "r");
	if (!msgfile) return IMAP_MESSAGE_NONEXISTENT;
    }

    /* Implied setting \Seen flag */
    if ((fetchitems & (FETCH_TEXT|FETCH_RFC822)) || fetchargs->bodyparts) {
	if (!seenflag[msgno]) {
	    seenflag[msgno] = 1;
	    fetchitems |= FETCH_FLAGS;
	}
    }

    printf("* %d FETCH ", msgno);

    if (fetchitems & FETCH_UID) {
	printf("%cUID %d", sepchar, UID(msgno));
	sepchar = ' ';
    }
    if (fetchitems & FETCH_INTERNALDATE) {
	time_t msgdate = INTERNALDATE(msgno);
	struct tm *tm = localtime(&msgdate);
	long gmtoff = tm->tm_gmtoff;
	static char *monthname[] = {
	    "Jan", "Feb", "Mar", "Apr", "May", "Jun",
	    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

	if (gmtoff < 0) gmtoff = -gmtoff;
	gmtoff /= 60;
	printf("%cINTERNALDATE \"%.2d-%s-%d %0.2d:%0.2d:%0.2d %c%0.2d%0.2d\"",
	       sepchar, tm->tm_mday, monthname[tm->tm_mon], tm->tm_year+1900,
	       tm->tm_hour, tm->tm_min, tm->tm_sec,
	       tm->tm_gmtoff < 0 ? '-' : '+', gmtoff/60, gmtoff%60);
	sepchar = ' ';
    }
    if (fetchitems & FETCH_SIZE) {
	printf("%cRFC822.SIZE %d", sepchar, SIZE(msgno));
	sepchar = ' ';
    }
    if (fetchitems & FETCH_FLAGS) {
	int flagsepchar = '(';
	int flag;
	bit32 flagmask;

	printf("%cFLAGS ", sepchar);
	sepchar = ' ';

	if (msgno > lastnotrecent) {
	    printf("%c\\Recent", flagsepchar);
	    flagsepchar = ' ';
	}
	flagmask = SYSTEM_FLAGS(msgno);
	if (flagmask & FLAG_ANSWERED) {
	    printf("%c\\Answered", flagsepchar);
	    flagsepchar = ' ';
	}
	if (flagmask & FLAG_FLAGGED) {
	    printf("%c\\Flagged", flagsepchar);
	    flagsepchar = ' ';
	}
	if (flagmask & FLAG_DELETED) {
	    printf("%c\\Deleted", flagsepchar);
	    flagsepchar = ' ';
	}
	if (seenflag[msgno]) {
	    printf("%c\\Seen", flagsepchar);
	    flagsepchar = ' ';
	}
	for (flag = 0; flag < MAX_USER_FLAGS; flag++) {
	    if ((flag & 31) == 0) {
		flagmask = USER_FLAGS(msgno,flag/32);
	    }
	    if (mailbox->flagname[flag] && (flagmask & (1<<(flag & 31)))) {
		printf("%c%s", mailbox->flagname[flag]);
		flagsepchar = ' ';
	    }
	}
	if (flagsepchar == '(') putc('(', stdout);
	putc(')', stdout);
	flagreport[msgno] = LAST_UPDATED(msgno);
    }
    if (fetchitems & FETCH_ENVELOPE) {
	printf("%cENVELOPE ", sepchar);
	sepchar = ' ';
	cacheitem = cache_base + CACHE_OFFSET(msgno);
	fwrite(cacheitem+4, 1, CACHE_ITEM_LEN(cacheitem), stdout);
    }
    if (fetchitems & FETCH_BODYSTRUCTURE) {
	printf("%cBODYSTRUCTURE ", sepchar);
	sepchar = ' ';
	cacheitem = cache_base + CACHE_OFFSET(msgno);
	cacheitem = CACHE_ITEM_NEXT(cacheitem); /* skip envelope */
	fwrite(cacheitem+4, 1, CACHE_ITEM_LEN(cacheitem), stdout);
    }
    if (fetchitems & FETCH_BODY) {
	printf("%cBODY ", sepchar);
	sepchar = ' ';
	cacheitem = cache_base + CACHE_OFFSET(msgno);
	cacheitem = CACHE_ITEM_NEXT(cacheitem); /* skip envelope */
	cacheitem = CACHE_ITEM_NEXT(cacheitem); /* skip bodystructure */
	fwrite(cacheitem+4, 1, CACHE_ITEM_LEN(cacheitem), stdout);
    }

    if (fetchitems & FETCH_HEADER) {
	printf("%cRFC822.HEADER ", sepchar);
	sepchar = ' ';
	index_fetchmsg(msgfile, mailbox->format, 0, HEADER_SIZE(msgno),
		       fetchargs->start_octet, fetchargs->octet_count);
    }
    else if (fetchargs->headers_not) {
	/* XXX todo */
    }
    else if (fetchargs->headers) {
	/* XXX todo */
    }

    if (fetchitems & FETCH_TEXT) {
	printf("%cRFC822.TEXT ", sepchar);
	sepchar = ' ';
	index_fetchmsg(msgfile, mailbox->format, CONTENT_OFFSET(msgno),
		       SIZE(msgno) - HEADER_SIZE(msgno),
		       fetchargs->start_octet, fetchargs->octet_count);
    }
    if (fetchitems & FETCH_RFC822) {
	printf("%cRFC822 ", sepchar);
	sepchar = ' ';
	index_fetchmsg(msgfile, mailbox->format, 0, SIZE(msgno),
		       fetchargs->start_octet, fetchargs->octet_count);
    }
    /* XXX body[x] */
    printf(")\r\n");
    if (msgfile) fclose(msgfile);
    return 0;
}

int
index_fetch(mailbox, sequence, usinguid, fetchargs)
struct mailbox *mailbox;
char *sequence;
int usinguid;
struct fetchargs *fetchargs;
{
    return index_forsequence(mailbox, sequence, usinguid,
			     index_fetchreply, (char *)fetchargs);
}

static int
index_forsequence(mailbox, sequence, usinguid, proc, rock)
struct mailbox *mailbox;
char *sequence;
int usinguid;
int (*proc)();
char *rock;
{
    int i, start = 0, end;
    int r, result = 0;

    for (;;) {
	if (isdigit(*sequence)) {
	    start = start*10 + *sequence - '0';
	}
	else if (*sequence == ':') {
	    end = 0;
	    sequence++;
	    while (isdigit(*sequence)) {
		end = end*10 + *sequence++ - '0';
	    }
	    if (start > end) {
		i = end;
		end = start;
		start = i;
	    }
	    if (usinguid) {
		i = index_finduid(start);
		if (!i || start != UID(i)) i++;
		start = i;
		end = index_finduid(end);
	    }
	    if (start < 1) start = 1;
	    if (end > imapd_exists) end = imapd_exists;
	    for (i = start; i <= end; i++) {
		r = (*proc)(mailbox, i, rock);
		if (r && !result) result = r;
	    }
	    start = 0;
	    if (!*sequence) return result;
	}
	else {
	    if (start && usinguid) {
		i = index_finduid(start);
		if (!i || start != UID(i)) i = 0;
		start = i;
	    }
	    if (start > 0 && start <= imapd_exists) {
		r = (*proc)(mailbox, start, rock);
		if (r && !result) result = r;
	    }
	    if (!*sequence) return result;
	}
	sequence++;
    }
}

int
index_finduid(uid)
int uid;
{
    int low=1, high=imapd_exists;
    int mid, miduid;

    while (low <= high) {
	mid = (high - low)/2 + low;
	miduid = UID(mid);
	if (miduid == uid) {
	    return mid;
	}
	else if (miduid > uid) {
	    high = mid - 1;
	}
	else {
	    low = mid + 1;
	}
    }
    return high;
}

index_fetchmsg(msgfile, format, offset, size, start_octet, octet_count)
FILE *msgfile;
int format;
int offset;
int size;
int start_octet;
int octet_count;
{
    char buf[4096], *p;
    int n;

    if (start_octet) {
	if (size < start_octet) {
	    size = 0;
	}
	else {
	    size -= start_octet - 1;
	}
	if (size > octet_count) size = octet_count;
	start_octet--;
    }

    if (size == 0) {
	printf("\"\"");
	return;
    }
    printf("{%d}\r\n", size);

    if (format == MAILBOX_FORMAT_NETNEWS) {
	fseek(msgfile, offset, 0);
	while (size) {
	    if (!fgets(buf, sizeof(buf)-1, msgfile)) {
		while (size--) putc(' ', stdout);
		return;
	    }
	    p = buf + strlen(buf);
	    if (p[-1] == '\n') {
		p[-1] = '\r';
		*p++ = '\n';
		*p = '\0';
	    }
	    n = p - buf;
	    if (start_octet >= n) {
		start_octet -= n;
	    }
	    else {
		n -= start_octet;
		fwrite(buf + start_octet, 1, n, stdout);
		start_octet = 0;
		size -= n;
	    }
	}
    }
    else {
	offset += start_octet;
	fseek(msgfile, offset, 0);
	while (size) {
	    n = fread(buf, 1, size>sizeof(buf) ? sizeof(buf) : size, msgfile);
	    if (n == 0) {
		while (size--) putc(' ', stdout);
		return;
	    }
	    fwrite(buf, 1, n, stdout);
	    size -= n;
	}
    }
}

	    

    

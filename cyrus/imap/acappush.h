

#ifndef ACAPPUSH_H
#define ACAPPUSH_H

/* for bit32 definitions */
#include "mailbox.h"


/* file to redevue (sp) at */
#define ACAPPUSH_PATH "/tmp/.acappush"

typedef struct acapmbdata_s {
    unsigned long uidvalidity;
    unsigned long exists;
    unsigned long deleted;
    unsigned long flagged;
    unsigned long answered;

    /* 1 for null. leave at end of structure for alignment */
    char name[MAX_MAILBOX_NAME+1];

} acapmbdata_t;



#endif /* ACAP_LISTEN_H */

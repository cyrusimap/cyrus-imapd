#ifndef ACAPPUSH_H_
#define ACAPPUSH_H_

/* for bit32 definitions */
#include "mailbox.h"

/* socket to communicate with the acappusher */
#define FNAME_ACAPPUSH_SOCK "/socket/acappush"

typedef struct acapmbdata_s {
    unsigned long uidvalidity;
    unsigned long exists;
    unsigned long deleted;
    unsigned long flagged;
    unsigned long answered;

    /* 1 for null. leave at end of structure for alignment */
    char name[MAX_MAILBOX_NAME+1];
} acapmbdata_t;

#endif /* ACAPPUSH_H_ */

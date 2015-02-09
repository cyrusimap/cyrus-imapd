#ifndef VCARDFAST_H
#define VCARDFAST_H

#include <stdlib.h>
#include "util.h"

enum parse_error {
PE_OK = 0,
PE_BACKQUOTE_EOF,
PE_BEGIN_PARAMS,
PE_ENTRY_MULTIGROUP,
PE_FINISHED_EARLY,
PE_KEY_EOF,
PE_KEY_EOL,
PE_MISMATCHED_CARD,
PE_NAME_EOF,
PE_NAME_EOL,
PE_PARAMVALUE_EOF,
PE_PARAMVALUE_EOL,
PE_QSTRING_EOF,
PE_QSTRING_EOL,
PE_QSTRING_COMMA,
PE_NUMERR /* last */
};

struct vparse_list {
    char *s;
    struct vparse_list *next;
};

struct vparse_state {
    struct buf buf;
    const char *base;
    const char *itemstart;
    const char *p;
    struct vparse_list *multival;
    struct vparse_list *multiparam;
    int barekeys;

    /* current items */
    struct vparse_card *card;
    struct vparse_param *param;
    struct vparse_entry *entry;
    struct vparse_list *value;
};

struct vparse_param {
    char *name;
    char *value;
    struct vparse_param *next;
};

struct vparse_entry {
    char *group;
    char *name;
    int multivalue;
    union {
	char *value;
	struct vparse_list *values;
    } v;
    struct vparse_param *params;
    struct vparse_entry *next;
};

struct vparse_card {
    char *type;
    struct vparse_entry *properties;
    struct vparse_card *objects;
    struct vparse_card *next;
};

struct vparse_errorpos {
    int startpos;
    int startline;
    int startchar;
    int errorpos;
    int errorline;
    int errorchar;
};

extern int vparse_parse(struct vparse_state *state, int only_one);
extern void vparse_free(struct vparse_state *state);
extern void vparse_fillpos(struct vparse_state *state, struct vparse_errorpos *pos);
extern const char *vparse_errstr(int err);

extern void vparse_set_multival(struct vparse_state *state, const char *name);

extern const char *vparse_stringval(const struct vparse_card *card, const char *name);
extern const struct vparse_list *vparse_multival(const struct vparse_card *card, const char *name);

#endif /* VCARDFAST_H */


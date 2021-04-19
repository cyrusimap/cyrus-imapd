#ifndef VCARDFAST_H
#define VCARDFAST_H

#include <stdlib.h>
#include "util.h"
#include "strarray.h"

#define APPLE_LABEL_PROPERTY "X-ABLabel"

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
PE_ILLEGAL_CHAR,
PE_NUMERR /* last */
};

struct vparse_state {
    struct buf buf;
    const char *base;
    const char *itemstart;
    const char *p;
    strarray_t *multivalsemi;
    strarray_t *multivalcomma;
    strarray_t *multiparam;
    int barekeys;

    /* current items */
    struct vparse_card *card;
    struct vparse_param *param;
    struct vparse_entry *entry;
};

struct vparse_param {
    char *name;
    char *value;
    struct vparse_param *next;
};

struct vparse_entry {
    char *group;
    char *name;
    char multivaluesep;
    union {
        char *value;
        strarray_t *values;
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

extern void vparse_set_multival(struct vparse_state *state, const char *name, char split);
extern void vparse_set_multiparam(struct vparse_state *state, const char *name);

extern const char *vparse_stringval(const struct vparse_card *card, const char *name);
extern const strarray_t *vparse_multival(const struct vparse_card *card, const char *name);

/* editing functions */
extern struct vparse_card *vparse_new_card(const char *type);
extern void vparse_free_card(struct vparse_card *card);
extern void vparse_free_entry(struct vparse_entry *entry);
extern void vparse_delete_entries(struct vparse_card *card, const char *group, const char *name);
extern void vparse_delete_entries_and_apple_labels(struct vparse_card *card, const char *name);
extern struct vparse_entry *vparse_get_entry(struct vparse_card *card, const char *group, const char *name);
extern struct vparse_entry *vparse_add_entry(struct vparse_card *card, const char *group, const char *name, const char *value);
extern void vparse_replace_entry(struct vparse_card *card, const char *group, const char *name, const char *value);
extern void vparse_set_value(struct vparse_entry *entry, const char *value);
/* XXX - multivalue should be strarray_t */
//extern void vparse_set_multivalue(struct vparse_entry *entry, const strarray_t *values);

extern void vparse_delete_params(struct vparse_entry *entry, const char *name);
extern struct vparse_param *vparse_get_param(struct vparse_entry *entry, const char *name);
extern struct vparse_param *vparse_add_param(struct vparse_entry *entry, const char *name, const char *value);

extern void vparse_tobuf(const struct vparse_card *card, struct buf *buf);
extern int vparse_restriction_check(struct vparse_card *card);

#endif /* VCARDFAST_H */


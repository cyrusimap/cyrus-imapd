/* vparse.c : fast vcard parser */

#include <ctype.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>

#include "vparse.h"
#include "xmalloc.h"

#define DEBUG 0

static char *buf_dup_cstring(struct buf *buf)
{
    char *ret = xstrndup(buf->s, buf->len);
    /* more space efficient than returning overlength buffers, and
     * you would just wind up mallocing another buffer anyway */
    buf->len = 0;
    return ret;
}

#define NOTESTART() state->itemstart = state->p
#define MAKE(X, Y) X = xzmalloc(sizeof(struct Y));
#define PUTC(C) buf_putc(&state->buf, C)
#define INC(I) state->p += I
#define IS_CTRL(ch) \
    (ch > 0 && ch <= 0x1f && ch != '\r' && ch != '\n' && ch != '\t')
#define HANDLECTRL(state) \
{ \
    if (IS_CTRL(*state->p)) { \
        while (IS_CTRL(*state->p)) \
            state->p++; \
    } \
    if ((*state->p) == 0) \
        break; \
}

/* just leaves it on the buffer */
static int _parse_param_quoted(struct vparse_state *state, int multiparam)
{
    NOTESTART();

    while (*state->p) {

        /* Handle control characters and break for NUL char */
        HANDLECTRL(state);

        switch (*state->p) {
        case '"':
            INC(1);
            return 0;

        /* normal backslash quoting - NOTE, not strictly RFC compliant,
         * but I figure anyone who generates one PROBABLY meant to escape
         * the next character because it's so common, and LABEL definitely
         * allows \n, so we have to handle that anyway */
        case '\\':
            /* seen in the wild - \n split by line wrapping */
            if (state->p[1] == '\r') INC(1);
            if (state->p[1] == '\n') {
                if (state->p[2] != ' ' && state->p[2] != '\t')
                    return PE_QSTRING_EOL;
                INC(2);
            }
            if (!state->p[1])
                return PE_BACKQUOTE_EOF;
            if (state->p[1] == 'n' || state->p[1] == 'N')
                PUTC('\n');
            else
                PUTC(state->p[1]);
            INC(2);
            break;

        /* special value quoting for doublequote and endline (RFC 6868) */
        case '^':
            if (state->p[1] == '\r') INC(1);
            if (state->p[1] == '\n') {
                if (state->p[2] != ' ' && state->p[2] != '\t')
                    return PE_QSTRING_EOL;
                INC(2);
            }
            if (state->p[1] == '\'') {
                PUTC('"');
                INC(2);
            }
            else if (state->p[1] == 'n') { /* only lower case per the RFC */
                PUTC('\n');
                INC(2);
            }
            else if (state->p[1] == '^') {
                PUTC('^');
                INC(2);
            }
            else {
                PUTC('^');
                INC(1); /* treat next char normally */
            }
            break;

        case '\r':
            INC(1);
            break; /* just skip */
        case '\n':
            if (state->p[1] != ' ' && state->p[1] != '\t')
                return PE_QSTRING_EOL;
            INC(2);
            break;

        case ',':
            if (multiparam)
                return PE_QSTRING_COMMA;
            /* or fall through, comma isn't special */
            GCC_FALLTHROUGH

        default:
            PUTC(*state->p);
            INC(1);
            break;
        }
    }

    return PE_QSTRING_EOF;
}

static int _parse_param_key(struct vparse_state *state, int *haseq)
{
    *haseq = 0;

    while (*state->p) {

        /* Handle control characters and break for NUL char */
        HANDLECTRL(state);

        switch (*state->p) {
        case '=':
            state->param->name = buf_dup_cstring(&state->buf);
            *haseq = 1;
            INC(1);
            return 0;

        case ';': /* vcard 2.1 parameter with no value */
        case ':':
            if (state->barekeys) {
                state->param->name = buf_dup_cstring(&state->buf);
            }
            else {
                state->param->name = strdup("type");
                state->param->value = buf_dup_cstring(&state->buf);
            }
            /* no INC - we need to see this char up a layer */
            return 0;

        case '\r':
            INC(1);
            break; /* just skip */
        case '\n':
            if (state->p[1] != ' ' && state->p[1] != '\t')
                return PE_KEY_EOL;
            INC(2);
            break;

        /* XXX - check exact legal set? */
        default:
            PUTC(*state->p);
            INC(1);
            break;
        }
    }

    return PE_KEY_EOF;
}

static int _parse_entry_params(struct vparse_state *state)
{
    struct vparse_param **paramp = &state->entry->params;
    int multiparam = 0;
    int haseq = 0;
    int r;

repeat:
    multiparam = 0;
    haseq = 0;
    MAKE(state->param, vparse_param);

    NOTESTART();

    r = _parse_param_key(state, &haseq);
    if (r) return r;

    if (state->multiparam && strarray_find_case(state->multiparam, state->param->name, 0) >= 0)
        multiparam = 1;

    /* now get the value */
    while (*state->p) {

        /* Handle control characters and break for NUL char */
        HANDLECTRL(state);

        switch (*state->p) {
        case '\\': /* normal backslash quoting */
            /* seen in the wild - \n split by line wrapping */
            if (state->p[1] == '\r') INC(1);
            if (state->p[1] == '\n') {
                if (state->p[2] != ' ' && state->p[2] != '\t')
                    return PE_PARAMVALUE_EOL;
                INC(2);
            }
            if (!state->p[1])
                return PE_BACKQUOTE_EOF;
            if (state->p[1] == 'n' || state->p[1] == 'N')
                PUTC('\n');
            else
                PUTC(state->p[1]);
            INC(2);
            break;

        case '^': /* special value quoting for doublequote (RFC 6868) */
            /* seen in the wild - \n split by line wrapping */
            if (state->p[1] == '\r') INC(1);
            if (state->p[1] == '\n') {
                if (state->p[2] != ' ' && state->p[2] != '\t')
                    return PE_PARAMVALUE_EOL;
                INC(2);
            }
            if (state->p[1] == '\'') {
                PUTC('"');
                INC(2);
            }
            else if (state->p[1] == 'n') {
                PUTC('\n');
                INC(2);
            }
            else if (state->p[1] == '^') {
                PUTC('^');
                INC(2);
            }
            else {
                PUTC('^');
                INC(1); /* treat next char normally */
            }
            break;

        case '"':
            INC(1);
            loop:
            r = _parse_param_quoted(state, multiparam);
            if (r == PE_QSTRING_COMMA) {
                char *name = strdup(state->param->name);
                state->param->value = buf_dup_cstring(&state->buf);
                *paramp = state->param;
                paramp = &state->param->next;
                MAKE(state->param, vparse_param);
                state->param->name = name;
                INC(1);
                goto loop;
            }
            if (r) return r;
            break;

        case ':':
            /* done - all parameters parsed */
            if (haseq)
                state->param->value = buf_dup_cstring(&state->buf);
            *paramp = state->param;
            state->param = NULL;
            INC(1);
            return 0;

        case ';':
            /* another parameter to parse */
            if (haseq)
                state->param->value = buf_dup_cstring(&state->buf);
            *paramp = state->param;
            paramp = &state->param->next;
            INC(1);
            goto repeat;

        case '\r':
            INC(1);
            break; /* just skip */
        case '\n':
            if (state->p[1] != ' ' && state->p[1] != '\t')
                return PE_PARAMVALUE_EOL;
            INC(2);
            break;

        case ',':
            if (multiparam) {
                char *name = strdup(state->param->name);
                if (haseq)
                    state->param->value = buf_dup_cstring(&state->buf);
                *paramp = state->param;
                paramp = &state->param->next;
                MAKE(state->param, vparse_param);
                state->param->name = name;
                INC(1);
                break;
            }
            /* or fall through, comma isn't special */
            GCC_FALLTHROUGH

        default:
            PUTC(*state->p);
            INC(1);
            break;
        }
    }

    return PE_PARAMVALUE_EOF;
}

static int _parse_entry_key(struct vparse_state *state)
{
    NOTESTART();

    while (*state->p) {

        /* Handle control characters and break for NUL char */
        HANDLECTRL(state);

        switch (*state->p) {
        case ':':
            state->entry->name = buf_dup_cstring(&state->buf);
            INC(1);
            return 0;

        case ';':
            state->entry->name = buf_dup_cstring(&state->buf);
            INC(1);
            return _parse_entry_params(state);

        case '.':
            if (state->entry->group)
                return PE_ENTRY_MULTIGROUP;
            state->entry->group = buf_dup_cstring(&state->buf);
            INC(1);
            break;

        case '\r':
            INC(1);
            break; /* just skip */
        case '\n':
            if (state->p[1] == ' ' || state->p[1] == '\t') /* wrapped line */
                INC(2);
            else if (!state->buf.len) /* no key yet?  blank intermediate lines are OK */
                INC(1);
            else
                return PE_NAME_EOL;
            break;

        default:
            PUTC(*state->p);
            INC(1);
            break;
        }
    }

    return PE_NAME_EOF;
}

static int _parse_entry_multivalue(struct vparse_state *state, char splitchar)
{
    state->entry->multivaluesep = splitchar;
    state->entry->v.values = strarray_new();

    NOTESTART();

    while (*state->p) {

        /* Handle control characters and break for NUL char */
        HANDLECTRL(state);

        switch (*state->p) {
        /* only one type of quoting */
        case '\\':
            /* seen in the wild - \n split by line wrapping */
            if (state->p[1] == '\r') INC(1);
            if (state->p[1] == '\n') {
                if (state->p[2] != ' ' && state->p[2] != '\t')
                    return PE_BACKQUOTE_EOF;
                INC(2);
            }
            if (!state->p[1])
                return PE_BACKQUOTE_EOF;
            if (state->p[1] == 'n' || state->p[1] == 'N')
                PUTC('\n');
            else
                PUTC(state->p[1]);
            INC(2);
            break;

        case '\r':
            INC(1);
            break; /* just skip */
        case '\n':
            if (state->p[1] == ' ' || state->p[1] == '\t') {/* wrapped line */
                INC(2);
                break;
            }
            /* otherwise it's the end of the value */
            INC(1);
            goto out;

        default:
            if (*state->p == splitchar) {
                strarray_appendm(state->entry->v.values, buf_dup_cstring(&state->buf));
            }
            else {
                PUTC(*state->p);
            }
            INC(1);
            break;
        }
    }

out:
    /* reaching the end of the file isn't a failure here,
     * it's just another type of end-of-value */
    strarray_appendm(state->entry->v.values, buf_dup_cstring(&state->buf));
    return 0;
}

static int _parse_entry_value(struct vparse_state *state)
{
    if (state->multivalsemi && strarray_find_case(state->multivalsemi, state->entry->name, 0) >= 0)
        return _parse_entry_multivalue(state, ';');
    if (state->multivalcomma && strarray_find_case(state->multivalcomma, state->entry->name, 0) >= 0)
        return _parse_entry_multivalue(state, ',');

    NOTESTART();

    while (*state->p) {

        /* Handle control characters and break for NUL char */
        HANDLECTRL(state);

        switch (*state->p) {
        /* only one type of quoting */
        case '\\':
            /* seen in the wild - \n split by line wrapping */
            if (state->p[1] == '\r') INC(1);
            if (state->p[1] == '\n') {
                if (state->p[2] != ' ' && state->p[2] != '\t')
                    return PE_BACKQUOTE_EOF;
                INC(2);
            }
            if (!state->p[1])
                return PE_BACKQUOTE_EOF;

            if (state->p[1] == 'n' || state->p[1] == 'N')
                PUTC('\n');
            else
                PUTC(state->p[1]);
            INC(2);
            break;

        case '\r':
            INC(1);
            break; /* just skip */
        case '\n':
            if (state->p[1] == ' ' || state->p[1] == '\t') {/* wrapped line */
                INC(2);
                break;
            }
            /* otherwise it's the end of the value */
            INC(1);
            goto out;

        default:
            PUTC(*state->p);
            INC(1);
            break;
        }
    }

out:
    /* reaching the end of the file isn't a failure here,
     * it's just another type of end-of-value */
    state->entry->v.value = buf_dup_cstring(&state->buf);
    return 0;
}

/* FREE MEMORY */

static void _free_param(struct vparse_param *param)
{
    struct vparse_param *paramnext;

    for (; param; param = paramnext) {
        paramnext = param->next;
        free(param->name);
        free(param->value);
        free(param);
    }
}

static void _free_entry(struct vparse_entry *entry)
{
    struct vparse_entry *entrynext;

    for (; entry; entry = entrynext) {
        entrynext = entry->next;
        free(entry->name);
        free(entry->group);
        if (entry->multivaluesep)
            strarray_free(entry->v.values);
        else
            free(entry->v.value);
        _free_param(entry->params);
        free(entry);
    }
}

static void _free_card(struct vparse_card *card)
{
    struct vparse_card *cardnext;

    for (; card; card = cardnext) {
        cardnext = card->next;
        free(card->type);
        _free_entry(card->properties);
        _free_card(card->objects);
        free(card);
    }
}

static void _free_state(struct vparse_state *state)
{
    buf_free(&state->buf);
    _free_card(state->card);
    _free_entry(state->entry);
    _free_param(state->param);
    if (state->multivalsemi) strarray_free(state->multivalsemi);
    if (state->multivalcomma) strarray_free(state->multivalcomma);
    if (state->multiparam) strarray_free(state->multiparam);

    memset(state, 0, sizeof(struct vparse_state));
}

static int _parse_entry(struct vparse_state *state)
{
    int r = _parse_entry_key(state);
    if (r) return r;
    return _parse_entry_value(state);
}

static int _parse_vcard(struct vparse_state *state, struct vparse_card *card, int only_one)
{
    struct vparse_card **subp = &card->objects;
    struct vparse_entry **entryp = &card->properties;
    struct vparse_card *sub;
    const char *cardstart = state->p;
    const char *entrystart;
    int r;

    while (*state->p) {
        /* whitespace is very skippable before AND afterwards */
        if (*state->p == '\r' || *state->p == '\n' || *state->p == ' ' || *state->p == '\t') {
            INC(1);
            continue;
        }

        entrystart = state->p;

        MAKE(state->entry, vparse_entry);

        r = _parse_entry(state);
        if (r) return r;

        if (!strcasecmp(state->entry->name, "begin")) {
            struct vparse_entry *version;

            /* shouldn't be any params */
            if (state->entry->params) {
                state->itemstart = entrystart;
                return PE_BEGIN_PARAMS;
            }
            /* only possible if some idiot passes 'begin' as
             * multivalue field name */
            if (state->entry->multivaluesep) {
                state->itemstart = entrystart;
                return PE_BEGIN_PARAMS;
            }

            MAKE(sub, vparse_card);
            sub->type = strdup(state->entry->v.value);
            _free_entry(state->entry);
            state->entry = NULL;
            /* we must stitch it in first, because state won't hold it */
            *subp = sub;
            subp = &sub->next;
            r = _parse_vcard(state, sub, /*only_one*/0);

            /* repair critical property values */
            version = vparse_get_entry(sub, NULL, "version");
            if (version) {
                const char *val;
                for (val = version->v.value; *val; val++) {
                    if (isspace(*val)) {
                        /* rewrite property value */
                        struct buf buf = BUF_INITIALIZER;
                        buf_setcstr(&buf, version->v.value);
                        buf_trim(&buf);
                        free(version->v.value);
                        version->v.value = buf_release(&buf);
                        break;
                    }
                }
            }

            if (r) return r;


            if (only_one) return 0;
        }
        else if (!strcasecmp(state->entry->name, "end")) {
            /* shouldn't be any params */
            if (state->entry->params) {
                state->itemstart = entrystart;
                return PE_BEGIN_PARAMS;
            }
            /* only possible if some idiot passes 'end' as
             * multivalue field name */
            if (state->entry->multivaluesep) {
                state->itemstart = entrystart;
                return PE_BEGIN_PARAMS;
            }

            if (!card->type) {
                /* no type means we're at the top level, haven't seen a BEGIN! */
                state->itemstart = cardstart;
                return PE_MISMATCHED_CARD;
            }

            if (strcasecmp(state->entry->v.value, card->type)) {
                /* special case mismatched card, the "start" was the start of
                 * the card */
                state->itemstart = cardstart;
                return PE_MISMATCHED_CARD;
            }

            _free_entry(state->entry);
            state->entry = NULL;

            return 0;
        }
        else {
            /* it's a parameter on this one */
            *entryp = state->entry;
            entryp = &state->entry->next;
            state->entry = NULL;
        }
    }

    if (card->type)
        return PE_FINISHED_EARLY;

    return 0;
}

/* PUBLIC API */

EXPORTED int vparse_parse(struct vparse_state *state, int only_one)
{
    MAKE(state->card, vparse_card);

    state->p = state->base;

    /* don't parse trailing non-whitespace */
    return _parse_vcard(state, state->card, only_one);
}

EXPORTED void vparse_free(struct vparse_state *state)
{
    _free_state(state);
}

EXPORTED void vparse_free_card(struct vparse_card *card)
{
    _free_card(card);
}

EXPORTED void vparse_free_entry(struct vparse_entry *entry)
{
    _free_entry(entry);
}

EXPORTED void vparse_fillpos(struct vparse_state *state, struct vparse_errorpos *pos)
{
    int l = 1;
    int c = 0;
    const char *p;

    memset(pos, 0, sizeof(struct vparse_errorpos));

    pos->errorpos = state->p - state->base;
    pos->startpos = state->itemstart - state->base;

    for (p = state->base; p < state->p; p++) {
        if (*p == '\n') {
            l++;
            c = 0;
        }
        else {
            c++;
        }
        if (p == state->itemstart) {
            pos->startline = l;
            pos->startchar = c;
        }
    }

    pos->errorline = l;
    pos->errorchar = c;
}

EXPORTED const char *vparse_errstr(int err)
{
    switch(err) {
    case PE_BACKQUOTE_EOF:
        return "EOF after backslash";
    case PE_BEGIN_PARAMS:
        return "Params on BEGIN field";
    case PE_ENTRY_MULTIGROUP:
        return "Multiple group levels in property name";
    case PE_FINISHED_EARLY:
        return "VCard not completed";
    case PE_KEY_EOF:
        return "End of data while parsing parameter key";
    case PE_KEY_EOL:
        return "End of line while parsing parameter key";
    case PE_MISMATCHED_CARD:
        return "Closed a different card name than opened";
    case PE_NAME_EOF:
        return "End of data while parsing entry name";
    case PE_NAME_EOL:
        return "End of line while parsing entry name";
    case PE_PARAMVALUE_EOF:
        return "End of data while parsing parameter value";
    case PE_PARAMVALUE_EOL:
        return "End of line while parsing parameter value";
    case PE_QSTRING_EOF:
        return "End of data while parsing quoted value";
    case PE_QSTRING_EOL:
        return "End of line while parsing quoted value";
    case PE_ILLEGAL_CHAR:
        return "Illegal character in VCard";
    }
    return "Unknown error";
}

EXPORTED const char *vparse_stringval(const struct vparse_card *card, const char *name)
{
    struct vparse_entry *entry;
    for (entry = card->properties; entry; entry = entry->next) {
        if (!strcasecmp(name, entry->name)) {
            if (entry->multivaluesep)
                return strarray_nth(entry->v.values, 0);
            else
                return entry->v.value;
        }
    }
    return NULL;
}

EXPORTED const strarray_t *vparse_multival(const struct vparse_card *card, const char *name)
{
    struct vparse_entry *entry;
    for (entry = card->properties; entry; entry = entry->next) {
        if (!entry->multivaluesep) continue;
        if (!strcasecmp(name, entry->name))
            return entry->v.values;
    }
    return NULL;
}

EXPORTED void vparse_set_multival(struct vparse_state *state, const char *name, char split)
{
    switch (split) {
    case ';':
        if (!state->multivalsemi) state->multivalsemi = strarray_new();
        strarray_append(state->multivalsemi, name);
        break;
    case ',':
        if (!state->multivalcomma) state->multivalcomma = strarray_new();
        strarray_append(state->multivalcomma, name);
        break;

    default:
        abort();
    }
}

EXPORTED void vparse_set_multiparam(struct vparse_state *state, const char *name)
{
    if (!state->multiparam) state->multiparam = strarray_new();
    strarray_append(state->multiparam, name);
}

struct vparse_target {
    struct buf *buf;
    size_t last;
};

static void _endline(struct vparse_target *tgt)
{
    buf_appendcstr(tgt->buf, "\r\n");
    tgt->last = buf_len(tgt->buf);
}

static void _checkwrap(unsigned char c, struct vparse_target *tgt)
{
    if (buf_len(tgt->buf) - tgt->last < 75)
        return; /* still short line */

    if (c >= 0x80 && c < 0xC0)
        return; /* never wrap continuation chars */

    /* wrap */
    _endline(tgt);
    buf_putc(tgt->buf, ' ');
}

static void _value_to_tgt(const char *value, struct vparse_target *tgt)
{
    if (!value) return; /* null fields or array items are empty string */
    for (; *value; value++) {
        /* never wrap just a single character by itself.  This is partially
         * a workaround for an OSX 10.10 bug with parsing this:
         * PRODID:+//IDN bitfire.at//DAVdroid/1.2.2-gplay vcard4android ez-vcard/0.9.1
         *  0
         * UID:[...]
         * which is totally valid, but it was barfing and saying there was no UID */
        if (value[1]) _checkwrap(*value, tgt);
        switch (*value) {
        case '\r':
            break;
        case '\n':
            buf_putc(tgt->buf, '\\');
            buf_putc(tgt->buf, 'n');
            break;
        case ';':
        case ',':
        case '\\':
            buf_putc(tgt->buf, '\\');
            /* fall through */
        default:
            buf_putc(tgt->buf, *value);
            break;
        }
    }
}

static void _paramval_to_tgt(const char *value, struct vparse_target *tgt)
{
    int seenchar = 0;
    for (; *value; value++) {
        /* XXX - don't wrap on the very first character of a value,
           because it breaks Mac OS X parser */
        if (seenchar) _checkwrap(*value, tgt);
        else seenchar = 1;
        switch (*value) {
        case '\r':
            break;
        case '\n':
            buf_putc(tgt->buf, '^');
            buf_putc(tgt->buf, 'n');
            break;
        case '^':
            buf_putc(tgt->buf, '^');
            buf_putc(tgt->buf, '^');
            break;
        case '"':
            buf_putc(tgt->buf, '^');
            buf_putc(tgt->buf, '\'');
            break;
        default:
            buf_putc(tgt->buf, *value);
        }
    }
}

static void _key_to_tgt(const char *key, struct vparse_target *tgt)
{
    /* uppercase keys */
    for (; *key; key++) {
        _checkwrap(*key, tgt);
        //buf_putc(tgt->buf, toupper(*key));
        buf_putc(tgt->buf, *key);
    }
}

static int _needsquote(const char *p)
{
    while (*p++) {
        switch (*p) {
        case '"':
        case ',':
        case ':':
        case ';':
        case ' ':  // in theory, whitespace is legal
        case '\t': // in theory, whitespace is legal
            return 1;
        }
    }
    return 0;
}

static void _entry_to_tgt(const struct vparse_entry *entry, struct vparse_target *tgt)
{
    struct vparse_param *param;

    // RFC 6350 3.3 - it is RECOMMENDED that property and parameter names be upper-case on output.
    if (entry->group) {
        _key_to_tgt(entry->group, tgt);
        buf_putc(tgt->buf, '.');
    }
    _key_to_tgt(entry->name, tgt);

    for (param = entry->params; param; param = param->next) {
        buf_putc(tgt->buf, ';');
        _key_to_tgt(param->name, tgt);
        buf_putc(tgt->buf, '=');
        if (_needsquote(param->value)) {
            /* XXX - smart quoting? */
            buf_putc(tgt->buf, '"');
            _paramval_to_tgt(param->value, tgt);
            buf_putc(tgt->buf, '"');
        }
        else {
            _paramval_to_tgt(param->value, tgt);
        }
    }

    buf_putc(tgt->buf, ':');

    if (entry->multivaluesep) {
        int i;
        for (i = 0; i < entry->v.values->count; i++) {
            if (i) buf_putc(tgt->buf, entry->multivaluesep);
            _value_to_tgt(strarray_nth(entry->v.values, i), tgt);
        }
    }
    else {
        _value_to_tgt(entry->v.value, tgt);
    }

    _endline(tgt);
}

static void _card_to_tgt(const struct vparse_card *card, struct vparse_target *tgt)
{
    const struct vparse_entry *entry;
    const struct vparse_card *sub;

    if (card->type) {
        _key_to_tgt("BEGIN", tgt);
        buf_putc(tgt->buf, ':');
        _key_to_tgt(card->type, tgt);
        _endline(tgt);
    }

    for (entry = card->properties; entry; entry = entry->next)
        _entry_to_tgt(entry, tgt);

    for (sub = card->objects; sub; sub = sub->next)
        _card_to_tgt(sub, tgt);

    if (card->type) {
        _key_to_tgt("END", tgt);
        buf_putc(tgt->buf, ':');
        _key_to_tgt(card->type, tgt);
        _endline(tgt);
    }
}

EXPORTED void vparse_tobuf(const struct vparse_card *card, struct buf *buf)
{
    struct vparse_target tgt;
    tgt.buf = buf;
    tgt.last = 0;
    for (; card; card = card->next)
        _card_to_tgt(card, &tgt);
}

EXPORTED struct vparse_card *vparse_new_card(const char *type)
{
    struct vparse_card *card = xzmalloc(sizeof(struct vparse_card));
    card->type = xstrdupnull(type);
    return card;
}

EXPORTED struct vparse_entry *vparse_add_entry(struct vparse_card *card, const char *group, const char *name, const char *value)
{
    struct vparse_entry **entryp = &card->properties;
    struct vparse_entry *entry = xzmalloc(sizeof(struct vparse_entry));

    while (*entryp) entryp = &((*entryp)->next);
    entry->group = xstrdupnull(group);
    entry->name = xstrdupnull(name);
    entry->v.value = xstrdupnull(value);
    *entryp = entry;
    return entry;
}

EXPORTED struct vparse_entry *vparse_get_entry(struct vparse_card *card, const char *group, const char *name)
{
    struct vparse_entry *entry = NULL;

    for (entry = card->properties; entry; entry = entry->next) {
        if (!strcasecmpsafe(entry->group, group) && !strcasecmpsafe(entry->name, name))
            break;
    }

    return entry;
}

EXPORTED void vparse_replace_entry(struct vparse_card *card, const char *group, const char *name, const char *value)
{
    struct vparse_entry *entry = vparse_get_entry(card, group, name);
    if (entry) {
        if (entry->multivaluesep) {
            /* FN isn't allowed to be a multi-value, but let's
             * rather check than deal with corrupt memory */
            strarray_free(entry->v.values);
            entry->v.values = NULL;
        } else {
            free(entry->v.value);
        }
        entry->v.value = xstrdupnull(value);
        entry->multivaluesep = '\0';
    }
    else {
        vparse_add_entry(card, group, name, value);
    }
}

EXPORTED void vparse_delete_entries(struct vparse_card *card, const char *group, const char *name)
{
    struct vparse_entry **entryp = &card->properties;
    while (*entryp) {
        struct vparse_entry *entry = *entryp;
        if ((!group || !strcasecmpsafe(entry->group, group)) && !strcasecmpsafe(entry->name, name)) {
            *entryp = entry->next;
            entry->next = NULL; /* so free doesn't walk the chain */
            _free_entry(entry);
        }
        else {
            entryp = &((*entryp)->next);
        }
    }
}

EXPORTED struct vparse_param *vparse_get_param(struct vparse_entry *entry, const char *name)
{
    struct vparse_param *param;
    for (param = entry->params; param; param = param->next) {
        if (!strcasecmp(param->name, name))
            return param;
    }
    return NULL;
}

EXPORTED struct vparse_param *vparse_add_param(struct vparse_entry *entry, const char *name, const char *value)
{
    struct vparse_param **paramp = &entry->params;
    struct vparse_param *param = xzmalloc(sizeof(struct vparse_param));

    while (*paramp) paramp = &((*paramp)->next);
    param->name = xstrdupnull(name);
    param->value = xstrdupnull(value);
    *paramp = param;
    return param;
}

EXPORTED void vparse_delete_params(struct vparse_entry *entry, const char *name)
{
    struct vparse_param **paramp = &entry->params;
    while (*paramp) {
        struct vparse_param *param = *paramp;
        if (!strcasecmpsafe(param->name, name)) {
            *paramp = param->next;
            param->next = NULL;
            _free_param(param);
        }
        else {
            paramp = &((*paramp)->next);
        }
    }
}

static const struct {
    const char *name;  /* property name */
    struct {
        unsigned min;  /* mandatory minimum number of occurrences */
        unsigned max;  /* allowed maximum number of occurrences */
    } version[3];      /* 1 min/max per vCard version */
} restrictions[] = {
    { "VERSION",     { { 1,  1 }, { 1,  1 }, { 1,  1 } } },
    { "ANNIVERSARY", { { 0,  1 }, { 0,  1 }, { 0,  1 } } },
    { "BDAY",        { { 0,  1 }, { 0,  1 }, { 0,  1 } } },
    { "FN",          { { 0, -1 }, { 1, -1 }, { 1, -1 } } },
    { "GENDER",      { { 0,  1 }, { 0,  1 }, { 0,  1 } } },
    { "KIND",        { { 0,  1 }, { 0,  1 }, { 0,  1 } } },
    { "N",           { { 1,  1 }, { 1,  1 }, { 0,  1 } } },
    { "PRODID",      { { 0,  1 }, { 0,  1 }, { 0,  1 } } },
    { "REV",         { { 0,  1 }, { 0,  1 }, { 0,  1 } } },
    { "UID",         { { 0,  1 }, { 0,  1 }, { 0,  1 } } }
};

#define NUM_CHECK_PROPS 10

EXPORTED int vparse_restriction_check(struct vparse_card *card)
{
    enum { VER_2_1 = 0, VER_3_0, VER_4_0 };
    struct vparse_entry *entry = NULL;
    unsigned counts[NUM_CHECK_PROPS];
    unsigned i, ver = VER_3_0;

    /* Zero property counts */
    memset(counts, 0, NUM_CHECK_PROPS * sizeof(unsigned));

    /* Count interesting properties */
    for (entry = card->properties; entry; entry = entry->next) {
        for (i = 0; i < NUM_CHECK_PROPS; i++) {
            if (!strcasecmpsafe(entry->name, restrictions[i].name)) {
                counts[i]++;

                if (i == 0) {
                    /* VERSION */
                    if (!strcmp(entry->v.value, "2.1")) ver = VER_2_1;
                    else if (!strcmp(entry->v.value, "3.0")) ver = VER_3_0;
                    else if (!strcmp(entry->v.value, "4.0")) ver = VER_4_0;
                    else return 0;
                }
            }
        }
    }

    /* Check property counts against restrictions */
    for (i = 0; i < NUM_CHECK_PROPS; i++) {
        if (counts[i] < restrictions[i].version[ver].min) return 0;
        if (counts[i] > restrictions[i].version[ver].max) return 0;
    }

    return 1;
}

#if DEBUG
static int _dump_card(struct vparse_card *card)
{
    struct vparse_entry *entry;
    struct vparse_param *param;
    struct vparse_card *sub;

    printf("begin:%s\n", card->type);
    for (entry = card->properties; entry; entry = entry->next) {
        printf("%s", entry->name);
        for (param = entry->params; param; param = param->next)
            printf(";%s=%s", param->name, param->value);
        if (entry->multivaluesep)
            printf(":multivalue (%c)\n", entry->multivaluesep);
        else
            printf(":%s\n", entry->v.value);
    }
    for (sub = card->objects; sub; sub = sub->next)
        _dump_card(sub);
    printf("end:%s\n", card->type);
    return 0;
}

static int _dump(struct vparse_card *card)
{
    _dump_card(card->objects);
    return 0;
}

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

int main(int argc, const char **argv)
{
    const char *fname = argv[1];
    struct stat sbuf;
    int fd = open(fname, O_RDONLY);
    struct vparse_state parser;
    char *data;
    int r;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s fname\n", argv[0]);
        exit(1);
    }

    memset(&parser, 0, sizeof(struct vparse_state));

    fstat(fd, &sbuf);
    data = malloc(sbuf.st_size+1);

    read(fd, data, sbuf.st_size);
    data[sbuf.st_size] = '\0';

    parser.base = data;
    r = vparse_parse(&parser, 0);
    if (r) {
        struct vparse_errorpos pos;
        vparse_fillpos(&parser, &pos);
        printf("error %s at line %d char %d: %.*s ... %.*s <--- (started at line %d char %d)\n",
              vparse_errstr(r), pos.errorline, pos.errorchar,
              20, parser.base + pos.startpos,
              20, parser.base + pos.errorpos - 20,
              pos.startline, pos.startchar);
        return 1;
    }

    _dump(parser.card);

    vparse_free(&parser);

    return 0;
}
#endif

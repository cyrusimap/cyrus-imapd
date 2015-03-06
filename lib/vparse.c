/* vparse.c : fast vcard parser */

#include <ctype.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>

#include "vparse.h"
#include "xmalloc.h"

#define LC(s) do { char *p; for (p = s; *p; p++) if (*p >= 'A' && *p <= 'Z') *p += ('a' - 'A'); } while (0)

static char *buf_dup_cstring(struct buf *buf)
{
    char *ret = xstrndup(buf->s, buf->len);
    /* more space efficient than returning overlength buffers, and
     * you would just wind up mallocing another buffer anyway */
    buf->len = 0;
    return ret;
}

static char *buf_dup_lcstring(struct buf *buf)
{
    char *ret = buf_dup_cstring(buf);
    LC(ret);
    return ret;
}

#define NOTESTART() state->itemstart = state->p
#define MAKE(X, Y) X = malloc(sizeof(struct Y)); memset(X, 0, sizeof(struct Y))
#define PUTC(C) buf_putc(&state->buf, C)
#define INC(I) state->p += I

/* just leaves it on the buffer */
static int _parse_param_quoted(struct vparse_state *state, int multiparam)
{
    NOTESTART();

    while (*state->p) {
        switch (*state->p) {
        case '"':
            INC(1);
            return 0;

        /* normal backslash quoting - NOTE, not strictly RFC complient,
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
        switch (*state->p) {
        case '=':
            state->param->name = buf_dup_lcstring(&state->buf);
            *haseq = 1;
            INC(1);
            return 0;

        case ';': /* vcard 2.1 parameter with no value */
        case ':':
            if (state->barekeys) {
                state->param->name = buf_dup_lcstring(&state->buf);
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
    struct vparse_list *item;
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

    for (item = state->multiparam; item; item = item->next) {
        if (!strcmp(state->param->name, item->s)) {
            multiparam = 1;
            break;
        }
    }

    /* now get the value */
    while (*state->p) {
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
        switch (*state->p) {
        case ':':
            state->entry->name = buf_dup_lcstring(&state->buf);
            INC(1);
            return 0;

        case ';':
            state->entry->name = buf_dup_lcstring(&state->buf);
            INC(1);
            return _parse_entry_params(state);

        case '.':
            if (state->entry->group)
                return PE_ENTRY_MULTIGROUP;
            state->entry->group = buf_dup_lcstring(&state->buf);
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

static int _parse_entry_multivalue(struct vparse_state *state)
{
    struct vparse_list **valp = &state->entry->v.values;

    state->entry->multivalue = 1;

    NOTESTART();

repeat:
    MAKE(state->value, vparse_list);

    while (*state->p) {
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

        case ';':
            state->value->s = buf_dup_cstring(&state->buf);
            *valp = state->value;
            valp = &state->value->next;
            INC(1);
            goto repeat;

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
    state->value->s = buf_dup_cstring(&state->buf);
    *valp = state->value;
    state->value = NULL;
    return 0;
}

static int _parse_entry_value(struct vparse_state *state)
{
    struct vparse_list *item;

    for (item = state->multival; item; item = item->next)
        if (!strcmp(state->entry->name, item->s))
            return _parse_entry_multivalue(state);

    NOTESTART();

    while (*state->p) {
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

static void _free_list(struct vparse_list *list)
{
    struct vparse_list *listnext;

    for (; list; list = listnext) {
        listnext = list->next;
        free(list->s);
        free(list);
    }
}

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
        if (entry->multivalue)
            _free_list(entry->v.values);
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
    _free_list(state->value);
    _free_entry(state->entry);
    _free_param(state->param);

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

        if (!strcmp(state->entry->name, "begin")) {
            /* shouldn't be any params */
            if (state->entry->params) {
                state->itemstart = entrystart;
                return PE_BEGIN_PARAMS;
            }
            /* only possible if some idiot passes 'begin' as
             * multivalue field name */
            if (state->entry->multivalue) {
                state->itemstart = entrystart;
                return PE_BEGIN_PARAMS;
            }

            MAKE(sub, vparse_card);
            sub->type = strdup(state->entry->v.value);
            LC(sub->type);
            _free_entry(state->entry);
            state->entry = NULL;
            /* we must stitch it in first, because state won't hold it */
            *subp = sub;
            subp = &sub->next;
            r = _parse_vcard(state, sub, /*only_one*/0);
            if (r) return r;
            if (only_one) return 0;
        }
        else if (!strcmp(state->entry->name, "end")) {
            /* shouldn't be any params */
            if (state->entry->params) {
                state->itemstart = entrystart;
                return PE_BEGIN_PARAMS;
            }
            /* only possible if some idiot passes 'end' as
             * multivalue field name */
            if (state->entry->multivalue) {
                state->itemstart = entrystart;
                return PE_BEGIN_PARAMS;
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
    }
    return "Unknown error";
}

#ifdef DEBUG
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
        if (entry->multivalue)
            printf(":multivalue\n");
        else
            printf(":%s\n", entry->v.value);
    }
    for (sub = card->objects; sub; sub = sub->next)
        _dump_card(sub);
    printf("end:%s\n", card->type);
}

static int _dump(struct vparse_card *card)
{
    _dump_card(card->objects);
}

int main(int argv, const char **argc)
{
    const char *fname = argc[1];
    struct stat sbuf;
    int fd = open(fname, O_RDONLY);
    struct vparse_state parser;
    char *data;
    int r;

    memset(&parser, 0, sizeof(struct vparse_state));

    fstat(fd, &sbuf);
    data = malloc(sbuf.st_size+1);

    read(fd, data, sbuf.st_size);
    data[sbuf.st_size] = '\0';

    parser.base = data;
    r = vparse_parse(&parser);
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

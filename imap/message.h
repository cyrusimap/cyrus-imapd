/* message.h -- Message parsing
 *
 * Copyright (c) 1994-2010 Carnegie Mellon University.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The name "Carnegie Mellon University" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For permission or any legal
 *    details, please contact
 *      Carnegie Mellon University
 *      Center for Technology Transfer and Enterprise Creation
 *      4615 Forbes Avenue
 *      Suite 302
 *      Pittsburgh, PA  15213
 *      (412) 268-7393, fax: (412) 268-7395
 *      innovation@andrew.cmu.edu
 *
 * 4. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by Computing Services
 *     at Carnegie Mellon University (http://www.cmu.edu/computing/)."
 *
 * CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
 * FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef INCLUDED_MESSAGE_H
#define INCLUDED_MESSAGE_H

#include <stdio.h>

#include "prot.h"
#include "mailbox.h"
#include "strarray.h"
#include "util.h"
#include "charset.h"

/* (draft standard) MIME tspecials */
#define MIME_TSPECIALS "()<>@,;:\\\"/[]?="

/*
 * Parsed form of a body-part
 */
struct body {
    /* Content-* header information */
    char *type;
    char *subtype;
    struct param *params;
    char *id;
    char *description;
    char *encoding;
    char *md5;
    char *disposition;
    struct param *disposition_params;
    struct param *language;
    char *location;
    int charset_enc;            /* encoding in binary bodystructure */
    char *charset_id;           /* charset in binary bodystructure */
    char *part_id;               /* IMAP part identifier of a subpart */

    /* Location/size information */
    uint32_t header_offset;
    uint32_t header_size;
    uint32_t header_lines;
    uint32_t content_offset;
    uint32_t content_size;
    uint32_t content_lines;
    uint32_t boundary_size;         /* Size of terminating boundary */
    uint32_t boundary_lines;

    /* Content guid - sha1 of binary content */
    struct message_guid content_guid;

    int numparts;               /* For multipart types */
    struct body *subpart;       /* For message/rfc822 and multipart types */

    uint32_t filesize;          /* to make sure that things match up! */

    /*
     * Other header information.
     * Only meaningful for body-parts at top level or
     * enclosed in message/rfc-822
     */
    char *date;
    char *subject;
    struct address *from;
    struct address *sender;
    struct address *reply_to;
    struct address *to;
    struct address *cc;
    struct address *bcc;
    char *in_reply_to;
    char *message_id;
    char *x_me_message_id;
    char *references;
    char *received_date;
    char *x_deliveredinternaldate;

    /*
     * Cached headers.  Only filled in at top-level
     */
    struct buf cacheheaders;

    /*
     * decoded body.  Filled in as needed.
     */
    char *decoded_body;

    /* Decoded content size, or 0 if unknown */
    uint32_t decoded_content_size;

    /* Message GUID. Only filled in at top level */
    struct message_guid guid;
};

/* List of Content-type parameters */
struct param {
    struct param *next;
    char *attribute;
    char *value;
};
extern void param_free(struct param **paramp);

extern int message_copy_strict(struct protstream *from, FILE *to,
                               unsigned size, int allow_null);

extern int message_parse(const char *fname, struct index_record *record);

struct message_content {
    struct buf map;
    struct body *body; /* parsed body structure */
#ifdef WITH_JMAP
    struct matchmime *matchmime;
#endif
};

#ifdef WITH_JMAP
#define MESSAGE_CONTENT_INITIALIZER { BUF_INITIALIZER, NULL, NULL }
#else
#define MESSAGE_CONTENT_INITIALIZER { BUF_INITIALIZER, NULL }
#endif

/* MUST keep this struct sync'd with sieve_bodypart in sieve_interface.h */
struct bodypart {
    char section[128];
    const char *decoded_body;
};


extern void parse_cached_envelope(char *env, char *tokens[], int tokens_size);

extern int message_parse_mapped(const char *msg_base, unsigned long msg_len,
                                struct body *body, const char *efname);
extern int message_parse_binary_file(FILE *infile, struct body **body,
                                     const char *efname);
extern int message_parse_file(FILE *infile,
                              const char **msg_base, size_t *msg_len,
                              struct body **body,
                              const char *efname);
extern int message_parse_file_buf(FILE *infile,
                                  struct buf *buf,
                                  struct body **body,
                                  const char *efname);
extern void message_parse_string(const char *hdr, char **hdrp);
extern void message_pruneheader(char *buf, const strarray_t *headers,
                                const strarray_t *headers_not);
extern void message_fetch_part(struct message_content *msg,
                               const char **content_types,
                               struct bodypart ***parts);
extern void message_write_nstring(struct buf *buf, const char *s);
extern void message_write_nstring_map(struct buf *buf, const char *s, unsigned int len);
extern void message_write_body(struct buf *buf, const struct body *body,
                                  int newformat);
extern void message_write_xdrstring(struct buf *buf, const struct buf *s);
extern int message_write_cache(struct index_record *record, const struct body *body);

extern int message_create_record(struct index_record *message_index,
                                 const struct body *body);
extern void message_free_body(struct body *body);

extern void message_parse_type(const char *hdr, char **typep, char **subtypep, struct param **paramp);
extern void message_parse_disposition(const char *hdr, char **hdpr, struct param **paramp);

extern void message_parse_charset_params(const struct param *params, charset_t *c_ptr);

/* NOTE - scribbles on its input */
extern void message_parse_env_address(char *str, struct address *addr);

extern char *parse_nstring(char **str);

extern void message_read_bodystructure(const struct index_record *record,
                                       struct body **body);

extern int message_update_conversations(struct conversations_state *, struct mailbox *, struct index_record *, conversation_t **);
extern char *message_extract_convsubject(const struct index_record *record);

/* Call proc for each header in headers, which must contain valid
 * MIME header bytes. Header keys and values passed to the callback
 * are zero-terminated strings. Header values are not unfolded and
 * omit the terminated CR LF sequence. */
extern int message_foreach_header(const char *headers, size_t len,
                   int (*proc)(const char *key, const char *val, void *rock),
                   void *rock);

/*-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-*/
/* New message API */

typedef struct message message_t;
struct mailbox;

/* Flags for use as the 'flags' argument to message_get_field(). */
enum message_format
{
    /* Original raw octets from the on-the-wire RFC 5322 format,
     * including folding and RFC 2047 encoding of non-ASCII characters.
     * The result may point into a mapping and not be NUL-terminated,
     * use buf_cstring() if necessary.  */
    MESSAGE_RAW=        1,
    /* Unfolded and RFC 2047 decoded */
    MESSAGE_DECODED,
    /* Unfolded, RFC 2047 decoded, and HTML-escaped */
    MESSAGE_SNIPPET,
    /* Unfolded, RFC 2047 decoded, and search-normalised */
    MESSAGE_SEARCH,

#define _MESSAGE_FORMAT_MASK    (0x7)

    /* This flag can be OR'd into the format argument to request that
     * the field name and a colon ':' are left in the result.  Normally
     * only the field value is returned.  This is useful when calling
     * multiple times with MESSAGE_APPEND, to accumulate multiple headers
     * in the buffer. */
    MESSAGE_FIELDNAME=          (1<<5),

    /* This flag can be OR'd into the format argument to request that
     * all the fields of the given name are returned.  Normally only
     * the first is returned, which is faster. */
    /* XXX this flag is not implemented, but is effectively always set! */
    MESSAGE_MULTIPLE=           (1<<6),

    /* This flag can be OR'd into the format argument to request that
     * results be appended to the buffer; normally the buffer is reset
     * first. */
    MESSAGE_APPEND=             (1<<7),

    /* This flag can be OR'd into the format argument to request that
     * leading and trailing space be trimmed from the buffer */
    MESSAGE_TRIM=               (1<<8),

    /* This flag can be OR'd into the format argument to request that
     * only the last field of the given name is returned.  Normally only
     * the first is returned, which is faster. */
    MESSAGE_LAST=               (1<<9),
};

enum message_indexflags
{
    MESSAGE_SEEN=               (1<<0),
    MESSAGE_RECENT=             (1<<1),
};

extern message_t *message_new(void);
extern message_t *message_new_from_data(const char *base, size_t len);
extern message_t *message_new_from_mailbox(struct mailbox *mailbox,
                                           unsigned int recno);
extern message_t *message_new_from_record(struct mailbox *,
                                          const struct index_record *);
extern message_t *message_new_from_index(struct mailbox *,
                                         const struct index_record *,
                                         uint32_t msgno,
                                         uint32_t indexflags);
extern message_t *message_new_from_filename(const char *filename);
extern void message_set_from_data(const char *base, size_t len,
                                  message_t *m);
extern void message_set_from_mailbox(struct mailbox *mailbox,
                                     unsigned int recno,
                                     message_t *m);
extern void message_set_from_index(struct mailbox *,
                                   const struct index_record *,
                                   uint32_t msgno,
                                   uint32_t indexflags,
                                   message_t *m);
extern void message_set_from_record(struct mailbox *,
                                    const struct index_record *,
                                    message_t *m);

extern int message_get_indexversion(message_t *m, uint32_t *versionp);

extern message_t *message_ref(message_t *m);
extern void message_unref(message_t **m);

extern int message_get_field(message_t *m, const char *name,
                             int format, struct buf *buf);
extern int message_get_cachebody(message_t *m, const struct body **bodyp);
extern int message_get_body(message_t *m, struct buf *buf);
extern int message_get_headers(message_t *m, struct buf *buf);
extern int message_get_type(message_t *m, const char **strp);
extern int message_get_subtype(message_t *m, const char **strp);
extern int message_get_charset_id(message_t *m, const char **strp);
extern int message_get_encoding(message_t *m, int *encp);
extern int message_get_num_parts(message_t *m, unsigned int *np);
extern int message_get_messageid(message_t *m, struct buf *buf);
extern int message_get_listid(message_t *m, struct buf *buf);
extern int message_get_mailinglist(message_t *m, struct buf *buf);
extern int message_get_from(message_t *m, struct buf *buf);
extern int message_get_to(message_t *m, struct buf *buf);
extern int message_get_cc(message_t *m, struct buf *buf);
extern int message_get_bcc(message_t *m, struct buf *buf);
extern int message_get_deliveredto(message_t *m, struct buf *buf);
extern int message_get_inreplyto(message_t *m, struct buf *buf);
extern int message_get_references(message_t *m, struct buf *buf);
extern int message_get_subject(message_t *m, struct buf *buf);
extern int message_get_priority(message_t *m, struct buf *buf);
extern int message_get_gmtime(message_t *m, time_t *tp);
extern int message_get_mailbox(message_t *m, struct mailbox **);
extern int message_get_uid(message_t *m, uint32_t *uidp);
extern int message_get_cid(message_t *m, conversation_id_t *cidp);
extern int message_get_guid(message_t *m, const struct message_guid **guidp);
extern int message_get_internaldate(message_t *m, time_t *);
extern int message_get_spamscore(message_t *m, uint32_t *scorep);
extern int message_get_savedate(message_t *m, time_t *);
extern int message_get_sentdate(message_t *m, time_t *);
extern int message_get_modseq(message_t *m, modseq_t *modseqp);
extern int message_get_internalflags(message_t *m, uint32_t *flagsp);
extern int message_get_systemflags(message_t *m, uint32_t *);
extern int message_get_userflags(message_t *m, uint32_t *flagsp);
extern int message_get_indexflags(message_t *m, uint32_t *);
extern int message_get_size(message_t *m, uint32_t *sizep);
extern int message_get_msgno(message_t *m, uint32_t *msgnop);
extern int message_get_fname(message_t *m, const char **fnamep);
extern int message_foreach_section(message_t *m,
                   int (*proc)(int isbody, charset_t charset, int encoding,
                               const char *type, const char *subtype,
                               const struct param *type_params,
                               const char *disposition,
                               const struct param *disposition_params,
                               const struct message_guid *content_guid,
                               const char *part,
                               struct buf *data,
                               void *rock),
                   void *rock);
extern int message_get_leaf_types(message_t *m, strarray_t *types);
extern int message_get_types(message_t *m, strarray_t *types);


/* less shitty interface */
extern const struct index_record *msg_record(const message_t *m);
extern struct mailbox *msg_mailbox(const message_t *m);
extern uint32_t msg_size(const message_t *m);
extern uint32_t msg_uid(const message_t *m);
extern conversation_id_t msg_cid(const message_t *m);
extern modseq_t msg_modseq(const message_t *m);
extern uint32_t msg_msgno(const message_t *m);
extern const struct message_guid *msg_guid(const message_t *m);

/*-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-*/

#endif /* INCLUDED_MESSAGE_H */

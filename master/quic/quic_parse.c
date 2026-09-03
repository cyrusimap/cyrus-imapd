/* quic_parse.c - QUIC packet parsing shared by both dispatch backends */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#include <config.h>

#include <string.h>

#include "master/quic/quic_parse.h"

/* Read one length-prefixed Connection ID (a 1-byte length, then that
 * many bytes) starting at *off, advancing *off past it on success.
 * Returns 0 and fills *cidlen/cid, -1 if the length byte itself is
 * missing, the length exceeds QUIC_MAX_CIDLEN, or the CID doesn't fit
 * in what's left of the buffer -- the two identical length-prefixed
 * CID reads quic_parse_initial() needs (dcid, then scid). */
static int quic_parse_read_cid(const uint8_t *buf, size_t len, size_t *off,
                               uint8_t cid[QUIC_MAX_CIDLEN], uint8_t *cidlen)
{
    uint8_t idlen;

    if (len < *off + 1) return -1;
    idlen = buf[(*off)++];
    if (idlen > QUIC_MAX_CIDLEN) return -1;
    if (len < *off + idlen) return -1;
    memcpy(cid, buf + *off, idlen);
    *cidlen = idlen;
    *off += idlen;
    return 0;
}

int quic_parse_initial(const uint8_t *buf, size_t len,
                       struct quic_initial_cids *out)
{
    size_t off;
    uint8_t b0;

    if (!buf || len < 1) return -1;

    b0 = buf[0];
    off = 1;

    /* Long header form only -- Initial packets are always long
     * header; short-header packets never carry version/CIDs the way
     * we need here. */
    if (!(b0 & 0x80)) return -1;

    if (len < off + 4) return -1;
    out->version = ((uint32_t) buf[off]     << 24) |
                   ((uint32_t) buf[off + 1] << 16) |
                   ((uint32_t) buf[off + 2] << 8)  |
                    (uint32_t) buf[off + 3];
    off += 4;

    /* Only QUIC v1 is recognized -- version negotiation and other
     * QUIC versions are out of scope; drop rather than guess. */
    if (out->version != 0x00000001u) return -1;

    if (quic_parse_read_cid(buf, len, &off, out->dcid, &out->dcidlen))
        return -1;
    if (quic_parse_read_cid(buf, len, &off, out->scid, &out->scidlen))
        return -1;

    /* Token length, token, remaining-length, packet number, and
     * payload follow, but dispatch doesn't need them -- the worker
     * re-parses the whole (relayed) datagram properly via ngtcp2. */

    return 0;
}

int quic_extract_dcid(const uint8_t *buf, size_t len, uint8_t cidlen,
                      uint8_t dcid[QUIC_MAX_CIDLEN], uint8_t *dcidlen)
{
    uint8_t b0, idlen;

    if (!buf || len < 1) return -1;
    b0 = buf[0];

    if (b0 & 0x80) {
        /* Long header: type(1) + version(4) + dcid_len(1), then DCID */
        if (len < 6) return -1;
        idlen = buf[5];
        if (idlen > QUIC_MAX_CIDLEN) return -1;
        if (len < (size_t) 6 + idlen) return -1;
        memcpy(dcid, buf + 6, idlen);
        *dcidlen = idlen;
    }
    else {
        /* Short header: no self-described length -- assume cidlen,
         * the fixed length the caller hands out for every connection
         * it dispatches. */
        if (len < (size_t) 1 + cidlen) return -1;
        memcpy(dcid, buf + 1, cidlen);
        *dcidlen = cidlen;
    }

    return 0;
}

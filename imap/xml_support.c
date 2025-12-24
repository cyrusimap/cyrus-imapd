/* xml_support.c -- Helper functions for libxml2 */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#include <config.h>

#include "xml_support.h"

/* libxml2 replacement functions for those missing in older versions */

#ifndef HAVE_XML_BUFFERDETACH

xmlChar *xmlBufferDetach(xmlBufferPtr buf)
{
    xmlChar *ret;

    if (!buf) return NULL;

    ret = buf->content;
    buf->content = NULL;
    buf->use = buf->size = 0;

    return ret;
}

#ifndef HAVE_XML_FIRSTCHILD

xmlNodePtr xmlGetNextNode(xmlNodePtr node)
{
    for (; node && node->type != XML_ELEMENT_NODE; node = node->next);
    return node;
}

#endif /* HAVE_XML_FIRSTCHILD */

#endif /* HAVE_XML_BUFFERDETACH */

/* xml_support.h - Helper functions for libxml2 */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */


#ifndef XML_SUPPORT_H
#define XML_SUPPORT_H

#include <config.h>

#include <libxml/tree.h>

/* libxml2 replacement functions for those missing in older versions */

#ifndef HAVE_XML_BUFFERDETACH

extern xmlChar *xmlBufferDetach(xmlBufferPtr buf);

#ifndef HAVE_XML_FIRSTCHILD

extern xmlNodePtr xmlGetNextNode(xmlNodePtr node);

#define xmlFirstElementChild(parent) xmlGetNextNode(parent->children)

#define xmlNextElementSibling(node) xmlGetNextNode(node->next)

#endif /* HAVE_XML_FIRSTCHILD */

#endif /* HAVE_XML_BUFFERDETACH */

#endif /* XML_SUPPORT_H */

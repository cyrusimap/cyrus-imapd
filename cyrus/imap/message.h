/* message.h -- Message parsing
 *
 * Copyright 1996, Carnegie Mellon University.  All Rights Reserved.
 * 
 * This software is made available for academic and research
 * purposes only.  No commercial license is hereby granted.
 * Copying and other reproduction is authorized only for research,
 * education, and other non-commercial purposes.  No warranties,
 * either expressed or implied, are made regarding the operation,
 * use, or results of the software.  Such a release does not permit
 * use of the code for commercial purposes or benefits by anyone
 * without specific, additional permission by the owner of the code.
 *
 */
#ifndef INCLUDED_MESSAGE_H
#define INCLUDED_MESSAGE_H

#ifndef P
#ifdef __STDC__
#define P(x) x
#else
#define P(x) ()
#endif
#endif

#include <stdio.h>

#include "prot.h"
#include "mailbox.h"

extern int message_copy_strict P((struct protstream *from, FILE *to,
				  unsigned size));

extern int message_parse_file P((FILE *infile, struct mailbox *mailbox,
				 struct index_record *message_index));
extern int message_parse_mapped P((const char *msg_base, unsigned long msg_len,
				   struct mailbox *mailbox,
				   struct index_record *message_index));

#endif /* INCLUDED_MESSAGE_H */

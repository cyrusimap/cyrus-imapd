#!/bin/sh
#
# xversion.sh: extract the timestamp from the $Id: string
# in every source file and use the most recent as the CYRUS_CVSDATE
#
# Copyright (c) 1994-2008 Carnegie Mellon University.  All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in
#    the documentation and/or other materials provided with the
#    distribution.
#
# 3. The name "Carnegie Mellon University" must not be used to
#    endorse or promote products derived from this software without
#    prior written permission. For permission or any legal
#    details, please contact
#      Carnegie Mellon University
#      Center for Technology Transfer and Enterprise Creation
#      4615 Forbes Avenue
#      Suite 302
#      Pittsburgh, PA  15213
#      (412) 268-7393, fax: (412) 268-7395
#      innovation@andrew.cmu.edu
#
# 4. Redistributions of any form whatsoever must retain the following
#    acknowledgment:
#    "This product includes software developed by Computing Services
#     at Carnegie Mellon University (http://www.cmu.edu/computing/)."
#
# CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
# THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
# FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
# AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
# OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#
# $Id: xversion.sh,v 1.9 2008/03/24 17:09:20 murch Exp $

if [ "$AWK" = "" ]; then
    AWK=awk
fi

TMPF=/tmp/xversion.$$
DATEPAT=[1-2][0-9][0-9][0-9]/[0-1][0-9]/[0-3][0-9]
TIMEPAT=[0-2][0-9]:[0-5][0-9]:[0-5][0-9]

printf "/* Generated automatically by xversion.sh */\n\n" > $TMPF

printf "#define CYRUS_CVSDATE " >> $TMPF

find .. -name '*.[chly]' -print | \
	xargs egrep '\$Id: ' | \
	$AWK ' # extract timestamp and surround with quotes
	match ($0, pattern) {
	    printf "\"%s\"\n", substr($0, RSTART, RLENGTH)
	}' pattern="$DATEPAT $TIMEPAT" | \
	sort | tail -1 >> $TMPF

if [ -f xversion.h ] && cmp -s $TMPF xversion.h
then
    rm $TMPF
else
    mv $TMPF xversion.h
    rm -f version.o
fi


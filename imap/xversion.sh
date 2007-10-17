#!/bin/sh
#
# xversion.sh: extract the timestamp from the $Id: string
# in every source file and use the most recent as the CYRUS_CVSDATE
#
# $Id: xversion.sh,v 1.8 2007/10/17 18:45:48 murch Exp $

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


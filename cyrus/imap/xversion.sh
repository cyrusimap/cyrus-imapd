#!/bin/sh
#
# xversion.sh: extract the timestamp from the $Id: string
# in every source file and use the most recent as the CVSDATE
#
# $Id: xversion.sh,v 1.5 2001/10/25 14:59:54 ken3 Exp $

if [ "$AWK" = "" ]; then
    AWK=awk
fi

DATEPAT=[1-2][0-9][0-9][0-9]/[0-1][0-9]/[0-3][0-9]
TIMEPAT=[0-2][0-9]:[0-5][0-9]:[0-5][0-9]

printf "/* Generated automatically by xversion.sh */\n\n" > xversion.h

printf "#define CVSDATE " >> xversion.h

find .. -name '*.[chly]' -print | \
	xargs egrep '\$Id: ' | \
	$AWK ' # extract timestamp and surround with quotes
	match ($0, pattern) {
	    printf "\"%s\"\n", substr($0, RSTART, RLENGTH)
	}' pattern="$DATEPAT $TIMEPAT" | \
	sort | tail -1 >> xversion.h

#!/bin/sh
# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

AWK=@AWK@
DIR=@DIR@

ROOT=`echo $1 | sed -e s/.et$//`
BASE=`echo $ROOT | sed -e 's;.*/;;'`

$AWK -f ${DIR}/et_h.awk outfile=${BASE}.h $ROOT.et
$AWK -f ${DIR}/et_c.awk outfile=${BASE}.c $ROOT.et

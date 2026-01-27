# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

# The entire purpose of this module is to
# do the horrible dance needed to import either
# of Digest::SHA or the older Digest::SHA1

package Cassandane::Util::SHA;
use strict;
use warnings;
use vars qw(@ISA @EXPORT);

@ISA = qw(Exporter);
@EXPORT = qw(sha1_hex sha1);

BEGIN {
    eval "use Digest::SHA qw(sha1_hex sha1); 1;"
     || eval "use Digest::SHA1 qw(sha1_hex sha1);";
}

1;

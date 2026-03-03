# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Cyrus::Thread;
use strict;
use warnings;
use DateTime;
use Data::Dumper;

use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;

sub new
{
    my $class = shift;
    return $class->SUPER::new({}, @_);
}

use Cassandane::Tiny::Loader;

1;

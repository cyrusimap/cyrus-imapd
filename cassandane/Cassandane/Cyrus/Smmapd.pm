# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Cyrus::Smmapd;
use strict;
use warnings;
use experimental 'signatures';

use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;

sub new ($class, @rest)
{
    $class->SUPER::new({ services => ['smmap', 'imap'] }, @rest);
}

use Cassandane::Tiny::Loader;

1;

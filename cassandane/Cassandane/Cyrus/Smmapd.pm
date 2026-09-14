# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Cyrus::Smmapd;
use strict;
use warnings;

use lib '.';
use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;

sub new
{
    my ($class, @args) = @_;

    return $class->SUPER::new({ services => ['smmap', 'imap'] }, @args);
}

use Cassandane::Tiny::Loader 'tiny-tests/Smmapd';

1;

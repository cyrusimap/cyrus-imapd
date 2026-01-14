# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Test::Parameter;
use strict;
use warnings;

use base qw(Cassandane::Unit::TestCase);
use Cassandane::Util::Log;

sub new
{
    my $class = shift;
    my $self = $class->SUPER::new(@_);
    return $self;
}

my $mustache;
Cassandane::Unit::TestCase::parameter(\$mustache, 'walrus', 'toothbrush', 'waxed');

my $nose;
Cassandane::Unit::TestCase::parameter(\$nose, 'roman');

my $eyes;
Cassandane::Unit::TestCase::parameter(\$eyes, 'brown', 'cat');

sub test_face
{
    xlog "XXX face: mustache=$mustache eyes=$eyes nose=$nose";
}

1;

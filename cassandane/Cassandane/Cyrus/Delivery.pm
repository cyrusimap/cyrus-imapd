# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Cyrus::Delivery;
use strict;
use warnings;
use IO::File;

use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;

Cassandane::Cyrus::TestCase::magic(DuplicateSuppressionOff => sub {
    shift->config_set(duplicatesuppression => 0);
});
Cassandane::Cyrus::TestCase::magic(DuplicateSuppressionOn => sub {
    shift->config_set(duplicatesuppression => 1);
});
Cassandane::Cyrus::TestCase::magic(FuzzyMatch => sub {
    shift->config_set(lmtp_fuzzy_mailbox_match => 1);
});
sub new
{
    my $class = shift;
    return $class->SUPER::new({
            deliver => 1,
            adminstore => 1,
    }, @_);
}

sub set_up
{
    my ($self) = @_;
    $self->SUPER::set_up();
}

sub tear_down
{
    my ($self) = @_;
    $self->SUPER::tear_down();
}

use Cassandane::Tiny::Loader;

1;

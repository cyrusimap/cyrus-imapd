# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Cyrus::T116;
use strict;
use warnings;

use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;
use Cassandane::Instance;

sub new
{
    my $class = shift;
    return $class->SUPER::new({ adminstore => 1 }, @_);
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

Cassandane::Cyrus::TestCase::magic(T116 => sub {
    my ($testcase) = @_;
    $testcase->config_set(virtdomains => 'userid');
});

use Cassandane::Tiny::Loader;

1;

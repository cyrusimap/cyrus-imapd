# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Cyrus::Bug3072;
use strict;
use warnings;
use DateTime;

use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;

sub new
{
    my $class = shift;
    return $class->SUPER::new({}, @_);
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

#
# Test COPY behaviour with a very long sequence set
#
sub test_copy_longset_slow
{
    my ($self) = @_;

    my $imaptalk = $self->{store}->get_client();

    $imaptalk->create("INBOX.dest");
    for (1..2000) {
        $self->make_message("Message $_");
    }
    my $list = join(',', map { $_ * 2 } 1..1000);

    $imaptalk->copy($list, "INBOX.dest");

    # XXX this doesn't even verify that the messages were copied!
}

1;

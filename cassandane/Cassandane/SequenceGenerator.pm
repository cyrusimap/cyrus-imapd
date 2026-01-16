# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::SequenceGenerator;
use strict;
use warnings;

use base qw(Cassandane::Generator);
use Cassandane::Util::DateTime qw(to_iso8601);
use Cassandane::Address;
use Cassandane::Message;
use Cassandane::Util::Log;
use Cassandane::Util::Words;

my $NMESSAGES = 240;
my $DELTAT = 3600;   # seconds

sub new
{
    my $class = shift;
    my $self = $class->SUPER::new(@_);

    $self->{nmessages} = $NMESSAGES;
    $self->{deltat} = $DELTAT;
    $self->{next_date} = DateTime->now->epoch -
                    $self->{deltat} * ($self->{nmessages}+1);

    return $self;
}

#
# Generate a single email.
# Args: Generator, (param-key => param-value ... )
# Returns: Message ref
#
sub generate
{
    my ($self, %params) = @_;

    return undef
        if (!$self->{nmessages});

    my $dt = DateTime->from_epoch( epoch => $self->{next_date} );
    $params{subject} = "message at " .  to_iso8601($dt);
    $params{date} = $dt;
    $self->{next_date} += $self->{deltat};

    my $msg = $self->SUPER::generate(%params);
    $self->{nmessages}--;

    return $msg;
}

1;

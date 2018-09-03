#!/usr/bin/perl
#
#  Copyright (c) 2011-2017 FastMail Pty Ltd. All rights reserved.
#
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that the following conditions
#  are met:
#
#  1. Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#
#  2. Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.
#
#  3. The name "Fastmail Pty Ltd" must not be used to
#     endorse or promote products derived from this software without
#     prior written permission. For permission or any legal
#     details, please contact
#      FastMail Pty Ltd
#      PO Box 234
#      Collins St West 8007
#      Victoria
#      Australia
#
#  4. Redistributions of any form whatsoever must retain the following
#     acknowledgment:
#     "This product includes software developed by Fastmail Pty. Ltd."
#
#  FASTMAIL PTY LTD DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE,
#  INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY  AND FITNESS, IN NO
#  EVENT SHALL OPERA SOFTWARE AUSTRALIA BE LIABLE FOR ANY SPECIAL, INDIRECT
#  OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF
#  USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
#  TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE
#  OF THIS SOFTWARE.
#

package Cassandane::SequenceGenerator;
use strict;
use warnings;

use lib '.';
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

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

package Cassandane::ThreadedGenerator;
use strict;
use warnings;

use lib '.';
use base qw(Cassandane::Generator);
use Cassandane::Address;
use Cassandane::Message;
use Cassandane::Util::Log;
use Cassandane::Util::Words;

my $NTHREADS = 5;
my $NMESSAGES = 20 * $NTHREADS;
my $DELTAT = 300;   # seconds
my $FINISH_CHANCE = 0.08;
my $FOLLOW_CHANCE = 0.30;

sub new
{
    my ($class, %params) = @_;

    my $nmessages = $NMESSAGES;
    $nmessages = delete $params{nmessages}
        if defined $params{nmessages};
    my $deltat = $DELTAT;
    $deltat = delete $params{deltat}
        if defined $params{deltat};
    my $nthreads = $NTHREADS;
    $nthreads = delete $params{nthreads}
        if defined $params{nthreads};

    my $self = $class->SUPER::new(%params);

    $self->{nmessages} = $nmessages;
    $self->{deltat} = $deltat;

    $self->{threads} = [];
    for (my $i = 1 ; $i <= $nthreads ; $i++)
    {
        my $thread =
        {
            id => $i,
            subject => ucfirst(random_word()) . " " . random_word(),
            cid => undef,
            last_message => undef,
        };
        push(@{$self->{threads}}, $thread);
    }

    $self->{next_date} = DateTime->now->epoch -
                    $self->{deltat} * ($self->{nmessages}+1);
    $self->{last_thread} = undef;

    return $self;
}

sub _choose_thread
{
    my ($self) = @_;

    my $dice = rand;
    my $thread;
    if ($dice <= $FINISH_CHANCE)
    {
        # follow-up on the last thread
        $thread = $self->{last_thread};
    }
    if (!defined $thread)
    {
        my $i = int(rand(scalar(@{$self->{threads}})));
        $thread = $self->{threads}->[$i];
    }

    $dice = rand;
    if ($dice <= $FINISH_CHANCE)
    {
        # detach from the generator...we won't find it again
        my @tt = grep { $thread != $_ } @{$self->{threads}};
        $self->{threads} = \@tt;
        $self->{last_thread} = undef
            if defined $self->{last_thread} && $thread == $self->{last_thread};
    }
    else
    {
        $self->{last_thread} = $thread;
    }

    return $thread;
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

    my $thread = $self->_choose_thread();
    return undef
        if (!defined $thread);

    my $last = $thread->{last_message};
    if (defined $last)
    {
        $params{subject} = "Re: " . $thread->{subject};
        $params{references} = [ $last ];
    }
    else
    {
        $params{subject} = $thread->{subject};
    }
    $params{date} = DateTime->from_epoch( epoch => $self->{next_date} );
    $self->{next_date} += $self->{deltat};

    my $msg = $self->SUPER::generate(%params);
    $msg->add_header('X-Cassandane-Thread', $thread->{id});

    my $cid = $thread->{cid};
    $cid = $thread->{cid} = $msg->make_cid()
        unless defined $cid;
    $msg->set_attributes(cid => $cid);

    $thread->{last_message} = $msg;
    $self->{nmessages}--;

    return $msg;
}

# TODO: test that both References: and In-Reply-To: are tracked in the server
# TODO: test that Subject: isnt tracked in the server

1;

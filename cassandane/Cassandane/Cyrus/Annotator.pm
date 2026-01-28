#!/usr/bin/perl
#
#  Copyright (c) 2017 FastMail Pty Ltd  All rights reserved.
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
#  FASTMAIL PTY LTD DISCLAIMS ALL WARRANTIES WITH REGARD TO
#  THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
#  AND FITNESS, IN NO EVENT SHALL OPERA SOFTWARE AUSTRALIA BE LIABLE
#  FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
#  WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
#  AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
#  OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#

package Cassandane::Cyrus::Annotator;
use strict;
use warnings;
use Cwd qw(abs_path);

use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;
use Cassandane::Util::Slurp;
use Cassandane::Util::Wait;

sub new
{
    my $class = shift;
    my $config = Cassandane::Config->default()->clone();

    $config->set(
        annotation_callout => '@basedir@/conf/socket/annotator.sock',
        conversations => 'yes',
        httpmodules => 'jmap',
        jmap_nonstandard_extensions => 'yes',
    );

    my $self = $class->SUPER::new({
        config => $config,
        deliver => 1,
        start_instances => 0,
        adminstore => 1,

        jmap => 1,
        services => [ 'imap', 'sieve', 'http' ]
    }, @_);

    $self->needs('component', 'jmap');

    return $self;
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

sub start_my_instances
{
    my ($self) = @_;

    $self->{instance}->add_generic_listener(
        name => 'annotator',
        port => $self->{instance}->{config}->get('annotation_callout'),
        argv => sub {
            my ($listener) = @_;
            return (
                abs_path('utils/annotator.pl'),
                '--port', $listener->port(),
                '--pidfile', '@basedir@/run/annotator.pid',
                );
        });

    $self->_start_instances();
}

# Note: remove_annotation can't really be tested with local
# delivery, just with the APPEND command.

use Cassandane::Tiny::Loader 'tiny-tests/Annotator';

1;

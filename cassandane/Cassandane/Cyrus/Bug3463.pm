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

package Cassandane::Cyrus::Bug3463;
use strict;
use warnings;
use DateTime;
use Data::Dumper;

use lib '.';
use base qw(Cassandane::Cyrus::TestCase);

sub new
{
    my $class = shift;
    my $self = $class->SUPER::new({}, @_);

    return $self;
}

sub set_up
{
    my ($self) = @_;
    $self->SUPER::set_up();

    my $imaptalk = $self->{store}->get_client();
    $imaptalk->create("INBOX.problem-eposter") || die;

    system("tar -C $self->{instance}{basedir}/ -z -x -f data/problem-mails-bug3463.tar.gz");

    my $path = $self->{instance}->folder_to_directory('user.cassandane.problem-eposter');
    system("cp -av $self->{instance}{basedir}/problem-eposter/* $path/");
}

sub tear_down
{
    my ($self) = @_;
    $self->SUPER::tear_down();
}

#
# Test LSUB behaviour
#
sub test_thread_crash
    :NoAltNameSpace
{
    my ($self) = @_;

    my $imaptalk = $self->{store}->get_client();
    $imaptalk->select("INBOX.problem-eposter");

    my @res = $imaptalk->thread("REFERENCES", "utf-8", "ALL");

    $self->assert(defined $res[0]);
}

1;

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

package Cassandane::Cyrus::Bug3470;
use strict;
use warnings;
use DateTime;
use Data::Dumper;

use lib '.';
use base qw(Cassandane::Cyrus::TestCase);

sub new
{
    my $class = shift;

    my $config = Cassandane::Config->default()->clone();
    $config->set(virtdomains => 'userid');
    $config->set(unixhierarchysep => 'on');
    $config->set(altnamespace => 'yes');

    return $class->SUPER::new({ config => $config }, @_);
}

sub set_up
{
    my ($self) = @_;
    $self->SUPER::set_up();

    my $imaptalk = $self->{store}->get_client();

    # Bug #3470 folders
    # sub folders only
    $imaptalk->create("Drafts") || die;
    $imaptalk->create("2001/05/wk18") || die;
    $imaptalk->create("2001/05/wk19") || die;
    $imaptalk->create("2001/05/wk20") || die;
    $imaptalk->subscribe("2001/05/wk20") || die;
}

sub tear_down
{
    my ($self) = @_;
    $self->SUPER::tear_down();
}

#
# Test LSUB behaviour
#
sub test_list_percent
{
    my ($self) = @_;

    my $imaptalk = $self->{store}->get_client();

    my @inbox_flags = qw( \\HasNoChildren );
    my @inter_flags = qw( \\HasChildren );
    my ($maj, $min) = Cassandane::Instance->get_version();
    if ($maj < 3) {
        unshift @inbox_flags, qw( \\Noinferiors );
        unshift @inter_flags, qw( \\Noselect );
    }
    elsif ($maj == 3 && $min < 5) {
        unshift @inter_flags, qw( \\Noselect );
    }

    my $alldata = $imaptalk->list("", "%");
    $self->assert_deep_equals($alldata, [
          [
            \@inbox_flags,
            '/',
            'INBOX'
          ],
          [
            \@inter_flags,
            '/',
            '2001'
          ],
          [
            [
              '\\HasNoChildren'
            ],
            '/',
            'Drafts'
          ]
    ], "LIST data mismatch: "  . Dumper($alldata, \@inbox_flags));
}

#
# Test LSUB behaviour
#
sub test_list_2011
{
    my ($self) = @_;

    my $imaptalk = $self->{store}->get_client();

    my @inter_flags = qw( \\HasChildren );
    my ($maj, $min) = Cassandane::Instance->get_version();
    if ($maj < 3 || ($maj == 3 && $min < 5)) {
        unshift @inter_flags, qw( \\Noselect );
    }

    my $alldata = $imaptalk->list("", "2001");
    $self->assert_deep_equals($alldata, [
          [
            \@inter_flags,
            '/',
            '2001'
          ]
    ], "LIST data mismatch: "  . Dumper($alldata));
}

sub test_lsub
{
    my ($self) = @_;

    my $imaptalk = $self->{store}->get_client();

    my $alldata = $imaptalk->lsub("", "2001");
    $self->assert_deep_equals($alldata, [
          [
            [
              '\\Noselect',
              '\\HasChildren'
            ],
            '/',
            '2001'
          ]
    ], "LSUB data mismatch: "  . Dumper($alldata));
}

1;

#!/usr/bin/perl
#
#  Copyright (c) 2011-2023 FastMail Pty Ltd. All rights reserved.
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

package Cassandane::Cyrus::UIDonly;
use strict;
use warnings;
use DateTime;
use JSON;
use JSON::XS;
use Data::Dumper;
use Storable 'dclone';
use File::Basename;
use IO::File;

use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;

use charnames ':full';

sub new
{
    my ($class, @args) = @_;

    my $config = Cassandane::Config->default()->clone();

    $config->set(conversations => 'yes');

    my $self = $class->SUPER::new({
        config => $config,
        deliver => 1,
        adminstore => 1,
        services => [ 'imap', 'sieve' ]
    }, @args);

    $self->needs('component', 'sieve');
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

sub uidonly_cmd
{
    my $self = shift;
    my $imaptalk = shift;
    my $cmd = shift;

    my %fetched;
    my %handlers =
    (
        uidfetch => sub
        {
            my (undef, $items, $uid) = @_;

            if (ref($items) ne 'HASH') {
                # IMAPTalk < 4.06. Convert the key/value list into a hash
                my %hash;
                my $kvlist = $imaptalk->_next_atom();
                while (@$kvlist) {
                    my ($key, $val) = (shift @$kvlist, shift @$kvlist);
                    $hash{lc($key)} = $val;
                }
                $items = \%hash;
            }

            $fetched{$uid} = $items;
        },
    );

    $imaptalk->_imap_cmd($cmd, 0, \%handlers, @_);
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());

    return %fetched;
}

use Cassandane::Tiny::Loader 'tiny-tests/UIDonly';

1;

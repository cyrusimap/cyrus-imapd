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

package Cassandane::Cyrus::Nntp;
use strict;
use warnings;
use DateTime;
use News::NNTPClient;

use lib '.';
use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;
use Cassandane::Util::Words;

sub new
{
    my ($class, @args) = @_;
    return $class->SUPER::new({ gen => 0, services => ['nntp'] }, @args);
}

sub set_up
{
    my ($self) = @_;
    $self->SUPER::set_up();

    my $svc = $self->{instance}->get_service('nntp');
    if (defined $svc)
    {
        my $debug = get_verbose() ? 2 : 0;
        $self->{client} = new News::NNTPClient($svc->host(),
                                               $svc->port(),
                                               $debug);
        $self->{client}->authinfo('cassandane', 'testpw');
    }
}

sub tear_down
{
    my ($self) = @_;

    if (defined $self->{client})
    {
        $self->{client}->quit();
        $self->{client} = undef;
    }

    $self->SUPER::tear_down();
}

my $stack_slosh = 256;

sub test_cve_2011_3208_list_newsgroups
    :needs_component_nttpd
{
    my ($self) = @_;

    my $client = $self->{client};
    my $wildmat = '';
    while (length $wildmat < 1024+$stack_slosh)
    {
        $wildmat .= ($wildmat eq '' ? '' : '.');
        $wildmat .= random_word();
        $client->list('newsgroups', $wildmat);
        $self->assert_num_equals(215, $client->code());
        $self->assert($client->message() =~ m/List of newsgroups follows/i);
    }
}

sub test_cve_2011_3208_list_active
    :needs_component_nttpd
{
    my ($self) = @_;

    my $client = $self->{client};
    my $wildmat = '';
    while (length $wildmat < 1024+$stack_slosh)
    {
        $wildmat .= ($wildmat eq '' ? '' : '.');
        $wildmat .= random_word();
        $client->list('active', $wildmat);
        $self->assert_num_equals(215, $client->code());
        $self->assert($client->message() =~ m/List of newsgroups follows/i);
    }
}

    # The NEWNEWS command is disabled by default.
Cassandane::Cyrus::TestCase::magic(AllowNewNews => sub {
    shift->config_set(allownewnews => 1);
});

sub test_cve_2011_3208_newnews
    :AllowNewNews :needs_component_nttpd
{
    my ($self) = @_;

    my $client = $self->{client};
    my $wildmat = '';
    my $since = time() - 3600;
    while (length $wildmat < 1024+$stack_slosh)
    {
        $wildmat .= ($wildmat eq '' ? '' : '.');
        $wildmat .= random_word();
        $client->newnews($wildmat, $since);
        $self->assert_num_equals(230, $client->code());
        $self->assert($client->message() =~ m/List of new articles follows/i);
    }
}

1;

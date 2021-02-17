#!/usr/bin/perl
#
#  Copyright (c) 2011-2020 FastMail Pty Ltd. All rights reserved.
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

package Cassandane::Cyrus::SearchSquat;
use strict;
use warnings;
use Cwd qw(abs_path);
use DateTime;
use Data::Dumper;

use lib '.';
use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;

sub new
{
    my ($class, @args) = @_;
    my $config = Cassandane::Config->default()->clone();
    $config->set(conversations => 'on');
    return $class->SUPER::new({ config => $config }, @args);
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

# XXX version gated to 3.4+ for now to keep travis happy, but if we
# XXX backport the fix we should change or remove the gate...
sub test_simple
    :SearchEngineSquat :min_version_3_4
{
    my ($self) = @_;
    my $imap = $self->{store}->get_client();

    $self->make_message("term2", body => "term1") || die;
    $self->make_message("term2", body => "term1") || die;
    $self->make_message("term1", body => "term2") || die;
    $self->make_message("term3", body => "term4") || die;

    $self->{instance}->run_command({cyrus => 1}, 'squatter');

    my @tests = ({
        search => ['body', 'term1'],
        wantUids => [1,2],
    }, {
        search => ['text', 'term1'],
        wantUids => [1,2,3],
    }, {
        search => ['subject', 'term2'],
        wantUids => [1,2],
    }, {
        search => ['subject', 'term3'],
        wantUids => [4],
    }, {
        search => ['body', 'term4'],
        wantUids => [4],
    }, {
        search => ['fuzzy', 'body', 'term4'],
        wantUids => [4],
    });

    foreach (@tests) {
        $self->{instance}->getsyslog();

        my $uids = $imap->search(@{$_->{search}}) || die;
        $self->assert_deep_equals($_->{wantUids}, $uids);

        my @lines = $self->{instance}->getsyslog();
        $self->assert(grep /Squat run/, @lines);
    }
}

# XXX version gated to 3.4+ for now to keep travis happy, but if we
# XXX backport the fix we should change or remove the gate...
sub test_skip_unmodified_slow
    :SearchEngineSquat :min_version_3_4
{
    my ($self) = @_;
    my $imap = $self->{store}->get_client();

    $self->make_message() || die;

    sleep(1);

    $self->{instance}->getsyslog();
    $self->{instance}->run_command({cyrus => 1}, 'squatter');
    my @lines = $self->{instance}->getsyslog();
    $self->assert(not grep /Squat skipping mailbox/, @lines);

    $self->{instance}->getsyslog();
    $self->{instance}->run_command({cyrus => 1}, 'squatter', '-v', '-s', '0');
    @lines = $self->{instance}->getsyslog();
    $self->assert(grep /Squat skipping mailbox/, @lines);
}

1;

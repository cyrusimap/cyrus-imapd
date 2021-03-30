#!/usr/bin/perl
#
#  Copyright (c) 2011-2019 FastMail Pty Ltd. All rights reserved.
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

package Cassandane::Cyrus::Create;
use strict;
use warnings;
use Data::Dumper;

use lib '.';
use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;
use Cassandane::Instance;

$Data::Dumper::Sortkeys = 1;

sub new
{
    my $class = shift;
    return $class->SUPER::new({ adminstore => 1 }, @_);
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

sub test_bad_userids
{
    my ($self) = @_;

    my $admintalk = $self->{adminstore}->get_client();

    my @bad_userids = (
        'user',
        'user.anyone',
        'user.anonymous',
        'user.%SHARED',
        #'user..foo', # silently fixed by namespace conversion
    );

    foreach my $u (@bad_userids) {
        $admintalk->create($u);
        $self->assert_str_equals('no',
            $admintalk->get_last_completion_response());
    }
}

sub test_bad_userids_unixhs
    :UnixHierarchySep
{
    my ($self) = @_;

    my $admintalk = $self->{adminstore}->get_client();

    my @bad_userids = (
        'user',
        'user/anyone',
        'user/anonymous',
        'user/%SHARED',
        #'user//foo', # silently fixed by namespace conversion
    );

    foreach my $u (@bad_userids) {
        $admintalk->create($u);
        $self->assert_str_equals('no',
            $admintalk->get_last_completion_response());
    }
}

sub test_good_userids
{
    my ($self) = @_;

    my $admintalk = $self->{adminstore}->get_client();

    my @good_userids = (
        'user.$RACL',
    );

    foreach my $u (@good_userids) {
        $admintalk->create($u);
        $self->assert_str_equals('ok',
            $admintalk->get_last_completion_response());
    }
}

sub test_good_userids_unixhs
    :UnixHierarchySep
{
    my ($self) = @_;

    my $admintalk = $self->{adminstore}->get_client();

    my @good_userids = (
        'user/$RACL',
        'user/.foo', # with unixhs, this is not a double-sep!
    );

    foreach my $u (@good_userids) {
        $admintalk->create($u);
        $self->assert_str_equals('ok',
            $admintalk->get_last_completion_response());
    }
}

sub test_bad_mailboxes
{
    my ($self) = @_;

    my $admintalk = $self->{adminstore}->get_client();

    my @bad_mailboxes = (
        '$RACL',
        '$RACL$U$anyone$user.foo',
        'domain.com!user.foo', # virtdomains=off
        #'user.cassandane..blah', # silently fixed by namespace conversion
    );

    foreach my $m (@bad_mailboxes) {
        $admintalk->create($m);
        $self->assert_str_equals('no',
            $admintalk->get_last_completion_response());
    }
}

sub test_good_mailboxes_unixhs
    :UnixHierarchySep
{
    my ($self) = @_;

    my $admintalk = $self->{adminstore}->get_client();

    my @good_mailboxes = (
        'user/cassandane/$RACL',
        'user/cassandane/.foo', # with unixhs, this is not a double-sep!
        'user/foo.',
        'user/foo./bar', # with unixhs, this is not a double-sep!
    );

    foreach my $m (@good_mailboxes) {
        $admintalk->create($m);
        $self->assert_str_equals('ok',
            $admintalk->get_last_completion_response());
    }
}

sub test_good_mailboxes_virtdomains
    :VirtDomains
{
    my ($self) = @_;

    my $admintalk = $self->{adminstore}->get_client();

    my @good_mailboxes = (
        'user.cassandane.$RACL',
        'user.foo@domain.com',
    );

    foreach my $m (@good_mailboxes) {
        $admintalk->create($m);
        $self->assert_str_equals('ok',
            $admintalk->get_last_completion_response());
    }
}

1;

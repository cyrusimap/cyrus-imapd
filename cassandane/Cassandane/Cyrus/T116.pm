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

package Cassandane::Cyrus::T116;
use strict;
use warnings;

use lib '.';
use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;
use Cassandane::Instance;

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

Cassandane::Cyrus::TestCase::magic(T116 => sub {
    my ($testcase) = @_;
    $testcase->config_set(virtdomains => 'userid');
});

sub test_list_inbox
    :T116
{
    my ($self) = @_;
    my $adminstore = $self->{adminstore};
    my $admintalk = $adminstore->get_client();

    xlog $self, "Test Cyrus extension which renames a user to a different partition";

    # create and prepare the user
    $admintalk->create('user.test@inbox.com');
    $admintalk->setacl('user.test@inbox.com', 'admin', 'lrswipkxtecda');

    $admintalk->create('user.test@inbox2.com');
    $admintalk->setacl('user.test@inbox2.com', 'admin', 'lrswipkxtecda');

    my @list = $admintalk->list('', '*');
    my @items = sort map { $_->[2] } @list;
    $self->assert_deep_equals(\@items, ['user.cassandane', 'user.test@inbox.com', 'user.test@inbox2.com']);
}

1;

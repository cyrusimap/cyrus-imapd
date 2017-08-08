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

package Cassandane::Cyrus::Expunge;
use strict;
use warnings;

use lib '.';
use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;

sub new
{
    my ($class, @args) = @_;
    return $class->SUPER::new({ adminstore => 1 }, @args);
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

sub test_status_after_expunge
{
    my ($self, $folder, %params) = @_;

    my $store = $self->{store};
    my $talk = $store->get_client();

    my $subfolder = 'INBOX.foo';

    xlog "First create a sub folder";
    $talk->create($subfolder)
	or die "Cannot create folder $subfolder: $@";
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    xlog "Generate messages in $subfolder";
    $store->set_folder($subfolder);
    $store->_select();
    for (1..5) {
	$self->make_message("Message $subfolder $_");
    }
    $talk->unselect();
    $talk->select($subfolder);

    my $stat = $talk->status($subfolder, '(highestmodseq unseen messages)');
    $self->assert_equals(5, $stat->{unseen});
    $self->assert_equals(5, $stat->{messages});

    $talk->store('1,3,5', '+flags', '(\\Seen)');

    $stat = $talk->status($subfolder, '(highestmodseq unseen messages)');
    $self->assert_equals(2, $stat->{unseen});
    $self->assert_equals(5, $stat->{messages});

    $talk->store('1:*', '+flags', '(\\Deleted \\Seen)');
    $talk->expunge();

    $stat = $talk->status($subfolder, '(highestmodseq unseen messages)');
    $self->assert_equals(0, $stat->{unseen});
    $self->assert_equals(0, $stat->{messages});
}

1;

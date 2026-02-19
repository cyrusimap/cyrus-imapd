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

package Cassandane::Cyrus::Objectid;
use strict;
use warnings;
use DateTime;
use Data::Dumper;

use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;
use Cassandane::Generator;
use Cassandane::MessageStoreFactory;
use Cassandane::Instance;

sub new
{
    my $class = shift;
    return  $class->SUPER::new({adminstore => 1}, @_);
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

use Cassandane::Tiny::Loader;

#
# Test uniqueid and rename
#
sub test_objectidbis
    :AltNamespace :Conversations :min_version_3_1
{
    my ($self) = @_;

    my $admintalk = $self->{adminstore}->get_client();

    # sub folders of another user - one is subscribable
    $self->{instance}->create_user("other",
                                   subdirs => [ 'sub', ['sub', 'folder'] ]);
    $admintalk->setacl("user.other.sub.folder", "cassandane", "lrswipkxtecdan");

    my $talk = $self->{store}->get_client();

    $talk->create('foo');
    $talk->select('foo');
    my $status1 = $talk->status('foo', "(mailboxid)");
    $talk->enable('objectidbis');
    $talk->create('bar');
    $talk->select('bar');
    my $status2 = $talk->status('bar', "(mailboxid accountid)");
    my $status3 = $talk->status('bar', "(objectid)");

    $talk->rename('foo', 'renamed');
    my $status3 = $talk->status('renamed', "(mailboxid)");
    my $status4 = $talk->status('bar', "(mailboxid)");

    $self->assert_str_equals($status1->{mailboxid}[0], $status3->{mailboxid}[0]);
    $self->assert_str_equals($status2->{mailboxid}[0], $status4->{mailboxid}[0]);

    $talk->list('', '*', 'return', [ "status", [ "mailboxid", "accountid", "objectid" ] ]);
}

1;

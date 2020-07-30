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

package Cassandane::Cyrus::Lsub;
use strict;
use warnings;
use DateTime;
use Data::Dumper;

use lib '.';
use base qw(Cassandane::Cyrus::TestCase);

sub new
{
    my $class = shift;
    return $class->SUPER::new({ adminstore => 1 }, @_);
}

sub set_up
{
    my ($self) = @_;
    $self->SUPER::set_up();

    my $admintalk = $self->{adminstore}->get_client();

    # Right - let's create ourselves some users and subscriptions
    # sub folders of the main user
    $admintalk->create("user.cassandane.asub");
    $admintalk->create("user.cassandane.asub.deeper");

    # sub folders of another user - one is subscribable
    $self->{instance}->create_user("other",
                                   subdirs => [ 'sub', ['sub', 'folder'] ]);
    $admintalk->setacl("user.other.sub.folder", "cassandane", "lrs");

    my $usertalk = $self->{store}->get_client();
    $usertalk->subscribe("INBOX");
    $usertalk->subscribe("INBOX.asub");
    $usertalk->subscribe("user.other.sub.folder");
}

sub tear_down
{
    my ($self) = @_;
    $self->SUPER::tear_down();
}

#
# Test LSUB behaviour
#
sub test_lsub_toplevel
    :NoAltNameSpace
{
    my ($self) = @_;

    my $imaptalk = $self->{store}->get_client();

    my $alldata = $imaptalk->lsub("", "*");
    $self->assert_deep_equals($alldata, [
          [
            [
              '\\HasChildren'
            ],
            '.',
            'INBOX'
          ],
          [
            [],
            '.',
            'INBOX.asub'
          ],
          [
            [],
            '.',
            'user.other.sub.folder'
          ]
    ], "LSUB all data mismatch: "  . Dumper($alldata));

    my $topdata = $imaptalk->lsub("", "%");
    $self->assert_deep_equals($topdata, [
          [
            [
              '\\HasChildren'
            ],
            '.',
            'INBOX'
          ],
          [
            [
              '\\Noselect',
              '\\HasChildren'
            ],
            '.',
            'user'
          ],
    ], "LSUB top data mismatch:" . Dumper($topdata));
}

sub test_lsub_delete
{
    my ($self) = @_;

    my $imaptalk = $self->{store}->get_client();

    $imaptalk->create("INBOX.deltest") || die;
    $imaptalk->create("INBOX.deltest.sub1") || die;
    $imaptalk->create("INBOX.deltest.sub2") || die;
    $imaptalk->subscribe("INBOX.deltest") || die;
    $imaptalk->subscribe("INBOX.deltest.sub2") || die;
    my $subdata = $imaptalk->lsub("INBOX.deltest", "*");
    $self->assert_deep_equals($subdata, [
          [
            [
              '\\HasChildren'
            ],
            '.',
            'INBOX.deltest'
          ],
          [
            [],
            '.',
            'INBOX.deltest.sub2'
          ],
    ], "LSUB deltest setup mismatch: " . Dumper($subdata));

    $imaptalk->delete("INBOX.deltest.sub2");
    my $onedata = $imaptalk->lsub("INBOX.deltest", "*");
    $self->assert_deep_equals($onedata, [
          [
            [
              '\\HasChildren'
            ],
            '.',
            'INBOX.deltest'
          ],
    ], "LSUB deltest.sub2 after delete mismatch: " . Dumper($onedata));
}

sub test_lsub_extrachild
    :NoAltNameSpace
{
    my ($self) = @_;

    my $imaptalk = $self->{store}->get_client();

    $imaptalk->create("INBOX.Test") || die;
    $imaptalk->create("INBOX.Test.Sub") || die;
    $imaptalk->create("INBOX.Test Foo") || die;
    $imaptalk->create("INBOX.Test Bar") || die;
    $imaptalk->subscribe("INBOX.Test") || die;
    $imaptalk->subscribe("INBOX.Test.Sub") || die;
    $imaptalk->subscribe("INBOX.Test Foo") || die;
    $imaptalk->delete("INBOX.Test.Sub") || die;
    my $subdata = $imaptalk->lsub("", "*");
    $self->assert_deep_equals($subdata, [
          [
            [
              '\\HasChildren'
            ],
            '.',
            'INBOX'
          ],
          [
            [
              '\\HasChildren'
            ],
            '.',
            'INBOX.Test'
          ],
          [
            [],
            '.',
            'INBOX.Test Foo'
          ],
          [
            [],
            '.',
            'INBOX.asub'
          ],
          [
            [],
            '.',
            'user.other.sub.folder'
          ],
    ], "LSUB extrachild mismatch: " . Dumper($subdata));
}

1;

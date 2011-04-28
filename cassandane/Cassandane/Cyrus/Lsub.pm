#!/usr/bin/perl
#
#  Copyright (c) 2011 Opera Software Australia Pty. Ltd.  All rights
#  reserved.
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
#  3. The name "Opera Software Australia" must not be used to
#     endorse or promote products derived from this software without
#     prior written permission. For permission or any legal
#     details, please contact
# 	Opera Software Australia Pty. Ltd.
# 	Level 50, 120 Collins St
# 	Melbourne 3000
# 	Victoria
# 	Australia
#
#  4. Redistributions of any form whatsoever must retain the following
#     acknowledgment:
#     "This product includes software developed by Opera Software
#     Australia Pty. Ltd."
#
#  OPERA SOFTWARE AUSTRALIA DISCLAIMS ALL WARRANTIES WITH REGARD TO
#  THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
#  AND FITNESS, IN NO EVENT SHALL OPERA SOFTWARE AUSTRALIA BE LIABLE
#  FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
#  WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
#  AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
#  OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#

use strict;
use warnings;
package Cassandane::Cyrus::Lsub;
use base qw(Test::Unit::TestCase);
use DateTime;
use Cassandane::Util::Log;
use Cassandane::Generator;
use Cassandane::MessageStoreFactory;
use Cassandane::Instance;
use Data::Dumper;

sub new
{
    my $class = shift;
    my $self = $class->SUPER::new(@_);

    $self->{instance} = Cassandane::Instance->new();
    $self->{instance}->add_service('imap');

    $self->{gen} = Cassandane::Generator->new();

    return $self;
}

sub set_up
{
    my ($self) = @_;

    $self->{instance}->start();
    $self->{store} = $self->{instance}->get_service('imap')->create_store();
    $self->{adminstore} = $self->{instance}->get_service('imap')->create_store(username => 'admin');

    my $admintalk = $self->{adminstore}->get_client();

    # Right - let's create ourselves some users and subscriptions
    # sub folders of the main user
    $admintalk->create("user.cassandane.asub");
    $admintalk->create("user.cassandane.asub.deeper");

    # sub folders of another user - one is subscribable
    $admintalk->create("user.other") || die "can't create user.other";
    $admintalk->create("user.other.sub");
    $admintalk->create("user.other.sub.folder");
    $admintalk->setacl("user.other.sub.folder", "cassandane", "lrs");

    my $usertalk = $self->{store}->get_client();
    $usertalk->subscribe("INBOX");
    $usertalk->subscribe("INBOX.asub");
    $usertalk->subscribe("user.other.sub.folder");
}

sub tear_down
{
    my ($self) = @_;

    $self->{store}->disconnect()
	if defined $self->{store};
    $self->{store} = undef;
    $self->{adminstore}->disconnect()
	if defined $self->{adminstore};
    $self->{adminstore} = undef;
    $self->{instance}->stop();
}

#
# Test LSUB behaviour
#
sub test_lsub_toplevel
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

    $imaptalk->delete("INBOX.deltest");
    my $onedata = $imaptalk->lsub("INBOX.deltest", "*");
    $self->assert_deep_equals($onedata, [
          [
            [],
            '.',
            'INBOX.deltest.sub2'
          ],
    ], "LSUB deltest setup mismatch: " . Dumper($onedata));


    $imaptalk->delete("INBOX.deltest.sub2");
    my $nodata = $imaptalk->lsub("INBOX.deltest", "*");
    $nodata = [] unless ref($nodata); # dammit Completed return
    $self->assert_deep_equals($nodata, [
    ], "LSUB deltest after delete mismatch: " . Dumper($nodata));

}

1;

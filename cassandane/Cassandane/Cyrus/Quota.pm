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
package Cassandane::Cyrus::Quota;
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

    # Right - let's set ourselves a basic usage quota
    $admintalk->setquota("user.cassandane", "(storage 100000)") || die "Failed $@";
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

sub make_message
{
    my ($self, $subject, @attrs) = @_;

    $self->{store}->write_begin();
    my $msg = $self->{gen}->generate(subject => $subject, @attrs);
    $self->{store}->write_message($msg);
    $self->{store}->write_end();

    return $msg;
}

#
# Test renames
#
sub test_quotarename
{
    my ($self) = @_;

    my $admintalk = $self->{adminstore}->get_client();
    my $imaptalk = $self->{store}->get_client();

    my @res = $admintalk->getquota("user.cassandane");
    $self->assert_num_equals(3, scalar @res);
    $self->assert_num_equals(0, $res[1]);

    for (1..10) {
	$self->make_message("Message $_", extra_lines => 5000);
    }

    @res = $admintalk->getquota("user.cassandane");

    my $base_usage = $res[1];
    $self->assert_num_not_equals(0, $base_usage, "10 messages should use some quota");

    $imaptalk->create("INBOX.sub") || die;
    $imaptalk->select($self->{store}->{folder}) || die;
    $imaptalk->copy("1:5", "INBOX.sub") || die;
    $imaptalk->select("INBOX.sub") || die;

    @res = $admintalk->getquota("user.cassandane");
    $self->assert_num_equals(3, scalar @res);

    my $more_usage = $res[1];
    $self->assert_num_not_equals($base_usage, $more_usage, "another 15 messages should use more quota");

    $imaptalk->rename("INBOX.sub", "INBOX.othersub") || die;
    $imaptalk->select("INBOX.othersub") || die;

    # usage should be the same after a rename
    @res = $admintalk->getquota("user.cassandane");
    $self->assert_num_equals($more_usage, $res[1], "Usage should be unchanged after a rename");

    $imaptalk->delete("INBOX.othersub") || die;

    @res = $admintalk->getquota("user.cassandane");
    $self->assert_num_equals($base_usage, $res[1], "Usage should drop back after a delete");
}

1;

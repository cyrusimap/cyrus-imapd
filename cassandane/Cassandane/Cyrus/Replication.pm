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
package Cassandane::Cyrus::Replication;
use base qw(Test::Unit::TestCase);
use DateTime;
use Cassandane::Util::Log;
use Cassandane::Generator;
use Cassandane::Instance;
use Cassandane::Service;
use Cassandane::Config;

sub new
{
    my $class = shift;
    my $self = $class->SUPER::new(@_);

    $self->{gen} = Cassandane::Generator->new();

    return $self;
}

sub set_up
{
    my ($self) = @_;

    my ($master, $replica, $master_store, $replica_store) =
	Cassandane::Instance->start_replicated_pair();
    $self->{master} = $master;
    $self->{master_store} = $master_store;
    $self->{replica} = $replica;
    $self->{replica_store} = $replica_store;

    $self->{expected} = {};
}

sub tear_down
{
    my ($self) = @_;

    $self->{master_store}->disconnect()
	if defined $self->{master_store};
    $self->{master_store} = undef;

    $self->{replica_store}->disconnect()
	if defined $self->{replica_store};
    $self->{replica_store} = undef;

    $self->{master}->stop();
    $self->{replica}->stop();
}

sub make_message
{
    my ($self, $subject, %params) = @_;

    my $store = $params{store} || $self->{master_store};
    delete $params{store};

    $store->write_begin();
    my $msg = $self->{gen}->generate(subject => $subject, %params);
    $store->write_message($msg);
    $store->write_end();

    return $msg;
}

sub check_messages
{
    my ($self, $store, $expected) = @_;
    my $actual = {};

    $store->read_begin();
    while (my $msg = $store->read_message())
    {
	my $subj = $msg->get_header('subject');
	$self->assert(!defined $actual->{$subj});
	$actual->{$subj} = $msg;
    }
    $store->read_end();

    $self->assert(scalar keys %$actual == scalar keys %$expected);

    foreach my $expmsg (values %$expected)
    {
	my $subj = $expmsg->get_header('subject');
	my $actmsg = $actual->{$subj};

	$self->assert(defined $actmsg);

	$self->assert(defined $actmsg->get_header('x-cassandane-unique'));

	$self->assert($actmsg->get_header('x-cassandane-unique') eq
		      $expmsg->get_header('x-cassandane-unique'));
    }

    return $actual;
}

sub run_replication
{
    my ($self) = @_;

    Cassandane::Instance->run_replication($self->{master},
					  $self->{replica},
					  $self->{master_store},
					  $self->{replica_store});
}

#
# Test replication of messages APPENDed to the master
#
sub test_append
{
    my ($self) = @_;

    xlog "generating messages A..D";
    my $expected;
    $expected->{A} = $self->make_message("Message A");
    $expected->{B} = $self->make_message("Message B");
    $expected->{C} = $self->make_message("Message C");
    $expected->{D} = $self->make_message("Message D");

    xlog "Before replication, the master should have all four messages";
    $self->check_messages($self->{master_store}, $expected);
    xlog "Before replication, the replica should have no messages";
    $self->check_messages($self->{replica_store}, {});

    $self->run_replication();

    xlog "After replication, the master should still have all four messages";
    $self->check_messages($self->{master_store}, $expected);
    xlog "After replication, the replica should now have all four messages";
    $self->check_messages($self->{replica_store}, $expected);
}

1;

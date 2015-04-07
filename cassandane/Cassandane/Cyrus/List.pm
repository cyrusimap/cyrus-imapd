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
package Cassandane::Cyrus::List;
use base qw(Cassandane::Unit::TestCase);
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

    my $config = Cassandane::Config->default()->clone();
    $config->set(altimap_virtdomains => 'userid');
    $config->set(altimap_unixhierarchysep => 'on');
    $config->set(altimap_altnamespace => 'yes');
    $self->{instance} = Cassandane::Instance->new(config => $config);
    $self->{instance}->add_service(name => 'imap');
    $self->{instance}->add_service(name => 'altimap');

    $self->{gen} = Cassandane::Generator->new();

    return $self;
}

# tests based on rfc 5258 examples:
# https://tools.ietf.org/html/rfc5258#section-5

sub _install_test_data
{
    my ($self, $test_data) = @_;

    my $imaptalk = $self->{store}->get_client();

    foreach my $row (@{$test_data}) {
	my ($cmd, $arg) = @{$row};
	if (ref $arg) {
	    foreach (@{$arg}) {
		$imaptalk->$cmd($_) || die;
	    }
	}
	else {
	    $imaptalk->$cmd($arg) || die;
	}
    }
}

sub set_up
{
    my ($self) = @_;

    $self->{instance}->start();
    $self->{store} = $self->{instance}->get_service('altimap')->create_store();
}

sub tear_down
{
    my ($self) = @_;

    $self->{store}->disconnect()
	if defined $self->{store};
    $self->{store} = undef;
    $self->{instance}->stop();
    $self->{instance}->cleanup();
    $self->{instance} = undef;
}

sub test_imap4_list_all
{
    my ($self) = @_;

    $self->_install_test_data([
	[ 'subscribe' => 'INBOX' ],
	[ 'create' => [qw( Fruit Fruit/Apple Fruit/Banana Fruit/Peach)] ],
	[ 'subscribe' => [qw( Fruit/Banana Fruit/Peach )] ],
	[ 'delete' => 'Fruit/Peach' ],
	[ 'create' => [qw( Tofu Vegetable Vegetable/Broccoli Vegetable/Corn )] ],
	[ 'subscribe' => [qw( Vegetable Vegetable/Broccoli )] ],
    ]);

    my $imaptalk = $self->{store}->get_client();

    my $alldata = $imaptalk->list("", "*");

    $self->assert_deep_equals($alldata, [
	[
	    [
		'\\Noinferiors',
		'\\HasNoChildren'
	    ],
	    '/',
	    'INBOX'
	],
	[
	    [
		'\\HasChildren',
	    ],
	    '/',
	    'Fruit',
	],
	[
	    [
		'\\HasNoChildren'
	    ],
	    '/',
	    'Fruit/Apple',
	],
	[
	    [
		'\\HasNoChildren'
	    ],
	    '/',
	    'Fruit/Banana',
	],
	[
	    [
		'\\HasNoChildren'
	    ],
	    '/',
	    'Tofu',
	],
	[
	    [
		'\\HasChildren',
	    ],
	    '/',
	    'Vegetable',
	],
	[
	    [
		'\\HasNoChildren'
	    ],
	    '/',
	    'Vegetable/Broccoli',
	],
	[
	    [
		'\\HasNoChildren'
	    ],
	    '/',
	    'Vegetable/Corn',
	],
    ], "LIST data mismatch: "  . Dumper($alldata));
}

sub test_5258_list_subscribed
{
    my ($self) = @_;

    $self->_install_test_data([
	[ 'subscribe' => 'INBOX' ],
	[ 'create' => [qw( Fruit Fruit/Apple Fruit/Banana Fruit/Peach)] ],
	[ 'subscribe' => [qw( Fruit/Banana Fruit/Peach )] ],
	[ 'delete' => 'Fruit/Peach' ],
	[ 'create' => [qw( Tofu Vegetable Vegetable/Broccoli Vegetable/Corn )] ],
	[ 'subscribe' => [qw( Vegetable Vegetable/Broccoli )] ],
    ]);

    my $imaptalk = $self->{store}->get_client();

    my $subdata = $imaptalk->list([qw(SUBSCRIBED)], "", "*");

    $self->assert_deep_equals($subdata, [
	[
	    [
		'\\Noinferiors',
		'\\Subscribed',
	    ],
	    '/',
	    'INBOX'
	],
	[
	    [
		'\\Subscribed',
	    ],
	    '/',
	    'Fruit/Banana',
	],
	[
	    [
		'\\NonExistent',
		'\\Subscribed',
	    ],
	    '/',
	    'Fruit/Peach',
	],
	[
	    [
		'\\Subscribed',
		'\\HasChildren', # not required by spec, but cyrus tells us
	    ],
	    '/',
	    'Vegetable',
	],
	[
	    [
		'\\Subscribed',
	    ],
	    '/',
	    'Vegetable/Broccoli',
	],
    ], "LIST data mismatch: "  . Dumper($subdata));
}

sub test_5258_children
{
    my ($self) = @_;

    $self->_install_test_data([
	[ 'subscribe' => 'INBOX' ],
	[ 'create' => [qw( Fruit Fruit/Apple Fruit/Banana Fruit/Peach)] ],
	[ 'subscribe' => [qw( Fruit/Banana Fruit/Peach )] ],
	[ 'delete' => 'Fruit/Peach' ],
	[ 'create' => [qw( Tofu Vegetable Vegetable/Broccoli Vegetable/Corn )] ],
	[ 'subscribe' => [qw( Vegetable Vegetable/Broccoli )] ],
    ]);

    my $imaptalk = $self->{store}->get_client();

    my $data = $imaptalk->list(
	[qw()], "", "%", 'RETURN', [qw(CHILDREN)],
    );

    $self->assert_deep_equals($data, [
	[
	    [
		'\\Noinferiors',
	    ],
	    '/',
	    'INBOX'
	],
	[
	    [
		'\\HasChildren',
	    ],
	    '/',
	    'Fruit'
	],
	[
	    [
		'\\HasNoChildren',
	    ],
	    '/',
	    'Tofu'
	],
	[
	    [
		'\\HasChildren',
	    ],
	    '/',
	    'Vegetable'
	],
    ], "LIST data mismatch: "  . Dumper($data));
}

# TODO not sure how to set up test data for remote mailboxes...
#sub test_5258_remote_children
#{
#    my ($self) = @_;
#    $self->assert(0, 'FIXME test not implemented');
#}

#sub test_5258_remote_subscribed
#{
#    my ($self) = @_;
#    $self->assert(0, 'FIXME test not implemented');
#}

#sub test_5258_remote_return_subscribed
#{
#    my ($self) = @_;
#    $self->assert(0, 'FIXME test not implemented');
#}

1;

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

# tests based on rfc 5258 examples:
# https://tools.ietf.org/html/rfc5258#section-5

use strict;
use warnings;
package Cassandane::Cyrus::List;
use base qw(Cassandane::Cyrus::TestCase);
use DateTime;
use Cassandane::Util::Log;
use Cassandane::Generator;
use Cassandane::MessageStoreFactory;
use Cassandane::Instance;
use Data::Dumper;

sub new
{
    my ($class, @args) = @_;

    my $config = Cassandane::Config->default()->clone();
    $config->set(virtdomains => 'userid');
    $config->set(unixhierarchysep => 'on');
    $config->set(altnamespace => 'yes');

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

sub _assert_list_data
{
    my ($self, $actual, $expected_hiersep, $expected_mailbox_flags, $msg) = @_;

    # rearrange list output into order-agnostic format
    my %actual_hash;
    foreach my $row (@{$actual}) {
        my ($flags, $hiersep, $mailbox) = @{$row};

        $actual_hash{$mailbox} = {
            flags => join(q{ }, sort @{$flags} ),
            hiersep => $hiersep,
            mailbox => $mailbox,
        }
    }

    # check that expected data exists
    foreach my $mailbox (keys %{$expected_mailbox_flags}) {
        xlog "expect mailbox: $mailbox";
        $self->assert(
            exists $actual_hash{$mailbox},
            "$mailbox: mailbox not found"
        );

        $self->assert_str_equals(
            $actual_hash{$mailbox}->{hiersep},
            $expected_hiersep,
            "$mailbox: got hierarchy separator '"
                . $actual_hash{$mailbox}->{hiersep}
                . "', expected '$expected_hiersep'"
        );

        my $expected_flag_str;
        if (ref $expected_mailbox_flags->{$mailbox}) {
            $expected_flag_str = join q{ }, sort @{$expected_mailbox_flags->{$mailbox}};
        }
        else {
            $expected_flag_str = $expected_mailbox_flags->{$mailbox};
        }

        $self->assert_str_equals(
            $actual_hash{$mailbox}->{flags},
            $expected_flag_str,
            "$mailbox: got flags '"
                . $actual_hash{$mailbox}->{flags}
                . "', expected '$expected_flag_str'"
        )
    }

    # check that unexpected data does not exist
    foreach my $mailbox (keys %actual_hash) {
        $self->assert(
            exists $expected_mailbox_flags->{$mailbox},
            "$mailbox: found unexpected extra mailbox"
        );
    }
}

sub test_5258_01_list_all
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

    $self->_assert_list_data($alldata, '/', {
        'INBOX'                 => [qw( \\Noinferiors \\HasNoChildren )],
        'Fruit'                 => [qw( \\HasChildren )],
        'Fruit/Apple'           => [qw( \\HasNoChildren )],
        'Fruit/Banana'          => [qw( \\HasNoChildren )],
        'Tofu'                  => [qw( \\HasNoChildren )],
        'Vegetable'             => [qw( \\HasChildren )],
        'Vegetable/Broccoli'    => [qw( \\HasNoChildren )],
        'Vegetable/Corn'        => [qw( \\HasNoChildren )],
    });
}

sub test_5258_02_list_subscribed
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

    xlog(Dumper $subdata);
    $self->_assert_list_data($subdata, '/', {
        'INBOX'                 => [qw( \\Noinferiors \\Subscribed )],
        'Fruit/Banana'          => '\\Subscribed',
        'Fruit/Peach'           => [qw( \\NonExistent \\Subscribed )],
        'Vegetable'             => [qw( \\Subscribed \\HasChildren )], # HasChildren not required by spec, but cyrus tells us
        'Vegetable/Broccoli'    => '\\Subscribed',
    });
}

sub test_5258_03_children
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

    $self->_assert_list_data($data, '/', {
        'INBOX' => [ '\\Noinferiors' ],
        'Fruit' => [ '\\HasChildren' ],
        'Tofu'  => [ '\\HasNoChildren' ],
        'Vegetable' => [ '\\HasChildren' ],
    });
}

# TODO not sure how to set up test data for remote mailboxes...
#sub test_5258_04_remote_children
#{
#    my ($self) = @_;
#    $self->assert(0, 'FIXME test not implemented');
#}

#sub test_5258_05_remote_subscribed
#{
#    my ($self) = @_;
#    $self->assert(0, 'FIXME test not implemented');
#}

#sub test_5258_06_remote_return_subscribed
#{
#    my ($self) = @_;
#    $self->assert(0, 'FIXME test not implemented');
#}

sub test_5258_07_multiple_mailbox_patterns
{
    my ($self) = @_;

    $self->_install_test_data([
	[ 'create' => 'Drafts' ],
	[ 'create' => [qw(
	    Sent Sent/March2004 Sent/December2003 Sent/August2004
	)] ],
	[ 'create' => [qw( Unlisted Unlisted/Foo )] ],
    ]);

    my $imaptalk = $self->{store}->get_client();

    my $data = $imaptalk->list("", [qw( INBOX Drafts Sent/% )]);

    $self->_assert_list_data($data, '/', {
        'INBOX' => [ '\\Noinferiors' ],
        'Drafts' => [],
        'Sent/August2004' => [ '\\HasNoChildren' ],
        'Sent/December2003' => [ '\\HasNoChildren' ],
        'Sent/March2004' => [], # FIXME why is this missing \HasNoChildren?
    });
}

sub test_5258_08_haschildren_childinfo
{
    my ($self) = @_;

    $self->_install_test_data([
        [ 'create' => [qw( Foo Foo/Bar Foo/Baz Moo )] ],
    ]);

    my $imaptalk = $self->{store}->get_client();

    my $data = $imaptalk->list("", "%", "RETURN", [qw( CHILDREN )]);

    $self->_assert_list_data($data, '/', {
        'INBOX' => '\\Noinferiors',
        'Foo'   => '\\HasChildren',
        'Moo'   => '\\HasNoChildren',
    });

    $self->_install_test_data([
        [ 'subscribe' => 'Foo/Baz' ],
    ]);

    $data = $imaptalk->list(['SUBSCRIBED'], "", "*");

    $self->_assert_list_data($data, '/', {
        'Foo/Baz'   => '\\Subscribed',
    });

    $data = $imaptalk->list(['SUBCRIBED'], "", "%");

    $self->_assert_list_data($data, '/', {
    });

    $data = $imaptalk->list([qw( SUBSCRIBED RECURSIVEMATCH )], "", "%");
    xlog(Dumper $data);

    $self->_assert_list_data($data, '/', {
        'Foo' => [],
    });

    # TODO a bunch more to test here...
    $self->assert(0, 'FIXME more to test here...');
}

sub test_5258_09_childinfo
{
    my ($self) = @_;
    $self->assert(0, 'FIXME test not implemented');
}

sub test_5258_10_multiple_mailbox_patterns_childinfo
{
    my ($self) = @_;
    $self->assert(0, 'FIXME test not implemented');
}

sub test_5258_11_missing_hierarchy_elements
{
    my ($self) = @_;
    $self->assert(0, 'FIXME test not implemented');
}

1;

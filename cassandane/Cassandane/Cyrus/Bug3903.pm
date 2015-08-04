#!/usr/bin/perl
#
#  Copyright (c) 2015 Opera Software Australia Pty. Ltd.  All rights
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
package Cassandane::Cyrus::Bug3903;
use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;

sub new
{
    my $class = shift;
    my $config = Cassandane::Config->default()->clone();
    $config->set(autocreate_quota => 101200);
    return $class->SUPER::new({
	config => $config,
	adminstore => 1,
    }, @_);
}

sub set_up
{
    my ($self) = @_;
    $self->SUPER::set_up();

    $self->{instance}->create_user("foo",
				   subdirs => [ 'cassandane', ['cassandane', 'sent'] ]);

    my $admintalk = $self->{adminstore}->get_client();
    $admintalk->setacl("user.foo.cassandane.sent", "cassandane", "lrswp");
}

sub tear_down
{
    my ($self) = @_;
    $self->SUPER::tear_down();
}

sub test_create_under_wrong_user
{
    my ($self) = @_;

    my $talk = $self->{store}->get_client();

    my $res = $talk->create('user.foo.cassandane.sent.Test1');
    $self->assert_null($res); # means it failed
    $self->assert_str_equals('no', $talk->get_last_completion_response());
    $self->assert($talk->get_last_error() =~ m/permission denied/i);

    $res = $talk->create('user.foo.cassandane.Test2');
    $self->assert_null($res); # means it failed
    $self->assert_str_equals('no', $talk->get_last_completion_response());
    $self->assert($talk->get_last_error() =~ m/permission denied/i);

    $res = $talk->create('user.foo.Test3');
    $self->assert_null($res); # means it failed
    $self->assert_str_equals('no', $talk->get_last_completion_response());
    $self->assert($talk->get_last_error() =~ m/permission denied/i);
}

sub test_create_under_user
{
    my ($self) = @_;

    my $talk = $self->{store}->get_client();

    my $res = $talk->create('user.Test4');
    $self->assert_null($res); # means it failed
    $self->assert_str_equals('no', $talk->get_last_completion_response());
    $self->assert($talk->get_last_error() =~ m/permission denied/i);

}

sub test_create_under_shared
{
    my ($self) = @_;

    my $talk = $self->{store}->get_client();

    my $res = $talk->create('shared.Test5');
    $self->assert_null($res); # means it failed
    $self->assert_str_equals('no', $talk->get_last_completion_response());
    $self->assert($talk->get_last_error() =~ m/permission denied/i);

}

sub test_create_at_top_level
{
    my ($self) = @_;

    my $talk = $self->{store}->get_client();

    my $res = $talk->create('Test6');
    $self->assert_null($res); # means it failed
    $self->assert_str_equals('no', $talk->get_last_completion_response());
    $self->assert($talk->get_last_error() =~ m/permission denied/i);
}

1;

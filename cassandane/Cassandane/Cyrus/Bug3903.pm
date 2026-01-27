# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Cyrus::Bug3903;
use strict;
use warnings;

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
    :NoAltNameSpace
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
    :NoAltNameSpace
{
    my ($self) = @_;

    my $talk = $self->{store}->get_client();

    my $res = $talk->create('user.Test4');
    $self->assert_null($res); # means it failed
    $self->assert_str_equals('no', $talk->get_last_completion_response());
    $self->assert($talk->get_last_error() =~ m/permission denied/i);

}

sub test_create_under_shared
    :NoAltNameSpace
{
    my ($self) = @_;

    my $talk = $self->{store}->get_client();

    my $res = $talk->create('shared.Test5');
    $self->assert_null($res); # means it failed
    $self->assert_str_equals('no', $talk->get_last_completion_response());
    $self->assert($talk->get_last_error() =~ m/permission denied/i);

}

sub test_create_at_top_level
    :NoAltNameSpace
{
    my ($self) = @_;

    my $talk = $self->{store}->get_client();

    my $res = $talk->create('Test6');
    $self->assert_null($res); # means it failed
    $self->assert_str_equals('no', $talk->get_last_completion_response());
    $self->assert($talk->get_last_error() =~ m/permission denied/i);
}

1;

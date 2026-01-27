# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Test::Mboxname;
use strict;
use warnings;

use base qw(Cassandane::Unit::TestCase);
use Cassandane::Mboxname;
use Cassandane::Config;

sub new
{
    my $class = shift;
    my $self = $class->SUPER::new(@_);
    return $self;
}

sub myconfig
{
    my $conf = Cassandane::Config::default();
    $conf->set(virtdomains => 'userid');
    return $conf;
}

sub test_default_ctor
{
    my ($self) = @_;
    my $mb = Cassandane::Mboxname->new();
    $self->assert_null($mb->domain);
    $self->assert_null($mb->userid);
    $self->assert_null($mb->box);
    $self->assert_null($mb->to_internal);
    $self->assert_null($mb->to_external);
    $self->assert_null($mb->to_username);
}

sub test_parts_ctor
{
    my ($self) = @_;

    my $mb = Cassandane::Mboxname->new(
            domain => 'quinoa.com',
            userid => 'pickled',
            box => 'pants.waist^band');
    $self->assert_str_equals($mb->domain, 'quinoa.com');
    $self->assert_str_equals($mb->userid, 'pickled');
    $self->assert_str_equals($mb->box, 'pants.waist^band');
    $self->assert_str_equals($mb->to_internal,
                             'quinoa.com!user.pickled.pants.waist^band');
    $self->assert_str_equals($mb->to_external,
                             'user.pickled.pants.waist^band@quinoa.com');
    $self->assert_str_equals($mb->to_external('admin'),
                             'user.pickled.pants.waist^band@quinoa.com');
    $self->assert_str_equals($mb->to_external('owner'),
                             'pants.waist^band');
    $self->assert_str_equals($mb->to_external('other'),
                             'Other Users.pickled@quinoa^com.pants.waist^band');
    $self->assert_str_equals($mb->to_username,
                             'pickled@quinoa.com');
}

sub test_internal_ctor
{
    my ($self) = @_;

    my $mb = Cassandane::Mboxname->new(
                config => myconfig(),
                internal => 'quinoa.com!user.pickled.pants.waist^band');
    $self->assert_str_equals($mb->domain, 'quinoa.com');
    $self->assert_str_equals($mb->userid, 'pickled');
    $self->assert_str_equals($mb->box, 'pants.waist^band');
    $self->assert_str_equals($mb->to_internal,
                             'quinoa.com!user.pickled.pants.waist^band');
    $self->assert_str_equals($mb->to_external,
                             'user.pickled.pants.waist^band@quinoa.com');
    $self->assert_str_equals($mb->to_external('admin'),
                             'user.pickled.pants.waist^band@quinoa.com');
    $self->assert_str_equals($mb->to_external('owner'),
                             'pants.waist^band');
    $self->assert_str_equals($mb->to_external('other'),
                             'Other Users.pickled@quinoa^com.pants.waist^band');
    $self->assert_str_equals($mb->to_username,
                             'pickled@quinoa.com');
}

sub test_external_ctor
{
    my ($self) = @_;

    my $mb = Cassandane::Mboxname->new(
                config => myconfig(),
                external => 'user.pickled.pants.waist^band@quinoa.com');
    $self->assert_str_equals($mb->domain, 'quinoa.com');
    $self->assert_str_equals($mb->userid, 'pickled');
    $self->assert_str_equals($mb->box, 'pants.waist^band');
    $self->assert_str_equals($mb->to_internal,
                             'quinoa.com!user.pickled.pants.waist^band');
    $self->assert_str_equals($mb->to_external,
                             'user.pickled.pants.waist^band@quinoa.com');
    $self->assert_str_equals($mb->to_external('admin'),
                             'user.pickled.pants.waist^band@quinoa.com');
    $self->assert_str_equals($mb->to_external('owner'),
                             'pants.waist^band');
    $self->assert_str_equals($mb->to_external('other'),
                             'Other Users.pickled@quinoa^com.pants.waist^band');
    $self->assert_str_equals($mb->to_username,
                             'pickled@quinoa.com');
}

sub test_username_ctor
{
    my ($self) = @_;

    my $mb = Cassandane::Mboxname->new(
                config => myconfig(),
                username => 'pickled@quinoa.com');
    $self->assert_str_equals($mb->domain, 'quinoa.com');
    $self->assert_str_equals($mb->userid, 'pickled');
    $self->assert_null($mb->box);
    $self->assert_str_equals($mb->to_internal,
                             'quinoa.com!user.pickled');
    $self->assert_str_equals($mb->to_external,
                             'user.pickled@quinoa.com');
    $self->assert_str_equals($mb->to_external('admin'),
                             'user.pickled@quinoa.com');
    $self->assert_str_equals($mb->to_external('owner'),
                             'INBOX');
    $self->assert_str_equals($mb->to_external('other'),
                             'Other Users.pickled@quinoa^com');
    $self->assert_str_equals($mb->to_username,
                             'pickled@quinoa.com');
}

sub test_broken_ctor
{
    my ($self) = @_;
    my $mb;
    my $ex;

    eval
    {
        $mb = Cassandane::Mboxname->new(
                config => myconfig(),
                internal => 'quinoa.com!user.pickled.pants.waist^band',
                username => 'pickled@quinoa.com');
    };
    $ex = $@;
    $self->assert_matches(qr/contradictory initialisers/, $ex);

    eval
    {
        $mb = Cassandane::Mboxname->new(
                config => myconfig(),
                external => 'user.pickled.pants.waist^band@quinoa.com',
                username => 'pickled@quinoa.com');
    };
    $ex = $@;
    $self->assert_matches(qr/contradictory initialisers/, $ex);

    eval
    {
        $mb = Cassandane::Mboxname->new(
                config => myconfig(),
                internal => 'quinoa.com!user.pickled.pants.waist^band',
                external => 'user.pickled.pants.waist^band@quinoa.com');
    };
    $ex = $@;
    $self->assert_matches(qr/contradictory initialisers/, $ex);

    eval
    {
        $mb = Cassandane::Mboxname->new(
                config => myconfig(),
                internal => 'quinoa.com!user.pickled.pants.waist^band',
                selvage => 'sustainble');
    };
    $ex = $@;
    $self->assert_matches(qr/extra arguments/, $ex);
}

sub test_from_internal
{
    my ($self) = @_;

    my $mb = Cassandane::Mboxname->new(config => myconfig());
    $mb->from_internal('quinoa.com!user.pickled.pants.waist^band');
    $self->assert_str_equals($mb->domain, 'quinoa.com');
    $self->assert_str_equals($mb->userid, 'pickled');
    $self->assert_str_equals($mb->box, 'pants.waist^band');
    $self->assert_str_equals($mb->to_internal,
                             'quinoa.com!user.pickled.pants.waist^band');
    $self->assert_str_equals($mb->to_external,
                             'user.pickled.pants.waist^band@quinoa.com');
    $self->assert_str_equals($mb->to_external('admin'),
                             'user.pickled.pants.waist^band@quinoa.com');
    $self->assert_str_equals($mb->to_external('owner'),
                             'pants.waist^band');
    $self->assert_str_equals($mb->to_external('other'),
                             'Other Users.pickled@quinoa^com.pants.waist^band');
    $self->assert_str_equals($mb->to_username,
                             'pickled@quinoa.com');
}

sub test_from_external
{
    my ($self) = @_;

    my $mb = Cassandane::Mboxname->new(config => myconfig());
    $mb->from_external('user.pickled.pants.waist^band@quinoa.com');
    $self->assert_str_equals($mb->domain, 'quinoa.com');
    $self->assert_str_equals($mb->userid, 'pickled');
    $self->assert_str_equals($mb->box, 'pants.waist^band');
    $self->assert_str_equals($mb->to_internal,
                             'quinoa.com!user.pickled.pants.waist^band');
    $self->assert_str_equals($mb->to_external,
                             'user.pickled.pants.waist^band@quinoa.com');
    $self->assert_str_equals($mb->to_external('admin'),
                             'user.pickled.pants.waist^band@quinoa.com');
    $self->assert_str_equals($mb->to_external('owner'),
                             'pants.waist^band');
    $self->assert_str_equals($mb->to_external('other'),
                             'Other Users.pickled@quinoa^com.pants.waist^band');
    $self->assert_str_equals($mb->to_username,
                             'pickled@quinoa.com');
}

sub test_from_username
{
    my ($self) = @_;

    my $mb = Cassandane::Mboxname->new(config => myconfig());
    $mb->from_username('pickled@quinoa.com');
    $self->assert_str_equals($mb->domain, 'quinoa.com');
    $self->assert_str_equals($mb->userid, 'pickled');
    $self->assert_null($mb->box);
    $self->assert_str_equals($mb->to_internal,
                             'quinoa.com!user.pickled');
    $self->assert_str_equals($mb->to_external,
                             'user.pickled@quinoa.com');
    $self->assert_str_equals($mb->to_external('admin'),
                             'user.pickled@quinoa.com');
    $self->assert_str_equals($mb->to_external('owner'),
                             'INBOX');
    $self->assert_str_equals($mb->to_external('other'),
                             'Other Users.pickled@quinoa^com');
    $self->assert_str_equals($mb->to_username,
                             'pickled@quinoa.com');
}

sub test_make_child
{
    my ($self) = @_;

    my $mb = Cassandane::Mboxname->new(
                config => myconfig(),
                internal => 'quinoa.com!user.pickled');
    $self->assert_str_equals($mb->to_internal,
                             'quinoa.com!user.pickled');

    my $mb2 = $mb->make_child('pants');
    $self->assert_str_equals($mb2->to_internal,
                             'quinoa.com!user.pickled.pants');
    $self->assert_str_equals($mb->to_internal,
                             'quinoa.com!user.pickled');

    my $mb3 = $mb2->make_child('waist^band');
    $self->assert_str_equals($mb3->to_internal,
                             'quinoa.com!user.pickled.pants.waist^band');
    $self->assert_str_equals($mb2->to_internal,
                             'quinoa.com!user.pickled.pants');
    $self->assert_str_equals($mb->to_internal,
                             'quinoa.com!user.pickled');
}

sub test_make_parent
{
    my ($self) = @_;

    my $mb = Cassandane::Mboxname->new(
                config => myconfig(),
                internal => 'quinoa.com!user.pickled.pants.waist^band');
    $self->assert_str_equals($mb->to_internal,
                             'quinoa.com!user.pickled.pants.waist^band');

    my $mb2 = $mb->make_parent();
    $self->assert_str_equals($mb2->to_internal,
                             'quinoa.com!user.pickled.pants');

    my $mb3 = $mb2->make_parent();
    $self->assert_str_equals($mb3->to_internal,
                             'quinoa.com!user.pickled');
    $self->assert_str_equals($mb2->to_internal,
                             'quinoa.com!user.pickled.pants');

    my $mb4 = $mb3->make_parent();
    $self->assert_str_equals($mb4->to_internal,
                             'quinoa.com!user.pickled');
    $self->assert_str_equals($mb3->to_internal,
                             'quinoa.com!user.pickled');
    $self->assert_str_equals($mb2->to_internal,
                             'quinoa.com!user.pickled.pants');
}

1;

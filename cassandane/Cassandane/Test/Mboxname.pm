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

package Cassandane::Test::Mboxname;
use strict;
use warnings;

use lib '.';
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
            box => 'fanny.pack');
    $self->assert_str_equals($mb->domain, 'quinoa.com');
    $self->assert_str_equals($mb->userid, 'pickled');
    $self->assert_str_equals($mb->box, 'fanny.pack');
    $self->assert_str_equals($mb->to_internal,
                             'quinoa.com!user.pickled.fanny.pack');
    $self->assert_str_equals($mb->to_external,
                             'user.pickled.fanny.pack@quinoa.com');
    $self->assert_str_equals($mb->to_username,
                             'pickled@quinoa.com');
}

sub test_internal_ctor
{
    my ($self) = @_;

    my $mb = Cassandane::Mboxname->new(
                config => myconfig(),
                internal => 'quinoa.com!user.pickled.fanny.pack');
    $self->assert_str_equals($mb->domain, 'quinoa.com');
    $self->assert_str_equals($mb->userid, 'pickled');
    $self->assert_str_equals($mb->box, 'fanny.pack');
    $self->assert_str_equals($mb->to_internal,
                             'quinoa.com!user.pickled.fanny.pack');
    $self->assert_str_equals($mb->to_external,
                             'user.pickled.fanny.pack@quinoa.com');
    $self->assert_str_equals($mb->to_username,
                             'pickled@quinoa.com');
}

sub test_external_ctor
{
    my ($self) = @_;

    my $mb = Cassandane::Mboxname->new(
                config => myconfig(),
                external => 'user.pickled.fanny.pack@quinoa.com');
    $self->assert_str_equals($mb->domain, 'quinoa.com');
    $self->assert_str_equals($mb->userid, 'pickled');
    $self->assert_str_equals($mb->box, 'fanny.pack');
    $self->assert_str_equals($mb->to_internal,
                             'quinoa.com!user.pickled.fanny.pack');
    $self->assert_str_equals($mb->to_external,
                             'user.pickled.fanny.pack@quinoa.com');
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
                internal => 'quinoa.com!user.pickled.fanny.pack',
                username => 'pickled@quinoa.com');
    };
    $ex = $@;
    $self->assert_matches(qr/contradictory initialisers/, $ex);

    eval
    {
        $mb = Cassandane::Mboxname->new(
                config => myconfig(),
                external => 'user.pickled.fanny.pack@quinoa.com',
                username => 'pickled@quinoa.com');
    };
    $ex = $@;
    $self->assert_matches(qr/contradictory initialisers/, $ex);

    eval
    {
        $mb = Cassandane::Mboxname->new(
                config => myconfig(),
                internal => 'quinoa.com!user.pickled.fanny.pack',
                external => 'user.pickled.fanny.pack@quinoa.com');
    };
    $ex = $@;
    $self->assert_matches(qr/contradictory initialisers/, $ex);

    eval
    {
        $mb = Cassandane::Mboxname->new(
                config => myconfig(),
                internal => 'quinoa.com!user.pickled.fanny.pack',
                selvage => 'sustainble');
    };
    $ex = $@;
    $self->assert_matches(qr/extra arguments/, $ex);
}

sub test_from_internal
{
    my ($self) = @_;

    my $mb = Cassandane::Mboxname->new(config => myconfig());
    $mb->from_internal('quinoa.com!user.pickled.fanny.pack');
    $self->assert_str_equals($mb->domain, 'quinoa.com');
    $self->assert_str_equals($mb->userid, 'pickled');
    $self->assert_str_equals($mb->box, 'fanny.pack');
    $self->assert_str_equals($mb->to_internal,
                             'quinoa.com!user.pickled.fanny.pack');
    $self->assert_str_equals($mb->to_external,
                             'user.pickled.fanny.pack@quinoa.com');
    $self->assert_str_equals($mb->to_username,
                             'pickled@quinoa.com');
}

sub test_from_external
{
    my ($self) = @_;

    my $mb = Cassandane::Mboxname->new(config => myconfig());
    $mb->from_external('user.pickled.fanny.pack@quinoa.com');
    $self->assert_str_equals($mb->domain, 'quinoa.com');
    $self->assert_str_equals($mb->userid, 'pickled');
    $self->assert_str_equals($mb->box, 'fanny.pack');
    $self->assert_str_equals($mb->to_internal,
                             'quinoa.com!user.pickled.fanny.pack');
    $self->assert_str_equals($mb->to_external,
                             'user.pickled.fanny.pack@quinoa.com');
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

    my $mb2 = $mb->make_child('fanny');
    $self->assert_str_equals($mb2->to_internal,
                             'quinoa.com!user.pickled.fanny');
    $self->assert_str_equals($mb->to_internal,
                             'quinoa.com!user.pickled');

    my $mb3 = $mb2->make_child('pack');
    $self->assert_str_equals($mb3->to_internal,
                             'quinoa.com!user.pickled.fanny.pack');
    $self->assert_str_equals($mb2->to_internal,
                             'quinoa.com!user.pickled.fanny');
    $self->assert_str_equals($mb->to_internal,
                             'quinoa.com!user.pickled');
}

sub test_make_parent
{
    my ($self) = @_;

    my $mb = Cassandane::Mboxname->new(
                config => myconfig(),
                internal => 'quinoa.com!user.pickled.fanny.pack');
    $self->assert_str_equals($mb->to_internal,
                             'quinoa.com!user.pickled.fanny.pack');

    my $mb2 = $mb->make_parent();
    $self->assert_str_equals($mb2->to_internal,
                             'quinoa.com!user.pickled.fanny');

    my $mb3 = $mb2->make_parent();
    $self->assert_str_equals($mb3->to_internal,
                             'quinoa.com!user.pickled');
    $self->assert_str_equals($mb2->to_internal,
                             'quinoa.com!user.pickled.fanny');

    my $mb4 = $mb3->make_parent();
    $self->assert_str_equals($mb4->to_internal,
                             'quinoa.com!user.pickled');
    $self->assert_str_equals($mb3->to_internal,
                             'quinoa.com!user.pickled');
    $self->assert_str_equals($mb2->to_internal,
                             'quinoa.com!user.pickled.fanny');
}

1;

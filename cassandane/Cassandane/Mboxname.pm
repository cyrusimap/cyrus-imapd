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

package Cassandane::Mboxname;
use strict;
use warnings;
use overload qw("") => \&to_internal;

use lib '.';
use Cassandane::Util::Log;

sub new
{
    my ($class, %params) = @_;

    my $self = bless({
        domain => delete $params{domain},
        userid => delete $params{userid},
        box => delete $params{box},         # internal format, i.e. '.' separated
        config => delete $params{config}
                    || Cassandane::Config::default(),
        # TODO is_deleted
    }, $class);

    my $s;
    my $n = 0;

    $s = delete $params{external};
    if (defined $s)
    {
        $self->from_external($s);
        $n++;
    }

    $s = delete $params{internal};
    if (defined $s)
    {
        $self->from_internal($s);
        $n++;
    }

    $s = delete $params{username};
    if (defined $s)
    {
        $self->from_username($s);
        $n++;
    }

    die "Too many contradictory initialisers"
        if $n > 1;
    die "Unknown extra arguments"
        if scalar(%params);

    return $self;
}

# We don't just use Clone because we actually
# want a shallow clone here.  We rely on the
# c'tor taking parameters which are the same
# as the field names.
sub clone
{
    my ($self) = @_;
    return Cassandane::Mboxname->new(%$self);
}

sub domain { return shift->{domain}; }
sub userid { return shift->{userid}; }
sub box { return shift->{box}; }

sub _set
{
    my ($self, $domain, $userid, $box) = @_;

    die "No Config specified"
        unless defined $self->{config};
    my $virtdomains = $self->{config}->get('virtdomains') || 'off';
    die "Domain specified but virtdomains not enabled in instance"
        if (defined $domain && $virtdomains eq 'off');

    $box = undef if defined $box && $box eq '';

    $self->{domain} = $domain;
    $self->{userid} = $userid;
    $self->{box} = $box;
}

sub _reset
{
    my ($self) = @_;
    $self->_set(undef, undef, undef);
}

sub _external_separator
{
    my ($self) = @_;
    die "No Config specified"
        unless defined $self->{config};
    return $self->{config}->get_bool('unixhierarchysep', 'off') ? '/' : '.';
}

sub _external_separator_regexp
{
    my ($self) = @_;
    die "No Config specified"
        unless defined $self->{config};
    return $self->{config}->get_bool('unixhierarchysep', 'off') ? qr/\// : qr/\./;
}


sub from_external
{
    my ($self, $s) = @_;

    if (!defined $s)
    {
        $self->_reset();
        return;
    }

    my ($local, $domain) = ($s =~ m/^([^@]+)@([^@]+)$/);
    $local ||= $s;
    my $sep = $self->_external_separator_regexp;
    my ($prefix, $userid, @comps) = split($sep, $local);
    die "Bad external name \"$s\""
        if !defined $userid || $prefix ne 'user';

    $self->_set($domain, $userid, join('.', @comps));
}

sub to_external
{
    my ($self) = @_;

    my @comps;
    push(@comps, 'user', $self->{userid}) if defined $self->{userid};
    push(@comps, split(/\./, $self->{box})) if defined $self->{box};
    my $s = join($self->_external_separator, @comps);
    $s .= '@' . $self->{domain} if defined $self->{domain};

    return ($s eq '' ? undef : $s);
}

sub from_internal
{
    my ($self, $s) = @_;

    if (!defined $s)
    {
        $self->_reset();
        return;
    }

    my ($domain, $local) = ($s =~ m/^([^!]+)!([^!]+)$/);
    $local ||= $s;
    my ($userid, $box) = ($local =~ m/^user\.([^.]*)(.*)$/);
    $box =~ s/^\.//;

    $self->_set($domain, $userid, $box);
}

sub to_internal
{
    my ($self) = @_;

    my @comps;
    push(@comps, 'user', $self->{userid}) if defined $self->{userid};
    push(@comps, $self->{box}) if defined $self->{box};
    my $s = join('.', @comps);
    $s = $self->{domain} . '!' . $s if defined $self->{domain};

    return ($s eq '' ? undef : $s);
}

sub from_username
{
    my ($self, $s) = @_;

    if (!defined $s)
    {
        $self->_reset();
        return;
    }

    my ($userid, $domain) = ($s =~ m/^([^@]+)@([^@]+)$/);
    $userid ||= $s;

    $self->_set($domain, $userid, undef);
}

sub to_username
{
    my ($self) = @_;
    my $s = $self->{userid} || '';
    $s .= '@' . $self->{domain} if defined $self->{domain};
    return ($s eq '' ? undef : $s);
}

sub make_child
{
    my ($self, @args) = @_;

    my $sep = $self->_external_separator;

    my @comps;
    # Flatten out any array refs and stringify
    foreach my $c (@args)
    {
        if (ref $c && ref $c eq 'ARRAY')
        {
            map { push(@comps, "" . $_); } @$c;
        }
        elsif (!ref $c)
        {
            push(@comps, "" . $c);
        }
    }
    map { die "Bad mboxname component \"$_\"" if index($_, $sep) >= 0; } @comps;

    my $child = $self->clone();
    if (scalar @comps)
    {
        unshift(@comps, $child->{box}) if defined $child->{box};
        $child->{box} = join('.', @comps);
    }

    return $child;
}

sub make_parent
{
    my ($self, @args) = @_;

    my @comps = split(/\./, $self->{box} || '');
    pop(@comps);

    my $child = $self->clone();
    if (scalar @comps)
    {
        $child->{box} = join('.', @comps);
    }
    else
    {
        $child->{box} = undef;
    }

    return $child;
}

1;

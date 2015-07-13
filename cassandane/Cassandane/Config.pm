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
package Cassandane::Config;
use strict;
use warnings;
use Cassandane::Cassini;
use Cassandane::Util::Log;

my $default;

sub new
{
    my $class = shift;
    my $self = {
	parent => undef,
	variables => {},
	params => { @_ },
    };

    bless $self, $class;
    return $self;
}

sub default
{
    if (!defined($default)) {
	$default = Cassandane::Config->new(
	    admins => 'admin',
	    configdirectory => '@basedir@/conf',
	    syslog_prefix => '@name@',
	    sievedir => '@basedir@/conf/sieve',
	    defaultpartition => 'default',
	    'partition-default' => '@basedir@/data',
	    sasl_mech_list => 'PLAIN LOGIN DIGEST-MD5',
	    allowplaintext => 'yes',
	    # config options used at FastMail - may as well be testing our stuff
	    expunge_mode => 'delayed',
	    delete_mode => 'delayed',
	    # for debugging - see cassandane.ini.example
	    debug_command => '@prefix@/utils/gdbtramp %s %d',
	    # everyone should be running this
	    improved_mboxlist_sort => 'yes',
	    # default changed, we want to be explicit about it
	    unixhierarchysep => 'no',
            # let's hear all about it
            debug => 'yes',
	);
	my $defs = Cassandane::Cassini->instance()->get_section('config');
	$default->set(%$defs);
    }

    return $default;
}

sub clone
{
    my ($self) = @_;

    my $child = Cassandane::Config->new();
    $child->{parent} = $self;
    return $child;
}

sub set
{
    my ($self, %nv) = @_;
    while (my ($n, $v) = each %nv)
    {
	if (defined $v)
	{
	    $self->{params}->{$n} = $v;
	}
	else
	{
	    delete $self->{params}->{$n};
	}
    }
}

sub get
{
    my ($self, $n) = @_;
    while (defined $self)
    {
	my $v = $self->{params}->{$n};
	return $v
	    if defined $v;
	$self = $self->{parent};
    }
    return undef;
}

sub get_bool
{
    my ($self, $n, $def) = @_;
    $def = 'no' if !defined $def;
    my $v = $self->get($n);
    $v = $def if !defined $v;

    return 1 if ($v =~ m/^yes$/i);
    return 1 if ($v =~ m/^true$/i);
    return 1 if ($v =~ m/^on$/i);
    return 1 if ($v =~ m/^1$/);

    return 0 if ($v =~ m/^no$/i);
    return 0 if ($v =~ m/^false$/i);
    return 0 if ($v =~ m/^off$/i);
    return 0 if ($v =~ m/^0$/);

    die "Bad boolean \"$v\"";
}

sub set_variables
{
    my ($self, %nv) = @_;
    while (my ($n, $v) = each %nv)
    {
	$self->{variables}->{$n} = $v;
    }
}

sub _get_variable
{
    my ($self, $n) = @_;
    $n =~ s/@//g;
    while (defined $self)
    {
	my $v = $self->{variables}->{$n};
	return $v if defined $v;
	$self = $self->{parent};
    }
    die "Variable $n not defined";
}

sub substitute
{
    my ($self, $s) = @_;

    my $r = '';
    while (defined $s)
    {
	my ($pre, $ref, $post) = ($s =~ m/(.*)(@[a-z]+@)(.*)/);
	if (defined $ref)
	{
	    $r .= $pre . $self->_get_variable($ref);
	    $s = $post;
	}
	else
	{
	    $r .= $s;
	    last;
	}
    }
    return $r;
}

sub _flatten
{
    my ($self) = @_;
    my %nv;
    for (my $conf = $self ; defined $conf ; $conf = $conf->{parent})
    {
	foreach my $n (keys %{$conf->{params}})
	{
	    $nv{$n} = $self->substitute($conf->{params}->{$n})
		unless defined $nv{$n};
	}
    }
    return \%nv;
}

sub generate
{
    my ($self, $filename) = @_;
    my $nv = $self->_flatten();

    open CONF,'>',$filename
	or die "Cannot open $filename for writing: $!";
    while (my ($n, $v) = each %$nv)
    {
	print CONF "$n: $v\n";
    }
    close CONF;
}

1;

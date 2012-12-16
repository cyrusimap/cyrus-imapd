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
package Cassandane::Unit::TestCase;
# use Cassandane::Util::Log;
use base qw(Test::Unit::TestCase);

my $enabled;

sub new
{
    my $class = shift;
    return $class->SUPER::new(@_);
}

sub enable_test
{
    my ($class, $test) = @_;
    $enabled = $test;
}

sub filter
{
    my ($self) = @_;
    return
    {
	x => sub
	{
	    my $method = shift;
	    $method =~ s/^test_//;
	    # Only the explicitly enabled test runs
	    return ($enabled eq $method ? undef : 1);
	}
    };
}

sub annotate_from_file
{
    my ($self, $filename) = @_;
    return if !defined $filename;

    open LOG, '<', $filename
	or die "Cannot open $filename for reading: $!";
    while (<LOG>)
    {
	$self->annotate($_);
    }
    close LOG;
}

my @params;

sub parameter
{
    my ($ref, @values) = @_;

    return if (!scalar(@values));

    my $param = {
	id => scalar(@params),
	package => caller,
	values => \@values,
	maxvidx => scalar(@values)-1,
	reference => $ref,
    };
    push(@params, $param);

#     xlog "XXX registering parameter id $param->{id} in package $param->{package}";
}

sub _describe_setting
{
    my ($setting) = @_;
    $setting ||= [];

    my @parts;
    my @ss = ( @$setting );
    while (scalar @ss)
    {
	my $id = shift @ss;
	my $value = $params[$id]->{values}->[shift @ss];
	push(@parts, "$id:\"$value\"");
    }
    return '[' . join(' ', @parts) . ']';
}

sub make_parameter_settings
{
    my ($class, $package) = @_;

#     xlog "XXX making parameter settings for package $package";

    my @settings;
    my @stack;
    foreach my $param (grep { $_->{package} eq $package } @params)
    {
	push(@stack, { param => $param, vidx => 0 });
    }
    return [] if !scalar(@stack);

    SETTING: while (1)
    {
	# save a setting
	my $setting = [ map { $_->{param}->{id}, $_->{vidx} } @stack ];
# 	xlog "XXX making setting " . _describe_setting($setting);
	push(@settings, $setting);
	# increment indexes, wrapping and overflowing
	foreach my $s (@stack)
	{
	    $s->{vidx}++;
	    if ($s->{vidx} > $s->{param}->{maxvidx})
	    {
		$s->{vidx} = 0;
	    }
	    else
	    {
		next SETTING;
	    }
	}
	last;
    }

    return @settings;
}

sub apply_parameter_setting
{
    my ($class, $setting) = @_;

#     xlog "XXX applying setting " . _describe_setting($setting);

    foreach my $param (@params)
    {
	${$param->{reference}} = undef;
    }

    my @ss = ( @$setting );
    while (scalar @ss)
    {
	my $param = $params[shift @ss];
	my $value = $param->{values}->[shift @ss];
# 	xlog "XXX setting parameter id $param->{id} to value \"$value\"";
	${$param->{reference}} = $value;
    }
}

1;

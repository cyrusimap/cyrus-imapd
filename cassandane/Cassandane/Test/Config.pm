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

package Cassandane::Test::Config;
use strict;
use warnings;
use File::Temp qw(tempfile);

use lib '.';
use base qw(Cassandane::Unit::TestCase);
use Cassandane::Config;

sub new
{
    my $class = shift;
    my $self = $class->SUPER::new(@_);
    return $self;
}

sub test_default
{
    my ($self) = @_;

    my $c = Cassandane::Config->default();
    $self->assert(defined $c);
    $self->assert(!defined $c->get('hello'));

    my $c2 = Cassandane::Config->default();
    $self->assert(defined $c2);
    $self->assert($c2 eq $c);
    $self->assert(!defined $c->get('hello'));
    $self->assert(!defined $c2->get('hello'));

    $c->set(hello => 'world');
    $self->assert($c->get('hello') eq 'world');
    $self->assert($c2->get('hello') eq 'world');

    $c->set(hello => undef);
    $self->assert(!defined $c->get('hello'));
    $self->assert(!defined $c2->get('hello'));
}

sub test_clone
{
    my ($self) = @_;

    my $c = Cassandane::Config->new();
    $self->assert(!defined $c->get('hello'));
    $self->assert(!defined $c->get('foo'));

    my $c2 = $c->clone();
    $self->assert($c2 ne $c);
    $self->assert(!defined $c->get('hello'));
    $self->assert(!defined $c2->get('hello'));
    $self->assert(!defined $c->get('foo'));
    $self->assert(!defined $c2->get('foo'));

    $c2->set(hello => 'world');
    $self->assert(!defined $c->get('hello'));
    $self->assert($c2->get('hello') eq 'world');
    $self->assert(!defined $c->get('foo'));
    $self->assert(!defined $c2->get('foo'));

    $c->set(foo => 'bar');
    $self->assert(!defined $c->get('hello'));
    $self->assert($c2->get('hello') eq 'world');
    $self->assert($c->get('foo') eq 'bar');
    $self->assert($c2->get('foo') eq 'bar');

    $c2->set(foo => 'baz');
    $self->assert(!defined $c->get('hello'));
    $self->assert($c2->get('hello') eq 'world');
    $self->assert($c->get('foo') eq 'bar');
    $self->assert($c2->get('foo') eq 'baz');

    $c2->set(foo => undef);
    $self->assert(!defined $c->get('hello'));
    $self->assert($c2->get('hello') eq 'world');
    $self->assert($c->get('foo') eq 'bar');
    $self->assert($c2->get('foo') eq 'bar');

    $c->set(foo => undef);
    $self->assert(!defined $c->get('hello'));
    $self->assert($c2->get('hello') eq 'world');
    $self->assert(!defined $c->get('foo'));
    $self->assert(!defined $c2->get('foo'));

    $c2->set(hello => undef);
    $self->assert(!defined $c->get('hello'));
    $self->assert(!defined $c2->get('hello'));
    $self->assert(!defined $c->get('foo'));
    $self->assert(!defined $c2->get('foo'));
}

sub _generate_and_read
{
    my ($self, $c) = @_;

    # Write the file
    my ($fh, $filename) = tempfile()
	or die "Cannot open temporary file: $!";
    $c->generate($filename);

    # read it back again to check
    my %nv;
    while (<$fh>)
    {
	chomp;
	my ($n, $v) = m/^([^:\s]+):\s*(\S+)$/;
	$self->assert(defined $v);
	$nv{$n} = $v;
    }

    close $fh;
    unlink $filename;

    return \%nv;
}

sub test_generate
{
    my ($self) = @_;

    my $c = Cassandane::Config->new();
    $c->set(foo => 'bar');
    $c->set(quux => 'foonly');
    my $c2 = $c->clone();
    $c2->set(hello => 'world');
    $c2->set(foo => 'baz');

    my $nv = $self->_generate_and_read($c2);

    $self->assert(scalar(keys(%$nv)) == 3);
    $self->assert($nv->{foo} eq 'baz');
    $self->assert($nv->{hello} eq 'world');
    $self->assert($nv->{quux} eq 'foonly');
}

sub test_variables
{
    my ($self) = @_;

    my $c = Cassandane::Config->new();
    $c->set(foo => 'b@grade@r');
    $c->set(quux => 'fo@grade@nly');
    my $c2 = $c->clone();
    $c2->set(hello => 'w@grade@rld');
    $c2->set(foo => 'baz');

    # missing @grade@ variable throws an exception
    my $nv;
    eval
    {
	$nv = $self->_generate_and_read($c2);
    };
    $self->assert(defined $@ && $@ =~ m/Variable grade not defined/i);

    # @grade@ on the parent affects all variable expansions
    $c->set_variables('grade' => 'B');
    $nv = $self->_generate_and_read($c2);
    $self->assert_num_equals(3, scalar(keys(%$nv)));
    $self->assert_str_equals('baz', $nv->{foo});
    $self->assert_str_equals('wBrld', $nv->{hello});
    $self->assert_str_equals('foBnly', $nv->{quux});

    # @grade@ on the child overrides @grade@ on the parent
    $c2->set_variables('grade' => 'A');
    $nv = $self->_generate_and_read($c2);
    $self->assert_num_equals(scalar(keys(%$nv)), 3);
    $self->assert_str_equals('baz', $nv->{foo});
    $self->assert_str_equals('wArld', $nv->{hello});
    $self->assert_str_equals('foAnly', $nv->{quux});
}


1;

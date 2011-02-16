#!/usr/bin/perl

use strict;
use warnings;
package Cassandane::Test::Config;
use base qw(Test::Unit::TestCase);
use File::Temp qw(tempfile);
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

sub test_generate
{
    my ($self) = @_;

    my $c = Cassandane::Config->new();
    $c->set(foo => 'bar');
    $c->set(quux => 'foonly');
    my $c2 = $c->clone();
    $c2->set(hello => 'world');
    $c2->set(foo => 'baz');

    # Write the file
    my ($fh, $filename) = tempfile()
	or die "Cannot open temporary file: $!";
    $c2->generate($filename);

    # read it back again to check
    my %nv;
    while (<$fh>)
    {
	chomp;
	my ($n, $v) = m/^([^:\s]+):\s*(\S+)$/;
	$self->assert(defined $v);
	$nv{$n} = $v;
    }

    $self->assert(scalar(keys(%nv)) == 3);
    $self->assert($nv{foo} eq 'baz');
    $self->assert($nv{hello} eq 'world');
    $self->assert($nv{quux} eq 'foonly');

    close $fh;
    unlink $filename;
}

1;

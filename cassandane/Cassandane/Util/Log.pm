#!/usr/bin/perl

package Cassandane::Util::Log;
use strict;
use warnings;

use Exporter ();
our @ISA = qw(Exporter);
our @EXPORT = qw(
    &xlog &set_verbose &get_verbose
    );

my $verbose = 1;

sub xlog
{
    my ($pkg, $file, $line) = caller;
    $pkg =~ s/^Cassandane:://;
    my $prefix = "=====> " . $pkg . "[" . $line . "]";
    my $msg = join(' ', @_);
    print STDERR "$prefix $msg\n" if $verbose;
}

sub set_verbose
{
    my ($v) = @_;
    $verbose = 0 + $v;
}

sub get_verbose
{
    return $verbose;
}

1;

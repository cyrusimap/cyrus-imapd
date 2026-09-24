# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Unit::FormatTAP;
use strict;
use warnings;
use Data::Dumper;
use IO::File;

use base qw(Cassandane::Unit::Formatter);

sub new
{
    my ($class, $fh) = @_;
    my $self = $class->SUPER::new($fh);

    $self->{i} = 0;

    return $self;
}

sub _print_line_for {
    my ($self, $witem, $ok, $extra) = @_;

    my $line = sprintf "%sok %i - %s.%s%s\n",
        ($ok ? q{} : 'not '),
        ++$self->{i},
        $witem->{suite},
        $witem->{testname},
        (length $extra ? " ($extra)" : q{});

    $self->_print($line);
}

sub start_test
{
    # ...
}

sub add_pass {
    my ($self, $witem) = @_;
    $self->_print_line_for($witem, 1);
}

sub add_error
{
    my ($self, $witem) = @_;
    $self->_print_line_for($witem, 0, 'error');
}

sub add_failure
{
    my ($self, $witem) = @_;
    $self->_print_line_for($witem, 0, 'failure');
}

sub add_skip
{
    my ($self, $witem) = @_;

    $self->SUPER::add_skip($witem);

    # TAP has its own way of saying this, and a skip is an 'ok'
    my $line = sprintf "ok %i - %s.%s # SKIP %s\n",
        ++$self->{i},
        $witem->{suite},
        $witem->{testname},
        $witem->{reason};

    $self->_print($line);
}

sub print_summary
{
    my ($self) = @_; # ignoring the other args
    $self->_print("1..$self->{i}\n");
}

1;

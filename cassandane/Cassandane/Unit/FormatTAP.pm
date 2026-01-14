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
    my ($self, $test, $ok, $extra) = @_;

    my $line = sprintf "%sok %i - %s.%s%s\n",
        ($ok ? q{} : 'not '),
        ++$self->{i},
        ref($test),
        ($test->name =~ s/^test_//r),
        (length $extra ? " ($extra)" : q{});

    $self->_print($line);
}

sub start_test
{
    # ...
}

sub add_pass {
    my ($self, $test) = @_;
    $self->_print_line_for($test, 1);
}

sub add_error
{
    my ($self, $test, $exception) = @_;
    $self->_print_line_for($test, 0, 'error');
}

sub add_failure
{
    my ($self, $test, $exception) = @_;
    $self->_print_line_for($test, 0, 'failure');
}

sub print_summary
{
    my ($self) = @_; # ignoring the other args
    $self->_print("1..$self->{i}\n");
}

1;

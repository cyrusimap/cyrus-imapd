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
    return $class->SUPER::new($fh);
}

sub start_test
{
    my ($self, $test) = @_;
    $self->_print('.');
}

sub add_error
{
    my ($self, $test, $exception) = @_;
    $self->_print('E');
}

sub add_failure
{
    my ($self, $test, $exception) = @_;
    $self->_print('F');
}

1;

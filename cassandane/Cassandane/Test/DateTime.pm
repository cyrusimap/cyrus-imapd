#!/usr/bin/perl

use strict;
use warnings;
package Cassandane::Test::DateTime;
use base qw(Test::Unit::TestCase);
use Cassandane::Util::DateTime;

sub new
{
    my $class = shift;
    my $self = $class->SUPER::new(@_);
    return $self;
}

sub test_basic
{
    my ($self) = @_;
    $self->assert((from_iso8601('20101014T161952Z')->epoch == 1287073192));
    $self->assert((from_rfc822('Fri, 15 Oct 2010 03:19:52 +1100')->epoch == 1287073192));
    $self->assert((from_rfc3501('15-Oct-2010 03:19:52 +1100')->epoch == 1287073192));
    $self->assert((to_iso8601(DateTime->from_epoch(epoch => 1287073192)) eq '20101014T161952Z'));
    $self->assert((to_rfc822(DateTime->from_epoch(epoch => 1287073192)) eq 'Fri, 15 Oct 2010 03:19:52 +1100'));
    $self->assert((to_rfc3501(DateTime->from_epoch(epoch => 1287073192)) eq '15-Oct-2010 03:19:52 +1100'));
}

1;

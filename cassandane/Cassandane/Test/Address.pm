# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Test::Address;
use strict;
use warnings;

use base qw(Cassandane::Unit::TestCase);
use Cassandane::Address;

sub new
{
    my $class = shift;
    my $self = $class->SUPER::new(@_);
    return $self;
}

sub test_default_ctor
{
    my ($self) = @_;
    my $a = Cassandane::Address->new();
    $self->assert(!defined $a->name);
    $self->assert($a->localpart eq 'unknown-user');
    $self->assert($a->domain eq 'unspecified-domain');
    $self->assert($a->address eq 'unknown-user@unspecified-domain');
    $self->assert($a->as_string eq '<unknown-user@unspecified-domain>');
    $self->assert("" . $a eq '<unknown-user@unspecified-domain>');
}

sub test_full_ctor
{
    my ($self) = @_;
    my $a = Cassandane::Address->new(
        name => 'Fred J. Bloggs',
        localpart => 'fbloggs',
        domain => 'fastmail.fm',
        );
    $self->assert($a->name eq 'Fred J. Bloggs');
    $self->assert($a->localpart eq 'fbloggs');
    $self->assert($a->domain eq 'fastmail.fm');
    $self->assert($a->address eq 'fbloggs@fastmail.fm');
    $self->assert($a->as_string eq 'Fred J. Bloggs <fbloggs@fastmail.fm>');
    $self->assert("" . $a eq 'Fred J. Bloggs <fbloggs@fastmail.fm>');
}

1;

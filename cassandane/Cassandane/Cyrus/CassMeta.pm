#!/usr/bin/perl
# Cassandane::Cyrus::CassMeta: Cassandane meta-tests that need Cyrus
# (as distinct from Cassandane::Test::*, which don't need Cyrus)
# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Cyrus::CassMeta;
use strict;
use warnings;
use Data::Dumper;

use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;

# See Cassandane::Cyrus::TestCase::_create_instances()
my @all_instance_names = qw(instance replica frontend backend2);

sub new
{
    my $class = shift;

    my $config = Cassandane::Config->default()->clone();

    # override ONE cyrusdb backend to a value that is:
    #   a) not its usual default
    #   b) not one that Cassandane::Instance ever prefers
    #   c) not one that master will reject for that database
    # so that test_cyrusdb_default_backends can determine whether suite-level
    # overrides like this are working correctly
    $config->set('subscription_db' => 'skiplist');

    # turn on murder and replication so we can examine all possible instances
    my $self = $class->SUPER::new({
        config => $config,
        imapmurder => 1,
        replica => 1,
    }, @_);

    $self->needs('component', 'murder');
    $self->needs('component', 'replication');

    return $self;
}

sub set_up
{
    my ($self) = @_;
    $self->SUPER::set_up();
}

sub tear_down
{
    my ($self) = @_;
    $self->SUPER::tear_down();
}

use Cassandane::Tiny::Loader 'tiny-tests/CassMeta';

1;

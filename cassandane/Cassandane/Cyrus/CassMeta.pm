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

sub test_cyrusdb_default_backends
{
    my ($self) = @_;

    my @regular_databases = qw(
        annotation_db
        conversations_db
        duplicate_db
        mboxkey_db
        mboxlist_db
        ptscache_db
        search_indexed_db
        seenstate_db
        statuscache_db
        sync_cache_db
        tls_sessions_db
        zoneinfo_db
    );

    my @regular_backends = grep { defined }
                           ($ENV{CASSANDANE_DEFAULT_DB}, 'twom', 'twoskip');

    my %irregular_databases = (
        quota_db => 'quotalegacy',
        subscription_db => 'skiplist', # usually 'flat', but we overrode it!
        tlscache_db => 'twoskip',
        userdeny_db => 'flat',
    );

    foreach my $instance_name (@all_instance_names) {
        my $instance = $self->{$instance_name}
            || die "instance '$instance_name' not found";

        if ($instance->{buildinfo}->get('cyrusdb', undef)) {
            # Cassandane sets cyrusdb backends explicitly for Cyrus versions
            # that report which backends they support

            foreach my $database (@regular_databases) {
                xlog "checking $database for $instance_name...";

                my $backend = $instance->{config}->get($database);

                # expect it to be set, and to a known backend
                $self->assert_not_null($backend);
                # XXX use assert_contains()
                $self->assert_num_equals(1, scalar grep { $backend eq $_ }
                                                        @regular_backends);
            }

            while (my ($database, $expect_backend) = each %irregular_databases) {
                xlog "checking $database for $instance_name...";

                my $backend = $instance->{config}->get($database);

                $self->assert_not_null($backend);
                $self->assert_str_equals($expect_backend, $backend);
            }
        }
        else {
            # other backends should not have been explicitly set
            foreach my $database (@regular_databases, keys %irregular_databases) {
                xlog "checking $database for $instance_name...";

                my $backend = $instance->{config}->get($database);

                if ($database eq 'subscription_db') {
                    # we overrode this one in the constructor
                    $self->assert_not_null($backend);
                    $self->assert_str_equals('skiplist', $backend);
                }
                else {
                    $self->assert_null($backend);
                }
            }
        }
    }
}

1;

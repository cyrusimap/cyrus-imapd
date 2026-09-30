# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::TestSuite::Cassandane::Outcome;
use strict;
use warnings;
use experimental 'signatures';

use base qw(Cassandane::Unit::TestSuite);

use File::Temp qw(tempfile);

use Cassandane::Unit::Worker;

# A test can go wrong in more than one place at once, and only one of them can
# be the report.  These are about which one wins.
#
# The fixtures below are one-test suites, each arranged to go wrong somewhere
# different.  They have to be real classes, because a worker finds the test by
# name on the suite and calls tear_down and post_tear_down by convention.
# None of them is a Cyrus test, so none of them starts a Cyrus.

my $FIXTURE = 'Cassandane::TestSuite::Cassandane::Outcome::Fixture';

{
    package Cassandane::TestSuite::Cassandane::Outcome::Fixture;
    our @ISA = ('Cassandane::Unit::TestSuite');

    sub test_it        { return }
    sub tear_down      { return }
    sub post_tear_down { return }
}

{
    package Cassandane::TestSuite::Cassandane::Outcome::Fixture::Clean;
    our @ISA = ('Cassandane::TestSuite::Cassandane::Outcome::Fixture');
}

{
    package Cassandane::TestSuite::Cassandane::Outcome::Fixture::TestDies;
    our @ISA = ('Cassandane::TestSuite::Cassandane::Outcome::Fixture');

    sub test_it { die "the test died\n" }
}

{
    package Cassandane::TestSuite::Cassandane::Outcome::Fixture::TearDownDies;
    our @ISA = ('Cassandane::TestSuite::Cassandane::Outcome::Fixture');

    sub tear_down { die "tear_down died\n" }
}

{
    package Cassandane::TestSuite::Cassandane::Outcome::Fixture::TestAndTearDownDie;
    our @ISA = ('Cassandane::TestSuite::Cassandane::Outcome::Fixture');

    sub test_it   { die "the test died\n" }
    sub tear_down { die "tear_down died\n" }
}

{
    package Cassandane::TestSuite::Cassandane::Outcome::Fixture::PostTearDownDies;
    our @ISA = ('Cassandane::TestSuite::Cassandane::Outcome::Fixture');

    sub post_tear_down { die "post_tear_down died\n" }
}

{
    package Cassandane::TestSuite::Cassandane::Outcome::Fixture::TestAndPostDie;
    our @ISA = ('Cassandane::TestSuite::Cassandane::Outcome::Fixture');

    sub test_it        { die "the test died\n" }
    sub post_tear_down { die "post_tear_down died\n" }
}

# Run one fixture the way a worker does, and hand back the outcome it would
# send to the parent.  The worker's own method does the running, so what these
# tests check is the rule it applies rather than a restatement of it.
sub _outcome_for ($moniker)
{
    my (undef, $logfile) = tempfile(UNLINK => 1);

    return Cassandane::Unit::Worker->new(0)->_run_test({
        suite    => "${FIXTURE}::$moniker",
        testname => 'it',
        logfile  => $logfile,
    });
}

# Assert that running the $moniker fixture comes out as $outcome, reported in
# words that mention $wanted and, when one is given, don't mention $unwanted.
sub assert_report ($self, $moniker, $outcome, $wanted, $unwanted = undef)
{
    my $got = _outcome_for($moniker);

    $self->assert_str_equals($outcome, $got->{outcome});
    $self->assert_matches($wanted, $got->{report});
    $self->assert_does_not_match($unwanted, $got->{report}) if $unwanted;
}

sub test_a_test_that_works ($self)
{
    my $got = _outcome_for('Clean');

    $self->assert_str_equals('pass', $got->{outcome});
    $self->assert_null($got->{report});
}

sub test_what_the_test_said ($self)
{
    $self->assert_report('TestDies', 'error', qr/the test died/);
}

sub test_tear_down_speaks_when_the_test_didnt ($self)
{
    # The test passed, so the only thing that went wrong is the only thing
    # there is to report.
    $self->assert_report('TearDownDies', 'error', qr/tear_down died/);

    $self->assert_report('PostTearDownDies', 'error', qr/post_tear_down died/);
}

sub test_the_test_outranks_its_tear_down ($self)
{
    # Tearing down a fixture the test never finished building tends to go
    # wrong as a consequence, so it's the test that gets to say what happened.
    $self->assert_report('TestAndTearDownDie', 'error',
                         qr/the test died/, qr/tear_down died/);

    $self->assert_report('TestAndPostDie', 'error',
                         qr/the test died/, qr/post_tear_down died/);
}

1;

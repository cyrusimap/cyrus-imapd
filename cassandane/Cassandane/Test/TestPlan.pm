# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Test::TestPlan;
use strict;
use warnings;
use experimental 'signatures';

use base qw(Cassandane::Unit::TestCase);
use Cassandane::Unit::TestPlan;

# We plan against a fixture tree rather than the real test roots so that these
# expectations don't have to be rewritten every time a suite is added or
# renamed.  See Cassandane/Fixture/TestPlan/README.  Like the real roots, these
# are relative to the cassandane directory, which is where a test run's cwd is.
my $ALPHA = 'Cassandane/Fixture/TestPlan/Alpha';
my $BETA  = 'Cassandane/Fixture/TestPlan/Beta';

# Trimmed off both sides of every comparison, so that expectations below can
# read "Alpha::GlobOne.beta" instead of the full package name.
my $PREFIX = 'Cassandane::Fixture::TestPlan::';

# Build a plan over the fixture roots and schedule @$specs on it.
sub _fixture_plan ($specs, %opts)
{
    my $plan = Cassandane::Unit::TestPlan->new(
        test_roots => [ $ALPHA, $BETA ],
        %opts,
    );
    $plan->schedule(@$specs);

    return $plan;
}

# Assert that scheduling $specs would run exactly the tests in @$expect, each
# named as "Alpha::GlobOne.beta".  The specs are folded into both sides of the
# comparison so that a failure says which case failed.
sub assert_plan ($self, $specs, $expect, $desc = undef)
{
    my $label = $desc // join q{ }, @$specs;
    my @got = map {; s/^\Q$PREFIX\E//r } _fixture_plan($specs)->list();

    $self->assert_str_equals(
        join(q{ }, "$label:", sort @$expect),
        join(q{ }, "$label:", sort @got),
    );
}

# Assert that scheduling $specs dies, with a message matching $qr.
sub assert_plan_dies ($self, $specs, $qr)
{
    eval { _fixture_plan($specs) };
    my $e = $@;

    $self->assert_matches($qr, $e);
}

# Assert that scheduling $specs leaves the $flag ('skip_slow' or 'slow_only')
# set to $expect.  %opts seeds the plan's initial flags.
sub assert_slow_flag ($self, $specs, $flag, $expect, %opts)
{
    my $plan = _fixture_plan($specs, %opts);

    $self->assert_str_equals(
        join(q{ }, @$specs, $flag, $expect),
        join(q{ }, @$specs, $flag, $plan->{$flag}),
    );
}

sub test_whole_suite ($self)
{
    $self->assert_plan(['GlobOne'],
                       [qw(Alpha::GlobOne.alpha
                           Alpha::GlobOne.beta
                           Alpha::GlobOne.gamma_slow)]);

    $self->assert_plan(['Other'], [qw(Alpha::Other.alpha)]);

    $self->assert_plan(['GlobOne', 'Other'],
                       [qw(Alpha::GlobOne.alpha
                           Alpha::GlobOne.beta
                           Alpha::GlobOne.gamma_slow
                           Alpha::Other.alpha)]);
}

sub test_single_test ($self)
{
    $self->assert_plan(['GlobOne.beta'], [qw(Alpha::GlobOne.beta)]);

    $self->assert_plan(['GlobOne.beta', 'GlobTwo.delta'],
                       [qw(Alpha::GlobOne.beta Alpha::GlobTwo.delta)]);

    # a test that doesn't exist is not an error -- it just quietly selects
    # nothing.  If that ever becomes an error, this expectation should change.
    $self->assert_plan(['GlobOne.nonesuch'], []);
}

sub test_suite_naming ($self)
{
    # a suite can be named by its bare moniker, by any suffix of its package
    # name, or by the whole thing -- with either separator
    for my $spec ('GlobOne',
                  'Alpha::GlobOne',
                  'Alpha.GlobOne',
                  'Alpha/GlobOne',
                  'Cassandane::Fixture::TestPlan::Alpha::GlobOne',
                  'Cassandane/Fixture/TestPlan/Alpha/GlobOne.pm')
    {
        $self->assert_plan([$spec],
                           [qw(Alpha::GlobOne.alpha
                               Alpha::GlobOne.beta
                               Alpha::GlobOne.gamma_slow)]);
    }
}

sub test_whole_root ($self)
{
    $self->assert_plan([$BETA],
                       [qw(Beta::GlobThree.alpha Beta::Shared.from_beta)]);

    $self->assert_plan([$ALPHA, $BETA],
                       [qw(Alpha::GlobOne.alpha
                           Alpha::GlobOne.beta
                           Alpha::GlobOne.gamma_slow
                           Alpha::GlobTwo.alpha
                           Alpha::GlobTwo.delta
                           Alpha::Other.alpha
                           Alpha::Shared.from_alpha
                           Beta::GlobThree.alpha
                           Beta::Shared.from_beta)]);
}

sub test_test_globs ($self)
{
    $self->assert_plan(['GlobOne.*'],
                       [qw(Alpha::GlobOne.alpha
                           Alpha::GlobOne.beta
                           Alpha::GlobOne.gamma_slow)]);

    $self->assert_plan(['GlobOne.*a'],
                       [qw(Alpha::GlobOne.alpha Alpha::GlobOne.beta)]);

    $self->assert_plan(['GlobOne.b*'], [qw(Alpha::GlobOne.beta)]);

    $self->assert_plan(['GlobOne.*mm*'], [qw(Alpha::GlobOne.gamma_slow)]);

    # a glob is anchored at both ends, so this does not match gamma_slow
    $self->assert_plan(['GlobOne.mm*'], []);
}

sub test_negation ($self)
{
    $self->assert_plan([$BETA, '!GlobThree'], [qw(Beta::Shared.from_beta)]);
    $self->assert_plan([$BETA, '~GlobThree'], [qw(Beta::Shared.from_beta)]);

    $self->assert_plan(['GlobOne', '!GlobOne.beta'],
                       [qw(Alpha::GlobOne.alpha Alpha::GlobOne.gamma_slow)]);

    $self->assert_plan(['GlobOne', '!GlobOne.*a'],
                       [qw(Alpha::GlobOne.gamma_slow)]);

    # denial beats permission, whichever order they're given in
    $self->assert_plan(['GlobOne.beta', '!GlobOne.beta'], []);
    $self->assert_plan(['!GlobOne.beta', 'GlobOne.beta'], []);
}

sub test_root_shadowing ($self)
{
    # Shared exists in both roots, and the earlier root wins ...
    $self->assert_plan(['Shared'], [qw(Alpha::Shared.from_alpha)]);
    $self->assert_plan(['Beta::Shared'], [qw(Alpha::Shared.from_alpha)]);

    # ... so the only way to name the other one is in full
    $self->assert_plan(['Cassandane::Fixture::TestPlan::Beta::Shared'],
                       [qw(Beta::Shared.from_beta)]);
}

sub test_unrecognised_spec_dies ($self)
{
    $self->assert_plan_dies(['Nonesuch'],
                            qr{Unrecognised test specification: Nonesuch});

    $self->assert_plan_dies(['Nonesuch.beta'],
                            qr{Unrecognised test specification: Nonesuch\.beta});

    # a bad spec is fatal even alongside good ones
    $self->assert_plan_dies(['GlobOne', 'Nonesuch'],
                            qr{Unrecognised test specification: Nonesuch});
}

sub test_slow_flags ($self)
{
    # naming a slow test explicitly turns the skip_slow filter off
    $self->assert_slow_flag(['GlobOne'], 'skip_slow', 1);
    $self->assert_slow_flag(['GlobOne.beta'], 'skip_slow', 1);
    $self->assert_slow_flag(['GlobOne.gamma_slow'], 'skip_slow', 0);

    # ... but a negated one doesn't
    $self->assert_slow_flag(['GlobOne', '!GlobOne.gamma_slow'], 'skip_slow', 1);

    # A glob doesn't count as naming it explicitly, so this selects the slow
    # test and then filters it back out again.  That is arguably wrong; if it
    # gets fixed, this expectation should change.
    $self->assert_slow_flag(['GlobOne.*_slow'], 'skip_slow', 1);

    # symmetrically, naming a non-slow test turns slow_only off
    $self->assert_slow_flag(['GlobOne.gamma_slow'], 'slow_only', 1,
                            slow_only => 1);
    $self->assert_slow_flag(['GlobOne.beta'], 'slow_only', 0,
                            slow_only => 1);
}

1;

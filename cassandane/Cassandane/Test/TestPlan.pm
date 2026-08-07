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

# The whole of Alpha::GlobOne, which most of these cases select one way or
# another.  Note that it has both slow and regular tests in it.
my @GLOB_ONE = qw(Alpha::GlobOne.alpha
                  Alpha::GlobOne.beta
                  Alpha::GlobOne.gamma_slow);

# Everything matching "Glob*", which spans both roots.
my @GLOB_STAR = (@GLOB_ONE, qw(Alpha::GlobTwo.alpha
                               Alpha::GlobTwo.delta
                               Beta::GlobThree.alpha));

# Every test in the fixture.
my @EVERYTHING = (@GLOB_STAR, qw(Alpha::Other.alpha
                                 Alpha::Shared.from_alpha
                                 Beta::Shared.from_beta));

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
    $self->assert_plan(['GlobOne'], \@GLOB_ONE);

    $self->assert_plan(['Other'], [qw(Alpha::Other.alpha)]);

    $self->assert_plan(['GlobOne', 'Other'],
                       [@GLOB_ONE, 'Alpha::Other.alpha']);
}

sub test_single_test ($self)
{
    $self->assert_plan(['GlobOne.beta'], [qw(Alpha::GlobOne.beta)]);

    $self->assert_plan(['GlobOne.beta', 'GlobTwo.delta'],
                       [qw(Alpha::GlobOne.beta Alpha::GlobTwo.delta)]);
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
        $self->assert_plan([$spec], \@GLOB_ONE);
    }
}

sub test_separators_are_interchangeable ($self)
{
    # The separator between a suite and a test is no different from the one
    # between the parts of a suite name: '.', '/' and '::' are all flattened to
    # the same thing before anything looks at the specification, which is why
    # nothing can tell which one you typed.
    for my $spec ('GlobOne.beta', 'GlobOne/beta', 'GlobOne::beta')
    {
        $self->assert_plan([$spec], [qw(Alpha::GlobOne.beta)]);
    }

    # ... and that stays true once both halves are globbed.  Only GlobOne has a
    # test starting with 'b', so the other suites the glob matched contribute
    # nothing rather than making this an error.
    for my $spec ('Glob*.b*', 'Glob*/b*', 'Glob*::b*',
                  'Glob+.b+', 'Glob+/b+', 'Glob+::b+')
    {
        $self->assert_plan([$spec], [qw(Alpha::GlobOne.beta)]);
    }
}

sub test_whole_root ($self)
{
    $self->assert_plan([$BETA],
                       [qw(Beta::GlobThree.alpha Beta::Shared.from_beta)]);

    $self->assert_plan([$ALPHA, $BETA], \@EVERYTHING);
}

sub test_suite_globs ($self)
{
    # a globbed suite name is collected from every root, unlike an exact one
    $self->assert_plan(['Glob*'], \@GLOB_STAR);
    $self->assert_plan(['Shared*'],
                       [qw(Alpha::Shared.from_alpha Beta::Shared.from_beta)]);

    $self->assert_plan(['GlobT*'],
                       [qw(Alpha::GlobTwo.alpha
                           Alpha::GlobTwo.delta
                           Beta::GlobThree.alpha)]);

    $self->assert_plan(['*One'], \@GLOB_ONE);

    # ... and on its own it means every suite there is
    $self->assert_plan(['*'], \@EVERYTHING);

    # a fully qualified glob is confined to the root it names
    $self->assert_plan(['Cassandane::Fixture::TestPlan::Beta::Glob*'],
                       [qw(Beta::GlobThree.alpha)]);

    # a glob matching no suite is as fatal as a name that doesn't exist
    $self->assert_plan_dies(['Nonesuch*'],
                            qr{Unrecognised test specification: Nonesuch\*});

    # a globbed suite can be negated, or have parts of it negated
    $self->assert_plan(['Glob*', '!GlobTwo'],
                       [@GLOB_ONE, 'Beta::GlobThree.alpha']);

    $self->assert_plan(['Glob*', '!Glob*.alpha'],
                       [qw(Alpha::GlobOne.beta
                           Alpha::GlobOne.gamma_slow
                           Alpha::GlobTwo.delta)]);
}

sub test_suite_globs_with_tests ($self)
{
    $self->assert_plan(['Glob*.alpha'],
                       [qw(Alpha::GlobOne.alpha
                           Alpha::GlobTwo.alpha
                           Beta::GlobThree.alpha)]);

    $self->assert_plan(['Glob*.*a'],
                       [qw(Alpha::GlobOne.alpha
                           Alpha::GlobOne.beta
                           Alpha::GlobTwo.alpha
                           Alpha::GlobTwo.delta
                           Beta::GlobThree.alpha)]);

    # The test only has to exist in one of the suites the glob matched.  If it
    # had to exist in all of them, a suite glob would be almost unusable with a
    # test name after it.
    $self->assert_plan(['Glob*.delta'], [qw(Alpha::GlobTwo.delta)]);

    # ... but if it turns up in none of them, that's still a mistake
    $self->assert_plan_dies(['Glob*.nonesuch'],
                            qr{No tests matched: Glob\*\.nonesuch});
}


sub test_test_globs ($self)
{
    $self->assert_plan(['GlobOne.*'], \@GLOB_ONE);

    $self->assert_plan(['GlobOne.*a'],
                       [qw(Alpha::GlobOne.alpha Alpha::GlobOne.beta)]);

    $self->assert_plan(['GlobOne.b*'], [qw(Alpha::GlobOne.beta)]);

    $self->assert_plan(['GlobOne.*mm*'], [qw(Alpha::GlobOne.gamma_slow)]);
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

    # Denying a test that doesn't exist is not an error, unlike selecting one:
    # the "suppress" setting names tests to deny, and has to keep working
    # against a version of Cyrus where the test is gone.
    $self->assert_plan(['GlobOne', '!GlobOne.nonesuch'], \@GLOB_ONE);
    $self->assert_plan(['GlobOne', '!GlobOne.zz*'], \@GLOB_ONE);
}

sub test_root_shadowing ($self)
{
    # Shared exists in both roots, and the earlier root wins ...
    $self->assert_plan(['Shared'], [qw(Alpha::Shared.from_alpha)]);
    $self->assert_plan(['Beta::Shared'], [qw(Alpha::Shared.from_alpha)]);

    # ... so the only way to name the other one is in full
    $self->assert_plan(['Cassandane::Fixture::TestPlan::Beta::Shared'],
                       [qw(Beta::Shared.from_beta)]);

    # A leading component that doesn't resolve is dropped rather than being
    # treated as a constraint, so naming a root doesn't confine a glob to it.
    $self->assert_plan(['Alpha::Glob*'], \@GLOB_STAR);
}

sub test_plus_stands_in_for_star ($self)
{
    # '+' means '*' wherever a '*' could have gone, because '*' can't be typed
    # unquoted at a shell prompt
    $self->assert_plan(['Glob+'], \@GLOB_STAR);
    $self->assert_plan(['+'], \@EVERYTHING);
    $self->assert_plan(['GlobOne.b+'], [qw(Alpha::GlobOne.beta)]);
    $self->assert_plan(['Glob+.alpha'],
                       [qw(Alpha::GlobOne.alpha
                           Alpha::GlobTwo.alpha
                           Beta::GlobThree.alpha)]);
    $self->assert_plan(['Glob+', '!Glob+.alpha'],
                       [qw(Alpha::GlobOne.beta
                           Alpha::GlobOne.gamma_slow
                           Alpha::GlobTwo.delta)]);

    # the two spellings are interchangeable within one specification
    $self->assert_plan(['Glob+.b*'], [qw(Alpha::GlobOne.beta)]);
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

sub test_unmatched_test_dies ($self)
{
    # Selecting nothing is nearly always a typo, and a run that plans no tests
    # looks just like a run where everything passed.
    $self->assert_plan_dies(['GlobOne.nonesuch'],
                            qr{No tests matched: GlobOne\.nonesuch});

    # a glob that matches nothing is exactly as suspicious
    $self->assert_plan_dies(['GlobOne.mm*'],
                            qr{No tests matched: GlobOne\.mm\*});

    # every bad specification is named, not just the first one found
    $self->assert_plan_dies(['GlobOne.nonesuch', 'GlobTwo.nonesuch'],
                            qr{No tests matched: GlobOne\.nonesuch, GlobTwo\.nonesuch});

    # a specification that matches, but is then denied, is not an error
    $self->assert_plan(['GlobOne.beta', '!GlobOne.beta'], []);
}

sub test_slow_flags ($self)
{
    # asking for a whole suite isn't asking for its slow tests
    $self->assert_slow_flag(['GlobOne'], 'skip_slow', 1);
    $self->assert_slow_flag(['GlobOne.beta'], 'skip_slow', 1);

    # but selecting only slow tests is, however you spell it
    $self->assert_slow_flag(['GlobOne.gamma_slow'], 'skip_slow', 0);
    $self->assert_slow_flag(['GlobOne.*_slow'], 'skip_slow', 0);
    $self->assert_slow_flag(['GlobOne.gamma*'], 'skip_slow', 0);

    # ... whereas selecting a mixture of slow and regular tests isn't
    $self->assert_slow_flag(['GlobOne.*'], 'skip_slow', 1);

    # ... and neither is denying a slow test
    $self->assert_slow_flag(['GlobOne', '!GlobOne.gamma_slow'], 'skip_slow', 1);

    # slow_only works the same way, in reverse
    $self->assert_slow_flag(['GlobOne.beta'], 'slow_only', 0, slow_only => 1);
    $self->assert_slow_flag(['GlobOne.*a'], 'slow_only', 0, slow_only => 1);
    $self->assert_slow_flag(['GlobOne.gamma_slow'], 'slow_only', 1,
                            slow_only => 1);
    $self->assert_slow_flag(['GlobOne.*'], 'slow_only', 1, slow_only => 1);
}

1;

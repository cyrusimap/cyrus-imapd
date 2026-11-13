# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Util::JMAPTestSuiteSkips;
use strict;
use warnings;
use v5.28;

use Exporter ();
our @ISA = qw(Exporter);
our @EXPORT = qw(
    &jmaptestsuite_skips
);

use Cassandane::Instance;

# The JMAP-TestSuite tests that Cassandane doesn't run, shared by the HTTP
# and WebSocket suites.

# Tests for behaviour that has changed over time, where older releases
# contain the older behaviour and can no longer pass the updated test.
# The value is the first version number that is supposed to work.
# Same as the :min_version annotations on native Cassandane tests, but
# dot-separated.  See skip_before() below for implementation details.
my %notbefore = (
    't:Email:get:header-header-field-name' => '3.5',
    't:Email:import:good-imports' => '3.8',
    't:Email:import:one-fails-another-succeeds' => '3.8',
    't:core:jmap-session-resource' => '3.13',
);

# Tests which JMAP-TestSuite will skip anyway when it detects it's
# talking to Cyrus.
my %notcyrus = map { $_ => 1 } (
    't:Mailbox:get:no-existing-entities',
    't:Mailbox:query:no-existing-entities',
);

# Tests for behaviour Cyrus differs on by design.  identityId is optional
# (a redirect has none) and goes to the submission server unchecked.
my %cyrusdiffers = map { $_ => 1 } (
    't:EmailSubmission:set:missing-required',
    't:EmailSubmission:set:unknown-references',
);

# Tests Cyrus fails with some JMAP-TestSuite version.  Remove an entry once
# Cyrus passes it with every suite version in use.
my %cyrusfails = map { $_ => 1 } (
    't:Email:foreign-account',    # older suites expect accountNotFound
);

# n.b. similar to _skip_version() in Cassandane::Unit::TestSuite
sub skip_before
{
    my ($lim) = @_;

    my ($lim_major, $lim_minor, $lim_revision, $lim_commits)
        = map { 0 + $_ } split /\./, $lim;
    return if not defined $lim_major;

    my ($major, $minor, $revision, $commits) =
        Cassandane::Instance->get_version();

    return 1 if $major < $lim_major; # too old, skip!
    return if $major > $lim_major;   # definitely new enough

    return if not defined $lim_minor; # don't check deeper if caller doesn't care
    return 1 if $minor < $lim_minor;
    return if $minor > $lim_minor;

    return if not defined $lim_revision;
    return 1 if $revision < $lim_revision;

    return if not defined $lim_commits;
    return 1 if $commits < $lim_commits;

    return;
}

# True if Cassandane shouldn't run the named test, e.g. 't:Email:get:basic'
sub jmaptestsuite_skips
{
    my ($name) = @_;

    return 1 if $notcyrus{$name} || $cyrusdiffers{$name} || $cyrusfails{$name};
    return 1 if exists $notbefore{$name} && skip_before($notbefore{$name});
    return 0;
}

1;

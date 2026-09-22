# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Unit::TestCase;
use strict;
use warnings;

# We need 0.29 because of a fix for exception handling
use Test::Unit 0.29 ();

use base qw(Test::Unit::TestCase);
use Data::Dumper;
use DateTime;
use DateTime::Format::ISO8601;
use Carp ();
use Error ();

use Cassandane::Failure;
use Cassandane::Util::Log;
use Cassandane::Util::TestUrl;

my $buildinfo;

sub new
{
    my $class = shift;
    if (not $buildinfo) {
        $buildinfo = Cassandane::BuildInfo->new();
    }
    return $class->SUPER::new(@_);
}

sub _skip_version
{
    my ($str) = @_;

    return if not $str =~ m/^(min|max)_(other_)?version_([\d_]+)$/;
    my $minmax = $1;
    my $installation = ($2 ? 'other' : 'default');
    my ($lim_major, $lim_minor, $lim_revision, $lim_commits)
        = map { 0 + $_ } split /_/, $3;
    return if not defined $lim_major;

    my ($major, $minor, $revision, $commits)
        = Cassandane::Instance->get_version($installation);

    if ($minmax eq 'min') {
        return 1 if $major < $lim_major; # too old, skip!
        return if $major > $lim_major;   # definitely new enough

        return if not defined $lim_minor; # don't check deeper if caller doesn't care
        return 1 if $minor < $lim_minor;
        return if $minor > $lim_minor;

        return if not defined $lim_revision;
        return 1 if $revision < $lim_revision;

        return if not defined $lim_commits;
        return 1 if $commits < $lim_commits;
    }
    else {
        return 1 if $major > $lim_major; # too new, skip!
        return if $major < $lim_major;   # definitely old enough

        return if not defined $lim_minor; # don't check deeper if caller doesn't care
        return 1 if $minor > $lim_minor;
        return if $minor < $lim_minor;

        return if not defined $lim_revision;
        return 1 if $revision > $lim_revision;

        return if not defined $lim_commits;
        return 1 if $commits > $lim_commits;
    }

    return;
}

# Returns why this build can't run the test, or nothing if it can.
sub is_feature_missing
{
    my ($self, $category, $key, $want_value) = @_;

    if (defined $want_value) {
        my $actual = $buildinfo->get($category, $key);
        return "$category.$key is '$actual', not '$want_value'"
            if $actual ne $want_value;
    }
    elsif (not $buildinfo->get($category, $key)) {
        return "$category.$key is not enabled";
    }

    return;
}

sub filter
{
    my ($self) = @_;
    return
    {
        # A filter returns why the test should be skipped, or nothing if it
        # should run.  The reason is reported, so write it for a reader.
        skip_version => sub
        {
            return if not exists $self->{_name};
            my $sub = $self->can($self->{_name});
            return if not defined $sub;
            foreach my $attr (attributes::get($sub)) {
                next if $attr !~ m/^(?:min|max)_(?:other_)?version_[\d_]+$/;
                return "this Cyrus does not satisfy :$attr"
                    if _skip_version($attr);
            }
            return;
        },
        skip_missing_features => sub
        {
            return if not exists $self->{_name};
            my $sub = $self->can($self->{_name});
            return if not defined $sub;
            foreach my $attr (attributes::get($sub)) {
                next if $attr !~
                    m/^needs_([A-Za-z0-9]+)_(\w+)(?:\(([^\)]*)\))?$/;
                my $missing = $self->is_feature_missing($1, $2, $3);
                return $missing if $missing;
            }
            return if not exists $self->{needs};
            while (my ($category, $subhash) = each %{$self->{needs}}) {
                while (my ($key, $want_value) = each %{$subhash}) {
                    my $missing = $self->is_feature_missing($category,
                                                            $key,
                                                            $want_value);
                    return $missing if $missing;
                }
            }
            return;
        },
        skip_slow => sub
        {
            my ($method) = @_;
            return 'test is slow, and slow tests were not requested'
                if $method =~ m/_slow$/;
            return;
        },
        slow_only => sub
        {
            my ($method) = @_;
            return 'test is not slow, and only slow tests were requested'
                if $method !~ m/_slow$/;
            return;
        },
        skip_runtime_check => sub
        {
            # To use: add a skip_check method to your test suite that
            # implements logic to determine whether some test should run or
            # not (perhaps by examining $self->{_name}).  Return undef if
            # the test should run, or a message explaining why the test is
            # being skipped
            return if not $self->can('skip_check');
            my $reason = $self->skip_check();
            return "skip_check said '$reason'" if $reason;
            return;
        },
    };
}

sub annotate_from_file
{
    my ($self, $filename) = @_;
    return if !defined $filename;

    open LOG, '<', $filename
        or die "Cannot open $filename for reading: $!";
    while (<LOG>)
    {
        $self->annotate($_);
    }
    close LOG;
}

# Report that the test failed.  Every assertion below ends up here.
#
# $Error::Depth is how many frames Error.pm climbs before deciding where the
# failure happened, and it decides both the reported line and where the stack
# trace starts.  fail() blames whoever called it, so an assertion calling
# fail() adds one to the depth first, and the test that called the assertion
# gets the blame rather than this file.
sub fail
{
    my ($self, @message) = @_;

    local $Error::Depth = $Error::Depth + 1;
    Cassandane::Failure->throw(-text => join(q{}, @message));
}

sub assert
{
    my ($self, $bool, @message) = @_;

    return 1 if $bool;

    local $Error::Depth = $Error::Depth + 1;
    $self->fail(@message ? @message : 'Boolean assertion failed');
}

sub assert_str_equals
{
    my ($self, $expected, $actual, @message) = @_;

    local $Error::Depth = $Error::Depth + 1;

    if (not defined $expected) {
        $self->fail(@message ? @message : 'expected value was undef; should be using assert_null?');
    }

    if (not defined $actual) {
        $self->fail(@message ? @message : "expected '$expected', got undef");
    }

    if ($expected ne $actual) {
        $self->fail(@message ? @message : "expected '$expected', got '$actual'");
    }

    return 1;
}

sub assert_str_not_equals
{
    my ($self, $expected, $actual, @message) = @_;

    local $Error::Depth = $Error::Depth + 1;

    if (not defined $expected) {
        $self->fail(@message ? @message : 'expected value was undef; should be using assert_not_null?');
    }

    if (not defined $actual) {
        $self->fail(@message ? @message : "expected a string ne '$expected', got undef");
    }

    if ($expected eq $actual) {
        $self->fail(@message ? @message : "'$expected' and '$actual' should differ");
    }

    return 1;
}

sub assert_num_equals
{
    my ($self, $expected, $actual, @message) = @_;

    local $Error::Depth = $Error::Depth + 1;

    # an empty or non-numeric string compares as 0 rather than warning about it
    no warnings 'numeric';

    if (not defined $expected) {
        $self->fail(@message ? @message : 'expected value was undef; should be using assert_null?');
    }

    if (not defined $actual) {
        $self->fail(@message ? @message : "expected '$expected', got undef");
    }

    if ($expected != $actual) {
        $self->fail(@message ? @message : "expected $expected, got $actual");
    }

    return 1;
}

sub assert_num_not_equals
{
    my ($self, $expected, $actual, @message) = @_;

    local $Error::Depth = $Error::Depth + 1;

    no warnings 'numeric';

    if (not defined $expected) {
        $self->fail(@message ? @message : 'expected value was undef; should be using assert_not_null?');
    }

    if (not defined $actual) {
        $self->fail(@message ? @message : "expected a number != '$expected', got undef");
    }

    if ($expected == $actual) {
        $self->fail(@message ? @message : "$expected and $actual should differ");
    }

    return 1;
}

# This is irritating inherited behavior from Test::Unit, and I'd like to be
# able to ditch it.  In Test::Unit's assert_equals, a value that numifies to
# something other than zero, or that really is zero, is a number;
# so is an object that overloads '=='.  Everything else is a string.
sub _compare_numerically
{
    my ($value) = @_;

    {
        no warnings 'numeric';
        return 1 if $value == 0 ? $value =~ m/^\s*[+-]?0(e0)?\s*$/i : 1;
    }

    if (ref $value && eval { $value->isa('UNIVERSAL') }) {
        require overload;
        return 1 if overload::Method($value, '==');
    }

    return;
}

sub assert_equals
{
    my ($self, $expected, $actual, @message) = @_;

    local $Error::Depth = $Error::Depth + 1;

    return 1 if not defined $expected and not defined $actual;

    $self->fail(@message ? @message : 'one arg was not defined')
        if not defined $expected or not defined $actual;

    return _compare_numerically($expected)
        ? $self->assert_num_equals($expected, $actual, @message)
        : $self->assert_str_equals($expected, $actual, @message);
}

sub assert_not_equals
{
    my ($self, $expected, $actual, @message) = @_;

    local $Error::Depth = $Error::Depth + 1;

    $self->fail(@message ? @message : 'both args were undefined')
        if not defined $expected and not defined $actual;

    return 1 if not defined $expected or not defined $actual;

    return _compare_numerically($expected)
        ? $self->assert_num_not_equals($expected, $actual, @message)
        : $self->assert_str_not_equals($expected, $actual, @message);
}

sub assert_null
{
    my ($self, $actual, @message) = @_;

    return 1 if not defined $actual;

    local $Error::Depth = $Error::Depth + 1;
    $self->fail(@message ? @message : "$actual is defined");
}

sub assert_not_null
{
    my ($self, $actual, @message) = @_;

    return 1 if defined $actual;

    local $Error::Depth = $Error::Depth + 1;
    $self->fail(@message ? @message : '<undef> unexpected');
}

# n.b. it's okay for unexpected bits to also be set!
# if you need to test that ONLY specific bits are set, try:
#
#   assert_bits_set($want, $got);
#   assert_bits_not_set(~$want, $got);
#
sub assert_bits_set
{
    my ($self, $expected_bits, $actual_bitfield) = @_;

    # force args to be numeric
    # XXX use feature 'bitwise';
    $expected_bits += 0;
    $actual_bitfield += 0;

    my $fail_msg = sprintf("%#.8b does not have all of %#.8b bits set",
                           $actual_bitfield, $expected_bits);

    $self->assert((($actual_bitfield & $expected_bits) == $expected_bits),
                  $fail_msg);
}

sub assert_bits_not_set
{
    my ($self, $expected_bits, $actual_bitfield) = @_;

    # force args to be numeric
    # XXX use feature 'bitwise';
    $expected_bits += 0;
    $actual_bitfield += 0;

    my $fail_msg = sprintf("%#.8b has some of %#.8b bits set",
                           $actual_bitfield, $expected_bits);

    $self->assert((($actual_bitfield & $expected_bits) == 0), $fail_msg);
}

sub assert_num_gte
{
    my ($self, $expected, $actual) = @_;

    $self->assert(($actual >= $expected),
                  "$actual is not greater-than-or-equal-to $expected");
}

sub assert_num_lte
{
    my ($self, $expected, $actual) = @_;

    $self->assert(($actual <= $expected),
                  "$actual is not less-than-or-equal-to $expected");
}

sub assert_num_gt
{
    my ($self, $expected, $actual) = @_;

    $self->assert(($actual > $expected),
                  "$actual is not greater-than $expected");
}

sub assert_num_lt
{
    my ($self, $expected, $actual) = @_;

    $self->assert(($actual < $expected),
                  "$actual is not less-than $expected");
}

# override assert_matches from Test::Unit:Assert, whose default failure
# message is very hard to read in common cases
sub assert_matches
{
    my ($self, $pattern, $string, @rest) = @_;
    my $message;
    my $multiline;

    die "pattern is not a regular expression"
        if lc ref($pattern) ne 'regexp';

    if (@rest) {
        $message = join('', @rest);
    }
    elsif ($string =~ m/\n./) {
        $multiline = 1;
        $message = "pattern /$pattern/ did not match [multiline string]";
    }
    else {
        $message = "pattern /$pattern/ did not match string \"$string\"";
    }

    my $matches = $string =~ m/$pattern/;
    if (!$matches && $multiline) {
        xlog "assert_matches: multiline string:\n" . $string;
    }
    $self->assert($matches, $message);
}

# override assert_does_not_match from Test::Unit:Assert, whose default failure
# message is very hard to read in common cases
sub assert_does_not_match
{
    my ($self, $pattern, $string, @rest) = @_;
    my $message;
    my $multiline;

    die "pattern is not a regular expression"
        if lc ref($pattern) ne 'regexp';

    if (@rest) {
        $message = join('', @rest);
    }
    elsif ($string =~ m/\n./) {
        $multiline = 1;
        $message = "pattern /$pattern/ unexpectedly matched [multiline string]";
    }
    else {
        $message = "pattern /$pattern/ unexpectedly matched string \"$string\"";
    }

    my $matches = $string =~ m/$pattern/;
    if ($matches && $multiline) {
        xlog "assert_does_not_match: multiline string:\n" . $string;
    }
    $self->assert(!$matches, $message);
}

sub assert_date_matches
{
    my ($self, $expected, $actual, $tolerance) = @_;

    my ($expected_dt, $expected_str, $actual_dt, $actual_str);

    # $expected may be a DateTime object or an ISO8601 string
    my $reftype = ref $expected;
    if (not $reftype) {
        $expected_str = $expected;
        $expected_dt = DateTime::Format::ISO8601->parse_datetime($expected);
    }
    elsif ($reftype ne 'DateTime') {
        die "wanted string or 'DateTime' for expected, got '$reftype'";
    }
    else {
        $expected_dt = $expected;
        $expected_str = $expected_dt->stringify();
    }

    # $actual may be a DateTime object or an ISO8601 string
    $reftype = ref $actual;
    if (not $reftype) {
        $actual_str = $actual;
        $actual_dt = DateTime::Format::ISO8601->parse_datetime($actual);
    }
    elsif ($reftype ne 'DateTime') {
        die "wanted string or 'DateTime' for actual, got '$reftype'";
    }
    else {
        $actual_dt = $actual;
        $actual_str = $actual_dt->stringify();
    }

    # $tolerance is in seconds, default 0
    $tolerance //= 0;

    # XXX here is where to check that timezones match:
    # XXX * if one has a timezone and the other doesn't, fail
    # XXX * if both have timezones but they're different, fail
    # XXX otherwise, carry on...

    my $diff = $expected_dt->epoch() - $actual_dt->epoch();

    my $msg = "expected '$expected_str', got '$actual_str'";
    if ($tolerance) {
        $msg .= " (difference $diff is greater than $tolerance)";
    }

    $self->assert((abs($diff) <= $tolerance), $msg);
}

sub assert_file_test
{
    my ($self, $path, $test_type) = @_;

    # see `perldoc -f -X` for valid test types
    $test_type ||= '-e';
    my $test = "$test_type \$path";
    xlog "XXX test=<$test> path=<$path>";
    my $result = eval $test;
    die $@ if $@;
    $self->assert($result, "'$path' failed '$test_type' test");
}

sub assert_not_file_test
{
    my ($self, $path, $test_type) = @_;

    # see `perldoc -f -X` for valid test types
    $test_type ||= '-e';
    my $test = "$test_type \$path";
    xlog "XXX test=<$test> path=<$path>";
    my $result = eval $test;
    die $@ if $@;
    $self->assert(!$result,
                  "'$path' unexpectedly passed '$test_type' test");
}

sub assert_deep_equals
{
    Carp::confess('assert_deep_equals is gone; call assert_cmp_deeply instead');
}

sub assert_cmp_deeply
{
    my ($self, $expected, $actual, $desc) = @_;
    $desc ||= "deep comparison matched";

    require Test::Deep;
    require Test::Deep::JType;

    no warnings 'once';
    local $Test::Deep::LeafWrapper = sub { Test::Deep::JType::_String->new(@_) };
    use warnings 'once';

    my ($ok, $stack) = Test::Deep::cmp_details($actual, $expected);

    if ($ok) {
        return $self->assert(1, $desc);
    }

    my ($package, $filename, $line) = caller;

    my $diag = join qq{\n},
               "deep comparison failed at $filename, line $line, $desc:\n",
               Test::Deep::deep_diag($stack);

    return $self->assert(0, $diag);
}

sub assert_contains
{
    my ($self, $needle, $haystack, $expect_count) = @_;

    my $actual_count = 0;

    if (not defined $haystack) {
        $self->assert($expect_count == 0,
                      "needle '$needle' not found in undef haystack");
        return;
    }

    die 'haystack is not an ARRAY reference: '
        if ref $haystack ne 'ARRAY';

    my $needle_string;
    my $haystack_string = q{(}
                          . join(q{, }, map { "'$_'" } @{$haystack})
                          . q{)};

    if (not defined $needle) {
        $needle_string = 'undef';
        $actual_count = scalar grep { not defined $_ } @{$haystack};
    }
    elsif (ref $needle eq '') {
        $needle_string = "'$needle'";
        $actual_count = scalar grep { $needle eq $_ } @{$haystack};
    }
    elsif (ref $needle eq 'CODE') {
        $needle_string = 'needle()';
        # count is how many elements the function returns true for
        $actual_count = scalar grep { $needle->($_) } @{$haystack};
    }
    elsif (lc ref $needle eq 'regexp') { # may be REGEXP or Regexp
        $needle_string = $needle;
        $actual_count = scalar grep { m/$needle/ } @{$haystack};
    }
    else {
        die 'needle is not a scalar, CODE reference, or REGEXP reference';
    }

    if (defined $expect_count) {
        my $message = "expected $expect_count $needle_string"
                      . " but got $actual_count in $haystack_string";
        $self->assert($actual_count == $expect_count, $message);
    }
    else {
        my $message = "$needle_string not found in $haystack_string";
        $self->assert($actual_count > 0, $message);
    }
}

sub assert_not_contains
{
    my ($self, $needle, $haystack) = @_;

    $self->assert_contains($needle, $haystack, 0);
}

sub new_test_url
{
    my ($self, $content_or_app) = @_;

    return Cassandane::Util::TestURL->new({
        app => $content_or_app,
    });
}

1;

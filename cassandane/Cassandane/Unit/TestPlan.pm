# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Unit::TestPlan;
use strict;
use warnings;
use experimental 'signatures';

use File::Find;

use Cassandane::Cassini;
use Cassandane::Unit::TestSuite;

my @default_test_roots = (
    'Cassandane/Test',
    'Cassandane/Cyrus',
);

sub new
{
    my ($class, %opts) = @_;
    my $self = {
        test_roots => delete $opts{test_roots} // [ @default_test_roots ],
    };
    die "Unknown options: " . join(' ', keys %opts)
        if scalar %opts;
    return bless $self, $class;
}

# Turns a glob into an anchored regex.  '*' matches any run of characters,
# including none, and nothing else is special.
sub _glob_to_regex ($glob)
{
    my @hunks = split /\*+/, $glob, -1;
    my $regex = join q{.*}, map {; quotemeta } @hunks;

    return qr{\A$regex\z};
}

# Given a path whose last component may be a glob -- ".../Cyrus/JMAP*" --
# return the suite files it matches, in sorted order.  Returns nothing if
# there's no glob to expand, or if the directory that would hold the matches
# doesn't exist, so the caller can use this to ask "is this a globbed suite
# name?" without checking first.
sub _glob_suites ($path)
{
    my ($dir, $leaf) = ($path =~ m/^(.*)\/([^\/]+)$/);
    return if not defined $leaf;
    return if $leaf !~ m/\*/;
    return if not -d $dir;

    my $regex = _glob_to_regex($leaf);

    opendir my $dh, $dir
        or die "Cannot open directory $dir for reading: $!";
    my @moniker = grep {; my $m = $_; $m =~ s/\.pm$// and $m =~ $regex }
                  readdir $dh;
    closedir $dh;

    return map {; "$dir/$_" } sort @moniker;
}

# Returns a list of [ $neg, $ostype, $ospath, $testname ] tuples.  It's a list
# because one specification can name more than one test case.
#
# An exact name is resolved against the roots in order and the first hit wins,
# so that a test case in an earlier root shadows one of the same name later on.  A
# globbed test case name is instead collected from every root, because "JMAP*"
# plainly means all of them and not just the ones in whichever root happened to
# match first.
sub _parse_test_spec
{
    my ($self, $name) = @_;

    my ($neg, $path) = ($name =~ m/^([~!]?)(.*)$/);
    $path =~ s/\.pm$//g;
    $path =~ s/::/\//g;
    $path =~ s/\./\//g;
    $path =~ s/\/+/\//g;
    $path =~ s/^\/*//;
    $path =~ s/\/*$//;

    $neg = '!' if $neg eq '~';

    # '*' has to be quoted in every shell worth using, so let '+' mean the same
    # thing.  Neither suite names nor test names can contain a '+', so there's
    # no loss in functionality.
    $path =~ s/\+/*/g;

    # Allow Cyrus::TesterJMAP and TesterJMAP to work
    my @paths;

    my @dirs = split('/', $path);

    while (@dirs) {
        push @paths, join('/', @dirs);
        shift @dirs;
    }

    foreach my $candidate (@paths) {
        my @globbed;

        foreach my $root ($self->{test_roots}->@*)
        {
            return [ $neg, q{d}, $candidate, undef ]
                if ($root eq $candidate);

            my $fpath = $candidate;
            $fpath = "$root/$candidate"
                if ("$root/" ne substr($candidate, 0, length($root)+1));

            return [ $neg, q{d}, $fpath, undef ]
                if ( -d $fpath );
            return [ $neg, q{f}, "$fpath.pm", undef ]
                if ( -f "$fpath.pm" );

            # the whole thing may be a globbed suite name, with no test named
            push @globbed, map {; [ $neg, q{f}, $_, undef ] }
                           _glob_suites($fpath);

            my $test;
            ($fpath, $test) = ($fpath =~ m/^(.*)\/([^\/]+)$/);
            next unless defined $test;

            $test = _glob_to_regex($test) if $test =~ m/\*/;

            return [ $neg, q{f}, "$fpath.pm", $test ]
                if ( -f "$fpath.pm" );

            # ... or the suite part alone may be globbed, with a test after it
            push @globbed, map {; [ $neg, q{f}, $_, $test ] }
                           _glob_suites($fpath);
        }

        return @globbed if @globbed;
    }

    die "Unrecognised test specification: $name";
}

sub _default_test_list
{
    my ($self) = @_;

    my $cassini = Cassandane::Cassini->instance();
    my @tosuppress = split /\s+/, $cassini->val('cassandane', 'suppress', '');

    my %default;
    my %suppressed;
    @default{$self->{test_roots}->@*} = ();

    # skip suppressions
    foreach my $s (@tosuppress) {
        if (exists $default{$s}) {
            # if it's named explicitly in the default list, un-name it
            delete $default{$s};
        }
        else {
            # otherwise, add a negation for it
            $suppressed{"!$s"} = undef;
        }
    }

    die "no default tests" if not scalar keys %default;
    return (sort(keys %default), sort(keys %suppressed));
}

# The names to plan for.  Naming nothing means the default roots; naming only
# things to leave out means the default roots minus those.
sub _names_to_plan ($self, @names)
{
    return $self->_default_test_list()
        if not scalar @names;

    return ($self->_default_test_list(), @names)
        if not scalar grep {; m/^[^!~]/ } @names;

    return @names;
}

# The .pm files directly under a directory a specification named.
sub _suite_files_in ($dir)
{
    opendir my $dh, $dir
        or die "Cannot open directory $dir for reading: $!";
    my @files = grep {; m/\.pm$/ } readdir $dh;
    closedir $dh;

    return map {; "$dir/$_" } @files;
}

# One specification, resolved into rules: which suites it names, which test
# within them if it names one, and whether it is taking them away rather than
# asking for them.  One specification makes several rules when its suite part
# is a glob, or when it names a directory.
sub _rules_for ($self, $name)
{
    my @rules;

    foreach my $found ($self->_parse_test_spec($name))
    {
        my ($neg, $type, $path, $test) = @$found;

        foreach my $file ($type eq 'd' ? _suite_files_in($path) : $path)
        {
            # The base class lives among the suites but isn't one.
            next if $file =~ m{/TestSuite\.pm$};

            push @rules, {
                spec  => $name,
                deny  => ($neg eq '!'),
                suite => ($file =~ s/\.pm$//r =~ s{/}{::}gr),
                test  => $test,
            };
        }
    }

    return @rules;
}

# The class a suite's tests live in, loaded the first time it's wanted.  Only
# the suites some specification named are ever loaded.
sub _load_suite ($suite)
{
    my $file = ($suite =~ s{::}{/}gr) . '.pm';
    require $file;

    die "$suite is not a Cassandane::Unit::TestSuite\n"
        if not $suite->isa('Cassandane::Unit::TestSuite');

    return $suite;
}

# A rule's test part is a name or a glob's regex, and undef when the rule is
# about the whole suite.
sub _rule_covers ($rule, $test)
{
    return 1 if not defined $rule->{test};
    return $test =~ $rule->{test} if ref $rule->{test};
    return $test eq $rule->{test};
}

# Work out which tests @names asks for: an arrayref of {suite, testname}, in
# alphabetical order by suite and then by test.
#
# The rules, in the order they're applied to each test:
#
#   * a suite nothing asked for isn't in the plan at all
#   * a suite something denied outright is gone, however it was asked for
#   * if anything named tests in this suite, only the tests it named run
#   * a denied test doesn't run, whatever asked for it
#
# Denial always beats selection, whichever order they were given in.
sub plan_for ($self, @names)
{
    my @rules = map {; $self->_rules_for($_) } $self->_names_to_plan(@names);

    my @allow = grep {; ! $_->{deny} } @rules;
    my @deny  = grep {;   $_->{deny} } @rules;

    # A specification that named a test has to match one somewhere; remember
    # the ones to judge, in the order they were given.
    my (@judged, %matches);
    foreach my $rule (grep {; defined $_->{test} } @allow)
    {
        push @judged, $rule->{spec} if not exists $matches{ $rule->{spec} };
        $matches{ $rule->{spec} } //= 0;
    }

    my %wanted = map {; $_->{suite} => 1 } @allow;

    my @plan;
    foreach my $suite (sort keys %wanted)
    {
        my @allowed_here = grep {; $_->{suite} eq $suite } @allow;
        my @denied_here  = grep {; $_->{suite} eq $suite } @deny;

        next if grep {; ! defined $_->{test} } @denied_here;

        # Naming even one test in a suite means the rest of it isn't wanted,
        # even if something else asked for the whole suite.
        my @named = grep {; defined $_->{test} } @allowed_here;

        foreach my $test (sort map {; s/^test_//r } _load_suite($suite)->list_tests())
        {
            my @covering = grep {; _rule_covers($_, $test) } @named;
            $matches{ $_->{spec} }++ for @covering;

            next if @named && ! @covering;
            next if grep {; _rule_covers($_, $test) } @denied_here;

            push @plan, { suite => $suite, testname => $test };
        }
    }

    my @unmatched = grep {; ! $matches{$_} } @judged;
    die "No tests matched: " . join(q{, }, @unmatched) . "\n" if @unmatched;

    die "No tests to run: the test plan is empty\n" if not @plan;

    return \@plan;
}

sub check_sanity
{
    my ($self, %params) = @_;

    my $nonfatal = delete $params{nonfatal};

    # collect tiny-tests directories that are used by test modules
    my %used_tt_dirs;
    find({
        no_chdir => 1,
        wanted => sub {
            my $fname = $File::Find::name;

            return if not -f $fname;
            return if $fname !~ m/\.pm$/;

            my ($moniker) = $fname =~ m{([^/]+)\.pm$};

            open my $fh, '<', $fname or die "open $fname: $!";
            while (<$fh>) {
                if (m{^\s*use\s+Cassandane::Tiny::Loader;\s*$})
                {
                    push @{$used_tt_dirs{"tiny-tests/$moniker"}}, $fname;
                }
            }
            close $fh;
        },
    }, $self->{test_roots}->@*);

    # collect tiny-tests directories that exist on disk
    my %real_tt_dirs;
    find({
        no_chdir => 1,
        wanted => sub {
            my $fname = $File::Find::name;

            my ($tt, $suite, $test) = split q{/}, $fname, 3;
            return if not $suite;

            # ignore dot-dirs
            return if $suite =~ m{\A\.};

            if (not $test) {
                # explicit initialisation to detect directories with no files
                $real_tt_dirs{"$tt/$suite"} //= 0;
                return;
            }

            $real_tt_dirs{"$tt/$suite"} ++;
        },
    }, 'tiny-tests') if -d 'tiny-tests';

    my @tt_errors;

    # whinge about bad test modules
    while (my ($tt, $modules) = each %used_tt_dirs) {
        # XXX this one might not be an error if we start doing this
        # XXX intentionally, perhaps to run the same group of tests under
        # XXX different setups or configurations
        push @tt_errors, "@{$modules} share tiny-tests directory $tt"
            if scalar @{$modules} > 1;

        push @tt_errors, "$modules->[0] uses nonexistent tiny-tests directory $tt"
            if not exists $real_tt_dirs{$tt};
    }

    # whinge about orphaned directories
    while (my ($tt, $ntests) = each %real_tt_dirs) {
        push @tt_errors, "$tt directory is not used by any tests"
            if not $used_tt_dirs{$tt};

        push @tt_errors, "$tt directory contains no tests"
            if not $ntests;
    }

    # whinge about 'tiny-tests' directories in unexpected places
    # start searching in the parent directory so that we're checking the
    # whole cyrus-imapd repository -- but not things in dot-dirs, because we
    # might use them (like cyrus-imapd.git/.claude/worktrees) for in-repo
    # worktrees.  A worktree will, of course, contain tiny-tests.
    my @unexpected_tt_dirs = grep {
        chomp;
        $_ ne '../cassandane/tiny-tests';
    } qx{find .. -path '../.*' -prune -o -type d -name tiny-tests -print};
    push @tt_errors, "unexpected extra tiny-tests directories: @unexpected_tt_dirs"
        if @unexpected_tt_dirs;

    if (@tt_errors) {
        print STDERR "$_\n" for @tt_errors;

        if ($nonfatal) {
            warn 'bad tiny-tests detected';
        }
        else {
            die 'bad tiny-tests detected';
        }
    }
}

1;

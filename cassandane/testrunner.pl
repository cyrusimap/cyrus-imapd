#!/usr/bin/perl
# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

=head1 NAME

testrunner.pl - run the Cassandane integration test suite

=head1 SYNOPSIS

    ./testrunner.pl [options] [testname...]

    ./testrunner.pl                     # run everything, 'prettier' output
    ./testrunner.pl Quota               # run the whole Quota suite
    ./testrunner.pl Quota.quotarename   # run one test
    ./testrunner.pl Admin Quota         # run several suites
    ./testrunner.pl ~Quota              # run everything *except* Quota
    ./testrunner.pl -l                  # list matching suites, don't run them

=head1 DESCRIPTION

This is the low-level runner for the Cassandane test suite.  If you just want
to run the tests, you almost certainly want C<cyd test> (inside the container)
or C<dar test> (from the host), which builds Cyrus, provisions a
F<cassandane.ini>, and drops to the C<cyrus> user before handing off to this
script.  Reach for C<testrunner.pl> directly only when you need something
C<cyd test> doesn't expose, or when you're debugging the runner itself.  In
other words: by the time you're typing C<./testrunner.pl>, you've opted into
hard mode.

A few things worth knowing before you do:

=over 4

=item *

Cassandane runs out of its own directory; nothing gets installed.  Run this
script with the F<cassandane/> directory as your working directory.

=item *

The Cyrus code under test must run as the superuser or as the C<cyrus> user.
You invoke C<testrunner.pl> as yourself; if you're root it steps down to
C<cyrus>, and otherwise it re-invokes itself under C<sudo>.

=item *

All runtime state lives under the C<rootdir> from F<cassandane.ini> (by
default F</var/tmp/cass>).  A list of the tests that failed is left in
F<$rootdir/failed> (this is what C<--rerun> reads), and C<-f prettier> writes
full error reports for failed tests under F<$rootdir/reports>.

=item *

Before running anything, the script checks that Cassandane's own helper
binaries (listed in F<utils/Makefile>) have been built, and bails out telling
you to run C<make> if they haven't.

=back

=head1 SELECTING TESTS

With no test names, every test is run.  Otherwise, name what you want:

=over 4

=item *

a whole suite by its name without the leading C<Cassandane::Cyrus::>, e.g.
C<Quota>;

=item *

a single test as C<Suite.test>, e.g. C<Quota.quotarename>.

=back

Names accumulate left to right, and any name may be negated by prefixing it
with C<!> or C<~>.  (Your shell probably wants C<!> escaped, so C<~> is usually
easier.)  So C<Quota ~Quota.quotarename> runs the whole Quota suite except
C<quotarename>, and C<~Quota> runs everything but the Quota suite.

For convenience, a single argument may contain several whitespace-separated
names.

=head1 OPTIONS

Run C<./testrunner.pl --help> for the authoritative, self-documenting list.
The options most worth knowing about:

=over 4

=item B<-f>, B<--format> I<FORMAT>

Choose a test report format; repeatable.  The formats are:

=over 4

=item C<prettier> (the default)

One line per test with its status, quiet about the details of failures.  Best
for running many tests: see F<$rootdir/failed> and F<$rootdir/reports>
afterward for the gory details.

=item C<pretty>

Like C<prettier>, but dumps each failure's error report inline.  Noisy in bulk;
handy when debugging a single test, especially with C<-vvv>.

=item C<tap>

Test Anything Protocol.  Rudimentary, but should be valid TAP.

=item C<xml>

jUnit-style XML, written to a F<reports/> subdirectory of the current
directory.  (Not the same F<reports> as C<prettier> uses.)  Useful for some CI
systems; our GitHub CI doesn't use it.

=back

=item B<-v>, B<--verbose>

Make Cassandane and several of the Cyrus programs it runs much noisier on
stderr.  Repeatable, and the short form stacks: C<-vvv>.

=item B<--valgrind>

Run every Cyrus executable under Valgrind.  Much slower, but it catches a lot
of subtle bugs.  Per-test logs land in F<$rootdir/$instance/vglogs/>, and any
error Valgrind reports (leaks included) fails the test.

=item B<-c>, B<--cleanup>[=I<yes|no|pre|post>]

Clean up C<$rootdir> leftovers before the run and after each passing test.
Useful when disk (e.g. a tmpfs) is tight.  Bare C<--cleanup> means C<yes>.  If
you want this most of the time, set C<cassandane.cleanup> in F<cassandane.ini>
and use C<--no-cleanup> to override it.

=item B<-j>, B<--jobs> I<N>

Run I<N> test workers in parallel.

=item B<--slow>, B<--slow-only>

Also run (or run only) the tests marked slow, which are skipped by default.

=item B<--rerun>, B<--rerun-suite>

Rerun just the tests that failed last time (read from F<$rootdir/failed>).
C<--rerun-suite> reruns the whole suite of each such test.

=item B<-l>, B<--list>

List the matching tests instead of running them.  Repeat (C<-ll>) to list
individual tests rather than just suites.

=back

=cut

use strict;
use warnings;
use File::Slurp;
use Getopt::Long::Descriptive;
use List::Util qw(uniq);

use lib '.';
use Cassandane::Util::Setup;
use Cassandane::Unit::FormatPretty;
use Cassandane::Unit::FormatTAP;
use Cassandane::Unit::FormatXML;
use Cassandane::Unit::Runner;
use Cassandane::Unit::TestPlan;
use Cassandane::Util::Log;
use Cassandane::Cassini;
use Cassandane::Instance;

use Data::Dumper;
$Data::Dumper::Deepcopy = 1;
$Data::Dumper::Indent = 1;
$Data::Dumper::Sortkeys = 1;
$Data::Dumper::Trailingcomma = 1;

my %format_params = ();
my $output_dir = 'reports';
my @names;

# Make sure our binary components have been built already
# -- get their names from the Makefile
open my $mf, '<', 'utils/Makefile'
    or die "Can't read utils/Makefile: $!";
my $pat = qr{^(?:PROGRAMS|LIBS)=};
my $missing_binaries = 0;
foreach my $match (grep { m/$pat/ } <$mf>) {
    chomp $match;
    $match =~ s/$pat//;
    foreach my $binary (split /\s+/, $match) {
        my $filename = "utils/$binary";
        if (! -e $filename || ! -x $filename) {
            print STDERR "$filename is not executable or is missing\n";
            $missing_binaries ++;
        }
    }
}
close $mf;
if ($missing_binaries) {
    print STDERR "Did you run 'make' yet?\n";
    exit 1;
}

# This disgusting hack makes Test::Unit report a useful stack trace for
# it's assert failures instead of just a file name and line number.
{
    use Error;
    use Test::Unit::Exception;

    # We also convert string exceptions into Test::Unit errors.
    $SIG{__DIE__} = sub
    {
        my ($e) = @_;
        if (!ref($e))
        {
            my ($text, $file, $line) = ($e =~ m/^(.*) at (.*\.pm) line (\d+)/);
            if ($line)
            {
                local $Error::Depth = 1;
                Test::Unit::Error->throw('-text' => "Perl exception: $text\n");
            }
        }
        die @_;
    };

    # Disable the warning about redefining T:U:E:stringify.
    # We know what we're doing, dammit.
    no warnings;
    # This makes Error->new() capture a full stacktrace
    $Error::Debug = 1;
    *Test::Unit::Exception::stringify = sub
    {
        my ($self) = @_;
        my $s = '';

        my $o = $self->object;
        $s .= $o->to_string() . "\n " if $o && $o->can('to_string');

        # Note, -stacktrace includes -text

        my $st = $self->{-stacktrace};
        # Prune all Test::Unit internal calls
        $st =~ s/Test::Unit::TestCase::run_test.*/[...framework calls elided...]/s;
        $s .= $st;

        return $s;
    };
};

my %formatters = (
    tap => {
        writes_to_stdout => 1,
        formatter => sub {
            my ($params, $fh) = @_;
            return Cassandane::Unit::FormatTAP->new($fh);
        },
    },
    pretty => {
        writes_to_stdout => 1,
        formatter => sub {
            my ($params, $fh) = @_;
            $params->{quiet} = 0;
            return Cassandane::Unit::FormatPretty->new($params, $fh);
        },
    },
    prettier => {
        writes_to_stdout => 1,
        formatter => sub {
            my ($params, $fh) = @_;
            $params->{quiet} = 1;
            return Cassandane::Unit::FormatPretty->new($params, $fh);
        },
    },
    xml => {
        writes_to_stdout => 0,
        formatter => sub {
            my ($params, $fh) = @_;
            $params->{directory} = $output_dir;
            return Cassandane::Unit::FormatXML->new($params);
        },
    },
);

become_cyrus();

eval {
    if ( ! -d $output_dir ) {
        mkdir($output_dir)
            or die "Cannot make output directory \"$output_dir\": $!\n";
    }

    if (! -w $output_dir ) {
        die "Cannot write to output directory \"$output_dir\"\n";
    }
};
if ($@) {
    my $eval_err = $@;
    $formatters{xml}->{formatter} = sub {
        die "Sorry, XML output format not available due to:\n",
            "=> $eval_err";
    };
}

my ($opt, $usage) = describe_options(
    "%c %o [testname...]",

    [ 'format|f=s@',   "test report format, repeatable: xml, tap, pretty, or"
                     . " prettier (default: prettier)" ],
    [ 'list|l+',       "list matching tests instead of running them; repeat"
                     . " (-ll) to list individual tests, not just suites" ],
    [],
    [ 'jobs|j=i',      "run this many test workers in parallel" ],
    # The default really should be --no-keep-going like make
    [ 'keep-going|k!', "keep going after a test fails (default: yes)",
                       { default => 1 } ],
    [ 'stop|S',        "stop at the first failing test; same as --no-keep-going" ],
    [],
    [ 'slow',          "also run the tests marked slow" ],
    [ 'slow-only',     "run *only* the tests marked slow" ],
    [ 'rerun',         "rerun only the tests that failed on the previous run" ],
    [ 'rerun-suite',   "like --rerun, but rerun the whole suite of each failure" ],
    [],
    [ 'valgrind!',     "run every Cyrus executable under Valgrind (slow, thorough)" ],
    [ 'cleanup|c:s',   "clean up leftovers before the run and after each passing"
                     . " test: yes|no|pre|post (bare --cleanup means yes)" ],
    [ 'no-cleanup',    "never clean up leftovers (overrides --cleanup)" ],
    [],
    [ 'verbose|v+',    "make Cassandane and Cyrus much noisier; repeat (-vvv)"
                     . " for more (default: 0)", { default => 0 } ],
    [ 'no-ok',         "report only failures and errors, omitting passing tests" ],
    [ 'log-directory|L=s', "collect per-test logs under this directory" ],
    [ 'config=s',      "use this Cassandane config file instead of the default" ],
    [ 'define|D=s%',   "override one Cassandane config value: -Dsection.param=value" ],
    [],
    [ 'help|h',        "print this help message and exit" ],
);

sub usage {
    print STDERR $usage->text;
    exit 1;
}

if ($opt->help) {
    print $usage->text;
    exit 0;
}

my $cassini_filename = $opt->config;
my @cassini_overrides;

my %want_formats;
for my $format (@{ $opt->format // [] }) {
    usage() unless defined $formatters{$format};
    $want_formats{$format} = 1;
}

set_verbose(get_verbose() + $opt->verbose);

$format_params{no_ok} = 1 if $opt->no_ok;

my $do_list       = $opt->list // 0;
my $keep_going    = $opt->stop ? 0 : $opt->keep_going;
my $skip_slow     = ($opt->slow || $opt->slow_only) ? 0 : 1;
my $slow_only     = $opt->slow_only ? 1 : 0;
my $log_directory = $opt->log_directory;
my $want_rerun    = $opt->rerun_suite ? 2 : $opt->rerun ? 1 : 0;

if (defined $opt->jobs) {
    usage() unless $opt->jobs > 0;
    push @cassini_overrides, ['cassandane', 'maxworkers', $opt->jobs];
}

if (defined $opt->valgrind) {
    push @cassini_overrides,
        ['valgrind', 'enabled', $opt->valgrind ? 'yes' : 'no'];
}

push @cassini_overrides, ['cassandane', 'cleanup', 'no'] if $opt->no_cleanup;

if (defined $opt->cleanup) {
    my $v = $opt->cleanup eq '' ? 'yes' : $opt->cleanup;
    usage() unless grep { $v eq $_ } qw(yes no pre post);
    push @cassini_overrides, ['cassandane', 'cleanup', $v];
}

if (my $overrides = $opt->define) {
    for my $key (sort keys %$overrides) {
        my ($sec, $param) = split /\./, $key, 2;
        usage() unless length($sec // '') && length($param // '');
        push @cassini_overrides, [$sec, $param, $overrides->{$key}];
    }
}

push @names, map { split /\s+/, $_ } @ARGV;

my $cassini = Cassandane::Cassini->new(filename => $cassini_filename);
map { $cassini->override(@$_); } @cassini_overrides;

# pre-run cleanup
my $cleanup = $cassini->val('cassandane', 'cleanup', 'no');
if ($cleanup eq 'yes' or $cleanup eq 'pre') {
    Cassandane::Instance::cleanup_leftovers();
}

my $rootdir = $cassini->val('cassandane', 'rootdir', '/var/tmp/cass');
unless (-e $rootdir) {
    mkdir($rootdir)
        or die "Cannot make output directory \"$rootdir\": $!\n";
}

if ($want_rerun) {
    my $failed_file = "$rootdir/failed";

    my @failed = eval { read_file($failed_file, { chomp => 1 }) };
    if ($@) {
        print STDERR "Cannot --rerun without an existing failed file.\n";
        exit 1;
    }

    if (scalar @failed) {
        if ($want_rerun > 1) {
            # rerun whole suites for failed tests
            @failed = uniq sort map { s/\..*$//r } @failed;
        }
        push @names, @failed;
    }
    else {
        # prevent accidentally running everything by default!
        print STDERR "The failed file is empty; there is nothing to ",
                        "re-run.\n";
        exit 0;
    }
}

my $plan = Cassandane::Unit::TestPlan->new(
        keep_going => $keep_going,
        maxworkers => $cassini->val('cassandane', 'maxworkers') || undef,
        log_directory => $log_directory,
        skip_slow => $skip_slow,
        slow_only => $slow_only,
    );

if ($do_list)
{
    # Build the schedule per commandline
    $plan->schedule(@names);
    # dump the plan to stdout
    my %plan = map { _listitem($_) => 1 } $plan->list();
    foreach my $nm (sort keys %plan)
    {
        print "$nm\n";
    }
    exit 0;
}
else
{
    # Build the schedule per commandline
    $plan->schedule(@names);
    $plan->check_sanity();

    # Run the schedule
    $want_formats{prettier} = 1 if not scalar keys %want_formats;
    my @writes_to_stdout = grep {
        $formatters{$_}->{writes_to_stdout}
    } keys %want_formats;
    if (scalar @writes_to_stdout > 1) {
        my $joined = join ', ', map { "'$_'" } @writes_to_stdout;
        die "$joined formatters all want to write to stdout\n";
    }

    my @filters = qw(x skip_version skip_missing_features
                     skip_runtime_check
                     enable_wanted_properties);
    push @filters, 'skip_slow' if $plan->{skip_slow};
    push @filters, 'slow_only' if $plan->{slow_only};

    my $runner = Cassandane::Unit::Runner->new();
    foreach my $f (keys %want_formats) {
        my $formatter = $formatters{$f}->{formatter}->({%format_params});
        $runner->add_formatter($formatter);
    }
    $runner->filter(@filters);

    exit !$runner->do_run($plan);
}

sub _listitem {
    my $item = shift;
    $item =~ s/\..*// if ($do_list == 1);
    return $item;
}

#!/usr/bin/perl
#
#  Copyright (c) 2011 Opera Software Australia Pty. Ltd.  All rights
#  reserved.
#
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that the following conditions
#  are met:
#
#  1. Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#
#  2. Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.
#
#  3. The name "Opera Software Australia" must not be used to
#     endorse or promote products derived from this software without
#     prior written permission. For permission or any legal
#     details, please contact
#       Opera Software Australia Pty. Ltd.
#       Level 50, 120 Collins St
#       Melbourne 3000
#       Victoria
#       Australia
#
#  4. Redistributions of any form whatsoever must retain the following
#     acknowledgment:
#     "This product includes software developed by Opera Software
#     Australia Pty. Ltd."
#
#  OPERA SOFTWARE AUSTRALIA DISCLAIMS ALL WARRANTIES WITH REGARD TO
#  THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
#  AND FITNESS, IN NO EVENT SHALL OPERA SOFTWARE AUSTRALIA BE LIABLE
#  FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
#  WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
#  AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
#  OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#

use strict;
use warnings;
use File::Slurp;

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

my %want_formats = ();
my $output_dir = 'reports';
my $do_list = 0;
# The default really should be --no-keep-going like make
my $keep_going = 1;
my $skip_slow = 1;
my $slow_only = 0;
my $log_directory;
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
            my ($fh) = @_;
            return Cassandane::Unit::FormatTAP->new($fh);
        },
    },
    pretty => {
        writes_to_stdout => 1,
        formatter => sub {
            my ($fh) = @_;
            return Cassandane::Unit::FormatPretty->new({}, $fh);
        },
    },
    prettier => {
        writes_to_stdout => 1,
        formatter => sub {
            my ($fh) = @_;
            return Cassandane::Unit::FormatPretty->new({quiet=>1}, $fh);
        },
    },
    xml => {
        writes_to_stdout => 0,
        formatter => sub {
            my ($fh) = @_;
            return Cassandane::Unit::FormatXML->new({
                directory => $output_dir
            });
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

sub usage
{
    printf STDERR "Usage: testrunner.pl [options] -f <xml|tap|pretty|prettier> [testname...]\n";
    exit(1);
}

my $cassini_filename;
my @cassini_overrides;
my $want_rerun;

while (my $a = shift)
{
    if ($a eq '--config')
    {
        $cassini_filename = shift;
    }
    elsif ($a eq '-c' || $a eq '--cleanup')
    {
        push(@cassini_overrides, ['cassandane', 'cleanup', 'yes']);
    }
    elsif ($a eq '--no-cleanup')
    {
        push(@cassini_overrides, ['cassandane', 'cleanup', 'no']);
    }
    elsif ($a eq '-f')
    {
        my $format = shift;
        usage unless defined $formatters{$format};
        $want_formats{$format} = 1;
    }
    elsif ($a =~ m/^-f(\w+)$/)
    {
        my $format = $1;
        usage unless defined $formatters{$format};
        $want_formats{$format} = 1;
    }
    elsif ($a eq '-v' || $a eq '--verbose')
    {
        set_verbose(get_verbose()+1);
    }
    elsif ($a =~ m/^-v+$/)
    {
        # ganged verbosity
        set_verbose(get_verbose() + length($a) - 1);
    }
    elsif ($a eq '--valgrind')
    {
        push(@cassini_overrides, ['valgrind', 'enabled', 'yes']);
    }
    elsif ($a eq '--no-valgrind')
    {
        push(@cassini_overrides, ['valgrind', 'enabled', 'no']);
    }
    elsif ($a eq '-j' || $a eq '--jobs')
    {
        my $jobs = 0 + shift;
        usage unless $jobs > 0;
        push(@cassini_overrides, ['cassandane', 'maxworkers', $jobs]);
    }
    elsif ($a =~ m/^-j(\d+)$/)
    {
        my $jobs = 0 + $1;
        usage unless $jobs > 0;
        push(@cassini_overrides, ['cassandane', 'maxworkers', $jobs]);
    }
    elsif ($a eq '-L' || $a eq '--log-directory')
    {
        $log_directory = shift;
        usage unless defined $log_directory;
    }
    elsif ($a eq '-l' || $a eq '--list')
    {
        $do_list++;
    }
    elsif ($a eq '-k' || $a eq '--keep-going')
    {
        # These option names stolen from GNU make
        $keep_going = 1;
    }
    elsif ($a eq '-S' || $a eq '--stop' || $a eq '--no-keep-going')
    {
        # These option names stolen from GNU make
        $keep_going = 0;
    }
    elsif ($a =~ m/^-D.*=/)
    {
        my ($sec, $param, $val) = ($a =~ m/^-D([^.=]+)\.([^.=]+)=(.*)$/);
        push(@cassini_overrides, [$sec, $param, $val]);
    }
    elsif ($a eq '--slow')
    {
        $skip_slow = 0;
    }
    elsif ($a eq '--slow-only')
    {
        $skip_slow = 0;
        $slow_only = 1;
    }
    elsif ($a eq '--rerun')
    {
        $want_rerun = 1;
    }
    elsif ($a =~ m/^-/)
    {
        usage;
    }
    else
    {
        push(@names, split(/\s+/, $a));
    }
}

my $cassini = Cassandane::Cassini->new(filename => $cassini_filename);
map { $cassini->override(@$_); } @cassini_overrides;

Cassandane::Instance::cleanup_leftovers()
    if ($cassini->bool_val('cassandane', 'cleanup'));

if ($want_rerun) {
    my $rootdir = $cassini->val('cassandane', 'rootdir', '/var/tmp/cass');
    my $failed_file = "$rootdir/failed";

    my @failed = eval { read_file($failed_file, { chomp => 1 }) };
    if ($@) {
        print STDERR "Cannot --rerun without an existing failed file.\n";
        exit 1;
    }

    if (scalar @failed) {
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
        $runner->add_formatter($formatters{$f}->{formatter}->());
    }
    $runner->filter(@filters);

    exit !$runner->do_run($plan);
}

sub _listitem {
    my $item = shift;
    $item =~ s/\..*// if ($do_list == 1);
    return $item;
}

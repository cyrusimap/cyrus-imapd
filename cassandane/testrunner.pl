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
use Cassandane::Unit::Runner;
use Cassandane::Unit::RunnerPretty;
use Cassandane::Unit::TestPlan;
use Cassandane::Util::Log;
use Cassandane::Cassini;
use Cassandane::Instance;

use Data::Dumper;
$Data::Dumper::Deepcopy = 1;
$Data::Dumper::Indent = 1;
$Data::Dumper::Sortkeys = 1;
$Data::Dumper::Trailingcomma = 1;

my $format = 'prettier';
my $output_dir = 'reports';
my $do_list = 0;
# The default really should be --no-keep-going like make
my $keep_going = 1;
my $skip_slow = 1;
my $log_directory;
my @names;

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

my %runners =
(
    tap => sub
    {
        my ($plan, $fh) = @_;
        local *__ANON__ = "runner_tap";
        my $runner = Cassandane::Unit::Runner->new($fh);
        my @filters = qw(x skip_version skip_missing_features);
        push @filters, 'skip_slow' if $plan->{skip_slow};
        $runner->filter(@filters);
        return $runner->do_run($plan, 0);
    },
    pretty => sub
    {
        my ($plan, $fh) = @_;
        local *__ANON__ = "runner_pretty";
        my $runner = Cassandane::Unit::RunnerPretty->new({}, $fh);
        my @filters = qw(x skip_version skip_missing_features);
        push @filters, 'skip_slow' if $plan->{skip_slow};
        $runner->filter(@filters);
        return $runner->do_run($plan, 0);
    },
    prettier => sub
    {
        my ($plan, $fh) = @_;
        local *__ANON__ = "runner_prettier";
        my $runner = Cassandane::Unit::RunnerPretty->new({quiet=>1}, $fh);
        my @filters = qw(x skip_version skip_missing_features);
        push @filters, 'skip_slow' if $plan->{skip_slow};
        $runner->filter(@filters);
        return $runner->do_run($plan, 0);
    },
);

become_cyrus();

eval
{
    require Cassandane::Unit::RunnerXML;

    if ( ! -d $output_dir )
    {
        mkdir($output_dir)
            or die "Cannot make output directory \"$output_dir\": $!\n";
    }

    if (! -w $output_dir )
    {
        die "Cannot write to output directory \"$output_dir\"\n";
    }

    $runners{xml} = sub
    {
        my ($plan, $fh) = @_;
        local *__ANON__ = "runner_xml";

        my $runner = Cassandane::Unit::RunnerXML->new($output_dir);
        my @filters = qw(x skip_version skip_missing_features);
        push @filters, 'skip_slow' if $plan->{skip_slow};
        $runner->filter(@filters);
        $runner->start($plan);
        return $runner->all_tests_passed();
    };
};
if ($@) {
    my $eval_err = $@;
    $runners{xml} = sub
    {
        print STDERR "Sorry, XML output format not available due to:\n=> $eval_err";
        return 0;
    };
}

sub usage
{
    printf STDERR "Usage: testrunner.pl [options] -f <xml|tap|pretty|prettier> [testname...]\n";
    exit(1);
}

my $cassini_filename;
my @cassini_overrides;

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
        $format = shift;
        usage unless defined $runners{$format};
    }
    elsif ($a =~ m/^-f(\w+)$/)
    {
        $format = $1;
        usage unless defined $runners{$format};
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
    elsif ($a eq '--rerun')
    {
        my $cassini = Cassandane::Cassini::instance();
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
    elsif ($a =~ m/^-/)
    {
        usage;
    }
    else
    {
        push(@names, $a);
    }
}

my $cassini = Cassandane::Cassini->new(filename => $cassini_filename);
map { $cassini->override(@$_); } @cassini_overrides;

Cassandane::Instance::cleanup_leftovers()
    if ($cassini->bool_val('cassandane', 'cleanup'));

my $plan = Cassandane::Unit::TestPlan->new(
        keep_going => $keep_going,
        maxworkers => $cassini->val('cassandane', 'maxworkers') || undef,
        log_directory => $log_directory,
        skip_slow => $skip_slow,
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
    # Run the schedule
    open my $fh, '>&', \*STDOUT
        or die "Cannot save STDOUT as a runner print stream: $!";
    exit(! $runners{$format}->($plan, $fh));
}

sub _listitem {
    my $item = shift;
    $item =~ s/\..*// if ($do_list == 1);
    return $item;
}

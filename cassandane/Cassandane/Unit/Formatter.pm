# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Unit::Formatter;
use strict;
use warnings;

use base qw(Cassandane::Unit::Listener);

use Benchmark;
use Date::Format;
use IO::Handle;

sub new
{
    my ($class, $fh) = @_;

    $fh //= \*STDOUT;
    $fh->autoflush(1);

    return bless {
        fh => $fh,
    }, $class;
}

sub _print
{
    my ($self, @args) = @_;
    $self->{fh}->print(@args);
}

# To create a new output format, subclass from this and override the event
# handlers it cares about.  Cassandane::Unit::Listener has the whole set.

# A skipped test never ran, so it never started either: this is the only event
# a formatter hears about it.
# Override this with your output format's end-of-tests handling.  The
# default is to print a summary.
sub finished
{
    my ($self, $summary, $start_time, $end_time) = @_;
    $self->print_summary($summary, $start_time, $end_time);
}

# Override this, and/or subs print_header, print_errors, print_failures
# to change how the summary is presented.
sub print_summary
{
    my ($self, $summary, $start_time, $end_time) = @_;

    my $run_time = timediff($end_time, $start_time);

    print "\n";
    print "Time: ", timestr($run_time), "\n";
    print "Finished: ", time2str("%T", $end_time->real()), "\n";

    $self->print_header($summary);
    $self->print_errors($summary);
    $self->print_failures($summary);
}

sub print_header
{
    my ($self, $summary) = @_;

    my $skip_count = scalar $summary->{skips}->@*;
    my $skipped = $skip_count ? ", Skipped: $skip_count" : "";

    if ($summary->{was_successful}) {
        $self->_print("\n", "OK", " (", $summary->{run_count}, " tests",
                      $skip_count ? ", $skip_count skipped" : "",
                      ")\n");
    }
    else {
        $self->_print("\n", "!!!FAILURES!!!", "\n",
                      "Test Results:\n",
                      "Run: ", $summary->{run_count},
                      ", Failures: ", scalar $summary->{failures}->@*,
                      ", Errors: ", scalar $summary->{errors}->@*,
                      $skipped,
                      "\n");
    }
}

sub print_errors
{
    my ($self, $summary) = @_;

    return unless my $error_count = scalar $summary->{errors}->@*;

    my $msg = "\nThere " .
              ($error_count == 1 ?
                "was 1 error"
              : "were $error_count errors") .
              ":\n";
    $self->_print($msg);

    my $i = 0;
    for my $e ($summary->{errors}->@*) {
        chomp(my $report = $e->{report});
        $i++;
        $self->_print("$i) $report\n");
        $self->_print("\nAnnotations:\n", $e->{annotations})
          if $e->{annotations};
    }
}

sub print_failures
{
    my ($self, $summary) = @_;

    return unless my $failure_count = scalar $summary->{failures}->@*;

    my $msg = "\nThere " .
              ($failure_count == 1 ?
                "was 1 failure"
              : "were $failure_count failures") .
              ":\n";
    $self->_print($msg);

    my $i = 0;
    for my $f ($summary->{failures}->@*) {
        chomp(my $report = $f->{report});
        $self->_print("\n") if $i++;
        $self->_print("$i) $report\n");
        $self->_print("\nAnnotations:\n", $f->{annotations})
          if $f->{annotations};
    }
}

1;

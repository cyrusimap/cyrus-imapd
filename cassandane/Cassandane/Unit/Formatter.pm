# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Unit::Formatter;
use strict;
use warnings;

use base 'Test::Unit::Listener';
use Benchmark;
use Date::Format;
use IO::Handle;

sub new
{
    my ($class, $fh) = @_;

    $fh //= \*STDOUT;
    $fh->autoflush(1);

    return bless {
        remove_me_in_cassandane_child => 1,
        fh => $fh,
    }, $class;
}

sub _print
{
    my ($self, @args) = @_;
    $self->{fh}->print(@args);
}

# No-op implementations of Listener interface.  To create a new output
# format, subclass from this and override the appropriate event handlers

sub start_suite
{
    my ($self, $suite) = @_;
}

sub start_test
{
    my ($self, $test) = @_;
}

sub add_pass
{
    my ($self, $test) = @_;
}

sub add_error
{
    my ($self, $test, $exception) = @_;
}

sub add_failure
{
    my ($self, $test, $exception) = @_;
}

sub end_test
{
    my ($self, $test) = @_;
}

# Override this with your output format's end-of-tests handling.  The
# default is to print a summary.
sub finished
{
    my ($self, $result, $start_time, $end_time) = @_;
    $self->print_summary($result, $start_time, $end_time);
}

# Override this, and/or subs print_header, print_errors, print_failures
# to change how the summary is presented.
sub print_summary
{
    my ($self, $result, $start_time, $end_time) = @_;

    my $run_time = timediff($end_time, $start_time);

    print "\n";
    print "Time: ", timestr($run_time), "\n";
    print "Finished: ", time2str("%T", $end_time->real()), "\n";

    $self->print_header($result);
    $self->print_errors($result);
    $self->print_failures($result);
}

sub print_header
{
    my ($self, $result) = @_;

    if ($result->was_successful()) {
        $self->_print("\n", "OK", " (", $result->run_count(), " tests)\n");
    }
    else {
        $self->_print("\n", "!!!FAILURES!!!", "\n",
                      "Test Results:\n",
                      "Run: ", $result->run_count(),
                      ", Failures: ", $result->failure_count(),
                      ", Errors: ", $result->error_count(),
                      "\n");
    }
}

sub print_errors
{
    my ($self, $result) = @_;

    return unless my $error_count = $result->error_count();

    my $msg = "\nThere " .
              ($error_count == 1 ?
                "was 1 error"
              : "were $error_count errors") .
              ":\n";
    $self->_print($msg);

    my $i = 0;
    for my $e (@{$result->errors()}) {
        chomp(my $e_to_str = $e);
        $i++;
        $self->_print("$i) $e_to_str\n");
        $self->_print("\nAnnotations:\n", $e->object->annotations())
          if $e->object->annotations();
    }
}

sub print_failures
{
    my ($self, $result) = @_;

    return unless my $failure_count = $result->failure_count;

    my $msg = "\nThere " .
              ($failure_count == 1 ?
                "was 1 failure"
              : "were $failure_count failures") .
              ":\n";
    $self->_print($msg);

    my $i = 0;
    for my $f (@{$result->failures()}) {
        chomp(my $f_to_str = $f);
        $self->_print("\n") if $i++;
        $self->_print("$i) $f_to_str\n");
        $self->_print("\nAnnotations:\n", $f->object->annotations())
          if $f->object->annotations();
    }
}

1;

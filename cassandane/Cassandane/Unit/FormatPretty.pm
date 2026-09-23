# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Unit::FormatPretty;
use strict;
use warnings;

use base qw(Cassandane::Unit::Formatter);

sub new
{
    my ($class, $params, @args) = @_;
    my $self = $class->SUPER::new(@args);
    if ($params->{quiet}) {
        # if we're in quiet ("prettier") mode, write detailed error/failure
        # reports to $rootdir/reports (if we can) rather than terminal
        $self->{_quiet} = 1;

        my $cassini = Cassandane::Cassini->instance();
        my $rootdir = $cassini->val('cassandane', 'rootdir', '/var/tmp/cass');
        my $quiet_report_file = "$rootdir/reports";

        $self->{_quiet_report_fh} = IO::File->new($quiet_report_file, 'w');
        # if we can't write there, just don't do it
    }
    if ($params->{no_ok}) {
        # don't print success outputs to terminal, only error/failure
        $self->{_no_ok} = 1;
    }
    return $self;
}

sub ansi
{
    my ($self, $codes, @args) = @_;
    my $isatty = -t $self->{fh};

    my $ansi;

    $ansi .= "\e[" . join(',', @{$codes}) . 'm' if $isatty;
    $ansi .= join ('', @args);
    $ansi .= "\e[0m" if $isatty;

    return $ansi;
}

sub add_pass
{
    my $self = shift;
    my $test = shift;

    return if $self->{_no_ok};

    my $line = sprintf "%s %s\n",
                       $self->ansi([32], '[  OK  ]'),
                       _getname($test);
    $self->_print($line);
}

sub add_error
{
    my $self = shift;
    my $test = shift;

    my $line = sprintf "%s %s\n",
                       $self->ansi([31], '[ERROR ]'),
                       _getname($test);
    $self->_print($line);
}

sub add_failure
{
    my $self = shift;
    my $test = shift;

    my $line = sprintf "%s %s\n",
                       $self->ansi([33], '[FAILED]'),
                       _getname($test);
    $self->_print($line);
}

sub add_skip
{
    my ($self, $test, $reason) = @_;

    $self->SUPER::add_skip($test, $reason);

    return if $self->{_no_ok};

    my $line = sprintf "%s %s (%s)\n",
                       $self->ansi([36], '[ SKIP ]'),
                       _getname($test),
                       $reason;
    $self->_print($line);
}

sub _getname
{
    my $test = shift;
    my $suite = ref($test);
    $suite =~ s/^Cassandane:://;

    my $testname = $test->name =~ s/^test_//r;

    return "$suite.$testname";
}

sub print_errors
{
    my $self = shift;

    my $saved_output_stream;
    if ($self->{_quiet}) {
        if ($self->{_quiet_report_fh}) {
            $saved_output_stream = $self->{fh};
            $self->{fh} = $self->{_quiet_report_fh};
        }
        else {
            return;
        }
    }

    my ($result) = @_;
    return unless my $error_count = $result->error_count();
    my $msg = "\nThere " .
              ($error_count == 1 ?
                "was 1 error"
              : "were $error_count errors") .
              ":\n";
    $self->_print($msg);

    my $i = 0;
    for my $e (@{$result->errors()}) {
        chomp(my $report = $e->{report});
        $self->_print("\n") if $i++;
        $self->_print($self->ansi([31], "$i) " . _getname($e->{test}))
                      . "\n$report\n");
        $self->_print("\nAnnotations:\n", $e->{test}->annotations())
          if $e->{test}->annotations();
    }

    if ($saved_output_stream) {
        $self->{fh} = $saved_output_stream;
    }
}

sub print_failures
{
    my $self = shift;

    my $saved_output_stream;
    if ($self->{_quiet}) {
        if ($self->{_quiet_report_fh}) {
            $saved_output_stream = $self->{fh};
            $self->{fh} = $self->{_quiet_report_fh};
        }
        else {
            return;
        }
    }

    my ($result) = @_;
    return unless my $failure_count = $result->failure_count;
    my $msg = "\nThere " .
              ($failure_count == 1 ?
                "was 1 failure"
              : "were $failure_count failures") .
              ":\n";
    $self->_print($msg);

    my $i = 0;
    for my $f (@{$result->failures()}) {
        chomp(my $report = $f->{report});
        $self->_print("\n") if $i++;
        $self->_print($self->ansi([33], "$i) " . _getname($f->{test}))
                      . "\n$report\n");
        $self->_print("\nAnnotations:\n", $f->{test}->annotations())
          if $f->{test}->annotations();
    }

    if ($saved_output_stream) {
        $self->{fh} = $saved_output_stream;
    }
}

sub print_header {
    my $self = shift;
    my ($result) = @_;
    my $skipped = $self->skip_count()
                ? ", Skipped: " . $self->ansi([36], $self->skip_count())
                : "";
    if ($result->was_successful()) {
        $self->_print("\n",
                      $self->ansi([32], "OK"),
                      " (", $result->run_count(), " tests",
                      $self->skip_count()
                        ? ", " . $self->skip_count() . " skipped"
                        : "",
                      ")\n");
    } else {
        my $failure_count = $result->failure_count()
                          ? $self->ansi([33], $result->failure_count)
                          : "0";
        my $error_count = $result->error_count()
                        ? $self->ansi([31], $result->error_count)
                        : "0";

        my $x = $result->run_count() - ($result->failure_count()
                                        + $result->error_count());
        my $success_count = $x ? $self->ansi([32], $x) : "0";

        $self->_print("\n", $self->ansi([31], "!!!FAILURES!!!"), "\n",
                      "Test Results:\n",
                      "Run: ", $result->run_count(),
                      ", Successes: $success_count",
                      ", Failures: $failure_count",
                      ", Errors: $error_count",
                      $skipped,
                      "\n");
    }
}

1;

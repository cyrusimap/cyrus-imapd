#!/usr/bin/perl
#
#  Copyright (c) 2011-2017 FastMail Pty Ltd. All rights reserved.
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
#  3. The name "Fastmail Pty Ltd" must not be used to
#     endorse or promote products derived from this software without
#     prior written permission. For permission or any legal
#     details, please contact
#      FastMail Pty Ltd
#      PO Box 234
#      Collins St West 8007
#      Victoria
#      Australia
#
#  4. Redistributions of any form whatsoever must retain the following
#     acknowledgment:
#     "This product includes software developed by Fastmail Pty. Ltd."
#
#  FASTMAIL PTY LTD DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE,
#  INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY  AND FITNESS, IN NO
#  EVENT SHALL OPERA SOFTWARE AUSTRALIA BE LIABLE FOR ANY SPECIAL, INDIRECT
#  OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF
#  USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
#  TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE
#  OF THIS SOFTWARE.
#

package Cassandane::Unit::Formatter;
use strict;
use warnings;

use base 'Test::Unit::Listener';
use Benchmark;
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
    print "\n", "Time: ", timestr($run_time), "\n";

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

    my $annotations;

    for my $e (@{$result->errors()}) {
        chomp(my $e_to_str = $e);
        $i++;
        $self->_print("$i) $e_to_str\n\n");

        # These will always be the same since they share the same test object
        # so we just need one of them...
        $annotations ||= \$e->object->annotations();
    }

    $self->_print("\nAnnotations:\n", $$annotations)
        if $$annotations;
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

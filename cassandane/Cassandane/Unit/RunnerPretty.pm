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

package Cassandane::Unit::RunnerPretty;
use strict;
use warnings;

use lib '.';
use base qw(Cassandane::Unit::Runner);

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
    return $self;
}

sub ansi
{
    my ($self, $codes, @args) = @_;
    my $isatty = -t $self->print_stream;

    my $ansi;

    $ansi .= "\e[" . join(',', @{$codes}) . 'm' if $isatty;
    $ansi .= join ('', @args);
    $ansi .= "\e[0m" if $isatty;

    return $ansi;
}

sub start_test
{
    my $self = shift;
    my $test = shift;
    # prevent the default action which is to print "."
}

sub add_pass
{
    my $self = shift;
    my $test = shift;
    $self->_print(_getpaddedname($test) . "[  " . $self->ansi([32], 'OK') . "  ]\n");
}

sub add_error
{
    my $self = shift;
    my $test = shift;
    $self->record_failed($test);
    $self->_print(_getpaddedname($test) . "[" . $self->ansi([31], 'ERROR') . " ]\n");
}

sub add_failure
{
    my $self = shift;
    my $test = shift;
    $self->record_failed($test);
    $self->_print(_getpaddedname($test) . "[" . $self->ansi([33], 'FAILED') . "]\n");
}

sub _getpaddedname
{
    my $test = shift;
    my $suite = ref($test);
    $suite =~ s/^Cassandane:://;

    my $testname = $test->{"Test::Unit::TestCase_name"};
    $testname =~ s/^test_//;

    my $res = "$suite.$testname";

    if (length($res) > 70) {
        $res = substr($res, 0, 67) . '...';
    }

    $res .= ' ' x (72 - length($res));

    return $res;
}

sub _prettytest
{
    my $test = shift;
    die "WEIRD TEST $test" unless $test =~ m/^test_(.*)\((.*)\)$/;
    my $item = $1;
    my $suite = $2;
    $suite =~ s/^Cassandane::Cyrus:://;
    return "$suite.$item";
}

sub print_errors
{
    my $self = shift;

    my $saved_output_stream;
    if ($self->{_quiet}) {
        if ($self->{_quiet_report_fh}) {
            $saved_output_stream = $self->{_Print_stream};
            $self->{_Print_stream} = $self->{_quiet_report_fh};
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
        my ($test, $errors) = split(/\n/, $e->to_string(), 2);
        chomp $errors;
        my $prettytest = _prettytest($test);
        $self->_print("\n") if $i++;
        $self->_print($self->ansi([31], "$i) $prettytest") . "\n$errors\n");
        $self->_print("\nAnnotations:\n", $e->object->annotations())
          if $e->object->annotations();
    }

    if ($saved_output_stream) {
        $self->{_Print_stream} = $saved_output_stream;
    }
}

sub print_failures
{
    my $self = shift;

    my $saved_output_stream;
    if ($self->{_quiet}) {
        if ($self->{_quiet_report_fh}) {
            $saved_output_stream = $self->{_Print_stream};
            $self->{_Print_stream} = $self->{_quiet_report_fh};
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
        my ($test, $failures) = split(/\n/, $f->to_string(), 2);
        chomp $failures;
        my $prettytest = _prettytest($test);
        $self->_print("\n") if $i++;
        $self->_print($self->ansi([33], "$i) $prettytest") . "\n$failures\n");
        $self->_print("\nAnnotations:\n", $f->object->annotations())
          if $f->object->annotations();
    }

    if ($saved_output_stream) {
        $self->{_Print_stream} = $saved_output_stream;
    }
}

1;

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

package Cassandane::Unit::FormatXML;
use strict;
use warnings;
use vars qw($VERSION);

use XML::Generator;
use Time::HiRes qw(time);
use Sys::Hostname;
use POSIX qw(strftime);

use base qw(Cassandane::Unit::Formatter);

$VERSION = '0.1';

sub new {
    my ($class, $params, @args) = @_;

    my $self = $class->SUPER::new(@args);

    $params->{generator} ||= XML::Generator->new(escape => 'always',
                                                 pretty => 2);

    $self->{directory} = $params->{directory};
    $self->{gen} = $params->{generator};
    $self->{classrecs} = {};

    return $self;
}

sub _classrec {
    my ($self, $test) = @_;

    return $self->{classrecs}->{ref($test)} ||= {
                testrecs => {}, tests => 0,
                errors => 0, failures => 0,
                timestamp => strftime("%Y-%m-%dT%H:%M:%S", gmtime(time())),
                };
}

sub _testrec {
    my ($self, $test) = @_;

    my $cr = $self->_classrec($test);
    return $cr->{testrecs}->{$test->name()} ||=
                { start_time => 0, node => undef, child_nodes => [] };
}

sub _extype
{
    my ($exception) = @_;
    my $o = $exception->object();
    return $o->to_string()
        if (defined $o && $o->can('to_string'));
    return "unknown";
}

sub add_failure {
    my ($self, $test, $exception) = @_;

    my $cr = $self->_classrec($test);
    my $tr = $self->_testrec($test);
    $cr->{failures}++;
    push(@{$tr->{child_nodes}},
         $self->{gen}->failure({type => _extype($exception),
                                message => $exception->get_message()},
                                $exception->stringify()));
}

sub add_error {
    my ($self, $test, $exception) = @_;

    my $cr = $self->_classrec($test);
    my $tr = $self->_testrec($test);
    $cr->{errors}++;
    push(@{$tr->{child_nodes}},
         $self->{gen}->error({type => _extype($exception),
                              message => $exception->get_message()},
                              $exception->stringify()));
}

sub start_test {
    my ($self, $test) = @_;

    my $cr = $self->_classrec($test);
    my $tr = $self->_testrec($test);
    $tr->{start_time} = time();
    $cr->{tests}++;
}

sub fake_start_time {
    my ($self, $test, $time) = @_;

    my $tr = $self->_testrec($test);
    $tr->{start_time} = $time;
}

sub end_test {
    my ($self, $test) = @_;

    my $cr = $self->_classrec($test);
    my $tr = $self->_testrec($test);
    my $time = time() - $tr->{start_time};
    $tr->{node} = $self->{gen}->testcase({name => $test->name(),
                                          classname => ref($test),
                                          time => sprintf('%.4f', $time)},
                                          @{$tr->{child_nodes}});
    $cr->{time} += $time;
}

sub _emit_xml {
    my ($self) = @_;

    my $hostname = hostname();

    foreach my $class (keys %{$self->{classrecs}}) {
        my $cr = $self->{classrecs}->{$class};

        my $output = IO::File->new(">" . $self->_xml_filename($class));
        unless(defined($output)) {
            die("Can't open " . $self->_xml_filename($class) . ": $!");
        }

        my $time = sprintf('%.4f', $cr->{time});
        my @child_nodes = map { $_->{node}; } (values %{$cr->{testrecs}});
        unshift(@child_nodes, $self->{gen}->properties());
        my $system_out = 'system-out';
        push(@child_nodes, $self->{gen}->$system_out());
        my $system_err = 'system-err';
        push(@child_nodes, $self->{gen}->$system_err());
        my $xml = $self->{gen}->testsuite({tests => $cr->{tests},
                                           failures => $cr->{failures},
                                           errors => $cr->{errors},
                                           time => $time,
                                           name => $class,
                                           hostname => $hostname,
                                           timestamp => $cr->{timestamp}},
                                          @child_nodes);
        $output->print($xml);
        $output->close();
    }
}

sub finished
{
    my ($self, $result, $start_time, $end_time) = @_;

    # XXX This class does all its own accounting, which is probably
    # XXX redundant since it doesn't report anything that it couldn't
    # XXX just get from the usual $result/$start_time/$end_time args.
    $self->_emit_xml();
}

sub _xml_filename {
    my ($self, $class) = @_;

    $class =~ s/::/./g;
    return File::Spec->catfile($self->{directory}, "TEST-${class}.xml");
}

1;

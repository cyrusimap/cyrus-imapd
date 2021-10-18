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

package Cassandane::Unit::Runner;
use strict;
use warnings;
use base qw(Test::Unit::TestRunner);
use Test::Unit::Result;
use IO::File;

use lib '.';
use Cassandane::Cassini;

sub new
{
    my $class = shift;
    my $self = $class->SUPER::new(@_);
    $self->{remove_me_in_cassandane_child} = 1;

    my $cassini = Cassandane::Cassini->instance();
    my $rootdir = $cassini->val('cassandane', 'rootdir', '/var/tmp/cass');
    my $failed_file = "$rootdir/failed";
    $self->{failed_fh} = IO::File->new($failed_file, 'w');
    # if we can't write there, we just won't record failed tests!

    return $self;
}

sub create_test_result
{
    my ($self) = @_;
    $self->{_result} = Test::Unit::Result->new();
    return $self->{_result};
}

sub record_failed
{
    my ($self, $test) = @_;
    return if not $self->{failed_fh};

    my $suite = ref($test);
    $suite =~ s/^Cassandane:://;

    my $testname = $test->{"Test::Unit::TestCase_name"};
    $testname =~ s/^test_//;

    $self->{failed_fh}->print("$suite.$testname\n");
}

sub add_error
{
    my ($self, $test) = @_;
    $self->record_failed($test);
    $self->SUPER::add_error($test);
}

sub add_failure
{
    my ($self, $test) = @_;
    $self->record_failed($test);
    $self->SUPER::add_failure($test);
}

1;

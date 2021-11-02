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

package Cassandane::Test::Core;
use strict;
use warnings;
use Data::Dumper;
use POSIX qw(getcwd);

use lib '.';
use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;

my $crash_bin = getcwd() . '/utils/crash';

sub new
{
    my $class = shift;
    return $class->SUPER::new({}, @_);
}

sub set_up
{
    my ($self) = @_;
    die "No crash binary $crash_bin.  Did you run \"make\" in the Cassandane directory?"
        unless (-f $crash_bin);
    $self->SUPER::set_up();
}

sub tear_down
{
    my ($self) = @_;
    $self->SUPER::tear_down();
}

sub _test_core_files_with_size
{
    my ($self, $alloc) = @_;

    my $instance = $self->{instance};
    my $signaled = 0; #n.b. spelling
    my $pid;

    $instance->run_command(
        { cyrus => 0,
          handlers => {
            signaled => sub {
                my ($child, $sig) = @_;
                $pid = $child->{pid};
                $signaled++;
            } },
        },
        $crash_bin, $alloc);

    $self->assert_equals(1, $signaled);
    $self->assert_not_null($pid);

    my $err;
    eval { $err = $instance->_check_cores() };
    $self->assert_matches(qr/Core files found/, $err);

    my $core = "$instance->{basedir}/conf/cores/core.$pid";
    if (not -f $core) {
        $core = "$instance->{basedir}/conf/cores/core";
    }
    $self->assert(-f $core);
    my $size = -s $core;

    # clean up the core we expected, so we don't barf on it existing!
    unlink $core or die "unlink $core: $!";
    # but don't clean up any other unexpected cores!

    $self->assert($size > $alloc);
}

sub test_core_files_1KB
{
    shift->_test_core_files_with_size(1 * 1024);
}

sub test_core_files_1MB
{
    shift->_test_core_files_with_size(1 * 1024 * 1024);
}

sub test_core_files_5MB
{
    shift->_test_core_files_with_size(5 * 1024 * 1024);
}

sub test_core_files_10MB
{
    shift->_test_core_files_with_size(10 * 1024 * 1024);
}

sub test_core_files_50MB
{
    shift->_test_core_files_with_size(50 * 1024 * 1024);
}

# Cassandane::Instance::_fork_command limits core sizes to 100MB

1;

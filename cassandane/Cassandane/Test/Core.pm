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

    my %initial_cores = map { $_ => 1 } $instance->find_cores();

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

    my @cores = $instance->find_cores();

    # expect there's at least one new core
    $self->assert_num_gt(scalar keys %initial_cores, scalar @cores);

    my $cassini = Cassandane::Cassini->instance();
    my $core_pattern = $cassini->get_core_pattern();
    my $found;
    my $size;

    foreach my $core (@cores) {
        # ignore cores that already existed
        next if exists $initial_cores{$core};

        if ($core =~ m/$core_pattern/) {
            if ($1) {
                if ($1 eq $pid) {
                    # found the core we expected...
                    $found ++;
                    # can only check the size if it's readable and uncompressed
                    $self->assert_file_test($core, '-r');
                    $self->assert_does_not_match(qr{compressed}, qx(file $core));
                    $size = -s $core;
                    # clean it up if we can, so we don't barf on it existing!
                    unlink $core;
                }
            }
            else {
                # core file names don't contain a pid field, can't identify our
                # own, nothing else to do
                return;
            }
        }
    }

    $self->assert_num_equals(1, $found);
    $self->assert_num_gt($alloc, $size) if $size;
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

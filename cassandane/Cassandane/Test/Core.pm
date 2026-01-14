# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

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

    # expect there's exactly one core
    $self->assert_num_equals(1, scalar @cores);

    my $cassini = Cassandane::Cassini->instance();
    my $core_pattern = $cassini->get_core_pattern();

    my $core = shift @cores;
    if ($core =~ m/$core_pattern/ && $1) {
        # if there's a pid in the filename, check it
        $self->assert_num_equals($pid, $1);
    }
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

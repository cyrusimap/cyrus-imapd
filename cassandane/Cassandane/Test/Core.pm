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

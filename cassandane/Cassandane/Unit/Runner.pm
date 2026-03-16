# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Unit::Runner;
use strict;
use warnings;
use base qw(Test::Unit::Runner);
use Test::Unit::Result;
use Benchmark;
use IO::File;

use Cassandane::Cassini;

sub new
{
    my ($class) = @_;

    my $cassini = Cassandane::Cassini->singleton();
    my $rootdir = $cassini->val('cassandane', 'rootdir', '/var/tmp/cass');
    my $rundir  = $cassini->val('cassandane', 'rundir', undef);

    unless ($rundir)
    {
        Carp::confess("can't construct Cassandane::Unit::Runner without Cassini rundir");
    }

    my $basedir = join q{/}, $rootdir, $rundir;
    my $failed_file = "$basedir/failed";
    # if we can't write there, we just won't record failed tests!

    return bless {
        remove_me_in_cassandane_child => 1,
        formatters => [],
        failed_fh => IO::File->new($failed_file, 'w'),
    }, $class;
}

sub create_test_result
{
    my ($self) = @_;
    $self->{_result} = Test::Unit::Result->new();
    return $self->{_result};
}

sub add_formatter
{
    my ($self, $formatter) = @_;

    push @{$self->{formatters}}, $formatter;
}

# this is very similar to Test::Unit::Result's tell_listeners(), except
# without the annoying crash when the listener doesn't care about the event
sub tell_formatters
{
    my ($self, $method, @args) = @_;

    foreach my $formatter (@{$self->{formatters}}) {
        if ($formatter->can($method)) {
            $formatter->$method(@args);
        }
    }
}

sub do_run
{
    my ($self, $suite) = @_;
    my $result = $self->create_test_result();

    $result->add_listener($self);
    foreach my $f (@{$self->{formatters}}) {
        $result->add_listener($f);
    }

    my $start_time = new Benchmark();
    $suite->run($result, $self);
    my $end_time = new Benchmark();

    foreach my $f (@{$self->{formatters}}) {
        $f->finished($result, $start_time, $end_time);
    }

    return $result->was_successful;
}

sub start_suite { }

sub end_suite { }

sub start_test { }

sub end_test { }

sub add_pass
{
    my ($self, $test) = @_;

    my $suite = ref($test);
    $suite =~ s/^Cassandane:://;

    my $testname = $test->{"Test::Unit::TestCase_name"};

    Cassandane::Cassini->singleton->manifest->record_completion(
      $suite,
      $testname,
      'pass',
    );
}

sub record_failed
{
    my ($self, $test, $type) = @_;

    my $suite = ref($test);
    $suite =~ s/^Cassandane:://;

    my $testname = $test->{"Test::Unit::TestCase_name"};

    Cassandane::Cassini->singleton->manifest->record_completion(
      $suite,
      $testname,
      $type,
    );

    $testname =~ s/^test_//;

    return if not $self->{failed_fh};
    $self->{failed_fh}->print("$suite.$testname\n");
}

sub add_error
{
    my ($self, $test) = @_;
    $self->record_failed($test, 'error');
}

sub add_failure
{
    my ($self, $test) = @_;
    $self->record_failed($test, 'failure');
}

1;

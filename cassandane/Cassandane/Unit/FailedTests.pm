# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Unit::FailedTests;
use strict;
use warnings;
use experimental 'signatures';

use base qw(Cassandane::Unit::Listener);

use IO::File;

use Cassandane::Cassini;

# The file the names of the failed tests are written to, one per line, in the
# form --rerun wants to read them back in.
sub filename ($class)
{
    my $cassini = Cassandane::Cassini->instance();
    my $rootdir = $cassini->val('cassandane', 'rootdir', '/var/tmp/cass');

    return "$rootdir/failed";
}

sub new ($class)
{
    return bless {
        # if we can't write there, we just won't record failed tests!
        fh => IO::File->new($class->filename, 'w'),
    }, $class;
}

sub _record ($self, $test)
{
    return if not $self->{fh};

    my $suite = ref($test) =~ s/^Cassandane:://r;
    my $name  = $test->name =~ s/^test_//r;

    $self->{fh}->print("$suite.$name\n");
    return;
}

sub add_failure ($self, $test, $exception) { $self->_record($test) }

sub add_error ($self, $test, $exception) { $self->_record($test) }

1;

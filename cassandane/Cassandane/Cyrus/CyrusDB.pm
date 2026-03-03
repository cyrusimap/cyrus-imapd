# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Cyrus::CyrusDB;
use strict;
use warnings;
use Data::Dumper;
use File::Copy;
use IO::File;

use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;
use Cassandane::Instance;

use lib '../perl/imap/lib';
use Cyrus::DList;
use Cyrus::HeaderFile;

sub new
{
    my $class = shift;
    return $class->SUPER::new({ start_instances => 0 }, @_);
}

sub set_up
{
    my ($self) = @_;
    $self->SUPER::set_up();
}

sub tear_down
{
    my ($self) = @_;
    $self->SUPER::tear_down();
}

# Some databases aren't created automatically during a minimal
# startup on a new install, so run some commands such that they
# become extant.
sub _force_db_creations
{
    my ($self) = @_;

    # nothing currently required here!
}

sub create_empty_file
{
    my ($fname) = @_;

    open my $fh, '>', $fname
        or die "create_empty_file($fname): $!";
    close $fh;
}

use Cassandane::Tiny::Loader;

1;

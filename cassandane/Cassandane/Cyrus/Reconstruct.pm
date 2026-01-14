# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Cyrus::Reconstruct;
use strict;
use warnings;
use Data::Dumper;
use File::Copy;
use IO::File;
use JSON;
use Cwd qw(abs_path);

use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;
use Cassandane::Instance;

use lib '../perl/imap/lib';
use Cyrus::DList;
use Cyrus::HeaderFile;
use Cyrus::IndexFile;

sub new
{
    my $class = shift;
    return $class->SUPER::new({ adminstore => 1 }, @_);
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

use Cassandane::Tiny::Loader;

1;

# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Cyrus::SearchSquat;
use strict;
use warnings;
use Cwd qw(abs_path);
use DateTime;
use Data::Dumper;

use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;
use Cassandane::Util::Slurp;

sub new
{
    my ($class, @args) = @_;
    my $config = Cassandane::Config->default()->clone();
    $config->set(conversations => 'on');
    return $class->SUPER::new({ config => $config }, @args);
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

sub run_squatter
{
    my ($self, @args) = @_;

    my $outfname = $self->{instance}->{basedir} . "/squatter.out";
    my $errfname = $self->{instance}->{basedir} . "/squatter.err";

    $self->{instance}->run_command({
            cyrus => 1,
            redirects => {
                stdout => $outfname,
                stderr => $errfname,
            },
        },
        'squatter',
        @args
    );

    return (slurp_file($outfname), slurp_file($errfname));
}

use Cassandane::Tiny::Loader;

1;

# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Cyrus::Search;
use strict;
use warnings;
use Cwd qw(abs_path);
use DateTime;
use Data::Dumper;

use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;

sub new
{
    my $class = shift;
    my $config = Cassandane::Config->default()->clone();
    $config->set(conversations => 'on');
    return $class->SUPER::new({adminstore => 1, config => $config}, @_);
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

sub _fgrep_msgs
{
    my ($msgs, $attr, $s) = @_;
    my @res;

    foreach my $msg (values %$msgs)
    {
        push(@res, $msg->uid())
            if (index($msg->$attr(), $s) >= 0);
    }
    @res = sort { $a <=> $b } @res;
    return \@res;
}

use Cassandane::Tiny::Loader;

1;

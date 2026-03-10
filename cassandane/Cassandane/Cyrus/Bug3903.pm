# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Cyrus::Bug3903;
use strict;
use warnings;

use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;

sub new
{
    my $class = shift;
    my $config = Cassandane::Config->default()->clone();
    $config->set(autocreate_quota => 101200);
    return $class->SUPER::new({
        config => $config,
        adminstore => 1,
    }, @_);
}

sub set_up
{
    my ($self) = @_;
    $self->SUPER::set_up();

    $self->{instance}->create_user("foo",
                                   subdirs => [ 'cassandane', ['cassandane', 'sent'] ]);

    my $admintalk = $self->{adminstore}->get_client();
    $admintalk->setacl("user.foo.cassandane.sent", "cassandane", "lrswp");
}

sub tear_down
{
    my ($self) = @_;
    $self->SUPER::tear_down();
}

use Cassandane::Tiny::Loader;

1;

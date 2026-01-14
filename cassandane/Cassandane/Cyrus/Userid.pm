# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Cyrus::Userid;
use strict;
use warnings;

use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;

Cassandane::Cyrus::TestCase::magic(NoAutocreate => sub {
    shift->config_set('autocreate_users' => 'nobody');
});
Cassandane::Cyrus::TestCase::magic(PopUseACL => sub {
    shift->config_set('popuseacl' => 'yes');
});

sub new
{
    my $class = shift;
    return $class->SUPER::new({
        adminstore => 1,
        services => ['imap', 'pop3']
    }, @_);
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

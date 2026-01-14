# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Cyrus::Pop3;
use strict;
use warnings;
use DateTime;
use Net::POP3;

use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;

Cassandane::Cyrus::TestCase::magic(PopSubFolders => sub {
    shift->config_set(popsubfolders => 1);
});

Cassandane::Cyrus::TestCase::magic(PopUseImapFlags => sub {
    shift->config_set('popuseimapflags' => 'yes');
});

sub new
{
    my ($class, @args) = @_;
    return $class->SUPER::new({
        # We need IMAP to be able to create the mailbox for POP
        services => ['imap', 'pop3'],
    }, @args);
}

sub set_up
{
    my ($self) = @_;
    $self->SUPER::set_up();

    my $svc = $self->{instance}->get_service('pop3');
    if (defined $svc)
    {
        $self->{pop_store} = $svc->create_store();
    }
}

sub tear_down
{
    my ($self) = @_;

    if (defined $self->{pop_store})
    {
        $self->{pop_store}->disconnect();
        $self->{pop_store} = undef;
    }

    $self->SUPER::tear_down();
}

use Cassandane::Tiny::Loader;

1;

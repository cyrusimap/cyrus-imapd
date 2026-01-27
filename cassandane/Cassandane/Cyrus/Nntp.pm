# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Cyrus::Nntp;
use strict;
use warnings;
use DateTime;
use News::NNTPClient;

use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;
use Cassandane::Util::Words;

sub new
{
    my ($class, @args) = @_;

    my $self = $class->SUPER::new({ gen => 0, services => ['nntp'] }, @args);

    $self->needs('component', 'nttpd');
    return $self;
}

sub set_up
{
    my ($self) = @_;
    $self->SUPER::set_up();

    my $svc = $self->{instance}->get_service('nntp');
    if (defined $svc)
    {
        my $debug = get_verbose() ? 2 : 0;
        $self->{client} = new News::NNTPClient($svc->host(),
                                               $svc->port(),
                                               $debug);
        $self->{client}->authinfo('cassandane', 'testpw');
    }
}

sub tear_down
{
    my ($self) = @_;

    if (defined $self->{client})
    {
        $self->{client}->quit();
        $self->{client} = undef;
    }

    $self->SUPER::tear_down();
}

my $stack_slosh = 256;

sub test_cve_2011_3208_list_newsgroups
{
    my ($self) = @_;

    my $client = $self->{client};
    my $wildmat = '';
    while (length $wildmat < 1024+$stack_slosh)
    {
        $wildmat .= ($wildmat eq '' ? '' : '.');
        $wildmat .= random_word();
        $client->list('newsgroups', $wildmat);
        $self->assert_num_equals(215, $client->code());
        $self->assert($client->message() =~ m/List of newsgroups follows/i);
    }
}

sub test_cve_2011_3208_list_active
{
    my ($self) = @_;

    my $client = $self->{client};
    my $wildmat = '';
    while (length $wildmat < 1024+$stack_slosh)
    {
        $wildmat .= ($wildmat eq '' ? '' : '.');
        $wildmat .= random_word();
        $client->list('active', $wildmat);
        $self->assert_num_equals(215, $client->code());
        $self->assert($client->message() =~ m/List of newsgroups follows/i);
    }
}

    # The NEWNEWS command is disabled by default.
Cassandane::Cyrus::TestCase::magic(AllowNewNews => sub {
    shift->config_set(allownewnews => 1);
});

sub test_cve_2011_3208_newnews
    :AllowNewNews
{
    my ($self) = @_;

    my $client = $self->{client};
    my $wildmat = '';
    my $since = time() - 3600;
    while (length $wildmat < 1024+$stack_slosh)
    {
        $wildmat .= ($wildmat eq '' ? '' : '.');
        $wildmat .= random_word();
        $client->newnews($wildmat, $since);
        $self->assert_num_equals(230, $client->code());
        $self->assert($client->message() =~ m/List of new articles follows/i);
    }
}

1;

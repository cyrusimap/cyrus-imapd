# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Cyrus::TestEntities;
use strict;
use warnings;

use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;

sub new
{
    my ($class, @args) = @_;

    my $config = Cassandane::Config->default()->clone();
    $config->set(conversations => 'yes',
                 httpmodules => 'carddav caldav jmap',
                 jmap_nonstandard_extensions => 'yes');

    my $self = $class->SUPER::new({
        config => $config,
        jmap => 1,
        deliver => 1,
        adminstore => 1,
        services => [ 'imap', 'http' ]
    }, @args);

    $self->needs('component', 'jmap');
    return $self;
}

sub set_up
{
    my ($self) = @_;
    $self->SUPER::set_up();
    $self->{jmap}->DefaultUsing([
        'urn:ietf:params:jmap:core',
        'urn:ietf:params:jmap:mail',
        'https://cyrusimap.org/ns/jmap/contacts',
        'https://cyrusimap.org/ns/jmap/debug',
    ]);

    my $buildinfo = Cassandane::BuildInfo->new();
    if ($buildinfo->get('dependency', 'icalvcard')) {
        $self->{jmap}->AddUsing('urn:ietf:params:jmap:contacts');
    }
}

use Cassandane::Tiny::Loader 'tiny-tests/TestEntities';

1;

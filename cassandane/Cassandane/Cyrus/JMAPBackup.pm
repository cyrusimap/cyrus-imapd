# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Cyrus::JMAPBackup;
use strict;
use warnings;
use DateTime;
use JSON::XS;
use Net::CalDAVTalk 0.09;
use Net::CardDAVTalk 0.03;
use Data::Dumper;
use Storable 'dclone';
use File::Basename;
use XML::Spice;

use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;

use charnames ':full';

sub new
{
    my ($class, @args) = @_;

    my $config = Cassandane::Config->default()->clone();
    $config->set(caldav_realm => 'Cassandane',
                 caldav_historical_age => -1,
                 conversations => 'yes',
                 httpmodules => 'carddav caldav jmap',
                 httpallowcompress => 'no',
                 imipnotifier => 'imip',
                 notesmailbox => 'Notes',
                 jmap_nonstandard_extensions => 'yes');

    my $self = $class->SUPER::new({
        config => $config,
        jmap => 1,
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
    if ($self->{_want}->{start_instances}) {
        $self->{jmap}->DefaultUsing([
            'urn:ietf:params:jmap:core',
            'urn:ietf:params:jmap:mail',
            'urn:ietf:params:jmap:calendars',
            'urn:ietf:params:jmap:contacts',
            'urn:ietf:params:jmap:principals',
            'https://cyrusimap.org/ns/jmap/backup',
            'https://cyrusimap.org/ns/jmap/contacts',
            'https://cyrusimap.org/ns/jmap/calendars',
            'https://cyrusimap.org/ns/jmap/notes',
        ]);
    }
}

use Cassandane::Tiny::Loader 'tiny-tests/JMAPBackup';

1;

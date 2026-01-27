# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Cyrus::JMAPNote;
use strict;
use warnings;
use DateTime;
use JSON::XS;
use Data::Dumper;
use Storable 'dclone';
use MIME::Base64 qw(encode_base64);
use Cwd qw(abs_path getcwd);

use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;

use lib '../perl/imap';
use Cyrus::DList;

use charnames ':full';

sub new
{
    my ($class, @args) = @_;

    my $config = Cassandane::Config->default()->clone();
    $config->set(caldav_realm => 'Cassandane',
                 conversations => 'yes',
                 httpmodules => 'jmap',
                 notesmailbox => 'Notes',
                 httpallowcompress => 'no');

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

    if ($self->{jmap}) {
        $self->{jmap}->DefaultUsing([
            'urn:ietf:params:jmap:core',
            'https://cyrusimap.org/ns/jmap/notes',
        ]);
    }
}

use Cassandane::Tiny::Loader 'tiny-tests/JMAPNote';

1;

# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Cyrus::JMAPEmailSubmission;
use strict;
use warnings;
use DateTime;
use JSON::XS;
use Net::CalDAVTalk 0.09;
use Net::CardDAVTalk 0.03;
use Data::Dumper;
use Storable 'dclone';
use MIME::Base64 qw(encode_base64);
use Cwd qw(abs_path getcwd);
use URI;

use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;

use charnames ':full';

sub new
{
    my ($class, @args) = @_;

    my $config = Cassandane::Config->default()->clone();
    $config->set(caldav_realm => 'Cassandane',
                 conversations => 'yes',
                 conversations_counted_flags => "\\Draft \\Flagged \$IsMailingList \$IsNotification \$HasAttachment",
                 event_groups => 'mailbox message flags calendar applepushservice jmap',
                 jmapsubmission_deleteonsend => 'no',
                 httpmodules => 'carddav caldav jmap',
                 httpallowcompress => 'no');

    my $self = $class->SUPER::new({
        config => $config,
        jmap => 1,
        adminstore => 1,
        services => [ 'imap', 'http' ],
        smtpdaemon => 1,
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
        'urn:ietf:params:jmap:submission',
    ]);
}

sub getinbox
{
    my ($self, $args) = @_;

    $args = {} unless $args;

    my $jmap = $self->{jmap};

    xlog $self, "get existing mailboxes";
    my $res = $jmap->CallMethods([['Mailbox/get', $args, "R1"]]);
    $self->assert_not_null($res);

    my %m = map { $_->{name} => $_ } @{$res->[0][1]{list}};
    return $m{"Inbox"};
}

use Cassandane::Tiny::Loader 'tiny-tests/JMAPEmailSubmission';

1;

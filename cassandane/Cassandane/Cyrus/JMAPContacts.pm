# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Cyrus::JMAPContacts;
use strict;
use warnings;

use experimental 'signatures';

use DateTime;
use JSON::XS;
use Net::CalDAVTalk 0.09;
use Net::CardDAVTalk 0.03;
use Data::Dumper;
use Storable 'dclone';
use File::Basename;
use File::Copy;
use Cwd qw(abs_path getcwd);

use base qw(Cassandane::Cyrus::TestCase Cassandane::Mixin::QuotaHelper);
use Cassandane::Util::Log;
use Cassandane::Util::Slurp;

use charnames ':full';

sub new
{
    my ($class, @args) = @_;

    my $config = Cassandane::Config->default()->clone();
    $config->set(carddav_realm => 'Cassandane',
                 conversations => 'yes',
                 httpmodules => 'carddav jmap',
                 httpallowcompress => 'no',
                 vcard_max_size => 100000,
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
    $self->{jmap}->DefaultUsing([
        'urn:ietf:params:jmap:core',
        'urn:ietf:params:jmap:contacts',
        'https://cyrusimap.org/ns/jmap/contacts',
        'https://cyrusimap.org/ns/jmap/debug',
    ]);

    $ENV{DEBUGDAV} = 1;
}

sub normalize_jscard
{
    my ($jscard) = @_;

    if ($jscard->{vCardProps}) {
        my @sorted = sort { $a->[0] cmp $b->[0] } @{$jscard->{vCardProps}};
        $jscard->{vCardProps} = \@sorted;
    }

    if (not exists $jscard->{kind}) {
        $jscard->{kind} = 'individual';
    }

    if (not exists $jscard->{'cyrusimap.org:importance'}) {
        $jscard->{'cyrusimap.org:importance'} = '0';
    }
}

sub dblookup ($self, $path, $headers) {
    # Using the admin JMAP UA for this is sort of nonsense, but it's going to
    # get the job done.  Isolating this in a subroutine should make it easy to
    # improve later. -- rjbs, 2025-12-12
    $self->{_admin_user} //= $self->{instance}->create_user_without_setup('admin');
    my $admin_jmap = $self->{_admin_user}->jmap;

    if (ref $headers eq 'HASH') {
        # This is just how HTTP::Request works.
        $headers = [ %$headers ];
    }

    my $req = HTTP::Request->new(
        GET => URI->new_abs($path, $admin_jmap->api_uri),
        $headers,
    );

    my $res = $admin_jmap->http_request($req);

    return {
        http_response => $res,
        payload => scalar eval { decode_json($res->decoded_content(charset => undef)) },
    };
}

use Cassandane::Tiny::Loader 'tiny-tests/JMAPContacts';

1;

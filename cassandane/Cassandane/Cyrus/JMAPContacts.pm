#!/usr/bin/perl
#
#  Copyright (c) 2011-2017 FastMail Pty Ltd. All rights reserved.
#
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that the following conditions
#  are met:
#
#  1. Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#
#  2. Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.
#
#  3. The name "Fastmail Pty Ltd" must not be used to
#     endorse or promote products derived from this software without
#     prior written permission. For permission or any legal
#     details, please contact
#      FastMail Pty Ltd
#      PO Box 234
#      Collins St West 8007
#      Victoria
#      Australia
#
#  4. Redistributions of any form whatsoever must retain the following
#     acknowledgment:
#     "This product includes software developed by Fastmail Pty. Ltd."
#
#  FASTMAIL PTY LTD DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE,
#  INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY  AND FITNESS, IN NO
#  EVENT SHALL OPERA SOFTWARE AUSTRALIA BE LIABLE FOR ANY SPECIAL, INDIRECT
#  OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF
#  USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
#  TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE
#  OF THIS SOFTWARE.
#

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

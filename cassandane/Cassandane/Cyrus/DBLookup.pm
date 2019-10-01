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

package Cassandane::Cyrus::DBLookup;
use strict;
use warnings;
use DateTime;
use JSON::XS;
use Net::DAVTalk 0.14;
use Net::CardDAVTalk 0.05;
use Net::CardDAVTalk::VCard;
use Data::Dumper;
use XML::Spice;

use lib '.';
use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;

sub new
{
    my $class = shift;

    my $config = Cassandane::Config->default()->clone();
    $config->set(caldav_realm => 'Cassandane');
    $config->set(httpmodules => 'carddav caldav');
    $config->set(httpallowcompress => 'no');
    return $class->SUPER::new({
        adminstore => 1,
        config => $config,
        services => ['imap', 'http'],
    }, @_);
}

sub set_up
{
    my ($self) = @_;
    $self->SUPER::set_up();
    my $service = $self->{instance}->get_service("http");
    $ENV{DEBUGDAV} = 1;
    $self->{carddav} = Net::CardDAVTalk->new(
        user => 'cassandane',
        password => 'pass',
        host => $service->host(),
        port => $service->port(),
        scheme => 'http',
        url => '/',
        expandurl => 1,
    );
}

sub tear_down
{
    my ($self) = @_;
    $self->SUPER::tear_down();
}

sub test_email2uids
    :needs_component_httpd
{
    my ($self) = @_;

    my $CardDAV = $self->{carddav};
    my $Id = $CardDAV->NewAddressBook('foo');
    $self->assert_not_null($Id);
    $self->assert_str_equals($Id, 'foo');

    my $Str = <<EOF;
BEGIN:VCARD
VERSION:3.0
N:Gump;Forrest;;Mr.
FN:Forrest Gump
ORG:Bubba Gump Shrimp Co.
TITLE:Shrimp Man
EMAIL;TYPE=INTERNET:user\@example.com
REV:2008-04-24T19:52:43Z
END:VCARD
EOF

    my $VCard = Net::CardDAVTalk::VCard->new_fromstring($Str);

    my $uid = $CardDAV->NewContact($Id, $VCard);

    my $res = $CardDAV->Request('GET', '/dblookup/email2uids', '',
        User => 'cassandane',
        Key => "user\@example.com",
        Mailbox => 'foo',
    );

    # XXX: actually compare to the UID
}

sub test_email2details
    :min_version_3_1 :needs_component_httpd
{
    my ($self) = @_;

    my $CardDAV = $self->{carddav};
    my $Id = $CardDAV->NewAddressBook('foo');
    $self->assert_not_null($Id);
    $self->assert_str_equals($Id, 'foo');

    my $Str = <<EOF;
BEGIN:VCARD
VERSION:3.0
N:Gump;Forrest;;Mr.
FN:Forrest Gump
ORG:Bubba Gump Shrimp Co.
TITLE:Shrimp Man
EMAIL;TYPE=INTERNET:user\@example.com
REV:2008-04-24T19:52:43Z
END:VCARD
EOF

    my $VCard = Net::CardDAVTalk::VCard->new_fromstring($Str);

    my $uid = $CardDAV->NewContact($Id, $VCard);

    my $res = $CardDAV->Request('GET', '/dblookup/email2details', '',
        User => 'cassandane',
        Key => "user\@example.com",
        Mailbox => 'foo',
    );

    # XXX: actually compare to the UID
}

1;

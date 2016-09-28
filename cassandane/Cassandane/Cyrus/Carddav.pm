#!/usr/bin/perl
#
#  Copyright (c) 2011 Opera Software Australia Pty. Ltd.  All rights
#  reserved.
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
#  3. The name "Opera Software Australia" must not be used to
#     endorse or promote products derived from this software without
#     prior written permission. For permission or any legal
#     details, please contact
# 	Opera Software Australia Pty. Ltd.
# 	Level 50, 120 Collins St
# 	Melbourne 3000
# 	Victoria
# 	Australia
#
#  4. Redistributions of any form whatsoever must retain the following
#     acknowledgment:
#     "This product includes software developed by Opera Software
#     Australia Pty. Ltd."
#
#  OPERA SOFTWARE AUSTRALIA DISCLAIMS ALL WARRANTIES WITH REGARD TO
#  THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
#  AND FITNESS, IN NO EVENT SHALL OPERA SOFTWARE AUSTRALIA BE LIABLE
#  FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
#  WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
#  AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
#  OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#

package Cassandane::Cyrus::Carddav;
use strict;
use warnings;
use DateTime;
use JSON::XS;
use Net::CardDAVTalk 0.03;
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
    $config->set(httpmodules => 'carddav');
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


sub test_carddavcreate
{
    my ($self) = @_;

    my $CardDAV = $self->{carddav};

    my $Id = $CardDAV->NewAddressBook('foo');
    $self->assert_not_null($Id);
}

sub test_counters
    :Conversations :min_version_3_0
{
    my ($self) = @_;
    my $KEY = "/private/vendor/cmu/cyrus-imapd/usercounters";

    my $CardDAV = $self->{carddav};
    my $Id = $CardDAV->NewAddressBook('foo');
    $self->assert_not_null($Id);
    $self->assert_str_equals($Id, 'foo');

    my $talk = $self->{store}->get_client();

    my $counters1 = $talk->getmetadata("", $KEY);
    $counters1 = $counters1->{''}{$KEY};
    my ($v1, $all1, $mail1, $cal1, $card1, $notes1, $mailfolders1, $calfolders1, $cardfolders1, $notesfolders1, $valid1, $nothing1) = split / /, $counters1;

    my $VCard = Net::CardDAVTalk::VCard->new_fromstring(<<EOF);
BEGIN:VCARD
VERSION:3.0
N:Gump;Forrest;;Mr.
FN:Forrest Gump
ORG:Bubba Gump Shrimp Co.
TITLE:Shrimp Man
PHOTO;VALUE=URL;TYPE=GIF:http://www.example.com/dir_photos/my_photo.gif
TEL;TYPE=WORK,VOICE:(111) 555-1212
TEL;TYPE=HOME,VOICE:(404) 555-1212
ADR;TYPE=WORK:;;100 Waters Edge;Baytown;LA;30314;United States of America
LABEL;TYPE=WORK:100 Waters Edge\\nBaytown\\, LA 30314\\nUnited States of Ameri
 ca
ADR;TYPE=HOME:;;42 Plantation St.;Baytown;LA;30314;United States of America
LABEL;TYPE=HOME:42 Plantation St.\\nBaytown\\, LA 30314\\nUnited States of Ame
 rica
EMAIL;TYPE=PREF,INTERNET:forrestgump\@example.com
REV:2008-04-24T19:52:43Z
END:VCARD
EOF

    $CardDAV->NewContact($Id, $VCard);

    my $counters2 = $talk->getmetadata("", $KEY);
    $counters2 = $counters2->{''}{$KEY};

    my ($v2, $all2, $mail2, $cal2, $card2, $notes2, $mailfolders2, $calfolders2, $cardfolders2, $notesfolders2, $valid2, $nothing2) = split / /, $counters2;

    $self->assert_num_equals($v1, $v2);
    $self->assert_num_not_equals($all1, $all2);
    $self->assert_num_equals($mail1, $mail2);
    $self->assert_num_equals($cal1, $cal2);
    $self->assert_num_not_equals($card1, $card2);
    $self->assert_num_equals($notes1, $notes2);
    $self->assert_num_equals($mailfolders1, $mailfolders2);
    $self->assert_num_equals($calfolders1, $calfolders2);
    $self->assert_num_equals($cardfolders1, $cardfolders2);
    $self->assert_num_equals($notesfolders1, $notesfolders2);
    $self->assert_num_equals($valid1, $valid2);
    $self->assert_null($nothing1);
    $self->assert_null($nothing2);
}

sub test_many_emails
{
    my ($self) = @_;

    my $CardDAV = $self->{carddav};
    my $Id = $CardDAV->NewAddressBook('foo');
    $self->assert_not_null($Id);
    $self->assert_str_equals($Id, 'foo');

    my $Phones = join("\r\n", map { sprintf("TEL;TYPE=HOME:(101) 555-%04d", $_) } (1..1000));
    my $Emails = join("\r\n", map { sprintf("EMAIL;TYPE=INTERNET:user%04d\@example.com", $_) } (1..1000));

    my $Str = <<EOF;
BEGIN:VCARD
VERSION:3.0
N:Gump;Forrest;;Mr.
FN:Forrest Gump
ORG:Bubba Gump Shrimp Co.
TITLE:Shrimp Man
$Phones
$Emails
REV:2008-04-24T19:52:43Z
END:VCARD
EOF

    my $VCard = Net::CardDAVTalk::VCard->new_fromstring($Str);

    $CardDAV->NewContact($Id, $VCard);
}

sub test_homeset_extradomain
    :ReverseACLs :min_version_3_0
{
    my ($self) = @_;

    my $service = $self->{instance}->get_service("http");
    my $talk = Net::CardDAVTalk->new(
	user => 'cassandane%extradomain.com',
	password => 'pass',
	host => $service->host(),
	port => $service->port(),
	scheme => 'http',
	url => '/',
	expandurl => 1,
    );

    $self->assert_str_equals("/dav/addressbooks/user/cassandane\@extradomain.com/", $talk->{basepath});
}

sub test_no_filter
{
    my ($self) = @_;

    my $CardDAV = $self->{carddav};
    my $Id = $CardDAV->NewAddressBook('foo');
    $self->assert_not_null($Id);
    $self->assert_str_equals($Id, 'foo');

    my $xml = <<EOF;
<C:addressbook-query xmlns:D="DAV:"
                    xmlns:C="urn:ietf:params:xml:ns:carddav">
    <D:prop>
      <D:getetag/>
      <C:address-data content-type="text/vcard" version="3.0"/>
    </D:prop>
</C:addressbook-query>
EOF

    my $Str = <<EOF;
BEGIN:VCARD
VERSION:3.0
N:Gump;Forrest;;Mr.
FN:Forrest Gump
ORG:Bubba Gump Shrimp Co.
TITLE:Shrimp Man
REV:2008-04-24T19:52:43Z
END:VCARD
EOF

    my $VCard = Net::CardDAVTalk::VCard->new_fromstring($Str);

    $CardDAV->NewContact($Id, $VCard);

    my $res = $CardDAV->Request('REPORT', "/dav/addressbooks/user/cassandane/$Id", $xml, Depth => 0, 'Content-Type' => 'text/xml');

    $self->assert_not_null($res->{"{DAV:}response"});
}

sub test_empty_filter
{
    my ($self) = @_;

    my $CardDAV = $self->{carddav};
    my $Id = $CardDAV->NewAddressBook('foo');
    $self->assert_not_null($Id);
    $self->assert_str_equals($Id, 'foo');

    my $xml = <<EOF;
<C:addressbook-query xmlns:D="DAV:"
                    xmlns:C="urn:ietf:params:xml:ns:carddav">
    <D:prop>
      <D:getetag/>
      <C:address-data content-type="text/vcard" version="3.0"/>
    </D:prop>
    <C:filter/>
</C:addressbook-query>
EOF

    my $Str = <<EOF;
BEGIN:VCARD
VERSION:3.0
N:Gump;Forrest;;Mr.
FN:Forrest Gump
ORG:Bubba Gump Shrimp Co.
TITLE:Shrimp Man
REV:2008-04-24T19:52:43Z
END:VCARD
EOF

    my $VCard = Net::CardDAVTalk::VCard->new_fromstring($Str);

    $CardDAV->NewContact($Id, $VCard);

    my $res = $CardDAV->Request('REPORT', "/dav/addressbooks/user/cassandane/$Id", $xml, Depth => 0, 'Content-Type' => 'text/xml');

    $self->assert_not_null($res->{"{DAV:}response"});
}

sub test_sharing_samedomain
    :VirtDomains :FastMailSharing :ReverseACLs :min_version_3_0
{
    my ($self) = @_;

    my $admintalk = $self->{adminstore}->get_client();
    $admintalk->create("user.user1\@example.com");
    $admintalk->setacl("user.user1\@example.com", "user1\@example.com", 'lrswipkxtecdan');
    $admintalk->create("user.user2\@example.com");
    $admintalk->setacl("user.user2\@example.com", "user2\@example.com", 'lrswipkxtecdan');

    my $service = $self->{instance}->get_service("http");
    my $talk1 = Net::CardDAVTalk->new(
	user => 'user1@example.com',
	password => 'pass',
	host => $service->host(),
	port => $service->port(),
	scheme => 'http',
	url => '/',
	expandurl => 1,
    );
    my $talk2 = Net::CardDAVTalk->new(
	user => 'user2@example.com',
	password => 'pass',
	host => $service->host(),
	port => $service->port(),
	scheme => 'http',
	url => '/',
	expandurl => 1,
    );

    $talk2->NewAddressBook("Shared", name => "Shared Address Book");
    $admintalk->setacl("user.user2.#addressbooks.Shared\@example.com", "user1\@example.com", 'lrsn');

    my $Addressbooks = $talk1->GetAddressBooks();

    $self->assert_deep_equals([
          {
            'name' => 'personal',
            'isReadOnly' => 0,
            'path' => 'Default',
            'href' => '/dav/addressbooks/user/user1@example.com/Default/'
          },
          {
            'path' => '/dav/addressbooks/zzzz/user2@example.com/Shared',
            'href' => '/dav/addressbooks/zzzz/user2@example.com/Shared/',
            'name' => 'Shared Address Book',
            'isReadOnly' => 1,
          }
        ], $Addressbooks);
}

sub test_sharing_crossdomain
    :VirtDomains :CrossDomains :FastMailSharing :ReverseACLs :min_version_3_0
{
    my ($self) = @_;

    my $admintalk = $self->{adminstore}->get_client();
    $admintalk->create("user.user1\@example.com");
    $admintalk->setacl("user.user1\@example.com", "user1\@example.com", 'lrswipkxtecdan');
    $admintalk->create("user.user2\@example.org");
    $admintalk->setacl("user.user2\@example.org", "user2\@example.org", 'lrswipkxtecdan');

    my $service = $self->{instance}->get_service("http");
    my $talk1 = Net::CardDAVTalk->new(
	user => 'user1@example.com',
	password => 'pass',
	host => $service->host(),
	port => $service->port(),
	scheme => 'http',
	url => '/',
	expandurl => 1,
    );
    my $talk2 = Net::CardDAVTalk->new(
	user => 'user2@example.org',
	password => 'pass',
	host => $service->host(),
	port => $service->port(),
	scheme => 'http',
	url => '/',
	expandurl => 1,
    );

    $talk2->NewAddressBook("Shared", name => "Shared Address Book");
    $admintalk->setacl("user.user2.#addressbooks.Shared\@example.org", "user1\@example.com", 'lrsn');

    my $Addressbooks = $talk1->GetAddressBooks();

    $self->assert_deep_equals([
          {
            'name' => 'personal',
            'isReadOnly' => 0,
            'path' => 'Default',
            'href' => '/dav/addressbooks/user/user1@example.com/Default/'
          },
          {
            'path' => '/dav/addressbooks/zzzz/user2@example.org/Shared',
            'href' => '/dav/addressbooks/zzzz/user2@example.org/Shared/',
            'name' => 'Shared Address Book',
            'isReadOnly' => 1
          }
        ], $Addressbooks);
}

sub test_control_chars
{
    my ($self) = @_;

    my $CardDAV = $self->{carddav};
    my $Id = $CardDAV->NewAddressBook('foo');
    $self->assert_not_null($Id);
    $self->assert_str_equals($Id, 'foo');
    my $href = "$Id/bar.vcf";

    my $card = <<EOF;
BEGIN:VCARD
VERSION:3.0
UID:123456789
N:Gump;Forrest;;Mr.
FN:Forrest\b Gump
ORG:Bubba Gump Shrimp Co.
TITLE:Shrimp Man
REV:2008-04-24T19:52:43Z
END:VCARD
EOF

    my $repair = $self->{instance}->{config}->get('carddav_repair_vcard');
    if ($repair ne 'yes') {
        eval { $CardDAV->Request('PUT', $href, $card, 'Content-Type' => 'text/vcard') };
        my $Err = $@;
        $self->assert_matches(qr/valid-address-data/, $Err);
    } else {
        my $VCard = Net::CardDAVTalk::VCard->new_fromstring($card);
        my $path = $CardDAV->NewContact($Id, $VCard);
        my $res = $CardDAV->GetContact($path);
        $self->assert_str_equals($res->{properties}{fn}[0]{value}, 'Forrest Gump');
    }
}

1;

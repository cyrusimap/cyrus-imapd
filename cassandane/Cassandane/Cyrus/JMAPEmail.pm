#!/usr/bin/perl
#
#  Copyright (c) 2017 FastMail Pty Ltd  All rights reserved.
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
#  FASTMAIL PTY LTD DISCLAIMS ALL WARRANTIES WITH REGARD TO
#  THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
#  AND FITNESS, IN NO EVENT SHALL OPERA SOFTWARE AUSTRALIA BE LIABLE
#  FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
#  WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
#  AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
#  OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#

package Cassandane::Cyrus::JMAPEmail;
use strict;
use warnings;
use DateTime;
use JSON::XS;
use Net::CalDAVTalk 0.09;
use Net::CardDAVTalk 0.03;
use Mail::JMAPTalk 0.13;
use Data::Dumper;
use Storable 'dclone';
use MIME::Base64 qw(encode_base64);
use Cwd qw(abs_path getcwd);
use URI;

use lib '.';
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
                 jmapsubmission_deleteonsend => 'no',
                 httpmodules => 'carddav caldav jmap',
                 httpallowcompress => 'no');

    # setup sieve
    my ($maj, $min) = Cassandane::Instance->get_version();
    if ($maj == 3 && $min == 0) {
        # need to explicitly add 'body' to sieve_extensions for 3.0
        $config->set(sieve_extensions =>
            "fileinto reject vacation vacation-seconds imap4flags notify " .
            "envelope relational regex subaddress copy date index " .
            "imap4flags mailbox mboxmetadata servermetadata variables " .
            "body");
    }
    elsif ($maj < 3) {
        # also for 2.5 (the earliest Cyrus that Cassandane can test)
        $config->set(sieve_extensions =>
            "fileinto reject vacation vacation-seconds imap4flags notify " .
            "envelope relational regex subaddress copy date index " .
            "imap4flags body");
    }
    $config->set(sievenotifier => 'mailto');

    return $class->SUPER::new({
        config => $config,
        jmap => 1,
        deliver => 1,
        adminstore => 1,
        services => [ 'imap', 'http', 'sieve' ]
    }, @args);
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

sub get_account_capabilities
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    my $Request;
    my $Response;

    xlog $self, "get session";
    $Request = {
        headers => {
            'Authorization' => $jmap->auth_header(),
        },
        content => '',
    };
    $Response = $jmap->ua->get($jmap->uri(), $Request);
    if ($ENV{DEBUGJMAP}) {
        warn "JMAP " . Dumper($Request, $Response);
    }
    $self->assert_str_equals('200', $Response->{status});

    my $session;
    $session = eval { decode_json($Response->{content}) } if $Response->{success};

    return $session->{accounts}{cassandane}{accountCapabilities};
}


sub defaultprops_for_email_get
{
    return ( "id", "blobId", "threadId", "mailboxIds", "keywords", "size", "receivedAt", "messageId", "inReplyTo", "references", "sender", "from", "to", "cc", "bcc", "replyTo", "subject", "sentAt", "hasAttachment", "preview", "bodyValues", "textBody", "htmlBody", "attachments" );
}

sub test_email_get
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();

    my $res = $jmap->CallMethods([['Mailbox/get', { }, "R1"]]);
    my $inboxid = $res->[0][1]{list}[0]{id};

    my $body = "";
    $body .= "Lorem ipsum dolor sit amet, consectetur adipiscing\r\n";
    $body .= "elit. Nunc in fermentum nibh. Vivamus enim metus.";

    my $maildate = DateTime->now();
    $maildate->add(DateTime::Duration->new(seconds => -10));

    xlog $self, "Generate a email in INBOX via IMAP";
    my %exp_inbox;
    my %params = (
        date => $maildate,
        from => Cassandane::Address->new(
            name => "Sally Sender",
            localpart => "sally",
            domain => "local"
        ),
        to => Cassandane::Address->new(
            name => "Tom To",
            localpart => 'tom',
            domain => 'local'
        ),
        cc => Cassandane::Address->new(
            name => "Cindy CeeCee",
            localpart => 'cindy',
            domain => 'local'
        ),
        bcc => Cassandane::Address->new(
            name => "Benny CarbonCopy",
            localpart => 'benny',
            domain => 'local'
        ),
        messageid => 'fake.123456789@local',
        extra_headers => [
            ['x-tra', "foo bar\r\n baz"],
            ['sender', "Bla <blu\@local>"],
        ],
        body => $body
    );
    $self->make_message("Email A", %params) || die;

    xlog $self, "get email list";
    $res = $jmap->CallMethods([['Email/query', {}, "R1"]]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{ids}});

    my @props = $self->defaultprops_for_email_get();

    push @props, "header:x-tra";

    xlog $self, "get emails";
    my $ids = $res->[0][1]->{ids};
    $res = $jmap->CallMethods([['Email/get', { ids => $ids, properties => \@props }, "R1"]]);
    my $msg = $res->[0][1]->{list}[0];

    $self->assert_not_null($msg->{mailboxIds}{$inboxid});
    $self->assert_num_equals(1, scalar keys %{$msg->{mailboxIds}});
    $self->assert_num_equals(0, scalar keys %{$msg->{keywords}});

    $self->assert_str_equals('fake.123456789@local', $msg->{messageId}[0]);
    $self->assert_str_equals(" foo bar\r\n baz", $msg->{'header:x-tra'});
    $self->assert_deep_equals({
            name => "Sally Sender",
            email => "sally\@local"
    }, $msg->{from}[0]);
    $self->assert_deep_equals({
            name => "Tom To",
            email => "tom\@local"
    }, $msg->{to}[0]);
    $self->assert_num_equals(1, scalar @{$msg->{to}});
    $self->assert_deep_equals({
            name => "Cindy CeeCee",
            email => "cindy\@local"
    }, $msg->{cc}[0]);
    $self->assert_num_equals(1, scalar @{$msg->{cc}});
    $self->assert_deep_equals({
            name => "Benny CarbonCopy",
            email => "benny\@local"
    }, $msg->{bcc}[0]);
    $self->assert_num_equals(1, scalar @{$msg->{bcc}});
    $self->assert_null($msg->{replyTo});
    $self->assert_deep_equals([{
            name => "Bla",
            email => "blu\@local"
    }], $msg->{sender});
    $self->assert_str_equals("Email A", $msg->{subject});

    my $datestr = $maildate->strftime('%Y-%m-%dT%TZ');
    $self->assert_str_equals($datestr, $msg->{receivedAt});
    $self->assert_not_null($msg->{size});
}

sub test_email_get_mimeencode
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();

    my $res = $jmap->CallMethods([['Mailbox/get', { }, "R1"]]);
    my $inboxid = $res->[0][1]{list}[0]{id};

    my $body = "a body";

    my $maildate = DateTime->now();
    $maildate->add(DateTime::Duration->new(seconds => -10));

     # Thanks to http://dogmamix.com/MimeHeadersDecoder/ for examples

    xlog $self, "Generate a email in INBOX via IMAP";
    my %exp_inbox;
    my %params = (
        date => $maildate,
        from => Cassandane::Address->new(
            name => "=?ISO-8859-1?Q?Keld_J=F8rn_Simonsen?=",
            localpart => "keld",
            domain => "local"
        ),
        to => Cassandane::Address->new(
            name => "=?US-ASCII?Q?Tom To?=",
            localpart => 'tom',
            domain => 'local'
        ),
        messageid => 'fake.123456789@local',
        extra_headers => [
            ['x-tra', "foo bar\r\n baz"],
            ['sender', "Bla <blu\@local>"],
            ['x-mood', '=?UTF-8?Q?I feel =E2=98=BA?='],
        ],
        body => $body
    );

    $self->make_message(
          "=?ISO-8859-1?B?SWYgeW91IGNhbiByZWFkIHRoaXMgeW8=?= " .
          "=?ISO-8859-2?B?dSB1bmRlcnN0YW5kIHRoZSBleGFtcGxlLg==?=",
    %params ) || die;

    xlog $self, "get email list";
    $res = $jmap->CallMethods([
        ['Email/query', { }, 'R1'],
        ['Email/get', {
            '#ids' => {
                resultOf => 'R1',
                name => 'Email/query',
                path => '/ids'
            },
            properties => [ 'subject', 'header:x-mood:asText', 'from', 'to' ],
        }, 'R2'],
    ]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{ids}});
    my $msg = $res->[1][1]->{list}[0];

    $self->assert_str_equals("If you can read this you understand the example.", $msg->{subject});
    $self->assert_str_equals("I feel \N{WHITE SMILING FACE}", $msg->{'header:x-mood:asText'});
    $self->assert_str_equals("Keld J\N{LATIN SMALL LETTER O WITH STROKE}rn Simonsen", $msg->{from}[0]{name});
    $self->assert_str_equals("Tom To", $msg->{to}[0]{name});
}

sub test_email_get_multimailboxes
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();

    my $now = DateTime->now();

    xlog $self, "Generate a email in INBOX via IMAP";
    my $res = $self->make_message("foo") || die;
    my $uid = $res->{attrs}->{uid};
    my $msg;

    xlog $self, "get email";
    $res = $jmap->CallMethods([
        ['Email/query', {}, "R1"],
        ['Email/get', { '#ids' => { resultOf => 'R1', name => 'Email/query', path => '/ids' } }, 'R2'],
    ]);
    $msg = $res->[1][1]{list}[0];
    $self->assert_num_equals(1, scalar @{$res->[0][1]{ids}});
    $self->assert_num_equals(1, scalar keys %{$msg->{mailboxIds}});

    xlog $self, "Create target mailbox";
    $talk->create("INBOX.target");

    xlog $self, "Copy email into INBOX.target";
    $talk->copy($uid, "INBOX.target");

    xlog $self, "get email";
    $res = $jmap->CallMethods([
        ['Email/query', {}, "R1"],
        ['Email/get', { '#ids' => { resultOf => 'R1', name => 'Email/query', path => '/ids' } }, 'R2'],
    ]);
    $msg = $res->[1][1]{list}[0];
    $self->assert_num_equals(1, scalar @{$res->[0][1]{ids}});
    $self->assert_num_equals(2, scalar keys %{$msg->{mailboxIds}});
}

sub test_email_get_multimailboxes_expunged
    :min_version_3_1 :needs_component_jmap :DelayedExpunge
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();

    my $now = DateTime->now();

    xlog $self, "Generate a email in INBOX via IMAP";
    my $res = $self->make_message("foo") || die;
    my $uid = $res->{attrs}->{uid};
    my $msg;

    xlog $self, "get email";
    $res = $jmap->CallMethods([
        ['Email/query', {}, "R1"],
        ['Email/get', { '#ids' => { resultOf => 'R1', name => 'Email/query', path => '/ids' } }, 'R2'],
    ]);
    $msg = $res->[1][1]{list}[0];
    $self->assert_num_equals(1, scalar @{$res->[0][1]{ids}});
    $self->assert_num_equals(1, scalar keys %{$msg->{mailboxIds}});

    xlog $self, "Create target mailbox";
    $talk->create("INBOX.target");

    xlog $self, "Copy email into INBOX.target";
    $talk->copy($uid, "INBOX.target");

    xlog $self, "get email";
    $res = $jmap->CallMethods([
        ['Email/query', {}, "R1"],
        ['Email/get', { '#ids' => { resultOf => 'R1', name => 'Email/query', path => '/ids' } }, 'R2'],
    ]);
    $msg = $res->[1][1]{list}[0];
    $self->assert_num_equals(1, scalar @{$res->[0][1]{ids}});
    $self->assert_num_equals(2, scalar keys %{$msg->{mailboxIds}});
    my $val = join(',', sort keys %{$msg->{mailboxIds}});

    xlog $self, "Move the message to target2";
    $talk->create("INBOX.target2");
    $talk->copy($uid, "INBOX.target2");

    xlog $self, "and move it back again!";
    $talk->select("INBOX.target2");
    $talk->move("1:*", "INBOX");

    # and finally delete the SECOND copy by UID sorting
    xlog $self, "and delete one of them";
    $talk->select("INBOX");
    $talk->store('2', "+flags", "\\Deleted");
    $talk->expunge();

    xlog $self, "check that email is still in both mailboxes";
    $res = $jmap->CallMethods([
        ['Email/query', {}, "R1"],
        ['Email/get', { '#ids' => { resultOf => 'R1', name => 'Email/query', path => '/ids' } }, 'R2'],
    ]);
    $msg = $res->[1][1]{list}[0];
    $self->assert_num_equals(1, scalar @{$res->[0][1]{ids}});
    $self->assert_num_equals(2, scalar keys %{$msg->{mailboxIds}});
    $self->assert_str_equals($val, join(',', sort keys %{$msg->{mailboxIds}}));
}

sub test_email_get_body_both
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();
    my $inbox = 'INBOX';

    xlog $self, "Generate a email in $inbox via IMAP";
    my %exp_sub;
    $store->set_folder($inbox);
    $store->_select();
    $self->{gen}->set_next_uid(1);

    my $htmlBody = "<html><body><p>This is the html part.</p></body></html>";
    my $textBody = "This is the plain text part.";

    my $body = "--047d7b33dd729737fe04d3bde348\r\n";
    $body .= "Content-Type: text/plain; charset=UTF-8\r\n";
    $body .= "\r\n";
    $body .= $textBody;
    $body .= "\r\n";
    $body .= "--047d7b33dd729737fe04d3bde348\r\n";
    $body .= "Content-Type: text/html;charset=\"UTF-8\"\r\n";
    $body .= "\r\n";
    $body .= $htmlBody;
    $body .= "\r\n";
    $body .= "--047d7b33dd729737fe04d3bde348--\r\n";
    $exp_sub{A} = $self->make_message("foo",
        mime_type => "multipart/alternative",
        mime_boundary => "047d7b33dd729737fe04d3bde348",
        body => $body
    );

    xlog $self, "get email list";
    my $res = $jmap->CallMethods([['Email/query', {}, "R1"]]);
    my $ids = $res->[0][1]->{ids};

    xlog $self, "get email";
    $res = $jmap->CallMethods([['Email/get', { ids => $ids, fetchAllBodyValues => JSON::true }, "R1"]]);
    my $msg = $res->[0][1]{list}[0];

    my $partId = $msg->{textBody}[0]{partId};
    $self->assert_str_equals($textBody, $msg->{bodyValues}{$partId}{value});
    $partId = $msg->{htmlBody}[0]{partId};
    $self->assert_str_equals($htmlBody, $msg->{bodyValues}{$partId}{value});
}

sub test_email_get_body_plain
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();
    my $inbox = 'INBOX';

    xlog $self, "Generate a email in $inbox via IMAP";
    my %exp_sub;
    $store->set_folder($inbox);
    $store->_select();
    $self->{gen}->set_next_uid(1);

    my $body = "A plain text email.";
    $exp_sub{A} = $self->make_message("foo",
        body => $body
    );

    xlog $self, "get email list";
    my $res = $jmap->CallMethods([['Email/query', {}, "R1"]]);
    my $ids = $res->[0][1]->{ids};

    xlog $self, "get emails";
    $res = $jmap->CallMethods([['Email/get', { ids => $ids, fetchAllBodyValues => JSON::true,  }, "R1"]]);
    my $msg = $res->[0][1]{list}[0];

    my $partId = $msg->{textBody}[0]{partId};
    $self->assert_str_equals($body, $msg->{bodyValues}{$partId}{value});
    $self->assert_str_equals($msg->{textBody}[0]{partId}, $msg->{htmlBody}[0]{partId});
}

sub test_email_get_body_html
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();
    my $inbox = 'INBOX';

    xlog $self, "Generate a email in $inbox via IMAP";
    my %exp_sub;
    $store->set_folder($inbox);
    $store->_select();
    $self->{gen}->set_next_uid(1);

    my $body = "<html><body> <p>A HTML email.</p> </body></html>";
    $exp_sub{A} = $self->make_message("foo",
        mime_type => "text/html",
        body => $body
    );

    xlog $self, "get email list";
    my $res = $jmap->CallMethods([['Email/query', {}, "R1"]]);
    my $ids = $res->[0][1]->{ids};

    xlog $self, "get email";
    $res = $jmap->CallMethods([['Email/get', { ids => $ids, fetchAllBodyValues => JSON::true }, "R1"]]);
    my $msg = $res->[0][1]{list}[0];

    my $partId = $msg->{htmlBody}[0]{partId};
    $self->assert_str_equals($body, $msg->{bodyValues}{$partId}{value});
}

sub test_email_get_attachment_name
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();
    my $inbox = 'INBOX';

    xlog $self, "Generate a email in $inbox via IMAP";
    my %exp_sub;
    $store->set_folder($inbox);
    $store->_select();
    $self->{gen}->set_next_uid(1);

    my $body = "".
    "--sub\r\n".
    "Content-Type: image/jpeg\r\n".
    "Content-Disposition: attachment; filename\r\n\t=\"image1.jpg\"\r\n".
    "Content-Transfer-Encoding: base64\r\n".
    "\r\n" .
    "beefc0de".
    "\r\n--sub\r\n".
    "Content-Type: image/tiff\r\n".
    "Content-Transfer-Encoding: base64\r\n".
    "\r\n" .
    "abc=".
    "\r\n--sub\r\n".
    "Content-Type: application/x-excel\r\n".
    "Content-Transfer-Encoding: base64\r\n".
    "Content-Disposition: attachment; filename\r\n\t=\"f.xls\"\r\n".
    "\r\n" .
    "012312312313".
    "\r\n--sub\r\n".
    "Content-Type: application/test1;name=y.dat\r\n".
    "Content-Disposition: attachment; filename=z.dat\r\n".
    "\r\n" .
    "test1".
    "\r\n--sub\r\n".
    "Content-Type: application/test2;name*0=looo;name*1=ooong;name*2=.name\r\n".
    "\r\n" .
    "test2".
    "\r\n--sub\r\n".
    "Content-Type: application/test3\r\n".
    "Content-Disposition: attachment; filename*0=cont;\r\n filename*1=inue\r\n".
    "\r\n" .
    "test3".
    "\r\n--sub\r\n".
    "Content-Type: application/test4; name=\"=?utf-8?Q?=F0=9F=98=80=2Etxt?=\"\r\n".
    "\r\n" .
    "test4".
    "\r\n--sub\r\n".
    "Content-Type: application/test5\r\n".
    "Content-Disposition: attachment; filename*0*=utf-8''%F0%9F%98%80;\r\n filename*1=\".txt\"\r\n".
    "\r\n" .
    "test5".
    "\r\n--sub\r\n".
    "Content-Type: application/test6\r\n" .
    "Content-Disposition: attachment;\r\n".
    " filename*0*=\"Unencoded ' char\";\r\n" .
    " filename*1*=\".txt\"\r\n" .
    "\r\n" .
    "test6".

    # RFC 2045, section 5.1. requires quoted-string for parameter
    # values with tspecial or whitespace, but some clients ignore
    # this. The following tests check Cyrus leniently accept this.

    "\r\n--sub\r\n".
    "Content-Type: application/test7; name==?iso-8859-1?b?Q2Fm6S5kb2M=?=\r\n".
    "Content-Disposition: attachment; filename==?iso-8859-1?b?Q2Fm6S5kb2M=?=\r\n".
    "\r\n" .
    "test7".
    "\r\n--sub\r\n".
    "Content-Type: application/test8; name= foo \r\n".
    "\r\n" .
    "test8".
    "\r\n--sub\r\n".
    "Content-Type: application/test9; name=foo bar\r\n".
    "\r\n" .
    "test9".
    "\r\n--sub\r\n".
    "Content-Type: application/test10; name=foo bar\r\n\t baz \r\n".
    "\r\n" .
    "test10".
    "\r\n--sub\r\n".
    "Content-Type: application/test11; name=\r\n\t baz \r\n".
    "\r\n" .
    "test11".
    "\r\n--sub\r\n".
    "Content-Type: application/test12; name= \r\n\t  \r\n".
    "\r\n" .
    "test12".

    "\r\n--sub\r\n".
    "Content-Type: application/test13\r\n".
    "Content-Disposition: attachment; filename=\"q\\\".dat\"\r\n".
    "\r\n" .
    "test13".

    # Some clients send raw UTF-8 characters in MIME parameters.
    # The following test checks Cyrus leniently accept this.
    "\r\n--sub\r\n".
    "Content-Type: application/test14; name=😀.txt\r\n".
    "\r\n" .
    "test14".

    "\r\n--sub--\r\n";

    $exp_sub{A} = $self->make_message("foo",
        mime_type => "multipart/mixed",
        mime_boundary => "sub",
        body => $body
    );
    $talk->store('1', '+flags', '($HasAttachment)');

    xlog $self, "get email list";
    my $res = $jmap->CallMethods([['Email/query', {}, "R1"]]);
    my $ids = $res->[0][1]->{ids};

    xlog $self, "get email";
    $res = $jmap->CallMethods([['Email/get', { ids => $ids }, "R1"]]);
    my $msg = $res->[0][1]{list}[0];

    $self->assert_equals(JSON::true, $msg->{hasAttachment});

    # Assert embedded email support
    my %m = map { $_->{type} => $_ } @{$msg->{attachments}};
    my $att;

    $att = $m{"image/tiff"};
    $self->assert_null($att->{name});

    $att = $m{"application/x-excel"};
    $self->assert_str_equals("f.xls", $att->{name});

    $att = $m{"image/jpeg"};
    $self->assert_str_equals("image1.jpg", $att->{name});

    $att = $m{"application/test1"};
    $self->assert_str_equals("z.dat", $att->{name});

    $att = $m{"application/test2"};
    $self->assert_str_equals("loooooong.name", $att->{name});

    $att = $m{"application/test3"};
    $self->assert_str_equals("continue", $att->{name});

    $att = $m{"application/test4"};
    $self->assert_str_equals("\N{GRINNING FACE}.txt", $att->{name});

    $att = $m{"application/test5"};
    $self->assert_str_equals("\N{GRINNING FACE}.txt", $att->{name});

    $att = $m{"application/test6"};
    $self->assert_str_equals("Unencoded ' char.txt", $att->{name});

    $att = $m{"application/test7"};
    $self->assert_str_equals("Caf\N{LATIN SMALL LETTER E WITH ACUTE}.doc", $att->{name});

    $att = $m{"application/test8"};
    $self->assert_str_equals("foo", $att->{name});

    $att = $m{"application/test9"};
    $self->assert_str_equals("foo bar", $att->{name});

    $att = $m{"application/test10"};
    $self->assert_str_equals("foo bar\t baz", $att->{name});

    $att = $m{"application/test11"};
    $self->assert_str_equals("baz", $att->{name});

    $att = $m{"application/test12"};
    $self->assert_null($att->{name});

    $att = $m{"application/test13"};
    $self->assert_str_equals('q".dat', $att->{name});

    $att = $m{"application/test14"};
    $self->assert_str_equals("\N{GRINNING FACE}.txt", $att->{name});
}

sub test_email_get_body_notext
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();
    my $inbox = 'INBOX';

    # Generate a email to have some blob ids
    xlog $self, "Generate a email in $inbox via IMAP";
    $self->make_message("foo",
        mime_type => "application/zip",
        body => "boguszip",
    );

    xlog $self, "get email list";
    my $res = $jmap->CallMethods([
        ['Email/query', { }, "R1"],
        ['Email/get', { '#ids' => { resultOf => 'R1', name => 'Email/query', path => '/ids' } }, 'R2'],
    ]);
    my $msg = $res->[1][1]->{list}[0];

    $self->assert_deep_equals([], $msg->{textBody});
    $self->assert_deep_equals([], $msg->{htmlBody});
}


sub test_email_get_preview
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();
    my $inbox = 'INBOX';

    xlog $self, "Generate a email in $inbox via IMAP";
    my %exp_sub;
    $store->set_folder($inbox);
    $store->_select();
    $self->{gen}->set_next_uid(1);

    my $body = "A   plain\r\ntext email.";
    $exp_sub{A} = $self->make_message("foo",
        body => $body
    );

    xlog $self, "get email list";
    my $res = $jmap->CallMethods([['Email/query', {}, "R1"]]);

    xlog $self, "get emails";
    $res = $jmap->CallMethods([['Email/get', { ids => $res->[0][1]->{ids} }, "R1"]]);
    my $msg = $res->[0][1]{list}[0];

    $self->assert_str_equals('A plain text email.', $msg->{preview});
}

sub test_email_get_imagesize
    :min_version_3_1 :needs_component_jmap
{
    # This is a FastMail-extension

    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();
    $store->set_folder('INBOX');

    # Part 1 has no imagesize defined, part 2 defines no EXIF
    # orientation, part 3 defines all image size properties.
    my $imageSize = {
        '2' => [1,2],
        '3' => [1,2,3],
    };

    # Generate an email with image MIME parts.
    xlog $self, "Generate an email via IMAP";
    my $msg = $self->make_message("foo",
        mime_type => "multipart/mixed",
        mime_boundary => "sub",
        body => ""
          . "--sub\r\n"
          . "Content-Type: text/plain; charset=UTF-8\r\n"
          . "some text"
          . "\r\n--sub\r\n"
          . "Content-Type: image/png\r\n"
          . "Content-Transfer-Encoding: base64\r\n"
          . "\r\n"
          . "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVQYV2NgYAAAAAMAAWgmWQ0AAAAASUVORK5CYII="
          . "\r\n--sub\r\n"
          . "Content-Type: image/png\r\n"
          . "Content-Transfer-Encoding: base64\r\n"
          . "\r\n"
          . "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVQYV2NgYAAAAAMAAWgmWQ0AAAAASUVORK5CYII="
          . "\r\n--sub\r\n"
          . "Content-Type: image/png\r\n"
          . "Content-Transfer-Encoding: base64\r\n"
          . "\r\n"
          . "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVQYV2NgYAAAAAMAAWgmWQ0AAAAASUVORK5CYII="
          . "\r\n--sub--\r\n",
    );
    xlog $self, "set imagesize annotation";
    my $annot = '/vendor/messagingengine.com/imagesize';
    my $ret = $talk->store('1', 'annotation', [
        $annot, ['value.shared', { Quote => encode_json($imageSize) }]
    ]);
    if (not $ret) {
        xlog $self, "Could not set $annot annotation. Aborting.";
        return;
    }

    xlog $self, "get email list";
    my $res = $jmap->CallMethods([['Email/query', {}, "R1"]]);
    my $ids = $res->[0][1]->{ids};

    xlog $self, "get email";
    $res = $jmap->CallMethods([['Email/get', {
        ids => $ids,
        properties => ['bodyStructure'],
        bodyProperties => ['partId', 'imageSize' ],
    }, "R1"]]);
    my $email = $res->[0][1]{list}[0];

    my $part = $email->{bodyStructure}{subParts}[0];
    $self->assert_str_equals('1', $part->{partId});
    $self->assert_null($part->{imageSize});

    $part = $email->{bodyStructure}{subParts}[1];
    $self->assert_str_equals('2', $part->{partId});
    $self->assert_deep_equals($imageSize->{2}, $part->{imageSize});

    $part = $email->{bodyStructure}{subParts}[2];
    $self->assert_str_equals('3', $part->{partId});
    $self->assert_deep_equals($imageSize->{3}, $part->{imageSize});
}

sub test_email_get_isdeleted
    :min_version_3_1 :needs_component_jmap
{
    # This is a FastMail-extension

    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();
    $store->set_folder('INBOX');

    my $msg = $self->make_message("foo",
        mime_type => "multipart/mixed",
        mime_boundary => "sub",
        body => ""
          . "--sub\r\n"
          . "Content-Type: text/plain; charset=UTF-8\r\n"
          . "some text"
          . "\r\n--sub\r\n"
          . "Content-Type: text/x-me-removed-file\r\n"
          . "\r\n"
          . "deleted"
          . "\r\n--sub--\r\n",
    );

    xlog $self, "get email list";
    my $res = $jmap->CallMethods([['Email/query', {}, "R1"]]);
    my $ids = $res->[0][1]->{ids};

    xlog $self, "get email";
    $res = $jmap->CallMethods([['Email/get', {
        ids => $ids,
        properties => ['bodyStructure'],
        bodyProperties => ['partId', 'isDeleted' ],
    }, "R1"]]);
    my $email = $res->[0][1]{list}[0];

    my $part = $email->{bodyStructure}{subParts}[0];
    $self->assert_str_equals('1', $part->{partId});
    $self->assert_equals(JSON::false, $part->{isDeleted});

    $part = $email->{bodyStructure}{subParts}[1];
    $self->assert_str_equals('2', $part->{partId});
    $self->assert_equals(JSON::true, $part->{isDeleted});
}

sub test_email_get_trustedsender
    :min_version_3_1 :needs_component_jmap
{
    # This is a FastMail-extension

    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();
    $store->set_folder('INBOX');

    my $msg = $self->make_message("foo");

    xlog $self, "Assert trustedSender isn't set";
    my $res = $jmap->CallMethods([
        ['Email/query', { }, "R1"],
        ['Email/get', {
            '#ids' => { resultOf => 'R1', name => 'Email/query', path => '/ids' },
            properties => [ 'id', 'trustedSender', 'keywords' ],
        }, 'R2'],
    ]);
    my $emailId = $res->[0][1]{ids}[0];
    my $email = $res->[1][1]{list}[0];
    $self->assert_null($email->{trustedSender});

    xlog $self, "Set IsTrusted flag";
    $talk->store('1', '+flags', '($IsTrusted)');

    xlog $self, "Assert trustedSender isn't set";
    $res = $jmap->CallMethods([['Email/get', {
        ids => [$emailId], properties => [ 'id', 'trustedSender', 'keywords' ],
    }, 'R1']]);
    $email = $res->[0][1]{list}[0];
    $self->assert_null($email->{trustedSender});

    xlog $self, "Set zero-length trusted annotation";
    my $annot = '/vendor/messagingengine.com/trusted';
    my $ret = $talk->store('1', 'annotation', [
        $annot, ['value.shared', { Quote => '' }]
    ]);
    if (not $ret) {
        xlog $self, "Could not set $annot annotation. Aborting.";
        return;
    }

    xlog $self, "Assert trustedSender isn't set";
    $res = $jmap->CallMethods([['Email/get', {
        ids => [$emailId], properties => [ 'id', 'trustedSender', 'keywords' ],
    }, 'R1']]);
    $email = $res->[0][1]{list}[0];
    $self->assert_null($email->{trustedSender});

    xlog $self, "Set trusted annotation";
    $ret = $talk->store('1', 'annotation', [
        $annot, ['value.shared', { Quote => 'bar' }]
    ]);
    if (not $ret) {
        xlog $self, "Could not set $annot annotation. Aborting.";
        return;
    }

    xlog $self, "Assert trustedSender is set";
    $res = $jmap->CallMethods([['Email/get', {
        ids => [$emailId], properties => [ 'id', 'trustedSender', 'keywords' ],
    }, 'R1']]);
    $email = $res->[0][1]{list}[0];
    $self->assert_str_equals('bar', $email->{trustedSender});

    xlog $self, "Remove IsTrusted flag";
    $talk->store('1', '-flags', '($IsTrusted)');

    xlog $self, "Assert trustedSender isn't set";
    $res = $jmap->CallMethods([['Email/get', {
        ids => [$emailId], properties => [ 'id', 'trustedSender', 'keywords' ],
    }, 'R1']]);
    $email = $res->[0][1]{list}[0];
    $self->assert_null($email->{trustedSender});
}

sub test_email_get_shared
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();

    my $admintalk = $self->{adminstore}->get_client();

    # Share account
    $self->{instance}->create_user("other");
    $admintalk->setacl("user.other", "cassandane", "lr") or die;

    # Create mailbox A
    $admintalk->create("user.other.A") or die;
    $admintalk->setacl("user.other.A", "cassandane", "lr") or die;

    # Create message in mailbox A
    $self->{adminstore}->set_folder('user.other.A');
    $self->make_message("Email", store => $self->{adminstore}) or die;

    # Copy message to unshared mailbox B
    $admintalk->create("user.other.B") or die;
    $admintalk->setacl("user.other.B", "cassandane", "") or die;
    $admintalk->copy(1, "user.other.B");

    my @fetchEmailMethods = [
        ['Email/query', {
            accountId => 'other',
            collapseThreads => JSON::true,
        }, "R1"],
        ['Email/get', {
            accountId => 'other',
            properties => ['mailboxIds'],
            '#ids' => {
                resultOf => 'R1',
                name => 'Email/query',
                path => '/ids'
            },
            fetchAllBodyValues => JSON::true,
        }, 'R2' ],
    ];

    # Fetch Email
    my $res = $jmap->CallMethods(@fetchEmailMethods);
    $self->assert_num_equals(1, scalar @{$res->[1][1]{list}});
    $self->assert_num_equals(1, scalar keys %{$res->[1][1]{list}[0]{mailboxIds}});
        my $emailId = $res->[1][1]{list}[0]{id};

        # Share mailbox B
    $admintalk->setacl("user.other.B", "cassandane", "lr") or die;
    $res = $jmap->CallMethods(@fetchEmailMethods);
    $self->assert_num_equals(1, scalar @{$res->[1][1]{list}});
    $self->assert_num_equals(2, scalar keys %{$res->[1][1]{list}[0]{mailboxIds}});

        # Unshare mailboxes A and B
    $admintalk->setacl("user.other.A", "cassandane", "") or die;
    $admintalk->setacl("user.other.B", "cassandane", "") or die;
    $res = $jmap->CallMethods([['Email/get', {
        accountId => 'other',
        ids => [$emailId],
    }, 'R1']]);
    $self->assert_num_equals(0, scalar @{$res->[0][1]{list}});
    $self->assert_str_equals($emailId, $res->[0][1]{notFound}[0]);
}

sub test_email_move_shared
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();

    my $admintalk = $self->{adminstore}->get_client();

    # Share account
    $self->{instance}->create_user("other");
    $admintalk->setacl("user.other", "cassandane", "lr") or die;

    # Create mailbox A
    $admintalk->create("user.other.A") or die;
    $admintalk->setacl("user.other.A", "cassandane", "lrswipkxtecdan") or die;

    # Create message in mailbox A
    $self->{adminstore}->set_folder('user.other.A');
    $self->make_message("Email", store => $self->{adminstore}) or die;

    # Create mailbox B
    $admintalk->create("user.other.B") or die;
    $admintalk->setacl("user.other.B", "cassandane", "lrswipkxtecdan") or die;

    my @fetchEmailMethods = (
        ['Email/query', {
            accountId => 'other',
            collapseThreads => JSON::true,
        }, "R1"],
        ['Email/get', {
            accountId => 'other',
            properties => ['mailboxIds'],
            '#ids' => {
                resultOf => 'R1',
                name => 'Email/query',
                path => '/ids'
            },
            fetchAllBodyValues => JSON::true,
        }, 'R2' ],
    );

    # Fetch Email
    my $res = $jmap->CallMethods([@fetchEmailMethods, ['Mailbox/get', { accountId => 'other' }, 'R3']]);
    $self->assert_num_equals(1, scalar @{$res->[1][1]{list}});
    $self->assert_num_equals(1, scalar keys %{$res->[1][1]{list}[0]{mailboxIds}});
    my $emailId = $res->[1][1]{list}[0]{id};
    my %mbids = map { $_->{name} => $_->{id} } @{$res->[2][1]{list}};

    $res = $jmap->CallMethods([
        ['Email/set', {
            update => { $emailId => {
                "mailboxIds/$mbids{A}" => undef,
                "mailboxIds/$mbids{B}" => $JSON::true,
            }},
            accountId => 'other',
        }, 'R1'],
    ]);

    $self->assert_not_null($res->[0][1]{updated});
    $self->assert_null($res->[0][1]{notUpdated});
}

# a case where ANOTHER user moved an email from a folder with sharedseen
# enabled to a folder with different seen options enabled caused an IOERROR
# and DBERROR because the seen db was in a transaction, and hence led to
# this in the logs:
#
# IOERROR: append_addseen failed to open DB for foo@example.com
sub test_email_move_shared_fromsharedseen
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();

    my $admintalk = $self->{adminstore}->get_client();

    # Share account
    $self->{instance}->create_user("other");
    $admintalk->setacl("user.other", "cassandane", "lr") or die;

    # Create mailbox A
    $admintalk->create("user.other.A") or die;
    $admintalk->setacl("user.other.A", "cassandane", "lrswipkxtecdan") or die;
    $admintalk->setmetadata("user.other.A", "/shared/vendor/cmu/cyrus-imapd/sharedseen", "true");

    # Create message in mailbox A
    $self->{adminstore}->set_folder('user.other.A');
    $self->make_message("Email", store => $self->{adminstore}) or die;

    # Create mailbox B
    $admintalk->create("user.other.B") or die;
    $admintalk->setacl("user.other.B", "cassandane", "lrswipkxtecdan") or die;

    my @fetchEmailMethods = (
        ['Email/query', {
            accountId => 'other',
            collapseThreads => JSON::true,
        }, "R1"],
        ['Email/get', {
            accountId => 'other',
            properties => ['mailboxIds'],
            '#ids' => {
                resultOf => 'R1',
                name => 'Email/query',
                path => '/ids'
            },
            fetchAllBodyValues => JSON::true,
        }, 'R2' ],
    );

    # Fetch Email
    my $res = $jmap->CallMethods([@fetchEmailMethods, ['Mailbox/get', { accountId => 'other' }, 'R3']]);
    $self->assert_num_equals(1, scalar @{$res->[1][1]{list}});
    $self->assert_num_equals(1, scalar keys %{$res->[1][1]{list}[0]{mailboxIds}});
    my $emailId = $res->[1][1]{list}[0]{id};
    my %mbids = map { $_->{name} => $_->{id} } @{$res->[2][1]{list}};

    $res = $jmap->CallMethods([
        ['Email/set', {
            update => { $emailId => {
                "keywords/\$seen" => $JSON::true,
            }},
            accountId => 'other',
        }, 'R1'],
        ['Email/set', {
            update => { $emailId => {
                "mailboxIds/$mbids{A}" => undef,
                "mailboxIds/$mbids{B}" => $JSON::true,
            }},
            accountId => 'other',
        }, 'R2'],
    ]);

    $self->assert_not_null($res->[0][1]{updated});
    $self->assert_null($res->[0][1]{notUpdated});
    $self->assert_not_null($res->[1][1]{updated});
    $self->assert_null($res->[1][1]{notUpdated});
}

sub test_email_set_draft
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    xlog $self, "create drafts mailbox";
    my $res = $jmap->CallMethods([
            ['Mailbox/set', { create => { "1" => {
                            name => "drafts",
                            parentId => undef,
                            role => "drafts"
             }}}, "R1"]
    ]);
    $self->assert_str_equals('Mailbox/set', $res->[0][0]);
    $self->assert_str_equals('R1', $res->[0][2]);
    $self->assert_not_null($res->[0][1]{created});
    my $draftsmbox = $res->[0][1]{created}{"1"}{id};

    my $draft =  {
        mailboxIds => { $draftsmbox => JSON::true },
        from => [ { name => "Yosemite Sam", email => "sam\@acme.local" } ] ,
        sender => [{ name => "Marvin the Martian", email => "marvin\@acme.local" }],
        to => [
            { name => "Bugs Bunny", email => "bugs\@acme.local" },
            { name => "Rainer M\N{LATIN SMALL LETTER U WITH DIAERESIS}ller", email => "rainer\@de.local" },
        ],
        cc => [
            { name => "Elmer Fudd", email => "elmer\@acme.local" },
            { name => "Porky Pig", email => "porky\@acme.local" },
        ],
        bcc => [
            { name => "Wile E. Coyote", email => "coyote\@acme.local" },
        ],
        replyTo => [ { name => undef, email => "the.other.sam\@acme.local" } ],
        subject => "Memo",
        textBody => [{ partId => '1' }],
        htmlBody => [{ partId => '2' }],
        bodyValues => {
            '1' => { value => "I'm givin' ya one last chance ta surrenda!" },
            '2' => { value => "Oh!!! I <em>hate</em> that Rabbit." },
        },
        keywords => { '$draft' => JSON::true },
    };

    xlog $self, "Create a draft";
    $res = $jmap->CallMethods([['Email/set', { create => { "1" => $draft }}, "R1"]]);
    my $id = $res->[0][1]{created}{"1"}{id};

    xlog $self, "Get draft $id";
    $res = $jmap->CallMethods([['Email/get', { ids => [$id] }, "R1"]]);
    my $msg = $res->[0][1]->{list}[0];

    $self->assert_deep_equals($msg->{mailboxIds}, $draft->{mailboxIds});
    $self->assert_deep_equals($msg->{from}, $draft->{from});
    $self->assert_deep_equals($msg->{sender}, $draft->{sender});
    $self->assert_deep_equals($msg->{to}, $draft->{to});
    $self->assert_deep_equals($msg->{cc}, $draft->{cc});
    $self->assert_deep_equals($msg->{bcc}, $draft->{bcc});
    $self->assert_deep_equals($msg->{replyTo}, $draft->{replyTo});
    $self->assert_str_equals($msg->{subject}, $draft->{subject});
    $self->assert_equals(JSON::true, $msg->{keywords}->{'$draft'});
    $self->assert_num_equals(1, scalar keys %{$msg->{keywords}});

    # Now change the draft keyword, which is allowed since approx ~Q1/2018.
    xlog $self, "Update a draft";
    $res = $jmap->CallMethods([
        ['Email/set', {
            update => { $id => { 'keywords/$draft' => undef } },
        }, "R1"]
    ]);
    $self->assert(exists $res->[0][1]{updated}{$id});
}

sub test_email_set_issue2293
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $inboxid = $self->getinbox()->{id};

    my $email =  {
        mailboxIds => { $inboxid => JSON::true },
        from => [ { email => q{test1@robmtest.vm}, name => q{} } ],
        to => [ {
            email => q{foo@bar.com},
            name => "asd \x{529b}\x{9928}\x{5fc5}  asd \x{30ec}\x{30f1}\x{30b9}"
        } ],
    };

    xlog $self, "create and get email";
    my $res = $jmap->CallMethods([
        ['Email/set', { create => { "1" => $email }}, "R1"],
        ['Email/get', { ids => [ "#1" ] }, "R2" ],
    ]);
    my $ret = $res->[1][1]->{list}[0];
    $self->assert_str_equals($email->{to}[0]{email}, $ret->{to}[0]{email});
    $self->assert_str_equals($email->{to}[0]{name}, $ret->{to}[0]{name});


    xlog $self, "create and get email";
    $email->{to}[0]{name} = "asd \x{529b}\x{9928}\x{5fc5}  asd \x{30ec}\x{30f1}\x{30b9} asd  \x{3b1}\x{3bc}\x{3b5}\x{3c4}";

    $res = $jmap->CallMethods([
        ['Email/set', { create => { "1" => $email }}, "R1"],
        ['Email/get', { ids => [ "#1" ] }, "R2" ],
    ]);
    $ret = $res->[1][1]->{list}[0];
    $self->assert_str_equals($email->{to}[0]{email}, $ret->{to}[0]{email});
    $self->assert_str_equals($email->{to}[0]{name}, $ret->{to}[0]{name});

    xlog $self, "create and get email";
    my $to = [{
        name => "abcdefghijklmnopqrstuvwxyz1",
        email => q{abcdefghijklmnopqrstuvwxyz1@local},
    }, {
        name => "abcdefghijklmnopqrstuvwxyz2",
        email => q{abcdefghijklmnopqrstuvwxyz2@local},
    }, {
        name => "abcdefghijklmnopqrstuvwxyz3",
        email => q{abcdefghijklmnopqrstuvwxyz3@local},
    }, {
        name => "abcdefghijklmnopqrstuvwxyz4",
        email => q{abcdefghijklmnopqrstuvwxyz4@local},
    }, {
        name => "abcdefghijklmnopqrstuvwxyz5",
        email => q{abcdefghijklmnopqrstuvwxyz5@local},
    }, {
        name => "abcdefghijklmnopqrstuvwxyz6",
        email => q{abcdefghijklmnopqrstuvwxyz6@local},
    }, {
        name => "abcdefghijklmnopqrstuvwxyz7",
        email => q{abcdefghijklmnopqrstuvwxyz7@local},
    }, {
        name => "abcdefghijklmnopqrstuvwxyz8",
        email => q{abcdefghijklmnopqrstuvwxyz8@local},
    }, {
        name => "abcdefghijklmnopqrstuvwxyz9",
        email => q{abcdefghijklmnopqrstuvwxyz9@local},
    }];
    $email->{to} = $to;

    $res = $jmap->CallMethods([
        ['Email/set', { create => { "1" => $email }}, "R1"],
        ['Email/get', { ids => [ "#1" ] }, "R2" ],
    ]);
    $ret = $res->[1][1]->{list}[0];
    $self->assert_deep_equals($email->{to}, $ret->{to});
}

sub test_email_set_bodystructure
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();

    xlog $self, "Generate a email in INBOX via IMAP";
    $self->make_message("foo",
        mime_type => "multipart/mixed",
        mime_boundary => "sub",
        body => ""
          . "--sub\r\n"
          . "Content-Type: text/plain; charset=UTF-8\r\n"
          . "Content-Disposition: inline\r\n" . "\r\n"
          . "some text"
          . "\r\n--sub\r\n"
          . "Content-Type: message/rfc822\r\n"
          . "\r\n"
          . "Return-Path: <Ava.Nguyen\@local>\r\n"
          . "Mime-Version: 1.0\r\n"
          . "Content-Type: text/plain\r\n"
          . "Content-Transfer-Encoding: 7bit\r\n"
          . "Subject: bar\r\n"
          . "From: Ava T. Nguyen <Ava.Nguyen\@local>\r\n"
          . "Message-ID: <fake.1475639947.6507\@local>\r\n"
          . "Date: Wed, 05 Oct 2016 14:59:07 +1100\r\n"
          . "To: Test User <test\@local>\r\n"
          . "\r\n"
          . "An embedded email"
          . "\r\n--sub--\r\n",
    ) || die;
    my $res = $jmap->CallMethods([
        ['Email/query', { }, "R1"],
        ['Email/get', {
            '#ids' => { resultOf => 'R1', name => 'Email/query', path => '/ids' },
            properties => ['attachments', 'blobId'],
        }, 'R2' ],
    ]);
    my $emailBlobId = $res->[1][1]->{list}[0]->{blobId};
    my $embeddedEmailBlobId = $res->[1][1]->{list}[0]->{attachments}[0]{blobId};

    xlog $self, "Upload a data blob";
    my $binary = pack "H*", "beefcode";
    my $data = $jmap->Upload($binary, "image/gif");
    my $dataBlobId = $data->{blobId};

    $self->assert_not_null($emailBlobId);
    $self->assert_not_null($embeddedEmailBlobId);
    $self->assert_not_null($dataBlobId);

    my $bodyStructure = {
        type => "multipart/alternative",
        subParts => [{
                type => 'text/plain',
                partId => '1',
            }, {
                type => 'message/rfc822',
                blobId => $embeddedEmailBlobId,
            }, {
                type => 'image/gif',
                blobId => $dataBlobId,
            }, {
                # No type set
                blobId => $dataBlobId,
            }, {
                type => 'message/rfc822',
                blobId => $emailBlobId,
        }],
    };

    xlog $self, "Create email with body structure";
    my $inboxid = $self->getinbox()->{id};
    my $email = {
        mailboxIds => { $inboxid => JSON::true },
        from => [{ name => "Test", email => q{foo@bar} }],
        subject => "test",
        bodyStructure => $bodyStructure,
        bodyValues => {
            "1" => {
                value => "A text body",
            },
        },
    };
    $res = $jmap->CallMethods([
        ['Email/set', { create => { '1' => $email } }, 'R1'],
        ['Email/get', {
            ids => [ '#1' ],
            properties => [ 'bodyStructure' ],
            bodyProperties => [ 'partId', 'blobId', 'type' ],
            fetchAllBodyValues => JSON::true,
        }, 'R2' ],
    ]);

    # Normalize server-set properties
    my $gotBodyStructure = $res->[1][1]{list}[0]{bodyStructure};
    $self->assert_str_equals('multipart/alternative', $gotBodyStructure->{type});
    $self->assert_null($gotBodyStructure->{blobId});
    $self->assert_str_equals('text/plain', $gotBodyStructure->{subParts}[0]{type});
    $self->assert_not_null($gotBodyStructure->{subParts}[0]{blobId});
    $self->assert_str_equals('message/rfc822', $gotBodyStructure->{subParts}[1]{type});
    $self->assert_str_equals($embeddedEmailBlobId, $gotBodyStructure->{subParts}[1]{blobId});
    $self->assert_str_equals('image/gif', $gotBodyStructure->{subParts}[2]{type});
    $self->assert_str_equals($dataBlobId, $gotBodyStructure->{subParts}[2]{blobId});
    # Default type is text/plain if no Content-Type header is set
    $self->assert_str_equals('text/plain', $gotBodyStructure->{subParts}[3]{type});
    $self->assert_str_equals($dataBlobId, $gotBodyStructure->{subParts}[3]{blobId});
    $self->assert_str_equals('message/rfc822', $gotBodyStructure->{subParts}[4]{type});
    $self->assert_str_equals($emailBlobId, $gotBodyStructure->{subParts}[4]{blobId});
}

sub test_email_set_issue2500
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();
    my $inboxid = $self->getinbox()->{id};

    my $email = {
        mailboxIds => { $inboxid => JSON::true },
        from => [{ name => "Test", email => q{foo@bar} }],
        subject => "test",
        bodyStructure => {
            partId => '1',
            charset => 'us/ascii',
        },
        bodyValues => {
            "1" => {
                value => "A text body",
            },
        },
    };
    my $res = $jmap->CallMethods([
        ['Email/set', { create => { '1' => $email } }, 'R1'],
    ]);
    $self->assert_str_equals('invalidProperties', $res->[0][1]{notCreated}{1}{type});
    $self->assert_str_equals('bodyStructure/charset', $res->[0][1]{notCreated}{1}{properties}[0]);

    delete $email->{bodyStructure}{charset};
    $email->{bodyStructure}{'header:Content-Type'} = 'text/plain;charset=us-ascii';
    $res = $jmap->CallMethods([
        ['Email/set', { create => { '1' => $email } }, 'R1'],
    ]);
    $self->assert_str_equals('invalidProperties', $res->[0][1]{notCreated}{1}{type});
    $self->assert_str_equals('bodyStructure/header:Content-Type', $res->[0][1]{notCreated}{1}{properties}[0]);

}

sub test_email_set_shared
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $imaptalk = $self->{store}->get_client();
    my $admintalk = $self->{adminstore}->get_client();

    xlog $self, "Create user and share mailbox";
    $self->{instance}->create_user("foo");
    $admintalk->setacl("user.foo", "cassandane", "lrswntex") or die;

    xlog $self, "Create email in shared account via IMAP";
    $self->{adminstore}->set_folder('user.foo');
    $self->make_message("Email foo", store => $self->{adminstore}) or die;

    xlog $self, "get email";
    my $res = $jmap->CallMethods([
        ['Email/query', { accountId => 'foo' }, "R1"],
    ]);
    my $id = $res->[0][1]->{ids}[0];

    xlog $self, "toggle Seen flag on email";
    $res = $jmap->CallMethods([['Email/set', {
        accountId => 'foo',
        update => { $id => { keywords => { '$seen' => JSON::true } } },
    }, "R1"]]);
    $self->assert(exists $res->[0][1]{updated}{$id});

    xlog $self, "Remove right to write annotations";
    $admintalk->setacl("user.foo", "cassandane", "lrtex") or die;

    xlog $self, 'Toggle \\Seen flag on email (should fail)';
    $res = $jmap->CallMethods([['Email/set', {
        accountId => 'foo',
        update => { $id => { keywords => { } } },
    }, "R1"]]);
    $self->assert(exists $res->[0][1]{notUpdated}{$id});

    xlog $self, "Remove right to delete email";
    $admintalk->setacl("user.foo", "cassandane", "lr") or die;

    xlog $self, 'Delete email (should fail)';
    $res = $jmap->CallMethods([['Email/set', {
        accountId => 'foo',
        destroy => [ $id ],
    }, "R1"]]);
    $self->assert(exists $res->[0][1]{notDestroyed}{$id});

    xlog $self, "Add right to delete email";
    $admintalk->setacl("user.foo", "cassandane", "lrtex") or die;

    xlog $self, 'Delete email';
    $res = $jmap->CallMethods([['Email/set', {
            accountId => 'foo',
            destroy => [ $id ],
    }, "R1"]]);
    $self->assert_str_equals($id, $res->[0][1]{destroyed}[0]);
}

sub test_email_set_userkeywords
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    xlog $self, "create drafts mailbox";
    my $res = $jmap->CallMethods([
            ['Mailbox/set', { create => { "1" => {
                            name => "drafts",
                            parentId => undef,
                            role => "drafts"
             }}}, "R1"]
    ]);
    $self->assert_str_equals('Mailbox/set', $res->[0][0]);
    $self->assert_str_equals('R1', $res->[0][2]);
    $self->assert_not_null($res->[0][1]{created});
    my $draftsmbox = $res->[0][1]{created}{"1"}{id};

    my $draft =  {
        mailboxIds =>  { $draftsmbox => JSON::true },
        from => [ { name => "Yosemite Sam", email => "sam\@acme.local" } ] ,
        to => [
            { name => "Bugs Bunny", email => "bugs\@acme.local" },
        ],
        subject => "Memo",
        textBody => [{ partId => '1' }],
        bodyValues => {
            '1' => {
                value => "I'm givin' ya one last chance ta surrenda!"
            }
        },
        keywords => {
            '$draft' => JSON::true,
            'foo' => JSON::true
        },
    };

    xlog $self, "Create a draft";
    $res = $jmap->CallMethods([['Email/set', { create => { "1" => $draft }}, "R1"]]);
    my $id = $res->[0][1]{created}{"1"}{id};

    xlog $self, "Get draft $id";
    $res = $jmap->CallMethods([['Email/get', { ids => [$id] }, "R1"]]);
    my $msg = $res->[0][1]->{list}[0];

    $self->assert_equals(JSON::true, $msg->{keywords}->{'$draft'});
    $self->assert_equals(JSON::true, $msg->{keywords}->{'foo'});
    $self->assert_num_equals(2, scalar keys %{$msg->{keywords}});

    xlog $self, "Update draft";
    $res = $jmap->CallMethods([['Email/set', {
        update => {
            $id => {
                "keywords" => {
                    '$draft' => JSON::true,
                    'foo' => JSON::true,
                    'bar' => JSON::true
                }
            }
        }
    }, "R1"]]);

    xlog $self, "Get draft $id";
    $res = $jmap->CallMethods([['Email/get', { ids => [$id] }, "R1"]]);
    $msg = $res->[0][1]->{list}[0];
    $self->assert_equals(JSON::true, JSON::true, $msg->{keywords}->{'$draft'}); # case-insensitive!
    $self->assert_equals(JSON::true, $msg->{keywords}->{'foo'});
    $self->assert_equals(JSON::true, $msg->{keywords}->{'bar'});
    $self->assert_num_equals(3, scalar keys %{$msg->{keywords}});
}

sub test_email_set_keywords_bogus_values
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    # See https://github.com/cyrusimap/cyrus-imapd/issues/2439

    $self->make_message("foo") || die;
    my $res = $jmap->CallMethods([['Email/query', { }, "R1"]]);
    my $emailId = $res->[0][1]{ids}[0];
    $self->assert_not_null($res);

    $res = $jmap->CallMethods([['Email/set', {
        'update' => { $emailId => {
            keywords => {
                'foo' => JSON::false,
            },
        }},
    }, 'R1' ]]);
    $self->assert_not_null($res->[0][1]{notUpdated}{$emailId});

    $res = $jmap->CallMethods([['Email/set', {
        'update' => { $emailId => {
            'keywords/foo' => JSON::false,
            },
        },
    }, 'R1' ]]);
    $self->assert_not_null($res->[0][1]{notUpdated}{$emailId});

    $res = $jmap->CallMethods([['Email/set', {
        'update' => { $emailId => {
            keywords => {
                'foo' => 1,
            },
        }},
    }, 'R1' ]]);
    $self->assert_not_null($res->[0][1]{notUpdated}{$emailId});

    $res = $jmap->CallMethods([['Email/set', {
        'update' => { $emailId => {
            'keywords/foo' => 1,
            },
        },
    }, 'R1' ]]);
    $self->assert_not_null($res->[0][1]{notUpdated}{$emailId});

    $res = $jmap->CallMethods([['Email/set', {
        'update' => { $emailId => {
            keywords => {
                'foo' => 'true',
            },
        }},
    }, 'R1' ]]);
    $self->assert_not_null($res->[0][1]{notUpdated}{$emailId});

    $res = $jmap->CallMethods([['Email/set', {
        'update' => { $emailId => {
            'keywords/foo' => 'true',
            },
        },
    }, 'R1' ]]);
    $self->assert_not_null($res->[0][1]{notUpdated}{$emailId});

    $res = $jmap->CallMethods([['Email/set', {
        'update' => { $emailId => {
            keywords => {
                'foo' => JSON::true,
            },
        }},
    }, 'R1' ]]);
    $self->assert(exists $res->[0][1]{updated}{$emailId});
}

sub test_misc_upload_zero
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    xlog $self, "create drafts mailbox";
    my $res = $jmap->CallMethods([
            ['Mailbox/set', { create => { "1" => {
                            name => "drafts",
                            parentId => undef,
                            role => "drafts"
             }}}, "R1"]
    ]);
    $self->assert_str_equals('Mailbox/set', $res->[0][0]);
    $self->assert_str_equals('R1', $res->[0][2]);
    $self->assert_not_null($res->[0][1]{created});
    my $draftsmbox = $res->[0][1]{created}{"1"}{id};

    my $data = $jmap->Upload("", "text/plain");
    $self->assert_matches(qr/^Gda39a3ee5e6b4b0d3255bfef95601890/, $data->{blobId});
    $self->assert_num_equals(0, $data->{size});
    $self->assert_str_equals("text/plain", $data->{type});

    my $msgresp = $jmap->CallMethods([
      ['Email/set', { create => { "2" => {
        mailboxIds =>  { $draftsmbox => JSON::true },
        from => [ { name => "Yosemite Sam", email => "sam\@acme.local" } ] ,
        to => [
            { name => "Bugs Bunny", email => "bugs\@acme.local" },
        ],
        subject => "Memo",
        textBody => [{ partId => '1' }],
        bodyValues => {
            '1' => {
                value => "I'm givin' ya one last chance ta surrenda!"
            }
        },
        attachments => [{
            blobId => $data->{blobId},
            name => "emptyfile.txt",
        }],
        keywords => { '$draft' => JSON::true },
      } } }, 'R2'],
    ]);

    $self->assert_not_null($msgresp->[0][1]{created});
}

sub test_misc_upload
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    xlog $self, "create drafts mailbox";
    my $res = $jmap->CallMethods([
            ['Mailbox/set', { create => { "1" => {
                            name => "drafts",
                            parentId => undef,
                            role => "drafts"
             }}}, "R1"]
    ]);
    $self->assert_str_equals('Mailbox/set', $res->[0][0]);
    $self->assert_str_equals('R1', $res->[0][2]);
    $self->assert_not_null($res->[0][1]{created});
    my $draftsmbox = $res->[0][1]{created}{"1"}{id};

    my $data = $jmap->Upload("a message with some text", "text/rubbish");
    $self->assert_matches(qr/^G44911b55c3b83ca05db9659d7a8e8b7b/, $data->{blobId});
    $self->assert_num_equals(24, $data->{size});
    $self->assert_str_equals("text/rubbish", $data->{type});

    my $msgresp = $jmap->CallMethods([
      ['Email/set', { create => { "2" => {
        mailboxIds =>  { $draftsmbox => JSON::true },
        from => [ { name => "Yosemite Sam", email => "sam\@acme.local" } ] ,
        to => [
            { name => "Bugs Bunny", email => "bugs\@acme.local" },
        ],
        subject => "Memo",
        textBody => [{partId => '1'}],
        htmlBody => [{partId => '2'}],
        bodyValues => {
            1 => {
                value => "I'm givin' ya one last chance ta surrenda!"
            },
            2 => {
                value => "<html>I'm givin' ya one last chance ta surrenda!</html>"
            },
        },
        attachments => [{
            blobId => $data->{blobId},
            name => "test.txt",
        }],
        keywords => { '$draft' => JSON::true },
      } } }, 'R2'],
    ]);

    $self->assert_not_null($msgresp->[0][1]{created});
}

sub test_misc_upload_multiaccount
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $imaptalk = $self->{store}->get_client();
    my $admintalk = $self->{adminstore}->get_client();

    # Create user and share mailbox
    $self->{instance}->create_user("foo");
    $admintalk->setacl("user.foo", "cassandane", "lrwikxd") or die;

    # Create user but don't share mailbox
    $self->{instance}->create_user("bar");

    my @res = $jmap->Upload("a email with some text", "text/rubbish", "foo");
    $self->assert_str_equals('201', $res[0]->{status});

    @res = $jmap->Upload("a email with some text", "text/rubbish", "bar");
    $self->assert_str_equals('404', $res[0]->{status});
}

sub test_misc_upload_bin
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    xlog $self, "create drafts mailbox";
    my $res = $jmap->CallMethods([
            ['Mailbox/set', { create => { "1" => {
                            name => "drafts",
                            parentId => undef,
                            role => "drafts"
             }}}, "R1"]
    ]);
    $self->assert_str_equals('Mailbox/set', $res->[0][0]);
    $self->assert_str_equals('R1', $res->[0][2]);
    $self->assert_not_null($res->[0][1]{created});
    my $draftsmbox = $res->[0][1]{created}{"1"}{id};

    my $logofile = abs_path('data/logo.gif');
    open(FH, "<$logofile");
    local $/ = undef;
    my $binary = <FH>;
    close(FH);
    my $data = $jmap->Upload($binary, "image/gif");

    my $msgresp = $jmap->CallMethods([
      ['Email/set', { create => { "2" => {
        mailboxIds =>  { $draftsmbox => JSON::true },
        from => [ { name => "Yosemite Sam", email => "sam\@acme.local" } ] ,
        to => [
            { name => "Bugs Bunny", email => "bugs\@acme.local" },
        ],
        subject => "Memo",
        textBody => [{ partId => '1' }],
        bodyValues => { 1 => { value => "I'm givin' ya one last chance ta surrenda!" }},
        attachments => [{
            blobId => $data->{blobId},
            name => "logo.gif",
        }],
        keywords => { '$draft' => JSON::true },
      } } }, 'R2'],
    ]);

    $self->assert_not_null($msgresp->[0][1]{created});

    # XXX - fetch back the parts
}

sub test_misc_download
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();
    my $inbox = 'INBOX';

    # Generate a email to have some blob ids
    xlog $self, "Generate a email in $inbox via IMAP";
    $self->make_message("foo",
        mime_type => "multipart/mixed",
        mime_boundary => "sub",
        body => ""
          . "--sub\r\n"
          . "Content-Type: text/plain; charset=UTF-8\r\n"
          . "some text"
          . "\r\n--sub\r\n"
          . "Content-Type: image/jpeg\r\n"
          . "Content-Transfer-Encoding: base64\r\n" . "\r\n"
          . "beefc0de"
          . "\r\n--sub\r\n"
          . "Content-Type: image/png\r\n"
          . "Content-Transfer-Encoding: base64\r\n"
          . "\r\n"
          . "f00bae=="
          . "\r\n--sub--\r\n",
    );

    xlog $self, "get email list";
    my $res = $jmap->CallMethods([['Email/query', {}, "R1"]]);
    my $ids = $res->[0][1]->{ids};

    xlog $self, "get email";
    $res = $jmap->CallMethods([['Email/get', {
        ids => $ids,
        properties => ['bodyStructure'],
    }, "R1"]]);
    my $msg = $res->[0][1]{list}[0];

    my $blobid1 = $msg->{bodyStructure}{subParts}[1]{blobId};
    my $blobid2 = $msg->{bodyStructure}{subParts}[2]{blobId};
    $self->assert_not_null($blobid1);
    $self->assert_not_null($blobid2);

    $res = $jmap->Download('cassandane', $blobid1);
    $self->assert_str_equals("beefc0de", encode_base64($res->{content}, ''));
}

sub test_misc_download_shared
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();
    my $inbox = 'INBOX';

    my $admintalk = $self->{adminstore}->get_client();

    xlog $self, "Create shared mailboxes";
    $self->{instance}->create_user("foo");
    $admintalk->create("user.foo.A") or die;
    $admintalk->setacl("user.foo.A", "cassandane", "lr") or die;
    $admintalk->create("user.foo.B") or die;
    $admintalk->setacl("user.foo.B", "cassandane", "lr") or die;

    xlog $self, "Create email in shared mailbox";
    $self->{adminstore}->set_folder('user.foo.B');
    $self->make_message("foo", store => $self->{adminstore}) or die;

    xlog $self, "get email blobId";
    my $res = $jmap->CallMethods([
        ['Email/query', { accountId => 'foo'}, 'R1'],
        ['Email/get', {
            accountId => 'foo',
            '#ids' => {
                resultOf => 'R1',
                name => 'Email/query',
                path => '/ids'
            },
            properties => ['blobId'],
        }, 'R2'],
    ]);
    my $blobId = $res->[1][1]->{list}[0]{blobId};

    xlog $self, "download email as blob";
    $res = $jmap->Download('foo', $blobId);

    xlog $self, "Unshare mailbox";
    $admintalk->setacl("user.foo.B", "cassandane", "") or die;

    my %Headers = (
        'Authorization' => $jmap->auth_header(),
    );
    my $httpRes = $jmap->ua->get($jmap->downloaduri('foo', $blobId),
                                 { headers => \%Headers });
    $self->assert_str_equals('404', $httpRes->{status});
}

sub test_base64_forward
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();
    my $inbox = 'INBOX';

    # Generate a email to have some blob ids
    xlog $self, "Generate a email in $inbox via IMAP";
    $self->make_message("foo",
        mime_type => "multipart/mixed",
        mime_boundary => "sub",
        body => ""
          . "--sub\r\n"
          . "Content-Type: text/plain; charset=UTF-8\r\n"
          . "some text"
          . "\r\n--sub\r\n"
          . "Content-Type: image/jpeg\r\n"
          . "Content-Transfer-Encoding: base64\r\n" . "\r\n"
          . "beefc0de"
          . "\r\n--sub--\r\n",
    );

    xlog $self, "get email list";
    my $res = $jmap->CallMethods([['Email/query', {}, "R1"]]);
    my $ids = $res->[0][1]->{ids};

    xlog $self, "get email";
    $res = $jmap->CallMethods([['Email/get', {
        ids => $ids,
        properties => ['bodyStructure', 'mailboxIds'],
    }, "R1"]]);
    my $msg = $res->[0][1]{list}[0];

    my $blobid = $msg->{bodyStructure}{subParts}[1]{blobId};
    $self->assert_not_null($blobid);
    my $size = $msg->{bodyStructure}{subParts}[1]{size};
    $self->assert_num_equals(6, $size);

    $res = $jmap->Download('cassandane', $blobid);
    $self->assert_str_equals("beefc0de", encode_base64($res->{content}, ''));

    # now create a new message referencing this blobId:

    $res = $jmap->CallMethods([['Email/set', {
        create => {
            k1 => {
                bcc => undef,
                bodyStructure => {
                    subParts => [{
                        partId => 'text',
                        type => 'text/plain',
                    },{
                        blobId => $blobid,
                        cid => undef,
                        disposition => 'attachment',
                        height => undef,
                        name => 'foobar.jpg',
                        size => $size,
                        type => 'image/jpeg',
                        width => undef,
                    }],
                    type => 'multipart/mixed',
                },
                bodyValues => {
                    text => {
                        isTruncated => $JSON::false,
                        value => "Hello world",
                    },
                },
                cc => undef,
                inReplyTo => undef,
                mailboxIds => $msg->{mailboxIds},
                from => [ {email => 'foo@example.com', name => 'foo' } ],
                keywords => { '$draft' => $JSON::true, '$seen' => $JSON::true },
                receivedAt => '2018-06-26T03:10:07Z',
                references => undef,
                replyTo => undef,
                sentAt => '2018-06-26T03:10:07Z',
                subject => 'test email',
                to => [ {email => 'foo@example.com', name => 'foo' } ],
            },
        },
    }, "R1"]]);

    my $id = $res->[0][1]{created}{k1}{id};
    $self->assert_not_null($id);

    $res = $jmap->CallMethods([['Email/get', {
        ids => [$id],
        properties => ['bodyStructure'],
    }, "R1"]]);
    $msg = $res->[0][1]{list}[0];

    my $newpart = $msg->{bodyStructure}{subParts}[1];
    $self->assert_str_equals("foobar.jpg", $newpart->{name});
    $self->assert_str_equals("image/jpeg", $newpart->{type});
    $self->assert_num_equals(6, $newpart->{size});

    # XXX - in theory, this IS allowed to change
    if ($newpart->{blobId} ne $blobid) {
        $res = $jmap->Download('cassandane', $blobid);
        # but this isn't!
        $self->assert_str_equals("beefc0de", encode_base64($res->{content}, ''));
    }
}

sub download
{
    my ($self, $accountid, $blobid) = @_;
    my $jmap = $self->{jmap};

    my $uri = $jmap->downloaduri($accountid, $blobid);
    my %Headers;
    $Headers{'Authorization'} = $jmap->auth_header();
    my %getopts = (headers => \%Headers);
    my $res = $jmap->ua->get($uri, \%getopts);
    xlog $self, "JMAP DOWNLOAD @_ " . Dumper($res);
    return $res;
}

sub test_blob_copy
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $imaptalk = $self->{store}->get_client();
    my $admintalk = $self->{adminstore}->get_client();

    # FIXME how to share just #jmap folder?
    xlog $self, "create user foo and share inbox";
    $self->{instance}->create_user("foo");
    $admintalk->setacl("user.foo", "cassandane", "lrkintex") or die;

    xlog $self, "upload blob in main account";
    my $data = $jmap->Upload('somedata', "text/plain");
    $self->assert_not_null($data);

    xlog $self, "attempt to download from shared account (should fail)";
    my $res = $self->download('foo', $data->{blobId});
    $self->assert_str_equals('404', $res->{status});

    xlog $self, "copy blob to shared account";
    $res = $jmap->CallMethods([['Blob/copy', {
        fromAccountId => 'cassandane',
        accountId => 'foo',
        blobIds => [ $data->{blobId} ],
    }, 'R1']]);

    xlog $self, "download from shared account";
    $res = $self->download('foo', $data->{blobId});
    $self->assert_str_equals('200', $res->{status});

    xlog $self, "generate an email in INBOX via IMAP";
    $self->make_message("Email A") || die;

    xlog $self, "get email blob id";
    $res = $jmap->CallMethods([
        ['Email/query', {}, "R1"],
        ['Email/get', {
            '#ids' => {
                resultOf => 'R1',
                name => 'Email/query',
                path => '/ids'
            },
            properties => [ 'blobId' ],
        }, 'R2']
    ]);
    my $msgblobId = $res->[1][1]->{list}[0]{blobId};

    xlog $self, "copy Email blob to shared account";
    $res = $jmap->CallMethods([['Blob/copy', {
        fromAccountId => 'cassandane',
        accountId => 'foo',
        blobIds => [ $msgblobId ],
    }, 'R1']]);

    xlog $self, "download Email blob from shared account";
    $res = $self->download('foo', $msgblobId);
    $self->assert_str_equals('200', $res->{status});
}

sub test_email_set_attachments
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();
    my $inbox = 'INBOX';

    # Generate a email to have some blob ids
    xlog $self, "Generate a email in $inbox via IMAP";
    $self->make_message("foo",
        mime_type => "multipart/mixed",
        mime_boundary => "sub",
        body => ""
          . "--sub\r\n"
          . "Content-Type: text/plain; charset=UTF-8\r\n"
          . "Content-Disposition: inline\r\n" . "\r\n"
          . "some text"
          . "\r\n--sub\r\n"
          . "Content-Type: image/jpeg;foo=bar\r\n"
          . "Content-Disposition: attachment\r\n"
          . "Content-Transfer-Encoding: base64\r\n" . "\r\n"
          . "beefc0de"
          . "\r\n--sub\r\n"
          . "Content-Type: image/png\r\n"
          . "Content-Disposition: attachment\r\n"
          . "Content-Transfer-Encoding: base64\r\n"
          . "\r\n"
          . "f00bae=="
          . "\r\n--sub--\r\n",
    );

    xlog $self, "get email list";
    my $res = $jmap->CallMethods([['Email/query', {}, "R1"]]);
    my $ids = $res->[0][1]->{ids};

    xlog $self, "get email";
    $res = $jmap->CallMethods([['Email/get', { ids => $ids }, "R1"]]);
    my $msg = $res->[0][1]{list}[0];

    my %m = map { $_->{type} => $_ } @{$res->[0][1]{list}[0]->{attachments}};
    my $blobJpeg = $m{"image/jpeg"}->{blobId};
    my $blobPng = $m{"image/png"}->{blobId};
    $self->assert_not_null($blobJpeg);
    $self->assert_not_null($blobPng);

    xlog $self, "create drafts mailbox";
    $res = $jmap->CallMethods([
            ['Mailbox/set', { create => { "1" => {
                            name => "drafts",
                            parentId => undef,
                            role => "drafts"
             }}}, "R1"]
    ]);
    $self->assert_str_equals('Mailbox/set', $res->[0][0]);
    $self->assert_str_equals('R1', $res->[0][2]);
    $self->assert_not_null($res->[0][1]{created});
    my $draftsmbox = $res->[0][1]{created}{"1"}{id};
    my $shortfname = "test\N{GRINNING FACE}.jpg";
    my $longfname = "a_very_long_filename_thats_looking_quite_bogus_but_in_fact_is_absolutely_valid\N{GRINNING FACE}!.bin";

    my $draft =  {
        mailboxIds =>  { $draftsmbox => JSON::true },
        from => [ { name => "Yosemite Sam", email => "sam\@acme.local" } ] ,
        to => [ { name => "Bugs Bunny", email => "bugs\@acme.local" }, ],
        subject => "Memo",
        htmlBody => [{ partId => '1' }],
        bodyValues => {
            '1' => {
                value => "<html>I'm givin' ya one last chance ta surrenda! ".
                         "<img src=\"cid:foo\@local\"></html>",
            },
        },
        attachments => [{
            blobId => $blobJpeg,
            name => $shortfname,
            type => 'image/jpeg',
        }, {
            blobId => $blobPng,
            cid => "foo\@local",
            type => 'image/png',
            disposition => 'inline',
        }, {
            blobId => $blobJpeg,
            type => "application/test",
            name => $longfname,
        }, {
            blobId => $blobPng,
            type => "application/test2",
            name => "simple",
        }],
        keywords => { '$draft' => JSON::true },
    };

    my $wantBodyStructure = {
        type => 'multipart/mixed',
        name => undef,
        cid => undef,
        disposition => undef,
        subParts => [{
            type => 'multipart/related',
            name => undef,
            cid => undef,
            disposition => undef,
            subParts => [{
                type => 'text/html',
                name => undef,
                cid => undef,
                disposition => undef,
                subParts => [],
            },{
                type => 'image/png',
                cid => "foo\@local",
                disposition => 'inline',
                name => undef,
                subParts => [],
            }],
        },{
            type => 'image/jpeg',
            name => $shortfname,
            cid => undef,
            disposition => 'attachment',
            subParts => [],
        },{
            type => 'application/test',
            name => $longfname,
            cid => undef,
            disposition => 'attachment',
            subParts => [],
        },{
            type => 'application/test2',
            name => 'simple',
            cid => undef,
            disposition => 'attachment',
            subParts => [],
        }]
    };

    xlog $self, "Create a draft";
    $res = $jmap->CallMethods([['Email/set', { create => { "1" => $draft }}, "R1"]]);
    my $id = $res->[0][1]{created}{"1"}{id};

    xlog $self, "Get draft $id";
    $res = $jmap->CallMethods([['Email/get', {
            ids => [$id],
            properties => ['bodyStructure'],
            bodyProperties => ['type', 'name', 'cid','disposition', 'subParts'],
    }, "R1"]]);
    $msg = $res->[0][1]->{list}[0];

    $self->assert_deep_equals($wantBodyStructure, $msg->{bodyStructure});
}

sub test_email_set_flagged
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    xlog $self, "create drafts mailbox";
    my $res = $jmap->CallMethods([
            ['Mailbox/set', { create => { "1" => {
                            name => "drafts",
                            parentId => undef,
                            role => "drafts"
             }}}, "R1"]
    ]);
    $self->assert_str_equals('Mailbox/set', $res->[0][0]);
    $self->assert_str_equals('R1', $res->[0][2]);
    $self->assert_not_null($res->[0][1]{created});
    my $drafts = $res->[0][1]{created}{"1"}{id};

    my $draft =  {
        mailboxIds =>  { $drafts => JSON::true },
        keywords => { '$draft' => JSON::true, '$Flagged' => JSON::true },
        textBody => [{ partId => '1' }],
        bodyValues => { '1' => { value => "a flagged draft" }},
    };

    xlog $self, "Create a draft";
    $res = $jmap->CallMethods([['Email/set', { create => { "1" => $draft }}, "R1"]]);
    my $id = $res->[0][1]{created}{"1"}{id};

    xlog $self, "Get draft $id";
    $res = $jmap->CallMethods([['Email/get', { ids => [$id] }, "R1"]]);
    my $msg = $res->[0][1]->{list}[0];

    $self->assert_deep_equals($msg->{mailboxIds}, $draft->{mailboxIds});
    $self->assert_equals(JSON::true, $msg->{keywords}->{'$flagged'});
}

sub test_email_set_mailboxids
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $inboxid = $self->getinbox()->{id};
    $self->assert_not_null($inboxid);

    my $res = $jmap->CallMethods([
        ['Mailbox/set', { create => {
            "1" => { name => "drafts", parentId => undef, role => "drafts" },
        }}, "R1"]
    ]);
    my $draftsid = $res->[0][1]{created}{"1"}{id};
    $self->assert_not_null($draftsid);

    my $msg =  {
        from => [ { name => "Yosemite Sam", email => "sam\@acme.local" } ],
        to => [ { name => "Bugs Bunny", email => "bugs\@acme.local" }, ],
        subject => "Memo",
        textBody => [{ partId => '1' }],
        bodyValues => { '1' => { value => "I'm givin' ya one last chance ta surrenda!" }},
        keywords => { '$draft' => JSON::true },
    };

    # Not OK: at least one mailbox must be specified
    $res = $jmap->CallMethods([['Email/set', { create => { "1" => $msg }}, "R1"]]);
    $self->assert_str_equals('invalidProperties', $res->[0][1]{notCreated}{"1"}{type});
    $self->assert_str_equals('mailboxIds', $res->[0][1]{notCreated}{"1"}{properties}[0]);
    $msg->{mailboxIds} = {};
    $res = $jmap->CallMethods([['Email/set', { create => { "1" => $msg }}, "R1"]]);
    $self->assert_str_equals('invalidProperties', $res->[0][1]{notCreated}{"1"}{type});
    $self->assert_str_equals('mailboxIds', $res->[0][1]{notCreated}{"1"}{properties}[0]);

    # OK: drafts mailbox isn't required (anymore)
    $msg->{mailboxIds} = { $inboxid => JSON::true },
    $msg->{subject} = "Email 1";
    $res = $jmap->CallMethods([['Email/set', { create => { "1" => $msg }}, "R1"]]);
    $self->assert(exists $res->[0][1]{created}{"1"});

    # OK: drafts mailbox is OK to create in
    $msg->{mailboxIds} = { $draftsid => JSON::true },
    $msg->{subject} = "Email 2";
    $res = $jmap->CallMethods([['Email/set', { create => { "1" => $msg }}, "R1"]]);
    $self->assert(exists $res->[0][1]{created}{"1"});

    # OK: drafts mailbox is OK to create in, as is for multiple mailboxes
    $msg->{mailboxIds} = { $draftsid => JSON::true, $inboxid => JSON::true },
    $msg->{subject} = "Email 3";
    $res = $jmap->CallMethods([['Email/set', { create => { "1" => $msg }}, "R1"]]);
    $self->assert(exists $res->[0][1]{created}{"1"});
}

sub test_email_get_keywords
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();

    xlog $self, "Create IMAP mailbox and message A";
    $talk->create('INBOX.A') || die;
    $store->set_folder('INBOX.A');
    $self->make_message('A') || die;

    xlog $self, "Create IMAP mailbox B and copy message A to B";
    $talk->create('INBOX.B') || die;
    $talk->copy('1:*', 'INBOX.B');
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    my $res = $jmap->CallMethods([
        ['Email/query', { }, 'R1'],
        ['Email/get', {
            '#ids' => { resultOf => 'R1', name => 'Email/query', path => '/ids'}
        }, 'R2' ]
    ]);
    $self->assert_num_equals(1, scalar @{$res->[1][1]{list}});
    my $jmapmsg = $res->[1][1]{list}[0];
    $self->assert_not_null($jmapmsg);

    # Keywords are empty by default
    my $keywords = {};
    $self->assert_deep_equals($keywords, $jmapmsg->{keywords});

    xlog $self, "Set \\Seen on message A";
    $store->set_folder('INBOX.A');
    $talk->store('1', '+flags', '(\\Seen)');

    # Seen must only be set if ALL messages are seen.
    $res = $jmap->CallMethods([
        ['Email/get', { 'ids' => [ $jmapmsg->{id} ] }, 'R2' ]
    ]);
    $jmapmsg = $res->[0][1]{list}[0];
    $keywords = {};
    $self->assert_deep_equals($keywords, $jmapmsg->{keywords});

    xlog $self, "Set \\Seen on message B";
    $store->set_folder('INBOX.B');
    $store->_select();
    $talk->store('1', '+flags', '(\\Seen)');

    # Seen must only be set if ALL messages are seen.
    $res = $jmap->CallMethods([
        ['Email/get', { 'ids' => [ $jmapmsg->{id} ] }, 'R2' ]
    ]);
    $jmapmsg = $res->[0][1]{list}[0];
    $keywords = {
        '$seen' => JSON::true,
    };
    $self->assert_deep_equals($keywords, $jmapmsg->{keywords});

    xlog $self, "Set \\Flagged on message B";
    $store->set_folder('INBOX.B');
    $store->_select();
    $talk->store('1', '+flags', '(\\Flagged)');

    # Any other keyword is set if set on any IMAP message of this email.
    $res = $jmap->CallMethods([
        ['Email/get', { 'ids' => [ $jmapmsg->{id} ] }, 'R2' ]
    ]);
    $jmapmsg = $res->[0][1]{list}[0];
    $keywords = {
        '$seen' => JSON::true,
        '$flagged' => JSON::true,
    };
    $self->assert_deep_equals($keywords, $jmapmsg->{keywords});
}

sub test_email_get_keywords_case_insensitive
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();

    xlog $self, "Create IMAP mailbox and message A";
    $talk->create('INBOX.A') || die;
    $store->set_folder('INBOX.A');
    $self->make_message('A') || die;

    xlog $self, "Set flag Foo and Flagged on message A";
    $store->set_folder('INBOX.A');
    $talk->store('1', '+flags', '(Foo \\Flagged)');

    my $res = $jmap->CallMethods([
        ['Email/query', { }, 'R1'],
        ['Email/get', {
            '#ids' => { resultOf => 'R1', name => 'Email/query', path => '/ids'},
            properties => ['keywords'],
        }, 'R2' ]
    ]);
    $self->assert_num_equals(1, scalar @{$res->[1][1]{list}});
    my $jmapmsg = $res->[1][1]{list}[0];
    my $keywords = {
        'foo' => JSON::true,
        '$flagged' => JSON::true,
    };
    $self->assert_deep_equals($keywords, $jmapmsg->{keywords});
}

sub test_email_set_keywords
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();
    $self->{store}->set_fetch_attributes(qw(uid flags));

    xlog $self, "Create IMAP mailboxes";
    $talk->create('INBOX.A') || die;
    $talk->create('INBOX.B') || die;
    $talk->create('INBOX.C') || die;

    xlog $self, "Get JMAP mailboxes";
    my $res = $jmap->CallMethods([['Mailbox/get', { properties => [ 'name' ]}, "R1"]]);
    my %jmailboxes = map { $_->{name} => $_ } @{$res->[0][1]{list}};
    $self->assert_num_equals(4, scalar keys %jmailboxes);
    my $jmailboxA = $jmailboxes{A};
    my $jmailboxB = $jmailboxes{B};
    my $jmailboxC = $jmailboxes{C};

    my %mailboxA;
    my %mailboxB;
    my %mailboxC;

    xlog $self, "Create message in mailbox A";
    $store->set_folder('INBOX.A');
    $mailboxA{1} = $self->make_message('Message');
    $mailboxA{1}->set_attributes(id => 1, uid => 1, flags => []);

    xlog $self, "Copy message from A to B";
    $talk->copy('1:*', 'INBOX.B');
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    xlog $self, "Set IMAP flag foo on message A";
    $store->set_folder('INBOX.A');
    $store->_select();
    $talk->store('1', '+flags', '(foo)');

    xlog $self, "Get JMAP keywords";
    $res = $jmap->CallMethods([
        ['Email/query', { }, 'R1'],
        ['Email/get', {
            '#ids' => {
                resultOf => 'R1',
                name => 'Email/query',
                path => '/ids'
            },
            properties => [ 'keywords']
        }, 'R2' ]
    ]);
    my $jmapmsg = $res->[1][1]{list}[0];
    my $keywords = {
        foo => JSON::true
    };
    $self->assert_deep_equals($keywords, $jmapmsg->{keywords});

    xlog $self, "Update JMAP email keywords";
    $keywords = {
        bar => JSON::true,
        baz => JSON::true,
    };
    $res = $jmap->CallMethods([
        ['Email/set', {
            update => {
                $jmapmsg->{id} => {
                    keywords => $keywords
                }
            }
        }, 'R1'],
        ['Email/get', {
            ids => [ $jmapmsg->{id} ],
            properties => ['keywords']
        }, 'R2' ]
    ]);
    $jmapmsg = $res->[1][1]{list}[0];
    $self->assert_deep_equals($keywords, $jmapmsg->{keywords});

    xlog $self, "Set \\Seen on message in mailbox B";
    $store->set_folder('INBOX.B');
    $store->_select();
    $talk->store('1', '+flags', '(\\Seen)');

    xlog $self, "Patch JMAP email keywords and update mailboxIds";
    $res = $jmap->CallMethods([
        ['Email/set', {
            update => {
                $jmapmsg->{id} => {
                    'keywords/bar' => undef,
                    'keywords/qux' => JSON::true,
                    mailboxIds => {
                        $jmailboxB->{id} => JSON::true,
                        $jmailboxC->{id} => JSON::true,
                    }
                }
            }
        }, 'R1'],
        ['Email/get', {
            ids => [ $jmapmsg->{id} ],
            properties => ['keywords', 'mailboxIds']
        }, 'R2' ]
    ]);
    $jmapmsg = $res->[1][1]{list}[0];
    $keywords = {
        baz => JSON::true,
        qux => JSON::true,
    };
    $self->assert_deep_equals($keywords, $jmapmsg->{keywords});

    $self->assert_str_not_equals($res->[0][1]{oldState}, $res->[0][1]{newState});

    xlog $self, 'Patch $seen on email';
    $res = $jmap->CallMethods([
        ['Email/set', {
            update => {
                $jmapmsg->{id} => {
                    'keywords/$seen' => JSON::true
                }
            }
        }, 'R1'],
        ['Email/get', {
            ids => [ $jmapmsg->{id} ],
            properties => ['keywords', 'mailboxIds']
        }, 'R2' ]
    ]);
    $jmapmsg = $res->[1][1]{list}[0];
    $keywords = {
        baz => JSON::true,
        qux => JSON::true,
        '$seen' => JSON::true,
    };
    $self->assert_deep_equals($keywords, $jmapmsg->{keywords});
}

sub test_email_import_snooze
    :min_version_3_1 :needs_component_jmap :needs_component_calalarmd
    :JMAPExtensions
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    # we need 'https://cyrusimap.org/ns/jmap/mail' capability for
    # snoozed property
    my @using = @{ $jmap->DefaultUsing() };
    push @using, 'https://cyrusimap.org/ns/jmap/mail';
    $jmap->DefaultUsing(\@using);

    my $store = $self->{store};
    my $talk = $store->get_client();

    my $inbox = $self->getinbox()->{id};
    $self->assert_not_null($inbox);

    # Generate an embedded email to get a blob id
    xlog $self, "Generate a email in INBOX via IMAP";
    $self->make_message("foo",
        mime_type => "multipart/mixed",
        mime_boundary => "sub",
        body => ""
          . "--sub\r\n"
          . "Content-Type: text/plain; charset=UTF-8\r\n"
          . "Content-Disposition: inline\r\n" . "\r\n"
          . "some text"
          . "\r\n--sub\r\n"
          . "Content-Type: message/rfc822\r\n"
          . "\r\n"
          . "Return-Path: <Ava.Nguyen\@local>\r\n"
          . "Mime-Version: 1.0\r\n"
          . "Content-Type: text/plain\r\n"
          . "Content-Transfer-Encoding: 7bit\r\n"
          . "Subject: bar\r\n"
          . "From: Ava T. Nguyen <Ava.Nguyen\@local>\r\n"
          . "Message-ID: <fake.1475639947.6507\@local>\r\n"
          . "Date: Wed, 05 Oct 2016 14:59:07 +1100\r\n"
          . "To: Test User <test\@local>\r\n"
          . "\r\n"
          . "An embedded email"
          . "\r\n--sub--\r\n",
    ) || die;

    xlog $self, "get blobId";
    my $res = $jmap->CallMethods([
        ['Email/query', { }, "R1"],
        ['Email/get', {
            '#ids' => { resultOf => 'R1', name => 'Email/query', path => '/ids' },
            properties => ['attachments'],
        }, 'R2' ],
    ]);
    my $blobid = $res->[1][1]->{list}[0]->{attachments}[0]{blobId};
    $self->assert_not_null($blobid);

    xlog $self, "create snooze mailbox";
    $res = $jmap->CallMethods([
            ['Mailbox/set', { create => { "1" => {
                            name => "snoozed",
                            parentId => undef,
                            role => "snoozed"
             }}}, "R1"]
    ]);
    my $snoozed = $res->[0][1]{created}{"1"}{id};
    $self->assert_not_null($snoozed);

    my $maildate = DateTime->now();
    $maildate->add(DateTime::Duration->new(seconds => 30));
    my $datestr = $maildate->strftime('%Y-%m-%dT%TZ');

    xlog $self, "import and get email from blob $blobid";
    $res = $jmap->CallMethods([['Email/import', {
        emails => {
            "1" => {
                blobId => $blobid,
                mailboxIds => {$snoozed =>  JSON::true},
                snoozed => { "until" => "$datestr" },
            },
        },
    }, "R1"], ["Email/get", { ids => ["#1"] }, "R2" ]]);

    $self->assert_str_equals("Email/import", $res->[0][0]);
    my $msg = $res->[0][1]->{created}{"1"};
    $self->assert_not_null($msg);

    $self->assert_str_equals("Email/get", $res->[1][0]);
    $self->assert_str_equals($msg->{id}, $res->[1][1]{list}[0]->{id});
    $self->assert_str_equals($datestr, $res->[1][1]{list}[0]->{snoozed}{'until'});
}

sub test_email_set_create_snooze
    :min_version_3_1 :needs_component_jmap :needs_component_calalarmd
    :JMAPExtensions
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    # we need 'https://cyrusimap.org/ns/jmap/mail' capability for
    # snoozed property
    my @using = @{ $jmap->DefaultUsing() };
    push @using, 'https://cyrusimap.org/ns/jmap/mail';
    $jmap->DefaultUsing(\@using);

    xlog $self, "create snooze mailbox";
    my $res = $jmap->CallMethods([
            ['Mailbox/set', { create => { "1" => {
                            name => "snoozed",
                            parentId => undef,
                            role => "snoozed"
             }}}, "R1"]
    ]);
    $self->assert_str_equals('Mailbox/set', $res->[0][0]);
    $self->assert_str_equals('R1', $res->[0][2]);
    $self->assert_not_null($res->[0][1]{created});
    my $snoozedmbox = $res->[0][1]{created}{"1"}{id};

    xlog $self, "create drafts mailbox";
    $res = $jmap->CallMethods([
            ['Mailbox/set', { create => { "1" => {
                            name => "drafts",
                            parentId => undef,
                            role => "drafts"
             }}}, "R4"]
    ]);
    $self->assert_not_null($res->[0][1]{created});
    my $draftsId = $res->[0][1]{created}{"1"}{id};

    my $maildate = DateTime->now();
    $maildate->add(DateTime::Duration->new(seconds => 30));
    my $datestr = $maildate->strftime('%Y-%m-%dT%TZ');

    my $draft =  {
        mailboxIds => { $snoozedmbox => JSON::true },
        from => [ { name => "Yosemite Sam", email => "sam\@acme.local" } ] ,
        sender => [{ name => "Marvin the Martian", email => "marvin\@acme.local" }],
        to => [
            { name => "Bugs Bunny", email => "bugs\@acme.local" },
            { name => "Rainer M\N{LATIN SMALL LETTER U WITH DIAERESIS}ller", email => "rainer\@de.local" },
        ],
        cc => [
           { name => "Elmer Fudd", email => "elmer\@acme.local" },
            { name => "Porky Pig", email => "porky\@acme.local" },
        ],
        bcc => [
            { name => "Wile E. Coyote", email => "coyote\@acme.local" },
        ],
        replyTo => [ { name => undef, email => "the.other.sam\@acme.local" } ],
        subject => "Memo",
        textBody => [{ partId => '1' }],
        htmlBody => [{ partId => '2' }],
        bodyValues => {
            '1' => { value => "I'm givin' ya one last chance ta surrenda!" },
            '2' => { value => "Oh!!! I <em>hate</em> that Rabbit." },
        },
        keywords => { '$draft' => JSON::true },
        snoozed => { "until" => "$datestr", "moveToMailboxId" => "$draftsId" },
    };

    xlog $self, "Create a draft";
    $res = $jmap->CallMethods([['Email/set', { create => { "1" => $draft }}, "R1"]]);
    my $id = $res->[0][1]{created}{"1"}{id};

    xlog $self, "Get draft $id";
    $res = $jmap->CallMethods([['Email/get', { ids => [$id] }, "R1"]]);
    my $msg = $res->[0][1]->{list}[0];

    $self->assert_deep_equals($msg->{mailboxIds}, $draft->{mailboxIds});
    $self->assert_deep_equals($msg->{from}, $draft->{from});
    $self->assert_deep_equals($msg->{sender}, $draft->{sender});
    $self->assert_deep_equals($msg->{to}, $draft->{to});
    $self->assert_deep_equals($msg->{cc}, $draft->{cc});
    $self->assert_deep_equals($msg->{bcc}, $draft->{bcc});
    $self->assert_deep_equals($msg->{replyTo}, $draft->{replyTo});
    $self->assert_str_equals($msg->{subject}, $draft->{subject});
    $self->assert_equals(JSON::true, $msg->{keywords}->{'$draft'});
    $self->assert_num_equals(1, scalar keys %{$msg->{keywords}});
    $self->assert_str_equals($datestr, $msg->{snoozed}{'until'});
    $self->assert_str_equals($datestr, $msg->{addedDates}{"$snoozedmbox"});

    # Now change the draft keyword, which is allowed since approx ~Q1/2018.
    xlog $self, "Update a draft";
    $res = $jmap->CallMethods([
        ['Email/set', {
            update => { $id => { 'keywords/$draft' => undef } },
        }, "R1"]
    ]);
    $self->assert(exists $res->[0][1]{updated}{$id});

    xlog $self, "trigger re-delivery of snoozed email";
    $self->{instance}->run_command({ cyrus => 1 },
                                   'calalarmd', '-t' => $maildate->epoch() + 30 );

    $res = $jmap->CallMethods( [ [ 'Email/get',
                                   { ids => [ $id ],
                                     properties => [ 'mailboxIds', 'keywords', 'snoozed', 'addedDates' ]}, "R7" ] ] );
    $msg = $res->[0][1]->{list}[0];
    $self->assert_num_equals(1, scalar keys %{$msg->{mailboxIds}});
    $self->assert_equals(JSON::true, $msg->{mailboxIds}{"$draftsId"});
    $self->assert_num_equals(0, scalar keys %{$msg->{keywords}});
    $self->assert_not_null($msg->{snoozed});
    $self->assert_str_equals($datestr, $msg->{snoozed}{'until'});
    $self->assert_str_equals($datestr, $msg->{addedDates}{"$draftsId"});
}

sub test_email_set_update_snooze
    :min_version_3_1 :needs_component_jmap :needs_component_calalarmd
    :JMAPExtensions
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    # we need 'https://cyrusimap.org/ns/jmap/mail' capability for
    # snoozed property
    my @using = @{ $jmap->DefaultUsing() };
    push @using, 'https://cyrusimap.org/ns/jmap/mail';
    $jmap->DefaultUsing(\@using);

    xlog $self, "Get mailbox id of Inbox";
    my $inboxId = $self->getinbox()->{id};

    xlog $self, "Generate a email via IMAP";
    $self->make_message("foo", body => "a email\r\nwithCRLF\r\n") or die;

    xlog $self, "get email id";
    my $res = $jmap->CallMethods( [ [ 'Email/query', {}, "R2" ] ] );
    my $emailId = $res->[0][1]->{ids}[0];

    $res = $jmap->CallMethods( [ [ 'Email/get',
                                   { ids => [ $emailId ],
                                     properties => [ 'mailboxIds', 'keywords', 'snoozed' ]}, "R3" ] ] );
    my $msg = $res->[0][1]->{list}[0];
    $self->assert_not_null($msg->{mailboxIds}{$inboxId});
    $self->assert_num_equals(1, scalar keys %{$msg->{mailboxIds}});

    xlog $self, "create snooze mailbox";
    $res = $jmap->CallMethods([
            ['Mailbox/set', { create => { "1" => {
                            name => "snoozed",
                            parentId => undef,
                            role => "snoozed"
             }}}, "R4"]
    ]);
    $self->assert_not_null($res->[0][1]{created});
    my $snoozedId = $res->[0][1]{created}{"1"}{id};

    xlog $self, "create drafts mailbox";
    $res = $jmap->CallMethods([
            ['Mailbox/set', { create => { "1" => {
                            name => "drafts",
                            parentId => undef,
                            role => "drafts"
             }}}, "R4"]
    ]);
    $self->assert_not_null($res->[0][1]{created});
    my $draftsId = $res->[0][1]{created}{"1"}{id};

    xlog $self, "Move message to drafts and snoozed mailbox";
    my $maildate = DateTime->now();
    $maildate->add(DateTime::Duration->new(seconds => 30));
    my $datestr = $maildate->strftime('%Y-%m-%dT%TZ');

    $res = $jmap->CallMethods([
        ['Email/set', {
            update => { $emailId => {
                "mailboxIds/$inboxId" => undef,
                "mailboxIds/$snoozedId" => $JSON::true,
                "snoozed" => { "until" => "$datestr",
                               "setKeywords" => { '$seen' => $JSON::true } },
                keywords => { '$flagged' => JSON::true, '$seen' => JSON::true },
            }}
        }, 'R5']
    ]);
    $self->assert_not_null($res->[0][1]{updated});
    $self->assert_null($res->[0][1]{notUpdated});

    $res = $jmap->CallMethods( [ [ 'Email/get',
                                   { ids => [ $emailId ],
                                     properties => [ 'mailboxIds', 'keywords', 'addedDates', 'snoozed' ]}, "R6" ] ] );
    $msg = $res->[0][1]->{list}[0];
    $self->assert_null($msg->{mailboxIds}{$inboxId});
    $self->assert_not_null($msg->{mailboxIds}{$snoozedId});
    $self->assert_null($msg->{mailboxIds}{$draftsId});
    $self->assert_num_equals(1, scalar keys %{$msg->{mailboxIds}});
    $self->assert_str_equals($datestr, $msg->{snoozed}{'until'});
    $self->assert_str_equals($datestr, $msg->{addedDates}{$snoozedId});

    xlog $self, "Adjust snooze#until";
    $maildate->add(DateTime::Duration->new(seconds => 15));
    $datestr = $maildate->strftime('%Y-%m-%dT%TZ');

    $res = $jmap->CallMethods([
        ['Email/set', {
            update => { $emailId => {
                "mailboxIds/$draftsId" => $JSON::true,
                "snoozed/until" => "$datestr",
                'snoozed/setKeywords/$awakened' => $JSON::true,
                'snoozed/setKeywords/$seen' => $JSON::false,
            }}
        }, 'R5']
    ]);
    $self->assert_not_null($res->[0][1]{updated});
    $self->assert_null($res->[0][1]{notUpdated});

    $res = $jmap->CallMethods( [ [ 'Email/get',
                                   { ids => [ $emailId ],
                                     properties => [ 'mailboxIds', 'keywords', 'addedDates', 'snoozed' ]}, "R6" ] ] );
    $msg = $res->[0][1]->{list}[0];
    $self->assert_null($msg->{mailboxIds}{$inboxId});
    $self->assert_not_null($msg->{mailboxIds}{$snoozedId});
    $self->assert_not_null($msg->{mailboxIds}{$draftsId});
    $self->assert_num_equals(2, scalar keys %{$msg->{mailboxIds}});
    $self->assert_str_equals($datestr, $msg->{snoozed}{'until'});
    $self->assert_str_equals($datestr, $msg->{addedDates}{$snoozedId});
    # but it shouldn't be changed on the drafts folder.  This is a little raceful, in that
    # the snooze#until date could just happen to be now...
    $self->assert_str_not_equals($datestr, $msg->{addedDates}{$draftsId});

    xlog $self, "trigger re-delivery of snoozed email";
    $self->{instance}->run_command({ cyrus => 1 },
                                   'calalarmd', '-t' => $maildate->epoch() + 30 );

    $res = $jmap->CallMethods( [ [ 'Email/get',
                                   { ids => [ $emailId ],
                                     properties => [ 'mailboxIds', 'keywords', 'addedDates', 'snoozed' ]}, "R7" ] ] );
    $msg = $res->[0][1]->{list}[0];
    $self->assert_num_equals(2, scalar keys %{$msg->{mailboxIds}});
    $self->assert_not_null($msg->{snoozed});
    $self->assert_num_equals(2, scalar keys %{$msg->{keywords}});
    $self->assert_equals(JSON::true, $msg->{keywords}{'$awakened'});
    $self->assert_null($msg->{keywords}{'$seen'});
    $self->assert_str_equals($datestr, $msg->{snoozed}{'until'});
    $self->assert_str_equals($datestr, $msg->{addedDates}{$inboxId});
    # but it shouldn't be changed on the drafts folder.  This is a little raceful, in that
    # the snooze#until date could just happen to be now...
    $self->assert_str_not_equals($datestr, $msg->{addedDates}{$draftsId});

    xlog $self, "Re-snooze";
    $maildate->add(DateTime::Duration->new(seconds => 15));
    $datestr = $maildate->strftime('%Y-%m-%dT%TZ');

    $res = $jmap->CallMethods([
        ['Email/set', {
            update => { $emailId => {
                "mailboxIds/$inboxId" => undef,
                "mailboxIds/$snoozedId" => $JSON::true,
                'keywords/$awakened' => undef,
                "snoozed/until" => "$datestr",
            }}
        }, 'R8']
    ]);
    $self->assert_not_null($res->[0][1]{updated});
    $self->assert_null($res->[0][1]{notUpdated});

    $res = $jmap->CallMethods( [ [ 'Email/get',
                                   { ids => [ $emailId ],
                                     properties => [ 'mailboxIds', 'keywords', 'snoozed' ]}, "R9" ] ] );
    $msg = $res->[0][1]->{list}[0];
    $self->assert_num_equals(2, scalar keys %{$msg->{mailboxIds}});
    $self->assert_not_null($msg->{snoozed});
    $self->assert_num_equals(1, scalar keys %{$msg->{keywords}});
    $self->assert_null($msg->{keywords}{'$seen'});
    $self->assert_null($msg->{keywords}{'$awakened'});
    $self->assert_str_equals($datestr, $msg->{snoozed}{'until'});

    xlog $self, "trigger re-delivery of re-snoozed email";
    $self->{instance}->run_command({ cyrus => 1 },
                                   'calalarmd', '-t' => $maildate->epoch() + 30 );

    $res = $jmap->CallMethods( [ [ 'Email/get',
                                   { ids => [ $emailId ],
                                     properties => [ 'mailboxIds', 'keywords', 'addedDates', 'snoozed' ]}, "R7" ] ] );
    $msg = $res->[0][1]->{list}[0];
    $self->assert_num_equals(2, scalar keys %{$msg->{mailboxIds}});
    $self->assert_not_null($msg->{snoozed});
    $self->assert_num_equals(2, scalar keys %{$msg->{keywords}});
    $self->assert_equals(JSON::true, $msg->{keywords}{'$awakened'});
    $self->assert_null($msg->{keywords}{'$seen'});
    $self->assert_str_equals($datestr, $msg->{snoozed}{'until'});
    $self->assert_str_equals($datestr, $msg->{addedDates}{$inboxId});
    # but it shouldn't be changed on the drafts folder.  This is a little raceful, in that
    # the snooze#until date could just happen to be now...
    $self->assert_str_not_equals($datestr, $msg->{addedDates}{$draftsId});

    xlog $self, "Remove snoozed";
    $res = $jmap->CallMethods([
        ['Email/set', {
            update => { $emailId => {
                "mailboxIds/$inboxId" => undef,
                "snoozed" => undef
            }}
        }, 'R8']
    ]);
    $self->assert_not_null($res->[0][1]{updated});
    $self->assert_null($res->[0][1]{notUpdated});

    $res = $jmap->CallMethods( [ [ 'Email/get',
                                   { ids => [ $emailId ],
                                     properties => [ 'mailboxIds', 'keywords', 'snoozed' ]}, "R9" ] ] );
    $msg = $res->[0][1]->{list}[0];
    $self->assert_num_equals(1, scalar keys %{$msg->{mailboxIds}});
    $self->assert_null($msg->{snoozed});
    $self->assert_num_equals(2, scalar keys %{$msg->{keywords}});
    $self->assert_equals(JSON::true, $msg->{keywords}{'$seen'});
    $self->assert_null($msg->{keywords}{'$awakened'});

    xlog $self, "Restore snoozed";
    $maildate->add(DateTime::Duration->new(seconds => 15));
    $datestr = $maildate->strftime('%Y-%m-%dT%TZ');

    $res = $jmap->CallMethods([
        ['Email/set', {
            update => { $emailId => {
                "mailboxIds" => { "$inboxId" => $JSON::true },
                "snoozed" => {
                    "until" => "$datestr",
                    "setKeywords" => { '$awakened' => $JSON::true, '$seen' => $JSON::false }
                },
            }}
        }, 'R8']
    ]);
    $self->assert_not_null($res->[0][1]{updated});
    $self->assert_null($res->[0][1]{notUpdated});

    $res = $jmap->CallMethods( [ [ 'Email/get',
                                   { ids => [ $emailId ],
                                     properties => [ 'mailboxIds', 'keywords', 'snoozed' ]}, "R9" ] ] );
    $msg = $res->[0][1]->{list}[0];
    $self->assert_num_equals(1, scalar keys %{$msg->{mailboxIds}});
    $self->assert_not_null($msg->{snoozed});
    $self->assert_num_equals(2, scalar keys %{$msg->{keywords}});
    $self->assert_equals(JSON::true, $msg->{keywords}{'$seen'});
    $self->assert_null($msg->{keywords}{'$awakened'});
    $self->assert_str_equals($datestr, $msg->{snoozed}{'until'});
}

sub test_replication_email_set_update_snooze
    :min_version_3_1 :needs_component_jmap :needs_component_calalarmd
    :JMAPExtensions
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    # we need 'https://cyrusimap.org/ns/jmap/mail' capability for
    # snoozed property
    my @using = @{ $jmap->DefaultUsing() };
    push @using, 'https://cyrusimap.org/ns/jmap/mail';
    $jmap->DefaultUsing(\@using);

    xlog $self, "Get mailbox id of Inbox";
    my $inboxId = $self->getinbox()->{id};

    xlog $self, "Generate a email via IMAP";
    $self->make_message("foo", body => "a email\r\nwithCRLF\r\n") or die;

    xlog $self, "get email id";
    my $res = $jmap->CallMethods( [ [ 'Email/query', {}, "R2" ] ] );
    my $emailId = $res->[0][1]->{ids}[0];

    $res = $jmap->CallMethods( [ [ 'Email/get',
                                   { ids => [ $emailId ],
                                     properties => [ 'mailboxIds', 'keywords', 'snoozed' ]}, "R3" ] ] );
    my $msg = $res->[0][1]->{list}[0];
    my $oldState = $res->[0][1]->{state};
    $self->assert_not_null($msg->{mailboxIds}{$inboxId});
    $self->assert_num_equals(1, scalar keys %{$msg->{mailboxIds}});

    xlog $self, "create snooze mailbox";
    $res = $jmap->CallMethods([
            ['Mailbox/set', { create => { "1" => {
                            name => "snoozed",
                            parentId => undef,
                            role => "snoozed"
             }}}, "R4"]
    ]);
    $self->assert_not_null($res->[0][1]{created});
    my $snoozedId = $res->[0][1]{created}{"1"}{id};

    xlog $self, "Move message to snooze mailbox";
    my $maildate = DateTime->now();
    $maildate->add(DateTime::Duration->new(seconds => 30));
    my $datestr = $maildate->strftime('%Y-%m-%dT%TZ');

    $res = $jmap->CallMethods([
        ['Email/set', {
            update => { $emailId => {
                "mailboxIds/$inboxId" => undef,
                "mailboxIds/$snoozedId" => $JSON::true,
                "snoozed" => { "until" => $datestr },
                keywords => { '$flagged' => JSON::true, '$seen' => JSON::true },
            }}
        }, 'R5']
    ]);
    $self->assert_not_null($res->[0][1]{updated});
    $self->assert_null($res->[0][1]{notUpdated});

    $res = $jmap->CallMethods([['Email/changes', { sinceState => $oldState }, "R1"]]);
    $self->assert_deep_equals([], $res->[0][1]{created});
    $self->assert_deep_equals([$emailId], $res->[0][1]{updated});
    $self->assert_deep_equals([], $res->[0][1]{destroyed});
    $oldState = $res->[0][1]{newState};

    $res = $jmap->CallMethods( [ [ 'Email/get',
                                   { ids => [ $emailId ],
                                     properties => [ 'mailboxIds', 'keywords', 'snoozed' ]}, "R6" ] ] );
    $msg = $res->[0][1]->{list}[0];
    $self->assert_null($msg->{mailboxIds}{$inboxId});
    $self->assert_not_null($msg->{mailboxIds}{$snoozedId});
    $self->assert_num_equals(1, scalar keys %{$msg->{mailboxIds}});
    $self->assert_equals($datestr, $msg->{snoozed}{'until'});

    $self->run_replication();
    $self->check_replication('cassandane');

    $res = $jmap->CallMethods([['Email/changes', { sinceState => $oldState }, "R1"]]);
    $self->assert_str_equals($oldState, $res->[0][1]{newState});
    $self->assert_deep_equals([], $res->[0][1]{created});
    $self->assert_deep_equals([], $res->[0][1]{updated});
    $self->assert_deep_equals([], $res->[0][1]{destroyed});

    $res = $jmap->CallMethods( [ [ 'Email/get',
                                   { ids => [ $emailId ],
                                     properties => [ 'mailboxIds', 'keywords', 'snoozed' ]}, "R6" ] ] );
    $msg = $res->[0][1]->{list}[0];
    $self->assert_null($msg->{mailboxIds}{$inboxId});
    $self->assert_not_null($msg->{mailboxIds}{$snoozedId});
    $self->assert_num_equals(1, scalar keys %{$msg->{mailboxIds}});
    $self->assert_equals($datestr, $msg->{snoozed}{'until'});

    xlog $self, "Adjust snooze#until";
    $maildate->add(DateTime::Duration->new(seconds => 15));
    $datestr = $maildate->strftime('%Y-%m-%dT%TZ');

    $res = $jmap->CallMethods([
        ['Email/set', {
            update => { $emailId => {
                "snoozed" => {
                    "until" => $datestr,
                    "setKeywords" => { '$awakened' => $JSON::true }
                },
            }}
        }, 'R5']
    ]);
    $self->assert_not_null($res->[0][1]{updated});
    $self->assert_null($res->[0][1]{notUpdated});

    $res = $jmap->CallMethods([['Email/changes', { sinceState => $oldState }, "R1"]]);
    $self->assert_str_not_equals($oldState, $res->[0][1]{newState});
    $self->assert_deep_equals([], $res->[0][1]{created});
    $self->assert_deep_equals([$emailId], $res->[0][1]{updated});
    $self->assert_deep_equals([], $res->[0][1]{destroyed});
    $oldState = $res->[0][1]{newState};

    $res = $jmap->CallMethods( [ [ 'Email/get',
                                   { ids => [ $emailId ],
                                     properties => [ 'mailboxIds', 'keywords', 'snoozed' ]}, "R6" ] ] );
    $msg = $res->[0][1]->{list}[0];
    $self->assert_null($msg->{mailboxIds}{$inboxId});
    $self->assert_not_null($msg->{mailboxIds}{$snoozedId});
    $self->assert_num_equals(1, scalar keys %{$msg->{mailboxIds}});
    $self->assert_equals($datestr, $msg->{snoozed}{'until'});

    xlog $self, "make sure replication doesn't revert it!";
    $self->run_replication();
    $self->check_replication('cassandane');

    $res = $jmap->CallMethods([['Email/changes', { sinceState => $oldState }, "R1"]]);
    $self->assert_str_equals($oldState, $res->[0][1]{newState});
    $self->assert_deep_equals([], $res->[0][1]{created});
    $self->assert_deep_equals([], $res->[0][1]{updated});
    $self->assert_deep_equals([], $res->[0][1]{destroyed});

    $res = $jmap->CallMethods( [ [ 'Email/get',
                                   { ids => [ $emailId ],
                                     properties => [ 'mailboxIds', 'keywords', 'snoozed' ]}, "R6" ] ] );
    $msg = $res->[0][1]->{list}[0];
    $self->assert_null($msg->{mailboxIds}{$inboxId});
    $self->assert_not_null($msg->{mailboxIds}{$snoozedId});
    $self->assert_num_equals(1, scalar keys %{$msg->{mailboxIds}});
    $self->assert_equals($datestr, $msg->{snoozed}{'until'});

    xlog $self, "trigger re-delivery of snoozed email";
    $self->{instance}->run_command({ cyrus => 1 },
                                   'calalarmd', '-t' => $maildate->epoch() + 30 );

    $res = $jmap->CallMethods( [ [ 'Email/get',
                                   { ids => [ $emailId ],
                                     properties => [ 'mailboxIds', 'keywords', 'snoozed' ]}, "R7" ] ] );
    $msg = $res->[0][1]->{list}[0];
    $self->assert_num_equals(3, scalar keys %{$msg->{keywords}});
    $self->assert_equals(JSON::true, $msg->{keywords}{'$awakened'});

    $res = $jmap->CallMethods([['Email/changes', { sinceState => $oldState }, "R1"]]);
    $self->assert_str_not_equals($oldState, $res->[0][1]{newState});
    $self->assert_deep_equals([], $res->[0][1]{created});
    $self->assert_deep_equals([$emailId], $res->[0][1]{updated});
    $self->assert_deep_equals([], $res->[0][1]{destroyed});
}

sub test_email_query_snooze
    :min_version_3_1 :needs_component_jmap :needs_component_calalarmd
    :JMAPExtensions
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    # we need 'https://cyrusimap.org/ns/jmap/mail' capability for
    # snoozed property
    my @using = @{ $jmap->DefaultUsing() };
    push @using, 'https://cyrusimap.org/ns/jmap/mail';
    $jmap->DefaultUsing(\@using);

    xlog $self, "Get mailbox id of Inbox";
    my $res = $jmap->CallMethods([['Mailbox/query',
                                   {filter => {role => 'inbox'}}, "R1"]]);
    my $inbox = $res->[0][1]->{ids}[0];

    xlog $self, "create snooze mailbox";
    $res = $jmap->CallMethods([
            ['Mailbox/set', { create => { "1" => {
                            name => "snoozed",
                            parentId => undef,
                            role => "snoozed"
             }}}, "R1"]
    ]);
    $self->assert_str_equals('Mailbox/set', $res->[0][0]);
    $self->assert_str_equals('R1', $res->[0][2]);
    $self->assert_not_null($res->[0][1]{created});
    my $snoozedmbox = $res->[0][1]{created}{"1"}{id};

    my $maildate = DateTime->now();
    $maildate->add(DateTime::Duration->new(seconds => 30));
    my $datestr1 = $maildate->strftime('%Y-%m-%dT%TZ');

    my $draft1 =  {
        mailboxIds => { $snoozedmbox => JSON::true },
        from => [ { name => "Yosemite Sam", email => "sam\@acme.local" } ] ,
        to => [ { name => "Bugs Bunny", email => "bugs\@acme.local" }, ],
        subject => "Memo1",
        snoozed => { "until" => "$datestr1" },
    };

    $maildate->add(DateTime::Duration->new(seconds => -15));
    my $datestr2 = $maildate->strftime('%Y-%m-%dT%TZ');

    my $draft2 =  {
        mailboxIds => { $snoozedmbox => JSON::true },
        from => [ { name => "Yosemite Sam", email => "sam\@acme.local" } ] ,
        to => [ { name => "Bugs Bunny", email => "bugs\@acme.local" }, ],
        subject => "Memo2",
        snoozed => { "until" => "$datestr2" },
    };

    $maildate->add(DateTime::Duration->new(seconds => 30));
    my $datestr3 = $maildate->strftime('%Y-%m-%dT%TZ');

    my $draft3 =  {
        mailboxIds => { $snoozedmbox => JSON::true },
        from => [ { name => "Yosemite Sam", email => "sam\@acme.local" } ] ,
        to => [ { name => "Bugs Bunny", email => "bugs\@acme.local" }, ],
        subject => "Memo3",
        snoozed => { "until" => "$datestr3" },
    };

    $maildate->add(DateTime::Duration->new(seconds => -1));
    my $datestr4 = $maildate->strftime('%Y-%m-%dT%TZ');

    my $draft4 =  {
        mailboxIds => { $snoozedmbox => JSON::true },
        from => [ { name => "Yosemite Sam", email => "sam\@acme.local" } ] ,
        to => [ { name => "Bugs Bunny", email => "bugs\@acme.local" }, ],
        subject => "Memo4",
        snoozed => { "until" => "$datestr4" },
    };

    $maildate->add(DateTime::Duration->new(seconds => 10));
    my $datestr5 = $maildate->strftime('%Y-%m-%dT%TZ');

    my $draft5 =  {
        mailboxIds => { $inbox => JSON::true },
        from => [ { name => "Yosemite Sam", email => "sam\@acme.local" } ] ,
        to => [ { name => "Bugs Bunny", email => "bugs\@acme.local" }, ],
        subject => "Memo5",
        receivedAt => "$datestr5",
    };

    $maildate->add(DateTime::Duration->new(seconds => -5));
    my $datestr6 = $maildate->strftime('%Y-%m-%dT%TZ');

    my $draft6 =  {
        mailboxIds => { $inbox => JSON::true },
        from => [ { name => "Yosemite Sam", email => "sam\@acme.local" } ] ,
        to => [ { name => "Bugs Bunny", email => "bugs\@acme.local" }, ],
        subject => "Memo6",
        receivedAt => "$datestr6",
    };

    xlog $self, "Create 6 drafts";
    $res = $jmap->CallMethods([['Email/set',
                                { create =>
                                  { "1" => $draft1,
                                    "2" => $draft2,
                                    "3" => $draft3,
                                    "4" => $draft4,
                                    "5" => $draft5,
                                    "6" => $draft6 }}, "R1"]]);
    my $id1 = $res->[0][1]{created}{"1"}{id};
    my $id2 = $res->[0][1]{created}{"2"}{id};
    my $id3 = $res->[0][1]{created}{"3"}{id};
    my $id4 = $res->[0][1]{created}{"4"}{id};
    my $id5 = $res->[0][1]{created}{"5"}{id};
    my $id6 = $res->[0][1]{created}{"6"}{id};

    xlog $self, "sort by ascending snoozedUntil";
    $res = $jmap->CallMethods([['Email/query', {
                    sort => [{ property => "snoozedUntil",
                               mailboxId => "$snoozedmbox" }],
                }, "R1"]]);
    $self->assert_num_equals(6, scalar @{$res->[0][1]->{ids}});
    $self->assert_str_equals($id2, $res->[0][1]->{ids}[0]);
    $self->assert_str_equals($id1, $res->[0][1]->{ids}[1]);
    $self->assert_str_equals($id4, $res->[0][1]->{ids}[2]);
    $self->assert_str_equals($id3, $res->[0][1]->{ids}[3]);
    $self->assert_str_equals($id6, $res->[0][1]->{ids}[4]);
    $self->assert_str_equals($id5, $res->[0][1]->{ids}[5]);

    xlog $self, "sort by descending snoozedUntil";
    $res = $jmap->CallMethods([['Email/query', {
                    sort => [{ property => "snoozedUntil",
                               mailboxId => "$snoozedmbox",
                               isAscending => JSON::false }],
                }, "R1"]]);
    $self->assert_num_equals(6, scalar @{$res->[0][1]->{ids}});
    $self->assert_str_equals($id5, $res->[0][1]->{ids}[0]);
    $self->assert_str_equals($id6, $res->[0][1]->{ids}[1]);
    $self->assert_str_equals($id3, $res->[0][1]->{ids}[2]);
    $self->assert_str_equals($id4, $res->[0][1]->{ids}[3]);
    $self->assert_str_equals($id1, $res->[0][1]->{ids}[4]);
    $self->assert_str_equals($id2, $res->[0][1]->{ids}[5]);
}

sub test_email_seen_shared
    :min_version_3_1 :needs_component_jmap :NoAltNameSpace
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();
    my $admintalk = $self->{adminstore}->get_client();

    # Share account
    $self->{instance}->create_user("other");
    $admintalk->setacl("user.other", "cassandane", "lr") or die;

    # Create mailbox A
    $admintalk->create("user.other.A") or die;
    $admintalk->setacl("user.other.A", "cassandane", "lrs") or die;

    # Create message in mailbox A
    $self->{adminstore}->set_folder('user.other.A');
    $self->make_message("Email", store => $self->{adminstore}) or die;

    # Set \Seen on message A as user cassandane
    $self->{store}->set_folder('user.other.A');
    $talk->select('user.other.A');
    $talk->store('1', '+flags', '(\\Seen)');

    # Get email and assert $seen
    my $res = $jmap->CallMethods([
        ['Email/query', {
            accountId => 'other',
        }, 'R1'],
        ['Email/get', {
            accountId => 'other',
            properties => ['keywords'],
            '#ids' => {
                resultOf => 'R1', name => 'Email/query', path => '/ids'
            }
        }, 'R2' ]
    ]);
    my $emailId = $res->[1][1]{list}[0]{id};
    my $wantKeywords = { '$seen' => JSON::true };
    $self->assert_deep_equals($wantKeywords, $res->[1][1]{list}[0]{keywords});

    # Set $seen via JMAP on the shared mailbox
    $res = $jmap->CallMethods([
        ['Email/set', {
            accountId => 'other',
            update => {
                $emailId => {
                    keywords => { },
                },
            },
        }, 'R1']
    ]);
    $self->assert(exists $res->[0][1]{updated}{$emailId});

    # Assert $seen got updated
    $res = $jmap->CallMethods([
        ['Email/get', {
            accountId => 'other',
            properties => ['keywords'],
            ids => [$emailId],
        }, 'R1' ]
    ]);
    $wantKeywords = { };
    $self->assert_deep_equals($wantKeywords, $res->[0][1]{list}[0]{keywords});
}

sub test_email_seen_shared_twofolder
    :min_version_3_1 :needs_component_jmap :NoAltNameSpace
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();
    my $admintalk = $self->{adminstore}->get_client();

    # Share account
    $self->{instance}->create_user("other");
    $admintalk->setacl("user.other", "cassandane", "lr") or die;

    # Create mailbox A
    $admintalk->create("user.other.A") or die;
    $admintalk->setacl("user.other.A", "cassandane", "lrs") or die;
    $admintalk->create("user.other.A.sub") or die;
    $admintalk->setacl("user.other.A.sub", "cassandane", "lrs") or die;

    # Create message in mailbox A
    $self->{adminstore}->set_folder('user.other.A');
    $self->make_message("Email", store => $self->{adminstore}) or die;

    # Set \Seen on message A as user cassandane
    $self->{store}->set_folder('user.other.A');
    $admintalk->select('user.other.A');
    $admintalk->copy('1', 'user.other.A.sub');
    $talk->select('user.other.A');
    $talk->store('1', '+flags', '(\\Seen)');
    $talk->select('user.other.A.sub');
    $talk->store('1', '+flags', '(\\Seen)');

    # Get email and assert $seen
    my $res = $jmap->CallMethods([
        ['Email/query', {
            accountId => 'other',
        }, 'R1'],
        ['Email/get', {
            accountId => 'other',
            properties => ['keywords'],
            '#ids' => {
                resultOf => 'R1', name => 'Email/query', path => '/ids'
            }
        }, 'R2' ]
    ]);
    my $emailId = $res->[1][1]{list}[0]{id};
    my $wantKeywords = { '$seen' => JSON::true };
    $self->assert_deep_equals($wantKeywords, $res->[1][1]{list}[0]{keywords});

    # Set $seen via JMAP on the shared mailbox
    $res = $jmap->CallMethods([
        ['Email/set', {
            accountId => 'other',
            update => {
                $emailId => {
                    keywords => { },
                },
            },
        }, 'R1']
    ]);
    $self->assert(exists $res->[0][1]{updated}{$emailId});

    # Assert $seen got updated
    $res = $jmap->CallMethods([
        ['Email/get', {
            accountId => 'other',
            properties => ['keywords'],
            ids => [$emailId],
        }, 'R1' ]
    ]);
    $wantKeywords = { };
    $self->assert_deep_equals($wantKeywords, $res->[0][1]{list}[0]{keywords});
}

sub test_email_seen_shared_twofolder_hidden
    :min_version_3_1 :needs_component_jmap :NoAltNameSpace
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();
    my $admintalk = $self->{adminstore}->get_client();

    # Share account
    $self->{instance}->create_user("other");
    $admintalk->setacl("user.other", "cassandane", "lr") or die;

    # Create mailbox A
    $admintalk->create("user.other.A") or die;
    $admintalk->setacl("user.other.A", "cassandane", "lrs") or die;
    # NOTE: user cassandane does NOT get permission to see this one
    $admintalk->create("user.other.A.sub") or die;
    $admintalk->setacl("user.other.A.sub", "cassandane", "") or die;

    # Create message in mailbox A
    $self->{adminstore}->set_folder('user.other.A');
    $self->make_message("Email", store => $self->{adminstore}) or die;

    # Set \Seen on message A as user cassandane
    $self->{store}->set_folder('user.other.A');
    $admintalk->select('user.other.A');
    $admintalk->copy('1', 'user.other.A.sub');
    $talk->select('user.other.A');
    $talk->store('1', '+flags', '(\\Seen)');

    # Get email and assert $seen
    my $res = $jmap->CallMethods([
        ['Email/query', {
            accountId => 'other',
        }, 'R1'],
        ['Email/get', {
            accountId => 'other',
            properties => ['keywords'],
            '#ids' => {
                resultOf => 'R1', name => 'Email/query', path => '/ids'
            }
        }, 'R2' ]
    ]);
    my $emailId = $res->[1][1]{list}[0]{id};
    my $wantKeywords = { '$seen' => JSON::true };
    $self->assert_deep_equals($wantKeywords, $res->[1][1]{list}[0]{keywords});

    # Set $seen via JMAP on the shared mailbox
    $res = $jmap->CallMethods([
        ['Email/set', {
            accountId => 'other',
            update => {
                $emailId => {
                    keywords => { },
                },
            },
        }, 'R1']
    ]);
    $self->assert(exists $res->[0][1]{updated}{$emailId});

    # Assert $seen got updated
    $res = $jmap->CallMethods([
        ['Email/get', {
            accountId => 'other',
            properties => ['keywords'],
            ids => [$emailId],
        }, 'R1' ]
    ]);
    $wantKeywords = { };
    $self->assert_deep_equals($wantKeywords, $res->[0][1]{list}[0]{keywords});
}

sub test_email_flagged_shared_twofolder_hidden
    :min_version_3_1 :needs_component_jmap :NoAltNameSpace
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();
    my $admintalk = $self->{adminstore}->get_client();

    # Share account
    $self->{instance}->create_user("other");

    # Create mailbox A
    $admintalk->create("user.other.A") or die;
    $admintalk->setacl("user.other.A", "cassandane", "lrsiwn") or die;
    # NOTE: user cassandane does NOT get permission to see this one
    $admintalk->create("user.other.A.sub") or die;

    # Create message in mailbox A
    $self->{adminstore}->set_folder('user.other.A');
    $self->make_message("Email", store => $self->{adminstore}) or die;

    # Set \Flagged on message A as user cassandane
    $self->{store}->set_folder('user.other.A');
    $admintalk->select('user.other.A');
    $admintalk->copy('1', 'user.other.A.sub');
    $talk->select('user.other.A');
    $talk->store('1', '+flags', '(\\Flagged)');

    # Get email and assert $seen
    my $res = $jmap->CallMethods([
        ['Email/query', {
            accountId => 'other',
        }, 'R1'],
        ['Email/get', {
            accountId => 'other',
            properties => ['keywords'],
            '#ids' => {
                resultOf => 'R1', name => 'Email/query', path => '/ids'
            }
        }, 'R2' ]
    ]);
    my $emailId = $res->[1][1]{list}[0]{id};
    my $wantKeywords = { '$flagged' => JSON::true };
    $self->assert_deep_equals($wantKeywords, $res->[1][1]{list}[0]{keywords});

    # Set $seen via JMAP on the shared mailbox
    $res = $jmap->CallMethods([
        ['Email/set', {
            accountId => 'other',
            update => {
                $emailId => {
                    keywords => { },
                },
            },
        }, 'R1']
    ]);
    $self->assert(exists $res->[0][1]{updated}{$emailId});

    # Assert $seen got updated
    $res = $jmap->CallMethods([
        ['Email/get', {
            accountId => 'other',
            properties => ['keywords'],
            ids => [$emailId],
        }, 'R1' ]
    ]);
    $wantKeywords = { };
    $self->assert_deep_equals($wantKeywords, $res->[0][1]{list}[0]{keywords});
}

sub test_email_set_move
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();
    my $inbox = 'INBOX';

    xlog $self, "Create test mailboxes";
    my $res = $jmap->CallMethods([
        ['Mailbox/set', { create => {
            "a" => { name => "a", parentId => undef },
            "b" => { name => "b", parentId => undef },
            "c" => { name => "c", parentId => undef },
            "d" => { name => "d", parentId => undef },
        }}, "R1"]
    ]);
    $self->assert_num_equals( 4, scalar keys %{$res->[0][1]{created}} );
    my $a = $res->[0][1]{created}{"a"}{id};
    my $b = $res->[0][1]{created}{"b"}{id};
    my $c = $res->[0][1]{created}{"c"}{id};
    my $d = $res->[0][1]{created}{"d"}{id};

    xlog $self, "Generate a email via IMAP";
    my %exp_sub;
    $exp_sub{A} = $self->make_message(
        "foo", body => "a email",
    );

    xlog $self, "get email id";
    $res = $jmap->CallMethods( [ [ 'Email/query', {}, "R1" ] ] );
    my $id = $res->[0][1]->{ids}[0];

    xlog $self, "get email";
    $res = $jmap->CallMethods([['Email/get', { ids => [$id] }, "R1"]]);
    my $msg = $res->[0][1]->{list}[0];
    $self->assert_num_equals(1, scalar keys %{$msg->{mailboxIds}});

    local *assert_move = sub {
        my ($moveto) = (@_);

        xlog $self, "move email to " . Dumper($moveto);
        $res = $jmap->CallMethods(
            [ [ 'Email/set', {
                    update => { $id => { 'mailboxIds' => $moveto } },
            }, "R1" ] ] );
        $self->assert(exists $res->[0][1]{updated}{$id});

        $res = $jmap->CallMethods( [ [ 'Email/get', { ids => [$id], properties => ['mailboxIds'] }, "R1" ] ] );
        $msg = $res->[0][1]->{list}[0];

        $self->assert_deep_equals($moveto, $msg->{mailboxIds});
    };

    assert_move({$a => JSON::true, $b => JSON::true});
    assert_move({$a => JSON::true, $b => JSON::true, $c => JSON::true});
    assert_move({$d => JSON::true});
}

sub test_email_set_move_keywords
    :min_version_3_1 :needs_component_jmap :NoAltNameSpace
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();
    my $inbox = 'INBOX';

    xlog $self, "Generate an email via IMAP";
    my %exp_sub;
    $exp_sub{A} = $self->make_message(
        "foo", body => "a email",
    );
    xlog $self, "Set flags on message";
    $store->set_folder('INBOX');
    $talk->store('1', '+flags', '($foo \\Flagged)');

    xlog $self, "get email";
    my $res = $jmap->CallMethods([
        ['Email/query', {}, 'R1'],
        ['Email/get', {
            '#ids' => { resultOf => 'R1', name => 'Email/query', path => '/ids'},
            properties => [ 'keywords', 'mailboxIds' ],
        }, 'R2' ]
    ]);
    my $msg = $res->[1][1]->{list}[0];
    $self->assert_num_equals(1, scalar keys %{$msg->{mailboxIds}});
    my $msgId = $msg->{id};
    my $inboxId = (keys %{$msg->{mailboxIds}})[0];
    $self->assert_not_null($inboxId);
    my $keywords = $msg->{keywords};

    xlog $self, "create Archive mailbox";
    $res = $jmap->CallMethods([ ['Mailbox/get', {}, 'R1'], ]);
    my $mboxState = $res->[0][1]{state};
    $talk->create("INBOX.Archive", "(USE (\\Archive))") || die;
    $res = $jmap->CallMethods([
        ['Mailbox/changes', {sinceState => $mboxState }, 'R1'],
    ]);
    my $archiveId = $res->[0][1]{created}[0];
    $self->assert_not_null($archiveId);
    $self->assert_deep_equals([], $res->[0][1]->{updated});
    $self->assert_deep_equals([], $res->[0][1]->{destroyed});

    xlog $self, "move email to Archive";
    xlog $self, "update email";
    $res = $jmap->CallMethods([
        ['Email/set', { update => {
            $msgId => {
                mailboxIds => { $archiveId => JSON::true }
            },
        }}, "R1"],
        ['Email/get', { ids => [ $msgId ], properties => ['keywords'] }, 'R2'],
    ]);
    $self->assert(exists $res->[0][1]{updated}{$msgId});
    $self->assert_deep_equals($keywords, $res->[1][1]{list}[0]{keywords});
}

sub test_email_set_update
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    xlog $self, "create drafts mailbox";
    my $res = $jmap->CallMethods([
            ['Mailbox/set', { create => { "1" => {
                            name => "drafts",
                            parentId => undef,
                            role => "drafts"
             }}}, "R1"]
    ]);
    $self->assert_str_equals('Mailbox/set', $res->[0][0]);
    $self->assert_str_equals('R1', $res->[0][2]);
    $self->assert_not_null($res->[0][1]{created});
    my $drafts = $res->[0][1]{created}{"1"}{id};

    my $draft =  {
        mailboxIds => {$drafts => JSON::true},
        from => [ { name => "Yosemite Sam", email => "sam\@acme.local" } ],
        to => [ { name => "Bugs Bunny", email => "bugs\@acme.local" } ],
        cc => [ { name => "Elmer Fudd", email => "elmer\@acme.local" } ],
        subject => "created",
        htmlBody => [ {partId => '1'} ],
        bodyValues => { 1 => { value => "Oh!!! I <em>hate</em> that Rabbit." }},
        keywords => {
            '$draft' => JSON::true,
        }
    };

    xlog $self, "Create a draft";
    $res = $jmap->CallMethods([['Email/set', { create => { "1" => $draft }}, "R1"]]);
    my $id = $res->[0][1]{created}{"1"}{id};

    xlog $self, "Get draft $id";
    $res = $jmap->CallMethods([['Email/get', { ids => [$id] }, "R1"]]);
    my $msg = $res->[0][1]->{list}[0];

    xlog $self, "Update draft $id";
    $draft->{keywords} = {
        '$draft' => JSON::true,
        '$flagged' => JSON::true,
        '$seen' => JSON::true,
        '$answered' => JSON::true,
    };
    $res = $jmap->CallMethods([['Email/set', { update => { $id => $draft }}, "R1"]]);

    xlog $self, "Get draft $id";
    $res = $jmap->CallMethods([['Email/get', { ids => [$id] }, "R1"]]);
    $msg = $res->[0][1]->{list}[0];
    $self->assert_deep_equals($draft->{keywords}, $msg->{keywords});
}

sub test_email_set_seen
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    # See https://github.com/cyrusimap/cyrus-imapd/issues/2270

    my $talk = $self->{store}->get_client();
    $self->{store}->_select();
    $self->{store}->set_fetch_attributes(qw(uid flags));

    xlog $self, "Add message";
    $self->make_message('Message A');

    xlog $self, "Query email";
    my $inbox = $self->getinbox();
    my $res = $jmap->CallMethods([
        ['Email/query', {
            filter => { inMailbox => $inbox->{id} }
        }, 'R1'],
        ['Email/get', {
            '#ids' => { resultOf => 'R1', name => 'Email/query', path => '/ids'}
        }, 'R2' ]
    ]);

    my $keywords = { };
    my $msg = $res->[1][1]->{list}[0];
    $self->assert_deep_equals($keywords, $msg->{keywords});

    $keywords->{'$seen'} = JSON::true;
    $res = $jmap->CallMethods([
        ['Email/set', { update => { $msg->{id} => { 'keywords/$seen' => JSON::true } } }, 'R1'],
        ['Email/get', { ids => [ $msg->{id} ] }, 'R2'],
    ]);
    $msg = $res->[1][1]->{list}[0];
    $self->assert_deep_equals($keywords, $msg->{keywords});
}

sub test_email_set_destroy
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    xlog $self, "create mailboxes";
    my $res = $jmap->CallMethods(
        [
            [
                'Mailbox/set',
                {
                    create => {
                        "1" => {
                            name     => "drafts",
                            parentId => undef,
                            role     => "drafts"
                        },
                        "2" => {
                            name     => "foo",
                            parentId => undef,
                        },
                        "3" => {
                            name     => "bar",
                            parentId => undef,
                        },
                    }
                },
                "R1"
            ]
        ]
    );
    $self->assert_str_equals('Mailbox/set', $res->[0][0]);
    $self->assert_str_equals('R1', $res->[0][2]);
    $self->assert_not_null( $res->[0][1]{created} );
    my $mailboxids = {
        $res->[0][1]{created}{"1"}{id} => JSON::true,
        $res->[0][1]{created}{"2"}{id} => JSON::true,
        $res->[0][1]{created}{"3"}{id} => JSON::true,
    };

    xlog $self, "Create a draft";
    my $draft = {
        mailboxIds => $mailboxids,
        from       => [ { name => "Yosemite Sam", email => "sam\@acme.local" } ],
        to         => [ { name => "Bugs Bunny", email => "bugs\@acme.local" } ],
        subject    => "created",
        textBody   => [{ partId => '1' }],
        bodyValues => { '1' => { value => "Oh!!! I *hate* that Rabbit." }},
        keywords => { '$draft' => JSON::true },
    };
    $res = $jmap->CallMethods(
        [ [ 'Email/set', { create => { "1" => $draft } }, "R1" ] ],
    );
    my $id = $res->[0][1]{created}{"1"}{id};
    $self->assert_not_null($id);

    xlog $self, "Get draft $id";
    $res = $jmap->CallMethods( [ [ 'Email/get', { ids => [$id] }, "R1" ] ]);
    $self->assert_num_equals(3, scalar keys %{$res->[0][1]->{list}[0]{mailboxIds}});

    xlog $self, "Destroy draft $id";
    $res = $jmap->CallMethods(
        [ [ 'Email/set', { destroy => [ $id ] }, "R1" ] ],
    );
    $self->assert_str_equals($id, $res->[0][1]{destroyed}[0]);

    xlog $self, "Get draft $id";
    $res = $jmap->CallMethods( [ [ 'Email/get', { ids => [$id] }, "R1" ] ]);
    $self->assert_str_equals($id, $res->[0][1]->{notFound}[0]);

    xlog $self, "Get emails";
    $res = $jmap->CallMethods([['Email/query', {}, "R1"]]);
    $self->assert_num_equals(0, scalar @{$res->[0][1]->{ids}});
}

sub test_email_query
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $account = undef;
    my $store = $self->{store};
    my $mboxprefix = "INBOX";
    my $talk = $store->get_client();

    my $res = $jmap->CallMethods([['Mailbox/get', { accountId => $account }, "R1"]]);
    my $inboxid = $res->[0][1]{list}[0]{id};

    xlog $self, "create mailboxes";
    $talk->create("$mboxprefix.A") || die;
    $talk->create("$mboxprefix.B") || die;
    $talk->create("$mboxprefix.C") || die;

    $res = $jmap->CallMethods([['Mailbox/get', { accountId => $account }, "R1"]]);
    my %m = map { $_->{name} => $_ } @{$res->[0][1]{list}};
    my $mboxa = $m{"A"}->{id};
    my $mboxb = $m{"B"}->{id};
    my $mboxc = $m{"C"}->{id};
    $self->assert_not_null($mboxa);
    $self->assert_not_null($mboxb);
    $self->assert_not_null($mboxc);

    xlog $self, "create emails";
    my %params;
    $store->set_folder("$mboxprefix.A");
    my $dtfoo = DateTime->new(
        year       => 2016,
        month      => 11,
        day        => 1,
        hour       => 7,
        time_zone  => 'Etc/UTC',
    );
    my $bodyfoo = "A rather short email";
    %params = (
        date => $dtfoo,
        body => $bodyfoo,
        store => $store,
    );
    $res = $self->make_message("foo", %params) || die;
    $talk->copy(1, "$mboxprefix.C") || die;

    $store->set_folder("$mboxprefix.B");
    my $dtbar = DateTime->new(
        year       => 2016,
        month      => 3,
        day        => 1,
        hour       => 19,
        time_zone  => 'Etc/UTC',
    );
    my $bodybar = ""
    . "In the context of electronic mail, emails are viewed as having an\r\n"
    . "envelope and contents.  The envelope contains whatever information is\r\n"
    . "needed to accomplish transmission and delivery.  (See [RFC5321] for a\r\n"
    . "discussion of the envelope.)  The contents comprise the object to be\r\n"
    . "delivered to the recipient.  This specification applies only to the\r\n"
    . "format and some of the semantics of email contents.  It contains no\r\n"
    . "specification of the information in the envelope.i\r\n"
    . "\r\n"
    . "However, some email systems may use information from the contents\r\n"
    . "to create the envelope.  It is intended that this specification\r\n"
    . "facilitate the acquisition of such information by programs.\r\n"
    . "\r\n"
    . "This specification is intended as a definition of what email\r\n"
    . "content format is to be passed between systems.  Though some email\r\n"
    . "systems locally store emails in this format (which eliminates the\r\n"
    . "need for translation between formats) and others use formats that\r\n"
    . "differ from the one specified in this specification, local storage is\r\n"
    . "outside of the scope of this specification.\r\n";

    %params = (
        date => $dtbar,
        body => $bodybar,
        extra_headers => [
            ['x-tra', "baz"],
        ],
        store => $store,
    );
    $self->make_message("bar", %params) || die;

    xlog $self, "run squatter";
    $self->{instance}->run_command({cyrus => 1}, 'squatter');

    xlog $self, "fetch emails without filter";
    $res = $jmap->CallMethods([
        ['Email/query', { accountId => $account }, 'R1'],
        ['Email/get', {
            accountId => $account,
            '#ids' => { resultOf => 'R1', name => 'Email/query', path => '/ids' }
        }, 'R2'],
    ]);
    $self->assert_num_equals(2, scalar @{$res->[0][1]->{ids}});
    $self->assert_num_equals(2, scalar @{$res->[1][1]->{list}});

    %m = map { $_->{subject} => $_ } @{$res->[1][1]{list}};
    my $foo = $m{"foo"}->{id};
    my $bar = $m{"bar"}->{id};
    $self->assert_not_null($foo);
    $self->assert_not_null($bar);

    xlog $self, "filter text";
    $res = $jmap->CallMethods([['Email/query', {
                    accountId => $account,
                    filter => {
                        text => "foo",
                    },
                }, "R1"]]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{ids}});
    $self->assert_str_equals($foo, $res->[0][1]->{ids}[0]);

    xlog $self, "filter NOT text";
    $res = $jmap->CallMethods([['Email/query', {
                    accountId => $account,
                    filter => {
                        operator => "NOT",
                        conditions => [ {text => "foo"} ],
                    },
                }, "R1"]]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{ids}});
    $self->assert_str_equals($bar, $res->[0][1]->{ids}[0]);

    xlog $self, "filter mailbox A";
    $res = $jmap->CallMethods([['Email/query', {
                    accountId => $account,
                    filter => {
                        inMailbox => $mboxa,
                    },
                }, "R1"]]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{ids}});
    $self->assert_str_equals($foo, $res->[0][1]->{ids}[0]);

    xlog $self, "filter mailboxes";
    $res = $jmap->CallMethods([['Email/query', {
                    accountId => $account,
                    filter => {
                        operator => 'OR',
                        conditions => [
                            {
                                inMailbox => $mboxa,
                            },
                            {
                                inMailbox => $mboxc,
                            },
                        ],
                    },
                }, "R1"]]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{ids}});
    $self->assert_str_equals($foo, $res->[0][1]->{ids}[0]);

    xlog $self, "filter mailboxes with not in";
    $res = $jmap->CallMethods([['Email/query', {
                    accountId => $account,
                    filter => {
                        inMailboxOtherThan => [$mboxb],
                    },
                }, "R1"]]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{ids}});
    $self->assert_str_equals($foo, $res->[0][1]->{ids}[0]);

    xlog $self, "filter mailboxes";
    $res = $jmap->CallMethods([['Email/query', {
                    accountId => $account,
                    filter => {
                        operator => 'AND',
                        conditions => [
                            {
                                inMailbox => $mboxa,
                            },
                            {
                                inMailbox => $mboxb,
                            },
                            {
                                inMailbox => $mboxc,
                            },
                        ],
                    },
                }, "R1"]]);
    $self->assert_num_equals(0, scalar @{$res->[0][1]->{ids}});

    xlog $self, "filter not in mailbox A";
    $res = $jmap->CallMethods([['Email/query', {
                    accountId => $account,
                    filter => {
                        operator => 'NOT',
                        conditions => [
                            {
                                inMailbox => $mboxa,
                            },
                        ],
                    },
                }, "R1"]]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{ids}});
    $self->assert_str_equals($bar, $res->[0][1]->{ids}[0]);

    xlog $self, "filter by before";
    my $dtbefore = $dtfoo->clone()->subtract(seconds => 1);
    $res = $jmap->CallMethods([['Email/query', {
                    accountId => $account,
                    filter => {
                        before => $dtbefore->strftime('%Y-%m-%dT%TZ'),
                    },
                }, "R1"]]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{ids}});
    $self->assert_str_equals($bar, $res->[0][1]->{ids}[0]);

    xlog $self, "filter by after",
    my $dtafter = $dtbar->clone()->add(seconds => 1);
    $res = $jmap->CallMethods([['Email/query', {
                    accountId => $account,
                    filter => {
                        after => $dtafter->strftime('%Y-%m-%dT%TZ'),
                    },
                }, "R1"]]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{ids}});
    $self->assert_str_equals($foo, $res->[0][1]->{ids}[0]);

    xlog $self, "filter by after and before",
    $res = $jmap->CallMethods([['Email/query', {
                    accountId => $account,
                    filter => {
                        after => $dtafter->strftime('%Y-%m-%dT%TZ'),
                        before => $dtbefore->strftime('%Y-%m-%dT%TZ'),
                    },
                }, "R1"]]);
    $self->assert_num_equals(0, scalar @{$res->[0][1]->{ids}});

    xlog $self, "filter by minSize";
    $res = $jmap->CallMethods([['Email/query', {
                    accountId => $account,
                    filter => {
                        minSize => length($bodybar),
                    },
                }, "R1"]]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{ids}});
    $self->assert_str_equals($bar, $res->[0][1]->{ids}[0]);

    xlog $self, "filter by maxSize";
    $res = $jmap->CallMethods([['Email/query', {
                    accountId => $account,
                    filter => {
                        maxSize => length($bodybar),
                    },
                }, "R1"]]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{ids}});
    $self->assert_str_equals($foo, $res->[0][1]->{ids}[0]);

    xlog $self, "filter by header";
    $res = $jmap->CallMethods([['Email/query', {
                    accountId => $account,
                    filter => {
                        header => [ "x-tra" ],
                    },
                }, "R1"]]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{ids}});
    $self->assert_str_equals($bar, $res->[0][1]->{ids}[0]);

    xlog $self, "filter by header and value";
    $res = $jmap->CallMethods([['Email/query', {
                    accountId => $account,
                    filter => {
                        header => [ "x-tra", "bam" ],
                    },
                }, "R1"]]);
    $self->assert_num_equals(0, scalar @{$res->[0][1]->{ids}});

    xlog $self, "sort by ascending receivedAt";
    $res = $jmap->CallMethods([['Email/query', {
                    accountId => $account,
                    sort => [{ property => "receivedAt" }],
                }, "R1"]]);
    $self->assert_num_equals(2, scalar @{$res->[0][1]->{ids}});
    $self->assert_str_equals($bar, $res->[0][1]->{ids}[0]);
    $self->assert_str_equals($foo, $res->[0][1]->{ids}[1]);

    xlog $self, "sort by descending receivedAt";
    $res = $jmap->CallMethods([['Email/query', {
                    accountId => $account,
                    sort => [{ property => "receivedAt", isAscending => JSON::false }],
                }, "R1"]]);
    $self->assert_num_equals(2, scalar @{$res->[0][1]->{ids}});
    $self->assert_str_equals($foo, $res->[0][1]->{ids}[0]);
    $self->assert_str_equals($bar, $res->[0][1]->{ids}[1]);

    xlog $self, "sort by ascending sentAt";
    $res = $jmap->CallMethods([['Email/query', {
                    accountId => $account,
                    sort => [{ property => "sentAt" }],
                }, "R1"]]);
    $self->assert_num_equals(2, scalar @{$res->[0][1]->{ids}});
    $self->assert_str_equals($bar, $res->[0][1]->{ids}[0]);
    $self->assert_str_equals($foo, $res->[0][1]->{ids}[1]);

    xlog $self, "sort by descending sentAt";
    $res = $jmap->CallMethods([['Email/query', {
                    accountId => $account,
                    sort => [{ property => "sentAt", isAscending => JSON::false }],
                }, "R1"]]);
    $self->assert_num_equals(2, scalar @{$res->[0][1]->{ids}});
    $self->assert_str_equals($foo, $res->[0][1]->{ids}[0]);
    $self->assert_str_equals($bar, $res->[0][1]->{ids}[1]);

    xlog $self, "sort by ascending size";
    $res = $jmap->CallMethods([['Email/query', {
                    accountId => $account,
                    sort => [{ property =>  "size" }],
                }, "R1"]]);
    $self->assert_num_equals(2, scalar @{$res->[0][1]->{ids}});
    $self->assert_str_equals($foo, $res->[0][1]->{ids}[0]);
    $self->assert_str_equals($bar, $res->[0][1]->{ids}[1]);

    xlog $self, "sort by descending size";
    $res = $jmap->CallMethods([['Email/query', {
                    accountId => $account,
                    sort => [{ property => "size", isAscending => JSON::false }],
                }, "R1"]]);
    $self->assert_num_equals(2, scalar @{$res->[0][1]->{ids}});
    $self->assert_str_equals($bar, $res->[0][1]->{ids}[0]);
    $self->assert_str_equals($foo, $res->[0][1]->{ids}[1]);

    xlog $self, "sort by ascending id";
    $res = $jmap->CallMethods([['Email/query', {
                    accountId => $account,
                    sort => [{ property => "id" }],
                }, "R1"]]);
    my @ids = sort ($foo, $bar);
    $self->assert_deep_equals(\@ids, $res->[0][1]->{ids});

    xlog $self, "sort by descending id";
    $res = $jmap->CallMethods([['Email/query', {
                    accountId => $account,
                    sort => [{ property => "id", isAscending => JSON::false }],
                }, "R1"]]);
    @ids = reverse sort ($foo, $bar);
    $self->assert_deep_equals(\@ids, $res->[0][1]->{ids});

    xlog $self, "delete mailboxes";
    $talk->delete("$mboxprefix.A") or die;
    $talk->delete("$mboxprefix.B") or die;
    $talk->delete("$mboxprefix.C") or die;
}

sub test_email_query_bcc
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $account = undef;
    my $store = $self->{store};
    my $mboxprefix = "INBOX";
    my $talk = $store->get_client();

    my $res = $jmap->CallMethods([['Mailbox/get', { accountId => $account }, "R1"]]);
    my $inboxid = $res->[0][1]{list}[0]{id};

    xlog $self, "create email1";
    my $bcc1  = Cassandane::Address->new(localpart => 'needle', domain => 'local');
    my $msg1 = $self->make_message('msg1', bcc => $bcc1);

    my $bcc2  = Cassandane::Address->new(localpart => 'beetle', domain => 'local');
    my $msg2 = $self->make_message('msg2', bcc => $bcc2);

    xlog $self, "run squatter";
    $self->{instance}->run_command({cyrus => 1}, 'squatter');

    xlog $self, "fetch emails without filter";
    $res = $jmap->CallMethods([
        ['Email/query', { accountId => $account }, 'R1'],
        ['Email/get', {
            accountId => $account,
            '#ids' => { resultOf => 'R1', name => 'Email/query', path => '/ids' }
        }, 'R2'],
    ]);

    my %m = map { $_->{subject} => $_ } @{$res->[1][1]{list}};
    my $emailId1 = $m{"msg1"}->{id};
    my $emailId2 = $m{"msg2"}->{id};
    $self->assert_not_null($emailId1);
    $self->assert_not_null($emailId2);

    xlog $self, "filter text";
    $res = $jmap->CallMethods([['Email/query', {
        filter => {
            text => "needle",
        },
    }, "R1"]]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{ids}});
    $self->assert_str_equals($emailId1, $res->[0][1]->{ids}[0]);

    xlog $self, "filter NOT text";
    $res = $jmap->CallMethods([['Email/query', {
        filter => {
            operator => "NOT",
            conditions => [ {text => "needle"} ],
        },
    }, "R1"]]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{ids}});
    $self->assert_str_equals($emailId2, $res->[0][1]->{ids}[0]);

    xlog $self, "filter bcc";
    $res = $jmap->CallMethods([['Email/query', {
        filter => {
            bcc => "needle",
        },
    }, "R1"]]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{ids}});
    $self->assert_str_equals($emailId1, $res->[0][1]->{ids}[0]);

    xlog $self, "filter NOT bcc";
    $res = $jmap->CallMethods([['Email/query', {
        filter => {
            operator => "NOT",
            conditions => [ {bcc => "needle"} ],
        },
    }, "R1"]]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{ids}});
    $self->assert_str_equals($emailId2, $res->[0][1]->{ids}[0]);
}

sub test_email_query_multiple_to_cross_domain
    :min_version_3_1 :needs_component_jmap :JMAPExtensions
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $account = undef;
    my $store = $self->{store};
    my $mboxprefix = "INBOX";
    my $talk = $store->get_client();

    my $res = $jmap->CallMethods([['Mailbox/get', { accountId => $account }, "R1"]]);
    my $inboxid = $res->[0][1]{list}[0]{id};

    xlog $self, "create email1";
    my $msg1 = {
        mailboxIds => { $inboxid => JSON::true },
        subject => 'msg1',
        to => [
            { name => undef, email => "foo\@example.com" },
            { name => undef, email => "bar\@example.net" }
        ]
    };

    $res = $jmap->CallMethods([['Email/set', { create => { "1" => $msg1 }}, "R1"]]);

    xlog $self, "run squatter";
    $self->{instance}->run_command({cyrus => 1}, 'squatter');

    xlog $self, "fetch emails without filter";
    $res = $jmap->CallMethods([
        ['Email/query', { accountId => $account }, 'R1'],
        ['Email/get', {
            accountId => $account,
            '#ids' => { resultOf => 'R1', name => 'Email/query', path => '/ids' },
            properties => [ 'subject', 'mailboxIds', 'to' ],
        }, 'R2'],
    ]);

    my %m = map { $_->{subject} => $_ } @{$res->[1][1]{list}};
    my $emailId1 = $m{"msg1"}->{id};
    $self->assert_not_null($emailId1);

    xlog $self, "filter to with mixed localpart and domain";
    $res = $jmap->CallMethods([['Email/query', {
        filter => {
            to => 'foo@example.net'
        }
    }, "R1"]]);
    $self->assert_num_equals(0, scalar @{$res->[0][1]->{ids}});
}


sub test_email_query_shared
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $admintalk = $self->{adminstore}->get_client();
    $self->{instance}->create_user("test");
    $admintalk->setacl("user.test", "cassandane", "lrwkx") or die;

    # run tests for both the main and "test" account
    foreach (undef, "test") {
        my $account = $_;
        my $store = defined $account ? $self->{adminstore} : $self->{store};
        my $mboxprefix = defined $account ? "user.$account" : "INBOX";
        my $talk = $store->get_client();

        my $res = $jmap->CallMethods([['Mailbox/get', { accountId => $account }, "R1"]]);
        my $inboxid = $res->[0][1]{list}[0]{id};

        xlog $self, "create mailboxes";
        $talk->create("$mboxprefix.A") || die;
        $talk->create("$mboxprefix.B") || die;
        $talk->create("$mboxprefix.C") || die;

        $res = $jmap->CallMethods([['Mailbox/get', { accountId => $account }, "R1"]]);
        my %m = map { $_->{name} => $_ } @{$res->[0][1]{list}};
        my $mboxa = $m{"A"}->{id};
        my $mboxb = $m{"B"}->{id};
        my $mboxc = $m{"C"}->{id};
        $self->assert_not_null($mboxa);
        $self->assert_not_null($mboxb);
        $self->assert_not_null($mboxc);

        xlog $self, "create emails";
        my %params;
        $store->set_folder("$mboxprefix.A");
        my $dtfoo = DateTime->new(
            year       => 2016,
            month      => 11,
            day        => 1,
            hour       => 7,
            time_zone  => 'Etc/UTC',
        );
        my $bodyfoo = "A rather short email";
        %params = (
            date => $dtfoo,
            body => $bodyfoo,
            store => $store,
        );
        $res = $self->make_message("foo", %params) || die;
        $talk->copy(1, "$mboxprefix.C") || die;

        $store->set_folder("$mboxprefix.B");
        my $dtbar = DateTime->new(
            year       => 2016,
            month      => 3,
            day        => 1,
            hour       => 19,
            time_zone  => 'Etc/UTC',
        );
        my $bodybar = ""
        . "In the context of electronic mail, emails are viewed as having an\r\n"
        . "envelope and contents.  The envelope contains whatever information is\r\n"
        . "needed to accomplish transmission and delivery.  (See [RFC5321] for a\r\n"
        . "discussion of the envelope.)  The contents comprise the object to be\r\n"
        . "delivered to the recipient.  This specification applies only to the\r\n"
        . "format and some of the semantics of email contents.  It contains no\r\n"
        . "specification of the information in the envelope.i\r\n"
        . "\r\n"
        . "However, some email systems may use information from the contents\r\n"
        . "to create the envelope.  It is intended that this specification\r\n"
        . "facilitate the acquisition of such information by programs.\r\n"
        . "\r\n"
        . "This specification is intended as a definition of what email\r\n"
        . "content format is to be passed between systems.  Though some email\r\n"
        . "systems locally store emails in this format (which eliminates the\r\n"
        . "need for translation between formats) and others use formats that\r\n"
        . "differ from the one specified in this specification, local storage is\r\n"
        . "outside of the scope of this specification.\r\n";

        %params = (
            date => $dtbar,
            body => $bodybar,
            extra_headers => [
                ['x-tra', "baz"],
            ],
            store => $store,
        );
        $self->make_message("bar", %params) || die;

        xlog $self, "run squatter";
        $self->{instance}->run_command({cyrus => 1}, 'squatter');

        xlog $self, "fetch emails without filter";
        $res = $jmap->CallMethods([
                ['Email/query', { accountId => $account }, 'R1'],
                ['Email/get', {
                        accountId => $account,
                        '#ids' => { resultOf => 'R1', name => 'Email/query', path => '/ids' }
                    }, 'R2'],
            ]);
        $self->assert_num_equals(2, scalar @{$res->[0][1]->{ids}});
        $self->assert_num_equals(2, scalar @{$res->[1][1]->{list}});

        %m = map { $_->{subject} => $_ } @{$res->[1][1]{list}};
        my $foo = $m{"foo"}->{id};
        my $bar = $m{"bar"}->{id};
        $self->assert_not_null($foo);
        $self->assert_not_null($bar);

        xlog $self, "filter text";
        $res = $jmap->CallMethods([['Email/query', {
                        accountId => $account,
                        filter => {
                            text => "foo",
                        },
                    }, "R1"]]);
        $self->assert_num_equals(1, scalar @{$res->[0][1]->{ids}});
        $self->assert_str_equals($foo, $res->[0][1]->{ids}[0]);

        xlog $self, "filter NOT text";
        $res = $jmap->CallMethods([['Email/query', {
                        accountId => $account,
                        filter => {
                            operator => "NOT",
                            conditions => [ {text => "foo"} ],
                        },
                    }, "R1"]]);
        $self->assert_num_equals(1, scalar @{$res->[0][1]->{ids}});
        $self->assert_str_equals($bar, $res->[0][1]->{ids}[0]);

        xlog $self, "filter mailbox A";
        $res = $jmap->CallMethods([['Email/query', {
                        accountId => $account,
                        filter => {
                            inMailbox => $mboxa,
                        },
                    }, "R1"]]);
        $self->assert_num_equals(1, scalar @{$res->[0][1]->{ids}});
        $self->assert_str_equals($foo, $res->[0][1]->{ids}[0]);

        xlog $self, "filter mailboxes";
        $res = $jmap->CallMethods([['Email/query', {
                        accountId => $account,
                        filter => {
                            operator => 'OR',
                            conditions => [
                                {
                                    inMailbox => $mboxa,
                                },
                                {
                                    inMailbox => $mboxc,
                                },
                            ],
                        },
                    }, "R1"]]);
        $self->assert_num_equals(1, scalar @{$res->[0][1]->{ids}});
        $self->assert_str_equals($foo, $res->[0][1]->{ids}[0]);

        xlog $self, "filter mailboxes with not in";
        $res = $jmap->CallMethods([['Email/query', {
                        accountId => $account,
                        filter => {
                            inMailboxOtherThan => [$mboxb],
                        },
                    }, "R1"]]);
        $self->assert_num_equals(1, scalar @{$res->[0][1]->{ids}});
        $self->assert_str_equals($foo, $res->[0][1]->{ids}[0]);

        xlog $self, "filter mailboxes with not in";
        $res = $jmap->CallMethods([['Email/query', {
                        accountId => $account,
                        filter => {
                            inMailboxOtherThan => [$mboxa],
                        },
                    }, "R1"]]);
        $self->assert_num_equals(2, scalar @{$res->[0][1]->{ids}});

        xlog $self, "filter mailboxes with not in";
        $res = $jmap->CallMethods([['Email/query', {
                        accountId => $account,
                        filter => {
                            inMailboxOtherThan => [$mboxa, $mboxc],
                        },
                    }, "R1"]]);
        $self->assert_num_equals(1, scalar @{$res->[0][1]->{ids}});
        $self->assert_str_equals($bar, $res->[0][1]->{ids}[0]);

        xlog $self, "filter mailboxes";
        $res = $jmap->CallMethods([['Email/query', {
                        accountId => $account,
                        filter => {
                            operator => 'AND',
                            conditions => [
                                {
                                    inMailbox => $mboxa,
                                },
                                {
                                    inMailbox => $mboxb,
                                },
                                {
                                    inMailbox => $mboxc,
                                },
                            ],
                        },
                    }, "R1"]]);
        $self->assert_num_equals(0, scalar @{$res->[0][1]->{ids}});

        xlog $self, "filter not in mailbox A";
        $res = $jmap->CallMethods([['Email/query', {
                        accountId => $account,
                        filter => {
                            operator => 'NOT',
                            conditions => [
                                {
                                    inMailbox => $mboxa,
                                },
                            ],
                        },
                    }, "R1"]]);
        $self->assert_num_equals(1, scalar @{$res->[0][1]->{ids}});
        $self->assert_str_equals($bar, $res->[0][1]->{ids}[0]);

        xlog $self, "filter by before";
        my $dtbefore = $dtfoo->clone()->subtract(seconds => 1);
        $res = $jmap->CallMethods([['Email/query', {
                        accountId => $account,
                        filter => {
                            before => $dtbefore->strftime('%Y-%m-%dT%TZ'),
                        },
                    }, "R1"]]);
        $self->assert_num_equals(1, scalar @{$res->[0][1]->{ids}});
        $self->assert_str_equals($bar, $res->[0][1]->{ids}[0]);

        xlog $self, "filter by after",
        my $dtafter = $dtbar->clone()->add(seconds => 1);
        $res = $jmap->CallMethods([['Email/query', {
                        accountId => $account,
                        filter => {
                            after => $dtafter->strftime('%Y-%m-%dT%TZ'),
                        },
                    }, "R1"]]);
        $self->assert_num_equals(1, scalar @{$res->[0][1]->{ids}});
        $self->assert_str_equals($foo, $res->[0][1]->{ids}[0]);

        xlog $self, "filter by after and before",
        $res = $jmap->CallMethods([['Email/query', {
                        accountId => $account,
                        filter => {
                            after => $dtafter->strftime('%Y-%m-%dT%TZ'),
                            before => $dtbefore->strftime('%Y-%m-%dT%TZ'),
                        },
                    }, "R1"]]);
        $self->assert_num_equals(0, scalar @{$res->[0][1]->{ids}});

        xlog $self, "filter by minSize";
        $res = $jmap->CallMethods([['Email/query', {
                        accountId => $account,
                        filter => {
                            minSize => length($bodybar),
                        },
                    }, "R1"]]);
        $self->assert_num_equals(1, scalar @{$res->[0][1]->{ids}});
        $self->assert_str_equals($bar, $res->[0][1]->{ids}[0]);

        xlog $self, "filter by maxSize";
        $res = $jmap->CallMethods([['Email/query', {
                        accountId => $account,
                        filter => {
                            maxSize => length($bodybar),
                        },
                    }, "R1"]]);
        $self->assert_num_equals(1, scalar @{$res->[0][1]->{ids}});
        $self->assert_str_equals($foo, $res->[0][1]->{ids}[0]);

        xlog $self, "filter by header";
        $res = $jmap->CallMethods([['Email/query', {
                        accountId => $account,
                        filter => {
                            header => [ "x-tra" ],
                        },
                    }, "R1"]]);
        $self->assert_num_equals(1, scalar @{$res->[0][1]->{ids}});
        $self->assert_str_equals($bar, $res->[0][1]->{ids}[0]);

        xlog $self, "filter by header and value";
        $res = $jmap->CallMethods([['Email/query', {
                        accountId => $account,
                        filter => {
                            header => [ "x-tra", "bam" ],
                        },
                    }, "R1"]]);
        $self->assert_num_equals(0, scalar @{$res->[0][1]->{ids}});

        xlog $self, "sort by ascending receivedAt";
        $res = $jmap->CallMethods([['Email/query', {
                        accountId => $account,
                        sort => [{ property => "receivedAt" }],
                    }, "R1"]]);
        $self->assert_num_equals(2, scalar @{$res->[0][1]->{ids}});
        $self->assert_str_equals($bar, $res->[0][1]->{ids}[0]);
        $self->assert_str_equals($foo, $res->[0][1]->{ids}[1]);

        xlog $self, "sort by descending receivedAt";
        $res = $jmap->CallMethods([['Email/query', {
                        accountId => $account,
                        sort => [{ property => "receivedAt", isAscending => JSON::false, }],
                    }, "R1"]]);
        $self->assert_num_equals(2, scalar @{$res->[0][1]->{ids}});
        $self->assert_str_equals($foo, $res->[0][1]->{ids}[0]);
        $self->assert_str_equals($bar, $res->[0][1]->{ids}[1]);

        xlog $self, "sort by ascending size";
        $res = $jmap->CallMethods([['Email/query', {
                        accountId => $account,
                        sort => [{ property => "size" }],
                    }, "R1"]]);
        $self->assert_num_equals(2, scalar @{$res->[0][1]->{ids}});
        $self->assert_str_equals($foo, $res->[0][1]->{ids}[0]);
        $self->assert_str_equals($bar, $res->[0][1]->{ids}[1]);

        xlog $self, "sort by descending size";
        $res = $jmap->CallMethods([['Email/query', {
                        accountId => $account,
                        sort => [{ property => "size", isAscending => JSON::false }],
                    }, "R1"]]);
        $self->assert_num_equals(2, scalar @{$res->[0][1]->{ids}});
        $self->assert_str_equals($bar, $res->[0][1]->{ids}[0]);
        $self->assert_str_equals($foo, $res->[0][1]->{ids}[1]);

        xlog $self, "sort by ascending id";
        $res = $jmap->CallMethods([['Email/query', {
                        accountId => $account,
                        sort => [{ property => "id" }],
                    }, "R1"]]);
        my @ids = sort ($foo, $bar);
        $self->assert_deep_equals(\@ids, $res->[0][1]->{ids});

        xlog $self, "sort by descending id";
        $res = $jmap->CallMethods([['Email/query', {
                        accountId => $account,
                        sort => [{ property => "id", isAscending => JSON::false }],
                    }, "R1"]]);
        @ids = reverse sort ($foo, $bar);
        $self->assert_deep_equals(\@ids, $res->[0][1]->{ids});

        xlog $self, "delete mailboxes";
        $talk->delete("$mboxprefix.A") or die;
        $talk->delete("$mboxprefix.B") or die;
        $talk->delete("$mboxprefix.C") or die;
    }
}

sub test_email_query_keywords
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();

    my $res = $jmap->CallMethods([['Mailbox/get', { }, "R1"]]);
    my $inboxid = $res->[0][1]{list}[0]{id};

    xlog $self, "create email";
    $res = $self->make_message("foo") || die;

    xlog $self, "run squatter";
    $self->{instance}->run_command({cyrus => 1}, 'squatter');

    xlog $self, "fetch emails without filter";
    $res = $jmap->CallMethods([
        ['Email/query', { }, 'R1'],
    ]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{ids}});
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{ids}});
    my $fooid = $res->[0][1]->{ids}[0];

    xlog $self, "fetch emails with \$seen flag";
    $res = $jmap->CallMethods([['Email/query', {
        filter => {
            hasKeyword => '$seen',
        }
    }, "R1"]]);
    $self->assert_num_equals(0, scalar @{$res->[0][1]->{ids}});

    xlog $self, "fetch emails without \$seen flag";
    $res = $jmap->CallMethods([['Email/query', {
        filter => {
            notKeyword => '$seen',
        }
    }, "R1"]]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{ids}});

    xlog $self, 'set $seen flag on email';
    $res = $jmap->CallMethods([['Email/set', {
        update => {
            $fooid => {
                keywords => { '$seen' => JSON::true },
            },
        }
    }, "R1"]]);
    $self->assert(exists $res->[0][1]->{updated}{$fooid});

    xlog $self, "fetch emails with \$seen flag";
    $res = $jmap->CallMethods([['Email/query', {
        filter => {
            hasKeyword => '$seen',
        }
    }, "R1"]]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{ids}});

    xlog $self, "fetch emails without \$seen flag";
    $res = $jmap->CallMethods([['Email/query', {
        filter => {
            notKeyword => '$seen',
        }
    }, "R1"]]);
    $self->assert_num_equals(0, scalar @{$res->[0][1]->{ids}});

    xlog $self, "create email";
    $res = $self->make_message("bar") || die;

    xlog $self, "fetch emails without \$seen flag";
    $res = $jmap->CallMethods([['Email/query', {
        filter => {
            notKeyword => '$seen',
        }
    }, "R1"]]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{ids}});
    my $barid = $res->[0][1]->{ids}[0];
    $self->assert_str_not_equals($fooid, $barid);

    xlog $self, "fetch emails sorted ascending by \$seen flag";
    $res = $jmap->CallMethods([['Email/query', {
        sort => [{ property => 'hasKeyword', keyword => '$seen' }],
    }, "R1"]]);
    $self->assert_num_equals(2, scalar @{$res->[0][1]->{ids}});
    $self->assert_str_equals($barid, $res->[0][1]->{ids}[0]);
    $self->assert_str_equals($fooid, $res->[0][1]->{ids}[1]);

    xlog $self, "fetch emails sorted descending by \$seen flag";
    $res = $jmap->CallMethods([['Email/query', {
        sort => [{ property => 'hasKeyword', keyword => '$seen', isAscending => JSON::false }],
    }, "R1"]]);
    $self->assert_num_equals(2, scalar @{$res->[0][1]->{ids}});
    $self->assert_str_equals($fooid, $res->[0][1]->{ids}[0]);
    $self->assert_str_equals($barid, $res->[0][1]->{ids}[1]);
}

sub test_email_query_userkeywords
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();

    xlog $self, "create email foo";
    my $res = $self->make_message("foo") || die;

    xlog $self, "fetch foo's id";
    $res = $jmap->CallMethods([['Email/query', { }, "R1"]]);
    my $fooid = $res->[0][1]->{ids}[0];
    $self->assert_not_null($fooid);

    xlog $self, 'set foo flag on email foo';
    $res = $jmap->CallMethods([['Email/set', {
        update => {
            $fooid => {
                keywords => { 'foo' => JSON::true },
            },
        }
    }, "R1"]]);
    $self->assert(exists $res->[0][1]->{updated}{$fooid});

    xlog $self, "run squatter";
    $self->{instance}->run_command({cyrus => 1}, 'squatter');

    xlog $self, "fetch emails with foo flag";
    $res = $jmap->CallMethods([['Email/query', {
        filter => {
            hasKeyword => 'foo',
        }
    }, "R1"]]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{ids}});
    $self->assert_str_equals($fooid, $res->[0][1]->{ids}[0]);

    xlog $self, "create email bar";
    $res = $self->make_message("bar") || die;

    xlog $self, "fetch emails without foo flag";
    $res = $jmap->CallMethods([['Email/query', {
        filter => {
            notKeyword => 'foo',
        }
    }, "R1"]]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{ids}});
    my $barid = $res->[0][1]->{ids}[0];
    $self->assert_str_not_equals($barid, $fooid);

    xlog $self, "fetch emails sorted ascending by foo flag";
    $res = $jmap->CallMethods([['Email/query', {
        sort => [{ property => 'hasKeyword', keyword => 'foo' }],
    }, "R1"]]);
    $self->assert_num_equals(2, scalar @{$res->[0][1]->{ids}});
    $self->assert_str_equals($barid, $res->[0][1]->{ids}[0]);
    $self->assert_str_equals($fooid, $res->[0][1]->{ids}[1]);

    xlog $self, "fetch emails sorted descending by foo flag";
    $res = $jmap->CallMethods([['Email/query', {
        sort => [{ property => 'hasKeyword', keyword => 'foo', isAscending => JSON::false }],
    }, "R1"]]);
    $self->assert_num_equals(2, scalar @{$res->[0][1]->{ids}});
    $self->assert_str_equals($fooid, $res->[0][1]->{ids}[0]);
    $self->assert_str_equals($barid, $res->[0][1]->{ids}[1]);
}

sub test_email_query_threadkeywords
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my %exp;
    my $jmap = $self->{jmap};
    my $res;

    my $imaptalk = $self->{store}->get_client();

    # check IMAP server has the XCONVERSATIONS capability
    $self->assert($self->{store}->get_client()->capability()->{xconversations});

    my $convflags = $self->{instance}->{config}->get('conversations_counted_flags');
    if (not defined $convflags) {
        xlog $self, "conversations_counted_flags not configured. Skipping test";
        return;
    }

    my $store = $self->{store};
    my $talk = $store->get_client();

    my %params = (store => $store);
    $store->set_folder("INBOX");

    xlog $self, "generating email A";
    $exp{A} = $self->make_message("Email A", %params);
    $exp{A}->set_attributes(uid => 1, cid => $exp{A}->make_cid());

    xlog $self, "generating email B";
    $exp{B} = $self->make_message("Email B", %params);
    $exp{B}->set_attributes(uid => 2, cid => $exp{B}->make_cid());

    xlog $self, "generating email C referencing A";
    %params = (
        references => [ $exp{A} ],
        store => $store,
    );
    $exp{C} = $self->make_message("Re: Email A", %params);
    $exp{C}->set_attributes(uid => 3, cid => $exp{A}->get_attribute('cid'));

    xlog $self, "run squatter";
    $self->{instance}->run_command({cyrus => 1}, 'squatter');

    xlog $self, "fetch email ids";
    $res = $jmap->CallMethods([
        ['Email/query', { }, "R1"],
        ['Email/get', { '#ids' => { resultOf => 'R1', name => 'Email/query', path => '/ids' } }, 'R2' ],
    ]);
    my %m = map { $_->{subject} => $_ } @{$res->[1][1]{list}};
    my $msga = $m{"Email A"};
    my $msgb = $m{"Email B"};
    my $msgc = $m{"Re: Email A"};
    $self->assert_not_null($msga);
    $self->assert_not_null($msgb);
    $self->assert_not_null($msgc);

    my @flags = split ' ', $convflags;
    foreach (@flags) {
        my $flag = $_;
        next if lc $flag eq '$hasattachment';  # special case

        xlog $self, "Testing for counted conversation flag $flag";
        $flag =~ s+^\\+\$+ ;

        xlog $self, "fetch collapsed threads with some $flag flag";
        $res = $jmap->CallMethods([['Email/query', {
            filter => {
                someInThreadHaveKeyword => $flag,
            },
            collapseThreads => JSON::true,
        }, "R1"]]);
        $self->assert_num_equals(0, scalar @{$res->[0][1]->{ids}});

        xlog $self, "set $flag flag on email email A";
        $res = $jmap->CallMethods([['Email/set', {
            update => {
                $msga->{id} => {
                    keywords => { $flag => JSON::true },
                },
            }
        }, "R1"]]);

        xlog $self, "fetch collapsed threads with some $flag flag";
        $res = $jmap->CallMethods([
            ['Email/query', {
                filter => {
                    someInThreadHaveKeyword => $flag,
                },
                collapseThreads => JSON::true,
            }, "R1"],
        ]);
        $self->assert_num_equals(1, scalar @{$res->[0][1]->{ids}});
        $self->assert(
            ($msga->{id} eq $res->[0][1]->{ids}[0]) or
            ($msgc->{id} eq $res->[0][1]->{ids}[0])
        );

        xlog $self, "fetch collapsed threads with no $flag flag";
        $res = $jmap->CallMethods([['Email/query', {
            filter => {
                noneInThreadHaveKeyword => $flag,
            },
            collapseThreads => JSON::true,
        }, "R1"]]);
        $self->assert_num_equals(1, scalar @{$res->[0][1]->{ids}});
        $self->assert_str_equals($msgb->{id}, $res->[0][1]->{ids}[0]);

        xlog $self, "fetch collapsed threads sorted ascending by $flag";
        $res = $jmap->CallMethods([['Email/query', {
            sort => [{ property => "someInThreadHaveKeyword", keyword => $flag }],
            collapseThreads => JSON::true,
        }, "R1"]]);
        $self->assert_num_equals(2, scalar @{$res->[0][1]->{ids}});
        $self->assert_str_equals($msgb->{id}, $res->[0][1]->{ids}[0]);
        $self->assert(
            ($msga->{id} eq $res->[0][1]->{ids}[1]) or
            ($msgc->{id} eq $res->[0][1]->{ids}[1])
        );

        xlog $self, "fetch collapsed threads sorted descending by $flag";
        $res = $jmap->CallMethods([['Email/query', {
            sort => [{ property => "someInThreadHaveKeyword", keyword => $flag, isAscending => JSON::false }],
            collapseThreads => JSON::true,
        }, "R1"]]);
        $self->assert_num_equals(2, scalar @{$res->[0][1]->{ids}});
        $self->assert(
            ($msga->{id} eq $res->[0][1]->{ids}[0]) or
            ($msgc->{id} eq $res->[0][1]->{ids}[0])
        );
        $self->assert_str_equals($msgb->{id}, $res->[0][1]->{ids}[1]);

        xlog $self, 'reset keywords on email email A';
        $res = $jmap->CallMethods([['Email/set', {
            update => {
                $msga->{id} => {
                    keywords => { },
                },
            }
        }, "R1"]]);
    }

    # test that 'someInThreadHaveKeyword' filter fail
    # with an 'cannotDoFilter' error for flags that are not defined
    # in the conversations_counted_flags config option
    xlog $self, "fetch collapsed threads with unsupported flag";
    $res = $jmap->CallMethods([['Email/query', {
        filter => {
            someInThreadHaveKeyword => 'notcountedflag',
        },
        collapseThreads => JSON::true,
    }, "R1"]]);
    $self->assert_str_equals('error', $res->[0][0]);
    $self->assert_str_equals('unsupportedFilter', $res->[0][1]->{type});
}

sub test_email_query_empty
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    # See
    # https://github.com/cyrusimap/cyrus-imapd/issues/2266
    # and
    # https://github.com/cyrusimap/cyrus-imapd/issues/2287

    my $res = $jmap->CallMethods([['Email/query', { }, "R1"]]);
    $self->assert(ref($res->[0][1]->{ids}) eq 'ARRAY');
    $self->assert_num_equals(0, scalar @{$res->[0][1]->{ids}});

    $res = $jmap->CallMethods([['Email/query', { limit => 0 }, "R1"]]);
    $self->assert(ref($res->[0][1]->{ids}) eq 'ARRAY');
    $self->assert_num_equals(0, scalar @{$res->[0][1]->{ids}});
}

sub test_email_query_collapse
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my %exp;
    my $jmap = $self->{jmap};
    my $res;

    my $imaptalk = $self->{store}->get_client();

    # check IMAP server has the XCONVERSATIONS capability
    $self->assert($self->{store}->get_client()->capability()->{xconversations});

    my $admintalk = $self->{adminstore}->get_client();
    $self->{instance}->create_user("test");
    $admintalk->setacl("user.test", "cassandane", "lrwkx") or die;

    # run tests for both the main and "test" account
    foreach (undef, "test") {
        my $account = $_;
        my $store = defined $account ? $self->{adminstore} : $self->{store};
        my $mboxprefix = defined $account ? "user.$account" : "INBOX";
        my $talk = $store->get_client();

        my %params = (store => $store);
        $store->set_folder($mboxprefix);

        xlog $self, "generating email A";
        $exp{A} = $self->make_message("Email A", %params);
        $exp{A}->set_attributes(uid => 1, cid => $exp{A}->make_cid());

        xlog $self, "generating email B";
        $exp{B} = $self->make_message("Email B", %params);
        $exp{B}->set_attributes(uid => 2, cid => $exp{B}->make_cid());

        xlog $self, "generating email C referencing A";
        %params = (
            references => [ $exp{A} ],
            store => $store,
        );
        $exp{C} = $self->make_message("Re: Email A", %params);
        $exp{C}->set_attributes(uid => 3, cid => $exp{A}->get_attribute('cid'));

        xlog $self, "list uncollapsed threads";
        $res = $jmap->CallMethods([['Email/query', { accountId => $account }, "R1"]]);
        $self->assert_num_equals(3, scalar @{$res->[0][1]->{ids}});

        $res = $jmap->CallMethods([['Email/query', { accountId => $account, collapseThreads => JSON::true }, "R1"]]);
        $self->assert_num_equals(2, scalar @{$res->[0][1]->{ids}});
    }
}

sub test_email_query_inmailbox_null
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $imaptalk = $self->{store}->get_client();

    # check IMAP server has the XCONVERSATIONS capability
    $self->assert($self->{store}->get_client()->capability()->{xconversations});

    xlog $self, "generating email A";
    $self->make_message("Email A") or die;

    xlog $self, "call Email/query with null inMailbox";
    my $res = $jmap->CallMethods([['Email/query', { filter => { inMailbox => undef } }, "R1"]]);
    $self->assert_str_equals("invalidArguments", $res->[0][1]{type});
}

sub test_email_query_cached_legacy
    :min_version_3_1 :max_version_3_4 :needs_component_jmap
    :JMAPSearchDBLegacy :JMAPExtensions
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();

    my $res = $jmap->CallMethods([['Mailbox/get', { }, "R1"]]);
    my $inboxid = $res->[0][1]{list}[0]{id};

    xlog $self, "create emails";
    $res = $self->make_message("foo 1") || die;
    $res = $self->make_message("foo 2") || die;

    xlog $self, "run squatter";
    $self->{instance}->run_command({cyrus => 1}, 'squatter');

    my $query1 = {
        filter => {
            subject => 'foo',
        },
        sort => [{ property => 'subject' }],
    };

    my $query2 = {
        filter => {
            subject => 'foo',
        },
        sort => [{ property => 'subject', isAscending => JSON::false }],
    };

    my $using = [
        'https://cyrusimap.org/ns/jmap/performance',
        'urn:ietf:params:jmap:core',
        'urn:ietf:params:jmap:mail',
    ];

    xlog $self, "run query #1";
    $res = $jmap->CallMethods([['Email/query', $query1, 'R1']], $using);
    $self->assert_num_equals(2, scalar @{$res->[0][1]->{ids}});
    $self->assert_equals(JSON::false, $res->[0][1]->{performance}{details}{isCached});

    xlog $self, "re-run query #1";
    $res = $jmap->CallMethods([['Email/query', $query1, 'R1']], $using);
    $self->assert_num_equals(2, scalar @{$res->[0][1]->{ids}});
    $self->assert_equals(JSON::true, $res->[0][1]->{performance}{details}{isCached});

    xlog $self, "run query #2";
    $res = $jmap->CallMethods([['Email/query', $query2, 'R1']], $using);
    $self->assert_num_equals(2, scalar @{$res->[0][1]->{ids}});
    $self->assert_equals(JSON::false, $res->[0][1]->{performance}{details}{isCached});

    xlog $self, "re-run query #1 (still cached)";
    $res = $jmap->CallMethods([['Email/query', $query1, 'R1']], $using);
    $self->assert_num_equals(2, scalar @{$res->[0][1]->{ids}});
    $self->assert_equals(JSON::true, $res->[0][1]->{performance}{details}{isCached});

    xlog $self, "re-run query #2 (still cached)";
    $res = $jmap->CallMethods([['Email/query', $query2, 'R1']], $using);
    $self->assert_num_equals(2, scalar @{$res->[0][1]->{ids}});
    $self->assert_equals(JSON::true, $res->[0][1]->{performance}{details}{isCached});

    xlog $self, "change Email state";
    $res = $self->make_message("foo 3") || die;

    xlog $self, "run squatter";
    $self->{instance}->run_command({cyrus => 1}, 'squatter');

    xlog $self, "re-run query #1 (cache invalidated)";
    $res = $jmap->CallMethods([['Email/query', $query1, 'R1']], $using);
    $self->assert_num_equals(3, scalar @{$res->[0][1]->{ids}});
    $self->assert_equals(JSON::false, $res->[0][1]->{performance}{details}{isCached});

    xlog $self, "re-run query #2 (cache invalidated)";
    $res = $jmap->CallMethods([['Email/query', $query2, 'R1']], $using);
    $self->assert_num_equals(3, scalar @{$res->[0][1]->{ids}});
    $self->assert_equals(JSON::false, $res->[0][1]->{performance}{details}{isCached});
}

sub test_email_query_cached
    :min_version_3_5 :needs_component_jmap :JMAPQueryCacheMaxAge1s :JMAPExtensions
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();

    my $res = $jmap->CallMethods([['Mailbox/get', { }, "R1"]]);
    my $inboxid = $res->[0][1]{list}[0]{id};

    xlog $self, "create emails";
    $res = $self->make_message("foo 1") || die;
    $res = $self->make_message("foo 2") || die;

    xlog $self, "run squatter";
    $self->{instance}->run_command({cyrus => 1}, 'squatter');

    my $query1 = {
        filter => {
            subject => 'foo',
        },
        sort => [{ property => 'subject' }],
    };

    my $query2 = {
        filter => {
            subject => 'foo',
        },
        sort => [{ property => 'subject', isAscending => JSON::false }],
    };

    my $using = [
        'https://cyrusimap.org/ns/jmap/performance',
        'urn:ietf:params:jmap:core',
        'urn:ietf:params:jmap:mail',
    ];

    xlog $self, "run query #1";
    $res = $jmap->CallMethods([['Email/query', $query1, 'R1']], $using);
    $self->assert_num_equals(2, scalar @{$res->[0][1]->{ids}});
    $self->assert_equals(JSON::false, $res->[0][1]->{performance}{details}{isCached});

    xlog $self, "re-run query #1";
    $res = $jmap->CallMethods([['Email/query', $query1, 'R1']], $using);
    $self->assert_num_equals(2, scalar @{$res->[0][1]->{ids}});
    $self->assert_equals(JSON::true, $res->[0][1]->{performance}{details}{isCached});

    xlog $self, "run query #2";
    $res = $jmap->CallMethods([['Email/query', $query2, 'R1']], $using);
    $self->assert_num_equals(2, scalar @{$res->[0][1]->{ids}});
    $self->assert_equals(JSON::false, $res->[0][1]->{performance}{details}{isCached});

    xlog $self, "re-run query #2";
    $res = $jmap->CallMethods([['Email/query', $query2, 'R1']], $using);
    $self->assert_num_equals(2, scalar @{$res->[0][1]->{ids}});
    $self->assert_equals(JSON::true, $res->[0][1]->{performance}{details}{isCached});

    xlog $self, "change Email state";
    $res = $self->make_message("foo 3") || die;

    xlog $self, "run squatter";
    $self->{instance}->run_command({cyrus => 1}, 'squatter');

    xlog $self, "re-run query #2";
    $res = $jmap->CallMethods([['Email/query', $query2, 'R1']], $using);
    $self->assert_num_equals(3, scalar @{$res->[0][1]->{ids}});
    $self->assert_equals(JSON::false, $res->[0][1]->{performance}{details}{isCached});
}

sub test_email_query_cached_evict_slow
    :min_version_3_5 :needs_component_jmap :JMAPQueryCacheMaxAge1s :JMAPExtensions
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    $self->make_message("foo") || die;
    $self->{instance}->run_command({cyrus => 1}, 'squatter');

    my $using = [
        'https://cyrusimap.org/ns/jmap/performance',
        'urn:ietf:params:jmap:core',
        'urn:ietf:params:jmap:mail',
        'urn:ietf:params:jmap:submission',
    ];

    my $res = $jmap->CallMethods([
        ['Email/query', {
            filter => {
                text => 'foo',
            },
        }, 'R1'],
    ], $using);
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{ids}});
    $self->assert_equals(JSON::false, $res->[0][1]->{performance}{details}{isCached});

    $res = $jmap->CallMethods([
        ['Email/query', {
            filter => {
                text => 'foo',
            },
        }, 'R1'],
    ], $using);
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{ids}});
    $self->assert_equals(JSON::true, $res->[0][1]->{performance}{details}{isCached});

    sleep(2);

    $res = $jmap->CallMethods([
        ['Identity/get', {
            # evict cache
        }, 'R1'],
        ['Email/query', {
            filter => {
                text => 'foo',
            },
        }, 'R2'],
    ], $using);
    $self->assert_num_equals(1, scalar @{$res->[1][1]->{ids}});
    $self->assert_equals(JSON::false, $res->[1][1]->{performance}{details}{isCached});
}

sub test_email_query_issue2905
    :min_version_3_1 :needs_component_jmap :JMAPQueryCacheMaxAge1s
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();

    xlog $self, "create emails";
    my $res = $jmap->CallMethods([
        ['Email/set', {
            create => {
                email1 => {
                    mailboxIds => {
                        '$inbox' => JSON::true
                    },
                    from => [{ email => q{foo1@bar} }],
                    to => [{ email => q{bar1@foo} }],
                    subject => "email1",
                    keywords => {
                        '$flagged' => JSON::true
                    },
                    bodyStructure => {
                        partId => '1',
                    },
                    bodyValues => {
                        "1" => {
                            value => "email1 body",
                        },
                    },
                },
                email2 => {
                    mailboxIds => {
                        '$inbox' => JSON::true
                    },
                    from => [{ email => q{foo2@bar} }],
                    to => [{ email => q{bar2@foo} }],
                    subject => "email2",
                    keywords => {
                        '$flagged' => JSON::true
                    },
                    bodyStructure => {
                        partId => '2',
                    },
                    bodyValues => {
                        "2" => {
                            value => "email2 body",
                        },
                    },
                },
            },
        }, 'R1'],
    ]);
    my $emailId1 = $res->[0][1]{created}{email1}{id};
    $self->assert_not_null($emailId1);
    my $emailId2 = $res->[0][1]{created}{email2}{id};
    $self->assert_not_null($emailId2);

    xlog $self, "run squatter";
    $self->{instance}->run_command({cyrus => 1}, 'squatter');

    $res = $jmap->CallMethods([
        # Run query with mutable search
        ['Email/query', {
            filter => {
                hasKeyword => '$flagged',
            },
        }, 'R1'],
        # Remove $flagged keyword from email2
        ['Email/set', {
            update => {
                $emailId2 => {
                    'keywords/$flagged' => undef,
                },
            },
        }, 'R2'],
        # Re-run query with mutable search
        ['Email/query', {
            filter => {
                hasKeyword => '$flagged',
            },
        }, 'R3'],
    ]);

    # Assert first query.
    my $queryState = $res->[0][1]->{queryState};
    $self->assert_not_null($queryState);
    $self->assert_equals(JSON::false, $res->[0][1]->{canCalculateChanges});

    # Assert email update.
    $self->assert(exists $res->[1][1]->{updated}{$emailId2});

    # Assert second query.
    $self->assert_str_not_equals($queryState, $res->[2][1]->{queryState});
    $self->assert_equals(JSON::false, $res->[2][1]->{canCalculateChanges});

    $res = $jmap->CallMethods([
        ['Email/queryChanges', {
            sinceQueryState => $queryState,
            filter => {
                hasKeyword => '$flagged',
            },
        }, 'R1']
    ]);

    # Assert queryChanges error.
    $self->assert_str_equals('cannotCalculateChanges', $res->[0][1]{type});
}

sub test_email_query_inmailboxid_conjunction
    :min_version_3_1 :needs_component_jmap :JMAPExtensions
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $imap = $self->{store}->get_client();

    xlog $self, "create mailboxes";
    $imap->create("INBOX.A") or die;
    $imap->create("INBOX.B") or die;
    my $res = $jmap->CallMethods([
        ['Mailbox/get', {
            properties => ['name', 'parentId'],
        }, "R1"]
    ]);
    my %mboxByName = map { $_->{name} => $_ } @{$res->[0][1]{list}};
    my $mboxIdA = $mboxByName{'A'}->{id};
    my $mboxIdB = $mboxByName{'B'}->{id};

    xlog $self, "create emails";
    $res = $jmap->CallMethods([
        ['Email/set', {
            create => {
                'mAB' => {
                    mailboxIds => {
                        $mboxIdA => JSON::true,
                        $mboxIdB => JSON::true,
                    },
                    from => [{
                        name => '', email => 'foo@local'
                    }],
                    to => [{
                        name => '', email => 'bar@local'
                    }],
                    subject => 'AB',
                    bodyStructure => {
                        type => 'text/plain',
                        partId => 'part1',
                    },
                    bodyValues => {
                        part1 => {
                            value => 'test',
                        }
                    },
                },
                'mA' => {
                    mailboxIds => {
                        $mboxIdA => JSON::true,
                    },
                    from => [{
                        name => '', email => 'foo@local'
                    }],
                    to => [{
                        name => '', email => 'bar@local'
                    }],
                    subject => 'A',
                    bodyStructure => {
                        type => 'text/plain',
                        partId => 'part1',
                    },
                    bodyValues => {
                        part1 => {
                            value => 'test',
                        }
                    },
                },
                'mB' => {
                    mailboxIds => {
                        $mboxIdB => JSON::true,
                    },
                    from => [{
                        name => '', email => 'foo@local'
                    }],
                    to => [{
                        name => '', email => 'bar@local'
                    }],
                    subject => 'B',
                    bodyStructure => {
                        type => 'text/plain',
                        partId => 'part1',
                    },
                    bodyValues => {
                        part1 => {
                            value => 'test',
                        }
                    },
                },
            },
        }, 'R1'],
    ]);
    my $emailIdAB = $res->[0][1]->{created}{mAB}{id};
    $self->assert_not_null($emailIdAB);
    my $emailIdA = $res->[0][1]->{created}{mA}{id};
    $self->assert_not_null($emailIdA);
    my $emailIdB = $res->[0][1]->{created}{mB}{id};
    $self->assert_not_null($emailIdB);

    xlog $self, "run squatter";
    $self->{instance}->run_command({cyrus => 1}, 'squatter');

    my $using = [
        'urn:ietf:params:jmap:core',
        'urn:ietf:params:jmap:mail',
        'urn:ietf:params:jmap:submission',
        'https://cyrusimap.org/ns/jmap/mail',
        'https://cyrusimap.org/ns/jmap/debug',
        'https://cyrusimap.org/ns/jmap/performance',
    ];

    xlog $self, "query emails in mailboxes A AND B";
    $res = $jmap->CallMethods([
        ['Email/query', {
            filter => {
                operator => 'AND',
                conditions => [{
                    inMailbox => $mboxIdA,
                }, {
                    inMailbox => $mboxIdB,
                }],
            },
            disableGuidSearch => JSON::true,
        }, 'R1'],
    ], $using);
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{ids}});
    $self->assert_str_equals($emailIdAB, $res->[0][1]->{ids}[0]);

    xlog $self, "query emails in mailboxes A AND B (forcing indexed search)";
    $res = $jmap->CallMethods([
        ['Email/query', {
            filter => {
                operator => 'AND',
                conditions => [{
                    inMailbox => $mboxIdA,
                }, {
                    inMailbox => $mboxIdB,
                }, {
                    text => "test",
                }],
            },
            disableGuidSearch => JSON::true,
        }, 'R1'],
    ], $using);
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{ids}});
    $self->assert_str_equals($emailIdAB, $res->[0][1]->{ids}[0]);
}

sub test_email_query_toaddress
    :min_version_3_1 :needs_component_jmap :JMAPExtensions
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $imap = $self->{store}->get_client();

    xlog $self, "create mailboxes";
    $imap->create("INBOX.A") or die;
    $imap->create("INBOX.B") or die;
    my $res = $jmap->CallMethods([
        ['Mailbox/get', {
            properties => ['name', 'parentId'],
        }, "R1"]
    ]);
    my %mboxByName = map { $_->{name} => $_ } @{$res->[0][1]{list}};
    my $mboxIdA = $mboxByName{'A'}->{id};
    my $mboxIdB = $mboxByName{'B'}->{id};

    xlog $self, "create emails";
    $res = $jmap->CallMethods([
        ['Email/set', {
            create => {
                'mAB' => {
                    mailboxIds => {
                        $mboxIdA => JSON::true,
                        $mboxIdB => JSON::true,
                    },
                    from => [{
                        name => '', email => 'bar@local'
                    }],
                    to => [{
                        name => '', email => 'xyzzy@remote'
                    }],
                    subject => 'AB',
                    bodyStructure => {
                        type => 'text/plain',
                        partId => 'part1',
                    },
                    bodyValues => {
                        part1 => {
                            value => 'test',
                        }
                    },
                },
                'mA' => {
                    mailboxIds => {
                        $mboxIdA => JSON::true,
                    },
                    from => [{
                        name => '', email => 'foo@local'
                    }],
                    to => [{
                        name => '', email => 'bar@local'
                    }],
                    subject => 'A',
                    bodyStructure => {
                        type => 'text/plain',
                        partId => 'part1',
                    },
                    bodyValues => {
                        part1 => {
                            value => 'test',
                        }
                    },
                },
                'mB' => {
                    mailboxIds => {
                        $mboxIdB => JSON::true,
                    },
                    from => [{
                        name => '', email => 'foo@local'
                    }],
                    to => [{
                        name => '', email => 'bar@local'
                    }],
                    subject => 'B',
                    bodyStructure => {
                        type => 'text/plain',
                        partId => 'part1',
                    },
                    bodyValues => {
                        part1 => {
                            value => 'test',
                        }
                    },
                },
            },
        }, 'R1'],
    ]);
    my $emailIdAB = $res->[0][1]->{created}{mAB}{id};
    $self->assert_not_null($emailIdAB);
    my $emailIdA = $res->[0][1]->{created}{mA}{id};
    $self->assert_not_null($emailIdA);
    my $emailIdB = $res->[0][1]->{created}{mB}{id};
    $self->assert_not_null($emailIdB);

    xlog $self, "run squatter";
    $self->{instance}->run_command({cyrus => 1}, 'squatter');

    my $using = [
        'urn:ietf:params:jmap:core',
        'urn:ietf:params:jmap:mail',
        'urn:ietf:params:jmap:submission',
        'https://cyrusimap.org/ns/jmap/mail',
        'https://cyrusimap.org/ns/jmap/debug',
        'https://cyrusimap.org/ns/jmap/performance',
    ];

    xlog $self, "query emails that are to bar";
    $res = $jmap->CallMethods([
        ['Email/query', {
            filter => {
                operator => 'AND',
                conditions => [
                   {
                      operator => 'OR',
                      conditions => [
                        { "to" => 'bar@local' },
                        { "cc" => 'bar@local' },
                        { "bcc" => 'bar@local' },
                      ],
                   },
                   { "text" => "test" },
                   { "inMailboxOtherThan" => [ $mboxIdB ] },
                ],
            },
            disableGuidSearch => JSON::true,
        }, 'R1'],
    ], $using);
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{ids}});
    $self->assert_str_equals($emailIdA, $res->[0][1]->{ids}[0]);
}

sub test_email_query_inmailboxotherthan
    :min_version_3_1 :needs_component_jmap :JMAPExtensions
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();

    my $res = $jmap->CallMethods([['Mailbox/get', { }, "R1"]]);
    my $inboxid = $res->[0][1]{list}[0]{id};

    xlog $self, "create mailboxes";
    $talk->create("INBOX.A") || die;
    $talk->create("INBOX.B") || die;
    $talk->create("INBOX.C") || die;

    $res = $jmap->CallMethods([['Mailbox/get', { }, "R1"]]);
    my %m = map { $_->{name} => $_ } @{$res->[0][1]{list}};
    my $mboxIdA = $m{"A"}->{id};
    my $mboxIdB = $m{"B"}->{id};
    my $mboxIdC = $m{"C"}->{id};
    $self->assert_not_null($mboxIdA);
    $self->assert_not_null($mboxIdB);
    $self->assert_not_null($mboxIdC);

    xlog $self, "create emails";
    $store->set_folder("INBOX.A");
    $res = $self->make_message("email1") || die;
    $talk->copy(1, "INBOX.B") || die;
    $talk->copy(1, "INBOX.C") || die;

    $store->set_folder("INBOX.B");
    $self->make_message("email2") || die;

    xlog $self, "run squatter";
    $self->{instance}->run_command({cyrus => 1}, 'squatter');

    my $using = [
        'urn:ietf:params:jmap:core',
        'urn:ietf:params:jmap:mail',
        'urn:ietf:params:jmap:submission',
        'https://cyrusimap.org/ns/jmap/mail',
        'https://cyrusimap.org/ns/jmap/debug',
        'https://cyrusimap.org/ns/jmap/performance',
    ];

    xlog $self, "fetch emails without filter";
    $res = $jmap->CallMethods([
        ['Email/query', { }, 'R1'],
        ['Email/get', {
            '#ids' => {
                resultOf => 'R1',
                name => 'Email/query',
                path => '/ids'
            }
        }, 'R2'],
    ], $using);
    $self->assert_num_equals(2, scalar @{$res->[0][1]->{ids}});
    $self->assert_num_equals(2, scalar @{$res->[1][1]->{list}});

    %m = map { $_->{subject} => $_ } @{$res->[1][1]{list}};
    my $emailId1 = $m{"email1"}->{id};
    my $emailId2 = $m{"email2"}->{id};
    $self->assert_not_null($emailId1);
    $self->assert_not_null($emailId2);

    $res = $jmap->CallMethods([['Email/query', {
        filter => {
            inMailboxOtherThan => [$mboxIdB],
        },
        sort => [{ property => 'subject' }],
        disableGuidSearch => JSON::true,
    }, "R1"]], $using);
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{ids}});
    $self->assert_str_equals($emailId1, $res->[0][1]->{ids}[0]);

    $res = $jmap->CallMethods([['Email/query', {
        filter => {
            inMailboxOtherThan => [$mboxIdA],
        },
        sort => [{ property => 'subject' }],
        disableGuidSearch => JSON::true,
    }, "R1"]], $using);
    $self->assert_num_equals(2, scalar @{$res->[0][1]->{ids}});
    $self->assert_str_equals($emailId1, $res->[0][1]->{ids}[0]);
    $self->assert_str_equals($emailId2, $res->[0][1]->{ids}[1]);

    $res = $jmap->CallMethods([['Email/query', {
        filter => {
            inMailboxOtherThan => [$mboxIdA, $mboxIdC],
        },
        sort => [{ property => 'subject' }],
        disableGuidSearch => JSON::true,
    }, "R1"]], $using);
    $self->assert_num_equals(2, scalar @{$res->[0][1]->{ids}});
    $self->assert_str_equals($emailId1, $res->[0][1]->{ids}[0]);
    $self->assert_str_equals($emailId2, $res->[0][1]->{ids}[1]);

    $res = $jmap->CallMethods([['Email/query', {
        filter => {
            operator => 'NOT',
            conditions => [{
                inMailboxOtherThan => [$mboxIdB],
            }],
        },
        sort => [{ property => 'subject' }],
        disableGuidSearch => JSON::true,
    }, "R1"]], $using);
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{ids}});
    $self->assert_str_equals($emailId2, $res->[0][1]->{ids}[0]);
}


sub test_email_query_moved
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $imap = $self->{store}->get_client();

    xlog $self, "create mailboxes";
    $imap->create("INBOX.A") or die;
    $imap->create("INBOX.B") or die;
    my $res = $jmap->CallMethods([
        ['Mailbox/get', {
            properties => ['name', 'parentId'],
        }, "R1"]
    ]);
    my %mboxByName = map { $_->{name} => $_ } @{$res->[0][1]{list}};
    my $mboxIdA = $mboxByName{'A'}->{id};
    my $mboxIdB = $mboxByName{'B'}->{id};

    xlog $self, "create emails in mailbox A";
    $res = $jmap->CallMethods([
        ['Email/set', {
            create => {
                'msg1' => {
                    mailboxIds => {
                        $mboxIdA => JSON::true,
                    },
                    from => [{
                        name => '', email => 'foo@local'
                    }],
                    to => [{
                        name => '', email => 'bar@local'
                    }],
                    subject => 'message 1',
                    bodyStructure => {
                        type => 'text/plain',
                        partId => 'part1',
                    },
                    bodyValues => {
                        part1 => {
                            value => 'test',
                        }
                    },
                },
            },
        }, 'R1'],
        ['Email/set', {
            create => {
                'msg2' => {
                    mailboxIds => {
                        $mboxIdA => JSON::true,
                    },
                    from => [{
                        name => '', email => 'foo@local'
                    }],
                    to => [{
                        name => '', email => 'bar@local'
                    }],
                    subject => 'message 2',
                    bodyStructure => {
                        type => 'text/plain',
                        partId => 'part1',
                    },
                    bodyValues => {
                        part1 => {
                            value => 'test',
                        }
                    },
                },
            },
        }, 'R2'],
    ]);
    my $emailId1 = $res->[0][1]->{created}{msg1}{id};
    $self->assert_not_null($emailId1);
    my $emailId2 = $res->[1][1]->{created}{msg2}{id};
    $self->assert_not_null($emailId2);

    xlog $self, "run squatter";
    $self->{instance}->run_command({cyrus => 1}, 'squatter');

    xlog $self, "query emails";
    $res = $jmap->CallMethods([
        ['Email/query', {
            filter => {
                inMailbox => $mboxIdA,
                text => 'message',
            },
            sort => [{
                property => 'subject',
                isAscending => JSON::true,
            }],
        }, 'R1'],
    ]);
    $self->assert_num_equals(2, scalar @{$res->[0][1]->{ids}});
    $self->assert_str_equals($emailId1, $res->[0][1]->{ids}[0]);
    $self->assert_str_equals($emailId2, $res->[0][1]->{ids}[1]);

    xlog $self, "move msg2 to mailbox B";
    $res = $jmap->CallMethods([
        ['Email/set', {
            update => {
                $emailId2 => {
                    mailboxIds => {
                        $mboxIdB => JSON::true,
                    },
                },
            },
        }, 'R1'],
    ]);
    $self->assert(exists $res->[0][1]{updated}{$emailId2});

    xlog $self, "assert move";
    $res = $jmap->CallMethods([
        ['Email/get', {
            ids => [$emailId1, $emailId2],
            properties => ['mailboxIds'],
        }, 'R1'],
    ]);
    $self->assert_str_equals($emailId1, $res->[0][1]{list}[0]{id});
    my $wantMailboxIds1 = { $mboxIdA => JSON::true };
    $self->assert_deep_equals($wantMailboxIds1, $res->[0][1]{list}[0]{mailboxIds});

    $self->assert_str_equals($emailId2, $res->[0][1]{list}[1]{id});
    my $wantMailboxIds2 = { $mboxIdB => JSON::true };
    $self->assert_deep_equals($wantMailboxIds2, $res->[0][1]{list}[1]{mailboxIds});

    xlog $self, "query emails";
    $res = $jmap->CallMethods([
        ['Email/query', {
            filter => {
                inMailbox => $mboxIdA,
                text => 'message',
            },
        }, 'R1'],
        ['Email/query', {
            filter => {
                inMailbox => $mboxIdB,
                text => 'message',
            },
        }, 'R2'],
    ]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{ids}});
    $self->assert_str_equals($emailId1, $res->[0][1]->{ids}[0]);
    $self->assert_num_equals(1, scalar @{$res->[1][1]->{ids}});
    $self->assert_str_equals($emailId2, $res->[1][1]->{ids}[0]);
}

sub test_email_query_from
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $imap = $self->{store}->get_client();

    # Create test messages.
    $self->make_message('uid1', from => Cassandane::Address->new(
        name => 'B',
        localpart => 'local',
        domain => 'hostA'
    ));
    $self->make_message('uid2', from => Cassandane::Address->new(
        name => 'A',
        localpart => 'local',
        domain => 'hostA'
    ));
    $self->make_message('uid3', from => Cassandane::Address->new(
        localpart => 'local',
        domain => 'hostY'
    ));
    $self->make_message('uid4', from => Cassandane::Address->new(
        localpart => 'local',
        domain => 'hostX'
    ));

    my $res = $jmap->CallMethods([
        ['Email/query', {
            sort => [{ property => 'subject' }],
        }, 'R1'],
    ]);
    $self->assert_num_equals(4, scalar @{$res->[0][1]->{ids}});
    my $emailId1 = $res->[0][1]{ids}[0];
    my $emailId2 = $res->[0][1]{ids}[1];
    my $emailId3 = $res->[0][1]{ids}[2];
    my $emailId4 = $res->[0][1]{ids}[3];

    $res = $jmap->CallMethods([
        ['Email/query', {
            sort => [
                { property => 'from' },
                { property => 'subject'}
            ],
        }, 'R1'],
    ]);
    $self->assert_num_equals(4, scalar @{$res->[0][1]->{ids}});
    $self->assert_str_equals($emailId2, $res->[0][1]{ids}[0]);
    $self->assert_str_equals($emailId1, $res->[0][1]{ids}[1]);
    $self->assert_str_equals($emailId4, $res->[0][1]{ids}[2]);
    $self->assert_str_equals($emailId3, $res->[0][1]{ids}[3]);
}

sub test_email_query_addedDates
    :min_version_3_1 :needs_component_jmap :JMAPExtensions
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $imap = $self->{store}->get_client();

    # we need 'https://cyrusimap.org/ns/jmap/mail' capability for
    # addedDates property
    my @using = @{ $jmap->DefaultUsing() };
    push @using, 'https://cyrusimap.org/ns/jmap/mail';
    $jmap->DefaultUsing(\@using);

    my $inboxid = $self->getinbox()->{id};

    xlog $self, "Create Trash folder";
    my $res = $jmap->CallMethods([
        ['Mailbox/set', {
            create => {
                "trash" => {
                    name => "Trash",
                    parentId => undef,
                    role => "trash"
                }
            }
        }, "R1"],
    ]);
    my $trashId = $res->[0][1]{created}{trash}{id};
    $self->assert_not_null($trashId);

    xlog $self, "create messages";
    $self->make_message('uid1') || die;
    $self->make_message('uid2') || die;
    sleep 1;
    $self->make_message('uid3') || die;
    $self->make_message('uid4') || die;

    xlog $self, "run squatter";
    $self->{instance}->run_command({cyrus => 1}, 'squatter');

    $res = $jmap->CallMethods([
        ['Email/query', {
            sort => [{
                property => 'subject',
                isAscending => JSON::true
            }],
        }, 'R1'],
    ]);
    my $emailId1 = $res->[0][1]{ids}[0];
    my $emailId2 = $res->[0][1]{ids}[1];
    my $emailId3 = $res->[0][1]{ids}[2];
    my $emailId4 = $res->[0][1]{ids}[3];
    $self->assert_not_null($emailId1);
    $self->assert_not_null($emailId2);
    $self->assert_not_null($emailId3);
    $self->assert_not_null($emailId4);

    # Move email2 to mailbox using role as id
    sleep 1;
    $res = $jmap->CallMethods([
        ['Email/set', {
            update => {
                $emailId2 => {
                    "mailboxIds/$inboxid" => undef,
                    "mailboxIds/$trashId" => JSON::true
                }
            },
        }, 'R1'],
    ]);

    # Move email1 to mailbox using role as id
    sleep 1;
    $res = $jmap->CallMethods([
        ['Email/set', {
            update => {
                $emailId1 => {
                    "mailboxIds/$inboxid" => undef,
                    "mailboxIds/$trashId" => JSON::true
                }
            },
        }, 'R1'],
    ]);

    # Copy email4 to mailbox using role as id
    sleep 1;
    $res = $jmap->CallMethods([
        ['Email/set', {
            update => {
                $emailId4 => {
                     "mailboxIds/$trashId" => JSON::true,
                     keywords => { '$flagged' => JSON::true }
                }
            },
        }, 'R1'],
    ]);

    # Copy email3 to mailbox using role as id
    sleep 1;
    $res = $jmap->CallMethods([
        ['Email/set', {
            update => {
                $emailId3 => {
                    "mailboxIds/$trashId" => JSON::true
                }
            },
        }, 'R1'],
    ]);

    xlog $self, "query emails sorted by addedDates";
    $res = $jmap->CallMethods([
        ['Email/query', {
            sort => [{
                property => 'addedDates',
                mailboxId => "$trashId",
                isAscending => JSON::true
            }],
        }, 'R1'],
    ]);
    $self->assert_num_equals(4, scalar @{$res->[0][1]->{ids}});
    $self->assert_str_equals($emailId1, $res->[0][1]->{ids}[1]);
    $self->assert_str_equals($emailId2, $res->[0][1]->{ids}[0]);
    $self->assert_str_equals($emailId3, $res->[0][1]->{ids}[3]);
    $self->assert_str_equals($emailId4, $res->[0][1]->{ids}[2]);

    $res = $jmap->CallMethods([
        ['Email/query', {
            sort => [{
                property => 'someInThreadHaveKeyword',
                keyword => '$flagged',
                isAscending => JSON::false,
              },
              {
                property => 'addedDates',
                mailboxId => "$trashId",
                isAscending => JSON::false,
            }],
        }, 'R1'],
    ]);
    $self->assert_num_equals(4, scalar @{$res->[0][1]->{ids}});
    $self->assert_str_equals($emailId1, $res->[0][1]->{ids}[2]);
    $self->assert_str_equals($emailId2, $res->[0][1]->{ids}[3]);
    $self->assert_str_equals($emailId3, $res->[0][1]->{ids}[1]);
    $self->assert_str_equals($emailId4, $res->[0][1]->{ids}[0]);
}


sub test_misc_collapsethreads_issue2024
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my %exp;
    my $jmap = $self->{jmap};
    my $res;

    my $imaptalk = $self->{store}->get_client();

    # test that the collapseThreads property is echoed back verbatim
    # see https://github.com/cyrusimap/cyrus-imapd/issues/2024

    # check IMAP server has the XCONVERSATIONS capability
    $self->assert($self->{store}->get_client()->capability()->{xconversations});

    xlog $self, "generating email A";
    $exp{A} = $self->make_message("Email A");
    $exp{A}->set_attributes(uid => 1, cid => $exp{A}->make_cid());

    xlog $self, "generating email B";
    $exp{B} = $self->make_message("Email B");
    $exp{B}->set_attributes(uid => 2, cid => $exp{B}->make_cid());

    xlog $self, "generating email C referencing A";
    $exp{C} = $self->make_message("Re: Email A", references => [ $exp{A} ]);
    $exp{C}->set_attributes(uid => 3, cid => $exp{A}->get_attribute('cid'));

    $res = $jmap->CallMethods([['Email/query', { collapseThreads => JSON::true }, "R1"]]);
    $self->assert_equals(JSON::true, $res->[0][1]->{collapseThreads});

    $res = $jmap->CallMethods([['Email/query', { collapseThreads => JSON::false }, "R1"]]);
    $self->assert_equals(JSON::false, $res->[0][1]->{collapseThreads});

    $res = $jmap->CallMethods([['Email/query', { collapseThreads => undef }, "R1"]]);
    $self->assert_null($res->[0][1]->{collapseThreads});

    $res = $jmap->CallMethods([['Email/query', { }, "R1"]]);
    $self->assert_equals(JSON::false, $res->[0][1]->{collapseThreads});
}

sub email_query_window_internal
{
    my ($self, $wantGuidSearch, $filter) = @_;
    my %exp;
    my $jmap = $self->{jmap};
    my $res;

    $wantGuidSearch ||= JSON::false;

    my $using = [
        'urn:ietf:params:jmap:core',
        'urn:ietf:params:jmap:mail',
        'urn:ietf:params:jmap:submission',
        'https://cyrusimap.org/ns/jmap/mail',
        'https://cyrusimap.org/ns/jmap/quota',
        'https://cyrusimap.org/ns/jmap/debug',
        'https://cyrusimap.org/ns/jmap/performance',
    ];

    my $imaptalk = $self->{store}->get_client();

    # check IMAP server has the XCONVERSATIONS capability
    $self->assert($self->{store}->get_client()->capability()->{xconversations});

    xlog $self, "generating email A";
    $exp{A} = $self->make_message("Email A");
    $exp{A}->set_attributes(uid => 1, cid => $exp{A}->make_cid());

    xlog $self, "generating email B";
    $exp{B} = $self->make_message("Email B");
    $exp{B}->set_attributes(uid => 2, cid => $exp{B}->make_cid());

    xlog $self, "generating email C referencing A";
    $exp{C} = $self->make_message("Re: Email A", references => [ $exp{A} ]);
    $exp{C}->set_attributes(uid => 3, cid => $exp{A}->get_attribute('cid'));

    xlog $self, "generating email D";
    $exp{D} = $self->make_message("Email D");
    $exp{D}->set_attributes(uid => 2, cid => $exp{B}->make_cid());

    xlog $self, "run squatter";
    $self->{instance}->run_command({cyrus => 1}, 'squatter');

    xlog $self, "list all emails";
    $res = $jmap->CallMethods([['Email/query', {
        calculateTotal => JSON::true,
    }, "R1"]]);
    $self->assert_num_equals(4, scalar @{$res->[0][1]->{ids}});
    $self->assert_num_equals(4, $res->[0][1]->{total});

    my $ids = $res->[0][1]->{ids};
    my @subids;

    xlog $self, "list emails from position 1";
    $res = $jmap->CallMethods([
        ['Email/query', {
            position => 1,
            filter => $filter,
            calculateTotal => JSON::true,
        }, "R1"]
    ], $using);
    $self->assert_equals($wantGuidSearch, $res->[0][1]{performance}{details}{isGuidSearch});
    @subids = @{$ids}[1..3];
    $self->assert_deep_equals(\@subids, $res->[0][1]->{ids});
    $self->assert_num_equals(4, $res->[0][1]->{total});

    xlog $self, "list emails from position 4";
    $res = $jmap->CallMethods([
        ['Email/query', {
            position => 4,
            filter => $filter,
            calculateTotal => JSON::true,
        }, "R1"]
    ], $using);
    $self->assert_equals($wantGuidSearch, $res->[0][1]{performance}{details}{isGuidSearch});
    $self->assert_num_equals(0, scalar @{$res->[0][1]->{ids}});
    $self->assert_num_equals(4, $res->[0][1]->{total});

    xlog $self, "limit emails from position 1 to one email";
    $res = $jmap->CallMethods([
        ['Email/query', {
            position => 1,
            limit => 1,
            filter => $filter,
            calculateTotal => JSON::true,
        }, "R1"]
    ], $using);
    $self->assert_equals($wantGuidSearch, $res->[0][1]{performance}{details}{isGuidSearch});
    @subids = @{$ids}[1..1];
    $self->assert_deep_equals(\@subids, $res->[0][1]->{ids});
    $self->assert_num_equals(4, $res->[0][1]->{total});
    $self->assert_num_equals(1, $res->[0][1]->{position});

    xlog $self, "anchor at 2nd email";
    $res = $jmap->CallMethods([
        ['Email/query', {
            anchor => @{$ids}[1],
            filter => $filter,
            calculateTotal => JSON::true,
        }, "R1"]
    ], $using);
    $self->assert_equals($wantGuidSearch, $res->[0][1]{performance}{details}{isGuidSearch});
    @subids = @{$ids}[1..3];
    $self->assert_deep_equals(\@subids, $res->[0][1]->{ids});
    $self->assert_num_equals(4, $res->[0][1]->{total});
    $self->assert_num_equals(1, $res->[0][1]->{position});

    xlog $self, "anchor at 2nd email and offset 1";
    $res = $jmap->CallMethods([
        ['Email/query', {
            anchor => @{$ids}[1],
            anchorOffset => 1,
            filter => $filter,
            calculateTotal => JSON::true,
        }, "R1"]
    ], $using);
    $self->assert_equals($wantGuidSearch, $res->[0][1]{performance}{details}{isGuidSearch});
    @subids = @{$ids}[2..3];
    $self->assert_deep_equals(\@subids, $res->[0][1]->{ids});
    $self->assert_num_equals(4, $res->[0][1]->{total});
    $self->assert_num_equals(2, $res->[0][1]->{position});

    xlog $self, "anchor at 3rd email and offset -1";
    $res = $jmap->CallMethods([
        ['Email/query', {
            anchor => @{$ids}[2],
            anchorOffset => -1,
            filter => $filter,
            calculateTotal => JSON::true,
        }, "R1"]
    ], $using);
    $self->assert_equals($wantGuidSearch, $res->[0][1]{performance}{details}{isGuidSearch});
    @subids = @{$ids}[1..3];
    $self->assert_deep_equals(\@subids, $res->[0][1]->{ids});
    $self->assert_num_equals(4, $res->[0][1]->{total});
    $self->assert_num_equals(1, $res->[0][1]->{position});

    xlog $self, "anchor at 1st email offset 1 and limit 2";
    $res = $jmap->CallMethods([
        ['Email/query', {
            anchor => @{$ids}[0],
            anchorOffset => 1,
            limit => 2,
            filter => $filter,
            calculateTotal => JSON::true,
        }, "R1"]
    ], $using);
    $self->assert_equals($wantGuidSearch, $res->[0][1]{performance}{details}{isGuidSearch});
    @subids = @{$ids}[1..2];
    $self->assert_deep_equals(\@subids, $res->[0][1]->{ids});
    $self->assert_num_equals(4, $res->[0][1]->{total});
    $self->assert_num_equals(1, $res->[0][1]->{position});
}

sub test_email_query_window
    :min_version_3_1 :needs_component_jmap :JMAPExtensions
{
    my ($self) = @_;
    $self->email_query_window_internal();
}

sub test_email_query_window_cached
    :min_version_3_1 :needs_component_jmap :JMAPQueryCacheMaxAge1s :JMAPExtensions
{
    my ($self) = @_;
    $self->email_query_window_internal();
}

sub test_email_query_window_guidsearch
    :min_version_3_1 :needs_component_jmap :JMAPExtensions
{
    my ($self) = @_;
    $self->email_query_window_internal(JSON::true, { subject => 'Email' });
}

sub test_email_query_long
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my %exp;
    my $jmap = $self->{jmap};
    my $res;

    my $imaptalk = $self->{store}->get_client();

    # check IMAP server has the XCONVERSATIONS capability
    $self->assert($self->{store}->get_client()->capability()->{xconversations});

    for (1..100) {
        $self->make_message("Email $_");
    }

    xlog $self, "list first 60 emails";
    $res = $jmap->CallMethods([['Email/query', {
        limit => 60,
        position => 0,
        collapseThreads => JSON::true,
        sort => [{ property => "id" }],
        calculateTotal => JSON::true,
    }, "R1"]]);
    $self->assert_num_equals(60, scalar @{$res->[0][1]->{ids}});
    $self->assert_num_equals(100, $res->[0][1]->{total});
    $self->assert_num_equals(0, $res->[0][1]->{position});

    xlog $self, "list 5 emails from offset 55 by anchor";
    $res = $jmap->CallMethods([['Email/query', {
        limit => 5,
        anchorOffset => 1,
        anchor => $res->[0][1]->{ids}[55],
        collapseThreads => JSON::true,
        sort => [{ property => "id" }],
        calculateTotal => JSON::true,
    }, "R1"]]);
    $self->assert_num_equals(5, scalar @{$res->[0][1]->{ids}});
    $self->assert_num_equals(100, $res->[0][1]->{total});
    $self->assert_num_equals(56, $res->[0][1]->{position});

    my $ids = $res->[0][1]->{ids};
    my @subids;
}

sub test_email_query_acl
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();

    my $admintalk = $self->{adminstore}->get_client();

    # Create user and share mailbox
    $self->{instance}->create_user("foo");
    $admintalk->setacl("user.foo", "cassandane", "lr") or die;

    xlog $self, "get email list";
    my $res = $jmap->CallMethods([['Email/query', { accountId => 'foo' }, "R1"]]);
    $self->assert_num_equals(0, scalar @{$res->[0][1]->{ids}});

    xlog $self, "Create email in shared account";
    $self->{adminstore}->set_folder('user.foo');
    $self->make_message("Email foo", store => $self->{adminstore}) or die;

    xlog $self, "get email list in main account";
    $res = $jmap->CallMethods([['Email/query', { }, "R1"]]);
    $self->assert_num_equals(0, scalar @{$res->[0][1]->{ids}});

    xlog $self, "get email list in shared account";
    $res = $jmap->CallMethods([['Email/query', { accountId => 'foo' }, "R1"]]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{ids}});
    my $id = $res->[0][1]->{ids}[0];

    xlog $self, "Create email in main account";
    $self->make_message("Email cassandane") or die;

    xlog $self, "get email list in main account";
    $res = $jmap->CallMethods([['Email/query', { }, "R1"]]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{ids}});
    $self->assert_str_not_equals($id, $res->[0][1]->{ids}[0]);

    xlog $self, "get email list in shared account";
    $res = $jmap->CallMethods([['Email/query', { accountId => 'foo' }, "R1"]]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{ids}});
    $self->assert_str_equals($id, $res->[0][1]->{ids}[0]);

    xlog $self, "create but do not share mailbox";
    $admintalk->create("user.foo.box1") or die;
    $admintalk->setacl("user.foo.box1", "cassandane", "") or die;

    xlog $self, "create email in private mailbox";
    $self->{adminstore}->set_folder('user.foo.box1');
    $self->make_message("Email private foo", store => $self->{adminstore}) or die;

    xlog $self, "get email list in shared account";
    $res = $jmap->CallMethods([['Email/query', { accountId => 'foo' }, "R1"]]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{ids}});
    $self->assert_str_equals($id, $res->[0][1]->{ids}[0]);
}

sub test_email_query_unknown_mailbox
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my %exp;
    my $jmap = $self->{jmap};
    my $res;

    my $imaptalk = $self->{store}->get_client();

    xlog $self, "filter inMailbox with unknown mailbox";
    $res = $jmap->CallMethods([['Email/query', { filter => { inMailbox => "foo" } }, "R1"]]);
    $self->assert_str_equals('error', $res->[0][0]);
    $self->assert_str_equals('invalidArguments', $res->[0][1]{type});
    $self->assert_str_equals('filter/inMailbox', $res->[0][1]{arguments}[0]);

    xlog $self, "filter inMailboxOtherThan with unknown mailbox";
    $res = $jmap->CallMethods([['Email/query', { filter => { inMailboxOtherThan => ["foo"] } }, "R1"]]);
    $self->assert_str_equals('error', $res->[0][0]);
    $self->assert_str_equals('invalidArguments', $res->[0][1]{type});
    $self->assert_str_equals('filter/inMailboxOtherThan[0:foo]', $res->[0][1]{arguments}[0]);
}


sub test_searchsnippet_get
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();

    my $res = $jmap->CallMethods([['Mailbox/get', { }, "R1"]]);
    my $inboxid = $res->[0][1]{list}[0]{id};

    xlog $self, "create emails";
    my %params = (
        body => "A simple message",
    );
    $res = $self->make_message("Message foo", %params) || die;

    %params = (
        body => ""
        . "In the context of electronic mail, messages are viewed as having an\r\n"
        . "envelope and contents.  The envelope contains whatever information is\r\n"
        . "needed to accomplish transmission and delivery.  (See [RFC5321] for a\r\n"
        . "discussion of the envelope.)  The contents comprise the object to be\r\n"
        . "delivered to the recipient.  This specification applies only to the\r\n"
        . "format and some of the semantics of message contents.  It contains no\r\n"
        . "specification of the information in the envelope.i\r\n"
        . "\r\n"
        . "However, some message systems may use information from the contents\r\n"
        . "to create the envelope.  It is intended that this specification\r\n"
        . "facilitate the acquisition of such information by programs.\r\n"
        . "\r\n"
        . "This specification is intended as a definition of what message\r\n"
        . "content format is to be passed between systems.  Though some message\r\n"
        . "systems locally store messages in this format (which eliminates the\r\n"
        . "need for translation between formats) and others use formats that\r\n"
        . "differ from the one specified in this specification, local storage is\r\n"
        . "outside of the scope of this specification.\r\n"
        . "\r\n"
        . "This paragraph is not part of the specification, it has been added to\r\n"
        . "contain the most mentions of the word message. Messages are processed\r\n"
        . "by messaging systems, which is the message of this paragraph.\r\n"
        . "Don't interpret too much into this message.\r\n",
    );
    $self->make_message("Message bar", %params) || die;
    %params = (
        body => "This body doesn't contain any of the search terms.\r\n",
    );
    $self->make_message("A subject without any matching search term", %params) || die;

    $self->make_message("Message baz", %params) || die;
    %params = (
        body => "This body doesn't contain any of the search terms.\r\n",
    );
    $self->make_message("A subject with message", %params) || die;

    xlog $self, "run squatter";
    $self->{instance}->run_command({cyrus => 1}, 'squatter');

    xlog $self, "fetch email ids";
    $res = $jmap->CallMethods([
        ['Email/query', { }, "R1"],
        ['Email/get', { '#ids' => { resultOf => 'R1', name => 'Email/query', path => '/ids' } }, 'R2' ],
    ]);

    my %m = map { $_->{subject} => $_ } @{$res->[1][1]{list}};
    my $foo = $m{"Message foo"}->{id};
    my $bar = $m{"Message bar"}->{id};
    my $baz = $m{"Message baz"}->{id};
    $self->assert_not_null($foo);
    $self->assert_not_null($bar);
    $self->assert_not_null($baz);

    xlog $self, "fetch snippets";
    $res = $jmap->CallMethods([['SearchSnippet/get', {
            emailIds => [ $foo, $bar ],
            filter => { text => "message" },
    }, "R1"]]);
    $self->assert_num_equals(2, scalar @{$res->[0][1]->{list}});
    $self->assert_null($res->[0][1]->{notFound});
    %m = map { $_->{emailId} => $_ } @{$res->[0][1]{list}};
    $self->assert_not_null($m{$foo});
    $self->assert_not_null($m{$bar});

    %m = map { $_->{emailId} => $_ } @{$res->[0][1]{list}};
    $self->assert_num_not_equals(-1, index($m{$foo}->{subject}, "<mark>Message</mark> foo"));
    $self->assert_num_not_equals(-1, index($m{$foo}->{preview}, "A simple <mark>message</mark>"));
    $self->assert_num_not_equals(-1, index($m{$bar}->{subject}, "<mark>Message</mark> bar"));
    $self->assert_num_not_equals(-1, index($m{$bar}->{preview}, ""
        . "<mark>Messages</mark> are processed by <mark>messaging</mark> systems,"
    ));

    xlog $self, "fetch snippets with one unknown id";
    $res = $jmap->CallMethods([['SearchSnippet/get', {
            emailIds => [ $foo, "bam" ],
            filter => { text => "message" },
    }, "R1"]]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{list}});
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{notFound}});

    xlog $self, "fetch snippets with only a matching subject";
    $res = $jmap->CallMethods([['SearchSnippet/get', {
            emailIds => [ $baz ],
            filter => { text => "message" },
    }, "R1"]]);
    $self->assert_not_null($res->[0][1]->{list}[0]->{subject});
    $self->assert(exists $res->[0][1]->{list}[0]->{preview});
}

sub test_searchsnippet_get_shared
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();

    my $admintalk = $self->{adminstore}->get_client();

    xlog $self, "create user and share mailboxes";
    $self->{instance}->create_user("foo");
    $admintalk->setacl("user.foo", "cassandane", "lr") or die;
    $admintalk->create("user.foo.box1") or die;
    $admintalk->setacl("user.foo.box1", "cassandane", "lr") or die;

    my $res = $jmap->CallMethods([['Mailbox/get', { accountId => 'foo' }, "R1"]]);
    my $inboxid = $res->[0][1]{list}[0]{id};

    xlog $self, "create emails in shared account";
    $self->{adminstore}->set_folder('user.foo');
    my %params = (
        body => "A simple email",
    );
    $res = $self->make_message("Email foo", %params, store => $self->{adminstore}) || die;
    $self->{adminstore}->set_folder('user.foo.box1');
    %params = (
        body => "Another simple email",
    );
    $res = $self->make_message("Email bar", %params, store => $self->{adminstore}) || die;

    xlog $self, "run squatter";
    $self->{instance}->run_command({cyrus => 1}, 'squatter');

    xlog $self, "fetch email ids";
    $res = $jmap->CallMethods([
        ['Email/query', { accountId => 'foo' }, "R1"],
        ['Email/get', {
            accountId => 'foo',
            '#ids' => { resultOf => 'R1', name => 'Email/query', path => '/ids' }
        }, 'R2' ],
    ]);

    my %m = map { $_->{subject} => $_ } @{$res->[1][1]{list}};
    my $foo = $m{"Email foo"}->{id};
    my $bar = $m{"Email bar"}->{id};
    $self->assert_not_null($foo);
    $self->assert_not_null($bar);

    xlog $self, "remove read rights for mailbox containing email $bar";
    $admintalk->setacl("user.foo.box1", "cassandane", "") or die;

    xlog $self, "fetch snippets";
    $res = $jmap->CallMethods([['SearchSnippet/get', {
            accountId => 'foo',
            emailIds => [ $foo, $bar ],
            filter => { text => "simple" },
    }, "R1"]]);
    $self->assert_str_equals($foo, $res->[0][1]->{list}[0]{emailId});
    $self->assert_str_equals($bar, $res->[0][1]->{notFound}[0]);
}

sub test_email_query_snippets
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my %exp;
    my $jmap = $self->{jmap};
    my $res;

    my $imaptalk = $self->{store}->get_client();

    # check IMAP server has the XCONVERSATIONS capability
    $self->assert($self->{store}->get_client()->capability()->{xconversations});

    xlog $self, "generating email A";
    $exp{A} = $self->make_message("Email A");
    $exp{A}->set_attributes(uid => 1, cid => $exp{A}->make_cid());

    xlog $self, "run squatter";
    $self->{instance}->run_command({cyrus => 1}, 'squatter');

    xlog $self, "fetch email and snippet";
    $res = $jmap->CallMethods([
        ['Email/query', { filter => { text => "email" }}, "R1"],
        ['SearchSnippet/get', {
            '#emailIds' => {
                resultOf => 'R1',
                name => 'Email/query',
                path => '/ids',
            },
            '#filter' => {
                resultOf => 'R1',
                name => 'Email/query',
                path => '/filter',
            },
        }, 'R2'],
    ]);

    my $snippet = $res->[1][1]{list}[0];
    $self->assert_not_null($snippet);
    $self->assert_num_not_equals(-1, index($snippet->{subject}, "<mark>Email</mark> A"));

    xlog $self, "fetch email and snippet with no filter";
    $res = $jmap->CallMethods([
        ['Email/query', { }, "R1"],
        ['SearchSnippet/get', {
            '#emailIds' => {
                resultOf => 'R1',
                name => 'Email/query',
                path => '/ids',
            },
        }, 'R2'],
    ]);
    $snippet = $res->[1][1]{list}[0];
    $self->assert_not_null($snippet);
    $self->assert_null($snippet->{subject});
    $self->assert_null($snippet->{preview});

    xlog $self, "fetch email and snippet with no text filter";
    $res = $jmap->CallMethods([
        ['Email/query', {
            filter => {
                operator => "OR",
                conditions => [{minSize => 1}, {maxSize => 1}]
            },
        }, "R1"],
        ['SearchSnippet/get', {
            '#emailIds' => {
                resultOf => 'R1',
                name => 'Email/query',
                path => '/ids',
            },
            '#filter' => {
                resultOf => 'R1',
                name => 'Email/query',
                path => '/filter',
            },
        }, 'R2'],
    ]);

    $snippet = $res->[1][1]{list}[0];
    $self->assert_not_null($snippet);
    $self->assert_null($snippet->{subject});
    $self->assert_null($snippet->{preview});
}

sub test_email_query_attachments
    :min_version_3_1 :needs_component_jmap :JMAPExtensions
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    xlog $self, "create drafts mailbox";
    my $res = $jmap->CallMethods([
            ['Mailbox/set', { create => { "1" => {
                            name => "drafts",
                            parentId => undef,
                            role => "drafts"
             }}}, "R1"]
    ]);
    $self->assert_str_equals('Mailbox/set', $res->[0][0]);
    $self->assert_str_equals('R1', $res->[0][2]);
    $self->assert_not_null($res->[0][1]{created});
    my $draftsmbox = $res->[0][1]{created}{"1"}{id};

    # create a email with an attachment
    my $logofile = abs_path('data/logo.gif');
    open(FH, "<$logofile");
    local $/ = undef;
    my $binary = <FH>;
    close(FH);
    my $data = $jmap->Upload($binary, "image/gif");

    $res = $jmap->CallMethods([
      ['Email/set', { create => {
                  "1" => {
                      mailboxIds => {$draftsmbox =>  JSON::true},
                      from => [ { name => "Yosemite Sam", email => "sam\@acme.local" } ] ,
                      to => [
                          { name => "Bugs Bunny", email => "bugs\@acme.local" },
                      ],
                      subject => "Memo",
                      textBody => [{ partId => '1' }],
                      bodyValues => {'1' => { value => "I'm givin' ya one last chance ta surrenda!" }},
                      attachments => [{
                              blobId => $data->{blobId},
                              name => "logo.gif",
                      }],
                      keywords => { '$draft' => JSON::true },
                  },
                  "2" => {
                      mailboxIds => {$draftsmbox =>  JSON::true},
                      from => [ { name => "Yosemite Sam", email => "sam\@acme.local" } ] ,
                      to => [
                          { name => "Bugs Bunny", email => "bugs\@acme.local" },
                      ],
                      subject => "Memo 2",
                      textBody => [{ partId => '1' }],
                      bodyValues => {'1' => { value => "I'm givin' ya *one* last chance ta surrenda!" }},
                      attachments => [{
                              blobId => $data->{blobId},
                              name => "somethingelse.gif",
                      }],
                      keywords => { '$draft' => JSON::true },
                  },
  } }, 'R2'],
    ]);
    my $id1 = $res->[0][1]{created}{"1"}{id};
    my $id2 = $res->[0][1]{created}{"2"}{id};

    xlog $self, "run squatter";
    $self->{instance}->run_command({cyrus => 1}, 'squatter');

    my $using = [
        'urn:ietf:params:jmap:core',
        'urn:ietf:params:jmap:mail',
        'urn:ietf:params:jmap:submission',
        'https://cyrusimap.org/ns/jmap/mail',
        'https://cyrusimap.org/ns/jmap/quota',
        'https://cyrusimap.org/ns/jmap/debug',
    ];

    xlog $self, "filter attachmentName";
    $res = $jmap->CallMethods([['Email/query', {
        filter => {
            attachmentName => "logo",
        },
    }, "R1"]], $using);
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{ids}});
    $self->assert_str_equals($id1, $res->[0][1]->{ids}[0]);

    xlog $self, "filter attachmentName";
    $res = $jmap->CallMethods([['Email/query', {
        filter => {
            attachmentName => "somethingelse.gif",
        },
    }, "R1"]], $using);
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{ids}});
    $self->assert_str_equals($id2, $res->[0][1]->{ids}[0]);

    xlog $self, "filter attachmentName";
    $res = $jmap->CallMethods([['Email/query', {
        filter => {
            attachmentName => "gif",
        },
    }, "R1"]], $using);
    $self->assert_num_equals(2, scalar @{$res->[0][1]->{ids}});

    xlog $self, "filter text";
    $res = $jmap->CallMethods([['Email/query', {
        filter => {
            text => "logo",
        },
    }, "R1"]], $using);
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{ids}});
    $self->assert_str_equals($id1, $res->[0][1]->{ids}[0]);
}

sub test_email_query_attachmentname
    :min_version_3_1 :needs_component_jmap :JMAPExtensions
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    xlog $self, "create drafts mailbox";
    my $res = $jmap->CallMethods([
            ['Mailbox/set', { create => { "1" => {
                            name => "drafts",
                            parentId => undef,
                            role => "drafts"
             }}}, "R1"]
    ]);
    $self->assert_str_equals('Mailbox/set', $res->[0][0]);
    $self->assert_str_equals('R1', $res->[0][2]);
    $self->assert_not_null($res->[0][1]{created});
    my $draftsmbox = $res->[0][1]{created}{"1"}{id};

    # create a email with an attachment
    my $logofile = abs_path('data/logo.gif');
    open(FH, "<$logofile");
    local $/ = undef;
    my $binary = <FH>;
    close(FH);
    my $data = $jmap->Upload($binary, "image/gif");

    $res = $jmap->CallMethods([
      ['Email/set', { create => {
                  "1" => {
                      mailboxIds => {$draftsmbox =>  JSON::true},
                      from => [ { name => "", email => "sam\@acme.local" } ] ,
                      to => [ { name => "", email => "bugs\@acme.local" } ],
                      subject => "msg1",
                      textBody => [{ partId => '1' }],
                      bodyValues => { '1' => { value => "foo" } },
                      attachments => [{
                              blobId => $data->{blobId},
                              name => "R\N{LATIN SMALL LETTER U WITH DIAERESIS}bezahl.txt",
                      }],
                      keywords => { '$draft' => JSON::true },
                  },
              }}, 'R2'],
    ]);
    my $id1 = $res->[0][1]{created}{"1"}{id};

    xlog $self, "run squatter";
    $self->{instance}->run_command({cyrus => 1}, 'squatter');

    my $using = [
        'urn:ietf:params:jmap:core',
        'urn:ietf:params:jmap:mail',
        'urn:ietf:params:jmap:submission',
        'https://cyrusimap.org/ns/jmap/mail',
        'https://cyrusimap.org/ns/jmap/quota',
        'https://cyrusimap.org/ns/jmap/debug',
    ];

    xlog $self, "filter attachmentName";
    $res = $jmap->CallMethods([['Email/query', {
        filter => {
            attachmentName => "r\N{LATIN SMALL LETTER U WITH DIAERESIS}bezahl",
        },
    }, "R1"]], $using);
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{ids}});
    $self->assert_str_equals($id1, $res->[0][1]->{ids}[0]);
}

sub test_email_query_attachmenttype_legacy
    :min_version_3_1 :max_version_3_4 :needs_component_jmap :JMAPExtensions
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $blobId = $jmap->Upload('some_data', "application/octet")->{blobId};

    my $inboxid = $self->getinbox()->{id};

    my $res = $jmap->CallMethods([
      ['Email/set', { create => {
        "1" => {
          mailboxIds => {$inboxid => JSON::true},
          from => [ { name => "", email => "sam\@acme.local" } ] ,
          to => [ { name => "", email => "bugs\@acme.local" } ],
          subject => "foo",
          textBody => [{ partId => '1' }],
          bodyValues => { '1' => { value => "foo" } },
          attachments => [{
            blobId => $blobId,
            type => 'image/gif',
          }],
      },
      "2" => {
          mailboxIds => {$inboxid => JSON::true},
          from => [ { name => "", email => "tweety\@acme.local" } ] ,
          to => [ { name => "", email => "duffy\@acme.local" } ],
          subject => "bar",
          textBody => [{ partId => '1' }],
          bodyValues => { '1' => { value => "bar" } },
      },
      "3" => {
          mailboxIds => {$inboxid => JSON::true},
          from => [ { name => "", email => "elmer\@acme.local" } ] ,
          to => [ { name => "", email => "porky\@acme.local" } ],
          subject => "baz",
          textBody => [{ partId => '1' }],
          bodyValues => { '1' => { value => "baz" } },
          attachments => [{
            blobId => $blobId,
            type => 'application/msword',
          }],
      },
      "4" => {
          mailboxIds => {$inboxid => JSON::true},
          from => [ { name => "", email => "elmer\@acme.local" } ] ,
          to => [ { name => "", email => "porky\@acme.local" } ],
          subject => "baz",
          textBody => [{ partId => '1' }],
          bodyValues => { '1' => { value => "baz" } },
          attachments => [{
            blobId => $blobId,
            type => 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
          }],
      },
      }}, 'R1']
    ]);
    my $idGif = $res->[0][1]{created}{"1"}{id};
    my $idTxt = $res->[0][1]{created}{"2"}{id};
    my $idDoc = $res->[0][1]{created}{"3"}{id};
    my $idWord = $res->[0][1]{created}{"4"}{id};
    $self->assert_not_null($idGif);
    $self->assert_not_null($idTxt);
    $self->assert_not_null($idDoc);
    $self->assert_not_null($idWord);

    xlog $self, "run squatter";
    $self->{instance}->run_command({cyrus => 1}, 'squatter');

    my @testCases = ({
        filter => {
            attachmentType => 'image/gif',
        },
        wantIds => [$idGif],
    }, {
        filter => {
            attachmentType => 'image',
        },
        wantIds => [$idGif],
    }, {
        filter => {
            attachmentType => 'application/msword',
        },
        wantIds => [$idDoc],
    }, {
        filter => {
            # this should be application/vnd... but Xapian has a 64 character limit on terms
            # indexed, so application_vndopenxmlformatsofficedocumentwordprocessingmldocument
            # never got indexed
            attachmentType => 'vnd.openxmlformats-officedocument.wordprocessingml.document',
        },
        wantIds => [$idWord],
    }, {
        filter => {
            attachmentType => 'document',
        },
        wantIds => [$idDoc, $idWord],
    });

    my $using = [
        'urn:ietf:params:jmap:core',
        'urn:ietf:params:jmap:mail',
        'urn:ietf:params:jmap:submission',
        'https://cyrusimap.org/ns/jmap/mail',
        'https://cyrusimap.org/ns/jmap/quota',
        'https://cyrusimap.org/ns/jmap/debug',
    ];

    foreach (@testCases) {
        my $filter = $_->{filter};
        my $wantIds = $_->{wantIds};
        $res = $jmap->CallMethods([['Email/query', {
            filter => $filter,
        }, "R1"]], $using);
        my @wantIds = sort @{$wantIds};
        my @gotIds = sort @{$res->[0][1]->{ids}};
        $self->assert_deep_equals(\@wantIds, \@gotIds);
    }
}

sub test_email_query_attachmenttype
    :min_version_3_5 :needs_component_jmap :JMAPExtensions
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $blobId = $jmap->Upload('some_data', "application/octet")->{blobId};

    my $rfc822Msg = <<'EOF';
From: "Some Example Sender" <example@example.com>
To: baseball@vitaead.com
Subject: test email
Date: Wed, 7 Dec 2016 00:21:50 -0500
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

This is a test email.
EOF
    $rfc822Msg =~ s/\r?\n/\r\n/gs;
    my $rfc822MsgBlobId = $jmap->Upload($rfc822Msg, "message/rfc822")->{blobId};
    $self->assert_not_null($rfc822MsgBlobId);

    my $inboxid = $self->getinbox()->{id};

    my $res = $jmap->CallMethods([
      ['Email/set', { create => {
        "1" => {
          mailboxIds => {$inboxid => JSON::true},
          from => [ { name => "", email => "sam\@acme.local" } ] ,
          to => [ { name => "", email => "bugs\@acme.local" } ],
          subject => "foo",
          textBody => [{ partId => '1' }],
          bodyValues => { '1' => { value => "foo" } },
          attachments => [{
            blobId => $blobId,
            type => 'image/gif',
          }],
      },
      "2" => {
          mailboxIds => {$inboxid => JSON::true},
          from => [ { name => "", email => "tweety\@acme.local" } ] ,
          to => [ { name => "", email => "duffy\@acme.local" } ],
          subject => "bar",
          textBody => [{ partId => '1' }],
          bodyValues => { '1' => { value => "bar" } },
      },
      "3" => {
          mailboxIds => {$inboxid => JSON::true},
          from => [ { name => "", email => "elmer\@acme.local" } ] ,
          to => [ { name => "", email => "porky\@acme.local" } ],
          subject => "baz",
          textBody => [{ partId => '1' }],
          bodyValues => { '1' => { value => "baz" } },
          attachments => [{
            blobId => $blobId,
            type => 'application/msword',
          }],
      },
      "4" => {
          mailboxIds => {$inboxid => JSON::true},
          from => [ { name => "", email => "elmer\@acme.local" } ] ,
          to => [ { name => "", email => "porky\@acme.local" } ],
          subject => "baz",
          textBody => [{ partId => '1' }],
          bodyValues => { '1' => { value => "baz" } },
          attachments => [{
            blobId => $blobId,
            type => 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
          }],
      },
      "5" => {
          mailboxIds => {$inboxid => JSON::true},
          from => [ { name => "", email => "elmer\@acme.local" } ] ,
          to => [ { name => "", email => "porky\@acme.local" } ],
          subject => "embeddedmsg",
          bodyStructure => {
              subParts => [{
                      partId => "text",
                      type => "text/plain"
                  },{
                      blobId => $rfc822MsgBlobId,
                      disposition => "attachment",
                      type => "message/rfc822"
                  }],
              type => "multipart/mixed",
          },
          bodyValues => {
              text => {
                  value => "Hello World",
              },
          },
      }
      }}, 'R1']
    ]);
    my $idGif = $res->[0][1]{created}{"1"}{id};
    my $idTxt = $res->[0][1]{created}{"2"}{id};
    my $idDoc = $res->[0][1]{created}{"3"}{id};
    my $idWord = $res->[0][1]{created}{"4"}{id};
    my $idRfc822Msg = $res->[0][1]{created}{"5"}{id};
    $self->assert_not_null($idGif);
    $self->assert_not_null($idTxt);
    $self->assert_not_null($idDoc);
    $self->assert_not_null($idWord);

    xlog $self, "run squatter";
    $self->{instance}->run_command({cyrus => 1}, 'squatter');

    my @testCases = ({
        filter => {
            attachmentType => 'image/gif',
        },
        wantIds => [$idGif],
    }, {
        filter => {
            attachmentType => 'image',
        },
        wantIds => [$idGif],
    }, {
        filter => {
            attachmentType => 'application/msword',
        },
        wantIds => [$idDoc],
    }, {
        filter => {
            # this should be application/vnd... but Xapian has a 64 character limit on terms
            # indexed, so application_vndopenxmlformatsofficedocumentwordprocessingmldocument
            # never got indexed
            attachmentType => 'vnd.openxmlformats-officedocument.wordprocessingml.document',
        },
        wantIds => [$idWord],
    }, {
        filter => {
            attachmentType => 'document',
        },
        wantIds => [$idDoc, $idWord],
    }, {
        filter => {
            operator => 'NOT',
            conditions => [{
                attachmentType => 'image',
            }, {
                attachmentType => 'document',
            }],
        },
        wantIds => [$idTxt, $idRfc822Msg],
    }, {
        filter => {
            attachmentType => 'email',
        },
        wantIds => [$idRfc822Msg],
    });

    my $using = [
        'urn:ietf:params:jmap:core',
        'urn:ietf:params:jmap:mail',
        'urn:ietf:params:jmap:submission',
        'https://cyrusimap.org/ns/jmap/mail',
        'https://cyrusimap.org/ns/jmap/quota',
        'https://cyrusimap.org/ns/jmap/debug',
    ];

    foreach (@testCases) {
        my $filter = $_->{filter};
        my $wantIds = $_->{wantIds};
        $res = $jmap->CallMethods([['Email/query', {
            filter => $filter,
        }, "R1"]], $using);
        my @wantIds = sort @{$wantIds};
        my @gotIds = sort @{$res->[0][1]->{ids}};
        $self->assert_deep_equals(\@wantIds, \@gotIds);
    }
}

sub test_email_query_attachmenttype_wildcards
    :min_version_3_3 :needs_component_jmap :JMAPExtensions
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $imap = $self->{store}->get_client();

    $self->make_message("msg1",
        mime_type => "multipart/mixed",
        mime_boundary => "123456789",
        body => ""
          . "--123456789\r\n"
          . "Content-Type: text/plain\r\n"
          . "msg1"
          . "\r\n--123456789\r\n"
          . "Content-Type: application/rtf\r\n"
          . "\r\n"
          . "data"
          . "\r\n--123456789--\r\n",
    );

    $self->make_message("msg2",
        mime_type => "multipart/mixed",
        mime_boundary => "123456789",
        body => ""
          . "--123456789\r\n"
          . "Content-Type: text/plain\r\n"
          . "msg1"
          . "\r\n--123456789\r\n"
          . "Content-Type: text/rtf\r\n"
          . "\r\n"
          . "data"
          . "\r\n--123456789--\r\n",
    );

    xlog $self, "run squatter";
    $self->{instance}->run_command({cyrus => 1}, 'squatter');

    my $using = [
        'urn:ietf:params:jmap:core',
        'urn:ietf:params:jmap:mail',
        'urn:ietf:params:jmap:submission',
        'https://cyrusimap.org/ns/jmap/mail',
        'https://cyrusimap.org/ns/jmap/debug',
        'https://cyrusimap.org/ns/jmap/performance',
    ];

    my $res = $jmap->CallMethods([
        ['Email/query', { }, 'R1'],
        ['Email/get', {
            '#ids' => {
                resultOf => 'R1',
                name => 'Email/query',
                path => '/ids'
            },
            properties => [ 'subject' ],
        }, 'R2'],
    ]);
    $self->assert_num_equals(2, scalar @{$res->[1][1]{list}});
    my %emails = map { $_->{subject} => $_->{id} } @{$res->[1][1]{list}};

    my @tests = ({
        filter => {
            attachmentType => 'text/plain',
        },
        wantIds => [ $emails{'msg1'}, $emails{'msg2'} ],
    }, {
        filter => {
            attachmentType => 'application/rtf',
        },
        wantIds => [ $emails{'msg1'} ],
    }, {
        filter => {
            attachmentType => 'text/rtf',
        },
        wantIds => [ $emails{'msg2'} ],
    }, {
        filter => {
            attachmentType => 'text',
        },
        wantIds => [ $emails{'msg1'}, $emails{'msg2'} ],
    }, {
        filter => {
            attachmentType => 'application',
        },
        wantIds => [ $emails{'msg1'} ],
    }, {
        filter => {
            attachmentType => 'plain',
        },
        wantIds => [ $emails{'msg1'}, $emails{'msg2'} ],
    }, {
        filter => {
            attachmentType => 'rtf',
        },
        wantIds => [ $emails{'msg1'}, $emails{'msg2'} ],
    }, {
        filter => {
            attachmentType => 'application/*',
        },
        wantIds => [ $emails{'msg1'} ],
    }, {
        filter => {
            attachmentType => '*/rtf',
        },
        wantIds => [ $emails{'msg1'}, $emails{'msg2'} ],
    });

    foreach (@tests) {
        my $res = $jmap->CallMethods([
            ['Email/query', {
                filter => $_->{filter},
            }, 'R1'],
        ], $using);
        my @gotIds = sort @{$res->[0][1]->{ids}};
        my @wantIds = sort @{$_->{wantIds}};
        $self->assert_deep_equals(\@wantIds, \@gotIds);
    }
}



sub test_thread_get
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my %exp;
    my $jmap = $self->{jmap};
    my $res;
    my %params;
    my $dt;

    my $imaptalk = $self->{store}->get_client();

    xlog $self, "create drafts mailbox";
    $res = $jmap->CallMethods([
            ['Mailbox/set', { create => { "1" => {
                            name => "drafts",
                            parentId => undef,
                            role => "drafts"
             }}}, "R1"]
    ]);
    my $drafts = $res->[0][1]{created}{"1"}{id};
    $self->assert_not_null($drafts);

    xlog $self, "generating email A";
    $dt = DateTime->now();
    $dt->add(DateTime::Duration->new(hours => -3));
    $exp{A} = $self->make_message("Email A", date => $dt, body => "a");
    $exp{A}->set_attributes(uid => 1, cid => $exp{A}->make_cid());

    xlog $self, "generating email B";
    $exp{B} = $self->make_message("Email B", body => "b");
    $exp{B}->set_attributes(uid => 2, cid => $exp{B}->make_cid());

    xlog $self, "generating email C referencing A";
    $dt = DateTime->now();
    $dt->add(DateTime::Duration->new(hours => -2));
    $exp{C} = $self->make_message("Re: Email A", references => [ $exp{A} ], date => $dt, body => "c");
    $exp{C}->set_attributes(uid => 3, cid => $exp{A}->get_attribute('cid'));

    xlog $self, "generating email D referencing A";
    $dt = DateTime->now();
    $dt->add(DateTime::Duration->new(hours => -1));
    $exp{D} = $self->make_message("Re: Email A", references => [ $exp{A} ], date => $dt, body => "d");
    $exp{D}->set_attributes(uid => 4, cid => $exp{A}->get_attribute('cid'));

    xlog $self, "fetch emails";
    $res = $jmap->CallMethods([
        ['Email/query', { }, "R1"],
        ['Email/get', {
            '#ids' => {
                resultOf => 'R1',
                name => 'Email/query',
                path => '/ids'
            },
            fetchAllBodyValues => JSON::true,
        }, 'R2' ],
    ]);

    # Map messages by body contents
    my %m = map { $_->{bodyValues}{$_->{textBody}[0]{partId}}{value} => $_ } @{$res->[1][1]{list}};
    my $msgA = $m{"a"};
    my $msgB = $m{"b"};
    my $msgC = $m{"c"};
    my $msgD = $m{"d"};
    $self->assert_not_null($msgA);
    $self->assert_not_null($msgB);
    $self->assert_not_null($msgC);
    $self->assert_not_null($msgD);

    %m = map { $_->{threadId} => 1 } @{$res->[1][1]{list}};
    my @threadids = keys %m;

    xlog $self, "create draft replying to email A";
    $res = $jmap->CallMethods(
        [[ 'Email/set', { create => { "1" => {
            mailboxIds           => {$drafts =>  JSON::true},
            inReplyTo            => $msgA->{messageId},
            from                 => [ { name => "", email => "sam\@acme.local" } ],
            to                   => [ { name => "", email => "bugs\@acme.local" } ],
            subject              => "Re: Email A",
            textBody             => [{ partId => '1' }],
            bodyValues           => { 1 => { value => "I'm givin' ya one last chance ta surrenda!" }},
            keywords             => { '$draft' => JSON::true },
        }}}, "R1" ]]);
    my $draftid = $res->[0][1]{created}{"1"}{id};
    $self->assert_not_null($draftid);

    xlog $self, "get threads";
    $res = $jmap->CallMethods([['Thread/get', { ids => \@threadids }, "R1"]]);
    $self->assert_num_equals(2, scalar @{$res->[0][1]->{list}});
    $self->assert_deep_equals([], $res->[0][1]->{notFound});

    %m = map { $_->{id} => $_ } @{$res->[0][1]{list}};
    my $threadA = $m{$msgA->{threadId}};
    my $threadB = $m{$msgB->{threadId}};

    # Assert all emails are listed
    $self->assert_num_equals(4, scalar @{$threadA->{emailIds}});
    $self->assert_num_equals(1, scalar @{$threadB->{emailIds}});

    # Assert sort order by date
    $self->assert_str_equals($msgA->{id}, $threadA->{emailIds}[0]);
    $self->assert_str_equals($msgC->{id}, $threadA->{emailIds}[1]);
    $self->assert_str_equals($msgD->{id}, $threadA->{emailIds}[2]);
    $self->assert_str_equals($draftid, $threadA->{emailIds}[3]);
}

sub test_thread_get_shared
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();

    my $admintalk = $self->{adminstore}->get_client();

    # Create user and share mailbox A but not B
    xlog $self, "Create shared mailbox";
    $self->{instance}->create_user("other");
    $admintalk->create("user.other.A") or die;
    $admintalk->setacl("user.other.A", "cassandane", "lr") or die;
    $admintalk->create("user.other.B") or die;

    # Create message in mailbox A
    $self->{adminstore}->set_folder('user.other.A');
    my $msg1 = $self->make_message("EmailA", store => $self->{adminstore}) or die;

    # move the message to mailbox B
    $admintalk->select("user.other.A");
    $admintalk->move("1:*", "user.other.B");

    # Reply-to message in mailbox A
    $self->{adminstore}->set_folder('user.other.A');
    my $msg2 = $self->make_message("Re: EmailA", (
        references => [ $msg1 ],
        store => $self->{adminstore},
    )) or die;

    my @fetchThreadMethods = [
        ['Email/query', {
            accountId => 'other',
            collapseThreads => JSON::true,
        }, "R1"],
        ['Email/get', {
            accountId => 'other',
            properties => ['threadId'],
            '#ids' => {
                resultOf => 'R1',
                name => 'Email/query',
                path => '/ids'
            },
            fetchAllBodyValues => JSON::true,
        }, 'R2' ],
        ['Thread/get', {
            accountId => 'other',
            '#ids' => {
                resultOf => 'R2',
                name => 'Email/get',
                path => '/list/*/threadId'
            },
        }, 'R3' ],
    ];

    # Fetch Thread
    my $res = $jmap->CallMethods(@fetchThreadMethods);
    $self->assert_num_equals(1, scalar @{$res->[1][1]{list}});
    $self->assert_num_equals(1, scalar @{$res->[2][1]{list}[0]{emailIds}});

    # Now share mailbox B
    $admintalk->setacl("user.other.B", "cassandane", "lr") or die;
    $res = $jmap->CallMethods(@fetchThreadMethods);
    $self->assert_num_equals(1, scalar @{$res->[1][1]{list}});
    $self->assert_num_equals(2, scalar @{$res->[2][1]{list}[0]{emailIds}});
}

sub test_identity_get
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $id;
    my $res;

    # Make sure it's in the correct JMAP capability, as reported in
    # https://github.com/cyrusimap/cyrus-imapd/issues/2912
    my $using = [
        'urn:ietf:params:jmap:core',
        'urn:ietf:params:jmap:submission',
    ];

    xlog $self, "get identities";
    $res = $jmap->CallMethods([['Identity/get', { }, "R1"]], $using);

    $self->assert_num_equals(1, scalar @{$res->[0][1]->{list}});
    $self->assert_num_equals(0, scalar @{$res->[0][1]->{notFound}});

    $id = $res->[0][1]->{list}[0];
    $self->assert_not_null($id->{id});
    $self->assert_not_null($id->{email});

    xlog $self, "get unknown identities";
    $res = $jmap->CallMethods([['Identity/get', { ids => ["foo"] }, "R1"]], $using);
    $self->assert_num_equals(0, scalar @{$res->[0][1]->{list}});
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{notFound}});
}

sub test_misc_emptyids
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $imaptalk = $self->{store}->get_client();
    my $res;

    $imaptalk->create("INBOX.foo") || die;

    $res = $jmap->CallMethods([['Mailbox/get', { ids => [] }, "R1"]]);
    $self->assert_num_equals(0, scalar @{$res->[0][1]{list}});

    $res = $jmap->CallMethods([['Thread/get', { ids => [] }, "R1"]]);
    $self->assert_num_equals(0, scalar @{$res->[0][1]{list}});

    $res = $jmap->CallMethods([['Email/get', { ids => [] }, "R1"]]);
    $self->assert_num_equals(0, scalar @{$res->[0][1]{list}});

    $res = $jmap->CallMethods([['Identity/get', { ids => [] }, "R1"]]);
    $self->assert_num_equals(0, scalar @{$res->[0][1]{list}});

    $res = $jmap->CallMethods([['SearchSnippet/get', { emailIds => [], filter => { text => "foo" } }, "R1"]]);
    $self->assert_num_equals(0, scalar @{$res->[0][1]{list}});
}

sub test_email_querychanges_basic
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $res;
    my $state;

    my $store = $self->{store};
    my $talk = $store->get_client();
    my $draftsmbox;

    xlog $self, "Generate some email in INBOX via IMAP";
    $self->make_message("Email A") || die;
    $self->make_message("Email B") || die;
    $self->make_message("Email C") || die;
    $self->make_message("Email D") || die;

    $res = $jmap->CallMethods([['Email/query', {
        sort => [
         {
           property =>  "subject",
           isAscending => $JSON::true,
         }
        ],
    }, 'R1']]);

    $talk->select("INBOX");
    $talk->store("3", "+flags", "(\\Flagged)");

    my $old = $res->[0][1];

    $res = $jmap->CallMethods([['Email/queryChanges', {
        sort => [
         {
           property =>  "subject",
           isAscending => $JSON::true,
         }
        ],
        sinceQueryState => $old->{queryState},
    }, 'R2']]);

    my $new = $res->[0][1];
    $self->assert_str_equals($old->{queryState}, $new->{oldQueryState});
    $self->assert_str_not_equals($old->{queryState}, $new->{newQueryState});
    $self->assert_num_equals(1, scalar @{$new->{added}});
    $self->assert_num_equals(1, scalar @{$new->{removed}});
    $self->assert_str_equals($new->{removed}[0], $new->{added}[0]{id});
    $self->assert_str_equals($new->{removed}[0], $old->{ids}[$new->{added}[0]{index}]);
}

sub test_email_querychanges_basic_collapse
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $res;
    my $state;

    my $store = $self->{store};
    my $talk = $store->get_client();
    my $draftsmbox;

    xlog $self, "Generate some email in INBOX via IMAP";
    $self->make_message("Email A") || die;
    $self->make_message("Email B") || die;
    $self->make_message("Email C") || die;
    $self->make_message("Email D") || die;

    $res = $jmap->CallMethods([['Email/query', {
        sort => [
         {
           property =>  "subject",
           isAscending => $JSON::true,
         }
        ],
        collapseThreads => $JSON::true,
    }, 'R1']]);

    $talk->select("INBOX");
    $talk->store("3", "+flags", "(\\Flagged)");

    my $old = $res->[0][1];

    $res = $jmap->CallMethods([['Email/queryChanges', {
        sort => [
         {
           property =>  "subject",
           isAscending => $JSON::true,
         }
        ],
        collapseThreads => $JSON::true,
        sinceQueryState => $old->{queryState},
    }, 'R2']]);

    my $new = $res->[0][1];
    $self->assert_str_equals($old->{queryState}, $new->{oldQueryState});
    $self->assert_str_not_equals($old->{queryState}, $new->{newQueryState});
    $self->assert_num_equals(1, scalar @{$new->{added}});
    $self->assert_num_equals(1, scalar @{$new->{removed}});
    $self->assert_str_equals($new->{removed}[0], $new->{added}[0]{id});
    $self->assert_str_equals($new->{removed}[0], $old->{ids}[$new->{added}[0]{index}]);
}

sub test_email_querychanges_basic_mb
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $res;
    my $state;

    my $store = $self->{store};
    my $talk = $store->get_client();
    my $inboxid = $self->getinbox()->{id};

    xlog $self, "Generate some email in INBOX via IMAP";
    $self->make_message("Email A") || die;
    $self->make_message("Email B") || die;
    $self->make_message("Email C") || die;
    $self->make_message("Email D") || die;

    $res = $jmap->CallMethods([['Email/query', {
        sort => [
         {
           property =>  "subject",
           isAscending => $JSON::true,
         }
        ],
        filter => { inMailbox => $inboxid },
    }, 'R1']]);

    $talk->select("INBOX");
    $talk->store("3", "+flags", "(\\Flagged)");

    my $old = $res->[0][1];

    $res = $jmap->CallMethods([['Email/queryChanges', {
        sort => [
         {
           property =>  "subject",
           isAscending => $JSON::true,
         }
        ],
        filter => { inMailbox => $inboxid },
        sinceQueryState => $old->{queryState},
    }, 'R2']]);

    my $new = $res->[0][1];
    $self->assert_str_equals($old->{queryState}, $new->{oldQueryState});
    $self->assert_str_not_equals($old->{queryState}, $new->{newQueryState});
    $self->assert_num_equals(1, scalar @{$new->{added}});
    $self->assert_num_equals(1, scalar @{$new->{removed}});
    $self->assert_str_equals($new->{removed}[0], $new->{added}[0]{id});
    $self->assert_str_equals($new->{removed}[0], $old->{ids}[$new->{added}[0]{index}]);
}

sub test_email_querychanges_basic_mb_collapse
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $res;
    my $state;

    my $store = $self->{store};
    my $talk = $store->get_client();
    my $inboxid = $self->getinbox()->{id};

    xlog $self, "Generate some email in INBOX via IMAP";
    $self->make_message("Email A") || die;
    $self->make_message("Email B") || die;
    $self->make_message("Email C") || die;
    $self->make_message("Email D") || die;

    $res = $jmap->CallMethods([['Email/query', {
        sort => [
         {
           property =>  "subject",
           isAscending => $JSON::true,
         }
        ],
        filter => { inMailbox => $inboxid },
        collapseThreads => $JSON::true,
    }, 'R1']]);

    $talk->select("INBOX");
    $talk->store("3", "+flags", "(\\Flagged)");
    $self->assert_equals(JSON::true, $res->[0][1]{canCalculateChanges});

    my $old = $res->[0][1];

    $res = $jmap->CallMethods([['Email/queryChanges', {
        sort => [
         {
           property =>  "subject",
           isAscending => $JSON::true,
         }
        ],
        filter => { inMailbox => $inboxid },
        collapseThreads => $JSON::true,
        sinceQueryState => $old->{queryState},
        ##upToId => $old->{ids}[3],
    }, 'R2']]);

    my $new = $res->[0][1];
    $self->assert_str_equals($old->{queryState}, $new->{oldQueryState});
    $self->assert_str_not_equals($old->{queryState}, $new->{newQueryState});
    # with collased threads we have to check
    $self->assert_num_equals(1, scalar @{$new->{added}});
    $self->assert_num_equals(1, scalar @{$new->{removed}});
    $self->assert_str_equals($new->{removed}[0], $new->{added}[0]{id});
    $self->assert_str_equals($new->{removed}[0], $old->{ids}[$new->{added}[0]{index}]);

    xlog $self, "now with upto past";
    $res = $jmap->CallMethods([['Email/queryChanges', {
        sort => [
         {
           property =>  "subject",
           isAscending => $JSON::true,
         }
        ],
        filter => { inMailbox => $inboxid },
        collapseThreads => $JSON::true,
        sinceQueryState => $old->{queryState},
        upToId => $old->{ids}[3],
    }, 'R2']]);

    $new = $res->[0][1];
    $self->assert_str_equals($old->{queryState}, $new->{oldQueryState});
    $self->assert_str_not_equals($old->{queryState}, $new->{newQueryState});
    $self->assert_num_equals(1, scalar @{$new->{added}});
    $self->assert_num_equals(1, scalar @{$new->{removed}});
    $self->assert_str_equals($new->{removed}[0], $new->{added}[0]{id});
    $self->assert_str_equals($new->{removed}[0], $old->{ids}[$new->{added}[0]{index}]);

    xlog $self, "now with upto equal";
    $res = $jmap->CallMethods([['Email/queryChanges', {
        sort => [
         {
           property =>  "subject",
           isAscending => $JSON::true,
         }
        ],
        filter => { inMailbox => $inboxid },
        collapseThreads => $JSON::true,
        sinceQueryState => $old->{queryState},
        upToId => $old->{ids}[2],
    }, 'R2']]);

    $new = $res->[0][1];
    $self->assert_str_equals($old->{queryState}, $new->{oldQueryState});
    $self->assert_str_not_equals($old->{queryState}, $new->{newQueryState});
    $self->assert_num_equals(1, scalar @{$new->{added}});
    $self->assert_num_equals(1, scalar @{$new->{removed}});
    $self->assert_str_equals($new->{removed}[0], $new->{added}[0]{id});
    $self->assert_str_equals($new->{removed}[0], $old->{ids}[$new->{added}[0]{index}]);

    xlog $self, "now with upto early";
    $res = $jmap->CallMethods([['Email/queryChanges', {
        sort => [
         {
           property =>  "subject",
           isAscending => $JSON::true,
         }
        ],
        filter => { inMailbox => $inboxid },
        collapseThreads => $JSON::true,
        sinceQueryState => $old->{queryState},
        upToId => $old->{ids}[1],
    }, 'R2']]);

    $new = $res->[0][1];
    $self->assert_str_equals($old->{queryState}, $new->{oldQueryState});
    $self->assert_str_not_equals($old->{queryState}, $new->{newQueryState});
    $self->assert_num_equals(0, scalar @{$new->{added}});
    $self->assert_num_equals(0, scalar @{$new->{removed}});
}

sub test_email_querychanges_skipdeleted
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $res;
    my $state;

    my $store = $self->{store};
    my $talk = $store->get_client();
    my $inboxid = $self->getinbox()->{id};

    xlog $self, "Generate some email in INBOX via IMAP";
    $self->make_message("Email A") || die;
    $self->make_message("Email B") || die;
    $self->make_message("Email C") || die;
    $self->make_message("Email D") || die;

    $talk->create("INBOX.foo");
    $talk->select("INBOX");
    $talk->move("1:2", "INBOX.foo");
    $talk->select("INBOX.foo");
    $talk->move("1:2", "INBOX");

    $res = $jmap->CallMethods([['Email/query', {
        sort => [
         {
           property =>  "subject",
           isAscending => $JSON::true,
         }
        ],
        filter => { inMailbox => $inboxid },
        collapseThreads => $JSON::true,
    }, 'R1']]);

    my $old = $res->[0][1];

    $talk->select("INBOX");
    $talk->store("1", "+flags", "(\\Flagged)");

    $res = $jmap->CallMethods([['Email/queryChanges', {
        sort => [
         {
           property =>  "subject",
           isAscending => $JSON::true,
         }
        ],
        filter => { inMailbox => $inboxid },
        collapseThreads => $JSON::true,
        sinceQueryState => $old->{queryState},
    }, 'R2']]);

    my $new = $res->[0][1];
    $self->assert_str_equals($old->{queryState}, $new->{oldQueryState});
    $self->assert_str_not_equals($old->{queryState}, $new->{newQueryState});
    # with collased threads we have to check
    $self->assert_num_equals(1, scalar @{$new->{added}});
    $self->assert_num_equals(1, scalar @{$new->{removed}});
    $self->assert_str_equals($new->{removed}[0], $new->{added}[0]{id});
    $self->assert_str_equals($new->{removed}[0], $old->{ids}[$new->{added}[0]{index}]);
}

sub test_email_querychanges_deletedcopy
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $res;
    my $state;

    my $store = $self->{store};
    my $talk = $store->get_client();
    my $inboxid = $self->getinbox()->{id};

    xlog $self, "Generate some email in INBOX via IMAP";
    $self->make_message("Email A") || die;
    $self->make_message("Email B") || die;
    $self->make_message("Email C") || die;
    $self->make_message("Email D") || die;

    $res = $jmap->CallMethods([['Email/query', {
        sort => [
         {
           property =>  "subject",
           isAscending => $JSON::true,
         }
        ],
        filter => { inMailbox => $inboxid },
        collapseThreads => $JSON::true,
    }, 'R1']]);

    $talk->create("INBOX.foo");
    $talk->select("INBOX");
    $talk->move("2", "INBOX.foo");
    $talk->select("INBOX.foo");
    $talk->move("1", "INBOX");
    $talk->select("INBOX");
    $talk->store("2", "+flags", "(\\Flagged)");

    # order is now A (B) C D B, and (B), C and B are "changed"

    my $old = $res->[0][1];

    $res = $jmap->CallMethods([['Email/queryChanges', {
        sort => [
         {
           property =>  "subject",
           isAscending => $JSON::true,
         }
        ],
        filter => { inMailbox => $inboxid },
        collapseThreads => $JSON::true,
        sinceQueryState => $old->{queryState},
    }, 'R2']]);

    my $new = $res->[0][1];
    $self->assert_str_equals($old->{queryState}, $new->{oldQueryState});
    $self->assert_str_not_equals($old->{queryState}, $new->{newQueryState});
    # with collased threads we have to check
    $self->assert_num_equals(2, scalar @{$new->{added}});
    $self->assert_num_equals(2, scalar @{$new->{removed}});
    $self->assert_str_equals($new->{added}[0]{id}, $old->{ids}[$new->{added}[0]{index}]);
    $self->assert_str_equals($new->{added}[1]{id}, $old->{ids}[$new->{added}[1]{index}]);
}

sub test_email_changes
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $res;
    my $state;

    my $store = $self->{store};
    my $talk = $store->get_client();
    my $draftsmbox;

    xlog $self, "create drafts mailbox";
    $res = $jmap->CallMethods([
            ['Mailbox/set', { create => { "1" => {
                            name => "drafts",
                            parentId => undef,
                            role => "drafts"
             }}}, "R1"]
    ]);
    $draftsmbox = $res->[0][1]{created}{"1"}{id};

    xlog $self, "get email updates (expect error)";
    $res = $jmap->CallMethods([['Email/changes', { sinceState => 0 }, "R1"]]);
    $self->assert_str_equals("invalidArguments", $res->[0][1]->{type});
    $self->assert_str_equals("sinceState", $res->[0][1]->{arguments}[0]);

    xlog $self, "get email state";
    $res = $jmap->CallMethods([['Email/get', { ids => []}, "R1"]]);
    $state = $res->[0][1]->{state};
    $self->assert_not_null($state);

    xlog $self, "get email updates";
    $res = $jmap->CallMethods([['Email/changes', { sinceState => $state }, "R1"]]);
    $self->assert_str_equals($state, $res->[0][1]->{oldState});
    $self->assert_str_equals($state, $res->[0][1]->{newState});
    $self->assert_equals(JSON::false, $res->[0][1]->{hasMoreChanges});
    $self->assert_deep_equals([], $res->[0][1]{created});
    $self->assert_deep_equals([], $res->[0][1]{updated});
    $self->assert_deep_equals([], $res->[0][1]{destroyed});

    xlog $self, "Generate a email in INBOX via IMAP";
    $self->make_message("Email A") || die;

    xlog $self, "Get email id";
    $res = $jmap->CallMethods([['Email/query', {}, "R1"]]);
    my $ida = $res->[0][1]->{ids}[0];
    $self->assert_not_null($ida);

    xlog $self, "get email updates";
    $res = $jmap->CallMethods([['Email/changes', { sinceState => $state }, "R1"]]);
    $self->assert_str_equals($state, $res->[0][1]->{oldState});
    $self->assert_str_not_equals($state, $res->[0][1]->{newState});
    $self->assert_equals(JSON::false, $res->[0][1]->{hasMoreChanges});
    $self->assert_num_equals(1, scalar @{$res->[0][1]{created}});
    $self->assert_str_equals($ida, $res->[0][1]{created}[0]);
    $self->assert_deep_equals([], $res->[0][1]{updated});
    $self->assert_deep_equals([], $res->[0][1]{destroyed});
    $state = $res->[0][1]->{newState};

    xlog $self, "get email updates (expect no changes)";
    $res = $jmap->CallMethods([['Email/changes', { sinceState => $state }, "R1"]]);
    $self->assert_str_equals($state, $res->[0][1]->{oldState});
    $self->assert_str_equals($state, $res->[0][1]->{newState});
    $self->assert_equals(JSON::false, $res->[0][1]->{hasMoreChanges});
    $self->assert_deep_equals([], $res->[0][1]{created});
    $self->assert_deep_equals([], $res->[0][1]{updated});
    $self->assert_deep_equals([], $res->[0][1]{destroyed});

    xlog $self, "update email $ida";
    $res = $jmap->CallMethods([['Email/set', {
        update => { $ida => { keywords => { '$seen' => JSON::true }}}
    }, "R1"]]);
    $self->assert(exists $res->[0][1]->{updated}{$ida});

    xlog $self, "get email updates";
    $res = $jmap->CallMethods([['Email/changes', { sinceState => $state }, "R1"]]);
    $self->assert_str_equals($state, $res->[0][1]->{oldState});
    $self->assert_str_not_equals($state, $res->[0][1]->{newState});
    $self->assert_equals(JSON::false, $res->[0][1]->{hasMoreChanges});
    $self->assert_deep_equals([], $res->[0][1]{created});
    $self->assert_num_equals(1, scalar @{$res->[0][1]{updated}});
    $self->assert_str_equals($ida, $res->[0][1]{updated}[0]);
    $self->assert_deep_equals([], $res->[0][1]{destroyed});
    $state = $res->[0][1]->{newState};

    xlog $self, "delete email $ida";
    $res = $jmap->CallMethods([['Email/set', {destroy => [ $ida ] }, "R1"]]);
    $self->assert_str_equals($ida, $res->[0][1]->{destroyed}[0]);

    xlog $self, "get email updates";
    $res = $jmap->CallMethods([['Email/changes', { sinceState => $state }, "R1"]]);
    $self->assert_str_equals($state, $res->[0][1]->{oldState});
    $self->assert_str_not_equals($state, $res->[0][1]->{newState});
    $self->assert_equals(JSON::false, $res->[0][1]->{hasMoreChanges});
    $self->assert_deep_equals([], $res->[0][1]{created});
    $self->assert_deep_equals([], $res->[0][1]{updated});
    $self->assert_num_equals(1, scalar @{$res->[0][1]{destroyed}});
    $self->assert_str_equals($ida, $res->[0][1]{destroyed}[0]);
    $state = $res->[0][1]->{newState};

    xlog $self, "get email updates (expect no changes)";
    $res = $jmap->CallMethods([['Email/changes', { sinceState => $state }, "R1"]]);
    $self->assert_str_equals($state, $res->[0][1]->{oldState});
    $self->assert_str_equals($state, $res->[0][1]->{newState});
    $self->assert_equals(JSON::false, $res->[0][1]->{hasMoreChanges});
    $self->assert_deep_equals([], $res->[0][1]{created});
    $self->assert_deep_equals([], $res->[0][1]{updated});
    $self->assert_deep_equals([], $res->[0][1]{destroyed});

    xlog $self, "create email B";
    $res = $jmap->CallMethods(
        [[ 'Email/set', { create => { "1" => {
            mailboxIds           => {$draftsmbox =>  JSON::true},
            from                 => [ { name => "", email => "sam\@acme.local" } ],
            to                   => [ { name => "", email => "bugs\@acme.local" } ],
            subject              => "Email B",
            textBody             => [{ partId => '1' }],
            bodyValues           => { '1' => { value => "I'm givin' ya one last chance ta surrenda!" }},
            keywords             => { '$draft' => JSON::true },
        }}}, "R1" ]]);
    my $idb = $res->[0][1]{created}{"1"}{id};
    $self->assert_not_null($idb);

    xlog $self, "create email C";
    $res = $jmap->CallMethods(
        [[ 'Email/set', { create => { "1" => {
            mailboxIds           => {$draftsmbox =>  JSON::true},
            from                 => [ { name => "", email => "sam\@acme.local" } ],
            to                   => [ { name => "", email => "bugs\@acme.local" } ],
            subject              => "Email C",
            textBody             => [{ partId => '1' }],
            bodyValues           => { '1' => { value => "I *hate* that rabbit!" } },
            keywords             => { '$draft' => JSON::true },
        }}}, "R1" ]]);
    my $idc = $res->[0][1]{created}{"1"}{id};
    $self->assert_not_null($idc);

    xlog $self, "get max 1 email updates";
    $res = $jmap->CallMethods([['Email/changes', { sinceState => $state, maxChanges => 1 }, "R1"]]);
    $self->assert_str_equals($state, $res->[0][1]->{oldState});
    $self->assert_str_not_equals($state, $res->[0][1]->{newState});
    $self->assert_equals(JSON::true, $res->[0][1]->{hasMoreChanges});
    $self->assert_num_equals(1, scalar @{$res->[0][1]{created}});
    $self->assert_str_equals($idb, $res->[0][1]{created}[0]);
    $self->assert_deep_equals([], $res->[0][1]{updated});
    $self->assert_deep_equals([], $res->[0][1]{destroyed});
    $state = $res->[0][1]->{newState};

    xlog $self, "get max 1 email updates";
    $res = $jmap->CallMethods([['Email/changes', { sinceState => $state, maxChanges => 1 }, "R1"]]);
    $self->assert_str_equals($state, $res->[0][1]->{oldState});
    $self->assert_str_not_equals($state, $res->[0][1]->{newState});
    $self->assert_equals(JSON::false, $res->[0][1]->{hasMoreChanges});
    $self->assert_num_equals(1, scalar @{$res->[0][1]{created}});
    $self->assert_str_equals($idc, $res->[0][1]{created}[0]);
    $self->assert_deep_equals([], $res->[0][1]{updated});
    $self->assert_deep_equals([], $res->[0][1]{destroyed});
    $state = $res->[0][1]->{newState};

    xlog $self, "get email updates (expect no changes)";
    $res = $jmap->CallMethods([['Email/changes', { sinceState => $state }, "R1"]]);
    $self->assert_str_equals($state, $res->[0][1]->{oldState});
    $self->assert_str_equals($state, $res->[0][1]->{newState});
    $self->assert_equals(JSON::false, $res->[0][1]->{hasMoreChanges});
    $self->assert_deep_equals([], $res->[0][1]{created});
    $self->assert_deep_equals([], $res->[0][1]{updated});
    $self->assert_deep_equals([], $res->[0][1]{destroyed});
}

sub test_email_querychanges
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $res;
    my $state;

    my $store = $self->{store};
    my $talk = $store->get_client();

    xlog $self, "Generate a email in INBOX via IMAP";
    $self->make_message("Email A") || die;

    xlog $self, "Get email id";
    $res = $jmap->CallMethods([['Email/query', {}, "R1"]]);
    my $ida = $res->[0][1]->{ids}[0];
    $self->assert_not_null($ida);

    $state = $res->[0][1]->{queryState};

    $self->make_message("Email B") || die;

    $res = $jmap->CallMethods([['Email/query', {}, "R1"]]);

    my ($idb) = grep { $_ ne $ida } @{$res->[0][1]->{ids}};

    xlog $self, "get email list updates";
    $res = $jmap->CallMethods([['Email/queryChanges', { sinceQueryState => $state }, "R1"]]);

    $self->assert_equals($idb, $res->[0][1]{added}[0]{id});

    xlog $self, "get email list updates with threads collapsed";
    $res = $jmap->CallMethods([['Email/queryChanges', { sinceQueryState => $state, collapseThreads => JSON::true }, "R1"]]);

    $self->assert_equals($idb, $res->[0][1]{added}[0]{id});
}

sub test_email_querychanges_toomany
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $res;
    my $state;

    my $store = $self->{store};
    my $talk = $store->get_client();

    xlog $self, "Generate a email in INBOX via IMAP";
    $self->make_message("Email A") || die;

    xlog $self, "Get email id";
    $res = $jmap->CallMethods([['Email/query', {}, "R1"]]);
    my $ida = $res->[0][1]->{ids}[0];
    $self->assert_not_null($ida);

    $state = $res->[0][1]->{queryState};

    $self->make_message("Email B") || die;

    $res = $jmap->CallMethods([['Email/query', {}, "R1"]]);

    my ($idb) = grep { $_ ne $ida } @{$res->[0][1]->{ids}};

    xlog $self, "get email list updates";
    $res = $jmap->CallMethods([['Email/queryChanges', { sinceQueryState => $state, maxChanges => 1 }, "R1"]]);

    $self->assert_str_equals("error", $res->[0][0]);
    $self->assert_str_equals("tooManyChanges", $res->[0][1]{type});
    $self->assert_str_equals("R1", $res->[0][2]);

    xlog $self, "get email list updates with threads collapsed";
    $res = $jmap->CallMethods([['Email/queryChanges', { sinceQueryState => $state, collapseThreads => JSON::true, maxChanges => 1 }, "R1"]]);

    $self->assert_str_equals("error", $res->[0][0]);
    $self->assert_str_equals("tooManyChanges", $res->[0][1]{type});
    $self->assert_str_equals("R1", $res->[0][2]);
}

sub test_email_querychanges_zerosince
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $res;
    my $state;

    my $store = $self->{store};
    my $talk = $store->get_client();

    xlog $self, "Generate a email in INBOX via IMAP";
    $self->make_message("Email A") || die;

    xlog $self, "Get email id";
    $res = $jmap->CallMethods([['Email/query', {}, "R1"]]);
    my $ida = $res->[0][1]->{ids}[0];
    $self->assert_not_null($ida);

    $state = $res->[0][1]->{queryState};

    $self->make_message("Email B") || die;

    $res = $jmap->CallMethods([['Email/query', {}, "R1"]]);

    my ($idb) = grep { $_ ne $ida } @{$res->[0][1]->{ids}};

    xlog $self, "get email list updates";
    $res = $jmap->CallMethods([['Email/queryChanges', { sinceQueryState => $state }, "R1"]]);

    $self->assert_equals($idb, $res->[0][1]{added}[0]{id});

    xlog $self, "get email list updates with threads collapsed";
    $res = $jmap->CallMethods([['Email/queryChanges', { sinceQueryState => "0", collapseThreads => JSON::true }, "R1"]]);
    $self->assert_equals('error', $res->[0][0]);
}


sub test_email_querychanges_thread
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $res;
    my $state;
    my %exp;
    my $dt;

    my $store = $self->{store};
    my $talk = $store->get_client();

    xlog $self, "generating email A";
    $dt = DateTime->now();
    $dt->add(DateTime::Duration->new(hours => -3));
    $exp{A} = $self->make_message("Email A", date => $dt, body => "a");
    $exp{A}->set_attributes(uid => 1, cid => $exp{A}->make_cid());

    xlog $self, "Get email id";
    $res = $jmap->CallMethods([['Email/query', {}, "R1"]]);
    my $ida = $res->[0][1]->{ids}[0];
    $self->assert_not_null($ida);

    $state = $res->[0][1]->{queryState};

    xlog $self, "generating email B";
    $exp{B} = $self->make_message("Email B", body => "b");
    $exp{B}->set_attributes(uid => 2, cid => $exp{B}->make_cid());

    xlog $self, "generating email C referencing A";
    $dt = DateTime->now();
    $dt->add(DateTime::Duration->new(hours => -2));
    $exp{C} = $self->make_message("Re: Email A", references => [ $exp{A} ], date => $dt, body => "c");
    $exp{C}->set_attributes(uid => 3, cid => $exp{A}->get_attribute('cid'));

    xlog $self, "generating email D referencing A";
    $dt = DateTime->now();
    $dt->add(DateTime::Duration->new(hours => -1));
    $exp{D} = $self->make_message("Re: Email A", references => [ $exp{A} ], date => $dt, body => "d");
    $exp{D}->set_attributes(uid => 4, cid => $exp{A}->get_attribute('cid'));

    $res = $jmap->CallMethods([['Email/queryChanges', { sinceQueryState => $state, collapseThreads => JSON::true }, "R1"]]);
    $state = $res->[0][1]{newQueryState};

    $self->assert_num_equals(2, $res->[0][1]{total});
    # assert that IDA got destroyed
    $self->assert_not_null(grep { $_ eq $ida } map { $_ } @{$res->[0][1]->{removed}});
    # and not recreated
    $self->assert_null(grep { $_ eq $ida } map { $_->{id} } @{$res->[0][1]->{added}});

    $talk->select("INBOX");
    $talk->store('3', "+flags", '\\Deleted');
    $talk->expunge();

    $res = $jmap->CallMethods([['Email/queryChanges', { sinceQueryState => $state, collapseThreads => JSON::true }, "R1"]]);
    $state = $res->[0][1]{newQueryState};

    $self->assert_num_equals(2, $res->[0][1]{total});
    $self->assert(ref($res->[0][1]{added}) eq 'ARRAY');
    $self->assert_num_equals(0, scalar @{$res->[0][1]{added}});
    $self->assert(ref($res->[0][1]{removed}) eq 'ARRAY');
    $self->assert_num_equals(0, scalar @{$res->[0][1]{removed}});

    $talk->store('3', "+flags", '\\Deleted');
    $talk->expunge();

    $res = $jmap->CallMethods([['Email/queryChanges', { sinceQueryState => $state, collapseThreads => JSON::true }, "R1"]]);

    $self->assert_num_equals(2, $res->[0][1]{total});
    $self->assert_num_equals(1, scalar(@{$res->[0][1]{added}}));
    $self->assert_num_equals(2, scalar(@{$res->[0][1]{removed}}));

    # same thread, back to ida
    $self->assert_str_equals($ida, $res->[0][1]{added}[0]{id});
    #$self->assert_str_equals($res->[0][1]{added}[0]{threadId}, $res->[0][1]{destroyed}[0]{threadId});
}

sub test_email_querychanges_sortflagged
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $res;
    my $state;
    my %exp;
    my $dt;

    my $store = $self->{store};
    my $talk = $store->get_client();

    xlog $self, "generating email A";
    $dt = DateTime->now();
    $dt->add(DateTime::Duration->new(hours => -3));
    $exp{A} = $self->make_message("Email A", date => $dt, body => "a");
    $exp{A}->set_attributes(uid => 1, cid => $exp{A}->make_cid());

    xlog $self, "Get email id";
    $res = $jmap->CallMethods([['Email/query', {
        collapseThreads => $JSON::true,
        sort => [
            { property => "someInThreadHaveKeyword",
              keyword => "\$flagged",
              isAscending => $JSON::false },
            { property => "receivedAt",
              isAscending => $JSON::false },
        ],
    }, "R1"]]);
    my $ida = $res->[0][1]->{ids}[0];
    $self->assert_not_null($ida);

    $state = $res->[0][1]->{queryState};

    xlog $self, "generating email B";
    $exp{B} = $self->make_message("Email B", body => "b");
    $exp{B}->set_attributes(uid => 2, cid => $exp{B}->make_cid());

    xlog $self, "generating email C referencing A";
    $dt = DateTime->now();
    $dt->add(DateTime::Duration->new(hours => -2));
    $exp{C} = $self->make_message("Re: Email A", references => [ $exp{A} ], date => $dt, body => "c");
    $exp{C}->set_attributes(uid => 3, cid => $exp{A}->get_attribute('cid'));

    xlog $self, "generating email D referencing A";
    $dt = DateTime->now();
    $dt->add(DateTime::Duration->new(hours => -1));
    $exp{D} = $self->make_message("Re: Email A", references => [ $exp{A} ], date => $dt, body => "d");
    $exp{D}->set_attributes(uid => 4, cid => $exp{A}->get_attribute('cid'));

    # EXPECTED ORDER OF MESSAGES NOW BY DATE IS:
    # A C D B
    # fetch them all by ID now to get an ID map
    $res = $jmap->CallMethods([['Email/query', {
        sort => [
            { property => "receivedAt",
              "isAscending" => $JSON::true },
        ],
    }, "R1"]]);
    my @ids = @{$res->[0][1]->{ids}};
    $self->assert_num_equals(4, scalar @ids);
    $self->assert_str_equals($ida, $ids[0]);
    my $idc = $ids[1];
    my $idd = $ids[2];
    my $idb = $ids[3];

    # raw fetch - check order now
    $res = $jmap->CallMethods([['Email/query', {
        collapseThreads => $JSON::true,
        sort => [
            { property => "someInThreadHaveKeyword",
              keyword => "\$flagged",
              isAscending => $JSON::false },
            { property => "receivedAt",
              isAscending => $JSON::false },
         ],
    }, "R1"]]);
    $self->assert_deep_equals([$idb, $idd], $res->[0][1]->{ids});

    $res = $jmap->CallMethods([['Email/queryChanges', {
        sinceQueryState => $state, collapseThreads => $JSON::true,
        sort => [
            { property => "someInThreadHaveKeyword",
              keyword => "\$flagged",
              isAscending => $JSON::false },
            { property => "receivedAt",
              isAscending => $JSON::false },
         ],
    }, "R1"]]);
    $state = $res->[0][1]{newQueryState};

    $self->assert_num_equals(2, $res->[0][1]{total});
    $self->assert_num_equals(4, scalar @{$res->[0][1]->{removed}});
    $self->assert_num_equals(2, scalar @{$res->[0][1]->{added}});
    # check that the order is B D
    $self->assert_deep_equals([{id => $idb, index => 0}, {id => $idd, index => 1}], $res->[0][1]{added});

    $talk->select("INBOX");
    $talk->store('1', "+flags", '\\Flagged');

    # this will sort D to the top because of the flag on A

    # raw fetch - check order now
    $res = $jmap->CallMethods([['Email/query', {
        collapseThreads => $JSON::true,
        sort => [
            { property => "someInThreadHaveKeyword",
              keyword => "\$flagged",
              isAscending => $JSON::false },
            { property => "receivedAt",
              isAscending => $JSON::false },
         ],
    }, "R1"]]);
    $self->assert_deep_equals([$idd, $idb], $res->[0][1]->{ids});

    $res = $jmap->CallMethods([['Email/queryChanges', {
        sinceQueryState => $state, collapseThreads => $JSON::true,
        sort => [
            { property => "someInThreadHaveKeyword",
              keyword => "\$flagged",
              isAscending => $JSON::false },
            { property => "receivedAt",
              isAscending => $JSON::false },
         ],
    }, "R1"]]);
    $state = $res->[0][1]{newQueryState};

    $self->assert_num_equals(2, $res->[0][1]{total});
    # will have removed 'D' (old exemplar) and 'A' (touched)
    $self->assert_num_equals(3, scalar @{$res->[0][1]->{removed}});
    $self->assert_not_null(grep { $_ eq $idd } map { $_ } @{$res->[0][1]->{removed}});
    $self->assert_not_null(grep { $_ eq $ida } map { $_ } @{$res->[0][1]->{removed}});
    $self->assert_not_null(grep { $_ eq $idc } map { $_ } @{$res->[0][1]->{removed}});
    $self->assert_deep_equals([{id => $idd, index => 0}], $res->[0][1]{added});
}

sub test_email_querychanges_sortflagged_topmessage
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $res;
    my $state;
    my %exp;
    my $dt;

    my $store = $self->{store};
    my $talk = $store->get_client();

    xlog $self, "generating email A";
    $dt = DateTime->now();
    $dt->add(DateTime::Duration->new(hours => -3));
    $exp{A} = $self->make_message("Email A", date => $dt, body => "a");
    $exp{A}->set_attributes(uid => 1, cid => $exp{A}->make_cid());

    xlog $self, "Get email id";
    $res = $jmap->CallMethods([['Email/query', {
        collapseThreads => $JSON::true,
        sort => [
            { property => "someInThreadHaveKeyword",
              keyword => "\$flagged",
              isAscending => $JSON::false },
            { property => "receivedAt",
              isAscending => $JSON::false },
        ],
    }, "R1"]]);
    my $ida = $res->[0][1]->{ids}[0];
    $self->assert_not_null($ida);

    $state = $res->[0][1]->{queryState};

    xlog $self, "generating email B";
    $exp{B} = $self->make_message("Email B", body => "b");
    $exp{B}->set_attributes(uid => 2, cid => $exp{B}->make_cid());

    xlog $self, "generating email C referencing A";
    $dt = DateTime->now();
    $dt->add(DateTime::Duration->new(hours => -2));
    $exp{C} = $self->make_message("Re: Email A", references => [ $exp{A} ], date => $dt, body => "c");
    $exp{C}->set_attributes(uid => 3, cid => $exp{A}->get_attribute('cid'));

    xlog $self, "generating email D referencing A";
    $dt = DateTime->now();
    $dt->add(DateTime::Duration->new(hours => -1));
    $exp{D} = $self->make_message("Re: Email A", references => [ $exp{A} ], date => $dt, body => "d");
    $exp{D}->set_attributes(uid => 4, cid => $exp{A}->get_attribute('cid'));

    # EXPECTED ORDER OF MESSAGES NOW BY DATE IS:
    # A C D B
    # fetch them all by ID now to get an ID map
    $res = $jmap->CallMethods([['Email/query', {
        sort => [
            { property => "receivedAt",
              "isAscending" => $JSON::true },
        ],
    }, "R1"]]);
    my @ids = @{$res->[0][1]->{ids}};
    $self->assert_num_equals(4, scalar @ids);
    $self->assert_str_equals($ida, $ids[0]);
    my $idc = $ids[1];
    my $idd = $ids[2];
    my $idb = $ids[3];

    # raw fetch - check order now
    $res = $jmap->CallMethods([['Email/query', {
        collapseThreads => $JSON::true,
        sort => [
            { property => "someInThreadHaveKeyword",
              keyword => "\$flagged",
              isAscending => $JSON::false },
            { property => "receivedAt",
              isAscending => $JSON::false },
         ],
    }, "R1"]]);
    $self->assert_deep_equals([$idb, $idd], $res->[0][1]->{ids});

    $res = $jmap->CallMethods([['Email/queryChanges', {
        sinceQueryState => $state, collapseThreads => $JSON::true,
        sort => [
            { property => "someInThreadHaveKeyword",
              keyword => "\$flagged",
              isAscending => $JSON::false },
            { property => "receivedAt",
              isAscending => $JSON::false },
         ],
    }, "R1"]]);
    $state = $res->[0][1]{newQueryState};

    $self->assert_num_equals(2, $res->[0][1]{total});
    $self->assert_num_equals(4, scalar @{$res->[0][1]->{removed}});
    $self->assert_num_equals(2, scalar @{$res->[0][1]->{added}});
    # check that the order is B D
    $self->assert_deep_equals([{id => $idb, index => 0}, {id => $idd, index => 1}], $res->[0][1]{added});

    $talk->select("INBOX");
    $talk->store('4', "+flags", '\\Flagged');

    # this will sort D to the top because of the flag on D

    # raw fetch - check order now
    $res = $jmap->CallMethods([['Email/query', {
        collapseThreads => $JSON::true,
        sort => [
            { property => "someInThreadHaveKeyword",
              keyword => "\$flagged",
              isAscending => $JSON::false },
            { property => "receivedAt",
              isAscending => $JSON::false },
         ],
    }, "R1"]]);
    $self->assert_deep_equals([$idd, $idb], $res->[0][1]->{ids});

    $res = $jmap->CallMethods([['Email/queryChanges', {
        sinceQueryState => $state, collapseThreads => $JSON::true,
        sort => [
            { property => "someInThreadHaveKeyword",
              keyword => "\$flagged",
              isAscending => $JSON::false },
            { property => "receivedAt",
              isAscending => $JSON::false },
         ],
    }, "R1"]]);
    $state = $res->[0][1]{newQueryState};

    $self->assert_num_equals(2, $res->[0][1]{total});
    # will have removed 'D' (touched) as well as
    # XXX: C and A because it can't know what the old order was, oh well
    $self->assert_num_equals(3, scalar @{$res->[0][1]->{removed}});
    $self->assert_not_null(grep { $_ eq $idd } map { $_ } @{$res->[0][1]->{removed}});
    $self->assert_not_null(grep { $_ eq $ida } map { $_ } @{$res->[0][1]->{removed}});
    $self->assert_not_null(grep { $_ eq $idc } map { $_ } @{$res->[0][1]->{removed}});
    $self->assert_deep_equals([{id => $idd, index => 0}], $res->[0][1]{added});
}

sub test_email_querychanges_sortflagged_otherfolder
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $res;
    my $state;
    my %exp;
    my $dt;

    my $store = $self->{store};
    my $talk = $store->get_client();

    xlog $self, "generating email A";
    $dt = DateTime->now();
    $dt->add(DateTime::Duration->new(hours => -3));
    $exp{A} = $self->make_message("Email A", date => $dt, body => "a");
    $exp{A}->set_attributes(uid => 1, cid => $exp{A}->make_cid());

    xlog $self, "Get mailbox id";
    $res = $jmap->CallMethods([['Mailbox/query', {}, "R1"]]);
    my $mbid = $res->[0][1]->{ids}[0];
    $self->assert_not_null($mbid);

    xlog $self, "Get email id";
    $res = $jmap->CallMethods([['Email/query', {
        filter => { inMailbox => $mbid },
        collapseThreads => $JSON::true,
        sort => [
            { property => "someInThreadHaveKeyword",
              keyword => "\$flagged",
              isAscending => $JSON::false },
            { property => "receivedAt",
              isAscending => $JSON::false },
        ],
    }, "R1"]]);
    my $ida = $res->[0][1]->{ids}[0];
    $self->assert_not_null($ida);

    $state = $res->[0][1]->{queryState};

    xlog $self, "generating email B";
    $exp{B} = $self->make_message("Email B", body => "b");
    $exp{B}->set_attributes(uid => 2, cid => $exp{B}->make_cid());

    xlog $self, "generating email C referencing A";
    $dt = DateTime->now();
    $dt->add(DateTime::Duration->new(hours => -2));
    $exp{C} = $self->make_message("Re: Email A", references => [ $exp{A} ], date => $dt, body => "c");
    $exp{C}->set_attributes(uid => 3, cid => $exp{A}->get_attribute('cid'));

    xlog $self, "Create new mailbox";
    $res = $jmap->CallMethods([['Mailbox/set', { create => { 1 => { name => "foo" } } }, "R1"]]);

    $self->{store}->set_folder("INBOX.foo");
    xlog $self, "generating email D referencing A (in foo)";
    $dt = DateTime->now();
    $dt->add(DateTime::Duration->new(hours => -1));
    $exp{D} = $self->make_message("Re: Email A", references => [ $exp{A} ], date => $dt, body => "d");
    $exp{D}->set_attributes(uid => 1, cid => $exp{A}->get_attribute('cid'));

    # EXPECTED ORDER OF MESSAGES NOW BY DATE IS:
    # A C B (with D in the other mailbox)
    # fetch them all by ID now to get an ID map
    $res = $jmap->CallMethods([['Email/query', {
        filter => { inMailbox => $mbid },
        sort => [
            { property => "receivedAt",
              "isAscending" => $JSON::true },
        ],
    }, "R1"]]);
    my @ids = @{$res->[0][1]->{ids}};
    $self->assert_num_equals(3, scalar @ids);
    $self->assert_str_equals($ida, $ids[0]);
    my $idc = $ids[1];
    my $idb = $ids[2];

    # raw fetch - check order now
    $res = $jmap->CallMethods([['Email/query', {
        filter => { inMailbox => $mbid },
        collapseThreads => $JSON::true,
        sort => [
            { property => "someInThreadHaveKeyword",
              keyword => "\$flagged",
              isAscending => $JSON::false },
            { property => "receivedAt",
              isAscending => $JSON::false },
         ],
    }, "R1"]]);
    $self->assert_deep_equals([$idb, $idc], $res->[0][1]->{ids});

    $res = $jmap->CallMethods([['Email/queryChanges', {
        filter => { inMailbox => $mbid },
        sinceQueryState => $state, collapseThreads => $JSON::true,
        sort => [
            { property => "someInThreadHaveKeyword",
              keyword => "\$flagged",
              isAscending => $JSON::false },
            { property => "receivedAt",
              isAscending => $JSON::false },
         ],
    }, "R1"]]);
    $state = $res->[0][1]{newQueryState};

    $self->assert_num_equals(2, $res->[0][1]{total});
    $self->assert_num_equals(3, scalar @{$res->[0][1]->{removed}});
    $self->assert_num_equals(2, scalar @{$res->[0][1]->{added}});
    # check that the order is B C
    $self->assert_deep_equals([{id => $idb, index => 0}, {id => $idc, index => 1}], $res->[0][1]{added});

    $talk->select("INBOX.foo");
    $talk->store('1', "+flags", '\\Flagged');

    # this has put the flag on D, which should sort C to the top!

    # raw fetch - check order now
    $res = $jmap->CallMethods([['Email/query', {
        filter => { inMailbox => $mbid },
        collapseThreads => $JSON::true,
        sort => [
            { property => "someInThreadHaveKeyword",
              keyword => "\$flagged",
              isAscending => $JSON::false },
            { property => "receivedAt",
              isAscending => $JSON::false },
         ],
    }, "R1"]]);
    $self->assert_deep_equals([$idc, $idb], $res->[0][1]->{ids});

    $res = $jmap->CallMethods([['Email/queryChanges', {
        filter => { inMailbox => $mbid },
        sinceQueryState => $state, collapseThreads => $JSON::true,
        sort => [
            { property => "someInThreadHaveKeyword",
              keyword => "\$flagged",
              isAscending => $JSON::false },
            { property => "receivedAt",
              isAscending => $JSON::false },
         ],
    }, "R1"]]);
    $state = $res->[0][1]{newQueryState};

    $self->assert_num_equals(2, $res->[0][1]{total});
    $self->assert_num_equals(2, scalar @{$res->[0][1]->{removed}});
    $self->assert_not_null(grep { $_ eq $ida } map { $_ } @{$res->[0][1]->{removed}});
    $self->assert_not_null(grep { $_ eq $idc } map { $_ } @{$res->[0][1]->{removed}});
    $self->assert_deep_equals([{id => $idc, index => 0}], $res->[0][1]{added});
}

sub test_email_querychanges_order
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $res;
    my $state;

    my $store = $self->{store};
    my $talk = $store->get_client();

    xlog $self, "Generate a email in INBOX via IMAP";
    $self->make_message("A") || die;

    # First order descending by subject. We expect Email/queryChanges
    # to return any items added after 'state' to show up at the start of
    # the result list.
    my $sort = [{ property => "subject", isAscending => JSON::false }];

    xlog $self, "Get email id and state";
    $res = $jmap->CallMethods([['Email/query', { sort => $sort }, "R1"]]);
    my $ida = $res->[0][1]->{ids}[0];
    $self->assert_not_null($ida);
    $state = $res->[0][1]->{queryState};

    xlog $self, "Generate a email in INBOX via IMAP";
    $self->make_message("B") || die;

    xlog $self, "Fetch updated list";
    $res = $jmap->CallMethods([['Email/query', { sort => $sort }, "R1"]]);
    my $idb = $res->[0][1]->{ids}[0];
    $self->assert_str_not_equals($ida, $idb);

    xlog $self, "get email list updates";
    $res = $jmap->CallMethods([['Email/queryChanges', { sinceQueryState => $state, sort => $sort }, "R1"]]);
    $self->assert_equals($idb, $res->[0][1]{added}[0]{id});
    $self->assert_num_equals(0, $res->[0][1]{added}[0]{index});

    # Now restart with sorting by ascending subject. We refetch the state
    # just to be sure. Then we expect an additional item to show up at the
    # end of the result list.
    xlog $self, "Fetch reverse sorted list and state";
    $sort = [{ property => "subject" }];
    $res = $jmap->CallMethods([['Email/query', { sort => $sort }, "R1"]]);
    $ida = $res->[0][1]->{ids}[0];
    $self->assert_str_not_equals($ida, $idb);
    $idb = $res->[0][1]->{ids}[1];
    $state = $res->[0][1]->{queryState};

    xlog $self, "Generate a email in INBOX via IMAP";
    $self->make_message("C") || die;

    xlog $self, "get email list updates";
    $res = $jmap->CallMethods([['Email/queryChanges', { sinceQueryState => $state, sort => $sort }, "R1"]]);
    $self->assert_str_not_equals($ida, $res->[0][1]{added}[0]{id});
    $self->assert_str_not_equals($idb, $res->[0][1]{added}[0]{id});
    $self->assert_num_equals(2, $res->[0][1]{added}[0]{index});
}

sub test_email_querychanges_implementation
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    # Also see https://github.com/cyrusimap/cyrus-imapd/issues/2294

    my $store = $self->{store};
    my $talk = $store->get_client();

    xlog $self, "Generate two emails via IMAP";
    $self->make_message("EmailA") || die;
    $self->make_message("EmailB") || die;

    # The JMAP implementation in Cyrus uses two strategies
    # for processing an Email/queryChanges request, depending
    # on the query arguments:
    #
    # (1) 'trivial': if collapseThreads is false
    #
    # (2) 'collapse': if collapseThreads is true
    #
    #  The results should be the same for (1) and (2), where
    #  updated message are reported as both 'added' and 'removed'.

    my $inboxid = $self->getinbox()->{id};

    xlog $self, "Get email ids and state";
    my $res = $jmap->CallMethods([
        ['Email/query', {
            sort => [
                { isAscending => JSON::true, property => 'subject' }
            ],
            collapseThreads => JSON::false,
        }, "R1"],
        ['Email/query', {
            sort => [
                { isAscending => JSON::true, property => 'subject' }
            ],
            collapseThreads => JSON::true,
        }, "R2"],
    ]);
    my $msgidA = $res->[0][1]->{ids}[0];
    $self->assert_not_null($msgidA);
    my $msgidB = $res->[0][1]->{ids}[1];
    $self->assert_not_null($msgidB);

    my $state_trivial = $res->[0][1]->{queryState};
    $self->assert_not_null($state_trivial);
    my $state_collapsed = $res->[1][1]->{queryState};
    $self->assert_not_null($state_collapsed);

        xlog $self, "update email B";
        $res = $jmap->CallMethods([['Email/set', {
                update => { $msgidB => {
                        'keywords/$seen' => JSON::true }
                },
        }, "R1"]]);
    $self->assert(exists $res->[0][1]->{updated}{$msgidB});

    xlog $self, "Create two new emails via IMAP";
    $self->make_message("EmailC") || die;
    $self->make_message("EmailD") || die;

    xlog $self, "Get email ids";
    $res = $jmap->CallMethods([['Email/query', {
        sort => [{ isAscending => JSON::true, property => 'subject' }],
    }, "R1"]]);
    my $msgidC = $res->[0][1]->{ids}[2];
    $self->assert_not_null($msgidC);
    my $msgidD = $res->[0][1]->{ids}[3];
    $self->assert_not_null($msgidD);

    xlog $self, "Query changes up to first newly created message";
    $res = $jmap->CallMethods([
        ['Email/queryChanges', {
            sort => [
                { isAscending => JSON::true, property => 'subject' }
            ],
            sinceQueryState => $state_trivial,
            collapseThreads => JSON::false,
            upToId => $msgidC,
        }, "R1"],
        ['Email/queryChanges', {
            sort => [
                { isAscending => JSON::true, property => 'subject' }
            ],
            sinceQueryState => $state_collapsed,
            collapseThreads => JSON::true,
            upToId => $msgidC,
        }, "R2"],
    ]);

    # 'trivial' case
    $self->assert_num_equals(2, scalar @{$res->[0][1]{added}});
    $self->assert_str_equals($msgidB, $res->[0][1]{added}[0]{id});
    $self->assert_num_equals(1, $res->[0][1]{added}[0]{index});
    $self->assert_str_equals($msgidC, $res->[0][1]{added}[1]{id});
    $self->assert_num_equals(2, $res->[0][1]{added}[1]{index});
    $self->assert_deep_equals([$msgidB, $msgidC], $res->[0][1]{removed});
    $self->assert_num_equals(4, $res->[0][1]{total});
    $state_trivial = $res->[0][1]{newQueryState};

    # 'collapsed' case
    $self->assert_num_equals(2, scalar @{$res->[1][1]{added}});
    $self->assert_str_equals($msgidB, $res->[1][1]{added}[0]{id});
    $self->assert_num_equals(1, $res->[1][1]{added}[0]{index});
    $self->assert_str_equals($msgidC, $res->[1][1]{added}[1]{id});
    $self->assert_num_equals(2, $res->[1][1]{added}[1]{index});
    $self->assert_deep_equals([$msgidB, $msgidC], $res->[1][1]{removed});
    $self->assert_num_equals(4, $res->[0][1]{total});
    $state_collapsed = $res->[1][1]{newQueryState};

    xlog $self, "delete email C ($msgidC)";
    $res = $jmap->CallMethods([['Email/set', { destroy => [ $msgidC ] }, "R1"]]);
    $self->assert_str_equals($msgidC, $res->[0][1]->{destroyed}[0]);

    xlog $self, "Query changes";
    $res = $jmap->CallMethods([
        ['Email/queryChanges', {
            sort => [
                { isAscending => JSON::true, property => 'subject' }
            ],
            sinceQueryState => $state_trivial,
            collapseThreads => JSON::false,
        }, "R1"],
        ['Email/queryChanges', {
            sort => [
                { isAscending => JSON::true, property => 'subject' }
            ],
            sinceQueryState => $state_collapsed,
            collapseThreads => JSON::true,
        }, "R2"],
    ]);

    # 'trivial' case
    $self->assert_num_equals(0, scalar @{$res->[0][1]{added}});
    $self->assert_deep_equals([$msgidC], $res->[0][1]{removed});
    $self->assert_num_equals(3, $res->[0][1]{total});

    # 'collapsed' case
    $self->assert_num_equals(0, scalar @{$res->[1][1]{added}});
    $self->assert_deep_equals([$msgidC], $res->[1][1]{removed});
    $self->assert_num_equals(3, $res->[0][1]{total});
}

sub test_email_changes_shared
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $res;

    my $store = $self->{store};
    my $imaptalk = $self->{store}->get_client();
    my $admintalk = $self->{adminstore}->get_client();

    xlog $self, "create user and share inbox";
    $self->{instance}->create_user("foo");
    $admintalk->setacl("user.foo", "cassandane", "lrwkxd") or die;

    xlog $self, "create non-shared mailbox box1";
    $admintalk->create("user.foo.box1") or die;
    $admintalk->setacl("user.foo.box1", "cassandane", "") or die;

    xlog $self, "get email state";
    $res = $jmap->CallMethods([['Email/get', { accountId => 'foo', ids => []}, "R1"]]);
    my $state = $res->[0][1]->{state};
    $self->assert_not_null($state);

    xlog $self, "get email updates (expect empty changes)";
    $res = $jmap->CallMethods([['Email/changes', { accountId => 'foo', sinceState => $state }, "R1"]]);
    $self->assert_str_equals($state, $res->[0][1]->{oldState});
    # This could be the same as oldState, or not, as we might leak
    # unshared modseqs (but not the according mail!).
    $self->assert_not_null($res->[0][1]->{newState});
    $self->assert_equals(JSON::false, $res->[0][1]->{hasMoreChanges});
    $self->assert_deep_equals([], $res->[0][1]{created});
    $self->assert_deep_equals([], $res->[0][1]{updated});
    $self->assert_deep_equals([], $res->[0][1]{destroyed});

    xlog $self, "Generate a email in shared account INBOX via IMAP";
    $self->{adminstore}->set_folder('user.foo');
    $self->make_message("Email A", store => $self->{adminstore}) || die;

    xlog $self, "get email updates";
    $res = $jmap->CallMethods([['Email/changes', { accountId => 'foo', sinceState => $state }, "R1"]]);
    $self->assert_str_equals($state, $res->[0][1]->{oldState});
    $self->assert_str_not_equals($state, $res->[0][1]->{newState});
    $self->assert_equals(JSON::false, $res->[0][1]->{hasMoreChanges});
    $self->assert_num_equals(1, scalar @{$res->[0][1]{created}});
    $self->assert_deep_equals([], $res->[0][1]{updated});
    $self->assert_deep_equals([], $res->[0][1]{destroyed});
    $state = $res->[0][1]->{newState};
    my $ida = $res->[0][1]{created}[0];

    xlog $self, "create email in non-shared mailbox";
    $self->{adminstore}->set_folder('user.foo.box1');
    $self->make_message("Email B", store => $self->{adminstore}) || die;

    xlog $self, "get email updates (expect empty changes)";
    $res = $jmap->CallMethods([['Email/changes', { accountId => 'foo', sinceState => $state }, "R1"]]);
    $self->assert_str_equals($state, $res->[0][1]->{oldState});
    # This could be the same as oldState, or not, as we might leak
    # unshared modseqs (but not the according mail!).
    $self->assert_not_null($res->[0][1]->{newState});
    $self->assert_equals(JSON::false, $res->[0][1]->{hasMoreChanges});
    $self->assert_deep_equals([], $res->[0][1]{created});
    $self->assert_deep_equals([], $res->[0][1]{updated});
    $self->assert_deep_equals([], $res->[0][1]{destroyed});

    xlog $self, "share private mailbox box1";
    $admintalk->setacl("user.foo.box1", "cassandane", "lr") or die;

    xlog $self, "get email updates";
    $res = $jmap->CallMethods([['Email/changes', { accountId => 'foo', sinceState => $state }, "R1"]]);
    $self->assert_str_equals($state, $res->[0][1]->{oldState});
    $self->assert_str_not_equals($state, $res->[0][1]->{newState});
    $self->assert_equals(JSON::false, $res->[0][1]->{hasMoreChanges});
    $self->assert_num_equals(1, scalar @{$res->[0][1]{created}});
    $self->assert_deep_equals([], $res->[0][1]{updated});
    $self->assert_deep_equals([], $res->[0][1]{destroyed});
    $state = $res->[0][1]->{newState};

    xlog $self, "delete email $ida";
    $res = $jmap->CallMethods([['Email/set', { accountId => 'foo', destroy => [ $ida ] }, "R1"]]);
    $self->assert_str_equals($ida, $res->[0][1]->{destroyed}[0]);

    xlog $self, "get email updates";
    $res = $jmap->CallMethods([['Email/changes', { accountId => 'foo', sinceState => $state }, "R1"]]);
    $self->assert_str_equals($state, $res->[0][1]->{oldState});
    $self->assert_str_not_equals($state, $res->[0][1]->{newState});
    $self->assert_equals(JSON::false, $res->[0][1]->{hasMoreChanges});
    $self->assert_deep_equals([], $res->[0][1]{created});
    $self->assert_deep_equals([], $res->[0][1]{updated});
    $self->assert_num_equals(1, scalar @{$res->[0][1]{destroyed}});
    $self->assert_str_equals($ida, $res->[0][1]{destroyed}[0]);
    $state = $res->[0][1]->{newState};
}

sub test_misc_upload_download822
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $email = <<'EOF';
From: "Some Example Sender" <example@example.com>
To: baseball@vitaead.com
Subject: test email
Date: Wed, 7 Dec 2016 00:21:50 -0500
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

This is a test email.
EOF
    $email =~ s/\r?\n/\r\n/gs;
    my $data = $jmap->Upload($email, "message/rfc822");
    my $blobid = $data->{blobId};

    my $download = $jmap->Download('cassandane', $blobid);

    $self->assert_str_equals($email, $download->{content});
}

sub test_email_get_bogus_encoding
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $email = <<'EOF';
From: "Some Example Sender" <example@example.com>
To: baseball@vitaead.com
Subject: test email
Date: Wed, 7 Dec 2016 00:21:50 -0500
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: foobar

This is a test email.
EOF
    $email =~ s/\r?\n/\r\n/gs;
    my $data = $jmap->Upload($email, "message/rfc822");
    my $blobid = $data->{blobId};
    my $inboxid = $self->getinbox()->{id};

    xlog $self, "import and get email from blob $blobid";
    my $res = $jmap->CallMethods([['Email/import', {
        emails => {
            "1" => {
                blobId => $blobid,
                mailboxIds => {$inboxid =>  JSON::true},
            },
        },
    }, "R1"], ["Email/get", {
        ids => ["#1"],
        properties => ['bodyStructure', 'bodyValues'],
        fetchAllBodyValues => JSON::true,
    }, "R2" ]]);

    $self->assert_str_equals("Email/import", $res->[0][0]);
    $self->assert_str_equals("Email/get", $res->[1][0]);

    my $msg = $res->[1][1]{list}[0];
    my $partId = $msg->{bodyStructure}{partId};
    my $bodyValue = $msg->{bodyValues}{$partId};
    $self->assert_str_equals("", $bodyValue->{value});
    $self->assert_equals(JSON::true, $bodyValue->{isEncodingProblem});
}

sub test_email_get_encoding_utf8
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    # Some clients erroneously declare encoding to be UTF-8.
    my $email = <<'EOF';
From: "Some Example Sender" <example@example.com>
To: baseball@vitaead.com
Subject: test email
Date: Wed, 7 Dec 2016 00:21:50 -0500
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: UTF-8

This is a test.
EOF
    $email =~ s/\r?\n/\r\n/gs;
    my $data = $jmap->Upload($email, "message/rfc822");
    my $blobid = $data->{blobId};
    my $inboxid = $self->getinbox()->{id};

    xlog $self, "import and get email from blob $blobid";
    my $res = $jmap->CallMethods([['Email/import', {
        emails => {
            "1" => {
                blobId => $blobid,
                mailboxIds => {$inboxid =>  JSON::true},
            },
        },
    }, "R1"], ["Email/get", {
        ids => ["#1"],
        properties => ['bodyStructure', 'bodyValues'],
        fetchAllBodyValues => JSON::true,
    }, "R2" ]]);

    $self->assert_str_equals("Email/import", $res->[0][0]);
    $self->assert_str_equals("Email/get", $res->[1][0]);

    my $msg = $res->[1][1]{list}[0];
    my $partId = $msg->{bodyStructure}{partId};
    my $bodyValue = $msg->{bodyValues}{$partId};
    $self->assert_str_equals("This is a test.\n", $bodyValue->{value});
}

sub test_email_get_8bit_headers
    :min_version_3_1 :needs_component_jmap :needs_dependency_chardet
    :NoMunge8Bit :RFC2047_UTF8
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $imap = $self->{store}->get_client();

    # Москва - столица России. - "Moscow is the capital of Russia."
    my $wantSubject =
        "\xd0\x9c\xd0\xbe\xd1\x81\xd0\xba\xd0\xb2\xd0\xb0\x20\x2d\x20\xd1".
        "\x81\xd1\x82\xd0\xbe\xd0\xbb\xd0\xb8\xd1\x86\xd0\xb0\x20\xd0\xa0".
        "\xd0\xbe\xd1\x81\xd1\x81\xd0\xb8\xd0\xb8\x2e";
    utf8::decode($wantSubject) || die $@;

    # Фёдор Михайлович Достоевский - "Fyódor Mikháylovich Dostoyévskiy"
    my $wantName =
        "\xd0\xa4\xd1\x91\xd0\xb4\xd0\xbe\xd1\x80\x20\xd0\x9c\xd0\xb8\xd1".
        "\x85\xd0\xb0\xd0\xb9\xd0\xbb\xd0\xbe\xd0\xb2\xd0\xb8\xd1\x87\x20".
        "\xd0\x94\xd0\xbe\xd1\x81\xd1\x82\xd0\xbe\xd0\xb5\xd0\xb2\xd1\x81".
        "\xd0\xba\xd0\xb8\xd0\xb9";
    utf8::decode($wantName) || die $@;

    my $wantEmail = 'fyodor@local';

    my @testCases = ({
        file => 'data/mime/headers-utf8.bin',
    }, {
        file => 'data/mime/headers-koi8r.bin',
    });

    foreach (@testCases) {
        open(my $F, $_->{file}) || die $!;
        $imap->append('INBOX', $F) || die $@;
        close($F);

        my $res = $jmap->CallMethods([
                ['Email/query', { }, "R1"],
                ['Email/get', {
                        '#ids' => {
                            resultOf => 'R1',
                            name => 'Email/query',
                            path => '/ids'
                        },
                        properties => ['subject', 'from'],
                    }, 'R2' ],
                ['Email/set', {
                        '#destroy' => {
                            resultOf => 'R1',
                            name => 'Email/query',
                            path => '/ids'
                        },
                    }, 'R3' ],
            ]);
        my $email = $res->[1][1]{list}[0];
        $self->assert_str_equals($wantSubject, $email->{subject});
        $self->assert_str_equals($wantName, $email->{from}[0]{name});
        $self->assert_str_equals($wantEmail, $email->{from}[0]{email});
    }
}

sub test_attach_base64_email
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $imap = $self->{store}->get_client();

    open(my $F, 'data/mime/base64-body.eml') || die $!;
    $imap->append('INBOX', $F) || die $@;
    close($F);

    my $res = $jmap->CallMethods([
                ['Email/query', { }, "R1"],
                ['Email/get', {
                        '#ids' => {
                            resultOf => 'R1',
                            name => 'Email/query',
                            path => '/ids'
                        },
                }, "R2"],
                ['Mailbox/get', {}, 'R3'],
    ]);

    my $blobId = $res->[1][1]{list}[0]{blobId};
    my $size = $res->[1][1]{list}[0]{size};
    my $name = $res->[1][1]{list}[0]{subject} . ".eml";

    my $mailboxId = $res->[2][1]{list}[0]{id};

    xlog $self, "Now we create an email which includes this";

    $res = $jmap->CallMethods([
        ['Email/set', { create => { 1 => {
            bcc => undef,
            bodyStructure => {
                subParts => [{
                    partId => "text",
                    type => "text/plain"
                },{
                    blobId => $blobId,
                    cid => undef,
                    disposition => "attachment",
                    name => $name,
                    size => $size,
                    type => "message/rfc822"
                }],
                type => "multipart/mixed",
            },
            bodyValues => {
                text => {
                    isTruncated => $JSON::false,
                    value => "Hello World",
                },
            },
            cc => undef,
            from => [{
                email => "foo\@example.com",
                name => "Captain Foo",
            }],
            keywords => {
                '$draft' => $JSON::true,
                '$seen' => $JSON::true,
            },
            mailboxIds => {
                $mailboxId => $JSON::true,
            },
            messageId => ["9048d4db-bd84-4ea4-9be3-ae4a136c532d\@example.com"],
            receivedAt => "2019-05-09T12:48:08Z",
            references => undef,
            replyTo => undef,
            sentAt => "2019-05-09T14:48:08+02:00",
            subject => "Hello again",
            to => [{
                email => "bar\@example.com",
                name => "Private Bar",
            }],
        }}}, "S1"],
        ['Email/query', { }, "R1"],
        ['Email/get', {
                '#ids' => {
                    resultOf => 'R1',
                    name => 'Email/query',
                    path => '/ids'
                },
        }, "R2"],
    ]);

    $imap->select("INBOX");
    my $ires = $imap->fetch('1:*', '(BODYSTRUCTURE)');

    $self->assert_str_equals('RE: Hello.eml', $ires->{2}{bodystructure}{'MIME-Subparts'}[1]{'Content-Disposition'}{filename});
    $self->assert_str_not_equals('BINARY', $ires->{2}{bodystructure}{'MIME-Subparts'}[1]{'Content-Transfer-Encoding'});

    my ($replyEmail) = grep { $_->{subject} eq 'Hello again' } @{$res->[2][1]{list}};
    $self->assert_str_equals($blobId, $replyEmail->{attachments}[0]{blobId});
}


sub test_misc_upload_sametype
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $lazy = "the quick brown fox jumped over the lazy dog";

    my $data = $jmap->Upload($lazy, "text/plain; charset=us-ascii");
    my $blobid = $data->{blobId};

    $data = $jmap->Upload($lazy, "TEXT/PLAIN; charset=US-Ascii");
    my $blobid2 = $data->{blobId};

    $self->assert_str_equals($blobid, $blobid2);
}

sub test_misc_brokenrfc822_badendline
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $email = <<'EOF';
From: "Some Example Sender" <example@example.com>
To: baseball@vitaead.com
Subject: test email
Date: Wed, 7 Dec 2016 00:21:50 -0500
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

This is a test email.
EOF
    $email =~ s/\r//gs;
    my $data = $jmap->Upload($email, "message/rfc822");
    my $blobid = $data->{blobId};

    xlog $self, "create drafts mailbox";
    my $res = $jmap->CallMethods([
            ['Mailbox/set', { create => { "1" => {
                            name => "drafts",
                            parentId => undef,
                            role => "drafts"
             }}}, "R1"]
    ]);
    my $draftsmbox = $res->[0][1]{created}{"1"}{id};
    $self->assert_not_null($draftsmbox);

    xlog $self, "import email from blob $blobid";
    $res = $jmap->CallMethods([['Email/import', {
            emails => {
                "1" => {
                    blobId => $blobid,
                    mailboxIds => {$draftsmbox =>  JSON::true},
                    keywords => {
                        '$draft' => JSON::true,
                    },
                },
            },
        }, "R1"]]);
    my $error = $@;
    $self->assert_str_equals("invalidEmail", $res->[0][1]{notCreated}{1}{type});
}

sub test_email_import_zerobyte
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    # A bogus email with an unencoded zero byte
    my $email = <<"EOF";
From: \"Some Example Sender\" <example\@local>\r\n
To: baseball\@local\r\n
Subject: test email\r\n
Date: Wed, 7 Dec 2016 22:11:11 +1100\r\n
MIME-Version: 1.0\r\n
Content-Type: text/plain; charset="UTF-8"\r\n
\r\n
This is a test email with a \x{0}-byte.\r\n
EOF

    my $data = $jmap->Upload($email, "message/rfc822");
    my $blobid = $data->{blobId};

    xlog $self, "create drafts mailbox";
    my $res = $jmap->CallMethods([
            ['Mailbox/set', { create => { "1" => {
                            name => "drafts",
                            parentId => undef,
                            role => "drafts"
             }}}, "R1"]
    ]);
    my $draftsmbox = $res->[0][1]{created}{"1"}{id};
    $self->assert_not_null($draftsmbox);

    xlog $self, "import email from blob $blobid";
    $res = $jmap->CallMethods([['Email/import', {
            emails => {
                "1" => {
                    blobId => $blobid,
                    mailboxIds => {$draftsmbox =>  JSON::true},
                    keywords => {
                        '$draft' => JSON::true,
                    },
                },
            },
        }, "R1"]]);
    $self->assert_str_equals("invalidEmail", $res->[0][1]{notCreated}{1}{type});
}

sub test_email_import_singlecopy
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $email = <<'EOF';
From: "Some Example Sender" <example@example.com>
To: baseball@vitaead.com
Subject: test email
Date: Wed, 7 Dec 2016 22:11:11 +1100
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

This is a test email.
EOF
    $email =~ s/\r?\n/\r\n/gs;
    my $data = $jmap->Upload($email, "message/rfc822");
    my $blobid = $data->{blobId};

    xlog $self, "create drafts mailbox";
    my $res = $jmap->CallMethods([
            ['Mailbox/set', { create => { "1" => {
                            name => "drafts",
                            parentId => undef,
                            role => "drafts"
             }}}, "R1"]
    ]);
    my $draftsmbox = $res->[0][1]{created}{"1"}{id};
    $self->assert_not_null($draftsmbox);

    xlog $self, "import email from blob $blobid";
    $res = eval {
        $jmap->CallMethods([['Email/import', {
            emails => {
                "1" => {
                    blobId => $blobid,
                    mailboxIds => {$draftsmbox =>  JSON::true},
                    keywords => {
                        '$draft' => JSON::true,
                    },
                },
            },
        }, "R1"]]);
    };

    $self->assert_str_equals("Email/import", $res->[0][0]);
    my $msg = $res->[0][1]->{created}{"1"};
    $self->assert_not_null($msg);

    my $basedir = $self->{instance}->{basedir};

    my @jstat = stat("$basedir/data/user/cassandane/\#jmap/1.");
    my @dstat = stat("$basedir/data/user/cassandane/drafts/1.");

    xlog $self, "sizes match";
    $self->assert_num_equals($jstat[7], $dstat[7]);
    xlog $self, "same device";
    $self->assert_num_equals($jstat[0], $dstat[0]);
    xlog $self, "same inode"; # single instance store
    $self->assert_num_equals($jstat[1], $dstat[1]);
}


sub test_email_import_setdate
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $email = <<'EOF';
From: "Some Example Sender" <example@example.com>
To: baseball@vitaead.com
Subject: test email
Date: Wed, 7 Dec 2016 22:11:11 +1100
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

This is a test email.
EOF
    $email =~ s/\r?\n/\r\n/gs;
    my $data = $jmap->Upload($email, "message/rfc822");
    my $blobid = $data->{blobId};

    xlog $self, "create drafts mailbox";
    my $res = $jmap->CallMethods([
            ['Mailbox/set', { create => { "1" => {
                            name => "drafts",
                            parentId => undef,
                            role => "drafts"
             }}}, "R1"]
    ]);
    my $draftsmbox = $res->[0][1]{created}{"1"}{id};
    $self->assert_not_null($draftsmbox);

    my $receivedAt = '2016-12-10T01:02:03Z';
    xlog $self, "import email from blob $blobid";
    $res = eval {
        $jmap->CallMethods([['Email/import', {
            emails => {
                "1" => {
                    blobId => $blobid,
                    mailboxIds => {$draftsmbox =>  JSON::true},
                    keywords => {
                        '$draft' => JSON::true,
                    },
                    receivedAt => $receivedAt,
                },
            },
        }, "R1"], ['Email/get', {ids => ["#1"]}, "R2"]]);
    };

    $self->assert_str_equals("Email/import", $res->[0][0]);
    my $msg = $res->[0][1]->{created}{"1"};
    $self->assert_not_null($msg);

    my $sentAt = '2016-12-07T22:11:11+11:00';
    $self->assert_str_equals("Email/get", $res->[1][0]);
    $self->assert_str_equals($msg->{id}, $res->[1][1]{list}[0]->{id});
    $self->assert_str_equals($receivedAt, $res->[1][1]{list}[0]->{receivedAt});
    $self->assert_str_equals($sentAt, $res->[1][1]{list}[0]->{sentAt});
}

sub test_email_import_mailboxid_by_role
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $email = <<'EOF';
From: "Some Example Sender" <example@example.com>
To: baseball@vitaead.com
Subject: test email
Date: Wed, 7 Dec 2016 22:11:11 +1100
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

This is a test email.
EOF
    $email =~ s/\r?\n/\r\n/gs;
    my $data = $jmap->Upload($email, "message/rfc822");
    my $blobid = $data->{blobId};

    xlog $self, "create drafts mailbox";
    my $res = $jmap->CallMethods([
            ['Mailbox/set', { create => { "1" => {
                            name => "drafts",
                            parentId => undef,
                            role => "drafts"
             }}}, "R1"]
    ]);
    my $draftsMboxId = $res->[0][1]{created}{"1"}{id};
    $self->assert_not_null($draftsMboxId);

    xlog $self, "import email from blob $blobid";
    $res = eval {
        $jmap->CallMethods([['Email/import', {
            emails => {
                "1" => {
                    blobId => $blobid,
                    mailboxIds => {
                        '$drafts'=>  JSON::true
                    },
                    keywords => {
                        '$draft' => JSON::true,
                    },
                },
            },
        }, "R1"], ['Email/get', {ids => ["#1"]}, "R2"]]);
    };

    $self->assert_str_equals("Email/import", $res->[0][0]);
    $self->assert_not_null($res->[1][1]{list}[0]->{mailboxIds}{$draftsMboxId});
}

sub test_email_import_issue2918
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $file = abs_path('data/mime/issue2918.eml');
    open(FH, "<$file");
    local $/ = undef;
    my $binary = <FH>;
    close(FH);
    my $data = $jmap->Upload($binary, "message/rfc822");
    my $blobId = $data->{blobId};

    # Not crashing here is enough.

    my $res = $jmap->CallMethods([
		['Email/import', {
			emails => {
				"1" => {
					blobId => $blobId,
					mailboxIds => {
						'$inbox' =>  JSON::true},
				},
			},
		}, "R1"]
	]);
}

sub test_thread_get_onemsg
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my %exp;
    my $jmap = $self->{jmap};
    my $res;
    my $draftsmbox;
    my $state;
    my $threadA;
    my $threadB;

    my $imaptalk = $self->{store}->get_client();

    xlog $self, "create drafts mailbox";
    $res = $jmap->CallMethods([
            ['Mailbox/set', { create => { "1" => {
                            name => "drafts",
                            parentId => undef,
                            role => "drafts"
             }}}, "R1"]
    ]);
    $draftsmbox = $res->[0][1]{created}{"1"}{id};
    $self->assert_not_null($draftsmbox);

    xlog $self, "get thread state";
    $res = $jmap->CallMethods([['Thread/get', { ids => [ 'no' ] }, "R1"]]);
    $state = $res->[0][1]->{state};
    $self->assert_not_null($state);

    my $email = <<'EOF';
Return-Path: <Hannah.Smith@gmail.com>
Received: from gateway (gateway.vmtom.com [10.0.0.1])
    by ahost (ahost.vmtom.com[10.0.0.2]); Wed, 07 Dec 2016 11:43:25 +1100
Received: from mail.gmail.com (mail.gmail.com [192.168.0.1])
    by gateway.vmtom.com (gateway.vmtom.com [10.0.0.1]); Wed, 07 Dec 2016 11:43:25 +1100
Mime-Version: 1.0
Content-Type: text/plain; charset="us-ascii"
Content-Transfer-Encoding: 7bit
Subject: Email A
From: Hannah V. Smith <Hannah.Smith@gmail.com>
Message-ID: <fake.1481071405.58492@gmail.com>
Date: Wed, 07 Dec 2016 11:43:25 +1100
To: Test User <test@vmtom.com>
X-Cassandane-Unique: 294f71c341218d36d4bda75aad56599b7be3d15b

a
EOF
    $email =~ s/\r?\n/\r\n/gs;
    my $data = $jmap->Upload($email, "message/rfc822");
    my $blobid = $data->{blobId};
    xlog $self, "import email from blob $blobid";
    $res = $jmap->CallMethods([['Email/import', {
        emails => {
            "1" => {
                blobId => $blobid,
                mailboxIds => {$draftsmbox =>  JSON::true},
                keywords => {
                    '$draft' => JSON::true,
                },
            },
        },
    }, "R1"]]);

    xlog $self, "get thread updates";
    $res = $jmap->CallMethods([['Thread/changes', { sinceState => $state }, "R1"]]);
    $self->assert_equals(JSON::false, $res->[0][1]->{hasMoreChanges});
}

sub test_thread_changes
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my %exp;
    my $jmap = $self->{jmap};
    my $res;
    my %params;
    my $dt;
    my $draftsmbox;
    my $state;
    my $threadA;
    my $threadB;

    my $imaptalk = $self->{store}->get_client();

    xlog $self, "create drafts mailbox";
    $res = $jmap->CallMethods([
            ['Mailbox/set', { create => { "1" => {
                            name => "drafts",
                            parentId => undef,
                            role => "drafts"
             }}}, "R1"]
    ]);
    $draftsmbox = $res->[0][1]{created}{"1"}{id};
    $self->assert_not_null($draftsmbox);

    xlog $self, "Generate an email in drafts via IMAP";
    $self->{store}->set_folder("INBOX.drafts");
    $self->make_message("Email A") || die;

    xlog $self, "get thread state";
    $res = $jmap->CallMethods([
        ['Email/query', { }, "R1"],
        ['Email/get', { '#ids' => { resultOf => 'R1', name => 'Email/query', path => '/ids' } }, 'R2' ],
    ]);
    $res = $jmap->CallMethods([
        ['Thread/get', { 'ids' => [ $res->[1][1]{list}[0]{threadId} ] }, 'R1'],
    ]);
    $state = $res->[0][1]->{state};
    $self->assert_not_null($state);

    xlog $self, "get thread updates";
    $res = $jmap->CallMethods([['Thread/changes', { sinceState => $state }, "R1"]]);
    $self->assert_str_equals($state, $res->[0][1]->{oldState});
    $self->assert_str_equals($state, $res->[0][1]->{newState});
    $self->assert_equals(JSON::false, $res->[0][1]->{hasMoreChanges});
    $self->assert_deep_equals([], $res->[0][1]{created});
    $self->assert_deep_equals([], $res->[0][1]{updated});
    $self->assert_deep_equals([], $res->[0][1]{destroyed});

    xlog $self, "generating email A";
    $dt = DateTime->now();
    $dt->add(DateTime::Duration->new(hours => -3));
    $exp{A} = $self->make_message("Email A", date => $dt, body => "a");
    $exp{A}->set_attributes(uid => 1, cid => $exp{A}->make_cid());

    xlog $self, "get thread updates";
    $res = $jmap->CallMethods([['Thread/changes', { sinceState => $state }, "R1"]]);
    $self->assert_str_equals($state, $res->[0][1]->{oldState});
    $self->assert_str_not_equals($state, $res->[0][1]->{newState});
    $self->assert_equals(JSON::false, $res->[0][1]->{hasMoreChanges});
    $self->assert_num_equals(1, scalar @{$res->[0][1]{created}});
    $self->assert_deep_equals([], $res->[0][1]{updated});
    $self->assert_deep_equals([], $res->[0][1]{destroyed});
    $state = $res->[0][1]->{newState};
    $threadA = $res->[0][1]{created}[0];

    xlog $self, "generating email C referencing A";
    $dt = DateTime->now();
    $dt->add(DateTime::Duration->new(hours => -2));
    $exp{C} = $self->make_message("Re: Email A", references => [ $exp{A} ], date => $dt, body => "c");
    $exp{C}->set_attributes(uid => 3, cid => $exp{A}->get_attribute('cid'));

    xlog $self, "get thread updates";
    $res = $jmap->CallMethods([['Thread/changes', { sinceState => $state }, "R1"]]);
    $self->assert_str_equals($state, $res->[0][1]->{oldState});
    $self->assert_str_not_equals($state, $res->[0][1]->{newState});
    $self->assert_equals(JSON::false, $res->[0][1]->{hasMoreChanges});
    $self->assert_deep_equals([], $res->[0][1]{created});
    $self->assert_num_equals(1, scalar @{$res->[0][1]{updated}});
    $self->assert_str_equals($threadA, $res->[0][1]{updated}[0]);
    $self->assert_deep_equals([], $res->[0][1]{destroyed});
    $state = $res->[0][1]->{newState};

    xlog $self, "get thread updates (expect no changes)";
    $res = $jmap->CallMethods([['Thread/changes', { sinceState => $state }, "R1"]]);
    $self->assert_str_equals($state, $res->[0][1]->{oldState});
    $self->assert_str_equals($state, $res->[0][1]->{newState});
    $self->assert_equals(JSON::false, $res->[0][1]->{hasMoreChanges});
    $self->assert_deep_equals([], $res->[0][1]{created});
    $self->assert_deep_equals([], $res->[0][1]{updated});
    $self->assert_deep_equals([], $res->[0][1]{destroyed});

    xlog $self, "generating email B";
    $exp{B} = $self->make_message("Email B", body => "b");
    $exp{B}->set_attributes(uid => 2, cid => $exp{B}->make_cid());

    xlog $self, "generating email D referencing A";
    $dt = DateTime->now();
    $dt->add(DateTime::Duration->new(hours => -1));
    $exp{D} = $self->make_message("Re: Email A", references => [ $exp{A} ], date => $dt, body => "d");
    $exp{D}->set_attributes(uid => 4, cid => $exp{A}->get_attribute('cid'));

    xlog $self, "generating email E referencing A";
    $dt = DateTime->now();
    $dt->add(DateTime::Duration->new(minutes => -30));
    $exp{E} = $self->make_message("Re: Email A", references => [ $exp{A} ], date => $dt, body => "e");
    $exp{E}->set_attributes(uid => 5, cid => $exp{A}->get_attribute('cid'));

    xlog $self, "get max 1 thread updates";
    $res = $jmap->CallMethods([['Thread/changes', { sinceState => $state, maxChanges => 1 }, "R1"]]);
    $self->assert_str_equals($state, $res->[0][1]->{oldState});
    $self->assert_str_not_equals($state, $res->[0][1]->{newState});
    $self->assert_equals(JSON::true, $res->[0][1]->{hasMoreChanges});
    $self->assert_num_equals(1, scalar @{$res->[0][1]{created}});
    $self->assert_str_not_equals($threadA, $res->[0][1]{created}[0]);
    $self->assert_deep_equals([], $res->[0][1]{updated});
    $self->assert_deep_equals([], $res->[0][1]{destroyed});
    $state = $res->[0][1]->{newState};
    $threadB = $res->[0][1]{created}[0];

    xlog $self, "get max 2 thread updates";
    $res = $jmap->CallMethods([['Thread/changes', { sinceState => $state, maxChanges => 2 }, "R1"]]);
    $self->assert_str_equals($state, $res->[0][1]->{oldState});
    $self->assert_str_not_equals($state, $res->[0][1]->{newState});
    $self->assert_equals(JSON::false, $res->[0][1]->{hasMoreChanges});
    $self->assert_deep_equals([], $res->[0][1]{created});
    $self->assert_num_equals(1, scalar @{$res->[0][1]{updated}});
    $self->assert_str_equals($threadA, $res->[0][1]{updated}[0]);
    $self->assert_deep_equals([], $res->[0][1]{destroyed});
    $state = $res->[0][1]->{newState};

    xlog $self, "fetch emails";
    $res = $jmap->CallMethods([
        ['Email/query', { }, "R1"],
        ['Email/get', {
            '#ids' => {
                resultOf => 'R1',
                name => 'Email/query',
                path => '/ids'
            },
            fetchAllBodyValues => JSON::true,
        }, 'R2' ],
    ]);

    # Map messages by body contents
    my %m = map { $_->{bodyValues}{$_->{textBody}[0]{partId}}{value} => $_ } @{$res->[1][1]{list}};
    my $msgA = $m{"a"};
    my $msgB = $m{"b"};
    my $msgC = $m{"c"};
    my $msgD = $m{"d"};
    my $msgE = $m{"e"};
    $self->assert_not_null($msgA);
    $self->assert_not_null($msgB);
    $self->assert_not_null($msgC);
    $self->assert_not_null($msgD);
    $self->assert_not_null($msgE);

    xlog $self, "destroy email b, update email d";
    $res = $jmap->CallMethods([['Email/set', {
        destroy => [ $msgB->{id} ],
        update =>  { $msgD->{id} => { 'keywords/$foo' => JSON::true }},
    }, "R1"]]);
    $self->assert_str_equals($msgB->{id}, $res->[0][1]{destroyed}[0]);
    $self->assert(exists $res->[0][1]->{updated}{$msgD->{id}});

    xlog $self, "get thread updates";
    $res = $jmap->CallMethods([['Thread/changes', { sinceState => $state }, "R1"]]);
    $self->assert_str_equals($state, $res->[0][1]->{oldState});
    $self->assert_str_not_equals($state, $res->[0][1]->{newState});
    $self->assert_equals(JSON::false, $res->[0][1]->{hasMoreChanges});
    $self->assert_deep_equals([], $res->[0][1]{created});
    $self->assert_num_equals(1, scalar @{$res->[0][1]{updated}});
    $self->assert_str_equals($threadA, $res->[0][1]{updated}[0]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]{destroyed}});
    $self->assert_str_equals($threadB, $res->[0][1]{destroyed}[0]);
    $state = $res->[0][1]->{newState};

    xlog $self, "destroy emails c and e";
    $res = $jmap->CallMethods([['Email/set', {
        destroy => [ $msgC->{id}, $msgE->{id} ],
    }, "R1"]]);
    $self->assert_num_equals(2, scalar @{$res->[0][1]{destroyed}});

    xlog $self, "get thread updates, fetch threads";
    $res = $jmap->CallMethods([
        ['Thread/changes', { sinceState => $state }, "R1"],
        ['Thread/get', { '#ids' => { resultOf => 'R1', name => 'Thread/changes', path => '/updated' }}, 'R2'],
    ]);
    $self->assert_str_equals($state, $res->[0][1]->{oldState});
    $self->assert_str_not_equals($state, $res->[0][1]->{newState});
    $self->assert_equals(JSON::false, $res->[0][1]->{hasMoreChanges});
    $self->assert_deep_equals([], $res->[0][1]{created});
    $self->assert_num_equals(1, scalar @{$res->[0][1]{updated}});
    $self->assert_str_equals($threadA, $res->[0][1]{updated}[0]);
    $self->assert_deep_equals([], $res->[0][1]{destroyed});
    $state = $res->[0][1]->{newState};

    $self->assert_str_equals('Thread/get', $res->[1][0]);
    $self->assert_num_equals(1, scalar @{$res->[1][1]{list}});
    $self->assert_str_equals($threadA, $res->[1][1]{list}[0]->{id});

    xlog $self, "destroy emails a and d";
    $res = $jmap->CallMethods([['Email/set', {
        destroy => [ $msgA->{id}, $msgD->{id} ],
    }, "R1"]]);
    $self->assert_num_equals(2, scalar @{$res->[0][1]{destroyed}});

    xlog $self, "get thread updates";
    $res = $jmap->CallMethods([['Thread/changes', { sinceState => $state }, "R1"]]);
    $self->assert_str_equals($state, $res->[0][1]->{oldState});
    $self->assert_str_not_equals($state, $res->[0][1]->{newState});
    $self->assert_equals(JSON::false, $res->[0][1]->{hasMoreChanges});
    $self->assert_deep_equals([], $res->[0][1]{created});
    $self->assert_deep_equals([], $res->[0][1]{updated});
    $self->assert_num_equals(1, scalar @{$res->[0][1]{destroyed}});
    $self->assert_str_equals($threadA, $res->[0][1]{destroyed}[0]);
    $state = $res->[0][1]->{newState};

    xlog $self, "get thread updates (expect no changes)";
    $res = $jmap->CallMethods([['Thread/changes', { sinceState => $state }, "R1"]]);
    $self->assert_str_equals($state, $res->[0][1]->{oldState});
    $self->assert_str_equals($state, $res->[0][1]->{newState});
    $self->assert_equals(JSON::false, $res->[0][1]->{hasMoreChanges});
    $self->assert_deep_equals([], $res->[0][1]{created});
    $self->assert_deep_equals([], $res->[0][1]{updated});
    $self->assert_deep_equals([], $res->[0][1]{destroyed});
}

sub test_thread_latearrival_drafts
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my %exp;
    my $dt;
    my $res;
    my $state;

    my $jmap = $self->{jmap};

    my $imaptalk = $self->{store}->get_client();

    $dt = DateTime->now();
    $dt->add(DateTime::Duration->new(hours => -8));
    $exp{A} = $self->make_message("Email A", date => $dt, body => 'a') || die;

    xlog $self, "get thread state";
    $res = $jmap->CallMethods([
        ['Email/query', { }, "R1"],
        ['Email/get', { '#ids' => { resultOf => 'R1', name => 'Email/query', path => '/ids' }, properties => ['threadId'] }, 'R2' ],
        ['Thread/get', { '#ids' => { resultOf => 'R2', name => 'Email/get', path => '/list/*/threadId' } }, 'R3'],
    ]);
    $state = $res->[2][1]{state};
    $self->assert_not_null($state);
    my $threadid = $res->[2][1]{list}[0]{id};
    $self->assert_not_null($threadid);

    my $inreplyheader = [['In-Reply-To' => $exp{A}->messageid()]];

    xlog $self, "create drafts mailbox";
    $res = $jmap->CallMethods([
            ['Mailbox/set', { create => { "1" => {
                            name => "drafts",
                            parentId => undef,
                            role => "drafts"
             }}}, "R1"]
    ]);
    my $draftsmbox = $res->[0][1]{created}{"1"}{id};
    $self->assert_not_null($draftsmbox);

    xlog $self, "generating email B";
    $dt = DateTime->now();
    $dt->add(DateTime::Duration->new(hours => -5));
    $exp{B} = $self->make_message("Re: Email A", references => [ $exp{A} ], date => $dt, body => "b");

    xlog $self, "generating email C";
    $dt = DateTime->now();
    $dt->add(DateTime::Duration->new(hours => -2));
    $exp{C} = $self->make_message("Re: Email A", references => [ $exp{A}, $exp{B} ], date => $dt, body => "c");

    xlog $self, "generating email D (before C)";
    $dt = DateTime->now();
    $dt->add(DateTime::Duration->new(hours => -3));
    $exp{D} = $self->make_message("Re: Email A", extra_headers => $inreplyheader, date => $dt, body => "d");

    xlog $self, "Generate draft email E replying to A";
    $self->{store}->set_folder("INBOX.drafts");
    $dt = DateTime->now();
    $dt->add(DateTime::Duration->new(hours => -4));
    $exp{E} = $self->{gen}->generate(subject => "Re: Email A", extra_headers => $inreplyheader, date => $dt, body => "e");
    $self->{store}->write_begin();
    $self->{store}->write_message($exp{E}, flags => ["\\Draft"]);
    $self->{store}->write_end();

    xlog $self, "fetch emails";
    $res = $jmap->CallMethods([
        ['Email/query', { }, "R1"],
        ['Email/get', {
            '#ids' => {
                resultOf => 'R1',
                name => 'Email/query',
                path => '/ids'
            },
            fetchAllBodyValues => JSON::true,
        }, 'R2' ],
    ]);

    # Map messages by body contents
    my %m = map { $_->{bodyValues}{$_->{textBody}[0]{partId}}{value} => $_ } @{$res->[1][1]{list}};
    my $msgA = $m{"a"};
    my $msgB = $m{"b"};
    my $msgC = $m{"c"};
    my $msgD = $m{"d"};
    my $msgE = $m{"e"};
    $self->assert_not_null($msgA);
    $self->assert_not_null($msgB);
    $self->assert_not_null($msgC);
    $self->assert_not_null($msgD);
    $self->assert_not_null($msgE);

    my %map = (
        A => $msgA->{id},
        B => $msgB->{id},
        C => $msgC->{id},
        D => $msgD->{id},
        E => $msgE->{id},
    );

    # check thread ordering
    $res = $jmap->CallMethods([
        ['Thread/get', { 'ids' => [$threadid] }, 'R3'],
    ]);
    $self->assert_deep_equals([$map{A},$map{B},$map{E},$map{D},$map{C}],
                              $res->[0][1]{list}[0]{emailIds});

    # now deliver something late that's earlier than the draft

    xlog $self, "generating email F (late arrival)";
    $dt = DateTime->now();
    $dt->add(DateTime::Duration->new(hours => -6));
    $exp{F} = $self->make_message("Re: Email A", references => [ $exp{A} ], date => $dt, body => "f");

    xlog $self, "fetch emails";
    $res = $jmap->CallMethods([
        ['Email/query', { }, "R1"],
        ['Email/get', {
            '#ids' => {
                resultOf => 'R1',
                name => 'Email/query',
                path => '/ids'
            },
            fetchAllBodyValues => JSON::true,
        }, 'R2' ],
    ]);

    # Map messages by body contents
    %m = map { $_->{bodyValues}{$_->{textBody}[0]{partId}}{value} => $_ } @{$res->[1][1]{list}};
    my $msgF = $m{"f"};
    $self->assert_not_null($msgF);

    $map{F} = $msgF->{id};

    # check thread ordering - this message should appear after F and before B
    $res = $jmap->CallMethods([
        ['Thread/get', { 'ids' => [$threadid] }, 'R3'],
    ]);
    $self->assert_deep_equals([$map{A},$map{F},$map{B},$map{E},$map{D},$map{C}],
                              $res->[0][1]{list}[0]{emailIds});
}

sub test_email_import
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();

    my $inbox = $self->getinbox()->{id};
    $self->assert_not_null($inbox);

    # Generate an embedded email to get a blob id
    xlog $self, "Generate a email in INBOX via IMAP";
    $self->make_message("foo",
        mime_type => "multipart/mixed",
        mime_boundary => "sub",
        body => ""
          . "--sub\r\n"
          . "Content-Type: text/plain; charset=UTF-8\r\n"
          . "Content-Disposition: inline\r\n" . "\r\n"
          . "some text"
          . "\r\n--sub\r\n"
          . "Content-Type: message/rfc822\r\n"
          . "\r\n"
          . "Return-Path: <Ava.Nguyen\@local>\r\n"
          . "Mime-Version: 1.0\r\n"
          . "Content-Type: text/plain\r\n"
          . "Content-Transfer-Encoding: 7bit\r\n"
          . "Subject: bar\r\n"
          . "From: Ava T. Nguyen <Ava.Nguyen\@local>\r\n"
          . "Message-ID: <fake.1475639947.6507\@local>\r\n"
          . "Date: Wed, 05 Oct 2016 14:59:07 +1100\r\n"
          . "To: Test User <test\@local>\r\n"
          . "\r\n"
          . "An embedded email"
          . "\r\n--sub--\r\n",
    ) || die;

    xlog $self, "get blobId";
    my $res = $jmap->CallMethods([
        ['Email/query', { }, "R1"],
        ['Email/get', {
            '#ids' => { resultOf => 'R1', name => 'Email/query', path => '/ids' },
            properties => ['attachments'],
        }, 'R2' ],
    ]);
    my $blobid = $res->[1][1]->{list}[0]->{attachments}[0]{blobId};
    $self->assert_not_null($blobid);

    xlog $self, "create drafts mailbox";
    $res = $jmap->CallMethods([
            ['Mailbox/set', { create => { "1" => {
                            name => "drafts",
                            parentId => undef,
                            role => "drafts"
             }}}, "R1"]
    ]);
    my $drafts = $res->[0][1]{created}{"1"}{id};
    $self->assert_not_null($drafts);

    xlog $self, "import and get email from blob $blobid";
    $res = $jmap->CallMethods([['Email/import', {
        emails => {
            "1" => {
                blobId => $blobid,
                mailboxIds => {$drafts =>  JSON::true},
                keywords => { '$draft' => JSON::true },
            },
        },
    }, "R1"], ["Email/get", { ids => ["#1"] }, "R2" ]]);

    $self->assert_str_equals("Email/import", $res->[0][0]);
    my $msg = $res->[0][1]->{created}{"1"};
    $self->assert_not_null($msg);

    $self->assert_str_equals("Email/get", $res->[1][0]);
    $self->assert_str_equals($msg->{id}, $res->[1][1]{list}[0]->{id});

    xlog $self, "load email";
    $res = $jmap->CallMethods([['Email/get', { ids => [$msg->{id}] }, "R1"]]);
    $self->assert_num_equals(1, scalar keys %{$res->[0][1]{list}[0]->{mailboxIds}});
    $self->assert_not_null($res->[0][1]{list}[0]->{mailboxIds}{$drafts});

    xlog $self, "import existing email (expect email exists error)";
    $res = $jmap->CallMethods([['Email/import', {
        emails => {
            "1" => {
                blobId => $blobid,
                mailboxIds => {$drafts =>  JSON::true, $inbox => JSON::true},
                keywords => { '$draft' => JSON::true },
            },
        },
    }, "R1"]]);
    $self->assert_str_equals("Email/import", $res->[0][0]);
    $self->assert_str_equals("alreadyExists", $res->[0][1]->{notCreated}{"1"}{type});
    $self->assert_not_null($res->[0][1]->{notCreated}{"1"}{existingId});
}

sub test_email_import_error
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();

    my $inboxid = $self->getinbox()->{id};

    my $res = $jmap->CallMethods([['Email/import', { emails => "nope" }, 'R1' ]]);
    $self->assert_str_equals('error', $res->[0][0]);
    $self->assert_str_equals('invalidArguments', $res->[0][1]{type});
    $self->assert_str_equals('emails', $res->[0][1]{arguments}[0]);

    $res = $jmap->CallMethods([['Email/import', { emails => { 1 => "nope" }}, 'R1' ]]);
    $self->assert_str_equals('error', $res->[0][0]);
    $self->assert_str_equals('invalidArguments', $res->[0][1]{type});
    $self->assert_str_equals('emails/1', $res->[0][1]{arguments}[0]);

    $res = $jmap->CallMethods([['Email/import', {
        emails => {
            "1" => {
                blobId => "nope",
                mailboxIds => {$inboxid =>  JSON::true},
            },
        },
    }, "R1"]]);

    $self->assert_str_equals('Email/import', $res->[0][0]);
    $self->assert_str_equals('invalidProperties', $res->[0][1]{notCreated}{1}{type});
    $self->assert_str_equals('blobId', $res->[0][1]{notCreated}{1}{properties}[0]);
}


sub test_email_import_shared
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $admintalk = $self->{adminstore}->get_client();

    # Create user and share mailbox
    xlog $self, "create shared mailbox";
    $self->{instance}->create_user("foo");
    $admintalk->setacl("user.foo", "cassandane", "lkrwpsintex") or die;

    my $email = <<'EOF';
From: "Some Example Sender" <example@example.com>
To: baseball@vitaead.com
Subject: test email
Date: Wed, 7 Dec 2016 22:11:11 +1100
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

This is a test email.
EOF
    $email =~ s/\r?\n/\r\n/gs;
    my $data = $jmap->Upload($email, "message/rfc822", "foo");
    my $blobid = $data->{blobId};

    my $mboxid = $self->getinbox({accountId => 'foo'})->{id};

    my $req = ['Email/import', {
                accountId => 'foo',
                emails => {
                    "1" => {
                        blobId => $blobid,
                        mailboxIds => {$mboxid =>  JSON::true},
                        keywords => {  },
                    },
                },
            }, "R1"
    ];

    xlog $self, "import email from blob $blobid";
    my $res = eval { $jmap->CallMethods([$req]) };
    $self->assert(exists $res->[0][1]->{created}{"1"});
}

sub test_email_import_has_attachment
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();

    my $emailSimple = <<'EOF';
From: example@example.com
To: example@example.biz
Subject: This is a test
Message-Id: <15288246899.CBDb71cE.3455@cyrus-dev>
Date: Tue, 12 Jun 2018 13:31:29 -0400
MIME-Version: 1.0

This is a very simple message.
EOF
    $emailSimple =~ s/\r?\n/\r\n/gs;
    my $blobIdSimple = $jmap->Upload($emailSimple, "message/rfc822")->{blobId};

    my $emailMixed = <<'EOF';
From: example@example.com
To: example@example.biz
Subject: This is a test
Message-Id: <15288246899.CBDb71cE.3455@cyrus-dev>
Date: Tue, 12 Jun 2018 13:31:29 -0400
MIME-Version: 1.0
Content-Type: multipart/mixed;boundary=123456789

--123456789
Content-Type: text/plain

This is a mixed message.

--123456789
Content-Type: application/data

data

--123456789--
EOF
    $emailMixed =~ s/\r?\n/\r\n/gs;
    my $blobIdMixed = $jmap->Upload($emailMixed, "message/rfc822")->{blobId};

    my $inboxId = $self->getinbox()->{id};

    my $res = $jmap->CallMethods([['Email/import', {
        emails => {
            "1" => {
                blobId => $blobIdSimple,
                mailboxIds => {$inboxId =>  JSON::true},
            },
            "2" => {
                blobId => $blobIdMixed,
                mailboxIds => {$inboxId =>  JSON::true},
            },
        },
    }, "R1"], ["Email/get", { ids => ["#1", "#2"] }, "R2" ]]);

    my $msgSimple = $res->[1][1]{list}[0];
    $self->assert_equals(JSON::false, $msgSimple->{hasAttachment});
    my $msgMixed = $res->[1][1]{list}[1];
    $self->assert_equals(JSON::true, $msgMixed->{hasAttachment});
}

sub test_misc_refobjects_simple
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();

    xlog $self, "get email state";
    my $res = $jmap->CallMethods([['Email/get', { ids => [] }, "R1"]]);
    my $state = $res->[0][1]->{state};
    $self->assert_not_null($state);

    xlog $self, "Generate a email in INBOX via IMAP";
    $self->make_message("Email A") || die;

    xlog $self, "get email updates and email using reference";
    $res = $jmap->CallMethods([
        ['Email/changes', {
            sinceState => $state,
        }, 'R1'],
        ['Email/get', {
            '#ids' => {
                resultOf => 'R1',
                name => 'Email/changes',
                path => '/created',
            },
        }, 'R2'],
    ]);

    # assert that the changed id equals the id of the returned email
    $self->assert_str_equals($res->[0][1]{created}[0], $res->[1][1]{list}[0]{id});
}

sub test_email_import_no_keywords
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $email = <<'EOF';
From: "Some Example Sender" <example@example.com>
To: baseball@vitaead.com
Subject: test email
Date: Wed, 7 Dec 2016 22:11:11 +1100
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

This is a test email.
EOF
    $email =~ s/\r?\n/\r\n/gs;
    my $data = $jmap->Upload($email, "message/rfc822");
    my $blobid = $data->{blobId};

    my $mboxid = $self->getinbox()->{id};

    my $req = ['Email/import', {
                emails => {
                    "1" => {
                        blobId => $blobid,
                        mailboxIds => {$mboxid =>  JSON::true},
                    },
                },
            }, "R1"
    ];
    xlog $self, "import email from blob $blobid";
    my $res = eval { $jmap->CallMethods([$req]) };
    $self->assert(exists $res->[0][1]->{created}{"1"});
}

sub test_misc_refobjects_extended
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();

    xlog $self, "Generate a email in INBOX via IMAP";
    foreach my $i (1..10) {
        $self->make_message("Email$i") || die;
    }

    xlog $self, "get email properties using reference";
    my $res = $jmap->CallMethods([
        ['Email/query', {
            sort => [{ property => 'receivedAt', isAscending => JSON::false }],
            collapseThreads => JSON::true,
            position => 0,
            limit => 10,
        }, 'R1'],
        ['Email/get', {
            '#ids' => {
                resultOf => 'R1',
                name => 'Email/query',
                path => '/ids',
            },
            properties => [ 'threadId' ],
        }, 'R2'],
        ['Thread/get', {
            '#ids' => {
                resultOf => 'R2',
                name => 'Email/get',
                path => '/list/*/threadId',
            },
        }, 'R3'],
    ]);
    $self->assert_num_equals(10, scalar @{$res->[2][1]{list}});
}

sub test_email_set_patch
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();

    my $res = $jmap->CallMethods([['Mailbox/get', { }, "R1"]]);
    my $inboxid = $res->[0][1]{list}[0]{id};

    my $draft =  {
        mailboxIds => { $inboxid => JSON::true },
        from => [ { name => "Yosemite Sam", email => "sam\@acme.local" } ] ,
        to => [ { name => "Bugs Bunny", email => "bugs\@acme.local" }, ],
        subject => "Memo",
        textBody => [{ partId => '1' }],
        bodyValues => { '1' => { value => "Whoa!" }},
        keywords => { '$draft' => JSON::true, foo => JSON::true },
    };

    xlog $self, "Create draft email";
    $res = $jmap->CallMethods([
        ['Email/set', { create => { "1" => $draft }}, "R1"],
    ]);
    my $id = $res->[0][1]{created}{"1"}{id};

    $res = $jmap->CallMethods([
        ['Email/get', { 'ids' => [$id] }, 'R2' ]
    ]);
    my $msg = $res->[0][1]->{list}[0];
    $self->assert_equals(JSON::true, $msg->{keywords}->{'$draft'});
    $self->assert_equals(JSON::true, $msg->{keywords}->{'foo'});
    $self->assert_num_equals(2, scalar keys %{$msg->{keywords}});
    $self->assert_equals(JSON::true, $msg->{mailboxIds}->{$inboxid});
    $self->assert_num_equals(1, scalar keys %{$msg->{mailboxIds}});

    xlog $self, "Patch email keywords";
    $res = $jmap->CallMethods([
        ['Email/set', {
            update => {
                $id => {
                    "keywords/foo" => undef,
                    "keywords/bar" => JSON::true,
                }
            },
        }, "R1"],
        ['Email/get', { ids => [$id], properties => ['keywords'] }, 'R2'],
    ]);

    $msg = $res->[1][1]->{list}[0];
    $self->assert_equals(JSON::true, $msg->{keywords}->{'$draft'});
    $self->assert_equals(JSON::true, $msg->{keywords}->{'bar'});
    $self->assert_num_equals(2, scalar keys %{$msg->{keywords}});

    xlog $self, "create mailbox";
    $res = $jmap->CallMethods([['Mailbox/set', {create => { "1" => { name => "baz", }}}, "R1"]]);
    my $mboxid = $res->[0][1]{created}{"1"}{id};
    $self->assert_not_null($mboxid);

    xlog $self, "Patch email mailboxes";
    $res = $jmap->CallMethods([
        ['Email/set', {
            update => {
                $id => {
                    "mailboxIds/$inboxid" => undef,
                    "mailboxIds/$mboxid" => JSON::true,
                }
            },
        }, "R1"],
        ['Email/get', { ids => [$id], properties => ['mailboxIds'] }, 'R2'],
    ]);
    $msg = $res->[1][1]->{list}[0];
    $self->assert_equals(JSON::true, $msg->{mailboxIds}->{$mboxid});
    $self->assert_num_equals(1, scalar keys %{$msg->{mailboxIds}});
}

sub test_misc_set_oldstate
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    # Assert that /set returns oldState (null, or a string)
    # See https://github.com/cyrusimap/cyrus-imapd/issues/2260

    xlog $self, "create drafts mailbox and email";
    my $res = $jmap->CallMethods([
            ['Mailbox/set', {
                create => { "1" => {
                    name => "drafts",
                    parentId => undef,
                    role => "drafts"
                }}
            }, "R1"],
    ]);
    $self->assert(exists $res->[0][1]{oldState});
    my $draftsmbox = $res->[0][1]{created}{"1"}{id};

    my $draft =  {
        mailboxIds => { $draftsmbox => JSON::true },
        from => [ { name => "Yosemite Sam", email => "sam\@acme.local" } ] ,
        to => [
            { name => "Bugs Bunny", email => "bugs\@acme.local" },
        ],
        subject => "foo",
        textBody => [{partId => '1' }],
        bodyValues => { 1 => { value => "bar" }},
        keywords => { '$draft' => JSON::true },
    };

    xlog $self, "create a draft";
    $res = $jmap->CallMethods([['Email/set', { create => { "1" => $draft }}, "R1"]]);
    $self->assert(exists $res->[0][1]{oldState});
    my $msgid = $res->[0][1]{created}{"1"}{id};

    $res = $jmap->CallMethods( [ [ 'Identity/get', {}, "R1" ] ] );
    my $identityid = $res->[0][1]->{list}[0]->{id};

    xlog $self, "create email submission";
    $res = $jmap->CallMethods( [ [ 'EmailSubmission/set', {
        create => {
            '1' => {
                identityId => $identityid,
                emailId  => $msgid,
            }
       }
    }, "R1" ] ] );
    $self->assert(exists $res->[0][1]{oldState});
}

sub test_email_set_text_crlf
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $inboxid = $self->getinbox()->{id};

    my $text = "ab\r\ncde\rfgh\nij";
    my $want = "ab\ncdefgh\nij";

    my $email =  {
        mailboxIds => { $inboxid => JSON::true },
        from => [ { email => q{test1@robmtest.vm}, name => q{} } ],
        to => [ {
            email => q{foo@bar.com},
            name => "foo",
        } ],
        textBody => [{partId => '1'}],
        bodyValues => {1 => { value => $text }},
    };

    xlog $self, "create and get email";
    my $res = $jmap->CallMethods([
        ['Email/set', { create => { "1" => $email }}, "R1"],
        ['Email/get', { ids => [ "#1" ], fetchAllBodyValues => JSON::true }, "R2" ],
    ]);
    my $ret = $res->[1][1]->{list}[0];
    my $got = $ret->{bodyValues}{$ret->{textBody}[0]{partId}}{value};
    $self->assert_str_equals($want, $got);
}

sub test_email_set_text_split
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $inboxid = $self->getinbox()->{id};

    my $text = "x" x 2000;

    my $email =  {
        mailboxIds => { $inboxid => JSON::true },
        from => [ { email => q{test1@robmtest.vm}, name => q{} } ],
        to => [ {
            email => q{foo@bar.com},
            name => "foo",
        } ],
        textBody => [{partId => '1'}],
        bodyValues => {1 => { value => $text }},
    };

    xlog $self, "create and get email";
    my $res = $jmap->CallMethods([
        ['Email/set', { create => { "1" => $email }}, "R1"],
        ['Email/get', { ids => [ "#1" ], fetchAllBodyValues => JSON::true }, "R2" ],
    ]);
    my $ret = $res->[1][1]->{list}[0];
    my $got = $ret->{bodyValues}{$ret->{textBody}[0]{partId}}{value};
}

sub test_email_get_attachedemails
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();
    my $inbox = 'INBOX';

    xlog $self, "Generate a email in $inbox via IMAP";
    my %exp_sub;
    $store->set_folder($inbox);
    $store->_select();
    $self->{gen}->set_next_uid(1);

    my $body = "".
    "--sub\r\n".
    "Content-Type: text/plain; charset=UTF-8\r\n".
    "Content-Disposition: inline\r\n".
    "\r\n".
    "Short text". # Exactly 10 byte long body
    "\r\n--sub\r\n".
    "Content-Type: message/rfc822\r\n".
    "\r\n" .
    "Return-Path: <Ava.Nguyen\@local>\r\n".
    "Mime-Version: 1.0\r\n".
    "Content-Type: text/plain\r\n".
    "Content-Transfer-Encoding: 7bit\r\n".
    "Subject: bar\r\n".
    "From: Ava T. Nguyen <Ava.Nguyen\@local>\r\n".
    "Message-ID: <fake.1475639947.6507\@local>\r\n".
    "Date: Wed, 05 Oct 2016 14:59:07 +1100\r\n".
    "To: Test User <test\@local>\r\n".
    "\r\n".
    "Jeez....an embedded email".
    "\r\n--sub--\r\n";

    $exp_sub{A} = $self->make_message("foo",
        mime_type => "multipart/mixed",
        mime_boundary => "sub",
        body => $body
    );
    $talk->store('1', '+flags', '($HasAttachment)');

    xlog $self, "get email list";
    my $res = $jmap->CallMethods([['Email/query', {}, "R1"]]);
    my $ids = $res->[0][1]->{ids};

    xlog $self, "get email";
    $res = $jmap->CallMethods([['Email/get', { ids => $ids }, "R1"]]);
    my $msg = $res->[0][1]{list}[0];

    $self->assert_num_equals(1, scalar @{$msg->{attachments}});
    $self->assert_str_equals("message/rfc822", $msg->{attachments}[0]{type});
}

sub test_email_get_maxbodyvaluebytes_utf8
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();

    # A body containing a three-byte, two-byte and one-byte UTF-8 char
    my $body = "\N{EURO SIGN}\N{CENT SIGN}\N{DOLLAR SIGN}";
    my @wantbodies = (
        [1, ""],
        [2, ""],
        [3, "\N{EURO SIGN}"],
        [4, "\N{EURO SIGN}"],
        [5, "\N{EURO SIGN}\N{CENT SIGN}"],
        [6, "\N{EURO SIGN}\N{CENT SIGN}\N{DOLLAR SIGN}"],
    );

    utf8::encode($body);
    my %params = (
        mime_charset => "utf-8",
        body => $body
    );
    $self->make_message("1", %params) || die;

    xlog $self, "get email id";
    my $res = $jmap->CallMethods([['Email/query', {}, 'R1']]);
    my $id = $res->[0][1]->{ids}[0];

    for my $tc ( @wantbodies ) {
        my $nbytes = $tc->[0];
        my $wantbody = $tc->[1];

        xlog $self, "get email";
        my $res = $jmap->CallMethods([
            ['Email/get', {
                ids => [ $id ],
                properties => [ 'bodyValues' ],
                fetchAllBodyValues => JSON::true,
                maxBodyValueBytes => $nbytes + 0,
            }, "R1"],
        ]);
        my $msg = $res->[0][1]->{list}[0];
        $self->assert_str_equals($wantbody, $msg->{bodyValues}{'1'}{value});
    }
}

sub test_email_get_header_all
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();

    xlog $self, "Generate a email in INBOX via IMAP";
    my %exp_inbox;
    my %params = (
        extra_headers => [
            ['x-tra', "foo"],
            ['x-tra', "bar"],
        ],
        body => "hello",
    );
    $self->make_message("Email A", %params) || die;

    xlog $self, "get email list";
    my $res = $jmap->CallMethods([['Email/query', {}, "R1"]]);
    my $ids = $res->[0][1]->{ids};

    xlog $self, "get email";
    $res = $jmap->CallMethods([['Email/get', { ids => $ids, properties => ['header:x-tra:all', 'header:x-tra:asRaw:all'] }, "R1"]]);
    my $msg = $res->[0][1]{list}[0];

    $self->assert_deep_equals([' foo', ' bar'], $msg->{'header:x-tra:all'});
    $self->assert_deep_equals([' foo', ' bar'], $msg->{'header:x-tra:asRaw:all'});
}

sub test_email_set_nullheader
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $inboxid = $self->getinbox()->{id};

    my $text = "x";

    # Prepare test email
    my $email =  {
        mailboxIds => { $inboxid => JSON::true },
        from => [ { email => q{test1@robmtest.vm}, name => q{} } ],
        'header:foo' => undef,
        'header:foo:asMessageIds' => undef,
    };

    # Create and get mail
    my $res = $jmap->CallMethods([
        ['Email/set', { create => { "1" => $email }}, "R1"],
        ['Email/get', {
            ids => [ "#1" ],
            properties => [ 'headers', 'header:foo' ],
        }, "R2" ],
    ]);
    my $msg = $res->[1][1]{list}[0];

    foreach (@{$msg->{headers}}) {
        xlog $self, "Checking header $_->{name}";
        $self->assert_str_not_equals('foo', $_->{name});
    }
    $self->assert_null($msg->{'header:foo'});
}

sub test_email_set_headers
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $inboxid = $self->getinbox()->{id};

    my $text = "x";

    # Prepare test headers
    my $headers = {
        'header:X-TextHeader8bit' => {
            format  => 'asText',
            value   => "I feel \N{WHITE SMILING FACE}",
            wantRaw => " =?UTF-8?Q?I_feel_=E2=98=BA?="
        },
        'header:X-TextHeaderLong' => {
            format  => 'asText',
            value   => "x" x 80,
            wantRaw => " =?UTF-8?Q?xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx?=\r\n =?UTF-8?Q?xxxxxxxxxxxxxxxxxx?="
        },
        'header:X-TextHeaderShort' => {
            format  => 'asText',
            value   => "x",
            wantRaw => " x"
        },
       'header:X-MsgIdsShort' => {
           format => 'asMessageIds',
           value  => [ 'foobar@ba' ],
           wantRaw => " <foobar\@ba>",
       },
       'header:X-MsgIdsLong' => {
           format => 'asMessageIds',
           value  => [
               'foobar@ba',
               'foobar@ba',
               'foobar@ba',
               'foobar@ba',
               'foobar@ba',
               'foobar@ba',
               'foobar@ba',
               'foobar@ba',
           ],
           wantRaw => (" <foobar\@ba>" x 5)."\r\n".(" <foobar\@ba>" x 3),
       },
       'header:X-AddrsShort' => {
           format => 'asAddresses',
           value => [{ 'name' => 'foo', email => 'bar@local' }],
           wantRaw => ' foo <bar@local>',
       },
       'header:X-AddrsQuoted' => {
           format => 'asAddresses',
           value => [{ 'name' => 'Foo Bar', email => 'quotbar@local' }],
           wantRaw => ' "Foo Bar" <quotbar@local>',
       },
       'header:X-Addrs8bit' => {
           format => 'asAddresses',
           value => [{ 'name' => "Rudi R\N{LATIN SMALL LETTER U WITH DIAERESIS}be", email => 'bar@local' }],
           wantRaw => ' =?UTF-8?Q?Rudi_R=C3=BCbe?= <bar@local>',
       },
       'header:X-AddrsLong' => {
           format => 'asAddresses',
           value => [{
               'name' => 'foo', email => 'bar@local'
           }, {
               'name' => 'foo', email => 'bar@local'
           }, {
               'name' => 'foo', email => 'bar@local'
           }, {
               'name' => 'foo', email => 'bar@local'
           }, {
               'name' => 'foo', email => 'bar@local'
           }, {
               'name' => 'foo', email => 'bar@local'
           }, {
               'name' => 'foo', email => 'bar@local'
           }, {
               'name' => 'foo', email => 'bar@local'
           }],
           wantRaw => (' foo <bar@local>,' x 3)."\r\n".(' foo <bar@local>,' x 4)."\r\n".' foo <bar@local>',
       },
       'header:X-URLsShort' => {
           format => 'asURLs',
           value => [ 'foourl' ],
           wantRaw => ' <foourl>',
       },
       'header:X-URLsLong' => {
           format => 'asURLs',
           value => [
               'foourl',
               'foourl',
               'foourl',
               'foourl',
               'foourl',
               'foourl',
               'foourl',
               'foourl',
               'foourl',
               'foourl',
               'foourl',
           ],
           wantRaw => (' <foourl>,' x 6)."\r\n".(' <foourl>,' x 4).' <foourl>',
       },
    };

    # Prepare test email
    my $email =  {
        mailboxIds => { $inboxid => JSON::true },
        from => [ { email => q{test1@robmtest.vm}, name => q{} } ],
    };
    while( my ($k, $v) = each %$headers ) {
        $email->{$k.':'.$v->{format}} = $v->{value},
    }

    my @properties = keys %$headers;
    while( my ($k, $v) = each %$headers ) {
        push @properties, $k.':'.$v->{format};
    }


    # Create and get mail
    my $res = $jmap->CallMethods([
        ['Email/set', { create => { "1" => $email }}, "R1"],
        ['Email/get', {
            ids => [ "#1" ],
            properties => \@properties,
        }, "R2" ],
    ]);
    my $msg = $res->[1][1]{list}[0];

    # Validate header values
    while( my ($k, $v) = each %$headers ) {
        xlog $self, "Validating $k";
        my $raw = $msg->{$k};
        my $val = $msg->{$k.':'.$v->{format}};
        # Check raw header
        $self->assert_str_equals($v->{wantRaw}, $raw);
        # Check formatted header
        if (ref $v->{value} eq 'ARRAY') {
            $self->assert_deep_equals($v->{value}, $val);
        } else {
            $self->assert_str_equals($v->{value}, $val);
        }
    }
}

sub test_email_download
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();

    xlog $self, "Generate a email in INBOX via IMAP";
    my $body = "--047d7b33dd729737fe04d3bde348\r\n";
    $body .= "Content-Type: text/plain; charset=UTF-8\r\n";
    $body .= "\r\n";
    $body .= "some text";
    $body .= "\r\n";
    $body .= "--047d7b33dd729737fe04d3bde348\r\n";
    $body .= "Content-Type: text/html;charset=\"UTF-8\"\r\n";
    $body .= "\r\n";
    $body .= "<p>some HTML text</p>";
    $body .= "\r\n";
    $body .= "--047d7b33dd729737fe04d3bde348--\r\n";
    $self->make_message("foo",
        mime_type => "multipart/alternative",
        mime_boundary => "047d7b33dd729737fe04d3bde348",
        body => $body
    );

    xlog $self, "get email";
    my $res = $jmap->CallMethods([
        ['Email/query', { }, 'R1'],
        ['Email/get', {
            '#ids' => {
                resultOf => 'R1',
                name => 'Email/query',
                path => '/ids'
            },
            properties => [ 'blobId' ],
        }, 'R2'],
    ]);
    my $msg = $res->[1][1]->{list}[0];

    my $blob = $jmap->Download({ accept => 'message/rfc822' }, 'cassandane', $msg->{blobId});
    $self->assert_str_equals('message/rfc822', $blob->{headers}->{'content-type'});
    $self->assert_num_not_equals(0, $blob->{headers}->{'content-length'});
}

sub test_email_embedded_download
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();

    # Generate an embedded email
    xlog $self, "Generate a email in INBOX via IMAP";
    $self->make_message("foo",
        mime_type => "multipart/mixed",
        mime_boundary => "sub",
        body => ""
          . "--sub\r\n"
          . "Content-Type: text/plain; charset=UTF-8\r\n"
          . "Content-Disposition: inline\r\n" . "\r\n"
          . "some text"
          . "\r\n--sub\r\n"
          . "Content-Type: message/rfc822\r\n"
          . "\r\n"
          . "Return-Path: <Ava.Nguyen\@local>\r\n"
          . "Mime-Version: 1.0\r\n"
          . "Content-Type: text/plain\r\n"
          . "Content-Transfer-Encoding: 7bit\r\n"
          . "Subject: bar\r\n"
          . "From: Ava T. Nguyen <Ava.Nguyen\@local>\r\n"
          . "Message-ID: <fake.1475639947.6507\@local>\r\n"
          . "Date: Wed, 05 Oct 2016 14:59:07 +1100\r\n"
          . "To: Test User <test\@local>\r\n"
          . "\r\n"
          . "An embedded email"
          . "\r\n--sub--\r\n",
    ) || die;

    xlog $self, "get blobId";
    my $res = $jmap->CallMethods([
        ['Email/query', { }, "R1"],
        ['Email/get', {
            '#ids' => { resultOf => 'R1', name => 'Email/query', path => '/ids' },
            properties => ['attachments'],
        }, 'R2' ],
    ]);
    my $blobId = $res->[1][1]->{list}[0]->{attachments}[0]{blobId};

    my $blob = $jmap->Download({ accept => 'message/rfc822' }, 'cassandane', $blobId);
    $self->assert_str_equals('message/rfc822', $blob->{headers}->{'content-type'});
    $self->assert_num_not_equals(0, $blob->{headers}->{'content-length'});
}

sub test_blob_download
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $logofile = abs_path('data/logo.gif');
    open(FH, "<$logofile");
    local $/ = undef;
    my $binary = <FH>;
    close(FH);
    my $data = $jmap->Upload($binary, "image/gif");

    my $blob = $jmap->Download({ accept => 'image/gif' }, 'cassandane', $data->{blobId});
    $self->assert_str_equals('image/gif', $blob->{headers}->{'content-type'});
    $self->assert_num_not_equals(0, $blob->{headers}->{'content-length'});
    $self->assert_equals($binary, $blob->{content});
}

sub test_email_set_filename
    :min_version_3_4 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();

    xlog $self, "Upload a data blob";
    my $binary = pack "H*", "beefcode";
    my $data = $jmap->Upload($binary, "image/gif");
    my $dataBlobId = $data->{blobId};

    my @testcases = ({
        name   => 'foo',
        wantCt => ' image/gif; name="foo"',
        wantCd => ' attachment;filename="foo"',
    }, {
        name   => "I feel \N{WHITE SMILING FACE}",
        wantCt => ' image/gif; name="=?UTF-8?Q?I_feel_=E2=98=BA?="',
        wantCd => " attachment;filename*=utf-8''I%20feel%20%E2%98%BA",
    }, {
        name   => "foo" . ("_foo" x 20),
        wantCt => " image/gif;\r\n name=\"=?UTF-8?Q?foo=5Ffoo=5Ffoo=5Ffoo=5Ffoo=5Ffoo=5Ffoo=5Ffoo=5Ffoo=5Ffoo=5Ffo?=\r\n =?UTF-8?Q?o=5Ffoo=5Ffoo=5Ffoo=5Ffoo=5Ffoo=5Ffoo=5Ffoo=5Ffoo=5Ffoo=5Ffoo?=\"",
        wantCd => " attachment;\r\n filename*0=\"foo_foo_foo_foo_foo_foo_foo_foo_foo_foo_foo_foo_foo_foo_foo_f\";\r\n filename*1=\"oo_foo_foo_foo_foo_foo\"",
    }, {
        name   => "foo" . ("_foo" x 20) . "\N{WHITE SMILING FACE}",
        wantCt => " image/gif;\r\n name=\"=?UTF-8?Q?foo=5Ffoo=5Ffoo=5Ffoo=5Ffoo=5Ffoo=5Ffoo=5Ffoo=5Ffoo=5Ffoo=5Ffo?=\r\n =?UTF-8?Q?o=5Ffoo=5Ffoo=5Ffoo=5Ffoo=5Ffoo=5Ffoo=5Ffoo=5Ffoo=5Ffoo=5Ffoo?=\r\n =?UTF-8?Q?=E2=98=BA?=\"",
        wantCd => " attachment;\r\n filename*0*=utf-8\'\'foo_foo_foo_foo_foo_foo_foo_foo_foo_foo_foo_foo_foo_fo;\r\n filename*1*=o_foo_foo_foo_foo_foo_foo_foo%E2%98%BA",
    }, {
        name   => 'Incoming Email Flow.xml',
        wantCt => ' image/gif; name="Incoming Email Flow.xml"',
        wantCd => ' attachment;filename="Incoming Email Flow.xml"',
    }, {
        name   => 'a"b\c.txt',
        wantCt => ' image/gif; name="a\"b\\\\c.txt"',
        wantCd => ' attachment;filename="a\"b\\\\c.txt"',
    });

    foreach my $tc (@testcases) {
        xlog $self, "Checking name $tc->{name}";
        my $bodyStructure = {
            type => "multipart/alternative",
            subParts => [{
                    type => 'text/plain',
                    partId => '1',
                }, {
                    type => 'image/gif',
                    disposition => 'attachment',
                    name => $tc->{name},
                    blobId => $dataBlobId,
                }],
        };

        xlog $self, "Create email with body structure";
        my $inboxid = $self->getinbox()->{id};
        my $email = {
            mailboxIds => { $inboxid => JSON::true },
            from => [{ name => "Test", email => q{foo@bar} }],
            subject => "test",
            bodyStructure => $bodyStructure,
            bodyValues => {
                "1" => {
                    value => "A text body",
                },
            },
        };
        my $res = $jmap->CallMethods([
                ['Email/set', { create => { '1' => $email } }, 'R1'],
                ['Email/get', {
                        ids => [ '#1' ],
                        properties => [ 'bodyStructure' ],
                        bodyProperties => [ 'partId', 'blobId', 'type', 'name', 'disposition', 'header:Content-Type', 'header:Content-Disposition' ],
                        fetchAllBodyValues => JSON::true,
                    }, 'R2' ],
            ]);

        my $gotBodyStructure = $res->[1][1]{list}[0]{bodyStructure};
        my $gotName = $gotBodyStructure->{subParts}[1]{name};
        $self->assert_str_equals($tc->{name}, $gotName);
        my $gotCt = $gotBodyStructure->{subParts}[1]{'header:Content-Type'};
        $self->assert_str_equals($tc->{wantCt}, $gotCt);
        my $gotCd = $gotBodyStructure->{subParts}[1]{'header:Content-Disposition'};
        $self->assert_str_equals($tc->{wantCd}, $gotCd);
    }
}

sub test_email_get_size
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    $self->make_message("foo",
        mime_type => 'text/plain; charset="UTF-8"',
        mime_encoding => 'quoted-printable',
        body => '=C2=A1Hola, se=C3=B1or!',
    ) || die;
    my $res = $jmap->CallMethods([
        ['Email/query', { }, "R1"],
        ['Email/get', {
            '#ids' => { resultOf => 'R1', name => 'Email/query', path => '/ids' },
            properties => ['bodyStructure', 'size'],
        }, 'R2' ],
    ]);

    my $msg = $res->[1][1]{list}[0];
    $self->assert_num_equals(15, $msg->{bodyStructure}{size});
}

sub test_email_get_references
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $rawReferences = '<bar>, <baz>';
    my $parsedReferences = [ 'bar', 'baz' ];

    $self->make_message("foo",
        mime_type => 'text/plain',
        extra_headers => [
            ['References', $rawReferences],
        ],
        body => 'foo',
    ) || die;
    my $res = $jmap->CallMethods([
        ['Email/query', { }, "R1"],
        ['Email/get', {
            '#ids' => { resultOf => 'R1', name => 'Email/query', path => '/ids' },
            properties => ['references', 'header:references', 'header:references:asMessageIds'],
        }, 'R2' ],
    ]);
    my $msg = $res->[1][1]{list}[0];
    $self->assert_str_equals(' ' . $rawReferences, $msg->{'header:references'});
    $self->assert_deep_equals($parsedReferences, $msg->{'header:references:asMessageIds'});
    $self->assert_deep_equals($parsedReferences, $msg->{references});
}

sub test_email_set_groupaddr
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my @testCases = ({
        # Example from from Appendix A.1.3 of RFC 5322
        rawHeader => 'A Group:Ed Jones <c@a.test>,joe@where.test,John <jdoe@one.test>',
        wantAddresses => [{
            name => 'Ed Jones',
            email => 'c@a.test',
        }, {
            name => undef,
            email => 'joe@where.test'
        }, {
            name => 'John',
            email => 'jdoe@one.test',
        }],
        wantGroupedAddresses => [{
            name => 'A Group',
            addresses => [{
                name => 'Ed Jones',
                email => 'c@a.test',
            }, {
                name => undef,
                email => 'joe@where.test'
            }, {
                name => 'John',
                email => 'jdoe@one.test',
            }],
        }],
    }, {
        # Example from JMAP mail spec, RFC 8621, Section 4.1.2.3
        rawHeader => '"James Smythe" <james@example.com>, Friends:'
                     . 'jane@example.com, =?UTF-8?Q?John_Sm=C3=AEth?= '
                     . '<john@example.com>;',
        wantAddresses => [{
                name => 'James Smythe',
                email => 'james@example.com'
            }, {
                name => undef,
                email => 'jane@example.com'
            }, {
                name => "John Sm\N{U+00EE}th",
                email => 'john@example.com'
        }],
        wantGroupedAddresses => [{
                name => undef,
                addresses => [{
                        name => 'James Smythe',
                        email => 'james@example.com'
                    }],
            }, {
                name => 'Friends',
                addresses => [{
                        name => undef,
                        email => 'jane@example.com'
                    }, {
                        name => "John Sm\N{U+00EE}th",
                        email => 'john@example.com'
                    }],
            }]
    }, {
        # Issue https://github.com/cyrusimap/cyrus-imapd/issues/2959
        rawHeader => 'undisclosed-recipients:',
        wantAddresses => [],
        wantGroupedAddresses => [{
            name => 'undisclosed-recipients',
            addresses => [],
        }],
    }, {
        # Sanity check
        rawHeader =>   'addr1@local, addr2@local, GroupA:; addr3@local, '
                     . 'GroupB:addr4@local,addr5@local;addr6@local',
        wantAddresses => [{
            name => undef,
            email => 'addr1@local',
        }, {
            name => undef,
            email => 'addr2@local',
        }, {
            name => undef,
            email => 'addr3@local',
        }, {
            name => undef,
            email => 'addr4@local',
        }, {
            name => undef,
            email => 'addr5@local',
        }, {
            name => undef,
            email => 'addr6@local',
        }],
        wantGroupedAddresses => [{
            name => undef,
            addresses => [{
                name => undef,
                email => 'addr1@local',
            }, {
                name => undef,
                email => 'addr2@local',
            }],
        }, {
            name => 'GroupA',
            addresses => [],
        }, {
            name => undef,
            addresses => [{
                name => undef,
                email => 'addr3@local',
            }],
        }, {
            name => 'GroupB',
            addresses => [{
                name => undef,
                email => 'addr4@local',
            }, {
                name => undef,
                email => 'addr5@local',
            }],
        }, {
            name => undef,
            addresses => [{
                name => undef,
                email => 'addr6@local',
            }],
        }],
    });

    foreach my $tc (@testCases) {
        my $res = $jmap->CallMethods([
            ['Email/set', {
                create => {
                    email1 => {
                        mailboxIds => {
                            '$inbox' => JSON::true,
                        },
                        from => [{ email => q{foo1@bar} }],
                        'header:to' => $tc->{rawHeader},
                        bodyStructure => {
                            partId => '1',
                        },
                        bodyValues => {
                            "1" => {
                                value => "email1 body",
                            },
                        },
                    },
                },
            }, 'R1'],
            ['Email/get', {
                ids => ['#email1'],
                properties => [
                    'header:to:asAddresses',
                    'header:to:asGroupedAddresses',
                ],
            }, 'R2'],
        ]);
        $self->assert_not_null($res->[0][1]{created}{email1}{id});
        $self->assert_deep_equals($tc->{wantAddresses},
            $res->[1][1]{list}[0]->{'header:to:asAddresses'});
        $self->assert_deep_equals($tc->{wantGroupedAddresses},
            $res->[1][1]{list}[0]->{'header:to:asGroupedAddresses'});

        # Now assert that group addresses loop back if set in Email/set.

        $res = $jmap->CallMethods([
            ['Email/set', {
                create => {
                    email2 => {
                        mailboxIds => {
                            '$inbox' => JSON::true,
                        },
                        from => [{ email => q{foo2@bar} }],
                        'header:to:asGroupedAddresses' => $tc->{wantGroupedAddresses},
                        bodyStructure => {
                            partId => '1',
                        },
                        bodyValues => {
                            "1" => {
                                value => "email2 body",
                            },
                        },
                    },
                },
            }, 'R1'],
            ['Email/get', {
                ids => ['#email2'],
                properties => [
                    'header:to:asAddresses',
                    'header:to:asGroupedAddresses',
                ],
            }, 'R2'],
        ]);
        $self->assert_not_null($res->[0][1]{created}{email2}{id});
        $self->assert_deep_equals($tc->{wantAddresses},
            $res->[1][1]{list}[0]->{'header:to:asAddresses'});
        $self->assert_deep_equals($tc->{wantGroupedAddresses},
            $res->[1][1]{list}[0]->{'header:to:asGroupedAddresses'});
    }
}

sub test_email_parse
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();

    $self->make_message("foo",
        mime_type => "multipart/mixed",
        mime_boundary => "sub",
        body => ""
          . "--sub\r\n"
          . "Content-Type: message/rfc822\r\n"
          . "\r\n"
          . "Return-Path: <Ava.Nguyen\@local>\r\n"
          . "Mime-Version: 1.0\r\n"
          . "Content-Type: text/plain\r\n"
          . "Content-Transfer-Encoding: 7bit\r\n"
          . "Subject: bar\r\n"
          . "From: Ava T. Nguyen <Ava.Nguyen\@local>\r\n"
          . "Message-ID: <fake.1475639947.6507\@local>\r\n"
          . "Date: Wed, 05 Oct 2016 14:59:07 +1100\r\n"
          . "To: Test User <test\@local>\r\n"
          . "\r\n"
          . "An embedded email"
          . "\r\n--sub--\r\n",
    ) || die;
    my $res = $jmap->CallMethods([
        ['Email/query', { }, "R1"],
        ['Email/get', {
            '#ids' => { resultOf => 'R1', name => 'Email/query', path => '/ids' },
            properties => ['attachments'],
        }, 'R2' ],
    ]);
    my $blobId = $res->[1][1]{list}[0]{attachments}[0]{blobId};

    my @props = $self->defaultprops_for_email_get();
    push @props, "bodyStructure";
    push @props, "bodyValues";

    $res = $jmap->CallMethods([['Email/parse', {
        blobIds => [ $blobId ], properties => \@props, fetchAllBodyValues => JSON::true,
    }, 'R1']]);
    my $email = $res->[0][1]{parsed}{$blobId};
    $self->assert_not_null($email);

    $self->assert_null($email->{id});
    $self->assert_null($email->{threadId});
    $self->assert_null($email->{mailboxIds});
    $self->assert_deep_equals({}, $email->{keywords});
    $self->assert_deep_equals(['fake.1475639947.6507@local'], $email->{messageId});
    $self->assert_deep_equals([{name=>'Ava T. Nguyen', email=>'Ava.Nguyen@local'}], $email->{from});
    $self->assert_deep_equals([{name=>'Test User', email=>'test@local'}], $email->{to});
    $self->assert_null($email->{cc});
    $self->assert_null($email->{bcc});
    $self->assert_null($email->{references});
    $self->assert_null($email->{sender});
    $self->assert_null($email->{replyTo});
    $self->assert_str_equals('bar', $email->{subject});
    $self->assert_str_equals('2016-10-05T14:59:07+11:00', $email->{sentAt});
    $self->assert_not_null($email->{blobId});
    $self->assert_str_equals('text/plain', $email->{bodyStructure}{type});
    $self->assert_null($email->{bodyStructure}{subParts});
    $self->assert_num_equals(1, scalar @{$email->{textBody}});
    $self->assert_num_equals(1, scalar @{$email->{htmlBody}});
    $self->assert_num_equals(0, scalar @{$email->{attachments}});

    my $bodyValue = $email->{bodyValues}{$email->{bodyStructure}{partId}};
    $self->assert_str_equals('An embedded email', $bodyValue->{value});
}

sub test_email_parse_digest
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();

    $self->make_message("foo",
        mime_type => "multipart/digest",
        mime_boundary => "sub",
        body => ""
          . "\r\n--sub\r\n"
          . "\r\n"
          . "Return-Path: <Ava.Nguyen\@local>\r\n"
          . "Mime-Version: 1.0\r\n"
          . "Content-Type: text/plain\r\n"
          . "Content-Transfer-Encoding: 7bit\r\n"
          . "Subject: bar\r\n"
          . "From: Ava T. Nguyen <Ava.Nguyen\@local>\r\n"
          . "Message-ID: <fake.1475639947.6507\@local>\r\n"
          . "Date: Wed, 05 Oct 2016 14:59:07 +1100\r\n"
          . "To: Test User <test\@local>\r\n"
          . "\r\n"
          . "An embedded email"
          . "\r\n--sub--\r\n",
    ) || die;
    my $res = $jmap->CallMethods([
        ['Email/query', { }, "R1"],
        ['Email/get', {
            '#ids' => { resultOf => 'R1', name => 'Email/query', path => '/ids' },
            properties => ['bodyStructure']
        }, 'R2' ],
    ]);
    my $blobId = $res->[1][1]{list}[0]{bodyStructure}{subParts}[0]{blobId};
    $self->assert_not_null($blobId);

    $res = $jmap->CallMethods([['Email/parse', { blobIds => [ $blobId ] }, 'R1']]);
    $self->assert_not_null($res->[0][1]{parsed}{$blobId});
}

sub test_email_parse_blob822
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();

    my $rawEmail = <<'EOF';
From: "Some Example Sender" <example@example.com>
To: baseball@vitaead.com
Subject: test email
Date: Wed, 7 Dec 2016 00:21:50 -0500
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

This is a test email.
EOF
    $rawEmail =~ s/\r?\n/\r\n/gs;
    my $data = $jmap->Upload($rawEmail, "application/data");
    my $blobId = $data->{blobId};

    my @props = $self->defaultprops_for_email_get();
    push @props, "bodyStructure";
    push @props, "bodyValues";

    my $res = $jmap->CallMethods([['Email/parse', {
        blobIds => [ $blobId ],
        properties => \@props,
        fetchAllBodyValues => JSON::true,
    }, 'R1']]);
    my $email = $res->[0][1]{parsed}{$blobId};

    $self->assert_not_null($email);
    $self->assert_deep_equals([{name=>'Some Example Sender', email=>'example@example.com'}], $email->{from});

    my $bodyValue = $email->{bodyValues}{$email->{bodyStructure}{partId}};
    $self->assert_str_equals("This is a test email.\n", $bodyValue->{value});
}

sub test_email_parse_base64
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();

    my $rawEmail = <<'EOF';
From: "Some Example Sender" <example@example.com>
To: baseball@vitaead.com
Subject: test email
Date: Wed, 7 Dec 2016 00:21:50 -0500
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

This is a test email.
EOF
    $rawEmail =~ s/\r?\n/\r\n/gs;

    $self->make_message("foo",
        mime_type => "multipart/mixed",
        mime_boundary => "sub",
        body => ""
          . "--sub\r\n"
          . "Content-Type: message/rfc822\r\n"
          . "Content-Transfer-Encoding: base64\r\n"
          . "\r\n"
          . MIME::Base64::encode_base64($rawEmail, "\r\n")
          . "\r\n--sub--\r\n",
    ) || die;

    my $res = $jmap->CallMethods([
        ['Email/query', { }, "R1"],
        ['Email/get', {
            '#ids' => { resultOf => 'R1', name => 'Email/query', path => '/ids' },
            properties => ['attachments'],
        }, 'R2' ],
    ]);
    my $blobId = $res->[1][1]{list}[0]{attachments}[0]{blobId};

    my @props = $self->defaultprops_for_email_get();
    push @props, "bodyStructure";
    push @props, "bodyValues";

    $res = $jmap->CallMethods([['Email/parse', {
        blobIds => [ $blobId ],
        properties => \@props,
        fetchAllBodyValues => JSON::true,
    }, 'R1']]);

    my $email = $res->[0][1]{parsed}{$blobId};
    $self->assert_not_null($email);
    $self->assert_deep_equals(
        [{
            name => 'Some Example Sender',
            email => 'example@example.com'
        }],
        $email->{from}
    );
    my $bodyValue = $email->{bodyValues}{$email->{bodyStructure}{partId}};
    $self->assert_str_equals("This is a test email.\n", $bodyValue->{value});
}

sub test_email_parse_blob822_lenient
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();

    # This isn't a valid RFC822 message, as it neither contains
    # a Date nor a From header. But there's wild stuff out there,
    # so let's be lenient.
    my $rawEmail = <<'EOF';
To: foo@bar.local
MIME-Version: 1.0

Some illegit mail.
EOF
    $rawEmail =~ s/\r?\n/\r\n/gs;
    my $data = $jmap->Upload($rawEmail, "application/data");
    my $blobId = $data->{blobId};

    my $res = $jmap->CallMethods([['Email/parse', {
        blobIds => [ $blobId ],
        fetchAllBodyValues => JSON::true,
    }, 'R1']]);
    my $email = $res->[0][1]{parsed}{$blobId};

    $self->assert_not_null($email);
    $self->assert_null($email->{from});
    $self->assert_null($email->{sentAt});
    $self->assert_deep_equals([{name=>undef, email=>'foo@bar.local'}], $email->{to});
}

sub test_email_parse_contenttype_default
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();

    my $emailWithoutContentType = <<'EOF';
From: "Some Example Sender" <example@example.com>
To: baseball@vitaead.com
Subject: test email
Date: Wed, 7 Dec 2016 00:21:50 -0500
MIME-Version: 1.0

This is a test email.
EOF

    my $emailWithoutCharset = <<'EOF';
From: "Some Example Sender" <example@example.com>
To: baseball@vitaead.com
Subject: test email
Date: Wed, 7 Dec 2016 00:21:50 -0500
Content-Type: text/plain
MIME-Version: 1.0

This is a test email.
EOF

    my $emailWithNonTextContentType = <<'EOF';
From: "Some Example Sender" <example@example.com>
To: baseball@vitaead.com
Subject: test email
Date: Wed, 7 Dec 2016 00:21:50 -0500
Content-Type: application/data
MIME-Version: 1.0

This is a test email.
EOF


    my @testCases = ({
        desc => "Email without Content-Type header",
        rawEmail => $emailWithoutContentType,
        wantContentType => 'text/plain',
        wantCharset => 'us-ascii',
    }, {
        desc => "Email without charset parameter",
        rawEmail => $emailWithoutCharset,
        wantContentType => 'text/plain',
        wantCharset => 'us-ascii',
    }, {
        desc => "Email with non-text Content-Type",
        rawEmail => $emailWithNonTextContentType,
        wantContentType => 'application/data',
        wantCharset => undef,
    });

    foreach (@testCases) {
        xlog $self, "Running test: $_->{desc}";
        my $rawEmail = $_->{rawEmail};
        $rawEmail =~ s/\r?\n/\r\n/gs;
        my $data = $jmap->Upload($rawEmail, "application/data");
        my $blobId = $data->{blobId};

        my $res = $jmap->CallMethods([['Email/parse', {
            blobIds => [ $blobId ],
            properties => ['bodyStructure'],
        }, 'R1']]);
        my $email = $res->[0][1]{parsed}{$blobId};
        $self->assert_str_equals($_->{wantContentType}, $email->{bodyStructure}{type});
        if (defined $_->{wantCharset}) {
            $self->assert_str_equals($_->{wantCharset}, $email->{bodyStructure}{charset});
        } else {
            $self->assert_null($email->{bodyStructure}{charset});
        }
    }
}

sub test_email_parse_charset
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();

    # LF in raw headers will be replaced to CRLF later.

    my @testCases = ({
        desc => "Canonical charset parameter",
        rawHeader => "text/plain; charset=utf-8",
        wantContentType => 'text/plain',
        wantCharset => 'utf-8',
    }, {
        desc => "Folded charset parameter",
        rawHeader => "text/plain;\n charset=\n utf-8",
        wantContentType => 'text/plain',
        wantCharset => 'utf-8',
    }, {
        desc => "Aliased charset parameter",
        rawHeader => "text/plain; charset=latin1",
        wantContentType => 'text/plain',
        wantCharset => 'latin1',
    });

    foreach (@testCases) {
        xlog $self, "Running test: $_->{desc}";
        my $rawEmail = ""
        . "From: foo\@local\n"
        . "To: bar\@local\n"
        . "Subject: test email\n"
        . "Date: Wed, 7 Dec 2016 00:21:50 -0500\n"
        . "Content-Type: " . $_->{rawHeader} . "\n"
        . "MIME-Version: 1.0\n"
        . "\n"
        . "This is a test email.\n";

        $rawEmail =~ s/\r?\n/\r\n/gs;
        my $data = $jmap->Upload($rawEmail, "application/octet-stream");
        my $blobId = $data->{blobId};

        my $res = $jmap->CallMethods([
            ['Email/import', {
                emails => {
                    1 => {
                        mailboxIds => {
                            '$inbox' => JSON::true,
                        },
                        blobId => $blobId,
                    },
                },
            }, 'R1'],
            ['Email/get', {
                ids => ['#1'],
                properties => ['bodyStructure'],
                bodyProperties => ['charset'],
            }, '$2'],
        ]);
        my $email = $res->[1][1]{list}[0];
        if (defined $_->{wantCharset}) {
            $self->assert_str_equals($_->{wantCharset}, $email->{bodyStructure}{charset});
        } else {
            $self->assert_null($email->{bodyStructure}{charset});
        }
    }
}

sub test_email_parse_encoding
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();

    my $decodedBody = "\N{LATIN SMALL LETTER A WITH GRAVE} la carte";
    my $encodedBody = '=C3=A0 la carte';
    $encodedBody =~ s/\r?\n/\r\n/gs;

    my $Header = <<'EOF';
From: "Some Example Sender" <example@example.com>
To: baseball@vitaead.com
Subject: test email
Date: Wed, 7 Dec 2016 00:21:50 -0500
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
EOF
    $Header =~ s/\r?\n/\r\n/gs;
    my $emailBlob = $Header . "\r\n" . $encodedBody;

    my $email;
    my $res;
    my $partId;

    $self->make_message("foo",
        mime_type => "multipart/mixed;boundary=1234567",
        body => ""
        . "--1234567\r\n"
        . "Content-Type: text/plain; charset=utf-8\r\n"
        . "Content-Transfer-Encoding: quoted-printable\r\n"
        . "\r\n"
        . $encodedBody
        . "\r\n--1234567\r\n"
        . "Content-Type: message/rfc822\r\n"
        . "\r\n"
        . "X-Header: ignore\r\n" # make this blob id unique
        . $emailBlob
        . "\r\n--1234567--\r\n"
    );

    # Assert content decoding for top-level message.
    xlog $self, "get email";
    $res = $jmap->CallMethods([
        ['Email/query', { }, 'R1'],
        ['Email/get', {
            '#ids' => {
                resultOf => 'R1',
                name => 'Email/query',
                path => '/ids'
            },
            properties => ['bodyValues', 'bodyStructure', 'textBody'],
            bodyProperties => ['partId', 'blobId'],
            fetchAllBodyValues => JSON::true,
        }, 'R2'],
    ]);
    $self->assert_num_equals(scalar @{$res->[0][1]->{ids}}, 1);
    $email = $res->[1][1]->{list}[0];
    $partId = $email->{textBody}[0]{partId};
    $self->assert_str_equals($decodedBody, $email->{bodyValues}{$partId}{value});

    # Assert content decoding for embedded message.
    xlog $self, "parse embedded email";
    my $embeddedBlobId = $email->{bodyStructure}{subParts}[1]{blobId};
    $res = $jmap->CallMethods([['Email/parse', {
        blobIds => [ $email->{bodyStructure}{subParts}[1]{blobId} ],
        properties => ['bodyValues', 'textBody'],
        fetchAllBodyValues => JSON::true,
    }, 'R1']]);
    $email = $res->[0][1]{parsed}{$embeddedBlobId};
    $partId = $email->{textBody}[0]{partId};
    $self->assert_str_equals($decodedBody, $email->{bodyValues}{$partId}{value});

    # Assert content decoding for message blob.
    my $data = $jmap->Upload($emailBlob, "application/data");
    my $blobId = $data->{blobId};

    $res = $jmap->CallMethods([['Email/parse', {
        blobIds => [ $blobId ],
        properties => ['bodyValues', 'textBody'],
        fetchAllBodyValues => JSON::true,
    }, 'R1']]);
    $email = $res->[0][1]{parsed}{$blobId};
    $partId = $email->{textBody}[0]{partId};
    $self->assert_str_equals($decodedBody, $email->{bodyValues}{$partId}{value});
}

sub test_email_parse_notparsable
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();

    my $rawEmail = ""
    ."To:foo\@bar.local\r\n"
    ."Date: Date: Wed, 7 Dec 2016 00:21:50 -0500\r\n"
    ."\r\n"
    ."Some\nbogus\nbody";

    my $data = $jmap->Upload($rawEmail, "application/data");
    my $blobId = $data->{blobId};

    my $res = $jmap->CallMethods([['Email/parse', { blobIds => [ $blobId ] }, 'R1']]);
    $self->assert_str_equals($blobId, $res->[0][1]{notParsable}[0]);
}

sub test_email_get_bodystructure
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();

    $self->make_message("foo",
        mime_type => "multipart/mixed",
        mime_boundary => "boundary_1",
        body => ""
        # body A
          . "\r\n--boundary_1\r\n"
          . "X-Body-Id:A\r\n"
          . "Content-Type: text/plain\r\n"
          . "Content-Disposition: inline\r\n"
          . "\r\n"
          . "A"
        # multipart/mixed
          . "\r\n--boundary_1\r\n"
          . "Content-Type: multipart/mixed; boundary=\"boundary_1_1\"\r\n"
        # multipart/alternative
          . "\r\n--boundary_1_1\r\n"
          . "Content-Type: multipart/alternative; boundary=\"boundary_1_1_1\"\r\n"
        # multipart/mixed
          . "\r\n--boundary_1_1_1\r\n"
          . "Content-Type: multipart/mixed; boundary=\"boundary_1_1_1_1\"\r\n"
        # body B
          . "\r\n--boundary_1_1_1_1\r\n"
          . "X-Body-Id:B\r\n"
          . "Content-Type: text/plain\r\n"
          . "Content-Disposition: inline\r\n"
          . "\r\n"
          . "B"
        # body C
          . "\r\n--boundary_1_1_1_1\r\n"
          . "X-Body-Id:C\r\n"
          . "Content-Type: image/jpeg\r\n"
          . "Content-Disposition: inline\r\n"
          . "\r\n"
          . "C"
        # body D
          . "\r\n--boundary_1_1_1_1\r\n"
          . "X-Body-Id:D\r\n"
          . "Content-Type: text/plain\r\n"
          . "Content-Disposition: inline\r\n"
          . "\r\n"
          . "D"
        # end multipart/mixed
          . "\r\n--boundary_1_1_1_1--\r\n"
        # multipart/mixed
          . "\r\n--boundary_1_1_1\r\n"
          . "Content-Type: multipart/related; boundary=\"boundary_1_1_1_2\"\r\n"
        # body E
          . "\r\n--boundary_1_1_1_2\r\n"
          . "X-Body-Id:E\r\n"
          . "Content-Type: text/html\r\n"
          . "\r\n"
          . "E"
        # body F
          . "\r\n--boundary_1_1_1_2\r\n"
          . "X-Body-Id:F\r\n"
          . "Content-Type: image/jpeg\r\n"
          . "\r\n"
          . "F"
        # end multipart/mixed
          . "\r\n--boundary_1_1_1_2--\r\n"
        # end multipart/alternative
          . "\r\n--boundary_1_1_1--\r\n"
        # body G
          . "\r\n--boundary_1_1\r\n"
          . "X-Body-Id:G\r\n"
          . "Content-Type: image/jpeg\r\n"
          . "Content-Disposition: attachment\r\n"
          . "\r\n"
          . "G"
        # body H
          . "\r\n--boundary_1_1\r\n"
          . "X-Body-Id:H\r\n"
          . "Content-Type: application/x-excel\r\n"
          . "\r\n"
          . "H"
        # body J
          . "\r\n--boundary_1_1\r\n"
          . "Content-Type: message/rfc822\r\n"
          . "X-Body-Id:J\r\n"
          . "\r\n"
          . "From: foo\@local\r\n"
          . "Date: Thu, 10 May 2018 15:15:38 +0200\r\n"
          . "\r\n"
          . "J"
          . "\r\n--boundary_1_1--\r\n"
        # body K
          . "\r\n--boundary_1\r\n"
          . "X-Body-Id:K\r\n"
          . "Content-Type: text/plain\r\n"
          . "Content-Disposition: inline\r\n"
          . "\r\n"
          . "K"
          . "\r\n--boundary_1--\r\n"
    ) || die;

    my $bodyA = {
        'header:x-body-id' => 'A',
        type => 'text/plain',
        disposition => 'inline',
    };
    my $bodyB = {
        'header:x-body-id' => 'B',
        type => 'text/plain',
        disposition => 'inline',
    };
    my $bodyC = {
        'header:x-body-id' => 'C',
        type => 'image/jpeg',
        disposition => 'inline',
    };
    my $bodyD = {
        'header:x-body-id' => 'D',
        type => 'text/plain',
        disposition => 'inline',
    };
    my $bodyE = {
        'header:x-body-id' => 'E',
        type => 'text/html',
        disposition => undef,
    };
    my $bodyF = {
        'header:x-body-id' => 'F',
        type => 'image/jpeg',
        disposition => undef,
    };
    my $bodyG = {
        'header:x-body-id' => 'G',
        type => 'image/jpeg',
        disposition => 'attachment',
    };
    my $bodyH = {
        'header:x-body-id' => 'H',
        type => 'application/x-excel',
        disposition => undef,
    };
    my $bodyJ = {
        'header:x-body-id' => 'J',
        type => 'message/rfc822',
        disposition => undef,
    };
    my $bodyK = {
        'header:x-body-id' => 'K',
        type => 'text/plain',
        disposition => 'inline',
    };

    my $wantBodyStructure = {
        'header:x-body-id' => undef,
        type => 'multipart/mixed',
        disposition => undef,
        subParts => [
            $bodyA,
            {
                'header:x-body-id' => undef,
                type => 'multipart/mixed',
                disposition => undef,
                subParts => [
                    {
                        'header:x-body-id' => undef,
                        type => 'multipart/alternative',
                        disposition => undef,
                        subParts => [
                            {
                                'header:x-body-id' => undef,
                                type => 'multipart/mixed',
                                disposition => undef,
                                subParts => [
                                    $bodyB,
                                    $bodyC,
                                    $bodyD,
                                ],
                            },
                            {
                                'header:x-body-id' => undef,
                                type => 'multipart/related',
                                disposition => undef,
                                subParts => [
                                    $bodyE,
                                    $bodyF,
                                ],
                            },
                        ],
                    },
                    $bodyG,
                    $bodyH,
                    $bodyJ,
                ],
            },
            $bodyK,
        ],
    };

    my $wantTextBody = [ $bodyA, $bodyB, $bodyC, $bodyD, $bodyK ];
    my $wantHtmlBody = [ $bodyA, $bodyE, $bodyK ];
    my $wantAttachments = [ $bodyC, $bodyF, $bodyG, $bodyH, $bodyJ ];

    my $res = $jmap->CallMethods([
        ['Email/query', { }, "R1"],
        ['Email/get', {
            '#ids' => { resultOf => 'R1', name => 'Email/query', path => '/ids' },
            properties => ['bodyStructure', 'textBody', 'htmlBody', 'attachments' ],
            bodyProperties => ['type', 'disposition', 'header:x-body-id'],
        }, 'R2' ],
    ]);
    my $msg = $res->[1][1]{list}[0];
    $self->assert_deep_equals($wantBodyStructure, $msg->{bodyStructure});
    $self->assert_deep_equals($wantTextBody, $msg->{textBody});
    $self->assert_deep_equals($wantHtmlBody, $msg->{htmlBody});
    $self->assert_deep_equals($wantAttachments, $msg->{attachments});
}

sub test_email_get_calendarevents
    :min_version_3_1 :needs_component_jmap :JMAPExtensions
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    # we need 'https://cyrusimap.org/ns/jmap/mail' capability for
    # calendarEvents property
    my @using = @{ $jmap->DefaultUsing() };
    push @using, 'https://cyrusimap.org/ns/jmap/mail';
    $jmap->DefaultUsing(\@using);

    my $store = $self->{store};
    my $talk = $store->get_client();

    my $uid1 = "d9e7f7d6-ce1a-4a71-94c0-b4edd41e5959";
    my $uid2 = "caf7f7d6-ce1a-4a71-94c0-b4edd41e5959";

    $self->make_message("foo",
        mime_type => "multipart/related",
        mime_boundary => "boundary_1",
        body => ""
          . "\r\n--boundary_1\r\n"
          . "Content-Type: text/plain\r\n"
          . "\r\n"
          . "txt body"
          . "\r\n--boundary_1\r\n"
          . "Content-Type: text/calendar;charset=utf-8\r\n"
          . "Content-Transfer-Encoding: quoted-printable\r\n"
          . "\r\n"
          . "BEGIN:VCALENDAR\r\n"
          . "VERSION:2.0\r\n"
          . "PRODID:-//CyrusIMAP.org/Cyrus 3.1.3-606//EN\r\n"
          . "CALSCALE:GREGORIAN\r\n"
          . "BEGIN:VTIMEZONE\r\n"
          . "TZID:Europe/Vienna\r\n"
          . "BEGIN:STANDARD\r\n"
          . "DTSTART:19700101T000000\r\n"
          . "RRULE:FREQ=YEARLY;BYDAY=-1SU;BYMONTH=10\r\n"
          . "TZOFFSETFROM:+0200\r\n"
          . "TZOFFSETTO:+0100\r\n"
          . "END:STANDARD\r\n"
          . "BEGIN:DAYLIGHT\r\n"
          . "DTSTART:19700101T000000\r\n"
          . "RRULE:FREQ=YEARLY;BYDAY=-1SU;BYMONTH=3\r\n"
          . "TZOFFSETFROM:+0100\r\n"
          . "TZOFFSETTO:+0200\r\n"
          . "END:DAYLIGHT\r\n"
          . "END:VTIMEZONE\r\n"
          . "BEGIN:VEVENT\r\n"
          . "CREATED:20180518T090306Z\r\n"
          . "DTEND;TZID=Europe/Vienna:20180518T100000\r\n"
          . "DTSTAMP:20180518T090306Z\r\n"
          . "DTSTART;TZID=Europe/Vienna:20180518T090000\r\n"
          . "LAST-MODIFIED:20180518T090306Z\r\n"
          . "SEQUENCE:1\r\n"
          . "SUMMARY:K=C3=A4se\r\n"
          . "TRANSP:OPAQUE\r\n"
          . "UID:$uid1\r\n"
          . "END:VEVENT\r\n"
          . "BEGIN:VEVENT\r\n"
          . "CREATED:20180718T090306Z\r\n"
          . "DTEND;TZID=Europe/Vienna:20180718T100000\r\n"
          . "DTSTAMP:20180518T090306Z\r\n"
          . "DTSTART;TZID=Europe/Vienna:20180718T190000\r\n"
          . "LAST-MODIFIED:20180718T090306Z\r\n"
          . "SEQUENCE:1\r\n"
          . "SUMMARY:Foo\r\n"
          . "TRANSP:OPAQUE\r\n"
          . "UID:$uid2\r\n"
          . "END:VEVENT\r\n"
          . "END:VCALENDAR\r\n"
          . "\r\n--boundary_1--\r\n"
    ) || die;

    my $res = $jmap->CallMethods([
        ['Email/query', { }, "R1"],
        ['Email/get', {
            '#ids' => { resultOf => 'R1', name => 'Email/query', path => '/ids' },
            properties => ['textBody', 'attachments', 'calendarEvents'],
        }, 'R2' ],
    ]);
    my $msg = $res->[1][1]{list}[0];

    $self->assert_num_equals(1, scalar @{$msg->{attachments}});
    $self->assert_str_equals('text/calendar', $msg->{attachments}[0]{type});

    $self->assert_num_equals(1, scalar keys %{$msg->{calendarEvents}});
    my $partId = $msg->{attachments}[0]{partId};

    my %jsevents_by_uid = map { $_->{uid} => $_ } @{$msg->{calendarEvents}{$partId}};
    $self->assert_num_equals(2, scalar keys %jsevents_by_uid);
    my $jsevent1 = $jsevents_by_uid{$uid1};
    my $jsevent2 = $jsevents_by_uid{$uid2};

    $self->assert_not_null($jsevent1);
    $self->assert_str_equals("K\N{LATIN SMALL LETTER A WITH DIAERESIS}se", $jsevent1->{title});
    $self->assert_str_equals('2018-05-18T09:00:00', $jsevent1->{start});
    $self->assert_str_equals('Europe/Vienna', $jsevent1->{timeZone});
    $self->assert_str_equals('PT1H', $jsevent1->{duration});

    $self->assert_not_null($jsevent2);
    $self->assert_str_equals("Foo", $jsevent2->{title});
}

sub test_email_get_calendarevents_utc
    :min_version_3_1 :needs_component_jmap :JMAPExtensions
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    # we need 'https://cyrusimap.org/ns/jmap/mail' capability for
    # calendarEvents property
    my @using = @{ $jmap->DefaultUsing() };
    push @using, 'https://cyrusimap.org/ns/jmap/mail';
    $jmap->DefaultUsing(\@using);

    my $store = $self->{store};
    my $talk = $store->get_client();

    my $uid1 = "d9e7f7d6-ce1a-4a71-94c0-b4edd41e5959";

    $self->make_message("foo",
        mime_type => "multipart/related",
        mime_boundary => "boundary_1",
        body => ""
          . "\r\n--boundary_1\r\n"
          . "Content-Type: text/plain\r\n"
          . "\r\n"
          . "txt body"
          . "\r\n--boundary_1\r\n"
          . "Content-Type: text/calendar;charset=utf-8\r\n"
          . "Content-Transfer-Encoding: quoted-printable\r\n"
          . "\r\n"
          . "BEGIN:VCALENDAR\r\n"
          . "VERSION:2.0\r\n"
          . "PRODID:-//CyrusIMAP.org/Cyrus 3.1.3-606//EN\r\n"
          . "CALSCALE:GREGORIAN\r\n"
          . "BEGIN:VTIMEZONE\r\n"
          . "TZID:UTC\r\n"
          . "BEGIN:STANDARD\r\n"
          . "DTSTART:16010101T000000\r\n"
          . "TZOFFSETFROM:+0000\r\n"
          . "TZOFFSETTO:+0000\r\n"
          . "END:STANDARD\r\n"
          . "BEGIN:DAYLIGHT\r\n"
          . "DTSTART:16010101T000000\r\n"
          . "TZOFFSETFROM:+0000\r\n"
          . "TZOFFSETTO:+0000\r\n"
          . "END:DAYLIGHT\r\n"
          . "END:VTIMEZONE\r\n"
          . "BEGIN:VEVENT\r\n"
          . "CREATED:20180518T090306Z\r\n"
          . "DTEND;TZID=UTC:20180518T100000\r\n"
          . "DTSTAMP:20180518T090306Z\r\n"
          . "DTSTART;TZID=UTC:20180518T090000\r\n"
          . "LAST-MODIFIED:20180518T090306Z\r\n"
          . "SEQUENCE:1\r\n"
          . "SUMMARY:Foo\r\n"
          . "TRANSP:OPAQUE\r\n"
          . "UID:$uid1\r\n"
          . "END:VEVENT\r\n"
          . "END:VCALENDAR\r\n"
          . "\r\n--boundary_1--\r\n"
    ) || die;

    my $res = $jmap->CallMethods([
        ['Email/query', { }, "R1"],
        ['Email/get', {
            '#ids' => { resultOf => 'R1', name => 'Email/query', path => '/ids' },
            properties => ['textBody', 'attachments', 'calendarEvents'],
        }, 'R2' ],
    ]);
    my $msg = $res->[1][1]{list}[0];

    $self->assert_num_equals(1, scalar @{$msg->{attachments}});
    $self->assert_str_equals('text/calendar', $msg->{attachments}[0]{type});

    $self->assert_num_equals(1, scalar keys %{$msg->{calendarEvents}});
    my $partId = $msg->{attachments}[0]{partId};

    my %jsevents_by_uid = map { $_->{uid} => $_ } @{$msg->{calendarEvents}{$partId}};
    $self->assert_num_equals(1, scalar keys %jsevents_by_uid);
    my $jsevent1 = $jsevents_by_uid{$uid1};

    $self->assert_not_null($jsevent1);
    $self->assert_str_equals("Foo", $jsevent1->{title});
    $self->assert_str_equals('2018-05-18T09:00:00', $jsevent1->{start});
    $self->assert_str_equals('UTC', $jsevent1->{timeZone});
    $self->assert_str_equals('PT1H', $jsevent1->{duration});
}

sub test_email_get_calendarevents_icsfile
    :min_version_3_1 :needs_component_jmap :JMAPExtensions
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    # we need 'https://cyrusimap.org/ns/jmap/mail' capability for
    # calendarEvents property
    my @using = @{ $jmap->DefaultUsing() };
    push @using, 'https://cyrusimap.org/ns/jmap/mail';
    $jmap->DefaultUsing(\@using);

    my $store = $self->{store};
    my $talk = $store->get_client();

    my $rawEvent = ""
          . "BEGIN:VCALENDAR\r\n"
          . "VERSION:2.0\r\n"
          . "PRODID:-//CyrusIMAP.org/Cyrus 3.1.3-606//EN\r\n"
          . "CALSCALE:GREGORIAN\r\n"
          . "BEGIN:VTIMEZONE\r\n"
          . "TZID:Europe/Vienna\r\n"
          . "BEGIN:STANDARD\r\n"
          . "DTSTART:19700101T000000\r\n"
          . "RRULE:FREQ=YEARLY;BYDAY=-1SU;BYMONTH=10\r\n"
          . "TZOFFSETFROM:+0200\r\n"
          . "TZOFFSETTO:+0100\r\n"
          . "END:STANDARD\r\n"
          . "BEGIN:DAYLIGHT\r\n"
          . "DTSTART:19700101T000000\r\n"
          . "RRULE:FREQ=YEARLY;BYDAY=-1SU;BYMONTH=3\r\n"
          . "TZOFFSETFROM:+0100\r\n"
          . "TZOFFSETTO:+0200\r\n"
          . "END:DAYLIGHT\r\n"
          . "END:VTIMEZONE\r\n"
          . "BEGIN:VEVENT\r\n"
          . "CREATED:20180518T090306Z\r\n"
          . "DTEND;TZID=Europe/Vienna:20180518T100000\r\n"
          . "DTSTAMP:20180518T090306Z\r\n"
          . "DTSTART;TZID=Europe/Vienna:20180518T090000\r\n"
          . "LAST-MODIFIED:20180518T090306Z\r\n"
          . "SEQUENCE:1\r\n"
          . "SUMMARY:Hello\r\n"
          . "TRANSP:OPAQUE\r\n"
          . "UID:d9e7f7d6-ce1a-4a71-94c0-b4edd41e5959\r\n"
          . "END:VEVENT\r\n"
          . "END:VCALENDAR\r\n";

    $self->make_message("foo",
        mime_type => "multipart/related",
        mime_boundary => "boundary_1",
        body => ""
          . "\r\n--boundary_1\r\n"
          . "Content-Type: text/plain\r\n"
          . "\r\n"
          . "txt body"
          . "\r\n--boundary_1\r\n"
          . "Content-Type: application/unknown\r\n"
          . "Content-Transfer-Encoding: base64\r\n"
          ."Content-Disposition: attachment; filename*0=Add_Appointment_;\r\n filename*1=To_Calendar.ics\r\n"
          . "\r\n"
          . encode_base64($rawEvent, "\r\n")
          . "\r\n--boundary_1--\r\n"
    ) || die;

    my $res = $jmap->CallMethods([
        ['Email/query', { }, "R1"],
        ['Email/get', {
            '#ids' => { resultOf => 'R1', name => 'Email/query', path => '/ids' },
            properties => ['textBody', 'attachments', 'calendarEvents'],
        }, 'R2' ],
    ]);
    my $msg = $res->[1][1]{list}[0];

    my $partId = $msg->{attachments}[0]{partId};
    my $jsevent = $msg->{calendarEvents}{$partId}[0];
    $self->assert_str_equals("Hello", $jsevent->{title});
}

sub test_email_set_blobencoding
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();

    xlog $self, "Upload a data blob";
    my $logofile = abs_path('data/logo.gif');
    open(FH, "<$logofile");
    local $/ = undef;
    my $binary = <FH>;
    close(FH);
    my $data = $jmap->Upload($binary, "image/gif");
    my $dataBlobId = $data->{blobId};

    my $emailBlob = <<'EOF';
From: "Some Example Sender" <example@example.com>
To: baseball@vitaead.com
Subject: test email
Date: Wed, 7 Dec 2016 00:21:50 -0500
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

This is a test email.
EOF
    $emailBlob =~ s/\r?\n/\r\n/gs;
    $data = $jmap->Upload($emailBlob, "application/octet");
    my $rfc822Blobid = $data->{blobId};

    xlog $self, "Create email with body structure";
    my $inboxid = $self->getinbox()->{id};
    my $email = {
        mailboxIds => { $inboxid => JSON::true },
        from => [{ name => "Test", email => q{foo@bar} }],
        subject => "test",
        textBody => [{
            type => 'text/plain',
            partId => '1',
        }],
        bodyValues => {
            '1' => {
                value => "A text body",
            },
        },
        attachments => [{
            type => 'image/gif',
            blobId => $dataBlobId,
        }, {
            type => 'message/rfc822',
            blobId => $rfc822Blobid,
        }],
    };
    my $res = $jmap->CallMethods([
        ['Email/set', { create => { '1' => $email } }, 'R1'],
        ['Email/get', {
            ids => [ '#1' ],
            properties => [ 'bodyStructure' ],
            bodyProperties => [ 'type', 'header:Content-Transfer-Encoding' ],
        }, 'R2' ],
    ]);

    my $gotPart;
    $gotPart = $res->[1][1]{list}[0]{bodyStructure}{subParts}[1];
    $self->assert_str_equals('message/rfc822', $gotPart->{type});
    $self->assert_str_equals(' 7BIT', $gotPart->{'header:Content-Transfer-Encoding'});
    $gotPart = $res->[1][1]{list}[0]{bodyStructure}{subParts}[2];
    $self->assert_str_equals('image/gif', $gotPart->{type});
    $self->assert_str_equals(' BASE64', uc($gotPart->{'header:Content-Transfer-Encoding'}));
}

sub test_email_get_fixbrokenmessageids
    :min_version_3_1 :needs_component_jmap
{

    # See issue https://github.com/cyrusimap/cyrus-imapd/issues/2601

    my ($self) = @_;
    my $jmap = $self->{jmap};

    # An email with a folded reference id.
    my %params = (
        extra_headers => [
            ['references', "<123\r\n\t456\@lo cal>" ],
        ],
    );
    $self->make_message("Email A", %params) || die;

    xlog $self, "get email";
    my $res = $jmap->CallMethods([
        ['Email/query', { }, 'R1'],
        ['Email/get', {
            '#ids' => {
                resultOf => 'R1',
                name => 'Email/query',
                path => '/ids'
            },
            properties => [
                'references'
            ],
        }, 'R2'],
    ]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{ids}});
    my $email = $res->[1][1]->{list}[0];

    $self->assert_str_equals('123456@local', $email->{references}[0]);
}


sub test_email_body_alternative_without_html
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();

    my %exp_sub;
    $store->set_folder("INBOX");
    $store->_select();
    $self->{gen}->set_next_uid(1);

    my $body = "".
    "--sub\r\n".
    "Content-Type: text/plain\r\n".
    "\r\n" .
    "plain text".
    "\r\n--sub\r\n".
    "Content-Type: some/part\r\n".
    "Content-Transfer-Encoding: base64\r\n".
    "\r\n" .
    "abc=".
    "\r\n--sub--\r\n";

    $exp_sub{A} = $self->make_message("foo",
        mime_type => "multipart/alternative",
        mime_boundary => "sub",
        body => $body
    );

    xlog $self, "get email list";
    my $res = $jmap->CallMethods([['Email/query', {}, "R1"]]);
    my $ids = $res->[0][1]->{ids};

    xlog $self, "get email";
    $res = $jmap->CallMethods([['Email/get', {
        ids => $ids,
        properties => ['textBody', 'htmlBody', 'bodyStructure'],
        fetchAllBodyValues => JSON::true
    }, "R1"]]);
    my $msg = $res->[0][1]{list}[0];
    $self->assert_num_equals(1, scalar @{$msg->{textBody}});
    $self->assert_num_equals(1, scalar @{$msg->{htmlBody}});
    $self->assert_str_equals($msg->{textBody}[0]->{partId}, $msg->{htmlBody}[0]->{partId});
}

sub test_email_copy
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $imaptalk = $self->{store}->get_client();
    my $admintalk = $self->{adminstore}->get_client();

    xlog $self, "Create user and share mailbox";
    $self->{instance}->create_user("other");
    $admintalk->setacl("user.other", "cassandane", "lrsiwntex") or die;

    my $srcInboxId = $self->getinbox()->{id};
    $self->assert_not_null($srcInboxId);

    my $dstInboxId = $self->getinbox({accountId => 'other'})->{id};
    $self->assert_not_null($dstInboxId);

    xlog $self, "create email";
    my $res = $jmap->CallMethods([
        ['Email/set', {
            create => {
                1 => {
                    mailboxIds => {
                        $srcInboxId => JSON::true,
                    },
                    keywords => {
                        'foo' => JSON::true,
                    },
                    subject => 'hello',
                    bodyStructure => {
                        type => 'text/plain',
                        partId => 'part1',
                    },
                    bodyValues => {
                        part1 => {
                            value => 'world',
                        }
                    },
                },
            },
        }, 'R1'],
    ]);
    my $emailId = $res->[0][1]->{created}{1}{id};
    $self->assert_not_null($emailId);

    my $email = $res = $jmap->CallMethods([
        ['Email/get', {
            ids => [$emailId],
            properties => ['receivedAt'],
        }, 'R1']
    ]);
    my $receivedAt = $res->[0][1]{list}[0]{receivedAt};
    $self->assert_not_null($receivedAt);

    # Safeguard receivedAt asserts.
    sleep 1;

    xlog $self, "move email";
    $res = $jmap->CallMethods([
        ['Email/copy', {
            fromAccountId => 'cassandane',
            accountId => 'other',
            create => {
                1 => {
                    id => $emailId,
                    mailboxIds => {
                        $dstInboxId => JSON::true,
                    },
                    keywords => {
                        'bar' => JSON::true,
                    },
                },
            },
            onSuccessDestroyOriginal => JSON::true,
        }, 'R1'],
    ]);

    my $copiedEmailId = $res->[0][1]->{created}{1}{id};
    $self->assert_not_null($copiedEmailId);
    $self->assert_str_equals('Email/set', $res->[1][0]);
    $self->assert_str_equals($emailId, $res->[1][1]{destroyed}[0]);

    xlog $self, "get copied email";
    $res = $jmap->CallMethods([
        ['Email/get', {
            accountId => 'other',
            ids => [$copiedEmailId],
            properties => ['keywords', 'receivedAt'],
        }, 'R1']
    ]);
    my $wantKeywords = { 'bar' => JSON::true };
    $self->assert_deep_equals($wantKeywords, $res->[0][1]{list}[0]{keywords});
    $self->assert_str_equals($receivedAt, $res->[0][1]{list}[0]{receivedAt});

    xlog $self, "copy email back";
    $res = $jmap->CallMethods([
        ['Email/copy', {
            accountId => 'cassandane',
            fromAccountId => 'other',
            create => {
                1 => {
                    id => $copiedEmailId,
                    mailboxIds => {
                        $srcInboxId => JSON::true,
                    },
                    keywords => {
                        'bar' => JSON::true,
                    },
                },
            },
        }, 'R1'],
    ]);

    $self->assert_str_equals($copiedEmailId, $res->[0][1]->{created}{1}{id});

    xlog $self, "copy email back (again)";
    $res = $jmap->CallMethods([
        ['Email/copy', {
            accountId => 'cassandane',
            fromAccountId => 'other',
            create => {
                1 => {
                    id => $copiedEmailId,
                    mailboxIds => {
                        $srcInboxId => JSON::true,
                    },
                    keywords => {
                        'bar' => JSON::true,
                    },
                },
            },
        }, 'R1'],
    ]);

   $self->assert_str_equals('alreadyExists', $res->[0][1]->{notCreated}{1}{type});
   $self->assert_not_null($res->[0][1]->{notCreated}{1}{existingId});
}

sub test_email_copy_hasattachment
    :min_version_3_1 :needs_component_jmap :JMAPNoHasAttachment
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $imaptalk = $self->{store}->get_client();
    my $admintalk = $self->{adminstore}->get_client();

    xlog $self, "Create user and share mailbox";
    $self->{instance}->create_user("other");
    $admintalk->setacl("user.other", "cassandane", "lrsiwntex") or die;

    my $srcInboxId = $self->getinbox()->{id};
    $self->assert_not_null($srcInboxId);

    my $dstInboxId = $self->getinbox({accountId => 'other'})->{id};
    $self->assert_not_null($dstInboxId);

    xlog $self, "create emails";
    my $res = $jmap->CallMethods([
        ['Email/set', {
            create => {
                1 => {
                    mailboxIds => {
                        $srcInboxId => JSON::true,
                    },
                    keywords => {
                        'foo' => JSON::true,
                        '$seen' => JSON::true,
                    },
                    subject => 'email1',
                    bodyStructure => {
                        type => 'text/plain',
                        partId => 'part1',
                    },
                    bodyValues => {
                        part1 => {
                            value => 'part1',
                        }
                    },
                },
                2 => {
                    mailboxIds => {
                        $srcInboxId => JSON::true,
                    },
                    keywords => {
                        'foo' => JSON::true,
                        '$seen' => JSON::true,
                    },
                    subject => 'email2',
                    bodyStructure => {
                        type => 'text/plain',
                        partId => 'part2',
                    },
                    bodyValues => {
                        part2 => {
                            value => 'part2',
                        }
                    },
                },
            },
        }, 'R1'],
    ]);
    my $emailId1 = $res->[0][1]->{created}{1}{id};
    $self->assert_not_null($emailId1);
    my $emailId2 = $res->[0][1]->{created}{2}{id};
    $self->assert_not_null($emailId2);

    xlog $self, "set hasAttachment";
    my $store = $self->{store};
    $store->set_folder('INBOX');
    $store->_select();
    my $talk = $store->get_client();
    $talk->store('1:2', '+flags', '($HasAttachment)') or die;

    xlog $self, "copy email";
    $res = $jmap->CallMethods([
        ['Email/copy', {
            fromAccountId => 'cassandane',
            accountId => 'other',
            create => {
                1 => {
                    id => $emailId1,
                    mailboxIds => {
                        $dstInboxId => JSON::true,
                    },
                },
                2 => {
                    id => $emailId2,
                    mailboxIds => {
                        $dstInboxId => JSON::true,
                    },
                    keywords => {
                        'baz' => JSON::true,
                    },
                },
            },
        }, 'R1'],
    ]);

    my $copiedEmailId1 = $res->[0][1]->{created}{1}{id};
    $self->assert_not_null($copiedEmailId1);
    my $copiedEmailId2 = $res->[0][1]->{created}{2}{id};
    $self->assert_not_null($copiedEmailId2);

    xlog $self, "get copied email";
    $res = $jmap->CallMethods([
        ['Email/get', {
            accountId => 'other',
            ids => [$copiedEmailId1, $copiedEmailId2],
            properties => ['keywords'],
        }, 'R1']
    ]);
    my $wantKeywords1 = {
        '$hasattachment' => JSON::true,
        foo => JSON::true,
        '$seen' => JSON::true,
    };
    my $wantKeywords2 = {
        '$hasattachment' => JSON::true,
        baz => JSON::true,
    };
    $self->assert_deep_equals($wantKeywords1, $res->[0][1]{list}[0]{keywords});
    $self->assert_deep_equals($wantKeywords2, $res->[0][1]{list}[1]{keywords});
}

sub test_email_copy_mailboxid_by_role
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $imaptalk = $self->{store}->get_client();
    my $admintalk = $self->{adminstore}->get_client();

    xlog $self, "Create user and share mailbox";
    $self->{instance}->create_user("other");
    $admintalk->setacl("user.other", "cassandane", "lrsiwntex") or die;

    my $srcInboxId = $self->getinbox()->{id};
    $self->assert_not_null($srcInboxId);

    my $dstInboxId = $self->getinbox({accountId => 'other'})->{id};
    $self->assert_not_null($dstInboxId);

    xlog $self, "create email";
    my $res = $jmap->CallMethods([
        ['Email/set', {
            create => {
                1 => {
                    mailboxIds => {
                        $srcInboxId => JSON::true,
                    },
                    keywords => {
                        'foo' => JSON::true,
                    },
                    subject => 'hello',
                    bodyStructure => {
                        type => 'text/plain',
                        partId => 'part1',
                    },
                    bodyValues => {
                        part1 => {
                            value => 'world',
                        }
                    },
                },
            },
        }, 'R1'],
    ]);
    my $emailId = $res->[0][1]->{created}{1}{id};
    $self->assert_not_null($emailId);

    # Copy to other account, with mailbox identified by role
    $res = $jmap->CallMethods([
        ['Email/copy', {
            fromAccountId => 'cassandane',
            accountId => 'other',
            create => {
                1 => {
                    id => $emailId,
                    mailboxIds => {
                        '$inbox' => JSON::true,
                    },
                },
            },
        }, 'R1'],
        ['Email/get', {
            accountId => 'other',
            ids => ['#1'],
            properties => ['mailboxIds'],
        }, 'R2']
    ]);
    $self->assert_not_null($res->[1][1]{list}[0]{mailboxIds}{$dstInboxId});
}

sub test_email_set_destroy_bulk
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $store = $self->{store};

    my $talk = $self->{store}->get_client();

    $talk->create('INBOX.A') or die;
    $talk->create('INBOX.B') or die;

    # Email 1 is in both A and B mailboxes.
    $store->set_folder('INBOX.A');
    $self->make_message('Email 1') || die;
    $talk->copy(1, 'INBOX.B');

    # Email 2 is in mailbox A.
    $store->set_folder('INBOX.A');
    $self->make_message('Email 2') || die;

    # Email 3 is in mailbox B.
    $store->set_folder('INBOX.B');
    $self->make_message('Email 3') || die;

    my $res = $jmap->CallMethods([['Email/query', { }, 'R1']]);
    $self->assert_num_equals(3, scalar @{$res->[0][1]->{ids}});
    my $ids = $res->[0][1]->{ids};

    $res = $jmap->CallMethods([['Email/set', { destroy => $ids }, 'R1']]);
    $self->assert_num_equals(3, scalar @{$res->[0][1]->{destroyed}});

}

sub test_email_set_update_bulk
    :min_version_3_1 :needs_component_jmap :JMAPExtensions
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $store = $self->{store};

    my $talk = $self->{store}->get_client();

    my $using = [
        'https://cyrusimap.org/ns/jmap/debug',
        'urn:ietf:params:jmap:core',
        'urn:ietf:params:jmap:mail',
    ];


    $talk->create('INBOX.A') or die;
    $talk->create('INBOX.B') or die;
    $talk->create('INBOX.C') or die;
    $talk->create('INBOX.D') or die;

    # Get mailboxes
    my $res = $jmap->CallMethods([['Mailbox/get', {}, "R1"]], $using);
    $self->assert_not_null($res);
    my %mboxIdByName = map { $_->{name} => $_->{id} } @{$res->[0][1]{list}};

    # Create email in mailbox A and B
    $store->set_folder('INBOX.A');
    $self->make_message('Email1') || die;
    $talk->copy(1, 'INBOX.B');
    $talk->store(1, "+flags", "(\\Seen hello)");

    # check that the flags aren't on B
    $talk->select("INBOX.B");
    $res = $talk->fetch("1", "(flags)");
    my @flags = @{$res->{1}{flags}};
    $self->assert_null(grep { $_ eq 'hello' } @flags);
    $self->assert_null(grep { $_ eq '\\Seen' } @flags);

    # Create email in mailboox A
    $talk->select("INBOX.A");
    $self->make_message('Email2') || die;

    $res = $jmap->CallMethods([['Email/query', {
        sort => [{ property => 'subject' }],
    }, 'R1']], $using);
    $self->assert_num_equals(2, scalar @{$res->[0][1]->{ids}});
    my $emailId1 = $res->[0][1]->{ids}[0];
    my $emailId2 = $res->[0][1]->{ids}[1];

    $res = $jmap->CallMethods([['Email/set', {
        update => {
            $emailId1 => {
                mailboxIds => {
                    $mboxIdByName{'C'} => JSON::true,
                },
            },
            $emailId2 => {
                mailboxIds => {
                    $mboxIdByName{'C'} => JSON::true,
                },
            }
        },
    }, 'R1']], $using);
    $self->make_message('Email3') || die;

    # check that the flags made it
    $talk->select("INBOX.C");
    $res = $talk->fetch("1", "(flags)");
    @flags = @{$res->{1}{flags}};
    $self->assert_not_null(grep { $_ eq 'hello' } @flags);
    # but \Seen shouldn't
    $self->assert_null(grep { $_ eq '\\Seen' } @flags);

    $res = $jmap->CallMethods([['Email/query', {
        sort => [{ property => 'subject' }],
    }, 'R1']], $using);
    $self->assert_num_equals(3, scalar @{$res->[0][1]->{ids}});
    my @ids = @{$res->[0][1]->{ids}};
    my $emailId3 = $ids[2];

    # now move all the ids to folder 'D' but two are not in the
    # source folder any more
    $res = $jmap->CallMethods([['Email/set', {
        update => {
            map { $_ => {
                 "mailboxIds/$mboxIdByName{'A'}" => undef,
                 "mailboxIds/$mboxIdByName{'D'}" => JSON::true,
            } } @ids,
        },
    }, 'R1']], $using);

    $self->assert_not_null($res);
    $self->assert(exists $res->[0][1]{updated}{$emailId1});
    $self->assert(exists $res->[0][1]{updated}{$emailId2});
    $self->assert(exists $res->[0][1]{updated}{$emailId3});
    $self->assert_null($res->[0][1]{notUpdated});

    $res = $jmap->CallMethods([['Email/get', {
        ids => [$emailId1, $emailId2, $emailId3],
        properties => ['mailboxIds'],
    }, "R1"]], $using);
    my %emailById = map { $_->{id} => $_ } @{$res->[0][1]{list}};

    # now we need to test for actual location
    my $wantMailboxesEmail1 = {
        $mboxIdByName{'C'} => JSON::true,
        $mboxIdByName{'D'} => JSON::true,
    };
    my $wantMailboxesEmail2 = {
        $mboxIdByName{'C'} => JSON::true,
        $mboxIdByName{'D'} => JSON::true,
    };
    my $wantMailboxesEmail3 = {
        $mboxIdByName{'D'} => JSON::true,
    };
    $self->assert_deep_equals($wantMailboxesEmail1, $emailById{$emailId1}->{mailboxIds});
    $self->assert_deep_equals($wantMailboxesEmail2, $emailById{$emailId2}->{mailboxIds});
    $self->assert_deep_equals($wantMailboxesEmail3, $emailById{$emailId3}->{mailboxIds});
}

sub test_email_set_update_after_attach
    :min_version_3_1 :needs_component_jmap :JMAPExtensions
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $store = $self->{store};

    my $talk = $self->{store}->get_client();

    my $using = [
        'https://cyrusimap.org/ns/jmap/debug',
        'urn:ietf:params:jmap:core',
        'urn:ietf:params:jmap:mail',
    ];

    $talk->create('INBOX.A') or die;
    $talk->create('INBOX.B') or die;
    $talk->create('INBOX.C') or die;

    # Get mailboxes
    my $res = $jmap->CallMethods([['Mailbox/get', {}, "R1"]], $using);
    $self->assert_not_null($res);
    my %mboxIdByName = map { $_->{name} => $_->{id} } @{$res->[0][1]{list}};

    # Create email in mailbox A
    $store->set_folder('INBOX.A');
    $self->make_message('Email1') || die;

    $res = $jmap->CallMethods([['Email/query', {
    }, 'R1']], $using);
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{ids}});
    my $emailId = $res->[0][1]->{ids}[0];
    $self->assert_not_null($emailId);

    $res = $jmap->CallMethods([['Email/get', { ids => [ $emailId ],
    }, 'R1']], $using);
    my $blobId = $res->[0][1]->{list}[0]{blobId};
    $self->assert_not_null($blobId);

    $res = $jmap->CallMethods([['Email/set', {
        create => {
            'k1' => {
                mailboxIds => {
                    $mboxIdByName{'B'} => JSON::true,
                },
                from => [{ name => "Test", email => q{test@local} }],
                subject => "test",
                bodyStructure => {
                    type => "multipart/mixed",
                    subParts => [{
                        type => 'text/plain',
                        partId => 'part1',
                    },{
                        type => 'message/rfc822',
                        blobId => $blobId,
                    }],
                },
                bodyValues => {
                    part1 => {
                        value => 'world',
                    }
                },
            },
        },
    }, 'R1']], $using);
    my $newEmailId = $res->[0][1]{created}{k1}{id};
    $self->assert_not_null($newEmailId);

    # now move the new email into folder C
    $res = $jmap->CallMethods([['Email/set', {
        update => {
            $emailId => {
                # set to exact so it picks up the copy in B if we're being buggy
                mailboxIds => { $mboxIdByName{'C'} => JSON::true },
            },
        },
    }, 'R1']], $using);
    $self->assert_not_null($res);
    $self->assert(exists $res->[0][1]{updated}{$emailId});
    $self->assert_null($res->[0][1]{notUpdated});

    $res = $jmap->CallMethods([['Email/get', {
        ids => [$emailId, $newEmailId],
        properties => ['mailboxIds'],
    }, "R1"]], $using);
    $self->assert_num_equals(0, scalar @{$res->[0][1]{notFound}});
    $self->assert_num_equals(2, scalar @{$res->[0][1]{list}});
    my %emailById = map { $_->{id} => $_ } @{$res->[0][1]{list}};

    # now we need to test for actual location
    $self->assert_deep_equals({$mboxIdByName{'C'} => JSON::true},
                              $emailById{$emailId}->{mailboxIds});
    $self->assert_deep_equals({$mboxIdByName{'B'} => JSON::true},
                              $emailById{$newEmailId}->{mailboxIds});
}

sub test_email_set_update_too_many_mailboxes
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $store = $self->{store};
    my $talk = $self->{store}->get_client();

    my $inboxId = $self->getinbox()->{id};

    # Create email in INBOX
    $self->make_message('Email') || die;

    my $res = $jmap->CallMethods([['Email/query', { }, 'R1']]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{ids}});
    my $emailId = $res->[0][1]->{ids}[0];

    my $accountCapabilities = $self->get_account_capabilities();
    my $mailCapabilities = $accountCapabilities->{'urn:ietf:params:jmap:mail'};
    my $maxMailboxesPerEmail = $mailCapabilities->{maxMailboxesPerEmail};
    $self->assert($maxMailboxesPerEmail > 0);

    # Create and get mailboxes
    for (my $i = 1; $i < $maxMailboxesPerEmail + 2; $i++) {
        $talk->create("INBOX.mbox$i") or die;
    }
    $res = $jmap->CallMethods([['Mailbox/get', {}, "R1"]]);
    $self->assert_not_null($res);
    my %mboxIds = map { $_->{id} => JSON::true } @{$res->[0][1]{list}};

    # remove from INBOX
    delete $mboxIds{$inboxId};

    # Move mailbox to too many mailboxes
    $res = $jmap->CallMethods([['Email/set', {
        update => {
            $emailId => {
                mailboxIds => \%mboxIds,
            },
        },
   }, 'R1']]);
   $self->assert_str_equals('tooManyMailboxes', $res->[0][1]{notUpdated}{$emailId}{type});
}

sub test_email_set_update_too_many_mailboxes_lowlimit
    :min_version_3_3 :needs_component_jmap :LowEmailLimits
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $store = $self->{store};
    my $talk = $self->{store}->get_client();

    my $inboxId = $self->getinbox()->{id};

    # Create email in INBOX
    $self->make_message('Email') || die;

    my $res = $jmap->CallMethods([['Email/query', { }, 'R1']]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{ids}});
    my $emailId = $res->[0][1]->{ids}[0];

    my $accountCapabilities = $self->get_account_capabilities();
    my $mailCapabilities = $accountCapabilities->{'urn:ietf:params:jmap:mail'};
    my $maxMailboxesPerEmail = 5; # from the magic
    $self->assert($maxMailboxesPerEmail > 0);

    # Create and get mailboxes
    for (my $i = 1; $i < $maxMailboxesPerEmail + 2; $i++) {
        $talk->create("INBOX.mbox$i") or die;
    }
    $res = $jmap->CallMethods([['Mailbox/get', {}, "R1"]]);
    $self->assert_not_null($res);
    my %mboxIds = map { $_->{id} => JSON::true } @{$res->[0][1]{list}};

    # remove from INBOX
    delete $mboxIds{$inboxId};

    # Move mailbox to too many mailboxes
    $res = $jmap->CallMethods([['Email/set', {
        update => {
            $emailId => {
                mailboxIds => \%mboxIds,
            },
        },
    }, 'R1']]);
    $self->assert_str_equals('tooManyMailboxes', $res->[0][1]{notUpdated}{$emailId}{type});

    if ($self->{instance}->{have_syslog_replacement}) {
        my @lines = $self->{instance}->getsyslog();
        $self->assert(grep { m/IOERROR: conversations GUID limit/ } @lines);
    }
}

sub test_email_set_update_too_many_keywords
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $store = $self->{store};
    my $talk = $self->{store}->get_client();

    my $inboxId = $self->getinbox()->{id};

    # Create email in INBOX
    $self->make_message('Email') || die;

    my $res = $jmap->CallMethods([['Email/query', { }, 'R1']]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{ids}});
    my $emailId = $res->[0][1]->{ids}[0];

    my $accountCapabilities = $self->get_account_capabilities();
    my $mailCapabilities = $accountCapabilities->{'urn:ietf:params:jmap:mail'};
    my $maxKeywordsPerEmail = $mailCapabilities->{maxKeywordsPerEmail};
    $self->assert($maxKeywordsPerEmail > 0);

    # Set lots of keywords on this email
    my %keywords;
    for (my $i = 1; $i < $maxKeywordsPerEmail + 2; $i++) {
        $keywords{"keyword$i"} = JSON::true;
    }
    $res = $jmap->CallMethods([['Email/set', {
        update => {
            $emailId => {
                keywords => \%keywords,
            },
        },
   }, 'R1']]);
   $self->assert_str_equals('tooManyKeywords', $res->[0][1]{notUpdated}{$emailId}{type});
}

sub test_email_get_headers_multipart
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();
    my $inbox = 'INBOX';

    xlog $self, "Generate a email in $inbox via IMAP";
    my %exp_sub;
    $store->set_folder($inbox);
    $store->_select();
    $self->{gen}->set_next_uid(1);

    my $htmlBody = "<html><body><p>This is the html part.</p></body></html>";
    my $textBody = "This is the plain text part.";

    my $body = "--047d7b33dd729737fe04d3bde348\r\n";
    $body .= "Content-Type: text/plain; charset=UTF-8\r\n";
    $body .= "\r\n";
    $body .= $textBody;
    $body .= "\r\n";
    $body .= "--047d7b33dd729737fe04d3bde348\r\n";
    $body .= "Content-Type: text/html;charset=\"UTF-8\"\r\n";
    $body .= "\r\n";
    $body .= $htmlBody;
    $body .= "\r\n";
    $body .= "--047d7b33dd729737fe04d3bde348--\r\n";
    $exp_sub{A} = $self->make_message("foo",
        mime_type => "multipart/alternative",
        mime_boundary => "047d7b33dd729737fe04d3bde348",
        body => $body,
        extra_headers => [['X-Spam-Hits', 'SPAMA, SPAMB, SPAMC']],
    );

    xlog $self, "get email list";
    my $res = $jmap->CallMethods([['Email/query', {}, "R1"]]);
    my $ids = $res->[0][1]->{ids};

    xlog $self, "get email";
    $res = $jmap->CallMethods([['Email/get', {
        ids => $ids,
        properties => [ "header:x-spam-hits:asRaw", "header:x-spam-hits:asText" ],
    }, "R1"]]);
    my $msg = $res->[0][1]{list}[0];

    $self->assert_str_equals(' SPAMA, SPAMB, SPAMC', $msg->{"header:x-spam-hits:asRaw"});
    $self->assert_str_equals('SPAMA, SPAMB, SPAMC', $msg->{"header:x-spam-hits:asText"});
}

sub test_email_get_brokenheader_split_codepoint
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $email = <<'EOF';
From: "Some Example Sender" <example@example.com>
To: baseball@vitaead.com
Subject: =?UTF-8?Q?=F0=9F=98=80=F0=9F=98=83=F0=9F=98=84=F0=9F=98=81=F0=9F=98=86=F0?=
 =?UTF-8?Q?=9F=98=85=F0=9F=98=82=F0=9F=A4=A3=E2=98=BA=EF=B8=8F=F0=9F=98=8A?=
  =?UTF-8?Q?=F0=9F=98=87?=
Date: Wed, 7 Dec 2016 00:21:50 -0500
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: foobar

This is a test email.
EOF
    $email =~ s/\r?\n/\r\n/gs;
    my $data = $jmap->Upload($email, "message/rfc822");
    my $blobid = $data->{blobId};
    my $inboxid = $self->getinbox()->{id};

    my $wantSubject = '😀😃😄😁😆😅😂🤣☺️😊😇';
    utf8::decode($wantSubject);

    xlog $self, "import and get email from blob $blobid";
    my $res = $jmap->CallMethods([['Email/import', {
        emails => {
            "1" => {
                blobId => $blobid,
                mailboxIds => {$inboxid =>  JSON::true},
            },
        },
    }, "R1"], ["Email/get", {
        ids => ["#1"],
        properties => ['subject'],
    }, "R2" ]]);

    $self->assert_str_equals($wantSubject, $res->[1][1]{list}[0]{subject});
}

sub test_email_get_detect_utf32
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $email = <<'EOF';
From: "Some Example Sender" <example@example.com>
To: baseball@vitaead.com
Subject: Here are some base64-encoded UTF-32LE bytes without BOM.
Date: Wed, 7 Dec 2016 00:21:50 -0500
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-32"
Content-Transfer-Encoding: base64

QjAAAIEwAACKMAAASzAAAGlyAACeigAADQAAAAoAAAANAAAACgAAAAAwAAAOZgAAu2wAAAlOAABB
UwAAbVEAAHReAABuMAAAy3kAAEFTAAAIZwAAbjAAAAOYAACIMAAAijAAAHN8AAALVwAAazAAAEqQ
AABzMAAAZjAAAMpOAAAygwAADmYAALtsAADbVgAAQVMAAHReAAANAAAACgAAAAAwAABuMAAAD1kA
AANOAAAIZwAA1TAAAOkwAADzMAAAuTAAAGswAAARVAAAcjAAAGYwAADLMAAA5TAAAPwwAADoMAAA
/DAAAK8wAACSMAAAu1MAAIswAABrMAAA6IEAAH8wAAABMAAA5WUAAAOYAAANAAAACgAAAAAwAADF
ZQAAl3oAAGswAAD4ZgAATTAAALR9AACKMAAAXzAAAIswAACCMAAAbjAAAJIwAAChYwAAijAAAMaW
AACBMAAAZjAAAAEwAABCMAAAgTAAAIowAABLMAAAgjAAAG4wAABMMAAAXzAAAIowAAANAAAACgAA
AAAwAABoMAAATJgAAFcwAAABMAAAY/oAAJMwAABnMAAAjzAAAEwwAABpYAAAK14AAGswAABXMAAA
ZjAAAGlgAADLUwAAajAAAIswAAAPXAAA4mwAAHFcAAC6TgAA1l0AADeMAABIUQAAH3UAAG4wAAAN
AAAACgAAAAAwAAA6ZwAAC04AAGswAABIVAAAWTAAAAIwAAAOZgAAu2wAANtWAABBUwAAdF4AAEFT
AAAATgAACGcAAMyRAAA7ZgAAazAAAGYwAAA4bAAAlU4AAHeDAAComAAAAjAAAA0AAAAKAAAADQAA
AAoAAAAAMAAAOYIAAD9iAAAcWQAAcYoAAA0AAAAKAAAADQAAAAoAAAAAMAAAVU8AAFWGAAAKMAAA
RDAAAGUwAABTMAAACzAAAGswAABXMAAAZjAAAIIwAAB4lgAAkjAAAIuJAACLMAAAi04AAG4wAAD6
UQAAhk8AAGowAABEMAAAKoIAAEX6AABvMAAAATAAAIZrAABpMAAAKlgAAHgwAABo+gAARDAAAAt6
AAAhcQAASoAAAAowAAB2MAAAjDAAAEYwAAALMAAAazAAAOaCAABXMAAAgTAAAIkwAACMMAAAizAA
AIIwAABuMAAAZzAAAEIwAACLMAAATDAAAAEwAABragAA8W8AAEswAACJMAAAnk4AAHN8AAApUgAA
oFIAAAowAABCMAAAgTAAAIowAABLMAAACzAAAG4wAACwZQAAi5UAADBXAAC3MAAAojAAAMgwAADr
MAAAbjAAAC9uAAB4MAAAGpAAAHUwAAAqggAARfoAAAEwAABkawAAjDAAAIIwAABdMAAAbjAAAABO
AADEMAAAZzAAAEIwAACJMAAARjAAAAIwAAANAAAACgAAAAAwAAD6UQAABl4AAFcwAABfMAAA5WUA
AAEwAABFZQAAC1cAAG4wAABxXAAAcV8AAGswAAAlUgAAjDAAAF8wAABqMAAAiTAAAAEwAAA5ggAA
olsAAG8wAAB8XwAAuFwAAG4wAAAnWQAAeJYAAGswAAA5kAAAWTAAAIswAAB2UQAAbjAAAOVlAAB+
MAAAZzAAAAEwAABKUwAACGcAAEIwAAB+MAAAijAAAG4wAACTlQAAATAAAABOAADEMAAAbjAAAPZc
AAABMAAAAE4AAMQwAABuMAAAcVwAAJIwAACCMAAAi4kAAIswAACLTgAAbzAAAPpRAACGTwAAajAA
AEQwAAACMAAAKGYAAOVlAACCMAAARfoAAAEwAADKTgAA5WUAAIIwAABF+gAAFSAAABUgAAAVIAAA
VU8AAEJmAACLiQAAZjAAAIIwAACKiwAAiTAAAGwwAAAqWQAAc14AAAttAABuMAAAOncAABtnAAAK
MAAAajAAAEwwAACBMAAACzAAAGgwAACRTgAAdTAAAG4wAABvMAAAL1UAAGAwAAArgwAAIG8AAGgw
AABXMAAAZjAAAAEwAAAnWQAATTAAAGowAADibAAAam0AAAowAABqMAAAfzAAAAswAABuMAAAd40A
AA9PAABZMAAAizAAAIqQAABrMAAA/H8AAG4wAAB3lQAARDAAADRWAAAKMAAATzAAAGEwAABwMAAA
VzAAAAswAABuMAAA8mYAAGQwAABfMAAAcHAAAHKCAABuMAAA4U8AAClZAADBfwAACjAAAEIwAABv
MAAARjAAAGkwAACKMAAACzAAAG4wAADbmAAAczAAAPteAABkMAAAZjAAAJAwAACLMAAAcDAAAEsw
AACKMAAAZzAAAEIwAACLMAAAAjAAAF0wAABuMAAACk4AAGswAACCMAAAKVkAACNsAABvMAAAIWsA
ACx7AABrMAAAF1MAAG4wAAC5ZQAAeDAAAGgwAAAykAAAgDAAAGswAAAjkAAAjDAAAGYwAADDXwAA
MFcAAIgwAABPMAAAEvoAAIwwAAAhbgAAizAAAItOAABvMAAAAHoAAGswAABqMAAAijAAAAEwAAB+
MAAAZTAAAM9rAADlZQAAbjAAAIQwAABGMAAAazAAAHp6AABvMAAAl2YAALlvAABfMAAAizAAACCf
AAByggAAbjAAAPKWAABrMAAAPYUAAHIwAADhdgAAVTAAAIswAACdMAAAbjAAAH8wAABLMAAA1VIA
AAowAACEMAAAnTAAAAswAACCMAAAWTAAAIwwAABwMAAA6JYAAEswAADIUwAAbzAAACeXAABrMAAA
ajAAAGQwAABmMAAAhk4AAHUwAAACMAAADQAAAAoAAAAAMAAAwXkAAG8wAAAWVwAAiTAAAFowAACC
MAAAZGsAAMttAABXMAAARDAAAEX6AABuMAAACk4AAG4wAADFZQAAuk4AAGswAABqMAAAZDAAAF8w
AAACMAAAXTAAAFcwAABmMAAA6WUAAE8wAACCMAAAQVMAAOVlAABwMAAASzAAAIowAABuMAAA5WUA
AHhlAACSMAAAAZAAAIowAACXXwAAXzAAAFWGAABnMAAAQjAAAIswAAACMAAAXWYAAJOVAABqMAAA
iTAAAHAwAAAydQAAf2cAAGcwAACwdAAAlWIAAAowAACPMAAAajAAAFIwAAALMAAAbjAAAEqQAABz
MAAAATAAAOWCAABXMAAATzAAAG8wAACrVQAAWXEAAKRbAABnMAAAqJoAAExyAAAKMAAASzAAAIsw
AABfMAAACzAAAJIwAADWUwAAijAAAGowAABeMAAAVzAAAGYwAAABMAAAaTAAAEYwAABLMAAAr2UA
AEYwAABLMAAAQmYAAJOVAACSMAAAiG0AALuMAABZMAAAizAAAItOAABMMAAA+lEAAIZPAACLMAAA
UTAAAIwwAABpMAAAATAAAFUwAABmMAAAWmYAABCZAABuMAAA35gAAFNTAAAKMAAAxjAAAPwwAADW
MAAA6zAAAAswAACSMAAA4pYAAIwwAABmMAAASzAAAIkwAABuMAAAHFkAAGswAABqMAAAizAAAGgw
AAABMAAAhmsAAGkwAAAycgAAWTAAAItOAABMMAAAIXEAAE8wAABqMAAAZDAAAGYwAACGTgAAdTAA
AAIwAAAUTgAAZDAAAMpOAADlZQAAQjAAAF8wAACKMAAAbzAAABiZAAALegAAI2wAABlQAACCMAAA
0lsAAE8wAABqMAAAZDAAAGYwAACGTwAAXzAAAIQwAABGMAAAYDAAAAIwAAAWWQAAV1kAAGowAABX
MAAAZzAAAG8wAABoMAAAZjAAAIIwAAAydQAAf2cAAJIwAABlawAARDAAAGYwAACrVQAAWXEAAKRb
AAB4MAAAgjAAAEyIAABLMAAAjDAAAH4wAABEMAAAaDAAAB1gAAB1MAAAQGIAAEswAACJMAAAATAA
AMF5AABvMAAAdlEAAG4wAAAYUQAAXP8AADmCAAA/YgAACjAAAK0wAADkMAAA0zAAAPMwAAALMAAA
azAAAImVAABYMAAAYHwAAGQwAABmMAAAATAAAOVlAAAsZwAASzAAAIkwAAABYwAAZDAAAGYwAACG
TwAAXzAAANyWAACMigAAZzAAAIIwAACLlQAASzAAAEYwAABLMAAAaDAAAB1gAABkMAAAZjAAAEVc
AACLMAAAaDAAAAEwAAB2UQAAbjAAAEJmAACkWwAAbjAAADZiAACSMAAAB2MAAEhRAABnMAAAszAA
AMgwAAAzMAAANTAAAGgwAAAVjwAATzAAAOlTAABPMAAAgjAAAG4wAABMMAAAQjAAAIswAAACMAAA
DQAAAAoA
EOF
    $email =~ s/\r?\n/\r\n/gs;
    my $data = $jmap->Upload($email, "message/rfc822");
    my $blobid = $data->{blobId};
    my $inboxid = $self->getinbox()->{id};

    xlog $self, "import and get email from blob $blobid";
    my $res = $jmap->CallMethods([['Email/import', {
        emails => {
            "1" => {
                blobId => $blobid,
                mailboxIds => {$inboxid =>  JSON::true},
            },
        },
    }, "R1"], ["Email/get", {
        ids => ["#1"],
        properties => ['textBody', 'bodyValues', 'preview'],
        fetchTextBodyValues => JSON::true,
    }, "R2" ]]);

    $self->assert_num_equals(0,
        index($res->[1][1]{list}[0]{bodyValues}{1}{value},
            "\N{HIRAGANA LETTER A}" .
            "\N{HIRAGANA LETTER ME}" .
            "\N{HIRAGANA LETTER RI}")
    );
    $self->assert_equals(JSON::true, $res->[1][1]{list}[0]{bodyValues}{1}{isEncodingProblem});
}

sub test_email_get_detect_iso_8859_1
    :min_version_3_1 :needs_component_jmap :needs_dependency_chardet
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    my $email = <<'EOF';
From: "Some Example Sender" <example@example.com>
To: baseball@vitaead.com
Subject: Here is some ISO-8859-1 text that claims to be ascii
Date: Wed, 7 Dec 2016 00:21:50 -0500
MIME-Version: 1.0
Content-Type: text/plain
Content-Transfer-Encoding: base64

Ikvkc2Ugc2NobGllc3N0IGRlbiBNYWdlbiIsIGj2cnRlIGljaCBkZW4gU2NobG/faGVycm4gc2FnZW4uCg==

EOF
    $email =~ s/\r?\n/\r\n/gs;
    my $data = $jmap->Upload($email, "message/rfc822");
    my $blobid = $data->{blobId};
    my $inboxid = $self->getinbox()->{id};

    xlog $self, "import and get email from blob $blobid";
    my $res = $jmap->CallMethods([['Email/import', {
        emails => {
            "1" => {
                blobId => $blobid,
                mailboxIds => {$inboxid =>  JSON::true},
            },
        },
    }, "R1"], ["Email/get", {
        ids => ["#1"],
        properties => ['textBody', 'bodyValues'],
        fetchTextBodyValues => JSON::true,
    }, "R2" ]]);

    $self->assert_num_equals(0,
        index($res->[1][1]{list}[0]{bodyValues}{1}{value},
            "\"K\N{LATIN SMALL LETTER A WITH DIAERESIS}se")
    );
    $self->assert_equals(JSON::true, $res->[1][1]{list}[0]{bodyValues}{1}{isEncodingProblem});
}

sub test_email_set_intermediary_create
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $imap = $self->{store}->get_client();

    xlog $self, "Create mailboxes";
    $imap->create("INBOX.i1.foo") or die;
    my $res = $jmap->CallMethods([
        ['Mailbox/get', {
            properties => ['name', 'parentId'],
        }, "R1"]
    ]);
    my %mboxByName = map { $_->{name} => $_ } @{$res->[0][1]{list}};
    my $mboxId1 = $mboxByName{'i1'}->{id};

    xlog $self, "Create email in intermediary mailbox";
    my $email =  {
        mailboxIds => {
            $mboxId1 => JSON::true
        },
        from => [{
            email => q{test1@local},
            name => q{}
        }],
        to => [{
            email => q{test2@local},
            name => '',
        }],
        subject => 'foo',
    };

    xlog $self, "create and get email";
    $res = $jmap->CallMethods([
        ['Email/set', { create => { "1" => $email }}, "R1"],
        ['Email/get', { ids => [ "#1" ] }, "R2" ],
    ]);
    $self->assert_not_null($res->[0][1]{created}{1});
    $self->assert_equals(JSON::true, $res->[1][1]{list}[0]{mailboxIds}{$mboxId1});
}

sub test_email_set_intermediary_move
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $imap = $self->{store}->get_client();

    xlog $self, "Create mailboxes";
    $imap->create("INBOX.i1.foo") or die;
    my $res = $jmap->CallMethods([
        ['Mailbox/get', {
            properties => ['name', 'parentId'],
        }, "R1"]
    ]);
    my %mboxByName = map { $_->{name} => $_ } @{$res->[0][1]{list}};
    my $mboxId1 = $mboxByName{'i1'}->{id};
    my $mboxIdFoo = $mboxByName{'foo'}->{id};

    xlog $self, "Create email";
    my $email =  {
        mailboxIds => {
            $mboxIdFoo => JSON::true
        },
        from => [{
            email => q{test1@local},
            name => q{}
        }],
        to => [{
            email => q{test2@local},
            name => '',
        }],
        subject => 'foo',
    };
    xlog $self, "create and get email";
    $res = $jmap->CallMethods([
        ['Email/set', { create => { "1" => $email }}, "R1"],
    ]);
    my $emailId = $res->[0][1]{created}{1}{id};
    $self->assert_not_null($emailId);

    xlog $self, "Move email to intermediary mailbox";
    $res = $jmap->CallMethods([
        ['Email/set', {
            update => {
                $emailId => {
                    mailboxIds => {
                        $mboxId1 => JSON::true,
                    },
                },
            },
        }, 'R1'],
        ['Email/get', { ids => [ $emailId ] }, "R2" ],
    ]);
    $self->assert(exists $res->[0][1]{updated}{$emailId});
    $self->assert_equals(JSON::true, $res->[1][1]{list}[0]{mailboxIds}{$mboxId1});
}

sub test_email_copy_intermediary
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $imaptalk = $self->{store}->get_client();
    my $admintalk = $self->{adminstore}->get_client();

    xlog $self, "Create user and share mailbox";
    $self->{instance}->create_user("other");
    $admintalk->setacl("user.other", "cassandane", "lrsiwntex") or die;
    $admintalk->create("user.other.i1.box") or die;
    my $res = $jmap->CallMethods([
        ['Mailbox/get', {
            accountId => 'other',
            properties => ['name'],
        }, "R1"]
    ]);
    my %mboxByName = map { $_->{name} => $_ } @{$res->[0][1]{list}};
    my $dstMboxId = $mboxByName{'i1'}->{id};
    $self->assert_not_null($dstMboxId);

    my $srcInboxId = $self->getinbox()->{id};
    $self->assert_not_null($srcInboxId);

    xlog $self, "create email";
    $res = $jmap->CallMethods([
        ['Email/set', {
            create => {
                1 => {
                    mailboxIds => {
                        $srcInboxId => JSON::true,
                    },
                    keywords => {
                        'foo' => JSON::true,
                    },
                    subject => 'hello',
                    bodyStructure => {
                        type => 'text/plain',
                        partId => 'part1',
                    },
                    bodyValues => {
                        part1 => {
                            value => 'world',
                        }
                    },
                },
            },
        }, 'R1'],
    ]);
    my $emailId = $res->[0][1]->{created}{1}{id};
    $self->assert_not_null($emailId);

    xlog $self, "move email";
    $res = $jmap->CallMethods([
        ['Email/copy', {
            fromAccountId => 'cassandane',
            accountId => 'other',
            create => {
                1 => {
                    id => $emailId,
                    mailboxIds => {
                        $dstMboxId => JSON::true,
                    },
                },
            },
        }, 'R1'],
    ]);

    my $copiedEmailId = $res->[0][1]->{created}{1}{id};
    $self->assert_not_null($copiedEmailId);

    xlog $self, "get copied email";
    $res = $jmap->CallMethods([
        ['Email/get', {
            accountId => 'other',
            ids => [$copiedEmailId],
            properties => ['mailboxIds'],
        }, 'R1']
    ]);
    $self->assert_equals(JSON::true, $res->[0][1]{list}[0]{mailboxIds}{$dstMboxId});
}

sub test_email_set_setflags_mboxevent
    :min_version_3_1 :needs_component_jmap
{

    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $imap = $self->{store}->get_client();

    xlog $self, "create mailboxes";
    my $res = $jmap->CallMethods([
        ['Mailbox/set', {
            create => {
                "A" => {
                    name => "A",
                },
                "B" => {
                    name => "B",
                },
            },
        }, "R1"]
    ]);
    my $mboxIdA = $res->[0][1]{created}{A}{id};
    $self->assert_not_null($mboxIdA);
    my $mboxIdB = $res->[0][1]{created}{B}{id};
    $self->assert_not_null($mboxIdB);

    xlog $self, "Create emails";
    # Use separate requests for deterministic order of UIDs.
    $res = $jmap->CallMethods([
        ['Email/set', {
            create => {
                msgA1 => {
                    mailboxIds => {
                        $mboxIdA => JSON::true
                    },
                    from => [{
                            email => q{test1@local},
                            name => q{}
                        }],
                    to => [{
                            email => q{test2@local},
                            name => '',
                        }],
                    subject => 'msgA1',
                    keywords => {
                        '$seen' => JSON::true,
                    },
                },
            }
        }, "R1"],
        ['Email/set', {
            create => {
                msgA2 => {
                    mailboxIds => {
                        $mboxIdA => JSON::true
                    },
                    from => [{
                            email => q{test1@local},
                            name => q{}
                        }],
                    to => [{
                            email => q{test2@local},
                            name => '',
                        }],
                    subject => 'msgA2',
                },
            }
        }, "R2"],
        ['Email/set', {
            create => {
                msgB1 => {
                    mailboxIds => {
                        $mboxIdB => JSON::true
                    },
                    from => [{
                            email => q{test1@local},
                            name => q{}
                        }],
                    to => [{
                            email => q{test2@local},
                            name => '',
                        }],
                    keywords => {
                        baz => JSON::true,
                    },
                    subject => 'msgB1',
                },
            }
        }, "R3"],
    ]);
    my $emailIdA1 = $res->[0][1]{created}{msgA1}{id};
    $self->assert_not_null($emailIdA1);
    my $emailIdA2 = $res->[1][1]{created}{msgA2}{id};
    $self->assert_not_null($emailIdA2);
    my $emailIdB1 = $res->[2][1]{created}{msgB1}{id};
    $self->assert_not_null($emailIdB1);

    # Clear notification cache
    $self->{instance}->getnotify();

    # Update emails
    $res = $jmap->CallMethods([
        ['Email/set', {
            update => {
                $emailIdA1 => {
                    'keywords/$seen' => undef,
                    'keywords/foo' => JSON::true,
                },
                $emailIdA2 => {
                    keywords => {
                        'bar' => JSON::true,
                    },
                },
                $emailIdB1 => {
                    'keywords/baz' => undef,
                },
            }
        }, "R1"],
    ]);
    $self->assert(exists $res->[0][1]{updated}{$emailIdA1});
    $self->assert(exists $res->[0][1]{updated}{$emailIdA2});
    $self->assert(exists $res->[0][1]{updated}{$emailIdB1});

    # Gather notifications
    my $data = $self->{instance}->getnotify();
    if ($self->{replica}) {
        my $more = $self->{replica}->getnotify();
        push @$data, @$more;
    }

    # Assert notifications
    my %flagsClearEvents;
    my %flagsSetEvents;
    foreach (@$data) {
        my $event = decode_json($_->{MESSAGE});
        if ($event->{event} eq "FlagsClear") {
            $flagsClearEvents{$event->{mailboxID}} = $event;
        }
        elsif ($event->{event} eq "FlagsSet") {
            $flagsSetEvents{$event->{mailboxID}} = $event;
        }
    }

    # Assert mailbox A events.
    $self->assert_str_equals('1:2', $flagsSetEvents{$mboxIdA}{uidset});
    $self->assert_num_not_equals(-1, index($flagsSetEvents{$mboxIdA}{flagNames}, 'foo'));
    $self->assert_num_not_equals(-1, index($flagsSetEvents{$mboxIdA}{flagNames}, 'bar'));
    $self->assert_str_equals('1', $flagsClearEvents{$mboxIdA}{uidset});
    $self->assert_str_equals('\Seen', $flagsClearEvents{$mboxIdA}{flagNames});

    # Assert mailbox B events.
    $self->assert(not exists $flagsSetEvents{$mboxIdB});
    $self->assert_str_equals('1', $flagsClearEvents{$mboxIdB}{uidset});
    $self->assert_str_equals('baz', $flagsClearEvents{$mboxIdB}{flagNames});
}

sub test_implementation_email_query
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();

    # These assertions are implementation-specific. Breaking them
    # isn't necessarly a regression, but change them with caution.

    my $now = DateTime->now();

    xlog $self, "Generate a email in INBOX via IMAP";
    my $res = $self->make_message("foo") || die;
    my $uid = $res->{attrs}->{uid};
    my $msg;

    my $inbox = $self->getinbox();

    xlog $self, "non-filtered query can calculate changes";
    $res = $jmap->CallMethods([['Email/query', {}, "R1"]]);
    $self->assert($res->[0][1]{canCalculateChanges});

    xlog $self, "inMailbox query can calculate changes";
    $res = $jmap->CallMethods([
        ['Email/query', {
          filter => { inMailbox => $inbox->{id} },
          sort => [ {
            isAscending => $JSON::false,
            property => 'receivedAt',
          } ],
        }, "R1"],
    ]);
    $self->assert_equals(JSON::true, $res->[0][1]{canCalculateChanges});

    xlog $self, "inMailbox query can calculate changes with mutable sort";
    $res = $jmap->CallMethods([
        ['Email/query', {
          filter => { inMailbox => $inbox->{id} },
          sort => [ {
            property => "someInThreadHaveKeyword",
            keyword => "\$seen",
            isAscending => $JSON::false,
          }, {
            property => 'receivedAt',
            isAscending => $JSON::false,
          } ],
        }, "R1"],
    ]);
    $self->assert_equals(JSON::true, $res->[0][1]{canCalculateChanges});

    xlog $self, "inMailbox query with keyword can not calculate changes";
    $res = $jmap->CallMethods([
        ['Email/query', {
          filter => {
            conditions => [
              { inMailbox => $inbox->{id} },
              { conditions => [ { allInThreadHaveKeyword => "\$seen" } ],
                operator => 'NOT',
              },
            ],
            operator => 'AND',
          },
            sort => [ {
                isAscending => $JSON::false,
                property => 'receivedAt',
            } ],
        }, "R1"],
    ]);
    $self->assert_equals(JSON::false, $res->[0][1]{canCalculateChanges});

    xlog $self, "negated inMailbox query can not calculate changes";
    $res = $jmap->CallMethods([
        ['Email/query', {
          filter => {
            operator => 'NOT',
            conditions => [
              { inMailbox => $inbox->{id} },
            ],
          },
        }, "R1"],
    ]);
    $self->assert_equals(JSON::false, $res->[0][1]{canCalculateChanges});

    xlog $self, "inMailboxOtherThan query can not calculate changes";
    $res = $jmap->CallMethods([
        ['Email/query', {
          filter => {
            operator => 'NOT',
            conditions => [
              { inMailboxOtherThan => [$inbox->{id}] },
            ],
          },
        }, "R1"],
    ]);
    $self->assert_equals(JSON::false, $res->[0][1]{canCalculateChanges});
}

sub _set_quotaroot
{
    my ($self, $quotaroot) = @_;
    $self->{quotaroot} = $quotaroot;
}

sub _set_quotalimits
{
    my ($self, %resources) = @_;
    my $admintalk = $self->{adminstore}->get_client();

    my $quotaroot = delete $resources{quotaroot} || $self->{quotaroot};
    my @quotalist;
    foreach my $resource (keys %resources)
    {
        my $limit = $resources{$resource}
            or die "No limit specified for $resource";
        push(@quotalist, uc($resource), $limit);
    }
    $self->{limits}->{$quotaroot} = { @quotalist };
    $admintalk->setquota($quotaroot, \@quotalist);
    $self->assert_str_equals('ok', $admintalk->get_last_completion_response());
}

sub test_email_set_getquota
    :min_version_3_1 :needs_component_jmap :JMAPExtensions
{
    my ($self) = @_;

    $self->_set_quotaroot('user.cassandane');
    xlog $self, "set ourselves a basic limit";
    $self->_set_quotalimits(storage => 1000); # that's 1000 * 1024 bytes

    my $jmap = $self->{jmap};
    my $service = $self->{instance}->get_service("http");
    my $inboxId = $self->getinbox()->{id};

    # we need 'https://cyrusimap.org/ns/jmap/quota' capability for
    # Quota/get method
    my @using = @{ $jmap->DefaultUsing() };
    push @using, 'https://cyrusimap.org/ns/jmap/quota';
    $jmap->DefaultUsing(\@using);

    my $res;

    $res = $jmap->CallMethods([
        ['Quota/get', {
            accountId => 'cassandane',
            ids => undef,
        }, 'R1'],
    ]);

    my $mailQuota = $res->[0][1]{list}[0];
    $self->assert_str_equals('mail', $mailQuota->{id});
    $self->assert_num_equals(0, $mailQuota->{used});
    $self->assert_num_equals(1000 * 1024, $mailQuota->{total});
    my $quotaState = $res->[0][1]{state};
    $self->assert_not_null($quotaState);

    xlog $self, "Create email";
    $res = $jmap->CallMethods([
        ['Email/set', {
            create => {
                msgA1 => {
                    mailboxIds => {
                        $inboxId => JSON::true,
                    },
                    from => [{
                            email => q{test1@local},
                            name => q{}
                        }],
                    to => [{
                            email => q{test2@local},
                            name => '',
                        }],
                    subject => 'foo',
                    keywords => {
                        '$seen' => JSON::true,
                    },
                },
            }
        }, "R1"],
        ['Quota/get', {}, 'R2'],
    ]);

    $self->assert_str_equals('Quota/get', $res->[1][0]);
    $mailQuota = $res->[1][1]{list}[0];
    $self->assert_str_equals('mail', $mailQuota->{id});
    $self->assert_num_not_equals(0, $mailQuota->{used});
    $self->assert_num_equals(1000 * 1024, $mailQuota->{total});
    $self->assert_str_not_equals($quotaState, $res->[1][1]{state});
}

sub test_email_set_mailbox_alias
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $imaptalk = $self->{store}->get_client();

    # Create mailboxes
    my $res = $jmap->CallMethods([
        ['Mailbox/set', {
            create => {
                "drafts" => {
                    name => "Drafts",
                    parentId => undef,
                    role => "drafts"
                },
                "trash" => {
                    name => "Trash",
                    parentId => undef,
                    role => "trash"
                }
            }
        }, "R1"]
    ]);
    my $draftsMboxId = $res->[0][1]{created}{drafts}{id};
    $self->assert_not_null($draftsMboxId);
    my $trashMboxId = $res->[0][1]{created}{trash}{id};
    $self->assert_not_null($trashMboxId);

    # Create email in mailbox using role as id
    $res = $jmap->CallMethods([
        ['Email/set', {
            create => {
                "1" => {
                    mailboxIds => {
                        '$drafts' => JSON::true
                    },
                    from => [{ email => q{from@local}, name => q{} } ],
                    to => [{ email => q{to@local}, name => q{} } ],
                }
            },
        }, 'R1'],
        ['Email/get', {
            ids => [ "#1" ],
            properties => ['mailboxIds'],
        }, "R2" ],
    ]);
    $self->assert_num_equals(1, scalar keys %{$res->[1][1]{list}[0]{mailboxIds}});
    $self->assert_not_null($res->[1][1]{list}[0]{mailboxIds}{$draftsMboxId});
    my $emailId = $res->[0][1]{created}{1}{id};

    # Move email to mailbox using role as id
    $res = $jmap->CallMethods([
        ['Email/set', {
            update => {
                $emailId => {
                    'mailboxIds/$drafts' => undef,
                    'mailboxIds/$trash' => JSON::true
                }
            },
        }, 'R1'],
        ['Email/get', {
            ids => [ $emailId ],
            properties => ['mailboxIds'],
        }, "R2" ],
    ]);
    $self->assert_num_equals(1, scalar keys %{$res->[1][1]{list}[0]{mailboxIds}});
    $self->assert_not_null($res->[1][1]{list}[0]{mailboxIds}{$trashMboxId});
}

sub test_email_set_update_mailbox_creationid
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $imaptalk = $self->{store}->get_client();

    # Create emails
    my $res = $jmap->CallMethods([
        ['Email/set', {
            create => {
                "msg1" => {
                    mailboxIds => {
                        '$inbox' => JSON::true
                    },
                    from => [{ email => q{from1@local}, name => q{} } ],
                    to => [{ email => q{to1@local}, name => q{} } ],
                },
                "msg2" => {
                    mailboxIds => {
                        '$inbox' => JSON::true
                    },
                    from => [{ email => q{from2@local}, name => q{} } ],
                    to => [{ email => q{to2@local}, name => q{} } ],
                }
            },
        }, 'R1'],
        ['Email/get', {
            ids => [ '#msg1', '#msg2' ],
            properties => ['mailboxIds'],
        }, "R2" ],
    ]);
    my $msg1Id = $res->[0][1]{created}{msg1}{id};
    $self->assert_not_null($msg1Id);
    my $msg2Id = $res->[0][1]{created}{msg2}{id};
    $self->assert_not_null($msg2Id);
    my $inboxId = (keys %{$res->[1][1]{list}[0]{mailboxIds}})[0];
    $self->assert_not_null($inboxId);

    # Move emails using mailbox creation id
    $res = $jmap->CallMethods([
        ['Mailbox/set', {
            create => {
                "mboxX" => {
                    name => "X",
                    parentId => undef,
                },
            }
        }, "R1"],
        ['Email/set', {
            update => {
                $msg1Id => {
                    mailboxIds => {
                        '#mboxX' => JSON::true
                    }
                },
                $msg2Id => {
                    'mailboxIds/#mboxX' => JSON::true,
                    'mailboxIds/' . $inboxId => undef,
                }
            },
        }, 'R2'],
        ['Email/get', {
            ids => [ $msg1Id, $msg2Id ],
            properties => ['mailboxIds'],
        }, "R3" ],
    ]);
    my $mboxId = $res->[0][1]{created}{mboxX}{id};
    $self->assert_not_null($mboxId);

    $self->assert(exists $res->[1][1]{updated}{$msg1Id});
    $self->assert(exists $res->[1][1]{updated}{$msg2Id});

    my @mailboxIds = keys %{$res->[2][1]{list}[0]{mailboxIds}};
    $self->assert_num_equals(1, scalar @mailboxIds);
    $self->assert_str_equals($mboxId, $mailboxIds[0]);

    @mailboxIds = keys %{$res->[2][1]{list}[1]{mailboxIds}};
    $self->assert_num_equals(1, scalar @mailboxIds);
    $self->assert_str_equals($mboxId, $mailboxIds[0]);
}

sub test_email_import_encoded_contenttype
    :min_version_3_1 :needs_component_jmap
{
    # Very old macOS Mail.app versions encode the complete
    # Content-Type header value, when they really should
    # just encode its file name parameter value.
    # See: https://github.com/cyrusimap/cyrus-imapd/issues/2622

    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();

    my $email = <<'EOF';
From: example@example.com
To: example@example.biz
Subject: This is a test
Message-Id: <15288246899.CBDb71cE.3455@cyrus-dev>
Date: Tue, 12 Jun 2018 13:31:29 -0400
MIME-Version: 1.0
Content-Type: multipart/mixed;boundary=123456789

--123456789
Content-Type: text/html

This is a mixed message.

--123456789
Content-Type: =?utf-8?B?aW1hZ2UvcG5nOyBuYW1lPSJr?=
 =?utf-8?B?w6RmZXIucG5nIg==?=

data

--123456789--
EOF
    $email =~ s/\r?\n/\r\n/gs;
    my $blobId = $jmap->Upload($email, "message/rfc822")->{blobId};

    my $inboxId = $self->getinbox()->{id};

    my $res = $jmap->CallMethods([['Email/import', {
        emails => {
            "1" => {
                blobId => $blobId,
                mailboxIds => {$inboxId =>  JSON::true},
            },
        },
    }, "R1"], ["Email/get", { ids => ["#1", "#2"], properties => ['bodyStructure'] }, "R2" ]]);

    my $msg = $res->[1][1]{list}[0];
    $self->assert_equals('image/png', $msg->{bodyStructure}{subParts}[1]{type});
    $self->assert_equals("k\N{LATIN SMALL LETTER A WITH DIAERESIS}fer.png", $msg->{bodyStructure}{subParts}[1]{name});
}

sub test_email_set_multipartdigest
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();

    xlog $self, "Generate emails via IMAP";
    $self->make_message() || die;
    $self->make_message() || die;
    my $res = $jmap->CallMethods([
        ['Email/query', { }, "R1"],
        ['Email/get', {
            '#ids' => { resultOf => 'R1', name => 'Email/query', path => '/ids' },
            properties => ['blobId'],
        }, 'R2' ],
    ]);
    my $emailBlobId1 = $res->[1][1]->{list}[0]->{blobId};
    $self->assert_not_null($emailBlobId1);
    my $emailBlobId2 = $res->[1][1]->{list}[1]->{blobId};
    $self->assert_not_null($emailBlobId2);
    $self->assert_str_not_equals($emailBlobId1, $emailBlobId2);

    xlog $self, "Create email with multipart/digest body";
    my $inboxid = $self->getinbox()->{id};
    my $email = {
        mailboxIds => { $inboxid => JSON::true },
        from => [{ name => "Test", email => q{test@local} }],
        subject => "test",
        bodyStructure => {
            type => "multipart/digest",
            subParts => [{
                blobId => $emailBlobId1,
            }, {
                blobId => $emailBlobId2,
            }],
        },
    };
    $res = $jmap->CallMethods([
        ['Email/set', { create => { '1' => $email } }, 'R1'],
        ['Email/get', {
            ids => [ '#1' ],
            properties => [ 'bodyStructure' ],
            bodyProperties => [ 'partId', 'blobId', 'type', 'header:Content-Type' ],
            fetchAllBodyValues => JSON::true,
        }, 'R2' ],
    ]);

    my $subPart = $res->[1][1]{list}[0]{bodyStructure}{subParts}[0];
    $self->assert_str_equals("message/rfc822", $subPart->{type});
    $self->assert_null($subPart->{'header:Content-Type'});
    $subPart = $res->[1][1]{list}[0]{bodyStructure}{subParts}[1];
    $self->assert_str_equals("message/rfc822", $subPart->{type});
    $self->assert_null($subPart->{'header:Content-Type'});
}

sub test_email_set_encode_plain_text_attachment
    :min_version_3_1 :needs_component_jmap :needs_dependency_chardet
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    my $text = "This line ends with a LF\nThis line does as well\n";

    my $data = $jmap->Upload($text, "text/plain");
    my $blobId = $data->{blobId};

    my $email = {
        mailboxIds => { '$inbox' => JSON::true },
        from => [{ name => "Test", email => q{test@local} }],
        subject => "test",
        bodyStructure => {
            type => "multipart/mixed",
            subParts => [{
                type => 'text/plain',
                partId => '1',
            }, {
                type => 'text/plain',
                blobId => $blobId,
            }, {
                type => 'text/plain',
                disposition => 'attachment',
                blobId => $blobId,
            }]
        },
        bodyValues => {
            1 => {
                value => "A plain text body",
            }
        }
    };
    my $res = $jmap->CallMethods([
        ['Email/set', { create => { '1' => $email } }, 'R1'],
        ['Email/get', {
            ids => [ '#1' ],
            properties => [ 'bodyStructure', 'bodyValues' ],
            bodyProperties => [
                'partId', 'blobId', 'type', 'header:Content-Transfer-Encoding', 'size'
            ],
            fetchAllBodyValues => JSON::true,
        }, 'R2' ],
    ]);
    my $subPart = $res->[1][1]{list}[0]{bodyStructure}{subParts}[1];
    $self->assert_str_equals(' QUOTED-PRINTABLE', $subPart->{'header:Content-Transfer-Encoding'});
    $subPart = $res->[1][1]{list}[0]{bodyStructure}{subParts}[2];
    $self->assert_str_equals(' BASE64', $subPart->{'header:Content-Transfer-Encoding'});
}

sub test_blob_get
    :min_version_3_1 :needs_component_jmap :JMAPExtensions
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();

    $self->make_message("foo") || die;

    my $res = $jmap->CallMethods([
        ['Email/query', {}, "R1"],
        ['Email/get', { '#ids' => { resultOf => 'R1', name => 'Email/query', path => '/ids' } }, 'R2'],
    ]);

    my $blobId = $res->[1][1]{list}[0]{blobId};
    $self->assert_not_null($blobId);

    my $wantMailboxIds = $res->[1][1]{list}[0]{mailboxIds};
    my $wantEmailIds = {
        $res->[1][1]{list}[0]{id} => JSON::true
    };
    my $wantThreadIds = {
        $res->[1][1]{list}[0]{threadId} => JSON::true
    };

    my @using = @{ $jmap->DefaultUsing() };
    push @using, 'https://cyrusimap.org/ns/jmap/blob';
    $jmap->DefaultUsing(\@using);

    $res = $jmap->CallMethods([
        ['Blob/get', { ids => [$blobId]}, "R1"],
    ]);

    my $blob = $res->[0][1]{list}[0];
    $self->assert_deep_equals($wantMailboxIds, $blob->{mailboxIds});
    $self->assert_deep_equals($wantEmailIds, $blob->{emailIds});
    $self->assert_deep_equals($wantThreadIds, $blob->{threadIds});

}

sub test_email_set_mimeversion
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();
    my $inboxid = $self->getinbox()->{id};

    my $email1 = {
        mailboxIds => { $inboxid => JSON::true },
        from => [{ name => "Test", email => q{foo@bar} }],
        subject => "test",
        bodyStructure => {
            partId => '1',
        },
        bodyValues => {
            "1" => {
                value => "A text body",
            },
        },
    };
    my $email2 = {
        mailboxIds => { $inboxid => JSON::true },
        from => [{ name => "Test", email => q{foo@bar} }],
        subject => "test",
	'header:Mime-Version' => '1.1',
        bodyStructure => {
            partId => '1',
        },
        bodyValues => {
            "1" => {
                value => "A text body",
            },
        },
    };
    my $res = $jmap->CallMethods([
        ['Email/set', { create => { '1' => $email1 , 2 => $email2 } }, 'R1'],
	['Email/get', { ids => ['#1', '#2'], properties => ['header:mime-version'] }, 'R2'],
    ]);
    $self->assert_str_equals(' 1.0', $res->[1][1]{list}[0]{'header:mime-version'});
    $self->assert_str_equals(' 1.1', $res->[1][1]{list}[1]{'header:mime-version'});
}

sub test_issue_2664
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();

    my $res = $jmap->CallMethods( [ [ 'Identity/get', {}, "R1" ] ] );
    my $identityId = $res->[0][1]->{list}[0]->{id};
    $self->assert_not_null($identityId);

    $res = $jmap->CallMethods([
        ['Mailbox/set', {
            create => {
                'mbox1' => {
                    name => 'foo',
                }
            }
        }, 'R1'],
        ['Email/set', {
            create => {
                email1 => {
                    mailboxIds => {
                        '#mbox1' => JSON::true
                    },
                    from => [{ email => q{foo@bar} }],
                    to => [{ email => q{bar@foo} }],
                    subject => "test",
                    bodyStructure => {
                        partId => '1',
                    },
                    bodyValues => {
                        "1" => {
                            value => "A text body",
                        },
                    },
                }
            },
        }, 'R2'],
        ['EmailSubmission/set', {
            create => {
                'emailSubmission1' => {
                    identityId => $identityId,
                    emailId  => '#email1'
                }
           }
        }, 'R3'],
    ]);
    $self->assert(exists $res->[0][1]{created}{mbox1});
    $self->assert(exists $res->[1][1]{created}{email1});
    $self->assert(exists $res->[2][1]{created}{emailSubmission1});
}

sub test_email_get_cid
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();

    $self->make_message("msg1",
        mime_type => "multipart/mixed",
        mime_boundary => "boundary",
        body => ""
        . "--boundary\r\n"
        . "Content-Type: text/plain\r\n"
        . "\r\n"
        . "body"
        . "\r\n"
        . "--boundary\r\n"
        . "Content-Type: image/png\r\n"
        . "Content-Id: <1234567890\@local>\r\n"
        . "\r\n"
        . "data"
        . "\r\n"
        . "--boundary\r\n"
        . "Content-Type: image/png\r\n"
        . "Content-Id: <1234567890>\r\n"
        . "\r\n"
        . "data"
        . "\r\n"
        . "--boundary\r\n"
        . "Content-Type: image/png\r\n"
        . "Content-Id: 1234567890\r\n"
        . "\r\n"
        . "data"
        . "\r\n"
        . "--boundary--\r\n"
    ) || die;

    my $res = $jmap->CallMethods([
        ['Email/query', { }, 'R1'],
        ['Email/get', {
            '#ids' => {
                resultOf => 'R1',
                name => 'Email/query',
                path => '/ids'
            },
            properties => [ 'bodyStructure' ],
            bodyProperties => ['partId', 'cid'],
        }, 'R2'],
    ]);
    my $bodyStructure = $res->[1][1]{list}[0]{bodyStructure};

    $self->assert_null($bodyStructure->{subParts}[0]{cid});
    $self->assert_str_equals('1234567890@local', $bodyStructure->{subParts}[1]{cid});
    $self->assert_str_equals('1234567890', $bodyStructure->{subParts}[2]{cid});
    $self->assert_str_equals('1234567890', $bodyStructure->{subParts}[3]{cid});

}

sub test_searchsnippet_get_attachment
    :min_version_3_3 :needs_component_jmap :needs_search_xapian
    :SearchAttachmentExtractor :JMAPExtensions
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $instance = $self->{instance};

    my $uri = URI->new($instance->{config}->get('search_attachment_extractor_url'));

    # Start a dummy extractor server.
    my %seenPath;
    my $handler = sub {
        my ($conn, $req) = @_;
        if ($req->method eq 'HEAD') {
            my $res = HTTP::Response->new(204);
            $res->content("");
            $conn->send_response($res);
        } elsif ($seenPath{$req->uri->path}) {
            my $res = HTTP::Response->new(200);
            $res->header("Keep-Alive" => "timeout=1");  # Force client timeout
            $res->content("dog cat bat");
            $conn->send_response($res);
        } else {
            $conn->send_error(404);
            $seenPath{$req->uri->path} = 1;
        }
    };
    $instance->start_httpd($handler, $uri->port());

    # Append an email with PDF attachment text "dog cat bat".
    my $file = "data/dogcatbat.pdf.b64";
    open my $input, '<', $file or die "can't open $file: $!";
    my $body = ""
    ."\r\n--boundary_1\r\n"
    ."Content-Type: text/plain\r\n"
    ."\r\n"
    ."text body"
    ."\r\n--boundary_1\r\n"
    ."Content-Type: application/pdf\r\n"
    ."Content-Transfer-Encoding: BASE64\r\n"
    . "\r\n";
    while (<$input>) {
        chomp;
        $body .= $_ . "\r\n";
    }
    $body .= "\r\n--boundary_1--\r\n";
    close $input or die "can't close $file: $!";

    $self->make_message("msg1",
        mime_type => "multipart/related",
        mime_boundary => "boundary_1",
        body => $body
    ) || die;

    # Run squatter
    $self->{instance}->run_command({cyrus => 1}, 'squatter', '-v');

    my $using = [
        'urn:ietf:params:jmap:core',
        'urn:ietf:params:jmap:mail',
        'https://cyrusimap.org/ns/jmap/mail',
    ];

    # Test 0: query attachmentbody
    my $filter = { attachmentBody => "cat" };
    my $res = $jmap->CallMethods([
        ['Email/query', {
            filter => $filter,
            findMatchingParts => JSON::true,
        }, "R1"],
    ], $using);
    my $emailIds = $res->[0][1]{ids};
    $self->assert_num_equals(1, scalar @{$emailIds});
    my $partIds = $res->[0][1]{partIds};
    $self->assert_not_null($partIds);

    # Test 1: pass partIds
    $res = $jmap->CallMethods([['SearchSnippet/get', {
            emailIds => $emailIds,
            partIds => $partIds,
            filter => $filter
    }, "R1"]], $using);
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{list}});
    my $snippet = $res->[0][1]->{list}[0];
    $self->assert_str_equals("dog <mark>cat</mark> bat", $snippet->{preview});

    # Test 2: pass null partids
    $res = $jmap->CallMethods([['SearchSnippet/get', {
            emailIds => $emailIds,
            partIds => {
                $emailIds->[0] => undef
            },
            filter => $filter
    }, "R1"]], $using);
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{list}});
    $snippet = $res->[0][1]->{list}[0];
    $self->assert_null($snippet->{preview});

    # Sleep 1 sec to force Cyrus to timeout the client connection
    sleep(1);

    # Test 3: pass no partids
    $res = $jmap->CallMethods([['SearchSnippet/get', {
            emailIds => $emailIds,
            filter => $filter
    }, "R1"]], $using);
    $self->assert_num_equals(1, scalar @{$res->[0][1]->{list}});
    $snippet = $res->[0][1]->{list}[0];
    $self->assert_null($snippet->{preview});

    # Test 4: test null partids for header-only match
    $filter = {
        text => "msg1"
    };
    $res = $jmap->CallMethods([
        ['Email/query', {
            filter => $filter,
            findMatchingParts => JSON::true,
        }, "R1"],
    ], $using);
    $emailIds = $res->[0][1]{ids};
    $self->assert_num_equals(1, scalar @{$emailIds});
    $partIds = $res->[0][1]{partIds};
    my $findMatchingParts = {
        $emailIds->[0] => undef
    };
    $self->assert_deep_equals($findMatchingParts, $partIds);

    # Test 5: query text
    $filter = { text => "cat" };
    $res = $jmap->CallMethods([
        ['Email/query', {
            filter => $filter,
            findMatchingParts => JSON::true,
        }, "R1"],
    ], $using);
    $emailIds = $res->[0][1]{ids};
    $self->assert_num_equals(1, scalar @{$emailIds});
    $partIds = $res->[0][1]{partIds};
    $self->assert_not_null($partIds);
}

sub test_email_set_date
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();

    my $res = $jmap->CallMethods([
        ['Email/set', {
            create => {
                email1 => {
                    mailboxIds => {
                        '$inbox' => JSON::true
                    },
                    from => [{ email => q{foo@bar} }],
                    to => [{ email => q{bar@foo} }],
                    sentAt => '2019-05-02T03:15:00+07:00',
                    subject => "test",
                    bodyStructure => {
                        partId => '1',
                    },
                    bodyValues => {
                        "1" => {
                            value => "A text body",
                        },
                    },
                }
            },
        }, 'R1'],
        ['Email/get', {
            ids => ['#email1'],
            properties => ['sentAt', 'header:Date'],
        }, 'R2'],
    ]);
    my $email = $res->[1][1]{list}[0];
    $self->assert_str_equals('2019-05-02T03:15:00+07:00', $email->{sentAt});
    $self->assert_str_equals(' Thu, 02 May 2019 03:15:00 +0700', $email->{'header:Date'});
}

sub test_email_query_language_stats
    :min_version_3_1 :needs_component_jmap :needs_dependency_cld2
    :SearchLanguage :JMAPExtensions
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $body = ""
    . "--boundary\r\n"
    . "Content-Type: text/plain;charset=utf-8\r\n"
    . "Content-Transfer-Encoding: quoted-printable\r\n"
    . "\r\n"
    . "Hoch oben in den L=C3=BCften =C3=BCber den reichgesegneten Landschaften des\r\n"
    . "s=C3=BCdlichen Frankreichs schwebte eine gewaltige dunkle Kugel.\r\n"
    . "\r\n"
    . "Ein Luftballon war es, der, in der Nacht aufgefahren, eine lange\r\n"
    . "Dauerfahrt antreten wollte.\r\n"
    . "\r\n"
    . "--boundary\r\n"
    . "Content-Type: text/plain;charset=utf-8\r\n"
    . "Content-Transfer-Encoding: quoted-printable\r\n"
    . "\r\n"
    . "The Bellman, who was almost morbidly sensitive about appearances, used\r\n"
    . "to have the bowsprit unshipped once or twice a week to be revarnished,\r\n"
    . "and it more than once happened, when the time came for replacing it,\r\n"
    . "that no one on board could remember which end of the ship it belonged to.\r\n"
    . "\r\n"
    . "--boundary\r\n"
    . "Content-Type: text/plain;charset=utf-8\r\n"
    . "Content-Transfer-Encoding: quoted-printable\r\n"
    . "\r\n"
    . "Verri=C3=A8res est abrit=C3=A9e du c=C3=B4t=C3=A9 du nord par une haute mon=\r\n"
    . "tagne, c'est une\r\n"
    . "des branches du Jura. Les cimes bris=C3=A9es du Verra se couvrent de neige\r\n"
    . "d=C3=A8s les premiers froids d'octobre. Un torrent, qui se pr=C3=A9cipite d=\r\n"
    . "e la\r\n"
    . "montagne, traverse Verri=C3=A8res avant de se jeter dans le Doubs et donne =\r\n"
    . "le\r\n"
    . "mouvement =C3=A0 un grand nombre de scies =C3=A0 bois; c'est une industrie =\r\n"
    . "--boundary--\r\n";

    $self->make_message("A multi-language email",
        mime_type => "multipart/mixed",
        mime_boundary => "boundary",
        body => $body
    );

    $self->{instance}->run_command({cyrus => 1}, 'squatter');

    my $using = [
        'urn:ietf:params:jmap:core',
        'urn:ietf:params:jmap:mail',
        'urn:ietf:params:jmap:submission',
        'https://cyrusimap.org/ns/jmap/mail',
        'https://cyrusimap.org/ns/jmap/quota',
        'https://cyrusimap.org/ns/jmap/debug',
    ];

    my $res = $jmap->CallMethods([
        ['Email/query', { }, 'R1' ]
    ], $using);
    $self->assert_deep_equals({
        iso => {
            de => 1,
            fr => 1,
            en => 1,
        },
        unknown => 0,
    }, $res->[0][1]{languageStats});
}
sub test_email_set_received_at
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();

    my $res = $jmap->CallMethods([
        ['Email/set', {
            create => {
                email1 => {
                    mailboxIds => {
                        '$inbox' => JSON::true
                    },
                    from => [{ email => q{foo@bar} }],
                    to => [{ email => q{bar@foo} }],
                    receivedAt => '2019-05-02T03:15:00Z',
                    subject => "test",
                    bodyStructure => {
                        partId => '1',
                    },
                    bodyValues => {
                        "1" => {
                            value => "A text body",
                        },
                    },
                }
            },
        }, 'R1'],
        ['Email/get', {
            ids => ['#email1'],
            properties => ['receivedAt'],
        }, 'R2'],
    ]);
    my $email = $res->[1][1]{list}[0];
    $self->assert_str_equals('2019-05-02T03:15:00Z', $email->{receivedAt});
}

sub test_email_set_email_duplicates_mailbox_counts
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $imap = $self->{store}->get_client();

    my $inboxid = $self->getinbox()->{id};

    # This is the opposite of a tooManyMailboxes error. It makes
    # sure that duplicate emails within a mailbox do not count
    # as multiple mailbox instances.

    my $accountCapabilities = $self->get_account_capabilities();
    my $maxMailboxesPerEmail = $accountCapabilities->{'urn:ietf:params:jmap:mail'}{maxMailboxesPerEmail};

    $self->assert($maxMailboxesPerEmail > 0);

    my $todo = $maxMailboxesPerEmail - 2;

    open(my $F, 'data/mime/simple.eml') || die $!;
    for (1..$todo) {
      $imap->create("INBOX.M$_") || die;

      # two copies in each folder
      $imap->append("INBOX.M$_", $F) || die $@;
    }
    close($F);

    my $res = $jmap->CallMethods([
        ['Email/query', { }, "R1"],
        ['Email/get', {
            '#ids' => {
                resultOf => 'R1',
                name => 'Email/query',
                path => '/ids'
            },
            properties => ['mailboxIds']
        }, 'R2'],
    ]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]{ids}});
    $self->assert_num_equals($todo, scalar keys %{$res->[1][1]{list}[0]{mailboxIds}});

    my $emailId = $res->[0][1]{ids}[0];
    $res = $jmap->CallMethods([
        ['Email/set', {
            update => {
                $emailId => {
                    'keywords/foo' => JSON::true,
                    "mailboxIds/$inboxid" => JSON::true,
                },
            }
        }, 'R1'],
    ]);
    $self->assert(exists $res->[0][1]{updated}{$emailId});
}

sub test_searchsnippet_get_regression
    :min_version_3_1 :needs_component_jmap :JMAPExtensions
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();

    my $body = "--047d7b33dd729737fe04d3bde348\r\n";
    $body .= "Content-Type: text/plain; charset=UTF-8\r\n";
    $body .= "\r\n";
    $body .= "This is the lady plain text part.";
    $body .= "\r\n";
    $body .= "--047d7b33dd729737fe04d3bde348\r\n";
    $body .= "Content-Type: text/html;charset=\"UTF-8\"\r\n";
    $body .= "\r\n";
    $body .= "<html><body><p>This is the lady html part.</p></body></html>";
    $body .= "\r\n";
    $body .= "--047d7b33dd729737fe04d3bde348--\r\n";
    $self->make_message("lady subject",
        mime_type => "multipart/alternative",
        mime_boundary => "047d7b33dd729737fe04d3bde348",
        body => $body
    ) || die;

    $self->{instance}->run_command({cyrus => 1}, 'squatter');

    my $using = [
        'https://cyrusimap.org/ns/jmap/performance',
        'https://cyrusimap.org/ns/jmap/debug',
        'urn:ietf:params:jmap:core',
        'urn:ietf:params:jmap:mail',
    ];

    my $res = $jmap->CallMethods([
        ['Email/query', { filter => {text => "lady"}}, "R1"],
    ], $using);
    my $emailIds = $res->[0][1]{ids};
    my $partIds = $res->[0][1]{partIds};

    $res = $jmap->CallMethods([
        ['SearchSnippet/get', {
            emailIds => $emailIds,
            filter => { text => "lady" },
        }, 'R2'],
    ], $using);
    $self->assert_num_equals(1, scalar @{$res->[0][1]{list}});
}

sub test_search_sharedpart
    :min_version_3_3 :needs_component_jmap :JMAPExtensions
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();

    my $body = "--047d7b33dd729737fe04d3bde348\r\n";
    $body .= "Content-Type: text/plain; charset=UTF-8\r\n";
    $body .= "\r\n";
    $body .= "This is the lady plain text part.";
    $body .= "\r\n";
    $body .= "--047d7b33dd729737fe04d3bde348\r\n";
    $body .= "Content-Type: text/html;charset=\"UTF-8\"\r\n";
    $body .= "\r\n";
    $body .= "<html><body><p>This is the lady html part.</p></body></html>";
    $body .= "\r\n";
    $body .= "--047d7b33dd729737fe04d3bde348--\r\n";

    $self->make_message("lady subject",
        mime_type => "multipart/alternative",
        mime_boundary => "047d7b33dd729737fe04d3bde348",
        body => $body
    ) || die;

    $body = "--h8h89737fe04d3bde348\r\n";
    $body .= "Content-Type: text/plain; charset=UTF-8\r\n";
    $body .= "\r\n";
    $body .= "This is the foobar plain text part.";
    $body .= "\r\n";
    $body .= "--h8h89737fe04d3bde348\r\n";
    $body .= "Content-Type: text/html;charset=\"UTF-8\"\r\n";
    $body .= "\r\n";
    $body .= "<html><body><p>This is the lady html part.</p></body></html>";
    $body .= "\r\n";
    $body .= "--h8h89737fe04d3bde348--\r\n";

    $self->make_message("foobar subject",
        mime_type => "multipart/alternative",
        mime_boundary => "h8h89737fe04d3bde348",
        body => $body
    ) || die;


    $self->{instance}->run_command({cyrus => 1}, 'squatter');

    my $using = [
        'https://cyrusimap.org/ns/jmap/performance',
        'https://cyrusimap.org/ns/jmap/mail',
        'https://cyrusimap.org/ns/jmap/debug',
        'urn:ietf:params:jmap:core',
        'urn:ietf:params:jmap:mail',
    ];

    my $res = $jmap->CallMethods([
        ['Email/query', {
            filter => {text => "foobar"},
            findMatchingParts => JSON::true,
        },"R1"],
    ], $using);
    my $emailIds = $res->[0][1]{ids};
    my $partIds = $res->[0][1]{partIds};

    my $fooId = $emailIds->[0];

    $self->assert_num_equals(1, scalar @$emailIds);
    $self->assert_num_equals(1, scalar keys %$partIds);
    $self->assert_num_equals(1, scalar @{$partIds->{$fooId}});
    $self->assert_str_equals("1", $partIds->{$fooId}[0]);

    $res = $jmap->CallMethods([
        ['Email/query', {
            filter => {text => "lady"},
            findMatchingParts => JSON::true,
        }, "R1"],
    ], $using);
    $emailIds = $res->[0][1]{ids};
    $partIds = $res->[0][1]{partIds};

    my ($ladyId) = grep { $_ ne $fooId } @$emailIds;

    $self->assert_num_equals(2, scalar @$emailIds);
    $self->assert_num_equals(2, scalar keys %$partIds);
    $self->assert_num_equals(1, scalar @{$partIds->{$fooId}});
    $self->assert_num_equals(2, scalar @{$partIds->{$ladyId}});
    $self->assert_not_null(grep { $_ eq "2" } @{$partIds->{$fooId}});
    $self->assert_not_null(grep { $_ eq "1" } @{$partIds->{$ladyId}});
    $self->assert_not_null(grep { $_ eq "2" } @{$partIds->{$ladyId}});
}

sub test_email_query_not_match
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $res = $jmap->CallMethods([
        ['Mailbox/set', {
            create => {
                "mboxA" => {
                    name => "A",
                },
                "mboxB" => {
                    name => "B",
                },
                "mboxC" => {
                    name => "C",
                },
            }
        }, "R1"]
    ]);
    my $mboxIdA = $res->[0][1]{created}{mboxA}{id};
    my $mboxIdB = $res->[0][1]{created}{mboxB}{id};
    my $mboxIdC = $res->[0][1]{created}{mboxC}{id};

    $res = $jmap->CallMethods([
        ['Email/set', {
            create => {
                email1 => {
                    mailboxIds => {
                        $mboxIdA => JSON::true
                    },
                    from => [{ email => q{foo1@bar} }],
                    to => [{ email => q{bar1@foo} }],
                    subject => "email1",
                    keywords => {
                        keyword1 => JSON::true
                    },
                    bodyStructure => {
                        partId => '1',
                    },
                    bodyValues => {
                        "1" => {
                            value => "email1 body",
                        },
                    },
                },
                email2 => {
                    mailboxIds => {
                        $mboxIdB => JSON::true
                    },
                    from => [{ email => q{foo2@bar} }],
                    to => [{ email => q{bar2@foo} }],
                    subject => "email2",
                    bodyStructure => {
                        partId => '2',
                    },
                    bodyValues => {
                        "2" => {
                            value => "email2 body",
                        },
                    },
                },
                email3 => {
                    mailboxIds => {
                        $mboxIdC => JSON::true
                    },
                    from => [{ email => q{foo3@bar} }],
                    to => [{ email => q{bar3@foo} }],
                    subject => "email3",
                    bodyStructure => {
                        partId => '3',
                    },
                    bodyValues => {
                        "3" => {
                            value => "email3 body",
                        },
                    },
                }
            },
        }, 'R1'],
    ]);
    my $emailId1 = $res->[0][1]{created}{email1}{id};
    $self->assert_not_null($emailId1);
    my $emailId2 = $res->[0][1]{created}{email2}{id};
    $self->assert_not_null($emailId2);
    my $emailId3 = $res->[0][1]{created}{email3}{id};
    $self->assert_not_null($emailId3);

    $self->{instance}->run_command({cyrus => 1}, 'squatter');

    $res = $jmap->CallMethods([
        ['Email/query', {
            filter => {
                operator => 'NOT',
                conditions => [{
                    text => "email2",
                }],
            },
            sort => [{ property => "subject" }],
        }, 'R1'],
    ]);
    $self->assert_num_equals(2, scalar @{$res->[0][1]{ids}});
    $self->assert_str_equals($emailId1, $res->[0][1]{ids}[0]);
    $self->assert_str_equals($emailId3, $res->[0][1]{ids}[1]);

    $res = $jmap->CallMethods([
        ['Email/query', {
            filter => {
                operator => 'AND',
                conditions => [{
                    operator => 'NOT',
                    conditions => [{
                        text => "email1"
                    }],
                }, {
                    operator => 'NOT',
                    conditions => [{
                        text => "email3"
                    }],
                }],
            },
            sort => [{ property => "subject" }],
        }, 'R1'],
    ]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]{ids}});
    $self->assert_str_equals($emailId2, $res->[0][1]{ids}[0]);

    $res = $jmap->CallMethods([
        ['Email/query', {
            filter => {
                operator => 'AND',
                conditions => [{
                    operator => 'NOT',
                    conditions => [{
                        text => "email3"
                    }],
                }, {
                    hasKeyword => 'keyword1',
                }],
            },
            sort => [{ property => "subject" }],
        }, 'R1'],
    ]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]{ids}});
    $self->assert_str_equals($emailId1, $res->[0][1]{ids}[0]);
}

sub test_email_query_fromcontactgroupid
    :min_version_3_1 :needs_component_jmap :JMAPExtensions
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $admintalk = $self->{adminstore}->get_client();
    $admintalk->create("user.cassandane.#addressbooks.Addrbook1", ['TYPE', 'ADDRESSBOOK']) or die;
    $admintalk->create("user.cassandane.#addressbooks.Addrbook2", ['TYPE', 'ADDRESSBOOK']) or die;

    my $using = [
        'urn:ietf:params:jmap:core',
        'urn:ietf:params:jmap:mail',
        'https://cyrusimap.org/ns/jmap/mail',
        'https://cyrusimap.org/ns/jmap/contacts',
    ];

    my $res = $jmap->CallMethods([
        ['Contact/set', {
            create => {
                contact1 => {
                    emails => [{
                        type => 'personal',
                        value => 'contact1@local',
                    }],
                },
                contact2 => {
                    emails => [{
                        type => 'personal',
                        value => 'contact2@local',
                    }]
                },
            }
        }, 'R1'],
        ['ContactGroup/set', {
            create => {
                contactGroup1 => {
                    name => 'contactGroup1',
                    contactIds => ['#contact1', '#contact2'],
                    addressbookId => 'Addrbook1',
                },
                contactGroup2 => {
                    name => 'contactGroup2',
                    contactIds => ['#contact1'],
                    addressbookId => 'Addrbook2',
                }
            }
        }, 'R2'],
    ], $using);
    my $contactId1 = $res->[0][1]{created}{contact1}{id};
    $self->assert_not_null($contactId1);
    my $contactId2 = $res->[0][1]{created}{contact2}{id};
    $self->assert_not_null($contactId2);
    my $contactGroupId1 = $res->[1][1]{created}{contactGroup1}{id};
    $self->assert_not_null($contactGroupId1);
    my $contactGroupId2 = $res->[1][1]{created}{contactGroup2}{id};
    $self->assert_not_null($contactGroupId2);

    $self->make_message("msg1", from => Cassandane::Address->new(
        localpart => 'contact1', domain => 'local'
    )) or die;
    $self->make_message("msg2", from => Cassandane::Address->new(
        localpart => 'contact2', domain => 'local'
    )) or die;
    $self->make_message("msg3", from => Cassandane::Address->new(
        localpart => 'neither', domain => 'local'
    )) or die;
    $self->{instance}->run_command({cyrus => 1}, 'squatter');

    $res = $jmap->CallMethods([
        ['Email/query', {
            sort => [{ property => "subject" }],
        }, 'R1']
    ], $using);
    $self->assert_num_equals(3, scalar @{$res->[0][1]{ids}});
    my $emailId1 = $res->[0][1]{ids}[0];
    my $emailId2 = $res->[0][1]{ids}[1];
    my $emailId3 = $res->[0][1]{ids}[2];

    # Filter by contact group.
    $res = $jmap->CallMethods([
        ['Email/query', {
            filter => {
                fromContactGroupId => $contactGroupId1
            },
            sort => [
                { property => "subject" }
            ],
        }, 'R1']
    ], $using);
    $self->assert_num_equals(2, scalar @{$res->[0][1]{ids}});
    $self->assert_str_equals($emailId1, $res->[0][1]{ids}[0]);
    $self->assert_str_equals($emailId2, $res->[0][1]{ids}[1]);

    # Filter by fromAnyContact
    $res = $jmap->CallMethods([
        ['Email/query', {
            filter => {
                fromAnyContact => $JSON::true
            },
            sort => [
                { property => "subject" }
            ],
        }, 'R1']
    ], $using);
    $self->assert_num_equals(2, scalar @{$res->[0][1]{ids}});
    $self->assert_str_equals($emailId1, $res->[0][1]{ids}[0]);
    $self->assert_str_equals($emailId2, $res->[0][1]{ids}[1]);

    # Filter by contact group and addressbook.
    $res = $jmap->CallMethods([
        ['Email/query', {
            filter => {
                fromContactGroupId => $contactGroupId2
            },
            sort => [
                { property => "subject" }
            ],
            addressbookId => 'Addrbook2'
        }, 'R1']
    ], $using);
    $self->assert_num_equals(1, scalar @{$res->[0][1]{ids}});
    $self->assert_str_equals($emailId1, $res->[0][1]{ids}[0]);


    # Negate filter by contact group.
    $res = $jmap->CallMethods([
        ['Email/query', {
            filter => {
                operator => 'NOT',
                conditions => [{
                    fromContactGroupId => $contactGroupId1
                }]
            },
            sort => [
                { property => "subject" }
            ],
        }, 'R1']
    ], $using);
    $self->assert_num_equals(1, scalar @{$res->[0][1]{ids}});
    $self->assert_str_equals($emailId3, $res->[0][1]{ids}[0]);

    # Reject unknown contact groups.
    $res = $jmap->CallMethods([
        ['Email/query', {
            filter => {
                fromContactGroupId => 'doesnotexist',
            },
            sort => [
                { property => "subject" }
            ],
        }, 'R1']
    ], $using);
    $self->assert_str_equals('invalidArguments', $res->[0][1]{type});

    # Reject contact groups in wrong addressbook.
    $res = $jmap->CallMethods([
        ['Email/query', {
            filter => {
                fromContactGroupId => $contactGroupId1
            },
            sort => [
                { property => "subject" }
            ],
            addressbookId => 'Addrbook2',
        }, 'R1']
    ], $using);
    $self->assert_str_equals('invalidArguments', $res->[0][1]{type});

    # Reject unknown addressbooks.
    $res = $jmap->CallMethods([
        ['Email/query', {
            filter => {
                fromContactGroupId => $contactGroupId1,
            },
            sort => [
                { property => "subject" }
            ],
            addressbookId => 'doesnotexist',
        }, 'R1']
    ], $using);
    $self->assert_str_equals('invalidArguments', $res->[0][1]{type});

    # Support also to, cc, bcc
    $res = $jmap->CallMethods([
        ['Contact/set', {
            create => {
                contact3 => {
                    emails => [{
                        type => 'personal',
                        value => 'contact3@local',
                    }]
                },
            }
        }, 'R1'],
        ['ContactGroup/set', {
            update => {
                $contactGroupId1 => {
                    contactIds => ['#contact3'],
                }
            }
        }, 'R1'],
    ], $using);
    $self->assert_not_null($res->[0][1]{created}{contact3});
    $self->make_message("msg4", to => Cassandane::Address->new(
        localpart => 'contact3', domain => 'local'
    )) or die;
    $self->make_message("msg5", cc => Cassandane::Address->new(
        localpart => 'contact3', domain => 'local'
    )) or die;
    $self->make_message("msg6", bcc => Cassandane::Address->new(
        localpart => 'contact3', domain => 'local'
    )) or die;
    $self->{instance}->run_command({cyrus => 1}, 'squatter');
    $res = $jmap->CallMethods([
        ['Email/query', {
            sort => [{ property => "subject" }],
        }, 'R1']
    ], $using);
    $self->assert_num_equals(6, scalar @{$res->[0][1]{ids}});
    my $emailId4 = $res->[0][1]{ids}[3];
    my $emailId5 = $res->[0][1]{ids}[4];
    my $emailId6 = $res->[0][1]{ids}[5];

    $res = $jmap->CallMethods([
        ['Email/query', {
            filter => {
                toContactGroupId => $contactGroupId1
            },
        }, 'R1'],
        ['Email/query', {
            filter => {
                ccContactGroupId => $contactGroupId1
            },
        }, 'R2'],
        ['Email/query', {
            filter => {
                bccContactGroupId => $contactGroupId1
            },
        }, 'R3']
    ], $using);
    $self->assert_num_equals(1, scalar @{$res->[0][1]{ids}});
    $self->assert_str_equals($emailId4, $res->[0][1]{ids}[0]);
    $self->assert_num_equals(1, scalar @{$res->[1][1]{ids}});
    $self->assert_str_equals($emailId5, $res->[1][1]{ids}[0]);
    $self->assert_num_equals(1, scalar @{$res->[2][1]{ids}});
    $self->assert_str_equals($emailId6, $res->[2][1]{ids}[0]);
}

sub test_email_querychanges_fromcontactgroupid
    :min_version_3_1 :needs_component_jmap :JMAPExtensions
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $using = [
        'urn:ietf:params:jmap:core',
        'urn:ietf:params:jmap:mail',
        'https://cyrusimap.org/ns/jmap/mail',
        'https://cyrusimap.org/ns/jmap/contacts',
    ];

    my $res = $jmap->CallMethods([
        ['Contact/set', {
            create => {
                contact1 => {
                    emails => [{
                        type => 'personal',
                        value => 'contact1@local',
                    }]
                },
            }
        }, 'R1'],
        ['ContactGroup/set', {
            create => {
                contactGroup1 => {
                    name => 'contactGroup1',
                    contactIds => ['#contact1'],
                }
            }
        }, 'R2'],
    ], $using);
    my $contactId1 = $res->[0][1]{created}{contact1}{id};
    $self->assert_not_null($contactId1);
    my $contactGroupId1 = $res->[1][1]{created}{contactGroup1}{id};
    $self->assert_not_null($contactGroupId1);

    # Make emails.
    $self->make_message("msg1", from => Cassandane::Address->new(
        localpart => 'contact1', domain => 'local'
    )) or die;
    $self->{instance}->run_command({cyrus => 1}, 'squatter');
    $res = $jmap->CallMethods([
        ['Email/query', {
            sort => [{ property => "subject" }],
        }, 'R1']
    ], $using);
    $self->assert_num_equals(1, scalar @{$res->[0][1]{ids}});
    my $emailId1 = $res->[0][1]{ids}[0];

    # Query changes.
    $res = $jmap->CallMethods([
        ['Email/query', {
            filter => {
                fromContactGroupId => $contactGroupId1
            },
            sort => [
                { property => "subject" }
            ],
        }, 'R1']
    ], $using);
    $self->assert_equals(JSON::true, $res->[0][1]{canCalculateChanges});
    my $queryState = $res->[0][1]{queryState};
    $self->assert_not_null($queryState);

    # Add new matching email.
    $self->make_message("msg2", from => Cassandane::Address->new(
        localpart => 'contact1', domain => 'local'
    )) or die;
    $self->{instance}->run_command({cyrus => 1}, 'squatter');
    $res = $jmap->CallMethods([
        ['Email/queryChanges', {
            filter => {
                fromContactGroupId => $contactGroupId1
            },
            sort => [
                { property => "subject" }
            ],
            sinceQueryState => $queryState,
        }, 'R1']
    ], $using);
    $self->assert_num_equals(1, scalar @{$res->[0][1]{added}});

    # Invalidate query state for ContactGroup state changes.
    $res = $jmap->CallMethods([
        ['Contact/set', {
            create => {
                contact2 => {
                    emails => [{
                        type => 'personal',
                        value => 'contact2@local',
                    }]
                },
            }
        }, 'R1'],
        ['ContactGroup/set', {
            update => {
                $contactGroupId1 => {
                    contactIds => [$contactId1, '#contact2'],
                }
            }
        }, 'R2'],
        ['Email/queryChanges', {
            filter => {
                fromContactGroupId => $contactGroupId1
            },
            sort => [
                { property => "subject" }
            ],
            sinceQueryState => $queryState,
        }, 'R3']
    ], $using);
    my $contactId2 = $res->[0][1]{created}{contact2}{id};
    $self->assert_not_null($contactId2);
    $self->assert(exists $res->[1][1]{updated}{$contactGroupId1});
    $self->assert_str_equals('cannotCalculateChanges', $res->[2][1]{type});
}

sub test_email_get_header_last_value
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();

    $self->make_message("msg", extra_headers => [
        ['x-tra', 'Fri, 21 Nov 1997 09:55:06 -0600'],
        ['x-tra', 'Thu, 22 Aug 2019 23:12:06 -0600'],
    ]) || die;

    my $res = $jmap->CallMethods([
        ['Email/query', { }, "R1"],
        ['Email/get', {
            '#ids' => {
                resultOf => 'R1',
                name => 'Email/query',
                path => '/ids'
            },
            properties => ['header:x-tra:asDate']
        }, 'R2'],
    ]);
    my ($maj, $min) = Cassandane::Instance->get_version();
    if ($maj > 3 || ($maj == 3 && $min >= 4)) {
        $self->assert_str_equals('2019-08-22T23:12:06-06:00',
                                 $res->[1][1]{list}[0]{'header:x-tra:asDate'});
    } else {
        $self->assert_str_equals('2019-08-23T05:12:06Z',
                                 $res->[1][1]{list}[0]{'header:x-tra:asDate'});
    }
}

sub test_email_matchmime
    :min_version_3_1 :needs_component_jmap :needs_component_calalarmd
    :JMAPExtensions
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    # we need 'https://cyrusimap.org/ns/jmap/mail' capability for
    # Email/matchMime method
    my @using = @{ $jmap->DefaultUsing() };
    push @using, 'https://cyrusimap.org/ns/jmap/mail';
    $jmap->DefaultUsing(\@using);

    my $email = <<'EOF';
From: sender@local
To: recipient@local
Subject: test email
Date: Wed, 7 Dec 2016 00:21:50 -0500
X-tra: baz
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

Some body.
EOF
    $email =~ s/\r?\n/\r\n/gs;

    my $res = $jmap->CallMethods([
        ['Email/matchMime', {
            mime => $email,
            filter => {
                subject => "test",
                header => [ "X-tra", 'baz' ],
            },
        }, "R1"],
    ]);

    $self->assert_equals(JSON::true, $res->[0][1]{matches});

    $res = $jmap->CallMethods([
        ['Email/matchMime', {
            mime => $email,
            filter => {
                operator => 'AND',
                conditions => [{
                    text => "body",
                }, {
                    header => [ "X-tra" ],
                }],
            },
        }, "R1"],
    ]);

    $self->assert_equals(JSON::true, $res->[0][1]{matches});

    $res = $jmap->CallMethods([
        ['Email/matchMime', {
            mime => $email,
            filter => {
                hasAttachment => JSON::true,
            },
        }, "R1"],
    ]);

    $self->assert_equals(JSON::false, $res->[0][1]{matches});
}

sub test_email_zero_length_text
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $email = <<'EOF';
MIME-Version: 1.0
From: "Example.com" <renewals@example.com>
To: "Me" <me@example.com>
Date: 25 Jun 2016 02:29:42 -0400
Subject: Upcoming Auto-Renewal Notification for July, 2016
Content-Type: multipart/alternative;
 boundary=--boundary_34056
Message-ID: <abc123@server.example.net>

----boundary_34056
Content-Type: text/plain
Content-Transfer-Encoding: quoted-printable


----boundary_34056
Content-Type: text/html
Content-Transfer-Encoding: 7bit

<html>
foo
</html>

----boundary_34056--

EOF
    $email =~ s/\r?\n/\r\n/gs;
    my $data = $jmap->Upload($email, "message/rfc822");
    my $blobid = $data->{blobId};
    my $inboxid = $self->getinbox()->{id};

    xlog $self, "import and get email from blob $blobid";
    my $res = $jmap->CallMethods([['Email/import', {
        emails => {
            "1" => {
                blobId => $blobid,
                mailboxIds => {$inboxid =>  JSON::true},
            },
        },
    }, "R1"], ["Email/get", {
        ids => ["#1"],
        properties => ['bodyStructure', 'bodyValues'],
        fetchAllBodyValues => JSON::true,
    }, "R2" ]]);

    $self->assert_str_equals("Email/import", $res->[0][0]);
    $self->assert_str_equals("Email/get", $res->[1][0]);

    my $msg = $res->[1][1]{list}[0];
    my $bodyValue = $msg->{bodyValues}{1};
    $self->assert_str_equals("", $bodyValue->{value});
    $self->assert_equals(JSON::false, $bodyValue->{isEncodingProblem});
}

sub test_email_set_language_header
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $res = $jmap->CallMethods([
        ['Email/set', {
                create => {
                    email1 => {
                        mailboxIds => {
                            '$inbox' => JSON::true,
                        },
                        from => [{ email => q{foo1@bar} }],
                        bodyStructure => {
                            language => ['de-DE', 'en-CA'],
                            partId => '1',
                        },
                        bodyValues => {
                            "1" => {
                                value => "Das ist eine Email. This is an email.",
                            },
                        },
                    },
                },
            }, 'R1'],
        ['Email/get', {
                ids => ['#email1'],
                properties => [
                    'bodyStructure',
                ],
                bodyProperties => [
                    'language',
                    'header:Content-Language',
                ],
            }, 'R2'],
    ]);
    $self->assert_str_equals(' de-DE, en-CA',
        $res->[1][1]{list}[0]{bodyStructure}{'header:Content-Language'});
    $self->assert_deep_equals(['de-DE', 'en-CA'],
        $res->[1][1]{list}[0]{bodyStructure}{language});
}

sub test_email_query_text_nomail
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    xlog "search for some text";
    my $res = $jmap->CallMethods([['Email/query', { filter => { text => 'foo' } }, "R1"]]);

    # check that the query succeeded
    $self->assert_str_equals($res->[0][0], "Email/query");
}

sub test_email_set_move_multiuid_patch
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $imap = $self->{store}->get_client();

    xlog "Set up mailboxes";
    my $res = $jmap->CallMethods([
        ['Mailbox/query', {
        }, 'R1'],
        ['Mailbox/set', {
            create => {
                "a" => { name => "a", parentId => undef },
            },
        }, 'R2'],
    ]);
    my $srcMboxId = $res->[0][1]{ids}[0];
    $self->assert_not_null($srcMboxId);
    my $dstMboxId = $res->[1][1]{created}{a}{id};
    $self->assert_not_null($dstMboxId);


    xlog "Append same message twice to inbox";
    my $rawMessage = <<"EOF";
From: <from\@local>\r
To: to\@local\r
Subject: test\r
Date: Wed, 7 Dec 2019 22:11:11 +1100\r
MIME-Version: 1.0\r
Content-Type: text/plain\r
\r
test\r
EOF
    $imap->append('INBOX', $rawMessage) || die $@;
    $imap->append('INBOX', $rawMessage) || die $@;
    my $msgCount = $imap->message_count("INBOX");
    $self->assert_num_equals(2, $msgCount);
    $res = $jmap->CallMethods([
        ['Email/query', {
        }, 'R1'],
        ['Email/get', {
            '#ids' => {
                resultOf => 'R1',
                name => 'Email/query',
                path => '/ids'
            },
            properties => [ 'mailboxIds' ],
        }, 'R2'],
    ]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]{ids}});
    my $emailId = $res->[0][1]{ids}[0];
    $self->assert_deep_equals(
        { $srcMboxId => JSON::true },
        $res->[1][1]{list}[0]{mailboxIds}
    );

    xlog "Move email to destination mailbox with mailboxIds patch";
    $res = $jmap->CallMethods([
        ['Email/set', {
            update => {
                $emailId => {
                    'mailboxIds/' . $srcMboxId => undef,
                    'mailboxIds/' . $dstMboxId => JSON::true,
                },
            },
        }, 'R1'],
        ['Email/get', {
            ids => [$emailId],
            properties => [ 'mailboxIds' ],
        }, 'R2'],
    ]);
    $self->assert(exists $res->[0][1]{updated}{$emailId});
    $self->assert_deep_equals(
        { $dstMboxId => JSON::true },
        $res->[1][1]{list}[0]{mailboxIds}
    );
}

sub test_email_set_move_multiuid_set
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $imap = $self->{store}->get_client();

    xlog "Set up mailboxes";
    my $res = $jmap->CallMethods([
        ['Mailbox/query', {
        }, 'R1'],
        ['Mailbox/set', {
            create => {
                "a" => { name => "a", parentId => undef },
            },
        }, 'R2'],
    ]);
    my $srcMboxId = $res->[0][1]{ids}[0];
    $self->assert_not_null($srcMboxId);
    my $dstMboxId = $res->[1][1]{created}{a}{id};
    $self->assert_not_null($dstMboxId);


    xlog "Append same message twice to inbox";
    my $rawMessage = <<"EOF";
From: <from\@local>\r
To: to\@local\r
Subject: test\r
Date: Wed, 7 Dec 2019 22:11:11 +1100\r
MIME-Version: 1.0\r
Content-Type: text/plain\r
\r
test\r
EOF
    $imap->append('INBOX', $rawMessage) || die $@;
    $imap->append('INBOX', $rawMessage) || die $@;
    my $msgCount = $imap->message_count("INBOX");
    $self->assert_num_equals(2, $msgCount);
    $res = $jmap->CallMethods([
        ['Email/query', {
        }, 'R1'],
        ['Email/get', {
            '#ids' => {
                resultOf => 'R1',
                name => 'Email/query',
                path => '/ids'
            },
            properties => [ 'mailboxIds' ],
        }, 'R2'],
    ]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]{ids}});
    my $emailId = $res->[0][1]{ids}[0];
    $self->assert_deep_equals(
        { $srcMboxId => JSON::true },
        $res->[1][1]{list}[0]{mailboxIds}
    );

    xlog "Move email to destination mailbox with mailboxIds set";
    $res = $jmap->CallMethods([
        ['Email/set', {
            update => {
                $emailId => {
                    mailboxIds => {
                        $dstMboxId => JSON::true
                    }
                },
            },
        }, 'R1'],
        ['Email/get', {
            ids => [$emailId],
            properties => [ 'mailboxIds' ],
        }, 'R2'],
    ]);
    $self->assert(exists $res->[0][1]{updated}{$emailId});
    $self->assert_deep_equals(
        { $dstMboxId => JSON::true },
        $res->[1][1]{list}[0]{mailboxIds}
    );
}

sub test_email_query_position_legacy
    :min_version_3_1 :max_version_3_4 :needs_component_jmap
    :JMAPSearchDBLegacy :JMAPExtensions
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    xlog "Creating emails";
    foreach my $i (1..9) {
        $self->make_message("test") || die;
    }

    xlog $self, "run squatter";
    $self->{instance}->run_command({cyrus => 1}, 'squatter');

    xlog "Query emails";
    my $res = $jmap->CallMethods([
        ['Email/query', {
            sort => [{ property => 'id' }],
        }, 'R1'],
    ]);
    my @emailIds = @{$res->[0][1]{ids}};
    $self->assert_num_equals(9, scalar @emailIds);

    my $using = [
        'https://cyrusimap.org/ns/jmap/performance',
        'https://cyrusimap.org/ns/jmap/debug',
        'urn:ietf:params:jmap:core',
        'urn:ietf:params:jmap:mail',
    ];

    xlog "Query with positive position (in range)";
    $res = $jmap->CallMethods([
        ['Email/query', {
            filter => { subject => 'test' },
            sort => [{ property => 'id' }],
            position => 1,
            limit => 2,
            disableGuidSearch => JSON::true,
        }, 'R1'],
        ['Email/query', {
            filter => { subject => 'test' },
            sort => [{ property => 'id' }],
            position => 1,
            limit => 2,
            disableGuidSearch => JSON::true,
        }, 'R2'],
        ['Email/query', {
            filter => { subject => 'test' },
            sort => [{ property => 'id' }],
            position => 1,
            limit => 2,
            disableGuidSearch => JSON::false,
        }, 'R3'],
    ], $using);
    my @wantIds = @emailIds[1..2];
    # Check UID search
    $self->assert_equals(JSON::false, $res->[0][1]{performance}{details}{isGuidSearch});
    $self->assert_equals(JSON::false, $res->[0][1]{performance}{details}{isCached});
    $self->assert_num_equals(1, $res->[0][1]{position});
    $self->assert_deep_equals(\@wantIds, $res->[0][1]{ids});
    $self->assert_equals(JSON::false, $res->[1][1]{performance}{details}{isGuidSearch});
    $self->assert_equals(JSON::true, $res->[1][1]{performance}{details}{isCached});
    $self->assert_num_equals(1, $res->[1][1]{position});
    $self->assert_deep_equals(\@wantIds, $res->[1][1]{ids});
    # Check GUID search
    $self->assert_equals(JSON::true, $res->[2][1]{performance}{details}{isGuidSearch});
    $self->assert_equals(JSON::false, $res->[2][1]{performance}{details}{isCached});
    $self->assert_num_equals(1, $res->[2][1]{position});
    $self->assert_deep_equals(\@wantIds, $res->[2][1]{ids});

    xlog "Create dummy message to invalidate query cache";
    $self->make_message("dummy") || die;

    xlog "Query with positive position (out of range)";
    $res = $jmap->CallMethods([
        ['Email/query', {
            filter => { subject => 'test' },
            sort => [{ property => 'id' }],
            position => 100,
            limit => 2,
            disableGuidSearch => JSON::true,
        }, 'R1'],
        ['Email/query', {
            filter => { subject => 'test' },
            sort => [{ property => 'id' }],
            position => 100,
            limit => 2,
            disableGuidSearch => JSON::true,
        }, 'R2'],
        ['Email/query', {
            filter => { subject => 'test' },
            sort => [{ property => 'id' }],
            position => 100,
            limit => 2,
            disableGuidSearch => JSON::false,
        }, 'R3'],
    ], $using);
    @wantIds = ();
    # Check UID search
    $self->assert_equals(JSON::false, $res->[0][1]{performance}{details}{isGuidSearch});
    $self->assert_equals(JSON::false, $res->[0][1]{performance}{details}{isCached});
    $self->assert_num_equals(9, $res->[0][1]{position});
    $self->assert_deep_equals(\@wantIds, $res->[0][1]{ids});
    $self->assert_equals(JSON::false, $res->[1][1]{performance}{details}{isGuidSearch});
    $self->assert_equals(JSON::true, $res->[1][1]{performance}{details}{isCached});
    $self->assert_num_equals(9, $res->[1][1]{position});
    $self->assert_deep_equals(\@wantIds, $res->[1][1]{ids});
    # Check GUID search
    $self->assert_equals(JSON::true, $res->[2][1]{performance}{details}{isGuidSearch});
    $self->assert_equals(JSON::false, $res->[2][1]{performance}{details}{isCached});
    $self->assert_num_equals(9, $res->[2][1]{position});
    $self->assert_deep_equals(\@wantIds, $res->[2][1]{ids});
}

sub test_email_query_position
    :min_version_3_5 :needs_component_jmap :JMAPQueryCacheMaxAge1s
    :JMAPExtensions
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    xlog "Creating emails";
    foreach my $i (1..9) {
        $self->make_message("test") || die;
    }

    xlog $self, "run squatter";
    $self->{instance}->run_command({cyrus => 1}, 'squatter');

    xlog "Query emails";
    my $res = $jmap->CallMethods([
        ['Email/query', {
            sort => [{ property => 'id' }],
        }, 'R1'],
    ]);
    my @emailIds = @{$res->[0][1]{ids}};
    $self->assert_num_equals(9, scalar @emailIds);

    my $using = [
        'https://cyrusimap.org/ns/jmap/performance',
        'https://cyrusimap.org/ns/jmap/debug',
        'urn:ietf:params:jmap:core',
        'urn:ietf:params:jmap:mail',
    ];

    xlog "Query with positive position (in range)";
    $res = $jmap->CallMethods([
        ['Email/query', {
            filter => { subject => 'test' },
            sort => [{ property => 'id' }],
            position => 1,
            limit => 2,
            disableGuidSearch => JSON::true,
        }, 'R1'],
        ['Email/query', {
            filter => { subject => 'test' },
            sort => [{ property => 'id' }],
            position => 1,
            limit => 2,
            disableGuidSearch => JSON::true,
        }, 'R2'],
        ['Email/query', {
            filter => { subject => 'test' },
            sort => [{ property => 'id' }],
            position => 1,
            limit => 2,
            disableGuidSearch => JSON::false,
        }, 'R3'],
    ], $using);
    my @wantIds = @emailIds[1..2];
    # Check UID search
    $self->assert_equals(JSON::false, $res->[0][1]{performance}{details}{isGuidSearch});
    $self->assert_equals(JSON::false, $res->[0][1]{performance}{details}{isCached});
    $self->assert_num_equals(1, $res->[0][1]{position});
    $self->assert_deep_equals(\@wantIds, $res->[0][1]{ids});
    $self->assert_equals(JSON::false, $res->[1][1]{performance}{details}{isGuidSearch});
    $self->assert_equals(JSON::true, $res->[1][1]{performance}{details}{isCached});
    $self->assert_num_equals(1, $res->[1][1]{position});
    $self->assert_deep_equals(\@wantIds, $res->[1][1]{ids});
    # Check GUID search
    $self->assert_equals(JSON::true, $res->[2][1]{performance}{details}{isGuidSearch});
    $self->assert_equals(JSON::false, $res->[2][1]{performance}{details}{isCached});
    $self->assert_num_equals(1, $res->[2][1]{position});
    $self->assert_deep_equals(\@wantIds, $res->[2][1]{ids});

    xlog "Create dummy message to invalidate query cache";
    $self->make_message("dummy") || die;

    xlog "Query with positive position (out of range)";
    $res = $jmap->CallMethods([
        ['Email/query', {
            filter => { subject => 'test' },
            sort => [{ property => 'id' }],
            position => 100,
            limit => 2,
            disableGuidSearch => JSON::true,
        }, 'R1'],
        ['Email/query', {
            filter => { subject => 'test' },
            sort => [{ property => 'id' }],
            position => 100,
            limit => 2,
            disableGuidSearch => JSON::true,
        }, 'R2'],
        ['Email/query', {
            filter => { subject => 'test' },
            sort => [{ property => 'id' }],
            position => 100,
            limit => 2,
            disableGuidSearch => JSON::false,
        }, 'R3'],
    ], $using);
    @wantIds = ();
    # Check UID search
    $self->assert_equals(JSON::false, $res->[0][1]{performance}{details}{isGuidSearch});
    $self->assert_equals(JSON::false, $res->[0][1]{performance}{details}{isCached});
    $self->assert_num_equals(9, $res->[0][1]{position});
    $self->assert_deep_equals(\@wantIds, $res->[0][1]{ids});
    $self->assert_equals(JSON::false, $res->[1][1]{performance}{details}{isGuidSearch});
    $self->assert_equals(JSON::true, $res->[1][1]{performance}{details}{isCached});
    $self->assert_num_equals(9, $res->[1][1]{position});
    $self->assert_deep_equals(\@wantIds, $res->[1][1]{ids});
    # Check GUID search
    $self->assert_equals(JSON::true, $res->[2][1]{performance}{details}{isGuidSearch});
    $self->assert_equals(JSON::false, $res->[2][1]{performance}{details}{isCached});
    $self->assert_num_equals(9, $res->[2][1]{position});
    $self->assert_deep_equals(\@wantIds, $res->[2][1]{ids});
}

sub test_email_query_negative_position_legacy
    :min_version_3_1 :max_version_3_4 :needs_component_jmap
    :JMAPSearchDBLegacy :JMAPExtensions
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    xlog "Creating emails";
    foreach my $i (1..9) {
        $self->make_message("test") || die;
    }

    xlog $self, "run squatter";
    $self->{instance}->run_command({cyrus => 1}, 'squatter');

    xlog "Query emails";
    my $res = $jmap->CallMethods([
        ['Email/query', {
            sort => [{ property => 'id' }],
        }, 'R1'],
    ]);
    my @emailIds = @{$res->[0][1]{ids}};
    $self->assert_num_equals(9, scalar @emailIds);

    my $using = [
        'https://cyrusimap.org/ns/jmap/performance',
        'https://cyrusimap.org/ns/jmap/debug',
        'urn:ietf:params:jmap:core',
        'urn:ietf:params:jmap:mail',
    ];

    xlog "Query with negative position (in range)";
    $res = $jmap->CallMethods([
        ['Email/query', {
            filter => { subject => 'test' },
            sort => [{ property => 'id' }],
            position => -3,
            limit => 2,
            disableGuidSearch => JSON::true,
        }, 'R1'],
        ['Email/query', {
            filter => { subject => 'test' },
            sort => [{ property => 'id' }],
            position => -3,
            limit => 2,
            disableGuidSearch => JSON::true,
        }, 'R2'],
        ['Email/query', {
            filter => { subject => 'test' },
            sort => [{ property => 'id' }],
            position => -3,
            limit => 2,
            disableGuidSearch => JSON::false,
        }, 'R3'],
    ], $using);
    my @wantIds = @emailIds[6..7];
    # Check UID search
    $self->assert_equals(JSON::false, $res->[0][1]{performance}{details}{isGuidSearch});
    $self->assert_equals(JSON::false, $res->[0][1]{performance}{details}{isCached});
    $self->assert_num_equals(6, $res->[0][1]{position});
    $self->assert_deep_equals(\@wantIds, $res->[0][1]{ids});
    $self->assert_equals(JSON::false, $res->[1][1]{performance}{details}{isGuidSearch});

    $self->assert_equals(JSON::true, $res->[1][1]{performance}{details}{isCached});
    $self->assert_num_equals(6, $res->[1][1]{position});
    $self->assert_deep_equals(\@wantIds, $res->[1][1]{ids});
    # Check GUID search
    $self->assert_equals(JSON::true, $res->[2][1]{performance}{details}{isGuidSearch});
    $self->assert_num_equals(6, $res->[2][1]{position});
    $self->assert_deep_equals(\@wantIds, $res->[2][1]{ids});

    xlog "Create dummy message to invalidate query cache";
    $self->make_message("dummy") || die;

    xlog "Query with negative position (out of range)";
    $res = $jmap->CallMethods([
        ['Email/query', {
            filter => { subject => 'test' },
            sort => [{ property => 'id' }],
            position => -100,
            limit => 2,
            disableGuidSearch => JSON::true,
        }, 'R1'],
        ['Email/query', {
            filter => { subject => 'test' },
            sort => [{ property => 'id' }],
            position => -100,
            limit => 2,
            disableGuidSearch => JSON::true,
        }, 'R2'],
        ['Email/query', {
            filter => { subject => 'test' },
            sort => [{ property => 'id' }],
            position => -100,
            limit => 2,
            disableGuidSearch => JSON::false,
        }, 'R3'],
    ], $using);
    @wantIds = @emailIds[0..1];
    # Check UID search
    $self->assert_equals(JSON::false, $res->[0][1]{performance}{details}{isGuidSearch});
    $self->assert_equals(JSON::false, $res->[0][1]{performance}{details}{isCached});
    $self->assert_num_equals(0, $res->[0][1]{position});
    $self->assert_deep_equals(\@wantIds, $res->[0][1]{ids});
    $self->assert_equals(JSON::false, $res->[1][1]{performance}{details}{isGuidSearch});
    $self->assert_equals(JSON::true, $res->[1][1]{performance}{details}{isCached});
    $self->assert_num_equals(0, $res->[1][1]{position});
    $self->assert_deep_equals(\@wantIds, $res->[1][1]{ids});
    # Check GUID search
    $self->assert_equals(JSON::true, $res->[2][1]{performance}{details}{isGuidSearch});
    $self->assert_num_equals(0, $res->[2][1]{position});
    $self->assert_deep_equals(\@wantIds, $res->[2][1]{ids});
}

sub test_email_query_negative_position
    :min_version_3_5 :needs_component_jmap :JMAPQueryCacheMaxAge1s
    :JMAPExtensions
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    xlog "Creating emails";
    foreach my $i (1..9) {
        $self->make_message("test") || die;
    }

    xlog $self, "run squatter";
    $self->{instance}->run_command({cyrus => 1}, 'squatter');

    xlog "Query emails";
    my $res = $jmap->CallMethods([
        ['Email/query', {
            sort => [{ property => 'id' }],
        }, 'R1'],
    ]);
    my @emailIds = @{$res->[0][1]{ids}};
    $self->assert_num_equals(9, scalar @emailIds);

    my $using = [
        'https://cyrusimap.org/ns/jmap/performance',
        'https://cyrusimap.org/ns/jmap/debug',
        'urn:ietf:params:jmap:core',
        'urn:ietf:params:jmap:mail',
    ];

    xlog "Query with negative position (in range)";
    $res = $jmap->CallMethods([
        ['Email/query', {
            filter => { subject => 'test' },
            sort => [{ property => 'id' }],
            position => -3,
            limit => 2,
            disableGuidSearch => JSON::true,
        }, 'R1'],
        ['Email/query', {
            filter => { subject => 'test' },
            sort => [{ property => 'id' }],
            position => -3,
            limit => 2,
            disableGuidSearch => JSON::true,
        }, 'R2'],
        ['Email/query', {
            filter => { subject => 'test' },
            sort => [{ property => 'id' }],
            position => -3,
            limit => 2,
            disableGuidSearch => JSON::false,
        }, 'R3'],
    ], $using);
    my @wantIds = @emailIds[6..7];
    # Check UID search
    $self->assert_equals(JSON::false, $res->[0][1]{performance}{details}{isGuidSearch});
    $self->assert_equals(JSON::false, $res->[0][1]{performance}{details}{isCached});
    $self->assert_num_equals(6, $res->[0][1]{position});
    $self->assert_deep_equals(\@wantIds, $res->[0][1]{ids});
    $self->assert_equals(JSON::false, $res->[1][1]{performance}{details}{isGuidSearch});

    $self->assert_equals(JSON::true, $res->[1][1]{performance}{details}{isCached});
    $self->assert_num_equals(6, $res->[1][1]{position});
    $self->assert_deep_equals(\@wantIds, $res->[1][1]{ids});
    # Check GUID search
    $self->assert_equals(JSON::true, $res->[2][1]{performance}{details}{isGuidSearch});
    $self->assert_num_equals(6, $res->[2][1]{position});
    $self->assert_deep_equals(\@wantIds, $res->[2][1]{ids});

    xlog "Create dummy message to invalidate query cache";
    $self->make_message("dummy") || die;

    xlog "Query with negative position (out of range)";
    $res = $jmap->CallMethods([
        ['Email/query', {
            filter => { subject => 'test' },
            sort => [{ property => 'id' }],
            position => -100,
            limit => 2,
            disableGuidSearch => JSON::true,
        }, 'R1'],
        ['Email/query', {
            filter => { subject => 'test' },
            sort => [{ property => 'id' }],
            position => -100,
            limit => 2,
            disableGuidSearch => JSON::true,
        }, 'R2'],
        ['Email/query', {
            filter => { subject => 'test' },
            sort => [{ property => 'id' }],
            position => -100,
            limit => 2,
            disableGuidSearch => JSON::false,
        }, 'R3'],
    ], $using);
    @wantIds = @emailIds[0..1];
    # Check UID search
    $self->assert_equals(JSON::false, $res->[0][1]{performance}{details}{isGuidSearch});
    $self->assert_equals(JSON::false, $res->[0][1]{performance}{details}{isCached});
    $self->assert_num_equals(0, $res->[0][1]{position});
    $self->assert_deep_equals(\@wantIds, $res->[0][1]{ids});
    $self->assert_equals(JSON::false, $res->[1][1]{performance}{details}{isGuidSearch});
    $self->assert_equals(JSON::true, $res->[1][1]{performance}{details}{isCached});
    $self->assert_num_equals(0, $res->[1][1]{position});
    $self->assert_deep_equals(\@wantIds, $res->[1][1]{ids});
    # Check GUID search
    $self->assert_equals(JSON::true, $res->[2][1]{performance}{details}{isGuidSearch});
    $self->assert_num_equals(0, $res->[2][1]{position});
    $self->assert_deep_equals(\@wantIds, $res->[2][1]{ids});
}

sub test_email_query_guidsearch
    :min_version_3_1 :needs_component_jmap :JMAPExtensions
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    for (my $i = 0; $i < 10; $i++) {
        $self->make_message("msg$i", to => Cassandane::Address->new(
            localpart => "recipient$i",
            domain => 'example.com'
        )) || die;
    }

    xlog $self, "run squatter";
    $self->{instance}->run_command({cyrus => 1}, 'squatter');

    my $using = [
        'urn:ietf:params:jmap:core',
        'urn:ietf:params:jmap:mail',
        'urn:ietf:params:jmap:submission',
        'https://cyrusimap.org/ns/jmap/mail',
        'https://cyrusimap.org/ns/jmap/quota',
        'https://cyrusimap.org/ns/jmap/debug',
        'https://cyrusimap.org/ns/jmap/performance',
    ];

    xlog "Running query with guidsearch";
    my $res = $jmap->CallMethods([
        ['Email/query', {
            filter => {
                to => '@example.com',
            },
        }, 'R1']
    ], $using);
    $self->assert_equals(JSON::true, $res->[0][1]{performance}{details}{isGuidSearch});
    my $guidSearchIds = $res->[0][1]{ids};
    $self->assert_num_equals(10, scalar @{$guidSearchIds});

    xlog "Running query without guidsearch";
    $res = $jmap->CallMethods([
        ['Email/query', {
            filter => {
                to => '@example.com',
            },
            disableGuidSearch => JSON::true,
        }, 'R1']
    ], $using);
    $self->assert_equals(JSON::false, $res->[0][1]{performance}{details}{isGuidSearch});
    my $uidSearchIds = $res->[0][1]{ids};
    $self->assert_num_equals(10, scalar @{$uidSearchIds});

    xlog "Comparing results";
    $self->assert_deep_equals($guidSearchIds, $uidSearchIds);
}

sub test_email_query_guidsearch_scanmode
    :min_version_3_1 :needs_component_jmap :JMAPExtensions :SearchSetForceScanMode
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    for (my $i = 0; $i < 10; $i++) {
        $self->make_message("msg$i", to => Cassandane::Address->new(
            localpart => "recipient$i",
            domain => 'example.com'
        )) || die;
    }

    xlog $self, "run squatter";
    $self->{instance}->run_command({cyrus => 1}, 'squatter');

    my $using = [
        'urn:ietf:params:jmap:core',
        'urn:ietf:params:jmap:mail',
        'urn:ietf:params:jmap:submission',
        'https://cyrusimap.org/ns/jmap/mail',
        'https://cyrusimap.org/ns/jmap/quota',
        'https://cyrusimap.org/ns/jmap/debug',
        'https://cyrusimap.org/ns/jmap/performance',
    ];

    xlog "Running query with guidsearch";
    my $res = $jmap->CallMethods([
        ['Email/query', {
            filter => {
                to => '@example.com',
            },
        }, 'R1']
    ], $using);
    $self->assert_equals(JSON::true, $res->[0][1]{performance}{details}{isGuidSearch});
    my $guidSearchIds = $res->[0][1]{ids};
    $self->assert_num_equals(10, scalar @{$guidSearchIds});

    xlog "Running query without guidsearch";
    $res = $jmap->CallMethods([
        ['Email/query', {
            filter => {
                to => '@example.com',
            },
            disableGuidSearch => JSON::true,
        }, 'R1']
    ], $using);
    $self->assert_equals(JSON::false, $res->[0][1]{performance}{details}{isGuidSearch});
    my $uidSearchIds = $res->[0][1]{ids};
    $self->assert_num_equals(10, scalar @{$uidSearchIds});

    xlog "Comparing results";
    $self->assert_deep_equals($guidSearchIds, $uidSearchIds);
}

sub test_email_query_guidsearch_sort
    :min_version_3_1 :needs_component_jmap :JMAPExtensions
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $imap = $self->{store}->get_client();

    my $using = [
        'urn:ietf:params:jmap:core',
        'urn:ietf:params:jmap:mail',
        'urn:ietf:params:jmap:submission',
        'https://cyrusimap.org/ns/jmap/mail',
        'https://cyrusimap.org/ns/jmap/quota',
        'https://cyrusimap.org/ns/jmap/debug',
        'https://cyrusimap.org/ns/jmap/performance',
    ];

    my $emailCount = 10;

    xlog "Creating $emailCount emails (every 5th has same internaldate)";
    my %createEmails;
    for (my $i = 0; $i < $emailCount; $i++) {
        my $receivedAt = '2019-01-0' . (($i % 5) + 1) . 'T00:00:00Z';
        $createEmails{$i} = {
            mailboxIds => {
                '$inbox' => JSON::true
            },
            from => [{ email => "foo$i\@bar" }],
            to => [{ email => "bar$i\@example.com" }],
            receivedAt => $receivedAt,
            subject => "email$i",
            bodyStructure => {
                partId => '1',
            },
            bodyValues => {
                "1" => {
                    value => "email$i body",
                },
            },
        }
    }
    my $res = $jmap->CallMethods([
        ['Email/set', {
            create => \%createEmails,
        }, 'R1'],
    ]);
    $self->assert_num_equals($emailCount, scalar keys %{$res->[0][1]{created}});

    my @emails;
    for (my $i = 0; $i < $emailCount; $i++) {
        $emails[$i] = {
            id => $res->[0][1]{created}{$i}{id},
            receivedAt => $createEmails{$i}{receivedAt}
        };
    }

    xlog $self, "run squatter";
    $self->{instance}->run_command({cyrus => 1}, 'squatter');

    xlog "Sort by id (ascending and descending)";
    $res = $jmap->CallMethods([
        ['Email/query', {
            filter => {
                to => '@example.com',
            },
            sort => [{
                property => 'id',
                isAscending => JSON::true,
            }]
        }, 'R1'],
        ['Email/query', {
            filter => {
                to => '@example.com',
            },
            sort => [{
                property => 'id',
                isAscending => JSON::false,
            }]
        }, 'R2'],
        ['Email/query', {
            filter => {
                to => '@example.com',
            },
            sort => [{
                property => 'id',
                isAscending => JSON::true,
            }],
            disableGuidSearch => JSON::true,
        }, 'R1'],
        ['Email/query', {
            filter => {
                to => '@example.com',
            },
            sort => [{
                property => 'id',
                isAscending => JSON::false,
            }],
            disableGuidSearch => JSON::true,
        }, 'R2'],
    ], $using);

    my $guidSearchIds;
    my @wantIds;

    # Check GUID search results
    $self->assert_equals(JSON::true, $res->[0][1]{performance}{details}{isGuidSearch});
    @wantIds = map { $_->{id} } sort { $a->{id} cmp $b->{id} } @emails;
    $self->assert_deep_equals(\@wantIds, $res->[0][1]{ids});

    $self->assert_equals(JSON::true, $res->[1][1]{performance}{details}{isGuidSearch});
    @wantIds = map { $_->{id} } sort { $b->{id} cmp $a->{id} } @emails;
    $self->assert_deep_equals(\@wantIds, $res->[1][1]{ids});

    # Check UID search result
    $self->assert_equals(JSON::false, $res->[2][1]{performance}{details}{isGuidSearch});
    @wantIds = map { $_->{id} } sort { $a->{id} cmp $b->{id} } @emails;
    $self->assert_deep_equals(\@wantIds, $res->[2][1]{ids});

    $self->assert_equals(JSON::false, $res->[3][1]{performance}{details}{isGuidSearch});
    @wantIds = map { $_->{id} } sort { $b->{id} cmp $a->{id} } @emails;
    $self->assert_deep_equals(\@wantIds, $res->[3][1]{ids});

    xlog "Sort by internaldate (break ties by id) (ascending and descending)";
    $res = $jmap->CallMethods([
        ['Email/query', {
            filter => {
                to => '@example.com',
            },
            sort => [{
                property => 'receivedAt',
                isAscending => JSON::true,
            }]
        }, 'R1'],
        ['Email/query', {
            filter => {
                to => '@example.com',
            },
            sort => [{
                property => 'receivedAt',
                isAscending => JSON::false,
            }]
        }, 'R2'],
        ['Email/query', {
            filter => {
                to => '@example.com',
            },
            sort => [{
                property => 'receivedAt',
                isAscending => JSON::true,
            }],
            disableGuidSearch => JSON::true,
        }, 'R3'],
        ['Email/query', {
            filter => {
                to => '@example.com',
            },
            sort => [{
                property => 'receivedAt',
                isAscending => JSON::false,
            }],
            disableGuidSearch => JSON::true,
        }, 'R4'],
    ], $using);

    # Check GUID search results
    $self->assert_equals(JSON::true, $res->[0][1]{performance}{details}{isGuidSearch});
    @wantIds = map { $_->{id} } sort {
        $a->{receivedAt} cmp $b->{receivedAt} or $b->{id} cmp $a->{id}
    } @emails;
    $self->assert_deep_equals(\@wantIds, $res->[0][1]{ids});

    $self->assert_equals(JSON::true, $res->[1][1]{performance}{details}{isGuidSearch});
    @wantIds = map { $_->{id} } sort {
        $b->{receivedAt} cmp $a->{receivedAt} or $b->{id} cmp $a->{id}
    } @emails;
    $self->assert_deep_equals(\@wantIds, $res->[1][1]{ids});

    # Check UID search result
    $self->assert_equals(JSON::false, $res->[2][1]{performance}{details}{isGuidSearch});
    @wantIds = map { $_->{id} } sort {
        $a->{receivedAt} cmp $b->{receivedAt} or $b->{id} cmp $a->{id}
    } @emails;
    $self->assert_deep_equals(\@wantIds, $res->[2][1]{ids});

    $self->assert_equals(JSON::false, $res->[3][1]{performance}{details}{isGuidSearch});
    @wantIds = map { $_->{id} } sort {
        $b->{receivedAt} cmp $a->{receivedAt} or $b->{id} cmp $a->{id}
    } @emails;
    $self->assert_deep_equals(\@wantIds, $res->[3][1]{ids});
}

sub test_email_query_guidsearch_inmailbox
    :min_version_3_3 :needs_component_jmap :JMAPExtensions
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $imap = $self->{store}->get_client();

    my $using = [
        'urn:ietf:params:jmap:core',
        'urn:ietf:params:jmap:mail',
        'urn:ietf:params:jmap:submission',
        'https://cyrusimap.org/ns/jmap/mail',
        'https://cyrusimap.org/ns/jmap/quota',
        'https://cyrusimap.org/ns/jmap/debug',
        'https://cyrusimap.org/ns/jmap/performance',
    ];

    xlog $self, "create mailboxes";
    $imap->create("INBOX.A") or die;
    $imap->create("INBOX.B") or die;
    $imap->create("INBOX.C") or die;
    $imap->create("INBOX.D") or die;
    my $res = $jmap->CallMethods([
        ['Mailbox/get', {
            properties => ['name', 'parentId'],
        }, "R1"]
    ], $using);
    my %mboxByName = map { $_->{name} => $_ } @{$res->[0][1]{list}};
    my $mboxIdA = $mboxByName{'A'}->{id};
    my $mboxIdB = $mboxByName{'B'}->{id};
    my $mboxIdC = $mboxByName{'C'}->{id};
    my $mboxIdD = $mboxByName{'D'}->{id};

    xlog $self, "create emails";
    $res = $jmap->CallMethods([
        ['Email/set', {
            create => {
                'mA' => {
                    mailboxIds => {
                        $mboxIdA => JSON::true,
                    },
                    from => [{
                        name => '', email => 'foo@local'
                    }],
                    to => [{
                        name => '', email => 'bar@local'
                    }],
                    subject => 'A',
                    bodyStructure => {
                        type => 'text/plain',
                        partId => 'part1',
                    },
                    bodyValues => {
                        part1 => {
                            value => 'test',
                        }
                    },
                },
                'mB' => {
                    mailboxIds => {
                        $mboxIdB => JSON::true,
                    },
                    from => [{
                        name => '', email => 'foo@local'
                    }],
                    to => [{
                        name => '', email => 'bar@local'
                    }],
                    subject => 'B',
                    bodyStructure => {
                        type => 'text/plain',
                        partId => 'part1',
                    },
                    bodyValues => {
                        part1 => {
                            value => 'test',
                        }
                    },
                },
                'mC' => {
                    mailboxIds => {
                        $mboxIdC => JSON::true,
                    },
                    from => [{
                        name => '', email => 'foo@local'
                    }],
                    to => [{
                        name => '', email => 'bar@local'
                    }],
                    subject => 'C',
                    bodyStructure => {
                        type => 'text/plain',
                        partId => 'part1',
                    },
                    bodyValues => {
                        part1 => {
                            value => 'test',
                        }
                    },
                },
                'mD' => {
                    mailboxIds => {
                        $mboxIdD => JSON::true,
                    },
                    from => [{
                        name => '', email => 'foo@local'
                    }],
                    to => [{
                        name => '', email => 'bar@local'
                    }],
                    subject => 'D',
                    bodyStructure => {
                        type => 'text/plain',
                        partId => 'part1',
                    },
                    bodyValues => {
                        part1 => {
                            value => 'test',
                        }
                    },
                },
                'mAB' => {
                    mailboxIds => {
                        $mboxIdA => JSON::true,
                        $mboxIdB => JSON::true,
                    },
                    from => [{
                        name => '', email => 'foo@local'
                    }],
                    to => [{
                        name => '', email => 'bar@local'
                    }],
                    subject => 'AB',
                    bodyStructure => {
                        type => 'text/plain',
                        partId => 'part1',
                    },
                    bodyValues => {
                        part1 => {
                            value => 'test',
                        }
                    },
                },
                'mCD' => {
                    mailboxIds => {
                        $mboxIdC => JSON::true,
                        $mboxIdD => JSON::true,
                    },
                    from => [{
                        name => '', email => 'foo@local'
                    }],
                    to => [{
                        name => '', email => 'bar@local'
                    }],
                    subject => 'CD',
                    bodyStructure => {
                        type => 'text/plain',
                        partId => 'part1',
                    },
                    bodyValues => {
                        part1 => {
                            value => 'test',
                        }
                    },
                },
                'mABCD' => {
                    mailboxIds => {
                        $mboxIdA => JSON::true,
                        $mboxIdB => JSON::true,
                        $mboxIdC => JSON::true,
                        $mboxIdD => JSON::true,
                    },
                    from => [{
                        name => '', email => 'foo@local'
                    }],
                    to => [{
                        name => '', email => 'bar@local'
                    }],
                    subject => 'ABCD',
                    bodyStructure => {
                        type => 'text/plain',
                        partId => 'part1',
                    },
                    bodyValues => {
                        part1 => {
                            value => 'test',
                        }
                    },
                },
            },
        }, 'R1'],
    ], $using);
    my $emailIdA = $res->[0][1]->{created}{mA}{id};
    $self->assert_not_null($emailIdA);
    my $emailIdB = $res->[0][1]->{created}{mB}{id};
    $self->assert_not_null($emailIdB);
    my $emailIdC = $res->[0][1]->{created}{mC}{id};
    $self->assert_not_null($emailIdC);
    my $emailIdD = $res->[0][1]->{created}{mD}{id};
    $self->assert_not_null($emailIdD);
    my $emailIdAB = $res->[0][1]->{created}{mAB}{id};
    $self->assert_not_null($emailIdAB);
    my $emailIdCD = $res->[0][1]->{created}{mCD}{id};
    $self->assert_not_null($emailIdCD);
    my $emailIdABCD = $res->[0][1]->{created}{mABCD}{id};
    $self->assert_not_null($emailIdABCD);

    xlog $self, "run squatter";
    $self->{instance}->run_command({cyrus => 1}, 'squatter');

    my @wantIds;

    xlog $self, "query emails in mailbox A";
    $res = $jmap->CallMethods([
        ['Email/query', {
            filter => {
                from => 'foo@local',
                inMailbox => $mboxIdA,
            },
            sort => [{
                property => 'id',
                isAscending => JSON::true,
            }],
        }, 'R1'],
    ], $using);
    $self->assert_equals(JSON::true, $res->[0][1]{performance}{details}{isGuidSearch});
    @wantIds = sort ($emailIdA, $emailIdAB, $emailIdABCD);
    $self->assert_deep_equals(\@wantIds, $res->[0][1]{ids});

    xlog $self, "query emails in mailbox A and B";
    $res = $jmap->CallMethods([
        ['Email/query', {
            filter => {
                operator => 'AND',
                conditions => [{
                    from => 'foo@local',
                    inMailbox => $mboxIdA,
                }, {
                    from => 'foo@local',
                    inMailbox => $mboxIdB,
                }],
            },
            sort => [{
                property => 'id',
                isAscending => JSON::true,
            }],
        }, 'R1'],
    ], $using);
    $self->assert_equals(JSON::true, $res->[0][1]{performance}{details}{isGuidSearch});
    @wantIds = sort ($emailIdAB, $emailIdABCD);
    $self->assert_deep_equals(\@wantIds, $res->[0][1]{ids});

    xlog $self, "query emails in mailboxes other than A,B";
    $res = $jmap->CallMethods([
        ['Email/query', {
            filter => {
                from => 'foo@local',
                inMailboxOtherThan => [$mboxIdA, $mboxIdB],
            },
            sort => [{
                property => 'id',
                isAscending => JSON::true,
            }],
        }, 'R1'],
    ], $using);
    $self->assert_equals(JSON::true, $res->[0][1]{performance}{details}{isGuidSearch});
    @wantIds = sort ($emailIdC, $emailIdD, $emailIdCD, $emailIdABCD);
    $self->assert_deep_equals(\@wantIds, $res->[0][1]{ids});
}

sub test_email_query_guidsearch_keywords
    :min_version_3_1 :needs_component_jmap :JMAPExtensions
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $imap = $self->{store}->get_client();

    my $using = [
        'urn:ietf:params:jmap:core',
        'urn:ietf:params:jmap:mail',
        'urn:ietf:params:jmap:submission',
        'https://cyrusimap.org/ns/jmap/mail',
        'https://cyrusimap.org/ns/jmap/quota',
        'https://cyrusimap.org/ns/jmap/debug',
        'https://cyrusimap.org/ns/jmap/performance',
    ];

    xlog $self, "create emails";
    my $res = $jmap->CallMethods([
        ['Email/set', {
            create => {
                'mA' => {
                    from => [{
                        name => '', email => 'foo@local'
                    }],
                    to => [{
                        name => '', email => 'bar@local'
                    }],
                    mailboxIds => {
                        '$inbox' => JSON::true,
                    },
                    subject => 'Answered',
                    keywords => {
                        '$Answered' => JSON::true,
                    },
                    bodyStructure => {
                        type => 'text/plain',
                        partId => 'part1',
                    },
                    bodyValues => {
                        part1 => {
                            value => 'test',
                        }
                    },
                },
                'mD' => {
                    from => [{
                        name => '', email => 'foo@local'
                    }],
                    to => [{
                        name => '', email => 'bar@local'
                    }],
                    mailboxIds => {
                        '$inbox' => JSON::true,
                    },
                    subject => 'Draft',
                    keywords => {
                        '$Draft' => JSON::true,
                    },
                    bodyStructure => {
                        type => 'text/plain',
                        partId => 'part1',
                    },
                    bodyValues => {
                        part1 => {
                            value => 'test',
                        }
                    },
                },
                'mF' => {
                    from => [{
                        name => '', email => 'foo@local'
                    }],
                    to => [{
                        name => '', email => 'bar@local'
                    }],
                    mailboxIds => {
                        '$inbox' => JSON::true,
                    },
                    subject => 'Flagged',
                    keywords => {
                        '$Flagged' => JSON::true,
                    },
                    bodyStructure => {
                        type => 'text/plain',
                        partId => 'part1',
                    },
                    bodyValues => {
                        part1 => {
                            value => 'test',
                        }
                    },
                },
            },
        }, 'R1'],
    ], $using);
    my $emailIdA = $res->[0][1]->{created}{mA}{id};
    $self->assert_not_null($emailIdA);
    my $emailIdD = $res->[0][1]->{created}{mD}{id};
    $self->assert_not_null($emailIdD);
    my $emailIdF = $res->[0][1]->{created}{mF}{id};
    $self->assert_not_null($emailIdF);

    xlog $self, "run squatter";
    $self->{instance}->run_command({cyrus => 1}, 'squatter');

    my @wantIds;

    xlog $self, "query draft emails";
    $res = $jmap->CallMethods([
        ['Email/query', {
            filter => {
                from => 'foo@local',
                hasKeyword => '$draft',
            },
            sort => [{
                property => 'id',
                isAscending => JSON::true,
            }],
        }, 'R1'],
    ], $using);
    $self->assert_equals(JSON::true, $res->[0][1]{performance}{details}{isGuidSearch});
    @wantIds = sort ($emailIdD);
    $self->assert_deep_equals(\@wantIds, $res->[0][1]{ids});

    xlog $self, "query anything but draft emails";
    $res = $jmap->CallMethods([
        ['Email/query', {
            filter => {
                from => 'foo@local',
                notKeyword => '$draft',
            },
            sort => [{
                property => 'id',
                isAscending => JSON::true,
            }],
        }, 'R1'],
    ], $using);
    $self->assert_equals(JSON::true, $res->[0][1]{performance}{details}{isGuidSearch});
    @wantIds = sort ($emailIdA, $emailIdF);
    $self->assert_deep_equals(\@wantIds, $res->[0][1]{ids});
}

sub test_email_set_guidsearch_updated_internaldate
    :min_version_3_1 :needs_component_jmap :JMAPExtensions
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $imap = $self->{store}->get_client();

    my $using = [
        'urn:ietf:params:jmap:core',
        'urn:ietf:params:jmap:mail',
        'urn:ietf:params:jmap:submission',
        'https://cyrusimap.org/ns/jmap/mail',
        'https://cyrusimap.org/ns/jmap/quota',
        'https://cyrusimap.org/ns/jmap/debug',
        'https://cyrusimap.org/ns/jmap/performance',
    ];

    xlog $self, "create emails";
    my $res = $jmap->CallMethods([
        ['Email/set', {
            create => {
                'mA' => {
                    from => [{
                        name => '', email => 'foo@local'
                    }],
                    to => [{
                        name => '', email => 'bar@local'
                    }],
                    mailboxIds => {
                        '$inbox' => JSON::true,
                    },
                    receivedAt => '2020-02-01T00:00:00Z',
                    subject => 'test',
                    bodyStructure => {
                        type => 'text/plain',
                        partId => 'part1',
                    },
                    bodyValues => {
                        part1 => {
                            value => 'test',
                        }
                    },
                },
                'mB' => {
                    from => [{
                        name => '', email => 'foo@local'
                    }],
                    to => [{
                        name => '', email => 'bar@local'
                    }],
                    mailboxIds => {
                        '$inbox' => JSON::true,
                    },
                    receivedAt => '2020-02-02T00:00:00Z',
                    subject => 'test',
                    bodyStructure => {
                        type => 'text/plain',
                        partId => 'part1',
                    },
                    bodyValues => {
                        part1 => {
                            value => 'test',
                        }
                    },
                },
            },
        }, 'R1'],
    ], $using);
    my $emailIdA = $res->[0][1]->{created}{mA}{id};
    $self->assert_not_null($emailIdA);
    my $emailBlobIdA = $res->[0][1]->{created}{mA}{blobId};
    $self->assert_not_null($emailBlobIdA);
    my $emailIdB = $res->[0][1]->{created}{mB}{id};
    $self->assert_not_null($emailIdB);

    xlog "Download blob of message A";
    $res = $jmap->Download('cassandane', $emailBlobIdA);
    my $emailBlobA = $res->{content};
    $self->assert_not_null($emailBlobA);

    xlog $self, "run squatter";
    $self->{instance}->run_command({cyrus => 1}, 'squatter');

    xlog "Query sorted by internaldate, then destroy message A";
    $res = $jmap->CallMethods([
        ['Email/query', {
            filter => {
                subject => 'test',
            },
            sort => [{
                property => 'receivedAt',
                isAscending => JSON::true,
            }]
        }, 'R1'],
        ['Email/set', {
            destroy => [$emailIdA],
        }, 'R2'],
    ], $using);
    $self->assert_equals(JSON::true, $res->[0][1]{performance}{details}{isGuidSearch});
    $self->assert_deep_equals([$emailIdA, $emailIdB], $res->[0][1]{ids});
    $self->assert_str_equals($emailIdA, $res->[1][1]{destroyed}[0]);

    xlog $self, "Compact search tier t1 to t2";
    $self->{instance}->run_command({cyrus => 1}, 'squatter', '-z', 't2', '-t', 't1');

    xlog "Sleep one second";
    sleep(1);

    xlog "Create dummy message";
    $self->make_message("dummy") || die;

    xlog "Append blob of message A via IMAP";
    $imap->append('INBOX', $emailBlobA) || die $@;

    xlog $self, "run incremental squatter";
    $self->{instance}->run_command({cyrus => 1}, 'squatter', '-i');

    xlog "Query sorted by internaldate";
    $res = $jmap->CallMethods([
        ['Email/query', {
            filter => {
                subject => 'test',
            },
            sort => [{
                property => 'receivedAt',
                isAscending => JSON::true,
            }]
        }, 'R1'],
    ], $using);
    $self->assert_equals(JSON::true, $res->[0][1]{performance}{details}{isGuidSearch});
    $self->assert_deep_equals([$emailIdB, $emailIdA], $res->[0][1]{ids});
}

sub test_email_query_guidsearch_mixedfilter
    :min_version_3_1 :needs_component_jmap :JMAPExtensions
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $imap = $self->{store}->get_client();

    my $using = [
        'urn:ietf:params:jmap:core',
        'urn:ietf:params:jmap:mail',
        'urn:ietf:params:jmap:submission',
        'https://cyrusimap.org/ns/jmap/mail',
        'https://cyrusimap.org/ns/jmap/quota',
        'https://cyrusimap.org/ns/jmap/debug',
        'https://cyrusimap.org/ns/jmap/performance',
    ];

    xlog $self, "create mailboxes";
    $imap->create("INBOX.A") or die;
    $imap->create("INBOX.B") or die;
    my $res = $jmap->CallMethods([
        ['Mailbox/get', {
            properties => ['name', 'parentId'],
        }, "R1"]
    ], $using);
    my %mboxByName = map { $_->{name} => $_ } @{$res->[0][1]{list}};
    my $mboxIdA = $mboxByName{'A'}->{id};
    my $mboxIdB = $mboxByName{'B'}->{id};

    xlog $self, "create emails";
    $res = $jmap->CallMethods([
        ['Email/set', {
            create => {
                'mAfoo' => {
                    mailboxIds => {
                        $mboxIdA => JSON::true,
                    },
                    from => [{
                        name => '', email => 'from@local'
                    }],
                    to => [{
                        name => '', email => 'to@local'
                    }],
                    subject => 'foo',
                    bodyStructure => {
                        type => 'text/plain',
                        partId => 'part1',
                    },
                    bodyValues => {
                        part1 => {
                            value => 'test',
                        }
                    },
                },
                'mAbar' => {
                    mailboxIds => {
                        $mboxIdA => JSON::true,
                    },
                    from => [{
                        name => '', email => 'from@local'
                    }],
                    to => [{
                        name => '', email => 'to@local'
                    }],
                    subject => 'bar',
                    bodyStructure => {
                        type => 'text/plain',
                        partId => 'part1',
                    },
                    bodyValues => {
                        part1 => {
                            value => 'test',
                        }
                    },
                },
                'mBfoo' => {
                    mailboxIds => {
                        $mboxIdB => JSON::true,
                    },
                    from => [{
                        name => '', email => 'from@local'
                    }],
                    to => [{
                        name => '', email => 'to@local'
                    }],
                    subject => 'foo',
                    bodyStructure => {
                        type => 'text/plain',
                        partId => 'part1',
                    },
                    bodyValues => {
                        part1 => {
                            value => 'test',
                        }
                    },
                },
                'mBbar' => {
                    mailboxIds => {
                        $mboxIdB => JSON::true,
                    },
                    from => [{
                        name => '', email => 'from@local'
                    }],
                    to => [{
                        name => '', email => 'to@local'
                    }],
                    subject => 'bar',
                    bodyStructure => {
                        type => 'text/plain',
                        partId => 'part1',
                    },
                    bodyValues => {
                        part1 => {
                            value => 'test',
                        }
                    },
                },
            },
        }, 'R1'],
    ], $using);
    my $emailIdAfoo = $res->[0][1]->{created}{mAfoo}{id};
    $self->assert_not_null($emailIdAfoo);
    my $emailIdAbar = $res->[0][1]->{created}{mAbar}{id};
    $self->assert_not_null($emailIdAbar);
    my $emailIdBfoo = $res->[0][1]->{created}{mBfoo}{id};
    $self->assert_not_null($emailIdBfoo);
    my $emailIdBbar = $res->[0][1]->{created}{mBbar}{id};
    $self->assert_not_null($emailIdBbar);

    xlog $self, "run squatter";
    $self->{instance}->run_command({cyrus => 1}, 'squatter');

    my @wantIds;

    xlog $self, "query emails with disjunction of mixed criteria";
    $res = $jmap->CallMethods([
        ['Email/query', {
            filter => {
                operator => 'OR',
                conditions => [{
                    subject => 'foo',
                }, {
                    inMailbox => $mboxIdB,
                }],
            },
            sort => [{
                property => 'id',
                isAscending => JSON::true,
            }],
        }, 'R1'],
    ], $using);

    # Current Cyrus implementation of GUID search does not support
    # disjunctions of Xapian and non-Xapian filters. This might change.
    $self->assert_equals(JSON::false, $res->[0][1]{performance}{details}{isGuidSearch});
    @wantIds = sort ($emailIdAfoo, $emailIdBfoo, $emailIdBbar);
    $self->assert_deep_equals(\@wantIds, $res->[0][1]{ids});
}

sub test_email_query_guidsearch_only_email_mailboxes
    :min_version_3_1 :needs_component_jmap :JMAPExtensions
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $imap = $self->{store}->get_client();

    my $using = [
        'urn:ietf:params:jmap:core',
        'urn:ietf:params:jmap:mail',
        'urn:ietf:params:jmap:submission',
        'https://cyrusimap.org/ns/jmap/mail',
        'https://cyrusimap.org/ns/jmap/quota',
        'https://cyrusimap.org/ns/jmap/debug',
        'https://cyrusimap.org/ns/jmap/performance',
        'https://cyrusimap.org/ns/jmap/calendars',
        'https://cyrusimap.org/ns/jmap/contacts',
    ];

    xlog $self, "create email, calendar event and contact";
    my $res = $jmap->CallMethods([
        ['Email/set', {
            create => {
                '1' => {
                    mailboxIds => {
                        '$inbox' => JSON::true,
                    },
                    from => [{
                        name => '', email => 'from@local'
                    }],
                    to => [{
                        name => '', email => 'to@local'
                    }],
                    subject => 'test',
                    bodyStructure => {
                        type => 'text/plain',
                        partId => 'part1',
                    },
                    bodyValues => {
                        part1 => {
                            value => 'test',
                        }
                    },
                },
            },
        }, 'R1'],
        ['CalendarEvent/set', {
            create => {
                '2' => {
                    calendarId => 'Default',
                    start => '2020-02-25T11:00:00',
                    timeZone => 'Australia/Melbourne',
                    title => 'test',
                }
            }
        }, 'R2'],
        ['Contact/set', {
            create => {
                "3" => {
                    lastName => "test",
                }
            }
        }, 'R3'],
    ], $using);
    my $emailId = $res->[0][1]->{created}{1}{id};
    $self->assert_not_null($emailId);
    my $eventId = $res->[1][1]->{created}{2}{id};
    $self->assert_not_null($eventId);
    my $contactId = $res->[2][1]->{created}{3}{id};
    $self->assert_not_null($contactId);

    xlog $self, "run squatter";
    $self->{instance}->run_command({cyrus => 1}, 'squatter');

    xlog "Query emails";
    $res = $jmap->CallMethods([
        ['Email/query', {
            filter => {
                text => 'test',
            },
        }, 'R1'],
    ], $using);
    $self->assert_equals(JSON::true, $res->[0][1]{performance}{details}{isGuidSearch});
    $self->assert_deep_equals([$emailId], $res->[0][1]{ids});
}

sub test_email_query_guidsearch_inmailboxotherthan
    :min_version_3_3 :needs_component_jmap :JMAPExtensions
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $imap = $self->{store}->get_client();

    my $using = [
        'urn:ietf:params:jmap:core',
        'urn:ietf:params:jmap:mail',
        'urn:ietf:params:jmap:submission',
        'https://cyrusimap.org/ns/jmap/mail',
        'https://cyrusimap.org/ns/jmap/quota',
        'https://cyrusimap.org/ns/jmap/debug',
        'https://cyrusimap.org/ns/jmap/performance',
    ];

    xlog $self, "create mailboxes";
    $imap->create("INBOX.A") or die;

    my $res = $jmap->CallMethods([
        ['Mailbox/get', {
            properties => ['name', 'parentId'],
        }, "R1"]
    ], $using);

    my %mboxByName = map { $_->{name} => $_ } @{$res->[0][1]{list}};
    my $mboxA = $mboxByName{'A'}->{id};
    $self->assert_not_null($mboxA);
    my $inbox = $mboxByName{'Inbox'}->{id};
    $self->assert_not_null($inbox);

    xlog $self, "create emails";
    $res = $jmap->CallMethods([
        ['Email/set', {
            create => {
                'msgInbox' => {
                    mailboxIds => {
                        $inbox => JSON::true,
                    },
                    from => [{
                        name => '', email => 'from@local'
                    }],
                    to => [{
                        name => '', email => 'to@local'
                    }],
                    subject => 'msgInbox',
                    bodyStructure => {
                        type => 'text/plain',
                        partId => 'part1',
                    },
                    bodyValues => {
                        part1 => {
                            value => 'test',
                        }
                    },
                },
                'msgA' => {
                    mailboxIds => {
                        $mboxA => JSON::true,
                    },
                    from => [{
                        name => '', email => 'from@local'
                    }],
                    to => [{
                        name => '', email => 'to@local'
                    }],
                    subject => 'msgA',
                    bodyStructure => {
                        type => 'text/plain',
                        partId => 'part1',
                    },
                    bodyValues => {
                        part1 => {
                            value => 'test',
                        }
                    },
                },
            },
        }, 'R1'],
    ], $using);
    my $emailInbox = $res->[0][1]->{created}{msgInbox}{id};
    $self->assert_not_null($emailInbox);
    my $emailA = $res->[0][1]->{created}{msgA}{id};
    $self->assert_not_null($emailA);

    xlog $self, "run squatter";
    $self->{instance}->run_command({cyrus => 1}, 'squatter');

    xlog "Running query with guidsearch";
    $res = $jmap->CallMethods([
        ['Email/query', {
            filter => {
                operator => 'AND',
                conditions => [{
                    body => 'test',
                    inMailboxOtherThan => [
                        $inbox,
                    ],
                }],
            },
            collapseThreads => JSON::true,
            findAllInThread => JSON::true,
        }, 'R1']
    ], $using);
    $self->assert_equals(JSON::true, $res->[0][1]{performance}{details}{isGuidSearch});
    my @wantIds = sort ($emailA);
    $self->assert_deep_equals(\@wantIds, $res->[0][1]{ids});
}

sub test_email_draft_subject_keeps_thrid
    :min_version_3_3 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    xlog $self, "create drafts mailbox";
    my $res = $jmap->CallMethods([
            ['Mailbox/set', { create => { "1" => {
                            name => "drafts",
                            parentId => undef,
                            role => "drafts"
             }}}, "R1"]
    ]);
    $self->assert_str_equals('Mailbox/set', $res->[0][0]);
    $self->assert_str_equals('R1', $res->[0][2]);
    $self->assert_not_null($res->[0][1]{created});
    my $draftsmbox = $res->[0][1]{created}{"1"}{id};

    my $messageId = "71cdcf3a-6dc5-4d95-b600-14e7f99719f0\@example.com";

    my $draft =  {
        mailboxIds => { $draftsmbox => JSON::true },
        from => [ { name => "Yosemite Sam", email => "sam\@acme.local" } ] ,
        sender => [{ name => "Marvin the Martian", email => "marvin\@acme.local" }],
        to => [
            { name => "Bugs Bunny", email => "bugs\@acme.local" },
            { name => "Rainer M\N{LATIN SMALL LETTER U WITH DIAERESIS}ller", email => "rainer\@de.local" },
        ],
        cc => [
            { name => "Elmer Fudd", email => "elmer\@acme.local" },
            { name => "Porky Pig", email => "porky\@acme.local" },
        ],
        bcc => [
            { name => "Wile E. Coyote", email => "coyote\@acme.local" },
        ],
        replyTo => [ { name => undef, email => "the.other.sam\@acme.local" } ],
        subject => "Memo",
        textBody => [{ partId => '1' }],
        htmlBody => [{ partId => '2' }],
        messageId => [$messageId],
        bodyValues => {
            '1' => { value => "I'm givin' ya one last chance ta surrenda!" },
            '2' => { value => "Oh!!! I <em>hate</em> that Rabbit." },
        },
        keywords => { '$draft' => JSON::true },
    };

    xlog $self, "create a draft";
    $res = $jmap->CallMethods([['Email/set', { create => { "1" => $draft }}, "R1"]]);
    my $id1 = $res->[0][1]{created}{"1"}{id};
    my $threadId = $res->[0][1]{created}{"1"}{threadId};

    xlog $self, "Get draft $id1";
    $res = $jmap->CallMethods([['Email/get', { ids => [$id1] }, "R1"]]);
    my $msg = $res->[0][1]->{list}[0];

    $self->assert_deep_equals($msg->{mailboxIds}, $draft->{mailboxIds});
    $self->assert_deep_equals($msg->{from}, $draft->{from});
    $self->assert_deep_equals($msg->{sender}, $draft->{sender});
    $self->assert_deep_equals($msg->{to}, $draft->{to});
    $self->assert_deep_equals($msg->{cc}, $draft->{cc});
    $self->assert_deep_equals($msg->{bcc}, $draft->{bcc});
    $self->assert_deep_equals($msg->{replyTo}, $draft->{replyTo});
    $self->assert_str_equals($msg->{subject}, $draft->{subject});
    $self->assert_str_equals($msg->{threadId}, $threadId);
    $self->assert_equals(JSON::true, $msg->{keywords}->{'$draft'});
    $self->assert_num_equals(1, scalar keys %{$msg->{keywords}});

    # change subject and prep for replace
    $draft->{subject} = "Wabbit Season!";

    xlog $self, "replace the draft with a new copy with a new subject";
    $res = $jmap->CallMethods([['Email/set', { create => { "1" => $draft }, destroy => [ $id1 ] }, "R1"]]);
    my $id2 = $res->[0][1]{created}{"1"}{id};
    $self->assert_str_not_equals($id1, $id2);
    $self->assert_str_equals($id1, $res->[0][1]{destroyed}[0]);

    xlog $self, "Get draft $id2";
    $res = $jmap->CallMethods([['Email/get', { ids => [$id2] }, "R1"]]);
    $msg = $res->[0][1]->{list}[0];

    $self->assert_deep_equals($msg->{mailboxIds}, $draft->{mailboxIds});
    $self->assert_deep_equals($msg->{from}, $draft->{from});
    $self->assert_deep_equals($msg->{sender}, $draft->{sender});
    $self->assert_deep_equals($msg->{to}, $draft->{to});
    $self->assert_deep_equals($msg->{cc}, $draft->{cc});
    $self->assert_deep_equals($msg->{bcc}, $draft->{bcc});
    $self->assert_deep_equals($msg->{replyTo}, $draft->{replyTo});
    $self->assert_str_equals($msg->{subject}, $draft->{subject});
    $self->assert_str_equals($msg->{threadId}, $threadId);
    $self->assert_equals(JSON::true, $msg->{keywords}->{'$draft'});
    $self->assert_num_equals(1, scalar keys %{$msg->{keywords}});
}

sub test_email_draft_reply_new_subject_new_thrid
    :min_version_3_3 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    xlog $self, "create drafts mailbox";
    my $res = $jmap->CallMethods([
            ['Mailbox/set', { create => { "1" => {
                            name => "drafts",
                            parentId => undef,
                            role => "drafts"
             }}}, "R1"]
    ]);
    $self->assert_str_equals('Mailbox/set', $res->[0][0]);
    $self->assert_str_equals('R1', $res->[0][2]);
    $self->assert_not_null($res->[0][1]{created});
    my $draftsmbox = $res->[0][1]{created}{"1"}{id};

    my $draft =  {
        mailboxIds => { $draftsmbox => JSON::true },
        from => [ { name => "Yosemite Sam", email => "sam\@acme.local" } ] ,
        sender => [{ name => "Marvin the Martian", email => "marvin\@acme.local" }],
        to => [
            { name => "Bugs Bunny", email => "bugs\@acme.local" },
            { name => "Rainer M\N{LATIN SMALL LETTER U WITH DIAERESIS}ller", email => "rainer\@de.local" },
        ],
        cc => [
            { name => "Elmer Fudd", email => "elmer\@acme.local" },
            { name => "Porky Pig", email => "porky\@acme.local" },
        ],
        bcc => [
            { name => "Wile E. Coyote", email => "coyote\@acme.local" },
        ],
        replyTo => [ { name => undef, email => "the.other.sam\@acme.local" } ],
        subject => "Memo",
        textBody => [{ partId => '1' }],
        htmlBody => [{ partId => '2' }],
        bodyValues => {
            '1' => { value => "I'm givin' ya one last chance ta surrenda!" },
            '2' => { value => "Oh!!! I <em>hate</em> that Rabbit." },
        },
        keywords => { '$draft' => JSON::true },
    };

    xlog $self, "Create a draft";
    $res = $jmap->CallMethods([['Email/set', { create => { "1" => $draft }}, "R1"]]);
    my $id = $res->[0][1]{created}{"1"}{id};

    xlog $self, "Get draft $id";
    $res = $jmap->CallMethods([['Email/get', { ids => [$id] }, "R1"]]);
    my $msg = $res->[0][1]->{list}[0];

    $self->assert_deep_equals($msg->{mailboxIds}, $draft->{mailboxIds});
    $self->assert_deep_equals($msg->{from}, $draft->{from});
    $self->assert_deep_equals($msg->{sender}, $draft->{sender});
    $self->assert_deep_equals($msg->{to}, $draft->{to});
    $self->assert_deep_equals($msg->{cc}, $draft->{cc});
    $self->assert_deep_equals($msg->{bcc}, $draft->{bcc});
    $self->assert_deep_equals($msg->{replyTo}, $draft->{replyTo});
    $self->assert_str_equals($msg->{subject}, $draft->{subject});
    $self->assert_equals(JSON::true, $msg->{keywords}->{'$draft'});
    $self->assert_num_equals(1, scalar keys %{$msg->{keywords}});

    xlog $self, "create sent mailbox";
    $res = $jmap->CallMethods([
            ['Mailbox/set', { create => { "1" => {
                            name => "sent",
                            parentId => undef,
                            role => "sent"
             }}}, "R1"]
    ]);
    $self->assert_str_equals('Mailbox/set', $res->[0][0]);
    $self->assert_str_equals('R1', $res->[0][2]);
    $self->assert_not_null($res->[0][1]{created});
    my $sentmbox = $res->[0][1]{created}{"1"}{id};

    # Now change the draft keyword, which is allowed since approx ~Q1/2018.
    xlog $self, "Update the email into the sent mailbox and remove draft";
    $res = $jmap->CallMethods([
        ['Email/set', {
            update => { $id => {
                'keywords' => { '$seen' => JSON::true },
                'mailboxIds' => { $sentmbox => JSON::true },
            } },
        }, "R1"]
    ]);
    $self->assert(exists $res->[0][1]{updated}{$id});

    xlog $self, "Create a new draft which is in reply";
    $draft->{inReplyTo} = $msg->{messageId};
    $draft->{subject} = "Rubbish different subject";
    $res = $jmap->CallMethods([['Email/set', { create => { "1" => $draft }}, "R1"]]);
    my $id2 = $res->[0][1]{created}{"1"}{id};
    my $thread2 = $res->[0][1]{created}{"1"}{threadId};
    $self->assert_str_not_equals($msg->{threadId}, $thread2);
}

sub test_email_query_guidsearch_collapsethreads
    :min_version_3_1 :needs_component_jmap :JMAPExtensions
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $imap = $self->{store}->get_client();

    my $using = [
        'urn:ietf:params:jmap:core',
        'urn:ietf:params:jmap:mail',
        'urn:ietf:params:jmap:submission',
        'https://cyrusimap.org/ns/jmap/mail',
        'https://cyrusimap.org/ns/jmap/quota',
        'https://cyrusimap.org/ns/jmap/debug',
        'https://cyrusimap.org/ns/jmap/performance',
    ];


    my $emailCount = 3;
    my %createEmails;
    for (my $i = 1; $i <= $emailCount; $i++) {
        my $extraBody = ' diy reseller' unless ($i % 2);
        $createEmails{$i} = {
            mailboxIds => {
                '$inbox' => JSON::true
            },
            from => [{ email => "foo$i\@bar" }],
            to => [{ email => "bar$i\@example.com" }],
            messageId => ["email$i\@local"],
            subject => "email$i",
            bodyStructure => {
                partId => '1',
            },
            bodyValues => {
                "1" => {
                    value => "email$i body" . $extraBody
                },
            },
        }
    }
    my $res = $jmap->CallMethods([
        ['Email/set', {
            create => \%createEmails,
        }, 'R1'],
    ]);
    $self->assert_num_equals($emailCount, scalar keys %{$res->[0][1]{created}});

    for (my $i = 1; $i <= $emailCount; $i++) {
        my %createEmails = ();
        my $threadCount = ($i % 7) + 3; # clamp to max 10 thread emails
        for (my $j = 1; $j <= $threadCount; $j++) {
            my $extraBody = ' nyi reseller' unless ($j % 2);
            $createEmails{$j} = {
                mailboxIds => {
                    '$inbox' => JSON::true
                },
                from => [{ email => "foo$i" . "ref$j\@bar" }],
                to => [{ email => "bar$i" . "ref$j\@example.com" }],
                messageId => ["email$i" . "ref$j\@local"],
                references => ["email$i\@local"],
                subject => "Re: email$i",
                bodyStructure => {
                    partId => '1',
                },
                bodyValues => {
                    "1" => {
                        value => "email$i" ."ref$j body" . $extraBody
                    },
                },
            }
        }
        $res = $jmap->CallMethods([
            ['Email/set', {
                create => \%createEmails,
            }, 'R1'],
        ]);
        $self->assert_num_equals($threadCount, scalar keys %{$res->[0][1]{created}});
    }

    xlog $self, "run squatter";
    $self->{instance}->run_command({cyrus => 1}, 'squatter');

    xlog "Query collapsed threads";
    $res = $jmap->CallMethods([
        ['Email/query', {
            filter => {
                operator => 'AND',
                conditions => [{
                    text => 'nyi',
                }, {
                    text => 'reseller',
                }],
            },
            sort => [{
                property => 'receivedAt',
                isAscending => JSON::false,
            }],
            collapseThreads => JSON::true,
        }, 'R1'],
        ['Email/query', {
            filter => {
                operator => 'AND',
                conditions => [{
                    text => 'nyi',
                }, {
                    text => 'reseller',
                }],
            },
            sort => [{
                property => 'receivedAt',
                isAscending => JSON::false,
            }],
            collapseThreads => JSON::true,
            disableGuidSearch => JSON::true,
        }, 'R2'],
    ], $using);

    my $guidSearchIds;
    my @wantIds;

    # Check GUID search results
    $self->assert_equals(JSON::true, $res->[0][1]{performance}{details}{isGuidSearch});
    $self->assert_equals(JSON::false, $res->[1][1]{performance}{details}{isGuidSearch});
    $self->assert_deep_equals($res->[1][1]{ids}, $res->[0][1]{ids});
}

sub test_email_get_bodyvalues_markdown
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $store = $self->{store};
    my $talk = $store->get_client();

    xlog "Upload email blob";
    my $rawEmail = ""
    . "From: foo\@local\r\n"
    . "To: bar\@local\r\n"
    . "Subject: test\r\n"
    . "Date: Tue, 24 Mar 2020 11:21:50 -0500\r\n"
    . "Content-Type: text/x-markdown\r\n"
    . "MIME-Version: 1.0\r\n"
    . "\r\n"
    . "This is a test";
    my $data = $jmap->Upload($rawEmail, "application/octet-stream");
    my $blobId = $data->{blobId};

    xlog "Import and get email";
    my $res = $jmap->CallMethods([
        ['Email/import', {
            emails => {
                1 => {
                    mailboxIds => {
                        '$inbox' => JSON::true,
                    },
                    blobId => $blobId,
                },
            },
        }, 'R1'],
        ['Email/get', {
            ids => ['#1'],
            properties => ['bodyStructure', 'bodyValues'],
            bodyProperties => [
                'partId',
                'type',
            ],
            fetchAllBodyValues => JSON::true,
        }, '$2'],
    ]);

    $self->assert_str_equals('text/x-markdown',
        $res->[1][1]{list}[0]{bodyStructure}{type});
    my $partId = $res->[1][1]{list}[0]{bodyStructure}{partId};
    $self->assert_not_null($partId);
    $self->assert_str_equals('This is a test',
        $res->[1][1]{list}[0]{bodyValues}{$partId}{value});
    $self->assert_equals(JSON::false,
        $res->[1][1]{list}[0]{bodyValues}{$partId}{isEncodingProblem});
}

sub test_email_query_sort_break_tie
    :min_version_3_1 :needs_component_jmap :JMAPExtensions
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $imap = $self->{store}->get_client();

    my $using = [
        'urn:ietf:params:jmap:core',
        'urn:ietf:params:jmap:mail',
        'urn:ietf:params:jmap:submission',
        'https://cyrusimap.org/ns/jmap/mail',
        'https://cyrusimap.org/ns/jmap/quota',
        'https://cyrusimap.org/ns/jmap/debug',
        'https://cyrusimap.org/ns/jmap/performance',
    ];

    my $emailCount = 10;
    my %createEmails;
    for (my $i = 1; $i <= $emailCount; $i++) {
        $createEmails{$i} = {
            mailboxIds => {
                '$inbox' => JSON::true
            },
            from => [{ email => "from\@local" }],
            to => [{ email => "to\@local" }],
            subject => "email$i",
            receivedAt => sprintf('2020-03-25T10:%02d:00Z', $i),
            bodyStructure => {
                partId => '1',
            },
            bodyValues => {
                "1" => {
                    value => "email$i body",
                },
            },
        }
    }
    my $res = $jmap->CallMethods([
        ['Email/set', {
            create => \%createEmails,
        }, 'R1'],
    ]);
    $self->assert_num_equals($emailCount, scalar keys %{$res->[0][1]{created}});
    my @wantEmailIds;
    # Want emails returned in descending receivedAt.
    for (my $i = $emailCount; $i >= 1; $i--) {
        push @wantEmailIds, $res->[0][1]{created}{$i}{id};
    }

    xlog $self, "run squatter";
    $self->{instance}->run_command({cyrus => 1}, 'squatter');

    xlog "Run queries";
    $res = $jmap->CallMethods([
        ['Email/query', {
        }, 'R1'],
        ['Email/query', {
            sort => [{
                property => 'from',
            }],
        }, 'R2'],
        ['Email/query', {
            filter => {
                body => 'body',
            },
        }, 'R3'],
    ], $using);

    $self->assert_equals(JSON::false, $res->[1][1]{performance}{details}{isGuidSearch});
    $self->assert_deep_equals(\@wantEmailIds, $res->[0][1]{ids});
    $self->assert_equals(JSON::false, $res->[1][1]{performance}{details}{isGuidSearch});
    $self->assert_deep_equals(\@wantEmailIds, $res->[1][1]{ids});
    $self->assert_equals(JSON::true, $res->[2][1]{performance}{details}{isGuidSearch});
    $self->assert_deep_equals(\@wantEmailIds, $res->[2][1]{ids});
}

sub test_email_query_notinmailboxid_attached
    :min_version_3_1 :needs_component_jmap :JMAPExtensions
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $imap = $self->{store}->get_client();

    xlog $self, "create mailboxes";
    $imap->create("INBOX.A") or die;
    $imap->create("INBOX.B") or die;
    my $res = $jmap->CallMethods([
        ['Mailbox/get', {
            properties => ['name', 'parentId'],
        }, "R1"]
    ]);
    my %mboxByName = map { $_->{name} => $_ } @{$res->[0][1]{list}};
    my $mboxIdA = $mboxByName{'A'}->{id};
    my $mboxIdB = $mboxByName{'B'}->{id};

    xlog $self, "create emails";
    $res = $jmap->CallMethods([
        ['Email/set', {
            create => {
                'mA' => {
                    mailboxIds => {
                        $mboxIdA => JSON::true,
                    },
                    from => [{
                        name => '', email => 'covfefe@local'
                    }],
                    to => [{
                        name => '', email => 'dest@local'
                    }],
                    subject => 'AB',
                    bodyStructure => {
                        type => 'text/plain',
                        partId => 'part1',
                    },
                    bodyValues => {
                        part1 => {
                            value => 'this email contains xyzzy',
                        }
                    },
                },
            },
        }, 'R1']
    ]);

    my $emailIdA = $res->[0][1]->{created}{mA}{id};
    my $blobA = $res->[0][1]{created}{mA}{blobId};
    $self->assert_not_null($emailIdA);
    $self->assert_not_null($blobA);

    $res = $jmap->CallMethods([
        ['Email/set', { create => { mB => {
            bcc => undef,
            bodyStructure => {
                subParts => [{
                    partId => "text",
                    type => "text/plain"
                },{
                    blobId => $blobA,
                    disposition => "attachment",
                    type => "message/rfc822"
                }],
                type => "multipart/mixed",
            },
            bodyValues => {
                text => {
                    isTruncated => $JSON::false,
                    value => "Hello World",
                },
            },
            cc => undef,
            from => [{
                email => "foo\@example.com",
                name => "Captain Foo",
            }],
            keywords => {
                '$draft' => $JSON::true,
                '$seen' => $JSON::true,
            },
            mailboxIds => {
                $mboxIdB => $JSON::true,
            },
            messageId => ["9048d4db-bd84-4ea4-9be3-ae4a136c532d\@example.com"],
            receivedAt => "2019-05-09T12:48:08Z",
            references => undef,
            replyTo => undef,
            sentAt => "2019-05-09T14:48:08+02:00",
            subject => "Hello again",
            to => [{
                email => "bar\@example.com",
                name => "Private Bar",
            }],
        }}}, "S1"],
    ]);
    my $emailIdB = $res->[0][1]->{created}{mB}{id};

    xlog $self, "run squatter";
    $self->{instance}->run_command({cyrus => 1}, 'squatter');

    xlog "Run queries";
    $res = $jmap->CallMethods([
        ['Email/query', {
        }, 'R1'],
        ['Email/query', {
            filter => {
                from => 'covfefe',
                text => 'xyzzy',
            },
        }, 'R2'],
        ['Email/query', {
            filter => {
                from => 'covfefe',
                text => 'xyzzy',
                inMailbox => $mboxIdA,
            },
        }, 'R3'],
        ['Email/query', {
            filter => {
                from => 'covfefe',
                text => 'xyzzy',
                inMailboxOtherThan => [$mboxIdA],
            },
        }, 'R4'],
        ['Email/query', {
            filter => {
                from => 'covfefe',
                text => 'xyzzy',
                inMailbox => $mboxIdB,
            },
        }, 'R5'],
        ['Email/query', {
            filter => {
                from => 'covfefe',
                text => 'xyzzy',
                inMailboxOtherThan => [$mboxIdB],
            },
        }, 'R6'],
    ]);

    $self->assert_num_equals(2, scalar(@{$res->[0][1]{ids}}));
    $self->assert_num_equals(1, scalar(@{$res->[1][1]{ids}}));
    $self->assert_num_equals(1, scalar(@{$res->[2][1]{ids}}));
    $self->assert_equals($emailIdA, $res->[2][1]{ids}[0]);
    $self->assert_num_equals(0, scalar(@{$res->[3][1]{ids}}));
    $self->assert_num_equals(0, scalar(@{$res->[4][1]{ids}}));
    $self->assert_num_equals(1, scalar(@{$res->[5][1]{ids}}));
    $self->assert_equals($emailIdA, $res->[5][1]{ids}[0]);

    my $using = [
        'urn:ietf:params:jmap:core',
        'urn:ietf:params:jmap:mail',
        'urn:ietf:params:jmap:submission',
        'https://cyrusimap.org/ns/jmap/mail',
        'https://cyrusimap.org/ns/jmap/quota',
        'https://cyrusimap.org/ns/jmap/debug',
        'https://cyrusimap.org/ns/jmap/performance',
    ];

    xlog "Run queries with extra using";
    $res = $jmap->CallMethods([
        ['Email/query', {
        }, 'R1'],
        ['Email/query', {
            filter => {
                from => 'covfefe',
                text => 'xyzzy',
            },
        }, 'R2'],
        ['Email/query', {
            filter => {
                from => 'covfefe',
                text => 'xyzzy',
                inMailbox => $mboxIdA,
            },
        }, 'R3'],
        ['Email/query', {
            filter => {
                from => 'covfefe',
                text => 'xyzzy',
                inMailboxOtherThan => [$mboxIdA],
            },
        }, 'R4'],
        ['Email/query', {
            filter => {
                from => 'covfefe',
                text => 'xyzzy',
                inMailbox => $mboxIdB,
            },
        }, 'R5'],
        ['Email/query', {
            filter => {
                from => 'covfefe',
                text => 'xyzzy',
                inMailboxOtherThan => [$mboxIdB],
            },
        }, 'R6'],
    ], $using);

    $self->assert_num_equals(2, scalar(@{$res->[0][1]{ids}}));
    $self->assert_num_equals(1, scalar(@{$res->[1][1]{ids}}));
    $self->assert_num_equals(1, scalar(@{$res->[2][1]{ids}}));
    $self->assert_equals($emailIdA, $res->[2][1]{ids}[0]);
    $self->assert_num_equals(0, scalar(@{$res->[3][1]{ids}}));
    $self->assert_num_equals(0, scalar(@{$res->[4][1]{ids}}));
    $self->assert_num_equals(1, scalar(@{$res->[5][1]{ids}}));
    $self->assert_equals($emailIdA, $res->[5][1]{ids}[0]);
}

sub test_email_copy_has_expunged
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $imaptalk = $self->{store}->get_client();
    my $admintalk = $self->{adminstore}->get_client();

    xlog $self, "Create user and share mailbox";
    $self->{instance}->create_user("other");
    $admintalk->setacl("user.other", "cassandane", "lrsiwntex") or die;

    my $srcInboxId = $self->getinbox()->{id};
    $self->assert_not_null($srcInboxId);

    my $dstInboxId = $self->getinbox({accountId => 'other'})->{id};
    $self->assert_not_null($dstInboxId);

    xlog $self, "create email";
    my $res = $jmap->CallMethods([
        ['Email/set', {
            create => {
                1 => {
                    mailboxIds => {
                        $srcInboxId => JSON::true,
                    },
                    keywords => {
                        'foo' => JSON::true,
                    },
                    subject => 'hello',
                    bodyStructure => {
                        type => 'text/plain',
                        partId => 'part1',
                    },
                    bodyValues => {
                        part1 => {
                            value => 'world',
                        }
                    },
                },
            },
        }, 'R1'],
    ]);

    my $emailId = $res->[0][1]->{created}{1}{id};
    $self->assert_not_null($emailId);

    # move to Trash and back
    $imaptalk->create("INBOX.Trash");
    $imaptalk->select("INBOX");
    $imaptalk->move('1:*', "INBOX.Trash");
    $imaptalk->select("INBOX.Trash");
    $imaptalk->move('1:*', "INBOX");

    # move into Temp
    $imaptalk->create("INBOX.Temp");
    $imaptalk->select("INBOX");
    $imaptalk->move('1:*', "INBOX.Temp");

    # Copy to other account, with mailbox identified by role
    $res = $jmap->CallMethods([
        ['Email/copy', {
            fromAccountId => 'cassandane',
            accountId => 'other',
            create => {
                1 => {
                    id => $emailId,
                    mailboxIds => {
                        '$inbox' => JSON::true,
                    },
                },
            },
        }, 'R1'],
        ['Email/get', {
            accountId => 'other',
            ids => ['#1'],
            properties => ['mailboxIds'],
        }, 'R2']
    ]);
    $self->assert_not_null($res->[1][1]{list}[0]{mailboxIds}{$dstInboxId});
}

sub test_email_query_language
    :min_version_3_3 :needs_component_jmap :JMAPExtensions
    :SearchLanguage :needs_dependency_cld2
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $using = [
        'urn:ietf:params:jmap:core',
        'urn:ietf:params:jmap:mail',
        'urn:ietf:params:jmap:submission',
        'https://cyrusimap.org/ns/jmap/mail',
        'https://cyrusimap.org/ns/jmap/quota',
        'https://cyrusimap.org/ns/jmap/debug',
        'https://cyrusimap.org/ns/jmap/performance',
    ];

use utf8;

    my @testEmailBodies = ({
        id => 'de',
        bodyStructure => {
            type => 'text/plain',
            partId => 'part1',
        },
        bodyValues => {
            part1 => {
                value =>  <<'EOF'
Jemand mußte Josef K. verleumdet haben, denn ohne daß er etwas Böses getan
hätte, wurde er eines Morgens verhaftet. Die Köchin der Frau Grubach,
seiner Zimmervermieterin, die ihm jeden Tag gegen acht Uhr früh das
Frühstück brachte, kam diesmal nicht. Das war noch niemals geschehen. K.
wartete noch ein Weilchen, sah von seinem Kopfkissen aus die alte Frau
die ihm gegenüber wohnte und die ihn mit einer an ihr ganz ungewöhnli
EOF
            },
        },
    }, {
        id => 'en',
        bodyStructure => {
            type => 'text/plain',
            partId => 'part1',
        },
        bodyValues => {
            part1 => {
                value =>  <<'EOF'
All human beings are born free and equal in dignity and rights. They are
endowed with reason and conscience and should act towards one another in
a spirit of brotherhood. Everyone has the right to life, liberty and security
of person. No one shall be held in slavery or servitude; slavery and the
slave trade shall be prohibited in all their forms. No one shall be
subjected to torture or to cruel, inhuman or degrading treatment or punishment.
EOF
            },
        },
    }, {
        id => 'fr',
        bodyStructure => {
            type => 'text/plain',
            partId => 'part1',
        },
        bodyValues => {
            part1 => {
                value =>  <<'EOF'
Hé quoi ! charmante Élise, vous devenez mélancolique, après les obligeantes
assurances que vous avez eu la bonté de me donner de votre foi ? Je vous
vois soupirer, hélas ! au milieu de ma joie ! Est-ce du regret, dites-moi,
de m'avoir fait heureux ? et vous repentez-vous de cet engagement où mes
feux ont pu vous contraindre ?
EOF
            },
        },
    }, {
        id => 'fr-and-de',
        bodyStructure => {
            type => 'multipart/mixed',
            subParts => [{
                type => 'text/plain',
                partId => 'part1',
            }, {
                type => 'text/plain',
                partId => 'part2',
            }],
        },
        bodyValues => {
            part1 => {
                value =>  <<'EOF'
Non, Valère, je ne puis pas me repentir de tout ce que je fais pour
vous. Je m'y sens entraîner par une trop douce puissance, et je n'ai
pas même la force de souhaiter que les choses ne fussent pas. Mais, a
vous dire vrai, le succès me donne de l'inquiétude ; et je crains fort
de vous aimer un peu plus que je ne devrais.
EOF
            },
            part2 => {
                value => <<'EOF'
Pfingsten, das liebliche Fest, war gekommen! es grünten und blühten
Feld und Wald; auf Hügeln und Höhn, in Büschen und Hecken
Übten ein fröhliches Lied die neuermunterten Vögel;
Jede Wiese sproßte von Blumen in duftenden Gründen,
Festlich heiter glänzte der Himmel und farbig die Erde.
EOF
            },
        },
    });

no utf8;

    my %emailIds;
    foreach (@testEmailBodies) {
        my $res = $jmap->CallMethods([
            ['Email/set', {
                create => {
                    $_->{id} => {
                        mailboxIds => {
                            '$inbox' => JSON::true
                        },
                        from => [{ email => 'foo@local' }],
                        to => [{ email => 'bar@local' }],
                        subject => $_->{id},
                        bodyStructure => $_->{bodyStructure},
                        bodyValues => $_->{bodyValues},
                    },
                },
            }, 'R1'],
        ], $using);
        $emailIds{$_->{id}} = $res->[0][1]{created}{$_->{id}}{id};
        $self->assert_not_null($emailIds{$_->{id}});
    }

    xlog $self, "run squatter";
    $self->{instance}->run_command({cyrus => 1}, 'squatter');

    my $res = $jmap->CallMethods([
        ['Email/query', {
            filter => {
                language => 'fr',
            },
        }, 'R1'],
        ['Email/query', {
            filter => {
                operator => 'OR',
                conditions => [{
                    language => 'de',
                }, {
                    language => 'fr',
                }],
            },
        }, 'R2'],
        ['Email/query', {
            filter => {
                operator => 'AND',
                conditions => [{
                    language => 'de',
                }, {
                    language => 'fr',
                }],
            },
        }, 'R3'],
        ['Email/query', {
            filter => {
                language => 'en',
            },
        }, 'R4'],
        ['Email/query', {
            filter => {
                operator => 'NOT',
                conditions => [{
                    language => 'de',
                }],
            },
        }, 'R5'],
        ['Email/query', {
            filter => {
                language => 'chr',
            },
        }, 'R6'],
        ['Email/query', {
            filter => {
                language => 'xxxx',
            },
        }, 'R7'],
    ], $using);

    # fr
    my @wantIds = sort ($emailIds{'fr'}, $emailIds{'fr-and-de'});
    my @gotIds = sort @{$res->[0][1]->{ids}};
    $self->assert_deep_equals(\@wantIds, \@gotIds);

    # OR de,fr
    @wantIds = sort ($emailIds{'fr'}, $emailIds{'de'}, $emailIds{'fr-and-de'});
    @gotIds = sort @{$res->[1][1]->{ids}};
    $self->assert_deep_equals(\@wantIds, \@gotIds);

    # AND de,fr
    $self->assert_deep_equals([$emailIds{'fr-and-de'}], $res->[2][1]->{ids});

    # en
    $self->assert_deep_equals([$emailIds{'en'}], $res->[3][1]->{ids});

    # NOT de
    @wantIds = sort ($emailIds{'en'}, $emailIds{'fr'});
    @gotIds = sort @{$res->[4][1]->{ids}};
    $self->assert_deep_equals(\@wantIds, \@gotIds);

    # chr
    $self->assert_deep_equals([], $res->[5][1]->{ids});

    # xxxx
    $self->assert_str_equals('invalidArguments', $res->[6][1]{type});
}

sub test_email_query_language_french_contractions
    :min_version_3_3 :needs_component_jmap :JMAPExtensions
    :SearchLanguage :needs_dependency_cld2
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $using = [
        'urn:ietf:params:jmap:core',
        'urn:ietf:params:jmap:mail',
        'urn:ietf:params:jmap:submission',
        'https://cyrusimap.org/ns/jmap/mail',
        'https://cyrusimap.org/ns/jmap/quota',
        'https://cyrusimap.org/ns/jmap/debug',
        'https://cyrusimap.org/ns/jmap/performance',
    ];

use utf8;

    my $res = $jmap->CallMethods([
        ['Email/set', {
            create => {
                email1 => {
                    mailboxIds => {
                        '$inbox' => JSON::true
                    },
                    subject => "fr",
                    bodyStructure => {
                        type => 'text/plain',
                        partId => 'part1',
                    },
                    bodyValues => {
                        part1 => {
                            value => <<'EOF'
C'est dadaïste d'Amérique j’aime je l'aime Je m’appelle
n’est pas là qu’il s’escrit Je t’aime.
EOF
                        }
                    },
                },
            },
        }, 'R1'],
    ], $using);
    my $emailId = $res->[0][1]{created}{email1}{id};
    $self->assert_not_null($emailId);

no utf8;

    xlog $self, "run squatter";
    $self->{instance}->run_command({cyrus => 1}, 'squatter');

    my @tests = ({
        body => "c'est",
        wantIds => [$emailId],
    }, {
        body => "est",
        wantIds => [$emailId],
    }, {
        body => "p'est",
        wantIds => [],
    }, {
        body => "amerique",
        wantIds => [$emailId],
    }, {
        body => "s'appelle",
        wantIds => [$emailId],
    }, {
        body => "il",
        wantIds => [$emailId],
    });

    foreach (@tests) {
        $res = $jmap->CallMethods([
            ['Email/query', {
                filter => {
                    body => $_->{body},
                },
            }, 'R1'],
        ]);
        $self->assert_deep_equals($_->{wantIds}, $res->[0][1]{ids});
    }
}

sub test_email_query_findallinthread
    :min_version_3_3 :needs_component_jmap :JMAPExtensions
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $imap = $self->{store}->get_client();

    my $using = [
        'urn:ietf:params:jmap:core',
        'urn:ietf:params:jmap:mail',
        'urn:ietf:params:jmap:submission',
        'https://cyrusimap.org/ns/jmap/mail',
        'https://cyrusimap.org/ns/jmap/quota',
        'https://cyrusimap.org/ns/jmap/debug',
        'https://cyrusimap.org/ns/jmap/performance',
    ];

    xlog "Create three top-level thread emails";
    my %createEmails;
    for (my $i = 1; $i <= 3; $i++) {
        $createEmails{$i} = {
            mailboxIds => {
                '$inbox' => JSON::true
            },
            from => [{ email => "$i\@local" }],
            to => [{ email => "$i\@local" }],
            messageId => ["email$i\@local"],
            subject => "email$i",
            bodyStructure => {
                partId => '1',
            },
            bodyValues => {
                "1" => {
                    value => "email$i body",
                },
            },
        }
    }
    my $res = $jmap->CallMethods([
        ['Email/set', {
            create => \%createEmails,
        }, 'R1'],
    ]);
    $self->assert_num_equals(3, scalar keys %{$res->[0][1]{created}});
    my $emailId1 = $res->[0][1]{created}{1}{id};
    $self->assert_not_null($emailId1);
    my $threadId1 = $res->[0][1]{created}{1}{threadId};
    $self->assert_not_null($threadId1);
    my $emailId2 = $res->[0][1]{created}{2}{id};
    $self->assert_not_null($emailId2);
    my $threadId2 = $res->[0][1]{created}{2}{threadId};
    $self->assert_not_null($threadId2);
    my $emailId3 = $res->[0][1]{created}{3}{id};
    $self->assert_not_null($emailId3);
    my $threadId3 = $res->[0][1]{created}{3}{threadId};
    $self->assert_not_null($threadId3);

    xlog "Create reference emails to top-level emails";
    %createEmails = ();
    foreach (qw/21 22 31/) {
        my $ref = substr($_, 0, 1);
        $createEmails{$_} = {
            mailboxIds => {
                '$inbox' => JSON::true
            },
            from => [{ email => "$_\@local" }],
            to => [{ email => "$_\@local" }],
            messageId => ["email$_\@local"],
            subject => "Re: email$ref",
            references => ["email$ref\@local"],
            bodyStructure => {
                partId => '1',
            },
            bodyValues => {
                "1" => {
                    value => "email$_ body",
                },
            },
        }
    }
    $res = $jmap->CallMethods([
        ['Email/set', {
            create => \%createEmails,
        }, 'R1'],
    ]);
    $self->assert_num_equals(3, scalar keys %{$res->[0][1]{created}});
    my $emailId21 = $res->[0][1]{created}{21}{id};
    $self->assert_not_null($emailId21);
    my $emailId22 = $res->[0][1]{created}{22}{id};
    $self->assert_not_null($emailId22);
    my $emailId31 = $res->[0][1]{created}{31}{id};
    $self->assert_not_null($emailId31);

    xlog $self, "run squatter";
    $self->{instance}->run_command({cyrus => 1}, 'squatter');

    xlog "Query emails";
    $res = $jmap->CallMethods([
        ['Email/query', {
            filter => {
                body => 'body',
            },
            sort => [{
                property => 'id',
            }],
            collapseThreads => JSON::true,
            findAllInThread => JSON::true,
        }, 'R1'],
        ['Email/query', {
            filter => {
                body => 'body',
            },
            sort => [{
                property => 'id',
            }],
            collapseThreads => JSON::true,
            findAllInThread => JSON::true,
            disableGuidSearch => JSON::true,
        }, 'R2'],
    ], $using);

    my @emailIdsThread1 = sort ($emailId1);
    my @emailIdsThread2 = sort ($emailId2, $emailId21, $emailId22);
    my @emailIdsThread3 = sort ($emailId3, $emailId31);

    my $wantThreadIdToEmailIds = {
        $threadId1 => \@emailIdsThread1,
        $threadId2 => \@emailIdsThread2,
        $threadId3 => \@emailIdsThread3,
    };

    my %gotThreadIdToEmailIds;
    while (my ($threadId, $emailIds) = each %{$res->[0][1]{threadIdToEmailIds}}) {
        my @emailIds = sort @{$emailIds};
        $gotThreadIdToEmailIds{$threadId} = \@emailIds;
    }
    $self->assert_equals(JSON::true, $res->[0][1]{performance}{details}{isGuidSearch});
    $self->assert_deep_equals($wantThreadIdToEmailIds, \%gotThreadIdToEmailIds);

    %gotThreadIdToEmailIds = ();
    while (my ($threadId, $emailIds) = each %{$res->[1][1]{threadIdToEmailIds}}) {
        my @emailIds = sort @{$emailIds};
        $gotThreadIdToEmailIds{$threadId} = \@emailIds;
    }
    $self->assert_equals(JSON::false, $res->[1][1]{performance}{details}{isGuidSearch});
    $self->assert_deep_equals($wantThreadIdToEmailIds, \%gotThreadIdToEmailIds);

    xlog "Assert empty result";
    $res = $jmap->CallMethods([
        ['Email/query', {
            filter => {
                body => 'nope',
            },
            findAllInThread => JSON::true,
        }, 'R1'],
        ['Email/query', {
            filter => {
                body => 'nope',
            },
            findAllInThread => JSON::true,
            disableGuidSearch => JSON::true,
        }, 'R2'],
    ], $using);
    $self->assert_deep_equals({}, $res->[0][1]{threadIdToEmailIds});
    $self->assert_deep_equals({}, $res->[1][1]{threadIdToEmailIds});

    xlog "Assert threadIdToEmailIds isn't set if not requested";
    $res = $jmap->CallMethods([
        ['Email/query', {
            filter => {
                body => 'body',
            },
        }, 'R1'],
        ['Email/query', {
            filter => {
                body => 'body',
            },
            disableGuidSearch => JSON::true,
        }, 'R2'],
    ], $using);
    $self->assert_null($res->[0][1]{threadIdToEmailIds});
    $self->assert_null($res->[1][1]{threadIdToEmailIds});
}

sub test_email_parse_replyto
    :min_version_3_1 :needs_component_jmap :JMAPExtensions
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $imap = $self->{store}->get_client();

    my $rawMessage = <<'EOF';
From: <from@local>
To: to@local
Reply-To: replyto@local
Subject: test
Date: Mon, 13 Apr 2020 15:34:03 +0200
MIME-Version: 1.0
Content-Type: multipart/mixed;
 boundary=6c3338934661485f87537c19b5f9d933

--6c3338934661485f87537c19b5f9d933
Content-Type: text/plain

body

--6c3338934661485f87537c19b5f9d933
Content-Type: message/rfc822

From: <attachedfrom@local>
To: attachedto@local
Reply-To: attachedreplyto@local
Subject: attachedtest
Date: Mon, 13 Apr 2020 15:34:03 +0200
MIME-Version: 1.0
Content-Type: text/plain

attachedbody

--6c3338934661485f87537c19b5f9d933--
EOF
    $rawMessage =~ s/\r?\n/\r\n/gs;
    $imap->append('INBOX', $rawMessage) || die $@;
    my $res = $jmap->CallMethods([
        ['Email/query', {
        }, 'R1'],
        ['Email/get', {
            '#ids' => {
                resultOf => 'R1',
                name => 'Email/query',
                path => '/ids'
            },
            properties => ['bodyStructure'],
        }, 'R2'],
    ]);
    my $emailId = $res->[0][1]{ids}[0];
    $self->assert_not_null($emailId);

    my $blobId = $res->[1][1]{list}[0]{bodyStructure}{subParts}[1]{blobId};
    $self->assert_not_null($blobId);

    $res = $jmap->CallMethods([
        ['Email/parse', {
            blobIds => [$blobId],
            properties => ['from', 'replyTo'],
        }, 'R1'],
    ]);
    $self->assert_str_equals('attachedfrom@local',
        $res->[0][1]{parsed}{$blobId}{from}[0]{email});
    $self->assert_str_equals('attachedreplyto@local',
        $res->[0][1]{parsed}{$blobId}{replyTo}[0]{email});
}

sub test_email_query_deliveredto
    :min_version_3_3 :needs_component_jmap :JMAPExtensions
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $imap = $self->{store}->get_client();

    my $rawMessage = <<'EOF';
From: <from@local>
To: to@local
Bcc: bcc@local
X-Delivered-To: deliveredto@local
Subject: match1
Date: Mon, 13 Apr 2020 15:34:03 +0200
MIME-Version: 1.0
Content-Type: text/plain

match1
EOF
    $rawMessage =~ s/\r?\n/\r\n/gs;
    $imap->append('INBOX', $rawMessage) || die $@;

    $rawMessage = <<'EOF';
From: <from@local>
To: to@local
Bcc: bcc@local
X-Original-Delivered-To: deliveredto@local
Subject: match2
Date: Mon, 13 Apr 2020 15:34:03 +0200
MIME-Version: 1.0
Content-Type: text/plain

match2
EOF
    $rawMessage =~ s/\r?\n/\r\n/gs;
    $imap->append('INBOX', $rawMessage) || die $@;

    $rawMessage = <<'EOF';
From: <from@local>
To: to@local
Subject: nomatch
Date: Mon, 13 Apr 2020 15:34:03 +0200
MIME-Version: 1.0
Content-Type: text/plain

nomatch
EOF
    $rawMessage =~ s/\r?\n/\r\n/gs;
    $imap->append('INBOX', $rawMessage) || die $@;

    xlog $self, "run squatter";
    $self->{instance}->run_command({cyrus => 1}, 'squatter');

    my $using = [
        'urn:ietf:params:jmap:core',
        'urn:ietf:params:jmap:mail',
        'urn:ietf:params:jmap:submission',
        'https://cyrusimap.org/ns/jmap/mail',
    ];

    my $res = $jmap->CallMethods([
        ['Email/query', {
            filter => { },
            sort => [{
                property => 'subject',
            }],
        }, 'R1'],
    ], $using);
    $self->assert_num_equals(3, scalar @{$res->[0][1]{ids}});
    my $match1Id = $res->[0][1]{ids}[0];
    $self->assert_not_null($match1Id);
    my $match2Id = $res->[0][1]{ids}[1];
    $self->assert_not_null($match2Id);
    my $noMatchId = $res->[0][1]{ids}[2];
    $self->assert_not_null($noMatchId);

    xlog "Query with JMAP search";
    $res = $jmap->CallMethods([
        ['Email/query', {
            filter => {
                deliveredTo => 'deliveredto@local',
            },
            sort => [{
                property => 'subject',
            }],
        }, 'R1'],
    ], $using);
    $self->assert_deep_equals([$match1Id,$match2Id], $res->[0][1]{ids});

    xlog "Query with IMAP search";
    $imap->select('INBOX');
    my $uids = $imap->search(
        'deliveredto', { Quote => 'deliveredto@local' },
    ) || die;
    $self->assert_deep_equals([1,2], $uids);

    xlog "Query with fuzzy IMAP search";
    $imap->select('INBOX');
    $uids = $imap->search(
        'fuzzy', 'deliveredto', { Quote => 'deliveredto@local' },
    ) || die;
    $self->assert_deep_equals([1,2], $uids);
}

sub test_email_query_guidsearch_inbox
    :min_version_3_1 :needs_component_jmap :JMAPExtensions
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $using = [
        'urn:ietf:params:jmap:core',
        'urn:ietf:params:jmap:mail',
        'urn:ietf:params:jmap:submission',
        'https://cyrusimap.org/ns/jmap/mail',
        'https://cyrusimap.org/ns/jmap/debug',
        'https://cyrusimap.org/ns/jmap/performance',
    ];

    xlog "Create message in mailbox A";
    my $email = <<'EOF';
From: from@local
To: to@local
Subject: email1
Date: Wed, 7 Dec 2016 22:11:11 +1100
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"

email1
EOF
    $email =~ s/\r?\n/\r\n/gs;
    my $data = $jmap->Upload($email, "message/rfc822");
    my $blobId = $data->{blobId};
    $self->assert_not_null($blobId);

    my $res = $jmap->CallMethods([
        ['Mailbox/query', {
        }, "R1"],
        ['Mailbox/set', {
            create => {
                mboxA => {
                    name => "A",
                }
            }
        }, "R2"]
    ], $using);
    my $inboxId = $res->[0][1]{ids}[0];
    $self->assert_not_null($inboxId);
    my $mboxId = $res->[1][1]{created}{mboxA}{id};
    $self->assert_not_null($mboxId);

    $res = $jmap->CallMethods([
        ['Email/import', {
            emails => {
                email1 => {
                    blobId => $blobId,
                    mailboxIds => {
                        $mboxId => JSON::true
                    },
                },
            },
        }, "R1"],
    ], $using);
    $self->assert_str_equals("Email/import", $res->[0][0]);
    my $email1Id = $res->[0][1]->{created}{email1}{id};
    $self->assert_not_null($email1Id);

    $self->{instance}->run_command({cyrus => 1}, 'squatter');

    xlog "Query inMailbox=inbox";
    $res = $jmap->CallMethods([
        ['Email/get', {
            ids => [$email1Id],
            properties => ['mailboxIds'],
        }, "R1"],
        ['Email/query', {
            filter => {
                operator => 'AND',
                conditions => [{
                    inMailbox => $inboxId,
                }],
            },
        }, "R2"],
        ['Email/query', {
            filter => {
                operator => 'AND',
                conditions => [{
                    inMailbox => $inboxId,
                    subject => 'email1',
                }],
            },
        }, "R3"],
    ], $using);
    $self->assert_deep_equals({
        $mboxId => JSON::true,
    }, $res->[0][1]{list}[0]{mailboxIds});
    $self->assert_equals(JSON::false, $res->[1][1]{performance}{details}{isGuidSearch});
    $self->assert_deep_equals([], $res->[1][1]{ids});
    $self->assert_equals(JSON::true, $res->[2][1]{performance}{details}{isGuidSearch});
    $self->assert_deep_equals([], $res->[2][1]{ids});

    xlog "Create message in inbox";
    $res = $jmap->CallMethods([
        ['Email/set', {
            create => {
                email2 => {
                    mailboxIds => {
                        $inboxId => JSON::true,
                    },
                    subject => 'email2',
                    bodyStructure => {
                        type => 'text/plain',
                        partId => 'part1',
                    },
                    bodyValues => {
                        part1 => {
                            value => 'email2',
                        }
                    },
                },
            },
        }, 'R1'],
    ]);
    my $email2Id = $res->[0][1]->{created}{email2}{id};
    $self->assert_not_null($email2Id);

    $self->{instance}->run_command({cyrus => 1}, 'squatter');

    xlog "Rerun query inMailbox=inbox";
    $res = $jmap->CallMethods([
        ['Email/query', {
            filter => {
                operator => 'AND',
                conditions => [{
                    inMailbox => $inboxId,
                }],
            },
        }, "R1"],
        ['Email/query', {
            filter => {
                operator => 'AND',
                conditions => [{
                    inMailbox => $inboxId,
                    subject => 'email2',
                }],
            },
        }, "R1"],
    ], $using);
    $self->assert_equals(JSON::false, $res->[0][1]{performance}{details}{isGuidSearch});
    $self->assert_deep_equals([$email2Id], $res->[0][1]{ids});
    $self->assert_equals(JSON::true, $res->[1][1]{performance}{details}{isGuidSearch});
    $self->assert_deep_equals([$email2Id], $res->[1][1]{ids});
}

sub test_email_get_iso2022jp_body
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $imap = $self->{store}->get_client();

    open(my $F, 'data/mime/iso-2022-jp.eml') || die $!;
    $imap->append('INBOX', $F) || die $@;
    close($F);

    my $res = $jmap->CallMethods([
        ['Email/query', { }, 'R1'],
        ['Email/get', {
            '#ids' => {
                resultOf => 'R1',
                name => 'Email/query',
                path => '/ids'
            },
            properties => ['bodyValues', 'preview'],
            fetchAllBodyValues => JSON::true,
        }, 'R2'],
    ]);

use utf8;
    $self->assert_str_equals("シニアソフトウェアエンジニア\n",
        $res->[1][1]{list}[0]{bodyValues}{1}{value});
    $self->assert_str_equals("シニアソフトウェアエンジニア ",
        $res->[1][1]{list}[0]{preview});
no utf8;
}

sub test_email_blob_set_singlecommand
    :min_version_3_3 :needs_component_jmap :JMAPExtensions
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $email = <<'EOF';
From: "Some Example Sender" <example@example.com>
To: baseball@vitaead.com
Subject: test email
Date: Wed, 7 Dec 2016 22:11:11 +1100
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

This is a test email.
EOF
    $email =~ s/\r?\n/\r\n/gs;

    xlog $self, "create drafts mailbox";
    my $res = $jmap->CallMethods([
            ['Mailbox/set', { create => { "1" => {
                            name => "drafts",
                            parentId => undef,
                            role => "drafts"
             }}}, "R1"]
    ]);
    $self->assert_str_equals('Mailbox/set', $res->[0][0]);
    $self->assert_str_equals('R1', $res->[0][2]);
    $self->assert_not_null($res->[0][1]{created});
    my $draftsmbox = $res->[0][1]{created}{"1"}{id};

    my $using = [
        'https://cyrusimap.org/ns/jmap/performance',
        'urn:ietf:params:jmap:core',
        'urn:ietf:params:jmap:mail',
        'https://cyrusimap.org/ns/jmap/blob',
    ];

    xlog $self, "do the lot!";
    $res = $jmap->CallMethods([
            ['Blob/set', { create => { "a" => { content => $email } } }, 'R0'],
            ['Email/import', {
            emails => {
                "1" => {
                    blobId => '#a',
                    mailboxIds => { $draftsmbox => JSON::true},
                    keywords => {
                        '$draft' => JSON::true,
                    },
                },
            },
        }, "R1"]
    ], $using);

    my $msg = $res->[1][1]->{created}{"1"};
    $self->assert_not_null($msg);

    my $logofile = abs_path('data/logo.gif');
    open(FH, "<$logofile");
    local $/ = undef;
    my $binary = <FH>;
    close(FH);

    $res = $jmap->CallMethods([
            ['Blob/set', { create => { "img" => { content64 => encode_base64($binary, ''), type => 'image/gif' } } }, 'R0'],
            ['Email/set', {
            create => {
                "2" => {
                    mailboxIds =>  { $draftsmbox => JSON::true },
                    from => [ { name => "Yosemite Sam", email => "sam\@acme.local" } ] ,
                    to => [
                        { name => "Bugs Bunny", email => "bugs\@acme.local" },
                    ],
                    subject => "Memo",
                    textBody => [{ partId => '1' }],
                    bodyValues => {
                        '1' => {
                            value => "I'm givin' ya one last chance ta surrenda!"
                        }
                    },
                    attachments => [{
                        blobId => '#img',
                        name => "logo.gif",
                    }],
                    keywords => { '$draft' => JSON::true },
      } } }, 'R1'],
    ], $using);

    $msg = $res->[1][1]->{created}{"2"};
    $self->assert_not_null($msg);
}

sub test_email_query_fromanycontact_ignore_localpartonly
    :min_version_3_3 :needs_component_jmap :JMAPExtensions :needs_component_sieve
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $imap = $self->{store}->get_client();

    xlog "Create contact with localpart-only mail address";
    my $using = [
        'urn:ietf:params:jmap:core',
        'urn:ietf:params:jmap:mail',
        'https://cyrusimap.org/ns/jmap/mail',
        'https://cyrusimap.org/ns/jmap/contacts',
    ];

    my $res = $jmap->CallMethods([
        ['Contact/set', {
            create => {
                contact1 => {
                    emails => [{
                        type => 'personal',
                        value => 'email',
                    }],
                },
            }
        }, 'R1'],
    ], $using);
    my $contactId1 = $res->[0][1]{created}{contact1}{id};
    $self->assert_not_null($contactId1);

    xlog "Assert JMAP sieve ignores localpart-only contacts";
    $imap->create("INBOX.matches") or die;
    $self->{instance}->install_sieve_script(<<'EOF'
require ["x-cyrus-jmapquery", "x-cyrus-log", "variables", "fileinto"];
if
  allof( not string :is "${stop}" "Y",
    jmapquery text:
  {
    "operator" : "NOT",
    "conditions" : [
        {
           "fromAnyContact" : true
        }
    ]
  }
.
  )
{
  fileinto "INBOX.matches";
}
EOF
    );

    my $msg1 = $self->{gen}->generate(from => Cassandane::Address->new(
            localpart => 'email', domain => 'local'
    ));
    $self->{instance}->deliver($msg1);
    $self->{store}->set_fetch_attributes('uid');
    $self->{store}->set_folder('INBOX.matches');
    $self->check_messages({ 1 => $msg1 }, check_guid => 0);

    xlog "Assert Email/query ignores localpart-only contacts";
    $res = $jmap->CallMethods([
        ['Email/query', {
            filter => {
                operator => 'NOT',
                conditions => [{
                    fromAnyContact => JSON::true
                }]
            },
            sort => [
                { property => "subject" }
            ],
        }, 'R1']
    ], $using);
    $self->assert_num_equals(1, scalar @{$res->[0][1]{ids}});
}

sub test_email_query_dash_sieve
    :min_version_3_3 :needs_component_jmap :JMAPExtensions :needs_component_sieve
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $imap = $self->{store}->get_client();

    xlog "Running query in sieve";
    $imap->create("INBOX.matches") or die;
    $self->{instance}->install_sieve_script(<<'EOF'
require ["x-cyrus-jmapquery", "x-cyrus-log", "variables", "fileinto"];
if
  allof( not string :is "${stop}" "Y",
    jmapquery text:
  {
     "operator" : "AND",
     "conditions" : [
        {
           "subject" : "something"
        },
        {
           "subject" : "-"
        },
        {
           "subject" : "otherthing"
        }
     ]
  }
.
  )
{
  fileinto "INBOX.matches";
}
EOF
    );

    my $msg1 = $self->{gen}->generate(
		subject => 'something - otherthing', body => ''
    );
    $self->{instance}->deliver($msg1);
    my $msg2 = $self->{gen}->generate(
		subject => 'something', body => ''
    );
    my $msg3 = $self->{gen}->generate(
		subject => 'otherthing', body => ''
    );
    $self->{instance}->deliver($msg1);
    $self->{store}->set_fetch_attributes('uid');
    $self->{store}->set_folder('INBOX.matches');
    $self->check_messages({ 1 => $msg1 }, check_guid => 0);
}

sub test_email_query_dash
    :min_version_3_3 :needs_component_jmap :JMAPExtensions
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $imap = $self->{store}->get_client();

    $self->make_message("something - otherthing", body => 'test') || die;
    $self->make_message("something", body => 'test') || die;
    $self->make_message("otherthing", body => 'test') || die;

    my $using = [
        'urn:ietf:params:jmap:core',
        'urn:ietf:params:jmap:mail',
        'urn:ietf:params:jmap:submission',
        'https://cyrusimap.org/ns/jmap/mail',
        'https://cyrusimap.org/ns/jmap/quota',
        'https://cyrusimap.org/ns/jmap/debug',
        'https://cyrusimap.org/ns/jmap/performance',
    ];

    xlog $self, "run squatter";
    $self->{instance}->run_command({cyrus => 1}, 'squatter');

    xlog "Running query with guidsearch";
    my $res = $jmap->CallMethods([
        ['Email/query', {
            filter => {
                "operator" => "AND",
                "conditions" => [
                    {
                        "subject" => "something"
                    },
                    {
                        "subject" => "-"
                    },
                    {
                        "subject" => "otherthing"
                    }
                ],
            },
        }, 'R1']
    ], $using);
    $self->assert_num_equals(1, scalar @{$res->[0][1]{ids}});
}

sub test_email_bimi_blob
    :min_version_3_3 :needs_component_jmap :JMAPExtensions
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    # we need 'https://cyrusimap.org/ns/jmap/mail' capability for
    # bimiBlobId property
    my @using = @{ $jmap->DefaultUsing() };
    push @using, 'https://cyrusimap.org/ns/jmap/mail';
    $jmap->DefaultUsing(\@using);

    my $bimifile = abs_path('data/FM_BIMI.svg');
    open(FH, "<$bimifile");
    local $/ = undef;
    my $binary = <FH>;
    close(FH);

    $self->make_message("foo",
        mime_type => 'text/plain',
        extra_headers => [
            ['BIMI-Indicator', encode_base64($binary, '')],
        ],
        body => 'foo',
    ) || die;

    xlog $self, "get email list";
    my $res = $jmap->CallMethods([['Email/query', {}, "R1"]]);
    my $ids = $res->[0][1]->{ids};

    xlog $self, "get email";
    $res = $jmap->CallMethods([['Email/get', {
        ids => $ids,
        properties => ['bimiBlobId'],
    }, "R1"]]);
    my $msg = $res->[0][1]{list}[0];

    my $blobid = $msg->{bimiBlobId};
    $self->assert_not_null($blobid);

    my $blob = $jmap->Download({ accept => 'image/svg+xml' },
                               'cassandane', $blobid);
    $self->assert_str_equals('image/svg+xml',
                             $blob->{headers}->{'content-type'});
    $self->assert_num_not_equals(0, $blob->{headers}->{'content-length'});
    $self->assert_equals($binary, $blob->{content});
}

sub test_email_bimi_blob_as_contact_avatar
    :min_version_3_5 :needs_component_jmap :JMAPExtensions
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    # we need 'https://cyrusimap.org/ns/jmap/mail' capability for
    # bimiBlobId property
    my @using = @{ $jmap->DefaultUsing() };
    push @using, 'https://cyrusimap.org/ns/jmap/mail';
    push @using, 'https://cyrusimap.org/ns/jmap/contacts';
    $jmap->DefaultUsing(\@using);

    my $bimifile = abs_path('data/FM_BIMI.svg');
    open(FH, "<$bimifile");
    local $/ = undef;
    my $binary = <FH>;
    close(FH);

    $self->make_message("foo",
        mime_type => 'text/plain',
        extra_headers => [
            ['BIMI-Indicator', encode_base64($binary, '')],
        ],
        body => 'foo',
    ) || die;

    xlog $self, "get email list";
    my $res = $jmap->CallMethods([['Email/query', {}, "R1"]]);
    my $ids = $res->[0][1]->{ids};

    xlog $self, "get email";
    $res = $jmap->CallMethods([['Email/get', {
        ids => $ids,
        properties => ['bimiBlobId'],
    }, "R1"]]);
    my $msg = $res->[0][1]{list}[0];

    my $blobid = $msg->{bimiBlobId};
    $self->assert_not_null($blobid);

    my $blob = $jmap->Download({ accept => 'image/svg+xml' },
                               'cassandane', $blobid);
    $self->assert_str_equals('image/svg+xml',
                             $blob->{headers}->{'content-type'});
    $self->assert_num_not_equals(0, $blob->{headers}->{'content-length'});
    $self->assert_equals($binary, $blob->{content});

    my $contact = {
        firstName => "first",
        lastName => "last",
        avatar => {
            blobId => $blobid,
            size => $blob->{headers}->{'content-length'},
            type => 'image/svg+xml',
            name => JSON::null
        }
    };

    $res = $jmap->CallMethods([['Contact/set',
                                {create => {"1" => $contact }}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals('Contact/set', $res->[0][0]);
    $self->assert_str_equals('R1', $res->[0][2]);
    $self->assert_not_null($res->[0][1]{created});
    $self->assert_not_null($res->[0][1]{created}{"1"}{avatar}{blobId});
}

sub test_email_attach_contact_by_blobid
    :min_version_3_5 :needs_component_jmap :JMAPExtensions
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my @using = @{ $jmap->DefaultUsing() };
    push @using, 'https://cyrusimap.org/ns/jmap/mail';
    push @using, 'https://cyrusimap.org/ns/jmap/contacts';
    $jmap->DefaultUsing(\@using);

    my $res = $jmap->CallMethods([['Mailbox/get', { }, "R1"]]);
    my $inboxid = $res->[0][1]{list}[0]{id};

    my $contact = {
        firstName => "first",
        lastName => "last"
    };

    $res = $jmap->CallMethods([['Contact/set',
                                {create => {"1" => $contact }}, "R1"]]);
    $self->assert_not_null($res);
    $self->assert_str_equals('Contact/set', $res->[0][0]);
    $self->assert_str_equals('R1', $res->[0][2]);
    $self->assert_not_null($res->[0][1]{created});

    my $blobid = $res->[0][1]{created}{"1"}{blobId};
    my $size = $res->[0][1]{created}{"1"}{size};

    $res = $jmap->CallMethods([['Email/set', {
        create => {
            k1 => {
                bcc => undef,
                bodyStructure => {
                    subParts => [{
                        partId => 'text',
                        type => 'text/plain',
                    },{
                        blobId => $blobid,
                        cid => undef,
                        disposition => 'attachment',
                        height => undef,
                        name => 'last.vcf',
                        size => $size,
                        type => 'text/vcard',
                        width => undef,
                    }],
                    type => 'multipart/mixed',
                },
                bodyValues => {
                    text => {
                        isTruncated => $JSON::false,
                        value => "Hello world",
                    },
                },
                mailboxIds => { $inboxid => JSON::true },
                subject => 'email with vCard',
                from => [ {email => 'foo@example.com', name => 'foo' } ],
                to => [ {email => 'foo@example.com', name => 'foo' } ],
            },
        },
    }, "R1"]]);

    my $id = $res->[0][1]{created}{k1}{id};
    $self->assert_not_null($id);

    $res = $jmap->CallMethods([['Email/get', {
        ids => [$id],
        properties => ['bodyStructure'],
    }, "R1"]]);
    my $msg = $res->[0][1]{list}[0];

    my $newpart = $msg->{bodyStructure}{subParts}[1];
    $self->assert_str_equals("last.vcf", $newpart->{name});
    $self->assert_str_equals("text/vcard", $newpart->{type});
    $self->assert_num_equals($size, $newpart->{size});

}

sub test_email_query_guidsearch_threadkeywords
    :min_version_3_3 :needs_component_jmap :JMAPExtensions
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $imap = $self->{store}->get_client();

    my $using = [
        'urn:ietf:params:jmap:core',
        'urn:ietf:params:jmap:mail',
        'urn:ietf:params:jmap:submission',
        'https://cyrusimap.org/ns/jmap/mail',
        'https://cyrusimap.org/ns/jmap/quota',
        'https://cyrusimap.org/ns/jmap/debug',
        'https://cyrusimap.org/ns/jmap/performance',
    ];

    my $res = $jmap->CallMethods([
        ['Mailbox/get', {
            properties => ['name'],
        }, "R1"]
    ], $using);
    my $inbox = $res->[0][1]{list}[0]{id};
    $self->assert_not_null($inbox);

    xlog $self, "create emails";
    my %emails = (
        'allthread1' => {
            subject => 'allthread',
            keywords => {
                '$flagged' => JSON::true,
            },
            messageId => ['allthread@local'],
        },
        'allthread2' => {
            subject => 're: allthread',
            keywords => {
                '$flagged' => JSON::true,
            },
            references => ['allthread@local'],
        },
        'somethread1' => {
            subject => 'somethread',
            keywords => {
                '$flagged' => JSON::true,
            },
            messageId => ['somethread@local'],
        },
        'somethread2' => {
            subject => 're: somethread',
            references => ['somethread@local'],
        },
        'nonethread1' => {
            subject => 'nonethread',
            messageId => ['nonethread@local'],
        },
        'nonethread2' => {
            subject => 're: nonethread',
            references => ['nonethread@local'],
        },
    );

    while (my ($key, $val) = each %emails) {
        my $email = {
            mailboxIds => {
                $inbox => JSON::true,
            },
            from => [{
                    name => '', email => 'from@local'
                }],
            to => [{
                    name => '', email => 'to@local'
                }],
            bodyStructure => {
                type => 'text/plain',
                partId => 'part1',
            },
            bodyValues => {
                part1 => {
                    value => 'test',
                }
            },
        };
        $email = { %$email, %$val };
        $res = $jmap->CallMethods([
            ['Email/set', {
                create => {
                    $key => $email,
                },
            }, 'R1'],
        ], $using);
        $self->assert_not_null($res->[0][1]->{created}{$key}{id});
        $val->{id} = $res->[0][1]->{created}{$key}{id};
        $self->assert_not_null($res->[0][1]->{created}{$key}{threadId});
        $val->{threadId} = $res->[0][1]->{created}{$key}{threadId};
    }

    xlog $self, "run squatter";
    $self->{instance}->run_command({cyrus => 1}, 'squatter');

    xlog "Running query with guidsearch";
    $res = $jmap->CallMethods([
        ['Email/query', {
            filter => {
                body => 'test',
                allInThreadHaveKeyword => '$flagged',
            },
            sort => [{
                property => 'id',
            }],
        }, 'R1'],
        ['Email/query', {
            filter => {
                body => 'test',
                someInThreadHaveKeyword => '$flagged',
            },
            sort => [{
                property => 'id',
            }],
        }, 'R2'],
        ['Email/query', {
            filter => {
                body => 'test',
                noneInThreadHaveKeyword => '$flagged',
            },
            sort => [{
                property => 'id',
            }],
        }, 'R3'],
    ], $using);

    $self->assert_equals(JSON::true, $res->[0][1]{performance}{details}{isGuidSearch});
    my @wantIds = sort $emails{allthread1}{id}, $emails{allthread2}{id};
    $self->assert_deep_equals(\@wantIds, $res->[0][1]{ids});

    $self->assert_equals(JSON::true, $res->[1][1]{performance}{details}{isGuidSearch});
    @wantIds = sort $emails{somethread1}{id}, $emails{somethread2}{id},
                    $emails{allthread1}{id}, $emails{allthread2}{id};
    $self->assert_deep_equals(\@wantIds, $res->[1][1]{ids});

    $self->assert_equals(JSON::true, $res->[2][1]{performance}{details}{isGuidSearch});
    @wantIds = sort ($emails{nonethread1}{id}, $emails{nonethread2}{id});
    $self->assert_deep_equals(\@wantIds, $res->[2][1]{ids});
}

sub test_email_query_highpriority
    :min_version_3_3 :needs_component_jmap :JMAPExtensions
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $imap = $self->{store}->get_client();

    xlog "Append emails with and without priority";
    $self->make_message("msg1",
        extra_headers => [['x-priority', '1']],
        body => "msg1"
    ) || die;
    $self->make_message("msg2",
        extra_headers => [['importance', 'high']],
        body => "msg2"
    ) || die;
    $self->make_message("msg3",
        body => "msg3"
    ) || die;

    xlog "Run squatter";
    $self->{instance}->run_command({cyrus => 1}, 'squatter', '-Z');

    my $using = [
        'urn:ietf:params:jmap:core',
        'urn:ietf:params:jmap:mail',
        'urn:ietf:params:jmap:submission',
        'https://cyrusimap.org/ns/jmap/mail',
        'https://cyrusimap.org/ns/jmap/debug',
        'https://cyrusimap.org/ns/jmap/performance',
    ];

    my $res = $jmap->CallMethods([
        ['Email/query', {
            sort => [{
                property => 'subject',
            }],
        }, 'R1'],
    ], $using);
    my @ids = @{$res->[0][1]{ids}};
    $self->assert_num_equals(3, scalar @ids);

    xlog "Query isHighPriority";
    $res = $jmap->CallMethods([
        ['Email/query', {
            filter => {
                isHighPriority => JSON::true,
            },
            sort => [{
                property => 'subject',
            }],
        }, 'R1'],
        ['Email/query', {
            filter => {
                operator => 'NOT',
                conditions => [{
                    isHighPriority => JSON::true,
                }],
            },
            sort => [{
                property => 'subject',
            }],
        }, 'R2'],
        ['Email/query', {
            filter => {
                isHighPriority => JSON::false,
            },
            sort => [{
                property => 'subject',
            }],
        }, 'R3'],
    ], $using);
    $self->assert_deep_equals([$ids[0], $ids[1]], $res->[0][1]{ids});
    $self->assert_deep_equals([$ids[2]], $res->[1][1]{ids});
    $self->assert_deep_equals([$ids[2]], $res->[2][1]{ids});
}

sub test_email_query_listid
    :min_version_3_3 :needs_component_jmap :JMAPExtensions
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $imap = $self->{store}->get_client();

    xlog "Append emails with list-id";
    $self->make_message("msg1", # RFC 2919
        extra_headers => [['list-id', "Foo <xxx.y\tyy. ZZZ>"]],
        body => "msg1"
    ) || die;
    $self->make_message("msg2", # as seen at Yahoo, Google, et al
        extra_headers => [['list-id', 'list aaa@bbb.ccc; contact aaa-contact@bbb.ccc']],
        body => "msg2"
    ) || die;
    $self->make_message("msg3", # as seen from sentry, just plain text
        extra_headers => [['list-id', 'sub3.sub2.sub1.top']],
        body => "msg3"
    ) || die;
    $self->make_message("msg4", # as seen in the wild
        extra_headers => [['list-id', '"<b>foo</b>" <xxx.yyy.zzz']],
        body => "msg4"
    ) || die;
    $self->make_message("msg5", # as seen in the wild
        extra_headers => [['list-id', '1234567890 list <xxx.yyy.zzz']],
        body => "msg5"
    ) || die;

    xlog "Run squatter";
    $self->{instance}->run_command({cyrus => 1}, 'squatter', '-Z');

    my $using = [
        'urn:ietf:params:jmap:core',
        'urn:ietf:params:jmap:mail',
        'urn:ietf:params:jmap:submission',
        'https://cyrusimap.org/ns/jmap/mail',
        'https://cyrusimap.org/ns/jmap/debug',
        'https://cyrusimap.org/ns/jmap/performance',
    ];

    my $res = $jmap->CallMethods([
        ['Email/query', {
            sort => [{
                property => 'subject',
            }],
        }, 'R1'],
    ], $using);
    my @ids = @{$res->[0][1]{ids}};
    $self->assert_num_equals(5, scalar @ids);

    my @testCases = ({
        desc => 'simple list-id',
        listId => 'xxx.yyy.zzz',
        wantIds => [$ids[0], $ids[3], $ids[4]],
    }, {
        desc => 'no substring search for list-id',
        listId => 'yyy',
        wantIds => [],
    }, {
        desc => 'no wildcard search for list-id',
        listId => 'xxx.yyy.*',
        wantIds => [],
    }, {
        desc => 'no substring search for list-id #2',
        listId => 'foo',
        wantIds => [],
    }, {
        desc => 'ignore whitespace',
        listId => 'xxx . yyy . zzz',
        wantIds => [$ids[0], $ids[3], $ids[4]],
    }, {
        desc => 'Groups-style list-id',
        listId => 'aaa@bbb.ccc',
        wantIds => [$ids[1]],
    }, {
        desc => 'Ignore contact in groups-style list-id',
        listId => 'aaa-contact@bbb.ccc',
        wantIds => [],
    }, {
        desc => 'Groups-style list-id with whitespace',
        listId => 'aaa @ bbb . ccc',
        wantIds => [$ids[1]],
    }, {
        desc => 'Also no substring search in groups-style list-id',
        listId => 'aaa',
        wantIds => [],
    }, {
        desc => 'unbracketed list-id',
        listId => 'sub3.sub2.sub1.top',
        wantIds => [$ids[2]],
    });

    foreach (@testCases) {
        $res = $jmap->CallMethods([
            ['Email/query', {
                filter => {
                    listId => $_->{listId},
                },
                sort => [{ property => 'subject' }],
            }, 'R1'],
        ], $using);
        $self->assert_deep_equals($_->{wantIds}, $res->[0][1]{ids});
    }
}

sub test_email_query_emailaddress
    :min_version_3_3 :needs_component_jmap :JMAPExtensions
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $imap = $self->{store}->get_client();

    xlog "Append emails";
    $self->make_message("msg1",
        from => Cassandane::Address->new(
            localpart => 'from',
            domain => 'local',
        ),
        to => Cassandane::Address->new(
            name => "Jon Doe",
            localpart => "foo.bar",
            domain => "xxx.example.com"
        ),
        body => "msg1"
    ) || die;
    $self->make_message("msg2",
        from => Cassandane::Address->new(
            localpart => 'from',
            domain => 'local',
        ),
        to => Cassandane::Address->new(
            name => "Jane Doe",
            localpart => "foo.baz+bla",
            domain => "yyy.example.com"
        ),
        body => "msg2"
    ) || die;
    $self->make_message("msg3",
        from => Cassandane::Address->new(
            localpart => 'from',
            domain => 'local',
        ),
        to => Cassandane::Address->new(
            localpart => '"tu x"',
            domain => "example.com"
        ),
        body => "msg3"
    ) || die;
    my $raw = <<'EOF';
From: <from@local>
To: toa@example.com, RecipientB <tob@example.com>
Subject: msg4
Date: Mon, 13 Apr 2020 15:34:03 +0200
MIME-Version: 1.0
Content-Type: text/plain

msg4
EOF
    $raw =~ s/\r?\n/\r\n/gs;
    $imap->append('INBOX', $raw) || die $@;

    xlog "Run squatter";
    $self->{instance}->run_command({cyrus => 1}, 'squatter', '-Z');

    my $using = [
        'urn:ietf:params:jmap:core',
        'urn:ietf:params:jmap:mail',
        'urn:ietf:params:jmap:submission',
        'https://cyrusimap.org/ns/jmap/mail',
        'https://cyrusimap.org/ns/jmap/debug',
        'https://cyrusimap.org/ns/jmap/performance',
    ];

    my $res = $jmap->CallMethods([
        ['Email/query', {
            sort => [{
                property => 'subject',
            }],
        }, 'R1'],

    ], $using);
    my @ids = @{$res->[0][1]{ids}};
    $self->assert_num_equals(4, scalar @ids);

    my @tests = ({
        to => '@xxx.example.com',
        wantIds => [$ids[0]],
    }, {
        to => '@*.example.com',
        wantIds => [$ids[0], $ids[1]],
    }, {
        to => '@*example.com',
        wantIds => [$ids[0], $ids[1], $ids[2], $ids[3]],
    }, {
        to => 'foo*@*example.com',
        wantIds => [$ids[0], $ids[1]],
    }, {
        to => 'foo.bar@*.com',
        wantIds => [$ids[0]],
    }, {
        to => 'foo.baz+*@yyy.example.com',
        wantIds => [$ids[1]],
    }, {
        to => 'foo.baz+bla@yyy.example.com',
        wantIds => [$ids[1]],
    }, {
        to => 'foo*@*example.com',
        wantIds => [$ids[0], $ids[1]],
    }, {
        to => 'foo.bar@',
        wantIds => [$ids[0]],
    }, {
        to => 'foo.ba*@',
        wantIds => [$ids[0], $ids[1]],
    }, {
        to => 'doe',
        wantIds => [$ids[0], $ids[1]],
    }, {
        to => 'jane doe',
        wantIds => [$ids[1]],
    }, {
        to => 'foo* example',
        wantIds => [$ids[0], $ids[1]],
    }, {
        to => 'foo* yyy',
        wantIds => [$ids[1]],
    }, {
        to => 'example.com',
        wantIds => [$ids[0], $ids[1], $ids[2], $ids[3]],
    }, {
        to => '"tu x"@example.com',
        wantIds => [$ids[2]],
    }, {
        to => 'tux@example.com',
        wantIds => [],
    }, {
        to => 'Jane Doe <foo.baz+bla@yyy.example.com>',
        wantIds => [$ids[1]],
    }, {
        to => 'Doe <foo*@*example.com>',
        wantIds => [$ids[0], $ids[1]],
    }, {
        to => 'tob@example.com',
        wantIds => [$ids[3]],
    });

    foreach (@tests) {
        $res = $jmap->CallMethods([
            ['Email/query', {
                filter => {
                    to => $_->{to},
                },
                sort => [{
                    property => 'subject',
                }],
            }, 'R1'],
        ]);
        $self->assert_deep_equals($_->{wantIds}, $res->[0][1]{ids});
    }
}

sub test_email_import_issue3122
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $file = abs_path('data/mime/msg1.eml');
    open(FH, "<$file");
    local $/ = undef;
    my $binary = <FH>;
    close(FH);
    my $data = $jmap->Upload($binary, "message/rfc822");
    my $blobId = $data->{blobId};

    # Not crashing here is enough.

    my $res = $jmap->CallMethods([
		['Email/import', {
			emails => {
				"1" => {
					blobId => $blobId,
					mailboxIds => {
						'$inbox' =>  JSON::true},
				},
			},
		}, "R1"]
	]);
}

sub test_email_query_unicodefdfx
    :min_version_3_3 :needs_component_jmap :SearchLanguage
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    # Unicode block FDFX for Arabic contains some code points that
    # make Cyrus search form blow up the stem word length over the
    # allowed limit of 200 bytes. This test asserts that Cyrus doesn't
    # choke on these and still indexes the unstemmed form.

    my $file = abs_path('data/mime/unicodefdfx.eml');
    open(FH, "<$file");
    local $/ = undef;
    my $binary = <FH>;
    close(FH);
    my $data = $jmap->Upload($binary, "message/rfc822");
    my $blobId = $data->{blobId};

    my $res = $jmap->CallMethods([
		['Email/import', {
			emails => {
				"1" => {
					blobId => $blobId,
					mailboxIds => {
						'$inbox' =>  JSON::true},
				},
			},
		}, "R1"]
	]);
    $self->assert_not_null($res->[0][1]{created}{1});

    xlog $self, "run squatter";
    $self->{instance}->run_command({cyrus => 1}, 'squatter');

    # As seen in the wild: multiple U+FDFA codepoints without separating
    # spaces. The unstemmed form in UTF-8 is about 30 bytes long, but
    # the stemmed term in Cyrus search form is 270 bytes long.

    $res = $jmap->CallMethods([
        ['Email/query', {
            filter => {
                body => "" .
                    "\N{ARABIC LIGATURE SALLALLAHOU ALAYHE WASALLAM}" .
                    "\N{ARABIC LIGATURE SALLALLAHOU ALAYHE WASALLAM}" .
                    "\N{ARABIC LIGATURE SALLALLAHOU ALAYHE WASALLAM}" .
                    "\N{ARABIC LIGATURE SALLALLAHOU ALAYHE WASALLAM}" .
                    "\N{ARABIC LIGATURE SALLALLAHOU ALAYHE WASALLAM}" .
                    "\N{ARABIC LIGATURE SALLALLAHOU ALAYHE WASALLAM}" .
                    "\N{ARABIC LIGATURE SALLALLAHOU ALAYHE WASALLAM}" .
                    "\N{ARABIC LIGATURE SALLALLAHOU ALAYHE WASALLAM}" .
                    "\N{ARABIC LIGATURE SALLALLAHOU ALAYHE WASALLAM}",
            },
        }, 'R1']
    ]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]{ids}});
}

sub test_email_parse_embedded_toplevel
    :min_version_3_3 :needs_component_jmap
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $res = $jmap->CallMethods([
        ['Email/set', {
            create => {
                1 => {
                    mailboxIds => {
                        '$inbox' => JSON::true,
                    },
                    subject => 'test1',
                    bodyStructure => {
                        type => 'text/plain',
                        partId => 'part1',
                    },
                    bodyValues => {
                        part1 => {
                            value => 'A text body',
                        },
                    },
                },
            },
        }, 'R1'],
    ]);
    my $blobId = $res->[0][1]{created}{1}{blobId};
    $self->assert_not_null($blobId);

    $res = $jmap->CallMethods([
        ['Email/set', {
            create => {
                2 => {
                    mailboxIds => {
                        '$inbox' => JSON::true,
                    },
                    subject => 'test2',
                    bodyStructure => {
                        subParts => [{
                            type => 'text/plain',
                            partId => 'part1',
                        }, {
                            type => 'message/rfc822',
                            blobId => $blobId,
                        }],
                    },
                    bodyValues => {
                        part1 => {
                            value => 'A text body',
                        },
                    },
                },
            },
        }, 'R1'],
        ['Email/get', {
            ids => ['#2'],
            properties => ['bodyStructure'],
            bodyProperties => ['blobId'],
        }, 'R2'],
    ]);
    $self->assert_not_null($res->[0][1]{created}{2});
    $self->assert_str_equals($blobId,
        $res->[1][1]{list}[0]{bodyStructure}{subParts}[1]{blobId});

    $res = $jmap->CallMethods([
        ['Email/parse', {
            blobIds => [ $blobId ],
            properties => ['blobId'],
        }, 'R1'],
    ]);
    $self->assert_str_equals($blobId, $res->[0][1]{parsed}{$blobId}{blobId});
}

sub test_searchsnippet_get_attachments
    :min_version_3_5 :needs_component_jmap :SearchAttachmentExtractor :JMAPExtensions
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $imap = $self->{store}->get_client();
    my $instance = $self->{instance};

    my $uri = URI->new($instance->{config}->get('search_attachment_extractor_url'));

    # Start a dummy extractor server.
    my $handler = sub {
        my ($conn, $req) = @_;
        if ($req->method eq 'HEAD') {
            my $res = HTTP::Response->new(204);
            $res->content("");
            $conn->send_response($res);
        } else {
            my $res = HTTP::Response->new(200);
            $res->header("Keep-Alive" => "timeout=1");  # Force client timeout
            $res->content("attachment body");
            $conn->send_response($res);
        }
    };
    $instance->start_httpd($handler, $uri->port());

    my $rawMessage = <<'EOF';
From: <from@local>
To: to@local
Reply-To: replyto@local
Subject: test
Date: Mon, 13 Apr 2020 15:34:03 +0200
MIME-Version: 1.0
Content-Type: multipart/mixed;
 boundary=6c3338934661485f87537c19b5f9d933

--6c3338934661485f87537c19b5f9d933
Content-Type: text/plain

text body

--6c3338934661485f87537c19b5f9d933
Content-Type: image/jpg
Content-Disposition: attachment; filename="November.jpg"
Content-Transfer-Encoding: base64

ZGF0YQ==

--6c3338934661485f87537c19b5f9d933
Content-Type: application/pdf
Content-Disposition: attachment; filename="December.pdf"
Content-Transfer-Encoding: base64

ZGF0YQ==

--6c3338934661485f87537c19b5f9d933--
EOF
    $rawMessage =~ s/\r?\n/\r\n/gs;
    $imap->append('INBOX', $rawMessage) || die $@;

    xlog $self, "run squatter";
    $self->{instance}->run_command({cyrus => 1}, 'squatter');

    my $using = [
        'urn:ietf:params:jmap:core',
        'urn:ietf:params:jmap:mail',
        'https://cyrusimap.org/ns/jmap/mail',
    ];

    my $res = $jmap->CallMethods([
        ['Email/query', {
            filter => {
                text => 'December',
            },
            findMatchingParts => JSON::true,
        }, 'R1'],
        ['SearchSnippet/get', {
            '#emailIds' => {
                resultOf => 'R1',
                name => 'Email/query',
                path => '/ids',
            },
            '#partIds' => {
                resultOf => 'R1',
                name => 'Email/query',
                path => '/partIds',
            },
            '#filter' => {
                resultOf => 'R1',
                name => 'Email/query',
                path => '/filter',
            },
        }, 'R2'],
    ], $using);

    $self->assert_not_null($res->[1][1]{list}[0]);
    $self->assert_null($res->[1][1]{list}[0]{preview});

    my $matches = $res->[1][1]{list}[0]{attachments};
    $self->assert_num_equals(1, scalar keys %{$matches});
    $self->assert_not_null($matches->{3}{blobId});
    delete($matches->{3}{blobId});

    $self->assert_deep_equals({
        3 => {
            name => '<mark>December</mark>.pdf',
            type => 'application/pdf',
        },
    }, $matches);

    $res = $jmap->CallMethods([
        ['Email/query', {
            filter => {
                text => 'body',
            },
            findMatchingParts => JSON::true,
        }, 'R1'],
        ['SearchSnippet/get', {
            '#emailIds' => {
                resultOf => 'R1',
                name => 'Email/query',
                path => '/ids',
            },
            '#partIds' => {
                resultOf => 'R1',
                name => 'Email/query',
                path => '/partIds',
            },
            '#filter' => {
                resultOf => 'R1',
                name => 'Email/query',
                path => '/filter',
            },
        }, 'R2'],
    ], $using);

    $self->assert_not_null($res->[1][1]{list}[0]);
    $self->assert_not_null($res->[1][1]{list}[0]{preview});

    $matches = $res->[1][1]{list}[0]{attachments};
    $self->assert_num_equals(2, scalar keys %{$matches});
    $self->assert_not_null($matches->{2}{blobId});
    delete($matches->{2}{blobId});
    $self->assert_not_null($matches->{3}{blobId});
    delete($matches->{3}{blobId});

    $self->assert_deep_equals({
        2 => {
            name => 'November.jpg',
            type => 'image/jpg',
        },
        3 => {
            name => 'December.pdf',
            type => 'application/pdf',
        },
    }, $matches);

    $res = $jmap->CallMethods([
        ['Email/query', {
            filter => {
                text => 'body',
            },
            findMatchingParts => JSON::false,
        }, 'R1'],
        ['SearchSnippet/get', {
            '#emailIds' => {
                resultOf => 'R1',
                name => 'Email/query',
                path => '/ids',
            },
            '#filter' => {
                resultOf => 'R1',
                name => 'Email/query',
                path => '/filter',
            },
        }, 'R2'],
    ], $using);
    $self->assert_not_null($res->[1][1]{list}[0]);
    $self->assert_null($res->[1][1]{list}[0]{attachments});
}

sub test_email_query_header
    :min_version_3_5 :needs_component_jmap :JMAPExtensions :NoMunge8Bit :RFC2047_UTF8
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $imap = $self->{store}->get_client();

use utf8;

    $self->make_message("xhdr1",
        extra_headers => [['X-hdr', 'val1'], ['X-hdr', 'val2']],
        body => "xhdr1"
    ) || die;
    $self->make_message("xhdr2",
        extra_headers => [['X-hdr', 'val1']],
        body => "xhdr2"
    ) || die;
    $self->make_message("xhdr3",
        extra_headers => [['X-hdr', " s\xc3\xa4ge   "]],
        body => "xhdr3"
    ) || die;
    $self->make_message("subject1",
        body => "subject1"
    ) || die;

    xlog "Run squatter";
    $self->{instance}->run_command({cyrus => 1}, 'squatter', '-Z');

    my $res = $jmap->CallMethods([
        ['Email/query', {
        }, 'R1'],
        ['Email/get', {
            '#ids' => {
                resultOf => 'R1',
                name => 'Email/query',
                path => '/ids'
            },
            properties => [ 'subject' ],
        }, 'R2'],
    ]);
    my %id = map { $_->{subject} => $_->{id} } @{$res->[1][1]{list}};

    my @testCases = ({
        desc => 'xhdr equals',
        header => ['x-hdr', 'val2', 'equals'],
        wantIds => [$id{'xhdr1'}],
    }, {
        desc => 'xhdr startsWith',
        header => ['x-hdr', 'val', 'startsWith'],
        wantIds => [$id{'xhdr1'}, $id{'xhdr2'}],
    }, {
        desc => 'xhdr endsWith',
        header => ['x-hdr', 'al1', 'endsWith'],
        wantIds => [$id{'xhdr1'}, $id{'xhdr2'}],
    }, {
        desc => 'xhdr contains',
        header => ['x-hdr', 'al', 'contains'],
        wantIds => [$id{'xhdr1'}, $id{'xhdr2'}],
    }, {
        desc => 'xhdr contains utf8 value',
        header => ['x-hdr', 'SaGE', 'contains'],
        wantIds => [$id{'xhdr3'}],
    }, {
        desc => 'subject contains ASCII',
        header => ['subject', 'ubjec', 'contains'],
        wantIds => [$id{'subject1'}],
    });

    foreach (@testCases) {
        xlog "Running test: $_->{desc}";
        $res = $jmap->CallMethods([
            ['Email/query', {
                filter => {
                    header => $_->{header},
                },
                sort => [{ property => 'subject' }],
            }, 'R1'],
        ]);
        $self->assert_deep_equals($_->{wantIds}, $res->[0][1]{ids});
    }

no utf8;
}

sub test_email_query_header_cost
    :min_version_3_5 :needs_component_jmap :JMAPExtensions :NoMunge8Bit :RFC2047_UTF8
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $imap = $self->{store}->get_client();

    $self->make_message() || die;

    xlog "Run squatter";
    $self->{instance}->run_command({cyrus => 1}, 'squatter', '-Z');

    my $using = [
        'urn:ietf:params:jmap:core',
        'urn:ietf:params:jmap:mail',
        'urn:ietf:params:jmap:submission',
        'https://cyrusimap.org/ns/jmap/mail',
        'https://cyrusimap.org/ns/jmap/debug',
        'https://cyrusimap.org/ns/jmap/performance',
    ];

    my $res = $jmap->CallMethods([
        ['Email/query', {
            filter => {
                header => ['x-hdr', 'foo', 'contains'],
            },
        }, 'R1'],
        ['Email/query', {
            filter => {
                header => ['subject', 'foo', 'contains'],
            },
        }, 'R2'],
    ], $using);
    $self->assert_deep_equals(['body'],
        $res->[0][1]{performance}{details}{filters});
    $self->assert_deep_equals(['cache'],
        $res->[1][1]{performance}{details}{filters});
}

sub test_email_query_header_sieve
    :min_version_3_5 :needs_component_jmap :JMAPExtensions :AltNamespace
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $imap = $self->{store}->get_client();

    $imap->create("matches") or die;

    $self->{instance}->install_sieve_script(<<'EOF'
require ["x-cyrus-jmapquery", "x-cyrus-log", "variables", "fileinto"];
if
  allof( not string :is "${stop}" "Y",
    jmapquery text:
  {
    "header" : [ "subject", "zzz", "endsWith" ]
  }
.
  )
{
  fileinto "matches";
}
EOF
    );

    xlog "Deliver matching message";
    my $msg1 = $self->{gen}->generate(
        subject => 'xxxyyyzzz',
        body => "msg1"
    );
    $self->{instance}->deliver($msg1);

    xlog "Assert that message got moved into INBOX.matches";
    $self->{store}->set_folder('matches');
    $self->check_messages({ 1 => $msg1 }, check_guid => 0);

    xlog $self, "Deliver a non-matching message";
    my $msg2 = $self->{gen}->generate(
        subject => 'zzzyyyyxxx',
        body => "msg2"
    );
    $self->{instance}->deliver($msg2);
    $msg2->set_attribute(uid => 1);

    xlog "Assert that message got moved into INBOX";
    $self->{store}->set_folder('INBOX');
    $self->check_messages({ 1 => $msg2 }, check_guid => 0);
}

sub test_email_query_mailbox_andor
    :min_version_3_5 :needs_component_jmap :JMAPExtensions
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $using = [
        'urn:ietf:params:jmap:core',
        'urn:ietf:params:jmap:mail',
        'urn:ietf:params:jmap:submission',
        'https://cyrusimap.org/ns/jmap/mail',
        'https://cyrusimap.org/ns/jmap/debug',
        'https://cyrusimap.org/ns/jmap/performance',
    ];

    my $res = $jmap->CallMethods([
        ['Mailbox/set', {
            create => {
                mboxA => {
                    name => 'A',
                },
                mboxB => {
                    name => 'B',
                },
                mboxC => {
                    name => 'C',
                },
            }
        }, 'R1'],
        ['Email/set', {
            create => {
                emailAB => {
                    mailboxIds => {
                        '#mboxA' => JSON::true,
                        '#mboxB' => JSON::true,
                    },
                    subject => 'emailAB',
                    bodyStructure => {
                        type => 'text/plain',
                        partId => 'part1',
                    },
                    bodyValues => {
                        part1 => {
                            value => 'emailAB',
                        }
                    },
                },
            },
        }, 'R2'],
    ], $using);
    my $mboxA = $res->[0][1]{created}{mboxA}{id};
    $self->assert_not_null($mboxA);
    my $mboxB = $res->[0][1]{created}{mboxB}{id};
    $self->assert_not_null($mboxB);
    my $mboxC = $res->[0][1]{created}{mboxC}{id};
    $self->assert_not_null($mboxC);
    my $emailId = $res->[1][1]{created}{emailAB}{id};
    $self->assert_not_null($emailId);

    $res = $jmap->CallMethods([
        ['Email/query', {
            filter => {
                operator => 'AND',
                conditions => [{
                    inMailbox => $mboxA,
                }, {
                    operator => 'OR',
                    conditions => [{
                        inMailbox => $mboxB,
                    }, {
                        inMailbox => $mboxC,
                    }],
                }],
            },
        }, 'R1'],
    ], $using);

    $self->assert_deep_equals([$emailId], $res->[0][1]{ids});
    $self->assert_equals(JSON::true,
        $res->[0][1]{performance}{details}{isImapFolderSearch});
}

sub test_email_querychanges_mailbox_or
    :min_version_3_1 :needs_component_jmap :JMAPExtensions
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $using = [
        'urn:ietf:params:jmap:core',
        'urn:ietf:params:jmap:mail',
        'urn:ietf:params:jmap:submission',
        'https://cyrusimap.org/ns/jmap/mail',
        'https://cyrusimap.org/ns/jmap/debug',
        'https://cyrusimap.org/ns/jmap/performance',
    ];

    my $res = $jmap->CallMethods([
        ['Email/set', {
            create => {
                email => {
                    mailboxIds => {
                        '$inbox' => JSON::true,
                    },
                    subject => 'email',
                    bodyStructure => {
                        type => 'text/plain',
                        partId => 'part1',
                    },
                    bodyValues => {
                        part1 => {
                            value => 'email',
                        }
                    },
                },
            },
        }, 'R1'],
        ['Mailbox/query', {
        }, 'R2'],
    ], $using);
    my $emailId = $res->[0][1]{created}{email}{id};
    $self->assert_not_null($emailId);
    my $inboxId = $res->[1][1]{ids}[0];
    $self->assert_not_null($inboxId);

    $res = $jmap->CallMethods([
        ['Email/query', {
            filter => {
                operator => 'OR',
                conditions => [{
                    inMailbox => $inboxId,
                }],
            },
        }, 'R1'],
    ], $using);

    $self->assert_deep_equals([$emailId], $res->[0][1]{ids});
    $self->assert_equals(JSON::true, $res->[0][1]{canCalculateChanges});
    my $queryState = $res->[0][1]{queryState};

    $res = $jmap->CallMethods([
        ['Email/queryChanges', {
            filter => {
                operator => 'OR',
                conditions => [{
                    inMailbox => $inboxId,
                }],
            },
            sinceQueryState => $queryState,
        }, 'R1'],
    ], $using);
    $self->assert_deep_equals([], $res->[0][1]{added});
    $self->assert_deep_equals([], $res->[0][1]{removed});
}

sub test_email_query_dnfcomplexity
    :min_version_3_4 :needs_component_jmap :JMAPExtensions
    :SearchNormalizationMax20000 :SearchMaxTime1Sec
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $imap = $self->{store}->get_client();

    my $using = [
        'urn:ietf:params:jmap:core',
        'urn:ietf:params:jmap:mail',
        'urn:ietf:params:jmap:submission',
        'https://cyrusimap.org/ns/jmap/mail',
        'https://cyrusimap.org/ns/jmap/debug',
        'https://cyrusimap.org/ns/jmap/performance',
    ];

    my $rawMessage = <<'EOF';
From: <from@local>
To: to@local
Reply-To: replyto@local
Subject: test
Date: Mon, 13 Apr 2020 15:34:03 +0200
MIME-Version: 1.0
Content-Type: multipart/mixed;
 boundary=6c3338934661485f87537c19b5f9d933

--6c3338934661485f87537c19b5f9d933
Content-Type: text/plain

text body

--6c3338934661485f87537c19b5f9d933
Content-Type: image/jpg
Content-Disposition: attachment; filename="November.jpg"
Content-Transfer-Encoding: base64

ZGF0YQ==

--6c3338934661485f87537c19b5f9d933
Content-Type: application/pdf
Content-Disposition: attachment; filename="December.pdf"
Content-Transfer-Encoding: base64

ZGF0YQ==

--6c3338934661485f87537c19b5f9d933--
EOF
    $rawMessage =~ s/\r?\n/\r\n/gs;
    $imap->append('INBOX', $rawMessage) || die $@;

    xlog $self, 'run squatter';
    $self->{instance}->run_command({cyrus => 1}, 'squatter');

    my $res = $jmap->CallMethods([
        ['Email/query', {
            position => 0,
            calculateTotal => JSON::false,
            limit => 30,
            findAllInThread => JSON::true,
            collapseThreads => JSON::true,
            sort => [{
                property => 'receivedAt',
                isAscending => JSON::false
            }],
            filter => {
                operator => 'AND',
                conditions => [{
                    hasAttachment => JSON::true
                }, {
                    operator => 'NOT',
                    conditions => [{
                        hasAttachment => JSON::true,
                        attachmentType => 'pdf'
                    }, {
                        hasAttachment => JSON::true,
                        attachmentType => 'presentation'
                    }, {
                        hasAttachment => JSON::true,
                        attachmentType => 'email'
                    }, {
                        hasAttachment => JSON::true,
                        attachmentType => 'spreadsheet'
                    }, {
                        attachmentType => 'document',
                        hasAttachment => JSON::true
                    }, {
                        attachmentType => 'image',
                        hasAttachment => JSON::true
                    }, {
                        attachmentType => 'presentation',
                        hasAttachment => JSON::true
                    }, {
                        attachmentType => 'document',
                        hasAttachment => JSON::true
                    }, {
                        hasAttachment => JSON::true,
                        attachmentType => 'pdf'
                    }],
                }],
            },
        }, 'R0'],
    ], $using);

    $self->assert_str_equals('unsupportedFilter', $res->[0][1]{type});
    $self->assert_str_equals('search too complex', $res->[0][1]{description});
}

sub test_email_query_toplevel_calendar
    :min_version_3_5 :needs_component_jmap :JMAPExtensions
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $imap = $self->{store}->get_client();

    my $using = [
        'urn:ietf:params:jmap:core',
        'urn:ietf:params:jmap:mail',
        'urn:ietf:params:jmap:submission',
        'https://cyrusimap.org/ns/jmap/mail',
        'https://cyrusimap.org/ns/jmap/debug',
        'https://cyrusimap.org/ns/jmap/performance',
    ];

    my $rawMessage = <<'EOF';
From: from@local
To: to@local
Subject: test
Date: Mon, 13 Apr 2020 15:34:03 +0200
MIME-Version: 1.0
Content-Type: text/calendar; charset="UTF-8"

BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.9.5//EN
CALSCALE:GREGORIAN
BEGIN:VEVENT
DTSTART:20160928T160000Z
DTEND:20160928T170000Z
UID:2a358cee-6489-4f14-a57f-c104db4dc357
DTSTAMP:20150928T132434Z
CREATED:20150928T125212Z
SUMMARY:event
ORGANIZER:mailto:organizer@local
ATTENDEE:mailto:attendee@local
LAST-MODIFIED:20150928T132434Z
END:VEVENT
END:VCALENDAR
EOF
    $rawMessage =~ s/\r?\n/\r\n/gs;
    $imap->append('INBOX', $rawMessage) || die $@;

    xlog $self, 'run squatter';
    $self->{instance}->run_command({cyrus => 1}, 'squatter');

    my $res = $jmap->CallMethods([
        ['Email/query', {
            filter => {
                from => 'organizer@local',
            },
        }, 'R1'],
        ['Email/query', {
            filter => {
                to => 'attendee@local',
            },
        }, 'R2'],
        ['Email/query', {
            filter => {
                from => 'from@local',
            },
        }, 'R3'],
        ['Email/query', {
            filter => {
                to => 'to@local',
            },
        }, 'R4'],
    ], $using);
    $self->assert_num_equals(1, scalar @{$res->[0][1]{ids}});
    $self->assert_num_equals(1, scalar @{$res->[1][1]{ids}});
    $self->assert_num_equals(1, scalar @{$res->[2][1]{ids}});
    $self->assert_num_equals(1, scalar @{$res->[3][1]{ids}});
}

sub test_email_query_toplevel_calendar_sieve
    :min_version_3_5 :needs_component_jmap :JMAPExtensions :needs_component_sieve
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $imap = $self->{store}->get_client();

    $imap->create("INBOX.matches") or die;
    $self->{instance}->install_sieve_script(<<'EOF'
require ["x-cyrus-jmapquery", "x-cyrus-log", "variables", "fileinto"];
if
  allof( not string :is "${stop}" "Y",
    jmapquery text:
  {
      "from" : "from@local"
  }
.
  )
{
  fileinto "INBOX.matches";
}
EOF
    );

    my $rawMessage = <<'EOF';
From: from@local
To: to@local
Subject: test
Date: Mon, 13 Apr 2020 15:34:03 +0200
MIME-Version: 1.0
Content-Type: text/calendar; charset="UTF-8"

BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Apple Inc.//Mac OS X 10.9.5//EN
CALSCALE:GREGORIAN
BEGIN:VEVENT
DTSTART:20160928T160000Z
DTEND:20160928T170000Z
UID:2a358cee-6489-4f14-a57f-c104db4dc357
DTSTAMP:20150928T132434Z
CREATED:20150928T125212Z
SUMMARY:event
ORGANIZER:mailto:organizer@local
ATTENDEE:mailto:attendee@local
LAST-MODIFIED:20150928T132434Z
END:VEVENT
END:VCALENDAR
EOF
    $rawMessage =~ s/\r?\n/\r\n/gs;

    my $msg = Cassandane::Message->new();
    $msg->set_lines(split /\n/, $rawMessage);
    $self->{instance}->deliver($msg);
    $self->assert_num_equals(1, $imap->message_count('INBOX.matches'));
}

sub test_email_query_fix_multiple_recipients
    :min_version_3_4 :needs_component_jmap :JMAPExtensions
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $imap = $self->{store}->get_client();

    my $using = [
        'urn:ietf:params:jmap:core',
        'urn:ietf:params:jmap:mail',
        'urn:ietf:params:jmap:submission',
        'https://cyrusimap.org/ns/jmap/mail',
        'https://cyrusimap.org/ns/jmap/debug',
        'https://cyrusimap.org/ns/jmap/performance',
    ];

    my $rawMessage = <<'EOF';
From: from@local
To: unquoted@local, "quot@ed" <quoted@local>
Subject: test
Date: Mon, 13 Apr 2020 15:34:03 +0200
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"

test
EOF
    $rawMessage =~ s/\r?\n/\r\n/gs;
    $imap->append('INBOX', $rawMessage) || die $@;

    $self->{instance}->run_command({cyrus => 1}, 'squatter');

    my $res = $jmap->CallMethods([
        ['Email/query', {
            filter => {
                to => 'unquoted@local',
            },
        }, 'R1'],
    ]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]{ids}});
}

sub test_email_set_update_no_id
    :min_version_3_4 :needs_component_jmap :JMAPExtensions
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $res = $jmap->CallMethods([
        ['Email/set', {
            create => {
                email => {
                    mailboxIds => {
                        '$inbox' => JSON::true,
                    },
                    subject => 'email',
                    bodyStructure => {
                        type => 'text/plain',
                        partId => 'part1',
                    },
                    bodyValues => {
                        part1 => {
                            value => 'email',
                        }
                    },
                },
            },
        }, 'R1'],
    ]);
    my $emailId = $res->[0][1]{created}{email}{id};
    $self->assert_not_null($emailId);

    $res = $jmap->CallMethods([
        ['Email/set', {
            update => {
                $emailId => {
                    keywords => {
                        'foo' => JSON::true,
                    },
                },
            },
        }, 'R1'],
    ]);
    $self->assert_equals(undef, $res->[0][1]{updated}{$emailId});

}

sub test_email_query_guidsearch_mixedfilter2
    :min_version_3_4 :needs_component_jmap :JMAPExtensions
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $using = [
        'urn:ietf:params:jmap:core',
        'urn:ietf:params:jmap:mail',
        'urn:ietf:params:jmap:submission',
        'https://cyrusimap.org/ns/jmap/mail',
        'https://cyrusimap.org/ns/jmap/debug',
        'https://cyrusimap.org/ns/jmap/performance',
    ];

    my $res = $jmap->CallMethods([
        ['Mailbox/get', {
            properties => ['id'],
        }, 'R1'],
        ['Mailbox/set', {
            create => {
                mboxA => {
                    name => 'A',
                },
                mboxB => {
                    name => 'B',
                },
            }
        }, 'R2'],
    ], $using);
    my $inbox = $res->[0][1]{list}[0]{id};
    $self->assert_not_null($inbox);
    my $mboxA = $res->[1][1]{created}{mboxA}{id};
    $self->assert_not_null($mboxA);
    my $mboxB = $res->[1][1]{created}{mboxB}{id};
    $self->assert_not_null($mboxB);

    $res = $jmap->CallMethods([
        ['Email/set', {
            create => {
                emailA => {
                    mailboxIds => {
                        $mboxA => JSON::true,
                    },
                    subject => 'emailA',
                    from => [{
                        email => 'fromA@local'
                    }] ,
                    to => [{
                        email => 'toA@local'
                    }] ,
                    bodyStructure => {
                        type => 'text/plain',
                        partId => 'part1',
                    },
                    bodyValues => {
                        part1 => {
                            value => 'emailA',
                        }
                    },
                },
                emailB => {
                    mailboxIds => {
                        $mboxB => JSON::true,
                    },
                    subject => 'emailB',
                    from => [{
                        email => 'fromB@local'
                    }] ,
                    to => [{
                        email => 'toB@local'
                    }] ,
                    cc => [{
                        email => 'ccB@local'
                    }] ,
                    bodyStructure => {
                        type => 'text/plain',
                        partId => 'part1',
                    },
                    bodyValues => {
                        part1 => {
                            value => 'emailB',
                        }
                    },
                },
                emailX => {
                    mailboxIds => {
                        $inbox => JSON::true,
                    },
                    subject => 'emailX',
                    from => [{
                        email => 'fromA@local'
                    }] ,
                    to => [{
                        email => 'toB@local'
                    }] ,
                    bodyStructure => {
                        type => 'text/plain',
                        partId => 'part1',
                    },
                    bodyValues => {
                        part1 => {
                            value => 'emailX',
                        }
                    },
                },
            },
        }, 'R1'],
    ], $using);
    my $emailA = $res->[0][1]{created}{emailA}{id};
    $self->assert_not_null($emailA);
    my $emailB = $res->[0][1]{created}{emailB}{id};
    $self->assert_not_null($emailB);
    my $emailX = $res->[0][1]{created}{emailX}{id};
    $self->assert_not_null($emailX);

    $self->{instance}->run_command({cyrus => 1}, 'squatter');

    $res = $jmap->CallMethods([
        ['Email/query', {
            filter => {
                'operator' => 'AND',
                'conditions' => [
                    {
                        'operator' => 'OR',
                        'conditions' => [
                            {
                                'from' => 'fromA@local',
                            },
                            {
                                'operator' => 'AND',
                                'conditions' => [
                                    {
                                        'inMailbox' => $mboxB,
                                    },
                                    {
                                        'operator' => 'OR',
                                        'conditions' => [
                                            {
                                                'to' => 'toB@local'
                                            },
                                            {
                                                'cc' => 'ccB@local'
                                            },
                                            {
                                                'bcc' => 'bccB@local'
                                            },
                                            {
                                                'deliveredTo' => 'deliveredToB@local'
                                            }
                                        ]
                                    }
                                ]
                            }
                        ]
                    },
                    {
                        'inMailboxOtherThan' => [
                            $inbox
                        ]
                    }
                ]
            },
            sort => [{ property => 'id' }],
        }, 'R1'],
    ], $using);

    # All DNF-clauses of a guidsearch query with Xapian and non-Xapian criteria
    # must contain the same non-Xapian criteria.
    # This might change in the future.
    $self->assert_equals(JSON::false, $res->[0][1]{performance}{details}{isGuidSearch});
    my @wantIds = sort ( $emailA, $emailB );
    $self->assert_deep_equals(\@wantIds, $res->[0][1]{ids});
}

sub test_email_set_update_mailboxids_nonempty
    :min_version_3_4 :needs_component_jmap :JMAPExtensions
{
    my ($self) = @_;
    my $jmap = $self->{jmap};

    my $using = [
        'urn:ietf:params:jmap:core',
        'urn:ietf:params:jmap:mail',
        'urn:ietf:params:jmap:submission',
        'https://cyrusimap.org/ns/jmap/mail',
        'https://cyrusimap.org/ns/jmap/debug',
        'https://cyrusimap.org/ns/jmap/performance',
    ];

    my $res = $jmap->CallMethods([
        ['Mailbox/get', {
            properties => ['id'],
        }, 'R1'],
        ['Mailbox/set', {
            create => {
                mboxA => {
                    name => 'A',
                },
                mboxB => {
                    name => 'B',
                },
            }
        }, 'R2'],
    ], $using);
    my $inbox = $res->[0][1]{list}[0]{id};
    $self->assert_not_null($inbox);
    my $mboxA = $res->[1][1]{created}{mboxA}{id};
    $self->assert_not_null($mboxA);
    my $mboxB = $res->[1][1]{created}{mboxB}{id};
    $self->assert_not_null($mboxB);

    $res = $jmap->CallMethods([
        ['Email/set', {
            create => {
                email => {
                    mailboxIds => {
                        $mboxA => JSON::true,
                        $mboxB => JSON::true,
                    },
                    subject => 'test',
                    from => [{
                        email => 'from@local'
                    }] ,
                    to => [{
                        email => 'to@local'
                    }] ,
                    bodyStructure => {
                        type => 'text/plain',
                        partId => 'part1',
                    },
                    bodyValues => {
                        part1 => {
                            value => 'email',
                        }
                    },
                },
            },
        }, 'R1'],
        ['Email/get', {
            ids => ['#email'],
            properties => ['mailboxIds'],
        }, 'R2'],
    ], $using);
    my $emailId = $res->[0][1]{created}{email}{id};
    $self->assert_not_null($emailId);

    $res = $jmap->CallMethods([
        ['Email/set', {
            update => {
                $emailId => {
                    mailboxIds => {},
                },
            },
        }, 'R1'],
        ['Email/set', {
            update => {
                $emailId => {
                    mailboxIds => undef,
                },
            },
        }, 'R2'],
        ['Email/set', {
            update => {
                $emailId => {
                    'mailboxIds'.$mboxA => undef,
                    'mailboxIds'.$mboxB => undef,
                },
            },
        }, 'R3'],
        ['Email/set', {
            update => {
                $emailId => {
                    mailboxIds => [],
                },
            },
        }, 'R4'],
        ['Email/get', {
            ids => [$emailId],
            properties => ['mailboxIds'],
        }, 'R5'],
    ], $using);

    $self->assert_deep_equals({
        type => 'invalidProperties',
        properties => ['mailboxIds'],
    }, $res->[0][1]{notUpdated}{$emailId});

    $self->assert_str_equals($emailId, $res->[4][1]{list}[0]{id});
}

sub test_searchsnippet_search_maxsize
    :min_version_3_5 :needs_component_jmap :JMAPExtensions :SearchMaxSize4k
{
    my ($self) = @_;
    my $jmap = $self->{jmap};
    my $imap = $self->{store}->get_client();

    my $rawMessage = <<'EOF';
From: from@local
To: to@local
Subject: test
Date: Mon, 13 Apr 2020 15:34:03 +0200
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"

EOF

    xlog "Index overlong text";
    my $kbody = "xxx\n" x 1023;
    $kbody .=   "foo\n"; # last line of included text
    $kbody .=   "bar\n"; # first line of excluded text
    $rawMessage .= $kbody;
    $rawMessage =~ s/\r?\n/\r\n/gs;
    $imap->append('INBOX', $rawMessage) || die $@;

    xlog "Assert indexer only processes maxsize bytes of text";
    $self->{instance}->getsyslog(); # clear syslog
    $self->{instance}->run_command({cyrus => 1}, 'squatter');
    my @lines = $self->{instance}->getsyslog();
    $self->assert_num_equals(1, scalar grep { m/Xapian: truncating/ } @lines);

    my $res = $jmap->CallMethods([
        ['Email/query', {
            filter => {
                body => 'foo',
            },
        }, "R1"],
        ['Email/query', {
            filter => {
                body => 'bar',
            },
        }, "R2"],
    ]);
    $self->assert_num_equals(1, scalar @{$res->[0][1]{ids}});
    $self->assert_num_equals(0, scalar @{$res->[1][1]{ids}});
    my $emailId = $res->[0][1]{ids}[0];

    # Note: test assumes Cyrus charset buffer to flush every 4096 bytes

    xlog "Assert snippet generator only processes maxsize bytes of text";
    $self->{instance}->getsyslog(); # clear syslog
    $res = $jmap->CallMethods([
        ['SearchSnippet/get', {
            emailIds => [ $emailId ],
            filter => {
                body => 'foo',
            },
        }, 'R3'],
    ]);
    $self->assert_not_null($res->[0][1]{list}[0]{preview});
    @lines = $self->{instance}->getsyslog();
    $self->assert_num_equals(1, scalar grep { m/Xapian: truncating/ } @lines);

    xlog "Assert snippet generator only processes maxsize bytes of text";
    $self->{instance}->getsyslog(); # clear syslog
    $res = $jmap->CallMethods([
        ['SearchSnippet/get', {
            emailIds => [ $emailId ],
            filter => {
                body => 'bar',
            },
        }, 'R3'],
    ]);
    $self->assert_null($res->[0][1]{list}[0]{preview});
    @lines = $self->{instance}->getsyslog();
    $self->assert_num_equals(1, scalar grep { m/Xapian: truncating/ } @lines);
}

1;

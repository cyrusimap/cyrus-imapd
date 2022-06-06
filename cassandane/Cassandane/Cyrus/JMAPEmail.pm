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
use URI::Escape;

use lib '.';
use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;

use charnames ':full';

sub new
{
    my ($class, @args) = @_;

    my $config = Cassandane::Config->default()->clone();
    $config->set(caldav_historical_age => -1,
                 caldav_realm => 'Cassandane',
                 conversations => 'yes',
                 conversations_counted_flags => "\\Draft \\Flagged \$IsMailingList \$IsNotification \$HasAttachment",
                 defaultdomain => 'example.com',
                 httpallowcompress => 'no',
                 httpmodules => 'carddav caldav jmap',
                 icalendar_max_size => 100000,
                 jmap_nonstandard_extensions => 'yes',
                 jmapsubmission_deleteonsend => 'no',
                 sync_log => 'yes');

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

# a case where ANOTHER user moved an email from a folder with sharedseen
# enabled to a folder with different seen options enabled caused an IOERROR
# and DBERROR because the seen db was in a transaction, and hence led to
# this in the logs:
#
# IOERROR: append_addseen failed to open DB for foo@example.com

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

sub email_query_window_internal
{
    my ($self, %params) = @_;
    my %exp;
    my $jmap = $self->{jmap};
    my $res;

    $params{filter} //= undef;
    $params{wantGuidSearch} //= JSON::false;
    $params{calculateTotal} //= JSON::true;

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
            filter => $params{filter},
            calculateTotal => $params{calculateTotal},
        }, "R1"]
    ], $using);
    $self->assert_equals($params{wantGuidSearch},
        $res->[0][1]{performance}{details}{isGuidSearch});
    @subids = @{$ids}[1..3];
    $self->assert_deep_equals(\@subids, $res->[0][1]->{ids});
    if ($params{calculateTotal}) {
        $self->assert_num_equals(4, $res->[0][1]->{total});
    }

    xlog $self, "list emails from position 4";
    $res = $jmap->CallMethods([
        ['Email/query', {
            position => 4,
            filter => $params{filter},
            calculateTotal => $params{calculateTotal},
        }, "R1"]
    ], $using);
    $self->assert_equals($params{wantGuidSearch},
        $res->[0][1]{performance}{details}{isGuidSearch});
    $self->assert_num_equals(0, scalar @{$res->[0][1]->{ids}});
    if ($params{calculateTotal}) {
        $self->assert_num_equals(4, $res->[0][1]->{total});
    }

    xlog $self, "limit emails from position 1 to one email";
    $res = $jmap->CallMethods([
        ['Email/query', {
            position => 1,
            limit => 1,
            filter => $params{filter},
            calculateTotal => $params{calculateTotal},
        }, "R1"]
    ], $using);
    $self->assert_equals($params{wantGuidSearch},
        $res->[0][1]{performance}{details}{isGuidSearch});
    @subids = @{$ids}[1..1];
    $self->assert_deep_equals(\@subids, $res->[0][1]->{ids});
    $self->assert_num_equals(1, $res->[0][1]->{position});
    if ($params{calculateTotal}) {
        $self->assert_num_equals(4, $res->[0][1]->{total});
    }

    xlog $self, "anchor at 2nd email";
    $res = $jmap->CallMethods([
        ['Email/query', {
            anchor => @{$ids}[1],
            filter => $params{filter},
            calculateTotal => $params{calculateTotal},
        }, "R1"]
    ], $using);
    $self->assert_equals($params{wantGuidSearch},
        $res->[0][1]{performance}{details}{isGuidSearch});
    @subids = @{$ids}[1..3];
    $self->assert_deep_equals(\@subids, $res->[0][1]->{ids});
    $self->assert_num_equals(1, $res->[0][1]->{position});
    if ($params{calculateTotal}) {
        $self->assert_num_equals(4, $res->[0][1]->{total});
    }

    xlog $self, "anchor at 2nd email and offset 1";
    $res = $jmap->CallMethods([
        ['Email/query', {
            anchor => @{$ids}[1],
            anchorOffset => 1,
            filter => $params{filter},
            calculateTotal => $params{calculateTotal},
        }, "R1"]
    ], $using);
    $self->assert_equals($params{wantGuidSearch},
        $res->[0][1]{performance}{details}{isGuidSearch});
    @subids = @{$ids}[2..3];
    $self->assert_deep_equals(\@subids, $res->[0][1]->{ids});
    $self->assert_num_equals(2, $res->[0][1]->{position});
    if ($params{calculateTotal}) {
        $self->assert_num_equals(4, $res->[0][1]->{total});
    }

    xlog $self, "anchor at 3rd email and offset -1";
    $res = $jmap->CallMethods([
        ['Email/query', {
            anchor => @{$ids}[2],
            anchorOffset => -1,
            filter => $params{filter},
            calculateTotal => $params{calculateTotal},
        }, "R1"]
    ], $using);
    $self->assert_equals($params{wantGuidSearch},
        $res->[0][1]{performance}{details}{isGuidSearch});
    @subids = @{$ids}[1..3];
    $self->assert_deep_equals(\@subids, $res->[0][1]->{ids});
    $self->assert_num_equals(1, $res->[0][1]->{position});
    if ($params{calculateTotal}) {
        $self->assert_num_equals(4, $res->[0][1]->{total});
    }

    xlog $self, "anchor at 1st email offset 1 and limit 2";
    $res = $jmap->CallMethods([
        ['Email/query', {
            anchor => @{$ids}[0],
            anchorOffset => 1,
            limit => 2,
            filter => $params{filter},
            calculateTotal => $params{calculateTotal},
        }, "R1"]
    ], $using);
    $self->assert_equals($params{wantGuidSearch},
        $res->[0][1]{performance}{details}{isGuidSearch});
    @subids = @{$ids}[1..2];
    $self->assert_deep_equals(\@subids, $res->[0][1]->{ids});
    $self->assert_num_equals(1, $res->[0][1]->{position});
    if ($params{calculateTotal}) {
        $self->assert_num_equals(4, $res->[0][1]->{total});
    }
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

1;

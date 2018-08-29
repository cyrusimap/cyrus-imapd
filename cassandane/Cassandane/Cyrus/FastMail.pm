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

package Cassandane::Cyrus::FastMail;
use strict;
use warnings;
use DateTime;
use JSON::XS;
use Net::CalDAVTalk 0.09;
use Net::CardDAVTalk 0.03;
use Mail::JMAPTalk 0.12;
use Data::Dumper;
use Storable 'dclone';

use lib '.';
use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;

use charnames ':full';

our $RNUM = 1;

sub new
{
    my ($class, @args) = @_;

    my $config = Cassandane::Config->default()->clone();
    $config->set(caldav_realm => 'Cassandane',
		 conversations => 'yes',
		 httpmodules => 'carddav caldav jmap',
		 httpallowcompress => 'no',
                 allowusermoves => 'yes',
                 altnamespace => 'no',
                 anyoneuseracl => 'no',
                 archive_enabled => 'yes',
                 caldav_allowattach => 'off',
                 caldav_allowscheduling => 'yes',
                 caldav_create_attach => 'no',
                 caldav_create_default => 'no',
                 caldav_create_sched => 'yes',
                 caldav_realm => 'FastMail',
                 crossdomains => 'yes',
                 crossdomains_onlyother => 'yes',
                 annotation_allow_undefined => 'yes',
                 conversations => 'yes',
                 conversations_counted_flags => '\\Draft \\Flagged $IsMailingList $IsNotification $HasAttachment $HasTD',
                 conversations_max_thread => '100',
                 mailbox_initial_flags => '$X-ME-Annot-2 $IsMailingList $IsNotification $HasAttachment $HasTD',
                 defaultacl => 'admin lrswipkxtecdan',
                 defaultdomain => 'internal',
                 delete_unsubscribe => 'yes',
                 expunge_mode => 'delayed',
                 hashimapspool => 'on',
                 httpallowcompress => 'no',
                 httpkeepalive => '0',
                 httpmodules => 'caldav carddav jmap',
                 httpprettytelemetry => 'yes',
                 imapidresponse => 'no',
                 imapmagicplus => 'yes',
                 implicit_owner_rights => 'lkn',
                 internaldate_heuristic => 'receivedheader',
                 jmap_preview_annot => '/shared/vendor/messagingengine.com/preview',
                 jmapauth_allowsasl => 'yes',
                 lmtp_fuzzy_mailbox_match => 'yes',
                 lmtp_over_quota_perm_failure => 'yes',
                 maxheaderlines => '4096',
                 maxword => '8388608',
                 maxquoted => '8388608',
                 munge8bit => 'no',
                 notesmailbox => 'Notes',
                 popsubfolders => 'yes',
                 popuseacl => 'yes',
                 postmaster => 'postmaster@example.com',
                 quota_db => 'quotalegacy',
                 quotawarn => '98',
                 reverseacls => 'yes',
                 rfc3028_strict => 'no',
                 sieve_extensions => 'fileinto reject vacation imapflags notify envelope body relational regex subaddress copy mailbox mboxmetadata servermetadata date index variables imap4flags editheader duplicate vacation-seconds',
                 sieve_utf8fileinto => 'yes',
                 sieve_use_lmtp_reject => 'no',
                 sievenotifier => 'mailto',
                 sieve_maxscriptsize => '1024',
                 sieve_vacation_min_response => '60',
                 specialusealways => 'yes',
                 specialuse_extra => '\\XChats \\XTemplates \\XNotes',
                 statuscache => 'on',
                 subscription_db => 'flat',
                 suppress_capabilities => 'URLAUTH URLAUTH=BINARY',
                 tcp_keepalive => 'yes',
                 timeout => '60',
                 unix_group_enable => 'no',
                 unixhierarchysep => 'no',
                 virtdomains => 'userid',
                 search_engine => 'xapian',
                 search_index_headers => 'no',
                 search_batchsize => '8192',
                 search_maxtime => '30',
                 search_snippet_length => '160',
                 telemetry_bysessionid => 'yes',
                 delete_mode => 'delayed',
                 pop3alt_uidl_format => 'dovecot',
                 event_content_inclusion_mode => 'standard',
                 event_content_size => '1',
                 event_exclude_specialuse => '\\Junk',
                 event_extra_params => 'modseq vnd.fastmail.clientId service uidnext vnd.fastmail.sessionId vnd.cmu.envelope vnd.fastmail.convUnseen vnd.fastmail.convExists vnd.fastmail.cid vnd.cmu.mbtype vnd.cmu.davFilename vnd.cmu.davUid vnd.cmu.mailboxACL vnd.fastmail.counters messages vnd.cmu.unseenMessages flagNames',
                 event_groups => 'mailbox message flags calendar applepushservice',
                 event_notifier => 'pusher',
    );

    return $class->SUPER::new({
	config => $config,
	jmap => 1,
	adminstore => 1,
	services => [ 'imap', 'http' ]
    }, @args);
}

sub set_up
{
    my ($self) = @_;
    $self->SUPER::set_up();
}

sub _fmjmap_req
{
    my ($self, $cmd, %args) = @_;
    my $jmap = $self->{jmap};

    my $rnum = "R" . $RNUM++;
    my $res = $jmap->Request({methodCalls => [[$cmd, \%args, $rnum]], using => ["ietf:jmap"]});
    my $res1 = $res->{methodResponses}[0];
    $self->assert_not_null($res1);
    $self->assert_str_equals($rnum, $res1->[2]);
    return $res1;
}

sub _fmjmap_ok
{
    my ($self, $cmd, %args) = @_;
    my $res = $self->_fmjmap_req($cmd, %args);
    $self->assert_str_equals($cmd, $res->[0]);
    return $res->[1];
}

sub _fmjmap_err
{
    my ($self, $cmd, %args) = @_;
    my $res = $self->_fmjmap_req($cmd, %args);
    $self->assert_str_equals($res->[0], "error");
    return $res->[1];
}

sub test_ajaxui_jmapcontacts_contactgroup_set
    :min_version_3_1 :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};
    my $service = $self->{instance}->get_service("http");

    my $admintalk = $self->{adminstore}->get_client();
    $admintalk->create("user.masteruser");
    $admintalk->setacl("user.masteruser", admin => 'lrswipkxtecdan');
    $admintalk->setacl("user.masteruser", masteruser => 'lrswipkxtecdn');
    $admintalk->create("user.masteruser.#addressbooks.Default", ['TYPE', 'ADDRESSBOOK']);
    $admintalk->create("user.masteruser.#addressbooks.Shared", ['TYPE', 'ADDRESSBOOK']);
    $admintalk->setacl("user.masteruser.#addressbooks.Default", "masteruser" => 'lrswipkxtecdn') or die;
    $admintalk->setacl("user.masteruser.#addressbooks.Shared", "masteruser" => 'lrswipkxtecdn') or die;
    $admintalk->setacl("user.masteruser.#addressbooks.Shared", "cassandane" => 'lrswipkxtecdn') or die;

    my $mastertalk = Net::CardDAVTalk->new(
        user => "masteruser",
        password => 'pass',
        host => $service->host(),
        port => $service->port(),
        scheme => 'http',
        url => '/',
        expandurl => 1,
    );

    my $res;

    xlog "create contact group";
    $res = $self->_fmjmap_ok('ContactGroup/set',
        accountId => 'cassandane',
        create => {
            "k2519" => {
                name => "personal group",
                addressbookId => 'Default',
                contactIds => [],
                otherAccountContactIds => {
                    masteruser => [],
                },
            },
        },
        update => {},
        destroy => [],
    );
    my $groupid = $res->{created}{"k2519"}{id};
    $self->assert_not_null($groupid);

    $res = $self->_fmjmap_ok('ContactGroup/get',
        ids => [$groupid],
    );

    $self->assert_num_equals(1, scalar @{$res->{list}});
    # check the rest?

    xlog "create contact group";
    $res = $self->_fmjmap_ok('ContactGroup/set',
        accountId => 'masteruser',
        create => {
            "k2520" => {
                name => "shared group",
                addressbookId => 'Shared',
                contactIds => [],
                otherAccountContactIds => {},
            },
        },
        update => {},
        destroy => [],
    );
    my $sgroupid = $res->{created}{"k2520"}{id};
    $self->assert_not_null($sgroupid);

}

1;

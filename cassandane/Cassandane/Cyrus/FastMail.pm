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
                 autoexpunge => 'yes',
                 caldav_allowattach => 'yes',
                 caldav_allowscheduling => 'yes',
                 caldav_create_attach => 'yes',
                 caldav_create_default => 'no',
                 caldav_create_sched => 'yes',
                 caldav_realm => 'FastMail',
                 calendar_component_set => 'VEVENT',
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
                 jmap_nonstandard_extensions => 'yes',
                 jmapauth_allowsasl => 'yes',
                 lmtp_fuzzy_mailbox_match => 'yes',
                 lmtp_exclude_specialuse => '\XChats \XTemplates \XNotes \Drafts \Snoozed',
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
                 quota_use_conversations => 'yes',
                 quotawarn => '98',
                 reverseacls => 'yes',
                 rfc3028_strict => 'no',
                 savedate => 'yes',
                 sieve_extensions => 'fileinto reject vacation imapflags notify envelope body relational regex subaddress copy mailbox mboxmetadata servermetadata date index variables imap4flags editheader duplicate vacation-seconds fcc x-cyrus-jmapquery x-cyrus-snooze x-cyrus-log mailboxid special-use',
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
                 search_query_language => 'yes',
                 search_index_language => 'yes',
                 telemetry_bysessionid => 'yes',
                 delete_mode => 'delayed',
                 pop3alt_uidl_format => 'dovecot',
                 event_content_inclusion_mode => 'standard',
                 event_content_size => '1',
                 event_exclude_specialuse => '\\Junk',
                 event_extra_params => 'modseq vnd.fastmail.clientId service uidnext vnd.fastmail.sessionId vnd.cmu.envelope vnd.fastmail.convUnseen vnd.fastmail.convExists vnd.fastmail.cid vnd.cmu.mbtype vnd.cmu.davFilename vnd.cmu.davUid vnd.cmu.mailboxACL vnd.fastmail.counters messages vnd.cmu.unseenMessages flagNames vnd.cmu.emailid vnd.cmu.threadid',
                 event_groups => 'mailbox message flags calendar applepushservice',
                 event_notifier => 'pusher',
                 sync_log => 'yes',
    );

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

# XXX Cheating and just passing in all the using strings that cyrus
# XXX recognises -- these were ripped from http_jmap.h, try to keep
# XXX them up to date! :)
my @default_using = qw(
    urn:ietf:params:jmap:core
    urn:ietf:params:jmap:mail
    urn:ietf:params:jmap:submission
    https://cyrusimap.org/ns/jmap/blob
    https://cyrusimap.org/ns/jmap/contacts
    https://cyrusimap.org/ns/jmap/calendars
    https://cyrusimap.org/ns/jmap/mail
    https://cyrusimap.org/ns/jmap/performance
    https://cyrusimap.org/ns/jmap/debug
    https://cyrusimap.org/ns/jmap/quota
);

# XXX This is here as documentation -- these ones are supported by
# XXX cyrus in some, but not all, configurations
my @non_default_using = qw(
    urn:ietf:params:jmap:vacationresponse
    urn:ietf:params:jmap:websocket
);

sub _fmjmap_req
{
    my ($self, $cmd, %args) = @_;
    my $jmap = delete $args{jmap} || $self->{jmap};

    my $rnum = "R" . $RNUM++;
    my $res = $jmap->Request({methodCalls => [[$cmd, \%args, $rnum]],
                              using => \@default_using });
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
    $self->assert_str_equals("error", $res->[0]);
    return $res->[1];
}

sub test_ajaxui_jmapcontacts_contactgroup_set
    :min_version_3_1 :needs_component_sieve
    :needs_component_jmap :JMAPExtensions
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

    xlog $self, "create contact group";
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

    xlog $self, "create contact group";
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

    xlog $self, "create invalid shared contact group";
    $res = $self->_fmjmap_ok('ContactGroup/set',
        accountId => 'masteruser',
        create => {
            "k2521" => {
                name => "invalid group",
                addressbookId => 'Default',
                contactIds => [],
                otherAccountContactIds => {},
            },
        },
        update => {},
        destroy => [],
    );

    $self->assert_not_null($res->{notCreated}{"k2521"});
    $self->assert_null($res->{created}{"k2521"});

    # now let's create a contact and put it in the event...
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

sub test_issue_LP52545479
    :min_version_3_1 :needs_component_sieve
    :needs_component_jmap :JMAPExtensions
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    my $res = $jmap->CallMethods([
        ['Calendar/set', {
            create => {
                calendar1 => {
                    name => 'calendar1',
                    color => 'coral',
                    sortOrder => 1,
                    isVisible => JSON::true,
                }
            },
        }, 'R1'],
    ], \@default_using);
    my $calendarId = $res->[0][1]{created}{calendar1}{id};
    $self->assert_not_null($calendarId);

    $res = $jmap->CallMethods([
        ['Contact/set', {
            create => {
                contact1 => {
                    firstName => "firstName",
                    lastName => "lastName",
                    notes => "x" x 1024
                }
            }
        }, 'R1'],
        ['CalendarEvent/set', {
            create => {
                event1 => {
                    calendarId => $calendarId,
                    uid => '58ADE31-custom-UID',
                    title => 'event1',
                    start => '2015-11-07T09:00:00',
                    duration => 'PT5M',
                    sequence => 42,
                    timeZone => 'Etc/UTC',
                    showWithoutTime => JSON::false,
                    locale => 'en',
                    description => 'x' x 1024,
                    freeBusyStatus => 'busy',
                    privacy => 'secret',
                    participants => undef,
                    alerts => undef,
                }
            },
        }, 'R2'],
    ], \@default_using);
    my $contactId1 = $res->[0][1]{created}{contact1}{id};
    $self->assert_not_null($contactId1);
    my $eventId1 = $res->[1][1]{created}{event1}{id};
    $self->assert_not_null($eventId1);

    $self->_set_quotaroot('user.cassandane');
    $self->_set_quotalimits(storage => 1, 'x-annotation-storage' => 1); # that's 1024 bytes

    $res = $jmap->CallMethods([
        ['Contact/set', {
              update => {
                  $contactId1 => {
                      lastName => "updatedLastName",
                  }
              }
        }, 'R1'],
        ['CalendarEvent/set', {
              update => {
                  $eventId1 => {
                      description => "y" x 2048,
                  }
              }
        }, 'R2'],
    ], \@default_using);
    $self->assert_str_equals('overQuota', $res->[0][1]{notUpdated}{$contactId1}{type});
    $self->assert(not exists $res->[0][1]{updated}{$contactId1});
    $self->assert_str_equals('overQuota', $res->[1][1]{notUpdated}{$eventId1}{type});
    $self->assert(not exists $res->[1][1]{updated}{$eventId1});
}

sub test_mailbox_query
    :min_version_3_1 :needs_component_sieve :needs_component_jmap
{
    my ($self) = @_;

    my $jmap = $self->{jmap};


    my $res = $jmap->CallMethods([
        ['Mailbox/set', {
            create => {
                1 => { name => 'Sent', role => 'sent' },
                2 => { name => 'Trash', role => 'junk' },
                3 => { name => 'Foo' },
                4 => { name => 'Bar', sortOrder => 30 },
                5 => { name => 'Early', sortOrder => 2 },
                6 => { name => 'Child', parentId => '#5' },
                7 => { name => 'EarlyChild', parentId => '#5', sortOrder => 0 },
            },
        }, 'a'],
        ['Mailbox/query', {
            sortAsTree => $JSON::true,
            sort => [{property => 'sortOrder'}, {property => 'name'}],
            filterAsTree => $JSON::true,
            filter => {
                operator => 'OR',
                conditions => [{role => 'inbox'}, {hasAnyRole => $JSON::false}],
            },
        }, 'b'],
        ['Mailbox/get', {
            '#ids' => {
                resultOf => 'b',
                name => 'Mailbox/query',
                path => '/ids',
            },
        }, 'c'],
    ]);

    # default sort orders should have been set for Sent, Trash and Foo:

    $self->assert_num_equals(5, $res->[0][1]{created}{1}{sortOrder});
    $self->assert_num_equals(6, $res->[0][1]{created}{2}{sortOrder});
    $self->assert_num_equals(10, $res->[0][1]{created}{3}{sortOrder});
    $self->assert_num_equals(10, $res->[0][1]{created}{6}{sortOrder});

    # sortOrder shouldn't be returned where it's been set explicitly
    $self->assert_null($res->[0][1]{created}{4}{sortOrder});
    $self->assert_null($res->[0][1]{created}{5}{sortOrder});
    $self->assert_null($res->[0][1]{created}{7}{sortOrder});

    my %mailboxes = map { $_->{id} => $_ } @{$res->[2][1]{list}};

    my $list = $res->[1][1]{ids};

    # expected values for name and sortOrder
    my @expected = (
      ['Inbox', 1],
      ['Early', 2],
        ['EarlyChild', 0],
        ['Child', 10],
      ['Foo', 10],
      ['Bar', 30],
    );
    $self->assert_num_equals(scalar @expected, scalar @$list);

    for (0..$#expected) {
        $self->assert_str_equals($expected[$_][0], $mailboxes{$list->[$_]}{name});
        $self->assert_num_equals($expected[$_][1], $mailboxes{$list->[$_]}{sortOrder});
    }
}

sub test_rename_deepuser_standardfolders
    :AllowMoves :Replication :min_version_3_3 :needs_component_sieve
    :needs_component_jmap :JMAPExtensions
{
    my ($self) = @_;

    my $admintalk = $self->{adminstore}->get_client();

    my $rhttp = $self->{replica}->get_service('http');
    my $rjmap = Mail::JMAPTalk->new(
        user => 'cassandane',
        password => 'pass',
        host => $rhttp->host(),
        port => $rhttp->port(),
        scheme => 'http',
        url => '/jmap/',
    );

    my $synclogfname = "$self->{instance}->{basedir}/conf/sync/log";

    $self->_fmjmap_ok('Calendar/set',
        create => {
            "1" => { name => "A calendar" },
        },
    );

    $self->_fmjmap_ok('Contact/set',
        create => {
            "1" => {firstName => "first", lastName => "last"},
            "2" => {firstName => "second", lastName => "last"},
        },
    );

    $self->_fmjmap_ok('Mailbox/set',
        create => {
            "1" => { name => 'Archive', parentId => undef, role => 'archive' },
            "2" => { name => 'Drafts', parentId => undef, role => 'drafts' },
            "3" => { name => 'Junk', parentId => undef, role => 'junk' },
            "4" => { name => 'Sent', parentId => undef, role => 'sent' },
            "5" => { name => 'Trash', parentId => undef, role => 'trash' },
            "6" => { name => 'bar', parentId => undef, role => undef },
            "7" => { name => 'sub', parentId => "#6", role => undef },
        },
    );

    xlog $self, "Create a folder with intermediates";
    $admintalk->create("user.cassandane.folderA.folderB.folderC");

    my $data = $self->_fmjmap_ok('Mailbox/get', properties => ['name']);
    my %byname = map { $_->{name} => $_->{id} } @{$data->{list}};

    xlog $self, "Test user rename";
    # replicate and check initial state
    $self->run_replication(rolling => 1, inputfile => $synclogfname);
    $self->check_replication('cassandane');
    unlink($synclogfname);

    $data = $self->_fmjmap_ok('Mailbox/get', jmap => $rjmap, properties => ['name']);
    my %byname_repl = map { $_->{name} => $_->{id} } @{$data->{list}};

    $self->assert_deep_equals(\%byname, \%byname_repl);

    # n.b. run_replication dropped all our store connections...
    $admintalk = $self->{adminstore}->get_client();
    $self->{instance}->getsyslog();
    my $res = $admintalk->rename('user.cassandane', 'user.newuser');
    $self->assert(not $admintalk->get_last_error());

    xlog $self, "Make sure we didn't create intermediates in the process!";
    my @syslog = $self->{instance}->getsyslog();
    $self->assert_null(grep { m/creating intermediate with children/ } @syslog);
    $self->assert_null(grep { m/deleting intermediate with no children/ } @syslog);

    $res = $admintalk->select("user.newuser.bar.sub");
    $self->assert(not $admintalk->get_last_error());

    $self->{jmap}->{user} = 'newuser';
    $data = $self->_fmjmap_ok('Mailbox/get', properties => ['name']);
    my %byname_new = map { $_->{name} => $_->{id} } @{$data->{list}};

    $self->assert_deep_equals(\%byname, \%byname_new);

    # replicate and check the renames
    $self->{replica}->getsyslog();
    $self->run_replication(rolling => 1, inputfile => $synclogfname);
    @syslog = $self->{replica}->getsyslog();

    $self->assert_null(grep { m/creating intermediate with children/ } @syslog);
    $self->assert_null(grep { m/deleting intermediate with no children/ } @syslog);

    # check replication is clean
    $self->check_replication('newuser');

    $rjmap->{user} = 'newuser';
    $data = $self->_fmjmap_ok('Mailbox/get', jmap => $rjmap, properties => ['name']);
    my %byname_newrepl = map { $_->{name} => $_->{id} } @{$data->{list}};

    $self->assert_deep_equals(\%byname, \%byname_newrepl);
}

sub test_rename_deepfolder_intermediates
    :AllowMoves :Replication :min_version_3_3 :needs_component_sieve
    :needs_component_jmap :JMAPExtensions
{
    my ($self) = @_;

    my $admintalk = $self->{adminstore}->get_client();

    $admintalk->setquota('user.cassandane', ['STORAGE', 500000]);

    my $rhttp = $self->{replica}->get_service('http');
    my $rjmap = Mail::JMAPTalk->new(
        user => 'cassandane',
        password => 'pass',
        host => $rhttp->host(),
        port => $rhttp->port(),
        scheme => 'http',
        url => '/jmap/',
    );

    my $synclogfname = "$self->{instance}->{basedir}/conf/sync/log";

    $self->_fmjmap_ok('Calendar/set',
        create => {
            "1" => { name => "A calendar" },
        },
    );

    $self->_fmjmap_ok('Contact/set',
        create => {
            "1" => {firstName => "first", lastName => "last"},
            "2" => {firstName => "second", lastName => "last"},
        },
    );

    $self->_fmjmap_ok('Mailbox/set',
        create => {
            "1" => { name => 'Archive', parentId => undef, role => 'archive' },
            "2" => { name => 'Drafts', parentId => undef, role => 'drafts' },
            "3" => { name => 'Junk', parentId => undef, role => 'junk' },
            "4" => { name => 'Sent', parentId => undef, role => 'sent' },
            "5" => { name => 'Trash', parentId => undef, role => 'trash' },
            "6" => { name => 'bar', parentId => undef, role => undef },
            "7" => { name => 'sub', parentId => "#6", role => undef },
        },
    );

    xlog $self, "Create a folder with intermediates";
    $admintalk->create("user.cassandane.folderA.folderB.folderC");

    my $data = $self->_fmjmap_ok('Mailbox/get', properties => ['name']);
    my %byname = map { $_->{name} => $_->{id} } @{$data->{list}};

    xlog $self, "Test replication";
    # replicate and check initial state
    $self->run_replication(rolling => 1, inputfile => $synclogfname);
    $self->check_replication('cassandane');
    unlink($synclogfname);

    $data = $self->_fmjmap_ok('Mailbox/get', jmap => $rjmap, properties => ['name']);
    my %byname_repl = map { $_->{name} => $_->{id} } @{$data->{list}};

    $self->assert_deep_equals(\%byname, \%byname_repl);

    # n.b. run_replication dropped all our store connections...
    $admintalk = $self->{adminstore}->get_client();
    $self->{instance}->getsyslog();
    my $res = $admintalk->rename('user.cassandane.folderA', 'user.cassandane.folderZ');
    $self->assert(not $admintalk->get_last_error());

    xlog $self, "Make sure we didn't create intermediates in the process!";
    my @syslog = $self->{instance}->getsyslog();
    $self->assert_null(grep { m/creating intermediate with children/ } @syslog);
    $self->assert_null(grep { m/deleting intermediate with no children/ } @syslog);

    $data = $self->_fmjmap_ok('Mailbox/get', properties => ['name']);
    my %byname_new = map { $_->{name} => $_->{id} } @{$data->{list}};

    # we renamed a folder!
    $byname{folderZ} = delete $byname{folderA};

    $self->assert_deep_equals(\%byname, \%byname_new);

    # replicate and check the renames
    $self->{replica}->getsyslog();
    $self->run_replication(rolling => 1, inputfile => $synclogfname);
    @syslog = $self->{replica}->getsyslog();

    $self->assert_null(grep { m/creating intermediate with children/ } @syslog);
    $self->assert_null(grep { m/deleting intermediate with no children/ } @syslog);

    # check replication is clean
    $self->check_replication('cassandane');

    $data = $self->_fmjmap_ok('Mailbox/get', jmap => $rjmap, properties => ['name']);
    my %byname_newrepl = map { $_->{name} => $_->{id} } @{$data->{list}};

    $self->assert_deep_equals(\%byname, \%byname_newrepl);

    # n.b. run_replication dropped all our store connections...
    $admintalk = $self->{adminstore}->get_client();
    $admintalk->delete("user.cassandane");

    xlog $self, "Make sure we didn't create intermediates in the process!";
    @syslog = $self->{instance}->getsyslog();
    $self->assert_null(grep { m/creating intermediate with children/ } @syslog);
    $self->assert_null(grep { m/deleting intermediate with no children/ } @syslog);

    xlog $self, "Make sure there are no files left with cassandane in the name";
    $self->assert_str_equals(q{}, join(q{ }, glob "$self->{instance}{basedir}/conf/user/c/cassandane.*"));
    $self->assert(not -d "$self->{instance}{basedir}/data/c/user/cassandane");
    $self->assert(not -f "$self->{instance}{basedir}/conf/quota/c/user.cassandane");

    # replicate and check the renames
    $self->run_replication(rolling => 1, inputfile => $synclogfname);
    @syslog = $self->{replica}->getsyslog();
    $self->assert_null(grep { m/creating intermediate with children/ } @syslog);
    $self->assert_null(grep { m/deleting intermediate with no children/ } @syslog);

    xlog $self, "Make sure there are no files left with cassandane in the name on the replica";
    $self->assert_str_equals(q{}, join(q{ }, glob "$self->{replica}{basedir}/conf/user/c/cassandane.*"));
    $self->assert(not -d "$self->{replica}{basedir}/data/c/user/cassandane");
    $self->assert(not -f "$self->{replica}{basedir}/conf/quota/c/user.cassandane");

    xlog $self, "Now clean up all the deleted mailboxes";
    $self->{instance}->run_command({ cyrus => 1 }, 'cyr_expire', '-D' => '0', '-a' );
}

sub test_mailbox_rename_to_inbox_sub
    :min_version_3_3 :needs_component_sieve
    :needs_component_jmap :JMAPExtensions
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    # we need the mail extensions for isSeenShared
    my @using = @{ $jmap->DefaultUsing() };
    push @using, 'https://cyrusimap.org/ns/jmap/mail';
    $jmap->DefaultUsing(\@using);

    my $imaptalk = $self->{store}->get_client();

    xlog $self, "create mailboxes";
    $imaptalk->create("INBOX.INBOX.Child") || die;
    $imaptalk->create("INBOX.Example.INBOX") || die;
    $imaptalk->create("INBOX.Example.Other") || die;
    $imaptalk->create("INBOX.Top") || die;

    xlog $self, "fetch mailboxes";
    my $res = $jmap->Call('Mailbox/get', {});
    my %mboxids = map { $_->{name} => $_->{id} } @{$res->{list}};

    xlog $self, "fail move Example.INBOX to top level";
    $res = $jmap->Call('Mailbox/set', {
      update => {
        $mboxids{INBOX} => {
          parentId => undef,
        }
      }
    });
    $self->assert_null($res->{updated});
    $self->assert_str_equals("parentId", $res->{notUpdated}{$mboxids{INBOX}}{properties}[0]);

    xlog $self, "fail move Top to inbox";
    $res = $jmap->Call('Mailbox/set', {
      update => {
        $mboxids{Top} => {
          name => 'inbox',
        }
      }
    });
    $self->assert_null($res->{updated});
    $self->assert_str_equals("name", $res->{notUpdated}{$mboxids{Top}}{properties}[0]);

    xlog $self, "fail move Example.Other to InBox";
    $res = $jmap->Call('Mailbox/set', {
      update => {
        $mboxids{Other} => {
          name => "InBox",
          parentId => undef,
        }
      }
    });
    $self->assert_null($res->{updated});
    $self->assert_str_equals("name", $res->{notUpdated}{$mboxids{Other}}{properties}[0]);

    # no updates YET!
    $res = $jmap->Call('Mailbox/get', {});
    my %mboxids2 = map { $_->{name} => $_->{id} } @{$res->{list}};
    $self->assert_deep_equals(\%mboxids, \%mboxids2);

    xlog $self, "Move Example.INBOX again to sub of Inbox (allowed)";
    $res = $jmap->Call('Mailbox/set', {
      update => {
        $mboxids{INBOX} => {
          parentId => $mboxids{Inbox},
          isSeenShared => $JSON::true,
        }
      }
    });
    # this will have content which is NULL, but it should exist
    $self->assert(exists $res->{updated}{$mboxids{INBOX}});
    $self->assert_null($res->{notUpdated});

    # make sure we didn't create the deep tree!
    my @syslog = $self->{instance}->getsyslog();
    $self->assert(not grep { m/INBOX\.INBOX\.INBOX/ } @syslog);
}

sub test_mailbox_rename_sub_inbox_both
    :min_version_3_3 :needs_component_sieve
    :needs_component_jmap :JMAPExtensions
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    # we need the mail extensions for isSeenShared
    my @using = @{ $jmap->DefaultUsing() };
    push @using, 'https://cyrusimap.org/ns/jmap/mail';
    $jmap->DefaultUsing(\@using);

    my $imaptalk = $self->{store}->get_client();

    xlog $self, "create mailboxes";
    $imaptalk->create("INBOX.INBOX.Child") || die;
    $imaptalk->create("INBOX.Example.INBOX") || die;
    $imaptalk->create("INBOX.Example.Other") || die;
    $imaptalk->create("INBOX.Top") || die;

    xlog $self, "fetch mailboxes";
    my $res = $jmap->Call('Mailbox/get', {});
    my %mboxids = map { $_->{name} => $_->{id} } @{$res->{list}};

    xlog $self, "move Example.INBOX to top level and rename at same time";
    $res = $jmap->Call('Mailbox/set', {
      update => {
        $mboxids{INBOX} => {
          parentId => undef,
          name => "INBOX1",
        }
      }
    });
    $self->assert(exists $res->{updated}{$mboxids{INBOX}});
    $self->assert_null($res->{notUpdated});

    # make sure we didn't create the deep tree!
    my @syslog = $self->{instance}->getsyslog();
    $self->assert(not grep { m/INBOX\.INBOX\.INBOX/ } @syslog);
}

sub test_mailbox_rename_inside_deep
    :min_version_3_3 :needs_component_sieve
    :needs_component_jmap :JMAPExtensions
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    # we need the mail extensions for isSeenShared
    my @using = @{ $jmap->DefaultUsing() };
    push @using, 'https://cyrusimap.org/ns/jmap/mail';
    $jmap->DefaultUsing(\@using);

    my $imaptalk = $self->{store}->get_client();

    xlog $self, "create mailboxes";
    $imaptalk->create("INBOX.A") || die;
    $imaptalk->create("INBOX.A.B") || die;
    $imaptalk->create("INBOX.A.B.C") || die;

    xlog $self, "fetch mailboxes";
    my $res = $jmap->Call('Mailbox/get', {});
    my %mboxids = map { $_->{name} => $_->{id} } @{$res->{list}};

    xlog $self, "move INBOX.A to be a child of INBOX.A.B.C";
    $res = $jmap->Call('Mailbox/set', {
      update => {
        $mboxids{A} => {
          parentId => $mboxids{C},
        }
      }
    });

    # rejected due to being a child
    $self->assert_str_equals("parentId", $res->{notUpdated}{$mboxids{A}}{properties}[0]);
}

sub test_mailbox_rename_to_clash_parent_only
    :min_version_3_3 :needs_component_sieve
    :needs_component_jmap :JMAPExtensions
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    # we need the mail extensions for isSeenShared
    my @using = @{ $jmap->DefaultUsing() };
    push @using, 'https://cyrusimap.org/ns/jmap/mail';
    $jmap->DefaultUsing(\@using);

    my $imaptalk = $self->{store}->get_client();

    xlog $self, "create mailboxes";
    $imaptalk->create("INBOX.A") || die;
    $imaptalk->create("INBOX.A.B") || die;

    xlog $self, "fetch mailboxes";
    my $res = $jmap->Call('Mailbox/get', {});
    my %mboxids = map { $_->{name} => $_->{id} } @{$res->{list}};

    $imaptalk->create("INBOX.B") || die;

    xlog $self, "move INBOX.A.B to be a child of INBOX";
    $res = $jmap->Call('Mailbox/set', {
      update => {
        $mboxids{B} => {
          parentId => undef,
        }
      }
    });

    # rejected due to being a child
    $self->assert_null($res->{updated});
    $self->assert_not_null($res->{notUpdated}{$mboxids{B}});

    # there were no renames
    my @syslog = $self->{instance}->getsyslog();
    $self->assert(not grep { m/auditlog: rename/ } @syslog);
}

sub test_mailbox_rename_to_clash_name_only_deep
    :min_version_3_3 :needs_component_sieve
    :needs_component_jmap :JMAPExtensions
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    # we need the mail extensions for isSeenShared
    my @using = @{ $jmap->DefaultUsing() };
    push @using, 'https://cyrusimap.org/ns/jmap/mail';
    $jmap->DefaultUsing(\@using);

    my $imaptalk = $self->{store}->get_client();

    xlog $self, "create mailboxes";
    $imaptalk->create("INBOX.A") || die;
    $imaptalk->create("INBOX.A.B") || die;
    $imaptalk->create("INBOX.C") || die;

    xlog $self, "fetch mailboxes";
    my $res = $jmap->Call('Mailbox/get', {});
    my %mboxids = map { $_->{name} => $_->{id} } @{$res->{list}};

    $imaptalk->create("INBOX.C.B") || die;

    xlog $self, "move INBOX.A.B to INBOX.C.B";
    $res = $jmap->Call('Mailbox/set', {
      update => {
        $mboxids{B} => {
          parentId => $mboxids{C},
        }
      }
    });

    # rejected due to name existing
    $self->assert_null($res->{updated});
    $self->assert_not_null($res->{notUpdated}{$mboxids{B}});

    # there were no renames
    my @syslog = $self->{instance}->getsyslog();
    $self->assert(not grep { m/auditlog: rename/ } @syslog);
}

sub test_mailbox_rename_to_clash_name_only
    :min_version_3_3 :needs_component_sieve
    :needs_component_jmap :JMAPExtensions
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    # we need the mail extensions for isSeenShared
    my @using = @{ $jmap->DefaultUsing() };
    push @using, 'https://cyrusimap.org/ns/jmap/mail';
    $jmap->DefaultUsing(\@using);

    my $imaptalk = $self->{store}->get_client();

    xlog $self, "create mailboxes";
    $imaptalk->create("INBOX.A") || die;
    $imaptalk->create("INBOX.B") || die;

    xlog $self, "fetch mailboxes";
    my $res = $jmap->Call('Mailbox/get', {});
    my %mboxids = map { $_->{name} => $_->{id} } @{$res->{list}};

    xlog $self, "move INBOX.A to INBOX.B";
    $res = $jmap->Call('Mailbox/set', {
      update => {
        $mboxids{A} => {
          name => "B",
        }
      }
    });

    # rejected due to name existing
    $self->assert_null($res->{updated});
    $self->assert_not_null($res->{notUpdated}{$mboxids{A}});

    $res = $jmap->Call('Mailbox/get', {});
    my %mboxids2 = map { $_->{name} => $_->{id} } @{$res->{list}};
    $self->assert_deep_equals(\%mboxids, \%mboxids2);

    # there were no renames
    my @syslog = $self->{instance}->getsyslog();
    $self->assert(not grep { m/auditlog: rename/ } @syslog);
}

sub test_mailbox_rename_to_clash_both
    :min_version_3_3 :needs_component_sieve
    :needs_component_jmap :JMAPExtensions
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    # we need the mail extensions for isSeenShared
    my @using = @{ $jmap->DefaultUsing() };
    push @using, 'https://cyrusimap.org/ns/jmap/mail';
    $jmap->DefaultUsing(\@using);

    my $imaptalk = $self->{store}->get_client();

    xlog $self, "create mailboxes";
    $imaptalk->create("INBOX.Foo") || die;
    $imaptalk->create("INBOX.Foo.A") || die;
    $imaptalk->create("INBOX.Bar") || die;
    $imaptalk->create("INBOX.Bar.B") || die;

    xlog $self, "fetch mailboxes";
    my $res = $jmap->Call('Mailbox/get', {});
    my %mboxids = map { $_->{name} => $_->{id} } @{$res->{list}};

    xlog $self, "move INBOX.Foo.A to INBOX.Bar.B";
    $res = $jmap->Call('Mailbox/set', {
      update => {
        $mboxids{A} => {
          parentId => $mboxids{Bar},
          name => "B",
        }
      }
    });

    # rejected due to name existing
    $self->assert_str_equals("name", $res->{notUpdated}{$mboxids{A}}{properties}[0]);

    $res = $jmap->Call('Mailbox/get', {});
    my %mboxids2 = map { $_->{name} => $_->{id} } @{$res->{list}};
    $self->assert_deep_equals(\%mboxids, \%mboxids2);

    # there were no renames
    my @syslog = $self->{instance}->getsyslog();
    $self->assert(not grep { m/auditlog: rename/ } @syslog);
}

sub test_mailbox_case_difference
    :min_version_3_3 :needs_component_sieve
    :needs_component_jmap :JMAPExtensions
{
    my ($self) = @_;

    my $jmap = $self->{jmap};

    # we need the mail extensions for isSeenShared
    my @using = @{ $jmap->DefaultUsing() };
    push @using, 'https://cyrusimap.org/ns/jmap/mail';
    $jmap->DefaultUsing(\@using);

    my $imaptalk = $self->{store}->get_client();

    xlog $self, "create mailboxes";
    $imaptalk->create("INBOX.Foo.Hi") || die;
    $imaptalk->create("INBOX.A") || die;

    xlog $self, "fetch mailboxes";
    my $res = $jmap->Call('Mailbox/get', {});
    my %mboxids = map { $_->{name} => $_->{id} } @{$res->{list}};

    xlog $self, "move INBOX.A to INBOX.Foo.B";
    $res = $jmap->Call('Mailbox/set', {
      update => {
        $mboxids{A} => {
          name => "Hi",
          parentId => $mboxids{Foo},
        },
        $mboxids{Hi} => {
          name => "HI",
        }
      }
    });

    $self->assert_null($res->{notUpdated});
    $self->assert(exists $res->{updated}{$mboxids{A}});
    $self->assert(exists $res->{updated}{$mboxids{Hi}});
}

sub test_rename_deepuser_standardfolders_rightnow
    :AllowMoves :Replication :min_version_3_3 :needs_component_sieve
    :needs_component_jmap :JMAPExtensions :RightNow
{
    my ($self) = @_;

    my $admintalk = $self->{adminstore}->get_client();

    my $rhttp = $self->{replica}->get_service('http');
    my $rjmap = Mail::JMAPTalk->new(
        user => 'cassandane',
        password => 'pass',
        host => $rhttp->host(),
        port => $rhttp->port(),
        scheme => 'http',
        url => '/jmap/',
    );

    my $synclogfname = "$self->{instance}->{basedir}/conf/sync/log";

    $self->_fmjmap_ok('Calendar/set',
        create => {
            "1" => { name => "A calendar" },
        },
    );

    $self->_fmjmap_ok('Contact/set',
        create => {
            "1" => {firstName => "first", lastName => "last"},
            "2" => {firstName => "second", lastName => "last"},
        },
    );

    $self->_fmjmap_ok('Mailbox/set',
        create => {
            "1" => { name => 'Archive', parentId => undef, role => 'archive' },
            "2" => { name => 'Drafts', parentId => undef, role => 'drafts' },
            "3" => { name => 'Junk', parentId => undef, role => 'junk' },
            "4" => { name => 'Sent', parentId => undef, role => 'sent' },
            "5" => { name => 'Trash', parentId => undef, role => 'trash' },
            "6" => { name => 'bar', parentId => undef, role => undef },
            "7" => { name => 'sub', parentId => "#6", role => undef },
        },
    );

    xlog $self, "Create a folder with intermediates";
    $admintalk->create("user.cassandane.folderA.folderB.folderC");

    my $data = $self->_fmjmap_ok('Mailbox/get', properties => ['name']);
    my %byname = map { $_->{name} => $_->{id} } @{$data->{list}};

    xlog $self, "Test user rename";
    # check initial state (replication has been running rightnow!)
    $self->check_replication('cassandane');

    $data = $self->_fmjmap_ok('Mailbox/get', jmap => $rjmap, properties => ['name']);
    my %byname_repl = map { $_->{name} => $_->{id} } @{$data->{list}};

    $self->assert_deep_equals(\%byname, \%byname_repl);

    # n.b. run_replication dropped all our store connections...
    $admintalk = $self->{adminstore}->get_client();
    $self->{instance}->getsyslog();
    my $res = $admintalk->rename('user.cassandane', 'user.newuser');
    $self->assert(not $admintalk->get_last_error());

    xlog $self, "Make sure we didn't create intermediates in the process!";
    my @syslog = $self->{instance}->getsyslog();
    $self->assert_null(grep { m/creating intermediate with children/ } @syslog);
    $self->assert_null(grep { m/deleting intermediate with no children/ } @syslog);

    $res = $admintalk->select("user.newuser.bar.sub");
    $self->assert(not $admintalk->get_last_error());

    $self->{jmap}->{user} = 'newuser';
    $data = $self->_fmjmap_ok('Mailbox/get', properties => ['name']);
    my %byname_new = map { $_->{name} => $_->{id} } @{$data->{list}};

    $self->assert_deep_equals(\%byname, \%byname_new);

    # check nothing got logged on the replica
    @syslog = $self->{replica}->getsyslog();
    $self->assert_null(grep { m/creating intermediate with children/ } @syslog);
    $self->assert_null(grep { m/deleting intermediate with no children/ } @syslog);

    # check replication is clean
    $self->check_replication('newuser');

    $rjmap->{user} = 'newuser';
    $data = $self->_fmjmap_ok('Mailbox/get', jmap => $rjmap, properties => ['name']);
    my %byname_newrepl = map { $_->{name} => $_->{id} } @{$data->{list}};

    $self->assert_deep_equals(\%byname, \%byname_newrepl);
}

sub test_rename_deepfolder_intermediates_rightnow
    :AllowMoves :Replication :min_version_3_3 :needs_component_sieve
    :needs_component_jmap :JMAPExtensions :RightNow
{
    my ($self) = @_;

    my $admintalk = $self->{adminstore}->get_client();

    $admintalk->setquota('user.cassandane', ['STORAGE', 500000]);

    my $rhttp = $self->{replica}->get_service('http');
    my $rjmap = Mail::JMAPTalk->new(
        user => 'cassandane',
        password => 'pass',
        host => $rhttp->host(),
        port => $rhttp->port(),
        scheme => 'http',
        url => '/jmap/',
    );

    my $synclogfname = "$self->{instance}->{basedir}/conf/sync/log";

    $self->_fmjmap_ok('Calendar/set',
        create => {
            "1" => { name => "A calendar" },
        },
    );

    $self->_fmjmap_ok('Contact/set',
        create => {
            "1" => {firstName => "first", lastName => "last"},
            "2" => {firstName => "second", lastName => "last"},
        },
    );

    $self->_fmjmap_ok('Mailbox/set',
        create => {
            "1" => { name => 'Archive', parentId => undef, role => 'archive' },
            "2" => { name => 'Drafts', parentId => undef, role => 'drafts' },
            "3" => { name => 'Junk', parentId => undef, role => 'junk' },
            "4" => { name => 'Sent', parentId => undef, role => 'sent' },
            "5" => { name => 'Trash', parentId => undef, role => 'trash' },
            "6" => { name => 'bar', parentId => undef, role => undef },
            "7" => { name => 'sub', parentId => "#6", role => undef },
        },
    );

    xlog $self, "Create a folder with intermediates";
    $admintalk->create("user.cassandane.folderA.folderB.folderC");

    my $data = $self->_fmjmap_ok('Mailbox/get', properties => ['name']);
    my %byname = map { $_->{name} => $_->{id} } @{$data->{list}};

    xlog $self, "Test replication";
    # replicate and check initial state
    $self->check_replication('cassandane');

    $data = $self->_fmjmap_ok('Mailbox/get', jmap => $rjmap, properties => ['name']);
    my %byname_repl = map { $_->{name} => $_->{id} } @{$data->{list}};

    $self->assert_deep_equals(\%byname, \%byname_repl);

    # n.b. run_replication dropped all our store connections...
    $admintalk = $self->{adminstore}->get_client();
    $self->{instance}->getsyslog();
    my $res = $admintalk->rename('user.cassandane.folderA', 'user.cassandane.folderZ');
    $self->assert(not $admintalk->get_last_error());

    xlog $self, "Make sure we didn't create intermediates in the process!";
    my @syslog = $self->{instance}->getsyslog();
    $self->assert_null(grep { m/creating intermediate with children/ } @syslog);
    $self->assert_null(grep { m/deleting intermediate with no children/ } @syslog);

    $data = $self->_fmjmap_ok('Mailbox/get', properties => ['name']);
    my %byname_new = map { $_->{name} => $_->{id} } @{$data->{list}};

    # we renamed a folder!
    $byname{folderZ} = delete $byname{folderA};

    $self->assert_deep_equals(\%byname, \%byname_new);

    # replicate and check the renames
    @syslog = $self->{replica}->getsyslog();

    $self->assert_null(grep { m/creating intermediate with children/ } @syslog);
    $self->assert_null(grep { m/deleting intermediate with no children/ } @syslog);

    # check replication is clean
    $self->check_replication('cassandane');

    $data = $self->_fmjmap_ok('Mailbox/get', jmap => $rjmap, properties => ['name']);
    my %byname_newrepl = map { $_->{name} => $_->{id} } @{$data->{list}};

    $self->assert_deep_equals(\%byname, \%byname_newrepl);

    # n.b. run_replication dropped all our store connections...
    $admintalk = $self->{adminstore}->get_client();
    $admintalk->delete("user.cassandane");

    xlog $self, "Make sure we didn't create intermediates in the process!";
    @syslog = $self->{instance}->getsyslog();
    $self->assert_null(grep { m/creating intermediate with children/ } @syslog);
    $self->assert_null(grep { m/deleting intermediate with no children/ } @syslog);

    xlog $self, "Make sure there are no files left with cassandane in the name";
    $self->assert_str_equals(q{}, join(q{ }, glob "$self->{instance}{basedir}/conf/user/c/cassandane.*"));
    $self->assert(not -d "$self->{instance}{basedir}/data/c/user/cassandane");
    $self->assert(not -f "$self->{instance}{basedir}/conf/quota/c/user.cassandane");

    # replicate and check the renames
    @syslog = $self->{replica}->getsyslog();
    $self->assert_null(grep { m/creating intermediate with children/ } @syslog);
    $self->assert_null(grep { m/deleting intermediate with no children/ } @syslog);

    xlog $self, "Make sure there are no files left with cassandane in the on the replica";
    $self->assert_str_equals(q{}, join(q{ }, glob "$self->{replica}{basedir}/conf/user/c/cassandane.*"));
    $self->assert(not -d "$self->{replica}{basedir}/data/c/user/cassandane");
    $self->assert(not -f "$self->{replica}{basedir}/conf/quota/c/user.cassandane");

    xlog $self, "Now clean up all the deleted mailboxes";
    $self->{instance}->run_command({ cyrus => 1 }, 'cyr_expire', '-D' => '0', '-a' );
}

sub test_imap_list_notes
    :min_version_3_1 :needs_component_sieve
{
    my ($self) = @_;

    my $imaptalk = $self->{store}->get_client();

    xlog $self, "create mailboxes";
    $imaptalk->create("INBOX.Foo") || die;
    $imaptalk->create("INBOX.Foo.Hi") || die;
    $imaptalk->create("INBOX.A") || die;
    $imaptalk->create("INBOX.Junk", "(USE (\\Junk))");
    $imaptalk->create("INBOX.Trash", "(USE (\\Trash))");
    $imaptalk->create("INBOX.Important", "(USE (\\Important))");
    $imaptalk->create("INBOX.Notes", "(USE (\\XNotes))");

    my $data = $imaptalk->list('', '*');
    $self->assert_deep_equals([
  [
    [
      '\\HasChildren',
    ],
    '.',
    'INBOX',
  ],
  [
    [
      '\\HasNoChildren',
    ],
    '.',
    'INBOX.A',
  ],
  [
    [
      '\\HasChildren',
    ],
    '.',
    'INBOX.Foo',
  ],
  [
    [
      '\\HasNoChildren',
    ],
    '.',
    'INBOX.Foo.Hi',
  ],
  [
    [
      '\\HasNoChildren',
      '\\Important',
    ],
    '.',
    'INBOX.Important',
  ],
  [
    [
      '\\HasNoChildren',
      '\\Junk',
    ],
    '.',
    'INBOX.Junk',
  ],
  [
    [
      '\\HasNoChildren',
      '\\XNotes',
    ],
    '.',
    'INBOX.Notes',
  ],
  [
    [
      '\\HasNoChildren',
      '\\Trash',
    ],
    '.',
    'INBOX.Trash',
  ],
], $data);

}

sub test_cyr_expire_delete_findpaths_legacy
    :DelayedDelete :min_version_3_5 :MailboxLegacyDirs
{
    my ($self) = @_;

    my $adminstore = $self->{adminstore};
    my $admintalk = $adminstore->get_client();

    my $inbox = "user.magicuser";
    my $subfolder = "$inbox.foo";

    $admintalk->create($inbox);
    $admintalk->setacl($inbox, admin => 'lrswipkxtecdan');
    $admintalk->create($subfolder);
    $self->assert_str_equals('ok', $admintalk->get_last_completion_response());

    $adminstore->set_folder($subfolder);
    $self->make_message("Email", store => $adminstore) or die;

    # Create the search database.
    xlog $self, "Run squatter";
    $self->{instance}->run_command({cyrus => 1}, 'squatter');

    xlog $self, "Delete $subfolder";
    $admintalk->unselect();
    $admintalk->delete($subfolder)
        or $self->fail("Cannot delete folder $subfolder: $@");
    $self->assert_str_equals('ok', $admintalk->get_last_completion_response());

    xlog $self, "Ensure we can't select $subfolder anymore";
    $admintalk->select($subfolder);
    $self->assert_str_equals('no', $admintalk->get_last_completion_response());
    $self->assert_matches(qr/Mailbox does not exist/i, $admintalk->get_last_error());

    my ($datapath) = $self->{instance}->folder_to_deleted_directories($subfolder);
    $self->assert_not_null($datapath);

    xlog $self, "Run cyr_expire -D now.";
    $self->{instance}->run_command({ cyrus => 1 }, 'cyr_expire', '-D' => '0' );

    # the folder should not exist now!
    $self->assert(!-d $datapath);

    # Delete the entire user!
    $admintalk->delete($inbox);

    my $basedir = $self->{instance}{basedir};
    open(FH, "-|", "find", $basedir);
    my @files = grep { m{/user/magicuser/} and not m{/conf/lock/} } <FH>;
    close(FH);

    xlog $self, "DELETED files exists";
    $self->assert(scalar grep { m{/DELETED/} } @files);
    xlog $self, "no non-deleted paths";
    $self->assert(not scalar grep { not m{/DELETED/} } @files);

    xlog $self, "Run cyr_expire -D now.";
    $self->{instance}->run_command({ cyrus => 1 }, 'cyr_expire', '-D' => '0' );

    open(FH, "-|", "find", $basedir);
    @files = grep { m{/user/magicuser/} and not m{/conf/lock/} } <FH>;
    close(FH);

    xlog $self, "no DELETED files exists";
    $self->assert(not scalar grep { m{/DELETED/} } @files);
    xlog $self, "no non-deleted paths";
    $self->assert(not scalar grep { not m{/DELETED/} } @files);
}

sub test_cyr_expire_delete_findpaths_nolegacy
    :DelayedDelete :min_version_3_5 :NoMailboxLegacyDirs
{
    my ($self) = @_;

    my $adminstore = $self->{adminstore};
    my $admintalk = $adminstore->get_client();

    my $inbox = "user.magicuser";
    my $subfolder = "$inbox.foo";

    $admintalk->create($inbox);
    $admintalk->setacl($inbox, admin => 'lrswipkxtecdan');
    $admintalk->create($subfolder);
    $self->assert_str_equals('ok', $admintalk->get_last_completion_response());

    $adminstore->set_folder($subfolder);
    $self->make_message("Email", store => $adminstore) or die;

    # Create the search database.
    xlog $self, "Run squatter";
    $self->{instance}->run_command({cyrus => 1}, 'squatter');

    my $res = $admintalk->status($inbox, ['mailboxid']);
    my $inboxid = $res->{mailboxid}[0];
    $res = $admintalk->status($subfolder, ['mailboxid']);
    my $subid = $res->{mailboxid}[0];

    xlog $self, "Delete $subfolder";
    $admintalk->unselect();
    $admintalk->delete($subfolder)
        or $self->fail("Cannot delete folder $subfolder: $@");
    $self->assert_str_equals('ok', $admintalk->get_last_completion_response());

    xlog $self, "Ensure we can't select $subfolder anymore";
    $admintalk->select($subfolder);
    $self->assert_str_equals('no', $admintalk->get_last_completion_response());
    $self->assert_matches(qr/Mailbox does not exist/i, $admintalk->get_last_error());

    my ($datapath) = $self->{instance}->folder_to_deleted_directories($subfolder);
    $self->assert_not_null($datapath);

    xlog $self, "Run cyr_expire -D now.";
    $self->{instance}->run_command({ cyrus => 1 }, 'cyr_expire', '-D' => '0' );

    # the folder should not exist now!
    $self->assert(!-d $datapath);

    # Delete the entire user!
    $admintalk->delete($inbox);

    my $basedir = $self->{instance}{basedir};
    open(FH, "-|", "find", $basedir);
    my @files = grep { m{/uuid/} } <FH>;
    close(FH);

    xlog $self, "files for the inbox still exist";
    $self->assert(scalar grep { m{$inboxid} } @files);
    xlog $self, "no files left for subfolder";
    $self->assert(not scalar grep { m{$subid} } @files);

    xlog $self, "Run cyr_expire -D now.";
    $self->{instance}->run_command({ cyrus => 1 }, 'cyr_expire', '-D' => '0' );

    open(FH, "-|", "find", $basedir);
    @files = grep { m{/uuid/} } <FH>;
    close(FH);

    use Data::Dumper;
    xlog $self, "no files for the inbox still exist" . Dumper(\@files, $inboxid);;
    $self->assert(not scalar grep { m{$inboxid} } @files);
}

sub test_sync_reset_legacy
    :DelayedDelete :min_version_3_5 :MailboxLegacyDirs
{
    my ($self) = @_;

    my $adminstore = $self->{adminstore};
    my $admintalk = $adminstore->get_client();

    my $inbox = "user.magicuser";
    my $subfolder = "$inbox.foo";

    $admintalk->create($inbox);
    $admintalk->setacl($inbox, admin => 'lrswipkxtecdan');
    $admintalk->create($subfolder);
    $self->assert_str_equals('ok', $admintalk->get_last_completion_response());

    $adminstore->set_folder($subfolder);
    $self->make_message("Email", store => $adminstore) or die;

    # Create the search database.
    xlog $self, "Run squatter";
    $self->{instance}->run_command({cyrus => 1}, 'squatter');

    my $basedir = $self->{instance}{basedir};
    open(FH, "-|", "find", $basedir);
    my @files = grep { m{/user/magicuser/} and not m{/conf/lock/} } <FH>;
    close(FH);

    xlog $self, "files exist";
    $self->assert_not_equals(0, scalar @files);

    $self->{instance}->run_command({ cyrus => 1 }, 'sync_reset', '-f' => 'magicuser' );

    open(FH, "-|", "find", $basedir);
    @files = grep { m{/user/magicuser/} and not m{/conf/lock/} } <FH>;
    close(FH);

    xlog $self, "no files left for this user";
    $self->assert_equals(0, scalar @files);
}

sub test_sync_reset_nolegacy
    :DelayedDelete :min_version_3_5 :NoMailboxLegacyDirs
{
    my ($self) = @_;

    my $adminstore = $self->{adminstore};
    my $admintalk = $adminstore->get_client();

    my $inbox = "user.magicuser";
    my $subfolder = "$inbox.foo";

    $admintalk->create($inbox);
    $admintalk->setacl($inbox, admin => 'lrswipkxtecdan');
    $admintalk->create($subfolder);
    $self->assert_str_equals('ok', $admintalk->get_last_completion_response());

    $adminstore->set_folder($subfolder);
    $self->make_message("Email", store => $adminstore) or die;

    # Create the search database.
    xlog $self, "Run squatter";
    $self->{instance}->run_command({cyrus => 1}, 'squatter');

    my $res = $admintalk->status($inbox, ['mailboxid']);
    my $inboxid = $res->{mailboxid}[0];
    $res = $admintalk->status($subfolder, ['mailboxid']);
    my $subid = $res->{mailboxid}[0];

    my $basedir = $self->{instance}{basedir};
    open(FH, "-|", "find", $basedir);
    my @files = grep { m{/uuid/} } <FH>;
    close(FH);

    xlog $self, "files exists";
    $self->assert(scalar grep { m{$inboxid} } @files);
    $self->assert(scalar grep { m{$subid} } @files);

    $self->{instance}->run_command({ cyrus => 1 }, 'sync_reset', '-f' => 'magicuser' );

    open(FH, "-|", "find", $basedir);
    @files = grep { m{/uuid/} } <FH>;
    close(FH);

    xlog $self, "ensure there's no files left matching either uuid!";
    $self->assert(not scalar grep { m{$inboxid} } @files);
    $self->assert(not scalar grep { m{$subid} } @files);
}

sub test_relocate_legacy_nodomain
    :DelayedDelete :min_version_3_5 :MailboxLegacyDirs
{
    my ($self) = @_;

    my $adminstore = $self->{adminstore};
    my $admintalk = $adminstore->get_client();

    my $inbox = "user.magicuser";
    my $subfolder = "user.magicuser.foo";

    $admintalk->create($inbox);
    $admintalk->setacl($inbox, admin => 'lrswipkxtecdan');
    $admintalk->create($subfolder);
    $self->assert_str_equals('ok', $admintalk->get_last_completion_response());

    $adminstore->set_folder($subfolder);
    $self->make_message("Email", store => $adminstore) or die;

    # Create the search database.
    xlog $self, "Run squatter";
    $self->{instance}->run_command({cyrus => 1}, 'squatter');

    my $basedir = $self->{instance}{basedir};
    open(FH, "-|", "find", $basedir);
    my @files = grep { m{/magicuser/} and not m{/conf/lock/} } <FH>;
    close(FH);

    xlog $self, "files exist";
    $self->assert_not_equals(0, scalar @files);

    $self->{instance}->run_command({ cyrus => 1 }, 'relocate_by_id', '-u' => "magicuser" );

    open(FH, "-|", "find", $basedir);
    @files = grep { m{/magicuser/} and not m{/conf/lock/} } <FH>;
    close(FH);

    xlog $self, "no files left for this user";
    $self->assert_equals(0, scalar @files);
}

sub test_relocate_legacy_domain
    :DelayedDelete :min_version_3_5 :MailboxLegacyDirs
{
    my ($self) = @_;

    my $adminstore = $self->{adminstore};
    my $admintalk = $adminstore->get_client();

    my $inbox = "user.magicuser\@example.com";
    my $subfolder = "user.magicuser.foo\@example.com";

    $admintalk->create($inbox);
    $admintalk->setacl($inbox, admin => 'lrswipkxtecdan');
    $admintalk->create($subfolder);
    $self->assert_str_equals('ok', $admintalk->get_last_completion_response());

    $adminstore->set_folder($subfolder);
    $self->make_message("Email", store => $adminstore) or die;

    # Create the search database.
    xlog $self, "Run squatter";
    $self->{instance}->run_command({cyrus => 1}, 'squatter');

    my $basedir = $self->{instance}{basedir};
    open(FH, "-|", "find", $basedir);
    my @files = grep { m{/magicuser/} and not m{/conf/lock/} } <FH>;
    close(FH);

    xlog $self, "files exist";
    $self->assert_not_equals(0, scalar @files);

    $self->{instance}->run_command({ cyrus => 1 }, 'relocate_by_id', '-u' => "magicuser\@example.com" );

    open(FH, "-|", "find", $basedir);
    @files = grep { m{/magicuser/} and not m{/conf/lock/} } <FH>;
    close(FH);

    xlog $self, "no files left for this user";
    $self->assert_equals(0, scalar @files);
}

sub test_relocate_legacy_nosearchdb
    :DelayedDelete :min_version_3_5 :MailboxLegacyDirs
{
    my ($self) = @_;

    my $adminstore = $self->{adminstore};
    my $admintalk = $adminstore->get_client();

    my $inbox = "user.magicuser\@example.com";
    my $subfolder = "user.magicuser.foo\@example.com";

    $admintalk->create($inbox);
    $admintalk->setacl($inbox, admin => 'lrswipkxtecdan');
    $admintalk->create($subfolder);
    $self->assert_str_equals('ok', $admintalk->get_last_completion_response());

    $adminstore->set_folder($subfolder);
    $self->make_message("Email", store => $adminstore) or die;

    # Don't create the search database!
    # A user who's never been indexed should still relocate cleanly

    my $basedir = $self->{instance}{basedir};
    open(FH, "-|", "find", $basedir);
    my @files = grep { m{/magicuser/} and not m{/conf/lock/} } <FH>;
    close(FH);

    xlog $self, "files exist";
    $self->assert_not_equals(0, scalar @files);

    $self->{instance}->run_command({ cyrus => 1 }, 'relocate_by_id', '-u' => "magicuser\@example.com" );

    open(FH, "-|", "find", $basedir);
    @files = grep { m{/magicuser/} and not m{/conf/lock/} } <FH>;
    close(FH);

    xlog $self, "no files left for this user";
    $self->assert_equals(0, scalar @files);

    # Hopefully squatter still works!
    xlog $self, "Run squatter";
    $self->{instance}->run_command({cyrus => 1}, 'squatter');
}

sub test_relocate_messages_still_exist
    :DelayedDelete :min_version_3_5 :MailboxLegacyDirs
{
    my ($self) = @_;

    my $adminstore = $self->{adminstore};
    my $admintalk = $adminstore->get_client();

    my $username = "magicuser\@example.com";

    $admintalk->create("user.$username");
    $admintalk->setacl("user.$username", admin => 'lrswipkxtecdan');
    $self->assert_str_equals('ok', $admintalk->get_last_completion_response());

    xlog $self, "Connect as the new user";
    my $svc = $self->{instance}->get_service('imap');
    $self->{store} = $svc->create_store(username => $username, folder => 'INBOX');
    $self->{store}->set_fetch_attributes('uid');
    my $imaptalk = $self->{store}->get_client();

    $self->make_message("Email 1") or die;
    $self->make_message("Email 2") or die;
    $self->make_message("Email xyzzy") or die;

    $imaptalk->create("INBOX.subfolder");
    $imaptalk->create("INBOX.subfolder2");

    $self->{store}->set_folder("INBOX.subfolder");
    $self->make_message("Email xyzzy") or die;

    $imaptalk->list('', '*', 'return', [ "status", [ "messages", "uidvalidity", "highestmodseq", "mailboxid" ] ]);
    my $prestatus = $imaptalk->get_response_code('status');

    # Create the search database.
    xlog $self, "Run squatter";
    $self->{instance}->run_command({cyrus => 1}, 'squatter');

    my $basedir = $self->{instance}{basedir};
    open(FH, "-|", "find", $basedir);
    my @files = grep { m{/magicuser/} and not m{/conf/lock/} } <FH>;
    close(FH);

    xlog $self, "files exist";
    $self->assert_not_equals(0, scalar @files);

    $self->{instance}->run_command({ cyrus => 1 }, 'relocate_by_id', '-u' => $username );

    open(FH, "-|", "find", $basedir);
    @files = grep { m{/magicuser/} and not m{/conf/lock/} } <FH>;
    close(FH);

    xlog $self, "no files left for this user";
    $self->assert_equals(0, scalar @files);

    $imaptalk = $self->{store}->get_client();

    $imaptalk->select("INBOX");
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
    my $exists = $imaptalk->get_response_code('exists');
    $self->assert_num_equals(3, $exists);
    my $msgs = $imaptalk->search("fuzzy", ["subject", { Quote => "xyzzy" }]) || die;
    $self->assert_num_equals(1, scalar @$msgs);

    $imaptalk->select("INBOX.subfolder");
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
    $exists = $imaptalk->get_response_code('exists');
    $self->assert_num_equals(1, $exists);
    $msgs = $imaptalk->search("fuzzy", ["subject", { Quote => "xyzzy" }]) || die;
    $self->assert_num_equals(1, scalar @$msgs);

    $imaptalk->select("INBOX.subfolder2");
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
    $exists = $imaptalk->get_response_code('exists');
    $self->assert_num_equals(0, $exists);
    $msgs = $imaptalk->search("fuzzy", ["subject", { Quote => "xyzzy" }]) || die;
    $self->assert_num_equals(0, scalar @$msgs);

    $imaptalk->list('', '*', 'return', [ "status", [ "messages", "uidvalidity", "highestmodseq", "mailboxid" ] ]);
    my $poststatus = $imaptalk->get_response_code('status');

    $self->assert_deep_equals($prestatus, $poststatus);
}

sub test_rename_quotaroot
    :AllowMoves :Replication :min_version_3_2
    :needs_component_jmap :JMAPExtensions
{
    my ($self) = @_;

    my $synclogfname = "$self->{instance}->{basedir}/conf/sync/log";

    my $admintalk = $self->{adminstore}->get_client();
    $admintalk->create('user.newuser@example.com');
    $admintalk->setacl('user.newuser@example.com', 'admin' => 'lrswipkxtecdan');
    $admintalk->setacl('user.newuser@example.com', 'newuser@example.com' => 'lrswipkxtecdan');
    $admintalk->setquota('user.newuser@example.com', [storage => 3000000]);

    my $newtalk = $self->{store}->get_client(username => 'newuser@example.com');
    $newtalk->create("INBOX.sub");
    $newtalk->create("INBOX.magic");

    $self->{adminstore}->set_folder('user.newuser.magic@example.com');
    $self->make_message("Message foo", store => $self->{adminstore});

    $self->run_replication(rolling => 1, inputfile => $synclogfname);
    $self->check_replication('newuser@example.com');
    unlink($synclogfname);

    $admintalk = $self->{adminstore}->get_client();
    $admintalk->rename('user.newuser@example.com', 'user.del@internal');

    $self->run_replication(rolling => 1, inputfile => $synclogfname);
    $self->check_replication('del@internal');
}

sub test_search_deleted_folder
    :DelayedDelete :min_version_3_5 :NoMailboxLegacyDirs
{
    my ($self) = @_;

    my $talk = $self->{store}->get_client();

    my $res = $self->_fmjmap_ok('Mailbox/get');
    my %m = map { $_->{name} => $_ } @{$res->{list}};
    my $inboxid = $m{"Inbox"}{id};
    $self->assert_not_null($inboxid);

    xlog $self, "Create the sub folders and emails";
    $talk->create("INBOX.sub");
    $talk->create("INBOX.extra");
    $self->make_message("Email abcd xyz hello 1") or die;
    $self->{store}->set_folder("INBOX.sub");
    $self->make_message("Email abcd xyz hello 2") or die;
    $self->{store}->set_folder("INBOX.extra");
    $self->make_message("Email abcd xyz hello 3") or die;

    # Create the search database.
    xlog $self, "Run squatter";
    $self->{instance}->run_command({cyrus => 1}, 'squatter');

    $res = $self->_fmjmap_ok('Email/query',
       filter => { text => "abcd", inMailboxOtherThan => [$inboxid] },
    );
    $self->assert_num_equals(2, scalar @{$res->{ids}});

    xlog $self, "Delete the sub folder";
    $talk->delete("INBOX.sub");

    xlog $self, "check that email can't be found";
    $res = $self->_fmjmap_ok('Email/query',
       filter => { text => "xyz", inMailboxOtherThan => [$inboxid] },
    );
    $self->assert_num_equals(1, scalar @{$res->{ids}});

    xlog $self, "use cyr_expire to clean up the deleted folder";
    $self->{instance}->run_command({ cyrus => 1 }, 'cyr_expire', '-D' => '0', '-a' );

    xlog $self, "check that email can't be found after folder deleted";
    $res = $self->_fmjmap_ok('Email/query',
       filter => { text => "hello", inMailboxOtherThan => [$inboxid] },
    );
    $self->assert_num_equals(1, scalar @{$res->{ids}});
}

1;

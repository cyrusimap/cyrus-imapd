# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Cyrus::FastMail;
use strict;
use warnings;
use DateTime;
use JSON::XS;
use Net::CalDAVTalk 0.09;
use Net::CardDAVTalk 0.05;
use Net::CardDAVTalk::VCard;
use Data::Dumper;
use Storable 'dclone';

use base qw(Cassandane::Cyrus::TestCase Cassandane::Mixin::QuotaHelper);
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
                 quotawarnpercent => '98',
                 reverseacls => 'yes',
                 rfc3028_strict => 'no',
                 savedate => 'yes',
                 servername => 'slot1',
                 sieve_extensions => 'fileinto reject vacation imapflags notify envelope body relational regex subaddress copy mailbox mboxmetadata servermetadata date index variables imap4flags editheader duplicate vacation-seconds fcc x-cyrus-jmapquery x-cyrus-snooze x-cyrus-log mailboxid special-use',
                 sieve_utf8fileinto => 'yes',
                 sieve_use_lmtp_reject => 'no',
                 sievenotifier => 'mailto',
                 sieve_maxscriptsize => '1024K',
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
                 event_extra_params => 'modseq vnd.fastmail.clientId service uidnext vnd.fastmail.sessionId vnd.cmu.envelope vnd.fastmail.convUnseen vnd.fastmail.convExists vnd.fastmail.cid vnd.cmu.mbtype vnd.cmu.davFilename vnd.cmu.davUid vnd.cmu.mailboxACL vnd.fastmail.counters messages vnd.cmu.unseenMessages flagNames vnd.cmu.emailid vnd.cmu.threadid vnd.cmu.visibleUsers',
                 event_groups => 'mailbox message flags calendar applepushservice',
                 event_notifier => 'pusher',
                 sync_log => 'yes',
    );

    my $self = $class->SUPER::new({
        config => $config,
        jmap => 1,
        deliver => 1,
        adminstore => 1,
        services => [ 'imap', 'http', 'sieve', 'backupcyrusd' ]
    }, @args);

    $self->needs('component', 'jmap');
    $self->needs('component', 'sieve');
    $self->needs('dependency', 'cld2');
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

# XXX Cheating and just passing in all the using strings that cyrus
# XXX recognises -- these were ripped from http_jmap.h, try to keep
# XXX them up to date! :)
sub default_using {
    return qw(
        urn:ietf:params:jmap:core
        urn:ietf:params:jmap:mail
        urn:ietf:params:jmap:submission
        https://cyrusimap.org/ns/jmap/blob
        urn:ietf:params:jmap:calendars
        https://cyrusimap.org/ns/jmap/contacts
        https://cyrusimap.org/ns/jmap/calendars
        https://cyrusimap.org/ns/jmap/mail
        https://cyrusimap.org/ns/jmap/performance
        https://cyrusimap.org/ns/jmap/debug
        https://cyrusimap.org/ns/jmap/quota
    );
}

# XXX This is here as documentation -- these ones are supported by
# XXX cyrus in some, but not all, configurations
# my @non_default_using = qw(
#     urn:ietf:params:jmap:vacationresponse
#     urn:ietf:params:jmap:websocket
# );

sub _fmjmap_req
{
    my ($self, $cmd, %args) = @_;
    my $jmap = delete $args{jmap} || $self->{jmap};

    my $rnum = "R" . $RNUM++;
    my $res = $jmap->CallMethods(
        [[$cmd, \%args, $rnum]],
        [ $self->default_using ],
    );
    $self->assert_not_null($res->[0]);
    $self->assert_str_equals($rnum, $res->[0][2]);
    return $res->[0];
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

use Cassandane::Tiny::Loader 'tiny-tests/FastMail';

1;

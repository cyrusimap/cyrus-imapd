# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Cyrus::FastMail;
use strict;
use warnings;
use DateTime;
use JSON::XS;
use Net::CalDAVTalk 0.14;
use Net::CardDAVTalk 0.11;
use Text::JSContact 0.01 qw(vcard_to_jscontact);
use Data::Dumper;
use Storable 'dclone';
use Cyrus::Backup;
use Cyrus::Backup::Restore;
use Cyrus::Backup::State;

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
                 autoexpunge => 'yes',
                 caldav_allowattach => 'no',
                 caldav_allowscheduling => 'yes',
                 caldav_create_attach => 'no',
                 caldav_create_default => 'no',
                 caldav_create_sched => 'yes',
                 caldav_realm => 'FastMail',
                 calendar_component_set => 'VEVENT',
                 crossdomains => 'yes',
                 crossdomains_onlyother => 'yes',
                 annotation_allow_undefined => 'yes',
                 conversations => 'yes',
                 conversations_counted_flags => '\\Draft \\Flagged \\Answered $followed $muted',
                 conversations_max_thread => '100',
                 mailbox_initial_flags => '$X-ME-Annot-2 $IsMailingList $IsNotification $HasAttachment $IsTrusted $MaskedEmail $MDNSent $Forwarded $Junk $NotJunk $Phishing $Important $SieveFailed $new $CanUnsubscribe $followed $muted $hasmemo',
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
                 implicit_owner_rights => 'lkan',
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
                 sieve_extensions => 'fileinto reject vacation notify envelope body relational regex subaddress copy mailbox mboxmetadata servermetadata date index variables imap4flags editheader duplicate vacation-seconds fcc vnd.cyrus.jmapquery vnd.cyrus.log mailboxid special-use snooze processcalendar vnd.cyrus.implicit_keep_target',
                 sieve_utf8fileinto => 'yes',
                 sieve_use_lmtp_reject => 'no',
                 sievenotifier => 'mailto',
                 sieve_maxscriptsize => '1024K',
                 sieve_vacation_min_response => '60',
                 specialusealways => 'yes',
                 specialuse_extra => '\\XChats \\XTemplates \\XNotes',
                 statuscache => 'on',
                 subscription_db => 'flat',
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
        services => [ 'imap', 'http', 'sieve' ]
    }, @args);

    $self->needs('component', 'jmap');
    $self->needs('component', 'sieve');
    $self->needs('dependency', 'cld2');
    return $self;
}

sub jmap_default_using
{
    return [
        'urn:ietf:params:jmap:core',
        'urn:ietf:params:jmap:mail',
        'urn:ietf:params:jmap:submission',
    ];
}

# XXX Cheating and just passing in all the using strings that cyrus
# XXX recognises -- these were ripped from http_jmap.h, try to keep
# XXX them up to date! :)
sub default_using {
    return qw(
        urn:ietf:params:jmap:core
        urn:ietf:params:jmap:mail
        urn:ietf:params:jmap:submission
        urn:ietf:params:jmap:blob
        urn:ietf:params:jmap:calendars
        urn:ietf:params:jmap:contacts
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

# Route Cyrus::Backup's chatter into the cassandane log when running verbose
package Cassandane::Cyrus::FastMail::BackupLogger {
    sub log
    {
        my (undef, $msg) = @_;
        if (ref $msg eq 'ARRAY') {
            my ($fmt, @args) = @$msg;
            $msg = sprintf($fmt, @args);
        }
        Cassandane::Util::Log::xlog($msg);
    }
    *log_debug = \&log;
    sub log_event {}
    sub log_debug_event {}
}

# Create the meta and data directories a backup needs, and return them
# along with everything needed to talk to this instance's backupcyrusd.
sub _backup_dirs
{
    my ($self) = @_;

    my $service = $self->{instance}->get_service('backupcyrusd');

    my $meta = "$self->{instance}->{basedir}/backupmeta";
    my $data = "$self->{instance}->{basedir}/backupdata";
    mkdir($meta);
    mkdir($data);

    $Cyrus::Backup::LOGGER_CB = sub { 'Cassandane::Cyrus::FastMail::BackupLogger' }
        if $self->{store}->{verbose};

    return ($service->host, $service->port,
            $self->{instance}->get_servername, $meta, $data);
}

# The uniqueid cyrus knows a folder by, which is also how the backup
# names the folder's directory in the tar file.
sub _mailbox_uniqueid
{
    my ($self, $folder) = @_;

    my $entry = '/shared/vendor/cmu/cyrus-imapd/uniqueid';
    my $talk = $self->{store}->get_client();
    my $res = $talk->getmetadata($folder, $entry);
    $self->assert_str_equals('ok', $talk->get_last_completion_response());
    $self->assert_not_null($res->{$folder}{$entry});

    return $res->{$folder}{$entry};
}

# Every mailbox cyrus has for a user, as { extname => uniqueid }, which is
# what a complete backup's folder list should look like.  Only valid with
# altnamespace off, which is how this suite configures cyrus.
sub _mailboxes_by_extname
{
    my ($self, $userid) = @_;
    $userid ||= 'cassandane';

    my $mboxes = $self->{instance}->read_mailboxes_db();

    my %res;
    foreach my $intname (keys %$mboxes) {
        my $extname = $intname;
        next unless $extname =~ s{^user\.\Q$userid\E(\.|$)}{INBOX$1};
        # tombstones ('d') and intermediates ('i') aren't real folders, and
        # mboxlist_usermboxtree doesn't hand them to backupcyrusd
        next if $mboxes->{$intname}{mbtype} =~ m/[di]/;
        $res{$extname} = $mboxes->{$intname}{uniqueid};
    }

    return \%res;
}

# Summarise what a backup contains, by joining up the tables of its state
# database into something a test can make readable assertions about:
#
#  {
#    names   => { $foldername => $uniqueid },      # live folders only
#    folders => { $uniqueid => { folderid => $id,
#                                uniqueid => $uniqueid,
#                                names => { $foldername => $deleted },
#                                meta => { index => {...}, header => {...} },
#                                uids => { $uid => $guid } } },
#    meta    => { seen => {...}, sub => {...} },   # per-user files
#    files   => { $guid => { size => $n, refcount => $n } },
#  }
sub _backup_content
{
    my ($self, $meta, $statefile) = @_;
    $statefile ||= 'backupstate.sqlite3';

    my $state = Cyrus::Backup::State->new($meta, $statefile);
    my $dbh = $state->dbh();

    my %res = (names => {}, folders => {}, meta => {}, files => {});

    my %byid;
    foreach my $row (@{$dbh->selectall_arrayref(
        "SELECT folderid, uniqueid FROM folders", { Slice => {} })})
    {
        my $folder = {
            folderid => $row->{folderid},
            uniqueid => $row->{uniqueid},
            names => {},
            meta => {},
            uids => {},
        };
        $byid{$row->{folderid}} = $folder;
        $res{folders}{$row->{uniqueid}} = $folder;
    }

    # a name may appear more than once as folders are deleted and recreated,
    # so walk them in the order they were backed up and let later win
    foreach my $row (@{$dbh->selectall_arrayref(
        "SELECT name, folderid, deleted FROM imap ORDER BY offset",
        { Slice => {} })})
    {
        my $folder = $byid{$row->{folderid}};
        next unless $folder;
        $folder->{names}{$row->{name}} = $row->{deleted};
        if ($row->{deleted}) {
            delete $res{names}{$row->{name}};
        }
        else {
            $res{names}{$row->{name}} = $folder->{uniqueid};
        }
    }

    foreach my $row (@{$dbh->selectall_arrayref(
        "SELECT folderid, name, sha1, size, mtime, inode, stale FROM fmeta",
        { Slice => {} })})
    {
        my $folder = $byid{$row->{folderid}};
        next unless $folder;
        $folder->{meta}{$row->{name}} = $row;
    }

    foreach my $row (@{$dbh->selectall_arrayref(
        "SELECT indexed.folderid, indexed.uid, files.guid
           FROM indexed JOIN files USING (fileid)", { Slice => {} })})
    {
        my $folder = $byid{$row->{folderid}};
        next unless $folder;
        $folder->{uids}{$row->{uid}} = $row->{guid};
    }

    foreach my $row (@{$dbh->selectall_arrayref(
        "SELECT guid, size, refcount FROM files", { Slice => {} })})
    {
        $res{files}{$row->{guid}} = $row;
    }

    # the meta table is keyed on (type, name), but 'annot' and 'sieve' are
    # legacy types that nothing writes any more, so name alone will do
    foreach my $row (@{$dbh->selectall_arrayref(
        "SELECT type, name, sha1, size, mtime, inode, stale FROM meta",
        { Slice => {} })})
    {
        $res{meta}{$row->{name}} = $row;
    }

    $state->cancel();

    return \%res;
}

# Just the structure of a _backup_content, without the bookkeeping that
# legitimately differs between two states describing the same content
# (folderids, offsets, staleness counters, timestamps).
sub _backup_summary
{
    my ($self, $content) = @_;

    my %res = (
        names => $content->{names},
        meta => [sort keys %{$content->{meta}}],
        folders => {},
        files => {},
    );

    foreach my $uniqueid (keys %{$content->{folders}}) {
        my $folder = $content->{folders}{$uniqueid};
        $res{folders}{$uniqueid} = {
            names => $folder->{names},
            uids => $folder->{uids},
            meta => [sort keys %{$folder->{meta}}],
        };
    }

    foreach my $guid (keys %{$content->{files}}) {
        $res{files}{$guid} = $content->{files}{$guid}{refcount};
    }

    return \%res;
}

# Extract a message from the backup's tar file and return its bytes.
sub _backup_file
{
    my ($self, $meta, $guid) = @_;

    my $restore = Cyrus::Backup::Restore->new($meta);
    $restore->GetFile($guid);

    # GetFile returns bare guids rather than paths when the file has
    # already been extracted, so work out the path ourselves
    my $path = "$meta/files/$guid";
    return undef unless -f $path;

    open(my $fh, '<', $path) or die "can't read $path: $!";
    local $/ = undef;
    my $content = <$fh>;
    close($fh);

    return $content;
}

use Cassandane::Tiny::Loader;

1;

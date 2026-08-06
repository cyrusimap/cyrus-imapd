# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Cyrus::MailboxVersion;
use strict;
use warnings;
use DateTime;
use JSON::XS;
use Net::CalDAVTalk 0.14;
use Net::CardDAVTalk 0.11;
use Data::Dumper;
use Storable 'dclone';
use MIME::Base64 qw(encode_base64 encode_base64url decode_base64url);
use Encode qw(decode_utf8);
use Cwd qw(abs_path getcwd);
use POSIX qw(mktime);

use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;
use Cassandane::Util::Slurp;

use charnames ':full';

sub new
{
    my ($class, @args) = @_;

    my $config = Cassandane::Config->default()->clone();
    $config->set(caldav_realm => 'Cassandane',
                 conversations => 'yes',
                 httpmodules => 'carddav caldav jmap',
                 imipnotifier => 'imip',
                 jmap_max_size_upload => '1k',
                 jmap_nonstandard_extensions => 'yes',
                 jmapsubmission_deleteonsend => 'no',
                 httpallowcompress => 'no',
                 notesmailbox => 'Notes');

    # Configure Sieve iMIP delivery
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
    $config->set(calendar_user_address_set => 'example.com');
    $config->set(caldav_historical_age => -1);

    my $self = $class->SUPER::new({
        config => $config,
        jmap => 1,
        adminstore => 1,
        replica => 1,
        services => [ 'imap', 'http', 'sieve' ],
        deliver => 1,
        smtpdaemon => 1,
    }, @args);

    $self->needs('component', 'jmap');

    return $self;
}

sub jmap_default_using
{
    return [
        'urn:ietf:params:jmap:calendars',
        'urn:ietf:params:jmap:calendars:preferences',
        'urn:ietf:params:jmap:core',
        'urn:ietf:params:jmap:mail',
        'urn:ietf:params:jmap:principals',
        'urn:ietf:params:jmap:quota',
        'urn:ietf:params:jmap:sieve',
        'urn:ietf:params:jmap:submission',
        'urn:ietf:params:jmap:vacationresponse',
        'urn:ietf:params:jmap:contacts',
        'https://cyrusimap.org/ns/jmap/backup',
        'urn:ietf:params:jmap:blob',
        'https://cyrusimap.org/ns/jmap/contacts',
        'https://cyrusimap.org/ns/jmap/notes',
        'https://cyrusimap.org/ns/jmap/debug',
        'https://cyrusimap.org/ns/jmap/mail',
    ];
}

sub upgrade_19_to_20
{
    my ($self, $user) = @_;

    {
        $user //= "cassandane";

        xlog $self, "Upgrade master mailbox version 19 -> 20 for $user";

        my $res = $self->{instance}->run_command_capture(
            { cyrus => 1 },
            qw(reconstruct -V 20 -u), $user,
        );

        $self->assert_num_equals(0, $res->status);
        $self->assert_str_equals("", $res->stderr);

        my @lines = split(/\n/, $res->stdout);
        $self->assert_num_not_equals(0, 0+@lines);

        my $user_lp = $user =~ s/@.*//r;

        for my $line (@lines) {
            $self->assert_matches(
                qr/^Converted (DELETED\.)?user\.$user(\.[^\s]+)? version 19 to 20/,
                $line
            );
        }
    }

    {
        xlog $self, "Upgrade master to conv.db version 1 -> 2 for $user";

        my $res = $self->{instance}->run_command_capture(
            { cyrus => 1 },
            qw(ctl_conversationsdb -U), $user,  qw(-v),
        );

        $self->assert_num_equals(0, $res->status);
        $self->assert_str_equals("", $res->stderr);

        my @lines = split(/\n/, $res->stdout);
        $self->assert_num_not_equals(0, 0+@lines);

        for my $line (@lines) {
            $self->assert_matches(qr/^user.$user(\.|$)/, $line);
        }
    }

    $self->enable_compact_ids($user);

    # Replica gets created at version 20 / mailbox version 2 so can't test...
}

# This currently *only* downgrades the mailbox, it does not downgrade the
# conversations db!
sub downgrade_20_to_19
{
    my ($self, $user) = @_;

    {
        $user //= "cassandane";

        xlog $self, "Downgrade master mailbox version 20 -> 19 for $user";

        my $res = $self->{instance}->run_command_capture(
            { cyrus => 1 },
            qw(reconstruct -V 19 -u), $user,
        );

        $self->assert_num_equals(0, $res->status);
        $self->assert_str_equals("", $res->stderr);

        my @lines = split(/\n/, $res->stdout);
        $self->assert_num_not_equals(0, 0+@lines);

        my $user_lp = $user =~ s/@.*//r;

        for my $line (@lines) {
            next if $line =~ /^FAILED TO REPACK DELETED\.user\.$user\./;
            $self->assert_matches(
                qr/^Converted user\.$user(\.[^\s]+)? version 20 to 19/,
                $line
            );
        }
    }
}

sub enable_compact_ids
{
    my ($self, $user) = @_;

    $user //= "cassandane";

    xlog $self, "Turn on compact ids for $user";

    my $res = $self->{instance}->run_command_capture(
        { cyrus => 1 },
        qw(ctl_conversationsdb -v -I on), $user,
    );

    $self->assert_num_equals(0, $res->status);
    $self->assert_str_equals("", $res->stdout);
    $self->assert_str_equals("", $res->stderr);
}

sub disable_compact_ids
{
    my ($self, $user) = @_;

    $user //= "cassandane";

    xlog $self, "Turn off compact ids for $user";

    my $res = $self->{instance}->run_command_capture(
        { cyrus => 1 },
        qw(ctl_conversationsdb -v -I off), $user,
    );

    $self->assert_num_equals(0, $res->status);
    $self->assert_str_equals("", $res->stdout);
    $self->assert_str_equals("", $res->stderr);
}

# Returns true if the $COMPACT_EMAILIDS key is present in the user's
# conversations database on the given instance, which is not the same question
# as whether the user gets compact ids: with "compact_ids: always" configured,
# a user with no key still gets them.
sub compact_ids_key_is_set
{
    my ($self, $user, $instance) = @_;

    $user //= "cassandane";
    $instance //= $self->{instance};

    my $outfile = $instance->{basedir} . "/conv-dump-$user.txt";

    $instance->run_command({ cyrus => 1,
                             redirects => { stdout => $outfile } },
                           'ctl_conversationsdb', '-d', $user);

    return slurp_file($outfile) =~ m/^\$COMPACT_EMAILIDS\t/m ? 1 : 0;
}

# Remove the key behind Cyrus's back, the way a stray replication event or a
# database rebuild might.
sub delete_compact_ids_key
{
    my ($self, $user, $instance) = @_;

    $user //= "cassandane";
    $instance //= $self->{instance};

    xlog $self, "Delete the \$COMPACT_EMAILIDS key for $user";

    my $dbfile = $instance->get_conf_user_file($user, 'conversations');
    my $engine = $instance->{config}->get('conversations_db');

    $instance->run_dbcommand($dbfile, $engine,
                             [ 'DELETE', '$COMPACT_EMAILIDS' ]);
}

# Assert that the ids the server hands out for the first message in the
# mailbox have the given shape.  Ids are computed at read time, so the same
# message answers to a different id once the setting changes.
sub assert_email_id_shape
{
    my ($self, $want) = @_;

    my %prefix = (compact => [ 'S', 'A' ], legacy => [ 'M', 'T' ]);
    my $prefix = $prefix{$want} or die "unknown id shape '$want'";

    my $res = $self->{jmap}->CallMethods([
        [ 'Email/query', {}, 'R1' ],
        [ 'Email/get', {
            '#ids' => {
                resultOf => 'R1', name => 'Email/query', path => '/ids',
            },
            properties => [ 'threadId' ],
        }, 'R2' ],
    ]);

    my $email = $res->[1][1]{list}[0];
    $self->assert_not_null($email);
    $self->assert_matches(qr/^$prefix->[0]/, $email->{id});
    $self->assert_matches(qr/^$prefix->[1]/, $email->{threadId});
}

sub lookup_email_id
{
    my ($self, $oldid) = @_;

    my $res = $self->{jmap}->CallMethods([
        ['Email/lookup', {
            oldIds => [ $oldid ]
         }, "R1"]
    ]);

    my $new_id = $res->[0][1]->{ids}{$oldid};

    $self->assert_not_null($new_id);

    return $new_id;
}

sub index_file_for {
    my ($self, $mailbox) = @_;

    my $dir = $self->{instance}->folder_to_directory($mailbox);
    my $file = "$dir/cyrus.index";
    my $fh = IO::File->new($file, "+<");
    die "NO SUCH FILE $file? ($!)" unless $fh;

    xlog $self, "Reading index of $mailbox ($file)";

    my $index = Cyrus::IndexFile->new($fh, strict_crc => 1);

    # Log the contents to help debug failures later...
    xlog $self, "Header: " . $index->header_longdump;

    my $i = 0;

    while (my $rec = $index->next_record) {
        xlog $self, "Record $i: " . $index->record_longdump;

        $i++;
    }

    $index->reset;

    return $index;
}

sub index_file_records {
    my ($self, $index) = @_;

    my @recs;

    while (my $rec = $index->next_record) {
        $rec->{SystemFlags} = {
            map {
                $_ => 1,
            } keys %{ $index->system_flags }
        };

        push @recs, $rec;
    }

    return @recs;
}

sub sentdate_ts {
    my ($self, $seconds) = @_;

    my @lt = localtime($seconds);

    # zero out sec/min/hour to truncate to day
    $lt[0] = $lt[1] = $lt[2] = 0;

    # Cyrus stores sentdate offset by local timezone, not UTC, so we need
    # mktime to calculate that for us like cyrus does
    return mktime(@lt);
}

use Cassandane::Tiny::Loader;

1;

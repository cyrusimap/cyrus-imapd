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

package Cassandane::Cyrus::MailboxVersion;
use strict;
use warnings;
use DateTime;
use JSON::XS;
use Net::CalDAVTalk 0.09;
use Net::CardDAVTalk 0.03;
use Mail::JMAPTalk 0.15;
use Data::Dumper;
use Storable 'dclone';
use MIME::Base64 qw(encode_base64);
use Encode qw(decode_utf8);
use Cwd qw(abs_path getcwd);

use lib '.';
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

sub set_up
{
    my ($self) = @_;

    $self->SUPER::set_up();

    $self->{jmap}->DefaultUsing([
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
        'https://cyrusimap.org/ns/jmap/blob',
        'https://cyrusimap.org/ns/jmap/contacts',
        'https://cyrusimap.org/ns/jmap/notes',
    ]);
}

sub upgrade_19_to_20
{
    my ($self) = @_;

    {
        xlog $self, "Upgrade master mailbox version 19 -> 20";

        my $res = $self->{instance}->run_command_capture(
            { cyrus => 1 },
            qw(reconstruct -V 20 -u cassandane),
        );

        $self->assert_num_equals(0, $res->status);
        $self->assert_str_equals("", $res->stderr);

        my @lines = split(/\n/, $res->stdout);
        $self->assert_num_not_equals(0, 0+@lines);

        for my $line (@lines) {
            $self->assert_matches(
                qr/^Converted user.cassandane.* 19 to 20/,
                $line
            );
        }
    }

    {
        xlog $self, "Upgrade master to conv.db version 1 -> 2";

        my $res = $self->{instance}->run_command_capture(
            { cyrus => 1 },
            qw(ctl_conversationsdb -U cassandane -v),
        );

        $self->assert_num_equals(0, $res->status);
        $self->assert_str_equals("", $res->stderr);

        my @lines = split(/\n/, $res->stdout);
        $self->assert_num_not_equals(0, 0+@lines);

        for my $line (@lines) {
            $self->assert_matches(qr/^user.cassandane(\.|$)/, $line);
        }
    }

    # Replica gets created at version 20 / mailbox version 2 so can't test...
}

use Cassandane::Tiny::Loader 'tiny-tests/MailboxVersion';

1;

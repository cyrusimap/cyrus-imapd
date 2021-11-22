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
#       Opera Software Australia Pty. Ltd.
#       Level 50, 120 Collins St
#       Melbourne 3000
#       Victoria
#       Australia
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

use strict;
use warnings;
use DateTime;
use URI::Escape;

use lib '.';
use Cassandane::Generator;
use Cassandane::Util::DateTime qw(to_iso8601 from_iso8601
                                  from_rfc822
                                  to_rfc3501 from_rfc3501);
use Cassandane::MessageStoreFactory;

sub usage
{
    die "Usage: pop3showafter.pl";
}

my $verbose = 1;
# Connection information for the IMAP server
my $imapport = 2143;
my $pop3port = 2110;
my %store_params = (
        host => '127.0.0.2',
        folder => 'inbox.showaftertestXX',
        username => 'test@vmtom.com',
        password => 'testpw',
        verbose => $verbose,
    );

#
# Given a set of messages downloaded via either IMAP
# or POP protocols, check them for consistency, using
# rules encoded in genmail.pl.
#
sub check_messages($$$$)
{
    my ($store, $expected_nmsgs, $expect_internaldate, $cutoff_dt) = @_;
    my $nmsgs = 0;

    $store->read_begin();
    while (my $msg = $store->read_message())
    {
        $nmsgs++;

        if ($verbose)
        {
            printf "[%u]\n", $nmsgs;
            printf "    message-id=\"%s\"\n", $msg->get_header('Message-ID');
            printf "    from=\"%s\"\n", $msg->get_header('From');
        }

        my $internal_dt;
        my $datehdr_dt;
        my $subject_dt;
        my $d;

        # Check that the Date: header is present and well formed.
        $d = $msg->get_header('Date');
        $datehdr_dt = from_rfc822($d)
            or die "Bogus RFC822 time in Date header \"$d\"";
        printf "    date=\"%s\" -> %u\n", $d, $datehdr_dt->epoch() if $verbose;

        # Check that the Subject: header is present and
        # encodes a datetime in ISO8601 format, as generated
        my $s = $msg->get_header('Subject');
        ($d) = ($s =~ m/^message at (\S*)$/)
            or die "Bogus Subject header \"$s\"";
        $subject_dt = from_iso8601($d)
            or die "Bogus ISO8601 time in Subject \"$s\"";
        printf "    subject=\"%s\" -> %u\n", $s, $subject_dt->epoch() if $verbose;

        if ($expect_internaldate)
        {
            # Check that an internaldate field is present and well formed.
            $internal_dt = from_rfc3501($msg->get_attribute('internaldate'));
            die "No or bogus INTERNALDATE"
                unless defined $internal_dt;
            printf "    internaldate=%u\n", $internal_dt->epoch() if $verbose;
        }
        else
        {
            # For convenience, pretend the internal date was here
            $internal_dt = $datehdr_dt;
        }

        # Check that all three of the dates match exactly.
        # If this fails, something has gone awry with the
        # dataset generation in genmail.pl.
        die "Invalid message: times don't match"
            unless ($internal_dt->epoch() == $datehdr_dt->epoch() &&
                    $datehdr_dt->epoch() == $subject_dt->epoch());

        if (defined($cutoff_dt))
        {
            die "Incorrectly found message before cutoff time " .  $cutoff_dt->epoch()
                unless ($internal_dt->epoch() > $cutoff_dt->epoch());
        }
    }
    $store->read_end();

    die "Wrong number of messages, got $nmsgs, expecting $expected_nmsgs"
        unless (!defined $expected_nmsgs || $nmsgs == $expected_nmsgs);

    return 1;
}

#
# Check the value of the pop3-show-after annotation
#
my $showafter_anno = '/private/vendor/cmu/cyrus-imapd/pop3showafter';

sub get_pop3showafter
{
    my ($store) = @_;

    my $annos = $store->get_client()->getmetadata($store->{folder}, $showafter_anno)
        or die "Cannot get annotation $showafter_anno: $@";

    if ($annos eq "Completed")
    {
        return "NIL";
    }

    my $aa = $annos->{$store->{folder}}->{$showafter_anno};
    die "No data for annotation $showafter_anno"
        unless defined $aa;
    die "Wrong content-type for annotation $showafter_anno: " . $aa->{'content-type.shared'}
        unless ($aa->{'content-type.shared'} eq 'text/plain');
    return $aa->{'value.shared'};
}

sub set_pop3showafter
{
    my ($store, $val) = @_;

    $store->get_client()->setannotation($store->{folder}, $showafter_anno, [ 'value.shared', $val ])
        or die "Setting annotation $showafter_anno failed: $@";

    my $newval = get_pop3showafter($store);
    die "Set $showafter_anno is not reflected in get: got \"$newval\" expecting \"$val\""
        unless ($newval eq $val);
}

my $imap_store = Cassandane::MessageStoreFactory->create(
                        type => 'imap',
                        port => $imapport,
                        %store_params
                    );
$imap_store->set_fetch_attributes('uid', 'internaldate');
my $pop3_store = Cassandane::MessageStoreFactory->create(
                        type => 'pop3',
                        port => $pop3port,
                        %store_params
                    );

my $now = DateTime->now()->epoch();
my $cutoff_dt = DateTime->from_epoch(epoch => $now - 86400/2);
my $gen = Cassandane::Generator->new();

printf "removing folder\n" if $verbose;
$imap_store->remove();
printf "generating messages\n" if $verbose;
$imap_store->write_begin();
my $expected_nmsgs_all = 0;
my $expected_nmsgs_after = 0;
for (my $offset = -86400 ; $offset <= 0 ; $offset += 3600)
{
    my $then = DateTime->from_epoch(epoch => $now + $offset);
    my $msg = $gen->generate(
        date => $then,
        subject => "message at " . to_iso8601($then),
    );
    $imap_store->write_message($msg);

    $expected_nmsgs_all++;
    $expected_nmsgs_after++
        if ($then->epoch() > $cutoff_dt->epoch());
}
$imap_store->write_end();

printf "Checking messages for validity...\n" if $verbose;
check_messages($imap_store, $expected_nmsgs_all, 1, undef);

printf "Testing that by default POP gives us all the messages...\n"
    if $verbose;
check_messages($pop3_store, $expected_nmsgs_all, 0, undef);

printf "Testing that after setting $showafter_anno, POP gives the correct subset of messages...\n";
set_pop3showafter($imap_store, to_rfc3501($cutoff_dt));
check_messages($pop3_store, $expected_nmsgs_after, 0, $cutoff_dt);

printf "Testing that after clearing $showafter_anno again, POP gives us all the messages...\n";
set_pop3showafter($imap_store, 'NIL');
check_messages($pop3_store, $expected_nmsgs_all, 0, undef);

printf "done\n" if $verbose;

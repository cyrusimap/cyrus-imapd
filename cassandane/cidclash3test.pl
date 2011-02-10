#!/usr/bin/perl
#
# Test APPEND of messages to IMAP which results in multiple CID clashes.
#

use strict;
use warnings;
use DateTime;
use URI::Escape;
use Digest::SHA1 qw(sha1_hex);
use Cassandane::Generator;
use Cassandane::Util::DateTime qw(to_iso8601 from_iso8601
				  from_rfc822
				  to_rfc3501 from_rfc3501);
use Cassandane::MessageStoreFactory;

sub usage
{
    die "Usage: cidclash3test.pl";
}

my $verbose = 1;
# Connection information for the IMAP server
my %store_params = (
	type => 'imap',
	host => '127.0.0.2',
	port => 2143,
	folder => 'inbox.cidclashtest',
	username => 'test@vmtom.com',
	password => 'testpw',
	verbose => $verbose,
    );

# Calculate a CID from a message - this is the CID that the
# first message in a new conversation will be assigned.
sub calc_cid
{
    my ($msg) = @_;
    return substr(sha1_hex($msg->as_string()), 0, 16);
}

# The resulting CID when a clash happens is supposed to be
# the MAXIMUM of all the CIDs.  Here we use the fact that
# CIDs are expressed in a form where lexical order is the
# same as numeric order.
sub choose_cid
{
    my (@cids) = @_;
    @cids = sort { $b cmp $a } @cids;
    printf("choose_cid: chose %s from (%s)\n",
	   $cids[0], join(' ', @cids)) if $verbose;
    return $cids[0];
}

sub make_message
{
    my ($gen, $store, $subject, @attrs) = @_;

    $store->write_begin();
    my $msg = $gen->generate(subject => $subject, @attrs);
    $store->write_message($msg);
    $store->write_end();

    return $msg;
}

sub check_messages
{
    my ($store, $expected, $context, $all_cid) = @_;
    my $actual = {};

    $store->read_begin();
    while (my $msg = $store->read_message())
    {
	my $subj = $msg->get_header('subject');
	die "Two messages with the same subject $context"
	    if defined $actual->{$subj};
	$actual->{$subj} = $msg;
    }
    $store->read_end();

    die "Wrong number of messages in folder $context"
	unless scalar keys %$actual == scalar keys %$expected;

    foreach my $expmsg (values %$expected)
    {
	my $subj = $expmsg->get_header('subject');
	my $actmsg = $actual->{$subj};

	die "$subj missing $context"
	    unless defined $actmsg;

	die "$subj has no CID $context"
	    unless defined $actmsg->get_attribute('cid');

	my $cid = (defined $all_cid ? $all_cid : calc_cid($actmsg));

	die "$subj has unexpected CID $context"
	    unless $actmsg->get_attribute('cid') eq $cid;

	die "$subj has no unique $context"
	    unless defined $actmsg->get_header('x-cassandane-unique');

	die "$subj has unexpected unique $context"
	    unless $actmsg->get_header('x-cassandane-unique') eq
		   $expmsg->get_header('x-cassandane-unique');
    }

    return $actual;
}


my $imap_store = Cassandane::MessageStoreFactory->create(%store_params);
$imap_store->set_fetch_attributes('uid', 'cid');
my $gen = Cassandane::Generator->new();
my $expected = {};

die "IMAP server does not have the XCONVERSATIONS capability"
    unless $imap_store->get_client()->capability()->{xconversations};

printf "removing folder\n" if $verbose;
$imap_store->remove();

printf "generating message A\n" if $verbose;
$expected->{A} = make_message($gen, $imap_store, "Message A");
check_messages($imap_store, $expected, "(after A)");

printf "generating message B\n" if $verbose;
$expected->{B} = make_message($gen, $imap_store, "Message B");
check_messages($imap_store, $expected, "(after B)");

printf "generating message C\n" if $verbose;
$expected->{C} = make_message($gen, $imap_store, "Message C");
my $actual = check_messages($imap_store, $expected, "(after C)");

printf "generating message D\n" if $verbose;
$expected->{D} = make_message($gen, $imap_store,
			     "Message D",
			     references =>
				   $expected->{A}->get_header('message-id') .  ", " .
				   $expected->{B}->get_header('message-id') .  ", " .
				   $expected->{C}->get_header('message-id'),
			     );
my $ElCid = choose_cid(
		calc_cid($actual->{'Message A'}),
		calc_cid($actual->{'Message B'}),
		calc_cid($actual->{'Message C'})
	    );
check_messages($imap_store, $expected, "(after D)", $ElCid);


printf "done\n" if $verbose;

#!/usr/bin/perl
#
# Test interaction between CID clashes and replication
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
    die "Usage: cidclashrepltest.pl";
}

my $verbose = 1;
# Connection information for the IMAP server
my %master_params = (
	type => 'imap',
	host => 'slott02',
	port => 2144,
	folder => 'inbox.cidclashtest',
	username => 'test@vmtom.com',
	password => 'testpw',
	verbose => $verbose,
    );
my %replica_params = ( %master_params, host => 'slott01' );

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


my $master_store = Cassandane::MessageStoreFactory->create(%master_params);
my $replica_store = Cassandane::MessageStoreFactory->create(%replica_params);
$master_store->set_fetch_attributes('uid', 'cid');
$replica_store->set_fetch_attributes('uid', 'cid');
my $gen = Cassandane::Generator->new();
my $expected = {};

# Double check that we're connected to the servers
# we wanted to be connected to.
die "Did not connect to expected master IMAP server"
    unless $master_store->get_server_name() eq $master_params{host};
die "Did not connect to expected replace IMAP server"
    unless $replica_store->get_server_name() eq $replica_params{host};

die "Master IMAP server does not have the XCONVERSATIONS capability"
    unless $master_store->get_client()->capability()->{xconversations};
die "Replica IMAP server does not have the XCONVERSATIONS capability"
    unless $replica_store->get_client()->capability()->{xconversations};

printf "removing folder\n" if $verbose;
$master_store->remove();

printf "generating message A\n" if $verbose;
$expected->{A} = make_message($gen, $master_store, "Message A");
sleep(3);   # let the replication catch up
check_messages($master_store, $expected, "(master after A)");
check_messages($replica_store, $expected, "(replica after A)");


printf "generating message C\n" if $verbose;
printf "generating message B\n" if $verbose;
$expected->{B} = make_message($gen, $master_store, "Message B");
sleep(3);   # let the replication catch up
check_messages($master_store, $expected, "(master after B)");
check_messages($replica_store, $expected, "(replica after B)");


printf "generating message C\n" if $verbose;
$expected->{C} = make_message($gen, $master_store, "Message C");
sleep(3);   # let the replication catch up
my $actual = check_messages($master_store, $expected, "(master after C)");
check_messages($replica_store, $expected, "(replica after C)");


printf "generating message D\n" if $verbose;
$expected->{D} = make_message($gen, $master_store,
			     "Message D",
			     references =>
				   $expected->{A}->get_header('message-id') .  ", " .
				   $expected->{B}->get_header('message-id') .  ", " .
				   $expected->{C}->get_header('message-id')
			     );
sleep(3);   # let the replication catch up
my $ElCid = choose_cid(
		calc_cid($actual->{'Message A'}),
		calc_cid($actual->{'Message B'}),
		calc_cid($actual->{'Message C'})
	    );
check_messages($master_store, $expected, "(master after D)", $ElCid);
check_messages($replica_store, $expected, "(replica after D)", $ElCid);

printf "done\n" if $verbose;

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
# 	Opera Software Australia Pty. Ltd.
# 	Level 50, 120 Collins St
# 	Melbourne 3000
# 	Victoria
# 	Australia
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
package Cassandane::Cyrus::Metadata;
use base qw(Cassandane::Unit::TestCase);
use DateTime;
use Cassandane::Util::Log;
use Cassandane::Generator;
use Cassandane::MessageStoreFactory;
use Cassandane::Instance;

sub new
{
    my $class = shift;
    my $self = $class->SUPER::new(@_);

    $self->{instance} = Cassandane::Instance->new();
    $self->{instance}->add_service('imap');

    $self->{gen} = Cassandane::Generator->new();

    return $self;
}

sub set_up
{
    my ($self) = @_;

    $self->{instance}->start();
    my $svc = $self->{instance}->get_service('imap');
    $self->{store} = $svc->create_store();
    $self->{adminstore} = $svc->create_store(username => 'admin');
}

sub tear_down
{
    my ($self) = @_;

    $self->{store}->disconnect()
	if defined $self->{store};
    $self->{store} = undef;
    $self->{adminstore}->disconnect()
	if defined $self->{adminstore};
    $self->{adminstore} = undef;
    $self->{instance}->stop();
}

# TODO: provide a way to do this in the same instance
# which would be more efficient
sub restart_with_config
{
    my ($self, %nv) = @_;

    my $conf = $self->{instance}->{config}->clone();
    $conf->set(%nv);

    $self->tear_down();

    $self->{instance} = Cassandane::Instance->new(config => $conf);
    my $svc = $self->{instance}->add_service('imap');
    $self->{instance}->start();
    $self->{store} = $svc->create_store();
    $self->{adminstore} = $svc->create_store(username => 'admin');
}

sub _save_message
{
    my ($self, $msg, $store) = @_;

    $store ||= $self->{store};

    $store->write_begin();
    $store->write_message($msg);
    $store->write_end();
}

sub make_message
{
    my ($self, $subject, %attrs) = @_;

    my $store = $attrs{store};	# may be undef
    delete $attrs{store};

    my $msg = $self->{gen}->generate(subject => $subject, %attrs);
    $self->_save_message($msg, $store);

    return $msg;
}

#
# Create and save two messages to two stores, according to GUID
# on the messages, so that the first store gets the message with
# the lower GUID and the second store the message with the higher
# GUID.  Both cases need to be done in a controlled manner in order
# to exercise some of the more obscure code paths in message
# replication.
#
# Returns: Message, Message in the order they went to Stores
#
sub make_message_pair
{
    my ($self, $store0, $store1) = @_;

    # Generate two messages and detect their resulting GUIDs
    my $msg0 = $self->{gen}->generate(subject => 'Message Zero');
    my $msg1 = $self->{gen}->generate(subject => 'Message One');
    my $guid0 = $msg0->get_guid();
    my $guid1 = $msg1->get_guid();
    xlog "Message 'Message Zero' has GUID $guid0";
    xlog "Message 'Message One' has GUID $guid1";

    # choose ordering of messages
    $self->assert_str_not_equals($guid0, $guid1);
    if ($guid0 gt $guid1)
    {
	# swap
	my $t = $msg0;
	$msg0 = $msg1;
	$msg1 = $t;
    }

    # Save and return the messages
    $self->_save_message($msg0, $store0);
    $self->_save_message($msg1, $store1);
    return ($msg0, $msg1);
}

sub check_messages
{
    my ($self, $expected, %params) = @_;
    my $actual = {};
    my $store = $params{store} || $self->{store};

    xlog "check_messages: " . join(' ',%params);

    $store->read_begin();
    while (my $msg = $store->read_message())
    {
	my $subj = $msg->get_header('subject');
	$self->assert(!defined $actual->{$subj});
	$actual->{$subj} = $msg;
    }
    $store->read_end();

    $self->assert(scalar keys %$actual == scalar keys %$expected);

    foreach my $expmsg (values %$expected)
    {
	my $subj = $expmsg->get_header('subject');
	my $actmsg = $actual->{$subj};

	$self->assert_not_null($actmsg);

	xlog "checking guid";
	$self->assert_str_equals($expmsg->get_guid(),
				 $actmsg->get_guid());

	xlog "checking x-cassandane-unique";
	$self->assert_not_null($actmsg->get_header('x-cassandane-unique'));
	$self->assert_str_equals($expmsg->get_header('x-cassandane-unique'),
			         $actmsg->get_header('x-cassandane-unique'));

	if (defined $expmsg->get_attribute('uid'))
	{
	    xlog "checking uid";
	    $self->assert_num_equals($expmsg->get_attribute('uid'),
				     $actmsg->get_attribute('uid'));
	}

	if (defined $expmsg->get_attribute('cid'))
	{
	    xlog "checking cid";
	    $self->assert_not_null($actmsg->get_attribute('cid'));
	    $self->assert_str_equals($expmsg->get_attribute('cid'),
				     $actmsg->get_attribute('cid'));
	}

	foreach my $ea ($expmsg->list_annotations())
	{
	    xlog "checking annotation ($ea->{entry} $ea->{attrib})";
	    $self->assert_not_null($actmsg->get_annotation($ea));
	    $self->assert_str_equals($expmsg->get_annotation($ea),
				     $actmsg->get_annotation($ea));
	}
    }

    return $actual;
}

#
# Test the capabilities
#
sub test_capabilities
{
    my ($self) = @_;
    my $imaptalk = $self->{store}->get_client();

    my $caps = $imaptalk->capability();
    xlog "RFC5257 defines capability ANNOTATE-EXPERIMENT-1";
    $self->assert_not_null($caps->{"annotate-experiment-1"});
    xlog "RFC5464 defines capability METADATA";
    $self->assert_not_null($caps->{"metadata"});
}


#
# Test the cyrus annotations
#
sub test_shared
{
    my ($self) = @_;

    my $imaptalk = $self->{store}->get_client();

    xlog "reading read_only Cyrus annotations";
    my $res = $imaptalk->getmetadata('INBOX', {depth => 'infinity'}, '/shared');
    my $r = $res->{INBOX};
    $self->assert_not_null($r);

    xlog "checking specific entries";
    # Note: lastupdate will be a time string close within the
    # last second, but I'm too lazy to check that properly
    $self->assert_not_null($r->{'/shared/vendor/cmu/cyrus-imapd/lastupdate'});
    delete $r->{'/shared/vendor/cmu/cyrus-imapd/lastupdate'};
    $self->assert_deep_equals({
	    '/shared/vendor/cmu/cyrus-imapd/squat' => undef,
	    '/shared/vendor/cmu/cyrus-imapd/size' => '0',
	    '/shared/vendor/cmu/cyrus-imapd/sieve' => undef,
	    '/shared/vendor/cmu/cyrus-imapd/sharedseen' => 'false',
	    '/shared/vendor/cmu/cyrus-imapd/pop3showafter' => undef,
	    '/shared/vendor/cmu/cyrus-imapd/pop3newuidl' => 'true',
	    '/shared/vendor/cmu/cyrus-imapd/partition' => 'default',
	    '/shared/vendor/cmu/cyrus-imapd/news2mail' => undef,
	    '/shared/vendor/cmu/cyrus-imapd/lastpop' => undef,
	    '/shared/vendor/cmu/cyrus-imapd/expire' => undef,
	    '/shared/vendor/cmu/cyrus-imapd/duplicatedeliver' => 'false',
	    '/shared/thread' => undef,
	    '/shared/specialuse' => undef,
	    '/shared/sort' => undef,
	    '/shared/comment' => undef,
	    '/shared/checkperiod' => undef,
	    '/shared/check' => undef,
	}, $r);

    # individual item fetch:
    my $part = $imaptalk->getmetadata('INBOX', "/shared/vendor/cmu/cyrus-imapd/partition");
    $self->assert_str_equals('default', $part->{INBOX}{"/shared/vendor/cmu/cyrus-imapd/partition"});

    # duplicate deliver should be false
    $self->assert_str_equals('false', $res->{INBOX}{"/shared/vendor/cmu/cyrus-imapd/duplicatedeliver"});

    # set duplicate deliver (as admin)
    my $admintalk = $self->{adminstore}->get_client();
    $admintalk->setmetadata('user.cassandane', "/shared/vendor/cmu/cyrus-imapd/duplicatedeliver", 'true');
    $self->assert_str_equals('ok', $admintalk->get_last_completion_response());

    # and make sure the change sticks
    my $dup = $imaptalk->getmetadata('INBOX', "/shared/vendor/cmu/cyrus-imapd/duplicatedeliver");
    $self->assert_str_equals('true', $dup->{INBOX}{"/shared/vendor/cmu/cyrus-imapd/duplicatedeliver"});
}

#
# Test the /private/specialuse annotation defined by RFC6154.
#
sub test_specialuse
{
    my ($self) = @_;

    xlog "testing /private/specialuse";

    my $imaptalk = $self->{store}->get_client();
    my $res;
#
#     Cyrus incorrectly implements /shared semantics for
#     the specialuse annotation, which is not correct for
#     the final RFC.
#
#     my $entry = '/private/specialuse';
    my $entry = '/shared/specialuse';
    my @testcases = (
	# Cyrus has no virtual folders, so cannot do \All
	{
	    folder => 'a',
	    specialuse => '\All',
	    result => 'no'
	},
	{
	    folder => 'b',
	    specialuse => '\Archive',
	    result => 'ok'
	},
	{
	    folder => 'c',
	    specialuse => '\Drafts',
	    result => 'ok'
	},
	# Cyrus has no virtual folders, so cannot do \Flagged
	{
	    folder => 'd',
	    specialuse => '\Flagged',
	    result => 'no'
	},
	{
	    folder => 'e',
	    specialuse => '\Junk',
	    result => 'ok'
	},
	{
	    folder => 'f',
	    specialuse => '\Sent',
	    result => 'ok'
	},
	{
	    folder => 'g',
	    specialuse => '\Trash',
	    result => 'ok'
	},
	# Tokens not defined in the RFC are rejected
	{
	    folder => 'h',
	    specialuse => '\Nonesuch',
	    result => 'no'
	},
	# Cyrus doesn't support more than a single special use
	# token per folder.
	{
	    folder => 'i',
	    specialuse => '\Sent \Trash',
	    result => 'no'
	},
    );

    xlog "First create all the folders";
    foreach my $tc (@testcases)
    {
	$imaptalk->create("INBOX.$tc->{folder}")
	    or die "Cannot create mailbox INBOX.$tc->{folder}: $@";
    }

    foreach my $tc (@testcases)
    {
	my $folder = "INBOX.$tc->{folder}";

	xlog "initial value for $folder is NIL";
	$res = $imaptalk->getmetadata($folder, $entry);
	$self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
	$self->assert_not_null($res);
	$self->assert_deep_equals({
	    $folder => { $entry => undef }
	}, $res);

	xlog "can set $folder to $tc->{specialuse}";
	$imaptalk->setmetadata($folder, $entry, $tc->{specialuse});
	$self->assert_str_equals($tc->{result}, $imaptalk->get_last_completion_response());

	xlog "can get the set value back";
	$res = $imaptalk->getmetadata($folder, $entry);
	$self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
	$self->assert_not_null($res);
	my $expected = {
		$folder => { $entry => ($tc->{result} eq 'ok' ?  $tc->{specialuse} : undef) }
	    };
	$self->assert_deep_equals($expected, $res);
    }

    xlog "can get same values in a new connection";
    $self->{store}->disconnect();
    $imaptalk = $self->{store}->get_client();

    foreach my $tc (@testcases)
    {
	my $folder = "INBOX.$tc->{folder}";

	$res = $imaptalk->getmetadata($folder, $entry);
	$self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
	$self->assert_not_null($res);
	my $expected = {
		$folder => { $entry => ($tc->{result} eq 'ok' ?  $tc->{specialuse} : undef) }
	    };
	$self->assert_deep_equals($expected, $res);
    }

    xlog "can delete values";
    foreach my $tc (@testcases)
    {
	next unless ($tc->{result} eq 'ok');
	my $folder = "INBOX.$tc->{folder}";

	$imaptalk->setmetadata($folder, $entry, undef);
	$self->assert_str_equals('ok', $imaptalk->get_last_completion_response());

	$res = $imaptalk->getmetadata($folder, $entry);
	$self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
	$self->assert_not_null($res);
	my $expected = {
		$folder => { $entry => undef }
	    };
	$self->assert_deep_equals($expected, $res);
    }

}

#
# Test the /shared/motd server annotation.
#
# Note: this needs the Mail::IMAPTalk install to have commit
# "Alert reponse is remainder of line, put that in the response code"
#
sub test_motd
{
    my ($self) = @_;

    xlog "testing /shared/motd";

    my $imaptalk = $self->{store}->get_client();
    my $res;
    my $entry = '/shared/motd';
    my $value1 = "Hello World this is a value";

    xlog "No ALERT was received when we connected";
    $self->assert($imaptalk->state() == Mail::IMAPTalk::Authenticated);
    $self->assert_null($imaptalk->get_response_code('alert'));

    xlog "initial value is NIL";
    $res = $imaptalk->getmetadata("", $entry);
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
    $self->assert_not_null($res);
    $self->assert_deep_equals({
	"" => { $entry => undef }
    }, $res);

    xlog "cannot set the value as ordinary user";
    $imaptalk->setmetadata("", $entry, $value1);
    $self->assert_str_equals('no', $imaptalk->get_last_completion_response());
    $self->assert($imaptalk->get_last_error() =~ m/permission denied/i);

    xlog "can set the value as admin";
    $imaptalk = $self->{adminstore}->get_client();
    $imaptalk->setmetadata("", $entry, $value1);
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());

    xlog "can get the set value back";
    $res = $imaptalk->getmetadata("", $entry);
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
    $self->assert_not_null($res);
    my $expected = {
	    "" => { $entry => $value1 }
    };
    $self->assert_deep_equals($expected, $res);

    xlog "a new connection will get an ALERT with the motd value";
    $self->{adminstore}->disconnect();
    $imaptalk = $self->{adminstore}->get_client();
    $self->assert($imaptalk->state() == Mail::IMAPTalk::Authenticated);
    my $alert = $imaptalk->get_response_code('alert');
    $self->assert_not_null($alert);
    $self->assert_str_equals($value1, $alert);

    xlog "the annot gives the same value in the new connection";
    $res = $imaptalk->getmetadata("", $entry);
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
    $self->assert_not_null($res);
    $expected = {
	    "" => { $entry => $value1 }
    };
    $self->assert_deep_equals($expected, $res);

    xlog "can delete value";
    $imaptalk->setmetadata("", $entry, undef);
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());

    $res = $imaptalk->getmetadata("", $entry);
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
    $self->assert_not_null($res);
    $expected = {
	    "" => { $entry => undef }
    };
    $self->assert_deep_equals($expected, $res);

    xlog "a new connection no longer gets an ALERT";
    $self->{adminstore}->disconnect();
    $imaptalk = $self->{adminstore}->get_client();
    $self->assert($imaptalk->state() == Mail::IMAPTalk::Authenticated);
    $self->assert_null($imaptalk->get_response_code('alert'));
}

#
# Test the /shared/vendor/cmu/cyrus-imapd/size annotation
# which reports the total byte count of the RFC822 message
# sizes in the mailbox.
#
sub test_size
{
    my ($self) = @_;

    xlog "testing /shared/vendor/cmu/cyrus-imapd/size";

    my $imaptalk = $self->{store}->get_client();
    my $res;
    my $folder = $self->{store}->{folder};
    my $entry = '/shared/vendor/cmu/cyrus-imapd/size';

    xlog "initial value is numeric zero";
    $res = $imaptalk->getmetadata($folder, $entry);
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
    $self->assert_deep_equals({
	$folder => { $entry => "0" }
    }, $res);

    xlog "cannot set the value as ordinary user";
    $imaptalk->setmetadata($folder, $entry, '123');
    $self->assert_str_equals('no', $imaptalk->get_last_completion_response());
    $self->assert($imaptalk->get_last_error() =~ m/permission denied/i);

    xlog "cannot set the value as admin either";
    my $admintalk = $self->{adminstore}->get_client();
    $admintalk->setmetadata($folder, $entry, '123');
    $self->assert_str_equals('no', $admintalk->get_last_completion_response());
    $self->assert($admintalk->get_last_error() =~ m/permission denied/i);

    xlog "adding a message bumps the value by the message's size";
    my $expected = 0;
    my %msg;
    $msg{A} = $self->make_message('Message A');
    $expected += length($msg{A}->as_string());

    $res = $imaptalk->getmetadata($folder, $entry);
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
    $self->assert_deep_equals({
	$folder => { $entry => "" . $expected }
    }, $res);

    xlog "adding a 2nd message bumps the value by the message's size";
    $msg{B} = $self->make_message('Message B');
    $expected += length($msg{B}->as_string());

    $res = $imaptalk->getmetadata($folder, $entry);
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
    $self->assert_deep_equals({
	$folder => { $entry => "" . $expected }
    }, $res);

    # TODO: removing a message doesn't reduce the value until (possibly delayed) expunge
}


sub test_private
{
    my ($self) = @_;

    my $imaptalk = $self->{store}->get_client();

    xlog "testing private metadata operations";

    # nothing present
    my $res = $imaptalk->getmetadata('INBOX', {depth => 'infinity'}, '/private');
    $self->assert_num_equals(0, scalar keys %$res);

    $imaptalk->setmetadata('INBOX', "/private/comment", "This is a comment");
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
    my $com = $imaptalk->getmetadata('INBOX', "/private/comment");
    $self->assert_str_equals("This is a comment", $com->{INBOX}{"/private/comment"});

    # remove it again
    $imaptalk->setmetadata('INBOX', "/private/comment", undef);
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());

    my $meta = $imaptalk->getmetadata('INBOX', {depth => 'infinity'}, '/private');
    $self->assert_num_equals(0, scalar keys %$meta);
}

sub test_embedded_nuls
{
    my ($self) = @_;

    xlog "testing getting and setting embedded NULs";

    my $imaptalk = $self->{store}->get_client();
    my $folder = 'INBOX.test_embedded_nuls';
    my $entry = '/private/comment';
    my $binary = "Hello\0World";

    xlog "create a temporary mailbox";
    $imaptalk->create($folder)
	or die "Cannot create mailbox $folder: $@";

    xlog "initially, NIL is reported";
    my $res = $imaptalk->getmetadata($folder, $entry)
	or die "Cannot get metadata: $@";
    $self->assert_num_equals(1, scalar keys %$res);
    $self->assert_null($res->{$folder}{$entry});

    xlog "set and then get the same back again";
    $imaptalk->setmetadata($folder, $entry, $binary);
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());
    $res = $imaptalk->getmetadata($folder, $entry);
    $self->assert_str_equals($binary, $res->{$folder}{$entry});

    xlog "remove it again";
    $imaptalk->setmetadata($folder, $entry, undef);
    $self->assert_str_equals('ok', $imaptalk->get_last_completion_response());

    xlog "check it's gone now";
    $res = $imaptalk->getmetadata($folder, $entry)
	or die "Cannot get metadata: $@";
    $self->assert_num_equals(1, scalar keys %$res);
    $self->assert_null($res->{$folder}{$entry});

    xlog "clean up temporary mailbox";
    $imaptalk->delete($folder)
	or die "Cannot delete mailbox $folder: $@";
}

sub test_permessage_getset
{
    my ($self) = @_;

    xlog "testing getting and setting message scope annotations";

    my $talk = $self->{store}->get_client();

    xlog "Append 3 messages";
    my %msg;
    $msg{A} = $self->make_message('Message A');
    $msg{B} = $self->make_message('Message B');
    $msg{C} = $self->make_message('Message C');

    my $entry = '/comment';
    my $attrib = 'value.priv';
    my $value1 = "Hello World";
    my $value2 = "Goodnight\0Irene";
    my $value3 = "Gump";

    xlog "fetch an annotation - should be no values";
    my $res = $talk->fetch('1:*',
			   ['annotation', [$entry, $attrib]]);
    $self->assert_str_equals('ok', $talk->get_last_completion_response());
    $self->assert_not_null($res);
    $self->assert_deep_equals(
	    {
		1 => { annotation => [ $entry, [ $attrib, undef ] ] },
		2 => { annotation => [ $entry, [ $attrib, undef ] ] },
		3 => { annotation => [ $entry, [ $attrib, undef ] ] },
	    },
	    $res);

    xlog "store an annotation";
    $talk->store('1', 'annotation',
	         [$entry, [$attrib, $value1]]);
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    xlog "fetch the annotation again, should see changes";
    $res = $talk->fetch('1:*',
		        ['annotation', [$entry, $attrib]]);
    $self->assert_str_equals('ok', $talk->get_last_completion_response());
    $self->assert_not_null($res);
    $self->assert_deep_equals(
	    {
		1 => { annotation => [ $entry, [ $attrib, $value1 ] ] },
		2 => { annotation => [ $entry, [ $attrib, undef ] ] },
		3 => { annotation => [ $entry, [ $attrib, undef ] ] },
	    },
	    $res);

    xlog "store an annotation with an embedded NUL";
    $talk->store('3', 'annotation',
	         [$entry, [$attrib, $value2]]);
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    xlog "fetch the annotation again, should see changes";
    $res = $talk->fetch('1:*',
		        ['annotation', [$entry, $attrib]]);
    $self->assert_str_equals('ok', $talk->get_last_completion_response());
    $self->assert_not_null($res);
    $self->assert_deep_equals(
	    {
		1 => { annotation => [ $entry, [ $attrib, $value1 ] ] },
		2 => { annotation => [ $entry, [ $attrib, undef ] ] },
		3 => { annotation => [ $entry, [ $attrib, $value2 ] ] },
	    },
	    $res);

    xlog "store multiple annotations";
    # Note $value3 has no whitespace so we have to
    # convince Mail::IMAPTalk to quote it anyway
    $talk->store('1:*', 'annotation',
	         [$entry, [$attrib, { Quote => $value3 }]]);
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    xlog "fetch the annotation again, should see changes";
    $res = $talk->fetch('1:*',
		        ['annotation', [$entry, $attrib]]);
    $self->assert_str_equals('ok', $talk->get_last_completion_response());
    $self->assert_not_null($res);
    $self->assert_deep_equals(
	    {
		1 => { annotation => [ $entry, [ $attrib, $value3 ] ] },
		2 => { annotation => [ $entry, [ $attrib, $value3 ] ] },
		3 => { annotation => [ $entry, [ $attrib, $value3 ] ] },
	    },
	    $res);

    xlog "delete an annotation";
    # Note $value3 has no whitespace so we have to
    # convince Mail::IMAPTalk to quote it anyway
    $talk->store('2', 'annotation',
	         [$entry, [$attrib, undef]]);
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    xlog "fetch the annotation again, should see changes";
    $res = $talk->fetch('1:*',
		        ['annotation', [$entry, $attrib]]);
    $self->assert_str_equals('ok', $talk->get_last_completion_response());
    $self->assert_not_null($res);
    $self->assert_deep_equals(
	    {
		1 => { annotation => [ $entry, [ $attrib, $value3 ] ] },
		2 => { annotation => [ $entry, [ $attrib, undef ] ] },
		3 => { annotation => [ $entry, [ $attrib, $value3 ] ] },
	    },
	    $res);

    xlog "delete all annotations";
    # Note $value3 has no whitespace so we have to
    # convince Mail::IMAPTalk to quote it anyway
    $talk->store('1:*', 'annotation',
	         [$entry, [$attrib, undef]]);
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    xlog "fetch the annotation again, should see changes";
    $res = $talk->fetch('1:*',
		        ['annotation', [$entry, $attrib]]);
    $self->assert_str_equals('ok', $talk->get_last_completion_response());
    $self->assert_not_null($res);
    $self->assert_deep_equals(
	    {
		1 => { annotation => [ $entry, [ $attrib, undef ] ] },
		2 => { annotation => [ $entry, [ $attrib, undef ] ] },
		3 => { annotation => [ $entry, [ $attrib, undef ] ] },
	    },
	    $res);
}

sub test_permessage_unknown
{
    my ($self) = @_;

    xlog "testing getting and setting unknown annotations on a message";
    xlog "where this is forbidden by the default config";

    xlog "Append a message";
    my %msg;
    $msg{A} = $self->make_message('Message A');

    my $entry = '/thisentryisnotdefined';
    my $attrib = 'value.priv';
    my $value1 = "Hello World";

    xlog "fetch annotation - should be no values";
    my $talk = $self->{store}->get_client();
    my $res = $talk->fetch('1:*',
			   ['annotation', [$entry, $attrib]]);
    $self->assert_str_equals('ok', $talk->get_last_completion_response());
    $self->assert_not_null($res);
    $self->assert_deep_equals(
	    {
		1 => { annotation => [ $entry, [ $attrib, undef ] ] },
	    },
	    $res);

    xlog "store annotation - should fail";
    $talk->store('1', 'annotation',
	         [$entry, [$attrib, $value1]]);
    $self->assert_str_equals('no', $talk->get_last_completion_response());

    xlog "fetch the annotation again, should see nothing";
    $res = $talk->fetch('1:*',
		        ['annotation', [$entry, $attrib]]);
    $self->assert_str_equals('ok', $talk->get_last_completion_response());
    $self->assert_not_null($res);
    $self->assert_deep_equals(
	    {
		1 => { annotation => [ $entry, [ $attrib, undef ] ] },
	    },
	    $res);
}

sub test_permessage_unknown_allowed
{
    my ($self) = @_;

    xlog "testing getting and setting unknown annotations on a message";
    xlog "with config allowing this";

    xlog "Start a new instance with a changed config";
    $self->restart_with_config(annotation_allow_undefined => 1);

    xlog "Append a message";
    my %msg;
    $msg{A} = $self->make_message('Message A');

    my $entry = '/thisentryisnotdefined';
    my $attrib = 'value.priv';
    my $value1 = "Hello World";

    xlog "fetch annotation - should be no values";
    my $talk = $self->{store}->get_client();
    my $res = $talk->fetch('1:*',
			   ['annotation', [$entry, $attrib]]);
    $self->assert_str_equals('ok', $talk->get_last_completion_response());
    $self->assert_not_null($res);
    $self->assert_deep_equals(
	    {
		1 => { annotation => [ $entry, [ $attrib, undef ] ] },
	    },
	    $res);

    xlog "store annotation - should succeed";
    $talk->store('1', 'annotation',
	         [$entry, [$attrib, $value1]]);
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    xlog "fetch the annotation again, should see the value";
    $res = $talk->fetch('1:*',
		        ['annotation', [$entry, $attrib]]);
    $self->assert_str_equals('ok', $talk->get_last_completion_response());
    $self->assert_not_null($res);
    $self->assert_deep_equals(
	    {
		1 => { annotation => [ $entry, [ $attrib, $value1 ] ] },
	    },
	    $res);
}

sub set_msg_annotation
{
    my ($self, $store, $uid, $entry, $attrib, $value) = @_;

    $store ||= $self->{store};
    $store->_connect();
    $store->_select();
    my $talk = $store->get_client();
    # Note $value might have no whitespace so we have to
    # convince Mail::IMAPTalk to quote it anyway
    $talk->store('' . $uid, 'annotation', [$entry, [$attrib, { Quote => $value }]]);
    $self->assert_str_equals('ok', $talk->get_last_completion_response());
}

sub test_msg_replication_new_mas
{
    my ($self) = @_;

    xlog "testing replication of message scope annotations";
    xlog "case new_mas: new message appears, on master only";

    xlog "set up a master and replica pair";
    my ($master, $replica, $master_store, $replica_store) =
	Cassandane::Instance->start_replicated_pair();

    my $entry = '/comment';
    my $attrib = 'value.priv';
    my $value1 = "Hello World";

    $master_store->set_fetch_attributes('uid', "annotation ($entry $attrib)");
    $replica_store->set_fetch_attributes('uid', "annotation ($entry $attrib)");

    xlog "Append a message and store an annotation";
    my %master_exp;
    my %replica_exp;
    $master_exp{A} = $self->make_message('Message A', store => $master_store);
    $self->set_msg_annotation($master_store, 1, $entry, $attrib, $value1);
    $master_exp{A}->set_attribute('uid', 1);
    $master_exp{A}->set_annotation($entry, $attrib, $value1);

    xlog "Before replication, message is present on the master";
    $self->check_messages(\%master_exp, store => $master_store);
    xlog "Before replication, message is missing from the replica";
    $self->check_messages(\%replica_exp, store => $replica_store);

    Cassandane::Instance->run_replication($master, $replica,
					  $master_store, $replica_store);

    $replica_exp{A} = $master_exp{A}->clone();
    xlog "After replication, message is still present on the master";
    $self->check_messages(\%master_exp, store => $master_store);
    xlog "After replication, message is now present on the replica";
    $self->check_messages(\%replica_exp, store => $replica_store);
}

sub test_msg_replication_new_rep
{
    my ($self) = @_;

    xlog "testing replication of message scope annotations";
    xlog "case new_rep: new message appears, on replica only";

    xlog "set up a master and replica pair";
    my ($master, $replica, $master_store, $replica_store) =
	Cassandane::Instance->start_replicated_pair();

    my $entry = '/comment';
    my $attrib = 'value.priv';
    my $value1 = "Hello World";

    $master_store->set_fetch_attributes('uid', "annotation ($entry $attrib)");
    $replica_store->set_fetch_attributes('uid', "annotation ($entry $attrib)");

    xlog "Append a message and store an annotation";
    my %master_exp;
    my %replica_exp;
    $replica_exp{A} = $self->make_message('Message A', store => $replica_store);
    $self->set_msg_annotation($replica_store, 1, $entry, $attrib, $value1);
    $replica_exp{A}->set_attribute('uid', 1);
    $replica_exp{A}->set_annotation($entry, $attrib, $value1);

    xlog "Before replication, message is missing from the master";
    $self->check_messages(\%master_exp, store => $master_store);
    xlog "Before replication, message is present on the replica";
    $self->check_messages(\%replica_exp, store => $replica_store);

    Cassandane::Instance->run_replication($master, $replica,
					  $master_store, $replica_store);

    $master_exp{A} = $replica_exp{A}->clone();
    xlog "After replication, message is now present on the master";
    $self->check_messages(\%master_exp, store => $master_store);
    xlog "After replication, message is still present on the replica";
    $self->check_messages(\%replica_exp, store => $replica_store);
}

sub test_msg_replication_new_bot_mse_gul
{
    my ($self) = @_;

    xlog "testing replication of message scope annotations";
    xlog "case new_bot_mse_gul: new messages appear, on both master " .
	 "and replica, with equal modseqs, lower GUID on master.";

    xlog "set up a master and replica pair";
    my ($master, $replica, $master_store, $replica_store) =
	Cassandane::Instance->start_replicated_pair();

    my $entry = '/comment';
    my $attrib = 'value.priv';
    my $valueA = "Hello World";
    my $valueB = "Hello Dolly";

    $master_store->set_fetch_attributes('uid', "annotation ($entry $attrib)");
    $replica_store->set_fetch_attributes('uid', "annotation ($entry $attrib)");

    xlog "Append a message and store an annotation to each store";
    my ($msgA, $msgB) = $self->make_message_pair($master_store, $replica_store);
    my %master_exp = ( A => $msgA );
    my %replica_exp = ( B => $msgB );
    $self->set_msg_annotation($master_store, 1, $entry, $attrib, $valueA);
    $master_exp{A}->set_attribute('uid', 1);
    $master_exp{A}->set_annotation($entry, $attrib, $valueA);
    $self->set_msg_annotation($replica_store, 1, $entry, $attrib, $valueB);
    $replica_exp{B}->set_attribute('uid', 1);
    $replica_exp{B}->set_annotation($entry, $attrib, $valueB);

    xlog "Before replication, only message A is present on the master";
    $self->check_messages(\%master_exp, store => $master_store);
    xlog "Before replication, only message B is present on the replica";
    $self->check_messages(\%replica_exp, store => $replica_store);

    Cassandane::Instance->run_replication($master, $replica,
					  $master_store, $replica_store);

    xlog "After replication, both messages are now present and renumbered on the master";
    $master_exp{B} = $replica_exp{B}->clone();
    $master_exp{A}->set_attribute('uid', 2);
    $master_exp{B}->set_attribute('uid', 3);
    $self->check_messages(\%master_exp, store => $master_store);
    xlog "After replication, both messages are now present and renumbered on the replica";
    $replica_exp{A} = $master_exp{A}->clone();
    $replica_exp{A}->set_attribute('uid', 2);
    $replica_exp{B}->set_attribute('uid', 3);
    $self->check_messages(\%replica_exp, store => $replica_store);
}

sub test_msg_replication_new_bot_mse_guh
{
    my ($self) = @_;

    xlog "testing replication of message scope annotations";
    xlog "case new_bot_mse_guh: new messages appear, on both master " .
	 "and replica, with equal modseqs, higher GUID on master.";

    xlog "set up a master and replica pair";
    my ($master, $replica, $master_store, $replica_store) =
	Cassandane::Instance->start_replicated_pair();

    my $entry = '/comment';
    my $attrib = 'value.priv';
    my $valueA = "Hello World";
    my $valueB = "Hello Dolly";

    $master_store->set_fetch_attributes('uid', "annotation ($entry $attrib)");
    $replica_store->set_fetch_attributes('uid', "annotation ($entry $attrib)");

    xlog "Append a message and store an annotation to each store";
    my ($msgB, $msgA) = $self->make_message_pair($replica_store, $master_store);
    my %master_exp = ( A => $msgA );
    my %replica_exp = ( B => $msgB );
    $self->set_msg_annotation($master_store, 1, $entry, $attrib, $valueA);
    $master_exp{A}->set_attribute('uid', 1);
    $master_exp{A}->set_annotation($entry, $attrib, $valueA);
    $self->set_msg_annotation($replica_store, 1, $entry, $attrib, $valueB);
    $replica_exp{B}->set_attribute('uid', 1);
    $replica_exp{B}->set_annotation($entry, $attrib, $valueB);

    xlog "Before replication, only message A is present on the master";
    $self->check_messages(\%master_exp, store => $master_store);
    xlog "Before replication, only message B is present on the replica";
    $self->check_messages(\%replica_exp, store => $replica_store);

    Cassandane::Instance->run_replication($master, $replica,
					  $master_store, $replica_store);

    xlog "After replication, both messages are now present and renumbered on the master";
    $master_exp{B} = $replica_exp{B}->clone();
    $master_exp{B}->set_attribute('uid', 2);
    $master_exp{A}->set_attribute('uid', 3);
    $self->check_messages(\%master_exp, store => $master_store);
    xlog "After replication, both messages are now present and renumbered on the replica";
    $replica_exp{A} = $master_exp{A}->clone();
    $replica_exp{B}->set_attribute('uid', 2);
    $replica_exp{A}->set_attribute('uid', 3);
    $self->check_messages(\%replica_exp, store => $replica_store);
}


sub test_msg_replication_mod_mas
{
    my ($self) = @_;

    xlog "testing replication of message scope annotations";
    xlog "case mod_mas: message is modified, on master only";

    xlog "set up a master and replica pair";
    my ($master, $replica, $master_store, $replica_store) =
	Cassandane::Instance->start_replicated_pair();

    my $entry = '/comment';
    my $attrib = 'value.priv';
    my $value1 = "Hello World";

    $master_store->set_fetch_attributes('uid', "annotation ($entry $attrib)");
    $replica_store->set_fetch_attributes('uid', "annotation ($entry $attrib)");

    xlog "Append a message";
    my %master_exp;
    my %replica_exp;
    $master_exp{A} = $self->make_message('Message A', store => $master_store);
    $master_exp{A}->set_attribute('uid', 1);

    xlog "Before first replication, message is present on the master";
    $self->check_messages(\%master_exp, store => $master_store);
    xlog "Before first replication, message is missing from the replica";
    $self->check_messages(\%replica_exp, store => $replica_store);

    xlog "Replicate the message";
    Cassandane::Instance->run_replication($master, $replica,
					  $master_store, $replica_store);

    $replica_exp{A} = $master_exp{A}->clone();
    xlog "After first replication, message is still present on the master";
    $self->check_messages(\%master_exp, store => $master_store);
    xlog "After first replication, message is now present on the replica";
    $self->check_messages(\%replica_exp, store => $replica_store);

    xlog "Set an annotation on the master";
    $self->set_msg_annotation($master_store, 1, $entry, $attrib, $value1);
    $master_exp{A}->set_annotation($entry, $attrib, $value1);

    xlog "Before second replication, the message annotation is present on the master";
    $self->check_messages(\%master_exp, store => $master_store);
    xlog "Before second replication, the message annotation is missing on the replica";
    $self->check_messages(\%replica_exp, store => $replica_store);

    Cassandane::Instance->run_replication($master, $replica,
					  $master_store, $replica_store);

    $replica_exp{A} = $master_exp{A}->clone();
    xlog "After second replication, the message annotation is still present on the master";
    $self->check_messages(\%master_exp, store => $master_store);
    xlog "After second replication, the message annotation is now present on the replica";
    $self->check_messages(\%replica_exp, store => $replica_store);
}


sub test_msg_replication_mod_rep
{
    my ($self) = @_;

    xlog "testing replication of message scope annotations";
    xlog "case mod_rep: message is modified, on replica only";

    xlog "set up a master and replica pair";
    my ($master, $replica, $master_store, $replica_store) =
	Cassandane::Instance->start_replicated_pair();

    my $entry = '/comment';
    my $attrib = 'value.priv';
    my $value1 = "Hello World";

    $master_store->set_fetch_attributes('uid', "annotation ($entry $attrib)");
    $replica_store->set_fetch_attributes('uid', "annotation ($entry $attrib)");

    xlog "Append a message";
    my %master_exp;
    my %replica_exp;
    $master_exp{A} = $self->make_message('Message A', store => $master_store);
    $master_exp{A}->set_attribute('uid', 1);

    xlog "Before first replication, message is present on the master";
    $self->check_messages(\%master_exp, store => $master_store);
    xlog "Before first replication, message is missing from the replica";
    $self->check_messages(\%replica_exp, store => $replica_store);

    xlog "Replicate the message";
    Cassandane::Instance->run_replication($master, $replica,
					  $master_store, $replica_store);

    $replica_exp{A} = $master_exp{A}->clone();
    xlog "After first replication, message is still present on the master";
    $self->check_messages(\%master_exp, store => $master_store);
    xlog "After first replication, message is now present on the replica";
    $self->check_messages(\%replica_exp, store => $replica_store);

    xlog "Set an annotation on the master";
    $self->set_msg_annotation($master_store, 1, $entry, $attrib, $value1);
    $master_exp{A}->set_annotation($entry, $attrib, $value1);

    xlog "Before second replication, the message annotation is present on the master";
    $self->check_messages(\%master_exp, store => $master_store);
    xlog "Before second replication, the message annotation is missing on the replica";
    $self->check_messages(\%replica_exp, store => $replica_store);

    Cassandane::Instance->run_replication($master, $replica,
					  $master_store, $replica_store);

    $replica_exp{A} = $master_exp{A}->clone();
    xlog "After second replication, the message annotation is still present on the master";
    $self->check_messages(\%master_exp, store => $master_store);
    xlog "After second replication, the message annotation is now present on the replica";
    $self->check_messages(\%replica_exp, store => $replica_store);
}

sub test_msg_replication_mod_bot_msl
{
    my ($self) = @_;

    xlog "testing replication of message scope annotations";
    xlog "case mod_bot_msl: message is modified, on both ends, " .
	 "modseq lower on master";

    xlog "set up a master and replica pair";
    my ($master, $replica, $master_store, $replica_store) =
	Cassandane::Instance->start_replicated_pair();

    my $entry = '/comment';
    my $attrib = 'value.priv';
    my $valueA = "Hello World";
    my $valueB1 = "Jeepers";
    my $valueB2 = "Creepers";

    $master_store->set_fetch_attributes('uid', "annotation ($entry $attrib)");
    $replica_store->set_fetch_attributes('uid', "annotation ($entry $attrib)");

    xlog "Append a message";
    my %master_exp;
    my %replica_exp;
    $master_exp{A} = $self->make_message('Message A', store => $master_store);
    $master_exp{A}->set_attribute('uid', 1);

    xlog "Before first replication, message is present on the master";
    $self->check_messages(\%master_exp, store => $master_store);
    xlog "Before first replication, message is missing from the replica";
    $self->check_messages(\%replica_exp, store => $replica_store);

    xlog "Replicate the message";
    Cassandane::Instance->run_replication($master, $replica,
					  $master_store, $replica_store);

    $replica_exp{A} = $master_exp{A}->clone();
    xlog "After first replication, message is still present on the master";
    $self->check_messages(\%master_exp, store => $master_store);
    xlog "After first replication, message is now present on the replica";
    $self->check_messages(\%replica_exp, store => $replica_store);

    xlog "Set an annotation once on the master, twice on the replica";
    $self->set_msg_annotation($master_store, 1, $entry, $attrib, $valueA);
    $master_exp{A}->set_annotation($entry, $attrib, $valueA);
    $self->set_msg_annotation($replica_store, 1, $entry, $attrib, $valueB1);
    $self->set_msg_annotation($replica_store, 1, $entry, $attrib, $valueB2);
    $replica_exp{A}->set_annotation($entry, $attrib, $valueB2);

    xlog "Before second replication, one message annotation is present on the master";
    $self->check_messages(\%master_exp, store => $master_store);
    xlog "Before second replication, a different message annotation is present on the replica";
    $self->check_messages(\%replica_exp, store => $replica_store);

    xlog "Replicate the annotation change";
    Cassandane::Instance->run_replication($master, $replica,
					  $master_store, $replica_store);

    $master_exp{A}->set_annotation($entry, $attrib, $valueB2);
    xlog "After second replication, the message annotation is updated on the master";
    $self->check_messages(\%master_exp, store => $master_store);
    xlog "After second replication, the message annotation is still present on the replica";
    $self->check_messages(\%replica_exp, store => $replica_store);
}

sub test_msg_replication_mod_bot_msh
{
    my ($self) = @_;

    xlog "testing replication of message scope annotations";
    xlog "case mod_bot_msh: message is modified, on both ends, " .
	 "modseq higher on master";

    xlog "set up a master and replica pair";
    my ($master, $replica, $master_store, $replica_store) =
	Cassandane::Instance->start_replicated_pair();

    my $entry = '/comment';
    my $attrib = 'value.priv';
    my $valueA1 = "Hello World";
    my $valueA2 = "and friends";
    my $valueB = "Jeepers";

    $master_store->set_fetch_attributes('uid', "annotation ($entry $attrib)");
    $replica_store->set_fetch_attributes('uid', "annotation ($entry $attrib)");

    xlog "Append a message";
    my %master_exp;
    my %replica_exp;
    $master_exp{A} = $self->make_message('Message A', store => $master_store);
    $master_exp{A}->set_attribute('uid', 1);

    xlog "Before first replication, message is present on the master";
    $self->check_messages(\%master_exp, store => $master_store);
    xlog "Before first replication, message is missing from the replica";
    $self->check_messages(\%replica_exp, store => $replica_store);

    xlog "Replicate the message";
    Cassandane::Instance->run_replication($master, $replica,
					  $master_store, $replica_store);

    $replica_exp{A} = $master_exp{A}->clone();
    xlog "After first replication, message is still present on the master";
    $self->check_messages(\%master_exp, store => $master_store);
    xlog "After first replication, message is now present on the replica";
    $self->check_messages(\%replica_exp, store => $replica_store);

    xlog "Set an annotation twice on the master, once on the replica";
    $self->set_msg_annotation($master_store, 1, $entry, $attrib, $valueA1);
    $self->set_msg_annotation($master_store, 1, $entry, $attrib, $valueA2);
    $master_exp{A}->set_annotation($entry, $attrib, $valueA2);
    $self->set_msg_annotation($replica_store, 1, $entry, $attrib, $valueB);
    $replica_exp{A}->set_annotation($entry, $attrib, $valueB);

    xlog "Before second replication, one message annotation is present on the master";
    $self->check_messages(\%master_exp, store => $master_store);
    xlog "Before second replication, a different message annotation is present on the replica";
    $self->check_messages(\%replica_exp, store => $replica_store);

    xlog "Replicate the annotation change";
    Cassandane::Instance->run_replication($master, $replica,
					  $master_store, $replica_store);

    $replica_exp{A}->set_annotation($entry, $attrib, $valueA2);
    xlog "After second replication, the message annotation is still present on the master";
    $self->check_messages(\%master_exp, store => $master_store);
    xlog "After second replication, the message annotation is updated on the replica";
    $self->check_messages(\%replica_exp, store => $replica_store);
}

sub test_msg_replication_exp_mas
{
    my ($self) = @_;

    xlog "testing replication of message scope annotations";
    xlog "case exp_mas: message is expunged, on master only";

    xlog "set up a master and replica pair";
    my ($master, $replica, $master_store, $replica_store) =
	Cassandane::Instance->start_replicated_pair();

    my $entry = '/comment';
    my $attrib = 'value.priv';
    my $value1 = "Hello World";

    $master_store->set_fetch_attributes('uid', "annotation ($entry $attrib)");
    $replica_store->set_fetch_attributes('uid', "annotation ($entry $attrib)");

    xlog "Append a message and store an annotation";
    my %master_exp;
    my %replica_exp;
    $master_exp{A} = $self->make_message('Message A', store => $master_store);
    $self->set_msg_annotation($master_store, 1, $entry, $attrib, $value1);
    $master_exp{A}->set_attribute('uid', 1);
    $master_exp{A}->set_annotation($entry, $attrib, $value1);

    xlog "Before first replication, message is present on the master";
    $self->check_messages(\%master_exp, store => $master_store);
    xlog "Before first replication, message is missing from the replica";
    $self->check_messages(\%replica_exp, store => $replica_store);

    xlog "Replicate the message";
    Cassandane::Instance->run_replication($master, $replica,
					  $master_store, $replica_store);

    $replica_exp{A} = $master_exp{A}->clone();
    xlog "After first replication, message is still present on the master";
    $self->check_messages(\%master_exp, store => $master_store);
    xlog "After first replication, message is now present on the replica";
    $self->check_messages(\%replica_exp, store => $replica_store);

    xlog "Delete and expunge the message on the master";
    my $talk = $master_store->get_client();
    $master_store->_select();
    $talk->store('1', '+flags', '(\\Deleted)');
    $talk->expunge();

    delete $master_exp{A};
    xlog "Before second replication, the message is now missing on the master";
    $self->check_messages(\%master_exp, store => $master_store);
    xlog "Before second replication, the message is still present on the replica";
    $self->check_messages(\%replica_exp, store => $replica_store);

    xlog "Replicate the expunge";
    Cassandane::Instance->run_replication($master, $replica,
					  $master_store, $replica_store);

    delete $replica_exp{A};
    xlog "After second replication, the message is still missing on the master";
    $self->check_messages(\%master_exp, store => $master_store);
    xlog "After second replication, the message is now missing on the replica";
    $self->check_messages(\%replica_exp, store => $replica_store);
}

sub test_msg_replication_exp_rep
{
    my ($self) = @_;

    xlog "testing replication of message scope annotations";
    xlog "case exp_rep: message is expunged, on replica only";

    xlog "set up a master and replica pair";
    my ($master, $replica, $master_store, $replica_store) =
	Cassandane::Instance->start_replicated_pair();

    my $entry = '/comment';
    my $attrib = 'value.priv';
    my $value1 = "Hello World";

    $master_store->set_fetch_attributes('uid', "annotation ($entry $attrib)");
    $replica_store->set_fetch_attributes('uid', "annotation ($entry $attrib)");

    xlog "Append a message and store an annotation";
    my %master_exp;
    my %replica_exp;
    $master_exp{A} = $self->make_message('Message A', store => $master_store);
    $self->set_msg_annotation($master_store, 1, $entry, $attrib, $value1);
    $master_exp{A}->set_attribute('uid', 1);
    $master_exp{A}->set_annotation($entry, $attrib, $value1);

    xlog "Before first replication, message is present on the master";
    $self->check_messages(\%master_exp, store => $master_store);
    xlog "Before first replication, message is missing from the replica";
    $self->check_messages(\%replica_exp, store => $replica_store);

    xlog "Replicate the message";
    Cassandane::Instance->run_replication($master, $replica,
					  $master_store, $replica_store);

    $replica_exp{A} = $master_exp{A}->clone();
    xlog "After first replication, message is still present on the master";
    $self->check_messages(\%master_exp, store => $master_store);
    xlog "After first replication, message is now present on the replica";
    $self->check_messages(\%replica_exp, store => $replica_store);

    xlog "Delete and expunge the message on the replica";
    my $talk = $replica_store->get_client();
    $replica_store->_select();
    $talk->store('1', '+flags', '(\\Deleted)');
    $talk->expunge();

    delete $replica_exp{A};
    xlog "Before second replication, the message is still present on the master";
    $self->check_messages(\%master_exp, store => $master_store);
    xlog "Before second replication, the message is now missing on the replica";
    $self->check_messages(\%replica_exp, store => $replica_store);

    xlog "Replicate the expunge";
    Cassandane::Instance->run_replication($master, $replica,
					  $master_store, $replica_store);

    delete $master_exp{A};
    xlog "After second replication, the message is now missing on the master";
    $self->check_messages(\%master_exp, store => $master_store);
    xlog "After second replication, the message is still missing on the replica";
    $self->check_messages(\%replica_exp, store => $replica_store);
}

sub test_msg_replication_exp_bot
{
    my ($self) = @_;

    xlog "testing replication of message scope annotations";
    xlog "case exp_bot: message is expunged, on both ends";

    xlog "set up a master and replica pair";
    my ($master, $replica, $master_store, $replica_store) =
	Cassandane::Instance->start_replicated_pair();

    my $entry = '/comment';
    my $attrib = 'value.priv';
    my $value1 = "Hello World";

    $master_store->set_fetch_attributes('uid', "annotation ($entry $attrib)");
    $replica_store->set_fetch_attributes('uid', "annotation ($entry $attrib)");

    xlog "Append a message and store an annotation";
    my %master_exp;
    my %replica_exp;
    $master_exp{A} = $self->make_message('Message A', store => $master_store);
    $self->set_msg_annotation($master_store, 1, $entry, $attrib, $value1);
    $master_exp{A}->set_attribute('uid', 1);
    $master_exp{A}->set_annotation($entry, $attrib, $value1);

    xlog "Before first replication, message is present on the master";
    $self->check_messages(\%master_exp, store => $master_store);
    xlog "Before first replication, message is missing from the replica";
    $self->check_messages(\%replica_exp, store => $replica_store);

    xlog "Replicate the message";
    Cassandane::Instance->run_replication($master, $replica,
					  $master_store, $replica_store);

    $replica_exp{A} = $master_exp{A}->clone();
    xlog "After first replication, message is still present on the master";
    $self->check_messages(\%master_exp, store => $master_store);
    xlog "After first replication, message is now present on the replica";
    $self->check_messages(\%replica_exp, store => $replica_store);

    xlog "Delete and expunge the message on the master";
    my $talk = $master_store->get_client();
    $master_store->_select();
    $talk->store('1', '+flags', '(\\Deleted)');
    $talk->expunge();

    xlog "Delete and expunge the message on the replica";
    $talk = $replica_store->get_client();
    $replica_store->_select();
    $talk->store('1', '+flags', '(\\Deleted)');
    $talk->expunge();

    delete $master_exp{A};
    delete $replica_exp{A};
    xlog "Before second replication, the message is now missing on the master";
    $self->check_messages(\%master_exp, store => $master_store);
    xlog "Before second replication, the message is now missing on the replica";
    $self->check_messages(\%replica_exp, store => $replica_store);

    xlog "Replicate the expunge";
    Cassandane::Instance->run_replication($master, $replica,
					  $master_store, $replica_store);

    xlog "After second replication, the message is still missing on the master";
    $self->check_messages(\%master_exp, store => $master_store);
    xlog "After second replication, the message is still missing on the replica";
    $self->check_messages(\%replica_exp, store => $replica_store);
}

sub test_msg_sort_order
{
    my ($self) = @_;

    xlog "testing RFC5257 SORT command ANNOTATION order criterion";

    my $entry = '/comment';
    my $attrib = 'value.priv';
    # 20 random dictionary words
    my @values = ( qw(gradual flips tempe cud flaunt nina crackle congo),
		   qw(buttons coating byrd arise ayyubid badgers argosy),
		   qw(sutton dallied belled fondues mimi) );
    # the expected result of sorting those words alphabetically
    my @exp_order = ( 15, 12, 13, 14, 18, 9, 11, 10, 8,
		      7, 4, 17, 5, 2, 19, 1, 20, 6, 16, 3 );

    $self->{store}->set_fetch_attributes('uid', "annotation ($entry $attrib)");

    xlog "Append some messages and store annotations";
    my %exp;
    for (my $i = 0 ; $i < 20 ; $i++)
    {
	my $letter = chr(ord('A')+$i);
	my $uid = $i+1;
	my $value = $values[$i];

	$exp{$letter} = $self->make_message("Message $letter");
	$self->set_msg_annotation(undef, $uid, $entry, $attrib, $value);
	$exp{$letter}->set_attribute('uid', $uid);
	$exp{$letter}->set_annotation($entry, $attrib, $value);
    }
    $self->check_messages(\%exp);

    my $talk = $self->{store}->get_client();

    xlog "run the SORT command with an ANNOTATION order criterion";
    my $res = $talk->sort("(ANNOTATION $entry $attrib)", 'utf-8', 'all');
    $self->assert_str_equals('ok', $talk->get_last_completion_response());
    $self->assert_not_null($res);
    $self->assert_deep_equals(\@exp_order, $res);
}

sub test_msg_sort_search
{
    my ($self) = @_;

    xlog "testing RFC5257 SORT command ANNOTATION search criterion";

    my $entry = '/comment';
    my $attrib = 'value.priv';
    # 10 random dictionary words, and 10 carefully chosen ones
    my @values = ( qw(deirdre agreed feedback cuspids breeds decreed greedily),
		   qw(gibbers eakins flash needful yules linseed equine hangman),
		   qw(hatters ragweed pureed cloaked heedless) );
    # the expected result of sorting the words with 'eed' alphabetically
    my @exp_order = ( 2, 5, 6, 3, 7, 20, 13, 11, 18, 17 );
    # the expected result of search for words with 'eed' and uid order
    my @exp_search = ( 2, 3, 5, 6, 7, 11, 13, 17, 18, 20 );

    $self->{store}->set_fetch_attributes('uid', "annotation ($entry $attrib)");

    xlog "Append some messages and store annotations";
    my %exp;
    my $now = DateTime->now->epoch;
    for (my $i = 0 ; $i < 20 ; $i++)
    {
	my $letter = chr(ord('A')+$i);
	my $uid = $i+1;
	my $value = $values[$i];
	my $date = DateTime->from_epoch(epoch => $now - (20-$i)*60);

	$exp{$letter} = $self->make_message("Message $letter",
					    date => $date);
	$self->set_msg_annotation(undef, $uid, $entry, $attrib, $value);
	$exp{$letter}->set_attribute('uid', $uid);
	$exp{$letter}->set_annotation($entry, $attrib, $value);
    }
    $self->check_messages(\%exp);

    my $talk = $self->{store}->get_client();

    xlog "run the SORT command with an ANNOTATION search criterion";
    my $res = $talk->sort("(DATE)", 'utf-8',
		          'ANNOTATION', $entry, $attrib, { Quote => "eed" });
    $self->assert_str_equals('ok', $talk->get_last_completion_response());
    $self->assert_not_null($res);
    $self->assert_deep_equals(\@exp_search, $res);

    xlog "run the SORT command with both ANNOTATION search & order criteria";
    $res = $talk->sort("(ANNOTATION $entry $attrib)", 'utf-8',
		       'ANNOTATION', $entry, $attrib, { Quote => "eed" });
    $self->assert_str_equals('ok', $talk->get_last_completion_response());
    $self->assert_not_null($res);
    $self->assert_deep_equals(\@exp_order, $res);
}




# Not sure if this cases can even work...
# sub test_msg_replication_mod_bot_mse

# Get the highestmodseq of the folder
sub get_highestmodseq
{
    my ($self) = @_;

    my $store = $self->{store};
    my $talk = $store->get_client();
    my $stat = $talk->status($store->{folder}, '(highestmodseq)');
    return undef unless defined $stat;
    return undef unless ref $stat eq 'HASH';
    return undef unless defined $stat->{highestmodseq};
    return 0 + $stat->{highestmodseq};
}

#
# Test interaction between RFC4551 modseq and STORE ANNOTATION
#  - setting an annotation the message's modseq
#    and the folder's highestmodseq
#  - deleting an annotation bumps the message's modseq etc
#  - modseq of other messages is never affected
#
sub test_modseq
{
    my ($self) = @_;

    my $talk = $self->{store}->get_client();
    $self->{store}->_select();
    $self->assert_num_equals(1, $talk->uid());
    $self->{store}->set_fetch_attributes(qw(uid modseq));

    xlog "Append 3 messages";
    my %msg;
    $msg{A} = $self->make_message('Message A');
    $msg{B} = $self->make_message('Message B');
    $msg{C} = $self->make_message('Message C');

    my $entry = '/comment';
    my $attrib = 'value.priv';
    my $value1 = "Hello World";

    xlog "fetch an annotation - should be no values";
    my $hms0 = $self->get_highestmodseq();
    my $res = $talk->fetch('1:*',
			   ['modseq', 'annotation', [$entry, $attrib]]);
    $self->assert_str_equals('ok', $talk->get_last_completion_response());
    $self->assert_not_null($res);
    $self->assert_deep_equals(
	    {
		1 => {
			modseq => [$hms0-2],
			annotation => [ $entry, [ $attrib, undef ] ]
		     },
		2 => {
			modseq => [$hms0-1],
			annotation => [ $entry, [ $attrib, undef ] ]
		     },
		3 => {
			modseq => [$hms0],
			annotation => [ $entry, [ $attrib, undef ] ]
		     },
	    },
	    $res);

    xlog "store an annotation";
    $talk->store('1', 'annotation',
	         [$entry, [$attrib, $value1]]);
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    xlog "fetch an annotation - should be updated";
    my $hms1 = $self->get_highestmodseq();
    $self->assert($hms1 > $hms0);
    $res = $talk->fetch('1:*',
		        ['modseq', 'annotation', [$entry, $attrib]]);
    $self->assert_str_equals('ok', $talk->get_last_completion_response());
    $self->assert_not_null($res);
    $self->assert_deep_equals(
	    {
		1 => {
			modseq => [$hms1],
			annotation => [ $entry, [ $attrib, $value1 ] ]
		     },
		2 => {
			modseq => [$hms0-1],
			annotation => [ $entry, [ $attrib, undef ] ]
		     },
		3 => {
			modseq => [$hms0],
			annotation => [ $entry, [ $attrib, undef ] ]
		     },
	    },
	    $res);

    xlog "delete an annotation";
    $talk->store('1', 'annotation',
	         [$entry, [$attrib, undef]]);
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    xlog "fetch an annotation - should be updated";
    my $hms2 = $self->get_highestmodseq();
    $self->assert($hms2 > $hms1);
    $res = $talk->fetch('1:*',
		        ['modseq', 'annotation', [$entry, $attrib]]);
    $self->assert_str_equals('ok', $talk->get_last_completion_response());
    $self->assert_not_null($res);
    $self->assert_deep_equals(
	    {
		1 => {
			modseq => [$hms2],
			annotation => [ $entry, [ $attrib, undef ] ]
		     },
		2 => {
			modseq => [$hms0-1],
			annotation => [ $entry, [ $attrib, undef ] ]
		     },
		3 => {
			modseq => [$hms0],
			annotation => [ $entry, [ $attrib, undef ] ]
		     },
	    },
	    $res);
}

#
# Test UNCHANGEDSINCE modifier; RFC4551 section 3.2.
# - changing an annotation with current modseq equal to the
#   UNCHANGEDSINCE value
#	- updates the annotation
#	- updates modseq
#	- sends an untagged FETCH response
#	- the FETCH response has the new modseq
#	- returns an OK response
#	- the UID does not appear in the MODIFIED response code
# - ditto less than
# - changing an annotation with current modseq greater than the
#   UNCHANGEDSINCE value
#	- doesn't update the annotation
#	- doesn't update modseq
#	- sent no FETCH untagged response
#	- returns an OK response
#	- but reports the UID in the MODIFIED response code
#
sub test_unchangedsince
{
    my ($self) = @_;

    my $talk = $self->{store}->get_client();
    $self->{store}->_select();
    $self->assert_num_equals(1, $talk->uid());
    $self->{store}->set_fetch_attributes(qw(uid modseq));

    xlog "Append 3 messages";
    my %msg;
    $msg{A} = $self->make_message('Message A');
    $msg{B} = $self->make_message('Message B');
    $msg{C} = $self->make_message('Message C');
    my $hms0 = $self->get_highestmodseq();

    my $entry = '/comment';
    my $attrib = 'value.priv';
    my $value1 = "Hello World";
    my $value2 = "Janis Joplin";
    my $value3 = "Phantom of the Opera";

    my %fetched;
    my $modified;
    my %handlers =
    (
	fetch => sub
	{
	    my ($response, $rr, $id) = @_;

	    # older versions of Mail::IMAPTalk don't have
	    # the 3rd argument.  We can't test properly in
	    # those circumstances.
	    $self->assert_not_null($id);

	    $fetched{$id} = $rr;
	},
	modified => sub
	{
	    my ($response, $rr) = @_;
	    # we should not get more than one of these ever
	    $self->assert_null($modified);
	    $modified = $rr;
	}
    );

    # Note: Mail::IMAPTalk::store() doesn't support modifiers
    # so we have to resort to the lower level interface.

    xlog "setting an annotation with current modseq == UNCHANGEDSINCE";
    %fetched = ();
    $modified = undef;
    $talk->_imap_cmd('store', 1, \%handlers,
		 '1', ['unchangedsince', $hms0-2],
	         'annotation', [$entry, [$attrib, $value1]]);
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    xlog "fetch an annotation - should be updated";
    my $hms1 = $self->get_highestmodseq();
    $self->assert($hms1 > $hms0);
    my $res = $talk->fetch('1:*',
		           ['modseq', 'annotation', [$entry, $attrib]]);
    $self->assert_str_equals('ok', $talk->get_last_completion_response());
    $self->assert_not_null($res);
    $self->assert_deep_equals(
	    {
		1 => {
			modseq => [$hms1],
			annotation => [ $entry, [ $attrib, $value1 ] ]
		     },
		2 => {
			modseq => [$hms0-1],
			annotation => [ $entry, [ $attrib, undef ] ]
		     },
		3 => {
			modseq => [$hms0],
			annotation => [ $entry, [ $attrib, undef ] ]
		     },
	    },
	    $res);

    xlog "setting an annotation with current modseq < UNCHANGEDSINCE";
    %fetched = ();
    $modified = undef;
    $talk->_imap_cmd('store', 1, \%handlers,
		 '1', ['unchangedsince', $hms1+1],
	         'annotation', [$entry, [$attrib, $value2]]);
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    xlog "fetch an annotation - should be updated";
    my $hms2 = $self->get_highestmodseq();
    $self->assert($hms2 > $hms1);
    $res = $talk->fetch('1:*',
		        ['modseq', 'annotation', [$entry, $attrib]]);
    $self->assert_str_equals('ok', $talk->get_last_completion_response());
    $self->assert_not_null($res);
    $self->assert_deep_equals(
	    {
		1 => {
			modseq => [$hms2],
			annotation => [ $entry, [ $attrib, $value2 ] ]
		     },
		2 => {
			modseq => [$hms0-1],
			annotation => [ $entry, [ $attrib, undef ] ]
		     },
		3 => {
			modseq => [$hms0],
			annotation => [ $entry, [ $attrib, undef ] ]
		     },
	    },
	    $res);

    xlog "setting an annotation with current modseq > UNCHANGEDSINCE";
    %fetched = ();
    $modified = undef;
    $talk->_imap_cmd('store', 1, \%handlers,
		 '1', ['unchangedsince', $hms2-1],
	         'annotation', [$entry, [$attrib, $value3]]);
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    xlog "didn't update modseq?";
    my $hms3 = $self->get_highestmodseq();
    $self->assert($hms3 == $hms2);
    xlog "fetch an annotation - should not be updated";
    $res = $talk->fetch('1:*',
		        ['modseq', 'annotation', [$entry, $attrib]]);
    $self->assert_str_equals('ok', $talk->get_last_completion_response());
    $self->assert_not_null($res);
    $self->assert_deep_equals(
	    {
		1 => {
			# unchanged
			modseq => [$hms2],
			annotation => [ $entry, [ $attrib, $value2 ] ]
		     },
		2 => {
			modseq => [$hms0-1],
			annotation => [ $entry, [ $attrib, undef ] ]
		     },
		3 => {
			modseq => [$hms0],
			annotation => [ $entry, [ $attrib, undef ] ]
		     },
	    },
	    $res);
    xlog "reports the UID in the MODIFIED response code?";
    $self->assert_not_null($modified);
    $self->assert_deep_equals($modified, [1]);
    xlog "sent no FETCH untagged response?";
    $self->assert_num_equals(0, scalar keys %fetched);
}

1;

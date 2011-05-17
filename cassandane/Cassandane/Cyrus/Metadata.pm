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
use base qw(Test::Unit::TestCase);
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

sub make_message
{
    my ($self, $subject, @attrs) = @_;

    $self->{store}->write_begin();
    my $msg = $self->{gen}->generate(subject => $subject, @attrs);
    $self->{store}->write_message($msg);
    $self->{store}->write_end();

    return $msg;
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

    # size should be zero
    $self->assert_not_null($res->{INBOX}{"/shared/vendor/cmu/cyrus-imapd/size"});
    $self->assert_num_equals(0, $res->{INBOX}{"/shared/vendor/cmu/cyrus-imapd/size"});

    # parition should be default
    $self->assert_str_equals('default', $res->{INBOX}{"/shared/vendor/cmu/cyrus-imapd/partition"});

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

sub test_permessage
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

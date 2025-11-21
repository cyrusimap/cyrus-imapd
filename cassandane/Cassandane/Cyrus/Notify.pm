#!/usr/bin/perl
#
#  Copyright (c) 2011-2023 FastMail Pty Ltd. All rights reserved.
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

package Cassandane::Cyrus::Notify;
use strict;
use warnings;
use DateTime;
use Data::Dumper;

use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;

sub new
{
    my $class = shift;
    my $config = Cassandane::Config->default()->clone();
    $config->set(imapidlepoll => 2);
    return $class->SUPER::new({
        config => $config,
        deliver => 1,
        start_instances => 0,
    }, @_);
}

sub set_up
{
    my ($self) = @_;
    $self->SUPER::set_up();
}

sub tear_down
{
    my ($self) = @_;
    $self->SUPER::tear_down();
}

sub test_bad
    :needs_component_idled :min_version_3_9
{
    my ($self) = @_;

    xlog $self, "Message test of the NOTIFY command (idled required)";

    $self->{instance}->{config}->set(imapidlepoll => '2');
    $self->{instance}->add_start(name => 'idled',
                                 argv => [ 'idled' ]);
    $self->{instance}->start();

    my $svc = $self->{instance}->get_service('imap');

    my $store = $svc->create_store();
    my $talk = $store->get_client();

    xlog $self, "The server should report the NOTIFY capability";
    $self->assert($talk->capability()->{notify});

    xlog $self, "Enable Notify with a missing arg";
    my $res = $talk->_imap_cmd('NOTIFY', 0, 'STATUS');
    $self->assert_str_equals('bad', $talk->get_last_completion_response());

    xlog $self, "Enable Notify with an invalid arg";
    $res = $talk->_imap_cmd('NOTIFY', 0, 'STATUS', 'FOO');
    $self->assert_str_equals('bad', $talk->get_last_completion_response());

    xlog $self, "Enable Notify with a missing filter";
    $res = $talk->_imap_cmd('NOTIFY', 0, 'STATUS', 'SET');
    $self->assert_str_equals('bad', $talk->get_last_completion_response());

    xlog $self, "Enable Notify with an invalid filter";
    $res = $talk->_imap_cmd('NOTIFY', 0, 'STATUS', 'SET',
                            "(FOO (MessageNew MessageExpunge))");
    $self->assert_str_equals('bad', $talk->get_last_completion_response());

    xlog $self, "Enable Notify with a duplicate filter";
    $res = $talk->_imap_cmd('NOTIFY', 0, 'STATUS', 'SET',
                            "(SELECTED (MessageNew MessageExpunge))",
                            "(SELECTED-DELAYED (MessageNew MessageExpunge))");
    $self->assert_str_equals('bad', $talk->get_last_completion_response());

    xlog $self, "Enable Notify with another duplicate filter";
    $res = $talk->_imap_cmd('NOTIFY', 0, 'STATUS', 'SET',
                            "(INBOXES (MessageNew MessageExpunge))",
                            "(INBOXES (MessageNew MessageExpunge FlagChange))");
    $self->assert_str_equals('bad', $talk->get_last_completion_response());

    xlog $self, "Enable Notify with an invalid event";
    $res = $talk->_imap_cmd('NOTIFY', 0, 'STATUS', 'SET',
                            "(INBOXES (MessageNew MessageExpunge Foo))");
    $self->assert_str_equals('no', $talk->get_last_completion_response());

    xlog $self, "Enable Notify with an invalid event group";
    $res = $talk->_imap_cmd('NOTIFY', 0, 'STATUS', 'SET',
                            "(SELECTED-DELAYED (MessageNew))");
    $self->assert_str_equals('bad', $talk->get_last_completion_response());

    xlog $self, "Enable Notify with another invalid event group";
    $res = $talk->_imap_cmd('NOTIFY', 0, 'STATUS', 'SET',
                            "(PERSONAL (MessageExpunge FlagChange))");
    $self->assert_str_equals('bad', $talk->get_last_completion_response());

    xlog $self, "Enable Notify with an empty mailbox list";
    $res = $talk->_imap_cmd('NOTIFY', 0, 'STATUS', 'SET',
                            "(MAILBOXES () (MessageNew MessageExpunge))");
    $self->assert_str_equals('bad', $talk->get_last_completion_response());
}

sub test_message
    :needs_component_idled :Conversations
{
    my ($self) = @_;

    xlog $self, "Message test of the NOTIFY command (idled required)";

    $self->{instance}->{config}->set(imapidlepoll => '2');
    $self->{instance}->add_start(name => 'idled',
                                 argv => [ 'idled' ]);
    $self->{instance}->start();

    my $svc = $self->{instance}->get_service('imap');

    my $store = $svc->create_store();
    my $talk = $store->get_client();

    my $otherstore = $svc->create_store();
    my $othertalk = $otherstore->get_client();

    xlog $self, "The server should report the NOTIFY capability";
    $self->assert($talk->capability()->{notify});

    xlog $self, "Create two mailboxes";
    $talk->create("INBOX.foo");
    $talk->create("INBOX.bar");

    xlog $self, "Deliver a message";
    my $msg = $self->{gen}->generate(subject => "Message 1");
    $self->{instance}->deliver($msg);

    xlog $self, "Examine INBOX.foo";
    $talk->examine("INBOX.foo");

    xlog $self, "Enable Notify";
    my $res = $talk->_imap_cmd('NOTIFY', 0, 'STATUS', 'SET', 'STATUS',
                               "(SELECTED (MessageNew" .
                               " (UID EMAILID MAILBOXIDS BODY.PEEK[HEADER.FIELDS (From Subject)])" .
                               " MessageExpunge FlagChange))",
                               "(PERSONAL (MessageNew MessageExpunge))");

    # Should get STATUS responses for unselected mailboxes
    my $status = $talk->get_response_code('status');
    $self->assert_num_equals(1, $status->{'INBOX'}{messages});
    $self->assert_num_equals(2, $status->{'INBOX'}{uidnext});
    $self->assert_num_equals(0, $status->{'INBOX.bar'}{messages});
    $self->assert_num_equals(1, $status->{'INBOX.bar'}{uidnext});

    xlog $self, "Deliver a message";
    $msg = $self->{gen}->generate(subject => "Message 2");
    $self->{instance}->deliver($msg);

    # Should get STATUS response for INBOX
    $res = $store->idle_response('STATUS', 3);
    $self->assert($res, "received an unsolicited response");
    $res = $store->idle_response({}, 1);
    $self->assert(!$res, "no more unsolicited responses");

    $status = $talk->get_response_code('status');
    $self->assert_num_equals(2, $status->{'INBOX'}{messages});
    $self->assert_num_equals(3, $status->{'INBOX'}{uidnext});

    xlog $self, "EXPUNGE message from INBOX in other session";
    $othertalk->select("INBOX");
    $res = $othertalk->store('1', '+flags', '(\\Deleted)');
    $res = $othertalk->expunge();

    # Should get STATUS response for INBOX
    $res = $store->idle_response('STATUS', 3);
    $self->assert($res, "received an unsolicited response");
    $res = $store->idle_response({}, 1);
    $self->assert(!$res, "no more unsolicited responses");

    $status = $talk->get_response_code('status');
    $self->assert_num_equals(1, $status->{'INBOX'}{messages});
    $self->assert_num_equals(3, $status->{'INBOX'}{uidnext});

    xlog $self, "Select INBOX";
    $talk->examine("INBOX");

    xlog $self, "Deliver a message";
    $msg = $self->{gen}->generate(subject => "Message 3");
    $self->{instance}->deliver($msg);

    # Should get EXISTS, RECENT, FETCH response
    $res = $store->idle_response({}, 3);
    $self->assert($res, "received an unsolicited response");
    $res = $store->idle_response({}, 3);
    $self->assert($res, "received an unsolicited response");
    $res = $store->idle_response('FETCH', 3);
    $self->assert($res, "received an unsolicited response");
    $res = $store->idle_response({}, 1);
    $self->assert(!$res, "no more unsolicited responses");

    $self->assert_num_equals(2, $talk->get_response_code('exists'));
    $self->assert_num_equals(1, $talk->get_response_code('recent'));

    my $fetch = $talk->get_response_code('fetch');
    $self->assert_num_equals(3, $fetch->{2}{uid});
    $self->assert_str_equals('Message 3', $fetch->{2}{headers}{subject}[0]);
    $self->assert_not_null($fetch->{2}{headers}{from});
    $self->assert_not_null($fetch->{2}{emailid}[0]);
    $self->assert_not_null($fetch->{2}{mailboxids}[0]);

    xlog $self, "DELETE message from INBOX in other session";
    $res = $othertalk->store('1', '+flags', '(\\Deleted)');

    # Should get FETCH response for INBOX
    $res = $store->idle_response('FETCH', 3);
    $self->assert($res, "received an unsolicited response");
    $res = $store->idle_response({}, 1);
    $self->assert(!$res, "no more unsolicited responses");

    $fetch = $talk->get_response_code('fetch');
    $self->assert_num_equals(2, $fetch->{1}{uid});
    $self->assert_str_equals('\\Deleted', $fetch->{1}{flags}[0]);

    xlog $self, "EXPUNGE message from INBOX in other session";
    $res = $othertalk->expunge();

    # Should get EXPUNGE response for INBOX
    $res = $store->idle_response('EXPUNGE', 3);
    $self->assert($res, "received an unsolicited response");
    $res = $store->idle_response({}, 1);
    $self->assert(!$res, "no more unsolicited responses");

    $self->assert_num_equals(1, $talk->get_response_code('expunge'));

    xlog $self, "Disable Notify";
    $res = $talk->_imap_cmd('NOTIFY', 0, "", "NONE");

    xlog $self, "Deliver a message";
    $msg = $self->{gen}->generate(subject => "Message 4");
    $self->{instance}->deliver($msg);

    # Should get no unsolicited responses
    $res = $store->idle_response({}, 1);
    $self->assert(!$res, "no unsolicited responses");

    # make sure that the connection is ended so that imapd reset happens
    $talk->logout();
    undef $talk;

    # we enabled NOTIFY, so we should see it in client behaviors
    my $pat = qr/session ended.*notify=<1>/;
    $self->assert_syslog_matches($self->{instance}, $pat);
}

sub test_mailbox
    :needs_component_idled :min_version_3_9
{
    my ($self) = @_;

    xlog $self, "Mailbox test of the NOTIFY command (idled required)";

    $self->{instance}->{config}->set(imapidlepoll => '2');
    $self->{instance}->add_start(name => 'idled',
                                 argv => [ 'idled' ]);
    $self->{instance}->start();

    my $svc = $self->{instance}->get_service('imap');

    my $store = $svc->create_store();
    my $talk = $store->get_client();

    my $otherstore = $svc->create_store();
    my $othertalk = $otherstore->get_client();

    xlog $self, "The server should report the NOTIFY capability";
    $self->assert($talk->capability()->{notify});

    xlog $self, "Enable Notify";
    my $res = $talk->_imap_cmd('NOTIFY', 0, "", "SET",
                               "(PERSONAL (MailboxName SubscriptionChange))");

    xlog $self, "Create mailbox in other session";
    $othertalk->create("INBOX.rename-me");

    # Should get LIST response
    $res = $store->idle_response('LIST', 3);
    $self->assert($res, "received an unsolicited response");
    $res = $store->idle_response({}, 1);
    $self->assert(!$res, "no more unsolicited responses");

    my $list = $talk->get_response_code('list');
    $self->assert_str_equals('INBOX.rename-me', $list->[0][2]);

    xlog $self, "Subscribe mailbox in other session";
    $othertalk->subscribe("INBOX.rename-me");

    # Should get LIST response with \Subscribed
    $res = $store->idle_response('LIST', 3);
    $self->assert($res, "received an unsolicited response");
    $res = $store->idle_response({}, 1);
    $self->assert(!$res, "no more unsolicited responses");

    $list = $talk->get_response_code('list');
    $self->assert_str_equals('\\Subscribed', $list->[0][0][0]);
    $self->assert_str_equals('INBOX.rename-me', $list->[0][2]);

    xlog $self, "Rename mailbox in other session";
    $othertalk->rename("INBOX.rename-me", "INBOX.delete-me");

    # Use our own handler since IMAPTalk will lose OLDNAME
    my %handlers =
    (
        list => sub
        {
            my (undef, $data) = @_;
            $list = [ $data ];
        },
    );

    # Should get LIST response with OLDNAME
    $res = $store->idle_response(\%handlers, 3);
    $self->assert($res, "received an unsolicited response");
    $res = $store->idle_response({}, 1);
    $self->assert(!$res, "no more unsolicited responses");

    $self->assert_str_equals('INBOX.delete-me', $list->[0][2]);
    $self->assert_str_equals('OLDNAME', $list->[0][3][0]);
    $self->assert_str_equals('INBOX.rename-me', $list->[0][3][1][0]);

    xlog $self, "Delete mailbox in other session";
    $othertalk->delete("INBOX.delete-me");

    # Should get LIST response with \NonExistent
    $res = $store->idle_response({}, 3);
    $self->assert($res, "received an unsolicited response");
    $res = $store->idle_response({}, 1);
    $self->assert(!$res, "no more unsolicited responses");

    $list = $talk->get_response_code('list');
    $self->assert_str_equals('\\NonExistent', $list->[0][0][0]);
    $self->assert_str_equals('INBOX.delete-me', $list->[0][2]);

    xlog $self, "Disable Notify";
    $res = $talk->_imap_cmd('NOTIFY', 0, "", "NONE");

    xlog $self, "Create mailbox in other session";
    $othertalk->create("INBOX.foo");

    # Should get no unsolicited responses
    $res = $store->idle_response({}, 1);
    $self->assert(!$res, "no unsolicited responses");
}

sub test_idle
    :needs_component_idled :min_version_3_9
{
    my ($self) = @_;

    xlog $self, "Test of the NOTIFY + IDLE commands (idled required)";

    $self->{instance}->{config}->set(imapidlepoll => '2');
    $self->{instance}->add_start(name => 'idled',
                                 argv => [ 'idled' ]);
    $self->{instance}->start();

    my $svc = $self->{instance}->get_service('imap');

    my $store = $svc->create_store();
    my $talk = $store->get_client();

    my $otherstore = $svc->create_store();
    my $othertalk = $otherstore->get_client();

    xlog $self, "The server should report the NOTIFY capability";
    $self->assert($talk->capability()->{notify});

    xlog $self, "Enable Notify";
    my $res = $talk->_imap_cmd('NOTIFY', 0, "", 'SET',
                               "(SELECTED (MessageNew" .
                               " (UID BODY.PEEK[HEADER.FIELDS (From Subject)])" .
                               " MessageExpunge))",
                               "(PERSONAL (MessageNew MessageExpunge MailboxName))");

    # Should NOT get STATUS response for INBOX
    $res = $store->idle_response({}, 1);
    $self->assert(!$res, "no more unsolicited responses");

    xlog $self, "Examine INBOX";
    $talk->examine("INBOX");
    $self->assert_num_equals(0, $talk->get_response_code('exists'));
    $self->assert_num_equals(0, $talk->get_response_code('recent'));
    $self->assert_num_equals(1, $talk->get_response_code('uidnext'));

    xlog $self, "Sending the IDLE command";
    $store->idle_begin()
        or die "IDLE failed: $@";

    xlog $self, "Deliver a message";
    my $msg = $self->{gen}->generate(subject => "Message 1");
    $self->{instance}->deliver($msg);

    # Should get EXISTS, RECENT, FETCH response
    $res = $store->idle_response({}, 3);
    $self->assert($res, "received an unsolicited response");
    $res = $store->idle_response({}, 3);
    $self->assert($res, "received an unsolicited response");
    $res = $store->idle_response('FETCH', 3);
    $self->assert($res, "received an unsolicited response");
    $res = $store->idle_response({}, 1);
    $self->assert(!$res, "no more unsolicited responses");

    $self->assert_num_equals(1, $talk->get_response_code('exists'));
    $self->assert_num_equals(1, $talk->get_response_code('recent'));

    my $fetch = $talk->get_response_code('fetch');
    $self->assert_num_equals(1, $fetch->{1}{uid});
    $self->assert_str_equals('Message 1', $fetch->{1}{headers}{subject}[0]);

    xlog $self, "Create mailbox in other session";
    $othertalk->create("INBOX.foo");

    # Should get LIST response
    $res = $store->idle_response('LIST', 3);
    $self->assert($res, "received an unsolicited response");
    $res = $store->idle_response({}, 1);
    $self->assert(!$res, "no more unsolicited responses");

    my $list = $talk->get_response_code('list');
    $self->assert_str_equals('INBOX.foo', $list->[0][2]);

    $othertalk->select("INBOX");

    xlog $self, "Add \Flagged to message in INBOX in other session";
    $res = $othertalk->store('1', '+flags', '(\\Flagged)');

    # Should NOT get FETCH response for INBOX
    $res = $store->idle_response('FETCH', 1);
    $self->assert(!$res, "no more unsolicited responses");

    xlog $self, "MOVE message from INBOX to INBOX.foo in other session";
    $res = $othertalk->move('1', "INBOX.foo");

    # Should get STATUS response for INBOX.foo and EXPUNGE response for INBOX
    $res = $store->idle_response('STATUS', 3);
    $self->assert($res, "received an unsolicited response");
    $res = $store->idle_response({}, 3);
    $self->assert($res, "received an unsolicited response");
    $res = $store->idle_response({}, 1);
    $self->assert(!$res, "no more unsolicited responses");

    my $status = $talk->get_response_code('status');
    $self->assert_num_equals(1, $status->{'INBOX.foo'}{messages});
    $self->assert_num_equals(2, $status->{'INBOX.foo'}{uidnext});
    $self->assert_num_equals(1, $talk->get_response_code('expunge'));

    xlog $self, "Sending DONE continuation";
    $store->idle_end({});
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    xlog $self, "Deliver a message";
    $msg = $self->{gen}->generate(subject => "Message 2");
    $self->{instance}->deliver($msg);

    # Should get EXISTS, RECENT, FETCH response
    $res = $store->idle_response({}, 3);
    $self->assert($res, "received an unsolicited response");
    $res = $store->idle_response({}, 3);
    $self->assert($res, "received an unsolicited response");
    $res = $store->idle_response('FETCH', 3);
    $self->assert($res, "received an unsolicited response");
    $res = $store->idle_response({}, 1);
    $self->assert(!$res, "no more unsolicited responses");

    $self->assert_num_equals(1, $talk->get_response_code('exists'));
    $self->assert_num_equals(1, $talk->get_response_code('recent'));

    $fetch = $talk->get_response_code('fetch');
    $self->assert_num_equals(2, $fetch->{1}{uid});
    $self->assert_str_equals('Message 2', $fetch->{1}{headers}{subject}[0]);

    xlog $self, "Unselect INBOX";
    $talk->unselect();

    xlog $self, "Deliver a message";
    $msg = $self->{gen}->generate(subject => "Message 3");
    $self->{instance}->deliver($msg);

    # Should get STATUS response for INBOX
    $res = $store->idle_response('STATUS', 3);
    $self->assert($res, "received an unsolicited response");
    $res = $store->idle_response({}, 1);
    $self->assert(!$res, "no more unsolicited responses");

    $status = $talk->get_response_code('status');
    $self->assert_num_equals(2, $status->{'INBOX'}{messages});
    $self->assert_num_equals(4, $status->{'INBOX'}{uidnext});

    xlog $self, "Delete mailbox in other session";
    $othertalk->delete("INBOX.foo");

    # Should get LIST response with \NonExistent
    $res = $store->idle_response({}, 3);
    $self->assert($res, "received an unsolicited response");
    $res = $store->idle_response({}, 1);
    $self->assert(!$res, "no more unsolicited responses");

    $list = $talk->get_response_code('list');
    $self->assert_str_equals('\\NonExistent', $list->[0][0][0]);
    $self->assert_str_equals('INBOX.foo', $list->[0][2]);
}

sub test_selected_delayed
    :needs_component_idled :min_version_3_9
{
    my ($self) = @_;

    xlog $self, "Selected-delayed test of the NOTIFY command (idled required)";

    $self->{instance}->{config}->set(imapidlepoll => '2');
    $self->{instance}->add_start(name => 'idled',
                                 argv => [ 'idled' ]);
    $self->{instance}->start();

    my $svc = $self->{instance}->get_service('imap');

    my $store = $svc->create_store();
    my $talk = $store->get_client();

    my $otherstore = $svc->create_store();
    my $othertalk = $otherstore->get_client();

    xlog $self, "The server should report the NOTIFY capability";
    $self->assert($talk->capability()->{notify});

    xlog $self, "Enable Notify";
    my $res = $talk->_imap_cmd('NOTIFY', 0, 'STATUS', 'SET',
                               "(SELECTED-DELAYED (MessageNew MessageExpunge FlagChange))");

    xlog $self, "Examine INBOX";
    $talk->examine("INBOX");

    xlog $self, "Deliver a message";
    my $msg = $self->{gen}->generate(subject => "Message 1");
    $self->{instance}->deliver($msg);

    # Should get EXISTS, RECENT response
    $res = $store->idle_response({}, 3);
    $self->assert($res, "received an unsolicited response");
    $res = $store->idle_response({}, 3);
    $self->assert($res, "received an unsolicited response");
    $res = $store->idle_response({}, 1);
    $self->assert(!$res, "no more unsolicited responses");

    $self->assert_num_equals(1, $talk->get_response_code('exists'));
    $self->assert_num_equals(1, $talk->get_response_code('recent'));

    xlog $self, "EXPUNGE message from INBOX in other session";
    $othertalk->select("INBOX");
    $res = $othertalk->store('1', '+flags', '(\\Deleted)');
    $res = $othertalk->expunge();

    # Should get FETCH response, but NO EXPUNGE response
    $res = $store->idle_response('FETCH', 3);
    $self->assert($res, "received an unsolicited response");
    $res = $store->idle_response({}, 1);
    $self->assert(!$res, "no more unsolicited responses");

    my $fetch = $talk->get_response_code('fetch');
    $self->assert_num_equals(1, $fetch->{1}{uid});
    $self->assert_str_equals('\\Recent', $fetch->{1}{flags}[0]);
    $self->assert_str_equals('\\Deleted', $fetch->{1}{flags}[1]);

    xlog $self, "Poll for changes";
    $talk->noop();

    # Should get EXPUNGE response
    $self->assert_num_equals(1, $talk->get_response_code('expunge'));
}

sub test_change_selected
    :needs_component_idled :min_version_3_9
{
    my ($self) = @_;

    xlog $self, "Test of NOTIFY events following SELECTED mailbox";

    $self->{instance}->{config}->set(imapidlepoll => '2');
    $self->{instance}->add_start(name => 'idled',
                                 argv => [ 'idled' ]);
    $self->{instance}->start();

    my $svc = $self->{instance}->get_service('imap');

    my $store = $svc->create_store();
    my $talk = $store->get_client();

    my $otherstore = $svc->create_store();
    my $othertalk = $otherstore->get_client();

    xlog $self, "The server should report the NOTIFY capability";
    $self->assert($talk->capability()->{notify});

    xlog $self, "Create another mailbox";
    $talk->create("INBOX.foo");

    xlog $self, "Enable Notify";
    my $res = $talk->_imap_cmd('NOTIFY', 0, "", 'SET',
                               "(SELECTED (MessageNew MessageExpunge))",
                               "(PERSONAL (MessageNew MessageExpunge))");

    xlog $self, "Examine INBOX";
    $talk->examine("INBOX");
    $self->assert_num_equals(0, $talk->get_response_code('exists'));
    $self->assert_num_equals(0, $talk->get_response_code('recent'));
    $self->assert_num_equals(1, $talk->get_response_code('uidnext'));

    xlog $self, "Deliver a message";
    my $msg = $self->{gen}->generate(subject => "Message 1");
    $self->{instance}->deliver($msg);

    # Should get EXISTS, RECENT response
    $res = $store->idle_response({}, 3);
    $self->assert($res, "received an unsolicited response");
    $res = $store->idle_response({}, 3);
    $self->assert($res, "received an unsolicited response");
    $res = $store->idle_response({}, 1);
    $self->assert(!$res, "no more unsolicited responses");

    $self->assert_num_equals(1, $talk->get_response_code('exists'));
    $self->assert_num_equals(1, $talk->get_response_code('recent'));

    xlog $self, "Examine INBOX.foo";
    $talk->examine("INBOX.foo");
    $self->assert_num_equals(0, $talk->get_response_code('exists'));
    $self->assert_num_equals(0, $talk->get_response_code('recent'));
    $self->assert_num_equals(1, $talk->get_response_code('uidnext'));

    xlog $self, "MOVE message from INBOX to INBOX.foo in other session";
    $othertalk->select("INBOX");
    $res = $othertalk->move('1', "INBOX.foo");

    # Should get EXISTS, RECENT response for INBOX.foo and STATUS response for INBOX
    $res = $store->idle_response({}, 3);
    $self->assert($res, "received an unsolicited response");
    $res = $store->idle_response({}, 3);
    $self->assert($res, "received an unsolicited response");
    $res = $store->idle_response('STATUS', 3);
    $self->assert($res, "received an unsolicited response");
    $res = $store->idle_response({}, 1);
    $self->assert(!$res, "no more unsolicited responses");

    $self->assert_num_equals(1, $talk->get_response_code('exists'));
    $self->assert_num_equals(1, $talk->get_response_code('recent'));

    my $status = $talk->get_response_code('status');
    $self->assert_num_equals(0, $status->{'INBOX'}{messages});
    $self->assert_num_equals(2, $status->{'INBOX'}{uidnext});
}

1;

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

package Cassandane::Cyrus::Expunge;
use strict;
use warnings;
use JSON::XS;

use lib '.';
use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;

sub new
{
    my ($class, @args) = @_;
    return $class->SUPER::new({ adminstore => 1 }, @args);
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

sub test_status_after_expunge
{
    my ($self, $folder, %params) = @_;

    my $store = $self->{store};
    my $talk = $store->get_client();

    my $subfolder = 'INBOX.foo';

    xlog $self, "First create a sub folder";
    $talk->create($subfolder)
        or die "Cannot create folder $subfolder: $@";
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    xlog $self, "Generate messages in $subfolder";
    $store->set_folder($subfolder);
    $store->_select();
    for (1..5) {
        $self->make_message("Message $subfolder $_");
    }
    $talk->unselect();
    $talk->select($subfolder);

    my $stat = $talk->status($subfolder, '(highestmodseq unseen messages)');
    $self->assert_equals(5, $stat->{unseen});
    $self->assert_equals(5, $stat->{messages});

    $talk->store('1,3,5', '+flags', '(\\Seen)');

    $stat = $talk->status($subfolder, '(highestmodseq unseen messages)');
    $self->assert_equals(2, $stat->{unseen});
    $self->assert_equals(5, $stat->{messages});

    $talk->store('1:*', '+flags', '(\\Deleted \\Seen)');
    $talk->expunge();

    $stat = $talk->status($subfolder, '(highestmodseq unseen messages)');
    $self->assert_equals(0, $stat->{unseen});
    $self->assert_equals(0, $stat->{messages});
}

sub test_auditlog_size
    :min_version_3_5
{
    my ($self, $folder, %params) = @_;

    my $store = $self->{store};
    my $talk = $store->get_client();

    my $subfolder = 'INBOX.foo';

    xlog $self, "First create a sub folder";
    $talk->create($subfolder)
        or die "Cannot create folder $subfolder: $@";
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    xlog $self, "Generate messages in $subfolder";
    $store->set_folder($subfolder);
    $store->_select();
    for (1..5) {
        $self->make_message("Message $subfolder $_");
    }
    $talk->unselect();
    $talk->select($subfolder);

    # discard syslogs from setup
    $self->{instance}->getsyslog();

    my $resp = $talk->fetch('1,3,5', 'RFC822.SIZE');
    $self->assert_str_equals('ok', $talk->get_last_completion_response());
    $self->assert_not_null($resp);
    my %expected_sizes = map {
        $_ => $resp->{$_}->{'rfc822.size'}
    } keys %{$resp};

    $talk->store('1,3,5', '+flags', '(\\Deleted \\Seen)');
    $talk->expunge();

    my @auditlogs = grep {
        m/auditlog: expunge/
    } $self->{instance}->getsyslog();

    my %actual_sizes = map {
        m/ uid=<([0-9]+)>.* size=<([0-9]+)>/
    } @auditlogs;

    $self->assert_deep_equals(\%expected_sizes, \%actual_sizes);
}

sub test_allowdeleted
    :AllowDeleted :DelayedExpunge :min_version_3_1
{
    my ($self, $folder, %params) = @_;

    my $store = $self->{store};
    my $talk = $store->get_client();

    my $subfolder = 'INBOX.foo';

    xlog $self, "First create a sub folder";
    $talk->create($subfolder)
        or die "Cannot create folder $subfolder: $@";
    $self->assert_str_equals('ok', $talk->get_last_completion_response());

    xlog $self, "Generate messages in $subfolder";
    $store->set_folder($subfolder);
    $store->_select();
    for (1..5) {
        $self->make_message("Message $subfolder $_");
    }
    $talk->unselect();
    $talk->select($subfolder);

    my $stat = $talk->status($subfolder, '(highestmodseq unseen messages)');
    $self->assert_equals(5, $stat->{unseen});
    $self->assert_equals(5, $stat->{messages});

    my $oldemailids = $talk->fetch('1:*', 'emailid');
    my @oldemailids = map { $oldemailids->{$_}{emailid}[0] } sort { $a <=> $b } keys %$oldemailids;

    $talk->store('1,3,5', '+flags', '(\\Deleted)');
    $talk->expunge();

    $stat = $talk->status($subfolder, '(highestmodseq unseen messages)');
    $self->assert_equals(2, $stat->{unseen});
    $self->assert_equals(2, $stat->{messages});

    xlog $self, "regular select finds 2 messages";
    $talk->unselect();
    $talk->select($subfolder);
    $self->assert_str_equals('ok', $talk->get_last_completion_response());
    $self->assert_num_equals(2, $talk->get_response_code('exists'));

    xlog $self, "include-expunged select finds 5 messages";
    $talk->unselect();
    # this API is janky
    $talk->select($subfolder, '(vendor.cmu-include-expunged)' => 1);
    $self->assert_str_equals('ok', $talk->get_last_completion_response());
    $self->assert_num_equals(5, $talk->get_response_code('exists'));

    my $newemailids = $talk->fetch('1:*', 'emailid');
    my @newemailids = map { $newemailids->{$_}{emailid}[0] } sort { $a <=> $b } keys %$newemailids;
    $self->assert_deep_equals(\@oldemailids, \@newemailids, Data::Dumper::Dumper(\@oldemailids, \@newemailids));

    xlog $self, "copy of deleted messages recreates them";
    $talk->copy('1,3,5', $subfolder);
    $talk->unselect();
    $talk->select($subfolder);
    $self->assert_str_equals('ok', $talk->get_last_completion_response());
    $self->assert_num_equals(5, $talk->get_response_code('exists'));

    xlog $self, "new mailbox contains the same emails";
    $newemailids = $talk->fetch('1:*', 'emailid');
    @newemailids = map { $newemailids->{$_}{emailid}[0] } sort { $a <=> $b } keys %$newemailids;
    $self->assert_deep_equals([sort @oldemailids], [sort @newemailids],
           Data::Dumper::Dumper([sort @oldemailids], [sort @newemailids]));
}

# XXX this isn't really the right place for this test
sub test_ipurge_mboxevent
    :NoAltNameSpace
{
    my ($self) = @_;

    my $shared_folder = 'shared.folder';

    # set up a shared folder that's easy to write to
    my $admintalk = $self->{adminstore}->get_client();
    $admintalk->create($shared_folder);
    $self->assert_str_equals('ok', $admintalk->get_last_completion_response());
    $admintalk->setacl($shared_folder, 'cassandane' => 'lrswipkxtecd');
    $self->assert_str_equals('ok', $admintalk->get_last_completion_response());

    # put some test messages in shared.folder
    my $talk = $self->{store}->get_client();
    $self->{store}->set_folder($shared_folder);
    $self->{store}->_select();
    for (1..5) {
        $self->make_message("message in $shared_folder $_");
    }
    $talk->unselect();
    $talk->select($shared_folder);

    my $stat = $talk->status($shared_folder, '(highestmodseq unseen messages)');
    $self->assert_num_equals(5, $stat->{unseen});
    $self->assert_num_equals(5, $stat->{messages});

    # consume/discard earlier events that we don't care about
    $self->{instance}->getnotify();

    # run ipurge, and collect any mboxevents it generates
    $self->{instance}->run_command(
        { cyrus => 1 },
        qw( ipurge -v -i -d 2 ), $shared_folder
    );
    my $events = $self->{instance}->getnotify();

    # the messages we just created should've been expunged
    $stat = $talk->status($shared_folder, '(highestmodseq unseen messages)');
    $self->assert_num_equals(0, $stat->{unseen});
    $self->assert_num_equals(0, $stat->{messages});

    # examine the mboxevents
    foreach (@{$events}) {
        my $e = decode_json($_->{MESSAGE});
        # uri must contain the mailbox!
        $self->assert_matches(qr{^imap://(?:[^/]+)/shared\.folder;UIDVALIDITY=},
                              $e->{uri});
    }
}

1;

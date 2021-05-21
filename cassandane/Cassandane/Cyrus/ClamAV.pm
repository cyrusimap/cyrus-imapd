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

package Cassandane::Cyrus::ClamAV;
use strict;
use warnings;
use Cwd qw(abs_path);
use Data::Dumper;

use lib '.';
use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;
use Cassandane::Instance;

$Data::Dumper::Sortkeys = 1;

my %eicar_attached = (
    mime_type => "multipart/mixed",
    mime_boundary => "boundary",
    body => ""
        . "--boundary\r\n"
        . "Content-Type: text/plain\r\n"
        . "\r\n"
        . "body"
        . "\r\n"
        . "--boundary\r\n"
        . "Content-Disposition: attachment; filename=eicar.txt;\r\n"
        . "Content-Type: text/plain\r\n"
        . "\r\n"
        # This is the EICAR AV test file:
        # http://www.eicar.org/83-0-Anti-Malware-Testfile.html
        . 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
        . "\r\n"
        . "--boundary\r\n",
);

my %custom_header = (
    'extra_headers' => [
        [ 'x-delete-me' => 'please' ],
    ],
);

sub new
{
    my $class = shift;
    return $class->SUPER::new({ adminstore => 1 }, @_);
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

sub test_aaasetup
    :needs_dependency_clamav
{
    my ($self) = @_;

    # does everything set up and tear down cleanly?
    $self->assert(1);
}

# This test uses the AV engine, which can be very slow to initialise.
sub test_remove_infected_slow
    :needs_dependency_clamav :NoAltNamespace
{
    my ($self) = @_;

    # set up a shared folder that's easy to write to
    my $admintalk = $self->{adminstore}->get_client();
    $admintalk->create('shared.folder');
    $admintalk->setacl('shared.folder', 'cassandane' => 'lrswipkxtecd');

    $self->{store}->set_fetch_attributes(qw(uid flags));

    my $talk = $self->{store}->get_client();
    $talk->select("INBOX");
    $self->assert_num_equals(1, $talk->uid());
    $talk->select("shared.folder");
    $self->assert_num_equals(1, $talk->uid());

    # put some test messages in INBOX (and verify)
    $self->{store}->set_folder("INBOX");
    my %cass_exp;
    $cass_exp{1} = $self->make_message("eicar attached", uid => 1, %eicar_attached);
    $cass_exp{2} = $self->make_message("clean", uid => 2);
    $self->check_messages(\%cass_exp, ( keyed_on => 'uid' ));

    # put some test messages in shared.folder (and verify)
    $self->{store}->set_folder("shared.folder");
    my %shared_exp;
    $shared_exp{1} = $self->make_message("eicar attached", uid => 1, %eicar_attached);
    $shared_exp{2} = $self->make_message("clean", uid => 2);
    $self->check_messages(\%shared_exp, ( keyed_on => 'uid' ));

    # run cyr_virusscan
    my $out = "$self->{instance}->{basedir}/$self->{_name}-cyr_virusscan.stdout";
    $self->{instance}->run_command(
        { cyrus => 1,
          redirects => { 'stdout' => $out },
        }, 'cyr_virusscan', '-r');

    # check the output
    # user.cassandane                       1  UNREAD  Eicar-Test-Signature
    # shared.folder                         1  UNREAD  Eicar-Test-Signature
    {
        local $/;
        open my $fh, '<', $out
            or die "Cannot open $out for reading: $!";
        $out = <$fh>;
        close $fh;
        xlog $self, $out;
    }
    # XXX is there a better way than hard coding UID:1 ?
    my ($v) = Cassandane::Instance->get_version();
    if ($v >= 3) {
        $self->assert_matches(
            qr/user\.cassandane\s+1\s+UNREAD\s+Eicar(?:-Test){0,1}-Signature/,
            $out);
        $self->assert_matches(
            qr/shared\.folder\s+1\s+UNREAD\s+Eicar(?:-Test){0,1}-Signature/,
            $out);
    }
    else {
        # pre-3.0 a different output format was used
        $self->assert_matches(
            qr/Working\son\sshared\.folder\.\.\.\nVirus\sdetected\sin\smessage\s1:\sEicar(?:-Test){0,1}-Signature/,
            $out);
        $self->assert_matches(
            qr/Working\son\suser\.cassandane\.\.\.\nVirus\sdetected\sin\smessage\s1:\sEicar(?:-Test){0,1}-Signature/,
            $out);
    }

    # make sure the infected ones were expunged, but the clean ones weren't
    $self->{store}->set_folder("INBOX");
    delete $cass_exp{1};
    $self->check_messages(\%cass_exp, ( keyed_on => 'uid' ));

    $self->{store}->set_folder("shared.folder");
    delete $shared_exp{1};
    $self->check_messages(\%shared_exp, ( keyed_on => 'uid' ));
}

# This test uses the '-s search-string' invocation, which is much faster
# than waiting for the AV engine to load when we just care about whether
# the notification gets sent
sub test_notify_deleted
    :needs_dependency_clamav
{
    my ($self) = @_;

    $self->{store}->set_fetch_attributes(qw(uid flags));

    # put some test messages in INBOX (and verify)
    $self->{store}->set_folder("INBOX");
    my %cass_exp;
    $cass_exp{1} = $self->make_message("custom header 1", uid => 1, %custom_header);
    $cass_exp{2} = $self->make_message("custom header 2", uid => 2, %custom_header);
    $self->check_messages(\%cass_exp, ( keyed_on => 'uid' ));

    # run cyr_virusscan
    $self->{instance}->run_command({ cyrus => 1, },
                                   'cyr_virusscan', '-r', '-n',
                                   '-s', 'header "x-delete-me" "please"');

    # let's see what's in there now
    my $found_notifications = 0;
    $self->{store}->read_begin();
    while (my $msg = $self->{store}->read_message()) {
        # should not be any of our test messages remaining
        $self->assert_null($msg->get_header('x-cassandane-unique'));

        # if we find something that looks like a notification, check it
		if ($msg->get_header('message-id') =~ m{^<cmu-cyrus-\d+-\d+-\d+\@}) {
            $found_notifications ++;

            my $body = $msg->get_body();
#            xlog $self, "body:\n>>>>>>\n$body<<<<<<";

            # make sure report body includes all our infected tests
            foreach my $exp (values %cass_exp) {
                my $message_id = $exp->get_header('message-id');
                $self->assert_matches(qr/Message-ID: $message_id/, $body);

                my $subject = $exp->get_header('subject');
                $self->assert_matches(qr/Subject: $subject/, $body);

                my $uid = $exp->get_attribute('uid');
                $self->assert_matches(qr/IMAP UID: $uid/, $body);
            }

            # make sure the message was removed for the reason we expect
            $self->assert_matches(qr/Cyrus Administrator Targeted Removal/,
                                  $body);
        }
    }
    $self->{store}->read_end();

    # finally, there should've been exactly one notification email sent
    $self->assert_num_equals(1, $found_notifications);
}

# This test uses the '-s search-string' invocation, which is much faster
# than waiting for the AV engine to load when we just care about whether
# the custom notification gets sent
# XXX https://github.com/cyrusimap/cyrus-imapd/issues/2516 might be
# XXX backported to 3.0 if anyone volunteers to test it
sub test_custom_notify_deleted
    :needs_dependency_clamav :NoStartInstances
    :min_version_3_1
{
    my ($self) = @_;

    # set up a custom notification template
    $self->{instance}->{config}->set(
        virusscan_notification_subject => 'custom ½ subject',
        virusscan_notification_template =>
            abs_path('data/custom-notification-template'),
    );
    $self->_start_instances();

    $self->{store}->set_fetch_attributes(qw(uid flags));

    # put some test messages in INBOX (and verify)
    $self->{store}->set_folder("INBOX");
    my %cass_exp;
    $cass_exp{1} = $self->make_message("custom header 1", uid => 1, %custom_header);
    $cass_exp{2} = $self->make_message("custom header 2", uid => 2, %custom_header);
    $self->check_messages(\%cass_exp, ( keyed_on => 'uid' ));

    # run cyr_virusscan
    $self->{instance}->run_command({ cyrus => 1, },
                                   'cyr_virusscan', '-r', '-n',
                                   '-s', 'header "x-delete-me" "please"');

    # let's see what's in there now
    my $found_notifications = 0;
    $self->{store}->read_begin();
    while (my $msg = $self->{store}->read_message()) {
        # should not be any of our test messages remaining
        $self->assert_null($msg->get_header('x-cassandane-unique'));

        # if we find something that looks like a notification, check it
		if ($msg->get_header('message-id') =~ m{^<cmu-cyrus-\d+-\d+-\d+\@}) {
            $found_notifications ++;

            my $subject = $msg->get_header('subject');
#            xlog $self, "subject: $subject";

            # make sure our custom subject was used (and correctly encoded)
            $self->assert_str_equals('=?UTF-8?Q?custom_=C2=BD_subject?=',
                                     $subject);

            my $body = $msg->get_body();
#            xlog $self, "body:\n>>>>>>\n$body<<<<<<";

            # make sure report body includes all our infected tests
            foreach my $exp (values %cass_exp) {
                my $message_id = $exp->get_header('message-id');
                $self->assert_matches(qr/Message-ID: $message_id/, $body);

                my $subject = $exp->get_header('subject');
                $self->assert_matches(qr/Subject: $subject/, $body);

                my $uid = $exp->get_attribute('uid');
                $self->assert_matches(qr/IMAP UID: $uid/, $body);
            }

            # make sure the message was removed for the reason we expect
            $self->assert_matches(qr/Cyrus Administrator Targeted Removal/,
                                  $body);

            # make sure our custom notification template was used
            $self->assert_matches(qr/^custom notification!/, $body);

            # make sure message was qp-encoded
            $self->assert_matches(qr/with =C2=BD as much 8bit/, $body);
        }
    }
    $self->{store}->read_end();

    # finally, there should've been exactly one notification email sent
    $self->assert_num_equals(1, $found_notifications);
}

1;

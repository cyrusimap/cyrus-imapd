#!/usr/bin/perl
#
#  Copyright (c) 2017 FastMail Pty Ltd  All rights reserved.
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
#  FASTMAIL PTY LTD DISCLAIMS ALL WARRANTIES WITH REGARD TO
#  THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
#  AND FITNESS, IN NO EVENT SHALL OPERA SOFTWARE AUSTRALIA BE LIABLE
#  FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
#  WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
#  AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
#  OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#

package Cassandane::Cyrus::Annotator;
use strict;
use warnings;
use Cwd qw(abs_path);

use lib '.';
use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;
use Cassandane::Util::Wait;

sub new
{
    my $class = shift;
    my $config = Cassandane::Config->default()->clone();
    $config->set(
	annotation_callout => '@basedir@/conf/socket/annotator.sock',
    );
    return $class->SUPER::new({ config => $config, deliver => 1 }, @_);
}

sub set_up
{
    my ($self) = @_;
    $self->SUPER::set_up();
}

sub _create_instances
{
    my ($self) = @_;

    $self->SUPER::_create_instances();
    $self->{instance}->add_daemon(
	    name => 'annotator',
	    port => $self->{instance}->{config}->get('annotation_callout'),
	    argv => sub {
		my ($daemon) = @_;
		return (
		    abs_path('utils/annotator.pl'),
		    '--port', $daemon->port(),
		    '--pidfile', '@basedir@/run/annotator.pid',
		);
	    });
}

sub tear_down
{
    my ($self) = @_;
    $self->SUPER::tear_down();
}

sub test_add_annot_deliver
{
    my ($self) = @_;

    my $entry = '/comment';
    my $attrib = 'value.shared';
    # Data thanks to http://hipsteripsum.me
    my $value1 = 'you_probably_havent_heard_of_them';

    my %exp;
    $exp{A} = $self->{gen}->generate(subject => "Message A");
    $exp{A}->set_body("set_shared_annotation $entry $value1\r\n");
    $self->{instance}->deliver($exp{A});
    $exp{A}->set_annotation($entry, $attrib, $value1);

    # Local delivery adds headers we can't predict or control,
    # which change the SHA1 of delivered messages, so we can't
    # be checking the GUIDs here.
    $self->{store}->set_fetch_attributes('uid', "annotation ($entry $attrib)");
    $self->check_messages(\%exp, check_guid => 0);
}

sub test_add_annot_deliver_tomailbox
{
    my ($self) = @_;

    xlog "Testing adding an annotation from the Annotator";
    xlog "when delivering to a non-INBOX mailbox [IRIS-955]";

    my $entry = '/comment';
    my $attrib = 'value.shared';
    # Data thanks to http://hipsteripsum.me
    my $value1 = 'before_they_sold_out';

    my $subfolder = 'target';
    my $talk = $self->{store}->get_client();
    $talk->create("INBOX.$subfolder")
	or die "Failed to create INBOX.$subfolder";

    my %exp;
    $exp{A} = $self->{gen}->generate(subject => "Message A");
    $exp{A}->set_body("set_shared_annotation $entry $value1\r\n");
    $self->{instance}->deliver($exp{A}, folder => $subfolder);
    $exp{A}->set_annotation($entry, $attrib, $value1);

    # Local delivery adds headers we can't predict or control,
    # which change the SHA1 of delivered messages, so we can't
    # be checking the GUIDs here.
    $self->{store}->set_folder("INBOX.$subfolder");
    $self->{store}->set_fetch_attributes('uid', "annotation ($entry $attrib)");
    $self->check_messages(\%exp, check_guid => 0);
}

sub test_set_system_flag_deliver
{
    my ($self) = @_;

    my $flag = '\\Flagged';

    my %exp;
    $exp{A} = $self->{gen}->generate(subject => "Message A");
    $exp{A}->set_body("set_flag $flag\r\n");
    $self->{instance}->deliver($exp{A});
    $exp{A}->set_attributes(flags => ['\\Recent', $flag]);

    # Local delivery adds headers we can't predict or control,
    # which change the SHA1 of delivered messages, so we can't
    # be checking the GUIDs here.
    $self->{store}->set_fetch_attributes('uid', 'flags');
    $self->check_messages(\%exp, check_guid => 0);
}

sub test_set_user_flag_deliver
{
    my ($self) = @_;

    # Data thanks to http://hipsteripsum.me
    my $flag = '$Artisanal';

    my %exp;
    $exp{A} = $self->{gen}->generate(subject => "Message A");
    $exp{A}->set_body("set_flag $flag\r\n");
    $self->{instance}->deliver($exp{A});
    $exp{A}->set_attributes(flags => ['\\Recent', $flag]);

    # Local delivery adds headers we can't predict or control,
    # which change the SHA1 of delivered messages, so we can't
    # be checking the GUIDs here.
    $self->{store}->set_fetch_attributes('uid', 'flags');
    $self->check_messages(\%exp, check_guid => 0);
}

sub test_reconstruct_after_delivery
{
    my ($self) = @_;

    xlog "Testing reconstruct after delivery";

    xlog "Create folders";
    my $imaptalk = $self->{store}->get_client();
    $self->{store}->set_fetch_attributes('uid');

    xlog "Deliver a message";
    my %msgs;
    $msgs{1} = $self->{gen}->generate(subject => "Message 1");
    $msgs{1}->set_attribute(uid => 1);
    $msgs{1}->set_body("set_shared_annotation /comment testvalue\r\n");
    $imaptalk->create("INBOX.subfolder");
    $self->{instance}->deliver($msgs{1}, user => "cassandane");

    xlog "Check that the message made it";
    $self->check_messages(\%msgs, check_guid => 0, keyed_on => 'uid');

    # run a fresh reconstruct
    my $out = "$self->{instance}->{basedir}/$self->{_name}-reconstruct.stdout";
    $self->{instance}->run_command(
        { cyrus => 1,
          redirects => { 'stdout' => $out },
        }, 'reconstruct', '-u', 'cassandane');

    # check the output
    {
        local $/;
        open my $fh, '<', $out
            or die "Cannot open $out for reading: $!";
        $out = <$fh>;
        close $fh;
        xlog $out;
    }

    $self->assert($out !~ m/ updating /);
}


# Note: remove_annotation can't really be tested with local
# delivery, just with the APPEND command.

1;

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

package Cassandane::Cyrus::Archive;
use strict;
use warnings;
use DateTime;
use Data::Dumper;

use lib '.';
use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;
use Cassandane::Util::Words;

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

Cassandane::Cyrus::TestCase::magic(ArchivePartition => sub {
    my $conf = shift;
    $conf->config_set('archivepartition-default' => '@basedir@/archive');
    $conf->config_set('archive_enabled' => 'yes');
    $conf->config_set('archive_days' => '7');
});

Cassandane::Cyrus::TestCase::magic(ArchiveNow => sub {
    my $conf = shift;
    $conf->config_set('archivepartition-default' => '@basedir@/archive');
    $conf->config_set('archive_enabled' => 'yes');
    $conf->config_set('archive_days' => '0');
});

#
# Test that
#  - cyr_expire archives messages
#  - once archived, messages are in the new path
#  - the message is gone from the old path
#  - XXX: hard to test - that there's no possible race in which the message
#    isn't available to clients during the archive operation
#
sub test_archive_messages
    :ArchivePartition :min_version_3_0
{
    my ($self) = @_;

    my $talk = $self->{store}->get_client();
    $self->{store}->_select();
    $self->assert_num_equals(1, $talk->uid());
    $self->{store}->set_fetch_attributes(qw(uid flags));

    xlog $self, "Append 3 messages";
    my %msg;
    $msg{A} = $self->make_message('Message A');
    $msg{A}->set_attributes(id => 1,
                            uid => 1,
                            flags => []);
    $msg{B} = $self->make_message('Message B');
    $msg{B}->set_attributes(id => 2,
                            uid => 2,
                            flags => []);
    $msg{C} = $self->make_message('Message C');
    $msg{C}->set_attributes(id => 3,
                            uid => 3,
                            flags => []);
    $self->check_messages(\%msg);

    my $data = $self->{instance}->run_mbpath("-u", 'cassandane');
    my $datadir = $data->{data};
    my $archivedir = $data->{archive};

    $self->assert(-f "$datadir/1.");
    $self->assert(-f "$datadir/2.");
    $self->assert(-f "$datadir/3.");

    $self->assert(!-f "$archivedir/1.");
    $self->assert(!-f "$archivedir/2.");
    $self->assert(!-f "$archivedir/3.");

    xlog $self, "Run cyr_expire but no messages should move";
    $self->{instance}->run_command({ cyrus => 1 }, 'cyr_expire', '-A' => '7d' );

    $self->assert(-f "$datadir/1.");
    $self->assert(-f "$datadir/2.");
    $self->assert(-f "$datadir/3.");

    $self->assert(!-f "$archivedir/1.");
    $self->assert(!-f "$archivedir/2.");
    $self->assert(!-f "$archivedir/3.");


    xlog $self, "Run cyr_expire to archive now";
    $self->{instance}->run_command({ cyrus => 1 }, 'cyr_expire', '-A' => '0' );

    $self->assert(!-f "$datadir/1.");
    $self->assert(!-f "$datadir/2.");
    $self->assert(!-f "$datadir/3.");

    $self->assert(-f "$archivedir/1.");
    $self->assert(-f "$archivedir/2.");
    $self->assert(-f "$archivedir/3.");
}

sub test_archivenow_messages
    :ArchiveNow :min_version_3_0
{
    my ($self) = @_;

    my $talk = $self->{store}->get_client();
    $self->{store}->_select();
    $self->assert_num_equals(1, $talk->uid());
    $self->{store}->set_fetch_attributes(qw(uid flags));

    xlog $self, "Append 3 messages";
    my %msg;
    $msg{A} = $self->make_message('Message A');
    $msg{A}->set_attributes(id => 1,
                            uid => 1,
                            flags => []);
    $msg{B} = $self->make_message('Message B');
    $msg{B}->set_attributes(id => 2,
                            uid => 2,
                            flags => []);
    $msg{C} = $self->make_message('Message C');
    $msg{C}->set_attributes(id => 3,
                            uid => 3,
                            flags => []);
    $self->check_messages(\%msg);

    my $data = $self->{instance}->run_mbpath("-u", 'cassandane');
    my $datadir = $data->{data};
    my $archivedir = $data->{archive};

    # already archived
    $self->assert(!-f "$datadir/1.");
    $self->assert(!-f "$datadir/2.");
    $self->assert(!-f "$datadir/3.");

    $self->assert(-f "$archivedir/1.");
    $self->assert(-f "$archivedir/2.");
    $self->assert(-f "$archivedir/3.");

    xlog $self, "Run cyr_expire with old and messages stay archived";
    $self->{instance}->run_command({ cyrus => 1 }, 'cyr_expire', '-A' => '7d' );

    $self->assert(!-f "$datadir/1.");
    $self->assert(!-f "$datadir/2.");
    $self->assert(!-f "$datadir/3.");

    $self->assert(-f "$archivedir/1.");
    $self->assert(-f "$archivedir/2.");
    $self->assert(-f "$archivedir/3.");

    xlog $self, "Run cyr_expire to archive now and messages stay archived";
    $self->{instance}->run_command({ cyrus => 1 }, 'cyr_expire', '-A' => '0' );

    $self->assert(!-f "$datadir/1.");
    $self->assert(!-f "$datadir/2.");
    $self->assert(!-f "$datadir/3.");

    $self->assert(-f "$archivedir/1.");
    $self->assert(-f "$archivedir/2.");
    $self->assert(-f "$archivedir/3.");
}

1;

sub test_archive_messages_archive_annotation
    :ArchivePartition :min_version_3_1
{
    my ($self) = @_;

    my $talk = $self->{store}->get_client();
    my $admintalk = $self->{adminstore}->get_client();

    $self->{store}->_select();
    $self->assert_num_equals(1, $talk->uid());
    $self->{store}->set_fetch_attributes(qw(uid flags));

    xlog $self, "Append 3 messages";
    my %msg;
    $msg{A} = $self->make_message('Message A');
    $msg{A}->set_attributes(id => 1,
                            uid => 1,
                            flags => []);
    $msg{B} = $self->make_message('Message B');
    $msg{B}->set_attributes(id => 2,
                            uid => 2,
                            flags => []);
    $msg{C} = $self->make_message('Message C');
    $msg{C}->set_attributes(id => 3,
                            uid => 3,
                            flags => []);
    $self->check_messages(\%msg);

    my $data = $self->{instance}->run_mbpath("-u", 'cassandane');
    my $datadir = $data->{data};
    my $archivedir = $data->{archive};

    $self->assert(-f "$datadir/1.");
    $self->assert(-f "$datadir/2.");
    $self->assert(-f "$datadir/3.");

    $self->assert(!-f "$archivedir/1.");
    $self->assert(!-f "$archivedir/2.");
    $self->assert(!-f "$archivedir/3.");

    xlog $self, "Run cyr_expire but no messages should move";
    $self->{instance}->run_command({ cyrus => 1 }, 'cyr_expire', '-A' => '7d' );

    $self->assert(-f "$datadir/1.");
    $self->assert(-f "$datadir/2.");
    $self->assert(-f "$datadir/3.");

    $self->assert(!-f "$archivedir/1.");
    $self->assert(!-f "$archivedir/2.");
    $self->assert(!-f "$archivedir/3.");

    $admintalk->setmetadata('user.cassandane',
                            "/shared/vendor/cmu/cyrus-imapd/archive",
                            '3');

    xlog $self, "Run cyr_expire asking to archive now, but it shouldn't";
    $self->{instance}->run_command({ cyrus => 1 }, 'cyr_expire', '-A' => '0' );

    $self->assert(-f "$datadir/1.");
    $self->assert(-f "$datadir/2.");
    $self->assert(-f "$datadir/3.");

    $self->assert(!-f "$archivedir/1.");
    $self->assert(!-f "$archivedir/2.");
    $self->assert(!-f "$archivedir/3.");


    xlog $self, "Run cyr_expire asking to archive now, with skip annotation";
    $self->{instance}->run_command({ cyrus => 1 }, 'cyr_expire', '-A' => '0' , '-a');

    $self->assert(!-f "$datadir/1.");
    $self->assert(!-f "$datadir/2.");
    $self->assert(!-f "$datadir/3.");

    $self->assert(-f "$archivedir/1.");
    $self->assert(-f "$archivedir/2.");
    $self->assert(-f "$archivedir/3.");
}

sub test_archivenow_reconstruct
    :ArchiveNow :min_version_3_0
{
    my ($self) = @_;

    my $talk = $self->{store}->get_client();
    $self->{store}->_select();
    $self->assert_num_equals(1, $talk->uid());
    $self->{store}->set_fetch_attributes(qw(uid flags));

    xlog $self, "Append 3 messages";
    my %msg;
    $msg{A} = $self->make_message('Message A');
    $msg{A}->set_attributes(id => 1,
                            uid => 1,
                            flags => []);
    $msg{B} = $self->make_message('Message B');
    $msg{B}->set_attributes(id => 2,
                            uid => 2,
                            flags => []);
    $msg{C} = $self->make_message('Message C');
    $msg{C}->set_attributes(id => 3,
                            uid => 3,
                            flags => []);
    $self->check_messages(\%msg);

    my $data = $self->{instance}->run_mbpath("-u", 'cassandane');
    my $datadir = $data->{data};
    my $archivedir = $data->{archive};

    # already archived
    $self->assert(!-f "$datadir/1.");
    $self->assert(!-f "$datadir/2.");
    $self->assert(!-f "$datadir/3.");

    $self->assert(-f "$archivedir/1.");
    $self->assert(-f "$archivedir/2.");
    $self->assert(-f "$archivedir/3.");

    xlog $self, "Run cyr_expire with old and messages stay archived";
    $self->{instance}->run_command({ cyrus => 1 }, 'cyr_expire', '-A' => '7d' );

    $self->assert(!-f "$datadir/1.");
    $self->assert(!-f "$datadir/2.");
    $self->assert(!-f "$datadir/3.");

    $self->assert(-f "$archivedir/1.");
    $self->assert(-f "$archivedir/2.");
    $self->assert(-f "$archivedir/3.");

    xlog $self, "Run cyr_expire to archive now and messages stay archived";
    $self->{instance}->run_command({ cyrus => 1 }, 'cyr_expire', '-A' => '0' );

    $self->assert(!-f "$datadir/1.");
    $self->assert(!-f "$datadir/2.");
    $self->assert(!-f "$datadir/3.");

    $self->assert(-f "$archivedir/1.");
    $self->assert(-f "$archivedir/2.");
    $self->assert(-f "$archivedir/3.");

    xlog $self, "Reconstruct doesn't lose files";

    $self->{instance}->run_command({ cyrus => 1 }, 'reconstruct', '-s');

    $self->assert(!-f "$datadir/1.");
    $self->assert(!-f "$datadir/2.");
    $self->assert(!-f "$datadir/3.");

    $self->assert(-f "$archivedir/1.");
    $self->assert(-f "$archivedir/2.");
    $self->assert(-f "$archivedir/3.");
}

1;

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
package Cassandane::Cyrus::Annotator;
use base qw(Cassandane::Cyrus::TestCase);
use Cwd qw(abs_path);
use Cassandane::Util::Log;

sub new
{
    my $class = shift;
    my $config = Cassandane::Config->default()->clone();
    $config->set(
	annotation_callout => '@basedir@/conf/socket/annotator.sock'
    );
    return $class->SUPER::new({ config => $config, deliver => 1 }, @_);
}

sub set_up
{
    my ($self) = @_;
    $self->SUPER::set_up();

    my $daemon = abs_path('utils/annotator.pl');
    my $sock = $self->{instance}->{basedir} . '/conf/socket/annotator.sock';
    my $pidfile = $self->{instance}->{basedir} . '/conf/socket/annotator.pid';
    $self->{instance}->run_command({ cyrus => 1, background => 1 }, $daemon);
    Cassandane::Instance::_timed_wait(sub { return ( -e $sock ); },
				      description => 'annotator daemon to be ready');
    $self->{annotator_pidfile} = $pidfile;
}

sub tear_down
{
    my ($self) = @_;

    if (defined $self->{annotator_pidfile})
    {
	$self->{instance}->stop_command_pidfile($self->{annotator_pidfile});
	$self->{annotator_pidfile} = undef;
    }

    $self->SUPER::tear_down();
}

sub test_add_annot_deliver
{
    my ($self) = @_;

    my $entry = '/comment';
    my $attrib = 'value.shared';
    my $shared = 'shared';
    # Data thanks to http://hipsteripsum.me
    my $value1 = 'you_probably_havent_heard_of_them';

    my %exp;
    $exp{A} = $self->{gen}->generate(subject => "Message A");
    $exp{A}->set_body("add_annotation $entry $shared $value1\r\n");
    $self->{instance}->deliver($exp{A});
    $exp{A}->set_annotation($entry, $attrib, $value1);

    # Local delivery adds headers we can't predict or control,
    # which change the SHA1 of delivered messages, so we can't
    # be checking the GUIDs here.
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

# Note: remove_annotation can't really be tested with local
# delivery, just with the APPEND command.

1;

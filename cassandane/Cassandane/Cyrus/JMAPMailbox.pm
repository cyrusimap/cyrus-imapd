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

package Cassandane::Cyrus::JMAPMailbox;
use strict;
use warnings;
use DateTime;
use JSON::XS;
use Net::CalDAVTalk 0.09;
use Net::CardDAVTalk 0.03;
use Data::Dumper;
use Storable 'dclone';
use MIME::Base64 qw(encode_base64);
use Cwd qw(abs_path getcwd);

use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;

use lib '../perl/imap';
use Cyrus::DList;

use charnames ':full';

sub new
{
    my ($class, @args) = @_;

    my $config = Cassandane::Config->default()->clone();
    $config->set(caldav_realm => 'Cassandane',
                 conversations => 'yes',
                 conversations_counted_flags => "\\Draft \\Flagged \$IsMailingList \$IsNotification \$HasAttachment",
                 httpmodules => 'carddav caldav jmap',
                 specialuse_extra => '\\XSpecialUse \\XChats \\XTemplates \\XNotes',
                 notesmailbox => 'Notes',
                 httpallowcompress => 'no');

    my $self = $class->SUPER::new({
        config => $config,
        jmap => 1,
        adminstore => 1,
        services => [ 'imap', 'http' ]
    }, @args);

    $self->needs('component', 'jmap');
    return $self;
}

sub setup_default_using
{
    my ($self) = @_;
    $self->{jmap}->DefaultUsing([
        'urn:ietf:params:jmap:core',
        'urn:ietf:params:jmap:mail',
    ]);
}

sub set_up
{
    my ($self) = @_;
    $self->SUPER::set_up();

    if ($self->{jmap}) {
        $self->setup_default_using();
    }
    # n.b. tests that use :NoStartInstances will need to call
    # $self->setup_default_using() themselves!
}

sub getinbox
{
    my ($self, $args) = @_;

    $args = {} unless $args;

    my $jmap = $self->{jmap};

    xlog $self, "get existing mailboxes";
    my $res = $jmap->CallMethods([['Mailbox/get', $args, "R1"]]);
    $self->assert_not_null($res);

    my %m = map { $_->{name} => $_ } @{$res->[0][1]{list}};
    return $m{"Inbox"};
}

sub _check_one_count {
    my $self = shift;
    my $want = shift;
    my $have = shift;
    my $name = shift;
    $self->assert_num_equals($want, $have);
}

sub _check_counts
{
    my $self = shift;
    my $name = shift;
    my %expect = @_;

    my $jmap = $self->{jmap};

    my $res = $jmap->CallMethods([['Mailbox/get', {}, 'R']]);

    #  "totalEmails": 3,
    #  "unreadEmails": 1,
    #  "totalThreads": 3,
    #  "unreadThreads": 1,

    for my $folder (@{$res->[0][1]{list}}) {
        my $want = $expect{$folder->{name}};
        next unless $want;
        $self->_check_one_count($want->[0], $folder->{totalEmails}, "$folder->{name} totalEmails");
        $self->_check_one_count($want->[1], $folder->{unreadEmails}, "$folder->{name} unreadEmails");
        $self->_check_one_count($want->[2], $folder->{totalThreads}, "$folder->{name} totalThreads");
        $self->_check_one_count($want->[3], $folder->{unreadThreads}, "$folder->{name} unreadThreads");
    }
}

use Cassandane::Tiny::Loader 'tiny-tests/JMAPMailbox';

1;

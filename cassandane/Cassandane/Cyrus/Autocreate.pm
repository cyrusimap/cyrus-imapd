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

package Cassandane::Cyrus::Autocreate;
use strict;
use warnings;
use Data::Dumper;

use lib '.';
use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;

sub new
{
    my $class = shift;
    my $config = Cassandane::Config->default()->clone();

    $config->set(
        autocreate_post => 'yes',
        autocreate_quota => '500000',
        autocreate_inbox_folders => 'Drafts|Sent|Trash|SPAM|plus',
        autocreate_subscribe_folder => 'Drafts|Sent|Trash|SPAM|plus',
        autocreate_sieve_script => '@basedir@/conf/foo_sieve.script',
        autocreate_acl => 'plus anyone p',
        'xlist-drafts' => 'Drafts',
        'xlist-junk' => 'SPAM',
        'xlist-sent' => 'Sent',
        'xlist-trash' => 'Trash',
    );
    return $class->SUPER::new({
        config => $config,
        adminstore => 1,
        deliver => 1,
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

sub test_autocreate_specialuse
     :min_version_3_0 :needs_component_autocreate :NoAltNameSpace
{
    my ($self) = @_;

    my $svc = $self->{instance}->get_service('imap');
    my $store = $svc->create_store(username => 'foo');
    my $talk = $store->get_client();
    my $list = $talk->list('', '*', 'return', ['special-use']);

    my %map = (
        drafts => 'Drafts',
        junk => 'SPAM',
        sent => 'Sent',
        trash => 'Trash',
    );
    foreach my $item (@$list) {
        my $key;
        foreach my $flag (@{$item->[0]}) {
            next unless $flag =~ m/\\(.*)/;
            $key = $1;
            last if $map{$key};
        }
        my $name = delete $map{$key};
        next unless $name;
        $self->assert_str_equals("INBOX.$name", $item->[2]);
    }
    $self->assert_num_equals(0, scalar keys %map);
}

sub test_autocreate_sieve_script_generation
    :min_version_3_0 :needs_component_autocreate :needs_component_sieve
{
    my ($self) = @_;

    my $basedir = $self->{instance}->get_basedir();
    my $sieve_script_path = $basedir . "/conf/foo_sieve.script";
    my $hitfolder = "INBOX.NewFolder";
    my $testfolder = "INBOX.TestFolder";
    my $missfolder = "INBOX";

    open(FH, '>', "$sieve_script_path")
        or die "Cannot open $sieve_script_path for writing: $!";
    print FH "require \[\"fileinto\", \"mailbox\"\];";
    print FH "if mailboxexists \"$testfolder\"  {";
    print FH "fileinto \"$hitfolder\";";
    print FH "}";
    close(FH);

    my $svc = $self->{instance}->get_service('imap');
    my $store = $svc->create_store(username => 'foo');
    my $talk = $store->get_client();

    my $sievedir = $self->{instance}->get_sieve_script_dir('foo');
    $self->assert(-f "$sievedir/foo_sieve.script.script");
    $self->assert(-f "$sievedir/defaultbc");
    $self->assert(-f "$sievedir/foo_sieve.script.bc");
}

sub test_autocreate_acl
    :min_version_3_1 :needs_component_autocreate :needs_component_sieve :NoAltNameSpace
{
    my ($self) = @_;

    my %folder_acls = (
        'INBOX'         => [qw( foo lrswipkxtecdan )],
        'INBOX.Drafts'  => [qw( foo lrswipkxtecdan )],
        'INBOX.Sent'    => [qw( foo lrswipkxtecdan )],
        'INBOX.SPAM'    => [qw( foo lrswipkxtecdan )],
        'INBOX.Trash'   => [qw( foo lrswipkxtecdan )],
        'INBOX.plus'    => [qw( foo lrswipkxtecdan anyone p )],
    );

    my $svc = $self->{instance}->get_service('imap');
    my $store = $svc->create_store(username => 'foo');
    my $talk = $store->get_client();

    while (my ($folder, $acl) = each %folder_acls) {
        my $res = $talk->getacl($folder);
        $self->assert_deep_equals($folder_acls{$folder}, $res);
    }
}

1;

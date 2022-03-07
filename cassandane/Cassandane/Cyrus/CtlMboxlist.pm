#!/usr/bin/perl
#
#  Copyright (c) 2011-2022 Fastmail Pty Ltd. All rights reserved.
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

package Cassandane::Cyrus::CtlMboxlist;
use strict;
use warnings;

use Data::Dumper;

use lib '.';
use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;
use Cassandane::Instance;

sub new
{
    my $class = shift;
    return $class->SUPER::new({}, @_);
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

sub fudge_mtimes
{
    my ($hash) = @_;

    foreach my $v (values %{$hash}) {
        if (exists $v->{mtime}) {
            $v->{mtime} = 1;
        }
    }
}

sub test_dump_undump
    :AltNamespace :UnixHierarchySep
{
    my ($self) = @_;

    # set up some mailboxes for the cassandane user
    my $expected = $self->populate_user(
        $self->{instance},
        $self->{store},
        [qw(INBOX Drafts Big Big/Red Big/Red/Dog)]
    );

    # sanity check
    $self->check_user($self->{instance}, $self->{store}, $expected);

    # stop the instance
    $self->{store}->disconnect();
    $self->{instance}->stop();
    $self->{instance}->{re_use_dir} = 1;

    # will refer to this a lot
    my $basedir = $self->{instance}->get_basedir();

    # get a dump
    my $dump1file = "$basedir/$$-dump.out1";
    my $dump1content = $self->{instance}->read_mailboxes_db({
        outfile => $dump1file
    });

    # move aside original mailboxes.db
    my $mboxlist_db_path = $self->{instance}->{config}->get('mboxlist_db_path');
    $mboxlist_db_path //= "$basedir/conf/mailboxes.db";
    rename $mboxlist_db_path, "$mboxlist_db_path.orig"
        or die "rename $mboxlist_db_path $mboxlist_db_path.orig: $!";

    # undump the dump into a new mailboxes.db
    my $errfile =  $basedir . "/$$-undump.err";
    $self->{instance}->run_command({
        cyrus => 1,
        redirects => {
            stdin => $dump1file,
            stderr => $errfile,
        },
    }, 'ctl_mboxlist', '-u');

    my $errors;
    {
        local $/;
        open my $fh, '<', $errfile or die "$errfile: $!";
        $errors = <$fh>;
        close $fh;
    }

    # should be no errors reported by the undump
    $self->assert_str_equals(q{}, $errors);

    # start the instance back up and reconnect the store
    $self->{instance}->start();
    $self->{store}->connect();

    # user's mailboxes should be as they were
    $self->check_user($self->{instance}, $self->{store}, $expected);

    # a second dump should produce the same output
    # ... though mtimes will differ, so fudge those first
    my $dump2file = "$basedir/$$-dump.out2";
    my $dump2content = $self->{instance}->read_mailboxes_db({
        outfile => $dump2file
    });
    fudge_mtimes($dump1content);
    fudge_mtimes($dump2content);
    $self->assert_deep_equals($dump1content, $dump2content);
}

1;

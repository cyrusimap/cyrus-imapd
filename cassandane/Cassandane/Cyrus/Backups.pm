#!/usr/bin/perl
#
#  Copyright (c) 2016 FastMail Pty. Ltd.  All rights reserved.
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
#  3. The name "FastMail" must not be used to
#     endorse or promote products derived from this software without
#     prior written permission. For permission or any legal
#     details, please contact
#         FastMail Pty. Ltd.
#         Level 1, 91 William St
#         Melbourne 3000
#         Victoria
#         Australia
#
#  4. Redistributions of any form whatsoever must retain the following
#     acknowledgment:
#     "This product includes software developed by FastMail Pty. Ltd."
#
#  FASTMAIL PTY LTD DISCLAIMS ALL WARRANTIES WITH REGARD TO
#  THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
#  AND FITNESS, IN NO EVENT SHALL OPERA SOFTWARE AUSTRALIA BE LIABLE
#  FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
#  WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
#  AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
#  OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#

package Cassandane::Cyrus::Backups;
use strict;
use warnings;
use Data::Dumper;
use JSON::XS;

use lib '.';
use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;
use Cassandane::Instance;

$Data::Dumper::Sortkeys = 1;

sub new
{
    my $class = shift;
    return $class->SUPER::new({ backups => 1 }, @_);
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
    :min_version_3_0
{
    my ($self) = @_;

    # does everything set up and tear down cleanly?
    $self->assert(1);
}

sub test_basic
    :min_version_3_0
{
    my ($self) = @_;

    # XXX probably don't do this like this
    $self->{instance}->run_command(
	{ cyrus => 1 },
	qw(sync_client -vv -n backup -u cassandane)
    );

    # XXX probably don't do this like this either
    my $cyr_backup_stdout = "$self->{backups}->{basedir}/$self->{_name}"
			  . "-cyr_backup.stdout";
    $self->{backups}->run_command(
	{ cyrus => 1,
	  redirects => { 'stdout' => $cyr_backup_stdout } },
	qw(cyr_backup -u cassandane json chunks)
    );

    local $/;
    open my $fh, '<', $cyr_backup_stdout
	or die "Cannot open $cyr_backup_stdout for reading: $!";
    my $chunks = JSON::decode_json(<$fh>);
    close $fh;

    $self->assert_equals(1, scalar @{$chunks});
    $self->assert_equals(0, $chunks->[0]->{offset});
    $self->assert_equals(1, $chunks->[0]->{id});
    # an empty chunk has a 29 byte prefix
    # make sure the chunk isn't empty -- it should at least send through
    # the state of an empty inbox
    $self->assert($chunks->[0]->{length} > 29);
}

1;

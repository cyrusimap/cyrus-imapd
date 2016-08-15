#!/usr/bin/perl
#
#  Copyright (c) 2015 FastMail Pty. Ltd.  All rights
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

package Cassandane::Cyrus::Specialuse;
use strict;
use warnings;

use lib '.';
use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;
use Cassandane::Instance;

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

# Test that you can rename a special use folder
sub test_rename_toplevel
{
    my ($self) = @_;

    my $imaptalk = $self->{store}->get_client();

    $imaptalk->create("INBOX.Junk", "(USE (\\Junk))") || die;
    $imaptalk->rename("INBOX.Junk", "INBOX.Other") || die;
}

sub test_rename_tosub
{
    my ($self) = @_;

    my $imaptalk = $self->{store}->get_client();

    $imaptalk->create("INBOX.Junk", "(USE (\\Junk))") || die;
    $imaptalk->create("INBOX.Trash") || die;
    # can't rename to a deep folder
    $imaptalk->rename("INBOX.Junk", "INBOX.Trash.Junk") && die;
}

sub test_create_multiple
{
    my ($self) = @_;

    my $imaptalk = $self->{store}->get_client();

    $imaptalk->create("INBOX.Rubbish", "(USE (\\Junk \\Trash \\Sent))") || die;
}

sub test_create_dupe
{
    my ($self) = @_;

    my $imaptalk = $self->{store}->get_client();

    $imaptalk->create("INBOX.Rubbish", "(USE (\\Trash))") || die;
    $imaptalk->create("INBOX.Trash", "(USE (\\Trash))") && die;
}

sub test_annot
{
    my ($self) = @_;

    my $imaptalk = $self->{store}->get_client();

    $imaptalk->create("INBOX.Trash") || die;
    $imaptalk->setmetadata("INBOX.Trash", "/private/specialuse", "\\Trash") || die;
}

sub test_annot_dupe
{
    my ($self) = @_;

    my $imaptalk = $self->{store}->get_client();

    $imaptalk->create("INBOX.Rubbish", "(USE (\\Trash))") || die;
    $imaptalk->create("INBOX.Trash") || die;
    $imaptalk->setmetadata("INBOX.Trash", "/private/specialuse", "\\Trash") && die;
}

sub test_delete_imm
    :ImmediateDelete
{
    my ($self) = @_;

    my $imaptalk = $self->{store}->get_client();

    $imaptalk->create("INBOX.Trash", "(USE (\\Trash))") || die;
    $imaptalk->delete("INBOX.Trash") && die;
}

sub test_delete_delay
    :DelayedDelete
{
    my ($self) = @_;

    my $imaptalk = $self->{store}->get_client();

    $imaptalk->create("INBOX.Trash", "(USE (\\Trash))") || die;
    $imaptalk->delete("INBOX.Trash") && die;
}

sub test_delete_removed_imm
    :ImmediateDelete
{
    my ($self) = @_;

    my $imaptalk = $self->{store}->get_client();

    $imaptalk->create("INBOX.Trash", "(USE (\\Trash))") || die;
    $imaptalk->setmetadata("INBOX.Trash", "/private/specialuse", undef) || die;
    $imaptalk->delete("INBOX.Trash") || die;
}

sub test_delete_removed_delay
    :DelayedDelete
{
    my ($self) = @_;

    my $imaptalk = $self->{store}->get_client();

    $imaptalk->create("INBOX.Trash", "(USE (\\Trash))") || die;
    $imaptalk->setmetadata("INBOX.Trash", "/private/specialuse", undef) || die;
    $imaptalk->delete("INBOX.Trash") || die;
}

# compile
1;

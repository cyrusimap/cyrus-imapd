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

package Cassandane::Cyrus::JMAPEmailSubmission;
use strict;
use warnings;
use DateTime;
use JSON::XS;
use Net::CalDAVTalk 0.09;
use Net::CardDAVTalk 0.03;
use Mail::JMAPTalk 0.13;
use Data::Dumper;
use Storable 'dclone';
use MIME::Base64 qw(encode_base64);
use Cwd qw(abs_path getcwd);
use URI;

use lib '.';
use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;

use charnames ':full';

sub new
{
    my ($class, @args) = @_;

    my $config = Cassandane::Config->default()->clone();
    $config->set(caldav_realm => 'Cassandane',
                 conversations => 'yes',
                 conversations_counted_flags => "\\Draft \\Flagged \$IsMailingList \$IsNotification \$HasAttachment",
                 event_groups => 'mailbox message flags calendar applepushservice jmap',
                 jmapsubmission_deleteonsend => 'no',
                 httpmodules => 'carddav caldav jmap',
                 httpallowcompress => 'no');

    return $class->SUPER::new({
        config => $config,
        jmap => 1,
        adminstore => 1,
        services => [ 'imap', 'http' ]
    }, @args);
}

sub set_up
{
    my ($self) = @_;
    $self->SUPER::set_up();
    $self->{jmap}->DefaultUsing([
        'urn:ietf:params:jmap:core',
        'urn:ietf:params:jmap:mail',
        'urn:ietf:params:jmap:submission',
    ]);
}

sub skip_check
{
    my ($self) = @_;

    # XXX skip tests that would hang in verbose mode for now -- see
    # XXX detailed comment at MaxMessages::put_submission
    if (get_verbose()
        && $self->{_name} eq 'test_emailsubmission_set_futurerelease')
    {
        return 'test would hang in verbose mode';
    }

    return undef;
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

use Cassandane::Tiny::Loader 'tiny-tests/JMAPEmailSubmission';

1;

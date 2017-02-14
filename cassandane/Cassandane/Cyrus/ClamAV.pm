#!/usr/bin/perl
#
#  Copyright (c) 2017 FastMail Pty. Ltd.  All rights reserved.
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

package Cassandane::Cyrus::ClamAV;
use strict;
use warnings;
use Data::Dumper;

use lib '.';
use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;
use Cassandane::Instance;

$Data::Dumper::Sortkeys = 1;

sub new
{
    my $class = shift;
    return $class->SUPER::new({ }, @_);
}

sub set_up
{
    my ($self) = @_;
    $self->SUPER::set_up();
    if (not $self->{instance}->{buildinfo}->{dependency}->{clamav}) {
        xlog "clamav not enabled. Skipping tests.";
        return;
    }
    $self->{test_clamav} = 1;
}

sub tear_down
{
    my ($self) = @_;
    $self->SUPER::tear_down();
}

sub test_aaasetup
{
    my ($self) = @_;
    return if not $self->{test_clamav};

    # does everything set up and tear down cleanly?
    $self->assert(1);
}

sub test_remove_infected
{
    my ($self) = @_;
    return if not $self->{test_clamav};

    $self->{store}->set_fetch_attributes(qw(uid flags));

    my $talk = $self->{store}->get_client();
    $talk->select("INBOX");
    $self->assert_num_equals(1, $talk->uid());

    my $body = ""
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
    . "--boundary\r\n";

    my %exp;

    $exp{1} = $self->make_message("eicar attached",
				       mime_type => "multipart/mixed",
				       mime_boundary => "boundary",
				       body => $body);

    $exp{2} = $self->make_message("clean");

    $self->check_messages(\%exp, ( keyed_on => 'uid' ));

    my $out = "$self->{instance}->{basedir}/$self->{_name}-cyr_virusscan.stdout";

    $self->{instance}->run_command(
	{ cyrus => 1,
	  redirects => { 'stdout' => $out },
	}, 'cyr_virusscan', '-r');

    # check the output
    # user.cassandane				         1  UNREAD  Eicar-Test-Signature
    {
	local $/;
	open my $fh, '<', $out
	    or die "Cannot open $out for reading: $!";
	$out = <$fh>;
	close $fh;
	xlog $out;
    }
    # XXX is there a better way than hard coding UID:1 ?
    $self->assert_matches(qr/user\.cassandane\s+1\s+UNREAD\s+Eicar-Test-Signature/,
			  $out);

    # make sure the infected one was expunged, but the clean one wasn't
    delete $exp{1};
    $self->check_messages(\%exp, ( keyed_on => 'uid' ));
}

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

package Cassandane::Cyrus::ClamAV;
use strict;
use warnings;
use Data::Dumper;

use lib '.';
use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;
use Cassandane::Instance;

$Data::Dumper::Sortkeys = 1;

my %eicar_attached = (
    mime_type => "multipart/mixed",
    mime_boundary => "boundary",
    body => ""
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
	. "--boundary\r\n",
);

sub new
{
    my $class = shift;
    return $class->SUPER::new({ adminstore => 1 }, @_);
}

sub set_up
{
    my ($self) = @_;
    $self->SUPER::set_up();

    # set up a shared folder that's easy to write to
    my $admintalk = $self->{adminstore}->get_client();
    $admintalk->create('shared.folder');
    $admintalk->setacl('shared.folder', 'cassandane' => 'lrswipkxtecd');
}

sub tear_down
{
    my ($self) = @_;
    $self->SUPER::tear_down();
}

sub test_aaasetup
    :needs_dependency_clamav
{
    my ($self) = @_;

    # does everything set up and tear down cleanly?
    $self->assert(1);
}

sub test_remove_infected
    :needs_dependency_clamav
{
    my ($self) = @_;

    $self->{store}->set_fetch_attributes(qw(uid flags));

    my $talk = $self->{store}->get_client();
    $talk->select("INBOX");
    $self->assert_num_equals(1, $talk->uid());
    $talk->select("shared.folder");
    $self->assert_num_equals(1, $talk->uid());

    # put some test messages in INBOX (and verify)
    $self->{store}->set_folder("INBOX");
    my %cass_exp;
    $cass_exp{1} = $self->make_message("eicar attached", uid => 1, %eicar_attached);
    $cass_exp{2} = $self->make_message("clean", uid => 2);
    $self->check_messages(\%cass_exp, ( keyed_on => 'uid' ));

    # put some test messages in shared.folder (and verify)
    $self->{store}->set_folder("shared.folder");
    my %shared_exp;
    $shared_exp{1} = $self->make_message("eicar attached", uid => 1, %eicar_attached);
    $shared_exp{2} = $self->make_message("clean", uid => 2);
    $self->check_messages(\%shared_exp, ( keyed_on => 'uid' ));

    # run cyr_virusscan
    my $out = "$self->{instance}->{basedir}/$self->{_name}-cyr_virusscan.stdout";
    $self->{instance}->run_command(
	{ cyrus => 1,
	  redirects => { 'stdout' => $out },
	}, 'cyr_virusscan', '-r');

    # check the output
    # user.cassandane				         1  UNREAD  Eicar-Test-Signature
    # shared.folder				         1  UNREAD  Eicar-Test-Signature
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
    $self->assert_matches(qr/shared\.folder\s+1\s+UNREAD\s+Eicar-Test-Signature/,
			  $out);

    # make sure the infected ones were expunged, but the clean ones weren't
    $self->{store}->set_folder("INBOX");
    delete $cass_exp{1};
    $self->check_messages(\%cass_exp, ( keyed_on => 'uid' ));

    $self->{store}->set_folder("shared.folder");
    delete $shared_exp{1};
    $self->check_messages(\%shared_exp, ( keyed_on => 'uid' ));
}

# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Cyrus::URLAuth;
use strict;
use warnings;
use Cwd qw(abs_path);
use File::Path qw(mkpath);
use DateTime;
use Data::Dumper;

use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;
use Cassandane::Util::NetString;


sub new
{
    my $class = shift;

    my $config = Cassandane::Config->default()->clone();
    $config->set(servername => "127.0.0.1"); # urlauth needs matching servername

    return $class->SUPER::new({
        config => $config,
        adminstore => 1,
        services => ['imap']
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

sub test_urlfetch
{
    my ($self) = @_;

    my %exp_sub;
    my $store = $self->{store};
    my $talk = $store->get_client();

    $store->set_folder("INBOX");
    $store->_select();
    $self->{gen}->set_next_uid(1);

    my $body;

    # Subpart 1
    $body = "--047d7b33dd729737fe04d3bde348\r\n"
    . "Content-Type: text/plain; charset=UTF-8\r\n"
    . "\r\n"
    . "body1"
    . "\r\n";

    # Subpart 2
    $body .= "--047d7b33dd729737fe04d3bde348\r\n"
    . "Content-Type: multipart/mixed;boundary=frontier\r\n"
    . "\r\n";

    # Subpart 2.1
    $body .= "--frontier\r\n"
    . "Content-Type: text/plain\r\n"
    . "\r\n"
    . "body21"
    . "\r\n";

    # End subpart 2
    $body .= "--frontier--\r\n";

    # Subpart 3
    my $msg3 = ""
    . "Return-Path: <Ava.Nguyen\@local>\r\n"
    . "Mime-Version: 1.0\r\n"
    . "Content-Type: text/plain\r\n"
    . "Content-Transfer-Encoding: 7bit\r\n"
    . "Subject: bar\r\n"
    . "From: Ava T. Nguyen <Ava.Nguyen\@local>\r\n"
    . "Message-ID: <fake.1475639947.6507\@local>\r\n"
    . "Date: Wed, 05 Oct 2016 14:59:07 +1100\r\n"
    . "To: Test User <test\@local>\r\n"
    . "\r\n"
    . "body3";

    $body .= "--047d7b33dd729737fe04d3bde348\r\n"
    . "Content-Type: message/rfc822\r\n"
    . "\r\n"
    . $msg3
    . "\r\n";

    # End body
    $body .= "--047d7b33dd729737fe04d3bde348--";

    $self->make_message("foo",
        mime_type => "multipart/mixed",
        mime_boundary => "047d7b33dd729737fe04d3bde348",
        body => $body
    );

    my $data;
    my %handlers =
    (
        urlfetch => sub
        {
            my ($cmd, $params) = @_;
            $data = ${$params}[1];
        },
    );

    my $url = $talk->_imap_cmd('genurlauth', 0, "genurlauth",
                               "imap://cassandane\@127.0.0.1/INBOX/;uid=1/;section=3.TEXT;partial=1.3;urlauth=user+cassandane",
                               'INTERNAL');

    my $res = $talk->_imap_cmd('urlfetch', 0, \%handlers, substr($url, 1, -1));
    
    $self->assert_str_equals($data, "ody");
}

1;

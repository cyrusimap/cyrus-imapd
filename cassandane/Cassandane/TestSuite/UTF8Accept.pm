# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::TestSuite::UTF8Accept;
use strict;
use warnings;
use Cwd qw(abs_path);
use File::Path qw(mkpath);
use DateTime;
use Data::Dumper;

use Encode qw(encode_utf8);

use base qw(Cassandane::Unit::TestSuite::Cyrus);
use Cassandane::Util::CRLF;
use Cassandane::Util::Log;
use Cassandane::Util::NetString;

Cassandane::Unit::TestSuite::Cyrus::magic(Munge8Bit => sub {
    shift->config_set(munge8bit => 'on');
});

sub new
{
    my $class = shift;
    my $config = Cassandane::Config->default()->clone();

    # Make sure the server will advertise support for UTF8=ACCEPT
    $config->set(reject8bit => 'off');
    $config->set(munge8bit => 'off');

    return $class->SUPER::new({
        services => ['imap'],
        config => $config,
        deliver => 1,
        adminstore => 1,
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

# Connect to lmtpd and read its greeting.
sub lmtp_connect
{
    my ($self) = @_;

    my $sock = $self->{instance}->get_service('lmtp')->get_socket()
        or die "Cannot connect to lmtpd: $!";
    my ($code) = $self->lmtp_read($sock);
    die "Bad LMTP greeting" if $code != 220;

    return $sock;
}

# Read one LMTP reply, and return its code and lines (without the code).
sub lmtp_read
{
    my ($self, $sock) = @_;

    my ($code, @lines);
    while (defined(my $line = $sock->getline())) {
        $line =~ s/\r?\n$//;
        my ($c, $more, $text) = $line =~ m/^(\d{3})([- ])(.*)$/
            or die "Bad LMTP reply: $line";
        $code = $c;
        push @lines, $text;
        last if $more eq ' ';
    }

    return ($code, @lines);
}

# Send an LMTP command, given as a character string, and read the reply.
sub lmtp_cmd
{
    my ($self, $sock, $cmd) = @_;

    $sock->print(encode_utf8($cmd) . "\r\n");
    return $self->lmtp_read($sock);
}

# Send message data, and return the reply codes, one per recipient.
sub lmtp_data
{
    my ($self, $sock, $nrcpts, $msg) = @_;

    my ($code) = $self->lmtp_cmd($sock, 'DATA');
    die "DATA refused: $code" if $code != 354;

    my $data = encode_utf8($msg);
    $data =~ s/^\./../mg;
    $sock->print($data . ".\r\n");

    return map { ($self->lmtp_read($sock))[0] } 1 .. $nrcpts;
}

use Cassandane::Tiny::Loader;

1;

# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::TestSuite::HttpH3;
use strict;
use warnings;
use v5.28.0;
use experimental 'signatures';

use File::Temp qw(tempdir);

use base qw(Cassandane::Unit::TestSuite::Cyrus);
use Cassandane::Util::Log;
use Cassandane::Util::Wire;

=head1 NAME

Cassandane::TestSuite::HttpH3 - HTTP/3 tests

=head1 OVERVIEW

This suite runs an httpd service with C<proto="quic">, alongside the usual
C<imap> and C<http> ones, and provides C<< L</http3_request> >> to send it
requests.  There is no QUIC or HTTP/3 client for Perl worth building on, so
requests are made by running C<curl>, and the suite is skipped unless that
C<curl> supports HTTP/3.  The QUIC service uses master's userspace relay,
so tests need neither root nor eBPF.

Every request and response is written to the test log by
L<Cassandane::Util::Wire>, so a failing test reports the exchange that failed.

=cut

sub new ($class, @args)
{
    my $config = Cassandane::Config->default()->clone();
    $config->set(tls_server_cert => '@basedir@/conf/certs/cert.pem',
                 tls_server_key => '@basedir@/conf/certs/key.pem',
                 caldav_realm => 'Cassandane',
                 httpmodules => 'caldav',
                 calendar_user_address_set => 'example.com',
                 httpcontentmd5 => 'yes');

    my $self = $class->SUPER::new({
        config => $config,
        install_certificates => 1,
        services => [ 'imap', 'http' ],
    }, @args);

    $self->needs('component', 'httpd');
    $self->needs('component', 'quic');
    $self->needs('dependency', 'nghttp3');

    return $self;
}

my $curl_has_http3;

# Skip the whole suite unless curl speaks HTTP/3.  Anything else that would
# have skipped the test gets to say so first.
sub reason_to_skip ($self, %opt)
{
    my $reason = $self->SUPER::reason_to_skip(%opt);
    return $reason if $reason;

    $curl_has_http3 //= (`curl -V 2>/dev/null` =~ m/^Features:.*\bHTTP3\b/m)
                        ? 1 : 0;
    return "curl does not support HTTP/3" if !$curl_has_http3;

    return;
}

sub _create_instances ($self)
{
    $self->SUPER::_create_instances();
    $self->{instance}->add_service(name => 'http3',
                                   argv => ['httpd'],
                                   proto => 'quic');
}

=head1 METHODS

=head2 http3_request

    my $res = $self->http3_request(
        method  => 'PUT',
        path    => '/dav/calendars/user/cassandane/Default/x.ics',
        headers => [ 'content-type' => 'text/calendar' ],
        body    => $ical,
    );
    # $res->{status}, $res->{headers} (hashref), $res->{body},
    # $res->{trailers} (hashref)

Performs a single HTTP/3 request on a new connection to the instance's
C<http3> service, and returns the response as a hashref with C<status> (an
integer), C<headers> (a hashref of the response headers, with lowercase
names and repeated fields comma-joined), C<body> and C<trailers> (a hashref
like C<headers>, of any trailer fields).  Dies if the response
didn't come over HTTP/3.

Options:

=over 4

=item C<method>

the request method (default C<GET>).

=item C<path>

the request target (default C<'/'>).

=item C<headers>

an arrayref of additional request header name/value pairs.  A value of
C<undef> removes a header curl would otherwise send, such as
C<Content-Length>.

=item C<body>

the request body.

=item C<username> / C<password>

HTTP Basic credentials to send.  Default to the C<cassandane> test user; pass
C<< username => undef >> for no auth.

=item C<timeout>

seconds to wait for the response (default 30)

=back

=cut

sub http3_request ($self, %args)
{
    my $method  = $args{method}  // 'GET';
    my $path    = $args{path}    // '/';
    my $headers = $args{headers} // [];
    my $timeout = $args{timeout} // 30;

    my $service = $self->{instance}->get_service('http3');
    my $authority = $service->host . ':' . $service->port;
    my $dir = tempdir(DIR => $self->{instance}->get_basedir() . '/tmp',
                      CLEANUP => 1);

    my @cmd = ('curl', '--http3-only', '--insecure', '--silent',
               '--show-error', '--max-time', $timeout,
               '--request', $method,
               '--dump-header', "$dir/headers", '--output', "$dir/body",
               '--write-out', '%{http_version}');

    my $username = exists $args{username} ? $args{username} : 'cassandane';
    if (defined $username) {
        my $password = $args{password} // 'pass';
        push @cmd, '--user', "$username:$password";
    }

    my @req_headers = @$headers;
    while (my ($name, $value) = splice @req_headers, 0, 2) {
        push @cmd, '--header', defined $value ? "$name: $value" : "$name:";
    }

    if (defined $args{body}) {
        open my $fh, '>:raw', "$dir/request" or die "$dir/request: $!";
        print $fh $args{body};
        close $fh;
        push @cmd, '--data-binary', "\@$dir/request";
    }

    push @cmd, "https://$authority$path";

    my $req_log = "$method $path HTTP/3\n";
    $req_log .= "$headers->[$_]: $headers->[$_ + 1]\n"
        for grep { $_ % 2 == 0 && defined $headers->[$_ + 1] } 0 .. $#$headers;
    wire_sent($authority, $req_log . "\n" . ($args{body} // ''));

    open my $curl, '-|', @cmd or die "cannot run curl: $!";
    my $version = do { local $/; <$curl> };
    close $curl;
    die "curl exited with status " . ($? >> 8) if $?;
    die "response came over HTTP/$version, not HTTP/3" if $version ne '3';

    my $res = { status => undef, headers => {}, body => '', trailers => {} };

    # curl writes any trailer fields after the header section's blank line
    open my $hfh, '<:raw', "$dir/headers" or die "$dir/headers: $!";
    my $status_line = <$hfh>;
    ($res->{status}) = $status_line =~ m{^HTTP/3 (\d{3})};
    my $fields = $res->{headers};
    while (my $line = <$hfh>) {
        $line =~ s/\r?\n$//;
        if ($line eq '') {
            $fields = $res->{trailers};
            next;
        }
        my ($name, $value) = $line =~ m/^([^:]+):\s*(.*)$/ or next;
        # A repeated field is the same as one with the values comma-joined
        # (RFC 9110 5.3)
        $fields->{lc $name} = exists $fields->{lc $name}
                            ? "$fields->{lc $name}, $value"
                            : $value;
    }
    close $hfh;

    if (open my $bfh, '<:raw', "$dir/body") {
        $res->{body} = do { local $/; <$bfh> };
        close $bfh;
    }

    my $res_log = 'HTTP/3 ' . ($res->{status} // '(no status)') . "\n";
    $res_log .= "$_: $res->{headers}{$_}\n" for sort keys %{ $res->{headers} };
    $res_log .= "\n" . $res->{body};
    $res_log .= "\n$_: $res->{trailers}{$_}" for sort keys %{ $res->{trailers} };
    wire_recv($authority, $res_log);

    return $res;
}

use Cassandane::Tiny::Loader;

1;

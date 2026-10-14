# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::TestSuite::HttpH3;
use strict;
use warnings;
use v5.28.0;
use experimental 'signatures';

use Cwd qw(abs_path);
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

Tests of connection migration use C<< L</h3migrate> >> instead, which runs
F<utils/h3migrate>.  That is only built where ngtcp2 and nghttp3 are
installed, and the tests are skipped without it.

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

    return "utils/h3migrate was not built (it needs ngtcp2 and nghttp3)"
        if $self->name() =~ m/migration/ && !-x 'utils/h3migrate';

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

=head2 h3migrate

    my $run = $self->h3migrate(path => $path, migrations => 3);
    # $run->{exit}, $run->{responses}, $run->{migrated}, $run->{end}

Runs F<utils/h3migrate> against the instance's C<http3> service: one
connection that GETs C<path>, then for each migration moves to a fresh local
port and GETs it again.  Returns a hashref with C<exit> (its exit status: 0
if every request was answered, 3 if the connection ended first),
C<responses> (an arrayref of C<{ status, bodylen, port }>, one per answered
request), C<migrated> (an arrayref of the local port after each migration)
and C<end> (how the connection ended early, such as C<"closed ..."> or
C<"stalled 8">, or undef).

Options are C<path> (default C<'/'>), C<migrations> (default 1),
C<timeout> (seconds to wait for each step, default 10) and C<username> /
C<password> (HTTP Basic credentials, none by default).

=cut

sub h3migrate ($self, %args)
{
    my $service = $self->{instance}->get_service('http3');
    my @cmd = (abs_path('utils/h3migrate'),
               '-n', $args{migrations} // 1,
               '-t', $args{timeout} // 10);
    push @cmd, '-u', "$args{username}:" . ($args{password} // 'pass')
        if defined $args{username};
    push @cmd, $service->host, $service->port, $args{path} // '/';

    open my $fh, '-|', @cmd or die "cannot run h3migrate: $!";
    my $output = do { local $/; <$fh> };
    close $fh;
    my $run = { exit => $? >> 8, responses => [], migrated => [],
                end => undef };
    xlog $self, "h3migrate exited $run->{exit}:\n$output";
    die "h3migrate failed" if $run->{exit} == 1 || $? & 127;

    for my $line (split /\n/, $output) {
        if ($line =~ m/^response \d+ (\d+) (\d+) (\d+)$/) {
            push @{$run->{responses}},
                 { status => $1, bodylen => $2, port => $3 };
        }
        elsif ($line =~ m/^migrated \d+ (\d+)$/) {
            push @{$run->{migrated}}, $1;
        }
        else {
            $run->{end} = $line;
        }
    }

    return $run;
}

use Cassandane::Tiny::Loader;

1;

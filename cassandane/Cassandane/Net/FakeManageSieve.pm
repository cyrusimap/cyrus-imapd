# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Net::FakeManageSieve;
use v5.28.0;
use warnings;
use experimental 'signatures';

use IO::Select;
use IO::Socket::INET;
use MIME::Base64 qw(decode_base64);
use POSIX ();

use Cassandane::Util::Slurp;

my $CAPABILITIES = qq{"SASL" "PLAIN"\r\n"VERSION" "1.0"\r\nOK\r\n};

=head1 NAME

Cassandane::Net::FakeManageSieve - scripted ManageSieve server for client tests

=head1 SYNOPSIS

    my $srv = Cassandane::Net::FakeManageSieve->new(
        main => {
            LISTSCRIPTS => sub ($srv, $line, $literal) {
                my $port = $srv->port('other');
                qq{BYE (REFERRAL "sieve://127.0.0.1:$port") "moved"\r\n};
            },
        },
        other => {
            auth => sub ($authzid, $authcid, $password) { "OK\r\n" },
            LISTSCRIPTS => sub { qq{"s1" ACTIVE\r\nOK\r\n} },
        },
    );
    my ($status, $output) = $srv->run_client($instance, $code, @args);

=head1 DESCRIPTION

Each role named in the constructor gets its own listener on 127.0.0.1,
served by a forked process.  A role is a hash:

=over

=item greeting

Text sent on connect.  Defaults to capabilities offering only PLAIN.

=item auth

Called with the PLAIN credentials of each AUTHENTICATE; returns the reply.
Defaults to accepting everything.

=item I<COMMAND>

Called for that command with the server, the command line and any literal
that followed it; returns the reply.  Commands without a handler get NO.

=back

The connection closes after any greeting or reply that doesn't end in CRLF,
and after LOGOUT.

=cut

sub new ($class, %roles)
{
    my %listeners = map {
        $_ => IO::Socket::INET->new(
            LocalAddr => '127.0.0.1',
            LocalPort => 0,
            Listen => 16,
        ) || die "listen: $!"
    } keys %roles;

    my $self = bless {
        ports => { map { $_ => $listeners{$_}->sockport() } keys %roles },
        owner => $$,
    }, $class;

    my $pid = fork() // die "fork: $!";
    if ($pid) {
        close $_ for values %listeners;
        $self->{pid} = $pid;
        return $self;
    }

    $SIG{CHLD} = 'IGNORE';
    my %role = map { fileno($listeners{$_}) => $_ } keys %listeners;
    my $select = IO::Select->new(values %listeners);
    while (my @ready = $select->can_read()) {
        for my $l (@ready) {
            my $conn = $l->accept() or next;
            my $role = $roles{$role{fileno($l)}};
            next if fork();
            alarm 60;
            close $_ for values %listeners;
            $self->_serve($conn, $role);
            POSIX::_exit(0);
        }
    }
    POSIX::_exit(0);
}

sub _serve ($self, $conn, $role)
{
    my $greeting = $role->{greeting} // $CAPABILITIES;
    syswrite $conn, $greeting;
    return if $greeting !~ m/\r\n\z/;

    while (defined(my $line = <$conn>)) {
        my $literal;
        if ($line =~ m/\{(\d+)\+?\}\r\n\z/) {
            read($conn, $literal, $1);
            <$conn>;
        }
        my ($cmd) = $line =~ m/^(\w+)/;
        $cmd = uc($cmd // '');
        return if $cmd eq 'LOGOUT';

        my $reply;
        if ($cmd eq 'AUTHENTICATE') {
            my @creds = split /\0/, decode_base64($literal // ''), 3;
            $reply = $role->{auth} ? $role->{auth}->(@creds) : "OK\r\n";
        }
        elsif ($role->{$cmd}) {
            $reply = $role->{$cmd}->($self, $line, $literal);
        }
        else {
            $reply = qq{NO "unsupported"\r\n};
        }
        syswrite $conn, $reply;
        return if $reply !~ m/\r\n\z/;
    }
}

=head1 METHODS

=head2 port($role)

The port that the listener for C<$role> is on.

=cut

sub port ($self, $role)
{
    return $self->{ports}{$role} // die "no role $role";
}

=head2 run_client($instance, $code, @args)

Runs C<$code> as a Perl program with Cyrus::SIEVE::managesieve loaded,
C<@args> in C<@ARGV>, and a 60 second alarm.  Returns its exit status
("ok", "exit N" or "signal N") and its combined stdout and stderr.

=cut

sub run_client ($self, $instance, $code, @args)
{
    my $basedir = $instance->get_basedir();
    my $n = $self->{nclients}++;
    my $script = "$basedir/managesieve-client$n.pl";
    my $out = "$basedir/managesieve-client$n.out";

    open my $fh, '>', $script or die "$script: $!";
    print $fh "use Cyrus::SIEVE::managesieve;\nalarm 60;\n$code";
    close $fh;

    my $status = 'ok';
    $instance->run_command({
        perl_xs => 1,
        redirects => { stdout => $out, stderr => $out },
        handlers => {
            exited_abnormally => sub ($child, $code) { $status = "exit $code" },
            signaled => sub ($child, $sig) { $status = "signal $sig" },
        },
    }, $^X, $script, @args);

    return ($status, slurp_file($out));
}

=head2 stop()

Stops the server.  Also called when the object is destroyed.

=cut

sub stop ($self)
{
    my $pid = delete $self->{pid};
    return if !$pid || $$ != $self->{owner};
    kill 'TERM', $pid;
    waitpid $pid, 0;
}

sub DESTROY ($self)
{
    $self->stop();
}

1;

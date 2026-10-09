# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::TestSuite::Simple;
use strict;
use warnings;
use Cwd qw(getcwd realpath);
use Data::Dumper;
use DateTime;
use DB_File;
use Fcntl;
use MIME::Base64;
use Sys::Hostname;

use base qw(Cassandane::Unit::TestSuite::Cyrus);
use Cassandane::Util::CRLF;
use Cassandane::Util::Log;
use Cassandane::Util::Slurp;

$Data::Dumper::Sortkeys = 1;

sub new
{
    my $class = shift;
    return $class->SUPER::new({}, @_);
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

# Authenticate over STARTTLS with imtest using SCRAM-SHA-256-PLUS, and
# return the GS2 header of the client's first message, which names the
# channel binding type both ends agreed on.  Call before starting instances.
sub scram_plus_gs2_header
{
    my ($self, %config) = @_;
    my $instance = $self->{instance};
    # the default SASL realm is servername, which defaults to gethostname()
    my $realm = hostname();

    $self->config_set(%config,
                      allowstarttls => 'on',
                      sasl_mech_list => 'PLAIN SCRAM-SHA-256-PLUS',
                      sasl_sasldb_path => '@basedir@/etc/sasldb2');
    $self->_start_instances();

    my $etc = $instance->get_basedir() . "/etc";
    mkdir $etc;
    tie my %sasldb, 'DB_File', "$etc/sasldb2", O_RDWR|O_CREAT, 0640, $DB_HASH
        or die "Can't tie $etc/sasldb2: $!";
    $sasldb{join "\0", 'cassandane', $realm, 'userPassword'} = 'secret';
    untie %sasldb;

    my $svc = $instance->get_service('imap');
    my $out = $instance->get_basedir() . "/imtest.$$.out";
    $instance->run_command(
        { redirects => { stdin => \". logout\r\n", stdout => $out } },
        $instance->_find_binary('imtest'),
        '-t', '', '-m', 'SCRAM-SHA-256-PLUS',
        '-a', 'cassandane', '-w', 'secret', '-r', $realm,
        '-p', $svc->port(), $svc->host());

    my $exchange = slurp_file($out);
    $self->assert_matches(qr/^S: A01 OK/m, $exchange);
    # imtest shows the mechanism without the -PLUS suffix
    my ($first) = $exchange =~ /^C: A01 AUTHENTICATE SCRAM-SHA-256\S* (\S+)/m;
    $self->assert_not_null($first);
    my ($gs2) = decode_base64($first) =~ /^([^,]*),/;
    return $gs2;
}

use Cassandane::Tiny::Loader;

1;

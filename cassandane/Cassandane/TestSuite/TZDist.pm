# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::TestSuite::TZDist;
use strict;
use warnings;
use HTTP::Tiny;
use JSON::XS;
use Path::Tiny;
use URI;

use base qw(Cassandane::Unit::TestSuite::Cyrus);
use Cassandane::Util::Log;
use Cassandane::Instance;

use v5.36.0;

sub new ($class, @args)
{
    my $config = Cassandane::Config->default()->clone();
    $config->set(tzdist_enabled => "yes");
    $config->set(httpmodules => "tzdist");

    my $self = $class->SUPER::new(
        { adminstore => 1,
          config => $config,
          services => ['imap', 'http'] },
        @args);

    $self->needs('component', 'httpd');
    return $self;
}

sub set_up ($self)
{
    $self->SUPER::set_up();

    my $instance = $self->{instance};

    # As best I can tell there's no way to determine the path
    # share/cyrus-imapd/zoneinfo from reading configuration files. It's exposed
    # to C code as extern const char *config_zoneinfo_dir;
    # and set in lib/libconfig.c
    #
    # #ifdef DEFAULT_ZONEINFO_DIR
    # if (!config_zoneinfo_dir)
    #     config_zoneinfo_dir = DEFAULT_ZONEINFO_DIR;
    # #endif
    #
    # and our Makefile has this:
    # am__append_3 = -DDEFAULT_ZONEINFO_DIR=\"$(zoneinfodir)\"
    # so it's in the C flags...

    my $tzdb_version =
        path("$instance->{cyrus_destdir}$instance->{cyrus_prefix}")
        ->child(qw(share cyrus-imapd zoneinfo version))
        ->lines({ chomp => 1, count => 1 });
    $self->{tzdb_publisher} = 'Olson';
    $self->{tzdb_version} = $tzdb_version;

    my $ctl_zoneinfo = $instance->_find_binary('ctl_zoneinfo');
    my $conf = $instance->_imapd_conf();

    $instance->run_command(
        $ctl_zoneinfo, '-C', $conf, '-r', "$self->{tzdb_publisher}:$tzdb_version",
    );
    return;
}

sub tzlist ($self, @query_params)
{
    my $service = $self->{instance}->get_service("http");
    my $url = URI->new(
        join(q{},
             q{http://}, $service->host(),
             q{:}, $service->port(),
             q{/tzdist/zones})
    );
    $url->query_form(@query_params) if @query_params;

    state $http = HTTP::Tiny->new();
    my $response = $http->get($url);
    my $content = $response->{content};

    $self->assert(length $content > 0);
    return decode_json($content);
}

use Cassandane::Tiny::Loader;

1;

#!/usr/bin/perl
#
#  Copyright (c) 2011 Opera Software Australia Pty. Ltd.  All rights
#  reserved.
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
#  3. The name "Opera Software Australia" must not be used to
#     endorse or promote products derived from this software without
#     prior written permission. For permission or any legal
#     details, please contact
#       Opera Software Australia Pty. Ltd.
#       Level 50, 120 Collins St
#       Melbourne 3000
#       Victoria
#       Australia
#
#  4. Redistributions of any form whatsoever must retain the following
#     acknowledgment:
#     "This product includes software developed by Opera Software
#     Australia Pty. Ltd."
#
#  OPERA SOFTWARE AUSTRALIA DISCLAIMS ALL WARRANTIES WITH REGARD TO
#  THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
#  AND FITNESS, IN NO EVENT SHALL OPERA SOFTWARE AUSTRALIA BE LIABLE
#  FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
#  WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
#  AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
#  OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#

use strict;
use warnings;

use lib '.';
use Cassandane::Util::Setup;
use Cassandane::Util::Log;
use Cassandane::Config;
use Cassandane::Instance;
use Cassandane::Cassini;

my $name;
my $config = Cassandane::Config->default()->clone();
my $start_flag = 0;
my $re_use_dir = 1;
my @services = ( 'imap' );
$start_flag = 1 if $0 =~ m/start-instance/;

sub latest_instance
{
    my @infos = Cassandane::Instance::list();
    die "No instances, sorry" unless scalar @infos;
    @infos = sort {
                $b->{ctime} <=> $a->{ctime}
            } @infos;
    return shift(@infos)->{name};
}

sub usage
{
    if ($start_flag)
    {
        print STDERR "Usage: start-instance.pl [ -O config-option=value ... ] [name]\n";
    }
    else
    {
        print STDERR "Usage: stop-instance.pl [name]\n";
    }
    exit(1);
}

while (my $a = shift)
{
    if ($a eq '-O' || $a eq '--option')
    {
        my $vv = shift || usage;
        my ($name, $value) = ($vv =~ m/^([a-z][a-z0-9-]+)=(.*)$/);
        usage() unless defined $value;
        $config->set($name, $value);
    }
    elsif ($a eq '-v' || $a eq '--verbose')
    {
        set_verbose(1);
    }
    elsif ($a eq '--reset')
    {
        $re_use_dir = 0;
    }
    elsif ($a eq '--valgrind')
    {
        Cassandane::Cassini->instance()->override('valgrind', 'enabled', 'yes');
    }
    elsif ($a eq '--service')
    {
        my $vv = shift || usage;
        push(@services, $vv);
    }
    elsif ($a eq '--latest')
    {
        usage() if defined $name;
        $name = latest_instance();
    }
    elsif ($a =~ m/^-/)
    {
        printf STDERR "Unknown option $a\n";
        usage();
    }
    else
    {
        usage() if defined $name;
        $name = $a;
    }
}
$name ||= 'casscmd';

become_cyrus();

my $iinfo = Cassandane::Instance::exists($name);
exit(0) if (!$iinfo && !$start_flag);   # nothing to stop
my $instance;
if ($iinfo && $re_use_dir)
{
    $instance = Cassandane::Instance->new(
                    name => $iinfo->{name},
                    basedir => $iinfo->{basedir},
                    re_use_dir => 1,
                    persistent => $start_flag ? 1 : 0,
               );
}
else
{
    $instance = Cassandane::Instance->new(
                    name => $name,
                    config => $config,
                    persistent => $start_flag ? 1 : 0,
               );
    $instance->add_services(@services);
}

if ($start_flag)
{
    $instance->start();
    $instance->describe();
}
else
{
    $instance->stop();
}

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

package Cassandane::Test::Cassini;
use strict;
use warnings;
use File::chdir;
use File::Temp qw(tempdir);

use lib '.';
use base qw(Cassandane::Unit::TestCase);
use Cassandane::Cassini;
use Cassandane::Util::Log;

sub new
{
    my $class = shift;
    return $class->SUPER::new(@_);
}

sub write_inifile
{
    my ($options, %contents) = @_;

    my $filename = $options->{filename} || 'cassandane.ini';

    my %sections;
    foreach my $k (keys %contents)
    {
        my ($sec, $param) = split(/\./, $k);
        $sections{$sec} ||= {};
        $sections{$sec}->{$param} = $contents{$k};
    }

    open INIFILE, '>', $filename
        or die "Cannot open file $filename for writing: $!";
    foreach my $sec (keys %sections)
    {
        printf INIFILE "[%s]\n", $sec;
        foreach my $param (keys %{$sections{$sec}})
        {
            printf INIFILE "%s=%s\n", $param, $sections{$sec}->{$param};
        }
    }
    close INIFILE;
}

sub test_basic
{
    my ($self) = @_;

    local $CWD = tempdir(CLEANUP => 1);

    xlog "Working in temporary directory $CWD";
    # data thanks to hipsteripsum.me
    write_inifile({},
        'helvetica.blog' => 'ethical',
    );

    my $cassini = new Cassandane::Cassini;

    # Don't find non-existant param in non-existant section
    $self->assert_null($cassini->val('swag', 'quinoa'));
    # or return the default
    $self->assert_str_equals('whatever',
                             $cassini->val('swag', 'quinoa', 'whatever'));

    # Don't find non-existant param in existant section
    $self->assert_null($cassini->val('helvetica', 'quinoa'));
    # or return the default
    $self->assert_str_equals('whatever',
                             $cassini->val('helvetica', 'quinoa', 'whatever'));

    # Don't find param in non-existant section where the
    # param does exist in another section
    $self->assert_null($cassini->val('swag', 'blog'));
    # or return the default
    $self->assert_str_equals('whatever',
                             $cassini->val('swag', 'blog', 'whatever'));

    # Don't find case aliases for existant param
    $self->assert_null($cassini->val('Helvetica', 'blog'));
    $self->assert_null($cassini->val('helvetica', 'Blog'));
    $self->assert_null($cassini->val('HELvEtIca', 'blOG'));

    # Do find exact match for existant param
    $self->assert_str_equals('ethical', $cassini->val('helvetica', 'blog'));
}

sub test_boolval
{
    my ($self) = @_;

    local $CWD = tempdir(CLEANUP => 1);

    xlog "Working in temporary directory $CWD";
    # data thanks to hipsteripsum.me
    write_inifile({},
        'narwhal.cardigan' => 'no',
        'narwhal.banksy' => 'yes',
        'narwhal.occupy' => 'NO',
        'narwhal.mustache' => 'YES',
        'narwhal.gentrify' => 'false',
        'narwhal.thundercats' => 'true',
        'narwhal.scenester' => 'FALSE',
        'narwhal.squid' => 'TRUE',
        'narwhal.selvage' => '0',
        'narwhal.portland' => '1',
        'narwhal.bunch' => 'off',
        'narwhal.bicycle' => 'on',
        'narwhal.organic' => 'OFF',
        'narwhal.leggings' => 'ON',
        'narwhal.mixtape' => '',
        'narwhal.vegan' => 'invalid',
    );

    my $cassini = new Cassandane::Cassini;

    $self->assert_equals(0, $cassini->bool_val('narwhal', 'cardigan'));
    $self->assert_equals(1, $cassini->bool_val('narwhal', 'banksy'));
    $self->assert_equals(0, $cassini->bool_val('narwhal', 'occupy'));
    $self->assert_equals(1, $cassini->bool_val('narwhal', 'mustache'));
    $self->assert_equals(0, $cassini->bool_val('narwhal', 'gentrify'));
    $self->assert_equals(1, $cassini->bool_val('narwhal', 'thundercats'));
    $self->assert_equals(0, $cassini->bool_val('narwhal', 'scenester'));
    $self->assert_equals(1, $cassini->bool_val('narwhal', 'squid'));
    $self->assert_equals(0, $cassini->bool_val('narwhal', 'selvage'));
    $self->assert_equals(1, $cassini->bool_val('narwhal', 'portland'));
    $self->assert_equals(0, $cassini->bool_val('narwhal', 'brunch'));
    $self->assert_equals(1, $cassini->bool_val('narwhal', 'bicycle'));
    $self->assert_equals(0, $cassini->bool_val('narwhal', 'organic'));
    $self->assert_equals(1, $cassini->bool_val('narwhal', 'leggings'));

    eval { $cassini->bool_val('narwhal', 'mixtape'); };
    my $exception = $@;
    $self->assert_matches(qr/Bad boolean/, $exception);

    eval { $cassini->bool_val('narwhal', 'vegan'); };
    $exception = $@;
    $self->assert_matches(qr/Bad boolean/, $exception);
}

sub test_environment_override
{
    my ($self) = @_;

    local $CWD = tempdir(CLEANUP => 1);
    local %ENV = (); # stop real environment from interfering!

    xlog "Working in temporary directory $CWD";
    # artisinal handcrafted data
    # okay that's a lie... these are the real options and their defaults
    # as documented by cassandane.ini.example
    write_inifile({},
        'cassandane.rootdir' => '/var/tmp/cass',
        'cassandane.pwcheck' => 'alwaystrue',
        'cassandane.cleanup' => 'no',
        'cassandane.maxworkers' => '1',
        'cassandane.base_port' => '9100',
        'cassandane.suppress' => '',
        'valgrind.enabled' => 'no',
        'valgrind.binary' => '/usr/bin/valgrind',
        'valgrind.suppressions' => 'vg.supp',
        'valgrind.arguments' => '-q --tool=memcheck --leak-check=full --run-libc-freeres=no',
        'cyrus default.prefix' => '/usr/cyrus',
        'cyrus default.destdir' => '',
        'cyrus default.quota' => 'cyr_quota',
        'cyrus default.coresizelimit' => '100',
        'cyrus replica.prefix' => '/usr/cyrus',
        'cyrus replica.destdir' => '',
        'cyrus murder.prefix' => '/usr/cyrus',
        'cyrus murder.destdir' => '',
        'gdb.imapd' => 'yes',
        'gdb.sync_server' => 'yes',
        'gdb.lmtpd' => 'yes',
        'gdb.timsieved' => 'yes',
        'gdb.backupd' => 'yes',
        'config.sasl_mech_list' => 'PLAIN LOGIN',
        'config.debug_command' => '@prefix@/utils/gdbtramp %s %d',
        'caldavtalk.basedir' => '',
        'imaptest.basedir' => '',
        'imaptest.suppress' => 'listext subscribe',
        'caldavtester.basedir' => '',
        'caldavtester.suppress-caldav' => '',
        'caldavtester.suppress-carddav' => '',
        'jmaptestsuite.basedir' => '',
        'jmaptestsuite.suppress' => '',
    );

    my $cassini = new Cassandane::Cassini;

    # let's test the things we provide examples of
    $self->assert_str_equals(
        '/var/tmp/cass',
        $cassini->val('cassandane', 'rootdir', 'ignored')
    );

    $ENV{CASSINI_CASSANDANE_ROOTDIR} = 'overridden!';
    $self->assert_str_equals(
        'overridden!',
        $cassini->val('cassandane', 'rootdir', 'ignored')
    );

    $ENV{CASSINI_CASSANDANE_ROOTDIR} = '';
    $self->assert_str_equals(
        '',
        $cassini->val('cassandane', 'rootdir', 'ignored')
    );

    delete $ENV{CASSINI_CASSANDANE_ROOTDIR};
    $self->assert_str_equals(
        '/var/tmp/cass',
        $cassini->val('cassandane', 'rootdir', 'ignored')
    );

    # [cyrus default] is a section with a space in its name
    $self->assert_str_equals(
        '/usr/cyrus',
        $cassini->val('cyrus default', 'prefix', 'ignored')
    );

    $ENV{CASSINI_CYRUS_DEFAULT_PREFIX} = 'overridden!';
    $self->assert_str_equals(
        'overridden!',
        $cassini->val('cyrus default', 'prefix', 'ignored')
    );

    $ENV{CASSINI_CYRUS_DEFAULT_PREFIX} = '';
    $self->assert_str_equals(
        '',
        $cassini->val('cyrus default', 'prefix', 'ignored')
    );

    delete $ENV{CASSINI_CYRUS_DEFAULT_PREFIX};
    $self->assert_str_equals(
        '/usr/cyrus',
        $cassini->val('cyrus default', 'prefix', 'ignored')
    );

    # booleans should work too
    $self->assert_str_equals(
        'no',
        $cassini->val('cassandane', 'cleanup', 'ignored')
    );

    foreach my $x (qw( no NO false FALSE 0 off OFF )) {
        $ENV{CASSINI_CASSANDANE_CLEANUP} = $x;
        $self->assert_equals(0, $cassini->bool_val('cassandane', 'cleanup'));
    }

    foreach my $x (qw( yes YES true TRUE 1 on ON )) {
        $ENV{CASSINI_CASSANDANE_CLEANUP} = $x;
        $self->assert_equals(1, $cassini->bool_val('cassandane', 'cleanup'));
    }

    foreach my $x (q{}, 'invalid') {
        $ENV{CASSINI_CASSANDANE_CLEANUP} = $x;
        eval { $cassini->bool_val('cassandane', 'cleanup'); };
        my $exception = $@;
        $self->assert_matches(qr/Bad boolean/, $exception);
    }

    delete $ENV{CASSINI_CASSANDANE_CLEANUP};
    $self->assert_str_equals(
        'no',
        $cassini->val('cassandane', 'cleanup', 'ignored')
    );
}

sub test_override
{
    my ($self) = @_;

    local $CWD = tempdir(CLEANUP => 1);

    xlog "Working in temporary directory $CWD";
    # data thanks to hipsteripsum.me
    write_inifile({},
        'semiotics.skateboard' => 'flexitarian',
    );

    my $cassini = new Cassandane::Cassini;

    $self->assert_null($cassini->val('semiotics', 'typewriter'));
    $self->assert_str_equals('whatever',
                             $cassini->val('semiotics', 'typewriter', 'whatever'));
    $self->assert_str_equals('flexitarian',
                             $cassini->val('semiotics', 'skateboard', 'whatever'));
    $self->assert_str_equals('flexitarian',
                             $cassini->val('semiotics', 'skateboard'));
    $self->assert_null($cassini->val('twee', 'cliche'));

    $cassini->override('semiotics', 'typewriter', 'vegan');

    $self->assert_str_equals('vegan',
                             $cassini->val('semiotics', 'typewriter'));
    $self->assert_str_equals('vegan',
                             $cassini->val('semiotics', 'typewriter', 'whatever'));
    $self->assert_str_equals('flexitarian',
                             $cassini->val('semiotics', 'skateboard', 'whatever'));
    $self->assert_str_equals('flexitarian',
                             $cassini->val('semiotics', 'skateboard'));
    $self->assert_null($cassini->val('twee', 'cliche'));
}


1;

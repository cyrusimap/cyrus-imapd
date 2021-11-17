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

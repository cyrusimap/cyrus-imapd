#!/usr/bin/perl
#
#  Copyright (c) 2011-2024 FastMail Pty Ltd. All rights reserved.
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

package Cassandane::Cyrus::LibCyrus;
use strict;
use warnings;
use Cwd qw(abs_path);
use Data::Dumper;
use DateTime;
use File::Copy;
use File::Find;

use lib '.';
use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;
use Cassandane::Util::Slurp;

$Data::Dumper::Sortkeys = 1;

my $examples_dir = abs_path('../doc/examples/libcyrus');

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

sub run_pkgconfig
{
    my ($self, $package, @options) = @_;

    my $outfname = $self->{instance}->{basedir} . "/pkg-config.out";
    my $errfname = $self->{instance}->{basedir} . "/pkg-config.err";

    $self->{instance}->run_command({
            cyrus => 0,
            redirects => {
                stdout => $outfname,
                stderr => $errfname,
            },
        },
        '/usr/bin/pkg-config', @options, $package
    );

    my $val = slurp_file($outfname);
    chomp $val;

    return $val;
}

sub find_tests
{
    my ($dir) = @_;

    my @tests;

    find(
        sub {
            my $file = $File::Find::name;

            return unless $file =~ s/\.c$//;
            return unless -f "$file.c";
            $file =~ s/^$dir\/?//;
            push @tests, "test_$file";
        },
        $dir,
    );

    return @tests;
}

sub list_tests
{
    my @tests;

    @tests = find_tests($examples_dir);

    return @tests;
}

sub run_test
{
    my ($self) = @_;

    my $name = $self->name();
    $name =~ s/^test_//;

    my $lib;
    if ($name =~ m/(libcyrus(?:_\w+)?)/) {
        $lib = $1;
    }
    else {
        die "couldn't determine libcyrus dependency for test_$name";
    }

    copy("$examples_dir/$name.c", $self->{instance}->{basedir})
        or die "copy $examples_dir/$name.c: $!";

    my $cflags = $self->run_pkgconfig($lib, '--cflags');
    my $ldflags = $self->run_pkgconfig($lib, '--libs-only-L',
                                             '--libs-only-other');
    my $ldlibs = $self->run_pkgconfig($lib, '--libs-only-l');

    my $makeerr = $self->{instance}->{basedir} . "/make.err";

    eval {
        $self->{instance}->run_command({
                cyrus => 0,
                redirects => {
                    stderr => $makeerr,
                },
            },
            '/usr/bin/make',
            "CFLAGS=-Wall -Wextra -Werror -g -O0 $cflags",
            "LDFLAGS=$ldflags",
            "LDLIBS=$ldlibs",
            '-C', $self->{instance}->{basedir},  # n.b. not cyrus's -C
            $name,
        );
    };
    if ($@) {
        xlog "make failed:\n" . slurp_file($makeerr);
        die $@;
    }

    my $runerr = $self->{instance}->{basedir} . "/$name.err";

    my @cmd;
    my $cassini = Cassandane::Cassini->instance();
    if ($cassini->bool_val('valgrind', 'enabled')) {
        push @cmd, $self->{instance}->_valgrind_setup($name);
    }

    push @cmd, $self->{instance}->{basedir} . "/$name",
               '-C', $self->{instance}->_imapd_conf();

    eval {
        $self->{instance}->run_command({
                cyrus => 0,
                redirects => {
                    stderr => $runerr,
                },
            },
            @cmd,
        );
    };
    if ($@) {
        xlog "$name failed:\n" . slurp_file($runerr);
        die $@;
    }

}

1;

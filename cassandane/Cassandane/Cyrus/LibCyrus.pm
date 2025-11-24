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
use v5.010;
use Cwd qw(abs_path);
use Data::Dumper;
use DateTime;
use File::Copy;
use File::Find;

use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;
use Cassandane::Util::Slurp;

$Data::Dumper::Sortkeys = 1;

my $examples_dir = abs_path('../doc/examples/libcyrus');

sub new
{
    my $class = shift;

    my $self = $class->SUPER::new({}, @_);

    my $cassini = Cassandane::Cassini->instance();
    my $rootdir = $cassini->val('cassandane', 'rootdir', '/var/tmp/cass');
    my $findmnt = $cassini->val('paths', 'findmnt', '/usr/bin/findmnt');
    my $rootdir_mount_opts = qx{$findmnt -n -o OPTIONS --target $rootdir};

    $self->{rootdir_is_noexec} = (defined $rootdir_mount_opts
                                  && $rootdir_mount_opts =~ m/\bnoexec\b/);

    return $self;
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
    my ($self, %params) = @_;
    state $counter = 0;

    $counter++;

    my $outfname = $self->{instance}->{basedir} . "/pkg-config$counter.out";
    my $errfname = $self->{instance}->{basedir} . "/pkg-config$counter.err";

    my $cassini = Cassandane::Cassini->instance();
    my $pkgconfig = $cassini->val('paths', 'pkg-config', '/usr/bin/pkg-config');

    $self->{instance}->run_command({
            cyrus => 0,
            redirects => {
                stdout => $outfname,
                stderr => $errfname,
            },
        },
        $pkgconfig, @{$params{options}}, @{$params{packages}},
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

sub find_deps
{
    my ($source) = @_;
    my @deps;

    open my $fh, '<', $source or die "read $source: $!";
    while (<$fh>) {
        if (m/\bDEPS:([-\sA-Za-z_]+)/) {
            if (get_verbose() > 1) {
                xlog "found DEPS at line $.: $_";
            }
            push @deps, split(q{ }, $1);
        }
    }
    close $fh;

    if (get_verbose() > 1) {
        xlog "parsed dependencies: " . Dumper \@deps;
    }
    return @deps;
}

sub run_test
{
    my ($self) = @_;

    my $cassini = Cassandane::Cassini->instance();

    my $name = $self->name();
    $name =~ s/^test_//;

    my $orig_source = "$examples_dir/$name.c";
    copy($orig_source, $self->{instance}->{basedir})
        or die "copy $orig_source: $!";

    my @deps = find_deps($orig_source)
        or die "couldn't determine libcyrus dependencies for test_$name";

    my $cflags = $self->run_pkgconfig(packages => \@deps,
                                      options => [ '--cflags' ]);
    my $ldflags = $self->run_pkgconfig(packages => \@deps,
                                       options => [ '--libs-only-L',
                                                    '--libs-only-other' ]);
    my $ldlibs = $self->run_pkgconfig(packages => \@deps,
                                      options => [ '--libs-only-l' ]);

    my $makeerr = $self->{instance}->{basedir} . "/make.err";
    my $make = $cassini->val('paths', 'make', '/usr/bin/make');

    my $warnopts = '-Wall -Wextra -Werror';
    my $otheropts = '-g -O0 -fdiagnostics-color=always';

    eval {
        $self->{instance}->run_command({
                cyrus => 0,
                redirects => {
                    stderr => $makeerr,
                },
            },
            $make,
            "CFLAGS=$warnopts $otheropts $cflags",
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

    my $exe = $self->{instance}->{basedir} . "/$name";

    if ($self->{rootdir_is_noexec} || ! -x $exe) {
        xlog $self, "$exe is not executable, won't try to run it";
    }
    else {
        my $runerr = $self->{instance}->{basedir} . "/$name.err";
        my @cmd;

        if ($cassini->bool_val('valgrind', 'enabled')) {
            push @cmd, $self->{instance}->_valgrind_setup($name);
        }

        push @cmd, $exe, '-C', $self->{instance}->_imapd_conf();

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
}

1;

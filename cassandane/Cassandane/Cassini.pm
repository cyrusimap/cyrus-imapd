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

# Cassini is an in-memory copy of the Cassandane .INI file.
# It has nothing to do with the astronomer or spacecraft.
package Cassandane::Cassini;
use strict;
use warnings;
use Cwd qw(abs_path);
use Config::IniFiles;

use lib '.';
use Cassandane::Util::Log;

my $instance;

sub homedir {
    my ($uid) = @_;

    return undef if not $uid;

    my @pw = getpwuid($uid);
    return $pw[7]; # dir field
}

sub new
{
    my ($class, %params) = @_;

    my $filename;

    if (defined $params{filename}) {
        # explicitly requested filename: just use it
        $filename = $params{filename};
    }
    else {
        # check some likely places, in order
        foreach my $dir (q{.},
                         q{..},
                         homedir($>),
                         homedir($<),
                         homedir($ENV{SUDO_UID})
        ) {
            next if not $dir;

            # might be called "cassandane.ini"
            if (-e "$dir/cassandane.ini") {
                $filename = "$dir/cassandane.ini";
                last;
            }

            # might be called ".cassandane.ini"
            if (-e "$dir/.cassandane.ini") {
                $filename = "$dir/.cassandane.ini";
                last;
            }
        }
    }

    die "couldn't find a cassandane.ini file" if not $filename;
    $filename = abs_path($filename);

    my $inifile = new Config::IniFiles();
    if ( -f $filename)
    {
        xlog "Reading $filename" if get_verbose;
        $inifile->SetFileName($filename);
        if (!$inifile->ReadConfig())
        {
            # Config::IniFiles seems to include the filename in
            # error messages, so we don't.  However it tends to
            # emit multiline-messages which confuses our logs.
            set_verbose(1);
            map { s/[\n\r]\s*/ /g; xlog $_; } @Config::IniFiles::errors;
            die "Failed reading $filename";
        }
    }

    my $self = {
        filename => $filename,
        inifile => $inifile
    };

    bless $self, $class;
    $instance = $self
        unless defined $instance;
    return $self;
}

sub instance
{
    my ($class) = @_;

    if (!defined $instance)
    {
        $instance = Cassandane::Cassini->new();
        die "Singleton broken in Cassini ctor!"
            unless defined $instance;
    }
    return $instance;
}

sub val
{
    # Args are: section, name, default
    # see the Config::IniFiles documentation for ->val()
    my ($self, @args) = @_;
    return $self->{inifile}->val(@args);
}

sub bool_val
{
    # Args are: section, name, default
    # returns a boolean 1 or 0
    my ($self, $section, $parameter, $default) = @_;
    $default = 'no' if !defined $default;
    my $v = $self->val($section, $parameter, $default);

    return 1 if ($v =~ m/^yes$/i);
    return 1 if ($v =~ m/^true$/i);
    return 1 if ($v =~ m/^on$/i);
    return 1 if ($v =~ m/^1$/);

    return 0 if ($v =~ m/^no$/i);
    return 0 if ($v =~ m/^false$/i);
    return 0 if ($v =~ m/^off$/i);
    return 0 if ($v =~ m/^0$/);

    die "Bad boolean \"$v\"";
}

sub override
{
    my ($self, $section, $parameter, $value) = @_;
    my $ii = $self->{inifile};

    if (defined $ii->val($section, $parameter))
    {
        $ii->setval($section, $parameter, $value);
    }
    else
    {
        $ii->newval($section, $parameter, $value);
    }
}

sub get_section
{
    my ($self, $section) = @_;
    my $inifile = $self->{inifile};
    my %params;
    if ($inifile->SectionExists($section)) {
        map { $params{$_} = $inifile->val($section, $_) } $inifile->Parameters($section);
    }
    return \%params;
}

1;

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
# 	Opera Software Australia Pty. Ltd.
# 	Level 50, 120 Collins St
# 	Melbourne 3000
# 	Victoria
# 	Australia
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

# Cassini is an in-memory copy of the Cassandane .INI file.
# It has nothing to do with the astronomer or spacecraft.
package Cassandane::Cassini;
use strict;
use warnings;
use Config::IniFiles;
use Cassandane::Util::Log;

my $instance;

sub new
{
    my ($class, %params) = @_;

    my $filename = 'cassandane.ini';
    $filename = $params{filename}
	if defined $params{filename};

    my $inifile = new Config::IniFiles();
    if ( -f $filename)
    {
	xlog "Reading $filename";
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
	Cassandane::Cassini->new();
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

sub apply_config
{
    my ($self, $config, $member) = @_;
    my $inifile = $self->{inifile};

    my $section = defined($member) ? "config $member" : 'config';
    if ($inifile->SectionExists($section)) {
	$config->set(map { $_ => $inifile->val($section, $_) } $inifile->Parameters($section));
    }
    # XXX - member parent hierarchy too ?

    return $config;
}

1;

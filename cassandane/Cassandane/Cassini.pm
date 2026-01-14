# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

# Cassini is an in-memory copy of the Cassandane .INI file.
# It has nothing to do with the astronomer or spacecraft.
package Cassandane::Cassini;
use strict;
use warnings;
use Cwd qw(abs_path);
use Config::IniFiles;

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
    elsif (defined $ENV{CASSINI_FILENAME}) {
        xlog "Using ini file from environment:"
             . " filename=\"$ENV{CASSINI_FILENAME}\"";
        $filename = $ENV{CASSINI_FILENAME};
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

    $filename = abs_path($filename) if $filename;

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

    if ((not $filename or not -f $filename)
        and not $self->bool_val('cassandane', 'allow_noinifile', 'no'))
    {
        die "couldn't find a cassandane.ini file";
    }

    # pre-validate cassandane.core_pattern early -- if the configured
    # pattern is invalid the qr// will crash out
    my $core_pattern = $self->val('cassandane', 'core_pattern');
    $core_pattern = qr{$core_pattern} if $core_pattern;

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
    my ($self, $section, $name, $default) = @_;

    # Allow overrides from specially-named environment variables.
    #
    # Examples:
    #
    # to override the "rootdir" option from the "[cassandane]" section,
    # set: CASSINI_CASSANDANE_ROOTDIR=/some/different/value
    #
    # to override the "prefix" option from the "[cyrus default]" section,
    # set: CASSINI_CYRUS_DEFAULT_PREFIX=/some/different/value
    #
    my $envname = "\UCASSINI $section $name\E";
    $envname =~ s{[^A-Z0-9]+}{_}g;
    if (defined $ENV{$envname}) {
        xlog "Using configuration from environment:"
             . " \$$envname=\"$ENV{$envname}\"";
        return $ENV{$envname};
    }

    # see the Config::IniFiles documentation for ->val()
    return $self->{inifile}->val($section, $name, $default);
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
    my $filename = $self->{filename} || 'inifile';
    if ($inifile->SectionExists($section)) {
        foreach my $key ($inifile->Parameters($section)) {
            # n.b. if there are multiple values for this section.key,
            # val() in scalar context returns them joined by $/, which is
            # nasty.  So call it in list context instead, even though we
            # don't support multiple values, and use the last one...
            my @values = $inifile->val($section, $key);

            if (scalar @values > 1) {
                # ... and whinge if there were multiple!
                xlog "$filename: multiple values for $section.$key,"
                     . " using last ($values[-1])";
                if (get_verbose()) {
                    xlog "$filename: $section.$key=<$_>" for @values;
                }
            }

            $params{$key} = $values[-1];
        }
    }
    return \%params;
}

sub get_core_pattern
{
    my ($self) = @_;

    my $core_pattern = $self->val('cassandane', 'core_pattern',
                                  '^core.*?(?:\.(\d+))?$');
    return qr{$core_pattern};
}

1;

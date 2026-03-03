# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Cyrus::Info;
use strict;
use warnings;
use Cwd qw(realpath);
use Data::Dumper;
use Date::Format qw(time2str);
use Time::HiRes qw(usleep);

use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;
use Cassandane::Instance;

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

Cassandane::Cyrus::TestCase::magic(ConfigJunk => sub {
    shift->config_set(trust_fund => 'street art');
});

sub _set_and_get_fields {
    my ($self, $set_fields, $get_fields, $cmd) = @_;

    $self->config_set(%$set_fields);

    $self->_start_instances();

    $cmd //= 'conf';

    my %cyr_info_conf;
    foreach my $line ($self->{instance}->run_cyr_info($cmd)) {
        chomp $line;
        my ($name, $value) = split /\s*:\s*/, $line, 2;
        if (Cassandane::Config::is_bitfield($name)) {
            my @values = split /\s+/, $value;
            $cyr_info_conf{$name} = join q{ }, sort @values;
        }
        else {
            $cyr_info_conf{$name} = $value;
        }
    }

    for my $field (keys %$get_fields) {
        my $expect = join q{ }, sort split /\s+/, $get_fields->{$field};
        $self->assert_str_equals($expect, $cyr_info_conf{$field});
    }
}

use Cassandane::Tiny::Loader;

1;

# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.
package Cyrus::IMAPOptions;
use Moo;

use Cyrus::IMAPOptions::Option;
use Types::Standard qw(Bool HashRef InstanceOf);

has options => (
    isa => HashRef[InstanceOf['Cyrus::IMAPOptions::Option']],
    is => 'ro',
);
has forbid_unreleased => (
    isa => Bool,
    is => 'ro',
    default => '0',
);

around BUILDARGS => sub
{
    my ($orig, $class, @args) = @_;

    my $args = $class->$orig(@args);

    if (my $path = delete $args->{from_path}) {
        _from_path($args, $path);
    }

    return $args;
};

sub _from_path
{
    my ($args, $path) = @_;

    opendir my $dh, $path or die "$path: $!";
    while (readdir $dh) {
        next if m/^\./;

        my $opt_name = $_;
        eval {
            $args->{options}->{$opt_name} = Cyrus::IMAPOptions::Option->new(
                from_file => "$path/$opt_name"
            );
        };
        if ($@) {
            die "$opt_name: $@";
        }
    }
    closedir $dh;
}

sub BUILD
{
    my ($self, $args) = @_;

    while (my ($opt_name, $option) = each %{$self->options}) {
        if ($option->has_replaced_by) {
            # replaced-by option must exist
            my $replaced_by = $option->replaced_by;

            die "$opt_name: replaced_by '$replaced_by' does not exist"
                if not exists $self->options->{$replaced_by};

            die "$opt_name: replaced by '$replaced_by' which is also deprecated"
                if $self->options->{$replaced_by}->has_deprecated_since;
        }
    }
}

sub check_unreleased
{
    my ($self, $cmd) = @_;

    my $warned_unreleased;

    foreach my $option (values %{$self->options}) {
        if (!$warned_unreleased && $option->is_unreleased) {
            # This warning is to remind the release manager to replace
            # "UNRELEASED" strings in lib/imapoptions with the version
            # number that is about to be released.
            # If you're not building a release, ignore it. :)
            my $prefix;

            if ($self->forbid_unreleased) {
                $prefix = -t STDERR ? "\033[31;1merror:\033[0m" : 'error:';
            }
            else {
                $prefix = -t STDERR ? "\033[33;1mwarning:\033[0m" : 'warning:',
            }

            my $msg = "$cmd: $prefix build contains UNRELEASED config options\n";

            if ($self->forbid_unreleased) {
                die $msg;
            }
            else {
                print STDERR $msg;
                $warned_unreleased = 1;
            }
        }
    }
}

sub iterate
{
    my ($self, $callback, @rock) = @_;

    foreach my $key (sort keys %{$self->options}) {
        $callback->($key, $self->options->{$key}, @rock);
    }
}

1;

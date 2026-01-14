# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Cyrus::IMAPLimits;
use strict;
use warnings;
use Data::Dumper;

use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;

sub email
{
    my $email = <<~EOF;
    Subject: foo
    Date: bar
    From: <foobar\@example.com>

    Body
    EOF

    $email =~ s/\r?\n/\r\n/gs;

    return $email;
}

sub toobig_email
{
    my ($self) = @_;

    my $email = $self->email;
    return $email . 'X' x 100;
}

# Check that we got an untagged BYE [TOOBIG] response
sub assert_bye_toobig
{
    my ($self, $store) = @_;

    $store = $self->{store} if (!defined $store);

    # We want to override Mail::IMAPTalk's builtin handling of the BYE
    # untagged response, as it will 'die' immediately without parsing
    # the remainder of the line and especially without picking out the
    # [TOOBIG] response code that we want to see.
    my $got_toobig = 0;
    my $handlers =
    {
        bye => sub
        {
            my (undef, $resp) = @_;
            $got_toobig = 1 if (uc($resp->[0]) eq '[TOOBIG]');
        }
    };

    $store->idle_response($handlers, 1);
    $self->assert_num_equals(1, $got_toobig);
}

# Send a command and expect an untagged BYE [TOOBIG] response
sub assert_cmd_bye_toobig
{
    my $self = shift;
    my $cmd = shift;

    my $talk = $self->{store}->get_client();
    $talk->enable('qresync'); # IMAPTalk requires lower-case
    $talk->select('INBOX');

    $talk->_send_cmd($cmd, @_);
    $self->assert_bye_toobig();
}

# Check that we got a tagged NO [TOOBIG] response
sub assert_no_toobig
{
    my ($self, $talk) = @_;

    my $got_toobig = 0;
    my $handlers =
    {
        'no' => sub
        {
            my (undef, $resp) = @_;
            $got_toobig = 1 if (uc($resp->[0]) eq '[TOOBIG]');
        }
    };

    eval {
        $talk->_parse_response($handlers);
    };

    $self->assert_num_equals(1, $got_toobig);
}

# Send a command and expect a tagged NO [TOOBIG] response
sub assert_cmd_no_toobig
{
    my $self = shift;
    my $talk = shift;
    my $cmd = shift;

    $talk->_send_cmd($cmd, @_);
    $self->assert_no_toobig($talk);
}

sub new
{
    my $class = shift;

    my $config = Cassandane::Config->default()->clone();
    $config->set(maxword => 25);
    $config->set(maxquoted => 25);
    $config->set(maxliteral => 25);
    $config->set(literalminus => 1);
    $config->set(maxargssize => 45);
    $config->set(maxmessagesize => 100);
    $config->set(event_groups => "message mailbox applepushservice");
    $config->set(aps_topic => "mail");

    return $class->SUPER::new({
        adminstore => 1,
        config => $config,
        services => ['imap'],
    }, @_);
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

use Cassandane::Tiny::Loader;

1;

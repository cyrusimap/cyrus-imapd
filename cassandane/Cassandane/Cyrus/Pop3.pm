# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Cyrus::Pop3;
use strict;
use warnings;
use DateTime;
use Net::POP3;

use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;

Cassandane::Cyrus::TestCase::magic(PopSubFolders => sub {
    shift->config_set(popsubfolders => 1);
});

Cassandane::Cyrus::TestCase::magic(PopUseImapFlags => sub {
    shift->config_set('popuseimapflags' => 'yes');
});

sub new
{
    my ($class, @args) = @_;
    return $class->SUPER::new({
        # We need IMAP to be able to create the mailbox for POP
        services => ['imap', 'pop3'],
    }, @args);
}

sub set_up
{
    my ($self) = @_;
    $self->SUPER::set_up();

    my $svc = $self->{instance}->get_service('pop3');
    if (defined $svc)
    {
        $self->{pop_store} = $svc->create_store();
    }
}

sub tear_down
{
    my ($self) = @_;

    if (defined $self->{pop_store})
    {
        $self->{pop_store}->disconnect();
        $self->{pop_store} = undef;
    }

    $self->SUPER::tear_down();
}

sub test_top_args
{
    my ($self) = @_;

    xlog $self, "Testing whether the TOP command checks its arguments [Bug 3641]";
    # Note, the POP client checks its arguments before sending
    # them so we have to reach around it to do bad things.

    xlog $self, "Ensure a message exists, before logging in to POP";
    my %exp;
    $exp{A} = $self->make_message('Message A');

    my $client = $self->{pop_store}->get_client();

    xlog $self, "TOP with no arguments should return an error";
    my $r = $client->command('TOP')->response();
    $self->assert_equals($r, Net::Cmd::CMD_ERROR);
    $self->assert_equals($client->code(), 500);
    $self->assert_matches(qr/Missing argument/, $client->message());

    xlog $self, "TOP with 1 argument should return an error";
    $r = $client->command('TOP', 1)->response();
    $self->assert_equals($r, Net::Cmd::CMD_ERROR);
    $self->assert_equals($client->code(), 500);
    $self->assert_matches(qr/Missing argument/, $client->message());

    xlog $self, "TOP with 2 correct arguments should actually work";
    $r = $client->command('TOP', 1, 2)->response();
    $self->assert_equals($r, Net::Cmd::CMD_OK);
    $self->assert_equals($client->code(), 200);
    my $lines = $client->read_until_dot();
    my %actual;
    $actual{'Message A'} = Cassandane::Message->new(lines => $lines,
                                                    attrs => { uid => 1 });
    $self->check_messages(\%exp, actual => \%actual);

    xlog $self, "TOP with 2 arguments, first one not a number, should return an error";
    $r = $client->command('TOP', '1xyz', 2)->response();
    $self->assert_equals($r, Net::Cmd::CMD_ERROR);
    $self->assert_equals($client->code(), 500);

    xlog $self, "TOP with 2 arguments, second one not a number, should return an error";
    $r = $client->command('TOP', 1, '2xyz')->response();
    $self->assert_equals($r, Net::Cmd::CMD_ERROR);
    $self->assert_equals($client->code(), 500);

    xlog $self, "TOP with 3 arguments should return an error";
    $r = $client->command('TOP', 1, 2, 3)->response();
    $self->assert_equals($r, Net::Cmd::CMD_ERROR);
    $self->assert_equals($client->code(), 500);
    $self->assert_matches(qr/Unexpected extra argument/, $client->message());
}

sub test_subfolder_login
    :PopSubFolders :NoAltNameSpace
{
    my ($self) = @_;

    xlog $self, "Testing whether + address login gets subfolder";

    my $imapclient = $self->{store}->get_client();

    xlog $self, "Ensure a messages exist";
    my %exp;
    $exp{A} = $self->make_message('Message A');

    $imapclient->create('INBOX.sub');
    $self->{store}->set_folder('INBOX.sub');
    # different mailbox, so reset generator's expected uid sequence
    $self->{gen}->set_next_uid(1);

    my %subexp;
    $subexp{B} = $self->make_message('Message B');

    my $popclient = $self->{pop_store}->get_client();

    xlog $self, "Test regular TOP gets the right message";
    my $r = $popclient->command('TOP', 1, 2)->response();
    $self->assert_equals($r, Net::Cmd::CMD_OK);
    $self->assert_equals($popclient->code(), 200);
    my $lines = $popclient->read_until_dot();
    my %actual;
    $actual{'Message A'} = Cassandane::Message->new(lines => $lines,
                                                    attrs => { uid => 1 });
    $self->check_messages(\%exp, actual => \%actual);

    my $svc = $self->{instance}->get_service('pop3');
    my $substore = $svc->create_store(folder => 'INBOX.sub');

    # create a new client
    my $subclient = $substore->get_client();


    xlog $self, "Test subfolder TOP gets the right message";
    my $subr = $subclient->command('TOP', 1, 2)->response();
    $self->assert_equals($subr, Net::Cmd::CMD_OK);
    $self->assert_equals($subclient->code(), 200);
    my $sublines = $subclient->read_until_dot();
    my %subactual;
    $subactual{'Message B'} = Cassandane::Message->new(lines => $sublines,
                                                       attrs => { uid => 1 });
    $self->check_messages(\%subexp, actual => \%subactual);
}

sub test_seen
    :PopUseImapFlags
{
    my ($self) = @_;

    xlog $self, "Testing whether the RETR command marks messages as sent";

    xlog $self, "Ensure a messages exist, before logging in to POP";
    my %exp;
    $exp{A} = $self->make_message('Message A');
    $exp{B} = $self->make_message('Message B');
    $exp{C} = $self->make_message('Message C');

    my $talk = $self->{store}->get_client();
    my $client = $self->{pop_store}->get_client();

    my $prestat = $talk->status('INBOX', '(highestmodseq unseen messages)');
    $self->assert_num_equals(3, $prestat->{unseen});
    $self->assert_num_equals(3, $prestat->{messages});

    my $r = $client->command('RETR', 2)->response();
    $self->assert_equals($r, Net::Cmd::CMD_OK);
    $self->assert_equals($client->code(), 200);
    my $lines = $client->read_until_dot();
    $client->command('QUIT');
    $r = $client->response();
    $self->assert_equals($r, Net::Cmd::CMD_OK);

    my $poststat = $talk->status('INBOX', '(highestmodseq unseen messages)');
    $self->assert_num_equals(2, $poststat->{unseen});
    $self->assert_num_equals(3, $poststat->{messages});
    $self->assert_num_gt($prestat->{highestmodseq}, $poststat->{highestmodseq});
}

sub test_dele
{
    my ($self) = @_;

    xlog $self, "Testing whether the DELE command removes messages";

    xlog $self, "Ensure a messages exist, before logging in to POP";
    my %exp;
    $exp{A} = $self->make_message('Message A');
    $exp{B} = $self->make_message('Message B');
    $exp{C} = $self->make_message('Message C');

    my $talk = $self->{store}->get_client();
    my $client = $self->{pop_store}->get_client();

    my $prestat = $talk->status('INBOX', '(highestmodseq unseen messages)');
    $self->assert_num_equals(3, $prestat->{unseen});
    $self->assert_num_equals(3, $prestat->{messages});

    my $r = $client->command('DELE', 2)->response();
    $self->assert_equals($r, Net::Cmd::CMD_OK);
    $client->command('QUIT');
    $r = $client->response();
    $self->assert_equals($r, Net::Cmd::CMD_OK);

    my $poststat = $talk->status('INBOX', '(highestmodseq unseen messages)');
    $self->assert_num_equals(2, $poststat->{unseen});
    $self->assert_num_equals(2, $poststat->{messages});
    $self->assert_num_gt($prestat->{highestmodseq}, $poststat->{highestmodseq});
}

1;


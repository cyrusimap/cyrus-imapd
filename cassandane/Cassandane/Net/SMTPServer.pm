package Cassandane::Net::SMTPServer;

use strict;
use warnings;
use Data::Dumper;
use Net::Server::PreForkSimple;

use lib ".";
use Net::XmtpServer;
use Cassandane::Util::Log;
use JSON;

use base qw(Net::XmtpServer Net::Server::PreForkSimple);

sub new {
    my $class = shift;
    return $class->SUPER::new(@_);
}

sub override {
    my $Self = shift;
    my $stage = shift;
    if ($Self->{server}{control_file} and -e $Self->{server}{control_file}) {
        local $/ = undef;
        open(FH, "<$Self->{server}{control_file}");
        my $data = decode_json(<FH>);
        close(FH);
        if ($data->{$stage}) {
            $Self->send_client_resp(@{$data->{$stage}});
            return 1;
        }
    }
    return 0;
}

sub mylog {
    my $Self = shift;
    if ($Self->{server}->{cass_verbose}) {
        xlog @_;
    }
}

sub new_connection {
    my ($Self) = @_;
    $Self->mylog("SMTP: new connection");
    return if $Self->override('new');
    $Self->send_client_resp(220, "localhost ESMTP");
}

sub helo {
    my ($Self) = @_;
    $Self->mylog("SMTP: HELO");
    return if $Self->override('helo');
    $Self->send_client_resp(250, "localhost",
                            "AUTH", "DSN", "SIZE 10000", "ENHANCEDSTATUSCODES");
}

sub mail_from {
    my ($Self, $From, @FromExtra) = @_;
    $Self->mylog("SMTP: MAIL FROM $From @FromExtra");
    return if $Self->override('from');
    # don't just quietly accept garbage!
    if ($From =~ m/[<>]/ || grep { m/[<>]/ } @FromExtra) {
        $Self->send_client_resp(501, "Junk in parameters");
    }
    $Self->send_client_resp(250, "ok");
}

sub rcpt_to {
    my ($Self, $To, @ToExtra) = @_;
    $Self->mylog("SMTP: RCPT TO $To @ToExtra");
    return if $Self->override('to');

    $Self->{_rcpt_to_count}++;
    if ($Self->{_rcpt_to_count} > 10) {
        $Self->send_client_resp(550, "5.5.3 Too many recipients");
    } elsif ($To =~ /\@fail\.to\.deliver$/i) {
        $Self->send_client_resp(553, "5.1.1 Bad destination mailbox address");
        $Self->mylog("SMTP: 553 5.1.1");
    } else {
        $Self->send_client_resp(250, "ok");
    }
}

sub begin_data {
    my ($Self) = @_;
    $Self->mylog("SMTP: BEGIN DATA");
    return if $Self->override('begin_data');
    $Self->send_client_resp(354, "ok");
    return 1;
}

sub end_data {
    my ($Self) = @_;
    $Self->mylog("SMTP: END DATA");
    return if $Self->override('end_data');
    $Self->send_client_resp(250, "ok");
    return 0;
}

sub rset {
    my ($Self) = @_;
    $Self->mylog("SMTP: RSET");
    return if $Self->override('rset');
    $Self->send_client_resp(250, "ok");
    return 0;
}

sub quit {
    my ($Self) = @_;
    $Self->mylog("SMTP: QUIT");
    return if $Self->override('quit');
    $Self->send_client_resp(221, "bye!");
}

1;

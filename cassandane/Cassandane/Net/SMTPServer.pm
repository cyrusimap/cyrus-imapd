package Cassandane::Net::SMTPServer;

use Data::Dumper;
use Net::Server::PreForkSimple;

use lib ".";
use Net::XmtpServer;
use Cassandane::Util::Log;

use base qw(Net::XmtpServer Net::Server::PreForkSimple);

sub new {
    my $class = shift;
    return $class->SUPER::new(@_);
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
    $Self->send_client_resp(220, "localhost ESMTP");
}

sub helo {
    my ($Self) = @_;
    $Self->mylog("SMTP: HELO");
    $Self->send_client_resp(250, "localhost", "AUTH", "DSN");
}

sub mail_from {
    my ($Self, $From, $FromExtra) = @_;
    $Self->mylog("SMTP: MAIL FROM $From $FromExtra");
    $Self->send_client_resp(250, "ok");
}

sub rcpt_to {
    my ($Self, $To, $ToExtra) = @_;
    $Self->mylog("SMTP: RCPT TO $To $ToExtra");
    $Self->send_client_resp(250, "ok");
}

sub begin_data {
    my ($Self) = @_;
    $Self->mylog("SMTP: BEGIN DATA");
    $Self->send_client_resp(354, "ok");
    return 1;
}

sub end_data {
    my ($Self) = @_;
    $Self->mylog("SMTP: END DATA");
    $Self->send_client_resp(250, "ok");
    return 0;
}

sub quit {
    my ($Self) = @_;
    $Self->mylog("SMTP: QUIT");
    $Self->send_client_resp(221, "bye!");
}

1;

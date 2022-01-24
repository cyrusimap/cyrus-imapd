package Cassandane::Util::TestURL;

use Plack::Loader;
use Plack::Request;
use Plack::Response;

use Test::TCP;
use Carp qw(croak);

use lib '.';
use Cassandane::PortManager;

sub new
{
    my ($pkg, $args) = @_;

    my %attrs;

    for my $required (qw(app)) {
        $attrs{$required} = delete $args->{$required};
        unless ($attrs{$required}) {
            croak("'$required' required for Cassandane::Test::URL->new");
        }
    }

    my $self = bless {}, __PACKAGE__;

    $self->update($attrs{app});

    return $self;
}

sub url
{
    my ($self) = @_;

    if ($self->was_unregistered) {
        croak("Cannot call ->url after ->unregister has been called!");
    }

    $self->{url};
}

sub _guard { shift->{_guard} }

sub unregister
{
    my ($self) = @_;

    delete $self->{_guard};
    $self->{was_unregistered} = 1;
}

sub was_unregistered { shift->{was_unregistered} }

sub update
{
    my ($self, $content_or_app) = @_;

    unless (ref $content_or_app) {
        my $content = $content_or_app;
        # Plain ol' successful response
        $content_or_app = sub {
            return [
                200,
                [],
                [ $content ],
            ];
        };
    }

    {
      package Shutdown::Guard;

      use POSIX qw(_exit);

      sub new { bless {}, __PACKAGE__ }

      sub DESTROY {
          _exit(0);
      }
    }

    my $app = sub {
        # No matter how we we leave this block, the $guard will go out
        # of scope while in the run phase, which means it can exit Perl
        # before any END block or object destructors are run.
        my $guard = Shutdown::Guard->new;

        # Test::TCP uses Term to stop us. We could just let that
        # terminate Perl cleanly, but in case something has put in a
        # signal handle or something else, let's just call exit here.
        # This will also cause our $guard above to go out of scope
        # in a timely manner during the run phase.
        local $SIG{TERM} = sub { exit; };

        my $sock_or_port = shift;
        my $server = Plack::Loader->auto(
            host => '0.0.0.0',
            port => $sock_or_port,
        );

        $server->run($content_or_app);
    };

    unless ($self->_guard) {
        if ($self->was_unregistered) {
            # We've already been unregistered. It's no longer safe to call
            # update because our port may have been reused by someone else
            # and our url is no longer useable
            croak("Cannot call ->update after ->unregister has been called!");
        }

        my $host = "127.0.0.1";

        my $guard = Test::TCP->new(
            host => $host,
            code => $app,
            port => Cassandane::PortManager::alloc(),
        );

        my $port = $guard->port;

        $self->{url} = "http://$host:$port/";
        $self->{_guard} = $guard;
    } else {
        $self->_guard->{code} = $app;

        $self->_guard->stop;
        $self->_guard->start;
    }

    return;
}

1;

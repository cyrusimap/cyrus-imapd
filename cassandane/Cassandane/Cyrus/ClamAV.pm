# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::Cyrus::ClamAV;
use strict;
use warnings;
use Cwd qw(abs_path);
use Data::Dumper;

use base qw(Cassandane::Cyrus::TestCase);
use Cassandane::Util::Log;
use Cassandane::Util::Slurp;
use Cassandane::Instance;

$Data::Dumper::Sortkeys = 1;

sub eicar_attached
{
    return (
        mime_type => "multipart/mixed",
        mime_boundary => "boundary",
        body => ""
            . "--boundary\r\n"
            . "Content-Type: text/plain\r\n"
            . "\r\n"
            . "body"
            . "\r\n"
            . "--boundary\r\n"
            . "Content-Disposition: attachment; filename=eicar.txt;\r\n"
            . "Content-Type: text/plain\r\n"
            . "\r\n"
            # This is the EICAR AV test file:
            # http://www.eicar.org/83-0-Anti-Malware-Testfile.html
            . 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
            . "\r\n"
            . "--boundary\r\n",
    );
}

sub custom_header
{
    return (
        'extra_headers' => [
            [ 'x-delete-me' => 'please' ],
        ],
    );
}

sub new
{
    my $class = shift;

    my $self = $class->SUPER::new({ adminstore => 1 }, @_);

    $self->needs('dependency', 'clamav');
    return $self;
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

# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cyrus::SIEVE::managesieve;

use strict;
use Carp;
use vars qw($VERSION @ISA @EXPORT @EXPORT_OK $AUTOLOAD);

require Exporter;
require DynaLoader;

@ISA = qw(Exporter DynaLoader);
# Items to export into callers namespace by default. Note: do not export
# names by default without a very good reason. Use EXPORT_OK instead.
# Do not simply export all your public functions/methods/constants.
@EXPORT = qw(
  sieve_get_handle
  sieve_get_error
  sieve_get_global_error
  sieve_put_file
  sieve_put_file_withdest
  sieve_put
  sieve_delete
  sieve_list
  sieve_activate
  sieve_get
  sieve_logout
);
$VERSION = '0.01';

sub AUTOLOAD {
    # This AUTOLOAD is used to 'autoload' constants from the constant()
    # XS function.  If a constant is not found then control is passed
    # to the AUTOLOAD in AutoLoader.

    my $constname;
    ($constname = $AUTOLOAD) =~ s/.*:://;
    my $val = constant($constname, @_ ? $_[0] : 0);
    if ($! != 0) {
        if ($! =~ /Invalid/) {
            $AutoLoader::AUTOLOAD = $AUTOLOAD;
            goto &AutoLoader::AUTOLOAD;
        }
        else {
                croak "Your vendor has not defined Cyrus::SIEVE::managesieve macro $constname";
        }
    }
    eval "sub $AUTOLOAD { $val }";
    goto &$AUTOLOAD;
}

bootstrap Cyrus::SIEVE::managesieve $VERSION;

# Preloaded methods go here.

# Autoload methods go after =cut, and are processed by the autosplit program.

1;
__END__
# Below is the stub of documentation for your module. You better edit it!

=head1 NAME

Cyrus::SIEVE::managesieve - Perl client for the SIEVE protocol

=head1 SYNOPSIS

  use Cyrus::SIEVE::managesieve;

=head1 DESCRIPTION

This is a Perl module which provides a client for the SIEVE protocol.
It supports SASL authentication and communication encryption, using the
Cyrus SASL infrastructure.

It provides the following functions.

=over

=item sieve_get_handle($servername, &username_cb, &authname_cb, &password_cb, &realm_cb)

Creates and returns a new Sieve object which can be used for communicating
with the SIEVE server.  The server is connected to and a login sequence
is performed, using some combination of the given callbacks to fetch
from the calling program any data needed for authentication.

The I<servername> may take any of the forms

=over

=item I<hostname>

=item I<hostname>:I<port>

=item I<ipv4address>

=item I<ipv4address>:I<port>

=item [I<ipv6address>]

=item [I<ipv6address>]:I<port>

=back

If not explicitly specified in the I<servername>, the port defaults to
the port named "sieve" in the client machine's service database (for
example the C</etc/services> files), or 4190.

All the callbacks are called with the following arguments

$string = callback($which, $prompt);

where I<which> is one of the strings C<"username">, C<"authname">,
C<"getpass">, or C<"realm"> respectively, and I<prompt> is a
human-readable English language prompt string for the user's benefit.
Each callback should return a string containing the required
information.

The function will return I<undef> on error, use
I<sieve_get_global_error> to get a description of the error.


=item sieve_get_error($sieveobj)

Returns a human-readable English language string describing the last
error encountered on the object I<$sieveobj>.

=item sieve_get_global_error()

Returns a human-readable English language string describing the last
error encountered while creating a Sieve object.

=item sieve_logout($sieveobj)

Log out from the SIEVE server.  The I<$sieveobj> will become unusable.

=item sieve_put_file($sieveobj, $filename)

Installs a SIEVE script contained in a local file named by I<$filename>
to the server.  The name of the script on the server will be the
basename of I<$filename>.  Returns zero on success and non-zero on
failure.

=item sieve_put_file_withdest($sieveobj, $filename, $destname)

Like I<sieve_put_file> but also specifies the name of the file on the
server.  Any directory part of I<$destname> is ignored.

=item sieve_put($sieveobj obj, $name, $data)

Installs a SIEVE script contained in the scalar $data to the server,
with the script name I<$name>.  Returns zero on success and non-zero on
failure.

=item sieve_delete($sieveobj obj, $name)

Removes a SIEVE script from the server.  Returns zero on success and
non-zero on failure.

=item sieve_list($sieveobj obj, &callback)

Lists existing SIEVE scripts on the server.  The I<&callback> returns no
value and is called once for each script on the server, with arguments

callback($name, $is_active)

I<sieve_list> returns zero on success and non-zero on failure.

=item sieve_activate($sieveobj, $name)

Makes the script named I<$name> the active script on the server.  Only
one script is active at a time; activating a script de-activates any
others.  Returns zero on success and non-zero on failure.

=item sieve_get($sieveobj, $name, $output)

Retrieves the SIEVE script named <$name> from the server, and stores it
in the scalar I<$output>.  Returns zero on success and non-zero on
failure.

=back

=head1 AUTHOR

T. Martin, tmartin@andrew.cmu.edu

=head1 SEE ALSO

RFC5804, A Protocol for Remotely Managing Sieve Scripts.

=cut

# imapoptions.pl - process imapoptions files into various formats
# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

sub read_option
{
    my ($path) = @_;

    my $option = {};

    open my $in, '<', $path or die "$in: $!";
    while (<$in>) {
        last if $_ eq "\n"; # empty line ends headers
        my ($field, $value) = split q{: }, $_;
        $option->{$field} = $value;
    }
    # everything after the empty line is the documentation body
    $option->{docs} = [ <$in> ];
    close $in;

    # XXX validation

    return $option;
}

sub validate_option
{
    my ($option) = @_;

    # must have Option field
    # must have Type field
    #   Type must be one of supported types
    # must have Default field
    # must have Last-Modified field
    #   Last-Modified must be a version number or UNRELEASED

    # for STRINGLIST, ENUM
    # must have Allowed-Values field
    # Default must be one of Allowed-Values

    # for BITFIELD
    # must have Allowed-Values field
    # Default must be subset of Allowed-Values
}

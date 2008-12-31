use strict;
use warnings;
package Net::SSLGlue::LWP;
use IO::Socket::SSL 1.19;

# force IO::Socket::SSL as superclass of Net::HTTPS, because
# only it can verify certificates
BEGIN {
	my $oc = $Net::HTTPS::SOCKET_CLASS;
	$Net::HTTPS::SOCKET_CLASS = my $need = 'IO::Socket::SSL';
	require Net::HTTPS;
	if ( ( my $oc = $Net::HTTPS::SOCKET_CLASS ) ne $need ) {
		# was probably loaded before, change ISA
		grep { s{^\Q$oc\E$}{$need} } @Net::HTTPS::ISA
	}
	die "cannot force IO::Socket:SSL into Net::HTTPS"
		if $Net::HTTPS::SOCKET_CLASS ne $need;
}

our %SSLopts;  # set by local and import
sub import {
	shift;
	%SSLopts = @_;
}
my $old_eso = defined &LWP::Protocol::https::_extra_sock_opts;
no warnings 'redefine';
*LWP::Protocol::https::_extra_sock_opts = sub {
	return (
		$old_eso ? ( $old_eso->(@_) ):(),
		SSL_verify_mode => 1,
		SSL_verifycn_scheme => 'http',
		%SSLopts,
	);
};

1;

=head1 NAME

Net::SSLGlue::LWP - proper certificate checking for https in LWP

=head1 SYNOPSIS

  	use Net::SSLGlue::LWP SSL_ca_path => ...;
	use LWP::Simple;
	get( 'https://www....' );

	{
		local %Net::SSLGlue::LWP::SSLopts = %Net::SSLGlue::LWP::SSLopts;
		$Net::SSLGlue::LWP::SSLopts{SSL_verify_mode} = 0; # no verification
	}


=head1 DESCRIPTION

L<Net::SSLGlue::LWP> modifies L<Net::HTTPS> and L<LWP::Protocol::https> so that
L<Net::HTTPS> is forced to use L<IO::Socket::SSL> instead of L<Crypt::SSLeay>
and that L<LWP::Protocol::https> does proper certificate checking using the
C<http> SSL_verify_scheme from L<IO::Socket::SSL>.

Because L<LWP> does not have a mechanism to forward arbitrary parameter for
the construction of the underlying socket these parameters can be set globally
when including the package or with local settings of the
C<%Net::SSLGlue::LWP::SSLopts> variable.

All of the C<SSL_*> parameter from L<IO::Socket::SSL> can be used, especially
the following parameters are useful:

=over 4

=item SSL_ca_path, SSL_ca_file

Specifies the path or a file where the CAs used for checking the certificates
are located. Typical for UNIX systems is L</etc/ssl/certs>.

=item SSL_verify_mode

If set to 0 disabled verification of the certificate. By default it is 1 which
means, that the peer certificate is checked.

=item SSL_verifycn_name

Usually the name given as the hostname in the constructor is used to verify the
identity of the certificate. If you want to check the certificate against
another name you might specify it with this parameter.

=back

=head1 SEE ALSO

IO::Socket::SSL, LWP, Net::HTTPS, LWP::Protocol::https

=head1 COPYRIGHT

This module is copyright (c) 2008, Steffen Ullrich.
All Rights Reserved.
This module is free software. It may be used, redistributed and/or modified
under the same terms as Perl itself.


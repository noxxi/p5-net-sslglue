use strict;
use warnings;
package Net::SSLGlue::LWP;
our $VERSION = 0.2;
use LWP::UserAgent '5.822';
use IO::Socket::SSL 1.19;
use URI::Escape 'uri_unescape';
use MIME::Base64 'encode_base64';
use URI;

# force IO::Socket::SSL as superclass of Net::HTTPS, because
# only it can verify certificates
BEGIN {
	my $oc = $Net::HTTPS::SOCKET_CLASS;
	$Net::HTTPS::SOCKET_CLASS = my $need = 'IO::Socket::SSL';
	require Net::HTTPS;
	require LWP::Protocol::https;
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

{
	# add SSL options
	my $old_eso = UNIVERSAL::can( 'LWP::Protocol::https','_extra_sock_opts' );
	no warnings 'redefine';
	*LWP::Protocol::https::_extra_sock_opts = sub {
		return (
			$old_eso ? ( $old_eso->(@_) ):(),
			SSL_verify_mode => 1,
			SSL_verifycn_scheme => 'http',
			HTTPS_proxy => $_[0]->{ua}{https_proxy},
			%SSLopts,
		);
	};
}

{
	# fix https_proxy handling - forward it to a variable handled by me
	my $old_proxy = defined &LWP::UserAgent::proxy && \&LWP::UserAgent::proxy
		or die "cannot find LWP::UserAgent::proxy";
	no warnings 'redefine';
	*LWP::UserAgent::proxy = sub {
		my ($self,$key,$val) = @_;
		goto &$old_proxy if ref($key) || $key ne 'https';
		if (@_>2) {
			my $rv = &$old_proxy;
			$self->{https_proxy} = delete $self->{proxy}{https}
				|| die "https proxy not set?";
		}
		return $self->{https_proxy};
	}
}

{

	my $old_new = UNIVERSAL::can( 'LWP::Protocol::https::Socket','new' );
	my $sockclass = 'IO::Socket::INET';
	$sockclass .= '6' if eval "require IO::Socket::INET6" && ! $@;
	no warnings 'redefine';
	*LWP::Protocol::https::Socket::new = sub {
		my $class = shift;
		my %args = @_>1 ? @_ : ( PeerAddr => shift );
		my $phost = delete $args{HTTPS_proxy}
			|| return $old_new->($class,%args);
		$phost = URI->new($phost) if ! ref $phost;

		my $port = delete $args{PeerPort};
		my $host = delete $args{PeerHost} || delete $args{PeerAddr};
		if ( ! $port ) {
			$host =~s{:(\w+)$}{};
			$port = $args{PeerPort} = $1;
			$args{PeerHost} = $host;
		}
		if ( $phost->scheme ne 'http' ) {
			$@ = "scheme ".$phost->scheme." not supported for https_proxy";
			return;
		}
		my $auth = '';
		if ( my ($user,$pass) = split( ':', $phost->userinfo || '' ) ) {
			$auth = "Proxy-authorization: Basic ".
				encode_base64( uri_unescape($user).':'.uri_unescape($pass),'' ).
				"\r\n";
		}

		my $pport = $phost->port;
		$phost = $phost->host;
		my $self = $sockclass->new( PeerAddr => $phost, PeerPort => $pport )
			or return;
		print $self "CONNECT $host:$port HTTP/1.0\r\n$auth\r\n";
		my $hdr = '';
		while (<$self>) {
			$hdr .= $_;
			last if $_ eq "\n" or $_ eq "\r\n";
		}
		if ( $hdr !~m{\AHTTP/1.\d 2\d\d} ) {
			# error
			$@ = "non 2xx response to CONNECT: $hdr";
			return;
		} else {
			$class->start_SSL( $self,
				SSL_verifycn_name => $host,
				%args
			);
		}
	};
}

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


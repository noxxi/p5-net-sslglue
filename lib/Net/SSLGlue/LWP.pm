use strict;
use warnings;
package Net::SSLGlue::LWP;

# force IO::Socket::SSL as superclass of Net::HTTPS, because
# only it can verify certificates
BEGIN {
	require IO::Socket::SSL;
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

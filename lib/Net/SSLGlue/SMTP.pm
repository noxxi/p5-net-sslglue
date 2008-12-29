use strict;
use warnings;

package Net::SSLGlue::SMTP;
use IO::Socket::SSL;
use Net::SMTP;

##############################################################################
# mix starttls method into Net::SMTP which on SSL handshake success 
# upgrades the class to Net::SMTP::_SSLified
##############################################################################
sub Net::SMTP::starttls {
	my $self = shift;
	$self->_STARTTLS or return;
	Net::SMTP::_SSLified->start_SSL( $self,
		SSL_verify_mode => 1,
		SSL_verifycn_scheme => 'smtp',
		SSL_verifycn_name => ${*$self}{net_smtp_host},
		@_ 
	);
}
sub Net::SMTP::_STARTTLS { 
	shift->command("STARTTLS")->response() == Net::SMTP::CMD_OK
}

no warnings 'redefine';
my $old_new = \&Net::SMTP::new;
*Net::SMTP::new = sub {
	my $class = shift;
	my %arg = @_ % 2 == 0 ? @_ : ( Host => shift,@_ );
	if ( delete $arg{SSL} ) {
		$arg{Port} ||= 465;
		return Net::SMTP::_SSLified->new(%arg);
	} else {
		return $old_new->($class,%arg);
	}
};

##############################################################################
# Socket class derived from IO::Socket::SSL
# strict certificate verification per default
##############################################################################
our %SSLargs;
{
	package Net::SMTP::_SSL_Socket;
	our @ISA = 'IO::Socket::SSL';
	sub configure_SSL {
		my ($self,$arg_hash) = @_;

		# set per default strict certificate verification
		$arg_hash->{SSL_verify_mode} = 1 
			if ! exists $arg_hash->{SSL_verify_mode};
		$arg_hash->{SSL_verifycn_scheme} = 'smtp'
			if ! exists $arg_hash->{SSL_verifycn_scheme};
		$arg_hash->{SSL_verifycn_name} = ${*$self}{net_smtp_host}
			if ! exists $arg_hash->{SSL_verifycn_name};

		# force keys from %SSLargs
		while ( my ($k,$v) = each %SSLargs ) {
			$arg_hash->{$k} = $v;
		}
		return $self->SUPER::configure_SSL($arg_hash)
	}
}


##############################################################################
# Net::SMTP derived from Net::SMTP::_SSL_Socket instead of IO::Socket::INET
# this talks SSL to the peer
##############################################################################
{
	package Net::SMTP::_SSLified;
	use Carp 'croak';

	# deriving does not work because we need to replace a superclass
	# from Net::SMTP, so just copy the class into the new one and then
	# change it

	# copy subs
	for ( keys %{Net::SMTP::} ) {
		no strict 'refs';
		*{$_} = \&{ "Net::SMTP::$_" } if *{$Net::SMTP::{$_}}{CODE};
	}

	# copy + fix @ISA
	our @ISA = @Net::SMTP::ISA;
	grep { s{^IO::Socket::INET$}{Net::SMTP::_SSL_Socket} } @ISA
		or die "cannot find and replace IO::Socket::INET superclass";

	# we are already sslified
	no warnings 'redefine';
	sub starttls { croak "have already TLS\n" }

	my $old_new = \&new;
	*Net::SMTP::_SSLified::new = sub {
		my $class = shift;
		my %arg = @_ % 2 == 0 ? @_ : ( Host => shift,@_ );
		local %SSLargs;
		$SSLargs{$_} = delete $arg{$_} for ( grep { /^SSL_/ } keys %arg );
		return $old_new->($class,%arg);
	};
}

1;

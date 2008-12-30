use strict;
use warnings;
package Net::DNSGlue::LDAP;
use Net::LDAP;

# can be reset with local
our %SSLargs;

# add SSL_verifycn_scheme to the SSL CTX args returned by
# Net::LDAP::_SSL_context_init_args

my $old = defined &Net::LDAP::_SSL_context_init_args
	|| die "cannot find Net::LDAP::_SSL_context_init_args";
no warnings 'redefine';
*Net::LDAP::_SSL_context_init_args = sub {
	my %arg = $old->(@_);
	$arg{SSL_verifycn_scheme} ||= 'ldap' if $arg{SSL_verify_mode};
	while ( my ($k,$v) = each %SSLargs ) {
		$arg{$k} = $v;
	}
	return %arg;
};

1;

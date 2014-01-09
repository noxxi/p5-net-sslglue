
package Net::SSLGlue::Socket;
our $VERSION = 1.0;

use strict;
use warnings;
use Carp 'croak';
use Symbol 'gensym';
use IO::Socket::SSL;
my $IPCLASS;
BEGIN {
    for(qw(IO::Socket::IP IO::Socket::INET6 IO::Socket::INET)) {
	$IPCLASS = $_,last if eval "require $_";
    }
}

# this can be overwritten (with local) to get arguments passed around
# to strict calls of the socket class new
our %ARGS;

sub new {
    my $class = shift;
    my %args = @_>1 ? @_ : ( PeerAddr => shift() );
    %args = ( %args, %ARGS );

    my %sslargs;
    for(keys %args) {
	$sslargs{$_} = delete $args{$_} if m{^SSL_};
    }

    my $ssl = delete $args{SSL};
    my $sock = $ssl
	? IO::Socket::SSL->new(%args,%sslargs)
	: $IPCLASS->new(%args)
	or return;

    my $self = gensym();
    bless $self,$class;
    ${*$self}{sock}    = $sock;
    ${*$self}{ssl}     = $ssl;
    ${*$self}{sslargs} = \%sslargs;

    tie *{$self},'Net::SSLGlue::Socket::HANDLE',$self;
    return $self;
}

for my $sub (qw(
    fileno sysread syswrite close connect accept fcntl
    read write readline print printf getc say eof getline getlines
    blocking autoflush timeout
    sockhost sockport peerhost peerport sockdomain
    truncate stat setbuf setvbuf fdopen ungetc send recv
)) {
    no strict 'refs';
    *$sub = sub {
	my $self = shift;
	my $sock = ${*$self}{sock} or return;
	my $sock_sub = $sock->can($sub) or croak("$sock does not support $sub");
	unshift @_,$sock;
	goto &$sock_sub;
    };
}

sub start_SSL {
    my $self = shift;
    croak("start_SSL called on SSL socket") if ${*$self}{ssl};
    IO::Socket::SSL->start_SSL(${*$self}{sock},%{${*$self}{sslargs}},@_)
	or return;
    ${*$self}{ssl} = 1;
    return $self;
}

sub stop_SSL {
    my $self = shift;
    croak("stop_SSL called on plain socket") if ! ${*$self}{ssl};
    ${*$self}{sock}->stop_SSL(@_) or return;
    ${*$self}{ssl} = 0;
    return $self;
}

sub can_read {
    my ($self,$timeout) = @_;
    return 1 if ${*$self}{ssl} && ${*$self}{sock}->pending;
    vec( my $vec,fileno(${*$self}{sock}),1) = 1;
    return select($vec,undef,undef,$timeout);
}

sub peer_certificate {
    my $self = shift;
    return ${*$self}{ssl} && ${*$self}{sock}->peer_certificate(@_);
}

sub is_ssl {
    my $self = shift;
    return ${*$self}{ssl} && ${*$self}{sock};
}


package Net::SSLGlue::Socket::HANDLE;
use Scalar::Util 'weaken';
use Errno 'EBADF';

sub TIEHANDLE {
    my ($class, $handle) = @_;
    weaken($handle);
    return bless \$handle, $class;
}

sub TELL     { $! = EBADF; return -1 }
sub BINMODE  { return 0 }

for (
    [ READ => 'sysread' ],
    [ WRITE => 'syswrite' ],
    qw(fileno close getc readline print printf)
) {
    my ($name,$sub) = ref($_) ? @$_ : (uc($_),$_);
    no strict 'refs';
    *$name = sub {
	my $self = ${shift()};
	my $sock = ${*$self}{sock} or return;
	my $sock_sub = $sock->can($sub) or croak("$sock does not support $sub");
	unshift @_,$sock;
	goto &$sock_sub;
    };
}

1;

=head1 NAME

Net::SSLGlue::Socket - socket which can be either SSL or plain IP (IPv4/IPv6)

=head1 SYNOPSIS

    use Net::SSLGlue::Socket;
    # SSL right from start
    my $ssl = Net::SSLGlue::Socket->new(
	PeerHost => ...,  # IPv4|IPv6 address
	PeerPort => ...,
	SSL => 1,
	SSL_ca_path => ...
    );

    # SSL through upgrade of plain connection
    my $plain = Net::SSLGlue::Socket->new(...);
    $plain->start_SSL( SSL_ca_path => ... );
    ...
    $plain->stop_SSL


=head1 DESCRIPTION

L<Net::SSLGlue::Socket> implements a socket which can be either plain or SSL.
If IO::Socket::IP or IO::Socket::INET6 are installed it will also transparently
handle IPv6 connections.

A socket can be either start directly with SSL or it can be start plain and
later be upgraded to SSL (because of a STARTTLS commando or similar) and also
downgraded again.

It is possible but not recommended to use the socket in non-blocking
mode, because in this case special care must be taken with SSL (see
documentation of L<IO::Socket::SSL>).

Additionally to the usual socket methods the following methods are defined or
extended:

=head1 METHODS

=over 4

=item new

The method C<new> of L<Net::SSLGlue::Socket> can have the argument SSL. If this
is true the SSL upgrade will be done immediatly. If not set any SSL_* args will
still be saved and used at a later start_SSL call.

=item start_SSL

This will upgrade the plain socket to SSL. See L<IO::Socket::SSL>  for
arguments to C<start_SSL>. Any SSL_* arguments given to new will be applied
here too.

=item stop_SSL

This will downgrade the socket from SSL to plain.

=item peer_certificate ...

Once the SSL connection is established you can use this method to get
information about the certificate. See the L<IO::Socket::SSL> documentation.

=item can_read(timeout)

This will check for available data. For a plain socket this will only use
C<select> to check the socket, but for SSL it will check if there are any
pending data before trying a select.
Because SSL needs to read the whole frame before decryption can be done, a
successful return of can_read is no guarantee that data can be read
immediatly, only that new data are either available or in the process of
arriving.

=back

=head1 SEE ALSO

IO::Socket::SSL

=head1 COPYRIGHT

This module is copyright (c) 2013, Steffen Ullrich.
All Rights Reserved.
This module is free software. It may be used, redistributed and/or modified
under the same terms as Perl itself.

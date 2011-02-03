package Net::SSLGlue;
our $VERSION = 0.5;

=head1 NAME

Net::SSLGlue - add/extend SSL support for common perl modules

=head1 DESCRIPTION

Some commonly used perl modules don't have SSL support at all, even if the
protocol would support it. Others have SSL support, but most of them don't do
proper checking of the servers certificate.

The C<Net::SSLGlue::*> modules try to add SSL support or proper certificate to
these modules. Currently is support for the following modules available:

=over 4

=item Net::SMTP - add SSL from beginning or using STARTTLS

=item Net::LDAP - add proper certificate checking

=item LWP - add proper certificate checking

=back

=head1 COPYRIGHT

This module and the modules in the Net::SSLGlue Hierarchy distributed together
with this module are copyright (c) 2008-2011, Steffen Ullrich.
All Rights Reserved.
These modules are free software. They may be used, redistributed and/or modified
under the same terms as Perl itself.

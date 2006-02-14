# Copyright (c) 2006 CentralNic Ltd. All rights reserved. This program is
# free software; you can redistribute it and/or modify it under the same
# terms as Perl itself.
# 
# $Id: Proxy.pm,v 1.2 2006/02/14 16:47:06 gavin Exp $
package Net::EPP::Proxy;
use bytes;
use Carp;
use Digest::MD5 qw(md5_hex);
use Net::EPP::Client;
use Net::EPP::Frame;
use Net::Server::PreForkSimple;
use Time::HiRes qw(time);
use base qw(Net::Server::PreForkSimple);
use vars qw($VERSION $CLIENT $GREETING $MAXLOAD $TIMEOUT);
use strict;

our $VERSION = '0.0.1';

=pod

=head1 NAME

Net::EPP::Proxy - a proxy server for the EPP protocol.

=head1 SYNOPSIS

	#!/usr/bin/perl
	use Net::EPP::Proxy;
	use strict;

	Net::EPP::Proxy->init(
		# EPP-specific params:
		remote_host	=> 'epp.nic.tld',
		remote_port	=> 700,
		ssl		=> 1,
		clid		=> $CLID,
		pw		=> $PW,

		# Net::Server params:
		host		=> 'localhost',
		port		=> 7000,
		log_level	=> 0,
		max_servers	=> 10,
		min_servers	=> 5,
	);

	### then in the client processes:

	my $client = Net::EPP::Client->new(
		host	=> 'localhost',
		port	=> 7000,
		ssl	=> undef,
	);

	print $client->connect;

=head1 DESCRIPTION

EPP is the Extensible Provisioning Protocol. EPP (defined in RFC 3730) is an
application layer client-server protocol for the provisioning and management of
objects stored in a shared central repository. Specified in XML, the protocol
defines generic object management operations and an extensible framework that
maps protocol operations to objects. As of writing, its only well-developed
application is the provisioning of Internet domain names, hosts, and related
contact details.

RFC 3734 defines a TCP based transport model for EPP, and this module
implements a proxy server for this model. You can use it to construct a daemon
that maintains a single connection to the EPP server that can be used by many
local clients, thereby reducing the overhead for each transaction.

Net::EPP::Proxy is based on the L<Net::Server> framework and
L<Net::EPP::Client>, which it uses to communicate with the server.

When a Net::EPP::Proxy server is started, it creates a connection to a single
remote EPP server using the supplied credentials. Each proxy can connect to a
single remote server - if you want to proxy for multiple servers you should
create a proxy server for each, perhaps listening on a different TCP port.

	Figure 1.0 - multiple clients connecting to a remote server

	+---+				+---+
	| C |<-----------//------------>|   |	In this model, each client must
	+---+				|   |   establish a session with the
					| S |   server, increasing the time and
	+---+				| E |	bandwidth overheard associated
	| C |<-----------//------------>| R |   with sending transactions to
	+---+				| V |   the server, especially if the
					| E |   client is a CGI or PHP script
	+---+				| R |	that must create a new
	| C |<-----------//------------>|   |	connection each time.
	+---+				+---+

	Figure 1.1 - multiple clients connecting to a proxy

	+---+		+---+		+---+
	| C |<--------->|   |		|   |	In this model, the proxy server
	+---+		|   |		|   |	maintains a single connection
			| P |		| S |	to the server on behalf of a
	+---+		| R |		| E |	number of clients, reducing
	| C |<--------->| O |<----//--->| R |	the time and bandwidth overhead
	+---+		| X |		| V |	associated with sending
			| Y |		| E |	transactions to the server.
	+---+		|   |		| R |
	| C |<--------->|   |		|   |
	+---+		+---+		+---+

When a local client connects to the proxy, it is immediately sent the EPP
C<E<lt>greetingE<gt>> frame the proxy server received from the remote server.
The client can then send EPP frames to the proxy, which passes these frames
on to the server within the context of its own connection, and returns the
remote servers' response to the client. A single connection to the remote
server can thereby be shared among a large number of local clients without
the need to connect and authenticate each client.

The proxy "speaks" the same protocol as an EPP server (XML payloads prefixed
by 4 bytes containing the payload's length, sent over TCP), so any client
capable of using the EPP protocol can use the proxy I<(eg, the
L<Net::EPP::Client> module, the Net_EPP_Client PHP class, etc)>.

=head1 USAGE

To start an EPP proxy server instance, use the following syntax:

	Net::EPP::Proxy->init(%PARAMS);

The C<%PARAMS> hash contain any of the configuration variables allowed by
L<Net::Server>, plus the following:

=over

=item C<remote_host>

The hostname of the remote EPP server to connect to.

=item C<remote_port>

The TCP port number of the remote EPP server to connect to (usually 700).

=item C<ssL>

Whether to use SSL (usually true).

=item C<clid>

The client ID to use to authenticate.

=item C<pw>

The password to use to authenticate.

=item C<req_timeout>

The amount of time in seconds to wait for a response from the remote server.
If there is a network outage or some other undefined error, the server will
C<croak()>. You should use an C<eval()> or an external "angel" script to catch
the error and restart the server if this happens.

=back

If the proxy is unable to authenticate with the remote EPP server it will
C<croak()>.

=head1 LOGGING, CONFIGURATION AND PERFORMANCE TUNING

See the documentation for L<Net::Server> for information about configuring the
server to do logging, and tweaking performance values. Net::EPP::Proxy uses
the L<Net::Server::PreForkSimple> model to handle connections, so for example
you can use the C<max_servers> and C<min_servers> to control how many child
processes the server will spawn.

=head1 AUTHOR

Gavin Brown (L<epp@centralnic.com>) for CentralNic Ltd (L<http://www.centralnic.com/>).

=head1 COPYRIGHT

This module is (c) 2006 CentralNic Ltd. This module is free software; you can
redistribute it and/or modify it under the same terms as Perl itself.

=head1 SEE ALSO

=over

=item * L<Net::EPP::Client>

=item * L<Net::EPP::Proxy>

=item * RFCs 3730 and RFC 3734, available from L<http://www.ietf.org/>.

=item * The CentralNic EPP site at L<http://www.centralnic.com/resellers/epp>.

=back

=cut

sub init {
	my ($package, %params) = @_;

	our $CLIENT = Net::EPP::Client->new(
		host	=> $params{remote_host},
		port	=> $params{remote_port},
		ssl	=> $params{ssl},
	);

	our $GREETING = $CLIENT->connect;

	our $MAXLOAD = $params{max_load} if ($^O eq 'linux');

	our $TIMEOUT = $params{req_timeout};

	my $login = Net::EPP::Frame::Command::Login->new;
	$login->clID->appendText($params{clid});
	$login->pw->appendText($params{pw});
	$login->clTRID->appendText(md5_hex($package.time().$$));

	if ($CLIENT->request($login) =~ /<result code="(\d+)">/) {
		croak('Unable to log into to server using supplied credentials') if ($1 != 1000);
	}

	return $package->SUPER::run(%params);
}

sub process_request {
	my $self = shift;

	print pack('N', length($GREETING) + 4).$GREETING;
	while (!eof(select())) {
		my $hdr;
		read(select(), $hdr, 4);
		my $question;
		read(select(), $question, (unpack('N', $hdr) - 4));

		my $answer;
		eval {
			local $SIG{ALRM} = sub { die "timeout\n" };
			alarm($TIMEOUT);
			$answer = $CLIENT->request($question);
			alarm(0);
		};
		if ($@ ne '') {
			croak("error getting answer from remote server: $@ (timeout $TIMEOUT secs)");

		} else {
			print pack('N', length($answer) + 4).$answer;

		}
	}
	return 1;
}

1;

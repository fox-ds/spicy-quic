##! Idea for a quic.log that only logs entries for QUIC connections
##! where the INITIAL packets are decrypted ClientHello / ServerHello.

@load base/frameworks/notice/weird
@load base/protocols/conn/removal-hooks

@load ./consts

module QUIC;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		## Time of first INITIAL packet observed for this connection.
		ts:          time    &log;
		## Unique ID for the connection.
		uid:         string  &log;
		## The connection's 4-tuple of endpoint addresses/ports.
		id:          conn_id &log;

		## QUIC version as found in the first INITIAL packet from
		## the client.
		version:     string  &log;

		## First Destination Connection ID used by client. This is
		## random and unpredictable, but used for packet protection
		## by client and server.
		## https://datatracker.ietf.org/doc/html/rfc9000#name-negotiating-connection-ids
		client_initial_dcid: string  &log &optional;

		## Server chosen Connection ID in server's INITIAL packet.
		## This is to be used by the client in subsequent packets.
		server_scid:        string  &log &optional;

		## From ClientHello in client INITIAL packet if available.
		server_name: string  &log &optional;

		## First protocol in list as requested by client via ALPN
		## extension in ClientHello if available.
		client_protocol: string &log &optional;

		# Has this record been logged.
		logged: bool &default=F;
	};

	global log_quic: event(rec: Info);

	global log_policy: Log::PolicyHook;

	global finalize_quic: Conn::RemovalHook;
}

redef record connection += {
	# XXX: We may have multiple QUIC connections with different
	#      Connection ID over the same UDP connection.
	quic: Info &optional;
};

function set_conn(c: connection, is_orig: bool, version: count, dcid: string, scid: string)
	{
	if ( ! c?$quic )
		{
		c$quic = Info(
			$ts=network_time(),
			$uid=c$uid,
			$id=c$id,
			$version=version_strings[version],
		);

		Conn::register_removal_hook(c, finalize_quic);
		}

	if ( is_orig && |dcid| > 0 && ! c$quic?$client_initial_dcid )
		c$quic$client_initial_dcid = bytestring_to_hexstr(dcid);

	if ( ! is_orig && |scid| > 0 )
		c$quic$server_scid = bytestring_to_hexstr(scid);
	}

event QUIC::long_header(c: connection, is_orig: bool, packet_type: QUIC::LongPacketType, version: count, dcid: string, scid: string)
	{
	if ( packet_type != LongPacketType_INITIAL )
		return;

	set_conn(c, is_orig, version, dcid, scid);
	}

event ssl_extension_server_name(c: connection, is_client: bool, names: string_vec) &priority=5
	{
	if ( is_client && c?$quic && |names| > 0 )
		c$quic$server_name = names[0];
	}

event ssl_extension_application_layer_protocol_negotiation(c: connection, is_client: bool, protocols: string_vec)
	{
	if ( c?$quic && is_client )
		{
		c$quic$client_protocol = protocols[0];
		if ( |protocols| > 1 )
			# Probably not overly weird, but the quic.log only
			# works with the first one in the hope to avoid
			# vector or concatenation.
			Reporter::conn_weird("QUIC_many_protocols", c, cat(protocols));
		}
	}

event ssl_server_hello(c: connection, version: count, record_version: count, possible_ts: time, server_random: string, session_id: string, cipher: count, comp_method: count) &priority=-5
	{
	if ( ! c?$quic || c$quic$logged )
		return;

	Log::write(LOG, c$quic);
	c$quic$logged = T;

	# TODO: Should we disable the analyzer at this point assuming
	#       the rest will just be protected/encrypted packets into
	#       which we can't actually see into anyhow?
	}

hook finalize_quic(c: connection)
	{
	if ( ! c?$quic || c$quic$logged )
		return;

	Log::write(LOG, c$quic);
	c$quic$logged = T;
	}

event zeek_init()
	{
	Log::create_stream(LOG, [$columns=Info, $ev=log_quic, $path="quic", $policy=log_policy]);
	}

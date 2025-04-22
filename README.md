# Waterfall

A deep packet inspection bypass proxy

## Introduction

This tool helps to bypass censorship caused by deep packet inspection

## CMD line

```
./waterfall [OPTION] [VALUE]
[Offset] is denoted as subcommand in format of N+[s]?,
  where N is unsigned 32-bit integer, s - SNI Index.
  [Offset] Block examples: 1+, 5+s, 13+s
  
--bind_host [String] - Bind SOCKS5 Proxy to a specified host
--bind_port [U16] - Bind SOCKS5 Proxy to a specified port

--default_ttl [U8] - Default TTL value for adequate packets.
--fake_packet_ttl [U8] - Default TTL value for packets that should reach ONLY DPI 
--disorder_packet_ttl [U8] - Default TTL value for packets that SHOULD BE RESENT

--fake_packet_sni [String] - Server name identification for fake packets.
--fake_packet_send_http - Set if fake module should mimic HTTP packets. 
  Can trick DPI into thinking that connection is made over HTTP and force it to skip
  Over next packets.
--fake_packet_host [String] - Fake host for fake packets. Tricks DPI
--fake_packet_override_data [UNICODE String] - Override default packet data for fake packets.
--fake_as_oob - Force fake packets to be sent as Out-of-band data. 
  May break some websites same as OOB module does.
  Useful for cases when deep packet inspection tool looks for OOB data.
--fake_packet_reversed - Send fake packets in reversed order.
--fake_packet_double - Send two fake packets instead of one.
--fake_packet_random - Send random fake packets.

--send_fake_clienthello - Send fake clienthello for each found SNI.
--fake_clienthello_sni [SNI] - Set fake clienthello SNI.

--disable_sack - Disable selelective acknowledgment on linux

--whitelist_sni [DOMAIN] - Add certain SNI domain in whitelist. Whitelist is disabled by default when not specified.

--packet_hop [U8] - Applies all traffic modifications only to specific number of packets.
--split_record_sni - Tampers all TLS segments with SNI, creating a new record in between of the SNI.

--http_host_cmix - Mix Host header case in HTTP
--http_host_rmspace - Remove space after Host: header in HTTP
--http_host_space - Add space after Host: header in HTTP
--http_domain_cmix - Mix case in HTTP domain
--split_record_sni - Split TLS record at SNI middle in ClientHello 

--split [Offset] - Apply TCP stream segmentation.
  If the offset in unapplicable for current case, strategy will be dropped
  for performance saving reasons.
--disorder [Offset] - Apply TCP stream segmentation and corrupt first part by settings TTL/Hop-by-hop to 1.
  The first segment will not reach the server, and client will know about it
  Only via ACK/SACK. Adds delay equal to ping.

  If the offset in unapplicable for current case, strategy will be dropped
  for performance saving reasons.
--fake [Offset] - Apply TCP stream segmentation, corrupt first part and send a duplicate of it.
--oob [Offset] - Apply TCP stream segmentation.
  Sends Out-Of-Band byte at the end of first segment.
--disoob [Offset] - Apply TCP stream segmentation, corrupt first part.
  Sends Out-Of-Band byte at the end of first segment.
```

## Offsets

Offset is a argument type for waterfall modules.

It consists out of 3 parts. Index (i64), sign (sum or substract from base index) and base index.

Examples:

- `1-s`
- `1-h`
- `1+s`
- `1+h`

## Building, running and testing

Build the project via `cargo`:

```bash
cargo build
```

Run the project:

```bash
cargo run
```

Test utilities and network capabilities:

```bash
cargo test
```

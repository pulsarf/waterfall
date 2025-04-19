# Waterfall
> This project is in active development. If you're looking for actually working DPI bypass, refer to [zapret](<https://github.com/bol-van/zapret>)

A deep packet inspection bypass proxy

## Introduction

This tool helps to bypass censorship caused by deep packet inspection.

## Bypass methods

> Most of methods in Waterfall are directed at TCP protocol

Config examples: 

----------
### --fake 1+s --disorder 10+s

```
|--------------------|---------------|---------------------|----------------|
|  [DATA CORRUPTED]  |  [DATA FAKE]  |  [DATA1 CORRUPTED]  |  [DATA2 REAL]  |
|--------------------|---------------|---------------------|----------------|
```

----------
### --disoob 5+s --split 1+s --fake 1+s

Warning: this is a very complex case. The SNI will not likely by in the second part of the segment - therefore 1+s will have the same effect as 1+, because "s" will have usize index of 0.

```
|--------------------|---------------|-----------------------|------------------|-----------|
|  [DATA CORRUPTED]  |  [DATA OOB ]  |  [DATA1.5 CORRUPTED]  |  [DATA1.5 FAKE]  |  [DATA2]  |
|--------------------|---------------|-----------------------|------------------|-----------|
```

## Software limitations

You must consider limitations that currently waterfall has. If you want to contribute at solving these issues, feel free to pull request.

Currently Waterfall is incapable of:

- Fragment packets on IP level. This leads to UDP bypasses not being possible, therefore Waterfall won't use bypasses for QUIC. In plans to be fixed after bugs will be fixed.
- Bypass DPI that checks server certificate. To solve this issue, migrate to TLS 1.3

## Command-line interface

Waterfall offers command line interface for managing the configuration, and keep much less hardcoded values.

Warning: In future, more options MUST be added. The default TTL/Hop-by-hop values don't work for every ISP, and without modification of them, modules other than --split and --oob will not likely work.

Currently, these options are implemented:

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
--fake_packet_send_http - Sets if fake module should mimic HTTP packets. 
  Can trick DPI into thinking that connection is made over HTTP and force it to skip
  Over next packets.
--fake_packet_host [String] - Fake host for fake packets. Tricks DPI
--fake_packet_override_data [UNICODE String] - Overrides default packet data for fake packets.
--fake_as_oob - Forces fake packets to be sent as Out-of-band data. 
  May break some websites same as OOB module does.
  Useful for cases when deep packet inspection tool looks for OOB data.
--fake_packet_reversed - Sends fake packets in reversed order.
--fake_packet_double - Sends two fake packets instead of one.
--fake_packet_random - Sends random fake packets.

--packet_hop [U8] - Applies all traffic modifications only to specific number of packets.
--split_record_sni - Tampers all TLS segments with SNI, creating a new record in between of the SNI.

--http_host_cmix - Mix Host header case in HTTP
--http_host_rmspace - Remove space after Host: header in HTTP
--http_host_space - Add space after Host: header in HTTP
--http_domain_cmix - Mix case in HTTP domain
--split_record_sni - Split TLS record at SNI middle in ClientHello 

--split [Offset] - Applies TCP stream segmentation.
  If the offset in unapplicable for current case, strategy will be dropped
  for performance saving reasons.
--disorder [Offset] - Applies TCP stream segmentation and corrupts first part by settings TTL/Hop-by-hop to 1.
  The first segment will not reach the server, and client will know about it
  Only via ACK/SACK. Adds delay equal to ping.

  If the offset in unapplicable for current case, strategy will be dropped
  for performance saving reasons.
--fake [Offset] - Applies TCP stream segmentation, corrupts first part and sends a duplicate of it.
  Applies "disorder" method to the first segment.
  Use this method if the DPI perfectly reassembles packets.
--oob [Offset] - Applies TCP stream segmentation.
  Sends Out-Of-Band byte at the end of first segment.
--disoob [Offset] - Applies TCP stream segmentation, corrupts first part.
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

## Packets capture

Packets are captured via SOCKS5 proxy. Waterfall is a backend that modifies the traffic, and to run it on any platform, you'll have to use a SOCKS5 client.

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

## Requirements

This project requires support of libc or winapi. This means, the project must work with these platforms:

- Unix (e.g freebsd, linux (including android), mach)
- Windows

iOS platform aren't and will never be supported. If you use apple's products, you won't get any blocked site working anyways.

## Development and testing 

Repeat the same step to build this project 

```bash
cargo build
```

Tests are done for utility functions and the modules itself. 

```bash
cargo test
```

### HTTP Attacks

- 'Host' case mixer.
- Host domain case mixer.

---------

### TLS Attacks

- Split TLS Record

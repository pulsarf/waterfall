# Waterfall
> This project is in active development. If you're looking for actually working DPI bypass, refer to [zapret](<https://github.com/bol-van/zapret>) and [byedpi](<https://github.com/hufrea/byedpi>)

High level deep packet inspection bypass utility with multiple strategies that can be used together.

This project uses SOCKS5 Proxy to capture packets, but it's not a huge problem, since in Rust you can save TcpStream as raw socket or file descriptor.

## Introduction

Blocking websites by IP address had became a bad practice over time, since such limitations can cause non-related websites to be blocked too. Deep packet inspection is an obvious solution to that issue, it can be bypassed easier than IP blocking, but it requires creating VPNs that mask the traffic. 

Serverless DPI bypasses allow to don't use VPNs.

This tool helps to bypass censorship caused by deep packet inspection.

> Important information will come!
> If you don’t read it, you will likely seek for configurations done by other people.
> Don’t get into that trap! DPI Bypass configurations are different for every ISP.

## Bypass methods

> Most of methods in Waterfall are directed at TCP protocol

### Desynchronization attacks

How would you implement deep packet inspection? For sure, set up a gateway between router and the ISP, and then filter each IP packet.

This is exactly what Russian or Chinese DPI does. However, this method doesn't account for fragmented packets on both IP and applicated protocol level. Waterfall implements much strategies targeted at exploiting this vulnerability.

---------
### TCP Stream segmentation.

This method has the least drawback on performance, and the least efficiency on practice.

The idea comes from reversing Nagle's alghoritm. If Nagle's Alghoritm merges segments, Split module will split them.

This method will not work if the DPI tries to recover applicated protocol packet.

Stream segmentation is the first ever way you must try, and if it works, consider using it further.

Deep packet inspection will see the stream like this:

```
|----------|----------|
|  [DATA]  |  [DATA1] |
|----------|----------|
```

---------
### Data disordering

This method is a modification of tcp segmentation with an extension which's idea is to corrupt first segment on packet level. 

As the result, the first segment will be automatically re-sent. 

This method is a bit harder to be set up, since you'll have to configure TTL/Hop-by-hop options for packet that will be re-sent.

Based on different systems and routers, the first packet may not be resent.

Deep packet inspection will see the stream like this:
```
|----------|-----------|-----------|----------|
|  [DATA - CORRUPTED]  |  [DATA1]  |  [DATA]  |
|----------|-----------|-----------|----------|
```

---------
### Sending fake data 

This method is data disordering with an extension that sends a fake data after first segment was sent. 

If the DPI perfectly reassembles the traffic, this method will be your only option.

If you pass this option multiple times, you will be able to spam data with fakes.

This option is really hard to use, but it has highest efficiency on practice.

Your target is to use options like --fake_packet_ttl and --fake_as_oob to make fake packets not to reach the server, but reach DPI.

Deep packet inspection will see the stream as follows:

```
|----------|-----------|-----------------|-----------|----------|
|  [DATA - CORRUPTED]  |  [FAKE OF DATA] |  [DATA1]  |  [DATA]  |
|----------|-----------|-----------------|-----------|----------|
```

---------
### Splitting with Out-of-band data as first part

This method is same as split, but the first data will be send as OOB data, with URG flag being set to 1. 

Since you can send only one byte as out of band, last byte is being manually appended.

The user can choose what byte will be appended, it's recommended to put that byte between SNI for tls and between domain in host header for http.

If this method doesn't work, use disordered version of it, which corrupts the first data, that has URG flag.

So, the normal data will be sent to the server, and the last out of band byte will go by it's special channel.

Most of HTTP servers ignore Out-of-band channel, because of it's complexity and they simply don't use it.

This method will work only when the DPI doesn't ignore Out of band bytes.

Deep packet inspection will see the stream as following:
```
|------------------|-----------|
| OUT OF BAND DATA |  [DATA1]  |
|------------------|-----------|
```

---------
### Disordered splitting with first part as Out-of-band

This method is same as Fake via OOB, but first segment is corrupted.

First segment is also sent as Out-of-band data, which means it will have URG flag set to 1.

In this segment, the last byte will be sent via different channel, and Waterfall automatically selects it from user input or default settings.

DPI will receive streamed bytes as denoted:
```
|----------|-----------|---------------------|-----------|----------|
|  [DATA - CORRUPTED]  |  [OUT OF BAND DATA] |  [DATA1]  |  [DATA]  |
|----------|-----------|---------------------|-----------|----------|
```

## Strategies model

Waterfall offers strategies model, where each strategy the user chooses is being recorded and automatically parsed. The strategy is **always** applied to unchanged segment. 

This means, that if you set a strategy "Split at index with step of 1 from TLS server name indication if found, otherwise zero" and duplicate it with "Disorder at index with step of 1 from TLS server name indication if found, otherwise zero", the first fragment will be left as it was, the second will be split to another 2 fragments, and the first of them will be corrupted.

Here's the schematic representation of what DPI will see:

```
|----------|-----------|-----------|
|  [DATA]  |  [DATA2]  |  [DATA1]  |
|----------|-----------|-----------|
```

Repeating again even simpler: If you pass multiple strategies, the first one will be applied as it is, and the others will be applied to last fragments from previous result.

More examples on how the program behaviour differs at different parameters:

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
--packet_hop [U8] - Applies all traffic modifications only to specific number of packets.

--http_host_cmix - Mix Host header case in HTTP
--http_host_rmspace - Remove space after Host: header in HTTP
--http_host_space - Add space after Host: header in HTTP
--http_domain_cmix - Mix case in HTTP domain
--split_record_sni - Split TLS record at SNI middle in ClientHello 

--synack - Wraps each packet into fake SYN and ACK.
  Those packets will be automatically dropped by server.
  But the DPI will process them as normal.
  As the result, it will trick DPI about client and server roles.
  Effective to use with disorder and fake.

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

## How to write a proper configuration 

> Configurations are different for each ISP
> Again, beware of "repackers" that distribute random configs

You must determine what DPI is doing to detect blocked source. 

---------
Most commonly the reason is ClientHello with SNI extension.

Server name identification (SNI) is a TLS extension that specifies which server name client wants to connect on.

At this moment, Waterfall doesn't offer a way to remove this extension from ClientHello.

You have to manually test on some domain if the packet with SNI of blocked website gets dropped by DPI.

<Insert Rust code that sends ClientHello without SNI>
<Insert Rust code that sends ClientHello with www.youtube.com SNI>

If so, you need to determine the vulnerability which allows us to prevent DPI from parsing SNI from the ClientHello.

Waterfall offers these DPI exploits, that you can test, and they all have the same argument - Index of splitting

- --split
- --disorder
- --fake
- --oob
- --disoob

For example, `--oob 3+s`

The arguments has almost same syntax, the only difference is that plus sign is enforced.

Here's the translation table from ByeDPI to Waterfall

| ByeDPI       | Waterfall     |
|--------------|---------------|
| --disorder 7 | --disorder 7+ |
| --split 1+s  | --split 1+s   |
| --fake hn    | --fake 0+h    |

---------

Given a case, when you're working with HTTP.

DPI will check Host header. Your target is to make DPI fail to parse it in any way.

Waterfall doesn't implement tampering metods at this moment.

You will have to use same attack exploits, as with SNI

For example: `--disorder 1+h`

You can use this code snippet, to watch DPI behaviour on HTTP:

<Insert Rust code that sends HTTP packet on blocked website>

---------
How to deal with DPI that tries to reassemble packets

If the DPI bypasses doesn't work even while using `--disorder` and `--disoob` methods, you're dealing with DPI that detects splitted packets and tries to reassemble them.

Waterfall offers a special exploit that bypasses this. Fake module is designed for these cases, to make DPI accept wrong packets and think that the reassembling is finished.

The only way to detect this kind of DPI is practice.

Example of fake module: `--fake 1+s`

---------
How to deal with DPI, that fakes server certificate 

This isn't a common case, because browsers automatically detect MITM attacks.

The only way is to manually decrease socket MSS. Waterfall isn't adapted for DPI that checks the server.

There isn't much you can do with it. Enable TLS 1.3. Server certificate is encrypted in it and mimicked as TLS 1.2 data, also known as wrapped record.

------------
Dealing with DPI that both hijacks certificates and reassembles packets

The only way is tampering the traffic. It could be modifying tls records and Host headers in packets.

## Tampering attacks

> Conceptual paragraph incoming!
> Tampering attacks aren't implemented yet!

The idea of these attacks is modifying data in that way, DPI will fail to parse it.

--------

### HTTP Attacks

- 'Host' case mixer.
  Changes the case write of host HTTP header.
- Host domain case mixer.
- Host EOL
- Space after 'Host:'
- Space after method
- EOL after method
- Mixed case for a list of headers

---------

### TLS Attacks

- Remove SNI
- Split TLS Record

---------

## Useful information for development 

---------
### Literature that developers must know

libc socket specification: [https://www.man7.org/linux/man-pages/man2/socket.2.html](https://www.man7.org/linux/man-pages/man2/socket.2.html)

geneva documentation: [https://geneva.cs.umd.edu/papers/geneva_ccs19.pdf](https://geneva.cs.umd.edu/papers/geneva_ccs19.pdf)

---------
### Waterfall internal API documentation 

#### waterfall::core::Strategy

public fields:

  pub method: Strategies,
  
  pub base_index: usize,
  
  pub add_sni: bool,
  
  pub add_host: bool

public methods:
  `pub fn from(first: String, second: String) -> Strategy `

The from method parses Strategy by first CLI argument and second CLI argument.

Doesn't handle singular arguments only.


-------------

#### waterfall::core::parse_args

`pub fn parse_args() -> waterfall::core::AuxConfig`

Parses CLI arguments passed by the user

-------------

#### waterfall::core::get_help_text

`pub fn get_help_text() -> String`

Returns help text.

-------------

#### waterfall::drop::send

`pub fn send(mut socket: &TcpStream, data: Vec<u8>) -> Result<(), std::io::Error>`

Sends TCP data with extremely low TTL. The packet is supposed to be delivered only to the DPI.

-------------

#### waterfall::drop::raw_send

`pub fn raw_send(mut socket: &TcpStream, data: Vec<u8>)`

Wraps TCP data in another TCP data and sends it. Same functionality as `send`

-------------

#### waterfall::duplicate::set_ttl_raw

`pub fn set_ttl_raw(mut socket: &TcpStream, ttl: u8)`

Sets TTL for a TcpStream using appropriate library for the platform.

--------------

#### waterfall::duplicate::send

`pub fn send(mut socket: &TcpStream, packet: Vec<u8>) -> Result<(), std::io::Error>`

```
/// Duplicate module sends the packet 2 times as the result.
/// It's done by setting low TTL/Hop-by-hop header to a low value.
/// Most routers will send the packet and after it's TTL expires
/// The packet will be re-sent. Our target is to simulate packet loss
/// Via it's corruption.
```

--------------

#### waterfall::net::write_oob

`pub fn write_oob(socket: &TcpStream, oob_char: u8)`

Writes a single OOB char.

-----------

#### waterfall::net::write_oob_multiplex

`pub fn write_oob_multiplex(socket: &TcpStream, oob_data: Vec<u8>)`

Writes a data to the socket, the last byte is automatically sent as out of band.

------------

#### waterfall::parsers::parsers::IpParser

public fields:

 pub host_raw: Vec<u8>,
 
 pub host_unprocessed: Vec<u8>,
 
 pub port: u16,
 
 pub dest_addr_type: u8

public methods:
  `pub fn parse(buffer: Vec<u8>) -> IpParser`

host_raw - Host, extracted from the buffer and processed by the parser. 

  Rather Ipv4 or Ipv6 address.
  
host_unprocessed - Host, extracted from buffer.

  May be ipv4, ipv6 or a domain.
  
port - Parsed from buffer port.

dest_addr_type - Address type given by the client through socks5 proxy.

  1 => ipv4
  
  3 => domain
  
  4 => ipv6

### parse method

Parses IP related info from socks5 address packet.

------------

#### waterfall::socks::socks5_proxy

`pub fn socks5_proxy(proxy_client: &mut TcpStream, client_hook: impl Fn(&TcpStream, &[u8]) -> Vec<u8> + std::marker::Sync + std::marker::Send + 'static)`

Processes TcpStream as socks5 proxy, when client sends a message, client_hook callback is called.



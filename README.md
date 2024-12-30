# Waterfall
> This project is in active development. If you're looking for actually working DPI bypass, refer to [zapret](<https://github.com/bol-van/zapret>) and [byedpi](<https://github.com/hufrea/byedpi>)

High level deep packet inspection bypass utility with multiple strategies that can be used together.

This project uses SOCKS5 Proxy to capture packets, but it's not a huge problem, since in Rust you can save TcpSream as raw socket or file descriptor.

## Introduction

Blocking websites by IP address had became a bad practice over time. Such limitations can cause non-related websites to be blocked too. As attempts to block telegram in far tike ago showed that blocking websites by IP can lead to consequences and is ineffective — Deep packet inspection had been brought into the work.
Nowadays, ISPs put devices to complain with the censorship laws in many countries, filter malicious traffic and prevent potential online threats. This tool helps to bypass one of these deep packet inspection usages - Censorship

> Important information will come!
> If you don’t read it, you will likely seek for configurations done by other people.
> Don’t get into that trap! DPI Bypass configurations are different for every ISP.

## Bypass methods

> Most of methods in Waterfall are directed at TCP protocol

### Desynchronization attacks

How would you implement deep packet inspection? For sure, set up a gateway between router and the ISP, and then filter each IP packet.

This is exactly what Russian or Chinese DPI does. However, this method doesn't account for fragmented packets on both IP and applicated protocol level. Waterfall implements much strategies targeted at exploiting this vulnerability.

1. TCP Stream segmentation.

This method has the least drawback on performance, and the least efficiency on practice.

The idea comes from reversing Nagle's alghoritm. If Nagle's Alghoritm merges segments, Split module will split them.

This method will not work if the DPI tries to recover applicated protocol packet.

Deep packet inspection will see the stream like this:
```
|----------|----------|
|  [DATA]  |  [DATA1] |
|----------|----------|
```
2. Data disordering

This method is a modification of tcp segmentation with an extension which's idea is to corrupt first segment on packet level. 
As the result, the first segment will be automatically re-sent. 

This method is way harder to be set up, since you'll have to configure TTL/Hop-by-hop options for packet that will be re-sent.

You'll have to configure --disorder_packet_ttl parameter to make it work.

Disorder has 2 variations.

--disorder will fragment data and send them in reverse order. Use it if you're dealing with UDP or TCP.

--disorder_ttlc will segment data and set low TTL for first segment. Use it if you're dealing with TCP.

Deep packet inspection will see the stream like this:
```
|----------|-----------|-----------|----------|
|  [DATA - CORRUPTED]  |  [DATA1]  |  [DATA]  |
|----------|-----------|-----------|----------|
```
3. Sending fake data 

This method is data disordering with an extension that sends a fake data after first segment was sent. If you pass this option multiple times, you will be able to spam data with fakes.

This option is really hard to use, but it has highest efficiency on practice.

Your target is to use options like --fake_packet_ttl and --fake_as_oob to make fake packets not to reach the server, but reach DPI.

The --fake_ttlc variation sends corrupted UDP datagram or writes corrupted TCP data.

The --fake variation simulates IP fragmentation and sends fake data via raw socket.

Deep packet inspection will see the stream as follows:
```
|----------|-----------|-----------------|-----------|----------|
|  [DATA - CORRUPTED]  |  [FAKE OF DATA] |  [DATA1]  |  [DATA]  |
|----------|-----------|-----------------|-----------|----------|
```
4. Fake via OOB

This method is same as split, but a fake OOB data will be send in between these segments. This method will work only when the DPI doesn't ignore Out of band bytes.

Deep packet inspection will see the stream as following:
```
|----------|------------------|-----------|
|  [DATA]  | OUT OF BAND DATA |  [DATA1]  |
|----------|------------------|-----------|
```
5. Disordered fake via OOB

This method is same as Fake via OOB, but first segment is corrupted.

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

- --fake 1+s --disorder 10+s
```
|--------------------|---------------|---------------------|----------------|
|  [DATA CORRUPTED]  |  [DATA FAKE]  |  [DATA1 CORRUPTED]  |  [DATA2 REAL]  |
|--------------------|---------------|---------------------|----------------|
```

--disoob 5+s --split 1+s --fake 1+s

Warning: this is a very complex case. The SNI will not likely by in the second part of the segment - therefore 1+s will have the same effect as 1+, because "s" will have usize index of 0.

```
|--------------------|---------------|-----------------------|------------------|-----------|
|  [DATA CORRUPTED]  |  [DATA OOB ]  |  [DATA1.5 CORRUPTED]  |  [DATA1.5 FAKE]  |  [DATA2]  |
|--------------------|---------------|-----------------------|------------------|-----------|
```

## Software limitations

You must consider limitations that currently waterfall has. If you want to contribute at solving these issues, feel free to pull request.

Currently Waterfall is incapable of:
- Bypassing DPI that perfectly reassembles TCP stream that the server will see. This includes caching proxies that can be used by the client or the ISP. This vulnerability is solved by using QUIC protocol, which Waterfall doesn't support right now because of multiple bugs.
- Fragment packets on IP level. This leads to UDP bypasses not being possible, therefore Waterfall won't use bypasses for QUIC. In plans to be fixed after bugs will be fixed.
- **Bug:** Doesn't support UDP. Issue of `crate::socks` module. Should be fixed.

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

--split [Offset] - Applies TCP stream segmentation
--disorder [Offset] - Applies TCP stream segmentation, corrupts first part
--disorder_ttlc [Offset] - Applies TCP stream segmentation, corrupts first part by changing it's TTL/Hop-by-hop value
--fake [Offset] - Applies TCP stream segmentation, corrupts first part and sends a duplicate of it with "yandex.ru" SNI
--fake_ttlc [Offset] - Applies TCP stream segmentation, corrupts first part by changing it's TTL/Hop-by-hop value and sends a duplicate of it with "yandex.ru" SNI, overriden data or fake HTTP preset.
  If present, otherwise, uses random bytes data with same length.
--oob [Offset] - Applies TCP stream segmentation.
  Sends Out-Of-Band byte with value of '213' between these segments.
--disoob [Offset] - Applies TCP stream segmentation, corrupts first part.
  Sends Out-Of-Band byte with value of '213' between these segments.
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

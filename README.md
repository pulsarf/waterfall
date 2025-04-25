# Waterfall

A deep packet inspection bypass proxy

## Introduction

This tool helps to bypass censorship caused by deep packet inspection

## CMD line

```
./waterfall [OPTION] [VALUE]

[Offset] format: N+[s]?
  N = signed 32-bit integer
  s = SNI Index (optional)
Examples: 1+, 5+s, 13+s

--bind_host                        String  Bind SOCKS5 Proxy to specified host
--bind_port                        U16     Bind SOCKS5 Proxy to specified port

--default_ttl                      U8      Default TTL value for adequate packets
--fake_packet_ttl                  U8      Default TTL for packets that should reach ONLY DPI
--disorder_packet_ttl              U8      Default TTL for packets that SHOULD BE RESENT

--fake_packet_sni                  String  Server name identification for fake packets

--fake_packet_send_http                    Set to mimic HTTP packets (tricks DPI)
                                           Can force DPI to skip next packets

--fake_packet_host                 String  Fake host for fake packets (DPI trick)
--fake_packet_override_data        String  Override default packet data for fake packets

--fake_as_oob                              Force fake packets as Out-of-band data
                                           May break some websites like OOB module
                                           Useful when DPI looks for OOB data

--fake_packet_reversed                     Send fake packets in reversed order
--fake_packet_double                       Send two fake packets instead of one
--fake_packet_random                       Send random fake packets

--send_fake_clienthello                    Send fake clienthello for each found SNI

--fc_sni                           SNI     Set fake clienthello SNI

--disable_sack                             Disable selective acknowledgment
                                           Fixes fake packet retransmission issues

--whitelist_sni                    SNI     Add SNI domain to whitelist
                                           Whitelist disabled by default when unspecified

--packet_hop                       U64     Apply traffic modifications only to
                                           specified number of packets

--http_host_cmix                           Mix Host header case in HTTP
--http_host_rmspace                        Remove space after Host: header in HTTP
--http_host_space                          Add space after Host: header in HTTP
--http_domain_cmix                         Mix case in HTTP domain

--oob_stream_hell_data             String  Set data for OOB stream hell

--tcp_split                        Offset  Apply TCP stream segmentation
                                           Strategy dropped if offset inapplicable

--tcp_disorder                     Offset  Segment and corrupt first part (TTL=1)
                                           First segment won't reach server
                                           Adds ping-equivalent delay
                                           Strategy dropped if offset inapplicable

--tcp_fake_disordered              Offset  Segment, corrupt and send duplicate

--tcp_fake_insert                  Offset  Segment and insert fake packet between

--tcp_out_of_band                  Offset  Segment and send OOB byte at end

--tcp_out_of_band_disorder         Offset  Segment, corrupt and send OOB byte

--tcp_out_of_band_hell             Offset  Segment and spam OOB data between

--tls_record_frag                  Offset  Fragment TLS headers
                                           See: https://upb-syssec.github.io/blog/2023/record-fragmentation/
```

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

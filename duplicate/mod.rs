
/// Duplicate module sends the packet 2 times as the result.
/// It's done by setting low TTL/Hop-by-hop header to a low value.
/// Most routers will send the packet and after it's TTL expires
/// The packet will be re-sent. Our target is to simulate packet loss
/// Via it's corruption.

use std::net::TcpStream;
use std::io::Write;
use crate::core;

pub fn send(mut socket: &TcpStream, packet: Vec<u8>) -> Result<(), std::io::Error> {
  let conf: core::AuxConfig = core::parse_args();

  socket.set_ttl(conf.disorder_packet_ttl.into())?;
  socket.write_all(&packet.as_slice())?;
  socket.set_ttl(conf.default_ttl.into())?;

  Ok(())
}

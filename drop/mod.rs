use std::net::TcpStream;
use std::io::Write;
use crate::core;

pub fn send(mut socket: &TcpStream, data: Vec<u8>) -> Result<(), std::io::Error> {
  let conf: core::AuxConfig = core::parse_args();

  socket.set_ttl(conf.fake_packet_ttl.into())?;
  socket.write_all(&data)?;
  socket.set_ttl(conf.default_ttl.into())?;

  Ok(())
}

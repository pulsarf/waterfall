use std::net::TcpStream;
use std::io::Write;

pub fn send(mut socket: &TcpStream, data: Vec<u8>) -> Result<(), std::io::Error> {
  socket.set_ttl(2)?;
  socket.write_all(&data)?;
  socket.set_ttl(100)?;

  Ok(())
}

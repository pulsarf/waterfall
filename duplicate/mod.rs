
/// Duplicate module sends the packet 2 times as the result.
/// It's done by setting low TTL/Hop-by-hop header to a low value.
/// Most routers will send the packet and after it's TTL expires
/// The packet will be re-sent. Our target is to simulate packet loss
/// Via it's corruption.

use std::net::TcpStream;
use std::io;
use std::io::Write;
use crate::core;

#[cfg(unix)]
pub fn set_ttl_raw(stream: &TcpStream, ttl: u32) -> io::Result<()> {
  use libc;
  use std::os::unix::io::AsRawFd;
  use libc::{setsockopt, IP_TTL, IPPROTO_IP, IPV6_UNICAST_HOPS, IPPROTO_IPV6};

  let fd = stream.as_raw_fd();
  
  unsafe {
    libc::setsockopt(fd, IPPROTO_IP, IP_TTL,
      &ttl as *const _ as *const libc::c_void, std::mem::size_of_val(&ttl) as libc::socklen_t);
    libc::setsockopt(fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS,
      &ttl as *const _ as *const libc::c_void, std::mem::size_of_val(&ttl) as libc::socklen_t);
  };

  Ok(())
}

#[cfg(target_os = "windows")]
pub fn set_ttl_raw(stream: &TcpStream, ttl: u32) -> io::Result<()> {
  use winapi::um::winsock2::{setsockopt};
  use winapi::shared::ws2def::{IPPROTO_IP, IPPROTO_IPV6};
  use winapi::shared::ws2ipdef::{IP_TTL, IPV6_UNICAST_HOPS};

  use std::os::windows::io::AsRawSocket;

  let socket = stream.as_raw_socket();
  
  unsafe {
    setsockopt(socket as _, IPPROTO_IP, IP_TTL, &ttl as *const _ as *const i8, std::mem::size_of_val(&ttl) as i32);
    setsockopt(socket as _, IPPROTO_IPV6.try_into().unwrap(), IPV6_UNICAST_HOPS, &ttl as *const _ as *const i8, std::mem::size_of_val(&ttl) as i32);
  };

  Ok(())
}

pub fn send(mut socket: &TcpStream, packet: Vec<u8>) -> Result<(), std::io::Error> {
  let conf: core::AuxConfig = core::parse_args();

  set_ttl_raw(&socket, 1);
  socket.write_all(&packet.as_slice())?;
  set_ttl_raw(&socket, conf.default_ttl.into());

  Ok(())
}

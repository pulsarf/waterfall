
/// Duplicate module sends the packet 2 times as the result.
/// It's done by setting low TTL/Hop-by-hop header to a low value.
/// Most routers will send the packet and after it's TTL expires
/// The packet will be re-sent. Our target is to simulate packet loss
/// Via it's corruption.

use std::net::TcpStream;
use std::io::Write;
use crate::core;

pub fn set_ttl_raw(mut socket: &TcpStream, ttl: u8) {
  #[cfg(target_os = "linux")]
  if cfg!(unix) {
    #[cfg(target_os = "linux")]
    use libc::{setsockopt, IP_TTL, IPPROTO_IP};
    #[cfg(target_os = "linux")]
    use std::os::unix::io::{AsRawFd, RawFd};

    #[cfg(target_os = "linux")]
    let fd = socket.as_raw_fd();

    #[cfg(target_os = "linux")]
    let _ = unsafe { 
      #[cfg(target_os = "linux")]
      setsockopt(fd, IPPROTO_IP, IP_TTL, &ttl as *const _ as *const libc::c_void, std::mem::size_of::<c_int>() as c_int);
    };
  } else if cfg!(windows) {
    #[cfg(target_os = "windows")]
    use winapi::um::winsock2::{setsockopt, IP_TTL, IPPROTO_IP, SOCKET, SOCK_STREAM};
    #[cfg(target_os = "windows")]
    use std::os::windows::io::{AsRawSocket, RawSocket};
    #[cfg(target_os = "windows")]
    use std::ptr;

    #[cfg(target_os = "windows")]
    let rs: RawSocket = socket.as_raw_socket();

    #[cfg(target_os = "windows")]
    let result = unsafe {
      setsockopt(
        rs as SOCKET,
        IPPROTO_IP,
        IP_TTL,
        &ttl as *const i32 as *const _,
        std::mem::size_of::<i32>() as i32
      )
    };
  }
}

pub fn send(mut socket: &TcpStream, packet: Vec<u8>) -> Result<(), std::io::Error> {
  let conf: core::AuxConfig = core::parse_args();

  set_ttl_raw(&socket, conf.disorder_packet_ttl.into());
  socket.write_all(&packet.as_slice())?;
  set_ttl_raw(&socket, conf.default_ttl.into());

  Ok(())
}

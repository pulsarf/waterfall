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

pub fn raw_send(mut socket: &TcpStream, data: Vec<u8>) {
  let conf: core::AuxConfig = core::parse_args();
  let _ = socket.set_ttl(conf.fake_packet_ttl.into());

  let mut fake_data = vec![255, 255, 1, 127, 0, 0, 1, 136, 0, 0, 0, 0, 0, 16, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0];

  fake_data.extend_from_slice(data.as_slice());

  if cfg!(unix) {
    #[cfg(target_os = "linux")]
    use libc::{c_int, send, MSG_OOB};
    #[cfg(target_os = "linux")]
    use std::os::unix::io::{AsRawFd, RawFd};

    #[cfg(target_os = "linux")]
    let fd = socket.as_raw_fd();

    #[cfg(target_os = "linux")]
    let _ = unsafe {
      #[cfg(target_os = "linux")]
      send(fd, (&data.as_slice()).as_ptr() as *const _, 1, if conf.fake_as_oob { MSG_OOB } else { 0 });
    };
  } else if cfg!(windows) {
    #[cfg(target_os = "windows")]
    use winapi::um::winsock2::{send, MSG_OOB};
    #[cfg(target_os = "windows")]
    use std::os::windows::io::{AsRawSocket, RawSocket};

    #[cfg(target_os = "windows")]
    let rs: RawSocket = socket.as_raw_socket();

    #[cfg(target_os = "windows")]
    let _ = unsafe {
      #[cfg(target_os = "windows")]
      send(rs.try_into().unwrap(), (&fake_data.as_slice()).as_ptr() as *const _, 1, if conf.fake_as_oob { MSG_OOB } else { 0 });
    };
  } else {
    panic!("Unsupported OS type! Cannot use Out-Of-Band/Disordered Out-Of-Band");
  }

  let _ = socket.set_ttl(conf.default_ttl.into());
}

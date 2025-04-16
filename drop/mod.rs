use std::net::TcpStream;
use crate::core;
use crate::duplicate;

pub fn raw_send(socket: &TcpStream, data: Vec<u8>) {
  let conf: core::AuxConfig = core::parse_args();
  let _ = duplicate::set_ttl_raw(&socket, conf.fake_packet_ttl.into());

  if cfg!(unix) {
    #[cfg(target_os = "linux")]
    use libc::{send, MSG_OOB};
    #[cfg(target_os = "linux")]
    use std::os::unix::io::{AsRawFd};

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
      send(rs.try_into().unwrap(), (&data.as_slice()).as_ptr() as *const _, 1, if conf.fake_as_oob { MSG_OOB } else { 0 });
    };
  } else {
    panic!("Unsupported OS type! Cannot use Fake module");
  }

  let _ = duplicate::set_ttl_raw(&socket, conf.default_ttl.into());
}

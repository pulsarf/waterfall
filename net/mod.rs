use std::net::TcpStream;

pub fn write_oob_multiplex(socket: &TcpStream, oob_data: Vec<u8>) {
  let data1 = oob_data.as_slice();
  let oob_len = oob_data.len();

  if cfg!(unix) {
    #[cfg(unix)]
    use libc::{send, MSG_OOB};
    #[cfg(unix)]
    use std::os::unix::io::{AsRawFd};

    #[cfg(unix)]
    let fd = socket.as_raw_fd();

    #[cfg(unix)]
    let _ = unsafe {
      #[cfg(unix)]
      send(fd, data1.as_ptr() as *const _, oob_len.try_into().unwrap(), MSG_OOB);
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
      send(rs.try_into().unwrap(), data1.as_ptr() as *const _, oob_len.try_into().unwrap(), MSG_OOB);
    };
  } else {
    panic!("Unsupported OS type! Cannot use Out-Of-Band/Disordered Out-Of-Band");
  }
}
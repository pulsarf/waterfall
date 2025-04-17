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

pub fn disable_sack(socket: &TcpStream) {
  if cfg!(unix) {
    #[cfg(unix)]
    use libc::{setsockopt, IPPROTO_TCP, TCP_SACK};
    #[cfg(unix)]
    use std::os::unix::io::AsRawFd;

    #[cfg(unix)]
    let fd = socket.as_raw_fd();

    #[cfg(unix)]
    let disable: libc::c_int = 0;

    #[cfg(unix)]
    let _ = unsafe {
      setsockopt(
        fd,
        IPPROTO_TCP,
        TCP_SACK,
        &disable as *const _ as *const libc::c_void,
        std::mem::size_of_val(&disable) as libc::socklen_t
      )
    };
  } else if cfg!(windows) {
    #[cfg(windows)]
    use winapi::shared::ws2def::{IPPROTO_TCP, TCP_NODELAY};
    #[cfg(windows)]
    use winapi::um::ws2tcpip::socklen_t;
    #[cfg(windows)]
    use winapi::um::winsock2::setsockopt;
    #[cfg(windows)]
    use std::os::windows::io::AsRawSocket;

    #[cfg(windows)]
    let socket_handle = socket.as_raw_socket() as winapi::um::winsock2::SOCKET;

    #[cfg(windows)]
    let disable: i32 = 1; // 1 = enable TCP_NODELAY (closest available option)

    #[cfg(windows)]
    let _ = unsafe {
      setsockopt(
        socket_handle,
        IPPROTO_TCP as i32,
        TCP_NODELAY as i32,
        &disable as *const _ as *const winapi::ctypes::c_char,
        std::mem::size_of_val(&disable) as socklen_t
      )
    };
  } else {
    panic!("Unsupported OS type! Cannot disable SACK.");
  }
}

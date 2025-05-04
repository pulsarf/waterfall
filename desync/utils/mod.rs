
pub mod utils {
  use curl::easy::Easy;
  use serde_json;
  use std::net::TcpStream;
  use crate::core;
  use std::io;
  use std::io::Write;

  use std::net::{IpAddr};

  #[derive(Debug, Clone)]
  pub struct IpParser<'a> {
    pub host_raw: Vec<u8>,
    pub host_unprocessed: &'a [u8],
    pub port: u16,
    pub dest_addr_type: u8,
    pub is_udp: bool,
  }

  impl IpParser<'_> {
    pub fn parse(buffer: &[u8]) -> IpParser {
      let dest_addr_type = buffer[3];
      let is_udp = buffer[1] == 0x03;

      match dest_addr_type {
        1 => {
          if buffer.len() < 10 {
            return IpParser {
              dest_addr_type,
              host_raw: vec![0, 0, 0, 0],
              host_unprocessed: &[0, 0, 0, 0],
              port: 0,
              is_udp
            };
          }
          IpParser {
            dest_addr_type,
            host_raw: buffer[4..8].to_vec(),
            host_unprocessed: &buffer[4..8],
            port: u16::from_be_bytes([buffer[8], buffer[9]]),
            is_udp
          }
        },
        3 => {
          let domain_length = buffer[4] as usize;

          let domain = &buffer[5..5 + domain_length];
          let port = u16::from_be_bytes([buffer[5 + domain_length], buffer[6 + domain_length]]);
 
          if let Ok(domain_str) = std::str::from_utf8(domain) {
            if let Ok(ip_addr) = domain_str.parse::<IpAddr>() {
              let ip_buffer = match ip_addr {
                  IpAddr::V4(ip) => ip.octets().to_vec(),
                  IpAddr::V6(ip) => ip.octets().to_vec(),
              };

              return IpParser {
                dest_addr_type,
                host_raw: ip_buffer,
                host_unprocessed: &domain,
                port,
                is_udp
              };
            }

            if let Ok(ip) = doh_resolver(domain_str.to_string()) {
              if let Ok(ip_addr) = ip.parse::<IpAddr>() {
                let ip_buffer = match ip_addr {
                  IpAddr::V4(ip) => ip.octets().to_vec(),
                  IpAddr::V6(ip) => ip.octets().to_vec(),
                };

                return IpParser {
                  dest_addr_type,
                  host_raw: ip_buffer,
                  host_unprocessed: &domain,
                  port,
                  is_udp
                };
              }
            }
          }

          IpParser {
            dest_addr_type,
            host_raw: vec![0, 0, 0, 0],
            host_unprocessed: &domain,
            port,
            is_udp
          }
        },
        4 => {
          if buffer.len() < 22 {
            return IpParser {
              dest_addr_type,
              host_raw: vec![0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
              host_unprocessed: &[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
              port: 0,
              is_udp
            };
          }
          IpParser {
            dest_addr_type,
            host_raw: buffer[4..20].to_vec(),
            host_unprocessed: &buffer[4..20],
            port: u16::from_be_bytes([buffer[20], buffer[21]]),
            is_udp
          }
        },
        _ => {
          IpParser {
            dest_addr_type,
            host_raw: [0, 0, 0, 0].to_vec(),
            host_unprocessed: &[0, 0, 0, 0],
            port: 0,
            is_udp
          }
        }
      }
    }
  }

  #[cfg(unix)]
  pub fn set_ttl_raw(stream: &TcpStream, ttl: u32) -> io::Result<()> {
    use libc;
    use std::os::unix::io::AsRawFd;
    use libc::{IP_TTL, IPPROTO_IP, IPV6_UNICAST_HOPS, IPPROTO_IPV6};

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

  pub fn send_duplicate(mut socket: &TcpStream, packet: Vec<u8>) -> Result<(), std::io::Error> {
    let conf: core::AuxConfig = core::parse_args();

    let _ = set_ttl_raw(&socket, 1);
    let _ = socket.write_all(&packet.as_slice())?;
    let _ = set_ttl_raw(&socket, conf.default_ttl.into());

    Ok(())
  }

  #[cfg(unix)]
  pub fn send_drop(socket: &TcpStream, data: Vec<u8>) {
    let conf: core::AuxConfig = core::parse_args();
    let _ = set_ttl_raw(&socket, conf.fake_packet_ttl.into());

    if cfg!(unix) {
        use libc::{send, MSG_OOB};
        use std::os::unix::io::{AsRawFd};

        let fd = socket.as_raw_fd();

        let _ = unsafe {
            send(fd, (&data.as_slice()).as_ptr() as *const _, 1, if conf.fake_as_oob { MSG_OOB } else { 0 });
        };
      } 

      let _ = set_ttl_raw(&socket, conf.default_ttl.into());
  }

  #[cfg(windows)]
  pub fn send_drop(socket: &TcpStream, data: Vec<u8>) {
      let conf: core::AuxConfig = core::parse_args();
      let _ = set_ttl_raw(&socket, conf.fake_packet_ttl.into());

      use winapi::um::winsock2::{send, MSG_OOB};
      use std::os::windows::io::{AsRawSocket, RawSocket};

      let rs: RawSocket = socket.as_raw_socket();

      let _ = unsafe {
        send(rs.try_into().unwrap(), (&data.as_slice()).as_ptr() as *const _, 1, if conf.fake_as_oob { MSG_OOB } else { 0 });
      };

      let _ = set_ttl_raw(&socket, conf.default_ttl.into());
  }

  pub fn check_whitelist(config: &Option<Vec<String>>, sni_data: &(u32, u32), data: &[u8]) -> bool {
    if let Some(whitelist_sni_list) = config {
        if sni_data != &(0, 0) {
          let start = sni_data.0 as usize;
          let end = sni_data.1 as usize;

          if data.len() <= end {
              return false;
          }

          let sni_slice = &data[start..end];

          let sni_string: String = String::from_utf8_lossy(sni_slice).to_string(); 

          if whitelist_sni_list.iter().position(|r| sni_string.contains(r)).is_none() {
            return false;
          }
        }

        if sni_data == &(0, 0) {
          return false;
        }
    }

    return true;
  }

  pub fn slice_packet(source: Vec<u8>, index: u64) -> Vec<Vec<u8>> {
    let mut current_index: u64 = 0;

    let mut alpha: Vec<u8> = Vec::new();
    let mut beta: Vec<u8> = Vec::new();

    for byte in source {
      if current_index >= index {
        alpha.push(byte);
      } else {
        beta.push(byte);
      }

      current_index += 1;
    }

    vec![beta, alpha]
  }

  pub struct Random {
      last_num: u32,

      magic_mul: u32,
      magic_add: u32
  }

  impl Random {
      pub fn new(initial: u32) -> Self {
          Self { 
              last_num: initial,
              magic_mul: 1664525,
              magic_add: 1013904223
          }
      }

      fn clamp_low_bits(&self, num: &u32) -> u32 {
          num >> 16
      }

      pub fn next_rand(&mut self) -> u8 {
          self.last_num = self.last_num
              .wrapping_mul(self.magic_mul)
              .wrapping_add(self.magic_add);

          self.clamp_low_bits(&self.last_num) as u8
      }
  }

  pub fn make_random_vec(len: usize, seed: u32) -> Vec<u8> {
      let mut rand: Random = Random::new(seed);

      (0..len).map(|_| rand.next_rand()).collect()
  }

  pub fn parse_sni_index(source: Vec<u8>) -> (u32, u32) {
      if source.is_empty() || source[0] != 0x16 { return (0, 0) };
      if source.len() < 48 { return (0, 0) };
      if source.len() <= 5 || source[5] != 0x01 { return (0, 0) };

      (0..source.len().saturating_sub(8)).find_map(|i| {
          if source[i] == 0x00 && source[i + 1] == 0x00 && source[i + 7] == 0x00 && (source[i + 3] as isize - source[i + 5] as isize) == 2 {
              let len = source[i + 8] as usize;

              let start = i + 9;
              let end = start + len as usize;
            
              if end <= source.len() && len > 0 && len < 256 {
                  return Some((start as u32, end as u32));
              }
          }

          None
      }).unwrap_or((0, 0))
  }

  fn get_first_ip(response_data: Vec<u8>) -> Result<String, String> {
    serde_json::from_str::<serde_json::Value>(&match String::from_utf8(response_data) {
      Ok(res) => res,
      Err(_) => return Err("Malformed request body".to_string()),
    })
    .map_err(|_| "JSON Parse error".to_string())
    .and_then(|json| {
      json.get("Answer")
        .and_then(|answers| answers.as_array().cloned())
        .ok_or("Malformed Answer".to_string())
    })
    .and_then(|answers| {
      answers
        .iter()
        .find_map(|answer| {
          answer
            .get("data")
            .and_then(|data| data.as_str())
            .filter(|data| data.parse::<std::net::IpAddr>().is_ok())
            .map(|ip| ip.to_string())
        })
        .ok_or("400".to_string())
    })
  }

  pub fn doh_resolver(domain: String) -> Result<String, std::string::String> {
      let cf_dns: &str = "https://dns.google/resolve?name={}&type=A";

      let mut easy = Easy::new();
      let mut response_data = Vec::new();

      easy.url(&cf_dns.replace("{}", &domain)).map_err(|n| n.to_string())?;

      easy.http_headers({
          let mut headers = curl::easy::List::new();
          headers.append("accept: application/dns-json").map_err(|n| n.to_string())?;

          headers
      }).map_err(|n| n.to_string())?;
  
      let mut transfer = easy.transfer();

      transfer.write_function(|data| {
          response_data.extend_from_slice(data);
          Ok(data.len())
      }).map_err(|n| n.to_string())?;

      transfer.perform().map_err(|n| n.to_string())?;

      drop(transfer);

      crate::utils::get_first_ip(response_data)
  }

  #[cfg(unix)]
  pub fn write_oob_multiplex(socket: &TcpStream, oob_data: Vec<u8>) {
    use libc::{send, MSG_OOB};
    use std::os::unix::io::{AsRawFd};

    let data1 = oob_data.as_slice();
    let oob_len = oob_data.len();

    let fd = socket.as_raw_fd();

    let _ = unsafe {
        send(fd, data1.as_ptr() as *const _, oob_len.try_into().unwrap(), MSG_OOB);
    };
  }

  #[cfg(target_os="windows")]
  pub fn write_oob_multiplex(socket: &TcpStream, oob_data: Vec<u8>) {
      use winapi::um::winsock2::{send, MSG_OOB};
      use std::os::windows::io::{AsRawSocket, RawSocket};

      let data1 = oob_data.as_slice();
      let oob_len = oob_data.len();

      let rs: RawSocket = socket.as_raw_socket();

      let _ = unsafe {
        send(rs.try_into().unwrap(), data1.as_ptr() as *const _, oob_len.try_into().unwrap(), MSG_OOB);
      };
  }
  
  #[cfg(unix)]
  pub fn disable_sack(socket: &TcpStream) {
      use libc::{setsockopt, IPPROTO_TCP};
      use std::os::unix::io::AsRawFd;

      let fd = socket.as_raw_fd();

      let filter: [libc::sock_filter; 7] = [
          libc::sock_filter { code: 0x30, jt: 0, jf: 0, k: 0x0000000c },
          libc::sock_filter { code: 0x74, jt: 0, jf: 0, k: 0x00000004 },
          libc::sock_filter { code: 0x35, jt: 3, jf: 0, k: 0x0000000b },
          libc::sock_filter { code: 0x30, jt: 0, jf: 0, k: 0x00000022 },
          libc::sock_filter { code: 0x15, jt: 1, jf: 0, k: 0x00000005 },
          libc::sock_filter { code: 0x6,  jt: 0, jf: 0, k: 0x00000000 },
          libc::sock_filter { code: 0x6,  jt: 0, jf: 0, k: 0x00040000 },
      ];

      let bpf = libc::sock_fprog {
          len: filter.len() as libc::c_ushort,
          filter: filter.as_ptr() as *mut libc::sock_filter,
      };

      let _ = unsafe {
          setsockopt(
              fd,
              libc::SOL_SOCKET,
              libc::SO_ATTACH_FILTER,
              &bpf as *const _ as *const libc::c_void,
              std::mem::size_of_val(&bpf) as libc::socklen_t
          )
      };
  }

  #[cfg(windows)]
  pub fn disable_sack(socket: &TcpStream) {
      use winapi::shared::ws2def::{IPPROTO_TCP, TCP_NODELAY};
      use winapi::um::ws2tcpip::socklen_t;
      use winapi::um::winsock2::setsockopt;
      use std::os::windows::io::AsRawSocket;

      let socket_handle = socket.as_raw_socket() as winapi::um::winsock2::SOCKET;

      let disable: i32 = 1; // 1 = enable TCP_NODELAY (closest available option)

      let _ = unsafe {
          setsockopt(
              socket_handle,
              IPPROTO_TCP as i32,
              TCP_NODELAY as i32,
              &disable as *const _ as *const winapi::ctypes::c_char,
              std::mem::size_of_val(&disable) as socklen_t
          )
      };
  }

}

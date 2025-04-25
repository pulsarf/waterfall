pub mod parsers {
  use std::net::{IpAddr};
  use crate::utils::doh_resolver;

  #[derive(Debug, Clone)]
  pub struct IpParser {
    pub host_raw: Vec<u8>,
    pub host_unprocessed: Vec<u8>,
    pub port: u16,
    pub dest_addr_type: u8,
    pub is_udp: bool,
  }

  impl IpParser {
    pub fn parse(buffer: Vec<u8>) -> IpParser {
      if buffer.len() < 10 {
        return IpParser {
          dest_addr_type: 0,
          host_raw: vec![],
          host_unprocessed: vec![],
          port: 0,
          is_udp: false
        };
      }

      let dest_addr_type = buffer[3];
      let is_udp = buffer[1] == 0x03;

      match dest_addr_type {
        1 => {
          if buffer.len() < 10 {
            return IpParser {
              dest_addr_type,
              host_raw: vec![0; 4],
              host_unprocessed: vec![0; 4],
              port: 0,
              is_udp
            };
          }
          IpParser {
            dest_addr_type,
            host_raw: buffer[4..8].to_vec(),
            host_unprocessed: buffer[4..8].to_vec(),
            port: u16::from_be_bytes([buffer[8], buffer[9]]),
            is_udp
          }
        },
        3 => {
          if buffer.len() < 5 {
            return IpParser {
              dest_addr_type,
              host_raw: vec![0; 4],
              host_unprocessed: vec![],
              port: 0,
              is_udp
            };
          }

          let domain_length = buffer[4] as usize;
          if buffer.len() < 5 + domain_length + 2 {
            return IpParser {
              dest_addr_type,
              host_raw: vec![0; 4],
              host_unprocessed: vec![],
              port: 0,
              is_udp
            };
          }

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
                host_unprocessed: domain.to_vec(),
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
                  host_unprocessed: domain.to_vec(),
                  port,
                  is_udp
                };
              }
            }
          }

          IpParser {
            dest_addr_type,
            host_raw: vec![0; 4],
            host_unprocessed: domain.to_vec(),
            port,
            is_udp
          }
        },
        4 => {
          if buffer.len() < 22 {
            return IpParser {
              dest_addr_type,
              host_raw: vec![0; 16],
              host_unprocessed: vec![0; 16],
              port: 0,
              is_udp
            };
          }
          IpParser {
            dest_addr_type,
            host_raw: buffer[4..20].to_vec(),
            host_unprocessed: buffer[4..20].to_vec(),
            port: u16::from_be_bytes([buffer[20], buffer[21]]),
            is_udp
          }
        },
        _ => {
          IpParser {
            dest_addr_type,
            host_raw: vec![],
            host_unprocessed: vec![],
            port: 0,
            is_udp
          }
        }
      }
    }
  }
}

pub mod parsers {
  #[derive(Debug, Clone)]
  pub struct IpParser {
    pub host_raw: Vec<u8>,
    pub port: u16,
    pub dest_addr_type: u8
  }

  impl IpParser {
    pub fn parse(buffer: Vec<u8>) -> IpParser {
      let dest_addr_type: u8 = buffer[1];

      return match dest_addr_type {
        1 => {
          IpParser {
            dest_addr_type,
            host_raw: vec![buffer[4], buffer[5], buffer[6], buffer[7]],
            port: 443u16
          }
        },
        _other => {
          IpParser {
            dest_addr_type,
            host_raw: vec![0, 0, 0, 0],
            port: 443u16
          }
        }
      }
    }
  }
}
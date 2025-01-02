use crate::core;
use crate::desync::utils::utils;

pub fn edit_http(mut data: Vec<u8>) -> Vec<u8> {
  let conf = core::parse_args();

  for iter in 0..data.len() {
    // Scan for HTTP

    if iter + 4 < data.len() &&
      data[iter] == 72 &&
      data[iter + 1] == 111 &&
      data[iter + 2] == 115 &&
      data[iter + 3] == 116 &&
      data[iter + 4] == 58 {
      if conf.http_host_cmix {
        data[iter + 1] = 79;
        data[iter + 3] = 84;
      }

      if conf.http_host_rmspace && data[iter + 5] == 32 {
        data.remove(iter + 5);
      }

      if conf.http_host_space {
        data.insert(iter + 5, 32);
      }

      if conf.http_domain_cmix {
        let b = std::str::from_utf8(&[data[iter + 6]]).expect("HOST detected but domain is wrong").to_uppercase();

        data[iter + 6] = b.as_bytes()[0];
      }
    }
  }

  data
}

pub fn edit_tls(mut data: Vec<u8>) -> Vec<u8> {
  let conf = core::parse_args();

  if conf.split_record_sni && data[0] == 0x16 && data[1] == 0x03 && data[2] == 0x01 {
    let (sni_start, sni_end) = utils::parse_sni_index(data.clone());
    
    if sni_start <= 0 || sni_start >= data.len().try_into().unwrap() {
      return data;
    }

    let reclen: [u8; 2] = ((sni_start + 2) as u16).to_be_bytes();
    
    data[3] = reclen[0];
    data[4] = reclen[1];

    let pointer: usize = (2 + 4 + sni_start).try_into().unwrap();
    let remaining = (data.len() as u16) - ((sni_start as u16) + 2 + 4 + 3);
    let bytes: [u8; 2] = remaining.to_le_bytes();

    data.insert(pointer, bytes[0]);
    data.insert(pointer, bytes[1]);

    data.insert(pointer, 0x01);
    data.insert(pointer, 0x03);
    data.insert(pointer, 0x16);
  }

  data
}


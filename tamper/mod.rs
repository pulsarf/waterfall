use crate::core;
use crate::desync::utils::utils;

pub fn edit_http(mut data: Vec<u8>) -> Vec<u8> {
  let conf = core::parse_args();

  for iter in 0..data.len() {
    // Scan for HTTP

    if data[iter] == 72 &&
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
    let point: usize = (4 + sni_start).try_into().unwrap();

    data[3] = 0;
    data[4] = sni_start as u8;

    data.insert(point, 0x16);
    data.insert(point, 0x03);
    data.insert(point, 0x01);
    
    data.insert(point, 0);
    data.insert(point, ((data.len() as u32) - sni_start).try_into().unwrap()); 
  }

  data
}

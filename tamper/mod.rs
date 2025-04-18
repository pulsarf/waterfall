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


fn as_record(data: Vec<u8>) -> Vec<u8> {
  let data_length: [u8; 2] = (data.len() as u16).to_be_bytes();
  let mut record: Vec<u8> = vec![0x16u8, 0x03u8, 0x01u8];
    
  record.extend(data_length);
  record.extend(data);
    
  record
}

pub fn edit_tls(mut data: Vec<u8>) -> Vec<u8> {
  let conf = core::parse_args();

  if conf.split_record_sni && data[0] == 0x16 && data[1] == 0x03 && data[2] == 0x01 {
    let (sni_start, _sni_end) = utils::parse_sni_index(data.clone());

    if sni_start <= 0 || sni_start >= data.len().try_into().unwrap() {
      return data;
    }

    let payload = data.split_off(5);
    let (first_part, second_part) = payload.split_at(sni_start as usize - 5);

    let record1 = as_record(first_part.to_vec());
    let record2 = as_record(second_part.to_vec());
        
    let mut result = record1;
    result.extend(record2);
        
    return result;
  }

  data
}

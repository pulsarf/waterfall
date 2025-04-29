use crate::core;

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


pub fn as_record(data: Vec<u8>) -> Vec<u8> {
  let data_length: [u8; 2] = (data.len() as u16).to_be_bytes();
  let mut record: Vec<u8> = vec![0x16u8, 0x03u8, 0x01u8];
    
  record.extend(data_length);
  record.extend(data);
    
  record
}

pub fn edit_tls(mut data: Vec<u8>, index: usize) -> Vec<u8> {
  if data[0] == 0x16 && data[1] == 0x03 && data[2] == 0x01 {
    let payload = data.split_off(5);
    let (first_part, second_part) = payload.split_at(index);

    let record1 = as_record(first_part.to_vec());
    let record2 = as_record(second_part.to_vec());
        
    let mut result = record1;
    result.extend(record2);
        
    return result;
  }

  data
}

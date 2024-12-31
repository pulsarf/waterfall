pub mod utils {
  pub fn aob_scan(target: Vec<u8>, source: Vec<u8>) -> usize {
    for (position, window) in source.windows(target.len()).enumerate() {
      if window == target {
        return position;
      }
    }

    return usize::MIN;
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

  // This is the laziest solution ever possible, but it works at least.
  // Assuming SNI size is less than u8
  pub fn parse_sni(source: Vec<u8>) -> String {
    let mut sni: String = String::from("");

    'label: for iter in 0..source.len() {
      if iter + 8 > source.len() {
        break 'label;
      }

      if source[iter] != 0 || source[iter + 1] != 0 {
        continue;
      }

      if ((source[iter + 3] as i8) - (source[iter + 5] as i8)).abs() != 2 {
        continue;
      }

      let hostname_size: usize = (((source[iter + 4] as u32) << 8) as u32 | (source[iter + 5] as u32)) as usize;

      for jter in (iter + 6)..(6 + iter + hostname_size) {
        if jter > source.len() {
          break;
        }

        match std::str::from_utf8(&[source[jter]]) {
          Ok(ch) => sni += &ch,
          Err(_) => continue 'label
        }
      }

      return sni;
    }

    sni
  }

  pub fn parse_sni_index(source: Vec<u8>) -> (u32, u32) {
    if source[0] != 0x16 { return (0, 0) };
    if source.len() < 48 { return (0, 0) };

    if source[5] != 0x01 {
      return (0, 0);
    }
 
    // 10 + 32 (client random) = 42. Session ID starts at index 43 for TLS 1.3
    // Max packet size possible is u32, since message length is u16 and 1 additional byte
    // will overflow to u32

    let mut offset: u32 = 43;

    offset += source[offset as usize] as u32;

    // Now we're at chipher suites. Skip over through these data. We don't need them to parse SNI.

    let cipher_suites_length: u16 = source[(offset + 1) as usize] as u16;

    offset += cipher_suites_length as u32;

    // Skip over compression methods and extensions length. Then we start an AOB scan for pattern [0x00, 0x00]

    offset += source[offset as usize] as u32;
    offset += 2;

    for iter in offset..(source.len() as u32) {
      if iter + 1 > source.len().try_into().unwrap() { break };

      if source[iter as usize] == 0x00 && source[(iter + 1) as usize] == 0x00 {
        // We had successfully found SNI offset! :happyhappyhappy_cat:

        let sni_length: u16 = source[(iter + 5) as usize] as u16;

        return (iter + 6, iter + 8 + sni_length as u32);
      }
    }

    (0, 0)
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_aob_scan_start() {
    let pattern_start: usize = utils::aob_scan(vec![0, 5], vec![0, 5, 6, 2]);

    assert_eq!(0 as usize, pattern_start);
  }

  #[test]
  fn test_aob_scan_middle() {
    assert_eq!(3 as usize, 
      utils::aob_scan(vec![16, 43], vec![78, 34, 22, 16, 43, 27]));
  }

  #[test]
  fn test_aob_scan_end() {
    assert_eq!(5 as usize,
      utils::aob_scan(vec![8, 1], vec![0, 0, 0, 0, 0, 8, 1]));
  }

  #[test]
  fn test_slice_packet() {
    let packet: Vec<u8> = vec![56, 78, 32];

    let split_packet: Vec<Vec<u8>> = utils::slice_packet(packet, 1);
  
    assert_eq!(vec![56], split_packet[0]);
    assert_eq!(vec![78, 32], split_packet[1]);
  }

  #[test]
  fn test_sni_parser() {
    let mut packet: Vec<u8> = vec![0, 0, 0];
    let sni: String = String::from("discord.com");
    let mut test_sni: Vec<u8> = sni.clone().into_bytes().to_vec();

    packet.append(&mut vec![0, 2 + test_sni.len() as u8, 0]);
    packet.append(&mut vec![test_sni.len() as u8]);
    packet.append(&mut test_sni);

    println!("{:?}", packet);

    assert_eq!(utils::parse_sni(packet), sni);
  }
}
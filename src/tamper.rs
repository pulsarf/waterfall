
mod tamper {
  pub fn aob_scan(target: Vec<u8>, source: Vec<u8>) -> usize {
    for (position, window) in source.windows(target.len()).enumerate() {
      if window == target {
        return position;
      }
    }

    return usize::MIN;
  }

  pub fn slice_packet(source: Vec<u8>, index: u8) -> Vec<Vec<u8>> {
    let mut current_index: u8 = 0;

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

  pub fn parse_sni(source: Vec<u8>) -> String {
    if super::tamper::aob_scan(vec![16, 3, 3, 0, 31], source.clone()) == 0 {
      let dyn_offset: u16 = 45u16 + ((source[44] as u16)) | (source[45] as u16);

      let static_offset_start: u16 = dyn_offset + 13u16;
      let static_offset_end: u16 = static_offset_start + source[static_offset_start as usize] as u16;

      let mut sni: String = String::from("");
      
      for iter in static_offset_start..static_offset_end {
        sni += &String::from_utf8_lossy(&[iter as u8]);
      }

      return sni;
    }

    return String::from("NULL.COM");
  }
}

#[cfg(test)]

mod tests {
  use super::*;

  #[test]

  fn test_aob_scan_start() {
    let pattern_start: usize = tamper::aob_scan(vec![0, 5], vec![0, 5, 6, 2]);

    assert_eq!(0 as usize, pattern_start);
  }

  #[test]

  fn test_aob_scan_middle() {
    assert_eq!(3 as usize, 
      tamper::aob_scan(vec![16, 43], vec![78, 34, 22, 16, 43, 27]));
  }

  #[test]

  fn test_aob_scan_end() {
    assert_eq!(5 as usize,
      tamper::aob_scan(vec![8, 1], vec![0, 0, 0, 0, 0, 8, 1]));
  }

  #[test]

  fn test_slice_packet() {
    let packet: Vec<u8> = vec![56, 78, 32];

    let split_packet: Vec<Vec<u8>> = tamper::slice_packet(packet, 1);
  
    assert_eq!(vec![56], split_packet[0]);
    assert_eq!(vec![78, 32], split_packet[1]);
  }

  #[test]

  fn test_sni_parser() {
    let packet: Vec<u8> = vec![];

    assert_eq!(tamper::parse_sni(packet), "google.com".to_owned());
  }
}

pub mod utils {
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
      if iter + 8 > source.len().try_into().unwrap() { break };

      if source[iter as usize] == 0x00 && source[(iter + 1) as usize] == 0x00 {
        // We had successfully found SNI offset! :happyhappyhappy_cat:

        let sni_length: u16 = source[(iter + 5) as usize] as u16;

        return (iter + 8, iter + 8 + sni_length as u32);
      }
    }

    (0, 0)
  }
}
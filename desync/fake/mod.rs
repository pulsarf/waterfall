
pub mod fake {
  pub fn get_split_packet(packet_buffer: &[u8], strategy: crate::core::Strategy) -> Vec<Vec<u8>> {
    use crate::desync::utils::utils;

    let (sni_start, sni_end) = utils::parse_sni_index(packet_buffer.to_vec());
    let middle: u64 = (strategy.base_index as u64) + if strategy.add_sni { ((sni_start + sni_end) / 2) as u64 } else { 0 };

    if middle < packet_buffer.to_vec().len().try_into().unwrap() && middle > 0 {
      let packet_parts: Vec<Vec<u8>> = utils::slice_packet(packet_buffer.to_vec(), middle);

      return packet_parts;
    } else {
      return vec![packet_buffer.to_vec()];
    }    
  }

  pub fn get_fake_http(host: String) -> String {
    return format!("GET / HTTP 1.1
Host: {:?}
Content-Type: text/html
Content-Length: 1
a", host).replace("\"", "").replace("\"", "");
  }

  pub fn get_fake_packet(mut packet: Vec<u8>) -> Vec<u8> {
    use crate::desync::utils::utils;
    use crate::core;

    let conf: core::AuxConfig = core::parse_args();

    if conf.fake_packet_override_data.active {
      return conf.fake_packet_override_data.data.clone();
    } else if conf.fake_packet_send_http {
      let fake_http: String = crate::fake::get_fake_http(conf.fake_packet_host);
      let bytes: Vec<u8> = Vec::from(fake_http.as_bytes());

      return bytes;
    } else {
      let (sni_start, sni_end) = utils::parse_sni_index(packet.clone());
      let fake_sni: Vec<String> = String::from(conf.fake_packet_sni)
        .chars()
        .map(|ch| String::from(ch))
        .collect();
      let mut sni_offset: u32 = 0;
    
      for iter in sni_start..sni_end {
        if sni_start + sni_offset + 1 > packet.len().try_into().unwrap() {
          break;
        }
        if iter + 1 > packet.len().try_into().unwrap() { break };
        if sni_offset + 1 > fake_sni.len().try_into().unwrap() { break };

        packet[iter as usize] = fake_sni[sni_offset as usize].as_bytes()[0];
        sni_offset += 1;
      }

      return packet.clone();
    }
  }
}

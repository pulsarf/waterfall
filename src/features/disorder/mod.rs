pub mod utils;

pub mod disorder {
  pub fn get_split_packet(packet_buffer: &[u8]) -> Vec<Vec<u8>> {
    use crate::features::disorder::utils::utils;

    let (sni_start, sni_end) = utils::parse_sni_index(packet_buffer.to_vec());
    let middle: u64 = ((sni_start + sni_end) / 2) as u64;

    if middle < packet_buffer.to_vec().len().try_into().unwrap() && middle > 0 {
      let packet_parts: Vec<Vec<u8>> = utils::slice_packet(packet_buffer.to_vec(), middle);

      return packet_parts;
    } else {
      return vec![packet_buffer.to_vec()];
    }    
  }
}
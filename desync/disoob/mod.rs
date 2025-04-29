
pub mod disoob {
  pub fn get_split_packet(packet_buffer: &[u8], strategy: crate::core::Strategy, sni_data: &(u32, u32)) -> Vec<Vec<u8>> {
    use crate::desync::utils::utils;

    let (sni_start, _sni_end) = sni_data;
    let middle: u64 = (strategy.base_index as u64) + if strategy.add_sni { *sni_start as u64 } else { 0 };

    if middle < packet_buffer.to_vec().len().try_into().unwrap() && middle > 0 {
      let packet_parts: Vec<Vec<u8>> = utils::slice_packet(packet_buffer.to_vec(), middle);

      return packet_parts;
    } else {
      return vec![packet_buffer.to_vec()];
    }    
  }
}

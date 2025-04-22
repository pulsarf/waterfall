
pub mod utils {
  use curl::easy::Easy;
  use std::io::{Read, Write};
  use serde_json;

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

  struct Random {
      last_num: u32,

      magic_mul: u32,
      magic_add: u32
  }

  impl Random {
      fn new(initial: u32) -> Self {
          Self { 
              last_num: initial,
              magic_mul: 1664525,
              magic_add: 1013904223
          }
      }

      fn clamp_low_bits(&self, num: &u32) -> u32 {
          num >> 16
      }

      fn next_rand(&mut self) -> u8 {
          self.last_num = self.last_num
              .wrapping_mul(self.magic_mul)
              .wrapping_add(self.magic_add);

          self.clamp_low_bits(&self.last_num) as u8
      }
  }

  pub fn make_random_vec(len: usize, seed: u32) -> Vec<u8> {
      let mut rand: Random = Random::new(seed);

      (0..len).map(|_| rand.next_rand()).collect()
  }

  pub fn is_english(byte: u8) -> bool {
      byte >= 97 && byte <= 123
  }

  pub fn parse_sni_index(source: Vec<u8>) -> (u32, u32) {
      if source.is_empty() || source[0] != 0x16 { return (0, 0) };
      if source.len() < 48 { return (0, 0) };
      if source.len() <= 5 || source[5] != 0x01 { return (0, 0) };

      for i in 0..source.len().saturating_sub(8) {
          if source[i] == 0x00 && source[i+1] == 0x00 {
              let len = ((source[i+5] as u32) << 8) | source[i+6] as u32;
              let start = i + 8;
              let end = start + len as usize;
            
              if end <= source.len() && len > 0 && len < 256 {
                  return (start as u32, end as u32);
              }
          }
      }
      
      (0, 0)
  }

  fn get_first_ip(response_data: Vec<u8>) -> Result<String, String> {
    serde_json::from_str::<serde_json::Value>(&match String::from_utf8(response_data) {
      Ok(res) => res,
      Err(_) => return Err("Malformed request body".to_string()),
    })
    .map_err(|_| "JSON Parse error".to_string())
    .and_then(|json| {
      json.get("Answer")
        .and_then(|answers| answers.as_array().cloned())
        .ok_or("Malformed Answer".to_string())
    })
    .and_then(|answers| {
      answers
        .iter()
        .find_map(|answer| {
          answer
            .get("data")
            .and_then(|data| data.as_str())
            .filter(|data| data.parse::<std::net::IpAddr>().is_ok())
            .map(|ip| ip.to_string())
        })
        .ok_or("400".to_string())
    })
  }

  pub fn doh_resolver(domain: String) -> Result<String, curl::Error> {
    let cf_dns: &str = "https://dns.google/resolve?name={}&type=A";

    let mut easy = Easy::new();
    let mut response_data = Vec::new();

    easy.url(&cf_dns.replace("{}", &domain))?;

    easy.http_headers({
      let mut headers = curl::easy::List::new();
      headers.append("accept: application/dns-json")?;

      headers
    })?;

    let mut transfer = easy.transfer();

    transfer.write_function(|data| {
      response_data.extend_from_slice(data);
      Ok(data.len())
    })?;

    transfer.perform()?;

    drop(transfer);

    Ok(crate::utils::get_first_ip(response_data).unwrap())
  }
}

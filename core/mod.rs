#[derive(Debug)]
pub enum Strategies {
  NONE,
  SPLIT,
  DISORDER,
  FAKE,
  OOB,
  DISOOB
}

#[derive(Debug)]
pub struct Strategy {
  pub method: Strategies,
  pub base_index: usize,
  pub add_sni: bool,
  pub add_host: bool
}

impl Strategy {
  pub fn from(first: String, second: String) -> Strategy {
    let mut strategy: Strategy = Strategy {
      method: Strategies::NONE,
      base_index: 0,
      add_sni: false,
      add_host: false
    };

    if second.contains("s") {
      strategy.add_sni = true;
    }

    if second.contains("h") {
      strategy.add_host = true;
    }

    if second.contains("+") {
      let parts: Vec<String> = second
        .split("+")
        .map(|str| String::from(str))
        .collect();
      
      match parts[0].parse::<u64>() {
        Ok(res) => {
          strategy.base_index = res as usize;
        },
        Err(_) => { }
      };
    };

    strategy.method = match first.as_str() {
      "--split" => Strategies::SPLIT,
      "--disorder" => Strategies::DISORDER,
      "--fake" => Strategies::FAKE,
      "--oob" => Strategies::OOB,
      "--disoob" => Strategies::DISOOB,
      _ => Strategies::NONE
    };

    strategy
  }
}
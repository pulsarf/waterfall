use std::env;

#[derive(Debug, Clone)]
pub enum Strategies {
  NONE,
  SPLIT,
  DISORDER,
  FAKE,
  OOB,
  DISOOB
}

#[derive(Debug, Clone)]
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

#[derive(Debug, Clone)]
pub struct AuxConfig {
  pub bind_host: String,
  pub bind_port: u16,

  pub fake_packet_ttl: u8,
  pub fake_packet_sni: String,

  pub fake_packet_send_http: bool,
  pub fake_packet_host: String,

  pub fake_packet_override_data: DataOverride::<Vec<u8>>,

  pub disorder_packet_ttl: u8,
  pub default_ttl: u8,
  pub out_of_band_charid: u8,

  pub strategies: Vec<DataOverride::<Strategy>>
}

#[derive(Clone, Debug)]
pub struct DataOverride<T> {
  pub active: bool,
  pub data: T
}

pub fn parse_args() -> AuxConfig {
  let mut config: AuxConfig = AuxConfig {
    bind_host: String::from("127.0.0.1"),
    bind_port: 7878u16,
    fake_packet_ttl: 3,
    fake_packet_sni: String::from("yandex.ru"),
    fake_packet_send_http: false,
    fake_packet_host: String::from("yandex.ru"),
    fake_packet_override_data: DataOverride::<Vec<u8>> {
      active: false,
      data: vec![0u8]
    },
    disorder_packet_ttl: 8,
    default_ttl: 128,
    out_of_band_charid: 213u8,
    
    strategies: vec![DataOverride::<Strategy> {
      active: false,
      data: Strategy::from(String::from("--split"), String::from("5+"))
    }]
  };

  let mut args: Vec<String> = env::args().collect();
  args.drain(0..1);

  let mut offset: usize = 0 as usize;

  'reader: loop {
    if args.len() == 0 {
      break 'reader;
    }

    if args.len() != 0 && offset > args.len() - 1 {
      break 'reader;
    }

    match args[offset].as_str() {
      "--bind_host" => {
        offset += 1 as usize;

        config.bind_host = args[offset].clone();
      },
      "--bind_port" => {
        offset += 1 as usize;

        config.bind_port = args[offset].parse::<u16>().expect("FATAL: bind_port argument exceeds uint16 limit.");
      },
      "--fake_packet_ttl" => {
        offset += 1 as usize;

        config.fake_packet_ttl = args[offset].parse::<u8>().expect("FATAL: fake_packet_ttl argument exceeds uint8 limit.");
      },
      "--fake_packet_sni" => {
        offset += 1 as usize;

        config.fake_packet_sni = args[offset].clone();
      },
      "--fake_packet_send_http" => {
        config.fake_packet_send_http = true;
      },
      "--fake_packet_host" => {
        offset += 1 as usize;

        config.fake_packet_host = args[offset].clone();
      },
      "--fake_packet_override_data" => {
        offset += 1 as usize;

        config.fake_packet_override_data = DataOverride::<Vec<u8>> {
          active: true,
          data: Vec::from(args[offset].as_bytes())
        };
      },
      "--disorder_packet_ttl" => {
        offset += 1 as usize;

        config.disorder_packet_ttl = args[offset].parse::<u8>().expect("FATAL: disorder_packet_ttl argument exceeds uint8 limit.");
      },
      "--default_ttl" => {
        offset += 1 as usize;

        config.default_ttl = args[offset].parse::<u8>().expect("FATAL: default_ttl argument exceeds uint8 limit.");
      },
      "--out_of_band_charid" => {
        offset += 1 as usize;

        config.out_of_band_charid = args[offset].parse::<u8>().expect("FATAL: out_of_band_charid argument exceeds uint8 limit.");
      },
      "--split" => {
        offset += 1 as usize;

        config.strategies.push(DataOverride::<Strategy> {
          active: true,
          data: Strategy::from(String::from("--split"), args[offset].clone())
        });
      },
      "--disorder" => {
        offset += 1 as usize;

        config.strategies.push(DataOverride::<Strategy> {
          active: true,
          data: Strategy::from(String::from("--disorder"), args[offset].clone())
        });
      },
      "--fake" => {
        offset += 1 as usize;

        config.strategies.push(DataOverride::<Strategy> {
          active: true,
          data: Strategy::from(String::from("--fake"), args[offset].clone())
        });
      },
      "--oob" => {
        offset += 1 as usize;

        config.strategies.push(DataOverride::<Strategy> {
          active: true,
          data: Strategy::from(String::from("--oob"), args[offset].clone())
        });
      },
      "--disoob" => {
        offset += 1 as usize;

        config.strategies.push(DataOverride::<Strategy> {
          active: true,
          data: Strategy::from(String::from("--disoob"), args[offset].clone())
        });
      },
      e => println!("[Err!] No such argument: {:?}", e)
    }

    offset += 1 as usize;
  }

  config
}
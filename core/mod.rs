use std::env;

#[derive(Debug, Clone)]
pub enum Strategies {
  NONE,
  SPLIT,
  DISORDER_TTL_CORRUPT,
  FAKE_TTL_CORRUPT,
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
      "--disorder_ttlc" => Strategies::DISORDER_TTL_CORRUPT,
      "--fake_ttlc" => Strategies::FAKE_TTL_CORRUPT,
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
  pub fake_as_oob: bool,

  pub fake_packet_send_http: bool,
  pub fake_packet_host: String,
  pub fake_packet_override_data: DataOverride::<Vec<u8>>,
  pub fake_packet_double: bool,
  pub fake_packet_reversed: bool,

  pub http_host_cmix: bool,
  pub http_host_rmspace: bool,
  pub http_host_space: bool,
  pub http_domain_cmix: bool,

  pub synack: bool,
  pub disorder_packet_ttl: u8,
  pub default_ttl: u8,
  pub out_of_band_charid: u8,
  pub packet_hop: u64,

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
    fake_as_oob: false,
    fake_packet_double: false,
    fake_packet_reversed: false,
    synack: false,
    fake_packet_override_data: DataOverride::<Vec<u8>> {
      active: false,
      data: vec![0u8]
    },
    disorder_packet_ttl: 8,
    default_ttl: 128,
    out_of_band_charid: 213u8,
    packet_hop: std::u64::MAX,
    http_host_cmix: false,
    http_host_rmspace: false,
    http_host_space: false,
    http_domain_cmix: false,
    
    strategies: vec![]
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
      "--fake_as_oob" => {
        config.fake_as_oob = true;
      },
      "--http_host_cmix" => {
        config.http_host_cmix = true;
      },
      "--http_domain_cmix" => {
        config.http_domain_cmix = true;
      },
      "--http_host_rmspace" => {
        config.http_host_rmspace = true;
      },
      "--http_host_space" => {
        config.http_host_space = true;
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
      "--packet_hop" => {
        offset += 1 as usize;

        config.packet_hop = args[offset].parse::<u64>().expect("FATAL: packet_hop argument exceeds uint64 limit.");
      },
      "--synack" => {
        config.synack = true;
      },
      "--fake_packet_double" => {
        config.fake_packet_double = true;
      },
      "--fake_packet_reversed" => {
        config.fake_packet_reversed = true;
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
      "--disorder_ttlc" => {
        offset += 1 as usize;

        config.strategies.push(DataOverride::<Strategy> {
          active: true,
          data: Strategy::from(String::from("--disorder_ttlc"), args[offset].clone())
        });
      },
      "--fake_ttlc" => {
        offset += 1 as usize;

        config.strategies.push(DataOverride::<Strategy> {
          active: true,
          data: Strategy::from(String::from("--fake_ttlc"), args[offset].clone())
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
      e => { }
    }

    offset += 1 as usize;
  }

  config
}

pub fn get_help_text() -> String {
  String::from("./waterfall [OPTION] [VALUE]
[Offset] is denoted as subcommand in format of N+[s]?,
  where N is unsigned 32-bit integer, s - SNI Index.
  [Offset] Block examples: 1+, 5+s, 13+s
  
--bind_host [String] - Bind SOCKS5 Proxy to a specified host
--bind_port [U16] - Bind SOCKS5 Proxy to a specified port

--default_ttl [U8] - Default TTL value for adequate packets.
--fake_packet_ttl [U8] - Default TTL value for packets that should reach ONLY DPI 
--disorder_packet_ttl [U8] - Default TTL value for packets that SHOULD BE RESENT

--fake_packet_sni [String] - Server name identification for fake packets.
--fake_packet_send_http - Sets if fake module should mimic HTTP packets. Can trick DPI into thinking that connection is made over HTTP and force it to skip over next packets.
--fake_packet_host [String] - Fake host for fake packets. Tricks DPI
--fake_packet_override_data [UNICODE String] - Overrides default packet data for fake packets.
--fake_as_oob - Forces fake packets to be sent as Out-of-band data. May break some websites same as OOB module does. Useful for cases when deep packet inspection tool looks for OOB data.
--fake_packet_double - Send two fake packets instead of one.
--fake_packet_reversed - Send fake packets in reverse-order.

--http_host_cmix - Mix Host header case in HTTP
--http_host_rmspace - Remove space after Host: header in HTTP
--http_host_space - Add space after Host: header in HTTP
--http_domain_cmix - Mix case in HTTP domain

--packet_hop - Max tampers/desyncs for connection
--synack - Wraps each packet into fake SYN and ACK. Those packets will be automatically dropped by server. Effective to use with disorder and fake.

--split [Offset] - Applies TCP stream segmentation
--disorder [Offset] - Applies TCP stream segmentation, corrupts first part
--disorder_ttlc [Offset] - Applies TCP stream segmentation, corrupts first part by changing it's TTL/Hop-by-hop value
--fake [Offset] - Applies TCP stream segmentation, corrupts first part and sends a duplicate of it with \"yandex.ru\" SNI
--fake_ttlc [Offset] - Applies TCP stream segmentation, corrupts first part by changing it's TTL/Hop-by-hop value and sends a duplicate of it with \"yandex.ru\" SNI, overriden data or fake HTTP preset. If present, otherwise, uses random bytes data with same length.
--oob [Offset] - Applies TCP stream segmentation. Sends Out-Of-Band byte with value of '213' between these segments.
--disoob [Offset] - Applies TCP stream segmentation, corrupts first part. Sends Out-Of-Band byte with value of '213' between these segments.")
}

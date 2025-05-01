use std::env;
use std::time;
use std::num::ParseIntError;
use std::str::FromStr;

#[derive(Debug, Clone)]
pub enum Strategies {
  NONE,
  SPLIT,
  DISORDER,
  FAKE,
  FAKEMD,
  FAKESURROUND,
  FAKE2DISORDER,
  FAKE2INSERT,
  DISORDER2,
  OOB2,
  OOB,
  DISOOB,
  OOBSTREAMHELL,
  MELTDOWN,
  TRAIL,
  MELTDOWNUDP,
  FRAGTLS
}

#[derive(Debug, Clone)]
pub struct WeakRange {
    pub start: u16,
    pub end: Option<u16>,
}

impl WeakRange {
    pub fn from(s: &str) -> Result<Self, String> {
        let mut parts = s.split('-');

        let start_str = parts.next().ok_or("Range parse failed".to_string())?;
        let start: u16 = start_str.trim().parse().map_err(|e: ParseIntError| e.to_string())?;

        if let Some(end_str) = parts.next() {
            let end_str = end_str.trim();
            if end_str.is_empty() {
                Ok(WeakRange {
                    start,
                    end: None,
                })
            } else {
                let end: u16 = end_str.parse().map_err(|e: ParseIntError| e.to_string())?;
                Ok(WeakRange {
                    start,
                    end: Some(end),
                })
            }
        } else {
            Ok(WeakRange {
                start,
                end: None,
            })
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum NetworkProtocol {
    UDP,
    TCP
}

#[derive(Debug, Clone)]
pub struct Strategy {
  pub method: Strategies,
  pub base_index: i64,
  pub add_sni: bool,
  pub add_host: bool,
  pub subtract: bool,

  pub filter_protocol: Option<NetworkProtocol>,
  pub filter_port: Option<WeakRange>
}

impl Strategy {
  pub fn from(first: String, second: String, subtract: bool, filter_protocol: &str, filter_port: &str) -> Strategy {
    let mut strategy: Strategy = Strategy {
      method: Strategies::NONE,
      base_index: 0,
      add_sni: false,
      add_host: false,
      subtract,
      filter_protocol: None,
      filter_port: None
    };

    if second.contains("s") {
      strategy.add_sni = true;
    }

    if second.contains("h") {
      strategy.add_host = true;
    }

    if let Ok(protocol) = match filter_protocol {
        "udp" => Ok(NetworkProtocol::UDP),
        "tcp" => Ok(NetworkProtocol::TCP),
        _ => Err(".")
    } {
        strategy.filter_protocol = Some(protocol);
    }

    // !!!! MEMORY LEAK
    if let Ok(weak_range) = WeakRange::from(filter_port) {
        strategy.filter_port = Some(weak_range);
    }

    if second.contains("+") {
      let parts: Vec<String> = second
        .split("+")
        .map(|str| String::from(str))
        .collect();
      
      match parts[0].parse::<i64>() {
        Ok(res) => {
          strategy.base_index = if strategy.subtract { res - 1 } else { res };
        },
        Err(_) => { }
      };
    };

    if second.contains("-") {
      let parts: Vec<String> = second
        .split("-")
        .map(|str| String::from(str))
        .collect();
      
      match parts[0].parse::<i64>() {
        Ok(res) => {
          strategy.base_index = if strategy.subtract { -(res + 1) } else { -res };
        },
        Err(_) => { }
      };
    };

    strategy.method = match first.as_str() {
      "--tcp_split" => Strategies::SPLIT,
      "--tcp_disorder" => Strategies::DISORDER,
      "--tcp_disorder2" => Strategies::DISORDER2,
      "--tcp_fake_disordered" => Strategies::FAKE,
      "--tcp_fake_insert" => Strategies::FAKEMD,
      "--tcp_fake_surround" => Strategies::FAKESURROUND,
      "--tcp_fake2_disordered" => Strategies::FAKE2DISORDER,
      "--tcp_fake2_insert" => Strategies::FAKE2INSERT,
      "--tcp_out_of_band" => Strategies::OOB,
      "--tcp_out_of_band_disorder" => Strategies::DISOOB,
      "--tcp_out_of_band_disorder2" => Strategies::OOB2,
      "--tcp_meltdown" => Strategies::MELTDOWN,
      "--tcp_out_of_band_hell" => Strategies::OOBSTREAMHELL,
      "--tls_record_frag" => Strategies::FRAGTLS,
      "--udp_0trail" => Strategies::TRAIL,
      "--udp_meltdown" => Strategies::MELTDOWNUDP,
      _ => Strategies::NONE
    };

    strategy
  }
}

#[derive(Debug, Clone)]
pub struct AuxConfig {
  pub bind_host: String,
  pub bind_port: u16,

  pub bind_iface: String,
  pub bind_iface_mtu: u32,
  pub bind_iface_ipv4: String,
  pub bind_iface_ipv6: String,

  pub fake_packet_ttl: u8,
  pub fake_packet_sni: String,
  pub fake_as_oob: bool,

  pub fake_packet_send_http: bool,
  pub fake_packet_host: String,
  pub fake_packet_override_data: DataOverride::<Vec<u8>>,
  pub fake_packet_double: bool,
  pub fake_packet_reversed: bool,
  pub fake_packet_random: bool,

  pub so_recv_size: usize,
  pub so_send_size: usize,
  pub so_opt_cutoff: u64,

  pub l7_packet_jitter_max: time::Duration,

  pub disable_sack: bool,

  pub fake_clienthello: bool,
  pub fake_clienthello_sni: String,

  pub oob_streamhell_data: String,

  pub http_host_cmix: bool,
  pub http_host_rmspace: bool,
  pub http_host_space: bool,
  pub http_domain_cmix: bool,

  pub disorder_packet_ttl: u8,
  pub default_ttl: u8,
  pub out_of_band_charid: u8,
  pub packet_hop: u64,

  pub whitelist_sni: bool,
  pub whitelist_sni_list: Vec<String>,

  pub strategies: Vec<DataOverride::<Strategy>>,
}

struct ResultPacket {
    seqnum: u8,
    is_fake: bool,
    oob: bool
}

struct StrategyStack {
    stack: Vec<ResultPacket>
}

impl StrategyStack {
    fn from(stack: String) -> StrategyStack {
        let mut strategy_stack: StrategyStack = StrategyStack {
            stack: Vec::new()
        };

        let mut seqnum: u8 = 0u8;

        for symbol in stack.chars() {
            seqnum += 1;

            strategy_stack.stack.push(match symbol {
                'A' => ResultPacket { seqnum: seqnum - 1, is_fake: false, oob: false },
                'B' => ResultPacket { seqnum: seqnum + 1, is_fake: false, oob: false },
                'F' => ResultPacket { seqnum, is_fake: true, oob: false },
                'O' => ResultPacket { seqnum, is_fake: false, oob: true },
                _ => ResultPacket { seqnum, is_fake: false, oob: false }
            });
        }

        strategy_stack
    }

    fn can_disorder(&self) -> bool {
        self.stack
            .iter()
            .filter(|x| !x.is_fake)
            .collect::<Vec<_>>()
            .windows(2)
            .any(|arr| arr[0].seqnum > arr[1].seqnum)
    }

    fn can_split(&self) -> bool {
        self.stack.len() > 1
    }

    fn has_fake_bit(&self) -> bool {
        self.stack[0].is_fake
    }

    fn can_oob_hell(&self) -> bool {
        self.stack
            .iter()
            .filter(|x| !x.is_fake)
            .collect::<Vec<_>>()
            .windows(3)
            .any(|arr| !arr[0].oob && arr[1].oob && !arr[2].oob)
    }

    fn can_meltdown(&self) -> bool {
        self.stack
            .windows(2)
            .any(|arr| arr[0].is_fake && !arr[1].is_fake && !arr[1].oob)
    }

    fn verify_signature(&self, strategies: Vec<Strategy>) -> Option<bool> {
        for strategy in strategies {
            if matches!(strategy.method, crate::Strategies::DISORDER | crate::Strategies::FAKE2DISORDER | crate::Strategies::DISOOB) && !self.can_disorder() {
                return None;
            }

            if matches!(strategy.method, crate::Strategies::SPLIT | crate::Strategies::DISORDER2 | crate::Strategies::OOB | crate::Strategies::OOB2) && !self.can_split() {
                return None;
            }

            if matches!(strategy.method, crate::Strategies::FAKE | crate::Strategies::FAKEMD | crate::Strategies::FAKESURROUND | crate::Strategies::FAKE2INSERT) && !self.has_fake_bit() {
                return None;
            }

            if matches!(strategy.method, crate::Strategies::OOBSTREAMHELL) && !self.can_oob_hell() {
                return None;
            }

            if matches!(strategy.method, crate::Strategies::MELTDOWN | crate::Strategies::MELTDOWNUDP) && !self.can_meltdown() {
                return None;
            }
        }

        Some(true)
    }
}

#[derive(Clone, Debug)]
pub struct DataOverride<T> {
  pub active: bool,
  pub data: T
}

use socket2::{Socket, Domain, Type, Protocol};
use std::{net::{TcpStream, SocketAddr}, io};
use std::thread;

pub fn connect_socket(addr: SocketAddr) -> io::Result<TcpStream> {
    let domain_type = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };

    let socket = Socket::new(domain_type, Type::STREAM, Some(Protocol::TCP))?;

    let AuxConfig { so_recv_size, so_send_size, so_opt_cutoff, .. } = parse_args();
    
    socket.set_recv_buffer_size(so_recv_size)?;
    socket.set_send_buffer_size(so_send_size)?;
    socket.set_nodelay(true)?;
    socket.set_keepalive(true)?;

    let so_clone = socket.try_clone().unwrap();

    thread::spawn(move || {
        thread::sleep(time::Duration::from_millis(so_opt_cutoff));

        let _ = so_clone.set_recv_buffer_size(16653);
        let _ = so_clone.set_send_buffer_size(16653);
    });

    if domain_type == Domain::IPV6 {
        socket.set_only_v6(false)?;
    }

    socket.connect(&addr.into())?;
    
    Ok(socket.into())
}

pub fn parse_args() -> AuxConfig {
  let mut config: AuxConfig = AuxConfig {
    bind_host: String::from("127.0.0.1"),
    bind_port: 7878u16,
    bind_iface: String::from(""),
    bind_iface_mtu: 8400,
    bind_iface_ipv4: String::from("192.18.0.0"),
    bind_iface_ipv6: String::from("fc00::1"),
    fake_packet_ttl: 3,
    fake_packet_sni: String::from("yandex.ru"),
    fake_packet_send_http: false,
    fake_packet_host: String::from("yandex.ru"),
    fake_as_oob: false,
    fake_packet_double: false,
    fake_packet_reversed: false,
    fake_packet_random: false,
    fake_packet_override_data: DataOverride::<Vec<u8>> {
      active: false,
      data: vec![0u8]
    },
    oob_streamhell_data: String::from(".@nt1_r3@ss3mbly_101.yandex"),
    disorder_packet_ttl: 8,
    disable_sack: false,
    default_ttl: 128,
    out_of_band_charid: 213u8,
    so_recv_size: 65535,
    so_send_size: 65535,
    so_opt_cutoff: 500,
    packet_hop: std::u64::MAX,
    l7_packet_jitter_max: time::Duration::from_millis(0),
    http_host_cmix: false,
    http_host_rmspace: false,
    http_host_space: false,
    http_domain_cmix: false,
    fake_clienthello: false,
    fake_clienthello_sni: String::from("yandex.ru"),

    whitelist_sni: false,
    whitelist_sni_list: vec![],
    
    strategies: vec![],
  };

  let mut args: Vec<String> = env::args().collect();
  args.drain(0..1);

  let mut offset: usize = 0 as usize;

  let mut filter_protocol: &str = "";
  let mut filter_port: &str = "";

  let mut strategy_stack = StrategyStack::from(String::new());

  'reader: loop {
    if args.len() == 0 {
      break 'reader;
    }

    if args.len() != 0 && offset > args.len() - 1 {
      break 'reader;
    }

    match args[offset].as_str() {
      "--filter_protocol" => {
        offset += 1 as usize;

        filter_protocol = &args[offset];
      },
      "--filter_port" => {
        offset += 1 as usize;

        filter_port = &args[offset];
      },
      "--bind_host" => {
        offset += 1 as usize;

        config.bind_host = args[offset].clone();
      },
      "--bind_port" => {
        offset += 1 as usize;

        config.bind_port = args[offset].parse::<u16>().expect("FATAL: bind_port argument exceeds uint16 limit.");
      },
      "--bind_iface" => {
          offset += 1 as usize;

          config.bind_iface = args[offset].clone();
      },
      "--bind_iface_mtu" => {
          offset += 1 as usize;

          config.bind_iface_mtu = args[offset].parse::<u32>().expect("bind_iface_mtu must be u32");
      },
      "--bind_iface_ipv4" => {
          offset += 1 as usize;

          config.bind_iface_ipv4 = args[offset].clone();
      },
      "--bind_iface_ipv6" => {
          offset += 1 as usize;

          config.bind_iface_ipv6 = args[offset].clone();
      },
      "--fake_packet_ttl" => {
        offset += 1 as usize;

        config.fake_packet_ttl = args[offset].parse::<u8>().expect("FATAL: fake_packet_ttl argument exceeds uint8 limit.");
      },
      "--send_fake_clienthello" => {
        config.fake_clienthello = true;
      },
      "--disable_sack" => {
        config.disable_sack = true;
      },
      "--fc_sni" => {
        offset += 1 as usize;

        config.fake_clienthello_sni = args[offset].clone();
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
      "--fake_packet_str" => {
        offset += 1 as usize;

        config.fake_packet_override_data = DataOverride::<Vec<u8>> {
          active: true,
          data: Vec::from(args[offset].as_bytes())
        };
      },
      "--fake_packet_hex" => {
        offset += 1 as usize;

        let hex_str = &args[offset];

        let hex_bytes = (0..hex_str.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex_str[i..(i + 2)], 16).unwrap())
            .collect::<Vec<u8>>();

        config.fake_packet_override_data = DataOverride::<Vec<u8>> {
          active: true,
          data: hex_bytes
        };
      },
      "--oob_stream_hell_data" => {
          offset += 1 as usize;

          config.oob_streamhell_data = args[offset].clone();
      },
      "--disorder_packet_ttl" => {
        offset += 1 as usize;

        config.disorder_packet_ttl = args[offset].parse::<u8>().expect("FATAL: disorder_packet_ttl argument exceeds uint8 limit.");
      },
      "--packet_hop" => {
        offset += 1 as usize;

        config.packet_hop = args[offset].parse::<u64>().expect("FATAL: packet_hop argument exceeds uint64 limit.");
      },
      "--fake_packet_random" => {
        config.fake_packet_random = true;
      },
      "--fake_packet_double" => {
        config.fake_packet_double = true;
      },
      "--fake_packet_reversed" => {
        config.fake_packet_reversed = true;
      },
      "--so_recv_size" => {
          offset += 1 as usize;

          config.so_recv_size = args[offset].parse::<usize>().expect("Receive buffer size must be usize"); 
      },
      "--so_send_size" => {
          offset += 1 as usize;

          config.so_send_size = args[offset].parse::<usize>().expect("Send buffer size must be usize"); 
      },
      "--so_opt_cutoff" => {
          offset += 1 as usize;

          config.so_opt_cutoff = args[offset].parse::<u64>().expect("Socket bufsize reset cutoff must be u64"); 
      },
      "--default_ttl" => {
        offset += 1 as usize;

        config.default_ttl = args[offset].parse::<u8>().expect("FATAL: default_ttl argument exceeds uint8 limit.");
      },
      "--out_of_band_charid" => {
        offset += 1 as usize;

        config.out_of_band_charid = args[offset].parse::<u8>().expect("FATAL: out_of_band_charid argument exceeds uint8 limit.");
      },
      "--whitelist_sni" => {
        offset += 1 as usize;

        config.whitelist_sni = true;
        config.whitelist_sni_list.push(args[offset].clone());
      },
      "--resist_timing_attack" => {
        offset += 1 as usize;

        config.l7_packet_jitter_max = time::Duration::from_millis(args[offset].parse::<u8>().expect("Packet jitter should be 0-255").into());
      },
      "--strategy_stack" => {
        offset += 1 as usize;

        strategy_stack = StrategyStack::from(args[offset].clone());
      },
      "--dpi_bypass_strategies" => {
          offset += 1 as usize;

          let mut bypass_strategies = args[offset]
              .split(",")
              .map(|n| n.to_string())
              .collect::<Vec<String>>();

          let base_strategy_name = bypass_strategies[0].clone();
          let base_opt_pos = args[offset + 1]
              .split(",")
              .map(|n| n.to_string())
              .collect::<Vec<String>>();

          for index in &base_opt_pos {
              config.strategies.push(DataOverride::<Strategy> {
                  active: true,
                  data: Strategy::from("--".to_owned() + &base_strategy_name.clone(), index.to_string(), false, filter_protocol, filter_port)
              });
          }

          bypass_strategies.drain(0..1);

          if bypass_strategies.len() == 0 {
              break;
          }

          let mut strategy_index = 1;

          for strategy in bypass_strategies {
              strategy_index += 1;

              let strategy_opt_pos = args[offset + strategy_index].clone();

              if cfg!(windows) && strategy_opt_pos == "auto" {
                  for index in &base_opt_pos {
                      if (base_strategy_name.contains("disorder") && strategy.contains("split")) ||
                         (base_strategy_name.contains("fake") && strategy.contains("disorder")) { 
                          config.strategies.push(DataOverride::<Strategy> {
                              active: true,
                              data: Strategy::from("--".to_owned() + &strategy.clone(), String::from(index), true, filter_protocol, filter_port)
                          });
                      }
                  }
              } else {
                  config.strategies.push(DataOverride::<Strategy> {
                      active: true,
                      data: Strategy::from("--".to_owned() + &strategy, String::from(&strategy_opt_pos), false, filter_protocol, filter_port)
                  });
              }
          }

          if strategy_stack.verify_signature(config.strategies
              .clone()
              .iter()
              .map(|n| n.data.clone())
              .collect::<Vec<Strategy>>()).is_none() {
              panic!("Strategy stack violated");
          }

          offset += strategy_index as usize;
      },
      _ => { }
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

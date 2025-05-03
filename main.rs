mod desync;
mod core;
mod socks;
mod tamper;

use crate::desync::split::split;
use crate::desync::disorder::disorder;
use crate::desync::fake::fake;
use crate::desync::oob::oob;
use crate::desync::disoob::disoob;
use crate::desync::utils::utils;

use utils::IpParser;

use crate::utils::Random;

use core::Strategies;
use core::Strategy;
use core::AuxConfig;

use std::net::TcpListener;
use std::net::TcpStream;
use std::io::Write;

use std::thread;
use std::time;

fn execute_l4_bypasses<'a>(mut socket: &'a TcpStream, config: &'a AuxConfig, current_data: &'a mut Vec<u8>, sni_data: &'a (u32, u32)) {
  if sni_data != &(0, 0) &&
    config.fake_clienthello {
    utils::send_drop(&socket, [&[0x16, 0x03, 0x01, 0x00, 0xa5,
        0x01, 0x00, 0x00, 0xa1, 0x03, 0x03, 

        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

        0x00,

        0x00, 2, 0x00, 0x0a,

        0x01, 0x00,

        0x00, 16, 

        0x00, 0x00, 0x00, 0x28], config.fake_clienthello_sni.as_bytes()].concat());
  }
  
  for strategy_raw in &config.strategies {
    let strategy: Strategy = strategy_raw.data.clone();

    if strategy.add_sni && sni_data == &(0, 0) {
      continue;
    }

    if !utils::check_whitelist(&strategy.filter_sni, sni_data, current_data.as_slice()) {
        continue;
    }

    if let Some(ref protocol) = strategy.filter_protocol {
        if protocol != &core::NetworkProtocol::TCP {
            continue;
        }
    }

    if let Ok(addr) = socket.peer_addr() {
        if let Some(ref port) = strategy.filter_port {
            let addr_port: u16 = addr.port();

            if let Some(end_port) = port.end {
                if addr_port > end_port {
                    continue;
                }
            }

            if addr_port < port.start {
                continue;
            }
        }
    }

    match strategy.method {
      Strategies::NONE => { },
      Strategies::SPLIT => {
        let send_data: Vec<Vec<u8>> = split::get_split_packet(&current_data, strategy, &sni_data);

        if send_data.len() > 1 {
          let _ = socket.write_all(&send_data[0]);

          *current_data = send_data[1].clone();
        }
      },
      Strategies::DISORDER => {
        let send_data: Vec<Vec<u8>> = disorder::get_split_packet(&current_data, strategy, &sni_data);

        if send_data.len() > 1 {
          let _ = utils::send_duplicate(&socket, send_data[0].clone());

          *current_data = send_data[1].clone();
        }
      },
      Strategies::DISORDER2 => {
        let send_data: Vec<Vec<u8>> = disorder::get_split_packet(&current_data, strategy, &sni_data);

        if send_data.len() > 1 {
          let _ = socket.write_all(&send_data[0]);

          let _ = utils::send_duplicate(&socket, send_data[1].clone());

          *current_data = vec![];
        }
      },
      Strategies::FAKE => {
        let send_data: Vec<Vec<u8>> = fake::get_split_packet(&current_data, strategy, &sni_data);
        
        if send_data.len() > 1 {
          let _ = utils::send_duplicate(&socket, send_data[0].clone());
          utils::send_drop(&socket, fake::get_fake_packet(send_data[if core::parse_args().fake_packet_reversed { 0 } else { 1 }].clone()));

          *current_data = send_data[1].clone();
        }
      },
      Strategies::FAKEMD => {
        let send_data: Vec<Vec<u8>> = fake::get_split_packet(&current_data, strategy, &sni_data);
        
        if send_data.len() > 1 {
          let _ = socket.write_all(&send_data[0]);

          utils::send_drop(&socket, fake::get_fake_packet(send_data[if core::parse_args().fake_packet_reversed { 0 } else { 1 }].clone()));

          *current_data = send_data[1].clone();
        }
      },
      Strategies::FAKE2INSERT => {
        let send_data: Vec<Vec<u8>> = fake::get_split_packet(&current_data, strategy, &sni_data);
        
        if send_data.len() > 1 {
          let _ = socket.write_all(&send_data[0]);

          utils::send_drop(&socket, fake::get_fake_packet(send_data[1].clone()));

          *current_data = send_data[1].clone();
        }
      },
      Strategies::FAKE2DISORDER => {
        let send_data: Vec<Vec<u8>> = disorder::get_split_packet(&current_data, strategy, &sni_data);

        if send_data.len() > 1 {
          let _ = socket.write_all(&send_data[0]);

          utils::send_drop(&socket, fake::get_fake_packet(send_data[1].clone()));

          let _ = utils::send_duplicate(&socket, send_data[1].clone());

          *current_data = vec![];
        }
      },
      Strategies::FAKESURROUND => {
        let send_data: Vec<Vec<u8>> = fake::get_split_packet(&current_data, strategy, &sni_data);
        
        if send_data.len() > 1 {
          utils::send_drop(&socket, fake::get_fake_packet(send_data[if core::parse_args().fake_packet_reversed { 0 } else { 1 }].clone()));

          let _ = socket.write_all(&send_data[0]);

          utils::send_drop(&socket, fake::get_fake_packet(send_data[if core::parse_args().fake_packet_reversed { 0 } else { 1 }].clone()));

          *current_data = send_data[1].clone();
        }
      },
      Strategies::MELTDOWN => {
          let _ = utils::send_duplicate(&socket, current_data.clone());

          *current_data = vec![];
      },
      Strategies::MELTDOWNUDP => { },
      Strategies::TRAIL => { },
      Strategies::OOB => {
        let send_data: Vec<Vec<u8>> = oob::get_split_packet(&current_data, strategy, &sni_data);

        if send_data.len() > 1 {
          let mut ax_part: Vec<u8> = send_data[0].clone();

          ax_part.push(core::parse_args().out_of_band_charid.into());

          utils::write_oob_multiplex(&socket, ax_part);

          *current_data = send_data[1].clone();
        }
      },
      Strategies::OOBSTREAMHELL => { 
          let send_data: Vec<Vec<u8>> = oob::get_split_packet(&current_data, strategy, &sni_data);

          if send_data.len() > 1 {
              let ax_part: Vec<u8> = send_data[0].clone();

              let _ = socket.write_all(&ax_part);

              let oob_part = core::parse_args().oob_streamhell_data.clone();

              for byte in oob_part.as_bytes() {
                  utils::write_oob_multiplex(&socket, vec![*byte]);
              }

              *current_data = send_data[1].clone();
          }
      },
      Strategies::DISOOB => { 
        let send_data: Vec<Vec<u8>> = disoob::get_split_packet(&current_data, strategy, &sni_data);

        if send_data.len() > 1 {
          let mut ax_part: Vec<u8> = send_data[0].clone();

          ax_part.push(core::parse_args().out_of_band_charid.into());

          let _ = utils::set_ttl_raw(&socket, 1);
          utils::write_oob_multiplex(&socket, ax_part);
          let _ = utils::set_ttl_raw(&socket, core::parse_args().default_ttl.into());

          *current_data = send_data[1].clone();
        }
      },
      Strategies::OOB2 => { 
        let send_data: Vec<Vec<u8>> = disoob::get_split_packet(&current_data, strategy, &sni_data);

        if send_data.len() > 1 {
          let mut ax_part: Vec<u8> = send_data[0].clone();

          ax_part.push(core::parse_args().out_of_band_charid.into());

          let _ = utils::set_ttl_raw(&socket, 1);
          utils::write_oob_multiplex(&socket, ax_part);
          let _ = utils::set_ttl_raw(&socket, core::parse_args().default_ttl.into());

          let _ = utils::send_duplicate(&socket, send_data[1].clone());

          *current_data = vec![];
        }
      },
      Strategies::FRAGTLS => {
        if strategy.add_sni {
            let (sni_start, _sni_end) = &sni_data;

            *current_data = tamper::edit_tls(current_data.to_vec(), (strategy.base_index + (*sni_start as i64)).try_into().unwrap());
        } else {
            *current_data = tamper::edit_tls(current_data.to_vec(), strategy.base_index.try_into().unwrap());
        } 
      }
    }
  } 

  if config.disable_sack {
    utils::disable_sack(&socket);
  }

  if config.fake_packet_random {
    utils::send_drop(&socket, utils::make_random_vec(32 as usize, 0xDEAD));
  }
}

fn execute_l5_bypasses(data: &[u8]) -> Vec<u8> {
    let current_data = tamper::edit_http(data.to_vec());

    current_data
}

fn execute_l7_bypasses(config: &AuxConfig) {
  let mut rand: Random = Random::new((time::SystemTime::now()
      .duration_since(time::SystemTime::UNIX_EPOCH)
      .unwrap()
      .as_millis() % 255)
      .try_into()
      .unwrap());

  let rand_num: u64 = rand.next_rand().into();
  
  let jitter_millis: u64 = config.l7_packet_jitter_max
      .as_millis()
      .try_into()
      .unwrap_or(u64::MAX);

  if jitter_millis > 0 {
      let random_jitter: u64 = ((rand_num * jitter_millis) / 256u64)
          .into();

      thread::sleep(time::Duration::from_millis(random_jitter));
  }
}

fn client_hook(mut socket: &TcpStream, data: &[u8]) -> Vec<u8> { 
  let config = core::parse_args();

  let sni_data = utils::parse_sni_index(Vec::from(data)); 

  let mut l5_data = execute_l5_bypasses(data);

  execute_l4_bypasses(&socket, &config, &mut l5_data, &sni_data);
  
  execute_l7_bypasses(&config);

  l5_data
}

fn main() -> std::io::Result<()> {
    let config: AuxConfig = core::parse_args();

    println!("{:#?}", config);

    let listener: TcpListener = TcpListener::bind(format!("{}:{}", config.bind_host, config.bind_port).replace("\"", "").replace("\"", "")).unwrap();

    for stream in listener.incoming() {
        socks::socks5_proxy(&mut (stream?), client_hook);
    }

    Ok(())
}



mod desync;
mod parsers;
mod net;
mod core;
mod socks;
mod duplicate;
mod drop;
mod tamper;

use crate::desync::split::split;
use crate::desync::disorder::disorder;
use crate::desync::fake::fake;
use crate::desync::oob::oob;
use crate::desync::disoob::disoob;
use crate::desync::utils::utils;

use crate::parsers::parsers::IpParser;

use core::Strategies;
use core::Strategy;
use core::AuxConfig;

use std::net::TcpListener;
use std::net::TcpStream;
use std::io::Write;

fn client_hook(mut socket: &TcpStream, data: &[u8]) -> Vec<u8> {
  let mut current_data = tamper::edit_http(data.to_vec());
  let mut fake_active: bool = false;

  let sni_data = utils::parse_sni_index(Vec::from(data));

  let mut can_run: bool = false;

  if sni_data != (0, 0) && 
      core::parse_args().whitelist_sni {
      let start = sni_data.0 as usize;
      let end = sni_data.1 as usize;

      let sni_slice =  &data[start..end];

      let sni_string: String = String::from_utf8_lossy(sni_slice).to_string(); 

      if !core::parse_args().whitelist_sni_list.iter().position(|r|
          sni_string.contains(&*r)).is_none() {
          println!("[W] Apply fooling on whitelisted domain {}", &sni_string);

          can_run = true;
      }
  }

  if !can_run {
      return current_data;
  }

  if sni_data != (0, 0) &&
    core::parse_args().fake_clienthello {
    drop::raw_send(&socket, [&[0x16, 0x03, 0x01, 0x00, 0xa5,
        0x01, 0x00, 0x00, 0xa1, 0x03, 0x03, 

        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

        0x00,

        0x00, 2, 0x00, 0x0a,

        0x01, 0x00,

        0x00, 16, 

        0x00, 0x00, 0x00, 0x28], core::parse_args().fake_clienthello_sni.as_bytes()].concat());
  }
  
  for strategy_raw in core::parse_args().strategies {
    let strategy: Strategy = strategy_raw.data;

    if strategy.add_sni && sni_data == (0, 0) {
      continue;
    }

    println!("[F {:?}] Loaded startegy at index {}", &strategy.method, &strategy.base_index);

    match strategy.method {
      Strategies::NONE => { },
      Strategies::SPLIT => {
        let send_data: Vec<Vec<u8>> = split::get_split_packet(&current_data, strategy, &sni_data);

        if send_data.len() > 1 {
          if let Err(_e) = socket.write_all(&send_data[0]) {
             return current_data;
          }

          current_data = send_data[1].clone();
        }
      },
      Strategies::DISORDER => {
        let send_data: Vec<Vec<u8>> = disorder::get_split_packet(&current_data, strategy, &sni_data);

        if send_data.len() > 1 {
          let _ = duplicate::send(&socket, send_data[0].clone());

          current_data = send_data[1].clone();
        }
      },
      Strategies::FAKE => {
        let send_data: Vec<Vec<u8>> = fake::get_split_packet(&current_data, strategy, &sni_data);
        
        if send_data.len() > 1 {
          fake_active = true;

          let _ = duplicate::send(&socket, send_data[0].clone());
          drop::raw_send(&socket, fake::get_fake_packet(send_data[if core::parse_args().fake_packet_reversed { 0 } else { 1 }].clone()));

          current_data = send_data[1].clone();
        }
      },
      Strategies::FAKEMD => {
        let send_data: Vec<Vec<u8>> = fake::get_split_packet(&current_data, strategy, &sni_data);
        
        if send_data.len() > 1 {
          fake_active = true;

          let _ = socket.write_all(&send_data[0]);

          drop::raw_send(&socket, fake::get_fake_packet(send_data[if core::parse_args().fake_packet_reversed { 0 } else { 1 }].clone()));

          current_data = send_data[1].clone();
        }
      },
      Strategies::OOB => {
        let send_data: Vec<Vec<u8>> = oob::get_split_packet(&current_data, strategy, &sni_data);

        if send_data.len() > 1 {
          let mut ax_part: Vec<u8> = send_data[0].clone();

          ax_part.push(core::parse_args().out_of_band_charid.into());

          net::write_oob_multiplex(&socket, ax_part);

          current_data = send_data[1].clone();
        }
      },
      Strategies::OOBSTREAMHELL => { 
          let send_data: Vec<Vec<u8>> = oob::get_split_packet(&current_data, strategy, &sni_data);

          if send_data.len() > 1 {
              let ax_part: Vec<u8> = send_data[0].clone();

              let _ = socket.write_all(&ax_part);

              let oob_part = core::parse_args().oob_streamhell_data.clone();

              for byte in oob_part.as_bytes() {
                  net::write_oob_multiplex(&socket, vec![*byte]);
              }

              current_data = send_data[1].clone();
          }
      },
      Strategies::DISOOB => { 
        let send_data: Vec<Vec<u8>> = disoob::get_split_packet(&current_data, strategy, &sni_data);

        if send_data.len() > 1 {
          let mut ax_part: Vec<u8> = send_data[0].clone();

          ax_part.push(core::parse_args().out_of_band_charid.into());

          let _ = duplicate::set_ttl_raw(&socket, 1);
          net::write_oob_multiplex(&socket, ax_part);
          let _ = duplicate::set_ttl_raw(&socket, core::parse_args().default_ttl.into());

          current_data = send_data[1].clone();
        }
      },
      Strategies::FRAGTLS => {
        if strategy.add_sni {
            let (sni_start, _sni_end) = &sni_data;

            current_data = tamper::edit_tls(current_data, (strategy.base_index + (*sni_start as i64)).try_into().unwrap());

            println!("[T {}] Tampering TLS Record at index {}", current_data.len(), (strategy.base_index + (*sni_start as i64)));
        } else {
            current_data = tamper::edit_tls(current_data, strategy.base_index.try_into().unwrap());

            println!("[T {}] Tampering TLS Record at index {}", current_data.len(), strategy.base_index);
        } 
      }
    }
  }

  if core::parse_args().fake_packet_reversed && fake_active {
    drop::raw_send(&socket, fake::get_fake_packet(current_data.clone()));
  }

  if core::parse_args().disable_sack {
    net::disable_sack(&socket);
  }

  if core::parse_args().fake_packet_random {
    drop::raw_send(&socket, utils::make_random_vec(32 as usize, 0xDEAD));
  }

  current_data
}

fn main() {
  let config: AuxConfig = core::parse_args();

  if std::env::args().map(|c| String::from(c)).collect::<Vec<String>>().contains(&String::from("--help")) {
    println!("{}", core::get_help_text());

    return;
  }

  println!(" == Waterfall DPI bypass tool == 
Configuration: {:#?}", config);

  let listener: TcpListener = TcpListener::bind(format!("{:?}:{:?}", config.bind_host, config.bind_port).replace("\"", "").replace("\"", "")).unwrap();

  for stream in listener.incoming() {
    match stream {
      Ok(mut client) => socks::socks5_proxy(&mut client, client_hook),
      Err(_error) => { }
    };
  }
}

#[cfg(test)]

mod tests {
  use std::process::{Output, Command};
  use super::*;

  #[test]

  fn can_send_requests_google() {
    let mut sender: Command = Command::new("curl");
    let config: AuxConfig = core::parse_args();

    sender.arg("--socks5").arg(format!("{:?}:{:?}", config.bind_host, config.bind_port).replace("\"", "").replace("\"", "")).arg("https://www.google.com");

    let output: Output = sender.output().unwrap();
    let string: String = format!("{:?}", output);

    assert_eq!(true, string.contains("html"));
  } 

  #[test]

  fn can_send_requests_youtube() {
    let mut sender: Command = Command::new("curl");
    let config: AuxConfig = core::parse_args();

    sender.arg("--socks5").arg(format!("{:?}:{:?}", config.bind_host, config.bind_port).replace("\"", "").replace("\"", "")).arg("https://www.google.com");

    let output: Output = sender.output().unwrap();
    let string: String = format!("{:?}", output);

    assert_eq!(true, string.contains("html"));
  } 

  #[test]

  fn can_send_requests_discord() {
    let mut sender: Command = Command::new("curl");
    let config: AuxConfig = core::parse_args();

    sender.arg("--socks5").arg(format!("{:?}:{:?}", config.bind_host, config.bind_port).replace("\"", "").replace("\"", "")).arg("https://www.google.com");

    let output: Output = sender.output().unwrap();
    let string: String = format!("{:?}", output);

    assert_eq!(true, string.contains("html"));
  } 
}

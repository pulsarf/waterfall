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
  let mod_data1 = tamper::edit_tls(data.to_vec());
  let data = tamper::edit_http(mod_data1);

  let mut current_data = data.to_vec();
  let mut fake_active: bool = false;

  if core::parse_args().synack {
    drop::raw_send(&socket, vec![255, 255, 0, 122, 0, 0, 0, 0, 0, 0, 0, 0, 5, 1, 0, 0, 255, 255, 0, 0, 0, 0, 255, 255, 255, 255]);
  }
  
  for strategy_raw in core::parse_args().strategies {
    let strategy: Strategy = strategy_raw.data;

    if strategy.add_sni && utils::parse_sni_index(Vec::from(data.clone())) == (0, 0) {
      continue;
    }

    match strategy.method {
      Strategies::NONE => { },
      Strategies::SPLIT => {
        let send_data: Vec<Vec<u8>> = split::get_split_packet(&current_data, strategy);

        if send_data.len() > 1 {
          if let Err(_e) = socket.write_all(&send_data[0]) {
             return current_data;
          }

          current_data = send_data[1].clone();
        }
      },
      Strategies::DISORDER => {
        let send_data: Vec<Vec<u8>> = disorder::get_split_packet(&current_data, strategy);

        if send_data.len() > 1 {
          let _ = duplicate::send(&socket, send_data[0].clone());

          current_data = send_data[1].clone();
        }
      },
      Strategies::FAKE => {
        let send_data: Vec<Vec<u8>> = fake::get_split_packet(&current_data, strategy);
        
        if send_data.len() > 1 {
          fake_active = true;
          let _ = socket.write_all(&send_data[0]);

          drop::raw_send(&socket, fake::get_fake_packet(send_data[if core::parse_args().fake_packet_reversed { 0 } else { 1 }].clone()));

          current_data = send_data[1].clone();
        }
      },
      Strategies::OOB => {
        let send_data: Vec<Vec<u8>> = oob::get_split_packet(&current_data, strategy);

        if send_data.len() > 1 {
          let mut ax_part: Vec<u8> = send_data[0].clone();

          ax_part.push(core::parse_args().out_of_band_charid.into());

          net::write_oob_multiplex(&socket, ax_part);

          current_data = send_data[1].clone();
        }
      },
      Strategies::DISOOB => { 
        let send_data: Vec<Vec<u8>> = disoob::get_split_packet(&current_data, strategy);

        if send_data.len() > 1 {
          let mut ax_part: Vec<u8> = send_data[0].clone();

          ax_part.push(core::parse_args().out_of_band_charid.into());

          let _ = duplicate::set_ttl_raw(&socket, 1);
          net::write_oob_multiplex(&socket, ax_part);
          let _ = duplicate::set_ttl_raw(&socket, core::parse_args().default_ttl.into());

          current_data = send_data[1].clone();
        }
      }
    }
  }

  if core::parse_args().synack { // ACK
    drop::raw_send(&socket, vec![255, 255, 0, 122, 0, 0, 0, 0, 0, 0, 0, 0, 5, 4, 0, 0, 255, 255, 0, 0, 0, 0, 255, 255, 255, 255]);
  }

  if core::parse_args().fake_packet_reversed && fake_active {
    drop::raw_send(&socket, fake::get_fake_packet(current_data.clone()));
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

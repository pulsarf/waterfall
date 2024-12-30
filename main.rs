mod desync;
mod parsers;
mod net;
mod core;
mod socks;
mod duplicate;
mod drop;

use crate::desync::split::split;
use crate::desync::disorder::disorder;
use crate::desync::fake::fake;
use crate::desync::oob::oob;
use crate::desync::disoob::disoob;
use crate::parsers::parsers::IpParser;

use core::Strategies;
use core::Strategy;
use core::AuxConfig;

use std::thread;
use std::net::TcpListener;
use std::net::TcpStream;
use std::io::Write;

fn client_hook(mut socket: TcpStream, data: &[u8]) -> Vec<u8> {
  let mut current_data = data.to_vec();

  for strategy_raw in core::parse_args().strategies {
    println!("[Send] Applied method: {:?}", strategy_raw);

    let strategy: Strategy = strategy_raw.data;

    match strategy.method {
      Strategies::NONE => { },
      Strategies::SPLIT => {
        let send_data: Vec<Vec<u8>> = split::get_split_packet(&current_data);

        if send_data.len() > 1 {
          if let Err(_e) = socket.write_all(&send_data[0]) {
             return current_data;
          }

          current_data = send_data[1].clone();
        }
      },
      Strategies::DISORDER => {
        let send_data: Vec<Vec<u8>> = disorder::get_split_packet(&current_data);

        if send_data.len() > 1 {
          duplicate::send(&socket, send_data[0].clone());

          current_data = send_data[1].clone();
        }
      },
      Strategies::FAKE => {
        let send_data: Vec<Vec<u8>> = fake::get_split_packet(&current_data);

        if send_data.len() > 1 {
          drop::send(&socket, fake::get_fake_packet(send_data[0].clone()));
          duplicate::send(&socket, send_data[0].clone());

          current_data = send_data[1].clone();
        }
      },
      Strategies::OOB => {
        let send_data: Vec<Vec<u8>> = oob::get_split_packet(&current_data);

        if send_data.len() > 1 {
          let _ = socket.write_all(&send_data[0]).ok();
          net::write_oob(&socket, core::parse_args().out_of_band_charid.into());

          current_data = send_data[1].clone();
        }
      },
      Strategies::DISOOB => { 
        let send_data: Vec<Vec<u8>> = disoob::get_split_packet(&current_data);
    
        if send_data.len() > 1 {
          duplicate::send(&socket, send_data[0].clone());
          net::write_oob(&socket, core::parse_args().out_of_band_charid.into());

          current_data = send_data[1].clone();
        }
      }
    }
  }

  current_data
}

fn main() {
  let config: AuxConfig = core::parse_args();

  println!("{}", format!("{:?}:{:?}", config.bind_host, config.bind_port).replace("\"", "").replace("\"", ""));

  let listener: TcpListener = TcpListener::bind(format!("{:?}:{:?}", config.bind_host, config.bind_port).replace("\"", "").replace("\"", "")).unwrap();

  for stream in listener.incoming() {
    match stream {
      Ok(mut client) => socks::socks5_proxy(&mut client, client_hook),
      Err(error) => println!("Socks5 proxy encountered an error: {}", error)
    };
  }
}

#[cfg(test)]

mod tests {
  use std::process::{Output, Command};
  use super::*;

  #[test]

  fn start_server() {
    thread::spawn(main);
  }

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

    println!("{}", string);

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

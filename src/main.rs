mod desync;
mod parsers;
mod net;
mod core;
mod socks;

use crate::desync::split::split;
use crate::desync::disorder::disorder;
use crate::desync::fake::fake;
use crate::desync::oob::oob;
use crate::desync::disoob::disoob;
use crate::parsers::parsers::IpParser;

use core::Strategies;
use core::Strategy;

use std::env;
use std::thread;
use std::net::TcpListener;
use std::net::TcpStream;
use std::io::Write;

fn client_hook(mut socket: TcpStream, data: &[u8]) -> Vec<u8> {
  let mut args: Vec<String> = env::args().collect();
  args.drain(0..1);
  
  if args.len() < 2 {
    args.drain(0..args.len());

    args.push("--disorder".to_string());
    args.push("1+s".to_string());
  }

  let mut current_data = data.to_vec();

  for index in (0..args.len()).step_by(2) {
    let first: String = args[index as usize].clone();
    let second: String = args[(index + 1) as usize].clone();

    let strategy: Strategy = Strategy::from(first, second);

    println!("[Send] Applied method: {:?}", strategy);

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
          let _ = socket.set_ttl(3);
          let _ = socket.write_all(&send_data[0]).ok();
          let _ = socket.set_ttl(100);

          current_data = send_data[1].clone();
        }
      },
      Strategies::FAKE => {
        let send_data: Vec<Vec<u8>> = fake::get_split_packet(&current_data);

        if send_data.len() > 1 {
          let _ = socket.set_ttl(2);
          let _ = socket.write_all(&fake::get_fake_packet(send_data[0].clone())).ok();

          let _ = socket.set_ttl(3);
          let _ = socket.write_all(&send_data[0]).ok();
          let _ = socket.set_ttl(100);

          current_data = send_data[1].clone();
        }
      },
      Strategies::OOB => {
        let send_data: Vec<Vec<u8>> = oob::get_split_packet(&current_data);

        if send_data.len() > 1 {
          let _ = socket.write_all(&send_data[0]).ok();
          net::write_oob(&socket, 213);

          current_data = send_data[1].clone();
        }
      },
      Strategies::DISOOB => { 
        let send_data: Vec<Vec<u8>> = disoob::get_split_packet(&current_data);
    
        if send_data.len() > 1 {
          let _ = socket.set_ttl(3);
          let _ = socket.write_all(&send_data[0]).ok();
          let _ = socket.set_ttl(100);

          net::write_oob(&socket, 213);

          current_data = send_data[1].clone();
        }
      }
    }
  }

  current_data
}

fn main() {
  let listener: TcpListener = TcpListener::bind("127.0.0.1:7878").unwrap();

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

    sender.arg("--socks5").arg("127.0.0.1:7878").arg("https://www.google.com");

    let output: Output = sender.output().unwrap();
    let string: String = format!("{:?}", output);

    assert_eq!(true, string.contains("html"));
  } 

  #[test]

  fn can_send_requests_youtube() {
    let mut sender: Command = Command::new("curl");

    sender.arg("--socks5").arg("127.0.0.1:7878").arg("https://www.youtube.com");

    let output: Output = sender.output().unwrap();
    let string: String = format!("{:?}", output);

    println!("{}", string);

    assert_eq!(true, string.contains("html"));
  } 

  #[test]

  fn can_send_requests_discord() {
    let mut sender: Command = Command::new("curl");

    sender.arg("--socks5").arg("127.0.0.1:7878").arg("https://discord.com");

    let output: Output = sender.output().unwrap();
    let string: String = format!("{:?}", output);

    assert_eq!(true, string.contains("html"));
  } 
}

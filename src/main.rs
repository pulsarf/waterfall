mod desync;
mod parsers;
mod net;
mod core;

use crate::desync::split::split;
use crate::desync::disorder::disorder;
use crate::desync::fake::fake;
use crate::desync::oob::oob;
use crate::desync::disoob::disoob;
use crate::parsers::parsers::IpParser;

use core::Strategies;
use core::Strategy;

use std::env;
use std::net::Shutdown;
use std::{
  io::{Read, Write},
  net::{TcpStream, TcpListener},
  thread
};

fn client_hook(mut socket: TcpStream, data: &[u8]) -> Vec<u8> {
  let mut args: Vec<String> = env::args().collect();
  args.drain(0..1);
  
  if args.len() < 2 {
    args.drain(0..args.len());

    args.push("--disorder".to_string());
    args.push("1+s".to_string());

    args.push("--split".to_string());
    args.push("5+s".to_string());
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

fn socks5_proxy(proxy_client: &mut TcpStream, client_hook: impl Fn(TcpStream, &[u8]) -> Vec<u8> + std::marker::Sync + std::marker::Send + 'static) {
  use std::sync::Arc;

  let mut client: TcpStream = match proxy_client.try_clone() {
    Ok(socket) => socket,
    Err(_error) => {
      println!("Connection dropped: failed to clone socket. {:?}", proxy_client);

      return;
    }
  };

  let _ = client.set_nodelay(true);

  let mut buffer = [0 as u8; 200];

  let mut state_auth: bool = false;

  while match client.read(&mut buffer) {
    Ok(_s) => {
      if !state_auth {
        // Client authentification packet. Reply with [5, 1] which stands for
        // no-authentification 

        match client.write(&[0x05, 0x00]) {
          Ok(_size) => println!("Authentification complete!"),
          Err(_error) => return
        }

        state_auth = true;
      } else {
        let mut parsed_data: IpParser = IpParser::parse(Vec::from(buffer));

        println!("Parsed IP data: {:?}", parsed_data);

        // Accept authentification and return connected IP
        // By default, if connected IP is not equal to the one
        // Client have chosen, the connection is dropped
        // So we can't just put [0, 0, 0, 0]

        // Server accept structure:
        // 0x05, 0, 0, dest_addr_type as u8, ..parsed_ip, port.as_bytes()

        let mut packet: Vec<u8> = vec![5, 0, 0, parsed_data.dest_addr_type];

        packet.extend_from_slice(&parsed_data.host_raw.as_slice());
        packet.extend_from_slice(&parsed_data.port.to_be_bytes());

        match client.write(&packet) {
          Ok(_size) => println!("[Auth] Accepted! {:?}", buffer),
          Err(_error) => return
        }

        // Create a socket connection and pipe to messages receiver 
        // Which is wrapped in other function

        let server_socket = TcpStream::connect(
          parsed_data.host_raw.
          iter_mut()
          .map(|fag| fag.to_string())
          .collect::<Vec<_>>()
          .join(".") + ":" + &parsed_data.port.to_string());

        println!("Socket instanced");

        match server_socket {
          Ok(mut socket) => {
            let _ = socket.set_nodelay(true);
            println!("Connected to socket: {:?}", socket);

            let mut socket1: TcpStream = socket.try_clone().unwrap();
            let mut client1: TcpStream = client.try_clone().unwrap();

            let func = Arc::new(client_hook);

            thread::spawn(move || {
              let msg_buffer: &mut [u8] = &mut [0u8; 1024];

              loop {
                match socket.read(msg_buffer) {
                  Ok(size) => {
                    if size > 0 {
                      let _ = client.write_all(&msg_buffer[..size]);
                    } else {
                      let _ = client.shutdown(Shutdown::Both);
                    }
                  }, Err(_error) => { }
                }
              }
            });

            thread::spawn(move || {
              let msg_buffer: &mut [u8] = &mut [0u8; 1024];

              loop {
                let client_hook_fn = Arc::clone(&func);

                match client1.read(msg_buffer) {
                  Ok(size) => {
                    if size > 0 {
                      let _ = socket1.write_all(&client_hook_fn(socket1.try_clone().unwrap(), &msg_buffer[..size]));
                    } else {
                      let _ = socket1.shutdown(Shutdown::Both);
                    }

                  }, Err(_error) => continue
                }
              }
            });

            return;
          },
          Err(_error) => {
            println!("Critical error happened! Couldn't restore from normal state, closing sockets.");
          }
        }
      }

      true
    },
    Err(_error) => false
  } {}

  println!("Connection complete: {:?}", client);
}

fn main() {
  let listener: TcpListener = TcpListener::bind("127.0.0.1:7878").unwrap();

  for stream in listener.incoming() {
    match stream {
      Ok(mut client) => socks5_proxy(&mut client, client_hook),
      Err(error) => println!("Socks5 proxy encountered an error: {}", error)
    };
  }
}

fn timeout_test() {
  use std::time::{SystemTime, Duration};

  let now: SystemTime = SystemTime::now();
  let listener: TcpListener = TcpListener::bind("127.0.0.1:7878").unwrap();

  for stream in listener.incoming() {
    if now.elapsed().unwrap() > Duration::new(5, 0) {
      panic!();
    }

    match stream {
      Ok(mut client) => socks5_proxy(&mut client, client_hook),
      Err(error) => println!("Socks5 proxy encountered an error: {}", error)
    };
  }
}


#[cfg(test)]

mod tests {
  use super::*;

  #[test]

  fn can_send_requests_google() {
    thread::spawn(timeout_test);

    use std::process::{Output, Command};
    
    let mut sender: Command = Command::new("curl");

    sender.arg("--verbose").arg("--ipv4").arg("--socks5").arg("127.0.0.1:7878").arg("https://www.google.com");

    let output: Output = sender.output().unwrap();
    let string: String = format!("{:?}", output);

    assert_eq!(true, string.contains("html"));
  } 

  #[test]

  fn can_send_requests_youtube() {
    thread::spawn(timeout_test);

    use std::process::{Output, Command};
    
    let mut sender: Command = Command::new("curl");

    sender.arg("--verbose").arg("--ipv4").arg("--socks5").arg("127.0.0.1:7878").arg("https://www.youtube.com/");

    let output: Output = sender.output().unwrap();
    let string: String = format!("{:?}", output);

    assert_eq!(true, string.contains("html"));
  } 

  #[test]

  fn can_send_requests_discord() {
    thread::spawn(timeout_test);

    use std::process::{Output, Command};
    
    let mut sender: Command = Command::new("curl");

    sender.arg("--verbose").arg("--ipv4").arg("--socks5").arg("127.0.0.1:7878").arg("https://discord.com/app");

    let output: Output = sender.output().unwrap();
    let string: String = format!("{:?}", output);

    assert_eq!(true, string.contains("html"));
  } 
}

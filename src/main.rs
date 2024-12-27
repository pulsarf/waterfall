mod features;

use crate::features::split::split;
use crate::features::disorder::disorder;
use crate::features::fake::fake;

use std::net::Shutdown;
use std::{
  io::{Read, Write},
  net::{TcpStream, TcpListener},
  thread
};

#[derive(Debug, Clone)]
struct IpParser {
  host_raw: Vec<u8>,
  port: u16,
  dest_addr_type: u8
}

impl IpParser {
  fn parse(buffer: Vec<u8>) -> IpParser {
    let dest_addr_type: u8 = buffer[1];

    return match dest_addr_type {
      1 => {
        IpParser {
          dest_addr_type,
          host_raw: vec![buffer[4], buffer[5], buffer[6], buffer[7]],
          port: 443u16
        }
      },
      _other => {
        IpParser {
          dest_addr_type,
          host_raw: vec![0, 0, 0, 0],
          port: 443u16
        }
      }
    }
  }
}

struct Config {
  split: bool,
  disorder: bool,
  fake: bool
}

fn client_hook(mut socket: TcpStream, data: &[u8]) -> Vec<u8> {
  let config: Config = Config {
    split: false,
    disorder: true,
    fake: false
  };

  if config.split {
    let send_data: Vec<Vec<u8>> = split::get_split_packet(data);

    if send_data.len() > 1 {
      if let Err(_e) = socket.write_all(&send_data[0]) {
        return data.to_vec();
      }

      return send_data[1].clone();
    }

    return data.to_vec();
  } else if config.disorder {
    let send_data: Vec<Vec<u8>> = disorder::get_split_packet(data);

    if send_data.len() > 1 {
      socket.set_ttl(1);
      socket.write_all(&send_data[0]);
      socket.set_ttl(100);

      return send_data[1].clone();
    }

    return data.to_vec();
  } else if config.fake {
    let send_data: Vec<Vec<u8>> = fake::get_split_packet(data);

    if send_data.len() > 1 {
      socket.set_ttl(0);
      socket.write_all(&fake::get_fake_packet(send_data[0].clone()));

      socket.set_ttl(1);
      socket.write_all(&send_data[0]);
      socket.set_ttl(100);

      return send_data[1].clone();
    }

    return data.to_vec();
  } else {
    return data.to_vec();
  }
}

fn socks5_proxy(proxy_client: &mut TcpStream) {
  let mut client: TcpStream = match proxy_client.try_clone() {
    Ok(socket) => socket,
    Err(_error) => {
      println!("Connection dropped: failed to clone socket. {:?}", proxy_client);

      return;
    }
  };

  client.set_nodelay(true);

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
            socket.set_nodelay(true);
            println!("Connected to socket: {:?}", socket);

            let mut socket1: TcpStream = socket.try_clone().unwrap();
            let mut client1: TcpStream = client.try_clone().unwrap();

            thread::spawn(move || {
              let msg_buffer: &mut [u8] = &mut [0u8; 1024];

              loop {
                match socket.read(msg_buffer) {
                  Ok(size) => {
                    if size > 0 {
                      let _ = client.write_all(&msg_buffer[..size]);
                    } else {
                      client.shutdown(Shutdown::Both);
                    }
                  }, Err(_error) => { }
                }
              }
            });

            thread::spawn(move || {
              let msg_buffer: &mut [u8] = &mut [0u8; 1024];

              loop {
                match client1.read(msg_buffer) {
                  Ok(size) => {
                    if size > 0 {
                      let _ = socket1.write_all(&client_hook(socket1.try_clone().unwrap(), &msg_buffer[..size]));
                    } else {
                      socket1.shutdown(Shutdown::Both);
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
      Ok(mut client) => socks5_proxy(&mut client),
      Err(error) => println!("Socks5 proxy encountered an error: {}", error)
    };
  }
}


#[cfg(test)]

mod tests {
  use super::*;

  #[test]

  fn can_send_requests_google() {
    thread::spawn(main);

    use std::process::{Output, Command};
    
    let mut sender: Command = Command::new("curl");

    sender.arg("--verbose").arg("--ipv4").arg("--socks5").arg("127.0.0.1:7878").arg("https://www.google.com");

    let output: Output = sender.output().unwrap();
    let string: String = format!("{:?}", output);

    assert_eq!(true, string.contains("google"));
  } 

  #[test]

  fn can_send_requests_youtube() {
    thread::spawn(main);

    use std::process::{Output, Command};
    
    let mut sender: Command = Command::new("curl");

    sender.arg("--verbose").arg("--ipv4").arg("--socks5").arg("127.0.0.1:7878").arg("https://www.youtube.com");

    let output: Output = sender.output().unwrap();
    let string: String = format!("{:?}", output);

    assert_eq!(true, string.contains("google"));
  } 

  #[test]

  fn can_send_requests_discord() {
    thread::spawn(main);

    use std::process::{Output, Command};
    
    let mut sender: Command = Command::new("curl");

    sender.arg("--verbose").arg("--ipv4").arg("--socks5").arg("127.0.0.1:7878").arg("https://discord.com/app");

    let output: Output = sender.output().unwrap();
    let string: String = format!("{:?}", output);

    assert_eq!(true, string.contains("discord"));
  } 
}

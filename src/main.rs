mod desync;
mod parsers;

use crate::desync::split::split;
use crate::desync::disorder::disorder;
use crate::desync::fake::fake;
use crate::desync::oob::oob;
use crate::desync::disoob::disoob;
use crate::parsers::parsers::IpParser;

use clap::{Parser, ArgAction};
use std::net::Shutdown;
use std::{
  io::{Read, Write},
  net::{TcpStream, TcpListener},
  thread
};

#[derive(Parser, Debug, Clone)]
#[command(version, about, long_about = None)]
struct Config {
    /// Enable stream segmentation
    #[arg(short, long, action=ArgAction::SetTrue, default_value_t = false)]
    split: bool,

    /// Enable segments sequence inversion
    #[arg(short = 'D', long, action=ArgAction::SetTrue, default_value_t = false)]
    disorder: bool,

    /// Enable fake packets with segments sequence inversion
    #[arg(short, long, action=ArgAction::SetTrue, default_value_t = false)]
    fake: bool,

    /// Enable segmentation with out-of-band data between them
    #[arg(short, long, action=ArgAction::SetTrue, default_value_t = false)]
    oob: bool,

    /// Enable segmentation with our-of-band data between then and reversed order of those segments
    #[arg(short, long, action=ArgAction::SetTrue, default_value_t = false)]
    disoob: bool,
}

fn write_oob(mut socket: &TcpStream, oob_char: u8) {
  if cfg!(unix) {
    #[cfg(target_os = "linux")]
    use libc::{c_int, send, MSG_OOB};
    #[cfg(target_os = "linux")]
    use std::os::unix::io::{AsRawFd, RawFd};

    #[cfg(target_os = "linux")]
    let fd = socket.as_raw_fd();

    unsafe {
      #[cfg(target_os = "linux")]
      send(fd, (&[oob_char]).as_ptr() as *const _, 1, MSG_OOB);
    }
  } else if cfg!(windows) {
    #[cfg(target_os = "windows")]
    use winapi::um::winsock2::{send, MSG_OOB};
    #[cfg(target_os = "windows")]
    use std::os::windows::io::{AsRawSocket, RawSocket};

    #[cfg(target_os = "windows")]
    let rs: RawSocket = socket.as_raw_socket();

    unsafe {
      #[cfg(target_os = "windows")]
      send(rs.try_into().unwrap(), (&[oob_char]).as_ptr() as *const _, 1, MSG_OOB);
    }
  } else {
    panic!("Unsupported OS type! Cannot use Out-Of-Band/Disordered Out-Of-Band");
  }
}

fn client_hook(config: Config, mut socket: TcpStream, data: &[u8]) -> Vec<u8> {
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
      socket.set_ttl(3);
      socket.write_all(&send_data[0]);
      socket.set_ttl(100);

      return send_data[1].clone();
    }

    return data.to_vec();
  } else if config.fake {
    let send_data: Vec<Vec<u8>> = fake::get_split_packet(data);

    if send_data.len() > 1 {
      socket.set_ttl(2);
      socket.write_all(&fake::get_fake_packet(send_data[0].clone()));

      socket.set_ttl(3);
      socket.write_all(&send_data[0]);
      socket.set_ttl(100);

      return send_data[1].clone();
    }

    return data.to_vec();
  } else if config.oob {
    let send_data: Vec<Vec<u8>> = oob::get_split_packet(data);
    
    if send_data.len() > 1 {
      socket.write_all(&send_data[0]);
      write_oob(&socket, 213);

      return send_data[1].clone();
    }

    return data.to_vec();
  } else if config.disoob {
    let send_data: Vec<Vec<u8>> = disoob::get_split_packet(data);
    
    if send_data.len() > 1 {
      socket.set_ttl(3);
      socket.write_all(&send_data[0]);
      socket.set_ttl(100);

      write_oob(&socket, 213);

      return send_data[1].clone();
    }

    return data.to_vec();
  } else {
    return data.to_vec();
  }
}

fn socks5_proxy(proxy_client: &mut TcpStream, config: Config) {
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
            let config1: Config = config.clone();

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
                      let _ = socket1.write_all(&client_hook(config1.clone(), socket1.try_clone().unwrap(), &msg_buffer[..size]));
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
  let config: Config = Config::parse();

  for stream in listener.incoming() {
    match stream {
      Ok(mut client) => socks5_proxy(&mut client, config.clone()),
      Err(error) => println!("Socks5 proxy encountered an error: {}", error)
    };
  }
}

fn timeout_test() {
  use std::time::{SystemTime, Duration};

  let now: SystemTime = SystemTime::now();
  let listener: TcpListener = TcpListener::bind("127.0.0.1:7878").unwrap();
  let config: Config = Config {
    split: false,
    disorder: true,
    fake: false,
    oob: false,
    disoob: false
  };

  for stream in listener.incoming() {
    if now.elapsed().unwrap() > Duration::new(5, 0) {
      panic!();
    }

    match stream {
      Ok(mut client) => socks5_proxy(&mut client, config.clone()),
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

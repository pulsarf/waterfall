use std::sync::Arc;
use std::net::UdpSocket;

use crate::IpParser;
use crate::core;

use std::{
  io::{Read, Write},
  net::{TcpStream, SocketAddr},
  thread
};

pub fn socks5_proxy(proxy_client: &mut TcpStream, client_hook: impl Fn(&TcpStream, &[u8]) -> Vec<u8> + std::marker::Sync + std::marker::Send + 'static) {
  let mut client: TcpStream = proxy_client.try_clone().unwrap();

  let mut buffer = [0 as u8; 128];

  let _ = client.set_nodelay(true);
  let _ = client.read(&mut buffer);
  let _ = client.write_all(&[5, 0]);
  let _ = client.read(&mut buffer);
  
  let parsed_data: IpParser = IpParser::parse(Vec::from(buffer));
  let mut packet: Vec<u8> = vec![5, 0, 0, parsed_data.dest_addr_type];

  if parsed_data.dest_addr_type == 3 {
    packet.extend_from_slice(&[parsed_data.host_unprocessed.len().try_into().unwrap()]);
  }

  packet.extend_from_slice(&parsed_data.host_unprocessed.as_slice());
  packet.extend_from_slice(&parsed_data.port.to_be_bytes());

  // Create a socket connection and pipe to messages receiver 
  // Which is wrapped in other function
 
  let sock_addr = match parsed_data.host_raw.len() {
    4 => {
      let mut sl: [u8; 4] = [0, 0, 0, 0];

      for iter in 0..4 {
        sl[iter] = parsed_data.host_raw[iter];
      }

      SocketAddr::new(sl.into(), parsed_data.port)
    },
    16 => {
      let mut sl: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

      for iter in 0..16 {
        sl[iter] = parsed_data.host_raw[iter];
      }

      SocketAddr::new(sl.into(), parsed_data.port)
    },
    _ => SocketAddr::new([0, 0, 0, 0].into(), parsed_data.port)
  };

  let server_socket = TcpStream::connect(sock_addr);

  if parsed_data.is_udp { 
    println!("UDP Associate");

    let udp_socket = UdpSocket::bind("0.0.0.0:0").unwrap(); 
    let _ = udp_socket.connect(sock_addr); 

    let udp_socket1 = udp_socket.try_clone().unwrap();
    let mut client1 = client.try_clone().unwrap();
        
    thread::spawn(move || { 
      let mut buf = [0u8; 1024]; 
      loop { 
        match udp_socket.recv(&mut buf) { 
          Ok(size) => { 
            let _ = client.write_all(&buf[..size]); 
          }, Err(_) => break 
        } 
      } 
    }); 

    thread::spawn(move || { 
      let mut buf = [0u8; 1024]; 
      loop { 
        match client1.read(&mut buf) { 
          Ok(size) => { 
            if size > 0 { 
              let _ = udp_socket1.send(&buf[..size]); 
            } else { break } 
          }, Err(_) => break 
        } 
      } 
    }); 

    return;
  }

  match server_socket {
    Ok(mut socket) => {
      let _ = client.write_all(&packet);

      let _ = socket.set_nodelay(true);
      let _ = client.set_nodelay(true);

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
              } else { break }
            }, Err(_error) => break
          }
        }
      });

      thread::spawn(move || {
        let msg_buffer: &mut [u8] = &mut [0u8; 1024];
        let client_hook_fn = Arc::clone(&func);
        let mut hops: u64 = 0;

        loop {
          match client1.read(msg_buffer) {
            Ok(size) => {
              if size > 0 {
                if hops < core::parse_args().packet_hop {
                  let data: Vec<u8> = client_hook_fn(&socket1, &msg_buffer[..size]);

                  if data.len() > 1 {
                    let _ = socket1.write_all(&data);

                    hops += 1;
                  }
                } else {
                  let _ = socket1.write_all(&msg_buffer[..size]);
                }
              } else { break }
            }, Err(_error) => break
          }
        }
      });
    },
    Err(_) => { }
  }
}

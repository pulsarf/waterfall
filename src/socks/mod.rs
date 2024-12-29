use std::net::Shutdown;
use std::sync::Arc;
use crate::IpParser;

use std::{
  io::{Read, Write},
  net::{TcpStream, SocketAddr},
  thread
};

pub fn socks5_proxy(proxy_client: &mut TcpStream, client_hook: impl Fn(TcpStream, &[u8]) -> Vec<u8> + std::marker::Sync + std::marker::Send + 'static) {
  let mut client: TcpStream = match proxy_client.try_clone() {
    Ok(socket) => socket,
    Err(_error) => {
      return;
    }
  };

  let _ = client.set_nodelay(true);

  let mut buffer = [0 as u8; 200];

  let mut state_auth: bool = false;

  while match client.read(&mut buffer) {
    Ok(_s) => {
      if _s <= 0 {
        return;
      }

      if !state_auth {
        // Client authentification packet. Reply with [5, 0] which stands for
        // no-authentification 

        let _ = client.write(&[5, 0]);

        state_auth = true;
      } else {
        let parsed_data: IpParser = IpParser::parse(Vec::from(buffer));
        let mut packet: Vec<u8> = vec![5, 0, 0, parsed_data.dest_addr_type];

        packet.extend_from_slice(&parsed_data.host_raw.as_slice());
        packet.extend_from_slice(&parsed_data.port.to_be_bytes());

        let _ = client.write(&packet);

        // Create a socket connection and pipe to messages receiver 
        // Which is wrapped in other function

        let mut raw_host = parsed_data.host_raw;

        let server_socket = TcpStream::connect(match raw_host.len() {
          4 => {
            let mut sl: [u8; 4] = [0, 0, 0, 0];
            raw_host.resize(4, 0);

            for iter in 0..4 {
              sl[iter] = raw_host[iter];
            }

            SocketAddr::new(sl.into(), parsed_data.port)
          },
          6 => {
            let mut sl: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
            raw_host.resize(16, 0);

            for iter in 0..16 {
              sl[iter] = raw_host[iter];
            }

            SocketAddr::new(sl.into(), parsed_data.port)
          },
          _ => SocketAddr::new([0, 0, 0, 0].into(), parsed_data.port)
        });

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
            println!("Critical error happened! Couldn't restore from normal state, closing sockets: {:?}", _error);

            let _ = client.shutdown(Shutdown::Both);
            return;
          }
        }
      }

      true
    },
    Err(_error) => false
  } {}

  println!("Connection complete: {:?}", client);
}
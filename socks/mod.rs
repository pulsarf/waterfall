use std::net::UdpSocket;

use crate::IpParser;
use crate::core;

use std::{
  io::{Read, Write, BufRead, BufReader, BufWriter},
  net::{TcpStream, SocketAddr},
  sync::Arc,
  thread,
  pin::Pin
};

use std::io;

struct BufReaderHook<R, F> {
    inner: BufReader<R>,
    hook: F,
    socket: TcpStream,
    hops: u64,
    max_hops: u64,
}

impl<R: Read, F> Read for BufReaderHook<R, F>
where
    F: Fn(&TcpStream, &[u8]) -> Vec<u8> + Send + Sync + 'static,
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let size = self.inner.read(buf)?;
        if size > 0 && self.hops < self.max_hops {
            let processed = (self.hook)(&self.socket, &buf[..size]);
            let len = processed.len().min(buf.len());
            buf[..len].copy_from_slice(&processed[..len]);
            self.hops += 1;
            Ok(len)
        } else {
            Ok(size)
        }
    }
}

fn find_udp_payload_start(packet: &[u8]) -> usize {
  if packet.len() < 4 { return 0; }
    
  match packet[3] {
    1 => 4 + 4 + 2,
    3 => {
      if packet.len() < 5 { return 0; }
      4 + 1 + packet[4] as usize + 2
    },
    4 => 4 + 16 + 2,
    _ => 0,
  }
}

pub fn socks5_proxy(proxy_client: &mut TcpStream, client_hook: impl Fn(&TcpStream, &[u8]) -> Vec<u8> + std::marker::Sync + std::marker::Send + 'static) {
  let mut client: TcpStream = proxy_client.try_clone().unwrap();

  let mut buffer = [0 as u8; 128];

  let _ = client.set_nodelay(true);
  let _ = client.read(&mut buffer);

  if buffer[0] != 5 {
      let _ = client.write_all(&[5, 0]);

      return;
  }
  
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
      let ip_bytes: [u8; 4] = parsed_data.host_raw[..4].try_into()
          .expect("host_raw must have at least 4 bytes for IPv4");

      SocketAddr::new(ip_bytes.into(), parsed_data.port)
    },
    16 => {
      let ip_bytes: [u8; 16] = parsed_data.host_raw[..16].try_into()
          .expect("host_raw must have at least 16 bytes for IPv6");

      SocketAddr::new(ip_bytes.into(), parsed_data.port)
    },
    _ => SocketAddr::new([0, 0, 0, 0].into(), parsed_data.port)
  };

  if parsed_data.is_udp {
    println!("UDP Associate Requested");
        
    let udp_socket = UdpSocket::bind("0.0.0.0:0").unwrap();
    let udp_port = udp_socket.local_addr().unwrap().port();
        

    let udp_response = vec![
      5, 0, 0, 1,
      0, 0, 0, 0,
      (udp_port >> 8) as u8, (udp_port & 0xFF) as u8 
    ];
    
    let _ = client.write_all(&udp_response);

    drop(udp_response);
        
    let mut client_clone = client.try_clone().unwrap();
    let udp_socket_clone = udp_socket.try_clone().unwrap(); 

    thread::spawn(move || {
      let mut buf = [0u8; 65535];

      loop {
        match udp_socket.recv_from(&mut buf) {
          Ok((size, _src)) => {
            let payload_start = find_udp_payload_start(&buf[..size]);
            let _ = client_clone.write_all(&buf[payload_start..size]);
          },
          Err(_) => break,
        }
      }
    });
        
    thread::spawn(move || {
      let mut buf = [0u8; 65535];
      
      loop {
        match client.read(&mut buf) {
          Ok(size) => {
            if size == 0 { break; }

            let mut packet = Vec::with_capacity(size + 10);
            packet.extend(&[0, 0, 0]);
            packet.push(1);
            packet.extend(&[0, 0, 0, 0]);
            packet.extend(&[0, 0]);
            packet.extend(&buf[..size]);
            
            let _ = udp_socket_clone.send_to(&packet, sock_addr);

          },
          Err(_) => break,
        }
      }
    });
        
    return;
  }

  let server_socket = core::connect_socket(sock_addr);

  match server_socket {
    Ok(mut socket) => {
      if let Err(_) = client.write_all(&packet) {
          println!("Failed initial packet write");
      };

      drop(packet);

      socket.set_nodelay(true).unwrap_or(());
      client.set_nodelay(true).unwrap_or(()); 

      let mut client_reader = client.try_clone().unwrap();
      let socket_reader = socket.try_clone().unwrap();
      
      thread::spawn(move || {
          io::copy(
              &mut BufReader::new(socket_reader), 
              &mut client
          ).unwrap_or(0);
      });

      thread::spawn(move || {
          let mut processor = BufReaderHook {
              inner: BufReader::new(&mut client_reader),
              hook: client_hook,
              socket: socket.try_clone().unwrap(),
              hops: 0,
              max_hops: core::parse_args().packet_hop
          };

          io::copy(&mut processor, &mut socket).unwrap_or(0);
        });
    },
    Err(_) => { }
  }
}

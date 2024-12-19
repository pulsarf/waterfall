use std::{
  io::{Read, Write},
  net::{TcpStream, TcpListener},
  thread
};

#[derive(Debug)]
struct PacketAbstraction {
  split_parts: Vec<Packet>,
  send_after_inbound: Vec<Packet>
}

#[derive(Debug, Clone)]
struct Packet {
  raw_body: Vec<u8>,
  time_to_live: u8,
  is_udp: bool,
  is_out_of_band: bool,
  synchronize_mss: u16,
  split_index: usize
}

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

impl Packet {
  fn new(default_ttl: u8, is_udp: bool, is_out_of_band: bool, split_index: usize) -> Packet {
    let packet: Packet = Packet {
      raw_body: vec![],
      time_to_live: default_ttl,
      is_udp, is_out_of_band, split_index,
      synchronize_mss: 1500
    };

    packet
  }

  fn push(&mut self, hex_byte: u8) -> u8 {
    self.raw_body.push(hex_byte);

    hex_byte
  }

  fn set_mss(&mut self, mss: u16) -> &mut Packet {
    self.synchronize_mss = mss;

    self
  }

  fn get_mutable(&mut self) -> &mut Packet {
    self
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
            println!("Connected to socket: {:?}", socket);

            let mut socket1: TcpStream = socket.try_clone().unwrap();
            let mut client1: TcpStream = client.try_clone().unwrap();

            thread::spawn(move || {
              let mut msg_buffer: &mut [u8] = &mut [0u8; 1024];

              loop {
                match socket.read(msg_buffer) {
                  Ok(size) => {
                    client.write_all(&msg_buffer[..size]);
                  }, Err(_error) => continue
                }
              }
            });

            thread::spawn(move || {
              let mut msg_buffer: &mut [u8] = &mut [0u8; 1024];

              loop {
                match client1.read(msg_buffer) {
                  Ok(size) => {
                    socket1.write_all(&msg_buffer[..size]);

                  }, Err(_error) => continue
                }
              }
            });

            return;
          },
          Err(_error) => {
            println!("FUCK THIS NIGGA WTF");
            panic!("yill kourself");
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

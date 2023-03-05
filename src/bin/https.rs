/*
 * Copyright (c) 2023, Tobias Müller <git@tsmr.eu>
 *
 */

use anothertls::net::TlsListener;
use anothertls::TlsConfig;
use std::{
    io,
    net::{TcpListener, ToSocketAddrs},
};

struct HttpsServer {
    listener: TlsListener,
}

impl HttpsServer {
    pub fn bind<A: ToSocketAddrs>(addr: A) -> io::Result<Self> {
        let listener = TcpListener::bind(addr)?;
        let listener = TlsListener::new(listener, TlsConfig {});
        Ok(Self { listener })
    }

    pub fn static_file_server(&self, _http_root: &str) {
        loop {
            match self.listener.accept() {
                Ok((mut socket, _addr)) => {
                    log::debug!("Waiting for tls handshake");

                    if let Err(e) = socket.do_handshake_block() {
                        println!("Error parsing handshake: {:?}", e);
                        break;
                    }

                    log::debug!("New Connection");

                    let mut buf: [u8; 4096] = [0; 4096];

                    loop {
                        let n = match socket.read(&mut buf) {
                            Ok(n) => n,
                            _ => break,
                        };

                        log::info!("Read from socket: {}", n);
                        socket.write(&buf[..n]);
                    }
                }
                Err(e) => log::error!("couldn't get client: {:?}", e),
            };
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    HttpsServer::bind("127.0.0.1:4000")?.static_file_server("./");
    Ok(())
}

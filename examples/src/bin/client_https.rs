/*
 * Copyright (c) 2023, Tobias Müller <git@tsmr.eu>
 *
 */

use anothertls::{ClientConnection, ClientConfigBuilder};
use std::net::TcpStream;

fn main() {
    // openssl x509 -noout -text -in src/bin/config/anothertls.local.cert

    let config = ClientConfigBuilder::new()
        .enable_keylog()
        .build()
        .unwrap();

    let tcp = TcpStream::connect("google.de:443").expect("Error binding to tcp socket.");
    let mut sock = ClientConnection::connect(tcp, &config).expect("Couldn't connect to server.");

    println!("New secure connection");

    let data = b"\
GET / HTTP/1.1\r\n\
User-Agent: AnotherTls/0.1\r\n\
\r\n";

    sock
        .tls_write(data)
        .expect("Error writing to socket.");

    let mut buf: [u8; 4096] = [0; 4096];
    let n = sock.tls_read(&mut buf).expect("Error reading from socket.");
    println!(
        "--- Request --- \n{}\n---------------",
        String::from_utf8(buf[..n - 4].to_vec()).unwrap()
    );
}


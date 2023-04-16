/*
 * Copyright (c) 2023, Tobias Müller <git@tsmr.eu>
 *
 */

use anothertls::{ClientConnection, ClientConfigBuilder};
use std::net::TcpStream;

fn main() {
    // openssl x509 -noout -text -in src/bin/config/anothertls.local.cert

    let server_name = "one.one.one.one".to_string();
    // let server_name = "www.google.de".to_string();
    let host = server_name.clone() + ":443";
    let server_name = "localhost".to_string();
    let host = server_name.clone() + ":4000";

    let config = ClientConfigBuilder::new()
        .set_server_name(server_name.clone())
        .enable_keylog()
        .build()
        .unwrap();

    let tcp = TcpStream::connect(host).expect("Error binding to tcp socket");
    let mut sock = ClientConnection::connect(tcp, &config).expect("Couldn't connect to server");

    println!("New secure connection");

    let data = format!("\
GET / HTTP/1.1\r\n\
Host: {}
User-Agent: AnotherTls/0.1\r\n\
\r\n", server_name);

    sock
        .tls_write(data.as_bytes())
        .expect("Error writing to socket.");

    let mut buf: [u8; 4096] = [0; 4096];
    let n = sock.tls_read(&mut buf).expect("Error reading from socket.");
    println!(
        "--- Response --- \n{}\n---------------",
        String::from_utf8(buf[..n].to_vec()).unwrap()
    );
}


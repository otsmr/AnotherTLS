/*
 * Copyright (c) 2023, Tobias Müller <git@tsmr.eu>
 *
 */

// #![cfg(feature = "debug")]
use anothertls::{ServerConfigBuilder, ServerConnection};
use std::net::TcpListener;

fn main() {
    // openssl x509 -noout -text -in src/bin/config/anothertls.local.cert

    let config = ServerConfigBuilder::new()
        // .enable_keylog()
        .add_cert_pem("./examples/src/bin/config/server.cert".to_string())
        .add_privkey_pem("./examples/src/bin/config/server.key".to_string())
        .build()
        .unwrap();

    let tcp = TcpListener::bind("127.0.0.1:4000").expect("Error binding to tcp socket.");
    let listener = ServerConnection::new(tcp, config);

    loop {
        let (mut sock, _) = listener.accept().expect("Couldn't get client");

        println!("New secure connection");

        let mut buf: [u8; 4096] = [0; 4096];

        let n = sock.tls_read(&mut buf).expect("Error reading from socket.");
        println!(
            "--- Request --- \n{}\n---------------",
            String::from_utf8(buf[..n - 4].to_vec()).unwrap()
        );
        let data = b"\
HTTP/1.1 200\r\n\
Server: AnotherTls/1.0\r\n\
Content-Type: text/html; charset=utf-8\r\n\
Content-Length: 12\r\n\
\r\n\
Hello world!";
        sock.tls_write(data).expect("Error writing to socket.");
    }
}

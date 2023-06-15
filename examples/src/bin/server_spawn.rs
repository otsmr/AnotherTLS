/*
 * Copyright (c) 2023, Tobias Müller <git@tsmr.eu>
 *
 */

#![allow(unused_must_use)]
use anothertls::{ServerConfigBuilder, ServerConnection};
use std::net::TcpListener;

fn main() {

    anothertls::log::init();

    let config = ServerConfigBuilder::new()
        .enable_keylog()
        .add_cert_pem("./examples/src/bin/config/server.cert".to_string())
        .add_privkey_pem("./examples/src/bin/config/server.key".to_string())
        .build()
        .unwrap();

    println!("Listening on 0.0.0.0:4000");

    let tcp = TcpListener::bind("0.0.0.0:4000").expect("Error binding to tcp socket.");
    let listener = ServerConnection::new(tcp, config);

    loop {

        let mut socket = match listener.accept() {
            Ok((s, _)) => s,
            Err(e) => {
                println!("Error while connecting: {e:?}");
                continue;
            },
        };

        std::thread::spawn(move || {
            socket.tls_write(b"\
                HTTP/1.1 200\r\n\
                Server: VulnTLS/1.0\r\n\
                Content-Type: text/html; charset=utf-8\r\n\
                Content-Length: 12\r\n\
                \r\n\
                Hello world!"
            );
        });

    }
}

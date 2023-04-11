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
        .set_keylog_path("./examples/src/bin/config/keylog.txt".to_string())
        .set_client_cert_custom_verify_fn(|cert| {
            let name = match cert.tbs_certificate.subject.get("commonName") {
                Ok(e) => e,
                Err(_) => return false,
            };
            name == "otsmr"
        })
        .add_client_cert_ca("./examples/src/bin/config/client_cert/ca.cert".to_string())
        .add_cert_pem("./examples/src/bin/config/server.cert".to_string())
        .add_privkey_pem("./examples/src/bin/config/server.key".to_string())
        .build()
        .unwrap();

    let tcp = TcpListener::bind("127.0.0.1:4000").expect("Error binding to tcp socket.");
    let listener = ServerConnection::new(tcp, config);

    let (mut sock, _) = listener.accept().expect("Couldn't get client");


    println!("New secure connection");

    let mut buf: [u8; 4096] = [0; 4096];

    let n = sock.read(&mut buf).expect("Error reading from socket.");
    println!(
        "--- Request --- \n{}\n---------------",
        String::from_utf8(buf[..n - 4].to_vec()).unwrap()
    );
    let body = "Hello admin!\n";
    let data = format!("\
HTTP/1.1 200\r\n\
Server: AnotherTls/1.0\r\n\
Content-Type: text/html; charset=utf-8\r\n\
Content-Length: {}\r\n\
\r\n\
{}", body.len(), body);
    sock
        .write_all(data.as_bytes())
        .expect("Error writing to socket.");
}

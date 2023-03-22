/*
 * Copyright (c) 2023, Tobias Müller <git@tsmr.eu>
 *
 */

// #![cfg(feature = "debug")]

use anothertls::net::{config::TlsConfigBuilder, TlsListener};
use anothertls::TlsConfig;
use std::{
    io,
    net::{TcpListener, ToSocketAddrs},
};

struct HttpsServer {
    listener: TlsListener,
}

impl HttpsServer {
    pub fn bind<A: ToSocketAddrs>(addr: A, config: TlsConfig) -> io::Result<Self> {
        let listener = TcpListener::bind(addr)?;
        let listener = TlsListener::new(listener, config);
        Ok(Self { listener })
    }

    pub fn static_file_server(&self, _http_root: &str) {
        loop {
            let client = self.listener.accept();
            if let Ok((mut socket, _addr)) = client {
                println!("Waiting for tls handshake");

                if let Err(e) = socket.do_handshake_block() {
                    println!("Error parsing handshake: {:?}", e);
                    continue;
                }

                println!("New secure connection");

                let mut buf: [u8; 4096] = [0; 4096];

                let receive = socket.read(&mut buf);
                if let Ok(n) = receive {
                    println!(
                        "--- Request --- \n{}\n---------------",
                        String::from_utf8(buf[..n-4].to_vec()).unwrap()
                    );
                    let not_found = b"\
HTTP/1.1 404 Not Found\r\n\
Server: AnotherTls/1.0\r\n\
Content-Type: text/html; charset=utf-8\r\n\
Content-Length: 118\r\n\
\r\n\
<!DOCTYPE html>\r\n\
<html>\r\n\
    <head>\r\n\
        <title>404 Not Found</title>\r\n\
    </head>\r\n\
    <body>\r\n\
        <h1>Not Found</h1>\r\n\
    </body>\r\n\
</html>\r\n";
                    if let Err(e) = socket.write_all(not_found) {
                        println!("Error write_all: {:?}", e);
                        continue;
                    }
                } else {
                    println!("Error reading = {:?}", receive.err().unwrap());
                }
                // socket.read_to_end();
            } else if let Err(e) = client {
                println!("Couldn't get client: {:?}", e);
            }
            break;
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Starting HTTPS Server");
    // openssl x509 -noout -text -in src/bin/config/anothertls.local.cert
    let config = TlsConfigBuilder::new()
        .set_keylog_path(
            "./examples/src/bin/config/keylog.txt".to_string(),
        )
        .add_client_cert_ca("./examples/src/bin/config/client_cert/ca.cert".to_string())
        .add_cert_pem("./examples/src/bin/config/server.cert".to_string())
        .add_privkey_pem("./examples/src/bin/config/server.key".to_string())
        .build()
        .unwrap();

    HttpsServer::bind("127.0.0.1:4000", config)?.static_file_server("~/");
    Ok(())
}

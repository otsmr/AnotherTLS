use anothertls::{update_to_tls_listener, TlsConfig, TlsListener};
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

        let listener = update_to_tls_listener(listener, TlsConfig {});

        Ok(Self { listener })
    }

    pub fn static_file_server(&self, _http_root: &str) {
        match self.listener.accept() {
            Ok((_socket, _addr)) => {
                log::debug!("New Connection");
            }
            Err(e) => log::error!("couldn't get client: {:?}", e),
        };
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    HttpsServer::bind("127.0.0.1:4000")?.static_file_server("./");

    Ok(())
}

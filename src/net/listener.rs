use crate::net::TlsStream;
use crate::TlsConfig;
use std::net::TcpListener;
use std::net::SocketAddr;
use std::io::Result;


pub struct TlsListener {
    server: TcpListener,
    config: TlsConfig
}

impl TlsListener {

    pub fn new(server: TcpListener, config: TlsConfig) -> Self {
        Self { server, config }
    }

    pub fn accept(&self) -> Result<(TlsStream, SocketAddr)> {

        let (socket, addr) = self.server.accept()?;

        let stream = TlsStream::new(socket, addr, &self.config);

        Ok((stream, addr))
    }

}

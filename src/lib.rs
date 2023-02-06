use std::{
    io,
    net::{SocketAddr, TcpListener, TcpStream},
};

pub struct TlsStream<'a> {
    stream: TcpStream,
    addr: SocketAddr,
    config: &'a TlsConfig
}

impl<'a> TlsStream<'a> {
    pub fn new(stream: TcpStream, addr: SocketAddr, config: &'a TlsConfig) -> Self {
        Self { stream, addr, config }
    }
}

pub struct TlsConfig {

}

pub struct TlsListener {
    server: TcpListener,
    config: TlsConfig
}

impl TlsListener {
    pub fn new(server: TcpListener, config: TlsConfig) -> Self {
        Self { server, config }
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.server.local_addr()
    }

    pub fn accept(&self) -> io::Result<(TlsStream, SocketAddr)> {

        let (socket, addr) = self.server.accept()?;

        let stream = TlsStream::new(socket, addr, &self.config);

        Ok((stream, addr))
    }
}

pub fn update_to_tls_listener(tcp: TcpListener, config: TlsConfig) -> TlsListener {
    TlsListener::new(tcp, config)
}


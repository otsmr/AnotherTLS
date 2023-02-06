use std::{
    io::{self, Read},
    net::{SocketAddr, TcpStream, TcpListener}, os::raw,
};
use std::io::Result;


#[derive(PartialEq)]
enum HandshakeState {
    WaitingForClientHello,
    SendServerHello,
    Finished,
}

pub struct TlsStream<'a> {
    stream: TcpStream,
    addr: SocketAddr,
    config: &'a TlsConfig
}

pub struct Extension {

}

pub struct CipherSuite {

}

struct ClientHello {
    legacy_version: u16,
    random: [u8; 32],
    // legacy_session_id,
    cipher_suites: [CipherSuite; 200], // FIXME: 2**16-2
    legacy_compression_methods: [u8; 32],
    extensions: Extension,
}
impl ClientHello {
    pub fn from_raw(buf: &[u8]) {



    }
}

impl<'a> TlsStream<'a> {

    pub fn new(stream: TcpStream, addr: SocketAddr, config: &'a TlsConfig) -> Self {
        Self { stream,  addr, config }
    }


    pub fn connect_block(&mut self) -> Result<()> {

        let mut state = HandshakeState::WaitingForClientHello;

        while state != HandshakeState::Finished {

            let mut raw_buf: [u8; 4096] = [0; 4096];

            let n = self.stream.read(&mut raw_buf)?;


            println!("{:?}", &raw_buf[..n]);

            let client_hello = ClientHello::from_raw(&raw_buf[..n]);

            // println!("{:?}", client_hello);



            panic!("");


            state = HandshakeState::Finished;

        }

        Ok(())


    }

    pub fn read<'b>(&'b mut self, buf: &'b mut [u8]) -> Result<usize> {

        let mut raw_buf: [u8; 4096] = [0; 4096];

        let n = self.stream.read(&mut raw_buf)?;


        Ok(n)

    }

    pub fn write<'b>(&'b mut self, src: &'b [u8]) {

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

    pub fn accept(&self) -> io::Result<(TlsStream, SocketAddr)> {

        let (socket, addr) = self.server.accept()?;

        let stream = TlsStream::new(socket, addr, &self.config);

        Ok((stream, addr))
    }

}

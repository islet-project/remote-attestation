use std::{net::TcpStream, ops::DerefMut};
use rustls::{Stream, ConnectionCommon, SideData};
use std::ops::Deref;

pub struct RaTlsConnection<C> {
    sock: TcpStream,
    conn: C,
}

impl<C: DerefMut + Deref<Target = ConnectionCommon<S>>, S: SideData> RaTlsConnection<C> {
    pub fn new(sock: TcpStream, conn: C) -> Self {
        Self { sock, conn }
    }

    pub fn stream<'a>(&'a mut self) -> Stream<'a, C, TcpStream> {
        Stream::new(&mut self.conn, &mut self.sock)
    }
}

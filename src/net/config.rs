/*
 * Copyright (c) 2023, Tobias Müller <git@tsmr.eu>
 *
 */


use ibig::IBig;

use crate::rand::RngCore;

pub struct TlsConfig {
    // pub server_name: Option<String>,
    // ca: Option<Certificate<'a>>,
    // cert: Option<Certificate<'a>>,
}

impl TlsConfig {

}

pub struct TlsContext<'a> {
    pub config: &'a TlsConfig,
    pub rng: Box<dyn RngCore<IBig>>
}

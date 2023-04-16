/*
 * Copyright (c) 2023, Tobias Müller <git@tsmr.eu>
 *
 */

// TODO: Validate server certificate against os trusted CA
// $ security verify-cert

pub struct ClientConfig {
    pub(crate) server_name: Option<String>,
    #[allow(unused)]
    pub(crate) keylog: Option<String>,
}

pub struct ClientConfigBuilder {
    keylog: Option<String>,
    server_name: Option<String>
}

impl Default for ClientConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl ClientConfigBuilder {
    pub fn new() -> Self {
        ClientConfigBuilder {
            keylog: None,
            server_name: None
        }
    }
    pub fn set_server_name(mut self, server_name: String) -> Self {
        self.server_name = Some(server_name);
        self
    }
    pub fn set_keylog_path(mut self, filepath: String) -> Self {
        self.keylog = Some(filepath);
        self
    }
    pub fn enable_keylog(mut self) -> Self {
        self.keylog = Some("keylog.txt".to_string());
        self
    }
    pub fn build(self) -> std::result::Result<ClientConfig, String> {
        Ok(ClientConfig {
            keylog: self.keylog,
            server_name: self.server_name
        })
    }
}


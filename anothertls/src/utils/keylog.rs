/*
 * Copyright (c) 2023, Tobias Müller <git@tsmr.eu>
 *
 */

use crate::net::record::RecordPayloadProtection;
use std::fs::OpenOptions;

use super::bytes;
use std::io::Write;


pub struct KeyLog {
    filepath: String,
    client_random: String
}

impl KeyLog {
    pub fn new(filepath: String, client_random: &[u8]) -> Self {
        let client_random = bytes::to_hex(client_random);
        Self {filepath, client_random}
    }

    pub fn append_from_record_payload_protection(&self, keys: &RecordPayloadProtection) {

        if let Some(akeys) = keys.application_keys.as_ref() {
            self.append_application_traffic_secrets(&akeys.server.traffic_secret, &akeys.client.traffic_secret);
        } else {
            self.append_handshake_traffic_secrets(&keys.handshake_keys.server.traffic_secret, &keys.handshake_keys.client.traffic_secret);
        }

    }

    pub fn append_application_traffic_secrets(&self, server: &[u8], client: &[u8]) {
        let mut content = String::new();
        content += "SERVER_TRAFFIC_SECRET_0 ";
        content += &self.client_random;
        content += " ";
        content += &bytes::to_hex(server);
        content += "\n";

        content += "CLIENT_TRAFFIC_SECRET_0 ";
        content += &self.client_random;
        content += " ";
        content += &bytes::to_hex(client);
        self.append_to_file(content)
    }
    pub fn append_handshake_traffic_secrets(&self, server: &[u8], client: &[u8]) {
        let mut content = String::new();
        content += "SERVER_HANDSHAKE_TRAFFIC_SECRET ";
        content += &self.client_random;
        content += " ";
        content += &bytes::to_hex(server);
        content += "\n";

        content += "CLIENT_HANDSHAKE_TRAFFIC_SECRET ";
        content += &self.client_random;
        content += " ";
        content += &bytes::to_hex(client);
        self.append_to_file(content)
    }

    fn append_to_file(&self, content: String) {
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .append(true)
            .open(&self.filepath)
            .unwrap_or_else(|_| panic!("Couldn't open or create keylog file {}", self.filepath));

        if let Err(e) = writeln!(file, "{}", content) {
            eprintln!("Couldn't write to file: {}", e);
        }
    }
}

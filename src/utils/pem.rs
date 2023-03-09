use std::{fs, collections::HashMap};

use super::base64;

#[derive(PartialEq, Debug)]
enum PemState {
    Start,
    InContent,
    End
}

pub fn get_pem_content_from_file(filepath: String) -> Option<HashMap<String, Vec<u8>>> {
    let pem = match fs::read_to_string(filepath) {
        Ok(e) => e,
        Err(_) => return None
    };
    let mut content = HashMap::new();
    let mut state = PemState::Start;
    let mut current_title = String::new();
    let mut current_content = String::new();
    for line in pem.split('\n') {
        match state {
            PemState::InContent => {
                if line.starts_with("-----END") {
                    let raw = base64::decode(&current_content)?;
                    content.insert(current_title.to_owned(), raw);
                    state = PemState::End;
                    current_content.clear();
                } else {
                    current_content += line;
                }
            }
            PemState::End | PemState::Start => {
                if line.starts_with("-----BEGIN") {
                    current_title = line[11..(line.len()-5)].to_string();
                    state = PemState::InContent;
                }
            }
        }
    }
    if state != PemState::End {
        return None;
    }
    Some(content)
}

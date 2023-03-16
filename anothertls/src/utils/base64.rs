/*
 * Copyright (c) 2023, Tobias Müller <git@tsmr.eu>
 *
 */

const CHARS: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

#[allow(dead_code)]
pub fn encode(input: &[u8]) -> String {
    let mut out = Vec::new();
    let mut tmp = [0; 3];
    let mut index = 0;
    let mut add = 0;

    while input.len() > index {
        for i in 0..3 {
            if input.len() <= i + index {
                tmp[i] = 0x0;
                add += 1;
            } else {
                tmp[i] = input[index + i];
            }
        }

        index += 3;

        let mut a = tmp[0] >> 2 & 63;
        out.push(CHARS.chars().nth(a as usize).unwrap());
        a = ((tmp[0] & 3) << 4 | (tmp[1] >> 4)) & 63;
        out.push(CHARS.chars().nth(a as usize).unwrap());
        a = ((tmp[1] & 15) << 2 | (tmp[2] >> 6)) & 63;
        out.push(CHARS.chars().nth(a as usize).unwrap());
        a = tmp[2] & 63;
        out.push(CHARS.chars().nth(a as usize).unwrap());
    }

    if add > 0 {
        let l = out.len() - 1;
        for i in 0..add {
            out[l - i] = '=';
        }
    }

    out.iter().collect()
}

pub fn decode(input: &str) -> Option<Vec<u8>> {
    let len = input.len();

    if len % 4 != 0 {
        return None;
    }

    let mut tmp = [0u8; 4];

    let mut reverse_characters = [0u8; 'z' as usize + 1];

    for (i, &c) in CHARS.as_bytes().iter().enumerate() {
        reverse_characters[c as usize] = i as u8;
    }

    let mut input_iter = input.chars();
    let mut out = vec![];
    let mut padding_len = 0;

    let mut consumed = 0;
    while consumed < input.len() {
        consumed += 4;
        for (i, t) in tmp.iter_mut().enumerate() {
            let idx = i + 1;
            let ch = input_iter
                .next()
                .unwrap_or(if idx <= 2 { '=' } else { '\0' });
            if ch == '=' {
                *t = 0;
                padding_len += 1;
            } else {
                *t = reverse_characters[ch as usize];
            }
        }

        out.push((tmp[0] << 2) | (tmp[1] >> 4));
        out.push((tmp[1] << 4) | (tmp[2] >> 2));
        out.push((tmp[2] << 6) | tmp[3]);
    }

    for _ in 0..padding_len {
        out.pop();
    }

    Some(out)
}

#[cfg(test)]
mod tests {
    use crate::utils::base64;
    fn get_test_strings() -> [(&'static str, &'static str); 7] {
        [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ]
    }

    #[test]
    fn test_base64_encode() {
        let test_strings = get_test_strings();
        for (raw, b64) in test_strings {
            assert_eq!(base64::encode(raw.as_bytes()), b64.to_string());
        }
    }
    #[test]
    fn test_base64_decode() {
        let test_strings = get_test_strings();
        for (raw, b64) in test_strings {
            assert_eq!(base64::decode(b64).unwrap(), raw.as_bytes().to_vec());
        }
    }
}

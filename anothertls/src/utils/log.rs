/*
 * Copyright (c) 2023, Tobias Müller <git@tsmr.eu>
 *
 */

use std::env;

#[derive(PartialEq, PartialOrd, Clone, Debug)]
pub enum LogLevel {
    None = 0,
    Error = 1,
    Debug = 2,
    // Info,
    Fixme = 3,
}

pub static mut LOG_LEVEL: LogLevel = LogLevel::None;

pub fn check_log_level(level: LogLevel) -> bool {
    unsafe { LOG_LEVEL >= level }
}

pub fn init() {
    for (key, value) in env::vars() {
        if key == "RUST_LOG" {
            match value.to_lowercase().as_str() {
                "debug" => unsafe { LOG_LEVEL = LogLevel::Debug },
                "error" => unsafe { LOG_LEVEL = LogLevel::Error },
                "fixme" => unsafe { LOG_LEVEL = LogLevel::Fixme },
                _ => ()
            }
            break;
        }
    }
}

// #[macro_export]
macro_rules! fixme {
    ($($x: expr),*) => {{
        $(
            if crate::utils::log::check_log_level(crate::utils::log::LogLevel::Fixme) {
                print!("\x1b[36;2m! ");
                println!($x);
                print!("\x1b[0m");
            }
        )*
    }}
}
pub(crate) use fixme;

// #[macro_export]
macro_rules! debug {
    ($($x: expr),*) => {{
        $(
            if crate::utils::log::check_log_level(crate::utils::log::LogLevel::Debug) {
                    print!("\x1b[33;2m* ");
                    println!($x);
                    print!("\x1b[0m");
            }
        )*
    }}
}
pub(crate) use debug;

// #[macro_export]
macro_rules! error {
    ($($x: expr),*) => {{
        $(

            if crate::utils::log::check_log_level(crate::utils::log::LogLevel::Error) {
                print!("\x1b[31;1m* ");
                println!($x);
                print!("\x1b[0m");
            }

        )*
    }}
}
pub(crate) use error;

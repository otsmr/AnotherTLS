

#[macro_export]
macro_rules! debug {
    ($($x: expr),*) => {{
        $(
            print!("\x1b[33;2m* ");
            println!($x);
            print!("\x1b[0m");

        )*
    }}
}
pub(crate) use debug;

#[macro_export]
macro_rules! error {
    ($($x: expr),*) => {{
        $(
            print!("\x1b[31;1m* ");
            println!($x);
            print!("\x1b[0m");

        )*
    }}
}
pub(crate) use error;


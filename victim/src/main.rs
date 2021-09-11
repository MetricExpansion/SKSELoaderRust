use std::ptr::null_mut;

use wide_literals::w;
use winapi::um::winuser::{MessageBoxW, MB_OK};

fn main() {
    unsafe {
        let title = w!("Message from Victim");
        let message = w!("Hello, I am an innocent victim process who doesn't know that things are a bit different!");
        MessageBoxW(null_mut(), message, title, MB_OK);
    };
}

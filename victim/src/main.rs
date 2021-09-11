use std::ptr::null_mut;

use widestring::WideCString;
use winapi::um::winuser::{MessageBoxW, MB_OK};

fn main() {
    unsafe {
        let title = WideCString::from_str("Message from Victim").unwrap();
        let message = WideCString::from_str("Hello, I am an innocent victim process who doesn't know that things are a bit different!").unwrap();
        MessageBoxW(null_mut(), message.as_ptr(), title.as_ptr(), MB_OK);
    };
}

#[allow(unused_imports)]
#[macro_use]
extern crate log;
extern crate env_logger;
extern crate crypto;

use crypto::aes::generic::ExpandedKey128;


fn main() {
    if let Err(_) = std::env::var("RUST_LOG") {
        std::env::set_var("RUST_LOG", "debug");
    }
    env_logger::init();
    
    let input = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    ];
    let key = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    ];
    
    let ek128  = ExpandedKey128::new(&key);
    println!("{:?}", ek128);

    println!("===================== Encrypt ===================");
    println!("Input: {:?}", &input[..]);
    let output = ek128.encrypt(&input);
    println!("Output: {:?}", &output[..]);

    println!("===================== Decrypt ===================");
    println!("Input: {:?}", &output[..]);
    let output2 = ek128.decrypt(&output);
    println!("Output: {:?}", &output2[..]);

    println!();
    println!("Ret: {}", input == output2);
}

#![crate_name="vault"]
#![allow(unstable)]

#[macro_use] extern crate log;
extern crate hyper;
extern crate url;
extern crate regex;
extern crate "rustc-serialize" as serialize;

use self::http::*;

pub mod http;

pub fn connect(key: &str, secret: &str){
  let mut client = rest::VaultClient::new("djvault", key, secret);
  let result = client.get_key("mykey");

  match result {
    Ok(res) => {
      println!("response: {:?}", res.status);
    }
    Err(res) => {
      println!("error: {:?}", res);
    }
  }

  println!("hello world");
}

#![crate_name="vault"]
#![allow(unstable)]

#[macro_use] extern crate log;
extern crate hyper;
extern crate url;
extern crate regex;
extern crate "rustc-serialize" as rustc_serialize;

use self::http::vault_client;

pub mod http;

pub fn connect(vault: &str, key: &str, secret: &str){
  let mut client = vault_client::VaultClient::new(vault, key, secret);
  let result = client.get_key("mykey");

  match result {
    Ok(mut res) => {
      println!("response: {:?}", res.read_to_string());
    }
    Err(res) => {
      println!("error: {:?}", res);
    }
  }

  println!("hello world");
}

#![crate_name="vault"]
#![allow(unstable)]

#[macro_use] extern crate log;
extern crate hyper;
extern crate url;
extern crate regex;
extern crate "rustc-serialize" as rustc_serialize;

use http::vault_client::AzureVaultClient;
use http::vault_client::VaultClient;

pub mod http;

pub fn connect(vault: &str, key: &str, secret: &str){
  let mut client: AzureVaultClient = VaultClient::new(vault, key, secret);
  let mykey = client.get_key("mykey");

  match mykey {
    Ok(key) => {
      println!("response: {:?}", key);
    }
    Err(err) => {
      println!("error: {:?}", err);
    }
  }
}

#![crate_name="vault"]
#![feature(old_io)]
#![feature(core)]
#![feature(collections)]

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

  display_current_keys_list(&mut client);

  delete_existing_key(&mut client, "mynewkey1");

  display_current_keys_list(&mut client);

  insert_new_key(&mut client, "mynewkey1");

  display_current_keys_list(&mut client);

  display_key_by_name(&mut client, "mynewkey1")
}

fn display_key_by_name(client: &mut AzureVaultClient, key_name: &str){
  let mykey = client.get_key(key_name);
  match mykey {
    Ok(key) => {
      println!("Found Key {:?} with Payload: {:?}\n", key_name, key);
    },
    Err(err) => {
      println!("error: {:?}", err);
    }
  }
}

fn delete_existing_key(client: &mut AzureVaultClient, key_name: &str){
  let deleted_key = client.delete_key(key_name);
  println!("Deleted Key with name: {:?}\n", key_name);
}

fn insert_new_key(client: &mut AzureVaultClient, key_name: &str){
  let key_ops_vec = vec!["verify", "decrypt", "encrypt", "sign"];
  let key_ops = key_ops_vec.iter().map(|&op| String::from_str(op)).collect();
  let create_key = client.create_key(key_name, key_ops);
  println!("Created Key with name: {:?}\n", key_name);
}

fn display_current_keys_list(client: &mut AzureVaultClient){
  let list = client.list();
  match list {
    Ok(keys) => {
      println!("Current Key List: {:?}\n", keys);
    },
    Err(err) => {
      println!("error: {:?}", err);
    }
  }
}

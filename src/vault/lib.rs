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

use rustc_serialize::base64::{FromBase64};

pub fn connect(vault: &str, key: &str, secret: &str){
  let mut client: AzureVaultClient = VaultClient::new(vault, key, secret);

  display_current_keys_list(&mut client);

  delete_existing_key(&mut client, "mynewkey1");

  display_current_keys_list(&mut client);

  insert_new_key(&mut client, "mynewkey1");

  display_encrypt_decrypt(&mut client, "mynewkey1", "Hello World!".to_string());

  display_current_keys_list(&mut client);

  display_key_by_name(&mut client, "mynewkey1")
}

fn display_encrypt_decrypt(client: &mut AzureVaultClient, key_name: &str, message: String){
  println!("Original Message: {:?}\n", message);
  let encrypted_message = client.encrypt(key_name, message.as_bytes()).unwrap();
  let encrypted_bits = encrypted_message.as_slice().from_base64().unwrap();
  println!("Encrypted Message: {:?}\n", encrypted_bits);
  println!("Length of Message: {:?}\n", encrypted_bits.len());
  let decrypted_message = client.decrypt(key_name, encrypted_bits.as_slice()).unwrap();
  let decrypted_bits = decrypted_message.from_base64().unwrap();
  println!("Decrypted Message: {:?}\n", String::from_utf8(decrypted_bits).unwrap());
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

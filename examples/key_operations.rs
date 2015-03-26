#![feature(collections)]
extern crate vault;
extern crate crypto;
extern crate rustc_serialize;

use std::env;

use vault::http::client::{Vault, AzureVault};

use rustc_serialize::base64::{FromBase64};
use rustc_serialize::hex::FromHex;

use crypto::digest::Digest;
use crypto::sha2::Sha512;

fn main() {
    let mut vault = String::new();
    let mut key = String::new();
    let mut secret = String::new();

    get_arg(1, &mut vault);
    get_arg(2, &mut key);
    get_arg(3, &mut secret);

    println!("vault: {:?}, key: {:?}, secret: {:?}", vault, key, secret);

    let mut client: AzureVault = Vault::new(&vault[..], &key[..], &secret[..]);

    display_current_keys_list(&mut client);

    delete_existing_key(&mut client, "mynewkey1");

    display_current_keys_list(&mut client);

    insert_new_key(&mut client, "mynewkey1");

    display_encrypt_decrypt(&mut client, "mynewkey1", "Hello World!".to_string());

    display_sign_verify(&mut client, "mynewkey1", "Hello World!".to_string());

    display_current_keys_list(&mut client);

    display_key_by_name(&mut client, "mynewkey1")
}

fn get_arg(index: usize, buf: &mut String){
    match env::args().nth(index) {
        Some(arg) => buf.push_str(&arg[..]),
        None => {
            panic!("Usage: key_operations <vault_name> <key> <secret>");
        }
    };
}

fn display_sign_verify(client: &mut AzureVault, key_name: &str, message: String){
    let mut hasher = Sha512::new();
    hasher.input_str(&message[..]);
    let hex = hasher.result_str().from_hex().unwrap();
    println!("SHA512 Hash for '{:?}': {:?}\n", message, hex);
    let signature = client.sign(key_name, hex.clone()).unwrap();
    println!("Signature of hash: {:?}\n", signature);
    let is_verified = client.verify(key_name, hex.clone(), signature.clone()).unwrap();
    println!("is verified: {:?}\n", is_verified);
}

fn display_encrypt_decrypt(client: &mut AzureVault, key_name: &str, message: String){
    println!("Original Message: {:?}\n", message);
    let encrypted_message = client.encrypt(key_name, message.as_bytes()).unwrap();
    let encrypted_bits = &encrypted_message[..].from_base64().unwrap();
    println!("Encrypted Message: {:?}\n", encrypted_bits);
    println!("Length of Message: {:?}\n", encrypted_bits.len());
    let decrypted_message = client.decrypt(key_name, &encrypted_bits[..]).unwrap();
    let decrypted_bits = decrypted_message.from_base64().unwrap();
    println!("Decrypted Message: {:?}\n", String::from_utf8(decrypted_bits).unwrap());
}

fn display_key_by_name(client: &mut AzureVault, key_name: &str){
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

fn delete_existing_key(client: &mut AzureVault, key_name: &str){
    let deleted_key = client.delete_key(key_name).unwrap();
    println!("Deleted Key with id: {:?}\n", deleted_key.key.kid);
}

fn insert_new_key(client: &mut AzureVault, key_name: &str){
    let key_ops_vec = vec!["verify", "decrypt", "encrypt", "sign"];
    let key_ops = key_ops_vec.iter().map(|&op| String::from_str(op)).collect();
    let create_key = client.create_key(key_name, key_ops).unwrap();
    println!("Created Key with id: {:?}\n", create_key.key.kid);
}

fn display_current_keys_list(client: &mut AzureVault){
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

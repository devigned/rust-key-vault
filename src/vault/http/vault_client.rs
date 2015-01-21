
use hyper;
use hyper::client::*;
use hyper::net::{HttpConnector};

use std::io::IoError;
use url::ParseError;
use hyper::HttpError;
use http::authenticate_header::*;

pub struct VaultClient<'a>{
  client: Client<HttpConnector<'a>>,
  vault_name: &'a str,
  key: &'a str,
  secret: &'a str,
}

impl<'a> VaultClient<'a> {
    pub fn new(vault_name: &'a str, key: &'a str, secret: &'a str) -> VaultClient<'a> {
      VaultClient{
        client: Client::new(),
        vault_name: vault_name,
        key: key,
        secret: secret
        }
    }

    pub fn get_key(&'a mut self, key_name: &str) -> Result<Response, HttpError>{
      let url_str = VaultClient::key_url(self.vault_name, key_name, &mut String::new());
      let url = url_str.as_slice();
      println!("{:?}", url);
      VaultClient::handle_result(self.client.get(url).send())
    }

    fn key_url(vault_name: &str, key_name: &str, url: &mut String) -> String{
      url.push_str("https://{vault_name}.vault.azure.net/keys/{key_name}");
      url.replace("{vault_name}", vault_name)
        .replace("{key_name}", key_name)
    }

    fn handle_result(mut result: Result<Response, HttpError>) -> Result<Response, HttpError>{
      match result {
        Ok(res) => {
          let headers = res.headers.clone();
          match res.status {
            hyper::status::StatusCode::Unauthorized => {

              let auth = headers.get::<WwwAuthenticate<Bearer>>().unwrap();
              println!("Authorization url: {:?}", &auth.0.authorization[]);
              Ok(res)
            },
            _ => Ok(res)
          }
        }
        Err(err) => Err(err)
      }
    }
}

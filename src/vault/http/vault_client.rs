
use hyper;
use hyper::client::{Client, Response};
use hyper::HttpError;
use hyper::method::Method;
use hyper::method::Method::{Get, Post, Delete, Put, Patch};
use hyper::net::{HttpConnector};
use hyper::status::StatusCode;

use url;

use http::authenticate_header::*;

pub struct VaultClient<'a>{
  client: Client<HttpConnector<'a>>,
  vault_name: &'a str,
  key: &'a str,
  secret: &'a str,
  auth_token: Option<String>
}


impl<'a> VaultClient<'a> {
    pub fn new(vault_name: &'a str, key: &'a str, secret: &'a str) -> VaultClient<'a> {
      VaultClient{
        client: Client::new(),
        vault_name: vault_name,
        key: key,
        secret: secret,
        auth_token: None
        }
    }

    pub fn get_key<'b>(&mut self, key_name: &str) -> hyper::HttpResult<String>{
      let url_str = VaultClient::key_url(self.vault_name, key_name);
      let url = url_str.as_slice();
      println!("{:?}", url);
      let result = self.client.get(url).send();

      match VaultClient::handle_result(&mut self.client, result, self.key.clone(), self.secret.clone()) {
        Ok(mut res) => {
          match res.read_to_string(){
            Ok(string) => Ok(string),
            Err(err) => panic!("io-error reading body: {:?}", err)
          }
          },
        Err(err) => Err(err)
      }
    }

    fn key_url<'b>(vault_name: &str, key_name: &str) -> String{
      let mut url = String::from_str("https://{vault_name}.vault.azure.net/keys/{key_name}");
      url.replace("{vault_name}", vault_name)
        .replace("{key_name}", key_name)
    }

    fn handle_result(client: &mut Client<HttpConnector>, result: hyper::HttpResult<Response>, key: &str, secret: &str) -> hyper::HttpResult<Response>{
      match result {
        Ok(res) => {
          match res.status {
            StatusCode::Unauthorized => {
              let ref my_res = res;
              let bearer_header = my_res.headers.get::<WwwAuthenticate<Bearer>>();
              match bearer_header {
                Some(header) => {
                  println!("Authorization url: {:?}", &header.0.authorization);
                  let mut auth_url = header.0.authorization.clone();
                  auth_url.push_str("/oauth2/token");
                  let resource = header.0.resource.as_slice();
                  match VaultClient::authenticate(client, auth_url.as_slice(), resource, key, secret){
                    Ok(auth_res) => {
                      println!("{:?}", auth_res.status);
                      Ok(auth_res)
                    },
                    Err(err) => Err(err)
                  }
                },
                None => panic!("401 with no WWW-Authenticate header!")
              }
            },
            _ => Ok(res)
          }
        }
        Err(err) => Err(err)
      }
    }

    fn authenticate(client: &mut Client<HttpConnector>, auth_url: &str, resource: &str, key: &str, secret: &str) -> hyper::HttpResult<Response> {
      let parmas = vec![("client_id", key),
                        ("client_secret", secret),
                        ("resource", resource),
                        ("grant_type", "client_credentials")];
      let headers = vec![("content", "application/x-www-form-urlencoded")];
      VaultClient::pstar_with_params(client, Method::Post, auth_url, parmas.into_iter(), headers.into_iter())
    }

    fn pstar_with_params<I, J>(client: &mut Client<HttpConnector>, method: Method, url: &str, params: I, mut headers: J) -> Result<Response, HttpError>
                          where I: Iterator<Item = (&'a str, &'a str)>,
                                J: Iterator<Item = (&'static str, &'a str)>{
      let mut req_headers = hyper::header::Headers::new();
      let post_body = url::form_urlencoded::serialize(params);

      for (key, value) in headers {
        let static_key: &'static str = key.clone();
        req_headers.set_raw(static_key, vec![value.as_bytes().to_vec()])
      }

      client.request(method, url)
        .headers(req_headers)
        .body(post_body.as_slice())
        .send()
    }
}

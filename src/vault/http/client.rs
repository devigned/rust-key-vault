// TODO: read for caching idea:
// http://mainisusuallyafunction.blogspot.ru/2014/10/a-taste-of-rust-yum-for-cc-programmers_29.html

use hyper;
use hyper::client::{Client, Response};
use hyper::header::{Authorization, ContentType};
use hyper::HttpError;
use hyper::method::Method;
use hyper::method::Method::{Post};
use hyper::mime::*;
use hyper::status::{StatusCode, StatusClass};

use url;

use std::collections::BTreeMap;
use std::cmp::PartialEq;
use std::error::Error;
use std::io::Error as IoError;
use std::io::ErrorKind;
use std::io::{Read};
use std::string::String;

use rustc_serialize::json;
use rustc_serialize::json::DecodeResult;
use rustc_serialize::base64::{ToBase64, FromBase64, URL_SAFE};
use rustc_serialize::Decodable;

use http::authenticate_header::*;

// authentication bearer token
#[derive(RustcEncodable, RustcDecodable, Debug, Clone)]
struct AuthToken {
  token_type: String,
  expires_in: i32,
  expires_on: i32,
  not_before: i32,
  resource: String,
  access_token: String,
}

// Azure Key Vault asymmetric key representation
#[derive(RustcEncodable, RustcDecodable, Debug, Clone)]
pub struct KeyWrapper {
  pub key: Key,
  pub attributes: Attributes,
}

#[derive(RustcEncodable, RustcDecodable, Debug, Clone)]
pub struct Key {
  pub kid: String,
  pub kty: String,
  pub n: String,
  pub e: String,
  pub key_ops: Vec<String>,
}

#[derive(RustcEncodable, RustcDecodable, Debug, Clone)]
pub struct KeyListItem {
  pub kid: String,
  attributes: Attributes
}

#[derive(RustcEncodable, RustcDecodable, Debug, Clone)]
struct CreateKey {
  kty: String,
  key_ops: Vec<String>,
  attributes: Attributes
}

#[derive(RustcEncodable, RustcDecodable, PartialEq, Debug, Clone)]
pub struct Attributes {
  pub enabled: Option<bool>,
  pub exp: Option<i32>,
  pub nbf: Option<i32>
}

pub struct AzureVault<'a>{
  client: Client,
  vault_name: &'a str,
  key: &'a str,
  secret: &'a str,
  auth_token: Option<AuthToken>
}

impl<'a> AzureVault<'a> {

    fn execute_wrapper<F: Fn(&mut Client, Option<AuthToken>) -> hyper::HttpResult<Response>>(vault_client: &mut AzureVault, req_fn: F) -> hyper::HttpResult<Response>{
      match req_fn(&mut vault_client.client, vault_client.auth_token.clone()) {
        Ok(res) => {
          match res.status {
            StatusCode::Unauthorized => {
              match AzureVault::handle_401(vault_client, res) {
                Ok(mut auth_res) => {
                    let mut body = String::new();
                    let _ = auth_res.read_to_string(&mut body);
                    match auth_res.status.class() {
                        StatusClass::Success => {
                            println!("Response: {}", auth_res.status);
                            println!("Headers:\n{}", auth_res.headers);
                            let decode_result: DecodeResult<AuthToken> = json::decode(body.as_ref());
                            match decode_result {
                                Ok(token) => {
                                    vault_client.auth_token = Some(token);
                                    req_fn(&mut vault_client.client, vault_client.auth_token.clone())
                                },
                                Err(err) => {
                                    Err(HttpError::from(IoError::new(ErrorKind::Other, err.description())))
                                }
                            }
                        },
                        _ => Err(HttpError::from(IoError::new(ErrorKind::Other, &format!("Status: {} :: Response: {}", auth_res.status, body)[..])))
                    }
                },
                Err(err) => Err(err)
              }
            },
            _ => Ok(res)
          }
        },
        Err(err) => Err(err)
      }
    }

    fn handle_401(vault_client: &mut AzureVault, response: Response) -> hyper::HttpResult<Response>{
      let bearer_header = response.headers.get::<WwwAuthenticate<Bearer>>();
      match bearer_header {
        Some(header) => {
          let mut auth_url = header.0.authorization.clone();
          auth_url.push_str("/oauth2/token");
          let resource = header.0.resource.as_ref();
          AzureVault::authenticate(&mut vault_client.client, auth_url.as_ref(), resource, vault_client.key, vault_client.secret)
        },
        None => panic!("401 with no WWW-Authenticate header!")
      }
    }

    fn authenticate(client: &mut Client, auth_url: &str, resource: &str, key: &str, secret: &str) -> hyper::HttpResult<Response> {
      let parmas = vec![("client_id", key),
                        ("client_secret", secret),
                        ("resource", resource),
                        ("grant_type", "client_credentials")];
      let headers = vec![("content", "application/x-www-form-urlencoded")];
      AzureVault::pstar_with_params(client, Method::Post, auth_url, parmas.into_iter(), headers.into_iter())
    }

    fn pstar_with_params<I, J>(client: &mut Client, method: Method, url: &str, params: I, headers: J) -> Result<Response, HttpError>
                          where I: Iterator<Item = (&'a str, &'a str)>,
                                J: Iterator<Item = (&'static str, &'a str)>{
      let mut req_headers = hyper::header::Headers::new();
      let post_body = url::form_urlencoded::serialize(params);

      for (key, value) in headers {
        let static_key: &'static str = key.clone();
        req_headers.set_raw(static_key, vec![value.as_bytes().to_vec()])
      }

      let hyper_body: &str = post_body.as_ref();
      client.request(method, url)
        .headers(req_headers)
        .body(hyper_body)
        .send()
    }

    fn key_url<'b>(vault_name: &str, key_name: &str, operation: Option<&str>) -> String{
      let op_string = match operation {
          Some(op) => {
            format!("/{}", op)
          },
          None => {
            format!{""}
          }
      };
      format!("https://{}.vault.azure.net/keys/{}{}?api-version=2014-12-08-preview", vault_name, key_name, op_string)
    }

    fn root_keys_url<'b>(vault_name: &str) -> String{
        format!("https://{}.vault.azure.net/keys?api-version=2014-12-08-preview", vault_name)
    }
}

pub trait Vault<'a>: {
  fn new(vault_name: &'a str, key: &'a str, secret: &'a str) -> Self;
  fn list<'b>(&mut self) -> hyper::HttpResult<Vec<KeyListItem>>;
  fn get_key<'b>(&mut self, key_name: &str) -> hyper::HttpResult<KeyWrapper>;
  fn update_key<'b>(&mut self, key: KeyWrapper) -> hyper::HttpResult<KeyWrapper>;
  fn delete_key<'b>(&mut self, key_name: &str) -> hyper::HttpResult<KeyWrapper>;
  fn create_key<'b>(&mut self, key_name: &str, key_ops: Vec<String>) -> hyper::HttpResult<KeyWrapper>;
  fn encrypt<'b>(&mut self, key_name: &str, data: &[u8]) -> hyper::HttpResult<String>;
  fn decrypt<'b>(&mut self, key_name: &str, data: &[u8]) -> hyper::HttpResult<String>;
  fn wrap<'b>(&mut self, key_name: &str, cek:  &[u8]) -> hyper::HttpResult<String>;
  fn unwrap<'b>(&mut self, key_name: &str, cek:  &[u8]) -> hyper::HttpResult<String>;
  fn sign<'b>(&mut self, key_name: &str, message:  Vec<u8>) -> hyper::HttpResult<Vec<u8>>;
  fn verify<'b>(&mut self, key_name: &str, message:  Vec<u8>, signiture: Vec<u8>) -> hyper::HttpResult<bool>;
  fn crypto_operation<T>(&mut self, payload: BTreeMap<&str, String>, url: String) -> hyper::HttpResult<T> where T : PartialEq + Decodable;
}

impl<'a> Vault<'a> for AzureVault<'a> {
  fn new(vault_name: &'a str, key: &'a str, secret: &'a str) -> AzureVault<'a> {
    AzureVault{
      client: Client::new(),
      vault_name: vault_name,
      key: key,
      secret: secret,
      auth_token: None
    }
  }

  fn get_key<'b>(&mut self, key_name: &str) -> hyper::HttpResult<KeyWrapper>{
    let url_str = AzureVault::key_url(self.vault_name, key_name, None);
    let url: &str = url_str.as_ref();
    let execute_get_key = |client: &mut Client, auth_token: Option<AuthToken>| {
      match auth_token {
        Some(token) => {
          let mut req_headers = hyper::header::Headers::new();
          req_headers.set(Authorization(BearerToken { token: token.access_token.clone() }));
          client.get(url).headers(req_headers).send()
        },
        None => client.get(url).send()
      }
    };

    match AzureVault::execute_wrapper(self, execute_get_key) {
      Ok(mut res) => {
        let mut body = String::new();
        let _ = res.read_to_string(&mut body);
        let key: KeyWrapper = json::decode(body.as_ref()).unwrap();
        Ok(key)
      },
      Err(err) => Err(err)
    }
  }

  fn update_key<'b>(&mut self, key: KeyWrapper) -> hyper::HttpResult<KeyWrapper>{
    Ok(key)
  }

  fn delete_key<'b>(&mut self, key_name: &str) -> hyper::HttpResult<KeyWrapper>{
    let url_str = AzureVault::key_url(self.vault_name, key_name, None);
    let url: &str = url_str.as_ref();
    let execute_delete_key = |client: &mut Client, auth_token: Option<AuthToken>| {
      match auth_token {
        Some(token) => {
          let mut req_headers = hyper::header::Headers::new();
          req_headers.set(Authorization(BearerToken { token: token.access_token.clone() }));
          client.delete(url).headers(req_headers).send()
        },
        None => client.delete(url).send()
      }
    };

    match AzureVault::execute_wrapper(self, execute_delete_key) {
      Ok(mut res) => {
        let mut body = String::new();
        let _ = res.read_to_string(&mut body);
        let key: KeyWrapper = json::decode(body.as_ref()).unwrap();
        Ok(key)
      },
      Err(err) => Err(err)
    }
  }

  fn create_key<'b>(&mut self, key_name: &str, key_ops: Vec<String>) -> hyper::HttpResult<KeyWrapper>{
    let url_str = AzureVault::key_url(self.vault_name, key_name, Some("create"));
    let url: &str = url_str.as_ref();
    let create_key = CreateKey{kty: "RSA".to_string(), key_ops: key_ops, attributes: Attributes{enabled: Some(true), nbf: None, exp: None}};
    let request_body = json::encode(&create_key).unwrap();
    let execute_create_key = |client: &mut Client, auth_token: Option<AuthToken>| {
      match auth_token {
        Some(token) => {
          let mut req_headers = hyper::header::Headers::new();
          let json_mime: Mime = "application/json".parse().unwrap();
          req_headers.set(Authorization(BearerToken { token: token.access_token.clone() }));
          req_headers.set(ContentType(json_mime));
          let body: &str = request_body.as_ref();
          client.post(url).headers(req_headers).body(body).send()
        },
        None => {
          let mut req_headers = hyper::header::Headers::new();
          let json_mime: Mime = "application/json".parse().unwrap();
          req_headers.set(ContentType(json_mime));
          let body: &str = request_body.as_ref();
          client.post(url).headers(req_headers).body(body).send()
        }
      }
    };

    match AzureVault::execute_wrapper(self, execute_create_key) {
      Ok(mut res) => {
        let mut body = String::new();
        let _ = res.read_to_string(&mut body);
        let key: KeyWrapper = json::decode(body.as_ref()).unwrap();
        Ok(key)
      },
      Err(err) => Err(err)
    }
  }

  fn list<'b>(&mut self) -> hyper::HttpResult<Vec<KeyListItem>>{
    let url_str = AzureVault::root_keys_url(self.vault_name);
    let url: &str = url_str.as_ref();
    let execute_list_keys = |client: &mut Client, auth_token: Option<AuthToken>| {
      match auth_token {
        Some(token) => {
          let mut req_headers = hyper::header::Headers::new();
          req_headers.set(Authorization(BearerToken { token: token.access_token.clone() }));
          client.get(url).headers(req_headers).send()
        },
        None => client.get(url).send()
      }
    };

    match AzureVault::execute_wrapper(self, execute_list_keys) {
      Ok(mut res) => {
        let mut body = String::new();
        let _ = res.read_to_string(&mut body);
        let keys: Vec<KeyListItem> = json::decode(body.as_ref()).unwrap();
        Ok(keys)
      },
      Err(err) => Err(err)
    }
  }

  fn encrypt<'b>(&mut self, key_name: &str, data: &[u8]) -> hyper::HttpResult<String>{
    let url = AzureVault::key_url(self.vault_name, key_name, Some("encrypt"));
    let mut payload = BTreeMap::new();
    payload.insert("alg", "RSA_OAEP".to_string());
    payload.insert("value", data.to_base64(URL_SAFE));

    match self.crypto_operation::<BTreeMap<String, String>>(payload, url){
      Ok(map) => {
        Ok(map.get("value").unwrap().clone())
      },
      Err(err) => Err(err)
    }
  }

  fn decrypt<'b>(&mut self, key_name: &str, data: &[u8]) -> hyper::HttpResult<String>{
    let url = AzureVault::key_url(self.vault_name, key_name, Some("decrypt"));
    let mut payload = BTreeMap::new();
    payload.insert("alg", "RSA_OAEP".to_string());
    payload.insert("value", data.to_base64(URL_SAFE));

    match self.crypto_operation::<BTreeMap<String, String>>(payload, url){
      Ok(map) => {
        Ok(map.get("value").unwrap().clone())
      },
      Err(err) => Err(err)
    }
  }

  fn wrap<'b>(&mut self, key_name: &str, cek:  &[u8]) -> hyper::HttpResult<String>{
    self.encrypt(key_name, cek)
  }

  fn unwrap<'b>(&mut self, key_name: &str, cek:  &[u8]) -> hyper::HttpResult<String>{
    self.decrypt(key_name, cek)
  }

  fn sign<'b>(&mut self, key_name: &str, digest: Vec<u8>) -> hyper::HttpResult<Vec<u8>>{
    let url = AzureVault::key_url(self.vault_name, key_name, Some("sign"));
    let mut payload = BTreeMap::new();
    payload.insert("alg", "RS512".to_string());
    payload.insert("value", digest.to_base64(URL_SAFE));

    match self.crypto_operation::<BTreeMap<String, String>>(payload, url){
      Ok(map) => {
        Ok(map.get("value").unwrap().from_base64().unwrap())
      },
      Err(err) => Err(err)
    }
  }

  fn verify<'b>(&mut self, key_name: &str, digest: Vec<u8>, signiture: Vec<u8>) -> hyper::HttpResult<bool>{
    let url = AzureVault::key_url(self.vault_name, key_name, Some("verify"));
    let mut payload = BTreeMap::new();
    payload.insert("alg", "RS512".to_string());
    payload.insert("digest", digest.to_base64(URL_SAFE));
    payload.insert("value", signiture.to_base64(URL_SAFE));

    match self.crypto_operation::<BTreeMap<String, bool>>(payload, url){
      Ok(map) => {
        Ok(map.get("value").unwrap().clone())
      },
      Err(err) => Err(err)
    }
  }

  fn crypto_operation<T>(&mut self, payload: BTreeMap<&str, String>, url: String) -> hyper::HttpResult<T>
      where T : PartialEq + Decodable{
    let url_str = url.as_ref();
    let request_body = json::encode(&payload).unwrap();
    let execute_create_key = |client: &mut Client, auth_token: Option<AuthToken>| {
      match auth_token {
        Some(token) => {
          let mut req_headers = hyper::header::Headers::new();
          let json_mime: Mime = "application/json".parse().unwrap();
          req_headers.set(Authorization(BearerToken { token: token.access_token.clone() }));
          req_headers.set(ContentType(json_mime));
          let hyper_body: &str = request_body.as_ref();
          client.post(url_str).headers(req_headers).body(hyper_body).send()
        },
        None => {
          let mut req_headers = hyper::header::Headers::new();
          let json_mime: Mime = "application/json".parse().unwrap();
          req_headers.set(ContentType(json_mime));
          let hyper_body: &str = request_body.as_ref();
          client.post(url_str).headers(req_headers).body(hyper_body).send()
        }
      }
    };

    match AzureVault::execute_wrapper(self, execute_create_key) {
      Ok(mut res) => {
        let mut body = String::new();
        let _ = res.read_to_string(&mut body);
        let json: T = json::decode(body.as_ref()).unwrap();
        Ok(json)
      },
      Err(err) => Err(err)
    }
  }
}

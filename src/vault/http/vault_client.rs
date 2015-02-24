
use hyper;
use hyper::client::{Client, Response};
use hyper::mime::*;
use hyper::header::{Authorization, ContentType};
use hyper::HttpError;
use hyper::method::Method;
use hyper::method::Method::{Post};
use hyper::net::{HttpConnector};
use hyper::status::StatusCode;

use url;

use rustc_serialize::json;

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

pub struct AzureVaultClient<'a>{
  client: Client<HttpConnector<'a>>,
  vault_name: &'a str,
  key: &'a str,
  secret: &'a str,
  auth_token: Option<AuthToken>
}

impl<'a> AzureVaultClient<'a> {

    fn execute_wrapper<F: Fn(&mut Client<HttpConnector>, Option<AuthToken>) -> hyper::HttpResult<Response>>(vault_client: &mut AzureVaultClient, req_fn: F) -> hyper::HttpResult<Response>{
      match req_fn(&mut vault_client.client, vault_client.auth_token.clone()) {
        Ok(res) => {
          match res.status {
            StatusCode::Unauthorized => {
              match AzureVaultClient::handle_401(vault_client, res) {
                Ok(mut auth_res) => {
                  let body = auth_res.read_to_string().unwrap();
                  let token: AuthToken = json::decode(body.as_slice()).unwrap();
                  vault_client.auth_token = Some(token);
                  req_fn(&mut vault_client.client, vault_client.auth_token.clone())
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

    fn handle_401(vault_client: &mut AzureVaultClient, response: Response) -> hyper::HttpResult<Response>{
      let bearer_header = response.headers.get::<WwwAuthenticate<Bearer>>();
      match bearer_header {
        Some(header) => {
          let mut auth_url = header.0.authorization.clone();
          auth_url.push_str("/oauth2/token");
          let resource = header.0.resource.as_slice();
          AzureVaultClient::authenticate(&mut vault_client.client, auth_url.as_slice(), resource, vault_client.key, vault_client.secret)
        },
        None => panic!("401 with no WWW-Authenticate header!")
      }
    }

    fn authenticate(client: &mut Client<HttpConnector>, auth_url: &str, resource: &str, key: &str, secret: &str) -> hyper::HttpResult<Response> {
      let parmas = vec![("client_id", key),
                        ("client_secret", secret),
                        ("resource", resource),
                        ("grant_type", "client_credentials")];
      let headers = vec![("content", "application/x-www-form-urlencoded")];
      AzureVaultClient::pstar_with_params(client, Method::Post, auth_url, parmas.into_iter(), headers.into_iter())
    }

    fn pstar_with_params<I, J>(client: &mut Client<HttpConnector>, method: Method, url: &str, params: I, headers: J) -> Result<Response, HttpError>
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

    fn key_url<'b>(vault_name: &str, key_name: &str, operation: Option<&str>) -> String{
      let url = String::from_str("https://{vault_name}.vault.azure.net/keys/{key_name}{op}?api-version=2014-12-08-preview")
        .replace("{vault_name}", vault_name)
        .replace("{key_name}", key_name);
      match operation {
        Some(op) => {
          let op_string = String::from_str("/") + op;
          url.replace("{op}", op_string.as_slice())
        },
        None => {
          url.replace("{op}", "")
        }
      }
    }

    fn root_keys_url<'b>(vault_name: &str) -> String{
      String::from_str("https://{vault_name}.vault.azure.net/keys?api-version=2014-12-08-preview")
        .replace("{vault_name}", vault_name)
    }
}

pub trait VaultClient<'a>: {
  fn new(vault_name: &'a str, key: &'a str, secret: &'a str) -> Self;
  fn list<'b>(&mut self) -> hyper::HttpResult<Vec<KeyListItem>>;
  fn get_key<'b>(&mut self, key_name: &str) -> hyper::HttpResult<KeyWrapper>;
  fn update_key<'b>(&mut self, key: KeyWrapper) -> hyper::HttpResult<KeyWrapper>;
  fn delete_key<'b>(&mut self, key_name: &str) -> hyper::HttpResult<KeyWrapper>;
  fn create_key<'b>(&mut self, key_name: &str, key_ops: Vec<String>) -> hyper::HttpResult<KeyWrapper>;
  fn encrypt<'b>(&mut self, data: String, key_name: &str) -> hyper::HttpResult<String>;
  fn decrypt<'b>(&mut self, data: String, key_name: &str) -> hyper::HttpResult<String>;
  fn wrap<'b>(&mut self, cek: String, key_name: &str) -> hyper::HttpResult<String>;
  fn unwrap<'b>(&mut self, cek: String, key_name: &str) -> hyper::HttpResult<String>;
}

impl<'a> VaultClient<'a> for AzureVaultClient<'a> {
  fn new(vault_name: &'a str, key: &'a str, secret: &'a str) -> AzureVaultClient<'a> {
    AzureVaultClient{
      client: Client::new(),
      vault_name: vault_name,
      key: key,
      secret: secret,
      auth_token: None
    }
  }

  fn get_key<'b>(&mut self, key_name: &str) -> hyper::HttpResult<KeyWrapper>{
    let url_str = AzureVaultClient::key_url(self.vault_name, key_name, None);
    let url = url_str.as_slice();
    let execute_get_key = |&: client: &mut Client<HttpConnector>, auth_token: Option<AuthToken>| {
      match auth_token {
        Some(token) => {
          let mut req_headers = hyper::header::Headers::new();
          req_headers.set(Authorization(BearerToken { token: token.access_token.clone() }));
          client.get(url).headers(req_headers).send()
        },
        None => client.get(url).send()
      }
    };

    match AzureVaultClient::execute_wrapper(self, execute_get_key) {
      Ok(mut res) => {
        let body = res.read_to_string().unwrap();
        let key: KeyWrapper = json::decode(body.as_slice()).unwrap();
        Ok(key)
      },
      Err(err) => Err(err)
    }
  }

  fn update_key<'b>(&mut self, key: KeyWrapper) -> hyper::HttpResult<KeyWrapper>{
    Ok(key)
  }

  fn delete_key<'b>(&mut self, key_name: &str) -> hyper::HttpResult<KeyWrapper>{
    let url_str = AzureVaultClient::key_url(self.vault_name, key_name, None);
    let url = url_str.as_slice();
    let execute_delete_key = |&: client: &mut Client<HttpConnector>, auth_token: Option<AuthToken>| {
      match auth_token {
        Some(token) => {
          let mut req_headers = hyper::header::Headers::new();
          req_headers.set(Authorization(BearerToken { token: token.access_token.clone() }));
          client.delete(url).headers(req_headers).send()
        },
        None => client.delete(url).send()
      }
    };

    match AzureVaultClient::execute_wrapper(self, execute_delete_key) {
      Ok(mut res) => {
        let body = res.read_to_string().unwrap();
        let key: KeyWrapper = json::decode(body.as_slice()).unwrap();
        Ok(key)
      },
      Err(err) => Err(err)
    }
  }

  fn create_key<'b>(&mut self, key_name: &str, key_ops: Vec<String>) -> hyper::HttpResult<KeyWrapper>{
    let url_str = AzureVaultClient::key_url(self.vault_name, key_name, Some("create"));
    let url = url_str.as_slice();
    let create_key = CreateKey{kty: "RSA".to_string(), key_ops: key_ops, attributes: Attributes{enabled: Some(true), nbf: None, exp: None}};
    let request_body = json::encode(&create_key).unwrap();
    let execute_create_key = |&: client: &mut Client<HttpConnector>, auth_token: Option<AuthToken>| {
      match auth_token {
        Some(token) => {
          let mut req_headers = hyper::header::Headers::new();
          let json_mime: Mime = "application/json".parse().unwrap();
          req_headers.set(Authorization(BearerToken { token: token.access_token.clone() }));
          req_headers.set(ContentType(json_mime));
          client.post(url).headers(req_headers).body(request_body.as_slice()).send()
        },
        None => {
          let mut req_headers = hyper::header::Headers::new();
          let json_mime: Mime = "application/json".parse().unwrap();
          req_headers.set(ContentType(json_mime));
          client.post(url).headers(req_headers).body(request_body.as_slice()).send()
        }
      }
    };

    match AzureVaultClient::execute_wrapper(self, execute_create_key) {
      Ok(mut res) => {
        let body = res.read_to_string().unwrap();
        let key: KeyWrapper = json::decode(body.as_slice()).unwrap();
        Ok(key)
      },
      Err(err) => Err(err)
    }
  }

  fn list<'b>(&mut self) -> hyper::HttpResult<Vec<KeyListItem>>{
    let url_str = AzureVaultClient::root_keys_url(self.vault_name);
    let url = url_str.as_slice();
    let execute_list_keys = |&: client: &mut Client<HttpConnector>, auth_token: Option<AuthToken>| {
      match auth_token {
        Some(token) => {
          let mut req_headers = hyper::header::Headers::new();
          req_headers.set(Authorization(BearerToken { token: token.access_token.clone() }));
          client.get(url).headers(req_headers).send()
        },
        None => client.get(url).send()
      }
    };

    match AzureVaultClient::execute_wrapper(self, execute_list_keys) {
      Ok(mut res) => {
        let body = res.read_to_string().unwrap();
        let keys: Vec<KeyListItem> = json::decode(body.as_slice()).unwrap();
        Ok(keys)
      },
      Err(err) => Err(err)
    }
  }

  fn encrypt<'b>(&mut self, data: String, key_name: &str) -> hyper::HttpResult<String>{
    Ok(String::new())
  }

  fn decrypt<'b>(&mut self, data: String, key_name: &str) -> hyper::HttpResult<String>{
    Ok(String::new())
  }

  fn wrap<'b>(&mut self, cek: String, key_name: &str) -> hyper::HttpResult<String>{
    Ok(String::new())
  }

  fn unwrap<'b>(&mut self, cek: String, key_name: &str) -> hyper::HttpResult<String>{
    Ok(String::new())
  }
}


use hyper;
use hyper::client::{Client, Response};
use hyper::header::{Authorization};
use hyper::HttpError;
use hyper::method::Method;
use hyper::method::Method::{Post};
use hyper::net::{HttpConnector};
use hyper::status::StatusCode;

use url;

use rustc_serialize::json;

use http::authenticate_header::*;

pub struct VaultClient<'a>{
  client: Client<HttpConnector<'a>>,
  vault_name: &'a str,
  key: &'a str,
  secret: &'a str,
  auth_token: Option<AuthToken<'a>>
}

// authentication bearer token
#[derive(RustcEncodable, RustcDecodable, Show, Clone)]
struct AuthToken<'a> {
  token_type: String,
  expires_in: i32,
  expires_on: i32,
  not_before: i32,
  resource: String,
  access_token: String,
}

// Azure Key Vault asymmetric key representation
#[derive(RustcEncodable, RustcDecodable, Show, Clone)]
pub struct KeyWrapper<'a> {
  key: Key<'a>,
  attributes: Attributes<'a>,
}

#[derive(RustcEncodable, RustcDecodable, Show, Clone)]
pub struct Key<'a> {
  kid: String,
  kty: String,
  n: String,
  e: String,
  key_ops: Vec<String>,
}

#[derive(RustcEncodable, RustcDecodable, Show, Clone)]
pub struct Attributes<'a> {
  enabled: bool,
  exp: i32,
  nbf: i32
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

    pub fn get_key<'b>(&mut self, key_name: &str) -> hyper::HttpResult<KeyWrapper>{
      let url_str = VaultClient::key_url(self.vault_name, key_name);
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

      match VaultClient::execute_wrapper(self, execute_get_key) {
        Ok(mut res) => {
          let body = res.read_to_string().unwrap();
          let key: KeyWrapper = json::decode(body.as_slice()).unwrap();
          Ok(key)
        },
        Err(err) => Err(err)
      }
    }

    fn execute_wrapper<F: Fn(&mut Client<HttpConnector>, Option<AuthToken>) -> hyper::HttpResult<Response>>(vault_client: &mut VaultClient, req_fn: F) -> hyper::HttpResult<Response>{
      match req_fn(&mut vault_client.client, vault_client.auth_token.clone()) {
        Ok(res) => {
          match res.status {
            StatusCode::Unauthorized => {
              match VaultClient::handle_401(vault_client, res) {
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


    fn handle_401(vault_client: &mut VaultClient, response: Response) -> hyper::HttpResult<Response>{
      let bearer_header = response.headers.get::<WwwAuthenticate<Bearer>>();
      match bearer_header {
        Some(header) => {
          let mut auth_url = header.0.authorization.clone();
          auth_url.push_str("/oauth2/token");
          let resource = header.0.resource.as_slice();
          VaultClient::authenticate(&mut vault_client.client, auth_url.as_slice(), resource, vault_client.key, vault_client.secret)
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

    fn key_url<'b>(vault_name: &str, key_name: &str) -> String{
      let url = String::from_str("https://{vault_name}.vault.azure.net/keys/{key_name}?api-version=2014-12-08-preview");
      url.replace("{vault_name}", vault_name)
      .replace("{key_name}", key_name)
    }
}


use hyper::client::*;
use hyper::net::{HttpConnector};

use std::io::IoError;
use url::ParseError;
use hyper::HttpError;

pub struct VaultClient<'a>{
  client: Client<HttpConnector>,
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

    pub fn get_key(&mut self, key_name: &str) -> Result<Response, HttpError>{
      let url = VaultClient::key_url(self.vault_name, key_name, &mut String::new());
      let url_str = url.as_slice();
      println!("{}", url_str);
      (&mut self.client).get(url_str).send()
    }

    fn key_url(vault_name: &str, key_name: &str, url: &mut String) -> String{
      url.push_str("https://{vault_name}.vault.azure.net/keys/{key_name}");
      url.replace("{vault_name}", vault_name)
        .replace("{key_name}", key_name)
    }

    // fn request_executor(&mut self, method: Method, url: &str) -> RequestBuilder<IntoUrl, HttpConnector> {
    //   RequestBuilder {
    //       client: (&mut self.client),
    //       method: method,
    //       url: url,
    //       body: None,
    //       headers: None,
    //     }
    // }
    //
    // fn set_body_length(requestBuilder :&mut RequestBuilder<IntoUrl, HttpConnector>, body: Option<&'static str>){
    //
    // }
}

// impl<'a, C: NetworkConnector + 'a> Restful<'a, C> {
//
//   pub fn new() -> Restful<'a, C> {
//     let mut client = Client::new();
//     Restful{client: &client}
//   }
//
//   pub fn get(self, url: &'static str) -> RequestBuilder<'a, IntoUrl, NetworkConnector>{
//     let headers = Some(Restful::default_headers());
//     return RequestBuilder {
//       client: self.client,
//       method: Method::Get,
//       url: url,
//       body: None,
//       headers: headers
//     }
//   }
//
//   fn default_headers() -> Headers {
//     let headers = Headers::new();
//     return headers;
//   }
// }

  // pub fn new(Request) -> Result<&Restful, RestError> {
  //   let mut url = match Url::parse(url_str) {
  //     Ok(url) => url,
  //     Err(err) => return Err(UrlParseError(err))
  //   };
  //
  //   match url_params {
  //     Some(params) => {
  //       // TODO: write article talking about iter() vs into_iter()
  //       url.set_query_from_pairs(params.to_vec().into_iter());
  //       },
  //       None => ()
  //     };
  //
  //     let mut req = match Request::new(method, url) {
  //       Ok(req) => req,
  //       Err(err) => return Err(HttpRequestError(err))
  //     };
  //
  //     match body {
  //       Some(body) =>
  //       req.headers_mut().set(ContentLength(body.len())),
  //       None =>
  //       // needed so that hyper doesn't try to send Transfer-Encoding:
  //       // Chunked, which causes some servers (e.g. www.reddit.co) to
  //       // hang. is this a bug in the hyper client? why would it send
  //       // T-E: Ch as a header in a GET request?
  //       req.headers_mut().set(ContentLength(0))
  //     };
  //
  //     match content_type {
  //       Some(content_type) =>
  //       req.headers_mut().set(ContentType(from_str(content_type).unwrap())),
  //       None => ()
  //     };
  //
  //     let mut req_started = match req.start() {
  //       Ok(req) => req,
  //       Err(err) => return Err(HttpRequestError(err))
  //     };
  //
  //     match body {
  //       Some(body) =>
  //       match req_started.write(body.as_bytes()) {
  //         Ok(()) => (),
  //         Err(err) => return Err(HttpIoError(err))
  //         },
  //         None => ()
  //       };
  //
  //       let mut resp = match req_started.send() {
  //         Ok(resp) => resp,
  //         Err(err) => return Err(HttpRequestError(err))
  //       };
  //
  //       let body = match resp.read_to_string() {
  //         Ok(body) => body,
  //         Err(err) => return Err(HttpIoError(err))
  //       };
  //
  //       let rest_response = Response {
  //         code: resp.status as i32,
  //         status: resp.status,
  //         headers: resp.headers,
  //         body: body,
  //       };
  //
  //       return Ok(rest_response);
  //     }
  //
  //   }
//}

// pub enum RestError {
//   UrlParseError(ParseError),
//   HttpRequestError(HttpError),
//   HttpIoError(IoError)
// }
